---
name: windbg-ogl-icd-triage
description: 'OpenGL ICD 用户态驱动崩溃与应用 GPU 识别失败问题排查技能。适用场景：应用报"不支持 GPU 加速"但实际问题是 OpenGL ICD 崩溃、新线程 TLS 未初始化导致 NULL 传入、jmOglICD_64.dll 访问违例、gcoOS_GetDriverTLS 返回 NULL。使用 mcp-windbg 工具进行 dump 分析。'
argument-hint: '可选：dump 文件路径'
---

# WinDbg OpenGL ICD 驱动崩溃排查技能

## 适用场景

- 应用（如 Adobe After Effects、DCC 软件）报"不支持 GPU 加速"或"GPU 无法识别"
- 应用可以打开但 GPU 特性不可用，切换到 CPU 渲染
- 崩溃发生在 `jmOglICD_64.dll`（JM OpenGL ICD）内部
- 调用栈含有 `__glGetCurrentGCResoure`、`__glShareTextureObjects`、`gcoOS_GetDriverTLS`

---

## 关键教训：先看异常，再看症状

> **本次分析的最大弯路**：从"应用层报错"（GPU 不识别）出发，试图在 GPU 硬件检测、D3D 初始化等路径上找原因，花费大量时间，最终才回到真正的崩溃点——OpenGL ICD 的一个 NULL 指针解引用。
>
> **正确姿势**：拿到 dump，**第一步就看异常类型和崩溃线程**，在找到物理崩溃位置之前，不要被应用层的错误描述牵着走。

---

## 第一步：确认崩溃类型与崩溃进程

拿到 dump 立刻执行：

```windbg
!analyze -v           ; 全量自动分析，获取异常类型、崩溃线程、关键寄存器
.lastevent            ; 最后一次事件
|                     ; 查看进程信息
```

**关键判断**：

| dump 进程 | 结论 |
|---|---|
| `GPUSniffer.exe`、`aesniffer.exe` 等检测工具进程 | 崩溃在 GPU 能力探测阶段，不是应用本身 |
| 主应用进程（如 `AfterFX.exe`） | 崩溃在运行时 |
| jmOglICD_64.dll 出现在崩溃栈 | **OpenGL ICD 问题，不是 DX 问题** |

> **本次案例**：崩溃在 `GPUSniffer.exe`（AE 的 GPU 检测子进程），不是 AfterFX 本身。AE 的报错"不支持 GPU 加速"来自 GPUSniffer 意外退出后 AE 的兜底逻辑。

---

## 第二步：确认崩溃模块与异常上下文

```windbg
; 切换到崩溃线程，还原异常上下文
~Xs; .ecxr            ; X = 崩溃线程号（!analyze 会给出）
kb 20                 ; 看完整调用栈
lm vm jmOgl*          ; 确认 OGL ICD 模块及其符号
```

**典型 jmOglICD 崩溃调用栈**：

```
ntdll!NtTerminateProcess
jmOglICD_64!__glShareTextureObjects+0x??   ← 访问 NULL 指针
jmOglICD_64!__glGetCurrentGCResoure+0x??   ← gc_es_context.c:1157
...
```

如果看到 `__glGetCurrentGCResoure` 调用了 `gcoOS_GetDriverTLS`，立刻跳到第三步。

---

## 第三步：识别 TLS 未初始化（新线程）模式

`gcoOS_GetDriverTLS(slot)` 是 JM OpenGL ICD 获取线程本地存储的函数。**新线程首次调用 OpenGL 时，TLS 尚未分配，会返回 NULL**。

```windbg
; 查看崩溃帧的局部变量
.frame /r N           ; N = __glGetCurrentGCResoure 的帧号
dv /t /v              ; 看 gcSrc、gc 等指针
```

**判断 TLS NULL 的特征**：

```
gcSrc = 0x00000000    ← gcoOS_GetDriverTLS 返回 NULL
```

下一句代码直接用 `gcSrc` 访问成员 → AV。

**为什么只在"新线程"发生**：
- OpenGL ICD 在线程创建时注册 TLS 回调（`DLL_THREAD_ATTACH`）
- 若线程未走此路径（线程池、异步任务框架复用已有线程但跳过 attach 通知），TLS slot 为空
- 主线程正常，worker thread / GPUSniffer 的检测线程可能触发

---

## 第四步：定位真正的修复位置

找到调用 `gcSrc` 之前的 NULL 检查缺失：

```windbg
u jmOglICD_64!__glShareTextureObjects L30    ; 反汇编，找缺少 null check 的位置
u jmOglICD_64!__glGetCurrentGCResoure L20   ; 确认 gcoOS_GetDriverTLS 之后没有判空
```

**正确的修复方式**（源码级）：

```c
// gc_es_context.c，__glShareTextureObjects 入口处
// 原代码：直接用 gcSrc，无 NULL 检查
// 修复：
if (gcSrc == NULL) {
    return GL_TRUE;   // 无源 context，直接返回成功，不操作
}
```

---

## 高效调试流程总结

```
1. !analyze -v
   ↓ 得到崩溃模块：是 jmOglICD 还是 jmUmd11？
   ├── jmOglICD → 走 OpenGL ICD 路径（本 skill）
   └── jmUmd11  → 走 D3D UMD 路径（windbg-dx-driver-triage skill）

2. 崩溃模块确认后，看崩溃线程的完整调用栈（.ecxr + kb）
   ↓ 是否包含 gcoOS_GetDriverTLS？
   ├── 是 → TLS 未初始化，找 NULL guard 缺失
   └── 否 → 其他 ICD 内部错误，需深入分析

3. 定位 NULL 指针来源：用 dv /t /v 查崩溃帧局部变量
   ↓ 确认 gcSrc/gc 等关键指针是否为 NULL

4. 找修复点：在调用 gcSrc 的函数入口加 NULL 返回检查
   ↓ 验证：用源码 image 或反汇编确认修复有效
```

---

## 避免弯路的关键原则

### 1. 应用层报错 ≠ 根因
"不支持 GPU 加速"是 AE 的兜底逻辑，真正的原因是 GPUSniffer 崩溃。不要从应用层错误字符串出发做分析，而要从异常记录出发。

### 2. OpenGL 和 DX 是两条不同的路径
JM GPU 驱动同时有 `jmOglICD_64.dll`（OpenGL）和 `jmUmd11_64.dll`（DirectX）。AE 的 GPU 加速使用 **OpenGL**，不是 DX。拿到 dump 后立刻 `lm m jmOgl* jmUmd*` 确认是哪条路径在崩溃，避免在错误的模块里深挖。

### 3. dump 进程可能是子进程/检测工具
AE 等软件会启动独立的 GPU 检测子进程（GPUSniffer）。子进程 dump 和主进程 dump 中看到的现象完全不同。拿到 dump 第一时间确认：**这个进程是主应用还是检测工具？**

### 4. TLS 问题天然只在特定线程触发
如果同样的函数在某些线程 OK、某些线程 crash，优先怀疑 TLS/线程初始化问题。看 `DLL_THREAD_ATTACH` 是否被跳过、线程是否从线程池复用。

---

## 本次案例技术细节（AE 2025 + JM GPU）

| 项目 | 详情 |
|---|---|
| **应用** | Adobe After Effects 2025 |
| **崩溃进程** | GPUSniffer.exe（AE GPU 检测子进程） |
| **崩溃模块** | `jmOglICD_64.dll` |
| **崩溃函数** | `__glGetCurrentGCResoure` @ gc_es_context.c:1157 |
| **异常类型** | Access Violation（NULL 指针解引用） |
| **根因** | `gcoOS_GetDriverTLS(slot=3)` 在新线程返回 NULL，返回值未判空直接传入 `__glShareTextureObjects` |
| **修复** | `if (gcSrc == NULL) return GL_TRUE;` 加在 `__glShareTextureObjects` 入口 |
| **验证方式** | 对照源码 image 确认修复逻辑 |

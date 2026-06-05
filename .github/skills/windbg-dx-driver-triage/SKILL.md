---
name: windbg-dx-driver-triage
description: 'DirectX 用户态驱动（UMD）问题调试与根因分析技能。适用场景：DX 应用报"不支持DX11/DX12硬件"错误、D3D11CreateDevice 失败、UMD DLL 加载错误（0xC000007B）、驱动 INF 注册表配置问题、DXGI/d3d11 UMD 版本索引错误。使用 mcp-windbg 工具进行 dump 分析和实时远程调试。'
argument-hint: '可选：dump 文件路径 或 远程调试连接字符串'
---

# WinDbg DirectX 驱动问题排查技能

## 适用场景

- DX 应用弹出 `error.dx11_hardware_required` 或类似硬件不支持错误
- `D3D11CreateDevice` 返回失败，特征级别不符合预期
- UMD DLL 加载失败（`STATUS_INVALID_IMAGE_FORMAT 0xC000007B`）
- 驱动 INF `UserModeDriverName` / `InstalledDisplayDrivers` 配置可疑
- `OpenAdapter10_2` 未被调用，意外走了 D3D11on12 路径

---

## 第一步：快速定位问题类型

拿到 dump 或连接实时目标后，先做以下三个检查：

```windbg
lm m jmUmd*        ; 查看 UMD 模块是否加载
lm m d3d11on12     ; 是否启用了 D3D11on12（不正常）
.lastevent         ; 最后一次事件是什么
```

然后查看已加载的 DX DLL 基址范围：
- 地址在 `00000000'xxxxxxxx`（32位范围）→ **疑似32位 DLL 被64位进程加载**
- 正常64位 DLL 地址在 `00007ff?'xxxxxxxx`

---

## 第二步：确认 UMD 加载路径

### 2a. 检查注册表实际值（通过 dump 内存）

从 `D3DKMTQueryAdapterInfo` 返回的缓冲区读取实际 UMD 文件名：

```windbg
; 在 dxgi!CDXGIBaseAdapter::LoadUMD 调用后，rcx 指向文件名缓冲区
; 或直接从注册表键读取
!reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v UserModeDriverName
```

### 2b. 设断点观察实际加载的 DLL

```windbg
; 在 LoadLibraryExW 调用前查看参数（rcx = 文件名）
bp dxgi!CDXGIBaseAdapter::LoadUMD+0xd9 ".printf \"[LoadUMD] Loading: %mu\n\", @rcx; g"
bp d3d11!CCreateDeviceCache::CUMDAdapterCache::Load ".printf \"[Load] entry_code=%d\n\", @r8d; g"
bp d3d11!NDXGI::CUMDAdapter::OpenAdapter10_2 ".printf \"[GOOD] OpenAdapter10_2\n\"; g"
bp d3d11!NDXGI::CUMDAdapter::OpenAdapterD3D11On12 ".printf \"[BUG] D3D11on12 fallback!\n\"; g"
```

`entry_code` 含义：
| 值 | 含义 |
|----|------|
| 0 | DX9（KMTUMDVERSION=0） |
| 1 | DX10（KMTUMDVERSION=1） |
| 2 | DX11（KMTUMDVERSION=2）← 应加载 jmUmd11 |
| 3 | DX12/D3D11on12 |

---

## 第三步：诊断 INF UserModeDriverName 索引偏移

**症状**：DXGI 查询 version=2（DX11）却拿到 DX12 的 DLL。

**根因**：INF 中使用了 `<>` 占位符，导致 multi-sz 字符串的槽位索引偏移。

```ini
; 错误写法（<> 占据 slot[0]，后续全部偏移+1）
HKR,, UserModeDriverName, %REG_MULTI_SZ%, "<>", "%11%\jmUmd11_64.dll", "%11%\jmUmd11_64.dll", "%11%\jmUmd12_64.dll"
;   slot[0]=<>  slot[1]=jmUmd11  slot[2]=jmUmd11  slot[3]=jmUmd12
;   DXGI 查 index[2] → 拿到 jmUmd11（看似正确但实际内核可能跳过无效项）
;   内核跳过 <> → DXGI 查 version=2 → 实际拿到 jmUmd12！

; 正确写法（4个槽位，DX9/DX10/DX11 都用 jmUmd11，DX12 用 jmUmd12）
HKR,, UserModeDriverName, %REG_MULTI_SZ%, "%11%\jmUmd11_64.dll", "%11%\jmUmd11_64.dll", "%11%\jmUmd11_64.dll", "%11%\jmUmd12_64.dll"
HKR,, InstalledDisplayDrivers, %REG_MULTI_SZ%, "jmUmd11_64", "jmUmd11_64", "jmUmd11_64", "jmUmd12_64", "jmUmd11_32", "jmUmd11_32", "jmUmd11_32", "jmUmd12_32"
```

**验证方法**：读取 `D3DKMTQueryAdapterInfo` 返回缓冲区

```windbg
; 找到 D3DKMTQueryAdapterInfo 的输出缓冲区地址（查调用后 rdx 指向的结构体）
; 结构体内 offset+0x?? 开始是 UMD 文件名表
; 正常应该是：
; KMTUMDVERSION=0 → jmUmd11_64
; KMTUMDVERSION=1 → jmUmd11_64
; KMTUMDVERSION=2 → jmUmd11_64   ← DX11 必须是 DX11 的 DLL
; KMTUMDVERSION=3 → jmUmd12_64
```

---

## 第四步：诊断子进程 DLL 位数不匹配（0xC000007B）

**症状**：子进程在 `LdrpInitialize` 阶段就退出，父进程收到异常退出后误判为"硬件不支持"。

**定位方法**：

```windbg
; 启用子进程调试
.childdbg 1

; dxgi.dll 加载时自动设 NtTerminateProcess 断点
sxn ld
sxe -c "bp ntdll!NtTerminateProcess \".printf \\\"[EXIT] status=0x%08x\n\\\",@ecx; kb 8; g\"; sxn ld; g" ld:dxgi
```

**关键退出码**：
| 状态码 | 含义 |
|--------|------|
| `0xC000007B` | `STATUS_INVALID_IMAGE_FORMAT` — DLL 位数不匹配（32位DLL被64位进程加载） |
| `0xC0000005` | 访问违例 |
| `0xC0000034` | 找不到对象 |

**确认 DLL 位数**：

```powershell
# 检查指定 DLL 是32位还是64位
$f = "C:\Windows\System32\D3DCOMPILER_43.dll"
$b = [IO.File]::ReadAllBytes($f)
$pe = [BitConverter]::ToInt32($b, 0x3c)
$machine = [BitConverter]::ToUInt16($b, $pe + 4)
"Machine: 0x{0:X4}" -f $machine
# 0x8664 = 64位 AMD64（正确）
# 0x014C = 32位 x86（错误！System32 中不应出现）
```

**修复**：
- 将正确位数的 DLL 复制到 `System32`（64位）/ `SysWOW64`（32位）
- 来源：从另一台正常系统复制，或从 DirectX Redistributable 提取对应架构版本

---

## 第五步：多进程调试策略

3DMark11 等应用由 WPF 启动器（父进程）+ DX 渲染子进程构成，断点必须在正确进程中设置。

```windbg
; 查看当前进程树
|

; 切换到子进程上下文
|1s

; 启用子进程继承调试
.childdbg 1

; 禁用 ibp 暂停（避免子进程一启动就超时）
sxd ibp     ; 或 sxo ibp（output 不暂停）

; dxgi 加载时在子进程上下文自动设断点
sxe -c "bp dxgi!CDXGIBaseAdapter::LoadUMD+0xd9 \".printf \\\"[DLL] %mu\n\\\",@rcx;g\"; g" ld:dxgi
```

**常见陷阱**：
- 断点设在父进程，子进程根本跑不到 → 用 `ld:dxgi` 事件触发
- `ibp` 导致子进程启动时暂停太久被父进程终止 → 改为 `sxd ibp`
- session log 只保留最近200行，关键输出被冲掉 → 用 `.logopen C:\debug.log` 持久化

---

## 经验教训

1. **首先排查系统 DLL 完整性**：出现 `0xC000007B` 时，优先检查 `System32` 中的 DLL 是否为正确位数，不要直接往驱动问题上靠。

2. **WPF/托管启动器会吞掉子进程错误**：子进程因 DLL 加载失败退出，父进程会把它解读成业务层错误（"硬件不支持"），导致误导方向。

3. **`<>` 在 INF multi-sz 中是有效字符串**：Windows INF 不会忽略 `<>` 而是把它当成普通字符串写入注册表，占用一个槽位，导致后续所有槽位索引 +1。

4. **KMTUMDVERSION 索引与 INF 槽位一一对应**：
   - slot[0] = DX9，slot[1] = DX10，slot[2] = DX11，slot[3] = DX12
   - INF 必须精确填写4个值，不能用占位符

5. **用 `.childdbg 1` + `sxe ld:dxgi` 是调试多进程 DX 问题的标准姿势**，比手动附加子进程更可靠。

---

## 复盘：Dump 分析 vs 实时调试的教训

> 本次调试在 dump 阶段花费了大量时间深挖 UMD 加载逻辑，但 dump 来自**父进程（WPF 启动器）**，实际的崩溃发生在**子进程**。这种情况下 dump 分析无论多深入，都找不到真正的根因。

### 问题：为什么 dump 分析走了弯路？

**dump 中看到的现象**（都是真实的）：
- `jmUmd11_64.dll` 从未加载
- DXGI 拿到了错误的 DLL（jmUmd12_64）
- D3D11on12 路径被触发，特征级别退降

**但这些都是父进程做系统检测时留下的"副作用"，不是本次用户触发 3DMark11 测试时的崩溃路径。**

真正的崩溃路径是：**子进程 `3DMark11Demo.exe` 在 `LdrpInitialize` 阶段就因 `D3DCOMPILER_43.dll` 位数不匹配而退出**，根本没跑到 D3D11CreateDevice。

### 早期应该抓住的信号

拿到 dump 时，以下几个信号应该触发"是否是多进程架构"的怀疑：

| 信号 | 含义 |
|------|------|
| dump 进程是 `.exe` 但调用栈是 WPF/CLR（`clr!`、`WindowsBase_ni`） | 这是托管启动器，不是真正的 DX 渲染进程 |
| `D3D11CreateDevice` **从未被调用**（dump 中无相关栈帧） | 报错不来自当前进程的 D3D 调用 |
| `lm m jmUmd*` 为空 | UMD 从未加载，说明设备创建根本没有发生 |
| 错误以字符串形式返回（`error.dx11_hardware_required`）而非 HRESULT | 这是应用层判断，来源于子进程退出码或 IPC 消息 |

### 更高效的调试流程（改进版）

```
1. 拿到报错 → 先问：报错的进程是不是真正做 DX 初始化的进程？
   - 检查 lm：是否有 jmUmd* / d3d11 / dxgi？
   - 检查调用栈：是否有 D3D11CreateDevice 的调用历史？
   - 检查进程类型：是 CLR 托管进程吗？

2. 如果是托管/启动器进程 → 立即转为实时调试模式
   .childdbg 1
   然后让用户复现，在子进程里找问题

3. 子进程一启动就退出 → 优先怀疑 LdrpInitialize 阶段失败
   sxe -c "bp ntdll!NtTerminateProcess ..." ld:dxgi
   看退出码：c000007b = DLL位数不匹配，先查 System32 DLL

4. 子进程能正常运行 → 才进入 DX 初始化逻辑的深度分析
   bp dxgi!CDXGIBaseAdapter::LoadUMD
   bp d3d11!NDXGI::CUMDAdapter::OpenAdapter10_2
   ...
```

### 核心教训

> **Dump 分析的深度不等于找到了正确的问题。** 在多进程架构下，如果 dump 来自父进程/启动器，深挖 dump 中的 DX 调用路径可能是在分析一条"不相关的代码路径"。
>
> **判断标准**：dump 中如果 `D3D11CreateDevice` 从未出现在任何线程的调用栈中，那么 UMD 加载逻辑的分析结论对本次崩溃**没有直接因果关系**，应立即切换到实时调试找子进程。

---

## 参考资料

- [调试案例详情](./references/case-3dmark11-dx11-required.md)
- [INF UserModeDriverName 配置规范](./references/inf-umd-slots.md)

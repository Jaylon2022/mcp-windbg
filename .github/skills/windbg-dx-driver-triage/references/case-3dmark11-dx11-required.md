# 案例复盘：3DMark11 报 error.dx11_hardware_required

**日期**：2026年5月  
**硬件**：景嘉微 JM GPU  
**现象**：3DMark11 运行时弹出错误框 `error.dx11_hardware_required`

---

## 调查时间线

### 阶段1：Dump 分析

分析 `3DMark11.DMP`，初步结论：

- `jmUmd11_64.dll`（DX11 UMD）**从未被加载**（`lm u` 无输出）
- `jmUmd12_64.dll`（DX12 UMD）被加载，但它没有 `OpenAdapter10_2` 导出
- d3d11.dll 因找不到 `OpenAdapter10_2` 而回退到 `OpenAdapterD3D11On12`
- D3D11on12 路径下特征级别退降到 FL_10_1，低于 3DMark11 要求的 FL_11_0

**关键内存证据**（`D3DKMTQueryAdapterInfo` 返回缓冲区）：
```
KMTUMDVERSION=0 (DX9):  jmUmd11_64  ✓
KMTUMDVERSION=1 (DX10): jmUmd11_64  ✓
KMTUMDVERSION=2 (DX11): jmUmd12_64  ✗ ← 本该是 jmUmd11_64
KMTUMDVERSION=3 (DX12): jmUmd12_64  ✓
```

### 阶段2：INF 配置分析

用户 INF 配置：
```ini
HKR,, UserModeDriverName, %REG_MULTI_SZ%, "<>", "%11%\jmUmd11_64.dll", "%11%\jmUmd11_64.dll", "%11%\jmUmd12_64.dll"
```

**根因**：`<>` 被 Windows 当作普通字符串写入注册表，占据 slot[0]（DX9 槽位），导致：
- 内核读取 `UserModeDriverName`：`<>` / `jmUmd11_64` / `jmUmd11_64` / `jmUmd12_64`
- DXGI 查 version=2（DX11）→ 内核跳过无效的 `<>` → 实际返回 `jmUmd12_64`

**修复方案**：
```ini
HKR,, UserModeDriverName, %REG_MULTI_SZ%, "%11%\jmUmd11_64.dll", "%11%\jmUmd11_64.dll", "%11%\jmUmd11_64.dll", "%11%\jmUmd12_64.dll"
```

### 阶段3：实时远程调试（192.168.87.118:5909）

连接后发现：
- 断点设在父进程（3DMark11.exe，WPF），但 D3D11CreateDevice **从未被调用**
- 实际的 DX 渲染在子进程 `3DMark11Demo.exe` 中

### 阶段4：子进程调试

启用 `.childdbg 1`，在子进程 dxgi 加载时设断点，捕获 `NtTerminateProcess`：

```
[CHILD EXIT] status=0xc000007b
ntdll!NtTerminateProcess
ntdll!LdrpInitialize+0x444   ← c000007b 在第三个参数
ntdll!LdrpInitialize+0x3b
ntdll!LdrInitializeThunk+0xe
```

**`STATUS_INVALID_IMAGE_FORMAT (0xC000007B)`**：子进程在 `LdrpInitialize` 阶段（DLL 初始化）就退出，说明 DLL 位数不匹配。

### 阶段5：确认根因

检查 `System32\D3DCOMPILER_43.dll`：
```
Machine: 0x014C → 32位 x86！（应为 0x8664 即64位）
```

**实际错误链**：
```
3DMark11.exe (64位 WPF 启动器)
  └→ CreateProcess(3DMark11Demo.exe)  [64位]
        └→ 加载 C:\Windows\System32\D3DCOMPILER_43.dll
              └→ 该文件是 32位！→ STATUS_INVALID_IMAGE_FORMAT
                    └→ LdrpInitialize 调 NtTerminateProcess
                          └→ 父进程收到子进程异常退出
                                └→ 弹出 error.dx11_hardware_required
```

**与驱动 INF 问题是两个独立问题**。当前崩溃直接原因是系统文件问题，INF 问题在修复 D3DCOMPILER 后还需单独验证。

---

## 关键调试命令总结

```windbg
; 查进程树
|
; 切换子进程
|1s
; 启用子进程调试
.childdbg 1
; 禁用 ibp 暂停
sxd ibp
; dxgi 加载时在子进程设断点
sxe -c "bp ntdll!NtTerminateProcess \".printf \\\"[EXIT] 0x%08x\n\\\",@ecx; kb 8; g\"; sxn ld; g" ld:dxgi
; 检查 DLL 位数（PowerShell）
.shell powershell "$b=[IO.File]::ReadAllBytes('C:\\Windows\\System32\\D3DCOMPILER_43.dll');$pe=[BitConverter]::ToInt32($b,0x3c);'0x{0:X4}' -f [BitConverter]::ToUInt16($b,$pe+4)"
```

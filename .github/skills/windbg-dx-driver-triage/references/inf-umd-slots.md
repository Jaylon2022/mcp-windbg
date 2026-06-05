# INF UserModeDriverName 槽位配置规范

## KMTUMDVERSION 与槽位对应关系

Windows DXGI 通过 `D3DKMTQueryAdapterInfo(KMTQAITYPE_UMDRIVERNAME, version)` 查询对应版本的 UMD 文件名，其中 `version` 直接对应 `UserModeDriverName` multi-sz 字符串的**索引**。

| 槽位 index | KMTUMDVERSION | 对应 API | 应填写的 DLL |
|-----------|---------------|----------|-------------|
| 0 | DX9 | D3D9 UMD | DX9 or DX11 UMD |
| 1 | DX10 | D3D10 UMD | DX11 UMD |
| 2 | DX11 | D3D11 UMD | **必须是支持 OpenAdapter10_2 的 DLL** |
| 3 | DX12 | D3D12 UMD | DX12 UMD |

## 正确写法

```ini
[DriverAddReg]
; UserModeDriverName：4个槽位，严格按 DX9/DX10/DX11/DX12 顺序
HKR,, UserModeDriverName,    %REG_MULTI_SZ%, "%11%\jmUmd11_64.dll", "%11%\jmUmd11_64.dll", "%11%\jmUmd11_64.dll", "%11%\jmUmd12_64.dll"
HKR,, UserModeDriverNameWow, %REG_MULTI_SZ%, "%13%\jmUmd11_32.dll", "%13%\jmUmd11_32.dll", "%13%\jmUmd11_32.dll", "%13%\jmUmd12_32.dll"

; InstalledDisplayDrivers：8个槽位（64位4个+32位4个），无路径，只有文件名（不含.dll）
HKR,, InstalledDisplayDrivers, %REG_MULTI_SZ%, "jmUmd11_64", "jmUmd11_64", "jmUmd11_64", "jmUmd12_64", "jmUmd11_32", "jmUmd11_32", "jmUmd11_32", "jmUmd12_32"
```

## 常见错误

### 错误1：使用 `<>` 占位符

```ini
; ❌ 错误：<> 被写入注册表，占据 slot[0]
HKR,, UserModeDriverName, %REG_MULTI_SZ%, "<>", "%11%\jmUmd11_64.dll", "%11%\jmUmd11_64.dll", "%11%\jmUmd12_64.dll"
```

**后果**：内核存储的 multi-sz 为 `<>\0jmUmd11_64\0jmUmd11_64\0jmUmd12_64\0\0`
- DXGI 查 index[2]（DX11）→ 可能跳过无效 `<>` → 实际返回 `jmUmd12_64`
- 导致 DX11 应用加载 DX12-only 的 UMD，找不到 `OpenAdapter10_2`

### 错误2：槽位数量不足

```ini
; ❌ 错误：只填了3个槽位，DX12 槽位缺失
HKR,, UserModeDriverName, %REG_MULTI_SZ%, "%11%\jmUmd11_64.dll", "%11%\jmUmd11_64.dll", "%11%\jmUmd12_64.dll"
```

### 错误3：DX11 槽位填了 DX12 DLL

```ini
; ❌ 错误：slot[2]=jmUmd12，但 jmUmd12 没有 OpenAdapter10_2
HKR,, UserModeDriverName, %REG_MULTI_SZ%, "%11%\jmUmd11_64.dll", "%11%\jmUmd11_64.dll", "%11%\jmUmd12_64.dll", "%11%\jmUmd12_64.dll"
```

## 验证方法

安装驱动后，用 PowerShell 读取注册表验证槽位：

```powershell
$key = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
$val = (Get-ItemProperty $key).UserModeDriverName
$val | ForEach-Object -Begin {$i=0} -Process { "slot[$i] = $_"; $i++ }
# 期望输出：
# slot[0] = C:\Windows\System32\jmUmd11_64.dll   (DX9)
# slot[1] = C:\Windows\System32\jmUmd11_64.dll   (DX10)
# slot[2] = C:\Windows\System32\jmUmd11_64.dll   (DX11) ← 必须是 DX11 UMD
# slot[3] = C:\Windows\System32\jmUmd12_64.dll   (DX12)
```

也可用 WinDbg 直接验证 `D3DKMTQueryAdapterInfo` 返回：

```windbg
; 在 dxgi!CDXGIBaseAdapter::LoadUMD+0xd9 处打印 rcx（LoadLibraryExW 的路径参数）
bp dxgi!CDXGIBaseAdapter::LoadUMD+0xd9 ".printf \"[version=%d] Loading: %mu\n\", @edx, @rcx; g"
```

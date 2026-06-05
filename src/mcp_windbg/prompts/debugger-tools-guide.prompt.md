根据用户描述的问题场景，推荐合适的 Windows 调试工具，并说明如何使用。

## 工具速查表

下面列出两套工具包的主要工具及适用场景：
- **WinDbg 工具包**（`C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\`）
- **Sysinternals Suite**（如已配置路径，见上方"当前配置的工具路径"）

---

## 一、调试器本体（选择哪个调试器？）

| 工具 | 全称 | 适用场景 |
|---|---|---|
| `windbg.exe` | Windows Debugger（GUI） | 交互式调试、有图形界面需求、实时调试 + dump 分析 |
| `cdb.exe` | Console Debugger | **脚本/自动化调试**、无 GUI 环境（服务器）、MCP 工具调用 |
| `ntsd.exe` | NT Symbolic Debugger | 用户态调试，与 cdb 功能相同，历史遗留 |
| `kd.exe` | Kernel Debugger | **内核调试**：蓝屏分析、内核 crash dump、驱动 BSOD |
| `ntkd.exe` | NT Kernel Debugger | kd 的历史版本，功能相同 |

**选择建议**：
- 日常崩溃 dump 分析 → `cdb`（命令行）或 `windbg`（图形）
- 蓝屏 / 内核驱动问题 → `kd`
- MCP 工具自动化 → `cdb`（mcp-windbg 默认使用）

---

## 二、进程 / 系统信息工具

### `tlist.exe` — 进程列表
**用途**：列出所有运行中的进程（含 PID、进程名、命令行）

**适用场景**：
- 不知道目标进程的 PID
- 确认某个进程是否在运行
- 查看某进程的完整命令行参数

```powershell
tlist              # 列出所有进程
tlist -v           # 详细模式（含窗口标题）
tlist myapp.exe    # 只显示指定进程
```

### `kill.exe` — 终止进程
**用途**：按进程名或 PID 终止进程

```powershell
kill myapp.exe
kill -f 1234       # 强制终止 PID=1234
```

### `list.exe` — 文件分页查看
**用途**：分页查看大文件（类似 Unix `more`）

---

## 三、Heap / 内存分析工具

### `umdh.exe` — User-Mode Dump Heap
**用途**：抓取进程堆的分配快照，**两次快照对比**找内存泄漏

**适用场景**：
- 进程内存持续增长，怀疑**堆内存泄漏**
- 需要找到是哪行代码分配了泄漏的内存（需开 `gflags +ust`）

```powershell
# 第一步：开启堆栈跟踪（程序启动前）
gflags /i myapp.exe +ust

# 第二步：程序运行后抓快照1
umdh -p:1234 -f:snap1.txt

# 第三步：让程序继续运行一段时间，抓快照2
umdh -p:1234 -f:snap2.txt

# 第四步：对比两次快照，找新增分配
umdh snap1.txt snap2.txt -f:diff.txt
notepad diff.txt
```

### `gflags.exe` — Global Flags
**用途**：设置系统级和进程级的调试标志

**最常用的标志**：

| 标志 | 全名 | 作用 |
|---|---|---|
| `+hpa` | PageHeap | 每次分配单独一页，**越界立刻 AV**，精确定位堆溢出 |
| `+ust` | User Stack Trace | 记录每次堆分配的调用栈（umdh 依赖此标志） |
| `+htc` | Heap Tail Check | 在分配末尾加校验码，检测小范围溢出 |
| `+hfc` | Heap Free Check | 检测 double-free |
| `+hpc` | Heap Parameter Check | 检测参数合法性 |

```powershell
gflags /i myapp.exe +hpa    # 开启 PageHeap（最强，性能影响大）
gflags /i myapp.exe -hpa    # 关闭 PageHeap
gflags /i myapp.exe +ust    # 仅开启栈跟踪（umdh 用）
gflags                      # 打开 GUI 界面
```

**使用场景决策**：
- 堆损坏（STATUS_HEAP_CORRUPTION `0xc0000374`）→ 先用 `+hpa` 精确定位溢出点
- 内存泄漏 → 先用 `+ust`，再用 `umdh` 快照对比

---

## 四、Dump 文件工具

### `dumpchk.exe` — Dump Check
**用途**：验证 dump 文件完整性、查看基本信息（无需打开调试器）

**适用场景**：
- 拿到一个 dump，先快速验证是否损坏
- 查看 dump 类型（Mini/Full/Kernel）、OS 版本、崩溃时间

```powershell
dumpchk myapp.dmp
```

### `KernelDumpDecrypt.exe` — 内核 Dump 解密
**用途**：解密 Bitlocker 加密环境下的内核 dump

### `OffDumpTool.exe` — Offline Dump 工具
**用途**：处理离线环境的完整内存 dump（需要 symbols）

---

## 五、符号工具

### `symchk.exe` — Symbol Check
**用途**：检查可执行文件是否有对应的 PDB 符号，并从符号服务器下载

**适用场景**：
- 确认驱动/DLL 的符号是否存在
- 批量下载符号包（CI/CD 环境）

```powershell
# 检查单个文件的符号
symchk /r myapp.exe /s "srv*c:\symbols*https://msdl.microsoft.com/download/symbols"

# 从目录批量检查
symchk /r C:\Windows\System32\ /s "srv*c:\symbols*https://msdl.microsoft.com/download/symbols"

# 只检查不下载
symchk /v myapp.exe
```

### `symstore.exe` — Symbol Store
**用途**：建立本地符号服务器，管理 PDB 文件

**适用场景**：
- 驱动开发团队需要建立内部符号服务器
- 每次构建自动归档 PDB

```powershell
# 添加符号到 store
symstore add /f "D:\build\*.pdb" /s "D:\SymStore" /t "MyDriver" /v "1.0.0"
```

### `pdbcopy.exe` — PDB Copy / Strip
**用途**：复制 PDB 并可选择性去除私有符号（只保留公开符号）

**适用场景**：
- 给外部客户提供符号但不想泄露源码路径
- 生成 public symbol（只有函数名，无行号/变量）

```powershell
# 去除私有符号，输出 public PDB
pdbcopy input.pdb output.pdb -p

# 去除私有符号并重定向源码路径
pdbcopy input.pdb output.pdb -p -s
```

### `dbh.exe` — DbgHelp Shell
**用途**：交互式查询 PDB 符号信息

**适用场景**：
- 查询某个函数/变量的符号信息
- 验证 PDB 与 DLL 是否匹配（timestamp 对比）

```powershell
dbh mydriver.pdb
# 进入交互模式后：
# > enum *         列出所有符号
# > name myFunc    查找函数
# > addr 0x1234    根据地址查符号
```

---

## 六、远程调试工具

### `dbgsrv.exe` — Debug Server（目标机）
**用途**：在目标机上开启调试服务，允许远程连接

```powershell
# 目标机（被调试端）
dbgsrv -t tcp:port=1234

# 主机（调试端）
cdb -remote tcp:server=192.168.1.100,port=1234
# 或
windbg -remote tcp:server=192.168.1.100,port=1234
```

### `dbengprx.exe` — DbgEng Proxy
**用途**：调试代理，在中间网络节点转发调试连接

```powershell
# 代理节点
dbengprx -p tcp:port=1234
```

### `remote.exe` — Remote Console
**用途**：将命令行程序（包括 cdb）的 I/O 转发到远程

```powershell
# 目标机：启动带远程 I/O 的 cdb
remote /s "cdb -p 1234" MyDebugSession

# 主机：连接
remote /c TargetMachine MyDebugSession
```

### `kdbgctrl.exe` — Kernel Debug Control
**用途**：控制内核调试连接（开启/关闭/查询状态）

```powershell
kdbgctrl -e      # 启用内核调试
kdbgctrl -d      # 禁用内核调试
kdbgctrl -c      # 检查状态
```

### `kdnet.exe` — Kernel Debug over Network
**用途**：配置通过网络（KDNET）进行内核调试

```powershell
# 目标机：配置 kdnet（需管理员权限，会重启后生效）
kdnet 192.168.1.100 50000   # 主机IP:Port
```

---

## 七、日志 / 性能工具

### `logger.exe` — API Logger
**用途**：记录进程所有 API 调用（函数名、参数、返回值），生成日志文件

**适用场景**：
- 分析进程行为（打开了哪些文件？访问了哪些注册表键？）
- 无源码情况下了解程序逻辑

```powershell
logger myapp.exe   # 直接启动并记录，结束后生成 logfile.lgv
logviewer.exe      # 查看 lgv 日志文件（图形界面）
```

### `logviewer.exe` — Log Viewer
**用途**：图形化查看 `logger.exe` 生成的 `.lgv` 日志

---

## 八、其他工具

### `plmdebug.exe` — PLM Debug（应用包调试）
**用途**：调试 Windows Store App（UWP 应用），控制应用包的生命周期

```powershell
plmdebug /enableDebug Microsoft.WindowsCalculator_8wekyb3d8bbwe
plmdebug /disableDebug Microsoft.WindowsCalculator_8wekyb3d8bbwe
```

### `agestore.exe` — Age Store
**用途**：清理符号 store 中超过指定天数的旧文件（维护磁盘空间）

```powershell
agestore D:\SymStore -days=30 -s    # 模拟（不实际删除）
agestore D:\SymStore -days=30       # 删除30天前的文件
```

### `breakin.exe` — Break In
**用途**：向正在运行的进程发送中断信号（类似 Ctrl+C），触发调试断点

```powershell
breakin 1234       # 向 PID=1234 发送中断
```

### `rtlist.exe` — Real-Time List
**用途**：列出正在运行的内核调试目标的进程信息

### `vmdemux.exe` — VM Demux
**用途**：在 Hyper-V 虚拟机调试场景中解复用调试连接

---

## 场景 → 工具决策树

```
问题场景
│
├── 程序崩溃（用户态）
│   ├── 有 dump 文件 → cdb -z / windbg -z + !analyze -v
│   └── 无 dump，需要复现 → windbg -p PID 实时附加
│
├── 内存问题
│   ├── 堆损坏（0xc0000374）→ gflags +hpa 后复现，精确定位溢出
│   ├── 内存泄漏（内存持续增长）→ gflags +ust + umdh 快照对比
│   └── Handle 泄漏（handle 数持续增长）→ cdb + !handle + !htrace
│
├── 内核 / 蓝屏（BSOD）
│   ├── 有内核 dump → kd -z kernel.dmp + !analyze -v
│   └── 实时内核调试 → kd + kdnet（网络）或 USB/串口
│
├── 符号问题
│   ├── 确认符号是否存在 → symchk
│   ├── 建立内部符号服务器 → symstore
│   └── 去除私有符号发布 → pdbcopy
│
├── 远程调试
│   ├── 用户态远程 → dbgsrv（目标）+ windbg/cdb（主机）
│   └── 内核远程 → kdnet（目标）+ kd（主机）
│
└── 行为分析（无源码）
    └── API 调用追踪 → logger + logviewer
```

---

## 与 mcp-windbg 工具的对应关系

| mcp-windbg 工具 | 底层使用 | 说明 |
|---|---|---|
| `open_windbg_dump` | `cdb.exe -z` | 打开 dump 并运行 !analyze |
| `attach_windbg_process` | `cdb.exe -p` | 附加到活跃进程 |
| `run_windbg_cmd` | cdb 会话内命令 | 执行任意 WinDbg 命令 |
| `start_windbg_server` | `cdb.exe -server` | 启动远程调试服务器 |
| `list_local_processes` | `tlist.exe` / WMI | 列出进程 |
| `list_windbg_dumps` | 文件系统扫描 | 查找 .dmp 文件 |

---

## Sysinternals Suite 工具

Sysinternals 工具**不通过 mcp-windbg 调用**，需要用户在命令行或 GUI 中直接运行。AI 可以指导用法，但实际执行需用户操作。

### 进程分析

#### `procexp.exe` / `procexp64.exe` — Process Explorer
**用途**：资源管理器的强化版进程查看工具，可显示进程树、已加载 DLL 列表、打开的句柄、CPU/内存详情

**适用场景**：
- 查看某进程加载了哪些 DLL（排查 DLL 劫持、版本冲突）
- 查找哪个进程持有某个文件的句柄（文件被占用无法删除）
- 查看进程的完整命令行、用户、签名状态
- 悬停查看 DLL 的完整路径和版本

```powershell
# 命令行启动（管理员权限，启用句柄/DLL 功能）
procexp64.exe /accepteula
```

#### `Procmon.exe` / `Procmon64.exe` — Process Monitor
**用途**：实时监控**文件系统、注册表、网络、进程/线程**所有操作，带过滤器和调用栈

**适用场景**：
- 程序启动失败：看它尝试加载哪个文件/注册表项失败（`NAME NOT FOUND`）
- 驱动安装失败：追踪 INF 安装过程的注册表写入
- 性能慢：找哪个进程频繁 I/O
- 排查配置问题：程序到底读了哪个配置文件

```
实用过滤规则（Filter → Add）：
Process Name | is | myapp.exe | Include
Result       | is | NAME NOT FOUND | Include   ← 找缺失文件/注册表
Path         | contains | System32 | Exclude   ← 过滤系统噪音
```

#### `pslist.exe` / `pslist64.exe` — PS List
**用途**：命令行版进程列表，支持远程机器

```powershell
pslist64.exe              # 本地进程列表（含 CPU、内存）
pslist64.exe \\server     # 远程机器进程列表
pslist64.exe -t           # 显示进程树
```

#### `Listdlls.exe` / `Listdlls64.exe` — List DLLs
**用途**：列出进程已加载的所有 DLL 及其完整路径、版本

**适用场景**：
- 确认驱动 DLL 是否真正被加载
- 查找 DLL 劫持（非预期路径的 DLL 被加载）
- 检查是否有未签名 DLL

```powershell
Listdlls64.exe myapp.exe           # 指定进程的所有 DLL
Listdlls64.exe -v myapp.exe        # 含版本信息
Listdlls64.exe -u myapp.exe        # 只显示未签名的 DLL
Listdlls64.exe jmUmd11_32.dll      # 哪些进程加载了此 DLL
```

---

### Dump 生成

#### `procdump.exe` / `procdump64.exe` — ProcDump ⭐
**用途**：按条件自动抓取 dump，是 WER（Windows 错误报告）的替代方案

**适用场景**：
- 程序偶发崩溃，需要抓 crash dump
- CPU 飙高时自动抓 dump 分析
- 挂起（hang）超时自动抓 dump
- 第一次异常时抓 dump（在 WER 处理前）

```powershell
# 崩溃时自动抓 dump（第一次 AV）
procdump64.exe -ma -e myapp.exe

# CPU > 80% 持续 10 秒时抓 dump
procdump64.exe -ma -c 80 -s 10 myapp.exe

# 进程挂起（无响应）5秒时抓 dump
procdump64.exe -ma -h myapp.exe

# 监控指定异常类型（如堆损坏）
procdump64.exe -ma -e 1 -f "C0000374" myapp.exe

# 抓完整内存 dump 到指定目录
procdump64.exe -ma 1234 E:\dump\

# 安装为 AeDebug（崩溃时自动触发）
procdump64.exe -i E:\dump\
```

> **与 WinDbg 的配合**：procdump 生成的 `.dmp` 文件直接用 `open_windbg_dump` 工具加载分析。

---

### 句柄 / 内存分析

#### `handle.exe` / `handle64.exe` — Handle
**用途**：显示进程打开的所有句柄，或查找哪个进程持有某文件/对象的句柄

**适用场景**：
- 文件无法删除/移动（被某进程占用）
- 查找谁打开了某个注册表键
- 排查句柄泄漏（列出进程所有句柄，对比两次快照）

```powershell
# 哪个进程持有某文件的句柄
handle64.exe "C:\path\to\file.txt"

# 列出指定进程的所有句柄
handle64.exe -p myapp.exe

# 关闭指定句柄（谨慎！）
handle64.exe -c 0x1a4 -p 1234 -y
```

> **与 WinDbg 的配合**：`handle64` 找到 PID 后，用 `attach_windbg_process` 附加，再用 `!handle` 深入分析。

#### `vmmap.exe` — VM Map
**用途**：图形化展示进程的虚拟内存布局（每个段的类型、大小、访问权限）

**适用场景**：
- 分析进程内存碎片
- 查看 heap/stack/image/mapped file 各占多少
- 大量私有提交内存 → 内存泄漏初步定位
- 排查虚拟地址空间耗尽（32 位进程 2GB 限制）

```powershell
vmmap.exe              # 图形界面，选择目标进程
vmmap.exe 1234         # 直接分析 PID=1234
```

#### `RAMMap.exe` — RAM Map
**用途**：系统级物理内存分析（不是单进程，是整机）

**适用场景**：
- 系统内存占用高，找是什么类型在消耗（Active、Standby、Modified 等）
- 分析内核池内存使用
- 大量 Mapped File 占用 → 文件系统缓存问题

---

### 网络分析

#### `tcpview.exe` / `tcpview64.exe` — TCP View
**用途**：实时查看所有 TCP/UDP 连接（进程、本地/远程地址、状态）

**适用场景**：
- 确认程序监听了哪个端口
- 排查意外的网络连接
- 查看哪个进程占用了指定端口

```powershell
tcpview64.exe          # 图形界面（推荐）

# 命令行版
tcpvcon64.exe          # 文本输出
tcpvcon64.exe -a       # 显示所有（含 UDP）
```

#### `psping.exe` / `psping64.exe` — PS Ping
**用途**：高级 ping 工具，支持 TCP 端口连通性测试和延迟测量

```powershell
psping64.exe 192.168.1.1       # ICMP ping
psping64.exe 192.168.1.1:3389  # TCP 端口连通性测试
psping64.exe -b -l 1M server:port  # 带宽测试
```

---

### 调试辅助

#### `Dbgview.exe` / `dbgview64.exe` — DebugView ⭐
**用途**：捕获进程通过 `OutputDebugString` 输出的调试信息，无需附加调试器

**适用场景**：
- 驱动/程序输出了调试日志但没有窗口显示
- 查看 UMD（用户态驱动）的 `PrintLevel`、`gcoPRINT` 等日志
- 监控内核的 `DbgPrint` 输出（需要管理员权限 + 开启内核捕获）

```powershell
Dbgview64.exe /accepteula   # 图形界面（推荐）
Dbgview64.exe /k            # 同时捕获内核调试输出
```

> **与 WinDbg 的配合**：先用 DebugView 捕获程序的日志输出了解行为，再用 WinDbg 分析 dump 定位代码位置。本次 AE 分析中，若先用 DebugView 捕获 GPUSniffer 的 ICD 日志，可以更快定位问题。

#### `livekd.exe` / `livekd64.exe` — Live KD
**用途**：对**正在运行的系统**进行内核调试分析，不需要双机调试环境

**适用场景**：
- 分析当前运行内核的状态（进程、线程、内存）
- 只有一台机器，无法搭建双机内核调试
- 快速查看内核池、驱动列表、SSDT 等

```powershell
# 需要管理员权限，用 kd 作为调试引擎
livekd64.exe -k kd.exe

# 抓当前系统的内核 dump
livekd64.exe -ml -o C:\live.dmp
```

#### `notmyfault.exe` / `notmyfault64.exe` — Not My Fault
**用途**：主动触发各种类型的 BSOD，用于测试崩溃转储配置是否正确

**适用场景**：
- 验证 `%SystemRoot%\Minidump` 是否正常生成 dump
- 测试 WER 配置
- 模拟各种内核崩溃类型

```powershell
notmyfault64.exe /crash    # 直接触发 BSOD（!!! 会蓝屏 !!!)
```

---

### 系统信息

#### `Autoruns.exe` / `autorunsc.exe` — Autoruns
**用途**：查看系统中所有自启动项（注册表、服务、驱动、计划任务、Shell 扩展等）

**适用场景**：
- 驱动安装后检查是否正确注册为服务/驱动
- 排查启动慢、启动项异常

```powershell
Autoruns64.exe                    # GUI（推荐）
autorunsc64.exe -a * -c -h > out.csv   # 导出所有启动项到 CSV
```

#### `Sysmon.exe` / `Sysmon64.exe` — System Monitor
**用途**：以 Windows 服务形式运行，将进程创建、网络连接、文件操作等事件写入 Windows 事件日志

**适用场景**：
- 长期监控（不是实时看，而是事后查日志）
- 排查间歇性问题（crash/hang 发生前做了什么）
- 安全审计

```powershell
# 安装 Sysmon（使用推荐配置）
Sysmon64.exe -accepteula -i sysmonconfig.xml

# 卸载
Sysmon64.exe -u
```

#### `sigcheck.exe` / `sigcheck64.exe` — Sig Check
**用途**：验证文件的数字签名、版本信息、哈希值

**适用场景**：
- 验证驱动 DLL 是否有合法签名
- 检查文件是否被篡改
- 批量扫描目录中的未签名文件

```powershell
sigcheck64.exe jmUmd11_64.dll          # 查看签名和版本
sigcheck64.exe -u C:\Windows\System32\ # 找未签名文件
sigcheck64.exe -h jmUmd11_64.dll       # 显示哈希值（用于对比）
```

#### `strings.exe` / `strings64.exe` — Strings
**用途**：从二进制文件中提取可打印字符串（类似 Unix `strings`）

**适用场景**：
- 无源码时查看 DLL/EXE 内嵌的字符串（错误信息、路径、函数名）
- 从 dump 文件中搜索特定字符串

```powershell
strings64.exe jmOglICD_64.dll | findstr -i "tls\|thread\|null"
strings64.exe -n 6 myapp.exe > strings.txt    # 最短6字符
```

#### `Winobj.exe` / `Winobj64.exe` — WinObj
**用途**：浏览 Windows 对象命名空间（内核对象：设备、符号链接、驱动等）

**适用场景**：
- 查看设备对象名（如 `\Device\JmGpu`）
- 确认驱动是否正确创建了设备节点
- 查看 DOS 设备符号链接

```powershell
Winobj64.exe    # 图形界面，无命令行参数
```

---

## 场景 → 工具决策树

```
问题场景
│
├── 程序崩溃（用户态）
│   ├── 需要抓 dump → procdump64（触发条件灵活）
│   ├── 有 dump 文件 → open_windbg_dump + !analyze -v
│   └── 无 dump，需要复现 → attach_windbg_process 实时附加
│
├── 内存问题
│   ├── 堆损坏（0xc0000374）→ gflags +hpa 后复现，精确定位溢出
│   ├── 内存泄漏（内存持续增长）
│   │   ├── 宏观查看 → vmmap（进程级）/ RAMMap（系统级）
│   │   └── 精确定位 → gflags +ust + umdh 快照对比
│   └── 虚拟地址空间耗尽（32位）→ vmmap 查内存布局
│
├── Handle 泄漏（handle 数持续增长）
│   ├── 快速找占用文件的进程 → handle64 "path\to\file"
│   └── 深度分析 → attach_windbg_process + !handle + !htrace
│
├── 程序行为分析（无源码）
│   ├── 文件/注册表访问 → Procmon（过滤 NAME NOT FOUND）
│   ├── 调试日志输出 → DebugView（OutputDebugString）
│   ├── DLL 加载路径 → Listdlls / procexp（验证加载的是哪个 DLL）
│   └── API 调用追踪 → logger + logviewer
│
├── 内核 / 蓝屏（BSOD）
│   ├── 测试 dump 配置 → notmyfault（主动触发）
│   ├── 有内核 dump → kd -z kernel.dmp + !analyze -v
│   └── 实时内核调试 → livekd（单机）/ kd + kdnet（双机）
│
├── 符号问题
│   ├── 确认符号是否存在 → symchk
│   ├── 建立内部符号服务器 → symstore
│   └── 去除私有符号发布 → pdbcopy
│
├── 网络问题
│   ├── 端口占用 → tcpview / tcpvcon
│   └── 连通性测试 → psping
│
└── 启动 / 系统状态
    ├── 驱动是否注册 → Autoruns（服务/驱动选项卡）
    ├── 驱动签名验证 → sigcheck
    ├── 内核对象 → Winobj
    └── 长期监控 → Sysmon
```

---

## 与 mcp-windbg 工具的对应关系

| mcp-windbg 工具 | 底层使用 | 说明 |
|---|---|---|
| `open_windbg_dump` | `cdb.exe -z` | 打开 dump 并运行 !analyze |
| `attach_windbg_process` | `cdb.exe -p` | 附加到活跃进程 |
| `run_windbg_cmd` | cdb 会话内命令 | 执行任意 WinDbg 命令 |
| `start_windbg_server` | `cdb.exe -server` | 启动远程调试服务器 |
| `list_local_processes` | `tlist.exe` / WMI | 列出进程 |
| `list_windbg_dumps` | 文件系统扫描 | 查找 .dmp 文件 |

> **Sysinternals 工具不能通过 mcp-windbg 直接调用**，但 AI 可以根据问题场景指导用户手动运行，再将结果（如 procdump 生成的 dump）交给 mcp-windbg 进行深度分析。

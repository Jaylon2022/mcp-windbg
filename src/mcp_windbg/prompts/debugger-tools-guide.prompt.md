根据用户描述的问题场景，推荐合适的 Windows 调试工具，并说明如何使用。

## 工具速查表

下面列出 Windows Debugger 工具包（`C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\`）中的主要工具及其适用场景。

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

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

### 自动化原则

> **[🤖 可自动化]** — CLI 工具，AI 可直接在终端中执行，结果可被解析和后续处理。  
> **[🖱️ 需手动操作]** — GUI 工具，AI 提供详细的界面操作步骤，用户按步骤执行后将结果反馈给 AI。

使用命令时，将 `$SYS` 替换为上方"当前配置的工具路径"中的 Sysinternals 目录（如 `E:\BaiduNetdiskDownload\SysinternalsSuite`）。

---

### 进程分析

#### [🤖 可自动化（后台静默采集）/ 🖱️ 需手动操作（实时过滤）] `Procmon64.exe` — Process Monitor ⭐

**适用场景**：程序启动失败（找缺失文件/注册表）、驱动安装行为追踪、I/O 性能分析

**自动化采集模式**（AI 可执行，适合后台记录再分析）：
```powershell
# 1. 后台静默采集到文件（最小化窗口，不弹交互）
$SYS\Procmon64.exe /accepteula /quiet /minimized /backingfile C:\procmon.pml

# 2. 复现问题...（让用户执行触发操作）

# 3. 停止采集
$SYS\Procmon64.exe /terminate

# 4. 将 .pml 转换为 CSV（AI 可解析）
$SYS\Procmon64.exe /accepteula /openlog C:\procmon.pml /saveas C:\procmon.csv

# 5. 过滤关键事件（NAME NOT FOUND = 文件/注册表缺失）
Select-String -Path C:\procmon.csv -Pattern "NAME NOT FOUND" | Select-Object -First 30
```

**图形界面操作步骤**（实时交互过滤时）：
1. 以管理员身份运行 `Procmon64.exe /accepteula`
2. **添加过滤器**：Filter → Filter... → 按以下规则添加：
   - `Process Name | is | myapp.exe | Include`（只看目标进程）
   - `Result | is | NAME NOT FOUND | Include`（找缺失资源）
   - `Path | contains | System32 | Exclude`（过滤系统噪音）
3. **触发问题**，观察红色的 `NAME NOT FOUND` 行
4. **查看调用栈**：双击某行 → Event → Stack 选项卡
5. **保存**：File → Save → All events → 保存 `.pml` 文件交给 AI 转换分析



```powershell
# 列出所有进程（含 CPU%、内存、线程数）
$SYS\pslist64.exe /accepteula

# 显示进程树
$SYS\pslist64.exe /accepteula -t

# 查找特定进程
$SYS\pslist64.exe /accepteula myapp.exe

# 持续监控（每2秒刷新）
$SYS\pslist64.exe /accepteula -s 2
```

#### [🤖 可自动化] `Listdlls64.exe` — 列出已加载 DLL

**适用场景**：确认驱动 DLL 是否真正被加载、查找 DLL 劫持（非预期路径）

```powershell
# 查看指定进程加载的所有 DLL（含完整路径和版本）
$SYS\Listdlls64.exe /accepteula -v myapp.exe

# 只显示未签名的 DLL（发现可疑项）
$SYS\Listdlls64.exe /accepteula -u myapp.exe

# 反向查询：哪些进程加载了某个 DLL
$SYS\Listdlls64.exe /accepteula jmUmd11_32.dll

# 输出到文件便于对比
$SYS\Listdlls64.exe /accepteula -v myapp.exe > dlls.txt
```

#### [🖱️ 需手动操作] `procexp64.exe` — Process Explorer

**适用场景**：快速查看进程树、悬停查看 DLL 路径、查找文件句柄持有者

**操作步骤**：
1. 以管理员身份运行 `procexp64.exe /accepteula`
2. **查看已加载 DLL**：找到目标进程 → 双击 → 切换到 **DLLs** 选项卡 → 查看路径列
3. **查找文件占用**：菜单 Find → Find Handle or DLL... → 输入文件名 → 点击 Search
4. **查看进程命令行**：找到进程 → 右键 → Properties → Image 选项卡 → Command line
5. **验证签名**：Options → VirusTotal.com → Check VirusTotal.com（需联网）

---

### Dump 生成

#### [🤖 可自动化] `procdump64.exe` ⭐ — 按条件自动抓 Dump

**适用场景**：程序偶发崩溃、CPU 飙高、挂起（hang）、特定异常类型

```powershell
# 崩溃时自动抓完整 dump（监控进程名，第一次异常触发）
$SYS\procdump64.exe /accepteula -ma -e myapp.exe C:\dumps\

# 监控特定异常码（如堆损坏 0xC0000374）
$SYS\procdump64.exe /accepteula -ma -e 1 -f "C0000374" myapp.exe C:\dumps\

# 对运行中进程立即抓一次完整 dump（PID 替换为实际值）
$SYS\procdump64.exe /accepteula -ma 1234 C:\dumps\

# CPU > 80% 持续 10 秒时自动抓 dump
$SYS\procdump64.exe /accepteula -ma -c 80 -s 10 myapp.exe C:\dumps\

# 进程无响应（hang）5 秒时自动抓 dump
$SYS\procdump64.exe /accepteula -ma -h myapp.exe C:\dumps\

# 安装为 JIT（即时）调试器，任何进程崩溃都自动抓 dump
$SYS\procdump64.exe /accepteula -i C:\dumps\
# 卸载 JIT 调试器
$SYS\procdump64.exe /accepteula -u
```

> **与 mcp-windbg 的自动化流程**：
> ```
> procdump 自动抓到 dump → open_windbg_dump 加载 → !analyze -v 分析
> ```

---

### 句柄分析

#### [🤖 可自动化] `handle64.exe` — 句柄查询

**适用场景**：文件被占用无法删除/移动、排查句柄泄漏、查找注册表键占用者

```powershell
# 哪个进程持有某文件的句柄（最常用）
$SYS\handle64.exe /accepteula "C:\path\to\file.txt"

# 列出指定进程的所有句柄（排查句柄泄漏）
$SYS\handle64.exe /accepteula -p myapp.exe

# 只显示文件类型的句柄
$SYS\handle64.exe /accepteula -t file -p myapp.exe

# 查询注册表键的持有者
$SYS\handle64.exe /accepteula "HKLM\SYSTEM\CurrentControlSet\Services\mydriver"

# 强制关闭指定句柄（谨慎！先确认句柄 ID）
$SYS\handle64.exe /accepteula -c 0x1a4 -p 1234 -y
```

> **与 mcp-windbg 配合**：`handle64` 找到 PID 后，用 `attach_windbg_process` 附加，再用 `!handle` + `!htrace` 深入分析泄漏调用栈。

---

### 内存分析

#### [🖱️ 需手动操作] `vmmap.exe` — 进程虚拟内存布局

**适用场景**：分析内存碎片、内存泄漏宏观定位、32 位进程虚拟地址耗尽

**操作步骤**：
1. 运行 `vmmap.exe`，在弹出的进程选择对话框中选择目标进程（或输入 PID）
2. 查看顶部饼图了解内存组成（Heap / Image / Stack / Mapped File）
3. **定位泄漏**：点击 **Private Data** 列排序 → 查找大量私有提交内存的堆
4. **追踪堆**：双击某个 Heap 行 → 展开查看各块的调用栈（需要提前开启 `gflags +ust`）
5. **导出数据**：File → Save → 保存为 `.vmp` 文件用于前后对比

#### [🖱️ 需手动操作] `RAMMap.exe` — 系统物理内存分析

**适用场景**：系统内存占用高时排查、内核池分析

**操作步骤**：
1. 以管理员身份运行 `RAMMap.exe`
2. 查看 **Use Counts** 选项卡：确认 Active / Standby / Modified 各占比例
3. **内核池泄漏**：切换到 **Kernel Stacks** / **Driver Locked** 选项卡查看内核态占用
4. **文件缓存过多**：查看 **Mapped File** 行 → 考虑调整系统缓存策略
5. File → Save → 保存快照，重复后与第一次快照对比增量

---

### 网络分析

#### [🤖 可自动化] `tcpvcon64.exe` — TCP/UDP 连接列表

```powershell
# 显示所有 TCP/UDP 连接（含 PID 和进程名）
$SYS\tcpvcon64.exe /accepteula -a

# 只看 TCP 连接
$SYS\tcpvcon64.exe /accepteula

# 查找占用特定端口的进程（结合 findstr）
$SYS\tcpvcon64.exe /accepteula -a | findstr ":8080"

# 每 3 秒刷新（持续监控）
$SYS\tcpvcon64.exe /accepteula -a -n 3
```

#### [🤖 可自动化] `psping64.exe` — 网络连通性测试

```powershell
# ICMP ping
$SYS\psping64.exe /accepteula 192.168.1.1

# TCP 端口连通性测试（无需 ICMP 权限）
$SYS\psping64.exe /accepteula 192.168.1.1:3389

# 延迟统计（100次）
$SYS\psping64.exe /accepteula -n 100 192.168.1.1:443

# 带宽测试（需目标机也运行 psping -s）
$SYS\psping64.exe /accepteula -b -l 1M 192.168.1.1:5000
```

#### [🖱️ 需手动操作] `tcpview64.exe` — 实时网络连接监控

**操作步骤**：
1. 以管理员身份运行 `tcpview64.exe /accepteula`
2. **查找端口占用**：View → Filter... → 输入端口号（如 `8080`）
3. **按进程过滤**：右键某进程 → Filter to this process
4. **监控新连接**：红色 = 刚关闭，绿色 = 刚建立（自动高亮）
5. **导出当前状态**：File → Save → 保存为文本文件

---

### 调试辅助

#### [🖱️ 需手动操作，支持后台静默采集] `Dbgview64.exe` ⭐ — OutputDebugString 捕获

**适用场景**：捕获驱动/程序通过 `OutputDebugString` / `DbgPrint` 输出的调试日志，无需附加调试器

**自动化采集方式（后台静默）**：
```powershell
# 静默启动 DebugView，捕获用户态+内核态日志，自动保存到文件
# （需要管理员权限才能捕获内核日志）
$SYS\Dbgview64.exe /accepteula /q /l C:\dbgview.log /k
# /q = 静默（不弹窗）  /l = 日志文件路径  /k = 捕获内核输出
# 程序运行完成后，Ctrl+C 停止 DebugView，然后读取日志文件
```

**图形界面操作步骤**（实时查看时）：
1. 以管理员身份运行 `Dbgview64.exe /accepteula`
2. **开启内核捕获**：Capture → Capture Kernel（需管理员）
3. **设置过滤**：Edit → Filter/Highlight → Include 填入关键词（如 `jmOgl`、`ICD`）
4. **保存日志**：File → Save As → 保存为 `.log` 文件，将文件路径告诉 AI 分析

#### [🤖 可自动化] `livekd64.exe` — 实时内核快照分析

```powershell
# 对当前运行的系统抓一次内核 dump（无需重启/双机）
# 需要管理员权限
$SYS\livekd64.exe /accepteula -ml -o C:\live_kernel.dmp

# 抓完后用 mcp-windbg 的 open_windbg_dump 分析（指定 kd 路径）
# open_windbg_dump("C:\live_kernel.dmp")
```

#### [🤖 可自动化] `sigcheck64.exe` — 签名验证

```powershell
# 验证单个文件的签名和版本信息
$SYS\sigcheck64.exe /accepteula -a jmUmd11_64.dll

# 扫描目录下所有未签名文件（排查 DLL 劫持）
$SYS\sigcheck64.exe /accepteula -u -e C:\Windows\System32\

# 显示文件哈希（MD5/SHA1/SHA256，用于前后对比）
$SYS\sigcheck64.exe /accepteula -h jmUmd11_64.dll

# 输出 CSV 便于后续分析
$SYS\sigcheck64.exe /accepteula -a -h -c jmUmd11_64.dll > sig.csv
```

#### [🤖 可自动化] `strings64.exe` — 二进制字符串提取

```powershell
# 提取 DLL 中的所有字符串（默认最短3字符）
$SYS\strings64.exe /accepteula jmOglICD_64.dll

# 过滤关键词（无源码时快速了解模块功能）
$SYS\strings64.exe /accepteula jmOglICD_64.dll | findstr /i "tls thread null error"

# 最短6字符（减少噪音）
$SYS\strings64.exe /accepteula -n 6 myapp.exe > strings.txt

# 从 dump 文件中搜索字符串（不用打开调试器）
$SYS\strings64.exe /accepteula -n 8 crash.dmp | findstr /i "corrupt heap"
```

---

### 系统信息

#### [🤖 可自动化] `autorunsc64.exe` — 启动项导出

**适用场景**：驱动安装后验证服务是否注册、批量导出启动项供 AI 分析

```powershell
# 导出所有启动项到 CSV（AI 可直接分析）
$SYS\autorunsc64.exe /accepteula -a * -c -h -s > autoruns.csv

# 只看驱动和服务
$SYS\autorunsc64.exe /accepteula -a d -c > drivers.csv

# 只看未签名的启动项
$SYS\autorunsc64.exe /accepteula -u -c > unsigned.csv

# 验证指定驱动是否已注册（过滤关键词）
$SYS\autorunsc64.exe /accepteula -a d -c | findstr /i "jm\|jingjia"
```

#### [🖱️ 需手动操作] `Autoruns64.exe` — 启动项图形界面

**操作步骤**（查看驱动注册状态时）：
1. 以管理员身份运行 `Autoruns64.exe /accepteula`
2. 切换到 **Drivers** 选项卡
3. 查找目标驱动（Ctrl+F 搜索 `jm` 或驱动名）
4. 黄色底色 = 文件不存在但有注册项（残留），红色 = 签名问题
5. **导出**：File → Save → 保存 `.arn` 文件，可后续重新打开或 diff

#### [🤖 可自动化] `Sysmon64.exe` — 系统监控服务

```powershell
# 安装 Sysmon（使用基础配置）
$SYS\Sysmon64.exe /accepteula -i

# 安装并指定配置文件（推荐 SwiftOnSecurity 配置）
$SYS\Sysmon64.exe /accepteula -i sysmonconfig.xml

# 查询 Sysmon 当前状态
$SYS\Sysmon64.exe -s

# 查询最近的事件（事件ID 1=进程创建，3=网络，7=DLL加载）
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 |
    Where-Object { $_.Id -eq 7 } |   # 7 = DLL 加载
    Select-Object TimeCreated, Message |
    Format-List

# 卸载
$SYS\Sysmon64.exe -u
```

#### [🤖 可自动化] `notmyfaultc64.exe` — 触发 BSOD（控制台版）

```powershell
# 触发 BSOD 测试 dump 配置（!!! 机器会立即蓝屏重启 !!!)
# 确保已配置 dump 路径再执行
$SYS\notmyfaultc64.exe /crash

# 验证 dump 是否生成（蓝屏重启后）
dir $env:SystemRoot\Minidump\*.dmp
dir $env:SystemRoot\memory.dmp
```

#### [🖱️ 需手动操作] `Winobj64.exe` — 内核对象命名空间浏览

**适用场景**：确认驱动设备节点是否创建、查看符号链接

**操作步骤**：
1. 以管理员身份运行 `Winobj64.exe`
2. **查看设备节点**：左侧树展开 `\Device\` → 右侧查找驱动创建的设备（如 `JmGpu`）
3. **查看符号链接**：展开 `\GLOBAL??` → 查看 DOS 设备名映射（如 `\\.\JmGpu` 对应哪个 `\Device\...`）
4. **验证驱动注册**：展开 `\Driver\` → 确认驱动对象存在
5. 右键任意对象 → Properties → 查看对象类型、引用计数、安全描述符

---

## 场景 → 工具决策树

> 🤖 = AI 可自动执行命令  
> 🖱️ = 需用户手动操作图形界面

```
问题场景
│
├── 程序崩溃（用户态）
│   ├── 需要抓 dump → 🤖 procdump64（触发条件灵活，AI 直接执行）
│   ├── 有 dump 文件 → 🤖 open_windbg_dump + !analyze -v
│   └── 无 dump，需要复现 → 🤖 attach_windbg_process 实时附加
│
├── 内存问题
│   ├── 堆损坏（0xc0000374）→ 🤖 gflags +hpa 后复现，精确定位溢出
│   ├── 内存泄漏（内存持续增长）
│   │   ├── 宏观查看 → 🖱️ vmmap（进程级）/ 🖱️ RAMMap（系统级）
│   │   └── 精确定位 → 🤖 gflags +ust + 🤖 umdh 快照对比
│   └── 虚拟地址空间耗尽（32位）→ 🖱️ vmmap 查内存布局
│
├── Handle 泄漏（handle 数持续增长）
│   ├── 快速找占用文件的进程 → 🤖 handle64 "path\to\file"
│   └── 深度分析 → 🤖 attach_windbg_process + !handle + !htrace
│
├── 程序行为分析（无源码）
│   ├── 文件/注册表访问
│   │   ├── 后台静默采集 → 🤖 Procmon /quiet /backingfile → 转 CSV 分析
│   │   └── 实时过滤查看 → 🖱️ Procmon 图形界面（Filter: NAME NOT FOUND）
│   ├── 调试日志输出
│   │   ├── 后台采集到文件 → 🤖 Dbgview64 /q /l C:\log.txt /k
│   │   └── 实时查看 → 🖱️ DebugView 图形界面
│   ├── DLL 加载路径 → 🤖 Listdlls64 -v（验证加载的是哪个 DLL）
│   └── 字符串/内嵌信息 → 🤖 strings64 | findstr
│
├── 内核 / 蓝屏（BSOD）
│   ├── 测试 dump 配置 → 🤖 notmyfaultc64 /crash（!!! 会蓝屏 !!!）
│   ├── 有内核 dump → 🤖 open_windbg_dump（kd 模式）+ !analyze -v
│   └── 实时内核分析 → 🤖 livekd64 -ml -o dump.dmp（单机抓快照）
│
├── 符号问题
│   ├── 确认符号是否存在 → 🤖 symchk
│   ├── 建立内部符号服务器 → 🤖 symstore
│   └── 去除私有符号发布 → 🤖 pdbcopy
│
├── 网络问题
│   ├── 端口占用 → 🤖 tcpvcon64 -a | findstr ":PORT"
│   ├── 实时连接监控 → 🖱️ tcpview64 图形界面
│   └── 连通性测试 → 🤖 psping64
│
├── 签名 / 完整性验证
│   └── → 🤖 sigcheck64 -a -h
│
└── 启动 / 系统状态
    ├── 驱动是否注册 → 🤖 autorunsc64 -a d -c | findstr 驱动名
    ├── 图形化查看启动项 → 🖱️ Autoruns64（Drivers 选项卡）
    ├── 内核对象/设备节点 → 🖱️ Winobj64（仅图形界面）
    └── 长期事件监控 → 🤖 Sysmon64 安装 + Get-WinEvent 查询
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

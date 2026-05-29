Perform a systematic memory leak analysis on a Windows process using WinDbg/CDB, covering both live process inspection and full-heap crash dump analysis.

## CHOOSING YOUR ANALYSIS PATH

Before starting, determine which scenario applies:

| Scenario | Approach |
|----------|----------|
| Live process that you suspect is leaking | **Path A** – Attach and inspect heaps in real time |
| Full memory dump (`.dmp` with complete heap) | **Path B** – Heap leak detection in a dump |
| Kernel pool leak | **Path C** – Kernel pool tag analysis |
| Need before/after comparison (reproducible leak) | **Path D** – UMDH snapshot diff (umdh.exe is in the same dir as cdb.exe) |

---

## PATH A — Live Process Heap Inspection

### Step 1: Identify the Target Process

**Tool:** `list_local_processes`
- Look for the suspect process by name or PID.
- Note the PID for the next step.

### Step 2: Attach to the Process

**Tool:** `attach_windbg_process`
- **Parameters:** `pid` (or `process_name`)
- After attaching, the process is paused.

### Step 3: Overall Memory Summary

**Tool:** `run_windbg_cmd` — run the following commands in sequence:

| Command | Purpose |
|---------|---------|
| `!address -summary` | Virtual memory region summary (committed, reserved, free) |
| `!heap -s` | All heap handles with committed and uncommitted sizes |
| `!heap -stat -h 0` | Per-heap allocation statistics for the default heap |

Interpret the output:
- Look for heaps with an unusually high **Committed** size.
- A steadily growing heap over time indicates a likely leak source.

### Step 4: Drill Into Suspicious Heaps

For each suspicious heap handle `<handle>` (e.g., `0x00420000`):

```
!heap -stat -h <handle>
```

This shows allocation size classes and their counts. Groups with many small allocations that keep growing are common leak patterns.

To list all active allocations in a heap:
```
!heap -h <handle>
```

To examine a specific allocation at address `<addr>`:
```
!heap -p -a <addr>
```

This shows the allocation size, the call stack at the time of allocation (if page heap is enabled), and surrounding heap metadata.

### Step 5: Check for Obvious Unreferenced Blocks (Heuristic)

```
!heap -l
```

This heuristic scan marks blocks not reachable from any stack pointer or global. **Note:** Requires a full heap; may produce false positives. It works best when GFlags page heap is enabled.

### Step 6: Resume the Process

**Tool:** `run_windbg_cmd` — command: `g`

Wait some time (minutes/hours depending on leak rate), then re-attach and repeat Steps 3–5 to compare heap sizes.

### Step 7: Detach

**Tool:** `close_windbg_process`

---

## PATH B — Full Heap Dump Analysis

### Step 1: Open the Dump

**Tool:** `open_windbg_dump`
- **Parameters:** `dump_path`, `include_modules: true`

### Step 2: Verify Heap Data is Available

**Tool:** `run_windbg_cmd` — command: `!heap -s`

If you see `Heap at 0x... is not a valid heap`, the dump is a **mini dump** and does not contain heap data. A **full user-mode dump** is required for heap analysis.

To create a full dump from Task Manager or via CDB:
```
.dump /ma /u C:\dumps\process.dmp
```

### Step 3: Heap Summary and Statistics

Run in order:

| Command | Purpose |
|---------|---------|
| `!address -summary` | Virtual memory overview |
| `!heap -s` | All heaps summary |
| `!heap -stat -h 0` | Allocation stats for default heap |
| `!heap -l` | Heuristic leak scan (may take time on large heaps) |

### Step 4: Investigate Flagged Allocations

For each address flagged by `!heap -l`:
```
!heap -p -a <address>
dd <address>
```

If page heap was active when the dump was taken, `!heap -p -a <address>` shows the **allocation call stack**, which directly identifies the leaking code path.

### Step 5: Cross-Reference with Module List

```
lm
```

Match the leaking code module against the loaded module list to identify the responsible DLL or EXE.

### Step 6: Close the Dump

**Tool:** `close_windbg_dump`

---

## PATH C — Kernel Pool Leak Analysis

For kernel drivers leaking nonpaged or paged pool memory.

### Step 1: Connect to Kernel Debugger

**Tool:** `open_windbg_kernel`
- Provide the transport string (e.g., `net:port=50000,key=1.2.3.4`).

### Step 2: Break In

**Tool:** `send_ctrl_break` — with `kernel_connection`

### Step 3: Pool Usage by Tag

```
!poolused 2
```

This sorts pool allocations by **nonpaged pool** usage, showing pool tags, allocation counts, and total bytes. Look for tags that are abnormally large compared to what a driver should use.

To see paged pool:
```
!poolused 4
```

### Step 4: Identify the Driver by Pool Tag

```
!poolfind <Tag> 0
```

Replace `<Tag>` with the 4-character pool tag (e.g., `Driv`). This lists all allocations with that tag.

To find which driver uses a given pool tag, check `%SystemRoot%\System32\drivers\pooltag.txt` or run:
```
!poolfind <Tag>
```

### Step 5: Enable Pool Tagging and Tracking (If Not Already)

On the target machine (before reproducing the leak):
```
gflags /i <processname.exe> +htc +hpa
```
Or for kernel: use Driver Verifier (`verifier /flags 0x1 /driver <driver.sys>`).

### Step 6: Disconnect

**Tool:** `close_windbg_kernel`

---

## PATH D — UMDH Snapshot Comparison (Recommended for Reproducible Leaks)

UMDH (User-Mode Dump Heap) captures call-stack-tagged allocation snapshots and produces
a diff that shows exactly which call stacks allocated memory that was never freed.

`umdh.exe` lives in the **same directory as `cdb.exe`**. Locate it first:

### D0: Locate umdh.exe

Check the standard Windows Debugging Tools install locations:

```powershell
# Most common SDK location (x64)
$umdh = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\umdh.exe"
if (Test-Path $umdh) { Write-Host "Found: $umdh" }

# Alternative x86 location
$umdh86 = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\umdh.exe"
if (Test-Path $umdh86) { Write-Host "Found: $umdh86" }
```

Or search automatically:
```powershell
Get-ChildItem "C:\Program Files (x86)\Windows Kits" -Recurse -Filter umdh.exe -ErrorAction SilentlyContinue | Select-Object FullName
Get-ChildItem "C:\Program Files\Debugging Tools*" -Recurse -Filter umdh.exe -ErrorAction SilentlyContinue | Select-Object FullName
```

Use whichever path is found (prefer the **x64** version for 64-bit targets). Substitute
`<umdh>` with the full path in all commands below.

> **Note:** `gflags.exe` is also in the same directory as `umdh.exe` and `cdb.exe`.

---

### D1: Enable User-Stack-Trace Database (UST) for the Target Process

This must be done **before** starting the process (or the process must be restarted after).

**Option 1 — Per-executable (persists across restarts):**
```
<umdh-dir>\gflags.exe /i <process.exe> +ust
```
Example: `gflags.exe /i myapp.exe +ust`

Verify it was set:
```
<umdh-dir>\gflags.exe /i <process.exe>
```
You should see `ust` listed in the flags.

**Option 2 — For already-running processes (requires page heap trick):**
UST can only be enabled before process start. If the process is already running without UST,
stop it, run the `gflags` command above, and restart it.

**Option 3 — System-wide (for services or processes you cannot easily restart):**
```
<umdh-dir>\gflags.exe /r +ust
```
(Requires reboot; remove with `/r -ust` afterward.)

---

### D2: Set the Symbol Path

UMDH resolves symbols when generating the diff. Set the symbol path in the environment
before running any UMDH commands:

```powershell
$env:_NT_SYMBOL_PATH = "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"
```

If you have private PDB files:
```powershell
$env:_NT_SYMBOL_PATH = "C:\MyApp\Symbols;srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"
```

---

### D3: Start the Target Process (with UST Enabled)

Launch the process normally. Confirm it is running:

**Tool:** `list_local_processes` — filter by process name to get the PID.

Or from PowerShell:
```powershell
Get-Process myapp | Select-Object Id, ProcessName
```

---

### D4: Take Snapshot 1 (Baseline)

Run this **before** triggering the suspected leak:
```powershell
& "<umdh>" -p:<PID> -f:C:\umdh\snap1.txt
```

Example:
```powershell
& "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\umdh.exe" -p:1234 -f:C:\umdh\snap1.txt
```

The snapshot file contains all current heap allocations tagged with their call stacks.

---

### D5: Reproduce the Leak

Trigger the operations you suspect cause the leak (e.g., run a batch of requests, open and
close documents, call an API repeatedly). The more cycles, the more obvious the diff.

---

### D6: Take Snapshot 2 (After Leak)

```powershell
& "<umdh>" -p:<PID> -f:C:\umdh\snap2.txt
```

---

### D7: Generate the Diff

```powershell
& "<umdh>" C:\umdh\snap1.txt C:\umdh\snap2.txt -f:C:\umdh\diff.txt
```

UMDH resolves symbols during diff generation (this may take a moment on first run while
downloading symbols from the symbol server).

---

### D8: Read and Interpret the Diff

Open `C:\umdh\diff.txt`. The format is:

```
+   <delta-bytes> (   <total-bytes> - <prev-bytes>) <alloc-count> allocs  BackTrace<ID>
    <size> bytes / <count> allocs @ BackTrace<ID>
        ntdll!RtlAllocateHeap+0x...
        myapp!SomeClass::DoSomething+0x...
        myapp!WorkerThread+0x...
        ...
```

**Key fields:**
| Field | Meaning |
|-------|---------|
| `+<delta-bytes>` | Bytes allocated between snap1 and snap2 for this call stack |
| `<alloc-count> allocs` | Number of live allocations from this call stack |
| `BackTrace<ID>` | Unique ID for this allocation call stack |

The entries are **sorted by delta descending** — the top entries are the biggest leakers.

**Patterns indicating a real leak:**
- High `alloc-count` with a matching size multiple (e.g., 1000 allocs × 256 bytes = 256 KB delta)
- Call stack points into your code (not just OS/CRT)
- The same call stack appears in many consecutive diffs

---

### D9: Investigate Leaking Call Stacks in WinDbg

Use `run_windbg_cmd` to attach to the process and inspect live allocations from a specific
call stack:

**Tool:** `attach_windbg_process` — attach to the leaking process.

Then:
```
!heap -stat -h 0
```
(Find the heap handle containing the most allocations.)

```
!heap -flt s <size>
```
(Filter allocations of the suspected size, e.g., `!heap -flt s 256`.)

```
!heap -p -a <address>
```
(Inspect a specific allocation — shows call stack if UST is active.)

To cross-reference a UMDH BackTrace ID with WinDbg:
```
!heap -p -t <BackTraceID>
```

**Tool:** `close_windbg_process` when done.

---

### D10: Cleanup After Investigation

Remove the UST flag when done (to avoid overhead in production):
```powershell
& "<umdh-dir>\gflags.exe" /i <process.exe> -ust
```

Verify removal:
```powershell
& "<umdh-dir>\gflags.exe" /i <process.exe>
```
Should show `0x00000000` or no flags.

---

### D11: Automate Repeated Snapshots (Optional)

For a slow leak, automate snapshot collection at intervals:

```powershell
$umdh = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\umdh.exe"
$pid  = (Get-Process myapp).Id
$dir  = "C:\umdh\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $dir | Out-Null

for ($i = 1; $i -le 5; $i++) {
    & $umdh -p:$pid -f:"$dir\snap$i.txt"
    Write-Host "Snapshot $i taken at $(Get-Date)"
    Start-Sleep -Seconds 60   # wait 1 minute between snapshots
}

# Diff first vs last
& $umdh "$dir\snap1.txt" "$dir\snap5.txt" -f:"$dir\diff_1_to_5.txt"
Write-Host "Diff written to $dir\diff_1_to_5.txt"
```

---

## REQUIRED OUTPUT FORMAT

After completing analysis, produce a structured report:

```markdown
# Memory Leak Analysis Report
**Analysis Date:** [Current Date]
**Target:** [Process name and PID, or dump file path]
**Analysis Path Used:** [A / B / C / D]

## Executive Summary
- **Leak Confirmed:** [Yes / Suspected / No evidence found]
- **Leak Rate:** [Estimated bytes/sec or MB/hour if measurable]
- **Primary Suspect:** [Module or function name]
- **Recommended Action:** [Immediate next steps]

## Memory Overview

### Virtual Memory Summary (`!address -summary`)
| Region Type | Size |
|-------------|------|
| Committed   | [MB] |
| Reserved    | [MB] |
| Free        | [MB] |

### Heap Summary (`!heap -s`)
| Heap Handle | Committed | Uncommitted | Notes |
|-------------|-----------|-------------|-------|
| [0x...]     | [MB]      | [MB]        |       |

## Leak Evidence

### Suspicious Allocations
[List allocations flagged by `!heap -l`, UMDH diff, or pool analysis]

### Allocation Call Stack (if available)
```
[Call stack from !heap -p -a or UMDH diff]
```

### Responsible Module
- **Module:** [dll/exe name]
- **Version:** [file version]
- **Function:** [suspected function]

## Root Cause Analysis
[Explain why the memory is not being freed:]
- Missing `free()` / `delete` / `Release()` call?
- Object lifetime management error (e.g., circular reference)?
- Cache growing without eviction?
- Event/callback registration without deregistration?

## Reproduction Steps
1. [How to reproduce the leak]
2. [Which operations trigger it]
3. [How fast it grows]

## Recommendations

### Immediate Fix
1. [Specific code change needed]
2. [Memory ownership rule to establish]

### Prevention
1. Use smart pointers (`std::unique_ptr`, `std::shared_ptr`) where applicable
2. Enable Application Verifier during testing (`appverif /enable Heaps /for <process.exe>`)
3. Add leak detection in CI (e.g., Valgrind on Linux counterpart, DrMemory on Windows)
4. Consider RAII patterns for all resource acquisition

## Additional Notes
[Observations about heap fragmentation, unusually large allocations, or other anomalies]
```

## COMMON LEAK PATTERNS TO LOOK FOR

| Pattern | WinDbg Signal | Fix |
|---------|--------------|-----|
| Raw pointer not freed | Many same-sized blocks from same call stack | Use `unique_ptr` |
| COM object ref count leak | `IUnknown`-derived objects accumulating | Call `Release()` |
| Circular `shared_ptr` | Growing ref-counted objects | Use `weak_ptr` for back-refs |
| STL container unbounded growth | `std::vector`/`map` with no clear/erase | Add size limits or eviction |
| Thread-local storage leak | TLS slots not freed on thread exit | `TlsFree()` in `DllMain` `THREAD_DETACH` |
| Handle leak (not heap) | `!handle` shows many open handles | Match every `CreateFile`/`OpenKey` with `CloseHandle`/`RegCloseKey` |

To check for handle leaks (not heap memory):
```
!handle 0 0f
```

Perform a systematic handle leak investigation for a Windows process using WinDbg/CDB and related tools.

Handle leaks occur when kernel objects (files, registry keys, events, mutexes, threads, processes, sockets, etc.)
are opened but never closed. They consume kernel nonpaged pool memory and system handle table entries.
Unchecked handle leaks can eventually exhaust the handle table, causing `ERROR_NO_MORE_FILES` (0x12) or
`STATUS_INSUFFICIENT_RESOURCES` on any new `Create*` / `Open*` call.

---

## STEP 1: Confirm a Handle Leak Exists

Before attaching a debugger, confirm the process is leaking handles.

### 1a. Quick Check via Task Manager

Open Task Manager → Details tab → right-click column header → add **Handles**.
Sort by Handles descending. A leaking process will show a steadily increasing count.

### 1b. PowerShell Monitor (no install required)

```powershell
$proc = Get-Process -Name myapp
while ($true) {
    $proc.Refresh()
    Write-Host "$(Get-Date -Format 'HH:mm:ss')  Handles: $($proc.HandleCount)"
    Start-Sleep -Seconds 5
}
```

If the count grows without bound, a handle leak is confirmed.

### 1c. Performance Monitor

Add the counter: **Process → Handle Count → <process name>**
Record a baseline and let it run for several minutes. A rising trend confirms the leak.

---

## STEP 2: Identify the Process and Get Its PID

**Tool:** `list_local_processes`
- Filter by name to find the suspect process.
- Record the PID for use in all subsequent steps.

---

## STEP 3: Attach WinDbg to the Process

**Tool:** `attach_windbg_process`
- **Parameters:** `pid` (or `process_name`)
- The process is paused after attaching.

---

## STEP 4: Initial Handle Census

### 4a. Total Handle Count and Type Breakdown

**Tool:** `run_windbg_cmd` — command:
```
!handle 0 0
```

Output shows: total open handles, and for each handle: handle value, type, and name (if available).

### 4b. Count by Handle Type

**Tool:** `run_windbg_cmd` — command:
```
!handle 0 0f
```

The `0f` flag dumps handle type, name, and attributes for every handle. Look for one type
dominating the count — that type is almost certainly the leaking resource.

**Common leaking handle types and their sources:**

| Handle Type | Typical API | Must be closed with |
|-------------|------------|---------------------|
| `File` | `CreateFile`, `CreateFileMapping` | `CloseHandle` |
| `Event` | `CreateEvent`, `OpenEvent` | `CloseHandle` |
| `Mutex` | `CreateMutex`, `OpenMutex` | `CloseHandle` |
| `Semaphore` | `CreateSemaphore` | `CloseHandle` |
| `Thread` | `CreateThread`, `_beginthread` | `CloseHandle` |
| `Process` | `OpenProcess`, `CreateProcess` | `CloseHandle` |
| `Key` | `RegOpenKeyEx`, `RegCreateKeyEx` | `RegCloseKey` |
| `Section` | `CreateFileMapping` | `CloseHandle` |
| `Token` | `OpenProcessToken`, `DuplicateToken` | `CloseHandle` |
| `Port` | I/O Completion Port | `CloseHandle` |
| `Socket` (Winsock) | `socket`, `accept` | `closesocket` |

### 4c. Filter by a Specific Handle Type

To list only, e.g., `File` handles:
```
!handle 0 0f File
```

To list only `Event` handles:
```
!handle 0 0f Event
```

### 4d. Inspect a Single Handle

```
!handle <handle-value> ff
```

The `ff` flag shows maximum detail: type, object address, reference count, name, and security descriptor.

---

## STEP 5: Enable Handle Tracing to Capture Allocation Stacks

WinDbg alone cannot show *where* a handle was opened unless handle tracing is active.
Enable it via GFlags — `gflags.exe` is in the same directory as `cdb.exe`.

**Find gflags.exe:**
```powershell
$gflags = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe"
if (-not (Test-Path $gflags)) {
    Get-ChildItem "C:\Program Files (x86)\Windows Kits" -Recurse -Filter gflags.exe -ErrorAction SilentlyContinue | Select-Object FullName
}
```

**Enable handle tracing for the process (before next run):**
```powershell
& $gflags /i <process.exe> +htc
```

`htc` = **Handle Trace** — records a call stack for every `NtCreateHandle` and `NtCloseHandle`.

Optionally combine with UST for full stack depth:
```powershell
& $gflags /i <process.exe> +htc +ust
```

Verify:
```powershell
& $gflags /i <process.exe>
```
Should show `htc` in the flags.

**Restart the process** with these flags active, reproduce the leak, then re-attach.

---

## STEP 6: Inspect Handle Trace with !htrace

Once `htc` is enabled and the process has been running:

### 6a. Show All Handle Operations (Recent)

**Tool:** `run_windbg_cmd` — command:
```
!htrace -enable
```

Then after reproducing the leak:
```
!htrace -snapshot
```

After another leak cycle:
```
!htrace -diff
```

`!htrace -diff` shows handles opened since the last snapshot — these are the **unclosed handles**.

### 6b. Inspect a Specific Handle's Trace

```
!htrace <handle-value>
```

Shows the full call stack at the time the handle was opened (and closed, if it was).

### 6c. Find All Unclosed Handles from a Specific Stack Pattern

```
!htrace -diff
```

Look for repeated identical call stacks — these point directly to the leaking code path.

---

## STEP 7: Inspect the Object Behind a Leaking Handle

For each suspicious handle value `<hval>`:

### 7a. Get the Kernel Object Address

```
!handle <hval> ff
```

Note the `Object:` address (e.g., `0xfffffa8012345678`).

### 7b. Inspect the Object

```
!object <object-address>
```

Shows the object type, name, reference count, and pointer count.

For file handles specifically:
```
!fileobj <object-address>
```

For process/thread handles:
```
!process <object-address>
!thread <object-address>
```

### 7c. Check Reference and Handle Counts

```
dt nt!_OBJECT_HEADER <object-address - 0x30>
```

(Subtract 0x30 from the object body address to reach the header on x64.)

Fields of interest:
- `HandleCount` — number of open handles to this object
- `PointerCount` — total reference count (includes kernel references)

A large `HandleCount` on a single object indicates repeated opens without closes.

---

## STEP 8: Correlation — Find the Leaking Code

### 8a. If htrace is Available (Preferred)

From `!htrace -diff`, copy the call stack. The frame in *your* code (not OS/CRT) is the leak site.

Use `.frame` and `dv` to inspect local variables at that frame:
```
.frame <N>
dv
```

### 8b. If htrace is NOT Available

Search your source code for all places that call the API matching the leaking handle type:
- `CreateFile` / `CreateEvent` / `OpenProcess` / `RegOpenKeyEx` / etc.

Then look for missing `CloseHandle` / `RegCloseKey` on error paths — a common pattern:
```cpp
// BUG: early return skips CloseHandle
HANDLE h = CreateEvent(NULL, FALSE, FALSE, NULL);
if (!SomeFunction()) return FALSE;   // h leaks here
CloseHandle(h);
```

### 8c. Use Application Verifier (Recommended for Future Testing)

Enable the **Handles** check in Application Verifier to catch handle leaks at the point of occurrence:
```powershell
appverif /enable Handles /for <process.exe>
```

Application Verifier will break into the debugger at the exact location where a handle is
closed twice or used after close.

---

## STEP 9: Resume and Detach

**Tool:** `run_windbg_cmd` — command: `g` (resume the process)

**Tool:** `close_windbg_process` — detach WinDbg

---

## STEP 10: Cleanup GFlags After Investigation

Remove tracing flags when done to avoid runtime overhead:
```powershell
& $gflags /i <process.exe> -htc -ust
```

Verify cleared:
```powershell
& $gflags /i <process.exe>
# Should show: 0x00000000
```

---

## ADVANCED: Process Handle Table Exhaustion

If the process is failing because the handle table is full (handle count near 16 million):

### Check Current Handle Count

```
!peb
```

Then from the PEB output, note `NumberOfHandles`.

### Dump the Entire Handle Table Summary

```
!handle 0 1
```

This gives a compact summary (type counts) without dumping every handle — useful when there
are hundreds of thousands of handles.

### Force-Close a Leaking Handle (Last Resort)

**Warning: This may destabilize the process.** Only use for diagnosis, not as a fix.
```
.closehandle <handle-value>
```

---

## ADVANCED: Kernel-Level Handle Leak (Driver or System Process)

For system processes (`System`, `lsass.exe`) or kernel driver handle leaks:

**Tool:** `open_windbg_kernel` — connect via KD transport.

**Tool:** `send_ctrl_break` — break into the kernel.

```
!handle 0 0 <PID>
```

Inspect handles for a specific kernel process by PID.

```
!object \
```

Browse the object namespace to find objects with unexpectedly high reference counts.

```
dt nt!_HANDLE_TABLE_ENTRY
```

Inspect raw handle table entries.

---

## REQUIRED OUTPUT FORMAT

```markdown
# Handle Leak Investigation Report
**Analysis Date:** [Current Date]
**Target Process:** [Name and PID]
**Leak Confirmed:** [Yes / Suspected / No]

## Executive Summary
- **Handle Count at Start:** [N]
- **Handle Count at End:** [N] (after [X] minutes / [Y] operations)
- **Growth Rate:** [handles/minute or handles/operation]
- **Dominant Leaking Type:** [File / Event / Mutex / Key / Thread / etc.]
- **Root Cause:** [Brief description]
- **Fix:** [One-line description of the fix]

## Handle Census

### Type Breakdown (`!handle 0 0f`)
| Handle Type | Count | Notes |
|-------------|-------|-------|
| File        | [N]   |       |
| Event       | [N]   |       |
| Key         | [N]   |       |
| [Other]     | [N]   |       |

### Sample Leaking Handles
| Handle Value | Type | Name / Path | Object Address |
|-------------|------|-------------|---------------|
| [0x...]     | File | [path]      | [0x...]       |

## Leak Call Stack (`!htrace -diff`)

```
[Call stack showing where handle was opened and never closed]
```

**Leak Location:**
- **Module:** [module.dll / process.exe]
- **Function:** [FunctionName]
- **Reason:** [Why CloseHandle / RegCloseKey / etc. is never reached]

## Root Cause Analysis

### What Happened
[Describe the handle lifecycle and where it breaks down]

### Why It Happened
[Missing close call / error path skipped cleanup / handle duplicated but original not closed / etc.]

### Code Pattern
```cpp
// Before (leaking)
[leaking code snippet if identifiable]

// After (fixed)
[corrected code snippet]
```

## Fix Recommendations

### Primary Fix
1. [Exact location to add CloseHandle / RegCloseKey / closesocket]
2. [RAII wrapper recommendation, e.g., std::unique_ptr with custom deleter]

### RAII Pattern (C++)
```cpp
// Use a scoped handle wrapper to guarantee cleanup
struct HandleDeleter { void operator()(HANDLE h) { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); } };
using ScopedHandle = std::unique_ptr<void, HandleDeleter>;

ScopedHandle h(CreateEvent(NULL, FALSE, FALSE, NULL));
// CloseHandle called automatically on scope exit
```

### Testing & Prevention
1. Enable Application Verifier Handles check in CI: `appverif /enable Handles /for <process.exe>`
2. Add handle count assertion in integration tests (compare before/after repeated operations)
3. Use `!handle 0 0f <Type>` check in automated WinDbg post-run analysis
4. Code review: every `Create*` / `Open*` call must have a corresponding close on **all** exit paths

## Additional Notes
[Handle fragmentation, object namespace observations, or other anomalies]
```

## QUICK REFERENCE — MOST USEFUL COMMANDS

| Goal | Command |
|------|---------|
| Total handle count | `!handle 0 0` |
| All handles with details | `!handle 0 0f` |
| Filter by type | `!handle 0 0f File` |
| Full detail on one handle | `!handle <hval> ff` |
| Kernel object info | `!object <addr>` |
| Enable tracing (runtime) | `!htrace -enable` |
| Snapshot for diff | `!htrace -snapshot` |
| Show unclosed since snapshot | `!htrace -diff` |
| Stack for one handle | `!htrace <hval>` |
| Force-close (diagnosis only) | `.closehandle <hval>` |
| PEB handle stats | `!peb` |

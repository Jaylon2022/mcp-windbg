Perform a comprehensive analysis of a live kernel debugging session on a target Windows machine, collecting key diagnostic information and producing a structured report.

## Prerequisites

Before using this prompt, verify the target machine is configured for kernel debugging:
- `bcdedit /debug on` has been run on the target
- Boot debug settings match the transport you will use (e.g., `bcdedit /dbgsettings net hostip:<HOST> port:50000` for KDNET)
- The target machine has been rebooted after those changes

## WORKFLOW - Execute in this exact sequence:

### Step 1: Connection String Identification

**If no kernel_connection provided:**
Ask the user for the transport string. Examples:
- **KDNET (network, recommended):** `net:port=50000,key=1.2.3.4`
- **Serial port:** `com:port=COM1,baud=115200`
- **Named pipe / VM (VMware, Hyper-V):** `com:pipe,port=\\.\pipe\com_1`
- **USB 3.0:** `usb3:targetname=MyTarget`
- **IEEE 1394:** `1394:channel=0`

Also ask if they need a custom kd.exe path (only required if not in the default Windows SDK location).

### Step 2: Establish Kernel Debug Session

**Tool:** `open_windbg_kernel`
- **Parameters:**
  - `kernel_connection`: The transport string provided above
  - `include_stack_trace`: false (target may still be running)
  - `include_modules`: false

This launches `kd.exe -k <transport>` and waits for the target machine to connect.

> **Note:** After this step the target machine may still be running. The debugger is connected but not yet at a break.

### Step 3: Break Into the Target

**Tool:** `send_ctrl_break`
- **Parameters:**
  - `kernel_connection`: same transport string

This sends a `.break` command through the KD transport, pausing all CPUs on the target machine.

Wait for the break to be acknowledged before proceeding.

### Step 4: Collect Core Diagnostic Data

**Tool:** `run_windbg_cmd` (with `kernel_connection` parameter)

Run the following commands in order:

| Command | Purpose |
|---------|---------|
| `vertarget` | OS version, build number, platform |
| `!analyze -v` | Automatic crash/hang analysis |
| `lm` | Loaded kernel modules |
| `!process 0 0` | Summary of all running processes |
| `!thread` | Current thread details |
| `k` | Current kernel call stack |
| `!pcr` | Processor control region |
| `!pte` | Page table entry (if investigating memory) |
| `.time` | Target machine time |
| `r` | Current register state |

For BugCheck (Blue Screen) analysis, also run:

| Command | Purpose |
|---------|---------|
| `!analyze -v -f` | Force full analysis even without exception |
| `!bugcheck` | BugCheck code and parameters |
| `!drivers` | Driver list with details |

### Step 5: Resume or Further Investigate

- To resume the target: `run_windbg_cmd` with command `g`
- To set a breakpoint: `run_windbg_cmd` with command `bp <address>` or `bu <module>!<function>`
- To inspect memory: `run_windbg_cmd` with command `dd <address>` / `dq <address>` / `db <address>`
- To inspect a specific process: `run_windbg_cmd` with command `!process <PID> 7`

### Step 6: Disconnect

**Tool:** `close_windbg_kernel`
- **Parameters:**
  - `kernel_connection`: same transport string

This sends `qd` (quit + detach), leaving the target machine running normally.

---

## REQUIRED OUTPUT FORMAT:

```markdown
# Kernel Debug Session Report
**Analysis Date:** [Current Date]
**Transport:** [e.g., net:port=50000,key=1.2.3.4]
**Debugger:** kd.exe

## Executive Summary
- **Session Type:** [Live kernel / BugCheck analysis / Hang investigation]
- **Severity:** [Critical/High/Medium/Low]
- **Finding:** [One-line description of what was observed]
- **Recommended Action:** [Immediate next steps]

## Target Machine Information
- **OS Build:** [Windows version and build from vertarget]
- **Platform:** [x86/x64/ARM64]
- **Kernel Version:** [NT kernel version]
- **System Uptime:** [From .time]
- **Number of CPUs:** [From vertarget]

## Current State at Break
- **Break Reason:** [User-initiated break / BugCheck / Exception]
- **Current CPU:** [From !pcr]
- **Current Process:** [Process name and PID]
- **Current Thread:** [Thread ID]

**Call Stack at Break:**
```
[Kernel call stack from k command]
```

**Register State:**
```
[Output of r command]
```

## Crash / Hang Analysis (if applicable)
**BugCheck / Exception Details:**
- **BugCheck Code:** [0x0000009F, etc.]
- **Parameters:** [BugCheck parameters]
- **Faulting Driver/Module:** [driver.sys or module]
- **Faulting Address:** [0x...]

**!analyze -v Output Summary:**
[Key findings from !analyze output]

## Loaded Kernel Modules (Notable)
| Module | Base Address | Size | Path |
|--------|--------------|------|------|
| [Key drivers / modules of interest] | | | |

## Process Summary
[Output from !process 0 0 - filter to notable processes]

## Root Cause Analysis
[Detailed explanation including:]
- **What happened:** [Technical description]
- **Why it happened:** [Contributing factors, driver bugs, hardware issues, etc.]
- **Affected component:** [Driver name, subsystem, version]
- **Related BugCheck history:** [If known from previous analysis]

## Recommendations

### Immediate Actions
1. [Specific action - e.g., update/replace driver X]
2. [Specific action]
3. [Specific action]

### Investigation Steps
1. [Further kernel analysis commands to run]
2. [Log/event review recommendations]
3. [Reproduction steps]

### Prevention Measures
1. [Driver fixes, kernel patches, configuration changes]
2. [Monitoring recommendations]
3. [Testing scenarios]

## Additional Notes
[Other relevant observations - IRQ levels, DPC activity, lock contention, memory pressure, etc.]
```

## ANALYSIS DEPTH:
- For **BugCheck / BSOD**: focus on `!analyze -v`, `!bugcheck`, faulting driver stack
- For **hangs**: focus on `!process 0 7`, `!locks`, `!spinlock` to find deadlocks
- For **memory issues**: focus on `!vm`, `!poolused`, `!poolfind`
- For **driver issues**: focus on `!devnode`, `!drvobj`, `!devobj`

**Always remember:**
- Use `close_windbg_kernel` when done to avoid leaving the target machine paused
- Never use `q` alone — it may crash the target; always use `qd` (via `close_windbg_kernel`)
- If the target is unresponsive after a break, use `g` to resume before disconnecting

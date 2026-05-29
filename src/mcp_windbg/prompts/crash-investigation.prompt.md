Perform a deep, interactive root-cause investigation of a Windows crash — going beyond automated `!analyze -v` output to understand *why* the crash occurred and identify the responsible code path.

Use this workflow when you need to understand the real cause behind a crash, not just the crash address. This prompt is complementary to the `dump-triage` prompt: use `dump-triage` for a quick structured report, and this prompt for a detailed investigation.

## STEP 1: Establish the Session

**If you have a crash dump:**
- **Tool:** `open_windbg_dump`
  - `dump_path`: path to the `.dmp` file
  - `include_stack_trace`: true
  - `include_modules`: true
  - `include_threads`: true

**If investigating a live process:**
- **Tool:** `attach_windbg_process` (use `pid` or `process_name`)

**Then run:** `run_windbg_cmd` — command: `!analyze -v`

Save the `!analyze -v` output — it provides the starting context (exception code, exception address, faulting module).

---

## STEP 2: Classify the Crash Type

Identify the exception code from `!analyze -v` and follow the matching branch:

| Exception Code | Type | Go To |
|----------------|------|--------|
| `0xC0000005` | Access Violation | [Section A] |
| `0xC00000FD` | Stack Overflow | [Section B] |
| `0xC0000374` | Heap Corruption detected by RtlHeap | [Section C] |
| `0xC0000409` | Stack Buffer Overrun (GS cookie) | [Section C] |
| `0xC0000602` | Unknown Image Corruption | [Section C] |
| `0xC0000008` | Invalid Handle | [Section D] |
| `0x80000003` | Breakpoint (assert/abort) | [Section E] |
| `0xE06D7363` | C++ Exception (`throw`) | [Section F] |
| `0xC000001D` | Illegal Instruction | [Section G] |

---

## SECTION A — Access Violation (0xC0000005)

Access Violations are caused by reading or writing to an invalid memory address. Sub-classify:

### A1. Determine Read vs. Write and the Faulting Address

```
.exr -1
```

Look for:
- `ExceptionInformation[0]` — `0` = read, `1` = write, `8` = DEP (execute)
- `ExceptionInformation[1]` — the address that was accessed

Then run:
```
!address <faulting-address>
```

| Region Type | Likely Cause |
|-------------|-------------|
| `NULL` or near-zero (`0x00000000`–`0x0000ffff`) | Null pointer dereference |
| Previously allocated (freed) | Use-after-free |
| Beyond end of buffer | Buffer over-read/write |
| Unmapped or `MEM_FREE` | Stale pointer |
| Stack range | Stack corruption or stack-based array overflow |

### A2. Null Pointer — Find the Source

```
k
```

Walk up the call stack. Find the first frame in *your* code (not OS code). Use:
```
.frame <N>
dv
```
(`dv` = display local variables) to see which pointer was null in that frame.

If symbols are available:
```
dt <type> <address>
```

### A3. Use-After-Free — Confirm with Heap Analysis

```
!heap -p -a <faulting-address>
```

If page heap is enabled, this shows:
- The **free call stack** (who freed it)
- The **allocation call stack** (who allocated it)
- The **size** of the allocation

Cross-reference the free/alloc stacks with your code to find the lifetime mismatch.

If page heap is NOT enabled, look for the freed block pattern:
```
db <faulting-address>
```

Freed heap blocks in NTDLL are often filled with `0xfeeefeee` (debug) or `0xdddddddd` patterns.

### A4. Buffer Overflow — Measure the Overflow

Determine buffer size from the allocation:
```
!heap -p -a <base-of-allocation>
```

Then compute: `faulting-address - base-address = overflow-distance`

Search backward in the call stack for the loop or copy operation that overran the buffer.

---

## SECTION B — Stack Overflow (0xC00000FD)

### B1. Find the Depth of Recursion

```
~* kb 10
```

Look for the crashing thread. Count the repeating frames — the stack will show the same function (or small group of functions) repeating many times.

### B2. Confirm Infinite Recursion

```
k 200
```

Look for a cycle in the call stack. The repeating pattern reveals the recursive call chain.

### B3. Check the Stack Bounds

```
!teb
```

Shows `StackBase` and `StackLimit`. Then:
```
r rsp
```

If RSP is at or below `StackLimit`, the stack is exhausted.

### B4. Find the Entry Point of Recursion

Walk up from the first occurrence of the repeating pattern to find what initially triggered the recursion:
```
.frame <N>
dv
```

Examine local variables at the first recursive call to understand the triggering condition.

---

## SECTION C — Heap Corruption / Buffer Overrun / Security Cookie Failure

Heap corruption crashes often happen *far from* the actual bug — the heap is corrupted earlier, and the crash occurs later when the heap manager detects it.

### C1. Check When Corruption Was Detected

```
!analyze -v
```

The `HEAP_CORRUPTION_DETECTED` or `STACK_BUFFER_OVERRUN` string in the analysis tells you what RTL check failed.

### C2. Examine All Thread Stacks for Prior Suspicious Activity

```
~*kb
```

Look for threads that were in heap operations (allocating, freeing, resizing) when the crash occurred.

### C3. Enable Page Heap for Future Reproduction (Recommendation)

If this is a reproducible crash, instruct the user to enable page heap before the next run:
```
gflags /i <process.exe> +hpa +htc +ust
```

This will catch the corruption *at the exact bad write*, giving a precise call stack.

### C4. Analyze Heap Block Boundaries

```
!heap -p -a <address-near-crash>
```

Check the block header and footer for corruption signatures.

### C5. Check for Double-Free

Look for the allocation state:
```
!heap -p -a <freed-address>
```

A `UserReq: 0` or `Flags: 0x10` on an already-freed block indicates a double-free.

---

## SECTION D — Invalid Handle (0xC0000008)

### D1. Identify the Handle Value

```
.exr -1
r
```

The faulting handle value is usually in RCX (x64 first argument) or on the stack.

### D2. Check Current Open Handles

```
!handle 0 0f
```

Compare the faulting handle against the open handles list. If not present, it was already closed (double-close) or was never valid.

### D3. Find Handle Lifecycle

Use the call stack to find where the handle was created:
```
k
.frame <N>
dv
```

---

## SECTION E — Abort / Assert Failure (0x80000003)

### E1. Examine the Assertion Message

```
.exr -1
k
```

The frame just before `abort()` / `_CrtDbgReport()` / `RaiseException()` contains the assertion site.

### E2. Read the Assertion Text

```
.frame <N>
dv
```

Or look for the format string in memory:
```
da <pointer-to-string>
```

### E3. Understand the Failed Condition

Identify what invariant was violated at the assertion point. This is typically a programmer-specified precondition.

---

## SECTION F — Unhandled C++ Exception (0xE06D7363)

### F1. Decode the Exception Object

```
!analyze -v
```

Then decode the thrown object:
```
.exr -1
```

### F2. Walk the C++ Exception Chain

```
!exchain
```

### F3. Find the `throw` Site

Look for `CxxThrowException` in the call stack:
```
k
```

The frame *above* `CxxThrowException` is the `throw` statement. Use `.frame` and `dv` to inspect the thrown object.

### F4. Check for Missing `catch` Handlers

Walk the call stack to find why no `catch` block handled the exception. Look for mismatched exception types.

---

## SECTION G — Illegal Instruction (0xC000001D)

### G1. Examine the Faulting Instruction

```
r
u <rip-value>
```

Common causes:
- `__debugbreak()` or `int 3` left in release code
- CPU feature mismatch (AVX-512 on non-supporting CPU)
- Corrupted code section or JIT-compiled code

### G2. Check Processor Features

```
!cpuinfo
```

Compare against required CPU features for the binary.

---

## STEP 3: Cross-Thread Analysis (For All Crash Types)

Always inspect all threads — the crash thread may not be the root cause:

```
~*kb 20
```

Look for:
- **Threads holding locks** that the crashing thread was waiting for (deadlock contributing factor)
- **Other threads** with suspicious stack frames (e.g., in free/alloc operations)
- **Background threads** that may have corrupted memory used by the crashing thread

Inspect a specific thread:
```
~<thread-id>s
k
!teb
```

---

## STEP 4: Memory Inspection Around the Crash Site

```
u <exception-address> L20
```
(Disassemble 20 instructions at the crash address)

```
dq rsp L10
```
(Dump stack memory)

```
dq <faulting-address>-0x20 L10
```
(Dump memory around the faulting address)

---

## STEP 5: Symbol and Module Verification

```
lmvm <module-name>
```

Confirms the module version and whether symbols are loaded. If symbols are missing:
```
.symfix
.reload /f
```

For private symbols (your own code), confirm the PDB matches:
```
!chksym <module-name>
```

---

## STEP 6: Close the Session

**For dump:** `close_windbg_dump`
**For live process:** `close_windbg_process`

---

## REQUIRED OUTPUT FORMAT

```markdown
# Crash Investigation Report
**Analysis Date:** [Current Date]
**Target:** [Process name / dump file]
**Crash Type:** [Exception code and classification from Step 2]

## Executive Summary
- **Root Cause:** [One-sentence description of what caused the crash]
- **Crash Category:** [Null deref / Use-after-free / Buffer overflow / Recursion / Heap corruption / etc.]
- **Responsible Code:** [Module!Function where the bug originates]
- **Confidence:** [High / Medium / Low] — [Why]

## Crash Classification

**Exception Code:** `0xXXXXXXXX` — [Human-readable name]
**Exception Address:** `0xXXXXXXXXXXXXXXXX`
**Faulting Module:** [module.dll @ base 0x...]
**Access Type:** [Read / Write / Execute] (for AV)
**Accessed Address:** `0x...` — [What this address represents]

## Call Stack of Crashing Thread

```
[Full call stack with frame numbers, modules, functions, offsets]
```

**Key Frames:**
- Frame [N]: [Why this frame is significant]
- Frame [M]: [The actual bug location]

## Root Cause Deep Dive

### What Happened
[Technical description of the exact failure mechanism]

### Why It Happened
[Root cause analysis — the actual code defect]

### Evidence
[Specific output from WinDbg commands that proves the diagnosis:
- Memory contents
- Heap allocation info
- Register values
- Call stack patterns]

## All-Thread Summary

| Thread ID | State | Notable Activity |
|-----------|-------|-----------------|
| [TID] (crashing) | Faulted | [Why it crashed] |
| [TID] | Waiting | [What it's waiting on] |
| [TID] | Running | [What it was doing] |

## Reproduction Guide
1. [How to reproduce the crash]
2. [Required conditions]
3. [Expected vs actual behavior]

## Fix Recommendation

### Primary Fix
[Specific code change to fix the root cause]

### Additional Hardening
1. [Guard condition to add]
2. [ASAN / Application Verifier / page heap recommendation]
3. [Unit test to add]

## Related Risks
[Other places in the codebase that may have the same bug pattern]
```

## INVESTIGATION TIPS

- **Symbols missing?** Use `.symfix` + `.reload /f`, then set `_NT_SYMBOL_PATH` to point to your symbol server before opening the dump.
- **Heap analysis requires full dump:** Mini dumps (`!heap -s` shows error) — request a new full dump (`.dump /ma`) from the field.
- **No page heap, no allocation stacks?** Enable `gflags /i <exe> +ust +hpa` and repro to get future allocation call stacks.
- **Stack looks wrong?** Try `k`, `kb`, `kP`, or `kv` — different stack walk algorithms may give better results when frame pointers are missing.
- **Remote crash with no repro?** Focus on the exception record (`.exr -1`), context record (`.cxr`), and heap metadata rather than live interaction.

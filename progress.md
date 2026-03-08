# PS5 Kernel Module Loader - Development Progress

## Overview

This document summarizes the work done to build a working kernel module loader (`kldload.elf`) for PS5 firmware 4.03. The loader receives arbitrary kernel code over a TCP socket, copies it into executable kernel memory, and launches it as a kernel thread via `kproc_create`. Starting from a pre-built `kstuff.elf` baseline, we hit a series of kernel panics and hangs that required deep debugging of the kekcall infrastructure, memory allocation, page table permissions, and kernel function calling conventions.

**Final result**: The loader is fully functional. A test payload (`test_kmod.bin`) confirmed end-to-end execution by writing `0xCAFEBABE`/`0xDEAD` markers from kernel context.

---

## Architecture

The system has three layers:

1. **ps5-kstuff-ldr** (loader) - ELF loader that mmaps the kstuff payload at a fixed address (`0x0000000926100000`), parses ELF headers, and calls `entry()`. After entry returns, it patches `app.db` via SQLite.

2. **ps5-kstuff** (main payload) - Initializes r0gdb, hooks `getpid` syscall for kekcall dispatch, sets up per-CPU kelf/uelf trap handlers, patches kernel security flags, IDT entries, and exports function pointers (`r0gdb_kmalloc`, `r0gdb_kfncall`, etc.) via an `r0_table` parameter.

3. **uelf** (micro-ELF trap handler) - Intercepts `#DB` and `#GP` exceptions in kernel context. Routes `getppid` syscalls to `handle_kekcall()` which dispatches based on kekcall number. All kernel function calls use `push_stack`/`doreti_iret`/`MKTRAP` trap patterns for safe return frames.

### Kekcall Table (Final State)

| Nr | Function | Description |
|----|----------|-------------|
| 1 | copyout | Copy kernel memory to userspace |
| 2 | copyin | Copy userspace memory to kernel |
| 6 | malloc | Allocate kernel heap memory |
| 7 | kproc_create | Launch a kernel thread |
| 8 | copyin (kernel context) | Full kernel copyin via push_stack/trap |
| 9 | Diagnostics | Read proc info, kernel memory |
| 10 | NX bit clearing | Walk page tables, clear NX on PTEs |
| 0xffffffff | Liveness check | Returns 0 if kstuff is loaded |

---

## Kernel Panics and Fixes (Chronological)

### Panic 1: Payload Not Executing (Uninitialized r0_table)

**Symptom**: `kstuff.elf` loaded without errors but did nothing. No kernel patches applied, no kekcall handlers registered.

**Root cause**: The loader's `hacky_args` buffer was not zeroed. The 7th parameter (`r0_table`) picked up garbage from the stack, which was non-NULL. The payload checks `if (r0_table != NULL)` to decide whether to export function pointers and return early (kldload mode) vs. do full initialization. With garbage in `r0_table`, it always returned early.

**Fix** (`4c986ff`): `memset(hacky_args, 0, 0x200)` before calling `entry()`.

---

### Panic 2: die() on Missing uelf Log Symbols

**Symptom**: Payload hit `die()` at line 196/197 during `load_kelf`.

**Root cause**: The loader's symbol table didn't include `uelf_log_buffer_kptr`, `uelf_log_buffer_size`, and `uelf_log_buffer_pos_kptr`. The kelf loader expected these symbols and called `die()` when they weren't found.

**Fix** (`dd79105`): Added the three uelf log buffer symbols to the loader's symbol export table.

---

### Panic 3: kekcall nr=6 (malloc) Returning 0

**Symptom**: `kmem_alloc` via kekcall always returned 0 to userspace, even though kernel malloc succeeded internally.

**Root cause**: The nr=6 handler used `TRAP_UTILS` which didn't store malloc's RAX return value into `td_retval`. The kernel syscall return path interpreted the pointer in RAX as an error code and zeroed the userspace return value.

**Fix** (`19fc9ab`): Changed to `TRAP_KEKCALL,5` with a custom handler that saves RAX into `td_retval[0]` and sets RAX=0 (success).

**Complication**: Rebuilding the full payload from source produced different machine code that hung on PS5. Solution (`4667456`): binary-patched only the uelf portion into the original working payload, fitting the new 21,768-byte uelf exactly into the original slot.

---

### Panic 4: kproc_create NULL fmt Dereference

**Symptom**: Immediate kernel panic when calling `kproc_create` via kekcall nr=7.

**Root cause**: `kproc_create(func, arg, procptr, 0, 0, fmt)` expects the process name string in R9 (the `fmt` parameter). The kekcall handler passed `kproc_name` on the stack as a variadic argument instead of in R9. This left R9=NULL, and `vsnrprintf` dereferenced NULL, causing an immediate page fault in kernel context.

**Fix** (`bc47ee5`): Passed `kproc_name` as R9 directly instead of as a stack argument.

---

### Panic 5: kproc_create Missing Return Frame

**Symptom**: Kernel panic after `kproc_create` returned. The function itself executed successfully (thread was created), but the return crashed.

**Root cause**: The kekcall nr=7 handler didn't set up a proper `doreti_iret` + `MKTRAP` return frame. When `kproc_create` executed `ret`, it popped garbage from the stack and jumped to an invalid address.

**Intermediate workaround** (`bbaac11`): Bypassed kekcall nr=7 entirely, using `r0gdb_kfncall` to call `kproc_create` directly at its kernel address with a FW-version offset lookup table.

**Proper fix** (`5eb9af9`): Added `doreti_iret + MKTRAP(TRAP_KEKCALL, 6)` return frame and corresponding trap handler 6. This matched the pattern already used by kekcall nr=6 (malloc).

---

### Panic 6: copyin Failing on Kernel Heap Addresses

**Symptom**: `kernel_copyin` (SDK function) returned -1 when copying to malloc'd kernel addresses. Code was never actually written to kernel memory.

**Root cause**: The SDK's `kernel_copyin` uses DMAP (direct physical memory mapping) to translate addresses. Malloc'd kernel heap addresses (`0xffffff80...`) aren't in the DMAP range and can't be resolved this way.

**Attempts**:
- (`9172b74`) Added kekcall nr=8 calling kernel's own `copyin()` directly
- (`0739180`) Tried DMEM-based copyin (translate both user and kernel VA to physical, memcpy through DMEM)
- (`cf1b093`) Fixed user VA resolution -- kernel CR3 doesn't map user addresses due to KPTI, needed process-specific CR3

**Final fix** (`ec59e43`): Used `push_stack`/`doreti_iret`/`MKTRAP(TRAP_KEKCALL, 7)` to call kernel's `copyin()` in full kernel context with proper CR3. This handles both user VA and kernel VA correctly.

---

### Panic 7: NX Bit on Malloc'd Pages

**Symptom**: Kernel thread created successfully but crashed immediately on first instruction. The copied code was correct in memory but not executable.

**Root cause**: `malloc` returns pages with the NX (No-Execute) bit set (bit 63 of the PTE). The kernel thread's instruction fetch triggered a page fault because the page was marked non-executable.

**Attempts**:
- (`77e4639`) Switched to `kmem_alloc(kernel_vmmap, size)` for RWX memory
- (`f86ee80`) Used `kmem_alloc` with `kmem_alloc_rwx_fix` breakpoint to change protection to `VM_PROT_ALL=7`
- (`8e62082`) Discovered that the `malloc_arena_fix` debug breakpoint (DR0) caused `kmem_alloc` to hang in an infinite retry loop

**Final fix** (`aa53367`, `8120daf`): Reverted to `malloc` (which works reliably) and added **kekcall nr=10** that walks kernel page tables via DMEM, clears the NX bit (bit 63) on PTEs, and flushes TLB. Applied after `copyin` completes but before `kproc_create` launches the thread.

---

## Key Lessons Learned

1. **Binary patching vs. source rebuilding**: Rebuilding the full payload from source often produced different machine code that hung or crashed. Binary-patching only the changed uelf portion into the original working payload was the reliable approach.

2. **Return frames are mandatory**: Every kernel function call from a kekcall handler requires a `push_stack` with `doreti_iret + MKTRAP` return frame. Without this, the called function's `ret` pops garbage and panics. This was the root cause of multiple panics.

3. **KPTI complicates everything**: The kernel's CR3 is KPTI-limited and cannot resolve user addresses or certain kernel heap addresses. Calling kernel functions that touch user memory requires full kernel context with the process-specific CR3.

4. **Memory allocation strategy**: `malloc` is reliable but returns NX pages. `kmem_alloc` can provide RWX pages but conflicts with debug register breakpoints. Final approach: `malloc` + manual NX bit clearing via page table walks through DMEM.

5. **Debug register conflicts**: The `malloc_arena_fix` breakpoint (DR0) interfered with `kmem_alloc`, causing infinite retry loops. Hardware debug registers are a limited resource and breakpoint conflicts can cause subtle hangs.

---

## Current Status

The kernel module loader (`kldload.elf`) is **fully functional**:

- Receives kernel code over TCP (port 9022)
- Allocates kernel heap memory via `malloc` (kekcall nr=6)
- Copies code into kernel memory via kernel `copyin` (kekcall nr=8)
- Clears NX bit on code pages via page table walk (kekcall nr=10)
- Launches kernel thread via `kproc_create` (kekcall nr=7)
- Reads back kthread_args buffer (2304 bytes) for structured output
- Verified with `test_kmod.bin` writing `0xCAFEBABE`/`0xDEAD` markers

---

## Phase 2: Kernel Reconnaissance

**Status: COMPLETE**

With kldload working, deployed multiple research payloads:

### apic_dump
Dumped all 28 `apic_ops` function pointers and sorted unique sysent ktext function addresses. Gave us ~200+ known ktext entry points as anchor addresses for gadget scanning.

### gadget_reader (v1-v2)
Attempted to read bytes around known ktext addresses via DMAP (Direct Memory Access Mapping). Idea: if physical pages backing ktext can be read through DMAP, we can scan for gadget byte patterns without executing anything.

**Result**: Limited success. The hypervisor appears to intercept or block DMAP accesses to ktext-backing physical pages.

### register_probe
Captured full register state at the apic_ops[2] call site. Confirmed which registers contain useful values (function pointers, kernel addresses) when entering apic_ops handlers.

### chain_prep
Read system registers (LSTAR, CR3, etc.) and confirmed pop_all_iret layout matches standard FreeBSD. Established that LSTAR = ktext_base + 0x294218.

### ktext_mapper
Built expanded ktext pointer map by scanning IDT entries + kdata for ktext function pointers. Discovered many function entry points across the ktext region.

---

## Phase 3: Pivot Gadget Scanning

**Status: IN PROGRESS — the core challenge**

### Goal
Find a **stack pivot gadget** in ktext (e.g., `xchg rsp, rax; ret` = bytes `48 94 c3`) that allows redirecting kernel execution to a controlled stack, enabling ROP despite CFI/hypervisor.

### Strategy 1: Blind Execution Probing (v1-v3)
Systematically executed offsets near known ktext function boundaries, checking if they returned cleanly or crashed.

- Built batch scanner that probed offsets within ktext functions
- Scanned epilogues (bytes before function entry points) for `pop; ret` sequences
- **Result**: Many crashes, no pivots found. Without fault recovery, each crash killed the thread.

### Strategy 2: pcb_onfault Fault Recovery (v5-v5.3)
FreeBSD's `pcb_onfault` mechanism: set a recovery address in the PCB, and faults jump there instead of panicking. Critical for surviving bad probes.

- **v5-v5.1**: Attempted to set pcb_onfault, but wrong td_pcb offset caused crashes
- **v5.2-v5.2f**: Series of diagnostics to discover pcpu layout and td_pcb offset
- **v5.3-v5.3c**: Attempted full probing with fault recovery — unreliable across reboots

**Key problem**: td_pcb offset varies between struct layout assumptions. Needed empirical discovery.

### Strategy 3: DMAP Byte Scanning (v6-v6b)
Read ktext bytes through DMAP to find gadget byte patterns without executing.

- **v6**: Static byte scanner searching for `48 94 c3` (xchg rsp,rax; ret) in DMAP
- **v6b**: Added pcb_onfault protection for XO page faults during DMAP reads
- **Result**: Hypervisor blocks DMAP reads of ktext physical pages. XOM enforced even through DMAP alias.

### Strategy 4: kdata Function Pointer Harvesting (v7-v10)
Scanned all of kdata for pointers into ktext, building a map of callable functions.

- **v7**: Wide scan of kdata for ktext pointers
- **v8**: Added kernel pointer diagnostics
- **v9**: Packed 8 ktext offsets per output slot for efficiency
- **v10**: Deduplicated page bitmap with summary mode

**Result**: Found many function entry points but couldn't read their bytes due to XOM.

### Strategy 5: Execute-Test (v11-v13)
Execute candidate ktext offsets and check if RSP changed (indicating a pivot).

- Set RAX to a known address, execute the candidate, check if RSP == RAX afterward
- **v11**: Initial implementation
- **v12**: One-offset-at-a-time for safety
- **v13**: Fixed stack layout for recovery label
- **Problem**: Still needed reliable pcb_onfault for surviving bad candidates

### Strategy 6: Thread Structure Research (v14-v17)

Pivoted to empirically mapping the kernel thread structure to get correct pcb_onfault offset.

| Version | What | Result |
|---------|------|--------|
| v14 | Dereference pcb pointer at td+0x3f8 | **CRASHED** — bad pcb sub-offsets |
| v15 | Minimal smoke test (no dereferences) | **WORKED** — confirmed infrastructure solid |
| v16 | Dump 1024 bytes of struct thread | **WORKED** — found td_pcb at +0x3f8, td_name at +0x290 |
| v17 | Dump 256 bytes of struct pcb | **COMPLETE** — revealed full PCB layout |

### Strategy 7: pcb_onfault Discovery — COMPLETE

Found pcb_onfault at **PCB+0x108** via `pcb_onfault_test` payload.

**Initial bug**: Faulting address `0xDEAD000000000000` was non-canonical → #GP → pcb_onfault never consulted (only checked in #PF handler). Fixed to `0xFFFFDEAD00000000` (canonical, unmapped → proper #PF).

**Confirmed result**: `fault_result=0xCAFE0001`, sentinel intact, onfault cleared by kernel after recovery. PCB+0x108 is immediately after pcb_flags at PCB+0x100, consistent with FreeBSD layout.

### Strategy 8: Suspend/Resume PCB Analysis

Shifted focus from gadget scanning to exploiting the suspend/resume path. The hypothesis: if we can control what cpu_switch restores after resume, we get code execution before the hypervisor re-locks things.

#### pcb_diff (two-phase)

**Phase 1** (pre-suspend): Snapshots the idle thread's full PCB (40 qwords) to kdata+0x200 (persistent through suspend).

**Phase 2** (post-resume): Reads the snapshot back, dumps current PCB, compares every field.

**RESULT — CRITICAL FINDINGS:**

1. **kdata persists across suspend/resume** — snap_magic `0x534E4150444946FF` survived intact
2. **cpu_switch RUNS during resume** — it saved new register state into the idle PCB
3. **Only pcb_r13 changed** — from `0xffffd86043104680` to `0xffffd86005f0a700` (new curthread pointer, expected)
4. **pcb_rip is STABLE** at ktext+0x65e955 (sw_return in cpu_switch)
5. **pcb_rsp is STABLE** at `0xffffff8008a4b828`
6. **pcb_rbp, pcb_rbx, pcb_r15, pcb_r14, pcb_r12 — all stable**
7. **CR/DR fields are zero** — cpu_switch doesn't save them (handled by suspend/resume path separately)

**Implication**: cpu_switch restores pcb_rip into RAX and does `jmp *%rax`. If we overwrite pcb_rip before suspend, the CPU will jump to our chosen address on resume. pcb_rsp is also controllable for stack pivoting.

#### pcb_overwrite — DEAD END (v1-v5)

**Concept**: Overwrite idle thread's `pcb_rip` so that on resume, `cpu_switch` jumps to our code instead of `sw_return`. A gated stub at the hijack address either skips hv_probe (gate=0, safe nop) or runs hv_probe (gate=1, set just before standby).

**v1** — bare `ret` gadget (nop_ret) in pcb_rip:
- PCB overwrite succeeds, readback confirms
- **Kernel panics**: sw_return is NOT just `ret` — it contains critical cleanup (scheduler lock release, CR3 restore, etc.). Bare `ret` skips all of it → deadlock/fault

**v2** — trampoline stub: `write sentinel → jmp sw_return`:
- **CONFIRMED WORKING** — trampoline executed on resume, wrote sentinel, jumped to sw_return, kernel resumed cleanly
- **Arbitrary code execution via PCB hijack proven**

**v3** — HV probe via trampoline: `writecr0(cr0 & ~CR0_WP)` to test HV:
- **CONFIRMED WORKING (once)** — HV probe ran during resume
- **Result: CR0.WP stuck** → HV is active at PCB hijack point
- PCB hijack runs **too late** — HV has already restarted by the time cpu_switch runs
- Subsequent runs kernel panicked (tight persistence loop + ungated hv_probe = repeated VMEXITs from idle thread)

**v4** — gated stub + persistence loop variations:
- Added gate mechanism: gate=0 (safe nop during normal ops), gate=1 (run hv_probe, set just before standby)
- **Tight loop (200M writes/sec)** → panic (cache line contention with cpu_switch)
- **Userspace loop (kekcall_copyin + usleep)** → stable but pcb_rip always lost (userspace threads stopped before kernel's final cpu_switch)
- **Pthread hammer (31K writes/sec)** → panic
- **Gentle kernel loop (100 pauses, ~170K writes/sec)** → panic
- **Fast-track kldload (skip readback, immediate standby)** → panic

**v5** — write-once, no persistence loop:
- Kernel thread writes pcb_rip once and exits immediately
- kldload busy-polls (no usleep) via kekcall for instant detection
- Immediately sets gate=1 + sceSystemStateMgrEnterStandby()
- **Still panics** — setting gate=1 allows the stub to run hv_probe during the standby sequence; writecr0 triggers a VMEXIT that crashes

**Root cause analysis**: The fundamental problem has two sides:
1. **Any kernel-side persistence loop → panic** (multi-core race: writing pcb_rip while cpu_switch is using the idle PCB on another core corrupts context switch state)
2. **gate=1 + active stub → panic** (stub runs hv_probe during standby processing, writecr0 VMEXIT crashes)
3. **No loop + no gate → pcb_rip lost** (cpu_switch overwrites pcb_rip with sw_return before standby completes)

**Conclusion**: PCB hijack is a dead end for reliable HV probing. v3 proved it works for code execution (trampoline + jmp sw_return), and confirmed **HV is active at the PCB hijack point**. Need earlier execution to catch the pre-HV window.

**Key finding from v3**: Consider apic_ops[2] hijack for pre-HV window — but this was already explored in Sessions 8-9 and blocked by **NPT NX** (HV enforces NX on all non-ktext pages during suspend, so apic_ops[2] must point to a ktext address).

---

## Key Discoveries

| Item | Value | How Found |
|------|-------|-----------|
| kdata_base | KASLR'd per boot | From payload_args |
| ktext_base | kdata_base - 0xC00000 | LSTAR - 0x294218 |
| LSTAR | ktext_base + 0x294218 | rdmsr 0xC0000082 |
| curthread | gs:0 | movq %%gs:0 |
| curthread region | DMAP (0xffffXXXX...) | v16 dump |
| td_pcb offset | **+0x3f8** | v16: only kern_heap ptr in thread struct |
| td_name offset | +0x290 | v16: contains "my_kthread" |
| td_proc (likely) | +0x008 | v16: DMAP pointer |
| **kdata persists** | Confirmed | pcb_diff phase 2: snap_magic survived suspend/resume |
| **cpu_switch runs on resume** | Confirmed | pcb_diff: pcb_r13 changed to new curthread |
| **pcb_rip stable** | ktext+0x65e955 (sw_return) | pcb_diff: identical before/after |
| **pcb_rsp stable** | `0xffffff8008a4b828` | pcb_diff: identical before/after |
| **nop_ret** | kdata - 0x9d20ca | `ret` gadget for safe hijack test |
| **PCB hijack works** | v2 trampoline confirmed | Sentinel written on resume, kernel stable |
| **HV active at PCB hijack** | CR0.WP stuck (v3) | writecr0 intercepted during resume at cpu_switch point |
| **pcb_onfault offset** | **PCB+0x108** | pcb_onfault_test: confirmed with fault recovery |
| **NPT NX during suspend** | Blocks non-ktext exec | Even `mov eax,1; ret` in kdata panics during suspend |
| **apic_ops[2] persists** | Overwrite survives rest mode | Confirmed across 8+ sessions |
| **No CFI on apic_ops** | Indirect calls unchecked | Can point at any ktext address |

### Thread Structure Layout (v16, FW 4.03)

```
+0x000: mutex/lock ptr (kdata range 0xffffffffdb...)
+0x008: DMAP ptr (likely td_proc)
+0x010: null
+0x018: DMAP ptr (list linkage)
+0x028: kdata ptr
+0x030: DMAP ptr
+0x038: DMAP ptr
+0x050: DMAP ptr
+0x058-0x070: DMAP ptrs (various subsystems)
+0x078: DMAP ptr
+0x088: DMAP ptr
+0x098: 0x0001898bffffffff (flags/timestamp)
+0x0c8: DMAP self-reference (curthread + 0xc0)
+0x0d0: DMAP ptr (same as +0x008, proc?)
+0x0d8: 1 (flag)
+0x0e0: 0x00000004000003ff (capabilities)
+0x0e8: 0x2020000000000000
+0x140: DMAP ptr
+0x148: DMAP ptr
+0x290: td_name "my_kthread\0" (MAXCOMLEN=19)
+0x3b8: 0x0044004400000000 (scheduling params)
+0x3c0: 0x02bc02bc000a0044 (scheduling params)
+0x3f8: td_pcb → 0xffffff80XXXXXXXX (kernel heap)
```

---

## Failures & Lessons

1. **XOM is enforced through DMAP**: The hypervisor doesn't just block ktext virtual address reads — it also blocks reading the same physical pages through the DMAP alias. This eliminates the most obvious bypass.

2. **Blind execution is dangerous**: Without fault recovery, any probe that doesn't return cleanly kills the kernel thread. Some bad probes crash the entire kernel.

3. **Struct offsets must be discovered empirically**: FreeBSD struct layouts on PS5 (FW 4.03) don't match public FreeBSD source exactly. td_pcb at +0x3f8 had to be found by dumping the struct.

4. **Linux gcc ≠ PS5 SDK**: Building kldload with Linux gcc produces an incompatible binary. Must use ps5-payload-dev/sdk with `prospero-clang` (target x86_64-sie-ps5).

5. **KASLR means addresses change every boot**: All ktext/kdata addresses are randomized. Only offsets from kdata_base or ktext_base are stable.

---

## Current Blockers & Constraints

1. **NPT NX during suspend**: HV enforces No-Execute on ALL non-ktext pages during `cpususpend_handler`. Custom code in kdata/kmod pages panics. apic_ops[2] MUST point to a ktext address.
2. **XOM on ktext**: Can't read or write ktext. Can only execute existing code at known offsets.
3. **PCB hijack too late**: HV is already active when cpu_switch runs during resume. PCB hijack gives code execution but NOT pre-HV access.
4. **PCB hijack unreliable**: Persistence loop crashes (multi-core race), no loop loses pcb_rip.

## What Works

- apic_ops[2] overwrite persists through suspend/resume
- Can point apic_ops[2] at any ktext address (no CFI)
- kdata persists (code, pointers, markers all survive)
- Guest PTE modifications persist (NX clearing survives)
- PCB hijack CAN execute code on resume (v2 proven) but unreliable and too late for HV probing

## Phase 4: ktext Gadget Discovery (via FreeBSD Source + Known Offsets)

**Status: IN PROGRESS**

### Key Breakthrough: We Don't Need to Read ktext

FreeBSD source code reveals the exact behavior of functions at known ktext offsets. Two critical functions from `cpu_switch.S`:

- **`savectx(pcb)`** — takes PCB pointer in **RDI**, saves ALL CPU state (GPRs, CRs, DRs, MSRs, GDT/IDT/LDT/TR) to it, returns 1
- **`resumectx(pcb)`** — takes PCB pointer in **RDI**, restores EVERYTHING from it (including RSP and RIP), effectively "returns" to saved context

Both are in ktext (same compilation unit as cpu_switch), so they survive NPT NX enforcement.

**If RDI points to writable memory we control when apic_ops[2] is called → `resumectx` gives total CPU state control from a fake PCB in kdata.**

### FreeBSD apic_ops Struct Layout (confirmed from source)

```
apic_ops[0]  = create(u_int, int)
apic_ops[1]  = init(vm_paddr_t)
apic_ops[2]  = xapic_mode(void)     ← our hijack target
apic_ops[3]  = is_x2apic(void)
apic_ops[4]  = setup(int)
apic_ops[5]  = dump(const char *)
apic_ops[6]  = disable(void)
apic_ops[7]  = eoi(void)
...28 total entries
```

Sony modified `xapic_mode` to return `int` (1 for XAPIC mode) instead of FreeBSD's `void`. It takes NO arguments — RDI is whatever the caller happened to have.

### ACPI Suspend/Resume Path (from FreeBSD source)

```
SUSPEND: acpi_sleep_machdep() → savectx(susppcbs[0]) → enters S3
RESUME:  ACPI wakeup code → resumectx(susppcbs[0]) → kernel continues
```

`susppcbs` is a globally allocated array of PCBs. The pointer is patched into low-memory ACPI wakeup code via `WAKECODE_FIXUP`. `resumectx` is called very early in resume with RDI = susppcbs[0].

### New Payloads Built

#### register_capture (`examples/register_capture/`)
Installs a trampoline that captures ALL 16 GPRs + RSP + RFLAGS + return address when the kernel calls apic_ops[2]. Writes to kdata+0x200 capture buffer.

**Result**: capture_count=0 after three iterations. apic_ops[2] (xapic_mode) is NOT called during normal steady-state operation — only during LAPIC init (boot) and LAPIC resume (after suspend). Trampoline approach is a dead end for normal-ops testing. Need to test during suspend/resume cycle instead.

**Iterations**:
- v1: Trampoline at kdata+0x400 — NX bit blocked execution, capture_count=0
- v2: Added DMAP-based NX clearing — instant kernel panic (DMAP probe reads unmapped addresses)
- v3: Static buffer in .data section — no panic, but capture_count=0 (apic_ops[2] never called)

#### savectx_finder (`examples/savectx_finder/`)
Three modes:
- **Mode 0x403 (SCAN)**: Scans kdata for pointers in range [cpu_switch, cpu_switch+0x2000] to locate savectx/resumectx addresses
- **Mode 0x2 (ARM)**: Points apic_ops[2] at `justreturn` (ktext `ret` gadget, kdata-0x9cf990) + writes "JUSTRETA" sentinel to kdata+0x200. Leave armed for suspend/resume test
- **Mode 0x3 (READBACK)**: Post-resume verification — checks sentinel persistence, reads apic_ops[2] value, restores original xapic_mode via set_tpr-8 trick

**v2 changes**: Removed dangerous DMAP probe code (same crash pattern as register_capture v2). Removed mode 0x1 (DMAP low-memory scan). Added modes 0x2/0x3 for justreturn suspend/resume test.

### pivot_scan_safe v5 — DMAP ktext Byte Scanner

Attempted to read ktext bytes through DMAP to scan for gadget patterns.

**Results:**
- DMAP base discovered: `0xFFFF9DA700000000` (via `pm_pml4 - CR3`)
- ktext PA found: `0x0000000004290000` (page table walk succeeded)
- **DMAP ktext read: FAILED** — ktext physical pages are **completely unmapped from DMAP** (PTE = 0)
- kdata DMAP reads work fine — only ktext is excluded
- **Conclusion**: Cannot read ktext bytes through any path. Must use execution-based probing.

---

## Phase 5: Execution-Based Gadget Probing

**Status: PLANNING**

### The Core Challenge

We need a **stack pivot gadget** in ktext so that apic_ops[2] can redirect RSP to a controlled ROP chain during LAPIC resume. The constraints:

1. **Cannot read ktext** — XOM enforced at VA level, DMAP pages unmapped at PT level
2. **Cannot execute non-ktext during suspend** — NPT NX enforced by hypervisor
3. **apic_ops[2] has no CFI** — can point at any ktext address
4. **kdata persists** — our data/pointers survive suspend/resume
5. **Register state at apic_ops[2] during resume is UNKNOWN** — register_capture got count=0 (only called during LAPIC resume), R8 gamble proved RDI is not valid

### The Circular Problem

- To pick the right gadget → need to know register state at resume
- To capture registers at resume → need a ktext trampoline (NPT NX blocks non-ktext)
- To find a ktext trampoline → need to find a gadget first

### Gadget Candidates (Ranked by Likelihood of Existing)

| Gadget | Bytes | Likelihood | Controllable Register | Notes |
|--------|-------|------------|----------------------|-------|
| `leave; ret` | `C9 C3` | **VERY HIGH** | RBP | Compilers actually emit this. Standard epilogue |
| `pop rsp; ret` | `5C C3` | **HIGH** | Stack (need controlled stack) | Only 2 bytes, common coincidence |
| `mov rsp, rbp; pop rbp; ret` | `48 89 EC 5D C3` | **HIGH** | RBP | Standard epilogue variant |
| `xchg rsp, rax; ret` | `48 94 C3` | **LOW** | RAX | 3-byte coincidence, never intentionally emitted |

**Key insight**: `xchg rsp, rax; ret` (`48 94 C3`) is a coincidental byte alignment that may or may not exist in Sony's specific compiler output. It is NOT a real instruction sequence any compiler generates. Searching for it is a gamble.

`leave; ret` (`C9 C3`) is **almost certainly present** — it's a real compiler-emitted epilogue. If RBP happens to point to kdata we control during the resume call, it gives us the same pivot capability.

### Breaking the Circle: The `leave; ret` Strategy

`leave; ret` does: `RSP = RBP; pop RBP; ret` (executes the address at `[RBP]`).

Even without knowing RBP's value at resume, we can use `leave; ret` as a **diagnostic tool**:

1. **Find a `leave; ret` gadget** in ktext (high confidence it exists)
2. **Point apic_ops[2] at it** and trigger suspend/resume
3. **Observe the crash** — the panic address tells us what RBP contained
   - If RBP → kdata range: we can control the pivot destination
   - If RBP → stack/heap: we learn the stack layout for alternative pivots
   - If RBP → 0 or garbage: `leave; ret` won't work, try `pop rsp; ret` instead

This turns a potential crash into **information gathering** — each crash teaches us the register state we couldn't capture any other way.

### Probing Strategy

**Smart candidate selection** near the 28 known apic_ops function entry points:

1. Functions in x86-64 are padded with `0xCC` (int3) bytes between them
2. Function epilogues (`leave; ret`, `pop; ret`, `ret`) appear just before the padding
3. We know 28 function start addresses → probe offsets -3, -4, -5, -6 from each
4. Skip -1, -2 (almost certainly `0xCC` padding → kernel panic)
5. ~112 candidates for `leave; ret` (`C9 C3`)

**Probing mechanism**: Single-probe-per-deployment via `fw_ver` encoding:
- `fw_ver = 0x0001XXYY` → probe apic_ops[YY] at offset -XX
- Kernel thread jumps to candidate with pcb_onfault set for #PF recovery
- Reports: 0 = returned normally (not a pivot), 1 = RSP changed (pivot!), 2 = faulted (#PF)
- If #BP (0xCC) → kernel panic, reboot, try next candidate

### The Goal

**Ultimate objective**: Find a ktext gadget that, when called via apic_ops[2] during LAPIC resume, redirects execution to a ROP chain in kdata. This ROP chain would:

1. Execute `wrmsr` to modify LSTAR or other MSRs before the hypervisor re-locks them
2. Or execute `mov cr0, X` to disable CR0.WP before HV restarts
3. Or dump HV state (VMCS fields, EPT/NPT root) for analysis
4. The key is that LAPIC resume happens **during the suspend/resume sequence** — potentially in a window where the HV is not yet fully active

If the HV IS already active at the apic_ops[2] call point (as PCB hijack v3 suggested), the ROP chain can still be used to probe exactly what the HV allows/blocks at that stage, mapping the HV's enforcement boundary.

### Revised Strategy: INT3 + IST (No Stack Pivot Needed)

**Key insight**: We don't need a stack pivot gadget at all. The CPU's IST (Interrupt Stack Table) mechanism gives us RSP control directly when an interrupt fires. This is the **same technique ps5-kstuff uses** for its kekcall infrastructure.

**How it works:**
1. Modify IDT[3] (INT 3 handler): handler = `pop_all_iret`, IST = 1
2. Modify TSS IST1 for all CPUs: point to kdata chain buffer
3. Write ROP chain to kdata at the IST1 address
4. Point apic_ops[2] at a `CC` byte in ktext (function padding, near-certain to exist)
5. Suspend/resume → LAPIC resume calls apic_ops[2] → CC fires INT 3 → CPU loads RSP from IST1 → pop_all_iret consumes chain → iretq → full ROP

The first 5 pops of pop_all_iret consume the CPU-pushed trap frame (RIP, CS, RFLAGS, RSP, SS → loaded into RDI, RSI, RDX, RCX, R8). Pops 6-15 read our controlled values from kdata (R9, RAX, RBX, RBP, R10-R15). The iretq at the end jumps to our target with controlled RSP.

**Previous approach (blind gadget scanning) abandoned** — we have all needed gadgets at known offsets from ps5-kstuff.

---

## Phase 6: IDT/TSS Safety Research

**Question**: Will modifying IDT/TSS entries block rest mode entry (like ktext PTE modifications did)?

### Evidence FOR safety (strong):

1. **apic_ops[2] modification persists** through 8+ suspend/resume cycles. apic_ops is a kdata function pointer table — same category as IDT.
2. **HV integrity monitor only checks ktext PTEs**, not kdata structures. The XOTEXT bit clearing on ktext PTEs triggered the monitor, but ALL kdata modifications (apic_ops, markers, QA flags) survive fine.
3. **ps5-kstuff modifies both IDT and TSS** (main.c lines 1170-1181):
   - IDT[1] (#DB handler), IDT[2] (NMI → doreti_iret), IDT[13] (#GP handler)
   - TSS IST3, IST7 for all CPUs
   - System runs stably after these modifications.
4. **IDT and TSS are in kdata** — read-write kernel data segment. No known HV checksum mechanism for arbitrary kdata.

### Evidence AGAINST (concerns):

1. **IDT/TSS + rest mode never explicitly tested** — ps5-kstuff modifies these but doesn't test suspend/resume afterward.
2. **During suspend processing**, HV is active. Modified interrupt handlers called during suspend could cause unexpected behavior.
3. **ACPI wakeup code** may reload IDT/GDT/TSS from known-good copies, overwriting our changes.
4. **DR registers likely do NOT persist** through suspend/resume (not in suspend PCB).

### Assessment Table

| Structure | In kdata? | HV checksums? | Survives rest mode? |
|-----------|-----------|---------------|---------------------|
| apic_ops  | Yes       | No (confirmed) | **Yes (8+ tests)** |
| kdata markers | Yes  | No (confirmed) | **Yes (confirmed)** |
| ktext PTEs | No       | **Yes**       | **No — blocks rest mode** |
| IDT       | Yes       | No (inferred) | **Likely yes** (untested) |
| TSS IST   | Yes       | No (inferred) | **Likely yes** (untested) |
| DR regs   | CPU state | N/A           | **Likely no** |

**Conclusion**: IDT/TSS modifications should be safe based on the pattern that ALL kdata modifications survive. Needs empirical confirmation.

---

## Known Gadgets Reference (FW 4.03, ps5-kstuff offsets)

All offsets relative to kdata_base (negative = ktext):

| Gadget | Offset | Purpose |
|--------|--------|---------|
| doreti_iret | -0x9cf84c | iretq — universal chain link |
| pop_all_iret | -0x9cf8ab | Pop 15 regs + add rsp 0x20 + iretq |
| pop_all_except_rdi_iret | -0x9cf8a7 | Skip RDI pop variant |
| nop_ret | -0x9d20ca | ret (no-op return) |
| wrmsr_ret | -0x9d20cc | wrmsr; ret — write MSR |
| rdmsr_start | -0x9d0cfa | rdmsr — read MSR |
| mov_cr3_rax | -0x396f9e | mov cr3, rax |
| mov_rdi_cr3 | -0x39700e | mov rdi, cr3 |
| rep_movsb_pop_rbp_ret | -0x99002a | rep movsb; pop rbp; ret |
| cpu_switch | -0x9d6f80 | Context switch function |
| copyin | -0x9908e0 | Copy user→kernel |
| copyout | -0x990990 | Copy kernel→user |
| push_pop_all_iret | -0x96be70 | Push/pop all regs + iretq |
| justreturn | -0x9cf990 | Exception return path (doreti) |
| justreturn_pop | -0x9cf988 | doreti path + 8 |
| add_rsp_iret | -0x9cf853 | add rsp, N; iretq |
| swapgs_add_rsp_iret | -0x9cf856 | swapgs; add rsp; iretq |
| malloc | -0xa9b00 | kernel malloc(9) |

### IDT/TSS Offsets (kdata-relative)

| Structure | Offset | Size |
|-----------|--------|------|
| IDT base | +0x64cdc80 | 256 × 16 bytes |
| TSS base | +0x64d0830 | per-CPU, 0x68 stride |
| GDT base | +0x64cee30 | — |
| PCPU base | +0x64d2280 | — |
| apic_ops | ktext+0x1934AC8 | 28 × 8 bytes |

### IDT Gate Descriptor Format (16 bytes)

```
Bytes 0-1:   offset_low (handler bits 15:0)
Bytes 2-3:   segment_selector (0x20 = kernel CS)
Byte 4:      IST (bits 2:0), reserved (bits 7:3)
Byte 5:      type_dpl_p (0x8E = interrupt gate, DPL=0, present)
Bytes 6-7:   offset_mid (handler bits 31:16)
Bytes 8-11:  offset_high (handler bits 63:32)
Bytes 12-15: reserved
```

### TSS IST Layout

IST entries at TSS + 36 + (N-1)*8 for IST N (N=1..7):
- IST1: TSS + 36  (= TSS + 28 + 1*8)
- IST3: TSS + 52  (= TSS + 28 + 3*8)
- IST7: TSS + 84  (= TSS + 28 + 7*8)

### IST Assignments (FW 4.03)

| IST | Used By | Notes |
|-----|---------|-------|
| IST1 | FreeBSD #DF handler | **DO NOT TOUCH** — causes triple fault |
| IST2 | Unknown | Untested |
| IST3 | ps5-kstuff #GP (IDT[13]) | kekcall dispatch |
| IST4 | System (preserved by kstuff) | kstuff saves/restores this |
| IST5 | **Unused** | Safe for our use |
| IST6 | Unknown/Unused | Likely safe |
| IST7 | ps5-kstuff #DB (IDT[1]) | Debug trap |

---

## Phase 6a: IDT/TSS Safety Test Results

### Test 1: IST1 (FAILED — IST collision)

**Payload**: `idt_safe_test` mode 0x1 with IST1
- Modified IDT[3] IST field = 1, TSS IST1 = kdata+0x300
- Rest mode entry: **succeeded**
- Resume from rest mode: **succeeded**
- Sending kldload.elf after resume: **FROZEN** — required holding power button
- **Root cause**: IST1 is used by FreeBSD Double Fault (#DF) handler. Overwriting TSS IST1 meant any double fault → CPU loads RSP from kdata+0x300 (garbage) → triple fault → CPU halt

### Test 2: IST5 (PARTIAL SUCCESS — rest mode safe, kldload crashes)

**Payload**: `idt_safe_test` mode 0x1 with IST5 (OUR_IST_NUM=5)
- Modified IDT[3] IST field = 5, TSS IST5 = kdata+0x300

**Output**:
```
[0x00] magic=0x49445453 status=0x0001  ← success
[0x08] kdata_base=0xffffffff8f470000
[0x10] ktext_base=0xffffffff8e870000
[0x18] idt_base=0xffffffff9593dc80
[0x20] tss_base=0xffffffff95940830
[0x28] orig IDT[3] lo=0x8eb0ee0000204178  ← IST=0, DPL=3, handler=0xffffffff8eb04178
[0x30] orig IDT[3] hi=0x00000000ffffffff
[0x38] mod  IDT[3] lo=0x8eb0ee0500204178  ← IST=5 ✓
```

**Results**:
- Rest mode entry: **succeeded** ✓
- Resume from rest mode: **succeeded** ✓
- Sending kldload.elf after resume: **instant kernel panic** (clean shutdown, not frozen)
- **Improvement over IST1**: Clean panic vs freeze. #DF handler works → panic handler can execute

**Key findings**:
1. **HV does NOT block rest mode with IDT/TSS modifications** — confirmed
2. **IDT[3] IST field persists through rest mode** (kldload crash proves INT3 still uses IST5 after resume)
3. **TSS IST5 persists through rest mode** (same evidence — IST5 must still point to kdata+0x300)
4. **kldload crash is expected**: IDT[3] IST=5 → any INT3 during normal operation → RSP=kdata+0x300 (garbage stack) → panic
5. **Original IDT[3] has DPL=3** (0xEE = present, DPL=3, interrupt gate) — INT3 callable from usermode

**Conclusion**: IDT/TSS modifications are safe through rest mode. The chain must **self-restore** IDT[3] and apic_ops[2] after executing, otherwise kldload can't run afterward.

---

## Phase 6b: resume_chain v2 — Self-Restoring ROP Chain

### Design

The v1 chain crashed after wrmsr with no way to verify results or use kldload afterward. v2 adds self-restoration: after wrmsr, the chain restores IDT[3] original and apic_ops[2] original using `rep_movsb_pop_rbp_ret` gadget (memcpy), then attempts return via `get_timer_freq`.

### Chain Stages (v2)

```
INT3 (CC byte in ktext) fires during LAPIC resume
  ↓ CPU loads RSP from TSS IST5 = kdata+0x300
  ↓ CPU pushes trap frame to [kdata+0x2D8..0x2F8]

Stage 0 (kdata+0x300): pop_all_iret
  → Pops 5 trap values (RIP→RDI, CS→RSI, RFLAGS→RDX, RSP→RCX, SS→R8)
  → Pops 10 controlled values (R9..R15)
  → iretq → Stage 1

Stage 1 (kdata+0x400): pop_all_iret → wrmsr
  → Loads ECX=0xC0000082 (LSTAR MSR#)
  → Loads EAX=LSTAR_low32, EDX=LSTAR_high32
  → iretq → wrmsr_ret (writes LSTAR back to current value for v1 safe test)
  → ret → Stage 2

Stage 2 (kdata+0x500): pop_all_iret → restore IDT[3]
  → Loads RDI=IDT[3] addr, RSI=save[0..1] addr, RCX=16
  → iretq → rep_movsb_pop_rbp_ret (copies 16 bytes: original IDT[3] restored!)
  → pop rbp, ret → Stage 3

Stage 3 (kdata+0x600): pop_all_iret → restore apic_ops[2]
  → Loads RDI=apic_ops[2] addr, RSI=save[3] addr, RCX=8
  → iretq → rep_movsb_pop_rbp_ret (copies 8 bytes: original apic_ops[2] restored!)
  → pop rbp, ret → Stage 4

Stage 4 (kdata+0x700): return attempt
  → doreti_iret → iretq → get_timer_freq (dummy RSP)
  → get_timer_freq returns → crash expected (v1)
  → But IDT[3] and apic_ops[2] are ALREADY RESTORED before crash
```

### Key Properties

- **Self-restoring**: Even if the return crashes, IDT[3] and apic_ops[2] are already restored by Stages 2-3
- **After power cycle + re-exploit**: kldload works normally (IDT[3] IST back to 0)
- **Chain verification**: If system resumes and kldload works → chain executed AND restored successfully
- **TSS IST5 left modified**: Harmless once IDT[3] IST=0 (no vector uses IST5 anymore)

### Gadgets Used

| Gadget | Offset | Role |
|--------|--------|------|
| pop_all_iret | -0x9cf8ab | Register loading (4 uses) |
| wrmsr_ret | -0x9d20cc | Write MSR |
| rep_movsb_pop_rbp_ret | -0x99002a | Restore IDT[3] and apic_ops[2] |
| doreti_iret | -0x9cf84c | iretq chain link |
| get_timer_freq | apic[19] | Safe return function |
| nop_ret | -0x9d20ca | No-op return |

### resume_chain v3 Results — FAILED (enters rest, doesn't resume)

Deployed the full 6-stage INT3+IST chain:
- System enters rest mode (chain arms successfully)
- **System never boots back from rest mode**

**Diagnostics (v5)**:
- Mode 0x1 (kdata dump): All zeros at kdata+0x000..0x447 — chain area not corrupting globals ✓
- Mode 0x2 (CC byte test): Instant panic — confirms byte at copyin-1 IS 0xCC ✓

**Leading failure hypotheses**:
1. Multi-CPU race: all CPUs call apic_ops[2]=CC simultaneously, shared IST5 → stack corruption
2. rep_movsb gadget might not exist at offset -0x99002a (can't verify, XOM)
3. Chain crashes before restoring apic_ops[2], leaving CC pointer for resume
4. On resume, corrupted chain data → crash

---

## Phase 7: IDT/TSS Persistence Verification (resume_chain v6)

**Critical question**: Do IDT and TSS modifications survive suspend/resume?

### Test Design
- Mode 0x1 (ARM): Modify IDT[3] IST field (0→1), write marker to TSS[0] IST1, save originals to kdata persistence area, keep apic_ops[2] = original xapic_mode (safe)
- Mode 0x2 (READBACK): After resume, compare current IDT[3] and TSS IST1 with saved armed values

### Results — BOTH PERSIST ✓
```
IDT[3]:  0x0050455253495354 → "PERSIST" (modification survived!)
TSS IST: 0x0050455253495354 → "PERSIST" (modification survived!)
Sentinel: 0xdead1d7acc000001 → match ✓
IDT[3] armed = IDT[3] current (identical qwords)
```

**Conclusions**:
1. IDT modifications persist through rest mode (handler + IST field)
2. TSS IST modifications persist through rest mode
3. ACPI wakeup does NOT restore IDT/TSS from clean copies
4. INT3+IST approach is viable

---

## Phase 8: doreti_iret Bounce (resume_chain v7)

### The Insight

Instead of a complex 6-stage ROP chain, use the CPU's trap mechanism as a self-sustaining trampoline. This eliminates ALL failure points from v3:

| v3 Problem | v7 Solution |
|-----------|-------------|
| Multi-CPU race on shared IST5 | No IST — each CPU uses own stack |
| Unverifiable rep_movsb gadget | No gadgets needed — just `iretq` |
| 6-stage chain complexity | Single instruction handler |
| Must restore IDT/apic_ops | Self-sustaining, no restoration needed |

### How It Works

```
1. IDT[3] handler = doreti_iret (just `iretq`)
2. apic_ops[2] = xapic_mode - 1 (hoping it's a CC byte)

Call flow:
  call *apic_ops[2]
    → CC byte at xapic_mode-1
    → INT3 trap
    → CPU pushes {RIP=xapic_mode, CS, RFLAGS, RSP, SS} on current stack
    → doreti_iret = iretq
    → pops everything back
    → RIP = xapic_mode, RSP = original
    → xapic_mode: mov eax, 1; ret
    → clean return to caller!
```

### Properties
- **Self-sustaining**: Works every call, every CPU, every suspend/resume cycle
- **No chain data**: No IST stacks, no kdata buffers
- **Multi-CPU safe**: Each CPU's trap frame on its own stack
- **Minimal surface**: Single `iretq` instruction as handler

### Test Modes
- Mode 0x1 (SAFE_ARM): IDT[3]=doreti_iret, apic_ops[2]=original (baseline — no CC)
- Mode 0x2 (BOUNCE_ARM): IDT[3]=doreti_iret, apic_ops[2]=xapic_mode-1 (full bounce)
- Mode 0x3 (READBACK): Verify state after resume

### v7 Mode 0x1 Results — SAFE_ARM ✓ (PASSED)

**Setup**: IDT[3] handler = doreti_iret, apic_ops[2] = original xapic_mode (no CC)

**ARM output** (kdata_base=0xffffffff901b0000):
```
out[3] = 0xffffffff8f7e07b4  → doreti_iret address ✓
out[4] = 0xffffffff8f844340  → original xapic_mode
out[5] = 0xffffffff8f84433f  → xapic_mode - 1 (bounce target)
out[6] = 0xffffffff8f844178  → original IDT[3] handler (ktext+0x294178)
out[7] = 0xffffffff8f7e07b4  → new handler = doreti_iret ✓
```

**READBACK after rest mode**:
```
out[3] = "PERSIST"  → IDT[3] handler = doreti_iret survived ✓
out[4] = "PERSIST"  → apic_ops[2] unchanged ✓
out[5] = 0xdead1d7ab00ce007  → v7 sentinel ✓
out[6] = 0x1  → armed mode was 0x1
out[7] = 0xffffffff8f7e07b4  → current handler = doreti_iret ✓
```

**Conclusion**: Changing IDT[3] handler to doreti_iret does NOT break suspend/resume.

### v7 Mode 0x2 Results — BOUNCE_ARM ✗ (FAILED)

**Setup**: IDT[3] handler = doreti_iret, apic_ops[2] = xapic_mode - 1

**ARM output** (kdata_base=0xffffffff9db00000):
```
out[3] = 0xffffffff9d1307b4  → doreti_iret ✓
out[4] = 0xffffffff9d194340  → original xapic_mode
out[5] = 0xffffffff9d19433f  → xapic_mode - 1
out[6] = 0xffffffff9d1307b4  → IDT[3] handler set ✓
out[7] = 0xffffffff9d19433f  → apic_ops[2] set ✓
```

**Result**: System enters rest mode but **never boots back**.

**Analysis**: Two hypotheses:
1. **xapic_mode - 1 is NOT CC** — could be `C3` (ret from previous function) → returns wrong EAX (not 1) → LAPIC mode detection fails → crash
2. **xapic_mode - 1 IS CC** — bounce fires but something about the INT3+iretq context during suspend fails

**Key insight**: We confirmed copyin-1 is CC (v5), but xapic_mode is a completely different function. Inter-function padding isn't guaranteed to be CC — the previous function could end right at xapic_mode-1 with its own `ret` (C3).

### Byte Identification Test Results (v7b mode 0x4)

Called xapic_mode-1 from kproc context with IDT[3]=doreti_iret, RAX pre-loaded with sentinel `0xBAD0BAD0BAD0BAD0`:

**Results:**
```
out[4] = 0xbad0bad0bad0bad0  → EAX sentinel UNCHANGED → C3 (ret)
out[6] = 0x00c300c300c300c3  → verdict: C3
out[7] = 0xbad0bad0bad0bad0  → xapic_mode-2 also C3 (still in prev function epilogue)
```

**Conclusion**: **xapic_mode-1 = C3 (ret), NOT CC (INT3)**. No CC padding exists before xapic_mode — the previous function's epilogue is immediately adjacent. The doreti_iret bounce CANNOT use xapic_mode directly.

**Next approaches**:
1. Scan all 28 apic_ops function entries at -1 for CC bytes
2. Use copyin-1 (confirmed CC) with pop_all_iret + IST chain redirecting to xapic_mode
3. Find CC before any ktext function that returns 1

### Phase 9: CC Byte Scanner (resume_chain v8)

Automated scan of all 28 apic_ops entries at fn-1 using sentinel-in-RAX technique. IDT[3]=doreti_iret for CC bounce, pcb_onfault + callee-saved RBX RSP backup for fault recovery. Skips 4 dangerous entries (disable, ipi_raw, ipi_vectored, calibrate). Also tests copyin-1, copyout-1, cpu_switch-1, malloc-1 as extras.

Reports cc_bitmap, ret1_bitmap (CC entries that also return 1 = golden for simple bounce), and per-entry raw values.

**Status**: Built (1056 bytes), awaiting deployment.

---

## Build Process Documentation

### Overview

There are **three distinct build pipelines** in this repo, each producing different artifact types for different purposes.

---

### 1. Research Payloads (examples/ directory) — Produces `.bin` + `.elf`

These are the standalone kernel research payloads (resume_chain, chain_prep, suspend_stackprobe, etc.).

**Toolchain**: Standard host `gcc` + `objcopy` (NOT the PS5 SDK). No cross-compiler needed — the PS5 kernel runs on x86-64 anyway.

**Exact build steps** (using `resume_chain` as example):

```bash
cd examples/resume_chain

# Step 1: Compile C source to object file
gcc -c -o build/main.o src/main.c \
    -Os -std=c11 -ffunction-sections -fdata-sections -fno-builtin \
    -nostartfiles -nostdlib -Wall -march=btver2 -mtune=btver2 \
    -m64 -mabi=sysv -mcmodel=small -fpie -fno-stack-protector

# Step 2: Link object file into ELF using custom linker script
gcc build/main.o -o resume_chain.elf \
    -Os -std=c11 -ffunction-sections -fdata-sections -fno-builtin \
    -nostartfiles -nostdlib -Wall -march=btver2 -mtune=btver2 \
    -m64 -mabi=sysv -mcmodel=small -fpie -fno-stack-protector \
    -Xlinker -T ./linker.x -Wl,--build-id=none -Wl,--gc-sections -nostdlib

# Step 3: Strip ELF to flat binary
objcopy -S -O binary resume_chain.elf resume_chain.bin

# Step 4: Move ELF into build/
mv resume_chain.elf build/
```

**Or simply**: `make` in the example directory.

**Key compiler flags explained**:
- `-Os` — optimize for size (these payloads must be small)
- `-nostartfiles -nostdlib` — no libc, no crt0 — this is a bare-metal kernel payload
- `-march=btver2 -mtune=btver2` — PS5's AMD Zen 2 CPU (btver2 is the closest base arch)
- `-fpie` — position-independent (payload gets loaded at arbitrary kdata addresses)
- `-fno-stack-protector` — no stack canaries (no libc to support them)
- `-mcmodel=small` — small code model, all symbols within 2GB

**Linker script** (`linker.x`):
- Entry point: `module_start` (function in main.c)
- Sections: `.text` (code) → `.rodata` (constants) → `.data` (initialized data) → `.bss` (zeroed data)
- Discards: `.comment`, `.note.GNU-stack`, `.eh_frame`, `.interp`, `.note.gnu.property`
- Each section gets its own PT_LOAD segment
- The `.text.module_start` section is placed FIRST so the entry point is at offset 0 in the binary

**What `.bin` vs `.elf` means**:
- `.elf` — standard ELF executable with section headers, symbol table, debug info. Used for analysis/debugging with tools like `readelf`, `objdump`, `gdb`
- `.bin` — flat raw binary, just the code+data bytes with no headers. This is what actually gets loaded into PS5 kernel memory. The entry point is byte 0. The `.bin` is produced by `objcopy -S -O binary` which strips all ELF metadata and outputs just the loadable segments laid out sequentially.

**All examples use the same Makefile pattern.** Each example directory has:
- `Makefile` — identical structure, just different `TARGET` and `ELF` names
- `linker.x` — identical linker script across all examples
- `src/main.c` — the actual payload code
- `build/` — output directory for `.o` and `.elf`
- `<name>.bin` — final flat binary in the example root

---

### 2. kstuff (ps5-kstuff) — Produces `payload.bin` / `payload.elf`

This is the main ps5-kstuff kernel payload from prosper0gdb/flatz. Located at `ps5_kernel_research/kstuff-no-fpkg/ps5-kstuff/`.

**Toolchain**: Host `gcc` + `yasm` (assembler) + `objcopy` + `python3`

**Full dependency chain**:

```
payload.elf
├── lib/lib-elf-ps5.a          (runtime library)
│   ├── crt-elf.o              (yasm: crt-elf.asm)
│   ├── crt-elf-c.o            (gcc: crt-elf-c.c)
│   ├── dl.o                   (gcc: dl.c)
│   └── syscalls-ps5.o         (yasm: syscalls-ps5.asm ← python3 syscalls-ps5.py)
├── prosper0gdb/prosper0gdb.o  (gcc: r0gdb.c + r0run.o + offsets.c)
│   └── r0run.o                (yasm: r0run.asm)
├── main.c                     (main payload logic)
├── sqlite_triggers.c
├── kelf                       (embedded kernel ELF — the ROP chain)
│   └── kelf.o                 (yasm: kelf.asm + structs.inc)
└── uelf/uelf.bin              (embedded userland ELF)
    └── uelf/uelf              (gcc: uelf/*.c + BearSSL + libtomcrypt)
        ├── uelf/crt.o         (yasm: uelf/crt.asm)
        ├── BearSSL/build/libbearssl.a  (bash build_bearssl.sh)
        └── libtomcrypt/libtomcrypt.a   (bash build_libtomcrypt.sh)
```

**Exact build commands** (in order):

```bash
cd ps5_kernel_research/kstuff-no-fpkg

# 1. Build runtime library
cd lib
python3 syscalls-ps5.py > syscalls-ps5.asm
yasm -f elf64 crt-elf.asm -o crt-elf.o
gcc -c -isystem ../freebsd-headers -nostdinc -fno-stack-protector -O3 crt-elf-c.c -o crt-elf-c.o -fPIE -ffreestanding
gcc -c -isystem ../freebsd-headers -nostdinc -fno-stack-protector dl.c -o dl.o -fPIE -ffreestanding
yasm -f elf64 syscalls-ps5.asm -o syscalls-ps5.o
ld -r crt-elf.o crt-elf-c.o dl.o syscalls-ps5.o -o lib-elf-ps5.a
cd ..

# 2. Build prosper0gdb
cd prosper0gdb
yasm -f elf64 -g dwarf2 r0run.asm -o r0run.o
gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector \
    -r -Wl,--unique='*' -ffunction-sections -fdata-sections \
    -DPS5KEK r0gdb.c r0run.o offsets.c -o prosper0gdb.o -fPIE -ffreestanding \
    -fno-unwind-tables -fno-asynchronous-unwind-tables
cd ..

# 3. Build kelf (kernel ROP chain)
cd ps5-kstuff
cp structs-ps5.inc structs.inc
yasm -f elf64 -g dwarf2 kelf.asm -o kelf.o
gcc -nostdlib -shared kelf.o -o kelf

# 4. Build BearSSL and libtomcrypt
bash build_bearssl.sh
bash build_libtomcrypt.sh

# 5. Build uelf (userland ELF)
yasm uelf/crt.asm -f elf64 -o uelf/crt.o
gcc -Wl,-Bsymbolic -Wl,-gc-sections -ffunction-sections -fdata-sections -O3 -g \
    -isystem ../freebsd-headers -nostdinc -nostdlib -mgeneral-regs-only \
    -fno-stack-protector -fPIE -fPIC -shared -fvisibility=hidden -ffreestanding \
    uelf/crt.o uelf/*.c -L BearSSL/build -lbearssl -L libtomcrypt -ltomcrypt \
    -o uelf/uelf -Wl,-z,max-page-size=4096
objcopy --strip-all uelf/uelf uelf/uelf.bin

# 6. Build final payload
gcc -O0 -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static \
    ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o main.c -DPS5KEK \
    ../prosper0gdb/dbg.c sqlite_triggers.c \
    -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding -no-pie \
    -Wl,-z,max-page-size=16384 -Wl,-zcommon-page-size=16384

# 7. Convert to binary and patch ELF header
objcopy payload.elf --only-section .text --only-section .data --only-section .bss \
    --only-section .rodata -O binary payload.bin
python3 ../lib/frankenelf.py payload.bin
```

**Or simply**: `make` in the `ps5-kstuff/` directory (it builds deps automatically).

**frankenelf.py**: Post-processes the `.bin` by patching the ELF magic bytes from standard `\x7fELF` to `\xeb\x0bPLD` and adjusting segment sizes. This makes the binary look like a "PLD" format that the PS5 loader expects rather than a standard ELF.

**Key differences from examples/ payloads**:
- Uses `yasm` assembler for hand-written assembly (kelf.asm, crt.asm, r0run.asm, syscalls)
- Uses `-O0` (no optimization) for debuggability
- Page size set to 16384 (PS5 page size) via linker flags
- Links against FreeBSD headers (`-isystem ../freebsd-headers`)
- The `kelf` binary is assembled from `kelf.asm` which contains the actual kernel ROP chain gadgets
- `uelf` is a separate shared library with BearSSL + libtomcrypt for crypto ops
- Uses `objcopy --only-section` (keeps specific sections) instead of `-S -O binary` (keeps everything)

---

### 3. kstuff.elf (ps5-kstuff-ldr) — Produces `kstuff.elf`

This is the **loader wrapper** that embeds `payload.bin` (from ps5-kstuff above) and runs it on the PS5. Located at `ps5_kernel_research/kstuff-no-fpkg/ps5-kstuff-ldr/`.

**Toolchain**: PS5 Payload SDK (`prospero-clang`) — same as kldload.

**How it works**: It first builds ps5-kstuff's `payload.bin`, converts it to a C byte array with `xxd -i`, then compiles a PS5 userland ELF that embeds and loads that payload.

**Exact build commands**:

```bash
cd ps5_kernel_research/kstuff-no-fpkg/ps5-kstuff-ldr

# Step 1: Build the kernel payload (triggers ps5-kstuff Makefile)
make -C ../ps5-kstuff/

# Step 2: Convert payload.bin to C header (byte array)
xxd -i ../ps5-kstuff/payload.bin > payload_bin.c
# This produces: unsigned char ____ps5_kstuff_payload_bin[] = { 0xeb, 0x0b, ... };

# Step 3: Compile the loader ELF
/opt/ps5-payload-sdk/bin/prospero-clang -Wall -Werror \
    -o kstuff.elf main.c sqlite_triggers.c -lsqlite3

# Step 4: Strip debug symbols
strip kstuff.elf
```

**Or simply**: `PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk make` in the `ps5-kstuff-ldr/` directory.

**Key points**:
- `xxd -i` converts the binary payload to a C byte array — this embeds the kernel payload directly into the userland ELF
- Links against `-lsqlite3` for SQLite trigger-based exploit delivery
- `main.c` handles loading the embedded payload into kernel memory via kekcalls
- The final `kstuff.elf` is a PS5 userland binary that contains everything needed

---

### 4. kldload — Produces `kldload.elf`

This is a PS5 userland payload that loads kernel modules. Located at `ps5_kernel_research/kstuff-no-fpkg/kldload/`.

**Toolchain**: PS5 Payload SDK (`prospero-clang`) — this is a DIFFERENT toolchain from the others!

**SDK location**: `/opt/ps5-payload-sdk/`

**SDK tools used**:
- `prospero-clang` — Clang 18.1.3 targeting `x86_64-sie-ps5` (Sony Interactive Entertainment PS5 target triple)
- `prospero-lld` — LLVM linker for PS5
- `prospero-deploy` — sends payload to PS5 over network
- Other tools: `prospero-ar`, `prospero-nm`, `prospero-objcopy`, `prospero-strip`

**Exact build commands**:

```bash
cd ps5_kernel_research/kstuff-no-fpkg/kldload

# The SDK include sets CC=/opt/ps5-payload-sdk/bin/prospero-clang, etc.
# via: include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

# Build
/opt/ps5-payload-sdk/bin/prospero-clang -Wall -Werror -o kldload.elf \
    main.c kekcall.asm -O0 -lSceSystemService
strip kldload.elf

# Deploy to PS5 (optional)
/opt/ps5-payload-sdk/bin/prospero-deploy -h <PS5_IP> -p 9021 kldload.elf
```

**Or simply**: `PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk make` in the `kldload/` directory.

**Key differences**:
- This is a **userland** payload, not a kernel payload — it runs as a PS5 process
- Uses `prospero-clang` (PS5 SDK Clang) instead of host `gcc`
- Links against `-lSceSystemService` (Sony PS5 system library)
- Includes `kekcall.asm` for making kernel executive calls from userland
- Output is a standard PS5 ELF (not a flat binary) — the PS5 loader handles it directly
- `strip` removes debug symbols for size

---

### Quick Reference

| Artifact | Directory | Toolchain | Compiler | Assembler | Key Output |
|----------|-----------|-----------|----------|-----------|------------|
| Research payloads | `examples/*` | Host | `gcc` | N/A | `.bin` (flat binary) |
| ps5-kstuff | `kstuff-no-fpkg/ps5-kstuff` | Host | `gcc` | `yasm` | `payload.bin` (frankenelf) |
| kstuff.elf | `kstuff-no-fpkg/ps5-kstuff-ldr` | PS5 SDK | `prospero-clang` | N/A | `kstuff.elf` (embeds payload.bin) |
| kldload | `kstuff-no-fpkg/kldload` | PS5 SDK | `prospero-clang` | `prospero-as` | `kldload.elf` (PS5 ELF) |

### Prerequisites

To build everything from scratch you need:
- `gcc` (any recent version, tested with 13.3.0)
- `objcopy` (GNU Binutils, tested with 2.42)
- `yasm` assembler (for kstuff assembly files — kelf.asm, crt.asm, etc.)
- `python3` (for syscall generation scripts and frankenelf.py)
- `xxd` (for converting payload.bin to C byte array — needed for kstuff.elf)
- PS5 Payload SDK at `/opt/ps5-payload-sdk/` (only needed for kstuff.elf and kldload.elf)
- `make`

---

## Phase 10: Gadget Discovery — apic_ops → sysent

**Status: apic_ops EXHAUSTED, sysent scanner READY**

### v10a Probe Results

Deployed v10a payload to probe fn-2 (two bytes before function entry) for `leave` (C9) bytes. Since v8 confirmed fn-1=C3 (ret) for many entries, finding C9 at fn-2 gives us `leave;ret` (C9 C3) = a stack pivot gadget.

The payload uses fw_ver encoding `0xddXX` where XX = apic_ops entry index, probing that entry's fn-2 address with sentinel-in-RAX + pcb_onfault fault recovery.

#### Run 1: Entry [2] fn-2 (xapic_mode - 2)

```
fw_ver override: 0x403 → 0xdd02
kdata_base = 0xffffffff96960000
ktext_base = 0xffffffff95d60000
fn         = 0xffffffff95ff4340 (xapic_mode)
fn-2       = 0xffffffff95ff433e
sentinel   = 0xbad0bad0bad0bad0 (UNCHANGED)
result     = 0x02 (FAULT — pcb_onfault caught #PF)
status     = 0x110a, magic = 0x5253434e ✓
end marker = 0xdeadbeefcafe010a ✓
```

#### Run 2: Entry [14] fn-2 (set_tpr - 2)

```
fw_ver override: 0xdd02 → 0xdd0e
kdata_base = 0xffffffff96960000  (same boot)
fn         = 0xffffffff95fee700 (set_tpr)
fn-2       = 0xffffffff95fee6fe
sentinel   = 0xbad0bad0bad0bad0 (UNCHANGED)
result     = 0x02 (FAULT — pcb_onfault caught #PF)
status     = 0x110a, magic = 0x5253434e ✓
end marker = 0xdeadbeefcafe010a ✓
```

### Interpretation: **Strong `leave;ret` (C9 C3) candidates**

Both fn-2 probes returned FAULT with sentinel unchanged. This rules out:

| Byte | What happens | Expected result | Matches? |
|------|-------------|-----------------|----------|
| C3 (ret) | Returns immediately | result=0, sentinel unchanged | **No** (result≠0) |
| CC (int3) | IDT[3]=doreti_iret bounce → return | result=0, sentinel changed | **No** |
| 48 (REX.W) | 48 C3 = `retq` → returns | result=0, sentinel unchanged | **No** (result≠0) |
| 90 (NOP) | NOP then C3 ret → returns | result=0, sentinel unchanged | **No** (result≠0) |
| 66 (operand prefix) | 66 C3 = `retw` → returns | result=0, sentinel unchanged | **No** (result≠0) |
| 5D (pop rbp) | Pops from valid stack, then ret | result=0, sentinel unchanged | **No** (result≠0) |
| **C9 (leave)** | RSP=RBP, pop [RBP] → #PF on unmapped addr | **result=2, sentinel unchanged** | **YES ✓** |

`leave` = `RSP ← RBP; pop RBP from [RSP]`. In the probe context, RBP does not point to a valid stack → the `pop` dereferences `[RBP]` → page fault → pcb_onfault catches it. RAX is never touched by `leave`, so sentinel stays at 0xBAD0BAD0BAD0BAD0.

**Combined with v7b result** (entry[2] fn-1 = C3 confirmed):
- **xapic_mode - 2 = C9 C3 = `leave; ret`** — a stack pivot gadget in ktext

Entry[14] fn-2 shows the same fault pattern → likely also C9. Needs fn-1=C3 confirmation for entry[14].

### All 28 apic_ops Addresses (this boot)

```
[0]  0xffffffff95fedb88    [14] 0xffffffff95fee700
[1]  0xffffffff95fed310    [15] 0xffffffff95fedc58
[2]  0xffffffff95ff4340    [16] 0xffffffff95ff02b8
[3]  0xffffffff95ff0808    [17] 0xffffffff95ff41d0
[4]  0xffffffff95ff3f18    [18] 0xffffffff95ff4348
[5]  0xffffffff95ff4100    [19] 0xffffffff95ff4320
[6]  0xffffffff95ff43b8    [20] 0xffffffff95fed130
[7]  0xffffffff95ff0330    [21] 0xffffffff95fedb80
[8]  0xffffffff95fee9d0    [22] 0xffffffff95ff06d0
[9]  0xffffffff95fedc60    [23] 0xffffffff95ffe830
[10] 0xffffffff95ff0240    [24] 0xffffffff95ff0800
[11] 0xffffffff95ff0aa8    [25] 0xffffffff962b69f0
[12] 0xffffffff95fed770    [26] 0xffffffff95fedfa8
[13] 0xffffffff95fee708    [27] 0xffffffff95fee760
```

### Significance

`leave; ret` at ktext offset (xapic_mode - 2) is a **usable stack pivot gadget**:
1. Point apic_ops[2] at xapic_mode-2 during LAPIC resume
2. If RBP → kdata we control: RSP redirects to our ROP chain
3. `pop RBP` loads controlled value, `ret` pops controlled RIP → full chain execution

### fn-3 Probing: Final apic_ops Conclusion

Probed fn-3 for all 4 entries where fn-1=C3 (ret). Entry [18] fn-3: benign (sentinel unchanged, verdict=2). All 4 fn-1=C3 entries show an identical pattern:

| Entry | fn-3 | fn-2 | fn-1 | Pattern |
|-------|------|------|------|---------|
| [2]   | benign | 48 (REX.W, benign) | C3 (ret) | `?? 48 C3` |
| [14]  | benign | 48 (REX.W, benign) | C3 (ret) | `?? 48 C3` |
| [17]  | benign | 48 (REX.W, benign) | C3 (ret) | `?? 48 C3` |
| [18]  | benign | 48 (REX.W, benign) | C3 (ret) | `?? 48 C3` |

**Sony Clang epilogue pattern**: Every function ends with `... 48 C3` — a REX.W-prefixed instruction followed by `ret`. This is completely consistent across all apic_ops functions. No `leave;ret` (C9 C3) exists anywhere in apic_ops epilogues.

**Correction**: The v10a analysis incorrectly identified fn-2=FAULT as evidence of `leave` (C9). The FAULT result was actually caused by the `48` (REX.W prefix) byte creating `48 <next_instr_byte>` which decoded as a different instruction and faulted. The actual byte at fn-2 is `48`, not `C9`.

**apic_ops is exhausted as a gadget source.** All 28 functions are compiled by the same Sony Clang with identical calling conventions — no epilogue variation exists.

---

## Phase 10b: Sysent Table Scanner — Expanding the Search

### Rationale

The sysent (system call entry) table contains ~678 function pointers spanning the **entire kernel** — different subsystems, different compilation units, potentially different compiler flags or even hand-written assembly. This gives us ~150+ unique functions (many sysent entries point to `nosys`) from across the kernel, vastly expanding the search space beyond the 28 apic_ops functions.

### v10b Design

Single-entry probe payload supporting two modes:

| Mode | fw_ver encoding | Source |
|------|----------------|--------|
| 0xAA | `printf '\xNN\xAA\xHH\x00'` | sysent[HH:NN] (index = HH<<8 \| NN) |
| 0xEE | `printf '\xNN\xEE\x00\x00'` | apic_ops[NN] (backward compat) |

**Probe technique**: Same as v8/v10a — IDT[3]=doreti_iret for CC bounce, pcb_onfault for #PF recovery, sentinel-in-RAX classification.

**RSP/RBP fix**: The probe function (`probe_byte`) now saves and restores both RBX and RBP before calling the target. This prevents stack corruption when the target function modifies RBP before faulting — pcb_onfault recovery restores RSP from RBX, then pops both RBP and RBX to return to a clean state.

**Sysent structure** (FreeBSD):
```c
struct sysent {       /* 48 bytes per entry */
    int      sy_narg;        /* +0: number of arguments */
    sy_call_t *sy_call;      /* +8: implementing function pointer */
    /* ... other fields ... */
};
```

Sysent table at ktext + 0x1100310. Function pointer: `sysent_base + entry * 48 + 8`.

**Output layout** (512 bytes, 64 uint64_t slots):
```
[0]      = MAGIC(lo32) | status(hi32)  — 0x010b=in-progress, 0x110b=complete
[1]      = kdata_base
[2]      = ktext_base
[3]      = curthread
[4..31]  = apic_ops[0..27] (always dumped)
[32]     = step (0x100=probing, 0x101=verdict, 4=done)
[33]     = entry index
[34]     = fn ptr
[35]     = probe addr (fn-1)
[36]     = raw result
[37]     = verdict (0=skip, 1=CC, 2=C3, 3=fault)
[38]     = source (0=apic_ops, 1=sysent)
[39]     = probe_offset (1=fn-1)
[63]     = end marker 0xdeadbeefcafe010b
```

**Binary**: 984 bytes, no .bss.

**Status**: Built, ready for deployment.

### Scanning Strategy

1. Start with a few entries to validate and identify the `nosys` function pointer
2. Once `nosys` is known, skip all duplicate entries pointing to it
3. Focus on entries with verdict=2 (C3 at fn-1) — these are candidates for fn-2 probing
4. Any fn-2=C9 with fn-1=C3 gives us `leave;ret` — a stack pivot gadget from a different compilation unit


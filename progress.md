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

### Phase 9a: v8a Canary — Byte Read Crash

Simplified v8 to a minimal canary (v8a): no IDT changes, no function calls, just reads apic_ops entries and reports bytes at fn-1. Magic written early for quick detection.

**v8a Result**: Kernel panic. Root cause: some apic_ops entries are NULL or point to addresses where fn-1 faults. Original sanity check `fn > 0xFFFF000000000000` passed for fn=0 (since 0-1 = 0xFFFFFFFFFFFFFFFF). Fixed with NULL check + ktext range validation, but still crashed — likely entry [25] at +0x4F69F0 is at a page boundary or the range check was too narrow.

### Phase 9b: v8b Canary — Function Pointer Dump Only

Stripped out all byte reads. Just dumps the 28 fn ptrs. Key fix: **magic written LAST** with `mfence` barrier, so kldload only reads back when payload is fully complete.

**v8b Result**: SUCCESS. Status 0x008B confirmed, all 28 entries populated, no crash.

### Full apic_ops Vtable Dump (FW 4.03)

```
ktext_base varies per boot (KASLR), offsets are stable:

idx  ktext offset  PS5 name (kldload)       FreeBSD header name
---  ------------  ----------------------   ----------------------
 [0]  +0x28DB88    create                   create
 [1]  +0x28D310    init                     init
 [2]  +0x294340    xapic_mode               xapic_mode
 [3]  +0x290808    is_x2apic                is_x2apic
 [4]  +0x293F18    setup                    setup
 [5]  +0x294100    dump                     dump
 [6]  +0x2943B8    disable                  disable
 [7]  +0x290330    set_id                   eoi (MISMATCH)
 [8]  +0x28E9D0    ipi_raw                  id (MISMATCH)
 [9]  +0x28DC60    ipi_vectored             intr_pending (MISMATCH)
[10]  +0x290240    ipi_wait                 set_logical_id (MISMATCH)
[11]  +0x290AA8    ipi_alloc                cpuid (MISMATCH)
[12]  +0x28D770    ipi_free                 alloc_vector (MISMATCH)
[13]  +0x28E708    set_lvt_mask             alloc_vectors (MISMATCH)
[14]  +0x28E700    set_lvt_mode             enable_vector (MISMATCH)
[15]  +0x28DC58    set_lvt_polarity         disable_vector (MISMATCH)
[16]  +0x2902B8    set_lvt_triggermode      free_vector (MISMATCH)
[17]  +0x2941D0    lvt_eoi_clear            enable_pmc (MISMATCH)
[18]  +0x294348    set_tpr                  disable_pmc (MISMATCH)
[19]  +0x294320    get_timer_freq           reenable_pmc (MISMATCH)
[20]  +0x28D130    timer_enable_intr        enable_cmc (MISMATCH)
[21]  +0x28DB80    timer_disable_intr       enable_mca_elvt (MISMATCH)
[22]  +0x2906D0    timer_set_divisor        ipi_raw (MISMATCH)
[23]  +0x29E830    timer_initial_count      ipi_vectored (MISMATCH)
[24]  +0x290800    timer_current_count      ipi_wait (MISMATCH)
[25]  +0x5569F0    self_ipi                 ipi_alloc (MISMATCH)
[26]  +0x28DFA8    ??? (unnamed)            ipi_free
[27]  +0x28E760    ??? (unnamed)            set_lvt_mask
```

**Struct Mismatch Analysis**: The PS5 kernel uses a Sony-modified `struct apic_ops`:
- Entries [0-6] match upstream FreeBSD (create through disable)
- From [7] onward, the PS5 struct diverges completely — Sony reorganized the vtable
- The kldload `apic_op_names[26]` (with timer/self_ipi) is the PS5-specific layout
- Upstream FreeBSD header has 31 fields (with vector/PMC/CMC/ELVT groups)
- PS5 has 28 populated entries, 2 more than the existing names array covers

**Notable Patterns**:
- Entry [25] at +0x5569F0 is a major outlier (~350KB away from the cluster) — likely a Sony-added function or different compilation unit
- Entries [13]+[14] at +0x28E708/+0x28E700 differ by only 8 bytes — trivial wrapper pair
- Entry [21] at +0x28DB80 is 8 bytes before [0] at +0x28DB88 — another adjacent pair
- All entries non-NULL — all 28 vtable slots are populated

**Safe Hook Candidates** (based on function semantics, CC status unknown):
- SAFE: [2] xapic_mode (tested), [3] is_x2apic (read-only), [19] get_timer_freq (read-only)
- DANGEROUS: [6] disable, [8/22] ipi_raw, [9/23] ipi_vectored (side effects)
- ALL need fn-1 byte check before use as doreti_iret bounce targets

**Cross-boot verification**: Second boot (ktext=0xffffffffc4ae0000) confirmed all 28 offsets identical. Entry [25] offset corrected from +0x4F69F0 to +0x5569F0 (arithmetic error in first analysis).

### Phase 9c: v8c — Safe Byte Probing with pcb_onfault

Built v8c canary using the proven pcb_onfault pattern from `pivot_scan_safe`. For each of the 28 apic_ops entries, arms pcb_onfault before reading fn-1, with fault recovery via saved_rsp restoration. Magic written last with mfence.

**v8c Result**: Kernel panic. Root cause: static global variables (`saved_rsp`, `onfault_ptr`, `fault_flag`) were in `.bss` section. `objcopy -O binary` doesn't include uninitialized .bss data in the flat binary, so RIP-relative accesses to those globals hit unmapped memory.

**v8c2 fix**: Eliminated ALL global variables. `onfault_addr` passed as a function parameter (register). Recovery label uses only the kernel-preserved stack frame (no need for saved_rsp — confirmed by pcb_onfault_test which also doesn't save RSP). Fault result returned directly in a register via inline asm output operand. Binary: 656 bytes, zero .bss symbols.

**v8c2 Result**: Kernel panic. No globals in binary (confirmed via objdump — zero .bss symbols), so the crash isn't from unmapped .bss. The disassembly looks correct. v8b (fn ptr reads only, from kdata) works. v8c/v8c2 (byte reads from ktext) crash.

**Hypothesis**: PS5 HV maps ktext as **execute-only via NPT** (nested page tables). Reading ktext bytes causes an NPT violation handled by the hypervisor (not a kernel #PF), so pcb_onfault never fires. Evidence:
- All successful reads are from kdata or kernel heap (never ktext)
- v7b EXECUTED xapic_mode-1 successfully (execute permission OK)
- v8a/v8c/v8c2 all crash when trying to READ ktext bytes
- pcb_onfault works for regular #PF (confirmed) but can't catch NPT violations

### Phase 9d: v8d — ktext Readability Diagnostic

Step-by-step diagnostic with progress markers and magic written EARLY (so kldload reads back even on crash):
1. Read fn ptrs from kdata (proven safe)
2. Read 1 byte from kdata with pcb_onfault (control test)
3. Read 1 byte from ktext with pcb_onfault (the dangerous test)
Progress marker at out[32] shows how far we got. If step marker = 0x04 and status = in-progress, confirms ktext read crashed (XOM).

**Status**: Superseded by v8e. ktext XOM confirmed (already documented in progress.md: "Cannot read ktext bytes through any path", "XOM enforced even through DMAP alias").

### Phase 9e: v8e — Execution-Based CC Scanner

Returned to the proven v7b execution-based approach: CALL fn-1 with sentinel in RAX, observe result. No ktext reads needed (XOM-safe).

For each of the 28 apic_ops entries:
1. Set IDT[3] = doreti_iret (IST=0) — catches INT3 via iretq, falls through to fn
2. Arm pcb_onfault for crash recovery on weird bytes
3. Load RAX = sentinel (0xBAD0BAD0BAD0BAD0)
4. CALL fn-1
5. Check RAX: unchanged = C3 (ret), changed = CC (INT3 → fn executed), 0xFAFA... = faulted

Skips dangerous entries: [6] disable, [8] ipi_raw, [9] ipi_vectored, [23] timer_initial_count.
Magic written early with step markers for crash diagnostics.

**Status**: Crashed instantly — pcb_onfault only catches #PF, not #UD/#GP from arbitrary fn-1 bytes. Bulk scanning abandoned.

### v8f: Single-Probe CC Scanner (Safe)

**Approach**: Probe ONE apic_ops entry per deployment, selected by fw_ver encoding.
- `fw_ver = 0xEE00 + entry_index` selects which entry to probe
- Only one CALL to fn-1 per deployment — limits blast radius to one reboot if non-CC/non-C3
- IDT[3] set to doreti_iret before probe, restored after
- Magic written LAST (no early readback race)

**Why single-probe works**:
- If fn-1 = CC (INT3): doreti_iret catches it → fn executes → clean return with RAX result
- If fn-1 = C3 (ret): immediate return, sentinel unchanged
- If fn-1 = other: kernel panic, reboot, try next candidate
- pcb_onfault armed but only helps with #PF — main safety is choosing likely-CC entries first

**Probe priority** (by alignment + safety, highest CC probability first):
1. `fw_ver=0xEE02` → [2] xapic_mode — **CONTROL TEST** (known C3, validates mechanism)
2. `fw_ver=0xEE18` → [24] timer_current_count (+0x290800, 256-byte aligned, read-only)
3. `fw_ver=0xEE0E` → [14] set_lvt_mode (+0x28E700, 256-byte aligned)
4. `fw_ver=0xEE13` → [19] get_timer_freq (+0x294320, 32-byte aligned, read-only)
5. `fw_ver=0xEE0A` → [10] ipi_wait (+0x290240, 64-byte aligned)

**Evidence CC exists**: PS5 kernel uses CC padding (copyin-1 = CC confirmed). 15 of 28 entries are 16-byte+ aligned. Entries [14] and [24] are 256-byte aligned → near-certain CC at fn-1.

**Output layout** (64 uint64_t slots):
- out[0] = MAGIC (lo32) + status (hi32): 0x018F = complete
- out[1] = kdata_base, out[2] = ktext_base, out[3] = td_pcb
- out[4..31] = all 28 fn ptrs (from kdata, safe read)
- out[33] = target entry index, out[34] = target fn ptr
- out[35] = call result (RAX after fn-1 call)
- out[36] = verdict: 1=CC, 2=C3, 3=faulted

**Status**: Deployed. Results below.

### v8f Probe Results

| Entry | Name | Offset | fw_ver | Result |
|-------|------|--------|--------|--------|
| [2] | xapic_mode | +0x294340 | 0xEE02 | **C3** (control test, sentinel unchanged) |
| [24] | timer_current_count | +0x290800 | 0xEE18 | **PANIC** (fn-1 not CC or C3) |
| [14] | set_lvt_mode | +0x28E700 | 0xEE0E | **C3** (sentinel unchanged) |
| [19] | get_timer_freq | +0x294320 | 0xEE13 | **CC** — RAX=0x13b0 (timer freq) |

**CONFIRMED: get_timer_freq - 1 (ktext+0x29431F) = 0xCC (INT3)**

The doreti_iret bounce caught the INT3, get_timer_freq executed and returned the LAPIC timer frequency (0x13b0 = 5040). This is the CC entry we need for the persistence chain.

---

## Phase 10: CC Bounce Persistence Test (resume_chain v9a)

### Context

v7 mode 0x2 failed because xapic_mode-1 = C3 (not CC). Now that v8f confirmed get_timer_freq-1 = CC, we can retry the doreti_iret bounce with the correct CC byte.

### v9a Design

Simple bounce test: `apic_ops[2] = get_timer_freq - 1` (CC byte) + `IDT[3] = doreti_iret, IST=0`.

During LAPIC resume:
```
call *apic_ops[2]  (= ktext+0x29431F = CC byte)
  → INT3 fires
  → IDT[3] = doreti_iret (iretq)
  → CPU pushes {RIP=get_timer_freq, CS, RFLAGS, RSP, SS}
  → iretq pops everything back
  → get_timer_freq executes, returns 0x13b0
  → clean return to LAPIC caller
```

Properties:
- Self-sustaining across all CPUs (each uses own kernel stack, no IST)
- No ROP chain, no IST, no multi-CPU race
- get_timer_freq is read-only and safe

### Modes

- `fw_ver=0x0901` (ARM): Set IDT[3]=doreti_iret IST=0, apic_ops[2]=CC byte, save originals to kdata persistence area
- `fw_ver=0x0903` (READBACK): After resume, verify persistence, restore originals

### Key Addresses

- CC byte: `ktext+0x29431F` (get_timer_freq - 1)
- doreti_iret: `kdata + (-0x9cf84c)`
- Persistence area: `kdata+0x200` (marker, mode, saved originals)

### v9a Results — FAILED (enters rest, doesn't resume)

**ARM output** (kdata_base=0xffffffff93d30000):
```
out[3] = 0xffffffff933607b4  → doreti_iret ✓
out[4] = 0xffffffff933c4340  → original xapic_mode
out[5] = 0xffffffff933c431f  → CC target (get_timer_freq - 1) ✓
out[6] = 0xffffffff933c4178  → original IDT[3] handler
out[7] = 0xffffffff933607b4  → new IDT[3] handler = doreti_iret ✓
```

ARM succeeded. System entered rest mode. **System never booted back from rest mode.**

**Analysis**: Same failure as v7 mode 0x2. The INT3 trap during LAPIC resume is the root cause.

**Key evidence**:
- apic_ops[2] = get_timer_freq (directly, no CC) → **survives rest mode** (user confirmed)
- apic_ops[2] = get_timer_freq - 1 (CC → INT3) → **fails to resume**
- apic_ops[2] = xapic_mode - 1 (C3 → wrong return) → **fails to resume** (v7 mode 0x2)
- IDT[3] = doreti_iret + apic_ops[2] = original → **survives rest mode** (v7 mode 0x1)

**Conclusion**: INT3 during LAPIC resume is fundamentally broken. Both modifications (IDT[3] and apic_ops[2]) work individually, but the CC bounce (which requires both) fails during resume. Possible causes:
1. IDT not yet loaded when LAPIC resume calls apic_ops[2] during early ACPI wakeup
2. CPU in special state during early resume where trap delivery fails
3. Some subtle interaction between INT3 and LAPIC initialization

**Impact**: ALL INT3-based approaches are blocked during resume:
- Simple doreti_iret bounce (v9a) — failed
- IST + pop_all_iret chain (v3) — failed
- Any CC byte technique — will fail

**Need alternative approach that doesn't rely on INT3 for code execution during resume.**

---

## Phase 11: Stack Pivot Gadget Discovery (resume_chain v10a)

### Why Stack Pivot?

INT3-based approaches are dead for resume. But we CAN point apic_ops[2] at any ktext address. If we find a `leave;ret` (C9 C3) gadget in ktext, calling it does:
```
leave: RSP = RBP, pop RBP
ret:   jump to [old_RBP + 8]
```
If RBP → kdata during resume, we get full ROP control without any traps.

### Discovery Approach

We already know fn-1 bytes for several entries:
- [2] xapic_mode fn-1 = C3, [14] set_lvt_mode fn-1 = C3
- [19] get_timer_freq fn-1 = CC

If fn-1 = C3, then fn-2 MIGHT be C9 (leave) → `leave;ret` at fn-2.

v10a probes fn-2 from kproc context using the v8f sentinel technique:
- `fw_ver = 0xDD00 + entry_index` → probe fn-2
- `fw_ver = 0xEE00 + entry_index` → probe fn-1 (v8f compatible)
- Magic written EARLY for crash diagnostics

### Expected fn-2 outcomes:
- **C9 (leave)**: leave;ret pivots stack → crash (probe doesn't return) → step marker shows crash during probe
- **48 (REX.W)**: REX prefix + C3 = still ret → returns with sentinel unchanged
- **5D (pop rbp)**: pop rbp; ret → wild return → crash
- **CC (INT3)**: doreti_iret catches → fn-1=C3=ret → returns with sentinel unchanged
- **90 (NOP)**: falls through to C3=ret → sentinel unchanged
- **Other**: #UD/#GP → crash

### Deployment

First probe entry [2] (xapic_mode, fn-1=C3):
```
printf '\x02\xDD\x00\x00' | nc 192.168.0.88 9022
```
Then send binary.

**Status**: Built (960 bytes, no .bss), awaiting deployment.


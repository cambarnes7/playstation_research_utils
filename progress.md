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

### Next Steps

1. **Deploy savectx_finder mode 0x403** → scan for savectx/resumectx ktext addresses
2. **Deploy savectx_finder mode 0x2** → arm apic_ops[2] with justreturn
3. **Suspend/resume PS5**
4. **Deploy savectx_finder mode 0x3** → verify justreturn executed cleanly during resume
5. **If justreturn works**: escalate to savectx/resumectx for register capture and full CPU state control

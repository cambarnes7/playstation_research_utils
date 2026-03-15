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
| **All 0xC001xxxx MSRs blocked** | VM killed (not #GP) | msrpm_probe: PATCH_LEVEL (0xC0010021) terminated VM |
| **EntrySign not viable** | PATCH_LOADER inaccessible | HV MSRPM blocks entire AMD MSR range from guest |
| **QA flags patched at FW 3.00** | Not accessible from guest | progress_session9.md + Byepervisor research |
| **Flatz private HV exploit ≤4.51** | Different from Byepervisor, unpublished | psdevwiki + wololo.net |
| **INT3 is VMCB-intercepted** | Causes VMEXIT (not IDT issue) | Explains ALL resume INT3 failures; kstuff proves #DB is NOT intercepted |
| **#DB via DR not intercepted** | Goes directly to guest IDT | kstuff uses DR breakpoints successfully; no VMEXIT for #DB |
| **kstuff persists through rest mode** | kdata/IDT hooks survive, DRs re-armed on demand | kstuff rebuilds DR state after resume, not hardware persistence |
| **IDT is global, DRs per-CPU** | Can't replace IDT[1] while kstuff active | dr_db_resume_test v1/v2: instant panic from cross-CPU #DB race |
| **DR0-DR7 do NOT survive rest mode** | All reset (S3 power-off clears CPU state) | dr_db_resume_test v3: DR2=0, DR7=0x400 (default) after resume |
| **Only RAM-mapped state persists** | kdata, IDT, TSS, apic_ops survive; no CPU regs | DR test + prior idt_safe_test + sentinel tests confirm |

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

**Status**: Built (960 bytes, no .bss). Deployed and tested.

### v10a fn-2 Probe Results

| Entry | Name | Offset | fn-1 | fn-2 probe | Result |
|-------|------|--------|------|------------|--------|
| [2] | xapic_mode | +0x294340 | C3 | sentinel unchanged | **Benign** (48/90/66/CC prefix, NOT C9) |
| [14] | set_lvt_mode | +0x28E700 | C3 | sentinel unchanged | **Benign** (48/90/66/CC prefix, NOT C9) |

**Raw output (entry [2], fw_ver=0xDD02):**
```
kdata_base=0xffffffff96960000, ktext_base=0xffffffff95d60000
step=0x04 (complete), target_idx=2
fn=0xffffffff95ff4340, probe_addr=0xffffffff95ff433e
call_result=0xbad0bad0bad0bad0 (SENTINEL), verdict=2 (ret/benign)
probe_type=2 (fn-2), end_marker=0xdeadbeefcafe010a
```

**Raw output (entry [14], fw_ver=0xDD0E):**
```
kdata_base=0xffffffff96960000, ktext_base=0xffffffff95d60000
step=0x04 (complete), target_idx=14
fn=0xffffffff95fee700, probe_addr=0xffffffff95fee6fe
call_result=0xbad0bad0bad0bad0 (SENTINEL), verdict=2 (ret/benign)
probe_type=2 (fn-2), end_marker=0xdeadbeefcafe010a
```

**Conclusion**: Neither entry [2] nor [14] has leave;ret (C9 C3) at fn-2. Both fn-2 bytes are benign prefixes that fall through to the C3 at fn-1 and return cleanly. Need to scan more entries for fn-1=C3 candidates.

### fn-1 Scan Results (0xEE mode)

| Entry | Name | Offset | fn-1 | fn-2 | Notes |
|-------|------|--------|------|------|-------|
| [0] | create | +0x28DB88 | **PANIC** | — | Bad byte, crashed kproc |
| [1] | init | +0x28D310 | **PANIC** | — | Bad byte, crashed kproc |
| [2] | xapic_mode | +0x294340 | **C3** | benign (48) | REX.W ret epilogue |
| [3] | is_x2apic | +0x290808 | other | — | RAX=0xf64c4566fcc97ae4 |
| [5] | dump | +0x294100 | other | — | RAX=0xff |
| [14] | set_lvt_mode | +0x28E700 | **C3** | benign (48) | REX.W ret epilogue |
| [17] | lvt_eoi_clear | +0x2941D0 | **C3** | benign (48) | REX.W ret epilogue |
| [18] | set_tpr | +0x294348 | **C3** | benign (48) | REX.W ret epilogue |
| [19] | get_timer_freq | +0x294320 | **CC** | — | INT3 padding |
| [24] | timer_current_count | +0x290800 | **PANIC** | — | Bad byte |

**Key finding**: All fn-1=C3 entries have fn-2=`48` (REX.W prefix). Sony Clang consistently emits `48 C3` (REX.W ret) epilogues, not `C9 C3` (leave;ret). The `48` is likely the last byte of a preceding multi-byte instruction that the CPU reinterprets as a REX prefix when we jump to fn-2.

### Phase 11a: fn-3 Probe — leave;REX.W-ret Discovery (v10a2)

**Insight**: Since fn-2=`48` and fn-1=`C3` for all C3 entries, the byte at fn-3 might be `C9` (leave). Calling fn-3 would execute:
```
C9    = leave (RSP=RBP, pop RBP)
48 C3 = REX.W ret (= ret)
```
This is `leave;ret` with a useless REX prefix — a working stack pivot gadget!

**Code change**: Added `0xCC` mode prefix for fn-3 probing (probe_offset=3).

**Deployment (v10a2, 976 bytes):**
```
printf '\x02\xCC\x00\x00' | nc 192.168.0.88 9022   # [2]  xapic_mode fn-3
printf '\x0E\xCC\x00\x00' | nc 192.168.0.88 9022   # [14] set_lvt_mode fn-3
printf '\x11\xCC\x00\x00' | nc 192.168.0.88 9022   # [17] lvt_eoi_clear fn-3
printf '\x12\xCC\x00\x00' | nc 192.168.0.88 9022   # [18] set_tpr fn-3
```

**Expected outcomes:**
- Sentinel unchanged → fn-3 is benign (90/66/F3 prefix)
- Crash (step stuck at 0x100+idx) → fn-3 is NOT benign → could be C9 (leave;ret!) or other
- RAX changed → fn-3 executed something that modified RAX

### fn-3 Probe Results

| Entry | Name | Offset | fn-1 | fn-2 | fn-3 | Notes |
|-------|------|--------|------|------|------|-------|
| [2] | xapic_mode | +0x294340 | C3 | 48 (benign) | **benign** | Sentinel unchanged |
| [14] | set_lvt_mode | +0x28E700 | C3 | 48 (benign) | **benign** | Sentinel unchanged |
| [17] | lvt_eoi_clear | +0x2941D0 | C3 | 48 (benign) | **benign** | Sentinel unchanged |
| [18] | set_tpr | +0x294348 | C3 | 48 (benign) | **benign** | Sentinel unchanged |

**Conclusion**: All 4 fn-1=C3 entries have identical `?? 48 C3` epilogues. fn-3 is another benign prefix byte in every case. Sony Clang is completely consistent — no `leave;ret` (C9 C3) gadget exists anywhere near apic_ops function boundaries.

**apic_ops is exhausted for gadget discovery.** Moving to sysent scanning.

---

## Phase 12: Sysent Scanner (resume_chain v10b)

### Why Sysent?

The 28 apic_ops entries come from a single compilation unit (`x86/apic/`) and share compiler flags — all use `48 C3` epilogues. The sysent table has 678 entries (~150 unique functions) spanning the entire kernel: hundreds of source files, different optimization levels, potentially hand-written asm. `leave;ret` (C9 C3) is much more likely among syscall handlers.

### Sysent Table Layout

From proven apic_dump.c results:
```
Base:        kdata + 0x1709c0
Entry size:  0x30 (48 bytes) — struct sysent
Fn ptr:      offset +0x08 within entry (sy_call_t*)
Entries:     678 total (~150 unique after dedup)
```

### fw_ver Encoding (v10b, backward-compatible)

```
Existing (apic_ops):
  0xEE00 + idx  → apic_ops[idx] fn-1 probe
  0xDD00 + idx  → apic_ops[idx] fn-2 probe
  0xCC00 + idx  → apic_ops[idx] fn-3 probe

New (sysent, idx = 0-255 per page):
  0xAA00 + idx  → sysent[idx] fn-1 probe        (entries 0-255)
  0xAB00 + idx  → sysent[256+idx] fn-1 probe     (entries 256-511)
  0xAC00 + idx  → sysent[512+idx] fn-1 probe     (entries 512-677)
  0xBA00 + idx  → sysent[idx] fn-2 probe
  0xBB00 + idx  → sysent[256+idx] fn-2 probe
  0xBC00 + idx  → sysent[512+idx] fn-2 probe
```

### Output Layout

Same as v10a with one new field:
```
out[0]     = MAGIC + status
out[1]     = kdata_base
out[2]     = ktext_base
out[3]     = td_pcb
out[4..31] = apic_ops fn ptrs (always dumped for reference)
out[32]    = step progress
out[33]    = real sysent index (page*256 + idx)
out[34]    = target fn ptr
out[35]    = probe address (fn - probe_offset)
out[36]    = call result (RAX after call)
out[37]    = verdict (1=executed, 2=sentinel/benign, 3=faulted)
out[38]    = probe type (1=fn-1, 2=fn-2, 3=fn-3)
out[39]    = source (0=apic_ops, 1=sysent)
out[63]    = end marker
```

### Strategy

1. Scan all sysent entries fn-1 (0xAA/AB/AC modes) — skip duplicates after first probe
2. For every fn-1=C3 entry, immediately probe fn-2 (0xBA/BB/BC modes)
3. If fn-2=C9 or crash → potential leave;ret gadget found

**Status**: v10b payload deployed. Initial scan in progress.

---

## Sysent fn-1 Probe Results (v10b)

### Boot 1 Results — Real Syscall Handlers (0x88b5xxxx region)

All real syscall handler fn ptrs on this boot are clustered in the `0xffffffff88b5xxxx` range. Every fn-1 read in this region **faults** (#PF caught by pcb_onfault, error code 3).

| Sysent Index | fn ptr | fn-1 byte | Result |
|-------------|--------|-----------|--------|
| 3 (read) | 0xffffffff88b575d0 | FAULT | error=3 |
| 4 (write) | 0xffffffff88b583f0 | FAULT | error=3 |
| 5 (open) | 0xffffffff88b578a8 | FAULT | error=3 |
| 20 (getpid) | 0xffffffff88b58178 | FAULT | error=3 |
| 73 (munmap) | 0xffffffff88b57d20 | FAULT | error=3 |
| 97 (socket) | 0xffffffff88b57648 | FAULT | error=3 |

### Boot 1 Results — Stub Functions (0x8827xxxx region)

Multiple entries share the same fn ptr — these are `nosys`/`lkmnosys` stubs. The fn-1 reads in this region **succeed**.

| Sysent Index | fn ptr | fn-1 byte | Result |
|-------------|--------|-----------|--------|
| 197 | 0xffffffff882784d8 | 0x00 | SUCCESS |
| 244 | 0xffffffff882784d8 | 0x00 | SUCCESS (same nosys) |
| 279 | 0xffffffff882784d8 | 0x00 | SUCCESS (same nosys) |
| 350 | 0xffffffff882784d8 | 0x00 | SUCCESS (same nosys) |
| 456 | 0xffffffff88277cf0 | 0x00 | SUCCESS (lkmnosys?) |
| 560 | 0xffffffff88278638 | FAULT | error=3 |

- **nosys** address: `0xffffffff882784d8` (shared by 197, 244, 279, 350 — and likely many more unimplemented entries)
- **lkmnosys** candidate: `0xffffffff88277cf0` (entry 456)
- Entry 560: Different fn ptr `0x88278638` but still faults — possibly on a different page with stricter protections

### Boot 1 — Panic Entry

| Sysent Index | Result |
|-------------|--------|
| 122 (0x7A) | **Kernel panic** — likely triggers #UD/#GP not caught by pcb_onfault |

### Boot 2 Results — Mixed Region (0x8827xxxx, different KASLR slide)

Different boot, all fn ptrs landed in `0x8827xxxx` range. Mixed read results within the same address range:

| Sysent Index | fn ptr | fn-1 byte | Result |
|-------------|--------|-----------|--------|
| 9 (link) | 0xffffffff882777b8 | 0x00 | SUCCESS |
| 27 (recvmsg) | 0xffffffff88277ea0 | FAULT | error=3 |
| 54 (ioctl) | 0xffffffff882771f0 | FAULT | error=3 |
| 78 (mincore) | 0xffffffff88278650 | 0x00 | SUCCESS |
| 104 (setitimer) | 0xffffffff88277868 | FAULT | error=3 |
| 138 (utrace) | — | — | Not tested (panic from entry 104 delayed effects) |

**Notable**: Entries 9 and 78 succeed (byte=0x00) while 27, 54, 104 fault, despite ALL being in the `0x8827xxxx` range. Entries 9 (`sys_link`) and 78 (`sys_mincore`) may be nosys stubs on PS5 (removed/unimplemented syscalls). The byte=0x00 is likely padding before the stub function, same pattern as the Boot 1 nosys results.

### Key Finding: Execute-Only ktext Pages

The PS5 hypervisor enforces **execute-only** page protections on most kernel text pages. Read-based probing (pcb_onfault) results:

| Category | Readable? | Byte Value | Notes |
|----------|-----------|------------|-------|
| nosys/lkmnosys stubs | **YES** | 0x00 | Padding before stub functions |
| Real syscall handlers | **NO** | FAULT | Execute-only, error code 3 |
| Some real handlers | **NO** | PANIC | #UD/#GP not caught by pcb_onfault |

XOM is NOT simply range-based — functions on the same 4K page can have different read behavior, suggesting the hypervisor's NPT permissions may be more granular or that readable entries are nosys stubs residing on special pages.

### Implications for Strategy

The pcb_onfault READ-based scan is hitting XOM walls for all real syscall handlers. Every successful read (byte=0x00) is likely just another nosys/unimplemented stub. The approach is useful for:
1. **Deduplication**: Identifying which entries share the nosys fn ptr (skip duplicates)
2. **Classification**: Separating nosys stubs from real handlers by fn ptr uniqueness

But for finding `leave;ret` (C9 C3) gadgets, we need to **switch to execution-based probing** (v8f sentinel technique) for unique sysent fn ptrs. This bypasses XOM entirely since we CALL fn-1 rather than READ fn-1. Trade-off: one probe per boot for dangerous bytes (non-C3/non-CC), but it's the only way to probe execute-only pages.

### Phase 12a: Sysent fn ptr Batch Dump (v10c)

READ-based byte scanning hits XOM for all real syscall handlers. Before switching to execution-based probing, need to **deduplicate** the full 678-entry sysent table to identify the ~150 unique fn ptrs.

**v10c adds dump mode** (`fw_ver = 0x9900 + batch`): pure kdata reads, no byte reads, no execution, completely safe. Dumps up to 284 fn ptrs per batch in 3 deployments.

**fw_ver encoding:**
```
0x9900 → batch 0: sysent[0..283]   (284 entries)
0x9901 → batch 1: sysent[284..567] (284 entries)
0x9902 → batch 2: sysent[568..677] (110 entries)
```

**Output layout** (288 uint64_t slots, 2304 bytes):
```
out[0]     = MAGIC (lo32) + status (hi32): 0x110C = complete
out[1]     = kdata_base
out[2]     = ktext_base
out[3]     = batch | (start_idx << 16) | (count << 32)
out[4..4+count-1] = fn ptrs for sysent[start_idx..start_idx+count-1]
```

**Deployment** (3 sends, all safe — no reboots needed):
```
printf '\x00\x99\x00\x00' | nc 192.168.0.88 9022   # set fw_ver=0x9900
cat resume_chain.bin | nc 192.168.0.88 9022          # batch 0

printf '\x01\x99\x00\x00' | nc 192.168.0.88 9022   # set fw_ver=0x9901
cat resume_chain.bin | nc 192.168.0.88 9022          # batch 1

printf '\x02\x99\x00\x00' | nc 192.168.0.88 9022   # set fw_ver=0x9902
cat resume_chain.bin | nc 192.168.0.88 9022          # batch 2
```

**Binary**: 1432 bytes, no .bss. All existing v10b probe modes preserved (0xAA-0xBC, 0xCC-0xEE).

**Status**: All 3 batches deployed and captured successfully. Full analysis below.

### Phase 12b: Sysent Dedup Results

All 3 v10c batches completed (status=0x110C). Full 678-entry sysent table captured.

**Summary:**
```
678 sysent entries total
  234 nosys (unimplemented)     = ktext+0x2984d8
  444 with handlers
  406 distinct handler functions
    4 handlers shared by multiple syscalls
  All handlers in 7,120-byte span: ktext+0x297180 to ktext+0x298d50
```

**Key findings:**

1. **No outliers** — every single syscall handler lives in one 7KB compilation unit (`ktext+0x2971xx` to `ktext+0x298dxx`). No entries from different source files, no far-off outliers. This means all syscall wrappers were compiled together with identical calling conventions.

2. **nosys** = `ktext+0x2984d8` (234 entries, 34.5% of table). Consistent across all 3 batches.

3. **Two additional "stub" handlers** shared by many syscalls:
   - `ktext+0x2985a8`: 28 syscalls (indices 154-155, 169-171, 220-231, 339, 377, 457-462, 505, 510-512) — likely `lkmnosys` or similar unloaded-module stub
   - `ktext+0x298918`: 10 syscalls (indices 210-219) — likely a block of related unimplemented calls

4. **Only 2 other shared handlers:**
   - `ktext+0x297598`: sysent[254, 275]
   - `ktext+0x297e18`: sysent[65, 277]

5. **Fn ptr spacing**: predominantly 8-byte aligned. Most common spacings: 8 bytes (184×), 16 bytes (107×), 24 bytes (54×). Densely packed function stubs.

6. **No overlap with apic_ops** — sysent handlers (`0x2971xx`) are in a completely different region from apic_ops (`0x28D1xx-0x29E8xx`). Despite nearby ktext ranges, no actual fn ptr collisions.

**Effective unique targets for execution probing:**
- 406 distinct fn ptrs total
- Minus nosys (1) = 405
- Minus `ktext+0x2985a8` stub (1) and `ktext+0x298918` stub (1) = 403
- These 403 are the real candidates for `leave;ret` (C9 C3) gadget hunting

### Phase 12c: Batch Execution Probe (v10d)

Probes fn-1 of all 406 unique sysent fn ptrs using the sentinel technique, batched 50 per deployment.

**fw_ver encoding:** `0x9800 + batch` (batch 0..8)
- Batches 0-7: 50 probes each (offsets 0-399)
- Batch 8: 6 probes (offsets 400-405)
- 9 deployments total

**Hardcoded offset table**: 406 unique ktext offsets (sorted, 32-bit, from dedup_sysent.py). Eliminates runtime dedup — each deployment knows exactly which fn ptrs to probe.

**Output layout** (288 uint64_t slots):
```
out[0]     = MAGIC + status (0x010D=in-progress, 0x110D=complete)
out[1]     = kdata_base
out[2]     = ktext_base
out[3]     = batch | (start_offset_idx << 16) | (count << 32)
out[4]     = td_pcb
out[5]     = probes_completed (crash-safe counter)
out[6+i*3] = ktext offset of fn probed
out[6+i*3+1] = RAX result
out[6+i*3+2] = verdict: 1=CC(executed), 2=C3(sentinel), 3=faulted
```

**Probe logic per entry:**
1. Reconstruct fn = ktext_base + unique_offsets[idx]
2. Call `probe_call(fn - 1, onfault_addr)` with IDT[3] armed for INT3
3. Classify: sentinel unchanged → C3, FAFA → fault, else → executed (CC)
4. Write result triple, increment probes_completed

**Crash safety:** Status starts at `0x010D` (in-progress). If a probe crashes the kernel, `probes_completed` tells us which entry caused it. Partial results are valid up to that point.

**Binary**: 3544 bytes (1624 bytes offset table + ~1900 bytes code). No .bss.

**Deployment:**
```bash
# 9 batches, all safe (probing fn-1 which is almost certainly C3 everywhere)
for batch in 0 1 2 3 4 5 6 7 8; do
  printf "\\x$(printf '%02x' $batch)\\x98\\x00\\x00" | nc 192.168.0.88 9022
  cat resume_chain.bin | nc 192.168.0.88 9022
done
```

**Status**: Built, awaiting deployment.

### Next Steps After Batch Probe

1. If all 406 return verdict=2 (C3): confirms `48 C3` epilogue everywhere, need alternative gadget strategy
2. If any return verdict=1 (CC): those have INT3 padding at fn-1 — probe fn-2 for C9 (leave;ret)
3. If any return verdict=3 (faulted): unusual, may indicate XOM page boundary or corrupted entry

---

## Phase 13: FreeBSD Source-Guided Analysis + savectx State Capture

**Status: BUILT, AWAITING DEPLOYMENT**

### Key Insight: Stop Blind Probing, Read the Source

We have ~50 known ktext function offsets from the DEF() macro list. Each maps to a real FreeBSD kernel function whose behavior is **fully documented** in open-source FreeBSD. Instead of probing unknown bytes or guessing register state, we can read the FreeBSD source code and pick the right tool.

### FreeBSD Source Analysis Results

#### savectx (cpu_switch.S) — THE breakthrough candidate

From FreeBSD `sys/amd64/amd64/cpu_switch.S`:

```asm
savectx:
  movq (%rsp), %rax       ; save return address
  movq %rax, PCB_RIP(%rdi)
  movq %rbx, PCB_RBX(%rdi)
  movq %rsp, PCB_RSP(%rdi)
  movq %rbp, PCB_RBP(%rdi)
  movq %r12-r15, PCB_R12-R15(%rdi)
  movq %cr0-cr4, PCB_CR0-CR4(%rdi)
  movq %dr0-dr7, PCB_DR0-DR7(%rdi)
  rdmsr(FSBASE, GSBASE, KGSBASE, EFER, STAR, LSTAR, CSTAR, SF_MASK)
  sgdt PCB_GDT(%rdi)
  sidt PCB_IDT(%rdi)
  sldt PCB_LDT(%rdi)
  str  PCB_TR(%rdi)
  movl $1, %eax           ; ← returns 1
  ret
```

**Why savectx is perfect as apic_ops[2]:**
1. Takes RDI as PCB pointer — writes ALL CPU state (GPRs, CRs, DRs, MSRs including **LSTAR**, GDT, IDT, TR)
2. **Returns 1** — matches what Sony's xapic_mode returns (non-zero = "yes, XAPIC mode")
3. If RDI → writable memory during resume: **non-crashing full state dump** AND system resumes normally
4. This breaks the circular problem (need register state to pick gadget / need gadget to capture register state) in one shot

#### resumectx (cpu_switch.S) — Total CPU control if RDI controllable

```asm
resumectx:
  movq KPML4phys, %rax    ; load known-good page table
  movq %rax, %cr3
  ; restore ALL MSRs (FSBASE, GSBASE, EFER, STAR, LSTAR, CSTAR, SF_MASK)
  ; restore CR0, CR2, CR4, CR3
  ; restore IDT, LDT, TR
  ; restore DR0-DR7
  ; restore R15-R12, RBP, RSP, RBX
  ; movq PCB_RIP(%rdi), %rax; movq %rax, (%rsp); ret → jumps to saved RIP
```

If RDI → fake PCB in kdata we control: **total CPU state control** including LSTAR, CR3, IDT, all registers, RIP.

#### Offset-to-Function Reference (from FreeBSD source)

| Offset | Function | Args | Return | As apic_ops[2]? |
|--------|----------|------|--------|-----------------|
| `wrmsr_ret` (-0x9d20cc) | wrmsr; ret | ECX=MSR#, EDX:EAX=val | - | Dangerous: unknown ECX |
| `nop_ret` (wrmsr_ret+2) | ret | none | RAX unchanged | Test: does caller check retval? |
| `rdmsr_start` (-0x9d0cfa) | rdmsr sequence | ECX=MSR#, writes [RDI] | - | Inside savectx, needs valid RDI |
| `dr2gpr_start` (-0x9d6d93) | DR save | Reads DR0-7 to [RDI] | - | Needs valid RDI |
| `gpr2dr_1_start` (-0x9d6c7a) | DR restore | Loads DR0-7 from [RDI] | - | **Sets debug breakpoints** from [RDI] |
| `mov_cr3_rax` (-0x396f9e) | mov cr3, rax | RAX = new PT root | - | Crash unless RAX valid |
| `mov_rdi_cr3` (-0x39700e) | mov rdi, cr3 | Reads CR3 → RDI | - | Safe read, needs chain |
| `copyin` (-0x9908e0) | copyin(u,k,len) | RDI=src RSI=dst RDX=len | 0/EFAULT | Needs controlled regs |
| `pop_all_iret` (-0x9cf8ab) | Restore trapframe + iretq | Pops 15 regs from stack | - | Full control from stack |
| `savectx` (near cpu_switch) | **Save full CPU state** | **RDI=pcb** | **1** | **IDEAL** |
| `resumectx` (near cpu_switch) | **Restore full CPU state** | **RDI=pcb** | via RIP | **Total control** |

**Key insight**: Most powerful gadgets need **RDI pointing to controlled memory**. savectx lets us discover what RDI is, and if it's controllable, resumectx gives us everything.

#### LAPIC Resume Call Path (from FreeBSD source)

```
lapic_resume(pic, suspend_cancelled)
  → lapic_setup(0)
    → native_lapic_setup(boot=0)
      → lapic_id()           ; reads LAPIC_ID register
      → lapic_set_tpr(0)     ; sets Task Priority Register
      → lapic_enable()       ; enables LAPIC
      → lapic_write32(...)   ; programs LVT entries
      → timer setup
```

`native_lapic_setup()` does NOT call xapic_mode in upstream FreeBSD. **Sony added the xapic_mode call** — likely at the beginning of their modified resume path, before LAPIC register access (to ensure correct access mode: MMIO vs MSR).

#### PCB Layout (FreeBSD `machine/pcb.h` + FreeBSD 11 additions)

```
Offset  Field           What savectx writes
0x00    pcb_r15         R15
0x08    pcb_r14         R14
0x10    pcb_r13         R13
0x18    pcb_r12         R12
0x20    pcb_rbp         RBP            ← KEY: if kdata range, leave;ret works
0x28    pcb_rsp         RSP            ← Stack pointer at call site
0x30    pcb_rbx         RBX
0x38    pcb_rip         Return address ← WHO called xapic_mode
0x40    pcb_fsbase      MSR FS.base
0x48    pcb_gsbase      MSR GS.base
0x50    pcb_kgsbase     MSR KernelGS.base
0x58    pcb_cr0         CR0            ← WP bit = HV active?
0x60    pcb_cr2         CR2
0x68    pcb_cr3         CR3            ← Page table root
0x70    pcb_cr4         CR4
0x78    pcb_dr0-dr7     DR0-DR7 (6 regs)
0xA8    pcb_gdt         GDT descriptor (10 bytes)
0xB2    pcb_idt         IDT descriptor (10 bytes)
0xBC    pcb_ldt         LDT descriptor (10 bytes)
0xC6    pcb_tr          TR selector
~0xD0+  pcb_efer       MSR EFER       (FreeBSD 11 addition)
~0xD8+  pcb_star       MSR STAR
~0xE0+  pcb_lstar      MSR LSTAR      ← THE target
~0xE8+  pcb_cstar      MSR CSTAR
~0xF0+  pcb_sfmask     MSR SF_MASK
0x108   pcb_onfault     Fault recovery (confirmed PS5 offset)
```

PS5's PCB is larger than FreeBSD 9.0 headers (pcb_onfault at 0x108 vs ~0xD0). Mode 0x4 (VERIFY) maps the exact layout.

### state_capture Payload (`examples/state_capture/`)

**Binary**: 3416 bytes. Four modes:

#### Mode 0x4 — VERIFY (local savectx test)
1. Scans kdata for pointers near cpu_switch (same as savectx_finder SCAN)
2. For each candidate: calls it with RDI → kdata+0x400 buffer
3. Verifies: return value == 1 AND saved CR3 matches actual CR3
4. If match: confirmed savectx. Dumps 256 bytes of PCB, finds LSTAR offset
5. Reports exact PCB layout for this PS5 firmware version

**Deploy first** — runs during normal operation (no NPT NX issue), confirms savectx works.

#### Mode 0x403 — LOCATE (find savectx address)
Same scan + verification as Mode 0x4, but focused on reporting the savectx ktext address and all cpu_switch-range hits for analysis.

#### Mode 0x2 — ARM (point apic_ops[2] at savectx)
1. Finds savectx via scan + verification
2. Saves LSTAR/CR3 fingerprints to kdata+0x200 (for READBACK matching)
3. Saves original apic_ops[2] to kdata+0x210
4. Overwrites apic_ops[2] with savectx address
5. Writes sentinel to kdata+0x100
6. **Leave armed for rest mode**

#### Mode 0x3 — READBACK (scan for PCB dump after resume)
1. Checks sentinel survived rest mode
2. Reads fingerprints from kdata+0x200
3. Calls savectx locally to determine LSTAR's PCB offset
4. **Scans all kdata (up to 112MB)** for a region where:
   - [addr + 0x68] == saved CR3 (PCB_CR3 offset)
   - [addr + lstar_offset] == saved LSTAR
   - [addr + 0x58] has PG+PE bits set (valid CR0)
5. If found: dumps everything:
   - pcb_rip → reveals WHO calls xapic_mode during resume
   - pcb_rbp → tells us if leave;ret stack pivot is viable
   - pcb_cr0 → WP bit reveals if HV is active at this point
   - pcb_lstar → confirms LSTAR value during resume
   - All debug registers, GDT, IDT, TR
6. Restores apic_ops[2] to original xapic_mode

### Deployment Plan

```bash
# Step 1: Local verify (normal operation, safe)
printf "\\x04\\x00\\x00\\x00" | nc PS5_IP 9022
cat state_capture.bin | nc PS5_IP 9022
# Check: savectx found? PCB layout mapped? LSTAR offset identified?

# Step 2: ARM for resume test
printf "\\x02\\x00\\x00\\x00" | nc PS5_IP 9022
cat state_capture.bin | nc PS5_IP 9022
# Check: apic_ops[2] set to savectx? Fingerprints saved?

# Step 3: Enter rest mode via PS5 UI, then resume

# Step 4: READBACK
printf "\\x03\\x00\\x00\\x00" | nc PS5_IP 9022
cat state_capture.bin | nc PS5_IP 9022
# Check: PCB found in kdata? Full register state dumped?
```

### What the State Dump Tells Us

| Finding | Implication | Next Step |
|---------|------------|-----------|
| pcb_cr0 has WP clear | HV not active at this point | Use wrmsr_ret directly to set LSTAR |
| pcb_cr0 has WP set | HV active, intercepting | Need ROP chain approach |
| pcb_rbp → kdata range | leave;ret gives stack pivot | Build ROP chain at [RBP] |
| pcb_rdi → kdata range | resumectx with fake PCB | Total CPU state control |
| pcb_rsp → known stack | pop_all_iret controllable | Load all regs from stack |
| pcb_rip → ktext addr | Identifies exact caller | Trace FreeBSD source for caller's register setup |

### If savectx Crashes (RDI Invalid)

**Fallback 1**: Test nop_ret (bare `ret`) as apic_ops[2] — determines if return value matters.
**Fallback 2**: Overwrite OTHER apic_ops entries that receive known arguments (init gets vm_paddr_t in RDI, dump gets string pointer in RDI).
**Fallback 3**: Find and modify susppcbs[0] PCB (used by ACPI save/resume, very early in resume path).

**UPDATE (Session 10)**: RDI confirmed invalid during resume (R8 gamble). savectx as apic_ops[2] is not viable. Fallback 3 (susppcbs) is now the primary approach — see Phase 16.

---

## Phase 14: kdata_scanner + Probe Range Fix

### kdata_scanner Results

Built `kdata_scanner` payload to scan kdata for all ktext pointers without executing anything. Scans 4.4MB across 4 kdata regions. Added paged output (modes 0x403-0x408, 57 entries per page) to work within kldloader's 0x1f8 readback limit.

**Results**: 270 unique ktext pointers found across 5 pages (57+57+57+57+42).

**Critical finding — cpu_switch dark zone:**
- Normalizing to offsets from ktext_base (stable across boots):
  - Page 0's last entry: offset ~0x190160 from ktext_base
  - Page 1's first entry: offset ~0x290160 from ktext_base
  - cpu_switch is at ktext_base + 0x229080
- **cpu_switch sits in a ~1MB gap with ZERO kdata references**
- savectx, resumectx, cpu_throw — none are referenced from any kdata function pointer table
- They're called exclusively via direct `call` instructions within ktext

### state_capture v3 Crash Root Cause

Deployed Mode 0x4 (FIND) — **instant system crash** (30-second delayed kernel panic).

**Root cause**: The probe range was `cpu_switch + 0x500` to `cpu_switch + 0x1500`. Computing offsets from the DEF() macros in offsets.c reveals this range is **20KB away from savectx**:

```
Offset from cpu_switch (FW 4.03):
+0x0000: cpu_switch        (-0x9d6f80)
+0x01ED: dr2gpr_start      (-0x9d6d93)
+0x0306: gpr2dr_1_start    (-0x9d6c7a)
+0x03F9: gpr2dr_2_start    (-0x9d6b87)
  ← OLD PROBE RANGE: +0x500 to +0x1500 (WRONG — random destructive functions) →
+0x4EB4: wrmsr_ret         (-0x9d20cc)  inside resumectx
+0x4EB6: nop_ret           (wrmsr_ret+2)
+0x6286: rdmsr_start       (-0x9d0cfa)  inside savectx (MSR save sequence)
  ← savectx entry is ~0x80-0xA0 bytes BEFORE rdmsr_start →
```

The probes hit random kernel functions between cpu_throw and resumectx. pcb_onfault only catches page faults, not "this function acquired locks and corrupted the scheduler."

### Fix: Precision Probe Near rdmsr_start

`rdmsr_start` (-0x9d0cfa) is the MSR save sequence **inside** savectx. Before it:
- GPR saves (movq %rbx/%rsp/%rbp/%r12-r15 to [RDI]) ≈ 34 bytes
- CR saves (movq %cr0-%cr4 via %rax to [RDI]) ≈ 28 bytes
- DR saves (movq %dr0-%dr7 via %rax to [RDI]) ≈ 60 bytes
- Total ≈ 122 bytes

savectx entry ≈ `rdmsr_start - 0x7A` to `- 0xA0` ≈ **cpu_switch + 0x61E6 to 0x620C** (16-byte aligned: ~0x6200)

**New probe range**: `rdmsr_start - 0x100` to `rdmsr_start + 0x10` (only 17 probes)

All probes land in:
- savectx's register-to-memory store code (safe `movq %reg, offset(%rdi)`)
- savectx's entry point (full save + return 1)
- Padding (NOPs/INT3 → fault caught by pcb_onfault)

**Result**: Still crashed. pcb_onfault only catches #PF (page faults). Entering mid-instruction
at 16-byte aligned boundaries inside savectx causes #UD or #GP — NOT caught → instant panic.

### v4: Zero Probing — Call rdmsr_start Directly

Key constraints discovered:
1. **ktext is XOM** (Execute Only Memory) — cannot read bytes to find prologue signatures
2. **pcb_onfault** only catches #PF, not #UD/#GP from mid-instruction entry
3. **td_pcb may be 0** for kproc threads, making onfault completely inoperative
4. **No kdata references** to savectx (only relative calls within ktext)

**Solution**: Call `rdmsr_start` directly. It's a KNOWN address inside savectx at a verified
instruction boundary. The code sets ECX before each rdmsr, writes to [RDI+offsets], then
falls through to sgdt/sidt/sldt/str, then `mov $1, %eax; ret`.

**Captures** (MSRs + descriptors): FSBASE, GSBASE, KGSBASE, EFER, STAR, LSTAR, CSTAR, SFMASK, GDT, IDT, LDT, TR

**Does NOT capture** (before rdmsr_start): GPRs, CRs, DRs

Mode 0x4 calls rdmsr_start with a clean buffer to discover which PCB offsets receive MSR values.
Mode 0x2 arms apic_ops[2] with rdmsr_start for ACPI resume capture.
Mode 0x3 scans kdata for LSTAR value to find the MSR dump after resume.

**Status**: v4 crashed (kernel panic on Mode 0x4).

### Phase 15: Root Cause — ALL Crashes Due to kdata Corruption (v5 Fix)

**Root cause identified**: Every version (v1-v4) wrote zeros to `kdata_base + 0x400` to clear the
PCB buffer. This offset falls in the kernel's live data segment, corrupting global variables,
lock structures, or list heads. The crash was never caused by the function calls themselves —
it was the buffer clear that destroyed kernel state.

Evidence:
- v3 original: 30-second delayed crash (corrupted a non-critical variable; probing then hit a destructive function)
- v3 fixed (correct probe range): instant crash (kdata corruption + possibly #UD from non-aligned entry)
- v4 (direct rdmsr_start call): instant crash (rdmsr_start is safe, but kdata+0x400 was zeroed before the call)

**Fix (v5)**: PCB buffer moved from `kdata_base + 0x400` to `kthread_args + 0x800`.
kthread_args is our own 4KB heap allocation (`kekcall_malloc(0x1000)`). Output slots use
offsets 0x000-0x3FF, PCB buffer uses 0x800-0x9FF. No overlap, no kdata writes.

**New Mode 0x5 — Pure Read-Only PCB Scanner**:
- Scans kdata for existing PCBs created by kernel's own `savectx`/`cpu_switch` calls
- Match criteria: CR3 at PCB offset 0x68 matches our kernel CR3, CR0 at offset 0x58 has PG+PE bits
- Zero function calls, zero writes to kdata — safest possible approach
- After ACPI suspend/resume, kernel's `savectx(susppcbs[0])` stores full CPU state including MSRs
- Mode 0x5 re-scan after resume finds the suspend PCB with complete state

**Status**: state_capture v5 built. Binary: `examples/state_capture/state_capture.bin`.

### Deployment Plan (v5)

```bash
# Step 1: Mode 0x5 first (SAFEST — zero calls, zero kdata writes)
# Scan for existing thread PCBs on fresh boot
printf '\x05\x00\x00\x00' | nc PS5_IP 9022
cat state_capture.bin | nc PS5_IP 9022
# Expected: finds thread PCBs with CR3/CR0 matches, dumps up to 4

# Step 2: Mode 0x4 (rdmsr_start call with FIXED heap buffer)
printf '\x04\x00\x00\x00' | nc PS5_IP 9022
cat state_capture.bin | nc PS5_IP 9022
# Expected: returns 1, MSR fields mapped, NO crash

# Step 3: Put PS5 in rest mode via UI (kernel calls savectx → susppcbs[0])
# Step 4: Resume PS5

# Step 5: Mode 0x5 again — find suspend PCB with full CPU state
printf '\x05\x00\x00\x00' | nc PS5_IP 9022
cat state_capture.bin | nc PS5_IP 9022
# Expected: additional PCB(s) with LSTAR and full MSR state
```

---

## Phase 16: CR3 Scan Results + kernel_pmap_store Discovery

### CR3 Scan of kdata BSS (state_capture v7.2, Mode 0x7 filter_type 1)

Scanned 44MB of kdata BSS (pages 0-10, each 4MB) for the exact CR3 value after rest mode.

**Results**: ONE hit across entire 44MB scan.

| Boot | kdata_base | CR3 | Hit Address | Offset from kdata |
|------|-----------|-----|-------------|-------------------|
| Boot 1 | `0xffffffff97800000` | `0x1df34000` | `0xffffffff99fed6c8` | **+0x27ed6c8** |
| Boot 2 | `0xffffffff8d1d0000` | `0x13904000` | `0xffffffff8f9bd6c8` | **+0x27ed6c8** |

**Offset +0x27ed6c8 is stable across boots** (different KASLR slides, different CR3 values).

### Memory Dump at kdata+0x27ed600 (MEMDUMP filter_type 3)

Dumped 32 qwords (256 bytes) around the hit. Structure analysis:

```
Offset  Value                    Interpretation
+0x00   0x0000000000000000       (lock/zero)
+0x08   self-pointer             TAILQ_HEAD (points to +0x00)
+0x10-  zeros
+0x38   0x7fffffffffffffff       CPU bitmask (all CPUs active)
+0x40-  zeros
+0x98   0x0000000000000031       Flags
+0xa0   ktext pointer            Function pointer (ktext+0xF0E951)
+0xa8   0x0000000001430000       Physical address
+0xb8   0x0000000000000004       Small constant
+0xc0   0xffffbff313904000       pm_pml4 (virtual addr of PML4 via DMAP)
+0xc8   0x0000000013904000       pm_cr3 (physical CR3)
+0xd0   0x0000000000000000
+0xd8   pointer to +0xd0         List linkage
```

### Identification: kernel_pmap_store (NOT susppcbs)

This is the **kernel pmap** (`kernel_pmap_store`), the page map structure for the kernel
address space. Key evidence:
- Self-pointer at +0x08 (TAILQ list head, standard for pmap)
- CPU bitmask `0x7fffffffffffffff` at +0x38 (pm_active, all CPUs)
- Two CR3 representations: virtual PML4 at +0xc0, physical CR3 at +0xc8
- Structure is mostly zeros with sparse metadata — NOT a PCB (which would have saved registers)

### DMAP Base Derivation

From the pmap structure:
```
DMAP_BASE = pm_pml4_va - CR3_phys
          = 0xffffbff313904000 - 0x13904000
          = 0xffffbff300000000
```

**DMAP_BASE = `0xffffbff300000000`** — any physical address can be read as `DMAP_BASE + phys_addr`.

### Key Discoveries

| Finding | Value | Significance |
|---------|-------|-------------|
| kernel_pmap_store | kdata + 0x27ed600 | Kernel page map, stable offset |
| DMAP_BASE | `0xffffbff300000000` | Physical memory readable via DMAP |
| susppcbs NOT in kdata BSS | Confirmed (1 hit in 44MB = kernel_pmap only) | Must search elsewhere |
| kdata BSS extends 44MB+ | Pages 0-10 safe, no panic | Larger than initially estimated |

### Implications for susppcbs Search

The single CR3 hit proves **susppcbs PCB data is NOT in kdata BSS**. It's heap-allocated
(in the `0xffffff80...` range), consistent with `state_capture/progress.md` findings
("Mode 0x5 found 0 PCBs: thread PCBs are heap-allocated, not in kdata").

In FreeBSD, `susppcbs` is a `struct pcb **` pointer in BSS. The pointer itself might be
in kdata BSS, but it points to heap-allocated PCB structures. The CR3 scan only searched
for the CR3 VALUE in BSS — it wouldn't find a pointer-to-heap.

### DMAP Low-Memory CR3 Scan — FAILED

Scanned first 11MB of physical memory (pages 0-10, 1MB each) via DMAP for the CR3 value,
looking for FreeBSD's ACPI wakeup trampoline containing `WAKECODE_FIXUP(wakeup_pdir, KPML4phys)`.

**Results**: ZERO hits across all 11 pages. Every page completed without panic (DMAP reads
of low physical memory work), but CR3 was not found.

**Likely causes**:
1. Sony does not use FreeBSD's standard `WAKECODE_FIXUP` / ACPI wakeup trampoline
2. CR3 may be stored at 4-byte alignment (scanner reads 8-byte-aligned qwords only)
3. PS5 rest mode may use a completely custom suspend/resume mechanism

**Conclusion**: ACPI wakeup trampoline approach is a **dead end**. Cannot locate `susppcbs`
through low physical memory scanning.

### Next Step: Broad kdata BSS Pointer Scan

Since the CR3-in-BSS scan found only kernel_pmap, and the DMAP low-memory scan found
nothing, the remaining approach is to search kdata BSS for the `susppcbs` **pointer variable**
itself (a heap address in BSS), rather than the PCB data it points to.

The broad pointer filter (`fw_ver = 0x87 | (page << 8)`) matches any qword with
`upper32 & 0xFFFF0000 == 0xFFFF0000` excluding `0xFFFFFFFF` (kdata/ktext). This catches:
- Heap pointers (`0xffffff80...`) — where susppcbs points
- DMAP pointers (`0xffffbff3...`) — kernel_pmap fields (control test)
- Thread pointers (`0xffffXXXX...`) — other kernel globals

**Deployment**: 11 runs (pages 0-10), all safe (read-only). Page 9 should find
kernel_pmap DMAP pointers as a known control.

### Broad kdata BSS Scan Results (fw_ver=0x87, filter: 0xFFFFxxxx excluding 0xFFFFFFFF)

**Pages 0-2**: Heavy noise. Broad filter matches bitmasks, packed flags, and interrupt
descriptor data. Pages 1-2 maxed out at 140 hits each (scanner limit). Most values are
clearly NOT pointers: `0xfffffffefffffffe` (bitmask), `0xffff00010001ffff` (packed halves),
`0xffff0004ffffffff` (counter/flags). Two potentially interesting tagged heap pointers on
page 0 at kdata+0x1745f8 (`0xffffff8c86bba801`) and kdata+0x174640 (`0xffffff8c86bba804`)
but both have non-zero low bits (tag bits, not clean pointers).

**Page 9** (kdata+0x2400000 to +0x2800000): **Clean results — 4 heap pointers found!**

Control test passed: many DMAP pointers (`0xffffbff3...`) from kernel_pmap_store region confirmed.

| # | kdata offset | Heap pointer value | Alignment | Notes |
|---|-------------|-------------------|-----------|-------|
| 1 | +0x256c1e0 | `0xffffff80931e3c00` | 1KB | Isolated, ~0xD0000 before cluster |
| 2 | +0x263a058 | `0xffffff8003afccb0` | 16-byte | Cluster start |
| 3 | +0x263ae10 | `0xffffff80049a0000` | **64KB** | Suspicious — large allocation (susppcbs?) |
| 4 | +0x263ae70 | `0xffffff8003af77f8` | 8-byte | ~0x60 after #3 |

**Analysis**:
- Hit #3 (`0xffffff80049a0000`) is 64KB-aligned — consistent with `malloc(N * sizeof(struct pcb))`
  for a per-CPU array like `susppcbs`. `sizeof(struct pcb)` on PS5 is ~0x110 bytes,
  so `MAXCPU * 0x110` rounded up to page alignment could produce a 64KB-aligned allocation.
- Hits 2-4 are clustered at kdata+0x263aXXX (within ~0xC18 bytes), suggesting they're fields
  of the same structure or nearby structures in BSS.
- Hit 1 is isolated ~0xD0000 earlier — likely a different structure.

### Pointer Follow Results (fw_ver=0xC7)

Followed all 4 heap pointers — **none are PCBs**:

| Hit | kdata offset | Heap target | Identity | Evidence |
|-----|-------------|-------------|----------|----------|
| 1 | +0x256c1e0 | `0xffffff80931e3c00` | Descriptor/segment table | Repeating `0xffff` limits at 16-byte stride |
| 2 | +0x263a058 | `0xffffff8003afccb0` | Empty allocated buffer | All zeros after single back-pointer to kdata |
| 3 | +0x263ae10 | `0xffffff80049a0000` | UMA zone allocator metadata | Self-referential ptrs, ktext fn ptr at +0x58, 0x88-byte repeating elements |
| 4 | +0x263ae70 | `0xffffff8003af77f8` | Live kernel variable | Value changed between scan and follow (now `0xffffffff8fc0c5b8`) |

### susppcbs Search — EXHAUSTED

| Approach | Result |
|----------|--------|
| CR3-in-kdata-BSS scan (44MB, 11 pages) | 1 hit = kernel_pmap_store (not susppcbs) |
| DMAP low-memory CR3 scan (11MB) | 0 hits (Sony doesn't use WAKECODE_FIXUP) |
| Broad BSS pointer scan (44MB, 0xFFFFxxxx filter) | 4 heap ptrs = allocator/descriptor metadata |
| Pointer follow of all 4 candidates | None are PCBs (no CR3, no saved registers) |

**Conclusion**: `susppcbs` is either not in kdata BSS, Sony replaced FreeBSD's ACPI
suspend mechanism entirely, or suspend PCBs use a non-standard allocation path.
**The susppcbs approach is a dead end.**

---

## Dead End: nop_ret as apic_ops[2] During Resume

**Test**: Point apic_ops[2] at `nop_ret` (bare `ret`, kdata-0x9d20ca). System enters rest mode, **never resumes**.

**Conclusion**: The LAPIC resume caller checks the return value of xapic_mode. `nop_ret` returns whatever RAX contains at the call site (likely 0 or garbage). A non-1 return value causes the caller to take the wrong LAPIC access path (x2APIC MSR-based on XAPIC hardware), crashing during resume. **apic_ops[2] MUST return non-zero** (get_timer_freq's 0x13b0 works, bare ret does not).

## Dead End: DMAP Access to Ktext Physical Pages

Confirmed across multiple attempts: ktext physical pages are **completely unmapped from DMAP** (PTE = 0). The hypervisor removes ktext backing pages from the guest's DMAP region entirely. Cannot read ktext bytes through any guest-accessible path (VA, DMAP, or page table walk). Only execution-based probing works.

## Dead End: Spectre v1 Side-Channel to Read Ktext (XOM Bypass)

Spectre v1 Flush+Reload attack attempted to speculatively read ktext bytes and leak via cache timing. **Failed**: NPT (nested page tables) enforce XOM even on speculative accesses. The hypervisor's NPT marks ktext pages as execute-only at the hardware level — speculative loads fault in the MMU before reaching the cache. Cannot bypass XOM via any known microarchitectural side-channel on this platform.

---

## Session 11: DR+IDT Persistence Strategy — Research & Worst-Case Analysis

### FreeBSD 11 Source Research Findings

Fetched and analyzed FreeBSD 11 amd64 source code for `cpu_switch.S`, `savectx()`/`resumectx()`, `acpi_wakeup.c`, and `pcb.h`.

#### Key Finding 1: savectx/resumectx handle DRs UNCONDITIONALLY

```asm
; savectx: saves ALL DRs (no PCB_DBREGS check)
movq %dr0,%rax / movq %rax,PCB_DR0(%rdi)  ; through DR7

; resumectx: restores ALL DRs (no PCB_DBREGS check)
movq PCB_DR0(%rdi),%rax / movq %rax,%dr0   ; through DR7

; resumectx also restores IDT:
lidt PCB_IDT(%rdi)
```

This is the ACPI suspend/resume path. On standard FreeBSD 11, any DR values present at suspend time are saved into `susppcbs[cpu].sp_pcb` by `savectx()` and restored on resume by `resumectx()`. No PCB_DBREGS flag check — completely unconditional.

#### Key Finding 2: cpu_switch handles DRs CONDITIONALLY

```asm
; Save path (old thread):
testl   $PCB_DBREGS, PCB_FLAGS(%r8)
jnz     store_dr          ; only if PCB_DBREGS (0x02) set in pcb_flags
; store_dr: saves DR0-3,DR6,DR7 to PCB, then clears DR7

; Restore path (new thread):
testl   $PCB_DBREGS, PCB_FLAGS(%r8)
jnz     load_dr           ; only if PCB_DBREGS set
; load_dr: loads DR0-3,DR6,DR7 from PCB to hardware
```

This is the normal context switch path. DR save/restore only happens if `pcb_flags & PCB_DBREGS`. On the restore side, cpu_switch loads DR values from the PCB into hardware registers.

#### Key Finding 3: susppcbs structure

```c
struct susppcb {
    struct pcb  sp_pcb;           /* full PCB for suspend context */
    void       *sp_fpususpend;    /* FPU state save area */
};
// Allocated: susppcbs = malloc(mp_ncpus * sizeof(*susppcbs), M_DEVBUF, M_WAITOK);
// One per CPU, dynamically allocated
```

Suspend flow uses setjmp-like semantics: `savectx(pcb)` returns non-zero initially (saving), returns 0 when `resumectx(pcb)` restores context (waking).

#### Key Finding 4: IDT saved via sidt, restored via lidt

`savectx()` does `sidt PCB_IDT(%rdi)` — saves the current IDTR (base + limit). `resumectx()` does `lidt PCB_IDT(%rdi)` — reloads IDTR from the saved value. The IDT TABLE itself (in kdata) is not copied — just the register that points to it. This is why our IDT modifications persist: the table in kdata memory is unchanged, and the IDTR is restored to point at it.

### kstuff Mechanism Research

Analyzed sleirsgoevy's ps5-kstuff from `ps4jb-payloads/bd-jb/ps5-kstuff/`:

#### Pointer Poisoning

kstuff uses "pointer poisoning" to hook kernel functions without text patching. Replaces top 16 bits of function pointers with `0xdeb7` (non-canonical address). When dereferenced → #GP (IDT[13]) → kstuff's handler fixes the pointer and emulates the call.

#### IDT Hooks

- **IDT[1] (#DB)**: Debug trap handler — fires on hardware breakpoint (DR0-DR3) hits
- **IDT[13] (#GP)**: General protection fault — fires on poisoned pointer dereference
- **IDT[2] (NMI)**: Redirected to `doreti_iret`
- Uses **IST3** and **IST7** (from code analysis) for dedicated interrupt stacks

#### DR Usage

Sets DR0-DR3 as execution breakpoints on specific kernel code addresses (e.g., `kmem_alloc` internals). When the CPU executes the breakpoint address → #DB fires → IDT[1] handler patches the instruction on-the-fly using register manipulation (can't write ktext, but can manipulate the return context to skip/modify behavior).

**Critical**: kstuff does NOT persist through rest mode. It must be re-deployed after every boot/resume. Our goal is to make this mechanism persist.

### Worst-Case Scenario Analysis

#### Unknown 1: DR persistence through rest mode

| Scenario | Probability | Evidence |
|----------|------------|---------|
| DRs persist (savectx saves them) | Medium | FreeBSD 11 savectx does it unconditionally |
| DRs zeroed (Sony removed from suspend path) | Medium | susppcbs not found (line 2029), Sony modifies everything |
| DRs zeroed (HV clears in wakeup trampoline) | Low | HV doesn't intercept DR access during normal operation |

**Worst case**: DRs zeroed. savectx/resumectx don't exist on PS5 or Sony's wakeup trampoline explicitly zeros DRs.

**Recovery**: Approach B (PCB_DBREGS via cpu_switch). cpu_switch confirmed running during resume. If PCB_DBREGS flag triggers DR loading from PCB, DRs get armed during first context switch after resume (normal operation, post-NPT window).

**If Approach B also fails**: Approach C (sysent hijack) — pure kdata, no DRs needed.

#### Unknown 2: PCB_DBREGS flag loading on PS5

| Scenario | Probability | Evidence |
|----------|------------|---------|
| cpu_switch checks PCB_DBREGS | High | Core FreeBSD debugger support, hard to remove without breaking ptrace |
| Sony removed DR handling from cpu_switch | Low | Would break kernel debugger, ptrace DR support |

**Worst case**: PCB_DBREGS ignored. cpu_switch never loads DRs from PCB.

**Recovery**: Only matters if DRs don't persist natively. If both fail → sysent hijack (Approach C), GPU DMA, or VMMCALL.

**Key insight**: This is testable pre-suspend (no risk). Write DR values to current thread's PCB, set PCB_DBREGS, trigger context switch, read DRs back.

#### Unknown 3: Sysent dispatch CFI

| Scenario | Probability | Evidence |
|----------|------------|---------|
| No CFI on sysent dispatch | High | apic_ops has no CFI, PS5 kernel predates LLVM kernel CFI |
| CFI active on sysent dispatch | Low | Sony could add CFI selectively |

**Worst case**: Sysent indirect call checks CFI → panic when calling kdata handler.

**Recovery**: This failure is learned pre-suspend (immediate test, single-boot crash, no persistence damage). Non-blocking because DR+IDT approaches (A/B) don't use sysent.

#### Unknown 4: Kdata execution post-resume

| Scenario | Probability | Evidence |
|----------|------------|---------|
| Kdata execution works post-resume | Very High | kstuff works on 4.03, IDT mods proven to persist and system runs stably |
| HV blocks kdata execution permanently after resume | Very Low | Would break kstuff entirely, contradicts Phase 7 results |

**Worst case**: HV permanently marks kdata NX after resume cycle.

**Recovery**: GPU DMA (bypass NPT via IOMMU path), VMMCALL probing (17 untested hypercalls), or ktext-only ROP chains via IDT+iretq gadgets.

#### Nuclear worst case: Everything fails simultaneously

DRs zeroed + PCB_DBREGS removed + sysent CFI + kdata NX post-resume.

**Remaining vectors**:
1. **GPU DMA** (unexplored on 4.03, proven concept on 6.00+ by flatz)
2. **VMMCALL hypercalls** (17 untested, IOMMU-related)
3. **Alternative apic_ops entries** (init/dump receive known args, unexplored)
4. **LAPIC timer hijack** (point IDT timer entry to ktext gadget chain)

### Action Items

1. **Deploy suspend_stackprobe** ARM → rest mode → READBACK → check DR sentinel slots [39-43]
2. **Build PCB_DBREGS pre-flight test** (normal operation, no rest mode needed)
3. **Build sysent CFI test** (normal operation, no rest mode needed)
4. Based on results, build the appropriate DR+IDT hook payload

---

## Consolidated Assessment: What We Know, What's Dead, What's Left

### What kldload Actually Gives Us (Current Capability)

We have **full kernel code execution** inside the guest VM:
- Allocate kernel memory, copy code, clear NX, launch kernel threads
- Read/write all of kdata, kernel heap, DMAP
- Call any kernel function (copyin, copyout, malloc, kproc_create, etc.)
- Modify IDT entries, TSS IST pointers, apic_ops vtable
- Set/read debug registers (DR0-DR7)
- Read MSRs (LSTAR, EFER, STAR, etc.) and CRs (CR0, CR3, CR4)
- Modifications to kdata, IDT, TSS, and apic_ops all **persist through rest mode**

### What the Hypervisor Blocks (Proven Walls)

Every one of these has been tested and confirmed blocked:

| Attack | How Blocked | Evidence |
|--------|------------|---------|
| Read ktext bytes (VA) | NPT XOM — execute-only pages | v8a/v8c/v8c2 all crash, pcb_onfault can't catch NPT violation |
| Read ktext bytes (DMAP) | PTEs zeroed — ktext pages removed from DMAP entirely | pivot_scan_safe v5: PTE=0 for ktext physical pages |
| Read ktext bytes (Spectre) | NPT enforced on speculative access | Flush+Reload attack failed |
| Write ktext | NPT read-only + XOM | Never attempted directly, but XOM + no write confirmed |
| Execute non-ktext during suspend | NPT NX on all non-ktext pages during cpususpend_handler | `mov eax,1; ret` in kdata panics during suspend |
| Write CR0 (clear WP) | VMEXIT interception | PCB hijack v3: CR0.WP write intercepted, HV active at cpu_switch |
| Write MSRs (LSTAR etc.) | VMEXIT interception | HV intercepts wrmsr — confirmed by CR0.WP test (same mechanism) |
| INT3 during LAPIC resume | VMCB-intercepted → VMEXIT → crash (HV not ready) | v7, v9a fail; root cause: INT3 is in VMCB exception intercept bitmap |
| Replacing IDT[1] while kstuff active | kstuff DR breakpoints on other CPUs crash | IDT global but DRs per-CPU; dr_db_resume_test v1/v2 panicked instantly |
| #DB via DR during resume | DRs reset by S3 power-off (CPU state lost) | dr_db_resume_test v3: DR2=0, DR7=0x400 after rest mode |
| nop_ret as apic_ops[2] | Must return non-zero | System enters rest, never resumes (LAPIC mode detection fails) |
| savectx as apic_ops[2] | RDI invalid during resume | R8 gamble confirmed RDI not controllable |
| Modify ktext PTEs | HV integrity monitor | XOTEXT bit clearing triggered HV, blocked rest mode entry |
| Set QA/SL debug flag | QA flags isolated from guest at FW 3.00 | Byepervisor bugs patched; confirmed in progress_session9.md |

### Confirmed Dead Ends (Do Not Revisit)

1. **DMAP reading ktext** — tested 5+ times across multiple strategies. PTEs are literally zeroed. The physical pages backing ktext are not mapped in DMAP at all. This is NOT a page fault we can catch — the pages simply don't exist in the guest's DMAP view.

2. **INT3-based approaches during resume** — INT3 (#BP, vector 3) is VMCB-intercepted. During resume, the HV VMEXIT handlers are not yet initialized, so INT3 causes a fatal VMEXIT crash. This is NOT because the IDT isn't loaded — it's because INT3 always triggers a VMEXIT regardless of IDT state. Both doreti_iret bounce (v9a) and IST+pop_all_iret chain (v3) fail identically for this reason. **#DB (vector 1) via DR breakpoints is NOT intercepted** — proven by kstuff using DR breakpoints successfully. See Phase 19.

3. **PCB hijack for pre-HV access** — cpu_switch runs too late. HV is already active. v3 proved code execution works but CR0.WP write was intercepted.

4. **susppcbs manipulation** — exhaustive search (44MB kdata BSS + 11MB DMAP low memory + broad pointer scan + all 4 candidate follows) found nothing. Sony either replaced FreeBSD's ACPI suspend or uses a non-standard allocation.

5. **Blind ktext byte scanning via read** — XOM is hardware-enforced via NPT. No guest-accessible path can read ktext bytes. Only execution-based probing works, and it's dangerous (one crash per bad byte).

6. **Stack pivot gadget via apic_ops epilogues** — Sony Clang consistently emits `?? 48 C3` epilogues (REX.W ret). No `C9 C3` (leave;ret) found in any of the 28 apic_ops entries at fn-1, fn-2, or fn-3.

7. **EntrySign / PATCH_LOADER MSR** — HV blocks entire 0xC001xxxx MSR range. VM terminated on first attempt (PATCH_LEVEL 0xC0010021). PATCH_LOADER (0xC0010020) never reached. All AMD-specific MSRs are inaccessible from guest ring 0. EntrySign (CVE-2024-56161) is not viable on PS5 FW 4.03.

8. **Byepervisor QA flags (SL debug flag)** — Both Byepervisor bugs patched at FW 3.00. Bug #1: QA flags isolated from guest kernel (guest can no longer set SL flag to disable xotext in NPT). Bug #2: HV jump tables moved out of kdata (HV separated into own binary). Flatz holds a private, different HV exploit for ≤4.51 (patched 5.00) but no technical details published. QA flags approach is not viable on FW 4.03.

### The Fundamental Problem

The hypervisor is a **hardware-enforced boundary**. Every approach tried so far operates within the guest VM — using guest page tables, guest IDT, guest MSR access. The HV controls:
- **NPT (Nested Page Tables)**: determines what physical memory the guest can read/write/execute
- **MSR intercept bitmap**: determines which MSR writes trigger VMEXITs
- **CR access intercept**: determines which CR writes trigger VMEXITs
- **VMCB (Virtual Machine Control Block)**: the HV's own configuration, inaccessible from guest

No amount of clever kernel tricks inside the guest changes these hardware controls. The guest cannot modify NPT entries because they're in host-physical memory the guest can't address. The guest cannot disable MSR intercepts because that's in the VMCB.

### What Could Actually Work (Honest Assessment)

#### 1. GPU DMA (Different Attack Class)

**Why it's fundamentally different from everything tried so far:**

The CPU path: `Guest VA → Guest PT → Guest PA → NPT → Host PA`
The GPU DMA path: `GPU command → IOMMU → Host PA` (or directly to PA if IOMMU is permissive)

GPU DMA does NOT go through NPT. It goes through the IOMMU (AMD's IOMMU, separate from AMD-V's NPT). If the IOMMU is misconfigured or can be reprogrammed from the kernel, GPU DMA can access physical memory that the CPU cannot — including potentially:
- Reading ktext physical pages (bypassing XOM)
- Writing to arbitrary physical memory
- Accessing HV memory / NPT tables / VMCB

**Why it might NOT work:**
- Sony may have configured the IOMMU correctly (locked down GPU DMA range)
- IOMMU configuration registers may be trapped by the HV
- The GPU command processor setup is complex (need to understand AMD's GFX ring buffer protocol)
- flatz's PS5 6.00+ GPU DMA work targeted a different firmware — IOMMU config may differ on 4.03
- We'd need to reverse-engineer the GPU driver's MMIO register layout from kdata (since we can't read ktext)

**Honest question: does GPU DMA give us more than kldload?**

If IOMMU is locked down: **NO.** We'd spend weeks setting up GPU commands and hit another wall.

If IOMMU is permissive or reconfigurable: **YES, dramatically.** GPU DMA would let us:
- Read ALL of ktext (every gadget, every function, full disassembly)
- Write to NPT entries (disable XOM, disable NX, make ktext writable)
- Potentially write to VMCB (disable MSR/CR interception entirely)
- Potentially access HV code/data

The difference is binary: it either works or it doesn't. There's no partial success scenario.

#### 2. VMMCALL Hypercall Probing (Low Effort, High Uncertainty)

17 untested hypercalls. Some may be IOMMU-related (AMD IOMMU uses hypercalls for some operations). A bug in any hypercall handler could give HV-level access.

**Effort**: Low (each probe is a single VMMCALL instruction with different arguments)
**Risk**: Each bad call is a potential crash
**Reward**: If a hypercall has a vulnerability, it's game over — direct HV compromise

#### 3. IOMMU Reconfiguration from Kernel (Medium Effort)

Instead of GPU DMA, directly reprogram the IOMMU via its MMIO registers. The kernel has an IOMMU driver that configures DMA mappings. If those MMIO registers are accessible:
- Add a DMA mapping for our own buffer → ktext physical address
- Use any DMA-capable device (USB, network, etc.) to read/write through the mapping

**Risk**: HV may trap IOMMU MMIO accesses
**Prerequisite**: Find IOMMU base address (probably discoverable from PCI config space, which is readable)

#### 4. Sysent Persistence (Different Goal)

If the goal is just **persistent kernel code execution** (survives rest mode, no need to re-run webkit/BD-J exploit):
- Replace a rarely-used sysent handler pointer with kdata function address
- After rest mode, sysent table persists (it's kdata)
- Re-exploit via webkit/BD-J, call the hijacked syscall → instant kernel code execution without kstuff reload

This doesn't bypass the HV, but it gives persistence. Combined with kldload's existing capabilities, it means every boot after the first only needs a userland exploit to regain full kernel access.

**Does NOT help with**: reading ktext, writing ktext, modifying protected MSRs/CRs

#### 5. Hardware Attacks (Highest Effort, Guaranteed Results)

- SPI flash dumping → read the HV binary, find vulnerabilities offline
- UART → debug output during boot, potential command injection
- Voltage glitching → fault the HV's integrity checks during boot

These bypass the software boundary entirely but require physical equipment.

### Bottom Line

**The user's question — "How is GPU DMA going to truly get more attack surface than kldload?" — is the right question.**

The honest answer: GPU DMA is a **completely different DMA path** that bypasses the CPU's NPT enforcement. It's not "maybe Sony didn't think of X within the hypervisor" — it's "can we go around the hypervisor entirely via a peripheral's DMA engine." If the IOMMU is locked down, it gives us nothing. If it's not, it gives us everything.

But we don't know which it is without trying, and the setup cost is significant. VMMCALL probing (approach 2) is lower effort and should be tried first — a single vulnerable hypercall could be more impactful than weeks of GPU driver reverse engineering.

**Recommended order:**
1. VMMCALL probing (hours of work, could find HV bug)
2. IOMMU register discovery (find if MMIO is accessible or trapped)
3. GPU DMA (only if IOMMU looks promising)
4. Hardware (if all software paths are exhausted)

**NOTE (updated):** MSR-based approaches (EntrySign, SYSCFG, VM_CR, HWCR) are confirmed dead — see Phase 17. The HV blocks ALL 0xC001xxxx MSRs. Only 9 standard MSRs (EFER, STAR, LSTAR, CSTAR, SFMASK, FSBASE, GSBASE, KGSBASE, APIC_BASE) are accessible from guest ring 0.

---

## Phase 17: MSR Accessibility Probe (msrpm_probe)

**Status: COMPLETE**

### Design

Deployed `msrpm_probe` kmod via kldload. Reads MSRs directly via `rdmsr` in kernel context (ring 0). The PS5 HV intercepts all `rdmsr` via VMEXIT — emulated MSRs return values, blocked MSRs terminate the VM (no #GP injected). Payload writes progress markers after each successful read so partial results survive VM termination.

### Results

9 tier-1 MSRs succeeded. First 0xC001xxxx MSR (PATCH_LEVEL, 0xC0010021) terminated the VM.

### Accessible MSRs (Tier 1 — kernel-standard)

| MSR | Name | Status |
|-----|------|--------|
| 0xC0000080 | EFER | Readable |
| 0xC0000081 | STAR | Readable |
| 0xC0000082 | LSTAR | Readable |
| 0xC0000083 | CSTAR | Readable |
| 0xC0000084 | SFMASK | Readable |
| 0xC0000100 | FSBASE | Readable |
| 0xC0000101 | GSBASE | Readable |
| 0xC0000102 | KGSBASE | Readable |
| 0x0000001B | APIC_BASE | Readable |

### Blocked MSRs (VM terminated — no #GP, instant kill)

| MSR | Name | Status |
|-----|------|--------|
| 0xC0010021 | PATCH_LEVEL | VM killed |
| 0xC0010020 | PATCH_LOADER | Not reached (killed on 0xC0010021 first) |
| 0xC0010010+ | All AMD-specific | Blocked (entire 0xC001xxxx range) |

### Analysis

The HV's MSRPM (MSR Permission Map) bitmap has intercept bits set for the entire 0xC0010000-0xC0011FFF range. The HV's VMEXIT handler for these MSRs does not inject #GP back to the guest — it terminates the VM outright. This is the same pattern seen with CR0.WP writes (HV intercepts and kills rather than allowing or emulating).

### EntrySign (CVE-2024-56161) Verdict

**Not viable from guest ring 0 on PS5 FW 4.03.** PATCH_LOADER (0xC0010020) cannot be read or written. Custom microcode loading is impossible from within the guest VM. EntrySign would require either:
1. HV-level access (to bypass MSRPM) — which is what we're trying to achieve
2. Physical access (SPI flash / voltage glitch during boot)

### Implications

- All MSR-based HV bypass approaches are dead from guest ring 0
- The accessible MSRs (EFER, STAR, LSTAR, etc.) are already known and provide no new attack surface
- WRMSR to LSTAR/STAR is also intercepted (confirmed by CR0.WP interception pattern — HV intercepts ALL security-relevant writes)
- Remaining software vectors: VMMCALL probing, IOMMU/GPU DMA, CR3 page table walk for MMIO discovery

---

## Phase 18: Byepervisor QA Flags Investigation

**Status: DEAD END**

### Research Summary

Investigated Byepervisor's QA flags approach (bug #2) as potential path to disable XOM on FW 4.03. The mechanism: set SL (System Level) debug flag in kdata → rest mode → HV reinitializes without resetting flag → NPT constructed without xotext bit → ktext becomes readable/writable.

### Why It Doesn't Work on 4.03

Both Byepervisor bugs were patched at FW 3.00 (confirmed in progress_session9.md):

1. **QA flags (bug #2)**: QA flags isolated from guest kernel. Guest can no longer read or write the SL debug flag. The flag may still exist in HV memory but is not in any guest-accessible memory region (kdata, kernel heap, DMAP).

2. **HV jump tables (bug #1)**: HV separated into own binary at FW 3.00. Hypercall vtable no longer in kernel .data segment.

### Flatz's Private HV Exploit (≤4.51)

psdevwiki lists an unnamed "Hypervisor bypass vulnerability (≤FW 4.51)" — this is flatz's private exploit, confirmed as different from Byepervisor. Key facts:
- NOT the QA flags approach
- Entry chain: PS4 savegame → kernel exploit → HV exploit → PSP dump
- Patched in FW 5.00
- No technical details published
- flatz won't release unless original discoverer goes first

### What Changed at FW 3.00 (HV Hardening)

- HV separated into its own binary
- QA flags isolated from guest kernel
- 3 new hypercalls added (potential attack surface):
  - VMCLOSURE_INVOCATION (0xe)
  - STARTUP_MP (0xf)
  - IOMMU-related hypercall(s)

### Netflix JB / Y2JB Context

Netflix-N-Hack and Y2JB (YouTube JailBreak) are userland entry points only — they provide JavaScript execution via MITM on the PS5's Netflix/YouTube apps. They chain into kernel exploits (UMTX UaF, Lapse) for kernel R/W. On FW 6.00+, GPU DMA is used to bypass kdata write protection (SMAP). Neither provides new HV bypass techniques — they use existing exploit chains.

### GPU DMA on PS5 (from psdevwiki)

- GPU DMA to kernel .data: proven technique (flatz, FW 6.00+)
- GPU DMA does NOT bypass XOM for ktext writes (IOMMU enforces same restrictions for writes)
- GPU DMA CAN write to kdata → used to trigger Byepervisor bug #2 on ≤2.70
- Unknown whether GPU DMA can READ ktext (IOMMU read permissions may differ from write)
- Implementations: Java (flatz BD-JB), Lua (Znullptr), WebKit (Specter)
- APIs: sceGnmSubmitCommandBuffers + sceGnmSubmitDone from libSceGnmDriverForNeoMode.sprx

### Remaining Software Attack Vectors (Post-QA-Flags)

| Vector | Effort | Chance | Notes |
|--------|--------|--------|-------|
| VMMCALL probing (3 new FW 3.00 hypercalls) | Low | Low-Medium | Bug in handler = HV access |
| GPU DMA ktext READ via IOMMU | Medium-High | 30-40% | IOMMU may not replicate NPT XOM for reads |
| CR3 page table walk → MMIO/IOMMU discovery | Low | 99% (info gathering) | Feeds into GPU DMA approach |
| Hardware (SPI, UART, glitching) | High | High | Bypasses software entirely |

---

## Phase 19: #DB Resume Test via DR Breakpoints (dr_db_resume_test)

**Status: COMPLETE — DRs do NOT survive rest mode (S3 power-off resets all CPU register state)**

### The Breakthrough: Why INT3 Fails and #DB Should Work

After exhaustive testing of INT3-based resume interception (v3 IST chain, v7 doreti_iret bounce, v9a CC bounce — all failed identically), the root cause was identified:

**INT3 (#BP, vector 3) is in the VMCB exception intercept bitmap.** Every INT3 triggers a mandatory VMEXIT regardless of guest IDT state. During the pre-HV resume window (when apic_ops[2] is called), the HV VMEXIT handlers are not yet initialized. So INT3 → VMEXIT → uninitialized handler → crash. This is a hardware-level interception that cannot be bypassed from the guest.

**#DB (vector 1) via DR hardware breakpoints is NOT in the VMCB intercept bitmap.** This is proven by kstuff: ps5-kstuff uses DR0-DR3 execution breakpoints to hook kernel functions, and these hooks work correctly — meaning #DB goes directly to the guest IDT without any VMEXIT. The HV never sees #DB events.

The key evidence that #DB is not intercepted:
- kstuff uses `mov %0, %%dr0` / `mov %0, %%dr7` to set execution breakpoints
- kstuff's #DB handler in IDT[1] fires and redirects execution during normal operation
- kstuff **persists through rest mode** — but this means its kdata/IDT hooks persist, NOT the DR registers themselves (see results below)

### Strategy: DR2 Execution Breakpoint on get_timer_freq

Set a hardware execution breakpoint (DR2) on the `get_timer_freq` function. During resume, `apic_ops[2]` is called (confirmed by flatz), which executes `get_timer_freq`. DR2 matches RIP → #DB fires → guest IDT[1] handler runs → bounces back via iretq. The CPU automatically sets the RF (Resume Flag) in the pushed RFLAGS, preventing DR2 from re-triggering on return.

### Implementation Iterations

#### v1: Replace IDT[1] + Set DR0 — INSTANT PANIC

First attempt: replaced IDT[1] with doreti_iret handler using IST5, set DR0=get_timer_freq, enabled DR7.

**Crash cause**: IDT is shared across ALL CPUs, but DR registers are per-CPU. kstuff has DR breakpoints active on all CPUs. Replacing IDT[1] with our simple doreti_iret caused kstuff's breakpoints on OTHER CPUs to fire into our handler. Multiple CPUs hitting the same IST5 stack (kdata+0x300) simultaneously = stack corruption = panic.

#### v2: Clear DR7 First — STILL INSTANT PANIC

Second attempt: clear DR7 before modifying IDT[1] to disable breakpoints.

**Crash cause**: `mov %0, %%dr7` only affects the CURRENT CPU. Other CPUs still have kstuff's DR breakpoints active. When we modified IDT[1] (global), other CPUs' #DB events went to our doreti_iret handler instead of kstuff's handler. Same cross-CPU race condition.

**Key learning**: Any modification to IDT[1] while kstuff is active on a multi-CPU system will crash. IDT modifications require either (a) disabling interrupts on ALL CPUs simultaneously (IPI + cli), or (b) not modifying IDT at all.

#### v3: Don't Touch IDT/TSS — Use DR2 + Preserve kstuff's DR7 (CURRENT)

Third attempt: completely different approach.

- **Do NOT modify IDT[1] or TSS** — let kstuff own the #DB handler
- **Use DR2** (not DR0/DR1 which kstuff uses) for our execution breakpoint
- **Preserve kstuff's DR7**: read current DR7, OR in DR2 enable bit, clear R/W2+LEN2 for execution BP
- kstuff's #DB handler sees unexpected DR2 match, has no registered hook for it, bounces back via iretq
- During resume: kstuff's handler is in ktext (executable), handles #DB correctly

**Proof mechanism**: If the system resumes successfully with DR2=get_timer_freq armed and apic_ops[2] calling get_timer_freq, then #DB MUST have fired and been handled. If #DB wasn't handled (no working IDT[1] handler), the system would triple-fault. System alive = proof.

### Payload Details (examples/dr_db_resume_test/)

**Size**: 960 bytes

**Mode 0x1 (ARM):**
1. Read kstuff's full DR state (DR0-DR3, DR7) — report in output
2. Set DR2 = get_timer_freq address
3. Build new DR7 = (kstuff's DR7 | L2 bit) with R/W2+LEN2 cleared for exec BP
4. Set apic_ops[2] = get_timer_freq
5. Write sentinel to kdata+0x200
6. Report IDT[1] state (kstuff's handler address + IST field) without modifying it

**Mode 0x2 (READBACK):**
1. Read all DR registers — check if DR2 and DR7 persisted through rest mode
2. Read sentinel — check kdata persistence
3. Read apic_ops[2] — check if still get_timer_freq
4. Report system_alive=1 (if readback runs, resume worked)
5. Restore: DR2 to kstuff's original, DR7 to kstuff's original, apic_ops[2] via set_tpr-8 trick

### v3 Results: DRs Do NOT Survive Rest Mode

v3 ARM completed successfully (status 0x0001). System entered rest mode and resumed. Readback results:

**ARM output (mode 0x1):**
| Slot | Field | Value |
|------|-------|-------|
| [0] | magic+status | `0x0000000144524442` (DRDB, success) |
| [1] | kdata_base | `0xffffffffcae20000` |
| [2] | ktext_base | `0xffffffffca220000` |
| [3] | get_timer_freq | `0xffffffffca4b4320` |
| [4] | original apic_ops[2] | `0xffffffffca4b4340` (xapic_mode) |
| [5] | apic_ops[2] set to | `0xffffffffca4b4320` (get_timer_freq ✓) |
| [6] | kstuff DR0 | `0x0` (not armed on this CPU) |
| [7] | kstuff DR1 | `0x0` (not armed on this CPU) |

**READBACK output (mode 0x2):**
| Slot | Field | Value | Meaning |
|------|-------|-------|---------|
| [0] | magic+status | `0x0000000144524442` | DRDB, success |
| [1] | kdata_base | `0xffffffffcae20000` | Same ✓ |
| [2] | ktext_base | `0xffffffffca220000` | Same ✓ |
| [3] | DR0 | `0x0` | Reset to zero |
| [4] | DR1 | `0x0` | Reset to zero |
| [5] | **DR2** | **`0x0`** | **RESET — was `0xffffffffca4b4320`** |
| [6] | DR3 | `0x0` | Reset to zero |
| [7] | **DR7** | **`0x0000000000000400`** | **Hardware default (GE bit only)** |

(Display truncated to first 8 entries; higher indices including sentinel and apic_ops[2] readback not shown in debug output.)

### Analysis: Why DRs Don't Survive

**DR0-DR3 are NOT part of the VMCB save area.** During S3 suspend, the CPU fully powers off. On resume, hardware reset clears all general-purpose and debug registers to zero. The HV then does VMRUN with a fresh (or restored) VMCB:

- **DR6, DR7**: Part of VMCB save area. HV initializes DR7 to `0x400` (hardware default: GE bit set, no breakpoints enabled). Our L2 bit is gone.
- **DR0-DR3**: Not in VMCB. CPU hardware reset clears them to zero. Our get_timer_freq address is gone.

**How kstuff actually persists**: kstuff's kdata modifications (IDT entries, sysent hooks, other memory-mapped state) survive rest mode because kdata is in RAM. After resume, when the guest kernel runs and hits one of kstuff's IDT/sysent hooks, kstuff re-arms its DR breakpoints from the hook handler. The DRs themselves are transient — kstuff rebuilds them on demand.

**Additional observation**: kstuff DR0/DR1 were ZERO during ARM mode too (slots [6]-[7]). This means kstuff either (a) doesn't use DRs on the CPU that ran our kproc, or (b) arms DRs lazily only when specific code paths trigger kstuff's IDT/sysent hooks.

### What This Rules Out

- **#DB via DR breakpoints during resume**: Cannot work. DRs are reset before the guest starts. No breakpoint is armed when apic_ops[2] fires.
- **Any CPU register-based persistence**: CR registers, DR registers, MSRs — all reset during S3. Only RAM-mapped state survives.

### What Still Works (Confirmed Persistent State)

| State | Survives Rest Mode | Evidence |
|-------|-------------------|----------|
| kdata writes | ✅ Yes | Confirmed across 10+ sessions (sentinels, markers) |
| IDT entries | ✅ Yes | idt_safe_test: IST field modification persisted |
| TSS entries | ✅ Yes | idt_safe_test: IST5 value persisted |
| apic_ops[2] override | ✅ Yes | Confirmed across 8+ sessions |
| DR0-DR3 | ❌ No | dr_db_resume_test v3: all reset to zero |
| DR7 | ❌ No | dr_db_resume_test v3: reset to 0x400 (default) |

### Revised Attack Surface for Pre-HV Resume Window

Since DRs don't survive, we cannot use #DB to intercept execution during resume. The available primitives are:

1. **apic_ops[2] → ktext function**: We control which ktext function runs during resume. It must return non-zero. We need to find a function that either (a) has a useful side effect, or (b) is a gadget that gives us more control.

2. **IDT + TSS persist**: We can set up custom interrupt handlers with IST stack switching. But we need a way to TRIGGER the interrupt during resume without DRs or INT3.

3. **kdata writes persist**: We can pre-write ROP chains, IRET frames, or any data structures to kdata before rest mode. The challenge is getting RIP to reach them (kdata is NX during resume).

4. **Stack pivot via apic_ops[2] epilogue**: If we find the right ktext function whose epilogue reads from a location we control (e.g., `pop rbp; ret` where RSP points to kdata we've written), we could redirect execution. This requires knowing RSP during the apic_ops[2] call — the suspend_stackprobe payload was designed for this.

---

## Phase 20: MP4 DECI5S Memory Access Analysis + IOMMU Architecture

**Status: IN PROGRESS — A53 cannot directly reach HV region; IOMMU reprogramming required**

### Background: Alternative Attack Vector via A53 Coprocessor

The PS5's Aeolia SoC contains an ARM Cortex-A53 coprocessor (the "MP4" or "MM controller") that runs its own firmware. During development/QA, the DECI5S debug protocol provides read/write access to memory through this coprocessor. The question: can the A53 reach system PA `0x70000000` (the HV region) via DECI5S PA reads?

### DECI5S Read Memory Handler (0x1112A4)

`deci5s_sdbgp_context_handle_read_memory_mp4` supports 4 read types based on `type & 0x7F000000`:

| Type | Name | Translation Function | Meaning |
|------|------|---------------------|---------|
| `0x02000000` | PA read | `pa_to_el3_va_with_flags` | A53 bus address (physical) |
| `0x40000000` | EL0 VA read | `el0_va_to_el3_va` | EL0 virtual address |
| `0x43000000` | EL3 VA read | `el3_va_to_el3_va` | EL3 virtual address |
| `0x48000000` | PA read (alt) | `pa_to_el3_va_with_flags` | Same as 0x02 |

The actual memory read is a raw pointer dereference — no filtering at the read site. Supports byte/word/dword/qword/128-bit access sizes based on `type & 0xF`.

### PA Translator: pa_to_el3_va_with_flags (0x10DED8)

```
if (pa <= 0xFFF)
    return pa | 0x4200000;     // Remap to SRAM base
else {
    va = pa;                   // Identity map — NO address filtering
    if (pa >= 0xC0000 && (pa & 0xFFFFFFFFFC000000) != 0x88000000)
        printf("not SRAM - try check VA==PA map");  // WARNING ONLY, not a block
}
// Then: AT S1E3R, va   (ARM address translation check at EL3)
// If EL3 MMU fault → return 0 (blocked)
// If PA mismatch → return 0
// Otherwise → return va (access allowed)
```

No address range filtering. The only gate is `AT S1E3R` — the EL3 MMU page table.

### EL3 MMU Page Table (from mmu_init_phase1)

4 × 1GB blocks (identity-mapped), then two regions unmapped:

| Address Range | Status |
|---------------|--------|
| `0x00000000-0x3FFFFFFF` | MAPPED (SRAM, MMIO, etc.) |
| `0x40000000-0x7FFFFFFF` | MAPPED ← includes `0x70000000` |
| `0x80000000-0xBFFFFFFF` | MAPPED (G6 SYSHUB at `0x88000000`) |
| `0xC0000000-0xC3FFFFFF` | UNMAPPED |
| `0xC4000000-0xCFFFFFFF` | MAPPED |
| `0xD0000000-0xEFFFFFFF` | UNMAPPED |
| `0xF0000000-0xFFFFFFFF` | MAPPED (IOMMU MMIO at `0xFDD88000`) |

**`0x70000000` passes the EL3 MMU check** — AT S1E3R succeeds.

### Exception Guard Wrapping the Read

The read is wrapped in setjmp/longjmp:

```
saved = sub_108104(jmpbuf);       // setjmp — saves qword_123180
if (sub_10813C(jmpbuf)) {         // Check if exception occurred
    printf("Exception in access %p", ptr);
    error = 1;                    // Mark failed, continue
} else {
    *dest = *ptr;                 // Actual read — raw dereference
}
sub_108144(jmpbuf, saved);        // Restore previous handler
```

### SYSHUB Violation — The Real Gatekeeper

From `el3_exception_dispatch`: when GIC interrupt 33 fires, it's a SYSHUB Violation:

```
case 33:  // GICC_IAR == 33
    printf("Error:SYSHUB Violation");
    printf("Error:mmMP4_SYSHUB_INT_STATUS=0x%08x", MEMORY[0x32305D0]);
    // Reads SYSHUB_RD_INT_ADDR or SYSHUB_WR_INT_ADDR for fault address
    // Checks qword_123180 (exception guard)
    if (qword_123180) {
        longjmp(qword_123180 + 8, 1);  // Returns to read handler
    }
```

This is what happens when accessing unmapped SYSHUB addresses like `0x70000000` — the SYSHUB fabric rejects the access, fires interrupt 33, the exception handler catches it via longjmp, and the read returns error 32 (access error). The firmware doesn't crash.

### A53 Memory Access Architecture

```
A53 VA → [EL3 MMU] → A53 bus addr → [SYSHUB TLB] → IOMMU addr → [IOMMU page table] → System PA
                                          ↓
                                     [BYPASS] entries skip IOMMU, go direct to system PA
```

### SYSHUB TLB Entries (from boot strings)

| Entry | Mode | Purpose |
|-------|------|---------|
| TLB10 | IOMMU | Kernel IOMMU VA space |
| TLB11 | IOMMU | Kernel IOMMU VA space |
| TLB12 | IOMMU | Kernel IOMMU VA space |
| TLB15 | BYPASS | Direct PA (SRAM/local) |
| TLB16 | BYPASS | Direct PA |
| TLB17 | BYPASS | Direct PA |

### What the A53 Can Actually Reach

| Region | System PA | Notes |
|--------|-----------|-------|
| SRAM | `0x00000000-0x000BFFFF` | Local |
| MMIO regs | `0x02000000-0x032A0000` | MP4 registers via SYSHUB |
| MSI window | `0xF6E00000` | x86 LAPIC, 2MB |
| DRAM (MM) | ~`0x18000000` | Small private window |
| DRAM (IO) | ~`0x1C000000` | Small private window |
| NVMe buffers | ~`0x14000000` | IO core, 50MB |
| G6 SYSHUB | `0x88000000-0x887FFFFF` | Firmware image, page tables, MDSR |
| IOMMU MMIO | `0xFDD88000` | IOMMU control registers |

### Result: 0x70000000 Read Path

**DECI5S PA read will NOT reach system PA `0x70000000`:**

1. `pa_to_el3_va_with_flags(0x70000000)` → passes (identity map, EL3 MMU OK)
2. A53 issues bus read to `0x70000000`
3. SYSHUB has no TLB entry for this range → **SYSHUB Violation (IRQ 33)**
4. Exception guard catches it → returns error 32

**The A53 does not have direct system DRAM access.** It sees the world through the SYSHUB TLB + IOMMU, which restricts it to specific mapped regions.

---

### IOMMU Architecture Deep Dive

#### Key IOMMU Parameters (from boot config)

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `mm4p_mapper_page_table_ioma` | `0x54000000` | IOMMU page table location |
| `mm4p_iommu_command_buffer_pa` | `0x01470000` | Command buffer in system memory |
| `mm4p_iommu_command_buffer_size` | `0x2000` | 8KB command buffer |
| `mm4p_iommu_mmio` (system PA) | `0xFDD88000` | IOMMU MMIO registers |
| `mm4p_iommu_mmio` (IOMMU addr) | `0x50E00000` | IOMMU MMIO via IOMMU translation |
| `m_sysvaKernelStart4K` | `0x50000` → IOMMU VA `0x50000000` | Kernel VA range start |
| `m_sysvaKernelEnd4K` | `0x4FFFFF` → IOMMU VA `0x4FFFFF000` | Kernel VA range end (wraps 4GB) |
| `m_pasidKernel` | `0x0001` | Kernel PASID |

#### How Existing Mappings Are Created

**g6_fix: IOMMU `0x50000000` → System PA `0x60000000` (8MB)**

Not set up through the command buffer. IOMMU page table entries are written directly to memory during EL3 boot:

1. EL3 boot code writes IOMMU page table entries at the page table base (system PA backing IOMMU VA `0x54000000`)
2. Each PTE maps a 4K page: IOMMU VA → System PA with permission bits
3. For g6_fix: PTEs map IOMMU VA `0x50000000-0x507FFFFF` → System PA `0x60000000-0x607FFFFF`
4. Then `INVALIDATE_IOTLB_PAGES` command sent to IOMMU to flush stale TLB entries

`MmController_init_iommu_page_tables` (0x64011A4) configures the runtime page table structure using boot config parameters.

#### IOMMU Command Buffer Format

`iommu_submit_invalidate_iotlb` (0x6442024) builds **256-bit (32-byte)** command entries:

```c
// 32-byte command entry (4 × qword)
struct iommu_cmd {
    uint64_t word0;  // bits[3:0]=type, bits[15:8]=queue_id, bits[63:32]=param
    uint64_t word1;  // extra data
    uint64_t word2;  // extra data
    uint64_t word3;  // extra data
};
```

Write to command buffer via `iommu_cmd_buffer_write_entry` (0x501BF20):
```c
dest = cmd_buf_base + (entry_index << entry_shift);
dest[0] = cmd->word0;
dest[1] = cmd->word1;
dest[2] = cmd->word2;
dest[3] = cmd->word3;
```

**Command type 4** = `INVALIDATE_IOTLB_PAGES` (called during MmController startup with DeviceID=0, all zeros — full flush).

**Note**: 32-byte entries, not 16-byte. Either AMD IOMMU v2 extension or Sony-custom format.

#### Can IOMMU Page Tables Be Modified via DECI5S?

**Yes, in principle:**

1. **Page tables are in IOMMU-addressable memory** — at IOMMU VA `0x54000000`. The A53 can read/write IOMMU addresses through the [IOMMU] SYSHUB TLB entries. The MM controller does exactly this during normal operation.

2. **DECI5S WRITE_MEMORY can reach the page tables** — the write_memory handler at 0x1116DC uses the same address translation as read_memory. If PA type routes through SYSHUB to IOMMU page table region, PTEs can be modified.

3. **Catch: need the A53 bus address** — the A53 bus address mapping to IOMMU VA `0x54000000` depends on SYSHUB TLB configuration. From EL0 page table maps: `MAP: 0x04001000+0x050000 → PA 0x48800000` (SYSHUB space, Device memory). Whether `0x48800000` covers the page table region depends on SYSHUB TLB translation.

#### Three Attack Options for IOMMU Reprogramming

**Option A: Direct page table modification via DECI5S**
1. Read IOMMU Device Table Entry to find page table root pointer
2. Walk IOMMU page table hierarchy to find the right PTE level
3. Write new PTE mapping: IOMMU VA X → System PA `0x70000000`
4. Send `INVALIDATE_IOTLB_PAGES` command via the command buffer
5. Read IOMMU VA X through DECI5S PA read (if SYSHUB TLB covers it)

**Option B: Inject ring buffer command to MM controller**
The MM controller processes map/unmap commands from 26 input ring buffers. Ring buffer base at IOMMU addr `0x50C00000` (from `mm4p_mm_rings_ioma`). Write a "map page" command into a ring buffer and trigger processing — creates IOMMU mapping through the normal code path.

**Option C: Use IOMMU MMIO directly**
IOMMU MMIO at system PA `0xFDD88000` (IOMMU addr `0x50E00000`). A53 can access through SYSHUB. IOMMU MMIO has registers for page table base, command buffer head/tail. Could potentially reconfigure IOMMU directly.

#### Key Unknowns ~~to Resolve~~ (RESOLVED — see Phase 20a below)

1. ~~**SYSHUB TLB dump**~~ → **RESOLVED**: TLB10 and TLB15 entries fully decoded from `deci5s_sdbgp_context_handle_test`
2. ~~**IOMMU page table format**~~ → Presumed standard AMD 4-level (to be confirmed by reading page table entries)
3. ~~**IOMMU page table system PA**~~ → Readable from IOMMU MMIO `DEV_TAB_BASE` at PA `0x28200000`

---

### Phase 20a: SYSHUB TLB Dump + Concrete IOMMU Exploitation Path

**Status: ANALYSIS COMPLETE — Ready for live verification**

#### SYSHUB TLB Configuration (from deci5s_sdbgp_context_handle_test at 0x1127A0)

The decompiled test function reveals the exact SYSHUB TLB entries. The firmware itself reads through both paths to verify IOMMU register access:

| Entry | Mode | A53 Bus Address | Translation | Destination |
|-------|------|----------------|-------------|-------------|
| TLB10 | IOMMU | `0x28000000+` | `bus_addr + 0x28C00000` | IOMMU VA `0x50C00000+` |
| TLB15 | BYPASS | `0x3C000000+` | `bus_addr + 0xC0000000` | Direct system PA |

**TLB10 [IOMMU]**: A53 bus address `0x28000000+` → IOMMU VA `0x50C00000+`
- Offset formula: `IOMMU_addr = bus_addr + 0x28C00000`
- Covers the MM controller's entire IOMMU working space (rings, page tables, IOMMU MMIO)

**TLB15 [BYPASS]**: A53 bus address `0x3C000000+` → system PA `bus_addr + 0xC0000000`
- Direct system PA access without IOMMU translation

**Both paths reach the IOMMU MMIO** (system PA `0xFDD88000`):
- Via IOMMU: DECI5S PA `0x28200000` → TLB10 → IOMMU `0x50E00000` → system PA `0xFDD88000`
- Via BYPASS: DECI5S PA `0x3DD88000` → TLB15 → system PA `0xFDD88000`

Confirmed by firmware: the test function reads `*(_DWORD *)0x28200018` and `*(_DWORD *)0x3DD88018` (IOMMU Control Register at offset 0x18) through both paths.

#### Concrete 5-Step Exploitation Path

**Step 1: Read IOMMU registers via DECI5S PA type 0x02**

| DECI5S PA | IOMMU Register | Purpose |
|-----------|---------------|---------|
| `0x28200000` | `DEV_TAB_BASE` | Device Table system PA + size |
| `0x28200008` | `CMD_BUF_BASE` | Should confirm PA `0x01470000` |
| `0x28200018` | `IOMMU_CTRL` | Verify IOMMU is enabled |
| `0x28200030` | `EXT_FEAT` | IOMMU capabilities |

**Step 2: Walk the IOMMU page table**

DECI5S PA `0x2B400000` → reads mapper page table root (IOMMU VA `0x54000000`). Walk the AMD IOMMU 4-level page table from here. Should see existing g6_fix mapping (IOMMU `0x50000000` → system PA `0x60000000`) and find unused PTE slots.

**Step 3: Modify a PTE via DECI5S WRITE_MEMORY**

Write a new PTE at an unused IOMMU VA mapping to system PA `0x70000000`. Standard AMD IOMMU PTE format:
```
bits[0]     = Present (1)
bits[1]     = Next Level / Page Size
bits[51:12] = System PA >> 12
bits[61:59] = Permission (read/write)
```

**Step 4: Invalidate IOTLB**

Write an `INVALIDATE_IOTLB_PAGES` command to the command buffer (via DECI5S write to command buffer area) and advance the tail pointer.

**Step 5: Read the HV region**

The new IOMMU VA now maps to system PA `0x70000000`. Access through TLB10 path by computing the corresponding A53 bus address:
```
bus_addr = IOMMU_VA - 0x28C00000
```

#### Key Caveat

The TLB10 offset formula (`bus + 0x28C00000 = IOMMU addr`) needs verification with live reads. Derivation from the test function's constants looks solid, but reading PA `0x28200018` first and confirming a valid IOMMU Control Register value would validate the formula before attempting writes.

#### Address Cheat Sheet

| What | DECI5S PA (type 0x02) | Via | Destination |
|------|----------------------|-----|-------------|
| IOMMU MMIO base | `0x28200000` | TLB10→IOMMU | System PA `0xFDD88000` |
| IOMMU MMIO base (alt) | `0x3DD88000` | TLB15→BYPASS | System PA `0xFDD88000` |
| Page table root | `0x2B400000` | TLB10→IOMMU | IOMMU VA `0x54000000` |
| MM ring buffers | `0x28000000` | TLB10→IOMMU | IOMMU VA `0x50C00000` |
| Command buffer | via `CMD_BUF_BASE` | Need to read register first | System PA `0x01470000` (expected) |

---

### Phase 20b: A53 ELF Deep Analysis — PTDMA Architecture Discovery

**Status: ANALYSIS COMPLETE — Revises exploitation model**

#### Key Discovery: PTDMA Engine, Not Direct IOMMU Commands

The A53 MM controller does NOT directly read/write IOMMU page tables. Instead, it programs a **PTDMA (Page Table DMA) engine** which has its own system memory DMA access independent of the SYSHUB TLB. The 32-byte ring buffer entries written by `sub_501A000` are PTDMA commands, not AMD IOMMU commands.

**Revised architecture:**
```
x86 kernel → ring buffer command → A53 MM controller (state machine)
    → PTDMA engine (MMIO at PA 0x3060000+)
        → DMA to system memory (page table modification)
        → IOMMU IOTLB invalidation (cmd buffer at system PA 0x01470000)
    → result back to x86 via output ring + MSI
```

#### MmController State Machine (sub_6401AF0)

| State | Action |
|-------|--------|
| 1 | Queue PTDMA map/unmap command via `sub_501A000` |
| 2 | Execute PTDMA via `sub_5022E48` (or `sub_6441080` with error handler) |
| 3 | Process PTDMA results, IOTLB invalidation |
| 4-5 | Completion, status polling |
| 6 | Full reset: clear PTDMA channels, clear SDMA, reinit MmController |

PTDMA command parameters (from state 1):
```c
sub_501A000(controller + 1048,        // PTDMA command ring
            0x20,                     // device ID
            pa | 0x1000000000000,     // source PA (flag bit 48 set)
            (boot_params + 88) & 0xFFFFF,  // page table offset
            pasid, 1, 1);            // PASID, queue, type
```

The AMD IOMMU command buffer (system PA `0x01470000`) is only used AFTER PTDMA completes, specifically for `INVALIDATE_IOTLB_PAGES` commands.

#### PTDMA Engine MMIO Map

| EL0 VA | Bus PA | Function |
|--------|--------|----------|
| `0x2060000` | `0x3060000` | PTDMA control/command |
| `0x20C0000+` | `0x30C0000+` | Per-channel PTDMA registers |
| `0x20C7000` | `0x30C7000` | PTDMA global status |
| `0x2001000` | `0x3001000` | PTDMA/SDMA status |
| `0x2290000` | `0x3290000` | SDMA registers |

#### EL3 Page Table Analysis

The L3 page table at VA `0x106000` has static entries in the ELF:
- `0x743` descriptor: AttrIndx=0 → MAIR[0]=0x00 → Device-nGnRnE, AP=RW, SH=Inner, AF
- `0x753` descriptor: AttrIndx=4 → MAIR[4]=0xFF → Normal WB, AP=RW, SH=Inner, AF
- First 8KB mapped as Device memory, remainder as Normal WB

**Critical finding**: EL3 `mmu_init_phase1` identity-maps the first GB with L2 block descriptors at runtime. Therefore **PA `0x2100000` (SMN base) IS mapped at EL3**. Memory attributes for the L2 blocks are runtime-generated and not in the static ELF, but SMN access is architecturally possible at EL3.

#### Boot Config — SMN/SYSHUB Offsets

| Field | Value | Meaning |
|-------|-------|---------|
| `m_offsetSmnIfSystemMmioIommu4K` | `0x00A` | IOMMU at SMN base + `0xA000` |
| `m_offsetSmnIfSystemMmioSdma4B` | `0x041343` | SDMA at SMN + `0x01104D0C` |
| `m_useSmnIfForSdma` | `0x1` | Use SMN interface for SDMA |
| `m_offsetSyshubIfSystemMmioMsi4K` | `0x87F00` | MSI window via SYSHUB |
| `m_offsetSyshubIf64K` | `0x1000` | Titania SYSHUB offset |
| `m_offsetSyshubIfSystemMmio4K` | `0x30200` | System MMIO via SYSHUB |
| `m_offsetSyshubIfDramPrivate4K` | `0x18000` | DRAM private region |
| `m_offsetSyshubIfDramPrivateReadOnly4K` | `0x00000` | DRAM private RO |
| `m_sysvaKernelStart4K` | `0x50000` | IOMMU VA `0x50000000` |
| `m_sysvaKernelEnd4K` | `0x4FFFFF` | IOMMU VA ~4GB |
| `m_sysvaRings` | `0x50C00000` | Ring buffers IOMMU VA |

#### Device Table

No string references to "DeviceTable", "DEV_TAB", or "DTE" in the ELF. The PS5's IOMMU likely uses one of:
- PTDMA engine embeds device table reference internally
- Single-device model (one page table root, no multi-device table)
- Custom Sony implementation that bypasses standard AMD device table walks

The device table address should still be readable from IOMMU MMIO register `DEV_TAB_BASE` at DECI5S PA `0x28200000`.

#### Revised Exploitation Strategy

The PTDMA discovery changes the attack surface. Three options remain viable:

**Option A: Read IOMMU state via TLB10/TLB15 (unchanged, still first step)**
- DECI5S PA `0x28200000+` reads IOMMU MMIO → get `DEV_TAB_BASE`, `CMD_BUF_BASE`, page table root
- Tells us WHERE page tables live in system memory
- Caveat: page table contents may be at system PAs the A53 can't reach via existing TLB entries

**Option B: Use PTDMA through DECI5S (new possibility)**
- PTDMA channel registers at bus PA `0x30C0000+`
- If EL3 maps these PAs (likely — within first GB identity map), DECI5S can program PTDMA
- Could submit PTDMA commands to create arbitrary page table entries
- Risk: PTDMA state machine is complex, wrong commands could corrupt active page tables

**Option C: Direct IOMMU command buffer manipulation (refined)**
- IOMMU command buffer at system PA `0x01470000`
- Need to determine which DECI5S path reaches this PA
- Write custom IOMMU commands (INVALIDATE_IOTLB or potentially MAP commands)
- Less risky than PTDMA but may have limited capability (IOTLB invalidation only, no mapping creation)

**Recommended first step (all options)**: Read IOMMU MMIO registers via DECI5S to get device table and page table root addresses. This is pure read, zero risk, and informs all three options.

---


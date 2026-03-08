# state_capture — Progress Log

## Goal
Capture CPU state (MSRs, CRs, descriptor tables, GPRs) across PS5 suspend/resume
to understand hypervisor behavior and kernel state management.

## Architecture
- Kernel code execution via kproc_create (prosper0gdb kstuff loader)
- Output via kthread_args readback (288 uint64 slots = 2304 bytes)
- Mode selected via fw_ver field override

## Version History

### v1-v4: All crashed (kernel panic)
- **Root cause 1**: Writing PCB buffer to `kdata_base + 0x400` corrupted live kernel
  variables in the .data segment (scheduler state, lock counts, etc.)
- **Root cause 2**: Calling `rdmsr_start` (ktext gadget) causes instant kernel panic
  regardless of buffer location. Likely hits a trapped instruction (sldt/str) or
  the gadget's control flow doesn't end cleanly in our context.
- These two issues were tangled together — fixing one wasn't enough.

### v5: First successful run (Mode 0x5 only)
- Added Mode 0x5: pure read-only kdata scanner, ZERO function calls, ZERO kdata writes
- Mode 0x5 ran successfully, proving the kdata write fix worked
- Mode 0x4 (calling rdmsr_start) still crashed — confirmed the call itself is unsafe
- Mode 0x5 found 0 PCBs: thread PCBs are heap-allocated, not in kdata

### v5.1: Full CPU state capture working
- **Key insight**: We can read ALL MSRs directly via inline `rdmsr` instruction.
  No need to call any kernel function. Already proved rdmsr(LSTAR) works in v5.
- Removed all modes that call kernel functions (0x4, 0x2, 0x3)
- Mode 0x5 now captures everything directly:
  - 8 MSRs: LSTAR, EFER, STAR, CSTAR, SFMASK, FSBASE, GSBASE, KGSBASE
  - 3 CRs: CR0, CR3, CR4
  - GDT/IDT base + limit via sgdt/sidt
  - curthread + td_pcb dump (64 qwords = 0x200 bytes)
  - kdata scan for LSTAR/CR3 values (susppcbs discovery)
  - Heap pointer scan (broadened to all canonical kernel pointers)
- Mode 0x6: curthread struct dump (128 qwords) + td_pcb (64 qwords)
- **Lesson**: td_pcb sits at top of kernel stack page; reading >0x200 bytes past
  it hits a guard page and panics. Deep dumps must use curthread struct instead.

## Confirmed Data

### Boot Session 1 (earlier session)

#### KASLR Layout
```
ktext_base = 0xffffffff8a720000
kdata_base = 0xffffffff8b320000
```

#### Key Values
- LSTAR = 0xffffffff8a9b4218 (ktext + 0x294218)
- CR3 = 0x11a54000
- td_pcb addresses observed: 0xffffff80a924fa40, 0xffffff809fe8ba40

---

### Boot Session 2 (current session — Option D + Option C runs)

#### KASLR Layout
```
ktext_base = 0xffffffffdf9a0000
kdata_base = 0xffffffffe05a0000
KASLR offset from session 1: +0x55280000 (~1.3 GB)
```

#### MSR Values
| MSR | Value | Notes |
|-----|-------|-------|
| LSTAR | 0xffffffffdfc34218 | ktext + 0x294218 (syscall entry, offset IDENTICAL) |
| EFER | 0x11d01 | SCE\|LME\|LMA\|NXE\|FFXSR |
| STAR | 0x0033002000000000 | user CS=0x33, kernel CS=0x20 |
| CSTAR | 0xffffffffdfc34460 | compat syscall entry |
| SFMASK | 0x4701 | RFLAGS mask on syscall |
| FSBASE | varies per thread | thread-local storage |
| GSBASE | 0xffffffffe6a72b80 | per-CPU data (kdata-relative) |
| KGSBASE | 0 | zero in kernel context |

#### Control Registers
| Register | Value | Notes |
|----------|-------|-------|
| CR0 | 0x8005003b | PG\|WP\|NE\|ET\|TS\|MP\|PE |
| CR3 | 0x26cd4000 | physical page table base (different from session 1) |
| CR4 | 0x340ee0 | SMEP\|SMAP\|PCIDE\|FSGSBASE\|PGE\|PAE\|MCE\|DE |

#### Descriptor Tables
| Register | Value | Notes |
|----------|-------|-------|
| GDT base | 0xffffffffe6a6ee98 | per-CPU (in kdata range) |
| GDT limit | 0x67 | 13 entries |
| IDT base | 0xffffffffe6a6dc80 | shared across CPUs |
| IDT limit | 0xfff | 256 entries |

#### Thread Observations
| Run | curthread | td_pcb |
|-----|-----------|--------|
| Mode 0x5 pre-suspend | 0xffffdd172f195380 | 0xffffff809fcf3a40 |
| Mode 0x6 pre-suspend | 0xffffdd1752366700 | 0xffffff80a0987a40 |
| Mode 0x5 post-resume | 0xffffdd1752366d80 | 0xffffff80a133fa40 |

**Key observation**: curthread lives in 0xffffdd17... range (kernel malloc heap).
td_pcb lives in 0xffffff80... range (a different kernel memory region). Each kproc
invocation gets a fresh thread + PCB.

### Suspend/Resume Delta (Session 2)
**Identical across rest mode**: kdata_base, ktext_base, LSTAR, EFER, STAR, CSTAR,
SFMASK, CR0, CR3, CR4, GDT limit, IDT base+limit, GSBASE

**Different (expected — different thread/core)**: FSBASE, curthread, td_pcb, GDT base

**Conclusion**: Full kernel state survives rest mode. No KASLR re-randomization.
Capabilities persist across suspend/resume.

### td_pcb Layout (FreeBSD amd64 struct pcb)
```
+0x00 pcb_r15 = 0xffffffffe09cce00  (kdata address — consistent across runs)
+0x08 pcb_r14 = 0x0b / 0x0f         (small integer, varies)
+0x10 pcb_r13 = 0xffffdd17...       (heap pointer, varies)
+0x18 pcb_r12 = 0xffffff80...       (kernel memory, varies)
+0x20 pcb_rbp = 0                   (kproc leaf frame)
+0x28 pcb_rsp = 0xffffff80...       (kernel stack, near td_pcb)
+0x30 pcb_rbx = 0xffffff80...       (callee-saved, varies)
+0x38 pcb_rip = 0xffffffffdfc34538  (ktext, LSTAR + 0x320 — CONSISTENT)
+0x40..+0x1FF  ALL ZEROS            (CRs/MSRs not saved for running thread)
```

**Critical insight**: pcb_cr3 and other CR fields (somewhere in +0x40..+0x1FF) are
ALL ZERO for a running thread. They're only populated by `savectx()` during suspend.
This means: after resume, only susppcbs PCBs will have non-zero CR values. Scanning
the heap for CR3 = 0x26cd4000 would find ONLY the suspend-saved PCBs.

### curthread Struct (Mode 0x6 dump, 0x400 bytes)
Non-zero fields observed:
```
+0x00: 0xffffffffe3234c28  (kdata ptr — td_lock or td_proc?)
+0x08: 0xffffdd1754669920  (heap ptr)
+0x18: 0xffffdd1754669930  (heap ptr, +0x10 from above)
+0x28: 0xffffffffe3231008  (kdata ptr)
+0x50: 0xffffdd1742834d00  (heap ptr)
+0x58: 0xffffdd1701292788  (heap ptr)
+0x60: 0xffffdd17015a0b90  (heap ptr)
+0x70: 0xffffdd174c0a8400  (heap ptr)
+0x78: 0xffffdd170040ce40  (heap ptr)
+0x88: 0xffffdd174afa9200  (heap ptr)
+0x98: 0x000188f1ffffffff  (flags/bitmap)
+0xc8: 0xffffdd17523667c0  (close to curthread itself — likely td_link)
+0xd0: 0xffffdd1754669920  (same as +0x08 — cross-reference)
+0xd8: 0x0000000000000001
+0xe0: 0x00000004000003ff  (flags)
+0xe8: 0x2020000000000000  (padding or string?)
+0x1a0: 0xffffdd1701274c00 (heap ptr)
+0x1a8: 0xffffdd1701294a00 (heap ptr)
```
Most of the struct is zero; kernel threads have minimal state compared to user threads.

## Scan Results Summary

### Option D: kdata Heap Pointer Scan
| Filter | Result |
|--------|--------|
| `(val >> 32) == 0xffffff80` (v1) | **0 hits** |
| Broadened: any canonical kernel ptr not in kdata/ktext (v2) | **0 hits** |
| LSTAR exact match | **0 hits** (both pre and post resume) |
| CR3 exact match | **0 hits** (both pre and post resume) |

**Conclusion**: The 112MB kdata scan range contains ZERO heap pointers and ZERO
LSTAR/CR3 values. This means:
1. `susppcbs` is NOT a simple kdata BSS global (or its pointer is accessed via
   GSBASE per-CPU indirection)
2. The kdata range is mostly demand-zero pages with no interesting globals
3. The kdata scan approach is a **dead end** for finding susppcbs

### Option C: curthread + td_pcb Dump
- Mode 0x6 ran successfully
- curthread is a ~0x400 byte slab allocation at 0xffffdd17...
- Contains mostly heap pointers in the 0xffffdd17 range
- td_pcb confirmed at +0x3F8 offset from curthread (TD_PCB = 0x3f8)
- PCB fields after GPRs are all zero for running threads

## What We've Achieved
1. Stable kernel code execution (no more panics)
2. Direct MSR/CR/descriptor table reads from kproc context
3. Full CPU state snapshot pre- and post-suspend
4. Confirmed PCB layout matches standard FreeBSD amd64
5. Confirmed all global CPU state survives suspend/resume unchanged
6. Confirmed kdata scan does NOT contain susppcbs or heap pointers
7. Confirmed two distinct kernel memory ranges: 0xffffdd17 (malloc heap) and 0xffffff80 (PCB/stack area)
8. Confirmed PCB CR fields are zero for running threads (only populated by savectx)

## Open Questions
1. Where is `susppcbs` allocated? Not in kdata. Possibly per-CPU (GSBASE-relative) or accessed through a function pointer table.
2. Can we read AMD-specific MSRs? (SYSCFG, TOP_MEM, VM_CR — HV might block with #GP)
3. Can we safely read debug registers (DR0-DR7)?
4. What is the exact pcb_cr3 offset within struct pcb? (somewhere in +0x40..+0x1FF)

## Next Steps — Recommended

### Option A: Heap scan for CR3 after resume (HIGH VALUE)
Since PCB CR fields are zero for running threads, scanning the heap for
CR3 = 0x26cd4000 would find ONLY the suspend-saved PCBs (susppcbs entries).
Scan a 128-256MB range centered on known td_pcb addresses in the 0xffffff80 region.
**Risk**: heap has unmapped holes — could crash on guard pages.
**Mitigation**: scan in small page-aligned chunks, accept that some regions may fault.

### Option B: Read AMD-specific MSRs (MEDIUM VALUE)
Try SYSCFG, TOP_MEM, TOP_MEM2, VM_CR, VM_HSAVE_PA to reveal HV config.
**Risk**: #GP on trapped MSRs causes panic.
**Mitigation**: test one MSR per run, starting with least-likely-to-trap.

### Option E: GSBASE per-CPU structure exploration
Read the per-CPU data structure starting at GSBASE. In FreeBSD, per-CPU data
contains pointers to many kernel structures including potentially susppcbs.
Dump 0x400+ bytes from GSBASE to map out the per-CPU layout.
**Risk**: low — GSBASE points to mapped kernel data, proven readable.

### Option F: Walk curthread pointer chains
Follow curthread → td_proc → process struct → thread list to enumerate all
kernel threads and their PCBs. This gives us a complete picture of the kernel's
thread state without needing to find susppcbs directly.
**Risk**: each pointer dereference could hit unmapped memory.
**Mitigation**: validate pointers are in known-good ranges before dereferencing.

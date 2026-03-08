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
- Mode 0x6: curthread struct dump (128 qwords) + td_pcb (64 qwords)
- **Lesson**: td_pcb sits at top of kernel stack page; reading >0x200 bytes past
  it hits a guard page and panics. Deep dumps must use curthread struct instead.

## Confirmed Data (Two successful Mode 0x5 runs: pre-suspend + post-resume)

### KASLR Layout (this boot)
```
ktext_base = 0xffffffff8a720000
kdata_base = 0xffffffff8b320000
ktext size = 0xC00000 (12 MB)
```

### MSR Values
| MSR | Value | Notes |
|-----|-------|-------|
| LSTAR | 0xffffffff8a9b4218 | ktext + 0x294218 (syscall entry) |
| EFER | 0x11d01 | SCE\|LME\|LMA\|NXE\|FFXSR |
| STAR | 0x0033002000000000 | user CS=0x33, kernel CS=0x20 |
| CSTAR | 0xffffffff8a9b4460 | compat syscall entry |
| SFMASK | 0x4701 | RFLAGS mask on syscall |
| FSBASE | 0x00000008ff800080 | thread-local (changes per kproc) |
| GSBASE | 0xffffffff917f5880 | per-CPU data (changes per core) |
| KGSBASE | 0 | kernel GS base (swapped on syscall) |

### Control Registers
| Register | Value | Notes |
|----------|-------|-------|
| CR0 | 0x8005003b | PG\|WP\|NE\|ET\|TS\|MP\|PE |
| CR3 | 0x11a54000 | physical page table base |
| CR4 | 0x340ee0 | SMEP\|SMAP\|PCIDE\|FSGSBASE\|PGE\|PAE\|MCE\|DE |

### Descriptor Tables
| Register | Pre-suspend | Post-resume | Notes |
|----------|-------------|-------------|-------|
| GDT base | 0xffffffff917ef0a0 | 0xffffffff917ef448 | per-CPU (different core) |
| GDT limit | 0x67 | 0x67 | 13 entries |
| IDT base | 0xffffffff917edc80 | 0xffffffff917edc80 | shared across CPUs |
| IDT limit | 0xfff | 0xfff | 256 entries |

### Suspend/Resume Delta
**Unchanged** (global state): LSTAR, EFER, STAR, CSTAR, SFMASK, CR0, CR3, CR4, IDT
**Changed** (per-CPU/per-thread): FSBASE, GSBASE, GDT base, curthread, td_pcb

Interpretation: All global CPU state is restored identically after resume. The
per-CPU differences (GSBASE, GDT) indicate the kproc ran on a different core
post-resume. The per-thread differences (FSBASE, curthread) are because each
run creates a new kproc instance.

### td_pcb Layout (confirmed standard FreeBSD)
```
+0x00 R15 = 0xffffffff8b74ce00  (kdata address)
+0x08 R14 = 0x0d
+0x10 R13 = 0xffff96a4012bc000  (heap pointer)
+0x18 R12 = 0xffffff8011fa0000  (kernel stack area)
+0x20 RBP = 0                   (kproc leaf frame)
+0x28 RSP = 0xffffff80a924f928  (kernel stack)
+0x30 RBX = 0xffffff801ff6c000
+0x38 RIP = 0xffffffff8a9b4538  (ktext, LSTAR + 0x320)
```

### kdata Scan Results
- LSTAR hits in kdata: **0** (pre and post-resume)
- CR3 hits in kdata: **0** (pre and post-resume)
- Scan range: 112 MB from kdata_base

**Why zero hits**: Thread PCBs are heap-allocated (`0xffffff80...` range), not in
kdata. `susppcbs` is also likely heap-allocated (malloc'd during boot in
`cpu_mp.c`), so it's not in the `.data`/`.bss` segment either.

## What We've Achieved
1. Stable kernel code execution (no more panics)
2. Direct MSR/CR/descriptor table reads from kproc context
3. Full CPU state snapshot pre- and post-suspend
4. Confirmed PCB layout matches standard FreeBSD
5. Confirmed all global CPU state survives suspend/resume unchanged
6. Confirmed kdata scan range doesn't contain PCBs or susppcbs

## Open Questions
1. Where is `susppcbs` allocated? (heap address unknown, not in kdata)
2. Can we read AMD-specific MSRs? (SYSCFG, TOP_MEM, VM_CR — HV might block)
3. What does the curthread struct layout look like? (Mode 0x6 ready to test)
4. Can we safely read debug registers (DR0-DR7)?

## Next Steps — Options

### Option A: Scan heap for susppcbs
Scan the `0xffffff80...` heap range for LSTAR value after resume. This would
find the actual susppcbs PCBs containing GPR state at the point of suspend.
**Risk**: heap has unmapped holes — could crash without pcb_onfault.
**Mitigation**: scan small regions around known-good addresses (td_pcb vicinity),
or walk pointer chains from curthread.

### Option B: Read AMD-specific MSRs
Try reading SYSCFG (0xC0010010), TOP_MEM (0xC001001A), TOP_MEM2 (0xC001001D),
VM_CR (0xC0010114), VM_HSAVE_PA (0xC0010117). These reveal hypervisor config
and memory topology. Some may be blocked by the HV (#GP on rdmsr).
**Risk**: #GP causes panic without fault handler. Could test one at a time.
**Mitigation**: start with least-likely-to-trap MSRs (SYSCFG, TOP_MEM).

### Option C: Dump curthread struct (Mode 0x6)
Run the fixed Mode 0x6 to dump 0x400 bytes of curthread struct. This reveals
thread struct layout, td_proc pointer (leads to process info), thread list
pointers (enumerate all threads), and other kernel internals.
**Risk**: minimal — curthread is a large slab allocation, 0x400 bytes is safe.

### Option D: Direct susppcbs discovery via kdata pointer scan
Instead of scanning heap for values, scan kdata for POINTERS into the heap
range (`0xffffff80...`). The `susppcbs` global variable is a pointer stored
in kdata BSS that points to heap memory. Finding it gives us the exact address.
**Risk**: low — read-only kdata scan, already proven safe.
**Approach**: scan kdata for any value in range `0xffffff8000000000..0xffffff80ffffffff`,
filter for page-aligned values (PCB arrays are page-aligned allocations).

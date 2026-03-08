# state_capture — Progress Log

## Goal
Capture CPU state (MSRs, CRs, descriptor tables, GPRs) across PS5 suspend/resume
to understand hypervisor behavior and kernel state management.

## Architecture
- Kernel code execution via kproc_create (prosper0gdb kstuff loader)
- Output via kthread_args readback — **hard limit: 64 qwords (0x200 bytes)**
- Mode selected via fw_ver field override
- Binary: `examples/state_capture/state_capture.bin`

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
- Mode 0x5 captures everything directly via inline asm
- Mode 0x6: curthread struct dump + td_pcb dump
- **Lesson**: td_pcb sits at top of kernel stack page; reading >0x200 bytes past
  it hits a guard page and panics. Deep dumps must use curthread struct instead.

### v5.1 Option D+C: kdata scan + curthread dump (Session 2)
- Added heap pointer scan to kdata loop (both narrow 0xffffff80 and broadened canonical filter)
- Both found ZERO hits — kdata contains no heap pointers or LSTAR/CR3 values
- Mode 0x6 curthread dump successful — mapped thread struct layout

### v5.1 Option E: GSBASE per-CPU dump (Session 3)
- Replaced dead kdata scan with per-CPU structure dump
- Discovered debug readback limit: exactly 64 qwords (0x200 bytes)
- Repacked layout: 8 header slots + 56 per-CPU data slots
- Successfully mapped struct pcpu layout

### v6: Complete CPU State Snapshot (Session 4)
- Added inline reads for CR0, CR2, CR4, EFER, STAR, CSTAR, SFMASK, FSBASE,
  KGSBASE, XCR0 (xgetbv), DR0-DR7, GDT base/limit, IDT base/limit
- AMD MSRs (SYSCFG, TOP_MEM, TOP_MEM2, VM_CR, VM_HSAVE_PA) caused instant
  kernel panic (#GP trapped by hypervisor) — disabled in second run
- All standard registers captured successfully in second run
- **Key finding**: SVME=1 in EFER — SVM/AMD-V is enabled, kernel runs under hypervisor
- **Key finding**: No hardware breakpoints (DR0-3=0, DR7=default) — HV not using debug regs
- **Key finding**: XCR0=7 — x87+SSE+AVX available, no AVX-512

### v7: kdata Heap Pointer Scanner (Session 4, continued)
- Mode 0x7: scan kdata for 0xffffff80 pointers (find susppcbs)
- v7.0 hit -Os compiler bug: volatile locals corrupted, counters showed garbage
- v7.1 fix: use output buffer directly as counters
- v7.1 page 0: scanner works, 0 hits in first 4MB (genuine — no 0xffffff80 ptrs)
- v7.1 page 0x193 (GSBASE area): kernel panic — **GSBASE/GDT/IDT are NOT in kdata**
- **Key finding**: kdata segment is ~8-15MB, not 100+MB. Per-CPU structs, GDT, IDT
  are in separately-allocated kernel virtual address space.

## Confirmed Data

### Constants Across All Sessions
| Field | Value | Notes |
|-------|-------|-------|
| LSTAR offset | ktext + 0x294218 | Syscall entry, identical across boots |
| pcb_rip | ktext + 0x25E538 | Context switch return, consistent |
| EFER | 0x11d01 | TCE\|SVME\|NXE\|LMA\|LME\|SCE |
| STAR | 0x0033002000000000 | user CS=0x33, kernel CS=0x20 |
| SFMASK | 0x4701 | RFLAGS mask on syscall |
| CR0 | 0x8005003b | PG\|WP\|NE\|ET\|TS\|MP\|PE |
| CR4 | 0x340ee0 | SMEP\|SMAP\|PCIDE\|FSGSBASE\|PGE\|PAE\|MCE\|DE |
| GDT limit | 0x67 | 13 entries |
| IDT limit | 0xfff | 256 entries |
| KGSBASE | 0 | Always zero in kernel context |
| TD_PCB offset | 0x3F8 | curthread → td_pcb |

### Boot Session 1
```
ktext_base = 0xffffffff8a720000
kdata_base = 0xffffffff8b320000
CR3        = 0x11a54000
```

### Boot Session 2 (Option D + C)
```
ktext_base = 0xffffffffdf9a0000
kdata_base = 0xffffffffe05a0000
CR3        = 0x26cd4000
GSBASE     = 0xffffffffe6a72b80
```
- curthread range: 0xffffdd17...
- td_pcb range: 0xffffff80...

### Boot Session 3 (Option E)
```
ktext_base = 0xffffffff99960000
kdata_base = 0xffffffff9a560000
CR3        = 0x20c94000
GSBASE     = 0xffffffffa0a33480 (CPU 2)
             0xffffffffa0a32b80 (CPU observed in prior run, = GSBASE - 0x900)
```
- curthread range: 0xfffff073...
- td_pcb range: 0xffffff80...

### Boot Session 4 (v6 — current)
```
ktext_base = 0xffffffff96dd0000
kdata_base = 0xffffffff979d0000
CR3        = 0x000000001e104000
GSBASE     = 0xffffffff9dea2b80 (CPU 1)
GDT_base   = 0xffffffff9de9ee98
IDT_base   = 0xffffffff9de9dc80
curthread  = 0xffff97294e380d00
td_pcb     = 0xffffff80a3d37a40
```

#### v6 Full CPU State Decode
```
CR0  = 0x8005003b     PG|AM|WP|NE|ET|TS|MP|PE
CR2  = 0x221960000    last page fault (userspace addr)
CR4  = 0x340ee0       SMAP|SMEP|OSXSAVE|UMIP|OSXMMEXCPT|OSFXSR|PGE|MCE|PAE
EFER = 0x11d01        TCE|SVME|NXE|LMA|LME|SCE  *** SVME=1 ***
STAR = 0x33002000..   sysret CS=0x33, syscall CS=0x20
CSTAR= ktext+0x294460 compat mode syscall handler
SFMASK=0x4701         masks NT|DF|IF|TF|CF
FSBASE=0x8ff834080    userspace TLS
KGSBASE=0             always zero in kernel context
XCR0 = 0x7            x87|SSE|AVX
DR0-3= 0              no hardware breakpoints
DR6  = 0xffff4ff0     default/reset
DR7  = 0x400          default — no active watchpoints
GDT  = 0x9de9ee98/0x67   13 entries
IDT  = 0x9de9dc80/0xfff  256 entries
```

### Suspend/Resume Delta (Session 2, confirmed)
**Identical across rest mode**: kdata_base, ktext_base, LSTAR, EFER, STAR, CSTAR,
SFMASK, CR0, CR3, CR4, GDT limit, IDT base+limit, GSBASE

**Different (expected — different thread/core)**: FSBASE, curthread, td_pcb, GDT base

**Conclusion**: Full kernel state survives rest mode. No KASLR re-randomization.

---

## Kernel Memory Map

### Address Ranges (observed across 4 boot sessions)
| Range | Purpose | Example |
|-------|---------|---------|
| `0xffffffff8...`-`0xffffffff9...` | ktext + kdata (KASLR, ~8-15MB each) | ktext_base, kdata_base |
| `0xffffffff9d...`-`0xffffffffa...` | Per-CPU / descriptor tables (separate alloc) | GSBASE, GDT, IDT |
| `0xfffff073...` / `0xffffdd17...` | Kernel malloc heap (threads) | curthread, pc_idlethread |
| `0xffffff80...` | Kernel memory (PCBs, stacks) | td_pcb, pcb_rsp |
| `0x00000008ff...` | User-space TLS (FSBASE) | Thread-local storage |
| `0x00000000_2XXXXXXX` | Physical addresses (CR3) | Page table base |

**CRITICAL CONSTRAINT**: ktext is **execute-only memory (XOM)**. We can execute
code from ktext (inline asm, function calls) but CANNOT read ktext bytes. This
means we cannot disassemble kernel functions or scan ktext for instruction patterns.

Note: The heap thread range changed between sessions (0xffffdd17 → 0xfffff073),
but td_pcb is always in 0xffffff80.

### struct pcpu Layout (FreeBSD per-CPU, at GSBASE)
```
+0x00  pc_curthread     (thread *)     — current thread on this CPU
+0x08  pc_idlethread    (thread *)     — idle thread for this CPU
+0x10  pc_fpcurthread   (thread *)     — FPU owner (usually null)
+0x18  pc_deadthread    (thread *)     — dead thread (null)
+0x20  pc_curpcb        (pcb *)        — current PCB (= td_pcb)
+0x28  pc_switchtime    (uint64)       — TSC at last context switch
+0x30  lo32: pc_switchticks            — tick count at last switch
+0x34  hi32: pc_cpuid                  — CPU number (observed: 2)
+0x38  ptr to GSBASE+0x900            — next CPU's pcpu or pc_dynamic
+0x40  (zero)
+0x48  stats/counters                  — struct vmmeter begins here
+0x50  stats
+0x58  stats (packed hi32/lo32)
+0x60  stats
+0x68  small counter (44)
+0x70  counter (82338)
+0x78  packed counters
+0x80  packed counters
+0x88..+0xB0  more counters
+0xB8..+0x1B8  all zeros
```
- Per-CPU stride: **0x900 bytes** (2304 = 288 qwords, same as output buffer size)
- No susppcbs pointer in per-CPU structure

### struct pcb Layout (FreeBSD amd64 PCB, at td_pcb)
```
+0x00  pcb_r15          — callee-saved (kdata addr, consistent)
+0x08  pcb_r14          — callee-saved (small int, varies)
+0x10  pcb_r13          — callee-saved (heap ptr, varies)
+0x18  pcb_r12          — callee-saved (kernel mem, varies)
+0x20  pcb_rbp          — frame pointer (0 for kproc)
+0x28  pcb_rsp          — stack pointer (near td_pcb)
+0x30  pcb_rbx          — callee-saved (varies)
+0x38  pcb_rip          — return address (ktext, consistent)
+0x40..+0x1FF  ALL ZEROS for running threads
               (CRs/MSRs only populated by savectx during suspend)
```
- td_pcb sits at TOP of kernel stack page
- Reading >0x200 bytes past td_pcb → guard page → panic
- PCB total safe read: 0x200 bytes (64 qwords)

### curthread Struct (from Mode 0x6 dump, Session 2)
```
+0x00   kdata ptr (td_lock or td_proc)
+0x08   heap ptr (td_sleepqueue?)
+0x18   heap ptr (+0x10 from above)
+0x28   kdata ptr
+0x50   heap ptr
+0x58   heap ptr
+0x60   heap ptr
+0x70   heap ptr
+0x78   heap ptr
+0x88   heap ptr
+0x98   flags/bitmap
+0xc8   self-relative ptr (td_link?)
+0xd0   heap ptr (same as +0x08)
+0xd8   1
+0xe0   flags (0x4000003ff)
+0xe8   string/padding
+0x1a0  heap ptr
+0x1a8  heap ptr
+0x3f8  td_pcb (TD_PCB offset, confirmed)
```

---

## Approaches Tried and Results

### kdata Scan for LSTAR/CR3/Heap Pointers — DEAD END
- Scanned 112MB from kdata_base, 4 runs across 2 sessions
- Found ZERO LSTAR hits, ZERO CR3 hits, ZERO heap pointers
- Both narrow (0xffffff80) and broad (any canonical non-kdata/ktext) filters
- **Anomaly**: scan should have found per-CPU heap pointers (curthread etc.)
  within the kdata range at GSBASE, but reported zero. Possible compiler
  optimization bug with -Os, or the filter logic was optimized away.
- **Conclusion**: kdata scan is unreliable and not productive

### GSBASE Per-CPU Dump — COMPLETED
- Successfully mapped first 0x1C0 bytes of struct pcpu
- Confirmed first 5 fields match stock FreeBSD layout
- Identified pc_cpuid at +0x34
- Per-CPU stride = 0x900 bytes
- **No susppcbs pointer found** — per-CPU struct contains thread/PCB pointers
  and stats counters only (in the first 0x1C0 bytes)

### curthread + td_pcb Dumps — COMPLETED
- Both structures mapped
- PCB CR fields zero for running threads (key insight for heap scanning)
- curthread is ~0x400 bytes, mostly heap pointers in 0xfffff073/0xffffdd17 range

### v7 kdata Heap Pointer Scanner — IN PROGRESS (Session 4)
**Goal**: Find 0xffffff80 pointers in kdata to locate susppcbs.
Rebuilt scanner with counters stored directly in output buffer (volatile locals
corrupted by -Os in v7.0).

**v7.0**: Counter corruption — hit_count showed 0xffffff800c824371 (a heap pointer
value, not a count). Root cause: -Os reuses registers for volatile locals.

**v7.1 page 0** (kdata + 0x00 to +0x400000): 0 hits, total_scanned=0x80000 ✓
- Scanner working correctly. First 4MB of kdata has no 0xffffff80 pointers.

**v7.1 page 0x193** (GSBASE area, kdata + 0x64C00000): **KERNEL PANIC**
- **Critical discovery**: GSBASE, GDT, and IDT are NOT in the kdata segment.
  They are in separately-allocated kernel virtual address space (per-CPU memory,
  descriptor table allocations). The kdata segment is much smaller than 101MB.
- This also explains why the v5.1 "112MB scan" found zero hits — it was scanning
  unmapped memory, but the broken compiler output meant it never actually read
  those addresses, so it didn't crash.
- **kdata actual size**: Unknown, but likely 8-15MB. Pages 1-3 should be safe.

**Key insight**: The GSBASE "self-test" was invalid — pc_curpcb IS 0xffffff80,
but it's NOT in kdata. The scanner works correctly; kdata genuinely has
zero 0xffffff80 pointers in the first 4MB.

---

## What We've Achieved
1. Stable kernel code execution — no panics since v5
2. Direct MSR/CR/descriptor table reads from kproc context (inline asm)
3. Full CPU state snapshot across 4 boot sessions
4. Confirmed state survives suspend/resume unchanged (no KASLR re-randomization)
5. Mapped struct pcpu layout (per-CPU structure at GSBASE)
6. Mapped struct pcb GPR layout
7. Mapped curthread struct partially
8. Identified per-CPU stride (0x900), CPU ID extraction
9. Identified kernel memory ranges and their purposes
10. Confirmed debug readback limit: 64 qwords (0x200 bytes)
11. Complete CPU state snapshot: CRs, standard MSRs, XCR0, DRs, GDT/IDT
12. Confirmed SVME=1 in EFER — kernel runs under AMD-V hypervisor
13. Confirmed AMD MSRs all #GP trapped — HV blocks SYSCFG/VM_CR/VM_HSAVE_PA
14. Confirmed no hardware breakpoints active (DR0-3=0, DR7=default)
15. XCR0=7: x87+SSE+AVX available, no AVX-512
16. v7 scanner working correctly (counter fix verified, total_scanned = 0x80000)
17. Confirmed GSBASE/GDT/IDT are NOT in kdata segment (separate KVA allocation)
18. kdata segment is ~8-15MB, not the assumed 100+MB

## Open Questions
1. **Where is `susppcbs`?** Not in kdata globals, not in per-CPU structure.
   In FreeBSD it's a `static struct pcb **` in `acpi_wakeup.c` BSS.
   The kdata scan should find it but reported zero (possible scan bug).
2. **What's the pcb_cr3 offset?** Somewhere in +0x40..+0x1FF, but zero for
   running threads. Only populated by savectx.
3. ~~Can we read AMD-specific MSRs?~~ **ANSWERED**: All #GP — HV traps them.
4. ~~Can we safely read debug registers?~~ **ANSWERED**: Yes, all default/empty.
5. What's in the rest of struct pcpu (+0x1C0..+0x900)?
6. ~~Why did kdata scan find zero heap pointers?~~ **PARTIALLY ANSWERED**: v7.1
   scanner works correctly (counters verified). Zero 0xffffff80 hits in first
   4MB is genuine — kdata .data section may not contain heap pointers. GSBASE
   area (where heap pointers exist) is NOT in kdata. Remaining question: does
   deeper kdata (pages 1-3) contain any, or is susppcbs a static array in BSS?
7. **Can we call savectx without panic?** savectx has no trapped instructions
   (pure movq+ret), unlike rdmsr_start which hit sldt/str.

## Next Steps

### ~~Option B: Complete CPU state~~ — DONE (v6)
### ~~Option G: Read ktext instructions~~ — IMPOSSIBLE (XOM)
### ~~Option K: kdata heap pointer scan~~ — IN PROGRESS (v7, page 0 = 0 hits)

### Option L: Scan kdata for CR3 value after rest mode (RECOMMENDED)
**Why this is the best next step**: The v7 scanner works correctly but found
zero 0xffffff80 pointers in kdata page 0. This may be correct — kdata globals
mostly contain integers, flags, and ktext function pointers, not heap pointers.

**Key insight**: In some FreeBSD versions, `susppcbs` is a static array in BSS,
not a pointer to heap:
```c
static struct pcb susppcbs[MAXCPU];  // PCBs directly in BSS
```
If this is the case, the PCBs are IN kdata, not on the heap. After a suspend/
resume cycle, each susppcbs[cpu].pcb_cr3 would contain the CR3 value (a physical
address like 0x1e104000), not a heap pointer.

**Approach**:
1. Put console into rest mode and wake it (if not already done this session)
2. Scan kdata for the raw CR3 value (0x1e104000) — Mode 0x7 with new filter
3. Any hit at address X means pcb_cr3 is at X, and the susppcbs entry starts
   at X - pcb_cr3_offset (likely 0x68 in stock FreeBSD)
4. Can also scan for CR0 (0x8005003b) as secondary confirmation

**Risk**: LOW — read-only scan, just need a new filter mode.
**Requires**: One code change (add CR3-value filter), rest mode cycle.

### Option K continued: Scan kdata pages 1-3
Continue sequential scan with broad filter (0xffff???? upper).
Pages 1-3 cover kdata 4-16MB. Will establish kdata boundary (panic = end).
**Risk**: LOW for pages 1-2, MEDIUM for page 3+ (may exceed kdata).
**Value**: LOW-MEDIUM — even if we find pointers, need to follow each one.

### Option H: Try calling savectx
savectx is a simple register-save function (movq sequences + ret).
Unlike rdmsr_start, it has no trapped instructions.
Calling it populates our td_pcb with CR0/CR2/CR3/CR4/DR0-7, revealing the
exact PCB field offsets. This is THE most direct path to understanding PCB layout.
**Risk**: MEDIUM — calling any ktext function has crashed before (rdmsr_start),
but savectx is simpler and might work.
**Value**: HIGH — directly reveals PCB CR/DR field offsets.

### Option I: Dump other CPUs' pcpu structs
Read GSBASE ± N*0x900 to see all CPU per-CPU data. Find CPU 0.
**Risk**: LOW — GSBASE ± 0x900 proven mapped in Session 3.

### Option J: Expand pcpu dump (+0x1C0..+0x900)
Per-CPU struct is 0x900 bytes, we only saw 0x1C0.
**Risk**: LOW — within per-CPU allocation.

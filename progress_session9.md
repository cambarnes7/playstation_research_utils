# PS5 Suspend/Resume Persistence — Current Status

**Date:** March 7, 2026 | **FW:** 4.03 | **Session:** 9+

---

## The Goal

Achieve **kernel code execution that survives suspend/resume** on PS5 FW 4.03.

Specifically: when the PS5 enters rest mode and wakes up, we want our code to run during the early resume path — before the user re-exploits. This would give us persistent kernel control across rest mode cycles without requiring the user to re-run the exploit chain.

The mechanism: the kernel calls `apic_ops[2]` (the `xapic_mode` function pointer) during LAPIC reinitialization on resume. We can overwrite this pointer pre-suspend (it persists in kdata), so on resume the kernel calls our target instead.

---

## What We've Proven (8 sessions, 100% reproducible)

1. **kdata fully persists** through suspend/resume — markers, code, pointers all survive
2. **apic_ops[2] overwrites persist** — the hooked pointer survives rest mode
3. **KASLR slide is stable** across resume (same ktext_base, kdata_base)
4. **DMAP base is stable** across resume (changes between boots only)
5. **Guest PTE modifications persist** — NX bit clearing survives
6. **No CFI on apic_ops** — indirect calls through the table are not checked

---

## The Blocker: NPT NX During Suspend

The PS5 hypervisor **enforces No-Execute on ALL non-ktext pages during `cpususpend_handler`**:

- **kdata code** — panics. Even `mov eax, 1; ret` (zero memory refs) panics during suspend.
- **kmod .text** — panics. kldload-allocated module pages get the same treatment.
- **Only ktext** survives. The HV tightens NPT permissions during the suspend path.

This means apic_ops[2] MUST point to a **ktext address** during suspend. We cannot inject custom code into ktext (it's XOM — execute-only, no read, no write via any path including DMAP).

---

## What We Can Do

We can point apic_ops[2] at any **existing ktext function or gadget**. The function will execute with whatever register state the LAPIC resume path sets up. We get exactly one call — it's a function pointer call, not a jump, so the caller expects a return.

The original `xapic_mode` at apic_ops[2] does `mov eax, 1; ret` — returns APIC_MODE_XAPIC. We need to either:
- Return 1 (to keep the kernel happy), OR
- Pivot to a controlled context that lets us do more

---

## The Current Approach: cpu_switch Hijack

### The Idea

FreeBSD's `cpu_switch()` function (in ktext) restores a full register context from a PCB (Process Control Block) structure:

```
cpu_switch:
    ; save current thread's registers to old PCB
    ; then load new thread's registers from new PCB:
    mov r15, [PCB+0x00]
    mov r14, [PCB+0x08]
    mov r13, [PCB+0x10]
    mov r12, [PCB+0x18]
    mov rbp, [PCB+0x20]
    mov rsp, [PCB+0x28]   <-- controls stack
    mov rbx, [PCB+0x30]
    ; ... then jumps to [PCB+0x38] (pcb_rip)
```

If we can call `cpu_switch` (or its restore half) with a pointer to a **fake PCB in kdata**, it will:
1. Load RSP from our fake PCB → stack pivot to kdata
2. Load RIP from our fake PCB → jump to a ktext ROP gadget
3. From there, a ROP chain in kdata (readable, not executable) uses ktext gadgets

### The Problem: Register State Unknown

`cpu_switch` takes arguments in registers. On FreeBSD, the restore half expects a PCB pointer. But we don't know **which register** holds what when apic_ops[2] is called during resume.

From `reg_probe` (Session 8 payloads), we captured register state at the apic_ops[2] call site during normal operation. **R8 is our best guess** for a register that might hold a useful pointer (like the idle thread's PCB) during the resume path — but this is unconfirmed for the suspend/resume context.

---

## Plan: Two Steps

### Step 1: Gamble on R8 (Option 3)

Point apic_ops[2] at a ktext gadget sequence like:
```
mov rdi, r8
jmp cpu_switch_restore   ; or call with appropriate setup
```

Pre-load the idle thread's PCB with controlled values:
- pcb_rsp → kdata ROP chain buffer
- pcb_rip → first ROP gadget (ktext `ret` or similar)

**Expected outcome:** Kernel panic. We don't actually know R8's value during resume, and even if we did, the cpu_switch restore sequence has more requirements than just a PCB pointer (it needs the old thread pointer too, for saving context).

**But:** If it works, we win. And the downside is just a reboot.

### Step 2: Observe PCB Changes (Option 2)

This is the safe, information-gathering approach:

1. **Before suspend:** Dump the idle thread's full PCB (pcb_r15 through pcb_rip, plus pcb_cr3, pcb_dr0-dr7, pcb_ext, etc.) — all ~256 bytes
2. **Set apic_ops[2] to original xapic_mode** (safe, no-op)
3. **Enter rest mode, resume, re-exploit**
4. **After resume:** Dump the idle thread's PCB again

**What this tells us:**
- If PCB values **changed**, then `cpu_switch` ran during the resume path and saved new register state into the idle PCB. The new saved RSP/RIP/etc. ARE the register values at the point cpu_switch was called during resume. This tells us exactly what the execution context looks like when the idle thread is being switched back in.
- If PCB values **didn't change**, then cpu_switch did NOT run during resume on the idle thread (the resume path may use a different mechanism).

**Either way, we learn something critical.** If cpu_switch ran, we know the exact register layout. If it didn't, we eliminate a hypothesis and look elsewhere.

We already have `pcpu_recon` and `suspend_stackprobe` payloads that dump parts of the PCB. Option 2 is essentially: run pcpu_recon before suspend, run it again after resume, diff the results.

---

## What We Already Have (Existing Payloads)

| Payload | Purpose | Status |
|---------|---------|--------|
| `suspend_probe` (v5) | Confirmed kdata persistence | DONE |
| `pcpu_recon` (v2) | Dumps pcpu, idle/cur thread, PCB, debug regs | DONE |
| `suspend_stackprobe` (v2) | Marker grid on idle stack + DR sentinels | DONE (has ARM + READBACK modes) |
| `reg_probe` | Register state at apic_ops[2] call site | DONE |
| `pcb_dump` (v17) | Full PCB structure dump | DONE |

### Key PCB Offsets (empirically confirmed, FW 4.03)
```
PCB+0x00: r15
PCB+0x08: r14
PCB+0x10: r13
PCB+0x18: r12
PCB+0x20: rbp
PCB+0x28: rsp
PCB+0x30: rbx
PCB+0x38: rip
PCB+0x100: flags
```

### Key Kernel Offsets (stable across boots)
```
LSTAR         = ktext_base + 0x294218
apic_ops      = kdata_base + 0x1656b0  (or ktext_base + 0x1934AC8)
pcpu[0]       = kdata_base + 0x64d2280
IDT           = kdata_base + 0x64cdc80
sysent        = kdata_base + 0x1709c0
td_pcb        = thread + 0x3f8
td_name       = thread + 0x290
```

---

## Summary of Unknowns

1. **Register state at apic_ops[2] call during RESUME** — we know normal-ops state from reg_probe, but resume context may differ
2. **Whether cpu_switch runs during resume on the idle thread** — Option 2 answers this
3. **Exact cpu_switch ktext offset** — need to locate it (can't read ktext, but kstuff offsets may have it)
4. **What gadgets exist in ktext** — XOM prevents scanning; we rely on known offsets from kstuff and blind probing

---

## Session 9 Results

### Option 3: R8 Gamble — CONFIRMED PANIC

**Payload:** `r8_gamble.bin` (mode 0, fw_ver=0x403)
**Target:** cpu_switch entry at `kdata_base - 0x9d6f80`

**Output (pre-suspend, armed successfully):**
```
kdata_base     = 0xffffffff9a680000
ktext_base     = 0xffffffff99a80000
target         = 0xffffffff99ca9080 (cpu_switch entry)
original_xapic = 0xffffffff99d14340
cpu_switch     = 0xffffffff99ca9080
offset         = 0x0 (function entry)
status         = 0x0001 (armed)
```

**Result:** Kernel panic during resume. System never came back from rest mode.

**Analysis:** cpu_switch entry does `movq TD_PCB(%rdi), %r8` as its first instruction.
RDI at the apic_ops[2] call site is not a valid thread pointer → immediate fault
on dereferencing RDI+0x3f8. This was expected.

**Decision:** Skip modes 1-3 (R8 equally unlikely to be a valid PCB pointer).
Proceed to Option 2 — gather real data instead of gambling.

### Known ktext Offsets (confirmed this session)
```
cpu_switch        = kdata_base - 0x9d6f80
cpu_switch_dr2gpr = kdata_base - 0x9d6d93  (+0x1ED into cpu_switch)
cpu_switch_gpr2dr = kdata_base - 0x9d6c7a  (+0x306 into cpu_switch)
nop_ret           = kdata_base - 0x9d20ca
doreti_iret       = kdata_base - 0x9cf84c
```

---

## Option 2: PCB Diff Across Suspend/Resume — IN PROGRESS

### Strategy

Two-phase payload using fw_ver as mode selector:

**Phase 1 (pre-suspend, fw_ver=0x403):**
1. Dump idle thread's full PCB to kdata (persistent region at kdata_base+0x200)
   - All saved registers: r15, r14, r13, r12, rbp, rsp, rbx, rip
   - System regs: fsbase, gsbase, kgsbase, cr0, cr2, cr3, cr4
   - Debug regs: dr0-dr7
   - Flags, onfault, etc.
2. Also dump curthread PCB for comparison
3. Record pcpu[0] state (curthread, idlethread, curpcb)
4. Set apic_ops[2] to ORIGINAL xapic_mode (safe, no hook)
5. Report all values to output buffer AND persist to kdata

**Phase 2 (post-resume, fw_ver=0x2):**
1. Dump idle thread's PCB again (same fields)
2. Read the pre-suspend values back from kdata
3. Compare every field: flag each as CHANGED or SAME
4. Report the diff to output buffer

**What we learn:**
- If pcb_rsp/pcb_rip changed → cpu_switch saved new context during resume,
  and the new values ARE the register state at that point
- If pcb_cr3 changed → pmap switch happened (expected, CR3 changes across resume)
- If debug regs changed → DR state tells us about HV/kernel debug usage
- If nothing changed → cpu_switch did NOT run on the idle thread during resume,
  meaning the resume path uses a different mechanism

### Why This Works
- kdata persists through suspend/resume (proven 8 sessions)
- We write pre-suspend PCB snapshot to kdata
- Post-resume, we read it back and compare with current PCB
- apic_ops[2] stays original → no panic risk, clean suspend/resume cycle
- We re-exploit after resume and deploy the readback payload

---

## Next Actions — PIVOTING TO GPU DMA

Previous approach (PCB diff, cpu_switch hijack, blind gadget hunting) is shelved.
All effort now goes to **GPU DMA** — programming the GPU to perform DMA transfers
to/from physical addresses that the CPU can't access due to NPT/XOM.

---

## GPU DMA Strategy

### Why GPU DMA

The core blocker is: **ktext is XOM (can't read or write) and NPT enforces NX on kdata during suspend**. Every approach so far has tried to work around this with blind gadget gambling and indirect techniques. All have failed or stalled.

GPU DMA operates through the **IOMMU**, which is a completely separate protection domain from the CPU's NPT. The GPU's page tables are NOT the same as the hypervisor's nested page tables. This means:

- GPU may be able to **read ktext physical pages** → bypass XOM → find every gadget we need
- GPU may be able to **write ktext physical pages** → inject code directly → persistence solved
- GPU may be able to **read/write HV memory** → modify VMCB/NPT → disable protections entirely

**Proven on PS5**: flatz demonstrated GPU DMA to kernel .data on FW 6.00+ (bypasses HV write protection). On FW 4.03, the HV is less mature — IOMMU may be even more permissive.

### What We Already Have

- `vaddr_to_paddr()` — working virtual-to-physical address translation (`usermode_phys_mem/include/dmem.h`)
- `PADDR_TO_DMAP()` — DMAP-based physical memory access
- `kernel_copyin/kernel_copyout` — kernel R/W primitives via PS5 Payload SDK
- Known kernel offsets (ktext_base, kdata_base, DMAP base, CR3, etc.)
- etaHEN jailbreak on FW 4.03 with full kernel R/W

### What We Don't Know (Honest Assessment)

| Question | Status | Risk |
|----------|--------|------|
| Can we call sceGnmSubmitCommandBuffers from a payload ELF? | Unknown | Medium — may need game context |
| Does the IOMMU allow GPU reads of ktext physical pages? | Unknown | HIGH — this is the key bet |
| Does the IOMMU allow GPU writes to ktext physical pages? | Unknown | HIGH — would be the ultimate win |
| Can we fall back to direct SDMA MMIO programming? | Probable | Low — we have kernel R/W, can access any register |
| What physical address ranges does the IOMMU permit? | Unknown | Need to probe empirically |

### The Approach: Incremental, Each Phase Gives Data

---

### Phase 0: GNM API Accessibility Probe

**Goal**: Determine if we can use the GNM (GPU) APIs from an etaHEN payload context.

**Method**: PS5 Payload SDK ELF that attempts to:
1. `sceKernelLoadStartModule("libSceGnmDriver.sprx")` — try loading the GNM driver
2. If that fails, try `libSceGnmDriverForNeoMode.sprx`
3. If loaded, resolve `sceGnmSubmitCommandBuffers` and `sceGnmSubmitDone` via dlsym
4. Report addresses (or errors) back to host

**Outcome A (GNM accessible)**: Use high-level API path. Much easier.
**Outcome B (GNM not accessible)**: Fall back to direct GPU MMIO programming (Phase 0b).

**Phase 0b (fallback): Direct SDMA Engine Access**

If GNM APIs aren't available, we program the GPU's SDMA (System DMA) engine directly:
1. Scan PCI config space to find GPU device (vendor 0x1002 = AMD)
2. Read GPU MMIO BAR address from PCI config
3. Map MMIO region via kernel R/W (we can read/write any physical address via DMAP)
4. Locate SDMA ring buffer registers (SDMA0_GFX_RB_BASE, SDMA0_GFX_RB_RPTR, SDMA0_GFX_RB_WPTR)
5. Submit SDMA_OP_COPY packets to the ring
6. Ring doorbell to trigger processing

The SDMA engine is simple: it copies data between physical addresses. No shaders, no GFX pipeline, no compute queues. AMD's open-source amdgpu driver documents all register offsets.

---

### Phase 1: GPU DMA Self-Test

**Goal**: Confirm GPU DMA works at all from our context.

**Method**:
1. Allocate two userspace buffers: `src` (fill with pattern 0xDEADBEEF) and `dst` (zeroed)
2. Translate both to physical addresses via `vaddr_to_paddr()`
3. Submit a GPU DMA copy: `src_phys → dst_phys`, 4096 bytes
4. Verify `dst` now contains 0xDEADBEEF pattern
5. Report success/failure

**If this fails**: GPU DMA pipeline is broken in our context. Need to debug (wrong ring buffer? IOMMU blocking userspace pages? Command format wrong?).

**If this works**: We have a working GPU DMA primitive. Proceed to Phase 2.

---

### Phase 2: IOMMU Boundary Probe — THE KEY EXPERIMENT

**Goal**: Map what physical address ranges the GPU can access through the IOMMU.

**Method**:
1. Translate known kernel addresses to physical:
   - `kdata_base` → `kdata_phys` (should work — proven on 6.00+)
   - `ktext_base` → `ktext_phys` (the big question)
   - DMAP region addresses → their backing physical pages
2. For each physical address range, attempt a GPU DMA **read** (copy phys → userspace buffer):
   - Read 64 bytes from kdata physical → compare with `kernel_copyout` of same address
   - Read 64 bytes from ktext physical → if we get data, XOM is BYPASSED
3. Log results: which ranges succeed, which cause errors/hangs

**Success criteria**:
- kdata readable via GPU → confirms GPU DMA works for kernel memory (matches 6.00+ results)
- ktext readable via GPU → **XOM bypass achieved** → can dump entire kernel .text
- ktext writable via GPU → **game over** → write our handler directly into ktext

**Failure modes**:
- IOMMU blocks ktext physical pages → GPU DMA can't bypass XOM. Still useful for other things.
- IOMMU blocks all kernel physical pages → GPU DMA only works for userspace memory. Dead end.
- GPU hangs/panics → command format issue or IOMMU violation triggers system fault.

---

### Phase 3: Exploit GPU DMA Capabilities

Depends entirely on Phase 2 results:

**If ktext is readable (XOM bypass)**:
1. Dump entire ktext (~12MB) via GPU DMA reads
2. Disassemble offline — find EVERY gadget, not just the handful we've been guessing at
3. Find the perfect apic_ops[2] target: a function or gadget sequence that does exactly what we need
4. Build the persistence hook with complete knowledge of available gadgets

**If ktext is writable (ultimate win)**:
1. Write a small handler (< 64 bytes) directly into ktext at an unused/padding location
2. Handler: save regs, execute our logic (from kdata), restore regs, return 1
3. Point apic_ops[2] at our injected ktext handler
4. Survives suspend/resume because it IS ktext — NPT NX doesn't apply

**If HV/VMCB is accessible**:
1. Find VMCB physical address (scan for known patterns or derive from HV code analysis)
2. Read NPT CR3 from VMCB → walk NPT page tables
3. Modify NPT entries: clear NX bit on kdata pages
4. Now kdata is executable during suspend → original apic_ops[2] → kdata handler approach works

---

### Implementation Plan — Files to Create

```
gpu_dma/
├── Makefile                    # PS5 Payload SDK build (userspace ELF)
├── include/
│   ├── dmem.h                  # Copy from usermode_phys_mem (vaddr_to_paddr)
│   ├── gpu_dma.h               # GPU DMA abstraction (GNM or SDMA backend)
│   └── pm4_packets.h           # AMD PM4/SDMA packet definitions
├── src/
│   ├── main.c                  # Phase selector (fw_ver-based, like other payloads)
│   ├── gnm_probe.c             # Phase 0: GNM API resolution
│   ├── sdma_direct.c           # Phase 0b: Direct SDMA MMIO programming
│   ├── gpu_dma_selftest.c      # Phase 1: Self-test
│   ├── iommu_probe.c           # Phase 2: IOMMU boundary mapping
│   └── ktext_ops.c             # Phase 3: Read/write ktext
└── freebsd-headers/            # Symlink to shared headers
```

### Risk Assessment

| Phase | Risk of Failure | Impact of Failure | Recovery |
|-------|----------------|-------------------|----------|
| Phase 0 (GNM probe) | Medium | Low — fall back to SDMA | Phase 0b |
| Phase 0b (SDMA direct) | Low | Medium — need kernel R/W for MMIO | Debug register offsets |
| Phase 1 (self-test) | Low | High — means GPU DMA doesn't work at all | Debug command format |
| Phase 2 (IOMMU probe) | **HIGH** | **HIGH** — if ktext not accessible, major goal blocked | Still useful for kdata ops |
| Phase 3 (exploit) | Low (if Phase 2 works) | N/A | Depends on Phase 2 results |

**The honest truth**: Phase 2 is the make-or-break. If the IOMMU blocks GPU access to ktext physical pages, GPU DMA can't bypass XOM. But the experiment is cheap — we either learn it works (huge win) or learn it doesn't (eliminate a hypothesis, move on). Either way, it's worth trying.

---

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

### Intelligence from psdevwiki.com/ps5/Vulnerabilities

Key facts that shape the approach:

1. **GPU DMA to kernel .data is a proven technique** (flatz, FW 6.00+)
   - Uses `sceGnmSubmitCommandBuffers` + `sceGnmSubmitDone`
   - Specifically from `libSceGnmDriverForNeoMode.sprx` (PS4 compat GNM driver)
   - BD-J alternative: `Java.sun.awt.GnmUtils.copyPlanesBackgroundToPrimary`

2. **Byepervisor bug #2**: "System-level debug flag in kernel .data, not wiped after rest mode"
   - Can be SET via GPU DMA write to kdata
   - Enables hypervisor exploitation
   - Directly relevant to our rest mode persistence work

3. **Hypervisor bypass vulnerability exists for ≤FW 4.51** — we're on 4.03, IN RANGE
   - "Without a Hypervisor bypass/compromise, limited to data-only attacks"
   - With HV bypass: can potentially disable NPT, XOM, NX — everything

4. **CR0.WP/XOM bypass** — possibly unpatched until FW 5.00
   - If this works on 4.03, we can read/write ktext without GPU DMA

5. **CRITICAL SAFETY**: Reading ktext via DMAP/kernel_copyout WILL PANIC
   - XOM is enforced by HV's NPT (nested page tables)
   - Any CPU access (including DMAP physical read) goes through NPT
   - Only GPU DMA bypasses NPT because GPU uses IOMMU instead
   - NEVER attempt `kernel_copyout(PADDR_TO_DMAP(ktext_phys))`

### Why GPU DMA

The core blocker is: **ktext is XOM (can't read or write) and NPT enforces NX on kdata during suspend**. CPU-based approaches cannot bypass this — the HV's NPT intercepts ALL CPU memory accesses.

GPU DMA operates through the **IOMMU**, a completely separate protection domain. The GPU's I/O page tables are NOT the CPU's nested page tables. This means:

- GPU may read ktext physical pages → bypass XOM → find every gadget
- GPU may write ktext physical pages → inject code → persistence solved
- GPU may access VMCB/NPT structures → disable protections entirely
- GPU DMA can SET the Byepervisor debug flag → enable HV exploitation

### What We Have

- `vaddr_to_paddr()` — VA→PA translation via guest page table walk (SAFE — reads PTEs in kdata, not ktext content)
- `kernel_copyin/kernel_copyout` — kernel R/W via PS5 Payload SDK
- Known kernel offsets (ktext_base, kdata_base, DMAP, CR3, apic_ops, etc.)
- etaHEN jailbreak on FW 4.03 with full kernel R/W
- HV bypass vulnerability coverage (≤4.51)

### What We Don't Know

| Question | Status | Risk |
|----------|--------|------|
| Can we load libSceGnmDriverForNeoMode.sprx from etaHEN? | Unknown | Medium — may need game context |
| Does the IOMMU allow GPU access to ktext physical pages? | Unknown | HIGH — the key bet |
| Where is the Byepervisor debug flag in kdata? | Unknown | Medium — needs scanning |
| Does CR0.WP bypass work on 4.03? | Unknown | Low risk to test |
| What PM4 packet format does sceGnmSubmitCommandBuffers expect? | Partially known | Medium |

---

### Phase 0: GNM API Probe

**Goal**: Load `libSceGnmDriverForNeoMode.sprx` and resolve `sceGnmSubmitCommandBuffers` + `sceGnmSubmitDone`.

This is THE library used in confirmed GPU DMA exploits (psdevwiki). Priority target.

**Outcome A**: GNM accessible → proceed to GPU DMA pipeline.
**Outcome B**: GNM not accessible from etaHEN → options:
  - Phase 5: Direct SDMA via PCI MMIO (find GPU BAR0, program SDMA ring)
  - Try from game process context
  - BD-J path (if disc available)

### Phase 1: PA Translation Self-Test

Verify `vaddr_to_paddr()` works correctly by DMAP round-trip on userspace buffers.
No kernel memory touched, no risk.

### Phase 2: Kernel Address Mapping (SAFE)

Walk guest page tables to translate ktext/kdata VAs to physical addresses.
Report PTE flags (RW, NX, present) for each mapping.

**SAFETY**: Only reads page table entries (stored in kdata). NEVER reads ktext content.

The physical addresses gathered here become GPU DMA targets in Phase 3/4.

Also reports the distinction: guest PTE flags are NOT what enforces XOM.
XOM is enforced by the HV's NPT layer, which the guest page tables don't see.

### Phase 3: GPU DMA kdata Test

First actual GPU DMA operation — target kdata (CPU-readable, so we can verify).
- GPU DMA copy: kdata_phys → userspace recv buffer
- Compare GPU-read data with CPU-read data (kernel_copyout)
- If they match → GPU DMA pipeline works, GPU can access kernel physical memory

### Phase 4: GPU DMA ktext Read (XOM Bypass) — THE KEY EXPERIMENT

**If Phase 3 succeeds**: Attempt GPU DMA read of ktext physical pages.
- GPU DMA copy: ktext_phys → userspace recv buffer
- If recv buffer contains real instructions → **XOM IS BYPASSED**
- If recv buffer is zeros/garbage or GPU faults → IOMMU blocks ktext, need Plan B

**If ktext readable**: Dump entire kernel .text (~12MB), disassemble offline, find every gadget.

**If ktext writable**: Inject handler directly into ktext padding. Game over for persistence.

### Phase 5: PCI/MMIO Probe (Fallback)

If GNM APIs unavailable: scan PCI config space for AMD GPU (vendor 0x1002),
read BAR0, probe SDMA engine registers. Direct SDMA ring programming as fallback.

### Byepervisor Path (If GPU DMA to kdata works)

Even if GPU DMA can't read ktext, it can WRITE to kdata. This enables:

1. Find the "system-level debug flag" in kdata (Byepervisor bug #2)
2. Set it via GPU DMA write
3. Flag survives rest mode (confirmed by psdevwiki)
4. On resume, debug flag enables HV exploitation
5. HV compromise → disable NPT → kdata becomes executable → persistence solved

This is a viable path even if IOMMU blocks ktext access.

### Risk Assessment

| Phase | Risk | Impact | Recovery |
|-------|------|--------|----------|
| Phase 0 (GNM probe) | Medium | Low | Phase 5 / game context |
| Phase 1 (PA self-test) | Very Low | Low | Debug translation code |
| Phase 2 (address map) | Very Low | None | Safe, information only |
| Phase 3 (GPU kdata) | Medium | Medium | Debug PM4 format |
| Phase 4 (GPU ktext) | **HIGH** | **HIGH** | HV bypass path |
| Phase 5 (PCI/MMIO) | Low | Medium | Known AMD register map |

---

## Hypervisor Bypass Research (≤FW 4.51)

### What Exists

The psdevwiki lists an unnamed "Hypervisor bypass vulnerability (≤FW 4.51)" — separate from Byepervisor (≤2.70). This is **flatz's private exploit**. Key facts:

- **NOT Byepervisor** — flatz explicitly confirmed a different exploit
- **Entry chain**: PS4 savegame → kernel exploit → HV exploit → PSP dump
- **Patched in FW 5.00** (same release that killed dlsym, MAP_SELF)
- **Not released**: flatz won't publish unless original discoverer goes first
- **No technical details** have ever been made public

### Why Byepervisor Doesn't Work on 4.03

Byepervisor (≤2.70) used two bugs, both patched by FW 3.00:

1. **QA flags shared with guest kernel** — HV init checked QA SL debug flag when building NPT. If set, NPT wouldn't apply xotext to ktext pages. Flag survived rest mode even though HV reinitializes. PATCHED: QA flags no longer accessible from guest.

2. **HV jump tables in kdata** — hypercall vtable stored in kernel .data, writable by guest. Hijack VMMCALL_HV_SET_CPUID_PS4 entry → ROP chain in HV → disable NPT + GMET → xotext gone. PATCHED: HV separated from kernel binary at FW 3.00.

### What Changed at FW 3.00 (HV Hardening)

- HV separated into its own binary (no longer part of kernel)
- QA flags isolated from guest kernel
- 3 new hypercalls added:
  - `VMCLOSURE_INVOCATION` (0xe) — purpose unknown, potential attack surface
  - `STARTUP_MP` (0xf) — multiprocessor startup
  - `DISABLE_STARTUP_MP` (0x10)

### HV Attack Surface on FW 4.03

Even without flatz's exploit, the HV exposes these interfaces:

**IOMMU hypercalls (7 total, 0x6-0xC)**:
- `IOMMU_SET_GUEST_BUFFERS` (0x6) — configure IOMMU page tables?
- `IOMMU_ENABLE_DEVICE` (0x7) — enable DMA for a device
- `IOMMU_BIND_PASID` (0x8) — bind process address space ID
- `IOMMU_UNBIND_PASID` (0x9)
- `IOMMU_CHECK_CMD_COMPLETION` (0xa)
- `IOMMU_CHECK_EVLOG_REGS` (0xb)
- `IOMMU_READ_DEVICE_TABLE` (0xc)

Any bug in these hypercall handlers could give IOMMU control → GPU DMA to anything.

**Key HV architectural facts**:
- EFER bit 16 (xotext/NDA) — guest can't modify, silently dropped
- GMET — traps execution from lower-priv pages in higher-priv context
- CR0.WP, CR4.SMAP, CR4.SMEP — all intercepted, can't disable
- HV's own page tables map ktext as **read/write** (needs it for intercept handlers)
- NPT maps ktext as execute-only (no read, no write from guest CPU)

**VMCLOSURE_INVOCATION** (0xe) — added in FW 3.00, purpose unknown.
If this hypercall has a vulnerability, it would be in the exact FW range of flatz's exploit (3.00-4.51). Worth investigating what arguments it takes and what it does.

### Strategy: GPU DMA First, HV Bypass Second

Since flatz's exploit is private, we pursue two parallel tracks:

**Track A: GPU DMA (immediate)**
1. Get GPU DMA working (Phases 0-3)
2. If GPU can read ktext through IOMMU → XOM bypassed without HV exploit
3. If GPU can write ktext → persistence solved without HV exploit
4. If IOMMU blocks ktext → Track B

**Track B: HV bypass research (longer term)**
1. Reverse engineer IOMMU hypercall handlers from ktext dump (needs Track A success)
2. Investigate VMCLOSURE_INVOCATION behavior
3. Probe IOMMU_SET_GUEST_BUFFERS with crafted arguments
4. If any HV hypercall handler has a bug → code exec in HV → disable NPT/GMET → game over

**Track C: Data-only persistence (fallback)**
If neither GPU DMA nor HV bypass yields ktext access:
- Focus on data-only attacks (function pointer manipulation)
- Use existing kdata gadgets (if any exist in mapped executable regions)
- Accept that full ktext dump may not be achievable on 4.03 without flatz's exploit

---

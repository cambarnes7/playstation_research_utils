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

## Next Actions

1. Build Option 3 payload (R8 gamble) — expect panic, but try it
2. After the expected panic, build Option 2 payload (PCB diff across suspend/resume)
3. Use Option 2 results to understand the resume execution context
4. Design the actual persistence hook based on real data

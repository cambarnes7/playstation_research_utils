# PS5 HV Defeat via APIC — Combined Research Progress

**Target:** FW 4.03 | **Date:** March 2026

This document synthesizes findings from two parallel research branches and outlines the path forward for defeating the PS5 hypervisor using the flatz APIC method.

**Sources:**
1. `playstation_research_utils` branch `claude/build-kstuff-elf-WkCbV` — kldload.elf kernel module loader
2. `etaHEN` branch `claude/debug-kernel-module-dvC04` — HV research tool (hv_research.elf + hv_kld.ko)
3. flatz's public notes on APIC ops, offset finding, and pointer poisoning

---

## What We Have (Combined)

### From Branch 1: kldload.elf (Kernel Module Loader)

A fully functional kernel module loader built on top of ps5-kstuff:

- **Loads ps5-kstuff** at fixed address `0x0000000926100000`, initializes r0gdb, hooks getpid for kekcall dispatch, sets up per-CPU kelf/uelf trap handlers
- **Kekcall infrastructure** — 8 working kekcalls:
  | Nr | Function | Description |
  |----|----------|-------------|
  | 1 | copyout | Kernel → userspace |
  | 2 | copyin | Userspace → kernel |
  | 6 | malloc | Kernel heap allocation |
  | 7 | kproc_create | Launch kernel thread |
  | 8 | copyin (kernel ctx) | Full kernel copyin via push_stack/trap |
  | 9 | Diagnostics | Read proc info, kernel memory |
  | 10 | NX bit clearing | Walk page tables, clear NX on PTEs |
  | 0xffffffff | Liveness | Returns 0 if kstuff loaded |

- **TCP kernel code loading** — Receives arbitrary kernel code over port 9022, copies to kernel heap via `copyin`, clears NX bit via PTE walk, launches as kernel thread via `kproc_create`
- **7 kernel panics debugged**: uninitialized r0_table, missing uelf symbols, malloc return value not stored in td_retval, kproc_create NULL fmt (R9 vs stack), missing doreti_iret return frame, copyin KPTI/CR3 issues, NX bit on malloc'd pages
- **Test payloads verified**: `test_kmod.bin` (0xCAFEBABE markers), `apic_ops.bin` (full APIC table dump)

### From Branch 2: hv_research.elf (HV Research Tool)

A comprehensive hypervisor research tool with 18+ confirmed capabilities:

- **Infrastructure**: DMAP base discovery, FW version detection, 4-level page table walking (VA→PA), kldload with SYSINIT/MOD_LOAD/IDT trampoline paths
- **Ring-0 execution**: Two methods — sysent hook (syscall dispatch) and kproc_create (kernel thread)
- **apic_ops management**: Discovery, hook installation (KLD trampoline + kdata cave trampoline), persistence markers ("FLATZHOO" cave + QA flags), writeback test
- **NPT scanning**: Scanned 512MB+ of physical memory, found NPT page tables at PA 0x6a000/0x6e000, identified ktext 4KB NPT mappings at PA 0x11564000-0x11565000
- **8 test sessions** across 4+ independent boot cycles with suspend/resume testing

### Fresh Result: apic_ops.bin via kldload Pipeline

Just confirmed working — the kldload pipeline loads and executes `apic_ops.bin` as a kernel thread on FW 4.03:

```
=== APIC OPS READER RESULTS ===
  FW version:  0x403
  kdata_base:  0xffffffff97e80000
  ktext_base:  0xffffffff97280000
  LSTAR:       0xffffffff97514218
  EFER:        0x11d01
  APIC_BASE:   0xfee00800
  CR0:         0x8005003b
  CR3:         0x1e5b4000
  CR4:         0x340ee0
  apic_ops @:  0xffffffff98bb4ac8
  num_ops:     26

  Slot  Name                     Address              ktext offset
  [ 0]  create                   0xffffffff9750db88   ktext+0x28db88
  [ 1]  init                     0xffffffff9750d310   ktext+0x28d310
  [ 2]  xapic_mode               0xffffffff97514340   ktext+0x294340
  [ 3]  is_x2apic                0xffffffff97510808   ktext+0x290808
  [ 4]  setup                    0xffffffff97513f18   ktext+0x293f18
  [ 5]  dump                     0xffffffff97514100   ktext+0x294100
  [ 6]  disable                  0xffffffff975143b8   ktext+0x2943b8
  [ 7]  set_id                   0xffffffff97510330   ktext+0x290330
  [ 8]  ipi_raw                  0xffffffff9750e9d0   ktext+0x28e9d0
  [ 9]  ipi_vectored             0xffffffff9750dc60   ktext+0x28dc60
  [10]  ipi_wait                 0xffffffff97510240   ktext+0x290240
  [11]  ipi_alloc                0xffffffff97510aa8   ktext+0x290aa8
  [12]  ipi_free                 0xffffffff9750d770   ktext+0x28d770
  [13]  set_lvt_mask             0xffffffff9750e708   ktext+0x28e708
  [14]  set_lvt_mode             0xffffffff9750e700   ktext+0x28e700
  [15]  set_lvt_polarity         0xffffffff9750dc58   ktext+0x28dc58
  [16]  set_lvt_triggermode      0xffffffff975102b8   ktext+0x2902b8
  [17]  lvt_eoi_clear            0xffffffff975141d0   ktext+0x2941d0
  [18]  set_tpr                  0xffffffff97514348   ktext+0x294348
  [19]  get_timer_freq           0xffffffff97514320   ktext+0x294320
  [20]  timer_enable_intr        0xffffffff9750d130   ktext+0x28d130
  [21]  timer_disable_intr       0xffffffff9750db80   ktext+0x28db80
  [22]  timer_set_divisor        0xffffffff975106d0   ktext+0x2906d0
  [23]  timer_initial_count      0xffffffff9751e830   ktext+0x29e830
  [24]  timer_current_count      0xffffffff97510800   ktext+0x290800
  [25]  self_ipi                 0xffffffff977d69f0   ktext+0x5569f0

Key: EFER=0x11d01 (NXE set), CR0=0x8005003b (WP set), CR4=0x340ee0 (SMEP+SMAP set)
```

All 26 slots point into ktext — executable during suspend/resume.

---

## What We Proved (8 Sessions of Testing)

### Persistence Across Suspend/Resume (Confirmed 6/6 Sessions)
- Cave markers ("FLATZHOO" in kdata) persist
- QA flags (bytes 0-1 = 0xFF, custom markers) persist
- Guest PTE NX-clear persists (kdata page stays NX=0)
- KASLR slide is stable (ktext/kdata base addresses don't change)
- DMAP base is stable within a boot cycle (changes between boots)
- apic_ops[2] retains its value across resume
- Minimal gadget code in kdata persists

### NPT Enforcement During Suspend (The Blocker)
| Region | Normal Ops | During cpususpend_handler |
|--------|-----------|--------------------------|
| ktext | Execute-only (XOM) | **Executable** (only region that works) |
| kdata | Executable (after PTE NX-clear) | **PANIC** — NPT NX enforced |
| kmod .text | Executable (IDT trampoline works) | **PANIC** — NPT NX enforced |
| DMAP writes | Works | **PANIC** — restricted during suspend |

**Key evidence:**
- Session 4 (Run 7): `mov eax, 1; ret` at kdata+0x150 → kernel panic during suspend (zero memory refs, pure register instruction)
- Session 8: KLD trampoline at 0x1c0000080 → kernel panic during suspend (kmod .text)
- Session 3 (Runs 5-6): Same kdata gadget survives 3+ seconds during normal ops as apic_ops[2]

### Other Key Findings
- PS5 kldload places modules at non-standard VAs (0x1c0000000 range, not 0xffffffff...)
- Late SYSINIT fires ~15s after kldload on FW 4.03 (race condition with writeback test)
- ktext XOTEXT bit (bit 58) present on FW 4.03 guest PTEs — clearing triggers HV integrity monitor
- ktext remains XOM after resume (DMAP reads return 0xCC/zeros)
- VMCB not found in 512MB scan of physical memory

---

## The Flatz Method: What It Actually Requires

From flatz's notes:

> struct apic_ops is located in RW segment of kernel data. With KRW you can overwrite a function pointer inside it like xapic_mode and **get into ROP**, for example (just need to bypass CFI).
> Then, after you do suspend/resume cycle your code will be executed before HV restarts and you can apply kernel patches, etc.

### Critical Distinction: ROP, Not Direct Code Execution

Our testing tried pointing apic_ops[2] to **custom code** (kdata gadgets, kmod trampolines). This panics because the HV enforces NPT NX on everything except ktext during suspend.

Flatz says **ROP** — Return-Oriented Programming using existing ktext instructions:

1. **Stack pivot**: Point apic_ops[2] to a ktext gadget like `xchg rsp, <reg>; ret` or a sequence that redirects RSP to a controlled buffer in kdata
2. **ROP chain in kdata**: A sequence of ktext return addresses that, chained together via `ret` instructions, perform the desired kernel patches
3. **CFI bypass**: PS5 kernel has Control Flow Integrity. The call from `apic_ops[2]` must land on a valid CFI target, or use a gadget that bypasses the CFI check

### Why ROP Works Where Direct Execution Doesn't

- ROP gadgets are in **ktext** → always executable, even during suspend
- The ROP **payload** (chain of addresses) is in **kdata** → readable (not executed, just dereferenced by `ret` instructions)
- The stack pivot redirects RSP to kdata, but instruction fetch stays in ktext
- The HV enforces NX (no-execute) on kdata, but doesn't restrict reads — ROP chains are data, not code

### What the ROP Chain Needs to Do

During early resume (before HV reinitializes NPT):
1. **Disable XOM enforcement** — Modify NPT entries to make ktext readable+writable, or disable NPT entirely
2. **Patch kernel security checks** — Disable SMAP/SMEP in CR4, clear WP in CR0, patch security functions
3. **Install persistent hooks** — Set up IDT entries or syscall hooks that survive the full resume
4. **Return cleanly** — apic_ops[2] (xapic_mode) must return 1 (APIC_MODE_XAPIC) or the kernel panics

### CFI Bypass Considerations

PS5 uses forward-edge CFI (likely based on clang CFI or similar). Options:
1. **Find a CFI-valid entry point** — Some ktext functions may be valid indirect call targets that also serve as useful gadgets
2. **Corrupt the CFI shadow stack/metadata** — If CFI metadata is in kdata (RW), poison it before suspend
3. **Use an apic_ops slot that doesn't have CFI** — Some function pointer dispatches may skip CFI checks (e.g., if the vtable dispatch is trusted)
4. **The APIC dispatch path itself** — If the kernel calls `apic_ops[2]()` via a direct vtable load without CFI instrumentation, no bypass is needed

---

## Known Offsets (FW 4.03)

### From ps5-kstuff (Hardcoded)
| Offset | Value | Source |
|--------|-------|--------|
| IDT | kdata+0x64cdc80 | kstuff offsets, validated by hv_research |
| TSS | kdata+0x64d0830 | kstuff offsets |
| GDT | kdata+0x64cee30 | kstuff offsets |
| PCPU | kdata+0x64d2280 | kstuff offsets |
| Sysent (native) | kdata+0x1709c0 | kstuff offsets, validated by hv_research |
| doreti_iret | known ktext offset | kstuff offsets |
| nop_ret | known ktext offset | kstuff offsets |
| justreturn | known ktext offset | kstuff offsets |
| Xinvtlb | IDT[244] | kstuff offsets, cross-verified from IDT dump |

### From apic_ops Dump (This Session)
| Slot | Name | ktext Offset |
|------|------|-------------|
| 0 | create | ktext+0x28db88 |
| 1 | init | ktext+0x28d310 |
| **2** | **xapic_mode** | **ktext+0x294340** |
| 3 | is_x2apic | ktext+0x290808 |
| 4 | setup | ktext+0x293f18 |
| 5 | dump | ktext+0x294100 |
| 6 | disable | ktext+0x2943b8 |
| 25 | self_ipi | ktext+0x5569f0 |

### From MSR/CR Reads
| Register | Value | Notes |
|----------|-------|-------|
| LSTAR | ktext+0x294218 | Syscall entry point |
| EFER | 0x11d01 | NXE enabled |
| CR0 | 0x8005003b | WP enabled |
| CR3 | per-boot | Changes on resume |
| CR4 | 0x340ee0 | SMEP+SMAP enabled |
| APIC_BASE | 0xfee00800 | Standard LAPIC base |

### From NPT Scan
| Physical Address | Content |
|-----------------|---------|
| PA 0x6a000 | NPT L2 — 512 entries, 2MB pages, ktext+kdata (RW User X) |
| PA 0x6e000 | NPT L2 — 512 entries, 2MB pages, ktext+kdata (RW Kern X) |
| PA 0x11564000-0x11565000 | NPT 4KB page tables for ktext (bit 58 XOTEXT, RO+X) |

---

## Architecture of the Combined Tool

### Current Pipeline (Working)

```
User (PC)  ──TCP:9022──>  kldload.elf (PS5 userland)
                               │
                               ├── Loads ps5-kstuff (kekcall infra, IDT hooks)
                               ├── Receives .bin payload over TCP
                               ├── malloc → copyin → NX-clear → kproc_create
                               └── Kernel thread executes payload
```

### What Each Component Provides

```
ps5-kstuff (branch 1)          hv_research (branch 2)
├── Kekcall dispatch            ├── DMAP base discovery
├── IDT #DB/#GP hooks           ├── Page table walking (VA→PA)
├── doreti_iret return frames   ├── NPT scanning
├── r0gdb primitives            ├── apic_ops hook management
├── malloc/copyin/kproc_create  ├── Persistence markers
└── getpid kekcall gateway      ├── Suspend/resume framework
                                └── Ring-0 shellcode execution
```

### Proposed Merged Architecture

Phase 1 (pre-suspend, current boot):
1. Load kstuff via kldload.elf (branch 1 infrastructure)
2. Run combined payload as kernel thread that:
   - Discovers DMAP base, walks page tables (branch 2 capabilities)
   - Dumps apic_ops table (confirmed working)
   - Scans ktext for ROP gadgets (NEW — needs ktext readable, or use single-stepping)
   - Builds ROP chain in kdata
   - Sets up stack pivot target in kdata
   - Hooks apic_ops[2] → ktext stack pivot gadget
   - Enters rest mode

Phase 2 (resume):
1. apic_ops[2] fires during LAPIC resume
2. Stack pivot → RSP points to ROP chain in kdata
3. ROP chain patches kernel (disable HV protections, install hooks)
4. Returns 1 (APIC_MODE_XAPIC)
5. Kernel resumes normally with patches applied

Phase 3 (post-resume):
1. Re-exploit via umtx2 + etaHEN
2. Verify patches applied
3. Full kernel access without HV restrictions

---

## Open Problems and Next Steps

### 1. ktext Readability for Gadget Scanning
**Problem:** ktext is XOM — we can't read it via DMAP to find gadgets.

**Approaches:**
- **Single-stepping** (flatz's method): Use r0gdb's trace infrastructure to single-step known functions and record instruction addresses/effects. This works because the CPU executes ktext (it's executable), and the debug trap (#DB) captures register state after each instruction.
- **doreti_iret trick**: Use the #GP/TSS trick from flatz's offset document to discover new ktext addresses without pre-existing knowledge.
- **Known offsets**: We already have ~30 ktext addresses from the apic_ops dump + kstuff offsets. Each of these is a known function entry point. The functions they call are also reachable via single-stepping.
- **Post-resume readability**: On some FW versions, ktext becomes readable after resume. Our tests show FW 4.03 keeps XOM post-resume, but this should be re-tested with different resume conditions.

### 2. Stack Pivot Gadget
**Problem:** Need a ktext gadget that redirects RSP to a controlled address.

**Candidates (typical x86-64):**
- `xchg rsp, rax; ret` — if RAX is controlled when apic_ops[2] is called
- `mov rsp, [rbx+N]; ret` — if RBX points to controlled data
- `leave; ret` — if RBP points to controlled data (RBP likely points to kdata stack frame)
- `pop rsp; ret` — direct stack pivot (uncommon but possible)

**How to find them:**
- Single-step the existing apic_ops functions and look for instruction sequences
- Trace the LAPIC suspend/resume path to understand register state when xapic_mode is called
- Use the `rep movsb; pop rbp; ret` gadget from memcpy (mentioned by flatz) to read ktext into userspace

### 3. CFI Bypass
**Problem:** The indirect call `apic_ops[2]()` may be CFI-instrumented.

**Investigation needed:**
- Single-step the apic_ops dispatch to see if CFI checks are present
- Examine whether apic_ops dispatch uses a standard vtable call (which may skip CFI) or an instrumented indirect call
- If CFI is present, find a valid CFI target that serves as a gadget, or corrupt CFI metadata in kdata

### 4. ROP Chain Construction
**Problem:** Need a chain of ktext gadgets that patches the kernel.

**Minimum viable chain:**
1. `wrmsr` gadget — to modify MSRs (disable protections)
2. `mov cr0, <reg>` gadget — to clear WP bit
3. `mov cr4, <reg>` gadget — to clear SMEP/SMAP
4. Memory write gadgets — to patch kernel functions
5. Return gadget — to return 1 (APIC_MODE_XAPIC) and resume

**flatz mentions:** rdmsr and wrmsr_ret can be found by single-stepping interrupt handlers. The `rep movsb; pop rbp; ret` gadget in memcpy provides arbitrary memory read/write.

### 5. Offset Portability (4.50, 4.51)
**Problem:** Other FW versions need offsets but ktext is XOM, preventing dump-based analysis.

**flatz's suggestion:** Develop a network-accessible script that probes the PS5 remotely:
- Survives kernel panics (script runs on PC, not PS5)
- Can detect panics and ask user to reboot
- Automates the single-stepping/probing that was done manually for 4.03
- Allows any PS5 owner to contribute offsets

### 6. Alternative: NPT Modification
**Problem:** If we could modify NPT entries directly, we wouldn't need ROP.

**Status:** VMCB not found in 512MB scan. NPT page tables located (PA 0x6a000, 0x6e000, 0x11564000) but modifying them may be detected by HV integrity checks (similar to how guest PTE XOTEXT clearing prevents rest mode).

### 7. Which apic_ops Slots Are Called When?
**Problem:** We tested only slot[2] (xapic_mode). Other slots may be called only during resume (not suspend), which would allow kdata code execution.

**Investigation:** Hook each slot individually, track which fire during suspend vs resume via persistence markers. Slots called only after HV reinitializes NPT could use kdata trampolines.

---

## Flatz's Offset Finding Methodology (Reference)

For porting to other FW versions, flatz describes these categories:

### Category 1: Kernel Data Offsets (from data dumps)
- IDT, TSS, PCPU (per-cpu arrays), sysentvecs, crypt_singleton_array

### Category 2: Kernel Text from Data Pointers
- Interrupt handlers from IDT (Xinvtlb = IDT[244], Xjustreturn)

### Category 3: doreti_iret (chicken-and-egg, solved via #GP/TSS trick)
1. Set up dedicated IST for #GP (int13) via TSS
2. Background thread writes valid trap frame at known stack address
3. Main thread loads non-canonical RIP via sigreturn → #GP on iret
4. Background thread fixes trap frame → kernel thinks it's userspace crash
5. SIGBUS handler captures m_rip = doreti_iret address

### Category 4: Offsets from Single-Stepping
- rdmsr, wrmsr_ret — from interrupt handler entry
- `rep movsb; pop rbp; ret` — from memcpy, used for kernel R/W
- cpu_switch — binary search on blocking syscall instruction count
- All fSELF/fPKG offsets via syscall tracing

### Category 5: Offsets from Pointer Poisoning (Parasites)
- Replace top 16 bits with 0xdeb7 → non-canonical → #GP → ps5-kstuff logs the dereference
- syscall_before (3rd syscall parasite), fSELF watchpoints, sceSblServiceCryptAsync

---

## Summary

We have two fully working toolchains:
1. **kldload pipeline**: TCP → malloc → copyin → NX-clear → kproc_create (branch 1)
2. **HV research framework**: DMAP, page tables, NPT scanning, apic_ops hooks, suspend/resume testing (branch 2)

The critical finding from 8 sessions of testing: **only ktext is executable during cpususpend_handler**. The path forward is flatz's ROP approach — use ktext gadgets chained together, with the payload in kdata. The next concrete step is building a ktext gadget scanner (via single-stepping or the memcpy read gadget) and identifying a stack pivot.

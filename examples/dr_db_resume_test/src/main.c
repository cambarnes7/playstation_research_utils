#include <stdint.h>

/*
 * dr_db_resume_test v3 — Prove #DB fires during pre-HV resume window
 *
 * KEY INSIGHT: INT3 (#BP, vector 3) is VMCB-intercepted → VMEXIT → crash
 * during resume when HV not ready. But #DB (vector 1) via DR breakpoints
 * is NOT intercepted (proven by kstuff using DR breakpoints). #DB goes
 * directly to the guest IDT without VMEXIT.
 *
 * v3 CHANGE: Don't modify IDT[1] or TSS at all. kstuff owns IDT[1] and
 * uses DR breakpoints on ALL CPUs. Replacing IDT[1] causes kstuff's
 * breakpoints on other CPUs to crash (IDT is global, DRs are per-CPU).
 *
 * Instead: use DR2 (not used by kstuff) and ADD it to kstuff's DR7
 * (preserve existing bits). kstuff's #DB handler will see an unknown
 * DR2 match, ignore it, and iretq back. During resume, kstuff's handler
 * (in ktext, which is executable) handles the #DB bounce.
 *
 * PROOF OF #DB: If the system resumes successfully with DR2=get_timer_freq
 * armed and apic_ops[2]=get_timer_freq being called, #DB MUST have fired
 * and been handled. If #DB wasn't handled, the system would crash.
 * Additionally, we write a sentinel that the readback checks.
 *
 * Modes (via fw_ver):
 *   0x1: ARM — set DR2, update DR7, set apic_ops[2], write sentinel
 *   0x2: READBACK — check DRs persisted, check sentinel, restore all
 *
 * Output layout for Mode 0x1 (ARM):
 *   [0]   magic "DRDB" (0x44524442) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   get_timer_freq address (= DR2 target)
 *   [4]   original apic_ops[2] (xapic_mode)
 *   [5]   apic_ops[2] set to (get_timer_freq)
 *   [6]   kstuff DR0 (preserved)
 *   [7]   kstuff DR1 (preserved)
 *   [8]   kstuff DR2 (original, overwritten)
 *   [9]   kstuff DR3 (preserved)
 *   [10]  kstuff DR7 (original)
 *   [11]  new DR7 (kstuff bits + DR2 enabled)
 *   [12]  sentinel address
 *   [13]  sentinel value
 *   [14]  IDT[1] low (kstuff's handler — NOT modified)
 *   [15]  IDT[1] high
 *   [16]  IDT[1] handler address (decoded)
 *   [17]  IDT[1] IST field
 *   [100] sentinel 0xdeadbeefcafe0050
 *
 * Output layout for Mode 0x2 (READBACK):
 *   [0]   magic "DRDB" (0x44524442) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   current DR0
 *   [4]   current DR1
 *   [5]   current DR2
 *   [6]   current DR3
 *   [7]   current DR7
 *   [8]   DR2 survived? (1 = still get_timer_freq)
 *   [9]   DR7 has DR2 enabled? (1/0)
 *   [10]  sentinel readback
 *   [11]  sentinel survived? (1/0)
 *   [12]  current apic_ops[2]
 *   [13]  apic_ops[2] is still get_timer_freq? (1/0)
 *   [14]  system_alive (always 1 — if you read this, resume worked!)
 *   [15]  restored apic_ops[2]
 *   [16]  restored DR2
 *   [17]  restored DR7
 *   [100] sentinel 0xdeadbeefcafe0051
 */

#define MAGIC_DRDB       0x44524442  /* "DRDB" */

/* FW 4.03 offsets */
#define APIC_OPS_OFF_KTEXT  0x1934AC8
#define IDT_OFF             0x64cdc80

/* Sentinel */
#define KDATA_SENTINEL_OFF   0x200
#define SENTINEL_VAL         0x4452444253454E54ULL  /* "DRDBSENT" */

/* Save area for originals (persists through suspend) */
#define KDATA_SAVE_OFF       0x280

/*
 * DR7 bit layout for DR2:
 *   Bit 4:  L2 (local enable DR2)
 *   Bits 24-25: R/W2 (00 = execution breakpoint)
 *   Bits 26-27: LEN2 (00 = 1 byte)
 * We OR this into the existing DR7 to preserve kstuff's bits.
 */
#define DR7_L2_BIT           (1ULL << 4)

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

static void mode1_arm(uint64_t kdata_base, volatile uint64_t* out, volatile uint32_t* out32)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

    /* Save area for restoring after readback */
    volatile uint64_t* save = (volatile uint64_t*)(kdata_base + KDATA_SAVE_OFF);

    uint64_t get_timer_freq = apic_table[19];

    /* Safety check */
    if (get_timer_freq < MIN_KERN_ADDR) {
        out32[0] = MAGIC_DRDB;
        out32[1] = 0xFE;
        out[1] = get_timer_freq;
        out[100] = 0xdeadbeefcafe00FEULL;
        return;
    }

    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = get_timer_freq;

    /* === Read kstuff's current DR state === */
    uint64_t orig_dr0, orig_dr1, orig_dr2, orig_dr3, orig_dr7;
    __asm__ volatile("mov %%dr0, %0" : "=r"(orig_dr0));
    __asm__ volatile("mov %%dr1, %0" : "=r"(orig_dr1));
    __asm__ volatile("mov %%dr2, %0" : "=r"(orig_dr2));
    __asm__ volatile("mov %%dr3, %0" : "=r"(orig_dr3));
    __asm__ volatile("mov %%dr7, %0" : "=r"(orig_dr7));

    /* Save kstuff's DR2 and DR7 for restore */
    save[0] = orig_dr2;
    save[1] = orig_dr7;

    out[6]  = orig_dr0;
    out[7]  = orig_dr1;
    out[8]  = orig_dr2;
    out[9]  = orig_dr3;
    out[10] = orig_dr7;

    /* === Set DR2 = get_timer_freq (execution breakpoint) ===
     * Use DR2 because kstuff typically uses DR0/DR1.
     * Preserve kstuff's DR7 bits, just add L2 enable.
     * R/W2=00 (execution) and LEN2=00 (1 byte) are the default
     * zero bits at positions 24-27, so we just need to clear those
     * bits (in case kstuff set them) and set L2. */
    __asm__ volatile("mov %0, %%dr2" :: "r"(get_timer_freq));

    /* Build new DR7: preserve kstuff's bits, enable DR2 as exec BP */
    uint64_t new_dr7 = orig_dr7;
    new_dr7 |= DR7_L2_BIT;                  /* enable DR2 local */
    new_dr7 &= ~(0xFULL << 24);             /* clear R/W2 + LEN2 = exec, 1 byte */
    __asm__ volatile("mov %0, %%dr7" :: "r"(new_dr7));

    out[11] = new_dr7;

    /* === Set apic_ops[2] = get_timer_freq === */
    uint64_t original_xapic = apic_table[2];
    save[2] = original_xapic;
    out[4] = original_xapic;

    apic_table[2] = get_timer_freq;
    out[5] = get_timer_freq;

    /* === Sentinel === */
    uint64_t sentinel_addr = kdata_base + KDATA_SENTINEL_OFF;
    write8(sentinel_addr, SENTINEL_VAL);
    out[12] = sentinel_addr;
    out[13] = SENTINEL_VAL;

    /* === Report IDT[1] state (NOT modified — kstuff's handler) === */
    uint64_t idt_base = kdata_base + IDT_OFF;
    uint64_t idt1_lo = read8(idt_base + 1 * 16);
    uint64_t idt1_hi = read8(idt_base + 1 * 16 + 8);
    out[14] = idt1_lo;
    out[15] = idt1_hi;

    /* Decode handler address */
    uint64_t offset_low  = idt1_lo & 0xFFFF;
    uint64_t offset_mid  = (idt1_lo >> 48) & 0xFFFF;
    uint64_t offset_high = idt1_hi & 0xFFFFFFFF;
    out[16] = offset_low | (offset_mid << 16) | (offset_high << 32);

    /* IST field: bits 34:32 of lo qword */
    out[17] = (idt1_lo >> 32) & 0x7;

    out[100] = 0xdeadbeefcafe0050ULL;
    out32[0] = MAGIC_DRDB;
    out32[1] = 0x0001;
}

static void mode2_readback(uint64_t kdata_base, volatile uint64_t* out, volatile uint32_t* out32)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;
    volatile uint64_t* save = (volatile uint64_t*)(kdata_base + KDATA_SAVE_OFF);

    uint64_t get_timer_freq = apic_table[19];

    out[1] = kdata_base;
    out[2] = ktext_base;

    /* === Read current DR state === */
    uint64_t dr0, dr1, dr2, dr3, dr7;
    __asm__ volatile("mov %%dr0, %0" : "=r"(dr0));
    __asm__ volatile("mov %%dr1, %0" : "=r"(dr1));
    __asm__ volatile("mov %%dr2, %0" : "=r"(dr2));
    __asm__ volatile("mov %%dr3, %0" : "=r"(dr3));
    __asm__ volatile("mov %%dr7, %0" : "=r"(dr7));

    out[3] = dr0;
    out[4] = dr1;
    out[5] = dr2;
    out[6] = dr3;
    out[7] = dr7;

    /* DR2 survived rest mode? */
    out[8] = (dr2 == get_timer_freq) ? 1 : 0;
    /* DR7 still has DR2 enabled? */
    out[9] = (dr7 & DR7_L2_BIT) ? 1 : 0;

    /* === Sentinel === */
    uint64_t sentinel_val = read8(kdata_base + KDATA_SENTINEL_OFF);
    out[10] = sentinel_val;
    out[11] = (sentinel_val == SENTINEL_VAL) ? 1 : 0;

    /* === apic_ops[2] state === */
    out[12] = apic_table[2];
    out[13] = (apic_table[2] == get_timer_freq) ? 1 : 0;

    /* If we're reading this, the system is alive = resume worked */
    out[14] = 1;

    /* === Restore apic_ops[2] === */
    uint64_t set_tpr = apic_table[18];
    uint64_t orig_xapic = set_tpr - 8;
    apic_table[2] = orig_xapic;
    out[15] = orig_xapic;

    /* === Restore DR2 and DR7 to kstuff's originals === */
    uint64_t saved_dr2 = save[0];
    uint64_t saved_dr7 = save[1];
    __asm__ volatile("mov %0, %%dr2" :: "r"(saved_dr2));
    __asm__ volatile("mov %0, %%dr7" :: "r"(saved_dr7));
    out[16] = saved_dr2;
    out[17] = saved_dr7;

    out[100] = 0xdeadbeefcafe0051ULL;
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
        out[100] = 0xdeadbeefcafe0055ULL;
    }

    return 0;
}

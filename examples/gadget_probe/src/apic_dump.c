#include <stdint.h>

/*
 * apic_dump — Dump all apic_ops function pointers + nearby vtables
 *
 * Reads the apic_ops vtable (28 function pointers) from kdata and
 * reports them back. Also scans sysent for ktext pointers to build
 * a function boundary map for safe gadget probing.
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "APCD" (0x41504344) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base (from LSTAR)
 *   [3]   apic_ops address (kdata + 0x1656b0)
 *   [4]   number of apic_ops entries dumped (28)
 *   [5..32]  apic_ops[0] through apic_ops[27] — 28 function pointers
 *   [33]  number of sysent ktext pointers found
 *   [34..N] sysent ktext function pointers (deduplicated, sorted)
 */

#define MAGIC_APCD    0x41504344  /* "APCD" */
#define APIC_OPS_OFF  0x1656b0   /* FW 4.03: apic_ops in kdata */
#define SYSENT_OFF    0x1709c0   /* FW 4.03: sysent in kdata */
#define NUM_APIC_OPS  28
#define NUM_SYSCALLS  678        /* FreeBSD ~678 syscalls */

/* sysent entry: { int narg; sy_call_t *func; ... } */
/* On FreeBSD/PS5 amd64: sizeof(struct sysent) = 0x30 (48 bytes) */
#define SYSENT_SIZE   0x30
#define SYSENT_FUNC_OFF 0x08    /* offset of sy_call_t* within sysent entry */

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

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    /* ktext is roughly 0xC00000 bytes, so ktext_end ~ ktext_base + 0xC00000 */
    uint64_t ktext_end = ktext_base + 0xC00000;

    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Header */
    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_APCD;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = kdata_base + APIC_OPS_OFF;
    out[4] = NUM_APIC_OPS;

    /* Dump apic_ops[0..27] */
    volatile uint64_t* apic_ops = (volatile uint64_t*)(kdata_base + APIC_OPS_OFF);
    for (int i = 0; i < NUM_APIC_OPS; i++) {
        out[5 + i] = apic_ops[i];
    }

    /* Scan sysent for unique ktext function pointers */
    volatile uint8_t* sysent_base = (volatile uint8_t*)(kdata_base + SYSENT_OFF);
    uint64_t* sysent_ptrs = (uint64_t*)&out[34]; /* output area */
    int sysent_count = 0;
    int max_sysent = 200; /* cap to fit in readback buffer */

    for (int i = 0; i < NUM_SYSCALLS && sysent_count < max_sysent; i++) {
        uint64_t func = *(volatile uint64_t*)(sysent_base + (i * SYSENT_SIZE) + SYSENT_FUNC_OFF);

        /* Only include ktext pointers */
        if (func < ktext_base || func >= ktext_end)
            continue;

        /* Deduplicate */
        int dup = 0;
        for (int j = 0; j < sysent_count; j++) {
            if (sysent_ptrs[j] == func) { dup = 1; break; }
        }
        if (!dup) {
            sysent_ptrs[sysent_count++] = func;
        }
    }

    /* Simple insertion sort */
    for (int i = 1; i < sysent_count; i++) {
        uint64_t key = sysent_ptrs[i];
        int j = i - 1;
        while (j >= 0 && sysent_ptrs[j] > key) {
            sysent_ptrs[j + 1] = sysent_ptrs[j];
            j--;
        }
        sysent_ptrs[j + 1] = key;
    }

    out[33] = sysent_count;

    return 0;
}

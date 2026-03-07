#include <stdint.h>

/*
 * resume_chain v5 — diagnostics for INT3+IST chain debugging
 *
 * The chain must point apic_ops[2] at ktext (NPT NX blocks non-ktext
 * during suspend). Before rebuilding the chain, we need two diagnostics:
 *
 * Mode (via fw_ver):
 *   0x1: KDATA_DUMP — dump kdata+0x000..0x8B8 (140 qwords) to check
 *        whether our chain data area overlaps kernel globals
 *   0x2: CC_BYTE_TEST — call copyin-1 from kproc with pcb_onfault,
 *        determine whether it's 0xCC (INT3) or something else
 */

#define MAGIC_RSCN       0x5253434E  /* "RSCN" */

/* FW 4.03 offsets */
#define APIC_OPS_OFF_KTEXT  0x1934AC8
#define OFF_COPYIN         (-0x9908e0)

#define MSR_LSTAR          0xC0000082

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

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    for (int i = 0; i < 140; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - 0x294218;

    out32[0] = MAGIC_RSCN;
    out[1] = kdata_base;
    out[2] = ktext_base;

    if (mode == 0x1) {
        /*
         * MODE 1: KDATA DUMP
         *
         * Dump 140 qwords starting at kdata_base+0x000.
         * This reveals what kernel globals live at offsets 0x000..0x8B8
         * where our chain data was being written.
         *
         * out[3..139] = kdata[0x000..0x448] (137 qwords, first 1096 bytes)
         */
        for (int i = 0; i < 137; i++)
            out[3 + i] = read8(kdata_base + i * 8);

        out32[1] = 0x0001;

    } else if (mode == 0x2) {
        /*
         * MODE 2: CC BYTE TEST
         *
         * Call copyin-1 from the kproc to test what byte is there.
         * Uses pcb_onfault for fault recovery.
         *
         * Three possible outcomes:
         *   result=1, RAX=sentinel → byte is 0xC3 (ret), returned immediately
         *   result=1, RAX!=sentinel → byte is 0xCC (INT3), copyin ran, returned error
         *   result=2 → byte caused a fault not caught by copyin's onfault
         */
        uint64_t cc_addr = kdata_base + OFF_COPYIN - 1;
        uint64_t sentinel_val = 0xDEADBEEF12345678ULL;
        uint64_t result_code = 0;
        uint64_t rax_after = 0;
        uint64_t rip_after = 0;

        /* Call the CC byte candidate with pcb_onfault protection */
        __asm__ volatile(
            /* Save callee-saved regs we'll use */
            "pushq %%rbx\n"
            "pushq %%r12\n"
            "pushq %%r13\n"
            "pushq %%r14\n"
            "pushq %%r15\n"

            /* Get curthread → PCB → set onfault */
            "movq %%gs:0, %%r12\n"           /* curthread */
            "movq 0x3f8(%%r12), %%r13\n"     /* td_pcb */
            "leaq 1f(%%rip), %%rax\n"        /* recovery address */
            "movq %%rax, 0x108(%%r13)\n"     /* pcb_onfault = recovery */

            /* Set sentinel in RAX */
            "movq %[sentinel], %%rax\n"

            /* Call the CC byte candidate */
            "callq *%[cc]\n"

            /* Returned normally */
            "movq $1, %[rc]\n"               /* result = 1 (returned) */
            "movq %%rax, %[rax_out]\n"       /* save RAX */
            "leaq (%%rip), %%rax\n"
            "movq %%rax, %[rip_out]\n"       /* save current RIP */
            "jmp 2f\n"

            "1:\n"                           /* fault recovery entry */
            "movq $2, %[rc]\n"               /* result = 2 (faulted) */
            "movq %%rax, %[rax_out]\n"
            "leaq (%%rip), %%rax\n"
            "movq %%rax, %[rip_out]\n"

            "2:\n"
            /* Clear onfault */
            "movq %%gs:0, %%r12\n"
            "movq 0x3f8(%%r12), %%r13\n"
            "movq $0, 0x108(%%r13)\n"

            /* Restore callee-saved regs */
            "popq %%r15\n"
            "popq %%r14\n"
            "popq %%r13\n"
            "popq %%r12\n"
            "popq %%rbx\n"

            : [rc] "=&r"(result_code),
              [rax_out] "=&r"(rax_after),
              [rip_out] "=&r"(rip_after)
            : [cc] "r"(cc_addr),
              [sentinel] "r"(sentinel_val)
            : "rax", "rcx", "rdx", "rdi", "rsi",
              "r8", "r9", "r10", "r11", "memory", "cc"
        );

        out[3] = cc_addr;
        out[4] = result_code;     /* 1=returned, 2=faulted */
        out[5] = rax_after;       /* RAX after call */
        out[6] = sentinel_val;    /* sentinel for comparison */
        out[7] = rip_after;

        /* Interpretation */
        if (result_code == 1 && rax_after == sentinel_val) {
            out[8] = 0xC3C3C3C3ULL; /* likely 0xC3 (ret) */
        } else if (result_code == 1 && rax_after != sentinel_val) {
            out[8] = 0xCCCCCCCCULL; /* likely 0xCC (INT3) → copyin ran */
        } else {
            out[8] = 0xBADBADBADULL; /* faulted — unknown byte */
        }

        out[9] = kdata_base + OFF_COPYIN;  /* copyin addr for reference */

        out32[1] = 0x0001;

    } else {
        out32[1] = 0xFF;
    }

    out[131] = 0xdeadbeefcafe0050ULL;
    return 0;
}

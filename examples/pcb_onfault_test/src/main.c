#include <stdint.h>

/*
 * pcb_onfault_test — Verify pcb_onfault offset empirically
 *
 * Sets pcb+0x108 to a recovery address, then deliberately faults.
 * If pcb_onfault is correct, the fault handler jumps to recovery
 * instead of panicking. Reports success/failure via output buffer.
 *
 * Output layout (uint64_t indices):
 *   [0]     magic "ONFT" (0x4f4e4654) | status(32)
 *   [1]     kdata_base
 *   [2]     ktext_base
 *   [3]     curthread
 *   [4]     td_pcb
 *   [5]     pcb_onfault_offset tested
 *   [6]     value written to pcb_onfault (recovery address)
 *   [7]     fault test result: 0xCAFE0001 = recovered, 0 = didn't fault
 *   [8]     value read back from faulting address (if no fault)
 *   [9]     eflags/error code if available
 *   [10]    pcb_onfault value AFTER test (should be 0, kernel clears it)
 *   [11]    sentinel 0xdeadbeefcafe0019
 */

#define MAGIC_ONFT  0x4f4e4654  /* "ONFT" */

#define PCPU_ARRAY_OFF  0x64d2280
#define TD_PCB          0x3f8

/* The offset we're testing */
#define PCB_ONFAULT_OFF 0x108

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
    return *(volatile uint64_t*)addr;
}

static inline void write8(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t*)addr = val;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 64; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    /* Header */
    out32[0] = MAGIC_ONFT;
    out32[1] = 0xAAAA;  /* in-progress */
    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Get curthread and PCB */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    out[3] = curthread;

    uint64_t td_pcb = read8(curthread + TD_PCB);
    out[4] = td_pcb;
    out[5] = PCB_ONFAULT_OFF;

    if (!td_pcb) {
        out32[1] = 0xFF;  /* error */
        out[11] = 0xdeadbeefcafe0019ULL;
        return 0;
    }

    /*
     * The test:
     * 1. Set pcb+0x108 to address of our recovery code
     * 2. Try to read from unmapped address 0xDEAD000000000000
     * 3. If fault recovery works, we land at recovery and set marker
     * 4. If it panics, offset is wrong
     *
     * FreeBSD's trap handler checks pcb_onfault: if non-NULL on a
     * page fault, it sets tf_rip = pcb_onfault and returns.
     * The faulting instruction's result register gets 0 or -1 depending
     * on the specific copyin/copyout wrapper.
     *
     * We use inline asm to set up a recovery label and do the
     * faulting load, so we can detect if we reached recovery.
     */

    volatile uint64_t fault_result = 0;
    volatile uint64_t read_val = 0;

    /*
     * Use asm to:
     * 1. Write recovery address to pcb_onfault
     * 2. Attempt faulting read
     * 3. Recovery label clears pcb_onfault and sets marker
     */
    __asm__ volatile(
        /* Save pcb address in r15 (callee-saved, we restore later) */
        "movq %[pcb], %%r15\n\t"

        /* Calculate address of .Lrecovery and write to pcb+0x108 */
        "leaq .Lrecovery(%%rip), %%rax\n\t"
        "movq %%rax, %[recovery_addr]\n\t"       /* save for output */
        "movq %%rax, 0x108(%%r15)\n\t"            /* set pcb_onfault */

        /* Attempt the faulting read */
        "movabsq $0xDEAD000000000000, %%rax\n\t"
        "movq (%%rax), %%rbx\n\t"                 /* THIS SHOULD FAULT */

        /* If we get here, no fault occurred (unexpected) */
        "movq %%rbx, %[read_val]\n\t"
        "jmp .Ldone\n\t"

        ".Lrecovery:\n\t"
        /* Fault handler jumped here! pcb_onfault worked! */
        /* Clear pcb_onfault so we don't interfere with anything */
        "movq $0, 0x108(%%r15)\n\t"
        "movl $0xCAFE, %%eax\n\t"
        "shlq $16, %%rax\n\t"
        "orq $0x0001, %%rax\n\t"
        "movq %%rax, %[fault_result]\n\t"

        ".Ldone:\n\t"
        : [fault_result] "=m"(fault_result),
          [read_val] "=m"(read_val),
          [recovery_addr] "=m"(out[6])
        : [pcb] "r"(td_pcb)
        : "rax", "rbx", "r15", "memory"
    );

    out[7] = fault_result;
    out[8] = read_val;

    /* Read back pcb_onfault after test (should be 0) */
    out[10] = read8(td_pcb + PCB_ONFAULT_OFF);

    out[11] = 0xdeadbeefcafe0019ULL;

    /* Set final status */
    if (fault_result == 0xCAFE0001)
        out32[1] = 0x0001;  /* PASS - onfault works! */
    else
        out32[1] = 0x0002;  /* no fault occurred (weird) */

    return 0;
}

#include <stdint.h>

/*
 * pcb_onfault_test v2 — Verify pcb_onfault offset empirically
 *
 * Takes the PCB offset to test from args->fw_ver.
 * Use the fw_ver override command to set the offset before sending:
 *   printf '\x10\x01\x00\x00' | nc PS5 9022   # test offset 0x110
 *   nc PS5 9022 < pcb_onfault_test.bin
 *
 * Sets pcb+<offset> to a recovery address, then deliberately faults.
 * If pcb_onfault is at that offset, the fault handler jumps to recovery.
 * If wrong, the thread dies (but system survives).
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
 *   [9]     pcb value at offset BEFORE write (for diagnostics)
 *   [10]    pcb_onfault value AFTER test (should be 0 if kernel clears it)
 *   [11]    sentinel 0xdeadbeefcafe0019
 */

#define MAGIC_ONFT  0x4f4e4654  /* "ONFT" */
#define TD_PCB      0x3f8

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

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t test_offset = args->fw_ver;
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

    /* Validate offset range */
    if (test_offset < 0x100 || test_offset > 0x148 || (test_offset & 7) != 0) {
        /* Bad offset — refuse to run */
        out[5] = test_offset;
        out32[1] = 0xFD;  /* bad offset */
        out[11] = 0xdeadbeefcafe0019ULL;
        return 0;
    }

    /* Get curthread and PCB */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    out[3] = curthread;

    uint64_t td_pcb = read8(curthread + TD_PCB);
    out[4] = td_pcb;
    out[5] = test_offset;

    if (!td_pcb) {
        out32[1] = 0xFF;  /* error */
        out[11] = 0xdeadbeefcafe0019ULL;
        return 0;
    }

    /* Read current value at the test offset (for diagnostics) */
    out[9] = read8(td_pcb + test_offset);

    volatile uint64_t fault_result = 0;
    volatile uint64_t read_val = 0;

    /*
     * The asm block:
     * - r15 = td_pcb base address
     * - r14 = test_offset
     * - Write recovery address to pcb+offset
     * - Attempt faulting read from 0xDEAD000000000000
     * - Recovery label sets 0xCAFE0001 marker
     */
    __asm__ volatile(
        "movq %[pcb], %%r15\n\t"
        "movq %[offset], %%r14\n\t"
        "addq %%r15, %%r14\n\t"        /* r14 = pcb + offset */

        /* Write recovery address */
        "leaq .Lrecovery2(%%rip), %%rax\n\t"
        "movq %%rax, %[recovery_addr]\n\t"
        "movq %%rax, (%%r14)\n\t"       /* pcb[offset] = recovery */

        /* Attempt faulting read */
        "movabsq $0xDEAD000000000000, %%rax\n\t"
        "movq (%%rax), %%rbx\n\t"       /* SHOULD FAULT */

        /* No fault path */
        "movq %%rbx, %[read_val]\n\t"
        "movq $0, (%%r14)\n\t"          /* clean up */
        "jmp .Ldone2\n\t"

        ".Lrecovery2:\n\t"
        /* Fault recovered! Clear onfault and set marker */
        "movq $0, (%%r14)\n\t"
        "movl $0xCAFE, %%eax\n\t"
        "shlq $16, %%rax\n\t"
        "orq $0x0001, %%rax\n\t"
        "movq %%rax, %[fault_result]\n\t"

        ".Ldone2:\n\t"
        : [fault_result] "=m"(fault_result),
          [read_val] "=m"(read_val),
          [recovery_addr] "=m"(out[6])
        : [pcb] "r"(td_pcb),
          [offset] "r"((uint64_t)test_offset)
        : "rax", "rbx", "r14", "r15", "memory"
    );

    out[7] = fault_result;
    out[8] = read_val;

    /* Read back the offset after test */
    out[10] = read8(td_pcb + test_offset);

    out[11] = 0xdeadbeefcafe0019ULL;

    /* Set final status */
    if (fault_result == 0xCAFE0001)
        out32[1] = 0x0001;  /* PASS */
    else
        out32[1] = 0x0002;  /* no fault */

    return 0;
}

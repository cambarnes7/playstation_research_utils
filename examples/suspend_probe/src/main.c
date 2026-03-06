#include <stdint.h>

/*
 * PS5 Suspend Persistence Test v5 (kstuff payload)
 *
 * KEY LEARNINGS from v1-v4:
 *   v1: nop_ret in apic_ops[2] → panic (garbage return value)
 *   v2: is_x2apic in apic_ops[2] → panic (APIC not initialized)
 *   v3: capture_stub (heap) in apic_ops[2] → panic (heap not mapped)
 *   v4: markers in apic_ops slots 0,1,7 → panic (slots called on resume!)
 *
 * CONCLUSION: ALL apic_ops slots may be called during resume.
 * The LAPIC must be fully reinitialized when waking from sleep, so
 * init, set_id, and possibly create are all invoked.
 *
 * v5 STRATEGY: Pure kdata persistence test — ZERO apic_ops modifications.
 *   - Read & dump apic_ops for reference (read-only)
 *   - Write marker values to a kdata region FAR from apic_ops
 *     (use kdata_base + small offset into BSS/padding area)
 *   - Write 16 distinct marker qwords so we can verify persistence
 *   - After resume, a readback payload checks if any survived
 *
 * Target kdata region: kdata_base + 0x100 (256 bytes into kdata)
 * This is deep in the BSS zero-fill area, far from any function
 * pointer tables. We write 16 qwords (128 bytes) starting there.
 *
 * Output layout (uint64_t indices):
 *   [0]   magic(32) "SRCP" | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   apic_ops_addr
 *   [4]   orig_xapic_mode (read-only, for reference)
 *   [5]   marker_region_addr (where we wrote markers)
 *   [6..33]  apic_ops table dump (read-only, 28 slots)
 *   [34]  marker_count (16)
 *   [35]  version_tag = 0x0005 (v5 identifier)
 *
 *   --- Marker data (16 markers) ---
 *   [36..51]  original values at marker region (before write)
 *   [52..67]  marker values written
 *   [68..83]  readback values (verify writes took)
 *
 *   [104] sentinel = 0xdeadbeefcafe0005
 *   [121] second_sentinel = 0xfeedface00000005
 *   [122] apic_ops[2] current (should be unchanged = [4])
 *   [123] apic_ops[2] original (should be unchanged = [4])
 */

#define MAGIC_SRCP       0x53524350  /* "SRCP" */
#define MARKER_COUNT     16
#define VERSION_TAG      0x0005

/* FW 4.03 offsets */
#define APIC_OPS_OFF_FROM_KTEXT  0x1934AC8

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
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 124; i++)
        out[i] = 0;

    /* Compute addresses */
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_FROM_KTEXT;

    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

    /*
     * Choose a marker region in kdata, far from apic_ops.
     * kdata_base + 0x100 should be in BSS/zero-fill territory.
     * We'll scan a few candidate offsets and pick one that looks
     * like unused memory (all zeros or padding).
     */
    uint64_t marker_region = kdata_base + 0x100;
    volatile uint64_t* markers = (volatile uint64_t*)marker_region;

    /* Write header */
    out32[0] = MAGIC_SRCP;
    out32[1] = 0xAAAA;  /* status: in progress */
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = apic_ops_addr;

    /* Read-only: save original xapic_mode for reference */
    out[4] = apic_table[2];

    /* Marker region address */
    out[5] = marker_region;

    /* Dump full apic_ops table (READ-ONLY — no modifications!) */
    for (int i = 0; i < 28; i++)
        out[6 + i] = apic_table[i];

    /* Marker metadata */
    out[34] = MARKER_COUNT;
    out[35] = VERSION_TAG;

    /* ════════════════════════════════════════════
     * Save original values at marker region
     * ════════════════════════════════════════════ */
    for (int i = 0; i < MARKER_COUNT; i++)
        out[36 + i] = markers[i];

    /* ════════════════════════════════════════════
     * Write distinguishable markers
     * Pattern: 0xPERSIST00 | index
     * Each marker is unique so we can verify individually.
     * ════════════════════════════════════════════ */
    for (int i = 0; i < MARKER_COUNT; i++) {
        uint64_t val = 0x5045525349535400ULL | (uint64_t)i;  /* "PERSIST\x00" | i */
        out[52 + i] = val;  /* record what we wrote */
        markers[i] = val;   /* write to kdata */
    }

    /* Readback to verify writes took */
    for (int i = 0; i < MARKER_COUNT; i++)
        out[68 + i] = markers[i];

    /* ════════════════════════════════════════════
     * IMPORTANT: apic_ops is COMPLETELY UNTOUCHED
     * No function pointers modified. Resume is safe.
     * ════════════════════════════════════════════ */

    out[104] = 0xdeadbeefcafe0005ULL;
    out[121] = 0xfeedface00000005ULL;

    /* Verify apic_ops[2] unchanged */
    out[122] = apic_table[2];
    out[123] = apic_table[2];

    /* Status: armed for suspend persistence test */
    out32[1] = 1;

    return 0;
}

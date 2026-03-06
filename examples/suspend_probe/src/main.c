#include <stdint.h>

/*
 * PS5 Suspend Persistence Test v4 (kstuff payload)
 *
 * KEY LEARNING from v1-v3:
 *   v1: nop_ret in apic_ops[2] → panic (garbage return value)
 *   v2: is_x2apic in apic_ops[2] → panic (APIC not initialized)
 *   v3: capture_stub (heap) in apic_ops[2] → panic (heap not mapped
 *       during early resume — only ktext/kdata are accessible)
 *
 * CONCLUSION: During early resume, only the kernel image (ktext + kdata)
 * is mapped. Heap pages (0xffffff80...) are NOT accessible. Any function
 * pointer called during resume MUST point into ktext.
 *
 * v4 STRATEGY: Safe kdata persistence test.
 *   - Leave apic_ops[2] (xapic_mode) UNTOUCHED → no panic
 *   - Write distinguishable ktext pointers to SAFE slots that are
 *     NOT called during resume (create/slot 0, init/slot 1)
 *   - Also write markers to kdata locations NEAR apic_ops
 *   - After resume, read back everything to check if writes persisted
 *
 * If kdata writes persist through suspend/resume, the CFI bypass
 * strategy is confirmed: we can write a ROP chain into kdata and
 * point apic_ops[2] at a ktext pivot gadget.
 *
 * SAFE SLOTS (not called during suspend/resume):
 *   slot 0 (create)  - LAPIC driver registration, boot-time only
 *   slot 1 (init)    - LAPIC init, boot-time only
 *   slot 7 (set_id)  - sets LAPIC ID, boot-time only
 *
 * Output layout (uint64_t indices):
 *   [0]   magic(32) "SRCP" | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   apic_ops_addr
 *   [4]   orig_xapic_mode
 *   [5]   test_slot_count(32) | pad(32)
 *   [6..33]  apic_ops table dump BEFORE modification (28 slots)
 *   [34]  test_marker_base (ktext addr used as marker)
 *   [35]  capture_stub_addr (for reference)
 *
 *   --- Test slot info (3 test slots) ---
 *   [36]  slot0_original
 *   [37]  slot0_marker (what we wrote)
 *   [38]  slot0_readback (verify write worked)
 *   [39]  slot1_original
 *   [40]  slot1_marker
 *   [41]  slot1_readback
 *   [42]  slot7_original
 *   [43]  slot7_marker
 *   [44]  slot7_readback
 *
 *   --- kdata marker area (write to kdata near apic_ops) ---
 *   [45]  kdata_marker_addr (apic_ops + 28*8 = just past table)
 *   [46]  kdata_marker_written
 *   [47]  kdata_marker_readback
 *   [48]  kdata_marker2_addr (apic_ops - 8)
 *   [49]  kdata_marker2_written
 *   [50]  kdata_marker2_readback
 *
 *   [104] sentinel = 0xdeadbeefcafe0005
 *   [121] second_sentinel = 0xfeedface00000005
 *   [122] reserved
 *   [123] reserved
 */

#define MAGIC_SRCP       0x53524350  /* "SRCP" */

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

    /* Write header */
    out32[0] = MAGIC_SRCP;
    out32[1] = 0xAAAA;  /* status: in progress */
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = apic_ops_addr;

    /* Save originals */
    uint64_t original_slot2 = apic_table[2];
    out[4] = original_slot2;

    /* Dump full apic_ops table BEFORE modification (28 slots) */
    for (int i = 0; i < 28; i++)
        out[6 + i] = apic_table[i];

    /*
     * Use distinguishable ktext addresses as markers.
     * We'll use existing ktext function addresses that are NOT the
     * original values — specifically, swap some values around so
     * we can detect if they persist.
     *
     * Marker strategy: use is_x2apic (slot 3's original value) as
     * the marker for slots 0, 1, 7. This is a valid ktext pointer
     * that won't cause issues even if somehow called (returns 0).
     */
    uint64_t marker_base = apic_table[3]; /* is_x2apic - known safe ktext */
    out[34] = marker_base;
    out[35] = 0; /* no capture_stub in v4 */

    /* Number of test slots */
    out32[10] = 3;

    /* ════════════════════════════════════════════
     * TEST 1: Write markers to safe apic_ops slots
     *
     * These slots are only called during boot, never during
     * suspend/resume. Writing to them is safe.
     * ════════════════════════════════════════════ */

    /* Slot 0 (create) — marker = is_x2apic XOR 0x1 (distinguishable) */
    uint64_t slot0_orig = apic_table[0];
    uint64_t slot0_marker = marker_base | 0x0;  /* is_x2apic itself */
    out[36] = slot0_orig;
    out[37] = slot0_marker;
    apic_table[0] = slot0_marker;
    out[38] = apic_table[0]; /* readback to verify */

    /* Slot 1 (init) — marker = get_timer_freq (slot 19, different value) */
    uint64_t slot1_orig = apic_table[1];
    uint64_t slot1_marker = apic_table[19]; /* get_timer_freq */
    out[39] = slot1_orig;
    out[40] = slot1_marker;
    apic_table[1] = slot1_marker;
    out[41] = apic_table[1]; /* readback */

    /* Slot 7 (set_id) — marker = self_ipi (slot 25, very different addr) */
    uint64_t slot7_orig = apic_table[7];
    uint64_t slot7_marker = apic_table[25]; /* self_ipi - far away in ktext */
    out[42] = slot7_orig;
    out[43] = slot7_marker;
    apic_table[7] = slot7_marker;
    out[44] = apic_table[7]; /* readback */

    /* ════════════════════════════════════════════
     * TEST 2: Write markers to kdata near apic_ops
     *
     * Write to the qword just past the 28-slot table, and
     * the qword just before the table. These should be padding
     * or adjacent data structures.
     * ════════════════════════════════════════════ */

    /* Marker just past apic_ops table (offset +224 = slot 28) */
    volatile uint64_t* kdata_marker_ptr = &apic_table[28];
    uint64_t kdata_marker_val = 0xCAFE0005BABE0004ULL;
    out[45] = (uint64_t)kdata_marker_ptr;
    out[46] = kdata_marker_val;
    *kdata_marker_ptr = kdata_marker_val;
    out[47] = *kdata_marker_ptr; /* readback */

    /* Marker just before apic_ops table (offset -8) */
    volatile uint64_t* kdata_marker2_ptr = (volatile uint64_t*)(apic_ops_addr - 8);
    uint64_t kdata_marker2_orig = *kdata_marker2_ptr;
    uint64_t kdata_marker2_val = 0xDEAD0005BEEF0004ULL;
    out[48] = (uint64_t)kdata_marker2_ptr;
    out[49] = kdata_marker2_val;
    /* Only write if it looks safe (not a critical pointer) */
    if (kdata_marker2_orig == 0 || (kdata_marker2_orig & 0xFFFF) == 0) {
        *kdata_marker2_ptr = kdata_marker2_val;
        out[50] = *kdata_marker2_ptr;
    } else {
        /* Looks like it holds important data, skip */
        out[50] = kdata_marker2_orig;
        out[49] = 0; /* signal: didn't write */
    }

    /* ════════════════════════════════════════════
     * IMPORTANT: apic_ops[2] is LEFT UNTOUCHED
     * xapic_mode remains the original function.
     * Resume will work normally.
     * ════════════════════════════════════════════ */

    out[104] = 0xdeadbeefcafe0005ULL;
    out[121] = 0xfeedface00000005ULL;

    /* Store what apic_ops[2] currently is (should be unchanged) */
    out[122] = apic_table[2];
    out[123] = original_slot2;

    /* Status: armed for suspend persistence test */
    out32[1] = 1;

    return 0;
}

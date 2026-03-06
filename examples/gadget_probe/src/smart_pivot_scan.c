#include <stdint.h>

/*
 * smart_pivot_scan v9 — Fit results in 8 visible output slots
 *
 * The kldload dump tool only shows [0x00]-[0x38] (8 qwords).
 * So we pack everything into those 8 slots.
 *
 * Strategy: scan all of kdata (4MB per batch) for ktext pointers,
 * but instead of storing individual pointers, report:
 *   - Count of ktext ptrs found
 *   - First 5 unique ktext offsets (packed into slots 3-7)
 *
 * With SCAN_BATCH we can page through results:
 *   batch 0: report ktext ptrs #0-#4
 *   batch 1: report ktext ptrs #5-#9
 *   etc.
 *
 * Each ktext offset is stored as a 32-bit value (max 12MB range fits).
 * We pack 2 offsets per slot (low 32 = even, high 32 = odd).
 *
 * Slot layout:
 *   [0] tag|magic
 *   [1] kdata_base
 *   [2] ktext_base
 *   [3] n_total_ktext_ptrs (32-bit) | batch (16-bit) | flags (16-bit)
 *   [4] ktext_off[0] | ktext_off[1]   (each 32-bit)
 *   [5] ktext_off[2] | ktext_off[3]
 *   [6] ktext_off[4] | ktext_off[5]
 *   [7] ktext_off[6] | ktext_off[7]
 *
 * That's 8 ktext offsets per run. SCAN_BATCH selects which 8:
 *   batch N reports offsets N*8 through N*8+7 (skipping duplicates).
 *
 * Configure: -DSCAN_BATCH=N
 */

#ifndef SCAN_BATCH
#define SCAN_BATCH     0
#endif

#define MAGIC_SPVT     0x53505654
#define KTEXT_SIZE     0xC00000     /* 12MB */
#define SCAN_SIZE      0x400000     /* scan first 4MB of kdata */
#define RESULTS_PER_BATCH  8

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
    uint64_t ktext_end = ktext_base + KTEXT_SIZE;

    volatile uint64_t* out = (volatile uint64_t*)args;

    for (int i = 0; i < 8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Scan kdata for ktext pointers.
     * Deduplicate: only count unique ktext offsets (page-aligned).
     * We use a simple bitmap for 12MB / 4KB = 3072 pages = 384 bytes.
     * But we don't have .bss here, so use a portion of the output
     * buffer (slots 8+ which won't be read back) as scratch. */

    /* We'll track unique ktext offsets in a simpler way:
     * Just collect raw offsets, skip the N*8 first, report next 8. */

    int skip_count = SCAN_BATCH * RESULTS_PER_BATCH;
    int n_total = 0;
    int n_reported = 0;
    uint32_t results[RESULTS_PER_BATCH];

    for (int i = 0; i < RESULTS_PER_BATCH; i++)
        results[i] = 0;

    volatile uint64_t* scan_ptr = (volatile uint64_t*)kdata_base;
    uint64_t n_qwords = SCAN_SIZE / 8;

    for (uint64_t i = 0; i < n_qwords; i++) {
        uint64_t val = scan_ptr[i];

        if (val >= ktext_base && val < ktext_end) {
            if (n_total >= skip_count && n_reported < RESULTS_PER_BATCH) {
                results[n_reported] = (uint32_t)(val - ktext_base);
                n_reported++;
            }
            n_total++;
        }
    }

    /* Pack results: 2 offsets per slot */
    out[4] = (uint64_t)results[0] | ((uint64_t)results[1] << 32);
    out[5] = (uint64_t)results[2] | ((uint64_t)results[3] << 32);
    out[6] = (uint64_t)results[4] | ((uint64_t)results[5] << 32);
    out[7] = (uint64_t)results[6] | ((uint64_t)results[7] << 32);

    /* Slot 3: total count (low 32), batch (bits 32-47), n_reported (bits 48-63) */
    out[3] = (uint64_t)(n_total & 0xFFFFFFFF) |
             ((uint64_t)(SCAN_BATCH & 0xFFFF) << 32) |
             ((uint64_t)(n_reported & 0xFFFF) << 48);

    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;

    return 0;
}

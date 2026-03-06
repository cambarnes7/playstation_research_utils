#include <stdint.h>

/*
 * smart_pivot_scan v10 — Unique ktext pages as 16-bit indices
 *
 * 3435 total ktext pointers but many are duplicates (same function
 * referenced from multiple vtable entries). Deduplicate by page
 * (4KB aligned) and report as 16-bit page indices.
 *
 * ktext = 12MB = 3072 pages → page index fits in 12 bits.
 * Pack as 16-bit values: 4 per slot × 4 data slots = 16 per batch.
 *
 * Also: two modes controlled by SCAN_BATCH:
 *   SCAN_BATCH < 0x100: report unique page indices (batch N = pages N*16..N*16+15)
 *   SCAN_BATCH = 0xFF:  summary mode — just report total unique pages + range
 *
 * Slot layout:
 *   [0] tag|magic
 *   [1] kdata_base
 *   [2] ktext_base
 *   [3] n_unique_pages[15:0] | n_total_ptrs[31:16] | batch[47:32] | flags[63:48]
 *   [4..7] 16 × 16-bit page indices (4 per slot)
 *
 * For summary mode (0xFF):
 *   [4] min_page_idx[15:0] | max_page_idx[31:16] | first_kdata_off[63:32]
 *   [5] LSTAR value
 *   [6] n_unique_pages (full 64-bit for verification)
 *   [7] reserved
 */

#ifndef SCAN_BATCH
#define SCAN_BATCH     0xFF   /* default: summary mode */
#endif

#define MAGIC_SPVT     0x53505654
#define KTEXT_SIZE     0xC00000     /* 12MB */
#define PAGE_SIZE_K    0x1000       /* 4KB */
#define N_KTEXT_PAGES  (KTEXT_SIZE / PAGE_SIZE_K)  /* 3072 */
#define SCAN_SIZE      0x400000     /* scan first 4MB of kdata */
#define PAGES_PER_BATCH 16

/* Bitmap for 3072 pages = 384 bytes = 48 uint64_t */
#define BITMAP_U64S    ((N_KTEXT_PAGES + 63) / 64)  /* 48 */

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

    /* Use output buffer beyond slot 8 as scratch for bitmap.
     * Slots 0-7 = 64 bytes. Slots 8+ = 2304-64 = 2240 bytes.
     * Bitmap needs 384 bytes → fits in slots 8..55. */
    volatile uint64_t* bitmap = &out[8];

    /* Clear everything */
    for (int i = 0; i < 2304/8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Scan kdata and build page bitmap */
    volatile uint64_t* scan_ptr = (volatile uint64_t*)kdata_base;
    uint64_t n_qwords = SCAN_SIZE / 8;
    int n_total_ptrs = 0;

    for (uint64_t i = 0; i < n_qwords; i++) {
        uint64_t val = scan_ptr[i];

        if (val >= ktext_base && val < ktext_end) {
            n_total_ptrs++;
            uint32_t page_idx = (uint32_t)((val - ktext_base) / PAGE_SIZE_K);
            if (page_idx < N_KTEXT_PAGES) {
                bitmap[page_idx / 64] |= (1ULL << (page_idx % 64));
            }
        }
    }

    /* Count unique pages and collect indices */
    int n_unique = 0;
    uint16_t min_page = 0xFFFF, max_page = 0;

    /* Summary mode or paged mode? */
    int batch = SCAN_BATCH;
    int skip = batch * PAGES_PER_BATCH;
    int n_reported = 0;
    uint16_t results[PAGES_PER_BATCH];
    for (int i = 0; i < PAGES_PER_BATCH; i++) results[i] = 0;

    for (int pg = 0; pg < N_KTEXT_PAGES; pg++) {
        if (bitmap[pg / 64] & (1ULL << (pg % 64))) {
            if (pg < min_page) min_page = pg;
            if (pg > max_page) max_page = pg;

            if (batch != 0xFF) {
                if (n_unique >= skip && n_reported < PAGES_PER_BATCH) {
                    results[n_reported] = (uint16_t)pg;
                    n_reported++;
                }
            }
            n_unique++;
        }
    }

    /* Pack header */
    out[3] = (uint64_t)(n_unique & 0xFFFF) |
             ((uint64_t)(n_total_ptrs & 0xFFFF) << 16) |
             ((uint64_t)(batch & 0xFFFF) << 32) |
             ((uint64_t)(n_reported & 0xFFFF) << 48);

    if (batch == 0xFF) {
        /* Summary mode */
        out[4] = (uint64_t)min_page |
                 ((uint64_t)max_page << 16) |
                 ((uint64_t)0 << 32);
        out[5] = lstar;
        out[6] = n_unique;
        out[7] = n_total_ptrs;
    } else {
        /* Paged mode: pack 16-bit page indices, 4 per slot */
        out[4] = (uint64_t)results[0]  | ((uint64_t)results[1] << 16) |
                 ((uint64_t)results[2] << 32) | ((uint64_t)results[3] << 48);
        out[5] = (uint64_t)results[4]  | ((uint64_t)results[5] << 16) |
                 ((uint64_t)results[6] << 32) | ((uint64_t)results[7] << 48);
        out[6] = (uint64_t)results[8]  | ((uint64_t)results[9] << 16) |
                 ((uint64_t)results[10] << 32) | ((uint64_t)results[11] << 48);
        out[7] = (uint64_t)results[12] | ((uint64_t)results[13] << 16) |
                 ((uint64_t)results[14] << 32) | ((uint64_t)results[15] << 48);
    }

    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;

    return 0;
}

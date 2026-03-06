#include <stdint.h>

/*
 * smart_pivot_scan v8 — Wide kdata scan with diagnostics
 *
 * Scans 4MB of kdata per batch. Also counts values in broader
 * kernel range [0xffffffff80000000, 0xffffffffc0000000) for
 * diagnostics — tells us if there are ANY kernel pointers even
 * if they're outside the strict ktext range.
 *
 * Reports: min/max kernel pointer found, ktext hits, broad kernel hits.
 *
 * Configure via -D flags:
 *   SCAN_BATCH: chunk index (each scans 4MB of kdata)
 */

#ifndef SCAN_BATCH
#define SCAN_BATCH     0
#endif

#define MAGIC_SPVT     0x53505654
#define KTEXT_SIZE     0xC00000     /* 12MB */
#define CHUNK_SIZE     0x400000     /* 4MB per batch */
#define HEADER_SLOTS   12
#define MAX_RESULTS    ((2304/8) - HEADER_SLOTS)  /* ~276 result slots */

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

    /* Broad kernel range for diagnostics */
    uint64_t kern_lo = 0xffffffff80000000ULL;
    uint64_t kern_hi = 0xffffffffc0000000ULL;

    volatile uint64_t* out = (volatile uint64_t*)args;

    for (int i = 0; i < 2304/8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = (uint64_t)SCAN_BATCH;

    uint64_t scan_start = kdata_base + (uint64_t)SCAN_BATCH * CHUNK_SIZE;
    uint64_t scan_end = scan_start + CHUNK_SIZE;

    /* Allow scanning up to 64MB of kdata */
    uint64_t max_kdata = kdata_base + 0x4000000;  /* 64MB */
    if (scan_end > max_kdata)
        scan_end = max_kdata;
    if (scan_start >= max_kdata) {
        out[0] = ((uint64_t)0xFFFF << 32) | MAGIC_SPVT;
        return 0;
    }

    out[4] = scan_start;
    out[5] = scan_end;

    int n_ktext_ptrs = 0;      /* pointers into ktext range */
    int n_kern_ptrs = 0;       /* pointers into broad kernel range */
    int n_results = 0;
    uint64_t min_kern_val = ~0ULL;
    uint64_t max_kern_val = 0;
    uint64_t first_nonzero_off = ~0ULL;  /* first non-zero qword offset */

    volatile uint64_t* scan_ptr = (volatile uint64_t*)scan_start;
    uint64_t n_qwords = (scan_end - scan_start) / 8;

    for (uint64_t i = 0; i < n_qwords; i++) {
        uint64_t val = scan_ptr[i];

        if (val == 0) continue;

        if (first_nonzero_off == ~0ULL)
            first_nonzero_off = i * 8;

        /* Check broad kernel range */
        if (val >= kern_lo && val < kern_hi) {
            n_kern_ptrs++;
            if (val < min_kern_val) min_kern_val = val;
            if (val > max_kern_val) max_kern_val = val;

            /* Check strict ktext range */
            if (val >= ktext_base && val < ktext_end) {
                n_ktext_ptrs++;

                if (n_results < MAX_RESULTS) {
                    uint64_t kdata_off = (scan_start + i * 8) - kdata_base;
                    uint64_t ktext_off = val - ktext_base;
                    out[HEADER_SLOTS + n_results] = (kdata_off & 0xFFFFFFFF) |
                                                    (ktext_off << 32);
                    n_results++;
                }
            }
        }
    }

    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    out[3] |= ((uint64_t)n_results << 16);
    out[6] = n_ktext_ptrs;
    out[7] = n_kern_ptrs;
    out[8] = min_kern_val;   /* min kernel pointer value found */
    out[9] = max_kern_val;   /* max kernel pointer value found */
    out[10] = first_nonzero_off; /* offset of first non-zero qword from scan_start */
    out[11] = n_qwords;

    return 0;
}

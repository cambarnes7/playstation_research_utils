#include <stdint.h>

/*
 * smart_pivot_scan v7 — Scan kdata for ktext function pointers
 *
 * PS5 ktext is EPT execute-only — can't read code bytes.
 * Instead, scan kdata (fully readable) for qword values that
 * fall within the ktext range. These are function pointers from
 * vtables, ops structs, GOT, jump tables, etc.
 *
 * This gives us a dense map of valid ktext code addresses.
 * We can then use the gaps between consecutive pointers to
 * identify function boundaries and epilogue regions.
 *
 * Each batch scans 1MB of kdata. kdata is ~100MB on PS5 FW 4.03
 * but most function pointers are in the first ~16MB.
 *
 * Configure via -D flags:
 *   SCAN_BATCH: chunk index (each scans 1MB of kdata)
 */

#ifndef SCAN_BATCH
#define SCAN_BATCH     0
#endif

#define MAGIC_SPVT     0x53505654
#define KTEXT_SIZE     0xC00000     /* 12MB */
#define CHUNK_SIZE     0x100000     /* 1MB per batch */
#define HEADER_SLOTS   8
#define MAX_RESULTS    ((2304/8) - HEADER_SLOTS)  /* ~282 result slots */

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

    for (int i = 0; i < 2304/8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = (uint64_t)SCAN_BATCH;

    /* Scan kdata for qwords pointing into ktext.
     * kdata is at kdata_base. We scan from kdata_base + batch*1MB.
     * Skip first 4KB (might overlap with unmapped region). */
    uint64_t scan_start = kdata_base + (uint64_t)SCAN_BATCH * CHUNK_SIZE;
    uint64_t scan_end = scan_start + CHUNK_SIZE;

    /* Don't scan beyond reasonable kdata size (16MB for function ptrs) */
    uint64_t max_kdata = kdata_base + 0x1000000;  /* 16MB */
    if (scan_end > max_kdata)
        scan_end = max_kdata;
    if (scan_start >= max_kdata) {
        out[0] = ((uint64_t)0xFFFF << 32) | MAGIC_SPVT;
        return 0;
    }

    out[4] = scan_start;
    out[5] = scan_end;

    int n_results = 0;
    int n_total_ptrs = 0;  /* total ktext pointers found (may exceed MAX_RESULTS) */

    volatile uint64_t* scan_ptr = (volatile uint64_t*)scan_start;
    uint64_t n_qwords = (scan_end - scan_start) / 8;

    for (uint64_t i = 0; i < n_qwords; i++) {
        uint64_t val = scan_ptr[i];

        /* Check if this qword points into ktext */
        if (val >= ktext_base && val < ktext_end) {
            n_total_ptrs++;

            if (n_results < MAX_RESULTS) {
                /* Store: kdata offset in low 32 bits, ktext offset in high 32 bits */
                uint64_t kdata_off = (scan_start + i * 8) - kdata_base;
                uint64_t ktext_off = val - ktext_base;
                out[HEADER_SLOTS + n_results] = (kdata_off & 0xFFFFFFFF) |
                                                (ktext_off << 32);
                n_results++;
            }
        }
    }

    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    out[3] |= ((uint64_t)n_results << 16);
    out[6] = n_total_ptrs;
    out[7] = n_qwords;  /* total qwords scanned */

    return 0;
}

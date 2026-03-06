#include <stdint.h>

/*
 * kdata_harvester — Comprehensive ktext function pointer scanner
 *
 * Scans the ENTIRE kdata segment for 8-byte-aligned values that fall
 * within the ktext VA range. This catches ALL function pointer tables,
 * vtables, ops structs, callback arrays, and other references to ktext
 * functions — not just the ones we know about.
 *
 * The PS5 kernel's kdata segment is ~100MB+ and contains thousands of
 * function pointers spread across hundreds of tables. By harvesting
 * them all, we can build a comprehensive map of ktext function entry
 * points, which tells us:
 *   1. WHERE to safely probe for pivot gadgets (near known functions)
 *   2. The approximate SIZE of each function (gap to next entry point)
 *   3. Coverage of the 12MB ktext binary
 *
 * Unlike ktext_mapper.c (which only scans ~400KB), this scans kdata
 * in configurable 1MB chunks.
 *
 * Configure via -D flags:
 *   SCAN_CHUNK:  which 1MB chunk of kdata to scan (0-based)
 *   CHUNK_SIZE:  scan size in bytes (default 0x100000 = 1MB)
 *
 * Output layout (uint64_t indices):
 *   [0]  magic "KHVT" (0x4B485654) | num_found(32)
 *   [1]  kdata_base
 *   [2]  ktext_base
 *   [3]  ktext_end
 *   [4]  scan_start (kdata_base + SCAN_CHUNK * CHUNK_SIZE)
 *   [5]  scan_end
 *   [6]  bytes_scanned
 *   [7]  status (1=complete, 0xAAAA=in_progress)
 *   [8..N] sorted unique ktext pointers found
 *
 * Max pointers: (2304/8 - 8) = 280
 */

#ifndef SCAN_CHUNK
#define SCAN_CHUNK     0
#endif
#ifndef CHUNK_SIZE
#define CHUNK_SIZE     0x100000   /* 1MB */
#endif

#define MAGIC_KHVT     0x4B485654  /* "KHVT" */
#define KTEXT_SIZE     0xC00000    /* 12MB */
#define HEADER_SLOTS   8
#define MAX_PTRS       280

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

/* Simple sort */
static void sort_u64(uint64_t* arr, int n)
{
    for (int i = 1; i < n; i++) {
        uint64_t key = arr[i];
        int j = i - 1;
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t ktext_end = ktext_base + KTEXT_SIZE;

    uint64_t scan_start = kdata_base + (uint64_t)SCAN_CHUNK * CHUNK_SIZE;
    uint64_t scan_end = scan_start + CHUNK_SIZE;

    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Clear output */
    for (int i = 0; i < 2304/8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0 << 32) | MAGIC_KHVT;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = ktext_end;
    out[4] = scan_start;
    out[5] = scan_end;
    out[6] = 0;
    out[7] = 0xAAAA;  /* in_progress */

    uint64_t* ptrs = (uint64_t*)&out[HEADER_SLOTS];
    int count = 0;

    /*
     * Scan the chunk looking for ktext pointers.
     * We read every 8-byte-aligned qword and check if it's in ktext range.
     * Additionally check for plausible function pointers: must be
     * at least 2-byte aligned (x86 function entries are typically
     * 16-byte aligned, but we allow any alignment for mid-function refs).
     */
    volatile uint64_t* scan = (volatile uint64_t*)scan_start;
    int num_qwords = CHUNK_SIZE / 8;

    for (int i = 0; i < num_qwords; i++) {
        uint64_t val = scan[i];

        /* Check if it's a plausible ktext pointer */
        if (val >= ktext_base && val < ktext_end) {
            /* Dedup and add */
            int dup = 0;
            for (int j = 0; j < count; j++) {
                if (ptrs[j] == val) { dup = 1; break; }
            }
            if (!dup && count < MAX_PTRS) {
                ptrs[count++] = val;
            }
        }

        /* Update progress every 16K qwords (~128KB) */
        if ((i & 0x3FFF) == 0) {
            out[6] = (uint64_t)(i + 1) * 8;
            out[0] = ((uint64_t)count << 32) | MAGIC_KHVT;
        }
    }

    /* Sort results */
    sort_u64(ptrs, count);

    /* Remove duplicates after sort (belt and suspenders) */
    if (count > 1) {
        int w = 1;
        for (int r = 1; r < count; r++) {
            if (ptrs[r] != ptrs[w-1])
                ptrs[w++] = ptrs[r];
        }
        count = w;
    }

    out[0] = ((uint64_t)count << 32) | MAGIC_KHVT;
    out[6] = CHUNK_SIZE;
    out[7] = 1;  /* complete */

    return 0;
}

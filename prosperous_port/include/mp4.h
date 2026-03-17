#ifndef PROSPEROUS_MP4_H
#define PROSPEROUS_MP4_H

#include <stdint.h>

/*
 * MP4 (Media Processor 4) / Belize ARM Cortex-A53 coprocessor access.
 *
 * The MP4 is accessed via BAR2 MMIO registers at physical address 0xE0400000.
 * Communication uses c2p (CPU-to-Processor) mailbox registers:
 *   c2p_reg(core, reg) = BAR2 + 0xF6000 + core * 0x5000 + reg * 0x1000
 *
 * Protocol:
 *   1. Write arguments to c2p regs 1-4
 *   2. Write command to c2p reg 0
 *   3. Poll c2p reg 0 until it becomes 0 (command acknowledged)
 *   4. Read results from c2p regs 1-2
 *
 * Commands (from prosperous mp4_payload):
 *   0x20400000: mem_read(addr_lo, addr_hi, size_flags)
 *   0x20400001: mem_write8(addr_lo, addr_hi, val)
 *   0x20400002: mem_write16(addr_lo, addr_hi, val)
 *   0x20400003: mem_write32(addr_lo, addr_hi, val)
 *   0x20400004: mem_write64(addr_lo, addr_hi, val_lo) [val_hi in ack reg]
 *   0x20400005: syshub_tlb_setup(addr_lo, addr_hi, tlb_index)
 *   0x20400006: memcpy(dst, src, len) [32-bit args only]
 *   0x20400007: dc_op(addr_lo, addr_hi, len) [op in ack: 0=civac, 1=ivac]
 *   0x20400008: tlb_invalidate()
 *   0x20400009: ping() -> timer count in reg1
 *   0x2040000a: caches_enable(enable)
 *   0x2040000b: reg_read(reg_id)
 */

#define MP4_BAR2_PA         0xE0400000ULL

/* MP4 DRAM region (A53 firmware resides here) */
#define MP4_DRAM_BASE       0x60000000ULL
#define MP4_DRAM_END        0x605F0000ULL

/* c2p register offsets from BAR2 */
#define MP4_C2P_BASE(core)  (0xF6000 + (core) * 0x5000)
#define MP4_C2P_REG(core, reg) (MP4_C2P_BASE(core) + (reg) * 0x1000)

/* p2c register offsets from BAR2 */
#define MP4_P2C_REG0(core)  (0x10500 + (core == 1 ? 0xE0B00 : 0))

/* Command IDs */
#define MP4_CMD_MEM_READ    0x20400000
#define MP4_CMD_MEM_W8      0x20400001
#define MP4_CMD_MEM_W16     0x20400002
#define MP4_CMD_MEM_W32     0x20400003
#define MP4_CMD_MEM_W64     0x20400004
#define MP4_CMD_TLB_SETUP   0x20400005
#define MP4_CMD_MEMCPY      0x20400006
#define MP4_CMD_DC_OP       0x20400007
#define MP4_CMD_TLB_INVAL   0x20400008
#define MP4_CMD_PING        0x20400009
#define MP4_CMD_CACHE_EN    0x2040000A
#define MP4_CMD_REG_READ    0x2040000B

/* Memory read size flags */
#define MP4_MEM_SIZE_8      0
#define MP4_MEM_SIZE_16     1
#define MP4_MEM_SIZE_32     2
#define MP4_MEM_SIZE_64     3
#define MP4_MEM_PHYS        (1 << 2)

/* MP4 command send timeout (iterations) */
#define MP4_CMD_TIMEOUT     10000

/* SysHub TLB configuration */
#define SYSHUB_TLB_REG_BASE         0x03230000
#define SYSHUB_TLB_SUB_PAGE_RW_OFF  0x3E0
#define SYSHUB_TLB_ATTRS_OFF        0x4D8

/* SysHub TLB sub-page RW cache (in MP4 VA space) */
#define MP4_SYSHUB_SUB_PAGE_RW_CACHE  0x11F538

/* Known firmware entry points (FW 4.03, Oberon 1.1.1.00 CEX build 179926) */
#define A53_HOOK_ADDR         0x108BD4   /* BL is_qaf in IRQ handler (GIC 83/78) */
#define A53_ELF_BASE          0x100000   /* Base address of A53 ELF in DRAM */
#define A53_QAF_FLAGS_OFF     0x123B74   /* dword_123B74: mm4p QAF flag in .data */

/* Payload placement addresses (in MP4 DRAM, relative to 0x60000000)
 * DRAM is ~5.875MB (0x5E0000 bytes), so all offsets must be < 0x5E0000.
 * Firmware ELF occupies ~0x100000-0x140000, leaving 0x140000-0x5E0000 free. */
#define MP4_THUNK_OFFSET      0xE0000   /* Thunk code: 0x600E0000 */
#define MP4_PAYLOAD_OFFSET    0x3F1000  /* Main payload: 0x603F1000 */

struct mp4_access {
    uint64_t dmap_base;
    uint64_t bar2_pa;
};

static inline void mp4_init_access(struct mp4_access *mp4, uint64_t dmap_base)
{
    mp4->dmap_base = dmap_base;
    mp4->bar2_pa = MP4_BAR2_PA;
}

#endif

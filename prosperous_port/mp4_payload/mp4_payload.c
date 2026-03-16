/*
 * MP4 AArch64 EL3 payload for PS5 Belize ARM Cortex-A53 coprocessor.
 *
 * Ported from fail0verflow's prosperous exploit.
 * This code runs at EL3 on the A53, providing memory R/W, SysHub TLB
 * manipulation, and cache management primitives that the x86 host
 * can invoke via c2p mailbox registers.
 *
 * Build:
 *   aarch64-linux-gnu-gcc -nostdlib -fpie -fno-jump-tables -Os \
 *     -mcpu=cortex-a53 -o mp4_payload.o mp4_payload.c
 *   aarch64-linux-gnu-objcopy -O binary -j .text -j .rodata mp4_payload.o mp4_payload
 *
 * The payload is injected into MP4 DRAM at 0x607F1000, with a thunk
 * at 0x600E0000 that branches to it from the mDbg_intr hook.
 *
 * -fno-jump-tables ensures no alignment-dependent code is generated,
 * allowing the payload to work without a fixed load address/linker script.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef volatile u8 vu8;
typedef volatile u16 vu16;
typedef volatile u32 vu32;
typedef volatile u64 vu64;

#define STRINGIFY(x) #x

#define aarch64_sysreg_read(name) ({         \
    u64 val;                                 \
    asm volatile("mrs %x0, " STRINGIFY(name) \
                 : "=r"(val));               \
    val;                                     \
})

#define aarch64_sysreg_write(name, val)             \
    do                                              \
    {                                               \
        asm volatile("msr " STRINGIFY(name) ", %x0" \
                     :                              \
                     : "r"(val));                   \
    } while (0)

static u8 core_id(void)
{
    return aarch64_sysreg_read(MPIDR_EL1);
}

static void aarch64_dc_clean_invalidate_va(uintptr_t va)
{
    asm volatile("dc civac, %x0" : : "r"(va));
}

static void aarch64_dc_invalidate_va(uintptr_t va)
{
    asm volatile("dc ivac, %x0" : : "r"(va));
}

static const u64 DAIF_D = 1 << 9;
static const u64 DAIF_A = 1 << 8;
static const u64 DAIF_I = 1 << 7;
static const u64 DAIF_F = 1 << 6;
static const u64 DAIF_all = (1 << 9) | (1 << 8) | (1 << 7) | (1 << 6);

static u64 aarch64_int_enable(bool enable, u64 mask)
{
    mask &= DAIF_all;
    const u64 old = aarch64_sysreg_read(DAIF);
    u64 val = old;
    if (enable)
        val &= ~mask;
    else
        val |= mask;
    aarch64_sysreg_write(DAIF, val);
    return old;
}

static u64 to_u64(u32 hi, u32 lo)
{
    return ((u64)hi << 32) | lo;
}

static vu32 *c2p_addr(u32 core, u32 reg)
{
    /* EL3 has c2pmsg regs identity mapped (2MB mapping @ 0x3000000) */
    const uintptr_t c2pmsg_reg_base = 0x3000000;
    const uintptr_t addr = c2pmsg_reg_base + 0xF6000 + core * 0x5000 + reg * 0x1000;
    return (vu32 *)addr;
}

static u32 c2p_read(u32 core, u32 reg)
{
    return *c2p_addr(core, reg);
}

static void c2p_write(u32 core, u32 reg, u32 val)
{
    *c2p_addr(core, reg) = val;
}

static void aarch64_barrier(void)
{
    asm("dsb sy");
    asm("isb");
}

static void aarch64_tlb_invalidate_el3(void)
{
    asm("tlbi alle3");
    aarch64_barrier();
}

static const u64 SCTLR_I = 1 << 12;
static const u64 SCTLR_C = 1 << 2;
static const u64 SCTLR_M = 1 << 0;
static const u64 SCTLR_ICM = (1 << 12) | (1 << 2) | (1 << 0);

static u64 aarch64_mmu_enable(bool enable, u64 mask)
{
    mask &= SCTLR_ICM;
    const u64 old = aarch64_sysreg_read(SCTLR_EL3);
    u64 sctlr = old;
    if (enable)
        sctlr |= mask;
    else
        sctlr &= ~mask;
    aarch64_sysreg_write(SCTLR_EL3, sctlr);
    aarch64_barrier();
    return old;
}

static void cmd_mem_read(u32 core, uintptr_t addr, u32 arg)
{
    const u32 size = arg & 3;
    const bool phys = (arg >> 2) & 1;
    u64 val = 0;
    u64 sctlr = 0;
    u64 imask = 0;

    if (phys) {
        imask = aarch64_int_enable(false, DAIF_all);
        sctlr = aarch64_mmu_enable(false, SCTLR_ICM);
    }

    switch (size) {
    case 0: val = *(u8 *)addr; break;
    case 1: val = *(u16 *)addr; break;
    case 2: val = *(u32 *)addr; break;
    case 3: val = *(u64 *)addr; break;
    }

    if (phys) {
        aarch64_mmu_enable(true, sctlr);
        aarch64_int_enable(true, imask);
    }

    c2p_write(core, 1, val);
    c2p_write(core, 2, val >> 32);
}

static void cmd_mem_write8(uintptr_t addr, u32 val)
{
    *(u8 *)addr = val;
}

static void cmd_mem_write16(uintptr_t addr, u32 val)
{
    *(u16 *)addr = val;
}

static void cmd_mem_write32(uintptr_t addr, u32 val)
{
    *(u32 *)addr = val;
}

static void cmd_mem_write64(u32 core, uintptr_t addr, u32 val_lo)
{
    u64 val = to_u64(c2p_read(core, 4), val_lo);
    *(u64 *)addr = val;
}

typedef struct {
    u32 tlb0;
    u32 tlb1;
    u32 tlb2;
    u32 tlb3;
} syshub_tlb_t;

static u32 cmd_syshub_tlb_setup(uintptr_t addr, u32 arg)
{
    const uintptr_t syshub_tlb_reg_base = 0x03230000;

    u32 index = arg & 0x3f;
    if (index == 0 || index > 61)
        return 1;
    index -= 1;

    syshub_tlb_t *tlbs = (syshub_tlb_t *)syshub_tlb_reg_base;
    u32 *sub_page_rws = (u32 *)(syshub_tlb_reg_base + 0x3e0);
    u32 *attrs = (u32 *)(syshub_tlb_reg_base + 0x4d8);

    syshub_tlb_t *tlb = &tlbs[index];
    u32 *sub_page_rw = &sub_page_rws[index];
    u32 *attr = &attrs[index];

    u32 seg_size = 9;
    u32 tlb1 = seg_size << 1;

    tlb->tlb0 = addr >> 26;
    tlb->tlb1 = tlb1;
    tlb->tlb2 = 4;
    tlb->tlb3 = 4;
    *sub_page_rw = 0xffffffff;
    *attr = 0xc0800003;

    return 0;
}

static void *memcpy(void *dst, const void *src, size_t len)
{
    u8 *d = dst;
    const u8 *s = src;
    while (len--)
        *d++ = *s++;
    return dst;
}

static void cmd_memcpy(uintptr_t dst, uintptr_t src, u32 len)
{
    memcpy((void *)dst, (void *)src, len);
}

static void cmd_dc_op(u32 core, uintptr_t va, u32 len)
{
    u32 op = c2p_read(core, 4);
    switch (op) {
    case 0:
        va = va & ~0x3f;
        for (u32 i = 0; i < len; i += 0x40)
            aarch64_dc_clean_invalidate_va(va + i);
        break;
    case 1:
        va = va & ~0x3f;
        for (u32 i = 0; i < len; i += 0x40)
            aarch64_dc_invalidate_va(va + i);
        break;
    }
}

static u32 timer_get_count(u32 index)
{
    return *(vu32 *)((uintptr_t)0x3200420 + index * 0x24);
}

static void cmd_ping(u32 core)
{
    c2p_write(core, 1, timer_get_count(0));
}

static void cmd_caches_enable(bool enable)
{
    aarch64_mmu_enable(enable, SCTLR_I | SCTLR_C);
}

static void cmd_reg_read(u32 core, u32 reg)
{
    u64 val = 0;
    switch (reg) {
    case 0:
        val = aarch64_sysreg_read(RVBAR_EL3);
        break;
    default:
        val = 0xdeadcacadeadd00d;
        break;
    }
    c2p_write(core, 1, val);
    c2p_write(core, 2, val >> 32);
}

/*
 * Entry point - called in place of mDbg_intr from el3_serror_handler.
 * The thunk at 0x600E0000 branches here.
 *
 * This code must be identity-mapped in DRAM so it works when MMU is
 * disabled, hence the thunk within 128M branch range.
 */
void _start(u32 core, u32 cmd, u32 arg1, u32 arg2, u32 arg3)
{
    const u64 arg1_64 = to_u64(arg2, arg1);
    u32 rv = 0;

    switch (cmd) {
    case 0x20400000:
        cmd_mem_read(core, arg1_64, arg3);
        break;
    case 0x20400001:
        cmd_mem_write8(arg1_64, arg3);
        break;
    case 0x20400002:
        cmd_mem_write16(arg1_64, arg3);
        break;
    case 0x20400003:
        cmd_mem_write32(arg1_64, arg3);
        break;
    case 0x20400004:
        cmd_mem_write64(core, arg1_64, arg3);
        break;
    case 0x20400005:
        rv = cmd_syshub_tlb_setup(arg1_64, arg3);
        break;
    case 0x20400006:
        cmd_memcpy(arg1, arg2, arg3);
        break;
    case 0x20400007:
        cmd_dc_op(core, arg1_64, arg3);
        break;
    case 0x20400008:
        aarch64_tlb_invalidate_el3();
        break;
    case 0x20400009:
        cmd_ping(core);
        break;
    case 0x2040000a:
        cmd_caches_enable(arg1);
        break;
    case 0x2040000b:
        cmd_reg_read(core, arg1);
        break;
    }

    c2p_write(core, 0, rv);
}

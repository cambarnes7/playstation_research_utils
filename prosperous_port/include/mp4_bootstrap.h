#ifndef MP4_BOOTSTRAP_H
#define MP4_BOOTSTRAP_H

/*
 * MP4 I-cache flush bootstrap - AArch64 EL3 one-shot payload.
 *
 * This code runs ONCE via the qword_123180 jmpbuf hijack to solve the
 * I-cache coherency problem. DECI5S WRITE_MEMORY updates the A53's
 * D-cache/DRAM but NOT the I-cache. Code patches (thunk at VA 0x1E0000,
 * BL hook at VA 0x108BD4) are invisible to instruction fetch until the
 * I-cache is invalidated.
 *
 * Flow:
 *   1. Exception handler sees qword_123180 != 0
 *   2. Calls sub_107BE0(qword_123180 + 8, 1) — custom EL3 longjmp
 *   3. Longjmp restores SP, sets SPSR_EL3 and ELR_EL3 from jmpbuf
 *   4. Longjmp RETs to X30 from jmpbuf → this bootstrap code
 *   5. Bootstrap does IC IALLU (flush all I-cache)
 *   6. Clears qword_123180 to prevent re-triggering
 *   7. ERET back to ELR_EL3 (also set in jmpbuf → firmware idle loop)
 *
 * After IC IALLU, the patched BL at 0x108BD4 and thunk body at 0x1E0000
 * will be fetched fresh from DRAM on next execution. The persistent
 * mp4_payload command dispatcher then works normally.
 *
 * Placed at DRAM offset 0x3F0000 (A53 identity-mapped VA 0x883F0000).
 * This address was never executed, so no stale I-cache entries exist.
 *
 * Jmpbuf layout (custom EL3 longjmp, from user's IDA analysis):
 *   qword_123180 + 0x08: SP
 *   qword_123180 + 0x10: SPSR_EL3
 *   qword_123180 + 0x18: ELR_EL3  ← ERET target (set to safe return addr)
 *   qword_123180 + 0x20: X19, X20
 *   ...
 *   qword_123180 + 0x70: X29, X30 (X30 = LR for RET → this bootstrap)
 */

/*
 * Bootstrap AArch64 assembly (8 instructions, 32 bytes):
 *
 *   IC IALLU                        ; invalidate entire I-cache
 *   DSB SY                          ; full system barrier
 *   ISB                             ; instruction synchronization
 *   MOVZ X0, #0x3180               ; qword_123180 VA (low)
 *   MOVK X0, #0x0012, LSL #16     ; qword_123180 VA = 0x00123180
 *   STR XZR, [X0]                  ; clear jmpbuf pointer (one-shot)
 *   DSB SY                          ; ensure store completes
 *   ERET                            ; return via ELR_EL3 (set in jmpbuf)
 */
static const unsigned char mp4_bootstrap_bin[] = {
    0x1F, 0x75, 0x08, 0xD5,  /* IC IALLU                      */
    0x9F, 0x3F, 0x03, 0xD5,  /* DSB SY                        */
    0xDF, 0x3F, 0x03, 0xD5,  /* ISB                           */
    0x00, 0x30, 0x86, 0xD2,  /* MOVZ X0, #0x3180              */
    0x40, 0x02, 0xA0, 0xF2,  /* MOVK X0, #0x0012, LSL #16    */
    0x1F, 0x00, 0x00, 0xF9,  /* STR XZR, [X0]                 */
    0x9F, 0x3F, 0x03, 0xD5,  /* DSB SY                        */
    0xE0, 0x03, 0x9F, 0xD6,  /* ERET                          */
};

static const unsigned int mp4_bootstrap_bin_len = sizeof(mp4_bootstrap_bin);

/*
 * Fake jmpbuf structure for the EL3 longjmp hijack.
 *
 * sub_107BE0 is called as sub_107BE0(qword_123180 + 8, 1).
 * It uses post-index loads from X0 (= qword_123180 + 8):
 *
 *   +0x00 (from X0): SP
 *   +0x08:           SPSR_EL3
 *   +0x10:           ELR_EL3    ← ERET destination
 *   +0x18:           X19, X20
 *   +0x28:           X21, X22
 *   +0x38:           X23, X24
 *   +0x48:           X25, X26
 *   +0x58:           X27, X28
 *   +0x68:           X29, X30   ← RET destination (X30 = bootstrap addr)
 *
 * Total: 0x78 bytes from (qword_123180 + 8).
 * We allocate 0x80 bytes at qword_123180 (0x78 jmpbuf + 8 byte prefix).
 */

/* SPSR_EL3 value: EL3h (SPSel=1), DAIF all masked, AArch64 */
#define BOOTSTRAP_SPSR_EL3  0x000003CDULL

/* Jmpbuf placement in DRAM */
#define BOOTSTRAP_OFFSET    0x3F0000   /* Bootstrap code: DRAM+0x3F0000 */
#define JMPBUF_OFFSET       0x3EF000   /* Jmpbuf struct: DRAM+0x3EF000 */

/* A53 firmware addresses */
#define A53_JMPBUF_PTR_VA   0x123180   /* qword_123180 in firmware .bss */
#define A53_IDLE_LOOP_VA    0x108BF4   /* B 0x108BD4 loop in IRQ handler */

/*
 * Build the fake jmpbuf in a caller-provided buffer.
 *
 * @buf:           Output buffer, must be >= 0x80 bytes
 * @bootstrap_va:  VA of bootstrap code (identity-mapped: 0x88000000 + DRAM offset)
 * @sp_val:        Stack pointer value (SRAM address, e.g., 0x1A00)
 * @eret_target:   ELR_EL3 value — where ERET goes after bootstrap (safe FW addr)
 */
static inline void build_jmpbuf(uint8_t *buf, uint64_t bootstrap_va,
                                 uint64_t sp_val, uint64_t eret_target)
{
    uint64_t *p;

    /* Zero entire buffer (0x80 bytes: 8-byte prefix + 0x78 jmpbuf) */
    for (int i = 0; i < 0x80 / 8; i++)
        ((uint64_t *)buf)[i] = 0;

    /* buf[0x00..0x07]: first 8 bytes skipped by "+8" in the call */

    /* Jmpbuf starts at buf + 0x08 (= qword_123180 + 8) */
    p = (uint64_t *)(buf + 0x08);

    p[0] = sp_val;               /* +0x00: SP */
    p[1] = BOOTSTRAP_SPSR_EL3;   /* +0x08: SPSR_EL3 (EL3h, IRQs masked) */
    p[2] = eret_target;          /* +0x10: ELR_EL3 (ERET goes here after bootstrap) */

    /* +0x18 .. +0x60: X19-X28 = 0 (already zeroed) */

    /* +0x68: X29 (FP) = 0, X30 (LR) = bootstrap_va (RET target) */
    p[13] = bootstrap_va;        /* +0x68 = X30 (LR) — sub_107BE0 RETs here */

    /* Note: p[12] = X29 = 0 (FP, don't care) */
}

#endif /* MP4_BOOTSTRAP_H */

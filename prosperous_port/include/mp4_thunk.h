#ifndef MP4_THUNK_H
#define MP4_THUNK_H

/*
 * MP4 thunk code - AArch64 trampoline placed at DRAM+0xE0000 (A53 VA 0x1E0000).
 *
 * FW 4.03 version: hooks the BL is_qaf at VA 0x108BD4 in the IRQ handler.
 * At this hook point, c2p register values are in callee-saved regs:
 *   W19 = core_id, W20 = c2p_command, W24 = arg1, W23 = arg2, W22 = arg3
 *
 * The thunk:
 *   1. Sets SysHub TLB entry 34 sub_page_rw = 0xFFFFFFFF (enable access)
 *   2. Shuffles registers into _start(core, cmd, arg1, arg2, arg3) ABI
 *   3. Calls main payload at 0x887F1000 (G6 addr = DRAM+0x7F1000)
 *   4. Returns 0 (command handled, skip firmware dispatch)
 *
 * Disassembly (16 instructions, 64 bytes):
 *   STP  X29, X30, [SP, #-0x10]!  ; save frame
 *   MOVZ X29, #0x0464             ; TLB34 sub_page_rw addr lo
 *   MOVK X29, #0x0323, LSL #16   ; TLB34 sub_page_rw addr hi (0x03230464)
 *   MOV  W30, #0xFFFFFFFF         ; all-access mask
 *   STR  W30, [X29]               ; enable TLB34 sub_page_rw
 *   MOV  X0, X19                  ; core_id → arg0
 *   MOV  X1, X20                  ; c2p_command → arg1
 *   MOV  X2, X24                  ; c2p_arg1 → arg2
 *   MOV  X3, X23                  ; c2p_arg2 → arg3
 *   MOV  X4, X22                  ; c2p_arg3 → arg4
 *   MOVZ X29, #0x1000             ; payload addr lo
 *   MOVK X29, #0x887F, LSL #16   ; payload addr hi (0x887F1000)
 *   BLR  X29                      ; call payload
 *   LDP  X29, X30, [SP], #0x10   ; restore frame
 *   MOV  W0, #0                   ; return 0 (handled)
 *   RET
 */
static const unsigned char mp4_thunk_bin[] = {
    0xFD, 0x7B, 0xBF, 0xA9,  /* STP  X29, X30, [SP, #-0x10]!  */
    0x9D, 0x8C, 0x80, 0xD2,  /* MOVZ X29, #0x0464             */
    0x7D, 0x64, 0xA0, 0xF2,  /* MOVK X29, #0x0323, LSL #16   */
    0x1E, 0x00, 0x80, 0x12,  /* MOV  W30, #0xFFFFFFFF         */
    0xBE, 0x03, 0x00, 0xB9,  /* STR  W30, [X29]               */
    0xE0, 0x03, 0x13, 0xAA,  /* MOV  X0, X19  (core)          */
    0xE1, 0x03, 0x14, 0xAA,  /* MOV  X1, X20  (cmd)           */
    0xE2, 0x03, 0x18, 0xAA,  /* MOV  X2, X24  (arg1)          */
    0xE3, 0x03, 0x17, 0xAA,  /* MOV  X3, X23  (arg2)          */
    0xE4, 0x03, 0x16, 0xAA,  /* MOV  X4, X22  (arg3)          */
    0x1D, 0x00, 0x82, 0xD2,  /* MOVZ X29, #0x1000             */
    0xFD, 0x0F, 0xB1, 0xF2,  /* MOVK X29, #0x887F, LSL #16   */
    0xA0, 0x03, 0x3F, 0xD6,  /* BLR  X29                      */
    0xFD, 0x7B, 0xC1, 0xA8,  /* LDP  X29, X30, [SP], #0x10   */
    0x00, 0x00, 0x80, 0x52,  /* MOV  W0, #0                   */
    0xC0, 0x03, 0x5F, 0xD6,  /* RET                           */
};

static const unsigned int mp4_thunk_bin_len = sizeof(mp4_thunk_bin);

#endif

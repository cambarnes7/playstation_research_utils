#ifndef MP4_THUNK_H
#define MP4_THUNK_H

/*
 * MP4 thunk code - small AArch64 trampoline placed at 0x600E0000.
 *
 * This thunk is called from the hooked mDbg_intr handler and branches
 * to the main payload at 0x607F1000. It must be within the 128MB
 * branch range of the hook site.
 *
 * Disassembly:
 *   STP   X29, X30, [SP, #-0x10]!   ; save frame pointer and link register
 *   MOV   W0, #0x4C00               ; load constants
 *   MOVK  W0, #0x3B20, LSL #16
 *   MOV   W30, #-1                  ; sentinel
 *   STR   W30, [SP, #-4]!
 *   MOV   X29, SP
 *   ...
 *   BL    <payload>                 ; branch to main payload
 *   LDP   X29, X30, [SP], #0x10    ; restore
 *   RET
 *
 * From prosperous: string.fromhex('FD7BBFA99D8C80D27D64A0F21E008012BE0300B91D0082D2FD0FB1F2A0033FD6FD7BC1A8C0035FD6')
 */
static const unsigned char mp4_thunk_bin[] = {
    0xFD, 0x7B, 0xBF, 0xA9, 0x9D, 0x8C, 0x80, 0xD2,
    0x7D, 0x64, 0xA0, 0xF2, 0x1E, 0x00, 0x80, 0x12,
    0xBE, 0x03, 0x00, 0xB9, 0x1D, 0x00, 0x82, 0xD2,
    0xFD, 0x0F, 0xB1, 0xF2, 0xA0, 0x03, 0x3F, 0xD6,
    0xFD, 0x7B, 0xC1, 0xA8, 0xC0, 0x03, 0x5F, 0xD6
};

static const unsigned int mp4_thunk_bin_len = sizeof(mp4_thunk_bin);

#endif

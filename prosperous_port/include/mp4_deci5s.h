/*
 * DECI5S protocol definitions for MP4/A53 communication
 *
 * Based on cragson's a53-code-exec and astrelsky's mp4rw.
 * Ported to C for use with ps5-payload-dev/sdk.
 *
 * The MP4 device contains an ARM Cortex-A53 running at EL3.
 * Communication uses DECI5S (debug protocol) via /dev/mp4/dump.
 *
 * References:
 *   https://github.com/cragson/a53-code-exec
 *   https://github.com/astrelsky/mp4rw
 *   https://github.com/ps5-payload-dev/sdk
 */

#ifndef MP4_DECI5S_H
#define MP4_DECI5S_H

#include <stdint.h>
#include <stddef.h>

/* ---- DECI5S protocol constants ---- */
#define DECI5S_MAGIC          0x73354450U   /* bswap32('PD5s') */
#define DECI5S_SRC_KERNEL     0x80FF0180U
#define DECI5S_DST_MP4        0x80FF0201U
#define DECI5S_PROTO_SDBGP    0x20000201U
#define DECI5S_DCMP            0x18U
#define DECI5S_CODE            0x50U

/* ---- SDBGP command types ---- */
#define SDBGP_GET_CONF         0x01010010U
#define SDBGP_READ_MEMORY      0x01040021U
#define SDBGP_WRITE_MEMORY     0x01040031U

/* ---- MP4 memory access types ---- */
#define MP4_MEM_PA_TO_EL3_VA     0x020000U  /* physical addr -> EL3 VA */
#define MP4_MEM_EL3_VA_TO_EL3_VA 0x430000U  /* EL3 VA pass-through */
#define MP4_MEM_EL0_VA_TO_EL3_VA 0x400000U  /* EL0 VA -> EL3 VA */

/* ---- MP4 dump ioctl commands ---- */
#define IOCTL_START            0x800c410bU
#define IOCTL_FINISH           0x8008410fU
#define IOCTL_ALTER_STATE      0x40184115U

/* ---- Auth IDs ---- */
#define SYSCORE_ID             0x4800000000000007ULL

/* ---- MP4 coredump command ---- */
#define MP4_COREDUMP_CMD       0x20303000U

/* ---- Device struct offsets (FreeBSD, stable across FW) ---- */
#define DEVICE_DEVLINK_OFFSET  0x18
#define DEVICE_NAMEUNIT_OFFSET 0x58
#define DEVICE_SOFTC_OFFSET    0x88

/* ---- MP4 softc offsets ---- */
#define SOFTC_ZCN_BAR2_RES     0x18
#define RESOURCE_BUSHANDLE     0x10

/* ---- Known A53 ELF base physical addresses ---- */
#define A53_ELF_PA_1           0x88100000ULL
#define A53_ELF_PA_2           0x88440000ULL
#define A53_ELF_PA_3           0x8A000000ULL

/* ---- DECI5S packet structures ---- */

struct deci5s_hdr {
    uint32_t magic;
    uint32_t self_size;
    uint32_t packet_size;
    uint32_t src;
    uint32_t dst;
    uint32_t protocol_id;
    uint32_t attr;
    uint32_t user_data;
    uint64_t timestamp;
};

struct deci5s_cmd_hdr {
    struct deci5s_hdr header;
    uint32_t dcmp;
    uint32_t code;
    uint64_t pad;
    uint8_t  unknown0[4];
    uint8_t  num_commands;
    uint8_t  unknown1[3];
};

struct deci5s_mem_arg {
    uint32_t self_size;
    uint32_t access_size_and_type; /* access_size:8, mem_type:24 */
    uint64_t addr;
    uint64_t size;
};

/* Helper to pack access_size (low 8 bits) and mem_type (high 24 bits) */
static inline uint32_t mp4_mem_arg_pack(uint32_t access_sz, uint32_t mem_type)
{
    return (access_sz & 0xFF) | (mem_type << 8);
}

#endif /* MP4_DECI5S_H */

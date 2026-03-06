#include <stdint.h>

/*
 * PS5 APIC Table Dump + Multi-Slot Register Probe v3 (kstuff payload)
 *
 * Part 1: Dumps all 28 apic_ops entries.
 * Part 2: Tries hooking multiple slots in sequence to find one that fires
 *         during normal kernel operation. Uses RDTSC for proper timing.
 *         Tests each slot for ~1 second before moving to the next.
 *
 * Slots to try (most likely to fire):
 *   slot  9: ipi_vectored - called for inter-processor interrupts (TLB flush, etc.)
 *   slot  8: ipi_raw - raw IPI sending
 *   slot 25: self_ipi - self-interrupts
 *   slot 23: timer_initial_count - timer setup (scheduler tick)
 *   slot 24: timer_current_count - timer read
 *   slot 18: set_tpr - task priority changes
 *
 * Output layout:
 *   [0x000] uint32_t magic = 0x52454750 ("REGP")
 *   [0x004] uint32_t status (1=captures, 2=table-only)
 *   [0x008] uint64_t kdata_base
 *   [0x010] uint64_t ktext_base
 *   [0x018] uint64_t apic_ops_table_addr
 *   [0x020] uint64_t original_slot2 (xapic_mode)
 *   [0x028] uint32_t call_count
 *   [0x02C] uint32_t hooked_slot_index
 *
 *   [0x030] apic_ops[0..27] = 28 x uint64 = 224 bytes
 *   [0x110] end of table dump
 *
 *   [0x110] uint64_t slots_tried_mask (bitmask of which slots were attempted)
 *   [0x118] uint64_t slots_hit_mask (bitmask of which slots got calls)
 *
 *   Per-call captures (4 captures x 17 uint64 = 544 bytes):
 *   [0x120] capture[0]: rax rbx rcx rdx rsi rdi rbp r8 r9 r10 r11 r12 r13 r14 r15 rsp rflags
 *   [0x1A8] capture[1]: ...
 *   [0x230] capture[2]: ...
 *   [0x2B8] capture[3]: ...
 *
 *   [0x340] uint64_t sentinel = 0xdeadbeefcafe0003
 */

#define MAGIC_REGP       0x52454750
#define APIC_OPS_OFFSET  0x1934AC8
#define APIC_OPS_COUNT   28
#define MAX_CAPTURES     4
#define REGS_PER_CAPTURE 17

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

static volatile uint64_t capture_buf[MAX_CAPTURES * REGS_PER_CAPTURE];
static volatile int capture_count;
static volatile uint64_t orig_func;

static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

__attribute__((naked, used))
static void probe_stub(void)
{
    __asm__ volatile(
        "pushq %%rax\n\t"
        "pushq %%rbx\n\t"

        "movl capture_count(%%rip), %%eax\n\t"
        "cmpl %[max], %%eax\n\t"
        "jge 1f\n\t"

        "leaq capture_buf(%%rip), %%rbx\n\t"
        "imulq $136, %%rax, %%rax\n\t"
        "addq %%rax, %%rbx\n\t"

        "movq %%rcx, 2*8(%%rbx)\n\t"
        "movq %%rdx, 3*8(%%rbx)\n\t"
        "movq %%rsi, 4*8(%%rbx)\n\t"
        "movq %%rdi, 5*8(%%rbx)\n\t"
        "movq %%rbp, 6*8(%%rbx)\n\t"
        "movq %%r8,  7*8(%%rbx)\n\t"
        "movq %%r9,  8*8(%%rbx)\n\t"
        "movq %%r10, 9*8(%%rbx)\n\t"
        "movq %%r11, 10*8(%%rbx)\n\t"
        "movq %%r12, 11*8(%%rbx)\n\t"
        "movq %%r13, 12*8(%%rbx)\n\t"
        "movq %%r14, 13*8(%%rbx)\n\t"
        "movq %%r15, 14*8(%%rbx)\n\t"

        "leaq 16(%%rsp), %%rax\n\t"
        "movq %%rax, 15*8(%%rbx)\n\t"

        "pushfq\n\t"
        "popq %%rax\n\t"
        "movq %%rax, 16*8(%%rbx)\n\t"

        "movq 8(%%rsp), %%rax\n\t"
        "movq %%rax, 0*8(%%rbx)\n\t"

        "movq (%%rsp), %%rax\n\t"
        "movq %%rax, 1*8(%%rbx)\n\t"

        "movl capture_count(%%rip), %%eax\n\t"
        "incl %%eax\n\t"
        "movl %%eax, capture_count(%%rip)\n\t"

        "1:\n\t"
        "popq %%rbx\n\t"
        "popq %%rax\n\t"
        "jmpq *orig_func(%%rip)\n\t"
        :
        : [max] "i"(MAX_CAPTURES)
        : "memory"
    );
}

/* Slots to try, in order of expected frequency */
#define NUM_TRY_SLOTS 8
static const int try_slots[NUM_TRY_SLOTS] = {
    9,   /* ipi_vectored - TLB shootdowns, scheduler */
    8,   /* ipi_raw - raw IPI */
    25,  /* self_ipi - self-interrupt */
    23,  /* timer_initial_count - scheduler tick */
    24,  /* timer_current_count - timer read */
    18,  /* set_tpr - interrupt priority */
    20,  /* timer_enable_intr */
    10,  /* ipi_wait */
};

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Output needs: 6 header + 28 table + 2 masks + 4*17 captures + 1 sentinel = 105 slots */
    for (int i = 0; i < 105; i++)
        out[i] = 0;

    /* rdmsr LSTAR */
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"((uint32_t)0xC0000082));
    uint64_t lstar = ((uint64_t)hi << 32) | lo;
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFFSET;

    volatile uint32_t* out32 = (volatile uint32_t*)args;
    out32[0] = MAGIC_REGP;
    out32[1] = 0;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = apic_ops_addr;

    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;
    out[4] = apic_table[2];  /* original xapic_mode */

    /* Part 1: Dump all apic_ops entries (slots 6..33) */
    for (int i = 0; i < APIC_OPS_COUNT; i++)
        out[6 + i] = apic_table[i];

    /* Part 2: Try hooking slots */
    uint64_t slots_tried = 0;
    uint64_t slots_hit = 0;
    int hooked_slot = -1;

    /* Get TSC frequency estimate: ~3.5 GHz on PS5 Zen 2 */
    /* 1 second ≈ 3,500,000,000 cycles */
    uint64_t one_second_tsc = 3500000000ULL;

    for (int t = 0; t < NUM_TRY_SLOTS; t++) {
        int slot = try_slots[t];
        if (slot >= APIC_OPS_COUNT) continue;

        uint64_t original = apic_table[slot];
        if (original == 0) continue;

        slots_tried |= (1ULL << slot);

        capture_count = 0;
        for (int i = 0; i < MAX_CAPTURES * REGS_PER_CAPTURE; i++)
            capture_buf[i] = 0;
        orig_func = original;

        /* Install probe */
        apic_table[slot] = (uint64_t)probe_stub;

        /* Wait up to 1 second using RDTSC */
        uint64_t start = rdtsc();
        while (capture_count < MAX_CAPTURES) {
            uint64_t now = rdtsc();
            if (now - start > one_second_tsc)
                break;
            /* Yield hint to allow other threads/cores to run */
            __asm__ volatile("pause");
        }

        /* Restore immediately */
        apic_table[slot] = original;

        if (capture_count > 0) {
            slots_hit |= (1ULL << slot);
            hooked_slot = slot;
            break;  /* Got captures! */
        }
    }

    /* Store masks (slots 34-35, offsets 0x110-0x11F) */
    out[34] = slots_tried;
    out[35] = slots_hit;

    out32[10] = (uint32_t)(capture_count > 0 ? capture_count : 0);
    out32[11] = (uint32_t)(hooked_slot >= 0 ? hooked_slot : 0xFF);

    if (capture_count > 0) {
        int n = capture_count;
        if (n > MAX_CAPTURES) n = MAX_CAPTURES;

        /* Captures at slots 36+ (offset 0x120) */
        for (int c = 0; c < n; c++) {
            for (int r = 0; r < REGS_PER_CAPTURE; r++) {
                out[36 + c * REGS_PER_CAPTURE + r] = capture_buf[c * REGS_PER_CAPTURE + r];
            }
        }
        out32[1] = 1;
    } else {
        out32[1] = 2;  /* table-only */
    }

    /* Sentinel at slot 104 (offset 0x340) */
    out[104] = 0xdeadbeefcafe0003ULL;

    return 0;
}

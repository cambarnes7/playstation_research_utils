#include <stdint.h>

/*
 * PS5 Suspend Register Capture v3 (kstuff payload)
 *
 * v3 changes from v2:
 *   - Arm with capture_stub TRAMPOLINE instead of is_x2apic.
 *     capture_stub saves registers then tail-calls orig_func (= original
 *     xapic_mode), so the APIC gets properly initialized on resume.
 *   - v2 panicked because is_x2apic doesn't do xapic_mode's hardware
 *     setup work (writes to APIC MSRs/MMIO). Returning 0 isn't enough.
 *   - v1 panicked because nop_ret returned garbage RAX.
 *
 * KEY INSIGHT: The capture_stub lives in kernel heap (NX-cleared page).
 *   The PTE modification is in-memory and survives suspend/resume.
 *   After resume, TLBs are flushed but the page table walk finds the
 *   NX-cleared PTE → capture_stub can execute → calls orig xapic_mode
 *   → APIC initializes properly → no panic.
 *
 * TWO PHASES:
 *
 * Phase 1 — REGISTER CAPTURE (normal operation):
 *   Hooks multiple apic_ops slots with capture stubs.
 *   Waits ~500ms per slot for natural kernel calls.
 *   Captures up to 4 full register snapshots per slot hit.
 *   Restores all originals when done.
 *
 * Phase 2 — SUSPEND ARMING:
 *   Sets orig_func = original xapic_mode.
 *   Overwrites apic_ops[2] with capture_stub (heap trampoline).
 *   On resume: capture_stub → saves regs → calls xapic_mode → no panic.
 *   After resume, readback shows registers from the resume call.
 *
 * Output layout (uint64_t indices):
 *   [0]   magic(32) "SRCP" | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   apic_ops_addr
 *   [4]   orig_xapic_mode
 *   [5]   capture_count(32) | hooked_slot(32)
 *   [6..33]  apic_ops table dump (28 slots)
 *   [34]  armed_target (capture_stub addr for v3)
 *   [35]  capture_stub_addr
 *   [36..103] register captures: 4 × 17 uint64_t
 *             each capture: RAX,RBX,RCX,RDX,RSI,RDI,RBP,R8-R15,RSP,RFLAGS
 *   [104] sentinel = 0xdeadbeefcafe0005
 *   [105] slots_tried (bitmask of which slots we hooked)
 *   [106] slots_hit (bitmask of which slots got calls)
 *   [107] first_hit_slot
 *   [108..120] reserved
 *   [121] second_sentinel = 0xfeedface00000005
 *   [122] apic_ops[2] armed value
 *   [123] apic_ops[2] readback after arming
 */

#define MAGIC_SRCP       0x53524350  /* "SRCP" */

/* FW 4.03 offsets */
#define APIC_OPS_OFF_FROM_KTEXT  0x1934AC8

#define MAX_CAPTURES 4

/* Slots to try hooking, in order of likely call frequency */
#define NUM_PROBE_SLOTS 6
static const int probe_slots[NUM_PROBE_SLOTS] = {
    18,  /* set_tpr — called on every interrupt for priority management */
    24,  /* timer_current_count — may be polled */
    3,   /* is_x2apic — checked by various LAPIC functions */
    2,   /* xapic_mode — the one we actually want for suspend */
    13,  /* set_lvt_mask — called during interrupt setup */
    19,  /* get_timer_freq — timer related */
};

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

/* ── Global state for capture stub ── */
static volatile uint64_t orig_func;
static volatile uint32_t cap_count;
static volatile uint64_t caps[MAX_CAPTURES][17]; /* 16 regs + rflags */

/*
 * capture_stub: naked function that intercepts apic_ops calls.
 *
 * Saves all 16 GP registers + RFLAGS, increments cap_count,
 * then tail-calls the original function.
 */
__attribute__((naked, used))
static void capture_stub(void)
{
    __asm__ volatile(
        "pushq %%rax\n\t"
        "pushq %%rbx\n\t"
        "pushfq\n\t"

        "leaq cap_count(%%rip), %%rax\n\t"
        "movl (%%rax), %%eax\n\t"
        "cmpl %[max_cap], %%eax\n\t"
        "jge 2f\n\t"

        "leaq caps(%%rip), %%rbx\n\t"
        "movl %%eax, %%eax\n\t"
        "imulq $136, %%rax, %%rax\n\t"
        "addq %%rax, %%rbx\n\t"

        "movq 16(%%rsp), %%rax\n\t"
        "movq %%rax, 0*8(%%rbx)\n\t"

        "movq 8(%%rsp), %%rax\n\t"
        "movq %%rax, 1*8(%%rbx)\n\t"

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

        "leaq 24(%%rsp), %%rax\n\t"
        "movq %%rax, 15*8(%%rbx)\n\t"

        "movq (%%rsp), %%rax\n\t"
        "movq %%rax, 16*8(%%rbx)\n\t"

        "leaq cap_count(%%rip), %%rax\n\t"
        "incl (%%rax)\n\t"

        "2:\n\t"
        "popfq\n\t"
        "popq %%rbx\n\t"
        "popq %%rax\n\t"

        "jmpq *orig_func(%%rip)\n\t"
        :
        : [max_cap] "i"(MAX_CAPTURES)
        : "memory"
    );
}

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

/* Busy-wait delay in milliseconds */
static void delay_ms(uint64_t ms)
{
    volatile uint64_t count = ms * 75000;
    while (count--) {
        __asm__ volatile("pause");
    }
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 124; i++)
        out[i] = 0;

    /* Compute addresses */
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_FROM_KTEXT;

    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

    /* Write header */
    out32[0] = MAGIC_SRCP;
    out32[1] = 0;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = apic_ops_addr;

    /* Save originals */
    uint64_t original_slot2 = apic_table[2];
    out[4] = original_slot2;

    /* Dump full apic_ops table (28 slots) */
    for (int i = 0; i < 28; i++)
        out[6 + i] = apic_table[i];

    out[35] = (uint64_t)capture_stub;

    /* Initialize capture state */
    cap_count = 0;
    for (int i = 0; i < MAX_CAPTURES; i++)
        for (int j = 0; j < 17; j++)
            caps[i][j] = 0;

    /* ════════════════════════════════════════════
     * PHASE 1: MULTI-SLOT REGISTER CAPTURE
     *
     * Try each probe slot for 500ms. If we get captures, stop.
     * If not, move to the next slot.
     * Total max wait: NUM_PROBE_SLOTS × 500ms = 3s
     * ════════════════════════════════════════════ */
    out32[1] = 0xAAAA;  /* status: capturing */

    uint64_t slots_tried = 0;
    uint64_t slots_hit = 0;
    int winning_slot = -1;

    for (int p = 0; p < NUM_PROBE_SLOTS; p++) {
        int slot = probe_slots[p];
        if (slot < 0 || slot > 27) continue;

        /* Save original for this slot */
        uint64_t slot_orig = apic_table[slot];
        orig_func = slot_orig;
        cap_count = 0;

        slots_tried |= (1ULL << slot);

        /* Install capture hook on this slot */
        apic_table[slot] = (uint64_t)capture_stub;

        /* Wait 500ms for calls */
        delay_ms(500);

        /* Unhook */
        apic_table[slot] = slot_orig;

        if (cap_count > 0) {
            slots_hit |= (1ULL << slot);
            winning_slot = slot;
            break;  /* Got captures! */
        }
    }

    /* Copy results */
    uint32_t count = cap_count;
    out32[10] = count;
    out32[11] = (winning_slot >= 0) ? (uint32_t)winning_slot : 0xFF;

    for (uint32_t c = 0; c < count && c < MAX_CAPTURES; c++)
        for (int r = 0; r < 17; r++)
            out[36 + c * 17 + r] = caps[c][r];

    out[105] = slots_tried;
    out[106] = slots_hit;
    out[107] = (winning_slot >= 0) ? (uint64_t)winning_slot : 0xFFFFFFFFULL;

    /* ════════════════════════════════════════════
     * PHASE 2: ARM FOR SUSPEND
     *
     * Use capture_stub as a TRAMPOLINE for apic_ops[2].
     * capture_stub saves all registers then tail-calls orig_func.
     * We set orig_func = original xapic_mode, so:
     *   resume → capture_stub → save regs → jmp xapic_mode → APIC init OK
     *
     * v2 used is_x2apic (just returns 0) → panic because APIC not initialized.
     * v1 used nop_ret (returns garbage) → panic because wrong return value.
     * v3 uses capture_stub → calls the REAL xapic_mode → works!
     *
     * capture_stub is in kernel heap with NX cleared. The PTE modification
     * is in physical memory and survives suspend/resume.
     * ════════════════════════════════════════════ */

    /* Set orig_func to the ORIGINAL xapic_mode so capture_stub calls it */
    orig_func = original_slot2;
    cap_count = 0;  /* reset so we capture the resume call */

    /* Armed target = capture_stub (heap trampoline → calls xapic_mode) */
    uint64_t armed_target = (uint64_t)capture_stub;
    out[34] = armed_target;

    out[121] = 0xfeedface00000005ULL;

    /* Arm apic_ops[2] with capture_stub trampoline */
    apic_table[2] = armed_target;

    uint64_t readback = apic_table[2];
    out[122] = armed_target;
    out[123] = readback;

    if (readback == armed_target) {
        out32[1] = 1;       /* status: armed for suspend */
    } else {
        apic_table[2] = original_slot2;
        out32[1] = 0xFF;
    }

    out[104] = 0xdeadbeefcafe0005ULL;

    return 0;
}

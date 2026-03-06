#include <stdint.h>

/*
 * pcb_dump v17 — Dump the full PCB struct to find pcb_onfault offset
 *
 * Reads curthread via gs:0, dereferences td_pcb at +0x3f8,
 * dumps 512 bytes (64 qwords) of the PCB into the output buffer.
 * Also reads the actual CR3 for cross-reference with pcb_cr3 field.
 *
 * The FreeBSD 9.0 header says pcb_onfault is at ~0xe8, but PS5's
 * struct is larger (pcb_flags is at 0x100 not 0xdc). We dump enough
 * to find it empirically.
 *
 * Output layout (uint64_t indices):
 *   [0]     magic "PCBD" (0x50434244) | status(32)
 *   [1]     kdata_base
 *   [2]     ktext_base (from LSTAR)
 *   [3]     curthread address
 *   [4]     td_pcb address (from curthread+0x3f8)
 *
 *   --- Raw PCB dump: 64 qwords (512 bytes) ---
 *   [5..68]  pcb[0x000..0x1f8]
 *
 *   --- Cross-reference values ---
 *   [69]    actual CR3 (from register)
 *   [70]    actual DR0
 *   [71]    actual DR1
 *   [72]    actual DR2
 *   [73]    actual DR3
 *   [74]    actual DR6
 *   [75]    actual DR7
 *
 *   --- Extended PCB dump: 32 more qwords (256 bytes) ---
 *   [76..107] pcb[0x200..0x2f8]
 *
 *   [108]   sentinel 0xdeadbeefcafe0017
 *
 *   --- Second thread PCB (idle thread) for comparison ---
 *   [109]   idle thread address
 *   [110]   idle td_pcb address
 *   [111..174] idle pcb[0x000..0x1f8] (64 qwords)
 *
 *   [175]   sentinel 0xdeadbeefcafe0018
 */

#define MAGIC_PCBD       0x50434244  /* "PCBD" */

/* FW 4.03 pcpu_array offset from kdata_base */
#define PCPU_ARRAY_OFF   0x64d2280

/* pcpu field offsets */
#define PC_CURTHREAD     0x00
#define PC_IDLETHREAD    0x08

/* thread field offsets */
#define TD_PCB           0x3f8

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

static inline uint64_t read_cr3(void)
{
    uint64_t val;
    __asm__ volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output area */
    for (int i = 0; i < 280; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    /* Header */
    out32[0] = MAGIC_PCBD;
    out32[1] = 0xAAAA;  /* in-progress */
    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Get curthread via gs:0 */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    out[3] = curthread;

    /* Read td_pcb */
    uint64_t td_pcb = read8(curthread + TD_PCB);
    out[4] = td_pcb;

    /* Dump 64 qwords (512 bytes) of PCB */
    if (td_pcb) {
        for (int i = 0; i < 64; i++) {
            out[5 + i] = read8(td_pcb + i * 8);
        }
    }

    /* Cross-reference: actual register values */
    out[69] = read_cr3();

    uint64_t dr_val;
    __asm__ volatile("mov %%dr0, %0" : "=r"(dr_val)); out[70] = dr_val;
    __asm__ volatile("mov %%dr1, %0" : "=r"(dr_val)); out[71] = dr_val;
    __asm__ volatile("mov %%dr2, %0" : "=r"(dr_val)); out[72] = dr_val;
    __asm__ volatile("mov %%dr3, %0" : "=r"(dr_val)); out[73] = dr_val;
    __asm__ volatile("mov %%dr6, %0" : "=r"(dr_val)); out[74] = dr_val;
    __asm__ volatile("mov %%dr7, %0" : "=r"(dr_val)); out[75] = dr_val;

    /* Extended PCB dump: 32 more qwords at offset 0x200 */
    if (td_pcb) {
        for (int i = 0; i < 32; i++) {
            out[76 + i] = read8(td_pcb + 0x200 + i * 8);
        }
    }

    out[108] = 0xdeadbeefcafe0017ULL;

    /* --- Second PCB: idle thread for comparison --- */
    uint64_t pcpu0 = kdata_base + PCPU_ARRAY_OFF;
    uint64_t idlethread = read8(pcpu0 + PC_IDLETHREAD);
    out[109] = idlethread;

    uint64_t idle_pcb = idlethread ? read8(idlethread + TD_PCB) : 0;
    out[110] = idle_pcb;

    if (idle_pcb) {
        for (int i = 0; i < 64; i++) {
            out[111 + i] = read8(idle_pcb + i * 8);
        }
    }

    out[175] = 0xdeadbeefcafe0018ULL;

    /* Mark success */
    out32[1] = 0x0001;

    return 0;
}

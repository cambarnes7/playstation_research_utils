#include <stdint.h>

/*
 * PS5 Gadget Reader (kstuff payload)
 *
 * Reads raw bytes from known ktext locations to:
 *   1. Find stack pivot gadgets in cpu_switch
 *   2. Check xapic_mode dispatch site for CFI instrumentation
 *   3. Dump key gadgets from flatz's offset table for verification
 *
 * Runs in kernel context via kldload -> kproc_create.
 * Results written to kthread_args buffer for readback.
 */

/* ── FW 4.03 offsets (relative to kdata_base, negative = ktext) ── */
#define OFF_CPU_SWITCH       (-0x9d6f80)
#define OFF_WRMSR_RET        (-0x9d20cc)
#define OFF_NOP_RET           (OFF_WRMSR_RET + 2)
#define OFF_DORETI_IRET      (-0x9cf84c)
#define OFF_ADD_RSP_IRET     (OFF_DORETI_IRET - 7)
#define OFF_REP_MOVSB_POP    (-0x99002a)
#define OFF_MOV_CR3_RAX      (-0x396f9e)
#define OFF_MOV_RDI_CR3      (-0x39700e)
#define OFF_RDMSR_START      (-0x9d0cfa)
#define OFF_JUSTRETURN       (-0x9cf990)
#define OFF_JUSTRETURN_POP   (OFF_JUSTRETURN + 8)
#define OFF_POP_ALL_IRET     (-0x9cf8ab)
#define OFF_COPYIN           (-0x9908e0)
#define OFF_COPYOUT          (-0x990990)

/*
 * APIC ops table offset from ktext_base.
 * apic_ops is at ktext_base + 0x1934AC8.
 * The xapic_mode caller is somewhere that does:
 *   call [apic_ops + 2*8]
 * We need to find this call site. The LAPIC code that calls xapic_mode
 * is typically in lapic_init or lapic_setup. We'll scan around known
 * APIC function offsets from the dump.
 *
 * From apic_ops dump:
 *   xapic_mode function itself is at ktext+0x294340
 *   But we need the CALLER, which references apic_ops[2].
 *
 * Strategy: scan ktext for the apic_ops address pattern.
 * apic_ops table is at ktext + 0x1934AC8.
 * A caller would reference this address + 0x10 (slot 2).
 * We'll also check the resume path - look for references in
 * the cpususpend_handler area.
 */

/* Number of bytes to dump per region */
#define REGION_SIZE 256

/* Max number of scan regions */
#define MAX_REGIONS 8

/* Result magic */
#define MAGIC_GADGET 0x47414447  /* "GADG" */

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

/*
 * Output layout:
 *   [0x000] uint32_t magic = "GADG"
 *   [0x004] uint32_t num_regions
 *   [0x008] uint64_t kdata_base
 *   [0x010] uint64_t ktext_base
 *
 *   Per region (starts at 0x018, each region = 8 + 8 + REGION_SIZE):
 *     uint64_t addr       - kernel VA of region start
 *     uint64_t offset     - offset from kdata_base (signed)
 *     uint8_t  bytes[REGION_SIZE]
 *
 * Total per region: 16 + 256 = 272 bytes
 * Header: 24 bytes
 * Max payload: 24 + 8 * 272 = 2200 bytes (fits in 4KB kthread_args)
 */

typedef struct __attribute__((packed)) {
    uint64_t addr;
    int64_t  offset;
    uint8_t  bytes[REGION_SIZE];
} region_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t num_regions;
    uint64_t kdata_base;
    uint64_t ktext_base;
    region_t regions[MAX_REGIONS];
} gadget_result_t;

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static void read_region(region_t* r, uint64_t addr, int64_t offset)
{
    r->addr = addr;
    r->offset = offset;
    volatile uint8_t* src = (volatile uint8_t*)addr;
    for (int i = 0; i < REGION_SIZE; i++)
        r->bytes[i] = src[i];
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;

    /* Estimate ktext_base from LSTAR */
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    gadget_result_t* out = (gadget_result_t*)args;
    out->magic = MAGIC_GADGET;
    out->kdata_base = kdata_base;
    out->ktext_base = ktext_base;

    int n = 0;

    /*
     * Region 0: cpu_switch (256 bytes)
     * This is the context switch function - likely contains
     * mov rsp, [reg+offset] or similar stack pivot gadgets.
     */
    read_region(&out->regions[n++], kdata_base + OFF_CPU_SWITCH, OFF_CPU_SWITCH);

    /*
     * Region 1: wrmsr_ret + surrounding context (256 bytes)
     * Contains: wrmsr; ret; nop (our nop_ret gadget)
     * Start 16 bytes before wrmsr_ret to see preamble.
     */
    read_region(&out->regions[n++], kdata_base + OFF_WRMSR_RET - 16, OFF_WRMSR_RET - 16);

    /*
     * Region 2: doreti_iret region (256 bytes)
     * Contains: swapgs; add rsp,N; iretq
     * Also add_rsp_iret and doreti_iret.
     * Start 32 bytes before to capture swapgs variant.
     */
    read_region(&out->regions[n++], kdata_base + OFF_DORETI_IRET - 32, OFF_DORETI_IRET - 32);

    /*
     * Region 3: rep movsb; pop rbp; ret (256 bytes)
     * memcpy gadget - useful for arbitrary memory writes in ROP.
     */
    read_region(&out->regions[n++], kdata_base + OFF_REP_MOVSB_POP - 16, OFF_REP_MOVSB_POP - 16);

    /*
     * Region 4: mov cr3, rax region (256 bytes)
     * CR3 manipulation - useful for page table switching.
     */
    read_region(&out->regions[n++], kdata_base + OFF_MOV_CR3_RAX - 16, OFF_MOV_CR3_RAX - 16);

    /*
     * Region 5: rdmsr region (256 bytes)
     * MSR read gadget.
     */
    read_region(&out->regions[n++], kdata_base + OFF_RDMSR_START, OFF_RDMSR_START);

    /*
     * Region 6: justreturn / pop_all_iret (256 bytes)
     * Return path gadgets for ending the ROP chain.
     */
    read_region(&out->regions[n++], kdata_base + OFF_POP_ALL_IRET - 16, OFF_POP_ALL_IRET - 16);

    /*
     * Region 7: copyin (256 bytes)
     * Kernel copyin function - useful as arbitrary write primitive.
     */
    read_region(&out->regions[n++], kdata_base + OFF_COPYIN, OFF_COPYIN);

    out->num_regions = n;

    return 0;
}

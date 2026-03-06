#include <stdint.h>

/*
 * PS5 APIC Ops Reader (kldload module)
 *
 * Reads the apic_ops function pointer table from kernel data and writes
 * results into the kthread_args buffer so kldload can read them back
 * over the network.
 *
 * Args struct (passed by kldload via kproc_create):
 *   [0]  uint64_t kdata_base
 *   [8]  uint32_t fw_ver
 *
 * We reuse this buffer (and extend it) to write results back.
 */

/* FW 4.03 offsets (relative to kernel base, not kdata) */
#define APIC_OPS_OFFSET    0x1934AC8   /* kdata + apic_ops_offset */
#define KPRINTF_OFFSET     0x28da78

/* apic_ops slot names */
static const char* apic_op_names[] = {
    "create",           /*  0 */
    "init",             /*  1 */
    "xapic_mode",       /*  2 */
    "is_x2apic",        /*  3 */
    "setup",            /*  4 */
    "dump",             /*  5 */
    "disable",          /*  6 */
    "set_id",           /*  7 */
    "ipi_raw",          /*  8 */
    "ipi_vectored",     /*  9 */
    "ipi_wait",         /* 10 */
    "ipi_alloc",        /* 11 */
    "ipi_free",         /* 12 */
    "set_lvt_mask",     /* 13 */
    "set_lvt_mode",     /* 14 */
    "set_lvt_polarity", /* 15 */
    "set_lvt_triggermode", /* 16 */
    "lvt_eoi_clear",    /* 17 */
    "set_tpr",          /* 18 */
    "get_timer_freq",   /* 19 */
    "timer_enable_intr",  /* 20 */
    "timer_disable_intr", /* 21 */
    "timer_set_divisor",  /* 22 */
    "timer_initial_count",/* 23 */
    "timer_current_count",/* 24 */
    "self_ipi",         /* 25 */
};

#define NUM_APIC_OPS 26

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t low, high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr));
    return ((uint64_t)high << 32) | low;
}

static inline uint64_t read_cr0(void)
{
    uint64_t val;
    __asm__ volatile("mov %%cr0, %0" : "=r"(val));
    return val;
}

static inline uint64_t read_cr3(void)
{
    uint64_t val;
    __asm__ volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

static inline uint64_t read_cr4(void)
{
    uint64_t val;
    __asm__ volatile("mov %%cr4, %0" : "=r"(val));
    return val;
}

/*
 * Output buffer layout (written over kthread_args):
 *
 *   [0x000] uint32_t magic = 0x41504943 ("APIC")
 *   [0x004] uint32_t fw_ver
 *   [0x008] uint64_t kdata_base
 *   [0x010] uint64_t ktext_base (estimated from LSTAR)
 *   [0x018] uint64_t lstar
 *   [0x020] uint64_t efer
 *   [0x028] uint64_t apic_base_msr
 *   [0x030] uint64_t cr0
 *   [0x038] uint64_t cr3
 *   [0x040] uint64_t cr4
 *   [0x048] uint64_t apic_ops_addr (kernel VA of apic_ops table)
 *   [0x050] uint32_t num_ops = 26
 *   [0x054] uint32_t reserved
 *   [0x058] uint64_t apic_ops[26] (the actual function pointers)
 */

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t fw_ver;
    uint64_t kdata_base;
    uint64_t ktext_base;
    uint64_t lstar;
    uint64_t efer;
    uint64_t apic_base_msr;
    uint64_t cr0;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t apic_ops_addr;
    uint32_t num_ops;
    uint32_t reserved;
    uint64_t apic_ops[NUM_APIC_OPS];
} apic_result_t;

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t fw_ver = args->fw_ver;

    /* Estimate kernel text base from LSTAR */
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218; /* Xfast_syscall offset for 4.03 */

    /* Read MSRs and CRs */
    uint64_t efer = rdmsr(0xC0000080);
    uint64_t apic_base_msr = rdmsr(0x1B);
    uint64_t cr0 = read_cr0();
    uint64_t cr3 = read_cr3();
    uint64_t cr4 = read_cr4();

    /* Find apic_ops table in kernel data */
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFFSET;

    /* Read apic_ops pointers via DMAP */
    /* We need DMAP base to read kernel memory. Compute from cr3. */
    /* On PS5, kernel_pmap->pm_pml4 - kernel_pmap->pm_cr3 = DMAP base */
    /* But we can't easily get that without more offsets. */
    /* Instead, read directly since we're in kernel context with kernel CR3. */
    volatile uint64_t* apic_ops_table = (volatile uint64_t*)apic_ops_addr;

    /* Write results into the args buffer (which kldload will read back) */
    apic_result_t* result = (apic_result_t*)args;

    result->magic = 0x41504943; /* "APIC" */
    result->fw_ver = fw_ver;
    result->kdata_base = kdata_base;
    result->ktext_base = ktext_base;
    result->lstar = lstar;
    result->efer = efer;
    result->apic_base_msr = apic_base_msr;
    result->cr0 = cr0;
    result->cr3 = cr3;
    result->cr4 = cr4;
    result->apic_ops_addr = apic_ops_addr;
    result->num_ops = NUM_APIC_OPS;
    result->reserved = 0;

    /* Copy apic_ops function pointers */
    for (int i = 0; i < NUM_APIC_OPS; i++)
        result->apic_ops[i] = apic_ops_table[i];

    return 0;
}

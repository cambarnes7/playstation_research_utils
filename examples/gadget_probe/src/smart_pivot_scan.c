#include <stdint.h>

/*
 * smart_pivot_scan v6b — Static byte scanner with XO-aware fault recovery
 *
 * PS5 ktext is execute-only (XO). Reading code bytes triggers #PF,
 * which pcb_onfault CAN catch (unlike #GP/#UD from execution probes).
 *
 * Strategy:
 *   1. Find pcb_onfault via curthread+0x3f8 → pcb+0xb0
 *   2. Set pcb_onfault to fault handler before each read attempt
 *   3. Try reading ktext bytes — if #PF, skip to next page boundary
 *   4. If readable, scan for RSP-pivot byte patterns
 *
 * Configure via -D flags:
 *   SCAN_BATCH: chunk index (each chunk scans 768KB of ktext)
 */

#ifndef SCAN_BATCH
#define SCAN_BATCH     0
#endif

#define MAGIC_SPVT     0x53505654
#define KTEXT_SIZE     0xC00000   /* 12MB */
#define CHUNK_SIZE     0xC0000    /* 768KB per batch = 16 batches */
#define HEADER_SLOTS   8
#define MAX_RESULTS    ((2304/8) - HEADER_SLOTS)

#define TD_PCB_OFF      0x3f8
#define PCB_ONFAULT_OFF 0xb0

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

/* Globals for fault recovery */
static volatile uint64_t read_saved_rsp;
static volatile uint64_t read_resume_rip;
static volatile int read_faulted;
static volatile uint64_t onfault_addr;
static volatile uint64_t saved_onfault_val;

__attribute__((naked, used))
static void read_fault_handler(void)
{
    __asm__ volatile(
        "movq $1, read_faulted(%%rip)\n\t"
        "movq read_saved_rsp(%%rip), %%rsp\n\t"
        "jmpq *read_resume_rip(%%rip)\n\t"
        ::: "memory"
    );
}

/* Try to read a byte from addr. Returns the byte value, or -1 on fault. */
static inline int safe_read_byte(volatile uint8_t* addr)
{
    read_faulted = 0;

    int result;
    __asm__ volatile(
        /* Save RSP and set resume point */
        "movq %%rsp, read_saved_rsp(%%rip)\n\t"
        "leaq 1f(%%rip), %%rcx\n\t"
        "movq %%rcx, read_resume_rip(%%rip)\n\t"

        /* Try the read */
        "movzbl (%1), %0\n\t"
        "jmp 2f\n\t"

        /* Fault resume */
        "1:\n\t"
        "movl $-1, %0\n\t"

        "2:\n\t"
        : "=r"(result)
        : "r"(addr)
        : "rcx", "memory"
    );

    return result;
}

/* Read 4 bytes safely. Returns 0 on success, -1 on fault. */
static inline int safe_read_4bytes(volatile uint8_t* addr, uint8_t* buf)
{
    read_faulted = 0;

    int ok;
    __asm__ volatile(
        "movq %%rsp, read_saved_rsp(%%rip)\n\t"
        "leaq 1f(%%rip), %%rcx\n\t"
        "movq %%rcx, read_resume_rip(%%rip)\n\t"

        /* Try reading 4 bytes via a 32-bit load */
        "movl (%1), %%ecx\n\t"
        "movl %%ecx, (%2)\n\t"
        "xorl %0, %0\n\t"       /* ok = 0 (success) */
        "jmp 2f\n\t"

        "1:\n\t"
        "movl $-1, %0\n\t"      /* ok = -1 (fault) */

        "2:\n\t"
        : "=r"(ok)
        : "r"(addr), "r"(buf)
        : "rcx", "memory"
    );

    return ok;
}

static uint64_t find_pcb_onfault(void)
{
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0x08, %0" : "=r"(curthread));

    uint64_t pcb = *(volatile uint64_t*)(curthread + TD_PCB_OFF);
    if ((pcb >> 40) != 0xFFFFFF)
        return 0;

    uint64_t addr = pcb + PCB_ONFAULT_OFF;
    saved_onfault_val = *(volatile uint64_t*)addr;
    return addr;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    volatile uint64_t* out = (volatile uint64_t*)args;

    for (int i = 0; i < 2304/8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = (uint64_t)SCAN_BATCH;

    /* Find pcb_onfault */
    onfault_addr = find_pcb_onfault();
    if (!onfault_addr) {
        out[0] = ((uint64_t)0xDEAD << 32) | MAGIC_SPVT;
        return 0;
    }

    /* Set pcb_onfault to our handler for the duration of scanning */
    *(volatile uint64_t*)onfault_addr = (uint64_t)read_fault_handler;

    /* Calculate scan range for this batch */
    uint64_t scan_start = ktext_base + (uint64_t)SCAN_BATCH * CHUNK_SIZE;
    uint64_t scan_end = scan_start + CHUNK_SIZE;
    if (scan_end > ktext_base + KTEXT_SIZE)
        scan_end = ktext_base + KTEXT_SIZE;
    if (scan_start >= ktext_base + KTEXT_SIZE) {
        *(volatile uint64_t*)onfault_addr = saved_onfault_val;
        out[0] = ((uint64_t)0xFFFF << 32) | MAGIC_SPVT;
        return 0;
    }

    out[4] = scan_start;
    out[5] = scan_end;

    int n_results = 0;
    int pages_readable = 0;
    int pages_xo = 0;

    /* Scan page by page */
    for (uint64_t page = scan_start; page < scan_end && n_results < MAX_RESULTS;
         page += 0x1000) {

        /* Test if this page is readable */
        int b = safe_read_byte((volatile uint8_t*)page);
        if (b < 0) {
            pages_xo++;
            continue;  /* XO page, skip */
        }
        pages_readable++;

        /* Page is readable — scan it for pivot patterns */
        volatile uint8_t* p = (volatile uint8_t*)page;
        for (int i = 0; i < 0x1000 - 4 && n_results < MAX_RESULTS; i++) {
            uint8_t b0 = p[i];
            uint8_t b1 = p[i+1];

            /* pop rsp; ret (5C C3) */
            if (b0 == 0x5C && b1 == 0xC3) {
                out[HEADER_SLOTS + n_results++] = (page + i) | ((uint64_t)0x01 << 56);
                continue;
            }

            /* leave; ret (C9 C3) — very common, skip to save space */
            /* if (b0 == 0xC9 && b1 == 0xC3) { ... } */

            /* pop rsp; pop reg; ret (5C 5x C3) */
            if (b0 == 0x5C && (b1 >= 0x58 && b1 <= 0x5F) && p[i+2] == 0xC3) {
                out[HEADER_SLOTS + n_results++] = (page + i) | ((uint64_t)0x0B << 56);
                continue;
            }

            /* REX.W prefix patterns (48 ...) */
            if (b0 == 0x48) {
                uint8_t b2 = p[i+2];
                uint8_t b3 = p[i+3];

                /* xchg rax,rsp; ret (48 94 C3) */
                if (b1 == 0x94 && b2 == 0xC3) {
                    out[HEADER_SLOTS + n_results++] = (page + i) | ((uint64_t)0x02 << 56);
                    continue;
                }

                /* xchg reg,rsp; ret (48 87 E? C3) */
                if (b1 == 0x87 && (b2 & 0xF8) == 0xE0 && b3 == 0xC3) {
                    out[HEADER_SLOTS + n_results++] = (page + i) | ((uint64_t)0x0C << 56);
                    continue;
                }

                /* mov rsp,REG; ret (48 89 XX C3) */
                if (b1 == 0x89 && b3 == 0xC3) {
                    int pat = 0;
                    switch (b2) {
                        case 0xC4: pat = 0x03; break; /* rax */
                        case 0xDC: pat = 0x04; break; /* rbx */
                        case 0xCC: pat = 0x05; break; /* rcx */
                        case 0xD4: pat = 0x06; break; /* rdx */
                        case 0xF4: pat = 0x07; break; /* rsi */
                        case 0xFC: pat = 0x08; break; /* rdi */
                        case 0xEC: pat = 0x09; break; /* rbp */
                    }
                    if (pat) {
                        out[HEADER_SLOTS + n_results++] = (page + i) | ((uint64_t)pat << 56);
                        continue;
                    }
                }

                /* mov rsp,[reg]; ret (48 8B 2x C3) */
                if (b1 == 0x8B && b3 == 0xC3 &&
                    (b2 & 0xF8) == 0x20 && b2 != 0x24 && b2 != 0x25) {
                    out[HEADER_SLOTS + n_results++] = (page + i) | ((uint64_t)0x10 << 56);
                    continue;
                }

                /* mov rsp,[reg+disp8]; ret (48 8B 6x XX C3) */
                if (b1 == 0x8B && (b2 & 0xF8) == 0x60 && b2 != 0x64 &&
                    p[i+4] == 0xC3) {
                    out[HEADER_SLOTS + n_results++] = (page + i) | ((uint64_t)0x11 << 56);
                    continue;
                }
            }

            /* pop rsp; pop; pop; ret (5C 5x 5x C3) */
            if (b0 == 0x5C && (b1 >= 0x58 && b1 <= 0x5F) &&
                (p[i+2] >= 0x58 && p[i+2] <= 0x5F) && p[i+3] == 0xC3) {
                out[HEADER_SLOTS + n_results++] = (page + i) | ((uint64_t)0x20 << 56);
                continue;
            }
        }
    }

    /* Restore pcb_onfault */
    *(volatile uint64_t*)onfault_addr = saved_onfault_val;

    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    out[3] |= ((uint64_t)n_results << 16);
    out[6] = (uint64_t)pages_readable | ((uint64_t)pages_xo << 32);
    out[7] = onfault_addr;

    return 0;
}

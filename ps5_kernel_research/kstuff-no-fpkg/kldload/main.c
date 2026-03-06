/*
 * kldload - PS5 Kernel Module Loader
 *
 * Accepts kernel modules over TCP (port 9022), copies them into
 * executable kernel memory, and launches them as kernel threads.
 * After execution, reads back the kthread_args buffer and displays
 * the results.
 *
 * Requires kstuff to be loaded first (provides kekcall infrastructure).
 *
 * Kekcalls used:
 *   nr=6:  malloc(size) -> kernel address
 *   nr=7:  kproc_create(func, args, name)
 *   nr=8:  copyin(user_buf, kern_addr, size)
 *   nr=9:  mode=5: read kernel uint64 at address
 *   nr=10: clear NX bit on page
 *   nr=0xffffffff: check if kstuff is loaded
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ps5/payload.h>

#define PORT 9022
#define READBACK_SIZE 2304  /* bytes to read back from kthread_args (enough for gadget_reader) */

/* kekcall wrappers (in kekcall.asm) */
extern uint64_t kekcall_malloc(uint64_t size);
extern int64_t  kekcall_copyin(void* user_buf, uint64_t kern_addr, uint64_t size);
extern int64_t  kekcall_kproc_create(uint64_t func, uint64_t args, uint64_t name);
extern uint64_t kekcall_read_kmem(uint64_t mode, uint64_t addr);
extern uint64_t kekcall_make_exec(uint64_t kern_addr, uint64_t mode);
extern uint64_t kekcall_check(void);

static uint64_t kdata_base_addr = 0;
static uint32_t fw_version = 0;

static void _kldload(void* data, size_t data_size)
{
    int kstuff_loaded = (kekcall_check() == 0) ? 1 : 0;

    printf("[debug] _kldload called, data_size=%ld, kstuff_loaded=%d\n",
           (long)data_size, kstuff_loaded);

    if (!kstuff_loaded) {
        printf("[error] kstuff not loaded! Cannot proceed.\n");
        return;
    }

    /* Allocate kernel memory for code, process name, and thread args */
    printf("[debug] about to call malloc(%ld) via kekcall nr=6...\n", (long)data_size);

    uint64_t exec_code = kekcall_malloc(data_size);
    uint64_t kproc_name = kekcall_malloc(0x100);
    uint64_t kthread_args = kekcall_malloc(0x1000); /* 4KB for args/results */

    printf("[debug] malloc returned exec_code=%#lx\n", exec_code);
    printf("[debug] malloc returned kproc_name=%#lx\n", kproc_name);
    printf("[debug] malloc returned kthread_args=%#lx\n", kthread_args);

    if (!exec_code || !kproc_name || !kthread_args) {
        printf("[error] malloc failed!\n");
        return;
    }

    /* Prepare kthread_args: kdata_base (uint64) + fw_ver (uint32) */
    struct {
        uint64_t kdata_base;
        uint32_t fw_ver;
        uint32_t pad;
    } args_buf;
    args_buf.kdata_base = kdata_base_addr;
    args_buf.fw_ver = fw_version;
    args_buf.pad = 0;

    printf("[debug] kdata_base=%#lx fw_ver=%u\n", kdata_base_addr, fw_version);

    /* Copy code into kernel memory */
    printf("[debug] kekcall_copyin exec_code (%#lx, %ld bytes)...\n", exec_code, (long)data_size);
    int64_t ret = kekcall_copyin(data, exec_code, data_size);
    printf("[debug] kekcall_copyin exec_code returned %ld\n", ret);
    if (ret != 0) {
        printf("[error] copyin exec_code failed!\n");
        return;
    }

    /* Copy process name */
    printf("[debug] kekcall_copyin kproc_name...\n");
    ret = kekcall_copyin("my_kthread\x00", kproc_name, 11);
    printf("[debug] kekcall_copyin kproc_name returned %ld\n", ret);

    /* Copy thread args */
    printf("[debug] kekcall_copyin kthread_args...\n");
    ret = kekcall_copyin(&args_buf, kthread_args, sizeof(args_buf));
    printf("[debug] kekcall_copyin kthread_args returned %ld\n", ret);

    if (ret != 0) {
        printf("[error] copyin kthread_args failed!\n");
        return;
    }

    /* Clear NX bit on exec_code pages */
    printf("[debug] clearing NX bit on exec_code pages...\n");
    uint64_t pte = kekcall_make_exec(exec_code, 1);
    printf("[debug] kekcall_make_exec returned %#lx (original PTE)\n", pte);

    /* Sleep briefly to let NX clearing take effect */
    usleep(10000);

    /* Launch the kernel thread */
    printf("[debug] calling kproc_create via kekcall...\n");
    kekcall_kproc_create(exec_code, kthread_args, kproc_name);
    printf("[debug] kproc_create returned\n");

    /* Wait for thread to complete */
    usleep(100000); /* 100ms */

    /* Read back results from kthread_args */
    printf("[debug] reading back kthread_args (%d bytes)...\n", READBACK_SIZE);

    uint64_t readback[READBACK_SIZE / 8];
    for (int i = 0; i < READBACK_SIZE / 8; i++) {
        readback[i] = kekcall_read_kmem(5, kthread_args + i * 8);
    }

    /* Check for APIC result magic */
    uint32_t magic = (uint32_t)(readback[0] & 0xFFFFFFFF);
    uint32_t result_fw = (uint32_t)(readback[0] >> 32);

    if (magic == 0x41504943) { /* "APIC" */
        printf("\n=== APIC OPS READER RESULTS ===\n");
        printf("  FW version:  0x%x\n", result_fw);
        printf("  kdata_base:  %#lx\n", readback[1]);
        printf("  ktext_base:  %#lx\n", readback[2]);
        printf("  LSTAR:       %#lx\n", readback[3]);
        printf("  EFER:        %#lx\n", readback[4]);
        printf("  APIC_BASE:   %#lx\n", readback[5]);
        printf("  CR0:         %#lx\n", readback[6]);
        printf("  CR3:         %#lx\n", readback[7]);
        printf("  CR4:         %#lx\n", readback[8]);
        printf("  apic_ops @:  %#lx\n", readback[9]);
        uint32_t num_ops = (uint32_t)(readback[10] & 0xFFFFFFFF);
        printf("  num_ops:     %u\n", num_ops);

        static const char* apic_op_names[] = {
            "create", "init", "xapic_mode", "is_x2apic",
            "setup", "dump", "disable", "set_id",
            "ipi_raw", "ipi_vectored", "ipi_wait", "ipi_alloc",
            "ipi_free", "set_lvt_mask", "set_lvt_mode", "set_lvt_polarity",
            "set_lvt_triggermode", "lvt_eoi_clear", "set_tpr", "get_timer_freq",
            "timer_enable_intr", "timer_disable_intr", "timer_set_divisor",
            "timer_initial_count", "timer_current_count", "self_ipi"
        };

        uint64_t ktext_base = readback[2];
        printf("\n  %-4s %-24s %-20s %s\n", "Slot", "Name", "Address", "ktext offset");
        printf("  %-4s %-24s %-20s %s\n", "----", "----", "-------", "------------");

        for (uint32_t i = 0; i < num_ops && i < 26; i++) {
            uint64_t addr = readback[11 + i]; /* apic_ops start at offset 0x58 = index 11 */
            const char* name = (i < 26) ? apic_op_names[i] : "???";
            if (addr >= ktext_base) {
                printf("  [%2d] %-24s %#-20lx ktext+0x%lx\n",
                       i, name, addr, addr - ktext_base);
            } else if (addr == 0) {
                printf("  [%2d] %-24s (null)\n", i, name);
            } else {
                printf("  [%2d] %-24s %#-20lx\n", i, name, addr);
            }
        }

        printf("\n  Key slot: xapic_mode (slot[2]) = %#lx\n", readback[13]);
        printf("  This pointer is in RW kernel data\n");
        printf("  With KRW: overwrite -> suspend/resume -> code runs before HV\n");

        printf("\n=== END APIC OPS ===\n");
    } else if (magic == 0x52454750) { /* "REGP" - register probe results */
        uint32_t status = (uint32_t)(readback[0] >> 32);

        printf("\n=== REGISTER PROBE RESULTS ===\n");
        printf("  status:     %s\n", status == 1 ? "SUCCESS" : "FAILED/CRASHED");
        printf("  kdata_base: %#lx\n", readback[1]);
        printf("  ktext_base: %#lx\n", readback[2]);
        printf("  apic_ops @: %#lx\n", readback[3]);
        printf("  xapic_mode returned: %lu\n", readback[4]);

        if (status == 1) {
            static const char* rnames[] = {
                "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "R8 ",
                "R9 ", "R10", "R11", "R12", "R13", "R14", "R15", "RSP"
            };
            uint64_t apic_addr = readback[3];
            printf("\n  Registers at xapic_mode entry:\n");
            for (int i = 0; i < 16; i++) {
                uint64_t val = readback[5 + i];
                const char* note = "";
                if (val == apic_addr)
                    note = " <-- apic_ops table! PIVOT REGISTER";
                else if (val >= readback[2] && val < readback[1])
                    note = " (ktext)";
                else if (val >= readback[1] && val < readback[1] + 0x10000000)
                    note = " (kdata)";
                printf("    %s: %#018lx%s\n", rnames[i], val, note);
            }
        }

        printf("\n=== END REGISTER PROBE ===\n");
    } else if (magic == 0x50495654) { /* "PIVT" - pivot test results */
        /*
         * Layout (packed):
         *   readback[0]: magic(32) | num_tests(32)
         *   readback[1]: kdata_base
         *   readback[2]: ktext_base
         *   readback[3]: nop_ret_addr
         *   readback[4]: test1_status(32) | test2_status(32)
         *   readback[5]: apic_ops2_original
         *   readback[6]: apic_ops2_readback
         *   readback[7]: test3_status(32) | pad(32)
         */
        uint32_t t1 = (uint32_t)(readback[4] & 0xFFFFFFFF);
        uint32_t t2 = (uint32_t)(readback[4] >> 32);
        uint32_t t3 = (uint32_t)(readback[7] & 0xFFFFFFFF);

        printf("\n=== PIVOT TEST RESULTS ===\n");
        printf("  kdata_base:  %#lx\n", readback[1]);
        printf("  ktext_base:  %#lx\n", readback[2]);
        printf("  nop_ret @:   %#lx\n", readback[3]);

        printf("\n  Test 1 (call nop_ret):     %s\n",
               t1 == 1 ? "PASS" : t1 == 0xAAAA ? "CRASHED" : "not reached");
        printf("  Test 2 (RSP pivot + ROP):  %s\n",
               t2 == 1 ? "PASS" : t2 == 0xAAAA ? "CRASHED" : "not reached");
        printf("  Test 3 (apic_ops write):   %s\n",
               t3 == 1 ? "PASS" : t3 == 0xAAAA ? "CRASHED" :
               t3 == 0xFFFF ? "WRITE FAILED" : "not reached");

        if (t3 == 1 || t3 == 0xFFFF) {
            printf("\n  apic_ops[2] original:  %#lx\n", readback[5]);
            printf("  apic_ops[2] readback:  %#lx\n", readback[6]);
        }

        printf("\n=== END PIVOT TEST ===\n");
    } else if (magic == 0x47414447) { /* "GADG" - gadget reader results */
        uint32_t num_regions = (uint32_t)(readback[0] >> 32);
        uint64_t rb_kdata = readback[1];
        uint64_t rb_ktext = readback[2];

        printf("\n=== GADGET READER RESULTS ===\n");
        printf("  kdata_base: %#lx\n", rb_kdata);
        printf("  ktext_base: %#lx\n", rb_ktext);
        printf("  regions:    %u\n\n", num_regions);

        /* Each region starts at byte offset 24 (3 uint64s header)
         * Region layout: addr(8) + offset(8) + bytes(256) = 272 bytes */
        uint8_t* raw = (uint8_t*)readback;
        for (uint32_t r = 0; r < num_regions && r < 8; r++) {
            uint8_t* rp = raw + 24 + r * 272;
            uint64_t raddr = *(uint64_t*)rp;
            int64_t  roff  = *(int64_t*)(rp + 8);
            uint8_t* rbytes = rp + 16;

            const char* label = "unknown";
            if (roff == -0x9d6f80)       label = "cpu_switch";
            else if (roff == (-0x9d20cc - 16)) label = "wrmsr_ret region";
            else if (roff == (-0x9cf84c - 32)) label = "doreti_iret region";
            else if (roff == (-0x99002a - 16)) label = "rep_movsb_pop region";
            else if (roff == (-0x396f9e - 16)) label = "mov_cr3_rax region";
            else if (roff == -0x9d0cfa)  label = "rdmsr region";
            else if (roff == (-0x9cf8ab - 16)) label = "pop_all_iret region";
            else if (roff == -0x9908e0)  label = "copyin";

            printf("  --- Region %u: %s ---\n", r, label);
            printf("  Address: %#lx (kdata_base %+ld / ktext+%#lx)\n",
                   raddr, roff, (uint64_t)(raddr - rb_ktext));

            /* Hex dump with inline ASCII */
            for (int row = 0; row < 256; row += 16) {
                printf("  %04x: ", row);
                for (int col = 0; col < 16; col++) {
                    printf("%02x ", rbytes[row + col]);
                    if (col == 7) printf(" ");
                }
                printf(" |");
                for (int col = 0; col < 16; col++) {
                    uint8_t c = rbytes[row + col];
                    printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
                }
                printf("|\n");
            }
            printf("\n");
        }

        printf("=== END GADGET READER ===\n");
    } else if (magic == 0x43505250) { /* "CPRP" - chain preparation results */
        uint32_t overall = (uint32_t)(readback[0] >> 32);
        uint32_t t1 = (uint32_t)(readback[8] & 0xFFFFFFFF);
        uint32_t t2 = (uint32_t)(readback[8] >> 32);

        printf("\n=== CHAIN PREP RESULTS ===\n");
        printf("  overall_status: %u\n", overall);
        printf("  kdata_base:     %#lx\n", readback[1]);
        printf("  ktext_base:     %#lx\n", readback[2]);

        printf("\n  --- System Registers (Test 1: %s) ---\n",
               t1 == 1 ? "PASS" : t1 == 0xAAAA ? "CRASHED" : "not reached");
        printf("  EFER:     %#018lx\n", readback[3]);
        printf("  CR0:      %#018lx\n", readback[4]);
        printf("  CR4:      %#018lx\n", readback[5]);
        uint16_t cs = (uint16_t)(readback[6] & 0xFFFF);
        uint16_t ss = (uint16_t)((readback[6] >> 16) & 0xFFFF);
        printf("  CS:       %#06x\n", cs);
        printf("  SS:       %#06x\n", ss);
        printf("  RFLAGS:   %#018lx\n", readback[7]);

        /* Decode key control register bits */
        uint64_t efer = readback[3];
        uint64_t cr0 = readback[4];
        uint64_t cr4 = readback[5];
        printf("\n  CR0 flags: WP=%lu\n", (cr0 >> 16) & 1);
        printf("  CR4 flags: SMEP=%lu SMAP=%lu\n", (cr4 >> 20) & 1, (cr4 >> 21) & 1);
        printf("  EFER flags: NXE=%lu SCE=%lu LMA=%lu\n",
               (efer >> 11) & 1, efer & 1, (efer >> 10) & 1);

        printf("\n  pop_all_iret @: %#lx\n", readback[9]);

        printf("\n  --- pop_all_iret Probe (Test 2: %s) ---\n",
               t2 == 1 ? "PASS" : t2 == 0xAAAA ? "CRASHED" : "not reached");

        if (t2 == 1) {
            static const char* rnames[] = {
                "RDI", "RSI", "RDX", "RCX", "R8 ", "R9 ", "RAX", "RBX",
                "RBP", "R10", "R11", "R12", "R13", "R14", "R15"
            };
            /* Expected markers: 0xD1..01 through 0xDF..0F */
            printf("  Register captures (marker = pop slot):\n");
            int match_count = 0;
            for (int i = 0; i < 15; i++) {
                uint64_t val = readback[10 + i];
                uint8_t slot = (uint8_t)(val & 0xFF);
                uint8_t hi = (uint8_t)(val >> 56);
                int is_marker = (hi >= 0xD1 && hi <= 0xDF);
                const char* note = "";
                if (is_marker && slot == (i + 1))
                    { note = " OK (expected)"; match_count++; }
                else if (is_marker)
                    note = " WRONG SLOT";
                else if ((val >> 56) == 0xEE)
                    note = " (skip marker - layout mismatch!)";
                else if ((val >> 56) == 0xAA || (val >> 56) == 0xBB ||
                         (val >> 56) == 0xCC || (val >> 56) == 0xDD)
                    note = " (skip/err marker - layout mismatch!)";
                printf("    %s: %#018lx%s\n", rnames[i], val, note);
            }
            printf("\n  Layout match: %d/15 registers correct\n", match_count);
            if (match_count == 15)
                printf("  pop_all_iret layout CONFIRMED - standard FreeBSD!\n");
            else
                printf("  Layout DIFFERS from standard - adjust SKIP_BYTES\n");
        }

        printf("\n=== END CHAIN PREP ===\n");
    } else if (magic == 0x47505242) { /* "GPRB" - gadget probe results */
        uint32_t status = (uint32_t)(readback[0] >> 32);
        uint64_t cand_addr = readback[3];
        uint32_t mode = (uint32_t)(readback[4] & 0xFFFFFFFF);
        uint32_t rcode = (uint32_t)(readback[4] >> 32);
        uint64_t marker_id = readback[5];

        printf("\n=== GADGET PROBE RESULTS ===\n");
        printf("  kdata_base:  %#lx\n", readback[1]);
        printf("  ktext_base:  %#lx\n", readback[2]);
        printf("  candidate:   %#lx (ktext+%#lx)\n",
               cand_addr, cand_addr - readback[2]);
        printf("  mode:        %s\n", mode == 0 ? "pop_ret" : "pivot");
        printf("  status:      %s\n",
               status == 1 ? "COMPLETED" :
               status == 0xAAAA ? "THREAD DIED (bad gadget)" : "unknown");
        printf("  result:      %s\n",
               rcode == 1 ? "returned normally" :
               rcode == 2 ? "PIVOT DETECTED!" :
               rcode == 0xAAAA ? "crashed" : "unknown");

        if (mode == 0 && rcode == 1) {
            static const char* rnames[] = {
                "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "R8 ",
                "R9 ", "R10", "R11", "R12", "R13", "R14", "R15", "RSP"
            };
            #define GPRB_MARKER 0xBEEF0000CAFE4242ULL
            if (marker_id <= 15) {
                printf("\n  >>> FOUND: pop %s; ret <<<\n", rnames[marker_id]);
            } else {
                printf("\n  No register holds the marker — not a simple pop;ret\n");
            }
            printf("\n  Register dump:\n");
            for (int i = 0; i < 16; i++) {
                uint64_t val = readback[6 + i];
                const char* note = (val == GPRB_MARKER) ? " <-- MARKER" : "";
                printf("    %s: %#018lx%s\n", rnames[i], val, note);
            }
        } else if (mode == 1 && rcode == 2) {
            printf("\n  >>> PIVOT GADGET FOUND at %#lx <<<\n", cand_addr);
        }

        printf("\n=== END GADGET PROBE ===\n");
    } else if (magic == 0x41504344) { /* "APCD" - apic_ops dump */
        uint64_t ktext_base = readback[2];
        uint64_t apic_addr = readback[3];
        int num_apic = (int)readback[4];
        int num_sysent = (int)readback[33];

        printf("\n=== APIC_OPS + KTEXT FUNCTION MAP ===\n");
        printf("  kdata_base:  %#lx\n", readback[1]);
        printf("  ktext_base:  %#lx\n", ktext_base);
        printf("  apic_ops @:  %#lx (kdata+0x1656b0)\n", apic_addr);

        printf("\n  --- apic_ops[0..%d] function pointers ---\n", num_apic - 1);
        for (int i = 0; i < num_apic && i < 28; i++) {
            uint64_t ptr = readback[5 + i];
            if (ptr >= ktext_base && ptr < ktext_base + 0xC00000)
                printf("  apic_ops[%2d]: %#lx (ktext+%#lx)\n", i, ptr, ptr - ktext_base);
            else if (ptr == 0)
                printf("  apic_ops[%2d]: (null)\n", i);
            else
                printf("  apic_ops[%2d]: %#lx (NOT in ktext!)\n", i, ptr);
        }

        printf("\n  --- sysent ktext function pointers (%d unique, sorted) ---\n", num_sysent);
        for (int i = 0; i < num_sysent && i < 200; i++) {
            uint64_t ptr = readback[34 + i];
            printf("  sysent_func[%3d]: %#lx (ktext+%#lx)\n", i, ptr, ptr - ktext_base);
        }

        /* Print gaps between consecutive apic_ops functions for epilogue probing */
        printf("\n  --- apic_ops function gaps (epilogue probe targets) ---\n");
        printf("  (probe bytes just BEFORE each entry point for pop;ret gadgets)\n");
        /* Collect and sort non-null apic_ops ptrs */
        uint64_t sorted_apic[28];
        int sa_count = 0;
        for (int i = 0; i < num_apic && i < 28; i++) {
            uint64_t p = readback[5 + i];
            if (p >= ktext_base && p < ktext_base + 0xC00000)
                sorted_apic[sa_count++] = p;
        }
        /* Sort */
        for (int i = 1; i < sa_count; i++) {
            uint64_t key = sorted_apic[i];
            int j = i - 1;
            while (j >= 0 && sorted_apic[j] > key) {
                sorted_apic[j + 1] = sorted_apic[j];
                j--;
            }
            sorted_apic[j + 1] = key;
        }
        for (int i = 0; i < sa_count; i++) {
            uint64_t addr = sorted_apic[i];
            int gap = (i + 1 < sa_count) ? (int)(sorted_apic[i + 1] - addr) : -1;
            printf("  %#lx (ktext+%#06lx)", addr, addr - ktext_base);
            if (gap >= 0)
                printf("  gap=%d bytes → probe %#lx to %#lx\n",
                       gap, addr + 1, sorted_apic[i + 1] - 1);
            else
                printf("  (last)\n");
        }

        printf("\n=== END APIC DUMP ===\n");
    } else if (magic == 0x4B4D4150) { /* "KMAP" - ktext function map */
        uint64_t ktext_base = readback[2];
        uint64_t ktext_end = readback[3];
        int total = (int)readback[5];

        printf("\n=== KTEXT FUNCTION MAP (IDT + KDATA SCAN) ===\n");
        printf("  kdata_base:  %#lx\n", readback[1]);
        printf("  ktext_base:  %#lx\n", ktext_base);
        printf("  ktext_end:   %#lx\n", ktext_end);
        printf("  IDT @:       %#lx\n", readback[4]);
        printf("  total unique ktext pointers: %d\n", total);

        printf("\n  --- All ktext function pointers (sorted) ---\n");
        for (int i = 0; i < total && i < 270; i++) {
            uint64_t ptr = readback[6 + i];
            uint64_t off = ptr - ktext_base;
            /* Show gap from previous */
            int gap = 0;
            if (i > 0) gap = (int)(ptr - readback[6 + i - 1]);
            if (i == 0)
                printf("  [%3d]: %#lx (ktext+%#08lx)\n", i, ptr, off);
            else
                printf("  [%3d]: %#lx (ktext+%#08lx)  gap=%d\n", i, ptr, off, gap);
        }

        /* Show distribution across ktext */
        printf("\n  --- Coverage distribution (256KB buckets) ---\n");
        int buckets[48] = {0};
        for (int i = 0; i < total && i < 270; i++) {
            uint64_t off = readback[6 + i] - ktext_base;
            int b = (int)(off >> 18); /* /256KB */
            if (b >= 0 && b < 48) buckets[b]++;
        }
        for (int b = 0; b < 48; b++) {
            if (buckets[b] > 0)
                printf("  ktext+%#08x..%#08x: %d ptrs\n",
                       b << 18, ((b + 1) << 18) - 1, buckets[b]);
        }

        printf("\n=== END KTEXT MAP ===\n");
    } else if (magic == 0x42505654) { /* "BPVT" - batch pivot scan */
        uint32_t status = (uint32_t)(readback[0] >> 32);
        uint64_t ktext_base = readback[2];
        uint64_t scan_start = readback[3];
        int scan_count = (int)readback[4];
        int last_idx = (int)readback[5];
        uint64_t found_off = readback[6];
        uint64_t found_addr = readback[7];
        int survived = (int)readback[8];
        int tested = (int)readback[9];

        printf("\n=== BATCH PIVOT SCAN RESULTS ===\n");
        printf("  kdata_base:    %#lx\n", readback[1]);
        printf("  ktext_base:    %#lx\n", ktext_base);
        printf("  scan_start:    %#lx (ktext+%#lx)\n",
               scan_start, scan_start - ktext_base);
        printf("  scan_count:    %d\n", scan_count);
        printf("  tested:        %d / %d\n", tested, scan_count);
        printf("  survived:      %d\n", survived);
        printf("  last_tested:   index %d (addr %#lx)\n",
               last_idx, scan_start + last_idx);

        if (status == 0x0002) {
            printf("\n  >>> PIVOT GADGET FOUND! <<<\n");
            printf("  Address: %#lx\n", found_addr);
            printf("  Offset:  ktext+%#lx\n", found_off);
            printf("  kdata offset: -0x%lx\n", ktext_base + 0xC00000 - found_addr);
        } else if (status == 0x0001) {
            printf("\n  Scan complete. No pivot found in this range.\n");
        } else if (status == 0xAAAA) {
            printf("\n  Thread died at index %d (addr %#lx ktext+%#lx)\n",
                   last_idx, scan_start + last_idx,
                   scan_start + last_idx - ktext_base);
            printf("  Resume next scan from: ktext+%#lx\n",
                   scan_start + last_idx + 1 - ktext_base);
        }

        printf("\n=== END BATCH PIVOT SCAN ===\n");
    } else if (magic == 0x53505654) { /* "SPVT" - smart pivot scan */
        uint32_t status = (uint32_t)(readback[0] >> 32);
        uint64_t ktext_base = readback[2];
        uint64_t curthread = readback[4];

        /* Detect v16 thread dump mode: sentinel at readback[5+127+1] won't exist,
         * but we can check if readback[4] looks like a DMAP/kernel thread pointer
         * and readback[3] looks like LSTAR (0xffffffff8xxxxxxx) */
        int is_thread_dump = (readback[3] >> 32) == 0xffffffff &&
                             (curthread >> 32) != 0 && curthread != 0;

        if (is_thread_dump) {
            printf("\n=== THREAD STRUCTURE DUMP ===\n");
            printf("  kdata_base:  %#lx\n", readback[1]);
            printf("  ktext_base:  %#lx\n", ktext_base);
            printf("  LSTAR:       %#lx\n", readback[3]);
            printf("  curthread:   %#lx\n", curthread);

            /* Dump 128 qwords from thread struct */
            printf("\n  --- struct thread @ %#lx (1024 bytes) ---\n", curthread);
            uint64_t kdata = readback[1];
            for (int i = 0; i < 128 && (5 + i) < READBACK_SIZE / 8; i++) {
                uint64_t val = readback[5 + i];
                int off = i * 8;
                const char* note = "";
                /* Annotate likely pointer types */
                if ((val >> 40) == 0xffffff)
                    note = " [kern_heap]";
                else if ((val >> 32) == 0xffffffff)
                    note = " [kdata/ktext]";
                else if ((val >> 44) == 0xfffff || (val >> 40) == 0xffffce ||
                         (val >> 40) == 0xffffcf || (val >> 40) == 0xffffd0)
                    note = " [DMAP?]";
                else if (val == 0)
                    note = " [null]";
                else if (val < 0x1000)
                    note = " [small]";
                printf("  +0x%03x: %#018lx%s\n", off, val, note);
            }

            /* Highlight candidates for td_pcb (kernel heap pointers) */
            printf("\n  --- td_pcb candidates (kernel heap ptrs) ---\n");
            for (int i = 0; i < 128 && (5 + i) < READBACK_SIZE / 8; i++) {
                uint64_t val = readback[5 + i];
                if ((val >> 40) == 0xffffff && val != 0) {
                    printf("  +0x%03x: %#018lx\n", i * 8, val);
                }
            }

            printf("\n=== END THREAD DUMP ===\n");
        } else {
            /* Original SPVT scan results format */
            uint32_t batch_id = (uint32_t)(readback[3] & 0xFFFF);
            uint32_t batch_size = (uint32_t)((readback[3] >> 16) & 0xFFFF);
            uint32_t probe_depth = (uint32_t)(readback[3] >> 32);
            int total_probed = (int)readback[4];
            int total_survived = (int)readback[5];
            int total_skipped = (int)readback[6];
            uint64_t found_addr = readback[7];
            uint64_t found_off = readback[8];

            printf("\n=== SMART PIVOT SCAN RESULTS ===\n");
            printf("  kdata_base:    %#lx\n", readback[1]);
            printf("  ktext_base:    %#lx\n", ktext_base);
            printf("  batch:         %u (size=%u, depth=%u)\n",
                   batch_id, batch_size, probe_depth);
            printf("  total_probed:  %d\n", total_probed);
            printf("  total_survived:%d\n", total_survived);
            printf("  total_skipped: %d (danger zone)\n", total_skipped);

            if (status == 0x0002) {
                printf("\n  >>> PIVOT GADGET FOUND! <<<\n");
                printf("  Address:     %#lx\n", found_addr);
                printf("  ktext offset: %#lx\n", found_off);
                printf("  kdata offset: -0x%lx\n", ktext_base + 0xC00000 - found_addr);
            } else if (status == 0x0001) {
                printf("\n  Batch complete. No pivot found.\n");
            } else if (status == 0xFFFF) {
                printf("\n  Batch %u past end of function list (%d total funcs)\n",
                       batch_id, total_probed);
            } else if (status == 0xAAAA) {
                printf("\n  Thread died during probing (in progress)\n");
            }
        }

        printf("\n=== END SMART PIVOT SCAN ===\n");
    } else if (magic == 0x50535243) { /* "PSRC" - DMAP pivot scan results */
        uint32_t num_hits = (uint32_t)(readback[0] >> 32);
        uint64_t rb_kdata = readback[1];
        uint64_t rb_ktext = readback[2];
        uint64_t rb_dmap  = readback[3];
        uint64_t scanned  = readback[4];
        uint64_t status   = readback[5];

        const char* pattern_names[] = {
            "xchg rsp,rax; ret  (48 94 C3)",
            "push rax; pop rsp; ret (50 5C C3)",
            "mov rsp,rax; ret  (48 89 C4 C3)",
            "xchg rsp,rax; ret  (48 87 E0 C3)",
        };

        printf("\n=== DMAP PIVOT SCAN RESULTS ===\n");
        printf("  kdata_base:     %#lx\n", rb_kdata);
        printf("  ktext_base:     %#lx\n", rb_ktext);
        printf("  dmap_base:      %#lx\n", rb_dmap);
        printf("  bytes_scanned:  %#lx (%lu MB)\n", scanned, scanned / (1024*1024));
        printf("  status:         %s\n",
               status == 1 ? "COMPLETE" :
               status == 0xAAAA ? "IN PROGRESS (thread died)" :
               status == 0xDEAD ? "DMAP INIT FAILED" : "UNKNOWN");
        printf("  hits:           %u\n\n", num_hits);

        if (num_hits > 0) {
            printf("  >>> PIVOT GADGETS FOUND! <<<\n\n");
        }

        for (uint32_t i = 0; i < num_hits && i < 70; i++) {
            int base = 6 + i * 4;
            uint64_t addr     = readback[base + 0];
            uint64_t kt_off   = readback[base + 1];
            uint64_t pat_info = readback[base + 2];
            uint64_t context  = readback[base + 3];
            int pat_id  = (int)(pat_info & 0xFF);
            int pat_len = (int)((pat_info >> 8) & 0xFF);

            printf("  [%2u] addr=%#lx  ktext+%#lx  kdata_off=%+ld\n",
                   i, addr, kt_off, (int64_t)(addr - rb_kdata));
            printf("       pattern=%d (%s)\n",
                   pat_id, pat_id < 4 ? pattern_names[pat_id] : "unknown");
            printf("       len=%d  context(8 bytes before): ", pat_len);
            for (int b = 0; b < 8; b++)
                printf("%02x ", (uint8_t)(context >> (b * 8)));
            printf("\n\n");
        }

        if (num_hits > 0) {
            /* Print usable offsets for the first hit */
            uint64_t best_addr = readback[6];
            int64_t kdata_off = (int64_t)(best_addr - rb_kdata);
            printf("  === USE THIS IN YOUR ROP CHAIN ===\n");
            printf("  kdata_base + (%ld)  =  kdata_base - 0x%lx\n",
                   kdata_off, (uint64_t)(-kdata_off));
            printf("  ktext_base + %#lx\n", readback[7]);
        }

        printf("\n=== END DMAP PIVOT SCAN ===\n");
    } else {
        /* Generic readback - check for test markers */
        uint64_t val0 = readback[0];
        uint64_t val8 = readback[1];

        if ((val0 & 0xFFFFFFFF) == 0xCAFEBABE && (val8 & 0xFFFFFFFF) == 0xDEAD) {
            printf("[debug] *** KERNEL THREAD EXECUTED SUCCESSFULLY! ***\n");
        } else if (val0 == kdata_base_addr) {
            printf("[debug] kthread_args unchanged (kdata_base still at [0])\n");
            printf("[debug] Thread may not have executed or didn't modify args.\n");
        }

        /* Dump raw readback */
        printf("[debug] kthread_args readback:\n");
        for (int i = 0; i < 8; i++) {
            printf("  [%#04x] %#018lx\n", i * 8, readback[i]);
        }
    }
}

int main()
{
    payload_args_t* pargs = payload_get_args();
    kdata_base_addr = pargs->kdata_base_addr;
    fw_version = 0x403; /* TODO: auto-detect firmware version */

    printf("Starting kldload...\n");
    printf("[debug] fw_version=0x%x\n", fw_version);
    printf("[debug] kdata_base=%#lx\n", kdata_base_addr);

    /* Check if kstuff is loaded */
    int kstuff_loaded = (kekcall_check() == 0) ? 1 : 0;
    printf("[debug] kstuff_loaded=%d\n", kstuff_loaded);

    if (!kstuff_loaded) {
        printf("[error] kstuff not loaded! Load kstuff.elf first.\n");
        return 1;
    }

    /* Create TCP server */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("Unable to create socket! Aborting...\n");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("Unable to bind on port %d! Aborting...\n", PORT);
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        printf("Unable to listen! Aborting...\n");
        close(server_fd);
        return 1;
    }

    while (1) {
        printf("Waiting connections on port %d...\n", PORT);

        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            printf("Accept failed!\n");
            continue;
        }

        /* Read incoming kernel module */
        uint8_t* buf = malloc(0x100000); /* 1MB max */
        if (!buf) {
            printf("malloc failed!\n");
            close(client_fd);
            continue;
        }

        size_t total = 0;
        ssize_t n;
        while ((n = read(client_fd, buf + total, 0x100000 - total)) > 0) {
            total += n;
        }
        close(client_fd);

        if (total > 0) {
            printf("Read %zd bytes!, calling callback...\n", total);
            _kldload(buf, total);
        } else {
            printf("No data received.\n");
        }

        free(buf);
    }

    close(server_fd);
    return 0;
}

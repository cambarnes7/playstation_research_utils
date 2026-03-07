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

    uint64_t exec_code = kekcall_malloc(data_size + 256); /* extra 256 for trampoline */
    uint64_t kproc_name = kekcall_malloc(0x100);
    uint64_t kthread_args = kekcall_malloc(0x1000); /* 4KB for args/results */

    printf("[debug] malloc returned exec_code=%#lx\n", exec_code);
    printf("[debug] malloc returned kproc_name=%#lx\n", kproc_name);
    printf("[debug] malloc returned kthread_args=%#lx\n", kthread_args);

    if (!exec_code || !kproc_name || !kthread_args) {
        printf("[error] malloc failed!\n");
        return;
    }

    /* Prepare kthread_args: kdata_base (uint64) + fw_ver (uint32) + exec info */
    struct {
        uint64_t kdata_base;
        uint32_t fw_ver;
        uint32_t data_size;
        uint64_t exec_code;
    } args_buf;
    args_buf.kdata_base = kdata_base_addr;
    args_buf.fw_ver = fw_version;
    args_buf.data_size = (uint32_t)data_size;
    args_buf.exec_code = exec_code;

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

    /* Poll for payload completion instead of fixed delay.
     * Check the status field (first uint32 at offset 4) every 500ms.
     * SRCP payloads set status=0xAAAA while capturing and change to
     * 1 (armed) or 0xFF (error) when done. Other payloads just get
     * a generous timeout. */
    {
        int completed = 0;
        for (int poll = 0; poll < 60; poll++) { /* up to 30s */
            usleep(500000); /* 500ms */
            uint64_t word0 = kekcall_read_kmem(5, kthread_args);
            uint32_t magic_chk = (uint32_t)(word0 & 0xFFFFFFFF);
            uint32_t status_chk = (uint32_t)(word0 >> 32);

            if (magic_chk == 0x53524350) { /* SRCP */
                if (status_chk != 0xAAAA) {
                    printf("[debug] SRCP completed (status=%#x) after %d.%ds\n",
                           status_chk, (poll + 1) / 2, ((poll + 1) % 2) * 5);
                    completed = 1;
                    break;
                }
                if (poll % 4 == 3)
                    printf("[debug] SRCP still capturing... (%d.%ds elapsed)\n",
                           (poll + 1) / 2, ((poll + 1) % 2) * 5);
            } else if (magic_chk != 0) {
                /* Non-SRCP payload wrote its magic — give it 1 more second */
                usleep(1000000);
                printf("[debug] payload completed (magic=%#x) after %d.%ds\n",
                       magic_chk, (poll + 1) / 2 + 1, ((poll + 1) % 2) * 5);
                completed = 1;
                break;
            }
        }
        if (!completed)
            printf("[debug] timeout waiting for payload (30s)\n");
    }

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

        /* Detect v3: sentinel at slot 104 = 0xdeadbeefcafe0003 */
        int is_v3 = (readback[104] == 0xdeadbeefcafe0003ULL);
        /* Detect v2: sentinel at slot 74 = 0xdeadbeefcafe0002 */
        int is_v2 = !is_v3 && (readback[74] == 0xdeadbeefcafe0002ULL);

        static const char* rnames[] = {
            "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "R8 ",
            "R9 ", "R10", "R11", "R12", "R13", "R14", "R15", "RSP", "FLG"
        };

        static const char* slot_names[] = {
            "create", "init", "xapic_mode", "is_x2apic",
            "setup", "dump", "disable", "set_id",
            "ipi_raw", "ipi_vectored", "ipi_wait", "ipi_alloc",
            "ipi_free", "set_lvt_mask", "set_lvt_mode", "set_lvt_polarity",
            "set_lvt_triggermode", "lvt_eoi_clear", "set_tpr", "get_timer_freq",
            "timer_enable_intr", "timer_disable_intr", "timer_set_divisor",
            "timer_initial_count", "timer_current_count", "self_ipi",
            "slot26", "slot27"
        };

        printf("\n=== REGISTER PROBE RESULTS ===\n");
        printf("  status:        %s\n",
               status == 1 ? "CAPTURES" : status == 2 ? "TABLE ONLY" : "NO CAPTURES");
        printf("  kdata_base:    %#lx\n", readback[1]);
        printf("  ktext_base:    %#lx\n", readback[2]);
        printf("  apic_ops @:    %#lx\n", readback[3]);
        printf("  orig xapic:    %#lx\n", readback[4]);

        if (is_v3) {
            uint32_t call_count = ((uint32_t*)&readback[5])[0];
            uint32_t hooked_slot = ((uint32_t*)&readback[5])[1];
            uint64_t slots_tried = readback[34];
            uint64_t slots_hit = readback[35];

            printf("  captures:      %u\n", call_count);
            printf("  hooked_slot:   %u (%s)\n", hooked_slot,
                   hooked_slot < 28 ? slot_names[hooked_slot] : "none");

            /* Show apic_ops table dump (slots 6..33) */
            uint64_t ktext = readback[2];
            printf("\n  --- apic_ops table dump ---\n");
            for (int i = 0; i < 28; i++) {
                uint64_t ptr = readback[6 + i];
                if (ptr == 0) continue;
                int tried = (slots_tried >> i) & 1;
                int hit = (slots_hit >> i) & 1;
                const char* probe_note = "";
                if (hit) probe_note = " [HOOKED - GOT CAPTURES]";
                else if (tried) probe_note = " [tried - no calls]";
                printf("  [%2d] %-22s %#lx (ktext+%#lx)%s\n",
                       i, slot_names[i], ptr, ptr - ktext, probe_note);
            }

            printf("\n  Slots tried: ");
            for (int i = 0; i < 28; i++)
                if ((slots_tried >> i) & 1)
                    printf("%s(%d) ", slot_names[i], i);
            printf("\n  Slots hit:   ");
            if (slots_hit == 0) printf("(none)");
            for (int i = 0; i < 28; i++)
                if ((slots_hit >> i) & 1)
                    printf("%s(%d) ", slot_names[i], i);
            printf("\n");

            /* Register captures (slots 36+) */
            uint64_t apic_addr = readback[3];
            uint64_t kdata = readback[1];

            for (uint32_t c = 0; c < call_count && c < 4; c++) {
                printf("\n  --- Capture %u ---\n", c);
                for (int i = 0; i < 17; i++) {
                    uint64_t val = readback[36 + c * 17 + i];
                    const char* note = "";
                    if (i == 16) {
                        printf("    %s: %#018lx\n", rnames[i], val);
                        continue;
                    }
                    if (val == apic_addr)
                        note = " <-- apic_ops table! PIVOT CANDIDATE";
                    else if (val >= apic_addr && val <= apic_addr + 0xE0)
                        note = " <-- inside apic_ops! PIVOT CANDIDATE";
                    else if (val >= ktext && val < kdata)
                        note = " [ktext]";
                    else if (val >= kdata && val < kdata + 0x10000000)
                        note = " [kdata]";
                    else if ((val >> 40) == 0xffffff)
                        note = " [kern_heap]";
                    else if ((val >> 40) == 0xffffd7 || (val >> 40) == 0xffffe0 ||
                             (val >> 40) == 0xffff80 || (val >> 40) == 0xffffee)
                        note = " [dmap/kernel]";
                    printf("    %s: %#018lx%s\n", rnames[i], val, note);
                }
            }

            /* Stability analysis */
            if (call_count >= 2) {
                printf("\n  --- Stability Analysis ---\n");
                for (int i = 0; i < 16; i++) {
                    int stable = 1;
                    uint64_t first = readback[36 + i];
                    for (uint32_t c = 1; c < call_count && c < 4; c++) {
                        if (readback[36 + c * 17 + i] != first) {
                            stable = 0;
                            break;
                        }
                    }
                    if (stable && first != 0)
                        printf("    %s: STABLE at %#018lx%s\n", rnames[i], first,
                               (first == apic_addr || (first >= apic_addr && first <= apic_addr + 0xE0))
                               ? " *** PIVOT TARGET ***" : "");
                }
            }
        } else if (is_v2) {
            uint32_t call_count = ((uint32_t*)&readback[5])[0];
            printf("  captures:      %u (natural kernel calls)\n", call_count);

            uint64_t apic_addr = readback[3];
            uint64_t ktext = readback[2];
            uint64_t kdata = readback[1];

            for (uint32_t c = 0; c < call_count && c < 4; c++) {
                printf("\n  --- Capture %u ---\n", c);
                for (int i = 0; i < 17; i++) {
                    uint64_t val = readback[6 + c * 17 + i];
                    const char* note = "";
                    if (i == 16) {
                        printf("    %s: %#018lx\n", rnames[i], val);
                        continue;
                    }
                    if (val == apic_addr)
                        note = " <-- apic_ops table! PIVOT CANDIDATE";
                    else if (val >= ktext && val < kdata)
                        note = " [ktext]";
                    else if (val >= kdata && val < kdata + 0x10000000)
                        note = " [kdata]";
                    else if ((val >> 40) == 0xffffff)
                        note = " [kern_heap]";
                    printf("    %s: %#018lx%s\n", rnames[i], val, note);
                }
            }

            if (call_count >= 2) {
                printf("\n  --- Stability Analysis ---\n");
                for (int i = 0; i < 16; i++) {
                    int stable = 1;
                    uint64_t first = readback[6 + i];
                    for (uint32_t c = 1; c < call_count && c < 4; c++) {
                        if (readback[6 + c * 17 + i] != first) {
                            stable = 0;
                            break;
                        }
                    }
                    if (stable && first != 0)
                        printf("    %s: STABLE at %#018lx%s\n", rnames[i], first,
                               first == readback[3] ? " *** PIVOT TARGET ***" : "");
                }
            }
        } else if (status == 1) {
            /* v1 format */
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
        uint64_t rb_dmap  = readback[3];
        uint64_t rb_cr3   = readback[4];

        printf("\n=== GADGET READER RESULTS ===\n");
        printf("  kdata_base: %#lx\n", rb_kdata);
        printf("  ktext_base: %#lx\n", rb_ktext);
        printf("  dmap_base:  %#lx\n", rb_dmap);
        printf("  cr3:        %#lx\n", rb_cr3);
        printf("  regions:    %u\n\n", num_regions);

        /* Each region starts at byte offset 40 (5 uint64s header)
         * Region layout: addr(8) + offset(8) + bytes(256) = 272 bytes */
        uint8_t* raw = (uint8_t*)readback;
        /* Cap num_regions to 8 in case field wasn't written */
        if (num_regions > 8) num_regions = 8;
        for (uint32_t r = 0; r < num_regions; r++) {
            uint8_t* rp = raw + 40 + r * 272;
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
            else if (roff == -0x5A16AB)  label = "sw_return (pcb_rip target)";

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

        /* Detect v20 gadget scanner: check for sentinel after gadget entries */
        int is_gadget_scan = 0;
        {
            int nfound = (int)readback[4];
            if (nfound >= 0 && nfound <= 128) {
                int sentinel_slot = 5 + nfound * 2;
                if (sentinel_slot < 278 && readback[sentinel_slot] == 0xdeadbeefcafe0020ULL)
                    is_gadget_scan = 1;
            }
        }

        /* Detect v19 multi-offset onfault: sentinel 0xdeadbeefcafe0019 at slot 9 */
        int is_onfault_v19 = !is_gadget_scan &&
                             (readback[9] == 0xdeadbeefcafe0019ULL);

        /* Detect v18 onfault test: sentinel 0xdeadbeefcafe0018 at slot 8 */
        int is_onfault_test = !is_onfault_v19 && !is_gadget_scan &&
                              (readback[8] == 0xdeadbeefcafe0018ULL);

        /* Detect v17 pcb dump: sentinel 0xdeadbeefcafe0017 at slot 37 */
        int is_pcb_dump = !is_onfault_test && !is_onfault_v19 &&
                          (readback[5 + 32] == 0xdeadbeefcafe0017ULL);

        /* Detect v16 thread dump: readback[3] is LSTAR (0xffffffff8xxx) */
        int is_thread_dump = !is_pcb_dump && !is_onfault_test && !is_onfault_v19 && !is_gadget_scan &&
                             (readback[3] >> 32) == 0xffffffff &&
                             (readback[4] >> 32) != 0 && readback[4] != 0;

        if (is_onfault_v19) {
            printf("\n=== PCB_ONFAULT MULTI-OFFSET TEST (v19) ===\n");
            printf("  kdata_base:       %#lx\n", readback[1]);
            printf("  ktext_base:       %#lx\n", ktext_base);
            printf("  curthread:        %#lx\n", readback[3]);
            printf("  td_pcb:           %#lx\n", readback[4]);
            printf("  recovery_label:   %#lx\n", readback[6]);
            printf("  fault_address:    %#lx\n", readback[8]);

            if (status == 0x0002) {
                printf("\n  >>> pcb_onfault WORKS! <<<\n");
                if (readback[7] == 0xFFFF)
                    printf("  Multi-offset hit (need single-offset test to determine exact offset)\n");
                else
                    printf("  Winning offset: pcb+0x%lx\n", readback[7]);
                printf("  Fault recovery confirmed with non-NULL address!\n");
            } else if (status == 0x0001) {
                printf("\n  pcb_onfault did NOT trigger\n");
                printf("  None of the tested offsets worked\n");
            } else if (status == 0xAAAA) {
                printf("\n  Module crashed or still running\n");
            }

            printf("\n=== END ONFAULT v19 TEST ===\n");
        } else if (is_onfault_test) {
            printf("\n=== PCB_ONFAULT VALIDATION TEST ===\n");
            printf("  kdata_base:       %#lx\n", readback[1]);
            printf("  ktext_base:       %#lx\n", ktext_base);
            printf("  curthread:        %#lx\n", readback[3]);
            printf("  td_pcb:           %#lx\n", readback[4]);
            printf("  recovery_label:   %#lx\n", readback[6]);
            printf("  onfault_offset:   +0x%lx\n", readback[7]);

            if (status == 0x0002) {
                printf("\n  >>> pcb_onfault WORKS! <<<\n");
                printf("  Fault recovery confirmed at pcb+0x%lx\n", readback[7]);
                printf("  We can now use pcb_onfault for safe gadget probing!\n");
            } else if (status == 0x0001) {
                printf("\n  pcb_onfault did NOT trigger (fault not caught)\n");
                printf("  Offset +0x%lx may be wrong\n", readback[7]);
            } else if (status == 0xAAAA) {
                printf("\n  Module still running or crashed\n");
            }

            printf("\n=== END ONFAULT TEST ===\n");
        } else if (is_pcb_dump) {
            uint64_t curthread = readback[3];
            uint64_t pcb_ptr = readback[4];

            printf("\n=== PCB STRUCTURE DUMP ===\n");
            printf("  kdata_base:  %#lx\n", readback[1]);
            printf("  ktext_base:  %#lx\n", ktext_base);
            printf("  curthread:   %#lx\n", curthread);
            printf("  td_pcb:      %#lx (curthread+0x3f8)\n", pcb_ptr);

            if (pcb_ptr == 0) {
                printf("\n  td_pcb is NULL!\n");
            } else {
                printf("\n  --- struct pcb @ %#lx (256 bytes) ---\n", pcb_ptr);
                for (int i = 0; i < 32; i++) {
                    uint64_t val = readback[5 + i];
                    int off = i * 8;
                    const char* note = "";
                    /* Annotate value types */
                    if (val == 0)
                        note = " [null]";
                    else if (val < 0x1000)
                        note = " [small]";
                    else if ((val >> 40) == 0xffffff)
                        note = " [kern_heap]";
                    else if ((val >> 32) == 0xffffffff)
                        note = " [kdata/ktext]";
                    else if ((val & 0xFFF) == 0 && val < 0x800000000ULL)
                        note = " [phys_addr? page-aligned]";
                    else if (val > 0xffff000000000000ULL)
                        note = " [kernel_ptr]";
                    else if (val < 0x100)
                        note = " [byte]";
                    printf("  pcb+0x%03x: %#018lx%s\n", off, val, note);
                }

                /* Highlight cr3 candidates: page-aligned physical addresses */
                printf("\n  --- cr3 candidates (page-aligned, < 4GB phys) ---\n");
                for (int i = 0; i < 32; i++) {
                    uint64_t val = readback[5 + i];
                    if (val != 0 && (val & 0xFFF) == 0 && val < 0x800000000ULL) {
                        printf("  pcb+0x%03x: %#018lx\n", i * 8, val);
                    }
                }

                /* Highlight kernel stack pointers */
                printf("\n  --- rsp/rbp candidates (kernel ptrs) ---\n");
                for (int i = 0; i < 32; i++) {
                    uint64_t val = readback[5 + i];
                    if (val > 0xffff000000000000ULL && val != 0xffffffffffffffffULL) {
                        printf("  pcb+0x%03x: %#018lx\n", i * 8, val);
                    }
                }
            }

            printf("\n=== END PCB DUMP ===\n");
        } else if (is_thread_dump) {
            uint64_t curthread = readback[4];

            printf("\n=== THREAD STRUCTURE DUMP ===\n");
            printf("  kdata_base:  %#lx\n", readback[1]);
            printf("  ktext_base:  %#lx\n", ktext_base);
            printf("  LSTAR:       %#lx\n", readback[3]);
            printf("  curthread:   %#lx\n", curthread);

            /* Dump 128 qwords from thread struct */
            printf("\n  --- struct thread @ %#lx (1024 bytes) ---\n", curthread);
            for (int i = 0; i < 128 && (5 + i) < READBACK_SIZE / 8; i++) {
                uint64_t val = readback[5 + i];
                int off = i * 8;
                const char* note = "";
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
    } else if (magic == 0x53524350) { /* "SRCP" - suspend register capture / persistence test */
        uint32_t status = (uint32_t)(readback[0] >> 32);
        uint64_t ktext = readback[2];
        uint64_t kdata = readback[1];
        uint64_t apic_addr = readback[3];

        static const char* slot_names[] = {
            "create", "init", "xapic_mode", "is_x2apic",
            "setup", "dump", "disable", "set_id",
            "ipi_raw", "ipi_vectored", "ipi_wait", "ipi_alloc",
            "ipi_free", "set_lvt_mask", "set_lvt_mode", "set_lvt_polarity",
            "set_lvt_triggermode", "lvt_eoi_clear", "set_tpr", "get_timer_freq",
            "timer_enable_intr", "timer_disable_intr", "timer_set_divisor",
            "timer_initial_count", "timer_current_count", "self_ipi",
            "slot26", "slot27"
        };

        /* Detect v5: version_tag at [35] == 0x0005 */
        int is_v5 = (readback[35] == 0x0005);
        /* Detect v4: slot 2 unchanged and marker_base is ktext addr */
        int is_v4 = !is_v5 && (readback[122] == readback[123]) &&
                     (readback[34] >= ktext && readback[34] < kdata) &&
                     (readback[36] != 0);

        const char* ver_str = is_v5 ? "PERSISTENCE TEST (v5)" :
                              is_v4 ? "PERSISTENCE TEST (v4)" : "REGISTER CAPTURE";
        printf("\n=== SUSPEND %s ===\n", ver_str);
        printf("  status:        %s\n",
               status == 1 ? "ARMED FOR SUSPEND" :
               status == 0xAAAA ? "IN PROGRESS..." :
               status == 0xFF ? "ERROR" : "unknown");
        printf("  kdata_base:    %#lx\n", kdata);
        printf("  ktext_base:    %#lx\n", ktext);
        printf("  apic_ops @:    %#lx\n", apic_addr);
        printf("  orig xapic:    %#lx (ktext+%#lx)\n", readback[4], readback[4] - ktext);

        /* Show apic_ops table dump (pre-modification snapshot) */
        printf("\n  --- apic_ops table (pre-modification snapshot) ---\n");
        for (int i = 0; i < 28; i++) {
            uint64_t ptr = readback[6 + i];
            if (ptr == 0) continue;
            printf("  [%2d] %-22s %#lx (ktext+%#lx)\n",
                   i, slot_names[i], ptr, ptr - ktext);
        }

        if (is_v5) {
            /* v5: pure kdata persistence test — NO apic_ops modifications */
            uint64_t marker_region = readback[5];
            int marker_count = (int)readback[34];
            if (marker_count > 16) marker_count = 16;

            printf("\n  --- v5 Pure kdata Persistence Test ---\n");
            printf("  marker_region: %#lx (kdata+%#lx)\n",
                   marker_region, marker_region - kdata);
            printf("  marker_count:  %d\n", marker_count);
            printf("  apic_ops[2]:   %#lx (UNTOUCHED) %s\n",
                   readback[122],
                   readback[122] == readback[4] ? "[OK - original]" : "[MODIFIED!]");

            printf("\n  --- Marker Write Verification ---\n");
            int all_ok = 1;
            for (int i = 0; i < marker_count; i++) {
                uint64_t orig = readback[36 + i];
                uint64_t wrote = readback[52 + i];
                uint64_t rb = readback[68 + i];
                int ok = (rb == wrote);
                if (!ok) all_ok = 0;
                printf("  [%2d] orig=%#018lx wrote=%#018lx rb=%#018lx %s\n",
                       i, orig, wrote, rb, ok ? "[OK]" : "[FAILED]");
            }

            printf("\n  sentinel: %#lx %s\n", readback[104],
                   readback[104] == 0xdeadbeefcafe0005ULL ? "[OK]" : "[MISSING]");
            printf("  second sentinel: %#lx %s\n", readback[121],
                   readback[121] == 0xfeedface00000005ULL ? "[OK]" : "[MISSING]");

            if (status == 1 && all_ok) {
                printf("\n  >>> PERSISTENCE TEST ARMED — apic_ops UNTOUCHED <<<\n");
                printf("  >>> %d markers written to kdata @ %#lx <<<\n",
                       marker_count, marker_region);
                printf("  >>> Enter rest mode. After resume: <<<\n");
                printf("  >>>   1. Re-run etaHEN exploit <<<\n");
                printf("  >>>   2. Send kldload.elf + readback payload <<<\n");
                printf("  >>>   3. Check if markers survived at kdata+%#lx <<<\n",
                       marker_region - kdata);
            }
        } else if (is_v4) {
            /* v4: DEPRECATED — slots 0,1,7 cause panic on resume */
            printf("\n  [v4 format — known to cause panic, use v5 instead]\n");
        } else {
            /* Legacy v1-v3 format */
            uint32_t call_count = ((uint32_t*)&readback[5])[0];
            uint32_t hooked_slot = ((uint32_t*)&readback[5])[1];

            printf("  captures:      %u (hooked slot %u = %s)\n", call_count,
                   hooked_slot, hooked_slot < 28 ? slot_names[hooked_slot] : "?");
            printf("  armed_target:  %#lx", readback[34]);
            if (readback[34] >= ktext && readback[34] < kdata)
                printf(" (ktext+%#lx)", readback[34] - ktext);
            else if ((readback[34] >> 40) == 0xffffff)
                printf(" (heap - capture_stub trampoline)");
            printf("\n");

            printf("\n  --- Suspend Arming ---\n");
            printf("  apic_ops[2] armed: %#lx\n", readback[122]);
            printf("  apic_ops[2] readback: %#lx %s\n", readback[123],
                   readback[122] == readback[123] ? "[WRITE OK]" : "[WRITE FAILED]");
            printf("  sentinel: %#lx %s\n", readback[104],
                   readback[104] == 0xdeadbeefcafe0005ULL ? "[OK]" : "[MISSING]");
        }

        printf("\n=== END SUSPEND %s ===\n", ver_str);
    } else if (magic == 0x4B545354) { /* "KTST" - ktext redirect test */
        uint32_t mode = (uint32_t)(readback[0] >> 32);
        uint64_t ktext = readback[2];
        uint64_t original = readback[4];
        uint64_t new_target = readback[5];
        uint64_t rb = readback[6];
        uint64_t nop_ret = readback[7];
        uint64_t is_x2apic = readback[8];
        uint32_t status = ((uint32_t*)&readback[9])[0];

        static const char* mode_names[] = {
            "nop_ret (ktext 'ret')",
            "is_x2apic (returns 0)",
            "original xapic_mode (control)",
            "RESTORE original"
        };

        printf("\n=== KTEXT REDIRECT TEST ===\n");
        printf("  mode:          %u (%s)\n", mode,
               mode < 4 ? mode_names[mode] : "unknown");
        printf("  kdata_base:    %#lx\n", readback[1]);
        printf("  ktext_base:    %#lx\n", ktext);
        printf("  apic_ops @:    %#lx\n", readback[3]);
        printf("  original:      %#lx (ktext+%#lx)\n", original, original - ktext);
        printf("  new_target:    %#lx (ktext+%#lx)\n", new_target, new_target - ktext);
        printf("  readback:      %#lx %s\n", rb,
               rb == new_target ? "[WRITE OK]" : "[WRITE FAILED!]");
        printf("  nop_ret:       %#lx (ktext+%#lx)\n", nop_ret, nop_ret - ktext);
        printf("  is_x2apic:     %#lx (ktext+%#lx)\n", is_x2apic, is_x2apic - ktext);
        printf("  status:        %s\n",
               status == 1 ? "ARMED (apic_ops[2] overwritten!)" :
               status == 2 ? "RESTORED (original value)" :
               status == 0xFF ? "ERROR" : "unknown");

        if (status == 1) {
            printf("\n  >>> apic_ops[2] is now pointing to ktext+%#lx <<<\n",
                   new_target - ktext);
            printf("  >>> Enter rest mode to test if ktext survives suspend! <<<\n");
            printf("  >>> If no panic on resume: ktext ROP approach CONFIRMED <<<\n");
            printf("\n  To restore: send payload with fw_ver=3\n");
        } else if (status == 2) {
            printf("\n  apic_ops[2] restored to original xapic_mode\n");
        }

        printf("\n=== END KTEXT REDIRECT TEST ===\n");
    } else if (magic == 0x50435055) { /* "PCPU" - pcpu recon results */
        uint32_t status = (uint32_t)(readback[0] >> 32);
        uint64_t kdata = readback[1];
        uint64_t ktext = readback[2];
        uint64_t pcpu0_addr = readback[3];

        printf("\n=== PCPU RECON RESULTS ===\n");
        printf("  status:          %s\n", status == 1 ? "PASS" : "FAIL");
        printf("  kdata_base:      %#lx\n", kdata);
        printf("  ktext_base:      %#lx\n", ktext);
        printf("  pcpu_array[0]:   %#lx (kdata+%#lx)\n", pcpu0_addr, pcpu0_addr - kdata);

        printf("\n  --- pcpu[0] fields ---\n");
        printf("  pc_curthread:    %#lx\n", readback[4]);
        printf("  pc_idlethread:   %#lx\n", readback[5]);
        printf("  pc_fpcurthread:  %#lx\n", readback[6]);
        printf("  pc_curpcb:       %#lx\n", readback[7]);

        printf("\n  --- curthread info ---\n");
        printf("  td_kstack:       %#lx\n", readback[8]);
        printf("  td_kstack_pages: %lu\n", readback[9]);
        printf("  td_pcb:          %#lx\n", readback[10]);
        printf("  td_proc:         %#lx\n", readback[11]);
        /* thread name: readback[12..15] = 32 bytes of td_name */
        {
            char name[33] = {0};
            __builtin_memcpy(name, &readback[12], 32);
            printf("  td_name:         \"%s\"\n", name);
        }

        printf("\n  --- idlethread info ---\n");
        printf("  td_kstack:       %#lx\n", readback[16]);
        printf("  td_kstack_pages: %lu\n", readback[17]);
        printf("  td_pcb:          %#lx\n", readback[18]);
        printf("  td_proc:         %#lx\n", readback[19]);
        {
            char name[33] = {0};
            __builtin_memcpy(name, &readback[20], 32);
            printf("  td_name:         \"%s\"\n", name);
        }

        printf("\n  --- curthread PCB (saved context) ---\n");
        printf("  pcb_rsp:         %#lx\n", readback[24]);
        printf("  pcb_rbp:         %#lx\n", readback[25]);
        printf("  pcb_rip:         %#lx\n", readback[26]);
        printf("  pcb_rbx:         %#lx\n", readback[27]);
        printf("  pcb_r12:         %#lx\n", readback[28]);
        printf("  pcb_flags:       %#lx\n", readback[29]);

        printf("\n  --- idlethread PCB ---\n");
        printf("  pcb_rsp:         %#lx\n", readback[30]);
        printf("  pcb_rbp:         %#lx\n", readback[31]);
        printf("  pcb_rip:         %#lx\n", readback[32]);
        printf("  pcb_rbx:         %#lx\n", readback[33]);
        printf("  pcb_flags:       %#lx\n", readback[34]);

        printf("\n  --- Debug registers ---\n");
        printf("  DR0:             %#lx\n", readback[35]);
        printf("  DR1:             %#lx\n", readback[36]);
        printf("  DR2:             %#lx\n", readback[37]);
        printf("  DR3:             %#lx\n", readback[38]);
        printf("  DR6:             %#lx\n", readback[39]);
        printf("  DR7:             %#lx\n", readback[40]);

        printf("\n  --- Live registers ---\n");
        printf("  RSP (current):   %#lx\n", readback[41]);
        printf("  RBP (current):   %#lx\n", readback[42]);

        /* Extra pcpu fields */
        printf("\n  --- Extra pcpu fields ---\n");
        printf("  pc_rsp0:         %#lx\n", readback[76]);
        printf("  pc_cpuid:        %lu\n", readback[77]);
        printf("  pc_curpmap:      %#lx\n", readback[78]);
        printf("  pc_scratch_rsp:  %#lx\n", readback[79]);

        /* Stack dump around idle pcb_rsp */
        uint64_t idle_pcb_rsp_ref = readback[113];
        uint64_t idle_pcb_rbp_ref = readback[114];
        printf("\n  --- Stack dump around idle pcb_rsp ---\n");
        printf("  idle pcb_rsp:    %#lx\n", idle_pcb_rsp_ref);
        printf("  idle pcb_rbp:    %#lx\n", idle_pcb_rbp_ref);
        if (idle_pcb_rsp_ref >= 0xFFFF800000000000ULL) {
            uint64_t dump_start = idle_pcb_rsp_ref - 128;
            for (int i = 0; i < 32; i++) {
                uint64_t addr = dump_start + (i * 8);
                uint64_t val = readback[43 + i];
                const char* note = "";
                if (addr == idle_pcb_rsp_ref)
                    note = " <-- pcb_rsp";
                else if (addr == idle_pcb_rbp_ref)
                    note = " <-- pcb_rbp";
                else if (val >= ktext && val < kdata)
                    note = " [ktext]";
                else if (val >= kdata && val < kdata + 0x10000000)
                    note = " [kdata]";
                else if ((val >> 40) == 0xffffff)
                    note = " [kern_heap]";
                printf("  [%#lx] %#018lx%s\n", addr, val, note);
            }
        } else {
            printf("  (no valid pcb_rsp, stack dump skipped)\n");
        }

        /* Thread struct offset scanner results */
        printf("\n  --- Thread struct offset scan (idle thread) ---\n");
        uint64_t hit_count = readback[80];
        printf("  hits found:      %lu (kernel-addr values at offsets 0x200..0x3F0)\n", hit_count);
        for (uint64_t h = 0; h < hit_count && h < 16; h++) {
            uint64_t off = readback[81 + h * 2];
            uint64_t val = readback[81 + h * 2 + 1];
            const char* note = "";
            /* Check if page-aligned (potential kstack base) */
            if ((val & 0xFFF) == 0)
                note = " [page-aligned, possible td_kstack]";
            else if (val >= idle_pcb_rsp_ref - 0x10000 && val <= idle_pcb_rsp_ref + 0x10000)
                note = " [near pcb_rsp]";
            printf("  thread+%#lx:  %#lx%s\n", off, val, note);
        }

        printf("\n  sentinel[75]:  %#lx [%s]\n", readback[75],
               readback[75] == 0xdeadbeefcafe0022ULL ? "OK" : "MISSING");
        printf("  sentinel[120]: %#lx [%s]\n", readback[120],
               readback[120] == 0xdeadbeefcafe0033ULL ? "OK" : "MISSING");

        printf("\n=== END PCPU RECON ===\n");
    } else if (magic == 0x50434244) { /* "PCBD" - PCB dump v17 */
        uint32_t status = (uint32_t)(readback[0] >> 32);
        uint64_t kdata = readback[1];
        uint64_t ktext = readback[2];
        uint64_t curthread_addr = readback[3];
        uint64_t td_pcb_addr = readback[4];

        printf("\n=== PCB DUMP v17 ===\n");
        printf("  status:        %s\n", status == 1 ? "PASS" : "FAIL");
        printf("  kdata_base:    %#lx\n", kdata);
        printf("  ktext_base:    %#lx\n", ktext);
        printf("  curthread:     %#lx\n", curthread_addr);
        printf("  td_pcb:        %#lx\n", td_pcb_addr);

        /* Known PCB field names from FreeBSD (offsets may differ on PS5) */
        static const char* pcb_names[] = {
            "pcb_r15",       /* 0x00 */
            "pcb_r14",       /* 0x08 */
            "pcb_r13",       /* 0x10 */
            "pcb_r12",       /* 0x18 */
            "pcb_rbp",       /* 0x20 */
            "pcb_rsp",       /* 0x28 */
            "pcb_rbx",       /* 0x30 */
            "pcb_rip",       /* 0x38 */
            "pcb_fsbase",    /* 0x40 */
            "pcb_gsbase",    /* 0x48 */
            "pcb_kgsbase",   /* 0x50 */
            "pcb_cr0",       /* 0x58 */
            "pcb_cr2",       /* 0x60 */
            "pcb_cr3",       /* 0x68 */
            "pcb_cr4",       /* 0x70 */
            "pcb_dr0",       /* 0x78 */
            "pcb_dr1",       /* 0x80 */
            "pcb_dr2",       /* 0x88 */
            "pcb_dr3",       /* 0x90 */
            "pcb_dr6",       /* 0x98 */
            "pcb_dr7",       /* 0xa0 */
        };

        printf("\n  --- curthread PCB raw dump (512 bytes) ---\n");
        printf("  %-6s %-14s %s\n", "Off", "Guess", "Value");
        for (int i = 0; i < 64; i++) {
            uint64_t val = readback[5 + i];
            uint64_t off = i * 8;
            const char* name = (i < 21) ? pcb_names[i] : "";
            const char* note = "";

            if (val >= ktext && val < kdata)
                note = " [ktext]";
            else if (val >= kdata && val < kdata + 0x10000000)
                note = " [kdata]";
            else if ((val >> 40) == 0xffffff)
                note = " [kern_heap]";
            else if ((val >> 40) == 0xffffe0 || (val >> 40) == 0xffffd7)
                note = " [DMAP]";

            if (val != 0 || i < 21)
                printf("  +%#-5lx %-14s %#018lx%s\n", off, name, val, note);
        }

        printf("\n  --- Cross-reference registers ---\n");
        printf("  actual CR3: %#lx\n", readback[69]);
        printf("  actual DR0: %#lx\n", readback[70]);
        printf("  actual DR1: %#lx\n", readback[71]);
        printf("  actual DR2: %#lx\n", readback[72]);
        printf("  actual DR3: %#lx\n", readback[73]);
        printf("  actual DR6: %#lx\n", readback[74]);
        printf("  actual DR7: %#lx\n", readback[75]);

        /* Find pcb_cr3 by matching actual CR3 */
        uint64_t actual_cr3 = readback[69];
        printf("\n  --- pcb_cr3 search (matching actual CR3 %#lx) ---\n", actual_cr3);
        for (int i = 0; i < 64; i++) {
            if (readback[5 + i] == actual_cr3) {
                printf("  MATCH at pcb+%#lx (value=%#lx)\n",
                       (uint64_t)(i * 8), readback[5 + i]);
            }
        }

        /* Find pcb_onfault: should be 0 (no fault handler set) or a ktext addr.
         * In FreeBSD 9: pcb_onfault is after pcb_flags. On PS5 pcb_flags=+0x100,
         * so pcb_onfault is likely somewhere around +0x108..+0x118.
         * Look for zero slots near pcb_flags that could be pcb_onfault. */
        printf("\n  --- pcb_onfault candidates ---\n");
        printf("  (slots that are 0 or ktext near pcb_flags at +0x100)\n");
        /* pcb_flags is at +0x100 = index 32 */
        uint64_t pcb_flags_val = readback[5 + 32]; /* +0x100 */
        printf("  pcb+0x100 (pcb_flags): %#lx\n", pcb_flags_val);
        for (int i = 30; i < 42; i++) {
            uint64_t val = readback[5 + i];
            uint64_t off = i * 8;
            const char* tag = "";
            if (val == 0)
                tag = " <-- candidate (NULL=no handler)";
            else if (val >= ktext && val < kdata)
                tag = " <-- candidate (ktext addr)";
            printf("  pcb+%#lx: %#018lx%s\n", off, val, tag);
        }

        /* Extended dump */
        printf("\n  --- Extended PCB dump (pcb+0x200..0x2f8) ---\n");
        for (int i = 0; i < 32; i++) {
            uint64_t val = readback[76 + i];
            if (val != 0) {
                uint64_t off = 0x200 + i * 8;
                const char* note = "";
                if ((val >> 40) == 0xffffff)
                    note = " [kern_heap]";
                printf("  pcb+%#lx: %#018lx%s\n", off, val, note);
            }
        }

        printf("\n  sentinel[108]: %#lx [%s]\n", readback[108],
               readback[108] == 0xdeadbeefcafe0017ULL ? "OK" : "MISSING");

        /* Idle thread PCB for comparison */
        uint64_t idle_addr = readback[109];
        uint64_t idle_pcb = readback[110];
        printf("\n  --- idle thread PCB (for comparison) ---\n");
        printf("  idle thread:   %#lx\n", idle_addr);
        printf("  idle td_pcb:   %#lx\n", idle_pcb);

        if (idle_pcb) {
            /* Show side-by-side differences in the key region */
            printf("\n  %-6s %-20s %-20s %s\n", "Off", "curthread PCB", "idle PCB", "Match?");
            for (int i = 0; i < 64; i++) {
                uint64_t cur_val = readback[5 + i];
                uint64_t idle_val = readback[111 + i];
                if (cur_val != 0 || idle_val != 0) {
                    printf("  +%#-5lx %#-20lx %#-20lx %s\n",
                           (uint64_t)(i * 8), cur_val, idle_val,
                           cur_val == idle_val ? "==" : "");
                }
            }
        }

        printf("\n  sentinel[175]: %#lx [%s]\n", readback[175],
               readback[175] == 0xdeadbeefcafe0018ULL ? "OK" : "MISSING");

        printf("\n=== END PCB DUMP ===\n");
    } else if (magic == 0x4f4e4654) { /* "ONFT" - pcb_onfault test */
        uint32_t status = (uint32_t)(readback[0] >> 32);

        printf("\n=== PCB_ONFAULT TEST ===\n");
        printf("  status:          %s\n",
               status == 1 ? "PASS (onfault works!)" :
               status == 2 ? "NO FAULT (unexpected)" :
               status == 0xAAAA ? "THREAD DIED (wrong offset)" :
               status == 0xFD ? "BAD OFFSET (out of range)" :
               status == 0xFF ? "ERROR (no PCB)" : "UNKNOWN");
        printf("  kdata_base:      %#lx\n", readback[1]);
        printf("  ktext_base:      %#lx\n", readback[2]);
        printf("  curthread:       %#lx\n", readback[3]);
        printf("  td_pcb:          %#lx\n", readback[4]);
        printf("  onfault offset:  %#lx\n", readback[5]);
        printf("  prev value:      %#lx\n", readback[9]);
        printf("  recovery addr:   %#lx\n", readback[6]);
        printf("  fault result:    %#lx %s\n", readback[7],
               readback[7] == 0xCAFE0001 ? "(RECOVERED)" : "(no recovery)");
        printf("  read value:      %#lx\n", readback[8]);
        printf("  onfault after:   %#lx %s\n", readback[10],
               readback[10] == 0 ? "(cleared, good)" : "(NOT cleared)");
        printf("  sentinel:        %#lx [%s]\n", readback[11],
               readback[11] == 0xdeadbeefcafe0019ULL ? "OK" : "MISSING");

        if (status == 1) {
            printf("\n  >>> pcb_onfault CONFIRMED at PCB+%#lx <<<\n", readback[5]);
            printf("  >>> Ready for v18 execute-test scanner <<<\n");
        } else if (status == 0xAAAA) {
            printf("\n  Offset +%#lx is NOT pcb_onfault (thread crashed)\n",
                   readback[5]);
            printf("  Set next offset: printf '\\xNN\\x01\\x00\\x00' | nc PS5 9022\n");
        }

        printf("\n=== END PCB_ONFAULT TEST ===\n");
    } else if (magic == 0x534B5052) { /* "SKPR" - suspend stack probe */
        uint32_t status = (uint32_t)(readback[0] >> 32);
        uint64_t kdata = readback[1];
        uint64_t ktext = readback[2];

        printf("\n=== SUSPEND STACK PROBE ===\n");
        printf("  status:          %s\n",
               status == 1 ? "PASS" : status == 0xAAAA ? "IN PROGRESS" :
               status == 0xFF ? "ERROR (bad mode)" :
               status == 0xFE ? "ERROR (invalid pcb_rsp)" : "UNKNOWN");
        printf("  kdata_base:      %#lx\n", kdata);
        printf("  ktext_base:      %#lx\n", ktext);

        if (status == 0xFF) {
            printf("\n  *** MODE ERROR: fw_ver was not 0x403 or 0x2 ***\n");
            printf("  *** Likely bug: fw_ver read after buffer zeroed ***\n");
        } else if (status == 0xFE) {
            printf("\n  *** SAFETY CHECK FAILED: invalid pcb_rsp ***\n");
            printf("  idle_pcb:        %#lx\n", readback[2]);
            printf("  pcb_rsp:         %#lx\n", readback[3]);
            printf("  *** No markers written, no crash risk ***\n");
        } else if (readback[100] == 0xdeadbeefcafe0023ULL) {
            /* Mode 0 (ARM) output */
            printf("\n  --- Mode 0: ARM ---\n");
            printf("  idle_pcb:        %#lx\n", readback[3]);
            printf("  pcb_rsp (center):%#lx\n", readback[4]);
            printf("  idle_pcb_rsp:    %#lx\n", readback[5]);
            printf("  idle_pcb_rip:    %#lx\n", readback[6]);
            printf("  marker_grid:     %#lx .. %#lx\n", readback[7], readback[8]);
            printf("  marker_count:    %lu\n", readback[9]);
            printf("  marker_spacing:  %lu bytes\n", readback[10]);
            printf("  apic_ops @:      %#lx\n", readback[11]);
            printf("  orig xapic:      %#lx\n", readback[12]);
            printf("  new xapic:       %#lx (get_timer_freq)\n", readback[13]);

            printf("\n  DR sentinels written:\n");
            printf("  DR0: %#lx\n", readback[78]);
            printf("  DR1: %#lx\n", readback[79]);
            printf("  DR2: %#lx\n", readback[80]);
            printf("  DR3: %#lx\n", readback[81]);

            printf("  kdata ctrl @:    %#lx = %#lx\n", readback[82], readback[83]);

            printf("\n  >>> ARMED FOR SUSPEND <<<\n");
            printf("  >>> apic_ops[2] -> get_timer_freq <<<\n");
            printf("  >>> %d markers on idle stack, DRs set <<<\n", 32);
            printf("  >>> Enter rest mode, then send readback (fw_ver=2) <<<\n");
        } else if (readback[100] == 0xdeadbeefcafe0024ULL) {
            /* Mode 2 (READBACK) output */
            printf("\n  --- Mode 2: READBACK ---\n");

            int marker_count = (int)readback[35];
            int64_t first_clob = (int64_t)readback[36];
            int64_t last_clob = (int64_t)readback[37];
            uint64_t est_rsp = readback[38];

            printf("  markers:         %d\n", marker_count);
            printf("  first clobbered: %ld\n", first_clob);
            printf("  last clobbered:  %ld\n", last_clob);
            printf("  estimated RSP:   %#lx\n", est_rsp);

            /* Show marker readback */
            printf("\n  --- Marker grid readback ---\n");
            for (int i = 0; i < 32; i++) {
                uint64_t val = readback[3 + i];
                uint64_t expected = 0x4D41524B00000000ULL | (uint64_t)i;
                const char* state = (val == expected) ? "intact" : "CLOBBERED";
                printf("  [%2d] %#018lx  %s\n", i, val, state);
            }

            printf("\n  --- Debug register readback ---\n");
            printf("  DR0: %#lx  %s\n", readback[39],
                   readback[39] == 0x5354414B50524F42ULL ? "[survived]" : "[clobbered]");
            printf("  DR1: %#lx  %s\n", readback[40],
                   readback[40] == 0x4452314452314452ULL ? "[survived]" : "[clobbered]");
            printf("  DR2: %#lx  %s\n", readback[41],
                   readback[41] == 0x4452324452324452ULL ? "[survived]" : "[clobbered]");
            printf("  DR3: %#lx  %s\n", readback[42],
                   readback[42] == 0x4452334452334452ULL ? "[survived]" : "[clobbered]");

            printf("\n  kdata ctrl:      %#lx  %s\n", readback[44],
                   readback[44] == 0x4B44415441435452ULL ? "[survived]" : "[clobbered]");

            printf("  apic_ops[2]:     %#lx (current)\n", readback[46]);
            printf("  apic_ops[2]:     %#lx (restored)\n", readback[47]);
        }

        printf("\n  sentinel: %#lx\n", readback[100]);
        printf("\n=== END SUSPEND STACK PROBE ===\n");
    } else if (magic == 0x5238474D) { /* "R8GM" - R8 gamble results */
        uint32_t status = (uint32_t)(readback[0] >> 32);
        printf("\n=== R8 GAMBLE RESULTS ===\n");
        printf("  status:          %s\n",
               status == 1 ? "ARMED" : status == 0xFE ? "ERROR (target not in ktext)" :
               status == 0xFF ? "ERROR (bad mode)" : "UNKNOWN");
        printf("  kdata_base:      %#lx\n", readback[1]);
        printf("  ktext_base:      %#lx\n", readback[2]);
        printf("  mode:            %lu\n", readback[3]);
        printf("  target:          %#lx\n", readback[4]);
        printf("  orig xapic:      %#lx\n", readback[5]);
        printf("  cpu_switch:      %#lx\n", readback[6]);
        printf("  offset into sw:  %#lx\n", readback[7]);

        printf("\n  --- pcpu[0] ---\n");
        printf("  pcpu0:           %#lx\n", readback[8]);
        printf("  idlethread:      %#lx\n", readback[9]);
        printf("  idle_pcb:        %#lx\n", readback[10]);

        printf("\n  --- idle PCB (current) ---\n");
        static const char* pcb_names_r8[] = {
            "pcb_r15", "pcb_r14", "pcb_r13", "pcb_r12",
            "pcb_rbp", "pcb_rsp", "pcb_rbx", "pcb_rip",
            "pcb_cr3", "pcb_flags"
        };
        for (int i = 0; i < 10; i++)
            printf("  %-12s %#018lx\n", pcb_names_r8[i], readback[11 + i]);

        printf("\n  --- fake PCB at kdata+0x200 ---\n");
        printf("  fake_pcb @:      %#lx\n", readback[21]);
        static const char* fake_names[] = {
            "pcb_r15", "pcb_r14", "pcb_r13", "pcb_r12",
            "pcb_rbp", "pcb_rsp", "pcb_rbx", "pcb_rip"
        };
        for (int i = 0; i < 8; i++)
            printf("  %-12s %#018lx\n", fake_names[i], readback[22 + i]);

        printf("\n  --- apic_ops ---\n");
        printf("  [0]:             %#lx\n", readback[30]);
        printf("  [1]:             %#lx\n", readback[31]);
        printf("  [2] before:      %#lx\n", readback[32]);
        printf("  [3]:             %#lx\n", readback[33]);
        printf("  [2] readback:    %#lx\n", readback[34]);

        printf("\n  --- known ktext ---\n");
        printf("  nop_ret:         %#lx\n", readback[35]);
        printf("  doreti_iret:     %#lx\n", readback[36]);
        printf("  dr2gpr:          %#lx\n", readback[37]);
        printf("  gpr2dr:          %#lx\n", readback[38]);

        if (status == 1)
            printf("\n  >>> ARMED: apic_ops[2] -> %#lx (cpu_switch+%#lx) <<<\n",
                   readback[4], readback[7]);

        printf("\n  sentinel: %#lx\n", readback[50]);
        printf("\n=== END R8 GAMBLE ===\n");

    } else if (magic == 0x50444946) { /* "PDIF" - PCB diff results */
        uint32_t status = (uint32_t)(readback[0] >> 32);
        uint64_t phase = readback[3];

        printf("\n=== PCB DIFF RESULTS ===\n");
        printf("  status:          %s\n",
               status == 1 ? "OK" : status == 0xFD ? "ERROR (no snapshot)" :
               status == 0xFE ? "ERROR (invalid pcb)" :
               status == 0xFF ? "ERROR (bad mode)" : "UNKNOWN");
        printf("  kdata_base:      %#lx\n", readback[1]);
        printf("  ktext_base:      %#lx\n", readback[2]);
        printf("  phase:           %lu\n", phase);

        printf("\n  --- pcpu[0] ---\n");
        printf("  curthread:       %#lx\n", readback[4]);
        printf("  idlethread:      %#lx\n", readback[5]);
        printf("  curpcb:          %#lx\n", readback[6]);
        printf("  idle_pcb:        %#lx\n", readback[8]);

        static const char* pcb_field_names[] = {
            "pcb_r15     +0x00", "pcb_r14     +0x08",
            "pcb_r13     +0x10", "pcb_r12     +0x18",
            "pcb_rbp     +0x20", "pcb_rsp     +0x28",
            "pcb_rbx     +0x30", "pcb_rip     +0x38",
            "pcb_fsbase  +0x40", "pcb_gsbase  +0x48",
            "pcb_kgsbase +0x50", "pcb_cr0     +0x58",
            "pcb_cr2     +0x60", "pcb_cr3     +0x68",
            "pcb_cr4     +0x70", "pcb_dr0     +0x78",
            "pcb_dr1     +0x80", "pcb_dr2     +0x88",
            "pcb_dr3     +0x90", "pcb_dr6     +0x98",
            "pcb_dr7     +0xA0", "pcb_gdt_lo  +0xA8",
            "pcb_gdt_hi  +0xB0", "pcb_idt_lo  +0xB8",
            "pcb_idt_hi  +0xC0", "pcb_ldt_lo  +0xC8",
            "pcb_ldt_hi  +0xD0", "pcb_tr      +0xD8",
            "pcb_pad1    +0xE0", "pcb_pad2    +0xE8",
            "pcb_pad3    +0xF0", "pcb_pad4    +0xF8",
            "pcb_flags   +0x100","pcb_pad5    +0x108",
            "pcb_onfault +0x110","pcb_pad6    +0x118",
            "pcb_gs32sd  +0x120","pcb_pad7    +0x128",
            "pcb_tssp    +0x130","pcb_save    +0x138"
        };

        if (phase == 1) {
            printf("\n  --- Phase 1: PRE-SUSPEND SNAPSHOT ---\n");
            printf("  Snapshotting %d qwords of idle PCB to kdata+0x200\n\n", 40);

            for (int i = 0; i < 40; i++) {
                const char* name = (i < 40) ? pcb_field_names[i] : "???";
                printf("  %-20s %#018lx\n", name, readback[10 + i]);
            }

            printf("\n  --- curthread PCB (first 10 qwords) ---\n");
            for (int i = 0; i < 10; i++) {
                const char* name = (i < 40) ? pcb_field_names[i] : "???";
                printf("  %-20s %#018lx\n", name, readback[50 + i]);
            }

            printf("\n  snapshot @:      %#lx (%lu qwords)\n", readback[60], readback[61]);
            printf("  apic_ops[2]:     %#lx (original, NOT hooked)\n", readback[62]);
            printf("\n  >>> SNAPSHOT SAVED TO KDATA <<<\n");
            printf("  >>> Enter rest mode, resume, re-exploit <<<\n");
            printf("  >>> Then send pcb_diff.bin with fw_ver=0x2 <<<\n");

            printf("\n  sentinel: %#lx\n", readback[70]);

        } else if (phase == 2) {
            printf("\n  --- Phase 2: POST-RESUME DIFF ---\n");

            if (status == 0xFD) {
                printf("  *** No valid snapshot found at kdata+0x200! ***\n");
                printf("  *** Run Phase 1 first, then suspend/resume ***\n");
                printf("  snap_magic:      %#lx\n", readback[133]);
            } else if (status == 1) {
                uint64_t changed = readback[130];
                uint64_t same = readback[131];

                printf("  snap_magic:      %#lx %s\n", readback[133],
                       readback[133] == 0x534E4150444946FFULL ? "[valid]" : "[INVALID]");
                printf("  apic_ops[2]:     %#lx (post-resume)\n", readback[132]);
                printf("\n  Fields changed:  %lu / %lu\n", changed, changed + same);
                printf("\n  %-20s  %-20s %-20s %s\n",
                       "FIELD", "BEFORE", "AFTER", "STATUS");
                printf("  %-20s  %-20s %-20s %s\n",
                       "-----", "------", "-----", "------");

                for (int i = 0; i < 40; i++) {
                    uint64_t before = readback[10 + i * 3 + 0];
                    uint64_t after  = readback[10 + i * 3 + 1];
                    uint64_t flag   = readback[10 + i * 3 + 2];
                    const char* name = (i < 40) ? pcb_field_names[i] : "???";
                    const char* st = flag ? "*** CHANGED ***" : "same";
                    printf("  %-20s  %#018lx %#018lx %s\n",
                           name, before, after, st);
                }

                printf("\n  === SUMMARY ===\n");
                if (changed > 0) {
                    printf("  %lu PCB fields CHANGED across suspend/resume!\n", changed);
                    printf("  cpu_switch likely ran during resume.\n");
                    printf("  Changed fields contain the register state at that point.\n");
                } else {
                    printf("  ALL PCB fields identical before and after suspend.\n");
                    printf("  cpu_switch did NOT save to idle PCB during resume.\n");
                    printf("  Resume path uses a different mechanism.\n");
                }
            }

            printf("\n  sentinel: %#lx\n", readback[140]);
        }

        printf("\n=== END PCB DIFF ===\n");

    } else if (magic == 0x5043424F) { /* "PCBO" - PCB overwrite results */
        uint32_t status = (uint32_t)(readback[0] >> 32);
        uint64_t phase = readback[3];

        printf("\n=== PCB OVERWRITE RESULTS ===\n");
        printf("  status:          %s\n",
               status == 1 ? "OK" : status == 0xFE ? "ERROR (invalid pcb)" :
               status == 0xFF ? "ERROR (bad mode)" : "UNKNOWN");
        printf("  kdata_base:      %#lx\n", readback[1]);
        printf("  ktext_base:      %#lx\n", readback[2]);
        printf("  phase:           %lu%s\n", phase,
               phase == 3 ? " (DRY RUN)" : phase == 1 ? " (ARMED)" : "");

        if (phase == 1 || phase == 3) {
            printf("\n  --- Addresses ---\n");
            printf("  pcpu0:           %#lx\n", readback[4]);
            printf("  idlethread:      %#lx\n", readback[5]);
            printf("  idle_pcb:        %#lx\n", readback[6]);
            printf("  stub (entry):    %#lx\n", readback[7]);
            printf("  orig pcb_rip:    %#lx (sw_return)\n", readback[8]);
            printf("  orig pcb_rsp:    %#lx\n", readback[9]);
            printf("  exec_code:       %#lx\n", readback[10]);
            printf("  hv_probe fn:     %#lx\n", readback[11]);

            printf("\n  --- Idle PCB snapshot ---\n");
            static const char* pnames[] = {
                "pcb_r15", "pcb_r14", "pcb_r13", "pcb_r12",
                "pcb_rbp", "pcb_rsp", "pcb_rbx", "pcb_rip"
            };
            for (int i = 0; i < 8; i++)
                printf("  %-12s %#018lx\n", pnames[i], readback[12 + i]);

            printf("\n  --- pcb_rip overwrite ---\n");
            printf("  BEFORE:          %#lx\n", readback[20]);
            printf("  AFTER:           %#lx\n", readback[21]);
            printf("  TARGET:          %#lx (stub)\n", readback[22]);

            if (phase == 1) {
                if (readback[21] == readback[22])
                    printf("  *** OVERWRITE CONFIRMED ***\n");
                else
                    printf("  *** OVERWRITE FAILED (readback mismatch) ***\n");
            } else {
                printf("  (dry run — no overwrite performed)\n");
            }

            printf("\n  kdata sentinel:  %#lx @ %#lx\n", readback[25], readback[24]);
            printf("  sw_return:       %#lx\n", readback[26]);
            printf("  stub size:       %lu bytes\n", readback[27]);
            printf("  ktext probe @:   %#lx\n", readback[28]);
            printf("  hv_probe fn @:   %#lx\n", readback[29]);

            if (phase == 1) {
                printf("\n  >>> pcb_rip OVERWRITTEN: sw_return -> HV probe stub <<<\n");
                printf("  >>> Enter rest mode NOW <<<\n");
                printf("  >>> On resume: stub calls hv_probe() then jmp sw_return <<<\n");
                printf("  >>> hv_probe tests: CR0.WP clear + ktext write <<<\n");
                printf("  >>> After re-exploit, send pcb_overwrite.bin fw_ver=0x2 <<<\n");
            }

            printf("\n  sentinel: %#lx\n", readback[30]);

        } else if (phase == 2) {
            printf("\n  --- Post-resume state ---\n");
            printf("  pcpu0:           %#lx\n", readback[4]);
            printf("  curthread:       %#lx\n", readback[5]);
            printf("  idlethread:      %#lx\n", readback[6]);
            printf("  idle_pcb:        %#lx\n", readback[7]);

            printf("\n  --- Current idle PCB ---\n");
            static const char* pn2[] = {
                "pcb_r15", "pcb_r14", "pcb_r13", "pcb_r12",
                "pcb_rbp", "pcb_rsp", "pcb_rbx", "pcb_rip"
            };
            for (int i = 0; i < 8; i++)
                printf("  %-12s %#018lx\n", pn2[i], readback[10 + i]);

            printf("\n  --- kdata persistence ---\n");
            uint64_t sent = readback[20];
            printf("  sentinel:        %#lx %s\n", sent,
                   sent == 0x484A4B5F52414E21ULL ? "[HJK_RAN! - TRAMPOLINE EXECUTED!]" :
                   sent == 0 ? "[zero - trampoline did NOT run]" : "[unexpected value]");
            printf("  snap_magic:      %#lx\n", readback[21]);

            printf("\n  --- pcb_rip analysis ---\n");
            uint64_t orig = readback[24];
            uint64_t curr = readback[25];
            uint64_t sw   = readback[26];
            uint64_t verdict = readback[27];

            printf("  original rip:    %#lx (backed up in kdata)\n", orig);
            printf("  current rip:     %#lx\n", curr);
            printf("  sw_return:       %#lx\n", sw);

            if (verdict == 1) {
                printf("\n  *** VERDICT: FULL SUCCESS — trampoline executed ***\n");
            } else if (verdict == 2) {
                printf("\n  *** VERDICT: pcb_rip restored but sentinel missing ***\n");
            } else if (verdict == 3) {
                printf("\n  *** VERDICT: stub addr still in pcb_rip ***\n");
            } else if (verdict == 4) {
                printf("\n  *** VERDICT: pcb_rip is UNEXPECTED value ***\n");
            } else {
                printf("\n  *** VERDICT: UNKNOWN ***\n");
            }

            /* v3: HV probe results */
            uint64_t hv_result = readback[38];
            if (hv_result != 0) {
                printf("\n  --- HV Probe Results (v3) ---\n");
                uint64_t cr0_before = readback[32];
                uint64_t cr4_val    = readback[33];
                uint64_t cr0_after  = readback[34];
                uint64_t probe_addr = readback[35];
                uint64_t kt_orig    = readback[36];
                uint64_t kt_rdback  = readback[37];
                uint64_t efer_val   = readback[39];

                printf("  CR0 (before):    %#lx  WP=%lu\n", cr0_before, (cr0_before >> 16) & 1);
                printf("  CR0 (after WP clear): %#lx  WP=%lu\n", cr0_after, (cr0_after >> 16) & 1);
                printf("  CR4:             %#lx\n", cr4_val);
                printf("  EFER:            %#lx  SVME=%lu\n", efer_val, (efer_val >> 12) & 1);
                printf("  ktext probe @:   %#lx\n", probe_addr);
                printf("  ktext original:  %#018lx\n", kt_orig);
                printf("  ktext readback:  %#018lx\n", kt_rdback);

                if (hv_result == 1) {
                    printf("\n  *** HV PROBE: WP CLEARED + KTEXT WRITABLE ***\n");
                    printf("  *** >>> HYPERVISOR WAS NOT ACTIVE DURING RESUME <<< ***\n");
                    printf("  *** >>> KERNEL TEXT CAN BE PATCHED IN THIS WINDOW <<< ***\n");
                } else if (hv_result == 2) {
                    printf("\n  *** HV PROBE: CR0.WP STUCK — HV is active ***\n");
                    printf("  *** HV intercepted CR0 write during resume ***\n");
                    printf("  *** PCB hijack runs TOO LATE — need earlier execution ***\n");
                    printf("  *** Consider: apic_ops[2] hijack for pre-HV window ***\n");
                } else if (hv_result == 3) {
                    printf("\n  *** HV PROBE: WP cleared but ktext write FAILED ***\n");
                    printf("  *** NPT may still be active despite no CR0 intercept ***\n");
                }
            } else if (sent == 0x484A4B5F52414E21ULL) {
                printf("\n  (HV probe results: all zero — probe may not have written)\n");
            }

            printf("\n  sentinel: %#lx\n", readback[30]);
        }

        printf("\n=== END PCB OVERWRITE ===\n");

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

        if (total == 4) {
            /* 4-byte message = fw_ver override command */
            uint32_t new_fw = *(uint32_t*)buf;
            printf("[debug] fw_ver override: 0x%x -> 0x%x\n", fw_version, new_fw);
            fw_version = new_fw;
        } else if (total > 0) {
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

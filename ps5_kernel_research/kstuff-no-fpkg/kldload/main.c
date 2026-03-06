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
#define READBACK_SIZE 512  /* bytes to read back from kthread_args */

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

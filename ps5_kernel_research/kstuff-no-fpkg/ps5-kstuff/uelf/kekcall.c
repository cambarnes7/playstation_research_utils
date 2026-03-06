#include <errno.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <machine/sysarch.h>
#include <string.h>
#include "kekcall.h"
#include "traps.h"
#include "utils.h"


extern char syscall_after[];
extern char doreti_iret[];
extern char nop_ret[];
extern char copyout[];
extern char copyin[];
extern char malloc[];
extern char M_something[];
extern char kproc_create[];
extern char mov_cr3_rax[];

extern struct sysent sysents[];

#define PS5_PAGE_SIZE 0x4000
#define ROUND_PG(x) (((x) + (PS5_PAGE_SIZE - 1)) & ~(PS5_PAGE_SIZE - 1))


int try_handle_kernel_fix_trap(uint64_t* regs)
{
    return 0;
}


int handle_kekcall(uint64_t* regs, uint64_t* args, uint32_t nr)
{
    if(nr == 1)
    {
        uint64_t stack_frame[12] = {
            (uint64_t)doreti_iret,
            (uint64_t)nop_ret, regs[CS], regs[EFLAGS], regs[RSP], regs[SS],
        };
        read_dbgregs(stack_frame+6);
        if(!get_pcb_dbregs())
        {
            stack_frame[6] = stack_frame[7] = stack_frame[8] = stack_frame[9] = 0;
            stack_frame[10] &= -16;
        }
        push_stack(regs, stack_frame, sizeof(stack_frame));
        kpoke64(regs[RDI]+td_retval, 0);
        regs[RDI] = regs[RSP] + 48;
        regs[RSI] = args[RDI];
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyout;
    }
    else if(nr == 2)
    {
        //
        // Copyin
        //
        uint64_t stack_frame[14] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 1), [12] = regs[RDI]};
        push_stack(regs, stack_frame, sizeof(stack_frame));
        regs[RDI] = args[RDI];
        regs[RSI] = regs[RSP] + 48;
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyin;
    }
    else if(nr == 3)
    {
        return rdmsr(args[RDI], &args[RAX]) ? 0 : EFAULT;
    }
    //nr 4 reserved for wrmsr
    else if(nr == 5)
    {
        uint64_t stack_frame[16] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 2)};
        stack_frame[6] = args[RDI];
        stack_frame[7] = args[RSI];
        stack_frame[14] = regs[RDI];
        push_stack(regs, stack_frame, sizeof(stack_frame));
        regs[RDI] = args[RDX];
        regs[RSI] = regs[RSP] + 64;
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyin;
    }
    else if (nr == 6)
    {
        //
        // malloc(size, M_something, M_WAITOK) - kernel heap allocation
        //
        LOG("Handling malloc kekcall\n");
        uint64_t td = regs[RDI];
        uint64_t stack_frame[14] = {
            (uint64_t)doreti_iret,
            MKTRAP(TRAP_KEKCALL, 6),
            [12] = td,
        };
        push_stack(regs, stack_frame, sizeof(stack_frame));
        kpoke64(td + td_retval, 0);

        regs[RDI] = ROUND_PG(args[RDI]);       // size (page-aligned)
        regs[RSI] = (uint64_t)M_something;      // type
        regs[RDX] = 0x0002;                     // M_WAITOK
        regs[RIP] = (uint64_t)malloc;
    }
    else if (nr == 10)
    {
        //
        // Page table diagnostic / NX clearing
        // args[RDI] = kernel virtual address
        // args[RSI] = mode: 0=read PTE only, 1=clear NX, 2=clear NX + flush TLB
        // Returns: PTE value (mode 0), pages_fixed count (mode 1,2), or 0xdead on error
        //
        LOG("Handling make_exec kekcall\n");
        uint64_t addr = args[RDI];
        uint64_t mode = args[RSI];

        // Walk page tables for this single address
        uint64_t pml = cr3_phys;
        for (int i = 39; i >= 12; i -= 9)
        {
            if (pml >= ((1ull << 39) - (1ull << 12)))
            {
                args[RAX] = 0xdead0001;
                return 0;
            }
            uint64_t entry_phys = pml + ((addr & (0x1ffull << i)) >> (i - 3));
            uint64_t entry = *(uint64_t*)(DMEM + entry_phys);
            if (!(entry & 1))
            {
                args[RAX] = 0xdead0002;
                return 0;
            }
            if ((entry & 128) || i == 12)
            {
                if (mode == 0)
                {
                    // Read-only: return PTE value
                    args[RAX] = entry;
                }
                else if (mode == 1)
                {
                    // Clear NX bit (no TLB flush)
                    *(uint64_t*)(DMEM + entry_phys) = entry & ~(1ull << 63);
                    args[RAX] = entry; // return original PTE
                }
                else
                {
                    // Clear NX + flush TLB
                    *(uint64_t*)(DMEM + entry_phys) = entry & ~(1ull << 63);
                    uint64_t flush_regs[NREGS] = {
                        [RIP] = (uint64_t)mov_cr3_rax, 0x20, 2, 0, 0,
                        [RAX] = cr3_phys,
                    };
                    run_gadget(flush_regs);
                    args[RAX] = entry;
                }
                return 0;
            }
            pml = entry & ((1ull << 52) - (1ull << 12));
        }
        args[RAX] = 0xdead0003;
        return 0;
    }
    else if (nr == 7)
    {
        // kproc_create(func, arg, newpp, flags, pages, fmt)
        // Must set up a return frame so kproc_create can ret properly
        LOG("Handling kproc_create kekcall\n");
        uint64_t td = regs[RDI];
        uint64_t stack_frame[14] = {
            (uint64_t)doreti_iret,
            MKTRAP(TRAP_KEKCALL, 6),
            [12] = td,
        };
        push_stack(regs, stack_frame, sizeof(stack_frame));

        kpoke64(td+td_retval, 0);
        regs[RDI] = args[RDI];      // func = exec_code
        regs[RSI] = args[RSI];      // arg = kthread_args
        regs[RDX] = 0;              // newpp = NULL
        regs[RCX] = 0;              // flags = 0
        regs[R8] = 0;               // pages = 0
        regs[R9] = args[RDX];       // fmt = kproc_name

        regs[RIP] = (uint64_t) kproc_create;
    }
    
    else if (nr == 8)
    {
        //
        // copyin via kernel's own copyin() function
        // Uses push_stack/trap pattern (same as kproc_create nr=7)
        // so copyin runs in full kernel context with proper CR3
        //
        // copyin(const void *uaddr, void *kaddr, size_t len)
        //   RDI = user source address
        //   RSI = kernel destination address
        //   RDX = size
        //   returns 0 on success, EFAULT on failure
        //
        uint64_t td = regs[RDI];
        uint64_t stack_frame[14] = {
            (uint64_t)doreti_iret,
            MKTRAP(TRAP_KEKCALL, 7),
            [12] = td,
        };
        push_stack(regs, stack_frame, sizeof(stack_frame));

        kpoke64(td + td_retval, 0);
        regs[RDI] = args[RDI];      // user_addr (source)
        regs[RSI] = args[RSI];      // kernel_addr (destination)
        regs[RDX] = args[RDX];      // size
        regs[RIP] = (uint64_t)copyin;
    }
    else if (nr == 9)
    {
        // Diagnostic kekcall: return process info for debugging
        // args[RDI] = what to return:
        //   0 = user_cr3
        //   1 = proc ptr
        //   2 = vmspace ptr
        //   3 = cr3_phys (kernel CR3)
        uint64_t td = regs[RDI];
        uint64_t proc = kpeek64(td + td_proc);
        uint64_t vmspace = kpeek64(proc + 0x200);
        uint64_t what = args[RDI];
        if(what == 0)
            args[RAX] = kpeek64(vmspace + 0x2E0 + 0x28); // pmap.pm_cr3
        else if(what == 1)
            args[RAX] = proc;
        else if(what == 2)
            args[RAX] = vmspace;
        else if(what == 3)
            args[RAX] = cr3_phys;
        else if(what == 4)
            args[RAX] = td;
        else
            args[RAX] = 0xdeadbeef;
        return 0;
    }
    else if(nr == 0xffffffff)
    {
        args[RAX] = 0;
        return 0;
    }
    return ENOSYS;
}

void handle_kekcall_trap(uint64_t* regs, uint32_t trap)
{
    if(trap == 1)
    {
        uint64_t stack_frame[14];
        pop_stack(regs, stack_frame, sizeof(stack_frame));
        regs[RIP] = stack_frame[13];
        if((uint32_t)regs[RAX])
            return;
        kpoke64(stack_frame[11]+td_retval, 0);
        set_pcb_dbregs();
        write_dbgregs(stack_frame+5);
    }
    else if(trap == 2)
    {
        uint64_t stack_frame[15];
        pop_stack(regs, stack_frame, sizeof(stack_frame));
        if((uint32_t)regs[RAX])
        {
            pop_stack(regs, &regs[RIP], 8);
            return;
        }
        uint32_t pid = stack_frame[5];
        uint32_t sysc_no = stack_frame[6];
        int64_t proc = kpeek64(stack_frame[13]+td_proc);
        while(proc < -0x100000000)
            proc = kpeek64(proc+8);
        while(proc && (uint32_t)kpeek64(proc+p_pid) != pid)
            proc = kpeek64(proc);
        if(!proc)
        {
            regs[RAX] = ESRCH;
            pop_stack(regs, &regs[RIP], 8);
            return;
        }
        regs[RDI] = kpeek64(proc+16);
        uint64_t stack_frame_2[14] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 3), [6] = stack_frame[13], regs[RDI]};
        memcpy(stack_frame_2+8, stack_frame+7, 48);
        if(sysc_no == SYS_sysarch && (uint32_t)stack_frame[7] == AMD64_GET_FSBASE)
        {
            stack_frame_2[1] = MKTRAP(TRAP_KEKCALL, 4);
            stack_frame_2[8] = kpeek64(kpeek64(regs[RDI]+td_pcb)+pcb_fsbase);
            kpoke64(stack_frame[13]+td_retval, 0);
        }
        else
            kpoke64(regs[RDI]+td_retval, 0);
        push_stack(regs, stack_frame_2, sizeof(stack_frame_2));
        regs[RAX] = (uint64_t)&sysents[sysc_no];
        if(sysc_no == SYS_sysarch && (uint32_t)stack_frame[7] == AMD64_GET_FSBASE)
        {
            regs[RIP] = (uint64_t)copyout;
            regs[RDI] = regs[RSP] + 64;
            regs[RSI] = stack_frame[8];
            regs[RDX] = 8;
        }
        else
        {
            regs[RIP] = kpeek64((uint64_t)&sysents[sysc_no].sy_call);
            regs[RSI] = regs[RSP] + 64;
            handle_syscall(regs, 0);
        }
    }
    else if(trap == 3 || trap == 4)
    {
        uint64_t stack_frame[14];
        pop_stack(regs, stack_frame, sizeof(stack_frame));
        if(trap == 3 && !(uint32_t)regs[RAX])
            kpoke64(stack_frame[5]+td_retval, kpeek64(stack_frame[6]+td_retval));
        regs[RIP] = stack_frame[13];
    }
    else if(trap == 6)
    {
        // Return from kekcall nr=7 (kproc_create)
        uint64_t stack_frame[14];
        pop_stack(regs, stack_frame, sizeof(stack_frame));
        uint64_t td = stack_frame[11];
        kpoke64(td+td_retval, regs[RAX]);
        regs[RAX] = 0;
        regs[RIP] = stack_frame[13];
    }
    else if(trap == 7)
    {
        // Return from kekcall nr=8 (copyin)
        // copyin returns 0 on success, EFAULT on failure
        uint64_t stack_frame[14];
        pop_stack(regs, stack_frame, sizeof(stack_frame));
        uint64_t td = stack_frame[11];
        kpoke64(td+td_retval, regs[RAX]);
        regs[RAX] = 0;
        regs[RIP] = stack_frame[13];
    }
}

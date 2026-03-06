.intel_syntax noprefix
.global kekcall_malloc
.global kekcall_copyin
.global kekcall_kproc_create
.global kekcall_read_kmem
.global kekcall_make_exec
.global kekcall_check

/* kekcall nr=6: malloc(size) -> kernel address */
kekcall_malloc:
    mov rax, 0x600000027
    syscall
    ret

/* kekcall nr=8: copyin(user_buf, kern_addr, size) */
/* RDI=user_buf, RSI=kern_addr, RDX=size */
kekcall_copyin:
    mov rax, 0x800000027
    syscall
    ret

/* kekcall nr=7: kproc_create(func, args, name) */
/* RDI=func, RSI=args, RDX=name */
kekcall_kproc_create:
    mov rax, 0x700000027
    syscall
    ret

/* kekcall nr=9 mode=5: read kernel uint64 at address */
/* RDI=mode (5), RSI=kernel_addr */
kekcall_read_kmem:
    mov rax, 0x900000027
    syscall
    ret

/* kekcall nr=10: clear NX bit on page at kernel addr */
/* RDI=kernel_addr, RSI=mode (1=clear NX) */
kekcall_make_exec:
    mov rax, 0xa00000027
    syscall
    ret

/* kekcall nr=0xffffffff: check if kstuff is loaded */
kekcall_check:
    mov rax, 0xffffffff00000027
    syscall
    ret

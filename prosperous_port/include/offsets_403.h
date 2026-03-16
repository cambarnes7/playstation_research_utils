#ifndef PROSPEROUS_OFFSETS_403_H
#define PROSPEROUS_OFFSETS_403_H

/*
 * PS5 Kernel symbol offsets for Firmware 4.03 (CEX)
 *
 * These are RVAs from kernel .text base.
 * Kernel base is discovered at runtime via LSTAR MSR.
 *
 * Sources: ps5_kernel_research/kstuff-no-fpkg, a53_exploit, kernel_patching
 */

/* Process / thread structure offsets */
#define OFF_PROC_P_LIST         0x000   /* struct proc -> p_list (ListEntry) */
#define OFF_PROC_P_UCRED        0x040   /* struct proc -> p_ucred */
#define OFF_PROC_P_FD           0x048   /* struct proc -> p_fd */
#define OFF_PROC_P_PID          0x0BC   /* struct proc -> p_pid */
#define OFF_PROC_P_VMSPACE      0x200   /* struct proc -> p_vmspace */
#define OFF_PROC_P_TITLEID      0x470   /* struct proc -> titleId */
#define OFF_PROC_SDK_VER_PPR    0x590   /* struct proc -> sdk_ver_ppr */
#define OFF_PROC_P_NAME         0x59C   /* struct proc -> p_comm */
#define OFF_PROC_IS_PPR         0xC39   /* struct proc -> is_ppr */
#define OFF_PROC_SDK_VER_MINOR  0xC84   /* struct proc -> sdk_ver_ppr_minor */

/* vmspace / pmap offsets */
#define OFF_VMSPACE_VM_PMAP     0x2E0   /* struct vmspace -> vm_pmap */
#define OFF_PMAP_PM_PML4        0x020   /* struct pmap -> pm_pml4 */
#define OFF_PMAP_PM_CR3         0x028   /* struct pmap -> pm_cr3 */

/* filedesc offsets */
#define OFF_FD_RDIR             0x010   /* struct filedesc -> fd_rdir */
#define OFF_FD_JDIR             0x018   /* struct filedesc -> fd_jdir */

/* ucred offsets */
#define OFF_UCRED_CR_UID        0x004
#define OFF_UCRED_CR_RUID       0x008
#define OFF_UCRED_CR_SVUID      0x00C
#define OFF_UCRED_CR_NGROUPS    0x010
#define OFF_UCRED_CR_RGID       0x014
#define OFF_UCRED_CR_SVGID      0x018
#define OFF_UCRED_SCE_0         0x058
#define OFF_UCRED_SCE_8         0x060
#define OFF_UCRED_CR_GROUPS     0x118

/* Kernel function RVAs for FW 4.03 */
#define KOFF_COPYIN             0x2DFEB0
#define KOFF_COPYOUT            0x2DFE00
#define KOFF_KMEM_ALLOC_CONTIG  0x4E9A30
#define KOFF_KMEM_MALLOC        0x4E9E70
#define KOFF_KMEM_FREE          0x4EA0F0
#define KOFF_PMAP_KEXTRACT      0x846CB0
#define KOFF_PMAP_PROTECT       0x849F00
#define KOFF_KTHREAD_ADD        0x88F7F0
#define KOFF_KTHREAD_EXIT       0x88FAC0
#define KOFF_SOACCEPT           0x4DFC00
#define KOFF_SOBIND             0x4DF4C0
#define KOFF_SOCLOSE            0x4DF660
#define KOFF_SOCREATE           0x4DE3A0
#define KOFF_SOLISTEN           0x4DF5B0
#define KOFF_SORECEIVE          0x4E2910
#define KOFF_SOSEND             0x4E0B10
#define KOFF_SOSETOPT           0x4E2C80
#define KOFF_PUTCHAR            0x490480
#define KOFF_MSGBUF_ADDSTR      0xB62370
#define KOFF_PRINTF             0x4909A0
#define KOFF_SMP_RENDEZVOUS     0xA54060
#define KOFF_SLEEP              0xB38CC0
#define KOFF_MTX_LOCK_FLAGS     0x4A4450
#define KOFF_MTX_UNLOCK_FLAGS   0x4A4950
#define KOFF_MALLOC             0xB3B560
#define KOFF_FREE               0xB3B770
#define KOFF_SBL_SVC_REQUEST    0x721A50
#define KOFF_IO_MSG_HANDLER     0x507090
#define KOFF_HANDLE_DEFAULT     0x722080
#define KOFF_NDINIT_ALL         0x5A1980
#define KOFF_NDFREE             0x5A1A00
#define KOFF_VN_OPEN            0x635AE0
#define KOFF_VN_CLOSE           0x636680
#define KOFF_VN_RDWR            0x636880

/* Kernel data RVAs */
#define KOFF_KERNEL_ARENA       0x18A1E30
#define KOFF_KMEM_ARENA         0x18A1E38
#define KOFF_KTEXT_SLACK        0xBCBBC8
#define KOFF_BOOTPARAMS         0x7041D40
#define KOFF_KERNEL_PMAP        0x3D94218
#define KOFF_MDBG_TRAP_EARLY    0x757A60
#define KOFF_SYSVERI_NOTIF      0x31D7C48
#define KOFF_ACCEPT_MTX         0x3332870
#define KOFF_DMAP_INDICES       0x3D944A0

/* allproc (process list head) */
#define KOFF_ALLPROC            0x333DC58

/* sysent table access (via proc) */
#define OFF_PROC_P_SYSENT       0x9C0   /* proc -> p_sysent (sysvec pointer) */
#define OFF_SYSVEC_SYSENT       0x008   /* sysvec -> sv_table (sysent array) */

/* sysent entry layout */
#define SYSENT_SIZE             0x30
#define OFF_SYSENT_NARG         0x00    /* sy_narg */
#define OFF_SYSENT_CALL         0x08    /* sy_call */

/* CFI check fail function offset */
#define KOFF_CFI_CHECK_FAIL     0x441DD0

/* ktext PA -> VA mapping offset (in kernel data segment) */
#define KOFF_KTEXT_VA_PTR       0x73A3030

/* VMCB physical address location (from HV data) */
#define VCPU_CTXS_PA            0x628485D0ULL

/* VMCB structure offsets */
#define VMCB_INTERCEPT_VEC0     0x00
#define VMCB_INTERCEPT_VEC3     0x0C
#define VMCB_INTERCEPT_VEC4     0x10
#define VMCB_NP_CTRL            0x90    /* Nested Paging control */

/* NP_CTRL flags */
#define NP_ENABLE               (1 << 0)
#define GMET_ENABLE             (1ULL << 36)

#endif

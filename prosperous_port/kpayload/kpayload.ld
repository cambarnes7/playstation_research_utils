ENTRY(sys_kpayload)
SECTIONS {
    payload_start = .;
    payload : {
        *(.text.sys_kpayload)
        payload_early_start = .;
        *(.text._ZL11nda_disablev)
        *(.text._ZL11nda_enabledv)
        *(.text._ZL18nda_disable_workerPv)
        payload_early_end = .;
        *(.text)
        *(.text.*)
        *(.rodata)
        *(.rodata.*)
        *(.data)
        *(.data.*)
    }
    payload_end = .;

    /* bootstrap stuff must be on first page (physically contiguous) */
    ASSERT((payload_end - payload_start) <= 0x4000, "payload larger than 16KB")

    /DISCARD/ : {
        *(.note.*)
        *(.comment)
        *(*)
    }
}

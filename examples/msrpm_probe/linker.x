OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

ENTRY(module_start)

PHDRS
{
        code_seg PT_LOAD;
        rdata_seg PT_LOAD;
        data_seg PT_LOAD;
}

SECTIONS
{
        .text : {
                *(.text.module_start)
                *(.text*)
        } : code_seg
        .rodata : {
                *(.rodata)
                *(.rodata*)
        } : rdata_seg
        .data : {
                *(.data)
                *(.data.*)
                /* Merge BSS into data so objcopy includes it in the
                 * flat binary.  The kernel malloc'd buffer must cover
                 * these addresses — otherwise we corrupt the heap. */
                *(.bss)
                *(.bss.*)
                . = ALIGN(8);
        } : data_seg
        /DISCARD/ : {
                *(.comment)
                *(.note.GNU-stack)
                *(.eh_frame)
                *(.interp)
                *(.note.gnu.property)
        }
}

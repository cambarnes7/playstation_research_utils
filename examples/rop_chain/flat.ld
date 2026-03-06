/* Flat binary linker script for PS5 kernel payloads.
 * Entry at offset 0, .text first, .data follows, .bss last.
 * No ELF headers in output — objcopy strips them.
 */
OUTPUT_FORMAT("elf64-x86-64")
ENTRY(_start)

SECTIONS
{
    . = 0;
    .text : { *(.text*) }
    .data : { *(.data*) }
    .bss  : { *(.bss*) }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}

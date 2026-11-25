MEMORY
{
    /* Code/rodata/data/bss region at base of the 64 MiB flat RV32IM benchmark RAM (0x8000_0000..0x8400_0000).
       Heap: 0x8040_0000..0x8340_0000 (48 MiB) | Input mailbox: 0x8340_0000..0x83F0_0000 (11 MiB)
       Output mailbox: 0x83F0_0000..0x83F1_0000 (64 KiB) | Stack: 0x83FF_FFF0 downward (~960 KiB). */
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 4M
}

ENTRY(_start)

SECTIONS
{
    .text 0x80000000 : {
        KEEP(*(.text.init))
        *(.text .text.*)
    } > RAM

    .rodata : ALIGN(4) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } > RAM

    .data : ALIGN(4) {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } > RAM

    .bss (NOLOAD) : ALIGN(4) {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment*)
    }
}

/*
 * Memory layout for stage 3
 */

SECTIONS
{
  . = 0x0;

  . = 0x7000;
  __heap_start = .;
  . = 0xa000;
  __heap_stop = .;

  . = 0xa000;
  _parm_addr = .;
  . = 0xa008;
  _initrd_addr = .;
  . = 0xa010;
  _initrd_len = .;
  . = 0xa018;
  _load_psw = .;
  . = 0xa020;
  _extra_parm = .;
  . = 0xa028;
  stage3_flags =.;

  . = 0xa000;
  .text.dummy : { *(.text.dummy) }

  . = 0xa050;
  .text.start : { *(.text.start) }
  .text : { *(.text) }
  __ex_table_start = .;
  .ex_table : { *(.ex_table) }
  __ex_table_stop = .;
  .eh_frame : { *(.eh_frame) }

  . = 0xc000;
  __bss_start = .;
  .bss : { *(.bss) }
  __bss_stop = .;
  .rodata : {*(.rodata) }
  .data : { *(.data) }

}

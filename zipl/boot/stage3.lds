/*
 * Memory layout for stage 3
 * =========================
 *
 * General memory layout
 * ---------------------
 *
 * 0x0000-0x1fff	Lowcore
 * 0x2000-0x5fff	Memory allocation (heap)
 * 0x6000-0x8fff	free
 * 0x9000-0x9fff        Stage3 parameter
 * 0xa000-0xdfff        Stage3 code + data
 * 0xf000-0xffff        Stack
 */

SECTIONS
{
  . = 0x0;

  . = 0x2000;
  __heap_start = .;
  . = 0x6000;
  __heap_stop = .;


  /* stage 3 parameter */
  . = 0x9000;
  _parm_addr = .;
  . = 0x9008;
  _initrd_addr = .;
  . = 0x9010;
  _initrd_len = .;
  . = 0x9018;
  _load_psw = .;
  . = 0x9020;
  _extra_parm = .;
  . = 0x9028;
  stage3_flags =.;
  . = 0x9030;
  _image_len = .;
  . = 0x9038;
  _image_addr = .;

  . = 0xa000;
  .text.start : { *(.text.start) }
  .text : { *(.text) }
  __ex_table_start = .;
  .ex_table : { *(.ex_table) }
  __ex_table_stop = .;
  .eh_frame : { *(.eh_frame) }

  __bss_start = .;
  .bss : { *(.bss) }
  __bss_stop = .;
  .rodata : {*(.rodata) }
  .data : { *(.data) }
}

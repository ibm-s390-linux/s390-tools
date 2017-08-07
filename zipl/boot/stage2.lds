/*
 * Memory layout for stage 2
 * =========================
 *
 * General memory layout
 * ---------------------
 *
 * 0x0000-0x1fff	Lowcore
 * 0x2000-0x4fff	Sections (load): head, text, data, rodata, rodata.str
 * 0x5000-0x51ff	eckd2dump_mv parameter block (426 bytes)
 * 0x5200-0x5fff	Sections: bss
 * 0x6000-0x9fff	Memory allocation (heap)
 * 0xa000-0xdfff        Memory to load stage3 to
 * 0xe000-0xffff	Stack
 *
 * Special memory locations
 * ------------------------
 *
 * 0x78			Stage 2 description parameters
 * 0x2018		Stage 2 entry point
 * 0x3ff7		eckd2dump_mv force parameter
 * 0x3ff8		Max mem dump parameter
 * 0x5000-0x51ff	eckd2dump_mv parameter block (426 bytes)
 */

SECTIONS
{
  . = 0x78;
  __stage2_desc = .;

  . = 0x2000;
  .stage2.head : { *(.stage2.head) }
  . = 0x2018;
  .text.start : { *(.text.start) }
  .text : { *(.text) }
  __ex_table_start = .;
  .ex_table : { *(.ex_table) }
  __ex_table_stop = .;
  .rodata : {*(.rodata) }
  .data : { *(.data) }
  __stage2_params = .;

  . = 0x4ff0;
  .stage2dump.tail : { *(.stage2dump.tail) }
  . = 0x5000;
  .eckd2dump_mv.tail : { *(.eckd2dump_mv.tail) }

  . = 0x5200;
  __bss_start = .;
  .bss : { *(.bss) }
  __bss_stop = .;

  . = 0x6000;
  __heap_start = .;
  . = 0xa000;
  __heap_stop = .;

  . = 0xf000;
  .eh_frame : { *(.eh_frame) }
  .note.gnu.build-id : { *(.note.gnu.build-id) }
}

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
 * 0x6000-0x8fff	Memory allocation (heap)
 * 0x9000-0x9fff        Memory to load stage3 parameter to
 * 0xa000-0xdfff        Memory to load stage3 to
 * 0xe000-0xe3ff	command line extra
 * 0xe400-0xffff	Stack
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

#include "boot/loaders_layout.h"

SECTIONS
{
  . = STAGE2_DESC;
  __stage2_desc = .;

  . = STAGE2_LOAD_ADDRESS;
  .stage2.head : { *(.stage2.head) }
  . = STAGE2_ENTRY;
  .text.start : {
    *(.text.start)
  }
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

  . = STAGE2_HEAP_ADDRESS;
  __heap_start = .;
  .heap : {
    . += STAGE2_HEAP_SIZE;
    ASSERT(__heap_stop - __heap_start == STAGE2_HEAP_SIZE,
           "Heap section doesn't conform to the described memory layout");
  }
  __heap_stop = .;

  /* Memory reserved for stage3. Use a dummy section to check if changes
   * in stage3 memory layout work with stage2 and vice versa.
   */
  . = STAGE3_PARAMS_ADDRESS;
  .stage3 : {
    . += STAGE3_PARAMS_MAXIMUM_SIZE;

    . = STAGE3_LOAD_ADDRESS - STAGE3_PARAMS_ADDRESS;
    . += STAGE3_MAXIMUM_SIZE;

    . = COMMAND_LINE_EXTRA - STAGE3_PARAMS_ADDRESS;
    . += COMMAND_LINE_EXTRA_SIZE;
  }

  . = STAGE2_STACK_ADDRESS;
  __stack_start = .;
  .stack : {
    . += STAGE2_STACK_SIZE;
    ASSERT(__stack_end - __stack_start == STAGE2_STACK_SIZE,
           "Stack section doesn't conform to the described memory layout");
  }
  __stack_end = .;

  .eh_frame : { *(.eh_frame) }
  .note.gnu.build-id : { *(.note.gnu.build-id) }
}

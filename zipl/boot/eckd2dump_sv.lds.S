/*
 * Memory layout of stage 2 for single volume dasd
 * dump tool with compression support
 * ===============================================
 *
 * General memory layout
 * ---------------------
 *
 * 0x0000-0x1fff	Lowcore
 * 0x2000-0x9fff	Sections (load): head, text, data, rodata, rodata.str
 * 0xa000-0xafff	Sections: bss
 * 0xb000-0xdfff	Memory allocation (heap)
 * 0xe000-0xffff	Stack
 *
 * Special memory locations
 * ------------------------
 *
 * 0x78			Stage 2 description parameters
 * 0x2018		Stage 2 entry point
 * 0x9ff8		Max mem dump parameter
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

  . = 0x9ff0;
  .stage2dump.tail : { *(.stage2dump.tail) }

  . = 0xa000;
  __bss_start = .;
  .bss : { *(.bss) }
  __bss_stop = .;

  . = ECKD2DUMP_SV_HEAP_ADDRESS;
  __heap_start = .;
  .heap : {
    . += STAGE2_HEAP_SIZE;
    ASSERT(__heap_stop - __heap_start == STAGE2_HEAP_SIZE,
           "Heap section doesn't conform to the described memory layout");
  }
  __heap_stop = .;

  . = ECKD2DUMP_SV_STACK_ADDRESS;
  __stack_start = .;
  .stack : {
    . += ECKD2DUMP_SV_STACK_SIZE;
    ASSERT(__stack_end - __stack_start == ECKD2DUMP_SV_STACK_SIZE,
           "Stack section doesn't conform to the described memory layout");
  }
  __stack_end = .;

  /* Sections to be discarded */
  /DISCARD/ : {
    *(.eh_frame)
    *(.interp)
    *(.note.GNU-stack)
  }
}

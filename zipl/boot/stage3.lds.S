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

#include "boot/loaders_layout.h"

SECTIONS
{
  . = 0x0;

  . = STAGE3_HEAP_ADDRESS;
  __heap_start = .;
  .heap : {
    . += STAGE3_HEAP_SIZE;
    ASSERT(__heap_stop - __heap_start == STAGE3_HEAP_SIZE,
           "Heap section doesn't conform to the described memory layout");
  }
  __heap_stop = .;

  /* stage 3 parameter */
  . = STAGE3_PARAMS_ADDRESS;
  _stage3_parms = .;

  . = STAGE3_ENTRY;
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

  . = COMMAND_LINE_EXTRA;
  .cmdline_extra : {
    . += COMMAND_LINE_EXTRA_SIZE;
  }

  . = STAGE3_STACK_ADDRESS;
  __stack_start = .;
  .stack : {
    . += STAGE3_STACK_SIZE;
    ASSERT(__stack_end - __stack_start == STAGE3_STACK_SIZE,
           "Stack section doesn't conform to the described memory layout");
  }
  __stack_end = .;
}

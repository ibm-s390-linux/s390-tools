/*
 * Memory layout of stage 2 for ECKD DASD dump tool
 * (single volume and multi volume)
 * ===============================================
 *
 * General memory layout
 * ---------------------
 *
 * 0x0000-0x1fff	Lowcore
 * 0x2000-0xafff	Sections (load): head, text, data, rodata, rodata.str,
 *			stage2dump.tail, eckd2dump_mv.tail, bss
 * 0xb000-0xdfff	Memory allocation (heap)
 * 0xe000-0xffff	Stack
 *
 * Special memory locations
 * ------------------------
 *
 * 0x78			Stage 2 description parameters
 * 0x2018		Stage 2 entry point
 * 0x5ff0		Stage 2 multi-volume dump parameters (eckd2dump_mv)
 * 0x6000		Multi-volume dump parameters table (eckd2dump_mv)
 * 0x9ff0		Stage 2 single volume dump parameters (eckd2dump_sv)
 */

#include "boot/loaders_layout.h"

SECTIONS
{
  . = STAGE2_DESC;
  __stage2_desc = .;

  . = STAGE2_LOAD_ADDRESS;
  __stage2_head = .;
  .stage2.head : { *(.stage2.head) }
  . = STAGE2_ENTRY;
  .text : {
    *(.text.start)
    *(.text .text.*)
  }
  __ex_table_start = .;
  .ex_table : { *(.ex_table) }
  __ex_table_stop = .;
  .rodata : {*(.rodata .rodata.*) }
  .data : { *(.data .data.*) }

  . = STAGE2DUMP_TAIL_ADDRESS;
  .stage2dump.tail : { *(.stage2dump.tail)
#ifdef ECKD2DUMP_MV
    ASSERT(__stage2dump_tail_end - __stage2_head == STAGE2_DUMPER_SIZE_MV,
           "MV dumper size doesn't conform to the described memory layout");
#else
    ASSERT(__stage2dump_tail_end - __stage2_head == STAGE2_DUMPER_SIZE_SV_ZLIB,
           "SV dumper size doesn't conform to the described memory layout");
#endif
  }
  __stage2dump_tail_end = .;
#ifdef ECKD2DUMP_MV
  . = ECKD2DUMP_MV_TAIL_ADDRESS;
  .eckd2dump_mv.tail : { *(.eckd2dump_mv.tail) }
#endif
  __bss_start = .;
  .bss : { *(.bss .bss.*) }
  __bss_stop = .;

  . = ECKD2DUMP_HEAP_ADDRESS;
  __heap_start = .;
  .heap : {
    . += STAGE2_HEAP_SIZE;
    ASSERT(__heap_stop - __heap_start == STAGE2_HEAP_SIZE,
           "Heap section doesn't conform to the described memory layout");
  }
  __heap_stop = .;

  . = ECKD2DUMP_STACK_ADDRESS;
  __stack_start = .;
  .stack : {
    . += ECKD2DUMP_STACK_SIZE;
    ASSERT(__stack_end - __stack_start == ECKD2DUMP_STACK_SIZE,
           "Stack section doesn't conform to the described memory layout");
  }
  __stack_end = .;

  /* Sections to be discarded */
  /DISCARD/ : {
    *(.eh_frame)
    *(.interp)
    *(.note.GNU-stack)
    *(.note.package)
  }
}

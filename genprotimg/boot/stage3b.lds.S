/*
 * Memory layout for stage 3b
 * ==========================
 *
 * General memory layout
 * ---------------------
 *
 * 0x00000 - 0x01fff	Lowcore
 * 0x02000 - 0x05fff	Memory allocation (heap)
 * 0x0a000 - 0x0efff	Stage3b code
 * 0x0f000 - 0x0ffff	Stack
 */

#include "stage3b.h"
#include "common_memory_layout.h"

OUTPUT_FORMAT("elf64-s390", "elf64-s390", "elf64-s390")
OUTPUT_ARCH(s390:64-bit)

ENTRY(_start)

SECTIONS
{
	. = 0x0;

	. = HEAP_ADDRESS;
	__heap_start = .;
	.heap : {
		. = . + HEAP_SIZE;
		ASSERT(__heap_stop - __heap_start == HEAP_SIZE,
		       "Heap section doesn't conform to the described memory layout");
	}
	__heap_stop = .;

	. = STAGE3B_ENTRY;
	.text : {
		head.o(.text.start)
		*(.text)
	}

	.ex_table ALIGN(16) : {
		__ex_table_start = .;
		*(.ex_table)
		__ex_table_stop = .;
	}

	.bss ALIGN(16) : {
		__bss_start = .;
		*(.bss)
		__bss_stop = .;
	}

	.rodata ALIGN(16) : {
		*(.rodata)
		*(.rodata.*)
	}

	.data ALIGN(16) : {
		*(.data)
		. = ALIGN(16);
		__loader_parms_start = .;
		KEEP(*(.loader_parms));
		__loader_parms_end = .;
		ASSERT(__loader_parms_end - __loader_parms_start == 3 * 16 + 16,
		       "Data size must be equal to 'sizeof(struct stage3b_args)'");
	}

	. = STACK_ADDRESS;
	__stack_start = .;
	.stack : {
		. = . + STACK_SIZE;
		ASSERT(__stack_end - __stack_start == STACK_SIZE,
		       "Stack section doesn't conform to the described memory layout");
	}
	__stack_end = .;

	/* List this explicitly as otherwise .note.gnu.build-id will be
	 * put at 0x0 */
	.notes : {
		*(.note.*)
	}

	/* Sections to be discarded */
	/DISCARD/ : {
		*(.eh_frame)
	}
}

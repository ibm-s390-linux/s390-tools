/*
 * Memory layout for stage 3a
 * ==========================
 *
 * General memory layout
 * ---------------------
 *
 * 0x00000 - 0x01fff	Lowcore
 * 0x02000 - 0x05fff	Memory allocation (heap)
 * 0x0f000 - 0x0ffff	Stack
 * 0x10000 - 0x10012	Jump to the "actual" stage3a code
 * 0x11000 - 0x12fff	Stage3a code + arguments (offsets and lengths to the
 * 			actual data: IPIB and UV header)
 */

#include "stage3a.h"
#include "common_memory_layout.h"

OUTPUT_FORMAT("elf64-s390", "elf64-s390", "elf64-s390")
OUTPUT_ARCH(s390:64-bit)

ENTRY(_init)

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

	. = STACK_ADDRESS;
	__stack_start = .;
	.stack : {
		. = . + STACK_SIZE;
		ASSERT(__stack_end - __stack_start == STACK_SIZE,
		       "Stack section doesn't conform to the described memory layout");
	}
	__stack_end = .;

	. = STAGE3A_INIT_ENTRY;
	__text_init_start = .;
	.text : {
		stage3a_init.o(.text.init)
		__text_init_stop = ABSOLUTE(.);
		/* Text size of text_init must be smaller than 'PARMAREA - IMAGE_ENTRY',
		 * otherwise the text data could be overwritten by the original zipl stage3
		 * boot loader */
		ASSERT(__text_init_stop - __text_init_start < PARMAREA - IMAGE_ENTRY,
		       "Text size must be smaller than 'PARMAREA - IMAGE_ENTRY'");
		. = 0x1000;
		ASSERT(ABSOLUTE(.) == STAGE3A_ENTRY,
		       "Text section doesn't conform to the described memory layout");
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
		/* The IPIB offset and the UV header offset and size will be
		 * saved in 'loader_parms' */
		__loader_parms_start = .;
		KEEP(*(.loader_parms));
		__loader_parms_stop = .;
		ASSERT(__loader_parms_stop - __loader_parms_start == 3 * 8,
		       "Data size must be equal to 'sizeof(struct stage3a_args)'");
		ASSERT(ABSOLUTE(.) < 0x13000, "Data section doesn't conform to the described memory layout");
	}

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

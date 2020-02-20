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

OUTPUT_FORMAT("elf64-s390", "elf64-s390", "elf64-s390")
OUTPUT_ARCH(s390:64-bit)

ENTRY(_start)

__heap_size__ = 0x4000;
__stack_size__ = 0x1000;

SECTIONS
{
	. = 0x0;

	. = 0x2000;
	__heap_start = .;
	.heap : {
		. = . + __heap_size__;
		ASSERT(__heap_stop - __heap_start == __heap_size__,
		       "Heap section doesn't conform to the described memory layout");
	}
	__heap_stop = .;

	. = 0xa000;
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

	. = 0xf000;
	__stack_start = .;
	.stack : {
		. = . + __stack_size__;
		ASSERT(__stack_end - __stack_start == __stack_size__,
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

OUTPUT_FORMAT("elf64-s390", "elf64-s390", "elf64-s390")
OUTPUT_ARCH(s390:64-bit)

ENTRY(_start)

SECTIONS
{
	.text : {
		*(.text.start)
		*(.text .text.*)
	}

	.unsupported_input_sections : {
	  *(.eh_frame)
	  *(.interp)
	}
	ASSERT(SIZEOF(.unsupported_input_sections) == 0, "Unsupported input sections were found.")

	/* Sections to be discarded */
	/DISCARD/ : {
		*(.note.*)
	}
}

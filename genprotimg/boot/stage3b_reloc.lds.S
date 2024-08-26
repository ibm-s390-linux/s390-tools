OUTPUT_FORMAT("elf64-s390", "elf64-s390", "elf64-s390")
OUTPUT_ARCH(s390:64-bit)

ENTRY(_start)

SECTIONS
{
	.text : {
		*(.text.start)
		*(.text .text.*)
	}

	/* Sections to be discarded */
	/DISCARD/ : {
		*(.eh_frame)
		*(.interp)
		*(.note.GNU-stack)
		*(.note.package)
	}
}

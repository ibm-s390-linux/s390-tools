#include "boot/loaders_layout.h"

ENTRY(_start)

SECTIONS
{
  . = STAGE1B_LOAD_ADDRESS;
  .text : {
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

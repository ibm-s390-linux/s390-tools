#include "boot/loaders_layout.h"

ENTRY(_start)

SECTIONS
{
  . = STAGE1_LOAD_ADDRESS;
  .text : {
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

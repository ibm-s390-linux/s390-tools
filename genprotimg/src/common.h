#ifndef COMMON_H
#define COMMON_H

#define GETTEXT_PACKAGE "genprotimg"
#include <glib.h>
#include <glib/gi18n-lib.h>

#include "boot/linux_layout.h"
#include "boot/s390.h"
#include "lib/zt_common.h"

static const gchar tool_name[] = "genprotimg";
static const gchar copyright_notice[] = "Copyright IBM Corp. 2020";

/* default values */
#define GENPROTIMG_STAGE3A_PATH (STRINGIFY(PKGDATADIR) "/stage3a.bin")
#define GENPROTIMG_STAGE3B_PATH (STRINGIFY(PKGDATADIR) "/stage3b_reloc.bin")

#define DEFAULT_INITIAL_PSW_ADDR IMAGE_ENTRY
#define DEFAULT_INITIAL_PSW_MASK (PSW_MASK_EA | PSW_MASK_BA)

#define DO_PRAGMA(x) _Pragma(#x)

# ifdef __clang__
#  define WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(...) \
	DO_PRAGMA(clang diagnostic push) \
	DO_PRAGMA(clang diagnostic ignored "-Wunused-function") \
	G_DEFINE_AUTOPTR_CLEANUP_FUNC(__VA_ARGS__) \
	DO_PRAGMA(clang diagnostic pop)
# else
#  define WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(...) \
	G_DEFINE_AUTOPTR_CLEANUP_FUNC(__VA_ARGS__)
# endif

#endif

#! /usr/bin/make -f
#
# This Makefile creates a message.po template for translation input.
#
# To create a localized message.po file from the template, run
# 	msginit -i progname.pot -l de_DE # --no-translator
#
# To finally create the binary message.mo file, run
# 	msgfmt de.po -o /usr/share/locale/de/LC_MESSAGES/progname.mo
#

#include ../../common.mak


ifndef GETTEXT_TEXTDOMAIN
GETTEXT_TEXTDOMAIN = iucvterm
endif

XGETTEXT = xgettext
XGETTEXT_ARGS = --keyword=print_error
POTFILES = POTFILES.in


all: $(GETTEXT_TEXTDOMAIN).pot

check:

install:

clean:
	-rm -f $(GETTEXT_TEXTDOMAIN).pot

$(GETTEXT_TEXTDOMAIN).pot:
	@$(XGETTEXT) --default-domain=$(GETTEXT_TEXTDOMAIN) --directory='..' \
		--add-comments --keyword=_ --keyword=N_ \
		--flag=g_strdup_printf:1:c-format \
		--flag=g_string_printf:2:c-format \
		--flag=g_string_append_printf:2:c-format \
		--flag=g_error_new:3:c-format \
		--flag=g_set_error:4:c-format \
		--flag=g_markup_printf_escaped:1:c-format \
		--flag=g_log:3:c-format \
		--flag=g_print:1:c-format \
		--flag=g_printerr:1:c-format \
		--flag=g_printf:1:c-format \
		--flag=g_fprintf:2:c-format \
		--flag=g_sprintf:2:c-format \
		--flag=g_snprintf:3:c-format \
		--flag=g_scanner_error:2:c-format \
		--flag=g_scanner_warn:2:c-format \
		--files-from=$(POTFILES) $(XGETTEXT_ARGS) \
	&& test ! -f $(GETTEXT_TEXTDOMAIN).po \
		|| ( rm -f $(GETTEXT_TEXTDOMAIN).pot \
			&& mv $(GETTEXT_TEXTDOMAIN).po $(GETTEXT_TEXTDOMAIN).pot )


.PHONY: install clean $(GETTEXT_TEXTDOMAIN).pot

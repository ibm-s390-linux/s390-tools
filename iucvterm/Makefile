#! /usr/bin/make -f

include ../common.mak


GETTEXT_TEXTDOMAIN = iucvterm
export GETTEXT_TEXTDOMAIN


SUBDIRS = src po doc bin etc test
RECURSIVE_TARGETS = all-recursive install-recursive clean-recursive \
                    check-recursive


all: all-recursive
install: install-recursive
clean: clean-recursive


$(RECURSIVE_TARGETS):
	@target=`echo $@ |sed s/-recursive//`; \
	for d in $(SUBDIRS); do \
		(cd $$d && $(MAKE) $$target) || exit 1; \
	done


.PHONY: install clean

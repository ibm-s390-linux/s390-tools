# Common definitions
include ../common.mak

.DEFAULT_GOAL := all

SUBDIRS := src man tools
RECURSIVE_TARGETS := all-recursive clean-recursive install-recursive

all: all-recursive

install: install-recursive

clean: clean-recursive

$(RECURSIVE_TARGETS):
	@target=`echo $@ |sed s/-recursive//`; \
		for d in $(SUBDIRS); do \
			$(MAKE) -C $$d $$target || exit 1; \
		done

.PHONY: all install clean $(RECURSIVE_TARGETS)

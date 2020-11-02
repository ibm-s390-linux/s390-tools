# Common definitions
include ../common.mak

.DEFAULT_GOAL := all

PKGDATADIR := "$(DESTDIR)$(TOOLS_DATADIR)/genprotimg"
TESTS :=
SUBDIRS := boot src man
RECURSIVE_TARGETS := all-recursive install-recursive clean-recursive

all: all-recursive

install: all install-recursive
	$(INSTALL) -d -m 755 "$(PKGDATADIR)"
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 boot/stage3a.bin "$(PKGDATADIR)"
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 boot/stage3b_reloc.bin "$(PKGDATADIR)"
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 samples/check_hostkeydoc "$(PKGDATADIR)"

clean: clean-recursive

$(RECURSIVE_TARGETS):
	@target=`echo $@ |sed s/-recursive//`; \
		for d in $(SUBDIRS); do \
			$(MAKE) -C $$d $$target || exit 1; \
		done

.PHONY: all install clean $(RECURSIVE_TARGETS)

#! /usr/bin/make -f

include ../../common.mak


IUCVTERM_DIR = $(SYSCONFDIR)/iucvterm
CONFIG_FILES = ts-shell.conf unrestricted.conf \
               ts-authorization.conf ts-audit-systems.conf


all:
check:
install: $(CONFIG_FILES)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -d $(DESTDIR)$(IUCVTERM_DIR) ; \
	for cnf in $(CONFIG_FILES); do \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 $$cnf $(DESTDIR)$(IUCVTERM_DIR) ; \
	done

clean:
	-rm -f *.o ts-shell.conf


%: %.in
	my_sysconf=$(IUCVTERM_DIR); \
	cat $< \
	  |sed -e "s#@sysconf_path@#$$my_sysconf#g" \
	       -e 's#@S390_TOOLS_RELEASE@#$(S390_TOOLS_RELEASE)#g' \
	> $@

.PHONY: install clean perl

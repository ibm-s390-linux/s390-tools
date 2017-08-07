#! /usr/bin/make -f

include ../../common.mak


BIN_SCRIPTS = ts-shell
SBIN_SCRIPTS = chiucvallow

SCRIPTS = $(BIN_SCRIPTS) $(SBIN_SCRIPTS)


all:
check:
install: $(SCRIPTS)
	for prg in $(BIN_SCRIPTS); do \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 $$prg $(DESTDIR)$(USRBINDIR) ; \
	done
	for prg in $(SBIN_SCRIPTS); do \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 $$prg $(DESTDIR)$(USRSBINDIR) ; \
	done
	$(INSTALL) -g $(GROUP) -o $(OWNER) -d $(DESTDIR)$(VARDIR)/log/ts-shell
	ln -f -s chiucvallow $(DESTDIR)$(USRSBINDIR)/lsiucvallow

clean:
	-rm -f *.o $(SCRIPTS)


%: %.in
	real_usrbin=$(USRBINDIR); \
	real_var=$(VARDIR); \
	my_sysconf=$(SYSCONFDIR)/iucvterm; \
	$(SED) -e "s#@sysconf_path@#$$my_sysconf#g" \
	       -e "s#@iucvconn_path@#$$real_usrbin#g" \
	       -e "s#@var_path@#$$real_var#g" \
	       -e 's#@S390_TOOLS_RELEASE@#$(S390_TOOLS_RELEASE)#g' \
	< $< > $@

perl: ts-shell
	perl -c $<

scripts: $(SCRIPTS)

.PHONY: install clean perl

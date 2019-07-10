#!/usr/bin/make -f

include ../common.mak


CPUMF_DATADIR = $(TOOLS_DATADIR)/cpumf
DATA_FILES = cpum-cf-hw-counter.map \
	     cpum-cf-cfvn-1.ctr cpum-cf-cfvn-3.ctr \
	     cpum-cf-csvn-12345.ctr cpum-cf-csvn-6.ctr \
             cpum-cf-extended-z10.ctr cpum-cf-extended-z196.ctr \
	     cpum-cf-extended-zEC12.ctr cpum-sf-modes.ctr \
	     cpum-cf-extended-z13.ctr cpum-cf-extended-z14.ctr
LIB_FILES = bin/cpumf_helper
USRBIN_SCRIPTS = bin/lscpumf
USRSBIN_SCRIPTS = bin/chcpumf
MAN_FILES = lscpumf.1 chcpumf.8

all:

scripts: $(USRBIN_SCRIPTS) $(USRSBIN_SCRIPTS) $(LIB_FILES)
	chmod +x $(USRBIN_SCRIPTS) $(USRSBIN_SCRIPTS) $(LIB_FILES)

check:

install: scripts install-man
	for prg in $(USRBIN_SCRIPTS); do \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 $$prg $(DESTDIR)$(USRBINDIR) ; \
	done
	for prg in $(USRSBIN_SCRIPTS); do \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 $$prg $(DESTDIR)$(USRSBINDIR) ; \
	done
	test -d $(DESTDIR)$(CPUMF_DATADIR) || mkdir -p $(DESTDIR)$(CPUMF_DATADIR)
	for lib in $(LIB_FILES); do \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 $$lib $(DESTDIR)$(TOOLS_LIBDIR) ; \
	done
	for data in $(DATA_FILES); do \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 data/$$data $(DESTDIR)$(CPUMF_DATADIR) ; \
	done

install-man:
	for man in $(MAN_FILES); do \
	  msection=`echo $$man |sed 's/.*\.\([1-9]\)$$/man\1/'` ; \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 -D man/$$man $(DESTDIR)$(MANDIR)/$$msection/$$man ; \
	done

man2pdf:
	for man in $(MAN_FILES); do \
	  man -t man/$$man |ps2pdf -sPAPERSIZE=a4 - man/$${man}.pdf ; \
	done
man2text:
	for man in $(MAN_FILES); do \
	  MANWIDTH=80 LANG=C man man/$$man |col -b |expand > man/$${man}.txt ; \
	done

clean:
	rm -f $(LIB_FILES) $(USRBIN_SCRIPTS) $(USRSBIN_SCRIPTS)

%: %.in
	real_libdir=$(TOOLS_LIBDIR); \
	real_cpumfdatadir=$(CPUMF_DATADIR); \
	$(SED) -e "s#@lib_path@#$$real_libdir#g" \
	       -e "s#@cpumfdata_path@#$$real_cpumfdatadir#g" \
	       -e 's#@S390_TOOLS_RELEASE@#$(S390_TOOLS_RELEASE)#g' \
	< $< > $@

.PHONY: all scripts install install-man man2pdf man2text clean

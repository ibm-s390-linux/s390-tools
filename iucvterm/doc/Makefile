#! /usr/bin/make -f

include ../../common.mak

MANS = iucvconn.1 iucvtty.1 ts-shell.1 hvc_iucv.9 chiucvallow.8 ttyrun.8

all:

check:

install: install-man

install-man: $(MANS)
	for man in $(MANS); do \
	  msection=`echo $$man |sed 's/.*\.\([1-9]\)$$/man\1/'` ; \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 -D $$man $(DESTDIR)$(MANDIR)/$$msection/$$man ; \
	done

clean:

pdf: $(MANS)
	for man in $(MANS); do \
	  man -t ./$$man |ps2pdf -sPAPERSIZE=a4 - $${man}.pdf ; \
	done


.PHONY: install-man install clean pdf

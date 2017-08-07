include ../common.mak

MANS = dumpconf.8 prandom.4 af_iucv.7

all:

clean:

install: $(MANS)
	for man in $(MANS); do \
	  msection=`echo $$man |sed 's/.*\.\([1-8]\)$$/man\1/'` ; \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 -D $$man $(DESTDIR)$(MANDIR)/$$msection/$$man ; \
	done

pdf: $(MANS)
	for man in $(MANS); do \
	  man -t ./$$man |ps2pdf -sPAPERSIZE=a4 - $${man}.pdf ; \
	done

.PHONY: all install clean pdf

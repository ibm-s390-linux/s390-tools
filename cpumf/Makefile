include ../common.mak

BIN_FILES = lscpumf chcpumf lshwc
MAN_FILES = lscpumf.1 chcpumf.8 lshwc.1

all: $(BIN_FILES)

libs =	$(rootdir)/libutil/libutil.a

lscpumf: lscpumf.o $(libs)
chcpumf: chcpumf.o $(libs)
lshwc: lshwc.o $(libs)

install: all install-man
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	for binf in $(BIN_FILES); do \
	 $(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 $$binf $(DESTDIR)$(BINDIR); \
	done

clean:
	rm -f *.o *~ $(BIN_FILES) core

install-man:
	for man in $(MAN_FILES); do \
	  msection=`echo $$man |sed 's/.*\.\([1-9]\)$$/man\1/'` ; \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 -D man/$$man $(DESTDIR)$(MANDIR)/$$msection/$$man ; \
	done

.PHONY: all install clean

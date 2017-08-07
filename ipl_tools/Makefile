include ../common.mak

all: chreipl lsreipl chshut lsshut

objects = main.o ccw.o fcp.o system.o shutdown.o \
	  cmd_lsshut.o cmd_chshut.o cmd_lsreipl.o cmd_chreipl.o proc.o

chreipl: $(objects)
	$(LINK) $(ALL_LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

lsreipl:
	ln -sf chreipl lsreipl

chshut:
	ln -sf chreipl chshut

lsshut:
	ln -sf chreipl lsshut

clean:
	rm -f *.o lsreipl chreipl chshut lsshut

install: all
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 chreipl \
		$(DESTDIR)$(USRSBINDIR)
	ln -f -s chreipl $(DESTDIR)$(USRSBINDIR)/lsreipl
	ln -f -s chreipl $(DESTDIR)$(USRSBINDIR)/chshut
	ln -f -s chreipl $(DESTDIR)$(USRSBINDIR)/lsshut
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/chreipl.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/lsreipl.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/lsshut.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/chshut.8 \
		$(DESTDIR)$(MANDIR)/man8

.PHONY: all install clean


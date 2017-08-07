include ../common.mak

all: mon_fsstatd mon_procd

mon_fsstatd: mon_fsstatd.o

mon_procd: mon_procd.o

install: all
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 mon_fsstatd \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 mon_fsstatd.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 mon_procd \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 mon_procd.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ mon_fsstatd mon_procd core

.PHONY: all install clean

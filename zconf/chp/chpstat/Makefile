include ../../../common.mak

all: chpstat

libs =	$(rootdir)/libutil/libutil.a

chpstat: chpstat.o $(libs) column.o key.o cmg.o cmg_helper.o \
	 cmg1.o cmg2.o cmg3.o cmg4.o cmg5.o

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 chpstat $(DESTDIR)$(BINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c chpstat.8 $(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o chpstat

.PHONY: all install clean

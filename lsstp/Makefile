include ../common.mak

libs = $(rootdir)/libutil/libutil.a
all: lsstp

lsstp: lsstp.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 lsstp $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 lsstp.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ lsstp core

.PHONY: all install clean

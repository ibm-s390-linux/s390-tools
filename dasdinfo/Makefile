include ../common.mak

libs = $(rootdir)/libutil/libutil.a \
       $(rootdir)/libdasd/libdasd.a

all: dasdinfo

dasdinfo: dasdinfo.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 dasdinfo $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 dasdinfo.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ dasdinfo core

.PHONY: all install clean

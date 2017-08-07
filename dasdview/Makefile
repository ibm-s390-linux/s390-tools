include ../common.mak

ALL_CPPFLAGS += -DSYSFS

all: dasdview

libs =	$(rootdir)/libdasd/libdasd.a \
	$(rootdir)/libzds/libzds.a \
	$(rootdir)/libvtoc/libvtoc.a \
	$(rootdir)/libu2s/libu2s.a \
	$(rootdir)/libutil/libutil.a

dasdview: dasdview.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 dasdview $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 dasdview.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ dasdview core

.PHONY: all install clean

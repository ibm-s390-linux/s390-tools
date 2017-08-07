include ../common.mak

ALL_CPPFLAGS += -D_FILE_OFFSET_BITS=64
LDLIBS += -lz

all: vmconvert

libs =  $(rootdir)/libvmdump/libvmdump.a
objects = vmconvert.o

vmconvert: $(objects) $(libs)
	$(LINKXX) $(ALL_LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR) $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 vmconvert \
		$(DESTDIR)$(USRBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 vmconvert.1 \
		$(DESTDIR)\$(MANDIR)/man1

clean:
	rm -f *.o vmconvert

.PHONY: all install clean

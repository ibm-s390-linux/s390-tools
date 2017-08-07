include ../common.mak

ALL_CPPFLAGS += -D_FILE_OFFSET_BITS=64
LDLIBS += -lz

all: vmur

libs =  $(rootdir)/libvmdump/libvmdump.a
objects = vmur.o

vmur: $(objects) $(libs)
	$(LINKXX) $(ALL_LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRSBINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 vmur $(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 vmur.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o vmur

.PHONY: all install clean

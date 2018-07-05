# Common definitions
include ../../common.mak

ALL_CPPFLAGS += -I../include -I../boot \
	    -DZFCPDUMP_IMAGE="STRINGIFY($(ZFCPDUMP_DIR)/$(ZFCPDUMP_IMAGE))" \
	    -DZFCPDUMP_INITRD="STRINGIFY($(ZFCPDUMP_DIR)/$(ZFCPDUMP_INITRD))" \
	    -D_FILE_OFFSET_BITS=64 $(NO_PIE_CFLAGS)
ALL_LDFLAGS += -Wl,-z,noexecstack $(NO_PIE_LDFLAGS)

libs =	$(rootdir)/libutil/libutil.a \
	$(rootdir)/libu2s/libu2s.a

objects = misc.o error.o scan.o job.o boot.o bootmap.o disk.o \
	  install.o zipl.o $(rootdir)/zipl/boot/data.o

zipl_helpers = $(basename $(wildcard zipl_helper.*.c))
chreipl_helpers = $(subst zipl_,chreipl_, $(zipl_helpers))

all: zipl $(chreipl_helpers)

zipl: $(objects) $(libs)

zipl_helper.device-mapper: $(rootdir)/libdasd/libdasd.a \
	$(rootdir)/libvtoc/libvtoc.a \
	$(libs) zipl_helper.device-mapper.o

chreipl_helper.%: zipl_helper.%
	ln -f -s $< $@

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -c zipl $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 $(zipl_helpers) $(chreipl_helpers) \
		$(DESTDIR)$(TOOLS_LIBDIR)
	$(CP) --no-dereference $(chreipl_helpers) $(DESTDIR)$(TOOLS_LIBDIR)

clean:
	rm -f *.o $(zipl_helpers) $(chreipl_helpers) zipl

.PHONY: all install clean

# Additional manual dependencies

../boot/data.h:
	make -C ../boot data.h

../boot/data.o:
	make -C ../boot data.o

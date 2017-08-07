# Common definitions
include ../../common.mak

ALL_CPPFLAGS += -I../include -I../boot \
	    -DZFCPDUMP_DIR=$(ZFCPDUMP_DIR) \
	    -DZFCPDUMP_FS_IMAGE=$(ZFCPDUMP_FS_IMAGE) \
	    -DZFCPDUMP_FS_RD=$(ZFCPDUMP_FS_RD) \
	    -DZFCPDUMP_PART_IMAGE=$(ZFCPDUMP_PART_IMAGE) \
	    -DZFCPDUMP_PART_RD=$(ZFCPDUMP_PART_RD) \
	    -D_FILE_OFFSET_BITS=64
ALL_LDFLAGS += -Wl,-z,noexecstack

libs =	$(rootdir)/libutil/libutil.a \
	$(rootdir)/libu2s/libu2s.a

objects = misc.o error.o scan.o job.o boot.o bootmap.o disk.o \
	  install.o zipl.o $(rootdir)/zipl/boot/data.o

zipl_helpers = $(wildcard zipl_helper.*)
chreipl_helpers = $(subst zipl_,chreipl_, $(zipl_helpers))

all: zipl $(chreipl_helpers)

zipl: $(objects) $(libs)

chreipl_helper.%: zipl_helper.%
	ln -s $< $@

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -c zipl $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 $(zipl_helpers) $(chreipl_helpers) \
		$(DESTDIR)$(TOOLS_LIBDIR)
	$(CP) --no-dereference $(chreipl_helpers) $(DESTDIR)$(TOOLS_LIBDIR)

clean:
	rm -f *.o $(chreipl_helpers) zipl

.PHONY: all install clean

# Additional manual dependencies

../boot/data.h:
	make -C ../boot data.h

../boot/data.o:
	make -C ../boot data.o

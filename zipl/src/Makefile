# Common definitions
include ../../common.mak

ALL_CPPFLAGS += -I../include -I../boot \
	    -DZFCPDUMP_IMAGE="STRINGIFY($(ZFCPDUMP_DIR)/$(ZFCPDUMP_IMAGE))" \
	    -DZFCPDUMP_INITRD="STRINGIFY($(ZFCPDUMP_DIR)/$(ZFCPDUMP_INITRD))" \
	    -D_FILE_OFFSET_BITS=64 -DBUILD_PATH="../boot"

libs =  $(rootdir)/libutil/libutil.a \
	$(rootdir)/libvtoc/libvtoc.a \

objects = misc.o error.o scan.o job.o boot.o bootmap.o fs-map.o disk.o \
	  bootmap_header.o envblk.o install.o zipl.o

zipl_helpers = $(basename $(wildcard zipl_helper.*.c))
zipl_helpers += zipl_helper.md
chreipl_helpers = $(subst zipl_,chreipl_, $(zipl_helpers))

all: zipl zipl-editenv zipl_helper.md $(chreipl_helpers)

boot.o: ../boot/.loaders
zipl: $(objects) $(libs)

zipl_helper.device-mapper: $(rootdir)/libdasd/libdasd.a \
	$(rootdir)/libvtoc/libvtoc.a \
	$(libs) misc.o error.o zipl_helper.device-mapper.o

zipl-editenv: $(libs) misc.o error.o fs-map.o bootmap_header.o \
	envblk.o zipl-editenv.o

zipl_helper.md: zipl_helper.device-mapper
	ln -f -s $< $@

chreipl_helper.%: zipl_helper.device-mapper
	ln -f -s $< $@

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -c zipl $(DESTDIR)$(BINDIR)
	$(INSTALL) -c zipl-editenv $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 zipl_helper.device-mapper $(DESTDIR)$(TOOLS_LIBDIR)
	ln -f -s zipl_helper.device-mapper $(DESTDIR)$(TOOLS_LIBDIR)/zipl_helper.md
	ln -f -s zipl_helper.device-mapper $(DESTDIR)$(TOOLS_LIBDIR)/chreipl_helper.md
	ln -f -s zipl_helper.device-mapper $(DESTDIR)$(TOOLS_LIBDIR)/chreipl_helper.device-mapper

clean:
	rm -f *.o $(zipl_helpers) $(chreipl_helpers) zipl zipl-editenv

.PHONY: all install clean

# Additional manual dependencies

../boot/.loaders:
	$(MAKE) -C ../boot .loaders

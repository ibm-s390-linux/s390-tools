#!/usr/bin/make -f

include ../common.mak

ifeq (${HAVE_FUSE},0)

all:
	$(SKIP) HAVE_FUSE=0

install:
	$(SKIP) HAVE_FUSE=0

else

check_dep:
	$(call check_dep, \
		"cmsfs-fuse", \
		"fuse.h", \
		"fuse3-devel or libfuse3-dev", \
		"HAVE_FUSE=0", \
		"-DFUSE_USE_VERSION=30")

all: check_dep cmsfs-fuse

ifneq ($(shell sh -c 'command -v pkg-config'),)
FUSE_CFLAGS = $(shell pkg-config --silence-errors --cflags fuse3)
FUSE_LDLIBS = $(shell pkg-config --silence-errors --libs fuse3)
else
FUSE_CFLAGS = -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse3
FUSE_LDLIBS = -lfuse3
endif
ALL_CFLAGS += -DHAVE_SETXATTR $(FUSE_CFLAGS)
LDLIBS += $(FUSE_LDLIBS) -lm

OBJECTS = cmsfs-fuse.o dasd.o amap.o config.o

CMSFS_FUSE_DIR = $(SYSCONFDIR)/cmsfs-fuse
CONFIG_FILES = filetypes.conf

libs = $(rootdir)/libutil/libutil.a

cmsfs-fuse: $(OBJECTS) $(libs)

install: all
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 cmsfs-fuse \
		$(DESTDIR)$(USRBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 cmsfs-fuse.1 \
		$(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -g $(GROUP) -o $(OWNER) -d $(DESTDIR)$(CMSFS_FUSE_DIR)
	for cnf in $(CONFIG_FILES); do \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 etc/$$cnf $(DESTDIR)$(CMSFS_FUSE_DIR) ; \
	done

endif

clean:
	rm -f cmsfs-fuse *.o

.PHONY: all install clean check_dep

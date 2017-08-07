include ../common.mak

libs =	$(rootdir)/libzds/libzds.a \
	$(rootdir)/libvtoc/libvtoc.a \
	$(rootdir)/libu2s/libu2s.a \
	$(rootdir)/libutil/libutil.a

ifeq (${HAVE_FUSE},0)

all:
	$(SKIP) HAVE_FUSE=0

install:
	$(SKIP) HAVE_FUSE=0

else

check_dep:
	$(call check_dep, \
		"zdsfs", \
		"fuse.h", \
		"fuse-devel or libfuse-dev", \
		"HAVE_FUSE=0")

ifneq ($(shell sh -c 'command -v pkg-config'),)
FUSE_CFLAGS = $(shell pkg-config --silence-errors --cflags fuse)
FUSE_LDLIBS = $(shell pkg-config --silence-errors --libs fuse)
else
FUSE_CFLAGS = -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse
FUSE_LDLIBS = -lfuse
endif
ALL_CPPFLAGS += -DSYSFS
ALL_CFLAGS += -DHAVE_SETXATTR -pthread $(FUSE_CFLAGS)
LDLIBS += $(FUSE_LDLIBS) -lpthread -lrt -lm

all: check_dep zdsfs

zdsfs: zdsfs.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR) $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zdsfs $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 zdsfs.1 \
		$(DESTDIR)$(MANDIR)/man1

endif

clean:
	rm -f *.o *~ zdsfs core

.PHONY: all install clean

include ../common.mak

libs =	$(rootdir)/libzds/libzds.a \
	$(rootdir)/libvtoc/libvtoc.a \
	$(rootdir)/libdasd/libdasd.a \
	$(rootdir)/libutil/libutil.a

ifeq (${HAVE_FUSE},0)

all:
	$(SKIP) HAVE_FUSE=0

install:
	$(SKIP) HAVE_FUSE=0


else

ifeq (${HAVE_CURL},0)

all:
	$(SKIP) HAVE_CURL=0

install:
	$(SKIP) HAVE_CURL=0

else

check_dep:
	$(call check_dep, \
		"zdsfs", \
		"fuse.h", \
		"fuse3-devel or libfuse3-dev", \
		"HAVE_FUSE=0", \
		"-DFUSE_USE_VERSION=30")
	$(call check_dep, \
		"zdsfs", \
		"curl/curl.h", \
		"curl-devel or libcurl-dev", \
		"HAVE_CURL=0")

FUSE_CFLAGS = $(shell $(PKG_CONFIG) --silence-errors --cflags fuse3)
FUSE_LDLIBS = $(shell $(PKG_CONFIG) --silence-errors --libs fuse3)
CURL_CFLAGS = $(shell $(PKG_CONFIG) --silence-errors --cflags libcurl)
CURL_LDLIBS = $(shell $(PKG_CONFIG) --silence-errors --libs libcurl)
ALL_CPPFLAGS += -DSYSFS
ALL_CFLAGS += -DHAVE_SETXATTR -pthread $(FUSE_CFLAGS) $(CURL_CFLAGS)
LDLIBS += $(FUSE_LDLIBS) $(CURL_LDLIBS) -lpthread -lrt -lm

all: check_dep zdsfs

zdsfs: zdsfs.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR) $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zdsfs $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 zdsfs.1 \
		$(DESTDIR)$(MANDIR)/man1

endif

endif

clean:
	rm -f *.o *~ zdsfs core

.PHONY: all install clean

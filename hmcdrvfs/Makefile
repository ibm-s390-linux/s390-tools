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
		"hmcdrvfs", \
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
ALL_CFLAGS += -DFUSE_USE_VERSION=26 -D_LARGEFILE_SOURCE $(FUSE_CFLAGS)
LDLIBS += $(FUSE_LDLIBS) -lpthread -lrt -ldl -lm

OBJECTS = hmcdrvfs.o


all: check_dep hmcdrvfs

$(OBJECTS): Makefile

hmcdrvfs: $(OBJECTS)

install: all install-scripts
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 hmcdrvfs \
		$(DESTDIR)$(USRBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 hmcdrvfs.1 \
		$(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 lshmc.8 \
		$(DESTDIR)$(MANDIR)/man8

install-scripts: lshmc
	@for i in $^; do \
		cat $$i | \
		sed -e 's+%S390_TOOLS_VERSION%+$(S390_TOOLS_RELEASE)+' \
		>$(DESTDIR)$(USRSBINDIR)/$$i; \
		chown $(OWNER).$(GROUP) $(DESTDIR)$(USRSBINDIR)/$$i; \
		chmod 755 $(DESTDIR)$(USRSBINDIR)/$$i; \
	done

endif

clean:
	rm -f hmcdrvfs *.o

.PHONY: all install install-scripts clean check_dep

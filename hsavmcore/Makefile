#
# Copyright IBM Corp. 2021
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

include ../common.mak

ALL_CPPFLAGS += -D_FILE_OFFSET_BITS=64

ifeq (${HAVE_FUSE},0)

all:
	$(SKIP) HAVE_FUSE=0

install:
	$(SKIP) HAVE_FUSE=0

else # HAVE_FUSE

#
# FUSE
#
ifneq ($(shell sh -c 'command -v pkg-config'),)
  FUSE_CFLAGS = $(shell pkg-config --silence-errors --cflags fuse)
  FUSE_LDLIBS = $(shell pkg-config --silence-errors --libs fuse)
else
  FUSE_CFLAGS = -I/usr/include/fuse
  FUSE_LDLIBS = -lfuse
endif

#
# systemd
#
ifneq (${HAVE_SYSTEMD},0)
  ifeq ($(call check_header_prereq,"systemd/sd-daemon.h"),yes)
    ifneq ($(shell sh -c 'command -v pkg-config'),)
      SYSTEMD_CFLAGS = $(shell pkg-config --silence-errors --cflags libsystemd)
      SYSTEMD_LDLIBS = $(shell pkg-config --silence-errors --libs libsystemd)
    else
      SYSTEMD_CFLAGS =
      SYSTEMD_LDLIBS = -lsystemd
    endif
    ALL_CPPFLAGS += -DHAVE_SYSTEMD
  else
    $(warning "systemd support disabled")
  endif
endif

ALL_CFLAGS += $(FUSE_CFLAGS) $(SYSTEMD_CFLAGS)
LDLIBS += $(FUSE_LDLIBS) $(SYSTEMD_LDLIBS) -lpthread

sources := $(wildcard *.c)
objects := $(patsubst %.c,%.o,$(sources))

libs = $(rootdir)/libutil/libutil.a

all: hsavmcore

hsavmcore: $(objects) $(libs)
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

overlay.o: check-dep-fuse overlay.c overlay.h

check-dep-fuse:
	$(call check_dep, \
		"hsavmcore", \
		"fuse.h", \
		"fuse-devel or libfuse-dev", \
		"HAVE_FUSE=0")
	touch check-dep-fuse

install: all
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 hsavmcore \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/hsavmcore.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/hsavmcore.conf.5 \
		$(DESTDIR)$(MANDIR)/man5

endif # HAVE_FUSE

clean:
	rm -f hsavmcore $(objects) check-dep-fuse

.PHONY: all install clean

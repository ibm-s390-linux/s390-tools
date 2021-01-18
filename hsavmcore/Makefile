#
# Copyright IBM Corp. 2021
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

include ../common.mak

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
ifneq ($(shell sh -c 'command -v pkg-config'),)
SYSTEMD_CFLAGS = $(shell pkg-config --silence-errors --cflags libsystemd)
SYSTEMD_LDLIBS = $(shell pkg-config --silence-errors --libs libsystemd)
else
SYSTEMD_CFLAGS =
SYSTEMD_LDLIBS = -lsystemd
endif
ALL_CPPFLAGS += -DHAVE_SYSTEMD
endif # HAVE_SYSTEMD

ALL_CPPFLAGS += -D_FILE_OFFSET_BITS=64
ALL_CFLAGS += $(FUSE_CFLAGS) $(SYSTEMD_CFLAGS)
LDLIBS += $(FUSE_LDLIBS) $(SYSTEMD_LDLIBS) -lpthread

OBJECTS = \
	main.o \
	cmdline_options.o \
	config.o \
	mount.o \
	swap.o \
	hsa.o \
	hsa_file.o \
	hsa_mem.o \
	proxy.o \
	overlay.o

libs = $(rootdir)/libutil/libutil.a

all: check_dep hsavmcore

check_dep:
	$(call check_dep, \
		"hsavmcore", \
		"fuse.h", \
		"fuse-devel or libfuse-dev", \
		"HAVE_FUSE=0")
ifneq (${HAVE_SYSTEMD},0)
	$(call check_dep, \
		"hsavmcore", \
		"systemd/sd-daemon.h", \
		"systemd-devel or libsystemd-dev", \
		"HAVE_SYSTEMD=0")
endif

hsavmcore: $(OBJECTS) $(libs)
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

install: all
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 hsavmcore \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/hsavmcore.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/hsavmcore.conf.5 \
		$(DESTDIR)$(MANDIR)/man5

endif # HAVE_FUSE

clean:
	rm -f hsavmcore $(OBJECTS)

.PHONY: all install clean

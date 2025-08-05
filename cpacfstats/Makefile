include ../common.mak

ifeq (${HAVE_LIBUDEV},0)

all:
	$(SKIP) HAVE_LIBUDEV=0

install:
	$(SKIP) HAVE_LIBUDEV=0

else

check_dep:
	$(call check_dep, \
		"cpacfstatsd", \
		"libudev.h", \
		"systemd-devel", \
		"HAVE_LIBUDEV=0")

ALL_CPPFLAGS += -DVERSION=$(VERSION)

all:		check_dep cpacfstats cpacfstatsd

cpacfstatsd:	cpacfstatsd.o stats_sock.o perf_crypto.o cpacfstats_common.o \
			$(rootdir)/libcpumf/libcpumf.a $(rootdir)/libutil/libutil.a
		$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -ludev -lpthread -o $@

cpacfstats:	cpacfstats.o stats_sock.o cpacfstats_common.o
		$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

install: 	all
		$(INSTALL) -m 755 cpacfstatsd   $(DESTDIR)$(USRSBINDIR)
		$(INSTALL) -m 755 cpacfstats    $(DESTDIR)$(USRBINDIR)
		$(INSTALL) -m 644 cpacfstatsd.8 $(DESTDIR)$(MANDIR)/man8
		$(INSTALL) -m 644 cpacfstats.1  $(DESTDIR)$(MANDIR)/man1

endif

clean:
		rm -f *.o *~ cpacfstatsd cpacfstats

.PHONY: all clean install check_dep

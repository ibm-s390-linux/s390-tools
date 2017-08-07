include ../common.mak

ALL_CPPFLAGS += -DVERSION=$(VERSION)


ifeq (${HAVE_PFM},0)

all:
	$(SKIP) HAVE_PFM=0

install:
	$(SKIP) HAVE_PFM=0

else

check_dep:
	$(call check_dep, \
			"cpacfstats", \
			"perfmon/pfmlib.h", \
			"libpfm-devel or libpfm4-dev", \
			"HAVE_PFM=0")

all:		check_dep cpacfstats cpacfstatsd

cpacfstatsd:	cpacfstatsd.o stats_sock.o perf_crypto.o
		$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -lpfm -o $@

cpacfstats:	cpacfstats.o stats_sock.o
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

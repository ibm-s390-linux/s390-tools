include ../common.mak

ALL_CPPFLAGS += -DVERSION=$(VERSION)

all:		cpacfstats cpacfstatsd

cpacfstatsd:	cpacfstatsd.o stats_sock.o perf_crypto.o
		$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

cpacfstats:	cpacfstats.o stats_sock.o
		$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

install: 	all
		$(INSTALL) -m 755 cpacfstatsd   $(DESTDIR)$(USRSBINDIR)
		$(INSTALL) -m 755 cpacfstats    $(DESTDIR)$(USRBINDIR)
		$(INSTALL) -m 644 cpacfstatsd.8 $(DESTDIR)$(MANDIR)/man8
		$(INSTALL) -m 644 cpacfstats.1  $(DESTDIR)$(MANDIR)/man1

clean:
		rm -f *.o *~ cpacfstatsd cpacfstats

.PHONY: all clean install check_dep

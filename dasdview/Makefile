include ../common.mak

libs =	$(rootdir)/libdasd/libdasd.a \
	$(rootdir)/libzds/libzds.a \
	$(rootdir)/libvtoc/libvtoc.a \
	$(rootdir)/libutil/libutil.a

ifneq (${HAVE_CURL},0)

check_dep:
	$(call check_dep, \
		"dasdview", \
		"curl/curl.h", \
		"curl-devel or libcurl-dev", \
		"HAVE_CURL=0")

BUILDTARGET = check_dep

CURL_CFLAGS = $(shell $(PKG_CONFIG) --silence-errors --cflags libcurl)
CURL_LDLIBS = $(shell $(PKG_CONFIG) --silence-errors --libs libcurl)

endif # HAVE_CURL

BUILDTARGET += dasdview

ALL_CPPFLAGS += -DSYSFS
ALL_CFLAGS += $(CURL_CFLAGS)
LDLIBS += $(CURL_LDLIBS)

all: $(BUILDTARGET)

dasdview: dasdview.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 dasdview $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 dasdview.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ dasdview core

.PHONY: all install clean

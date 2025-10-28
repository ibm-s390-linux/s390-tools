include ../common.mak

TESTS := tests/

libs =$(rootdir)/libzpci/libzpci.a $(rootdir)/libutil/libutil.a

ifneq (${HAVE_OPENSSL},0)
check_dep_openssl:
	$(call check_dep, \
		"opticsmon", \
		"openssl/evp.h", \
		"openssl-devel", \
		"HAVE_OPENSSL=0")
BUILDTARGET += check_dep_openssl
endif # HAVE_OPENSSL

ifneq (${HAVE_LIBNL3},0)
check_dep_libnl3:
	$(call check_dep, \
		"opticsmon", \
		"netlink/socket.h", \
		"libnl3-devel", \
		"HAVE_LIBNL3=0")
BUILDTARGET += check_dep_libnl3
endif # HAVE_LIBNL3

ifeq (${HAVE_OPENSSL},0)

all:
	$(SKIP) HAVE_OPENSSL=0

install:
	$(SKIP) HAVE_OPENSSL=0

else ifeq (${HAVE_LIBNL3},0)
all:
	$(SKIP) HAVE_LIBNL3=0

install:
	$(SKIP) HAVE_LIBNL3=0

else

ifneq ($(shell sh -c 'command -v pkg-config'),)
LIB_CFLAGS += $(shell $(PKG_CONFIG) --silence-errors --cflags libnl-3.0)
LIB_CFLAGS += $(shell $(PKG_CONFIG) --silence-errors --cflags libnl-genl-3.0)
LIB_CFLAGS += $(shell $(PKG_CONFIG) --silence-errors --cflags libnl-route-3.0)

LIB_CFLAGS += $(shell $(PKG_CONFIG) --silence-errors --cflags libcrypto)

LIB_LFLAGS += $(shell $(PKG_CONFIG) --silence-errors --libs libnl-3.0)
LIB_LFLAGS += $(shell $(PKG_CONFIG) --silence-errors --libs libnl-genl-3.0)
LIB_LFLAGS += $(shell $(PKG_CONFIG) --silence-errors --libs libnl-route-3.0)

LIB_LFLAGS += $(shell $(PKG_CONFIG) --silence-errors --libs libcrypto)
else
LIB_CFLAGS += -I /usr/include/libnl3/
LIB_LFLAGS += -lnl-route-3 -lnl-genl-3 -lnl-3

LIB_CFLAGS += -I /usr/include/openssl/
LIB_LFLAGS += -lcrypto
endif

ALL_CPPFLAGS += $(LIB_CFLAGS)
LDLIBS += $(LIB_LFLAGS)

BUILDTARGET += opticsmon

all: ${BUILDTARGET}

opticsmon: opticsmon.o optics_info.o optics_sclp.o ethtool.o link_mon.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 opticsmon $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 opticsmon.8 \
		$(DESTDIR)$(MANDIR)/man8
endif # HAVE_OPENSSL3=0 or HAVE_LIBNL3=0

clean:
	rm -f *.o *~ opticsmon core

.PHONY: all install clean

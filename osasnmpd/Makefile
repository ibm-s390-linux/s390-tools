include ../common.mak
LDLIBS = `net-snmp-config --agent-libs`
CFLAGS += `net-snmp-config --cflags`

OBJS = ibmOSAMib.o ibmOSAMibUtil.o osasnmpd.o

ifeq (${HAVE_SNMP},0)

all:
	$(SKIP) HAVE_SNMP=0

install:
	$(SKIP) HAVE_SNMP=0

else

check_dep:
	$(call check_dep, \
		"osasnmpd", \
		"net-snmp/net-snmp-config.h", \
		"net-snmp-devel or libsnmp-dev", \
		"HAVE_SNMP=0")

all: check_dep osasnmpd

osasnmpd: $(OBJS)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRSBINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 osasnmpd \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 osasnmpd.8 \
		$(DESTDIR)$(MANDIR)/man8

endif

clean:
	rm -f $(OBJS) osasnmpd core

.PHONY: all install clean

#==============================================================================
# Makefile for zSeries configuration utilities.
#==============================================================================
include ../common.mak

SCRIPTS	= lsdasd lstape chccwdev lszfcp cio_ignore znetconf dasdstat
USRSBIN_SCRIPTS = lsluns
MANPAGES= lsdasd.8 lstape.8 chccwdev.8 lszfcp.8 lsluns.8 \
	  cio_ignore.8 znetconf.8 dasdstat.8

SUB_DIRS = zcrypt scm chp css qeth

all: $(SUB_DIRS)

clean: $(SUB_DIRS)

install:	install-scripts install-manpages install-usrsbin-scripts $(SUB_DIRS)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 lsznet.raw \
		$(DESTDIR)$(TOOLS_LIBDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 znetcontrolunits \
		$(DESTDIR)$(TOOLS_LIBDIR)

install-scripts:	$(SCRIPTS)
	@for i in $^; do \
		cat $$i | \
		sed -e 's/%S390_TOOLS_VERSION%/$(S390_TOOLS_RELEASE)/' \
		>$(DESTDIR)$(BINDIR)/$$i; \
		chown $(OWNER):$(GROUP) $(DESTDIR)$(BINDIR)/$$i; \
		chmod 755 $(DESTDIR)$(BINDIR)/$$i; \
	done

install-usrsbin-scripts:	$(USRSBIN_SCRIPTS)
	@for i in $^; do \
		cat $$i | \
		sed -e 's/%S390_TOOLS_VERSION%/$(S390_TOOLS_RELEASE)/' \
		>$(DESTDIR)$(USRSBINDIR)/$$i; \
		chown $(OWNER):$(GROUP) $(DESTDIR)$(USRSBINDIR)/$$i; \
		chmod 755 $(DESTDIR)$(USRSBINDIR)/$$i; \
	done

install-manpages:	$(MANPAGES)
	@if [ ! -d $(DESTDIR)$(MANDIR) ]; then \
		mkdir -p $(DESTDIR)$(MANDIR)/man8; \
		chown $(OWNER):$(GROUP) $(DESTDIR)$(MANDIR); \
		chown $(OWNER):$(GROUP) $(DESTDIR)$(MANDIR)/man8; \
		chmod 755 $(DESTDIR)$(MANDIR); \
		chmod 755 $(DESTDIR)$(MANDIR)/man8; \
	fi; \
	for i in $^; do \
		install -o $(OWNER) -g $(GROUP) -m 644 $$i $(DESTDIR)$(MANDIR)/man8; \
	done

#
# For simple "make" we explicitly set the MAKECMDGOALS to "all".
#
ifeq ($(MAKECMDGOALS),)
MAKECMDGOALS = all
endif

$(SUB_DIRS):
	$(foreach goal,$(MAKECMDGOALS), \
		$(MAKE) -C $@ TOPDIR=$(TOPDIR) HOST_ARCH=$(HOST_ARCH) $(goal) ;)
.PHONY: $(SUB_DIRS)

.PHONY: all install clean install-scripts install-manpages install-usrsbin-scripts

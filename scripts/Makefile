include ../common.mak

SCRIPTS = dbginfo.sh zfcpdbf zipl-switch-to-blscfg sclpdbf
# Helper scripts controlled by corresponding systemd services
SD_HELPER_SCRIPTS = cpictl dumpconf
MAN_PAGES = dbginfo.sh.8 zfcpdbf.8 zipl-switch-to-blscfg.8

all:

install:
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	@for i in $(SCRIPTS); \
	do \
		cat $$i | \
		sed -e 's/%S390_TOOLS_VERSION%/$(S390_TOOLS_RELEASE)/' \
		>$(DESTDIR)$(BINDIR)/$$i; \
		chown $(OWNER):$(GROUP) $(DESTDIR)$(BINDIR)/$$i; \
		chmod 755 $(DESTDIR)$(BINDIR)/$$i; \
	done

	@for i in $(SD_HELPER_SCRIPTS); \
	do \
		cat $$i | \
		sed -e 's/%S390_TOOLS_VERSION%/$(S390_TOOLS_RELEASE)/' \
		>$(DESTDIR)$(TOOLS_LIBDIR)/$$i; \
		chown $(OWNER):$(GROUP) $(DESTDIR)$(TOOLS_LIBDIR)/$$i; \
		chmod 755 $(DESTDIR)$(TOOLS_LIBDIR)/$$i; \
	done

	@for i in $(MAN_PAGES); \
	do \
		$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 $$i \
		$(DESTDIR)$(MANDIR)/man8; \
	done

clean:

.zfcpdbf.ct: zfcpdbf
	$(PERLC) $(ALL_PERLCFLAGS) zfcpdbf 2>$(@);			\
	if [ "$${?}" -ne 0 ]; then					\
		cat "$(@)" >&2 && rm "$(@)";				\
	elif [ "$$(cat '$(@)' | wc -l)" -gt 1 ]; then			\
		cat "$(@)" >&2;						\
	elif [ " $(V)" = " 1" ]; then					\
		cat "$(@)";						\
	fi

.PHONY: .zfcpdbf.ct-clean
.zfcpdbf.ct-clean:
	rm -f .zfcpdbf.ct

all: .zfcpdbf.ct
clean: .zfcpdbf.ct-clean

.PHONY: all install clean

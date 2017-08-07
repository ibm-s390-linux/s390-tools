include ../common.mak

all: xcec-bridge

xcec-bridge: xcec-bridge.o

clean:
	rm -f *.o core xcec-bridge

install: ip_watcher.pl xcec-bridge start_hsnc.sh
	$(SED) -e 's+%S390_TOOLS_VERSION%+$(S390_TOOLS_RELEASE)+' \
	< start_hsnc.sh >$(DESTDIR)$(USRSBINDIR)/start_hsnc.sh; \
	chown $(OWNER).$(GROUP) $(DESTDIR)$(USRSBINDIR)/start_hsnc.sh; \
	chmod 755 $(DESTDIR)$(USRSBINDIR)/start_hsnc.sh; \
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 ip_watcher.pl \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 xcec-bridge \
		$(DESTDIR)$(USRSBINDIR)

.PHONY: all install clean

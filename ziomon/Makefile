include ../common.mak

ALL_CPPFLAGS += -DNDEBUG
ALL_CFLAGS   += -Wundef -Wstrict-prototypes -Wno-trigraphs
ALL_CXXFLAGS += -Wundef -Wno-trigraphs

TARGETS = ziomon_util ziomon_mgr ziomon_zfcpdd ziorep_utilization ziorep_traffic
all: $(TARGETS)

ziomon_mgr_main.o: ziomon_mgr.c
	$(CC) -DWITH_MAIN $(ALL_CFLAGS) $(ALL_CPPFLAGS) -c $< -o $@
ziomon_mgr: LDLIBS += -lm
ziomon_mgr: ziomon_dacc.o ziomon_util.o ziomon_mgr_main.o ziomon_tools.o \
	    ziomon_zfcpdd.o ziomon_msg_tools.o
	$(LINK) $(ALL_LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

ziomon_util_main.o: ziomon_util.c ziomon_util.h
	$(CC) -DWITH_MAIN $(ALL_CFLAGS) $(ALL_CPPFLAGS) -c $< -o $@
ziomon_util: LDLIBS += -lm
ziomon_util: ziomon_util_main.o ziomon_tools.o
	$(LINK) $(ALL_LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

ziomon_zfcpdd_main.o: ziomon_zfcpdd.c ziomon_zfcpdd.h
	$(CC) -DWITH_MAIN $(ALL_CFLAGS) $(ALL_CPPFLAGS) -c $< -o $@
ziomon_zfcpdd: LDLIBS += -lm -lrt -lpthread
ziomon_zfcpdd: ziomon_zfcpdd_main.o ziomon_tools.o
	$(LINK) $(ALL_LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

ziorep_traffic: ziorep_traffic.o ziorep_framer.o ziorep_frameset.o \
		ziorep_printers.o ziomon_dacc.o ziomon_util.o \
		ziomon_msg_tools.o ziomon_tools.o ziomon_zfcpdd.o \
		ziorep_cfgreader.o ziorep_collapser.o ziorep_utils.o \
		ziorep_filters.o
	$(LINKXX) $(ALL_LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

ziorep_utilization: ziorep_utilization.o ziorep_framer.o ziorep_frameset.o \
		    ziorep_printers.o ziomon_dacc.o ziomon_util.o \
		    ziomon_msg_tools.o ziomon_tools.o ziomon_zfcpdd.o \
		    ziorep_cfgreader.o ziorep_collapser.o ziorep_utils.o \
		    ziorep_filters.o
	$(LINKXX) $(ALL_LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

install: all
	$(SED) -e 's/%S390_TOOLS_VERSION%/$(S390_TOOLS_RELEASE)/' \
		< ziomon > $(DESTDIR)$(USRSBINDIR)/ziomon;
	chown $(OWNER).$(GROUP) $(DESTDIR)$(USRSBINDIR)/ziomon;
	chmod 755 $(DESTDIR)$(USRSBINDIR)/ziomon;
	$(SED) -e \
		's/%S390_TOOLS_VERSION%/$(S390_TOOLS_RELEASE)/' \
		< ziomon_fcpconf > $(DESTDIR)$(USRSBINDIR)/ziomon_fcpconf;
	chown $(OWNER).$(GROUP) $(DESTDIR)$(USRSBINDIR)/ziomon_fcpconf;
	chmod 755 $(DESTDIR)$(USRSBINDIR)/ziomon_fcpconf;
	$(SED) -e \
		's/%S390_TOOLS_VERSION%/$(S390_TOOLS_RELEASE)/' \
		< ziorep_config > $(DESTDIR)$(USRSBINDIR)/ziorep_config;
	chown $(OWNER).$(GROUP) $(DESTDIR)$(USRSBINDIR)/ziorep_config;
	chmod 755 $(DESTDIR)$(USRSBINDIR)/ziorep_config;
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 ziomon.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 ziomon_fcpconf.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 ziomon_util \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 ziomon_util.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 ziomon_mgr \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 ziomon_mgr.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 ziomon_zfcpdd \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 ziomon_zfcpdd.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 ziorep_config.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 ziorep_utilization \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 ziorep_utilization.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 ziorep_traffic \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 ziorep_traffic.8 \
		$(DESTDIR)$(MANDIR)/man8

uninstall:
	rm $(DESTDIR)$(USRSBINDIR)/ziomon
	rm $(DESTDIR)$(USRSBINDIR)/ziomon_util
	rm $(DESTDIR)$(USRSBINDIR)/ziomon_mgr
	rm $(DESTDIR)$(USRSBINDIR)/ziomon_zfcpdd
	rm $(DESTDIR)$(USRSBINDIR)/ziomon_fcpconf
	rm $(DESTDIR)$(USRSBINDIR)/ziorep_config
	rm $(DESTDIR)$(USRSBINDIR)/ziorep_utilization
	rm $(DESTDIR)$(USRSBINDIR)/ziorep_traffic
	rm $(DESTDIR)$(MANDIR)/man8/ziomon.8*
	rm $(DESTDIR)$(MANDIR)/man8/ziomon_util.8*
	rm $(DESTDIR)$(MANDIR)/man8/ziomon_mgr.8*
	rm $(DESTDIR)$(MANDIR)/man8/ziomon_zfcpdd.8*
	rm $(DESTDIR)$(MANDIR)/man8/ziomon_fcpconf.8*
	rm $(DESTDIR)$(MANDIR)/man8/ziorep_config.8*
	rm $(DESTDIR)$(MANDIR)/man8/ziorep_utilization.8*
	rm $(DESTDIR)$(MANDIR)/man8/ziorep_traffic.8*

clean:
	-rm -f *.o $(TARGETS)

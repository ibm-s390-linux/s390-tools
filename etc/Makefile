include ../common.mak

CONFIG_FILES =

ifneq (${SYSTEMDSYSTEMUNITDIR},)
CONFIG_FILES += cpuplugd.conf sysconfig/cpi sysconfig/dumpconf \
                sysconfig/mon_fsstatd sysconfig/mon_procd
endif

install:
	for file in $(CONFIG_FILES); do \
		$(INSTALL) -g $(GROUP) -o $(OWNER) \
			   -m 644 $$file $(DESTDIR)$(SYSCONFDIR)/$$file ; \
	done

.PHONY: all install clean

# Common definitions
include ../../common.mak

UDEVDIR := /usr/lib/udev/rules.d/
RULES := 81-dpm.rules

install:
	$(INSTALL) -m 755 -d $(DESTDIR)$(UDEVDIR)
	$(INSTALL) -m 644 $(RULES) $(DESTDIR)$(UDEVDIR)/

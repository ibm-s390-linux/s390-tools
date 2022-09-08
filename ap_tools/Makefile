include ../common.mak

MDEVCTL_DIR = /etc/mdevctl.d/
MDEVCTL_SCRIPTS = /etc/mdevctl.d/scripts.d/
MDEVCTL_CALLOUTS = /etc/mdevctl.d/scripts.d/callouts/

libs =	$(rootdir)/libap/libap.a \
	$(rootdir)/libutil/libutil.a

ifeq (${HAVE_JSONC},0)
all:
	$(SKIP) HAVE_JSONC=0

install:
	$(SKIP) HAVE_JSONC=0
else
LDLIBS += -ljson-c

all: ap-check

ap-check: ap-check.o $(libs)

install: all
	@if [ ! -d $(DESTDIR)$(MDEVCTL_CALLOUTS) ]; then \
		mkdir -p $(DESTDIR)$(MDEVCTL_CALLOUTS); \
		chown $(OWNER).$(GROUP) $(DESTDIR)$(MDEVCTL_DIR); \
		chown $(OWNER).$(GROUP) $(DESTDIR)$(MDEVCTL_SCRIPTS); \
		chown $(OWNER).$(GROUP) $(DESTDIR)$(MDEVCTL_CALLOUTS); \
		chmod 755 $(DESTDIR)$(MDEVCTL_DIR); \
		chmod 755 $(DESTDIR)$(MDEVCTL_SCRIPTS); \
		chmod 755 $(DESTDIR)$(MDEVCTL_CALLOUTS); \
	fi; \
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 ap-check \
		$(DESTDIR)$(MDEVCTL_CALLOUTS)
endif

clean:
	rm -f *.o *~ ap-check core

.PHONY: all install clean

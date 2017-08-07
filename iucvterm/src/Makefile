#! /usr/bin/make -f

include ../../common.mak

ifndef GETTEXT_TEXTDOMAIN
GETTEXT_TEXTDOMAIN = iucvterm
endif

ALL_CPPFLAGS += -I../include
ALL_CPPFLAGS += -DUSE_NLS -DGETTEXT_TEXTDOMAIN=\"$(GETTEXT_TEXTDOMAIN)\"
#ALL_CPPFLAGS += -D__DEBUG__

PROGRAMS = iucvconn iucvtty
SYSTOOLS = ttyrun

all: $(PROGRAMS) $(SYSTOOLS)
check:
install:
	for prg in $(PROGRAMS); do \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 $$prg $(DESTDIR)$(USRBINDIR) ; \
	done
	for prg in $(SYSTOOLS); do \
	  $(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 $$prg $(DESTDIR)$(BINDIR) ; \
	done

clean:
	-rm -f *.o $(PROGRAMS) $(SYSTOOLS)

iucvconn: iucvconn.o getopt.o auditlog.o functions.o

iucvtty: LDLIBS = -lutil
iucvtty: iucvtty.o getopt.o auditlog.o functions.o

ttyrun: GETTEXT_TEXTDOMAIN = ttyrun
ttyrun: ttyrun.o

.PHONY: install clean

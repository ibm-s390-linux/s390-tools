include ../common.mak

all: cpuplugd

LDLIBS += -lm

OBJECTS = daemon.o cpu.o info.o terms.o config.o main.o getopt.o mem.o

cpuplugd: $(OBJECTS)
	$(LINK) $(ALL_LDFLAGS) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f cpuplugd $(OBJECTS)

install: all
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 cpuplugd \
		$(DESTDIR)$(USRSBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/cpuplugd.8 \
		$(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/cpuplugd.conf.5 \
		$(DESTDIR)$(MANDIR)/man5

.PHONY: all install clean

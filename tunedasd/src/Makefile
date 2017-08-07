include ../../common.mak

ALL_CPPFLAGS += -I../include -I../boot

libs =	$(rootdir)/libdasd/libdasd.a \
	$(rootdir)/libu2s/libu2s.a \
	$(rootdir)/libutil/libutil.a

all: tunedasd


objects = tunedasd.o disk.o

tunedasd: $(objects) $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 tunedasd $(DESTDIR)$(BINDIR)

clean:
	rm -f *.o tunedasd

.PHONY: all install clean

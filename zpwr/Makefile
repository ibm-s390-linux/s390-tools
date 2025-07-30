#
# Copyright IBM Corp. 2025
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

include ../common.mak

all: zpwr

OBJECTS = zpwr.o
LDLIBS += -lm

zpwr: $(OBJECTS) $(rootdir)/libutil/libutil.a

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zpwr $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 man/zpwr.1 $(DESTDIR)$(MANDIR)/man1

clean:
	rm -f *.o *~ zpwr core

.PHONY: all install clean

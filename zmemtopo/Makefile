#
# Copyright IBM Corp. 2025
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
include ../common.mak

libs =	$(rootdir)/libutil/libutil.a

all: zmemtopo

zmemtopo: zmemtopo.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zmemtopo $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 zmemtopo.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ zmemtopo

.PHONY: all install clean


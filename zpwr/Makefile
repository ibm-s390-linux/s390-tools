#
# Copyright IBM Corp. 2025
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

include ../common.mak

all: zpwr

OBJECTS = zpwr.o

zpwr: $(OBJECTS) $(rootdir)/libutil/libutil.a -lm

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zpwr $(DESTDIR)$(USRBINDIR)

clean:
	rm -f *.o *~ zpwr core

.PHONY: all install clean

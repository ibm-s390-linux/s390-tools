# Common definitions
include ../common.mak

all:
	$(MAKE) -C boot
	$(MAKE) -C src

install: all
	$(MAKE) -C src install
	$(MAKE) -C man install

clean:
	$(MAKE) -C src clean
	$(MAKE) -C boot clean

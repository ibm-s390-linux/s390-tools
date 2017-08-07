# Common definitions
include ../common.mak

all:
	$(MAKE) -C src

install: all
	$(MAKE) -C src install
	$(MAKE) -C man install
	$(MAKE) -C dracut install

clean:
	$(MAKE) -C src clean

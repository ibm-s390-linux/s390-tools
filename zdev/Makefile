# Common definitions
include ../common.mak

all:
	$(MAKE) -C src

install: all
	$(MAKE) -C src install
	$(MAKE) -C man install
	$(MAKE) -C udev install
	$(MAKE) -C dracut install
	$(MAKE) -C initramfs install

clean:
	$(MAKE) -C src clean

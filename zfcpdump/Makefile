include ../common.mak

CPIOINIT  = $(call echocmd,"  CPIOINI ",/$@)./cpioinit
INSTALL_SCRIPTS = 10-zfcpdump.install

ALL_CFLAGS += -fno-sanitize=all
ALL_LDFLAGS += -fno-sanitize=all

ifeq (${HAVE_LIBC_STATIC},0)

all:
	$(SKIP) HAVE_LIBC_STATIC=0

install:
	$(SKIP) HAVE_LIBC_STATIC=0

else

check_dep:
	$(call check_dep, \
		"zfcpdump", \
		"stdio.h", \
		"glibc-static or libc-dev", \
		"HAVE_LIBC_STATIC=0", \
		"-static")

all: check_dep $(ZFCPDUMP_INITRD) scripts

cpioinit: cpioinit.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

zfcpdump_part: zfcpdump.o zfcpdump_part.o
	$(LINK) $(ALL_LDFLAGS) $^ -static -o $@
	$(STRIP) -s $@

$(ZFCPDUMP_INITRD): cpioinit zfcpdump_part
	$(CPIOINIT) zfcpdump_part > $@.tmp
	$(GZIP) -f $@.tmp
	$(MV) $@.tmp.gz $(ZFCPDUMP_INITRD)

scripts: $(INSTALL_SCRIPTS)
	chmod +x $(INSTALL_SCRIPTS)

install: all
	$(INSTALL) -m 611 $(ZFCPDUMP_INITRD) $(DESTDIR)$(ZFCPDUMP_DIR)

%: %.in
	zfcpdump_image=$(ZFCPDUMP_DIR)/$(ZFCPDUMP_IMAGE);	\
	$(SED)	-e "s#@zfcpdump_image@#$$zfcpdump_image#g"	\
		-e "s#@flavor@#$(ZFCPDUMP_FLAVOR)#g"		\
	< $< > $@
endif

clean:
	rm -f *.o *.gz *.tmp *~ zfcpdump_part cpioinit $(ZFCPDUMP_INITRD) \
		$(INSTALL_SCRIPTS)

.PHONY: all clean install check_dep scripts

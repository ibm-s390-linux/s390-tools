include ../common.mak

CPIOINIT  = $(call echocmd,"  CPIOINI ",/$@)./cpioinit

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

all: check_dep $(ZFCPDUMP_PART_RD)

cpioinit: cpioinit.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $^

zfcpdump_part: zfcpdump.o zfcpdump_part.o
	$(LINK) $(ALL_LDFLAGS) $^ -static -o $@
	$(STRIP) -s $@

$(ZFCPDUMP_PART_RD): cpioinit zfcpdump_part
	$(CPIOINIT) zfcpdump_part > $@.tmp
	$(GZIP) -f $@.tmp
	$(MV) $@.tmp.gz $(ZFCPDUMP_PART_RD)

install: all
	$(INSTALL) -m 611 $(ZFCPDUMP_PART_RD) $(DESTDIR)$(ZFCPDUMP_DIR)

endif

clean:
	rm -f *.o *.gz *.tmp *~ zfcpdump_part cpioinit $(ZFCPDUMP_PART_RD)

.PHONY: all clean install check_dep

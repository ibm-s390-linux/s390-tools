# Common definitions
include ../../common.mak

EMBEDDED_BOOTLOADERS := fba0.bin fba1b.bin fba2.bin \
	  eckd0_ldl.bin eckd0_cdl.bin \
	  eckd1.bin eckd1b.bin eckd2.bin \
	  tape0.bin \
	  eckd2dump_sv.bin tape2dump.bin fba2dump.bin eckd2dump_mv.bin
DEBUG_EMBEDDED_BOOTLOADERS := $(addsuffix .debug,$(EMBEDDED_BOOTLOADERS))
EXTERNAL_BOOTLOADERS := stage3.bin
DEBUG_EXTERNAL_BOOTLOADERS := $(addsuffix .debug,$(EXTERNAL_BOOTLOADERS))

.loaders: $(EMBEDDED_BOOTLOADERS) $(DEBUG_EMBEDDED_BOOTLOADERS)
	touch .loaders

.DEFAULT_GOAL := all
all: .loaders $(EXTERNAL_BOOTLOADERS) $(DEBUG_EXTERNAL_BOOTLOADERS)

clean:
	rm -f -- ./**/*.o *.o *.exec *.bin *.lds .*.lds.d .loaders *.debug

.PHONY: all clean

ifeq ($(HOST_ARCH),s390x)
INCLUDE_PATHS := $(rootdir)/zipl/include $(rootdir)/include
INCLUDE_PARMS := $(addprefix -I,$(INCLUDE_PATHS))

ALL_CFLAGS = $(NO_PIE_CFLAGS) -Os -g $(INCLUDE_PARMS) \
	  -DS390_TOOLS_RELEASE=$(S390_TOOLS_RELEASE) \
	  -fno-builtin -ffreestanding -fno-asynchronous-unwind-tables \
	  -fno-delete-null-pointer-checks -fno-stack-protector \
	  -fexec-charset=IBM1047 -m64 -mpacked-stack \
	  -mstack-size=4096 -mstack-guard=128 -msoft-float \
	  -W -Wall -Wformat-security -fno-sanitize=all -Wno-array-bounds
ALL_LDFLAGS += -fno-sanitize=all

# Prevent make from using some default rules...
%:	%.S

%.o:	%.S
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

%.o:	%.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

# Dependencies for the .lds generation
sources_lds_S = $(wildcard *.lds.S)
dependencies_lds_S = $(sources_lds_S:%.lds.S=.%.lds.d)
# Include all ".lds.d" dependency files for all make targets except for "clean"
ifneq ($(MAKECMDGOALS),clean)
-include $(dependencies_lds_S)
endif

%.lds: %.lds.S
	$(CPP) -Wp,-MD,.$@.d,-MT,$@ $(INCLUDE_PARMS) -P -C -o $@ $<

fba0.exec eckd0_ldl.exec eckd0_cdl.exec tape0.exec: \
	stage0.lds

eckd1.exec: \
	stage1.lds

eckd1b.exec fba1b.exec: \
	stage1b.lds

eckd2dump_sv.exec: \
	head.o stage2dump.o cio.o eckd2dump.o eckd2dump_sv.o eckd2dump_zlib.o \
	zlib/deflate.o zlib/deftree.o zlib/dfltcc.o zlib/dfltcc_deflate.o \
	libc.o ebcdic.o sclp.o entry.o eckd2dump_sv.lds
eckd2dump_mv.exec: \
	head.o stage2dump.o cio.o eckd2dump.o eckd2dump_mv.o \
	libc.o ebcdic.o sclp.o entry.o stage2.lds
fba2dump.exec: \
	head.o stage2dump.o cio.o fba2dump.o \
	libc.o ebcdic.o sclp.o entry.o stage2.lds
tape2dump.exec: \
	head.o stage2dump.o cio.o tape2dump.o \
	libc.o ebcdic.o sclp.o entry.o stage2.lds
eckd2.exec: head.o stage2.o cio.o eckd2.o libc.o ebcdic.o menu.o sclp.o \
	    kdump2.o kdump.o entry.o stage2.lds
fba2.exec: head.o stage2.o cio.o fba2.o libc.o ebcdic.o menu.o sclp.o \
	   kdump2.o kdump.o entry.o stage2.lds
stage3.exec: head.o stage3.o kdump3.o libc.o ebcdic.o ebcdic_conv.o sclp.o \
	     sclp_stage3.o kdump.o entry.o stage3.lds

%.exec:	%.o
	$(LINK) -Wl,-T,$(filter %.lds,$^) $(NO_PIE_LDFLAGS) $(NO_WARN_RWX_SEGMENTS_LDFLAGS) -Wl,--build-id=none -m64 -static -nostdlib $(filter %.o, $^) -o $@
	@chmod a-x $@

%.bin.debug: %.exec
	$(OBJCOPY) --only-keep-debug $< $@
	@chmod a-x $@

%.bin:	%.exec
	$(OBJCOPY) -O binary $< $@
	@chmod a-x $@

install: $(EXTERNAL_BOOTLOADERS)
	$(INSTALL) -d -m 755 "$(DESTDIR)$(TOOLS_LIBDIR)"
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 $(EXTERNAL_BOOTLOADERS) "$(DESTDIR)$(TOOLS_LIBDIR)"
else
# Don't generate the dependency files (see `common.mak` for the
# `-include $(dependencies_c)` statement).
.PHONY: $(dependencies_c)

$(EMBEDDED_BOOTLOADERS) $(DEBUG_EMBEDDED_BOOTLOADERS) $(EXTERNAL_BOOTLOADERS) $(DEBUG_EXTERNAL_BOOTLOADERS):
	echo "  SKIP    $@ due to HOST_ARCH != s390x"

install:
	echo "  SKIP    Bootloader installation due to HOST_ARCH != s390x"
endif

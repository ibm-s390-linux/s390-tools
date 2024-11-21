# Common definitions
include ../../../common.mak

FILES := stage3a.bin stage3b.bin stage3b_reloc.bin
DEBUG_FILES := $(addsuffix .debug,$(FILES))

ifeq ($(HOST_ARCH),s390x)
ZIPL_DIR := $(rootdir)/zipl
ZIPL_BOOT_DIR := $(ZIPL_DIR)/boot
PKGDATADIR := $(TOOLS_DATADIR)/pvimg

INCLUDE_PATHS := $(ZIPL_BOOT_DIR) $(ZIPL_DIR)/include $(rootdir)/include
INCLUDE_PARMS := $(addprefix -I,$(INCLUDE_PATHS))

ALL_CFLAGS := $(NO_PIE_CFLAGS) -Os -g \
	$(INCLUDE_PARMS) \
	-DENABLE_SCLP_ASCII=1 \
	-DS390_TOOLS_RELEASE=$(S390_TOOLS_RELEASE) \
	-fno-builtin -ffreestanding -fno-asynchronous-unwind-tables \
	-fno-delete-null-pointer-checks -fno-stack-protector \
	-fexec-charset=IBM1047 -m64 -mpacked-stack \
	-mstack-size=4096 -mstack-guard=128 -msoft-float \
	-Wall -Wformat-security -Wextra \
	-Wno-array-bounds

ZIPL_SRCS_C := libc.c ebcdic.c ebcdic_conv.c sclp.c
ZIPL_SRCS_ASM := entry.S

ZIPL_OBJS_C := $(ZIPL_SRCS_C:%.c=%.o)
ZIPL_OBJS_ASM := $(ZIPL_SRCS_ASM:%.S=%.o)
ZIPL_OBJS := $(ZIPL_OBJS_C) $(ZIPL_OBJS_ASM)

# Prevent make from using some default rules...
%:	%.S

%.o:	%.S Makefile
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

%.o:	%.c Makefile
	$(CC) $(ALL_CFLAGS) -c -o $@ $<


# Dependencies for the .lds generation
sources_lds_S = $(wildcard *.lds.S)
dependencies_lds_S = $(sources_lds_S:%.lds.S=.%.lds.d)
# Include all ".lds.d" dependency files for all make targets except for "clean"
ifneq ($(MAKECMDGOALS),clean)
-include $(dependencies_lds_S)
endif

%.lds:	%.lds.S Makefile
	$(CPP) -Wp,-MD,.$@.d,-MT,$@ $(INCLUDE_PARMS) -P -C -o $@ $<

# Special rules for zipl object files
$(ZIPL_OBJS_C): %.o : $(ZIPL_BOOT_DIR)/%.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

$(ZIPL_OBJS_ASM): %.o : $(ZIPL_BOOT_DIR)/%.S
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

dependencies_zipl_c := $(ZIPL_SRCS_C:%.c=.%.o.d)

$(dependencies_zipl_c): .%.o.d : $(ZIPL_BOOT_DIR)/%.c
	$(CC_SILENT) -MM $(ALL_CPPFLAGS) $(ALL_CFLAGS) $< > $@

ifneq ($(MAKECMDGOALS),clean)
-include $(dependencies_zipl_c)
endif

stage3b_reloc.o: stage3b.bin

stage3a.elf: head.o stage3a_init.o $(ZIPL_OBJS)
stage3b.elf: head.o $(ZIPL_OBJS)

.SECONDARY: $(FILES:.bin=.lds)
%.elf: %.lds %.o
	$(LINK) $(NO_PIE_LDFLAGS) $(NO_WARN_RWX_SEGMENTS_LDFLAGS) -Wl,-T,$< -Wl,--build-id=none -m64 -static -nostdlib $(filter %.o, $^) -o $@
	@chmod a-x $@

%.bin.debug: %.elf
	$(OBJCOPY) --only-keep-debug $< $@
	@chmod a-x $@

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
	@chmod a-x $@

install: stage3a.bin stage3b_reloc.bin
	$(INSTALL) -d -m 755 $(DESTDIR)$(PKGDATADIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 stage3a.bin $(DESTDIR)$(PKGDATADIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 stage3b_reloc.bin $(DESTDIR)$(PKGDATADIR)

else
# Don't generate the dependency files (see `common.mak` for the
# `-include $(dependencies_c)` statement).
.PHONY: $(dependencies_c)

$(FILES) $(DEBUG_FILES):
	echo "  SKIP    $@ due to HOST_ARCH != s390x"

install:
	echo "  SKIP    Bootloader installation due to HOST_ARCH != s390x"
endif

.DEFAULT_GOAL := all
all: $(FILES) $(DEBUG_FILES)

clean:
	rm -f -- *.o *.elf *.bin *.map .*.d *.lds *.debug

.PHONY: all clean

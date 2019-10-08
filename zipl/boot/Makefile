# Common definitions
include ../../common.mak

ALL_CFLAGS = $(NO_PIE_CFLAGS) -Os -g -I $(rootdir)/zipl/include \
	   -I $(rootdir)/include -DS390_TOOLS_RELEASE=$(S390_TOOLS_RELEASE) \
	  -fno-builtin -ffreestanding -fno-asynchronous-unwind-tables \
	  -fno-delete-null-pointer-checks \
	  -fexec-charset=IBM1047 -m64 -mpacked-stack \
	  -mstack-size=4096 -mstack-guard=128 -msoft-float \
	  -W -Wall -Wformat-security

FILES	= fba0.bin fba1b.bin fba2.bin \
	  eckd0_ldl.bin eckd0_cdl.bin \
	  eckd1.bin eckd1b.bin eckd2.bin \
	  tape0.bin \
	  eckd2dump_sv.bin tape2dump.bin fba2dump.bin eckd2dump_mv.bin

all: data.o data.h tape0.bin stage3.bin

# Prevent make from using some default rules...
%:	%.S

%.o:	%.S
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

%.o:	%.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

eckd2dump_sv.exec: \
	head.o stage2dump.o cio.o eckd2dump.o eckd2dump_sv.o \
	libc.o sclp.o entry.o
eckd2dump_mv.exec: \
	head.o stage2dump.o cio.o eckd2dump.o eckd2dump_mv.o \
	libc.o sclp.o entry.o
fba2dump.exec: \
	head.o stage2dump.o cio.o fba2dump.o \
	libc.o sclp.o entry.o
tape2dump.exec: \
	head.o stage2dump.o cio.o tape2dump.o \
	libc.o sclp.o entry.o
eckd2.exec: head.o stage2.o cio.o eckd2.o libc.o menu.o sclp.o \
	    kdump2.o kdump.o entry.o
fba2.exec: head.o stage2.o cio.o fba2.o libc.o menu.o sclp.o \
	   kdump2.o kdump.o entry.o
stage3.exec: head.o stage3.o kdump3.o libc.o sclp.o sclp_stage3.o \
	     kdump.o entry.o stage3.lds

%.exec:	%.o
	STAGE=$$( \
		echo $@ | awk ' \
			match($$0,/[0-9]+b*/){ \
				print substr($$0,RSTART,RLENGTH) \
			}' \
	); \
	case $$STAGE in \
		0) SFLAGS="$(NO_PIE_LINKFLAGS) -nostdlib -Wl,-Ttext,0";; \
		1) SFLAGS="$(NO_PIE_LINKFLAGS) -nostdlib -Wl,-Ttext,0x18";; \
		1b) SFLAGS="$(NO_PIE_LINKFLAGS) -nostdlib -Wl,-Ttext,0xE000";; \
		2) SFLAGS="$(NO_PIE_LINKFLAGS) -nostdlib -Wl,-T,stage2.lds";; \
		3) SFLAGS="$(NO_PIE_LINKFLAGS) -nostdlib -Wl,-T,stage3.lds";; \
	esac; \
	$(LINK) $$SFLAGS -m64 $(filter %.o, $^) -o $@

%.bin:	%.exec
	$(OBJCOPY) -O binary \
		--only-section=.stage2.head \
		--only-section=.text.dummy \
		--only-section=.text.start \
		--only-section=.text \
		--only-section=.ex_table \
		--only-section=.data \
		--only-section=.rodata.str1.2 \
		--only-section=.rodata.cst8 \
		--only-section=.rodata \
		--only-section=.stage2dump.tail \
		--only-section=.eckd2dump_mv.tail \
		--only-section=.fixup \
		$< $@

stage3.bin:	stage3.exec
	$(OBJCOPY) -O binary \
		--only-section=.stage2.head \
		--only-section=.text.dummy \
		--only-section=.text.start \
		--only-section=.text \
		--only-section=.ex_table \
		--only-section=.data \
		--only-section=.rodata.str1.2 \
		--only-section=.rodata.cst8 \
		--only-section=.rodata \
		--only-section=.stage2dump.tail \
		--only-section=.eckd2dump_mv.tail \
		--only-section=.fixup \
		--pad-to=0xe000 \
		$< $@

data.o: $(FILES)
	$(LD) $(NO_PIE_LDFLAGS) -r -b binary -o data.o $(FILES)

data.h: data.o
	rm -f data.h
	$(NM) data.o | while read ADDR TYPE SYMBOL ; do \
				echo "extern char $$SYMBOL;" >>data.h; done

clean:
	rm -f *.o *.exec *.bin $(FILES) data.o data.h tape0.bin *.xxx *.yyy \
	      stage3.bin

.PHONY: all clean

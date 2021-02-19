ifndef $(COMMON_INCLUDED)
COMMON_INCLUDED = true

# Global definitions
# The variable "DISTRELEASE" should be overwritten in rpm spec files with:
# "make DISTRELEASE=%{release}" and "make install DISTRELEASE=%{release}"
VERSION            = 2
RELEASE            = 16
PATCHLEVEL         = 0
DISTRELEASE        = build-$(shell date +%Y%m%d)
S390_TOOLS_RELEASE = $(VERSION).$(RELEASE).$(PATCHLEVEL)-$(DISTRELEASE)
export S390_TOOLS_RELEASE

reldir = $(subst $(shell cd -P $(dir $(filter %common.mak,$(MAKEFILE_LIST))); \
	 pwd)/,,$(CURDIR))
rootdir= $(dir $(filter %common.mak,$(MAKEFILE_LIST)))
export S390_TEST_LIB_PATH=$(rootdir)/s390-tools-testsuite/lib

#
# For cross compiles specify CROSS_COMPILE= on the commandline:
#
# $ make CROSS_COMPILE="s390x-5.1.0-"
#

CROSS_COMPILE   =

#
# Commands can be overwritten on the command line with "make <VAR>=<VALUE>":
#
#  $ make CC=gcc-4.8
#
# The "cmd_define" macro wraps the command definition so that the commands
# can be user supplied and are still pretty-printed for the build process.
#
# The macro is called with the following parameters:
#
#  $(1) - Used command variable in the Makefiles
#  $(2) - Pretty Print output for the command
#  $(3) - Default command if not user-specified
#
# The Example below...
#
#  $(eval $(call cmd_define,     CC,"  CC      ",$(CROSS_COMPILE)gcc))
#
# ... produces the following code:
#
#  CC              = $(CROSS_COMPILE)gcc
#  CC_SILENT      := $(CC)
#  override CC     = $(call echocmd,"  CC      ",/$@)$(CC_SILENT)
#
# The "strip" make function is used for the first parameter to allow blanks,
# which improves readability.
#

define cmd_define
	$(strip $(1))		 = $(3)
	$(strip $(1))_SILENT	:= $$($(strip $(1)))
	override $(strip $(1))	 = $$(call echocmd,$(2),/$$@)$$($(strip $(1))_SILENT)
endef

$(eval $(call cmd_define,     AS,"  AS      ",$(CROSS_COMPILE)as))
$(eval $(call cmd_define,   LINK,"  LINK    ",$(CROSS_COMPILE)gcc))
$(eval $(call cmd_define,     LD,"  LD      ",$(CROSS_COMPILE)ld))
$(eval $(call cmd_define,     CC,"  CC      ",$(CROSS_COMPILE)gcc))
$(eval $(call cmd_define, HOSTCC,"  HOSTCC  ",gcc))
$(eval $(call cmd_define, LINKXX,"  LINKXX  ",$(CROSS_COMPILE)g++))
$(eval $(call cmd_define,    CXX,"  CXX     ",$(CROSS_COMPILE)g++))
$(eval $(call cmd_define,    CPP,"  CPP     ",$(CROSS_COMPILE)gcc -E))
$(eval $(call cmd_define,     AR,"  AR      ",$(CROSS_COMPILE)ar))
$(eval $(call cmd_define,     NM,"  NM      ",$(CROSS_COMPILE)nm))
$(eval $(call cmd_define,  STRIP,"  STRIP   ",$(CROSS_COMPILE)strip))
$(eval $(call cmd_define,OBJCOPY,"  OBJCOPY ",$(CROSS_COMPILE)objcopy))
$(eval $(call cmd_define,OBJDUMP,"  OBJDUMP ",$(CROSS_COMPILE)objdump))
$(eval $(call cmd_define,RUNTEST,"  RUNTEST ",$(S390_TEST_LIB_PATH)/s390_runtest))
$(eval $(call cmd_define,    CAT,"  CAT     ",cat))
$(eval $(call cmd_define,    SED,"  SED     ",sed))
$(eval $(call cmd_define,   GZIP,"  GZIP    ",gzip))
$(eval $(call cmd_define,     MV,"  MV      ",mv))

CHECK           = sparse
CHECK_SILENT   := $(CHECK)
CHECKTOOL       = $(call echocmd,"  CHECK   ",/$@)$(CHECK_SILENT)

SKIP            = echo           "  SKIP    $(call reldir) due to"

INSTALL         = install
CP              = cp
ifneq ("${V}","1")
	MAKEFLAGS += --quiet
	echocmd=echo $1$(call reldir)$2;
	RUNTEST += > /dev/null 2>&1
else
	echocmd=
endif
ifeq ("${W}","1")
	DEFAULT_CFLAGS = -g -rdynamic -fstack-protector-all -W -Wall -Wformat-security -Wextra
else
	DEFAULT_CFLAGS = -g -rdynamic -fstack-protector-all -W -Wall -Wformat-security
endif
ifeq ("${D}","1")
	DEFAULT_CFLAGS += -Og
else
	DEFAULT_CFLAGS += -O3
endif

DEFAULT_CPPFLAGS = -D_GNU_SOURCE
DEFAULT_LDFLAGS = -rdynamic

ifeq ("${ASAN}","1")
	DEFAULT_CFLAGS  += -fsanitize=address -fno-omit-frame-pointer
	DEFAULT_LDFLAGS += -fsanitize=address
endif

#
# Check for build dependency
#
# $1: Name of tool or feature that requires dependency
# $2: Name of include file to check
# $3: Name of required devel package
# $4: Option to skip build (e.g. HAVE_FUSE=0)
# $5: Additional compiler & linker options (optional)
#
check_dep=\
printf "\#include <%s>\n int main(void) {return 0;}" $2 | ( $(CC) $(filter-out --coverage, $(ALL_CFLAGS)) $(ALL_CPPFLAGS) $5 -o /dev/null -xc - ) > /dev/null 2>&1; \
if [ $$? != 0 ]; \
then \
	printf "  REQCHK  %s (%s)\n" $1 $2; \
	printf "********************************************************************************\n" >&2; \
	printf "* Missing build requirement for: %-45s *\n" $1 >&2; \
	printf "* Install package..............: %-45s *\n" $3 >&2; \
	printf "* You can skip build with......: make %-40s *\n" $4 >&2; \
	printf "********************************************************************************\n" >&2; \
	exit 1; \
fi

#
# Support alternate install root
#
# INSTALLDIR: Finally install s390-tools to INSTALLDIR. This can be used
#             for testing locally installed tools.
# DESTDIR:    Temporary install s390-tools to this directory. This can be
#             used for building s390-tools e.g. with rpmbuild.
#
# The difference between INSTALLDIR and DESTDIR is that for INSTALLDIR
# internally used directories (e.g. for config files) are adjusted.
#
# Example:
#
#  $ cd cpumf
#  $ INSTALLDIR=/tmp make install
#  $ cat /tmp/lib/s390-tools/cpumf_helper | grep DATA_DIR
#    my $CPUMF_DATA_DIR = '/tmp/usr/share/s390-tools/cpumf';
#
#  $ make clean
#  $ DESTDIR=/tmp make install
#  $ cat /tmp/lib/s390-tools/cpumf_helper | grep DATA_DIR
#    my $CPUMF_DATA_DIR = '/usr/share/s390-tools/cpumf';
#

ifdef INSTROOT
$(error INSTROOT is no longer available, use DESTDIR instead)
endif

INSTALLDIR     ?=
DESTDIR        ?=

USRSBINDIR      = $(INSTALLDIR)/usr/sbin
USRBINDIR       = $(INSTALLDIR)/usr/bin
BINDIR          = $(INSTALLDIR)/sbin
LIBDIR          = $(INSTALLDIR)/lib
USRLIB64DIR     = $(INSTALLDIR)/usr/lib64
SYSCONFDIR      = $(INSTALLDIR)/etc
MANDIR          = $(INSTALLDIR)/usr/share/man
VARDIR          = $(INSTALLDIR)/var
TOOLS_DATADIR   = $(INSTALLDIR)/usr/share/s390-tools
TOOLS_LIBDIR    = $(INSTALLDIR)/lib/s390-tools
ZFCPDUMP_DIR    = $(TOOLS_LIBDIR)/zfcpdump
# Systemd support files are installed only if a directory is specified
# for SYSTEMDSYSTEMUNITDIR (e.g. /lib/systemd/system)
SYSTEMDSYSTEMUNITDIR =
USRINCLUDEDIR   = $(INSTALLDIR)/usr/include
ZKEYKMSPLUGINDIR = $(USRLIB64DIR)/zkey

ifeq ($(LIBDIR),$(INSTALLDIR)/lib)
SOINSTALLDIR = $(USRLIB64DIR)
else
SOINSTALLDIR = $(LIBDIR)
endif

INSTDIRS        = $(USRSBINDIR) $(USRBINDIR) $(BINDIR) $(LIBDIR) $(MANDIR) \
			$(SYSCONFDIR) $(SYSCONFDIR)/sysconfig \
			$(TOOLS_LIBDIR) $(TOOLS_DATADIR) \
			$(ZFCPDUMP_DIR) $(SYSTEMDSYSTEMUNITDIR) \
			$(USRLIB64DIR) $(USRINCLUDEDIR) $(ZKEYKMSPLUGINDIR) \
			$(SOINSTALLDIR)
OWNER           = $(shell id -un)
GROUP		= $(shell id -gn)
export INSTALLDIR BINDIR LIBDIR USRLIB64DIR MANDIR OWNER GROUP

# Special defines for zfcpdump
ZFCPDUMP_IMAGE	= zfcpdump-image
ZFCPDUMP_INITRD	= zfcpdump-initrd
ZFCPDUMP_FLAVOR	= zfcpdump
export ZFCPDUMP_DIR ZFCPDUMP_IMAGE ZFCPDUMP_INITRD ZFCPDUMP_FLAVOR

CFLAGS		?= $(DEFAULT_CFLAGS) $(OPT_FLAGS)
HOSTCFLAGS	?= $(DEFAULT_CFLAGS) $(OPT_FLAGS)
CPPFLAGS	?= $(DEFAULT_CPPFLAGS)
LDFLAGS		?= $(DEFAULT_LDFLAGS)

ALL_CFLAGS	= -DS390_TOOLS_RELEASE=$(S390_TOOLS_RELEASE) \
			-DS390_TOOLS_LIBDIR=$(TOOLS_LIBDIR) \
			-DS390_TOOLS_DATADIR=$(TOOLS_DATADIR) \
			-DS390_TOOLS_SYSCONFDIR=$(SYSCONFDIR) \
			-DS390_TOOLS_BINDIR=$(BINDIR) \
			$(CFLAGS)
CXXFLAGS	?= $(DEFAULT_CFLAGS) $(OPT_FLAGS)
ALL_CXXFLAGS	= -DS390_TOOLS_RELEASE=$(S390_TOOLS_RELEASE) \
			-DS390_TOOLS_LIBDIR=$(TOOLS_LIBDIR) \
			-DS390_TOOLS_DATADIR=$(TOOLS_DATADIR) \
			-DS390_TOOLS_SYSCONFDIR=$(SYSCONFDIR) \
			-DS390_TOOLS_BINDIR=$(BINDIR) \
			$(CXXFLAGS)
ALL_CPPFLAGS	= -I $(rootdir)include $(CPPFLAGS)
ALL_LDFLAGS	= $(LDFLAGS)

# make G=1
# Compile tools so that gcov can be used to collect code coverage data.
# See the gcov man page for details.
ifeq ("${G}","1")
ALL_CFLAGS := $(filter-out -O%,$(ALL_CFLAGS)) --coverage
ALL_CXXFLAGS := $(filter-out -O%,$(ALL_CXXFLAGS)) --coverage
ALL_LDFLAGS += --coverage
endif
export AS LD CC CPP AR NM STRIP OBJCOPY OBJDUMP INSTALL CFLAGS CXXFLAGS \
       LDFLAGS CPPFLAGS ALL_CFLAGS ALL_CXXFLAGS ALL_LDFLAGS ALL_CPPFLAGS

ifneq ($(shell $(CC_SILENT) -dumpspecs 2>/dev/null | grep -e '[^f]no-pie'),)
	NO_PIE_CFLAGS := -fno-pie
	NO_PIE_LINKFLAGS := -no-pie
	NO_PIE_LDFLAGS := -no-pie
else
	NO_PIE_CFLAGS :=
	NO_PIE_LINKFLAGS :=
	NO_PIE_LDFLAGS :=
endif

# Overwrite implicite makefile rules for having nice compile output
%.o: %.c
ifeq ("${C}","1")
	$(CHECKTOOL) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -c $< -o $@
endif
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(ALL_CPPFLAGS) $(ALL_CXXFLAGS) -c $< -o $@

%: %.o
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

%.a:
	$(AR) rcs $@ $^

all:

help:
	@echo 'Usage: make [TARGETS] [OPTIONS]'
	@echo ''
	@echo 'TARGETS'
	@echo '  all      Build all tools (default target)'
	@echo '  install  Install tools'
	@echo '  clean    Delete all generated files'
	@echo ''
	@echo 'OPTIONS'
	@echo '  D=1      Build with debugging option "-Og"'
	@echo '  C=1      Build with check tool defined with "CHECK=" (default=sparse)'
	@echo '  G=1      Build with gcov to collect code coverage data'
	@echo '  V=1      Generate verbose build output'
	@echo '  W=1      Build with higher warning level'
	@echo '  ASAN=1   Build with address sanitizer'
	@echo ''
	@echo 'EXAMPLES'
	@echo '  # make clean all D=1 W=1 -j'
	@echo '  # make C=1 CHECK=smatch'
.PHONY: help

# Automatic dependency generation
#
# Create ".o.d" dependency files with the -MM compile option for all ".c" and
# ".cpp" files in the directory of the Makefile that includes common.mak:
#
#  $ gcc -MM vmcp.c
#  vmcp.o: vmcp.c vmcp.h ../include/zt_common.h
#
# Use -MM instead of -M to *not* mention system header files. We expect
# "make clean all" in case of system header updates.

# We consider header files in three possible directories
sources_h = \
	$(wildcard *.h) \
	$(wildcard ../include/*.h) \
	$(wildcard $(rootdir)/include/lib/*.h)

# Rules to create ".o.d" files out of ".c" or ".cpp" files:

.%.o.d: %.c $(sources_h)
	$(CC_SILENT) -MM $(ALL_CPPFLAGS) $(ALL_CFLAGS) $< > $@
.%.o.d: %.cpp $(sources_h)
	$(CXX_SILENT) -MM $(ALL_CPPFLAGS) $(ALL_CXXFLAGS) $< > $@
# The sources_c/cpp variable contains a list of all ".c" or ".cpp" files in
# in the current directory.
sources_c = $(wildcard *.c)
sources_cpp = $(wildcard *.cpp)
# The dependencies_c/cpp variable contains a list of all ".o.d" files,
# one for each ".c" or ".cpp" file.
dependencies_c = $(sources_c:%.c=.%.o.d)
dependencies_cpp = $(sources_cpp:%.cpp=.%.o.d)
# Include all ".o.d" dependency files for all make targets except for "clean"
ifneq ($(MAKECMDGOALS),clean)
-include $(dependencies_c)
-include $(dependencies_cpp)
endif

# Rules for internal libraries needed to ensure that these files are build
# with their own build flags even if they are build from external directories.
#
# Because of the PHONY directory dependency all tools that use libraries
# check the library directory via "make -C" when the tools Makefile is
# processed.

$(rootdir)/libutil/libutil.a: $(rootdir)/libutil
	$(MAKE) -C $(rootdir)/libutil/ libutil.a
.PHONY: $(rootdir)/libutil

$(rootdir)/libccw/libccw.a: $(rootdir)/libccw
	$(MAKE) -C $(rootdir)/libccw/ libccw.a
.PHONY: $(rootdir)/libccw

$(rootdir)/libvtoc/libvtoc.a: $(rootdir)/libvtoc
	$(MAKE) -C $(rootdir)/libvtoc/ libvtoc.a
.PHONY: $(rootdir)/libvtoc

$(rootdir)/libdasd/libdasd.a: $(rootdir)/libdasd
	$(MAKE) -C $(rootdir)/libdasd/ libdasd.a
.PHONY: $(rootdir)/libdasd

$(rootdir)/libzds/libzds.a: $(rootdir)/libzds
	$(MAKE) -C $(rootdir)/libzds/ libzds.a
.PHONY: $(rootdir)/libzds

$(rootdir)/libvmdump/libvmdump.a: $(rootdir)/libvmdump
	$(MAKE) -C $(rootdir)/libvmdump/ libvmdump.a
.PHONY: $(rootdir)/libvmdump

$(rootdir)/libvmcp/libvmcp.a: $(rootdir)/libvmcp
	$(MAKE) -C $(rootdir)/libvmcp/ libvmcp.a
.PHONY: $(rootdir)/libvmcp

$(rootdir)/libekmfweb/libekmfweb.so: $(rootdir)/libekmfweb
	$(MAKE) -C $(rootdir)/libekmfweb/ libekmfweb.so
.PHONY: $(rootdir)/libekmfweb

$(rootdir)/zipl/boot/data.o:
	$(MAKE) -C $(rootdir)/zipl/boot/ data.o

install_dirs:
	for dir in $(INSTDIRS); do \
		test -d $(DESTDIR)$$dir || $(INSTALL) -g $(GROUP) -o $(OWNER) -d $(DESTDIR)$$dir; \
	done
	for i in 1 2 3 4 5 6 7 8; do \
		test -d $(DESTDIR)$(MANDIR)/man$$i || $(INSTALL) -g $(GROUP) -o $(OWNER) \
		-d $(DESTDIR)$(MANDIR)/man$$i; \
	done

install_echo:
	$(call echocmd,"  INSTALL ")

install: install_echo install_dirs

clean_echo:
	$(call echocmd,"  CLEAN   ")
clean_gcov:
	rm -f -- *.gcda *.gcno *.gcov
clean_dep:
	rm -f -- .*.o.d

clean: clean_echo clean_gcov clean_dep
endif


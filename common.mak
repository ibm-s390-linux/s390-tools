COMMON_INCLUDED ?= false
V ?= 0
W ?= 0
G ?= 0
C ?= 0
D ?= 0
ASAN ?= 0
ENABLE_WERROR ?= 0
OPT_FLAGS ?=
MAKECMDGOALS ?=

ifeq ($(COMMON_INCLUDED),false)
COMMON_INCLUDED := true

# 'BUILD_ARCH' is the architecture of the machine where the build takes place
BUILD_ARCH := $(shell uname -m | sed -e 's/i.86/i386/' -e 's/sun4u/sparc64/' -e 's/arm.*/arm/' -e 's/sa110/arm/')
# 'HOST_ARCH' is the architecture of the machine that will run the compiled output
HOST_ARCH ?= $(BUILD_ARCH)

# The `*clean` targets are mutually exclusive to all other targets
ifneq ($(filter %clean,$(MAKECMDGOALS)),)
  ifneq ($(MAKECMDGOALS),$(filter %clean,$(MAKECMDGOALS)))
    $(error The *clean targets are mutually exclusive to all other targets)
  endif
endif

# Global definitions
# The variable "DISTRELEASE" should be overwritten in rpm spec files with:
# "make DISTRELEASE=%{release}" and "make install DISTRELEASE=%{release}"
VERSION            = 2
RELEASE            = 26
PATCHLEVEL         = 0
DISTRELEASE        = build-$(shell date +%Y%m%d)
S390_TOOLS_RELEASE = $(VERSION).$(RELEASE).$(PATCHLEVEL)-$(DISTRELEASE)
export S390_TOOLS_RELEASE

reldir = $(subst $(realpath $(dir $(filter %common.mak,$(MAKEFILE_LIST))))/,,$(CURDIR))
rootdir= $(dir $(filter %common.mak,$(MAKEFILE_LIST)))
export S390_TEST_LIB_PATH=$(rootdir)/s390-tools-testsuite/lib

#
# For cross compiles specify HOST_ARCH= and CROSS_COMPILE= on the commandline:
#
# $ make HOST_ARCH=s390x CROSS_COMPILE="s390x-linux-gnu-"
#

CROSS_COMPILE   =

#
# Commands can be overwritten on the command line with "make <VAR>=<VALUE>":
#
#  $ make CC=gcc-4.8
#
# The "cmd_define_and_export" macro wraps the command definition so that
# the commands can be user supplied and are still pretty-printed for the
# build process. In addition, the command variable gets exported so it
# can be used by sub-makes.
#
# The macro is called with the following parameters:
#
#  $(1) - Used command variable in the Makefiles
#  $(2) - Pretty Print output for the command
#  $(3) - Default command if not user-specified
#
# The Example below...
#
#  $(eval $(call cmd_define_and_export,     CC,"  CC      ",$(CROSS_COMPILE)gcc))
#
# ... produces the following code:
#
#  CC              = $(CROSS_COMPILE)gcc
#  CC_SILENT      := $(CC)
#  override CC     = $(call echocmd,"  CC      ",/$@)$(CC_SILENT)
#  export CC
#
# The "strip" make function is used for the first parameter to allow blanks,
# which improves readability.
#

define cmd_define
	$(strip $(1))		 = $(3)
	$(strip $(1))_SILENT	:= $$($(strip $(1)))
	override $(strip $(1))	 = $$(call echocmd,$(2),/$$@)$$($(strip $(1))_SILENT)
endef

define cmd_define_and_export
	$(call cmd_define,$(1),$(2),$(3))
	export $(strip $(1))
endef

define define_toolchain_variables
	$(eval $(call cmd_define_and_export,     AS$(1),"  AS$(1)       ",$(2)as))
	$(eval $(call cmd_define_and_export,     CC$(1),"  CC$(1)       ",$(2)gcc))
	$(eval $(call cmd_define_and_export,   LINK$(1),"  LINK$(1)     ",$$(CC$(1))))
	$(eval $(call cmd_define_and_export,    CXX$(1),"  CXX$(1)      ",$(2)g++))
	$(eval $(call cmd_define_and_export, LINKXX$(1),"  LINKXX$(1)   ",$$(CXX$(1))))
	$(eval $(call cmd_define_and_export,    CPP$(1),"  CPP$(1)      ",$(2)gcc -E))
	$(eval $(call cmd_define_and_export,     AR$(1),"  AR$(1)       ",$(2)ar))
	$(eval $(call cmd_define_and_export,     NM$(1),"  NM$(1)       ",$(2)nm))
	$(eval $(call cmd_define_and_export,   STRIP$(1),"  STRIP$(1)    ",$(2)strip))
	$(eval $(call cmd_define_and_export,OBJCOPY$(1),"  OBJCOPY$(1)  ",$(2)objcopy))
	$(eval $(call cmd_define_and_export,OBJDUMP$(1),"  OBJDUMP$(1)  ",$(2)objdump))
	$(eval PKG_CONFIG$(1) = pkg-config)
	$(eval export PKG_CONFIG$(1))
endef

# If the host architecture is not the same as the build architecture
# 'CROSS_COMPILE=...' is always required (except for the '*clean' targets).
ifneq ($(HOST_ARCH),$(BUILD_ARCH))
  ifeq ($(CROSS_COMPILE),)
    # `make clean` and similar must always work!
    ifeq ($(filter %clean,$(MAKECMDGOALS)),)
      $(error Please specify CROSS_COMPILE=... and try it again!)
    endif
  endif
endif

$(call define_toolchain_variables,_FOR_BUILD,)
$(call define_toolchain_variables,,$(CROSS_COMPILE))

$(eval $(call cmd_define,RUNTEST,"  RUNTEST ",$(S390_TEST_LIB_PATH)/s390_runtest))
$(eval $(call cmd_define,    CAT,"  CAT     ",cat))
$(eval $(call cmd_define,    SED,"  SED     ",sed))
$(eval $(call cmd_define,   GZIP,"  GZIP    ",gzip))
$(eval $(call cmd_define,     MV,"  MV      ",mv))
$(eval $(call cmd_define,  PERLC,"  PERLC   ",perl -c))

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
DEFAULT_CFLAGS = -g -fstack-protector-all -W -Wall -Wformat-security
ifeq ("${W}","1")
	DEFAULT_CFLAGS += -Wextra -Wshadow -Wundef -Wuninitialized -Wdouble-promotion -Wconversion
endif
ifeq ("${D}","1")
	DEFAULT_CFLAGS += -Og -g3 -ggdb3
else
	DEFAULT_CFLAGS += -O3
endif

ifeq ("${ENABLE_WERROR}", "1")
	DEFAULT_CFLAGS += -Werror
endif

DEFAULT_CPPFLAGS = -D_GNU_SOURCE
DEFAULT_LDFLAGS = -rdynamic

ifeq ("${ASAN}","1")
	DEFAULT_CFLAGS  += -fsanitize=address -fno-omit-frame-pointer
	DEFAULT_LDFLAGS += -fsanitize=address
endif

DEFAULT_PERLCFLAGS =
ifeq ("${W}","1")
	DEFAULT_PERLCFLAGS += -w
endif

#
# Check for header prerequisite
#
# $1: Name of include file to check
# $2: Additional compiler & linker options (optional)
#
# Returns "yes" on success and nothing otherwise
#
define check_header_prereq
$(shell printf "#include <%s>\n int main(void) {return 0;}\n" $1 | \
        ( $(CC) $(filter-out --coverage, $(ALL_CFLAGS)) $(ALL_CPPFLAGS) \
                $2 -o /dev/null -x c - ) >/dev/null 2>&1 && echo -n yes)
endef

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
printf "\#include <%s>\n int main(void) {return 0;}\n" $2 | ( $(CC) $(filter-out --coverage, $(ALL_CFLAGS)) $(ALL_CPPFLAGS) $5 -o /dev/null -x c - ) > /dev/null 2>&1; \
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
# Test for linker option
#
# $1: Linker option
#
# Returns the linker option if available and nothing otherwise
#
define test_linker_flag
$(shell printf "int main(void) {return 0;}\n" | \
        ( $(CC) "-Wl,$1" -o /dev/null -x c - ) >/dev/null 2>&1 && printf -- '-Wl,%s' "$1")
endef

NO_WARN_RWX_SEGMENTS_LDFLAGS := $(call test_linker_flag,"--no-warn-rwx-segments")

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
USRLIBDIR	= $(INSTALLDIR)/usr/lib
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
UDEVDIR		= $(USRLIBDIR)/udev
UDEVRULESDIR	= $(UDEVDIR)/rules.d
DRACUTDIR	= $(USRLIBDIR)/dracut
DRACUTCONFDIR   = $(DRACUTDIR)/dracut.conf.d
DRACUTMODDIR	= $(DRACUTDIR)/modules.d

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
			$(SOINSTALLDIR) $(USRLIBDIR)
OWNER           = $(shell id -un)
GROUP		= $(shell id -gn)
export INSTALLDIR BINDIR LIBDIR USRLIBDIR USRLIB64DIR MANDIR OWNER GROUP

# Special defines for zfcpdump
ZFCPDUMP_IMAGE	= zfcpdump-image
ZFCPDUMP_INITRD	= zfcpdump-initrd
ZFCPDUMP_FLAVOR	= zfcpdump
export ZFCPDUMP_DIR ZFCPDUMP_IMAGE ZFCPDUMP_INITRD ZFCPDUMP_FLAVOR

CFLAGS		 ?= $(DEFAULT_CFLAGS) $(OPT_FLAGS)
CFLAGS_FOR_BUILD ?= $(DEFAULT_CFLAGS) $(OPT_FLAGS)
CPPFLAGS	 ?= $(DEFAULT_CPPFLAGS)
LDFLAGS		 ?= $(DEFAULT_LDFLAGS)

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

ALL_PERLCFLAGS	= $(DEFAULT_PERLCFLAGS)

# make G=1
# Compile tools so that gcov can be used to collect code coverage data.
# See the gcov man page for details.
ifeq ("${G}","1")
ALL_CFLAGS := $(filter-out -O%,$(ALL_CFLAGS)) --coverage
ALL_CXXFLAGS := $(filter-out -O%,$(ALL_CXXFLAGS)) --coverage
ALL_LDFLAGS += --coverage
endif
export INSTALL CFLAGS CXXFLAGS \
       LDFLAGS CPPFLAGS ALL_CFLAGS ALL_CXXFLAGS ALL_LDFLAGS ALL_CPPFLAGS

ifneq ($(shell $(CC_SILENT) -dumpspecs 2>/dev/null | grep -e '[^f]no-pie'),)
	NO_PIE_CFLAGS := -fno-pie
	NO_PIE_LDFLAGS := -no-pie
else
	NO_PIE_CFLAGS :=
	NO_PIE_LDFLAGS :=
endif

# Overwrite implicit makefile rules for having nice compile output
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
	@echo '  D=1      	 Build with debugging option "-Og"'
	@echo '  C=1      	 Build with check tool defined with "CHECK=" (default=sparse)'
	@echo '  G=1      	 Build with gcov to collect code coverage data'
	@echo '  V=1      	 Generate verbose build output'
	@echo '  W=1		 Build with higher warning level'
	@echo '  ASAN=1   	 Build with address sanitizer'
	@echo '  ENABLE_WERROR=1 Build with -Werror'
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

$(rootdir)/libvmcp/libvmcp.a: $(rootdir)/libvmcp
	$(MAKE) -C $(rootdir)/libvmcp/ libvmcp.a
.PHONY: $(rootdir)/libvmcp

$(rootdir)/libcpumf/libcpumf.a: $(rootdir)/libcpumf
	$(MAKE) -C $(rootdir)/libcpumf/ libcpumf.a
.PHONY: $(rootdir)/libcpumf

$(rootdir)/libekmfweb/libekmfweb.so: $(rootdir)/libekmfweb
	$(MAKE) -C $(rootdir)/libekmfweb/ libekmfweb.so
.PHONY: $(rootdir)/libekmfweb

$(rootdir)/libseckey/libseckey.a: $(rootdir)/libseckey
	$(MAKE) -C $(rootdir)/libseckey/ libseckey.a
.PHONY: $(rootdir)/libseckey

$(rootdir)/libkmipclient/libkmipclient.so: $(rootdir)/libkmipclient
	$(MAKE) -C $(rootdir)/libkmipclient/ libkmipclient.so
.PHONY: $(rootdir)/libkmipclient

$(rootdir)/libap/libap.a: $(rootdir)/libap
	$(MAKE) -C $(rootdir)/libap/ libap.a
.PHONY: $(rootdir)/libap

$(rootdir)/libpv/libpv.a: $(rootdir)/libpv
	$(MAKE) -C $(rootdir)/libpv libpv.a
.PHONY: $(rootdir)/libpv

$(rootdir)/zipl/boot/.loaders:
	$(MAKE) -C $(rootdir)/zipl/boot/ .loaders

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

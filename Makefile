ARCH := $(shell uname -m | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ -e s/arm.*/arm/ -e s/sa110/arm/)

# Include common definitions
include common.mak

#
# BASELIBS: Libraries that have no dependency to other libraries in s390-tools
# LIBS: Libraries that can have a dependency to base libraries
# TOOLS: Tools that can have a dependency to base libraries or libraries
#
BASELIB_DIRS = libutil libseckey
LIB_DIRS = libvtoc libzds libdasd libvmdump libccw libvmcp libekmfweb \
	   libkmipclient
TOOL_DIRS = zipl zdump fdasd dasdfmt dasdview tunedasd \
	   tape390 osasnmpd qetharp ip_watcher qethconf scripts zconf \
	   vmconvert vmcp man mon_tools dasdinfo vmur cpuplugd ipl_tools \
	   ziomon iucvterm hyptop cmsfs-fuse qethqoat zfcpdump zdsfs cpumf \
	   systemd hmcdrvfs cpacfstats zdev dump2tar zkey netboot etc zpcictl \
	   genprotimg lsstp hsci hsavmcore

SUB_DIRS = $(BASELIB_DIRS) $(LIB_DIRS) $(TOOL_DIRS)

all: $(TOOL_DIRS)
clean: $(TOOL_DIRS)
install: $(TOOL_DIRS)

#
# For simple "make" we explicitly set the MAKECMDGOALS to "all".
#
ifeq ($(MAKECMDGOALS),)
MAKECMDGOALS = all
endif

#
# We have to build the base libraries before the other libraries are built,
# and then build the other libraries before the tools are built. Otherwise the 
# other libraries and tools would trigger parallel "make -C" builds for the
# base libraries and the other libraries in case of "make -j".
#
# MAKECMDGOALS contains the list of goals, e.g. "clean all". We use
# "foreach" to generate a ";" separated list of "make -C <target>".
# For example the the expansion for "make clean all" is:
#
# $(MAKE) -C $@ [..] clean ;  $(MAKE) -C $@ [...] all ;
#
# This ensures that the commandline targets are serialized and also "make -j"
# works as expected, e.g. "make clean all -j 20".
#

$(TOOL_DIRS): $(LIB_DIRS)
	$(foreach goal,$(MAKECMDGOALS), \
		$(MAKE) -C $@ TOPDIR=$(TOPDIR) ARCH=$(ARCH) $(goal) ;)
.PHONY: $(TOOL_DIRS)

$(LIB_DIRS): $(BASELIB_DIRS)
	$(foreach goal,$(MAKECMDGOALS), \
		$(MAKE) -C $@ TOPDIR=$(TOPDIR) ARCH=$(ARCH) $(goal) ;)
.PHONY: $(LIB_DIRS)

$(BASELIB_DIRS):
	$(foreach goal,$(MAKECMDGOALS), \
		$(MAKE) -C $@ TOPDIR=$(TOPDIR) ARCH=$(ARCH) $(goal) ;)
.PHONY: $(BASELIB_DIRS)

ARCH := $(shell uname -m | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ -e s/arm.*/arm/ -e s/sa110/arm/)

# Include common definitions
include common.mak

LIB_DIRS = libvtoc libutil libzds libdasd libvmdump libccw libvmcp libekmfweb
TOOL_DIRS = zipl zdump fdasd dasdfmt dasdview tunedasd \
	   tape390 osasnmpd qetharp ip_watcher qethconf scripts zconf \
	   vmconvert vmcp man mon_tools dasdinfo vmur cpuplugd ipl_tools \
	   ziomon iucvterm hyptop cmsfs-fuse qethqoat zfcpdump zdsfs cpumf \
	   systemd hmcdrvfs cpacfstats zdev dump2tar zkey netboot etc zpcictl \
	   genprotimg lsstp hsci hsavmcore

SUB_DIRS = $(LIB_DIRS) $(TOOL_DIRS)

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
# We have to build the libraries before the tools are built. Otherwise
# the tools would trigger parallel "make -C" builds for libraries in
# case of "make -j".
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

$(LIB_DIRS):
	$(foreach goal,$(MAKECMDGOALS), \
		$(MAKE) -C $@ TOPDIR=$(TOPDIR) ARCH=$(ARCH) $(goal) ;)
.PHONY: $(LIB_DIRS)

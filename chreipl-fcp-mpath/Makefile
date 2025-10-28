# SPDX-License-Identifier: MIT
#
# chreipl-fcp-mpath: use multipath information to change FCP IPL target
# (C) Copyright IBM Corp. 2021
#
# Uses the following system-utilities (and shell-builtins):
#   Utilities list in GNU Make Conventions:
#     https://www.gnu.org/software/make/manual/make.html#Utilities-in-Makefiles
#   Those necessary for sourced Makefiles:
#     - ../common.mak
#     - chreipl-fcp-mpath.mak
#   bash:
#     - bash
#   GNU coreutils:
#     - sha256sum
# If $(ENABLE_DOC) is `1`:
#   GNU awk:
#     - gawk

override .SHELLFLAGS	:= -O globstar -O nullglob -O extglob -c

# Include common s390-tools definitions
include ../common.mak

# Include common chreipl-fcp-mpath definitions
include chreipl-fcp-mpath.mak

# Local setting: .make.config
#	You may create a file named like this in the same directory as this
#	Makefile, and customize the build this way (e.g. re-define variables
#	set in `chreipl-fcp-mpath.mak`, or define a `CHREIPLZFCPMP_POST_INSTALL`
#	that is automatically called after each installation)
ifneq ($(wildcard .make.config),)
include $(wildcard .make.config)
endif

#
## Build
#

.PHONY: chreipl-fcp-mpath chreipl-fcp-mpath-clean
chreipl-fcp-mpath:
chreipl-fcp-mpath-clean:
all: chreipl-fcp-mpath
clean: chreipl-fcp-mpath-clean

# common function used in the helper scripts
CHREIPL_FCP_MPATH_COMMON	:=					\
	chreipl-fcp-mpath-common.sh
CHREIPL_FCP_MPATH_UDEV_HELPER	:=					\
	chreipl-fcp-mpath-is-ipl-tgt					\
	chreipl-fcp-mpath-is-ipl-vol					\
	chreipl-fcp-mpath-is-reipl-zfcp					\
	chreipl-fcp-mpath-record-volume-identifier			\
	chreipl-fcp-mpath-try-change-ipl-path

$(CHREIPL_FCP_MPATH_UDEV_HELPER) $(CHREIPL_FCP_MPATH_COMMON): $(MAKEFILE_LIST)
$(CHREIPL_FCP_MPATH_UDEV_HELPER) $(CHREIPL_FCP_MPATH_COMMON): % : %.in
	$(call chreiplzfcpmp-sed-buildvar-replace,$(<),$(@))
	chmod a+x $(@)

$(CHREIPL_FCP_MPATH_UDEV_HELPER): $(CHREIPL_FCP_MPATH_COMMON)

.PHONY: chreipl-fcp-mpath-udev-helper-clean
chreipl-fcp-mpath-udev-helper-clean:
	rm -f $(CHREIPL_FCP_MPATH_UDEV_HELPER) $(CHREIPL_FCP_MPATH_COMMON)

udev/rules.d/70-chreipl-fcp-mpath.rules: $(CHREIPL_FCP_MPATH_UDEV_HELPER)

chreipl-fcp-mpath: udev/rules.d/70-chreipl-fcp-mpath.rules
chreipl-fcp-mpath-clean: chreipl-fcp-mpath-udev-helper-clean

dracut/dracut.conf.d/70-chreipl-fcp-mpath.conf: $(MAKEFILE_LIST)
dracut/dracut.conf.d/70-chreipl-fcp-mpath.conf: % : %.in
	$(call chreiplzfcpmp-sed-buildvar-replace,$(<),$(@))

.PHONY: chreipl-fcp-mpath-dracut-clean
chreipl-fcp-mpath-dracut-clean:
	rm -f dracut/dracut.conf.d/70-chreipl-fcp-mpath.conf

chreipl-fcp-mpath: dracut/dracut.conf.d/70-chreipl-fcp-mpath.conf
chreipl-fcp-mpath-clean: chreipl-fcp-mpath-dracut-clean

ifeq ($(ENABLE_DOC),1)

.PHONY: chreipl-fcp-mpath-doc
chreipl-fcp-mpath-doc: README.html chreipl-fcp-mpath.7

ifeq ($(ENABLE_DOC_PDF),1)
chreipl-fcp-mpath-doc: README.pdf

README.pdf: PANDOCFLAGS += -M title="chreipl-fcp-mpath" -M subtitle="README"
endif

README.html: PANDOCFLAGS += -M title="chreipl-fcp-mpath" -M subtitle="README"

chreiplzfcpmp-doc-man-meta =						\
	-M title="CHREIPL-FCP-MPATH"					\
	-V header="Administrator Manual"				\
	-V section="7"							\
	-V footer="s390-tools $(S390_TOOLS_RELEASE)"

chreipl-fcp-mpath.7: PANDOCFLAGS += $(chreiplzfcpmp-doc-man-meta)
chreipl-fcp-mpath.7: .chreipl-fcp-mpath.7.cksum

.INTERMEDIATE: chreipl-fcp-mpath.md
chreipl-fcp-mpath.md: README.md
	gawk -- '/NOT-IN-MAN \{/,/NOT-IN-MAN \}/ { next } { print }' $(<) > $(@)

.chreipl-fcp-mpath.7.cksum: README.md
	sha256sum $(<) > $(@)

.PHONY: chreipl-fcp-mpath-doc-clean
chreipl-fcp-mpath-doc-clean:
	rm -f README.html README.pdf chreipl-fcp-mpath.md

chreipl-fcp-mpath: chreipl-fcp-mpath-doc
chreipl-fcp-mpath-clean: chreipl-fcp-mpath-doc-clean

else # $(ENABLE_DOC) != 1

# We bundle a pre-cooked man page with the source-code so that distributions
# don't need `pandoc` in order to be able to ship the man page. As of this
# writing multiple distributions don't have a packaged version of it.
#
# In order to remember to regenerate this pre-cooked version whenever the
# README.md is changed, we also generate a checksum of the README.md, bundle
# that as well, and compare that whenever `make` is called. This way, the
# freshness of the man page can be checked, even if `pandoc` is not available,
# or ENABLE_DOC disabled.

MANPAGE_FRESH	:= $(shell sha256sum -c .chreipl-fcp-mpath.7.cksum >/dev/null && echo 1 || echo 0)
ifeq ($(MANPAGE_FRESH),0)
$(warning chreipl-fcp-mpath.7 is outdated, please regenerate it by calling `make ENABLE_DOC=1`)
endif

endif # $(ENABLE_DOC) == 1

#
## Install
#

.PHONY: chreipl-fcp-mpath-install
# The content of `CHREIPLZFCPMP_POST_INSTALL` (bash script) is automatically
# called *after* installing chreipl-fcp-mpath during `make install`. If not
# defined (the default), nothing happens. You may define this on the make
# command line, or by creating a `.make.config` and defining the variable in
# there.
chreipl-fcp-mpath-install:
	$(CHREIPLZFCPMP_POST_INSTALL)

install: chreipl-fcp-mpath-install

# install udev rules
INSTDIRS += $(UDEVRULESDIR)
$(DESTDIR)$(UDEVRULESDIR): install_dirs

.PHONY: chreipl-fcp-mpath-install-udev-rules
chreipl-fcp-mpath-install-udev-rules: | $(DESTDIR)$(UDEVRULESDIR)
chreipl-fcp-mpath-install-udev-rules: udev/rules.d/70-chreipl-fcp-mpath.rules
	$(INSTALL_DATA) -t $(DESTDIR)$(UDEVRULESDIR)			\
		udev/rules.d/70-chreipl-fcp-mpath.rules

chreipl-fcp-mpath-install: chreipl-fcp-mpath-install-udev-rules

# install udev helper programs
INSTDIRS += $(UDEVDIR)
$(DESTDIR)$(UDEVDIR): install_dirs

.PHONY: chreipl-fcp-mpath-install-udev-helper
chreipl-fcp-mpath-install-udev-helper: | $(DESTDIR)$(UDEVDIR)
chreipl-fcp-mpath-install-udev-helper: $(CHREIPL_FCP_MPATH_UDEV_HELPER)
	$(INSTALL_EXEC) -t $(DESTDIR)$(UDEVDIR) $(CHREIPL_FCP_MPATH_UDEV_HELPER)

chreipl-fcp-mpath-install: chreipl-fcp-mpath-install-udev-helper

# install common library files
INSTDIRS += $(CHREIPLZFCPMPDIR)
$(DESTDIR)$(CHREIPLZFCPMPDIR): install_dirs

.PHONY: chreipl-fcp-mpath-install-libfiles
chreipl-fcp-mpath-install-libfiles: | $(DESTDIR)$(CHREIPLZFCPMPDIR)
chreipl-fcp-mpath-install-libfiles: $(CHREIPL_FCP_MPATH_COMMON)
	$(INSTALL_DATA) -t $(DESTDIR)$(CHREIPLZFCPMPDIR)		\
		$(CHREIPL_FCP_MPATH_COMMON)

chreipl-fcp-mpath-install: chreipl-fcp-mpath-install-libfiles

ifeq ($(HAVE_DRACUT),1)

# install dracut config files
INSTDIRS += $(DRACUTCONFDIR)
$(DESTDIR)$(DRACUTCONFDIR): install_dirs

.PHONY: chreipl-fcp-mpath-install-dracut-config
chreipl-fcp-mpath-install-dracut-config: | $(DESTDIR)$(DRACUTCONFDIR)
chreipl-fcp-mpath-install-dracut-config: dracut/dracut.conf.d/70-chreipl-fcp-mpath.conf
	$(INSTALL_DATA) -t $(DESTDIR)$(DRACUTCONFDIR)			\
		dracut/dracut.conf.d/70-chreipl-fcp-mpath.conf

chreipl-fcp-mpath-install: chreipl-fcp-mpath-install-dracut-config

endif

# chreipl-fcp-mpath: install man page
INSTDIRS += $(MANDIR)
$(DESTDIR)$(MANDIR)/man7: install_dirs

.PHONY: chreipl-fcp-mpath-install-man-page
chreipl-fcp-mpath-install-man-page: | $(DESTDIR)$(MANDIR)/man7
chreipl-fcp-mpath-install-man-page: chreipl-fcp-mpath.7
	$(INSTALL_DATA) -t $(DESTDIR)$(MANDIR)/man7			\
		chreipl-fcp-mpath.7

chreipl-fcp-mpath-install: chreipl-fcp-mpath-install-man-page

#
## Utility
#

# Utilities for the debug feature of chreipl-fcp-mpath-common.sh.
#
# When `chreipl-fcp-mpath` is built with D=1 (default is D=0), each run
# of one of the helper scripts will create a debug log in $(DEBUGOUTDIR)
# (default: /run/udev) which among other things contains the complete shell
# trace of that script run, with some added information that would not be
# inspectable otherwise with just the trace.
#
# There is currently no way of enabling/disabling this at runtime.
#
# chreipl-fcp-mpath-common.sh defines debug log file name as
# "chreiplzfcpmp-${debug_trace_tag}-${SEQNUM:-0}.XXXXXXXXXX" where SEQNUM is a
# udev rule environment variable and each X is replaced with some [[:alnum:]]
# by mktemp. For a definition of `debug_trace_tag`, please see the comments
# in the source.
#
# The following targets can be used for some simple access and filtering of the
# logs during development.

DEBUG_LOG_GLOB = $(DEBUGOUTDIR)/chreiplzfcpmp-[[:digit:]][[:digit:]][[:alpha:]][[:alpha:]][[:alpha:]][[:alpha:]]-+([[:digit:]]).[[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]]

# display all debug log files on the system
.PHONY: chreipl-fcp-mpath-debug-logs
chreipl-fcp-mpath-debug-logs:
	@ls -1d $(DEBUG_LOG_GLOB)

# display only debug log files of script runs that exited with status 0 (= good)
#
# XXX: `sed -n -e '$p'` is used instead of `tail -n1` to prevent an other
#      dependency just for that (both invocations do the same thing).
.PHONY: chreipl-fcp-mpath-debug-logs-filter-good
chreipl-fcp-mpath-debug-logs-filter-good:
	@for lg in $(DEBUG_LOG_GLOB); do				\
		sed -e '/^+ trap_exit$$/,/^+ trap - EXIT$$/d' "$${lg}"	\
		    | sed -n -e '$$p'					\
		    | grep -q -e '^+ exit 0$$'		|| continue;	\
		ls -d "$${lg}";						\
	done

# display only debug log files of script runs that didn't exit with status 0
# (= bad)
.PHONY: chreipl-fcp-mpath-debug-logs-filter-bad
chreipl-fcp-mpath-debug-logs-filter-bad:
	@for lg in $(DEBUG_LOG_GLOB); do				\
		sed -e '/^+ trap_exit$$/,/^+ trap - EXIT$$/d' "$${lg}"	\
		    | sed -n -e '$$p'					\
		    | grep -q -e '^+ exit 0$$'		&& continue;	\
		ls -d "$${lg}";						\
	done

.PHONY: chreipl-fcp-mpath-debug-logs-clean
chreipl-fcp-mpath-debug-logs-clean:
	rm -f $(DEBUG_LOG_GLOB)

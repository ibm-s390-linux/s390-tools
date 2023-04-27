# SPDX-License-Identifier: MIT
#
# chreipl-fcp-mpath: use multipath information to change FCP IPL target
# (C) Copyright IBM Corp. 2021
#
# Uses the following system-utilities (and shell-builtins):
#   Utilities list in GNU Make Conventions:
#     https://www.gnu.org/software/make/manual/make.html#Utilities-in-Makefiles
#   GNU coreutils:
#     - mktemp
# If $(ENABLE_DOC) is `1`:
#   Pandoc:
#     - pandoc
#   GNU coreutils:
#     - date

#
## Paths and Build Variables
#

# Install the configuration file for dracut, to automatically pull in the
# toolset into the initial ramdisk, when built with it.
HAVE_DRACUT	 = 0

# Build documentation; requires: Pandoc
ENABLE_DOC	 = 0

# https://www.gnu.org/software/make/manual/make.html#Directory-Variables
CHREIPLZFCPMPDIR = $(USRLIBDIR)/chreipl-fcp-mpath
UDEVRUNDIR	 = /run/udev
DEBUGOUTDIR	 = $(UDEVRUNDIR)

INSTALL_EXEC	 = $(INSTALL) -g $(GROUP) -o $(OWNER) --preserve-timestamps
INSTALL_DATA	 = $(INSTALL_EXEC) --mode=0644

# used for data exchange and synchronization across the different helpers
chreiplzfcpmp-id-file		 = $(UDEVRUNDIR)/chreiplzfcpmp-ipl-volume-id
# file used to implement mutual exclusion when accessing firmware IPL info:
#   - this should be something that is (practically) always available, so we
#     dont have to worry about fallbacks or error-handling;
#   - at the same time, it should not be used by anything else with flock(2) to
#     hold a lock for long periods.
chreiplzfcpmp-fwlock-file	 = /sys/firmware/reipl

.DELETE_ON_ERROR:

# export build-time definitions to the scripts/built-components
define chreiplzfcpmp-sed-buildvar-replace =
tmpout=$$(mktemp -p ./ .make.tmp.XXXXXXXXXXXXXXXX) && {			\
	$(SED) -E 							\
		-e 's|@DEBUG@|$(if $(filter 1,$(D)),true,false)|g'	\
		-e 's|@chreiplzfcpmp-id-file@|$(chreiplzfcpmp-id-file)|g' \
		-e 's|@chreiplzfcpmp-fwlock-file@|$(chreiplzfcpmp-fwlock-file)|g' \
		-e 's|@chreiplzfcpmp-lib@|$(CHREIPLZFCPMPDIR)/chreipl-fcp-mpath-common.sh|g' \
		-e 's|@debugoutdir@|$(DEBUGOUTDIR)|g'			\
		-e 's|@udevdir@|$(UDEVDIR)|g'				\
		-e 's|@udevrulesdir@|$(UDEVRULESDIR)|g'			\
		$(1) > $${tmpout}					\
	    && mv $${tmpout} $(2)					\
	    || { rm $${tmpout}; false; }				\
; }
endef

.PHONY: clean-mk-temp
clean: clean-mk-temp
clean-mk-temp:
	rm -f .make.tmp.[[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]]

# Definitions for generating documentation when $(ENABLE_DOC) is set to `1`

PANDOCFLAGS	 = --fail-if-warnings
ALL_PANDOCFLAGS	 = --preserve-tabs --tab-stop=8 --strip-comments	\
		   --standalone --self-contained			\
		   -M date="$(shell date +'%Y-%m-%d')"			\
		   $(PANDOCFLAGS)

$(eval $(call cmd_define_and_export, PANDOC,"  PANDOC  ",pandoc))

%.html : ALL_PANDOCFLAGS += -t html
%.html : %.md
	$(PANDOC) $(ALL_PANDOCFLAGS) -f gfm -o $(@) $(<)

%.pdf : ALL_PANDOCFLAGS += -t latex --toc
%.pdf : %.md
	$(PANDOC) $(ALL_PANDOCFLAGS) -f gfm -o $(@) $(<)

%.7 : ALL_PANDOCFLAGS += -t man
%.7 : %.md
	$(PANDOC) $(ALL_PANDOCFLAGS) -f gfm -o $(@) $(<)

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

#
## Paths and Build Variables
#

# https://www.gnu.org/software/make/manual/make.html#Directory-Variables
CHREIPLZFCPMPDIR = $(USRLIBDIR)/chreipl-fcp-mpath
UDEVDIR		 = $(USRLIBDIR)/udev
UDEVRULESDIR	 = $(UDEVDIR)/rules.d
UDEVRUNDIR	 = /run/udev
DEBUGOUTDIR	 = $(UDEVRUNDIR)

INSTALL_EXEC	 = $(INSTALL) -g $(GROUP) -o $(OWNER) --preserve-timestamps
INSTALL_DATA	 = $(INSTALL_EXEC) --mode=0644

.DELETE_ON_ERROR:

# export build-time definitions to the scripts/built-components
define chreiplzfcpmp-sed-buildvar-replace =
tmpout=$$(mktemp -p ./ .make.tmp.XXXXXXXXXXXXXXXX) && {			\
	$(SED) -E 							\
		-e 's|@DEBUG@|$(if $(filter 1,$(D)),true,false)|g'	\
		-e 's|@chreiplzfcpmp-lib@|$(CHREIPLZFCPMPDIR)/chreipl-fcp-mpath-common.sh|g' \
		-e 's|@debugoutdir@|$(DEBUGOUTDIR)|g'			\
		$(1) > $${tmpout}					\
	    && mv $${tmpout} $(2)					\
	    || { rm $${tmpout}; false; }				\
; }
endef

.PHONY: clean-mk-temp
clean: clean-mk-temp
clean-mk-temp:
	rm -f .make.tmp.[[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]][[:alnum:]]

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

override SHELL		:= /bin/bash
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

udev/rules.d/70-chreipl-fcp-mpath.rules:

chreipl-fcp-mpath: udev/rules.d/70-chreipl-fcp-mpath.rules

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

.PHONY: chreipl-fcp-mpath-install-udev-rules
chreipl-fcp-mpath-install-udev-rules: | $(DESTDIR)$(UDEVRULESDIR)
chreipl-fcp-mpath-install-udev-rules: udev/rules.d/70-chreipl-fcp-mpath.rules
	$(INSTALL_DATA) -t $(DESTDIR)$(UDEVRULESDIR)			\
		udev/rules.d/70-chreipl-fcp-mpath.rules

chreipl-fcp-mpath-install: chreipl-fcp-mpath-install-udev-rules

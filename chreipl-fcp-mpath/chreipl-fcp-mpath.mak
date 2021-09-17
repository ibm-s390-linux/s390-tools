# SPDX-License-Identifier: MIT
#
# chreipl-fcp-mpath: use multipath information to change FCP IPL target
# (C) Copyright IBM Corp. 2021
#
# Uses the following system-utilities (and shell-builtins):
#   Utilities list in GNU Make Conventions:
#     https://www.gnu.org/software/make/manual/make.html#Utilities-in-Makefiles

#
## Paths and Build Variables
#

# https://www.gnu.org/software/make/manual/make.html#Directory-Variables
UDEVDIR		 = $(USRLIBDIR)/udev
UDEVRULESDIR	 = $(UDEVDIR)/rules.d

INSTALL_EXEC	 = $(INSTALL) -g $(GROUP) -o $(OWNER) --preserve-timestamps
INSTALL_DATA	 = $(INSTALL_EXEC) --mode=0644

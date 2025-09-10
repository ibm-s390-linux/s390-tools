# SPDX-License-Identifier: MIT
# Copyright IBM Corp. 2025


# This file defines the build process for shell autocompletion binaries
#
# How to incorporate it into tool Makefiles:
#
# 0. The file with the autocompletion script generation code should be named
# 'autocompletion_generator_host.c'
#
# 1. Define the 'bash-completions' and 'zsh-completions' variables: both must be a list
# of the names of all the shell completion scripts that belong to the tools the Makefile
# is responsible for building.
#
# (The name of a zsh completion script is the same as the name of the tool,
# prefixed by an underscore)
#
# (The name of a bash completion script is the same as the name of the tool,
# suffixed by '.bash')
#
# 2. include this file
#
# +1: Add the autocompletion scripts to the .gitignore file
#
# (See cpumf or dasdfmt as example)


autocomplete-bin := autocompletion_generator_host

autocomp-object := $(rootdir)/libutil/util_autocomp_host.o

$(autocomp-object): $(rootdir)/libutil
	$(MAKE) -C $(rootdir)/libutil/ $(notdir $@)

$(autocomplete-bin).o: $(autocomplete-bin).c
	$(CC_FOR_BUILD) $(CFLAGS_FOR_BUILD) -I $(rootdir)/include -c $< -o $@

$(autocomplete-bin): $(autocomplete-bin).o $(autocomp-object)
	$(LINK_FOR_BUILD) $^ -o $@

$(bash-completions) $(zsh-completions) &: $(autocomplete-bin)
	./$(autocomplete-bin)

install-shell-completions: $(bash-completions) $(zsh-completions)
	$(INSTALL) -d -m 755 $(DESTDIR)$(ZSHCOMPLETIONDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(BASHCOMPLETIONDIR)
	for completion in $(bash-completions); do \
		$(INSTALL) -m 644 $$completion $(DESTDIR)$(BASHCOMPLETIONDIR); \
	done
	for completion in $(zsh-completions); do \
		$(INSTALL) -m 644 $$completion $(DESTDIR)$(ZSHCOMPLETIONDIR); \
	done

all: $(zsh-completions) $(bash-completions)

install: install-shell-completions

.PHONY: install-shell-completions $(rootdir)/libutil

clean-autocomplete-bin:
	$(RM) -- $(autocomplete-bin)

clean: clean-autocomplete-bin

ifdef bash-completions
clean-bash-completions:
	$(RM) -- $(bash-completions)

clean: clean-bash-completions
endif


ifdef zsh-completions
clean-zsh-completions:
	$(RM) -- $(zsh-completions)

clean: clean-zsh-completions
endif

.PHONY: clean-autocomplete-bin clean-bash-completions clean-zsh-completions

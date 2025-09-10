// SPDX-License-Identifier: MIT
/*
 * autocomp - command line autocompletion
 *
 * Generating autocompletion scripts for bash and zsh
 * based on util_opt struct
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/util_autocomp.h"
#include "lib/util_opt.h"

static const char *bash_script_part1 = "() {\n\n\
\tlocal current_word previous_word options_array\n\n\
\tCOMPREPLY=()\n\n\
\tcurrent_word=\"${COMP_WORDS[COMP_CWORD]}\"\n\n\
\tprevious_word=\"${COMP_WORDS[COMP_CWORD-1]}\"\n\n\
\toptions_array=\"";

static const char *bash_script_part2 = "\tif [[ ${current_word} == -* || ${COMP_CWORD} -eq 1 ]] ; then\n\n\
\t\tCOMPREPLY=( $(compgen -W \"${options_array}\" -- ${current_word} ) )\n\n\
\t\treturn 0\n\n\
\tfi\n\n\
}\n\n\
complete -F ";

static char *format_name(const char *fmt, char *tool_name)
{
	char *func_name;

	if (asprintf(&func_name, fmt, tool_name) == -1)
		return NULL;
	return func_name;
}

/*
 * The convention for a completion function name is to be the same
 * as the command's name, but prefixed by '_'.
 */
static char *generate_func_name(char *tool_name)
{
	return format_name("_%s", tool_name);
}

static char *generate_bash_filename(char *tool_name)
{
	return format_name("%s.bash", tool_name);
}

static int init_scriptfile(char *file_path)
{
	int fd;

	fd = open(file_path, O_CREAT | O_WRONLY, 0644);
	if (fd < 0)
		return -EIO;
	return fd;
}

static int start_bash_scriptfile(int fd, char *func_name)
{
	int len, ret = 0;
	char *str;

	len = asprintf(&str, "%s%s", func_name, bash_script_part1);
	if (len == -1)
		return -EIO;

	if (write(fd, str, len) != len)
		ret = -EIO;
	free(str);
	return ret;
}

static int start_zsh_scriptfile(int fd, char *func_name, char *tool_name)
{
	const char *part3 = " {\n\n\t_arguments -C \\\n";
	const char *part2 = "\n\nfunction ";
	const char *part1 = "#compdef ";
	int len, ret = 0;
	char *str;

	len = asprintf(&str, "%s%s%s%s%s", part1, tool_name, part2, func_name, part3);
	if (len == -1)
		return -EIO;

	if (write(fd, str, len) != len)
		ret = -EIO;
	free(str);
	return ret;
}

static int write_bash_command_options(struct util_opt *opt_vec, int fd)
{
	const char *prefix = " --";
	char *str;
	int len;

	for (int i = 0; opt_vec[i].desc; i++) {
		if (opt_vec[i].option.name) {
			len = asprintf(&str, "%s%s", prefix, opt_vec[i].option.name);
			if (len == -1)
				return -EIO;
			if (write(fd, str, len) != len) {
				free(str);
				return -EIO;
			}
			free(str);
		}
	}
	if (write(fd, "\"\n\n", 3) != 3)
		return -EIO;
	return 0;
}

static int write_zsh_command_options(struct util_opt *opt_vec, int fd)
{
	const char *name, *desc;
	char *str;
	int len;

	for (int i = 0; opt_vec[i].desc; i++) {
		if (opt_vec[i].option.name) {
			name = opt_vec[i].option.name;
			desc = opt_vec[i].desc;
			len = asprintf(&str, "\t\t\"--%s[%s]\" \\\n", name, desc);
			if (len == -1)
				return -EIO;
			if (write(fd, str, len) != len) {
				free(str);
				return -EIO;
			}
			free(str);
		}
	}
	if (write(fd, "\n}\n", 3) != 3)
		return -EIO;
	return 0;
}

static int finish_bash_scriptfile(char *tool_name, int fd, char *func_name)
{
	int len, ret = 0;
	char *str;

	len = asprintf(&str, "%s%s %s\n", bash_script_part2, func_name, tool_name);
	if (len == -1)
		return -EIO;

	if (write(fd, str, len) != len)
		ret = -EIO;
	free(str);
	return ret;
}

/*
 * Adds tab completion in bash for a command.
 * Works by generating an autocompletion
 * script file  at '/usr/share/bash-completion/completions'.
 *
 * The full script will be as follows, supposing the tool name is
 * 'example' and it only has the options '--help' and
 * '--version':
 *
 * _example() {
 *
 *      local current_word previous_word options_array
 *
 *      COMPREPLY=()
 *
 *      current_word="${COMP_WORDS[COMP_CWORD]}"
 *
 *      previous_word="${COMP_WORDS[COMP_CWORD-1]}"
 *
 *      options_array="--version --help"
 *
 *      if [[ ${current_word} == -* || ${COMP_CWORD} -eq 1 ]] ; then
 *
 *              COMPREPLY=( $(compgen -W "${options_array}" -- ${current_word} ) )
 *
 *              return 0
 *
 *      fi
 *
 *	}
 *
 *	complete -F _example example
 *
 */
static void generate_bash_autocomp(struct util_opt *opt_vec, char *tool_name)
{
	char *func_name, *filename;
	int fd, ret = 0;

	func_name = generate_func_name(tool_name);
	if (!func_name) {
		ret = -ENOMEM;
		goto end;
	}
	filename = generate_bash_filename(tool_name);
	if (!filename) {
		ret = -ENOMEM;
		goto free_func;
	}
	fd = init_scriptfile(filename);
	if (fd < 0) {
		ret = fd;
		goto free_file;
	}
	ret = start_bash_scriptfile(fd, func_name);
	if (ret < 0)
		goto close;
	ret = write_bash_command_options(opt_vec, fd);
	if (ret < 0)
		goto close;
	ret = finish_bash_scriptfile(tool_name, fd, func_name);
close:
	close(fd);
	if (ret)
		remove(filename);
free_file:
	free(filename);
free_func:
	free(func_name);
end:
	printf("  AUTOCOMP\t%s/%s.bash\n", tool_name, tool_name);
	if (ret)
		printf("%s.bash: error - %s\n", tool_name, strerror(abs(ret)));
}

/*
 * Adds tab completion in zsh for a command.
 * Works by generating an autocompletion
 * script file  at '/usr/share/zsh/site-functions'.
 *
 * The full script will be as follows, supposing the tool name is
 * 'example' and it only has the options '--help', -h and
 * '--version' (the descriptions, as well as the flags are
 * taken from a util_opt struct):
 *
 * #compdef example_completion
 *
 * function _example_completion {
 *
 *	_arguments -C \
 *		"-h[Show help information]" \
 *		"--help[Show help but long format]" \
 *		"--version[Show version]"
 * }
 *
 */
static void generate_zsh_autocomp(struct util_opt *opt_vec, char *tool_name)
{
	char *func_name;
	int fd, ret = 0;

	func_name = generate_func_name(tool_name);
	if (!func_name) {
		ret = -ENOMEM;
		goto end;
	}
	fd = init_scriptfile(func_name);
	if (fd < 0) {
		ret = fd;
		goto free_func;
	}
	ret = start_zsh_scriptfile(fd, func_name, tool_name);
	if (ret < 0)
		goto close;
	ret = write_zsh_command_options(opt_vec, fd);
close:
	close(fd);
	if (ret)
		remove(func_name);
free_func:
	free(func_name);
end:
	printf("  AUTOCOMP\t%s/_%s\n", tool_name, tool_name);
	if (ret)
		printf("_%s: error - %s\n", tool_name, strerror(abs(ret)));
}

void generate_autocomp(struct util_opt *opt_vec, char *tool_name)
{
	generate_bash_autocomp(opt_vec, tool_name);
	generate_zsh_autocomp(opt_vec, tool_name);
}

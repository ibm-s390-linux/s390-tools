/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <execinfo.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "lib/util_file.h"

#include "dasd.h"
#include "device.h"
#include "devtype.h"
#include "misc.h"
#include "path.h"

#define DRYRUN_HEADER_BEGIN	((char) 0x01)
#define DRYRUN_HEADER_END	((char) 0x02)
#define DRYRUN_DATA_END		((char) 0x03)
#define DRYRUN_WRITE		"WRITE:"
#define DRYRUN_CMD		"CMD:"

#define LONGRUN_INITIAL_USEC	300000
#define LONGRUN_USEC		200000

/* Global variables. */
const char *toolname = NULL;
int verbose = 0;
int debug_enabled;
int quiet = 0;
int force = 0;
int yes = 0;
int found_forceable = 0;
int dryrun = 0;
int stdout_data = 0;
int delayed_errors = 0;

unsigned long longrun_total;
unsigned long longrun_current;

static struct util_list *delayed_messages;
static struct util_list *warn_once_messages;
static FILE *dryrun_file;

static FILE *dryrun_get_file(void)
{
	if (!dryrun_file)
		dryrun_file = tmpfile();

	return dryrun_file;
}

static void dryrun_announce(const char *type, const char *data, ...)
{
	va_list args;
	char *str;
	FILE *fd;

	va_start(args, data);
	if (vasprintf(&str, data, args) == -1)
		oom();
	va_end(args);

	fd = dryrun_get_file();
	if (fd) {
		fprintf(fd, "%c%s:%s%c", DRYRUN_HEADER_BEGIN, type, str,
			DRYRUN_HEADER_END);
	}

	free(str);
}

static void dryrun_end_data(void)
{
	FILE *fd;

	fd = dryrun_get_file();
	if (fd)
		fprintf(fd, "%c", DRYRUN_DATA_END);
}

static int count_newline(const char *str)
{
	int i, newline;

	newline = 0;
	for (i = 0; str[i]; i++) {
		if (str[i] == '\n')
			newline++;
	}

	return newline;
}

/* Display actions recorded during --dry-run. */
static void dryrun_print(void)
{
	char *txt, *header, *data, *end, *file;
	int cmd, newline;

	fseek(dryrun_file, 0, SEEK_SET);
	txt = util_file_read_fd(dryrun_file, 0);

	if (!txt)
		return;

	info("Skipped actions due to --dry-run:\n");
	cmd = 0;
	header = txt;
	while ((header = strchr(header, DRYRUN_HEADER_BEGIN)) &&
	       (data = strchr(header, DRYRUN_HEADER_END)) &&
	       (end = strchr(data, DRYRUN_DATA_END))) {
		header++;
		*(data++) = 0;
		*end = 0;

		if (starts_with(header, DRYRUN_WRITE)) {
			newline = count_newline(data);
			file = header + sizeof(DRYRUN_WRITE);
			switch (newline) {
			case 0:
				/* Show as echo -n */
				if (!cmd) {
					info("  Run:\n");
					cmd = 1;
				}
				indent(4, "echo -n \"%s\" > %s\n", data, file);
				break;
			case 1:
				/* Show as echo */
				if (!cmd) {
					info("  Run:\n");
					cmd = 1;
				}
				*(end - 1) = 0;
				if (!*data)
					indent(4, "echo > %s\n", file);
				else {
					indent(4, "echo \"%s\" > %s\n", data,
					       file);
				}
				break;
			default:
				/* Show as file write. */
				cmd = 0;
				info("  Write to %s\n", file);
				indent(4, data);
				break;
			}
		} else if (starts_with(header, DRYRUN_CMD)) {
			if (!cmd) {
				info("  Run:\n");
				cmd = 1;
			}
			indent(4, header + sizeof(DRYRUN_CMD));
		}
		header = end + 1;
	}

	free(txt);
}

void misc_exit(void)
{
	strlist_free(delayed_messages);
	strlist_free(warn_once_messages);
	if (dryrun_file) {
		if (verbose)
			dryrun_print();
		fclose(dryrun_file);
	}
}

/* Report an error. */
void error(const char *format, ...)
{
	va_list args;

	if (toolname)
		fprintf(stderr, "%s: ", toolname);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

/* Report an error and exit with the specified error code. */
void __attribute__((noreturn)) fatal(exit_code_t rc, const char *format, ...)
{
	va_list args;

	if (toolname)
		fprintf(stderr, "%s: ", toolname);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	exit(rc);
}

/* Report an error that can be overridden using --force */
void forceable(const char *format, ...)
{
	va_list args;
	char *str;
	const char *star = force ? "" : " (*)";
	int l;

	found_forceable = 1;

	/* Get error message. */
	va_start(args, format);
	if (vasprintf(&str, format, args) == -1)
		oom();
	va_end(args);

	/* Remove newline. */
	l = strlen(str);
	if ((l > 0) && (str[l - 1] == '\n'))
		str[l - 1] = 0;

	/* Print message. */
	if (toolname)
		fprintf(stderr, "%s: %s%s\n", toolname, str, star);
	else
		fprintf(stderr, "%s%s\n", str, star);

	free(str);
}

/* Report a warning that can be overridden using --force */
void forceable_warn(const char *format, ...)
{
	va_list args;
	char *str;
	const char *star = force ? "" : " (*)";
	int l;

	found_forceable = 1;

	/* Get error message. */
	va_start(args, format);
	if (vasprintf(&str, format, args) == -1)
		oom();
	va_end(args);

	/* Remove newline. */
	l = strlen(str);
	if ((l > 0) && (str[l - 1] == '\n'))
		str[l - 1] = 0;

	/* Print message. */
	fprintf(stderr, "%s%s\n", str, star);

	free(str);
}

/* Report a syntax error: print an error message to standard error prefixed
 * with toolname, followed by a reference to the --help option. */
void syntax(const char *format, ...)
{
	va_list args;

	if (toolname)
		fprintf(stderr, "%s: ", toolname);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	if (toolname) {
		fprintf(stderr, "Use '%s --help' for more information\n",
			toolname);
	}
}

/* Report a warning: print an error message to standard error. */
void _warn(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

/* Report a warning: print an error message to standard error. Only print each
 * warning once. */
void _warn_once(const char *format, ...)
{
	va_list args;
	char *str;

	va_start(args, format);
	if (vasprintf(&str, format, args) == -1)
		oom();
	va_end(args);

	/* Check if message was printed before. */
	if (!warn_once_messages)
		warn_once_messages = strlist_new();
	if (!strlist_find(warn_once_messages, str)) {
		fprintf(stderr, "%s", str);
		strlist_add(warn_once_messages, "%s", str);
	}

	free(str);
}

/* Print an error message indicating an out-of-memory situation and exit. */
void oom(void)
{
	if (!toolname)
		fprintf(stderr, "Out of memory\n");
	else
		fprintf(stderr, "%s: Out of memory\n", toolname);

	/* We can't rely on our clean-up routines to work reliably during an
	 * OOM situation, so just exit here. */

	exit(EXIT_OUT_OF_MEMORY);
}

#define	LINE_SIZE	80

/* Ask user for confirmation. */
bool confirm(const char *format, ...)
{
	va_list args;
	char *str;
	bool rc = false;
	char line[LINE_SIZE];
	int input;

	va_start(args, format);
	if (vasprintf(&str, format, args) == -1)
		oom();
	va_end(args);

	if (yes) {
		rc = true;
		if (verbose)
			info("%s - assuming 'yes' due to --yes\n", str);
		goto out;
	}

	/* Get user input. */
	input = -1;
	while (input == -1) {
		printf("%s (yes/no) ", str);
		if (!fgets(line, sizeof(line), stdin)) {
			warn("Operation canceled due to missing input\n");
			input = 0;
		} else if (strcasecmp(line, "yes\n") == 0 ||
			   strcasecmp(line, "y\n") == 0)
			input = 1;
		else if (strcasecmp(line, "no\n") == 0 ||
			 strcasecmp(line, "n\n") == 0) {
			warn("Operation canceled on user request\n");
			input = 0;
		} else {
			printf("Unrecognized input: %s\n", line);
			printf("Please enter 'yes' or 'y' to continue or 'no' "
			       "or 'n' to abort\n");
		}
	}
	if (input)
		rc = true;

out:
	free(str);
	return rc;
}

/* Return a newly allocated copy of string S. Exit with an error message if
 * memory could not be allocated. */
char *misc_strdup(const char *s)
{
	char *result = strdup(s);

	if (!result)
		oom();

	return result;
}

/* Return a newly allocated buffer with size SIZE. Exit with an error message
 * if memory could not be allocated. */
void *misc_malloc(size_t size)
{
	void *buffer;

	buffer = malloc(size);
	if (!buffer) {
		verb("Failed to allocate %zu bytes\n", size);
		oom();
	}
	memset(buffer, 0, size);

	return buffer;
}

/* Return a newly allocated buffer containing the result of the specified
 * string format arguments. */
char *misc_asprintf(const char *fmt, ...)
{
	char *str;
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = vasprintf(&str, fmt, args);
	va_end(args);

	if (rc == -1)
		oom();

	return str;
}

/* Run specified command and return exit code or < 0 on error. */
int misc_system(err_t err, const char *fmt, ...)
{
	char *cmd;
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = vasprintf(&cmd, fmt, args);
	va_end(args);

	if (rc == -1)
		oom();

	if (dryrun) {
		dryrun_announce(DRYRUN_CMD, cmd);
		dryrun_end_data();
		free(cmd);
		return 0;
	}

	debug("Running command: %s\n", cmd);
	rc = system(cmd);
	debug("rc=%d\n", rc);

	if (rc == -1) {
		err_t_print(err, "Could not start command: %s\n", cmd);
	} else if (WIFEXITED(rc)) {
		rc = WEXITSTATUS(rc);
		if (rc != 0) {
			err_t_print(err, "Command failed (exit code %d): %s\n",
				    rc, cmd);
		}
	} else if (WIFSIGNALED(rc)) {
		err_t_print(err, "Command failed (killed by signal %d): %s\n",
			    WTERMSIG(rc), cmd);
		rc = -2;
	} else {
		err_t_print(err, "Command failed (status %d): %s\n", rc, cmd);
		rc = -3;
	}

	free(cmd);

	return rc;
}

/* Create a new temporary file and return a newly allocated copy of its name
 * and open file descriptor. */
exit_code_t misc_mktemp(char **filename, int *fd)
{
	char template[] = "/tmp/chzdev.XXXXXX";
	int rc;

	debug("Creating temporary file\n");
	rc = mkstemp(template);
	if (rc == -1) {
		delayed_err("Could not create temporary file: %s\n",
			    strerror(errno));
		return EXIT_RUNTIME_ERROR;
	}
	if (fd)
		*fd = rc;
	else
		close(rc);
	if (filename)
		*filename = misc_strdup(template);

	return EXIT_OK;
}

/* Read a directory and add all contained filenames except . and .. to strlist
 * LIST. Apply FILTER callback to filenames if supplied. */
bool misc_read_dir(const char *path, struct util_list *list,
		   bool (*filter)(const char *, void *), void *data)
{
	DIR *dir;
	struct dirent *de;

	debug("Reading contents of directory %s\n", path);
	dir = opendir(path);
	if (!dir)
		return false;

	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.') {
			if (de->d_name[1] == 0)
				continue;
			if (de->d_name[1] == '.' && de->d_name[2] == 0)
				continue;
		}
		if (filter && !filter(de->d_name, data))
			continue;
		strlist_add(list, de->d_name);
	}

	closedir(dir);

	return true;
}

/* Print a text string indented by I spaces. */
void indent(unsigned int i, const char *format, ...)
{
	va_list args;
	char *str, *curr, *next, *last;

	/* Get text message. */
	va_start(args, format);
	if (vasprintf(&str, format, args) == -1)
		oom();
	va_end(args);

	last = str + strlen(str);
	next = str;
	while ((curr = strsep(&next, "\n"))) {
		/* Prevent extra newline at end. */
		if (curr == last)
			break;
		if (!*curr)
			printf("\n");
		else
			printf("%*s%s\n", i, "", curr);
	}
	free(str);
}

/* Allocate and initialize a new list of struct strlist_node. */
struct util_list *strlist_new(void)
{
	struct util_list *list;

	list = misc_malloc(sizeof(struct util_list));
	util_list_init(list, struct strlist_node, node);

	return list;
}

/* Release all resources associated with the specified list. */
void strlist_free(struct util_list *list)
{
	struct strlist_node *s, *n;

	if (!list)
		return;
	util_list_iterate_safe(list, s, n) {
		util_list_remove(list, s);
		free(s);
	}
	free(list);
}

/* Allocate and initialize a new list of struct strlist_node which is a
 * copy of %list. */
struct util_list *strlist_copy(struct util_list *list)
{
	struct util_list *copy;
	struct strlist_node *s;

	copy = strlist_new();
	util_list_iterate(list, s)
		strlist_add(copy, s->str);

	return copy;
}

/* Add a string to the list. */
void strlist_add(struct util_list *list, const char *fmt, ...)
{
	struct strlist_node *s;
	char *str;
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = vasprintf(&str, fmt, args);
	va_end(args);

	if (rc == -1)
		oom();

	s = misc_malloc(sizeof(struct strlist_node) + strlen(str) +
			/* NUL */ 1);
	strcpy(s->str, str);
	free(str);
	util_list_add_tail(list, s);
}

/* Add a string to the list only if it has not been previously added. Return
 * %true if string was added, %false if string was already in @list. */
bool strlist_add_unique(struct util_list *list, const char *fmt, ...)
{
	struct strlist_node *s;
	char *str;
	va_list args;
	int rc;

	va_start(args, fmt);
	rc = vasprintf(&str, fmt, args);
	va_end(args);

	if (rc == -1)
		oom();

	if (strlist_find(list, str)) {
		free(str);
		return false;
	}

	s = misc_malloc(sizeof(struct strlist_node) + strlen(str) +
			/* NUL */ 1);
	strcpy(s->str, str);
	free(str);
	util_list_add_tail(list, s);

	return true;
}

/* Parse STR as delimiter-separated list of strings and add each to LIST. */
void strlist_add_multi(struct util_list *list, const char *str,
		       const char *delim, int allow_empty)
{
	char *copy, *curr, *next;

	copy = misc_strdup(str);
	next = copy;
	while ((curr = strsep(&next, delim))) {
		if (!*curr && !allow_empty)
			continue;
		strlist_add(list, "%s", curr);
	}

	free(copy);
}

/* Find a string in a strlist. */
struct strlist_node *strlist_find(struct util_list *list, const char *str)
{
	struct strlist_node *s;

	util_list_iterate(list, s) {
		if (strcmp(s->str, str) == 0)
			return s;
	}

	return NULL;
}

/* Return a string containing all strlist_nodes concatenated by delimiter. */
char *strlist_flatten(struct util_list *list, const char *delim)
{
	size_t len, dlen, copied;
	struct strlist_node *s;
	int first;
	char *str;

	/* Determine length of resulting string. */
	dlen = strlen(delim);
	len = 1;
	first = 1;
	util_list_iterate(list, s) {
		len += strlen(s->str);
		if (first)
			first = 0;
		else
			len += dlen;
	}

	/* Combine resulting string. */
	str = misc_malloc(len);
	first = 1;
	copied = 0;
	util_list_iterate(list, s) {
		copied += sprintf(&str[copied], "%s%s", first ? "" : delim,
				  s->str);
		first = 0;
	}

	return str;
}

static void strlist_to_argv(struct util_list *list, char ***argv_ptr,
			    size_t *argc_ptr)
{
	char **argv;
	size_t argc;
	struct strlist_node *s;
	size_t i;

	argc = util_list_len(list);
	argv = misc_malloc(argc * sizeof(char *));

	i = 0;
	util_list_iterate(list, s)
		argv[i++] = misc_strdup(s->str);

	*argv_ptr = argv;
	*argc_ptr = argc;
}

/* Remove and release all elements from a strlist. */
static void strlist_clear(struct util_list *list)
{
	struct strlist_node *s, *n;

	util_list_iterate_safe(list, s, n) {
		util_list_remove(list, s);
		free(s);
	}
}

typedef int (*qsort_cmp_t)(const void *, const void *);

/* Sort entries in strlist according to compare function CMP and remove
 * duplicates. Note: CMP gets char **s as parameter. */
void strlist_sort_unique(struct util_list *list,
			 int (*cmp)(const void *, const void *))
{
	char **argv;
	size_t argc, i;
	char *last;

	if (util_list_is_empty(list))
		return;
	strlist_to_argv(list, &argv, &argc);
	qsort(argv, argc, sizeof(char *), cmp);
	strlist_clear(list);

	last = NULL;
	for (i = 0; i < argc; i++) {
		if (last && strcmp(argv[i], last) == 0)
			continue;
		last = argv[i];
		strlist_add(list, "%s", argv[i]);
	}
	for (i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
}

/* A sort function for sorting strings. */
int str_cmp(const void *a, const void *b)
{
	return strcmp(*(char * const *) a, *(char * const *) b);
}

/* Allocate and initialize a new list of pointers. */
struct util_list *ptrlist_new(void)
{
	struct util_list *list;

	list = misc_malloc(sizeof(struct util_list));
	util_list_init(list, struct ptrlist_node, node);

	return list;
}

/* Release all resources associated with the specified list. If FREE_PTR is
 * non-zero, also call free() for ptrlist_node->ptr. */
void ptrlist_free(struct util_list *list, int free_ptr)
{
	struct ptrlist_node *p, *n;

	if (!list)
		return;
	util_list_iterate_safe(list, p, n) {
		util_list_remove(list, p);
		if (free_ptr)
			free(p->ptr);
		free(p);
	}
	free(list);
}

/* Add pointer to the list. */
void ptrlist_add(struct util_list *list, void *ptr)
{
	struct ptrlist_node *s;

	s = misc_malloc(sizeof(struct ptrlist_node));
	s->ptr = ptr;
	util_list_add_tail(list, s);
}

/* Add pointer to the list before entry. */
void ptrlist_add_before(struct util_list *list, struct ptrlist_node *entry,
			void *ptr)
{
	struct ptrlist_node *s;

	s = misc_malloc(sizeof(struct ptrlist_node));
	s->ptr = ptr;
	util_list_add_prev(list, s, entry);
}

/* Find a pointer. */
static struct ptrlist_node *ptrlist_find(struct util_list *list, void *ptr)
{
	struct ptrlist_node *s;

	util_list_iterate(list, s) {
		if (s->ptr == ptr)
			return s;
	}

	return NULL;
}

/* Remove a pointer from a ptrlist. */
void ptrlist_remove(struct util_list *list, void *ptr)
{
	struct ptrlist_node *p;

	p = ptrlist_find(list, ptr);
	if (p)
		util_list_remove(list, p);
}

/* Add a pointer to the list only if it hasn't been added before. */
void ptrlist_add_unique(struct util_list *list, void *ptr)
{
	struct ptrlist_node *s;

	if (ptrlist_find(list, ptr))
		return;
	s = misc_malloc(sizeof(struct ptrlist_node));
	s->ptr = ptr;
	util_list_add_tail(list, s);
}

/* Move ptrlist_node %node from list %from to %to. */
void ptrlist_move(struct util_list *to, struct util_list *from,
		  struct ptrlist_node *node)
{
	util_list_remove(from, node);
	util_list_add_tail(to, node);
}

/* Check if file is a block or character special file. */
bool file_is_devnode(const char *path)
{
	struct stat s;

	debug("Checking if file is a device node: %s\n", path);
	if (stat(path, &s) != 0)
		return false;

	if (!S_ISBLK(s.st_mode) && !S_ISCHR(s.st_mode))
		return false;

	return true;
}

/* Remove file. */
exit_code_t remove_file(const char *path)
{
	debug("Removing file %s\n", path);
	if (dryrun) {
		dryrun_announce(DRYRUN_CMD, "rm -f %s\n", path);
		dryrun_end_data();
		return EXIT_OK;
	}

	if (unlink(path) == 0)
		return EXIT_OK;
	delayed_err("Could not remove file %s: %s\n", path, strerror(errno));

	return EXIT_RUNTIME_ERROR;
}

/* Read file as text and return NULL-terminated contents. Remove trailing
 * newline if CHOMP is specified. Handle error messages according to @err. */
char *misc_read_text_file(const char *path, int chomp, err_t err)
{
	char *buffer = NULL;
	FILE *fd;

	fd = misc_fopen(path, "r");
	if (!fd)
		goto out;

	buffer = util_file_read_fd(fd, chomp);
	misc_fclose(fd);

out:
	if (!buffer) {
		err_t_print(err, "Could not read file %s: %s\n", path,
			    strerror(errno));
	}

	return buffer;
}

/* Run a command and return its output as text string. Remove trailing
 * newline if CHOMP is specified. Handle error messages according to @err. */
char *misc_read_cmd_output(const char *cmd, int chomp, err_t err)
{
	char *buffer = NULL;
	FILE *fd;

	debug("Running command: %s\n", cmd);
	fd = popen(cmd, "r");
	if (!fd)
		goto out;

	buffer = util_file_read_fd(fd, chomp);
	pclose(fd);

out:
	if (!buffer) {
		err_t_print(err, "Could not run command %s: %s\n", cmd,
			    strerror(errno));
	}

	return buffer;
}

/* Run a configuration modifying command and return its output as text string.
 * Remove trailing newline if CHOMP is specified. Handle error messages
 * according to @err. */
char *config_read_cmd_output(const char *cmd, int chomp, err_t err)
{
	char *buffer = NULL;
	FILE *fd;

	fd = misc_popen(cmd, "r");
	if (!fd)
		goto out;

	buffer = util_file_read_fd(fd, chomp);
	misc_pclose(fd);

out:
	if (!buffer) {
		err_t_print(err, "Could not run command %s: %s\n", cmd,
			    strerror(errno));
	}

	return buffer;
}

/* Write text to file. Handle error messages according to @err. */
static int write_text(const char *path, const char *text, err_t err)
{
	size_t len = strlen(text);
	FILE *fd;
	int rc;

	fd = misc_fopen(path, "w");
	if (!fd)
		goto err;
	if (fwrite(text, 1, len, fd) != len)
		goto err;
	if (misc_fclose(fd)) {
		fd = NULL;
		goto err;
	}

	return 0;

err:
	rc = errno;
	if (err == err_print)
		error("Could not write file %s: %s\n", path, strerror(rc));
	else if (err == err_delayed_print) {
		delayed_err("Could not write file %s: %s\n", path,
			    strerror(rc));
	}
	if (fd)
		misc_fclose(fd);

	return rc;
}

exit_code_t misc_write_text_file(const char *path, const char *text, err_t err)
{
	if (write_text(path, text, err))
		return EXIT_RUNTIME_ERROR;

	return EXIT_OK;
}

/* Write a text file. If writing fails with errno EAGAIN, retry the operation
 * after a short delay. */
exit_code_t misc_write_text_file_retry(const char *path, const char *text,
				       err_t err)
{
	long delay_ns[] = {
		0,
		100000000,
		200000000,
		500000000,
	};
	int rc;
	unsigned int retry;
	struct timespec ts;

	for (retry = 0; retry < ARRAY_SIZE(delay_ns); retry++) {
		if (delay_ns[retry] > 0) {
			debug("Retrying write after %ld ns\n", delay_ns[retry]);
			ts.tv_sec = 0;
			ts.tv_nsec = delay_ns[retry];
			nanosleep(&ts, NULL);
		}
		rc = write_text(path, text, err);
		if (rc != EAGAIN)
			break;
	}

	return rc == 0 ? EXIT_OK : EXIT_RUNTIME_ERROR;
}

#define READLINE_SIZE	4096

/* Return a newly allocated string containing the contents of the symbolic link
 * at the specified path or NULL on error. */
char *misc_readlink(const char *path)
{
	char *name, *name2;
	ssize_t len;

	debug("Reading link %s\n", path);
	name = misc_malloc(READLINE_SIZE);
	len = readlink(path, name, READLINE_SIZE - 1);
	if (len < 0) {
		free(name);
		return NULL;
	}
	name[len++] = 0;

	name2 = realloc(name, len);
	return (name2) ? name2 : name;
}

/* Determine configuration set. */
config_t get_config(int active, int persistent, int autoconf)
{
	config_t config = 0;

	if (active)
		config |= config_active;
	if (persistent)
		config |= config_persistent;
	if (autoconf)
		config |= config_autoconf;

	return config;
}

/* Determine if program is running under z/VM. */
bool is_zvm(void)
{
	static int done;
	static bool zvm = false;
	char *path, *sysinfo;

	if (done)
		return zvm;

	path = path_get_proc("sysinfo");
	sysinfo = misc_read_text_file(path, 0, err_ignore);
	if (!sysinfo) {
		warn("Failed to read %s: Could not determine if system is a "
		     "z/VM guest\n", path);
	} else if (strstr(sysinfo, "\nVM00 Name:"))
		zvm = true;

	free(sysinfo);
	free(path);
	done = 1;

	return zvm;
}

bool starts_with(const char *str, const char *s)
{
	size_t len;

	len = strlen(s);

	if (strncmp(str, s, len) == 0)
		return true;
	return false;
}

bool starts_with_nocase(const char *str, const char *s)
{
	size_t len;

	len = strlen(s);

	if (strncasecmp(str, s, len) == 0)
		return true;
	return false;
}


bool ends_with(const char *str, const char *s)
{
	size_t str_len, s_len;

	str_len = strlen(str);
	s_len = strlen(s);

	if (str_len < s_len)
		return false;
	if (strcmp(str + str_len - s_len, s) != 0)
		return false;

	return true;
}

/* Split a line into an array of arguments. */
void line_split(const char *line, int *argc, char ***argv)
{
	char *t, *p, *copy, *c;
	char **a;
	int num, i;

	/* Count arguments. */
	copy = misc_strdup(line);
	c = copy;
	num = 0;
	while (strtok_r(c, " \t\n", &p)) {
		c = NULL;
		num++;
	}
	free(copy);

	/* Copy arguments. */
	a = misc_malloc(sizeof(char *) * num);
	copy = misc_strdup(line);
	c = copy;
	for (i = 0; i < num; i++) {
		t = strtok_r(c, " \n\t", &p);
		c = NULL;
		a[i] = misc_strdup(t);
	}
	free(copy);

	*argv = a;
	*argc = num;
}

void line_free(int argc, char **argv)
{
	int i;

	if (!argv)
		return;
	for (i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
}

#define BACKTRACE_MAX	32

/* Used for debugging. */
void print_trace(void)
{
	void *bt[BACKTRACE_MAX];
	char **bt_sym;
	int num, i;

	fprintf(stderr, "DEBUG: Backtrace: \n");
	num = backtrace(bt, ARRAY_SIZE(bt));
	bt_sym = backtrace_symbols(bt, num);
	for (i = 0; i < num; i++)
		fprintf(stderr, "DEBUG:  %s\n", bt_sym[i]);
	free(bt_sym);
}

/* Return a textual representation of @config. */
const char *config_to_str(config_t config)
{
	switch (config) {
	case config_active:
		return "active";
	case config_persistent:
		return "persistent";
	case config_autoconf:
		return "autoconf";
	case config_all:
		return "all";
	}
	return "multiple";
}

/* Convert textual config representation to config_t. */
bool str_to_config(const char *str, config_t *config_ptr)
{
	if (strcasecmp(str, "active") == 0)
		*config_ptr = config_active;
	else if (strcasecmp(str, "persistent") == 0)
		*config_ptr = config_persistent;
	else if (strcasecmp(str, "autoconf") == 0)
		*config_ptr = config_autoconf;
	else if (strcasecmp(str, "all") == 0)
		*config_ptr = config_all;
	else
		return false;
	return true;
}

/* Prefix special characters (backslash, double quote, newline) with a
 * backslash. Put double-quotes around string if it contains spaces or
 * @force_quotes is set. */
char *quote_str(const char *value, int force_quotes)
{
	int i, j, special, normal, spaces;
	char *str, c;

	special = spaces = normal = 0;
	for (i = 0; (c = value[i]); i++) {
		if (c == '\\' || c == '"' || c == '\n')
			special++;
		else if (isspace(c))
			spaces++;
		else
			normal++;
	}

	/* Quick exit if nothing needs escaping. */
	if (special == 0) {
		if (force_quotes || spaces > 0 ||
		    (normal + special + spaces == 0))
			return misc_asprintf("\"%s\"", value);
		else
			return misc_strdup(value);
	}

	/* Prefix all backslashes and double-quotes with a backslash. */
	str = misc_malloc(special * 2 + spaces + normal + /* quotes */ 2 +
			  /* nil */ 1);
	j = 0;
	str[j++] = '"';
	for (i = 0; (c = value[i]); i++) {
		if (c == '\\' || c == '"' || c == '\n') {
			str[j++] = '\\';
			if (c == '\n')
				c = 'n';
		}
		str[j++] = c;
	}
	str[j++] = '"';

	return str;
}

/* Remove quotes and escaping backslashes. */
char *unquote_str(const char *value)
{
	char *str, c;
	int i, j, first, last;

	str = misc_malloc(strlen(value) + 1);

	/* Find first and last non-space characters. */
	for (first = 0; value[first] && isspace(value[first]); first++);
	for (last = strlen(value) - 1; last >= first && isspace(value[last]);
	     last--);

	j = 0;
	for (i = first; i <= last; i++) {
		c = value[i];
		if (c == '"' && i == first)
			continue;
		if (i == last) {
			if (c == '"')
				break;
		} else if (c == '\\') {
			c = value[++i];
			if (c == 'n')
				c = '\n';
		}
		str[j++] = c;
	}

	return str;
}

/* Return a copy of @str without any leading or trailing whitespaces. */
char *shrink_str(const char *str)
{
	int first, last;
	char *s;

	for (first = 0; str[first] && isspace(str[first]); first++);
	for (last = strlen(str) - 1; last >= first && isspace(str[last]);
	     last--);
	s = misc_malloc(last - first + 2);
	memcpy(s, &str[first], last - first + 1);

	return s;
}

/* Mark standard output stream as being used for data. */
void set_stdout_data(void)
{
	stdout_data = 1;
}

/* Store an error message for delayed reporting. */
void delayed_err(const char *format, ...)
{
	va_list args;
	char *str;

	delayed_errors++;

	/* Get error message. */
	va_start(args, format);
	if (vasprintf(&str, format, args) == -1)
		oom();
	va_end(args);

	if (!delayed_messages)
		delayed_messages = strlist_new();
	strlist_add(delayed_messages, "Error: %s", str);
	free(str);
}

/* Store a warning message for delayed reporting. */
void delayed_warn(const char *format, ...)
{
	va_list args;
	char *str;

	/* Get warning message. */
	va_start(args, format);
	if (vasprintf(&str, format, args) == -1)
		oom();
	va_end(args);

	if (!delayed_messages)
		delayed_messages = strlist_new();
	strlist_add(delayed_messages, "Warning: %s", str);
	free(str);
}

/* Store an information message for delayed reporting. */
void delayed_info(const char *format, ...)
{
	va_list args;
	char *str;

	if (quiet)
		return;

	/* Get info message. */
	va_start(args, format);
	if (vasprintf(&str, format, args) == -1)
		oom();
	va_end(args);

	if (!delayed_messages)
		delayed_messages = strlist_new();
	strlist_add(delayed_messages, "%s", str);
	free(str);
}

/* Store a message about an error that can be overridden using --force. */
void delayed_forceable(const char *format, ...)
{
	va_list args;
	char *str;
	const char *star = force ? "" : " (*)";
	const char *severity = force ? "Warning:" : "Error:";
	int l;

	found_forceable = 1;
	delayed_errors++;

	/* Get error message. */
	va_start(args, format);
	if (vasprintf(&str, format, args) == -1)
		oom();
	va_end(args);

	/* Remove newline. */
	l = strlen(str);
	if ((l > 0) && (str[l - 1] == '\n'))
		str[l - 1] = 0;

	/* Add to delayed messages. */
	if (!delayed_messages)
		delayed_messages = strlist_new();
	strlist_add(delayed_messages, "%s %s%s\n", severity, str, star);

	free(str);
}

void delayed_print(int indent)
{
	struct strlist_node *s, *n;

	if (!delayed_messages)
		return;

	util_list_iterate_safe(delayed_messages, s, n) {
		util_list_remove(delayed_messages, s);
		if (starts_with(s->str, "Warning:") ||
		    starts_with(s->str, "Error:"))
			fprintf(stderr, "%*s%s", indent, "", s->str);
		else
			info("%*s%s", indent, "", s->str);
		free(s);
	}

	delayed_errors = 0;
}

void delayed_clear(void)
{
	if (!delayed_messages)
		return;

	strlist_clear(delayed_messages);
	delayed_errors = 0;
}

bool delayed_messages_available(void)
{
	if (!delayed_messages || util_list_is_empty(delayed_messages))
		return false;
	return true;
}

/* Determine width of terminal. */
int get_columns(void)
{
	struct winsize w;
	static int columns = -1;

	if (!is_terminal())
		return INT_MAX;
	if (columns == -1) {
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) < 0 || w.ws_col == 0)
			columns = 80;
		else
			columns = w.ws_col;
	}

	return columns;
}

FILE *misc_fopen(const char *path, const char *mode)
{
	debug("Opening file %s for mode %s\n", path, mode);

	/* Redirect writes in case of --dry-run. */
	if (dryrun && (strchr(mode, 'w') || strchr(mode, 'a'))) {
		if (verbose) {
			dryrun_announce(DRYRUN_WRITE, path);

			return dryrun_get_file();
		}
		path = "/dev/null";
	}

	return fopen(path, mode);
}

FILE *misc_popen(const char *command, const char *type)
{
	debug("Opening pipe to command %s type %s\n", command, type);

	/* Ignore command in case of --dry-run. */
	if (dryrun) {
		if (verbose) {
			dryrun_announce(DRYRUN_CMD, command);
			dryrun_end_data();
		}

		return fopen("/dev/null", type);
	}

	return popen(command, type);
}

int misc_fclose(FILE *fd)
{
	if (fd == dryrun_file) {
		dryrun_end_data();
		return 0;
	}

	return fclose(fd);
}

int misc_pclose(FILE *fd)
{
	if (fd == dryrun_file) {
		dryrun_end_data();
		return 0;
	}

	return pclose(fd);
}

bool is_terminal(void)
{
	static bool result;
	static int done;

	if (done)
		return result;
	if (isatty(fileno(stdout)))
		result = true;
	else
		result = false;
	done = 1;

	return result;
}

static const char *longrun_text;
static int longrun_shown;
static int longrun_pairs;

static void setup_timer(long usec)
{
	static struct itimerval timer;

	memset(&timer, 0, sizeof(struct itimerval));
	timer.it_value.tv_usec = usec;
	setitimer(ITIMER_REAL, &timer, NULL);
}

static void longrun_update(void)
{
	if (longrun_pairs) {
		if (!quiet) {
			printf("PROGRESS_TEXT=\"%s\" PROGRESS_CURR=\"%lu\" "
			       "PROGRESS_TOTAL=\"%lu\"\n", longrun_text,
			       longrun_current, longrun_total);
		}
	} else {
		info("\r%s: %5.1f%% (%lu/%lu)", longrun_text,
		     (100.0 * longrun_current) / longrun_total, longrun_current,
		     longrun_total);
	}
	fflush(stdout);
	longrun_shown = 1;
}

static void longrun_handler(int signal)
{
	longrun_update();
	setup_timer(LONGRUN_USEC);
}

void longrun_start(const char *text, int pairs)
{
	struct sigaction act;

	if (!is_terminal() && !pairs)
		return;

	longrun_text = text;
	longrun_pairs = pairs;
	longrun_current = 0;
	longrun_shown = 0;

	/* Setup timer for progress update. */
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = &longrun_handler;
	sigaction(SIGALRM, &act, NULL);
	setup_timer(LONGRUN_INITIAL_USEC);
}

void longrun_stop(void)
{
	struct sigaction act;

	if (!is_terminal() && !longrun_pairs)
		return;

	/* Reset timer. */
	setup_timer(0);
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_flags = SA_RESETHAND;
	sigaction(SIGALRM, &act, NULL);

	if (longrun_shown) {
		longrun_current = longrun_total;
		longrun_update();
		if (!longrun_pairs)
			info("\n");
	}
}

/* /a/b/ -> /b/ */
char *skip_comp(char *s)
{
	if (!s)
		return NULL;

	return strchr(s + 1, '/');
}

/* Swap @len bytes in @addr according to @pos. */
void byte_swap(uint8_t *addr, unsigned int *pos, unsigned num)
{
	unsigned int i;
	uint8_t s;

	for (i = 0; i < num; i++) {
		s = addr[i];
		addr[i] = addr[pos[i]];
		addr[pos[i]] = s;
	}
}

/* Check if the specified text string @str is a valid hexadecimal number. */
bool valid_hex(const char *str)
{
	char *err;

	err = NULL;
	strtoll(str, &err, 16);
	if (err && *err == 0)
		return true;

	return false;
}

void debug_init(int argc, char *argv[])
{
	int i;
	char *zdev_debug;

	zdev_debug = getenv("ZDEV_DEBUG");
	if (zdev_debug)
		debug_enabled = atoi(zdev_debug);
	if (!debug_enabled)
		return;

	fprintf(stderr, "DEBUG: Tool version: %s\n", RELEASE_STRING);
	fprintf(stderr, "DEBUG: Tool invocation: ");

	for (i = 0; i < argc; i++)
		fprintf(stderr, "%s\"%s\"", i > 0 ? ", " : "", argv[i]);
	fprintf(stderr, "\n");
}

/* Return the last occurrence of @needle in @haystack, or %NULL if @needle
 * was not found. */
char *misc_strrstr(const char *haystack, const char *needle)
{
	char *result, *next;

	result = strstr(haystack, needle);
	if (result) {
		while ((next = strstr(result + 1, needle)))
			result = next;
	}

	return result;
}

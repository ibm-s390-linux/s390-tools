/*
 * HMC Drive FUSE Filesystem (FUSE.HMCDRVFS)
 *
 * Copyright IBM Corp. 2015, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <inttypes.h>
#include <langinfo.h>
#include <libgen.h>
#include <limits.h>
#include <locale.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "lib/util_libc.h"
#include "lib/zt_common.h"

#define HMCDRV_FUSE_LOGNAME	"hmcdrvfs" /* log prefix */
#define HMCDRV_FUSE_LOGHEAD	HMCDRV_FUSE_LOGNAME ": " /* log header */
#define HMCDRV_FUSE_FTPDEV	"/dev/hmcdrv" /* DIAG/SCLP FTP device */
#define HMCDRV_FUSE_MAXPATH	192 /* max. path length (including EOS) */
#define HMCDRV_FUSE_MAXFTPLEN	3 /* max. length of FTP cmd (dir/nls/get) */
#define HMCDRV_FUSE_OFSPATH	(HMCDRV_FUSE_MAXFTPLEN + 1) /* path in cmd */
#define HMCDRV_FUSE_MAXCMDLEN	(HMCDRV_FUSE_MAXPATH + HMCDRV_FUSE_OFSPATH)

/* internal increase (margin/offset) of cache timeout with respect to FUSE
 * options 'attr_timeout' and/or 'entry_timeout' (having default 1s)
 */
#define HMCDRV_FUSE_CACHE_TMOFS 30

/* size of file name/attributes cache (should be a prime number)
 */
#define HMCDRV_FUSE_CACHE_SIZE	2053

/* number of hash table lines inspected in a single garbage loop
 */
#define HMCDRV_FUSE_GARBAGE_MAX 128

/* max. size of FTP 'dir <path>' output chunk size
 */
#define HMCDRV_FUSE_DIRBUF_SIZE (64 * 1024)

/* max. string length in FTP 'dir <path>' output buffer
 */
#define HMCDRV_FUSE_DIRBUF_LEN	(HMCDRV_FUSE_DIRBUF_SIZE - 1)


/* pointer to path (token) in FTP command string associated with file 'fp'
 */
#define HMCDRV_FUSE_PATH(fp)	((fp)->ftpcmd + HMCDRV_FUSE_OFSPATH)



/*
 * DEBUG log macro (requires -DDEBUG, else empty)
 */
#ifdef DEBUG
#define HMCDRV_FUSE_DBGLOG(fmt, ...) syslog(LOG_ERR, (fmt), ##__VA_ARGS__)
#else
#define HMCDRV_FUSE_DBGLOG(fmt, ...) do {} while (0)
#endif /* DEBUG */


/*
 * log output to 'stderr' and optionally (if from a fork'ed process/thread)
 * to syslog
 */
#define HMCDRV_FUSE_LOG(sev, fmt, ...)				\
	hmcdrv_fuse_log((sev), HMCDRV_FUSE_LOGHEAD "%s: " fmt "\n",	\
			hmcdrv_fuse_logsevname[sev], ##__VA_ARGS__)


#define HMCDRV_FUSE_STR(x)	#x
#define HMCDRV_FUSE_STRINGER(x)	HMCDRV_FUSE_STR(x)
#define HMCDRV_FUSE_RELEASE	HMCDRV_FUSE_STRINGER(S390_TOOLS_RELEASE)

#define HMCDRV_FUSE_OPT(t, p, v) { t, offsetof(struct hmcdrv_fuse_opt, p), v }


/*
 * option key IDs (used on command line parsing)
 */
enum {
	HMCDRV_FUSE_OPTKEY_VERSION, /* "-v", "--version" */
	HMCDRV_FUSE_OPTKEY_HELP, /* "-h", "--help" */
	HMCDRV_FUSE_OPTKEY_RO, /* read-only, e.g. "-o ro" or "-r" */
	HMCDRV_FUSE_OPTKEY_RW, /* option associated with -wr (ignored) */
	HMCDRV_FUSE_OPTKEY_NATM, /* option "noatime" */
	HMCDRV_FUSE_OPTKEY_CTMO, /* cache timeout (entry/attr_timeout) */
	HMCDRV_FUSE_OPTKEY_NSUP, /* unsupported options, e.g. "subdir" */
};


/*
 * internal used FTP command IDs
 */
enum hmcdrv_fuse_cmdid {
	HMCDRV_FUSE_CMDID_NLS = 0,
	HMCDRV_FUSE_CMDID_DIR = 1,
	HMCDRV_FUSE_CMDID_GET = 2,
	HMCDRV_FUSE_CMDID_SIZE
};


/*
 * options/parameters to lookup at start
 */
struct hmcdrv_fuse_opt {
	unsigned int ro:1; /* option(s) "ro", "-r", etc. */
	unsigned int noatime:1; /* option "noatime" */

	char *hmctz; /* HMC timezone option "-o hmctz=TZ" */
	char *hmclang; /* HMC locale option "-o hmclang=LANG" */
};


/*
 * HMC drive FUSE context
 */
struct hmcdrv_fuse_context {
	struct hmcdrv_fuse_opt opt; /* some saved startup options */
	int fd; /* file descriptor of FTP device HMCDRV_FUSE_FTPDEV */
	char *path; /* mount point path (root) */
	struct stat st; /* mount point stat attributes */
	time_t ctmo; /* cache timeout (derived from entry/attr_timeout) */
	pthread_t tid; /* cache aging thread ID */
	pthread_mutex_t mutex; /* cache access mutex */
	pid_t pid; /* PID of main() */
	char *abmon[12]; /* abbreviated month name of HMC locale */
	int ablen[12]; /* length of each abbreviated month name */
};


/*
 * SE/HMC drive FUSE file private data
 */
struct hmcdrv_fuse_file {
	struct hmcdrv_fuse_file *next; /* collision list (equal hash) */
	struct stat st; /* stat structure of this file */
	char *symlnk; /* pointer to path name of symlink target (S_IFLNK) */
	time_t timeout; /* cache timeout for this file */
	size_t cmdlen; /* length of FTP command + path */
	char ftpcmd[0]; /* FTP command + path (max HMCDRV_FUSE_MAXCMDLEN) */
};


/*
 * all file attributes accumulated from interpreting tokens/fields of 'dir'
 * command listing
 */
struct hmcdrv_fuse_attr {
	struct stat *st; /* pointer to stat structure */
	struct tm ftm; /* local time */
	char *fname; /* (base-) name */
};


/*
 * prototype (forward) declaration for hmcdrv_cache_dir()
 */
static struct hmcdrv_fuse_file *hmcdrv_file_get(const char *path);


/*
 * log severity strings
 */
static const char *const hmcdrv_fuse_logsevname[] = {

	"Emergency", /* (0) LOG_EMERG */
	"Alert", /* (1) LOG_ALERT */
	"Critical", /* (2) LOG_CRIT */
	"Error", /* (3) LOG_ERR */
	"Warning", /* (4) LOG_WARNING */
	"Notice", /* (5) LOG_NOTICE */
	"Info", /* (6) LOG_INFO */
	"Debug" /* (7) DEBUG */
};


/*
 * file attributes cache
 */
static struct hmcdrv_fuse_file *hmcdrv_fuse_cache[HMCDRV_FUSE_CACHE_SIZE];


/*
 * context
 */
static struct hmcdrv_fuse_context hmcdrv_ctx = {
	.fd = -1,
	.ctmo = 1 + HMCDRV_FUSE_CACHE_TMOFS,
	.mutex = PTHREAD_MUTEX_INITIALIZER,
};


/*
 * log output from hmcdrvfs daemon
 */
static void hmcdrv_fuse_log(int sev, const char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	vfprintf(stderr, fmt, argp); /* always to stderr */
	va_end(argp);

	if (hmcdrv_ctx.pid != getpid()) {
		struct fuse_context *fctx = fuse_get_context();

		if ((fctx != NULL) && (hmcdrv_ctx.pid != fctx->pid)) {
			va_start(argp, fmt);
			vsyslog(sev,
				fmt + (sizeof(HMCDRV_FUSE_LOGHEAD) - 1),
				argp);
			va_end(argp);
		}
	}
}


/*
 * calculate a hash value from a file path
 */
static unsigned int hmcdrv_hash_path(const char *path)
{
	unsigned int hash = ~0;
	int len = strlen(path);

	while (len > 0) {
		hash += (unsigned) *path;

		++path;
		--len;
	}

	hash %= HMCDRV_FUSE_CACHE_SIZE;
	return hash;
}


/*
 * restart of cache entry aging time
 */
static void hmcdrv_cache_trestart(struct hmcdrv_fuse_file *fp)
{
	fp->timeout = time(NULL) + hmcdrv_ctx.ctmo;
}


/*
 * update or free symlink information
 */
static void hmcdrv_cache_symlink(struct hmcdrv_fuse_file *fp,
				const char *symlink)
{
	if (fp->symlnk != NULL) {
		free(fp->symlnk);
		fp->symlnk = NULL;
	}

	if ((symlink != NULL) && (symlink[0] != '\0')) {
		fp->symlnk = malloc(HMCDRV_FUSE_MAXPATH);

		if (fp->symlnk != NULL) {
			util_strlcpy(fp->symlnk, symlink, HMCDRV_FUSE_MAXPATH);
			fp->symlnk[HMCDRV_FUSE_MAXPATH - 1] = '\0';
		}
	}
}



/*
 * refresh the attributes of file/directory 'path'
 * note: if there is no cache entry for this file, then create one
 */
static void hmcdrv_cache_refresh(const char *path, const struct stat *st,
				const char *symlink)
{
	struct hmcdrv_fuse_file **pbase; /* storage location of fp */
	struct hmcdrv_fuse_file *fp;
	unsigned int index;

	int pathlen = strlen(path);

	if ((pathlen == 0) || (pathlen >= HMCDRV_FUSE_MAXPATH)) {
		HMCDRV_FUSE_LOG(LOG_WARNING,
				"Invalid path length for '%s'", path);
		return;
	}

	index = hmcdrv_hash_path(path);
	pbase = &hmcdrv_fuse_cache[index];
	fp = *pbase;

	while (fp != NULL) {
		if (strcmp(HMCDRV_FUSE_PATH(fp), path) == 0) {
			fp->st = *st;		   /* update file info */
			hmcdrv_cache_symlink(fp, symlink);
			hmcdrv_cache_trestart(fp); /* restart aging */
			return;
		}

		pbase = &fp->next;
		fp = fp->next;
	}

	/* entry does not exist so far - create new one
	 */
	fp = malloc((offsetof(struct hmcdrv_fuse_file, ftpcmd) +
		     HMCDRV_FUSE_OFSPATH + 1) + pathlen);

	if (fp == NULL) {
		HMCDRV_FUSE_LOG(LOG_ERR, "Out of memory, %ld bytes",
				(offsetof(struct hmcdrv_fuse_file, ftpcmd) +
				 HMCDRV_FUSE_OFSPATH + 1) + pathlen);
	} else {
		*pbase = fp;
		fp->cmdlen = pathlen + HMCDRV_FUSE_OFSPATH;
		fp->st = *st;
		memcpy(HMCDRV_FUSE_PATH(fp), path, pathlen + 1);
		fp->symlnk = NULL;
		hmcdrv_cache_symlink(fp, symlink);
		hmcdrv_cache_trestart(fp);
		fp->next = NULL;
	}
}


/*
 * search for a file/directory path in cache
 */
static struct hmcdrv_fuse_file *hmcdrv_cache_find(const char *path)
{
	unsigned index = hmcdrv_hash_path(path);
	struct hmcdrv_fuse_file *fp = hmcdrv_fuse_cache[index];

	while (fp != NULL) {
		if (strcmp(HMCDRV_FUSE_PATH(fp), path) == 0) {
			hmcdrv_cache_trestart(fp);
			return fp;
		}

		fp = fp->next;
	}

	return NULL;
}


/*
 * check for aging timeout of cache entry at index
 */
static void hmcdrv_cache_expire(unsigned index, time_t now)
{
	struct hmcdrv_fuse_file **pbase; /* storage location of fp */
	struct hmcdrv_fuse_file *fp, *next;

	pbase = &hmcdrv_fuse_cache[index];
	fp = *pbase;

	/* iterate the collision list */
	while (fp != NULL) {
		next = fp->next;

		if ((fp->timeout <= now) &&
		    (strcmp(HMCDRV_FUSE_PATH(fp), "/") != 0)) {
			hmcdrv_cache_symlink(fp, NULL);
			*pbase = next;
			free(fp);
		} else {
			pbase = &fp->next;
		}

		fp = next;
	}
}


/*
 * cache expiry handler thread
 */
static void *hmcdrv_cache_aging(void *UNUSED(arg))
{
	unsigned int cnt;
	time_t now;

	unsigned index = 0;

	while (1) {
		sleep(1);

		pthread_mutex_lock(&hmcdrv_ctx.mutex);
		now = time(NULL);

		/* each second scan a number of cache entries
		 */
		for (cnt = 0; cnt < HMCDRV_FUSE_GARBAGE_MAX; ++cnt) {

			hmcdrv_cache_expire(index, now);

			if (++index == HMCDRV_FUSE_CACHE_SIZE)
				index = 0;
		}

		pthread_mutex_unlock(&hmcdrv_ctx.mutex);
	}

	return NULL;
}


/*
 * convert a FTP command ID into a string
 *
 * Note: If a command string is shorter than HMCDRV_FUSE_MAXFTPLEN then
 *       define it right-aligned (prefixed with spaces) in table 'cmdstr'.
 */
static void hmcdrv_ftp_str(enum hmcdrv_fuse_cmdid cmd, char *ftp)
{
	static const char *cmdstr[HMCDRV_FUSE_CMDID_SIZE] = {

#if (HMCDRV_FUSE_MAXFTPLEN != 3)
#error The length of strings in cmdstr[] must match HMCDRV_FUSE_MAXFTPLEN
#endif
		"nls", /* HMCDRV_FUSE_CMDID_NLS */
		"dir", /* HMCDRV_FUSE_CMDID_DIR */
		"get"  /* HMCDRV_FUSE_CMDID_GET */
	};

	strcpy(ftp, cmdstr[cmd]);
	ftp[HMCDRV_FUSE_MAXFTPLEN] = ' '; /* overwrite '\0' from strcpy() */
}


/*
 * FTP command execution via kernel device
 */
static ssize_t hmcdrv_ftp_transfer(struct hmcdrv_fuse_file *fp, char *buf,
				   size_t len, off_t offset)
{
	static off_t current_offset;
	static char last_ftpcmd[HMCDRV_FUSE_MAXCMDLEN];

	ssize_t retlen;

	/*
	 * First check if this is a sequential read from the same file.	 If
	 * so skip repositioning the files seek pointer and emitting a new
	 * command.
	 */
	if ((offset != current_offset) ||
	    (strncmp(fp->ftpcmd, last_ftpcmd, HMCDRV_FUSE_MAXCMDLEN) != 0)) {

		if ((lseek(hmcdrv_ctx.fd, offset, SEEK_END) < 0) ||
		    (write(hmcdrv_ctx.fd, fp->ftpcmd, fp->cmdlen) < 0)) {
			last_ftpcmd[0] = '\0';
			return -errno;
		}

		current_offset = offset;
	}

	retlen = read(hmcdrv_ctx.fd, buf, len);

	if (retlen < 0) {
		last_ftpcmd[0] = '\0';
		return -errno;
	}

	current_offset += retlen;
	util_strlcpy(last_ftpcmd, fp->ftpcmd, HMCDRV_FUSE_MAXCMDLEN);
	return retlen;
}


/*
 * FTP command assembly and execution
 */
static ssize_t hmcdrv_ftp_cmd(struct hmcdrv_fuse_file *fp,
			      enum hmcdrv_fuse_cmdid cmd,
			      char *buf, size_t len, off_t offset)
{
	if (fp == NULL)
		return -EBADF;

	hmcdrv_ftp_str(cmd, fp->ftpcmd);
	return hmcdrv_ftp_transfer(fp, buf, len, offset);
}



/*
 * returns a file path (from internal file structure) to a buffer,
 * with appending a slash (in case it is missing)
 */
static int hmcdrv_path_copy(struct hmcdrv_fuse_file *fp, char *dest)
{
	char *src = HMCDRV_FUSE_PATH(fp);
	int len = 0;

	while ((len < (HMCDRV_FUSE_MAXPATH - 1)) &&
	       (*src != '\0')) {

		*dest = *src;

		++len;
		++dest;
		++src;
	}

	if ((len > 0) && (*(dest - 1) != '/')) {
		*dest++ = '/';
		++len;
	}

	*dest = '\0';
	return len;
}


/*
 * convert a string into into a unsigned number,
 * returning 0 on success or -errno on error
 */
static int hmcdrv_parse_uint(const char *s, unsigned int *pval)
{
	errno = 0;
	*pval = strtoul(s, NULL, 10);
	return -errno;
}


/*
 * convert a string into into a signed number (with range check),
 * returning 0 on success or -errno on error
 */
static int hmcdrv_parse_int(const char *s, int vmin, int vmax, int *pval)
{
	errno = 0;
	*pval = strtol(s, NULL, 10);

	if (errno == 0) {
		if ((*pval >= vmin) && (*pval <= vmax))
			return 0;

		errno = ERANGE;
	}

	return -errno;
}


/*
 * convert an abbreviated month name (%b) into a number
 */
static int hmcdrv_parse_month(const char *s)
{
	int i;

	for (i = 0; i < 12; ++i) {
		if (strncasecmp(hmcdrv_ctx.abmon[i], s,
				hmcdrv_ctx.ablen[i]) == 0)
			return i;
	}

	return -1;
}


/*
 * return the file mode from a 'ls -l' like mode string
 */
static mode_t hmcdrv_parse_mode(const char *s)
{
	int i;
	mode_t type;
	mode_t mode = 0;

	switch (*s) {
	case 'd': /* directory */
		type = S_IFDIR;
		break;

	case 'b': /* block device */
		type = S_IFBLK;
		break;

	case 'c': /* character device */
		type = S_IFCHR;
		break;

	case 'l': /* symbolic link */
		type = S_IFLNK;
		break;

	case 'p': /* FIFO */
		type = S_IFIFO;
		break;

	case 's': /* socket */
		type = S_IFSOCK;
		break;

	case '-':
		type = S_IFREG;
		break;

	default:
		return 0;
	}

	for (i = 0; i < 9; ++i) {
		mode <<= 1;

		switch (*++s) {
		case 'r':
		case 'w':
		case 'x':
			mode |= 1;
			break;

		case '-':
			break;

		default:
			return 0;
		}

	}

	mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
	return mode | type;
}


/*
 * convert a time string from format "%H:%M" into a 'struct tm' (without any
 * local time conversion)
 */
static int hmcdrv_parse_time(const char *s, struct tm *t)
{
	char *endptr;
	int hour, minute;

	errno = 0;
	hour = strtol(s, &endptr, 10);

	if ((errno == 0) && (endptr != s) &&
	    (hour >= 0) && (hour < 24)) {
		if (*endptr == ':') {
			s = ++endptr;
			errno = 0;
			minute = strtol(s, &endptr, 10);

			if ((errno == 0) && (endptr != s) &&
			    (minute >= 0) && (minute < 60)) {

				t->tm_hour = hour;
				t->tm_min = minute;

				return 0; /* success */
			}
		}
	}

	return -1;
}


/*
 * interpret token depending on current field number and
 * fill the attributes structure
 *
 * Return: 'field' incremented by 1 or INT_MAX on parse errors
 */
static int hmcdrv_parse_ntoken(int field, char *token,
			       struct hmcdrv_fuse_attr *attr)
{
	switch (field) {
	case 0: /* mode */
		attr->st->st_mode = hmcdrv_parse_mode(token);

		if (attr->st->st_mode == 0) /* error ? */
			field = INT_MAX - 1; /* stop */
		break;

	case 1: /* number of hard links to this file */
		errno = 0;
		attr->st->st_nlink = strtoul(token, NULL, 10);

		if (errno != 0)
			field = INT_MAX - 1;
		break;

	case 2: /* user ID */
		if (hmcdrv_parse_uint(token, &attr->st->st_uid) != 0) {
			attr->st->st_uid = hmcdrv_ctx.st.st_uid;
			HMCDRV_FUSE_LOG(LOG_WARNING,
					"Could not parse UID (will use %u)",
					attr->st->st_uid);
		}

		break;

	case 3: /* group ID */
		if (hmcdrv_parse_uint(token, &attr->st->st_gid) != 0) {
			attr->st->st_gid = hmcdrv_ctx.st.st_gid;
			HMCDRV_FUSE_LOG(LOG_WARNING,
					"Could not parse GID (will use %u)",
					attr->st->st_gid);
		}

		break;

	case 4: /* file size */
		errno = 0;
		attr->st->st_size = strtol(token, NULL, 10);

		if (errno != 0)
			field = INT_MAX - 1;
		break;

	case 5: /* month of year [0,11] */
		attr->ftm.tm_mon = hmcdrv_parse_month(token);
		break;

	case 6: /* day of month [1,31] */
		if (hmcdrv_parse_int(token, 1, 31, &attr->ftm.tm_mday) != 0) {
			field = INT_MAX - 1;
		} else {
			/*
			 * in case month is not in English language we've
			 * got an error in attr->ftm.tm_mon
			 */
			if (attr->ftm.tm_mon < 0) {
				attr->ftm.tm_mday = 1; /* YYYY-01-01 */
				attr->ftm.tm_mon = 0;
			}
		}

		break;

	case 7: /* %H:%M or %Y */
		if (hmcdrv_parse_time(token, &attr->ftm) != 0) {
			if (hmcdrv_parse_int(token, 1900, INT_MAX,
					     &attr->ftm.tm_year) != 0)
				field = INT_MAX - 1;
			else
				attr->ftm.tm_year -= 1900;
		}

		break;

	case 8: /* file name (rest of line) */
		attr->fname = token;
		break;


	default:
		break;
	}

	return ++field;
}


/*
 * parse filename and attributes from 'dir' output (a single line)
 *
 * Note: Because HMC command 'dir' always uses the HMC server local time the
 *       current timezone should be set correctly, based on startup option
 *       "-o hmctz=TZ".
 *
 * Return: pointer to start of next line (skipping any whitespace)
 *         or pointer to '\0'
 */
static char *hmcdrv_parse_line(char *line, char *namebuf,
			       int bufsize, struct stat *st,
			       char *symlink)
{
	int field = 0;
	struct hmcdrv_fuse_attr attr = {.fname = NULL, .st = st};

	memset(st, 0, sizeof(*st));
	namebuf[0] = '\0';

	/* set default values
	 */
	st->st_mtime = time(NULL);  /* see next line: gmtime_r() */
	gmtime_r(&st->st_mtime, &attr.ftm);   /* tm_year default */
	attr.ftm.tm_isdst = -1; /* mktime() should use "TZ" info */
	attr.ftm.tm_hour = attr.ftm.tm_min = attr.ftm.tm_sec = 0;

	while ((*line != '\0') && isspace(*line))
		++line; /* skip leading whitespace (incl. newlines) */


	while ((*line != '\0') && (*line != '\n') && (field < 9)) {

		while ((*line != '\0') &&
		       (*line != '\n') &&
		       isspace(*line))
			++line; /* skip spaces, but not newlines */

		if ((*line != '\0') && (*line != '\n')) {
			field = hmcdrv_parse_ntoken(field, line, &attr);

			while ((*line != '\0') && (*line != '\n')) {
				if (isspace(*line))
					break;
				if (field == 1 && isdigit(*line))
					break;
				++line; /* search end of field */
			}
		}
	} /* while */

	/* search end of line now (skips some fields in case of error)
	 */
	while ((*line != '\0') && (*line != '\n'))
		++line;

	/*
	 * If start of file name was found by parser, then indicate success
	 * returning the file attributes.  But do this only if the end of
	 * line was really found, else this seems to be an incomplete line
	 * in current chunk (fragment).
	 */
	if ((attr.fname != NULL) && (*line == '\n')) {
		char *arrow = NULL; /* " -> " pointer, when symlink */
		*line = '\0'; /* temporary set EOS for strncpy() */

		if (S_ISLNK(st->st_mode)) {
			arrow = strstr(attr.fname, " -> ");

			if (arrow != NULL)
				*arrow = '\0';
		}

		util_strlcpy(namebuf, attr.fname, bufsize);

		if (arrow == NULL) {
			symlink[0] = '\0';
		} else {
			util_strlcpy(symlink, arrow + 4, HMCDRV_FUSE_MAXPATH);
			*arrow = ' '; /* restore */
		}

		*line = '\n'; /* restore */
		st->st_mtime = mktime(&attr.ftm); /* UTC from local time */

		if (st->st_mtime == (time_t) -1)
			st->st_mtime = 0;

		st->st_atime = st->st_ctime = st->st_mtime;

		/* In contrast to FUSE documentation the members below must
		 * be set in stat structure.  For example 'du' uses them,
		 * because it shows the disk usage from used blocks and not
		 * the file size (unless option '--apparent-size' is given).
		 */
		st->st_blksize = 2048U; /* nearly all CD/DVDs have this */
		st->st_blocks = (st->st_size + 511U) / 512U;
	}


	while ((*line != '\0') && isspace(*line))
		++line; /* skip whitespace after EOL, incl. newlines */

	return line;
}


/*
 * performs a FTP 'dir', then scans/parses the output, fills the cache and
 * (optional) calls the FUSE filler function for every file in 'dir' listing
 */
static int hmcdrv_cache_dir(const char *dir, fuse_fill_dir_t filler, void *buf)
{
	char path[HMCDRV_FUSE_MAXPATH]; /* constructed path of a file */
	char symlink[HMCDRV_FUSE_MAXPATH]; /* target of symlink (S_IFLNK) */
	struct hmcdrv_fuse_file *fpdir; /* directory file pointer */
	struct stat st; /* attributes of file */
	char *dirbuf; /* 'dir' listing (chunk) buffer */
	char *next; /* 'next line' pointer in 'dir' buffer */
	char *line; /* current line start position in 'dir' buffer */
	int dirlen; /* number of characters in 'dir' buffer */
	int fraglen; /* fragment length in 'dir' buffer */
	char *fname; /* buffer pointer for basename of file */
	int len; /* maximum length of file basename (buffer space) */
	off_t offset; /* device 'dir' position */

	char *tzenv = NULL; /* "TZ" environment variable */

	fpdir = hmcdrv_file_get(dir);

	if (fpdir == NULL) {
		HMCDRV_FUSE_LOG(LOG_ERR,
				"Could not find directory '%s' in cache",
				dir);
		return -ENOENT;
	}

	dirbuf = malloc(HMCDRV_FUSE_DIRBUF_SIZE);

	if (dirbuf == NULL) {
		HMCDRV_FUSE_LOG(LOG_ERR,
				"Out of memory, %d bytes",
				HMCDRV_FUSE_DIRBUF_SIZE);
		return -ENOMEM;
	}

	/* set HMC timezone (optional), else host timezone remains active -
	 * possibly different from HMC timezone and so resulting in wrong
	 * file modification times (cf. mktime() in hmcdrv_parse_line())
	 */
	if (hmcdrv_ctx.opt.hmctz != NULL) { /* "-o hmctz=TZ" present ? */
		tzenv = getenv("TZ");

		if (tzenv != NULL)
			tzenv = strdup(tzenv);

		if (setenv("TZ", hmcdrv_ctx.opt.hmctz, 1) != 0) {
			HMCDRV_FUSE_LOG(LOG_ERR,
					"Could not set HMC timezone '%s': %s",
					hmcdrv_ctx.opt.hmctz,
					strerror(errno));

			if (tzenv != NULL) {
				setenv("TZ", tzenv, 1);
				free(tzenv);
			}

			free(dirbuf);
			return -ENOMEM;
		}

		tzset();
	}

	len = hmcdrv_path_copy(fpdir, path); /* get directory path */
	fname = path + len; /* start of basename in path buffer */
	len = HMCDRV_FUSE_MAXPATH - len; /* space for basename */
	HMCDRV_FUSE_DBGLOG("scanning '%s'...", path);

	/* do the 'dir' chunks and parse all
	 */
	dirlen = hmcdrv_ftp_cmd(fpdir, HMCDRV_FUSE_CMDID_DIR,
				dirbuf, HMCDRV_FUSE_DIRBUF_LEN, 0);
	next = dirbuf; /* first line at start of buffer */
	offset = dirlen;

	while (dirlen > 0) {

		next[dirlen] = '\0'; /* force end of string */

		/* parse all files in this 'dir' listing chunk
		 */
		do {
			line = next;

			/* parse next line and retrieve the file name
			 */
			next = hmcdrv_parse_line(line, fname, len,
						 &st, symlink);

			/* If parsing of 'dir' line was successful, then
			 * store file attributes and name in cache. Else
			 * skip this line because of incorrect syntax -
			 * possibly it is a fragment (at end of buffer) or
			 * this line does not hold any valid file info.
			 */
			if (*fname != '\0') {
				hmcdrv_cache_refresh(path, &st, symlink);

				if ((filler != NULL) &&
				    (filler(buf, fname, &st, 0, 0) != 0))
					filler = NULL; /* stop filling */
#ifdef DEBUG
				strftime(symlink, sizeof(symlink),
					 "%c", gmtime(&st.st_mtime));
				HMCDRV_FUSE_DBGLOG(" * %s (size=%zu, mode=%o, uid=%u, gid=%u, time=%s)",
						   fname,
						   st.st_size, st.st_mode,
						   st.st_uid, st.st_gid,
						   symlink);
#endif
			}

		} while (*next != '\0');

		/* Try to read more bytes from the FTP device. But regard
		 * remaining chars from the last line, in case it could not
		 * completely parsed (in other words the line was a
		 * fragment, and has to be moved to start of buffer).
		 */
		if (*fname == '\0') { /* no valid filename? */
			fraglen = next - line;

			if (fraglen > 0)
				memcpy(dirbuf, line, fraglen);
		} else {
			fraglen = 0;
		}

		dirlen = hmcdrv_ftp_cmd(fpdir, HMCDRV_FUSE_CMDID_DIR,
					dirbuf + fraglen,
					HMCDRV_FUSE_DIRBUF_LEN - fraglen,
					offset);

		if (dirlen > 0) { /* on success continue */
			next = dirbuf;
			offset += dirlen;
			dirlen += fraglen;
		}
	}


	free(dirbuf);

	/* restore old host timezone
	 */
	if (hmcdrv_ctx.opt.hmctz != NULL) {
		if (tzenv != NULL) {
			putenv(tzenv);
			free(tzenv);
		} else {
			unsetenv("TZ");
		}

		tzset();
	}

	return dirlen;
}


/*
 * cache all files located in parent directory of 'dir',
 * so also caching the attributes of 'dir' again
 *
 * Return: 0 on success, else a negative error code (-ENOENT if 'dir' is "/")
 */
static int hmcdrv_cache_parent(const char *dir)
{
	char *tmp, *parent;

	if (strcmp(dir, "/") == 0) /* root has no parent */
		return -ENOENT;

	tmp = strdup(dir); /* need a copy because of dirname() */

	if (tmp == NULL) {
		HMCDRV_FUSE_LOG(LOG_ERR, "Out of memory, %zd bytes",
				strlen(dir) + 1);
		return -ENOMEM;
	}

	parent = dirname(tmp);
	HMCDRV_FUSE_DBGLOG("re-scanning parent '%s'...", parent);
	hmcdrv_cache_dir(parent, NULL, NULL);
	free(tmp);
	return 0;
}


/*
 * return the file attributes data pointer (or NULL on error)
 */
static struct hmcdrv_fuse_file *hmcdrv_file_get(const char *path)
{
	struct hmcdrv_fuse_file *fp = hmcdrv_cache_find(path);

	if (fp != NULL) /* path found in cache ? */
		return fp;

	/* in very, very rare cases we must scan the parent again,
	 * recursive up to the root directory
	 */
	if (hmcdrv_cache_parent(path) != 0)
		return NULL;

	/* because the mutex is taken by the caller, we MUST find this file
	 * now in cache (if not so then the HMC drive DVD may have changed
	 * without unmounting FUSE.HMCDRVFS)
	 */
	return hmcdrv_cache_find(path);
}


/*
 * obtain file status information (attributes) on FUSE.HMCDRVFS filesystem
 *
 * Note: The most important function which FUSE calls (very often).
 */
static int hmcdrv_fuse_getattr(const char *path, struct stat *stbuf)
{
	struct hmcdrv_fuse_file *fp;
	int rc = 0;

	pthread_mutex_lock(&hmcdrv_ctx.mutex);
	fp = hmcdrv_file_get(path);

	if (fp == NULL)
		rc = -ENOENT;
	else
		*stbuf = fp->st;

	pthread_mutex_unlock(&hmcdrv_ctx.mutex);
	return rc;
}


/*
 * get symlink target path
 */
static int hmcdrv_fuse_readlink(const char *path, char *buf, size_t size)
{
	struct hmcdrv_fuse_file *fp;
	int rc = 0;

	pthread_mutex_lock(&hmcdrv_ctx.mutex);
	fp = hmcdrv_file_get(path);

	if (fp == NULL) {
		rc = -ENOENT;
	} else {
		if (fp->symlnk == NULL) {
			rc = -ENOMEM;
		} else {
			if (!S_ISLNK(fp->st.st_mode)) {
				rc = -EINVAL;
			} else {
				util_strlcpy(buf, fp->symlnk, size);
			}
		}
	}

	pthread_mutex_unlock(&hmcdrv_ctx.mutex);
	return rc;
}


/*
 * open a directory on FUSE.HMCDRVFS filesystem
 */
static int hmcdrv_fuse_opendir(const char *UNUSED(path),
			       struct fuse_file_info *fi)
{
	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES; /* all files are read-only */

	return 0;
}


/*
 * read a directory on FUSE.HMCDRVFS filesystem
 */
static int hmcdrv_fuse_readdir(const char *path, void *buf,
			       fuse_fill_dir_t filler, off_t UNUSED(offset),
			       struct fuse_file_info *UNUSED(fi))
{
	int ret;

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);

	pthread_mutex_lock(&hmcdrv_ctx.mutex);
	ret = hmcdrv_cache_dir(path, filler, buf);
	pthread_mutex_unlock(&hmcdrv_ctx.mutex);
	return ret;
}


/*
 * open a file on FUSE.HMCDRVFS filesystem
 */
static int hmcdrv_fuse_open(const char *UNUSED(path), struct fuse_file_info *fi)
{
	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES; /* all files are read-only */

	return 0;
}


/*
 * read a file on FUSE.HMCDRVFS filesystem
 */
static int hmcdrv_fuse_read(const char *path, char *buf, size_t size,
			    off_t offset, struct fuse_file_info *UNUSED(fi))
{
	struct hmcdrv_fuse_file *fp;
	int rc;

	pthread_mutex_lock(&hmcdrv_ctx.mutex);
	fp = hmcdrv_file_get(path);

	if (fp == NULL)
		rc = -ENOENT;
	else
		rc = hmcdrv_ftp_cmd(fp, HMCDRV_FUSE_CMDID_GET,
				    buf, size, offset);

	pthread_mutex_unlock(&hmcdrv_ctx.mutex);
	return rc;
}


/*
 * initialize FUSE.HMCDRVFS filesystem
 *
 * Note: calls fuse_exit() on errors
 *
 * Return: value to be passed in the private_data field of fuse_context to
 *         all file operations and as a parameter to the destroy() method
 */
static void *hmcdrv_fuse_init(struct fuse_conn_info *UNUSED(conn))
{
	pthread_mutexattr_t attr;

	memset(hmcdrv_fuse_cache, 0, sizeof(hmcdrv_fuse_cache));
	openlog(HMCDRV_FUSE_LOGNAME, LOG_PID, LOG_DAEMON);

	if (pthread_mutexattr_init(&attr) != 0)
		goto err_out;

	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	hmcdrv_ctx.fd = open(HMCDRV_FUSE_FTPDEV, O_RDWR);

	if (hmcdrv_ctx.fd < 0)
		goto err_dev;

	if (pthread_mutex_init(&hmcdrv_ctx.mutex, &attr) != 0)
		goto err_mutex;

	hmcdrv_cache_refresh("/", &hmcdrv_ctx.st, NULL); /* never expires */

	if (pthread_create(&hmcdrv_ctx.tid, NULL,
			   hmcdrv_cache_aging, NULL) == 0) {

		pthread_mutexattr_destroy(&attr);
		return &hmcdrv_ctx.tid;
	}

err_mutex:
	close(hmcdrv_ctx.fd);
err_dev:
	pthread_mutexattr_destroy(&attr);
err_out:
	HMCDRV_FUSE_LOG(LOG_ERR, "Initialization failed: %s",
			strerror(errno));
	closelog();
	fuse_exit(fuse_get_context()->fuse);
	return NULL;
}


/*
 * clean up FUSE.HMCDRVFS filesystem
 */
static void hmcdrv_fuse_exit(void *arg)
{
	struct hmcdrv_fuse_file *fp, *next;
	int i;

	if (arg != NULL)
		pthread_cancel(*(pthread_t *) arg);

	pthread_mutex_lock(&hmcdrv_ctx.mutex);

	for (i = 0; i < HMCDRV_FUSE_CACHE_SIZE; ++i) {
		fp = hmcdrv_fuse_cache[i];

		while (fp != NULL) {
			next = fp->next;
			hmcdrv_cache_symlink(fp, NULL);
			free(fp);
			fp = next;
		}
	}

	memset(hmcdrv_fuse_cache, 0, sizeof(hmcdrv_fuse_cache));
	pthread_mutex_destroy(&hmcdrv_ctx.mutex);
	closelog();

	if (hmcdrv_ctx.fd >= 0)
		close(hmcdrv_ctx.fd);
}


/*
 * FUSE.HMCDRVFS internal main function
 */
static int hmcdrv_fuse_main(struct fuse_args *args)
{
	static struct fuse_operations hmcdrv_fuse_op = {
		.init = hmcdrv_fuse_init,
		.destroy = hmcdrv_fuse_exit,
		.getattr = hmcdrv_fuse_getattr,
		.opendir = hmcdrv_fuse_opendir,
		.readdir = hmcdrv_fuse_readdir,
		.open = hmcdrv_fuse_open,
		.read = hmcdrv_fuse_read,
		.readlink = hmcdrv_fuse_readlink
	};


#if FUSE_VERSION >= 26
	return fuse_main(args->argc, args->argv, &hmcdrv_fuse_op, NULL);
#else
	return fuse_main(args->argc, args->argv, &hmcdrv_fuse_op);
#endif
}


/*
 * usage output
 */
static void hmcdrv_fuse_usage(const char *progname)
{
	fprintf(stdout,
		"Usage: %s MOUNTPOINT [OPTIONS]\n\n"
		"Use the %s command to read files from a HMC drive DVD.\n"
		"\n"
		"General options:\n"
		"    -o opt,[opt...]        Mount options\n"
		"    -h   --help            Print help, then exit\n"
		"    -v   --version         Print version, then exit\n"
		"\n"
		"Specific options:\n"
		"    -o hmclang=LANG        HMC speaks language LANG (see locale(1))\n"
		"    -o hmctz=TZ            HMC is in timezone TZ (see tzset(3))\n"
		"\n"
		"Attention:\n"
		"    The following general and FUSE specific mount options will\n"
		"    be ignored (most do not make sense on a read-only media):\n"
		"    --rw, -w, -o rw, -o atime, -o max_write=N, -o big_writes,\n"
		"    -o atomic_o_trunc, -o hard_remove, -o negative_timeout=T,\n"
		"    -o use_ino, -o readdir_ino, -o subdir=DIR\n"
		"\n",
		progname, progname);
}


/*
 * process the "-o hmclang=LANG" command line option (if there is one) and
 * prepare abbreviated month names (%b) in context structure
 *
 * Return: 0 on success, -1 on error
 */
static int hmcdrv_optproc_lang(void)
{
	static const nl_item nl_abmon[12] = {
		ABMON_1, ABMON_2, ABMON_3, ABMON_4, ABMON_5, ABMON_6,
		ABMON_7, ABMON_8, ABMON_9, ABMON_10, ABMON_11, ABMON_12};

	unsigned int i;
	char *lc = NULL; /* current LC_TIME locale */

	if (hmcdrv_ctx.opt.hmclang != NULL) {
		HMCDRV_FUSE_DBGLOG("option \"-o hmclang=%s\" detected",
				   hmcdrv_ctx.opt.hmclang);

		lc = setlocale(LC_TIME, NULL);

		if (setlocale(LC_TIME, hmcdrv_ctx.opt.hmclang) == NULL) {
			setlocale(LC_TIME, lc);
			return -1;
		}
	}

	for (i = 0; i < (sizeof(nl_abmon) / sizeof(nl_abmon[0])); ++i) {
		hmcdrv_ctx.abmon[i] = nl_langinfo(nl_abmon[i]);
		hmcdrv_ctx.ablen[i] = strlen(hmcdrv_ctx.abmon[i]);
	}

	if (lc)
		setlocale(LC_TIME, lc); /* restore LC_TIME locale */

	return 0;
}


/*
 * option parsing function
 */
static int hmcdrv_fuse_optproc(void *data, const char *arg,
			       int key, struct fuse_args *outargs)
{
	double tmo; /* timeout T in "-o entry/attr_timeout=T" */
	mode_t mask; /* umask() of caller */

	(void)outargs;

	switch (key) {
	case HMCDRV_FUSE_OPTKEY_NSUP:
		HMCDRV_FUSE_LOG(LOG_WARNING,
				"FUSE option \"%s\" ignored (unsupported)",
				arg);
		return 0; /* remove this option(s) */

	case HMCDRV_FUSE_OPTKEY_RW: /* write options (unsupported) */
		HMCDRV_FUSE_LOG(LOG_WARNING,
				"FUSE option \"%s\" ignored (r/o filesystem)",
				arg);
		return 0; /* remove this option(s) */

	case HMCDRV_FUSE_OPTKEY_RO: /* "-o ro" or "-r" */
		((struct hmcdrv_fuse_opt *)data)->ro = 1;
		return 1;

	case HMCDRV_FUSE_OPTKEY_NATM: /* "-o noatime" */
		((struct hmcdrv_fuse_opt *)data)->noatime = 1;
		return 1;

	case HMCDRV_FUSE_OPTKEY_CTMO: /* "-o entry/attr_timeout=T" */
		if (sscanf(arg, "%*[^=]=%lf", &tmo) == 1) {
			if (tmo < 1.0)
				tmo = 1.0;

			if (hmcdrv_ctx.ctmo <
			    (HMCDRV_FUSE_CACHE_TMOFS + (time_t)tmo))
				hmcdrv_ctx.ctmo =
					HMCDRV_FUSE_CACHE_TMOFS + (time_t)tmo;

			HMCDRV_FUSE_DBGLOG("option \"%s\" detected (cache timeout now is %" PRIdMAX " sec.)",
					   arg, (intmax_t) hmcdrv_ctx.ctmo);
		}

		return 1;

	case HMCDRV_FUSE_OPTKEY_VERSION:
		fprintf(stdout, HMCDRV_FUSE_LOGHEAD
			"HMC drive DVD file system, version %s\n"
			"Copyright IBM Corp. 2015, 2017\n",
			HMCDRV_FUSE_RELEASE);
		exit(EXIT_SUCCESS);

	case HMCDRV_FUSE_OPTKEY_HELP:
		hmcdrv_fuse_usage(outargs->argv[0]);

		/*
		 * Usage output needs to go to stdout to be consistent with
		 * coding guidelines. FUSE versions before 3.0.0 print help
		 * output to stderr. Redirect stderr to stdout here to enforce
		 * consistent behavior.
		 */
		fflush(stderr);
		dup2(STDOUT_FILENO, STDERR_FILENO);

		fuse_opt_add_arg(outargs, "-ho");
		hmcdrv_fuse_main(outargs);
		exit(EXIT_SUCCESS);

	case FUSE_OPT_KEY_NONOPT: /* normally the mount point */
		mask = umask(0);
		umask(mask);
		hmcdrv_ctx.st.st_uid = getgid();
		hmcdrv_ctx.st.st_gid = getuid();
		hmcdrv_ctx.st.st_ino = 0;
		hmcdrv_ctx.st.st_size = 0; /* unknown */
		hmcdrv_ctx.st.st_blksize = 2048U; /* DVD sector size */
		hmcdrv_ctx.st.st_nlink = 2; /* minimum */
		hmcdrv_ctx.st.st_mtime = time(NULL);
		hmcdrv_ctx.st.st_atime = hmcdrv_ctx.st.st_mtime;
		hmcdrv_ctx.st.st_ctime = hmcdrv_ctx.st.st_mtime;

		hmcdrv_ctx.st.st_mode =
			(S_IFDIR |
			 S_IXUSR | S_IRUSR |
			 S_IXGRP | S_IRGRP |
			 S_IXOTH | S_IROTH) &
			~(mask | (S_IWUSR | S_IWGRP | S_IWOTH));

		HMCDRV_FUSE_DBGLOG("mount point is %s (uid = %u, gid = %u)",
				   arg,
				   hmcdrv_ctx.st.st_uid,
				   hmcdrv_ctx.st.st_gid);
		return 1;


	default:
		HMCDRV_FUSE_DBGLOG("option \"%s\" passed to FUSE", arg);
		return 1; /* pass all other options to fuse_main() */
	}
}


/*
 * FUSE.HMCDRVFS entry function
 */
int main(int argc, char *argv[])
{
	static struct fuse_opt lookup_opt[] = {

		HMCDRV_FUSE_OPT("hmctz=%s", hmctz, 0),
		HMCDRV_FUSE_OPT("hmclang=%s", hmclang, 0),

		FUSE_OPT_KEY("ro", HMCDRV_FUSE_OPTKEY_RO),
		FUSE_OPT_KEY("-r", HMCDRV_FUSE_OPTKEY_RO),
		FUSE_OPT_KEY("--read-only", HMCDRV_FUSE_OPTKEY_RO),

		FUSE_OPT_KEY("noatime", HMCDRV_FUSE_OPTKEY_NATM),
		FUSE_OPT_KEY("entry_timeout=%lf", HMCDRV_FUSE_OPTKEY_CTMO),
		FUSE_OPT_KEY("attr_timeout=%lf", HMCDRV_FUSE_OPTKEY_CTMO),

		/* unsupported (ignored) */
		FUSE_OPT_KEY("subdir=%s", HMCDRV_FUSE_OPTKEY_NSUP),
		FUSE_OPT_KEY("use_ino", HMCDRV_FUSE_OPTKEY_NSUP),
		FUSE_OPT_KEY("readdir_ino", HMCDRV_FUSE_OPTKEY_NSUP),

		/* to be ignored on read-only filesystem */
		FUSE_OPT_KEY("rw", HMCDRV_FUSE_OPTKEY_RW),
		FUSE_OPT_KEY("-w", HMCDRV_FUSE_OPTKEY_RW),
		FUSE_OPT_KEY("--rw", HMCDRV_FUSE_OPTKEY_RW),
		FUSE_OPT_KEY("atime", HMCDRV_FUSE_OPTKEY_RW),
		FUSE_OPT_KEY("max_write=%u", HMCDRV_FUSE_OPTKEY_RW),
		FUSE_OPT_KEY("big_writes", HMCDRV_FUSE_OPTKEY_RW),
		FUSE_OPT_KEY("hard_remove", HMCDRV_FUSE_OPTKEY_RW),
		FUSE_OPT_KEY("atomic_o_trunc", HMCDRV_FUSE_OPTKEY_RW),
		FUSE_OPT_KEY("negative_timeout=%lf", HMCDRV_FUSE_OPTKEY_RW),

		/* options, that exit immediately */
		FUSE_OPT_KEY("-v", HMCDRV_FUSE_OPTKEY_VERSION),
		FUSE_OPT_KEY("--version", HMCDRV_FUSE_OPTKEY_VERSION),
		FUSE_OPT_KEY("-h", HMCDRV_FUSE_OPTKEY_HELP),
		FUSE_OPT_KEY("--help", HMCDRV_FUSE_OPTKEY_HELP),

		FUSE_OPT_END
	};

	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	memset(&hmcdrv_ctx.opt, 0, sizeof(hmcdrv_ctx.opt));
	hmcdrv_ctx.pid = getpid();

	fuse_opt_parse(&args, &hmcdrv_ctx.opt, lookup_opt,
		       hmcdrv_fuse_optproc);

	/* the following options are required on a read-only media */
	if (!hmcdrv_ctx.opt.ro)
		fuse_opt_add_arg(&args, "-oro");

	if (!hmcdrv_ctx.opt.noatime)
		fuse_opt_add_arg(&args, "-onoatime");

	if (hmcdrv_optproc_lang() != 0) {
		HMCDRV_FUSE_LOG(LOG_ERR,
				"Unknown HMC language in '-o hmclang=%s'",
				hmcdrv_ctx.opt.hmclang);
		exit(EXIT_FAILURE);
	}

	/* notice that there is no way to check the timezone parameter for
	 * correct syntax, not in glibc as well as POSIX 1003.1
	 */
	if (hmcdrv_ctx.opt.hmctz != NULL)
		HMCDRV_FUSE_DBGLOG("option \"-o hmctz=%s\" detected",
				   hmcdrv_ctx.opt.hmctz);

	ret = hmcdrv_fuse_main(&args);
	fuse_opt_free_args(&args);

	return ret;
}

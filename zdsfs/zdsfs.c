/*
 * zdsfs - FUSE file system for z/OS data set access
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

/* The fuse version define tells fuse that we want to use the new API */
#define FUSE_USE_VERSION 26

#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <limits.h>
#include <malloc.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>
#include <signal.h>

#include <iconv.h>

#ifdef HAVE_SETXATTR
#include <linux/xattr.h>
#endif

#include "lib/libzds.h"
#include "lib/util_libc.h"
#include "lib/zt_common.h"

#define COMP "zdsfs: "

#define METADATAFILE "metadata.txt"

/* defaults for file and directory permissions (octal) */
#define DEF_FILE_PERM 0440
#define DEF_DIR_PERM 0550
/* default timer interval 9 minutes, enq times out after 10 minutes */
#define DEFAULT_KEEPALIVE_SEC	         540

#define SECTION_ENTRIES 3
static char CODEPAGE_EDF[] = "CP1047";
static char CODEPAGE_LINUX[] = "UTF-8";

struct zdsfs_info {
	int devcount;
	int allow_inclomplete_multi_volume;
	int keepRDW;
	int host_count;
	unsigned int tracks_per_frame;
	unsigned long long seek_buffer_size;
	struct zdsroot *zdsroot;

	char *metadata;  /* buffer that contains the content of metadata.txt */
	size_t metasize; /* total size of meta data buffer */
	size_t metaused; /* how many bytes of buffer are already filled */
	time_t metatime; /* when did we create this meta data */
	char *configfile;
	int restapi;
	unsigned int nr_server;
	int active_server;
	char *server[MAX_SERVER];
	long keepalive;
	int codepage_convert;
	char *codepage_from;
	char *codepage_to;
	iconv_t iconv;
	struct util_list *dsclist;
	char *dsfile;
};

static struct zdsfs_info zdsfsinfo;
static int zdsfs_create_meta_data_buffer(struct zdsfs_info *);
static int zdsfs_verify_datasets(void);
static struct util_list *open_dsh;
static int timer_running;

struct dsh_node {
	struct util_list_node node;
	struct dshandle *dsh;
};

struct zdsfs_file_info {
	struct dshandle *dsh;
	pthread_mutex_t mutex;

	int is_metadata_file;
	size_t metaread; /* how many bytes have already been read */
};

struct dsconvert {
	char *name;
	char *codepage_from;
	char *codepage_to;
	bool keeprdw;
};

struct dsc_node {
	struct util_list_node node;
	struct dsconvert *dsc;
};

/* Allocate and initialize a new list of struct dsh_node. */
static struct util_list *dshlist_alloc(void)
{
	struct util_list *list;

	list = util_malloc(sizeof(struct util_list));
	util_list_init(list, struct dsh_node, node);

	return list;
}

/* free list of struct dsh_node. */
static void dshlist_free(struct util_list *list)
{
	struct dsh_node *s, *n;

	if (!list)
		return;

	util_list_iterate_safe(list, s, n) {
		util_list_remove(list, s);
		free(s);
	}

	free(list);
}

/* add dsh to list */
static void dshlist_add(struct util_list *list, struct dshandle *dsh)
{
	struct dsh_node *s;

	s = util_malloc(sizeof(struct dsh_node));
	s->dsh = dsh;
	util_list_add_tail(list, s);
}

/* Find a dsh_node. */
static struct dsh_node *dshlist_find(struct util_list *list, struct dshandle *dsh)
{
	struct dsh_node *s;

	util_list_iterate(list, s) {
		if (s->dsh == dsh)
			return s;
	}

	return NULL;
}

/* Remove a dsh_node from the list. */
void dshlist_remove(struct util_list *list, struct dshandle *dsh)
{
	struct dsh_node *p;

	p = dshlist_find(list, dsh);
	if (p) {
		util_list_remove(list, p);
		free(p);
	}
}

/* Allocate and initialize a new list of struct dsc_node. */
static struct util_list *dsclist_alloc(void)
{
	struct util_list *list;

	list = util_malloc(sizeof(struct util_list));
	util_list_init(list, struct dsc_node, node);

	return list;
}

/* free struct dsconvert. */
static void dsc_free(struct dsconvert *dsc)
{
	free(dsc->name);
	free(dsc->codepage_from);
	free(dsc->codepage_to);
	free(dsc);
}

/* free list of struct dsc_node. */
static void dsclist_free(struct util_list *list)
{
	struct dsc_node *s, *n;

	if (!list)
		return;

	util_list_iterate_safe(list, s, n) {
		util_list_remove(list, s);
		dsc_free(s->dsc);
		free(s);
	}

	free(list);
}

/* add dsc to list */
static void dsclist_add(struct util_list *list, struct dsconvert *dsc)
{
	struct dsc_node *s;

	s = util_malloc(sizeof(struct dsc_node));
	s->dsc = dsc;
	util_list_add_tail(list, s);
}

/* Find a dsc_node by name. */
static struct dsc_node *dsclist_find_by_name(struct util_list *list, char *name)
{
	struct dsc_node *s;

	util_list_iterate(list, s) {
		if (strcmp(s->dsc->name, name) == 0)
			return s;
	}

	return NULL;
}

/* normalize the given path name to a dataset name
 * so that we can compare it to the names in the vtoc. This means:
 * - remove the leading /
 * - remove member names (everything after a subsequent / )
 * Note: we do no upper case, EBCDIC conversion or padding
 */
static void path_to_ds_name(const char *path, char *normds, size_t size)
{
	char *end;

	if (*path == '/')
		++path;
	util_strlcpy(normds, path, size);
	end = strchr(normds, '/');
	if (end)
		*end = '\0';
}

static void path_to_member_name(const char *path, char *normds, size_t size)
{
	if (*path == '/')
		++path;
	path = strchr(path, '/');
	if (!path)
		normds[0] = '\0';
	else {
		++path;
		util_strlcpy(normds, path, size);
	}
}

static int setup_iconv(iconv_t *conv, const char *from, const char *to)
{
	*conv = iconv_open(to, from);
	if (*conv == ((iconv_t) -1)) {
		fprintf(stderr, "error when setting up iconv\n");
		return -1;
	}
	return 0;
}

static void setup_timer(long sec)
{
	static struct itimerval timer;

	memset(&timer, 0, sizeof(struct itimerval));
	timer.it_value.tv_sec = sec;
	setitimer(ITIMER_REAL, &timer, NULL);
}

static void keep_alive(int UNUSED(signal))
{
	struct dsh_node *s;

	if (!open_dsh) {
		timer_running = 0;
		setup_timer(0);
		return;
	}

	util_list_iterate(open_dsh, s) {
		lzds_rest_ping(s->dsh,
			       zdsfsinfo.server[zdsfsinfo.active_server]);
	}
	timer_running = 1;
	setup_timer(zdsfsinfo.keepalive);
}

void keepalive_start(void)
{
	struct sigaction act;

	if (!open_dsh || timer_running)
		return;

	timer_running = 1;
	/* Setup timer for periodic ping. */
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = &keep_alive;
	sigaction(SIGALRM, &act, NULL);
	setup_timer(zdsfsinfo.keepalive);
}

static int zdsfs_getattr(const char *path, struct stat *stbuf)
{
	char normds[MAXDSNAMELENGTH];
	size_t dssize;
	struct dataset *ds;
	struct pdsmember *member;
	int rc, ispds, issupported;
	unsigned long long tracks;
	format1_label_t *f1;
	time_t time;
	struct tm tm;

	memset(stbuf, 0, sizeof(struct stat));
	/* root directory case */
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | DEF_DIR_PERM;
		stbuf->st_nlink = 2;
		stbuf->st_atime = zdsfsinfo.metatime;
		stbuf->st_mtime = zdsfsinfo.metatime;
		stbuf->st_ctime = zdsfsinfo.metatime;
		return 0;
	}

	if (strcmp(path, "/"METADATAFILE) == 0) {
		stbuf->st_mode = S_IFREG | DEF_FILE_PERM;
		stbuf->st_nlink = 1;
		stbuf->st_size = zdsfsinfo.metaused;
		stbuf->st_atime = zdsfsinfo.metatime;
		stbuf->st_mtime = zdsfsinfo.metatime;
		stbuf->st_ctime = zdsfsinfo.metatime;
		return 0;
	}

	path_to_ds_name(path, normds, sizeof(normds));
	rc = lzds_zdsroot_find_dataset(zdsfsinfo.zdsroot, normds, &ds);
	if (rc)
		return -rc;

	lzds_dataset_get_is_supported(ds, &issupported);
	if (!issupported)
		return -ENOENT;

	/* upper limit for the size of the whole data set */
	lzds_dataset_get_size_in_tracks(ds, &tracks);
	dssize = MAXRECSIZE * tracks;

	/* get the last access time */
	lzds_dataset_get_format1_dscb(ds, &f1);
	memset(&tm, 0, sizeof(tm));
	if (f1->DS1REFD.year || f1->DS1REFD.day) {
		tm.tm_year = f1->DS1REFD.year;
		tm.tm_mday = f1->DS1REFD.day;
	} else {
		tm.tm_year = f1->DS1CREDT.year;
		tm.tm_mday = f1->DS1CREDT.day;
	}
	tm.tm_isdst = -1;
	time = mktime(&tm);
	if (time < 0)
		time = 0;

	lzds_dataset_get_is_PDS(ds, &ispds);
	if (ispds) {
		path_to_member_name(path, normds, sizeof(normds));
		/* the dataset itself is represented as directory */
		if (strcmp(normds, "") == 0) {
			stbuf->st_mode = S_IFDIR | DEF_DIR_PERM;
			stbuf->st_nlink = 2;
			stbuf->st_size = 0;
			stbuf->st_atime = time;
			stbuf->st_mtime = time;
			stbuf->st_ctime = time;
			stbuf->st_blocks = tracks * 16 * 8;
			stbuf->st_size = dssize;
			return 0;
		}
		rc = lzds_dataset_get_member_by_name(ds, normds, &member);
		if (rc)
			return -ENOENT;
		stbuf->st_mode = S_IFREG | DEF_FILE_PERM;
		stbuf->st_nlink = 1;
		/* the member cannot be bigger than the data set */
		stbuf->st_size = dssize;
		return 0;
	} else { /* normal data set */
		stbuf->st_mode = S_IFREG | DEF_FILE_PERM;
		stbuf->st_nlink = 1;
		stbuf->st_size = dssize;
		stbuf->st_blocks = tracks * 16 * 8;
		stbuf->st_atime = time;
		stbuf->st_mtime = time;
		stbuf->st_ctime = time;
	}
	return 0;
}

static void zdsfs_read_device(struct dasd *newdasd, const char *device)
{
	struct errorlog *log;
	int rc;

	rc = dasd_disk_reserve(device);
	if (rc) {
		fprintf(stderr, "error when reserving device %s: %s\n",
			device, strerror(rc));
		lzds_dasd_get_errorlog(newdasd, &log);
		lzds_errorlog_fprint(log, stderr);
		exit(1);
	}
	rc = lzds_dasd_alloc_rawvtoc(newdasd);
	if (rc) {
		fprintf(stderr, "error when reading VTOC from device %s: %s\n",
			device, strerror(rc));
		lzds_dasd_get_errorlog(newdasd, &log);
		lzds_errorlog_fprint(log, stderr);
		exit(1);
	}
	rc = lzds_zdsroot_extract_datasets_from_dasd(zdsfsinfo.zdsroot,
						     newdasd);
	if (rc) {
		fprintf(stderr,
			"error when extracting data sets from dasd %s: %s\n",
			device, strerror(rc));
		lzds_zdsroot_get_errorlog(zdsfsinfo.zdsroot, &log);
		lzds_errorlog_fprint(log, stderr);
		exit(1);
	}
	rc = dasd_disk_release(device);
	if (rc) {
		fprintf(stderr, "error when releasing device %s: %s\n",
			device, strerror(rc));
		lzds_dasd_get_errorlog(newdasd, &log);
		lzds_errorlog_fprint(log, stderr);
		exit(1);
	}
}


static int zdsfs_statfs(const char *UNUSED(path), struct statvfs *statvfs)
{
	struct dasditerator *dasdit;
	unsigned int cyls, heads;
	struct dasd *dasd;
	struct dataset *ds;
	struct dsiterator *dsit;
	unsigned long long totaltracks, usedtracks, dstracks;
	int rc;

	totaltracks = 0;
	rc = lzds_zdsroot_alloc_dasditerator(zdsfsinfo.zdsroot, &dasdit);
	if (rc)
		return -ENOMEM;
	while (!lzds_dasditerator_get_next_dasd(dasdit, &dasd)) {
		lzds_dasd_get_cylinders(dasd, &cyls);
		lzds_dasd_get_heads(dasd, &heads);
		totaltracks += cyls * heads;
	}
	lzds_dasditerator_free(dasdit);

	usedtracks = 0;
	rc = lzds_zdsroot_alloc_dsiterator(zdsfsinfo.zdsroot, &dsit);
	if (rc)
		return -ENOMEM;
	while (!lzds_dsiterator_get_next_dataset(dsit, &ds)) {
		/* To compute the occupied space we consider all data sets,
		 * not just the supported ones */
		lzds_dataset_get_size_in_tracks(ds, &dstracks);
		usedtracks += dstracks;
	}
	lzds_dsiterator_free(dsit);

	if (totaltracks < usedtracks)
		return -EPROTO;

	memset(statvfs, 0, sizeof(*statvfs));
	statvfs->f_bsize = RAWTRACKSIZE;
	statvfs->f_frsize = RAWTRACKSIZE;
	statvfs->f_blocks = totaltracks;
	statvfs->f_bfree = totaltracks - usedtracks;
	statvfs->f_bavail = totaltracks - usedtracks;
	statvfs->f_namemax = MAXDSNAMELENGTH - 1;
	return 0;
}


static int zdsfs_update_vtoc(void)
{
	struct dasditerator *dasdit;
	struct dasd *dasd;
	int rc;

	lzds_dslist_free(zdsfsinfo.zdsroot);
	rc = lzds_zdsroot_alloc_dasditerator(zdsfsinfo.zdsroot, &dasdit);
	if (rc)
		return -ENOMEM;

	while (!lzds_dasditerator_get_next_dasd(dasdit, &dasd))
		zdsfs_read_device(dasd, dasd->device);

	lzds_dasditerator_free(dasdit);
	rc = zdsfs_verify_datasets();
	if (rc)
		return rc;

	rc = zdsfs_create_meta_data_buffer(&zdsfsinfo);
	if (rc)
		return rc;

	return 0;
}

static int zdsfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t UNUSED(offset), struct fuse_file_info *UNUSED(fi))
{
	char normds[MAXDSNAMELENGTH];
	char *mbrname;
	char *dsname;
	struct dataset *ds;
	struct dsiterator *dsit;
	struct memberiterator *it;
	struct pdsmember *member;
	int rc;
	int ispds, issupported;

	rc = zdsfs_update_vtoc();
	if (rc)
		return rc;

	/* we have two type of directories
	 * type one: the root directory contains all data sets
	 */
	if (strcmp(path, "/") == 0) {
		filler(buf, ".", NULL, 0);
		filler(buf, "..", NULL, 0);
		filler(buf, METADATAFILE, NULL, 0);
		/* note that we do not need to distinguish between
		 * normal files and directories here, that is done
		 * in the rdf_getattr function
		 */
		rc = lzds_zdsroot_alloc_dsiterator(zdsfsinfo.zdsroot, &dsit);
		if (rc)
			return -ENOMEM;
		while (!lzds_dsiterator_get_next_dataset(dsit, &ds)) {
			lzds_dataset_get_is_supported(ds, &issupported);
			if (issupported) {
				lzds_dataset_get_name(ds, &dsname);
				filler(buf, dsname, NULL, 0);
			}
		}
		lzds_dsiterator_free(dsit);
		return 0;
	}

	/* type two: a partitioned data set, contains all PDS members */
	path_to_ds_name(path, normds, sizeof(normds));
	rc = lzds_zdsroot_find_dataset(zdsfsinfo.zdsroot, normds, &ds);
	if (rc)
		return -ENOENT;
	lzds_dataset_get_is_PDS(ds, &ispds);
	if (ispds) {
		filler(buf, ".", NULL, 0);
		filler(buf, "..", NULL, 0);
		rc = lzds_dataset_alloc_memberiterator(ds, &it);
		if (rc)
			return -ENOMEM;
		while (!lzds_memberiterator_get_next_member(it, &member)) {
			lzds_pdsmember_get_name(member, &mbrname);
			filler(buf, mbrname, NULL, 0);
		}
		lzds_memberiterator_free(it);
	} else
		return -ENOENT;

	return 0;
}

/*
 * walk through the serverlist and check if the URLs start with http or https
 * if not attach a https:// prefix
 * also check if they end with / and if not attach it
 *
 * afterwards ping the z/OSMF server and use the first working one
 *
 * return 1 if working server found 0 otherwise
 */
static int zdsfs_test_restserver(void)
{
	unsigned int i;
	char *server;
	char *prefix;

	for (i = 0; i < zdsfsinfo.nr_server; i++) {
		server = zdsfsinfo.server[i];
		if (strncmp(server, "http", 4)) {
			prefix = util_strdup("https://");
			server = util_strcat_realloc(prefix, server);
			free(zdsfsinfo.server[i]);
			zdsfsinfo.server[i] = server;
		}
		if (strncmp(server + strlen(server) - 1, "/", 1)) {
			server = util_strcat_realloc(server, "/");
			zdsfsinfo.server[i] = server;
		}
		if (lzds_rest_ping(NULL, zdsfsinfo.server[i])) {
			zdsfsinfo.active_server = i;
			fprintf(stdout, "Using z/OSMF REST services on %s\n",
				zdsfsinfo.server[i]);
			return 1;
		}
	}
	return 0;
}

/*
 * check if a dsconvert entry exists that match the given DS name
 * if the dsconvert entry ends in an asterisk only match the prefix
 * otherwise look for an exact match
 */
static struct dsconvert *zdsfs_get_matching_dsc(char *name)
{
	struct dsconvert *dsc;
	unsigned int length;
	struct dsc_node *n;
	char *match;

	util_list_iterate(zdsfsinfo.dsclist, n) {
		dsc = n->dsc;
		match = dsc->name;
		length = strlen(match);
		if (strcmp(&match[length - 1], "*") == 0)
			length--;
		else if (strlen(name) != length)
			continue;

		if (strncmp(name, match, length) == 0)
			return dsc;
	}
	return NULL;
}

/*
 * Setup iconv conversion for a given dataset.
 * The codepage settings can be obtained from (in descending priority)
 *   - globally set codepage settings
 *   - a dsconvert entry matching the DS name
 *   - default codepage settings.
 */
static int zdsfs_setup_conversion(struct dshandle *dsh, struct dataset *ds)
{
	struct dsconvert *dsc;
	const char *from, *to;
	struct errorlog *log;
	iconv_t *iconv;
	char *dsname;
	int rc;

	from = to = NULL;
	lzds_dataset_get_name(ds, &dsname);
	dsc = zdsfs_get_matching_dsc(dsname);
	/* the DS matches a dsconvert entry */
	if (dsc) {
		from = dsc->codepage_from;
		to = dsc->codepage_to;
	}

	/* globally set conversion overwriting possible config file settings */
	if (zdsfsinfo.codepage_from && zdsfsinfo.codepage_to) {
		from = zdsfsinfo.codepage_from;
		to = zdsfsinfo.codepage_to;
	}

	/*
	 * globally set conversion using defaults
	 * if not specified otherwise already
	 */
	if (zdsfsinfo.codepage_convert) {
		if (!from)
			from = CODEPAGE_EDF;
		if  (!to)
			to = CODEPAGE_LINUX;
	}

	/* no conversion */
	if (!from || !to)
		return 0;

	iconv = util_malloc(sizeof(*iconv));
	rc = setup_iconv(iconv, from, to);
	if (rc) {
		fprintf(stderr,	"Error when preparing iconv setting:\n");
		lzds_dshandle_get_errorlog(dsh, &log);
		lzds_errorlog_fprint(log, stderr);
		rc = -rc;
		goto out;
	}
	rc = lzds_dshandle_set_iconv(dsh, iconv);
	if (rc) {
		fprintf(stderr,	"Error when setting iconv handle:\n");
		lzds_dshandle_get_errorlog(dsh, &log);
		lzds_errorlog_fprint(log, stderr);
		rc = -rc;
		goto out;
	}
	return 0;
out:
	free(iconv);
	return rc;
}


static int zdsfs_open(const char *path, struct fuse_file_info *fi)
{
	char normds[45];
	struct dshandle *dsh;
	struct dataset *ds;
	struct zdsfs_file_info *zfi;
	int rc;
	int ispds, issupported;
	struct errorlog *log;

	if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;
	/*
	 * The contents of the dataset is smaller than the data set
	 * size we return in zdsfs_getattr. We need to set direct_io
	 * to make sure that fuse will report the end of the data with EOF.
	 */
	fi->direct_io = 1;

	zfi = malloc(sizeof(*zfi));
	if (!zfi)
		return -ENOMEM;
	rc = pthread_mutex_init(&zfi->mutex, NULL);
	if (rc)
		goto error1;

	if (strcmp(path, "/"METADATAFILE) == 0) {
		rc = zdsfs_update_vtoc();
		if (rc)
			return rc;
		zfi->dsh = NULL;
		zfi->is_metadata_file = 1;
		zfi->metaread = 0;
		fi->fh = (unsigned long)zfi;
		return 0;
	}

	path_to_ds_name(path, normds, sizeof(normds));
	rc = lzds_zdsroot_find_dataset(zdsfsinfo.zdsroot, normds, &ds);
	if (rc)
		goto error1;

	lzds_dataset_get_is_supported(ds, &issupported);
	if (!issupported) {
		/* we should never get this error, as unsupported data sets are
		 * not listed. But just in case, print a message */
		fprintf(stderr,	"Error: Data set %s is not supported\n", normds);
		rc = -ENOENT;
		goto error1;
	}

	rc = lzds_dataset_alloc_dshandle(ds, zdsfsinfo.tracks_per_frame, &dsh);
	if (rc) {
		rc = -rc;
		goto error1;
	}

	rc = lzds_dshandle_set_seekbuffer(dsh, zdsfsinfo.seek_buffer_size);
	if (rc) {
		fprintf(stderr,	"Error when preparing seek buffer:\n");
		lzds_dshandle_get_errorlog(dsh, &log);
		lzds_errorlog_fprint(log, stderr);
		rc = -rc;
		goto error2;
	}
	/* if the data set is a PDS, then the path must contain a valid
	 * member name, and the context must be set to this member
	 */
	lzds_dataset_get_is_PDS(ds, &ispds);
	if (ispds) {
		path_to_member_name(path, normds, sizeof(normds));
		rc = lzds_dshandle_set_member(dsh, normds);
		if (rc) {
			fprintf(stderr,	"Error when preparing member:\n");
			lzds_dshandle_get_errorlog(dsh, &log);
			lzds_errorlog_fprint(log, stderr);
			rc = -rc;
			goto error2;
		}
	}
	rc = lzds_dshandle_set_keepRDW(dsh, zdsfsinfo.keepRDW);
	if (rc) {
		fprintf(stderr,	"Error when preparing RDW setting:\n");
		lzds_dshandle_get_errorlog(dsh, &log);
		lzds_errorlog_fprint(log, stderr);
		rc = -rc;
		goto error2;
	}
	zdsfs_setup_conversion(dsh, ds);

retry:
	if (zdsfsinfo.restapi && zdsfsinfo.active_server >= 0) {
		rc = lzds_rest_get_enq(dsh,
				  zdsfsinfo.server[zdsfsinfo.active_server]);
		/* if the REST server is not responding try the other */
		if (rc == ECONNREFUSED && zdsfs_test_restserver()) {
			goto retry;
		} else if (rc) {
			lzds_dshandle_get_errorlog(dsh, &log);
			lzds_errorlog_fprint(log, stderr);
			rc = -rc;
			goto error2;
		} else {
			dshlist_add(open_dsh, dsh);
			/* add to open dsh list */
			keepalive_start();
		}
	}
	rc = lzds_dshandle_open(dsh);
	if (rc) {
		fprintf(stderr,	"Error when opening data set:\n");
		lzds_dshandle_get_errorlog(dsh, &log);
		lzds_errorlog_fprint(log, stderr);
		rc = -rc;
		goto error3;
	}
	zfi->is_metadata_file = 0;
	zfi->metaread = 0;
	zfi->dsh = dsh;
	fi->fh = (uint64_t)(unsigned long)zfi;
	return 0;

error3:
	dshlist_remove(open_dsh, dsh);
error2:
	lzds_dshandle_free(dsh);
error1:
	free(zfi);
	return rc;
}

static int zdsfs_release(const char *UNUSED(path), struct fuse_file_info *fi)
{
	struct zdsfs_file_info *zfi;
	int rc;

	if (!fi->fh)
		return -EINVAL;
	zfi = (struct zdsfs_file_info *)(unsigned long)fi->fh;
	if (zfi->dsh) {
		lzds_rest_release_enq(zfi->dsh,
				      zdsfsinfo.server[zdsfsinfo.active_server]);
		lzds_dshandle_close(zfi->dsh);
		dshlist_remove(open_dsh, zfi->dsh);
		lzds_dshandle_free(zfi->dsh);
	}
	rc = pthread_mutex_destroy(&zfi->mutex);
	if (rc)
		fprintf(stderr,	"Error: could not destroy mutex, rc=%d\n", rc);
	free(zfi);
	return 0;
}

static int zdsfs_read(const char *UNUSED(path), char *buf, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
	struct zdsfs_file_info *zfi;
	ssize_t count;
	int rc, rc2;
	long long rcoffset;
	struct errorlog *log;

	if (!fi->fh)
		return -ENOENT;
	zfi = (struct zdsfs_file_info *)(unsigned long)fi->fh;

	rc2 = pthread_mutex_lock(&zfi->mutex);
	if (rc2) {
		fprintf(stderr,	"Error: could not lock mutex, rc=%d\n", rc2);
		return -EIO;
	}
	rc = 0;
	if (zfi->is_metadata_file) {
		if (zfi->metaread >= zdsfsinfo.metaused) {
			pthread_mutex_unlock(&zfi->mutex);
			return 0;
		}
		count = zdsfsinfo.metaused - zfi->metaread;
		if (size < (size_t)count)
			count = size;
		memcpy(buf, &zdsfsinfo.metadata[zfi->metaread], count);
		zfi->metaread += count;
	} else {
		lzds_dshandle_get_offset(zfi->dsh, &rcoffset);
		if (rcoffset != offset)
			rc = lzds_dshandle_lseek(zfi->dsh, offset, &rcoffset);
		if (!rc)
			rc = lzds_dshandle_read(zfi->dsh, buf, size, &count);
	}
	rc2 = pthread_mutex_unlock(&zfi->mutex);
	if (rc2)
		fprintf(stderr,	"Error: could not unlock mutex, rc=%d\n", rc2);
	if (rc) {
		fprintf(stderr,	"Error when reading from data set:\n");
		lzds_dshandle_get_errorlog(zfi->dsh, &log);
		lzds_errorlog_fprint(log, stderr);
		return -rc;
	}
	return count;
}


#ifdef HAVE_SETXATTR

#define RECFMXATTR "user.recfm"
#define LRECLXATTR "user.lrecl"
#define DSORGXATTR "user.dsorg"

static int zdsfs_listxattr(const char *path, char *list, size_t size)
{
	int pos = 0;
	size_t list_len;

	/* root directory and the metadata have no extended attributes */
	if (!strcmp(path, "/") || !strcmp(path, "/"METADATAFILE))
		return 0;

	list_len = strlen(RECFMXATTR) + 1 +
		strlen(LRECLXATTR) + 1 +
		strlen(DSORGXATTR) + 1;
	/* size 0 is a special case to query the necessary buffer length */
	if (!size)
		return list_len;
	if (size < list_len)
		return -ERANGE;
	strcpy(list, RECFMXATTR);
	pos += strlen(RECFMXATTR) + 1;
	strcpy(&list[pos], LRECLXATTR);
	pos += strlen(LRECLXATTR) + 1;
	strcpy(&list[pos], DSORGXATTR);
	pos += strlen(DSORGXATTR) + 1;
	return pos;
}

static int zdsfs_getxattr(const char *path, const char *name, char *value,
			  size_t size)
{
	char normds[45];
	struct dataset *ds;
	format1_label_t *f1;
	int rc;
	char buffer[20];
	size_t length;
	int ispds;

	/* nothing for root directory but clear error code needed */
	if (!strcmp(path, "/") || !strcmp(path, "/"METADATAFILE))
		return -ENODATA;

	path_to_ds_name(path, normds, sizeof(normds));
	rc = lzds_zdsroot_find_dataset(zdsfsinfo.zdsroot, normds, &ds);
	if (rc)
		return -rc;
	lzds_dataset_get_format1_dscb(ds, &f1);

	/* null terminate strings */
	memset(value, 0, size);
	memset(buffer, 0, sizeof(buffer));

	/* returned size should be the string length, getfattr fails if I
	 * include an extra byte for the zero termination */
	if (strcmp(name, RECFMXATTR) == 0) {
		lzds_DS1RECFM_to_recfm(f1->DS1RECFM, buffer);
	} else if (strcmp(name, LRECLXATTR) == 0) {
		snprintf(buffer, sizeof(buffer), "%d", f1->DS1LRECL);
	} else if (strcmp(name, DSORGXATTR) == 0) {
		lzds_dataset_get_is_PDS(ds, &ispds);
		if (ispds) {
			/* It is valid to ask for attributes of the directory */
			path_to_member_name(path, normds, sizeof(normds));
			if (strlen(normds))
				snprintf(buffer, sizeof(buffer), "PS");
			else
				snprintf(buffer, sizeof(buffer), "PO");
		} else
			snprintf(buffer, sizeof(buffer), "PS");
	} else
		return -ENODATA;

	length = strlen(buffer);
	if (size == 0) /* special case to query the necessary buffer size */
		return length;
	if (size < length)
		return -ERANGE;
	strcpy(value, buffer);
	return length;

}

#endif /* HAVE_SETXATTR */


static struct fuse_operations rdf_oper = {
	.getattr   = zdsfs_getattr,
	.statfs    = zdsfs_statfs,
	.readdir   = zdsfs_readdir,
	.open      = zdsfs_open,
	.release   = zdsfs_release,
	.read      = zdsfs_read,
#ifdef HAVE_SETXATTR
	.listxattr = zdsfs_listxattr,
	.getxattr  = zdsfs_getxattr,
	/* no setxattr, removexattr since our xattrs are virtual */
#endif
};


static int zdsfs_verify_datasets(void)
{
	int allcomplete, rc;
	struct dataset *ds;
	char *dsname;
	struct dsiterator *dsit;
	int iscomplete, issupported;

	allcomplete = 1;

	rc = lzds_zdsroot_alloc_dsiterator(zdsfsinfo.zdsroot, &dsit);
	if (rc)
		return ENOMEM;
	while (!lzds_dsiterator_get_next_dataset(dsit, &ds)) {
		lzds_dataset_get_name(ds, &dsname);
		lzds_dataset_get_is_complete(ds, &iscomplete);
		if (!iscomplete) {
			lzds_dataset_get_name(ds, &dsname);
			fprintf(stderr,	"Warning: Data set %s is not "
				"complete\n", dsname);
			allcomplete = 0;
			continue;
		}
		lzds_dataset_get_is_supported(ds, &issupported);
		if (!issupported) {
			lzds_dataset_get_name(ds, &dsname);
			fprintf(stderr,	"Warning: Data set %s is not "
				"supported\n", dsname);
		}
	}
	lzds_dsiterator_free(dsit);

	if (!allcomplete && zdsfsinfo.allow_inclomplete_multi_volume) {
		fprintf(stderr, "Continue operation with incomplete data"
			" sets\n");
		return 0;
	}

	if (allcomplete) {
		return 0;
	} else {
		fprintf(stderr,
			"Error: Some multi volume data sets are not complete.\n"
			"Specify option 'ignore_incomplete' to allow operation "
			"with incomplete data sets, or add missing volumes.\n");
		return EPROTO;
	}
}


static int zdsfs_create_meta_data_buffer(struct zdsfs_info *info)
{
	char *mbrname;
	char *dsname;
	struct dataset *ds;
	struct dsiterator *dsit;
	struct memberiterator *it;
	struct pdsmember *member;
	int rc;
	int ispds, issupported;

	char buffer[200]; /* large enough for one line of meta data */
	char recfm[20];
	char *temp;
	char *metadata;
	size_t metasize; /* total size of meta data buffer */
	size_t metaused; /* how many bytes of buffer are already filled */
	size_t count;
	format1_label_t *f1;

	metadata = malloc(4096);
	if (!metadata)
		return -ENOMEM;
	metasize = 4096;
	metaused = 0;
	metadata[metaused] = 0;

	rc = lzds_zdsroot_alloc_dsiterator(zdsfsinfo.zdsroot, &dsit);
	if (rc) {
		rc = -ENOMEM;
		goto error;
	}
	while (!lzds_dsiterator_get_next_dataset(dsit, &ds)) {
		lzds_dataset_get_is_supported(ds, &issupported);
		if (!issupported)
			continue;
		lzds_dataset_get_name(ds, &dsname);
		lzds_dataset_get_format1_dscb(ds, &f1);
		lzds_DS1RECFM_to_recfm(f1->DS1RECFM, recfm);
		lzds_dataset_get_is_PDS(ds, &ispds);
		count = snprintf(buffer, sizeof(buffer),
				 "dsn=%s,recfm=%s,lrecl=%u,"
				 "dsorg=%s\n",
				 dsname, recfm, f1->DS1LRECL,
				 ispds ? "PO" : "PS");
		if (count >= sizeof(buffer)) {	/* just a sanity check */
			count = sizeof(buffer) - 1;
			buffer[count] = 0;
		}
		if (metaused + count + 1 > metasize) {
			temp = realloc(metadata,  metasize + 4096);
			if (!temp) {
				rc = -ENOMEM;
				goto error;
			}
			metadata = temp;
			metasize += 4096;
		}
		memcpy(&metadata[metaused], buffer, count + 1);
		metaused += count;

		/* if the dataset is a PDS then we need to process all members
		 * of the PDS, otherwise continue with the next dataset */
		if (!ispds)
			continue;

		rc = lzds_dataset_alloc_memberiterator(ds, &it);
		if (rc) {
			rc = -ENOMEM;
			goto error;
		}
		while (!lzds_memberiterator_get_next_member(it, &member)) {
			lzds_pdsmember_get_name(member, &mbrname);
			count = snprintf(buffer, sizeof(buffer),
					 "dsn=%s(%s),recfm=%s,lrecl=%u,"
					 "dsorg=PS\n",
					 dsname, mbrname, recfm, f1->DS1LRECL);
			if (count >= sizeof(buffer)) {
				count = sizeof(buffer) - 1;
				buffer[count] = 0;
			}
			if (metaused + count + 1 > metasize) {
				temp = realloc(metadata,  metasize + 4096);
				if (!temp) {
					rc = -ENOMEM;
					goto error;
				}
				metadata = temp;
				metasize += 4096;
			}
			memcpy(&metadata[metaused], buffer, count + 1);
			metaused += count;
		}
		lzds_memberiterator_free(it);
		it = NULL;
	}
	lzds_dsiterator_free(dsit);
	dsit = NULL;

	if (info->metadata)
		free(info->metadata);
	info->metadata = metadata;
	info->metasize = metasize;
	info->metaused = metaused;
	info->metatime = time(NULL);
	return 0;

error:
	free(metadata);
	lzds_dsiterator_free(dsit);
	lzds_memberiterator_free(it);
	return rc;
}



enum {
	KEY_HELP,
	KEY_VERSION,
	KEY_DEVFILE,
	KEY_TRACKS,
	KEY_SEEKBUFFER,
	KEY_CONFIG,
	KEY_DSCONFIG,
	KEY_SERVER,
	KEY_CODE_FROM,
	KEY_CODE_TO,
};

#define ZDSFS_OPT(t, p, v) { t, offsetof(struct zdsfs_info, p), v }

static const struct fuse_opt zdsfs_opts[] = {
	FUSE_OPT_KEY("-h",		KEY_HELP),
	FUSE_OPT_KEY("--help",		KEY_HELP),
	FUSE_OPT_KEY("-v",		KEY_VERSION),
	FUSE_OPT_KEY("--version",	KEY_VERSION),
	FUSE_OPT_KEY("-l %s",		KEY_DEVFILE),
	FUSE_OPT_KEY("tracks=",         KEY_TRACKS),
	FUSE_OPT_KEY("seekbuffer=",     KEY_SEEKBUFFER),
	FUSE_OPT_KEY("-c %s",           KEY_CONFIG),
	FUSE_OPT_KEY("-x %s",           KEY_DSCONFIG),
	FUSE_OPT_KEY("restserver=",     KEY_SERVER),
	FUSE_OPT_KEY("codepage_from=",  KEY_CODE_FROM),
	FUSE_OPT_KEY("codepage_to=",    KEY_CODE_TO),
	ZDSFS_OPT("rdw",                keepRDW, 1),
	ZDSFS_OPT("ignore_incomplete",  allow_inclomplete_multi_volume, 1),
	ZDSFS_OPT("check_host_count",   host_count, 1),
	ZDSFS_OPT("restapi",            restapi, 1),
	ZDSFS_OPT("codepage_convert",   codepage_convert, 1),
	FUSE_OPT_END
};


static void usage(const char *progname)
{
	fprintf(stdout,
"Usage: %s <devices> <mountpoint> [<options>]\n"
"\n"
"Use the zdsfs command to provide read access to data sets stored on one or\n"
"more z/OS DASD devices.\n\n"
"General options:\n"
"    -o opt,[opt...]        Mount options\n"
"    -h   --help            Print help, then exit\n"
"    -v   --version         Print version, then exit\n"
"\n"
"ZDSFS options:\n"
"    -l list_file           Text file that contains a list of DASD device"
" nodes\n"
"    -c config_file         Text file that contains configuration options\n"
"                           for zdsfs\n"
"    -x ds_config_file      Text file that contains conversion options\n"
"                           for specific datasets\n"
"    -o rdw                 Keep record descriptor words in byte stream\n"
"    -o ignore_incomplete   Continue processing even if parts of a multi"
" volume\n"
"                           data set are missing\n"
"    -o tracks=N            Size of the track buffer in tracks (default 128)\n"
"    -o seekbuffer=S        Upper limit in bytes for the seek history buffer\n"
"                           size (default 1048576)\n"
"    -o check_host_count    Stop processing if the device is used by another\n"
"                           operating system instance\n"
"    -o restapi             Enable using z/OSMF REST services for coordinated\n"
"                           access to datasets\n"
"    -o restserver=URL      The URL of the z/OSMF REST server to be used for\n"
"                           coordinated access to datasets\n"
"    -o codepage_convert    Enable codepage conversion using default codepages\n"
"                           from 'CP1047' to 'UTF-8'\n"
"    -o codepage_from=from  Set codepage for source. See 'iconv -l' for a list\n"
"    -o codepage_to=to      Set codepage for target. See 'iconv -l' for a list\n"
		, progname);
}

static void zdsfs_process_device(const char *device)
{
	struct dasd *newdasd;
	struct errorlog *log;
	int rc;

	rc = lzds_zdsroot_add_device(zdsfsinfo.zdsroot, device, &newdasd);
	if (rc) {
		fprintf(stderr, "error when adding device %s: %s\n", device,
			strerror(rc));
		lzds_zdsroot_get_errorlog(zdsfsinfo.zdsroot, &log);
		lzds_errorlog_fprint(log, stderr);
		exit(1);
	}
	zdsfsinfo.devcount++;
	rc = lzds_dasd_read_vlabel(newdasd);
	if (rc) {
		fprintf(stderr, "error when reading volume label from "
			"device %s: %s\n", device, strerror(rc));
		lzds_dasd_get_errorlog(newdasd, &log);
		lzds_errorlog_fprint(log, stderr);
		exit(1);
	}
	zdsfs_read_device(newdasd, device);
}

static void zdsfs_process_device_file(const char *devfile)
{
	struct stat sb;
	int fd;
	ssize_t count;
	size_t size, residual;
	char *buffer;
	char *runbuf;
	char *token;

	fd = open(devfile, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "could not open file %s: %s\n",
			devfile, strerror(errno));
		exit(1);
	}
	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, "could not stat file %s: %s\n",
			devfile, strerror(errno));
		exit(1);
	}
	if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "not a regular file %s\n", devfile);
		exit(1);
	}
	if (sb.st_size) {
		size = (size_t)sb.st_size + 1;
		buffer = malloc(size);
		bzero(buffer, size);
		if (!buffer) {
			fprintf(stderr, "could not allocate memory to buffer"
				" file %s\n", devfile);
			exit(1);
		}
	} else
		return;

	count = 0;
	residual = (size_t)sb.st_size;
	while (residual) {
		count = read(fd, buffer, residual);
		if (count < 0) {
			fprintf(stderr, "error when reading file %s: %s\n",
				devfile, strerror(errno));
			exit(1);
		}
		if (!count) /* EOF */
			residual = 0;
		residual -= count;
	}

	runbuf = buffer;
	while ((token = strsep(&runbuf, " \t\n"))) {
		/* if several delimiters follow after another, token points
		 * to an empty string
		 */
		if (!strlen(token))
			continue;

		if (stat(token, &sb) < 0) {
			fprintf(stderr, "could not stat device %s from"
				" device list, %s\n", token, strerror(errno));
			exit(1);
		}
		if (S_ISBLK(sb.st_mode))
			zdsfs_process_device(token);
	}
	free(buffer);
}

void remove_whitespace(const char *s, char *t)
{
	while (*s != '\0') {
		if (!isblank(*s)) {
			*t = *s;
			t++;
		}
		s++;
	}
	*t = '\0';
}

static void zdsfs_process_config_file(const char *config)
{
	char line[MAX_LINE_LENGTH];
	char *tmp, *key, *value;
	FILE *fd;
	char delimiter[] = " =#\n";
	unsigned long enabled;

	fd = fopen(config, "r");
	if (!fd) {
		fprintf(stderr, "could not open file %s: %s\n",
			config, strerror(errno));
		return;
	}

	while (fgets(line, sizeof(line), fd)) {
		/* skip empty lines */
		if (*line == '\n' || *line == '#')
			continue;

		/* remove all whitespaces */
		tmp = util_malloc(strlen(line) + 1);
		remove_whitespace(line, tmp);

		key = strtok(tmp, delimiter);
		if (strcmp(key, "restserver")  == 0) {
			if (zdsfsinfo.nr_server >= MAX_SERVER) {
				free(tmp);
				continue;
			}
			value = strtok(NULL, delimiter);
			zdsfsinfo.server[zdsfsinfo.nr_server] =
				util_strdup(value);
			zdsfsinfo.nr_server++;
		} else if (strcmp(key, "restapi") == 0) {
			value = strtok(NULL, delimiter);
			enabled = strtoul(value, NULL, 0);
			if (enabled == 1)
				zdsfsinfo.restapi = true;
		} else if (strcmp(key, "keepalive") == 0) {
			value = strtok(NULL, delimiter);
			zdsfsinfo.keepalive = strtoul(value, NULL, 0);
		}
		free(tmp);
	}
	fclose(fd);
}

static struct dsconvert *zdsfs_allocate_dsc(char *name, const char *config)
{
	struct dsconvert *dsc;

	/* check for duplicate entries */
	if (dsclist_find_by_name(zdsfsinfo.dsclist, name)) {
		fprintf(stderr,
			"Error in config file %s. Duplicate entry found: %s\n",
			config, name);
		return NULL;
	}
	dsc = util_zalloc(sizeof(*dsc));
	dsc->name = util_strdup(name);

	return dsc;
}

static int zdsfs_check_codepage_setting(char *from, char *to)
{
	iconv_t iconv;

	/* no conversion is OK */
	if (!from && !to)
		return 0;

	/* partial setup is not OK */
	if ((from && !to) || (to && !from))
		return 1;

	/* return if the codepages are valid */
	return setup_iconv(&iconv, from, to);
}

/*
 * process a dataset configuration file that specifies conversion on a per dataset basis
 *
 * expect a section title each 3 lines
 * the section should contain a rdw= and conv= line
 * valid values for rdw= are 0/1
 * valid values for conv= are 0/1 or a comma separated list
 * of codepage_from and codepage_to arguments
 */
static int zdsfs_process_dataset_conf(const char *config)
{
	char line[MAX_LINE_LENGTH];
	char delimiter[] = " =#\n";
	char *tmp, *key, *value;
	int linecount, in_section;
	unsigned long enabled;
	struct dsconvert *dsc;
	int rc = 1;
	FILE *fd;

	fd = fopen(config, "r");
	if (!fd) {
		fprintf(stderr, "could not open file %s: %s\n",
			config, strerror(errno));
		return 0;
	}
	in_section = 0;
	linecount = 0;
	dsc = NULL;
	tmp = NULL;
	while (fgets(line, sizeof(line), fd)) {
		linecount++;
		/* remove all whitespaces */
		tmp = util_malloc(strlen(line) + 1);
		remove_whitespace(line, tmp);
		/* skip empty lines */
		if (*tmp == '\n' || *tmp == '#') {
			free(tmp);
			tmp = NULL;
			continue;
		}
		if (!in_section) {
			/* the section title should not contain a '=' */
			if (strchr(line, '=') != NULL) {
				fprintf(stderr,
					"Error in config file %s line %d. Expected section title instead of %s\n",
					config, linecount, line);
				goto out;
			}
		}
		key = strtok(tmp, delimiter);
		if (!in_section) {
			dsc = zdsfs_allocate_dsc(key, config);
			if (!dsc)
				goto out;
			in_section = SECTION_ENTRIES;
		} else if (strcmp(key, "rdw")  == 0) {
			value = strtok(NULL, delimiter);
			enabled = strtoul(value, NULL, 0);
			if (enabled == 1)
				dsc->keeprdw = true;
			else
				dsc->keeprdw = false;
		} else if (strcmp(key, "conv") == 0) {
			value = strtok(NULL, delimiter);
			if (strchr(value, ',') != NULL) {
				/* use provided codepages */
				value = strtok(value, ",");
				dsc->codepage_from = util_strdup(value);
				value = strtok(NULL, delimiter);
				dsc->codepage_to = util_strdup(value);
			} else if (strcmp(value, "1") == 0) {
				/* use default codepages */
				dsc->codepage_from = CODEPAGE_EDF;
				dsc->codepage_to = CODEPAGE_LINUX;
			} else if  (strcmp(value, "0") == 0) {
				/* disable conversion */
				dsc->codepage_from = NULL;
				dsc->codepage_to = NULL;
			} else {
				fprintf(stderr,
					"Error in config file %s line %d. Invalid 'conv' statement: %s.\n",
					config, linecount, value);
				goto out;
			}
		} else {
			fprintf(stderr,
				"Error in config file %s line %d. Missing 'rdw' or 'conv' statement.\n",
				config, linecount);
			goto out;
		}
		in_section--;
		/* if the section was parsed completely, add the dsc to the list */
		if (!in_section) {
			if (zdsfs_check_codepage_setting(dsc->codepage_from,
							 dsc->codepage_to)) {
				fprintf(stderr,
					"Error in config file %s. Invalid codepage setting: %s %s.\n",
					config, dsc->codepage_from,
					dsc->codepage_to);
				goto out;
			}
			dsclist_add(zdsfsinfo.dsclist, dsc);
			dsc = NULL;
		}
		free(tmp);
		tmp = NULL;
	}
	/* find incomplete last section */
	if (in_section)
		fprintf(stderr,
			"Error in config file %s. Missing 'rdw' or 'conv' statement.\n",
			config);
	else
		rc = 0;

out:
	fclose(fd);
	free(tmp);
	dsc_free(dsc);

	return rc;
}

static int zdsfs_process_args(void *UNUSED(data), const char *arg, int key,
			      struct fuse_args *outargs)
{
	struct stat sb;
	unsigned long tracks_per_frame;
	unsigned long long seek_buffer_size;
	const char *value;
	char *endptr;

	switch (key) {
	case FUSE_OPT_KEY_OPT:
		return 1;
	case FUSE_OPT_KEY_NONOPT:
		if (stat(arg, &sb) < 0) {
			fprintf(stderr, "could not stat device %s, %s\n",
				arg, strerror(errno));
			return 1;
		}
		if (S_ISBLK(sb.st_mode)) {
			zdsfs_process_device(arg);
			return 0;
		}
		/* not a block device, so let fuse parse it */
		return 1;
	case KEY_DEVFILE:
		/* note that arg starts with "-l" */
		zdsfs_process_device_file(arg + 2);
		return 0;
	case KEY_TRACKS:
		value = arg + strlen("tracks=");
		/* strtoul does not complain about negative values  */
		if (*value == '-') {
			errno = EINVAL;
		} else {
			errno = 0;
			tracks_per_frame = strtoul(value, &endptr, 10);
		}
		if (!errno && tracks_per_frame <= UINT_MAX)
			zdsfsinfo.tracks_per_frame = tracks_per_frame;
		else
			errno = ERANGE;
		if (errno || (endptr && (*endptr != '\0'))) {
			fprintf(stderr, "Invalid value '%s' for option "
				"'tracks'\n", value);
			exit(1);
		}
		return 0;
	case KEY_SEEKBUFFER:
		value = arg + strlen("seekbuffer=");
		/* strtoull does not complain about negative values  */
		if (*value == '-') {
			errno = EINVAL;
		} else {
			errno = 0;
			seek_buffer_size = strtoull(value, &endptr, 10);
		}
		if (errno || (endptr && (*endptr != '\0'))) {
			fprintf(stderr,	"Invalid value '%s' for option "
				"'seekbuffer'\n", value);
			exit(1);
		}
		zdsfsinfo.seek_buffer_size = seek_buffer_size;
		return 0;
	case KEY_HELP:
		usage(outargs->argv[0]);

		/*
		 * Usage output needs to go to stdout to be consistent with
		 * coding guidelines. FUSE versions before 3.0.0 print help
		 * output to stderr. Redirect stderr to stdout here to enforce
		 * consistent behavior.
		 */
		fflush(stderr);
		dup2(STDOUT_FILENO, STDERR_FILENO);

		fuse_opt_add_arg(outargs, "-ho");
		/* call fuse_main to let library print fuse options */
		fuse_main(outargs->argc, outargs->argv, &rdf_oper, NULL);
		exit(0);
	case KEY_VERSION:
		fprintf(stdout, COMP "FUSE file system for z/OS data set access"
			", program version %s\n", RELEASE_STRING);
		fprintf(stdout, "Copyright IBM Corp. 2013, 2017\n");
		exit(0);
	case KEY_CONFIG:
		/* note that arg starts with "-c" */
		zdsfsinfo.configfile = util_strdup(arg + 2);
		return 0;
	case KEY_DSCONFIG:
		/* note that arg starts with "-x" */
		zdsfsinfo.dsfile = util_strdup(arg + 2);
		return 0;
	case KEY_SERVER:
		if (zdsfsinfo.nr_server >= MAX_SERVER)
			return 0;
		value = arg + strlen("restserver=");
		zdsfsinfo.server[zdsfsinfo.nr_server] =
			util_strdup(value);
		zdsfsinfo.nr_server++;
		return 0;
	case KEY_CODE_FROM:
		value = arg + strlen("codepage_from=");
		zdsfsinfo.codepage_from =
			util_strdup(value);
		return 0;
	case KEY_CODE_TO:
		value = arg + strlen("codepage_to=");
		zdsfsinfo.codepage_to =
			util_strdup(value);
		return 0;
	default:
		fprintf(stderr, "Unknown argument key %x\n", key);
		exit(1);
	}
}


int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	int rc;

	timer_running = 0;
	bzero(&zdsfsinfo, sizeof(zdsfsinfo));
	zdsfsinfo.keepRDW = 0;
	zdsfsinfo.allow_inclomplete_multi_volume = 0;
	zdsfsinfo.tracks_per_frame = 128;
	zdsfsinfo.seek_buffer_size = 1048576;
	zdsfsinfo.configfile = "/etc/zdsfs.conf";
	zdsfsinfo.dsfile = "/etc/zdsfs-dataset.conf";
	zdsfsinfo.keepalive = DEFAULT_KEEPALIVE_SEC;
	zdsfsinfo.active_server = -1;

	rc = lzds_zdsroot_alloc(&zdsfsinfo.zdsroot);
	open_dsh = dshlist_alloc();
	zdsfsinfo.dsclist = dsclist_alloc();

	if (rc) {
		fprintf(stderr, "Could not allocate internal structures\n");
		exit(1);
	}
	if (fuse_opt_parse(&args, &zdsfsinfo, zdsfs_opts,
			   zdsfs_process_args) == -1) {
		fprintf(stderr, "Failed to parse option\n");
		exit(1);
	}
	if (zdsfs_check_codepage_setting(zdsfsinfo.codepage_from,
					 zdsfsinfo.codepage_to)) {
		fprintf(stderr, "Ivalid codepage setting from '%s' to '%s'\n",
			zdsfsinfo.codepage_from,
			zdsfsinfo.codepage_to);
		rc = -EINVAL;
		goto cleanup;
	}
	zdsfs_process_config_file(zdsfsinfo.configfile);
	if (zdsfs_process_dataset_conf(zdsfsinfo.dsfile)) {
		rc = -EACCES;
		goto cleanup;
	}
	if (!zdsfsinfo.devcount) {
		fprintf(stderr, "Please specify a block device\n");
		fprintf(stderr, "Try '%s --help' for more information\n",
			argv[0]);
		exit(1);
	}

	if (zdsfsinfo.host_count) {
		/* check, print error and exit if multiple online */
		rc = lzds_analyse_open_count(zdsfsinfo.zdsroot, 0);
		if (rc == -EACCES)
			goto cleanup;
	} else {
		/* check, print warning if multiple online */
		lzds_analyse_open_count(zdsfsinfo.zdsroot, 1);
	}

	rc = zdsfs_verify_datasets();
	if (rc)
		goto cleanup;

	rc = zdsfs_create_meta_data_buffer(&zdsfsinfo);
	if (rc)
		goto cleanup;

	if (zdsfsinfo.restapi) {
		curl_global_init(CURL_GLOBAL_DEFAULT);
		zdsfs_test_restserver();
		if (zdsfsinfo.active_server < 0) {
			fprintf(stderr, "Error: No z/OSMF REST Server reachable\n");
			rc = -EACCES;
			goto cleanup;
		}
	}
	rc = fuse_main(args.argc, args.argv, &rdf_oper, NULL);

cleanup:
	curl_global_cleanup();
	dshlist_free(open_dsh);
	dsclist_free(zdsfsinfo.dsclist);
	lzds_zdsroot_free(zdsfsinfo.zdsroot);

	fuse_opt_free_args(&args);
	return rc;
}

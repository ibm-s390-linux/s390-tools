/*
 * cmsfs-fuse - CMS EDF filesystem support for Linux
 *
 * Main function
 *
 * Copyright IBM Corp. 2010, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#define FUSE_USE_VERSION 26
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <iconv.h>
#include <limits.h>
#include <linux/fs.h>
#ifdef HAVE_SETXATTR
#include <linux/xattr.h>
#endif
#include <math.h>
#include <search.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_list.h"
#include "lib/zt_common.h"

#include "cmsfs-fuse.h"
#include "ebcdic.h"
#include "edf.h"
#include "helper.h"

struct cmsfs cmsfs;
static struct util_list open_file_list;
static struct util_list text_type_list;
FILE *logfile;

#define FSNAME_MAX_LEN	200
#define MAX_FNAME	18

#define CMSFS_OPT(t, p, v) { t, offsetof(struct cmsfs, p), v }

enum {
	KEY_HELP,
	KEY_VERSION,
};

static const struct fuse_opt cmsfs_opts[] = {
	CMSFS_OPT("-a",			mode, TEXT_MODE),
	CMSFS_OPT("--ascii",		mode, TEXT_MODE),
	CMSFS_OPT("-t",			mode, TYPE_MODE),
	CMSFS_OPT("--filetype",		mode, TYPE_MODE),
	CMSFS_OPT("--from=%s",		codepage_from, 0),
	CMSFS_OPT("--to=%s",		codepage_to, 0),

	FUSE_OPT_KEY("-h",		KEY_HELP),
	FUSE_OPT_KEY("--help",		KEY_HELP),
	FUSE_OPT_KEY("-v",		KEY_VERSION),
	FUSE_OPT_KEY("--version",	KEY_VERSION),
	FUSE_OPT_END
};

static void usage(const char *progname)
{
	fprintf(stdout,
"Usage: %s DEVICE MOUNTPOINT [OPTIONS]\n"
"\n"
"Use the cmsfs-fuse command to read and write files stored on a z/VM CMS disk.\n"
"\n"
"General options:\n"
"    -o opt,[opt...]        Mount options\n"
"    -h   --help            Print help, then exit\n"
"    -v   --version         Print version, then exit\n"
"    -t   --filetype        ASCII translation based on file type\n"
"    -a   --ascii           Force ascii translation\n"
"         --from=           Codepage used on the CMS disk\n"
"         --to=             Codepage used for conversion to Linux\n"
"\n", progname);
}

static char CODEPAGE_EDF[] = "CP1047";
static char CODEPAGE_LINUX[] = "ISO-8859-1";

#define READDIR_FILE_ENTRY	-1
#define READDIR_END_OF_DIR	-2
#define READDIR_DIR_ENTRY	-3
#define READDIR_MAP_ENTRY	-4

#define LINEFEED_OFFSET		((struct record *) -1)
#define LINEFEED_ASCII		0xa
#define LINEFEED_EBCDIC		0x25
#define LINEFEED_NOT_FOUND	-1
#define FILLER_EBCDIC		0x40
#define FILLER_ASCII		0x20

#define RSS_HEADER_STARTED	0x1
#define RSS_HEADER_COMPLETE	0x2
#define RSS_DATA_BLOCK_STARTED	0x4
#define RSS_DATA_BLOCK_EXT	0x8

#define RWS_HEADER_STARTED	0x1
#define RWS_HEADER_COMPLETE	0x2
#define RWS_RECORD_INCOMPLETE	0x4
#define RWS_RECORD_COMPLETE	0x8

#define BWS_BLOCK_NOT_INIT	0x0
#define BWS_BLOCK_NEW		0x1
#define BWS_BLOCK_USED		0x2

#define WCACHE_MAX		(MAX_RECORD_LEN + 1)

struct block {
	off_t		disk_addr;
	unsigned int	disp;
	int		hi_record_nr;
};

struct record_ext {
	/* start addr of the extension */
	off_t		disk_start;
	/* length of extension in this disk block */
	int		len;
	/* null block start flag */
	int		null_block_started;
	/* corresponding disk block number */
	int		block_nr;

	struct record_ext *prev;
	struct record_ext *next;
};

struct record {
	/* length of the complete record */
	unsigned int	total_len;
	/* offset of first record block on the disk */
	off_t		disk_start;
	/* bytes in first record block */
	int		first_block_len;
	/* logical offset, dependent on line feed mode */
	off_t		file_start;
	/* null block start flag */
	int		null_block_started;
	/* spanned record extension */
	struct record_ext *ext;
	/* corresponding disk block number */
	int		block_nr;
};

struct file;

struct file_operations {
	int (*cache_data) (struct file *f, off_t addr, int level, int *block,
			    unsigned int *disp, int *record, off_t *total);
	int (*write_data) (struct file *f, const char *buf, int len, size_t size,
			   int rlen);
	int (*delete_pointers) (struct file *f, int level, off_t addr);
	int (*write_pointers) (struct file *f, int level, off_t dst, int offset);
};

static struct file_operations fops_fixed;
static struct file_operations fops_variable;

struct io_operations {
	int (*read) (void *buf, size_t size, off_t addr);
	int (*write) (const void *buf, size_t size, off_t addr);
};

static struct io_operations io_ops;

struct write_state {
	int		block_state;
	/* number of free bytes in the current block */
	int		block_free;
	int		var_record_state;
	/* remaining record bytes for a write request */
	int		var_record_len;
	/* only used for var records hi_record_nr by now */
	int		var_records_written;
};

/*
 * File object for operations that follow open
 */
struct file {
	/* pointer to the fst entry */
	struct fst_entry *fst;
	/* fst address on disk */
	off_t		fst_addr;
	/* translate mode enabled */
	int		translate;
	/* linefeed mode enabled */
	int		linefeed;
	/* list of records */
	struct		record *rlist;
	/* record scan state machine flag */
	int		record_scan_state;
	/* next record for sequential reads */
	int		next_record_hint;
	/* counter for null bytes to detect block start */
	int		null_ctr;
	/* list of disk blocks */
	struct		block *blist;
	/* disk address of next byte to write */
	off_t		write_ptr;
	/* the filesize while the file is opened */
	off_t		session_size;
	/* number of null blocks for fixed files */
	int		nr_null_blocks;
	/* number of written padding bytes for a fixed file */
	int		pad_bytes;
	/* old levels value, needed to rewrite pointers */
	int		old_levels;
	/* state information needed for a write request */
	struct write_state *wstate;
	/* path name for open and unlink */
	char		path[MAX_FNAME + 1];
	/* counter for pseudo null length records */
	int		null_records;
	/* write cache for text mode */
	char		*wcache;
	/* buffer for iconv */
	char		*iconv_buf;
	/* used bytes in write cache */
	int		wcache_used;
	/* committed written bytes to FUSE */
	int		wcache_commited;
	/* dirty flag for file meta data */
	int		ptr_dirty;
	/* fops pointers */
	struct file_operations *fops;
	/* pointers per block constant */
	int		ptr_per_block;
	/* open list head */
	struct util_list_node	list;
	/* usage counter for all openers */
	int		use_count;
	/* usage counter for all writers */
	int		write_count;
	/* unlink flag */
	int		unlinked;
};

struct xattr {
	char		name[20];
	size_t		size;
};

/*
 * Record format: 'F' (fixed) or 'V' (variable), 1 byte
 * Record lrecl: 0-65535, 5 bytes
 * Record mode: [A-Z][0-6], 2 bytes
 */
static struct xattr xattr_format = { .name = "user.record_format", .size = 1 };
static struct xattr xattr_lrecl = { .name = "user.record_lrecl", .size = 5 };
static struct xattr xattr_mode = { .name = "user.file_mode", .size = 2 };

#define SHOW_UNLINKED		0
#define HIDE_UNLINKED		1

#define WALK_FLAG_LOOKUP	0x1
#define WALK_FLAG_READDIR	0x2
#define WALK_FLAG_LOCATE_EMPTY	0x4
#define WALK_FLAG_CACHE_DBLOCKS	0x8

struct walk_file {
	int		flag;
	char		*name;
	char		*type;
	void		*buf;
	off_t		addr;
	fuse_fill_dir_t	filler;
	off_t		*dlist;
	int		dlist_used;
};

/*
 * Prototypes
 */
static struct file *create_file_object(struct fst_entry *fst, int *rc);
static void destroy_file_object(struct file *f);

static unsigned long dec_to_hex(unsigned long long num)
{
	unsigned long res;

	asm volatile("cvb %0,%1" : "=d" (res) : "Q" (num));
	return res & 0xffffffff;
}

static unsigned int hex_to_dec(unsigned int num)
{
	unsigned long long res;

	asm volatile("cvd %1,%0" : "=Q" (res) : "d" (num));
	return res & 0xffffffff;
}

static void setup_iconv(iconv_t *conv, const char *from, const char *to)
{
	*conv = iconv_open(to, from);
	if (*conv == ((iconv_t) -1))
		DIE("Could not initialize conversion table %s->%s.\n",
			from, to);
}

static inline struct file *get_fobj(struct fuse_file_info *fi)
{
	return (struct file *)(unsigned long) fi->fh;
}

static int access_ok(size_t size, off_t addr)
{
	if (((addr + (off_t) size - 1) & ~DATA_BLOCK_MASK) >
	    (addr & ~DATA_BLOCK_MASK))
		DIE("crossing disk blocks, addr: %x  size: %d\n",
			(int) addr, (int) size);

	if ((unsigned long long) addr < (unsigned long long) cmsfs.label
	    || addr > cmsfs.size)
		return 0;
	return 1;
}

static int read_memory(void *buf, size_t size, off_t addr)
{
	memcpy(buf, cmsfs.map + addr, size);
	return 0;
}

static int read_syscall(void *buf, size_t size, off_t addr)
{
	int rc;

	rc = pread(cmsfs.fd, buf, size, addr);
	if (rc < 0)
		perror("pread failed");
	return rc;
}

int _read(void *buf, size_t size, off_t addr)
{
	if (!access_ok(size, addr))
		return -EIO;

	return io_ops.read(buf, size, addr);
}

static int write_syscall(const void *buf, size_t size, off_t addr)
{
	char *zbuf;
	int rc;

	if (buf == NULL) {
		zbuf = malloc(size);
		if (zbuf == NULL)
			return -ENOMEM;
		memset(zbuf, 0, size);
		rc = pwrite(cmsfs.fd, zbuf, size, addr);
		free(zbuf);
	} else
		rc = pwrite(cmsfs.fd, buf, size, addr);

	if (rc < 0)
		perror("pwrite failed");
	return rc;
}

static int write_memory(const void *buf, size_t size, off_t addr)
{
	if (buf == NULL)
		memset(cmsfs.map + addr, 0, size);
	else
		memcpy(cmsfs.map + addr, buf, size);
	return 0;
}

int _write(const void *buf, size_t size, off_t addr)
{
	if (!access_ok(size, addr))
		return -EIO;

	return io_ops.write(buf, size, addr);
}

int _zero(off_t addr, size_t size)
{
	return _write(NULL, size, addr);
}

static off_t get_filled_block(void)
{
	off_t addr = get_free_block();

	if (addr < 0)
		return -ENOSPC;

	memset(cmsfs.map + addr, FILLER_EBCDIC, cmsfs.blksize);
	return addr;
}

static int get_fop(off_t addr)
{
	struct fst_entry fst;
	int rc;

	rc = _read(&fst, sizeof(fst), addr);
	BUG(rc < 0);
	return ABS(fst.fop);
}

static int get_levels(off_t addr)
{
	struct fst_entry fst;
	int rc;

	rc = _read(&fst, sizeof(fst), addr);
	BUG(rc < 0);
	return fst.levels;
}

static int get_files_count(off_t addr)
{
	struct fst_entry fst;
	int rc;

	rc = _read(&fst, sizeof(fst), addr);
	BUG(rc < 0);
	/* ignore director and allocmap entries */
	return fst.nr_records - 2;
}

static int get_order(int shift)
{
	int count = 0;

	while (!(shift & 0x1)) {
		shift >>= 1;
		count++;
	}
	return count;
}

/*
 * Read pointer from fixed size pointer block and return
 * absolute address on disk.
 */
off_t get_fixed_pointer(off_t addr)
{
	struct fixed_ptr ptr;
	int rc;

	if (!addr)
		return NULL_BLOCK;
	rc = _read(&ptr, sizeof(ptr), addr);
	if (rc < 0)
		return -EIO;
	if (!ptr.next)
		return NULL_BLOCK;
	else
		return ABS((off_t)ptr.next);
}

/*
 * Read variable pointer from block and return absolute address on disk
 * and highest record number.
 */
static off_t get_var_pointer(off_t addr, int *max_record,
			     unsigned int *disp)
{
	struct var_ptr vptr;
	off_t ptr = 0;
	int rc;

	BUG(!addr);

	rc = _read(&vptr, VPTR_SIZE, addr);
	if (rc < 0)
		return -EIO;
	ptr = (off_t) vptr.next;

	*max_record = vptr.hi_record_nr;
	*disp = vptr.disp;

	if (!ptr) {
		if (vptr.hi_record_nr)
			return NULL_BLOCK;
		else
			return VAR_FILE_END;
	} else
		return ABS(ptr);
}

int is_edf_char(int c)
{
	switch (c) {
	case 'A' ... 'Z':
		break;
	case 'a' ... 'z':
		break;
	case '0' ... '9':
		break;
	case '#':
		break;
	case '@':
		break;
	case '+':
		break;
	case '$':
		break;
	case '-':
		break;
	case ':':
		break;
	case '_':
		break;
	default:
		return 0;
	}
	return 1;
}

/*
 * Force conversion to upper case since lower case file names although
 * valid are not accepted by many CMS tools.
 */
static void str_toupper(char *str)
{
	int i;

	for (i = 0; i < (int) strlen(str); i++)
		str[i] = toupper(str[i]);
}

/*
 * Set the FST date to the specified date.
 */
static void update_fst_date(struct fst_entry *fst, struct tm *tm)
{
	unsigned int num;
	int i;

	if (tm->tm_year >= 100)
		fst->flag |= FST_FLAG_CENTURY;
	else
		fst->flag &= ~FST_FLAG_CENTURY;
	fst->date[0] = tm->tm_year;
	fst->date[1] = tm->tm_mon + 1;
	fst->date[2] = tm->tm_mday;
	fst->date[3] = tm->tm_hour;
	fst->date[4] = tm->tm_min;
	fst->date[5] = tm->tm_sec;

	/* convert hex to decimal */
	for (i = 0; i < 6; i++) {
		num = fst->date[i];
		num = hex_to_dec(num);
		fst->date[i] = num >> 4;
	}
}

/*
 * Set the FST date to the current date.
 */
static int set_fst_date_current(struct fst_entry *fst)
{
	struct timeval tv;
	struct tm tm;

	/* convert timespec to tm */
	memset(&tm, 0, sizeof(struct tm));

	if (gettimeofday(&tv, NULL) < 0) {
		perror(COMP "gettimeofday failed");
		return -EINVAL;
	}

	if (localtime_r(&tv.tv_sec, &tm) == NULL)
		return -EINVAL;

	update_fst_date(fst, &tm);
	return 0;
}

/*
 * Check if the file is on the opened list.
 */
static struct file *file_open(const char *name)
{
	char uc_name[MAX_FNAME];
	struct file *f;

	util_strlcpy(uc_name, name, MAX_FNAME);
	str_toupper(uc_name);

	util_list_iterate(&open_file_list, f)
		if (strncmp(f->path + 1, uc_name, MAX_FNAME) == 0)
			return f;
	return NULL;
}

/*
 * Check if the file is open and unlinked.
 */
static int file_unlinked(const char *name)
{
	struct file *f = file_open(name);

	if (f && f->unlinked)
		return 1;
	else
		return 0;
}

/*
 * Convert EDF date to time_t.
 */
static time_t fst_date_to_time_t(char *date, int century)
{
	unsigned long long num;
	unsigned int res[6];
	struct tm tm;
	time_t time;
	int i;

	/*
	 * date : YY MM DD HH MM SS (decimal!)
	 * century: 0=19, 1=20, dead=21
	 * convert decimal to hex
	 */
	for (i = 0; i < 6; i++) {
		num = date[i];
		num <<= 4;
		num += 0xc;	/* plus */
		res[i] = dec_to_hex(num);
	}

	memset(&tm, 0, sizeof(tm));
	tm.tm_year = res[0];
	tm.tm_mon = res[1];
	tm.tm_mday = res[2];
	tm.tm_hour = res[3];
	tm.tm_min = res[4];
	tm.tm_sec = res[5];
	/* see man 3 tzset */
	tm.tm_isdst = -1;

	/* prepare for mktime */
	tm.tm_mon--;
	if (century == FST_FLAG_CENTURY)
		tm.tm_year += 100;

	time = mktime(&tm);
	if (time == -1) {
		fprintf(stderr, COMP "mktime failed!\n");
		memset(&time, 0, sizeof(time));
	}
	return time;
}

/*
 * Read one FST entry into *fst from offset on disk addr and detect type.
 *
 * Return values:
 * ret > 0 : disk address of additional FOP block
 * ret = -1 : file entry filled
 * ret = -2 : end of directory
 * ret = -3 : directory entry
 * ret = -4 : allocmap entry
 */
static int readdir_entry(struct fst_entry *fst, off_t addr)
{
	int rc;

	BUG(addr & (sizeof(struct fst_entry) - 1));

	rc = _read(fst, sizeof(*fst), addr);
	BUG(rc < 0);

	if (is_directory(fst->name, fst->type)) {
		/* check for multi-block directory */
		if (ABS(fst->fop) != addr)
			return ABS(fst->fop);
		return READDIR_DIR_ENTRY;
	}

	if (is_allocmap(fst->name, fst->type))
		return READDIR_MAP_ENTRY;

	if (is_file(fst->name, fst->type))
		return READDIR_FILE_ENTRY;

	return READDIR_END_OF_DIR;
}

/*
 * Return number of characters excluding trailing spaces.
 */
static inline int strip_right(const char *str, int size)
{
	while (str[size - 1] == 0x20)
		size--;
	return size;
}

/*
 * Convert ASCII name to EBCDIC name.
 */
static int encode_edf_name(const char *name, char *fname, char *ftype)
{
	int dot_pos, tlen;
	char *tmp;

	/*
	 * name is ascii string "FILE.EXT"
	 * readdir_entry returns fst.name fst.type as EBCDIC including spaces
	 * pre-fill name and type with ascii spaces, remove dot and convert
	 * to EBCDIC.
	 */
	memset(fname, 0x20, 8);
	memset(ftype, 0x20, 8);

	tmp = index(name, '.');
	/* filenames without a dot are invalid! */
	if (tmp == NULL)
		return -EINVAL;

	dot_pos = tmp - name;
	if (dot_pos == 0 || dot_pos > 8)
		return -EINVAL;
	memcpy(fname, name, dot_pos);
	ebcdic_enc(fname, fname, 8);

	tlen = strlen(name) - (dot_pos + 1);
	if (tlen == 0 || tlen > 8)
		return -EINVAL;

	memcpy(ftype, name + dot_pos + 1, tlen);
	ebcdic_enc(ftype, ftype, 8);
	return 0;
}

/*
 * Convert EBCDIC name to ASCII name.
 */
static void decode_edf_name(char *file, char *fname, char *ftype)
{
	int len, pos = 0;

	ebcdic_dec(fname, fname, 8);
	ebcdic_dec(ftype, ftype, 8);

	/* strip spaces but only from the end */
	len = strip_right(fname, 8);
	memcpy(file, fname, len);

	/* add dot */
	pos += len;
	file[pos] = '.';
	pos++;

	len = strip_right(ftype, 8);
	memcpy(&file[pos], ftype, len);
	pos += len;

	/* terminate string */
	file[pos] ='\0';
}

static int edf_name_valid(const char *name)
{
	int name_len, i;
	char *dot;

	/* name must contain . */
	dot = index(name, '.');
	if (dot == NULL)
		return -EINVAL;

	name_len = dot - name;

	for (i = 0; i < name_len; i++)
		if (!is_edf_char(name[i]))
			return -EINVAL;
	for (i = name_len + 1; i < (int) strlen(name); i++)
		if (!is_edf_char(name[i]))
			return -EINVAL;
	return 0;
}

/*
 * Summarize the number of bytes used in the last data block.
 */
static int walk_last_var_data_block(off_t addr, off_t *total)
{
	ssize_t left = cmsfs.blksize;
	u16 len;
	int rc;

	/* subtract displacement */
	left -= addr & DATA_BLOCK_MASK;

	while (left >= (int) sizeof(len)) {

		rc = _read(&len, sizeof(len), addr);
		if (rc < 0)
			return rc;

		/*
		 * Null length means no more records follow.
		 * Assumption: the last block is zero-padded.
		 */
		if (!len)
			return 0;

		/* add length of record with the header length */
		*total += len + sizeof(len);

		left -= len + sizeof(len);

		/* point to next record */
		addr += len + sizeof(len);
	}
	return 0;
}

/*
 * Return struct record for record number nr.
 */
static struct record *get_record(struct file *f, int nr)
{
	BUG(nr > f->fst->nr_records - 1);
	return &f->rlist[nr];
}

static int skip_header_byte(struct file *f)
{
	if (f->fst->record_format == RECORD_LEN_FIXED)
		return 0;

	if (f->record_scan_state == RSS_HEADER_STARTED)
		return 1;
	else
		return 0;
}

static void set_record_len_upper(struct file *f, int record, u8 len)
{
	struct record *r = &f->rlist[record];

	if (f->record_scan_state != RSS_DATA_BLOCK_STARTED &&
	    f->record_scan_state != RSS_DATA_BLOCK_EXT)
		DIE("%s: internal error\n", __func__);

	r->total_len = len << 8;
	f->record_scan_state = RSS_HEADER_STARTED;
}

static void set_record_len_lower(struct file *f, int record, u8 len)
{
	struct record *r = &f->rlist[record];

	if (f->record_scan_state != RSS_HEADER_STARTED)
		DIE("%s: internal error\n", __func__);

	r->total_len += len;
	f->record_scan_state = RSS_HEADER_COMPLETE;
}

static void set_record_len(struct file *f, int record, u16 len)
{
	struct record *r = &f->rlist[record];

	if (f->fst->nr_records && f->fst->nr_records == record)
		DIE("%s: record nr: %d out of bounds\n", __func__, record);

	if (f->record_scan_state != RSS_DATA_BLOCK_STARTED &&
	    f->record_scan_state != RSS_DATA_BLOCK_EXT)
		DIE("%s: internal error\n", __func__);

	r->total_len = len;
	f->record_scan_state = RSS_HEADER_COMPLETE;
}

static void set_record(struct file *f, int *record, off_t addr, int len,
		       off_t *total, int block)
{
	struct record *r = &f->rlist[*record];

	if (f->record_scan_state != RSS_HEADER_COMPLETE)
		DIE("%s: internal error\n", __func__);

	r->first_block_len = len;
	r->disk_start = addr;
	r->block_nr = block;

	if (addr == NULL_BLOCK) {
		if (f->null_ctr % cmsfs.blksize == 0)
			r->null_block_started = 1;
		f->null_ctr += len;
	} else
		f->null_ctr = 0;

	/* add previous record linefeed but not for the first record */
	if (f->linefeed && *record)
		(*total)++;
	r->file_start = *total;
	(*total) += r->total_len;
	f->record_scan_state = RSS_DATA_BLOCK_STARTED;
}

static void add_record_ext(struct record *rec, struct record_ext *ext)
{
	struct record_ext *tmp;

	if (rec->ext == NULL) {
		rec->ext = ext;
		ext->prev = NULL;
		ext->next = NULL;
	} else {
		tmp = rec->ext;
		while (tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = ext;
		ext->prev = tmp;
		ext->next = NULL;
	}
}

static void set_record_extension(struct file *f, int *record, off_t addr,
				 int len, int block)
{
	struct record *rec = &f->rlist[*record];
	struct record_ext *ext;

	if (f->record_scan_state != RSS_DATA_BLOCK_STARTED &&
	    f->record_scan_state != RSS_DATA_BLOCK_EXT)
		DIE("%s: interal error\n", __func__);

	BUG(*record >= f->fst->nr_records);

	ext = malloc(sizeof(struct record_ext));
	if (ext == NULL)
		DIE_PERROR("malloc failed\n");
	memset(ext, 0, sizeof(*ext));
	ext->len = len - skip_header_byte(f);
	ext->disk_start = addr + skip_header_byte(f);
	ext->block_nr = block;

	if (ext->disk_start == NULL_BLOCK) {
		if (f->null_ctr % cmsfs.blksize == 0)
			ext->null_block_started = 1;
		f->null_ctr += len;
	} else
		f->null_ctr = 0;

	add_record_ext(rec, ext);
	f->record_scan_state = RSS_DATA_BLOCK_EXT;
}

/* check for file end by record number */
static int end_of_file(struct file *f, int record)
{
	if (record == f->fst->nr_records - 1)
		return 1;
	return 0;
}

static int walk_fixed_data_block(struct file *f, off_t addr, int *record,
				  off_t *total, int block, int disp)
{
	off_t offset = (off_t ) block * cmsfs.blksize + disp;
	int len = (f->fst->record_len > cmsfs.blksize) ?
		cmsfs.blksize : f->fst->record_len;
	int left = cmsfs.blksize - disp;
	int first = 0;

	if (offset % f->fst->record_len) {
		if (f->fst->record_len - offset >= cmsfs.blksize)
			first = cmsfs.blksize;
		else
			first = (f->fst->record_len % cmsfs.blksize) - (offset % len);
	}

	if (first) {
		BUG(first > left);
		set_record_extension(f, record, addr, first, block);
		left -= first;
		if (addr != NULL_BLOCK)
			addr += first;
	}

	while (left >= len) {
		/*
		 * Increment record number only after adding a possible
		 * extension. *record starts with -1 so the first is 0.
		 */
		if (end_of_file(f, *record))
			return 1;
		(*record)++;

		set_record_len(f, *record, f->fst->record_len);
		set_record(f, record, addr, len, total, block);

		left -= len;
		if (addr != NULL_BLOCK)
			addr += len;
	}

	/* partial record left */
	if (left > 0) {
		if (end_of_file(f, *record))
			return 1;
		(*record)++;

		set_record_len(f, *record, f->fst->record_len);
		set_record(f, record, addr, left, total, block);
		return 0;
	}
	return 0;
}

static int get_record_unused_bytes(struct file *f, int nr)
{
	struct record *rec = get_record(f, nr);
	struct record_ext *rext;
	int used = 0;

	/* no data bytes yet */
	if (f->record_scan_state == RSS_HEADER_COMPLETE)
		return rec->total_len;

	used = rec->first_block_len;

	/* only first block */
	if (f->record_scan_state == RSS_DATA_BLOCK_STARTED)
		goto out;
	rext = rec->ext;
	while (rext != NULL) {
		used += rext->len;
		rext = rext->next;
	}
out:
	return rec->total_len - used;
}

static int walk_var_data_block(struct file *f, off_t addr, unsigned int disp,
			       int *record, off_t *total, int block, int skip)
{
	ssize_t left = cmsfs.blksize - skip;
	int last, rc;
	u8 half_len;
	u16 len;

	/*
	 * If records are skipped on this block there is no record extension,
         * overwrite disp and start with scanning the record.
	 */
	if (skip)
		disp = 0;

	/*
	 * disp set means 1 or 2 header bytes and possibly data bytes on the
	 * last block or a null block.
	 */
	if (disp) {
		if (addr == NULL_BLOCK) {
			last = cmsfs.blksize;

			/*
			 * Special case: last block can be a null block with
			 * not all bytes used on it.
			 */
			if (f->fst->nr_blocks - 1 == block)
				last = get_record_unused_bytes(f, *record);

			/*
			 * Special case: record header on last block wo. data.
			 * That means no record data yet for this block.
			 */
			if (f->record_scan_state == RSS_HEADER_COMPLETE)
				set_record(f, record, addr, last, total, block);
			else
				set_record_extension(f, record, addr, last,
						     block);
			return 0;
		}

		if (disp == VAR_RECORD_SPANNED)
			len = cmsfs.blksize;
		else
			len = disp;


		/* split header -> read second length byte */
		if (f->record_scan_state == RSS_HEADER_STARTED) {
			rc = _read(&half_len, sizeof(half_len), addr);
			if (rc < 0)
				return rc;
			set_record_len_lower(f, *record, half_len);
			left--;
			len--;
			addr++;
		}

		if (f->record_scan_state == RSS_HEADER_COMPLETE)
			set_record(f, record, addr, len, total, block);
		else
			set_record_extension(f, record, addr, len, block);

		if (disp == VAR_RECORD_SPANNED)
			return 0;

		left -= len;
		addr += len;
	}

	/* at least one data byte */
	while (left >= (int) sizeof(len) + 1) {

		rc = _read(&len, sizeof(len), addr);
		if (rc < 0)
			return rc;

		/*
		 * Null length means no more records follow.
		 * Assumption: the last block is zero-padded.
		 */
		if (!len)
			return 0;

		/*
		 * Increment record number only after adding a possible
		 * extension. *record starts with -1 so the first is 0.
		 */
		(*record)++;
		set_record_len(f, *record, len);

		/* account consumed header bytes */
		left -= sizeof(len);
		addr += sizeof(len);

		/* limit to block end */
		if (len > left)
			len = left;

		/* add length of record including the header length */
		set_record(f, record, addr, len, total, block);

		left -= len;
		/* point to next record header */
		addr += len;
	}

	/* 2 header bytes left */
	if (left == 2) {
		rc = _read(&len, sizeof(len), addr);
		if (rc < 0)
			return rc;
		if (!len)
			return 0;

		(*record)++;
		set_record_len(f, *record, len);
		return 0;
	}

	/* split header */
	if (left == 1) {
		if (end_of_file(f, *record))
			return 0;
		rc = _read(&half_len, sizeof(half_len), addr);
		if (rc < 0)
			return rc;
		(*record)++;
		set_record_len_upper(f, *record, half_len);
		f->record_scan_state = RSS_HEADER_STARTED;
	}
	return 0;
}

static int cache_fixed_data_block(struct file *f, off_t addr, int *block,
				  int *record, off_t *total, int disp)
{
	/*
	 * Cannot distinguish null block pointers from not existing pointers,
	 * so this fn is called for the whole pointer block and maybe for
	 * non-existing blocks and records too. Check and bail out if EOF.
	 */
	if (*block >= f->fst->nr_blocks || *record >= f->fst->nr_records)
		return 0;

	f->blist[*block].disk_addr = addr & ~DATA_BLOCK_MASK;
	walk_fixed_data_block(f, addr, record, total, *block, disp);
	/* record starts with 0 but on-disk record number with 1 */
	f->blist[*block].hi_record_nr = *record + 1;
	(*block)++;
	return 0;
}

/*
 * Walk all pointer blocks of a fixed file and call function for every
 * data block respecting the sequence of the data.
 */
static int cache_file_fixed(struct file *f, off_t addr, int level, int *block,
			    unsigned int *disp, int *record, off_t *total)
{
	int left = f->ptr_per_block;
	off_t ptr;

	if (level > 0) {
		level--;
		while (left--) {
			ptr = get_fixed_pointer(addr);
			if (ptr < 0)
				return ptr;
			/*
			 * In difference to variable record format a null pointer
			 * may be valid for a null block so we cannot determine
			 * the file end from a pointer entry. Check for the number
			 * of scanned blocks instead.
			 */
			if (*block >= f->fst->nr_blocks
			    || *record >= f->fst->nr_records)
				return 0;
			cache_file_fixed(f, ptr, level, block, disp, record, total);
			/* don't increment for null block pointers */
			if (addr)
				addr += PTR_SIZE;
		}
		return 0;
	}
	return cache_fixed_data_block(f, addr, block, record, total, 0);
}

static int cache_variable_data_block(struct file *f, off_t addr, int *block,
				      int *record, int disp, off_t *total, int skip)
{
	int rc;

	/*
	 * Cannot distinguish null block pointers from not existing pointers,
	 * so this fn is called for the whole pointer block and maybe for
	 * non-existing blocks and records too. Check and bail out if EOF.
	 */
	if (*block >= f->fst->nr_blocks || *record >= f->fst->nr_records)
		return 0;

	f->blist[*block].disk_addr = addr & ~DATA_BLOCK_MASK;
	rc = walk_var_data_block(f, addr, disp, record, total, *block, skip);
	if (rc < 0)
		return rc;

	/* record starts with 0 but on-disk record number with 1 */
	f->blist[*block].hi_record_nr = *record + 1;
	f->blist[*block].disp = disp;
	(*block)++;
	return 0;
}

/*
 * Walk all pointer blocks of a variable file and call function for every
 * data block respecting the sequence of the data.
 */
static int cache_file_variable(struct file *f, off_t addr, int level,
				int *block, unsigned int *disp,
				int *record, off_t *total)
{
	int nr, left = f->ptr_per_block;
	off_t ptr;

	if (level > 0) {
		level--;
		/* 4 or 8 bytes are left at the end (offset) which we ignore */
		while (left--) {
			ptr = get_var_pointer(addr, &nr, disp);
			if (ptr < 0)
				return ptr;
			if (ptr == VAR_FILE_END)
				return 0;
			cache_file_variable(f, ptr, level, block,
					    disp, record, total);
			addr += VPTR_SIZE;
		}
		return 0;
	}
	return cache_variable_data_block(f, addr, block, record, *disp, total, 0);
}

static int locate_last_data_vptr(off_t addr, int level,
				  struct fst_entry *fst, struct var_ptr *vptr)
{
	int last, rc;

	if (!level)
		return 0;
	level--;

	/* read offset pointer from the end of the var pointer block */
	rc = _read(&last, sizeof(last), addr + cmsfs.blksize - sizeof(last));
	if (rc < 0)
		return rc;

	if (last % VPTR_SIZE || last > cmsfs.blksize)
		return -EIO;
	rc = _read(vptr, VPTR_SIZE, addr + last);
	if (rc < 0)
		return rc;
	if (vptr->hi_record_nr != fst->nr_records)
		return -EIO;

	/* vptr should contain the highest data block pointer */
	if (!level)
		return 0;

	if (vptr->next == NULL_BLOCK)
		return 0;

	return locate_last_data_vptr(ABS(vptr->next), level, fst, vptr);
}

static int is_textfile(struct fst_entry *fst)
{
	char type[MAX_TYPE_LEN];
	struct filetype *ft;

	if (!fst)
		return 0;

	memset(type, 0, sizeof(type));
	ebcdic_dec(type, fst->type, 8);

	util_list_iterate(&text_type_list, ft)
		if (strncmp(ft->name, type, strlen(ft->name)) == 0)
			return 1;
	return 0;
}

/*
 * Decide if linefeeds are needed for this file type.
 */
static int linefeed_mode_enabled(struct fst_entry *fst)
{
	if (cmsfs.mode == BINARY_MODE)
		return 0;
	if (cmsfs.mode == TEXT_MODE)
		return 1;
	return is_textfile(fst);
}

/*
 * Workaround glibc 2.9 bug with less than 3 files and give room for some
 * new files. If cache is full it will be purged and rebuild.
 */
static int max_cache_entries(void)
{
	return cmsfs.files + 10 + cmsfs.files / 4;
}

static void resize_htab(void)
{
	int i;

	for (i = 0; i < cmsfs.fcache_used; i++)
		free(cmsfs.fcache[i].str);
	hdestroy_r(&cmsfs.htab);
	free(cmsfs.fcache);
	cmsfs.fcache_used = 0;
	cmsfs.fcache_max = max_cache_entries();

	cmsfs.fcache = calloc(cmsfs.fcache_max, sizeof(struct fcache_entry));
	if (!hcreate_r(cmsfs.fcache_max, &cmsfs.htab))
		DIE("hcreate failed\n");
}

static void cache_fst_addr(off_t addr, const char *file)
{
	struct fcache_entry *fce;
	ENTRY e, *eptr;

	e.key = strdup(file);

again:
	if (hsearch_r(e, FIND, &eptr, &cmsfs.htab) == 0) {
		/* cache it */
		if (cmsfs.fcache_used == cmsfs.fcache_max - 1) {
			DEBUG("hsearch: hash table full: %d\n", cmsfs.fcache_used);
			resize_htab();
			goto again;
		}

		fce = &cmsfs.fcache[cmsfs.fcache_used];
		cmsfs.fcache_used++;
		fce->fst_addr = addr;
		fce->str = e.key;

		e.data = fce;
		if (hsearch_r(e, ENTER, &eptr, &cmsfs.htab) == 0)
			DIE("hsearch: hash table full\n");
	} else
		free(e.key);
}

static void update_htab_entry(off_t addr, const char *file)
{
	struct fcache_entry *fce;
	ENTRY e, *eptr;

	e.key = strdup(file);

	if (hsearch_r(e, FIND, &eptr, &cmsfs.htab) == 0) {
		/* not yet cached, nothing to do */
		free(e.key);
		return;
	} else {
		/* update it */
		fce = eptr->data;
		fce->fst_addr = addr;
		e.data = fce;
		if (hsearch_r(e, ENTER, &eptr, &cmsfs.htab) == 0)
			DIE("%s: hash table full\n", __func__);
	}
}

static void invalidate_htab_entry(const char *name)
{
	struct fcache_entry *fce;
	ENTRY e, *eptr;

	e.key = strdup(name);

	if (hsearch_r(e, FIND, &eptr, &cmsfs.htab) == 0) {
		/* nothing to do if not cached */
		free(e.key);
		return;
	}

	fce = eptr->data;
	fce->fst_addr = 0;
	e.data = fce;
	if (hsearch_r(e, ENTER, &eptr, &cmsfs.htab) == 0)
		DIE("hsearch: hash table full\n");
}

/*
 * For each FST entry in a directory block do action.
 *
 * Return:
 *	hit == NULL : lookup file not found
 *	hit != NULL : lookup file found, addr of the fst entry
 */
static void walk_dir_block(struct fst_entry *fst, struct walk_file *walk,
			   int level, off_t *hit)
{
	off_t ptr, addr = walk->addr;
	char file[MAX_FNAME];
	int ret, left;

	/* handle higher level directory pointer blocks */
	if (level > 0) {
		level--;
		left = PTRS_PER_BLOCK;
		while (left--) {
			ptr = get_fixed_pointer(addr);
			BUG(ptr < 0);
			if (!ptr)
				break;
			walk->addr = ptr;
			walk_dir_block(fst, walk, level, hit);
			if (hit != NULL && *hit)
				return;
			addr += PTR_SIZE;
		}
		return;
	}

	if (walk->flag == WALK_FLAG_CACHE_DBLOCKS) {
		walk->dlist[walk->dlist_used++] = walk->addr;
		return;
	}

	left = cmsfs.blksize / sizeof(struct fst_entry);
	while (left--) {
		ret = readdir_entry(fst, walk->addr);

		/* directory and allocmap type are skipped */

		if (ret == READDIR_FILE_ENTRY) {
			if (walk->flag == WALK_FLAG_LOOKUP) {
				if ((memcmp(fst->name, walk->name, 8) == 0) &&
				    (memcmp(fst->type, walk->type, 8) == 0)) {
					/* got it */
					*hit = walk->addr;
					return;
				}
			}

			if (walk->flag == WALK_FLAG_READDIR) {
				memset(file, 0, sizeof(file));
				decode_edf_name(file, fst->name, fst->type);
				if (!file_unlinked(file)) {
					cache_fst_addr(walk->addr, file);
					walk->filler(walk->buf, file, NULL, 0);
				}
			}
		}

		if (ret == READDIR_END_OF_DIR) {
			if (walk->flag == WALK_FLAG_LOCATE_EMPTY) {
				*hit = walk->addr;
				return;
			}
			break;
		}
		walk->addr += sizeof(struct fst_entry);
	};
	return;
}

static void walk_directory(struct fst_entry *fst, struct walk_file *walk,
			   off_t *hit)
{
	if (cmsfs.dir_levels == 0)
		walk->addr = cmsfs.fdir;
	else
		walk->addr = get_fop(cmsfs.fdir);
	walk_dir_block(fst, walk, cmsfs.dir_levels, hit);
}

/*
 * Check FST record format only when reading FST entry from disk.
 */
static int check_fst_valid(struct fst_entry *fst)
{
	if (fst->record_format != RECORD_LEN_FIXED &&
	    fst->record_format != RECORD_LEN_VARIABLE)
		return 0;
	else
		return 1;
}

/*
 * Locate the file's fst_entry in any of the directory blocks.
 */
static off_t lookup_file(const char *name, struct fst_entry *fst, int flag)
{
	struct fcache_entry *fce;
	char uc_name[MAX_FNAME];
	char fname[8], ftype[8];
	struct walk_file walk;
	ENTRY e, *eptr;
	off_t faddr = 0;
	int rc;

	util_strlcpy(uc_name, name, MAX_FNAME);
	str_toupper(uc_name);

	if (flag == HIDE_UNLINKED && file_unlinked(uc_name))
		return 0;

	e.key = strdup(uc_name);

	/* already cached ? */
	if (hsearch_r(e, FIND, &eptr, &cmsfs.htab)) {
		fce = eptr->data;

		/* check if fst is valid, may be zero for a stale entry */
		if (!fce->fst_addr)
			goto renew;

		/* read in the fst entry */
		rc = _read(fst, sizeof(*fst), fce->fst_addr);
		BUG(rc < 0);

		if (!check_fst_valid(fst))
			DIE("Invalid file format in file: %s\n", uc_name);

		free(e.key);
		return fce->fst_addr;
	}

renew:
	free(e.key);
	if (encode_edf_name(uc_name, fname, ftype))
		return 0;
	memset(&walk, 0, sizeof(walk));
	walk.flag = WALK_FLAG_LOOKUP;
	walk.name = fname;
	walk.type = ftype;
	walk_directory(fst, &walk, &faddr);
	if (!faddr)
		return 0;
	if (!check_fst_valid(fst))
		DIE("Invalid file format in file: %s\n", uc_name);
	cache_fst_addr(faddr, uc_name);
	return faddr;
}

static int cache_file(struct file *f)
{
	int block = 0, record = -1;
	unsigned int disp = 0;
	off_t total = 0;

	return f->fops->cache_data(f, ABS(f->fst->fop), f->fst->levels,
				   &block, &disp, &record, &total);
}

/*
 * Caveat: for fixed files nr_blocks is excluding null blocks,
 * for variable files nr_blocks is including null blocks.
 * Add null blocks for fixed files so allocation and file end
 * checks work identical for both variants.
 */
static void workaround_nr_blocks(struct file *f)
{
	int nr;

	if (f->fst->record_format == RECORD_LEN_VARIABLE)
		return;
	nr = (off_t) f->fst->nr_records * (off_t) f->fst->record_len
		/ cmsfs.blksize;
	if ((off_t) f->fst->nr_records * (off_t) f->fst->record_len % cmsfs.blksize)
		nr++;
	f->nr_null_blocks = nr - f->fst->nr_blocks;
	f->fst->nr_blocks = nr;
}

static off_t get_file_size_fixed(struct fst_entry *fst)
{
	return (off_t) fst->nr_records * (off_t) fst->record_len;
}

static off_t get_file_size_variable(struct fst_entry *fst)
{
	struct var_ptr vptr;
	off_t total = 0;
	off_t ptr;
	int rc;

	if (fst->levels > 0) {
		rc = locate_last_data_vptr(ABS(fst->fop), fst->levels, fst,
					   &vptr);
		if (rc < 0)
			return rc;
		if (vptr.next == 0) {
			/*
			 * Last block is a null block. No more records can
			 * follow, so the displacement value points to EOF.
			 */
			total = vptr.disp;
			goto skip_scan;
		}
		ptr = ABS(vptr.next);
		if (vptr.disp != VAR_RECORD_SPANNED) {
			ptr += vptr.disp;
			/* count displacement as used space */
			total += vptr.disp;
		} else {
			total += cmsfs.blksize;
			goto skip_scan;
		}
	} else
		ptr = ABS(fst->fop);

	/* now count the remaining used space in the last block */
	rc = walk_last_var_data_block(ptr, &total);
	if (rc < 0)
		return rc;

skip_scan:
	/*
	 * Add the full blocks. For variable record file nr_blocks contains
	 * also null blocks.
	 */
	if (fst->nr_blocks)
		total += ((off_t) fst->nr_blocks - 1) * cmsfs.blksize;
	return total;
}

/*
 * Return the file size as it is on the disk. Includes headers for
 * variable records.
 */
static off_t get_file_size(struct fst_entry *fst)
{
	if (fst->record_format == RECORD_LEN_FIXED)
		return get_file_size_fixed(fst);
	else if (fst->record_format == RECORD_LEN_VARIABLE)
		return get_file_size_variable(fst);
	return 0;
}

static off_t get_file_size_logical(struct fst_entry *fst)
{
	off_t total;

	if (fst->nr_records == 0)
		return 0;
	if (!fst->fop)
		return -EIO;
	total = get_file_size(fst);
	if (total < 0)
		return -EIO;

	/* subtract the record headers */
	if (fst->record_format == RECORD_LEN_VARIABLE)
		total -= (off_t) fst->nr_records * VAR_RECORD_HEADER_SIZE;

	if (linefeed_mode_enabled(fst))
		total += fst->nr_records;
	return total;
}

static int cmsfs_getattr(const char *path, struct stat *stbuf)
{
	int mask = (cmsfs.allow_other) ? 0444 : 0440;
	struct fst_entry fst;

        if (!cmsfs.readonly)
                mask |= ((cmsfs.allow_other) ? 0222 : 0220);

	memset(stbuf, 0, sizeof(*stbuf));
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_blksize = cmsfs.blksize;

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | mask |
			((cmsfs.allow_other) ? 0111 : 0110);
		stbuf->st_nlink = 2;

		readdir_entry(&fst, cmsfs.fdir);

		/* date */
		stbuf->st_mtime = fst_date_to_time_t(&fst.date[0],
			fst.flag & FST_FLAG_CENTURY);
		stbuf->st_atime = stbuf->st_ctime = stbuf->st_mtime;

		/* size */
		stbuf->st_size = (off_t) fst.record_len * (off_t) fst.nr_records;
		stbuf->st_blocks = MAX(stbuf->st_size, cmsfs.blksize);
		stbuf->st_blocks = ((stbuf->st_blocks + cmsfs.data_block_mask) &
			~cmsfs.data_block_mask) >> 9;
	} else {
		if (!lookup_file(path + 1, &fst, HIDE_UNLINKED))
			return -ENOENT;

		stbuf->st_mode = S_IFREG | mask;
		stbuf->st_nlink = 1;

		/* date */
		stbuf->st_mtime = stbuf->st_atime = stbuf->st_ctime =
			fst_date_to_time_t(&fst.date[0],
					   fst.flag & FST_FLAG_CENTURY);
		/* size */
		stbuf->st_size = get_file_size_logical(&fst);
		if (stbuf->st_size < 0)
			return -EIO;
		/*
		 * Include potential sparse blocks for variable files which
		 * are included in nr_blocks to avoid scanning the whole file.
		 */
		stbuf->st_blocks = (off_t) fst.nr_blocks * cmsfs.nr_blocks_512;
	}
	return 0;
}

static int cmsfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	struct walk_file walk;
	struct fst_entry fst;

	(void) offset;
	(void) fi;

	/*
	 * Offset is ignored and 0 passed to the filler fn so the whole
	 * directory is read at once.
	 */

	/* EDF knows only the root directory */
	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	memset(&walk, 0, sizeof(walk));
	/* readdir is possible without open so fi->fh is not set */
	walk.flag = WALK_FLAG_READDIR;
	walk.buf = buf;
	walk.filler = filler;
	walk_directory(&fst, &walk, NULL);
	return 0;
}

static int cmsfs_open(const char *path, struct fuse_file_info *fi)
{
	struct fst_entry fst;
	struct file *f;
	off_t fst_addr;
	int rc = 0;

	/*
	 * open flags:
	 * O_DIRECTORY: FUSE captures open on / so not needed.
	 * O_NOATIME: ignored because there is no atime in EDF.
	 * O_NOFOLLOW: can be ignored since EDF has no links.
	 * O_SYNC: ignored since IO is always sync.
	 * O_TRUNC, O_CREAT, O_EXCL: avoided by FUSE.
	 */
	fst_addr = lookup_file(path + 1, &fst, SHOW_UNLINKED);
	if (!fst_addr)
		return -ENOENT;

	f = file_open(path + 1);
	if (f == NULL) {
		f = create_file_object(&fst, &rc);
		if (f == NULL)
			return rc;
		f->fst_addr = fst_addr;

		/*
		 * Store file size in file object. Needed for write of fixed record
		 * length files when the write is not a multiple of the record length.
		 * In this case a second write would fail since the file size would
		 * be calculated by lrecl * nr_records. Use session_size therefore.
		 */
		f->session_size = get_file_size_logical(&fst);
		if (f->session_size < 0)
			return -EIO;

		f->wcache = malloc(WCACHE_MAX);
		if (f->wcache == NULL)
			return -ENOMEM;

		/*
		 * For fixed-length records f->fst->record_len contains
		 * the fixed record length, which will not change. For
		 * variable-length records it contains the (current) maximum
		 * record length, which could be increased later by appending
		 * new records, so use MAX_RECORD_LEN for the iconv buffer.
		 * The MAX_RECORD_LEN is not valid for fixed-length records,
		 * only for variable-length records, so use the actual record
		 * length (f->fst->record_len) for fixed-length records.
		 */
		if (f->fst->record_format == RECORD_LEN_FIXED)
			f->iconv_buf = malloc(f->fst->record_len + 1);
		else
			f->iconv_buf = malloc(MAX_RECORD_LEN + 1);
		if (f->iconv_buf == NULL) {
			destroy_file_object(f);
			return -ENOMEM;
		}

		util_strlcpy(f->path, path, MAX_FNAME + 1);
		str_toupper(f->path);

		f->use_count = 1;
		util_list_add_head(&open_file_list, f);
	} else
		f->use_count++;

	if (fi->flags & O_RDWR || fi->flags & O_WRONLY)
		f->write_count++;

	fi->fh = (uint64_t)(unsigned long) f;
	return 0;
}

static void set_fdir_date_current(void)
{
	struct fst_entry fst;
	int rc;

	rc = _read(&fst, sizeof(fst), cmsfs.fdir);
	BUG(rc < 0);
	set_fst_date_current(&fst);
	rc = _write(&fst, sizeof(fst), cmsfs.fdir);
	BUG(rc < 0);
}

static void increase_file_count(void)
{
	struct fst_entry fst;
	int rc;

	rc = _read(&fst, sizeof(fst), cmsfs.fdir);
	BUG(rc < 0);
	fst.nr_records = ++cmsfs.files + 2;
	set_fst_date_current(&fst);
	rc = _write(&fst, sizeof(fst), cmsfs.fdir);
	BUG(rc < 0);
}

static void decrease_file_count(void)
{
	struct fst_entry fst;
	int rc;

	rc = _read(&fst, sizeof(fst), cmsfs.fdir);
	BUG(rc < 0);
	fst.nr_records = --cmsfs.files + 2;
	set_fst_date_current(&fst);
	rc = _write(&fst, sizeof(fst), cmsfs.fdir);
	BUG(rc < 0);
}

static off_t get_reserved_block(void)
{
	off_t addr;

	if (cmsfs.reserved_blocks > 0)
		cmsfs.reserved_blocks--;
	addr = get_zero_block();
	BUG(addr < 0);
	return addr;
}

static void cache_dblocks(struct walk_file *walk)
{
	double dblocks;

	/* calculate number of data blocks used for FST entries */
	dblocks = (cmsfs.files + 2) * sizeof(struct fst_entry);
	dblocks = ceil(dblocks / cmsfs.blksize);
	/* add a spare one in case of create file */
	dblocks++;

	memset(walk, 0, sizeof(*walk));
	walk->flag = WALK_FLAG_CACHE_DBLOCKS;
	walk->dlist = calloc(dblocks, sizeof(off_t));
	if (walk->dlist == NULL)
		DIE_PERROR("malloc failed");
	walk_directory(NULL, walk, NULL);
}

static void free_dblocks(struct walk_file *walk)
{
	free(walk->dlist);
}

static void purge_dblock_ptrs(int level, off_t addr)
{
	int left = PTRS_PER_BLOCK;
	off_t ptr, start = addr;

	if (!level)
		return;
	level--;
	while (left--) {
		ptr = get_fixed_pointer(addr);
		BUG(ptr < 0);
		if (ptr != NULL_BLOCK)
			purge_dblock_ptrs(level, ptr);

		/* don't increment for null block pointers */
		if (addr)
			addr += PTR_SIZE;
	}
	free_block(start);
}

/*
 * Return total number of pointer entries for level.
 */
static int pointers_per_level(struct file *f, int level, int nr_blocks)
{
	double entries = nr_blocks;

	if (!level || nr_blocks < 2)
		return 0;

	if (level == 1)
		return nr_blocks;

	level--;
	while (level--)
		entries = ceil(entries / f->ptr_per_block);
	return (int) entries;
}

static int per_level_fixed(int level, int entries)
{
	double val = entries;

	while (level--)
		val = ceil(val / PTRS_PER_BLOCK);
	return (int) val;
}

static void rewrite_dir_ptr_block(struct walk_file *walk,
				  int level, off_t dst, int start)
{
	struct fixed_ptr ptr;
	int rc, i, end;
	off_t addr;

	if (!level)
		return;

	end = MIN(start + PTRS_PER_BLOCK,
		  per_level_fixed(level - 1, walk->dlist_used));
	BUG(start > end);

	for (i = start; i < end; i++) {
		if (level == 1) {
			addr = walk->dlist[i];
			if (addr)
				ptr.next = REL(addr);
			else
				ptr.next = 0;
		} else {
			addr = get_zero_block();
			BUG(addr < 0);
			ptr.next = REL(addr);
		}

		rc = _write(&ptr, sizeof(ptr), dst);
		BUG(rc < 0);
		dst += sizeof(ptr);

		rewrite_dir_ptr_block(walk, level - 1, addr,
			i * PTRS_PER_BLOCK);
	}
}

static int update_dir_levels(int blocks)
{
	int levels = 1;

	if (blocks < 2)
		return 0;

	while (blocks / PTRS_PER_BLOCK) {
		levels++;
		blocks /= PTRS_PER_BLOCK;
	}
	return levels;
}

static void rewrite_dblock_ptrs(struct walk_file *walk)
{
	int rc, nr_blocks = walk->dlist_used;
	struct fst_entry fst;
	off_t dst;

	BUG(!nr_blocks);

	/* read in the directory FST */
	rc = _read(&fst, sizeof(fst), cmsfs.fdir);
	BUG(rc < 0);

	if (nr_blocks == 1) {
		fst.fop = REL(cmsfs.fdir);
		fst.levels = 0;
		cmsfs.dir_levels = fst.levels;
		goto store;
	}

	dst = get_zero_block();
	BUG(dst < 0);
	fst.fop = REL(dst);

	fst.levels = update_dir_levels(walk->dlist_used);
	cmsfs.dir_levels = fst.levels;
	rewrite_dir_ptr_block(walk, fst.levels, dst, 0);
store:
	rc = _write(&fst, sizeof(fst), cmsfs.fdir);
	BUG(rc < 0);
}

/*
 * Update used block count in disk label.
 */
static void update_block_count(void)
{
	int rc;

	rc = _write(&cmsfs.used_blocks, sizeof(unsigned int), cmsfs.label + 32);
	BUG(rc < 0);
}

static int cmsfs_create(const char *path, mode_t mode,
			struct fuse_file_info *fi)
{
	char fname[8], ftype[8];
	char uc_name[MAX_FNAME];
	struct walk_file walk;
	struct fst_entry fst;
	off_t fst_addr = 0;
	int rc;

	/* no permissions in EDF */
	(void) mode;

	/*
	 * Note: creating a file that was unlinked but not yet deleted from
	 * disk is not supported. That means the unlinked file can still be
	 * opened.
	 */
	if (lookup_file(path + 1, &fst, SHOW_UNLINKED))
		return cmsfs_open(path, fi);

	if (cmsfs.readonly)
		return -EACCES;

	rc = edf_name_valid(path + 1);
	if (rc)
		return rc;

	/* force uppercase */
	util_strlcpy(uc_name, path + 1, MAX_FNAME);
	str_toupper(uc_name);

	rc = encode_edf_name(uc_name, fname, ftype);
	if (rc)
		return rc;

	/* find free fst entry */
	memset(&walk, 0, sizeof(walk));
	walk.flag = WALK_FLAG_LOCATE_EMPTY;
	walk_directory(&fst, &walk, &fst_addr);

	/* no free slot found, allocate new directory block */
	if (!fst_addr) {
		/*
		 * Be conservative and check if enough blocks for all
		 * directory levels are available.
		 */
		if (cmsfs.total_blocks - cmsfs.used_blocks < cmsfs.dir_levels + 2)
			return -ENOSPC;

		fst_addr = get_zero_block();
		if (fst_addr < 0)
			return fst_addr;

		cache_dblocks(&walk);
		/* add the newly allocated block to dlist */
		walk.dlist[walk.dlist_used++] = fst_addr;

		purge_dblock_ptrs(cmsfs.dir_levels, get_fop(cmsfs.fdir));
		rewrite_dblock_ptrs(&walk);
		free_dblocks(&walk);
		update_block_count();
	}

	/*
	 * Fill fst entry. Default template:
	 *   format:     variable
	 *   record_len: 0
	 *   mode:	 A1
	 *   flag:	 0, century bit (0x8) set by following utimens
	 *   fop:        0
	 *   nr_records: 0
	 *   nr_blocks:  0
	 *   levels:     0
	 *   ptr_size:   0xc for variable format
	 *   date:       set to current date
	 */
	memset(&fst, 0, sizeof(fst));
	memcpy(fst.name, fname, 8);
	memcpy(fst.type, ftype, 8);
	ebcdic_enc((char *) &fst.mode, "A1", 2);
	fst.record_format = RECORD_LEN_VARIABLE;
	fst.ptr_size = sizeof(struct var_ptr);

	rc = set_fst_date_current(&fst);
	if (rc != 0)
		return rc;

	rc = _write(&fst, sizeof(fst), fst_addr);
	BUG(rc < 0);
	cache_fst_addr(fst_addr, uc_name);
	increase_file_count();
	return cmsfs_open(path, fi);
}

static int purge_pointer_block_fixed(struct file *f, int level, off_t addr)
{
	int left = f->ptr_per_block;
	off_t ptr, start = addr;

	if (!level)
		return 0;

	level--;
	while (left--) {
		if (!level)
			break;

		ptr = get_fixed_pointer(addr);
		if (ptr < 0)
			return ptr;
		if (ptr != NULL_BLOCK)
			purge_pointer_block_fixed(f, level, ptr);

		/* don't increment for null block pointers */
		if (addr)
			addr += PTR_SIZE;
	}
	free_block(start);
	return 0;
}

static int purge_pointer_block_variable(struct file *f, int level,
					  off_t addr)
{
	int nr, left = f->ptr_per_block;
	off_t ptr, start = addr;
	unsigned int disp;

	if (!level)
		return 0;

	level--;
	while (left--) {
		if (!level)
			break;

		ptr = get_var_pointer(addr, &nr, &disp);
		if (ptr < 0)
			return ptr;
		if (ptr == VAR_FILE_END)
			break;
		if (ptr != NULL_BLOCK)
			purge_pointer_block_variable(f, level, ptr);

		/* don't increment for null block pointers */
		if (addr)
			addr += VPTR_SIZE;
	}
	free_block(start);
	return 0;
}

/*
 * Store the back pointer for a variable pointer block.
 * Pointer is offset of last VPTR to block start.
 */
static int store_back_pointer(off_t dst, int entries)
{
	unsigned int back;

	back = (entries - 1) * VPTR_SIZE;
	return _write(&back, sizeof(back),
		((dst | DATA_BLOCK_MASK) + 1) - sizeof(back));
}

/*
 * Rewrite one pointer block starting from the highest level.
 */
static int rewrite_pointer_block_fixed(struct file *f, int level, off_t dst,
				       int start)
{
	struct fixed_ptr ptr;
	int i, end, rc = 0;
	off_t addr;

	if (!level)
		return 0;

	/*
	 * start is always the first entry of a pointer block,
	 * end is the last used entry in this pointer block.
	 */
	end = MIN(start + f->ptr_per_block,
		  per_level_fixed(level - 1, f->fst->nr_blocks));
	BUG(start > end);

	for (i = start; i < end; i++) {
		if (level == 1) {
			addr = f->blist[i].disk_addr;
			if (addr)
				ptr.next = REL(addr);
			else
				ptr.next = 0;
		} else {
			addr = get_reserved_block();
			ptr.next = REL(addr);
		}

		rc = _write(&ptr, sizeof(ptr), dst);
		if (rc < 0)
			return rc;
		dst += sizeof(ptr);

		rc = rewrite_pointer_block_fixed(f, level - 1, addr,
			i * f->ptr_per_block);
		if (rc < 0)
			return rc;
	}
	return rc;
}

static int get_first_block_nr(int level, int entry)
{
	while (level-- > 1)
		entry *= VPTRS_PER_BLOCK;
	return entry;
}

static int get_last_block_nr(int level, int entry, int nr_blocks)
{
	while (level-- > 1)
		entry *= VPTRS_PER_BLOCK;
	entry--;
	if (entry > nr_blocks - 1)
		entry = nr_blocks - 1;
	return entry;
}

static int per_level_var(int level, int entries)
{
	double val = entries;

	while (level--)
		val = ceil(val / VPTRS_PER_BLOCK);
	return (int) val;
}

/*
 * Rewrite one pointer block starting from the highest level.
 */
static int rewrite_pointer_block_variable(struct file *f, int level,
					  off_t dst, int start)
{
	int i, bnr, end, rc = 0;
	struct var_ptr ptr;
	off_t addr;

	if (!level)
		return 0;

	/*
	 * start is always the first entry of a pointer block,
	 * end is the last used entry in this pointer block.
	 */
	end = MIN(start + f->ptr_per_block,
		  per_level_var(level - 1, f->fst->nr_blocks));
	BUG(start > end);

	for (i = start; i < end; i++) {
		if (level == 1) {
			addr = f->blist[i].disk_addr;
			if (addr)
				ptr.next = REL(addr);
			else
				ptr.next = 0;
		} else {
			addr = get_reserved_block();
			ptr.next = REL(addr);
		}

		bnr = get_first_block_nr(level, i);
		ptr.disp = f->blist[bnr].disp;

		bnr = get_last_block_nr(level, i + 1, f->fst->nr_blocks);
		ptr.hi_record_nr = f->blist[bnr].hi_record_nr;

		rc = _write(&ptr, sizeof(ptr), dst);
		if (rc < 0)
			return rc;
		dst += sizeof(ptr);

		rc = rewrite_pointer_block_variable(f, level - 1, addr,
			i * f->ptr_per_block);
		if (rc < 0)
			return rc;
	}
	return store_back_pointer(dst, end - start);
}

/*
 * Update fop and pointer blocks if needed.
 */
static int rewrite_pointers(struct file *f)
{
	struct record *rec;
	off_t dst;

	if (f->fst->nr_blocks == 0) {
		f->fst->fop = 0;
		return 0;
	}

	if (f->fst->nr_blocks == 1) {
		rec = get_record(f, 0);
		if (rec->disk_start == NULL_BLOCK)
			f->fst->fop = 0;
		else
			f->fst->fop = REL(rec->disk_start);
		return 0;
	}

	/* allocate root block for fst */
	dst = get_reserved_block();
	f->fst->fop = REL(dst);
	return f->fops->write_pointers(f, f->fst->levels, dst, 0);
}

/*
 * Guess position in record table.
 */
static int guess_record_number(struct file *f, off_t offset)
{
	int nr;

	if (f->linefeed)
		nr = (offset / (f->fst->record_len + 1));
	else
		nr = (offset / f->fst->record_len);
	if (nr >= f->fst->nr_records)
		nr = f->fst->nr_records - 1;
	return nr;
}

static int offset_is_linefeed(off_t offset, struct record *prev,
			      struct record *next)
{
	if ((offset < next->file_start) &&
	    (offset >= prev->file_start + prev->total_len))
		return 1;
	return 0;
}

static int offset_in_record(off_t offset, struct record *rec)
{
	if (offset >= rec->file_start &&
	    offset < rec->file_start + rec->total_len)
		return 1;
	return 0;
}

static void set_hint(struct file *f, int hint)
{
	f->next_record_hint = hint;

	/* limit hint to last record */
	if (f->next_record_hint >= f->fst->nr_records)
		f->next_record_hint = f->fst->nr_records - 1;
}

/*
 * Find record by file offset.
 *
 * Returns: record number in *nr
 *   > 0  : ptr to found record
 *   -1   : linefeed offset
 *   NULL : error
 */
static struct record *find_record(struct file *f, off_t offset, int *nr)
{
	int i, start, step, max = f->fst->nr_records;
	struct record *rec;

	/*
	 * next_record_hint is a guess which is optimal for sequential
	 * single-threaded reads.
	 */
	i = f->next_record_hint;
	rec = &f->rlist[i];

	if (offset_in_record(offset, rec)) {
		/* increment hint for sequential read, fails for extensions */
		set_hint(f, i + 1);
		*nr = i;
		return rec;
	}

	/* look out for previous record linefeed from sequential read hint */
	if (f->linefeed && i > 0)
		if (offset_is_linefeed(offset, &f->rlist[i - 1], rec))
			return LINEFEED_OFFSET;

	start = guess_record_number(f, offset);

	/* because of potential linefeed we need to check the next record */
	rec = &f->rlist[start];
	if (offset < rec->file_start)
		step = -1;
	else
		step = 1;

	for (i = start; i >= 0 && i < max; i += step) {
		rec = &f->rlist[i];
		if (offset_in_record(offset, rec)) {
			set_hint(f, i + 1);
			*nr = i;
			return rec;
		}

		/* last record reached, only one linefeed can follow */
		if (i == max - 1) {
			if (f->linefeed &&
			    (offset == rec->file_start + rec->total_len))
				return LINEFEED_OFFSET;
			else
				return NULL;
		}

		/* check for linefeed byte between two records */
		if (step == 1) {
			if (offset_is_linefeed(offset, rec, &f->rlist[i + 1]))
				return LINEFEED_OFFSET;
		} else
			/*
			 * No need to check if i > 0 since no linefeed before
			 * record 0 possible.
			 */
			if (offset_is_linefeed(offset, &f->rlist[i - 1], rec))
				return LINEFEED_OFFSET;

	}
	DEBUG("find: record not found!\n");
	return NULL;
}

/*
 * Get disk address and block size from a record.
 */
static void get_block_data_from_record(struct record *rec, off_t offset,
				       off_t *addr, int *chunk)
{
	int record_off = offset - rec->file_start;
	struct record_ext *rext;

	if (record_off >= rec->first_block_len) {
		record_off -= rec->first_block_len;
		rext = rec->ext;

		BUG(rext == NULL);

		while (record_off >= rext->len) {
			record_off -= rext->len;
			rext = rext->next;
			BUG(rext == NULL);
		}

		/* found the right record extension */
		if (rext->disk_start == NULL_BLOCK)
			*addr = NULL_BLOCK;
		else
			*addr = rext->disk_start + record_off;
		*chunk = rext->len - record_off;
	} else {
		if (rec->disk_start == NULL_BLOCK)
			*addr = NULL_BLOCK;
		else
			*addr = rec->disk_start + record_off;
		*chunk = rec->first_block_len - record_off;
	}
}

static int convert_text(iconv_t conv, char *in_buf, char *out_buf, int size)
{
	size_t out_count = size;
	size_t in_count = size;
	int rc;

	rc = iconv(conv, &in_buf, &in_count, &out_buf, &out_count);
	if ((rc == -1) || (in_count != 0)) {
		DEBUG("Code page translation EBCDIC-ASCII failed\n");
		return -EIO;
	}
	return 0;
}

static int cmsfs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	struct file *f = get_fobj(fi);
	size_t len, copied = 0;
	struct record *rec;
	int chunk, nr, rc;
	off_t addr;

	(void) path;

	len = f->session_size;
	if ((size_t) offset >= len)
		return 0;

	if (offset + size > len)
		size = len - offset;

	while (size > 0) {
		rec = find_record(f, offset, &nr);
		if (rec == NULL) {
			copied = -EINVAL;
			DEBUG("%s: invalid addr, size: %lu  copied: %lu  len: %lu\n",
				__func__, size, copied, len);
			goto out;
		}

		/* write linefeed directly to buffer and go to next record */
		if (rec == LINEFEED_OFFSET) {
			BUG(!f->linefeed);
			if (f->translate)
				*buf = LINEFEED_ASCII;
			else
				*buf = LINEFEED_EBCDIC;
			buf++;
			copied++;
			offset++;
			size--;
			continue;
		}

		/* get addr and block size from record */
		get_block_data_from_record(rec, offset, &addr, &chunk);
		if (chunk <= 0 || addr < 0)
			DIE("Invalid record data\n");

		/* copy less if there is not enough space in the fuse buffer */
		if (size < (size_t) chunk)
			chunk = size;

		/* read one record */
		if (addr == NULL_BLOCK)
			memset(buf, 0, chunk);
		else if (f->translate) {
			rc = _read(f->iconv_buf, chunk, addr);
			if (rc < 0)
				return rc;
			rc = convert_text(cmsfs.iconv_from, f->iconv_buf, buf, chunk);
			if (rc < 0)
				return rc;
		} else {
			rc = _read(buf, chunk, addr);
			if (rc < 0)
				return rc;
		}

		copied += chunk;
		size -= chunk;
		buf += chunk;
		offset += chunk;
	}
out:
	DEBUG("%s: copied: %lu\n", __func__, copied);
	return copied;
}

static int cmsfs_statfs(const char *path, struct statvfs *buf)
{
	unsigned int inode_size = cmsfs.blksize + sizeof(struct fst_entry);
	unsigned int free_blocks = cmsfs.total_blocks - cmsfs.used_blocks;
	unsigned long long tmp;

	(void) path;

	buf->f_bsize = buf->f_frsize = cmsfs.blksize;
	buf->f_blocks =	cmsfs.total_blocks;
	buf->f_bfree =  buf->f_bavail = free_blocks;

	/* number of possible inodes */
	tmp = (unsigned long long) cmsfs.total_blocks *
		cmsfs.blksize / inode_size;
	buf->f_files = (long) tmp;

	tmp = (unsigned long long) free_blocks * cmsfs.blksize / inode_size;
	buf->f_ffree = (long) tmp;
	buf->f_namemax = MAX_FNAME - 1;
	return 0;
}

static int cmsfs_utimens(const char *path, const struct timespec ts[2])
{
	struct fst_entry fst;
	off_t fst_addr;
	struct tm tm;
	int rc;

	if (cmsfs.readonly)
		return -EACCES;

	fst_addr = lookup_file(path + 1, &fst, HIDE_UNLINKED);
	if (!fst_addr)
		return -ENOENT;

	/* convert timespec to tm */
	memset(&tm, 0, sizeof(struct tm));
	if (localtime_r(&ts[0].tv_sec, &tm) == NULL)
		return -EINVAL;

	update_fst_date(&fst, &tm);
	rc = _write(&fst, sizeof(fst), fst_addr);
	BUG(rc < 0);
	return 0;
}

/*
 * Get the address of the last directory entry.
 */
static off_t find_last_fdir_entry(off_t addr, int level)
{
	struct fst_entry fst;
	int left, rc;
	off_t ptr;

	if (level > 0) {
		level--;
		left = PTRS_PER_BLOCK;
		while (left--) {
			ptr = get_fixed_pointer(addr + left * PTR_SIZE);
			BUG(ptr < 0);
			if (ptr)
				return find_last_fdir_entry(ptr, level);
		}
		DIE("Directory entry not found\n");
		return 0;
	}

	left = cmsfs.blksize / sizeof(struct fst_entry);
	while (left--) {
		rc = _read(&fst, sizeof(fst),
			   addr + left * sizeof(struct fst_entry));
		BUG(rc < 0);
		if (is_file(fst.name, fst.type))
			return addr + left * sizeof(struct fst_entry);
	}
	DIE("Directory entry not found\n");
}

static int delete_file(const char *path)
{
	off_t fst_kill, fst_last;
	struct walk_file walk;
	struct file *f_moved;
	char file[MAX_FNAME];
	struct fst_entry fst;
	struct file *f;
	int rc = 0, i;

	if (cmsfs.readonly)
		return -EROFS;

	fst_kill = lookup_file(path + 1, &fst, SHOW_UNLINKED);
	if (!fst_kill)
		return -ENOENT;
	f = create_file_object(&fst, &rc);
	if (f == NULL)
		return rc;

	/* delete all data blocks */
	for (i = 0; i < f->fst->nr_blocks; i++)
		free_block(f->blist[i].disk_addr);

	if (f->fst->fop) {
		rc = f->fops->delete_pointers(f, f->fst->levels, ABS(f->fst->fop));
		if (rc < 0)
			goto error;
	}

	if (cmsfs.dir_levels)
		fst_last = find_last_fdir_entry(get_fop(cmsfs.fdir), cmsfs.dir_levels);
	else
		fst_last = find_last_fdir_entry(cmsfs.fdir, cmsfs.dir_levels);

	/* remove unlinked file from fcache */
	util_strlcpy(file, path + 1, MAX_FNAME);
	str_toupper(file);
	invalidate_htab_entry(file);

	if (fst_last == fst_kill)
		goto skip_copy;

	/* copy last entry over unlinked entry */
	rc = _read(&fst, sizeof(struct fst_entry), fst_last);
	BUG(rc < 0);
	rc = _write(&fst, sizeof(struct fst_entry), fst_kill);
	BUG(rc < 0);

	/* update moved fcache entry */
	memset(file, 0, sizeof(file));
	decode_edf_name(file, fst.name, fst.type);
	update_htab_entry(fst_kill, file);
	/* update cached address of moved FST */
	f_moved = file_open(file);
	if (f_moved != NULL)
		f->fst_addr = fst_kill;

skip_copy:
	/* delete last entry */
	rc = _zero(fst_last, sizeof(struct fst_entry));
	BUG(rc < 0);

	/* if the deleted entry was the first of a block, free the block */
	if (fst_last % cmsfs.blksize == 0) {
		cache_dblocks(&walk);
		/* delete the last block from dlist */
		walk.dlist_used--;
		free_block(fst_last);
		purge_dblock_ptrs(cmsfs.dir_levels, get_fop(cmsfs.fdir));
		rewrite_dblock_ptrs(&walk);
		free_dblocks(&walk);
	}

	destroy_file_object(f);
	decrease_file_count();
	update_block_count();
	return 0;

error:
	destroy_file_object(f);
	return rc;
}

static int cmsfs_rename(const char *path, const char *new_path)
{
	struct fst_entry fst, fst_new;
	off_t fst_addr, fst_addr_new;
	char uc_old_name[MAX_FNAME];
	char fname[8], ftype[8];
	char *uc_new_name;
	struct file *f;
	int rc;

	if (cmsfs.readonly)
		return -EACCES;

	fst_addr = lookup_file(path + 1, &fst, HIDE_UNLINKED);
	if (!fst_addr)
		return -ENOENT;

	/* if new file already exists it must be overwritten so delete it */
	fst_addr_new = lookup_file(new_path + 1, &fst_new, HIDE_UNLINKED);
	if (fst_addr_new) {
		delete_file(new_path);
		/* fst_addr may have changed due to copy-up */
		fst_addr = lookup_file(path + 1, &fst, HIDE_UNLINKED);
	}

	rc = edf_name_valid(new_path + 1);
	if (rc)
		return rc;

	/* force uppercase */
	uc_new_name = strdup(new_path + 1);
	if (uc_new_name == NULL)
		return -ENOMEM;
	str_toupper(uc_new_name);

	rc = encode_edf_name(uc_new_name, fname, ftype);
	free(uc_new_name);
	if (rc)
		return rc;

	memcpy(&fst.name[0], fname, 8);
	memcpy(&fst.type[0], ftype, 8);

	util_strlcpy(uc_old_name, path + 1, MAX_FNAME);
	str_toupper(uc_old_name);
	invalidate_htab_entry(uc_old_name);

	/* update name in file object if the file is opened */
	f = file_open(uc_old_name);
	if (f != NULL) {
		util_strlcpy(f->path, new_path, MAX_FNAME + 1);
		str_toupper(f->path);
		memcpy(f->fst->name, fname, 8);
		memcpy(f->fst->type, ftype, 8);
	}

	rc = _write(&fst, sizeof(fst), fst_addr);
	BUG(rc < 0);
	return 0;
}

static int cmsfs_fsync(const char *path, int datasync,
		       struct fuse_file_info *fi)
{
	(void) path;
	(void) datasync;
	(void) fi;

	if (cmsfs.readonly)
		return -EROFS;
	return msync(cmsfs.map,	cmsfs.size, MS_SYNC);
}

/*
 * Detect whether the whole block can be freed.
 */
static int block_started(struct file *f, struct record *rec)
{
	if (rec->disk_start == NULL_BLOCK) {
		if (rec->null_block_started)
			return 1;
		else
			return 0;
	}

	if (f->fst->record_format == RECORD_LEN_FIXED) {
		if (rec->disk_start % cmsfs.blksize == 0)
			return 1;
		else
			return 0;
	}

	if (f->fst->record_format == RECORD_LEN_VARIABLE) {
		if ((rec->disk_start % cmsfs.blksize == 0) ||
		    (rec->disk_start % cmsfs.blksize == 1) ||
		    (rec->disk_start % cmsfs.blksize == 2))
			return 1;
		else
			return 0;
	}
	return 0;
}

/*
 * Note: only called for the very last record of a file. That means if the
 * data starts on a block offset the block can be freed. It does not free
 * header bytes for variable record files if they are on the previous block!
 */
static void free_record(struct file *f, struct record *rec)
{
	struct record_ext *rext = rec->ext;

	f->fst->nr_records--;

	if (block_started(f, rec)) {
		free_block(rec->disk_start);
		f->fst->nr_blocks--;
		if (!rec->disk_start && f->fst->record_format == RECORD_LEN_FIXED)
			f->nr_null_blocks--;
	}

	while (rext != NULL) {
		/* extensions always start on a new block */
		free_block(rext->disk_start);
		f->fst->nr_blocks--;
		if (!rext->disk_start && f->fst->record_format == RECORD_LEN_FIXED)
			f->nr_null_blocks--;
		rext = rext->next;
	}
}

static int update_var_header_len(struct file *f, u16 *header,
				  struct record *rec)
{
	off_t prev_block_end;
	int rc, split = 0;

	if (rec->disk_start % cmsfs.blksize == 0)
		split = 2;
	if (rec->disk_start % cmsfs.blksize == 1)
		split = 1;

	/* header is completely in this block */
	if (!split) {
		rc = _write(header, sizeof(*header),
			    rec->disk_start - sizeof(*header));
		if (rc < 0)
			return rc;
		return 0;
	}

	BUG(!rec->block_nr);
	prev_block_end = f->blist[rec->block_nr - 1].disk_addr | DATA_BLOCK_MASK;

	if (split == 1) {
		rc = _write((char *) header + 1, 1, rec->disk_start - 1);
		if (rc < 0)
			return rc;
		rc = _write((char *) header, 1, prev_block_end);
		if (rc < 0)
			return rc;
		return 0;
	}

	if (split == 2) {
		rc = _write(header, sizeof(*header), prev_block_end - 1);
		if (rc < 0)
			return rc;
		return 0;
	}
	return 0;
}

/*
 * Update the displacement of the last block if the block was spanned and
 * the new end is inside the previously spanned block. The displacement
 * must point after the last record to a null length header.
 * If the block wasn't spanned the displacement of the trimmed record needs
 * no update.
 */
static void adjust_displacement(struct file *f, int bnr, unsigned int disp)
{
	if (f->blist[bnr].disp == VAR_RECORD_SPANNED)
		f->blist[bnr].disp = disp;
}

/*
 * Split the last record if needed and wipe until block end.
 * offset points to the last byte of the trimmed record that is
 * not a line feed.
 */
static int trim_record(struct file *f, off_t offset, struct record *rec)
{
	int rc, wipe_off, wipe_len, free = 0;
	off_t file_start = rec->file_start;
	struct record_ext *rext;
	u16 header;

	BUG(!offset_in_record(offset, rec));

	if (offset >= rec->file_start &&
	    offset < rec->file_start + rec->first_block_len) {
		wipe_off = offset + 1 - rec->file_start;
		wipe_len = cmsfs.blksize - ((rec->disk_start & DATA_BLOCK_MASK) + wipe_off);
		if (!wipe_len)
			goto ext;
		if (rec->disk_start) {
			rc = _zero(rec->disk_start + wipe_off, wipe_len);
			BUG(rc < 0);
		}

		if (f->fst->record_format == RECORD_LEN_VARIABLE)
			adjust_displacement(f, rec->block_nr,
				(rec->disk_start + wipe_off) & DATA_BLOCK_MASK);
		free = 1;
	}

ext:
	if (rec->ext == NULL)
		goto header;

	file_start += rec->first_block_len;
	rext = rec->ext;
	do {
		if (free) {
			free_block(rext->disk_start);
			f->fst->nr_blocks--;
			if (!rext->disk_start && f->fst->record_format == RECORD_LEN_FIXED)
				f->nr_null_blocks--;
		} else {
			if (offset >= file_start &&
			    offset < file_start + rext->len) {
				wipe_off = offset + 1 - file_start;
				wipe_len = cmsfs.blksize - ((rec->disk_start & DATA_BLOCK_MASK) + wipe_off);
				if (!wipe_len)
					continue;
				if (rext->disk_start) {
					rc = _zero(rext->disk_start + wipe_off, wipe_len);
					BUG(rc < 0);
				}

				if (f->fst->record_format == RECORD_LEN_VARIABLE)
					adjust_displacement(f, rext->block_nr,
						(rext->disk_start + wipe_off) & DATA_BLOCK_MASK);
				free = 1;
			}
		}
		file_start += rext->len;
		rext = rext->next;
	} while (rext != NULL);

header:
	/* update variable record header with new record length */
	if (f->fst->record_format == RECORD_LEN_VARIABLE) {
		header = offset + 1 - rec->file_start;
		rc = update_var_header_len(f, &header, rec);
		if (rc < 0)
			return rc;

		/* update total_len in rlist, needed to recalculate lrecl */
		rec->total_len = header;
	}
	return 0;
}

/*
 * Update levels count.
 */
static void update_levels(struct file *f)
{
	int per_block = f->ptr_per_block;
	int levels = 1, blocks = f->fst->nr_blocks;

	if (blocks < 2) {
		f->fst->levels = 0;
		return;
	}

	while (blocks / per_block) {
		levels++;
		blocks /= per_block;
	}

	f->fst->levels = levels;
}

/*
 * Called by write only using the cached value.
 */
static void update_lrecl_fast(struct file *f, int rlen)
{
	if (rlen > (int) f->fst->record_len)
		f->fst->record_len = rlen;
}

/*
 * Update longest record length for variable files.
 */
static void update_lrecl(struct file *f)
{
	unsigned int lrecl = 0;
	struct record *rec;
	int i;

	if (f->fst->record_format == RECORD_LEN_FIXED)
		return;

	if (!f->fst->nr_records) {
		f->fst->record_len = 0;
		return;
	}

	for (i = 0; i < f->fst->nr_records; i++) {
		rec = get_record(f, i);
		if (rec->total_len > lrecl)
			lrecl = rec->total_len;
	}
	f->fst->record_len = lrecl;
}

static int shrink_file(struct file *f, off_t size)
{
	struct record *new_end_rec, *end_rec;
	int rlen = f->fst->record_len;
	off_t offset = size;
	int new_end_nr, rc;

	/* truncate MUST be aligned to record length for fixed files */
	if (f->fst->record_format == RECORD_LEN_FIXED) {
		if (f->linefeed)
			rlen++;
		if (size % rlen)
			return -EINVAL;
	}

	if (size == 0) {
		new_end_nr = -1;
		new_end_rec = NULL;
		goto free;
	}

	/*
	 * offset may point to the linefeed after a record, let it point to the
	 * last byte of the new last record instead. The linefeed is virtual
	 * and will be generated automatically.
	 */
	if (f->linefeed) {
		new_end_rec = find_record(f, offset - 1, &new_end_nr);
		if (new_end_rec == LINEFEED_OFFSET)
			offset--;
	}

	/* get the new last record of the file */
	new_end_rec = find_record(f, offset - 1, &new_end_nr);
	BUG(new_end_rec == NULL || new_end_rec == LINEFEED_OFFSET);

free:
	/* free from the end until new_end_rec */
	while (f->fst->nr_records - 1 > new_end_nr) {
		/* get the currently last record of the file */
		end_rec = get_record(f, f->fst->nr_records - 1);
		free_record(f, end_rec);
	}

	if (new_end_rec != NULL) {
		rc = trim_record(f, offset - 1, new_end_rec);
		if (rc < 0)
			return rc;
	}

	f->session_size = size;
	if (f->fst->fop)
		f->fops->delete_pointers(f, f->fst->levels, ABS(f->fst->fop));

	update_levels(f);
	update_lrecl(f);
	rc = rewrite_pointers(f);
	if (rc < 0)
		return rc;
	update_block_count();
	return 0;
}

static void hide_null_blocks(struct file *f)
{
	if (f->fst->record_format == RECORD_LEN_VARIABLE)
		return;
	f->fst->nr_blocks -= f->nr_null_blocks;
}

static void unhide_null_blocks(struct file *f)
{
	if (f->fst->record_format == RECORD_LEN_VARIABLE)
		return;
	f->fst->nr_blocks += f->nr_null_blocks;
}

static void update_fst(struct file *f, off_t addr)
{
	int rc;

	hide_null_blocks(f);
	rc = _write(f->fst, sizeof(*f->fst), addr);
	BUG(rc < 0);
	unhide_null_blocks(f);
}

static int cmsfs_truncate(const char *path, off_t size)
{
	struct fst_entry fst;
	off_t fst_addr, len;
	struct file *f;
	int rc = 0;

	if (cmsfs.readonly)
		return -EROFS;

	/*
	 * If file is opened and modified disk content may be obsolete.
	 * Must use the file object to get the current version of the file.
	 */
	f = file_open(path + 1);
	if (f != NULL) {
		fst_addr = f->fst_addr;
		len = f->session_size;
	} else {
		fst_addr = lookup_file(path + 1, &fst, HIDE_UNLINKED);
		if (!fst_addr)
			return -ENOENT;
		len = get_file_size_logical(&fst);
		if (len < 0)
			return -EIO;
		f = create_file_object(&fst, &rc);
		if (f == NULL)
			return rc;
	}

	if (len == size)
		return 0;
	if (size < len) {
		rc = shrink_file(f, size);
		if (rc != 0)
			return rc;
	} else
		return -EINVAL;

	rc = set_fst_date_current(f->fst);
	if (rc != 0)
		return rc;

	update_fst(f, fst_addr);
	if (!f->use_count)
		destroy_file_object(f);
	return rc;
}

#ifdef HAVE_SETXATTR
static int cmsfs_setxattr(const char *path, const char *name, const char *value,
			  size_t size, int flags)
{
	struct fst_entry fst;
	off_t fst_addr;
	int mode_n, rc;
	long int rlen;
	char mode_l;
	char *in;

	/* meaningless since our xattrs are virtual and not stored on disk */
	(void) flags;

	if (cmsfs.readonly)
		return -EROFS;

	fst_addr = lookup_file(path + 1, &fst, HIDE_UNLINKED);
	if (!fst_addr)
		return -ENOENT;

	if (strcmp(name, xattr_format.name) == 0) {
		/* only allowed for empty files */
		if (fst.nr_records != 0)
			return -EINVAL;
		if (size != xattr_format.size)
			return -ERANGE;
		if (*value == 'F') {
			fst.record_format = RECORD_LEN_FIXED;
			fst.ptr_size = 0x4;
		} else if (*value == 'V') {
			fst.record_format = RECORD_LEN_VARIABLE;
			fst.ptr_size = 0xc;
		} else
			return -EINVAL;
		goto write;
	}

	if (strcmp(name, xattr_lrecl.name) == 0) {
		/* done by fs for variable files */
		if (fst.record_format == RECORD_LEN_VARIABLE)
			return -EINVAL;
		/* only allowed for empty files */
		if (fst.nr_records != 0)
			return -EINVAL;
		if (size > xattr_lrecl.size)
			return -ERANGE;
		in = calloc(size + 1, 1);
		if (in == NULL)
			return -ENOMEM;
		memcpy(in, value, size);
		errno = 0;
		rlen = strtol(in, (char **) NULL, 10);
		free(in);
		if (errno != 0 || rlen == 0 || rlen > MAX_RECORD_LEN)
			return -EINVAL;
		fst.record_len = rlen;
		goto write;
	}

	if (strcmp(name, xattr_mode.name) == 0) {
		if (size != xattr_mode.size)
			return -ERANGE;
		mode_l = value[0];
		if (mode_l < 'A' || mode_l > 'Z')
			return -EINVAL;
		mode_n = atoi(&value[1]);
		if (!isdigit(value[1]) || mode_n < 0 || mode_n > 6)
			return -EINVAL;
		ebcdic_enc((char *) &fst.mode, value, sizeof(fst.mode));
		goto write;
	}
	return -ENODATA;

write:
	rc = _write(&fst, sizeof(fst), fst_addr);
	BUG(rc < 0);
	return 0;
}

static int cmsfs_getxattr(const char *path, const char *name, char *value,
			  size_t size)
{
	char buf[xattr_lrecl.size + 1];
	struct fst_entry fst;

	/* nothing for root directory but clear error code needed */
	if (strcmp(path, "/") == 0)
		return -ENODATA;

	if (!lookup_file(path + 1, &fst, HIDE_UNLINKED))
		return -ENOENT;

	/* null terminate strings */
	memset(value, 0, size);

	/* format */
	if (strcmp(name, xattr_format.name) == 0) {
		if (size == 0)
			return xattr_format.size;
		if (size < xattr_format.size)
			return -ERANGE;
		if (fst.record_format == RECORD_LEN_FIXED)
			*value = 'F';
		else if (fst.record_format == RECORD_LEN_VARIABLE)
			*value = 'V';
		return xattr_format.size;
	}

	/* lrecl */
	if (strcmp(name, xattr_lrecl.name) == 0) {
		if (size == 0)
			return xattr_lrecl.size;
		if (size < xattr_lrecl.size)
			return -ERANGE;
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "%d", fst.record_len);
		memcpy(value, buf, strlen(buf));
		return strlen(buf);
	}

	/* mode */
	if (strcmp(name, xattr_mode.name) == 0) {
		if (size == 0)
			return xattr_mode.size;
		if (size < xattr_mode.size)
			return -ERANGE;
		ebcdic_dec(value, (char *) &fst.mode, 2);
		return xattr_mode.size;
	}
	return -ENODATA;
}

static int cmsfs_listxattr(const char *path, char *list, size_t size)
{
	struct fst_entry fst;
	size_t list_len;
	int pos = 0;

	if (!lookup_file(path + 1, &fst, HIDE_UNLINKED))
		return -ENOENT;

	list_len = strlen(xattr_format.name) + 1 +
		   strlen(xattr_lrecl.name) + 1 +
		   strlen(xattr_mode.name);
	if (!size)
		return list_len;
	if (size < list_len)
		return -ERANGE;

	strcpy(list, xattr_format.name);
	pos += strlen(xattr_format.name) + 1;
	strcpy(&list[pos], xattr_lrecl.name);
	pos += strlen(xattr_lrecl.name) + 1;
	strcpy(&list[pos], xattr_mode.name);
	pos += strlen(xattr_mode.name) + 1;
	return pos;
}
#endif /* HAVE_SETXATTR */

/*
 * Return the number of unused bytes in the last block.
 */
static int examine_last_block(struct file *f)
{
	struct record_ext *rext;
	struct record *rec;
	int last_bnr, len;
	off_t start;

	if (!f->fst->nr_blocks || !f->fst->nr_records)
		return 0;

	/*
	 * For subsequent writes we know how much is left on the current block.
	 * */
	if (f->wstate->block_state != BWS_BLOCK_NOT_INIT)
		return f->wstate->block_free;

	last_bnr = f->fst->nr_blocks - 1;
	rec = &f->rlist[f->fst->nr_records - 1];

	/* last block may be an extension */
	if (rec->block_nr == last_bnr) {
		start = rec->disk_start;
		len = rec->first_block_len;
		goto out;
	}

	/* if write is split and exactly the extension not yet started */
	if (rec->ext == NULL)
		return 0;

	rext = rec->ext;
	do {
		if (rext->block_nr == last_bnr) {
			start = rext->disk_start;
			len = rext->len;
			goto out;
		}
		rext = rext->next;
	} while (rext != NULL);

	return 0;
out:
	if (start == NULL_BLOCK)
		start = f->null_ctr;
	return ((start | DATA_BLOCK_MASK) + 1) - (start + len);
}

static int get_record_len(struct file *f, size_t size)
{
	int chunk = 0;

	if (f->fst->record_format == RECORD_LEN_FIXED) {
		if (!f->fst->record_len) {
			chunk = (size > MAX_RECORD_LEN) ?
				MAX_RECORD_LEN : size;
			f->fst->record_len = chunk;
		} else
			chunk = f->fst->record_len;

		if (chunk > MAX_RECORD_LEN)
			return -EINVAL;
		if (size < (size_t) chunk)
			chunk = size;
	} else if (f->fst->record_format == RECORD_LEN_VARIABLE) {
		chunk = size;
		if (chunk > MAX_RECORD_LEN)
			chunk = MAX_RECORD_LEN;
	}
	return chunk;
}

/*
 * Get the disk address of the first byte after the last record.
 */
static off_t disk_end(struct file *f)
{
	struct record_ext *rext;
	struct record *rec;

	if (!f->fst->nr_records)
		return 0;

	/*
	 * Only the first write on a newly opened file should set the write_ptr
	 * according to what is on the disk. Subsequent writes should use the
	 * actual write_ptr. This avoids the problem for fixed records that
	 * for a record that is not yet completely written the calculated
	 * write_ptr would be wrong.
	 */
	if (f->wstate->block_state != BWS_BLOCK_NOT_INIT)
		return f->write_ptr;

	rec = &f->rlist[f->fst->nr_records - 1];
	if (rec->ext == NULL) {
		if (rec->disk_start == NULL_BLOCK)
			return 0;
		else
			return rec->disk_start + rec->first_block_len;
	}

	rext = rec->ext;
	while (rext->next != NULL)
		rext = rext->next;
	if (rext->disk_start == NULL_BLOCK)
		return 0;
	else
		return rext->disk_start + rext->len;
}

/*
 * Store the displacement for the first write to a new block.
 * nr_blocks already contains the new block. If the block is completely filled
 * the displacement is spanned, also if one header byte is used
 * since the header belongs to the record regarding the
 * displacement but not if both header bytes are on the block.
 */
void store_displacement(struct file *f, int disp)
{
	f->blist[f->fst->nr_blocks - 1].disp = disp;
	f->wstate->block_state = BWS_BLOCK_USED;
}

/*
 * Allocate a new block if needed, set write pointer and return the number
 * of bytes available on the block.
 */
static int write_prepare_block(struct file *f, int null_block, ssize_t size)
{
	int len, new_block = 0;

	if (null_block) {
		/*
		 * TODO: need to write header before killing write_ptr for
		 * sparse files.
		 */
		BUG(f->fst->record_format == RECORD_LEN_VARIABLE);

		f->write_ptr = 0;
		/* new null block started ? */
		if (f->null_ctr % cmsfs.blksize == 0) {
			new_block = 1;
			len = cmsfs.blksize;

			/*
			 * Prevent allocating a null block if the block would
			 * not be complete. Use a normal block instead.
			 */
			if (size < cmsfs.blksize) {
				f->write_ptr = get_zero_block();
				if (f->write_ptr < 0)
					return f->write_ptr;
			}

		} else
			len = ((f->null_ctr | DATA_BLOCK_MASK) + 1) - f->null_ctr;
	} else {
		if (f->write_ptr % cmsfs.blksize == 0) {
			/*
			 * For fixed files use a different padding in text
			 * mode to pad records with spaces.
			 */
			if (f->fst->record_format == RECORD_LEN_FIXED &&
			    f->translate)
				f->write_ptr = get_filled_block();
			else
				f->write_ptr = get_zero_block();
			if (f->write_ptr < 0) {
				/* reset to catch subsequent writes */
				f->write_ptr = 0;
				return -ENOSPC;
			}
			new_block = 1;
			len = cmsfs.blksize;
		} else
			len = ((f->write_ptr | DATA_BLOCK_MASK) + 1) - f->write_ptr;
	}

	if (new_block) {
		f->wstate->block_state = BWS_BLOCK_NEW;
		f->blist[f->fst->nr_blocks].disk_addr = f->write_ptr;

		if (!f->write_ptr && f->fst->record_format == RECORD_LEN_FIXED)
			f->nr_null_blocks++;
		f->wstate->block_free = cmsfs.blksize;
		f->fst->nr_blocks++;
	}
	return len;
}

/*
 * Write variable record length header and return number of written bytes.
 */
static int write_var_header(struct file *f, int len, u16 vheader)
{
	u8 half_vheader;
	int rc;

	if (f->wstate->var_record_state == RWS_HEADER_COMPLETE ||
	    f->wstate->var_record_state == RWS_RECORD_INCOMPLETE)
		return 0;

	if (f->wstate->var_record_state == RWS_HEADER_STARTED) {
		/* write secord header byte */
		half_vheader = vheader & 0xff;
		rc = _write(&half_vheader, 1, f->write_ptr);
		if (rc < 0)
			return rc;
		f->write_ptr++;
		f->wstate->block_free--;
		f->wstate->var_record_state = RWS_HEADER_COMPLETE;
		f->wstate->var_records_written++;
		return 1;
	}

	/* block cannot be spanned if a header starts on it */
	if (f->wstate->block_state == BWS_BLOCK_NEW)
		store_displacement(f, f->write_ptr & DATA_BLOCK_MASK);

	if (len >= 2) {
		rc = _write(&vheader, 2, f->write_ptr);
		if (rc < 0)
			return rc;
		f->write_ptr += 2;
		f->wstate->block_free -= 2;
		f->wstate->var_record_len = vheader;
		f->wstate->var_record_state = RWS_HEADER_COMPLETE;
		f->wstate->var_records_written++;
		return 2;
	} else {
		/* len = 1, write first header byte */
		half_vheader = vheader >> 8;
		rc = _write(&half_vheader, 1, f->write_ptr);
		if (rc < 0)
			return rc;
		f->write_ptr++;
		f->wstate->block_free--;
		f->wstate->var_record_len = vheader;
		f->wstate->var_record_state = RWS_HEADER_STARTED;
		return 1;
	}
}

static int extend_block_fixed(struct file *f, const char *buf, int len,
			      size_t size, int rlen)
{
	int rc;

	(void) rlen;

	if (size < (size_t) len)
		len = size;
	if (f->write_ptr) {
		rc = _write(buf, len, f->write_ptr);
		if (rc < 0)
			return rc;
		f->write_ptr += len;
		f->wstate->block_free -= len;
	}
	return len;
}

static int extend_block_variable(struct file *f, const char *buf, int len,
				 size_t size, int rlen)
{
	int rc, copied = 0, vh_len = 0, max = cmsfs.blksize;

	if (!f->write_ptr)
		return len;

	while (len > 0) {
		/* record may be party written already */
		if (size < (size_t) rlen)
			rlen = size;

		vh_len = write_var_header(f, len, rlen);
		if (vh_len < 0)
			return vh_len;
		len -= vh_len;
		if (!len)
			return copied;
		/* record does not fit on block */
		if (len < rlen)
			rlen = len;
		/* remaining record data less than block len */
		if (f->wstate->var_record_len < rlen)
			rlen = f->wstate->var_record_len;
		rc = _write(buf, rlen, f->write_ptr);
		if (rc < 0)
			return rc;

		f->write_ptr += rlen;
		f->wstate->block_free -= rlen;

		if (f->wstate->block_state == BWS_BLOCK_NEW) {
			/*
			 * If the second byte of a split header was written
			 * (blocksize - 1) is enough to make the block spanned.
			 */
			if (vh_len == 1)
				max--;
			if (rlen >= max)
				store_displacement(f, VAR_RECORD_SPANNED);
			else
				store_displacement(f, f->write_ptr & DATA_BLOCK_MASK);
		}


		copied += rlen;
		size -= rlen;
		len -= rlen;
		f->wstate->var_record_len -= rlen;

		BUG(f->wstate->var_record_len < 0);
		if (!f->wstate->var_record_len) {
			f->wstate->var_record_state = RWS_RECORD_COMPLETE;
			/* reset rlen for the next record */
			rlen = get_record_len(f, size);
		}

		DEBUG("%s: wrote %d record bytes\n", __func__, rlen);
		if (size == 0)
			return copied;
	}

	/* record is not yet finished */
	f->wstate->var_record_state = RWS_RECORD_INCOMPLETE;
	return copied;
}

/*
 * Extend an existing block or write data on a new block.
 *
 * size: requestes bytes to write to disk
 * rlen: projected record len
 * len: bytes left on the block
 */
static int extend_block(struct file *f, const char *buf, size_t size, int rlen)
{
	int len = write_prepare_block(f, (buf == NULL) ? 1 : 0, size);

	if (len < 0)
		return -ENOSPC;
	BUG(!len);
	return f->fops->write_data(f, buf, len, size, rlen);
}

/*
 * Delete the record data from rlist and free extensions.
 */
static void delete_record(struct file *f, int nr)
{
	struct record *rec = &f->rlist[nr];
	struct record_ext *tmp, *rext = rec->ext;

	memset(rec, 0, sizeof(struct record));
	while (rext != NULL) {
		tmp = rext->next;
		free(rext);
		rext = tmp;
	}
}

/*
 * Update records from a start record to the end. The start record is one less
 * than the previous last record since the previous last record may be
 * incomplete.
 */
static int update_records(struct file *f, int nrecords)
{
	int i, rc, rnr, bnr = 0, skip = 0;
	off_t total = 0;

	rnr = f->fst->nr_records - 1;
	if (rnr >= 0) {
		total = f->rlist[rnr].file_start;
                if (f->linefeed && total)
                        total--;
		bnr = f->rlist[rnr].block_nr;
		skip = f->rlist[rnr].disk_start & DATA_BLOCK_MASK;

		/* skip must point before a variable header */
		if (f->fst->record_format == RECORD_LEN_VARIABLE) {
			if (skip >= VAR_RECORD_HEADER_SIZE)
				skip -= VAR_RECORD_HEADER_SIZE;
			else if (skip == 1) {
				bnr--;
				skip = cmsfs.blksize - 1;
			} else if (skip == 0 && f->rlist[rnr].disk_start) {
				bnr--;
				skip = cmsfs.blksize - 2;
			}
		}
		delete_record(f, rnr);
		rnr--;
	}

	if (rnr < -1) {
		rnr = -1;
		skip = 0;
		total = 0;
		bnr = 0;
	}

	f->fst->nr_records += nrecords;
	f->record_scan_state = RSS_DATA_BLOCK_STARTED;
	for (i = bnr; i < f->fst->nr_blocks; i++) {
		if (f->fst->record_format == RECORD_LEN_FIXED)
			cache_fixed_data_block(f, f->blist[i].disk_addr + skip,
					       &bnr, &rnr, &total, skip);
		else {
			rc = cache_variable_data_block(f,
				f->blist[i].disk_addr + skip,
				&bnr, &rnr, f->blist[i].disp, &total, skip);
			if (rc < 0)
				return rc;
		}
		skip = 0;
	}
	return 0;
}

/*
 * Calculate the number of new records.
 */
static int new_records(struct file *f, size_t size, int rlen)
{
	double tmp = size;
	int len;

	if (f->fst->record_format == RECORD_LEN_FIXED) {
		len = f->fst->record_len;
		if (f->linefeed)
			len++;

		/* need to fill a previously started record first */
		if (f->session_size &&
		    f->session_size % len)
			tmp = tmp - (len - (f->session_size % len));
	}

	if (tmp <= 0)
		return 0;

	tmp = ceil(tmp / rlen);
	return (int) tmp;
}

/*
 * Calculate number of new blocks.
 */
static int new_blocks(struct file *f, size_t size, int last, int nrecords)
{
	int last_usable = last;
	double tmp = size;

	/* subtract header bytes */
	if (last_usable && f->fst->record_format == RECORD_LEN_VARIABLE) {
		if (last_usable == 1)
			last_usable = 0;
		else
			last_usable -= VAR_RECORD_HEADER_SIZE;
	}

	if ((int) size <= last_usable)
		return 0;

	if (f->fst->record_format == RECORD_LEN_VARIABLE)
		tmp += (double) nrecords * VAR_RECORD_HEADER_SIZE;

	tmp -= last;
	if (tmp <= 0)
		return 0;

	tmp = ceil(tmp / cmsfs.blksize);
	return (int) tmp;
}

/*
 * Increase record list count.
 */
static void resize_rlist(struct file *f, int new)
{
	if (!new)
		return;

	f->rlist = realloc(f->rlist, (f->fst->nr_records + new) *
			   sizeof(struct record));
	if (f->rlist == NULL)
		DIE_PERROR("realloc failed");
	memset(&f->rlist[f->fst->nr_records], 0,
	       new * sizeof(struct record));
}

/*
 * Increase block list count.
 */
static void resize_blist(struct file *f, int new)
{
	if (!new)
		return;

	f->blist = realloc(f->blist, (f->fst->nr_blocks + new) *
			   sizeof(struct block));
	if (f->blist == NULL)
		DIE_PERROR("realloc failed");
	memset(&f->blist[f->fst->nr_blocks], 0,
	       new * sizeof(struct block));
}

/*
 * Reserve blocks for meta data (pointer blocks) of a file so that
 * blocks for meta-data are available if the disk runs full.
 */
static void reserve_meta_blocks(struct file *f, int old, int new, int level)
{
	double nentries, oentries;
	int newp;

	if (!new)
		return;

	newp = pointers_per_level(f, level, old + new);
	oentries = pointers_per_level(f, level, old);

	oentries = ceil(oentries / f->ptr_per_block);
	nentries = newp;
	nentries = ceil(nentries / f->ptr_per_block);

	cmsfs.reserved_blocks += nentries - oentries;

	if (newp > f->ptr_per_block)
		reserve_meta_blocks(f, oentries, nentries, ++level);
}

/*
 * Update the max record number in the last pointer block per level.
 */
static int update_last_block_vptr(struct file *f, off_t addr, int level,
				  struct var_ptr *vptr)
{
	int last, rc;

	if (!level)
		return 0;
	level--;

	/* read offset pointer from the end of the var pointer block */
	rc = _read(&last, sizeof(last), addr + cmsfs.blksize - sizeof(last));
	if (rc < 0)
		return rc;

	if (last % sizeof(*vptr) || last > cmsfs.blksize)
		return -EIO;
	rc = _read(vptr, sizeof(*vptr), addr + last);
	if (rc < 0)
		return rc;

	/* update max record number */
	vptr->hi_record_nr = f->fst->nr_records;
	rc = _write(vptr, sizeof(*vptr), addr + last);
	if (rc < 0)
		return rc;

	if (!level)
		return 0;
	if (vptr->next == NULL_BLOCK)
		return 0;
	return update_last_block_vptr(f, ABS(vptr->next), level, vptr);
}

static void reset_write_state(struct file *f)
{
	f->wstate->var_record_state = RWS_RECORD_COMPLETE;
	f->wstate->var_record_len = 0;
	f->wstate->var_records_written = 0;
}

/*
 * Append records at current file end. If buf is NULL write zero bytes.
 */
static int write_append(struct file *f, const char *buf, size_t size)
{
	int rc, i, nrecords, nblocks, last, len, copied = 0;
	int rlen = get_record_len(f, size);

	if (rlen < 0)
		return rlen;
	nrecords = new_records(f, size, rlen);

	/* get last block unused bytes for block count */
	last = examine_last_block(f);

	/* initialize write_ptr once */
	f->write_ptr = disk_end(f);

	nblocks = new_blocks(f, size, last, nrecords);
	if (nblocks > 0)
		f->ptr_dirty = 1;

	resize_rlist(f, nrecords);
	resize_blist(f, nblocks);
	if (f->fst->nr_blocks + nblocks > 1)
		reserve_meta_blocks(f, f->fst->nr_blocks, nblocks, 1);

	reset_write_state(f);

	/* first use existing last block */
	if (last) {
		len = extend_block(f, buf, size, rlen);
		if (len < 0)
			return len;
		copied += len;
		size -= len;
		if (buf != NULL)
			buf += len;
	}

	for (i = 0; i < nblocks; i++) {
		len = extend_block(f, buf, size, rlen);
		if (len < 0) {
			if (copied > 0) {
				/*
				 * Not all records may be written, need to
				 * update nrecords to store a correct
				 * hi_record_nr in the last vptr.
				 */
				if (f->fst->record_format == RECORD_LEN_VARIABLE)
					nrecords = f->wstate->var_records_written;
				goto out;
			} else
				return len;
		}
		copied += len;
		size -= len;
		if (buf != NULL)
			buf += len;
		DEBUG("%s: wrote: %d bytes\n", __func__, copied);
	}
out:
	rc = update_records(f, nrecords);
	if (rc < 0)
		return rc;
	if (f->fst->record_format == RECORD_LEN_VARIABLE)
		update_lrecl_fast(f, rlen);
	return copied;
}

static int do_write(struct file *f, const char *buf, size_t size, off_t offset)
{
	off_t len, copied = 0;
	struct var_ptr vptr;
	int rc;

	if (!size)
		return 0;

	len = f->session_size;
	if (f->linefeed)
		len -= f->fst->nr_records;
	BUG(len < 0);

	if (offset < len)
		return -EINVAL;

	/*
	 * Writes with null blocks (sparse files) may be prevented by tools
	 * which call lseek instead. Since we don't implement lseek fuse may
	 * call us with an offset after file. We don't support sparse file
	 * writes currently.
	 */
	if (offset > len)
		return -EINVAL;

	copied = write_append(f, buf, size);
	if (copied <= 0)
		return copied;
	f->session_size += copied;

	/* add linefeed byte */
	if (f->linefeed)
		f->session_size++;

	if (f->ptr_dirty) {
		f->old_levels = f->fst->levels;
		update_levels(f);

		if (f->fst->fop)
			f->fops->delete_pointers(f, f->old_levels,
				ABS(f->fst->fop));
		rc = rewrite_pointers(f);
		if (rc < 0)
			return rc;
		f->ptr_dirty = 0;
	} else
		if (f->fst->levels > 0 &&
		    f->fst->record_format == RECORD_LEN_VARIABLE) {
			rc = update_last_block_vptr(f, ABS(f->fst->fop),
						    f->fst->levels, &vptr);
			if (rc < 0)
				return rc;
		}

	rc = set_fst_date_current(f->fst);
	if (rc != 0)
		return rc;

	update_fst(f, f->fst_addr);
	set_fdir_date_current();
	update_block_count();
	return copied;
}

static void cache_write_data(struct file *f, const char *buf, int len)
{
	if (f->wcache_used + len > WCACHE_MAX)
		len = WCACHE_MAX - f->wcache_used;
	if (buf == NULL)
		memset(&f->wcache[f->wcache_used], FILLER_ASCII, len);
	else
		memcpy(&f->wcache[f->wcache_used], buf, len);
	f->wcache_used += len;
}

static void purge_wcache(struct file *f)
{
	f->wcache_used = 0;
	f->wcache_commited = 0;
}

/*
 * Scan for the next newline character and return the number of bytes in
 * this record.
 */
static ssize_t find_newline(const char *buf, int len)
{
	char *pos;

	pos = memchr(buf, LINEFEED_ASCII, len);
	if (pos == NULL)
		return LINEFEED_NOT_FOUND;
	else
		return pos - buf;
}

static int cmsfs_write_strings(struct file *f, const char *buf,
			       size_t size, off_t offset)
{
	int scan_len = MIN(size, (size_t)MAX_RECORD_LEN + 1);
	int rc, nl_byte = 1, null_record = 0, pad = 0;
	ssize_t rsize;

	/* remove already committed bytes */
	offset -= f->wcache_commited;

	/* write offset must be at the end of the file */
	if (offset + f->null_records + f->pad_bytes != f->session_size)
		return -EINVAL;

	if (f->fst->record_format == RECORD_LEN_FIXED &&
	    f->fst->record_len)
		scan_len = MIN(scan_len, f->fst->record_len + 1);

	rsize = find_newline(buf, scan_len);
	BUG(rsize < LINEFEED_NOT_FOUND);

	if (rsize == LINEFEED_NOT_FOUND) {
		if (f->wcache_used + scan_len >= WCACHE_MAX) {
			purge_wcache(f);
			return -EINVAL;
		} else {
			if (f->fst->record_format == RECORD_LEN_FIXED &&
			    f->wcache_commited + scan_len > f->fst->record_len) {
				purge_wcache(f);
				return -EINVAL;
			}
			cache_write_data(f, buf, scan_len);
			f->wcache_commited += scan_len;
			return scan_len;
		}
	}

	cache_write_data(f, buf, rsize);

	if (f->fst->record_format == RECORD_LEN_FIXED &&
	    f->wcache_used < f->fst->record_len) {
		pad = f->fst->record_len - f->wcache_used;
		cache_write_data(f, NULL, pad);
	}

	/* translate */
	rc = convert_text(cmsfs.iconv_to, f->wcache, f->iconv_buf, f->wcache_used);
	if (rc < 0)
		return rc;

	/*
	 * Note: empty records are forbidden by design. CMS converts
	 * an empty record to a single space. Follow that convention.
	 */
	if (!f->wcache_used) {
		*f->wcache = FILLER_EBCDIC;
		*f->iconv_buf = FILLER_EBCDIC;
		f->wcache_used = 1;
		nl_byte = 0;
		null_record = 1;
	}

	/* correct file offset by removing the virtual linefeeds */
	offset -= (f->fst->nr_records - f->null_records);
	offset += f->pad_bytes;
	BUG(offset < 0);

	rc = do_write(f, f->iconv_buf, f->wcache_used, offset);
	if (rc < 0)
		return rc;

	rc += nl_byte;
	if (null_record)
		f->null_records++;
	rc -= f->wcache_commited;
	rc -= pad;
	BUG(rc < 0);
	purge_wcache(f);
	f->pad_bytes += pad;
	return rc;
}

static int cmsfs_write(const char *path, const char *buf, size_t size,
		       off_t offset, struct fuse_file_info *fi)
{
	struct file *f = get_fobj(fi);
	int rc, written, nbytes;

	(void) path;

	if (cmsfs.readonly)
		return -EROFS;

	if (!f->linefeed)
		return do_write(f, buf, size, offset);

	/* Limit the size to what we can report back as written */
	nbytes = MIN(size, (size_t) INT_MAX);

	written = 0;
	while (nbytes) {
		rc = cmsfs_write_strings(f, buf, nbytes, offset);
		if (rc < 0)
			return written ? written : rc;
		written += rc;
		offset += rc;
		buf += rc;
		nbytes -= rc;
	}
	return written;
}

static int cmsfs_unlink(const char *path)
{
	struct fst_entry fst;
	off_t fst_addr;
	struct file *f;

	if (cmsfs.readonly)
		return -EROFS;

	fst_addr = lookup_file(path + 1, &fst, HIDE_UNLINKED);
	if (!fst_addr)
		return -ENOENT;

	f = file_open(path + 1);
	if (f != NULL) {
		f->unlinked = 1;
		return 0;
	}
	return delete_file(path);
}

static int flush_wcache(struct file *f)
{
	off_t offset = f->session_size;
	int rc;

	/* translate */
	rc = convert_text(cmsfs.iconv_to, f->wcache, f->iconv_buf, f->wcache_used);
	if (rc < 0)
		return rc;

	/* correct file offset by removing the virtual linefeeds */
	offset -= (f->fst->nr_records - f->null_records);
	BUG(offset < 0);

	rc = do_write(f, f->iconv_buf, f->wcache_used, offset);
	purge_wcache(f);
	f->null_records = 0;
	if (rc < 0)
		return rc;
	return 0;
}

static int cmsfs_release(const char *path, struct fuse_file_info *fi)
{
	struct file *f = get_fobj(fi);
	int rc = 0;

	(void) path;

	if (f == NULL) {
		DEBUG("release internal error\n");
		return -EINVAL;
	}

	if (fi->flags & O_RDWR || fi->flags & O_WRONLY) {
		f->write_count--;
		if (f->wcache_used)
			rc = flush_wcache(f);
	}

	if (f->use_count == 1) {
		if (f->unlinked)
			delete_file(f->path);
		util_list_remove(&open_file_list, f);
		destroy_file_object(f);
	} else
		f->use_count--;

	fi->fh = 0;
	return rc;
}

static void init_fops(struct file *f)
{
	if (f->fst->record_format == RECORD_LEN_FIXED)
		f->fops = &fops_fixed;
	else
		f->fops = &fops_variable;
}

/*
 * Create a file object to cache all needed file data.
 * Note: the caller must ensure that the file exists.
 */
static struct file *create_file_object(struct fst_entry *fst, int *rc)
{
	struct file *f;

	f = malloc(sizeof(*f));
	if (f == NULL)
		goto oom;
	memset(f, 0, sizeof(*f));

	f->fst = malloc(sizeof(struct fst_entry));
	if (f->fst == NULL)
		goto oom_f;

	memcpy(f->fst, fst, sizeof(*fst));
	workaround_nr_blocks(f);
	init_fops(f);

	f->linefeed = linefeed_mode_enabled(f->fst);
	f->translate = f->linefeed;

	f->record_scan_state = RSS_DATA_BLOCK_STARTED;

	if (f->fst->record_format == RECORD_LEN_FIXED)
		f->ptr_per_block = cmsfs.fixed_ptrs_per_block;
	else
		f->ptr_per_block = cmsfs.var_ptrs_per_block;

	f->wstate = malloc(sizeof(*f->wstate));
	if (f->wstate == NULL)
		goto oom_fst;
	memset(f->wstate, 0, sizeof(*f->wstate));

	/*
	 * Prevent calloc for zero records since it returns a pointer != NULL
	 * which causes trouble at free. Also don't call cache_file.
	 */
	if (f->fst->nr_records == 0)
		return f;

	f->rlist = calloc(f->fst->nr_records, sizeof(struct record));
	if (f->rlist == NULL)
		goto oom_wstate;

	f->blist = calloc(f->fst->nr_blocks, sizeof(struct block));
	if (f->blist == NULL)
		goto oom_rlist;

	*rc = cache_file(f);
	if (*rc < 0)
		goto error;
	return f;

error:
	if (*rc == 0)
		*rc = -ENOMEM;
oom_rlist:
	free(f->rlist);
oom_wstate:
	free(f->wstate);
oom_fst:
	free(f->fst);
oom_f:
	free(f);
oom:
	return NULL;
}

static void destroy_file_object(struct file *f)
{
	struct record_ext *rext, *tmp;
	struct record *rec;
	int i;

	free(f->iconv_buf);
	free(f->wcache);
	free(f->wstate);

	for (i = 0; i < f->fst->nr_records; i++) {
		rec = &f->rlist[i];
		rext = rec->ext;
		while (rext != NULL) {
			tmp = rext->next;
			free(rext);
			rext = tmp;
		}
	}

	free(f->rlist);
	free(f->blist);
	free(f->fst);
	free(f);
}

static struct file_operations fops_fixed = {
	.cache_data = cache_file_fixed,
	.write_data = extend_block_fixed,
	.delete_pointers = purge_pointer_block_fixed,
	.write_pointers = rewrite_pointer_block_fixed,
};

static struct file_operations fops_variable = {
	.cache_data = cache_file_variable,
	.write_data = extend_block_variable,
	.delete_pointers = purge_pointer_block_variable,
	.write_pointers = rewrite_pointer_block_variable,
};

static struct fuse_operations cmsfs_oper = {
	.getattr	= cmsfs_getattr,
	.statfs		= cmsfs_statfs,
	.readdir	= cmsfs_readdir,
	.open		= cmsfs_open,
	.release	= cmsfs_release,
	.read		= cmsfs_read,
	.utimens	= cmsfs_utimens,
	.rename		= cmsfs_rename,
	.fsync		= cmsfs_fsync,
	.truncate	= cmsfs_truncate,
	.create		= cmsfs_create,
	.write		= cmsfs_write,
	.unlink		= cmsfs_unlink,
#ifdef HAVE_SETXATTR
	.listxattr      = cmsfs_listxattr,
	.getxattr       = cmsfs_getxattr,
	.setxattr       = cmsfs_setxattr,
	/* no removexattr since our xattrs are virtual */
#endif
};

static int cmsfs_fuse_main(struct fuse_args *args,
			   struct fuse_operations *cmsfs_oper)
{
#if FUSE_VERSION >= 26
	return fuse_main(args->argc, args->argv, cmsfs_oper, NULL);
#else
	return fuse_main(args->argc, args->argv, cmsfs_oper);
#endif
}

static int cmsfs_process_args(void *data, const char *arg, int key,
			      struct fuse_args *outargs)
{
	(void) data;

	switch (key) {
	case FUSE_OPT_KEY_OPT:
		if (strcmp(arg, "allow_other") == 0)
			cmsfs.allow_other = 1;
		return 1;
	case FUSE_OPT_KEY_NONOPT:
		if (cmsfs.device == NULL) {
			cmsfs.device = strdup(arg);
			return 0;
		}
		return 1;
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
		cmsfs_fuse_main(outargs, &cmsfs_oper);
		exit(0);
	case KEY_VERSION:
		fprintf(stdout, COMP "FUSE file system for CMS disks "
			"program version %s\n", RELEASE_STRING);
		fprintf(stdout, "Copyright IBM Corp. 2010, 2017\n");
		exit(0);

	default:
		DIE("Process arguments error\n");
	}
}

static void init_io(int fd)
{
	int prot;

	DEBUG("read-only: %d", cmsfs.readonly);
	cmsfs.fd = fd;
	cmsfs.size = (off_t) cmsfs.total_blocks * cmsfs.blksize;
	DEBUG("  mmap size: %lu", cmsfs.size);

	/* try to map the whole block device for speeding-up access */
	if (cmsfs.readonly)
		prot = PROT_READ;
	else
		prot = PROT_READ | PROT_WRITE;

	cmsfs.map = mmap(NULL, cmsfs.size, prot, MAP_SHARED, fd, 0);
	if (cmsfs.map == MAP_FAILED) {
		DEBUG("\nmmap failed, using pread/write for disk I/O.\n");
		io_ops.read = &read_syscall;
		io_ops.write = &write_syscall;
	} else {
		DEBUG("  addr: %p\n", cmsfs.map);
		io_ops.read = &read_memory;
		io_ops.write = &write_memory;
	}
}

static void cmsfs_init(int fd)
{
	init_io(fd);

	/* calculate blocksize dependent values */
	cmsfs.data_block_mask = cmsfs.blksize - 1;
	cmsfs.nr_blocks_512 = cmsfs.blksize / 512;

	cmsfs.fixed_ptrs_per_block = cmsfs.blksize / sizeof(struct fixed_ptr);
	cmsfs.var_ptrs_per_block = cmsfs.blksize / sizeof(struct var_ptr);

	cmsfs.bits_per_data_block = get_order(cmsfs.blksize);

	/* store directory information */
	cmsfs.dir_levels = get_levels(cmsfs.fdir);
	cmsfs.files = get_files_count(cmsfs.fdir);

	/* alloc cache entries for all files */
	cmsfs.fcache_max = max_cache_entries();
	cmsfs.fcache = calloc(cmsfs.fcache_max, sizeof(struct fcache_entry));

	cmsfs.amap = get_fop(cmsfs.fdir + sizeof(struct fst_entry));
	cmsfs.amap_levels = get_levels(cmsfs.fdir + sizeof(struct fst_entry));
	cmsfs.amap_bytes_per_block = cmsfs.blksize * 8 * cmsfs.blksize;

	if (!hcreate_r(cmsfs.fcache_max, &cmsfs.htab))
		DIE("hcreate failed\n");

	util_list_init(&open_file_list, struct file, list);
	util_list_init(&text_type_list, struct filetype, list);
	scan_conf_file(&text_type_list);
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	char *fsname;
	int rc, fd;

#ifdef DEBUG_ENABLED
	logfile = fopen(DEBUG_LOGFILE, "w");
	if (logfile == NULL)
		DIE_PERROR("Cannot open file " DEBUG_LOGFILE " for writing");
#endif

	if (fuse_opt_parse(&args, &cmsfs, cmsfs_opts,
			   cmsfs_process_args) == -1)
		DIE("Failed to parse option\n");

	if (!cmsfs.device)
		DIE("Missing device\n"
		    "Try '%s --help' for more information\n", argv[0]);

	DEBUG("using device: %s", cmsfs.device);
	fd = get_device_info(&cmsfs);
	DEBUG("  blocksize: %d\n", cmsfs.blksize);

	fsname = malloc(FSNAME_MAX_LEN);
	if (fsname == NULL)
		DIE_PERROR("malloc failed");

#if FUSE_VERSION >= 27
	snprintf(fsname, FSNAME_MAX_LEN, "-osubtype=cmsfs,fsname=%s",
		 cmsfs.device);
#else
	snprintf(fsname, FSNAME_MAX_LEN, "-ofsname=%s", cmsfs.device);
#endif
	fuse_opt_add_arg(&args, fsname);
	free(fsname);

	cmsfs_init(fd);

	if (cmsfs.readonly)
		fuse_opt_add_arg(&args, "-oro");
	/* force single threaded mode which requires no locking */
	fuse_opt_add_arg(&args, "-s");
	/* force immediate file removal */
	fuse_opt_add_arg(&args, "-ohard_remove");

	if (cmsfs.mode == BINARY_MODE &&
	    (cmsfs.codepage_from != NULL || cmsfs.codepage_to != NULL))
		DIE("Incompatible options, select -a or -t if using --from or --to\n");

	if (cmsfs.mode != BINARY_MODE) {
		if (cmsfs.codepage_from == NULL)
			cmsfs.codepage_from = CODEPAGE_EDF;
		if (cmsfs.codepage_to == NULL)
			cmsfs.codepage_to = CODEPAGE_LINUX;

		setup_iconv(&cmsfs.iconv_from, cmsfs.codepage_from,
			    cmsfs.codepage_to);
		setup_iconv(&cmsfs.iconv_to, cmsfs.codepage_to,
			    cmsfs.codepage_from);
	}

	rc = cmsfs_fuse_main(&args, &cmsfs_oper);

	fuse_opt_free_args(&args);
#ifdef DEBUG_ENABLED
	fclose(logfile);
#endif
	hdestroy_r(&cmsfs.htab);
	return rc;
}

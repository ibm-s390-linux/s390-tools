/*
 * tape390_crypt: Provide encryption for tape devices
 *
 * Copyright 2006, 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mtio.h>
#include <unistd.h>

#include "lib/zt_common.h"
#include "tape390_common.h"

#define KEKL_LENGTH 65 /* 64 bytes plus trailing \0 */
#define TOT_KEKL_LENGTH KEKL_LENGTH+1+5 /* kekl plus colon plus LABEL or HASH */
#define ENCRYPTION_ON 1
#define ENCRYPTION_OFF 0
#define CRYPT_SET_FAILED_MSG "%s: Tape drive does not support encryption.\n"
#define CRYPT_QUERY_FAILED_MSG CRYPT_SET_FAILED_MSG
#define KEKL_QUERY_FAILED_MSG "%s: Query of encryption keys failed.\n"
#define KEKL_SET_FAILED_MSG "%s: Unable to set or modify encryption keys.\n"
#define PROC_DEVICES_FILE "/proc/devices"
#define PROC_DEVICES_FILE_WIDTH 100
#define MAX_BLOCKSIZE 65535 /* max blocksize supported by escon/ficon tapes */

#ifndef ENOKEY
#define ENOKEY          126
#endif
#ifndef EKEYREJECTED
#define EKEYREJECTED    129
#endif

#define CHECK_SPEC_MAX(i,j,numstr,str)                       \
	{if (i>j) ERRMSG_EXIT(EXIT_MISUSE,"%s: " str " " \
	"can only be specified " numstr ".\n",prog_name);}

#define PRINT_TYPE(byte)                                       \
	{if (byte==TAPE390_KEKL_TYPE_LABEL) printf("label\n");\
	else if (byte == TAPE390_KEKL_TYPE_HASH) printf("hash\n");\
	else printf("Unsupported type\n");}

/*
 * Structure tape390_crypt is used to store the command line parameters
 */
struct tape390_crypt {
	int   e_switch;
	char  delimiter;
	char  devname[PATH_MAX];
	char  kekl_input[2][TOT_KEKL_LENGTH];
	int   encryption_specified;
	int   query_specified;
	int   key_specified;
	int   delimiter_specified;
	int   force_specified;
} __attribute__ ((packed));

/*
 * The following ioctl's belong to linux-2.5/include/asm-s390/tape390.h
 *
 * The TAPE390_CRYPT_SET ioctl is used to switch on/off encryption.
 * The "encryption_capable" field is ignored for this ioctl!
 */
#define TAPE390_CRYPT_SET _IOW('d', 2, struct tape390_crypt_info)

/*
 * The TAPE390_CRYPT_QUERY ioctl is used to query the encryption state.
 */
#define TAPE390_CRYPT_QUERY _IOR('d', 3, struct tape390_crypt_info)

struct tape390_crypt_info {
	char capability;
	char status;
	char medium_status;
} __attribute__ ((packed));

/* Macros for "capable" field */
#define TAPE390_CRYPT_SUPPORTED_MASK 0x01
#define TAPE390_CRYPT_SUPPORTED(x) \
	((x.capability & TAPE390_CRYPT_SUPPORTED_MASK))

/* Macros for "status" field */
#define TAPE390_CRYPT_ON_MASK 0x01
#define TAPE390_CRYPT_ON(x) (((x.status) & TAPE390_CRYPT_ON_MASK))

/* Macros for "medium status" field */
#define TAPE390_MEDIUM_LOADED_MASK 0x01
#define TAPE390_MEDIUM_ENCRYPTED_MASK 0x02
#define TAPE390_MEDIUM_ENCRYPTED(x) \
	(((x.medium_status) & TAPE390_MEDIUM_ENCRYPTED_MASK))
#define TAPE390_MEDIUM_LOADED(x) \
	(((x.medium_status) & TAPE390_MEDIUM_LOADED_MASK))

/*
 * The TAPE390_KEKL_SET ioctl is used to set Key Encrypting Key labels.
 */
#define TAPE390_KEKL_SET _IOW('d', 4, struct tape390_kekl_pair)

/*
 * The TAPE390_KEKL_QUERY ioctl is used to query Key Encrypting Key labels.
 */
#define TAPE390_KEKL_QUERY _IOR('d', 5, struct tape390_kekl_pair)

struct tape390_kekl {
	unsigned char type;
	unsigned char type_on_tape;
	char label[65];
} __attribute__ ((packed));

struct tape390_kekl_pair {
        struct tape390_kekl kekl[2];
} __attribute__ ((packed));

/* Values for "kekl1/2_type" and "kekl1/2_type_on_tape" fields */
#define TAPE390_KEKL_TYPE_NONE 0
#define TAPE390_KEKL_TYPE_LABEL 1
#define TAPE390_KEKL_TYPE_HASH 2

/* Full tool name */
static const char tool_name[] = "tape390_crpyt: zSeries tape encryption program";

/* Copyright notice */
static const char copyright_notice[] = "Copyright IBM Corp. 2006, 2017";

/*
 * Print version information.
 */
static void print_version (void)
{
	printf ("%s version %s\n", tool_name, RELEASE_STRING);
	printf ("%s\n", copyright_notice);
}

/*
 * prints out the usage text
 */
static void tape390_crypt_usage (void)
{
	printf ("Usage: tape390_crypt [OPTIONS] [DEVICE]\n"
		"\n"
		"Provide encryption for "
		"tape devices.\n"
		"DEVICE is the node of the tape device (e.g. '/dev/ntibm0')\n"
		"\n"
		"-h, --help               Print this help, then exit\n"
		"-v, --version            Print version information, "
		                          "then exit\n"
		"-q, --query              Query information on encryption "
		                          "status and keys\n"
		"-k, --key value:type     Set encryption key(s)\n"
		"-d, --delimiter char     Specify character separating "
		                          "key value from key type\n"
		"-f, --force              Do not prompt user\n"
		"-e, --encryption on|off  Switch encryption on or off\n");
}

/*
 * initialize the tape390_crypt info structure
 */
static void init_info(struct tape390_crypt *info)
{
	info->delimiter            = ':';
	info->encryption_specified = 0;
	info->query_specified       = 0;
	info->key_specified        = 0;
	info->delimiter_specified  = 0;
	info->force_specified  = 0;
}

/*
 * parse the commandline options
 */
static void tape390_crypt_parse_opts(struct tape390_crypt *info, int argc,
				     char* argv[])
{
	int opt, index, kekl_too_long=0, deli_too_long=0, e_switch_invalid=0;
	int i;
	static struct option crypt_long_options[] = {
		{ "version",     no_argument,       NULL, 'v'},
		{ "encryption",  required_argument, NULL, 'e'},
		{ "query",       no_argument,       NULL, 'q'},
		{ "key",         required_argument, NULL, 'k'},
		{ "help",        no_argument,       NULL, 'h'},
		{ "delimiter",   required_argument, NULL, 'd'},
		{ "force",       no_argument,       NULL, 'f'},
		{ NULL,          0,                 NULL,  0 }
	};
	/* Command line option abbreviations */
	static const char crypt_option_string[] = "ve:qk:hd:f";

	while (1) {
		opt = getopt_long(argc, argv, crypt_option_string,
				  crypt_long_options, &index);
		if (opt == -1)
			break;
		switch (opt) {
		case 'v':
			print_version();
			exit(0);
		case 'h':
			tape390_crypt_usage();
			exit(0);
		case 'q':
			++info->query_specified;
			break;
		case 'k':
			++info->key_specified;
			if(strlen(optarg) >= TOT_KEKL_LENGTH)
				kekl_too_long = 1;
			else if (info->key_specified == 1) 
				for (i = 0; i < 2; i++)
					strcpy(info->kekl_input[i], optarg);
			else 
				strcpy(info->kekl_input[1], optarg);
			break;
		case 'e':
			++info->encryption_specified;
			if (strcmp(optarg,"off") == 0)
				info->e_switch = ENCRYPTION_OFF;
			else if (strcmp(optarg,"on") == 0)
				info->e_switch = ENCRYPTION_ON;
			else
				e_switch_invalid = 1;
			break;
		case 'd':
			++info->delimiter_specified;
			if(strlen(optarg) > 1)
				deli_too_long = 1;
			else
				info->delimiter = optarg[0];
			break;
		case 'f':
			++info->force_specified;
			break;
		default:
			fprintf(stderr, "Try '%s --help' for more"
					" information.\n",prog_name);
			exit(1);
		}
	}
	CHECK_SPEC_MAX(info->query_specified, 1, "once", "query");
	CHECK_SPEC_MAX(info->encryption_specified, 1, "once", "encryption");
	CHECK_SPEC_MAX(info->delimiter_specified, 1, "once", "delimiter");
	CHECK_SPEC_MAX(info->force_specified, 1, "once", "force");
	CHECK_SPEC_MAX(info->key_specified,2, "twice", "key");
	if (kekl_too_long)
		ERRMSG_EXIT(EXIT_MISUSE,
			    "%s: Specified key too long.\n",prog_name);
	if (deli_too_long)
		ERRMSG_EXIT(EXIT_MISUSE,
			    "%s: Delimiter must be one character.\n",prog_name);
	if (e_switch_invalid)
		ERRMSG_EXIT(EXIT_MISUSE,
			    "%s: ERROR: encryption can be set 'on' or 'off'.\n",
			    prog_name);
	if (((info->query_specified) &&
	     (info->key_specified + info->encryption_specified > 0)) ||
	    ((info->encryption_specified) &&
	     (info->key_specified + info->query_specified > 0)) ||
	    ((info->force_specified) &&
	     (info->encryption_specified)) ||
	    ((info->delimiter_specified) &&
	     (info->encryption_specified + info->query_specified > 0)))
		ERRMSG_EXIT(EXIT_MISUSE,
			    "%s: Conflicting options specified.\n",prog_name);
	if (info->query_specified + info->encryption_specified +
	    info->key_specified == 0)
		ERRMSG_EXIT(EXIT_MISUSE,
			    "%s: ERROR: Missing options.\n",prog_name);
	/* save device */
	if (optind >= argc)
		ERRMSG_EXIT(EXIT_MISUSE,
			    "%s: No device specified.\n",prog_name);
	if (optind + 1 < argc)
		ERRMSG_EXIT(EXIT_MISUSE,
			    "%s: More than one device specified.\n",prog_name);
	strcpy(info->devname, argv[optind]);
}

/*
 * check and parse key operand, must be value:type
 * where  value  is an arbitrary string, maximal 64 char long
 *        :      is a 1-char delimiter specified with the -d option (default :)
 *        type   is the type identifier, which can be either 'hash' or 'label'
 *               default is 'label'
 */
static void fill_kekl(char *s, char delimiter,
			      struct tape390_kekl *mykekl)
{
	int i;
	char typestring[TOT_KEKL_LENGTH] = {0};
	for (i = strlen(s); i >= 0; i--)
		if (*(s+i) == delimiter)
			break;
	if (i == -1)		/* delimiter not found, no type specified */
		mykekl->type_on_tape = TAPE390_KEKL_TYPE_LABEL; /* default type*/
	else if (i == 0)
		ERRMSG_EXIT(EXIT_MISUSE,
			    "%s: ERROR: delimiter '%c' found as first "
			    "character.\n",prog_name,delimiter);
	else if (i == (int) strlen(s) - 1)
		ERRMSG_EXIT(EXIT_MISUSE,
			    "%s: ERROR: Delimiter '%c' found as last "
			    "character.\n",prog_name,delimiter);
	else {
		strcpy(typestring,s+i+1);
		*(s+i) = '\0';
		if (strcmp(typestring,"hash") == 0)
			mykekl->type_on_tape = TAPE390_KEKL_TYPE_HASH;
		else if (strcmp(typestring,"label") == 0)
			mykekl->type_on_tape = TAPE390_KEKL_TYPE_LABEL;
		else
			ERRMSG_EXIT(EXIT_MISUSE,
			    "%s: Invalid key type '%s',"
			    " must be either 'label' or 'hash'.\n",
			    prog_name,typestring);
	}
	if (strlen(s) >= KEKL_LENGTH)
		ERRMSG_EXIT(EXIT_MISUSE,
			    "%s: Specified key value too long, has %d chars.\n",
			    prog_name,(int)strlen(s));
	else {
		strcpy(mykekl->label, s);
		mykekl->type = TAPE390_KEKL_TYPE_LABEL;
	}
}

/*
 * Write two tapemarks on tape to initialize tape after kekl set
 */

static int init_tape(int fd)
{
	struct mtop mtop;
	int rc;

	mtop.mt_op = MTWEOF;
	mtop.mt_count = 2;
	rc = ioctl(fd, MTIOCTOP, &mtop);
	if (rc)
		return rc;
	mtop.mt_op = MTREW;
	return ioctl(fd, MTIOCTOP, &mtop);
}

/*
 * Tell the current block on tape
 */

static int tell_tape(int fd)
{
	struct mtop mtop;

	mtop.mt_op = MTTELL;
	mtop.mt_count = 1;
	return ioctl(fd, MTIOCTOP, &mtop);
}


/*
 * Do read IO to tape in order to enforce update of KEKL information.
 * Leave tape position unchanged.
 */

static int read_tape(int fd)
{
	struct mtop mtop;
	int block_number, n_read;
	char buffer[MAX_BLOCKSIZE];

	/* remember current block on tape */
	block_number = tell_tape(fd);
	n_read = read(fd, buffer, sizeof(buffer));
	if (n_read == -1) {
		/* tape read failed, ignore if caused by end-of-volume */
		if (errno == ENOSPC)
			return 0;
		else
			return 1;
	}
	if (block_number != tell_tape(fd)) {
		/* re-position tape */
		mtop.mt_op = MTSEEK;
		mtop.mt_count = block_number;
		if (ioctl(fd, MTIOCTOP, &mtop) != 0)
			return 1;
	}
	return 0;
}

/*
 * set Key Encrypting Key labels
 */
static int set_encryption_keys(int fd, struct tape390_crypt *info)
{
	struct tape390_kekl_pair kekls;
	char delim;
	char *s, inp_buffer[5];
	int i, rc;

	delim = info->delimiter;
	for (i = 0; i < 2; i++) {
		s = info->kekl_input[i];
		fill_kekl(s, delim, &kekls.kekl[i]);
	}
	if (info->force_specified == 0) {
		printf("--->> ATTENTION! <<---\n");
		printf("All data on tape %s will be lost.\nType "
		       "\"yes\" to continue: ", info->devname);
		if (fgets(inp_buffer, sizeof(inp_buffer), stdin) == NULL) {
			fprintf(stderr, "Reading from terminal failed.\n");
			exit(1);
		}
		if (strcasecmp(inp_buffer,"yes\n")) {
			printf("Tape and its encryption keys " 
			       "remain unchanged.\n");
			exit(0);
		}
	}
	rc = ioctl(fd, TAPE390_KEKL_SET, &kekls);
	if (rc)
		return rc;
	return init_tape(fd);
}

/*
 * Switch on/off encryption
 */
static int switch_encryption_on_or_off(int fd,struct tape390_crypt *info)
{
	struct tape390_crypt_info myinfo;

	memset(&myinfo, 0, sizeof(myinfo));
	if (info->e_switch == ENCRYPTION_ON)
		myinfo.status |= TAPE390_CRYPT_ON_MASK;
	return ioctl(fd, TAPE390_CRYPT_SET, &myinfo);
}

/*
 * Query information on encryption and keys
 */
static int query_encryption(int fd,struct tape390_crypt *info)
{
	struct tape390_crypt_info myinfo;
	struct tape390_kekl_pair kekls;
	int i, ret;

	ret = ioctl(fd, TAPE390_CRYPT_QUERY, &myinfo);
	if (ret)
		return -1;
	if (!TAPE390_MEDIUM_LOADED(myinfo)) {
		printf("Medium not loaded\n");
		return 0;
	}
	printf("ENCRYPTION: ");
	if (TAPE390_CRYPT_ON(myinfo))
		printf("ON\n");
	else
		printf("OFF\n");
	printf("MEDIUM: ");
	if (TAPE390_MEDIUM_ENCRYPTED(myinfo))
		printf("ENCRYPTED\n");
	else {
		printf("NOT ENCRYPTED\n");
		return 0;
	}
	/* 
	 * do a dummy read in order to force the control unit to get 
	 * the key information from the EKM
	*/
	ret = read_tape(fd);
	if (ret && (info->force_specified == 0))
		return -2;
	ret = ioctl(fd, TAPE390_KEKL_QUERY, &kekls);
	if (ret)
		return -2;
	printf("KEKLs on TAPE:\n");
	if (kekls.kekl[0].type == TAPE390_KEKL_TYPE_NONE) {
		ERRMSG("Unable to retrieve key information.\n");
		return 0;
	}
	for (i = 0; i < 2; i++) {
		printf(" KEY%i:\n",i+1);
		if (kekls.kekl[i].type == TAPE390_KEKL_TYPE_NONE)
			printf("None\n");
		else {
			printf("  value:  %s\n",kekls.kekl[i].label);
			printf("  type:   ");
			PRINT_TYPE(kekls.kekl[i].type);
			printf("  ontape: ");
			PRINT_TYPE(kekls.kekl[i].type_on_tape);
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct tape390_crypt info;
	char error_msg[80];
	int rc=0, fd=-1;

	/* set name of program */
	set_prog_name(basename(argv[0]));

	/* set default values */
	init_info(&info);

	/* parse command line options and check syntax */
	tape390_crypt_parse_opts(&info, argc, argv);

	/* check whether specified device node is tape */
	if (is_not_tape(info.devname))
		exit(EXIT_MISUSE);

	/* open device                                 */
	fd = open_tape(info.devname);

	/* process -k or -e or -q operand              */
	if (info.key_specified >= 1) {
		rc = set_encryption_keys(fd, &info);
		if (rc == 0)
			printf("SUCCESS: key information set.\n");
		strcpy(error_msg, KEKL_SET_FAILED_MSG);
	} else if (info.encryption_specified) {
		rc = switch_encryption_on_or_off(fd, &info);
		strcpy(error_msg, CRYPT_SET_FAILED_MSG);
	} else if (info.query_specified) {
		rc = query_encryption(fd, &info);
		if (rc == -1)
			strcpy(error_msg, CRYPT_QUERY_FAILED_MSG);
		else if (rc == -2)
			strcpy(error_msg, KEKL_QUERY_FAILED_MSG);
	}
	if (rc) {
		ERRMSG(error_msg, prog_name);
		switch (errno) {
			case ENOKEY:
				ERRMSG("EKM error.\n");
				break;
			case ENOTCONN:
				ERRMSG("Could not connect to EKM.\n");
				break;
			case EKEYREJECTED:
				ERRMSG("Key not available on EKM.\n");
				break;
			case EUNATCH:
				ERRMSG("Encryption must be set ON prior to "
				       "setting or querying encryption " 
				       "keys.\n");
				break;
			case EBADSLT:
				ERRMSG("Tape must be at load point in order "
				       "to set encryption keys.\n");
				break;
			case ENOSYS:
				ERRMSG("Tape device does not support "
				       "encryption.\n");
				break;
			case EINVAL:
				ERRMSG("Kernel does not support tape "
				       "encryption.\n"); 
				break;
			default:
				perror("");
		}
	}
	if (fd != -1)
		close(fd);
	return(rc);
}

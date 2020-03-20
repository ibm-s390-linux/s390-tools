/*
 * dasdview - Display DASD and VTOC information or dump the contents of a DASD
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#define _LARGEFILE64_SOURCE    /* needed for unistd.h */
#define _FILE_OFFSET_BITS 64   /* needed for unistd.h */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/version.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "lib/dasd_base.h"
#include "lib/dasd_sys.h"
#include "lib/libzds.h"
#include "lib/util_base.h"
#include "lib/util_opt.h"
#include "lib/util_prg.h"
#include "lib/util_sys.h"
#include "lib/vtoc.h"
#include "lib/zt_common.h"

#include "dasdview.h"

/* Characters per line */
#define DASDVIEW_CPL 16

static const struct util_prg prg = {
	.desc = "Display DASD and VTOC information and dump the content of "
		"a DASD to the console.\n"
		"DEVICE is the node of the device (e.g. '/dev/dasda').",
	.args = "DEVICE",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2001,
			.pub_last = 2006,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("DUMP OPTIONS"),
	{
		.option = { NULL, no_argument, NULL, '1' },
		.desc = "Show DASD content in short Hex/EBCDIC/ASCII format",
		.flags = UTIL_OPT_FLAG_NOLONG,
	},
	{
		.option = { NULL, no_argument, NULL, '2' },
		.desc = "Show DASD content in detailed Hex/EBCDIC/ASCII format",
		.flags = UTIL_OPT_FLAG_NOLONG,
	},
	{
		.option = { "begin", required_argument, NULL, 'b' },
		.argument = "BEGIN",
		.desc = "Specify start of dump in kilobytes (suffix k), "
			"megabytes (m), blocks (b), tracks (t), or cylinders (c)",
	},
	{
		.option = { "size", required_argument, NULL, 's' },
		.argument = "SIZE",
		.desc = "Specify size of dump in kilobytes (suffix k), "
			"megabytes (m), blocks (b), tracks (t), or cylinders (c)",
	},
	UTIL_OPT_SECTION("MISC"),
	{
		.option = { "characteristic", no_argument, NULL, 'c' },
		.desc = "Print the characteristics of a device",
	},
	{
		.option = { "info", no_argument, NULL, 'i' },
		.desc = "Print general DASD information and geometry",
	},
	{
		.option = { "volser", no_argument, NULL, 'j' },
		.desc = "Print the volume serial number",
	},
	{
		.option = { "label", no_argument, NULL, 'l' },
		.desc = "Print information about the volume label",
	},
	{
		.option = { "vtoc", required_argument, NULL, 't' },
		.argument = "SPEC",
		.desc = "Print the table of content (VTOC)",
	},
	{
		.option = { "extended", no_argument, NULL, 'x' },
		.desc = "Print extended DASD information",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

/*
 * Generate and print an error message based on the formatted
 * text string FMT and a variable amount of extra arguments.
 */
static void zt_error_print(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(error_str, ERROR_STRING_SIZE, fmt, args);
	va_end(args);

	fprintf(stderr, "Error: %s\n", error_str);
}

/*
 * replace special characters with dots and question marks
 */
static void dot(char label[])
{
	int i;
	char c;

	for (i = 0; i < 16; i++) {
		c = label[i];
		if (c <= 0x20)
			label[i] = '?';
		if (c == 0x00)
			label[i] = '.';
		if (c == 0x60)
			label[i] = '?';
		if (c >= 0x7f)
			label[i] = '?';
	}
}

static void
dasdview_get_info(dasdview_info_t *info)
{
	struct dasd_eckd_characteristics *characteristics;
	int err;

	err = dasd_get_geo(info->device, &info->geo);
	if (err != 0) {
		/* Test for unknown device in the first call to libdasd to avoid
		 * spitting out two different error messages to the user
		 */
		if (err != EBADF)
			zt_error_print("dasdview: "
				       "Could not retrieve geo information!\n");
		exit(EXIT_FAILURE);
	}

	if (dasd_get_blocksize(info->device, &info->blksize) != 0) {
		zt_error_print("dasdview: "
			       "Could not retrieve blocksize information!\n");
		exit(EXIT_FAILURE);
	}

	if (dasd_get_info(info->device, &info->dasd_info) != 0) {
		zt_error_print("dasdview: "
			       "Could not retrieve disk information!\n");
		exit(EXIT_FAILURE);
	}

	characteristics = (struct dasd_eckd_characteristics *)
		&info->dasd_info.characteristics;
	if (characteristics->no_cyl == LV_COMPAT_CYL &&
	    characteristics->long_no_cyl)
		info->hw_cylinders = characteristics->long_no_cyl;
	else
		info->hw_cylinders = characteristics->no_cyl;

	if (util_sys_get_dev_addr(info->device, info->busid) != 0)
		info->busid_valid = 0;
	else
		info->busid_valid = 1;

	info->raw_track_access = dasd_sys_raw_track_access(info->device);
}

static void
dasdview_parse_input(unsigned long long *p, dasdview_info_t *info, char *s)
{
	unsigned long long l;
	char *endp;
	char suffix;

	l = strtoull(s, &endp, 0);
	if ((endp == s) || ((l + 1) == 0))
		goto error;

	if (*endp) {
		if (!strchr("kmtbcKMTBC", *endp) || *(endp + 1))
			goto error;
		suffix = tolower(*endp);
	} else {
		suffix = 0;
	}
	if (info->raw_track_access) {
		switch (suffix) {
		case 't':
			l *= RAWTRACKSIZE;
			break;
		case 'c':
			l *= (unsigned long long)info->geo.heads * RAWTRACKSIZE;
			break;
		case 0:
			if (l % RAWTRACKSIZE) {
				zt_error_print("dasdview: only full tracks can"
					       " be accessd on devices with "
					       " raw_track_access enabled.\n", s);
				goto error;
			}
			break;
		default:
			zt_error_print("dasdview: only types t and c are"
				       " allowed for devices with"
				       " raw_track_access enabled.\n", s);
			goto error;
		}
	} else {
		switch (suffix) {
		case 'k':
			l *= 1024LL;
			break;
		case 'm':
			l *= 1024LL * 1024LL;
			break;
		case 't':
			l *= (unsigned long long)info->blksize *
				(unsigned long long)info->geo.sectors;
			break;
		case 'b':
			l *= (unsigned long long)info->blksize;
			break;
		case 'c':
			l *= (unsigned long long)info->blksize *
				(unsigned long long)info->geo.sectors *
				(unsigned long long)info->geo.heads;
			break;
		default:
			break;
		}
	}
	*p = l;

	return;
error:
	zt_error_print("dasdview: usage error\n"
		       "%s is not a valid begin/size value!", s);
	exit(EXIT_FAILURE);
}

/*
 * Print general DASD information.
 */
static void
dasdview_print_general_info(dasdview_info_t *info)
{
	printf("\n--- general DASD information -----------------"
	       "---------------------------------\n");
	printf("device node            : %s\n", info->device);
#ifdef SYSFS
	struct utsname buf;
	unsigned char a, b, c;
	char suffix[sizeof(buf.release)];
	int rc;

	rc = uname(&buf);
	if (!rc) {
		sscanf(buf.release, "%c.%c.%c-%s", &a, &b, &c, suffix);
		if (KERNEL_VERSION(2, 5, 0) <= KERNEL_VERSION(a, b, c)) {
			if (info->busid_valid)
				printf("busid                  : %s\n",
				       info->busid);
			else
				printf("busid                  :"
				       " <not found>\n");
		} else {
#endif
			printf("device number          : hex %x  \tdec %d\n",
			       info->dasd_info.devno,
			       info->dasd_info.devno);
#ifdef SYSFS
		}
	}
#endif
	printf("type                   : %4s\n", info->dasd_info.type);
	printf("device type            : hex %x  \tdec %d\n",
	       info->dasd_info.dev_type,
	       info->dasd_info.dev_type);
	printf("\n--- DASD geometry ----------------------------"
	       "---------------------------------\n");
	printf("number of cylinders    : hex %x  \tdec %d\n",
	       info->hw_cylinders,
	       info->hw_cylinders);
	printf("tracks per cylinder    : hex %x  \tdec %d\n",
	       info->geo.heads,
	       info->geo.heads);
	printf("blocks per track       : hex %x  \tdec %d\n",
	       info->geo.sectors,
	       info->geo.sectors);
	printf("blocksize              : hex %x  \tdec %d\n",
	       info->blksize,
	       info->blksize);
}

/*
 * Loop over the given character array and HEXdump the content.
 */
static inline void
dasdview_dump_array(char *name, int size, unsigned char *addr)
{
	int i;

	for (i = 0; i < size; i++) {
		if (i % DASDVIEW_CPL == 0) {
			if (i == 0)
				printf("%-23.23s: ", name);
			else
				printf("\n%25s", "");
		} else {
			if (i % 8 == 0)
				printf(" ");
			if (i % 4 == 0)
				printf(" ");
		}
		printf("%02x", addr[i]);
	}
	printf("\n");
}

/*
 * Print extended DASD information.
 */
static void
dasdview_print_extended_info(dasdview_info_t *info)
{
	unsigned int i;
	struct dasd_information2_t *dasd_info;
	struct {
		unsigned int mask;
		char *name;
	} flist[2] = { {DASD_FEATURE_READONLY, "ro"  },
		       {DASD_FEATURE_USEDIAG,  "diag"} };

	dasd_info = &info->dasd_info;
	printf("\n--- extended DASD information ----------------"
	       "---------------------------------\n");
	printf("real device number     : hex %x  \tdec %d\n",
	       dasd_info->real_devno, dasd_info->real_devno);
	printf("subchannel identifier  : hex %x  \tdec %d\n",
	       dasd_info->schid, dasd_info->schid);
	printf("CU type  (SenseID)     : hex %x  \tdec %d\n",
	       dasd_info->cu_type, dasd_info->cu_type);
	printf("CU model (SenseID)     : hex %x  \tdec %d\n",
	       dasd_info->cu_model, dasd_info->cu_model);
	printf("device type  (SenseID) : hex %x  \tdec %d\n",
	       dasd_info->dev_type, dasd_info->dev_type);
	printf("device model (SenseID) : hex %x  \tdec %d\n",
	       dasd_info->dev_model, dasd_info->dev_model);
	printf("open count             : hex %x  \tdec %d\n",
	       dasd_info->open_count, dasd_info->open_count);
	printf("req_queue_len          : hex %x  \tdec %d\n",
	       dasd_info->req_queue_len, dasd_info->req_queue_len);
	printf("chanq_len              : hex %x  \tdec %d\n",
	       dasd_info->chanq_len, dasd_info->chanq_len);
	printf("status                 : hex %x  \tdec %d\n",
	       dasd_info->status, dasd_info->status);
	printf("label_block            : hex %x  \tdec %d\n",
	       dasd_info->label_block, dasd_info->label_block);
	printf("FBA_layout             : hex %x  \tdec %d\n",
	       dasd_info->FBA_layout, dasd_info->FBA_layout);
	printf("characteristics_size   : hex %x  \tdec %d\n",
	       dasd_info->characteristics_size,
	       dasd_info->characteristics_size);
	printf("confdata_size          : hex %x  \tdec %d\n",
	       dasd_info->confdata_size, dasd_info->confdata_size);

	printf("format                 : hex %x  \tdec %d      \t%s\n",
	       dasd_info->format, dasd_info->format,
	       dasd_info->format == DASD_FORMAT_NONE ?
	       "NOT formatted" :
	       dasd_info->format == DASD_FORMAT_LDL  ?
	       "LDL formatted" :
	       dasd_info->format == DASD_FORMAT_CDL  ?
	       "CDL formatted" : "unknown format");

	printf("features               : hex %x  \tdec %d      \t",
	       dasd_info->features, dasd_info->features);
	if (dasd_info->features == DASD_FEATURE_DEFAULT) {
		printf("default\n");
	} else {
		for (i = 0; i < ARRAY_SIZE(flist); i++)
			if (dasd_info->features & flist[i].mask)
				printf("%s ", flist[i].name);
		printf("\n");
	}
	printf("\n");
	dasdview_dump_array("characteristics",
			    dasd_info->characteristics_size,
			    dasd_info->characteristics);
	printf("\n");
	dasdview_dump_array("configuration_data",
			    dasd_info->confdata_size,
			    dasd_info->configuration_data);
}

static void
dasdview_read_vlabel(dasdview_info_t *info, volume_label_t *vlabel)
{
	volume_label_t tmp;
	unsigned long  pos;

	pos = info->dasd_info.label_block * info->blksize;

	bzero(vlabel, sizeof(volume_label_t));
	if ((strncmp(info->dasd_info.type, "ECKD", 4) == 0) &&
	    !info->dasd_info.FBA_layout) {
		/* OS/390 and zOS compatible disk layout */
		vtoc_read_volume_label(info->device, pos, vlabel);
	} else {
		/* standard LINUX disk layout */
		vtoc_read_volume_label(info->device, pos, &tmp);
		memcpy(vlabel->vollbl, &tmp, sizeof(tmp) - 4);
	}
}

static void
dasdview_print_vlabel(dasdview_info_t *info)
{
	volume_label_t vlabel;
	volume_label_t *tmpvlabel;
	int rc;
	unsigned char s4[5], t4[5], s5[6], t5[6], s6[7], t6[7];
	char s14[15], t14[15], s29[30], t29[30];
	int i;

	if (info->raw_track_access) {
		rc = lzds_dasd_read_vlabel(info->dasd);
		if (rc) {
			zt_error_print("error when reading label from device:"
				       " rc=%d\n", rc);
			exit(EXIT_FAILURE);
		}
		lzds_dasd_get_vlabel(info->dasd, &tmpvlabel);
		memcpy(&vlabel, tmpvlabel, sizeof(vlabel));
	} else {
		dasdview_read_vlabel(info, &vlabel);
	}

	printf("\n--- volume label -----------------------------"
	       "---------------------------------\n");

	bzero(s4, 5); bzero(t4, 5); strncpy((char *)s4, vlabel.volkey, 4);
	printf("volume label key        : ascii  '%4s'\n", s4);
	vtoc_ebcdic_dec((char *)s4, (char *)t4, 4);
	printf("                        : ebcdic '%4s'\n", t4);
	printf("                        : hex    ");
	for (i = 0; i < 4; i++)
		printf("%02x", s4[i]);

	bzero(s4, 5); bzero(s4, 5); strncpy((char *)s4, vlabel.vollbl, 4);
	printf("\n\nvolume label identifier : ascii  '%4s'\n", s4);
	vtoc_ebcdic_dec((char *)s4, (char *)t4, 4);
	printf("                        : ebcdic '%4s'\n", t4);
	printf("                        : hex    ");
	for (i = 0; i < 4; i++)
		printf("%02x", s4[i]);

	bzero(s6, 7); bzero(t6, 7); strncpy((char *)s6, vlabel.volid, 6);
	printf("\n\nvolume identifier       : ascii  '%6s'\n", s6);
	vtoc_ebcdic_dec((char *)s6, (char *)t6, 6);
	printf("                        : ebcdic '%6s'\n", t6);
	printf("                        : hex    ");
	for (i = 0; i < 6; i++)
		printf("%02x", s6[i]);

	printf("\n\nsecurity byte           : hex    %02x\n", vlabel.security);

	printf("\n\nVTOC pointer            : hex    %04x%04x%02x ",
	       vlabel.vtoc.cc, vlabel.vtoc.hh, vlabel.vtoc.b);
	if ((vlabel.vtoc.cc == 0x4040) && (vlabel.vtoc.hh == 0x4040) &&
	    (vlabel.vtoc.b == 0x40))
		printf("\n");
	else
		printf("\n                                 "
		       "(cyl %d, trk %d, blk %d)\n\n",
		       vtoc_get_cyl_from_cchhb(&vlabel.vtoc),
		       vtoc_get_head_from_cchhb(&vlabel.vtoc), vlabel.vtoc.b);

	bzero(s5, 6); bzero(t5, 6); strncpy((char *)s5, vlabel.res1, 5);
	printf("reserved                : ascii  '%5s'\n", s5);
	vtoc_ebcdic_dec((char *)s5, (char *)t5, 5);
	printf("                        : ebcdic '%5s'\n", t5);
	printf("                        : hex    ");
	for (i = 0; i < 5; i++)
		printf("%02x", s5[i]);

	bzero(s4, 5); bzero(t4, 5); strncpy((char *)s4, vlabel.cisize, 4);
	printf("\n\nCI size for FBA         : ascii  '%4s'\n", s4);
	vtoc_ebcdic_dec((char *)s4, (char *)t4, 4);
	printf("                        : ebcdic '%4s'\n", t4);
	printf("                        : hex    ");
	for (i = 0; i < 4; i++)
		printf("%02x", s4[i]);

	bzero(s4, 5); bzero(t4, 5); strncpy((char *)s4, vlabel.blkperci, 4);
	printf("\n\nblocks per CI (FBA)     : ascii  '%4s'\n", s4);
	vtoc_ebcdic_dec((char *)s4, (char *)t4, 4);
	printf("                        : ebcdic '%4s'\n", t4);
	printf("                        : hex    ");
	for (i = 0; i < 4; i++)
		printf("%02x", s4[i]);

	bzero(s4, 5); bzero(t4, 5); strncpy((char *)s4, vlabel.labperci, 4);
	printf("\n\nlabels per CI (FBA)     : ascii  '%4s'\n", s4);
	vtoc_ebcdic_dec((char *)s4, (char *)t4, 4);
	printf("                        : ebcdic '%4s'\n", t4);
	printf("                        : hex    ");
	for (i = 0; i < 4; i++)
		printf("%02x", s4[i]);

	bzero(s4, 5); bzero(t4, 5); strncpy((char *)s4, vlabel.res2, 4);
	printf("\n\nreserved                : ascii  '%4s'\n", s4);
	vtoc_ebcdic_dec((char *)s4, (char *)t4, 4);
	printf("                        : ebcdic '%4s'\n", t4);
	printf("                        : hex    ");
	for (i = 0; i < 4; i++)
		printf("%02x", s4[i]);

	bzero(s14, 15); bzero(t14, 15); strncpy(s14, vlabel.lvtoc, 14);
	printf("\n\nowner code for VTOC     : ascii  '%14s'\n", s14);
	vtoc_ebcdic_dec(s14, t14, 14);
	printf("                          ebcdic '%14s'\n", t14);
	printf("                          hex    ");
	for (i = 0; i < 14; i++) {
		printf("%02x", s14[i]);
		if ((i + 1) % 4 == 0)
			printf(" ");
		if ((i + 1) % 8 == 0)
			printf(" ");
	}

	bzero(s29, 30); strncpy(s29, vlabel.res3, 28);
	printf("\n\nreserved                : ascii  '%28s'\n", s29);
	bzero(t29, 30);
	vtoc_ebcdic_dec(s29, t29, 28);
	printf("                          ebcdic '%28s'\n", t29);
	printf("                          hex    ");
	for (i = 0; i < 28; i++) {
		printf("%02x", s29[i]);
		if ((i + 1) % 4 == 0)
			printf(" ");
		if ((i + 1) % 8 == 0)
			printf(" ");
		if ((i + 1) % 16 == 0)
			printf("\n                "
			       "                 ");
	}

	bzero(s4, 5); bzero(t4, 5); s4[0] = vlabel.ldl_version;
	printf("\n\nldl_version             : ascii  '%1s'\n", s4);
	vtoc_ebcdic_dec((char *)s4, (char *)t4, 1);
	printf("                        : ebcdic '%1s'\n", t4);
	printf("                        : hex    %02x", s4[0]);

	printf("\n\nformatted_blocks        : dec %llu",
	       vlabel.formatted_blocks);
	printf("\n                        : hex %016llx",
	       vlabel.formatted_blocks);

	printf("\n");
}

static void
dasdview_print_volser(dasdview_info_t *info)
{
	volume_label_t vlabel;
	volume_label_t *tmpvlabel;
	char           volser[7];
	char           vollbl[5];
	int rc;

	if (info->raw_track_access) {
		rc = lzds_dasd_read_vlabel(info->dasd);
		if (rc) {
			zt_error_print("error when reading label from device:"
				       " rc=%d\n", rc);
			exit(EXIT_FAILURE);
		}
		lzds_dasd_get_vlabel(info->dasd, &tmpvlabel);
		memcpy(&vlabel, tmpvlabel, sizeof(vlabel));
	} else {
		dasdview_read_vlabel(info, &vlabel);
	}

	bzero(vollbl, 5);
	bzero(volser, 7);
	strncpy(vollbl, vlabel.vollbl, 4);
	vtoc_ebcdic_dec(vollbl, vollbl, 4);

	if ((strncmp(vollbl, "VOL1", 4) == 0) ||
	    (strncmp(vollbl, "LNX1", 4) == 0)) {
		strncpy(volser, vlabel.volid, 6);
		vtoc_ebcdic_dec(volser, volser, 6);
	} else {
		memcpy(volser, "      ", 6);
	}

	printf("%6.6s\n", volser);
}

static void
dasdview_read_vtoc(dasdview_info_t *info)
{
	volume_label_t vlabel;
	format1_label_t tmp;
	unsigned long maxblk, pos;
	u_int64_t vtocblk;
	int i;

	pos = info->dasd_info.label_block * info->blksize;

	bzero(&vlabel, sizeof(vlabel));
	if ((strncmp(info->dasd_info.type, "ECKD", 4) == 0) &&
	    !info->dasd_info.FBA_layout) {
		/* OS/390 and zOS compatible disk layout */
		vtoc_read_volume_label(info->device, pos, &vlabel);
	} else {
		zt_error_print("dasdview: disk layout error\n"
			       "%s is not formatted with the z/OS "
			       "compatible disk layout!\n", info->device);
		exit(EXIT_FAILURE);
	}

	vtocblk = (u_int64_t)vtoc_get_cyl_from_cchhb(&vlabel.vtoc) *
		info->geo.heads * info->geo.sectors +
		vtoc_get_head_from_cchhb(&vlabel.vtoc) * info->geo.sectors +
		vlabel.vtoc.b;

	/*
	 * geo.cylinders is the minimum of hw_cylinders and LV_COMPAT_CYL
	 * Actually the vtoc should be located in in the first 65k-1 tracks
	 * so this check could be even more restrictive, but it doesn't
	 * hurt the way it is. Linux cdl format restricts the vtoc to
	 * the first two tracks anyway.
	 */
	maxblk = info->geo.cylinders * info->geo.heads * info->geo.sectors;

	if ((vtocblk <= 0) || (vtocblk > maxblk)) {
		zt_error_print("dasdview: VTOC error\n"
			       "Volume label VTOC pointer is not valid!\n");
		exit(EXIT_FAILURE);
	}

	vtoc_read_label(info->device, (vtocblk - 1) * info->blksize,
			NULL, &info->f4, NULL, NULL);

	if ((info->f4.DS4KEYCD[0] != 0x04) ||
	    (info->f4.DS4KEYCD[43] != 0x04) ||
	    (info->f4.DS4IDFMT != 0xf4)) {
		/* format4 DSCB is invalid */
		zt_error_print("dasdview: VTOC error\n"
			       "Format 4 DSCB is invalid!\n");
		exit(EXIT_FAILURE);
	}

	info->f4c++;
	pos = (vtocblk - 1) * info->blksize;

	for (i = 1; i < info->geo.sectors; i++) {
		pos += info->blksize;
		vtoc_read_label(info->device, pos, &tmp, NULL, NULL, NULL);

		switch (tmp.DS1FMTID) {
		case 0xf1:
			memcpy(&info->f1[info->f1c], &tmp,
			       sizeof(format1_label_t));
			info->f1c++;
			break;
		case 0xf4:
			info->f4c++;
			break;
		case 0xf5:
			memcpy(&info->f5, &tmp, sizeof(format1_label_t));
			info->f5c++;
			break;
		case 0xf7:
			memcpy(&info->f7, &tmp, sizeof(format1_label_t));
			info->f7c++;
			break;
		case 0xf8:
			memcpy(&info->f8[info->f8c], &tmp,
			       sizeof(format1_label_t));
			info->f8c++;
			break;
		case 0xf9:
			memcpy(&info->f9[info->f9c], &tmp,
			       sizeof(format1_label_t));
			info->f9c++;
			break;
		case 0x00:
			break;
		default:
			printf("Unknown label in VTOC detected (id=%x)\n",
			       tmp.DS1FMTID);
		}
	}

	if (info->f4c > 1) {
		zt_error_print("dasdview: VTOC error\n"
			       "More than one FMT4 DSCB!\n");
		exit(EXIT_FAILURE);
	}

	if (info->f5c > 1) {
		zt_error_print("dasdview: VTOC error\n"
			       "More than one FMT5 DSCB!\n");
		exit(EXIT_FAILURE);
	}

	if (info->f7c > 1) {
		zt_error_print("dasdview: VTOC error\n"
			       "More than one FMT7 DSCB!\n");
		exit(EXIT_FAILURE);
	}
}

static void dasdview_print_format1_8_short_info(format1_label_t *f1,
						struct hd_geometry *geo)
{
	char s6[7], s13[14], s44[45];
	unsigned long track_low, track_up;

	bzero(s44, 45);
	strncpy(s44, f1->DS1DSNAM, 44);
	vtoc_ebcdic_dec(s44, s44, 44);
	bzero(s6, 7);
	strncpy(s6, (char *)f1->DS1DSSN, 6);
	vtoc_ebcdic_dec(s6, s6, 6);
	bzero(s13, 14);
	strncpy(s13, (char *)f1->DS1SYSCD, 13);
	vtoc_ebcdic_dec(s13, s13, 13);

	track_low = cchh2trk(&f1->DS1EXT1.llimit, geo);
	track_up = cchh2trk(&f1->DS1EXT1.ulimit, geo);

	printf(" | %44s |          trk |          trk |\n",
	       s44);
	printf(" | data set serial number :"
	       " '%6s'            |"
	       " %12ld | %12ld |\n", s6, track_low, track_up);
	printf(" | system code            :"
	       " '%13s'     |"
	       "      cyl/trk |      cyl/trk |\n", s13);
	printf(" | creation date          :"
	       "  year %4d, day %3d |"
	       " %8d/%3d | %8d/%3d |\n",
	       f1->DS1CREDT.year + 1900,
	       f1->DS1CREDT.day,
	       vtoc_get_cyl_from_cchh(&f1->DS1EXT1.llimit),
	       vtoc_get_head_from_cchh(&f1->DS1EXT1.llimit),
	       vtoc_get_cyl_from_cchh(&f1->DS1EXT1.ulimit),
	       vtoc_get_head_from_cchh(&f1->DS1EXT1.ulimit));
	printf(" +-----------------------------------------"
	       "-----+--------------+--------------+\n");
}

static void dasdview_print_vtoc_info(dasdview_info_t *info)
{
	int i;

	printf("--- VTOC info --------------------------------"
	       "---------------------------------\n");
	printf("The VTOC contains:\n");
	printf("  %d format 1 label(s)\n", info->f1c);
	printf("  %d format 4 label(s)\n", info->f4c);
	printf("  %d format 5 label(s)\n", info->f5c);
	printf("  %d format 7 label(s)\n", info->f7c);
	printf("  %d format 8 label(s)\n", info->f8c);
	printf("  %d format 9 label(s)\n", info->f9c);

	if ((info->f1c < 1) && (info->f8c < 1)) {
		printf("There are no partitions defined.\n");
	} else {
		printf("Other mainframe operating systems would see "
		       "the following data sets:\n");
		printf(" +----------------------------------------------+"
		       "--------------+--------------+\n");
		printf(" | data set                                     |"
		       " start        | end          |\n");
		printf(" +----------------------------------------------+"
		       "--------------+--------------+\n");

		for (i = 0; i < info->f1c; i++)
			dasdview_print_format1_8_short_info(&info->f1[i],
							    &info->geo);
		for (i = 0; i < info->f8c; i++)
			dasdview_print_format1_8_short_info(&info->f8[i],
							    &info->geo);
	}
}

static void dasdview_print_short_info_extent_raw(extent_t *ext)
{
	if (ext->typeind > 0x00)
		printf("   %3d          (%5d,%5d)        (%5d,%5d)\n",
		       ext->seqno,
		       vtoc_get_cyl_from_cchh(&ext->llimit),
		       vtoc_get_head_from_cchh(&ext->llimit),
		       vtoc_get_cyl_from_cchh(&ext->ulimit),
		       vtoc_get_head_from_cchh(&ext->ulimit));
}

static void dasdview_print_format1_8_short_info_raw(format1_label_t *f1,
						    dasdview_info_t *info)
{
	char s6[7], s13[14], s44[45];
	unsigned long long j;
	format3_label_t *f3;
	format9_label_t *f9;
	struct dscb *dscb;
	int rc;

	bzero(s44, 45);
	strncpy(s44, f1->DS1DSNAM, 44);
	vtoc_ebcdic_dec(s44, s44, 44);
	bzero(s6, 7);
	strncpy(s6, (char *)f1->DS1DSSN, 6);
	vtoc_ebcdic_dec(s6, s6, 6);
	bzero(s13, 14);
	strncpy(s13, (char *)f1->DS1SYSCD, 13);
	vtoc_ebcdic_dec(s13, s13, 13);

	printf("data set name          : '%44s'\n", s44);
	printf("data set serial number : '%6s'\n", s6);
	printf("system code            : '%13s'\n", s13);
	printf("creation date          :  year %4d, day %3d\n",
	       f1->DS1CREDT.year + 1900, f1->DS1CREDT.day);

	printf("flags                  :  ");
	if (f1->DS1FLAG1 & 0x80)
		printf("DS1COMPR ");
	if (f1->DS1FLAG1 & 0x40)
		printf("DS1CPOIT ");
	if (f1->DS1FLAG1 & 0x20)
		printf("DS1EXPBY ");
	if (f1->DS1FLAG1 & 0x10)
		printf("DS1RECAL ");
	if (f1->DS1FLAG1 & 0x08)
		printf("DS1LARGE ");
	if (f1->DS1FLAG1 & 0x04)
		printf("unknown ");
	if ((f1->DS1FLAG1 & 0x01) && (f1->DS1FLAG1 & 0x02))
		printf("DS1EATTR=not used ");
	if (!(f1->DS1FLAG1 & 0x01) && (f1->DS1FLAG1 & 0x02))
		printf("DS1EATTR=optional ");
	if ((f1->DS1FLAG1 & 0x01) && !(f1->DS1FLAG1 & 0x02))
		printf("DS1EATTR=no ");
	if (f1->DS1FLAG1 & 0x00)
		printf("DS1EATTR=default ");
	printf("\n");

	printf("SMS flags              :  ");
	if (f1->DS1SMSFG & 0x80)
		printf("DS1SMSDS ");
	if (f1->DS1SMSFG & 0x40)
		printf("DS1SMSUC ");
	if (f1->DS1SMSFG & 0x20)
		printf("DS1REBLK ");
	if (f1->DS1SMSFG & 0x10)
		printf("DS1CRSDB ");
	if (f1->DS1SMSFG & 0x08)
		printf("DS1PDSE ");
	if (f1->DS1SMSFG & 0x04)
		printf("DS1STRP ");
	if (f1->DS1SMSFG & 0x02)
		printf("DS1PDSEX ");
	if (f1->DS1SMSFG & 0x01)
		printf("DS1DSAE ");
	printf("\n");

	printf("organisation           :  ");
	if (f1->DS1DSRG1 & 0x80)
		printf("DS1DSGIS ");
	if (f1->DS1DSRG1 & 0x40)
		printf("DS1DSGPS ");
	if (f1->DS1DSRG1 & 0x20)
		printf("DS1DSGDA ");
	if (f1->DS1DSRG1 & 0x10)
		printf("DS1DSGCX ");
	if (f1->DS1DSRG1 & 0x08)
		printf("reserved ");
	if (f1->DS1DSRG1 & 0x04)
		printf("reserved ");
	if (f1->DS1DSRG1 & 0x02)
		printf("DS1DSGPO ");
	if (f1->DS1DSRG1 & 0x01)
		printf("DS1DSGU ");
	if (f1->DS1DSRG2 & 0x80)
		printf("DS1DSGGS ");
	if (f1->DS1DSRG2 & 0x40)
		printf("DS1DSGTX ");
	if (f1->DS1DSRG2 & 0x20)
		printf("DS1DSGTQ ");
	if (f1->DS1DSRG2 & 0x10)
		printf("reserved ");
	if (f1->DS1DSRG2 & 0x08)
		printf("DS1ACBM ");
	if (f1->DS1DSRG2 & 0x04)
		printf("DS1DSGTR ");
	if (f1->DS1DSRG2 & 0x02)
		printf("reserved ");
	if (f1->DS1DSRG2 & 0x01)
		printf("reserved");
	printf("\n");

	printf("record format          :  ");
	if ((f1->DS1RECFM & 0x80) && !(f1->DS1RECFM & 0x40))
		printf("DS1RECFF ");
	if (!(f1->DS1RECFM & 0x80) && (f1->DS1RECFM & 0x40))
		printf("DS1RECFV ");
	if ((f1->DS1RECFM & 0x80) && (f1->DS1RECFM & 0x40))
		printf("DS1RECFU ");
	if (f1->DS1RECFM & 0x20)
		printf("DS1RECFT ");
	if (f1->DS1RECFM & 0x10)
		printf("DS1RECFB ");
	if (f1->DS1RECFM & 0x08)
		printf("DS1RECFS ");
	if (f1->DS1RECFM & 0x04)
		printf("DS1RECFA ");
	if (f1->DS1RECFM & 0x02)
		printf("DS1RECMC ");
	if (f1->DS1RECFM & 0x01)
		printf("reserved");
	printf("\n");

	printf("(max) block length     :  %u\n", f1->DS1BLKL);
	printf("logical record length  :  %u\n", f1->DS1LRECL);

	printf("extents belonging to this dataset:\n");
	printf("  seqno        llimit (cyl, trk)    ulimit (cyl, trk)\n");

	/* The format 1 label can point to a chain of f3 labels
	 * The format 8 label points to a (chain of) f9 labels
	 * The format 9 label may contain several format 3 labels, but as
	 * far as I know, it is still OK to follow the 'next dscb' chain.
	 * So for a format 9 label I have to follow this chain until I
	 * find the first format 3 dscb and then I can follow the format 3
	 * dscbs to the end of the chain.
	 */
	rc = lzds_raw_vtoc_get_dscb_from_cchhb(info->rawvtoc, &f1->DS1PTRDS,
					       &dscb);
	/* The first f9 label contains extra data that we may want to print here
	 */
	while (!rc && dscb && dscb->fmtid == 0xf9) {
		f9 = (format9_label_t *)dscb;
		rc = lzds_raw_vtoc_get_dscb_from_cchhb(info->rawvtoc,
						       &f9->DS9PTRDS, &dscb);
	}
	if (rc) {
		zt_error_print("dasdview: Broken format 3 DSCB chain \n");
		exit(EXIT_FAILURE);
	}
	f3 = (dscb && dscb->fmtid == 0xf3) ? (format3_label_t *)dscb : NULL;

	/* first print the extents that are part of the f1/f8 label itself */
	dasdview_print_short_info_extent_raw(&f1->DS1EXT1);
	dasdview_print_short_info_extent_raw(&f1->DS1EXT2);
	dasdview_print_short_info_extent_raw(&f1->DS1EXT3);

	/* now follow the f3 chain into the rabbit hole */
	while (f3) {
		/* sanity check */
		if (f3->DS3FMTID != 0xf3) {
			zt_error_print("dasdview: Broken format 3 DSCB"
				       " chain \n");
			exit(EXIT_FAILURE);
		}
		for (j = 0; j < 4; ++j)
			dasdview_print_short_info_extent_raw(&f3->DS3EXTNT[j]);
		for (j = 0; j < 9; ++j)
			dasdview_print_short_info_extent_raw(&f3->DS3ADEXT[j]);
		rc = lzds_raw_vtoc_get_dscb_from_cchhb(info->rawvtoc,
						       &f3->DS3PTRDS,
						       (struct dscb **)&f3);
		if (rc) {
			zt_error_print("dasdview: Broken format 3 DSCB"
				       " chain \n");
			exit(EXIT_FAILURE);
		}
	}
	printf("\n");
}

static void dasdview_print_vtoc_info_raw(dasdview_info_t *info)
{
	struct dscbiterator *it;
	struct dscb *dscb;
	int rc;
	int f1c, f3c, f4c, f5c, f7c, f8c, f9c;

	f1c = 0;
	f3c = 0;
	f4c = 0;
	f5c = 0;
	f7c = 0;
	f8c = 0;
	f9c = 0;
	rc = lzds_raw_vtoc_alloc_dscbiterator(info->rawvtoc, &it);
	if (rc) {
		zt_error_print("dasdview: could not allocate DSCB iterator \n");
		exit(EXIT_FAILURE);
	}
	while (!lzds_dscbiterator_get_next_dscb(it, &dscb)) {
		if (dscb->fmtid == 0xf1)
			++f1c;
		else if (dscb->fmtid == 0xf3)
			++f3c;
		else if (dscb->fmtid == 0xf4)
			++f4c;
		else if (dscb->fmtid == 0xf5)
			++f5c;
		else if (dscb->fmtid == 0xf7)
			++f7c;
		else if (dscb->fmtid == 0xf8)
			++f8c;
		else if (dscb->fmtid == 0xf9)
			++f9c;
	}
	lzds_dscbiterator_free(it);
	printf("--- VTOC info --------------------------------"
	       "---------------------------------\n");
	printf("The VTOC contains:\n");
	printf("  %d format 1 label(s)\n", f1c);
	printf("  %d format 3 label(s)\n", f3c);
	printf("  %d format 4 label(s)\n", f4c);
	printf("  %d format 5 label(s)\n", f5c);
	printf("  %d format 7 label(s)\n", f7c);
	printf("  %d format 8 label(s)\n", f8c);
	printf("  %d format 9 label(s)\n", f9c);

	rc = lzds_raw_vtoc_alloc_dscbiterator(info->rawvtoc, &it);
	if (rc) {
		zt_error_print("dasdview: could not allocate DSCB iterator \n");
		exit(EXIT_FAILURE);
	}
	while (!lzds_dscbiterator_get_next_dscb(it, &dscb)) {
		if (dscb->fmtid == 0xf1 || dscb->fmtid == 0xf8)
			dasdview_print_format1_8_short_info_raw(
				(format1_label_t *)dscb, info);
	}
	lzds_dscbiterator_free(it);
}

/*
 * Note: the explicit cylinder/head conversion for large volume
 * adresses should not be necessary for entries that point to
 * vtoc labels, as those must be located in the first 65K-1 tracks,
 * but we do it anyway to be on the safe side.
 */
static void dasdview_print_format1_8_no_head(format1_label_t *f1)
{
	char s6[7], s13[14], s44[45];
	int i;

	bzero(s6, 7);
	bzero(s13, 14);
	bzero(s44, 45);

	strncpy(s44, f1->DS1DSNAM, 44);
	printf("DS1DSNAM    : ascii  '%44s'\n", s44);
	vtoc_ebcdic_dec(s44, s44, 44);
	printf("              ebcdic '%44s'\n", s44);
	printf("DS1FMTID    : dec %d, hex %02x\n",
	       f1->DS1FMTID, f1->DS1FMTID);
	printf("DS1DSSN     : hex    ");
	for (i = 0; i < 6; i++)
		printf("%02x", f1->DS1DSSN[i]);
	strncpy(s6, (char *)f1->DS1DSSN, 6);
	printf("\n              ascii  '%6s'\n", s6);
	vtoc_ebcdic_dec(s6, s6, 6);
	printf("              ebcdic '%6s'\n", s6);
	printf("DS1VOLSQ    : dec %d, hex %04x\n",
	       f1->DS1VOLSQ, f1->DS1VOLSQ);
	printf("DS1CREDT    : hex %02x%04x "
	       "(year %d, day %d)\n",
	       f1->DS1CREDT.year, f1->DS1CREDT.day,
	       f1->DS1CREDT.year + 1900,
	       f1->DS1CREDT.day);
	printf("DS1EXPDT    : hex %02x%04x "
	       "(year %d, day %d)\n",
	       f1->DS1EXPDT.year, f1->DS1EXPDT.day,
	       f1->DS1EXPDT.year + 1900,
	       f1->DS1EXPDT.day);
	printf("DS1NOEPV    : dec %d, hex %02x\n",
	       f1->DS1NOEPV, f1->DS1NOEPV);
	printf("DS1NOBDB    : dec %d, hex %02x\n",
	       f1->DS1NOBDB, f1->DS1NOBDB);
	printf("DS1FLAG1    : dec %d, hex %02x\n",
	       f1->DS1FLAG1, f1->DS1FLAG1);
	printf("DS1SYSCD    : hex    ");
	for (i = 0; i < 13; i++)
		printf("%02x", f1->DS1SYSCD[i]);
	strncpy(s13, (char *)f1->DS1SYSCD, 13);
	printf("\n              ascii  '%13s'\n", s13);
	vtoc_ebcdic_dec(s13, s13, 13);
	printf("              ebcdic '%13s'\n", s13);
	printf("DS1REFD     : hex %02x%04x "
	       "(year %d, day %d)\n",
	       f1->DS1REFD.year, f1->DS1REFD.day,
	       f1->DS1REFD.year + 1900,
	       f1->DS1REFD.day);
	printf("DS1SMSFG    : dec %d, hex %02x\n",
	       f1->DS1SMSFG, f1->DS1SMSFG);
	printf("DS1SCXTF    : dec %d, hex %02x\n",
	       f1->DS1SCXTF, f1->DS1SCXTF);
	printf("DS1SCXTV    : dec %d, hex %04x\n",
	       f1->DS1SCXTV, f1->DS1SCXTV);
	printf("DS1DSRG1    : dec %d, hex %02x\n",
	       f1->DS1DSRG1, f1->DS1DSRG1);
	printf("DS1DSRG2    : dec %d, hex %02x\n",
	       f1->DS1DSRG2, f1->DS1DSRG2);
	printf("DS1RECFM    : dec %d, hex %02x\n",
	       f1->DS1RECFM, f1->DS1RECFM);
	printf("DS1OPTCD    : dec %d, hex %02x\n",
	       f1->DS1OPTCD, f1->DS1OPTCD);
	printf("DS1BLKL     : dec %d, hex %04x\n",
	       f1->DS1BLKL, f1->DS1BLKL);
	printf("DS1LRECL    : dec %d, hex %04x\n",
	       f1->DS1LRECL, f1->DS1LRECL);
	printf("DS1KEYL     : dec %d, hex %02x\n",
	       f1->DS1KEYL, f1->DS1KEYL);
	printf("DS1RKP      : dec %d, hex %04x\n",
	       f1->DS1RKP, f1->DS1RKP);
	printf("DS1DSIND    : dec %d, hex %02x\n",
	       f1->DS1DSIND, f1->DS1DSIND);
	printf("DS1SCAL1    : dec %d, hex %02x\n",
	       f1->DS1SCAL1, f1->DS1SCAL1);
	printf("DS1SCAL3    : hex ");
	for (i = 0; i < 3; i++)
		printf("%02x", f1->DS1SCAL3[i]);
	printf("\nDS1LSTAR    : hex %04x%02x "
	       "(trk %d, blk %d)\n",
	       f1->DS1LSTAR.tt, f1->DS1LSTAR.r,
	       f1->DS1LSTAR.tt, f1->DS1LSTAR.r);
	printf("DS1TRBAL    : dec %d, hex %04x\n",
	       f1->DS1TRBAL, f1->DS1TRBAL);
	printf("reserved    : dec %d, hex %04x\n",
	       f1->res1, f1->res1);
	printf("DS1EXT1     : hex %02x%02x%04x%04x%04x%04x\n",
	       f1->DS1EXT1.typeind,
	       f1->DS1EXT1.seqno,
	       f1->DS1EXT1.llimit.cc,
	       f1->DS1EXT1.llimit.hh,
	       f1->DS1EXT1.ulimit.cc,
	       f1->DS1EXT1.ulimit.hh);
	printf("              typeind    : dec %d, hex %02x\n",
	       f1->DS1EXT1.typeind,
	       f1->DS1EXT1.typeind);
	printf("              seqno      : dec %d, hex %02x\n",
	       f1->DS1EXT1.seqno, f1->DS1EXT1.seqno);
	printf("              llimit     : hex %04x%04x "
	       "(cyl %d, trk %d)\n",
	       f1->DS1EXT1.llimit.cc,
	       f1->DS1EXT1.llimit.hh,
	       vtoc_get_cyl_from_cchh(&f1->DS1EXT1.llimit),
	       vtoc_get_head_from_cchh(&f1->DS1EXT1.llimit));
	printf("              ulimit     : hex %04x%04x "
	       "(cyl %d, trk %d)\n",
	       f1->DS1EXT1.ulimit.cc,
	       f1->DS1EXT1.ulimit.hh,
	       vtoc_get_cyl_from_cchh(&f1->DS1EXT1.ulimit),
	       vtoc_get_head_from_cchh(&f1->DS1EXT1.ulimit));
	printf("DS1EXT2     : hex %02x%02x%04x%04x%04x%04x\n",
	       f1->DS1EXT2.typeind,
	       f1->DS1EXT2.seqno,
	       f1->DS1EXT2.llimit.cc,
	       f1->DS1EXT2.llimit.hh,
	       f1->DS1EXT2.ulimit.cc,
	       f1->DS1EXT2.ulimit.hh);
	printf("              typeind    : dec %d, hex %02x\n",
	       f1->DS1EXT2.typeind,
	       f1->DS1EXT2.typeind);
	printf("              seqno      : dec %d, hex %02x\n",
	       f1->DS1EXT2.seqno, f1->DS1EXT2.seqno);
	printf("              llimit     : hex %04x%04x "
	       "(cyl %d, trk %d)\n",
	       f1->DS1EXT2.llimit.cc,
	       f1->DS1EXT2.llimit.hh,
	       vtoc_get_cyl_from_cchh(&f1->DS1EXT2.llimit),
	       vtoc_get_head_from_cchh(&f1->DS1EXT2.llimit));
	printf("              ulimit     : hex %04x%04x "
	       "(cyl %d, trk %d)\n",
	       f1->DS1EXT2.ulimit.cc,
	       f1->DS1EXT2.ulimit.hh,
	       vtoc_get_cyl_from_cchh(&f1->DS1EXT2.ulimit),
	       vtoc_get_head_from_cchh(&f1->DS1EXT2.ulimit));
	printf("DS1EXT3     : hex %02x%02x%04x%04x%04x%04x\n",
	       f1->DS1EXT3.typeind,
	       f1->DS1EXT3.seqno,
	       f1->DS1EXT3.llimit.cc,
	       f1->DS1EXT3.llimit.hh,
	       f1->DS1EXT3.ulimit.cc,
	       f1->DS1EXT3.ulimit.hh);
	printf("              typeind    : dec %d, hex %02x\n",
	       f1->DS1EXT3.typeind,
	       f1->DS1EXT3.typeind);
	printf("              seqno      : dec %d, hex %02x\n",
	       f1->DS1EXT3.seqno, f1->DS1EXT3.seqno);
	printf("              llimit     : hex %04x%04x "
	       "(cyl %d, trk %d)\n",
	       f1->DS1EXT3.llimit.cc,
	       f1->DS1EXT3.llimit.hh,
	       vtoc_get_cyl_from_cchh(&f1->DS1EXT3.llimit),
	       vtoc_get_head_from_cchh(&f1->DS1EXT3.llimit));
	printf("              ulimit     : hex %04x%04x "
	       "(cyl %d, trk %d)\n",
	       f1->DS1EXT3.ulimit.cc,
	       f1->DS1EXT3.ulimit.hh,
	       vtoc_get_cyl_from_cchh(&f1->DS1EXT3.ulimit),
	       vtoc_get_head_from_cchh(&f1->DS1EXT3.ulimit));
	printf("DS1PTRDS    : %04x%04x%02x "
	       "(cyl %d, trk %d, blk %d)\n",
	       f1->DS1PTRDS.cc, f1->DS1PTRDS.hh,
	       f1->DS1PTRDS.b,
	       vtoc_get_cyl_from_cchhb(&f1->DS1PTRDS),
	       vtoc_get_head_from_cchhb(&f1->DS1PTRDS),
	       f1->DS1PTRDS.b);
}

static void dasdview_print_vtoc_f1_raw(format1_label_t *f1)
{
	printf("\n--- VTOC format 1 label -----------------------"
	       "---------------------------------\n");
	dasdview_print_format1_8_no_head(f1);
}

/* Note: A format 8 label uses the same type as format 1 */
static void dasdview_print_vtoc_f8_raw(format1_label_t *f8)
{
	printf("\n--- VTOC format 8 label -----------------------"
	       "---------------------------------\n");
	dasdview_print_format1_8_no_head(f8);
}

static void dasdview_print_extent(extent_t *ext, char *name, int index)
{
	printf("%s[%d] : hex %02x%02x%04x%04x%04x%04x\n",
	       name,
	       index,
	       ext->typeind,
	       ext->seqno,
	       ext->llimit.cc,
	       ext->llimit.hh,
	       ext->ulimit.cc,
	       ext->ulimit.hh);
	printf("              typeind    : dec %d, hex %02x\n",
	       ext->typeind,
	       ext->typeind);
	printf("              seqno      : dec %d, hex %02x\n",
	       ext->seqno, ext->seqno);
	printf("              llimit     : hex %04x%04x "
	       "(cyl %d, trk %d)\n",
	       ext->llimit.cc,
	       ext->llimit.hh,
	       vtoc_get_cyl_from_cchh(&ext->llimit),
	       vtoc_get_head_from_cchh(&ext->llimit));
	printf("              ulimit     : hex %04x%04x "
	       "(cyl %d, trk %d)\n",
	       ext->ulimit.cc,
	       ext->ulimit.hh,
	       vtoc_get_cyl_from_cchh(&ext->ulimit),
	       vtoc_get_head_from_cchh(&ext->ulimit));
}

static void dasdview_print_vtoc_f3_raw(format3_label_t *f3)
{
	int i;

	printf("\n--- VTOC format 3 label ----------------------"
	       "---------------------------------\n");

	printf("DS3KEYID    : ");
	for (i = 0; i < 4; i++)
		printf("%02x", f3->DS3KEYID[i]);
	printf("\n");

	for (i = 0; i < 4; ++i)
		dasdview_print_extent(&f3->DS3EXTNT[i], "DS3EXTNT", i);

	printf("DS3FMTID    : dec %d, hex %02x\n",
	       f3->DS3FMTID, f3->DS3FMTID);

	for (i = 0; i < 9; ++i)
		dasdview_print_extent(&f3->DS3ADEXT[i], "DS3ADEXT", i);

	printf("DS3PTRDS    : %04x%04x%02x "
	       "(cyl %d, trk %d, blk %d)\n",
	       f3->DS3PTRDS.cc, f3->DS3PTRDS.hh,
	       f3->DS3PTRDS.b,
	       vtoc_get_cyl_from_cchhb(&f3->DS3PTRDS),
	       vtoc_get_head_from_cchhb(&f3->DS3PTRDS),
	       f3->DS3PTRDS.b);
}

static void dasdview_print_vtoc_f4_raw(format4_label_t *f4)
{
	int i;

	printf("\n--- VTOC format 4 label ----------------------"
	       "---------------------------------\n");

	printf("DS4KEYCD    : ");
	for (i = 0; i < 44; i++)
		printf("%02x", f4->DS4KEYCD[i]);
	printf("\nDS4IDFMT    : dec %d, hex %02x\n",
	       f4->DS4IDFMT, f4->DS4IDFMT);
	printf("DS4HPCHR    : %04x%04x%02x "
	       "(cyl %d, trk %d, blk %d)\n",
	       f4->DS4HPCHR.cc, f4->DS4HPCHR.hh,
	       f4->DS4HPCHR.b,
	       vtoc_get_cyl_from_cchhb(&f4->DS4HPCHR),
	       vtoc_get_head_from_cchhb(&f4->DS4HPCHR),
	       f4->DS4HPCHR.b);
	printf("DS4DSREC    : dec %d, hex %04x\n",
	       f4->DS4DSREC, f4->DS4DSREC);
	printf("DS4HCCHH    : %04x%04x (cyl %d, trk %d)\n",
	       f4->DS4HCCHH.cc, f4->DS4HCCHH.hh,
	       vtoc_get_cyl_from_cchh(&f4->DS4HCCHH),
	       vtoc_get_head_from_cchh(&f4->DS4HCCHH));
	printf("DS4NOATK    : dec %d, hex %04x\n",
	       f4->DS4NOATK, f4->DS4NOATK);
	printf("DS4VTOCI    : dec %d, hex %02x\n",
	       f4->DS4VTOCI, f4->DS4VTOCI);
	printf("DS4NOEXT    : dec %d, hex %02x\n",
	       f4->DS4NOEXT, f4->DS4NOEXT);
	printf("DS4SMSFG    : dec %d, hex %02x\n",
	       f4->DS4SMSFG, f4->DS4SMSFG);
	printf("DS4DEVAC    : dec %d, hex %02x\n",
	       f4->DS4DEVAC, f4->DS4DEVAC);
	printf("DS4DSCYL    : dec %d, hex %04x\n",
	       f4->DS4DEVCT.DS4DSCYL, f4->DS4DEVCT.DS4DSCYL);
	printf("DS4DSTRK    : dec %d, hex %04x\n",
	       f4->DS4DEVCT.DS4DSTRK, f4->DS4DEVCT.DS4DSTRK);
	printf("DS4DEVTK    : dec %d, hex %04x\n",
	       f4->DS4DEVCT.DS4DEVTK, f4->DS4DEVCT.DS4DEVTK);
	printf("DS4DEVI     : dec %d, hex %02x\n",
	       f4->DS4DEVCT.DS4DEVI, f4->DS4DEVCT.DS4DEVI);
	printf("DS4DEVL     : dec %d, hex %02x\n",
	       f4->DS4DEVCT.DS4DEVL, f4->DS4DEVCT.DS4DEVL);
	printf("DS4DEVK     : dec %d, hex %02x\n",
	       f4->DS4DEVCT.DS4DEVK, f4->DS4DEVCT.DS4DEVK);
	printf("DS4DEVFG    : dec %d, hex %02x\n",
	       f4->DS4DEVCT.DS4DEVFG, f4->DS4DEVCT.DS4DEVFG);
	printf("DS4DEVTL    : dec %d, hex %04x\n",
	       f4->DS4DEVCT.DS4DEVTL, f4->DS4DEVCT.DS4DEVTL);
	printf("DS4DEVDT    : dec %d, hex %02x\n",
	       f4->DS4DEVCT.DS4DEVDT, f4->DS4DEVCT.DS4DEVDT);
	printf("DS4DEVDB    : dec %d, hex %02x\n",
	       f4->DS4DEVCT.DS4DEVDB, f4->DS4DEVCT.DS4DEVDB);
	printf("DS4AMTIM    : hex ");
	for (i = 0; i < 8; i++)
		printf("%02x", f4->DS4AMTIM[i]);
	printf("\nDS4AMCAT    : hex ");
	for (i = 0; i < 3; i++)
		printf("%02x", f4->DS4AMCAT[i]);
	printf("\nDS4R2TIM    : hex ");
	for (i = 0; i < 8; i++)
		printf("%02x", f4->DS4R2TIM[i]);
	printf("\nres1        : hex ");
	for (i = 0; i < 5; i++)
		printf("%02x", f4->res1[i]);
	printf("\nDS4F6PTR    : hex ");
	for (i = 0; i < 5; i++)
		printf("%02x", f4->DS4F6PTR[i]);
	printf("\nDS4VTOCE    : hex %02x%02x%04x%04x%04x%04x\n",
	       f4->DS4VTOCE.typeind, f4->DS4VTOCE.seqno,
	       f4->DS4VTOCE.llimit.cc, f4->DS4VTOCE.llimit.hh,
	       f4->DS4VTOCE.ulimit.cc, f4->DS4VTOCE.ulimit.hh);
	printf("              typeind    : dec %d, hex %02x\n",
	       f4->DS4VTOCE.typeind, f4->DS4VTOCE.typeind);
	printf("              seqno      : dec %d, hex %02x\n",
	       f4->DS4VTOCE.seqno, f4->DS4VTOCE.seqno);
	printf("              llimit     : hex %04x%04x (cyl %d, trk %d)\n",
	       f4->DS4VTOCE.llimit.cc, f4->DS4VTOCE.llimit.hh,
	       vtoc_get_cyl_from_cchh(&f4->DS4VTOCE.llimit),
	       vtoc_get_head_from_cchh(&f4->DS4VTOCE.llimit));
	printf("              ulimit     : hex %04x%04x (cyl %d, trk %d)\n",
	       f4->DS4VTOCE.ulimit.cc, f4->DS4VTOCE.ulimit.hh,
	       vtoc_get_cyl_from_cchh(&f4->DS4VTOCE.ulimit),
	       vtoc_get_head_from_cchh(&f4->DS4VTOCE.ulimit));
	printf("res2        : hex ");
	for (i = 0; i < 10; i++)
		printf("%02x", f4->res2[i]);
	printf("\nDS4EFLVL    : dec %d, hex %02x\n",
	       f4->DS4EFLVL, f4->DS4EFLVL);
	printf("DS4EFPTR    : hex %04x%04x%02x "
	       "(cyl %d, trk %d, blk %d)\n",
	       f4->DS4EFPTR.cc, f4->DS4EFPTR.hh,
	       f4->DS4EFPTR.b,
	       vtoc_get_cyl_from_cchhb(&f4->DS4EFPTR),
	       vtoc_get_head_from_cchhb(&f4->DS4EFPTR),
	       f4->DS4EFPTR.b);
	printf("res3        : hex %02x\n", f4->res3);
	printf("DS4DCYL     : dec %d, hex %08x\n",
	       f4->DS4DCYL, f4->DS4DCYL);
	printf("res4        : hex ");
	for (i = 0; i < 2; i++)
		printf("%02x", f4->res4[i]);
	printf("\nDS4DEVF2    : dec %d, hex %02x\n",
	       f4->DS4DEVF2, f4->DS4DEVF2);
	printf("res5        : hex %02x\n", f4->res5);
}

static void dasdview_print_vtoc_f5_raw(format5_label_t *f5)
{
	int i;

	printf("\n--- VTOC format 5 label ----------------------"
	       "---------------------------------\n");

	printf("key identifier\n        DS5KEYID    : ");
	for (i = 0; i < 4; i++)
		printf("%02x", f5->DS5KEYID[i]);
	printf("\nfirst extent description\n");
	printf("        DS5AVEXT    : %04x%04x%02x "
	       "(start trk: %d, length: %d cyl, %d trk)\n",
	       f5->DS5AVEXT.t,  f5->DS5AVEXT.fc,
	       f5->DS5AVEXT.ft, f5->DS5AVEXT.t,
	       f5->DS5AVEXT.fc, f5->DS5AVEXT.ft);
	printf("next 7 extent descriptions\n");
	for (i = 0; i < 7; i++) {
		printf("        DS5EXTAV[%d] : %04x%04x%02x "
		       "(start trk: %d, length: %d cyl, %d trk)\n", i + 2,
		       f5->DS5EXTAV[i].t,  f5->DS5EXTAV[i].fc,
		       f5->DS5EXTAV[i].ft, f5->DS5EXTAV[i].t,
		       f5->DS5EXTAV[i].fc, f5->DS5EXTAV[i].ft);
	}
	printf("format identifier\n"
	       "        DS5FMTID    : dec %d, hex %02x\n",
	       f5->DS5FMTID, f5->DS5FMTID);
	printf("next 18 extent descriptions\n");
	for (i = 0; i < 18; i++) {
		printf("        DS5MAVET[%d] : %04x%04x%02x "
		       "(start trk: %d, length: %d cyl, %d trk)\n", i + 9,
		       f5->DS5MAVET[i].t,  f5->DS5MAVET[i].fc,
		       f5->DS5MAVET[i].ft, f5->DS5MAVET[i].t,
		       f5->DS5MAVET[i].fc, f5->DS5MAVET[i].ft);
	}
	printf("pointer to next format 5 label\n"
	       "        DS5PTRDS    : %04x%04x%02x "
	       "(cyl %d, trk %d, blk %d)\n",
	       f5->DS5PTRDS.cc, f5->DS5PTRDS.hh,
	       f5->DS5PTRDS.b,
	       vtoc_get_cyl_from_cchhb(&f5->DS5PTRDS),
	       vtoc_get_head_from_cchhb(&f5->DS5PTRDS),
	       f5->DS5PTRDS.b);
}

static void dasdview_print_vtoc_f7_raw(format7_label_t *f7)
{
	int i;

	printf("\n--- VTOC format 7 label ----------------------"
	       "---------------------------------\n");

	printf("key identifier\n        DS7KEYID    : ");
	for (i = 0; i < 4; i++)
		printf("%02x", f7->DS7KEYID[i]);
	printf("\nfirst 5 extent descriptions\n");
	for (i = 0; i < 5; i++) {
		printf("        DS7EXTNT[%d] : %08x %08x "
		       "(start trk %d, end trk %d)\n", i + 1,
		       f7->DS7EXTNT[i].a, f7->DS7EXTNT[i].b,
		       f7->DS7EXTNT[i].a, f7->DS7EXTNT[i].b);
	}
	printf("format identifier\n"
	       "        DS7FMTID    : dec %d, hex %02x\n",
	       f7->DS7FMTID, f7->DS7FMTID);
	printf("next 11 extent descriptions\n");
	for (i = 0; i < 11; i++) {
		printf("        DS7ADEXT[%d] : %08x %08x "
		       "(start trk %d, end trk %d)\n", i + 6,
		       f7->DS7ADEXT[i].a, f7->DS7ADEXT[i].b,
		       f7->DS7ADEXT[i].a, f7->DS7ADEXT[i].b);
	}
	printf("reserved field\n        res1        : ");
	for (i = 0; i < 2; i++)
		printf("%02x", f7->res1[i]);
	printf("\npointer to next format 7 label\n"
	       "        DS7PTRDS    : %04x%04x%02x "
	       "(cyl %d, trk %d, blk %d)\n",
	       f7->DS7PTRDS.cc, f7->DS7PTRDS.hh,
	       f7->DS7PTRDS.b,
	       vtoc_get_cyl_from_cchhb(&f7->DS7PTRDS),
	       vtoc_get_head_from_cchhb(&f7->DS7PTRDS),
	       f7->DS7PTRDS.b);
}

static void dasdview_print_vtoc_f9_nohead(format9_label_t *f9)
{
	unsigned int i;

	printf("DS9KEYID    : dec %d, hex %02x\n",
	       f9->DS9KEYID, f9->DS9KEYID);
	printf("DS9SUBTY    : dec %d, hex %02x\n",
	       f9->DS9SUBTY, f9->DS9SUBTY);
	printf("DS9NUMF9    : dec %d, hex %02x\n",
	       f9->DS9NUMF9, f9->DS9NUMF9);

	printf("res1        : hex ");
	for (i = 0; i < sizeof(f9->res1); i++) {
		if ((i > 0) && (i % 16 == 0))
			printf("\n                  ");
		printf("%02x", f9->res1[i]);
		if ((i + 9) % 16 == 0)
			printf(" ");
	}
	printf("\n");

	printf("DS9FMTID    : dec %d, hex %02x\n",
	       f9->DS9FMTID, f9->DS9FMTID);

	printf("res2        : hex ");
	for (i = 0; i < sizeof(f9->res2); i++) {
		if ((i > 0) && (i % 16 == 0))
			printf("\n                  ");
		printf("%02x", f9->res2[i]);
		if ((i + 9) % 16 == 0)
			printf(" ");
	}
	printf("\n");
	printf("pointer to next format 9 label\n"
	       "        DS9PTRDS    : %04x%04x%02x "
	       "(cyl %d, trk %d, blk %d)\n",
	       f9->DS9PTRDS.cc, f9->DS9PTRDS.hh,
	       f9->DS9PTRDS.b,
	       vtoc_get_cyl_from_cchhb(&f9->DS9PTRDS),
	       vtoc_get_head_from_cchhb(&f9->DS9PTRDS),
	       f9->DS9PTRDS.b);
}

static void dasdview_print_vtoc_f9_raw(format9_label_t *f9)
{
	printf("\n--- VTOC format 9 label ----------------------"
	       "---------------------------------\n");
	dasdview_print_vtoc_f9_nohead(f9);
}

static void dasdview_print_vtoc_dscb(dasdview_info_t *info, void *dscb)
{
	format1_label_t *tmp = dscb;

	switch (tmp->DS1FMTID) {
	case 0x00:
		break;
	case 0xf1:
		if (info->vtoc_f1 || info->vtoc_all)
			dasdview_print_vtoc_f1_raw(dscb);
		break;
	case 0xf3:
		if (info->vtoc_f3 || info->vtoc_all)
			dasdview_print_vtoc_f3_raw(dscb);
		break;
	case 0xf4:
		if (info->vtoc_f4 || info->vtoc_all)
			dasdview_print_vtoc_f4_raw(dscb);
		break;
	case 0xf5:
		if (info->vtoc_f5 || info->vtoc_all)
			dasdview_print_vtoc_f5_raw(dscb);
		break;
	case 0xf7:
		if (info->vtoc_f7 || info->vtoc_all)
			dasdview_print_vtoc_f7_raw(dscb);
		break;
	case 0xf8:
		if (info->vtoc_f8 || info->vtoc_all)
			dasdview_print_vtoc_f8_raw(dscb);
		break;
	case 0xf9:
		if (info->vtoc_f9 || info->vtoc_all)
			dasdview_print_vtoc_f9_raw(dscb);
		break;
	default:
		printf("unrecognized DSCB of type: %x \n\n", tmp->DS1FMTID);
		break;
	}
}

static void dasdview_print_vtoc_f1(dasdview_info_t *info)
{
	int j;

	printf("--- VTOC format 1 labels ----------------------"
	       "---------------------------------\n");

	if (info->f1c < 1) {
		printf("This VTOC doesn't contain a format 1 label.\n");
		return;
	}

	for (j = 0; j < info->f1c; j++) {
		printf("\n--- format 1 DSCB number %d ---\n", j + 1);
		dasdview_print_format1_8_no_head(&info->f1[j]);
	}
}

static void dasdview_print_vtoc_f8(dasdview_info_t *info)
{
	int j;

	printf("--- VTOC format 8 labels ----------------------"
	       "---------------------------------\n");

	if (info->f8c < 1) {
		printf("This VTOC doesn't contain a format 8 label.\n");
		return;
	}

	for (j = 0; j < info->f8c; j++) {
		printf("\n--- format 8 DSCB number %d ---\n", j + 1);
		dasdview_print_format1_8_no_head(&info->f8[j]);
	}
}

static void dasdview_print_vtoc_f4(dasdview_info_t *info)
{
	if (info->f4c < 1) {
		printf("\n--- VTOC format 4 label ----------------------"
		       "---------------------------------\n");
		printf("This VTOC doesn't contain a format 4 label.\n");
		return;
	}
	dasdview_print_vtoc_f4_raw(&info->f4);
}

static void dasdview_print_vtoc_f5(dasdview_info_t *info)
{
	if (info->f5c < 1) {
		printf("\n--- VTOC format 5 label ----------------------"
		       "---------------------------------\n");
		printf("This VTOC doesn't contain a format 5 label.\n");
		return;
	}
	dasdview_print_vtoc_f5_raw(&info->f5);
}

static void dasdview_print_vtoc_f7(dasdview_info_t *info)
{
	if (info->f7c < 1) {
		printf("\n--- VTOC format 7 label ----------------------"
		       "---------------------------------\n");
		printf("This VTOC doesn't contain a format 7 label.\n");
		return;
	}
	dasdview_print_vtoc_f7_raw(&info->f7);
}

static void dasdview_print_vtoc_f9(dasdview_info_t *info)
{
	int j;

	printf("\n--- VTOC format 9 label ----------------------"
	       "---------------------------------\n");
	if (info->f9c < 1) {
		printf("This VTOC doesn't contain a format 9 label.\n");
		return;
	}
	for (j = 0; j < info->f9c; j++) {
		printf("\n--- format 9 DSCB number %d ---\n", j + 1);
		dasdview_print_vtoc_f9_nohead(&info->f9[j]);
	}
}

static void dasdview_print_vtoc_f3(void)
{
	/* dasdfmt formatted DASD devices have no format3 labels, but since the
	 *  option exists for raw DASDs, we need to have some sensible message
	 */
	printf("\n--- VTOC format 3 label ----------------------"
	       "---------------------------------\n");
	printf("This VTOC doesn't contain a format 3 label.\n");
}

static void dasdview_print_vtoc_standard(dasdview_info_t *info)
{
	dasdview_read_vtoc(info);

	if (info->vtoc_info || info->vtoc_all)
		dasdview_print_vtoc_info(info);

	if (info->vtoc_f4 || info->vtoc_all)
		dasdview_print_vtoc_f4(info);

	if (info->vtoc_f5 || info->vtoc_all)
		dasdview_print_vtoc_f5(info);

	if (info->vtoc_f7 || info->vtoc_all)
		dasdview_print_vtoc_f7(info);

	if (info->vtoc_f1 || info->vtoc_all)
		dasdview_print_vtoc_f1(info);

	if (info->vtoc_f8 || info->vtoc_all)
		dasdview_print_vtoc_f8(info);

	if (info->vtoc_f9 || info->vtoc_all)
		dasdview_print_vtoc_f9(info);

	if (info->vtoc_f3 || info->vtoc_all)
		dasdview_print_vtoc_f3();
}

/* a simple routine to print all records in the vtoc */
static void dasdview_print_vtoc_raw(dasdview_info_t *info)
{
	struct dscbiterator *it;
	struct dscb *record;
	int rc;

	rc = lzds_dasd_read_vlabel(info->dasd);
	if (rc) {
		zt_error_print("error when reading label from device:"
			       " rc=%d\n", rc);
		exit(EXIT_FAILURE);
	}
	rc = lzds_dasd_alloc_rawvtoc(info->dasd);
	if (rc == EINVAL) {
		zt_error_print("dasdview: Cannot read VTOC because disk does"
			       " not contain valid VOL1 label.\n",
			       info->device);
		exit(EXIT_FAILURE);
	} else if (rc) {
		zt_error_print("error when reading vtoc from device:"
			       " rc=%d\n", rc);
		exit(EXIT_FAILURE);
	}
	rc = lzds_dasd_get_rawvtoc(info->dasd, &info->rawvtoc);
	if (rc || !info->rawvtoc) {
		zt_error_print("dasdview: libvtoc could not read vtoc\n");
		exit(EXIT_FAILURE);
	}

	if (info->vtoc_info || info->vtoc_all)
		dasdview_print_vtoc_info_raw(info);

	rc = lzds_raw_vtoc_alloc_dscbiterator(info->rawvtoc, &it);
	if (rc) {
		zt_error_print("dasdview: could not allocate DSCB iterator\n");
		exit(EXIT_FAILURE);
	}
	while (!lzds_dscbiterator_get_next_dscb(it, &record))
		dasdview_print_vtoc_dscb(info, record);
	lzds_dscbiterator_free(it);
}

static void dasdview_print_vtoc(dasdview_info_t *info)
{
	if (info->raw_track_access)
		dasdview_print_vtoc_raw(info);
	else
		dasdview_print_vtoc_standard(info);
}

static int
dasdview_print_format1(unsigned int size, unsigned char *dumpstr)
{
	unsigned int i;
	char asc[17], ebc[17];

	for (i = 0; i < size; i++) {
		if ((i / 16) * 16 == i) {
			printf("\n|  ");
			strncpy(asc, (char *)dumpstr + i, 16);
			strncpy(ebc, (char *)dumpstr + i, 16);
			asc[16] = '\0';
			ebc[16] = '\0';
		}
		printf("%02X", dumpstr[i]);
		if (((i + 1) / 4)  * 4  == i + 1)
			printf(" ");
		if (((i + 1) / 8)  * 8  == i + 1)
			printf(" ");
		if (((i + 1) / 16) * 16 == i + 1) {
			vtoc_ebcdic_dec(asc, asc, 16);
			dot(asc);
			dot(ebc);
			printf("| %16.16s | %16.16s |", asc, ebc);
		}
	}

	return 0;
}

static int
dasdview_print_format2(unsigned int size, unsigned char *dumpstr,
		       unsigned long long begin)
{
	unsigned int i;
	char asc[17], ebc[17];

	for (i = 0; i < size; i++) {
		if ((i / 8) * 8 == i) {
			printf("\n | %13llu | %13llX |  ",
			       begin + (unsigned long long)i,
			       begin + (unsigned long long)i);

			strncpy(asc, (char *)dumpstr + i, 8);
			strncpy(ebc, (char *)dumpstr + i, 8);
		}
		printf("%02X", dumpstr[i]);
		if (((i + 1) / 4) * 4 == i + 1)
			printf("  ");
		if (((i + 1) / 8) * 8 == i + 1) {
			vtoc_ebcdic_dec(asc, asc, 8);
			dot(asc);
			dot(ebc);
			printf("| %8.8s | %8.8s |", asc, ebc);
		}
	}

	return 0;
}

static void dasdview_view_standard(dasdview_info_t *info)
{
	unsigned char  dumpstr[DUMP_STRING_SIZE];
	unsigned long long i = 0, j = 0, k = 0, count = 0;
	int   fd, rc;

	unsigned long long a = 0;
	int b = 0;

	k = ((info->size) % 16LL);

	if (k != 0)
		info->size += (16LL - k);

	fd = open(info->device, O_RDONLY);
	if (fd == -1) {
		zt_error_print("dasdview: open error\n"
			       "Unable to open device %s in read-only mode!\n",
			       info->device);
		exit(EXIT_FAILURE);
	}

	j = (info->begin / SEEK_STEP);
	k = (info->begin % SEEK_STEP);

	/* seek in SEEK_STEP steps */
	for (i = 1; i <= j; i++) {
		rc = lseek64(fd, SEEK_STEP, SEEK_CUR);
		if (rc == -1) {
			printf("*** rc: %d (%d) ***\n", rc, errno);
			printf("*** j: %llu ***\n", j);
			printf("*** k: %llu ***\n", k);
			printf("*** a: %llu ***\n", a);
			printf("*** b: %d ***\n", b);
			close(fd);
			zt_error_print("dasdview: seek error\n"
				       "Unable to seek in device %s!\n",
				       info->device);
			exit(EXIT_FAILURE);
		}
		b++;
		a += SEEK_STEP;
	}

	if (k > 0) {
		rc = lseek(fd, k, SEEK_CUR);
		if (rc == -1) {
			close(fd);
			zt_error_print("dasdview: seek error\n"
				       "Unable to seek in device %s!\n",
				       info->device);
			exit(EXIT_FAILURE);
		}
	}

	j = info->size / DUMP_STRING_SIZE;
	k = info->size % DUMP_STRING_SIZE;

	if (info->format1) {
		printf("+----------------------------------------+"
		       "------------------+------------------+\n");
		printf("| HEXADECIMAL                            |"
		       " EBCDIC           | ASCII            |\n");
		printf("|  01....04 05....08  09....12 13....16  |"
		       " 1.............16 | 1.............16 |\n");
		printf("+----------------------------------------+"
		       "------------------+------------------+");
	} else if (info->format2) {
		printf(" +---------------+---------------+----------------"
		       "------+----------+----------+\n");
		printf(" |     BYTE      |     BYTE      |     HEXADECIMAL"
		       "      |  EBCDIC  |  ASCII   |\n");
		printf(" |    DECIMAL    |  HEXADECIMAL  |  1 2 3 4   5 6 "
		       "7 8   | 12345678 | 12345678 |\n");
		printf(" +---------------+---------------+----------------"
		       "------+----------+----------+");
	}

	count = info->begin;
	for (i = 1; i <= j; i++) {
		bzero(dumpstr, DUMP_STRING_SIZE);
		rc = read(fd, &dumpstr, DUMP_STRING_SIZE);
		if (rc != DUMP_STRING_SIZE) {
			close(fd);
			zt_error_print("dasdview: read error\n"
				       "Unable to read from device %s!\n",
				       info->device);
			exit(EXIT_FAILURE);
		}

		if (info->format1)
			dasdview_print_format1(DUMP_STRING_SIZE, dumpstr);
		else if (info->format2)
			dasdview_print_format2(DUMP_STRING_SIZE, dumpstr,
					       count);
		count += DUMP_STRING_SIZE;
	}

	if (k > 0) {
		bzero(dumpstr, DUMP_STRING_SIZE);
		rc = read(fd, &dumpstr, k);
		if (rc != (int)k) {
			close(fd);
			zt_error_print("dasdview: read error\n"
				       "Unable to read from device %s!\n",
				       info->device);
			exit(EXIT_FAILURE);
		}

		if (info->format1)
			dasdview_print_format1((unsigned int)k, dumpstr);
		else if (info->format2)
			dasdview_print_format2((unsigned int)k, dumpstr,
					       count);
	}

	close(fd);

	if (info->format1)
		printf("\n+----------------------------------------+"
		       "------------------+------------------+\n\n");
	else if (info->format2)
		printf("\n +---------------+---------------+----------------"
		       "------+----------+----------+\n\n");
}

static void dasdview_print_format_raw(unsigned int size, char *dumpstr)
{
	unsigned int i;
	char asc[17], ebc[17];
	unsigned int residual, count;
	char *data;

	data = dumpstr;
	residual = size;
	while (residual) {
		/* we handle at most 16 bytes per line */
		count = MIN(residual, 16u);
		bzero(asc, 17);
		bzero(ebc, 17);
		printf("|");
		memcpy(asc, data, count);
		memcpy(ebc, data, count);

		for (i = 0; i < 16; ++i) {
			if ((i % 4) == 0)
				printf(" ");
			if ((i % 8) == 0)
				printf(" ");
			if (i < count)
				printf("%02X", data[i]);
			else
				printf("  ");
		}
		vtoc_ebcdic_dec(asc, asc, count);
		dot(asc);
		dot(ebc);
		printf("  | %16.16s | %16.16s |\n", asc, ebc);
		data += count;
		residual -= count;
	}
}

/* gets the pointer to an eckd record structure in memory and
 * prints a hex/ascii/ebcdic dump for it
 */
static void dasdview_print_raw_record(char *rec)
{
	struct eckd_count *ecount;
	unsigned int cyl, head;

	ecount = (struct eckd_count *)rec;
	/* Note: the first 5 bytes of the count area are the
	 * record ID and by convention these bytes are interpreted
	 * as CCHHR (or ccccCCChR for large volumes)
	 */
	cyl = vtoc_get_cyl_from_cchhb(&ecount->recid);
	head = vtoc_get_head_from_cchhb(&ecount->recid);
	printf("+-----------------------------------------"
	       "-------------------------------------+\n");
	printf("| count area:                                    "
	       "                              |\n");
	printf("|          hex: %016llX                          "
	       "                     |\n",
	       *((unsigned long long *)ecount));
	printf("|     cylinder:        %9d                 "
	       "                              |\n", cyl);
	printf("|         head:        %9d                 "
	       "                              |\n", head);
	printf("|       record:        %9d                 "
	       "                              |\n", ecount->recid.b);
	printf("|   key length:        %9d                 "
	       "                              |\n", ecount->kl);
	printf("|  data length:        %9d                 "
	       "                              |\n", ecount->dl);
	printf("+-----------------------------------------"
	       "-------------------------------------+\n");
	printf("| key area:                               "
	       "                                     |\n");
	printf("| HEXADECIMAL                            |"
	       " EBCDIC           | ASCII            |\n");
	printf("|  01....04 05....08  09....12 13....16  |"
	       " 1.............16 | 1.............16 |\n");
	printf("+----------------------------------------+"
	       "------------------+------------------+\n");
	dasdview_print_format_raw(ecount->kl, rec + sizeof(*ecount));
	printf("+----------------------------------------+"
	       "------------------+------------------+\n");
	printf("| data area:                              "
	       "                                     |\n");
	printf("| HEXADECIMAL                            |"
	       " EBCDIC           | ASCII            |\n");
	printf("|  01....04 05....08  09....12 13....16  |"
	       " 1.............16 | 1.............16 |\n");
	printf("+----------------------------------------+"
	       "------------------+------------------+\n");
	dasdview_print_format_raw(ecount->dl,
				  rec + sizeof(*ecount) + ecount->kl);
	printf("+----------------------------------------+"
	       "------------------+------------------+\n");
}

static void dasdview_print_raw_track(char *trackdata,
				     unsigned int cyl,
				     unsigned int head)
{
	struct eckd_count *ecount;
	char *data;
	u_int32_t record;

	record = 0;
	data = trackdata;

	do {
		printf("cylinder %u, head %u, record %u\n",
		       cyl, head, record);
		dasdview_print_raw_record(data);
		printf("\n");

		ecount = (struct eckd_count *)data;
		data += sizeof(*ecount) + ecount->kl + ecount->dl;
		++record;

		if ((*(unsigned long long *)data) == ENDTOKEN)
			break;
		if ((unsigned long)data >=
		    (unsigned long)trackdata + RAWTRACKSIZE)
			break;
	} while (1);
}

static void dasdview_view_raw(dasdview_info_t *info)
{
	u_int64_t residual, trckstart, trckend, track, trckbuffsize;
	u_int64_t tracks_to_read, trckcount, i;
	char *trackdata;
	char *data;
	int rc;
	struct dasdhandle *dasdh;

	trckstart = info->begin / RAWTRACKSIZE;
	tracks_to_read = info->size / RAWTRACKSIZE;

	/* TODO: how large should we make our buffer?
	 * The DASD device driver cannot read more than 16 tracks at once
	 * but we can read a larger blob and the block layer will split up
	 * the requests for us.
	 */
	trckbuffsize = MIN(tracks_to_read, 16u);
	/* track data must be page aligned for O_DIRECT */
	trackdata = memalign(4096, trckbuffsize * RAWTRACKSIZE);
	if (!trackdata) {
		zt_error_print("failed to allocate memory\n");
		exit(EXIT_FAILURE);
	}
	rc = lzds_dasd_alloc_dasdhandle(info->dasd, &dasdh);
	if (rc) {
		zt_error_print("failed to allocate memory\n");
		exit(EXIT_FAILURE);
	}
	rc = lzds_dasdhandle_open(dasdh);
	if (rc) {
		lzds_dasdhandle_free(dasdh);
		zt_error_print("failed to open device\n");
		exit(EXIT_FAILURE);
	}
	/* residual is the number of tracks we still have to read */
	residual = tracks_to_read;
	track = trckstart;
	while (residual) {
		trckcount = MIN(trckbuffsize, residual);
		trckend = track + trckcount - 1;
		rc = lzds_dasdhandle_read_tracks_to_buffer(dasdh, track,
							   trckend, trackdata);
		if (rc) {
			perror("Error on read");
			exit(EXIT_FAILURE);
		}
		data = trackdata;
		for (i = 0; i < trckcount; ++i) {
			dasdview_print_raw_track(data, track / info->geo.heads,
						 track % info->geo.heads);
			data += RAWTRACKSIZE;
			++track;
		}
		residual -= trckcount;
	}

	free(trackdata);

	rc = lzds_dasdhandle_close(dasdh);
	lzds_dasdhandle_free(dasdh);
	if (rc < 0) {
		perror("Error on closing file");
		exit(EXIT_FAILURE);
	}
}

static void dasdview_view(dasdview_info_t *info)
{
	if (info->raw_track_access)
		dasdview_view_raw(info);
	else
		dasdview_view_standard(info);
}

static void
dasdview_print_characteristic(dasdview_info_t *info)
{
	dasd_information2_t dasd_info = info->dasd_info;

	printf("encrypted disk         : %s\n",
	       (dasd_info.characteristics[46] & 0x80) ? "yes" : "no");
	printf("solid state device     : %s\n",
	       (dasd_info.characteristics[46] & 0x40) ? "yes" : "no");
}

int main(int argc, char *argv[])
{
	dasdview_info_t info;
	int oc;
	unsigned long long max = 0LL;
	char *begin_param_str = NULL;
	char *size_param_str  = NULL;
	int rc;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	bzero(&info, sizeof(info));
	while (1) {
		oc = util_opt_getopt_long(argc, argv);

		switch (oc) {
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		case 'b':
			begin_param_str = optarg;
			info.action_specified = 1;
			info.begin_specified = 1;
			break;
		case 's':
			size_param_str = optarg;
			info.action_specified = 1;
			info.size_specified = 1;
			break;
		case '1':
			info.format1 = 1;
			info.format2 = 0;
			break;
		case '2':
			info.format1 = 0;
			info.format2 = 1;
			break;
		case 'i':  /* print general DASD information and geometry */
			info.action_specified = 1;
			info.general_info = 1;
			break;
		case 'x':  /* print extended DASD information */
			info.action_specified = 1;
			info.extended_info = 1;
			break;
		case 'j':
			info.action_specified = 1;
			info.volser = 1;
			break;
		case 't':
			if (strcmp(optarg, "info") == 0) {
				info.vtoc_info = 1;
			} else if (strcmp(optarg, "f1") == 0) {
				info.vtoc_f1 = 1;
			} else if (strcmp(optarg, "f3") == 0) {
				info.vtoc_f3 = 1;
			} else if (strcmp(optarg, "f4") == 0) {
				info.vtoc_f4 = 1;
			} else if (strcmp(optarg, "f5") == 0) {
				info.vtoc_f5 = 1;
			} else if (strcmp(optarg, "f7") == 0) {
				info.vtoc_f7 = 1;
			} else if (strcmp(optarg, "f8") == 0) {
				info.vtoc_f8 = 1;
			} else if (strcmp(optarg, "f9") == 0) {
				info.vtoc_f9 = 1;
			} else if (strcmp(optarg, "all") == 0) {
				info.vtoc_all = 1;
			} else {
				zt_error_print("dasdview: usage error\n"
					       "%s is no valid argument for"
					       " option -t/--vtoc\n", optarg);
				exit(EXIT_FAILURE);
			}
			info.vtoc = 1;
			info.action_specified = 1;
			break;
		case 'l':
			info.action_specified = 1;
			info.vlabel_info = 1;
			break;
		case 'c':
			info.action_specified = 1;
			info.characteristic_specified = 1;
			break;
		case -1:
			/* End of options string - start of devices list */
			info.device_id = optind;
			break;
		default:
			fprintf(stderr, "Try 'dasdview --help' for more"
				" information.\n");
			exit(1);
		}
		if (oc == -1)
			break;
	}

	/* do some tests */
	if (info.device_id >= argc) {
		zt_error_print("dasdview: usage error\n"
			       "No device specified!");
		exit(EXIT_FAILURE);
	}

	if (info.device_id + 1 < argc) {
		zt_error_print("dasdview: usage error\n"
			       "More than one device specified!");
		exit(EXIT_FAILURE);
	}

	if (info.device_id < argc)
		strcpy(info.device, argv[info.device_id]);

	dasdview_get_info(&info);

	if (info.raw_track_access) {
		rc = lzds_zdsroot_alloc(&info.zdsroot);
		if (rc) {
			zt_error_print("Could not allocate index\n");
			exit(EXIT_FAILURE);
		}
		rc = lzds_zdsroot_add_device(info.zdsroot, info.device,
					     &info.dasd);
		if (rc) {
			zt_error_print("Could not add device to index\n");
			exit(EXIT_FAILURE);
		}
	}

	if (info.begin_specified)
		dasdview_parse_input(&info.begin, &info, begin_param_str);
	else
		info.begin = DEFAULT_BEGIN;

	if (info.raw_track_access)
		max = (unsigned long long)info.hw_cylinders *
			(unsigned long long)info.geo.heads * RAWTRACKSIZE;
	else
		max = (unsigned long long)info.hw_cylinders *
			(unsigned long long)info.geo.heads *
			(unsigned long long)info.geo.sectors *
			(unsigned long long)info.blksize;

	if (info.begin > max) {
		zt_error_print("dasdview: usage error\n"
			"'begin' value is not within disk range!");
		exit(EXIT_FAILURE);
	}

	if (info.size_specified)
		dasdview_parse_input(&info.size, &info, size_param_str);
	else if (info.raw_track_access)
		info.size = RAWTRACKSIZE;
	else
		info.size = DEFAULT_SIZE;

	if ((info.begin_specified || info.size_specified) &&
	    ((info.begin + info.size) > max)) {
		zt_error_print("dasdview: usage error\n"
			"'begin' + 'size' is not within "
			"disk range!");
		exit(EXIT_FAILURE);
	}

	if ((info.begin_specified || info.size_specified) &&
	    (!info.format1 && !info.format2))
		info.format1 = 1;

	if ((info.format1 || info.format2) &&
	    (!info.size_specified && !info.begin_specified)) {
		zt_error_print("dasdview: usage error\n"
			"Options -1 or -2 make only sense with "
			"options -b or -s!");
		exit(EXIT_FAILURE);
	}

	/* do the output */

	if (info.begin_specified || info.size_specified)
		dasdview_view(&info);

	if (info.general_info || info.extended_info)
		dasdview_print_general_info(&info);

	if (info.extended_info)
		dasdview_print_extended_info(&info);

	if (info.volser)
		dasdview_print_volser(&info);

	if (info.vlabel_info)
		dasdview_print_vlabel(&info);

	if (info.vtoc)
		dasdview_print_vtoc(&info);

	if (!info.action_specified)
		printf("No action specified.\n");

	if (info.characteristic_specified)
		dasdview_print_characteristic(&info);

	return 0;
}

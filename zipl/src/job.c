/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Functions and data structures representing the actual 'job' that the
 * user wants us to execute
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "error.h"
#include "job.h"
#include "misc.h"
#include "scan.h"
#include "zipl.h"

/* Command line options */
static struct option options[] = {
	{ "config",		required_argument,	NULL, 'c'},
	{ "blsdir",		required_argument,	NULL, 'b'},
	{ "target",		required_argument,	NULL, 't'},
	{ "targetbase",         required_argument,      NULL, 0xaa},
	{ "targettype",         required_argument,      NULL, 0xab},
	{ "targetgeometry",     required_argument,      NULL, 0xac},
	{ "targetblocksize",    required_argument,      NULL, 0xad},
	{ "targetoffset",       required_argument,      NULL, 0xae},
	{ "image", 		required_argument,	NULL, 'i'},
	{ "ramdisk",		required_argument,	NULL, 'r'},
	{ "parmfile",		required_argument,	NULL, 'p'},
	{ "parameters",		required_argument,	NULL, 'P'},
	{ "dumpto",		required_argument,	NULL, 'd'},
	{ "dumptofs",		required_argument,	NULL, 'D'},
	{ "mvdump",		required_argument,	NULL, 'M'},
	{ "segment",		required_argument,	NULL, 's'},
	{ "menu",		required_argument,	NULL, 'm'},
	{ "help",		no_argument,		NULL, 'h'},
	{ "noninteractive",	no_argument,		NULL, 'n'},
	{ "version",		no_argument,		NULL, 'v'},
	{ "verbose",		no_argument,		NULL, 'V'},
	{ "add-files",		no_argument,		NULL, 'a'},
	{ "tape",		required_argument,	NULL, 'T'},
	{ "dry-run",		no_argument,		NULL, '0'},
	{ "force",		no_argument,		NULL, 'f'},
	{ "kdump",		required_argument,	NULL, 'k'},
	{ "secure",		required_argument,	NULL, 'S'},
	{ NULL,			0,			NULL, 0 }
};

/* Command line option abbreviations */
static const char option_string[] = "-c:b:t:i:r:p:P:d:D:M:s:S:m:hHnVvaT:fk:";

/* Locations of zipl.conf configuration file */
static const char *zipl_conf[] = {
	ZIPL_RUNTIME_CONF,
	ZIPL_DEFAULT_CONF,
	ZIPL_MINIMAL_CONF,
	NULL
};

struct command_line {
	char* data[SCAN_KEYWORD_NUM];
	char* config;
	char *blsdir;
	char* menu;
	char* section;
	int help;
	int noninteractive;
	int version;
	int verbose;
	int add_files;
	int dry_run;
	int force;
	int is_secure;
	enum scan_section_type type;
};


static int
store_option(struct command_line* cmdline, enum scan_keyword_id keyword,
	     char* value)
{
	if (cmdline->data[(int) keyword] != NULL) {
		error_reason("Option '%s' specified more than once",
			     scan_keyword_name(keyword));
		return -1;
	}
	cmdline->data[(int) keyword] = value;
	return 0;
}

static int
set_secure_ipl(char *keyword, int *is_secure)
{
	if (strcmp(keyword, "auto") == 0) {
		*is_secure = SECURE_BOOT_AUTO;
	} else if (strcmp(keyword, "0") == 0) {
		*is_secure = SECURE_BOOT_DISABLED;
	} else if (strcmp(keyword, "1") == 0) {
		*is_secure = SECURE_BOOT_ENABLED;
	} else {
		error_reason("Invalid secure boot setting '%s'",
			     keyword);
		return -1;
	}
	return 0;
}

static int
get_command_line(int argc, char* argv[], struct command_line* line)
{
	struct command_line cmdline;
	int is_keyword;
	int opt;
	int rc;
	int i;

	memset((void *) &cmdline, 0, sizeof(struct command_line));
	cmdline.type = section_invalid;
	is_keyword = 0;
	cmdline.is_secure = SECURE_BOOT_UNDEFINED;
	/* Process options */
	do {
		opt = getopt_long(argc, argv, option_string, options, NULL);
		rc = 0;
		switch (opt) {
		case 'd':
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_dumpto,
					  optarg);
			break;
		case 'D':
			error_reason("dumptofs has been deprecated, use "
				     "--dumpto instead");
			rc = -1;
			break;
		case 'M':
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_mvdump,
					  optarg);
#ifndef __s390x__
			error_reason("Option '%s' not supported on 31-bit",
				     scan_keyword_name(scan_keyword_mvdump));
			rc = -1;
#endif
			break;
		case 'i':
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_image,
					  optarg);
			break;
		case 'P':
			rc = store_option(&cmdline, scan_keyword_parameters,
					  optarg);
			break;
		case 'p':
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_parmfile,
					  optarg);
			break;
		case 'r':
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_ramdisk,
					  optarg);
			break;
		case 's':
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_segment,
					  optarg);
			break;
		case 't':
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_target,
					  optarg);
			break;
		case 0xaa:
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_targetbase,
					  optarg);
			break;
		case 0xab:
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_targettype,
					  optarg);
			break;
		case 0xac:
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_targetgeometry,
					  optarg);
			break;
		case 0xad:
			is_keyword = 1;
			rc = store_option(&cmdline,
					  scan_keyword_targetblocksize,
					  optarg);
			break;
		case 0xae:
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_targetoffset,
					  optarg);
			break;
		case 'T':
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_tape,
					  optarg);
			break;
		case 'k':
			is_keyword = 1;
			rc = store_option(&cmdline, scan_keyword_kdump,
					  optarg);
			break;
		case 'c':
			if (cmdline.config != NULL) {
				error_reason("Option 'config' specified more "
					     "than once");
				rc = -1;
			} else
				cmdline.config = optarg;
			break;
		case 'b':
			if (cmdline.blsdir != NULL) {
				error_reason("Option 'blsdir' specified more "
					     "than once");
				rc = -1;
			} else
				cmdline.blsdir = optarg;
			break;
		case 'm':
			if (cmdline.menu != NULL) {
				error_reason("Option 'menu' specified more "
					     "than once");
				rc = -1;
			} else
				cmdline.menu = optarg;
			break;
		case 'S':
			rc = set_secure_ipl(optarg, &cmdline.is_secure);
			break;
		case 'h':
			cmdline.help = 1;
			break;
		case 'n':
			cmdline.noninteractive = 1;
			break;
		case 'v':
			cmdline.version = 1;
			break;
		case 'V':
			cmdline.verbose = 1;
			break;
		case 'a':
			cmdline.add_files = 1;
			break;
		case '0':
			cmdline.dry_run = 1;
			break;
		case 'f':
			cmdline.force = 1;
			break;
		case 1:
			/* Non-option is interpreted as section name */
			if (cmdline.section != NULL) {
				error_reason("More than one section "
					     "specified on command line");
				rc = -1;
			} else
				cmdline.section = optarg;
			break;
		case -1:
			/* End of options string */
			break;
		default:
			fprintf(stderr, "Try 'zipl --help' for "
					"more information.\n");
			exit(1);
		}
		if (rc)
			return rc;
	} while (opt != -1);
	/* Check command line options */
	if (cmdline.help || cmdline.version) {
		/* Always accept --help and --version */
	} else if ((cmdline.menu != NULL) || (cmdline.section != NULL)) {
		/* Config file mode */
		if ((cmdline.menu != NULL) && (cmdline.section != NULL)) {
			error_reason("Option 'menu' cannot be used when "
				     "specifying a configuration section");
			return -1;
		}
		/* Make sure no other keyword option was specified */
		for (i=0; i < SCAN_KEYWORD_NUM; i++) {
			/* Allow '--parameters' when specifying a section */
			if ((i == (int) scan_keyword_parameters) &&
			    (cmdline.menu == NULL))
				continue;
			if (cmdline.data[i] != NULL) {
				if (cmdline.menu != NULL) {
					error_reason("Only one of options "
						     "'menu' and '%s' allowed",
						     scan_keyword_name(
						     	(enum scan_keyword_id)
						     		i));
				} else {
					error_reason("Option '%s' cannot be "
						     "used when specifying "
						     "a configuration section",
						     scan_keyword_name(
						     	(enum scan_keyword_id)
						     		i));
				}
				return -1;
			}
		}
	} else if (is_keyword) {
		/* Command line mode */
		rc = scan_check_section_data(cmdline.data, NULL, NULL, 0,
					     &cmdline.type);
		if (rc) {
			if (cmdline.type == section_invalid) {
				error_reason("Need one of options 'image', "
					     "'segment','dumpto', 'dumptofs', "
					     "'mvdump' or 'menu'");
			}
			return rc;
		}
		rc = scan_check_target_data(cmdline.data, NULL);
		if (rc)
			return rc;
	}
	*line = cmdline;
	return 0;
}


static void
free_target_data(struct job_target_data* data)
{
	if (data->targetbase != NULL)
		free(data->targetbase);
}

static void
free_ipl_data(struct job_ipl_data* data)
{
	if (data->image != NULL)
		free(data->image);
	if (data->parmline != NULL)
		free(data->parmline);
	if (data->ramdisk != NULL)
		free(data->ramdisk);
}


static void
free_ipl_tape_data(struct job_ipl_tape_data* data)
{
	if (data->device != NULL)
		free(data->device);
	if (data->image != NULL)
		free(data->image);
	if (data->parmline != NULL)
		free(data->parmline);
	if (data->ramdisk != NULL)
		free(data->ramdisk);
}


static void
free_segment_data(struct job_segment_data* data)
{
	if (data->segment != NULL)
		free(data->segment);
}


static void
free_dump_data(struct job_dump_data* data)
{
	if (data->device != NULL)
		free(data->device);
	if (data->image != NULL)
		free(data->image);
	if (data->parmline != NULL)
		free(data->parmline);
	if (data->ramdisk != NULL)
		free(data->ramdisk);
}


static void
free_menu_data(struct job_menu_data* data)
{
	int i;

	if (data->entry != NULL) {
		for (i=0; i < data->num; i++) {
			if (data->entry[i].name != NULL)
				free(data->entry[i].name);
			switch (data->entry[i].id) {
			case job_ipl:
				free_ipl_data(&data->entry[i].data.ipl);
				break;
			case job_dump_partition:
				free_dump_data(
					&data->entry[i].data.dump);
				break;
			default:
				break;
			}
		}
		free(data->entry);
	}
}


void
free_mvdump_data(struct job_mvdump_data* data)
{
	int i;

	if (data->device_list != NULL)
		free(data->device_list);
	for (i = 0; i < data->device_count; i++)
		if (data->device[i] != NULL)
			free(data->device[i]);
}


void
job_free(struct job_data* job)
{
	if (job->target.bootmap_dir != NULL)
		free(job->target.bootmap_dir);
	free_target_data(&job->target);
	if (job->name != NULL)
		free(job->name);
	switch (job->id) {
	case job_ipl:
		free_ipl_data(&job->data.ipl);
		break;
	case job_menu:
		free_menu_data(&job->data.menu);
		break;
	case job_segment:
		free_segment_data(&job->data.segment);
		break;
	case job_dump_partition:
		free_dump_data(&job->data.dump);
		break;
	case job_mvdump:
		free_mvdump_data(&job->data.mvdump);
		break;
	case job_ipl_tape:
		free_ipl_tape_data(&job->data.ipl_tape);
		break;
	default:
		break;
	}
	free(job);
}


struct component_loc {
	char *name;
	address_t *addrp;
	size_t size;
	off_t align;
};

static int
set_cl_element(struct component_loc *cl, char *name, char *filename,
	       address_t *addrp, size_t size, off_t off, off_t align)
{
	struct stat stats;

	cl->name = name;
	cl->addrp = addrp;
	cl->align = align;
	if (size != 0) {
		/* The loader works on blocks, so alignment is required */
		cl->size = ALIGN(size, MAXIMUM_PHYSICAL_BLOCKSIZE);
		return 0;
	}
	/* Get size */
	if (stat(filename, &stats)) {
		error_reason(strerror(errno));
		error_text("Could not get information for file '%s'", filename);
		return -1;
	}
	cl->size = ALIGN(stats.st_size - off, MAXIMUM_PHYSICAL_BLOCKSIZE);
	return 0;
}

static void
sort_cl_array(struct component_loc* cl, int elements)
{
	int i, j, min;
	struct component_loc swap;

	/* Selection sort keeping sequence */
	for (i = 0; i < elements - 1; i++) {
		min = i;
		for (j = i + 1; j < elements; j++) {
			if (*(cl[j].addrp) == UNSPECIFIED_ADDRESS)
				continue;
			if ((*(cl[min].addrp) == UNSPECIFIED_ADDRESS) ||
			    (*(cl[j].addrp) < *(cl[min].addrp)))
				min = j;
		}
		if (i != min) {
			swap = cl[i];
			cl[i] = cl[min];
			for (j = min; j > i + 1; j--)
				cl[j] = cl[j - 1];
			cl[i + 1] = swap;
		}
	}
}

static int
get_ipl_components(struct job_ipl_data *ipl, struct component_loc **clp,
		   int *nump)
{
	struct component_loc *cl;
	int num;
	int rc;

	/* Get memory for image, parmline, ramdisk */
	cl = misc_calloc(3, sizeof(struct component_loc));
	if (cl == NULL)
		return -1;
	/* Fill in component data */
	num = 0;
	rc = set_cl_element(&cl[num++], "kernel image", ipl->image,
			    &ipl->image_addr, 0, 0,
			    MAXIMUM_PHYSICAL_BLOCKSIZE);
	if (rc)
		goto error;
	if (ipl->parmline) {
		rc = set_cl_element(&cl[num++], "parmline", NULL,
				    &ipl->parm_addr, MAXIMUM_PARMLINE_SIZE, 0,
				    MAXIMUM_PHYSICAL_BLOCKSIZE);
		if (rc)
			goto error;
	}
	if (ipl->ramdisk) {
		rc = set_cl_element(&cl[num++], "initial ramdisk", ipl->ramdisk,
			&ipl->ramdisk_addr, 0, 0, 0x10000);
		if (rc)
			goto error;
	}

	*clp = cl;
	*nump = num;
	return 0;
error:
	free(cl);
	return rc;
}


static int
get_dump_components(struct job_dump_data *dump,
		       struct component_loc **clp, int *nump)
{
	struct component_loc *cl;
	int num;
	int rc;

	/* Get memory for image, parmline, ramdisk, loader */
	cl = misc_calloc(3, sizeof(struct component_loc));
	if (cl == NULL)
		return -1;
	/* Fill in component data */
	num = 0;
	rc = set_cl_element(&cl[num++], "kernel image", dump->image,
			    &dump->image_addr, 0, 0x0,
			    MAXIMUM_PHYSICAL_BLOCKSIZE);
	if (rc)
		goto error;
	rc = set_cl_element(&cl[num++], "parmline", NULL, &dump->parm_addr,
			    MAXIMUM_PARMLINE_SIZE, 0,
			    MAXIMUM_PHYSICAL_BLOCKSIZE);
	if (rc)
		goto error;
	if (dump->ramdisk) {
		rc = set_cl_element(&cl[num++], "initial ramdisk",
				    dump->ramdisk, &dump->ramdisk_addr,
				    0, 0, 0x10000);
		if (rc)
			goto error;
	}

	*clp = cl;
	*nump = num;
	return 0;
error:
	free(cl);
	return rc;
}


static int
get_ipl_tape_components(struct job_ipl_tape_data *ipl_tape,
			struct component_loc **clp, int *nump)
{
	struct component_loc *cl;
	int num;
	int rc;

	/* Get memory for image, parmline, ramdisk */
	cl = misc_calloc(3, sizeof(struct component_loc));
	if (cl == NULL)
		return -1;
	/* Fill in component data */
	num = 0;
	rc = set_cl_element(&cl[num++], "kernel image", ipl_tape->image,
			    &ipl_tape->image_addr, 0, 0x10000,
			    MAXIMUM_PHYSICAL_BLOCKSIZE);
	if (rc)
		goto error;
	/* Enhance the image size value for tape loader specific logic */
	cl[0].size = ALIGN(cl[0].size + 0x100, MAXIMUM_PHYSICAL_BLOCKSIZE);
	if (ipl_tape->parmline) {
		rc = set_cl_element(&cl[num++], "parmline", NULL,
				    &ipl_tape->parm_addr, MAXIMUM_PARMLINE_SIZE,
				    0, MAXIMUM_PHYSICAL_BLOCKSIZE);
		if (rc)
			goto error;
	}
	if (ipl_tape->ramdisk) {
		rc = set_cl_element(&cl[num++], "initial ramdisk",
				    ipl_tape->ramdisk, &ipl_tape->ramdisk_addr,
				    0, 0, 0x10000);
		if (rc)
			goto error;
	}
	*clp = cl;
	*nump = num;
	return 0;
error:
	free(cl);
	return rc;
}


static int
check_component_address_data(struct component_loc *cl, int num, char *name,
			     unsigned long address_limit)
{
	int i;

	/* Check for address limit */
	for (i = 0; i < num; i++) {
		if (*cl[i].addrp == UNSPECIFIED_ADDRESS)
			continue;
		if (*cl[i].addrp + cl[i].size > address_limit) {
			if (name != NULL)
				error_text("Section '%s'", name);
			error_reason("Component '%s' exceeds available address "
				     "space (limit is 0x%08x)", cl[i].name,
				     address_limit);
			return -1;
		}
		if (*cl[i].addrp < IMAGE_LOAD_ADDRESS) {
			if (name != NULL)
				error_text("Section '%s'", name);
			error_reason("Component '%s' falls below available "
				     "address space (limit is 0x%08x)",
				     cl[i].name, IMAGE_LOAD_ADDRESS);
			return -1;
		}
	}
	/* Check for overlap */
	for (i = 0; i < num - 1; i++) {
		if (*cl[i].addrp == UNSPECIFIED_ADDRESS ||
		    *cl[i + 1].addrp == UNSPECIFIED_ADDRESS)
			continue;
		if (*cl[i].addrp + cl[i].size > *cl[i + 1].addrp) {
			if (name != NULL)
				error_text("Section '%s'", name);
			error_reason("Components '%s' and '%s' overlap",
				     cl[i].name, cl[i + 1].name);
			return -1;
		}
	}
	return 0;
}


static int
finalize_component_address_data(struct component_loc *cl, int num,
				unsigned long address_limit)
{
	struct component_loc swap;
	address_t addr;
	int i;
	int j;
	int k;

	/* Calculate unspecified addresses */
	for (i = 0; i < num; i++) {
		if (*cl[i].addrp != UNSPECIFIED_ADDRESS)
			continue;
		for (j = -1; j < i; j++) {
			if (j < 0) {
				/* Try address before first component */
				addr = IMAGE_LOAD_ADDRESS;
			} else {
				/* Try address after component j */
				addr = *cl[j].addrp + cl[j].size;
				if (addr < IMAGE_LOAD_ADDRESS)
					addr = IMAGE_LOAD_ADDRESS;
			}
			addr = ALIGN(addr, cl[i].align);
			if (addr + cl[i].size > address_limit) {
				error_text("Could not fit component '%s' into "
					   "available address space",
					   cl[i].name);
				return -1;
			}
			/* Check for enough room */
			if (*cl[j + 1].addrp != UNSPECIFIED_ADDRESS &&
			    addr + cl[i].size > *cl[j + 1].addrp)
				continue;
			*cl[i].addrp = addr;
			/* If there is no next component we are done */
			if (i == j + 1)
				break;
			/* Restore sort order */
			swap = cl[j + 1];
			cl[j + 1] = cl[i];
			for (k = i; k > j + 2; k--)
				cl[k] = cl[k - 1];
			cl[j + 2] = swap;
			break;
		}
	}
	return 0;
}


static int
finalize_ipl_address_data(struct job_ipl_data* ipl, char *name)
{
	unsigned long address_limit;
	struct component_loc *cl;
	int num;
	int rc;

	address_limit = ipl->is_kdump ? ADDRESS_LIMIT_KDUMP : ADDRESS_LIMIT;
	rc = get_ipl_components(ipl, &cl, &num);
	if (rc)
		return rc;
	sort_cl_array(cl, num);
	rc = check_component_address_data(cl, num, name, address_limit);
	if (rc)
		goto out_free;
	rc = finalize_component_address_data(cl, num, address_limit);
out_free:
	free(cl);
	return rc;
}


static int
finalize_dump_address_data(struct job_dump_data* dump, char *name)
{
	struct component_loc *cl;
	int num;
	int rc;

	rc = get_dump_components(dump, &cl, &num);
	if (rc)
		return rc;
	sort_cl_array(cl, num);
	rc = check_component_address_data(cl, num, name, ADDRESS_LIMIT);
	if (rc)
		goto out_free;
	rc = finalize_component_address_data(cl, num, ADDRESS_LIMIT);
out_free:
	free(cl);
	return rc;
}


static int
finalize_ipl_tape_address_data(struct job_ipl_tape_data* ipl_tape, char *name)
{
	struct component_loc *cl;
	int num;
	int rc;
	int i;

	rc = get_ipl_tape_components(ipl_tape, &cl, &num);
	if (rc)
		return rc;
	sort_cl_array(cl, num);
	rc = check_component_address_data(cl, num, name, ADDRESS_LIMIT);
	if (rc)
		goto out_free;
	rc = finalize_component_address_data(cl, num, ADDRESS_LIMIT);
	/* The loader needs a ramdisk_addr anyway */
	if (ipl_tape->ramdisk_addr == 0) {
		for (i = 0; i < num; i++) {
			if (*cl[i].addrp == ipl_tape->image_addr)
				ipl_tape->ramdisk_addr =
					*cl[i].addrp + cl[i].size;
		}
	}
out_free:
	free(cl);
	return rc;
}


static int
check_job_ipl_data(struct job_ipl_data *ipl, char* name)
{
	int rc;

	if (ipl->image != NULL) {
		rc = misc_check_readable_file(ipl->image);
		if (rc) {
			if (name == NULL) {
				error_text("Image file '%s'", ipl->image);
			} else {
				error_text("Image file '%s' in section '%s'",
					   ipl->image, name);
			}
			return rc;
		}
	}
	if (ipl->ramdisk != NULL) {
		rc = misc_check_readable_file(ipl->ramdisk);
		if (rc) {
			if (name == NULL) {
				error_text("Ramdisk file '%s'", ipl->ramdisk);
			} else {
				error_text("Ramdisk file '%s' in section '%s'",
					   ipl->ramdisk, name);
			}
			return rc;
		}
	}
	return finalize_ipl_address_data(ipl, name);
}


static int
check_job_segment_data(struct job_segment_data* segment, char* name)
{
	int rc;

	if (segment->segment != NULL) {
		rc = misc_check_readable_file(segment->segment);
		if (rc) {
			if (name == NULL) {
				error_text("Segment file '%s'",
					   segment->segment);
			} else {
				error_text("Segment file '%s' in section '%s'",
					   segment->segment, name);
			}
			return rc;
		}
	}
	return 0;
}


static int
check_job_dump_data(struct job_dump_data* dump, char* name)
{
	int rc;

	if (dump->device != NULL) {
		rc = misc_check_writable_device(dump->device, 1, 1);
		if (rc) {
			if (name == NULL) {
				error_text("Dump device '%s'", dump->device);
			} else {
				error_text("Dump device '%s' in section '%s'",
					   dump->device, name);
			}
			return rc;
		}
	}
	return 0;
}


int
check_job_dump_images(struct job_dump_data* dump, char* name)
{
	int rc;
	/* Add data needed to convert fs dump job to IPL job */
	rc = misc_check_readable_file(ZFCPDUMP_IMAGE);
	if (rc) {
		error_text("Need external file '%s' for partition dump",
			   ZFCPDUMP_IMAGE);
		return rc;
	}
	dump->image = misc_strdup(ZFCPDUMP_IMAGE);
	if (dump->image == NULL)
		return -1;
	dump->image_addr = IMAGE_LOAD_ADDRESS;

	/* Ramdisk is no longer required with new initramfs dump system */
	if (misc_check_readable_file(ZFCPDUMP_INITRD))
		dump->ramdisk = NULL;
	else {
		dump->ramdisk = misc_strdup(ZFCPDUMP_INITRD);
		if (dump->ramdisk == NULL)
			return -1;
		dump->ramdisk_addr = UNSPECIFIED_ADDRESS;
	}

	dump->parm_addr = UNSPECIFIED_ADDRESS;
	return finalize_dump_address_data(dump, name);
}


static int
check_job_menu_data(struct job_menu_data* menu)
{
	int rc;
	int i;

	for (i=0; i<menu->num; i++) {
		switch (menu->entry[i].id) {
		case job_ipl:
			rc = check_job_ipl_data(&menu->entry[i].data.ipl,
						menu->entry[i].name);
			if (rc)
				return rc;
			break;
		case job_print_usage:
		case job_print_version:
		case job_segment:
		case job_dump_partition:
		case job_mvdump:
		case job_menu:
		case job_ipl_tape:
			break;
		}
	}
	return 0;
}


static int
check_job_ipl_tape_data(struct job_ipl_tape_data *ipl, char* name)
{
	int rc;

	if (ipl->device != NULL) {
		rc = misc_check_writable_device(ipl->device, 1, 1);
		if (rc) {
			if (name == NULL) {
				error_text("Tape device '%s'", ipl->device);
			} else {
				error_text("Tape device '%s' in section '%s'",
					   ipl->device, name);
			}
			return rc;
		}
	}
	if (ipl->image != NULL) {
		rc = misc_check_readable_file(ipl->image);
		if (rc) {
			if (name == NULL) {
				error_text("Image file '%s'", ipl->image);
			} else {
				error_text("Image file '%s' in section '%s'",
					   ipl->image, name);
			}
			return rc;
		}
	}
	if (ipl->ramdisk != NULL) {
		rc = misc_check_readable_file(ipl->ramdisk);
		if (rc) {
			if (name == NULL) {
				error_text("Ramdisk file '%s'", ipl->ramdisk);
			} else {
				error_text("Ramdisk file '%s' in section '%s'",
					   ipl->ramdisk, name);
			}
			return rc;
		}
	}
	return finalize_ipl_tape_address_data(ipl, name);
}

static int
check_job_mvdump_data(struct job_mvdump_data* dump, char* name)
{
	int rc;
	size_t size, i, j, k;
	char* buffer;

	rc = misc_read_file(dump->device_list, &buffer, &size, 0);
	if (rc) {
		if (name == NULL) {
			error_text("Dump target list '%s'", dump->device_list);
		} else {
			error_text("Dump target list '%s' in section '%s'",
				   dump->device_list, name);
		}
		return rc;
	}
	if (size == 0) {
		error_text("Dump target list '%s' is empty.",
			   dump->device_list);
		free(buffer);
		return -1;
	}
	for (i = 0, j = 0, k = 0 ; i < size; i++) {
		if (buffer[i] != '\n')
			buffer[j++] = buffer[i];
		else if (j > 0) {
			if (k == MAX_DUMP_VOLUMES) {
				error_text("Dump target list '%s' contains "
					   "more than %d entries.",
					   dump->device_list, k);
				free(buffer);
				return -1;
			}
			buffer[j] = 0;
			dump->device[k] = misc_strdup(buffer);
			if (dump->device[k] == NULL)
				return -1;
			k++;
			j = 0;
		}
	}
	free(buffer);
	dump->device_count = k;
	for (i = 0; i < (size_t) dump->device_count; i++) {
		rc = misc_check_writable_device(dump->device[i], 1, 0);
		if (rc) {
			error_text("Dump target '%s'", dump->device[i]);
			return rc;
		}
		for (j = 0; j < i; j++) {
			if (!strcmp(dump->device[i], dump->device[j])) {
				error_text("Dump target list '%s' contains "
					   "duplicate entry '%s'.",
					   dump->device_list, dump->device[i]);
				return -1;
			}
		}
	}
	return 0;
}

static int
check_secure_boot(struct job_data *job)
{
	switch (job->is_secure) {
	case SECURE_BOOT_UNDEFINED:
	case SECURE_BOOT_DISABLED:
	case SECURE_BOOT_ENABLED:
	case SECURE_BOOT_AUTO:
		return 0;
	default:
		error_reason("Invalid secure boot setting '%d'",
			     job->is_secure);
		return -1;
	}
}

static int
check_job_data(struct job_data* job)
{
	int rc = -1;

	/* Check for missing information */
	if (job->target.bootmap_dir != NULL) {
		rc = misc_check_writable_directory(job->target.bootmap_dir);
		if (rc) {
			if (job->name == NULL) {
				error_text("Target directory '%s'",
					   job->target.bootmap_dir);
			} else {
				error_text("Target directory '%s' in section "
					   "'%s'",
					   job->target.bootmap_dir, job->name);
			}
			return rc;
		}
	}
	switch (job->id) {
	case job_print_usage:
	case job_print_version:
		rc = 0;
		break;
	case job_ipl:
		rc = check_job_ipl_data(&job->data.ipl, job->name);
		break;
	case job_menu:
		rc = check_job_menu_data(&job->data.menu);
		break;
	case job_segment:
		rc = check_job_segment_data(&job->data.segment, job->name);
		break;
	case job_dump_partition:
		rc = check_job_dump_data(&job->data.dump, job->name);
		break;
	case job_ipl_tape:
		rc = check_job_ipl_tape_data(&job->data.ipl_tape, job->name);
		break;
	case job_mvdump:
		rc = check_job_mvdump_data(&job->data.mvdump, job->name);
	}
	if (!rc)
		rc = check_secure_boot(job);
	return rc;
}

static int
extract_address (char* string, address_t* address)
{
	unsigned long long result;

	/* Find trailing comma */
	string = strrchr(string, ',');
	if (string != NULL) {
		/* Try to scan a hexadecimal address */
		if (sscanf(string + 1, "%llx", &result) == 1) {
			/* Got a match, remove address from string */
			*string = '\0';
			*address = (address_t) result;
			return 0;
		}
	}
	return -1;
}


static int
extract_memsize(char* string, uint64_t* size)
{
	unsigned long long result;

	/* Find trailing comma */
	string = strrchr(string, ',');
	if (string == NULL)
		return -1;
	if (sscanf(string + 1, "%lld", &result) != 1)
		return -1;
	switch(string[strlen(string) - 1]) {
	case 'G':
	case 'g':
		/* Number in gigabytes */
		result *= 1024LL * 1024LL * 1024LL;
		break;
	case 'M':
	case 'm':
		/* Number in megabytes*/
		result *= 1024LL * 1024LL;
		break;
	case 'K':
	case 'k':
		/* Number in kilobytes */
		result *= 1024LL;
		break;
	default:
		/* Number in bytes */
		break;
	}
	*string = '\0';
	*size = result;
	return 0;
}


static char*
append_parmline(char* a, char* b)
{
	char* buffer;
	int insert_blank;

	/* Insert blank if none is present at end of A */
	if (strlen(a) == 0)
		insert_blank = 0;
	else
		insert_blank = (a[strlen(a) - 1] != ' ');
	buffer = misc_malloc(strlen(a) + strlen(b) + (insert_blank ? 2 : 1));
	if (buffer != NULL) {
		if (insert_blank)
			sprintf(buffer, "%s %s", a, b);
		else
			sprintf(buffer, "%s%s", a, b);
	}
	return buffer;
}


/* Combine given parmfile FILENAME and parmline LINE into resulting PARMLINE
 * by appending lines as necessary. Parmline load address will be stored in
 * ADDRESS. */
static int
get_parmline(char* filename, char* line, char** parmline, address_t* address,
	     char* section)
{
	char* buffer;
	char* result;
	address_t addr;
	size_t len;
	int rc;
	int from;
	int to;
	int got_lf;

	addr = UNSPECIFIED_ADDRESS;
	if (filename != NULL) {
		/* Need a filename copy to be able to change it */
		filename = misc_strdup(filename);
		if (filename == NULL)
			return -1;
		extract_address(filename, &addr);
		rc = misc_read_file(filename, &buffer, &len, 1);
		if (rc) {
			if (section == NULL)
				error_text("Parmfile '%s'", filename);
			else {
				error_text("Parmfile '%s' in section '%s'",
					   filename, section);
			}
			free(filename);
			return rc;
		}
		free(filename);
		/* Remove \n's from parmfile */
		got_lf = 0;
		for (from=0, to=0; buffer[from] != 0; from++)
			if (buffer[from] != '\n') {
				buffer[to++] = buffer[from];
				got_lf = 0;
			} else {
				if (!got_lf)
					buffer[to++] = ' ';
				got_lf = 1;
			}
		buffer[to] = 0;
		/* Combine parmfile and parmline if present */
		if (line == NULL)
			result = buffer;
		else {
			/* Append parmline to end of parmfile content */
			result = append_parmline(buffer, line);
			free(buffer);
			if (result == NULL)
				return -1;
		}
	} else if (line != NULL) {
		result = misc_strdup(line);
		if (result == NULL)
			return -1;

	} else result = NULL;
	/* Check for maximum length */
	if (result) {
		len = strlen(result);
		if (len > MAXIMUM_PARMLINE_SIZE) {
			error_text("The length of the parameters line "
				   "(%d bytes) exceeds the allowed maximum "
				   "(%d bytes)", len, MAXIMUM_PARMLINE_SIZE);
			free(result);
			return -1;
		}
	}
	*parmline = result;
	*address = addr;
	return 0;
}


#define	MEGABYTE_MASK	(1024LL * 1024LL - 1LL)

int
type_from_target(char *target, disk_type_t *type)
{
	switch (scan_get_target_type(target)) {
	case target_type_scsi:
		*type = disk_type_scsi;
		return 0;
	case target_type_fba:
		*type = disk_type_fba;
		return 0;
	case target_type_ldl:
		*type = disk_type_eckd_ldl;
		return 0;
	case target_type_cdl:
		*type = disk_type_eckd_cdl;
		return 0;
	default:
		return -1;
	}
}

static int
get_job_from_section_data(char* data[], struct job_data* job, char* section)
{
	int rc;

	switch (scan_get_section_type(data)) {
	case section_ipl:
		/* IPL job */
		job->id = job_ipl;
		/* Fill in name of bootmap directory */
		job->target.bootmap_dir =
			misc_strdup(data[(int) scan_keyword_target]);
		if (job->target.bootmap_dir == NULL)
			return -1;
		/* Fill in target */
		if (data[(int) scan_keyword_targetbase] != NULL) {
			job->target.targetbase =
				misc_strdup(data[(int)
				scan_keyword_targetbase]);
			if (job->target.targetbase == NULL)
				return -1;
		}
		if (data[(int) scan_keyword_targettype] != NULL) {
			if (type_from_target(
				data[(int) scan_keyword_targettype],
				&job->target.targettype))
				return -1;
		}
		if (data[(int) scan_keyword_targetgeometry] != NULL) {
			job->target.targetcylinders =
				atoi(strtok(data[(int)
				scan_keyword_targetgeometry], ","));
			job->target.targetheads = atoi(strtok(NULL, ","));
			job->target.targetsectors = atoi(strtok(NULL, ","));
		}
		if (data[(int) scan_keyword_targetblocksize] != NULL)
			job->target.targetblocksize =
				atoi(data[(int) scan_keyword_targetblocksize]);
		if (data[(int) scan_keyword_targetoffset] != NULL)
			job->target.targetoffset =
				atol(data[(int) scan_keyword_targetoffset]);
		/* Fill in name and address of image file */

		job->data.ipl.image = misc_strdup(
					data[(int) scan_keyword_image]);
		if (job->data.ipl.image == NULL)
			return -1;
		if (extract_address(job->data.ipl.image,
				    &job->data.ipl.image_addr)) {
			job->data.ipl.image_addr = IMAGE_LOAD_ADDRESS;
		}
		/* Fill in parmline */
		rc = get_parmline(data[(int) scan_keyword_parmfile],
				  data[(int) scan_keyword_parameters],
				  &job->data.ipl.parmline,
				  &job->data.ipl.parm_addr, section);
		if (rc)
			return rc;
		/* Fill in name and address of ramdisk file */
		if (data[(int) scan_keyword_ramdisk] != NULL) {
			job->data.ipl.ramdisk =
				misc_strdup(data[(int) scan_keyword_ramdisk]);
			if (job->data.ipl.ramdisk == NULL)
				return -1;
			if (extract_address(job->data.ipl.ramdisk,
					    &job->data.ipl.ramdisk_addr)) {
				job->data.ipl.ramdisk_addr =
					UNSPECIFIED_ADDRESS;
			}
		}
		/* Fill in kdump */
		if (data[(int) scan_keyword_kdump] != NULL) {
			if (strcmp(data[(int) scan_keyword_kdump],
				   "auto") == 0) {
				job->data.ipl.is_kdump = 1;
			} else {
				error_reason("Invalid kdump setting '%s'",
					     data[(int) scan_keyword_kdump]);
				return -1;
			}
		}
		/* Fill in secure boot */
		if (data[(int) scan_keyword_secure] != NULL) {
			rc = set_secure_ipl(data[(int) scan_keyword_secure],
					    &job->is_secure);
			if (rc)
				return rc;
		}
		break;
	case section_ipl_tape:
		/* Tape IPL job */
		job->id = job_ipl_tape;
		/* Fill in name of tape device */
		job->data.ipl_tape.device =
			misc_strdup(data[(int) scan_keyword_tape]);
		if (job->data.ipl_tape.device == NULL)
			return -1;
		/* Fill in name and address of image file */
		job->data.ipl_tape.image = misc_strdup(
					data[(int) scan_keyword_image]);
		if (job->data.ipl_tape.image == NULL)
			return -1;
		if (extract_address(job->data.ipl_tape.image,
				    &job->data.ipl_tape.image_addr)) {
			job->data.ipl_tape.image_addr = IMAGE_LOAD_ADDRESS;
		}
		/* Fill in parmline */
		rc = get_parmline(data[(int) scan_keyword_parmfile],
				  data[(int) scan_keyword_parameters],
				  &job->data.ipl_tape.parmline,
				  &job->data.ipl_tape.parm_addr, section);
		if (rc)
			return rc;
		/* Fill in name and address of ramdisk file */
		if (data[(int) scan_keyword_ramdisk] != NULL) {
			job->data.ipl_tape.ramdisk =
				misc_strdup(data[(int) scan_keyword_ramdisk]);
			if (job->data.ipl_tape.ramdisk == NULL)
				return -1;
			if (extract_address(job->data.ipl_tape.ramdisk,
					    &job->data.ipl_tape.ramdisk_addr)) {
				job->data.ipl_tape.ramdisk_addr =
					UNSPECIFIED_ADDRESS;
			}
		}
		break;
	case section_segment:
		/* SEGMENT LOAD job */
		job->id = job_segment;
		/* Fill in name of bootmap directory */
		job->target.bootmap_dir =
			misc_strdup(data[(int) scan_keyword_target]);
		if (job->target.bootmap_dir == NULL)
			return -1;
		/* Fill in segment filename */
		job->data.segment.segment =
			misc_strdup(data[(int) scan_keyword_segment]);
		if (job->data.segment.segment == NULL)
			return -1;
		extract_address(job->data.segment.segment,
				&job->data.segment.segment_addr);
		break;
	case section_dump:
		/* DUMP TO PARTITION job */
		job->id = job_dump_partition;
		/* Fill in device node filename */
		job->data.dump.device = misc_strdup(
					   data[(int) scan_keyword_dumpto]);
		if (job->data.dump.device == NULL)
			return -1;
		/* Check for mem size specification */
		if (extract_memsize(job->data.dump.device,
				    &job->data.dump.mem) == 0) {
			/* Ensure megabyte alignment of size */
			job->data.dump.mem =
				(job->data.dump.mem + MEGABYTE_MASK) &
					~MEGABYTE_MASK;
			printf("Found specification of dump size limit "
			       "to %lldMB\n",
			       (unsigned long long) job->data.dump.mem /
			       		(1024LL * 1024LL));
		}
		else
			job->data.dump.mem = -1LL;
		break;
	case section_mvdump:
		/* DUMP TO MULTI-VOLUME job */
		job->id = job_mvdump;
		/* Fill in name of file containing the multiple partitions */
		job->data.mvdump.device_list = misc_strdup(
					       data[(int) scan_keyword_mvdump]);
		if (job->data.mvdump.device_list == NULL)
			return -1;
		/* Check for mem size specification */
		if (extract_memsize(job->data.mvdump.device_list,
				    &job->data.mvdump.mem) == 0) {
			/* Ensure megabyte alignment of size */
			job->data.mvdump.mem =
				(job->data.mvdump.mem + MEGABYTE_MASK) &
					~MEGABYTE_MASK;
			printf("Found specification of dump size limit "
			       "to %lldMB\n",
			       (unsigned long long) job->data.mvdump.mem /
			       		(1024LL * 1024LL));
		} else
			job->data.mvdump.mem = -1LL;
		break;
	default:
		/* Should not happen */
		job->id = job_print_usage;
		break;
	}
	return 0;
}


static int
get_menu_job(struct scan_token* scan, char* menu, struct job_data* job)
{
	char* data[SCAN_KEYWORD_NUM];
	struct job_data* temp_job;
	char* section;
	int index;
	int i;
	int j;
	int current;
	int rc;

	job->id = job_menu;
	job->name = misc_strdup(menu);
	if (job->name == NULL)
		return -1;
	/* Extract menu job from configuration data in SCAN */
	index = scan_find_section(scan, menu, scan_id_menu_heading, 0);
	if (index<0) {
		error_reason("Menu section '%s' not found", menu);
		return -1;
	}
	/* Count menu entries, find default entry and target directory */
	job->data.menu.num = 0;
	job->data.menu.default_pos = -1;
	job->data.menu.prompt = MENU_DEFAULT_PROMPT;
	job->data.menu.timeout = MENU_DEFAULT_TIMEOUT;
	for (i=index+1; (scan[i].id != scan_id_empty) &&
			(scan[i].id != scan_id_section_heading) &&
			(scan[i].id != scan_id_menu_heading); i++) {
		if (scan[i].id == scan_id_number_assignment) {
			if (job->data.menu.default_pos < 0)
				job->data.menu.default_pos =
					scan[i].content.number.number;
			job->data.menu.num++;
		} else if (scan[i].id == scan_id_keyword_assignment) {
			switch (scan[i].content.keyword.keyword) {
				case scan_keyword_default:
					job->data.menu.default_pos =
					  atol(scan[i].content.keyword.value);
					break;
				case scan_keyword_prompt:
					job->data.menu.prompt =
					  atol(scan[i].content.keyword.value);
					break;
				case scan_keyword_timeout:
					job->data.menu.timeout =
					  atol(scan[i].content.keyword.value);
					break;
				case scan_keyword_secure:
					rc = set_secure_ipl(
						scan[i].content.keyword.value,
						&job->is_secure);
					if (rc)
						return rc;
					break;
				case scan_keyword_target:
					job->target.bootmap_dir = misc_strdup(
						scan[i].content.keyword.value);
					if (job->target.bootmap_dir == NULL)
						return -1;
					break;
				case scan_keyword_targetbase:
					job->target.targetbase = misc_strdup(
						scan[i].content.keyword.value);
					if (job->target.targetbase == NULL)
						return -1;
					break;
				case scan_keyword_targettype:
					if (type_from_target(
						scan[i].content.keyword.value,
						&job->target.targettype))
						return -1;
					break;
				case scan_keyword_targetgeometry:
					job->target.targetcylinders =
						atoi(strtok(
						scan[i].content.keyword.value,
						","));
					job->target.targetheads =
						atoi(strtok(NULL, ","));
					job->target.targetsectors =
						atoi(strtok(NULL, ","));
					break;
				case scan_keyword_targetblocksize:
					job->target.targetblocksize =
						atoi(
						scan[i].content.keyword.value);
					break;
				case scan_keyword_targetoffset:
					job->target.targetoffset =
						atol(
						scan[i].content.keyword.value);
					break;
				default:
					/* Should not happen */
					break;
			}
		}
	}
	if (job->data.menu.num == 0) {
		/* Should not happen */
		error_reason("No entries found in menu '%s'", menu);
		return -1;
	}
	/* Allocate array */
	job->data.menu.entry = misc_malloc(sizeof(struct job_menu_entry) *
					   job->data.menu.num);
	if (job->data.menu.entry == NULL)
		return -1;
	memset((void *) job->data.menu.entry, 0,
	       sizeof(struct job_menu_entry) * job->data.menu.num);
	/* Fill in data */
	current = 0;
	job->data.menu.entry->is_secure = SECURE_BOOT_UNDEFINED;
	for (i=index+1; (scan[i].id != scan_id_empty) &&
			(scan[i].id != scan_id_section_heading) &&
			(scan[i].id != scan_id_menu_heading); i++) {
		if (scan[i].id != scan_id_number_assignment)
			continue;
		job->data.menu.entry[current].pos =
			scan[i].content.number.number;
		job->data.menu.entry[current].name =
			misc_strdup(scan[i].content.number.value);
		if (job->data.menu.entry[current].name == NULL)
			return -1;
		section = job->data.menu.entry[current].name;
		/* Search for section in config file */
		j = scan_find_section(scan, section, scan_id_section_heading,
				      0);
		if (j<0) {
			error_reason("Configuration section '%s' not found",
				     section);
			return -1;
		}
		/* Get section_data from scan */
		memset(&data, 0, sizeof(data));
		for (j++; scan[j].id == scan_id_keyword_assignment; j++)
			data[(int) scan[j].content.keyword.keyword] =
				scan[j].content.keyword.value;
		/* Get job from section_data */
		temp_job = (struct job_data *) misc_malloc(
						sizeof(struct job_data));
		if (temp_job == NULL)
			return -1;
		memset((void *) temp_job, 0, sizeof(struct job_data));
		temp_job->is_secure = SECURE_BOOT_UNDEFINED;
		rc = get_job_from_section_data(data, temp_job,
					job->data.menu.entry[current].name);
		if (rc) {
			job_free(temp_job);
			return rc;
		}
		/* Copy data from temporary job */
		switch (temp_job->id) {
			case job_ipl:
				job->data.menu.entry[current].id = job_ipl;
				job->data.menu.entry[current].data.ipl =
					temp_job->data.ipl;
				job->data.menu.entry[current].is_secure =
					temp_job->is_secure;
				memset((void *) &temp_job->data.ipl, 0,
				       sizeof(struct job_ipl_data));
				break;
			default:
				error_reason("Section '%s' cannot be included "
					     "in menu '%s'", section, menu);
				rc = -1;
				break;
		}
		job_free(temp_job);
		if (rc)
			return rc;
		current++;
	}
	return 0;
}


static int
get_default_section(struct scan_token* scan, char** section, int* is_menu)
{
	int i;

	/* Find defaultboot section */
	i = scan_find_section(scan, DEFAULTBOOT_SECTION,
			      scan_id_section_heading, 0);
	if (i<0) {
		error_reason("No '" DEFAULTBOOT_SECTION "' section found and "
			     "no section specified on command line");
		return -1;
	}
	/* Find 'default' or 'defaultmenu' keyword */
	for (i++; scan[i].id == scan_id_keyword_assignment; i++) {
		if (scan[i].content.keyword.keyword == scan_keyword_default) {
		    	*section = scan[i].content.keyword.value;
			*is_menu = 0;
		    	return 0;
		}
		if (scan[i].content.keyword.keyword ==
						scan_keyword_defaultmenu) {
		    	*section = scan[i].content.keyword.value;
			*is_menu = 1;
		    	return 0;
		}
	}
	/* Should not happen */
	error_reason("No default section specified");
	return -1;
}


/* Extract job data from configuration data in SCAN. SECTION specifies the
 * name of the section to use or NULL if the default section should be used.
 * Upon success, return zero, store job data in JOB and set NAME to point to
 * the section name. Return non-zero otherwise. */
static int
get_section_job(struct scan_token* scan, char* section, struct job_data* job,
		char* extra_parmline)
{
	char* data[SCAN_KEYWORD_NUM];
	char* buffer;
	int rc;
	int i;

	if (section == NULL) {
		rc = get_default_section(scan, &section, &i);
		if (rc)
			return rc;
		if (i) {
			/* 'defaultmenu' was specified */
			rc = get_menu_job(scan, section, job);
			return rc;
		}
	}
	if (strcmp(section, DEFAULTBOOT_SECTION) == 0) {
		error_reason("Special section '" DEFAULTBOOT_SECTION "' cannot "
			     "be used as target section");
		return -1;
	}
	/* Search for section in config file */
	i = scan_find_section(scan, section, scan_id_section_heading, 0);
	if (i<0) {
		error_reason("Configuration section '%s' not found", section);
		return -1;
	}
	job->name = misc_strdup(section);
	if (job->name == NULL)
		return -1;
	/* Get section_data from scan */
	memset(&data, 0, sizeof(data));
	for (i++; scan[i].id == scan_id_keyword_assignment; i++)
		data[(int) scan[i].content.keyword.keyword] =
			scan[i].content.keyword.value;
	/* Get job from section_data */
	rc = get_job_from_section_data(data, job, job->name);
	if (rc)
		return rc;
	/* Append extra parmline */
	if (extra_parmline != NULL) {
		switch (job->id) {
		case job_ipl:
			if (job->data.ipl.parmline == NULL)
				buffer = misc_strdup(extra_parmline);
			else {
				buffer = append_parmline(
						job->data.ipl.parmline,
						extra_parmline);
				free(job->data.ipl.parmline);
			}
			job->data.ipl.parmline = buffer;
			if (buffer == NULL)
				return -1;
			break;
		case job_segment:
			error_reason("Option 'parameters' cannot be used with "
				     "section '%s'", section);
			return -1;
			break;
		case job_dump_partition:
			error_reason("Option 'parameters' cannot be used with "
				     "partition dump section '%s'", section);
			return -1;
			break;
		default:
			/* Should not happen */
			break;
		}
	}
	return 0;
}


static int
get_job_from_config_file(struct command_line* cmdline, struct job_data* job)
{
	struct scan_token* scan;
	struct scan_token* new_scan;
	const char *filename = NULL;
	char *blsdir;
	char* source;
	int i, rc, scan_size;

	/* Read configuration file */
	if (cmdline->config != NULL) {
		/* Use config file as provided on command line */
		filename = cmdline->config;
		source = " (from command line)";
	} else if (getenv(ZIPL_CONF_VAR) != NULL) {
		/* Use config file specified by environment variable */
		filename = getenv(ZIPL_CONF_VAR);
		source = " (from environment variable "
			 ZIPL_CONF_VAR ")";
	} else {
		/* Use default config file */
		for (i = 0; zipl_conf[i]; i++) {
			if (misc_check_readable_file(zipl_conf[i]) == 0) {
				filename = zipl_conf[i];
				break;
			}
		}
		if (filename == NULL) {
			error_text("No zipl configuration was readable");
			return -1;
		}
		source = "";
	}
	printf("Using config file '%s'%s\n", filename, source);
	scan_size = scan_file(filename, &scan);
	if (scan_size <= 0) {
		error_text("Config file '%s'", filename);
		return scan_size;
	}
	/* Check if a BLS directory was provided on command line */
	if (cmdline->blsdir != NULL) {
		blsdir = cmdline->blsdir;
	} else {
		blsdir = ZIPL_DEFAULT_BLSDIR;
	}
	rc = scan_bls(blsdir, &scan, scan_size);
	if (rc) {
		error_text("BLS parsing '%s'", blsdir);
		return rc;
	}
	if ((cmdline->menu == NULL) && (cmdline->section == NULL)) {
		rc = scan_check_defaultboot(scan);
		if (rc < 0) {
			error_text("Config file '%s'", filename);
			scan_free(scan);
			return rc;
		}
		if (rc == 1) {
			new_scan = scan_build_automenu(scan);
			scan_free(scan);
			if (new_scan == NULL) {
				error_text("Config file '%s'", filename);
				return -1;
			}
			scan = new_scan;
		}
	}
	rc = scan_check(scan);
	if (rc) {
		error_text("Config file '%s'", filename);
		scan_free(scan);
		return rc;
	}
	/* maybe we need to update bls search path with target path */
	scan_update_bls_path(scan);
	/* Get job from config file data */
	if (cmdline->menu != NULL)
		rc = get_menu_job(scan, cmdline->menu, job);
	else {
		rc = get_section_job(scan, cmdline->section, job,
				cmdline->data[(int) scan_keyword_parameters]);
	}
	/* Make sure no '--parameters' option was specified when writing a 
	 * menu section. */
	if (job->id == job_menu &&
	    cmdline->data[(int) scan_keyword_parameters]) {
		error_text("Option 'parameters' cannot be used with a menu "
			   "section");
		rc = -1;
	}
	scan_free(scan);
	return rc;
}


int
job_get(int argc, char* argv[], struct job_data** data)
{
	struct command_line cmdline;
	struct job_data* job;
	int rc;

	rc = get_command_line(argc, argv, &cmdline);
	if (rc)
		return rc;
	job = (struct job_data *) misc_malloc(sizeof(struct job_data));
	if (job == NULL)
		return -1;
	memset((void *) job, 0, sizeof(struct job_data));
	/* Fill in global options */
	job->noninteractive = cmdline.noninteractive;
	job->verbose = cmdline.verbose;
	job->add_files = cmdline.add_files;
	job->data.mvdump.force = cmdline.force;
	job->dry_run = cmdline.dry_run;
	job->is_secure =  SECURE_BOOT_UNDEFINED;
	/* Get job data from user input */
	if (cmdline.help) {
		job->command_line = 1;
		job->id = job_print_usage;
	} else if (cmdline.version) {
		job->command_line = 1;
		job->id = job_print_version;
	} else if (cmdline.type != section_invalid) {
		job->command_line = 1;
		rc = get_job_from_section_data(cmdline.data, job, NULL);
	} else {
		job->command_line = 0;
		rc = get_job_from_config_file(&cmdline, job);
	}
	if (rc) {
		job_free(job);
		return rc;
	}
	if (cmdline.is_secure != SECURE_BOOT_UNDEFINED)
		job->is_secure = cmdline.is_secure;
	else if (job->id != job_menu && job->is_secure == SECURE_BOOT_UNDEFINED)
		job->is_secure = SECURE_BOOT_AUTO;

	/* Check job data for validity */
	rc = check_job_data(job);
	if (rc) {
		job_free(job);
		return rc;
	}
	*data = job;
	return rc;
}

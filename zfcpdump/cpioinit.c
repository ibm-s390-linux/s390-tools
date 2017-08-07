/*
 * cpioinit - Tool to create cpio archives
 *
 * This tool can be used to create a cpio initrd for the linux kernel.
 *
 * The executable init program needs to be specified as parameter.
 * The cpio archive is printed to stdout.
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Cpio archive new header structure
 */
struct cpio_newc_header {
	char c_magic[6];
	char c_ino[8];
	char c_mode[8];
	char c_uid[8];
	char c_gid[8];
	char c_nlink[8];
	char c_mtime[8];
	char c_filesize[8];
	char c_devmajor[8];
	char c_devminor[8];
	char c_rdevmajor[8];
	char c_rdevminor[8];
	char c_namesize[8];
	char c_check[8];
};

/*
 * Structure to specify a cpio archive entry
 */
struct cpio_line {
	struct cpio_newc_header head;
	const char *filename;
	char *data;
	unsigned int datasize;
};

/*
 * Fill line with zeros to be aligned to 4 bytes
 */
static int cpio_fill_aligned(int size)
{
	while (size % 4) {
		printf("%c", 0);
		size++;
	}
	return size;
}

/*
 * Print a cpio_line structure to stdout
 */
static void cpio_print_ln(struct cpio_line *line)
{
	unsigned int i, lnsize = 0;

	for (i = 0; i < sizeof(struct cpio_newc_header); i++)
		printf("%c", ((char *)&line->head)[i]);
	lnsize += sizeof(struct cpio_newc_header);

	if (line->filename != NULL) {
		printf("%s", line->filename);
		printf("%c", 0); /* print ending zero */
		lnsize += strlen(line->filename) + 1;
		lnsize = cpio_fill_aligned(lnsize);
	}

	if (line->data != NULL) {
		for (i = 0; i < line->datasize; i++)
			printf("%c", line->data[i]);
		lnsize += line->datasize;
		lnsize = cpio_fill_aligned(lnsize);
	}
}

/*
 * Write number in cpio new ascii format into header field with
 * size of 6 chars
 */
static void cpio_insert_num6(char *head, int num)
{
	char buf[7];

	/* Need memcpy because snprintf addes zero at the end */
	snprintf(buf, sizeof(buf), "%06x", num);
	memcpy(head, buf, 6);
}

/*
 * Write number in cpio new ascii format into header field with
 * size of 8 chars
 */
static void cpio_insert_num8(char *head, int num)
{
	char buf[9];

	/* Need memcpy because snprintf addes zero at the end */
	snprintf(buf, sizeof(buf), "%08x", num);
	memcpy(head, buf, 8);
}

/*
 * Write basics to cpio_newc_header managing the entry number,
 * thus each structure write has to call this function once
 */
static void cpio_header_init(struct cpio_newc_header *head)
{
	static int number;

	cpio_insert_num6(head->c_magic, 0x070701);
	cpio_insert_num8(head->c_ino, 0x2d1 + number);
	cpio_insert_num8(head->c_uid, 0);
	cpio_insert_num8(head->c_gid, 0);
	cpio_insert_num8(head->c_nlink, number);
	cpio_insert_num8(head->c_mtime, 0);
	cpio_insert_num8(head->c_check, 0);
	cpio_insert_num8(head->c_devmajor, 3);
	cpio_insert_num8(head->c_devminor, 1);
	number++;
}

/*
 * Writes directory in cpio archive structure to stdout
 */
static void cpio_write_dir(const char *dir)
{
	struct cpio_line line;

	cpio_header_init(&line.head);
	cpio_insert_num8(line.head.c_mode, 0x41ed);
	cpio_insert_num8(line.head.c_filesize, 0);
	cpio_insert_num8(line.head.c_rdevmajor, 0);
	cpio_insert_num8(line.head.c_rdevminor, 0);
	cpio_insert_num8(line.head.c_namesize, strlen(dir) + 1);
	line.filename = dir;
	line.data = NULL;
	cpio_print_ln(&line);
}

/*
 * Writes end of cpio archive to stdout
 */
static void cpio_write_tail()
{
	struct cpio_line line;
	int i;

	cpio_header_init(&line.head);
	cpio_insert_num8(line.head.c_ino, 0);
	cpio_insert_num8(line.head.c_mode, 0);
	cpio_insert_num8(line.head.c_filesize, 0);
	cpio_insert_num8(line.head.c_devmajor, 0);
	cpio_insert_num8(line.head.c_devminor, 0);
	cpio_insert_num8(line.head.c_rdevmajor, 0);
	cpio_insert_num8(line.head.c_rdevminor, 0);
	cpio_insert_num8(line.head.c_namesize, 11);
	line.filename = "TRAILER!!!";
	line.data = NULL;
	cpio_print_ln(&line);
	for (i = 0; i < 30; i++)
		printf("%c", 0);
}

/*
 * Writes device node in cpio archive structure to stdout
 */
static void cpio_write_nod(char *name, int major, int minor, int chardev)
{
	struct cpio_line line;

	cpio_header_init(&line.head);
	if (chardev == 1)
		cpio_insert_num8(line.head.c_mode, 0x21a4);
	else
		cpio_insert_num8(line.head.c_mode, 0x61a4);
	cpio_insert_num8(line.head.c_filesize, 0);
	cpio_insert_num8(line.head.c_rdevmajor, major);
	cpio_insert_num8(line.head.c_rdevminor, minor);
	cpio_insert_num8(line.head.c_namesize, strlen(name) + 1);
	line.filename = name;
	line.data = NULL;
	cpio_print_ln(&line);
}

/*
 * Writes file in cpio archiv structure to stdout
 */
static void cpio_write_file(char *name, char *filedata, int filesize)
{
	struct cpio_line line;

	cpio_header_init(&line.head);
	cpio_insert_num8(line.head.c_mode, 0x81ed);
	cpio_insert_num8(line.head.c_filesize, filesize);
	cpio_insert_num8(line.head.c_rdevmajor, 0);
	cpio_insert_num8(line.head.c_rdevminor, 0);
	cpio_insert_num8(line.head.c_namesize, strlen(name) + 1);
	line.filename = name;
	line.data = filedata;
	line.datasize = filesize;
	cpio_print_ln(&line);
}

/*
 * Read size bytes from file into buffer
 */
static int read_file(const char *file, char *buf, int size)
{
	int fh;

	fh = open(file, O_RDONLY);
	if (fh == -1) {
		fprintf(stderr, "Open %s failed (%s)\n", file, strerror(errno));
		return -1;
	}
	if (read(fh, buf, size) < 0) {
		fprintf(stderr, "Read %s failed (%s)\n", file, strerror(errno));
		close(fh);
		return -1;
	}
	close(fh);
	return 0;
}

/*
 * Program writes a cpio archive to stdout.
 *  - containing device nodes needed to run scsi dumper
 *  - expecting init program as parameter
 */
int main(int argc, char *argv[])
{
	char path[10], *filebuffer, *filename;
	struct stat st;
	int i;

	/* First read in init file */
	if (argc != 2) {
		fprintf(stderr, "Usage: cpioinit <init program>\n");
		return -1;
	}
	filename = argv[1];
	if (stat(filename, &st)) {
		fprintf(stderr, "Cannot open file: %s (%s)\n", filename,
			strerror(errno));
		return -1;
	}
	filebuffer = malloc(st.st_size);
	if (filebuffer == NULL) {
		fprintf(stderr, "Malloc %lu bytes failed\n", st.st_size);
		return -1;
	}
	if (read_file(filename, filebuffer, st.st_size))
		return -1;

	/* Write init */
	cpio_write_file("init", filebuffer, st.st_size);
	free(filebuffer);

	/* Define device nodes */
	cpio_write_dir("dev");
	cpio_write_dir("proc");
	cpio_write_dir("sys");
	cpio_write_dir("mnt");
	cpio_write_nod("dev/console", 5, 1, 1);
	cpio_write_nod("dev/null", 1, 3, 1);

	/* Write sda for access via part offset */
	cpio_write_nod("dev/sda", 8, 0, 0);

	/* Write sda 1 - 15 nodes */
	for (i = 1; i < 15; i++) {
		snprintf(path, sizeof(path), "dev/sda%d", i);
		cpio_write_nod(path, 8, i, 0);
	}
	cpio_write_tail();
	return 0;
}

/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "lib/util_file.h"
#include "lib/util_log.h"

#include "hsa.h"

long get_hsa_size(const char *zcore_hsa_path)
{
	long size;
	int ret;

	util_log_print(UTIL_LOG_DEBUG, "Reading HSA memory size from %s\n",
		       zcore_hsa_path);

	/* Read HSA size */
	ret = util_file_read_l(&size, 16, zcore_hsa_path);
	if (ret < 0) {
		util_log_print(UTIL_LOG_ERROR, "File read failed (%s)\n",
			       strerror(errno));
		return -1;
	}

	return size;
}

long get_hsa_vmcore_offset(const char *vmcore_path)
{
	Elf64_Ehdr elf_hdr;
	int fd = -1, n, i;
	long offset = -1;

	util_log_print(UTIL_LOG_DEBUG,
		       "Reading HSA memory offset from vmcore %s\n",
		       vmcore_path);

	/* Open vmcore file */
	fd = open(vmcore_path, O_RDONLY);
	if (fd < 0) {
		util_log_print(UTIL_LOG_ERROR, "open syscall failed (%s)\n",
			       strerror(errno));
		goto fail;
	}

	util_log_print(UTIL_LOG_DEBUG, "Reading vmcore ELF header\n");

	/* Read ELF header */
	n = read(fd, &elf_hdr, sizeof(Elf64_Ehdr));
	if (n < 0) {
		util_log_print(UTIL_LOG_ERROR, "read syscall failed (%s)\n",
			       strerror(errno));
		goto fail;
	} else if (n != sizeof(Elf64_Ehdr)) {
		util_log_print(UTIL_LOG_ERROR,
			       "read syscall read less data than expected (%s)\n",
			       strerror(errno));
		goto fail;
	}

	/* Verify ELF header */
	if ((memcmp(elf_hdr.e_ident, ELFMAG, SELFMAG) != 0) ||
	    elf_hdr.e_type != ET_CORE || elf_hdr.e_machine != EM_S390 ||
	    elf_hdr.e_ident[EI_CLASS] != ELFCLASS64) {
		util_log_print(UTIL_LOG_ERROR, "Invalid vmcore ELF header\n");
		goto fail;
	}

	util_log_print(UTIL_LOG_DEBUG,
		       "Reading vmcore ELF program header(s)\n");

	/* Read ELF program header(s) */
	n = lseek(fd, elf_hdr.e_phoff, SEEK_SET);
	if (n < 0) {
		util_log_print(UTIL_LOG_ERROR, "lseek syscall failed (%s)\n",
			       strerror(errno));
		goto fail;
	}
	/*
	 * Go through all ELF program headers and find one
	 * that starts at physical/virtual address 0x0.
	 */
	for (i = 0; i < elf_hdr.e_phnum; i++) {
		Elf64_Phdr elf_phdr;

		util_log_print(UTIL_LOG_DEBUG,
			       "Reading vmcore ELF program header #%d\n", i);

		n = read(fd, &elf_phdr, sizeof(Elf64_Phdr));
		if (n < 0) {
			util_log_print(UTIL_LOG_ERROR,
				       "read syscall failed (%s)\n",
				       strerror(errno));
			goto fail;
		} else if (n != sizeof(Elf64_Phdr)) {
			util_log_print(UTIL_LOG_ERROR,
				       "read syscall read less data than expected (%s)\n",
				       strerror(errno));
			goto fail;
		}

		util_log_print(UTIL_LOG_DEBUG,
			       "vmcore ELF program segment #%d: type=%lx vaddr=%lx paddr=%lx offset=%lx\n",
			       i, elf_phdr.p_type, elf_phdr.p_vaddr,
			       elf_phdr.p_paddr, elf_phdr.p_offset);

		/* HSA memory starts at physical/virtual address 0x0 */
		if (elf_phdr.p_type == PT_LOAD && elf_phdr.p_vaddr == 0 &&
		    elf_phdr.p_paddr == 0) {
			offset = elf_phdr.p_offset;
			break;
		}
	}

	if (offset < 0) {
		util_log_print(UTIL_LOG_ERROR,
			       "Couldn't find HSA memory offset in vmcore\n");
		goto fail;
	}

	util_log_print(UTIL_LOG_DEBUG, "HSA memory vmcore offset %lx\n",
		       offset);

	close(fd);

	return offset;

fail:
	if (fd >= 0)
		close(fd);
	return -1;
}

int release_hsa(const char *zcore_hsa_path)
{
	int ret;

	util_log_print(UTIL_LOG_INFO, "Release HSA memory via %s\n",
		       zcore_hsa_path);

	/* Release HSA memory */
	ret = util_file_write_s("0", zcore_hsa_path);
	if (ret < 0) {
		util_log_print(UTIL_LOG_ERROR, "File write failed (%s)\n",
			       strerror(errno));
		return -1;
	}

	/* Verify that HSA memory has been released */
	if (get_hsa_size(zcore_hsa_path) > 0) {
		util_log_print(UTIL_LOG_ERROR, "HSA memory release failed\n");
		return -1;
	}

	util_log_print(UTIL_LOG_INFO, "HSA memory successfully released\n");

	return 0;
}

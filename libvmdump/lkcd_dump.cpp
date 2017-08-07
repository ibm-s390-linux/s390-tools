/*
 * vmdump - z/VM dump conversion library
 *
 * LKCD dump classes: LKCDDump, LKCDDump32, LKCDDump64
 *
 * Copyright IBM Corp. 2004, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "lkcd_dump.h"

LKCDDump::LKCDDump(Dump* dump, const char* arch) {
	referenceDump = dump;
	dumpHeader.magic_number   = DUMP_MAGIC_NUMBER;
	dumpHeader.version        = DUMP_VERSION_NUMBER;
	dumpHeader.header_size    = sizeof(struct _lkcd_dump_header);
	dumpHeader.time.tv_sec    = dump->getDumpTime().tv_sec;
	dumpHeader.time.tv_usec   = dump->getDumpTime().tv_usec;
	strcpy(dumpHeader.utsname_machine, arch);
	dumpHeader.memory_size    = dump->getMemSize();
	dumpHeader.memory_start   = 0;
	dumpHeader.memory_end     = dump->getMemSize();
	dumpHeader.num_dump_pages = dump->getMemSize()/0x1000;
	dumpHeader.page_size      = 0x1000;
	dumpHeader.dump_compress  = DUMP_COMPRESS_GZIP;
	dumpHeader.dump_level     = DUMP_LEVEL_ALL;

	dumpHeaderAsm.magic_number = DUMP_ASM_MAGIC_NUMBER;
	dumpHeaderAsm.version = 1;
	dumpHeaderAsm.header_size = sizeof(dumpHeaderAsm);
}

int LKCDDump::compressGZIP(const char *old, uint32_t old_size, char *n,
			   uint32_t new_size)
{
	unsigned long len = old_size;
	int rc;

	rc = compress((Bytef*)n, &len, (const Bytef*)old, new_size);
	switch(rc) {
		case Z_OK:
			rc = len;
			break;
		case Z_BUF_ERROR:
			/* In this case the compressed output is bigger than */
			/* the uncompressed */
			rc = GZIP_NOT_COMPRESSED;
			break;
		case Z_MEM_ERROR:
			throw(DumpException("gzip call failed: out of memory"));
		case Z_DATA_ERROR:
			throw(DumpException("gzip call failed: input data " \
					    "corrupted!"));
		default:
			throw(DumpException("gzip call failed: unknown error"));
	}
	return rc;
}

void LKCDDump::writeDump(const char* fileName)
{
	char dump_header_buf[DUMP_HEADER_SIZE] = {};
	char dump_page_buf[DUMP_BUFFER_SIZE];
	char dpcpage[DUMP_PAGE_SIZE];
	uint32_t dp_size,dp_flags;
	ProgressBar progressBar;
	char buf[DUMP_PAGE_SIZE];
	struct _dump_page dp;
	uint64_t mem_loc = 0;
	ssize_t buf_loc = 0;
	int size, fd;

	if (fileName == NULL) {
		fd = STDOUT_FILENO;
	} else {
		fd = open(fileName, O_WRONLY | O_CREAT | O_TRUNC,
			  S_IRUSR | S_IWUSR);
		if (fd == -1) {
			char msg[1024];
			sprintf(msg, "Open of dump '%s' failed.", fileName);
			throw(DumpErrnoException(msg));
		}
	}

	/* write dump header */

	memcpy(dump_header_buf, &dumpHeader, sizeof(dumpHeader));
	memcpy(&dump_header_buf[sizeof(dumpHeader)], &dumpHeaderAsm,
	       sizeof(dumpHeaderAsm));
	if (write(fd, dump_header_buf, sizeof(dump_header_buf)) !=
	    sizeof(dump_header_buf)) {
		throw(DumpErrnoException("write failed"));
	}

	/* write memory */

	referenceDump->seekMem(0);

	while (mem_loc < dumpHeader.memory_size) {
		referenceDump->readMem(buf, DUMP_PAGE_SIZE);
		copyRegsToPage(mem_loc,buf);

		memset(dpcpage, 0, DUMP_PAGE_SIZE);
		/*
		 * Get the new compressed page size
		 */
		size = compressGZIP((char *)buf, DUMP_PAGE_SIZE,
				    (char *)dpcpage, DUMP_PAGE_SIZE);

		/*
		 * If compression failed or compressed was ineffective,
		 * we write an uncompressed page
		 */
		if (size == GZIP_NOT_COMPRESSED) {
			dp_flags = DUMP_DH_RAW;
			dp_size  = DUMP_PAGE_SIZE;
		} else {
			dp_flags = DUMP_DH_COMPRESSED;
			dp_size  = size;
		}
		dp.address = mem_loc;
		dp.size    = dp_size;
		dp.flags   = dp_flags;
		memcpy((void *)(dump_page_buf + buf_loc),
				(const void *)&dp, sizeof(dp));
		buf_loc += sizeof(dp);
		/*
		 * Copy the page of memory
		 */
		if (dp_flags & DUMP_DH_COMPRESSED) {
			/* Copy the compressed page */
			memcpy((void *)(dump_page_buf + buf_loc),
					(const void *)dpcpage, dp_size);
		} else {
			/* Copy directly from memory */
			memcpy((void *)(dump_page_buf + buf_loc),
					(const void *)buf, dp_size);
		}
		buf_loc += dp_size;
		if(write(fd, dump_page_buf, buf_loc) != buf_loc){
			throw(DumpErrnoException("write failed"));
		}
		buf_loc = 0;
		mem_loc += DUMP_PAGE_SIZE;
		progressBar.displayProgress(mem_loc/(1024*1024),
				dumpHeader.memory_size/(1024*1024));
	}

	/*
	 * Write end marker
	 */
	dp.address = 0x0;
	dp.size = 0x0;
	dp.flags = DUMP_DH_END;
	if(write(fd, &dp, sizeof(dp)) != sizeof(dp)){
		throw(DumpErrnoException("write failed"));
	}
	fprintf(stderr, "\n");
	if (fd != STDOUT_FILENO)
		close(fd);
}

struct timeval LKCDDump::getDumpTime(void) const
{
	struct timeval rc;

	rc.tv_sec = dumpHeader.time.tv_sec;
	rc.tv_usec = dumpHeader.time.tv_usec;
	return rc;
}

LKCDDump32::LKCDDump32(Dump* dump, const RegisterContent32& r)
	: LKCDDump(dump,"s390")
{
	unsigned int i;

	dumpHeaderAsm.real_cpu_cnt = (uint32_t) r.getNumCpus();
	for (i = 0; i < dumpHeaderAsm.real_cpu_cnt; i++) {
		if (!r.regSets[i].prefix)
			continue;
		dumpHeaderAsm.lc_vec[i] = r.regSets[i].prefix;
		dumpHeaderAsm.cpu_cnt++;
	}
	registerContent = r;
}

void LKCDDump32::copyRegsToPage(uint64_t offset, char *buf)
{
	int cpu;

	for(cpu = 0; cpu < registerContent.getNumCpus(); cpu++){
		if(offset == registerContent.regSets[cpu].prefix){
			memcpy(buf+0xd8,&registerContent.regSets[cpu].cpuTimer,
				sizeof(registerContent.regSets[cpu].cpuTimer));
			memcpy(buf+0xe0,&registerContent.regSets[cpu].clkCmp,
				sizeof(registerContent.regSets[cpu].clkCmp));
			memcpy(buf+0x100,&registerContent.regSets[cpu].psw,
				sizeof(registerContent.regSets[cpu].psw));
			memcpy(buf+0x108,&registerContent.regSets[cpu].prefix,
				sizeof(registerContent.regSets[cpu].prefix));
			memcpy(buf+0x120,&registerContent.regSets[cpu].acrs,
				sizeof(registerContent.regSets[cpu].acrs));
			memcpy(buf+0x160,&registerContent.regSets[cpu].fprs,
				sizeof(registerContent.regSets[cpu].fprs));
			memcpy(buf+0x180,&registerContent.regSets[cpu].gprs,
				sizeof(registerContent.regSets[cpu].gprs));
			memcpy(buf+0x1c0,&registerContent.regSets[cpu].crs,
				sizeof(registerContent.regSets[cpu].crs));
		}
	}
}

LKCDDump64::LKCDDump64(Dump* dump, const RegisterContent64& r)
	: LKCDDump(dump,"s390x")
{
	unsigned int i;

	dumpHeaderAsm.real_cpu_cnt = (uint32_t) r.getNumCpus();
	for (i = 0; i < dumpHeaderAsm.real_cpu_cnt; i++) {
		if (!r.regSets[i].prefix)
			continue;
		dumpHeaderAsm.lc_vec[i] = r.regSets[i].prefix;
		dumpHeaderAsm.cpu_cnt++;
	}
	registerContent = r;
}

void LKCDDump64::copyRegsToPage(uint64_t offset, char *buf)
{
	int cpu;

	for(cpu = 0; cpu < registerContent.getNumCpus(); cpu++){
		if(offset == (registerContent.regSets[cpu].prefix + 0x1000)){
			memcpy(buf+0x328,&registerContent.regSets[cpu].cpuTimer,
				sizeof(registerContent.regSets[cpu].cpuTimer));
			memcpy(buf+0x330,&registerContent.regSets[cpu].clkCmp,
				sizeof(registerContent.regSets[cpu].clkCmp));
			memcpy(buf+0x300,&registerContent.regSets[cpu].psw,
				sizeof(registerContent.regSets[cpu].psw));
			memcpy(buf+0x318,&registerContent.regSets[cpu].prefix,
				sizeof(registerContent.regSets[cpu].prefix));
			memcpy(buf+0x340,&registerContent.regSets[cpu].acrs,
				sizeof(registerContent.regSets[cpu].acrs));
			memcpy(buf+0x200,&registerContent.regSets[cpu].fprs,
				sizeof(registerContent.regSets[cpu].fprs));
			memcpy(buf+0x280,&registerContent.regSets[cpu].gprs,
				sizeof(registerContent.regSets[cpu].gprs));
			memcpy(buf+0x380,&registerContent.regSets[cpu].crs,
				sizeof(registerContent.regSets[cpu].crs));
			memcpy(buf+0x31c,&registerContent.regSets[cpu].fpCr,
				sizeof(registerContent.regSets[cpu].fpCr));
		}
	}
}

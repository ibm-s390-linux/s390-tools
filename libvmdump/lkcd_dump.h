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

#ifndef LKCD_DUMP_H
#define LKCD_DUMP_H

#include "lib/zt_common.h"

#include "dump.h"
#include "register_content.h"

#define UTS_LEN 65
#define DUMP_BUFFER_SIZE     0x2000  /* Size of dump buffer */

/* Standard header definitions */
#define DUMP_HEADER_SIZE    0x10000
#define DUMP_MAGIC_NUMBER   0xa8190173618f23edULL  /* Dump magic number  */
#define DUMP_ASM_MAGIC_NUMBER 0x733339302d64756dULL /* asm magic number */
#define DUMP_VERSION_NUMBER 0x8      /* Dump version number             */
#define DUMP_PANIC_LEN      0x100    /* Dump panic string length        */

/* Dump levels - type specific stuff added later */
#define DUMP_LEVEL_ALL         0x10  /* Dump all memory RAM and firmware */

/* Dump compression options */
#define DUMP_COMPRESS_GZIP     0x2   /* Use GZIP compression          */

/* Dump header flags */
#define DUMP_DH_RAW            0x1   /* Raw page (no compression) */
#define DUMP_DH_COMPRESSED     0x2   /* Page is compressed */
#define DUMP_DH_END            0x4   /* End marker on a full dump */

/* Dump page defines */
#define DUMP_PAGE_SHIFT     12ULL
#define DUMP_PAGE_SIZE      (1ULL << DUMP_PAGE_SHIFT)

#define GZIP_NOT_COMPRESSED -1

class LKCDDump : public Dump
{
public:
	LKCDDump(Dump*, const char *);
	virtual ~LKCDDump(void) {}
	inline virtual void readMem(char *UNUSED(buf), int UNUSED(size))
	{
		throw(DumpException("LKCDDump::readMem() not implemented!"));
	}
	inline int seekMem(uint64_t UNUSED(offset))
	{
		throw(DumpException("LKCDDump::seekMem() not implemented!"));
	}
	inline virtual uint64_t getMemSize() const
	{
		return dumpHeader.memory_size;
	}
	virtual struct timeval getDumpTime(void) const;
	virtual void writeDump(const char *fileName);
	virtual void copyRegsToPage(uint64_t offset, char *buf) = 0;
protected:
	struct _lkcd_dump_header {
		uint64_t magic_number; /* dump magic number,unique to verify */
				       /* dump */
		uint32_t version;      /* version number of this dump */
		uint32_t header_size;  /* size of this header */
		uint32_t dump_level;   /* level of this dump */
		uint32_t page_size;    /* page size (e.g. 4K, 8K, 16K, etc.) */
		uint64_t memory_size;  /* size of entire physical memory */
		uint64_t memory_start; /* start of physical memory */
		uint64_t memory_end;   /* end of physical memory */
		/* the number of dump pages in this dump specifically */
		uint32_t num_dump_pages;
		char panic_string[DUMP_PANIC_LEN];

		/* timeval depends on machine, two long values */
		struct {uint64_t tv_sec;
			uint64_t tv_usec;
		} time; /* the time of the system crash */

		/* the NEW utsname (uname) information -- in character form */
		/* we do this so we don't have to include utsname.h	 */
		/* plus it helps us be more architecture independent	*/
		char utsname_sysname[UTS_LEN];
		char utsname_nodename[UTS_LEN];
		char utsname_release[UTS_LEN];
		char utsname_version[UTS_LEN];
		char utsname_machine[UTS_LEN];
		char utsname_domainname[UTS_LEN];

		uint64_t current_task;
		uint32_t dump_compress; /* compression type used in this dump */
		uint32_t dump_flags;    /* any additional flags */
		uint32_t dump_device;   /* any additional flags */
		uint64_t s390_asm_magic;
		uint16_t cpu_cnt;
		uint32_t lowcore_ptr[512];
	} __packed;

	struct _lkcd_dump_header_asm {
		uint64_t	magic_number;
		uint32_t	version;
		uint32_t	header_size;
		uint16_t	cpu_cnt;
		uint16_t	real_cpu_cnt;
		uint32_t	lc_vec[512];
	} __packed;

	struct _dump_page {
		uint64_t address;	/* the address of this dump page */
		uint32_t size;		/* the size of this dump page */
		uint32_t flags;		/* flags (DUMP_COMPRESSED, DUMP_RAW */
					/* or DUMP_END) */
	} __packed;

	struct _lkcd_dump_header dumpHeader;
	struct _lkcd_dump_header_asm dumpHeaderAsm;

private:
	int compressGZIP(const char *old, uint32_t old_size, char *n,
			uint32_t new_size);
	Dump *referenceDump;
};

class LKCDDump32 : public LKCDDump
{
public:
	LKCDDump32(Dump *dump, const RegisterContent32 &rc);
	virtual void copyRegsToPage(uint64_t offset, char *buf);
private:
	RegisterContent32 registerContent;
};

class LKCDDump64 : public LKCDDump
{
public:
	LKCDDump64(Dump *dump, const RegisterContent64 &rc);
	virtual void copyRegsToPage(uint64_t offset, char *buf);
private:
	RegisterContent64 registerContent;
};

#endif /* LKCD_DUMP_H */

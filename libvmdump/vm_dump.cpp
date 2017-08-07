/*
 * vmdump - z/VM dump conversion library
 *
 * Register content classes:
 * VMDump, VMDumpClassic, VMDump64, VMDump64Big, VMDump32
 *
 * Copyright IBM Corp. 2004, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <stdint.h>
#include <time.h>

#include "vm_dump.h"

Dump::DumpType VMDump::getDumpType(const char* inputFileName)
{
	uint8_t fmbk_id[8] = {0xc8, 0xc3, 0xd7, 0xc4, 0xc6, 0xd4, 0xc2, 0xd2};
	struct _fir_basic  fir;
	struct _fmbk fmbk;
	struct _adsr adsr;
	char msg[200];
	FILE* fh;

	fh = fopen(inputFileName,"r");
	if (!fh) {
		sprintf(msg,"Could not open '%s'",inputFileName);
		throw DumpErrnoException(msg);
	}

	/* Record 1: adsr */
	dump_read(&adsr, sizeof(adsr), 1, fh);

        /* Record 2: fmbk */
	dump_seek(fh, 0x1000, SEEK_SET);
	if (fread(&fmbk, sizeof(fmbk), 1, fh) != 1) {
		if(ferror(fh)) {
			sprintf(msg,"Could not read header of vmdump '%s'",
				inputFileName);
			fclose(fh);
			throw DumpErrnoException(msg);
		} else{
			sprintf(msg,"Input file '%s' is not a vmdump",
				inputFileName);
			fclose(fh);
			throw DumpException(msg);
		}
	}

	/* Check if this is a vmdump */
	if (memcmp(fmbk.id, fmbk_id, 8) != 0 ||
	   adsr.dump_type != 0xe5d4c4e4d4d74040ULL) {
		fclose(fh);
		sprintf(msg, "Input file '%s' is not a vmdump", inputFileName);
		throw DumpException(msg);
	}

	/* Record 3-7: fir */
	dump_seek(fh, (fmbk.rec_nr_fir - 1) * 0x1000, SEEK_SET);
	if(fread(&fir, sizeof(fir), 1, fh) != 1) {
		if (ferror(fh)) {
			sprintf(msg,"Could not read header of vmdump '%s'",
				inputFileName);
			fclose(fh);
			throw DumpErrnoException(msg);
		}
		else{
			sprintf(msg, "Could not read header of vmdump '%s'",
				inputFileName);
			fclose(fh);
			throw DumpException(msg);
		}
	}
	fclose(fh);
	if (fir.fir_format == 0) {
		return DT_VM32;
	} else if (fir.fir_format == 0x02) {/*XXX && (fir.dump_format == 0x1))*/
		return DT_VM64_BIG;
	} else if (fir.fir_format == 0x82) {
		return DT_VM64;
	} else {
		return DT_UNKNOWN;
	}
}

VMDump::VMDump(const char *fileName) : Dump(fileName, "rb")
{
	uint8_t fmbk_id[8] = {0xc8, 0xc3, 0xd7, 0xc4, 0xc6, 0xd4, 0xc2, 0xd2};

	ebcdicAsciiConv = iconv_open("ISO-8859-1", "EBCDIC-US");

	/* Record 1: adsrRecord */

	dump_seek(fh,0,SEEK_SET);
	dump_read(&adsrRecord,sizeof(adsrRecord),1,fh);

	if(debug) {
		char buf[1024];
		int i;

		fprintf(stderr, "off=%d\n", adsrRecord.sec5_offset);
		dump_seek(fh, adsrRecord.sec5_offset, SEEK_SET);
		dump_read(buf, adsrRecord.sec5_len, 1, fh);
		ebcAsc(buf, adsrRecord.sec5_len);
		for (i=0; i < adsrRecord.sec5_len; i++) {
			if ((buf[i]==0) || iscntrl(buf[i]))
				buf[i]=' ';
		}
		buf[adsrRecord.sec5_len] = 0;
		printf("symptom string1: %s\n",buf);
	}

	/* Record 2: fmbk */

	dump_seek(fh,0x1000,SEEK_SET);
	dump_read(&fmbkRecord,sizeof(fmbkRecord),1,fh);

	/* Check if this is a vmdump */
	if(memcmp(fmbkRecord.id, fmbk_id, 8) != 0) {
		throw DumpException("Input file is not a vmdump");
	}

	/* Record 3-7: fir records read by subclasses */

	/* Record 8: albk */

	dump_seek(fh,(fmbkRecord.rec_nr_access-1)*0x1000 ,SEEK_SET);
	dump_read(&albkRecord,sizeof(albkRecord),1,fh);
}

struct timeval VMDump::getDumpTime(void) const
{
	struct timeval rc;

	s390TodToTimeval(adsrRecord.tod,&rc);
	return rc;
}

void VMDump::printDebug(void)
{
	struct timeval time;
	char buf[1024];

	s390TodToTimeval(adsrRecord.tod, &time);

	/* adsr */

	printf("time         : %s\n", ctime(&time.tv_sec));
	printf("stat1        : %x\n", adsrRecord.record_status_flag1);
	printf("stat2        : %x\n", adsrRecord.record_status_flag2);
	printf("sec 2     len: %i\n", adsrRecord.sec2_len);
	printf("sec 2.1   len: %i/%i\n", adsrRecord.sec2_1_len,
	       adsrRecord.sec2_1_offset);
	printf("sec 3     len: %i/%i\n", adsrRecord.sec3_len,
	       adsrRecord.sec3_offset);
	printf("sec 4     len: %i/%i\n", adsrRecord.sec4_len,
	       adsrRecord.sec4_offset);
	printf("sec 5     len: %i/%i\n", adsrRecord.sec5_len,
	       adsrRecord.sec5_offset);
	printf("sec 6     len: %i/%i\n", adsrRecord.sec6_len,
	       adsrRecord.sec6_offset);

	/* fmbk */

	ebcAsc(fmbkRecord.id, sizeof(fmbkRecord.id));
	fmbkRecord.id[7] = 0;
	printf("id           : %s\n", fmbkRecord.id);
	printf("fir    rec nr: %i\n", fmbkRecord.rec_nr_fir);
	printf("vec    rec nr: %i\n", fmbkRecord.rec_nr_vector);
	printf("access rec nr: %i\n", fmbkRecord.rec_nr_access);


	/* albk */

	memcpy(buf, albkRecord.id, sizeof(albkRecord.id));
	ebcAsc(buf, sizeof(albkRecord.id));
	buf[8]=0;
	printf("ALBK id      : %s\n",buf);

	/* asibk */
/*
  XXX
	memcpy(buf,asibkRecord.id,sizeof(asibkRecord.id));
	ebcAsc(buf,sizeof(asibkRecord.id));
	asibkRecord.id[8]=0;
	printf("ASIBK id     : %s\n",buf);
	printf("storage      : %x\n",asibkRecord.storage_size_2GB);
	printf("bitmapsrecs  : %i\n",asibkRecord.nr_of_recs_of_first_bit_map);
*/
}

void VMDump::printInfo(void)
{
	struct timeval time;

	s390TodToTimeval(adsrRecord.tod,&time);
	fprintf(stderr, "  date........: %s",ctime(&time.tv_sec));
}

int VMDump::seekMem(uint64_t offset)
{
	if (offset != 0) {
		return -1;
	}
	pageOffset = 0;
	return 0;
}

void VMDump::readMem(char* buf, int size)
{
	int i;

	if (pageOffset == 0)
		dump_seek(fh, memoryStartRecord, SEEK_SET);

	if (size % 0x1000 != 0) {
		throw(DumpException("internal error: VMDump::readMem() " \
		"can only handle sizes which are multiples of page size"));
	}

	for(i = 0; i < size; i += 0x1000) {
		if(testPage(pageOffset)) {
			dump_read(buf + i, 0x1000, 1, fh);
		} else {
			memset(buf + i, 0, 0x1000);
		}
		pageOffset += 1;
	}
}

VMDump::~VMDump(void)
{
}

/*****************************************************************************/
/* VMDumpClassic: traditional 32/64 bit vmdump (before z/VM 5.2)             */
/*****************************************************************************/

VMDumpClassic::VMDumpClassic(const char *fileName) : VMDump(fileName)
{
	int storageKeyPages,bitMapPages;

	pageOffset = 0;

	/* Record 9: asibk */

	dump_seek(fh,fmbkRecord.rec_nr_access * 0x1000,SEEK_SET);
	dump_read(&asibkRecord,sizeof(asibkRecord),1,fh);

	/* Record 10: bitmaps */

	dump_seek(fh,(fmbkRecord.rec_nr_access + 1)* 0x1000 ,SEEK_SET);
        bitmap = new char[asibkRecord.storage_size_2GB / (0x1000 * 8)];
	dump_read(bitmap,asibkRecord.storage_size_2GB / (0x1000*8),1,fh);

	bitMapPages=asibkRecord.storage_size_2GB / (0x1000 * 8);
	if (bitMapPages % 0x1000 != 0)
		bitMapPages = bitMapPages/0x1000 + 1;
	else
		bitMapPages = bitMapPages/0x1000;

	storageKeyPages=asibkRecord.storage_size_2GB / 0x1000;
	if(storageKeyPages % 0x1000 != 0) {
		storageKeyPages = storageKeyPages/0x1000 + 1;
	} else {
		storageKeyPages = storageKeyPages/0x1000;
	}

	/* Skip storage keys */

	memoryStartRecord = (fmbkRecord.rec_nr_access + 1) *0x1000 /* 0x9000 */
				+ (bitMapPages + storageKeyPages)*0x1000;
	if(debug) {
		printf("Mem Offset: %llx\n", (long long) memoryStartRecord);
	}
}

void VMDumpClassic::printInfo(void)
{
	VMDump::printInfo();
	fprintf(stderr, "  storage.....: %i MB\n",
			asibkRecord.storage_size_2GB/(1024*1024));
}

VMDumpClassic::~VMDumpClassic(void)
{
	delete bitmap;
}


/*****************************************************************************/
/* VMDump32: 32 bit vmdump                                                   */
/*****************************************************************************/

VMDump32::VMDump32(const char* filename) : VMDumpClassic(filename)
{
	int i;

	if(!fh) {
		return;
	}

	dump_seek(fh,(fmbkRecord.rec_nr_fir-1)* 0x1000 ,SEEK_SET);
	dump_read(&fir32Record,sizeof(fir32Record),1,fh);

	fir32OtherRecords = new _fir_other_32[fir32Record.online_cpus];
	for(i=0; i < fir32Record.online_cpus; i++) {
		/* fir other */
		dump_read(&fir32OtherRecords[i],sizeof(fir32OtherRecords[i]),1,
			  fh);
	}
	if(debug)
		printDebug();
}

RegisterContent32 VMDump32::getRegisterContent(void)
{
	RegisterContent32 rc;
	RegisterSet32     rs;
	int cpu;

	/* First CPU */

	memcpy(&rs.gprs,   &fir32Record.gprs, sizeof(rs.gprs));
	memcpy(&rs.crs,    &fir32Record.crs, sizeof(rs.crs));
	memcpy(&rs.acrs,   &fir32Record.acrs, sizeof(rs.acrs));
	memcpy(&rs.psw,    &fir32Record.psw, sizeof(rs.psw));
	memcpy(&rs.prefix, &fir32Record.prefix, sizeof(rs.prefix));
	memcpy(&rs.fprs,   &fir32Record.fprs, sizeof(rs.fprs));
	memcpy(&rs.cpuTimer, &fir32Record.cpu_timer, sizeof(rs.cpuTimer));
	memcpy(&rs.clkCmp, &fir32Record.clock_cmp, sizeof(rs.clkCmp));

	rc.addRegisterSet(rs);

	/* Other online cpus */

	for(cpu = 0; cpu < fir32Record.online_cpus; cpu++) {
		memcpy(&rs.gprs, &fir32OtherRecords[cpu].gprs, sizeof(rs.gprs));
		memcpy(&rs.crs,  &fir32OtherRecords[cpu].crs, sizeof(rs.crs));
		memcpy(&rs.acrs, &fir32OtherRecords[cpu].acrs, sizeof(rs.acrs));
		/* No psw for ESA vmdumps */
		rs.psw[0] = 0xdeadbeef;
		rs.psw[1] = 0xdeadbeef;
		memcpy(&rs.prefix, &fir32OtherRecords[cpu].prefix,
				sizeof(rs.prefix));
		memcpy(&rs.fprs, &fir32OtherRecords[cpu].fprs, sizeof(rs.fprs));
		memcpy(&rs.cpuTimer, &fir32OtherRecords[cpu].cpu_timer,
				sizeof(rs.cpuTimer));
		memcpy(&rs.clkCmp, &fir32OtherRecords[cpu].clock_cmp,
				sizeof(rs.clkCmp));
		rc.addRegisterSet(rs);
	}
	return rc;
}

void VMDump32::printDebug(void)
{
	int i;

	VMDump::printDebug();
	printf("prefix: %x\n", fir32Record.prefix);
	printf("cpus: %x\n", fir32Record.online_cpus);
	printf("psw: %08x %08x\n", fir32Record.psw[0], fir32Record.psw[1]);

	for (i=0; i < fir32Record.online_cpus; i++) {
		/* fir other */
		printf("prefix (%i): %x\n", i, fir32OtherRecords[i].prefix);
	}
}

void
VMDump32::printInfo(void)
{
	fprintf(stderr, "vmdump information:\n");
	fprintf(stderr, "  architecture: 32 bit\n");
	VMDumpClassic::printInfo();
	fprintf(stderr, "  cpus........: %x\n", fir32Record.online_cpus + 1);
}


VMDump32::~VMDump32(void)
{
	delete 	fir32OtherRecords;
}


/*****************************************************************************/
/* VMDump64: 64 bit vmdump for old vmdump format (z/VM < 5.2)                */
/*****************************************************************************/

VMDump64::VMDump64(const char* filename) : VMDumpClassic(filename)
{
	int i;

	if(!fh) {
		return;
	}

	dump_seek(fh,(fmbkRecord.rec_nr_fir-1)* 0x1000 ,SEEK_SET);
	dump_read(&fir64Record,sizeof(fir64Record),1,fh);

	fir64OtherRecords = new _fir_other_64[fir64Record.online_cpus];
	for (i=0; i < fir64Record.online_cpus; i++) {
		/* fir other */
		dump_read(&fir64OtherRecords[i], sizeof(fir64OtherRecords[i]),
			  1, fh);
	}
	if(debug)
		printDebug();
}

void VMDump64::printDebug(void)
{
	int i;

	VMDump::printDebug();
	printf("prefix: %x\n", fir64Record.prefix);
	printf("cpus: %x\n", fir64Record.online_cpus);
	printf("psw: %016llx %016llx\n", (long long)fir64Record.psw[0],
	       (long long)fir64Record.psw[1]);

	for (i=0; i < fir64Record.online_cpus; i++) {
		/* fir other */
		printf("prefix (%i): %x\n", i, fir64OtherRecords[i].prefix);
	}
}

void VMDump64::printInfo(void)
{
	fprintf(stderr, "vmdump information:\n");
	fprintf(stderr, "  architecture: 64 bit\n");
	VMDumpClassic::printInfo();
	fprintf(stderr, "  cpus........: %x\n",fir64Record.online_cpus + 1);
}


RegisterContent64 VMDump64::getRegisterContent(void)
{
	RegisterContent64 rc;
	RegisterSet64 rs;
	int cpu;

	/* First CPU */

	memcpy(&rs.gprs, &fir64Record.gprs, sizeof(rs.gprs));
	memcpy(&rs.crs, &fir64Record.crs, sizeof(rs.crs));
	memcpy(&rs.acrs, &fir64Record.acrs, sizeof(rs.acrs));
	memcpy(&rs.psw, &fir64Record.psw, sizeof(rs.psw));
	memcpy(&rs.prefix, &fir64Record.prefix, sizeof(rs.prefix));
	memcpy(&rs.fprs, &fir64Record.fprs, sizeof(rs.fprs));
	memcpy(&rs.cpuTimer, &fir64Record.cpu_timer, sizeof(rs.cpuTimer));
	memcpy(&rs.clkCmp, &fir64Record.clock_cmp, sizeof(rs.clkCmp));
	memcpy(&rs.fpCr, &fir64Record.fp_cntrl_reg, sizeof(rs.fpCr));

	rc.addRegisterSet(rs);

	/* other online cpus */

	for (cpu = 0; cpu < fir64Record.online_cpus; cpu++) {
		memcpy(&rs.gprs, &fir64OtherRecords[cpu].gprs, sizeof(rs.gprs));
		memcpy(&rs.crs, &fir64OtherRecords[cpu].crs, sizeof(rs.crs));
		memcpy(&rs.acrs, &fir64OtherRecords[cpu].acrs, sizeof(rs.acrs));
		memcpy(&rs.psw, &fir64OtherRecords[cpu].psw, sizeof(rs.psw));
		memcpy(&rs.prefix, &fir64OtherRecords[cpu].prefix,
				sizeof(rs.prefix));
		memcpy(&rs.fprs, &fir64OtherRecords[cpu].fprs, sizeof(rs.fprs));
		memcpy(&rs.cpuTimer, &fir64OtherRecords[cpu].cpu_timer,
				sizeof(rs.cpuTimer));
		memcpy(&rs.clkCmp, &fir64OtherRecords[cpu].clock_cmp,
				sizeof(rs.clkCmp));
		memcpy(&rs.fpCr, &fir64OtherRecords[cpu].fp_cntrl_reg,
				sizeof(rs.fpCr));
		rc.addRegisterSet(rs);
	}
	return rc;
}

VMDump64::~VMDump64(void)
{
	delete 	fir64OtherRecords;
}

/*****************************************************************************/
/* VMDump64Big: 64 bit vmdump with new big storage dump format               */
/*****************************************************************************/

VMDump64Big::VMDump64Big(const char* filename) : VMDump(filename)
{
	uint64_t pageNum, nrDumpedPages;
	int i, j;

	if(!fh) {
		return;
	}

	/* Record 9: asibk */

	dump_seek(fh, fmbkRecord.rec_nr_access * 0x1000,SEEK_SET);
	dump_read(&asibkRecordNew, sizeof(asibkRecordNew), 1, fh);

	/* Record 10: bitmaps: */
	/* Read all bitmap pages and setup bitmap array */

	pageNum = 0;
	nrDumpedPages = asibkRecordNew.storage_size_def_store / 0x1000;
	memoryStartRecord = (fmbkRecord.rec_nr_access +  1) * 0x1000;
	bitmap = new char[asibkRecordNew.storage_size_def_store/(0x1000 * 8)];
	if(!bitmap) {
		throw(DumpErrnoException("out of memory"));
	}
	memset(bitmap,0,asibkRecordNew.storage_size_def_store/(0x1000 * 8));

	dump_seek(fh,(fmbkRecord.rec_nr_access + 1)* 0x1000 ,SEEK_SET);

	do {
		char bmIndexPage[0x1000];

		dump_read(bmIndexPage, sizeof(bmIndexPage), 1, fh);
		memoryStartRecord += 0x1000;
		for (i=0; i < 0x1000; i++) {
			if(testBitmapPage(bmIndexPage, i)) {
				char bmPage[0x1000];

				dump_read(bmPage,sizeof(bmPage),1,fh);
				memoryStartRecord += 0x1000;
				for(j = 0; j < 0x1000; j++) {
					if(testBitmapKeyPage(bmPage, j)) {
						setPageBit(pageNum);
					}
					pageNum++;
					if(pageNum == nrDumpedPages) {
						goto all_bitmaps_read;
					}
				}
			} else {
				pageNum += 0x1000; /* Empty pages */
			}
		}
	} while (pageNum < nrDumpedPages);

all_bitmaps_read:

	if(debug)
		printf("Mem Offset: %llx\n", (long long)memoryStartRecord);

	dump_seek(fh, (fmbkRecord.rec_nr_fir-1)* 0x1000, SEEK_SET);
	dump_read(&fir64Record, sizeof(fir64Record), 1, fh);

	fir64OtherRecords = new _fir_other_64[fir64Record.online_cpus];
	for (i=0; i < fir64Record.online_cpus; i++) {
		/* fir other */
		dump_read(&fir64OtherRecords[i], sizeof(fir64OtherRecords[i]),
			  1, fh);
	}
	if(debug)
		printDebug();
}

void VMDump64Big::printDebug(void)
{
	int i;

	VMDump::printDebug();
	printf("prefix: %x\n", fir64Record.prefix);
	printf("cpus: %x\n", fir64Record.online_cpus);
	printf("psw: %016llx %016llx\n", (long long)fir64Record.psw[0],
					 (long long)fir64Record.psw[1]);

	for (i=0; i < fir64Record.online_cpus; i++) {
		/* fir other */
		printf("prefix (%i): %x\n", i, fir64OtherRecords[i].prefix);
	}
}

void VMDump64Big::printInfo(void)
{
	fprintf(stderr, "vmdump information:\n");
	fprintf(stderr, "  architecture: 64 bit (big)\n");
	fprintf(stderr, "  storage.....: %lli MB\n",
		(long long)asibkRecordNew.storage_size_def_store / (1024*1024));
	VMDump::printInfo();
	fprintf(stderr, "  cpus........: %x\n", fir64Record.online_cpus + 1);
}


RegisterContent64 VMDump64Big::getRegisterContent(void)
{
	RegisterContent64 rc;
	RegisterSet64     rs;
	int cpu;

	/* First CPU */

	memcpy(&rs.gprs, &fir64Record.gprs, sizeof(rs.gprs));
	memcpy(&rs.crs, &fir64Record.crs, sizeof(rs.crs));
	memcpy(&rs.acrs, &fir64Record.acrs, sizeof(rs.acrs));
	memcpy(&rs.psw, &fir64Record.psw, sizeof(rs.psw));
	memcpy(&rs.prefix, &fir64Record.prefix, sizeof(rs.prefix));
	memcpy(&rs.fprs, &fir64Record.fprs, sizeof(rs.fprs));
	memcpy(&rs.cpuTimer, &fir64Record.cpu_timer, sizeof(rs.cpuTimer));
	memcpy(&rs.clkCmp, &fir64Record.clock_cmp, sizeof(rs.clkCmp));
	memcpy(&rs.fpCr, &fir64Record.fp_cntrl_reg, sizeof(rs.fpCr));

	rc.addRegisterSet(rs);

	/* other online cpus */

	for(cpu = 0; cpu < fir64Record.online_cpus; cpu++) {
		memcpy(&rs.gprs, &fir64OtherRecords[cpu].gprs, sizeof(rs.gprs));
		memcpy(&rs.crs, &fir64OtherRecords[cpu].crs, sizeof(rs.crs));
		memcpy(&rs.acrs, &fir64OtherRecords[cpu].acrs, sizeof(rs.acrs));
		memcpy(&rs.psw, &fir64OtherRecords[cpu].psw, sizeof(rs.psw));
		memcpy(&rs.prefix, &fir64OtherRecords[cpu].prefix,
		       sizeof(rs.prefix));
		memcpy(&rs.fprs, &fir64OtherRecords[cpu].fprs, sizeof(rs.fprs));
		memcpy(&rs.cpuTimer, &fir64OtherRecords[cpu].cpu_timer,
		       sizeof(rs.cpuTimer));
		memcpy(&rs.clkCmp, &fir64OtherRecords[cpu].clock_cmp,
		       sizeof(rs.clkCmp));
		memcpy(&rs.fpCr, &fir64OtherRecords[cpu].fp_cntrl_reg,
		       sizeof(rs.fpCr));
		rc.addRegisterSet(rs);
	}
	return rc;
}

VMDump64Big::~VMDump64Big(void)
{
	delete  bitmap;
	delete 	fir64OtherRecords;
}

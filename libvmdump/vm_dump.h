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

/*===========================*
 * The format of an vmdump:  *
 *===========================*
 *---------------------------*
 * Symptom Record            *
 * (ADSR COPY) Record 1      *
 *---------------------------*
 * Dump File Map Record      *
 * (HCPDFMBK COPY) Record 2  *
 *---------------------------*
 * Dump File Info Record     *
 * (HCPDFIR COPY) Records 3-7*
 *---------------------------*
 * Vector Registers          *
 *     (optional)            *
 *---------------------------*
 * Access Lists (HCPDALBK)   *
 *---------------------------*
 * Address Space A           *
 *  Information and Map      *
 *  Record (HCPASIBK)        *
 *---------------------------*
 * Address Space A           *
 *  Bit Maps                 *
 *---------------------------*
 * Address Space A           *
 *  Key Maps                 *
 *---------------------------*
 * Address Space A           *
 *  Guest Storage            *
 *---------------------------*
 * Additional Address Spaces *
 *     ASIBK                 *
 *     Bit Maps              *
 *     Key Maps              *
 *     Guest Storage         *
 * *NOTE* These probably     *
 *  aren't in a Linux guest. *
 *---------------------------*
*/

#ifndef VMDUMP_H
#define VMDUMP_H

#include <iconv.h>
#include <string.h>

#include "lib/zt_common.h"

#include "dump.h"
#include "register_content.h"

class VMDump : public Dump
{
public:
	VMDump(const char *filename);
	virtual ~VMDump(void);
	virtual void readMem(char *buf, int size);
	virtual int seekMem(uint64_t offset);
	virtual struct timeval getDumpTime(void) const;

	void printDebug(void);
	void printInfo(void);

	static DumpType getDumpType(const char *);
	inline int testPage(uint64_t bit) const
	{
		return (bitmap[bit/8] & (1 << (7-(bit % 8))));
	}
	inline void setPageBit(uint64_t bit) const
	{
		bitmap[bit/8] |= (1 << (7-(bit % 8)));
	}
protected:
	/* Types */
	struct _adsr {
		/* Section 1*/
		uint16_t sr;
		uint32_t cpu_model;
		char     cpu_serial[6];
		uint32_t time_zone_conversion_factor;
		uint64_t tod;
		char     time_stamp_str[4];
		char     date_str[6];
		char     node_name[8];
		char     product_id[4];
		char     feature_level[8];
		uint8_t  record_status_flag1;
		uint8_t  record_status_flag2;
		uint64_t dump_type;

		/* Section 2*/
		char     arch_level[2];
		uint16_t sec2_len;
		uint16_t sec2_1_len;
		uint16_t sec2_1_offset;
		uint16_t sec3_len;
		uint16_t sec3_offset;
		uint16_t sec4_len;
		uint16_t sec4_offset;
		uint16_t sec5_len;
		uint16_t sec5_offset;
		uint16_t sec6_len;
		uint16_t sec6_offset;
	} __packed;

	struct _fmbk {
		char id[8];
		uint32_t rec_nr_fir;
		uint32_t rec_nr_vector;
		uint32_t rec_nr_access;
		uint32_t num_acc_recs;
		uint32_t num_addr_spaces;
		uint32_t rec_nr_asibk;
	} __packed;

	struct _fir_basic {
		char     filler1[15];
		uint8_t  dump_format;/* 0x1 for big storage dump, 0x2 for cp */
				     /* hard abend, 0x3 for cp soft abend    */
		char     filler2[171];
		uint8_t  fir_format; /* 0x2 for big esame, 0x82 for esame, */
				     /* 0x00 for esa */
	} __packed;

	struct _albk {
		char id[8];
	} __packed;

	/* Methods */
	inline void ebcAsc(char *in, char *out, size_t size) const
	{
		size_t size_out = size;
		size_t size_in = size;
		size_t rc;

		rc = iconv(ebcdicAsciiConv, &in, &size_in, &out, &size_out);
		if (rc == (size_t) -1)
			throw(DumpException("Code page translation EBCDIC-ASCII failed"));
	}

	/* Members */
	struct _adsr  adsrRecord;
	struct _fmbk  fmbkRecord;
	struct _albk  albkRecord;
	uint64_t memoryStartRecord;
	char   *bitmap;
	uint64_t pageOffset;
private:
	iconv_t ebcdicAsciiConv;
};

class VMDumpClassic : public VMDump
{
public:
	VMDumpClassic(const char *filename);
	virtual ~VMDumpClassic(void);
	void printInfo(void);
	inline virtual uint64_t getMemSize(void) const
	{
		return (uint64_t)asibkRecord.storage_size_2GB;
	}
protected:
	/* Types */
	struct _asibk {
		char     id[8];
		char     as_token[8];
		char     spaceid[33];
		char     reserved1[3];
		uint32_t storage_size_2GB;
		uint32_t dcss_bitmap_first_rec;
		uint32_t byte_past_highest_defined_byte;
		uint64_t format_of_as;
		char     dump_id[100];
		uint32_t nr_of_recs_of_first_bit_map;
	} __packed;


	/* Members */
	struct _asibk asibkRecord;

};

#define MAX_BKEY_PAGES 2

class VMDump64Big : public VMDump
{
public:
	VMDump64Big(const char *filename);
	virtual ~VMDump64Big(void);
	RegisterContent64 getRegisterContent(void);

	void printDebug(void);
	void printInfo(void);

	inline virtual uint64_t getMemSize(void) const
	{
		return (uint64_t)asibkRecordNew.storage_size_def_store;
	}
private:
	inline int testBitmapPage(char *page, uint64_t bit) const
	{
		return (page[bit/8] & (1 << (7-(bit % 8))));
	}

	inline int testBitmapKeyPage(char *page, uint64_t bit) const
	{
		return (page[bit] & 0x01);
	}

	/* types */
	struct _asibk_64_new {
		char     id[8];
		char     as_token[8];
		char     spaceid[33];
		char     reserved1[2];
		uint8_t  asibk_format;
		char     filler1[12];
		uint64_t storage_size_with_dcss;
		uint64_t storage_size_def_store;
		char     filler2[136];
		uint64_t online_storage_table[8]; /* for "def store config" */
		uint64_t fence1;
		uint64_t requested_range_table[8];
		uint64_t fence2;
		uint32_t record_number_of_first_bit_map; /* XXX */
	} __packed;

	struct _fir_64 {
		char     id[8];
		uint64_t reserved1;
		uint64_t gprs[16];
		uint32_t prefix;
		char     reserved2[5];
		uint64_t tod;
		char     reserved3[8];
		uint64_t cpu_timer;
		char     reserved4[7];
		uint8_t  flag;
		uint8_t  type;
		uint8_t  complete;
		uint8_t  fir_format; /* 0x82 for esame - 0x00 for esa */
		uint8_t  cont_flags;
		uint8_t  crypto_domain_index_reg;
		uint8_t  virt_cpu_info;
		uint8_t  arch_mode_id;
		uint64_t psw[2];
		uint64_t crs[16];
		uint64_t fprs[16];
		uint8_t  reserved5;
		uint64_t clock_cmp;
		char     reserved6[3];
		uint32_t tod_programmable_reg;
		uint32_t reserved_for_dvf[20];
		uint32_t acrs[16];
		uint32_t storage_size_2GB;
		uint32_t reserved7;
		uint32_t hcpsys_addr;
		uint32_t reserved8;
		uint64_t storage_size;
		uint32_t snap_area_map_blk;
		uint32_t reserved9;
		char     loc_mem[256];
		uint16_t online_cpus;
		uint16_t cpu_addr;
		uint16_t section_size_vector;
		uint16_t reserved10;
		char     asit_primary[8];
		char     space_id_primary[33];
		char     reserved12[3];
		uint16_t crypto_domain_index_mask;
		uint16_t reserved11;
		uint32_t fp_cntrl_reg;
		uint32_t reserved13;
		uint64_t reserved14[16];
	} __packed;

	struct _fir_other_64 {
		uint16_t cpu_addr;
		uint16_t vector_sec_size;
		uint8_t  crypto_index_reg;
		uint8_t  virt_cpu_info;
		uint16_t crypto_index_mask;
		uint32_t reserved1[2];
		uint64_t fprs[16];
		uint64_t gprs[16];
		uint64_t psw[2];
		uint32_t reserved2[2];
		uint32_t prefix;
		uint32_t fp_cntrl_reg;
		uint32_t reserved3;
		uint32_t tod;
		uint64_t cpu_timer;
		uint64_t clock_cmp;
		uint32_t reserved4[2];
		uint32_t acrs[16];
		uint64_t crs[16];
		uint64_t mc_interrupt_code;
		uint32_t reserved5;
		uint32_t external_damage_code;
		uint64_t mc_failing_storage_addr;
	} __packed;

	/* Members */
	struct   _asibk_64_new asibkRecordNew;
	struct   _fir_64 fir64Record;
	struct   _fir_other_64 *fir64OtherRecords;
};

class VMDump64 : public VMDumpClassic
{
public:
	VMDump64(const char *filename);
	virtual ~VMDump64(void);
	RegisterContent64 getRegisterContent(void);

	void printDebug(void);
	void printInfo(void);
private:
	/* Types */
	struct _fir_64 {
		char     id[8];
		uint64_t reserved1;
		uint64_t gprs[16];
		uint32_t prefix;
		char     reserved2[5];
		uint64_t tod;
		char     reserved3[8];
		uint64_t cpu_timer;
		char     reserved4[7];
		uint8_t  flag;
		uint8_t  type;
		uint8_t  complete;
		uint8_t  fir_format; /* 0x82 for esame - 0x00 for esa */
		uint8_t  cont_flags;
		uint8_t  crypto_domain_index_reg;
		uint8_t  virt_cpu_info;
		uint8_t  arch_mode_id;
		uint64_t psw[2];
		uint64_t crs[16];
		uint64_t fprs[16];
		uint8_t  reserved5;
		uint64_t clock_cmp;
		char     reserved6[3];
		uint32_t tod_programmable_reg;
		uint32_t reserved_for_dvf[20];
		uint32_t acrs[16];
		uint32_t storage_size_2GB;
		uint32_t reserved7;
		uint32_t hcpsys_addr;
		uint32_t reserved8;
		uint64_t storage_size;
		uint32_t snap_area_map_blk;
		uint32_t reserved9;
		char     loc_mem[256];
		uint16_t online_cpus;
		uint16_t cpu_addr;
		uint16_t section_size_vector;
		uint16_t reserved10;
		char     asit_primary[8];
		char     space_id_primary[33];
		char     reserved12[3];
		uint16_t crypto_domain_index_mask;
		uint16_t reserved11;
		uint32_t fp_cntrl_reg;
		uint32_t reserved13;
		uint64_t reserved14[16];
	} __packed;

	struct _fir_other_64 {
		uint16_t cpu_addr;
		uint16_t vector_sec_size;
		uint8_t  crypto_index_reg;
		uint8_t  virt_cpu_info;
		uint16_t crypto_index_mask;
		uint32_t reserved1[2];
		uint64_t fprs[16];
		uint64_t gprs[16];
		uint64_t psw[2];
		uint32_t reserved2[2];
		uint32_t prefix;
		uint32_t fp_cntrl_reg;
		uint32_t reserved3;
		uint32_t tod;
		uint64_t cpu_timer;
		uint64_t clock_cmp;
		uint32_t reserved4[2];
		uint32_t acrs[16];
		uint64_t crs[16];
		uint64_t mc_interrupt_code;
		uint32_t reserved5;
		uint32_t external_damage_code;
		uint64_t mc_failing_storage_addr;
	} __packed;

	/* Members */
	struct _fir_64 fir64Record;
	struct _fir_other_64 *fir64OtherRecords;
};

class VMDump32 : public VMDumpClassic
{
public:
	VMDump32(const char *filename);
	virtual ~VMDump32(void);
	RegisterContent32 getRegisterContent(void);
	void printDebug(void);
	void printInfo(void);
private:
	/* Types */
	struct _fir_32 {
		uint32_t gprs[16];
		uint32_t crs[16];
		uint64_t fprs[4];
		uint64_t tod;
		uint64_t cpu_timer;
		uint64_t clock_cmp;
		uint8_t  flag;
		uint8_t  type;
		uint8_t  complete;
		uint8_t  fir_format;
		uint32_t storage_size_2GB;
		char     loc_mem[256];
		uint32_t prefix;
		uint16_t online_cpus;
		uint8_t  cont_flags;
		uint8_t  crypto_domain_index_reg;
		uint8_t  virt_cpu_info;
		uint8_t  arch_mode_id;
		uint16_t crypto_domain_index_mask;
		uint32_t reserved1;
		uint32_t snap_area_map_blk;
		uint64_t reserved2;
		uint32_t hcpsys_addr;
		uint32_t reserved3[20];
		uint32_t psw[2];
		uint16_t cpu_addr;
		uint16_t section_size_vector;
		uint32_t acrs[16];
		char     asit_primary[8];
		char     space_id_primary[33];
		char     reserved4[131];
	} __packed;

	struct _fir_other_32 {
		uint16_t cpu_addr;
		uint16_t vector_sec_size;
		uint32_t prefix;
		uint8_t  crypto_index_reg;
		uint8_t  virt_cpu_info;
		uint16_t crypto_index_mask;
		uint32_t reserved1;
		uint64_t cpu_timer;
		uint64_t clock_cmp;
		uint64_t mc_interrupt_code;
		uint64_t reserved2;
		uint32_t mc_failing_storage_addr;
		uint32_t machine_dependent_region_code;
		uint32_t lixed_logout_area[4];
		char     reserved3[16];
		uint32_t acrs[16];
		uint64_t fprs[4];
		uint32_t gprs[16];
		uint32_t crs[16];
	} __packed;

	/* Members */
	struct _fir_32 fir32Record;
	struct _fir_other_32 *fir32OtherRecords;
};

#endif /* VMDUMP_H */

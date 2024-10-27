/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * VMDUMP format definitions
 *
 * Copyright IBM Corp. 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DF_VMDUMP_H
#define DF_VMDUMP_H

/*
 * The format of an vmdump
 *
 * Symptom Record: (ADSR COPY) Record 1
 * Dump File Map Record: (HCPDFMBK COPY) Record 2
 * Dump File Info Record: (HCPDFIR COPY) Records 3-7
 * Vector Registers: (optional)
 * Access Lists (HCPDALBK):
 * Address Space A: Information and Map Record (HCPASIBK)
 * Address Space A: Bit Maps
 * Address Space A: Key Maps
 * Address Space A: Guest Storage
 * Additional Address Spaces (not in linux):
 * - ASIBK
 * - Bit Maps
 * - Key Maps
 * - Guest Storage
 */

/*
 * Defines for VMDUMP magic numbers.
 */
const u8 ADSR_MAGIC[2] = { 0xe2, 0xd9 }; /* 'SR' EBCDIC */
const u8 VMDUMP_MAGIC[8] = { 0xe5, 0xd4, 0xc4, 0xe4, 0xd4, 0xd7, 0x40, 0x40 }; /* 'VMDUMP  ' EBCDIC */
const u8 FMBK_MAGIC[8] = { 0xc8, 0xc3, 0xd7, 0xc4, 0xc6, 0xd4, 0xc2, 0xd2 }; /* 'HCPDFMBK' EBCDIC */
const u8 ALBK_MAGIC[8] = { 0xc8, 0xc3, 0xd7, 0xc4, 0xc1, 0xd3, 0xc2, 0xd2 }; /* 'HCPDALBK' EBCDIC */

/*
 * Layout of dump symptom record . The ADSR is always the first record in
 * a dump file. Its size varies between 200 bytes and 4000 bytes
 */
struct vmd_adsr {
	/* Section 1*/
	u8 sr[sizeof(ADSR_MAGIC)];
	u32 cpu_model;
	u8 cpu_serial[6];
	u32 time_zone_conversion_factor;
	u64 tod;
	u8 time_stamp_str[4];
	u8 date_str[6];
	u8 node_name[8];
	u8 product_id[4];
	u8 feature_level[8];
	u8 record_status_flag1;
	u8 record_status_flag2;
	u8 dump_type[sizeof(VMDUMP_MAGIC)];

	/* Section 2*/
	u8 arch_level[2];
	u16 sec2_len;
	u16 sec2_1_len;
	u16 sec2_1_offset;
	u16 sec3_len;
	u16 sec3_offset;
	u16 sec4_len;
	u16 sec4_offset;
	u16 sec5_len;
	u16 sec5_offset;
	u16 sec6_len;
	u16 sec6_offset;
} __packed;

/*
 * Layout of Dump file map record. The DFMBK is always the second record in
 * a dump file. Its size is 4 KB
 */
struct vmd_fmbk {
	u8 id[sizeof(FMBK_MAGIC)];
	u32 rec_nr_fir;
	u32 rec_nr_vector;
	u32 rec_nr_access;
	u32 num_acc_recs;
	u32 num_addr_spaces;
	u32 rec_nr_asibk;
} __packed;

struct vmd_fir_basic { /* Dump file (basic) information record */
	u8 filler1[15];
	u8 dump_format; /* 0x1 --> big storage dump
			 * 0x2 --> cp hard abend
			 * 0x3 --> cp soft abend
			 */
	u8 filler2[171];
	u8 fir_format; /* 0x02 --> big esame (only one supported)
			* 0x82 --> esame
			* 0x00 --> esa
			*/
} __packed;

struct vmd_albk {
	u8 id[sizeof(ALBK_MAGIC)];
} __packed;

struct vmd_asibk_64_new {
	u8 id[8];
	u8 as_token[8];
	u8 spaceid[33];
	u8 reserved1[2];
	u8 asibk_format;
	u8 filler1[12];
	u64 storage_size_with_dcss;
	u64 storage_size_def_store;
	u8 filler2[136];
	u64 online_storage_table[8]; /* For "def store config" */
	u64 fence1;
	u64 requested_range_table[8];
	u64 fence2;
	u32 record_number_of_first_bit_map;
} __packed;

struct vmd_fir_64 {
	u8 id[8];
	u64 reserved1;
	u64 gprs[16];
	u32 prefix;
	u8 reserved2[5];
	u64 tod;
	u8 reserved3[8];
	u64 cpu_timer;
	u8 reserved4[7];
	u8 flag;
	u8 type;
	u8 complete;
	u8 fir_format; /* 0x82 for esame - 0x00 for esa */
	u8 cont_flags;
	u8 crypto_domain_index_reg;
	u8 virt_cpu_info;
	u8 arch_mode_id;
	u64 psw[2];
	u64 crs[16];
	u64 fprs[16];
	u8 reserved5;
	u64 clock_cmp;
	u8 reserved6[3];
	u32 tod_programmable_reg;
	u32 reserved_for_dvf[20];
	u32 acrs[16];
	u32 storage_size_2GB;
	u32 reserved7;
	u32 hcpsys_addr;
	u32 reserved8;
	u64 storage_size;
	u32 snap_area_map_blk;
	u32 reserved9;
	u8 loc_mem[256];
	u16 online_cpus;
	u16 cpu_addr;
	u16 section_size_vector;
	u16 reserved10;
	u8 asit_primary[8];
	u8 space_id_primary[33];
	u8 reserved12[3];
	u16 crypto_domain_index_mask;
	u16 reserved11;
	u32 fp_cntrl_reg;
	u32 reserved13;
	u64 reserved14[16];
} __packed;

struct vmd_fir_other_64 {
	u16 cpu_addr;
	u16 vector_sec_size;
	u8 crypto_index_reg;
	u8 virt_cpu_info;
	u16 crypto_index_mask;
	u32 reserved1[2];
	u64 fprs[16];
	u64 gprs[16];
	u64 psw[2];
	u32 reserved2[2];
	u32 prefix;
	u32 fp_cntrl_reg;
	u32 reserved3;
	u32 tod;
	u64 cpu_timer;
	u64 clock_cmp;
	u32 reserved4[2];
	u32 acrs[16];
	u64 crs[16];
	u64 mc_interrupt_code;
	u32 reserved5;
	u32 external_damage_code;
	u64 mc_failing_storage_addr;
} __packed;

#define DF_VMDUMP_HDR_SIZE                                                                         \
	(sizeof(struct vmd_adsr) + sizeof(struct vmd_fmbk) + sizeof(struct vmd_fir_basic) +        \
	 sizeof(struct vmd_albk) + sizeof(struct vmd_asibk_64_new) + sizeof(struct vmd_fir_64))

#endif

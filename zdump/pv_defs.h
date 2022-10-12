/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Secure execution/PV guest dump definitions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_DEFS_H
#define PV_DEFS_H

#include <stdint.h>

#include "lib/zt_common.h"

/* Special ELF section names used for Protected Virtualization Dumps */
#define PV_ELF_SECTION_NAME_COMPL  "pv_compl"
#define PV_ELF_SECTION_NAME_TWEAKS "pv_mem_meta"

#define PV_COMPL_DATA_VERSION_1	  ((uint32_t)1)
#define PV_SEC_CPU_DATA_VERSION_1 ((uint32_t)1)

/**
 * pv_tweak_nonce_t:
 *
 * Struct representing a tweak nonce.
 */
typedef struct {
	uint8_t value[16];
} pv_tweak_nonce_t __big_endian;

/**
 * pv_dump_completion_aad_v1_t:
 *
 * Struct representing the authenticated part of a PV dump completion v1
 */
typedef struct {
	uint32_t version;  /* 0000 */
	uint32_t len;	   /* 0004 */
	uint64_t res_0x8;  /* 0008 */
	uint8_t seed[64];  /* 0016 */
	uint8_t iv[12];	   /* 0080 */
	uint32_t res_0x92; /* 0092 */
} pv_dump_completion_aad_v1_t __big_endian;
STATIC_ASSERT(sizeof(pv_dump_completion_aad_v1_t) == 96)

/**
 * pv_dump_completion_confidential_area_v1_t:
 *
 * Struct representing the encrypted part of a PV dump completion v1
 */
typedef struct {
	pv_tweak_nonce_t nonce; /* 0096 */
	union {
		uint8_t key[64]; /* 0112 */
		struct {
			uint8_t key1[32]; /* 0112 */
			uint8_t key2[32]; /* 0144 */
		};
	};
	uint8_t res_0x176[96]; /* 0176 */
} pv_dump_completion_confidential_area_v1_t __big_endian;
STATIC_ASSERT(sizeof(pv_dump_completion_confidential_area_v1_t) == 176)

/**
 * pv_dump_completion_data_v1_t
 *
 * Struct to interpret the data returned by the `Complete Configuration Dump` UVC.
 */
typedef struct {
	pv_dump_completion_aad_v1_t aad;			     /* 0000 */
	pv_dump_completion_confidential_area_v1_t confidential_area; /* 0096 */
	uint8_t tag[16];					     /* 0272 */
								     /* 0288 */
} pv_dump_completion_data_v1_t __big_endian;
STATIC_ASSERT(sizeof(pv_dump_completion_data_v1_t) == 288)

/* Container data structures used to implement polymorphic behavior */
#define PV_STRUCT_NAME(_struct, _version) _struct##_v##_version##_t
#define PV_GET_STRUCT_DATA(_struct, _version, _container)                                          \
	_container->version != _version ?                                                          \
		NULL :                                                                             \
		&(((PV_STRUCT_NAME(_struct, _version) *)_container)->data)

#define PV_GET_DUMP_DATA_V1(_container) PV_GET_STRUCT_DATA(pv_dump_completion, 1, _container)

typedef struct {
	unsigned int version;
} pv_dump_completion_t;

typedef struct {
	pv_dump_completion_t super;
	pv_dump_completion_data_v1_t data;
} PV_STRUCT_NAME(pv_dump_completion, 1);

/**
 * pv_cpu_vector_register_t:
 *
 * Struct representing the PV CPU vector register
 */
typedef struct {
	uint64_t low;
	uint64_t high;
} pv_cpu_vector_register_t __big_endian;
STATIC_ASSERT(sizeof(pv_cpu_vector_register_t) == 16)

/**
 * pv_cpu_dump_aad_v1_t:
 *
 * Struct representing the authenticated part of a PV cpu dump v1
 */
typedef struct {
	uint32_t version;     /*  0000 */
	uint32_t len;	      /*  0004 */
	uint8_t iv[12];	      /*  0008 */
	uint8_t res_0x20[12]; /*  0020 */
} pv_cpu_dump_aad_v1_t __big_endian;
STATIC_ASSERT(sizeof(pv_cpu_dump_aad_v1_t) == 32)

/**
 * pv_cpu_dump_confidential_area_v1_t:
 *
 * Struct to interpret the Secure CPU Dump Area UVC.
 */
typedef struct {
	uint8_t gprs[128];    /* 0032 */
	uint8_t psw[16];      /* 0160 */
	uint8_t res_0x176[8]; /* 0176 */
	uint32_t prefix;      /* 0184 */
	uint32_t fpc;	      /* 0188 */
	uint8_t res_0x192[4]; /* 0192 */
	uint32_t todpreg;     /* 0196 */
	uint64_t timer;	      /* 0200 */
	uint64_t todcmp;      /* 0208 */
	uint8_t res_0x216[8]; /* 0216 */
	uint8_t acrs[64];     /* 0224 */
	uint8_t ctrs[128];    /* 0288 */
	struct {
		pv_cpu_vector_register_t vector_register_low[16];
		uint8_t vector_register_high[256];
	};			/* 0416 */
	uint8_t res_0x928[512]; /* 0928 */
	uint8_t zeros_2[8];	/* 1440 */
	uint64_t gsd;		/* 1448 */
	uint64_t gssm;		/* 1456 */
	uint64_t gs_epl_a;	/* 1464 */
	uint8_t res_0x1472[64]; /* 1472 */
	union {
		struct {
			uint16_t has_osii : 1;
			uint16_t reserved : 15;
		};
		uint16_t dump_flags; /* 1536 */
	};
	uint8_t res_0x1538[6]; /* 1538 */
	uint8_t res_0x1544[8]; /* 1544 */
} pv_cpu_dump_confidential_area_v1_t __big_endian;
STATIC_ASSERT(sizeof(pv_cpu_dump_confidential_area_v1_t) == 1520)

/**
 * pv_cpu_dump_v1_t:
 *
 * Struct representing a PV CPU dump v1 returned by the `Dump CPU state` UVC.
 */
typedef struct {
	pv_cpu_dump_aad_v1_t aad;			      /* 0000 */
	pv_cpu_dump_confidential_area_v1_t confidential_area; /* 0032 */
	uint8_t tag[16];				      /* 1552 */
} pv_cpu_dump_v1_t __big_endian;
STATIC_ASSERT(sizeof(pv_cpu_dump_v1_t) == 1568)

/* PV special tweak component indicator */
#define PV_SPECIAL_INDICATOR 0xFFFFFFFFUL

/**
 * pv_special_tweak_component_layout_t:
 *
 * Struct representing the layout of a special tweak component.
 */
typedef struct {
	uint32_t indicator;
	uint8_t reserved[10];
	uint8_t flag_reserved1;
	uint8_t flag_reserved2 : 5;
	uint8_t is_mapped_page : 1;
	uint8_t is_shared_page : 1;
	uint8_t is_zero_page   : 1;
} pv_special_tweak_component_layout_t __big_endian;
STATIC_ASSERT(sizeof(pv_special_tweak_component_layout_t) == 16)

/**
 * pv_tweak_component_t:
 *
 * Struct representing a tweak component returned by `Dump Configuration Storage State` UVC.
 */
typedef union {
	uint8_t value[16];
	pv_special_tweak_component_layout_t special;
} pv_tweak_component_t __big_endian;
STATIC_ASSERT(sizeof(pv_tweak_component_t) == 16)

/**
 * pv_tweak_t:
 *
 * Struct representing one tweak value.
 */
typedef struct {
	uint8_t value[16];
} pv_tweak_t;
STATIC_ASSERT(sizeof(pv_tweak_t) == 16)

STATIC_ASSERT(sizeof_field(pv_tweak_t, value) == sizeof_field(pv_tweak_component_t, value))
STATIC_ASSERT(sizeof_field(pv_tweak_t, value) == sizeof_field(pv_tweak_nonce_t, value))

#endif /* PV_DEFS_H */

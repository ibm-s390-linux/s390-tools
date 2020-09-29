/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines the interface to the EP11 host library.
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef EP11_H
#define EP11_H

#include <stdint.h>

#include "lib/zt_common.h"

/* EP11 definitions */

typedef uint64_t		target_t;
typedef unsigned long int	CK_ULONG;
typedef CK_ULONG		CK_RV;
typedef unsigned char		CK_BYTE;
typedef CK_BYTE			CK_CHAR;
typedef CK_ULONG		*CK_ULONG_PTR;
typedef void			*CK_VOID_PTR;

typedef struct XCP_ModuleSocket {
	char		host[256 + 1];
	uint32_t	port;
} *XCP_ModuleSocket_t;

typedef struct XCP_DomainPerf {
	unsigned int	lastperf[256];
} *XCP_DomainPerf_t;

typedef struct XCP_Module {
	uint32_t	version;
	uint64_t	flags;
	uint32_t	domains;
	unsigned char	domainmask[256 / 8];
	struct XCP_ModuleSocket socket;
	uint32_t	module_nr;
	void		*mhandle;
	struct XCP_DomainPerf perf;
	/* -----  end of v1 fields  ----- */
	uint32_t	api;
	/* -----  end of v2 fields  ----- */
} *XCP_Module_t;

typedef enum {
	XCP_MFL_SOCKET       =    1,
	XCP_MFL_MODULE       =    2,
	XCP_MFL_MHANDLE      =    4,
	XCP_MFL_PERF         =    8,
	XCP_MFL_VIRTUAL      = 0x10,
	XCP_MFL_STRICT       = 0x20,
	XCP_MFL_PROBE        = 0x40,
	XCP_MFL_ALW_TGT_ADD  = 0x80,
	XCP_MFL_MAX          = 0xff
} XCP_Module_Flags;

#define XCP_MOD_VERSION_1	1
#define XCP_MOD_VERSION_2	2
#define XCP_TGT_INIT		~0UL

#define XCPTGTMASK_SET_DOM(mask, domain)      \
				mask[((domain)/8)] |=   (1 << (7-(domain)%8))

#define XCP_SERIALNR_CHARS	8
#define XCP_ADMCTR_BYTES	((size_t) (128/8))
#define XCP_KEYCSUM_BYTES	(256/8)

#define XCP_ADM_REENCRYPT	25 /* transform blobs to next WK */

#define MAX_BLOBSIZE		8192

#define CKR_VENDOR_DEFINED	0x80000000
#define CKR_IBM_WKID_MISMATCH	CKR_VENDOR_DEFINED + 0x10001

typedef struct XCPadmresp {
	uint32_t	fn;
	uint32_t	domain;
	uint32_t	domainInst;

	/* module ID || module instance */
	unsigned char	module[XCP_SERIALNR_CHARS + XCP_SERIALNR_CHARS];
	unsigned char	modNr[XCP_SERIALNR_CHARS];
	unsigned char	modInst[XCP_SERIALNR_CHARS];

	unsigned char	tctr[XCP_ADMCTR_BYTES];  /* transaction counter */

	CK_RV		rv;
	uint32_t	reason;

	const unsigned char *payload;
	size_t		pllen;
} *XCPadmresp_t;

typedef struct CK_IBM_DOMAIN_INFO {
	CK_ULONG domain;
	CK_BYTE wk[XCP_KEYCSUM_BYTES];
	CK_BYTE nextwk[XCP_KEYCSUM_BYTES];
	CK_ULONG flags;
	CK_BYTE mode[8];
} CK_IBM_DOMAIN_INFO;

#define CK_IBM_DOM_COMMITTED_NWK	8

#define CK_IBM_XCPHQ_VERSION	0xff000001
#define CK_IBM_XCPQ_DOMAIN	3

#define MAX_APQN 256

typedef struct {
	short	format;
	short	length;
	short	apqns[2 * MAX_APQN];
} __packed ep11_target_t;

#define CKR_OK			0x00000000

typedef int (*m_init_t) (void);
typedef int (*m_add_module_t) (XCP_Module_t module, target_t *target);
typedef int (*m_rm_module_t) (XCP_Module_t module, target_t target);
typedef CK_RV (*m_get_xcp_info_t)(CK_VOID_PTR pinfo, CK_ULONG_PTR infbytes,
				  unsigned int query, unsigned int subquery,
				  target_t target);
typedef unsigned long int (*m_admin_t)(unsigned char *resp1, size_t *r1len,
				       unsigned char *resp2, size_t *r2len,
				       const unsigned char *cmd, size_t clen,
				       const unsigned char *sigs, size_t slen,
				       target_t target);
typedef long (*xcpa_cmdblock_t)(unsigned char *blk, size_t blen,
				unsigned int fn, const struct XCPadmresp *minf,
				const unsigned char *tctr,
				const unsigned char *payload, size_t plen);
typedef long (*xcpa_internal_rv_t)(const unsigned char *rsp, size_t rlen,
				   struct XCPadmresp *rspblk, CK_RV *rv);

struct ep11_version {
	unsigned int	minor;
	unsigned int	major;
};

struct ep11_lib {
	void *lib_ep11;
	m_init_t dll_m_init;
	m_add_module_t dll_m_add_module;
	m_rm_module_t dll_m_rm_module;
	m_get_xcp_info_t dll_m_get_xcp_info;
	m_admin_t dll_m_admin;
	xcpa_cmdblock_t dll_xcpa_cmdblock;
	xcpa_internal_rv_t dll_xcpa_internal_rv;
	struct ep11_version version;
};

int load_ep11_library(struct ep11_lib *ep11, bool verbose);

int get_ep11_target_for_apqn(struct ep11_lib *ep11, unsigned int card,
			     unsigned int domain, target_t *target,
			     bool verbose);

void free_ep11_target_for_apqn(struct ep11_lib *ep11, target_t target);

#define FLAG_SEL_EP11_MATCH_CUR_MKVP	0x01
#define FLAG_SEL_EP11_NEW_MUST_BE_SET	0x80

int select_ep11_apqn_by_mkvp(struct ep11_lib *ep11, u8 *mkvp,
			     const char *apqns,  unsigned int flags,
			     target_t *target, unsigned int *card,
			     unsigned int *domain, bool verbose);

int reencipher_ep11_key(struct ep11_lib *ep11, target_t target,
			unsigned int card, unsigned int domain, u8 *secure_key,
			unsigned int secure_key_size, bool verbose);

#endif

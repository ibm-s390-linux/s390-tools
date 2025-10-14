/*
 * Main program for stage3a bootloader
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "libc.h"
#include "stage3a.h"

#include "lib/zt_common.h"
#include "boot/error.h"
#include "boot/s390.h"
#include "boot/ipl.h"
#include "sclp.h"

/*
 * The following UV RC and RRC codes correspond to the errors
 * that occur often or may be fixeable directly by the user when
 * applying DIAG308 subcode 10 but configuration is unable to
 * enter the secure mode. Note that it is not an exhaustive list
 * of all possible UV RCs and RRCs.
 */
enum UV_RC {
	UNPACK_VERIFY_MISMATCH = 0x0102,
	SSC_HDR_VER_MISMATCH = 0x0104,
	SSC_UNSUPPORTED_PCF = 0x0106,
	SSC_HOSTKEY_HASH_ERR = 0x0108,
	SSC_UNSUPPORTED_SCF = 0x0109,
	SSC_HDR_CORRUPT = 0x010a,
};

enum UV_RRC_UNPACK_VERIFY_MISMATCH {
	ALD_MISMATCH = 0x001A,
	PLD_MISMATCH = 0x001B,
	TLD_MISMATCH = 0x001C,
	NUM_ENC_PAGES_MISMATCH = 0x001D,
};

enum UV_RRC_SSC_HDR_VER_MISMATCH {
	HDR_VER_MISMATCH = 0x0001,
};

enum UV_RRC_SSC_UNSUPPORTED_PCF {
	UNSUPPORTED_PCF = 0x0030,
};

enum UV_RRC_SSC_HOSTKEY_HASH_ERR {
	HOSTKEY_MISMATCH = 0x0005,
	INVAL_ECDH_KEY_HDR = 0x000B,
	BACKUP_HOSTKEY_MISMATCH = 0x0034,
};

enum UV_RRC_SSC_UNSUPPORTED_SCF {
	UNSUPPORTED_SCF = 0x0000,
};

enum UV_RRC_SSC_HDR_CORRUPT {
	HDR_LEN_MISMATCH = 0x0031,
	HDR_SIZE_ENC_INVAL = 0x0039,
	KEY_SLOT_EMPTY = 0x0040,
};

static volatile struct stage3a_args __section(.loader_parms) loader_parms;

static void print_error_message(enum UV_RC pv_rc, uint16_t pv_rrc)
{
	switch (pv_rc) {
	case UNPACK_VERIFY_MISMATCH:
		switch ((enum UV_RRC_UNPACK_VERIFY_MISMATCH)pv_rrc) {
		case ALD_MISMATCH:
			printf("Address digest list (ALD) mismatch.\n");
			break;
		case PLD_MISMATCH:
			printf("Page digest list (PLD) mismatch.\n");
			break;
		case TLD_MISMATCH:
			printf("Tweak digest list (TLD) mismatch.\n");
			break;
		case NUM_ENC_PAGES_MISMATCH:
			printf("Mismatch in number of encrypted pages.\n");
			break;
		}
		break;
	case SSC_HDR_VER_MISMATCH:
		if (pv_rrc == HDR_VER_MISMATCH)
			printf("Mismatch in IBM Secure Execution image header version.\n");
		break;
	case SSC_UNSUPPORTED_PCF:
		if (pv_rrc == UNSUPPORTED_PCF)
			printf("An unsupported plaintext control flag is set.\n");
		break;
	case SSC_HOSTKEY_HASH_ERR:
		switch ((enum UV_RRC_SSC_HOSTKEY_HASH_ERR)pv_rrc) {
		case HOSTKEY_MISMATCH:
			printf("The host key hash of the IBM Secure Execution image ");
			printf("does not match the host key of the installed key bundle.\n");
			break;
		case INVAL_ECDH_KEY_HDR:
			printf("The public customer ECDH key in the ");
			printf("IBM Secure Execution image is not valid.\n");
			break;
		case BACKUP_HOSTKEY_MISMATCH:
			printf("The secondary host key hash of the ");
			printf("IBM Secure Execution image does not match the ");
			printf("host key of the installed key bundle.\n");
			break;
		default:
			printf("Ensure that the image is ");
			printf("correctly encrypted for this host.\n");
		}
		break;
	case SSC_UNSUPPORTED_SCF:
		if (pv_rrc == UNSUPPORTED_SCF)
			printf("An unsupported secret control flag is set.\n");
		break;
	case SSC_HDR_CORRUPT:
		switch ((enum UV_RRC_SSC_HDR_CORRUPT)pv_rrc) {
		case HDR_LEN_MISMATCH:
			printf("Mismatch in IBM Secure Execution image header size.\n");
			break;
		case HDR_SIZE_ENC_INVAL:
			printf("The size of the encrypted area in the ");
			printf("IBM Secure Execution image is invalid.\n");
			break;
		case KEY_SLOT_EMPTY:
			printf("There are no host keys in");
			printf("the IBM Secure Execution image.\n");
			break;
		}
		break;
	}
}

char *get_cmd_name(uint16_t pv_cmd)
{
	char *cmd_name;

	/*
	 * QEMU returns command code IDs 2, 3 or 4 corresponding
	 * to the UV commands (SSC, UNPACK or UNPACK VERIFY) when
	 * DIAG 308 subcode is applied and the configuration is
	 * unable to enter the secure mode.
	 */
	switch (pv_cmd) {
	case 2:
		cmd_name = "KVM_PV_SET_SEC_PARMS";
		break;
	case 3:
		cmd_name = "KVM_PV_UNPACK";
		break;
	case 4:
		cmd_name = "KVM_PV_VERIFY";
		break;
	default:
		// should not reach here
		cmd_name = "UNKNOWN";
	}

	return cmd_name;
}

void report_diag308_unpack_pv_error(uint64_t rc)
{
	union {
		struct {
			uint16_t pv_cmd;
			uint16_t pv_rrc;
			uint16_t pv_rc;
			uint16_t diag_rc;
		};
		uint64_t regs;
	} resp = { .regs = rc };

	sclp_setup(SCLP_LINE_ASCII_INIT);
	print_error_message(resp.pv_rc, resp.pv_rrc);
	panic(EPV,
	      "Protected boot failed: 0x%x, "
	      "%s - RC: 0x%x, RRC:0x%x\n",
	      resp.diag_rc, get_cmd_name(resp.pv_cmd), resp.pv_rc, resp.pv_rrc);
}

void __noreturn start(void)
{
	volatile struct stage3a_args *args = &loader_parms;
	uint64_t rc;

	/* calculate the IPIB memory address */
	struct ipl_parameter_block *ipib = (void *)((uint64_t)args + args->ipib_offs);

	/* Calculate the PV header memory address and set it and its
	 * size in the IPIB. This allows the PV header to be position
	 * independent.
	 */
	ipib->pv.pv_hdr_addr = (uint64_t)args + args->hdr_offs;
	ipib->pv.pv_hdr_size = args->hdr_size;

	/* set up ASCII and line-mode */
	sclp_setup(SCLP_LINE_ASCII_INIT);

	/* test if Secure Execution Unpack facility is available */
	stfle(S390_lowcore.stfle_fac_list, ARRAY_SIZE(S390_lowcore.stfle_fac_list));
	rc = test_facility(UNPACK_FACILITY);
	if (rc == 0)
		panic(ENOPV, "Secure unpack facility is not available\n");

	rc = diag308(DIAG308_SET_PV, ipib);
	if (rc != DIAG308_RC_OK)
		panic(EPV, "Protected boot setup has failed: 0x%x\n", rc);

	rc = diag308(DIAG308_UNPACK_PV, 0x0);
	if (rc != DIAG308_RC_OK)
		report_diag308_unpack_pv_error(rc);

	while (1)
		;
}

void panic_notify(unsigned long UNUSED(rc))
{
}

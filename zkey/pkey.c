/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"

#include "pkey.h"

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

#define DOUBLE_KEYSIZE_FOR_XTS(keysize, xts) ((xts) ? 2 * (keysize) : (keysize))
#define HALF_KEYSIZE_FOR_XTS(keysize, xts)   ((xts) ? (keysize) / 2 : (keysize))

#define MAX_CIPHER_LEN		32

#define DEFAULT_KEYBITS		256

/**
 * Opens the pkey device and returns its file descriptor.
 *
 * @param verbose            if true, verbose messages are printed
 *
 * @returns the file descriptor or -1 to indicate an error
 */
int open_pkey_device(bool verbose)
{
	int pkey_fd;

	pkey_fd = open(PKEYDEVICE, O_RDWR);
	if (pkey_fd < 0) {
		warnx("File '%s:' %s\nEnsure that the 'pkey' kernel module "
		      "is loaded", PKEYDEVICE, strerror(errno));
		return -1;
	}

	pr_verbose(verbose, "Device '%s' has been opened successfully",
		   PKEYDEVICE);
	return pkey_fd;
}

/**
 * Read a secure key file and return the allocated buffer and size.
 *
 * @param[in]  keyfile     the name of the file to read
 * @param[out] secure_key_size  on return, the size of the secure key read
 * @param[in]  verbose     if true, verbose messages are printed
 *
 * @return a buffer containing the secure key, or NULL in case of an error.
 *         The returned buffer must be freed by the caller.
 */
u8 *read_secure_key(const char *keyfile, size_t *secure_key_size,
		    bool verbose)
{
	size_t count, size;
	struct stat sb;
	char *msg;
	FILE *fp;
	u8 *buf;

	util_assert(keyfile != NULL, "Internal error: keyfile is NULL");
	util_assert(secure_key_size != NULL,
		    "Internal error: secure_key_size is NULL");

	if (stat(keyfile, &sb)) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		return NULL;
	}
	size = sb.st_size;

	if (size != SECURE_KEY_SIZE && size != 2*SECURE_KEY_SIZE) {
		warnx("File '%s' has an invalid size, %lu or %lu bytes "
		      "expected", keyfile, SECURE_KEY_SIZE,
		      2 * SECURE_KEY_SIZE);
		return NULL;
	}

	fp = fopen(keyfile, "r");
	if (fp == NULL) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		return NULL;
	}

	buf = util_malloc(size);
	count = fread(buf, 1, size, fp);
	if (count != size) {
		msg = ferror(fp) ? strerror(errno) : "File is too small";
		warnx("File '%s': %s", keyfile, msg);
		free(buf);
		buf = NULL;
		goto out;
	}

	*secure_key_size = size;

	if (verbose) {
		pr_verbose(verbose, "%lu bytes read from file '%s'", size,
			   keyfile);
		util_hexdump_grp(stderr, NULL, buf, 4, size, 0);
	}
out:
	fclose(fp);
	return buf;
}

/**
 * Write a secure key file
 *
 * @param[in] keyfile     the name of the file to write
 * @param[in] secure_key  a buffer containing the secure key
 * @param[in] secure_key_size the size of the secure key
 * @param[in]  verbose     if true, verbose messages are printed
 *
 * @returns 0 in case of success, -EIO in case of an error
 */
int write_secure_key(const char *keyfile, const u8 *secure_key,
		     size_t secure_key_size, bool verbose)
{
	size_t count;
	FILE *fp;

	util_assert(keyfile != NULL, "Internal error: keyfile is NULL");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");
	util_assert(secure_key_size > 0,
		    "Internal error: secure_key_size is zero");

	fp = fopen(keyfile, "w");
	if (fp == NULL) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		return -EIO;
	}

	count = fwrite(secure_key, 1, secure_key_size, fp);
	if (count != secure_key_size) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		fclose(fp);
		return -EIO;
	}

	if (verbose) {
		pr_verbose(verbose, "%lu bytes written to file '%s'",
			   secure_key_size, keyfile);
		util_hexdump_grp(stderr, NULL, secure_key, 4,
				 secure_key_size, 0);
	}
	fclose(fp);
	return 0;
}

/**
 * Read a clear key file and return the allocated buffer and size
 *
 * @param[in]  keyfile     the name of the file to read
 * @param[in]  keybits     the clear key size in bits. When keybits is 0, then
 *                         the file size determines the keybits.
 * @param[in]  xts         if true an XTS key is to be read
 * @param[out] clear_key_size  on return, the size of the clear key read
 * @param[in]  verbose     if true, verbose messages are printed
 *
 * @return a buffer containing the clear key, or NULL in case of an error.
 *         The returned buffer must be freed by the caller.
 */
static u8 *read_clear_key(const char *keyfile, size_t keybits, bool xts,
			  size_t *clear_key_size, bool verbose)
{
	size_t count, size, expected_size;
	struct stat sb;
	char *msg;
	FILE *fp;
	u8 *buf;

	util_assert(keyfile != NULL, "Internal error: keyfile is NULL");
	util_assert(clear_key_size != NULL,
		    "Internal error: clear_key_size is NULL");

	if (stat(keyfile, &sb)) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		return NULL;
	}
	size = sb.st_size;

	if (keybits != 0) {
		expected_size = DOUBLE_KEYSIZE_FOR_XTS(keybits / 8, xts);
		if (size != expected_size) {
			warnx("File '%s' has an invalid size, "
			      "%lu bytes expected", keyfile, expected_size);
			return NULL;
		}
	} else {
		keybits = HALF_KEYSIZE_FOR_XTS(size * 8, xts);
	}

	switch (keybits) {
	case 128:
		break;
	case 192:
		if (xts) {
			warnx("File '%s' has an invalid size, "
			      "192 bit keys are not supported with XTS",
			      keyfile);
			return NULL;
		}
		break;
	case 256:
		break;
	default:
		if (xts)
			warnx("File '%s' has an invalid size, "
			      "32 or 64 bytes expected", keyfile);
		else
			warnx("File '%s' has an invalid size, 16, 24 "
			      "or 32 bytes expected", keyfile);
		return NULL;
	}

	fp = fopen(keyfile, "r");
	if (fp == NULL) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		return NULL;
	}

	buf = util_malloc(size);
	count = fread(buf, 1, size, fp);
	if (count != size) {
		msg = ferror(fp) ? strerror(errno) : "File is too small";
		warnx("File '%s': %s", keyfile, msg);
		free(buf);
		buf = NULL;
		goto out;
	}

	*clear_key_size = size;

	if (verbose) {
		pr_verbose(verbose, "%lu bytes read from file '%s'", size,
			   keyfile);
		util_hexdump_grp(stderr, NULL, buf, 4, size, 0);
	}
out:
	fclose(fp);
	return buf;
}

/**
 * Generate a secure key by random
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in] keyfile       the file name of the secure key to generate
 * @param[in] keybits       the cryptographic size of the key in bits
 * @param[in] xts           if true an XTS key is generated
 * @param[in] card          the card number to use (or AUTOSELECT)
 * @param[in] domain        the domain number to use (or AUTOSELECT)
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int generate_secure_key_random(int pkey_fd, const char *keyfile,
			       size_t keybits, bool xts, u16 card, u16 domain,
			       bool verbose)
{
	struct pkey_genseck gensec;
	size_t secure_key_size;
	u8 *secure_key;
	int rc;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(keyfile != NULL, "Internal error: keyfile is NULL");

	if (keybits == 0)
		keybits = DEFAULT_KEYBITS;

	secure_key_size = DOUBLE_KEYSIZE_FOR_XTS(SECURE_KEY_SIZE, xts);
	secure_key = util_malloc(secure_key_size);

	pr_verbose(verbose, "Generate key on card %02x.%04x", card, domain);

	gensec.cardnr = card;
	gensec.domain = domain;
	switch (keybits) {
	case 128:
		gensec.keytype = PKEY_KEYTYPE_AES_128;
		break;
	case 192:
		if (xts) {
			warnx("Invalid value for '--keybits'|'-c' "
			      "for XTS: '%lu'", keybits);
			rc = -EINVAL;
			goto out;
		}
		gensec.keytype = PKEY_KEYTYPE_AES_192;
		break;
	case 256:
		gensec.keytype = PKEY_KEYTYPE_AES_256;
		break;
	default:
		warnx("Invalid value for '--keybits'/'-c': '%lu'", keybits);
		rc = -EINVAL;
		goto out;
	}

	rc = ioctl(pkey_fd, PKEY_GENSECK, &gensec);
	if (rc < 0) {
		rc = -errno;
		warnx("Failed to generate a secure key: %s", strerror(errno));
		warnx("Make sure that all available CCA crypto adapters are "
		      "setup with the same master key");
		goto out;
	}

	memcpy(secure_key, &gensec.seckey, SECURE_KEY_SIZE);

	if (xts) {
		rc = ioctl(pkey_fd, PKEY_GENSECK, &gensec);
		if (rc < 0) {
			rc = -errno;
			warnx("Failed to generate a secure key: %s",
			      strerror(errno));
			warnx("Make sure that all available CCA crypto "
			      "adapters are setup with the same master key");
			goto out;
		}

		memcpy(secure_key + SECURE_KEY_SIZE, &gensec.seckey,
		       SECURE_KEY_SIZE);
	}

	pr_verbose(verbose, "Successfully generated a secure key");

	rc = write_secure_key(keyfile, secure_key, secure_key_size, verbose);

out:
	free(secure_key);
	return rc;
}


/*
 * Generate a secure key from a clear key file
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in] keyfile       the file name of the secure key to generate
 * @param[in] keybits       the cryptographic size of the key in bits. When
 *                          keybits is 0, then the clear key file size
 *                          determines the keybits.
 * @param[in] xts           if true an XTS key is generated
 * @param[in] clearkeyfile  the file name of the clear key to read
 * @param[in] card          the card number to use (or AUTOSELECT)
 * @param[in] domain        the domain number to use (or AUTOSELECT)
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int generate_secure_key_clear(int pkey_fd, const char *keyfile,
			      size_t keybits, bool xts,
			      const char *clearkeyfile,
			      u16 card, u16 domain,
			      bool verbose)
{
	struct pkey_clr2seck clr2sec;
	size_t secure_key_size;
	size_t clear_key_size;
	u8 *secure_key;
	u8 *clear_key;
	int rc;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(keyfile != NULL, "Internal error: keyfile is NULL");
	util_assert(clearkeyfile != NULL,
		    "Internal error: clearkeyfile is NULL");

	secure_key_size = DOUBLE_KEYSIZE_FOR_XTS(SECURE_KEY_SIZE, xts);
	secure_key = util_malloc(secure_key_size);

	clear_key = read_clear_key(clearkeyfile, keybits, xts, &clear_key_size,
				   verbose);
	if (clear_key == NULL)
		return -EINVAL;

	pr_verbose(verbose, "Generate key on card %02x.%04x", card, domain);

	clr2sec.cardnr = card;
	clr2sec.domain = domain;
	switch (HALF_KEYSIZE_FOR_XTS(clear_key_size * 8, xts)) {
	case 128:
		clr2sec.keytype = PKEY_KEYTYPE_AES_128;
		break;
	case 192:
		clr2sec.keytype = PKEY_KEYTYPE_AES_192;
		break;
	case 256:
		clr2sec.keytype = PKEY_KEYTYPE_AES_256;
		break;
	default:
		warnx("Invalid clear key size: '%lu' bytes", clear_key_size);
		rc = -EINVAL;
		goto out;
	}

	memcpy(&clr2sec.clrkey, clear_key,
	       HALF_KEYSIZE_FOR_XTS(clear_key_size, xts));

	rc = ioctl(pkey_fd, PKEY_CLR2SECK, &clr2sec);
	if (rc < 0) {
		rc = -errno;
		warnx("Failed to generate a secure key from a "
		      "clear key: %s", strerror(errno));
		warnx("Make sure that all available CCA crypto adapters are "
		      "setup with the same master key");
		goto out;
	}

	memcpy(secure_key, &clr2sec.seckey, SECURE_KEY_SIZE);

	if (xts) {
		memcpy(&clr2sec.clrkey, clear_key + clear_key_size / 2,
		       clear_key_size / 2);

		rc = ioctl(pkey_fd, PKEY_CLR2SECK, &clr2sec);
		if (rc < 0) {
			rc = -errno;
			warnx("Failed to generate a secure key from "
			      "a clear key: %s", strerror(errno));
			warnx("Make sure that all available CCA crypto "
			      "adapters are setup with the same master key");
			goto out;
		}

		memcpy(secure_key+SECURE_KEY_SIZE, &clr2sec.seckey,
		       SECURE_KEY_SIZE);
	}

	pr_verbose(verbose,
		   "Successfully generated a secure key from a clear key");

	rc = write_secure_key(keyfile, secure_key, secure_key_size, verbose);

out:
	memset(&clr2sec, 0, sizeof(clr2sec));
	memset(clear_key, 0, clear_key_size);
	free(clear_key);
	free(secure_key);
	return rc;
}

/**
 * Validates an XTS secure key (the second part)
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in] secure_key    a buffer containing the secure key
 * @param[in] secure_key_size the secure key size
 * @param[in] part1_keysize the key size of the first key part
 * @param[in] part1_attributes the attributes of the first key part
 * @param[out] clear_key_bitsize on return , the cryptographic size of the
 *                          clear key
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int validate_secure_xts_key(int pkey_fd,
				   u8 *secure_key, size_t secure_key_size,
				   u16 part1_keysize, u32 part1_attributes,
				   size_t *clear_key_bitsize, bool verbose)
{
	struct secaeskeytoken *token = (struct secaeskeytoken *)secure_key;
	struct pkey_verifykey verifykey;
	struct secaeskeytoken *token2;
	int rc;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");

	/* XTS uses 2 secure key tokens concatenated to each other */
	token2 = (struct secaeskeytoken *)(secure_key + SECURE_KEY_SIZE);

	if (secure_key_size != 2 * SECURE_KEY_SIZE) {
		pr_verbose(verbose, "Size of secure key is too small: "
			   "%lu expected %lu", secure_key_size,
			   2 * SECURE_KEY_SIZE);
		return -EINVAL;
	}

	if (token->bitsize != token2->bitsize) {
		pr_verbose(verbose, "XTS secure key contains 2 clear keys of "
			   "different sizes");
		return -EINVAL;
	}
	if (token->keysize != token2->keysize) {
		pr_verbose(verbose, "XTS secure key contains 2 keys of "
			   "different sizes");
		return -EINVAL;
	}
	if (memcmp(&token->mkvp, &token2->mkvp, sizeof(token->mkvp)) != 0) {
		pr_verbose(verbose, "XTS secure key contains 2 keys using "
			   "different CCA master keys");
		return -EINVAL;
	}

	memcpy(&verifykey.seckey, token2, sizeof(verifykey.seckey));

	rc = ioctl(pkey_fd, PKEY_VERIFYKEY, &verifykey);
	if (rc < 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to validate a secure key: %s",
			   strerror(-rc));
		return rc;
	}

	if ((verifykey.attributes & PKEY_VERIFY_ATTR_AES) == 0) {
		pr_verbose(verbose, "Secure key is not an AES key");
		return -EINVAL;
	}

	if (verifykey.keysize != part1_keysize) {
		pr_verbose(verbose, "XTS secure key contains 2 keys using "
			   "different key sizes");
		return -EINVAL;
	}

	if (verifykey.attributes != part1_attributes) {
		pr_verbose(verbose, "XTS secure key contains 2 keys using "
			   "different attributes");
		return -EINVAL;
	}

	if (clear_key_bitsize)
		*clear_key_bitsize += verifykey.keysize;

	return 0;
}

/**
 * Validates a secure key
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in] secure_key    a buffer containing the secure key
 * @param[in] secure_key_size the secure key size
 * @param[out] clear_key_bitsize on return , the cryptographic size of the
 *                          clear key
 * @param[out] is_old_mk    in return set to 1 to indicate if the secure key
 *                          is currently enciphered by the OLD CCA master key
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int validate_secure_key(int pkey_fd,
			u8 *secure_key, size_t secure_key_size,
			size_t *clear_key_bitsize, int *is_old_mk,
			bool verbose)
{
	struct secaeskeytoken *token = (struct secaeskeytoken *)secure_key;
	struct pkey_verifykey verifykey;
	int rc;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");

	if (secure_key_size < SECURE_KEY_SIZE) {
		pr_verbose(verbose, "Size of secure key is too small: "
			   "%lu expected %lu", secure_key_size,
			   SECURE_KEY_SIZE);
		return -EINVAL;
	}

	memcpy(&verifykey.seckey, token, sizeof(verifykey.seckey));

	rc = ioctl(pkey_fd, PKEY_VERIFYKEY, &verifykey);
	if (rc < 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to validate a secure key: %s",
			   strerror(-rc));
		return rc;
	}

	if ((verifykey.attributes & PKEY_VERIFY_ATTR_AES) == 0) {
		pr_verbose(verbose, "Secure key is not an AES key");
		return -EINVAL;
	}

	if (clear_key_bitsize)
		*clear_key_bitsize = verifykey.keysize;

	/* XTS uses 2 secure key tokens concatenated to each other */
	if (secure_key_size > SECURE_KEY_SIZE) {
		rc = validate_secure_xts_key(pkey_fd,
					     secure_key, secure_key_size,
					     verifykey.keysize,
					     verifykey.attributes,
					     clear_key_bitsize,
					     verbose);
		if (rc != 0)
			return rc;
	}

	if (is_old_mk)
		*is_old_mk = (verifykey.attributes &
			      PKEY_VERIFY_ATTR_OLD_MKVP) != 0;

	pr_verbose(verbose, "Secure key validation completed successfully");

	return 0;
}

/**
 * Generate a key verification pattern of a secure key by encrypting the all
 * zero message with the secure key using the AF_ALG interface
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 * @param[in] vp            buffer where the verification pattern is returned
 * @param[in] vp_len        the size of the buffer
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int generate_key_verification_pattern(const char *key, size_t key_size,
				      char *vp, size_t vp_len, bool verbose)
{
	int tfmfd = -1, opfd = -1, rc = 0;
	char null_msg[ENC_ZERO_LEN];
	char enc_zero[ENC_ZERO_LEN];
	struct af_alg_iv *alg_iv;
	struct cmsghdr *header;
	uint32_t *type;
	ssize_t len;
	size_t i;

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
	};
	struct iovec iov = {
		.iov_base = (void *)null_msg,
		.iov_len = sizeof(null_msg),
	};
	int iv_msg_size = CMSG_SPACE(sizeof(*alg_iv) + PAES_BLOCK_SIZE);
	char buffer[CMSG_SPACE(sizeof(*type)) + iv_msg_size];
	struct msghdr msg = {
		.msg_control = buffer,
		.msg_controllen = sizeof(buffer),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	if (vp_len < VERIFICATION_PATTERN_LEN) {
		rc = -EMSGSIZE;
		goto out;
	}

	snprintf((char *)sa.salg_name, sizeof(sa.salg_name), "%s(paes)",
		 key_size > SECURE_KEY_SIZE ? "xts" : "cbc");

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfmfd < 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to open an AF_ALG socket");
		goto out;
	}

	if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to bind the AF_ALG socket, "
			   "salg_name='%s' ", sa.salg_name);
		goto out;
	}

	if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key,
		       key_size) < 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to set the key");
		goto out;
	}

	opfd = accept(tfmfd, NULL, 0);
	if (opfd < 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to accept on the AF_ALG socket");
		goto out;
	}

	memset(null_msg, 0, sizeof(null_msg));
	memset(buffer, 0, sizeof(buffer));

	header = CMSG_FIRSTHDR(&msg);
	if (header == NULL) {
		pr_verbose(verbose, "Failed to obtain control message header");
		rc = -EINVAL;
		goto out;
	}

	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_OP;
	header->cmsg_len = CMSG_LEN(sizeof(*type));
	type = (void *)CMSG_DATA(header);
	*type = ALG_OP_ENCRYPT;

	header = CMSG_NXTHDR(&msg, header);
	if (header == NULL) {
		pr_verbose(verbose, "Failed to obtain control message "
			   "header");
		rc = -EINVAL;
		goto out;
	}
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_IV;
	header->cmsg_len = iv_msg_size;
	alg_iv = (void *)CMSG_DATA(header);
	alg_iv->ivlen = PAES_BLOCK_SIZE;
	memcpy(alg_iv->iv, null_msg, PAES_BLOCK_SIZE);

	len = sendmsg(opfd, &msg, 0);
	if (len != ENC_ZERO_LEN) {
		pr_verbose(verbose, "Failed to send to the AF_ALG socket");
		rc = -errno;
		goto out;
	}

	len = read(opfd, enc_zero, sizeof(enc_zero));
	if (len != ENC_ZERO_LEN) {
		pr_verbose(verbose, "Failed to receive from the AF_ALG socket");
		rc = -errno;
		goto out;
	}

	memset(vp, 0, vp_len);
	for (i = 0; i < sizeof(enc_zero); i++)
		sprintf(&vp[i * 2], "%02x", enc_zero[i]);

	pr_verbose(verbose, "Key verification pattern:  %s", vp);

out:
	if (opfd != -1)
		close(opfd);
	if (tfmfd != -1)
		close(tfmfd);

	if (rc != 0)
		pr_verbose(verbose, "Failed to generate the key verification "
			   "pattern: %s", strerror(-rc));

	return rc;
}

int get_master_key_verification_pattern(const u8 *secure_key,
					size_t secure_key_size, u64 *mkvp,
					bool verbose)
{
	struct secaeskeytoken *token = (struct secaeskeytoken *)secure_key;

	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");
	util_assert(mkvp != NULL, "Internal error: mkvp is NULL");

	if (secure_key_size < SECURE_KEY_SIZE) {
		pr_verbose(verbose, "Size of secure key is too small: "
			   "%lu expected %lu", secure_key_size,
			   SECURE_KEY_SIZE);
		return -EINVAL;
	}

	*mkvp = token->mkvp;

	return 0;
}

/**
 * Check if the specified key is a CCA AESDATA key token.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an CCA AESDATA token type
 */
bool is_cca_aes_data_key(const u8 *key, size_t key_size)
{
	struct tokenheader *hdr = (struct tokenheader *)key;

	if (key == NULL || key_size < SECURE_KEY_SIZE)
		return false;

	if (hdr->type != TOKEN_TYPE_CCA_INTERNAL)
		return false;
	if (hdr->version != TOKEN_VERSION_AESDATA)
		return false;

	return true;
}

/**
 * Returns the type of the key
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns a static string on success, NULL in case of an error
 */
const char *get_key_type(const u8 *key, size_t key_size)
{
	if (is_cca_aes_data_key(key, key_size))
		return KEY_TYPE_CCA_AESDATA;

	return NULL;
}

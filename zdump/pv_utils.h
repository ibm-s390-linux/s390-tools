/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Utilities to decrypt secure execution guest dumps.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_UTILS_H
#define PV_UTILS_H

#include <stdbool.h>

#include <openssl/evp.h>

#include "lib/util_log.h"
#include "libpv/crypto.h"

#include "df_elf.h"
#include "dfi.h"
#include "pv_defs.h"
#include <stdint.h>

#define PV_INVAL_PAGE_STATE 0UL
#define PV_ENCRYPTED_PAGE   (1UL << 0)
#define PV_SHARED_PAGE	    (1UL << 1)
#define PV_ZERO_PAGE	    (1UL << 2)
#define PV_MAPPED_PAGE	    (1UL << 3)

#define FUNC_NAME_FLAT_STRUCT_CLEANSE_FREE(type) type##_flat_struct_cleanse_free
#define DEFINE_FLAT_STRUCT_CLEANSE_FREE(type, free_func)                                           \
	static void FUNC_NAME_FLAT_STRUCT_CLEANSE_FREE(type)(type * obj)                           \
	{                                                                                          \
		if (!obj)                                                                          \
			return;                                                                    \
		OPENSSL_cleanse(obj, sizeof(type));                                                \
		free_func(obj);                                                                    \
	}

/* The typedef is required to be able to define a autoptr cleanup
 * function using glib2.
 */
typedef struct dfi_cpu dfi_cpu_t;

DEFINE_FLAT_STRUCT_CLEANSE_FREE(dfi_cpu_t, dfi_cpu_free)
DEFINE_FLAT_STRUCT_CLEANSE_FREE(pv_dump_completion_data_v1_t, g_free)
DEFINE_FLAT_STRUCT_CLEANSE_FREE(pv_dump_completion_confidential_area_v1_t, g_free)

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(dfi_cpu_t, FUNC_NAME_FLAT_STRUCT_CLEANSE_FREE(dfi_cpu_t))
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(
	pv_dump_completion_data_v1_t,
	FUNC_NAME_FLAT_STRUCT_CLEANSE_FREE(pv_dump_completion_data_v1_t))
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(
	pv_dump_completion_confidential_area_v1_t,
	FUNC_NAME_FLAT_STRUCT_CLEANSE_FREE(pv_dump_completion_confidential_area_v1_t))

typedef struct _pv_crypto_ctx pv_crypto_ctx_t;
typedef struct _storage_state_mmap storage_state_mmap_t;
struct _pv_elf_ctx {
	BIO *output;
	u64 elf_load_off;
	pv_crypto_ctx_t *pv_ctx;
	storage_state_mmap_t *storage_state_data;
};
typedef struct _pv_elf_ctx pv_elf_ctx_t;

void pv_dump_completion_free(pv_dump_completion_t *cpl);
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(pv_dump_completion_t, pv_dump_completion_free)

/**
 * pv_derive_dump_key_v1:
 * @cpl_data: v1 dump completion data
 * @cck: Customer communication key
 * @error: return location for a #GError
 *
 * Derives an 32 byte AES-256-GCM key using the key derivation function HDKF
 * together with the customer communication key (CCK) @cck as input keying
 * material, and the seed from the completion configuration dump @cpl_data as salt.
 *
 * Returns: 32 byte AES-256-GCM key on success, %NULL if an error occurred
 */
GBytes *pv_derive_dump_key_v1(const pv_dump_completion_data_v1_t *cpl_data, GBytes *cck,
			      GError **error);

/**
 * pv_decrypt_dump_completion_v1:
 * @cpl_data: v1 dump completion data
 * @dump_key: Dump key
 * @error: return location for a #GError
 *
 * Decrypts and authenticates the completion configuration dump data @cpl_data
 * using the AES-256-GCM @dump_key.
 *
 * Returns: Decrypted confidential area of the completion configuration dump on success,
 *          %NULL if an error occurred
 */
pv_dump_completion_v1_t *pv_decrypt_dump_completion_v1(const pv_dump_completion_data_v1_t *cpl_data,
						       GBytes *dump_key, GError **error);

dfi_cpu_t *pv_decrypt_cpu_note_data(const unsigned int expected_version, GBytes *cpu_note,
				    GBytes *dump_key, GError **error);

/**
 * pv_decrypt_cpu_dump_area_v1:
 * @cpu_dump_area: a v1 CPU dump area
 * @dump_key: Dump key
 * @error: return location for a #GError
 *
 * Decrypts and authenticates a secure CPU dump using AES-256-GCM with specified
 * dump_key.
 *
 * Returns: Decrypted part of the CPU dump on success, %NULL if an error occurred
 */
GBytes *pv_decrypt_cpu_dump_area_v1(const pv_cpu_dump_v1_t *cpu_dump_area, GBytes *dump_key,
				    GError **error);

/**
 * pv_dfi_cpu_from_pv_cpu:
 * @pv_cpu: PV CPU data
 *
 * Convert PV CPU data to internal dfi_cpu struct.
 *
 * Returns: #dfi_cpu struct
 */
dfi_cpu_t *pv_dfi_cpu_from_pv_cpu(const pv_cpu_dump_confidential_area_v1_t *pv_cpu);

/**
 * pv_crypto_ctx_new:
 * @input: a #BIO input
 * @key: (array length=key_size): byte data of the key
 * @key_size: size of @key in bytes
 * @nonce: The PV tweak nonce
 * @mode: encrypt or decrypt mode
 * @error: return location for a #GError
 *
 * Create a PV crypto context using @input as the input, @key as the cipher key
 * and @nonce as the nonce for deriving the tweaks.
 *
 * Returns: a new #pv_crypto_ctx_t
 */
pv_crypto_ctx_t *pv_crypto_ctx_new(BIO *input, const unsigned char *key, size_t key_size,
				   const pv_tweak_nonce_t *nonce, enum PvCryptoMode mode,
				   GError **error);

/**
 * pv_crypto_ctx_free:
 * @ctx: a #pv_crypto_ctx_t
 *
 * Free all resources and the memory allocated for the #pv_crypto_ctx_t
 */
void pv_crypto_ctx_free(pv_crypto_ctx_t *ctx);

/**
 * pv_process_pglist:
 * @ctx: a #pv_crypto_ctx_t context
 * @output: Output
 * @tweaks_components: (array length=tweaks_len) (element-type pv_tweak_component_t): tweaks
 * components to be used for the decryption
 * @tweaks_components_len: the length of @tweaks and the length of the page list to be processed
 * @input_off: the file offset of the encrypted memory passed in @ctx to decrypt
 * @error: return location for a #GError
 *
 * Decrypts a page block (e.g. 256 pages).
 *
 * Returns: number of processed pages on success, -1 if an error occurred
 */
ssize_t pv_process_pglist(pv_crypto_ctx_t *ctx, BIO *output,
			  const pv_tweak_component_t *tweak_components, size_t tweak_components_len,
			  long input_off, GError **error);

/**
 * calculate_tweak:
 *
 * calculates the bitwise or of tweak component and nonce.
 */
void calculate_tweak(const pv_tweak_component_t *tweak, const pv_tweak_nonce_t *nonce,
		     pv_tweak_t *out);
/**
 * pv_read_page:
 * @output: Input
 * @output: Output
 *
 * Read one page data from @input and write it to @output.
 *
 * Returns: The number of bytes read for success, -1 if an error occurred
 */
int pv_read_page(BIO *input, BIO *output, GError **error);

/**
 * pv_page_state:
 *
 * Get the page state of the tweak component.
 */
unsigned long pv_page_state(const pv_tweak_component_t *comp);

/**
 * pv_get_tweak_components:
 * @storage_state_data: input data
 * @page_idx: Page index of the fist page
 * @page_cnt: number of tweak components that can be at least accessed
 *
 * get a pointer to the page states of the given pages.
 *
 * Returns: pointer to page states or NULL in case of an error
 *
 */
const pv_tweak_component_t *pv_get_tweak_components(storage_state_mmap_t *storage_state_data,
						    u64 page_idx, u64 page_cnt);

/**
 * pv_elf_ctx_new:
 * fd: file descriptor of elf file
 * @completion_confidential_decr:  content of ection pv_meta size must be
 * sizeof(pv_dump_completion_confidential_area_t)
 * @storage_state_data: mmap to pv_mem_meta
 * @load_offset: offset of LOAD segment in fd
 * @error: return value for GError
 *
 * creates a new elf context for processing the elf file
 *
 * Returns: new elf context or NULL in case of error
 */
pv_elf_ctx_t *
pv_elf_ctx_new(const int fd,
	       const pv_dump_completion_confidential_area_v1_t *completion_confidential_decr,
	       storage_state_mmap_t *storage_state_data, const u64 load_offset, GError **error);

/**
 * pv_info_free:
 * frees the elf context
 */
void pv_elf_ctx_free(pv_elf_ctx_t *p);

/**
 * pv_is_pv_elf:
 * @shdrs: list of section headers
 * @shnum: size of shdrs list
 * @shstrtab: content of shstrtab (section hdr string table)
 * @shstrtab_size: size of shstrtab
 *
 * Returns: true in case it is a PV ELF vmcore dump, false otherwise.
 */
bool pv_is_pv_elf(const Elf64_Shdr *shdrs, const unsigned int shnum, const char *shstrtab,
		  const size_t shstrtab_size);

/**
 * pv_process_section_data:
 *
 * Uses the ELF sections data to derive dump key, using the provided
 * customer-communication-key. It copies the decrypted completion
 * data into @completion_decr and mmaps storage state tweaks to storage
 * state data.
 *
 * The caller is responsible for cleanup and overwriting.
 *
 * Returns: 0 in case of success, -1 otherwise.
 */
int pv_process_section_data(const int fd, GBytes *completion_sec, const u64 storage_state_offset,
			    const size_t storage_state_size, GBytes *cck,
			    pv_dump_completion_t **completion_decr, GBytes **dump_key,
			    storage_state_mmap_t **storage_state_data, GError **error);

/**
 * pv_elf_read:
 *
 * elf_ctx: elf context
 * @start_addr: first address to read from
 * @dst: target
 * @size: num bytes to read
 * @error: return value for GError
 *
 * Read size bytes from start addr in elf_ctx and save it into dest.
 * Will decrypt pages if defined by page state.
 *
 * Returns: 0 in case of success, -1 otherwise.
 */
int pv_elf_read(const pv_elf_ctx_t *elf_ctx, const u64 start_addr, void *dst, const u64 size,
		GError **error);

/**
 * storage_state_mmap_new:
 * @fd: file descriptor for which to create the mapping
 * @offset: offset in fd to pv_mem_meta section
 * @size: size of mapping  (and pv_mem_meta section)
 * @error: return value for GError
 *
 * Returns: new storage_state_mmap context
 */
storage_state_mmap_t *storage_state_mmap_new(const int fd, const u64 offset, const u64 size,
					     GError **error);

/**
 * storage_state_ref:
 *
 * increase the reference counter by one.
 *
 * Returns: pointer to storage_state
 */
storage_state_mmap_t *storage_state_mmap_ref(storage_state_mmap_t *storage_state);

/**
 * storage_state_unref:
 *
 * Decreases the reference counter by one.
 * If the counter is now zero storage_state will be unmapped and freed.
 * If the munmap fails, an error will be logged.
 */
void storage_state_mmap_unref(storage_state_mmap_t *storage_state);

#define ZDUMP_PV_UTILS_ERROR g_quark_from_static_string("zdump-pv-utils")
typedef enum {
	ZDUMP_ERR_BIO,
	ZDUMP_ERR_BIO_FAIL,
	ZDUMP_ERR_BIO_KEY,
	ZDUMP_ERR_CORRUPTED_COMPL_DATA,
	ZDUMP_ERR_CORRUPTED_NOTE,
	ZDUMP_ERR_CRYPTO_CTX,
	ZDUMP_ERR_ELF_CTX,
	ZDUMP_ERR_ELF_CTX_BIO,
	ZDUMP_ERR_ELF_READ,
	ZDUMP_ERR_ELF_READ_END_ADDR_OVERFLOW,
	ZDUMP_ERR_MMAP,
	ZDUMP_ERR_PAGELIST_ELF_OFFSET_TOO_LARGE,
	ZDUMP_ERR_PAGE_END_ADDR_OVERFLOW,
	ZDUMP_ERR_PAGE_START_ADDR_OVERFLOW,
	ZDUMP_ERR_PGLIST_BIO,
	ZDUMP_ERR_PGLIST_INVAL,
	ZDUMP_ERR_PGLIST_INVAL_STATE,
	ZDUMP_ERR_PROC_SECT,
	ZDUMP_ERR_TWEAK,
	ZDUMP_ERR_UNSUPP_COMPL_VER,
	ZDUMP_ERR_UNSUPP_SEC_CPU_VER,
	ZDUMP_ERR_WRONG_AAD_SIZE,
	ZDUMP_ERR_WRONG_CCK_SIZE,
	ZDUMP_ERR_WRONG_CONFIDENTIAL_SIZE,
	ZDUMP_ERR_WRONG_NOTE_SIZE,
	ZDUMP_ERR_WRONG_TAG_SIZE,
} zdump_pv_utils_error_e;

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(pv_crypto_ctx_t, pv_crypto_ctx_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(pv_elf_ctx_t, pv_elf_ctx_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(storage_state_mmap_t, storage_state_mmap_unref)

#endif /* PV_UTILS_H */

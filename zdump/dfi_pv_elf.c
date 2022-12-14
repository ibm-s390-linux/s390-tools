/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * PV ELF core dump input format
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>
#include <elf.h>
#include <error.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <elf.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>

#include "lib/util_log.h"
#include "libpv/glib-helper.h"

#include "pv_defs.h"
#include "pv_utils.h"
#include "zgetdump.h"
#include "zg.h"
#include "df_elf.h"
#include "dfi.h"
#include "dfi_mem_chunk.h"
#include "dfi_elf_common.h"
#include "opts.h"

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(Elf64_Phdr, free);
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(Elf64_Shdr, free);
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(Elf64_Ehdr, free);

/**
 * read_elf_section_data_as_gbytes:
 * @fh: (not nullable): open input file
 * @shdr: (not nullable): section header of the section to read
 * @max_size: maximum section data size in bytes
 *
 * Try to read section data and return it as #GBytes.
 *
 * Returns: #GBytes on success, %NULL if an error occurred
 */
static GBytes *read_elf_section_data_as_gbytes(const struct zg_fh *fh, const Elf64_Shdr *shdr,
					       const size_t max_size)
{
	unsigned char *data;
	size_t size;

	data = read_elf_section_data(fh, shdr, &size, max_size);
	if (!data)
		return NULL;
	return g_bytes_new_with_free_func(data, size, free, data);
}

/**
 * dfi_pv_elf_mem_chunk_read_fn:
 * @chunk: (not nullable): memory chunk to read from
 * @chunk_off: offset in the memory chunk to read from
 * @dst: (not nullable): destination buffer
 * @size: size in bytes to read
 *
 * Memory chunk callback that attempts to read and decrypt up to @size
 * bytes encrypted memory from @chunk.
 */
static void dfi_pv_elf_mem_chunk_read_fn(struct dfi_mem_chunk *chunk, u64 chunk_off, void *dst,
					 u64 size)
{
	const pv_elf_ctx_t *ctx = chunk->data;
	g_autoptr(GError) error = NULL;

	g_assert_nonnull(ctx);

	if (pv_elf_read(ctx, chunk_off, dst, size, &error) < 0)
		ERR_EXIT(_("Reading encrypted memory failed:" ERR_NEWLINE "%s"), error->message);
}

/**
 * nt_s390_pv_cpu_data_read:
 * @fh: (not nullable): open input ELF file
 * @note_hdr: (not nullable): note header of the note to read
 * @version: expected PV CPU dump version
 * @dump_key: (not nullable): key to be used to decrypt data stored in the note
 * @error: return location for a #GError
 *
 * Read and decrypt PV CPU data of the note using @dump_key.
 *
 * Returns: #dfi_cpu_t struct on success, %NULL if an error occurred.
 */
static dfi_cpu_t *nt_s390_pv_cpu_data_read(const struct zg_fh *fh, const Elf64_Nhdr *note_hdr,
					   const unsigned int version, GBytes *dump_key,
					   GError **error)
{
	const size_t note_descsz = note_hdr->n_descsz;
	g_autofree uint8_t *note_data = NULL;
	g_autoptr(GBytes) note = NULL;

	g_assert(dump_key);

	if (note_descsz > PV_MAX_NT_S390_PV_CPU_DATA_SIZE) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_CORRUPTED_NOTE,
			    _("Unable to read confidential CPU data. Dump probably corrupted."));
		return NULL;
	}

	note_data = g_malloc(note_descsz);
	if (nt_read(fh, note_hdr, note_data, note_descsz) < 0) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_CORRUPTED_NOTE,
			    _("Unable to read confidential CPU data. Dump probably corrupted."));
		return NULL;
	}

	note = g_bytes_new_take(g_steal_pointer(&note_data), note_descsz);
	return pv_decrypt_cpu_note_data(version, note, dump_key, error);
}

/**
 * pt_notes_add:
 * @fh: (not nullable): open input file
 * @phdr: (not nullable): program header of the note segment to add
 * @version: expected PV CPU dump version
 * @dump_key: (not nullable): key to be used to decrypt data stored in the notes
 * @error: return location for a #GError
 *
 * Read all ELF notes for @phdr.
 *
 * Returns: %0 on success, -EINVAL if an error occurred.
 */
static int pt_notes_add(const struct zg_fh *fh, const Elf64_Phdr *phdr, const unsigned int version,
			GBytes *dump_key, GError **error)
{
	if (phdr->p_offset > OFF_T_MAX) {
		g_set_error(
			error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_CORRUPTED_NOTE,
			_("Confidential CPU data has too large offset. Dump probably corrupted."));
		return -EINVAL;
	}

	zg_seek(fh, (off_t)phdr->p_offset, ZG_CHECK);
	/* Cast to `size_t` is safe because we're using `ZG_CHECK` here. This
	 * means an error in `zg_tell` leads to an exit and therefore `zg_tell`
	 * cannot return an negative value.
	 */
	while ((size_t)zg_tell(fh, ZG_CHECK) - phdr->p_offset < phdr->p_filesz) {
		g_autoptr(dfi_cpu_t) cpu_current = NULL;
		Elf64_Nhdr note;
		ssize_t rc;

		rc = zg_read(fh, &note, sizeof(note), ZG_CHECK_ERR);
		if (rc != sizeof(note)) {
			g_set_error(
				error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_CORRUPTED_NOTE,
				_("Confidential CPU data could not be read. Dump probably corrupted."));
			return -EINVAL;
		}
		switch (note.n_type) {
		case NT_S390_PV_CPU_DATA:
			cpu_current = nt_s390_pv_cpu_data_read(fh, &note, version, dump_key, error);
			if (!cpu_current)
				return -EINVAL;
			dfi_cpu_add(g_steal_pointer(&cpu_current));
			break;
		default:
			util_log_print(UTIL_LOG_WARN, _("Unknown ELF-Note %#x\n"), note.n_type);
			__attribute__((fallthrough));
		case NT_PRSTATUS:
		case NT_FPREGSET:
		case NT_S390_TIMER:
		case NT_S390_TODCMP:
		case NT_S390_TODPREG:
		case NT_S390_CTRS:
		case NT_S390_PREFIX:
		case NT_S390_VXRS_LOW:
		case NT_S390_VXRS_HIGH:
		case NT_S390_GS_CB:
			/* In case of PV ignore all these note types */
			nt_skip(fh, &note);
			break;
		}
	}
	return 0;
}

/**
 * dfi_pv_elf_init:
 *
 * Initialize Protected Virtualization ELF input dump format for @g.fh.
 *
 * Returns: %0 on success, -ENODEV in case it's not a PV ELF dump and
 *          -EINVAL in case of an error.
 */
static int dfi_pv_elf_init(void)
{
	const Elf64_Shdr *completion_shdr = NULL, *storage_state_shdr = NULL;
	g_autoptr(GBytes) key = NULL, dump_key = NULL, completion_sdata = NULL;
	g_autoptr(storage_state_mmap_t) storage_state_data = NULL;
	const pv_dump_completion_v1_t *cpl_conf_v1_decr = NULL;
	g_autoptr(pv_dump_completion_t) cpl_conf_decr = NULL;
	const char *key_path = g.opts.key_path;
	g_autoptr(Elf64_Phdr) phdrs = NULL;
	g_autoptr(Elf64_Shdr) shdrs = NULL;
	g_autoptr(Elf64_Ehdr) ehdr = NULL;
	g_autofree char *shstrtab = NULL;
	g_autoptr(GError) error = NULL;
	unsigned int cpu_dump_version;
	const struct zg_fh *fh = g.fh;
	unsigned int shnum, phnum;
	bool load_found = false;
	size_t shstrtab_size;
	unsigned int i;

	util_log_print(UTIL_LOG_DEBUG, _("DFI %s initialization\n"), dfi_pv_elf.name);
	ehdr = read_elf_hdr(fh);
	if (!ehdr)
		return -ENODEV;

	if (ehdr_check_s390x(ehdr) < 0)
		return -ENODEV;

	shdrs = read_elf_shdrs(fh, ehdr, &shnum);
	if (!shdrs)
		return -ENODEV;

	shstrtab = read_elf_shstrtab(fh, ehdr, shdrs, shnum, &shstrtab_size, PV_MAX_SHSTRTAB_SIZE);
	if (!shstrtab)
		return -ENODEV;

	if (!pv_is_pv_elf(shdrs, shnum, shstrtab, shstrtab_size))
		return -ENODEV;

	df_elf_ensure_s390x();
	dfi_arch_set(DFI_ARCH_64);
	dfi_cpu_info_init(DFI_CPU_CONTENT_ALL);

	/* Try to read the customer communication key */
	if (!key_path)
		return -ENOKEY;
	util_log_print(UTIL_LOG_DEBUG, _("Key path: %s\n"), key_path);
	key = pv_file_get_content_as_secure_bytes(key_path);
	if (!key)
		return -ENOKEY;

	/* Find PV completion configuration data and storage state data sections */
	completion_shdr = find_elf_shdr_by_name(shdrs, shnum, shstrtab, shstrtab_size,
						PV_ELF_SECTION_NAME_COMPL);
	if (!completion_shdr)
		return -EINVAL;

	storage_state_shdr = find_elf_shdr_by_name(shdrs, shnum, shstrtab, shstrtab_size,
						   PV_ELF_SECTION_NAME_TWEAKS);
	if (!storage_state_shdr)
		return -EINVAL;

	/* Read the PV completion configuration section data */
	completion_sdata =
		read_elf_section_data_as_gbytes(fh, completion_shdr, PV_MAX_COMPL_DATA_SIZE);
	if (!completion_sdata)
		return -EINVAL;

	/* Derive and store the dump key in `@dump_key`. This key is used to AES-GCM decrypt the
	 * completion configuration data and store it in `@cpl_conf_decr`. In addition, mmap the
	 * configuration storage state area and use the `tweak_nonce`.
	 */
	if (pv_process_section_data(fh->fh, fh->sb.st_size, completion_sdata,
				    storage_state_shdr->sh_offset, storage_state_shdr->sh_size, key,
				    &cpl_conf_decr, &dump_key, &storage_state_data, &error) < 0) {
		ERR(_("Unable to read decryption information:" ERR_NEWLINE "%s."), error->message);
		return -EINVAL;
	}
	g_assert_nonnull(cpl_conf_decr);
	g_assert_cmpuint(cpl_conf_decr->version, ==, PV_COMPL_DATA_VERSION_1);

	cpl_conf_v1_decr = (pv_dump_completion_v1_t *)cpl_conf_decr;
	cpu_dump_version = PV_SEC_CPU_DATA_VERSION_1;
	phdrs = read_elf_phdrs(fh, ehdr, &phnum);
	util_log_print(UTIL_LOG_DEBUG, _("DFI %s e_phnum %u\n"), dfi_pv_elf.name, phnum);
	for (i = 0; i < phnum; i++) {
		const Elf64_Phdr *phdr = &phdrs[i];

		util_log_print(UTIL_LOG_DEBUG, _("DFI %s p_type[%d] 0x%lx\n"), dfi_pv_elf.name, i,
			       phdr->p_type);
		switch (phdr->p_type) {
		case PT_LOAD: {
			/* Initialize callback data for the `dfi_pv_elf_mem_chunk_read_fn` function
			 */
			g_autoptr(pv_elf_ctx_t) elf_ctx =
				pv_elf_ctx_new(fh->fh, &cpl_conf_v1_decr->data.confidential_area,
					       storage_state_data, phdr->p_offset, &error);
			if (!elf_ctx) {
				ERR(_("Reading dump failed:" ERR_NEWLINE "%s"), error->message);
				return -EINVAL;
			}

			if (load_found) {
				ERR(_("Reading dump failed:" ERR_NEWLINE
				      "Multiple PT_LOAD segments are not supported."));
				return -EINVAL;
			}

			if (pt_load_add(fh, phdr, (void **)&elf_ctx, dfi_pv_elf_mem_chunk_read_fn,
					(dfi_mem_chunk_free_fn)pv_elf_ctx_free) < 0)
				return -EINVAL;
			load_found = true;
			break;
		}
		case PT_NOTE:
			/* Add CPU information (decrypts the CPU data) */
			if (pt_notes_add(fh, phdr, cpu_dump_version, dump_key, &error)) {
				ERR(_("Reading dump failed:" ERR_NEWLINE "%s"), error->message);
				return -EINVAL;
			}
			break;
		default:
			util_log_print(UTIL_LOG_WARN, _("Unknown ELF-PHDR type %#x\n"),
				       phdr->p_type);
			break;
		}
	}
	dfi_attr_version_set(cpl_conf_decr->version);
	return 0;
}

static void dfi_pv_elf_cleanup(void)
{
	/* nothing to do here */
}

/*
 * PV ELF DFI operations
 */
struct dfi dfi_pv_elf = {
	.exit = dfi_pv_elf_cleanup,
	.feat_bits = DFI_FEAT_COPY | DFI_FEAT_SEEK,
	.init = dfi_pv_elf_init,
	.name = "ELF (protected virtualization dump)",
};

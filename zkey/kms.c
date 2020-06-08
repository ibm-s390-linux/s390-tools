/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <dlfcn.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_rec.h"
#include "lib/util_panic.h"
#include "lib/util_prg.h"

#include "kms.h"
#include "utils.h"
#include "pkey.h"

#define ENVVAR_ZKEY_REPOSITORY		"ZKEY_REPOSITORY"
#define DEFAULT_KEYSTORE		"/etc/zkey/repository"

#define ENVVAR_ZKEY_KMS_PLUGINS		"ZKEY_KMS_PLUGINS"
#define DEFAULT_KMS_PLUGINS		"/etc/zkey/kms-plugins.conf"

#define KMS_CONFIG_FILE			"kms.conf"
#define KMS_CONFIG_PROP_KMS		"kms"
#define KMS_CONFIG_PROP_KMS_CONFIG	"config"
#define KMS_CONFIG_PROP_APQNS		"apqns"
#define KMS_CONFIG_PROP_CCA_APQNS	"ep11_apqns"
#define KMS_CONFIG_PROP_EP11_APQNS	"cca_apqns"
#define KMS_CONFIG_LOCAL		"local"

#define KMS_KEY_PROP_NAME		"zkey-name"
#define KMS_KEY_PROP_CIPHER		"cipher"
#define KMS_KEY_PROP_IV_MODE		"iv-mode"
#define KMS_KEY_PROP_DESCRIPTION	"description"
#define KMS_KEY_PROP_VOLUMES		"volumes"
#define KMS_KEY_PROP_VOLUME_TYPE	"volume-type"
#define KMS_KEY_PROP_SECTOR_SIZE	"sector-size"
#define KMS_KEY_PROP_XTS_KEY		"xts-key"
#define KMS_KEY_PROP_XTS_KEY1_ID	"xts-key1-id"
#define KMS_KEY_PROP_XTS_KEY2_ID	"xts-key2-id"
#define KMS_KEY_PROP_XTS_KEY1_LABEL	"xts-key1-label"
#define KMS_KEY_PROP_XTS_KEY2_LABEL	"xts-key2-label"

static const char * const key_types[] = {
		KEY_TYPE_CCA_AESDATA,
		KEY_TYPE_CCA_AESCIPHER,
		KEY_TYPE_EP11_AES,
		NULL
};

typedef const struct kms_functions *(*kms_get_functions_t)(void);

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

#define ARRAY_ADD(array, num_elemnts, element_size, new_element)	\
	do {								\
		(num_elemnts)++;					\
		(array) = util_realloc((array),				\
				(num_elemnts) * element_size);		\
		memcpy(&(array)[(num_elemnts) - 1], new_element,	\
		       element_size);					\
	} while (0)

#define ARRAY_REMOVE(array, num_elemnts, element_size, index)		\
	do {								\
		if ((index) < (num_elemnts) - 1)			\
			memmove(&(array)[(index)],			\
				&(array)[(index) + 1],			\
				((num_elemnts) - (index) - 1) *		\
							element_size);	\
		(num_elemnts)--;					\
		if ((num_elemnts) > 0) {				\
			(array) = util_realloc((array),			\
					(num_elemnts) * element_size);	\
		}							\
	} while (0)


/**
 * Opens kms-plugins.conf. Looks for the file in /etc/zkey/, or if environment
 * variable ZKEY_KMS_PLUGINS is set then it uses the file name and path
 * specified there.
 */
static FILE *open_kms_plugins_file(bool verbose)
{
	char *conf;
	FILE *fp;

	conf = getenv(ENVVAR_ZKEY_KMS_PLUGINS);
	if (conf == NULL)
		conf = DEFAULT_KMS_PLUGINS;

	pr_verbose(verbose, "Opening KMS plugins config file '%s'", conf);
	fp = fopen(conf, "r");
	if (fp == NULL) {
		warnx("File '%s': %s", conf, strerror(errno));
		return NULL;
	}

	return fp;
}

/**
 * Lists the KMS plugins defined in kms-plugins.conf
 *
 * @param[in] verbose    if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
int list_kms_plugins(bool verbose)
{
	struct util_rec *rec;
	char line[4096];
	int rc = 0;
	size_t len;
	FILE *fp;
	char *ch;

	fp = open_kms_plugins_file(verbose);
	if (fp == NULL)
		return -EIO;

	rec = util_rec_new_wide("-");
	util_rec_def(rec, "PLUGIN", UTIL_REC_ALIGN_LEFT, 25, "KMS-Plugin");
	util_rec_def(rec, "LIB", UTIL_REC_ALIGN_LEFT, 25, "Shared library");
	util_rec_print_hdr(rec);

	while (fgets(line, sizeof(line), fp) != NULL) {
		len = strlen(line);
		if (len < 1)
			continue;
		if (line[0] == '#')
			continue;
		if (line[len - 1] == '\n')
			line[len - 1] = '\0';
		ch = strchr(line, '=');
		if (ch == NULL) {
			rc = -EPERM;
			warnx("Syntax error in kms-plugins.conf. Line: '%s'",
			      line);
			goto out;
		}

		*ch = '\0';
		ch++;

		util_rec_set(rec, "PLUGIN", line);
		util_rec_set(rec, "LIB", ch);
		util_rec_print(rec);
	}

out:
	util_rec_free(rec);
	fclose(fp);

	return rc;
}

/**
 * Loads a KMS plugin by its plugin name. Looks up the shared library in
 * kms-plugins.conf for the specified plugin name, and loads the shared library
 * via dlopen
 *
 * @param[in] plugin          the plugin name (as in kms-plugins.conf)
 * @param[out] kms_functions  the plugin functions obtain from the plugin
 * @param[out] plugin_lib     the library handle (free with dlclose)
 * @param[out] plugin_name    the full name of the plugin loaded
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int load_kms_plugin(const char *plugin,
			   const struct kms_functions **kms_functions,
			   void **plugin_lib, char **plugin_name, bool verbose)
{
	kms_get_functions_t _kms_get_functions;
	char *so_name = NULL;
	FILE *fp = NULL;
	char line[4096];
	int rc = 0;
	size_t len;
	char *ch;

	util_assert(plugin != NULL, "Internal error: plugin is NULL");
	util_assert(kms_functions != NULL,
		    "Internal error: kms_functions is NULL");
	util_assert(plugin_lib != NULL, "Internal error: plugin_lib is NULL");
	util_assert(plugin_name != NULL, "Internal error: plugin_name is NULL");

	fp = open_kms_plugins_file(verbose);
	if (fp == NULL)
		return -EIO;

	while (fgets(line, sizeof(line), fp) != NULL) {
		len = strlen(line);
		if (len < 1)
			continue;
		if (line[0] == '#')
			continue;
		if (line[len - 1] == '\n')
			line[len - 1] = '\0';
		ch = strchr(line, '=');
		if (ch == NULL) {
			rc = -EPERM;
			warnx("Syntax error in kms-plugins.conf. Line: '%s'",
			      line);
			goto out;
		}

		*ch = '\0';
		ch++;

		if (strcasecmp(line, plugin) == 0) {
			so_name = ch;
			*plugin_name = util_strdup(line);
			break;
		}
	}

	if (so_name == NULL) {
		rc = -ENOENT;
		warnx("KMS plugin '%s' not found.", plugin);
		goto out;
	}

	pr_verbose(verbose, "Loading KMS plugin '%s': '%s'", *plugin_name,
		   so_name);
	*plugin_lib = dlopen(so_name, RTLD_GLOBAL | RTLD_NOW);
	if (*plugin_lib == NULL) {
		pr_verbose(verbose, "%s", dlerror());
		warnx("Failed to load KMS plugin '%s': '%s'", *plugin_name,
		      so_name);
		rc = -ELIBACC;
		goto out;
	}

	_kms_get_functions = (kms_get_functions_t)dlsym(*plugin_lib,
							"kms_get_functions");
	if (_kms_get_functions == NULL) {
		pr_verbose(verbose, "%s", dlerror());
		warnx("Failed to load KMS plugin '%s': '%s'", *plugin_name,
		      so_name);
		rc = -ELIBACC;
		goto out;
	}

	*kms_functions = _kms_get_functions();
	if (*kms_functions == NULL) {
		pr_verbose(verbose, "kms_get_functions() reutned NULL");
		warnx("Failed to load KMS plugin '%s': '%s'", *plugin_name,
		      so_name);
		rc = -ELIBACC;
		goto out;
	}

	pr_verbose(verbose, "Successfully loaded KMS plugin '%s': '%s' (API "
			    "version: %u)", *plugin_name, so_name,
			    (*kms_functions)->api_version);

out:
	if (fp != NULL)
		fclose(fp);
	if (rc != 0 && *plugin_lib != NULL) {
		dlclose(*plugin_lib);
		*plugin_lib = NULL;
	}
	if (rc != 0 && *plugin_name != NULL) {
		free(*plugin_name);
		*plugin_name = NULL;
	}

	return rc;
}

/**
 * Load the kms.conf properties file that is located in the repository
 * directory. The returned properties object must be freed by the caller using
 * properties_free() when no longer needed.
 *
 * @param[in]  repository     the repository directory
 * @param[out] kms_props      On return: a new properties object with the
 *                            properties read from kms.conf.
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int load_kms_properties(const char *repository,
			       struct properties **kms_props, bool verbose)
{
	struct properties *props = NULL;
	char *filename = NULL;
	int rc;

	util_assert(repository != NULL, "Internal error: repository is NULL");
	util_assert(kms_props != NULL, "Internal error: kms_props is NULL");

	util_asprintf(&filename, "%s/%s", repository, KMS_CONFIG_FILE);

	pr_verbose(verbose, "Trying to load '%s'", filename);

	props = properties_new();
	rc = properties_load(props, filename, true);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to load '%s': %s", filename,
			   strerror(-rc));
		goto out;
	}

	*kms_props = props;

out:
	if (filename != NULL)
		free(filename);
	if (rc != 0)
		properties_free(props);

	return rc;
}

/**
 * Save the kms.conf properties file that is located in the repository
 * directory.
 *
 * @param[in] keystore        the keystore
 * @param[in] kms_props       The properties object to save to kms.conf.
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int _save_kms_properties(const struct keystore *keystore,
				struct properties *kms_props, bool verbose)
{
	char *filename = NULL;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(kms_props != NULL, "Internal error: kms_props is NULL");

	util_asprintf(&filename, "%s/%s", keystore->directory, KMS_CONFIG_FILE);

	pr_verbose(verbose, "Saving '%s'", filename);

	rc = properties_save(kms_props, filename, true);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to save '%s': %s", filename,
			   strerror(-rc));
		goto out;
	}

	if (chmod(filename, keystore->mode) != 0) {
		rc = -errno;
		warnx("chmod failed on file '%s': %s", filename, strerror(-rc));
		return rc;
	}

	if (chown(filename, geteuid(), keystore->owner) != 0) {
		rc = -errno;
		warnx("chown failed on file '%s': %s", filename, strerror(-rc));
		return rc;
	}

out:
	if (filename != NULL)
		free(filename);

	return rc;
}

/**
 * Check if a KMS plugin is configured for the current repository, and if so,
 * load the KMS plugin.
 *
 * @param[out] kms_info       Filled with information about the KMS plugin and
 *                            configuration. If no KMS plugin is configured,
 *                            all fields are set to NULL.
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 * Note: It is not an error case of no plugin is configured.
 */
int check_for_kms_plugin(struct kms_info *kms_info, bool verbose)
{
	char *directory, *plugin = NULL;
	int rc;

	util_assert(kms_info != NULL, "Internal error: kms_info is NULL");

	memset(kms_info, 0, sizeof(*kms_info));

	directory = getenv(ENVVAR_ZKEY_REPOSITORY);
	if (directory == NULL)
		directory = DEFAULT_KEYSTORE;

	rc = load_kms_properties(directory, &kms_info->props, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "No KMS plugin is configured");
		rc = 0;
		goto out;
	}

	plugin = properties_get(kms_info->props, KMS_CONFIG_PROP_KMS);
	if (plugin == NULL || strcasecmp(plugin, KMS_CONFIG_LOCAL) == 0) {
		pr_verbose(verbose, "No KMS plugin is configured");
		rc = 0;
		goto out;
	}

	rc = load_kms_plugin(plugin, &kms_info->funcs, &kms_info->plugin_lib,
			     &kms_info->plugin_name, verbose);
	if (rc != 0)
		goto out;

out:
	if (plugin != NULL)
		free(plugin);
	if (rc != 0)
		free_kms_plugin(kms_info);

	return rc;
}

/**
 * Initializes the KMS plugin.
 *
 * @param[in] kms_info        The KMS Plugin info
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
int init_kms_plugin(struct kms_info *kms_info, bool verbose)
{
	char *config_path = NULL;
	char **apqn_list = NULL;
	char *apqns = NULL;
	int i, rc = 0;

	util_assert(kms_info != NULL, "Internal error: kms_info is NULL");

	config_path = properties_get(kms_info->props,
				     KMS_CONFIG_PROP_KMS_CONFIG);
	if (config_path == NULL) {
		warnx("Incomplete KMS configuration");
		rc = -EIO;
		goto out;
	}

	if (kms_info->funcs->kms_initialize != NULL) {
		kms_info->handle = kms_info->funcs->kms_initialize(config_path,
								   verbose);
		if (kms_info->handle == NULL) {
			warnx("KMS plugin '%s' failed to initialize",
			      kms_info->plugin_name);
			rc = -EIO;
			goto out;
		}
	}

	apqns = properties_get(kms_info->props, KMS_CONFIG_PROP_APQNS);
	if (apqns != NULL && strlen(apqns) > 0) {
		apqn_list = str_list_split(apqns);
		for (i = 0; apqn_list[i] != NULL; i++)
			;
		kms_info->num_apqns = i;
		kms_info->apqns = util_malloc(i * sizeof(struct kms_apqn));
		for (i = 0; apqn_list[i] != NULL; i++) {
			if (sscanf(apqn_list[i], "%hx.%hx",
				   &kms_info->apqns[i].card,
				   &kms_info->apqns[i].domain) != 2) {
				warnx("The APQN '%s' is not valid",
				      apqn_list[i]);
				rc = -EINVAL;
				goto out;
			}
		}
	}

out:
	if (config_path != NULL)
		free(config_path);
	if (apqns != NULL)
		free(apqns);
	if (apqn_list != NULL)
		str_list_free_string_array(apqn_list);

	return rc;
}

/**
 * Terminates, free and close a KMS plugin
 *
 * @param[in] kms_info        The KMS Plugin info to free
 */
void free_kms_plugin(struct kms_info *kms_info)
{
	if (kms_info == NULL)
		return;

	if (kms_info->handle != NULL && kms_info->funcs != NULL &&
	    kms_info->funcs->kms_terminate != NULL)
		kms_info->funcs->kms_terminate(kms_info->handle);
	kms_info->handle = NULL;

	if (kms_info->props != NULL)
		properties_free(kms_info->props);
	kms_info->props = NULL;

	if (kms_info->plugin_lib != NULL)
		dlclose(kms_info->plugin_lib);
	kms_info->plugin_lib = NULL;
	kms_info->funcs = NULL;

	if (kms_info->plugin_name != NULL)
		free(kms_info->plugin_name);
	kms_info->plugin_name = NULL;

	if (kms_info->apqns != NULL)
		free(kms_info->apqns);
	kms_info->apqns = NULL;
	kms_info->num_apqns = 0;
}

/**
 * Prints the error message from the KMS plugin's last error
 */
void print_last_kms_error(const struct kms_info *kms_info)
{
	const char *msg;

	if (kms_info == NULL || kms_info->funcs == NULL ||
	    kms_info->funcs->kms_get_last_error == NULL ||
	    kms_info->handle == NULL)
		return;

	msg = kms_info->funcs->kms_get_last_error(kms_info->handle);
	if (msg == NULL)
		return;

	util_print_indented(msg, 0);
}

/**
 * Binds the specified KMS plugin to the current repository.
 * If the repository is already bound to a KMS plugin, then -EALREADY is
 * returned.
 *
 * @param[in] keystore        the keystore to bind to the plugin
 * @param[in] plugin          the name of the KMS plugin to bind
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
int bind_kms_plugin(struct keystore *keystore, const char *plugin,
		    bool verbose)
{
	char *directory, *config_dir = NULL;
	const struct kms_functions *funcs;
	struct properties *props = NULL;
	char *plugin_name = NULL;
	void *plugin_lib = NULL;
	bool created = false;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(plugin != NULL, "Internal error: plugin is NULL");

	rc = load_kms_properties(keystore->directory, &props, verbose);
	if (rc == 0) {
		plugin_name = properties_get(props, KMS_CONFIG_PROP_KMS);
		if (plugin_name != NULL &&
		     strcasecmp(plugin_name, KMS_CONFIG_LOCAL) != 0) {
			warnx("The repository is already bound to KMS plugin "
			     "'%s'", plugin_name);
			rc = -EALREADY;
			goto out;
		}

		properties_free(props);
		props = NULL;
	}

	rc = load_kms_plugin(plugin, &funcs, &plugin_lib, &plugin_name,
			     verbose);
	if (rc != 0)
		goto out;

	directory = getenv(ENVVAR_ZKEY_REPOSITORY);
	if (directory == NULL)
		directory = DEFAULT_KEYSTORE;
	util_asprintf(&config_dir, "%s/%s", directory, plugin_name);
	pr_verbose(verbose, "Plugin config dir: '%s'", config_dir);

	rc = mkdir(config_dir, keystore->mode);
	if (rc != 0) {
		rc = -errno;
		warnx("Failed to create directory '%s': %s", config_dir,
		      strerror(-rc));
		goto out;
	}
	created = true;

	if (chmod(config_dir, keystore->mode) != 0) {
		rc = -errno;
		warnx("chmod failed on directory '%s': %s", config_dir,
		      strerror(-rc));
		return rc;
	}

	if (chown(config_dir, geteuid(), keystore->owner) != 0) {
		rc = -errno;
		warnx("chown failed on directory '%s': %s", config_dir,
		      strerror(-rc));
		return rc;
	}

	if (funcs->kms_bind != NULL) {
		rc = funcs->kms_bind(config_dir);
		if (rc != 0) {
			warnx("KMS plugin '%s' failed to bind to the "
			      "repository: %s", plugin_name, strerror(-rc));
			goto out;
		}
	}

	props = properties_new();
	rc = properties_set(props, KMS_CONFIG_PROP_KMS, plugin_name);
	if (rc != 0)
		goto out;

	rc = properties_set(props, KMS_CONFIG_PROP_KMS_CONFIG, config_dir);
	if (rc != 0)
		goto out;

	rc = _save_kms_properties(keystore, props, verbose);
	if (rc != 0) {
		warnx("Failed to save kms.conf into repository directory");
		goto out;
	}

out:
	if (plugin_name != NULL)
		free(plugin_name);
	if (props != NULL)
		properties_free(props);
	if (plugin_lib != NULL)
		dlclose(plugin_lib);
	if (config_dir != NULL) {
		if (rc != 0 && created)
			rmdir(config_dir);
		free(config_dir);
	}

	return rc;
}

/**
 * Removes a directory and all its contents.
 */
static int remove_directory_recursively(const char *directory)
{
	char *filename = NULL;
	struct dirent *de;
	DIR *dirp;
	int rc = 0;

	dirp = opendir(directory);
	if (dirp == NULL) {
		rc = -errno;
		warnx("Failed to open directory '%s'", directory);
		return rc;
	}

	while ((de = readdir(dirp))) {
		util_asprintf(&filename, "%s/%s", directory, de->d_name);
		if (de->d_type == DT_DIR) {
			if (strcmp(de->d_name, ".") != 0 &&
			    strcmp(de->d_name, "..") != 0)
				rc = remove_directory_recursively(filename);
		} else {
			rc = remove(filename);
			if (rc != 0) {
				rc = -errno;
				warnx("Failed to remove '%s': %s", filename,
				      strerror(-rc));
			}
		}
		free(filename);

		if (rc != 0)
			break;
	}
	closedir(dirp);
	if (rc != 0)
		goto out;

	if (rmdir(directory) != 0) {
		rc = -errno;
		warnx("Failed to remove '%s': %s", filename, strerror(-rc));
		goto out;
	}

out:
	return rc;
}

/**
 * Unbinds the currently bound KMS plugin from the current repository.
 * If the repository is not bound to a KMS plugin, then -ENOENT is
 * returned.
 *
 * @param[in] kms_info        information of the currently bound plugin.
 *                            This function does NOT free the plugin, this must
 *                            be done by the caller using free_kms_plugin().
 * @param[in] keystore        the keystore to bind to the plugin
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
int unbind_kms_plugin(struct kms_info *kms_info, struct keystore *keystore,
		      bool UNUSED(verbose))
{
	char *config_dir = NULL;
	char *filename = NULL;
	int rc;

	util_assert(kms_info != NULL, "Internal error: kms_info is NULL");
	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	if (kms_info->plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
		goto out;
	}

	if (kms_info->funcs->kms_deconfigure != NULL &&
	    kms_info->handle != NULL) {
		rc = kms_info->funcs->kms_deconfigure(kms_info->handle);
		if (rc != 0) {
			warnx("KMS plugin '%s' failed to unbind from the "
			      "repository: %s", kms_info->plugin_name,
			      strerror(-rc));
			print_last_kms_error(kms_info);
			goto out;
		}
	}

	config_dir = properties_get(kms_info->props,
				    KMS_CONFIG_PROP_KMS_CONFIG);
	if (config_dir != NULL) {
		rc = remove_directory_recursively(config_dir);
		if (rc != 0) {
			warnx("Failed to remove the KMS plugin's config "
			      "directory: %s", strerror(-rc));
			goto out;
		}
	}

	util_asprintf(&filename, "%s/%s", keystore->directory, KMS_CONFIG_FILE);
	rc = remove(filename);
	if (rc != 0) {
		rc = -errno;
		warnx("Failed to remove '%s': %s", filename, strerror(-rc));
		goto out;
	}

out:
	if (config_dir != NULL)
		free(config_dir);
	if (filename != NULL)
		free(filename);
	return rc;
}

/**
 * Displays information about the KMS plugin and its configuration
 *
 * @param[in] kms_info        information of the currently bound plugin.
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
int print_kms_info(struct kms_info *kms_info)
{
	bool first;
	int rc = 0;
	size_t i;

	util_assert(kms_info != NULL, "Internal error: kms_info is NULL");

	if (kms_info->plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
		goto out;
	}

	printf("KMS-Plugin:             %s\n", kms_info->plugin_name);

	if (kms_info->funcs->kms_supports_key_type != NULL) {
		for (i = 0, first = true; key_types[i] != NULL; i++) {
			if (kms_info->funcs->kms_supports_key_type(
					kms_info->handle, key_types[i])) {
				printf("  %s  %s\n", first ?
				       "Supported key types:" :
				       "                    ", key_types[i]);
				first = false;
			}
		}
		if (first)
			printf("  Supported key types:  (none)\n");
	} else {
		printf("  Supported key types:  (unknown)\n");
	}

	if (kms_info->apqns == NULL || kms_info->num_apqns == 0) {
		printf("  APQNs:                (configuration required)\n");
		goto kms_info;
	}

	for (i = 0; i < kms_info->num_apqns; i++)
		printf("  %s                %02x.%04x\n",
		       i == 0 ? "APQNs:" : "      ",
		       kms_info->apqns[i].card,
		       kms_info->apqns[i].domain);

kms_info:
	if (kms_info->funcs->kms_display_info == NULL)
		goto out;

	rc = kms_info->funcs->kms_display_info(kms_info->handle);
	if (rc != 0) {
		warnx("Failed to display information about the plugin: %s",
		      strerror(-rc));
		print_last_kms_error(kms_info);
		goto out;
	}

out:
	return rc;
}

/**
 * Gets the KMS plugin command specific option vector and puts them into the
 * placeholder slots in opt_vec.
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] opt_vec         the option vector to modify.
 * @param[in] placeholder_cmd the command with which the placeholder option
 *                            vector entries are marked
 * @param[in] plugin_command  the plugin command to get the options for
 * @param[in] opt_vec_command the command to use in the option vector entries
 * @param[out] first_plugin_opt on return: the index of the first plugin option
 *                            in opt_vec, or -1 if no plugin options are used.
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
int get_kms_options(struct kms_info *kms_info, struct util_opt *opt_vec,
		    const char *placeholder_cmd, const char *plugin_command,
		    const char *opt_vec_command, int *first_plugin_opt,
		    bool verbose)
{
	const struct util_opt *plugin_opts;
	int i, k, first = 0, num_slots = 0;

	util_assert(kms_info != NULL, "Internal error: kms_info is NULL");
	util_assert(opt_vec != NULL, "Internal error: opt_vec is NULL");
	util_assert(placeholder_cmd != NULL,
		    "Internal error: placeholder_cmd is NULL");
	util_assert(plugin_command != NULL,
		    "Internal error: plugin_command is NULL");
	util_assert(first_plugin_opt != NULL,
		    "Internal error: first_plugin_opt is NULL");

	*first_plugin_opt = -1;

	if (kms_info->plugin_lib == NULL) {
		pr_verbose(verbose, "not bound to a KMS plugin");
		return 0;
	}

	if (kms_info->funcs->kms_get_command_options == NULL) {
		pr_verbose(verbose, "Plugin does not support command options");
		return 0;
	}

	if (strcmp(plugin_command, KMS_COMMAND_CONFIGURE) != 0 &&
	    strcmp(plugin_command, KMS_COMMAND_REENCIPHER) != 0 &&
	    strcmp(plugin_command, KMS_COMMAND_GENERATE) != 0 &&
	    strcmp(plugin_command, KMS_COMMAND_REMOVE) != 0 &&
	    strcmp(plugin_command, KMS_COMMAND_LIST) != 0 &&
	    strcmp(plugin_command, KMS_COMMAND_LIST_IMPORT) != 0) {
		pr_verbose(verbose, "Command %s is not eligible for plugin "
			   "options", plugin_command);
		return 0;
	}

	for (i = 0; opt_vec[i].desc != NULL; i++) {
		if (opt_vec[i].command != NULL &&
		    strcmp(opt_vec[i].command, placeholder_cmd) == 0) {
			if (first == 0)
				first = i;
			num_slots++;
		}
	}

	pr_verbose(verbose, "%u placeholder slots found", num_slots);

	plugin_opts = kms_info->funcs->kms_get_command_options(plugin_command,
							       num_slots);
	if (plugin_opts == NULL) {
		pr_verbose(verbose, "No plugin options for command %s",
			   plugin_command);
		return 0;
	}

	for (k = 0, i = first; plugin_opts[k].desc != NULL &&
			       i < first + num_slots; i++, k++) {
		memcpy(&opt_vec[i], &plugin_opts[k], sizeof(struct util_opt));
		opt_vec[i].command = (char *)opt_vec_command;
	}

	pr_verbose(verbose, "%u plugin options", k);

	*first_plugin_opt = first;

	return 0;
}

/**
 * Checks if the option is a KMS plugin specific option and if so, adds it to
 * list of KMS options. If the option is not handled by the plugin, then
 * -ENOENT is returned.
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] opt_vec         the option vector.
 * @param[in] first_kms_option index of first KMS option in opt_vec
 * @param[in] command         the plugin command to handle
 * @param[in] option          the option character to handle
 * @param[in] optarg          the option argument or NULL
 * @param[out] kms_options    on return: an array of KMS options handled. The
 *                            array is resized to add more options.
 * @param[out] num_kms_options on return: The number of options in above array
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 *
 */
int handle_kms_option(struct kms_info *kms_info, struct util_opt *opt_vec,
		      int first_kms_option, const char *command, int option,
		      const char *optarg, struct kms_option **kms_options,
		      size_t *num_kms_options, bool verbose)
{
	struct kms_option opt = { .option = option, .argument = optarg };
	int i;

	util_assert(kms_info != NULL, "Internal error: kms_info is NULL");
	util_assert(opt_vec != NULL, "Internal error: opt_vec is NULL");
	util_assert(command != NULL, "Internal error: command is NULL");
	util_assert(kms_options != NULL, "Internal error: kms_options is NULL");
	util_assert(num_kms_options != NULL,
		    "Internal error: num_kms_options is NULL");

	if (kms_info->plugin_lib == NULL) {
		pr_verbose(verbose, "not bound to a KMS plugin");
		return -ENOENT;
	}

	if (first_kms_option < 0) {
		pr_verbose(verbose, "No plugin specific options");
		return -ENOENT;
	}

	for (i = first_kms_option; opt_vec[i].command != NULL &&
		strcmp(opt_vec[i].command, command) == 0; i++) {
		if ((opt_vec[i].flags & UTIL_OPT_FLAG_SECTION) == 0 &&
		    opt_vec[i].option.val == option) {
			ARRAY_ADD(*kms_options, *num_kms_options,
				  sizeof(struct kms_option), &opt);
			return 0;
		}
	}

	return -ENOENT;
}

struct card_info {
	enum card_type type;
	int min_level;
	struct fw_version min_fw_version;
	struct kms_apqn *apqns;
	size_t num_apqns;
};

/**
 * Parses an APQN and checks if it is online.
 *
 * @param[in] apqn            the APQN to parse
 * @param[out] kms_apqn       the parse APQN is filled in
 * @param{in] check           if true, the APQN is checked to be online
 * @param[in] cards           An array of cards types with its requirements
 * @param[in] num_cards       The number of elements in above array
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int _parse_and_check_apqn(const char *apqn, struct kms_apqn *kms_apqn,
				 bool check, struct card_info *cards,
				 size_t num_cards)
{
	struct card_info *card_info = NULL;
	struct fw_version fw_version;
	int rc, card, domain, level;
	enum card_type type;
	regmatch_t pmatch[1];
	regex_t reg_buf;
	unsigned int num;
	size_t i;

	rc = regcomp(&reg_buf, "[[:xdigit:]]+\\.[[:xdigit:]]", REG_EXTENDED);
	if (rc != 0)
		return -EIO;

	rc = regexec(&reg_buf, apqn, (size_t)1, pmatch, 0);
	if (rc != 0) {
		warnx("The APQN '%s' is not valid", apqn);
		rc = -EINVAL;
		goto out;
	}

	if (sscanf(apqn, "%x.%x%n", &card, &domain, &num) != 2 ||
	    num != strlen(apqn) || card < 0 || card > 0xff ||
	    domain < 0 || domain > 0xFFFF) {
		warnx("The APQN '%s' is not valid", apqn);
		rc = -EINVAL;
		goto out;
	}

	kms_apqn->card = card;
	kms_apqn->domain = domain;

	if (!check) {
		rc = 0;
		goto out;
	}

	type = sysfs_get_card_type(card);
	if (type == -1) {
		warnx("The APQN %02x.%04x is not available or has an "
		     "unsupported type", card, domain);
		rc = -EIO;
		goto out;
	}

	rc = sysfs_is_apqn_online(card, domain, CARD_TYPE_ANY);
	if (rc != 1) {
		warnx("The APQN %02x.%04x is not available or not online",
		      card, domain);
		rc = -EIO;
		goto out;
	}

	for (i = 0, card_info = NULL; i < num_cards; i++) {
		if (cards[i].type == type) {
			card_info = &cards[i];
			break;
		}
	}
	if (card_info == NULL) {
		warnx("APQN %02x.%04x: The card type is not supported by the "
		      "KMS plugin", card, domain);
		rc = -EIO;
		goto out;
	}

	level = sysfs_get_card_level(card);
	if (level < card_info->min_level) {
		warnx("APQN %02x.%04x: The card level is less than CEX%dn.",
		      card, domain, card_info->min_level);
		rc = -EIO;
		goto out;
	}

	rc = sysfs_get_firmware_version(card, &fw_version, false);
	if (rc == 0) {
		if (fw_version.api_ordinal <
				card_info->min_fw_version.api_ordinal) {
			warnx("APQN %02x.%04x: The firmware version is too "
			      "less", card, domain);
			rc = -EIO;
			goto out;
		}
		if (card_info->min_level > 0 && card_info->min_level == level &&
		    (fw_version.major < card_info->min_fw_version.major ||
		     (fw_version.major == card_info->min_fw_version.major &&
		      fw_version.minor < card_info->min_fw_version.minor))) {
			warnx("APQN %02x.%04x: The firmware version is too "
			      "less", card, domain);
			rc = -EIO;
			goto out;
		}
	}

	rc = 0;

out:
	regfree(&reg_buf);
	return rc;
}

/**
 * Add APQNs to the current APQN association of the KMS plugin
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] apqns           the APQNs specification from --apqns option
 * @param[in] cards           An array of card types with its requirements
 * @param[in] num_cardsqs     The number of elements in above array
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int _add_kms_apqns(struct kms_info *kms_info, const char *apqns,
			  struct card_info *cards, size_t num_cards)
{
	struct kms_apqn kms_apqn;
	char **new_apqns;
	int i, rc = 0;
	size_t k;

	new_apqns = str_list_split(apqns);

	for (i = 0; new_apqns[i] != NULL; i++) {
		rc = _parse_and_check_apqn(new_apqns[i], &kms_apqn, true,
					   cards, num_cards);
		if (rc != 0)
			goto out;

		for (k = 0; k < kms_info->num_apqns; k++) {
			if (kms_apqn.card == kms_info->apqns[k].card &&
			    kms_apqn.domain == kms_info->apqns[k].domain) {
				warnx("APQN %02x.%04x is already associated "
				      "with the KMS plugin", kms_apqn.card,
				      kms_apqn.domain);
				rc = -EEXIST;
				goto out;
			}
		}

		ARRAY_ADD(kms_info->apqns, kms_info->num_apqns,
			  sizeof(struct kms_apqn), &kms_apqn);
	}

out:
	str_list_free_string_array(new_apqns);

	return rc;
}

/**
 * Remove APQNs from the current APQN association of the KMS plugin
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] apqns           the APQNs specification from --apqns option
 * @param[in] cards           An array of card types with its requirements
 * @param[in] num_cards       The number of elements in above array
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int _remove_kms_apqns(struct kms_info *kms_info, const char *apqns,
			     struct card_info *cards, size_t num_cards)
{
	struct kms_apqn kms_apqn;
	char **rem_apqns;
	int i, rc = 0;
	size_t k;

	rem_apqns = str_list_split(apqns);

	for (i = 0; rem_apqns[i] != NULL; i++) {
		rc = _parse_and_check_apqn(rem_apqns[i], &kms_apqn, false,
					   cards, num_cards);
		if (rc != 0)
			goto out;

		for (k = 0; k < kms_info->num_apqns; k++) {
			if (kms_apqn.card == kms_info->apqns[k].card &&
			    kms_apqn.domain == kms_info->apqns[k].domain) {
				ARRAY_REMOVE(kms_info->apqns,
					     kms_info->num_apqns,
					     sizeof(struct kms_apqn), k);
				rc = 0;
				goto out;
			}
		}

		warnx("APQN %02x.%04x is not associated with the KMS plugin",
		      kms_apqn.card, kms_apqn.domain);
		rc = -ENOENT;
		goto out;
	}

out:
	free(rem_apqns);

	return rc;
}

/**
 * Set the APQN association of the KMS plugin
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] apqns           the APQNs specification from --apqns option
 * @param[in] cards           An array of card types with its requirements
 * @param[in] num_cards       The number of elements in above array
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int _set_kms_apqns(struct kms_info *kms_info, const char *apqns,
			  struct card_info *cards, size_t num_cards)
{
	if (kms_info->apqns != NULL)
		free(kms_info->apqns);
	kms_info->apqns = NULL;
	kms_info->num_apqns = 0;

	if (strlen(apqns) == 0) {
		/* Indicate empty list specified */
		kms_info->apqns = util_malloc(sizeof(struct kms_apqn));
		return 0;
	}

	return _add_kms_apqns(kms_info, apqns, cards, num_cards);
}

/**
 * Change the APQN association of the KMS plugin
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] apqns           the APQNs specification from --apqns option
 * @param[in] cards           An array of card types with its requirements
 * @param[in] num_cards       The number of elements in above array
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int _change_kms_apqns(struct kms_info *kms_info, const char *apqns,
			     struct card_info *cards, size_t num_cards)
{
	switch (*apqns) {
	case '+':
		if (kms_info->apqns != NULL && kms_info->num_apqns > 0)
			return _add_kms_apqns(kms_info, &apqns[1], cards,
					      num_cards);
		else
			return _set_kms_apqns(kms_info, &apqns[1], cards,
					      num_cards);
	case '-':
		if (kms_info->apqns != NULL && kms_info->num_apqns > 0)
			return _remove_kms_apqns(kms_info, &apqns[1], cards,
						 num_cards);

		warnx("No APQNs are currently associated with the KMS plugin");
		return -ENOENT;
	default:
		return _set_kms_apqns(kms_info, apqns, cards, num_cards);
	}
}

/**
 * Returns the crypto card requirements per card type base on the key types that
 * the KMS plugin supports.
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[out] cards          on return: An array of card types with its
 *                            requirements. The caller must free this array if
 *                            no longer used.
 * @param[out] num_cards      on return: The number of elements in above array
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns the card type
 */
static int _get_supported_card_types(struct kms_info *kms_info,
				     struct card_info **cards,
				     size_t *num_cards, bool verbose)
{
	struct card_info new_card = { 0 };
	const struct fw_version *fw_ver;
	struct card_info *req;
	enum card_type type;
	int i, level;
	size_t k;

	util_assert(kms_info != NULL, "Internal error: kms_info is NULL");
	util_assert(cards != NULL, "Internal error: reqs is NULL");
	util_assert(num_cards != NULL, "Internal error: num_reqs is NULL");

	*cards = NULL;
	*num_cards = 0;

	if (kms_info->funcs->kms_supports_key_type == NULL)
		return 0;

	for (i = 0; key_types[i] != NULL; i++) {
		if (kms_info->funcs->kms_supports_key_type(kms_info->handle,
							   key_types[i])) {
			pr_verbose(verbose, "KMS plugin supports key type %s",
				   key_types[i]);

			type = get_card_type_for_keytype(key_types[i]);
			level = get_min_card_level_for_keytype(key_types[i]);
			fw_ver = get_min_fw_version_for_keytype(key_types[i]);

			for (req = NULL, k = 0; k < *num_cards; k++) {
				if ((*cards)[k].type == type)
					req = &(*cards)[k];
			}

			if (req == NULL) {
				new_card.type = type;
				new_card.min_level = level;
				if (fw_ver != NULL)
					new_card.min_fw_version = *fw_ver;

				ARRAY_ADD(*cards, *num_cards,
					  sizeof(struct card_info),
					  &new_card);
				req = &(*cards)[*num_cards - 1];
			}

			if (req->min_level < level) {
				req->min_level = level;

				if (fw_ver != NULL) {
					if (req->min_fw_version.api_ordinal <
							fw_ver->api_ordinal ||
					    req->min_fw_version.major <
							fw_ver->major ||
					    (req->min_fw_version.major ==
							fw_ver->major &&
					     req->min_fw_version.minor <
							fw_ver->minor))
						req->min_fw_version = *fw_ver;
				}
			}

			pr_verbose(verbose, "Card type: %d", req->type);
			pr_verbose(verbose, "Card level: %d", req->min_level);
			pr_verbose(verbose, "Fw version: %d.%d (API: %d)",
				   req->min_fw_version.major,
				   req->min_fw_version.minor,
				   req->min_fw_version.api_ordinal);
		}
	}

	pr_verbose(verbose, "%lu card type are supported", *num_cards);

	return 0;
}

/**
 * Builds an APQN list per card type.
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] cards           An array of card types to build APQNs lists for
 * @param[in] num_cards       The number of elements in above array
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int _get_apqns_per_card_type(struct kms_info *kms_info,
				    struct card_info *cards, size_t num_cards)
{
	enum card_type type;
	size_t i, k;
	bool found;

	for (i = 0; i < kms_info->num_apqns; i++) {
		if (!sysfs_is_apqn_online(kms_info->apqns[i].card,
					  kms_info->apqns[i].domain, 0)) {
			warnx("The APQN %02x.%04x is not online",
			      kms_info->apqns[i].card,
			      kms_info->apqns[i].domain);
			return -EIO;
		}

		type = sysfs_get_card_type(kms_info->apqns[i].card);
		for (k = 0, found = false; k < num_cards; k++) {
			if (cards[k].type == type) {
				ARRAY_ADD(cards[k].apqns, cards[k].num_apqns,
					  sizeof(struct kms_apqn),
					  &kms_info->apqns[i]);
				found = true;
			}
		}

		if (!found) {
			warnx("The APQN %02x.%04x is not available of has an "
			      "unsupported type", kms_info->apqns[i].card,
			      kms_info->apqns[i].domain);
			return -EIO;
		}
	}

	return 0;
}

/**
 * Build an APQN string from an APQN array
 *
 * @param[in] apqns           An array of APQNs
 * @param[in] num_apqns       The number of elements in above array
 *
 * @return an allocated string with the APQNs
 */
static char *_build_apqn_string(struct kms_apqn *apqns, size_t num_apqns)
{
	char *apqn_str, *str;
	size_t size, i;

	if (num_apqns == 0) {
		apqn_str = util_malloc(1);
		*apqn_str = '\0';
		return apqn_str;
	}

	size = num_apqns * 8; /* 'cc.dddd' plus ',' or '\0' */
	apqn_str = util_malloc(size);

	str = apqn_str;
	for (i = 0; i < num_apqns; i++) {
		if (i != 0) {
			*str = ',';
			str++;
		}

		sprintf(str, "%02x.%04x", apqns[i].card, apqns[i].domain);
		str += 7;
	}

	return apqn_str;
}

/**
 * Update the APQNS properties in the KMS properties to reflect the list of
 * APQNs contained in kms_info and supported card types.
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] cards           An array of card types supported
 * @param[in] num_cards       The number of elements in above array
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int _update_apqns_properties(struct kms_info *kms_info,
				    struct card_info *cards, size_t num_cards,
				    bool verbose)
{
	char *apqns = NULL;
	char *prop;
	size_t i;
	int rc;

	rc = properties_remove(kms_info->props,
			       KMS_CONFIG_PROP_CCA_APQNS);
	if (rc != 0 && rc != -ENOENT) {
		pr_verbose(verbose, "Failed to remove the APQNS "
			   "property: %s", strerror(-rc));
		return rc;
	}

	rc = properties_remove(kms_info->props,
			       KMS_CONFIG_PROP_EP11_APQNS);
	if (rc != 0 && rc != -ENOENT) {
		pr_verbose(verbose, "Failed to remove the APQNS "
			   "property: %s", strerror(-rc));
		return rc;
	}

	if (kms_info->num_apqns == 0) {
		rc = properties_remove(kms_info->props, KMS_CONFIG_PROP_APQNS);
		if (rc != 0 && rc != -ENOENT) {
			pr_verbose(verbose, "Failed to remove the APQNS "
				   "property: %s", strerror(-rc));
			return rc;
		}

		pr_verbose(verbose, "APQNs: none");
		return 0;
	}

	apqns = _build_apqn_string(kms_info->apqns, kms_info->num_apqns);
	pr_verbose(verbose, "APQNs: '%s'", apqns);

	rc = properties_set(kms_info->props, KMS_CONFIG_PROP_APQNS, apqns);
	free(apqns);

	if (rc != 0) {
		pr_verbose(verbose, "Failed to set the APQNS property: %s",
			   strerror(-rc));
		goto out;
	}

	for (i = 0; i < num_cards; i++) {
		switch (cards[i].type) {
		case CARD_TYPE_CCA:
			prop = KMS_CONFIG_PROP_CCA_APQNS;
			break;
		case CARD_TYPE_EP11:
			prop = KMS_CONFIG_PROP_EP11_APQNS;
			break;
		default:
			continue;
		}

		apqns = _build_apqn_string(cards[i].apqns, cards[i].num_apqns);
		pr_verbose(verbose, "%s: '%s'", prop, apqns);

		rc = properties_set(kms_info->props, prop, apqns);
		free(apqns);

		if (rc != 0) {
			pr_verbose(verbose, "Failed to set the %s property: %s",
				   prop, strerror(-rc));
			goto out;
		}
	}

out:
	return rc;
}

/**
 * Cross checks the APQNs per card type
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] cards           An array of card types to build APQNs lists for
 * @param[in] num_cards       The number of elements in above array
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int _cross_check_apqns(struct card_info *cards, size_t num_cards,
			      bool verbose)
{
	char *apqns;
	size_t i;
	int rc;

	for (i = 0; i < num_cards; i++) {
		if (cards[i].num_apqns == 0)
			continue;

		apqns = _build_apqn_string(cards[i].apqns, cards[i].num_apqns);

		rc = cross_check_apqns(apqns, NULL, cards[i].min_level,
				       &cards[i].min_fw_version, cards[i].type,
				       true, verbose);
		free(apqns);

		if (rc == -ENOTSUP)
			continue;
		if (rc != 0)
			return rc;
	}

	return 0;
}

/**
 * Checks existing KMS-bound keys in the keystore of the new set of APQNs
 * would make them unusable. The user is prompted if so.
 *
 * @param[in] keystore        the keystore
 * @param[in] cards           An array of card types
 * @param[in] num_cards       The number of elements in above array
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int _check_keystore_keys(struct keystore *keystore,
				struct card_info *cards, size_t num_cards)
{
	struct kms_info *kms_info = keystore->kms_info;
	struct card_info *card = NULL;
	enum card_type type;
	size_t i, k;
	char *msg;
	int rc;

	for (i = 0; key_types[i] != NULL; i++) {
		type = get_card_type_for_keytype(key_types[i]);
		if (type <= 0)
			continue;

		for (k = 0; k < num_cards; k++) {
			if (cards[k].type == type) {
				card = &cards[k];
				break;
			}
		}
		if (card == NULL)
			continue;

		pr_verbose(keystore->verbose, "Checking repository for "
			   "KMS-bound keys of type %s", key_types[i]);

		if (card->num_apqns > 0) {
			pr_verbose(keystore->verbose, "Set of APQNs for key "
				   "type %s is not empty", key_types[i]);
			continue;
		}

		util_asprintf(&msg, "The following keys of type '%s' are bound "
			      "to KMS plugin '%s', and may become unusable "
			      "with this set of APQNs:", key_types[i],
			      kms_info->plugin_name);
		rc = keystore_msg_for_kms_key(keystore, key_types[i], msg);
		free(msg);

		if (rc == -ENOENT) {
			pr_verbose(keystore->verbose, "No keys of type %s "
				   "found", key_types[i]);
			continue;
		}
		if (rc != 0)
			return rc;

		printf("Do you want to continue [y/N]? ");
		if (!prompt_for_yes(keystore->verbose)) {
			warnx("Operation aborted");
			return -ECANCELED;
		}
	}

	return 0;
}

/**
 * Updates existing KMS-bound keys in the keystore with the set of APQNs that
 * match the key type.
 *
 * @param[in] keystore        the keystore
 * @param[in] cards           An array of card types
 * @param[in] num_cards       The number of elements in above array
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
static int _update_keystore_keys(struct keystore *keystore,
				 struct card_info *cards, size_t num_cards)
{
	struct card_info *card = NULL;
	enum card_type type;
	size_t i, k;
	char *apqns;
	int rc;

	for (i = 0; key_types[i] != NULL; i++) {
		type = get_card_type_for_keytype(key_types[i]);
		if (type <= 0)
			continue;

		for (k = 0; k < num_cards; k++) {
			if (cards[k].type == type) {
				card = &cards[k];
				break;
			}
		}
		if (card == NULL)
			continue;

		apqns = _build_apqn_string(card->apqns, card->num_apqns);

		pr_verbose(keystore->verbose, "Changing KMS-bound keys of "
			   "type %s to: '%s'", key_types[i], apqns);

		rc = keystore_kms_keys_set_property(keystore, key_types[i],
						    PROP_NAME_APQNS, apqns);
		free(apqns);
		if (rc != 0) {
			warnx("Failed to update APQNs for KMS-bound keys of "
			      "type %s: %s", key_types[i], strerror(-rc));
			return rc;
		}
	}

	return 0;
}

/**
 * Performs configuration of the KMS plugin.
 *
 * @param[in] keystore        the keystore
 * @param[in] apqns           the APQNs specification from --apqns option, or
 *                            NULL if the option was not specified
 * @param[in] kms_options     an array of KMS options specified, or NULL if no
 *                            KMS options have been specified
 * @param[in] num_kms_options the number of options in above array
 * @param[in] has_plugin_optins if true, then the KMS plugin uses KMS specific
 *                            options, false of no options are supported
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 * -EAGAIN to indicate that the specified configuration was accepted so far, but
 * the configuration is still incomplete, and needs to be completed.
 */
int configure_kms_plugin(struct keystore *keystore, const char *apqns,
			 struct kms_option *kms_options, size_t num_kms_options,
			 bool has_plugin_optins, bool verbose)
{
	struct card_info *cards = NULL;
	struct kms_info *kms_info;
	bool incomplete = false;
	size_t i, num_cards = 0;
	int rc = 0;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	kms_info = keystore->kms_info;
	if (kms_info->plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
		goto out;
	}

	if (apqns == NULL) {
		if (kms_info->apqns == NULL || kms_info->num_apqns == 0) {
			warnx("Option '--apqns|-a' is required when no APQNS "
			      "are associated with the KMS plugin");
			util_prg_print_parse_error();
			rc = -EINVAL;
			goto out;
		}

		if (has_plugin_optins && num_kms_options == 0) {
			warnx("At least one option is required");
			util_prg_print_parse_error();
			rc = -EINVAL;
			goto out;
		}
	}

	if (apqns != NULL) {
		rc = _get_supported_card_types(kms_info, &cards, &num_cards,
					       verbose);
		if (rc != 0)
			goto out;
		if (num_cards == 0) {
			warnx("The KMS plugin does not support any key type");
			rc = -EIO;
			goto out;
		}

		rc = _change_kms_apqns(kms_info, apqns, cards, num_cards);
		if (rc != 0)
			goto out;

		rc = _get_apqns_per_card_type(kms_info, cards, num_cards);
		if (rc != 0)
			goto out;

		rc = _cross_check_apqns(cards, num_cards, verbose);
		if (rc != 0)
			goto out;

		rc = _check_keystore_keys(keystore, cards, num_cards);
		if (rc != 0)
			goto out;

		rc = _update_apqns_properties(kms_info, cards, num_cards,
					      verbose);
		if (rc != 0) {
			warnx("Failed to update the APQNs: %s", strerror(-rc));
			goto out;
		}
	}

	if (kms_info->funcs->kms_configure != NULL) {
		rc = kms_info->funcs->kms_configure(kms_info->handle,
						    apqns != NULL ?
							kms_info->apqns : NULL,
						    apqns != NULL ?
							kms_info->num_apqns : 0,
						    kms_options,
						    num_kms_options);

		if (rc == -EAGAIN) {
			incomplete = true;
			rc = 0;
		}

		if (rc != 0) {
			warnx("Failed to configure the KMS plugin: '%s'",
			      strerror(-rc));
			print_last_kms_error(kms_info);
			goto out;
		}
	}

	if (apqns != NULL) {
		rc = _save_kms_properties(keystore, kms_info->props, verbose);
		if (rc != 0)
			goto out;

		rc = _update_keystore_keys(keystore, cards, num_cards);
		if (rc != 0)
			goto out;

		if (kms_info->num_apqns == 0)
			incomplete = true;
	}

out:
	if (cards != NULL) {
		for (i = 0; i < num_cards; i++)
			if (cards[i].apqns != NULL)
				free(cards[i].apqns);
		free(cards);
	}

	if (rc == 0 && incomplete)
		rc = -EAGAIN;
	return rc;
}

/**
 * Performs re-enciphering of secure keys internally used by the KMS plugin
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] from_old        If true the keys are reenciphered from the OLD to
 *                            the CURRENT master key.
 * @param[in] to_new          If true the keys are reenciphered from the CURRENT
 *                            to the OLD master key.
 * @param[in] inplace         if true, the key will be re-enciphere in-place
 * @param[in] staged          if true, the key will be re-enciphere not in-place
 * @param[in] complete        if true, a pending re-encipherment is completed
 * @param[in] kms_options     an array of KMS options specified, or NULL if no
 *                            KMS options have been  specified
 * @param[in] num_kms_options the number of options in above array
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 * -EAGAIN to indicate that the specified configuration was accepted so far, but
 * the configuration is still incomplete, and needs to be completed.
 */
int reencipher_kms(struct kms_info *kms_info, bool from_old, bool to_new,
		   bool inplace, bool staged, bool complete,
		   struct kms_option *kms_options, size_t num_kms_options,
		   bool verbose)
{
	enum kms_reencipher_mode mode = KMS_REENC_MODE_AUTO;
	enum kms_reenc_mkreg mkreg = KMS_REENC_MKREG_AUTO;
	int rc = 0;

	util_assert(kms_info != NULL, "Internal error: kms_info is NULL");

	if (kms_info->plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
		goto out;
	}

	if (kms_info->funcs->kms_reenciper == NULL) {
		pr_verbose(verbose, "The KMS plugin does not support "
			   "reencipher");
		goto out;
	}

	if (inplace)
		mode = KMS_REENC_MODE_IN_PLACE;
	else if (staged)
		mode = KMS_REENC_MODE_STAGED;
	else if (complete)
		mode = KMS_REENC_MODE_STAGED_COMPLETE;

	if (from_old && !to_new) {
		mkreg = KMS_REENC_MKREG_FROM_OLD;
		if (mode == KMS_REENC_MODE_AUTO)
			mode = KMS_REENC_MODE_IN_PLACE;
	} else if (to_new && !from_old) {
		mkreg = KMS_REENC_MKREG_TO_NEW;
		if (mode == KMS_REENC_MODE_AUTO)
			mode = KMS_REENC_MODE_STAGED;
	} else if (from_old && to_new) {
		mkreg = KMS_REENC_MKREG_FROM_OLD_TO_NEW;
		if (mode == KMS_REENC_MODE_AUTO)
			mode = KMS_REENC_MODE_STAGED;
	}

	rc = kms_info->funcs->kms_reenciper(kms_info->handle, mode, mkreg,
					    kms_options, num_kms_options);
	if (rc != 0) {
		warnx("Failed to reencipher KMS plugin internal keys: %s",
		      strerror(-rc));
		print_last_kms_error(kms_info);
		goto out;
	}

out:
	return rc;
}

/**
 * Performs a login with the KMS plugin, if one is configured
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
int perform_kms_login(struct kms_info *kms_info, bool verbose)
{
	int rc = 0;

	util_assert(kms_info != NULL, "Internal error: kms_info is NULL");

	if (kms_info->plugin_lib == NULL) {
		rc = -ENOENT;
		warnx("The repository is not bound to a KMS plugin");
		goto out;
	}

	if (kms_info->funcs->kms_login == NULL) {
		pr_verbose(verbose, "The KMS plugin does not support login");
		goto out;
	}

	rc = kms_info->funcs->kms_login(kms_info->handle);
	if (rc != 0) {
		warnx("Failed to login into the KMS: %s",
		      strerror(-rc));
		print_last_kms_error(kms_info);
		goto out;
	}

out:
	return rc;
}

/**
 * Gets the subset of the APQNs of a KMS plugin for a specific key type
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] key_type        the key type to get the APQNs for, or NULL to
 *                            get all APQNs associated with the KMS
 * @param[in] cross_check     if true, the APQNs are cross checked
 * @param[out] apqns          On return the list of APQNs as comma separated
 *                            string. Must be freed by the caller.
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 * If the KMS plugin does not support the key type, then -ENOTSUP is returned
 */
int get_kms_apqns_for_key_type(struct kms_info *kms_info, const char *key_type,
			       bool cross_check, char **apqns, bool verbose)
{
	const struct fw_version *fw_version;
	const char *prop_name;
	int rc = 0, min_level;
	enum card_type type;

	util_assert(kms_info != NULL, "Internal error: kms_info is NULL");
	util_assert(apqns != NULL, "Internal error: apqns is NULL");

	if (kms_info->plugin_lib == NULL) {
		warnx("The repository is not bound to a KMS plugin");
		return -ENOENT;
	}

	if (key_type != NULL) {
		if (kms_info->funcs->kms_supports_key_type == NULL)
			return -ENOTSUP;

		if (!kms_info->funcs->kms_supports_key_type(kms_info->handle,
							   key_type))
			return -ENOTSUP;
	}

	type = get_card_type_for_keytype(key_type);
	switch (type) {
	case CARD_TYPE_CCA:
		prop_name = KMS_CONFIG_PROP_CCA_APQNS;
		break;
	case CARD_TYPE_EP11:
		prop_name = KMS_CONFIG_PROP_EP11_APQNS;
		break;
	default:
		prop_name = KMS_CONFIG_PROP_APQNS;
		break;
	}

	*apqns = properties_get(kms_info->props, prop_name);
	if (*apqns == NULL)
		return -ENOTSUP;

	if (str_list_count(*apqns) == 0) {
		rc = -ENOTSUP;
		goto out;
	}

	if (cross_check) {
		min_level = get_min_card_level_for_keytype(key_type);
		fw_version = get_min_fw_version_for_keytype(key_type);

		rc = cross_check_apqns(*apqns, NULL, min_level, fw_version,
				       type, true, verbose);
		if (rc == -ENOTSUP)
			rc = 0;
		if (rc != 0) {
			warnx("Your master key setup is improper");
			goto out;
		}
	}

out:
	if (rc != 0) {
		free(*apqns);
		*apqns = NULL;
	}

	return rc;
}

/**
 * Returns a system specific version of the specified properties name.
 * The properties name does not contain any special characters, except '-'
 * and '_'. The returned string mst be freed by the caller.
 *
 * @param[in] prop_name      the base property name
 *
 * @returns an allocated string
 */
static char *_get_system_specific_prop_name(const char *prop_name)
{
	struct utsname utsname;
	char *ret;
	int i;

	if (uname(&utsname)) {
		warnx("uname failed: %s", strerror(errno));
		return NULL;
	}

	for (i = 0; utsname.nodename[i] != '\0'; i++)
		if (!isalnum(utsname.nodename[i]))
			utsname.nodename[i] = '_';

	util_asprintf(&ret, "%s-%s", prop_name, utsname.nodename);
	return ret;
}

#define ADD_KMS_PROPS(props, num, pname, pvalue)			\
	do {								\
		util_assert((num) * sizeof(struct kms_property) <	\
			    sizeof(props), " Internal error: kss "	\
			    "property array is full");			\
		(props)[num].name = (pname);				\
		(props)[num].value = (pvalue);				\
		(num)++;						\
	} while (0)

/**
 * Requests the KMS plugin to generate  a key of the specified key type, size
 * and mode, and stores the secure key blob into the specified file.
 *
 * For an XTS-mode key, 2 keys are generated and those are cross linked using
 * its properties.
 *
 * The key ID(s) and label(s) of the generated keys (2 for XTS) are set into
 * the properties object.
 *
 * @param[in] kms_info        information of the currently bound plugin.
 * @param[in] name            the name of the key to generate
 * @param[in] key_type        the key type o the key to generate
 * @param[in] key_props       a properties object containing the key's initial
 *                            properties. On return additional properties are
 *                            added/set for the key ID(s) and label(s).
 * @param[in] xts             if true, an XTS key (i.e 2 keys) is generated
 * @param[in] keybits         the key bit size (e.g. 128, 196, 256, 0 to use the
 *                            plugin's default)
 * @param[in] filename        the file name to store the key in
 * @param[in] kms_options     an array of KMS options specified, or NULL if no
 *                            KMS options have been specified
 * @param[in] num_kms_options the number of options in above array
 * @param[in] verbose         if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error.
 * If the KMS plugin does not support the key type, then -ENOTSUP is returned
 */
int generate_kms_key(struct kms_info *kms_info, const char *name,
		     const char *key_type, struct properties *key_props,
		     bool xts, size_t keybits, const char *filename,
		     struct kms_option *kms_options, size_t num_kms_options,
		     bool verbose)
{
	char *cipher, *iv_mode, *description, *volumes, *vol_type, *sector_size;
	unsigned char key_blob[MAX_SECURE_KEY_SIZE * 2];
	char key1_label[KMS_KEY_LABEL_SIZE + 1] = { 0 };
	char key2_label[KMS_KEY_LABEL_SIZE + 1] = { 0 };
	char key1_id[KMS_KEY_ID_SIZE + 1] = { 0 };
	char key2_id[KMS_KEY_ID_SIZE + 1] = { 0 };
	struct kms_property kms_props[12];
	int xts_mode_prop = -1, rc = 0;
	size_t key_size, key_blob_size;
	enum kms_key_mode key_mode;
	size_t num_kms_props = 0;
	char *sys_volumes = NULL;

	util_assert(kms_info != NULL, "Internal error: kms_info is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");
	util_assert(key_type != NULL, "Internal error: key_type is NULL");
	util_assert(key_props != NULL, "Internal error: key_props is NULL");
	util_assert(filename != NULL, "Internal error: filename is NULL");

	if (kms_info->plugin_lib == NULL) {
		warnx("The repository is not bound to a KMS plugin");
		return -ENOENT;
	}

	if (kms_info->funcs->kms_generate_key == NULL ||
	    kms_info->funcs->kms_set_key_properties == NULL) {
		pr_verbose(verbose, "The KMS plugin does not support to "
			   "generate keys or set properties");
		return -ENOTSUP;
	}

	if (strcasecmp(key_type, KEY_TYPE_CCA_AESDATA) == 0)
		key_size = AESDATA_KEY_SIZE;
	else if (strcasecmp(key_type, KEY_TYPE_CCA_AESCIPHER) == 0)
		key_size = AESCIPHER_KEY_SIZE;
	else if (strcasecmp(key_type, KEY_TYPE_EP11_AES) == 0)
		key_size = EP11_KEY_SIZE;
	else
		return -ENOTSUP;

	memset(key_blob, 0, sizeof(key_blob));

	cipher = properties_get(key_props, PROP_NAME_CIPHER);
	iv_mode = properties_get(key_props, PROP_NAME_IV_MODE);
	description = properties_get(key_props, PROP_NAME_DESCRIPTION);
	volumes = properties_get(key_props, PROP_NAME_VOLUMES);
	vol_type = properties_get(key_props, PROP_NAME_VOLUME_TYPE);
	sector_size = properties_get(key_props, PROP_NAME_SECTOR_SIZE);

	ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_NAME, name);
	ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_CIPHER,
		      cipher != NULL ? cipher : "");
	ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_IV_MODE,
		      iv_mode != NULL ? iv_mode : "");
	ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_DESCRIPTION,
		      description != NULL ? description : "");
	ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_VOLUMES,
		      volumes != NULL ? volumes : "");
	sys_volumes = _get_system_specific_prop_name(KMS_KEY_PROP_VOLUMES);
	if (sys_volumes == NULL)
		return -ENOMEM;
	ADD_KMS_PROPS(kms_props, num_kms_props, sys_volumes,
		      volumes != NULL ? volumes : "");

	ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_VOLUME_TYPE,
		      vol_type != NULL ? vol_type : "");
	ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_SECTOR_SIZE,
		      sector_size != NULL ? sector_size : "");

	if (xts) {
		xts_mode_prop = num_kms_props;
		ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_XTS_KEY,
			      "XTS-KEY-1");
	}

	key_mode = xts ? KMS_KEY_MODE_XTS_1 : KMS_KEY_MODE_NON_XTS;

	key_blob_size = key_size;
	rc = kms_info->funcs->kms_generate_key(kms_info->handle, key_type,
					       keybits, key_mode,
					       kms_props, num_kms_props,
					       kms_options, num_kms_options,
					       key_blob, &key_blob_size,
					       key1_id, sizeof(key1_id),
					       key1_label, sizeof(key1_label));
	if (rc != 0) {
		pr_verbose(verbose, "KMS plugin failed to generate key #1: %s",
			   strerror(-rc));
		goto out;
	}

	pr_verbose(verbose, "Key1: ID: '%s' Label: '%s'", key1_id, key1_label);
	pr_verbose(verbose, "Keyblob #1: %lu bytes:'", key_blob_size);
	if (verbose)
		util_hexdump_grp(stderr, NULL, key_blob, 4, key_blob_size, 0);

	/* Save ID and label of 1st key */
	rc = properties_set(key_props, xts ? PROP_NAME_KMS_XTS_KEY1_ID :
			    PROP_NAME_KMS_KEY_ID, key1_id);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to set key id of key #1: %s",
			   strerror(-rc));
		goto out;
	}

	rc = properties_set(key_props, xts ? PROP_NAME_KMS_XTS_KEY1_LABEL :
			    PROP_NAME_KMS_KEY_LABEL, key1_label);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to set key label of key #1: %s",
			   strerror(-rc));
		goto out;
	}

	if (!xts)
		goto save_key;

	/* Generate 2nd key of the XTS key */
	kms_props[xts_mode_prop].value = "XTS-KEY-2";
	key_mode = KMS_KEY_MODE_XTS_2;

	/* Cross link key 1 with key 2 */
	ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_XTS_KEY1_ID,
		      key1_id);
	ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_XTS_KEY1_LABEL,
		      key1_label);

	key_blob_size = key_size;
	rc = kms_info->funcs->kms_generate_key(kms_info->handle, key_type,
					       keybits, key_mode,
					       kms_props, num_kms_props,
					       kms_options, num_kms_options,
					       &key_blob[key_size],
					       &key_blob_size,
					       key2_id, sizeof(key2_id),
					       key2_label, sizeof(key2_label));
	if (rc != 0) {
		pr_verbose(verbose, "KMS plugin failed to generate key #2: %s",
			   strerror(-rc));
		goto out;
	}

	pr_verbose(verbose, "Key2: ID: '%s' Label: '%s'", key1_id, key1_label);
	pr_verbose(verbose, "Keyblob #2: %lu bytes:'", key_blob_size);
	if (verbose)
		util_hexdump_grp(stderr, NULL, &key_blob[key_size], 4,
				 key_blob_size, 0);

	/* Save ID and label of 2nd key */
	rc = properties_set(key_props, PROP_NAME_KMS_XTS_KEY2_ID, key2_id);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to set key id of key #2: %s",
			   strerror(-rc));
		goto out;
	}

	rc = properties_set(key_props, PROP_NAME_KMS_XTS_KEY2_LABEL,
			    key2_label);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to set key label of key #2: %s",
			   strerror(-rc));
		goto out;
	}

	/* Cross link key 2 with key 1 */
	num_kms_props = 0;
	ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_XTS_KEY2_ID,
		      key2_id);
	ADD_KMS_PROPS(kms_props, num_kms_props, KMS_KEY_PROP_XTS_KEY2_LABEL,
		      key2_label);

	rc = kms_info->funcs->kms_set_key_properties(kms_info->handle, key1_id,
						     kms_props, num_kms_props);
	if (rc != 0) {
		pr_verbose(verbose, "KMS plugin failed to set properties of "
			   "key #1: %s", strerror(-rc));
		goto out;
	}

save_key:
	rc = write_secure_key(filename, key_blob, xts ? key_size * 2 : key_size,
			      verbose);
	if (rc != 0)
		goto out;

out:
	if (cipher != NULL)
		free(cipher);
	if (iv_mode != NULL)
		free(iv_mode);
	if (description != NULL)
		free(description);
	if (volumes != NULL)
		free(volumes);
	if (vol_type != NULL)
		free(vol_type);
	if (sector_size != NULL)
		free(sector_size);
	if (sys_volumes != NULL)
		free(sys_volumes);

	return rc;
}


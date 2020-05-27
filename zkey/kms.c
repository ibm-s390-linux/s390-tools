/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dlfcn.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_rec.h"
#include "lib/util_panic.h"

#include "kms.h"

#define ENVVAR_ZKEY_REPOSITORY		"ZKEY_REPOSITORY"
#define DEFAULT_KEYSTORE		"/etc/zkey/repository"

#define ENVVAR_ZKEY_KMS_PLUGINS		"ZKEY_KMS_PLUGINS"
#define DEFAULT_KMS_PLUGINS		"/etc/zkey/kms-plugins.conf"

#define KMS_CONFIG_FILE			"kms.conf"
#define KMS_CONFIG_PROP_KMS		"kms"
#define KMS_CONFIG_PROP_KMS_CONFIG	"config"
#define KMS_CONFIG_PROP_APQNS		"apqns"
#define KMS_CONFIG_LOCAL		"local"

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

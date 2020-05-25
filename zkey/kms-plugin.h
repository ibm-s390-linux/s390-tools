/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines the interface to a Key Management System (KMS)
 * Plugin.
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef KMS_PLUGIN_H
#define KMS_PLUGIN_H

#include <stddef.h>
#include <stdbool.h>

#include "lib/util_opt.h"

/**
 * Informs a KMS plugin that it is bound to a zkey repository.
 *
 * Note: This function is called before kms_initialize()!
 *
 * @param config_path       name of a directory where the KMS plugin can store
 *                          its configuration and other files it needs to store
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
int kms_bind(const char *config_path);

typedef void *kms_handle_t;

/**
 * Initializes a KMS plugin for usage by zkey. When a repository is bound to a
 * KMS plugin, zkey calls this function when opening the repository.
 *
 * @param config_path       name of a directory where the KMS plugin can store
 *                          its configuration and other files it needs to store
 * @param verbose           if true, the plugin should write verbose or debug
 *                          messages to stderr during further processing.
 *
 * @returns a KMS plugin handle, or NULL in case of an error.
 */
kms_handle_t kms_initialize(const char *config_path, bool verbose);

/**
 * Terminates the use of a KMS plugin. When a repository is bound to a KMS
 * plugin, zkey calls this function when closing the repository.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_terminate(const kms_handle_t handle);

/**
 * Returns a textual message about the last occurred error that occurred in the
 * last called KMS plugin function. If no error occurred (i.e. the last plugin
 * function returned rc = 0), then NULL is returned.
 * The returned string is static or contained within the handle. It is valid
 * only until the next KMS plugin function is called.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 *
 * @returns an error message of NULL
 */
const char *kms_get_last_error(const kms_handle_t handle);

/**
 * Returns true if the KMS plugin supports the specified key type.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_type          the zkey key type, euch as 'CCA-AESDATA',
 *                          'CCA-AESCIPHER', 'EP11-AES'.
 *
 * @returns true if the KMS plugin supports the key type, false otherwise.
 */
bool kms_supports_key_type(const kms_handle_t handle, const char *key_type);

/**
 * Displays information about the KMS Plugin and its current configuration on
 * stdout.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_display_info(const kms_handle_t handle);

#define KMS_COMMAND_CONFIGURE		"configure"
#define KMS_COMMAND_REENCIPHER		"reencipher"
#define KMS_COMMAND_GENERATE		"generate"
#define KMS_COMMAND_REMOVE		"remove"
#define KMS_COMMAND_LIST		"list"
#define KMS_COMMAND_LIST_IMPORT		"list-import"

/**
 * Returns a list of KMS specific command line options that zkey should accept
 * and pass to the appropriate KMS plugin function. The option list must be
 * terminated by an UTIL_OPT_END entry (see util_opt.h). The options returned
 * must not interfere with the already defined options of the zkey command.
 * Field 'command' of the returned options should either be NULL or specify
 * the command that it is for.
 *
 * If max_opts is not -1, then only up to max_opts options are allowed. If more
 * options are returned, only up to max_opts options are used by zkey.
 *
 * @param command           the command for which the KMS-specific options are
 *                          to be returned, see KMS_COMMAND_xxx defines
 * @param max_opts          maximum number of options allowed. If -1 then there
 *                          is no limit.
 *
 * @returns a list of options terminated by an UTIL_OPT_END entry, or NULL in
 * case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
const struct util_opt *kms_get_command_options(const char *command,
					       int max_opts);

struct kms_apqn {
	unsigned short card;
	unsigned short domain;
};

struct kms_option {
	int option;		/** option character as in struct option */
	const char *argument;   /** argument of the option (if any) */
};


/**
 * Configures (or re-configures) a KMS plugin. This function can be called
 * several times to configure a KMS plugin is several steps (if supported by the
 * KMS plugin). In case a configuration is not fully complete, this function
 * may return -EAGAIN to indicate that it has accepted the configuration so far,
 * but the configuration needs to be completed.
 *
 * No kms_login is performed before calling this function. If the KMS plugin
 * requires a login for the configuration, it must perform it itself within this
 * function.
 *
 * A KMS plugin must be associated with at least one APQN. Thus, in a multi-step
 * configuration, a list f APQNs must be specified at least once.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param apqns             a list of APQNs to associate with the KMS plugin, or
 *                          NULL if no APQNs are specified.
 * @param num_apqns         number of APQNs in above array. 0 if no APQNs are
 *                          specified.
 * @param options           a list of options as specified by the user. These
 *                          options are a subset of the possible options as
 *                          returned by kms_get_command_options() with command
 *                          KMS_COMMAND_CONFIGURE.
 * @param num_options       number of options in above array.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 * -EAGAIN to indicate that the specified configuration was accepted so far, but
 * the configuration is still incomplete, and needs to be completed.
 */
int kms_configure(const kms_handle_t handle,
		  const struct kms_apqn *apqns, size_t num_apqns,
		  const struct kms_option *options, size_t num_options);

/**
 * De-configures a KMS plugin. This is called by zkey when a repository is
 * unbound from a KMS plugin. It gives the KMS plugin the chance to gracefully
 * remove any files that the plugin has stored in its config directory. zkey
 * will unconditionally remove all left over files when this function returns.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_deconfigure(const kms_handle_t handle);

/**
 * Allows the KMS plugin to perform a login to the KMS (if required). This
 * function is called at least once before any key operation function, typically
 * shortly after opening the repository.
 * The KMS plugin may prompt the user (by reading from stdin) for its
 * credentials, if needed.
 *
 * It is suggested that a KMS plugin performs a login with the KMS once, and
 * stores a login token (or similar) in its config directory. The next time
 * the kms_login function is called, the login token can be reused (if still
 * valid). This avoids to prompt the user for every key operation.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_login(const kms_handle_t handle);

enum kms_reencipher_mode {
	KMS_REENC_MODE_AUTO = 0,
	KMS_REENC_MODE_IN_PLACE = 1,
	KMS_REENC_MODE_STAGED = 2,
	KMS_REENC_MODE_STAGED_COMPLETE = 3,
};

enum kms_reenc_mkreg {
	KMS_REENC_MKREG_AUTO = 0,
	KMS_REENC_MKREG_FROM_OLD = 1,
	KMS_REENC_MKREG_TO_NEW = 2,
	KMS_REENC_MKREG_FROM_OLD_TO_NEW = 3,
};

/**
 * Called when the master keys of an APQN associated with the KMS plugin has
 * been changed. The KMS plugin can then re-encipher all its secure keys (if
 * any) that it has stored in its config directory.
 *
 * Keys that have been generated by the KMS plugin and stored in the zkey
 * repository do not need to be re-enciphered by the KMS plugin. Those are
 * re-enciphered by zkey without the help of the KMS plugin.
 *
 * HSM have different master key registers. Typically a CURRENT and a NEW master
 * key register exists. The NEW register may be loaded with the new to be set
 * master key, and secure keys can be re-enciphered with it proactively.
 *
 * CCA also supports an OLD master key register, that contains the previously
 * used master key. You thus can re-encipher a secure key that is currently
 * enciphered with the master key from the OLD register with the master key
 * from the CURRENT register.
 *
 * HSMs may also support different master keys for different key types or
 * algorithms. It is up to the KMS plugin to know which master key registers
 * are used for its secure keys
 *
 * A staged re-encipherment is performed by re-enciphering a secure key with
 * the new HSM master key, without making it available for use in the first
 * stage. Only when the staged re-encipherment is completed, then the previously
 * re-enciphered secure key is make available for use and the old on is removed.
 *
 * An in-place re-encipherment replaces the secure key right away with its
 * re-enciphered version.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param mode              Re-encipherment mode
 * @param mkreg             Re-encipherment register selection
 * @param options           a list of options as specified by the user. These
 *                          options are a subset of the possible options as
 *                          returned by kms_get_command_options() with command
 *                          KMS_COMMAND_REENCIPHER.
 * @param num_options       number of options in above array.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_reenciper(const kms_handle_t handle,
		  enum kms_reencipher_mode mode, enum kms_reenc_mkreg mkreg,
		  const struct kms_option *options, size_t num_options);

struct kms_property {
	const char *name;
	const char *value;
};

#define KMS_KEY_ID_SIZE		256
#define KMS_KEY_LABEL_SIZE	256

enum kms_key_mode {
	KMS_KEY_MODE_NON_XTS = 0,
	KMS_KEY_MODE_XTS_1 = 1,
	KMS_KEY_MODE_XTS_2 = 2,
};

/**
 * Generates a key in or with the KMS and returns a secure key that is
 * enciphered under the current HSM master key.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_type          the zkey key type, euch as 'CCA-AESDATA',
 *                          'CCA-AESCIPHER', 'EP11-AES'.
 * @param key_bits          the key bit size (e.g. 256 for an AES 256 bit key).
 *                          0 to use the plugin's default key size.
 * @param key_mode          mode of the key, e.g. non-XTS key, or first/second
 *                          XTS key to be generated. A KMS plugin may need to
 *                          use different key templates for the different key
 *                          modes (i.e. key parts).
 * @param properties        a list of properties to associate the key with
 * @param num_properties    the number of properties in above array
 * @param options           a list of options as specified by the user. These
 *                          options are a subset of the possible options as
 *                          returned by kms_get_command_options() with command
 *                          KMS_COMMAND_GENERATE.
 * @param num_options       number of options in above array.
 * @param key_blob          a buffer to return the key blob. The size of the
 *                          buffer is specified in key_blob_length
 * @param key_blob_length   on entry: the size of the key_blob buffer.
 *                          on exit: the size of the key blob returned.
 * @param key_id            a buffer to return the key-ID of the generated key.
 *                          The key-id is a textual identifier uniquely
 *                          identifying a key in the KMS and the KMS plugin.
 *                          The returned key-id contains the terminating zero.
 * @paran key_id_size       size of the key_id buffer. It should be at least
 *                          KMS_KEY_ID_SIZE + 1 bytes large.
 * @param key_label         a buffer to return the key-label of the generated
 *                          key. The key-label is a textual identifier used to
 *                          identify a key in the user interface of the KMS.
 *                          A key label may be equal to the key-ID, or it may
 *                          different. The returned key-label contains the
 *                          terminating zero.
 * @paran key_label_size    size of the key_lanble buffer. It should be at least
 *                          KMS_KEY_LABEL_SIZE + 1 bytes large.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_generate_key(const kms_handle_t handle, const char *key_type,
		     size_t key_bits, enum kms_key_mode key_mode,
		     const struct kms_property *properties,
		     size_t num_properties, const struct kms_option *options,
		     size_t num_options, unsigned char *key_blob,
		     size_t *key_blob_length, char *key_id,
		     size_t key_id_size, char *key_label,
		     size_t key_label_size);

/**
 * Sets (adds/replaces/removes) properties of a key. Already existing properties
 * with the same property name are replaced, non-existing properties are added.
 * To remove a property, set the property value to NULL.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_id            the key-ID to set the properties for
 * @param properties        a list of properties to set
 * @param num_properties    the number of properties in above array
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_set_key_properties(const kms_handle_t handle, const char *key_id,
			   const struct kms_property *properties,
			   size_t num_properties);

/**
 * Gets properties of a key.
 *
 * The returned list of properties must be freed by the caller. Each property
 * name and value must be freed individually (using free()), as well as the
 * complete array.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_id            the key-ID to set the properties for
 * @param properties        On return: a list of properties
 * @param num_properties    On return: the number of properties in above array
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_get_key_properties(const kms_handle_t handle, const char *key_id,
			   struct kms_property **properties,
			   size_t *num_properties);

/**
 * Called when zkey removes a KMS-bound key from the zkey repository. The KMS
 * plugin can then set the state of the key in the KMS, or remove it also from
 * the KMS (this is usually not done).
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_id            the key-ID to set the properties for
 * @param options           a list of options as specified by the user. These
 *                          options are a subset of the possible options as
 *                          returned by kms_get_command_options() with command
 *                          KMS_COMMAND_REMOVE.
 * @param num_options       number of options in above array.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_remove_key(const kms_handle_t handle, const char *key_id,
		   const struct kms_option *options, size_t num_options);

/**
 * Callback used with the kms_list_keys() function. Called for each key.
 *
 * @param key_id            the key-ID of the key
 * @param label             the label of the key.
 * @param key_type          the type of the key (CCA-AESDATA, etc)
 * @param key_bits          the key size in bits
 * @param properties        a list of properties of the key
 * @param num_properties    the number of properties in above array
 * @param addl_info_argz    an argz string containing additional KMS plugin
 *                           specific infos to be displayed, or NULL if none.
 * @param addl_info_len     length of the argz string in addl_info_argz
 * @param private_data      the private data pointer
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
typedef int (*kms_list_callback)(const char *key_id, const char *label,
				 const char *key_type, size_t key_bits,
				 const struct kms_property *properties,
				 size_t num_properties,
				 const char *addl_info_argz,
				 size_t addl_info_len, void *private_data);

/**
 * List keys managed by the KMS. This list is independent of the zkey key
 * repository. It lists keys as known by the KMS.
 *
 * Note: The list function is used to display a list of keys managed by the KMS,
 * but also for producing a list of keys to import. Because the two use cases
 * might require different plugin specific options, kms_get_command_options()
 * allows two commands to get options for:
 * - KMS_COMMAND_LIST:        Options for displaying a list.
 * - KMS_COMMAND_LIST_IMPORT: Options for building a list to import keys.
 * Functionkms_list_keys() is called for both cases with the appropriate
 * options as returned by kms_get_command_options() for the case.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param label_pattern     a pattern of the label used to filter the keys, or
 *                          NULL if no label pattern is specified.
 * @param properties        a list of properties used to to filter the keys, or
 *                          NULL if no properties filter is specified.
 * @param num_properties    the number of properties in above array.
 * @param options           a list of options as specified by the user. These
 *                          options are a subset of the possible options as
 *                          returned by kms_get_command_options() with command
 *                          KMS_COMMAND_LIST or KMS_COMMAND_LIST_IMPORT.
 * @param num_options       number of options in above array.*
 * @param callback          a callback function that is called for each key that
 *                          matches the filter (if any).
 * @private_data            a private pointer passed as is to the callback
 *                          function. Can be used to pass user specific
 *                          information to the callback.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_list_keys(const kms_handle_t handle, const char *label_pattern,
		  const struct kms_property *properties, size_t num_properties,
		  const struct kms_option *options, size_t num_options,
		  kms_list_callback callback, void *private_data);

/**
 * Imports a key from the KMS and returns a secure key that is
 * enciphered under the current HSM master key.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_id            the key-ID of the key to import
 * @param key_blob          a buffer to return the key blob. The size of the
 *                          buffer is specified in key_blob_length
 * @param key_blob_length   on entry: the size of the key_blob buffer.
 *                          on exit: the size of the key blob returned.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_import_key(const kms_handle_t handle, const char *key_id,
		   unsigned char *key_blob, size_t *key_blob_length);

#define KMS_API_VERSION_1	1

struct kms_functions {
	unsigned int api_version;
	int (*kms_bind)(const char *config_path);
	kms_handle_t (*kms_initialize)(const char *config_path, bool verbose);
	int (*kms_terminate)(const kms_handle_t handle);
	const char *(*kms_get_last_error)(const kms_handle_t handle);
	bool (*kms_supports_key_type)(const kms_handle_t handle,
				      const char *key_type);
	int (*kms_display_info)(const kms_handle_t handle);
	const struct util_opt *(*kms_get_command_options)(
			const char *command, int max_opts);
	int (*kms_configure)(const kms_handle_t handle,
			     const struct kms_apqn *apqns, size_t num_apqns,
			     const struct kms_option *options,
			     size_t num_options);
	int (*kms_deconfigure)(const kms_handle_t handle);
	int (*kms_login)(const kms_handle_t handle);
	int (*kms_reenciper)(const kms_handle_t handle,
			     enum kms_reencipher_mode mode,
			     enum kms_reenc_mkreg mkreg,
			     const struct kms_option *options,
			     size_t num_options);
	int (*kms_generate_key)(const kms_handle_t handle,
				const char *key_type, size_t key_bits,
				enum kms_key_mode key_mode,
				const struct kms_property *properties,
				size_t num_properties,
				const struct kms_option *options,
				size_t num_options,
				unsigned char *key_blob,
				size_t *key_blob_length, char *key_id,
				size_t key_id_size, char *key_label,
				size_t key_label_size);
	int (*kms_set_key_properties)(const kms_handle_t handle,
				      const char *key_id,
				      const struct kms_property *properties,
				      size_t num_properties);
	int (*kms_get_key_properties)(const kms_handle_t handle,
				      const char *key_id,
				      struct kms_property **properties,
				      size_t *num_properties);
	int (*kms_remove_key)(const kms_handle_t handle, const char *key_id,
			      const struct kms_option *options,
			      size_t num_options);
	int (*kms_list_keys)(const kms_handle_t handle,
			     const char *label_pattern,
			     const struct kms_property *properties,
			     size_t num_properties,
			     const struct kms_option *options,
			     size_t num_options,
			     kms_list_callback callback, void *private_data);
	int (*kms_import_key)(const kms_handle_t handle, const char *key_id,
			      unsigned char *key_blob,
			      size_t *key_blob_length);
};

/**
 * Returns an address of a structure containing the KMS plugin functions.
 * This function is exported by the KMS plugin, and its address is obtain
 * via dlsym() after loading the plugin via dlopen().
 * *
 * @returns the address of a structure or NULL in case of an error.
 */
const struct kms_functions *kms_get_functions(void);

#endif

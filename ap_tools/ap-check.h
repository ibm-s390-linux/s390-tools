/*
 * ap-check - Validate vfio-ap mediated device configuration changes
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef AP_CHECK_H
#define AP_CHECK_H

#include <stdbool.h>

/*
 * List of all of the supported mdevctl actions
 */
enum mdevctl_action_id {
	MDEVCTL_ACTION_DEFINE = 0,
	MDEVCTL_ACTION_LIST,
	MDEVCTL_ACTION_MODIFY,
	MDEVCTL_ACTION_START,
	MDEVCTL_ACTION_STOP,
	MDEVCTL_ACTION_TYPES,
	MDEVCTL_ACTION_UNDEFINE,
	MDEVCTL_ACTION_ATTRIBUTES,
	/* UNKNOWN must always be the last in the list */
	MDEVCTL_ACTION_UNKNOWN,
};
#define NUM_MDEVCTL_ACTIONS MDEVCTL_ACTION_UNKNOWN

struct mdevctl_action {
	enum mdevctl_action_id id;
	const char action[32];
};

enum mdevctl_event_id {
	MDEVCTL_EVENT_PRE = 0,
	MDEVCTL_EVENT_POST,
	MDEVCTL_EVENT_GET,
	MDEVCTL_EVENT_LIVE,
	MDEVCTL_EVENT_UNKNOWN,
};
#define NUM_MDEVCTL_EVENTS MDEVCTL_EVENT_UNKNOWN

struct mdevctl_event {
	enum mdevctl_event_id id;
	const char event[32];
};

/* ap-check special exit codes */
#define APC_EXIT_UNKNOWN_TYPE 2

struct ap_check_anchor {
	enum mdevctl_event_id event;
	enum mdevctl_action_id action;
	char *uuid;
	char *parent;
	char *type;
	struct vfio_ap_device *dev;
	/* Active Masks */
	char apmask[80];
	char aqmask[80];
	/* Persistent Masks */
	char p_apmask[80];
	char p_aqmask[80];
	bool cleanup_lock;
};

struct other_mdev_cb_data {
	const char *uuid;
	struct vfio_ap_device *dev;
};

#endif /* AP_CHECK_H */

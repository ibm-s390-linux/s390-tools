/*
 * hyptop - Show hypervisor performance data on System z
 *
 * System data module: Provide backend independent database for system data
 *                     (e.g. for CPU and memory data)
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>
#include <time.h>

#include "helper.h"
#include "hyptop.h"
#include "opts.h"
#include "sd.h"

/*
 * Internal globals for system data
 */
static u32		l_cpu_type_selected_mask;
static int		l_cpu_type_cnt;
static int		l_sys_item_cnt;
static int		l_cpu_item_cnt;
static int		l_has_core_data;
static int		l_has_phys_data;
static struct sd_sys	*l_root_sys;

/*
 * External globals for system data
 */
struct sd_globals sd;

/*
 * Get root system
 */
struct sd_sys *sd_sys_root_get(void)
{
	return l_root_sys;
}

/*
 * Get CPU type by it's ID
 */
struct sd_cpu_type *sd_cpu_type_by_id(const char *id)
{
	struct sd_cpu_type *type;
	unsigned int i;

	sd_cpu_type_iterate(type, i) {
		if (strcasecmp(id, type->id) == 0)
			return type;
	}
	return NULL;
}

/*
 * Is CPU type selected?
 */
int sd_cpu_type_selected(struct sd_cpu_type *cpu_type)
{
	return l_cpu_type_selected_mask & cpu_type->idx;
}

/*
 * Toggle selection of CPU type
 */
void sd_cpu_type_select_toggle(struct sd_cpu_type *cpu_type)
{
	if (l_cpu_type_selected_mask & cpu_type->idx)
		l_cpu_type_selected_mask &= ~cpu_type->idx;
	else
		l_cpu_type_selected_mask |= cpu_type->idx;
}

/*
 * Select exactly specified CPU type
 */
void sd_cpu_type_select(struct sd_cpu_type *cpu_type)
{
	l_cpu_type_selected_mask = cpu_type->idx;
}

/*
 * Select all available CPU types
 */
void sd_cpu_type_select_all(void)
{
	l_cpu_type_selected_mask = (u32)-1;
}

/*
 * Deselect all CPU types
 */
void sd_cpu_type_select_none(void)
{
	l_cpu_type_selected_mask = 0;
}

/*
 * Setup CPU types specified on command line
 */
static void l_opts_cpu_types_init(void)
{
	struct sd_cpu_type *type;
	unsigned int i;

	if (!g.o.cpu_types.specified)
		return;

	sd_cpu_type_select_none();
	for (i = 0; i < g.o.cpu_types.cnt; i++) {
		type = sd_cpu_type_by_id(g.o.cpu_types.vec[i]);
		if (!type)
			ERR_EXIT("Invalid CPU type \"%s\"\n",
				 g.o.cpu_types.vec[i]);
		sd_cpu_type_select_toggle(type);
	}
}

/*
 * Init CPU count for all CPU types
 */
static void l_cpu_types_init(void)
{
	struct sd_sys *sys = sd_sys_root_get();
	struct sd_cpu_type *cpu_type;
	unsigned int i;

	sd_cpu_type_iterate(cpu_type, i) {
		sd_cpu_type_select(cpu_type);
		cpu_type->cpu_cnt = sd_sys_item_u64(sys, &sd_sys_item_cpu_cnt);
	}
	sd_cpu_type_select_all();
	l_opts_cpu_types_init();
}

/*
 * Update system data using the data gatherer
 */
void sd_update(void)
{
	sd.dg->update_sys();
}

/*
 * Register a data gatherer
 */
void sd_dg_register(struct sd_dg *dg, int has_core_data, int has_phys_data)
{
	struct timespec ts = {SD_DG_INIT_INTERVAL_SEC, 0};
	struct sd_sys_item *sys_item;
	struct sd_cpu_item *cpu_item;
	unsigned int i;

	l_has_core_data = has_core_data;
	l_has_phys_data = has_phys_data;
	sd.dg = dg;
	for (i = 0; dg->cpu_type_vec[i]; i++)
		dg->cpu_type_vec[i]->idx = (1UL << i);
	l_cpu_type_cnt = i;
	sd_sys_item_iterate(sys_item, i)
		l_sys_item_cnt++;
	sd_cpu_item_iterate(cpu_item, i)
		l_cpu_item_cnt++;

	sd_update();
	nanosleep(&ts, NULL);
	sd_update();

	l_cpu_types_init();
}

/*
 * Does backend has physical CPUs data?
 */
int sd_dg_has_phys_data(void)
{
	return l_has_phys_data;
}

/*
 * Does backend has core data?
 */
int sd_dg_has_core_data(void)
{
	return l_has_core_data;
}

/*
 * Get CPU from sys by ID
 */
struct sd_cpu *sd_cpu_get(struct sd_sys *sys, const char* id)
{
	struct sd_cpu *cpu;

	util_list_iterate(&sys->cpu_list, cpu) {
		if (strcmp(cpu->id, id) == 0)
			return cpu;
	}
	return NULL;
}

/*
 * Get CPU type by ID
 */
static struct sd_cpu_type *l_cpu_type_by_id(const char *id)
{
	struct sd_cpu_type **cpu_type_vec = sd.dg->cpu_type_vec;
	int i;

	for (i = 0; i < l_cpu_type_cnt; i++) {
		if (strcmp(cpu_type_vec[i]->id, id) == 0)
			return cpu_type_vec[i];
	}
	return NULL;
}

/*
 * Allocate and initialize new CPU
 */
struct sd_cpu *sd_cpu_new(struct sd_sys *parent, const char *id,
			  const char *type, int cnt)
{
	struct sd_cpu *cpu;

	cpu = ht_zalloc(sizeof(*cpu));
	cpu->i.parent = parent;
	util_strlcpy(cpu->id, id, sizeof(cpu->id));
	cpu->type = l_cpu_type_by_id(type);
	cpu->d_cur = &cpu->d1;
	cpu->cnt = cnt;

	util_list_add_tail(&parent->cpu_list, cpu);

	return cpu;
}

/*
 * Get system by ID
 */
struct sd_sys *sd_sys_get(struct sd_sys *parent, const char* id)
{
	struct sd_sys *sys;

	util_list_iterate(&parent->child_list, sys) {
		if (strcmp(sys->id, id) == 0)
			return sys;
	}
	return NULL;
}

/*
 * Allocate and initialize new system
 */
struct sd_sys *sd_sys_new(struct sd_sys *parent, const char *id)
{
	struct sd_sys *sys_new;

	sys_new = ht_zalloc(sizeof(*sys_new));
	util_strlcpy(sys_new->id, id, sizeof(sys_new->id));
	util_list_init(&sys_new->child_list, struct sd_sys, list);
	util_list_init(&sys_new->cpu_list, struct sd_cpu, list);

	if (parent) {
		sys_new->i.parent = parent;
		parent->child_cnt++;
		util_list_add_tail(&parent->child_list, sys_new);
	}
	sys_new->threads_per_core = 1;
	return sys_new;
}

/*
 * Free system
 */
static void sd_sys_free(struct sd_sys *sys)
{
	ht_free(sys);
}

/*
 * Free CPU
 */
static void sd_cpu_free(struct sd_cpu *cpu)
{
	ht_free(cpu);
}

/*
 * Start update cycle for CPU
 */
static void l_cpu_update_start(struct sd_cpu *cpu)
{
	struct sd_cpu_info *tmp;

	cpu->i.active = 0;
	if (!cpu->d_prev) {
		cpu->d_prev = &cpu->d1;
		cpu->d_cur = &cpu->d2;
	} else {
		tmp = cpu->d_prev;
		cpu->d_prev = cpu->d_cur;
		cpu->d_cur = tmp;
	}
}

/*
 * Start update cycle for system
 */
void sd_sys_update_start(struct sd_sys *sys)
{
	struct sd_sys *child;
	struct sd_cpu *cpu;

	sys->i.active = 0;
	sys->child_cnt_active = 0;
	sys->cpu_cnt_active = 0;

	util_list_iterate(&sys->cpu_list, cpu)
		l_cpu_update_start(cpu);
	util_list_iterate(&sys->child_list, child)
		sd_sys_update_start(child);
}

/*
 * End update cycle for CPUs of a system
 */
static void l_cpu_update_end(struct sd_sys *sys)
{
	struct sd_cpu *cpu, *tmp;

	/* Has system not lost any CPU? */
	if (sys->cpu_cnt_active == sys->cpu_cnt)
		return;
	util_list_iterate_safe(&sys->cpu_list, cpu, tmp) {
		if (!cpu->i.active) {
			/* CPU has not been updated, remove it */
			util_list_remove(&sys->cpu_list, cpu);
			sd_cpu_free(cpu);
			continue;
		}
	}
	sys->cpu_cnt = sys->cpu_cnt_active;
}

/*
 * End update cycle for system
 */
static void l_sys_update_end(struct sd_sys *sys)
{
	struct sd_sys *child, *tmp;

	l_cpu_update_end(sys);

	util_list_iterate_safe(&sys->child_list, child, tmp) {
		if (!child->i.active) {
			/* child has not been updated, remove it */
			util_list_remove(&sys->child_list, child);
			sd_sys_free(child);
			continue;
		}
		/* Recursively update child */
		l_sys_update_end(child);
	}
	sys->child_cnt = sys->child_cnt_active;
}

/*
 * End update cycle for system
 */
void sd_sys_update_end(struct sd_sys *sys, u64 update_time_us)
{
	sys->update_time_us = update_time_us;
	l_sys_update_end(sys);
}

/*
 * Is system item available?
 */
int sd_sys_item_available(struct sd_sys_item *item)
{
	struct sd_sys_item *ptr;
	unsigned int i;

	sd_sys_item_iterate(ptr, i) {
		if (item == ptr)
			return 1;
	}
	return 0;
}

/*
 * Number of system items
 */
int sd_sys_item_cnt(void)
{
	return l_sys_item_cnt;
}

/*
 * Is CPU item avaiable?
 */
int sd_cpu_item_available(struct sd_cpu_item *item)
{
	struct sd_cpu_item *ptr;
	unsigned int i;

	sd_cpu_item_iterate(ptr, i) {
		if (item == ptr)
			return 1;
	}
	return 0;
}

/*
 * Number of CPU items
 */
int sd_cpu_item_cnt(void)
{
	return l_cpu_item_cnt;
}

/*
 * Init system data module
 */
void sd_init(void)
{
	l_root_sys = sd_sys_new(NULL, SD_SYS_DEFAULT_ID);
}

/*
 * CPU Types
 */
struct sd_cpu_type sd_cpu_type_ifl = {
	.id	= SD_CPU_TYPE_STR_IFL,
	.desc	= "Integrated Facility for Linux",
	.hotkey	= 'i',
};

struct sd_cpu_type sd_cpu_type_cp = {
	.id	= SD_CPU_TYPE_STR_CP,
	.desc	= "Central processor",
	.hotkey	= 'p',
};

struct sd_cpu_type sd_cpu_type_un = {
	.id	= SD_CPU_TYPE_STR_UN,
	.desc	= "Unspecified processor type",
	.hotkey	= 'u',
};

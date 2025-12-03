/*
 * hyptop - Show hypervisor performance data on System z
 *
 * System data module: Provide database for system data (e.g. CPU and memory)
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef SD_H
#define SD_H

#include "lib/util_list.h"

#include "helper.h"
#include "table.h"

#define SD_DG_INIT_INTERVAL_SEC	1
#define SD_SYS_ID_SIZE		9
#define SD_SYS_DEFAULT_ID	"PHYSICAL"

/*
 * CPU info
 */
struct sd_cpu_info {
	u64	cpu_time_us;
	u64	thread_time_us;
	u64	mgm_time_us_set;
	u64	mgm_time_us;
	u64	wait_time_us;
	s64	steal_time_us;
	u64	online_time_us;
};

/*
 * Memory Info
 */
struct sd_mem {
	u64	min_kib;
	u64	max_kib;
	u64	use_kib;
};

/*
 * Weight
 */
struct sd_weight {
	u16	cur;
	u16	min;
	u16	max;
};

/*
 * System Name
 */
struct sd_sys_name {
	char	os[9];
};

struct sd_sys;

/*
 * SD info
 */
struct sd_info {
	u8		active;
	struct sd_sys	*parent;
};

struct sd_cpu;

/*
 * SD System (can be e.g. CEC, VM or guest/LPAR)
 */
struct sd_sys {
	struct util_list_node	list;
	struct sd_info		i;
	u64			update_time_us;
	u64			phys_delta_us;
	u32			child_cnt;
	u32			child_cnt_active;
	struct util_list	child_list;
	u32			cpu_cnt;
	u32			cpu_cnt_active;
	struct util_list	cpu_list;
	u32			threads_per_core;
	char			id[SD_SYS_ID_SIZE];
	struct sd_sys_name	name;
	struct sd_mem		mem;
	struct sd_weight	weight;
};

#define sd_sys_id(sys) ((sys)->id)
#define sd_sys_name_os(sys) ((sys)->name.os)

void sd_sys_update_start(struct sd_sys *sys);
void sd_sys_update_end(struct sd_sys *sys, u64 update_time_us);
struct sd_sys *sd_sys_root_get(void);
struct sd_sys *sd_sys_get(struct sd_sys *parent, const char *id);
struct sd_sys *sd_sys_new(struct sd_sys *parent, const char *id);

static inline void sd_sys_weight_cur_set(struct sd_sys *sys, u64 value)
{
	sys->weight.cur = value;
}

static inline void sd_sys_weight_min_set(struct sd_sys *sys, u64 value)
{
	sys->weight.min = value;
}

static inline void sd_sys_weight_max_set(struct sd_sys *sys, u64 value)
{
	sys->weight.max = value;
}

static inline void sd_sys_mem_use_kib_set(struct sd_sys *sys, u64 value)
{
	sys->mem.use_kib = value;
}

static inline void sd_sys_mem_min_kib_set(struct sd_sys *sys, u64 value)
{
	sys->mem.min_kib = value;
}

static inline void sd_sys_mem_max_kib_set(struct sd_sys *sys, u64 value)
{
	sys->mem.max_kib = value;
}

static inline void sd_sys_update_time_us_set(struct sd_sys *sys, u64 value)
{
	sys->update_time_us = value;
}

static inline void sd_phys_delta_time_us_set(struct sd_sys *sys, u64 value)
{
	sys->phys_delta_us = value;
}

/*
 * CPU type
 */
#define CPU_TYPE_ID_LEN		16
#define CPU_TYPE_DESC_LEN	64

#define SD_CPU_TYPE_STR_IFL	"IFL"
#define SD_CPU_TYPE_STR_CP	"CP"
#define SD_CPU_TYPE_STR_UN	"UN"

struct sd_cpu_type {
	char	id[CPU_TYPE_ID_LEN];
	char	desc[CPU_TYPE_DESC_LEN];
	u32	idx;
	int	cpu_cnt;
	char	hotkey;
};

#define sd_cpu_type_id(type) (type->id)
#define sd_cpu_type_desc(type) (type->desc)

int sd_cpu_type_selected(struct sd_cpu_type *cpu_type);
void sd_cpu_type_select_toggle(struct sd_cpu_type *cpu_type);
void sd_cpu_type_select(struct sd_cpu_type *cpu_type);
void sd_cpu_type_select_all(void);
void sd_cpu_type_select_none(void);
struct sd_cpu_type *sd_cpu_type_by_id(const char *id);

static inline int sd_cpu_type_cpu_cnt(struct sd_cpu_type *type)
{
	return type->cpu_cnt;
}

static inline void sd_sys_commit(struct sd_sys *sys)
{
	struct sd_sys *parent = sys->i.parent;

	sys->i.active = 1;
	if (parent)
		parent->child_cnt_active++;
}

extern struct sd_cpu_type sd_cpu_type_ifl;
extern struct sd_cpu_type sd_cpu_type_cp;
extern struct sd_cpu_type sd_cpu_type_un;

/*
 * SD CPU
 */
enum sd_cpu_state {
	SD_CPU_STATE_UNKNOWN	= 0,
	SD_CPU_STATE_OPERATING	= 1,
	SD_CPU_STATE_STOPPED	= 2,
	SD_CPU_STATE_DECONFIG	= 3,
};

struct sd_cpu {
	struct util_list_node	list;
	struct sd_info		i;
	char			id[9];
	struct sd_cpu_type	*type;
	struct sd_cpu_info	d1;
	struct sd_cpu_info	d2;
	struct sd_cpu_info	*d_cur;
	struct sd_cpu_info	*d_prev;
	u16			cnt;
	int			threads_per_core;
	enum sd_cpu_state	state;
};

static inline char *sd_cpu_state_str(enum sd_cpu_state state)
{
	static char *state_str[] = {"UK", "OP", "ST", "DC"};

	return state_str[(int) state];
}

#define sd_cpu_has_diff(cpu) (cpu->d_prev != NULL)
#define sd_cpu_diff(cpu, member) (cpu->d_cur->member - cpu->d_prev->member)

#define sd_cpu_id(cpu) (cpu->id)
#define sd_cpu_cnt(cpu) (cpu->cnt)
#define sd_cpu_type_str(cpu) (cpu->type->id)
#define sd_cpu_state(cpu) (cpu->state)

struct sd_cpu *sd_cpu_get(struct sd_sys *sys, const char *cpu_id);
struct sd_cpu *sd_cpu_new(struct sd_sys *parent, const char *id,
			  const char *type, int cnt);

static inline void sd_cpu_state_set(struct sd_cpu *cpu, enum sd_cpu_state state)
{
	cpu->state = state;
}

static inline void sd_cpu_cpu_time_us_set(struct sd_cpu *cpu, u64 value)
{
	cpu->d_cur->cpu_time_us = value;
}

static inline void sd_cpu_threads_per_core_set(struct sd_cpu *cpu, int value)
{
	cpu->threads_per_core = value;
}

static inline void sd_cpu_thread_time_us_set(struct sd_cpu *cpu, u64 value)
{
	cpu->d_cur->thread_time_us = value;
}

static inline void sd_cpu_mgm_time_us_set(struct sd_cpu *cpu, u64 value)
{
	cpu->d_cur->mgm_time_us_set = 1;
	cpu->d_cur->mgm_time_us = value;
}

static inline void sd_cpu_wait_time_us_set(struct sd_cpu *cpu, u64 value)
{
	cpu->d_cur->wait_time_us = value;
}

static inline void sd_cpu_steal_time_us_set(struct sd_cpu *cpu, s64 value)
{
	cpu->d_cur->steal_time_us = value;
}

static inline void sd_cpu_online_time_us_set(struct sd_cpu *cpu, u64 value)
{
	cpu->d_cur->online_time_us = value;
}

static inline void sd_cpu_commit(struct sd_cpu *cpu)
{
	struct sd_sys *parent = cpu->i.parent;

	cpu->i.active = 1;
	if (parent)
		parent->cpu_cnt_active++;
}

/*
 * Item types
 */
enum sd_item_type {
	SD_TYPE_U16,
	SD_TYPE_U32,
	SD_TYPE_U64,
	SD_TYPE_S64,
	SD_TYPE_STR,
};

/*
 * CPU item
 */
struct sd_cpu_item {
	struct table_col	table_col;
	enum sd_item_type	type;
	int			offset;
	char			*desc;
	int (*fn_set)(struct sd_cpu_item *, struct sd_cpu *);
	u64 (*fn_u64)(struct sd_cpu_item *, struct sd_cpu *);
	s64 (*fn_s64)(struct sd_cpu_item *, struct sd_cpu *);
	char *(*fn_str)(struct sd_cpu_item *, struct sd_cpu *);
};

#define sd_cpu_item_type(x) ((x)->type)
#define sd_cpu_item_table_col(item) (&(item)->table_col)

int sd_cpu_item_available(struct sd_cpu_item *item);
int sd_cpu_item_cnt(void);

/*
 * Item access functions
 */
static inline u64 sd_cpu_item_set(struct sd_cpu_item *item, struct sd_cpu *cpu)
{
	return (item->fn_set == NULL) ? 1 : item->fn_set(item, cpu);
}

static inline u64 sd_cpu_item_u64(struct sd_cpu_item *item,
				  struct sd_cpu *cpu)
{
	return item->fn_u64(item, cpu);
}

static inline u64 sd_cpu_item_s64(struct sd_cpu_item *item,
				  struct sd_cpu *cpu)
{
	return item->fn_s64(item, cpu);
}

static inline char *sd_cpu_item_str(struct sd_cpu_item *item,
				    struct sd_cpu *cpu)
{
	if (item->fn_str)
		return item->fn_str(item, cpu);
	else
		return ((char *) cpu) + item->offset;
}

/*
 * Predefined CPU items
 */
extern struct sd_cpu_item sd_cpu_item_type;
extern struct sd_cpu_item sd_cpu_item_state;
extern struct sd_cpu_item sd_cpu_item_cpu_diff;
extern struct sd_cpu_item sd_cpu_item_core_diff;
extern struct sd_cpu_item sd_cpu_item_thread_diff;
extern struct sd_cpu_item sd_cpu_item_smt_diff;
extern struct sd_cpu_item sd_cpu_item_mgm_diff;
extern struct sd_cpu_item sd_cpu_item_wait_diff;
extern struct sd_cpu_item sd_cpu_item_steal_diff;
extern struct sd_cpu_item sd_cpu_item_cpu;
extern struct sd_cpu_item sd_cpu_item_core;
extern struct sd_cpu_item sd_cpu_item_thread;
extern struct sd_cpu_item sd_cpu_item_mgm;
extern struct sd_cpu_item sd_cpu_item_wait;
extern struct sd_cpu_item sd_cpu_item_steal;
extern struct sd_cpu_item sd_cpu_item_online;

/*
 * System item
 */
struct sd_sys_item {
	struct table_col	table_col;
	enum sd_item_type	type;
	int			offset;
	char			*desc;
	int			info;
	int (*fn_set)(struct sd_sys_item *, struct sd_sys *);
	u64 (*fn_u64)(struct sd_sys_item *, struct sd_sys *);
	s64 (*fn_s64)(struct sd_sys_item *, struct sd_sys *);
};

#define sd_sys_item_table_col(item) (&item->table_col)
#define sd_sys_item_type(item) (item->type)

int sd_sys_item_available(struct sd_sys_item *item);
int sd_sys_item_cnt(void);

/*
 * Item access functions
 */
static inline int sd_sys_item_set(struct sd_sys *sys, struct sd_sys_item *item)
{
	return (item->fn_set == NULL) ? 1 : item->fn_set(item, sys);
}

static inline u64 sd_sys_item_u64(struct sd_sys *sys,
				  struct sd_sys_item *item)
{
	return item->fn_u64(item, sys);
}

static inline s64 sd_sys_item_s64(struct sd_sys *sys,
				  struct sd_sys_item *item)
{
	return item->fn_s64(item, sys);
}

static inline char *sd_sys_item_str(struct sd_sys *sys,
				    struct sd_sys_item *item)
{
	return ((char *) sys) + item->offset;
}

/*
 * Predefined System items
 */
extern struct sd_sys_item sd_sys_item_cpu_cnt;
extern struct sd_sys_item sd_sys_item_core_cnt;
extern struct sd_sys_item sd_sys_item_thread_cnt;
extern struct sd_sys_item sd_sys_item_smt_diff;
extern struct sd_sys_item sd_sys_item_cpu_oper_cnt;
extern struct sd_sys_item sd_sys_item_cpu_deconf_cnt;
extern struct sd_sys_item sd_sys_item_cpu_stop_cnt;
extern struct sd_sys_item sd_sys_item_cpu_diff;
extern struct sd_sys_item sd_sys_item_core_diff;
extern struct sd_sys_item sd_sys_item_thread_diff;
extern struct sd_sys_item sd_sys_item_mgm_diff;
extern struct sd_sys_item sd_sys_item_wait_diff;
extern struct sd_sys_item sd_sys_item_steal_diff;

extern struct sd_sys_item sd_sys_item_cpu;
extern struct sd_sys_item sd_sys_item_core;
extern struct sd_sys_item sd_sys_item_thread;
extern struct sd_sys_item sd_sys_item_mgm;
extern struct sd_sys_item sd_sys_item_wait;
extern struct sd_sys_item sd_sys_item_steal;
extern struct sd_sys_item sd_sys_item_online;

extern struct sd_sys_item sd_sys_item_mem_max;
extern struct sd_sys_item sd_sys_item_mem_min;
extern struct sd_sys_item sd_sys_item_mem_use;

extern struct sd_sys_item sd_sys_item_weight_cur;
extern struct sd_sys_item sd_sys_item_weight_min;
extern struct sd_sys_item sd_sys_item_weight_max;

extern struct sd_sys_item sd_sys_item_os_name;

extern struct sd_sys_item sd_sys_item_samples_total;
extern struct sd_sys_item sd_sys_item_samples_cpu_using;

extern struct sd_sys_item sd_sys_item_phys_mgm_diff;

/*
 * Data gatherer backend
 */
struct sd_dg {
	void 			(*update_sys)(void);
	struct sd_cpu_type 	**cpu_type_vec;
	struct sd_sys_item	**phys_item_vec;
	struct sd_sys_item	**sys_item_vec;
	struct sd_sys_item	**sys_item_enable_vec;
	struct sd_cpu_item	**cpu_item_vec;
	struct sd_cpu_item	**cpu_item_enable_vec;
};

void sd_dg_register(struct sd_dg *, int, int);
int sd_dg_has_phys_data(void);
int sd_dg_has_core_data(void);

/*
 * Iterators
 */
#define sd_sys_iterate(parent, sys) \
	util_list_iterate(&parent->child_list, sys)

#define sd_cpu_iterate(parent, cpu) \
	util_list_iterate(&parent->cpu_list, cpu)

#define sd_phys_item_iterate(ptr, i) \
	for (i = 0; (ptr = sd.dg->phys_item_vec[i]); i++)

#define sd_sys_item_iterate(ptr, i) \
	for (i = 0; (ptr = sd.dg->sys_item_vec[i]); i++)

#define sd_sys_item_enable_iterate(ptr, i) \
	for (i = 0; (ptr = sd.dg->sys_item_enable_vec[i]); i++)

#define sd_cpu_item_iterate(ptr, i) \
	for (i = 0; (ptr = sd.dg->cpu_item_vec[i]); i++)

#define sd_cpu_item_enable_iterate(ptr, i) \
	for (i = 0; (ptr = sd.dg->cpu_item_enable_vec[i]); i++)

#define sd_cpu_type_iterate(ptr, i) \
	for (i = 0; (ptr = sd.dg->cpu_type_vec[i]); i++)


/*
 * Offset macros
 */
#define SD_SYSTEM_OFFSET(x) \
	((unsigned long)(void *)&(((struct sd_sys *) NULL)->x))
#define SD_CPU_INFO_OFFSET(x) \
	((unsigned long)(void *)&(((struct sd_cpu_info *) NULL)->x))

static inline int l_cpu_info_set(struct sd_cpu_info *info, unsigned long offset)
{
	return (int)*(u64 *)(((char *) info) + offset - 8);
}

static inline u64 l_cpu_info_u64(struct sd_cpu_info *info,
				 unsigned long offset)
{
	return *(u64 *)(((char *) info) + offset);
}

static inline s64 l_cpu_info_s64(struct sd_cpu_info *info,
				 unsigned long offset)
{
	return *(s64 *)(((char *) info) + offset);
}

/*
 * Misc
 */
void sd_update(void);
void sd_init(void);

static inline u64 l_sub_64(u64 x, u64 y)
{
	return x < y ? 0 : x - y;
}

struct sd_globals {
	struct sd_dg	*dg;
};

extern struct sd_globals sd;

#endif /* SD_H */

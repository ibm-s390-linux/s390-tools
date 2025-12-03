/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Provide System Items
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "sd.h"

/*
 * Count CPUs of system according to active CPU types and requested CPU state
 */
static u64 l_sys_cpu_cnt_gen(struct sd_sys *sys, enum sd_cpu_state state,
			     int all)
{
	struct sd_cpu *cpu;
	u32 cnt = 0;

	sd_cpu_iterate(sys, cpu) {
		if (!sd_cpu_type_selected(cpu->type))
			continue;
		if (all || sd_cpu_state(cpu) == state)
			cnt += cpu->cnt;
	}
	return cnt;
}

/*
 * Count all CPUs of system
 */
static u64 l_sys_cpu_cnt(struct sd_sys_item *item, struct sd_sys *sys)
{
	(void) item;
	return l_sys_cpu_cnt_gen(sys, SD_CPU_STATE_UNKNOWN, 1);
}

/*
 * Count all threads of system
 */
static u64 l_sys_thread_cnt(struct sd_sys_item *item, struct sd_sys *sys)
{
	(void) item;
	return l_sys_cpu_cnt_gen(sys, SD_CPU_STATE_UNKNOWN, 1) *
			sys->threads_per_core;
}

/*
 * Count CPUs of system with state stopped
 */
static u64 l_sys_cpu_st_cnt(struct sd_sys_item *item, struct sd_sys *sys)
{
	(void) item;

	return l_sys_cpu_cnt_gen(sys, SD_CPU_STATE_STOPPED, 0);
}

/*
 * Count CPUs of system with state operating
 */
static u64 l_sys_cpu_op_cnt(struct sd_sys_item *item, struct sd_sys *sys)
{
	(void) item;

	return l_sys_cpu_cnt_gen(sys, SD_CPU_STATE_OPERATING, 0);
}

/*
 * Count CPUs of system with state deconfigured
 */
static u64 l_sys_cpu_dc_cnt(struct sd_sys_item *item,
				     struct sd_sys *sys)
{
	(void) item;

	return l_sys_cpu_cnt_gen(sys, SD_CPU_STATE_DECONFIG, 0);
}

/*
 * Check if CPU info is set
 */
static int l_sys_cpu_info_set(struct sd_sys_item *item, struct sd_sys *sys)
{
	struct sd_cpu *cpu;

	sd_cpu_iterate(sys, cpu) {
		if (!sd_cpu_type_selected(cpu->type))
			continue;
		if (!l_cpu_info_set(cpu->d_cur, item->offset))
			return 0;
	}
	return 1;
}

/*
 * Get u64 system item value from "sys"
 */
static u64 l_sys_item_u64(struct sd_sys_item *item, struct sd_sys *sys)
{
	switch (item->type) {
	case SD_TYPE_U16:
		return *(u16 *)(((char *) sys) + item->offset);
	case SD_TYPE_U32:
		return *(u32 *)(((char *) sys) + item->offset);
	case SD_TYPE_U64:
		return *(u64 *)(((char *) sys) + item->offset);
	case SD_TYPE_S64:
	case SD_TYPE_STR:
		break;
	}
	assert(0);
	return 0;
}

/*
 * Calculate system item out of sum of CPU info
 */
static u64 l_sys_cpu_info_sum_u64(struct sd_sys_item *item, struct sd_sys *sys)
{
	struct sd_cpu *cpu;
	u64 rc = 0;

	sd_cpu_iterate(sys, cpu) {
		if (!sd_cpu_type_selected(cpu->type))
			continue;
		rc += l_cpu_info_u64(cpu->d_cur, item->offset);
	}
	return rc;
}

/*
 * Calculate system item out of MAX of CPU info
 */
static u64 l_sys_cpu_info_max_u64(struct sd_sys_item *item, struct sd_sys *sys)
{
	struct sd_cpu *cpu;
	u64 rc = 0;

	sd_cpu_iterate(sys, cpu) {
		if (!sd_cpu_type_selected(cpu->type))
				continue;
		rc = MAX(rc, l_cpu_info_u64(cpu->d_cur, item->offset));
	}
	return rc;
}

/*
 * value = (value_current - value_prev) / online_time_diff
 */
static double l_cpu_info_diff_u64(struct sd_sys_item *item, struct sd_cpu *cpu,
				  int sign)
{
	u64 online_time_diff_us;
	double factor, diff_us;

	if (!sd_cpu_type_selected(cpu->type))
		return 0;
	if (sd_cpu_state(cpu) == SD_CPU_STATE_STOPPED)
		return 0;
	online_time_diff_us = l_sub_64(cpu->d_cur->online_time_us,
				       cpu->d_prev->online_time_us);
	if (online_time_diff_us == 0)
		return 0;
	if (sign) {
		diff_us = l_cpu_info_s64(cpu->d_cur, item->offset) -
			  l_cpu_info_s64(cpu->d_prev, item->offset);
	} else {
		diff_us = l_sub_64(l_cpu_info_u64(cpu->d_cur, item->offset),
				   l_cpu_info_u64(cpu->d_prev, item->offset));
	}
	factor = ((double) online_time_diff_us) / 1000000;
	diff_us /= factor;
	return diff_us;
}

/*
 * SUM over all CPUs: value = (value_current - value_prev) / online_time_diff
 */
static u64 l_sys_cpu_info_diff_u64(struct sd_sys_item *item, struct sd_sys *sys)
{
	struct sd_cpu *cpu;
	u64 rc = 0;

	sd_cpu_iterate(sys, cpu) {
		if (!cpu->d_prev || !cpu->d_cur)
			return 0;
		rc += l_cpu_info_diff_u64(item, cpu, 0);
	}
	return rc;
}

/*
 * SUM over all CPUs: value = (value_current - value_prev) / online_time_diff
 */
static s64 l_sys_cpu_info_diff_s64(struct sd_sys_item *item, struct sd_sys *sys)
{
	struct sd_cpu *cpu;
	s64 rc = 0;

	sd_cpu_iterate(sys, cpu) {
		if (!cpu->d_prev || !cpu->d_cur)
			return 0;
		rc += l_cpu_info_diff_u64(item, cpu, 1);
	}
	return rc;
}

static u64 l_sys_smt_util(struct sd_sys_item *item, struct sd_sys *sys)
{
	u64 core_us, thr_us, mgm_us;
	(void)item;

	core_us = sd_sys_item_u64(sys, &sd_sys_item_core_diff);
	thr_us = sd_sys_item_u64(sys, &sd_sys_item_thread_diff);
	mgm_us = sd_sys_item_u64(sys, &sd_sys_item_mgm_diff);

	return ht_calculate_smt_util(core_us, thr_us, mgm_us, sys->threads_per_core);
}

/*
 * value = (value_current - value_prev) / online_time_diff
 */
static double l_phys_cpu_info_diff_u64(struct sd_sys_item *item,
				       struct sd_cpu *cpu,
				       u64 time_diff_us)
{
	double factor, diff_us;

	if (!sd_cpu_type_selected(cpu->type))
		return 0;
	if (sd_cpu_state(cpu) == SD_CPU_STATE_STOPPED)
		return 0;
	if (time_diff_us == 0)
		return 0;
	diff_us = l_sub_64(l_cpu_info_u64(cpu->d_cur, item->offset),
			   l_cpu_info_u64(cpu->d_prev, item->offset));
	factor = ((double)time_diff_us) / 1000000;
	diff_us /= factor;
	return diff_us;
}

/*
 * SUM over all CPUs: value = (value_current - value_prev) / online_time_diff
 */
static u64 l_sys_phys_cpu_info_diff_u64(struct sd_sys_item *item, struct sd_sys *sys)
{
	struct sd_cpu *cpu;
	u64 rc = 0;

	sd_cpu_iterate(sys, cpu) {
		if (!cpu->d_prev || !cpu->d_cur)
			return 0;
		rc += l_phys_cpu_info_diff_u64(item, cpu, sys->phys_delta_us);
	}
	return rc;
}

/*
 * System item definitions
 */
struct sd_sys_item sd_sys_item_phys_mgm_diff = {
	.table_col = TABLE_COL_TIME_DIFF_SUM(table_col_unit_perc, 'm', "mgm"),
	.offset = SD_CPU_INFO_OFFSET(mgm_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Management time per second",
	.fn_set	= l_sys_cpu_info_set,
	.fn_u64	= l_sys_phys_cpu_info_diff_u64,
};

struct sd_sys_item sd_sys_item_core_cnt = {
	.table_col = TABLE_COL_CNT_SUM('#', "#core"),
	.type	= SD_TYPE_U32,
	.desc	= "Number of cores",
	.fn_u64	= l_sys_cpu_cnt,
};

struct sd_sys_item sd_sys_item_cpu_cnt = {
	.table_col = TABLE_COL_CNT_SUM('#', "#cpu"),
	.type	= SD_TYPE_U32,
	.desc	= "Number of CPUs",
	.fn_u64	= l_sys_cpu_cnt,
};

struct sd_sys_item sd_sys_item_thread_cnt = {
	.table_col = TABLE_COL_CNT_SUM('T', "#the"),
	.type	= SD_TYPE_U32,
	.desc	= "Number of threads",
	.fn_u64	= l_sys_thread_cnt,
};

struct sd_sys_item sd_sys_item_cpu_oper_cnt = {
	.table_col = TABLE_COL_CNT_SUM('O', "#cpuop"),
	.type	= SD_TYPE_U32,
	.desc	= "Number of operating CPUs",
	.fn_u64	= l_sys_cpu_op_cnt,
};

struct sd_sys_item sd_sys_item_cpu_stop_cnt = {
	.table_col = TABLE_COL_CNT_SUM('S', "#cpust"),
	.type	= SD_TYPE_U32,
	.desc	= "Number of stopped CPUs",
	.fn_u64	= l_sys_cpu_st_cnt,
};

struct sd_sys_item sd_sys_item_cpu_deconf_cnt = {
	.table_col = TABLE_COL_CNT_SUM('D', "#cpudc"),
	.type	= SD_TYPE_U32,
	.desc	= "Number of deconfigured CPUs",
	.fn_u64	= l_sys_cpu_dc_cnt,
};

struct sd_sys_item sd_sys_item_core_diff = {
	.table_col = TABLE_COL_TIME_DIFF_SUM(table_col_unit_perc, 'c', "core"),
	.offset = SD_CPU_INFO_OFFSET(cpu_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Core dispatch time per second",
	.fn_u64	= l_sys_cpu_info_diff_u64,
};

struct sd_sys_item sd_sys_item_cpu_diff = {
	.table_col = TABLE_COL_TIME_DIFF_SUM(table_col_unit_perc, 'c', "cpu"),
	.offset = SD_CPU_INFO_OFFSET(cpu_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "CPU time per second",
	.fn_u64	= l_sys_cpu_info_diff_u64,
};

struct sd_sys_item sd_sys_item_thread_diff = {
	.table_col = TABLE_COL_TIME_DIFF_SUM(table_col_unit_perc, 'e', "the"),
	.offset = SD_CPU_INFO_OFFSET(thread_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Thread time per second",
	.fn_u64	= l_sys_cpu_info_diff_u64,
};

struct sd_sys_item sd_sys_item_smt_diff = {
	.table_col = TABLE_COL_TIME_DIFF_SUM(table_col_unit_perc, 'S', "smt"),
	.type	= SD_TYPE_U64,
	.desc	= "Real CPU SMT utilization",
	.fn_u64	= l_sys_smt_util,
};

struct sd_sys_item sd_sys_item_mgm_diff = {
	.table_col = TABLE_COL_TIME_DIFF_SUM(table_col_unit_perc, 'm', "mgm"),
	.offset = SD_CPU_INFO_OFFSET(mgm_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Management time per second",
	.fn_set	= l_sys_cpu_info_set,
	.fn_u64	= l_sys_cpu_info_diff_u64,
};

struct sd_sys_item sd_sys_item_wait_diff = {
	.table_col = TABLE_COL_TIME_DIFF_SUM(table_col_unit_perc, 'w', "wait"),
	.offset = SD_CPU_INFO_OFFSET(wait_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Wait time per second",
	.fn_u64	= l_sys_cpu_info_diff_u64,
};

struct sd_sys_item sd_sys_item_steal_diff = {
	.table_col = TABLE_COL_STIME_DIFF_SUM(table_col_unit_perc, 's',
					      "steal"),
	.offset = SD_CPU_INFO_OFFSET(steal_time_us),
	.type	= SD_TYPE_S64,
	.desc	= "Steal time per second",
	.fn_s64	= l_sys_cpu_info_diff_s64,
};

struct sd_sys_item sd_sys_item_core = {
	.table_col = TABLE_COL_TIME_SUM(table_col_unit_hm, 'C', "core+"),
	.offset = SD_CPU_INFO_OFFSET(cpu_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Total core dispatch time",
	.fn_u64	= l_sys_cpu_info_sum_u64,
};

struct sd_sys_item sd_sys_item_cpu = {
	.table_col = TABLE_COL_TIME_SUM(table_col_unit_hm, 'C', "cpu+"),
	.offset = SD_CPU_INFO_OFFSET(cpu_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Total CPU time",
	.fn_u64	= l_sys_cpu_info_sum_u64,
};

struct sd_sys_item sd_sys_item_thread = {
	.table_col = TABLE_COL_TIME_SUM(table_col_unit_hm, 'E', "the+"),
	.offset = SD_CPU_INFO_OFFSET(thread_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Total thread time",
	.fn_u64	= l_sys_cpu_info_sum_u64,
};

struct sd_sys_item sd_sys_item_wait = {
	.table_col = TABLE_COL_TIME_SUM(table_col_unit_hm, 'W', "wait+"),
	.offset = SD_CPU_INFO_OFFSET(wait_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Total wait time",
	.fn_u64	= l_sys_cpu_info_sum_u64,
};

struct sd_sys_item sd_sys_item_mgm = {
	.table_col = TABLE_COL_TIME_SUM(table_col_unit_hm, 'M', "mgm+"),
	.offset = SD_CPU_INFO_OFFSET(mgm_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Total management time",
	.fn_set	= l_sys_cpu_info_set,
	.fn_u64	= l_sys_cpu_info_sum_u64,
};

struct sd_sys_item sd_sys_item_steal = {
	.table_col = TABLE_COL_STIME_SUM(table_col_unit_hm, 'T', "steal+"),
	.offset = SD_CPU_INFO_OFFSET(steal_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Total steal time",
	.fn_u64	= l_sys_cpu_info_sum_u64,
};

struct sd_sys_item sd_sys_item_online = {
	.table_col = TABLE_COL_TIME_MAX(table_col_unit_dhm, 'o', "online"),
	.offset = SD_CPU_INFO_OFFSET(online_time_us),
	.type	= SD_TYPE_U64,
	.desc	= "Online time",
	.fn_u64	= l_sys_cpu_info_max_u64,
};

struct sd_sys_item sd_sys_item_mem_max = {
	.table_col = TABLE_COL_MEM_SUM(table_col_unit_gib, 'a', "memmax"),
	.offset = SD_SYSTEM_OFFSET(mem.max_kib),
	.type	= SD_TYPE_U64,
	.desc	= "Maximum memory",
	.fn_u64	= l_sys_item_u64,
};

struct sd_sys_item sd_sys_item_mem_use = {
	.table_col = TABLE_COL_MEM_SUM(table_col_unit_gib, 'u', "memuse"),
	.offset = SD_SYSTEM_OFFSET(mem.use_kib),
	.type	= SD_TYPE_U64,
	.desc	= "Used memory",
	.fn_u64	= l_sys_item_u64,
};

struct sd_sys_item sd_sys_item_weight_cur = {
	.table_col = TABLE_COL_CNT_MAX('r', "wcur"),
	.offset = SD_SYSTEM_OFFSET(weight.cur),
	.type	= SD_TYPE_U16,
	.desc	= "Current weight",
	.fn_u64	= l_sys_item_u64,
};

struct sd_sys_item sd_sys_item_weight_min = {
	.table_col = TABLE_COL_CNT_MAX('n', "wmin"),
	.offset = SD_SYSTEM_OFFSET(weight.min),
	.type	= SD_TYPE_U16,
	.desc	= "Minimum weight",
	.fn_u64	= l_sys_item_u64,
};

struct sd_sys_item sd_sys_item_weight_max = {
	.table_col = TABLE_COL_CNT_MAX('x', "wmax"),
	.offset = SD_SYSTEM_OFFSET(weight.max),
	.type	= SD_TYPE_U16,
	.desc	= "Maximum weight",
	.fn_u64	= l_sys_item_u64,
};

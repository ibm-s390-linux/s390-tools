/*
 * zmemtopo - Show CEC memory topology data on System z
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <iconv.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "lib/util_libc.h"
#include "lib/util_list.h"
#include "lib/util_opt.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"

#include "zmemtopo.h"

static const struct util_prg prg = {
	.desc = "Display CEC memory topology of allocated memory increments.",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2025,
			.pub_last = 2025,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OUTPUT FORMAT OPTIONS"),
	{
		.option = { "level", required_argument, NULL, 'l' },
		.argument = "NESTING_LEVEL",
		.desc = "Set the topology display depth to NESTING_LEVEL"
	}, {
		.option = { "full", no_argument, NULL, 'f' },
		.desc = "Display tree view with padded elements"
	}, {
		.option = { "reverse", no_argument, NULL, 'r' },
		.desc = "Reverse tree view hierarchy direction"
	}, {
		.option = { "table", no_argument, NULL, 't' },
		.desc = "Use table view to display topology"
	}, {
		.option = { "sort", required_argument, NULL, 's' },
		.argument = "FIELD",
		.desc = "Sort view by FIELD (nr, lpar, size)"
	}, {
		.option = { "ascii", no_argument, NULL, 'i' },
		.desc = "Use only ASCII characters",
	},
	UTIL_OPT_SECTION("GENERAL OPTIONS"),
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

static struct zmemtopo_globals {
	unsigned int nesting_level;
	unsigned int max_level;
	unsigned int tree_full;
	unsigned int tree_reverse;
	unsigned int table_view;
	unsigned int sort_field;
	unsigned int ascii;
} g;

static void parse_nesting_level(char *arg)
{
	unsigned long level;

	level = strtoul(arg, NULL, 10);
	if (level < NESTING_LVL_MIN || level > NESTING_LVL_MAX)
		errx(EXIT_FAILURE, "The nesting level given is not valid");
	g.nesting_level = (unsigned int)level;
}

static void parse_sort_field(char *arg)
{
	char *s;

	s = util_strdup(arg);
	util_strstrip(s);
	if (strcasecmp(s, "nr") == 0)
		g.sort_field = SORT_NR;
	else if (strcasecmp(s, "lpar") == 0)
		g.sort_field = SORT_NAME;
	else if (strcasecmp(s, "size") == 0)
		g.sort_field = SORT_SIZE;
	else
		errx(EXIT_FAILURE, "%s is not a valid sort field option", arg);
}

static void parse_args(int argc, char *argv[])
{
	int opt;

	do {
		opt = util_opt_getopt_long(argc, argv);
		switch (opt) {
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'l':
			parse_nesting_level(optarg);
			break;
		case 't':
			g.table_view = 1;
			break;
		case 'f':
			g.tree_full = 1;
			break;
		case 'r':
			g.tree_reverse = 1;
			break;
		case 's':
			parse_sort_field(optarg);
			break;
		case 'i':
			g.ascii = 1;
			break;
		case -1:
			break;
		default:
			util_opt_print_parse_error(opt, argv);
			exit(EXIT_FAILURE);
		}
	} while (opt != -1);
	if (optind != argc) {
		errx(EXIT_FAILURE, "An invalid parameter %s was entered",
		     argv[optind]);
	}
	if (g.table_view && (g.tree_full || g.tree_reverse)) {
		errx(EXIT_FAILURE,
		     "The --full and --reverse options cannot be used with the table view");
	}
}

static void diag310_handle_error(int err)
{
	switch (err) {
	case EACCES:
		errx(EXIT_FAILURE,
		     "Check your permissions. You must have access to query memory topology");
	case ENODATA:
		errx(EXIT_FAILURE, "Nesting level %u is not supported",
		     g.nesting_level);
	case EINVAL:
		errx(EXIT_FAILURE,
		     "Check the zmemtopo arguments, the parameters received are not valid");
	case EOPNOTSUPP:
		errx(EXIT_FAILURE, "Memory topology querying is not supported");
	case EBUSY:
		errx(EXIT_FAILURE, "Memory topology querying is busy");
	default:
		warnx("An unknown error occurred");
	}
}

static void diag310_check_support(void)
{
	if (util_path_exists(DIAG_PATH))
		return;
	errx(EXIT_FAILURE, "Memory topology querying is not supported");
}

static int diag310_open_device(int flags)
{
	int fd;

	fd = open(DIAG_PATH, flags);
	if (fd <  0) {
		diag310_handle_error(errno);
		errx(EXIT_FAILURE, "Could not open %s", DIAG_PATH);
	}
	return fd;
}

static unsigned long diag310_get_stride(void)
{
	size_t stride;
	int fd;

	fd = diag310_open_device(O_RDONLY);
	if (ioctl(fd, DIAG310_GET_STRIDE, &stride)) {
		diag310_handle_error(errno);
		errx(EXIT_FAILURE,
		     "An error occurred while reading stride from %s",
		     DIAG_PATH);
	}
	close(fd);
	return stride;
}

static unsigned long diag310_get_memtop_length(void)
{
	size_t data_len;
	int fd;

	fd = diag310_open_device(O_RDONLY);
	data_len = g.nesting_level;
	if (ioctl(fd, DIAG310_GET_MEMTOPLEN, &data_len)) {
		diag310_handle_error(errno);
		errx(EXIT_FAILURE,
		     "An error occurred while reading buffer length from %s",
		     DIAG_PATH);
	}
	close(fd);
	return data_len;
}

static void *diag310_get_memtop_data(void)
{
	struct diag310_memtop data;
	unsigned long buffer_size;
	char *buf;
	int fd;

	buffer_size = diag310_get_memtop_length();
	buf = util_zalloc(buffer_size * sizeof(*buf));
	fd = diag310_open_device(O_RDONLY);
	data.nesting_lvl = g.nesting_level;
	data.address = (uint64_t)buf;
	if (ioctl(fd, DIAG310_GET_MEMTOPBUF, data)) {
		diag310_handle_error(errno);
		errx(EXIT_FAILURE,
		     "An error occurred while reading topology data from %s",
		     DIAG_PATH);
	}
	close(fd);
	return buf;
}

static struct stride_unit determine_stride_unit(void)
{
	static const char * const suffix[] = {"b", "K", "M", "G", "T"};
	unsigned long scale[] = {1, SCALE_KB, SCALE_MB, SCALE_GB, SCALE_TB};
	struct stride_unit unit;
	unsigned long stride;
	unsigned int i;

	stride = diag310_get_stride();
	stride *= SCALE_MB;
	unit.size = stride;
	for (i = 0; stride >= SCALE_KB; i++)
		stride /= SCALE_KB;
	snprintf(unit.suffix, UNIT_LEN, "%s", suffix[i]);
	unit.scale = scale[i];
	return unit;
}

static iconv_t iconv_ebcdic_ascii;

static void ebcdic_iconv_deinit(void)
{
	if (iconv_close(iconv_ebcdic_ascii)) {
		errx(EXIT_FAILURE,
		     "The zmemtopo command could not deinitialize iconv");
	}
}

static void ebcdic_iconv_init(void)
{
	iconv_ebcdic_ascii = iconv_open("ISO-8859-1", "EBCDIC-US");
	if (iconv_ebcdic_ascii == (iconv_t)-1) {
		errx(EXIT_FAILURE,
		     "The zmemtopo command could not initialize iconv");
	}
}

static void ebcdic_to_ascii(char *in, char *out, size_t size)
{
	size_t size_out, size_in, rc;

	size_out = size;
	size_in = size;
	rc = iconv(iconv_ebcdic_ascii, &in, &size_in, &out, &size_out);
	if (rc == (size_t)-1)
		errx(EXIT_FAILURE, "Code page translation EBCDIC-ASCII failed");
}

static void topology_entries_add_entry(struct topology_entry *entry,
				       unsigned short *ices,
				       unsigned int len)
{
	unsigned short *increments;
	unsigned int index, new_count;

	index = entry->count;
	new_count = index + len;
	increments = util_realloc(entry->increments,
				  new_count * sizeof(*increments));
	if (!ices)
		memset(increments + index, 0, len * sizeof(*increments));
	else
		memcpy(increments + index, ices, len * sizeof(*ices));
	entry->increments = increments;
	entry->count = new_count;
}

static void partition_set_name(struct partition *part, char *pname)
{
	ebcdic_to_ascii(pname, part->part_name, LPAR_NAME_LEN);
	util_strstrip(part->part_name);
}

static void partition_add_entry(struct partition *part,
				unsigned int *max_entry_nr,
				struct diag310_tle *tle)
{
	unsigned int i;

	topology_entries_add_entry(&part->entries[tle->cl - 1],
				   tle->ices, tle->ice_nr);
	if (tle->cl == g.nesting_level) {
		for (i = 0; i < tle->ice_nr; i++)
			part->increment_total += tle->ices[i];
	}
	/* Fill missing entries with padding to correctly represent topology */
	if (tle->ice_nr > 1 || tle->ices[0])
		return;
	for (i = tle->cl - 1; i >= g.nesting_level; i--) {
		topology_entries_add_entry(&part->entries[i - 1], NULL,
					   max_entry_nr[i - 1]);
	}
}

static struct partition *partition_create(struct diag310_p_hdr *p_hdr)
{
	struct partition *part;

	part = util_zalloc(sizeof(*part));
	partition_set_name(part, p_hdr->pname);
	part->increment_total = 0;
	part->part_nr = p_hdr->pn;
	return part;
}

static void partition_list_free(struct partitions *parts)
{
	struct partition *cur, *next;
	unsigned int level;

	util_list_iterate_safe(parts->list, cur, next) {
		util_list_remove(parts->list, cur);
		for (level = g.nesting_level; level <= g.max_level; level++)
			free(cur->entries[level - 1].increments);
		free(cur);
	}
	util_list_free(parts->list);
	free(parts);
}

static struct partitions *partition_list_create(void)
{
	struct partitions *ptr;

	ptr = util_zalloc(sizeof(*ptr));
	ptr->list = util_list_new(struct partition, node);
	return ptr;
}

static void partition_list_calculate_level_lengths(struct partitions *parts,
						   struct view_data *vdata)
{
	struct partition *cur;
	unsigned int level;

	cur = util_list_start(parts->list);
	for (level = g.max_level; level >= g.nesting_level; level--) {
		vdata->level_len[level - 1] = cur->entries[level - 1].count;
		if (level < g.max_level)
			vdata->level_len[level - 1] /= vdata->level_len[level];
	}
}

static uint64_t jump_over_padding(uint64_t addr)
{
	size_t offset;

	offset = sizeof(uint64_t) * 2;
	if (addr % offset)
		addr = (addr / offset + 1) * offset;
	return addr;
}

static void partition_list_populate(void *data, struct partitions *parts)
{
	unsigned int max_entry_nr[NESTING_LVL_MAX];
	unsigned int entry, lpar_idx;
	struct diag310_p_hdr *p_hdr;
	struct diag310_t_hdr *t_hdr;
	struct diag310_tle *tle;
	unsigned long tle_bytes;
	struct partition *part;

	memset(max_entry_nr, 0, sizeof(max_entry_nr));
	t_hdr = (struct diag310_t_hdr *)data;
	p_hdr = (void *)t_hdr + sizeof(*t_hdr);
	tle = (void *)p_hdr + sizeof(*p_hdr);
	/* Traverse over the data first to explore dimentions */
	for (lpar_idx = 0; lpar_idx < t_hdr->lpar_cnt; lpar_idx++) {
		for (entry = 0; entry < p_hdr->tie; entry++) {
			if (g.max_level < tle->cl)
				g.max_level = tle->cl;
			if (max_entry_nr[tle->cl - 1] < tle->ice_nr)
				max_entry_nr[tle->cl - 1] = tle->ice_nr;
			tle_bytes = sizeof(*tle->ices) * (tle->ice_nr + 1);
			tle = (void *)tle + tle_bytes;
		}
		p_hdr = (void *)jump_over_padding((uint64_t)(void *)tle);
		tle = (void *)p_hdr + sizeof(*p_hdr);
	}
	t_hdr = (struct diag310_t_hdr *)data;
	p_hdr = (void *)t_hdr + sizeof(*t_hdr);
	tle = (void *)p_hdr + sizeof(*p_hdr);
	for (lpar_idx = 0; lpar_idx < t_hdr->lpar_cnt; lpar_idx++) {
		if (!p_hdr->tie) {
			p_hdr = (void *)jump_over_padding((uint64_t)(void *)tle);
			tle = (void *)p_hdr + sizeof(*p_hdr);
			continue;
		}
		part = partition_create(p_hdr);
		for (entry = 0; entry < p_hdr->tie; entry++) {
			partition_add_entry(part, max_entry_nr, tle);
			tle_bytes = sizeof(*tle->ices) * (tle->ice_nr + 1);
			tle = (void *)tle + tle_bytes;
		}
		p_hdr = (void *)jump_over_padding((uint64_t)(void *)tle);
		tle = (void *)p_hdr + sizeof(*p_hdr);
		util_list_add_tail(parts->list, part);
	}
}

static int part_cmp_sum(void *a, void *b, void *UNUSED(data))
{
	struct partition *pa = a, *pb = b;

	if (pa->increment_total == pb->increment_total)
		return 0;
	return pa->increment_total > pb->increment_total ? 1 : -1;
}

static int part_cmp_lpar(void *a, void *b, void *UNUSED(data))
{
	struct partition *pa = a, *pb = b;

	return strcmp(pa->part_name, pb->part_name);
}

static int part_cmp_nr(void *a, void *b, void *UNUSED(data))
{
	struct partition *pa = a, *pb = b;

	if (pa->part_nr == pb->part_nr)
		return 0;
	return pa->part_nr > pb->part_nr ? 1 : -1;
}

static void partition_list_sort(struct partitions *parts)
{
	switch (g.sort_field) {
	case SORT_NAME:
		util_list_sort(parts->list, part_cmp_lpar, NULL);
		break;
	case SORT_SIZE:
		util_list_sort(parts->list, part_cmp_sum, NULL);
		break;
	case SORT_NR:
	default:
		util_list_sort(parts->list, part_cmp_nr, NULL);
		break;
	}
}

static unsigned int find_entry_cell_size(struct partitions *parts)
{
	unsigned int max_digit, max_increment;
	struct partition *cur;

	max_increment = 0;
	max_digit = 1;
	util_list_iterate(parts->list, cur) {
		if (cur->increment_total > max_increment)
			max_increment = cur->increment_total;
	}
	while (max_increment) {
		max_increment /= 10;
		max_digit++;
	}
	return max_digit > ENTRY_DIGIT ? max_digit : ENTRY_DIGIT;
}

static void concat_w_padding(char **buf, unsigned int padding,
			     unsigned int direction, const char *fmt, ...)
{
	va_list args;
	char *cell;

	va_start(args, fmt);
	util_vasprintf(&cell, fmt, args);
	va_end(args);
	if (direction)
		util_concatf(buf, "%-*s", padding, cell);
	else
		util_concatf(buf, "%*s", padding, cell);
	free(cell);
}

static void table_print_level_separator(char **buf, unsigned int col,
					unsigned int *level_length)
{
	unsigned int level, col_max;

	col_max = 1;
	for (level = g.max_level; level >= g.nesting_level; level--)
		col_max *= level_length[level - 1];
	if (col == col_max)
		return;
	for (level = g.max_level; level > g.nesting_level; level--) {
		if (col % (col_max / level_length[level - 1]) == 0)
			util_concatf(buf, " ");
	}
}

static void table_print_row(char **buf, struct partition *cur,
			    struct view_data *vdata)
{
	struct topology_entry *entries;
	unsigned int i, s_padding;

	s_padding = vdata->entry_len >= SUM_PAD ? vdata->entry_len : SUM_PAD;
	concat_w_padding(buf, LPAR_NO_LEN, 0, "%2d", cur->part_nr);
	concat_w_padding(buf, LPAR_NAME_LEN, 0, "%s", cur->part_name);
	concat_w_padding(buf, s_padding, 0, "%lu", cur->increment_total);
	entries = &cur->entries[g.nesting_level - 1];
	for (i = 0; i < entries->count; i++) {
		if (entries->increments[i]) {
			concat_w_padding(buf, vdata->entry_len, 0, "%lu",
					 entries->increments[i]);
		} else {
			concat_w_padding(buf, vdata->entry_len, 0, "-");
		}
		table_print_level_separator(buf, i + 1, vdata->level_len);
	}
	util_concatf(buf, "\n");
}

static void table_print_header(char **buf, struct view_data *vdata)
{
	unsigned int level, l_padding, s_padding, col_max, i, idx;
	unsigned int *level_len;

	col_max = 1;
	level_len = vdata->level_len;
	for (level = g.max_level; level >= g.nesting_level; level--)
		col_max *= level_len[level - 1];
	s_padding = vdata->entry_len >= SUM_PAD ? vdata->entry_len : SUM_PAD;
	l_padding = s_padding + LPAR_NO_LEN + LPAR_NAME_LEN;
	for (level = g.max_level; level >= g.nesting_level; level--) {
		concat_w_padding(buf, l_padding, 0, "LEVEL %u", level);
		for (i = 0; i < col_max; i++) {
			if (level == g.max_level)
				idx = i / (col_max / level_len[level - 1]);
			else
				idx = i % (col_max / level_len[level]);
			concat_w_padding(buf, vdata->entry_len, 0, "%u", idx);
			table_print_level_separator(buf, i + 1, level_len);
		}
		util_concatf(buf, "\n");
	}
	util_concatf(buf, "%*s", LPAR_NO_LEN, "NR");
	util_concatf(buf, "%*s", LPAR_NAME_LEN, "LPAR");
	util_concatf(buf, "%*s\n", s_padding, "SUM");
}

static void table_print(struct partitions *parts)
{
	struct stride_unit unit;
	struct view_data *vdata;
	struct partition *cur;
	char **table;

	unit = determine_stride_unit();
	vdata = util_zalloc(sizeof(*vdata));
	table = util_zalloc(sizeof(*table));
	vdata->entry_len = find_entry_cell_size(parts);
	partition_list_calculate_level_lengths(parts, vdata);
	table_print_header(table, vdata);
	util_list_iterate(parts->list, cur)
		table_print_row(table, cur, vdata);
	printf("%s\n", *table);
	printf("Increment size: %lu%s\n", unit.size / unit.scale, unit.suffix);
	free(vdata);
	free(*table);
	free(table);
}

static unsigned int tree_find_cell_len(void)
{
	unsigned int indent;

	indent = g.max_level - g.nesting_level;
	if (g.tree_reverse)
		indent++;
	return indent + LEVEL_LEN;
}

static void tree_create_header(char **buf, struct view_data *vdata)
{
	if (g.tree_reverse)
		util_concatf(buf, "%-*s", vdata->cell_len, "LEVEL/LPAR");
	else
		util_concatf(buf, "%-*s", vdata->cell_len, "LPAR/LEVEL");
	util_concatf(buf, "%*s\n", vdata->entry_len, "SIZE");
}

static unsigned int tree_add_indent(char **buf, unsigned int level,
				    unsigned int *end_flag)
{
	unsigned int i, nesting;
	char *prefix;

	if (level > g.max_level)
		return 0;
	prefix = util_strdup("");
	nesting = g.max_level - level;
	if (g.ascii) {
		for (i = 0; i < nesting; i++) {
			util_concatf(&prefix, "%s%s",
				     end_flag[i] ? " " : ASCII_V, " ");
		}
		util_concatf(&prefix, "%s", end_flag[i] ? ASCII_UR : ASCII_VR);
	} else {
		for (i = 0; i < nesting; i++) {
			util_concatf(&prefix, "%s%s",
				     end_flag[i] ? UTF_SP : UTF_V, UTF_SP);
		}
		util_concatf(&prefix, "%s", end_flag[i] ? UTF_UR : UTF_VR);
	}
	util_concatf(buf, "%s", prefix);
	free(prefix);
	if (g.ascii)
		return (nesting + 1) * 2;
	return nesting * 2 + 1;
}

static unsigned int entry_exists_at(struct topology_entry *entries,
				    unsigned int start,
				    unsigned int end)
{
	unsigned int idx;

	if (g.tree_full)
		return start == end;
	for (idx = start; idx < end; idx++) {
		if (entries->increments[idx])
			return 0;
	}
	return 1;
}

static void tree_part_to_level(char **buf, struct partition *part,
			       unsigned int step, unsigned int level,
			       struct view_data *vdata)
{
	unsigned int start, end, idx, flag_idx, indent;
	struct topology_entry *entries;
	unsigned long memory_size;
	struct stride_unit unit;

	if (level < g.nesting_level)
		return;
	unit = vdata->unit;
	entries = &part->entries[level - 1];
	start = step * vdata->level_len[level - 1];
	end = (step + 1) * vdata->level_len[level - 1];
	flag_idx = g.max_level - level;
	for (idx = start; idx < end; idx++) {
		memory_size = entries->increments[idx] * unit.size / unit.scale;
		if (!memory_size && !g.tree_full)
			continue;
		vdata->end_flag[flag_idx] = entry_exists_at(entries, idx + 1,
							    end);
		indent = tree_add_indent(buf, level, vdata->end_flag);
		concat_w_padding(buf, vdata->cell_len - indent, 1, "LEVEL%u_%u",
				 level, idx % vdata->level_len[level - 1]);
		if (memory_size) {
			concat_w_padding(buf, vdata->entry_len, 0, "%lu%s",
					 memory_size, unit.suffix);
		} else {
			concat_w_padding(buf, vdata->entry_len, 0, "-");
		}
		util_concatf(buf, "\n");
		tree_part_to_level(buf, part, idx, level - 1, vdata);
	}
}

static void tree_create(char **tree, struct partitions *parts,
			struct view_data *vdata)
{
	struct stride_unit unit;
	unsigned long part_size;
	struct partition *cur;

	unit = vdata->unit;
	tree_create_header(tree, vdata);
	util_list_iterate(parts->list, cur) {
		util_concatf(tree, "%-*s", vdata->cell_len, cur->part_name);
		part_size = cur->increment_total * unit.size / unit.scale;
		concat_w_padding(tree, vdata->entry_len, 0, "%u%s", part_size,
				 unit.suffix);
		util_concatf(tree, "\n");
		tree_part_to_level(tree, cur, 0, g.max_level, vdata);
	}
}

static unsigned int is_increment_at(struct partitions *parts,
				    struct partition *cur,
				    unsigned int level,
				    unsigned int idx)
{
	struct partition *next;

	if (!cur)
		next = util_list_start(parts->list);
	else
		next = util_list_next(parts->list, cur);
	for (; next; next = util_list_next(parts->list, next)) {
		if (next->entries[level - 1].increments[idx])
			return 1;
	}
	return 0;
}

static unsigned int rtree_level_total_size(struct partitions *parts,
					   unsigned int level,
					   unsigned int idx)
{
	struct partition *cur;
	unsigned int total;

	total = 0;
	util_list_iterate(parts->list, cur) {
		if (!cur->entries[level - 1].increments[idx])
			continue;
		total += cur->entries[level - 1].increments[idx];
	}
	return total;
}

static void rtree_print_parts(char **buf, struct partitions *parts,
			      unsigned int idx, unsigned int level,
			      struct view_data *vdata)
{
	struct topology_entry *entries;
	unsigned int flag_idx, indent;
	unsigned long incr_size;
	struct stride_unit unit;
	struct partition *cur;

	unit = vdata->unit;
	flag_idx = (g.max_level - level) + 1;
	util_list_iterate(parts->list, cur) {
		entries = &cur->entries[level - 1];
		if (!entries->increments[idx])
			continue;
		vdata->end_flag[flag_idx] = !is_increment_at(parts, cur, level,
							     idx);
		indent = tree_add_indent(buf, level - 1, vdata->end_flag);
		concat_w_padding(buf, vdata->cell_len - indent, 1, "%s",
				 cur->part_name);
		incr_size = entries->increments[idx] * unit.size / unit.scale;
		concat_w_padding(buf, vdata->entry_len, 0, "%lu%s", incr_size,
				 unit.suffix);
		util_concatf(buf, "\n");
		if (vdata->end_flag[flag_idx])
			break;
	}
}

static void rtree_level_to_part(char **buf, struct partitions *parts,
				unsigned int step, unsigned int level,
				struct view_data *vdata)
{
	unsigned int start, end, idx, flag_idx, indent;
	unsigned long incr_size;
	struct stride_unit unit;

	if (level < g.nesting_level)
		return;
	unit = vdata->unit;
	flag_idx = g.max_level - level;
	start = step * vdata->level_len[level - 1];
	end = (step + 1) * vdata->level_len[level - 1];
	for (idx = start; idx < end; idx++) {
		if (!is_increment_at(parts, NULL, level, idx) && !g.tree_full)
			continue;
		indent = 0;
		vdata->end_flag[flag_idx] = (idx + 1) == end;
		if (level != g.max_level)
			indent = tree_add_indent(buf, level, vdata->end_flag);
		concat_w_padding(buf, vdata->cell_len - indent, 1, "LEVEL%u_%u",
				 level, idx % vdata->level_len[level - 1]);
		incr_size = rtree_level_total_size(parts, level, idx);
		incr_size = incr_size * unit.size / unit.scale;
		if (incr_size) {
			concat_w_padding(buf, vdata->entry_len, 0, "%u%s",
					 incr_size, unit.suffix);
		} else {
			concat_w_padding(buf, vdata->entry_len, 0, "-");
		}
		util_concatf(buf, "\n");
		rtree_level_to_part(buf, parts, idx, level - 1, vdata);
		if (level != g.nesting_level)
			continue;
		rtree_print_parts(buf, parts, idx, level, vdata);
	}
}

static void rtree_create(char **tree, struct partitions *parts,
			 struct view_data *vdata)
{
	tree_create_header(tree, vdata);
	rtree_level_to_part(tree, parts, 0, g.max_level, vdata);
}

static void tree_print(struct partitions *parts)
{
	struct view_data *vdata;
	char **tree;

	vdata = util_zalloc(sizeof(*vdata));
	vdata->unit = determine_stride_unit();
	vdata->entry_len = find_entry_cell_size(parts) + UNIT_LEN;
	vdata->cell_len = tree_find_cell_len();
	partition_list_calculate_level_lengths(parts, vdata);
	tree = util_zalloc(sizeof(*tree));
	if (g.tree_reverse)
		rtree_create(tree, parts, vdata);
	else
		tree_create(tree, parts, vdata);
	printf("%s\n", *tree);
	free(vdata);
	free(*tree);
	free(tree);
}

int main(int argc, char *argv[])
{
	struct partitions *parts;
	void *data;

	g.max_level = NESTING_LVL_MIN;
	g.nesting_level = NESTING_LVL_DEF;
	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);
	ebcdic_iconv_init();
	parse_args(argc, argv);
	diag310_check_support();
	data = diag310_get_memtop_data();
	parts = partition_list_create();
	partition_list_populate(data, parts);
	partition_list_sort(parts);
	if (g.table_view)
		table_print(parts);
	else
		tree_print(parts);
	ebcdic_iconv_deinit();
	partition_list_free(parts);
	free(data);
	return 0;
}

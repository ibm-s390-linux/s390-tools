#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <iconv.h>
#include <inttypes.h>

#include "lib/util_opt.h"
#include "lib/util_file.h"
#include "lib/util_prg.h"
#include "lib/util_path.h"

static const struct util_prg prg = {
	.desc = "Display STP system information",
	.args = "",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2020,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static struct util_opt opt_vec[] = {
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

struct stp_parms {
	uint64_t ctn_id;
	unsigned int online;
	unsigned int leap_seconds;
	int leap_seconds_diff;
	unsigned int leap_seconds_utc;
	unsigned int stratum;
	unsigned int ctn_type;
	unsigned int timing_mode;
	unsigned int timing_state;
	int dst_offset;
	int time_offset;
	int time_zone_offset;
};

static int convert_ctn_id(char *in, char *out)
{
	iconv_t ic;
	size_t inlen = sizeof(unsigned long long);
	size_t outlen = sizeof(unsigned long long);

	ic = iconv_open("ISO-8859-1", "EBCDIC-US");
	if (ic == (iconv_t)-1) {
		warn("Could not initialize EBCDIC to ISO-8859-1 conversion table");
		return -1;
	}

	if (iconv(ic, &in, &inlen, (char **)&out, &outlen) == (size_t)-1) {
		warn("Code page translation EBCDIC to ISO-8859-1 failed");
		iconv_close(ic);
		return -1;
	}
	iconv_close(ic);
	return 0;
}

static const char *ctn_type_str(int type)
{
	switch (type) {
	case 0:
		return "No CTN defined";
	case 1:
		return "STP-only";
	case 2:
		return "mixed";
	default:
		return "unknown";
	}
}

static const char *tmd_to_str(int mode)
{
	switch (mode) {
	case 0:
		return "Local";
	case 1:
		return "ETR";
	case 2:
		return "STP";
	case 15:
		return "Uninitialized";
	default:
		return "unknown";
	}
}

static const char *tst_to_str(int mode)
{
	switch (mode) {
	case 0:
		return "Unsynchronized";
	case 1:
		return "Synchronized";
	case 2:
		return "Physical clock stopped";
	default:
		return "unknown";
	}
}

static const char *yesno_str(int val)
{
	return val ? "yes" : "no";
}

#define read_sysfs_attr(attr, parm, func, base)							\
	do {											\
		path = util_path_sysfs("devices/system/stp/%s", attr);				\
		ret = func(parm, base, path);							\
		if (ret) {									\
			fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));	\
			free(path);								\
			exit(EXIT_FAILURE);							\
		}										\
		free(path);									\
	} while (0)

int main(int argc, char **argv)
{
	struct stp_parms parm = { 0 };
	char ctn_id[32] = { 0 };
	char *path;
	int ret, c;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	for (;;) {
		c = util_opt_getopt_long(argc, argv);
		if (c == -1)
			break;

		switch (c) {
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		default:
			fprintf(stderr, "Try 'lsstp --help' for more information.\n");
			exit(EXIT_FAILURE);
		}
	}

	read_sysfs_attr("online", &parm.online, util_file_read_ui, 10);
	if (!parm.online) {
		printf("STP disabled\n");
		goto out;
	}

	read_sysfs_attr("ctn_id", &parm.ctn_id, util_file_read_ul, 16);
	read_sysfs_attr("ctn_type", &parm.ctn_type, util_file_read_ui, 10);
	read_sysfs_attr("stratum", &parm.stratum, util_file_read_ui, 10);
	read_sysfs_attr("leap_seconds", &parm.leap_seconds, util_file_read_ui, 10);
	read_sysfs_attr("timing_mode", &parm.timing_mode, util_file_read_ui, 10);
	read_sysfs_attr("timing_state", &parm.timing_state, util_file_read_ui, 10);
	read_sysfs_attr("dst_offset", &parm.dst_offset, util_file_read_i, 10);
	read_sysfs_attr("time_offset", &parm.time_offset, util_file_read_i, 10);
	read_sysfs_attr("time_zone_offset", &parm.time_zone_offset, util_file_read_i, 10);

	if (convert_ctn_id((char *)&parm.ctn_id, ctn_id))
		snprintf(ctn_id, sizeof(ctn_id)-1, "%016" PRIx64, parm.ctn_id);

	printf("STP online:            %s\n"
	       "CTN ID:                %s\n"
	       "CTN type:              %s\n"
	       "Stratum:               %d\n"
	       "Timing mode:           %s\n"
	       "Timing state:          %s\n"
	       "DST offset:            %d\n"
	       "Timezone offset:       %d\n"
	       "Time offset:           %d\n"
	       "Active leap seconds:   %d\n",
	       yesno_str(parm.online),
	       ctn_id,
	       ctn_type_str(parm.ctn_type),
	       parm.stratum,
	       tmd_to_str(parm.timing_mode),
	       tst_to_str(parm.timing_state),
	       parm.dst_offset,
	       parm.time_zone_offset,
	       parm.time_offset,
	       parm.leap_seconds);

	printf("Scheduled leap second: ");

	path = util_path_sysfs("devices/system/stp/leap_seconds_scheduled");
	if (util_file_read_va(path, "%d,%d", &parm.leap_seconds_utc,
				&parm.leap_seconds_diff) == 2 &&
			parm.leap_seconds_diff && parm.leap_seconds_utc) {
		time_t lsoup = parm.leap_seconds_utc;

		printf("%s at: %s UTC",
			parm.leap_seconds_diff > 0 ? "insertion" : "deletion",
			ctime(&lsoup));
	} else {
		printf("-\n");
	}
	free(path);
	return 0;
out:
	return 1;
}

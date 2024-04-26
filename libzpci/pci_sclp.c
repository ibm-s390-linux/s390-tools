#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>

#include "lib/pci_sclp.h"
#include "lib/util_path.h"

static int zpci_sclp_report(char *pci_addr, struct zpci_report_error *report)
{
	size_t r_size = sizeof(*report);
	char *path;
	FILE *fp;

	path = util_path_sysfs("bus/pci/devices/%s/report_error", pci_addr);
	fp = fopen(path, "w");
	free(path);
	if (!fp)
		return -ENODEV;
	if (fwrite(report, 1, r_size, fp) != r_size)
		return -EIO;
	if (fclose(fp))
		return -EIO;
	return 0;
}

/**
 * Issue an SCLP Adapter Error Notification event with a specific action
 * qualifier and optional log data.
 *
 * The logged data is truncated if needed.
 *
 * @return the number of bytes of the data which were actually logged
 *	   or a negative value on error.
 */
int zpci_sclp_issue_action(char *pci_addr, int action,
			   char *data, size_t length, u64 err_log_id)
{
	struct zpci_report_error report = {0};
	size_t copy_length = 0;
	int ret;

	/* Data is truncated to fit in the report */
	if (data)
		copy_length = MIN(length, sizeof(report.data.log_data));
	report.header.version = 1;
	report.header.action = action;
	report.header.length = offsetof(struct zpci_report_error_data, log_data) + copy_length;
	report.data.timestamp = (__u64)time(NULL);
	report.data.err_log_id = err_log_id;

	if (data)
		memcpy(report.data.log_data, data, copy_length);
	ret = zpci_sclp_report(pci_addr, &report);
	if (ret)
		return ret;
	return copy_length;
}

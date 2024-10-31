#include <stdint.h>

#include "lib/pci_list.h"

#include "optics_info.h"

struct sclp_optics_data {
	/* Status */
	uint32_t module_present	 : 1;
	uint32_t rx_los		 : 1;
	uint32_t tx_fault	 : 1;
	uint32_t reserved_status : 29;
	/* Data Identifier */
	uint32_t data_identifier;
	/* Reserved */
	uint64_t reserved[3];
	/* Additional Log Data */
	uint8_t data[];
} __packed;

int sclp_issue_optics_report(struct zpci_dev *zdev, struct optics *oi);

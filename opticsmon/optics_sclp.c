#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "lib/pci_sclp.h"
#include "lib/util_libc.h"

#include "optics_sclp.h"

static struct sclp_optics_data *init_sclp_optics_data(struct optics *oi, size_t *length)
{
	struct sclp_optics_data *od;

	*length = sizeof(*od) + oi->size;
	od = util_zalloc(*length);
	od->module_present = optics_type(oi) != OPTICS_TYPE_UNKNOWN;
	od->rx_los = optics_rx_los(oi) == OPTICS_LOS;
	od->tx_fault = optics_tx_fault(oi) == OPTICS_LOS;
	switch (optics_type(oi)) {
	case OPTICS_TYPE_SFP:
		od->data_identifier = 1;
		break;
	case OPTICS_TYPE_QSFP28:
		od->data_identifier = 2;
		break;
	default:
		od->data_identifier = 0;
	}
	memcpy(od->data, oi->raw, oi->size);

	return od;
}

int sclp_issue_optics_report(struct zpci_dev *zdev, struct optics *oi)
{
	struct sclp_optics_data *od;
	size_t length;
	char *pci_addr;
	int rc;

	if (zdev->pft != ZPCI_PFT_NETD)
		return -ENOTSUP;
	od = init_sclp_optics_data(oi, &length);
	pci_addr = zpci_pci_addr(zdev);
	rc = zpci_sclp_issue_action(pci_addr, SCLP_ERRNOTIFY_AQ_OPTICS_DATA,
				    (char *)od, length, SCLP_ERRNOTIFY_ID_OPTICSMON);
	free(pci_addr);
	free(od);
	return rc;
}

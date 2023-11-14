#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <err.h>

#include "lib/util_list.h"
#include "lib/pci_list.h"

static void zpci_print(struct zpci_dev *zdev)
{
	char *pci_addr = zpci_pci_addr(zdev);
	int i;

	if (!zdev->conf) {
		printf("fid: %8x address: %s\n", zdev->fid, pci_addr);
	} else {
		printf("fid: %8x address: %s uid: %4x%s pchid: %4x vfn: %4d port: %1d pft: %s ",
		       zdev->fid, pci_addr, zdev->uid, (zdev->uid_is_unique) ? " (unique)" : "",
		       zdev->pchid, zdev->vfn, zdev->port, zpci_pft_str(zdev));
		if (zdev->num_netdevs) {
			printf("netdevs: ");
			for (i = 0; i < zdev->num_netdevs; i++) {
				printf("%s", zdev->netdevs[i]);
				if (i + 1 < zdev->num_netdevs)
					printf(", ");
			}
		}
		printf("\n");
	}
	free(pci_addr);
}

int main(void)
{
	struct util_list *zpci_list;
	struct zpci_dev *zdev;

	zpci_list = zpci_dev_list();
	if (!zpci_list)
		errx(EXIT_FAILURE, "Error getting list of zPCI devices");

	util_list_iterate(zpci_list, zdev)
		zpci_print(zdev);

	zpci_free_dev_list(zpci_list);
	return EXIT_SUCCESS;
}

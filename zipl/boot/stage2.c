/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Main program for stage2 bootloader
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/zt_common.h"

#include "error.h"
#include "libc.h"
#include "menu.h"
#include "boot/s390.h"
#include "boot/loaders_layout.h"
#include "stage2.h"

static int is_null_descriptor(disk_blockptr_t *address)
{
	unsigned long long *value = (unsigned long long *)address;

	return *value == 0;
}

static void *load_blocklist(struct component_entry *descriptor_address,
			    struct subchannel_id subchannel_id, void *load_address)
{
	disk_blockptr_t *indirect_blocks, *indirect_blockspace,
		*start_addr;
	unsigned long length;
	long long nr_descr;

	/* start address to load first indirect blocks */
	start_addr = (disk_blockptr_t *)&descriptor_address->data;
	/* get a free page to store indirect blocks in */
	indirect_blockspace = (void *)get_zeroed_page();

	do {
		length = extract_length(start_addr);
		/* calculate number of descriptors to be processed and base 0 */
		nr_descr = length/DESCR_PER_BLOCK - 1;
		indirect_blocks = indirect_blockspace;
		/* load indirect blocks */
		load_direct(start_addr, subchannel_id, indirect_blocks);

		/* process indirect blocks */
		while (nr_descr > 0) {
			if (is_null_descriptor(indirect_blocks))
				goto out_free_page;

			/* for special zero block simply clear mem */
			if (!is_zero_block(indirect_blocks)) {
				length = extract_length(indirect_blocks);
				memset(load_address, 0, length);
				load_address += length;
			} else
				load_address = load_direct(indirect_blocks,
							   subchannel_id,
							   load_address);

			indirect_blocks++;
			nr_descr--;
		}
		/* update pointer for next round */
		start_addr = indirect_blocks;
	/* as long as another indirect block needs to be loaded */
	} while (!is_null_descriptor(indirect_blocks));

out_free_page:
	free_page((unsigned long)indirect_blockspace);
	return load_address;
}


static void execute(uint64_t psw)
{
	asm volatile(
		"      lpsw    %[psw]\n"
		: : [psw] "Q" (psw) : "cc"
		);
}

void start(void)
{
	struct stage2_descr stage2_descr;
	struct subchannel_id subchannel_id;
	void *load_address;
	struct component_entry *entry;
	disk_blockptr_t *blockptr;
	uint64_t load_psw;
	void *load_page;
	int config_nr;

	subchannel_id = *(struct subchannel_id *)&S390_lowcore.subchannel_id;
	stage2_descr = *(struct stage2_descr*)STAGE2_DESC;

	/* print menu and get configuration number */
	config_nr = menu();
	kdump_stage2(config_nr);

	io_irq_enable();
	set_device(subchannel_id, ENABLED);

	load_page = (void *)get_zeroed_page();
	load_address = (disk_blockptr_t *) load_page;

	/* load blockpointer list to load address */
	load_direct((disk_blockptr_t *)&stage2_descr, subchannel_id,
		    load_address);

	blockptr = (disk_blockptr_t *)(load_address +
					     sizeof(disk_blockptr_t));

	load_direct(&blockptr[config_nr], subchannel_id, load_address);

	/* skip header */
	entry = (struct component_entry *)
		(load_address + sizeof(struct component_header));
	while (entry->type == COMPONENT_LOAD ||
	       entry->type == COMPONENT_SIGNATURE) {
		if (entry->type == COMPONENT_SIGNATURE) {
			/* Skip unhandled signature components */
			entry++;
			continue;
		}
		load_address = (void *)(unsigned long)
			entry->address.load_address[1];
		load_blocklist(entry, subchannel_id, load_address);
		entry++;
	}
	if (entry->type != COMPONENT_EXECUTE)
		panic(EWRONGTYPE, "");

	load_psw = entry->address.load_psw;

	free_page((unsigned long)load_page);
	io_irq_disable();
	set_device(subchannel_id, DISABLED);

	execute(load_psw);
}

void panic_notify(unsigned long UNUSED(reason))
{
}

uint64_t __section(.stage2.head) stage2_head;

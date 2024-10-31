#pragma once
#include <stdbool.h>
#include <stdint.h>

#include <sys/types.h>

#define SFF8079_I2C_ADDRESS_LOW	 0x50
#define SFF8079_I2C_ADDRESS_HIGH 0x51

#define SFF8472_DIAGNOSTICS_TYPE_OFFSET 0x5C
#define SFF8472_DIAGNOSTICS_TYPE_MASK	(1 << 6)

#define SFF8636_PAGE_SIZE     0x80
#define SFF8636_QSFP28_LENGTH 0x100

#define SFF8636_STATUS_2_OFFSET 0x02
#define SFF8636_STATUS_FLAT_MEM (1 << 2)

#define SFF8636_PAGE_OFFSET 0xC3
#define SFF8636_P01H	    (1 << 6)
#define SFF8636_P02H	    (1 << 7)

enum optics_type {
	OPTICS_TYPE_UNKNOWN = 0x0, /* Unknown or unsupported */
	OPTICS_TYPE_SFP = 0x3,	   /* SFP/SFP+/SFP28 and later with SFF-8472 management interface */
	OPTICS_TYPE_QSFP28 = 0x11  /* QSFP28 (SFF-8665 et al.)*/
};

enum optics_los {
	OPTICS_NO_LOS = 0x0,
	OPTICS_LOS = 0x1,
	OPTICS_UNKNOWN_LOS = 0x2,
	OPTICS_UNAVAILABLE_LOS = 0x3,
};

struct optics {
	size_t size;
	uint8_t *raw;
};

enum optics_type optics_type(struct optics *oi);
const char *optics_type_str(enum optics_type type);
const char *optics_los_str(enum optics_los los);

enum optics_los optics_rx_los(struct optics *oi);
enum optics_los optics_tx_los(struct optics *oi);
enum optics_los optics_tx_fault(struct optics *oi);

void optics_free(struct optics *oi);

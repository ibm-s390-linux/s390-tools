#include <stdlib.h>

#include "optics_info.h"

#define OPTICS_TYPE_OFFSET 0x0

#define OPTICS_SFP_LOS_IMPLEMENTED_OFFSET 0x41
#define OPTICS_SFP_LOS_IMPLEMENTED_MASK	  0x2

#define OPTICS_SFP_A2H_OFFSET	       0x100
#define OPTICS_SFP_LOS_OFFSET	       (OPTICS_SFP_A2H_OFFSET + 0x6e)
#define OPTICS_SFP_DATA_NOT_READY_MASK 0x1
#define OPTICS_SFP_TX_FAULT_MASK       0x4
#define OPTICS_SFP_RX_LOS_MASK	       0x2

#define OPTICS_QSFP28_LOS_IMPLEMENTED_OFFSET	0xC3
#define OPTICS_QSFP28_TX_LOS_IMPLEMENTED_MASK	0x2
#define OPTICS_QSFP28_TX_FAULT_IMPLEMENTED_MASK 0x8

#define OPTICS_QSFP28_LOS_OFFSET   0x3
#define OPTICS_QSFP28_LOS_MASK	   0xf
#define OPTICS_QSFP28_TX_LOS_MASK  0xf0
#define OPTICS_QSFP28_TX_LOS_SHIFT 0x4

#define OPTICS_QSFP28_TX_FAULT_OFFSET 0x4
#define OPTICS_QSFP28_TX_FAULT_MASK   0xf

const char *optics_type_str(enum optics_type type)
{
	switch (type) {
	case OPTICS_TYPE_UNKNOWN:
		return "unknown";
	case OPTICS_TYPE_SFP:
		return "SFP/SFP+/SFP28";
	case OPTICS_TYPE_QSFP28:
		return "QSFP28";
	};
	return "n.a.";
}

enum optics_type optics_type(struct optics *oi)
{
	if (!oi || !oi->raw || oi->size < OPTICS_TYPE_OFFSET + 1)
		return OPTICS_TYPE_UNKNOWN;

	switch (oi->raw[OPTICS_TYPE_OFFSET]) {
	case (uint8_t)OPTICS_TYPE_SFP:
		return OPTICS_TYPE_SFP;
	case (uint8_t)OPTICS_TYPE_QSFP28:
		return OPTICS_TYPE_QSFP28;
	default:
		return OPTICS_TYPE_UNKNOWN;
	};
}

bool optics_los_implemented(struct optics *oi)
{
	enum optics_type type = optics_type(oi);
	uint8_t implemented;

	if (type == OPTICS_TYPE_SFP) {
		if (oi->size < OPTICS_SFP_LOS_IMPLEMENTED_OFFSET + 1)
			return false;
		implemented = oi->raw[OPTICS_SFP_LOS_IMPLEMENTED_OFFSET];
		return !!(implemented & OPTICS_SFP_LOS_IMPLEMENTED_MASK);
	} else if (type == OPTICS_TYPE_QSFP28) {
		if (oi->size < OPTICS_QSFP28_LOS_OFFSET + 1)
			return false;
		if (oi->size < OPTICS_QSFP28_LOS_IMPLEMENTED_OFFSET)
			return false;
		implemented = oi->raw[OPTICS_QSFP28_LOS_IMPLEMENTED_OFFSET];
		/*
		 * No RX LoS implemented flag take TX LOS implemented like
		 * ethtool
		 */
		return !!(implemented & OPTICS_QSFP28_TX_LOS_IMPLEMENTED_MASK);
	}
	return false;
}

enum optics_los optics_rx_los(struct optics *oi)
{
	enum optics_los los = OPTICS_UNKNOWN_LOS;
	enum optics_type type = optics_type(oi);

	if (!optics_los_implemented(oi))
		return los;

	if (type == OPTICS_TYPE_SFP) {
		los = oi->raw[OPTICS_SFP_LOS_OFFSET];
		if (los & OPTICS_SFP_DATA_NOT_READY_MASK)
			return OPTICS_UNKNOWN_LOS;
		if (los & OPTICS_SFP_RX_LOS_MASK)
			return OPTICS_LOS;
		else
			return OPTICS_NO_LOS;
	} else if (type == OPTICS_TYPE_QSFP28) {
		los = oi->raw[OPTICS_QSFP28_LOS_OFFSET];
		if (los & OPTICS_QSFP28_LOS_MASK)
			los = OPTICS_LOS;
		else
			los = OPTICS_NO_LOS;
	}
	return los;
}

const char *optics_los_str(enum optics_los los)
{
	switch (los) {
	case OPTICS_LOS:
		return "yes";
	case OPTICS_NO_LOS:
		return "no";
	case OPTICS_UNAVAILABLE_LOS:
		return "unavailable";
	default:
		return "unknown";
	}
}

enum optics_los optics_tx_fault(struct optics *oi)
{
	enum optics_los los = OPTICS_UNKNOWN_LOS;
	enum optics_type type = optics_type(oi);

	if (!optics_los_implemented(oi))
		return los;

	if (type == OPTICS_TYPE_SFP) {
		los = oi->raw[OPTICS_SFP_LOS_OFFSET];
		if (los & OPTICS_SFP_DATA_NOT_READY_MASK)
			return OPTICS_UNKNOWN_LOS;
		if (los & OPTICS_SFP_TX_FAULT_MASK)
			return OPTICS_LOS;
		else
			return OPTICS_NO_LOS;
	} else if (type == OPTICS_TYPE_QSFP28) {
		los = oi->raw[OPTICS_QSFP28_TX_FAULT_OFFSET];
		if (los & OPTICS_QSFP28_TX_FAULT_MASK)
			los = OPTICS_LOS;
		else
			los = OPTICS_NO_LOS;
	}
	return los;
}

enum optics_los optics_tx_los(struct optics *oi)
{
	enum optics_los los = OPTICS_UNKNOWN_LOS;
	enum optics_type type = optics_type(oi);

	if (!optics_los_implemented(oi))
		return los;

	if (type == OPTICS_TYPE_SFP) {
		return OPTICS_UNAVAILABLE_LOS;
	} else if (type == OPTICS_TYPE_QSFP28) {
		los = oi->raw[OPTICS_QSFP28_LOS_OFFSET];
		if (los & OPTICS_QSFP28_TX_LOS_MASK)
			los = OPTICS_LOS;
		else
			los = OPTICS_NO_LOS;
	}
	return los;
}

void optics_free(struct optics *oi)
{
	free(oi->raw);
	free(oi);
}

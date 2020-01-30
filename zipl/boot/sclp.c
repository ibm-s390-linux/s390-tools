/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Functions for console input and output
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "libc.h"
#include "error.h"
#include "boot/s390.h"
#include "sclp.h"
#include "ebcdic.h"
#ifdef ENABLE_SCLP_ASCII
# include "ebcdic_conv.h"
#endif /* ENABLE_SCLP_ASCII */

/* Perform service call. Return 0 on success, non-zero otherwise. */
static int sclp_service_call(unsigned int command, void *sccb)
{
	int cc;

	asm volatile(
		"       .insn   rre,0xb2200000,%1,%2\n"  /* servc %1,%2 */
		"       ipm     %0\n"
		"       srl     %0,28"
		: "=&d" (cc)
		: "d" (command), "a" (sccb)
		: "cc", "memory");
	if (cc == 3)
		return 3;
	if (cc == 2)
		return 2;
	return 0;
}

static inline int wait(void)
{
	struct psw_t ext_old_psw_save;
	uint16_t ext_int_code_save;
	int rc = 0;

	ext_old_psw_save = S390_lowcore.external_old_psw;
	ext_int_code_save = S390_lowcore.ext_int_code;

	S390_lowcore.ext_int_code = 0;
	do {
		load_wait_psw(0x0102000180000000ULL, &S390_lowcore.external_new_psw);
		if (S390_lowcore.ext_int_code == 0x1004) {
			rc = ETIMEOUT;
			break;
		}
	} while (S390_lowcore.ext_int_code != 0x2401);

	S390_lowcore.ext_int_code = ext_int_code_save;
	S390_lowcore.external_old_psw = ext_old_psw_save;

	return rc;
}

int sclp_wait_for_int(unsigned long long timeout)
{
	unsigned long old_ctl, ctl;
	uint64_t time;
	int rc;

	if (timeout) {
		timeout <<= 32;
		time = get_tod_clock();
		time += timeout;
		set_clock_comparator(time);
	}

	/* get control register 0 */
	__ctl_store(old_ctl, 0, 0);

	ctl = old_ctl;
	/* set new mask */
	ctl |= CTL_SERVICE_SIGNAL;
	if (timeout)
		ctl |= CTL_CLOCK_COMPARATOR;
	else
		ctl &= ~CTL_CLOCK_COMPARATOR;
	/* write control register 0 */
	__ctl_load(ctl, 0, 0);

	rc = wait();

	/* restore old control register 0 */
	__ctl_load(old_ctl, 0, 0);

	return rc;
}

int start_sclp(unsigned int cmd, void *sccb)
{
	int rc;

	while (1) {
		rc = sclp_service_call(cmd, sccb);
		if (rc == 3)
			return 1;

		if (rc == 2)
			sclp_wait_for_int(0);
		else
			break;
	}
	sclp_wait_for_int(0);
	return 0;
}

static int mask_is_set(sccb_mask_t mask_to_set, sccb_mask_t mask_set)
{
	return (mask_to_set & mask_set) == mask_to_set;
}

int sclp_setup(int initialise)
{
	struct init_sccb *sccb;
	unsigned int cmd;
	int rc;

	sccb = (void *)get_zeroed_page();
	sccb->header.length = sizeof(struct init_sccb);
	sccb->mask_length = 4;

	switch (initialise) {
	case SCLP_INIT:
		sccb->receive_mask = SCLP_EVENT_MASK_OPCMD;
		sccb->send_mask = SCLP_EVENT_MASK_MSG;
		break;
	case SCLP_DISABLE:
		sccb->receive_mask = SCLP_EVENT_MASK_DISABLE;
		sccb->send_mask = SCLP_EVENT_MASK_DISABLE;
		break;
	case SCLP_LINE_ASCII_INIT:
		sccb->receive_mask = SCLP_EVENT_MASK_DISABLE;
		sccb->send_mask = SCLP_EVENT_MASK_MSG | SCLP_EVENT_MASK_ASCII;
		break;
	case SCLP_HSA_INIT:
		sccb->receive_mask = SCLP_EVENT_MASK_DISABLE;
		sccb->send_mask = SCLP_EVENT_MASK_MSG | SCLP_EVENT_MASK_SDIAS;
		break;
	case SCLP_HSA_INIT_ASYNC:
		sccb->receive_mask = SCLP_EVENT_MASK_SDIAS;
		sccb->send_mask = SCLP_EVENT_MASK_MSG | SCLP_EVENT_MASK_SDIAS;
		break;
	}

	cmd = SCLP_CMD_WRITE_MASK;
	rc = start_sclp(cmd, sccb);
	if (rc || sccb->header.response_code != 0x20) {
		rc = 1;
		goto out_free_page;
	}

	if (!mask_is_set(sccb->send_mask, sccb->sclp_send_mask) ||
	    !mask_is_set(sccb->receive_mask, sccb->sclp_receive_mask)) {
		rc = 1;
		goto out_free_page;
	}
	rc = 0;
out_free_page:
	free_page((unsigned long) sccb);
	return rc;
}

#ifdef ENABLE_SCLP_ASCII
/* Content of @buffer must be EBCDIC encoded. The function used for
 * the conversion `ebcdic_to_ascii` differentiates whether the code
 * runs on z/VM or not and then selects the appropriate EBCDIC
 * coding.
 */
int sclp_print_ascii(const char *buffer)
{
	struct write_sccb *sccb = NULL;
	int rc, str_len = strlen(buffer);
	unsigned long data_len = str_len + 1;

	/* don't overflow the sccb buffer */
	if (data_len > SCCB_MAX_DATA_LEN)
		data_len = SCCB_MAX_DATA_LEN;

	sccb = (void *)get_zeroed_page();
	sccb->header.length = sizeof(struct write_sccb) - sizeof(struct mdb)
		+ data_len;
	sccb->header.function_code = SCLP_FC_NORMAL_WRITE;
	sccb->msg_buf.header.length = sizeof(struct msg_buf) - sizeof(struct mdb)
		+ data_len;
	sccb->msg_buf.header.type = SCLP_EVENT_DATA_ASCII;
	sccb->msg_buf.header.flags = 0;
	ebcdic_to_ascii(sccb->msg_buf.data,
			(const unsigned char *)buffer,
			data_len - 1);
	sccb->msg_buf.data[data_len - 1] = '\0';

	/* SCLP command for write data */
	rc = start_sclp(SCLP_CMD_WRITE_DATA, sccb);
	if (rc || sccb->header.response_code != 0x20) {
		rc = 1;
		goto out_free_page;
	}
	rc = 0;
out_free_page:
	free_page((unsigned long) sccb);
	return rc;
}
#endif /* ENABLE_SCLP_ASCII */

int sclp_print(char *buffer)
{
	struct write_sccb *sccb;
	struct mto *mto;
	char *data;
	unsigned int cmd;
	int rc, i = 0;

	sccb = (void *)get_zeroed_page();
	mto = (void *)((char *)sccb) + sizeof(struct write_sccb);
	data = (char *)mto + sizeof(struct mto);
	sccb->header.length = sizeof(struct write_sccb);
	sccb->msg_buf.header.length =  sizeof(struct msg_buf);
	sccb->msg_buf.header.type = 0x02;
	sccb->msg_buf.mdb.header.length = sizeof(struct mdb);
	sccb->msg_buf.mdb.header.type = 1;
	sccb->msg_buf.mdb.header.tag = EBC_MDB;
	sccb->msg_buf.mdb.header.revision_code = 1;
	sccb->msg_buf.mdb.go.length = sizeof(struct go);
	sccb->msg_buf.mdb.go.type = 1;

	while (buffer[i] != 0) {
		memset(mto, 0, sizeof(struct mto));
		mto->length = sizeof(struct mto);
		mto->type = 4;
		mto->line_type_flags = 0x1000;

		/*
		 * while not end of string and not end of line
		 * copy characterwise
		 */
		while (buffer[i] != 0 && buffer[i] != 0x15) {
			*data = buffer[i];
			mto->length++;
			data++;
			i++;
		}

		/* update lengths */
		sccb->msg_buf.mdb.header.length += mto->length;
		sccb->msg_buf.header.length +=  mto->length;
		sccb->header.length +=  mto->length;

		/* if another line is remaining build a new mto */
		if (buffer[i] != 0) {
			mto = (struct mto *)data;
			data = (char *)mto + sizeof(struct mto);
			i++;
		}
	}

	/* SCLP command for write data */
	cmd = SCLP_CMD_WRITE_DATA;
	rc = start_sclp(cmd, sccb);
	if (rc || sccb->header.response_code != 0x20) {
		rc = 1;
		goto out_free_page;
	}
	rc = 0;
out_free_page:
	free_page((unsigned long) sccb);
	return rc;
}

int sclp_read_info(struct read_info_sccb *sccb)
{
	unsigned int cmd;
	int rc;

	sccb->header.length = sizeof(struct read_info_sccb);
	cmd = SCLP_CMD_READ_INFO;

	rc = start_sclp(cmd, sccb);

	if (rc)
		return 1;

	if (sccb->header.response_code != 0x10) {
		cmd = SCLP_CMD_READ_INFO2;
		rc = start_sclp(cmd, sccb);
	}

	if (rc || sccb->header.response_code != 0x10)
		return 2;

	return 0;
}

int sclp_param(char *loadparm)
{
	struct read_info_sccb *sccb;
	int rc;

	sccb = (void *)get_zeroed_page();
	rc = sclp_read_info(sccb);

	if (rc == 0)
		memcpy(loadparm, sccb->loadparm, 8);
	free_page((unsigned long) sccb);
	return rc;
}

static struct gds_vector *sclp_find_gds_vector(void *start, void *end, uint16_t id)
{
	struct gds_vector *v;

	for (v = start; (void *)v < end; v = (void *)v + v->length)
		if (v->gds_id == id)
			return v;
	return NULL;
}

static struct gds_subvector *sclp_eval_selfdeftextmsg(struct gds_subvector *sv)
{
	void *end;

	end = (void *)sv + sv->length;
	for (sv = sv + 1; (void *)sv < end; sv = (void *)sv + sv->length)
		if (sv->key == 0x30)
			return sv;

	return NULL;
}

static struct gds_subvector *sclp_eval_textcmd(struct gds_vector *v)
{
	struct gds_subvector *sv;
	void *end;

	end = (void *)v + v->length;
	for (sv = (struct gds_subvector *)(v + 1); (void *)sv < end;
	     sv = (void *)sv + sv->length)
		if (sv->key == GDS_KEY_SELFDEFTEXTMSG)
			return sclp_eval_selfdeftextmsg(sv);

	return NULL;
}

static struct gds_subvector *sclp_eval_cpmsu(struct gds_vector *v)
{
	void *end;

	end = (void *)v + v->length;
	for (v = v + 1; (void *)v < end; v = (void *)v + v->length)
		if (v->gds_id == GDS_ID_TEXTCMD)
			return sclp_eval_textcmd(v);

	return NULL;
}

static struct gds_subvector *sclp_eval_mdsmu(struct gds_vector *v)
{
	v = sclp_find_gds_vector(v + 1, (void *)v + v->length, GDS_ID_CPMSU);
	if (v)
		return sclp_eval_cpmsu(v);

	return NULL;
}

int sclp_read(unsigned long timeout, void *target, int *count)
{
	struct read_sccb *sccb;
	struct evbuf_header *evbuf;
	struct gds_subvector *sv;
	struct gds_vector *v;
	unsigned int cmd;
	int rc;

	sccb = (void *)get_zeroed_page();
	evbuf = (struct evbuf_header *)sccb->data;
retry:
	memset(sccb, 0, sizeof(struct read_sccb));
	sccb->header.length = 0x1000;

	cmd = SCLP_CMD_READ_DATA;
	rc = start_sclp(cmd, sccb);
	if (rc) {
		rc = 1;
		goto out_free_page;
	}

	if (sccb->header.response_code == 0x20) {
		v = sclp_find_gds_vector((void *)evbuf + sizeof(*evbuf),
					 (void *)evbuf + evbuf->length,
					 GDS_ID_MDSMU);
		if (!v) {
			rc = -EIO;
			goto out_free_page;
		}
		sv = sclp_eval_mdsmu(v);
		if (!sv) {
			rc = -EIO;
			goto out_free_page;
		}
		*count = sv->length - (sizeof(*sv));
		memcpy(target, sv + 1, *count);
		rc = 0;
		goto out_free_page;
	}

	if (sccb->header.response_code == 0x60f0) {
		rc = sclp_wait_for_int(timeout);
		if (rc) {
			rc = 2;
			goto out_free_page;
		}
		goto retry;
	} else {
		rc = 1;
	}
out_free_page:
	free_page((unsigned long) sccb);
	return rc;
}

/*
 * iSCSI driver for Linux
 * Copyright (C) 2001 Cisco Systems, Inc.
 * Copyright (C) 2004 Mike Christie
 * Copyright (C) 2004 IBM Corporation
 * maintained by linux-iscsi-devel@lists.sourceforge.net
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 *
 * $Id: iscsi-xmit-pdu.c,v 1.1.2.28 2005/04/26 17:44:50 mikenc Exp $
 *
 * Contains functions to handle transmission of iSCSI PDUs
 */
#include <linux/tcp.h>
#include <linux/net.h>
#include <asm/scatterlist.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_dbg.h>

#include "iscsi-session.h"
#include "iscsi-task.h"
#include "iscsi-protocol.h"
#include "iscsi-login.h"
#include "iscsi-sfnet.h"

static int
iscsi_send_header(struct iscsi_session *session, struct iscsi_hdr *hdr,
		  int hdr_digest)
{
	struct scatterlist sg;
	struct kvec iov[2];
	u32 crc32c;
	int len, iovn = 0;

	iov[iovn].iov_base = hdr;
	iov[iovn].iov_len = sizeof(*hdr);
	len = iov[iovn].iov_len;
	iovn++;

	if (hdr_digest == ISCSI_DIGEST_CRC32C) {
		crypto_digest_init(session->tx_tfm);
		sg_init_one(&sg, (u8 *)hdr, len);
		crypto_digest_digest(session->tx_tfm, &sg, 1, (u8*)&crc32c);
		iov[iovn].iov_base = &crc32c;
		iov[iovn].iov_len = sizeof(crc32c);
		len += iov[iovn].iov_len;
		iovn++;
	}

	return iscsi_sendmsg(session, iov, iovn, len);
}

static int
send_extra_data(struct iscsi_session *session, u32 data_len, int digest_opt)
{
	struct scatterlist sg;
	struct kvec iov[2];
	int pad, iovn = 0, len = 0;
	char padding[PAD_WORD_LEN - 1];
	u32 data_crc32c;

	if (data_len % PAD_WORD_LEN) {
		pad = PAD_WORD_LEN - (data_len % PAD_WORD_LEN);
		memset(padding, 0, pad);
		iov[iovn].iov_base = padding;
		iov[iovn].iov_len = pad;
		iovn++;
		len += pad;

		if (digest_opt == ISCSI_DIGEST_CRC32C) {
			sg_init_one(&sg, padding, pad);
			crypto_digest_update(session->tx_tfm, &sg, 1);
		}
	}

	if (data_len && digest_opt == ISCSI_DIGEST_CRC32C) {
		crypto_digest_final(session->tx_tfm, (u8*)&data_crc32c);
		iov[iovn].iov_base = &data_crc32c;
		iov[iovn].iov_len = sizeof(data_crc32c);
		len += iov[iovn].iov_len;
		iovn++;
	}

	if (iov)
		return iscsi_sendmsg(session, iov, iovn, len);
	else
		return ISCSI_IO_SUCCESS;
}

/**
 * iscsi_send_sg_data - send SCSI data
 * @session: iscsi session
 * @sglist: scatterlist
 * @start_sg: index into sglist to start from
 * @sg_offset: offset in scatterlist entry to start from
 * @sglist_len: number of entries in sglist
 * @data_len: transfer length
 * @digest_opt: CRC32C or NONE
 *
 * Note:
 *    iscsi_send_sg_data will set start_sg and sg_offset to the
 *    next starting values for future transfers from this scatterlist
 *    (if one is possible), for the caller.
 **/
static int
iscsi_send_sg_data(struct iscsi_session *session, struct scatterlist *sglist,
		   int *start_sg, u32 *sg_offset, int sglist_len,
		   u32 data_len, int digest_opt)
{
	unsigned int len, sg_bytes, pg_offset, remaining = data_len;
	struct scatterlist tmpsg, *sg;
	struct page *pg;
	int i, rc, flags = MSG_MORE;

	if (digest_opt == ISCSI_DIGEST_CRC32C)
		crypto_digest_init(session->tx_tfm);
	/*
	 * loop over the scatterlist
	 */
	for (i = *start_sg; remaining > 0 && i < sglist_len; i++) {
		sg = &sglist[i];

		if (signal_pending(current))
			return ISCSI_IO_INTR;

		pg_offset = sg->offset + *sg_offset;
		pg = sg->page + (pg_offset >> PAGE_SHIFT);
		pg_offset -= (pg_offset & PAGE_MASK);

		/*
		 * set the offset and sg for the next pdu or loop
		 * iteration
		 */
		sg_bytes = sg->length - *sg_offset;
		if (sg_bytes <= remaining) {
			(*start_sg)++;
			*sg_offset = 0;
		} else {
			*sg_offset = *sg_offset + remaining;
			sg_bytes = remaining;
		}
		remaining -= sg_bytes;

		/*
		 * loop over each page in sg entry 
		 */ 
		for (; sg_bytes > 0; sg_bytes -= len) {
			len = min_t(unsigned int, sg_bytes,
				    PAGE_SIZE - pg_offset);
			if (len == sg_bytes)
				flags = 0;

			rc = iscsi_sendpage(session, flags, pg, pg_offset, len);
			if (rc != ISCSI_IO_SUCCESS)
				return rc;

			if (digest_opt == ISCSI_DIGEST_CRC32C) {
				tmpsg.page = pg;
				tmpsg.offset = pg_offset;
				tmpsg.length = len;
				crypto_digest_update(session->tx_tfm,
						     &tmpsg, 1);
			}

			pg++;
			pg_offset = 0;
		}
	}

	/*
	 * this should only happen for driver or scsi/block layer bugs
	 */
	if (remaining != 0) {
		iscsi_host_err(session, "iscsi_send_sg_data - invalid sg list "
			       "start_sg %d, sg_offset %u, sglist_len %d "
			       "data_len %u, remaining %u\n", *start_sg,
			       *sg_offset, sglist_len, data_len, remaining);
		return ISCSI_IO_INVALID_OP;
	}

	return send_extra_data(session, data_len, digest_opt);
}

int
iscsi_send_pdu(struct iscsi_session *session, struct iscsi_hdr *hdr,
	       int hdr_digest, char *data, int data_digest)
{
	struct scatterlist sg;
	u32 data_len, offset = 0;
	int rc, index = 0;

	rc = iscsi_send_header(session, hdr, hdr_digest);
	if (rc != ISCSI_IO_SUCCESS) {
		iscsi_drop_session(session);
		goto done;
	}

	data_len= ntoh24(hdr->dlength);
	if (data && data_len) {
		sg_init_one(&sg, data, data_len);
		rc = iscsi_send_sg_data(session, &sg, &index, &offset, 1,
					data_len, data_digest);
		if (rc != ISCSI_IO_SUCCESS)
			iscsi_drop_session(session);
	}

 done:
	return rc == ISCSI_IO_SUCCESS ? 1 : 0;
}

static void
set_task_mgmt_attrs(struct iscsi_scsi_task_mgmt_hdr *ststmh,
		    struct iscsi_task *task)
{
	u8 tmf_code;

	if (test_bit(ISCSI_TASK_ABORT, &task->flags)) {
		/*
		 * we reused cmdsn for refcmdsn for abort tasks.
		 */
		ststmh->refcmdsn = htonl(task->cmdsn);
		ststmh->rtt = htonl(task->rtt);
		ststmh->lun[1] = task->lun;
		tmf_code = ISCSI_TMF_ABORT_TASK;
	} else if (test_bit(ISCSI_TASK_ABORT_TASK_SET, &task->flags)) {
		ststmh->lun[1] = task->lun;
		tmf_code = ISCSI_TMF_ABORT_TASK_SET;
	} else if (test_bit(ISCSI_TASK_LU_RESET, &task->flags)) {
		ststmh->lun[1] = task->lun;
		tmf_code = ISCSI_TMF_LOGICAL_UNIT_RESET;
	} else
		tmf_code = ISCSI_TMF_TARGET_WARM_RESET;

	ststmh->flags = ISCSI_FLAG_FINAL | (tmf_code & ISCSI_FLAG_TMF_MASK);
}

void
iscsi_send_task_mgmt(struct iscsi_session *session)
{
	struct iscsi_task *task;
	struct iscsi_scsi_task_mgmt_hdr ststmh;
	int rc;

	spin_lock_bh(&session->task_lock);

	task = iscsi_find_session_task(session, session->last_mgmt_itt);
	if (!task) {
		/*
		 * timed out or session dropping
		 */
		spin_unlock_bh(&session->task_lock);
		return;
	}

	memset(&ststmh, 0, sizeof(struct iscsi_scsi_task_mgmt_hdr));
	ststmh.opcode = ISCSI_OP_TASK_MGT_REQ | ISCSI_OP_IMMEDIATE;
	ststmh.rtt = ISCSI_RSVD_TASK_TAG;
	ststmh.itt = htonl(task->itt);
	ststmh.cmdsn = htonl(session->cmd_sn);
	/* CmdSN not incremented after imm cmd */
	ststmh.expstatsn = htonl(session->exp_stat_sn);
	set_task_mgmt_attrs(&ststmh, task);

	__iscsi_put_task(task);
	spin_unlock_bh(&session->task_lock);

	rc = iscsi_send_header(session, (struct iscsi_hdr *)&ststmh,
			       session->header_digest);
	if (rc != ISCSI_IO_SUCCESS) {
		/* TODO drop session here still? */
		iscsi_host_err(session, "xmit_task_mgmt failed\n");
		iscsi_drop_session(session);
	}
}

/**
 * iscsi_send_nop_out - transmit iscsi NOP-out
 * @session: iscsi session
 * @itt: Initiator Task Tag (must be in network byte order)
 * @ttt: Target Transfer Tag (must be in network byte order)
 * @lun: when ttt is valid, lun must be set
 **/
static void
__iscsi_send_nop_out(struct iscsi_session *session, u32 itt, u32 ttt, u8 *lun)
{
	struct iscsi_nop_out_hdr stph;
	int rc;

	memset(&stph, 0, sizeof(stph));
	stph.opcode = ISCSI_OP_NOOP_OUT | ISCSI_OP_IMMEDIATE;
	stph.flags = ISCSI_FLAG_FINAL;
	stph.cmdsn = htonl(session->cmd_sn);
	stph.expstatsn = htonl(session->exp_stat_sn);
	if (lun)
		memcpy(stph.lun, lun, sizeof(stph.lun));
	stph.ttt = ttt;
	stph.itt = itt;

	rc = iscsi_send_header(session, (struct iscsi_hdr *)&stph, 
			       session->header_digest);
	if (rc != ISCSI_IO_SUCCESS) {
		iscsi_host_err(session, "xmit_ping failed\n");
		/* mv drop ? */
		iscsi_drop_session(session);
	}
}

void
iscsi_send_nop_out(struct iscsi_session *session)
{
	u32 itt;

	spin_lock_bh(&session->task_lock);
	itt = iscsi_alloc_itt(session);
	spin_unlock_bh(&session->task_lock);
	__iscsi_send_nop_out(session, htonl(itt), ISCSI_RSVD_TASK_TAG, NULL);
}

/* send replies for NopIns that requested them */
void
iscsi_send_nop_replys(struct iscsi_session *session)
{
	struct iscsi_nop_info *nop_info;
	/*
	 * these aren't really tasks, but it's not worth having
	 * a separate lock for them
	 */
	spin_lock_bh(&session->task_lock);
	/*
	 * space for one data-less reply is preallocated in
	 * the session itself
	 */
	if (session->nop_reply.ttt != ISCSI_RSVD_TASK_TAG) {
		spin_unlock_bh(&session->task_lock);
		__iscsi_send_nop_out(session, ISCSI_RSVD_TASK_TAG,
				     session->nop_reply.ttt,
				     session->nop_reply.lun);
		session->nop_reply.ttt = ISCSI_RSVD_TASK_TAG;
		spin_lock_bh(&session->task_lock);
	}
	/*
	 * if we get multiple reply requests, or they have data,
	 * they'll get queued up
	 */
	while (!list_empty(&session->nop_reply_list)) {
		nop_info = list_entry(session->nop_reply_list.next,
				      struct iscsi_nop_info, reply_list);
		list_del_init(&nop_info->reply_list);

		spin_unlock_bh(&session->task_lock);
		__iscsi_send_nop_out(session, ISCSI_RSVD_TASK_TAG,
				     nop_info->ttt, nop_info->lun);
		kfree(nop_info);
		if (signal_pending(current))
			return;
		spin_lock_bh(&session->task_lock);
	}
	spin_unlock_bh(&session->task_lock);
}

void
iscsi_send_logout(struct iscsi_session *session)
{
	struct iscsi_logout_hdr stlh;
	u32 itt;
	int rc;

	spin_lock_bh(&session->task_lock);
	itt = iscsi_alloc_itt(session);
	spin_unlock_bh(&session->task_lock);

	memset(&stlh, 0, sizeof(stlh));
	stlh.opcode = ISCSI_OP_LOGOUT_CMD | ISCSI_OP_IMMEDIATE;
	stlh.flags = ISCSI_FLAG_FINAL | (ISCSI_LOGOUT_REASON_CLOSE_SESSION &
					 ISCSI_FLAG_LOGOUT_REASON_MASK);
	stlh.itt = htonl(itt);
	stlh.cmdsn = htonl(session->cmd_sn);
	stlh.expstatsn = htonl(session->exp_stat_sn);

	rc = iscsi_send_header(session, (struct iscsi_hdr *)&stlh,
			       session->header_digest);
	if (rc != ISCSI_IO_SUCCESS) {
		iscsi_host_err(session, "xmit_logout failed\n");
		/* drop here ? */
		iscsi_drop_session(session);
	}
}

/**
 * iscsi_send_data_out - send a SCSI Data-out PDU
 * @task: iscsi task
 * @ttt: target transfer tag
 * @data_offset: offset of transfer within the complete transfer
 * @data_len: data trasnfer length
 *
 * Note:
 *   If command PDUs are small (no immediate data), we
 *   start new commands as soon as possible, so that we can
 *   overlap the R2T latency with the time it takes to
 *   send data for commands already issued.  This increases
 *   throughput without significantly increasing the completion
 *   time of commands already issued.
 **/
static int
iscsi_send_data_out(struct iscsi_task *task, u32 ttt, u32 data_offset,
		    u32 data_len)
{
	struct iscsi_session *session = task->session;
	struct scsi_cmnd *sc = task->scsi_cmnd;
	struct scatterlist tmpsg, *sg;
	struct iscsi_data_hdr stdh;
	u32 data_sn = 0, dlen, remaining, sg_offset;
	int i, rc = ISCSI_IO_SUCCESS;

	memset(&stdh, 0, sizeof(stdh));
	stdh.opcode = ISCSI_OP_SCSI_DATA;
	stdh.itt = htonl(task->itt);
	stdh.ttt = ttt;

	/*
	 * Find the right sg entry and offset into it if needed.
	 * Why do we not cache this index for DataPDUInOrder?
	 */
	sg_offset = data_offset;
	sg = sc->request_buffer;
	for (i = 0; i < sc->use_sg; i++) {
		if (sg_offset < sg->length)
			break;
		else {
			sg_offset -= sg->length;
			sg++;
		}
	}

	/*
	 * check that the target did not send us some bad values. just
	 * let the cmnd timeout if it does.
	 */
	if (sc->request_bufflen < data_offset + data_len ||
	    (sc->use_sg && i >= sc->use_sg)) {
		iscsi_host_err(session, "iscsi_send_data_out - invalid write. "
			       "len %u, offset %u, request_bufflen %u, usg_sg "
			       "%u, task %u\n", data_len, data_offset,
			       sc->request_bufflen, sc->use_sg, task->itt);
		return ISCSI_IO_INVALID_OP;
	}

	/*
	 * PDU loop - might need to send multiple PDUs to satisfy
	 * the transfer, or we can also send a zero length PDU
	 */
	remaining = data_len;
	do {
		if (signal_pending(current)) {
			rc = ISCSI_IO_INTR;
			break;
		}

		if (!session->immediate_data) 
			iscsi_run_pending_queue(session);

		stdh.datasn = htonl(data_sn++);
		stdh.offset = htonl(data_offset);
		stdh.expstatsn = htonl(session->exp_stat_sn);

		if (session->max_xmit_data_segment_len && 
		    remaining > session->max_xmit_data_segment_len) 
			/* enforce the target's data segment limit */
			dlen = session->max_xmit_data_segment_len;
		 else {
			/* final PDU of a data burst */
			dlen = remaining;
			stdh.flags = ISCSI_FLAG_FINAL;
		}
		hton24(stdh.dlength, dlen);

		rc = iscsi_send_header(session, (struct iscsi_hdr *)&stdh,
				       session->header_digest);
		if (rc != ISCSI_IO_SUCCESS) {
			iscsi_drop_session(session);
			break;
		}

		if (sc->use_sg)
			rc = iscsi_send_sg_data(session, sc->request_buffer,
						&i, &sg_offset, sc->use_sg,
						dlen, session->data_digest);
		else {
			sg_init_one(&tmpsg, sc->request_buffer, sc->bufflen);
			rc = iscsi_send_sg_data(session, &tmpsg, &i,
						&sg_offset, 1, dlen,
						session->data_digest);
		}

		if (rc != ISCSI_IO_SUCCESS &&
		    rc != ISCSI_IO_INVALID_OP)
			iscsi_drop_session(session);

		data_offset += dlen;
		remaining -= dlen;
	} while (remaining > 0 && rc == ISCSI_IO_SUCCESS);

	return rc;
}

static inline unsigned
get_immediate_data_len(struct iscsi_session *session, struct scsi_cmnd *sc)
{
	int len;

	if (!session->immediate_data)
		return 0;

	if (session->first_burst_len)
		len = min(session->first_burst_len,
			  session->max_xmit_data_segment_len);
	else
		len = session->max_xmit_data_segment_len;
	return min_t(unsigned, len, sc->request_bufflen);
}

/*
 * iscsi_queue_r2t may be called so the task lock must be held
 * why not handle this in iscsi_send_scsi_cmnd?
 */
void
iscsi_queue_unsolicited_data(struct iscsi_task *task)
{
	unsigned imm_data_len;
	struct iscsi_session *session = task->session;
	struct scsi_cmnd *sc = task->scsi_cmnd;

	/*
	 * With ImmediateData, we may or may not have to send
	 * additional Data PDUs, depending on the amount of data, and
	 * the Max PDU Length, and the first_burst_len.
	 */
	if (!test_bit(ISCSI_TASK_WRITE, &task->flags) ||
	    !sc->request_bufflen || session->initial_r2t)
		return;
	/*
	 * queue up unsolicited data PDUs. the implied initial R2T
	 * doesn't count against the MaxOutstandingR2T, so we can't use
	 * the normal R2T * fields of the task for the implied initial
	 * R2T. Use a special flag for the implied initial R2T, and
	 * let the rx thread update tasks in the tx_tasks collection
	 * if an R2T comes in before the implied initial R2T has been
	 * processed.
	 */
	if (session->immediate_data) {
		imm_data_len = get_immediate_data_len(session, sc);
		/*
		 * Only queue unsolicited data out PDUs if there is more
		 * data in the request, and the FirstBurstLength hasn't
		 * already been satisfied with the ImmediateData that
		 * will be sent below via iscsi_send_scsi_cmnd().
		 */
		if (sc->request_bufflen == imm_data_len ||
		    imm_data_len == session->first_burst_len)
			return;
	}

	__set_bit(ISCSI_TASK_INITIAL_R2T, &task->flags);
	iscsi_queue_r2t(session, task);
	set_bit(TX_DATA, &session->control_bits);
	set_bit(TX_WAKE, &session->control_bits);
}

/**
 * iscsi_send_r2t_data - see if we need to send more data.
 * @session: iscsi session
 *
 * Note:
 *   This may call iscsi_run_pending_queue under some conditions.
 **/
void
iscsi_send_r2t_data(struct iscsi_session *session)
{
	struct iscsi_task *task;
	struct scsi_cmnd *sc;
	u32 ttt, offset, len;
	unsigned implied_len, imm_data_len;
	int rc;

	spin_lock_bh(&session->task_lock);
 retry:
	task = iscsi_dequeue_r2t(session);
	if (!task)
		goto done;

	rc = ISCSI_IO_SUCCESS;
	/*
	 * save the values that get set when we receive an R2T from
	 * the target, so that we can receive another one while
	 * we're sending data.
	 */
	ttt = task->ttt;
	offset = task->data_offset;
	len = task->data_length;
	task->ttt = ISCSI_RSVD_TASK_TAG;
	spin_unlock_bh(&session->task_lock);

	/*
	 * implied initial R2T
	 * (ISCSI_TASK_INITIAL_R2T bit is only accessed by tx
	 * thread so we do not need atomic ops)
	 */
	if (__test_and_clear_bit(ISCSI_TASK_INITIAL_R2T, &task->flags)) {
		sc = task->scsi_cmnd;
		/*
		 * FirstBurstLength == 0 means no limit when
		 * ImmediateData == 0 (not documented in README?)
		 */
		if (!session->first_burst_len)
			implied_len = sc->request_bufflen;
		else
			implied_len = min_t(unsigned, session->first_burst_len,
					    sc->request_bufflen);

		if (session->immediate_data) {
			imm_data_len = get_immediate_data_len(session, sc);
			implied_len -= imm_data_len;
		} else
			imm_data_len = 0;

		rc = iscsi_send_data_out(task, ISCSI_RSVD_TASK_TAG,
					 imm_data_len, implied_len);
	}

	/* normal R2T from the target */
	if (ttt != ISCSI_RSVD_TASK_TAG && rc == ISCSI_IO_SUCCESS)
		iscsi_send_data_out(task, ttt, offset, len);

	spin_lock_bh(&session->task_lock);
	__iscsi_put_task(task);

	if (!signal_pending(current))
		goto retry;
 done:
	spin_unlock_bh(&session->task_lock);
}

/**
 * iscsi_send_scsi_cmnd - Transmit iSCSI Command PDU.
 * @task: iSCSI task to be transmitted
 *
 * Description:
 *     The header digest on the cmd PDU is calculated before sending the cmd.
 *     If ImmediateData is enabled, data digest is computed and data is sent
 *     along with cmd PDU.
 **/
void
iscsi_send_scsi_cmnd(struct iscsi_task *task)
{
	struct iscsi_scsi_cmd_hdr stsch;
	struct iscsi_session *session = task->session;
	struct scsi_cmnd *sc = task->scsi_cmnd;
	int rc, first_sg = 0;
	struct scatterlist tmpsg;
	u32 imm_data_len = 0,  sg_offset = 0;

	memset(&stsch, 0, sizeof(stsch));
	if (test_bit(ISCSI_TASK_READ, &task->flags)) {
		stsch.flags |= ISCSI_FLAG_CMD_READ;
		stsch.data_length = htonl(sc->request_bufflen);
	} else if (test_bit(ISCSI_TASK_WRITE, &task->flags)) {
		stsch.flags |= ISCSI_FLAG_CMD_WRITE;
		stsch.data_length = htonl(sc->request_bufflen);
	}
	/* tagged command queueing */
	stsch.flags |= (iscsi_command_attr(sc) & ISCSI_FLAG_CMD_ATTR_MASK);
	stsch.opcode = ISCSI_OP_SCSI_CMD;
	stsch.itt = htonl(task->itt);
	task->cmdsn = session->cmd_sn;
	stsch.cmdsn = htonl(session->cmd_sn);
	stsch.expstatsn = htonl(session->exp_stat_sn);
	/*
	 * set the final bit when there are no unsolicited Data-out
	 * PDUs following the command PDU
	 */
	if (!test_bit(ISCSI_TASK_INITIAL_R2T, &task->flags))
		stsch.flags |= ISCSI_FLAG_FINAL;
	/* single level LUN format puts LUN in byte 1, 0 everywhere else */
	stsch.lun[1] = sc->device->lun;
	memcpy(stsch.scb, sc->cmnd, min_t(size_t, sizeof(stsch.scb),
					  sc->cmd_len));

	if (session->immediate_data &&
	    sc->sc_data_direction == DMA_TO_DEVICE) {
		if (!sc->request_bufflen)
			/* zero len write? just let it timeout */
			return;

		imm_data_len = get_immediate_data_len(session, sc);
		/* put the data length in the PDU header */
		hton24(stsch.dlength, imm_data_len);
		stsch.data_length = htonl(sc->request_bufflen);
	}

	rc = iscsi_send_header(session, (struct iscsi_hdr *)&stsch,
			       session->header_digest);
	if (rc != ISCSI_IO_SUCCESS) {
		iscsi_host_err(session, "iscsi_send_scsi_cmnd failed to send "
			       "scsi cmnd header\n");
		iscsi_drop_session(session);
		return;
	}

	if (!imm_data_len)
		goto done;

	if (sc->use_sg)
		rc = iscsi_send_sg_data(session, sc->request_buffer,
					&first_sg, &sg_offset, sc->use_sg,
					imm_data_len, session->data_digest);
	else {
		sg_init_one(&tmpsg, sc->request_buffer, sc->bufflen);
		rc = iscsi_send_sg_data(session, &tmpsg, &first_sg,
					&sg_offset, 1, imm_data_len,
					session->data_digest);
	}

	if (rc != ISCSI_IO_SUCCESS) {
		iscsi_host_err(session, "iscsi_send_scsi_cmnd failed to send "
			       "scsi cmnd data (%u bytes)\n", imm_data_len);
		if (rc != ISCSI_IO_INVALID_OP)
			iscsi_drop_session(session);
	}
 done:
	session->cmd_sn++;
}

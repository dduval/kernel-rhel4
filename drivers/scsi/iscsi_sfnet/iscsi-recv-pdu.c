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
 * $Id: iscsi-recv-pdu.c,v 1.1.2.32 2005/03/29 19:35:08 mikenc Exp $
 *
 * All the incoming iSCSI PDUs are processed by functions
 * defined here.
 */
#include <linux/blkdev.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_dbg.h>

#include "iscsi-session.h"
#include "iscsi-task.h"
#include "iscsi-protocol.h"
#include "iscsi-login.h"
#include "iscsi-sfnet.h"

/* possibly update the ExpCmdSN and MaxCmdSN - may acquire task lock */
static void
update_sn(struct iscsi_session *session, u32 expcmdsn, u32 maxcmdsn)
{
	/*
	 * standard specifies this check for when to update expected and
	 * max sequence numbers
	 */
	if (iscsi_sna_lt(maxcmdsn, expcmdsn - 1))
		return;

	if (expcmdsn != session->exp_cmd_sn &&
	    !iscsi_sna_lt(expcmdsn, session->exp_cmd_sn))
		session->exp_cmd_sn = expcmdsn;

	if (maxcmdsn != session->max_cmd_sn &&
	    !iscsi_sna_lt(maxcmdsn, session->max_cmd_sn)) {
		session->max_cmd_sn = maxcmdsn;
		/* wake the tx thread to try sending more commands */
		iscsi_wake_tx_thread(TX_SCSI_COMMAND, session);
	}

	/*
	 * record whether or not the command window for this session
	 * has closed, so that we can ping the target periodically to
	 * ensure we eventually find out that the window has re-opened.
	 */
	if (maxcmdsn == expcmdsn - 1) {
		/*
		 * record how many times this happens, to see
		 * how often we're getting throttled
		 */
		session->window_closed++;
		/*
		 * prepare to poll the target to see if
		 * the window has reopened
		 */
		spin_lock_bh(&session->task_lock);
		iscsi_mod_session_timer(session, 5);
		set_bit(SESSION_WINDOW_CLOSED, &session->control_bits);
		spin_unlock_bh(&session->task_lock);
	} else if (test_bit(SESSION_WINDOW_CLOSED, &session->control_bits))
		clear_bit(SESSION_WINDOW_CLOSED, &session->control_bits);
}

static int
iscsi_recv_header(struct iscsi_session *session, struct iscsi_hdr *sth,
		 int digest)
{
	struct scatterlist sg;
	struct kvec iov[2];
	int length, rc;
	u32 recvd_crc32c, hdr_crc32c;
	u8 iovn = 0;

	iov[iovn].iov_base = sth;
	iov[iovn].iov_len = length = sizeof(*sth);
	iovn++;
	if (digest == ISCSI_DIGEST_CRC32C) {
		iov[iovn].iov_base = &recvd_crc32c;
		iov[iovn].iov_len = sizeof(recvd_crc32c);
		iovn++;
		length += sizeof(recvd_crc32c);
	}

	rc = iscsi_recvmsg(session, iov, iovn, length);
	if (rc != ISCSI_IO_SUCCESS)
		return rc;

	if (digest == ISCSI_DIGEST_CRC32C) {
		crypto_digest_init(session->rx_tfm);
		sg_init_one(&sg, (u8 *)sth, sizeof(*sth));
		crypto_digest_digest(session->rx_tfm, &sg, 1,
				     (u8*)&hdr_crc32c);
		if (recvd_crc32c != hdr_crc32c) {
			iscsi_host_err(session, "HeaderDigest mismatch, "
				       "received 0x%08x, calculated 0x%08x, "
				       "dropping session\n", recvd_crc32c,
				       hdr_crc32c);
			return ISCSI_IO_CRC32C_ERR;
		}
	}

	/* connection is ok */
	session->last_rx = jiffies;

	if (sth->hlength) {
		/*
		 * FIXME: read any additional header segments.
		 * For now, drop the session if one is
		 * received, since we can't handle them.
		 */
		iscsi_host_err(session, "Received opcode %x, ahs length %d, itt"
			       " %u. Dropping, additional header segments not "
			       "supported by this driver version.\n",
			       sth->opcode, sth->hlength, ntohl(sth->itt));
		return ISCSI_IO_ERR;
	}

	return ISCSI_IO_SUCCESS;
}

static void
handle_logout(struct iscsi_session *session, struct iscsi_hdr *sth)
{
	struct iscsi_logout_rsp_hdr *stlh = (struct iscsi_logout_rsp_hdr *)sth;

	update_sn(session, ntohl(stlh->expcmdsn), ntohl(stlh->maxcmdsn));

	if (test_bit(SESSION_IN_LOGOUT, &session->control_bits))
		switch (stlh->response) {
		case ISCSI_LOGOUT_SUCCESS:
			/*
			 * set session's time2wait to zero?
			 * use DefaultTime2Wait?
			 */
			session->time2wait = 0;
			iscsi_host_notice(session, "Session logged out\n");
			break;
		case ISCSI_LOGOUT_CID_NOT_FOUND:
			iscsi_host_err(session, "Session logout failed, cid not"
				       " found\n");
			break;
		case ISCSI_LOGOUT_RECOVERY_UNSUPPORTED:
			iscsi_host_err(session, "Session logout failed, "
				       "connection recovery not supported\n");
			break;
		case ISCSI_LOGOUT_CLEANUP_FAILED:
			iscsi_host_err(session, "Session logout failed, cleanup"
				       " failed\n");
			break;
		default:
			iscsi_host_err(session, "Session logout failed, "
				       "response 0x%x\n", stlh->response);
			break;
		}
	else
		iscsi_host_err(session, "Session received logout response, but "
			       "never sent a login request\n");
	iscsi_drop_session(session);
}

static void
setup_nop_out(struct iscsi_session *session, struct iscsi_nop_in_hdr *stnih)
{
	struct iscsi_nop_info *nop_info;

	/*
	 * we preallocate space for one data-less nop reply in
	 * session structure, to avoid having to invoke kernel
	 * memory allocator in the common case where the target
	 * has at most one outstanding data-less nop reply
	 * requested at any given time.
	 */
	spin_lock_bh(&session->task_lock);
	if (session->nop_reply.ttt == ISCSI_RSVD_TASK_TAG &&
	    list_empty(&session->nop_reply_list))
		nop_info = &session->nop_reply;
	else {
		nop_info = kmalloc(sizeof(*nop_info), GFP_ATOMIC);
		if (!nop_info) {
			spin_unlock_bh(&session->task_lock);
			iscsi_host_warn(session, "Couldn't queue nop reply "
					"for ttt %u ", ntohl(stnih->ttt));
			return;
		}
		list_add_tail(&nop_info->reply_list, &session->nop_reply_list);
	}

	session->nop_reply.ttt = stnih->ttt;
	memcpy(session->nop_reply.lun, stnih->lun,
	       sizeof(session->nop_reply.lun));
	spin_unlock_bh(&session->task_lock);

	iscsi_wake_tx_thread(TX_NOP_REPLY, session);
}

static void
handle_nop_in(struct iscsi_session *session, struct iscsi_hdr *sth)
{
	struct iscsi_nop_in_hdr *stnih = (struct iscsi_nop_in_hdr *)sth;

	update_sn(session, ntohl(stnih->expcmdsn), ntohl(stnih->maxcmdsn));

	if (stnih->itt != ISCSI_RSVD_TASK_TAG)
		/*
		 * we do not send data in our nop-outs, so there
		 * is not much to do right now
		 */

		/*
		 * FIXME: check StatSN
		 */
		session->exp_stat_sn = ntohl(stnih->statsn) + 1;

	/*
	 * check the ttt to decide whether to reply with a Nop-out
	 */
	if (stnih->ttt != ISCSI_RSVD_TASK_TAG)
		setup_nop_out(session, stnih);
}

/**
 * handle_scsi_rsp - Process the SCSI response PDU.
 * @session: Session on which the cmd response is received.
 * @stsrh: SCSI cmd Response header
 * @sense_data: Sense data received for the cmd
 *
 * Description:
 *     Get the task for the SCSI cmd, process the response received and
 *     complete the task.
 **/
static void
handle_scsi_rsp(struct iscsi_session *session, struct iscsi_hdr *sth,
		unsigned char *sense_data)
{
	struct iscsi_scsi_rsp_hdr *stsrh = (struct iscsi_scsi_rsp_hdr *)sth;
	struct iscsi_task *task;
	unsigned int senselen = 0;
	u32 itt = ntohl(stsrh->itt);

	/* FIXME: check StatSN */
	session->exp_stat_sn = ntohl(stsrh->statsn) + 1;
	update_sn(session, ntohl(stsrh->expcmdsn), ntohl(stsrh->maxcmdsn));

	spin_lock_bh(&session->task_lock);
	task = iscsi_find_session_task(session, itt);
	if (!task) {
		iscsi_host_info(session, "recv_cmd - response for itt %u, but "
				"no such task\n", itt);
		spin_unlock_bh(&session->task_lock);
		return;
	}

	/* check for sense data */
	if (ntoh24(stsrh->dlength) > 1) {
		/*
		 * Sense data format per draft-08, 3.4.6.  2-byte sense length,
		 * then sense data, then iSCSI response data
		 */
		senselen = (sense_data[0] << 8) | sense_data[1];
		if (senselen > (ntoh24(stsrh->dlength) - 2))
			senselen = (ntoh24(stsrh->dlength) - 2);
		sense_data += 2;
	}

	iscsi_process_task_response(task, stsrh, sense_data, senselen);
	iscsi_complete_task(task);
	__iscsi_put_task(task);
	spin_unlock_bh(&session->task_lock);
}

static void
handle_r2t(struct iscsi_session *session, struct iscsi_hdr *sth)
{
	struct iscsi_r2t_hdr *strh = (struct iscsi_r2t_hdr *)sth;
	struct iscsi_task *task;
	u32 itt = ntohl(strh->itt);

	update_sn(session, ntohl(strh->expcmdsn), ntohl(strh->maxcmdsn));

	spin_lock_bh(&session->task_lock);

	task = iscsi_find_session_task(session, itt);
	if (!task) {
		/* the task no longer exists */
		iscsi_host_info(session, "ignoring R2T for itt %u, %u bytes @ "
				"offset %u\n", ntohl(strh->itt),
				ntohl(strh->data_length),
				ntohl(strh->data_offset));
		goto done;
	}

	if (!test_bit(ISCSI_TASK_WRITE, &task->flags)) {
		/*
		 * bug in the target.  the command isn't a write,
		 * so we have no data to send
		 */
		iscsi_host_err(session, "Ignoring unexpected R2T for task itt "
			       "%u, %u bytes @ offset %u, ttt %u, not a write "
			       "command\n", ntohl(strh->itt),
			       ntohl(strh->data_length),
			       ntohl(strh->data_offset), ntohl(strh->ttt));
		iscsi_drop_session(session);
	} else if (task->ttt != ISCSI_RSVD_TASK_TAG)
		/*
		 * bug in the target.  MaxOutstandingR2T == 1 should
		 * have prevented this from occuring
		 */
		iscsi_host_warn(session, "Ignoring R2T for task itt %u, %u "
				"bytes @ offset %u, ttt %u, already have R2T "
				"for %u @ %u, ttt %u\n", ntohl(strh->itt),
				ntohl(strh->data_length),
				ntohl(strh->data_offset), ntohl(strh->ttt),
				task->data_length, task->data_offset,
				ntohl(task->ttt));
	else {
		/* record the R2T */
		task->ttt = strh->ttt;
		task->data_length = ntohl(strh->data_length);
		task->data_offset = ntohl(strh->data_offset);
		/*
		 * even if we've issued an abort task set, we need
		 * to respond to R2Ts for this task, though we can
		 * apparently set the F-bit and terminate the data burst
		 * early.  Rather than hope targets handle that
		 * correctly, we just send the data requested as usual.
		 */
		iscsi_queue_r2t(session, task);
		iscsi_wake_tx_thread(TX_DATA, session);
	}

	__iscsi_put_task(task);

 done:
	spin_unlock_bh(&session->task_lock);
}

static int
recv_extra_data(struct iscsi_session *session,  u32 data_len, u32 *recvd_crc32c)
{
	struct scatterlist tmpsg;
	struct kvec iov[2];
	char padding[PAD_WORD_LEN - 1];
	int pad = 0, iovn = 0, len = 0, rc;

	if (data_len % PAD_WORD_LEN) {
		pad = PAD_WORD_LEN - (data_len % PAD_WORD_LEN);
		iov[iovn].iov_base = padding;
		iov[iovn].iov_len = pad;
		iovn++;
		len += pad;
	}

	if (recvd_crc32c) {
		iov[iovn].iov_base = recvd_crc32c;
		iov[iovn].iov_len = sizeof(*recvd_crc32c);
		len += iov[iovn].iov_len;
		iovn++;
	}

	if (iovn) {
		rc = iscsi_recvmsg(session, iov, iovn, len);
		if (rc != ISCSI_IO_SUCCESS)
			return rc;

		if (pad && recvd_crc32c) {
			sg_init_one(&tmpsg, padding, pad);
			crypto_digest_update(session->rx_tfm, &tmpsg, 1);
		}
	}

	return ISCSI_IO_SUCCESS;
}

/**
 * iscsi_recv_sg_data - read the PDU's payload
 * @session: iscsi session
 * @data_len: data length
 * @sglist: data scatterlist
 * @sglist_len: number of sg elements
 * @sg_offset: offset in sglist
 * @digest_opt: CRC32C or NONE
 **/
static int
iscsi_recv_sg_data(struct iscsi_session *session, u32 data_len,
		   struct scatterlist *sglist, int sglist_len,
		   unsigned int sg_offset, int digest_opt)
{
	int i, len, rc = ISCSI_IO_ERR;
	struct scatterlist *sg, tmpsg;
	unsigned int page_offset, remaining, sg_bytes;
	struct page *p;
	void *page_addr;
	struct kvec iov;
	u32 recvd_crc32c, data_crc32c;

	remaining = data_len;

	if (digest_opt == ISCSI_DIGEST_CRC32C)
		crypto_digest_init(session->rx_tfm);
	/*
	 * Read in the data for each sg in PDU
	 */
	for (i = 0; remaining > 0 && i < sglist_len; i++) {
		/*
		 * Find the right sg entry first
		 */
		if (sg_offset >= sglist[i].length) {
			sg_offset -= sglist[i].length;
			continue;
		}
		sg = &sglist[i];

		/*
		 * Find page corresponding to segment offset first
		 */
		page_offset = sg->offset + sg_offset;
		p = sg->page + (page_offset >> PAGE_SHIFT);
		page_offset -= (page_offset & PAGE_MASK);
		/*
		 * yuck, for each page in sg (can't pass a sg with its
		 * pages mapped to kernel_recvmsg in one iov entry and must
		 * use one iov entry for each PAGE when using highmem???????)
		 */
		sg_bytes = min(remaining, sg->length - sg_offset);
		remaining -= sg_bytes;
		for (; sg_bytes > 0; sg_bytes -= len) {
			page_addr = kmap(p);
			if (!page_addr) {
				iscsi_host_err(session, "recv_sg_data kmap "
					       "failed to map page in sg %p\n",
					       sg);
				goto error_exit;
			}
		
			iov.iov_base = page_addr + page_offset;
			iov.iov_len = min_t(unsigned int, sg_bytes,
					    PAGE_SIZE - page_offset);
			len = iov.iov_len;
			/*
			 * is it better to do one call with all the pages
			 * setup or multiple calls?
			 */
			rc = iscsi_recvmsg(session, &iov, 1, len);
			kunmap(p);
			if (rc != ISCSI_IO_SUCCESS)
				goto error_exit;

			/* crypto_digest_update will kmap itself */
			if (digest_opt == ISCSI_DIGEST_CRC32C) {
				tmpsg.page = p;
				tmpsg.offset = page_offset;
				tmpsg.length = len;
				crypto_digest_update(session->rx_tfm, &tmpsg,
						     1);
			}

			p++;
			page_offset = 0;
		}

		sg_offset = 0;
	}

	if (remaining != 0) {
		/* Maybe this should be a BUG? */
		iscsi_host_err(session, "recv_sg_data - invalid sglist for "
			       "offset %u len %u, remaining data %u, sglist "
			       "size %d, dropping session\n", sg_offset,
			       data_len, remaining, sglist_len);
		goto error_exit;
	}

	rc = recv_extra_data(session, data_len, digest_opt ==
			     ISCSI_DIGEST_CRC32C ? &recvd_crc32c : NULL);
	if (rc != ISCSI_IO_SUCCESS)  
		goto error_exit;

	if (digest_opt == ISCSI_DIGEST_CRC32C) {
		crypto_digest_final(session->rx_tfm, (u8*)&data_crc32c);
		if (data_crc32c != recvd_crc32c) {
			iscsi_host_err(session, "DataDigest mismatch, received "
				       "0x%08x, calculated 0x%08x\n",
				       recvd_crc32c, data_crc32c);
			return ISCSI_IO_CRC32C_ERR;
		}
	}

	/* connection is ok */
	session->last_rx = jiffies;
	return rc;

 error_exit:
	/* FIXME: we could discard the data or drop the session */
	return rc;
}

/*
 * Only call this from recvs where the rx_buffer is not in
 * use. We don't bother checking the CRC, since we couldn't
 * retry the command anyway
 */
static void
drop_data(struct iscsi_session *session, struct iscsi_hdr *sth)
{
	int pad, length, num_bytes;
	struct kvec iov;

	length = ntoh24(sth->dlength);

	pad = length % PAD_WORD_LEN;
	if (pad)
		pad = PAD_WORD_LEN - pad;
	length += pad;

	if (session->data_digest == ISCSI_DIGEST_CRC32C) {
		iscsi_host_info(session, "recv_data discarding %d data PDU "
				"bytes, %d pad bytes, %Zu digest bytes\n",
				ntoh24(sth->dlength), pad, sizeof(u32));
		length += sizeof(u32);
	} else
		iscsi_host_info(session, "recv_data discarding %d data PDU "
				"bytes, %d pad bytes\n", ntoh24(sth->dlength),
				pad);

	while (!signal_pending(current) && length > 0) {
		num_bytes = min_t(int, length, sizeof(session->rx_buffer));
		iov.iov_base = session->rx_buffer;
		iov.iov_len = sizeof(session->rx_buffer);
		/* should iov_len match num_bytes ? */
		if (iscsi_recvmsg(session, &iov, 1, num_bytes) !=
		    ISCSI_IO_SUCCESS) {
			iscsi_drop_session(session);
			break;
		}
		/* assume a PDU round-trip, connection is ok */
		session->last_rx = jiffies;
		length -= num_bytes;
	}
}

static void
handle_scsi_data(struct iscsi_session *session, struct iscsi_hdr *sth)
{
	struct iscsi_data_rsp_hdr *stdrh = (struct iscsi_data_rsp_hdr *)sth;
	struct iscsi_task *task;
	struct scsi_cmnd *sc;
	struct scatterlist sg;
	int dlength, offset, rc;
	u32 itt = ntohl(stdrh->itt);

	if (stdrh->flags & ISCSI_FLAG_DATA_STATUS)
		/* FIXME: check StatSN */
		session->exp_stat_sn = ntohl(stdrh->statsn) + 1;

	update_sn(session, ntohl(stdrh->expcmdsn), ntohl(stdrh->maxcmdsn));

	dlength = ntoh24(stdrh->dlength);
	offset = ntohl(stdrh->offset);

	spin_lock_bh(&session->task_lock);

	task = iscsi_find_session_task(session, itt);
	if (!task) {
		iscsi_host_warn(session, "recv_data, no task for itt %u next "
				"itt %u, discarding received data, offset %u "
				"len %u\n", ntohl(stdrh->itt),
				session->next_itt, offset, dlength);
		spin_unlock_bh(&session->task_lock);
		drop_data(session, sth);
		return;
	}
	sc = task->scsi_cmnd;

	/* sanity check the PDU against the command */
	if (!test_bit(ISCSI_TASK_READ, &task->flags)) {
		iscsi_host_err(session, "lun%u: recv_data itt %u, command "
			       "cdb 0x%02x, dropping session due to "
			       "unexpected Data-in from\n", task->lun, itt,
			       sc->cmnd[0]);
		iscsi_drop_session(session);
		goto done;
	} else if ((offset + dlength) > sc->request_bufflen) {
		/* buffer overflow, often because of a corrupt PDU header */
		iscsi_host_err(session, "recv_data for itt %u, cmnd 0x%x, "
			       "bufflen %u, Data PDU with offset %u len %u "
			       "overflows command buffer, dropping session\n",
			       itt, sc->cmnd[0], sc->request_bufflen, offset,
			       dlength);
		iscsi_drop_session(session);
		goto done;
	} else if (task->rxdata != offset) {
		/*	
		 * if the data arrives out-of-order, it becomes much harder
		 * for us to correctly calculate the residual if we don't get
		 * enough data and also don't get an underflow from the
		 * target.  This can happen if we discard Data PDUs due to
		 * bogus offsets/lengths.  Since we always negotiate for
		 * Data PDUs in-order, this should never happen, but check
		 * for it anyway.
		 */
		iscsi_host_err(session, "recv_data for itt %u, cmnd 0x%x, "
			       "bufflen %u, offset %u does not match expected "
			       "offset %u, dropping session\n", itt,
			       sc->cmnd[0], sc->request_bufflen, offset,
			       task->rxdata);
		iscsi_drop_session(session);
		goto done;
	}

	/*
	 * either we'll read it all, or we'll drop the session and requeue
	 * the command, so it's safe to increment early
	 */
	task->rxdata += dlength;
	spin_unlock_bh(&session->task_lock);

	if (sc->use_sg)
		rc = iscsi_recv_sg_data(session, dlength, sc->request_buffer,
					sc->use_sg, offset,
					session->data_digest);
	else {
		sg_init_one(&sg, sc->request_buffer, dlength);
		rc = iscsi_recv_sg_data(session, dlength, &sg, 1, offset,
					session->data_digest);
	}

	spin_lock_bh(&session->task_lock);

	switch (rc) {
	case ISCSI_IO_ERR:
		iscsi_drop_session(session);
		break;
	case ISCSI_IO_CRC32C_ERR:
		__set_bit(ISCSI_TASK_CRC_ERROR, &task->flags);
		/* fall through */
	case ISCSI_IO_SUCCESS:
		if (stdrh->flags & ISCSI_FLAG_DATA_STATUS) {
			iscsi_process_task_status(task, sth);
			iscsi_complete_task(task);
		}
	}

 done:
	__iscsi_put_task(task);
	spin_unlock_bh(&session->task_lock);
}

/**
 * handle_task_mgmt_rsp - Process the task management response.
 * @session: to retrieve the task
 * @ststmrh: task management response header
 *
 * Description:
 *     Retrieve the task for which task mgmt response is received and take
 *     appropriate action based on the type of task management request.
 **/
static void
handle_task_mgmt_rsp(struct iscsi_session *session, struct iscsi_hdr *sth)
{
	struct iscsi_scsi_task_mgmt_rsp_hdr *ststmrh;
	struct iscsi_task *task;
	u32 mgmt_itt;

	ststmrh = (struct iscsi_scsi_task_mgmt_rsp_hdr *)sth;
	mgmt_itt = ntohl(ststmrh->itt);

	/* FIXME: check StatSN */
	session->exp_stat_sn = ntohl(ststmrh->statsn) + 1;
	update_sn(session, ntohl(ststmrh->expcmdsn), ntohl(ststmrh->maxcmdsn));

	spin_lock_bh(&session->task_lock);
	/*
	 * This can fail if they timedout and we escalated the recovery
	 * to a new function
	 */
	task = iscsi_find_session_task(session, mgmt_itt);
	if (!task) {
		iscsi_host_warn(session, "mgmt response 0x%x for unknown itt "
				"%u, rtt %u\n", ststmrh->response,
				ntohl(ststmrh->itt), ntohl(ststmrh->rtt));
		goto done;
	}

	if (ststmrh->response == 0) {
		iscsi_host_info(task->session, "task mgmt itt %u "
				"successful\n", mgmt_itt);
		iscsi_complete_tmf_task(task, ISCSI_TASK_TMF_SUCCESS);
	} else {
		iscsi_host_err(task->session, "task mgmt itt %u rejected"
			       " (0x%x)\n", mgmt_itt, ststmrh->response);
		iscsi_complete_tmf_task(task, ISCSI_TASK_TMF_FAILED);
	}
	__iscsi_put_task(task);	

 done:
	/*
	 * we got the expected response, allow the eh thread to send
	 * another task mgmt PDU whenever it wants to
	 */
	if (session->last_mgmt_itt == mgmt_itt)
		session->last_mgmt_itt = ISCSI_RSVD_TASK_TAG;

	spin_unlock_bh(&session->task_lock);
}

static void
process_immed_cmd_reject(struct iscsi_session *session, unsigned char *xbuf,
			 int dlength)
{
	u32 itt;
	struct iscsi_task *task;
	struct iscsi_hdr pdu;

	if (dlength < sizeof(pdu)) {
		iscsi_host_warn(session, "Immediate command rejected, dlength "
				"%u\n", dlength);
		return;
	}

	/* look at the rejected PDU */
	memcpy(&pdu, xbuf, sizeof(pdu));
	itt = ntohl(pdu.itt);

	/*
	 * try to find the task corresponding to this itt,
	 * and wake up any process waiting on it
	 */
	spin_lock_bh(&session->task_lock);

	if (session->last_mgmt_itt == itt)
		session->last_mgmt_itt = ISCSI_RSVD_TASK_TAG;

	task = iscsi_find_session_task(session, itt);
	if (task) {
		iscsi_host_notice(session, "task mgmt PDU rejected, mgmt %u, "
				  "itt %u\n", itt, task->itt);
		iscsi_complete_tmf_task(task, ISCSI_TASK_IMM_REJECT);
		__iscsi_put_task(task);
	} else if ((pdu.opcode & ISCSI_OPCODE_MASK) == ISCSI_OP_LOGOUT_CMD)
		/*
		 * our Logout was rejected.  just let the
		 * logout response timer drop the session
		 */
		iscsi_host_warn(session, "Logout PDU rejected, itt %u\n", itt);
	else
		iscsi_host_warn(session, "itt %u immediate command rejected\n",
				itt);

	spin_unlock_bh(&session->task_lock);
}

static void
handle_reject(struct iscsi_session *session, struct iscsi_hdr *sth,
	      unsigned char *xbuf)
{
	struct iscsi_reject_hdr *reject;
	struct iscsi_hdr pdu;
	int dlength;
	u32 itt;

	reject = (struct iscsi_reject_hdr *)sth;
	dlength = ntoh24(reject->dlength);

	/* FIXME: check StatSN */
	session->exp_stat_sn = ntohl(reject->statsn) + 1;
	update_sn(session, ntohl(reject->expcmdsn), ntohl(reject->maxcmdsn));

	if (reject->reason == ISCSI_REJECT_DATA_DIGEST_ERROR) {
		/*
		 * we don't need to do anything about these,
		 * timers or other PDUs will handle the problem.
		 */
		if (dlength >= sizeof(pdu)) {
			memcpy(&pdu, xbuf, sizeof(pdu));
			itt = ntohl(pdu.itt);
			iscsi_host_warn(session, "itt %u (opcode 0x%x) rejected"
					" because of a DataDigest error\n", itt,
					pdu.opcode);
		} else
			iscsi_host_warn(session, "Target rejected a PDU because"
					" of a DataDigest error\n");
	} else if (reject->reason == ISCSI_REJECT_IMM_CMD_REJECT)
		process_immed_cmd_reject(session, xbuf, dlength);
	else {
		if (dlength >= sizeof(pdu)) {
			/* look at the rejected PDU */
			memcpy(&pdu, xbuf, sizeof(pdu));
			itt = ntohl(pdu.itt);
			iscsi_host_err(session, "Dropping session because "
				       "target rejected a PDU, reason 0x%x, "
				       "dlength %d, rejected itt %u, opcode "
				       "0x%x\n", reject->reason, dlength, itt,
				       pdu.opcode);
		} else
			iscsi_host_err(session, "Dropping session because "
				       "target rejected a PDU, reason 0x%x, "
				       "dlength %u\n", reject->reason, dlength);
		iscsi_drop_session(session);
	}
}

static void
handle_async_msg(struct iscsi_session *session, struct iscsi_hdr *sth,
		 unsigned char *xbuf)
{
	struct iscsi_async_msg_hdr *staeh = (struct iscsi_async_msg_hdr *)sth;
	unsigned int senselen;

	/* FIXME: check StatSN */
	session->exp_stat_sn = ntohl(staeh->statsn) + 1;
	update_sn(session, ntohl(staeh->expcmdsn), ntohl(staeh->maxcmdsn));

	switch (staeh->async_event) {
	case ISCSI_ASYNC_MSG_SCSI_EVENT:
		senselen = (xbuf[0] << 8) | xbuf[1];
		xbuf += 2;

		iscsi_host_info(session, "Received async SCSI event. Printing "
				"sense\n");
/*
		remove for 2.6.11
		__scsi_print_sense(ISCSI_PROC_NAME, xbuf, senselen);
*/
		break;
	case ISCSI_ASYNC_MSG_REQUEST_LOGOUT:
		/*
		 * FIXME: this is really a request to drop a connection,
		 * not the whole session, but we currently only have one
		 * connection per session, so there's no difference
		 * at the moment.
		 */
		iscsi_host_warn(session, "Target requests logout within %u "
				"seconds for session\n", ntohs(staeh->param3));
		/*
		 * we need to get the task lock to make sure the TX thread
		 * isn't in the middle of adding another task to the session.
		 */
		spin_lock_bh(&session->task_lock);
		iscsi_request_logout(session, ntohs(staeh->param3) - (HZ / 10),
				     session->active_timeout);
		spin_unlock_bh(&session->task_lock);
		break;
	case ISCSI_ASYNC_MSG_DROPPING_CONNECTION:
		iscsi_host_warn(session, "Target dropping connection %u, "
				"reconnect min %u max %u\n",
				ntohs(staeh->param1), ntohs(staeh->param2),
				ntohs(staeh->param3));
		session->time2wait = (long) ntohs(staeh->param2) & 0x0000FFFFFL;
		break;
	case ISCSI_ASYNC_MSG_DROPPING_ALL_CONNECTIONS:
		iscsi_host_warn(session, "Target dropping all connections, "
				"reconnect min %u max %u\n",
				ntohs(staeh->param2), ntohs(staeh->param3));
		session->time2wait = (long) ntohs(staeh->param2) & 0x0000FFFFFL;
		break;
	case ISCSI_ASYNC_MSG_VENDOR_SPECIFIC:
		iscsi_host_warn(session, "Ignoring vendor-specific async event,"
				" vcode 0x%x\n", staeh->async_vcode);
		break;
	case ISCSI_ASYNC_MSG_PARAM_NEGOTIATION:
		iscsi_host_warn(session, "Received async event param "
				"negotiation, dropping session\n");
		iscsi_drop_session(session);
		break;
	default:
		iscsi_host_err(session, "Received unknown async event 0x%x\n",
			       staeh->async_event);
		break;
	}
	if (staeh->async_event == ISCSI_ASYNC_MSG_DROPPING_CONNECTION ||
	    staeh->async_event == ISCSI_ASYNC_MSG_DROPPING_ALL_CONNECTIONS ||
	    staeh->async_event == ISCSI_ASYNC_MSG_REQUEST_LOGOUT) {
		spin_lock(&session->portal_lock);
		memcpy(&session->addr, &session->portal.addr,
		       sizeof(struct sockaddr));
		spin_unlock(&session->portal_lock);
	}
}

/**
 * iscsi_recv_pdu - Read in a iSCSI PDU
 * @session: iscsi session structure
 * @hdr: a iSCSI PDU header
 * @hdr_digest: digest type for header
 * @data: buffer for data
 * @max_data_len: buffer size
 * @data_digest: digest type for data
 *
 * Description:
 *    Reads a iSCSI PDU into memory. Excpet for login PDUs, this function
 *    will also process the PDU.
 **/
int
iscsi_recv_pdu(struct iscsi_session *session, struct iscsi_hdr *hdr,
	       int hdr_digest, char *data, int max_data_len, int data_digest)
{
	int rc;
	int data_len;
	struct scatterlist sg;
	u8 opcode;

	if (iscsi_recv_header(session, hdr, hdr_digest) != ISCSI_IO_SUCCESS)
		goto fail;

	data_len = ntoh24(hdr->dlength);
	opcode = hdr->opcode & ISCSI_OPCODE_MASK;

	/*
	 * scsi data is read in and processed by its handler for now
	 */
	if (data_len && opcode != ISCSI_OP_SCSI_DATA_RSP) {
        	if (data_len > max_data_len) {
                	iscsi_host_err(session, "iscsi_recv_pdu() cannot read "
				       "%d bytes of PDU data, only %d bytes "
				       "of buffer available\n", data_len,
				       max_data_len);
			goto fail;
        	}

		/*
		 * must clear this, beucase the login api uses the same
		 * buffer for recv and send
		 */
		memset(data, 0, max_data_len);
		sg_init_one(&sg, data, data_len);
		rc = iscsi_recv_sg_data(session, data_len, &sg, 1, 0,
					data_digest);
		if (rc == ISCSI_IO_CRC32C_ERR) {
			switch (opcode) {
			case ISCSI_OP_ASYNC_MSG:
			case ISCSI_OP_REJECT:
				/* unsolicited so ignore */
				goto done;
			default:
				goto fail;
			};
		} else if (rc != ISCSI_IO_SUCCESS)
			goto fail;
	}

	switch (opcode) {
	case ISCSI_OP_NOOP_IN:
		handle_nop_in(session, hdr);
		break;
	case ISCSI_OP_SCSI_RSP:
		handle_scsi_rsp(session, hdr, data);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
		handle_task_mgmt_rsp(session, hdr);
		break;
	case ISCSI_OP_R2T:
		handle_r2t(session, hdr);
		break;
	case ISCSI_OP_SCSI_DATA_RSP:
		handle_scsi_data(session, hdr);
		break;
	case ISCSI_OP_ASYNC_MSG:
		handle_async_msg(session, hdr, data);
		break;
	case ISCSI_OP_REJECT:
	        handle_reject(session, hdr, data);
		break;
	case ISCSI_OP_LOGOUT_RSP:
		handle_logout(session, hdr);
		break;
	case ISCSI_OP_LOGIN_RSP:
		/*
		 * The login api needs the buffer to be cleared when no
		 * data has been read
		 */
		if (!data_len)
			memset(data, 0, max_data_len);	
		/*
		 * login api will process further
		 */
		break;
	default:
		iscsi_host_err(session, "Dropping session after receiving "
			       "unexpected opcode 0x%x\n", opcode);
		session->time2wait = 2;
		goto fail;
	}

 done:
	return 1;
 fail:
	iscsi_drop_session(session);
	return 0;
}

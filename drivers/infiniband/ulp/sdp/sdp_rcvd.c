/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id: sdp_rcvd.c 3079 2005-08-14 13:37:59Z mst $
 */

#include "sdp_main.h"

/*
 * Specific MID handler functions. (RECV)
 */
static int sdp_rcvd_disconnect(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct sock *sk;
	int result = 0;
	int band;

	sdp_dbg_ctrl(conn, "Disconnect msg received.");

	switch (conn->state) {
	case SDP_CONN_ST_ESTABLISHED:
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_DIS_RECV_1);
		band = POLL_IN;
		break;
	case SDP_CONN_ST_DIS_SEND_1:
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_DIS_RECV_R);
		band = POLL_HUP;
		break;
	case SDP_CONN_ST_DIS_SENT_1:
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_TIME_WAIT_1);
		band = POLL_HUP;
		/*
		 * Begin IB/CM disconnect
		 */
		result = ib_send_cm_dreq(conn->cm_id, NULL, 0);
		/*
		 * if the remote DREQ was already received, but unprocessed,
		 * do not treat it as an error
		 */
		if (result) {
			sdp_dbg_warn(conn, "Error <%d> sending CM DREQ",
				     result);

			if (result != -EPROTO)
				goto error;
		}

		break;
	default:
		sdp_warn("Disconnect rcvd, unexpected state. <%d> <%04x>",
			 conn->hashent, conn->state);
		result = -EPROTO;
		goto error;
		break;
	}

	conn->shutdown |= RCV_SHUTDOWN;
	/*
	 * cancel all outstanding read AIO's since there will be
	 * no more data from the peer.
	 */
	sdp_iocb_q_cancel_all_read(conn, 0);
	/*
	 * async notification. POLL_HUP on full duplex close only.
	 */

	sk = sk_sdp(conn);
	sk->sk_state_change(sk);
	sk_wake_async(sk, 1, band);

	return 0;
error:
	return result;
}

static int sdp_rcvd_abort(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	int result = 0;

	sdp_dbg_ctrl(conn, "Abort msg received.");
	/*
	 * Connection should be in some post DisConn recveived state.
	 */
	switch (conn->state) {
	case SDP_CONN_ST_DIS_RECV_1:
	case SDP_CONN_ST_DIS_RECV_R:
	case SDP_CONN_ST_DIS_SEND_2:

		sdp_conn_abort(conn);
		break;
	default:
		sdp_warn("Unexpected abort. conn <%d> state <%04x>",
			 conn->hashent, conn->state);
		result = -EPROTO;
	}

	return result;
}

static int sdp_rcvd_send_sm(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct sdpc_iocb *iocb;

	/*
	 * 1) Conn is not in source cancel mode. Send active IOCB
	 *    using buffered mode
	 * 2) Conn is in source cancel, and this message acks the cancel.
	 *    Release all active IOCBs in the source queue.
	 * 3) Conn is in source cancel, but this message doesn't ack the
	 *    cancel.
	 *
	 *    Do nothing, can't send since the IOCB is being cancelled, but
	 *    cannot release the IOCB since the cancel has yet to be ack'd
	 */
	sdp_dbg_ctrl(conn, "SendSM msg. active <%d> count <%d> flags <%08x>",
		     conn->src_sent, conn->src_cncl, conn->flags);

	if ((conn->flags & SDP_CONN_F_SRC_CANCEL_L) &&
	    SDP_WRAP_GTE(buff->bsdh_hdr->seq_ack, conn->src_cseq)) {
		/*
		 * drain the active source queue
		 */
		while ((iocb = sdp_iocb_q_get_tail(&conn->w_src))) {
			SDP_EXPECT((iocb->flags & SDP_IOCB_F_ACTIVE));
			SDP_EXPECT((iocb->flags & SDP_IOCB_F_CANCEL));

			conn->src_sent--;

			sdp_iocb_complete(iocb, 0);
		}
		/*
		 * Cancel complete, clear the state.
		 */
		conn->src_cncl = 0;
		conn->flags &= ~(SDP_CONN_F_SRC_CANCEL_L);
	}

	return 0;
}

static int sdp_rcvd_rdma_wr(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct msg_hdr_rwch *rwch;
	struct sdpc_iocb *iocb;

	rwch = (struct msg_hdr_rwch *) buff->data;
	buff->data = buff->data + sizeof(struct msg_hdr_rwch);

	sdp_msg_net_to_cpu_rwch(rwch);
	/*
	 * lookup active IOCB read.
	 */
	iocb = sdp_iocb_q_look(&conn->r_snk);
	if (!iocb) {
		sdp_dbg_warn(conn, "Cannot find IOCB for Write Completion.");
		return -EPROTO;
	}

	SDP_EXPECT((iocb->flags & SDP_IOCB_F_RDMA_W));

	sdp_dbg_data(conn, "Write <%d> size <%d:%d:%Zu> mode <%d> active <%d>",
		     iocb->key, rwch->size, iocb->len, iocb->size,
		     conn->recv_mode, conn->snk_sent);
	/*
	 * update IOCB
	 */
	if (rwch->size > iocb->len) {
		sdp_dbg_warn(conn, "IOCB and Write size mismatch. <%d:%d>",
			     rwch->size, iocb->len);
		return -EPROTO;
	}
	/*
	 * Iocb is done, deregister memory, and generate completion.
	 */
	iocb = sdp_iocb_q_get_head(&conn->r_snk);

	iocb->len -= rwch->size;
	iocb->post += rwch->size;

	SDP_CONN_STAT_SNK_INC(conn);
	SDP_CONN_STAT_READ_INC(conn, iocb->post);
	SDP_CONN_STAT_RQ_DEC(conn, iocb->size);

	conn->snk_sent--;

	sdp_iocb_complete(iocb, 0);

	return 0;
}

static int sdp_rcvd_rdma_rd(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct msg_hdr_rrch *rrch;
	struct sdpc_iocb *iocb;

	rrch = (struct msg_hdr_rrch *) buff->data;
	buff->data = buff->data + sizeof(struct msg_hdr_rrch);

	sdp_msg_net_to_cpu_rrch(rrch);
	/*
	 * lookup IOCB read.
	 */
	iocb = sdp_iocb_q_look(&conn->w_src);
	if (!iocb) {
		sdp_dbg_warn(conn, "Cannot find IOCB for Read Completion.");
		return -EPROTO;
	}

	SDP_CONN_STAT_SRC_INC(conn);

	sdp_dbg_data(conn, "Read <%d> size <%d:%d:%Zu> mode <%d> active <%d>",
		     iocb->key, rrch->size, iocb->len, iocb->size,
		     conn->recv_mode, conn->src_sent);
	/*
	 * update IOCB
	 */
	if (rrch->size > iocb->len) {
		sdp_dbg_warn(conn, "IOCB and Read size mismatch. <%d:%d>",
			     rrch->size, iocb->len);
		return -EPROTO;
	}
	/*
	 * In combined mode the total RDMA size is going to be the buffer
	 * size minus the size sent in the SrcAvail. We could fix up the
	 * iocb->post in the SrcAvailSend function, but it's better to do
	 * it on the first successful RDMA to make sure we don't get a
	 * false positive of data sent. (specification ambiguity/pain)
	 */
	iocb->post += iocb->post ? 0 : (iocb->size - iocb->len);
	iocb->len -= rrch->size;
	iocb->post += rrch->size;

	conn->send_pipe -= rrch->size;
	conn->oob_offset -= (conn->oob_offset > 0) ? rrch->size : 0;

	/*
	 * If iocb is done, deregister memory, and generate completion.
	 */
	if (iocb->len <= 0) {
		iocb = sdp_iocb_q_get_head(&conn->w_src);

		conn->src_sent--;

		SDP_CONN_STAT_WRITE_INC(conn, iocb->post);
		SDP_CONN_STAT_WQ_DEC(conn, iocb->size);

		sdp_iocb_complete(iocb, 0);
	}
	/*
	 * If Source Cancel was in process, and there are no more outstanding
	 * advertisments, then it should now be cleared.
	 */
	if ((conn->flags & SDP_CONN_F_SRC_CANCEL_L) &&
	    !sdp_iocb_q_size(&conn->w_src)) {
		conn->src_cncl = 0;
		conn->flags &= ~(SDP_CONN_F_SRC_CANCEL_L);
	}

	return 0;
}

static int sdp_rcvd_mode_change(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct msg_hdr_mch *mch;
	int result;

	mch = (struct msg_hdr_mch *) buff->data;
	buff->data = buff->data + sizeof(struct msg_hdr_mch);

	sdp_msg_net_to_cpu_mch(mch);

	sdp_dbg_ctrl(conn, "Mode request <%d> from current mode. <%d:%d>",
		     SDP_MSG_MCH_GET_MODE(mch), conn->recv_mode,
		     conn->send_mode);
	/*
	 * Check if the mode change is to the same mode.
	 */
	if (((SDP_MSG_MCH_GET_MODE(mch) & 0x7) ==
	     ((SDP_MSG_MCH_GET_MODE(mch) & 0x8) ?
	      conn->send_mode : conn->recv_mode))) {
		sdp_dbg_warn(conn, "Mode transition <%d> is a nop. <%d:%d>",
			     SDP_MSG_MCH_GET_MODE(mch), conn->recv_mode,
			     conn->send_mode);
		result = -EPROTO;
		goto error;
	}
	/*
	 * process mode change requests based on which state we're in
	 */
	switch (SDP_MSG_MCH_GET_MODE(mch)) {
	case SDP_MSG_MCH_BUFF_RECV:	/* source to sink */
		if (conn->recv_mode != SDP_MODE_COMB) {
			result = -EPROTO;
			goto mode_error;
		}

		if (conn->src_recv > 0) {
			sdp_dbg_warn(conn, "mode error <%d> src pending <%d>",
				     SDP_MSG_MCH_GET_MODE(mch),
				     conn->src_recv);
			result = -EPROTO;
			goto error;
		}

		break;
	case SDP_MSG_MCH_COMB_SEND:	/* sink to source */
		if (conn->send_mode != SDP_MODE_BUFF) {
			result = -EPROTO;
			goto mode_error;
		}

		break;
	case SDP_MSG_MCH_PIPE_RECV:	/* source to sink */
		if (conn->recv_mode != SDP_MODE_COMB) {
			result = -EPROTO;
			goto mode_error;
		}

		break;
	case SDP_MSG_MCH_COMB_RECV:	/* source to sink */
		if (conn->recv_mode != SDP_MODE_PIPE) {
			result = -EPROTO;
			goto mode_error;
		}

		/* if */
		/*
		 * drop all srcAvail message, they will be reissued, with
		 * combined mode constraints. No snkAvails outstanding on
		 * this half of the connection. How do I know which srcAvail
		 * RDMA's completed?
		 */
		break;
	default:
		sdp_dbg_warn(conn, "Invalid mode transition <%d> requested.",
			     SDP_MSG_MCH_GET_MODE(mch));
		result = -EPROTO;
		goto error;
	}
	/*
	 * assign new mode
	 */
	if (SDP_MSG_MCH_GET_MODE(mch) & 0x8)
		conn->send_mode = SDP_MSG_MCH_GET_MODE(mch) & 0x7;
	else
		conn->recv_mode = SDP_MSG_MCH_GET_MODE(mch) & 0x7;

	return 0;

mode_error:
	sdp_dbg_warn(conn, "Invalid mode <%d:%d> transition request <%d>",
		     conn->recv_mode, conn->send_mode,
		     SDP_MSG_MCH_GET_MODE(mch));
error:
	return result;
}

static int sdp_rcvd_src_cancel(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct sdpc_advt *advt;
	int result;

	sdp_dbg_ctrl(conn, "Source Cancel. active <%d> pending <%d> mode <%d>",
		     sdp_advt_q_size(&conn->src_actv),
		     sdp_advt_q_size(&conn->src_pend), conn->send_mode);
	/*
	 * If there are no outstanding advertisments, then there is nothing
	 * to do.
	 */
	if (conn->src_recv <= 0) {
		sdp_dbg_warn(conn, "No SrcAvail advertisments to cancel.");
		result = 0;
		goto done;
	}
	/*
	 * Get and terminate the remainder of the oldest advertisment, only
	 * if it's already processed data.
	 */
	advt = sdp_advt_q_look(&conn->src_pend);
	if (advt && advt->post > 0) {
		/*
		 * If active, move to the active queue. Otherwise generate an
		 * immediate completion
		 */
		if (advt->flag & SDP_ADVT_F_READ) {

			sdp_advt_q_put(&conn->src_actv,
				       sdp_advt_q_get(&conn->src_pend));
			/*
			 * keep track of cancellations
			 */
			conn->flags |= SDP_CONN_F_SRC_CANCEL_C;
		} else {
			result = sdp_send_ctrl_rdma_rd(conn, advt->post);
			if (result < 0) {
				sdp_dbg_warn(conn,
					     "Error <%d> read completion",
					     result);
				goto done;
			}
		}
	}
	/*
	 * drop the pending advertisment queue.
	 */
	while ((advt = sdp_advt_q_get(&conn->src_pend))) {
		conn->flags |= SDP_CONN_F_SRC_CANCEL_C;

		conn->src_recv--;

		sdp_advt_destroy(advt);
	}
	/*
	 * If there are active reads, mark the connection as being in
	 * source cancel. Otherwise
	 */
	if (sdp_advt_q_size(&conn->src_actv) > 0) {
		/*
		 * Set flag. Adjust sequence number ack. (spec dosn't want the
		 * seq ack in subsequent messages updated until the cancel has
		 * been processed. all would be simpler with an explicit cancel
		 * ack, but...)
		 */
		conn->flags |= SDP_CONN_F_SRC_CANCEL_R;
		conn->advt_seq--;
	} else {
		/*
		 * If a source was dropped, generate an ack.
		 */
		if (conn->flags & SDP_CONN_F_SRC_CANCEL_C) {
			result = sdp_send_ctrl_send_sm(conn);
			if (result < 0) {
				sdp_dbg_warn(conn, "Error<%d> posting SendSm",
					     result);
				goto done;
			}

			conn->flags &= ~SDP_CONN_F_SRC_CANCEL_C;
		}
	}

	return 0;
done:
	return result;
}

static int sdp_rcvd_snk_cancel(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct sdpc_advt *advt;
	s32 counter;
	int result;

	sdp_dbg_ctrl(conn, "Sink Cancel. active <%d> mode <%d>",
		     conn->snk_recv, conn->send_mode);
	/*
	 * If there are no outstanding advertisments, they we've completed
	 * since the message was sent, and there is nothing to do.
	 */
	if (conn->snk_recv <= 0) {
		sdp_dbg_warn(conn, "No SnkAvail advertisments to cancel.");
		result = 0;
		goto done;
	}
	/*
	 * Get the oldest advertisment, and complete it if it's partially
	 * consumed. Throw away all unprocessed advertisments, and ack
	 * the cancel. Since all the active writes and sends are fenced,
	 * it's possible to handle the entire Cancel here.
	 */
	advt = sdp_advt_q_look(&conn->snk_pend);
	if (advt && advt->post > 0) {
		/*
		 * Generate completion
		 */
		result = sdp_send_ctrl_rdma_wr(conn, advt->post);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> write completion",
				     result);
			goto done;
		}
		/*
		 * reduce cancel counter
		 */
		counter = -1;
	} else
		/*
		 * cancel count.
		 */
		counter = 0;
	/*
	 * drain the advertisments which have yet to be processed.
	 */
	while ((advt = sdp_advt_q_get(&conn->snk_pend))) {
		counter++;
		conn->snk_recv--;

		sdp_advt_destroy(advt);
	}
	/*
	 * A cancel ack is sent only if we cancelled an advertisment without
	 * sending a completion
	 */
	if (counter > 0) {
		result = sdp_send_ctrl_snk_cancel_ack(conn);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> SnkCacelAck response",
				     result);
			goto done;
		}
	}

	return 0;
done:
	return result;
}

/*
 * sdp_rcvd_snk_cancel_ack - sink cancel confirmantion
 */
static int sdp_rcvd_snk_cancel_ack(struct sdp_sock *conn,
				   struct sdpc_buff *buff)
{
	struct sdpc_iocb *iocb;

	sdp_dbg_ctrl(conn, "Sink Cancel Ack. actv <%d> mode <%d> flag <%08x>",
		     conn->snk_sent, conn->recv_mode, conn->flags);

	if (!(conn->flags & SDP_CONN_F_SNK_CANCEL)) {
		sdp_dbg_warn(conn, "Connection not in sink cancel mode <%08x>",
			     conn->flags);
		return -EPROTO;
	}
	/*
	 * drain and complete all active IOCBs
	 */
	while ((iocb = sdp_iocb_q_get_head(&conn->r_snk))) {

		conn->snk_sent--;
		sdp_iocb_complete(iocb, 0);
	}
	/*
	 * cancellation is complete. Cancel flag is cleared in RECV post.
	 */
	return 0;
}

/*
 * sdp_rcvd_resize_buff_ack - buffer size change request
 */
static int sdp_rcvd_resize_buff_ack(struct sdp_sock *conn,
				    struct sdpc_buff *buff)
{
	struct msg_hdr_crbh *crbh;
	int result;

	crbh = (struct msg_hdr_crbh *) buff->data;
	buff->data = buff->data + sizeof(struct msg_hdr_crbh);

	sdp_msg_net_to_cpu_crbh(crbh);
	/*
	 * request to change our recv buffer size, we're pretty much locked
	 * into the size we're using, once the connection is set up, so we
	 * reject the request.
	 */
	sdp_dbg_ctrl(conn, "Buffer Size Change request. <%d:%d>",
		     crbh->size, conn->recv_size);

	result = sdp_send_ctrl_resize_buff_ack(conn, conn->recv_size);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> acking size change request",
			     result);
		goto error;
	}

	return 0;
error:
	return result;
}

static int sdp_rcvd_suspend(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct msg_hdr_sch *sch;

	sch = (struct msg_hdr_sch *) buff->data;
	buff->data = buff->data + sizeof(struct msg_hdr_sch);

	sdp_msg_net_to_cpu_sch(sch);

	return 0;
}

static int sdp_rcvd_suspend_ack(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	return 0;
}

static int sdp_rcvd_snk_avail(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct msg_hdr_snkah *snkah;
	struct sdpc_advt *advt;
	struct sdpc_iocb *iocb;
	int result;

	snkah = (struct msg_hdr_snkah *) buff->data;
	buff->data = buff->data + sizeof(struct msg_hdr_snkah);

	sdp_msg_net_to_cpu_snkah(snkah);

	sdp_dbg_data(conn, "SnkAvail received. <%d:%d:%016llx> mode <%d>",
		     snkah->size, snkah->r_key,
		     (unsigned long long) snkah->addr,
		     conn->send_mode);
	/*
	 * check our send mode, and make sure parameters are within reason.
	 */
	if (conn->send_mode != SDP_MODE_PIPE) {
		sdp_dbg_warn(conn, "SinkAvail, incorrect source mode <%d>",
			     conn->send_mode);
		return -EPROTO;
	}

	if (SDP_MSG_MAX_ADVS == (conn->src_recv + conn->snk_recv)) {
		sdp_dbg_warn(conn, "SinkAvail, too many advertisments. <%d>",
			     (conn->src_recv + conn->snk_recv));
		return -EPROTO;
	}

	if (snkah->size < conn->send_size) {
		sdp_dbg_warn(conn, "SinkAvail too small. <%d:%d>",
			     snkah->size, conn->send_size);
		return -EPROTO;
	}
	/*
	 * Save the advertisment, if it's not stale. otherwise update
	 * discard and skip to data processing.
	 */
	if (conn->nond_send != snkah->non_disc) {
		conn->nond_send--;
		goto consume;
	}
	/*
	 * If there are outstanding SrcAvail messages, they are now
	 * invalid and the queue needs to be fixed up.
	 */
	if (conn->src_sent > 0) {
		while ((iocb = sdp_iocb_q_get_tail(&conn->w_src))) {
			SDP_EXPECT((iocb->flags & SDP_IOCB_F_ACTIVE));

			iocb->flags &= ~SDP_IOCB_F_ACTIVE;
			conn->src_sent--;
			/*
			 * Either move the active queue, back to the
			 * pending queue, or if the operations are
			 * in cancel processing they need to be
			 * completed.
			 */
			if (!(iocb->flags & SDP_IOCB_F_CANCEL))
				sdp_desc_q_put_head(&conn->send_queue,
						    (struct sdpc_desc *)iocb);
			else
				sdp_iocb_complete(iocb, 0);
		}
		/*
		 * If Source Cancel was in process, it should now
		 * be cleared.
		 */
		if (conn->flags & SDP_CONN_F_SRC_CANCEL_L) {
			conn->src_cncl = 0;
			conn->flags &= ~(SDP_CONN_F_SRC_CANCEL_L);
		}
	}
	/*
	 * create and queue new advertisment
	 */
	advt = sdp_advt_create();
	if (!advt) {
		sdp_dbg_warn(conn, "SrcAvail cannot be copied.");
		return -ENOMEM;
	}

	advt->post = 0;
	advt->size = snkah->size;
	advt->addr = snkah->addr;
	advt->rkey = snkah->r_key;

	conn->snk_recv++;

	conn->s_cur_adv = 1;
	conn->s_par_adv = 0;

	sdp_advt_q_put(&conn->snk_pend, advt);

consume:
	conn->s_wq_cur = SDP_SEND_POST_SLOW;
	conn->s_wq_par = 0;
	/*
	 * consume any data in the advertisment for the other direction.
	 */
	if ((buff->tail - buff->data) > 0) {
		result = sdp_recv_buff(conn, buff);
		if (result > 0)
			/*
			 * count number of bytes buffered by the connection,
			 * zero byte buffers or errors can be returned, the
			 * buffer will be dispossed of by the caller.
			 */
			conn->byte_strm += result;
		else
			if (result < 0)
				sdp_dbg_warn(conn, "Error <%d> buffer recv",
					     result);
	} else
		result = 0;

	/*
	 * PostRecv will take care of consuming this advertisment, based
	 * on result.
	 */
	return result;
}

static int sdp_rcvd_src_avail(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct msg_hdr_srcah *srcah;
	struct sdpc_advt *advt;
	int result;
	s32 size;

	srcah = (struct msg_hdr_srcah *) buff->data;
	buff->data = buff->data + sizeof(struct msg_hdr_srcah);

	sdp_msg_net_to_cpu_srcah(srcah);

	size = buff->tail - buff->data;

	sdp_dbg_data(conn, "SrcAvail received. <%d:%d:%d:%016llx> mode <%d>",
		     srcah->size, srcah->r_key, size,
		     (unsigned long long) srcah->addr, conn->recv_mode);

	if (conn->snk_sent > 0) {
		/*
		 * crossed SrcAvail and SnkAvail, the source message is
		 * discarded.
		 */
		sdp_dbg_data(conn, "avail cross<%d> dropping src. mode <%d>",
			     conn->snk_sent, conn->recv_mode);
		result = 0;
		goto done;
	}

	if (conn->flags & SDP_CONN_F_SRC_CANCEL_R) {
		sdp_dbg_warn(conn, "SrcAvail during SrcAvailCancel. <%d>",
			     conn->src_recv);
		result = -EFAULT;
		goto done;
	}
	/*
	 * To emulate RFC 1122 (page 88) a connection should be reset/aborted
	 * if data is received and the receive half of the connection has been
	 * closed. This notifies the peer that the data was not received.
	 */
	if (RCV_SHUTDOWN & conn->shutdown) {
		sdp_dbg_warn(conn, "SrcAvail, receive path closed <%02x>",
			     conn->shutdown);
		/*
		 * abort connection (send reset)
		 */
		sdp_conn_abort(conn);
		/*
		 * drop packet
		 */
		result = 0;
		goto done;
	}
	/*
	 * save the advertisment
	 */
	advt = sdp_advt_create();
	if (!advt) {
		sdp_dbg_warn(conn, "SrcAvail cannot be copied.");
		result = -ENOMEM;
		goto done;
	}
	/*
	 * consume the advertisment, if it's allowed, first check the recv
	 * path mode to determine if all is cool for the advertisment.
	 */
	switch (conn->recv_mode) {
	case SDP_MODE_BUFF:
		sdp_dbg_warn(conn, "SrcAvail in bad mode. <%d>",
			     conn->recv_mode);
		result = -EPROTO;
		goto advt_error;

		break;
	case SDP_MODE_COMB:
		if (conn->src_recv > 0 ||
		    size <= 0 ||
		    !(srcah->size > size)) {
			sdp_dbg_warn(conn,
				     "SrcAvail mode <%d> mismatch. <%d:%d:%d>",
				     conn->recv_mode, conn->src_recv,
				     size, srcah->size);
			result = -EPROTO;
			goto advt_error;
		}

		advt->rkey = srcah->r_key;
		advt->post =
		    0 - ((SDP_SRC_AVAIL_RECV > size) ? size : 0);
		advt->size =
		    srcah->size -
		    ((SDP_SRC_AVAIL_RECV > size) ? 0 : size);
		advt->addr =
		    srcah->addr +
		    ((SDP_SRC_AVAIL_RECV > size) ? 0 : size);

		break;
	case SDP_MODE_PIPE:
		if (SDP_MSG_MAX_ADVS == (conn->src_recv + conn->snk_recv) ||
		    size) {
			sdp_dbg_warn(conn,
				     "SrcAvail mode <%d> mismatch. <%d:%d>",
				     conn->recv_mode,
				     conn->src_recv + conn->snk_recv, size);

			result = -EPROTO;
			goto advt_error;
		}

		advt->post = 0;
		advt->size = srcah->size;
		advt->addr = srcah->addr;
		advt->rkey = srcah->r_key;

		break;
	default:
		sdp_dbg_warn(conn, "SrcAvail message in unknown mode. <%d>",
			     conn->recv_mode);
		result = -EPROTO;
		goto advt_error;
	}
	/*
	 * save advertisment
	 */
	conn->src_recv++;

	sdp_advt_q_put(&conn->src_pend, advt);
	/*
	 * process any ULP data in the message
	 */
	if (!size) {
		result = 0;
		goto done;
	}
	/*
	 * update non-discard for sink advertisment management
	 */
	conn->nond_recv++;

	if (!(SDP_SRC_AVAIL_RECV > size)) {
		result = sdp_recv_buff(conn, buff);
		if (result > 0)
			/*
			 * count number of bytes buffered by the
			 * connection, zero byte buffers or errors
			 * can be returned, the buffer will be
			 * dispossed of by the caller.
			 */
			conn->byte_strm += result;
		else
			if (result < 0)
				sdp_dbg_warn(conn, "Error <%d> buffer recv",
					     result);
	} else
		result = 0;
	/*
	 * PostRecv will take care of consuming this advertisment.
	 */
	return result;

advt_error:
	sdp_advt_destroy(advt);
done:
	return result;
}

/*
 * sdp_rcvd_data - SDP data message event received
 */
static int sdp_rcvd_data(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	int ret_val;

	if (buff->tail == buff->data)
		return 0;
	/*
	 * If we are processing a SrcAvail, there should be no
	 * buffered data
	 */
	if (conn->src_recv > 0) {
		sdp_dbg_warn(conn, "Error, recv'd data with SrcAvail active.");
		return -EPROTO;
	}
	/*
	 * check for out-of-band data, and mark the buffer if there
	 * is a pending urgent message. If the OOB data is in this
	 * buffer, pull it out.
	 */
	if (SDP_BSDH_GET_OOB_PEND(buff->bsdh_hdr))
		buff->flags |= SDP_BUFF_F_OOB_PEND;

	if (SDP_BSDH_GET_OOB_PRES(buff->bsdh_hdr))
		buff->flags |= SDP_BUFF_F_OOB_PRES;
	/*
	 * update non-discard for sink advertisment management
	 */
	conn->nond_recv++;

	ret_val = sdp_recv_buff(conn, buff);
	if (ret_val < 0)
		sdp_dbg_warn(conn, "Error <%d> processing buff recv", ret_val);
	/*
	 * result contains the number of bytes in the buffer which
	 * are being kept by the connection. (zero buffered means
	 * me can dispose of the buffer.
	 */
	conn->byte_strm += ret_val;

	return ret_val;
}

/*
 * sdp_rcvd_unsupported - Valid messages we're not expecting
 */
static int sdp_rcvd_unsupported(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	/*
	 * Since the gateway only initates RDMA's but is never a target, and
	 * for a few other reasons, there are certain valid SDP messages
	 * which we never expect to see.
	 */
	sdp_dbg_warn(conn, "Unexpected SDP message <%02x> received!",
		     buff->bsdh_hdr->mid);

	return 0;
}

/*
 * Event Dispatch table. For performance a dispatch table is used to avoid
 * a giant case statment for every single SDP event. This is a bit more
 * confusing, relies on the layout of the Message IDs, and is less
 * flexable. However, it is faster.
 *
 * Sparse table, the full table would be 16x16, where the low 4 bits, of
 * the MID byte, are one dimension, and the high 4 bits are the other
 * dimension. Since all rows, except for the first and last, are empty,
 * only those are represented in the table.
 */
#define SDP_MSG_EVENT_TABLE_SIZE 0x20

static sdp_event_cb_func recv_event_funcs[SDP_MSG_EVENT_TABLE_SIZE] = {
	NULL,                      /* SDP_MID_HELLO            0x00 */
	NULL,                      /* SDP_MID_HELLO_ACK        0x01 */
	sdp_rcvd_disconnect,       /* SDP_MID_DISCONNECT       0x02 */
	sdp_rcvd_abort,            /* SDP_MID_ABORT_CONN       0x03 */
	sdp_rcvd_send_sm,          /* SDP_MID_SEND_SM          0x04 */
	sdp_rcvd_rdma_wr,          /* SDP_MID_RDMA_WR_COMP     0x05 */
	sdp_rcvd_rdma_rd,          /* SDP_MID_RDMA_RD_COMP     0x06 */
	sdp_rcvd_mode_change,      /* SDP_MID_MODE_CHANGE      0x07 */
	sdp_rcvd_src_cancel,       /* SDP_MID_SRC_CANCEL       0x08 */
	sdp_rcvd_snk_cancel,       /* SDP_MID_SNK_CANCEL       0x09 */
	sdp_rcvd_snk_cancel_ack,   /* SDP_MID_SNK_CANCEL_ACK   0x0A */
	sdp_rcvd_resize_buff_ack,  /* SDP_MID_CH_RECV_BUF      0x0B */
	sdp_rcvd_unsupported,      /* SDP_MID_CH_RECV_BUF_ACK  0x0C */
	sdp_rcvd_suspend,          /* SDP_MID_SUSPEND          0x0D */
	sdp_rcvd_suspend_ack,      /* SDP_MID_SUSPEND_ACK      0x0E */
	NULL,                      /* reserved                 0x0F */
	NULL,                      /* reserved                 0xF0 */
	NULL,                      /* reserved                 0xF1 */
	NULL,                      /* reserved                 0xF2 */
	NULL,                      /* reserved                 0xF3 */
	NULL,                      /* reserved                 0xF4 */
	NULL,                      /* reserved                 0xF5 */
	NULL,                      /* reserved                 0xF6 */
	NULL,                      /* reserved                 0xF7 */
	NULL,                      /* reserved                 0xF8 */
	NULL,                      /* reserved                 0xF9 */
	NULL,                      /* reserved                 0xFA */
	NULL,                      /* reserved                 0xFB */
	NULL,                      /* reserved                 0xFC */
	sdp_rcvd_snk_avail,        /* SDP_MID_SNK_AVAIL        0xFD */
	sdp_rcvd_src_avail,        /* SDP_MID_SRC_AVAIL        0xFE */
	sdp_rcvd_data              /* SDP_MID_DATA             0xFF */
};

/*
 * sdp_event_recv - recv event demultiplexing into sdp messages
 */
int sdp_event_recv(struct sdp_sock *conn, struct ib_wc *comp)
{
	sdp_event_cb_func dispatch_func;
	struct sdpc_buff *buff;
	struct sock *sk;
	u32 offset;
	int result;

	/*
	 * error handling
	 */
	if (IB_WC_SUCCESS != comp->status) {
		switch (comp->status) {
		case IB_WC_WR_FLUSH_ERR:
			/*
			 * clear posted buffers from error'd queue
			 */
			sdp_buff_q_clear_unmap(&conn->recv_post,
					       conn->ca->dma_device,
					       PCI_DMA_FROMDEVICE);
			result = 0;
			break;
		default:
			sdp_dbg_warn(conn, "Unhandled RECV error status <%d>.",
				     comp->status);
			result = -EIO;
		}

		goto done;
	}
	/*
	 * get data
	 */
	buff = sdp_buff_q_get_head(&conn->recv_post);
	if (!buff) {
		sdp_dbg_warn(conn, "receive event, but no posted receive?!");
		result = -EINVAL;
		goto done;
	}
	if (comp->wr_id != buff->wrid) {
		sdp_dbg_warn(conn, "work request ID mismatch. <%llu:%llu>",
			     (unsigned long long)comp->wr_id,
			     (unsigned long long)buff->wrid);

		result = -ERANGE;
		goto drop;
	}

	dma_unmap_single(conn->ca->dma_device,
			 buff->sge.addr,
			 buff->tail - buff->data,
			 PCI_DMA_FROMDEVICE);

	/*
	 * endian swap
	 */
	conn->l_recv_bf--;
	conn->l_advt_bf--;

	buff->bsdh_hdr = (struct msg_hdr_bsdh *) buff->data;

        sdp_msg_net_to_cpu_bsdh(buff->bsdh_hdr);

	if (comp->byte_len != buff->bsdh_hdr->size) {
		sdp_dbg_warn(conn,
			     "receive event, message size mismatch <%d:%d>",
			     comp->byte_len, buff->bsdh_hdr->size);

		result = -EINVAL;
		goto drop;
	}

	buff->tail = buff->data + buff->bsdh_hdr->size;
	buff->data = buff->data + sizeof(struct msg_hdr_bsdh);
	/*
	 * Do not update the advertised sequence number, until the
	 * SrcAvailCancel message has been processed.
	 */
	conn->recv_seq = buff->bsdh_hdr->seq_num;
	conn->advt_seq = ((conn->flags & SDP_CONN_F_SRC_CANCEL_R) ?
			  conn->advt_seq : conn->recv_seq);
	/*
	 * buffers advertised minus the difference in buffer count between
	 * the number we've sent and the remote host has received.
	 */
	conn->r_recv_bf = (buff->bsdh_hdr->recv_bufs -
			   abs((s32) conn->send_seq -
			       (s32) buff->bsdh_hdr->seq_ack));
	/*
	 * dispatch
	 */
	sdp_dbg_data(conn, "RECV BSDH <%04x:%02x:%02x:%08x:%08x:%08x>",
		     buff->bsdh_hdr->recv_bufs,
		     buff->bsdh_hdr->flags,
		     buff->bsdh_hdr->mid,
		     buff->bsdh_hdr->size,
		     buff->bsdh_hdr->seq_num,
		     buff->bsdh_hdr->seq_ack);
	/*
	 * fast path data messages
	 */
	if (SDP_MID_DATA == buff->bsdh_hdr->mid)
		result = sdp_rcvd_data(conn, buff);
	else {
		offset = buff->bsdh_hdr->mid & 0x1F;

		if (offset >= SDP_MSG_EVENT_TABLE_SIZE ||
		    !recv_event_funcs[offset]) {
			sdp_dbg_warn(conn, "receive event, unknown MID <%d>",
				     buff->bsdh_hdr->mid);
			result = -EINVAL;
			goto drop;
		}

		SDP_CONN_STAT_RECV_MID_INC(conn, offset);

		dispatch_func = recv_event_funcs[offset];
		result = dispatch_func(conn, buff);
	}
	/*
	 * process result.
	 */
	if (!result) {
		sdp_buff_pool_put(buff);
		/*
		 * If this buffer was consumed, then make sure sufficient
		 * recv buffers are posted. Also we might be able to move
		 * data with a new RDMA SrcAvail advertisment.
		 */
		result = sdp_recv_flush(conn);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> flushing recv queue",
				     result);
			goto done;
		}
	} else
		if (result < 0) {
			sdp_dbg_warn(conn,
				     "receive event, dispatch error. <%d>",
				     result);

			goto drop;
		}
		else {
			/*
			 * If data was consumed by the protocol, signal
			 * the user.
			 */
			sk = sk_sdp(conn);
			sk->sk_data_ready(sk, conn->byte_strm);
		}
	/*
	 * It's possible that a new recv buffer advertisment opened up the
	 * recv window and we can flush buffered send data
	 */
	result = sdp_send_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing send queue",
			     result);
		goto done;
	}

	return 0;
drop:
	sdp_buff_pool_put(buff);
done:
	return result;
}

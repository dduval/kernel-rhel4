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
 * $Id: sdp_read.c 2762 2005-06-30 19:01:38Z libor $
 */

#include "sdp_main.h"

/*
 * RDMA read processing functions
 */

/*
 * sdp_event_read_advt - RDMA read event handler for source advertisments
 */
static int sdp_event_read_advt(struct sdp_sock *conn, struct ib_wc *comp)
{
	struct sdpc_advt *advt;
	int result;

	/*
	 * if this was the last RDMA read for an advertisment, post a notice.
	 * Might want to post multiple RDMA read completion messages per
	 * advertisment, to open up a sending window? Have to test to see
	 * what MS does... (Either choice is correct)
	 */
	advt = sdp_advt_q_look(&conn->src_actv);
	if (!advt || advt->wrid != comp->wr_id) {
		advt = sdp_advt_q_look(&conn->src_pend);
		if (advt && advt->wrid == comp->wr_id)
			advt->flag &= ~SDP_ADVT_F_READ;

		goto done;
	}

	advt = sdp_advt_q_get(&conn->src_actv);

	conn->src_recv--;

	result = sdp_send_ctrl_rdma_rd(conn, advt->post);
	SDP_EXPECT(result >= 0);

	sdp_advt_destroy(advt);
	/*
	 * If a SrcAvailCancel was received, and all RDMA reads
	 * have been flushed, perform tail processing
	 */
	if ((conn->flags & SDP_CONN_F_SRC_CANCEL_R) &&
	    !conn->src_recv) {
		conn->flags &= ~SDP_CONN_F_SRC_CANCEL_R;
		conn->advt_seq = conn->recv_seq;
		/*
		 * If any data was canceled, post a SendSm, also
		 */
		if (conn->flags & SDP_CONN_F_SRC_CANCEL_C) {
			result = sdp_send_ctrl_send_sm(conn);
			if (result < 0) {
				sdp_dbg_warn(conn, "Error <%d> posting SendSm",
					     result);
				goto error;
			}

			conn->flags &= ~SDP_CONN_F_SRC_CANCEL_C;
		}
	}

done:
	return 0;
error:
	return result;
}

/*
 * RDMA read QP Event Handler
 */

/*
 * sdp_event_read - RDMA read event handler
 */
int sdp_event_read(struct sdp_sock *conn, struct ib_wc *comp)
{
	struct sdpc_iocb *iocb;
	struct sdpc_buff *buff;
	struct sock *sk;
	s32 result;
	s32 type;

	/*
	 * error handling
	 */
	if (IB_WC_SUCCESS != comp->status) {
		switch (comp->status) {
		case IB_WC_WR_FLUSH_ERR:
			/*
			 * clear posted buffers from error'd queue
			 */
			sdp_desc_q_clear(&conn->r_src);
			result = 0;
			break;
		default:
			sdp_dbg_warn(conn, "Unhandled READ status <%d>.",
				     comp->status);
			result = -EIO;
		}

		goto done;
	}

	sdp_dbg_data(conn, "Read complete <%llu> of <%u> bytes.",
		     (unsigned long long) comp->wr_id, comp->byte_len);
	/*
	 * update queue depth
	 */
	conn->s_wq_size--;
	/*
	 * Four basic scenarios:
	 *
	 * 1) BUFF at the head of the active read table is completed by this
	 *    read event completion
	 * 2) IOCB at the head of the active read table is completed by this
	 *    read event completion
	 * 3) IOCB at the head of the active read table is not associated
	 *    with this event, meaning a later event in flight will complete
	 *    it, no IOCB is completed by this event.
	 * 4) No IOCBs are in the active table, the head of the read pending
	 *    table, matches the work request ID of the event and the recv
	 *    low water mark has been satisfied.
	 */
	/*
	 * check type at head of queue
	 */
	type = sdp_desc_q_type_head(&conn->r_src);
	switch (type) {
	case SDP_DESC_TYPE_BUFF:
		buff = (struct sdpc_buff *)sdp_desc_q_get_head(&conn->r_src);

		if (comp->wr_id != buff->wrid) {
			sdp_dbg_warn(conn, "work request mismatch <%llu:%llu>",
				     (unsigned long long)comp->wr_id,
				     (unsigned long long)buff->wrid);

			sdp_buff_pool_put(buff);
			result = -EPROTO;
			goto done;
		}
		/*
		 * post data to the stream interface
		 */
		result = sdp_recv_buff(conn, buff);
		if (result > 0) {
			/*
			 * count number of bytes buffered by the connection,
			 * zero byte buffers can be returned. If data was
			 * consumed by the protocol, signal the user.
			 */
			conn->byte_strm += result;

			sk = sk_sdp(conn);
			sk->sk_data_ready(sk, conn->byte_strm);
		} else {
			if (result < 0)
				sdp_dbg_warn(conn, "Error <%d> receiving buff",
					     result);

			sdp_buff_pool_put(buff);
		}

		break;
	case SDP_DESC_TYPE_IOCB:
		iocb = (struct sdpc_iocb *) sdp_desc_q_look_head(&conn->r_src);
		if (!iocb || iocb->wrid != comp->wr_id)
			break;

		iocb = (struct sdpc_iocb *)sdp_desc_q_get_head(&conn->r_src);

		iocb->flags &= ~(SDP_IOCB_F_ACTIVE | SDP_IOCB_F_RDMA_R);

		SDP_CONN_STAT_READ_INC(conn, iocb->post);
		SDP_CONN_STAT_RQ_DEC(conn, iocb->size);

		sdp_iocb_complete(iocb, 0);

		break;
	case SDP_DESC_TYPE_NONE:
		iocb = sdp_iocb_q_look(&conn->r_pend);
		if (!iocb) {
			result = -EPROTO;
			goto done;
		}

		if (iocb->wrid != comp->wr_id)
			break;

		iocb->flags &= ~(SDP_IOCB_F_ACTIVE | SDP_IOCB_F_RDMA_R);

		if (sk_sdp(conn)->sk_rcvlowat > iocb->post)
			break;

		SDP_CONN_STAT_READ_INC(conn, iocb->post);
		SDP_CONN_STAT_RQ_DEC(conn, iocb->size);

		sdp_iocb_complete(sdp_iocb_q_get_head(&conn->r_pend), 0);

		break;
	default:
		sdp_warn("Unknown type <%d> at head of READ SRC queue. <%d>",
			 type, sdp_desc_q_size(&conn->r_src));
		result = -EPROTO;
		goto done;
	}
	/*
	 * The advertisment which generated this READ needs to be checked.
	 */
	result = sdp_event_read_advt(conn, comp);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> handling READ advertisment",
			     result);
		goto done;
	}
	/*
	 * It's possible that the "send" queue was opened up by the completion
	 * of some RDMAs
	 */
	result = sdp_send_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing send queue.", result);
		goto done;
	}
	/*
	 * The completion of the RDMA read may allow us to post additional RDMA
	 * reads.
	 */
	result = sdp_recv_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing recv queue.", result);
		goto done;
	}

done:
	return result;
}

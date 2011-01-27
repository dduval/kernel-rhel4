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
 * $Id: sdp_sent.c 3370 2005-09-12 14:15:59Z mst $
 */

#include "sdp_main.h"

/*
 * Specific MID handler functions. (SEND)
 */

static int sdp_sent_disconnect(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	int result;

	sdp_dbg_ctrl(conn, "Disconnect message sent.");

	switch (conn->state) {
	case SDP_CONN_ST_TIME_WAIT_2:
		/*
		 * Nothing to do, CM disconnects have been exchanged.
		 */
		break;
	case SDP_CONN_ST_DIS_SEND_1:
		/*
		 * Active disconnect message send completed
		 */
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_DIS_SENT_1);

		break;
	case SDP_CONN_ST_DIS_SEND_2:
	case SDP_CONN_ST_DIS_RECV_R:
		/*
		 * simultaneous disconnect. Received a disconnect, after we
		 * initiated one. This needs to be handled as the active
		 * stream interface close that it is.
		 */
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_TIME_WAIT_1);
		/*
		 * Begin IB/CM disconnect
		 */
		result = ib_send_cm_dreq(conn->cm_id, NULL, 0);
		/*
		 * if the remote DREQ was already received, but unprocessed, do
		 * not treat it as an error
		 */
		if (result)
			sdp_dbg_warn(conn, "Error <%d> sending CM DREQ",
				     result);

		break;
	case SDP_CONN_ST_ERROR:
		break;
	default:
		sdp_warn("Disconnect sent, unexpected state. <%d> <%04x>",
			 conn->hashent, conn->state);
		result = -EPROTO;
		goto error;

		break;
	}

	return 0;
error:
	return result;
}

static int sdp_sent_abort(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	int result;

	/*
	 * The gateway interface should be in error state, initiate CM
	 * disconnect.
	 */
	SDP_CONN_ST_SET(conn, SDP_CONN_ST_CLOSED);

	result = ib_send_cm_dreq(conn->cm_id, NULL, 0);
	if (result)
		sdp_dbg_warn(conn, "Error <%d> sending CM DREQ", result);

	return result;
}

/*
 * sdp_event_send - send event handler
 */
int sdp_event_send(struct sdp_sock *conn, struct ib_wc *comp)
{
	struct sdpc_buff *buff;
	u64 current_wrid = 0;
	u32 free_count = 0;
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
			sdp_buff_q_clear_unmap(&conn->send_post,
					       conn->ca->dma_device,
					       PCI_DMA_TODEVICE);
			result = 0;
			break;
		default:
			sdp_dbg_warn(conn, "Unhandled SEND error status <%d>.",
				     comp->status);
			result = -EIO;
		}

		goto done;
	}
	/*
	 * get buffer.
	 */
	while ((buff = sdp_buff_q_get_head(&conn->send_post))) {
		/*
		 * sanity checks
		 */
		if (!buff->bsdh_hdr) {
			sdp_dbg_warn(conn, "Send header is missing?!");
			result = -ENODATA;
			goto drop;
		}
		/* check WRID taking into account wrap around */
		if (((s64)(comp->wr_id - buff->wrid)) < 0) {
			/*
			 * error
			 */
			sdp_dbg_warn(conn,
				     "Send wrid mismatch. <%llu:%llu:%d>",
				     (unsigned long long)comp->wr_id,
				     (unsigned long long)buff->wrid,
				     conn->send_usig);
			result = -EINVAL;
			goto drop;
		}

		dma_unmap_single(conn->ca->dma_device,
				 buff->sge.addr, buff->tail - buff->data,
				 PCI_DMA_TODEVICE);

		/*
		 * execute the send dispatch function, for specific actions.
		 */
		sdp_dbg_data(conn, "SENT BSDH <%04x:%02x:%02x:%08x:%08x:%08x>",
			     buff->bsdh_hdr->recv_bufs,
			     buff->bsdh_hdr->flags,
			     buff->bsdh_hdr->mid,
			     buff->bsdh_hdr->size,
			     buff->bsdh_hdr->seq_num,
			     buff->bsdh_hdr->seq_ack);
		/*
		 * data fast path we collapse the next level dispatch function.
		 * For all other buffers we go the slow path.
		 */
		result = 0;

		switch (buff->bsdh_hdr->mid) {
		case SDP_MID_DATA:
			conn->send_qud -= buff->data_size;
			break;
                case SDP_MID_DISCONNECT:
			result = sdp_sent_disconnect(conn, buff);
			break;
		case SDP_MID_ABORT_CONN:
			result = sdp_sent_abort(conn, buff);
			break;
		case SDP_MID_SEND_SM:
		case SDP_MID_RDMA_WR_COMP:
		case SDP_MID_RDMA_RD_COMP:
		case SDP_MID_MODE_CHANGE:
		case SDP_MID_SRC_CANCEL:
		case SDP_MID_SNK_CANCEL:
		case SDP_MID_SNK_CANCEL_ACK:
		case SDP_MID_CH_RECV_BUF_ACK:
		case SDP_MID_SNK_AVAIL:
		case SDP_MID_SRC_AVAIL:
			break;
		case SDP_MID_CH_RECV_BUF:
		case SDP_MID_SUSPEND:
		case SDP_MID_SUSPEND_ACK:
			sdp_dbg_warn(conn,
				     "Unexpected SDP message <%02x> sent!",
				     buff->bsdh_hdr->mid);
			break;
		default:
			sdp_dbg_warn(conn, "Send complete unknown MID <%d>",
				     buff->bsdh_hdr->mid);
			result = -EINVAL;
			break;
		}

		if (result) {
			sdp_dbg_warn(conn, "Sent dispatch error. <%d>",
				     result);
			goto drop;
		}

		current_wrid = buff->wrid;
		/*
		 * send queue size reduced by one.
		 */
		conn->s_wq_size--;

		if (SDP_BUFF_F_GET_UNSIG(buff) > 0)
			conn->send_usig--;

		sdp_buff_pool_put(buff);

		free_count++;

		if (comp->wr_id == current_wrid)
			break;
	}

	if (free_count <= 0 || conn->send_usig < 0) {
		sdp_dbg_warn(conn,
			     "Send processing mismatch. <%llu:%llu:%d:%d>",
			     (unsigned long long)comp->wr_id,
			     (unsigned long long)current_wrid,
			     free_count, conn->send_usig);
		result = -EINVAL;
		goto done;
	}
	/*
	 * Flush queued send data into the post queue if there is room.
	 */
	result = sdp_send_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing send queue.", result);
		goto done;
	}

	return 0;
drop:
	sdp_buff_pool_put(buff);
done:
	return result;
}

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
 * $Id: sdp_write.c 3033 2005-08-09 12:45:08Z mst $
 */

#include "sdp_main.h"

/*
 * RDMA read QP Event Handler
 */

/*
 * sdp_event_write - RDMA write event handler
 */
int sdp_event_write(struct sdp_sock *conn, struct ib_wc *comp)
{
	struct sdpc_iocb *iocb;
	struct sdpc_buff *buff;
	int result;
	int type;

	/*
	 * error handling
	 */
	if (IB_WC_SUCCESS != comp->status) {
		switch (comp->status) {
		case IB_WC_WR_FLUSH_ERR:
			/*
			 * clear posted buffers from error'd queue
			 */
			sdp_desc_q_clear(&conn->w_snk);
			result = 0;
			break;
		default:
			sdp_dbg_warn(conn, "Unhandled WRITE status <%d>.",
				     comp->status);
			result = -EIO;
		}

		goto error;
	}

	sdp_dbg_data(conn, "Write complete <%llu> of <%u> bytes.",
		     (unsigned long long) comp->wr_id, comp->byte_len);
	/*
	 * Four basic scenarios:
	 *
	 * 1) IOCB at the head of the active sink table is completed by this
	 *    write event completion
	 * 2) BUFF at the head of the active sink table is completed by this
	 *    write event completion
	 * 2) IOCB at the head of the active sink table is not associated
	 *    with this event, meaning a later event in flight will be the
	 *    write to complete it, no IOCB is completed by this event.
	 * 3) No IOCBs are in the active table, the head of the send pending
	 *    table, matches the work request ID of the event.
	 */
	type = sdp_desc_q_type_head(&conn->w_snk);
	switch (type) {
	case SDP_DESC_TYPE_BUFF:
		buff = (struct sdpc_buff *)sdp_desc_q_get_head(&conn->w_snk);

		conn->send_qud -= buff->data_size;

		sdp_buff_pool_put(buff);

		break;
	case SDP_DESC_TYPE_IOCB:
		iocb = (struct sdpc_iocb *)sdp_desc_q_look_head(&conn->w_snk);
		if (!iocb || iocb->wrid != comp->wr_id) {

			break;
		}

		iocb = (struct sdpc_iocb *)sdp_desc_q_get_head(&conn->w_snk);

		iocb->flags &= ~(SDP_IOCB_F_ACTIVE | SDP_IOCB_F_RDMA_W);

		SDP_CONN_STAT_WRITE_INC(conn, iocb->post);
		SDP_CONN_STAT_WQ_DEC(conn, iocb->size);

		sdp_iocb_complete(iocb, 0);

		break;
	case SDP_DESC_TYPE_NONE:
		iocb = (struct sdpc_iocb *)sdp_desc_q_look_type_head(&conn->send_queue,
								     SDP_DESC_TYPE_IOCB);
		if (!iocb) {
			sdp_dbg_warn(conn,
				     "No IOCB on write complete <%llu:%d:%d>",
				     (unsigned long long)comp->wr_id,
				     sdp_desc_q_size(&conn->w_snk),
				     sdp_desc_q_size(&conn->send_queue));

			result = -EPROTO;
			goto error;
		}

		if (iocb->wrid == comp->wr_id) {
			/*
			 * clear flags on a previously active partially
			 * satisfied IOCB
			 */
			iocb->flags &=
				~(SDP_IOCB_F_ACTIVE | SDP_IOCB_F_RDMA_W);
		}

		break;
	default:
		sdp_warn("Unknown type <%d> at head of WRITE SINK queue. <%d>",
			 type, sdp_desc_q_size(&conn->w_snk));
		result = -EPROTO;
		goto error;
	}
	/*
	 * update queue depth
	 */
	conn->s_wq_size--;
	/*
	 * It's possible that the "send" queue was opened up by the completion
	 * of some more sends.
	 */
	result = sdp_send_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing send queue.", result);
		goto error;
	}
	/*
	 * The completion of the RDMA read may allow us to post additional RDMA
	 * reads.
	 */
	result = sdp_recv_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing recv queue.", result);
		goto error;
	}

	return 0;
error:
	return result;
}

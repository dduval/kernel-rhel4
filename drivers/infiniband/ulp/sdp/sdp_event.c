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
 * $Id: sdp_event.c 3363 2005-09-11 08:17:02Z mst $
 */

#include "sdp_main.h"

/*
 * Primary QP Event Handler
 */

/*
 * sdp_cq_event_locked - main per QP event handler
 */
int sdp_cq_event_locked(struct ib_wc *comp, struct sdp_sock *conn)
{
	int result = 0;

	if (SDP_ST_MASK_CLOSED & conn->state) {
		/*
		 * Ignore events in closed state, connection is being
		 * terminated, connection cleanup will take care of freeing
		 * posted buffers.
		 */
		sdp_dbg_warn(conn, "Event <%d:%llu:%u:%u:%u> ignored in state",
			     comp->status,
			     (unsigned long long)comp->wr_id,
			     comp->opcode,
			     comp->byte_len,
			     comp->imm_data);
		result = 0;
		goto done;
	}
	/*
	 * event demultiplexing
	 */
	switch (comp->opcode) {
	case IB_WC_RECV:
		result = sdp_event_recv(conn, comp);
		break;
	case IB_WC_SEND:
		result = sdp_event_send(conn, comp);
		break;
	case IB_WC_RDMA_READ:
		result = sdp_event_read(conn, comp);
		break;
	case IB_WC_RDMA_WRITE:
		result = sdp_event_write(conn, comp);
		break;
	default:
		/*
		 * sometimes the errors come from the CQ but without an
		 * operation
		 */
		result = 0;

		switch (comp->status) {
		case IB_WC_WR_FLUSH_ERR:
			break;
		case IB_WC_SUCCESS:
			sdp_warn("unknown IB event. <%d>", comp->opcode);
			result = -ERANGE;
			break;
		default:
			sdp_warn("Unhandled status <%d> unknown event <%d>",
				 comp->status, comp->opcode);
			result = -EIO;
			break;
		}

		break;
	}
	/*
	 * release socket before error processing.
	 */
	if (result < 0) {
		sdp_dbg_warn(conn, "ABORT on error <%d> event <%u:%llu:%u:%u>",
			     result,
			     comp->status,
			     (unsigned long long)comp->wr_id,
			     comp->opcode,
			     comp->byte_len);
		/*
		 * abort.
		 */
		sdp_conn_abort(conn);
		return -EFAULT;
	}

done:
	return result;
}

/*
 * sdp_cq_event_handler - main per QP event handler, and demuxer
 */
void sdp_cq_event_handler(struct ib_cq *cq, void *arg)
{
	s32 hashent = (unsigned long)arg;
	struct sdp_sock *conn;
	u16 event;
	unsigned long flags;

	sdp_dbg_data(NULL, "CQ event. hashent <%d>", hashent);
	/*
	 * get socket
	 */
	conn = sdp_conn_table_lookup(hashent);
	if (!conn) {
		sdp_dbg_warn(conn, "Unknown connection <%d> for cq event",
			     hashent);
		return;
	}
	/*
	 * lock the bottom half of the socket. If the connection is in use,
	 * then queue the event, otherwise process this event.
	 */
	SDP_CONN_LOCK_IRQ(conn, flags);
	/*
	 * Check for event completions before CM has transitioned to
	 * the established state. The CQ will not be polled or rearmed
	 * until the CM makes the transition. Once the CM transition
	 * has been made, the act of unlocking the connection will
	 * drain the CQ.
	 */
	event = (cq == conn->recv_cq) ? SDP_LOCK_F_RECV_CQ:SDP_LOCK_F_SEND_CQ;

	if (!conn->lock.users) {
		if (!(SDP_ST_MASK_EVENTS & conn->state)) {
			/*
			 * passive and active connect respectively
			 */
			if (conn->state == SDP_CONN_ST_REQ_RECV)
				(void)ib_cm_establish(conn->cm_id);
			else
				sdp_dbg_warn(conn, "Unexpected event state.");
		}
		else {
			/*
			 * dispatch CQ completions.
			 */
			(void)sdp_conn_cq_drain(cq, conn);
			event = 0;
		}
	}
	/*
	 * Mark the event which was received, for the unlock code to
	 * process at a later time.
	 */
	conn->lock.event |= event;

	SDP_CONN_UNLOCK_IRQ(conn, flags);
	sdp_conn_put(conn);
}

static void sdp_cm_to_error(struct sdp_sock *conn)
{
	sdp_conn_inet_error(conn, -ECONNRESET);
	conn->cm_id = NULL;
	sdp_conn_put_light(conn);	/* CM reference */
}
/*
 * Connection establishment IB/CM callback functions
 */

static int sdp_cm_idle(struct ib_cm_id *cm_id, struct ib_cm_event *event,
		       struct sdp_sock *conn)
{
	sdp_dbg_ctrl(conn, "CM IDLE. commID <%08x> event <%d> status <%d>",
		     cm_id->local_id, event->event, event->param.send_status);
	/*
	 * check state
	 */
	switch (conn->state) {
	case SDP_CONN_ST_REQ_SENT:
		sdp_cm_actv_error(conn, -ECONNREFUSED);
		break;
	case SDP_CONN_ST_REQ_RECV:
	case SDP_CONN_ST_ESTABLISHED:
		sdp_conn_inet_error(conn, -ECONNREFUSED);
		break;
	case SDP_CONN_ST_TIME_WAIT_1:
		sdp_dbg_warn(conn, "Unexpected connection state");
		/*
		 * fall through
		 */
	case SDP_CONN_ST_CLOSED:
	case SDP_CONN_ST_ERROR:
	case SDP_CONN_ST_TIME_WAIT_2:
		/*
		 * Connection is finally dead. Drop the CM reference
		 */
		break;
	default:
		sdp_warn("Unknown conn state. conn <%d> state <%04x>",
			 conn->hashent, conn->state);
		break;
	}

	conn->cm_id = NULL;
	sdp_conn_put_light(conn); /* CM reference */
	return -ENOENT;     /* ensure CM cleans-up identifier. */
}

static int sdp_cm_established(struct ib_cm_id *cm_id,
			      struct ib_cm_event *event,
			      struct sdp_sock *conn)
{
	int result = 0;

	sdp_dbg_ctrl(conn, "CM ESTABLISHED. commID <%08x>", cm_id->local_id);
	/*
	 * release disconnects.
	 */
	conn->flags &= ~SDP_CONN_F_DIS_HOLD;
	/*
	 * check state
	 */
	switch (conn->state) {
	case SDP_CONN_ST_REQ_RECV:
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_ESTABLISHED);
	case SDP_CONN_ST_DIS_SEND_1:
	case SDP_CONN_ST_DIS_RECV_R:
	case SDP_CONN_ST_DIS_SEND_2:
		/* bring QP to established state, and flush queues. */
		result = sdp_cm_pass_establish(conn);
		if (!result)
			break;
		/*
		 * on error fall through to disconnect
		 */
	case SDP_CONN_ST_CLOSED:
	case SDP_CONN_ST_ERROR:
		/*
		 * Begin abortive disconnect.
		 * Leave state unchanged, time_wait and idle will handle the
		 * existing state correctly.
		 */
		result = ib_send_cm_dreq(conn->cm_id, NULL, 0);
		if (result) {
			sdp_dbg_warn(conn, "Error <%d> sending CM DREQ",
				     result);
			goto error;
		}

		break;
	case SDP_CONN_ST_ESTABLISHED:
		break;
	default:

		sdp_warn("Unexpected conn state. conn <%d> state <%04x>",
			 conn->hashent, conn->state);
		result = -EINVAL;
		goto error;
		break;
	}

	return 0;
error:
	sdp_cm_to_error(conn);
	return result;
}

static int sdp_cm_dreq_rcvd(struct ib_cm_id *cm_id, struct ib_cm_event *event,
			    struct sdp_sock *conn)
{
	int result = 0;

	sdp_dbg_ctrl(conn, "CM DREQ RCVD. commID <%08x> event <%d>",
		     cm_id->local_id, event->event);
	/*
	 * Respond with a DREP.
	 */
	result = ib_send_cm_drep(conn->cm_id, NULL, 0);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> sending CM DREP", result);
		sdp_cm_to_error(conn);
	}

	return result;
}
/*
 * sdp_cm_timewait - handler for connection Time Wait completion
 */
static int sdp_cm_timewait(struct ib_cm_id *cm_id, struct ib_cm_event *event,
			   struct sdp_sock *conn)
{
	int result = 0;

	sdp_dbg_ctrl(conn, "CM TIME WAIT. commID <%08x> event <%d>",
		     cm_id->local_id, event->event);
	/*
	 * Clear out posted receives now, vs after IDLE timeout, which consumes
	 * too many buffers when lots of connections are being established and
	 * torn down. Here is a good spot since we know that the QP has gone to
	 * reset, and pretty much all take downs end up here.
	 */
	sdp_buff_q_clear_unmap(&conn->recv_post,
			       conn->ca->dma_device,
			       PCI_DMA_FROMDEVICE);
	/*
	 * process state changes.
	 */
	switch (conn->state) {
	case SDP_CONN_ST_CLOSED:
	case SDP_CONN_ST_ERROR:
		/*
		 * error on stream interface, no more call to/from those
		 * interfaces.
		 */
		break;
	case SDP_CONN_ST_DIS_RECV_R:
	case SDP_CONN_ST_DIS_SEND_2:
	case SDP_CONN_ST_TIME_WAIT_1:
		/*
		 * SDP disconnect messages have been exchanged, and
		 * DREQ/DREP received, wait for idle timer.
		 */
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_TIME_WAIT_2);
		break;
	case SDP_CONN_ST_DIS_SEND_1:
	case SDP_CONN_ST_DIS_SENT_1:
	case SDP_CONN_ST_DIS_RECV_1:
		/*
		 * connection is being closed without a disconnect message,
		 * abortive close.
		 */
	case SDP_CONN_ST_ESTABLISHED:
		/*
		 * Change state, so we only need to wait for the abort
		 * callback, and idle. Call the abort callback.
		 */
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_TIME_WAIT_2);

		sdp_conn_abort(conn);
		break;
	default:
		sdp_warn("Unexpected conn state. conn <%d> state <%04x>",
			 conn->hashent, conn->state);
		sdp_cm_to_error(conn);
		result = -EINVAL;
		break;
	}

	return result;
}

/*
 * Primary Connection Managment callback function
 */
int sdp_cm_event_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event)
{
	s32 hashent = (unsigned long)cm_id->context;
	struct sdp_sock *conn = NULL;
	int result = 0;

	sdp_dbg_ctrl(NULL, "event <%d> commID <%08x> ID <%d>",
		     event->event, cm_id->local_id, hashent);

	if (event->event != IB_CM_REQ_RECEIVED) {
		conn = sdp_conn_table_lookup(hashent);
		if (conn)
			sdp_conn_lock(conn);
		else {
			sdp_dbg_warn(NULL, "No conn <%d> CM event <%d>",
				     hashent, event->event);
			return -EINVAL;
		}
	}

	switch (event->event) {
	case IB_CM_REQ_RECEIVED:
		result = sdp_cm_req_handler(cm_id, event);
		break;
	case IB_CM_REP_RECEIVED:
		result = sdp_cm_rep_handler(cm_id, event, conn);
		break;
	case IB_CM_REQ_ERROR:
	case IB_CM_REP_ERROR:
	case IB_CM_REJ_RECEIVED:
	case IB_CM_TIMEWAIT_EXIT:
		result = sdp_cm_idle(cm_id, event, conn);
		break;
	case IB_CM_RTU_RECEIVED:
	case IB_CM_USER_ESTABLISHED:
		result = sdp_cm_established(cm_id, event, conn);
		break;
	case IB_CM_DREQ_RECEIVED:
		result = sdp_cm_dreq_rcvd(cm_id, event, conn);
		if (result)
			break;
		/* fall through on success to handle state transition */
	case IB_CM_DREQ_ERROR:
	case IB_CM_DREP_RECEIVED:
		result = sdp_cm_timewait(cm_id, event, conn);
		break;
	default:
		sdp_dbg_warn(conn, "Unhandled CM event <%d>", event->event);
		result = -EINVAL;
	}
	/*
	 * if a socket was found, release the lock, and put the reference.
	 */
	if (conn) {
		if (result < 0 && event->event != IB_CM_TIMEWAIT_EXIT) {
			sdp_dbg_warn(conn,
				     "CM state <%d> event <%d> error <%d>",
				     cm_id->state, event->event, result);
			/*
			 * dump connection state if it is being recorded.
			 */
			sdp_conn_state_dump(conn);
		}

		sdp_conn_unlock(conn);
		sdp_conn_put(conn);
	}

	return result;
}

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
 * $Id: sdp_actv.c 3465 2005-09-18 08:27:39Z mst $
 */

#include "sdp_main.h"

/*
 * Connection establishment functions
 */
void sdp_cm_actv_error(struct sdp_sock *conn, int error)
{
	int result;
	struct sock *sk;
	/*
	 * Handle errors within active connections stream.
	 * First generate appropriate response, REJ, DREQ or nothing.
	 * Second the socket must be notified of the error.
	 */
	switch (conn->state) {
	default:
		sdp_dbg_warn(conn, "Error in unknown connection state");
	case SDP_CONN_ST_REQ_SENT:
	case SDP_CONN_ST_REQ_PATH:
		/*
		 * CM message was never sent.
		 */
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_ERROR);
	case SDP_CONN_ST_ERROR:
	case SDP_CONN_ST_CLOSED:
		break;
	case SDP_CONN_ST_REP_RECV:
		/*
		 * All four states we have gotten a REP and are now in
		 * one of these states.
		 */
		result = ib_send_cm_rej(conn->cm_id,
					IB_CM_REJ_CONSUMER_DEFINED,
					NULL, 0, NULL, 0);

		if (result < 0)
			sdp_dbg_warn(conn, "Error <%d> sending CM REJ.",
				     result);

		SDP_CONN_ST_SET(conn, SDP_CONN_ST_ERROR);
		break;
	case SDP_CONN_ST_ESTABLISHED:
		/*
		 * Made it all the way to established, need to initiate a
		 * full disconnect.
		 */
		result = ib_send_cm_dreq(conn->cm_id, NULL, 0);
		if (result < 0)
			sdp_dbg_warn(NULL, "Error <%d> sending CM DREQ",
				     result);

		SDP_CONN_ST_SET(conn, SDP_CONN_ST_TIME_WAIT_1);
		break;
	}

	conn->shutdown = SHUTDOWN_MASK;
	conn->send_buf = 0;

	sk = sk_sdp(conn);
	sk->sk_err = -error;

	if (sk->sk_socket)
		sk->sk_socket->state = SS_UNCONNECTED;

	sdp_iocb_q_cancel_all(conn, error);
	sk->sk_error_report(sk);
}

/*
 * sdp_cm_actv_establish - process an accepted connection request.
 */
static int sdp_cm_actv_establish(struct sdp_sock *conn)
{
	struct ib_qp_attr *qp_attr;
	int attr_mask = 0;
	struct sock *sk;
	int result;

	sdp_dbg_ctrl(conn, "active establish. src <%08x:%04x> dst <%08x:%04x>",
		     conn->src_addr, conn->src_port,
		     conn->dst_addr, conn->dst_port);

	sk = sk_sdp(conn);

	qp_attr = kmalloc(sizeof(*qp_attr), GFP_KERNEL);
	if (!qp_attr)
		return -ENOMEM;
	/*
	 * modify QP to RTR
	 */
	qp_attr->qp_state = IB_QPS_RTR;

	result = ib_cm_init_qp_attr(conn->cm_id, qp_attr, &attr_mask);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> QP attributes for RTR", result);
		goto done;
	}

	qp_attr->rq_psn        = conn->rq_psn;

	attr_mask |= IB_QP_RQ_PSN;

	result = ib_modify_qp(conn->qp, qp_attr, attr_mask);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> QP modify to RTR", result);
		goto done;
	}
	/*
	 * post receive buffers.
	 */
	result = sdp_recv_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting recv buffers.", result);
		goto done;
	}
	/*
	 * modify QP to RTS
	 */
	qp_attr->qp_state = IB_QPS_RTS;

	result = ib_cm_init_qp_attr(conn->cm_id, qp_attr, &attr_mask);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> QP attributes for RTS", result);
		goto done;
	}

	result = ib_modify_qp(conn->qp, qp_attr, attr_mask);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> QP modify to RTS", result);
		goto done;
	}
	/*
	 * respond to the remote connection manager with a RTU
	 */
	result = ib_send_cm_rtu(conn->cm_id, NULL, 0);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> sending CM RTU.", result);
		goto done;
	}
	/*
	 * wake the accepting connection
	 */
	SDP_CONN_ST_SET(conn, SDP_CONN_ST_ESTABLISHED);

	sk->sk_socket->state = SS_CONNECTED;
	conn->send_buf = SDP_INET_SEND_SIZE;
	/*
	 * release disconnects.
	 */
	conn->flags &= ~SDP_CONN_F_DIS_HOLD;

	inet_sk(sk)->saddr     = htonl(conn->src_addr);
	inet_sk(sk)->rcv_saddr = htonl(conn->src_addr);

	result = sdp_send_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing receives.", result);
		goto done;
	}
	/*
	 * write/read ready. (for those waiting on just one...)
	 */
	sk->sk_write_space(sk);
	sk->sk_data_ready(sk, 0);

	result = 0;
done:
	kfree(qp_attr);
	return result;
}

/*
 * sdp_cm_hello_ack_check - validate the hello ack header
 */
static int sdp_cm_hello_ack_check(struct sdp_msg_hello_ack *hello_ack)
{
	/*
	 * endian swap
	 */
	sdp_msg_net_to_cpu_bsdh(&hello_ack->bsdh);
	sdp_msg_net_to_cpu_hah(&hello_ack->hah);
	/*
	 * validation and consistency checks
	 */
	if (hello_ack->bsdh.size != sizeof(struct sdp_msg_hello_ack)) {
		sdp_dbg_warn(NULL, "hello ack, size mismatch. (2) <%d:%Zu>",
			     hello_ack->bsdh.size,
			     sizeof(struct sdp_msg_hello_ack));
		return -EINVAL;
	}

	if (SDP_MID_HELLO_ACK != hello_ack->bsdh.mid) {
		sdp_dbg_warn(NULL, "hello ack, unexpected message. <%d>",
			     hello_ack->bsdh.mid);
		return -EINVAL;
	}

	if (hello_ack->hah.max_adv <= 0) {
		sdp_dbg_warn(NULL, "hello ack, bad zcopy advertisment. <%d>",
			     hello_ack->hah.max_adv);
		return -EINVAL;
	}

	if ((0xF0 & hello_ack->hah.version) != (0xF0 & SDP_MSG_VERSION)) {
		sdp_dbg_warn(NULL, "hello ack, version mismatch. <%d:%d>",
			     (0xF0 & hello_ack->hah.version) >> 4,
			     (0xF0 & SDP_MSG_VERSION) >> 4);
		return -EINVAL;
	}

	sdp_dbg_ctrl(NULL, "Hello Ack BSDH <%04x:%02x:%02x:%08x:%08x:%08x>",
		     hello_ack->bsdh.recv_bufs,
		     hello_ack->bsdh.flags,
		     hello_ack->bsdh.mid,
		     hello_ack->bsdh.size,
		     hello_ack->bsdh.seq_num,
		     hello_ack->bsdh.seq_ack);
	sdp_dbg_ctrl(NULL, "Hello Ack HAH <%02x:%02x:%08x>",
		     hello_ack->hah.max_adv,
		     hello_ack->hah.version,
		     hello_ack->hah.l_rcv_size);

	return 0; /* success */
}

/*
 * sdp_cm_rep_handler - handler for active connection open completion
 */
int sdp_cm_rep_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event,
		       struct sdp_sock *conn)
{
	struct sdp_msg_hello_ack *hello_ack;
	int result = -ECONNRESET;

	if (cm_id != conn->cm_id) {
		sdp_dbg_warn(conn, "REP comm ID mismatch. <%08x:%08x>",
			     conn->cm_id->local_id, cm_id->local_id);
		return -EINVAL;
	}

	hello_ack = (struct sdp_msg_hello_ack *)event->private_data;

	sdp_dbg_ctrl(conn, "CM REP. comm <%08x>", cm_id->local_id);

	if (conn->state != SDP_CONN_ST_REQ_SENT)
		goto error;

	SDP_CONN_ST_SET(conn, SDP_CONN_ST_REP_RECV);
	/*
	 * check Hello Header Ack, to determine if we want
	 * the connection.
	 */
	result = sdp_cm_hello_ack_check(hello_ack);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> hello ack check.", result);
		goto error;
	}

	/*
	 * read remote information
	 */
	conn->send_size = hello_ack->hah.l_rcv_size;
	conn->r_max_adv = hello_ack->hah.max_adv;
	conn->r_recv_bf = hello_ack->bsdh.recv_bufs;
	conn->recv_seq  = hello_ack->bsdh.seq_num;
	conn->advt_seq  = hello_ack->bsdh.seq_num;

	conn->d_qpn  = event->param.rep_rcvd.remote_qpn;
	/*
	 * The maximum amount of data that can be sent to the remote
	 * peer is the smaller of the local and remote buffer sizes,
	 * minus the size of the message header.
	 */
	conn->send_size = min((u16)sdp_buff_pool_buff_size(),
			      (u16)conn->send_size) - SDP_MSG_HDR_SIZE;
	/*
	 * Pop the hello message that was sent
	 */
	sdp_buff_pool_put(sdp_buff_q_get_head(&conn->send_post));

	result = sdp_cm_actv_establish(conn);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> accept receive failed", result);
		goto error;
	}

	return 0;
error:
	sdp_cm_actv_error(conn, result);

	if (conn->state == SDP_CONN_ST_CLOSED) {
		conn->cm_id = NULL;
		sdp_conn_put_light(conn); /* CM reference */

		return -EPROTO;
	}

	return 0;
}

/*
 * sdp_cm_path_complete - path lookup complete, initiate SDP connection
 */
static void sdp_cm_path_complete(u64 id, int status, u32 dst_addr, u32 src_addr,
				 u8 hw_port, struct ib_device *ca,
				 struct ib_sa_path_rec *path, void *arg)
{
	struct ib_cm_req_param param;
	struct sdp_msg_hello *hello_msg;
	struct sdp_sock *conn = (struct sdp_sock *) arg;
	struct sdpc_buff *buff;
	int result = 0;
	/*
	 * lock the socket
	 */
	sdp_conn_lock(conn);
	/*
	 * path lookup is complete
	 */
	if (id != conn->plid) {
		sdp_dbg_warn(conn, "Path record ID mismatch <%016llx:%016llx>",
			     (unsigned long long)id,
			     (unsigned long long)conn->plid);
		goto done;
	}

	if (conn->state != SDP_CONN_ST_REQ_PATH) {
		status = -EPROTO;
		goto failed;
	}

	conn->plid = 0;
	/*
	 * update addresses.
	 */
	conn->src_addr = ntohl(src_addr);
	conn->dst_addr = ntohl(dst_addr);
	/*
	 * create address handle
	 */
	if (status) {
		sdp_dbg_warn(conn, "Path record completion error <%d>",
			     status);
		goto failed;
	}

	status = -ENOMEM; /* incase error path is taken */

	sdp_dbg_ctrl(conn, "Path record lookup complete <%016llx:%016llx:%d>",
		     (unsigned long long)
		     cpu_to_be64(path->dgid.global.subnet_prefix),
		     (unsigned long long)
		     cpu_to_be64(path->dgid.global.interface_id),
		     path->dlid);
	/*
	 * allocate IB resources.
	 */
	result = sdp_conn_alloc_ib(conn, ca, hw_port, path->pkey);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> allocating IB connection",
			     result);
		goto failed;
	}
	/*
	 * create the hello message . (don't need to worry about header
	 * space reservation)
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "Failed to allocate buff for Hello Msg.");
		goto failed;
	}

	hello_msg = (struct sdp_msg_hello *)buff->data;
	buff->tail = buff->data + sizeof(struct sdp_msg_hello);

	memset(hello_msg, 0, sizeof(struct sdp_msg_hello));

	conn->l_advt_bf = conn->recv_cq_size;
	conn->l_max_adv = SDP_MSG_MAX_ADVS;

	hello_msg->bsdh.recv_bufs = conn->l_advt_bf;
	hello_msg->bsdh.flags     = SDP_MSG_FLAG_NON_FLAG;
	hello_msg->bsdh.mid       = SDP_MID_HELLO;
	hello_msg->bsdh.size      = sizeof(struct sdp_msg_hello);
	hello_msg->bsdh.seq_num   = conn->send_seq;
	hello_msg->bsdh.seq_ack   = conn->advt_seq;

	hello_msg->hh.max_adv       = conn->l_max_adv;
	hello_msg->hh.ip_ver        = SDP_MSG_IPVER;
	hello_msg->hh.version       = SDP_MSG_VERSION;
	hello_msg->hh.r_rcv_size    = conn->recv_size;
	hello_msg->hh.l_rcv_size    = conn->recv_size;
	hello_msg->hh.port          = conn->src_port;
	hello_msg->hh.src.ipv4.addr = conn->src_addr;
	hello_msg->hh.dst.ipv4.addr = conn->dst_addr;

	memcpy(&conn->d_gid, &path->dgid, sizeof(union ib_gid));

	conn->d_lid = path->dlid;
	conn->s_lid = path->slid;
	/*
	 * endian swap
	 */
	sdp_msg_cpu_to_net_bsdh(&hello_msg->bsdh);
	sdp_msg_cpu_to_net_hh(&hello_msg->hh);
	/*
	 * save message
	 */
	sdp_buff_q_put_tail(&conn->send_post, buff);
#if 1
	/*
	 * Mellanox performance bug workaround.
	 */
	if (path->mtu > IB_MTU_1024)
		path->mtu = IB_MTU_1024;
#endif
	conn->path_mtu = path->mtu;
	/*
	 * set QP/CM parameters.
	 */
	memset(&param, 0, sizeof param);

	param.qp_num           = conn->qp->qp_num;
	param.qp_type	       = conn->qp->qp_type;
	param.srq	       = (conn->qp->srq != NULL);
	param.primary_path     = path;
	param.alternate_path   = NULL;
	param.service_id       = cpu_to_be64(SDP_PORT_TO_SID(conn->dst_port));
	param.starting_psn     = conn->rq_psn;
        param.private_data     = (void *)hello_msg;
	/*
	 * no endian swap needed for single byte values.
	 */
        param.private_data_len           = (u8)(buff->tail - buff->data);
        param.responder_resources        = 4;
        param.initiator_depth            = 4;
        param.remote_cm_response_timeout = 20;
        param.flow_control               = 1;
        param.local_cm_response_timeout  = 20;
        param.retry_count                = SDP_CM_PARAM_RETRY;
        param.rnr_retry_count            = SDP_CM_PARAM_RNR_RETRY;
        param.max_cm_retries             = 7;
#if 0
	/* XXX set timeout to default value of 14 */
	path->packet_life = 13;
#endif
	conn->cm_id = ib_create_cm_id(ca, sdp_cm_event_handler,
				      hashent_arg(conn->hashent));
	if (!conn->cm_id) {
		sdp_dbg_warn(conn, "Failed to create CM handle, %d",
			     (u8)(buff->tail - buff->data));
		goto failed;
	}

	/*
	 * initiate connection
	 */
	result = ib_send_cm_req(conn->cm_id, &param);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> CM connect request", result);
		status = result;
		goto failed;
	}

	SDP_CONN_ST_SET(conn, SDP_CONN_ST_REQ_SENT);
	sdp_conn_hold(conn); /* CM reference */

	goto done;
failed:
	sdp_cm_actv_error(conn, status);
done:
	sdp_conn_unlock(conn);
	sdp_conn_put(conn); /* address resolution reference */
}

/*
 * sdp_cm_connect - initiate a SDP connection with a hello message.
 */
int sdp_cm_connect(struct sdp_sock *conn)
{
	int result;
	/*
	 * get the buffer size we'll use for this connection. (and all others)
	 */
	if (sizeof(struct sdp_msg_hello) > conn->recv_size) {
		sdp_dbg_warn(conn, "buffer size <%d> too small. <%Zu>",
			     conn->recv_size, sizeof(struct sdp_msg_hello));
		return -ENOBUFS;
	}

	SDP_CONN_ST_SET(conn, SDP_CONN_ST_REQ_PATH);
	/*
	 * lookup the remote address
	 */
	sdp_conn_hold(conn); /* address resolution reference */
	sdp_conn_unlock(conn);

	result = sdp_link_path_lookup(htonl(conn->dst_addr),
				      htonl(conn->src_addr),
				      sk_sdp(conn)->sk_bound_dev_if,
				      sdp_cm_path_complete,
				      conn,
				      &conn->plid);
	sdp_conn_lock(conn);

	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> getting link <%08x:%08x> addr",
			     result,
			     htonl(conn->dst_addr),
			     htonl(conn->src_addr));
		/*
		 * callback dosn't have this socket.
		 */
		sdp_conn_put_light(conn); /* address resolution reference */

		return -EDESTADDRREQ;
	}

	return 0;
}

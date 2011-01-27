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
 * $Id: sdp_pass.c 3482 2005-09-19 17:46:19Z mst $
 */

#include "sdp_main.h"

/*
 * handle incoming passive connection establishment. (RTU)
 */
int sdp_cm_pass_establish(struct sdp_sock *conn)
{
        struct ib_qp_attr *qp_attr;
	int attr_mask = 0;
	struct sock *sk;
	int result;

	sdp_dbg_ctrl(conn, "Passive Establish src <%08x:%04x> dst <%08x:%04x>",
		     conn->src_addr, conn->src_port,
		     conn->dst_addr, conn->dst_port);
	/*
	 * free hello ack message
	 */
	sdp_buff_pool_put(sdp_buff_q_get_head(&conn->send_post));

        qp_attr = kmalloc(sizeof(*qp_attr), GFP_KERNEL);
        if (!qp_attr) {
                result = -ENOMEM;
		goto done;
        }

        memset(qp_attr, 0, sizeof(*qp_attr));
	qp_attr->qp_state = IB_QPS_RTS;

	result = ib_cm_init_qp_attr(conn->cm_id, qp_attr, &attr_mask);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> QP attributes for RTS", result);
		goto error;
	}

        result = ib_modify_qp(conn->qp, qp_attr, attr_mask);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> modifying QP to RTS", result);
		goto error;
	}

	conn->send_buf = SDP_INET_SEND_SIZE;

	result = sdp_send_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing sends.", result);
		goto error;
	}

	result = sdp_recv_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing receives.", result);
		goto error;
	}

	sk = sk_sdp(conn);
	sk->sk_write_space(sk);

        kfree(qp_attr);
	return 0;
error:
        kfree(qp_attr);
done:
	sdp_conn_inet_error(conn, result);
	return result;
}
/*
 * Functions to handle incoming passive connection requests. (REQ)
 */
static int sdp_cm_accept(struct sdp_sock *conn)
{
	struct ib_cm_rep_param param;
	struct sdp_msg_hello_ack *hello_ack;
	struct sdpc_buff *buff;
	struct ib_qp_attr *qp_attr;
	int qp_mask = 0;
	int result;
	/*
	 * Accept connection, build listen response headers and send
	 * a REP message to remote peer.
	 */
	if (sizeof(struct sdp_msg_hello_ack) > conn->recv_size) {
		sdp_dbg_warn(conn, "buffer size <%d> too small. <%Zu>",
			     conn->recv_size,
			     sizeof(struct sdp_msg_hello_ack));
		result = -ENOBUFS;
		goto error;
	}
	/*
	 * get a buffer, in which we will create the hello header ack.
	 * (don't need to worry about header space reservation on sends)
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "Failed to allocate buff for Hello Ack.");
		result = -ENOMEM;
		goto error;
	}

	hello_ack = (struct sdp_msg_hello_ack *)buff->data;
	buff->tail = buff->data + sizeof(struct sdp_msg_hello_ack);
	/*
	 * create the message
	 */
	memset(hello_ack, 0, sizeof(struct sdp_msg_hello_ack));

	conn->l_advt_bf = conn->recv_cq_size;
	conn->l_max_adv = SDP_MSG_MAX_ADVS;

	hello_ack->bsdh.recv_bufs = conn->l_advt_bf;
	hello_ack->bsdh.flags     = SDP_MSG_FLAG_NON_FLAG;
	hello_ack->bsdh.mid       = SDP_MID_HELLO_ACK;
	hello_ack->bsdh.size      = sizeof(struct sdp_msg_hello_ack);
	hello_ack->bsdh.seq_num   = conn->send_seq;
	hello_ack->bsdh.seq_ack   = conn->advt_seq;

	hello_ack->hah.max_adv    = conn->l_max_adv;
	hello_ack->hah.version    = SDP_MSG_VERSION;
	hello_ack->hah.l_rcv_size = conn->recv_size;
	/*
	 * endian swap
	 */
	sdp_msg_cpu_to_net_bsdh(&hello_ack->bsdh);
	sdp_msg_cpu_to_net_hah(&hello_ack->hah);
	/*
	 * save message
	 */
	sdp_buff_q_put_tail(&conn->send_post, buff);
	/*
	 * modify QP. INIT->RTR
	 */
        qp_attr = kmalloc(sizeof(*qp_attr), GFP_KERNEL);
        if (!qp_attr) {
		sdp_dbg_warn(conn, "Failed to allocate QP attribute.");
                result = -ENOMEM;
		goto error;
        }

        memset(qp_attr, 0, sizeof(*qp_attr));

	qp_attr->qp_state = IB_QPS_RTR;

	result = ib_cm_init_qp_attr(conn->cm_id, qp_attr, &qp_mask);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> QP attributes for RTR",
			     result);
		goto error;
	}

	qp_attr->rq_psn        = conn->rq_psn;

        qp_mask |= IB_QP_RQ_PSN;

        result = ib_modify_qp(conn->qp, qp_attr, qp_mask);
	kfree(qp_attr);

	if (result) {
		sdp_dbg_warn(conn, "Error <%d> modifying QP to RTR.", result);
		goto error;
        }
	/*
	 * Post receive buffers for this connection
	 */
	result = sdp_recv_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing receive queue",
			     result);
		goto error;
	}
	/*
	 * send REP message to remote CM to continue connection.
	 */
	param.qp_num              = conn->qp->qp_num;
	param.srq		  = (conn->qp->srq != NULL);
	param.starting_psn        = conn->rq_psn;
	param.private_data        = hello_ack;
	/*
	 * no endian swap needed for single byte values.
	 */
	param.private_data_len    = (u8)(buff->tail - buff->data);
	param.responder_resources = 4;
	param.initiator_depth     = 4;
	param.target_ack_delay    = 14;
	param.failover_accepted   = 0;
	param.flow_control        = 1;
	param.rnr_retry_count     = SDP_CM_PARAM_RNR_RETRY;

	result = ib_send_cm_rep(conn->cm_id, &param);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> CM accept request.", result);
		goto error;
	}

	return 0;
error:
	return result;
}

static void sdp_cm_listen_inherit(struct sdp_sock *parent,
				  struct sdp_sock *child)
{
	struct sock *psk;
	struct sock *csk;

	sdp_inet_port_inherit(parent, child);

	psk = sk_sdp(parent);
	csk = sk_sdp(child);
	/*
	 * insert accept socket into listen sockets list.
	 * TODO: needs to be a FIFO not a LIFO, as is now.
	 */
	inet_sk(csk)->num       = child->src_port;
	inet_sk(csk)->sport     = htons(child->src_port);
	inet_sk(csk)->rcv_saddr = htonl(child->src_addr);
	inet_sk(csk)->saddr     = htonl(child->src_addr);
	inet_sk(csk)->daddr     = htonl(child->dst_addr);
	inet_sk(csk)->dport     = htons(child->dst_port);
	/*
	 * relevant options, and others... TCP does a full copy, I'd like to
	 * know what I'm inheriting.
	 */
	csk->sk_lingertime   = psk->sk_lingertime;
	csk->sk_rcvlowat     = psk->sk_rcvlowat;
	csk->sk_sndbuf       = psk->sk_sndbuf;
	csk->sk_rcvbuf       = psk->sk_rcvbuf;
	csk->sk_no_check     = psk->sk_no_check;
	csk->sk_priority     = psk->sk_priority;
	csk->sk_rcvtimeo     = psk->sk_rcvtimeo;
	csk->sk_sndtimeo     = psk->sk_sndtimeo;
	csk->sk_reuse        = psk->sk_reuse;
	csk->sk_bound_dev_if = psk->sk_bound_dev_if;
	csk->sk_userlocks   |= (psk->sk_userlocks & ~SOCK_BINDPORT_LOCK);
	csk->sk_flags        = ((SOCK_URGINLINE|SOCK_LINGER|SOCK_BROADCAST) &
				psk->sk_flags);

	csk->sk_debug        = psk->sk_debug;
	csk->sk_localroute   = psk->sk_localroute;
	csk->sk_rcvtstamp    = psk->sk_rcvtstamp;

	child->src_zthresh = parent->src_zthresh;
	child->snk_zthresh = parent->snk_zthresh;
	child->nodelay     = parent->nodelay;
}

static int sdp_cm_hello_check(struct sdp_msg_hello *msg_hello)
{
	/*
	 * endian swap
	 */
	sdp_msg_net_to_cpu_bsdh(&msg_hello->bsdh);
	sdp_msg_net_to_cpu_hh(&msg_hello->hh);
	/*
	 * validation and consistency checks
	 */
	if (msg_hello->bsdh.size != sizeof(struct sdp_msg_hello)) {
		sdp_dbg_warn(NULL, "hello msg size mismatch. (2) <%d:%Zu>",
			     msg_hello->bsdh.size,
			     sizeof(struct sdp_msg_hello));
		return -EINVAL;
	}

	if (SDP_MID_HELLO != msg_hello->bsdh.mid) {
		sdp_dbg_warn(NULL, "hello msg unexpected ID. <%d>",
			     msg_hello->bsdh.mid);
		return -EINVAL;
	}

	if (msg_hello->hh.max_adv <= 0) {
		sdp_dbg_warn(NULL, "hello msg, bad zcopy count <%d>",
			     msg_hello->hh.max_adv);
		return -EINVAL;
	}

	if ((0xF0 & msg_hello->hh.version) != (0xF0 & SDP_MSG_VERSION)) {
		sdp_dbg_warn(NULL, "hello msg, version mismatch. <%d:%d>",
			     (0xF0 & msg_hello->hh.version) >> 4,
			     (0xF0 & SDP_MSG_VERSION) >> 4);
		return -EINVAL;
	}
#ifdef _SDP_MS_APRIL_ERROR_COMPAT
	if ((SDP_MSG_IPVER & 0x0F) != (msg_hello->hh.ip_ver & 0x0F)) {
#else
	if ((SDP_MSG_IPVER & 0xF0) != (msg_hello->hh.ip_ver & 0xF0)) {
#endif
		sdp_dbg_warn(NULL, "hello msg, ip version mismatch. <%d:%d>",
			     msg_hello->hh.ip_ver, SDP_MSG_IPVER);
		return -EINVAL;
	}

	sdp_dbg_ctrl(NULL, "Hello BSDH <%04x:%02x:%02x:%08x:%08x:%08x>",
		     msg_hello->bsdh.recv_bufs,
		     msg_hello->bsdh.flags,
		     msg_hello->bsdh.mid,
		     msg_hello->bsdh.size,
		     msg_hello->bsdh.seq_num,
		     msg_hello->bsdh.seq_ack);
	sdp_dbg_ctrl(NULL,
		     "Hello HH <%02x:%02x:%02x:%08x:%08x:%04x:%08x:%08x>",
		     msg_hello->hh.max_adv,
		     msg_hello->hh.ip_ver,
		     msg_hello->hh.version,
		     msg_hello->hh.r_rcv_size,
		     msg_hello->hh.l_rcv_size,
		     msg_hello->hh.port,
		     msg_hello->hh.src.ipv4.addr,
		     msg_hello->hh.dst.ipv4.addr);

	return 0; /* success */
}

int sdp_cm_req_handler(struct ib_cm_id *cm_id, struct ib_cm_event *event)
{
	struct sdp_msg_hello *msg_hello = event->private_data;
	struct sdp_sock *listen_conn;
	struct sdp_sock *conn;
	struct sock *sk;
	int result;
	u16 port;
	u32 addr;

	sdp_dbg_ctrl(NULL,
		     "CM REQ. comm <%08x> SID <%016llx> ca <%s> port <%d>",
		     cm_id->local_id, (unsigned long long)cm_id->service_id,
		     cm_id->device->name, event->param.req_rcvd.port);
	/*
	 * check Hello Header, to determine if we want the connection.
	 */
	result = sdp_cm_hello_check(msg_hello);
	if (result < 0) {
		sdp_dbg_warn(NULL, "Error <%d> validating hello msg. <%08x>",
			     result, cm_id->local_id);
		goto empty;
	}

	port = SDP_SID_TO_PORT(be64_to_cpu(cm_id->service_id));
	addr = msg_hello->hh.dst.ipv4.addr;
	/*
	 * first find a listening connection, and check backlog
	 */
	result = -ECONNREFUSED;

	listen_conn = sdp_inet_listen_lookup(addr, port);
	if (!listen_conn) {
		/*
		 * no connection, reject
		 */
		sdp_dbg_ctrl(NULL, "no listener for connection. <%08x:%04x>",
			     addr, port);
		goto empty;
	}

	sdp_conn_lock(listen_conn);

	if (listen_conn->state != SDP_CONN_ST_LISTEN)
		goto done;

	if (listen_conn->backlog_cnt > listen_conn->backlog_max) {
		sdp_dbg_ctrl(listen_conn,
			     "Listen backlog <%d> too big to accept new conn",
			     listen_conn->backlog_cnt);
		goto done;
	}
	/*
	 * Create a connection for this request.
	 */
	conn = sdp_conn_alloc(GFP_KERNEL); /* CM sk reference */
	if (!conn) {
		sdp_dbg_warn(NULL, "Failed to allocate connection. <%08x>",
			     cm_id->local_id);
		result = -ENOMEM;
		goto done;
	}
	/*
	 * Lock the new connection before modifying it into any tables.
	 */
	sdp_conn_lock(conn);
	/*
	 * save hello parameters.
	 */
	SDP_CONN_ST_SET(conn, SDP_CONN_ST_REQ_RECV);

	conn->src_addr  = addr;
	conn->src_port  = port;
	conn->dst_addr  = msg_hello->hh.src.ipv4.addr;
	conn->dst_port  = msg_hello->hh.port;

	conn->send_size = msg_hello->hh.l_rcv_size;
	conn->r_max_adv = msg_hello->hh.max_adv;
	conn->r_recv_bf = msg_hello->bsdh.recv_bufs;
	conn->recv_seq  = msg_hello->bsdh.seq_num;
	conn->advt_seq  = msg_hello->bsdh.seq_num;
	/*
	 * The maximum amount of data that can be sent to the remote
	 * peer is the smaller of the local and remote buffer sizes,
	 * minus the size of the message header.
	 */
	conn->send_size = min((u16)sdp_buff_pool_buff_size(),
			      (u16)conn->send_size) - SDP_MSG_HDR_SIZE;

	memcpy(&conn->d_gid,
	       &event->param.req_rcvd.remote_ca_guid,
	       sizeof(conn->d_gid));
	/*
	 * update CM context to refer to the connection, before alloc_ib()
	 */
	conn->cm_id          = cm_id;
	conn->cm_id->context = hashent_arg(conn->hashent);
	/*
	 * associate connection with a hca/port, and allocate IB.
	 */
	result = sdp_conn_alloc_ib(conn,
				   cm_id->device,
				   event->param.req_rcvd.port,
				   event->param.req_rcvd.primary_path->pkey);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> binding connection to HCA/port",
			     result);
		goto error;
	}
	/*
	 * Save connect request info for QP modify in cm_accept().
	 */
	conn->d_lid = event->param.req_rcvd.primary_path->dlid;
	conn->s_lid = event->param.req_rcvd.primary_path->slid;
	conn->d_qpn = event->param.req_rcvd.remote_qpn;

        conn->path_mtu = event->param.req_rcvd.primary_path->mtu;
	/*
	 * inherit listener properties
	 */
	sdp_cm_listen_inherit(listen_conn, conn);
	/*
	 * initiate a CM response message.
	 */
	result = sdp_cm_accept(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> CM connect accept", result);
		goto error;
	}
	/*
	 * place connection into the listen connections accept queue.
	 */
	sdp_inet_accept_q_put(listen_conn, conn);

	sk = sk_sdp(listen_conn);
	sk->sk_data_ready(sk, 0);
	/*
	 * unlock
	 */
	sdp_conn_unlock(conn);
	sdp_conn_unlock(listen_conn);
	sdp_conn_put(listen_conn);	/* ListenLookup reference. */

	return 0;
error:
	SDP_CONN_ST_SET(conn, SDP_CONN_ST_CLOSED);
	conn->cm_id = NULL; /* cm_id destroyed by CM on error result. */
	sdp_conn_unlock(conn);
	sdp_conn_put(conn); /* CM reference */
done:
	sdp_conn_unlock(listen_conn);
	sdp_conn_put(listen_conn);	/* ListenLookup reference. */
empty:
	(void)ib_send_cm_rej(cm_id,
			     IB_CM_REJ_CONSUMER_DEFINED,
			     NULL, 0, NULL, 0);
	return result;
}

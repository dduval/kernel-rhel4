/*
 * Copyright (c) 2005 SilverStorm Technologies, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials
 * provided with the distribution.
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
 */

#include "rds.h"


struct rds_service service;

static void rds_cq_callback(struct ib_cq *cq, void *context)
{
	struct ib_wc wc;
	struct rds_buf *buf;

	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);

	while (ib_poll_cq(cq, 1, &wc) > 0 ) {

		buf = (struct rds_buf*)(unsigned long) wc.wr_id;
		if (!buf || (buf->magic != RDS_MAGIC_BUF) ) {
			printk("rds: completion buffer bad!\n");
			continue;
		}
		switch (buf->optype) {
		case OP_RECV:
			rds_recv_completion(context, &wc);
			break;
		case OP_SEND:
			rds_send_completion(context, &wc);
			break;
		default:
			printk("rds: completion opcode <%d>, optype <%d>\n",
				wc.opcode, buf->optype);

		}
	}
}

static void rds_cq_event_callback(struct ib_event *event, void *data)
{

}

static void rds_qp_event_callback(struct ib_event *event, void *context)
{

	if (event->event == IB_EVENT_COMM_EST) {

		struct rds_session *s;
		struct rds_ep *ep;

		ep = (struct rds_ep*)context;

		if (!ep || ep->magic != RDS_MAGIC_EP)
			return;

		s = (struct rds_session*)ep->parent_session;

		if (!s || s->magic != RDS_MAGIC_SESSION)
			return;

		atomic_set(&ep->state, EP_CONNECTED);

		atomic_set(&s->state, SESSION_ACTIVE);
	}
}

static int rds_cma_init_conn(struct rds_ep *ep)
{
	struct ib_qp_init_attr init_qp_attr;
	int err=0;

	/* Alloc PD */
	ep->pd = ib_alloc_pd(ep->cma_id->device);
	if (IS_ERR(ep->pd)) {
		err = PTR_ERR(ep->pd);
		printk("rds: unable to allocate PD: %d\n", err);
		goto error;
	}


	ep->mr = ib_get_dma_mr(ep->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(ep->mr)) {
		err = PTR_ERR(ep->mr);
		printk("failed to get DMA MR: %d\n", err);
		goto error;
	}

	/* Alloc Recv CQ */
	//ep->recv_cq_len = ep->max_recv_bufs;

	ep->recv_cq = ib_create_cq(ep->cma_id->device,
		rds_cq_callback,
		rds_cq_event_callback,
		ep, ep->max_recv_bufs);

	if (IS_ERR(ep->recv_cq)) {
		err = PTR_ERR(ep->recv_cq);
		printk("rds: unable to create recv CQ: %d\n", err);
		goto error;
	}

	if ((err = ib_req_notify_cq(ep->recv_cq, IB_CQ_NEXT_COMP))) {
		printk("rds: set recv cq notify error\n");
		goto error;
	}
	/* Alloc Send CQ */
	//ep->send_cq_len = ep->max_send_bufs;

	ep->send_cq = ib_create_cq(ep->cma_id->device,
		rds_cq_callback,
		rds_cq_event_callback,
		ep, ep->max_send_bufs);

	if (IS_ERR(ep->send_cq)) {
		err = PTR_ERR(ep->send_cq);
		printk("rds: unable to create recv CQ: %d\n", err);
		goto error;
	}

	if ((err = ib_req_notify_cq(ep->send_cq, IB_CQ_NEXT_COMP))) {
		printk("rds: set send cq notify error\n");
		goto error;
	}

	/* Alloc QP */
	memset(&init_qp_attr, 0, sizeof init_qp_attr);
	init_qp_attr.event_handler = rds_qp_event_callback;
	init_qp_attr.qp_context = (void*) ep;
	init_qp_attr.cap.max_send_wr = ep->max_send_bufs;
	init_qp_attr.cap.max_recv_wr = ep->max_recv_bufs;
	init_qp_attr.cap.max_send_sge = 1;
	init_qp_attr.cap.max_recv_sge = 1;
	//init_qp_attr.sq_sig_type = IB_SIGNAL_ALL_WR;
	init_qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

	init_qp_attr.qp_type = IB_QPT_RC;
	init_qp_attr.send_cq = ep->send_cq;
	init_qp_attr.recv_cq = ep->recv_cq;
	err = rdma_create_qp(ep->cma_id, ep->pd, &init_qp_attr);
	if (err) {
		printk("unable to create QP: %d\n", err);
		goto error;
	}


	/* Allocate Send pool */
	err = rds_alloc_send_pool(ep);
	if (err) {
		printk("unable to allocate send pool: %d\n", err);
		goto error;
	}

	/* Allocate recv pool */
	err = rds_alloc_recv_pool(ep);
	if (err) {
		printk("unable to allocate recv pool: %d\n", err);
		goto error;
	}

	/* Post Recv buffers */
	err = rds_post_recvs_list(ep);
	if (err) {
		printk("unable to pre post recv pool: %d, ep <0x%p>\n", err, ep);
		goto error;
	}

	return 0;
error:

	return err;
}

void rds_cma_cleanup_conn(struct rds_ep *ep)
{
	rds_free_pool(&ep->send_pool);
	rds_free_pool(&ep->recv_pool);

	if (!ep->cma_id || IS_ERR(ep->cma_id))
		return;

	if (ep->cma_id->qp)
		rdma_destroy_qp(ep->cma_id);

	if (ep->recv_cq && !IS_ERR(ep->recv_cq))
		ib_destroy_cq(ep->recv_cq);

	if (ep->send_cq && !IS_ERR(ep->send_cq))
		ib_destroy_cq(ep->send_cq);

	if (ep->pd && !IS_ERR(ep->pd))
		ib_dealloc_pd(ep->pd);

	rdma_destroy_id(ep->cma_id);

}

static void rds_addr_resolved(struct rds_ep *ep)
{
	int err;
	err = rdma_resolve_route(ep->cma_id, RDS_CONNECT_TIMEOUT);
	if (err)
		printk("resolve route failed: %d\n", err);
}

static void rds_connect_est(struct rds_ep *ep)
{
	struct rds_session *s;
	s = (struct rds_session*)ep->parent_session;

	atomic_set(&ep->state, EP_CONNECTED);

	if (atomic_dec_and_test(&s->conn_pend))
		atomic_set(&s->state, SESSION_ACTIVE);

	atomic_inc(&s->disconn_pend);

	wake_up(&ep->event);
}

static void rds_connect_error(struct rds_ep *ep, struct rdma_cm_event *event)
{
	printk("rds: connect_error ep <0x%p>\n", ep);
	atomic_set(&ep->state, EP_DISCONNECTED);
	wake_up(&ep->event);

}

static void rds_route_resolved(struct rds_ep *ep)
{
	struct rdma_conn_param conn_param;
	int err;

	struct rds_cr_prd priv_data;

	/* Allocate PD, CQ, QP, Send pool, Recv Pool and Post recvs */
	err = rds_cma_init_conn(ep);
	if (err) {
		printk("rds: could not init conn, aborting; ep <0x%p>\n",
			ep);
		goto error;
	}

	memset(&conn_param, 0, sizeof(conn_param));

	/* connect private data */
	priv_data.version = RDS_PROTO_VERSION;
	priv_data.dst_addr = ep->dst_addr;
	priv_data.src_addr = ep->src_addr;
	priv_data.mtu = params.mtu;
	priv_data.ep_type = ep->type;

	/* connection parameters */
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 7;
	conn_param.rnr_retry_count = 7;
	conn_param.private_data = &priv_data;
	conn_param.private_data_len = sizeof (priv_data);

	/* connect */
	err = rdma_connect(ep->cma_id, &conn_param);
	if (err) {
		printk("failure connecting: %d\n", err);
		goto error;
	}
	return;
error:
	rds_connect_error(ep, NULL);
	return;
}


static void rds_disconnected(struct rds_ep *ep)
{
	struct rds_session *s;
	s = (struct rds_session*)ep->parent_session;


	atomic_set(&ep->state, EP_DISCONNECTED);
#if 0
	atomic_set(&s->state, SESSION_CLOSE_PENDING);

	if (atomic_dec_and_test(&s->disconn_pend)) {
		atomic_set(&s->state, SESSION_ABRUPT_CLOSE_PENDING);
		rds_queue_session_close(s);
	}
#endif
	wake_up(&ep->event);
}


static int rds_connect_req(struct rdma_cm_id *cma_id,
			   struct rdma_cm_event *event)
{
	struct rds_ep *ep;
	int err=0;
	struct rdma_conn_param conn_param;
	__be64 local_guid, remote_guid;

	/* Get RDS Endpoint for this request */
	local_guid = cma_id->route.path_rec->sgid.global.interface_id;
	remote_guid = cma_id->route.path_rec->dgid.global.interface_id;

	err = rds_ep_connect_req( local_guid, remote_guid,
		(struct rds_cr_prd*)event->private_data,
		&ep);

	if (err) {
		rdma_reject(cma_id, NULL, 0);
		goto error;
	}
	if (!ep) {
		/* set private data */

		rdma_reject(cma_id, NULL, 0);
		goto error;
	}

	ep->cma_id = cma_id;
	cma_id->context = ep;

	/* Allocate PD, CQ, QP, Send pool, Recv Pool and Post recvs */
	err = rds_cma_init_conn(ep);
	if (err)
		goto error;

	/* Accept connection */
	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 7;
	conn_param.rnr_retry_count = 7;
	err = rdma_accept(cma_id, &conn_param);
	if (err) {
		printk("failure accepting: %d\n", err);
		goto error;
	}

	/* Release ref count on this session */
	rds_session_put(ep->parent_session);

	return 0;
error:
	return err;

}
static int rds_cma_cb(struct rdma_cm_id *cma_id, struct rdma_cm_event *event)
{
	int err = 0;

	switch (event->event) {

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		err = rds_connect_req(cma_id, event);
		break;

	case RDMA_CM_EVENT_ADDR_RESOLVED:
		rds_addr_resolved(cma_id->context);
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		rds_route_resolved(cma_id->context);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		rds_connect_est(cma_id->context);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		printk("rds: connection event: %d, error: %d\n", event->event,
			event->status);
		rds_connect_error(cma_id->context, event);
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		rdma_disconnect(cma_id);
		rds_disconnected(cma_id->context);
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		break;
	default:
		break;
	}
	return err;
}

int rds_cma_connect( struct rds_ep *ep)
{
	int err=0;
	struct sockaddr_in src_in, dst_in;

	/* Create CMA id */
	ep->cma_id = rdma_create_id(rds_cma_cb, (void*)ep, RDMA_PS_TCP);

	if (IS_ERR(ep->cma_id)) {
		printk("rds: error <%ld> creating cma ID for connect\n",
			PTR_ERR(ep->cma_id));
		err = PTR_ERR(ep->cma_id);
		goto error;
	}
	src_in.sin_addr = ep->src_addr;
	src_in.sin_family = AF_INET;
	src_in.sin_port = 0;

	dst_in.sin_addr = ep->dst_addr;
	dst_in.sin_family = AF_INET;
	dst_in.sin_port = 6556;

	err = rdma_resolve_addr(ep->cma_id,
				(struct sockaddr *)&src_in,
				(struct sockaddr *)&dst_in,
				RDS_CONNECT_TIMEOUT);
	if (err) {
		printk("rds: failure getting addr <%d>\n", err);
		goto error;
	}
	return 0;
error:
	if (!IS_ERR(ep->cma_id))
		rdma_destroy_id(ep->cma_id);

	return err;
}

int rds_cma_disconnect( struct rds_ep *ep)
{
	int err=0;

	err = rdma_disconnect(ep->cma_id);
	if (err)
		printk("rds: cma failure disconnecting <%d>, ep <0x%p>\n", err,
			ep);
	return err;

}

int
rds_cma_init (void)
{
	int err = 0;

	struct sockaddr_in src_in ={0};

	/* Create CMA id */
	service.listen_id = rdma_create_id(rds_cma_cb,
					(void*)&service, RDMA_PS_TCP);

	if (IS_ERR(service.listen_id)) {
		printk("rds: error <%ld> creating listen ID\n",
			PTR_ERR(service.listen_id));
		goto error;
	}


	/* Bind address */
	src_in.sin_family = AF_INET;
	src_in.sin_addr.s_addr = INADDR_ANY;
	src_in.sin_port = 6556;

	err = rdma_bind_addr(service.listen_id, (struct sockaddr *)&src_in);
	if (err) {
		printk("rds: error <%d> RDS listener bind failed\n", err);
		goto error;
	}

	/* Listen */
	err = rdma_listen(service.listen_id, 0);
	if (err) {
		printk("rds: error <%d> trying to listen\n", err);
		goto error;
	}

	return 0;

error:
	rdma_destroy_id(service.listen_id);

	return err;
}

void rds_cma_exit (void)
{
	rdma_destroy_id(service.listen_id);

}

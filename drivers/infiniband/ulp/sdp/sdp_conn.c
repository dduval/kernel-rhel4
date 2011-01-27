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
 * $Id: sdp_conn.c 3465 2005-09-18 08:27:39Z mst $
 */

#include "sdp_main.h"

static int sdp_zcopy_thrsh_src_default = SDP_ZCOPY_THRSH_SRC_DEFAULT;
module_param(sdp_zcopy_thrsh_src_default, int, 0644);
MODULE_PARM_DESC(sdp_zcopy_thrsh_src_default, "Default ZCopy Threshold for Data Source");
static int sdp_zcopy_thrsh_snk_default = SDP_ZCOPY_THRSH_SNK_DEFAULT;
module_param(sdp_zcopy_thrsh_snk_default, int, 0644);
MODULE_PARM_DESC(sdp_zcopy_thrsh_snk_default, "Default ZCopy Threshold for Data Sink");

static struct sdev_root dev_root_s;

static void sdp_device_init_one(struct ib_device *device);
static void sdp_device_remove_one(struct ib_device *device);

static struct ib_client sdp_client = {
	.name   = "sdp",
	.add    = sdp_device_init_one,
	.remove = sdp_device_remove_one
};

static DEFINE_SPINLOCK(psn_lock);
static u32 psn_seed;

/*
 * module specific functions
 */

/*
 * sdp_psn_generate - generate a PSN for connection management.
 */
static u32 sdp_psn_generate(void)
{
        u32 psn;

	spin_lock(&psn_lock);

        /* 3-shift-register generator with period 2^32-1 */
        psn_seed ^= psn_seed << 13;
        psn_seed ^= psn_seed >> 17;
        psn_seed ^= psn_seed << 5;

        psn = psn_seed & 0xffffff;

        spin_unlock(&psn_lock);

        return psn;
}

void sdp_conn_inet_error(struct sdp_sock *conn, int error)
{
	struct sock *sk;

	sdp_dbg_ctrl(conn, "report connection error <%d>", error);
	/*
	 * the connection has failed, move to error, and notify anyone
	 * waiting of the state change. remove connection from listen
	 * queue if possible.
	 */
	(void)sdp_inet_accept_q_remove(conn);

	SDP_CONN_ST_SET(conn, SDP_CONN_ST_ERROR);
	conn->shutdown = SHUTDOWN_MASK;
	conn->send_buf = 0;

	sk = sk_sdp(conn);
	sk->sk_err = -error;

	if (sk->sk_socket)
		sk->sk_socket->state = SS_UNCONNECTED;

	sdp_iocb_q_cancel_all(conn, error);
	sk->sk_error_report(sk);
}

void sdp_conn_abort(struct sdp_sock *conn)
{
	int result;
	int error = -ECONNRESET;

	sdp_dbg_ctrl(conn, "Abort send. src <%08x:%04x> dst <%08x:%04x>",
		     conn->src_addr, conn->src_port,
		     conn->dst_addr, conn->dst_port);

	switch (conn->state) {
	case SDP_CONN_ST_DIS_SENT_1:	/* IBTA v1.1 spec A4.5.3.2 */
		/*
		 * clear the pending control buffer.
		 */
		sdp_desc_q_clear(&conn->send_ctrl);
		/*
		 * fall through
		 */
	case SDP_CONN_ST_DIS_SEND_2:
	case SDP_CONN_ST_DIS_SEND_1:
		/*
		 * don't touch control queue, diconnect message may
		 * still be queued.
		 */
		sdp_desc_q_clear(&conn->send_queue);
		/*
		 * post abort
		 */
		if (conn->flags & SDP_CONN_F_DIS_PEND)
			result = -ECONNRESET;
		else
			result = sdp_send_ctrl_abort(conn);

		if (!result)
			break;

		conn->flags &= ~SDP_CONN_F_DIS_PEND;
	case SDP_CONN_ST_DIS_RECV_1:
		error = -EPIPE;
	case SDP_CONN_ST_ESTABLISHED:
		/*
		 * abortive close.
		 */
		result = ib_send_cm_dreq(conn->cm_id, NULL, 0);
		if (result)
			sdp_dbg_warn(conn, "Error <%d> CM disconnect send",
				     result);
		break;
	case SDP_CONN_ST_REQ_PATH:
	case SDP_CONN_ST_REQ_SENT:
	case SDP_CONN_ST_REQ_RECV:
		/*
		 * outstanding CM request. Mark it in error, and CM
		 * completion needs to complete the closing.
		 */
		error = -ECONNREFUSED;
		break;
	case SDP_CONN_ST_ERROR:
	case SDP_CONN_ST_CLOSED:
	case SDP_CONN_ST_TIME_WAIT_1:
	case SDP_CONN_ST_TIME_WAIT_2:
		break;
	default:
		/*
		 * post abort
		 */
		sdp_dbg_warn(conn, "Unexpected connection state for abort");
		break;
	}

	sdp_conn_inet_error(conn, error);
	return;
}
/*
 * sdp_inet_accept_q_put - put a conn into a listen conn's accept Q.
 */
void sdp_inet_accept_q_put(struct sdp_sock *listen_conn,
			   struct sdp_sock *accept_conn)
{
	struct sdp_sock *next_conn;

	BUG_ON(listen_conn->parent);
	BUG_ON(accept_conn->parent);
	BUG_ON(!listen_conn->accept_next || !listen_conn->accept_prev);

	next_conn = listen_conn->accept_next;

	accept_conn->accept_next = listen_conn->accept_next;
	listen_conn->accept_next = accept_conn;
	accept_conn->accept_prev = listen_conn;
	next_conn->accept_prev = accept_conn;

	accept_conn->parent = listen_conn;
	listen_conn->backlog_cnt++;
	/*
	 * up ref until we release. One ref for GW and one for INET.
	 */
	sdp_conn_hold(accept_conn); /* AcceptQueue INET reference */
}

/*
 * sdp_inet_accept_q_get - get a conn from a listen conn's accept Q.
 */
struct sdp_sock *sdp_inet_accept_q_get(struct sdp_sock *listen_conn)
{
	struct sdp_sock *prev_conn;
	struct sdp_sock *accept_conn;

	if (listen_conn->parent ||
	    !listen_conn->accept_next ||
	    !listen_conn->accept_prev ||
	    listen_conn == listen_conn->accept_next ||
	    listen_conn == listen_conn->accept_prev)
		return NULL;
	/*
	 * Return the next connection in the listening sockets accept
	 * queue. The new connections lock is acquired, the caller must
	 * unlock the connection before it is done with the connection.
	 * Also the process context lock is used, so the function may
	 * not be called from the CQ interrupt.
	 */
	accept_conn = listen_conn->accept_prev;

	sdp_conn_lock(accept_conn);

	prev_conn = accept_conn->accept_prev;

	listen_conn->accept_prev = accept_conn->accept_prev;
	prev_conn->accept_next = listen_conn;

	accept_conn->accept_next = NULL;
	accept_conn->accept_prev = NULL;
	accept_conn->parent = NULL;

	listen_conn->backlog_cnt--;

	return accept_conn;
}

/*
 * sdp_inet_accept_q_remove - remove a conn from a conn's accept Q.
 */
int sdp_inet_accept_q_remove(struct sdp_sock *accept_conn)
{
	struct sdp_sock *next_conn;
	struct sdp_sock *prev_conn;

	if (!accept_conn->parent)
		return -EFAULT;
	/*
	 * Removes the connection from the listening sockets accept queue.
	 * The listning connections lock must be acquired to access the
	 * list. The process context lock is used, so the function may
	 * not be called from the CQ interrupt.
	 */
	sdp_conn_lock(accept_conn->parent);

	next_conn = accept_conn->accept_next;
	prev_conn = accept_conn->accept_prev;

	prev_conn->accept_next = accept_conn->accept_next;
	next_conn->accept_prev = accept_conn->accept_prev;

	accept_conn->parent->backlog_cnt--;

	sdp_conn_unlock(accept_conn->parent);

	accept_conn->accept_next = NULL;
	accept_conn->accept_prev = NULL;
	accept_conn->parent = NULL;

	sdp_conn_put(accept_conn); /* AcceptQueue INET reference */

	return 0;
}

/*
 * sdp_inet_listen_start - start listening for new connections on a socket
 */
int sdp_inet_listen_start(struct sdp_sock *conn)
{
	unsigned long flags;

	if (conn->state != SDP_CONN_ST_CLOSED) {
		sdp_dbg_warn(conn, "Incorrect connection state to listen.");
		return -EBADFD;
	}

	conn->state  = SDP_CONN_ST_LISTEN;
	conn->accept_next = conn;
	conn->accept_prev = conn;

	spin_lock_irqsave(&dev_root_s.listen_lock, flags);
	list_add(&conn->lstn_next, &dev_root_s.listen_list);
	spin_unlock_irqrestore(&dev_root_s.listen_lock, flags);

	return 0;
}

/*
 * sdp_inet_listen_stop - stop listening for new connections on a socket
 */
int sdp_inet_listen_stop(struct sdp_sock *listen_conn)
{
	struct sdp_sock *accept_conn;
	unsigned long flags;

	if (listen_conn->state != SDP_CONN_ST_LISTEN) {
		sdp_dbg_warn(listen_conn, "Incorrect state to stop listen.");
		return -EBADFD;
	}

	listen_conn->state  = SDP_CONN_ST_CLOSED;

	spin_lock_irqsave(&dev_root_s.listen_lock, flags);
	list_del(&listen_conn->lstn_next);
	spin_unlock_irqrestore(&dev_root_s.listen_lock, flags);

	/*
	 * reject and delete all pending connections
	 */
	while ((accept_conn = sdp_inet_accept_q_get(listen_conn))) {
		/*
		 * The connection is going to be dropped now, mark the
		 * state as such in case of conntension for this conn.
		 * Remember to unlock since the Get function will acquire
		 * the lock.
		 */
		sdp_conn_abort(accept_conn);
		/* AcceptQueueGet */
		sdp_conn_unlock(accept_conn);
		/* INET reference (AcceptQueuePut). */
		sdp_conn_put(accept_conn);
	}

	listen_conn->accept_next = NULL;
	listen_conn->accept_prev = NULL;

	return 0;
}

/*
 * sdp_inet_listen_lookup - lookup a connection in the listen list
 */
struct sdp_sock *sdp_inet_listen_lookup(u32 addr, u16 port)
{
	struct sdp_sock *conn, *ret = NULL;
	unsigned long flags;
	/*
	 * table lock
	 */
	spin_lock_irqsave(&dev_root_s.listen_lock, flags);
	/*
	 * first find a listening connection
	 */
	list_for_each_entry(conn, &dev_root_s.listen_list, lstn_next)
		if (port == conn->src_port &&
		    (INADDR_ANY == conn->src_addr || addr == conn->src_addr)) {
			sdp_conn_hold(conn);
			ret = conn;
			break;
		}

	spin_unlock_irqrestore(&dev_root_s.listen_lock, flags);
	return ret;
}

/*
 * sdp_inet_port_get - bind a socket to a port.
 */
int sdp_inet_port_get(struct sdp_sock *conn, u16 port)
{
	struct sock *sk;
	struct sock *srch;
	struct sdp_sock *look;
	s32 counter;
	s32 low_port;
	s32 top_port;
	int port_ok;
	int result;
	static s32 rover = -1;
	unsigned long flags;

	sk = sk_sdp(conn);
	/*
	 * lock table
	 */
	spin_lock_irqsave(&dev_root_s.bind_lock, flags);
	/*
	 * simple linked list of sockets ordered on local port number.
	 */
	if (port > 0) {
		port_ok = 1;
		list_for_each_entry(look, &dev_root_s.bind_list, bind_next) {
			srch = sk_sdp(look);
			/*
			 * 1) same port
			 * 2) linux force reuse is off.
			 * 3) same bound interface, or neither has a bound
			 *    interface
			 */
			if (look->src_port == port &&
			    !(1 < sk->sk_reuse) &&
			    !(1 < srch->sk_reuse) &&
			    sk->sk_bound_dev_if ==
			    srch->sk_bound_dev_if) {
				/*
				 * 3) either socket has reuse turned off
				 * 4) socket already listening on this port
				 */
				if (!sk->sk_reuse ||
				    !srch->sk_reuse ||
				    look->state == SDP_CONN_ST_LISTEN) {
					/*
					 * 5) neither socket is using a
					 *    specific address
					 * 6) both sockets are trying for the
					 *    same interface.
					 */
					if (INADDR_ANY == conn->src_addr ||
					    INADDR_ANY == look->src_addr ||
					    conn->src_addr == look->src_addr) {

						sdp_dbg_warn(conn,
							     "port rejected. <%04x><%d:%d><%d:%d><%04x><%u:%u>",
							 port,
							 sk->sk_bound_dev_if,
							 srch->sk_bound_dev_if,
							 sk->sk_reuse,
							 srch->sk_reuse,
							 look->state,
							 conn->src_addr,
							 look->src_addr);
						port_ok = 0;
						break;
					}
				}
			}
		}

		if (!port_ok) {
			result = -EADDRINUSE;
			goto done;
		}
	} else {
		low_port = SDP_INET_PORT_LOW;
		top_port = SDP_INET_PORT_HIGH;
		rover = (rover < 0) ? low_port : rover;

		for (counter = (top_port - low_port) + 1; counter > 0;
		     counter--) {
			int found = 0;
			rover++;
			if (rover < low_port || rover > top_port)
				rover = low_port;

			list_for_each_entry(look, &dev_root_s.bind_list,
					    bind_next)
				if (look->src_port == port) {
					found = 1;
					break;
				}

			if (!found) {
				port = rover;
				break;
			}
		}

		if (!port) {
			result = -EADDRINUSE;
			goto done;
		}
	}

	conn->src_port = port;
	/*
	 * insert into bind list.
	 */
	list_add(&conn->bind_next, &dev_root_s.bind_list);

	result = 0;
done:
	spin_unlock_irqrestore(&dev_root_s.bind_lock, flags);
	return result;
}

/*
 * sdp_inet_port_put - unbind a socket from a port.
 */
int sdp_inet_port_put(struct sdp_sock *conn)
{
	unsigned long flags;
	int result = -EADDRNOTAVAIL;

	spin_lock_irqsave(&dev_root_s.bind_lock, flags);
	if (conn->src_port) {
		list_del(&conn->bind_next);
		conn->src_port = 0;
		result = 0;
	}
	spin_unlock_irqrestore(&dev_root_s.bind_lock, flags);

	return result;
}

/*
 * sdp_inet_port_inherit - inherit a port from another socket (accept)
 */
void sdp_inet_port_inherit(struct sdp_sock *parent, struct sdp_sock *child)
{
	unsigned long flags;

	/*
	 * lock table
	 */
	spin_lock_irqsave(&dev_root_s.bind_lock, flags);

	BUG_ON(child->src_port != parent->src_port);
	/*
	 * insert into bind list.
	 */
	list_add(&child->bind_next, &dev_root_s.bind_list);
	spin_unlock_irqrestore(&dev_root_s.bind_lock, flags);
}

/*
 * sdp_conn_table_insert - insert a connection into the connection table
 */
static int sdp_conn_table_insert(struct sdp_sock *conn)
{
	u32 counter;
	int result = -ENOMEM;
	unsigned long flags;

	if (SDP_DEV_SK_INVALID != conn->hashent)
		return -ERANGE;
	/*
	 * lock table
	 */
	spin_lock_irqsave(&dev_root_s.sock_lock, flags);
	/*
	 * find an empty slot.
	 */
	for (counter = 0;
	     counter < dev_root_s.sk_size;
	     counter++, dev_root_s.sk_rover++) {
		if (!(dev_root_s.sk_rover < dev_root_s.sk_size))
			dev_root_s.sk_rover = 0;

		if (!dev_root_s.sk_array[dev_root_s.sk_rover]) {
			dev_root_s.sk_array[dev_root_s.sk_rover] = conn;
			dev_root_s.sk_entry++;
			conn->hashent = dev_root_s.sk_rover;

			result = 0;
			break;
		}
	}

#if 0				/* set for reproducibility from run-run. */
	dev_root_s.sk_rover = 0;
#endif
	/*
	 * unlock table
	 */
	spin_unlock_irqrestore(&dev_root_s.sock_lock, flags);
	return result;
}

/*
 * sdp_conn_table_remove - remove a connection from the connection table
 */
static void sdp_conn_table_remove(struct sdp_sock *conn)
{
	/*
	 * validate entry
	 */
	BUG_ON(SDP_DEV_SK_INVALID == conn->hashent);
	BUG_ON(conn->hashent < 0);
	BUG_ON(conn != dev_root_s.sk_array[conn->hashent]);
	/*
	 * drop entry
	 */
	dev_root_s.sk_array[conn->hashent] = NULL;
	dev_root_s.sk_entry--;
	conn->hashent = SDP_DEV_SK_INVALID;
}

/*
 * sdp_conn_table_lookup - look up connection in the connection table
 */
struct sdp_sock *sdp_conn_table_lookup(s32 entry)
{
	struct sdp_sock *conn;
	unsigned long flags;
	/*
	 * lock table
	 */
	spin_lock_irqsave(&dev_root_s.sock_lock, flags);
#if 0
	/*
	 * validate range
	 */
	if (entry < 0 || entry >= dev_root_s.sk_size) {
		conn = NULL;
		goto done;
	}
#endif

	conn = dev_root_s.sk_array[entry];
	if (!conn)
		goto done;

	sdp_conn_hold(conn);
done:
	spin_unlock_irqrestore(&dev_root_s.sock_lock, flags);
	return conn;
}

/*
 * Functions to cancel IOCB requests in a conenctions queues.
 */
static int sdp_desc_q_cancel_lookup_func(struct sdpc_desc *element, void *arg)
{
	return ((element->type == SDP_DESC_TYPE_IOCB) ? 0 : -ERANGE);
}

static void sdp_desc_q_cancel_iocb(struct sdpc_desc_q *table, ssize_t error)
{
	struct sdpc_iocb *iocb;

	while ((iocb = (struct sdpc_iocb *)sdp_desc_q_lookup
			(table,
			 sdp_desc_q_cancel_lookup_func,
			 NULL))) {

		sdp_iocb_q_remove(iocb);
		sdp_iocb_complete(iocb, error);
	}
}

void sdp_iocb_q_cancel_all_read(struct sdp_sock *conn, ssize_t error)
{
	sdp_iocb_q_cancel(&conn->r_pend, SDP_IOCB_F_ALL, error);
	sdp_iocb_q_cancel(&conn->r_snk, SDP_IOCB_F_ALL, error);

	sdp_desc_q_cancel_iocb(&conn->r_src, error);
}

void sdp_iocb_q_cancel_all_write(struct sdp_sock *conn, ssize_t error)
{
	sdp_iocb_q_cancel(&conn->w_src, SDP_IOCB_F_ALL, error);

	sdp_desc_q_cancel_iocb(&conn->send_queue, error);
	sdp_desc_q_cancel_iocb(&conn->w_snk, error);
}

void sdp_iocb_q_cancel_all(struct sdp_sock *conn, ssize_t error)
{
	sdp_iocb_q_cancel_all_read(conn, error);
	sdp_iocb_q_cancel_all_write(conn, error);
}

/*
 * connection allocation/deallocation
 */

/*
 * sdp_conn_put - reference counting and final destructor for connection.
 */
void sdp_conn_put(struct sdp_sock *conn)
{
	unsigned long flags;
	int dump = 0;
	int result;

	spin_lock_irqsave(&dev_root_s.sock_lock, flags);

	if (!atomic_dec_and_test(&conn->refcnt)) {
		spin_unlock_irqrestore(&dev_root_s.sock_lock, flags);
		return;
	}

	sdp_conn_table_remove(conn);

	spin_unlock_irqrestore(&dev_root_s.sock_lock, flags);

	sdp_dbg_ctrl(conn, "DESTRUCT. <%08x:%04x> <%08x:%04x> <%u:%u>",
		     conn->src_addr, conn->src_port,
		     conn->dst_addr, conn->dst_port,
		     conn->src_serv, conn->snk_serv);
	/*
	 * If the socket is bound, return the port
	 */
	(void)sdp_inet_port_put(conn);

	sdp_conn_stat_dump(conn);
	/*
	 * really there shouldn't be anything in these tables, but it's
	 * really bad if we leave a dangling reference here.
	 */
	sdp_iocb_q_cancel_all(conn, -ECANCELED);
	sdp_iocb_q_clear(&conn->r_pend);
	sdp_iocb_q_clear(&conn->r_snk);
	sdp_iocb_q_clear(&conn->w_src);

	sdp_desc_q_clear(&conn->r_src);
	sdp_desc_q_clear(&conn->w_snk);
	/*
	 * clear the buffer pools
	 */
	sdp_buff_q_clear(&conn->recv_pool);

	if (conn->ca) {
		sdp_buff_q_clear_unmap(&conn->send_post,
				       conn->ca->dma_device,
				       PCI_DMA_TODEVICE);
		sdp_buff_q_clear_unmap(&conn->recv_post,
				       conn->ca->dma_device,
				       PCI_DMA_FROMDEVICE);
	}

	/*
	 * clear advertisment tables
	 */
	sdp_advt_q_clear(&conn->src_pend);
	sdp_advt_q_clear(&conn->src_actv);
	sdp_advt_q_clear(&conn->snk_pend);
	/*
	 * generic table clear
	 */
	sdp_desc_q_clear(&conn->send_ctrl);
	sdp_desc_q_clear(&conn->send_queue);
	/*
	 * If the QP owner is not the CM, then destroy.
	 */
	if (conn->qp) {
		result = ib_destroy_qp(conn->qp);
		if (result < 0 && result != -EINVAL) {
			sdp_dbg_warn(conn, "Error <%d> detroying QP", result);
			dump++;
		}
	}
	/*
	 * destroy CQs
	 */
	if (conn->recv_cq) {
		result = ib_destroy_cq(conn->recv_cq);
		if (result < 0 && result != -EINVAL) {
			sdp_dbg_warn(conn, "Error <%d> detroying recv CQ",
				     result);
			dump++;
		}
	}

	if (conn->send_cq) {
		result = ib_destroy_cq(conn->send_cq);
		if (result < 0 && result != -EINVAL) {
			sdp_dbg_warn(conn, "Error <%d> detroying send CQ",
				     result);
			dump++;
		}
	}
	/*
	 * in case CM/IB are still tracking this connection.
	 */
	if (conn->cm_id) {
		sdp_dbg_warn(conn, "destroying CM ID.");
		ib_destroy_cm_id(conn->cm_id);
	}
	/*
	 * check consistancy
	 */
	if (atomic_read(&conn->refcnt) < 0)
		sdp_dbg_warn(conn, "destruct low ref count <%04x>",
			     atomic_read(&conn->refcnt));

	if (dump)
		sdp_conn_state_dump(conn);
	/*
	 * free the OS socket structure
	 */
	if (!conn->sk)
		sdp_dbg_warn(conn, "destruct, no socket! continuing.");
	else {
		sk_free(conn->sk);
		conn->sk = NULL;
	}

	kmem_cache_free(dev_root_s.conn_cache, conn);
}

/*
 * sdp_conn_internal_lock - lock the connection (use only from macro)
 */
void sdp_conn_internal_lock(struct sdp_sock *conn, unsigned long *flags)
{
	DECLARE_WAITQUEUE(wait, current);
	unsigned long f = *flags;

	add_wait_queue_exclusive(&(conn->lock.waitq), &wait);
	for (;;) {
		current->state = TASK_UNINTERRUPTIBLE;
		spin_unlock_irqrestore(&(conn->lock.slock), f);
		schedule();
		spin_lock_irqsave(&(conn->lock.slock), f);
		*flags = f;

		if (!conn->lock.users)
			break;
	}

	current->state = TASK_RUNNING;
	remove_wait_queue(&(conn->lock.waitq), &wait);
}

/*
 * sdp_conn_relock - test the connection (use only from macro)
 */
void sdp_conn_relock(struct sdp_sock *conn)
{
	unsigned long flags;
	struct ib_wc entry;
	int result_r;
	int result_s;
	int result;
	int rearm = 1;

	spin_lock_irqsave(&conn->lock.slock, flags);

	while (1) {
		result_r = ib_poll_cq(conn->recv_cq, 1, &entry);
		if (1 == result_r) {
			result = sdp_cq_event_locked(&entry, conn);
			if (result < 0)
				sdp_dbg_warn(conn,
					     "Error <%d> from event handler.",
					     result);

			rearm = 1;
		}

		result_s = ib_poll_cq(conn->send_cq, 1, &entry);
		if (1 == result_s) {
			result = sdp_cq_event_locked(&entry, conn);
			if (result < 0)
				sdp_dbg_warn(conn,
					     "Error <%d> from event handler.",
					     result);
			rearm = 1;
		}

		if (result_r || result_s)
			continue;

		if (rearm > 0) {
			result = ib_req_notify_cq(conn->recv_cq,
						  IB_CQ_NEXT_COMP);
			if (result)
				sdp_dbg_warn(conn,
					     "Error <%d> rearming recv CQ",
					     result);

			result = ib_req_notify_cq(conn->send_cq,
						  IB_CQ_NEXT_COMP);
			if (result)
				sdp_dbg_warn(conn,
					     "Error <%d> rearming send CQ",
					     result);

			rearm = 0;
		} else
			break;  /* exit CQ handler routine */
	}

	conn->lock.event = 0;

	spin_unlock_irqrestore(&conn->lock.slock, flags);
}

/*
 * sdp_conn_cq_drain - drain one of the the connection's CQs
 */
int sdp_conn_cq_drain(struct ib_cq *cq, struct sdp_sock *conn)
{
	struct ib_wc entry;
	int result;
	int rearm = 1;
	int calls = 0;
	/*
	 * the function should only be called under the connection locks
	 * spinlock to ensure the call is serialized to avoid races.
	 */
	for (;;) {
		/*
		 * poll for a completion
		 */
		result = ib_poll_cq(cq, 1, &entry);
		if (1 == result) {
			/*
			 * dispatch completion, and mark that the CQ needs
			 * to be armed.
			 */
			result = sdp_cq_event_locked(&entry, conn);
			if (result < 0)
				sdp_dbg_warn(conn, "Error <%d> event handler.",
					     result);

			rearm = 1;
			calls++;

			continue;
		}

		if (!result) {
			if (rearm > 0) {
				result = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
				if (result)
					sdp_dbg_warn(conn,
						     "Error <%d> rearming CQ",
						     result);
				rearm = 0;
			} else
				break; /* exit CQ handler routine */
		} else
			sdp_dbg_warn(conn, "Unexpected error <%d> from CQ",
				     result);
	}

	return calls;
}

/*
 * sdp_conn_internal_unlock - lock the connection (use only from macro)
 */
void sdp_conn_internal_unlock(struct sdp_sock *conn)
{
	int calls = 0;
	/*
	 * poll CQs for events.
	 */
	if (conn->lock.event & SDP_LOCK_F_RECV_CQ)
		calls += sdp_conn_cq_drain(conn->recv_cq, conn);

	if (conn->lock.event & SDP_LOCK_F_SEND_CQ)
		calls += sdp_conn_cq_drain(conn->send_cq, conn);

	conn->lock.event = 0;
}

/*
 * sdp_conn_lock_init - initialize connection lock
 */
static void sdp_conn_lock_init(struct sdp_sock *conn)
{
	spin_lock_init(&(conn->lock.slock));
	conn->lock.users = 0;
	conn->lock.event = 0;
	init_waitqueue_head(&(conn->lock.waitq));
}

/*
 * sdp_conn_alloc_ib - allocate IB structures for a new connection.
 */
int sdp_conn_alloc_ib(struct sdp_sock *conn, struct ib_device *device,
		      u8 hw_port, u16 pkey)
{
	struct ib_qp_init_attr *init_attr;
	struct ib_qp_attr     *qp_attr;
	struct sdev_hca_port  *port;
	struct sdev_hca       *hca;
	int                    attr_mask = 0;
	int                    result = 0;

	/*
	 * look up correct HCA and port
	 */
	hca = ib_get_client_data(device, &sdp_client);
	if (!hca)
		return -ERANGE;

	list_for_each_entry(port, &hca->port_list, list)
		if (hw_port == port->index) {
			result = 1;
			break;
		}

	if (!result)
		return -ERANGE;
	/*
	 * allocate creation parameters
	 */
	qp_attr = kmalloc(sizeof(*qp_attr),  GFP_KERNEL);
	if (!qp_attr) {
		result = -ENOMEM;
		goto error_attr;
	}

	init_attr = kmalloc(sizeof(*init_attr), GFP_KERNEL);
	if (!init_attr) {
		result = -ENOMEM;
		goto error_param;
	}

	memset(qp_attr,   0, sizeof(*qp_attr));
	memset(init_attr, 0, sizeof(*init_attr));
	/*
	 * set port specific connection parameters.
	 */
	conn->ca       = hca->ca;
	conn->pd       = hca->pd;
	conn->hw_port  = port->index;
	conn->l_key    = hca->l_key;
	conn->fmr_pool = hca->fmr_pool;

	memcpy(&conn->s_gid, &port->gid, sizeof(union ib_gid));
	/*
	 * allocate IB CQ's and QP
	 */
	if (!conn->send_cq) {
		conn->send_cq = ib_create_cq(conn->ca, sdp_cq_event_handler,
					     NULL, hashent_arg(conn->hashent),
					     conn->send_cq_size);
		if (IS_ERR(conn->send_cq)) {
			result = PTR_ERR(conn->send_cq);
			sdp_dbg_warn(conn, "Error <%d> creating send CQ <%d>",
				     result, conn->send_cq_size);
			goto error_scq;
		}

		conn->send_cq_size = conn->send_cq->cqe;

		result = ib_req_notify_cq(conn->send_cq, IB_CQ_NEXT_COMP);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> arming send CQ.",
				     result);
			goto error_rcq;
		}
	}

	if (!conn->recv_cq) {
		conn->recv_cq = ib_create_cq(conn->ca, sdp_cq_event_handler,
					     NULL, hashent_arg(conn->hashent),
					     conn->recv_cq_size);

		if (IS_ERR(conn->recv_cq)) {
			result = PTR_ERR(conn->recv_cq);
			sdp_dbg_warn(conn, "Error <%d> creating recv CQ <%d>",
				     result, conn->recv_cq_size);
			goto error_rcq;
		}

		conn->recv_cq_size = conn->recv_cq->cqe;

		result = ib_req_notify_cq(conn->recv_cq, IB_CQ_NEXT_COMP);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> arming recv CQ.",
				     result);
			goto error_qp;
		}
	}

	if (!conn->qp) {
		init_attr->cap.max_send_wr  = conn->send_cq_size;
		init_attr->cap.max_recv_wr  = conn->recv_cq_size;
		init_attr->cap.max_send_sge = SDP_QP_LIMIT_SG_SEND;
		init_attr->cap.max_recv_sge = SDP_QP_LIMIT_SG_RECV;

		init_attr->send_cq        = conn->send_cq;
		init_attr->recv_cq        = conn->recv_cq;
		init_attr->sq_sig_type    = IB_SIGNAL_REQ_WR;
		init_attr->qp_type        = IB_QPT_RC;
		/* TODO: real handler */
		init_attr->event_handler  = NULL;

		conn->qp = ib_create_qp(conn->pd, init_attr);
		if (IS_ERR(conn->qp)) {
			result = PTR_ERR(conn->qp);
			sdp_dbg_warn(conn, "Error <%d> creating QP", result);

			goto error_qp;
		}
		conn->s_qpn = conn->qp->qp_num;
		/*
		 * modify QP to INIT
		 */
		attr_mask |= IB_QP_PKEY_INDEX;
		result = ib_find_cached_pkey(device,
					     hw_port,
					     pkey,
					     &qp_attr->pkey_index);
		if (result) {
			sdp_dbg_warn(conn, "Error <%d> find pkey index <%04x>",
				     result, pkey);
			goto error_mod;
		}

		attr_mask |= IB_QP_STATE;
		qp_attr->qp_state = IB_QPS_INIT;

		attr_mask |= IB_QP_ACCESS_FLAGS;
		qp_attr->qp_access_flags = (IB_ACCESS_REMOTE_READ|
					    IB_ACCESS_REMOTE_WRITE);

		attr_mask |= IB_QP_PORT;
		qp_attr->port_num = conn->hw_port;

		result = ib_modify_qp(conn->qp, qp_attr, attr_mask);

		if (result) {
			sdp_dbg_warn(conn, "Error <%d> modifying QP", result);
			goto error_mod;
		}
	}

	result = 0;
	goto done;

error_mod:
	(void)ib_destroy_qp(conn->qp);
error_qp:
	(void)ib_destroy_cq(conn->recv_cq);
error_rcq:
	(void)ib_destroy_cq(conn->send_cq);
error_scq:
	conn->send_cq = NULL;
	conn->recv_cq = NULL;
	conn->qp      = NULL;
done:
	kfree(init_attr);
error_param:
	kfree(qp_attr);
error_attr:
	return result;
}

/*
 * sdp_conn_alloc - allocate a new socket, and init.
 */
struct sdp_sock *sdp_conn_alloc(unsigned int priority)
{
	struct sdp_sock *conn;
	struct sock *sk;
	int result;

	sk = sk_alloc(dev_root_s.proto, priority, 
		      sizeof(struct inet_sock), dev_root_s.sock_cache);
	if (!sk) {
		sdp_dbg_warn(NULL, "socket alloc error for protocol. <%d:%u>",
			     dev_root_s.proto, priority);
		return NULL;
	}
	/*
	 * initialize base socket
	 */
	sock_init_data(NULL, sk);	/* refcnt set to 1 */
	/*
	 * other non-zero sock initialization.
	 */
	sk->sk_protocol = IPPROTO_TCP;
	/*
	 * replace some callbacks from the standard functions.
	 */
	sk->sk_destruct     = NULL;
	sk->sk_write_space  = sdp_inet_wake_send;
	/*
	 * Allocate must be called from process context, since QP
	 * create/modifies must be in that context.
	 */
	conn = kmem_cache_alloc(dev_root_s.conn_cache, priority);
	if (!conn) {
		sdp_dbg_warn(conn, "connection alloc error. <%d>", priority);
		result = -ENOMEM;
		goto error;
	}
 
	memset(conn, 0, sizeof *conn);
	/*
	 * The STRM interface specific data is map/cast over the TCP specific
	 * area of the sock.
	 */
	SDP_SET_CONN(sk, conn);
	SDP_CONN_ST_INIT(conn);

	conn->cm_id       = NULL;

	conn->oob_offset  = -1;
	conn->rcv_urg_cnt = 0;

	conn->nodelay     = 0;
	conn->src_zthresh = sdp_zcopy_thrsh_src_default;
	conn->snk_zthresh = sdp_zcopy_thrsh_snk_default;

	conn->accept_next = NULL;
	conn->accept_prev = NULL;
	conn->parent      = NULL;

	conn->pid       = 0;
	conn->sk        = sk;
	conn->hashent   = SDP_DEV_SK_INVALID;
	conn->flags     = 0;
	conn->shutdown  = 0;
	conn->recv_mode = SDP_MODE_COMB;
	conn->send_mode = SDP_MODE_COMB;

	SDP_CONN_ST_SET(conn, SDP_CONN_ST_CLOSED);

	conn->send_seq  = 0;
	conn->recv_seq  = 0;
	conn->advt_seq  = 0;

	conn->nond_recv = 0;
	conn->nond_send = 0;

	conn->recv_max  = dev_root_s.recv_buff_max;
	conn->send_max  = dev_root_s.send_buff_max;
	conn->rwin_max  = SDP_INET_RECV_SIZE;
	conn->s_wq_size = 0;

	conn->send_buf  = 0;
	conn->send_qud  = 0;
	conn->send_pipe = 0;

	conn->recv_size = sdp_buff_pool_buff_size();
	conn->send_size = 0;

	conn->src_serv  = 0;
	conn->snk_serv  = 0;
	conn->s_cur_adv = 1;
	conn->s_par_adv = 0;

	conn->src_recv  = 0;
	conn->snk_recv  = 0;
	conn->src_sent  = 0;
	conn->snk_sent  = 0;

	conn->send_bytes   = 0;
	conn->recv_bytes   = 0;
	conn->write_bytes  = 0;
	conn->read_bytes   = 0;
	conn->write_queued = 0;
	conn->read_queued  = 0;

	conn->send_usig = 0;
	conn->send_cons = 0;
	conn->usig_max  = dev_root_s.send_usig_max;

	conn->s_wq_par = 0;

	conn->plid = 0;

	conn->send_cq_size = dev_root_s.send_post_max;
	conn->recv_cq_size = dev_root_s.recv_post_max;
	conn->s_wq_cur     = dev_root_s.send_post_max;

	conn->send_cq  = NULL;
	conn->recv_cq  = NULL;
	conn->qp       = NULL;
	conn->ca       = NULL;
	conn->pd       = NULL;
	conn->l_key    = 0;
	conn->fmr_pool = NULL;
	conn->hw_port  = 0;

	conn->rq_psn   = sdp_psn_generate();
	/*
	 * generic send queue
	 */
	sdp_desc_q_init(&conn->send_queue);
	sdp_desc_q_init(&conn->send_ctrl);
	/*
	 * create buffer pools for posted events
	 */
	sdp_buff_q_init(&conn->recv_post);
	sdp_buff_q_init(&conn->recv_pool);
	sdp_buff_q_init(&conn->send_post);
	/*
	 * initialize zcopy advertisment tables
	 */
	sdp_advt_q_init(&conn->src_pend);
	sdp_advt_q_init(&conn->src_actv);
	sdp_advt_q_init(&conn->snk_pend);
	/*
	 * initialize zcopy iocb tables
	 */
	sdp_iocb_q_init(&conn->r_pend);
	sdp_iocb_q_init(&conn->r_snk);
	sdp_iocb_q_init(&conn->w_src);

	sdp_desc_q_init(&conn->r_src);
	sdp_desc_q_init(&conn->w_snk);
	/*
	 * connection lock
	 */
	sdp_conn_lock_init(conn);
	/*
	 * insert connection into lookup table
	 */
	result = sdp_conn_table_insert(conn);
	if (result < 0) {

		sdp_dbg_warn(conn, "Error <%d> conn table insert <%d:%d>",
			     result, dev_root_s.sk_entry,
			     dev_root_s.sk_size);
		goto error_conn;
	}
	/*
	 * set reference
	 */
	atomic_set(&conn->refcnt, 1);
	/*
	 * hold disconnect messages till established state has been reached.
	 */
	conn->flags |= SDP_CONN_F_DIS_HOLD;
	/*
	 * done
	 */
	return conn;
error_conn:
	kmem_cache_free(dev_root_s.conn_cache, conn);
error:
	sk_free(sk);
	return NULL;
}

/*
 * module public functions
 */

#define SDP_CONN_PROC_MAIN_SIZE  183 /* output line size. */
#define SDP_PROC_CONN_MAIN_HEAD \
        "dst address:port src address:port  ID  comm_id  pid  " \
        "    dst guid         src guid     dlid slid dqpn   "   \
	"sqpn   data sent buff'd data rcvd_buff'd "             \
	"  data written      data read     src_serv snk_serv\n"
#define SDP_PROC_CONN_MAIN_SEP  \
	"---------------- ---------------- ---- -------- ---- " \
	"---------------- ---------------- ---- ---- ------ "   \
	"------ ---------------- ---------------- "             \
	"---------------- ---------------- -------- --------\n"
#define SDP_PROC_CONN_MAIN_FORM \
	"%02x.%02x.%02x.%02x:%04x %02x.%02x.%02x.%02x:%04x "  \
	"%04x %08x %04x %08x%08x %08x%08x %04x %04x "         \
	"%06x %06x %08x%08x %08x%08x %08x%08x %08x%08x %08x %08x\n"

/*
 * sdp_proc_dump_conn_main - dump the connection table to /proc
 */
int sdp_proc_dump_conn_main(char *buffer, int max_size, off_t start_index,
			    long *end_index)
{
	struct sdp_sock *conn;
	off_t counter = 0;
	int   offset = 0;
	u64   s_guid;
	u64   d_guid;
	unsigned long flags;

	*end_index = 0;
	/*
	 * header should only be printed once
	 */
	if (!start_index) {
		offset += sprintf(buffer + offset, SDP_PROC_CONN_MAIN_HEAD);
		offset += sprintf(buffer + offset, SDP_PROC_CONN_MAIN_SEP);
	}
	/*
	 * lock table
	 */
	spin_lock_irqsave(&dev_root_s.sock_lock, flags);
	/*
	 * if the entire table has been walked, exit.
	 */
	if (!(start_index < dev_root_s.sk_size))
		goto done;
	/*
	 * loop across connections.
	 */
	for (counter = start_index;
	     counter < dev_root_s.sk_size &&
		     !(SDP_CONN_PROC_MAIN_SIZE > (max_size - offset));
	     counter++) {
		if (!dev_root_s.sk_array[counter])
			continue;

		conn = dev_root_s.sk_array[counter];

		d_guid = cpu_to_be64(conn->d_gid.global.interface_id);
		s_guid = cpu_to_be64(conn->s_gid.global.interface_id);

		offset += sprintf(buffer + offset, SDP_PROC_CONN_MAIN_FORM,
				  conn->dst_addr & 0xff,
				  (conn->dst_addr >> 8) & 0xff,
				  (conn->dst_addr >> 16) & 0xff,
				  (conn->dst_addr >> 24) & 0xff,
				  conn->dst_port,
				  conn->src_addr & 0xff,
				  (conn->src_addr >> 8) & 0xff,
				  (conn->src_addr >> 16) & 0xff,
				  (conn->src_addr >> 24) & 0xff,
				  conn->src_port,
				  conn->hashent,
				  conn->cm_id ? conn->cm_id->local_id : 0,
				  conn->pid,
				  (u32)((d_guid >> 32) & 0xffffffff),
				  (u32)(d_guid & 0xffffffff),
				  (u32)((s_guid >> 32) & 0xffffffff),
				  (u32)(s_guid & 0xffffffff),
				  conn->d_lid,
				  conn->s_lid,
				  conn->d_qpn,
				  conn->s_qpn,
				  (u32)((conn->send_bytes >> 32) & 0xffffffff),
				  (u32)(conn->send_bytes & 0xffffffff),
				  (u32)((conn->recv_bytes >> 32) & 0xffffffff),
				  (u32)(conn->recv_bytes & 0xffffffff),
				  (u32)((conn->write_bytes >> 32)& 0xffffffff),
				  (u32)(conn->write_bytes & 0xffffffff),
				  (u32)((conn->read_bytes >> 32) & 0xffffffff),
				  (u32)(conn->read_bytes & 0xffffffff),
				  conn->src_serv,
				  conn->snk_serv);

	}

	*end_index = counter - start_index;

done:
	spin_unlock_irqrestore(&dev_root_s.sock_lock, flags);
	return offset;
}

#define SDP_CONN_PROC_DATA_SIZE  171 /* output line size. */
#define SDP_PROC_CONN_DATA_HEAD \
	" ID  conn r s fl sh send_buf recv_buf send q'd recv q'd " \
        "send_seq recv_seq advt_seq smax rmax recv_max lrcv " \
	"lavt rrcv sd sc sp rd rp swqs rbuf sbuf " \
        "us cu send_oob rurg back maxb\n"
#define SDP_PROC_CONN_DATA_SEP  \
	"---- ---- - - -- -- -------- -------- -------- -------- " \
	"-------- -------- -------- ---- ---- -------- ---- " \
	"---- ---- -- -- -- -- -- ---- ---- ---- " \
	"-- -- -------- ---- ---- ----\n"
#define SDP_PROC_CONN_DATA_FORM \
	"%04x %04x %01x %01x %02x %02x " \
	"%08x %08x %08x %08x %08x %08x " \
	"%08x %04x %04x %08x %04x %04x %04x %02x %02x " \
	"%02x %02x %02x %04x %04x %04x %02x %02x %08x %04x %04x %04x\n"

/*
 * sdp_proc_dump_conn_data - dump the connection table to /proc
 */
int sdp_proc_dump_conn_data(char *buffer, int max_size, off_t start_index,
			    long *end_index)
{
	struct sock *sk;
	struct sdp_sock *conn;
	off_t counter = 0;
	int   offset = 0;
	unsigned long flags;

	*end_index = 0;
	/*
	 * header should only be printed once
	 */
	if (!start_index) {
		offset += sprintf(buffer + offset, SDP_PROC_CONN_DATA_HEAD);
		offset += sprintf(buffer + offset, SDP_PROC_CONN_DATA_SEP);
	}
	/*
	 * lock table
	 */
	spin_lock_irqsave(&dev_root_s.sock_lock, flags);
	/*
	 * if the entire table has been walked, exit.
	 */
	if (!(start_index < dev_root_s.sk_size))
		goto done;
	/*
	 * loop across connections.
	 */
	for (counter = start_index; counter < dev_root_s.sk_size &&
		     !(SDP_CONN_PROC_DATA_SIZE > (max_size - offset));
	     counter++) {
		if (!dev_root_s.sk_array[counter])
			continue;

		conn = dev_root_s.sk_array[counter];
		sk = sk_sdp(conn);

		offset += sprintf(buffer + offset, SDP_PROC_CONN_DATA_FORM,
				  conn->hashent,
				  conn->state,
				  conn->recv_mode,
				  conn->send_mode,
				  conn->flags,
				  conn->shutdown,
				  conn->send_buf,
				  sk->sk_rcvbuf,
				  conn->send_qud,
				  conn->byte_strm,
				  conn->send_seq,
				  conn->recv_seq,
				  conn->advt_seq,
				  conn->send_max,
				  conn->recv_max,
				  conn->rwin_max,
				  conn->l_recv_bf,
				  conn->l_advt_bf,
				  conn->r_recv_bf,
				  sdp_desc_q_size(&conn->send_queue),
				  sdp_desc_q_size(&conn->send_ctrl),
				  sdp_buff_q_size(&conn->send_post),
				  sdp_buff_q_size(&conn->recv_pool),
				  sdp_buff_q_size(&conn->recv_post),
				  conn->s_wq_size,
				  conn->recv_size,
				  conn->send_size,
				  conn->send_usig,
				  conn->send_cons,
				  conn->oob_offset,
				  conn->rcv_urg_cnt,
				  conn->backlog_cnt,
				  conn->backlog_max);
	}

	*end_index = counter - start_index;
done:
	spin_unlock_irqrestore(&dev_root_s.sock_lock, flags);
	return offset;
}

#define SDP_CONN_PROC_RDMA_SIZE   98 /* output line size. */
#define SDP_PROC_CONN_RDMA_HEAD \
	" ID  rr rw lr lw ap aa as rpnd rsnk wsrc rsrc wsnk ra la sc sp " \
        "non_recv non_send  readq    writeq \n"
#define SDP_PROC_CONN_RDMA_SEP  \
	"---- -- -- -- -- -- -- -- ---- ---- ---- ---- ---- -- -- -- -- " \
	"-------- -------- -------- --------\n"
#define SDP_PROC_CONN_RDMA_FORM \
	"%04x %02x %02x %02x %02x %02x %02x %02x " \
	"%04x %04x %04x %04x %04x %02x %02x %02x %02x %08x %08x %08x %08x\n"

/*
 * sdp_proc_dump_conn_rdma - dump the connection table to /proc
 */
int sdp_proc_dump_conn_rdma(char *buffer, int max_size, off_t start_index,
			    long *end_index)
{
	struct sdp_sock *conn;
	off_t counter = 0;
	int   offset = 0;
	unsigned long flags;

	*end_index = 0;
	/*
	 * header should only be printed once
	 */
	if (!start_index) {
		offset += sprintf(buffer + offset, SDP_PROC_CONN_RDMA_HEAD);
		offset += sprintf(buffer + offset, SDP_PROC_CONN_RDMA_SEP);
	}
	/*
	 * lock table
	 */
	spin_lock_irqsave(&dev_root_s.sock_lock, flags);
	/*
	 * if the entire table has been walked, exit.
	 */
	if (!(start_index < dev_root_s.sk_size))
		goto done;
	/*
	 * loop across connections.
	 */
	for (counter = start_index; counter < dev_root_s.sk_size &&
		     !(SDP_CONN_PROC_RDMA_SIZE > (max_size - offset));
	     counter++) {
		if (!dev_root_s.sk_array[counter])
			continue;

		conn = dev_root_s.sk_array[counter];

		offset += sprintf(buffer + offset, SDP_PROC_CONN_RDMA_FORM,
				  conn->hashent,
				  conn->src_recv,
				  conn->snk_recv,
				  conn->src_sent,
				  conn->snk_sent,
				  sdp_advt_q_size(&conn->src_pend),
				  sdp_advt_q_size(&conn->src_actv),
				  sdp_advt_q_size(&conn->snk_pend),
				  sdp_iocb_q_size(&conn->r_pend),
				  sdp_iocb_q_size(&conn->r_snk),
				  sdp_iocb_q_size(&conn->w_src),
				  sdp_desc_q_size(&conn->r_src),
				  sdp_desc_q_size(&conn->w_snk),
				  conn->r_max_adv,
				  conn->l_max_adv,
				  conn->s_cur_adv,
				  conn->s_par_adv,
				  conn->nond_recv,
				  conn->nond_send,
				  conn->read_queued,
				  conn->write_queued);
	}

	*end_index = counter - start_index;
done:
	spin_unlock_irqrestore(&dev_root_s.sock_lock, flags);
	return offset;
}

#define SDP_SOPT_PROC_DUMP_SIZE   55 /* output line size. */
#define SDP_PROC_CONN_SOPT_HEAD \
	"dst address:port src address:port src zcpy snk zcpy nd\n"
#define SDP_PROC_CONN_SOPT_SEP  \
	"---------------- ---------------- -------- -------- --\n"
#define SDP_PROC_CONN_SOPT_FORM \
	"%02x.%02x.%02x.%02x:%04x %02x.%02x.%02x.%02x:%04x %08x %08x %04x\n"

/*
 * sdp_proc_dump_conn_sopt - dump the options portion of each conn to /proc
 */
int sdp_proc_dump_conn_sopt(char *buffer, int max_size, off_t start_index,
			    long *end_index)
{
	struct sdp_sock *conn;
	off_t counter = 0;
	int   offset = 0;
	unsigned long flags;

	*end_index = 0;
	/*
	 * header should only be printed once
	 */
	if (!start_index) {
		offset += sprintf(buffer + offset, SDP_PROC_CONN_SOPT_HEAD);
		offset += sprintf(buffer + offset, SDP_PROC_CONN_SOPT_SEP);
	}
	/*
	 * lock table
	 */
	spin_lock_irqsave(&dev_root_s.sock_lock, flags);
	/*
	 * if the entire table has been walked, exit.
	 */
	if (!(start_index < dev_root_s.sk_size))
		goto done;
	/*
	 * loop across connections.
	 */
	for (counter = start_index; counter < dev_root_s.sk_size &&
		     !(SDP_SOPT_PROC_DUMP_SIZE > (max_size - offset));
	     counter++) {
		if (!dev_root_s.sk_array[counter])
			continue;

		conn = dev_root_s.sk_array[counter];

		offset += sprintf(buffer + offset, SDP_PROC_CONN_SOPT_FORM,
				  conn->dst_addr & 0xff,
				  (conn->dst_addr >> 8) & 0xff,
				  (conn->dst_addr >> 16) & 0xff,
				  (conn->dst_addr >> 24) & 0xff,
				  conn->dst_port,
				  conn->src_addr & 0xff,
				  (conn->src_addr >> 8) & 0xff,
				  (conn->src_addr >> 16) & 0xff,
				  (conn->src_addr >> 24) & 0xff,
				  conn->src_port,
				  conn->src_zthresh,
				  conn->snk_zthresh,
				  conn->nodelay);
	}

	*end_index = counter - start_index;
done:
	spin_unlock_irqrestore(&dev_root_s.sock_lock, flags);
	return offset;
}

/*
 * sdp_proc_dump_device - dump the primary device table to /proc
 */
int sdp_proc_dump_device(char *buffer, int max_size, off_t start_index,
			 long *end_index)
{
	int offset = 0;

	*end_index = 0;
	/*
	 * header should only be printed once
	 */
	if (!start_index) {
		offset += sprintf(buffer + offset,
				  "connection table maximum: <%d>\n",
				  dev_root_s.sk_size);
		offset += sprintf(buffer + offset,
				  "connection table entries: <%d>\n",
				  dev_root_s.sk_entry);
		offset += sprintf(buffer + offset,
				  "connection table   rover:  <%d>\n",
				  dev_root_s.sk_rover);

		offset += sprintf(buffer + offset,
				  "max send posted:          <%d>\n",
				  dev_root_s.send_post_max);
		offset += sprintf(buffer + offset,
				  "max send buffered:        <%d>\n",
				  dev_root_s.send_buff_max);
		offset += sprintf(buffer + offset,
		      "max send unsignalled:     <%d>\n",
				  dev_root_s.send_usig_max);
		offset += sprintf(buffer + offset,
				  "max receive posted:       <%d>\n",
				  dev_root_s.recv_post_max);
		offset += sprintf(buffer + offset,
				  "max receive buffered:     <%d>\n",
				  dev_root_s.recv_buff_max);
	}

	return offset;
}

/*
 * initialization/cleanup functions
 */

/*
 * sdp_device_init_one - add a device to the list
 */
static void sdp_device_init_one(struct ib_device *device)
{
	struct ib_fmr_pool_param fmr_param_s;
	struct sdev_hca_port *port, *tmp;
	struct sdev_hca *hca;
	int result;
	int port_count;
	/*
	 * allocate per-HCA structure
	 */
	hca = kmalloc(sizeof *hca, GFP_KERNEL);
	if (!hca) {
		sdp_warn("Error allocating HCA <%s> memory.", device->name);
		return;
	}
	/*
	 * init and insert into list.
	 */
	memset(hca, 0, sizeof *hca);

	hca->ca = device;
	INIT_LIST_HEAD(&hca->port_list);
	/*
	 * protection domain
	 */
	hca->pd = ib_alloc_pd(hca->ca);
	if (IS_ERR(hca->pd)) {
		sdp_warn("Error <%ld> creating HCA <%s> protection domain.",
			 PTR_ERR(hca->pd), device->name);
		goto err1;
	}
	/*
	 * memory registration
	 */
	hca->mem_h = ib_get_dma_mr(hca->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(hca->mem_h)) {
		sdp_warn("Error <%ld> registering HCA <%s> memory.",
			 PTR_ERR(hca->mem_h), device->name);
		goto err2;
	}

	hca->l_key = hca->mem_h->lkey;
	hca->r_key = hca->mem_h->rkey;
	/*
	 * FMR allocation
	 */
	fmr_param_s.pool_size = SDP_FMR_POOL_SIZE;
	fmr_param_s.dirty_watermark = SDP_FMR_DIRTY_SIZE;
	fmr_param_s.cache = 1;
	fmr_param_s.max_pages_per_fmr = SDP_IOCB_PAGE_MAX;
	fmr_param_s.access = (IB_ACCESS_LOCAL_WRITE  |
			      IB_ACCESS_REMOTE_WRITE |
			      IB_ACCESS_REMOTE_READ);

	fmr_param_s.flush_function = NULL;
	/*
	 * create SDP memory pool
	 */
	hca->fmr_pool = ib_create_fmr_pool(hca->pd, &fmr_param_s);
	if (IS_ERR(hca->fmr_pool))
		sdp_warn("Warning, could not create HCA <%s> FMR pool <%ld>",
			 device->name, PTR_ERR(hca->fmr_pool));

	/*
	 * port allocation
	 */
	for (port_count = 0;
	     port_count < device->phys_port_cnt;
	     port_count++) {
		port = kmalloc(sizeof *port, GFP_KERNEL);
		if (!port) {
			sdp_warn("Error allocating HCA <%s> port <%d:%d>",
				 device->name, port_count,
				 device->phys_port_cnt);

			goto err3;
		}

		memset(port, 0, sizeof *port);

		port->index = port_count + 1;
		list_add(&port->list, &hca->port_list);

		result = ib_query_gid(hca->ca,
				      port->index,
				      0,	/* index */
				      &port->gid);
		if (result) {
			sdp_warn("Error <%d> getting GID for port <%s:%d:%d>",
				 result, device->name,
				 port->index, device->phys_port_cnt);
			goto err3;
		}
	}

	hca->listen_id = ib_create_cm_id(device, sdp_cm_event_handler, hca);
	if (IS_ERR(hca->listen_id)) {
		sdp_warn("Error <%ld> creating listen ID on <%s>.",
			 PTR_ERR(hca->listen_id), device->name);
		goto err3;
	}

	result = ib_cm_listen(hca->listen_id,
		              cpu_to_be64(SDP_MSG_SERVICE_ID_VALUE),
			      cpu_to_be64(SDP_MSG_SERVICE_ID_MASK));
	if (result) {
		sdp_warn("Error <%d> listening for SDP connections", result);
		goto err4;
	}

	ib_set_client_data(device, &sdp_client, hca);

	return;

err4:
	ib_destroy_cm_id(hca->listen_id);
err3:
	list_for_each_entry_safe(port, tmp, &hca->port_list, list) {
		list_del(&port->list);
		kfree(port);
	}

	if (!IS_ERR(hca->fmr_pool))
		ib_destroy_fmr_pool(hca->fmr_pool);
	ib_dereg_mr(hca->mem_h);
err2:
	ib_dealloc_pd(hca->pd);
err1:
	kfree(hca);
}

/*
 * sdp_device_remove_one - remove a device from the hca list
 */
static void sdp_device_remove_one(struct ib_device *device)
{
	struct sdev_hca_port *port, *tmp;
	struct sdev_hca *hca;

	hca = ib_get_client_data(device, &sdp_client);

	if (!hca) {
		sdp_warn("Device <%s> has no HCA info.", device->name);
		return;
	}

	ib_destroy_cm_id(hca->listen_id);

	list_for_each_entry_safe(port, tmp, &hca->port_list, list) {
		list_del(&port->list);
		kfree(port);
	}

	if (!IS_ERR(hca->fmr_pool))
		ib_destroy_fmr_pool(hca->fmr_pool);

	ib_dereg_mr(hca->mem_h);
	ib_dealloc_pd(hca->pd);
	kfree(hca);
}

/*
 * sdp_conn_table_init - create a sdp connection table
 */
int sdp_conn_table_init(int proto_family, int conn_size, int recv_post_max,
			int recv_buff_max, int send_post_max, int send_buff_max,
			int send_usig_max)
{
	int result;
	int byte_size;
	int page_size;

	sdp_dbg_init("Creating connection tables.");
	/*
	 * psn init
	 */
	get_random_bytes(&psn_seed, sizeof(psn_seed));

	memset(&dev_root_s, 0, sizeof(struct sdev_root));
	/*
	 * list
	 */
	INIT_LIST_HEAD(&dev_root_s.listen_list);
	INIT_LIST_HEAD(&dev_root_s.bind_list);

	spin_lock_init(&dev_root_s.sock_lock);
	spin_lock_init(&dev_root_s.bind_lock);
	spin_lock_init(&dev_root_s.listen_lock);
	/*
	 * Initialize IB
	 */
	dev_root_s.proto = proto_family;

	dev_root_s.recv_post_max = recv_post_max;
	dev_root_s.recv_buff_max = recv_buff_max;
	dev_root_s.send_post_max = send_post_max;
	dev_root_s.send_buff_max = send_buff_max;

	dev_root_s.send_usig_max = send_usig_max;
	/*
	 * Get HCA/port list
	 */
	result = ib_register_client(&sdp_client);
	if (result < 0) {
		sdp_warn("Error <%d> registering SDP client.", result);
		goto error_hca;
	}
	/*
	 * create socket table
	 */
	if (conn_size <= 0) {
		sdp_warn("Invalid connection table size. <%d>", conn_size);
		result = -EINVAL;
		goto error_size;
	}

	byte_size = conn_size * sizeof(struct sdp_sock *);
	page_size = (byte_size >> 12) + ((0xfff & byte_size) > 0 ? 1 : 0);
	for (dev_root_s.sk_ordr = 0;
	     (1 << dev_root_s.sk_ordr) < page_size; dev_root_s.sk_ordr++) ;

	dev_root_s.sk_array = (void *) __get_free_pages(GFP_KERNEL,
						        dev_root_s.sk_ordr);
	if (!dev_root_s.sk_array) {
		sdp_warn("Failed to create connection table. <%d:%d:%d>",
			 byte_size, page_size, dev_root_s.sk_ordr);
		result = -ENOMEM;
		goto error_array;
	}

	memset(dev_root_s.sk_array, 0, byte_size);
	dev_root_s.sk_size = conn_size - 1; /* top is reserved for invalid */
	dev_root_s.sk_array++; /* bump table forward so negative -1 index
				   is always a null entry to improve invalid
				   entry processing. */
	/*
	 * IOCB table
	 */
	result = sdp_main_iocb_init();
	if (result < 0) {
		sdp_warn("Error <%d> initializing SDP IOCB table.", result);
		goto error_iocb;
	}

	dev_root_s.conn_cache = kmem_cache_create("sdp_conn",
						  sizeof(struct sdp_sock),
						  0, SLAB_HWCACHE_ALIGN,
						  NULL, NULL);
	if (!dev_root_s.conn_cache) {
		sdp_warn("failed to initialize connection cache.");
		result = -ENOMEM;
		goto error_conn;
	}

        dev_root_s.sock_cache = kmem_cache_create("sdp_sock",
						  sizeof(struct inet_sock), 
						  0, SLAB_HWCACHE_ALIGN,
						  NULL, NULL);
        if (!dev_root_s.sock_cache) {
		sdp_warn("Failed to initialize sock cache.");
		result = -ENOMEM;
		goto error_sock;
        }

	sdp_dbg_init("Started listening for SDP connection requests");

	return 0;
	kmem_cache_destroy(dev_root_s.sock_cache);
error_sock:
	kmem_cache_destroy(dev_root_s.conn_cache);
error_conn:
	sdp_main_iocb_cleanup();
error_iocb:
	dev_root_s.sk_array--;
	free_pages((unsigned long)dev_root_s.sk_array, dev_root_s.sk_ordr);
error_array:
error_size:
	ib_unregister_client(&sdp_client);
error_hca:
	return result;
}

/*
 * sdp_conn_table_clear - destroy connection managment and tables
 */
void sdp_conn_table_clear(void)
{
	sdp_dbg_init("Deleting connection tables.");
#if 0
	struct sdp_sock *conn;
	/*
	 * drain all the connections
	 */
	while ((conn = dev_root_s.conn_list)) {

	}
#endif
	/*
	 * delete list of HCAs/PORTs
	 */
	ib_unregister_client(&sdp_client);
	/*
	 * drop socket table
	 */
	dev_root_s.sk_array--;
	free_pages((unsigned long)dev_root_s.sk_array, dev_root_s.sk_ordr);
	/*
	 * delete IOCB table
	 */
	sdp_main_iocb_cleanup();
 	/*
	 * delete conn cache
	 */
	kmem_cache_destroy(dev_root_s.conn_cache);
	/*
	 * delete sock cache
	 */
	kmem_cache_destroy(dev_root_s.sock_cache);
}

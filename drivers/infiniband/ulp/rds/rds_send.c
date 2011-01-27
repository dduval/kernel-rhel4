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

static inline int get_dst_addr(struct sock *sk, struct msghdr *msg,
				struct in_addr *d_addr, u16 *d_port)
{
	struct sockaddr_in * in;

	if (!sk_daddr(sk)) {
		if (!msg->msg_name) {
			printk("rds: error msg->msg_name == NULL\n");
			return -EINVAL;
		}
		if (msg->msg_namelen < sizeof(*in))
			return -EINVAL;

		in = (struct sockaddr_in*)msg->msg_name;

		if (in->sin_family != AF_INET_RDS)
			return -EINVAL;

		*d_addr = in->sin_addr;
		*d_port = in->sin_port;
	}
	else {
		d_addr->s_addr = sk_daddr(sk);
		*d_port = sk_dport(sk);
	}
	return 0;

}

int rds_wait_for_space(struct rds_ep *ep, int pkts)
{
	long timeout = 1000;
	DECLARE_WAITQUEUE(wait, current);

	while (atomic_read(&(ep->send_pool.num_available)) < pkts) {
		add_wait_queue(&ep->send_pool.event, &wait);
		set_current_state(TASK_INTERRUPTIBLE);

		timeout = schedule_timeout(timeout);

		remove_wait_queue(&ep->send_pool.event, &wait);
		set_current_state(TASK_RUNNING);

		if ( (atomic_read(&ep->send_pool.num_available) >= pkts))
			return pkts;

		if (signal_pending(current) || !timeout)
			return 0;
	}
	return pkts;
}


static int
rds_copy_send(struct rds_ep *ep, u16 dport, u16 sport,
		struct msghdr *msg, size_t length,
		struct list_head *send_list,
		int pkts)
{
	struct rds_buf *buf, *prev_buf;

	u32 niovs;
	u32 iov_len;
	struct iovec *iov;
	void *iov_base;

	u8 *data;
	u32 data_len;
	struct rds_data_hdr *data_hdr;

	int copy, total_copied;
	int npkts;


	niovs = msg->msg_iovlen;
	iov = msg->msg_iov;
	iov_base = iov->iov_base;
	iov_len = iov->iov_len;

	buf = list_entry(send_list->next, struct rds_buf, list_item);

	data_hdr = (struct rds_data_hdr*)(buf->data);
	data = &(data_hdr->data[0]);
	data_len = params.mtu;

	npkts = pkts;
	total_copied = 0;
	prev_buf = NULL;

	while (npkts && niovs) {

		copy = min_t(unsigned int, iov_len, data_len);

		if (copy_from_user(data, iov_base, copy)) {
			printk("rds: error in copying data from user!, size %d, ep <0x%p>",copy, ep);
			goto error;
		}

		data_len-=copy;
		iov_len-=copy;
		iov_base+=copy;
		data+=copy;

		total_copied+=copy;

		if (iov_len == 0) {
			/* We have used up this iov go to next */

			niovs--;
			if (niovs) {
				/* setup info for the next iov */
				iov++;
				iov_base = iov->iov_base;
				iov_len = iov->iov_len;
			}
		}
		if (niovs == 0 || data_len == 0) {

			buf->sge.length = total_copied + RDS_DATA_HDR_SIZE;
			buf->wr.send_wr.send_flags = 0;

			if (buf->loopback) {
				buf->pkts = npkts;
				buf->src_addr = ep->src_addr;
				buf->recv_len = total_copied + RDS_DATA_HDR_SIZE;
			}

			/* Set header information */
			data_hdr->dst_port = dport;
			data_hdr->src_port = sport;
			data_hdr->pkts = npkts;/* Number of packets remaining including this one */
			data_hdr->psn = pkts - npkts;

			/* For completion processing */
			buf->psn = data_hdr->psn;

			/* Chain the buffers */
			if (prev_buf) {
				prev_buf->wr.send_wr.next = &buf->wr.send_wr;
			}
			prev_buf = buf;

			/* Reset total_copied for the next send */
			total_copied=0;

			npkts--;
			if (npkts) {
				/* There are more packets left to be sent
				* get the next buffer
				*/

				buf = list_entry(buf->list_item.next,
						struct rds_buf, list_item);

				if (!buf) {
					printk("rds: no more buffers available to send, ep 0x%p\n", ep);
					goto error;
				}
				if (buf->magic != RDS_MAGIC_BUF ) {
					printk("rds: send, buffer bad! magic <0x%x>\n", buf->magic);
					goto error;
				}
				data_hdr = (struct rds_data_hdr*)(buf->data);
				data = &(data_hdr->data[0]);
				data_len = params.mtu;
			}
			else {
				buf->wr.send_wr.send_flags = IB_SEND_SIGNALED;
			}
		}
	}
	return 0;

error:
	return -EFAULT;
}

static int rds_remote_send(struct rds_ep *ep,
			u16 dport, u16 sport,
			struct msghdr *msg, size_t length)
{
	struct list_head send_list;
	struct rds_buf *buf;
	struct ib_send_wr *failed_wr;

	int pkts=0;
	int err=0;

	unsigned long flags;

	if (!ep || ep->magic != RDS_MAGIC_EP) {
		printk("rds: bad ep context in send\n");
		return -EAGAIN;
	}

	if (atomic_read(&ep->state) != EP_CONNECTED ) {
		printk("rds: send: ep <0x%p> not connected!\n", ep);
		return -EFAULT;
	}

	INIT_LIST_HEAD(&send_list);

	/* get send buffers */
	err = rds_get_send_list(ep, length, &send_list, &pkts);
	if (err || !pkts) {
		return -ENOBUFS;
	}
	/* copy user data */
	err = rds_copy_send(ep, dport, sport, msg, length, &send_list, pkts);
	if (err) {
		printk("rds: send: ep <0x%p> error in copy send\n",
			ep);
		return -EAGAIN;
	}
	buf = list_entry(send_list.next, struct rds_buf, list_item);

	/* post send */
	spin_lock_irqsave(&ep->lock, flags);

	err = ib_post_send(ep->cma_id->qp, &buf->wr.send_wr, &failed_wr);
	if (err) {
		printk("rds: post send failed ep <0x%p> \n", ep);
		goto done;
	}

	atomic_add(pkts, &ep->send_pool.num_posted);

done:
	rds_put_send_list(ep, &send_list, FALSE);

	spin_unlock_irqrestore(&ep->lock, flags);

	return 0;
}


static int rds_loopback_send(struct rds_ep *ep,
			u16 dport, u16 sport,
			struct msghdr *msg, size_t length)
{
	unsigned long rw_flags, flags;
	struct rds_cb *cb;
	struct list_head send_list;

	int pkts=0;
	int err=0;

	struct sock *sk;

	INIT_LIST_HEAD(&send_list);

	/* Find destination port */
	read_lock_irqsave(&port_lock, rw_flags);

	cb = rds_find_port(dport);
	if (!cb) {
		read_unlock_irqrestore(&port_lock, rw_flags);

		atomic_inc(&rds_stats.loopback_pkts_dropped);
		goto done;
	}

	read_unlock_irqrestore(&port_lock, rw_flags);

	/* get send buffers */
	err = rds_get_send_list_lpbk(ep, length, &send_list, &pkts);
	if (err || !pkts) {
		atomic_dec(&cb->ref);
		return -ENOBUFS;
	}

	/* copy user data */
	err = rds_copy_send(ep, dport, sport, msg, length, &send_list, pkts);
	if (err) {
		printk("rds: send: ep <0x%p> error in copy send\n", ep);
		atomic_dec(&cb->ref);
		return -EAGAIN;
	}

	/* Queue pkts directly to destination socket */
	read_lock_irqsave(&port_lock, rw_flags);

	spin_lock_irqsave(&cb->recv_q_lock, flags);

	list_splice_init(&send_list, cb->recv_queue.prev);

	atomic_add(pkts, &cb->recv_pending);
	atomic_add(pkts, &rds_stats.rx_pkts_pending);

	spin_unlock_irqrestore(&cb->recv_q_lock, flags);

	atomic_dec(&cb->ref);

	read_unlock_irqrestore(&port_lock, rw_flags);

	/* wake up any processes waiting in poll() */
	sk = (struct sock*)(cb->sk);
	read_lock(&sk->sk_callback_lock);
	if (sk->sk_sleep) {
		wake_up(sk->sk_sleep);
		sk_wake_async(sk,1,POLL_IN);
	}
	read_unlock(&sk->sk_callback_lock);

done:
	rds_put_send_list_lpbk(ep, &send_list);

	return 0;

}


int rds_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t len)
{
	struct in_addr daddr;
	struct in_addr saddr;
	u8 *addr;

	u16 dport;
	u16 sport;

	struct rds_session *session;
	struct rds_cb *cb;
	struct rds_ep *ep;

	int err=0;

	/* get destination address */
	err = get_dst_addr(sk, msg, &daddr, &dport);
	if (err) {
		return err;
	}

	sport = sk_sport(sk);
	saddr.s_addr = sk_saddr(sk);

	/* get port control block */
	cb = (struct rds_cb*)sk->sk_user_data;

	if (!cb || cb->magic != RDS_MAGIC_CB) {
		printk("rds_sendmsg: invalid socket control block\n");
		return -EAGAIN;
	}

	addr = (u8 *) &daddr.s_addr;
#if 0
	printk("rds: send to dst %d.%d.%d.%d, port %d\n",
		addr[0], addr[1], addr[2], addr[3],
		ntohs(dport));
#endif
	if (!msg || !len) {
		printk("rds: send: zero length send\n");
		return 0;
	}
	/* get session for this destination */
	session = rds_session_get(daddr, saddr);
	if (!session) {
		addr = (u8 *) &daddr.s_addr;
		printk("rds_sendmsg: could not get session for dst %d.%d.%d.%d, port %d\n",
			addr[0], addr[1], addr[2], addr[3],
			ntohs(dport));
		return -EFAULT;
	}

	/* Connect session */
	if (atomic_read(&session->state) != SESSION_ACTIVE) {
		err = rds_session_connect(session);
		if (err) {
			rds_session_put(session);
			if (err == -EFAULT) {
				rds_queue_session_close(session);
			}

			return -EAGAIN;
		}
	}
#if 0
	/* check if destination socket stalled */
	if (rds_find_stall_port(session, dport, TRUE)) {
		return -EWOULDBLOCK;
	}
#endif
#if 0
	/* check if destination socket stalled */
	if (rds_find_stall_port(session, dport, TRUE)) {
		if (rds_wait_for_unstall(session, dport)) {
			printk("rds: send to stalled port returning EWOULDBLOCK \n");
			return -EWOULDBLOCK;
		}
	}
#endif
	if (rds_wait_for_unstall(session, dport))
		return -EWOULDBLOCK;

	ep = &session->data_ep;

	if (ep->loopback) {
		err = rds_loopback_send(ep, dport, sport, msg, len);

		if (err)
			goto error;
	}
	else {
		err = rds_remote_send(ep, dport, sport, msg, len);

		if (err)
			goto error;
	}
	/* Release reference on the session */
	rds_session_put(session);

	return len;

error:
	rds_session_put(session);
	return err;
}


void rds_send_error(struct rds_ep *ep, struct ib_wc *wc)
{
	struct rds_buf *buff;
	struct rds_session *s;

	buff = (struct rds_buf*)(unsigned long) wc->wr_id;
	s = ep->parent_session;

	atomic_inc(&rds_stats.tx_errors);
	atomic_inc(&ep->send_pool.num_available);

	if ((wc->status == IB_WC_RETRY_EXC_ERR) ||
		(wc->status == IB_WC_WR_FLUSH_ERR) ) {

			cmpxchg(&(s->state.counter), SESSION_ACTIVE, SESSION_ERROR);

			if (atomic_dec_and_test(&ep->send_pool.num_posted) ) {
				/* If we are still in error then initiate disconnect */
				if (cmpxchg(&(s->state.counter), SESSION_ERROR,
					SESSION_DISCONNECT_PENDING) == SESSION_ERROR ) {

						printk("rds: send error, session <0x%p> disconnect pending\n", s);
						rds_queue_session_close(s);
					}
					wake_up(&ep->send_pool.event);
			}

		}
	else {
		printk("rds: got send error <%d> != IB_WC_RETRY_EXC_ERR != IB_WC_WR_FLUSH_ERR\n",
			wc->status);
	}

}

void rds_send_completion(void *context, struct ib_wc *wc)
{
	struct rds_buf *buf;
	struct rds_ep *ep = (struct rds_ep*) context;
	int nmore;

	if (!ep || (ep->magic != RDS_MAGIC_EP)) {
		printk("rds: send completion context bad!\n");
		return;
	}

	buf = (struct rds_buf*)(unsigned long) wc->wr_id;
	if (!buf || (buf->magic != RDS_MAGIC_BUF) ) {
		printk("rds: send completion buffer bad!\n");
		return;
	}

	if (wc->status) {
		rds_send_error(ep, wc);
		return;
	}

	nmore = buf->psn;
	do {
		atomic_dec(&ep->send_pool.num_posted);

		if (buf->state != BUFFER_RESEND_PENDING )
			atomic_inc(&ep->send_pool.num_available);

		buf->state = BUFFER_AVAILABLE;
		buf = list_entry(buf->list_item.prev,
		struct rds_buf, list_item);
	} while (nmore--);

#if 0
	atomic_dec(&ep->send_pool.num_posted);

	if (buf->state != BUFFER_RESEND_PENDING )
		atomic_inc(&ep->send_pool.num_available);

	buf->state = BUFFER_AVAILABLE;
#endif
	if (waitqueue_active(&ep->send_pool.event))
		wake_up(&ep->send_pool.event);

}

void rds_send_ctrl(struct rds_ep *ep,
		struct rds_ctrl_hdr *msg)
{
	int err;
	unsigned long flags;
	struct rds_buf *buf;
	struct rds_ctrl_hdr *ctrl_hdr;

	spin_lock_irqsave(&ep->lock, flags);

	if (!atomic_read(&(ep->send_pool.num_available)))
		goto done;

	/* Get a buffer */
	buf = list_entry(ep->send_pool.buffer_list.next,
	struct rds_buf, list_item);

	if (buf->state != BUFFER_AVAILABLE)
		goto done;

	list_del(&buf->list_item);
	buf->state = BUFFER_SEND_PENDING;
	list_add_tail(&buf->list_item, &ep->send_pool.buffer_list);

	atomic_dec(&ep->send_pool.num_available);

	/* copy ctrl message */
	ctrl_hdr = (struct rds_ctrl_hdr*)(buf->data);

	*ctrl_hdr = *msg;

	buf->sge.length = sizeof (*msg);
	buf->wr.send_wr.next = NULL;

	/* post send */
	err = ib_post_send(ep->cma_id->qp, &buf->wr.send_wr, NULL);
	if (err) {
		printk("rds: post send failed ep <0x%p> \n", ep);
		goto done;
	}

	atomic_inc(&ep->send_pool.num_posted);

done:
	spin_unlock_irqrestore(&ep->lock, flags);

}

void rds_send_ctrl_to_all(struct rds_ctrl_hdr *msg)
{
	struct rds_session *s;

	rcu_read_lock();

	list_for_each_entry_rcu(s, &session_list, list)
		if (atomic_read(&s->state) == SESSION_ACTIVE)
			rds_send_ctrl(&s->ctrl_ep, msg);

	rcu_read_unlock();
}

void rds_send_port_stall( void *context)
{
	struct rds_work *work = context;
	struct rds_cb *cb;
	struct rds_ctrl_hdr msg;

	if (!work)
		return;

	cb = work->cb;

	if (atomic_read(&cb->recv_pending) <= cb->max_recv)
		return;

	msg.ctrl_code = PORT_STALL;
	msg.port = cb->port_num;
	rds_send_ctrl_to_all(&msg);

	atomic_set(&cb->state, STALLED);

	kfree(work);

}

void rds_send_port_unstall( void *context)
{
	struct rds_work *work = context;
	struct rds_cb *cb;
	struct rds_ctrl_hdr msg;

	if (!work)
		return;

	cb = work->cb;

	msg.ctrl_code = PORT_UNSTALL;
	msg.port = cb->port_num;

	rds_send_ctrl_to_all(&msg);

	atomic_set(&cb->state, UNSTALLED);

	kfree(work);
}


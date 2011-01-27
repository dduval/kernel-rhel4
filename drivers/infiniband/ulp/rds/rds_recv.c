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

int rds_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t total_len, int nonblock, int flags, int *addrlen)
{
	int err=0;
	struct rds_cb *cb;
	struct rds_buf *buf;

	u32 niovs;
	u32 iov_len;
	struct iovec *iov;
	void *iov_base;

	u8 *data;
	u32 data_len;
	struct rds_data_hdr *data_hdr;


	int copy, total_copied;
	int npkts, total_pkts;

	u16 src_port;
	struct in_addr src_addr;
	u8 *addr;

	struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;

	cb = (struct rds_cb*)sk->sk_user_data;
	if (!cb || cb->magic != RDS_MAGIC_CB ) {
		printk("rds: invalid control block\n");
		err = -EFAULT;
		goto error;
	}

	while (atomic_read(&cb->recv_pending) == 0) {
		long timeout = 0;
		DECLARE_WAITQUEUE(wait, current);

		rds_chk_port_quota(cb);

		if (nonblock)
			return -EWOULDBLOCK;

		add_wait_queue(sk->sk_sleep, &wait);
		set_current_state(TASK_INTERRUPTIBLE);

		set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);

		if (!atomic_read(&cb->recv_pending))
			timeout = schedule_timeout(timeout);

		clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
		remove_wait_queue(sk->sk_sleep, &wait);
		set_current_state(TASK_RUNNING);

		if (signal_pending(current)) {
			err = ((timeout > 0) ?
				//sock_intr_errno(timeout) : 0);
				sock_intr_errno(timeout) : -EINTR);
			return err;
		}
	}

	niovs = msg->msg_iovlen;
	iov = msg->msg_iov;
	iov_base = iov->iov_base;
	iov_len = iov->iov_len;

	buf = list_entry(cb->recv_queue.next, struct rds_buf, list_item);

	data_hdr = (struct rds_data_hdr*)(buf->data);
	data = &(data_hdr->data[0]);
	data_len = buf->recv_len - RDS_DATA_HDR_SIZE;

	total_pkts = npkts = buf->pkts;
	total_copied = 0;

	src_port = data_hdr->src_port;
	src_addr = buf->src_addr;

	addr = (u8 *) &(buf->src_addr.s_addr);
#if 0
	printk(" rds_recvmsg: src_ip %d.%d.%d.%d, src_port %d: npkts %d, niovs %d\n",
		addr[0], addr[1], addr[2], addr[3],
		ntohs(src_port), npkts, niovs);
#endif
	while (npkts && niovs) {
		copy = min_t(unsigned int, iov_len, data_len);
		if (!iov_base || !data) {
			printk("rds: error in copying data to user! iov_base %p, data 0x%p, copy_size %d\n",
				iov_base, data, copy);
			err = -EFAULT;
			goto error;
		}

		if ((err = copy_to_user(iov_base, data, copy))) {
			printk("rds: error in copying data to user! iov_base 0x%p, data %p, copy_size %d\n",
				iov_base, data, copy);
			niovs = 0;
			goto error;
		}
#if 0
		printk(" rds_recvmsg: total_pkts %d, pkt # %d, niovs %d, data_len %d, iov_len %d\n",
			total_pkts, (total_pkts - npkts), niovs, data_len, iov_len);
#endif
		data_len-=copy;
		iov_len-=copy;
		iov_base+=copy;
		data+=copy;
		//buf->copied+=copy;

		total_copied+=copy;

		if (iov_len == 0) {
			/* We've used up this iov go to next */
			niovs--;

			if (niovs) {
				/* setup info for the next iov */
				iov++;
				iov_base = iov->iov_base;
				iov_len = iov->iov_len;
			}
		}
		if (data_len == 0) {
			/* We've used up this data packet,free it and go to next */

			spin_lock_irqsave(&cb->recv_q_lock, flags);
			list_del(&buf->list_item);
			atomic_dec(&cb->recv_pending);
			spin_unlock_irqrestore(&cb->recv_q_lock, flags);

			//rds_free_buffer(buf);

			rds_recv_buffer_put(buf);

			buf = NULL;

			npkts--;
			if (npkts) {
				/* Dequeue next buffer */

				buf = list_entry(cb->recv_queue.next,
						struct rds_buf, list_item);

				if (!buf) {
					printk("rds: cb <0x%p> expect %d more packtes but recv queue empty!\n",
						cb, npkts);
					goto done;
				}

				data_hdr = (struct rds_data_hdr*)(buf->data);
				data = &(data_hdr->data[0]);
				data_len = buf->recv_len - RDS_DATA_HDR_SIZE;
			}
		}
	}

	if (npkts > 0 && !(flags&MSG_PEEK)) {
		spin_lock_irqsave(&cb->recv_q_lock, flags);

		while(npkts) {
			buf = list_entry(cb->recv_queue.next,
					struct rds_buf, list_item);

			if (!buf) {
				spin_unlock_irqrestore(&cb->recv_q_lock, flags);
				goto done;
			}

			list_del(&buf->list_item);
			atomic_dec(&cb->recv_pending);
			//rds_free_buffer(buf);
			rds_recv_buffer_put(buf);
			npkts--;
		}
		spin_unlock_irqrestore(&cb->recv_q_lock, flags);

	}

	rds_chk_port_quota(cb);

done:
	if (addrlen)
		*addrlen=sizeof(*sin);

	if (sin) {
		sin->sin_family = AF_INET_RDS;
		sin->sin_port = src_port;
		sin->sin_addr = src_addr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
	}
	return total_copied;

error:
	return err;
}

int rds_post_new_recv(struct rds_ep *ep)
{
	int err=0;
	struct rds_buf *buf, *prev;

	if (ep->recv_pool.coalesce_count) {

		buf = rds_alloc_recv_buffer(ep, GFP_ATOMIC);
		if ( !buf)
			goto error;

		if (!list_empty(&ep->recv_pool.buffer_list)) {
			prev = list_entry(ep->recv_pool.buffer_list.prev,
			struct rds_buf, list_item);
			prev->wr.recv_wr.next = &buf->wr.recv_wr;

		}
		list_add_tail(&(buf->list_item), &ep->recv_pool.buffer_list);
		//ep->recv_pool.num_buffers++;
		ep->recv_pool.coalesce_count--;

	}
	else {
		buf = list_entry(ep->recv_pool.buffer_list.next,
		struct rds_buf, list_item);
		INIT_LIST_HEAD(&ep->recv_pool.buffer_list);
		ep->recv_pool.coalesce_count = ep->recv_pool.coalesce_max;
		err = ib_post_recv(ep->cma_id->qp, &buf->wr.recv_wr, NULL);
		if (err) {
			printk("rds: post recvs failed ep <0x%p> \n", ep);
			goto error;
		}

		atomic_add(ep->recv_pool.coalesce_max, &ep->recv_pool.num_posted);

	}

	return 0;

error:
	return -1;
}

#if 0
int rds_post_new_recv(struct rds_ep *ep)
{
	int err=0;

	struct rds_buf *buf;
	buf = rds_alloc_recv_buffer(ep, GFP_ATOMIC);
	if ( !buf){
		printk("error in allocating recv buffer, ep type %d\n", ep->type);
		goto error;
	}

	err = ib_post_recv(ep->cma_id->qp, &buf->wr.recv_wr, NULL);
	if (err){
		printk("rds: post recv failed ep <0x%p> \n", ep);
		goto error;
	}

	atomic_inc(&ep->recv_pool.num_posted);

	return 0;

error:
	return -1;
}
#endif

int rds_repost_recv(struct rds_ep *ep, struct rds_buf *buf)
{
	int err=0;

	buf->wr.recv_wr.next = NULL;

	err = ib_post_recv(ep->cma_id->qp, &buf->wr.recv_wr, NULL);
	if (err) {
		printk("rds: post recv failed ep <0x%p> \n", ep);
		goto error;
	}

	atomic_inc(&ep->recv_pool.num_posted);

	return 0;

error:
	return -1;
}

void rds_recv_buffer_put(struct rds_buf *buf)
{
	struct rds_ep *ep;

	if (buf) {
		if (!(ep = (struct rds_ep*)buf->parent_ep) ||
			!((struct rds_ep*)buf->parent_ep)->kmem_cache) {
				printk("rds: free buffer, bad ep or ep->kmem_cache!!\n");
				return;
		}
		if (!buf->loopback && (atomic_read(&ep->recv_pool.num_posted) < (ep->max_recv_bufs -
			ep->recv_pool.coalesce_max - 10))) {
				if (!rds_repost_recv(ep, buf))
					return;
		}
		kmem_cache_free(((struct rds_ep*)buf->parent_ep)->kmem_cache,
				buf);
	}
}

int rds_post_recvs_list(struct rds_ep *ep)
{
	struct list_head *entry = NULL, *n;
	struct rds_buf *buff, *prev;

	struct ib_recv_wr *first_wr, *failed_wr;

	int count=0;
	int err;

	prev = NULL;
	first_wr = NULL;

	/*Chain the recv work requests */

	list_for_each_safe(entry, n, &ep->recv_pool.buffer_list){
		if (!entry) {
			printk("rds: pre_post entry NULL\n");
			continue;
		}
		buff = list_entry(entry, struct rds_buf, list_item);
		if (!buff) {
			printk("rds: pre_post buff NULL\n");
			continue;
		}
		if (prev)
			prev->wr.recv_wr.next = &buff->wr.recv_wr;

		if (!first_wr)
			first_wr = &buff->wr.recv_wr;

		list_del(entry);

		prev = buff;
		count++;
	}

	err = ib_post_recv(ep->cma_id->qp, first_wr, &failed_wr);
	if (err) {
		printk("rds: pre post recvs failed ep <0x%p> \n", ep);
		return -EFAULT;
	}

	atomic_add(count, &ep->recv_pool.num_posted);

	return 0;
}

void rds_recv_error(struct rds_ep *ep, struct ib_wc *wc)
{
	struct rds_buf *buf;
	struct rds_session *s;

	buf = (struct rds_buf*)(unsigned long) wc->wr_id;
	s = ep->parent_session;

	atomic_inc(&rds_stats.rx_errors);
	//atomic_inc(&ep->recv_pool.num_available);

	cmpxchg(&(s->state.counter), SESSION_ACTIVE, SESSION_ERROR);

	if (atomic_dec_and_test(&ep->recv_pool.num_posted) ){
		/* If we are still in error then initiate disconnect */
		if (cmpxchg(&(s->state.counter), SESSION_ERROR,
			SESSION_DISCONNECT_PENDING) == SESSION_ERROR ){

				printk("rds: recv error, session <0x%p> now disconnect pending\n", s);
				rds_queue_session_close(s);
			}
			wake_up(&ep->recv_pool.event);
	}

	rds_free_buffer(buf);

}

void rds_free_seg_queue(struct rds_ep *ep)
{
	struct rds_buf *buf;

	while (!list_empty(&ep->seg_pkts_queue)) {
		buf = list_entry(ep->seg_pkts_queue.next,
		struct rds_buf, list_item);
		list_del(&buf->list_item);
		rds_free_buffer(buf);
	}
}

void rds_free_pending_recvs(struct rds_cb *cb)
{
	struct rds_buf *buf;

	while (!list_empty(&cb->recv_queue)) {
		buf = list_entry(cb->recv_queue.next,
		struct rds_buf, list_item);
		list_del(&buf->list_item);
		rds_free_buffer(buf);
	}
}

void rds_chk_port_quota(struct rds_cb *cb)
{
	struct rds_work *work;

	//if (atomic_read(&cb->recv_pending) < cb->max_recv) {
	if (atomic_read(&cb->recv_pending) == 0) {
		if ( ( cmpxchg(&(cb->state.counter), STALLED,
			UNSTALL_QUEUED) == STALLED )) {
				work = kzalloc( sizeof(*work), GFP_ATOMIC);
				if (work) {
					work->cb = cb;
					INIT_WORK(&work->work, rds_send_port_unstall,
						work);
					queue_work(rds_wq, &work->work);
				}
			}

	}
	else if (atomic_read(&cb->recv_pending) >= cb->max_recv) {
		if ( ( cmpxchg(&(cb->state.counter), UNSTALLED,
			STALL_QUEUED) == UNSTALLED )) {
				work = kzalloc( sizeof(*work), GFP_ATOMIC);
				if (work) {
					work->cb = cb;
					INIT_WORK(&work->work, rds_send_port_stall,
						work);
					queue_work(rds_wq, &work->work);
				}
			}
	}
}

void rds_process_recv( struct rds_ep *ep, struct rds_buf *buf)
{
	struct sock *sk;

	struct rds_data_hdr *data_hdr;
	u8 *data;
	struct rds_cb *cb;

	u8 seg, first, last;
	unsigned long rw_flags;

	data_hdr = (struct rds_data_hdr*)(buf->data);
	data = &(data_hdr->data[0]);

	buf->pkts = data_hdr->pkts;
	buf->src_addr = ep->dst_addr;



	/* Segmented? First pkt? Last pkt? */
	seg = FALSE; first = FALSE; last = FALSE;

	if (data_hdr->pkts > 1) {

		seg = TRUE;
		if (data_hdr->psn == 0) {

			/* First packet */
			first = TRUE;
			ep->seg_pkt_count=0;
		}
	}
	else if ( data_hdr->psn > 0) {
		/* num_packets == 1, psn > 1*/
		/* Last packet */
		seg = TRUE;
		last = TRUE;
	}

	read_lock_irqsave(&port_lock, rw_flags);

	cb = rds_find_port(data_hdr->dst_port);
	if (!cb) {
		read_unlock_irqrestore(&port_lock, rw_flags);

		atomic_inc(&rds_stats.rx_pkts_dropped);
		if (seg && !first){
			rds_free_seg_queue(ep);
		}
		rds_free_buffer(buf);
		goto done;
	}

	if (seg) {
		list_add_tail(&buf->list_item, &ep->seg_pkts_queue);
		ep->seg_pkt_count++;

		if (last) {
			unsigned long flags;

			spin_lock_irqsave(&cb->recv_q_lock, flags);

			list_splice_init(&ep->seg_pkts_queue, cb->recv_queue.prev);

			atomic_add(ep->seg_pkt_count, &cb->recv_pending);
			atomic_add(ep->seg_pkt_count, &rds_stats.rx_pkts_pending);
			ep->seg_pkt_count=0;

			spin_unlock_irqrestore(&cb->recv_q_lock, flags);

			atomic_dec(&cb->ref);

			rds_chk_port_quota(cb);

			read_unlock_irqrestore(&port_lock, rw_flags);



			/* wake up any processes waiting in poll() */
			sk = (struct sock*)(cb->sk);

			read_lock(&sk->sk_callback_lock);

			if (sk->sk_sleep) {
				wake_up(sk->sk_sleep);
				sk_wake_async(sk,1,POLL_IN);
			}
			read_unlock(&sk->sk_callback_lock);
		}
		else {
			atomic_dec(&cb->ref);
			read_unlock_irqrestore(&port_lock, rw_flags);
		}
	}
	else {
		unsigned long flags;

		spin_lock_irqsave(&cb->recv_q_lock, flags);

		list_add_tail(&buf->list_item, &cb->recv_queue);
		atomic_inc(&cb->recv_pending);
		atomic_inc(&rds_stats.rx_pkts_pending);

		spin_unlock_irqrestore(&cb->recv_q_lock, flags);

		atomic_dec(&cb->ref);

		rds_chk_port_quota(cb);

		read_unlock_irqrestore(&port_lock, rw_flags);

		/* wake up any processes waiting in poll() */
		sk = (struct sock*)(cb->sk);
		read_lock(&sk->sk_callback_lock);
		if (sk->sk_sleep) {
			wake_up(sk->sk_sleep);
			sk_wake_async(sk,1,POLL_IN);
		}
		read_unlock(&sk->sk_callback_lock);

		if (ep->seg_pkt_count) {
			/* Something's wrong, free the segmented queue */
			rds_free_seg_queue(ep);
		}
	}
done:
	return;
}

void rds_process_ctrl_recv(struct rds_ep *ep, struct rds_buf *buf)
{

	struct rds_ctrl_hdr *ctrl;
	struct rds_session *s;
	struct rds_stall_port *stall;

	ctrl = (struct rds_ctrl_hdr*)(buf->data);
	s = (struct rds_session*)ep->parent_session;

	switch (ctrl->ctrl_code) {
	case PORT_STALL:
	{
		struct rds_stall_port *old;
		stall = kzalloc(sizeof(*stall), GFP_ATOMIC);
		if (!stall)
			break;

		stall->port = ctrl->port;
		init_waitqueue_head(&stall->wait);
		if ((old = rds_insert_stall_port(s, stall)))
			kfree(stall);
		break;
	}
	case PORT_UNSTALL:
		if (!(stall = rds_find_stall_port(s, ctrl->port, TRUE))) {
			printk("rds: trying to unstall a port that is not stalled\n");
			break;
		}

		rds_delete_stall_port(s, stall);

		if (waitqueue_active(&stall->wait))
			wake_up(&stall->wait);
		else
			kfree(stall);
		break;

	default:
		break;
	}

	rds_free_buffer(buf);

}

void rds_recv_completion(void *context, struct ib_wc *wc)
{
	struct rds_buf *buf;
	struct rds_ep *ep = (struct rds_ep*) context;



	if (!ep || (ep->magic != RDS_MAGIC_EP)) {
		printk("rds: recv completion context bad!\n");
		return;
	}

	buf = (struct rds_buf*)(unsigned long) wc->wr_id;
	if (!buf || (buf->magic != RDS_MAGIC_BUF) ) {
		printk("rds: recv completion buffer bad!\n");
		return;
	}

	if (wc->status) {
		rds_recv_error(ep, wc);
		return;
	}

	atomic_dec(&ep->recv_pool.num_posted);

	rds_post_new_recv(ep);

	buf->recv_len = wc->byte_len;
	switch (ep->type) {
	case DATA_EP:
		rds_process_recv(ep, buf);
		break;

	case CONTROL_EP:
		rds_process_ctrl_recv(ep, buf);
		break;

	default:
		printk("rds: recv cmp, ep->type not recognized\n");
		break;
	}

}

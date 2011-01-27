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

struct rds_stats rds_stats;

struct rds_params params;

//struct rds_control rds_control;

/* PORT Map */
struct rb_root port_rbtree = RB_ROOT ;
rwlock_t port_lock;

/* Session List */
LIST_HEAD(session_list);
spinlock_t session_lock;


/* Caches */
static kmem_cache_t *rds_data_cache = NULL;
static kmem_cache_t *rds_ctrl_cache = NULL;

/* Work queue */
struct workqueue_struct *rds_wq;


int rds_init_caches(void)
{
	rds_data_cache = kmem_cache_create("rds:data",
		sizeof(struct rds_buf)+
		RDS_PKT_SIZE,
		0,
		SLAB_HWCACHE_ALIGN,
		NULL, NULL);
	if (!rds_data_cache) {
		printk("rds: could not create data cache\n");
		goto error;
	}

	rds_ctrl_cache = kmem_cache_create("rds:ctrl",
		sizeof(struct rds_buf) +
		sizeof (struct rds_ctrl_hdr),
		0,
		SLAB_HWCACHE_ALIGN,
		NULL, NULL);
	if (!rds_ctrl_cache) {
		printk("rds: could not create ctrl cache\n");
		goto error;
	}

	return 0;

error:
	rds_cleanup_caches();

	return -EFAULT;
}

void rds_cleanup_caches(void)
{
	if (rds_data_cache)
		kmem_cache_destroy(rds_data_cache);

	if (rds_ctrl_cache)
		kmem_cache_destroy(rds_ctrl_cache);
}

void rds_cleanup_globals(void)
{
	rds_cleanup_caches();

	if (rds_wq) {
		flush_workqueue(rds_wq);
		destroy_workqueue(rds_wq);
	}
}

int rds_init_globals(void)
{	int err = 0;

	rwlock_init(&port_lock);
	spin_lock_init(&session_lock);

	if (rds_init_caches()) {
		err = -EFAULT;
		goto error;
	}

	rds_wq = create_workqueue("rds_wq");
	if (!rds_wq) {
		err = -ENOMEM;
		goto error;
	}

	params.mtu = RDS_DFLT_MTU;
	params.max_data_recv_bufs = RDS_DFLT_DATA_RX_BUFS;
	params.max_data_send_bufs = RDS_DFLT_DATA_TX_BUFS;
	params.max_ctrl_recv_bufs = RDS_DFLT_CTRL_RX_BUFS;
	params.max_ctrl_send_bufs = RDS_DFTL_CTRL_TX_BUFS;

	return 0;
error:
	rds_cleanup_globals();
	return err;
}



struct rds_cb*
	rds_alloc_cb(struct sock *sk)
{
	struct rds_cb *cb;

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (cb == NULL)
		return NULL;

	cb->magic = RDS_MAGIC_CB;

	spin_lock_init(&cb->recv_q_lock);


	INIT_LIST_HEAD(&cb->recv_queue);

	atomic_set(&cb->recv_pending, 0);

	atomic_set(&cb->polled, 0);

	init_waitqueue_head(&cb->recv_event);

	cb->sk = sk;
	cb->stats.recv_pkts = 0;
	cb->stats.send_pkts = 0;

	/* Just for testing */
	cb->max_recv = 5000;

	atomic_set(&cb->state, UNSTALLED);
	atomic_set(&cb->ref, 0);

	return cb;

}

void
rds_free_cb(struct rds_cb *cb)
{
	kfree(cb);
}

struct rds_cb* rds_insert_port(struct rds_cb *cb)
{
	struct rb_node **p = &port_rbtree.rb_node;
	struct rb_node *parent = NULL;

	struct rds_cb *cur_cb;

	unsigned long flags;

	write_lock_irqsave(&port_lock, flags);

	while (*p) {
		parent = *p;
		cur_cb = rb_entry(parent, struct rds_cb, node);

		if (cb->port_num < cur_cb->port_num)
			p = &(*p)->rb_left;
		else if (cb->port_num > cur_cb->port_num)
			p = &(*p)->rb_right;
		else
			goto done;
	}
	rb_link_node(&cb->node, parent, p);
	rb_insert_color(&cb->node, &port_rbtree);
	rds_stats.ports++;
	cur_cb = NULL;
done:
	write_unlock_irqrestore(&port_lock, flags);

	return cur_cb;

}

struct rds_cb *rds_find_port(u16 port)
{
	struct rb_node *p = port_rbtree.rb_node;
	struct rb_node *parent = NULL;

	struct rds_cb *cb=NULL;

	unsigned long flags;

	read_lock_irqsave(&port_lock, flags);

	while (p) {
		parent = p;
		cb = rb_entry(parent, struct rds_cb, node);
		if (port == cb->port_num ) {
			atomic_inc(&cb->ref);
			goto done;
		}
		else if ( port < cb->port_num)
			p = p->rb_left;
		else if (port > cb->port_num)
			p = p->rb_right;
		cb = NULL;
	}
done:
	read_unlock_irqrestore(&port_lock, flags);

	return cb;

}

void rds_delete_port(struct rds_cb *cb)
{
	unsigned long flags;
	write_lock_irqsave(&port_lock, flags);

	rb_erase(&cb->node, &port_rbtree);
	rds_stats.ports--;
	write_unlock_irqrestore(&port_lock, flags);
}



static void rds_session_init(struct rds_session *s,
			struct in_addr dst_addr, struct in_addr src_addr)
{
	s->magic = RDS_MAGIC_SESSION;

	s->stall_rbtree = RB_ROOT;
	rwlock_init(&s->stall_lock);

	s->dst_addr = dst_addr;
	s->src_addr = src_addr;

	spin_lock_init(&s->lock);

	/* INIT Data EP */
	rds_ep_init(s, &s->data_ep);

	s->data_ep.type = DATA_EP;

	s->data_ep.max_send_bufs = params.max_data_send_bufs;
	s->data_ep.max_recv_bufs = params.max_data_recv_bufs;

	s->data_ep.buffer_size = params.mtu + RDS_DATA_HDR_SIZE;
	s->data_ep.recv_pool.coalesce_max = 50;

	s->data_ep.kmem_cache = rds_data_cache;

	/* INIT Control EP */
	rds_ep_init(s, &s->ctrl_ep);

	s->ctrl_ep.type = CONTROL_EP;
	s->ctrl_ep.max_send_bufs = params.max_ctrl_send_bufs;
	s->ctrl_ep.max_recv_bufs = params.max_ctrl_recv_bufs;
	s->ctrl_ep.buffer_size = sizeof(struct rds_ctrl_hdr);
	s->ctrl_ep.recv_pool.coalesce_max = 1;
	s->ctrl_ep.kmem_cache = rds_ctrl_cache;

	/* For data and control eps */
	atomic_set(&s->conn_pend, 2);
	atomic_set(&s->disconn_pend, 0);

}

struct rds_session* rds_session_lookup(struct in_addr dst_addr)
{
	struct rds_session *s, *session;

	session = NULL;

	rcu_read_lock();

	list_for_each_entry_rcu(s, &session_list, list) {
		if (s->dst_addr.s_addr == dst_addr.s_addr) {
			session = s;
			atomic_inc(&session->ref_count);
			break;
		}
	}

	rcu_read_unlock();

	return session;

}

struct rds_session* rds_session_alloc(struct in_addr dst_addr,
					struct in_addr src_addr)
{
	unsigned long flags;
	struct rds_session *s;

	s = NULL;

	/* Sync with other writers */
	spin_lock_irqsave(&session_lock, flags);

	/* Lookup once more */
	if ( (s = rds_session_lookup(dst_addr)) )
		/* found */
		goto done;

	s = kzalloc(sizeof (*s), GFP_ATOMIC);
	if (!s) {
		printk ("rds: could not allocate memory for session\n");
		goto done;
	}
	rds_session_init(s, dst_addr, src_addr);

	atomic_inc(&s->ref_count);
	/* Add to the sessions list */
	list_add_rcu(&s->list, &session_list);
done:
	spin_unlock_irqrestore(&session_lock, flags);
	return s;
}

struct rds_session* rds_session_get(struct in_addr dst_addr,
				struct in_addr src_addr)
{
	struct rds_session *s;

	s = rds_session_lookup(dst_addr);

	if (!s) {
		s = rds_session_alloc(dst_addr, src_addr);
		if (!s)
			printk("rds: error in session get\n");

	}
	return s;
}


void rds_session_put(struct rds_session *s)
{
	atomic_dec(&s->ref_count);

}


int rds_session_connect(struct rds_session *s)
{
	int err=0;

	if ( ( cmpxchg(&(s->state.counter), SESSION_INIT,
		SESSION_CONN_PENDING) == SESSION_INIT )) {
			err = rds_ep_connect(&s->ctrl_ep);
			if (err) {
				printk("rds: control ep connect failed\n");
				goto ctrl_err;
			}
			err = rds_ep_connect(&s->data_ep);
			if (err) {
				printk("rds: data ep connect failed\n");
				goto data_err;
			}
			if (s->ctrl_ep.loopback)
				atomic_set(&s->state, SESSION_ACTIVE);
		}
	else {
		switch atomic_read(&s->state)
		{
		case SESSION_CONN_PENDING:
			return -EAGAIN;

		case SESSION_ABRUPT_CLOSE_PENDING:
		case SESSION_CLOSE_PENDING:
		case SESSION_CLOSE_TIMEWAIT:
#if 0
		case SESSION_IDLE:
		case SESSION_FAILOVER_PENDING:
		case SESSION_FAILINGOVER:
		case SESSION_FAILOVER:
#endif
		default:
			return -EFAULT;
		}
	}
	return 0;

data_err:
	rds_ep_disconnect(&s->ctrl_ep);
ctrl_err:

	return err;

}

int rds_session_disconnect(struct rds_session *s)
{
	int err=0;
	unsigned long flags;

	spin_lock_irqsave(&s->lock, flags);

	switch (atomic_read(&s->state))
	{
	case SESSION_ACTIVE:
	case SESSION_CONN_PENDING:
	case SESSION_ERROR:
	case SESSION_DISCONNECT_PENDING:
		{
			atomic_set(&s->state, SESSION_CLOSE_PENDING);
			spin_unlock_irqrestore(&s->lock, flags);
			err = rds_ep_disconnect(&s->ctrl_ep);
			if (err)
				printk("rds: control ep disconnect failed\n");

			err = rds_ep_disconnect(&s->data_ep);
			if (err)
				printk("rds: data ep disconnect failed\n");
			break;
		}
	default:
		{
			spin_unlock_irqrestore(&s->lock, flags);
			printk("rds: session not ACTIVE nor CONN_PENDING <0x%p>\n", s);
			break;
		}
	}
	return err;

}

void rds_session_close(struct rds_session *s)
{
	int err;

	err = rds_session_disconnect(s);
	if (err)
		printk("rds: error in disconnecting session <0x%p>\n", s);

	kfree(s);
}

void rds_queue_session_close(struct rds_session *s)
{
	struct rds_work *work;
	work = kzalloc( sizeof(*work), GFP_ATOMIC);
	if (work) {
		work->session = s;
		INIT_WORK(&work->work, rds_session_close_cb, work);
		queue_work(rds_wq, &work->work);
	}
}

void rds_session_close_cb(void *context)
{
	struct rds_work *work = context;
	struct rds_session *s;
	unsigned long flags;

	if (!work)
		goto done;

	s = work->session;

	if (atomic_read(&s->ref_count)) {
		printk("rds: session ref cnt %d, delay closing\n",
			atomic_read(&s->ref_count));
		goto done;
	}
	spin_lock_irqsave(&session_lock, flags);
	list_del_rcu(&s->list);
	spin_unlock_irqrestore(&session_lock, flags);

	rds_session_close(s);

	kfree(work);
done:
	return;
}

void rds_close_all_sessions(void)
{
	unsigned long flags;
	struct rds_session *s;

	spin_lock_irqsave(&session_lock, flags);
	while (!list_empty(&session_list)) {
		s = list_entry(session_list.next,
		struct rds_session, list);
		list_del(&s->list);

		spin_unlock_irqrestore(&session_lock, flags);

		rds_session_close(s);

		spin_lock_irqsave(&session_lock, flags);
	}

	spin_unlock_irqrestore(&session_lock, flags);
}

struct rds_stall_port* rds_insert_stall_port(struct rds_session *s,
			struct rds_stall_port *stall_port)
{
	struct rb_node **p = &s->stall_rbtree.rb_node;
	struct rb_node *parent = NULL;

	struct rds_stall_port *cur;

	unsigned long flags;

	write_lock_irqsave(&s->stall_lock, flags);

	while (*p) {
		parent = *p;
		cur = rb_entry(parent, struct rds_stall_port, node);

		if (stall_port->port < cur->port)
			p = &(*p)->rb_left;
		else if (stall_port->port > cur->port)
			p = &(*p)->rb_right;
		else
			goto done;
	}
	rb_link_node(&stall_port->node, parent, p);
	rb_insert_color(&stall_port->node, &s->stall_rbtree);
	cur = NULL;
done:
	write_unlock_irqrestore(&s->stall_lock, flags);

	return cur;

}

struct rds_stall_port* rds_find_stall_port(struct rds_session *s,
					u16 port, u8 lock)
{
	struct rb_node *p = s->stall_rbtree.rb_node;
	struct rb_node *parent = NULL;

	struct rds_stall_port *cur=NULL;

	unsigned long flags=0;

	if (lock )
		read_lock_irqsave(&s->stall_lock, flags);

	while (p) {
		parent = p;
		cur = rb_entry(parent, struct rds_stall_port, node);
		if (port == cur->port )
			goto done;
		else if ( port < cur->port)
			p = p->rb_left;
		else if (port > cur->port)
			p = p->rb_right;
		cur = NULL;
	}
done:
	if (lock)
		read_unlock_irqrestore(&s->stall_lock, flags);

	return cur;

}

void rds_delete_stall_port(struct rds_session *s,
			struct rds_stall_port *p)
{
	unsigned long flags;
	write_lock_irqsave(&s->stall_lock, flags);

	rb_erase(&p->node, &s->stall_rbtree);

	write_unlock_irqrestore(&s->stall_lock, flags);
}

struct rds_stall_port *rds_wait_for_unstall(struct rds_session *s, u16 port)
{
	long timeout = 1000;
	DECLARE_WAITQUEUE(wait, current);
	struct rds_stall_port *stall=NULL, *new_stall=NULL;
	unsigned long flags;


	read_lock_irqsave(&s->stall_lock, flags);
	stall = rds_find_stall_port(s, port, FALSE);
	if (stall) {
		add_wait_queue(&stall->wait, &wait);
		set_current_state(TASK_INTERRUPTIBLE);

		read_unlock_irqrestore(&s->stall_lock, flags);

		timeout = schedule_timeout(timeout);

		read_lock_irqsave(&s->stall_lock, flags);

		remove_wait_queue(&stall->wait, &wait);
		set_current_state(TASK_RUNNING);

		if (signal_pending(current))
			return stall;


		if ( !(new_stall = rds_find_stall_port(s, port, FALSE))) {
			kfree(stall);
			stall = NULL;
			goto done;
		}
		/* We timedout and we are still stalled */
		if (new_stall != stall) {
			/* The port unstalled and stalled again, free the old one */
			kfree(stall);
			stall = new_stall;
		}
	}
done:
	read_unlock_irqrestore(&s->stall_lock, flags);
	return stall;
}

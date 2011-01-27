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

/* Init EP */
void rds_ep_init( struct rds_session *session, struct rds_ep *ep)
{
	ep->magic = RDS_MAGIC_EP;

	ep->parent_session = (void*)session;

	spin_lock_init(&ep->lock);

	init_waitqueue_head(&ep->event);
	init_waitqueue_head(&ep->active_conn_idle);

	ep->dst_addr = session->dst_addr;
	ep->src_addr = session->src_addr;

	INIT_LIST_HEAD(&ep->seg_pkts_queue);

	ep->kmem_cache = NULL;

	rds_init_buf_pool(&ep->send_pool);
	rds_init_buf_pool(&ep->recv_pool);

	ep->seg_pkt_count = 0;
}

int rds_ep_connect(struct rds_ep *ep)
{
	int err=0;

	/* validate state */
	if ( ((cmpxchg(&(ep->state.counter), EP_INIT,
		EP_ACTIVE_CONN_PENDING)) != EP_INIT ))
			return -EAGAIN;

	/* loopback ? */
	if (ep->dst_addr.s_addr == ep->src_addr.s_addr) {
		ep->loopback = TRUE;
		atomic_set(&ep->state, EP_CONNECTED);
		return 0;
	}

	/* start the connection process */
	err = rds_cma_connect(ep);
	if (err) {
		atomic_set(&ep->state, EP_DISCONNECTED);
		return err;
	}

	/* wait for connected */
	wait_event(ep->event, (atomic_read(&ep->state) == EP_CONNECTED ||
		atomic_read(&ep->state) == EP_DISCONNECTED));

	if (atomic_read(&ep->state) != EP_CONNECTED)
		return -EFAULT;

	return 0;
}

int rds_ep_disconnect(struct rds_ep *ep)
{
	int err=0;
	struct rds_session *s;

	s = (struct rds_session*)ep->parent_session;

	if (atomic_read(&ep->state) != EP_DISCONNECTED) {
		if (ep->loopback) {
			atomic_set(&ep->state, EP_DISCONNECTED);
			return 0;
		}
		err = rds_cma_disconnect(ep);
		if (err) {
			atomic_set(&ep->state, EP_DISCONNECTED);
			if (atomic_dec_and_test(&s->disconn_pend)) {
				printk("rds: session <0x%p> close timewait\n", s);
				atomic_set(&s->state, SESSION_CLOSE_TIMEWAIT);
			}
		}

		/* wait for disconnect */
		wait_event(ep->event, (atomic_read(&ep->state) == EP_DISCONNECTED) );

		if (atomic_read(&ep->state) != EP_DISCONNECTED)
			return -EFAULT;
	}

	rds_cma_cleanup_conn(ep);

	return err;
}

int rds_ep_connect_req( __be64 local_guid, __be64 remote_guid,
			struct rds_cr_prd *priv_data,
			struct rds_ep **ep)
{
	int err=0;
	u8 *daddr, *saddr;
	struct rds_session *s;

	if ( priv_data->version != RDS_PROTO_VERSION ||
		priv_data->mtu != params.mtu ||
		(priv_data->ep_type != DATA_EP &&
		priv_data->ep_type != CONTROL_EP) ) {
			err = -EINVAL;
			goto error;
	}
	daddr = (u8*) &priv_data->dst_addr.s_addr;
	saddr = (u8*) &priv_data->src_addr.s_addr;
#if 0
	printk("rds: connecting req, daddr <%d.%d.%d.%d> saddr <%d.%d.%d.%d>, type %s\n",
		daddr[0], daddr[1], daddr[2], daddr[3],
		saddr[0], saddr[1], saddr[2], saddr[3],
		(priv_data->ep_type)? "CONTROL_EP":"DATA_EP");

	printk("rds: local guid 0x%llx, remote guid 0x%llx\n",
		(u64)local_guid, (u64)remote_guid);
#endif
	/* get session for this source
	* the source addr of this request now becomes our dst
	*/

	s = rds_session_get(priv_data->src_addr, priv_data->dst_addr);

	if (!s) {
		printk("rds: could not get session for dst %d.%d.%d.%d\n",
			daddr[0], daddr[1], daddr[2], daddr[3]);
		err = -EFAULT;
		goto error;

	}
#if 0
	//if active connections pending then compare the guid and return 0 if
	// our_guid > remote_guid


#endif
	/* DATA or CONTROL EP */
	if (priv_data->ep_type == DATA_EP)
		*ep = &s->data_ep;

	else if (priv_data->ep_type == CONTROL_EP)
		*ep = &s->ctrl_ep;

	return 0;
error:
	return err;
}

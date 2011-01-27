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


#ifndef _RDS_EP_H_
#define _RDS_EP_H_

enum EP_STATE {
	EP_INIT,
	EP_ACTIVE_CONN_PENDING,
	EP_ACTIVE_CONN_IDLE,
	EP_PASSIVE_CONN_PENDING,
	EP_CONNECTED,
	EP_DISCONNECTED
};



enum EP_TYPE {
	DATA_EP,
	CONTROL_EP
};


struct rds_ep {
	u32 magic;
	spinlock_t lock;

	atomic_t ref_count;

	atomic_t state;
	u8 type;
	int loopback;

	void *parent_session;

	/* IP addresses */
	struct in_addr dst_addr;
	struct in_addr src_addr;

	struct ib_pd *pd;
	struct ib_mr *mr;
	struct ib_cq *recv_cq;
	struct ib_cq *send_cq;

	struct rdma_cm_id *cma_id;

	wait_queue_head_t event; /* Triggered on state change */
	u32 event_type;

	wait_queue_head_t active_conn_idle;
	/* DATA */
	u32 buffer_size;

	struct rds_buf_pool send_pool;
	u32 max_send_bufs;

	struct rds_buf_pool recv_pool;
	u32 max_recv_bufs;

	//spinlock_t recv_cache_lock;
	//struct list_head free_recv_cache; /* freed recv buffer cache */
	//atomic_t cache_size;
	kmem_cache_t *kmem_cache;

	/* Segmented packet queue */
	struct list_head seg_pkts_queue;
	u32 seg_pkt_count;
	u32 next_psn;

};

struct rds_cr_prd {
	u32 version;
	struct in_addr dst_addr;
	struct in_addr src_addr;
	u8 ep_type; /* Control or Data*/
	u32 mtu;
}__attribute__ ((packed));

#endif

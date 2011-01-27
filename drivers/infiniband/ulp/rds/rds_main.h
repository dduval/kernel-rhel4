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


#ifndef _RDS_MAIN_H_
#define _RDS_MAIN_H_

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define RDS "rds: "

//#define RDS_DFLT_MTU (4096 - RDS_DATA_HDR_SIZE)
#define RDS_DFLT_MTU 4096
#define RDS_PKT_SIZE (RDS_DFLT_MTU + RDS_DATA_HDR_SIZE)
#define RDS_DFLT_DATA_RX_BUFS 500
#define RDS_DFLT_DATA_TX_BUFS 100


#define RDS_DFLT_CTRL_RX_BUFS 50
#define RDS_DFTL_CTRL_TX_BUFS 50

extern struct rb_root port_rbtree;
extern rwlock_t port_lock;
extern struct workqueue_struct *rds_wq;
extern struct list_head session_list;

struct rds_params {
	u32 mtu;
	u32 max_data_recv_bufs;
	u32 max_data_send_bufs;
	u32 max_ctrl_recv_bufs;
	u32 max_ctrl_send_bufs;
#if 0
	u32 DataRecvBufferLVM;
	u32 DataRecvCoalesceFactor;
	u32 MinRnrTimer;
	u32 MaxRecvMemory;
	u32 PendingRxPktsHWM;
	u32 PerfCounters;
#endif
};

extern struct rds_params params;

struct rds_stats {
	u32 ports; /* Number of Socket ports open */
	atomic_t sessions; /* Number of Nodes connected to */
	atomic_t stalled_ports;

	union {
		struct {
			atomic_t tx_bytes_lo; /* in Bytes */
			atomic_t tx_bytes_hi; /* in Bytes */
		};
		u64 tx_bytes_as_64;
	} tx_u;
	atomic_t tx_pkts;
	atomic_t tx_errors;
	atomic_t loopback_pkts_dropped;
	union {
		struct {
			atomic_t rx_bytes_lo; /* in Bytes */
			atomic_t rx_bytes_hi; /* in Bytes */
		};
		u64 rx_bytes_as_64;
	} rx_u;

	atomic_t rx_pkts;
	atomic_t rx_pkts_pending;
	atomic_t rx_pkts_dropped;
	atomic_t rx_errors;


	/* Stats for debug ONLY */
	atomic_t rx_post_thread_wakeup;

	atomic_t stalls_sent;
	atomic_t unstalls_sent;
	atomic_t stalls_recvd;
	atomic_t unstalls_recvd;
	atomic_t rx_alloc_memory;
	atomic_t rx_cache_miss;
	atomic_t stalls_ignored;
	atomic_t enobufs;
	atomic_t ewouldblocks;
	atomic_t rx_allocs_failed;

	atomic_t failovers;
};

extern struct rds_stats rds_stats;


struct rds_port_stats {
	u32 recv_pkts;
	u32 send_pkts;
	atomic_t mem_used;
};


/* Port states */
enum {
	UNSTALLED =0,
	UNSTALL_QUEUED,
	STALLED,
	STALL_QUEUED
};


/* magic number values for verification & debug */
enum rds_magic {
	RDS_MAGIC_SESSION = 0xFeedFace,
	RDS_MAGIC_EP = 0xBeefCafe,
	RDS_MAGIC_CB = 0xBabeFace,
	RDS_MAGIC_BUF = 0xCafeFeed

};

/* Control block */
struct rds_cb {
	struct rb_node node;
	u32 magic;
	atomic_t ref;
	atomic_t state;
	struct sock *sk;
	u16 port_num;
	spinlock_t recv_q_lock;

	struct list_head recv_queue;
	atomic_t recv_pending;
	u32 max_recv;

	struct rds_port_stats stats;
	wait_queue_head_t recv_event;
	atomic_t polled;

};

/* Stall port */
struct rds_stall_port {
	struct rb_node node;
	u16 port;
	wait_queue_head_t wait;
};

enum SESSION_STATE {
	SESSION_INIT,
	SESSION_CONN_PENDING,
	SESSION_ACTIVE,
	SESSION_ERROR,
	SESSION_DISCONNECT_PENDING,
	SESSION_ABRUPT_CLOSE_PENDING,
	SESSION_CLOSE_PENDING,
	SESSION_CLOSE_TIMEWAIT,
#if 0
	SESSION_IDLE,
	SESSION_FAILOVER_PENDING,
	SESSION_FAILINGOVER,
	SESSION_FAILOVER
#endif
};

struct rds_session {
	struct list_head list; /* For rds_session_list */
	spinlock_t lock;
	u32 magic;

	atomic_t ref_count;
	atomic_t state;
	atomic_t activity;

	atomic_t conn_pend;
	atomic_t disconn_pend;

	struct in_addr dst_addr;
	struct in_addr src_addr;

	struct rds_ep data_ep; /* Data Channel */
	struct rds_ep ctrl_ep; /* Control Channel */

	/*struct list_head stall_list;
	spinlock_t stall_lock;*/

	struct rb_root stall_rbtree;
	rwlock_t stall_lock;
};

struct rds_work {
	struct work_struct work;
	struct rds_session *session;
	struct rds_cb *cb;
};


int rds_init_globals(void);
void rds_cleanup_globals(void);
void rds_cleanup_caches(void);

/* Control Block */
struct rds_cb* rds_alloc_cb(struct sock *sk);
void rds_free_cb(struct rds_cb *cb);
struct rds_cb* rds_insert_port(struct rds_cb *cb);
void rds_delete_port(struct rds_cb *cb);
struct rds_cb *rds_find_port(u16 port);

struct rds_stall_port* rds_insert_stall_port(struct rds_session *s,
struct rds_stall_port *stall_port);
struct rds_stall_port* rds_find_stall_port(struct rds_session *s,
	u16 port, u8 lock);
void rds_delete_stall_port(struct rds_session *s,
struct rds_stall_port *p);
struct rds_stall_port
	*rds_wait_for_unstall(struct rds_session *s, u16 port);

void rds_chk_port_quota(struct rds_cb *cb);

/* Session */
struct rds_session* rds_session_get(struct in_addr dst_addr,
struct in_addr src_addr);
int rds_session_connect(struct rds_session *s);
void rds_session_put(struct rds_session *s);
void rds_close_all_sessions(void);
void rds_queue_session_close(struct rds_session *s);
void rds_session_close_cb(void *c);


/* Send */
int rds_sendmsg(struct kiocb *iocb, struct sock *sk,
struct msghdr *msg, size_t len);
void rds_send_completion(void *context, struct ib_wc *wc);
void rds_send_port_stall( void *context);
void rds_send_port_unstall( void *context);
int rds_wait_for_space(struct rds_ep *ep, int pkts);

/* Recv */
int rds_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t total_len, int nonblock, int flags, int *addrlen);
int rds_post_recvs_list(struct rds_ep *ep);
void rds_recv_completion(void *context, struct ib_wc *wc);
void rds_free_pending_recvs(struct rds_cb *cb);
void rds_recv_buffer_put(struct rds_buf *buf);

/* EP */
void rds_ep_init( struct rds_session *session, struct rds_ep *ep);
int rds_ep_connect(struct rds_ep *ep);
int rds_ep_disconnect(struct rds_ep *ep);
int rds_ep_connect_req( __be64 local_guid, __be64 remote_guid,
struct rds_cr_prd *priv_data,
struct rds_ep **ep);

/* Buffers */
void rds_init_buf_pool(struct rds_buf_pool *buf_pool);
int rds_alloc_send_pool(struct rds_ep *ep);
int rds_alloc_recv_pool(struct rds_ep *ep);
void rds_free_pool(struct rds_buf_pool *pool);
int rds_get_send_list(struct rds_ep *ep, size_t length,
	struct list_head *send_list, int *count);
int rds_get_send_list_lpbk(struct rds_ep *ep, size_t length,
	struct list_head *send_list, int *count);
void rds_put_send_list(struct rds_ep *ep,
	struct list_head *send_list, u8 avail );
void rds_put_send_list_lpbk(struct rds_ep *ep,
	struct list_head *send_list );
struct rds_buf* rds_alloc_recv_buffer(struct rds_ep *ep, unsigned int flags);
void rds_free_buffer(struct rds_buf *buff);


/* CMA */
int rds_cma_init (void);
int rds_cma_connect( struct rds_ep *ep);
int rds_cma_disconnect( struct rds_ep *ep);
void rds_cma_cleanup_conn(struct rds_ep *ep);
void rds_cma_exit (void);

#endif

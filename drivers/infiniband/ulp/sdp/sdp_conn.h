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
 * $Id: sdp_conn.h 3033 2005-08-09 12:45:08Z mst $
 */

#ifndef _SDP_CONN_H
#define _SDP_CONN_H

#include <linux/list.h>

#include "sdp_advt.h"
#include "sdp_iocb.h"
#include "sdp_dev.h"

/*
 * SDP connection specific definitions
 */

/*
 * definitions
 */
#define SDP_CONN_COMM_ID_NULL   0xFFFFFFFF	/* when no id is available */

#define SDP_CONN_F_SRC_CANCEL_L 0x01 /* source cancel was issued */
#define SDP_CONN_F_SRC_CANCEL_R 0x02 /* source cancel was received */
#define SDP_CONN_F_SRC_CANCEL_C 0x04 /* source data cancelled */
#define SDP_CONN_F_SNK_CANCEL   0x08 /* sink cancel issued */
#define SDP_CONN_F_DIS_HOLD     0x10 /* Hold pending disconnects. */
#define SDP_CONN_F_DIS_PEND     0x20 /* disconnect pending. */
#define SDP_CONN_F_OOB_SEND     0x40 /* OOB notification pending. */
#define SDP_CONN_F_DEAD         0xFF /* connection has been deleted */

/*
 * SDP states.
 */
enum sdp_mode {
	SDP_MODE_BUFF = 0x00,
	SDP_MODE_COMB = 0x01,
	SDP_MODE_PIPE = 0x02,
	SDP_MODE_ERROR = 0x03
};

/*
 * First two bytes are the primary state values. Third and fourth
 * byte are a bit field used for different mask operations, defined
 * below.
 */
#define SDP_CONN_ST_LISTEN      0x0100 /* listening */

#define SDP_CONN_ST_ESTABLISHED 0x1171 /* connected */

#define SDP_CONN_ST_REQ_PATH    0x2100 /* active open, path record lookup */
#define SDP_CONN_ST_REQ_SENT    0x2200 /* active open, Hello msg sent */
#define SDP_CONN_ST_REQ_RECV    0x2340 /* passive open, Hello msg recv'd */
#define SDP_CONN_ST_REP_RECV    0x2440 /* active open, Hello ack recv'd */

#define SDP_CONN_ST_DIS_RECV_1  0x4171 /* recv disconnect, passive close */
#define SDP_CONN_ST_DIS_SEND_1  0x4271 /* send disconnect, active close */
#define SDP_CONN_ST_DIS_SENT_1  0x4361 /* disconnect sent, active close */
#define SDP_CONN_ST_DIS_RECV_R  0x4471 /* disconnect recv, active close */
#define SDP_CONN_ST_DIS_SEND_2  0x4571 /* send disconnect, passive close */
#define SDP_CONN_ST_TIME_WAIT_1 0x4701 /* IB/gateway disconnect */
#define SDP_CONN_ST_TIME_WAIT_2 0x4801 /* waiting for idle close */

#define SDP_CONN_ST_CLOSED      0x8E01 /* not connected */
#define SDP_CONN_ST_ERROR       0x8D01 /* not connected */
#define SDP_CONN_ST_INVALID     0x8F01 /* not connected */

/*
 * states masks for SDP
 */
#define SDP_ST_MASK_CONNECT   0x2000    /* connection establishment states */
#define SDP_ST_MASK_CLOSED    0x8000    /* all connection closed states. */
#define SDP_ST_MASK_EVENTS    0x0001	/* event processing is allowed. */
#define SDP_ST_MASK_SEND_OK   0x0010	/* posting data for send */
#define SDP_ST_MASK_CTRL_OK   0x0020	/* posting control for send */
#define SDP_ST_MASK_RCV_POST  0x0040	/* posting IB recv's is allowed. */

/*
 * event dispatch table
 */
#define SDP_MSG_EVENT_TABLE_SIZE 0x20

/*
 * state transition information recording
 */
#ifdef _SDP_CONN_STATE_REC

#define SDP_CONN_STATE_MAX 16 /* maximum state transitions recorded. */

struct sdp_conn_state {
	__u8  value;
	__u16 state[SDP_CONN_STATE_MAX];
	void *file[SDP_CONN_STATE_MAX];
	__s32 line[SDP_CONN_STATE_MAX];
};

#define SDP_CONN_ST_SET(conn, val) \
do { \
  (conn)->state = (val); \
  if (SDP_CONN_STATE_MAX > (conn)->state_rec.value) { \
    (conn)->state_rec.state[(conn)->state_rec.value] = (val); \
    (conn)->state_rec.file[(conn)->state_rec.value] = __FILE__; \
    (conn)->state_rec.line[(conn)->state_rec.value] = __LINE__; \
    (conn)->state_rec.value++; \
  } \
} while (0)

#define SDP_CONN_ST_INIT(conn) \
do { \
  (conn)->state = SDP_CONN_ST_INVALID; \
  for ((conn)->state_rec.value = 0; \
       SDP_CONN_STATE_MAX > (conn)->state_rec.value; \
       (conn)->state_rec.value++) { \
    (conn)->state_rec.state[(conn)->state_rec.value] = SDP_CONN_ST_INVALID;\
    (conn)->state_rec.file[(conn)->state_rec.value] = NULL; \
    (conn)->state_rec.line[(conn)->state_rec.value] = 0; \
  } \
  (conn)->state_rec.value = 0; \
} while (0)
#else
#define SDP_CONN_ST_SET(conn, val) ((conn)->state = (val))
#define SDP_CONN_ST_INIT(conn)     ((conn)->state = SDP_CONN_ST_INVALID)
#endif

/*
 * connection lock
 */
struct sdp_conn_lock {
	u16 users;
	u16 event;
	spinlock_t slock;
	wait_queue_head_t waitq;
};

#define SDP_LOCK_F_RECV_CQ 0x01 /* recv CQ event is pending */
#define SDP_LOCK_F_SEND_CQ 0x02 /* send CQ event is pending */
/*
 * SDP Connection structure.
 */
struct sdp_sock {
	__s32 hashent;     /* connection ID/hash entry */
	atomic_t refcnt;   /* connection reference count. */

	struct sock *sk;
	/*
	 * SDP specific data
	 */
	u32 send_buf;
	u32 send_qud;
	u32 send_pipe;	/* buffered bytes in the local send queue */
	s32 oob_offset;	/* bytes till OOB byte is sent. */

	s16 send_usig;  /* number of unsignalled sends in the pipe. */
	s16 send_cons;  /* number of consecutive unsignalled sends. */
	s16 usig_max;   /* maximum unsignalled back-to-back sends. */


	struct sdpc_desc_q send_queue;	/* queue of send objects. */
	struct sdpc_buff_q send_post;	/* posted sends */

	u32 send_seq;	/* sequence number of last message sent */
	u32 recv_seq;	/* sequence number of last message received */
	u32 advt_seq;	/* sequence number of last message acknowledged */

	struct sdpc_buff_q recv_pool;	/* pool of received buffer */
	struct sdpc_buff_q recv_post;	/* posted receives */

	s32 byte_strm;  /* buffered bytes in the local recv queue */
	s32 rwin_max;   /* maximum recveive window size */

	u16 state;      /* connection state */

	u8  flags;      /* single bit flags. */
	u8  shutdown;   /* shutdown flag */
	u8  recv_mode;  /* current flow control mode */
	u8  send_mode;  /* current flow control mode */

	u16 recv_max;   /* max posted/used receive buffers */
	u16 send_max;   /* max posted/used send buffers */

	u16 recv_size;  /* local recv buffer size */
	u16 send_size;  /* remote recv buffer size */

	u8  l_max_adv;  /* local maximum zcopy advertisments */
	u8  r_max_adv;  /* remote maximum zcopy advertisments */
	u8  s_cur_adv;  /* current source advertisments (slow start) */
	u8  s_par_adv;  /* current source advertisments (slow start) */

	u16 r_recv_bf;  /* number of recv buffers remote currently has */
	u16 l_recv_bf;  /* number of recv buffers local currently has */
	u16 l_advt_bf;  /* number of recv buffers local has advertised */

	u8  s_wq_size;  /* current number of posted sends. */

	u8  s_wq_cur;   /* buffered transmission limit current */
	u8  s_wq_par;   /* buffered transmission limit increment */

	u8  src_recv;   /* outstanding remote source advertisments */
	u8  snk_recv;   /* outstanding remote sink advertisments */
	u8  src_sent;   /* outstanding local source advertisments */
	u8  snk_sent;   /* outstanding local sink advertisments */

	u8  src_cncl;   /* local source advertisments cancelled by user */
	u32 src_cseq;   /* sequence number of source cancel message */
	/*
	 * work request ID's used to double-check queue consistency
	 */
	u64 send_wrid;
	u64 recv_wrid;

	u32 send_cq_size;
	u32 recv_cq_size;
	/*
	 * stale SnkAvail detection
	 */
	u32 nond_recv;	/* non discarded buffers received. */
	u32 nond_send;	/* non discarded buffers sent */
	/*
	 * OOB/URG data transfer.
	 */
	s16 rcv_urg_cnt;	/* queued urgent data */
	/*
	 * listen backlog
	 */
	u16 backlog_cnt;	/* depth of the listen backlog queue */
	u16 backlog_max;	/* max length of the listen backlog queue */
	/*
	 * memory specific data
	 */
	struct sdpc_desc_q send_ctrl;	/* control messages waiting to
					   be transmitted, which do not
					   depend on data ordering */
	/*
	 * advertisment managment
	 */
	struct sdpc_advt_q src_pend; /* pending remote source advertisments */
	struct sdpc_advt_q src_actv; /* active remote source advertisments */
	struct sdpc_advt_q snk_pend; /* pending remote sink advertisments */
	/*
	 * outstanding IOCBs/BUFFs
	 */
	struct sdpc_iocb_q r_pend; /* pending user read IOCBs */
	struct sdpc_iocb_q r_snk;  /* active user read sink IOCBs */
	struct sdpc_iocb_q w_src;  /* active user write source IOCBs */

	struct sdpc_desc_q r_src;  /* active user read source IOCBs */
	struct sdpc_desc_q w_snk;  /* active user write sink IOCBs */
	/*
	 * addresses
	 */
	u32 src_addr; /* ipv4 address on the stream interface */
	u32 dst_addr; /* ipv4 address of the remote SDP client */
	u16 dst_port; /* tcp port of the remote SDP client */
	u16 src_port; /* tcp port on the stream interface */
	/*
	 * IB specific data
	 */
	union ib_gid d_gid;
	union ib_gid s_gid;
	u16 d_lid;
	u16 s_lid;
	u32 d_qpn;
	u32 s_qpn;
	u32 rq_psn;
        enum ib_mtu path_mtu;

	struct ib_device *ca;	/* hca that we'll be using for sdp */
	struct ib_qp *qp;	/* queue pair for the SDP connection */
	struct ib_pd *pd;	/* protection domain used by the kernel */
	struct ib_cq *send_cq;	/* send completion queue */
	struct ib_cq *recv_cq;	/* recv completion queue */
	u8  hw_port;            /* hca port */
	u32 l_key;		/* local key for buffered memory */
	struct ib_fmr_pool *fmr_pool;	/* fast memory for Zcopy */
	/*
	 * CM connection handle
	 */
	struct ib_cm_id *cm_id;
	/*
	 * timer for defered execution. Used to call CM functions from a
	 * non-interupt context.
	 */
	struct work_struct cm_exec; /* task for defered completion. */
	/*
	 * path record ID lookup
	 */
	u64 plid;
	/*
	 * SDP connection lock
	 */
	struct sdp_conn_lock lock;
	/*
	 * table managment
	 */
	struct list_head lstn_next;
	struct list_head bind_next;

	/*
	 * listen/accept managment
	 */
	struct sdp_sock *parent;      /* listening socket queuing. */
	struct sdp_sock *accept_next; /* sockets waiting for acceptance. */
	struct sdp_sock *accept_prev; /* sockets waiting for acceptance. */
	/*
	 * OS info
	 */
	u16 pid;		/* process ID of creator */
	/*
	 * TCP specific socket options
	 */
	u8  nodelay;		/* socket nodelay is set */
	u32 src_zthresh;	/* source zero copy threshold */
	u32 snk_zthresh;	/* sink zero copy threshold */
	/*
	 * stats
	 */
	u32 send_mid[SDP_MSG_EVENT_TABLE_SIZE];	/* send event stats */
	u32 recv_mid[SDP_MSG_EVENT_TABLE_SIZE];	/* recv event stats */

	u64 send_bytes;   /* socket bytes sent */
	u64 recv_bytes;   /* socket bytes received */
	u64 write_bytes;  /* AIO bytes sent */
	u64 read_bytes;   /* AIO bytes received */

	u32 read_queued;  /* reads queued for reception */
	u32 write_queued; /* writes queued for transmission */

	u32 src_serv;     /* source advertisments completed. */
	u32 snk_serv;     /* sink advertisments completed. */

#ifdef _SDP_CONN_STATE_REC
	struct sdp_conn_state state_rec;
#endif
};

#define SDP_WRAP_GT(x, y) ((signed int)((x) - (y)) > 0)
#define SDP_WRAP_LT(x, y) ((signed int)((x) - (y)) < 0)
#define SDP_WRAP_GTE(x, y) ((signed int)((x) - (y)) >= 0)
#define SDP_WRAP_LTE(x, y) ((signed int)((x) - (y)) <= 0)

/*
 * statistics.
 */
#ifdef _SDP_CONN_STATS_REC
#define SDP_CONN_STAT_SEND_INC(conn, size)  ((conn)->send_bytes += (size))
#define SDP_CONN_STAT_RECV_INC(conn, size)  ((conn)->recv_bytes += (size))
#define SDP_CONN_STAT_READ_INC(conn, size)  ((conn)->read_bytes += (size))
#define SDP_CONN_STAT_WRITE_INC(conn, size) ((conn)->write_bytes += (size))

#define SDP_CONN_STAT_RQ_INC(conn, size) ((conn)->read_queued  += (size))
#define SDP_CONN_STAT_WQ_INC(conn, size) ((conn)->write_queued += (size))
#define SDP_CONN_STAT_RQ_DEC(conn, size) ((conn)->read_queued  -= (size))
#define SDP_CONN_STAT_WQ_DEC(conn, size) ((conn)->write_queued -= (size))

#define SDP_CONN_STAT_SRC_INC(conn) ((conn)->src_serv++)
#define SDP_CONN_STAT_SNK_INC(conn) ((conn)->snk_serv++)

#define SDP_CONN_STAT_SEND_MID_INC(conn, mid) \
        ((conn)->send_mid[(mid)]++)
#define SDP_CONN_STAT_RECV_MID_INC(conn, mid) \
        ((conn)->recv_mid[(mid)]++)
#else
#define SDP_CONN_STAT_SEND_INC(conn, size)
#define SDP_CONN_STAT_RECV_INC(conn, size)
#define SDP_CONN_STAT_READ_INC(conn, size)
#define SDP_CONN_STAT_WRITE_INC(conn, size)

#define SDP_CONN_STAT_RQ_INC(conn, size)
#define SDP_CONN_STAT_WQ_INC(conn, size)
#define SDP_CONN_STAT_RQ_DEC(conn, size)
#define SDP_CONN_STAT_WQ_DEC(conn, size)

#define SDP_CONN_STAT_SRC_INC(conn)
#define SDP_CONN_STAT_SNK_INC(conn)

#define SDP_CONN_STAT_SEND_MID_INC(conn, mid)
#define SDP_CONN_STAT_RECV_MID_INC(conn, mid)

#endif

/*
 * connection handle within a socket.
 */

#define SDP_GET_CONN(sk) \
       (*((struct sdp_sock **)&(sk)->sk_protinfo))
#define SDP_SET_CONN(sk, conn) \
       (*((struct sdp_sock **)&(sk)->sk_protinfo) = (conn))

static inline struct sdp_sock *sdp_sk(struct sock *sk)
{
	return SDP_GET_CONN(sk);
}

static inline struct sock *sk_sdp(struct sdp_sock *conn)
{
	return conn->sk;
}

/*
 * SDP connection lock
 */
extern void sdp_conn_internal_lock(struct sdp_sock *conn, unsigned long *flags);
extern void sdp_conn_internal_unlock(struct sdp_sock *conn);
extern void sdp_conn_relock(struct sdp_sock *conn);
extern int sdp_conn_cq_drain(struct ib_cq *cq, struct sdp_sock *conn);

#define SDP_CONN_LOCK_IRQ(conn, flags) \
        spin_lock_irqsave(&((conn)->lock.slock), flags)
#define SDP_CONN_UNLOCK_IRQ(conn, flags) \
        spin_unlock_irqrestore(&((conn)->lock.slock), flags)

static inline void sdp_conn_lock(struct sdp_sock *conn)
{
	unsigned long flags;

	might_sleep();

	spin_lock_irqsave(&conn->lock.slock, flags);
	if (conn->lock.users != 0) {

		sdp_conn_internal_lock(conn, &flags);
	}

	conn->lock.users = 1;
	spin_unlock_irqrestore(&(conn->lock.slock), flags);
}

static inline void sdp_conn_unlock(struct sdp_sock *conn)
{
	unsigned long flags;

	spin_lock_irqsave(&conn->lock.slock, flags);
	if (conn->lock.event && (conn->state & SDP_ST_MASK_EVENTS)) {

		sdp_conn_internal_unlock(conn);
	}

	conn->lock.users = 0;
	wake_up(&conn->lock.waitq);

	spin_unlock_irqrestore(&conn->lock.slock, flags);
}

/*
 * connection reference counting.
 */
static inline void sdp_conn_hold(struct sdp_sock *conn)
{
	atomic_inc(&conn->refcnt);
}

/*
 * safe to call if there's another reference on connection.
 */
static inline void sdp_conn_put_light(struct sdp_sock *conn)
{
	int noref = atomic_dec_and_test(&conn->refcnt);
	BUG_ON(noref);
}

void sdp_conn_put(struct sdp_sock *conn);

static inline void *hashent_arg(s32 hashent)
{
	return (void *)(unsigned long)hashent;
}

#endif /* _SDP_CONN_H */

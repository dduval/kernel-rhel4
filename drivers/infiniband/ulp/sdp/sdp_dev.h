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
 * $Id: sdp_dev.h 3465 2005-09-18 08:27:39Z mst $
 */

#ifndef _SDP_DEV_H
#define _SDP_DEV_H
/*
 * linux types
 */
#include <linux/module.h>
#include <linux/errno.h>	/* error codes       */
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <net/sock.h>
/*
 * sdp types
 */
#include <rdma/ib_verbs.h>
#include "sdp_msgs.h"

#define SDP_MSG_HDR_REQ_SIZE 0x10 /* required header size (BSDH) */
#define SDP_MSG_HDR_OPT_SIZE 0x14 /* optional header size (SNKAH) */
#define SDP_MSG_HDR_SIZE     SDP_MSG_HDR_REQ_SIZE
/*
 * set of performance parameters. Some are interdependent. If you
 * change, run full regression test suite, you may be surprised.
 */
#define SDP_INET_RECV_SIZE  0x40000 /* number of bytes in flight */
#define SDP_INET_SEND_SIZE  0x40000
#define SDP_CQ_SEND_SIZE    0x003F
#define SDP_CQ_RECV_SIZE    0x003F

#define SDP_BUFF_RECV_MAX   0x0040 /* max number of recvs buffered  */
#define SDP_BUFF_SEND_MAX   0x0040 /* max number of sends buffered  */
#define SDP_INET_SEND_MODE  0x0002 /* tx backlog before PIPELINED mode */

#define SDP_INET_SEND_MARK     1024 /* send high water mark */
#define SDP_INET_PORT_LOW     32768
#define SDP_INET_PORT_HIGH    61000

#define SDP_QP_LIMIT_SG_SEND   0x0001 /* max send scather/gather entries */
#define SDP_QP_LIMIT_SG_RECV   0x0001 /* max recv scather/gather entries */

#define SDP_CM_PARAM_RETRY     0x07 /* connect retry count. */
#define SDP_CM_PARAM_RNR_RETRY 0x07 /* RNR retry count. */
/*
 * maximum number of src/sink advertisments we can handle at a given time.
 */
#define SDP_MSG_MAX_ADVS        0xFF
/*
 * Service ID is 64 bits, but a socket port is only the low 16 bits, a
 * mask is defined for the rest of the 48 bits, and is reserved in the
 * IBTA.
 */
#define SDP_MSG_SERVICE_ID_RANGE (0x0000000000010000ULL)
#define SDP_MSG_SERVICE_ID_VALUE (0x000000000001FFFFULL)
#define SDP_MSG_SERVICE_ID_MASK  (0xFFFFFFFFFFFF0000ULL)

#define SDP_SID_TO_PORT(sid)  ((u16)((sid) & 0xFFFF))
#define SDP_PORT_TO_SID(port) \
        ((u64)(SDP_MSG_SERVICE_ID_RANGE | ((port) & 0xFFFF)))
/*
 * invalid socket identifier, top entry in table.
 */
#define SDP_DEV_SK_LIST_SIZE 16384  /* array of active sockets */
#define SDP_DEV_SK_INVALID   (-1)   /* negative index into the table */
/*
 * The protocol requires a SrcAvail message to contain at least one
 * byte of the data stream, when the connection is in combined mode.
 * Here's the amount of data to send.
 */
#define SDP_SRC_AVAIL_MIN 0x01
#define SDP_SRC_AVAIL_RECV  0x40
/*
 * Slow start for src avail advertisments. (because they are slower then
 * sink advertisments.) Fractional increase. If we've received a sink
 * then use the fractional component for an even slower start. Once
 * a peer is known to use sinks, they probably will again.
 */
#define SDP_SEND_POST_FRACTION   0x06
#define SDP_SEND_POST_SLOW   0x01
#define SDP_SEND_POST_COUNT  0x0A
/*
 * SDP experimental parameters.
 */

/*
 * maximum consecutive unsignalled send events.
 * (crap, watch out for deactivated nodelay!)
 */
#if 0
#define SDP_SEND_UNSIG_MAX 0x00
#else
#define SDP_SEND_UNSIG_MAX 0x0F
#endif
/*
 * FMR pool creation parameters.
 */
#define SDP_FMR_POOL_SIZE  1024
#define SDP_FMR_DIRTY_SIZE 32
/*
 * connection flow control.
 */
#define SDP_RECV_POST_FREQ 0x08	/* rate for posting new recv buffs */
#define SDP_RECV_POST_ACK  0x08	/* rate for posting ack windows. */

/*
 * SDP root device structure
 */
struct sdev_hca_port {
	u8                    index; /* port ID */
	union ib_gid          gid;   /* port GID */
	struct list_head      list;
};

struct sdev_hca {
	struct ib_device     *ca;        /* HCA */
	struct ib_pd         *pd;        /* protection domain for this HCA */
	struct ib_mr         *mem_h;     /* registered memory region */
	u32                   l_key;     /* local key */
	u32                   r_key;     /* remote key */
	struct ib_fmr_pool   *fmr_pool;  /* fast memory for Zcopy */
	struct list_head      port_list; /* ports on this HCA */
	struct ib_cm_id	     *listen_id;
};

struct sdev_root {
	u32 src_addr;
	int proto;
	/*
	 * tuneable limits
	 */
	int recv_post_max;
	int recv_buff_max;
	int send_post_max;
	int send_buff_max;
	int send_usig_max;
	/*
	 * connections. The table is a simple linked list, since it does not
	 * need fast lookup capabilities.
	 */
	u32 sk_size;  /* socket array size */
	u32 sk_ordr;  /* order size of region. */
	u32 sk_rover; /* next potential available space. */
	u32 sk_entry; /* number of socket table entries. */
	struct sdp_sock **sk_array;	/* array of sockets. */
	/*
	 * connection managment
	 */
	struct list_head listen_list;
	struct list_head bind_list;	/* connections bound to a port. */
	/*
	 * list locks
	 */
	spinlock_t bind_lock;
	spinlock_t sock_lock;
	spinlock_t listen_lock;
 	/*
	 * caches
 	 */
	kmem_cache_t *conn_cache;
	kmem_cache_t *sock_cache;
};

#endif /* _SDP_DEV_H */

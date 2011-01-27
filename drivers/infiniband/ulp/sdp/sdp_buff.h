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
 * $Id: sdp_buff.h 3370 2005-09-12 14:15:59Z mst $
 */

#ifndef _SDP_BUFF_H
#define _SDP_BUFF_H

#include "sdp_queue.h"
/*
 * structures
 */
struct sdpc_buff_q {
	struct sdpc_buff *head; /* double linked list of buffers */
	u32 size;               /* number of buffers in the pool */
};

struct sdpc_buff {
	struct sdpc_buff   *next;
	struct sdpc_buff   *prev;
	u32                 type; /* element type. (for generic queue) */
	struct sdpc_buff_q *pool; /* pool currently holding this buffer. */
	void (*release)(struct sdpc_buff *buff); /* release the object */
	/*
	 * primary generic data pointers
	 */
	void *head; /* first byte of data buffer */
	void *data; /* first byte of valid data in buffer */
	void *tail; /* last byte of valid data in buffer */
	void *end;  /* last byte of data buffer */
	/*
	 * Experimental
	 */
	u32 flags;  /* Buffer flags */
	/*
	 * Protocol specific data
	 */
	struct msg_hdr_bsdh *bsdh_hdr; /* SDP header (BSDH) */
	u32 data_size;                 /* size of just data in the buffer */
	u64 wrid;                   /* IB work request ID */
	/*
	 * IB specific data (The main buffer pool sets the lkey when
	 * it is created)
	 */
	struct ib_sge sge;
};

struct sdpc_buff_root {
	kmem_cache_t *pool_cache; /* pool of buffers */
	kmem_cache_t *buff_cache; /* cache of buffer descriptor objects */
};

/*
 * buffer flag defintions
 */
#define SDP_BUFF_F_UNSIG    0x0001	/* unsignalled buffer */
#define SDP_BUFF_F_SE       0x0002	/* buffer is an IB solicited event */
#define SDP_BUFF_F_OOB_PEND 0x0004	/* urgent byte in flight (OOB) */
#define SDP_BUFF_F_OOB_PRES 0x0008	/* urgent byte in buffer (OOB) */
#define SDP_BUFF_F_QUEUED   0x0010	/* buffer is queued for transmission */

#define SDP_BUFF_F_GET_SE(buff)    ((buff)->flags &    SDP_BUFF_F_SE)
#define SDP_BUFF_F_SET_SE(buff)    ((buff)->flags |=   SDP_BUFF_F_SE)
#define SDP_BUFF_F_CLR_SE(buff)    ((buff)->flags &= (~SDP_BUFF_F_SE))
#define SDP_BUFF_F_GET_UNSIG(buff) ((buff)->flags &    SDP_BUFF_F_UNSIG)
#define SDP_BUFF_F_SET_UNSIG(buff) ((buff)->flags |=   SDP_BUFF_F_UNSIG)
#define SDP_BUFF_F_CLR_UNSIG(buff) ((buff)->flags &= (~SDP_BUFF_F_UNSIG))

/*
 * pool size
 */
#define sdp_buff_q_size(pool) ((pool)->size)

#define sdp_buff_pool_buff_size() PAGE_SIZE

#endif /* _SDP_BUFF_H */

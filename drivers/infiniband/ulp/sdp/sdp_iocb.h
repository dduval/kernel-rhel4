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
 * $Id: sdp_iocb.h 3202 2005-08-26 17:11:34Z roland $
 */

#ifndef _SDP_IOCB_H
#define _SDP_IOCB_H

#include <linux/config.h>
#include <rdma/ib_fmr_pool.h>
#include "sdp_queue.h"
/*
 * definitions
 */
#define SDP_IOCB_KEY_INVALID 0xffffffff	/* invalid IOCB key */
/*
 * IOCB flags.
 */
#define SDP_IOCB_F_BUFF   0x00000001 /* IOCB must be sent buffered */
#define SDP_IOCB_F_CANCEL 0x00000002 /* IOCB has a pending cancel. */
#define SDP_IOCB_F_ACTIVE 0x00000004 /* IOCB has an active operation */
#define SDP_IOCB_F_QUEUED 0x00000008 /* IOCB is queued for transmission */
#define SDP_IOCB_F_RDMA_R 0x00000010 /* IOCB is in RDMA read processing */
#define SDP_IOCB_F_RDMA_W 0x00000020 /* IOCB is in RDMA write processing */
#define SDP_IOCB_F_LOCKED 0x00000040 /* IOCB is locked in memory */
#define SDP_IOCB_F_REG    0x00000080 /* IOCB memory is registered */
#define SDP_IOCB_F_RECV   0x00000100 /* IOCB is for a receive request */
#define SDP_IOCB_F_ALL    0xFFFFFFFF /* IOCB all mask */
/*
 * zcopy constants.
 */
#define SDP_IOCB_SIZE_MAX (128*1024) /* matches AIO max kvec size. */
#define SDP_IOCB_PAGE_MAX (SDP_IOCB_SIZE_MAX/PAGE_SIZE)
/*
 * make size a macro.
 */
#define sdp_iocb_q_size(table) ((table)->size)

/*
 * INET read/write IOCBs
 */

/*
 * save a kvec read/write for processing once data shows up.
 */
struct sdpc_iocb {
	struct sdpc_iocb   *next;  /* next structure in table */
	struct sdpc_iocb   *prev;  /* previous structure in table */
	u32                 type;  /* element type. (for generic queue) */
	struct sdpc_iocb_q *table; /* table to which this iocb belongs */
	void (*release)(struct sdpc_iocb *iocb); /* release the object */
	/*
	 * iocb sepcific
	 */
	int      flags;  /* usage flags */
	/*
	 * iocb information
	 */
	u32 key;    /* matches kiocb key for lookups */
	int len;    /* space left in the user buffer */
	int post;   /* amount of data requested so far. */
	u64 wrid;   /* work request completing this IOCB */
	ssize_t status; /* status of completed iocb */
	/*
	 * IB specific information for zcopy.
	 */
	struct ib_pool_fmr *mem;     /* memory region handle */
	u32                 l_key;   /* local access key */
	u32                 r_key;   /* remote access key */
	u64                 io_addr; /* virtual IO address */
	/*
	 * page list. data for locking/registering userspace
	 */
	struct mm_struct   *mm;      /* user mm struct */
	struct task_struct *tsk;
	unsigned long       addr;    /* user space address */
	size_t              size;    /* total size of the user buffer */

	struct page **page_array;  /* list of page structure pointers. */
	u64          *addr_array;  /* list of physical page addresses. */
	int           page_count;  /* number of physical pages. */
	int           page_offset; /* offset into first page. */

	struct work_struct completion; /* task for defered completion. */
	/*
	 * kernel iocb structure
	 */
	struct kiocb *req;
	struct sock_iocb *si;
};

/*
 * table for IOCBs
 */
struct sdpc_iocb_q {
	struct sdpc_iocb *head; /* double linked list of IOCBs */
	int size;               /* current number of IOCBs in table */
};

#endif /* _SDP_IOCB_H */

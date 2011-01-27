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

#ifndef _RDS_BUF_H_
#define _RDS_BUF_H_


enum BUFFER_STATE {
	BUFFER_AVAILABLE,
	BUFFER_SEND_PENDING,
	BUFFER_SEND_ERROR,
	BUFFER_RESEND_PENDING
};
enum OP_TYPE {
	OP_SEND,
	OP_RECV
};

struct rds_buf {
	struct list_head list_item;
	u32 magic;
	u8 state;
	u8 loopback;
	enum OP_TYPE optype;

	void *parent_ep;
	void *data; /* Virtual address of data */

	struct ib_sge sge;
	union {
		struct ib_send_wr send_wr;
		struct ib_recv_wr recv_wr;
	} wr;
	u32 psn;
	struct in_addr src_addr;
	u32 recv_len;
	u32 pkts;
	u32 copied;
	DECLARE_PCI_UNMAP_ADDR(mapping)
};

struct rds_buf_pool {
	struct list_head buffer_list; /* List of struct rds_buf */
	struct rds_buf *next_avail_buf;
	spinlock_t lock;
	atomic_t num_available;
	atomic_t num_posted;

	u32 buffer_size;
	u32 num_buffers;

	wait_queue_head_t event;

	struct list_head coalesce_list;
	u32 coalesce_max;
	u32 coalesce_count;

};

#endif

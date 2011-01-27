/*
 * Copyright (c) 2005 Voltaire. Inc.  All rights reserved.
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
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
 * $Id: uat.h 3202 2005-08-26 17:11:34Z roland $
 */

#ifndef UAT_H
#define UAT_H

#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/idr.h>

#include <rdma/ib_at.h>
#include <rdma/ib_user_at.h>

struct ib_uat_file {
	struct semaphore mutex;
	struct file *filp;
	/*
	 * list of pending events
	 */
	struct list_head  ctxs;   /* list of active requests */
	struct list_head  events; /* list of pending events */
	wait_queue_head_t poll_wait;
};

struct ib_uat_context {
	int                 id;
	int                 ref;

	struct ib_uat_file *file;
	struct semaphore    mutex;

	struct list_head    events;    /* list of pending events. */
	struct list_head    file_list; /* member in file ctx list */

	u64		    req_id;
	struct ib_sa_path_rec *path_arr;
	struct ib_at_route *ib_route;
	u32                *ips;
	struct ib_at_completion *comp;
	void (*user_callback)(u64 req_id, void *context, int rec_num);
	void		   *user_context;
	struct ib_sa_path_rec *user_path_arr;
	struct ib_uat_ib_route *user_ib_route;
	u32		   *user_ips;
	int		    user_length;
	int		    status;
	int		    rec_num;
};

enum ib_uat_event_type {
	IB_UAT_PATH_EVENT,
	IB_UAT_ROUTE_EVENT,
	IB_UAT_IPS_EVENT,
};

struct ib_uat_event {
	enum ib_uat_event_type type;
	struct ib_uat_context *ctx;
	struct list_head file_list; /* member in file event list */
	struct list_head ctx_list;  /* member in ctx event list */
	struct ib_uat_event_resp resp;
};
#endif /* UAT_H */

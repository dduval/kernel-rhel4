/*
 * Copyright (c) 2005 Voltaire, Inc.  All rights reserved.
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
 * $Id: ib_user_at.h 3202 2005-08-26 17:11:34Z roland $
 */

#ifndef IB_USER_AT_H
#define IB_USER_AT_H

#include <linux/types.h>
#include <rdma/ib_verbs.h>

#define IB_USER_AT_ABI_VERSION 1

enum {
	IB_USER_AT_CMD_ROUTE_BY_IP,
	IB_USER_AT_CMD_PATHS_BY_ROUTE,
	IB_USER_AT_CMD_IPS_BY_GID,
	IB_USER_AT_CMD_IPS_BY_SUBNET,
	IB_USER_AT_CMD_INVALIDATE_PATHS,
	IB_USER_AT_CMD_CANCEL,
	IB_USER_AT_CMD_STATUS,

	IB_USER_AT_CMD_EVENT,
};

/*
 * command ABI structures.
 */
struct ib_uat_cmd_hdr {
	__u32 cmd;
	__u16 in;
	__u16 out;
};

enum ib_uat_multipathing_type {
        IB_USER_AT_PATH_SAME_PORT    = 0,
        IB_USER_AT_PATH_SAME_HCA     = 1,	/* but different ports if applicable */
        IB_USER_AT_PATH_SAME_SYSTEM  = 2,	/* but different ports if applicable */
        IB_USER_AT_PATH_INDEPENDENT_HCA = 3,
        IB_USER_AT_PATH_SRC_ROUTE    = 4,	/* application controlled multipathing */
};

enum ib_uat_route_flags {
        IB_USER_AT_ROUTE_USE_DEFAULTS	= 0,
        IB_USER_AT_ROUTE_FORCE_ATS	= 1,
        IB_USER_AT_ROUTE_FORCE_ARP	= 2,
        IB_USER_AT_ROUTE_FORCE_RESOLVE	= 4,
};

struct ib_uat_path_attr {
	__u16 qos_tag;
	__u16 pkey;
	__u8  multi_path_type;
};

struct ib_uat_ib_route {
	__u8 sgid[16];
	__u8 dgid[16];
	struct ibv_device *out_dev;
	int out_port;
	struct ib_uat_path_attr attr;
};

enum ib_uat_op_status {
        IB_USER_AT_STATUS_INVALID	= 0,
        IB_USER_AT_STATUS_PENDING	= 1,
        IB_USER_AT_STATUS_COMPLETED	= 2,
        IB_USER_AT_STATUS_CANCELED	= 3,
};

struct ib_uat_completion {
	void (*fn)(__u64 req_id, void *context, int rec_num);
	void *context;
	__u64 req_id;
};

struct ib_uat_paths_by_route_req {
	struct ib_uat_ib_route *ib_route;
	__u32 mpath_type;
	struct ib_sa_path_rec *path_arr;
	int npath;
	struct ib_uat_completion *async_comp;
	__u64 response;
};

struct ib_uat_paths_by_route_resp {
	__u64 req_id;
};

struct ib_uat_route_by_ip_req {
	__u32 dst_ip;
	__u32 src_ip;
	int   tos;
	__u16 flags;
	struct ib_uat_ib_route *ib_route;
	struct ib_uat_completion *async_comp;
	__u64 response;
};

struct ib_uat_route_by_ip_resp {
	__u64 req_id;
};

struct ib_uat_ips_by_gid_req {
	union ibv_gid *gid;
	__u32 *dst_ips;
	int    nips;
	struct ib_uat_completion *async_comp;
	__u64 response;
};

struct ib_uat_ips_by_gid_resp {
	__u64 req_id;
};

struct ib_uat_ips_by_subnet_req {
	__u32 network;
	__u32 netmask;
	__u32 *dst_ips;
	int nips;
};

struct ib_uat_invalidate_paths_req {
	struct ib_uat_ib_route *ib_route;
};

struct ib_uat_cancel_req {
	__u64 req_id;
};

struct ib_uat_status_req {
	__u64 req_id;
};

/*
 * event notification ABI structures.
 */
struct ib_uat_event_get {
	__u64 response;
};

struct ib_uat_event_resp {
	__u64 callback;
	__u64 context;
	__u64 req_id;
	int   rec_num;
};
#endif /* IB_USER_AT_H */

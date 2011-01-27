/*
 * iSCSI driver for Linux
 * Copyright (C) 2001 Cisco Systems, Inc.
 * Copyright (C) 2004 Mike Christie
 * Copyright (C) 2004 IBM Corporation
 * maintained by linux-iscsi-devel@lists.sourceforge.net
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 *
 * $Id: iscsi-portal.h,v 1.1.2.9 2005/04/26 17:44:50 mikenc Exp $
 *
 * portal info structure used in ioctls and the kernel module
 */
#ifndef ISCSI_PORTAL_H_
#define ISCSI_PORTAL_H_

#include <linux/socket.h>

struct iscsi_session;

/*
 * iscsi_portal_info - contains the values userspace had
 * requested. This differs from the session duplicates
 * as they are the values we negotiated with the target
 */
struct iscsi_portal_info {
	int	initial_r2t;
	int	immediate_data;
	int	max_recv_data_segment_len;
	int	first_burst_len;
	int	max_burst_len;
	int	def_time2wait;
	int	def_time2retain;
	int	header_digest;
	int	data_digest;
	int	tag;
	int	tcp_window_size;
	int	type_of_service;
	/* support ipv4 when we finish the interface */
	struct sockaddr addr;
};

extern void iscsi_set_portal_info(struct iscsi_session *session);
extern void iscsi_set_portal(struct iscsi_session *session);
extern int iscsi_update_portal_info(struct iscsi_portal_info *old,
				    struct iscsi_portal_info *new);
#endif

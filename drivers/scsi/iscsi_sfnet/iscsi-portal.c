/*
 * iSCSI driver for Linux
 * Copyright (C) 2001 Cisco Systems, Inc.
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
 * $Id: iscsi-portal.c,v 1.1.2.11 2005/04/26 17:44:50 mikenc Exp $
 *
 * Portal setup functions
 */
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/in.h>

#include "iscsi-session.h"
#include "iscsi-ioctl.h"
#include "iscsi-sfnet.h"

/* caller must hold the session's portal_lock */
void
iscsi_set_portal_info(struct iscsi_session *session)
{
	/*
	 * Set the iSCSI op params based on the portal's
	 * settings. Don't change the address, since a termporary redirect may
	 * have already changed the address, and we want to use the redirected
	 * address rather than the portal's address.
	 */
	session->initial_r2t = session->portal.initial_r2t;
	session->immediate_data = session->portal.immediate_data;
	session->max_recv_data_segment_len =
		session->portal.max_recv_data_segment_len;
	session->first_burst_len = session->portal.first_burst_len;
	session->max_burst_len = session->portal.max_burst_len;
	session->def_time2wait = session->portal.def_time2wait;
	session->def_time2retain = session->portal.def_time2retain;

	session->header_digest = session->portal.header_digest;
	session->data_digest = session->portal.data_digest;

	session->portal_group_tag = session->portal.tag;

	/* TCP options */
	session->tcp_window_size = session->portal.tcp_window_size;
	/* FIXME: type_of_service */
}

/* caller must hold the session's portal_lock */
void
iscsi_set_portal(struct iscsi_session *session)
{
	/* address */
	memcpy(&session->addr, &session->portal.addr, sizeof(struct sockaddr));
	/* timeouts, operational params, other settings */
	iscsi_set_portal_info(session);
}

/*
 * returns 1 if a relogin is required.
 * caller must hold the session's portal_lock
 */
int
iscsi_update_portal_info(struct iscsi_portal_info *old,
			 struct iscsi_portal_info *new)
{
	int ret = 0;

	if (new->initial_r2t != old->initial_r2t ||
	    new->immediate_data != old->immediate_data ||
	    new->max_recv_data_segment_len != old->max_recv_data_segment_len ||
	    new->first_burst_len != old->first_burst_len ||
	    new->max_burst_len != old->max_burst_len ||
	    new->def_time2wait != old->def_time2wait ||
	    new->def_time2retain != old->def_time2retain ||
	    new->header_digest != old->header_digest ||
	    new->data_digest != old->data_digest ||
	    new->tcp_window_size != old->tcp_window_size)
                ret = 1;

	memcpy(old, new, sizeof(*old));
	return ret;
}

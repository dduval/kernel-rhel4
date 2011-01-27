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
 * $Id: iscsi-ioctl.h,v 1.1.2.19 2005/04/26 17:44:50 mikenc Exp $
 *
 * include for ioctl calls between the daemon and the kernel module
 */
#ifndef ISCSI_IOCTL_H_
#define ISCSI_IOCTL_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#include "iscsi-protocol.h"
#include "iscsi-portal.h"
#include "iscsi-auth-client.h"

/*
 * still not sure if the ioctl is going to stay
 * so can fix up later
 */
struct iscsi_session_ioctl {
	__u32		ioctl_version;
	__u32		config_number;
	int		update;
	__u8		isid[6];
	/*
	 * passwords can contain NULL chars so we need
	 * the length.
	 */
	int		password_length;
	char		username[AUTH_STR_MAX_LEN];
	unsigned char	password[AUTH_STR_MAX_LEN];
	int		password_length_in;
	char		username_in[AUTH_STR_MAX_LEN];
	unsigned char	password_in[AUTH_STR_MAX_LEN];
	unsigned char	target_name[TARGET_NAME_MAXLEN + 1];
	unsigned char	initiator_name[TARGET_NAME_MAXLEN + 1];
	unsigned char	initiator_alias[TARGET_NAME_MAXLEN + 1];
	int		login_timeout;
	int		active_timeout;
	int		idle_timeout;
	int		ping_timeout;
	int		abort_timeout;
	int		reset_timeout;
	int		replacement_timeout;
	struct iscsi_portal_info portal;
};

#define ISCSI_SESSION_IOCTL_VERSION 25

/*
 * ioctls
 */
#define ISCSI_EST_SESS_CMD 0

#define ISCSI_IOCTL 0xbc
#define ISCSI_ESTABLISH_SESSION _IOW(ISCSI_IOCTL, ISCSI_EST_SESS_CMD, \
					struct iscsi_session_ioctl)
#endif

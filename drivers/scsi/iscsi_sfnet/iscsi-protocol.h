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
 * $Id: iscsi-protocol.h,v 1.1.2.8 2005/03/29 19:35:09 mikenc Exp $ 
 *
 * This file sets up definitions of messages and constants used by the
 * iSCSI protocol.
 */
#ifndef ISCSI_PROTOCOL_H_
#define ISCSI_PROTOCOL_H_

#include "iscsi.h"

/* assumes a pointer to a 3-byte array */
#define ntoh24(p) (((p)[0] << 16) | ((p)[1] << 8) | ((p)[2]))

/* assumes a pointer to a 3 byte array, and an integer value */
#define hton24(p, v) {\
        p[0] = (((v) >> 16) & 0xFF); \
        p[1] = (((v) >> 8) & 0xFF); \
        p[2] = ((v) & 0xFF); \
}

/* for Login min, max, active version fields */
#define ISCSI_MIN_VERSION	ISCSI_DRAFT20_VERSION
#define ISCSI_MAX_VERSION	ISCSI_DRAFT20_VERSION

/* Padding word length */
#define PAD_WORD_LEN		4

/* maximum length for text values */
#define TARGET_NAME_MAXLEN	255

/*
 * We should come up with a enum or some defines (in iscsi.h)
 * of all the iSCSI defaults so we can verify values against
 * what we receive (from the ioctl and targets)
 */
#define DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH	8192

#endif

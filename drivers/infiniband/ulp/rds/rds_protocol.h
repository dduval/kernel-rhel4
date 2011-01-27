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


#ifndef _RDS_PROTOCOL_H_
#define _RDS_PROTOCOL_H_

#define RDS_PROTO_VERSION 2

struct rds_data_hdr {
	u16 dst_port;
	u16 src_port;
	//rds_ip_addr_t src_ip;
	u32 psn; /* Packet sequence num */
	u32 pkts;
	u8 data[1];
}__attribute__ ((packed));

#define RDS_DATA_HDR_SIZE (sizeof(struct rds_data_hdr) - 1)

enum CTRL_CODE {
	PORT_STALL =1,
	PORT_UNSTALL,
	HEARTBEAT,
};

struct rds_ctrl_hdr {
	u16 ctrl_code;
	u16 port; /* For stall and unstall */
}__attribute__ ((packed));

#endif

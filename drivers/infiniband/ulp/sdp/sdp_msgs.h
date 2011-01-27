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
 * $Id: sdp_msgs.h 2663 2005-06-20 17:17:58Z libor $
 */

#ifndef _SDP_MSGS_H
#define _SDP_MSGS_H

#include <asm/byteorder.h>
/*
 * Message Identifier Opcodes for BSDH
 */
/*        Name                        Value    Extended Header   Payload   */
#define SDP_MID_HELLO           0x00 /* msg_hdr_hh      <none>   */
#define SDP_MID_HELLO_ACK       0x01 /* msg_hdr_hah     <none>   */
#define SDP_MID_DISCONNECT      0x02 /* <none>          <none>   */
#define SDP_MID_ABORT_CONN      0x03 /* <none>          <none>   */
#define SDP_MID_SEND_SM         0x04 /* <none>          <none>   */
#define SDP_MID_RDMA_WR_COMP    0x05 /* msg_hdr_rwch    <none>   */
#define SDP_MID_RDMA_RD_COMP    0x06 /* msg_hdr_rrch    <none>   */
#define SDP_MID_MODE_CHANGE     0x07 /* msg_hdr_mch     <none>   */
#define SDP_MID_SRC_CANCEL      0x08 /* <none>          <none>   */
#define SDP_MID_SNK_CANCEL      0x09 /* <none>          <none>   */
#define SDP_MID_SNK_CANCEL_ACK  0x0A /* <none>          <none>   */
#define SDP_MID_CH_RECV_BUF     0x0B /* msg_hdr_crbh    <none>   */
#define SDP_MID_CH_RECV_BUF_ACK 0x0C /* msg_hdr_crbah   <none>   */
#define SDP_MID_SUSPEND         0x0D /* msg_hdr_sch     <none>   */
#define SDP_MID_SUSPEND_ACK     0x0E /* <none>          <none>   */
#define SDP_MID_SNK_AVAIL       0xFD /* msg_hdr_snkah   <optional> */
#define SDP_MID_SRC_AVAIL       0xFE /* msg_hdr_srcah   <optional> */
#define SDP_MID_DATA            0xFF /* <none>          <optional> */
/*
 * shift number for BSDH Flags.
 */
#define SDP_MSG_FLAG_NON_FLAG (0x0)	/* no flag present */
#define SDP_MSG_FLAG_OOB_PRES  0	/* out-of-band data present */
#define SDP_MSG_FLAG_OOB_PEND  1	/* out-of-band data pending */
#define SDP_MSG_FLAG_REQ_PIPE  2	/* request change to pipelined  */
/*
 * message type masks
 */
#define SDP_MID_CTRL(mid) ((0xF0 & mid) ? 0 : 1)
/*
 * Base Sockets Direct Header (header for all SDP messages)
 */
struct msg_hdr_bsdh {
	__u8  mid;       /* message identifier opcode (SDP_MID_*) */
	__u8  flags;     /* flags as defined by SDP_MSG_FLAG_* */
	__u16 recv_bufs; /* current number of posted private recv buffers */
	__u32 size;      /* length of msg, including header(s) and data */
	__u32 seq_num;   /* message sequence number */
	__u32 seq_ack;   /* last received message sequence number */
} __attribute__ ((packed)); /* struct msg_hdr_bsdh */
/*
 * Hello Header constants (two 8-bit constants, no conversion needed)
 */
#ifdef _SDP_MS_APRIL_ERROR_COMPAT
#define SDP_MSG_IPVER   0x04	/* (1: ipversion), (0: reserved) */
#else
#define SDP_MSG_IPVER   0x40	/* (1: ipversion), (0: reserved) */
#endif
#define SDP_MSG_VERSION 0x11	/* (1: major ), (0: minor ) */
/*
 * Hello Header (BSDH + HH are contained in private data of the CM REQ MAD
 */
struct msg_hdr_hh {
	__u8  version;     /* 0-3: minor version (current spec; 0x1)
			      4-7: major version (current spec; 0x1) */
	__u8  ip_ver;      /* 0-3: reserved
			      4-7: ip version (0x4 = ipv4, 0x6 = ipv6) */
	__u8  rsvd_1;      /* reserved */
	__u8  max_adv;     /* max outstanding Zcopy advertisments (>0) */
	__u32 r_rcv_size;  /* requested size of each remote recv buffer */
	__u32 l_rcv_size;  /* initial size of each local receive buffer */
	__u16 port;        /* local port */
	__u16 rsvd_2;      /* reserved */

	union {		   /* source IP address. */
		struct {
			__u32 addr3;	/* ipv6 96-127 */
			__u32 addr2;	/* ipv6 64-95  */
			__u32 addr1;	/* ipv6 32-63  */
			__u32 addr0;	/* ipv6  0-31  */
		} ipv6;	   /* 128bit IPv6 address */
		struct {
			__u32 none2;	/* unused 96-127 */
			__u32 none1;	/* unused 64-95  */
			__u32 none0;	/* unused 32-63  */
			__u32 addr;	/* ipv4    0-31  */
		} ipv4;	   /* 32bit IPv4 address */
	} src;

	union {		   /* destination IP address. */
		struct {
			__u32 addr3;	/* ipv6 96-127 */
			__u32 addr2;	/* ipv6 64-95  */
			__u32 addr1;	/* ipv6 32-63  */
			__u32 addr0;	/* ipv6  0-31  */
		} ipv6;	   /* 128bit IPv6 address */
		struct {
			__u32 none2;	/* unused 96-127 */
			__u32 none1;	/* unused 64-95  */
			__u32 none0;	/* unused 32-63  */
			__u32 addr;	/* ipv4    0-31  */
		} ipv4;	   /* 32bit IPv4 address */
	} dst;

	__u8 rsvd_3[28];   /* reserved for future use, and zero'd */
} __attribute__ ((packed)); /* struct msg_hdr_hh */
/*
 * Hello Acknowledgement Header (BSDH + HAH are contained in private data
 *                               of the CM REP MAD)
 */
struct msg_hdr_hah {
	__u8  version;     /* 0-3: minor version (current spec; 0x1)
			      4-7: major version (current spec; 0x1) */
	__u16 rsvd_1;      /* reserved */
	__u8  max_adv;     /* max outstanding Zcopy advertisments (>0) */
	__u32 l_rcv_size;  /* initial size of each local receive buffer */
#if 0 /* There is a bug in the 1.1 spec. REP message grew by 8 bytes. */
	__u8  rsvd_2[180]; /* reserved for future use, and zero'd (big) */
#else
	__u8  rsvd_2[172]; /* reserved for future use, and zero'd (big) */
#endif
} __attribute__ ((packed)); /* struct msg_hdr_hah */
/*
 * Source Available Header. Source notifies Sink that there are buffers
 * which can be moved, using RDMA Read, by the Sink. The message is flowing
 * in the same direction as the data it is advertising.
 */
struct msg_hdr_srcah {
	__u32 size;    /* size, in bytes, of buffer to be RDMA'd */
	__u32 r_key;   /* R_Key needed for sink to perform RMDA Read */
	__u64 addr;    /* virtual address of buffer */
#ifdef _SDP_MS_APRIL_ERROR_COMPAT
	__u64 none;    /* garbage in their header. */
#endif
} __attribute__ ((packed)); /* struct msg_hdr_srcah */
/*
 * Sink Available Header. Sink notifies Source that there are buffers
 * into which the source, using RMDA write, can move data. The message
 * is flowing in the opposite direction as the data will be moving into
 * the buffer.
 */
struct msg_hdr_snkah {
	__u32 size;      /* size, in bytes, of buffer to be RDMA'd */
	__u32 r_key;     /* R_Key needed for sink to perform RMDA Read */
	__u64 addr;      /* virtual address of buffer */
	__u32 non_disc;  /* SDP messages, containing data, not discarded */
} __attribute__ ((packed)); /* struct msg_hdr_snkah */
/*
 * RDMA Write Completion Header. Notifying the data sink, which sent a
 * SinkAvailable message, that the RDMA write, for the oldest outdtanding
 * SNKAH message has completed.
 */
struct msg_hdr_rwch {
	__u32 size;      /* size of data RDMA'd */
} __attribute__ ((packed)); /* struct msg_hdr_rwch */
/*
 * RDMA Read Completion Header. Notifiying the data source, which sent a
 * SourceAvailable message, that the RDMA Read. Sink must RDMA the
 * entire contents of the advertised buffer, minus the data sent as
 * immediate data in the SRCAH.
 */
struct msg_hdr_rrch {
	__u32 size;      /* size of data actually RDMA'd */
} __attribute__ ((packed)); /* struct msg_hdr_rrch */
/*
 * Mode Change Header constants. (low 4 bits are reserved, next 3 bits
 * are cast to integer and determine mode, highest bit determines send
 * or recv half of the receiving peers connection.)
 */
#define SDP_MSG_MCH_BUFF_RECV 0x0
#define SDP_MSG_MCH_COMB_RECV 0x1
#define SDP_MSG_MCH_PIPE_RECV 0x2
#define SDP_MSG_MCH_BUFF_SEND 0x8
#define SDP_MSG_MCH_COMB_SEND 0x9
#define SDP_MSG_MCH_PIPE_SEND 0xA
/*
 * Mode Change Header. Notification of a flowcontrol mode transition.
 * The receiver is required to change mode upon notification.
 */
struct msg_hdr_mch {
	__u8 flags;        /* 0-3: reserved
			      4-6: flow control modes
			      7: send/recv flow control */
	__u8 reserved[3];  /* reserved for future use */
} __attribute__ ((packed)); /* struct msg_hdr_mch */
/*
 * Change Receive Buffer size Header. Request for the peer to change the
 * size of it's private receive buffers.
 */
struct msg_hdr_crbh {
	__u32 size;      /* desired receive buffer size */
} __attribute__ ((packed)); /* struct msg_hdr_crbh */
/*
 * Change Receive Buffer size Acknowkedgement Header. Response to the
 * peers request for a receive buffer size change, containing the
 * actual size size of the receive buffer.
 */
struct msg_hdr_crbah {
	__u32 size;      /* actuall receive buffer size */
} __attribute__ ((packed)); /* struct msg_hdr_crbah */
/*
 * Suspend Communications Header. Request for the peer to suspend
 * communication in preperation for a socket duplication. The message
 * contains the new serviceID of the connection.
 */
struct msg_hdr_sch {
	__u64 service_id;  /* new service ID */
} __attribute__ ((packed)); /* struct msg_hdr_sch */
/*
 * Header flags accessor functions
 */
#define SDP_BSDH_GET_FLAG(bsdh, flag) \
        (((bsdh)->flags & (0x1U << (flag))) >> (flag))
#define SDP_BSDH_SET_FLAG(bsdh, flag) \
        ((bsdh)->flags |= (0x1U << (flag)))
#define SDP_BSDH_CLR_FLAG(bsdh, flag) \
        ((bsdh)->flags &= ~(0x1U << (flag)))

#define SDP_BSDH_GET_OOB_PRES(bsdh) \
        SDP_BSDH_GET_FLAG(bsdh, SDP_MSG_FLAG_OOB_PRES)
#define SDP_BSDH_SET_OOB_PRES(bsdh) \
        SDP_BSDH_SET_FLAG(bsdh, SDP_MSG_FLAG_OOB_PRES)
#define SDP_BSDH_CLR_OOB_PRES(bsdh) \
        SDP_BSDH_CLR_FLAG(bsdh, SDP_MSG_FLAG_OOB_PRES)
#define SDP_BSDH_GET_OOB_PEND(bsdh) \
        SDP_BSDH_GET_FLAG(bsdh, SDP_MSG_FLAG_OOB_PEND)
#define SDP_BSDH_SET_OOB_PEND(bsdh) \
        SDP_BSDH_SET_FLAG(bsdh, SDP_MSG_FLAG_OOB_PEND)
#define SDP_BSDH_CLR_OOB_PEND(bsdh) \
        SDP_BSDH_CLR_FLAG(bsdh, SDP_MSG_FLAG_OOB_PEND)
#define SDP_BSDH_GET_REQ_PIPE(bsdh) \
        SDP_BSDH_GET_FLAG(bsdh, SDP_MSG_FLAG_REQ_PIPE)
#define SDP_BSDH_SET_REQ_PIPE(bsdh) \
        SDP_BSDH_SET_FLAG(bsdh, SDP_MSG_FLAG_REQ_PIPE)
#define SDP_BSDH_CLR_REQ_PIPE(bsdh) \
        SDP_BSDH_CLR_FLAG(bsdh, SDP_MSG_FLAG_REQ_PIPE)

#define SDP_MSG_MCH_GET_MODE(mch) (((mch)->flags & 0xF0) >> 4)
#define SDP_MSG_MCH_SET_MODE(mch, value) \
        ((mch)->flags = (((mch)->flags & 0x0F) | (value << 4)))

/*
 * Endian Conversions
 */

/*
 * sdp_msg_swap_bsdh - SDP header endian byte swapping
 */
static inline void sdp_msg_swap_bsdh(struct msg_hdr_bsdh *header)
{
	header->recv_bufs = cpu_to_be16(header->recv_bufs);
	header->size = cpu_to_be32(header->size);
	header->seq_num = cpu_to_be32(header->seq_num);
	header->seq_ack = cpu_to_be32(header->seq_ack);
}

/*
 * sdp_msg_swap_hh - SDP header endian byte swapping
 */
static inline void sdp_msg_swap_hh(struct msg_hdr_hh *header)
{
	header->r_rcv_size = cpu_to_be32(header->r_rcv_size);
	header->l_rcv_size = cpu_to_be32(header->l_rcv_size);
	header->port = cpu_to_be16(header->port);
	header->src.ipv6.addr0 = cpu_to_be32(header->src.ipv6.addr0);
	header->src.ipv6.addr1 = cpu_to_be32(header->src.ipv6.addr1);
	header->src.ipv6.addr2 = cpu_to_be32(header->src.ipv6.addr2);
	header->src.ipv6.addr3 = cpu_to_be32(header->src.ipv6.addr3);
	header->dst.ipv6.addr0 = cpu_to_be32(header->dst.ipv6.addr0);
	header->dst.ipv6.addr1 = cpu_to_be32(header->dst.ipv6.addr1);
	header->dst.ipv6.addr2 = cpu_to_be32(header->dst.ipv6.addr2);
	header->dst.ipv6.addr3 = cpu_to_be32(header->dst.ipv6.addr3);
}

/*
 * sdp_msg_swap_hah - SDP header endian byte swapping
 */
static inline void sdp_msg_swap_hah(struct msg_hdr_hah *header)
{
	header->l_rcv_size = cpu_to_be32(header->l_rcv_size);
}

/*
 * sdp_msg_swap_srcah - SDP header endian byte swapping
 */
static inline void sdp_msg_swap_srcah(struct msg_hdr_srcah *header)
{
	header->size = cpu_to_be32(header->size);
#ifdef _SDP_MS_APRIL_ERROR_COMPAT
	header->r_key = cpu_to_le32(header->r_key);
	header->addr = cpu_to_le64(header->addr);
#else
	header->r_key = cpu_to_be32(header->r_key);
	header->addr = cpu_to_be64(header->addr);
#endif
}

/*
 * sdp_msg_swap_snkah - SDP header endian byte swapping
 */
static inline void sdp_msg_swap_snkah(struct msg_hdr_snkah *header)
{
	header->size = cpu_to_be32(header->size);
	header->r_key = cpu_to_be32(header->r_key);
	header->addr = cpu_to_be64(header->addr);
	header->non_disc = cpu_to_be32(header->non_disc);
}

/*
 * sdp_msg_swap_rwch - SDP header endian byte swapping
 */
static inline void sdp_msg_swap_rwch(struct msg_hdr_rwch *header)
{
	header->size = cpu_to_be32(header->size);
}

/*
 * sdp_msg_swap_rrch - SDP header endian byte swapping
 */
static inline void sdp_msg_swap_rrch(struct msg_hdr_rrch *header)
{
	header->size = cpu_to_be32(header->size);
}

/*
 * sdp_msg_swap_mch - SDP header endian byte swapping
 */
static inline void sdp_msg_swap_mch(struct msg_hdr_mch *header)
{
}

/*
 * sdp_msg_swap_crbh - SDP header endian byte swapping
 */
static inline void sdp_msg_swap_crbh(struct msg_hdr_crbh *header)
{
	header->size = cpu_to_be32(header->size);
}

/*
 * sdp_msg_swap_crbah - SDP header endian byte swapping
 */
static inline void sdp_msg_swap_crbah(struct msg_hdr_crbah *header)
{
	header->size = cpu_to_be32(header->size);
}

/*
 * sdp_msg_swap_sch - SDP header endian byte swapping
 */
static inline void sdp_msg_swap_sch(struct msg_hdr_sch *header)
{
	header->service_id = cpu_to_be64(header->service_id);
}

#define sdp_msg_cpu_to_net_bsdh  sdp_msg_swap_bsdh
#define sdp_msg_net_to_cpu_bsdh  sdp_msg_swap_bsdh
#define sdp_msg_cpu_to_net_hh    sdp_msg_swap_hh
#define sdp_msg_net_to_cpu_hh    sdp_msg_swap_hh
#define sdp_msg_cpu_to_net_hah   sdp_msg_swap_hah
#define sdp_msg_net_to_cpu_hah   sdp_msg_swap_hah
#define sdp_msg_cpu_to_net_srcah sdp_msg_swap_srcah
#define sdp_msg_net_to_cpu_srcah sdp_msg_swap_srcah
#define sdp_msg_cpu_to_net_snkah sdp_msg_swap_snkah
#define sdp_msg_net_to_cpu_snkah sdp_msg_swap_snkah
#define sdp_msg_cpu_to_net_rwch  sdp_msg_swap_rwch
#define sdp_msg_net_to_cpu_rwch  sdp_msg_swap_rwch
#define sdp_msg_cpu_to_net_rrch  sdp_msg_swap_rrch
#define sdp_msg_net_to_cpu_rrch  sdp_msg_swap_rrch
#define sdp_msg_cpu_to_net_mch   sdp_msg_swap_mch
#define sdp_msg_net_to_cpu_mch   sdp_msg_swap_mch
#define sdp_msg_cpu_to_net_crbh  sdp_msg_swap_crbh
#define sdp_msg_net_to_cpu_crbh  sdp_msg_swap_crbh
#define sdp_msg_cpu_to_net_crbah sdp_msg_swap_crbah
#define sdp_msg_net_to_cpu_crbah sdp_msg_swap_crbah
#define sdp_msg_cpu_to_net_sch   sdp_msg_swap_sch
#define sdp_msg_net_to_cpu_sch   sdp_msg_swap_sch

/*
 * Miscellaneous message related informtation
 */

/*
 * Connection messages
 */
struct sdp_msg_hello {
	struct msg_hdr_bsdh bsdh;  /* base sockets direct header */
	struct msg_hdr_hh   hh;    /* hello message header */
} __attribute__ ((packed)); /* struct sdp_msg_hello */

struct sdp_msg_hello_ack {
	struct msg_hdr_bsdh bsdh;  /* base sockets direct header */
	struct msg_hdr_hah  hah;   /* hello ack message header */
} __attribute__ ((packed)); /* struct sdp_msg_hello_ack */

#endif /* _SDP_MSGS_H */

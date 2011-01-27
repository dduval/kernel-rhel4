/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
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
 *
 * $Id: at_priv.h 3354 2005-09-09 23:17:45Z halr $
 */

#ifndef __IB_AT_PRIV_H__
#define __IB_AT_PRIV_H__

#define IB_AT_REQ_TIMEOUT	(HZ*10)
#define IB_AT_SWEEP_INTERVAL	(HZ*5)
#define IB_AT_REQ_RETRY_MS	100
#define IB_AT_REQ_RETRIES	3
#define IB_AT_ATS_REG_INTERVAL	(HZ*60)

struct ib_sa_ats_rec {
	u8	data8[12];
	u32	node_addr;
	u16	magic_key;
	u16	node_type;
	u16	data16[6];
	u8	node_name[32];
};

#define ATS_REC_FIELD(field) \
	.struct_offset_bytes = offsetof(struct ib_sa_ats_rec, field),   \
	.struct_size_bytes   = sizeof ((struct ib_sa_ats_rec *) 0)->field,      \
	.field_name          = "sa_ats_rec:" #field

static const struct ib_field ats_rec_table[] = {
	{ ATS_REC_FIELD(data8),
	  .offset_words = 0,
	  .offset_bits  = 0,
	  .size_bits    = 12*8 },
	{ ATS_REC_FIELD(node_addr),
	  .offset_words = 3,
	  .offset_bits  = 0,
	  .size_bits    = 32 },
	{ ATS_REC_FIELD(magic_key),
	  .offset_words = 4,
	  .offset_bits  = 0,
	  .size_bits    = 16 },
	{ ATS_REC_FIELD(node_type),
	  .offset_words = 4,
	  .offset_bits  = 16,
	  .size_bits    = 16 },
	{ ATS_REC_FIELD(node_name),
	  .offset_words = 8,
	  .offset_bits  = 0,
	  .size_bits    = 32*8 },
};

#define IB_ATS_MASK     ((__force ib_sa_comp_mask) cpu_to_be64((1ull<<37)-1) & ~(IB_SA_COMP_MASK( 3) | IB_SA_SERVICE_REC_SERVICE_KEY))

#define IB_ATS_GET_GID_MASK     (IB_SA_SERVICE_REC_SERVICE_ID |   \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_0 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_1 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_2 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_3 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_4 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_5 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_6 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_7 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_8 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_9 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_10 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_11 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_12 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_13 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_14 | \
				 IB_SA_SERVICE_REC_SERVICE_DATA8_15)

#define IB_ATS_GET_PRIM_IP_MASK (IB_SA_SERVICE_REC_SERVICE_ID |   \
				 IB_SA_SERVICE_REC_SERVICE_GID)

/* Extended ATS queries: get multi address. Query is done by
 * Service Name. Returned SID must be in range
 *      IB_ATS_SERVICE_ID and IB_ATS_LAST_SERVICE_ID (inc.)
 */
#define IB_ATS_GET_MULTI_GIDS_MASK      (IB_SA_SERVICE_REC_SERVICE_NAME |   \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_0 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_1 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_2 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_3 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_4 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_5 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_6 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_7 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_8 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_9 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_10 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_11 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_12 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_13 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_14 | \
					 IB_SA_SERVICE_REC_SERVICE_DATA8_15)

#define IB_ATS_GET_ALL_IP_MASK  (IB_SA_SERVICE_REC_SERVICE_NAME |   \
				 IB_SA_SERVICE_REC_SERVICE_GID)

#define IB_ATS_SERVICE_NAME             "DAPL Address Translation Service"
#define IB_ATS_SERVICE_ID               cpu_to_be64(0x10000ce100415453ULL)
#define IB_ATS_LAST_SERVICE_ID          cpu_to_be64(0x10000ce1ff415453ULL)
#define IB_ATS_OPENIB_MAGIC_KEY         cpu_to_be16(IB_OPENIB_OUI & 0xffff)

#if 1
#define WARN(fmt, arg...)	printk("ib_at: %s: " fmt "\n", __FUNCTION__ , ## arg);
#define WARN_VAR(x, y...)	x, ## y
#else
#define WARN(fmt, ...)	while (0) {}
#define WARN_VAR(x, y...)
#endif

#if 0
#define DEBUG(fmt, arg...)	printk("ib_at: %s: " fmt "\n", __FUNCTION__ , ## arg);
#define DEBUG_VAR(x, y...)	x, ## y
#else
#define DEBUG(fmt, ...)	while (0) {}
#define DEBUG_VAR(x, y...)
#endif

static kmem_cache_t *route_req_cache = NULL;
static kmem_cache_t *path_req_cache = NULL;
static kmem_cache_t *ats_ips_req_cache = NULL;

static struct workqueue_struct *ib_at_wq;
static struct work_struct       ib_at_timer;
static struct work_struct       ib_at_ats;

struct ib_arp {
	/*
	 * generic arp header
	 */
	u16 addr_type;    /* format of hardware address   */
	u16 proto_type;   /* format of protocol address   */
	u8  addr_len;     /* length of hardware address   */
	u8  proto_len;    /* length of protocol address   */
	u16 op;           /* ARP opcode (command)         */
	/*
	 * begin IB specific section
	 */
	u32          src_qpn; /* MSB = reserved, low 3 bytes=QPN */
	union ib_gid src_gid;
	u32          src_ip;

	u32          dst_qpn; /* MSB = reserved, low 3 bytes=QPN */
	union ib_gid dst_gid;
	u32          dst_ip;

} __attribute__ ((packed));

enum async_types {
	IBAT_REQ_NONE = 0,
	IBAT_REQ_ARP,
	IBAT_REQ_ATS,
	IBAT_REQ_PATHREC,
	IBAT_REQ_ATSARP,
};

struct async {
	u64 id;
	int status;
	int type;
	void *data;
	int nelem;
	spinlock_t lock;
	struct work_struct work;

	struct ib_at_completion comp;
	struct async *parent;	/* if waiting */
	struct async *waiting;	/* waiting list */
	struct async *next;	/* pending list */
	struct async *prev;	/* pending list */

	unsigned long start;
	unsigned long timeout_ms;

	struct ib_sa_query *sa_query;
	int sa_id;
};

static struct async pending_reqs;	/* dummy head for cyclic list */

struct ib_at_src {
	u32 ip;
	u32 gw;
	struct ib_device *dev;
	struct net_device *netdev;
	int port;
	__be16 pkey;
	union ib_gid gid;
};

struct route_req {
	u32 dst_ip;
	u32 src_ip;
	int tos;
	u16 flags;

	struct ib_at_src src;
	union ib_gid dgid;

	struct async pend;
};

struct path_req {
	struct ib_at_ib_route rt;

	struct async pend;
};

struct ats_ips_req {
	struct ib_at_src src;
	union ib_gid gid;

	struct async pend;
};

struct arp_work {
	struct work_struct work;
	struct sk_buff *skb;
};

struct ib_at_dev {
	struct net_device *netdev;
	u32 ip;
	u32 old_ip;		/* ip to be deleted */
	char registered;
	char valid;
	char pend_op;
	char retries;

	struct ib_sa_query *sa_query;
	int sa_id;

	u64 pend_mask;
};

#define IB_AT_MAX_DEV		20

#endif	/* __IB_AT_PRIV_H__ */

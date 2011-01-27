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
 * $Id: sdp_link.c 3904 2005-10-30 12:24:44Z mst $
 */

#include "ipoib.h"
#include "sdp_main.h"

#define SDP_LINK_F_VALID 0x01 /* valid path info record. */
#define SDP_LINK_F_ARP   0x02 /* arp request in progress. */
#define SDP_LINK_F_PATH  0x04 /* arp request in progress. */
/*
 * wait for an ARP event to complete.
 */
struct sdp_path_info {
	u32 src;                    /* source IP address. */
	u32 dst;                    /* destination IP address */
	int dif;                    /* bound device interface option */
	u32 gw;                     /* gateway IP address */
	int qid;                    /* path record query ID */
	u8  port;                   /* HCA port */
	u32 flags;                  /* record flags */
	int sa_time;                /* path_rec request timeout */
	unsigned long arp_time;     /* ARP request timeout */
	unsigned long use;          /* last time accessed. */
	struct ib_device  *ca;      /* HCA device. */
	struct ib_sa_path_rec path; /* path record info */
        struct ib_sa_query *query;

	struct work_struct timer;   /* arp request timers. */

	struct list_head info_list;

	struct list_head wait_list;
};

struct sdp_path_wait {
	u64 id;  /* request identifier */
	void (*completion)(u64 id,
			   int status,
			   u32 dst_addr,
			   u32 src_addr,
			   u8  hw_port,
			   struct ib_device *ca,
			   struct ib_sa_path_rec *path,
			   void *arg);
	void *arg;
	int retry;
	struct list_head list;
};

struct sdp_work {
	struct work_struct work;
	void *arg;
};

struct sdp_link_arp {
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

} __attribute__ ((packed)); /* sdp_link_arp */

#define SDP_LINK_SWEEP_INTERVAL (10 * (HZ)) /* frequency of sweep function */
#define SDP_LINK_INFO_TIMEOUT   (300UL * (HZ)) /* unused time */
#define SDP_LINK_SA_RETRY       (3)          /* number of SA retry requests */
#define SDP_LINK_ARP_RETRY      (3)          /* number of ARP retry requests */

#define SDP_LINK_SA_TIME_MIN    (500)   /* milliseconds. */
#define SDP_LINK_SA_TIME_MAX    (10000) /* milliseconds. */
#define SDP_LINK_ARP_TIME_MIN   (HZ)
#define SDP_LINK_ARP_TIME_MAX   (32UL * (HZ))

#if 0
#define SDP_IPOIB_RETRY_VALUE    3        /* number of retries. */
#define SDP_IPOIB_RETRY_INTERVAL (HZ * 1) /* retry frequency */

#define SDP_DEV_PATH_WAIT       (5 * (HZ))
#define SDP_PATH_TIMER_INTERVAL (15 * (HZ))  /* cache sweep frequency */
#define SDP_PATH_REAPING_AGE    (300 * (HZ)) /* idle time before reaping */
#endif

static kmem_cache_t *wait_cache;
static kmem_cache_t *info_cache;

static DECLARE_MUTEX(sdp_link_mutex);
static LIST_HEAD(info_list);

static struct workqueue_struct *link_wq;
static struct work_struct       link_timer;

static u64 path_lookup_id;

#define _SDP_PATH_LOOKUP_ID() \
      ((++path_lookup_id) ? path_lookup_id : ++path_lookup_id)

#define GID_FMT           "%x:%x:%x:%x:%x:%x:%x:%x"
#define GID_ARG(gid)      be16_to_cpup((__be16 *) ((gid).raw +  0)), \
                          be16_to_cpup((__be16 *) ((gid).raw +  2)), \
                          be16_to_cpup((__be16 *) ((gid).raw +  4)), \
                          be16_to_cpup((__be16 *) ((gid).raw +  6)), \
                          be16_to_cpup((__be16 *) ((gid).raw +  8)), \
                          be16_to_cpup((__be16 *) ((gid).raw + 10)), \
                          be16_to_cpup((__be16 *) ((gid).raw + 12)), \
                          be16_to_cpup((__be16 *) ((gid).raw + 14))
/*
 * proto
 */
static void retry_link_path_lookup(void *);

/*
 * sdp_link_path_complete - generate a path record completion for user
 */
static void sdp_link_path_complete(u64 id, int status,
				   struct sdp_path_info *info,
				   void (*func)(u64 id,
						int status,
						u32 dst_addr,
						u32 src_addr,
						u8  hw_port,
						struct ib_device *ca,
						struct ib_sa_path_rec *path,
						void *arg),
				   void *arg)
{
	/*
	 * call completion function
	 */
	func(id,
	     status,
	     info->dst,
	     info->src,
	     info->port,
	     info->ca,
	     &info->path,
	     arg);

	info->use = jiffies;
}

/*
 * sdp_path_wait_complete - complete an entry for a wait element
 */
static void sdp_path_wait_complete(struct sdp_path_wait *wait,
				   struct sdp_path_info *info, int status)
{
	sdp_link_path_complete(wait->id,
				status,
				info,
				wait->completion,
				wait->arg);

	list_del(&wait->list);
	kmem_cache_free(wait_cache, wait);
}

/*
 * sdp_path_info_create - create an entry for a path record element
 */
static struct sdp_path_info *sdp_path_info_create(u32 dst_ip, int dev_if)
{
	struct sdp_path_info *info;

	info = kmem_cache_alloc(info_cache, SLAB_KERNEL);
	if (!info)
		return NULL;

	memset(info, 0, sizeof(struct sdp_path_info));

	info->dst = dst_ip;
	info->dif = dev_if;
	info->use = jiffies;

	info->sa_time  = SDP_LINK_SA_TIME_MIN;
	info->arp_time = SDP_LINK_ARP_TIME_MIN;

	INIT_LIST_HEAD(&info->wait_list);
	INIT_WORK(&info->timer, retry_link_path_lookup, info);
	list_add(&info->info_list, &info_list);

	return info;
}

/*
 * sdp_path_info_destroy - destroy an entry for a path record element
 */
static void sdp_path_info_destroy(struct sdp_path_info *info, int status)
{
	struct sdp_path_wait *wait, *tmp;
	/* TODO: replace by list_del once we have proper locking */
	list_del_init(&info->info_list);

	list_for_each_entry_safe(wait, tmp, &info->wait_list, list)
		sdp_path_wait_complete(wait, info, status);

	cancel_delayed_work(&info->timer);
	kmem_cache_free(info_cache, info);
}

/*
 * sdp_link_path_rec_done - path record completion function
 */
static void sdp_link_path_rec_done(int status, struct ib_sa_path_rec *resp,
				   void *context)
{
	struct sdp_path_info *info = context;
	struct sdp_path_wait *wait;
	struct sdp_path_wait *sweep;
	int result;

	down(&sdp_link_mutex);

	info->query = NULL;

	sdp_dbg_data(NULL, "Path Record status <%d>", status);

	if (!status) {
		/*
		 * on success save path record, stop waiting for info,
		 * and complete all waiting IOs
		 */
		info->flags &= ~SDP_LINK_F_PATH;
		info->flags |=  SDP_LINK_F_VALID;
		info->path   = *resp;
	}

	list_for_each_entry_safe(wait, sweep, &info->wait_list, list) {
		/*
		 * on timeout increment retries.
		 */
		if (status == -ETIMEDOUT)
			wait->retry++;

		if (!status || wait->retry > SDP_LINK_SA_RETRY)
			sdp_path_wait_complete(wait, info, status);
	}
	/*
	 * retry if anyone is waiting.
	 */
	if (!list_empty(&info->wait_list)) {
		info->sa_time = min(info->sa_time * 2, SDP_LINK_SA_TIME_MAX);

		result = ib_sa_path_rec_get(info->ca,
					    info->port,
					    &info->path,
					    (IB_SA_PATH_REC_DGID |
					     IB_SA_PATH_REC_SGID |
					     IB_SA_PATH_REC_PKEY |
					     IB_SA_PATH_REC_NUMB_PATH),
					    info->sa_time,
					    GFP_KERNEL,
					    sdp_link_path_rec_done,
					    info,
					    &info->query);

	        if (result < 0) {
			sdp_dbg_warn(NULL, "Error <%d> restarting path query",
				     result);
			sdp_path_info_destroy(info, result);
		}
	}
	up(&sdp_link_mutex);
}

/*
 * sdp_link_path_rec_get - resolve GIDs to a path record
 */
static int sdp_link_path_rec_get(struct sdp_path_info *info)
{
	int result;

	sdp_dbg_data(NULL, "Path Record request: src " GID_FMT " dst " GID_FMT,
		     GID_ARG(info->path.sgid),
		     GID_ARG(info->path.dgid));

	if (info->flags & SDP_LINK_F_PATH)
		return 0;

	result = ib_sa_path_rec_get(info->ca,
				    info->port,
				    &info->path,
				    (IB_SA_PATH_REC_DGID |
				     IB_SA_PATH_REC_SGID |
				     IB_SA_PATH_REC_PKEY |
				     IB_SA_PATH_REC_NUMB_PATH),
				    info->sa_time,
				    GFP_KERNEL,
				    sdp_link_path_rec_done,
				    info,
				    &info->query);
        if (result < 0) {
		sdp_dbg_warn(NULL, "Error <%d> starting path record query",
			     result);
                info->query = NULL;
		return result;
	}

	info->qid    = result;
	info->flags |= SDP_LINK_F_PATH;

	return 0;
}

/*
 * do_link_path_lookup - resolve an ip address to a path record
 */
static void do_link_path_lookup(struct sdp_path_info *info)
{
	struct ipoib_dev_priv *priv;
	struct net_device *dev = NULL;
	struct rtable *rt;
	int result = 0;
	struct flowi fl = {
		.oif = info->dif, /* oif */
		.nl_u = {
			.ip4_u = {
				.daddr = info->dst, /* dst */
				.saddr = info->src, /* src */
				.tos   = 0, /* tos */
			}
		},
		.proto = 0, /* protocol */
		.uli_u = {
			.ports = {
				.sport = 0, /* sport */
				.dport = 0, /* dport */
			}
		}
	};

	/*
	 * path request in progress?
	 */
	if (info->flags & SDP_LINK_F_PATH)
		goto done;

	result = ip_route_output_key(&rt, &fl);
	if (result < 0 || !rt) {
		rt = NULL;
		sdp_dbg_warn(NULL, "Error <%d> routing <%08x:%08x> (%d)",
			     result, info->dst, info->src, info->dif);
		goto error;
	}
	/*
	 * check route flags
	 */
	if ((RTCF_MULTICAST|RTCF_BROADCAST) & rt->rt_flags) {
		result = -ENETUNREACH;
		goto error;
	}

	if (!rt->u.dst.neighbour || !rt->u.dst.neighbour->dev) {
		sdp_dbg_warn(NULL, "No neighbour found for <%08x:%08x>",
			     rt->rt_src, rt->rt_dst);

		result = -ENETUNREACH;
		goto error;
	}

	sdp_dbg_data(NULL, "Found dev <%s>. <%08x:%08x:%08x> state <%02x>",
		     rt->u.dst.neighbour->dev->name,
		     rt->rt_src, rt->rt_dst, rt->rt_gateway,
		     rt->u.dst.neighbour->nud_state);
	/*
	 * device needs to be a valid IB device. Check for loopback.
	 * In case of loopback find a valid IB device on which to
	 * direct the loopback traffic.
	 */
	if (rt->u.dst.neighbour->dev->flags & IFF_LOOPBACK)
		dev = ip_dev_find(rt->rt_src);
	else {
		dev = rt->u.dst.neighbour->dev;
		dev_hold(dev);
	}

	/*
	 * check for IB device or loopback, the later requires extra
	 * handling.
	 */
	if (dev->type != ARPHRD_INFINIBAND && !(dev->flags & IFF_LOOPBACK)) {
		result = -ENETUNREACH;
		goto error;
	}

	info->gw  = rt->rt_gateway;
	info->src = rt->rt_src;     /* true source IP address */

	if (dev->flags & IFF_LOOPBACK) {
		dev_put(dev);
		read_lock(&dev_base_lock);
		for (dev = dev_base; dev; dev = dev->next) {
			if (dev->type == ARPHRD_INFINIBAND &&
			    (dev->flags & IFF_UP)) {
				dev_hold(dev);
				break;
			}
		}
		read_unlock(&dev_base_lock);
	}

	if (!dev) {
		sdp_dbg_warn(NULL, "No device for IB comm <%s:%08x:%08x>",
			     rt->u.dst.neighbour->dev->name,
			     rt->u.dst.neighbour->dev->flags,
			     rt->rt_src);
		result = -ENODEV;
		goto error;
	}
	/*
	 * lookup local info.
	 */
	priv = dev->priv;

	info->ca             = priv->ca;
	info->port           = priv->port;
	info->path.pkey      = cpu_to_be16(priv->pkey);
	info->path.numb_path = 1;

	memcpy(&info->path.sgid, dev->dev_addr + 4, sizeof(union ib_gid));
	/*
	 * If the routing device is loopback save the device address of
	 * the IB device which was found.
	 */
	if (rt->u.dst.neighbour->dev->flags & IFF_LOOPBACK) {
		memcpy(&info->path.dgid, dev->dev_addr + 4,
		       sizeof(union ib_gid));

		goto path;
	}

	if ((NUD_CONNECTED|NUD_DELAY|NUD_PROBE) &
	    rt->u.dst.neighbour->nud_state) {
		memcpy(&info->path.dgid, rt->u.dst.neighbour->ha + 4,
		       sizeof(union ib_gid));

		goto path;
	}
	/*
	 * No address entry, either ARP inprogress or needs to be issued.
	 */
	if (NUD_INCOMPLETE & rt->u.dst.neighbour->nud_state) {
		result = 0;
		goto done;
	}

	arp_send(ARPOP_REQUEST,
		 ETH_P_ARP,
		 info->gw,
		 dev,
		 info->src,
		 NULL,
		 dev->dev_addr,
		 NULL);
	/*
	 * start arp timer if it's not already going.
	 */
	if (info->flags & SDP_LINK_F_ARP) {
		struct sdp_path_wait *sweep;
		struct sdp_path_wait *wait;

		list_for_each_entry_safe(wait, sweep, &info->wait_list, list)
			if (wait->retry++ > SDP_LINK_ARP_RETRY)
				sdp_path_wait_complete(wait, info, -ETIMEDOUT);

		if (list_empty(&info->wait_list)) {
			result = -ETIMEDOUT;
			goto error;
		}

		info->arp_time = min(SDP_LINK_ARP_TIME_MAX,
				     (info->arp_time * 2));
	}

	info->flags |= SDP_LINK_F_ARP;
	queue_delayed_work(link_wq, &info->timer, info->arp_time);
	if (dev)
		dev_put(dev);
	ip_rt_put(rt);
	return;
path:
	result = sdp_link_path_rec_get(info);
	if (result) {
		sdp_dbg_warn(NULL, "Error <%d> getting path record.", result);
		goto error;
	}
done:
	if (dev)
		dev_put(dev);
	ip_rt_put(rt);
	return;
error:
	sdp_path_info_destroy(info, result);
	if (dev)
		dev_put(dev);
	ip_rt_put(rt);
}

static void retry_link_path_lookup(void *data)
{
	down(&sdp_link_mutex);
	do_link_path_lookup(data);
	up(&sdp_link_mutex);
}

/*
 * Public functions
 */

/*
 * sdp_link_path_lookup - resolve an ip address to a path record
 */
int sdp_link_path_lookup(u32 dst_addr,      /* NBO */
			 u32 src_addr,      /* NBO */
			 int bound_dev_if,  /* socket option */
			 void (*completion)(u64 id,
					    int status,
					    u32 dst_addr,
					    u32 src_addr,
					    u8  hw_port,
					    struct ib_device *ca,
					    struct ib_sa_path_rec *path,
					    void *arg),
			 void *arg,
			 u64  *id)
{
	struct sdp_path_info *info;
	struct sdp_path_wait *wait;
	int result = 0;

	down(&sdp_link_mutex);

	*id = _SDP_PATH_LOOKUP_ID();

	list_for_each_entry(info, &info_list, info_list)
		if (info->dst == dst_addr && info->dif == bound_dev_if)
			break;

	if (&info->info_list == &info_list) {
		info = sdp_path_info_create(dst_addr, bound_dev_if);
		if (!info) {
			sdp_dbg_warn(NULL, "Failed to create path object");
			return -ENOMEM;
		}

		info->src = src_addr; /* source is used in lookup and
					 populated by routing lookup */
	}
	/*
	 * if not waiting for result, complete.
	 */
	if (info->flags & SDP_LINK_F_VALID) {
		sdp_link_path_complete(*id, 0, info, completion, arg);
		goto done;
	}
	/*
	 * add request to list of lookups.
	 */
	wait = kmem_cache_alloc(wait_cache, SLAB_KERNEL);
	if (!wait) {
		sdp_dbg_warn(NULL, "Failed to create path wait object");
		result = -ENOMEM;
		goto done;
	}

	wait->id = *id;
	wait->completion = completion;
	wait->arg        = arg;

	list_add(&wait->list, &info->wait_list);

	/*
	 * initiate address lookup, if not in progress.
	 */
	if (!((SDP_LINK_F_ARP|SDP_LINK_F_PATH) & info->flags))
		do_link_path_lookup(info);

done:
	up(&sdp_link_mutex);
	return result;
}

/*
 * timers
 */

/*
 * sdp_link_sweep - periodic path information cleanup function
 */
static void sdp_link_sweep(void *data)
{
	struct sdp_path_info *info;
	struct sdp_path_info *sweep;

	down(&sdp_link_mutex);
	list_for_each_entry_safe(info, sweep, &info_list, info_list) {
		if (jiffies > (info->use + SDP_LINK_INFO_TIMEOUT)) {
			sdp_dbg_ctrl(NULL,
				     "info delete <%d.%d.%d.%d> <%lu:%lu>",
				     info->dst & 0x000000ff,
				     (info->dst & 0x0000ff00) >> 8,
				     (info->dst & 0x00ff0000) >> 16,
				     (info->dst & 0xff000000) >> 24,
				     jiffies, info->use);

			sdp_path_info_destroy(info, -ETIMEDOUT);
		}
	}
	up(&sdp_link_mutex);

	queue_delayed_work(link_wq, &link_timer, SDP_LINK_SWEEP_INTERVAL);
}

/*
 * Arp packet reception for completions
 */

/*
 * sdp_link_arp_work - handle IB REQUEST/REPLY ARP packets
 */
static void sdp_link_arp_work(void *data)
{
	struct sdp_work *work = data;
	struct sk_buff *skb = work->arg;
	struct sdp_path_info *info;
	struct sdp_link_arp *arp;
	int result;

	arp = (struct sdp_link_arp *)skb->nh.raw;

	sdp_dbg_data(NULL, "Recv IB ARP ip <%d.%d.%d.%d> gid <" GID_FMT ">",
		     arp->src_ip & 0x000000ff,
		     (arp->src_ip & 0x0000ff00) >> 8,
		     (arp->src_ip & 0x00ff0000) >> 16,
		     (arp->src_ip & 0xff000000) >> 24,
		     GID_ARG(arp->src_gid));

	down(&sdp_link_mutex);
	/*
	 * find a path info structure for the source IP address.
	 */
	list_for_each_entry(info, &info_list, info_list)
		if (info->dst == arp->src_ip)
			break;

	if (&info->info_list == &info_list)
		goto done;
	/*
	 * update record info, and request new path record data.
	 */
	if (info->flags & SDP_LINK_F_ARP) {
		cancel_delayed_work(&info->timer);
		info->flags &= ~SDP_LINK_F_ARP;
	}

	memcpy(&info->path.dgid, &arp->src_gid, sizeof(union ib_gid));

	result = sdp_link_path_rec_get(info);
	if (result) {
		sdp_dbg_warn(NULL, "Error <%d> path request on ARP.", result);
		sdp_path_info_destroy(info, result);
	}

done:
	up(&sdp_link_mutex);
	kfree_skb(skb);
	kfree(work);
}

/*
 * sdp_link_arp_recv - receive all ARP packets
 */
static int sdp_link_arp_recv(struct sk_buff *skb, struct net_device *dev,
			     struct packet_type *pt)
{
	struct sdp_work *work;
	struct arphdr *arp_hdr;

	arp_hdr = (struct arphdr *)skb->nh.raw;

	if (dev->type != ARPHRD_INFINIBAND ||
	    (arp_hdr->ar_op != __constant_htons(ARPOP_REPLY) &&
	     arp_hdr->ar_op != __constant_htons(ARPOP_REQUEST)))
		goto done;
	/*
	 * queue IB arp packet onto work queue.
	 */
	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		goto done;

	work->arg = skb;
	INIT_WORK(&work->work, sdp_link_arp_work, work);
	queue_work(link_wq, &work->work);

	return 0;
done:
	kfree_skb(skb);
	return 0;
}

/*
 * primary initialization/cleanup functions
 */
static struct packet_type sdp_arp_type = {
	.type           = __constant_htons(ETH_P_ARP),
	.func           = sdp_link_arp_recv,
	.af_packet_priv = (void*) 1, /* understand shared skbs */
};

/*
 * sdp_link_addr_init - initialize the link address retrival code
 */
int sdp_link_addr_init(void)
{
	int result;

	sdp_dbg_init("Link level services initialization.");

	info_cache = kmem_cache_create("sdp_path_info",
					sizeof(struct sdp_path_info),
					0, SLAB_HWCACHE_ALIGN,
					NULL, NULL);
	if (!info_cache) {
		sdp_warn("Failed to allocate path info cache.");

		result = -ENOMEM;
		goto error_path;
	}

	wait_cache = kmem_cache_create("sdp_path_wait",
					sizeof(struct sdp_path_wait),
					0, SLAB_HWCACHE_ALIGN,
					NULL, NULL);
	if (!wait_cache) {
		sdp_warn("Failed to allocate path wait cache.");

		result = -ENOMEM;
		goto error_wait;
	}

	link_wq = create_workqueue("sdp_wq");
	if (!link_wq) {
		sdp_warn("Failed to allocate ARP wait queue.");

		result = -ENOMEM;
		goto error_wq;
	}

	INIT_WORK(&link_timer, sdp_link_sweep, NULL);
	queue_delayed_work(link_wq, &link_timer, SDP_LINK_SWEEP_INTERVAL);
	/*
	 * install device for receiving ARP packets in parallel to the normal
	 * Linux ARP, this will be the SDP notifier that an ARP request has
	 * completed.
	 */
	dev_add_pack(&sdp_arp_type);

	return 0;
error_wq:
	kmem_cache_destroy(wait_cache);
error_wait:
	kmem_cache_destroy(info_cache);
error_path:
	return result;
}

/*
 * sdp_link_addr_cleanup - cleanup the link address retrival code
 */
void sdp_link_addr_cleanup(void)
{
	struct sdp_path_info *info;
	struct sdp_path_info *sweep;

	sdp_dbg_init("Link level services cleanup.");
	/*
	 * remove ARP packet processing.
	 */
	dev_remove_pack(&sdp_arp_type);
	/*
	 * destroy work queue
	 */
	cancel_delayed_work(&link_timer);
	flush_workqueue(link_wq);
	destroy_workqueue(link_wq);
	/*
	 * clear objects
	 */
	list_for_each_entry_safe(info, sweep, &info_list, info_list)
		sdp_path_info_destroy(info, -EINTR);
	/*
	 * destroy caches
	 */
	kmem_cache_destroy(info_cache);
	kmem_cache_destroy(wait_cache);
}

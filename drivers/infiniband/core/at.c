/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
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
 * $Id: at.c 3938 2005-11-02 11:29:35Z mst $
 */

/*
 * IB address translation service implementation. The ARP path is modeled
 * after the ARP path of the original openib gen 2 SDP resolving path by
 * Libor Michalek.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <net/flow.h>
#include <net/route.h>
#include <net/arp.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/utsname.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_sa.h>

#include <ipoib.h>
#include <rdma/ib_at.h>
#include "at_priv.h"

MODULE_AUTHOR("Shahar Frank");
MODULE_DESCRIPTION("InfiniBand address translation");
MODULE_LICENSE("Dual BSD/GPL");

static struct ib_at_dev ib_at_devs[IB_AT_MAX_DEV];

static void free_ats_req(void *async);
static void free_route_req(void *async);
static void free_path_req(void *async);
static void path_req_complete(int status, struct ib_sa_path_rec *resp,
			      void *context);
static int resolve_path(struct path_req *req, struct ib_sa_path_rec *rec);
static int resolve_ats_route(struct route_req *req,
			      struct ib_sa_service_rec *rec);
static int resolve_ats_ips(struct ats_ips_req *req,
			      struct ib_sa_service_rec *rec);
static void ib_dev_ats_op(struct ib_at_dev *ib_dev, int op,
			  u64 mask, struct ib_sa_service_rec *rec);
static void ib_dev_remove(struct ib_at_dev *ib_dev);
static char *ipstr(u32 ip, char *buf, int len) __attribute__ ((unused));

static char *ipstr(u32 ip, char *buf, int len)
{
	unsigned char *ipa = (char *)&ip;

	ip = cpu_to_be32(ip);

	snprintf(buf, len, "%u.%u.%u.%u", ipa[3], ipa[2], ipa[1], ipa[0]);

	buf[len-1] = 0;

	return buf;
}

static void build_ats_req(struct ib_sa_service_rec *rec,
			  union ib_gid *gid, u16 pkey, u32 addr)
{
	struct ib_sa_ats_rec *ats;

	memset(rec, 0, sizeof *rec);

	rec->id = IB_ATS_SERVICE_ID;
	if (gid)
		memcpy(&rec->gid, gid, sizeof rec->gid);
	rec->pkey = pkey;
	rec->lease = IB_DEFAULT_SERVICE_LEASE;
	/* key is left as zero */
	strcpy(rec->name, IB_ATS_SERVICE_NAME);

	ats = (struct ib_sa_ats_rec *)&rec->data8;
	ats->node_addr = addr;
	ats->magic_key = IB_ATS_OPENIB_MAGIC_KEY;

	if (!system_utsname.domainname[0])
		strncpy(ats->node_name, system_utsname.nodename,
			sizeof ats->node_name);
	else
		snprintf(ats->node_name, sizeof ats->node_name, "%s.%s",
			system_utsname.nodename, system_utsname.domainname);
}

static void ats_op_complete(int status, struct ib_sa_service_rec *resp,
			    void *context)
{
	struct ib_at_dev *ib_dev = context;
	int op = ib_dev->pend_op;
	DEBUG_VAR(char ipbuf[32]);

	DEBUG("ib_dev %s (%s) op %d completed with status %d",
		ib_dev->netdev->name, ipstr(ib_dev->ip, ipbuf, sizeof ipbuf),
		op, status);

	if (status) {
		DEBUG("retry #%d", ib_dev->retries);
		if (++(ib_dev->retries) >= IB_AT_REQ_RETRIES) {
			WARN("op %d timed out after %d retries",
				op, ib_dev->retries);
			ib_dev->sa_query = NULL;
			ib_dev->pend_op = 0;
			return;
		}
		ib_dev_ats_op(ib_dev, ib_dev->pend_op, ib_dev->pend_mask, resp);
		return;
	}

	ib_dev->sa_query = NULL;
	ib_dev->pend_op = 0;

	if (op == IB_MGMT_METHOD_SET)
		ib_dev->registered = 1;

	ib_dev->old_ip = 0;

	if (ib_dev->pend_op == IB_SA_METHOD_DELETE)
		ib_dev_remove(ib_dev);

}

static void ib_dev_ats_op(struct ib_at_dev *ib_dev, int op,
			  u64 mask, struct ib_sa_service_rec *rec)
{
	struct ib_sa_service_rec sa_rec;
	struct ipoib_dev_priv *priv;
	struct net_device *netdev;
	WARN_VAR(char ipbuf[32]);

	netdev = ib_dev->netdev;
	priv = netdev->priv;

	DEBUG("ib_dev %p (%s) op %d mask %llx rec %p",
		ib_dev, netdev->name, op, mask, rec);
	if (!rec) {	/* new query */
		if (ib_dev->pend_op) {
			WARN("dev (%p) %s already has pending op %d",
				ib_dev, netdev->name, ib_dev->pend_op);
			return;
		}
		build_ats_req(&sa_rec, (union ib_gid *)(netdev->dev_addr + 4),
			      priv->pkey, ib_dev->ip);
		rec = &sa_rec;

		ib_dev->pend_op = op;
		ib_dev->pend_mask = mask;
	}

	ib_dev->sa_query = NULL;

	ib_dev->sa_id =
		ib_sa_service_rec_query(priv->ca,
					priv->port,
					op,
					rec,
					mask,
					IB_AT_REQ_RETRY_MS,
					GFP_KERNEL,
					ats_op_complete,
					ib_dev,
					&ib_dev->sa_query);

	if (ib_dev->sa_id < 0) {
		ib_dev->sa_query = NULL;
		WARN("operation %d on dev %s (%s) failed: %d",
			op, netdev->name, 
			ipstr(ib_dev->ip, ipbuf, sizeof ipbuf),
			ib_dev->sa_id);
	}

	DEBUG("req id %d", ib_dev->sa_id);
}

static void ib_dev_remove(struct ib_at_dev *ib_dev)
{
	DEBUG_VAR(char ipbuf[32], ipbuf1[32]);

	DEBUG("removing ib_dev %s (%s, old %s)",
		ib_dev->netdev->name,
		ipstr(ib_dev->ip, ipbuf, sizeof ipbuf),
		ipstr(ib_dev->old_ip, ipbuf1, sizeof ipbuf1));

	if (ib_dev->sa_query) {
		ib_sa_cancel_query(ib_dev->sa_id, ib_dev->sa_query);
		ib_dev->sa_query = NULL;
	}
	ib_dev->pend_op = 0;

	dev_put(ib_dev->netdev);
	ib_dev->netdev = NULL;
	ib_dev->old_ip = 0;
	ib_dev->ip = 0;
	ib_dev->valid = 0;
	ib_dev->registered = 0;
}

static void ib_dev_deregister(struct ib_at_dev *ib_dev)
{
	ib_dev_ats_op(ib_dev, IB_SA_METHOD_DELETE, IB_ATS_GET_GID_MASK, NULL);
}

static void ib_dev_register(struct ib_at_dev *ib_dev)
{
	ib_dev_ats_op(ib_dev, IB_MGMT_METHOD_SET, IB_ATS_MASK, NULL);
}

static void ib_devs_clean(void)
{
	struct ib_at_dev *ib_dev, *e;
	DEBUG_VAR(char ipbuf[32]);

	DEBUG("cleaning...");
	for (ib_dev = ib_at_devs, e = ib_dev + IB_AT_MAX_DEV;
	     ib_dev < e; ib_dev++) {
		if (!ib_dev->netdev || !ib_dev->valid)
			continue;
		DEBUG("cleaning %s (%s)", ib_dev->netdev->name,
			ipstr(ib_dev->ip, ipbuf, sizeof ipbuf));
		ib_dev_remove(ib_dev);
	}
}

static void ib_devs_sweep(void)
{
	struct net_device *netdev;
	struct ib_at_dev *ib_dev, *e;
	DEBUG_VAR(char ipbuf[32]);

	for (ib_dev = ib_at_devs, e = ib_dev + IB_AT_MAX_DEV;
	     ib_dev < e; ib_dev++) {
		if (!(netdev = ib_dev->netdev))
			continue;

		DEBUG("checking ib_dev %s (%s)",
			netdev->name,
			ipstr(ib_dev->ip, ipbuf, sizeof ipbuf));
		
		if (ib_dev->valid && ib_dev->registered && !ib_dev->old_ip)
			continue;

		DEBUG("handling ib_dev %s (%s)",
			netdev->name,
			ipstr(ib_dev->ip, ipbuf, sizeof ipbuf));

		if (!ib_dev->valid) {
			if (ib_dev->old_ip)
				ib_dev_deregister(ib_dev);
			else
				ib_dev_remove(ib_dev);
			continue;
		}

		/*
		 * !ib_dev->registered || ib_dev->old_ip : new or addr changed,
		 * just (re)-register.
		 */

		ib_dev_register(ib_dev);
	}
}

static int ib_devs_changed(void)
{
	struct net_device *ibdevs[IB_AT_MAX_DEV];
	struct net_device *netdev;
	struct ib_at_dev *ib_dev, *e = ib_at_devs + IB_AT_MAX_DEV;
	int changed = 0;
	int n, i;
	u32 ip;
	WARN_VAR(char ipbuf[32]);
	DEBUG_VAR(char ipbuf1[32]);

	rtnl_lock();
	for (netdev = dev_base, n = 0; netdev && n < IB_AT_MAX_DEV;
	     netdev = netdev->next) {
		if (netdev->type == ARPHRD_INFINIBAND &&
		    netdev->flags & IFF_UP) {
			ibdevs[n++] = netdev;
			dev_hold(netdev);
		}
	}
	rtnl_unlock();

	/* Validate ib_devs, and check for address changes */
	for (ib_dev = ib_at_devs; ib_dev < e; ib_dev++) {
		if (!(netdev = ib_dev->netdev))
			continue;

		for (i = 0; i < n; i++)
			if (netdev == ibdevs[i]) {
				ibdevs[i] = NULL; /* dev handled - not new */
				break;
			}

		if (i >= n) { 	/* dev not found - mark as deleted */
			DEBUG("ib_dev %s (%s) is removed",
				netdev->name,
				ipstr(ib_dev->ip, ipbuf, sizeof ipbuf));

			ib_dev->valid = 0;
			if (ib_dev->registered && ib_dev->ip) {
				ib_dev->old_ip = ib_dev->ip;
				ib_dev->ip = 0;
			}
			dev_put(netdev);
			changed++;
			continue;
		}

		/* found - check that addr is the same */
		ip = inet_select_addr(netdev, 0, RT_SCOPE_LINK);

		if (ib_dev->ip == ip) {		/* known dev, known addr */
			dev_put(netdev);
			continue;
		}

		/* known dev, unknown addr */
		DEBUG("ib_dev %s (%s) addr changed to %s",
			netdev->name,
			ipstr(ib_dev->ip, ipbuf, sizeof ipbuf),
			ipstr(ip, ipbuf1, sizeof ipbuf1));

		ib_dev->old_ip = ib_dev->ip;
		ib_dev->ip = ip;

		dev_put(netdev);
		changed++;
	}

	/* any devices left on list are new unknown devices */
	for (i = 0; i < n; i++) {
		if (!(netdev = ibdevs[i]))
			continue;

		ip = inet_select_addr(netdev, 0, RT_SCOPE_LINK);
		/* Alloc new ib_dev */
		for (ib_dev = ib_at_devs; ib_dev < e; ib_dev++)
			if (!ib_dev->netdev)
				break;

		if (ib_dev >= e) {
			WARN("no more ib_dev slots for new device (addr %s)",
				ipstr(ip, ipbuf, sizeof ipbuf));
			dev_put(netdev);

			/* no break to let us see warnings on all new devices */
			continue;	
		}

		DEBUG("new ib_dev %s (%s) is added",
			netdev->name,
			ipstr(ip, ipbuf, sizeof ipbuf));

		/*
		 * keep netdev reference count,
		 * to be released on ib_dev_remove.
		 */
		ib_dev->netdev = netdev;
		ib_dev->old_ip = 0;
		ib_dev->ip = ip;
		ib_dev->valid = 1;
		ib_dev->registered = 0;
		
		changed++;
	}

	return changed;
}

static void ib_at_ats_reg(void *data)
{
	DEBUG("start ATS registration");

	if (ib_devs_changed())
		ib_devs_sweep();

//	queue_delayed_work(ib_at_wq, &ib_at_ats, IB_AT_ATS_REG_INTERVAL);
}

static int resolve_ip(struct ib_at_src *src, u32 dst_ip, u32 src_ip,
			int tos, union ib_gid *dgid)
{
	struct ipoib_dev_priv *priv;
	struct net_device *loopback = NULL;
	struct net_device *ipoib_dev;
	struct rtable *rt;
	struct flowi fl = {
		.oif = 0, 	/* oif */
		.nl_u = {
			.ip4_u = {
				.daddr = dst_ip, /* dst */
				.saddr = src_ip, /* src */
				.tos   = tos, /* tos */
			}
		},
	};
	int r;

	DEBUG("dst ip %08x src ip %08x tos %d", dst_ip, src_ip, tos);

	r = ip_route_output_key(&rt, &fl);
	if (r < 0 || !rt) {
		WARN("ip_route_output_key: routing <%08x:%08x>: err %d",
		     dst_ip, src_ip, r);
		if (r >= 0)
			r = -EINVAL;
		rt = NULL;
		goto done;
	}

	/*
	 * check route flags
	 */
	if ((RTCF_MULTICAST|RTCF_BROADCAST) & rt->rt_flags) {
		r = -ENETUNREACH;
		goto done;
	}

	if (!rt->u.dst.neighbour || !rt->u.dst.neighbour->dev) {
		WARN("no neighbour found for <%08x:%08x>",
		     rt->rt_src, rt->rt_dst);

		r = -ENETUNREACH;
		goto done;
	}

	DEBUG("Found dev <%s>. <%08x:%08x:%08x> state <%02x>",
	     rt->u.dst.neighbour->dev->name,
	     rt->rt_src, rt->rt_dst, rt->rt_gateway,
	     rt->u.dst.neighbour->nud_state);

	/*
	 * device needs to be a valid IB device. Check for loopback.
	 * In case of loopback, find valid IB device on which to
	 * direct the loopback traffic.
	 */
	ipoib_dev = ((rt->u.dst.neighbour->dev->flags & IFF_LOOPBACK) ?
		     (loopback = ip_dev_find(rt->rt_src)) :
		     rt->u.dst.neighbour->dev);

	/* Check for IB device or loopback */
	if (ipoib_dev->type != ARPHRD_INFINIBAND &&
	    !(ipoib_dev->flags & IFF_LOOPBACK)) {
		r = -ENETUNREACH;
		goto done;
	}

	src->gw  = rt->rt_gateway;
	src->ip = rt->rt_src;     /* true source IP address */

	if (ipoib_dev->flags & IFF_LOOPBACK) {
		read_lock(&dev_base_lock);
		for (ipoib_dev = dev_base; ipoib_dev; 
		     ipoib_dev = ipoib_dev->next)
			if (ARPHRD_INFINIBAND == ipoib_dev->type &&
			    (ipoib_dev->flags & IFF_UP))
				break;
		read_unlock(&dev_base_lock);
	}

	if (!ipoib_dev) {
		WARN("No device for IB comm <%s:%08x:%08x>",
		     rt->u.dst.neighbour->dev->name,
		     rt->u.dst.neighbour->dev->flags,
		     rt->rt_src);
		r = -ENODEV;
		goto done;
	}

	/*
	 * lookup local info.
	 */
	priv = ipoib_dev->priv;

	src->netdev = ipoib_dev;
	src->dev = priv->ca;
	src->port = priv->port;
	src->pkey = cpu_to_be16(priv->pkey);
	memcpy(&src->gid, ipoib_dev->dev_addr + 4, sizeof src->gid);

	if (!dgid) {
		r = 0;
		goto done;
	}

	/*
	 * If the routing device is loopback save the device address of
	 * the IB device which was found.
	 */
	if (rt->u.dst.neighbour->dev->flags & IFF_LOOPBACK) {
		memcpy(dgid, ipoib_dev->dev_addr + 4, sizeof *dgid);
		r = 1;
		goto done;
	}

	if ((NUD_CONNECTED|NUD_DELAY|NUD_PROBE) &
	    rt->u.dst.neighbour->nud_state) {
		memcpy(dgid, rt->u.dst.neighbour->ha + 4, sizeof *dgid);
		r = 1;
		goto done;
	}

	memset(dgid, 0, sizeof *dgid);
	r = 0;
done:
	if (loopback)
		dev_put(loopback);
	ip_rt_put(rt);
	return r;
}

static u64 alloc_req_id(void)
{
	static u64 req_id = 0;
	u64 new_id;
	unsigned long flags;

	spin_lock_irqsave(&pending_reqs.lock, flags);
	new_id = ++req_id;
	if (!new_id)		/* 0 is not used as req_id (reserved value) */
		new_id = ++req_id;
	spin_unlock_irqrestore(&pending_reqs.lock, flags);

	return new_id;
}

static void req_init(struct async *pend, void *data, int nelem, int type,
		     struct ib_at_completion *async_comp)
{
	memset(pend, 0, sizeof *pend);

	pend->id = async_comp->req_id = alloc_req_id();
	pend->status = IB_AT_STATUS_INVALID;
	pend->data = data;
	pend->nelem = nelem;
	pend->comp = *async_comp;
	pend->type = type;
	pend->timeout_ms = IB_AT_REQ_RETRY_MS;
}

static void req_free(struct async *pend)
{
	switch (pend->type) {
	case IBAT_REQ_ATSARP:
		free_ats_req(pend);
		break;
	case IBAT_REQ_ARP:
	case IBAT_REQ_ATS:
		free_route_req(pend);
		break;
	case IBAT_REQ_PATHREC:
		free_path_req(pend);
		break;
	default:
		WARN("bad async req type %d", pend->type);
		if (pend->sa_query) {
			ib_sa_cancel_query(pend->sa_id, pend->sa_query);
			pend->sa_query = NULL;
		}
		pend->status = IB_AT_STATUS_INVALID;
		pend->type = IBAT_REQ_NONE;
		break;
	}
}

static int req_start(struct async *q, struct async *pend,
		     struct async *parent)
{
	unsigned long flags;

	DEBUG("q %p pend %p parent %p", q, pend, parent);

	spin_lock_irqsave(&q->lock, flags);
	pend->status = IB_AT_STATUS_PENDING;
	pend->start = jiffies;

	if (parent) {
		DEBUG("wait on parent %p", parent);
		pend->next = pend->prev = NULL;
		pend->parent = parent;
		pend->waiting = parent->waiting;
		parent->waiting = pend;
		spin_unlock_irqrestore(&q->lock, flags);
		return 0;	/* waiting on other request */
	}

	pend->waiting = NULL;
	pend->parent = NULL;

	DEBUG("link to pending list %p", q);
	pend->next = q;
	pend->prev = q->prev;
	q->prev->next = pend;
	q->prev = pend;
	spin_unlock_irqrestore(&q->lock, flags);

	return 1;		/* should start new request */
}

static void req_comp_work(void *v)
{
	struct async *pend = v;

	DEBUG("complete pend %p", pend);

	pend->comp.fn(pend->comp.req_id, pend->comp.context, pend->nelem);

	req_free(pend);
}

static void req_end(struct async *pend, int nrec, struct async *q)
{
	struct async **rr, *waiting;
	unsigned long flags = 0;

	DEBUG("pend %p nrec %d async %p", pend, nrec, q);

	if (pend->sa_query) {
		ib_sa_cancel_query(pend->sa_id, pend->sa_query);
		pend->sa_query = NULL;
	}

	if (pend->status != IB_AT_STATUS_PENDING)
		WARN("pend %p already completed? status %d", pend, pend->status);

	pend->status = nrec < 0 ? IB_AT_STATUS_ERROR : IB_AT_STATUS_COMPLETED;

	if (q)
		spin_lock_irqsave(&q->lock, flags);

	if (pend->parent) {
		DEBUG("pend->parent %p", pend->parent);
		for (rr = &pend->parent->waiting; *rr; rr = &(*rr)->waiting)
			if (*rr == pend) {
				*rr = (*rr)->waiting;
				break;
			}

		if (!*rr)
			WARN("pending request not found in parent request!");

		pend->waiting = NULL;
		DEBUG("child %p removed from parent %p list",
			pend, pend->parent);
	}

	while ((waiting = pend->waiting)) {
		DEBUG("pend %p ending child req %p", pend, waiting);
		pend->waiting = waiting->waiting;

		waiting->waiting = NULL;
		waiting->parent = NULL;

		req_end(waiting, nrec, NULL);
	}

	if (pend->next) {
		BUG_ON(!pend->prev);

		DEBUG("remove self %p from pending q", pend);
		pend->next->prev = pend->prev;
		pend->prev->next = pend->next;
	}

	if (nrec < pend->nelem)
		pend->nelem = nrec;

	if (q)
		spin_unlock_irqrestore(&q->lock, flags);

	INIT_WORK(&pend->work, req_comp_work, pend);
	queue_work(ib_at_wq, &pend->work);
}

static int same_route_req(struct async *a, struct async *b)
{
	struct route_req *ra = container_of(a, struct route_req, pend);
	struct route_req *rb = container_of(b, struct route_req, pend);

	return ra->dst_ip == rb->dst_ip &&
	       ra->src.ip == rb->src.ip &&
	       ra->src.pkey == rb->src.pkey;
}

static int same_path_req(struct async *a, struct async *b)
{
	struct path_req *pa = container_of(a, struct path_req, pend);
	struct path_req *pb = container_of(b, struct path_req, pend);

	return !memcmp(&pa->rt.sgid, &pb->rt.sgid, sizeof pa->rt.sgid) &&
	       !memcmp(&pa->rt.dgid, &pb->rt.dgid, sizeof pa->rt.dgid) &&
	       pa->rt.out_dev == pb->rt.out_dev &&
	       pa->rt.out_port == pb->rt.out_port &&
	       pa->rt.attr.pkey == pb->rt.attr.pkey &&
	       pa->rt.attr.qos_tag == pb->rt.attr.qos_tag &&
	       pa->rt.attr.multi_path_type == pb->rt.attr.multi_path_type;
};

static int same_ats_ips_req(struct async *a, struct async *b)
{
	struct ats_ips_req *ra = container_of(a, struct ats_ips_req, pend);
	struct ats_ips_req *rb = container_of(b, struct ats_ips_req, pend);

	return !memcmp(&ra->gid, &rb->gid, sizeof ra->gid);
}

static void free_ats_req(void *async)
{
	struct ats_ips_req *req = container_of(async, struct ats_ips_req, pend);

	DEBUG("free async %p req %p", async, req);

	if (req->pend.sa_query) {
		ib_sa_cancel_query(req->pend.sa_id, req->pend.sa_query);
		req->pend.sa_query = NULL;
	}
	req->pend.status = IB_AT_STATUS_INVALID;
	req->pend.type = IBAT_REQ_NONE;

	kmem_cache_free(ats_ips_req_cache, req);
}

static void free_route_req(void *async)
{
	struct route_req *req = container_of(async, struct route_req, pend);

	DEBUG("free async %p req %p", async, req);

	if (req->pend.sa_query) {
		ib_sa_cancel_query(req->pend.sa_id, req->pend.sa_query);
		req->pend.sa_query = NULL;
	}
	req->pend.status = IB_AT_STATUS_INVALID;
	req->pend.type = IBAT_REQ_NONE;

	kmem_cache_free(route_req_cache, req);
}

static void free_path_req(void *async)
{
	struct path_req *req = container_of(async, struct path_req, pend);

	DEBUG("free async %p req %p", async, req);

	if (req->pend.sa_query) {
		ib_sa_cancel_query(req->pend.sa_id, req->pend.sa_query);
		req->pend.sa_query = NULL;
	}
	req->pend.status = IB_AT_STATUS_INVALID;
	req->pend.type = IBAT_REQ_NONE;

	kmem_cache_free(path_req_cache, req);
}

static struct async *lookup_pending(struct async *q, struct async *new,
			     	    int type, int (same_fn)(struct async *a,
							    struct async *b))
{
	unsigned long flags;
	struct async *a;

	DEBUG("lookup in q %p pending %p", q, new);
	spin_lock_irqsave(&q->lock, flags);
	for (a = q->next; a != q; a = a->next) {
		DEBUG("req type %d %d", a->type, type);
		if (a->type == type && same_fn(a, new))
			break;
	}

	spin_unlock_irqrestore(&q->lock, flags);
	return a == q ? NULL : a;
}

static struct async *lookup_req_id(struct async *q, u64 id)
{
	unsigned long flags;
	struct async *a;

	DEBUG("lookup in q %p id 0x%llx", q, id);
	spin_lock_irqsave(&q->lock, flags);
	for (a = q->next; a != q; a = a->next)
		if (a->id == id)
			break;

	spin_unlock_irqrestore(&q->lock, flags);
	return a == q ? NULL : a;
}

static void flush_pending(struct async *q)
{
	unsigned long flags;
	struct async *a;

	DEBUG("flushing pending q %p", q);
	spin_lock_irqsave(&q->lock, flags);
	while ((a = q->next) != q)
		req_end(a, -EINTR, NULL);
	spin_unlock_irqrestore(&q->lock, flags);
}

static int ats_ips_req_output(struct ats_ips_req *req,
			      struct ib_sa_service_rec *resp,
			      int nrecs, u32 *ips, int nelem)
{
	int i, n = min(nrecs, nelem);

	DEBUG("parent %p output %d records", req, n);

	for (i = 0; i < n; i++)
		memcpy(ips + i, resp[i].data8 + 12, sizeof (u32));

	return n;
}

static int route_req_output(struct route_req *req,
			     struct ib_at_ib_route *rt)
{
	DEBUG("fill ib_route %p using req %p", rt, req);

	rt->sgid = req->src.gid;
	rt->dgid = req->dgid;
	rt->out_dev = req->src.dev;
	rt->out_port = req->src.port;
	rt->attr.qos_tag = 0;			/* FIXME: ??? */
	rt->attr.pkey = req->src.pkey;
	rt->attr.multi_path_type = IB_AT_PATH_SAME_PORT;

	return 1;		/* one entry is filled */
}

static int path_req_output(struct ib_sa_path_rec *resp, int npath,
			   struct ib_sa_path_rec *out, int nelem)
{
	int n = min(npath, nelem);

	DEBUG("output ib_sa_path_rec %p %d records", out, n);

	memcpy(out, resp, n * sizeof (struct ib_sa_path_rec));
	return n;
}

/* call under pending list lock */
static void
route_req_complete(struct route_req *req, union ib_gid *gid)
{
	struct async *pend;

	DEBUG("req %p", req);

	if (req->pend.parent) {
		WARN("route_req_complete for child req %p???", req);
		return;
	}

	req->dgid = *gid;

	route_req_output(req, req->pend.data);

	for (pend = req->pend.waiting; pend; pend = pend->waiting)	
		route_req_output(req, pend->data);

	req_end(&req->pend, 1, NULL);
}

static void
ats_route_req_complete(int status, struct ib_sa_service_rec *resp,
		       void *context)
{
	struct route_req *req = context;
	unsigned long flags;

	DEBUG("req %p status %d", req, status);

	req->pend.sa_query = NULL;

	if (status) {
		DEBUG("status %d - checking if should retry", status);
		if (status == -ETIMEDOUT &&
		    jiffies - req->pend.start < IB_AT_REQ_TIMEOUT)
			resolve_ats_route(req, resp);
		else
			req_end(&req->pend, status, &pending_reqs);
		return;
	}

	spin_lock_irqsave(&pending_reqs.lock, flags);
	route_req_complete(req, &resp->gid);
	spin_unlock_irqrestore(&pending_reqs.lock, flags);
}

static void
ats_ips_req_complete(int status, struct ib_sa_service_rec *resp,
			    void *context)
{
	struct ats_ips_req *req = context;
	struct async *pend;
	unsigned long flags;

	DEBUG("req %p status %d", req, status);

	req->pend.sa_query = NULL;

	if (status) {
		DEBUG("status %d - checking if should retry", status);
		if (status == -ETIMEDOUT &&
		    jiffies - req->pend.start < IB_AT_REQ_TIMEOUT)
			resolve_ats_ips(req, resp);
		else
			req_end(&req->pend, status, &pending_reqs);
		return;
	}

	req->pend.nelem = ats_ips_req_output(req, resp, 1,
					     req->pend.data, req->pend.nelem);

	spin_lock_irqsave(&pending_reqs.lock, flags);
	for (pend = req->pend.waiting; pend; pend = pend->waiting)	
		pend->nelem = ats_ips_req_output(req, resp, 1,
						 pend->data, pend->nelem);

	req_end(&req->pend, req->pend.nelem, NULL);
	spin_unlock_irqrestore(&pending_reqs.lock, flags);
}

static void
path_req_complete(int status, struct ib_sa_path_rec *resp, void *context)
{
	struct path_req *req = context;
	unsigned long flags;
	struct async *pend;

	DEBUG("req %p status %d", req, status);

	req->pend.sa_query = NULL;

	if (req->pend.parent) {
		WARN("for child req %p???", req);
		return;
	}

	if (status) {
		DEBUG("status %d - checking if should retry", status);
		if (status == -ETIMEDOUT &&
		    jiffies - req->pend.start < IB_AT_REQ_TIMEOUT)
			resolve_path(req, resp);
		else
			req_end(&req->pend, status, &pending_reqs);
		return;
	}

	req->pend.nelem = path_req_output(resp, 1,
					  req->pend.data, req->pend.nelem);

	spin_lock_irqsave(&pending_reqs.lock, flags);
	for (pend = req->pend.waiting; pend; pend = pend->waiting)	
		pend->nelem = path_req_output(resp, 1,
					      pend->data, pend->nelem);

	req_end(&req->pend, req->pend.nelem, NULL);
	spin_unlock_irqrestore(&pending_reqs.lock, flags);
}

static void ib_at_sweep(void *data)
{
	struct async *pend, *next;
	struct route_req *req;
	struct ats_ips_req *areq;
	struct path_req *preq;
	unsigned long flags;

	DEBUG("start sweeping");

	spin_lock_irqsave(&pending_reqs.lock, flags);
	for (pend = pending_reqs.next; pend != &pending_reqs; pend = next) {
		next = pend->next;

		switch (pend->type) {
		case IBAT_REQ_ARP:
		case IBAT_REQ_ATS:
			req = container_of(pend, struct route_req, pend);

			DEBUG("examining route req %p pend %p", req, pend);
			if (jiffies > pend->start + IB_AT_REQ_TIMEOUT) {
				DEBUG("delete route <%d.%d.%d.%d> <%lu:%lu>",
				     (req->dst_ip & 0x000000ff),
				     (req->dst_ip & 0x0000ff00) >> 8,
				     (req->dst_ip & 0x00ff0000) >> 16,
				     (req->dst_ip & 0xff000000) >> 24,
				     jiffies, pend->start);

				req_end(pend, -ETIMEDOUT, NULL);
			}
			break;
		case IBAT_REQ_ATSARP:
			areq = container_of(pend, struct ats_ips_req, pend);

			DEBUG("examining ATS IP req %p pend %p", areq, pend);
			if (jiffies > pend->start + IB_AT_REQ_TIMEOUT) {
				DEBUG("delete ATS IP <%lu:%lu>",
				      jiffies, pend->start);

				req_end(pend, -ETIMEDOUT, NULL);
			}
			break;
		case IBAT_REQ_PATHREC:
			preq = container_of(pend, struct path_req, pend);

			DEBUG("examining path req %p pend %p", preq, pend);
			if (jiffies > pend->start + IB_AT_REQ_TIMEOUT) {
				DEBUG("delete path <%lu:%lu>",
				      jiffies, pend->start);

				req_end(pend, -ETIMEDOUT, NULL);
			}
			break;
		default:
			WARN("unknown async req type %d", pend->type);
			break;
		}
	}

	spin_unlock_irqrestore(&pending_reqs.lock, flags);

	queue_delayed_work(ib_at_wq, &ib_at_timer, IB_AT_SWEEP_INTERVAL);
}

static int resolve_ats_ips(struct ats_ips_req *req,
			      struct ib_sa_service_rec *rec)
{
	struct ib_sa_service_rec sa_rec;
	struct ipoib_dev_priv *priv;
	struct net_device *netdev;

	netdev = req->src.netdev;
	priv = netdev->priv;

	req->pend.sa_query = NULL;

	DEBUG("req %p using %s pkey 0x%x",
		req, netdev->name, (int)req->src.pkey);

	if (req->pend.type != IBAT_REQ_ATSARP) {
		WARN("bad req %p type %d", req, req->pend.type);
		return -1;
	}

	if (!rec) {	/* new query */
		build_ats_req(&sa_rec, &req->gid, req->src.pkey, 0);
		rec = &sa_rec;
	}

	req->pend.sa_id =
	    ib_sa_service_rec_query(req->src.dev,
				    req->src.port,
				    IB_MGMT_METHOD_GET,
				    rec,
				    IB_ATS_GET_PRIM_IP_MASK,
				    req->pend.timeout_ms,
				    GFP_KERNEL,
				    ats_ips_req_complete,
				    req,
				    &req->pend.sa_query);

	if (req->pend.sa_id < 0) {
		req->pend.sa_query = NULL;
		return req->pend.sa_id;
	}

	req->pend.timeout_ms <<= 1;		/* exponential backoff */
	return 0;
}

static int resolve_ats_route(struct route_req *req,
			      struct ib_sa_service_rec *rec)
{
	struct ib_sa_service_rec sa_rec;
	struct ipoib_dev_priv *priv;
	struct net_device *netdev;

	netdev = req->src.netdev;
	priv = netdev->priv;

	req->pend.sa_query = NULL;

	DEBUG("req %p (%s)", req, netdev->name);

	if (req->pend.type != IBAT_REQ_ATS) {
		WARN("bad req %p type %d", req, req->pend.type);
		return -1;
	}

	if (!rec) {	/* new query */
		build_ats_req(&sa_rec, NULL, req->src.pkey, req->dst_ip);
		rec = &sa_rec;
	}

	req->pend.sa_id =
	    ib_sa_service_rec_query(req->src.dev,
				    req->src.port,
				    IB_MGMT_METHOD_GET,
				    rec,
				    IB_ATS_GET_GID_MASK,
				    req->pend.timeout_ms,
				    GFP_KERNEL,
				    ats_route_req_complete,
				    req,
				    &req->pend.sa_query);

	if (req->pend.sa_id < 0) {
		req->pend.sa_query = NULL;
		return req->pend.sa_id;
	}

	req->pend.timeout_ms <<= 1;		/* exponential backoff */
	return 0;
}

static int resolve_route(struct route_req *req)
{
	DEBUG("req %p type %d", req, req->pend.type);

	if (req->pend.type == IBAT_REQ_ARP) {
		arp_send(ARPOP_REQUEST,
			 ETH_P_ARP,
			 req->src.gw,
			 req->src.netdev,
			 req->src.ip,
			 NULL,
			 req->src.netdev->dev_addr,
			 NULL);
		return 0;
	}

	if (req->pend.type == IBAT_REQ_ATS)
		return resolve_ats_route(req, NULL);

	WARN("bad req %p type %d", req, req->pend.type);
	return -1;
}

static int resolve_path(struct path_req *req, struct ib_sa_path_rec *rec)
{
	struct ib_sa_path_rec sa_rec;

	if (req->pend.type != IBAT_REQ_PATHREC) {
		WARN("bad req %p type %d", req, req->pend.type);
		return -1;
	}

	if (!rec) {
		memset(&sa_rec, 0, sizeof sa_rec);
		sa_rec.pkey = req->rt.attr.pkey;
		sa_rec.numb_path = req->pend.nelem;
		sa_rec.dgid = req->rt.dgid;
		sa_rec.sgid = req->rt.sgid;
		rec = &sa_rec;
	}

	req->pend.sa_id = ib_sa_path_rec_get(req->rt.out_dev,
					     req->rt.out_port,
					     rec,
					    (IB_SA_PATH_REC_DGID |
					     IB_SA_PATH_REC_SGID |
					     IB_SA_PATH_REC_PKEY |
					     IB_SA_PATH_REC_NUMB_PATH),
					     req->pend.timeout_ms,
					     GFP_KERNEL,
					     path_req_complete,
					     req,
					    &req->pend.sa_query);

	if (req->pend.sa_id < 0) {
		req->pend.sa_query = NULL;
		WARN("ib_sa_path_rec_get failed %d", req->pend.sa_id);
		return req->pend.sa_id;
	}

	req->pend.timeout_ms <<= 1;		/* exponential backoff */
	return 0;
}

static void ib_at_arp_work(void *data)
{
	struct arp_work *work = data;
	struct sk_buff *skb = work->skb;
	struct ib_arp *arp;
	struct async *a, *q = &pending_reqs;
	struct route_req *req;
	unsigned long flags;

	arp = (struct ib_arp *)skb->nh.raw;

	DEBUG("Process IB ARP ip <%d.%d.%d.%d> gid <0x%016llx%016llx>",
	      (arp->src_ip & 0x000000ff),
	      (arp->src_ip & 0x0000ff00) >> 8,
	      (arp->src_ip & 0x00ff0000) >> 16,
	      (arp->src_ip & 0xff000000) >> 24,
	      be64_to_cpu(arp->src_gid.global.subnet_prefix),
	      be64_to_cpu(arp->src_gid.global.interface_id));

	spin_lock_irqsave(&q->lock, flags);
	for (a = q->next; a != q; a = a->next) {
		DEBUG("a %p", a);
		if (a->type != IBAT_REQ_ARP)
			continue;

		req = container_of(a, struct route_req, pend);
		DEBUG("req %p", req);

		if (arp->op == __constant_htons(ARPOP_REPLY)) {
			if (arp->dst_ip == req->dst_ip)
				route_req_complete(req, &arp->dst_gid);
		}
		/* in ARPOP_REQUESTs only the src is valid */
		if (arp->src_ip == req->dst_ip)
			route_req_complete(req, &arp->src_gid);
	}
	spin_unlock_irqrestore(&q->lock, flags);

	kfree_skb(skb);
	kfree(work);
}

static int ib_at_arp_recv(struct sk_buff *skb, struct net_device *dev,
			  struct packet_type *pt, struct net_device *orig_dev)
{
	struct arp_work *work;
	struct arphdr *arp_hdr;

	arp_hdr = (struct arphdr *)skb->nh.raw;

	if (ARPHRD_INFINIBAND != dev->type ||
	    (arp_hdr->ar_op != __constant_htons(ARPOP_REPLY) &&
	     arp_hdr->ar_op != __constant_htons(ARPOP_REQUEST)))
		goto done;
	/*
	 * queue IB arp packet onto work queue.
	 */
	DEBUG("recv IB ARP - queue work");
	work = kmalloc(sizeof *work, GFP_ATOMIC);
	if (!work)
		goto done;

	work->skb = skb;
	INIT_WORK(&work->work, ib_at_arp_work, work);
	queue_work(ib_at_wq, &work->work);
	return 0;

done:
	kfree_skb(skb);
	return 0;
}

static int
inetaddr_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	DEBUG("notifier ptr %p event %lu (%p)\n", this, event, ptr);

	cancel_delayed_work(&ib_at_ats);
	queue_work(ib_at_wq, &ib_at_ats);
	return NOTIFY_DONE;
}

/*
 * Interface functions:
 */

int ib_at_route_by_ip(u32 dst_ip, u32 src_ip, int tos, u16 flags,
		     struct ib_at_ib_route *ib_route,
		     struct ib_at_completion *async_comp)
{

	struct route_req *rreq;
	struct async *parent;
	int r, req_type;

	if (!ib_route || !dst_ip)
		return -EINVAL;

	if (async_comp)
		async_comp->req_id = 0;

	if (!(rreq = kmem_cache_alloc(route_req_cache, SLAB_KERNEL)))
		return -ENOMEM;

	rreq->dst_ip = dst_ip;
	rreq->src_ip = src_ip;
	rreq->tos = tos;
	rreq->flags = flags;

	r = resolve_ip(&rreq->src, dst_ip, src_ip, tos, &rreq->dgid);
	if (r < 0) {
		DEBUG("resolve_ip r < 0 free req %p", rreq);
		kmem_cache_free(route_req_cache, rreq);
		return r;
	}

	if (r > 0 && !(flags & IB_AT_ROUTE_FORCE_RESOLVE)) {
		route_req_output(rreq, ib_route);
		DEBUG("resolve_ip r > 0 free req %p", rreq);
		kmem_cache_free(route_req_cache, rreq);
		return 1;
	}	

	if (!async_comp) {
		DEBUG("!async_comp free req %p", rreq);
		kmem_cache_free(route_req_cache, rreq);
		return -EWOULDBLOCK;
	}

	req_type = (flags & IB_AT_ROUTE_FORCE_ATS) ?
			IBAT_REQ_ATS : IBAT_REQ_ARP;

	req_init(&rreq->pend, ib_route, 1, req_type, async_comp);

	parent = lookup_pending(&pending_reqs, &rreq->pend,
				req_type, same_route_req);

	if (req_start(&pending_reqs, &rreq->pend, parent))
		resolve_route(rreq);

	return 0;			/* async req */
}
EXPORT_SYMBOL(ib_at_route_by_ip);

int ib_at_paths_by_route(struct ib_at_ib_route *ib_route, u32 mpath_type,
			struct ib_sa_path_rec *path_arr, int npath,
			struct ib_at_completion *async_comp)
{
	struct path_req *preq;
	struct async *parent;
	struct ib_at_dev *ib_dev, *e;
	struct ipoib_dev_priv *priv;
	int found = 0;
	/* int r; */

	if (!ib_route || npath <= 0 || !path_arr)
		return -EINVAL;

	/* If supplied, validate ib_device pointer in supplied ib_route */
	if (ib_route->out_dev) {
		for (ib_dev = ib_at_devs, e = ib_dev + IB_AT_MAX_DEV;
			      ib_dev < e; ib_dev++) {
			if (!ib_dev->netdev || !ib_dev->valid)
				continue;
			priv = ib_dev->netdev->priv;
			if (priv->ca == ib_route->out_dev) {
				found = 1;
				break;
			}
		}
		if (!found)
			return -EINVAL;
	}

	if (!(preq = kmem_cache_alloc(path_req_cache, SLAB_KERNEL)))
		return -ENOMEM;

	preq->rt = *ib_route;

	/* TODO: cache lookup
	if (in_cache) {
		DEBUG("!in_cache free req %p", preq);
		kmem_cache_free(path_req_cache, preq);
		return path_req_output(cached_arr, n, path_arr, npath);
	}
	*/

	/* TODO: resolve outdev if not given
	r = resolve_outdev(&preq->rt);
	if (r < 0) {
		DEBUG("resolve_outdev r < 0 free req %p", preq);
		kmem_cache_free(path_req_cache, preq);
		return r;
	}
	*/

	if (!async_comp) {
		DEBUG("!async_comp free req %p", preq);
		kmem_cache_free(path_req_cache, preq);
		return -EWOULDBLOCK;
	}

	req_init(&preq->pend, path_arr, npath, IBAT_REQ_PATHREC, async_comp);

	parent = lookup_pending(&pending_reqs, &preq->pend,
				IBAT_REQ_PATHREC, same_path_req);

	if (req_start(&pending_reqs, &preq->pend, parent))
		resolve_path(preq, NULL);

	return 0;			/* async req */
}
EXPORT_SYMBOL(ib_at_paths_by_route);

int ib_at_ips_by_gid(union ib_gid *gid, u32 *dst_ips, int nips,
		    struct ib_at_completion *async_comp)
{
	struct ats_ips_req *areq;
	struct async *parent;
	int r;

	if (!gid || !dst_ips || nips <= 0)
		return -EINVAL;

	if (async_comp)
		async_comp->req_id = 0;

	if (!(areq = kmem_cache_alloc(ats_ips_req_cache, SLAB_KERNEL)))
		return -ENOMEM;

	areq->gid = *gid;

	r = resolve_ip(&areq->src, 0, 0, 0, NULL);
	if (r < 0) {
		DEBUG("resolve_ip r < 0 free req %p", areq);
		kmem_cache_free(ats_ips_req_cache, areq);
		return r;
	}

	/* For now, no caching support
	 * 
	 * if (r > 0 && !(flags & IB_AT_ROUTE_FORCE_RESOLVE)) {
	 * 	ats_ips_req_output(areq, xxx, 1, ips, nips);
	 *	DEBUG("ats_ips_req_output free req %p", areq);
	 * 	kmem_cache_free(ats_ips_req_cache, areq);
	 * 	return 1;
	 * }	
	 */

	if (!async_comp) {
		DEBUG("!async_comp free req %p",areq);
		kmem_cache_free(ats_ips_req_cache, areq);
		return -EWOULDBLOCK;
	}

	req_init(&areq->pend, dst_ips, nips, IBAT_REQ_ATSARP, async_comp);

	parent = lookup_pending(&pending_reqs, &areq->pend,
				IBAT_REQ_ATSARP, same_ats_ips_req);

	if (req_start(&pending_reqs, &areq->pend, parent))
		resolve_ats_ips(areq, NULL);

	return 0;			/* async req */
}
EXPORT_SYMBOL(ib_at_ips_by_gid);

int ib_at_ips_by_subnet(u32 network, u32 netmask, u32 *dst_ips, int nips)
{
	return -1;	/* FIXME: not implemented yet */
}
EXPORT_SYMBOL(ib_at_ips_by_subnet);

int ib_at_invalidate_paths(struct ib_at_ib_route *ib_route)
{
	/* Need to validate ib_route->out_dev if supplied */
	return 0;	/* no caching for now */
}
EXPORT_SYMBOL(ib_at_invalidate_paths);

int ib_at_cancel(u64 req_id)
{
	struct async *child, *a = lookup_req_id(&pending_reqs, req_id);
	unsigned long flags;

	if (!a)
		return -1;	/* not found */

	spin_lock_irqsave(&pending_reqs.lock, flags);

	/* Promote first child to be pending req */
	if ((child = a->waiting)) {
		child->parent = NULL;

		/* link child after parent in pending list */
		child->next = a->next;
		child->prev = a;
		a->next->prev = child;
		a->next = child;

		a->waiting = NULL;	/* clear to avoid cancelling children */
	}

	req_end(a, -EINTR, NULL);

	spin_unlock_irqrestore(&pending_reqs.lock, flags);

	return 0;
}
EXPORT_SYMBOL(ib_at_cancel);

int ib_at_status(u64 req_id)
{
	struct async *a = lookup_req_id(&pending_reqs, req_id);

	if (!a)
		return -EINVAL;	/* not found */

	return a->status;
}
EXPORT_SYMBOL(ib_at_status);


/*
 * Internal init/cleanup functions:
 */

static struct packet_type ib_at_arp_type = {
	.type           = __constant_htons(ETH_P_ARP),
	.func           = ib_at_arp_recv,
	.af_packet_priv = (void*) 1, /* understand shared skbs */
};

static struct notifier_block ib_at_netdev_notifier = {
	.notifier_call = inetaddr_event,
};

static struct notifier_block ib_at_inetaddr_notifier = {
	.notifier_call = inetaddr_event,
};

static int ib_at_init(void)
{
	int r = 0;

	DEBUG("IB AT services init");

	/*
	 * init pending lists' dummies.
	 */
	pending_reqs.next = pending_reqs.prev = &pending_reqs;
	spin_lock_init(&pending_reqs.lock);

	/*
	 * Init memory pools
	 */
	route_req_cache = kmem_cache_create("ib_at_routes",
					sizeof (struct route_req),
					0, SLAB_HWCACHE_ALIGN,
					NULL, NULL);
	if (!route_req_cache) {
		WARN("Failed to allocate route requests cache.");
		r = -ENOMEM;
		goto err_route;
	}

	path_req_cache = kmem_cache_create("ib_at_paths",
					sizeof (struct path_req),
					0, SLAB_HWCACHE_ALIGN,
					NULL, NULL);
	if (!path_req_cache) {
		WARN("Failed to allocate path requests cache.");
		r = -ENOMEM;
		goto err_path;
	}

	ats_ips_req_cache = kmem_cache_create("ib_at_ats_ips",
					sizeof (struct ats_ips_req),
					0, SLAB_HWCACHE_ALIGN,
					NULL, NULL);
	if (!ats_ips_req_cache) {
		WARN("Failed to allocate ats_ips requests cache.");
		r = -ENOMEM;
		goto err_ats_ips;
	}

	/*
	 * Init ib at worker thread and queue
	 */
	ib_at_wq = create_workqueue("ib_at_wq");
	if (!ib_at_wq) {
		WARN("Failed to allocate IB AT wait queue.");
		r = -ENOMEM;
		goto err_wq;
	}
	
	INIT_WORK(&ib_at_timer, ib_at_sweep, NULL);
	queue_delayed_work(ib_at_wq, &ib_at_timer, IB_AT_SWEEP_INTERVAL);

	INIT_WORK(&ib_at_ats, ib_at_ats_reg, NULL);
	queue_work(ib_at_wq, &ib_at_ats);

	/*
	 * install device for receiving ARP packets in parallel to the normal
	 * Linux ARP, this will be the notifier that an ARP request has
	 * completed.
	 */
	dev_add_pack(&ib_at_arp_type);

	/*
	 * register notification handlers
	 */
	register_inetaddr_notifier(&ib_at_inetaddr_notifier);
	register_netdevice_notifier(&ib_at_netdev_notifier);

	return 0;

err_wq:
	kmem_cache_destroy(ats_ips_req_cache);

err_ats_ips:
	kmem_cache_destroy(path_req_cache);

err_path:
	kmem_cache_destroy(route_req_cache);

err_route:
	return r;
}
EXPORT_SYMBOL(ib_at_init);

static void ib_at_cleanup(void)
{
	DEBUG("IB AT services cleanup");

	/*
	 * remove ARP packet processing.
	 */
	dev_remove_pack(&ib_at_arp_type);

	/*
	 * remove net devices notification handlers
	 */
	unregister_inetaddr_notifier(&ib_at_inetaddr_notifier);
	unregister_netdevice_notifier(&ib_at_netdev_notifier);

	/*
	 * destroy work queue
	 */
	cancel_delayed_work(&ib_at_timer);
	cancel_delayed_work(&ib_at_ats);
	flush_workqueue(ib_at_wq);
	destroy_workqueue(ib_at_wq);

	/*
	 * clear pending reqs
	 */
	flush_pending(&pending_reqs);
	ib_devs_clean();

	/*
	 * destroy caches
	 */
	kmem_cache_destroy(ats_ips_req_cache);
	kmem_cache_destroy(path_req_cache);
	kmem_cache_destroy(route_req_cache);
}

module_init(ib_at_init);
module_exit(ib_at_cleanup);

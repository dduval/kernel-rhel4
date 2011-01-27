/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2002-2005, Network Appliance, Inc. All rights reserved.
 * Copyright (c) 1999-2005, Mellanox Technologies, Inc. All rights reserved.
 * Copyright (c) 2005-2006 Intel Corporation.  All rights reserved.
 *
 * This Software is licensed under one of the following licenses:
 *
 * 1) under the terms of the "Common Public License 1.0" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/cpl.php.
 *
 * 2) under the terms of the "The BSD License" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/bsd-license.php.
 *
 * 3) under the terms of the "GNU General Public License (GPL) Version 2" a
 *    copy of which is available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/gpl-license.php.
 *
 * Licensee has the right to choose one of the above licenses.
 *
 * Redistributions of source code must retain the above copyright
 * notice and one of the license notices.
 *
 * Redistributions in binary form must reproduce both the above copyright
 * notice, one of the license notices in the documentation
 * and/or other materials provided with the distribution.
 *
 */

#include <linux/completion.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/idr.h>

#include <net/tcp.h>

#include <rdma/rdma_cm.h>
#include <rdma/rdma_cm_ib.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_sa.h>

MODULE_AUTHOR("Sean Hefty");
MODULE_DESCRIPTION("Generic RDMA CM Agent");
MODULE_LICENSE("Dual BSD/GPL");

static int tavor_quirk = 0;
module_param_named(tavor_quirk, tavor_quirk, int, 0644);
MODULE_PARM_DESC(tavor_quirk, "Tavor performance quirk: limit MTU to 1K if > 0");

#define CMA_CM_RESPONSE_TIMEOUT 20

static int CMA_MAX_CM_RETRIES = 15;
module_param_named(max_cm_retries, CMA_MAX_CM_RETRIES, int, 0644);
MODULE_PARM_DESC(max_cm_retries, "How many times to retry a connection attempt");

static void cma_add_one(struct ib_device *device);
static void cma_remove_one(struct ib_device *device);

static struct ib_client cma_client = {
	.name   = "cma",
	.add    = cma_add_one,
	.remove = cma_remove_one
};

static LIST_HEAD(dev_list);
static LIST_HEAD(listen_any_list);
static DEFINE_MUTEX(lock);
static struct workqueue_struct *cma_wq;
static DEFINE_IDR(sdp_ps);
static DEFINE_IDR(tcp_ps);

struct cma_device {
	struct list_head	list;
	struct ib_device	*device;
	__be64			node_guid;
	struct completion	comp;
	atomic_t		refcount;
	struct list_head	id_list;
};

enum cma_state {
	CMA_IDLE,
	CMA_ADDR_QUERY,
	CMA_ADDR_RESOLVED,
	CMA_ROUTE_QUERY,
	CMA_ROUTE_RESOLVED,
	CMA_CONNECT,
	CMA_DISCONNECT,
	CMA_ADDR_BOUND,
	CMA_LISTEN,
	CMA_DEVICE_REMOVAL,
	CMA_DESTROYING
};

struct rdma_bind_list {
	struct idr		*ps;
	struct hlist_head	owners;
	unsigned short		port;
};

/*
 * Device removal can occur at anytime, so we need extra handling to
 * serialize notifying the user of device removal with other callbacks.
 * We do this by disabling removal notification while a callback is in process,
 * and reporting it after the callback completes.
 */
struct rdma_id_private {
	struct rdma_cm_id	id;

	struct rdma_bind_list	*bind_list;
	struct hlist_node	node;
	struct list_head	list;
	struct list_head	listen_list;
	struct cma_device	*cma_dev;

	enum cma_state		state;
	spinlock_t		lock;
	struct completion	comp;
	atomic_t		refcount;
	wait_queue_head_t	wait_remove;
	atomic_t		dev_remove;

	int			backlog;
	int			timeout_ms;
	struct ib_sa_query	*query;
	int			query_id;
	union {
		struct ib_cm_id	*ib;
	} cm_id;

	union {
		struct ib_cm_req_opt *req;
	} options;

	u32			seq_num;
	u32			qp_num;
	enum ib_qp_type		qp_type;
	u8			srq;
};

struct cma_work {
	struct work_struct	work;
	struct rdma_id_private	*id;
	enum cma_state		old_state;
	enum cma_state		new_state;
	struct rdma_cm_event	event;
};

union cma_ip_addr {
	struct in6_addr ip6;
	struct {
		__u32 pad[3];
		__u32 addr;
	} ip4;
};

struct cma_hdr {
	u8 cma_version;
	u8 ip_version;	/* IP version: 7:4 */
	__u16 port;
	union cma_ip_addr src_addr;
	union cma_ip_addr dst_addr;
};

struct sdp_hh {
	u8 bsdh[16];
	u8 sdp_version; /* Major version: 7:4 */
	u8 ip_version;	/* IP version: 7:4 */
	u8 sdp_specific1[10];
	__u16 port;
	__u16 sdp_specific2;
	union cma_ip_addr src_addr;
	union cma_ip_addr dst_addr;
};

struct sdp_hah {
	u8 bsdh[16];
	u8 sdp_version;
};

#define CMA_VERSION 0x00
#define SDP_MAJ_VERSION 0x2

static int cma_comp(struct rdma_id_private *id_priv, enum cma_state comp)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&id_priv->lock, flags);
	ret = (id_priv->state == comp);
	spin_unlock_irqrestore(&id_priv->lock, flags);
	return ret;
}

static int cma_comp_exch(struct rdma_id_private *id_priv,
			 enum cma_state comp, enum cma_state exch)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&id_priv->lock, flags);
	if ((ret = (id_priv->state == comp)))
		id_priv->state = exch;
	spin_unlock_irqrestore(&id_priv->lock, flags);
	return ret;
}

static enum cma_state cma_exch(struct rdma_id_private *id_priv,
			       enum cma_state exch)
{
	unsigned long flags;
	enum cma_state old;

	spin_lock_irqsave(&id_priv->lock, flags);
	old = id_priv->state;
	id_priv->state = exch;
	spin_unlock_irqrestore(&id_priv->lock, flags);
	return old;
}

static inline u8 cma_get_ip_ver(struct cma_hdr *hdr)
{
	return hdr->ip_version >> 4;
}

static inline void cma_set_ip_ver(struct cma_hdr *hdr, u8 ip_ver)
{
	hdr->ip_version = (ip_ver << 4) | (hdr->ip_version & 0xF);
}

static inline u8 sdp_get_majv(u8 sdp_version)
{
	return sdp_version >> 4;
}

static inline u8 sdp_get_ip_ver(struct sdp_hh *hh)
{
	return hh->ip_version >> 4;
}

static inline void sdp_set_ip_ver(struct sdp_hh *hh, u8 ip_ver)
{
	hh->ip_version = (ip_ver << 4) | (hh->ip_version & 0xF);
}

static void cma_attach_to_dev(struct rdma_id_private *id_priv,
			      struct cma_device *cma_dev)
{
	atomic_inc(&cma_dev->refcount);
	id_priv->cma_dev = cma_dev;
	id_priv->id.device = cma_dev->device;
	list_add_tail(&id_priv->list, &cma_dev->id_list);
}

static inline void cma_deref_dev(struct cma_device *cma_dev)
{
	if (atomic_dec_and_test(&cma_dev->refcount))
		complete(&cma_dev->comp);
}

static void cma_detach_from_dev(struct rdma_id_private *id_priv)
{
	list_del(&id_priv->list);
	cma_deref_dev(id_priv->cma_dev);
	id_priv->cma_dev = NULL;
}

static int cma_acquire_ib_dev(struct rdma_id_private *id_priv)
{
	struct cma_device *cma_dev;
	union ib_gid gid;
	int ret = -ENODEV;

	ib_addr_get_sgid(&id_priv->id.route.addr.dev_addr, &gid);


	list_for_each_entry(cma_dev, &dev_list, list) {
		ret = ib_find_cached_gid(cma_dev->device, &gid,
					 &id_priv->id.port_num, NULL);
		if (!ret) {
			cma_attach_to_dev(id_priv, cma_dev);
			break;
		}
	}
	return ret;
}

static int cma_acquire_dev(struct rdma_id_private *id_priv)
{
	switch (id_priv->id.route.addr.dev_addr.dev_type) {
	case IB_NODE_CA:
		return cma_acquire_ib_dev(id_priv);
	default:
		return -ENODEV;
	}
}

static void cma_deref_id(struct rdma_id_private *id_priv)
{
	if (atomic_dec_and_test(&id_priv->refcount))
		complete(&id_priv->comp);
}

static void cma_release_remove(struct rdma_id_private *id_priv)
{
	if (atomic_dec_and_test(&id_priv->dev_remove))
		wake_up(&id_priv->wait_remove);
}

struct rdma_cm_id *rdma_create_id(rdma_cm_event_handler event_handler,
				  void *context, enum rdma_port_space ps)
{
	struct rdma_id_private *id_priv;

	id_priv = kzalloc(sizeof *id_priv, GFP_KERNEL);
	if (!id_priv)
		return ERR_PTR(-ENOMEM);

	id_priv->state = CMA_IDLE;
	id_priv->id.context = context;
	id_priv->id.event_handler = event_handler;
	id_priv->id.ps = ps;
	spin_lock_init(&id_priv->lock);
	init_completion(&id_priv->comp);
	atomic_set(&id_priv->refcount, 1);
	init_waitqueue_head(&id_priv->wait_remove);
	atomic_set(&id_priv->dev_remove, 0);
	INIT_LIST_HEAD(&id_priv->listen_list);
	INIT_LIST_HEAD(&id_priv->list);
	get_random_bytes(&id_priv->seq_num, sizeof id_priv->seq_num);

	return &id_priv->id;
}
EXPORT_SYMBOL(rdma_create_id);

static int cma_init_ib_qp(struct rdma_id_private *id_priv, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	struct rdma_dev_addr *dev_addr;
	int ret;

	dev_addr = &id_priv->id.route.addr.dev_addr;
	ret = ib_find_cached_pkey(id_priv->id.device, id_priv->id.port_num,
				  ib_addr_get_pkey(dev_addr),
				  &qp_attr.pkey_index);
	if (ret)
		return ret;

	qp_attr.qp_state = IB_QPS_INIT;
	qp_attr.qp_access_flags = IB_ACCESS_LOCAL_WRITE;
	qp_attr.port_num = id_priv->id.port_num;
	return ib_modify_qp(qp, &qp_attr, IB_QP_STATE | IB_QP_ACCESS_FLAGS |
					  IB_QP_PKEY_INDEX | IB_QP_PORT);
}

int rdma_create_qp(struct rdma_cm_id *id, struct ib_pd *pd,
		   struct ib_qp_init_attr *qp_init_attr)
{
	struct rdma_id_private *id_priv;
	struct ib_qp *qp;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (id->device != pd->device)
		return -EINVAL;

	qp = ib_create_qp(pd, qp_init_attr);
	if (IS_ERR(qp))
		return PTR_ERR(qp);

	switch (id->device->node_type) {
	case IB_NODE_CA:
		ret = cma_init_ib_qp(id_priv, qp);
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	if (ret)
		goto err;

	id->qp = qp;
	id_priv->qp_num = qp->qp_num;
	id_priv->qp_type = qp->qp_type;
	id_priv->srq = (qp->srq != NULL);
	return 0;
err:
	ib_destroy_qp(qp);
	return ret;
}
EXPORT_SYMBOL(rdma_create_qp);

void rdma_destroy_qp(struct rdma_cm_id *id)
{
	ib_destroy_qp(id->qp);
}
EXPORT_SYMBOL(rdma_destroy_qp);

static int cma_modify_qp_rtr(struct rdma_cm_id *id)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	if (!id->qp)
		return 0;

	/* Need to update QP attributes from default values. */
	qp_attr.qp_state = IB_QPS_INIT;
	ret = rdma_init_qp_attr(id, &qp_attr, &qp_attr_mask);
	if (ret)
		return ret;

	ret = ib_modify_qp(id->qp, &qp_attr, qp_attr_mask);
	if (ret)
		return ret;

	qp_attr.qp_state = IB_QPS_RTR;
	ret = rdma_init_qp_attr(id, &qp_attr, &qp_attr_mask);
	if (ret)
		return ret;

	return ib_modify_qp(id->qp, &qp_attr, qp_attr_mask);
}

static int cma_modify_qp_rts(struct rdma_cm_id *id)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	if (!id->qp)
		return 0;

	qp_attr.qp_state = IB_QPS_RTS;
	ret = rdma_init_qp_attr(id, &qp_attr, &qp_attr_mask);
	if (ret)
		return ret;

	return ib_modify_qp(id->qp, &qp_attr, qp_attr_mask);
}

static int cma_modify_qp_err(struct rdma_cm_id *id)
{
	struct ib_qp_attr qp_attr;

	if (!id->qp)
		return 0;

	qp_attr.qp_state = IB_QPS_ERR;
	return ib_modify_qp(id->qp, &qp_attr, IB_QP_STATE);
}

int rdma_init_qp_attr(struct rdma_cm_id *id, struct ib_qp_attr *qp_attr,
		       int *qp_attr_mask)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	switch (id_priv->id.device->node_type) {
	case IB_NODE_CA:
		ret = ib_cm_init_qp_attr(id_priv->cm_id.ib, qp_attr,
					 qp_attr_mask);
		if (qp_attr->qp_state == IB_QPS_RTR)
			qp_attr->rq_psn = id_priv->seq_num;
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}
EXPORT_SYMBOL(rdma_init_qp_attr);

static inline int cma_zero_addr(struct sockaddr *addr)
{
	struct in6_addr *ip6;

	if (addr->sa_family == AF_INET)
		return ZERONET(((struct sockaddr_in *) addr)->sin_addr.s_addr);
	else {
		ip6 = &((struct sockaddr_in6 *) addr)->sin6_addr;
		return (ip6->s6_addr32[0] | ip6->s6_addr32[1] |
			ip6->s6_addr32[2] | ip6->s6_addr32[3]) == 0;
	}
}

static inline int cma_loopback_addr(struct sockaddr *addr)
{
	return LOOPBACK(((struct sockaddr_in *) addr)->sin_addr.s_addr);
}

static inline int cma_any_addr(struct sockaddr *addr)
{
	return cma_zero_addr(addr) || cma_loopback_addr(addr);
}

static inline int cma_any_port(struct sockaddr *addr)
{
	return !((struct sockaddr_in *) addr)->sin_port;
}

static int cma_get_net_info(void *hdr, enum rdma_port_space ps,
			    u8 *ip_ver, __u16 *port,
			    union cma_ip_addr **src, union cma_ip_addr **dst)
{
	switch (ps) {
	case RDMA_PS_SDP:
		if (sdp_get_majv(((struct sdp_hh *) hdr)->sdp_version) !=
		    SDP_MAJ_VERSION)
			return -EINVAL;

		*ip_ver	= sdp_get_ip_ver(hdr);
		*port	= ((struct sdp_hh *) hdr)->port;
		*src	= &((struct sdp_hh *) hdr)->src_addr;
		*dst	= &((struct sdp_hh *) hdr)->dst_addr;
		break;
	default:
		if (((struct cma_hdr *) hdr)->cma_version != CMA_VERSION)
			return -EINVAL;

		*ip_ver	= cma_get_ip_ver(hdr);
		*port	= ((struct cma_hdr *) hdr)->port;
		*src	= &((struct cma_hdr *) hdr)->src_addr;
		*dst	= &((struct cma_hdr *) hdr)->dst_addr;
		break;
	}

	if (*ip_ver != 4 && *ip_ver != 6)
		return -EINVAL;
	return 0;
}

static void cma_save_net_info(struct rdma_addr *addr,
			      struct rdma_addr *listen_addr,
			      u8 ip_ver, __u16 port,
			      union cma_ip_addr *src, union cma_ip_addr *dst)
{
	struct sockaddr_in *listen4, *ip4;
	struct sockaddr_in6 *listen6, *ip6;

	switch (ip_ver) {
	case 4:
		listen4 = (struct sockaddr_in *) &listen_addr->src_addr;
		ip4 = (struct sockaddr_in *) &addr->src_addr;
		ip4->sin_family = listen4->sin_family;
		ip4->sin_addr.s_addr = dst->ip4.addr;
		ip4->sin_port = listen4->sin_port;

		ip4 = (struct sockaddr_in *) &addr->dst_addr;
		ip4->sin_family = listen4->sin_family;
		ip4->sin_addr.s_addr = src->ip4.addr;
		ip4->sin_port = port;
		break;
	case 6:
		listen6 = (struct sockaddr_in6 *) &listen_addr->src_addr;
		ip6 = (struct sockaddr_in6 *) &addr->src_addr;
		ip6->sin6_family = listen6->sin6_family;
		ip6->sin6_addr = dst->ip6;
		ip6->sin6_port = listen6->sin6_port;

		ip6 = (struct sockaddr_in6 *) &addr->dst_addr;
		ip6->sin6_family = listen6->sin6_family;
		ip6->sin6_addr = src->ip6;
		ip6->sin6_port = port;
		break;
	default:
		break;
	}
}

static inline int cma_user_data_offset(enum rdma_port_space ps)
{
	switch (ps) {
	case RDMA_PS_SDP:
		return 0;
	default:
		return sizeof(struct cma_hdr);
	}
}

static int cma_notify_user(struct rdma_id_private *id_priv,
			   enum rdma_cm_event_type type, int status,
			   void *data, u8 data_len)
{
	struct rdma_cm_event event;

	event.event = type;
	event.status = status;
	event.private_data = data;
	event.private_data_len = data_len;

	return id_priv->id.event_handler(&id_priv->id, &event);
}

static void cma_cancel_route(struct rdma_id_private *id_priv)
{
	switch (id_priv->id.device->node_type) {
	case IB_NODE_CA:
		if (id_priv->query)
			ib_sa_cancel_query(id_priv->query_id, id_priv->query);
		break;
	default:
		break;
	}
}

static inline int cma_internal_listen(struct rdma_id_private *id_priv)
{
	return (id_priv->state == CMA_LISTEN) && id_priv->cma_dev &&
	       cma_any_addr(&id_priv->id.route.addr.src_addr);
}

static void cma_destroy_listen(struct rdma_id_private *id_priv)
{
	cma_exch(id_priv, CMA_DESTROYING);

	if (id_priv->cma_dev) {
		switch (id_priv->id.device->node_type) {
		case IB_NODE_CA:
	 		if (id_priv->cm_id.ib && !IS_ERR(id_priv->cm_id.ib))
				ib_destroy_cm_id(id_priv->cm_id.ib);
			break;
		default:
			break;
		}
		cma_detach_from_dev(id_priv);
	}
	list_del(&id_priv->listen_list);

	cma_deref_id(id_priv);
	wait_for_completion(&id_priv->comp);

	kfree(id_priv);
}

static void cma_cancel_listens(struct rdma_id_private *id_priv)
{
	struct rdma_id_private *dev_id_priv;

	mutex_lock(&lock);
	list_del(&id_priv->list);

	while (!list_empty(&id_priv->listen_list)) {
		dev_id_priv = list_entry(id_priv->listen_list.next,
					 struct rdma_id_private, listen_list);
		cma_destroy_listen(dev_id_priv);
	}
	mutex_unlock(&lock);
}

static void cma_cancel_operation(struct rdma_id_private *id_priv,
				 enum cma_state state)
{
	switch (state) {
	case CMA_ADDR_QUERY:
		rdma_addr_cancel(&id_priv->id.route.addr.dev_addr);
		break;
	case CMA_ROUTE_QUERY:
		cma_cancel_route(id_priv);
		break;
	case CMA_LISTEN:
		if (cma_any_addr(&id_priv->id.route.addr.src_addr) &&
		    !id_priv->cma_dev)
			cma_cancel_listens(id_priv);
		break;
	default:
		break;
	}
}

static void cma_release_port(struct rdma_id_private *id_priv)
{
	struct rdma_bind_list *bind_list = id_priv->bind_list;

	if (!bind_list)
		return;

	mutex_lock(&lock);
	hlist_del(&id_priv->node);
	if (hlist_empty(&bind_list->owners)) {
		idr_remove(bind_list->ps, bind_list->port);
		kfree(bind_list);
	}
	mutex_unlock(&lock);
}

void rdma_destroy_id(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv;
	enum cma_state state;

	id_priv = container_of(id, struct rdma_id_private, id);
	state = cma_exch(id_priv, CMA_DESTROYING);
	cma_cancel_operation(id_priv, state);

	mutex_lock(&lock);
	if (id_priv->cma_dev) {
		mutex_unlock(&lock);
		switch (id->device->node_type) {
		case IB_NODE_CA:
	 		if (id_priv->cm_id.ib && !IS_ERR(id_priv->cm_id.ib))
				ib_destroy_cm_id(id_priv->cm_id.ib);
			break;
		default:
			break;
		}
	  	mutex_lock(&lock);
		cma_detach_from_dev(id_priv);
	}
	mutex_unlock(&lock);

	cma_release_port(id_priv);
	cma_deref_id(id_priv);
	wait_for_completion(&id_priv->comp);

	kfree(id_priv->id.route.path_rec);
	kfree(id_priv->options.req);
	kfree(id_priv);
}
EXPORT_SYMBOL(rdma_destroy_id);

static int cma_rep_recv(struct rdma_id_private *id_priv)
{
	int ret;

	ret = cma_modify_qp_rtr(&id_priv->id);
	if (ret)
		goto reject;

	ret = cma_modify_qp_rts(&id_priv->id);
	if (ret)
		goto reject;

	ret = ib_send_cm_rtu(id_priv->cm_id.ib, NULL, 0);
	if (ret)
		goto reject;

	return 0;
reject:
	cma_modify_qp_err(&id_priv->id);
	ib_send_cm_rej(id_priv->cm_id.ib, IB_CM_REJ_CONSUMER_DEFINED,
		       NULL, 0, NULL, 0);
	return ret;
}

static int cma_verify_rep(struct rdma_id_private *id_priv, void *data)
{
	if (id_priv->id.ps == RDMA_PS_SDP &&
	    sdp_get_majv(((struct sdp_hah *) data)->sdp_version) !=
	    SDP_MAJ_VERSION)
		return -EINVAL;

	return 0;
}

static int cma_ib_handler(struct ib_cm_id *cm_id, struct ib_cm_event *ib_event)
{
	struct rdma_id_private *id_priv = cm_id->context;
	enum rdma_cm_event_type event;
	u8 private_data_len = 0;
	int ret = 0, status = 0;

	atomic_inc(&id_priv->dev_remove);
	if (!cma_comp(id_priv, CMA_CONNECT))
		goto out;

	switch (ib_event->event) {
	case IB_CM_REQ_ERROR:
	case IB_CM_REP_ERROR:
		event = RDMA_CM_EVENT_UNREACHABLE;
		status = -ETIMEDOUT;
		break;
	case IB_CM_REP_RECEIVED:
		status = cma_verify_rep(id_priv, ib_event->private_data);
		if (status)
			event = RDMA_CM_EVENT_CONNECT_ERROR;
		else if (id_priv->id.qp && id_priv->id.ps != RDMA_PS_SDP) {
			status = cma_rep_recv(id_priv);
			event = status ? RDMA_CM_EVENT_CONNECT_ERROR :
					 RDMA_CM_EVENT_ESTABLISHED;
		} else
			event = RDMA_CM_EVENT_CONNECT_RESPONSE;
		private_data_len = IB_CM_REP_PRIVATE_DATA_SIZE;
		break;
	case IB_CM_RTU_RECEIVED:
	case IB_CM_USER_ESTABLISHED:
		event = RDMA_CM_EVENT_ESTABLISHED;
		break;
	case IB_CM_DREQ_ERROR:
		status = -ETIMEDOUT; /* fall through */
	case IB_CM_DREQ_RECEIVED:
	case IB_CM_DREP_RECEIVED:
		if (!cma_comp_exch(id_priv, CMA_CONNECT, CMA_DISCONNECT))
			goto out;
		event = RDMA_CM_EVENT_DISCONNECTED;
		break;
	case IB_CM_TIMEWAIT_EXIT:
	case IB_CM_MRA_RECEIVED:
		/* ignore event */
		goto out;
	case IB_CM_REJ_RECEIVED:
		cma_modify_qp_err(&id_priv->id);
		status = ib_event->param.rej_rcvd.reason;
		event = RDMA_CM_EVENT_REJECTED;
		private_data_len = IB_CM_REJ_PRIVATE_DATA_SIZE;
		break;
	default:
		printk(KERN_ERR "RDMA CMA: unexpected IB CM event: %d",
		       ib_event->event);
		goto out;
	}

	ret = cma_notify_user(id_priv, event, status, ib_event->private_data,
			      private_data_len);
	if (ret) {
		/* Destroy the CM ID by returning a non-zero value. */
		id_priv->cm_id.ib = NULL;
		cma_exch(id_priv, CMA_DESTROYING);
		cma_release_remove(id_priv);
		rdma_destroy_id(&id_priv->id);
		return ret;
	}
out:
	cma_release_remove(id_priv);
	return ret;
}

static struct rdma_id_private *cma_new_id(struct rdma_cm_id *listen_id,
					  struct ib_cm_event *ib_event)
{
	struct rdma_id_private *id_priv;
	struct rdma_cm_id *id;
	struct rdma_route *rt;
	union cma_ip_addr *src, *dst;
	__u16 port;
	u8 ip_ver;

	id = rdma_create_id(listen_id->event_handler, listen_id->context,
			    listen_id->ps);
	if (IS_ERR(id))
		return NULL;

	rt = &id->route;
	rt->num_paths = ib_event->param.req_rcvd.alternate_path ? 2 : 1;
	rt->path_rec = kmalloc(sizeof *rt->path_rec * rt->num_paths, GFP_KERNEL);
	if (!rt->path_rec)
		goto err;

	if (cma_get_net_info(ib_event->private_data, listen_id->ps,
			     &ip_ver, &port, &src, &dst))
		goto err;

	cma_save_net_info(&id->route.addr, &listen_id->route.addr,
			  ip_ver, port, src, dst);
	rt->path_rec[0] = *ib_event->param.req_rcvd.primary_path;
	if (rt->num_paths == 2)
		rt->path_rec[1] = *ib_event->param.req_rcvd.alternate_path;

	ib_addr_set_sgid(&rt->addr.dev_addr, &rt->path_rec[0].sgid);
	ib_addr_set_dgid(&rt->addr.dev_addr, &rt->path_rec[0].dgid);
	ib_addr_set_pkey(&rt->addr.dev_addr, be16_to_cpu(rt->path_rec[0].pkey));
	rt->addr.dev_addr.dev_type = IB_NODE_CA;

	id_priv = container_of(id, struct rdma_id_private, id);
	id_priv->state = CMA_CONNECT;
	return id_priv;
err:
	rdma_destroy_id(id);
	return NULL;
}

static int cma_req_handler(struct ib_cm_id *cm_id, struct ib_cm_event *ib_event)
{
	struct rdma_id_private *listen_id, *conn_id;
	int offset, ret;

	listen_id = cm_id->context;
	atomic_inc(&listen_id->dev_remove);
	if (!cma_comp(listen_id, CMA_LISTEN)) {
		ret = -ECONNABORTED;
		goto out;
	}

	conn_id = cma_new_id(&listen_id->id, ib_event);
	if (!conn_id) {
		ret = -ENOMEM;
		goto out;
	}

	atomic_inc(&conn_id->dev_remove);
	mutex_lock(&lock);
	ret = cma_acquire_ib_dev(conn_id);
	mutex_unlock(&lock);
	if (ret) {
		ret = -ENODEV;
		cma_exch(conn_id, CMA_DESTROYING);
		cma_release_remove(conn_id);
		rdma_destroy_id(&conn_id->id);
		goto out;
	}

	conn_id->cm_id.ib = cm_id;
	cm_id->context = conn_id;
	cm_id->cm_handler = cma_ib_handler;

	offset = cma_user_data_offset(listen_id->id.ps);
	ret = cma_notify_user(conn_id, RDMA_CM_EVENT_CONNECT_REQUEST, 0,
			      ib_event->private_data + offset,
			      IB_CM_REQ_PRIVATE_DATA_SIZE - offset);
	if (ret) {
		/* Destroy the CM ID by returning a non-zero value. */
		conn_id->cm_id.ib = NULL;
		cma_exch(conn_id, CMA_DESTROYING);
		cma_release_remove(conn_id);
		rdma_destroy_id(&conn_id->id);
	}
out:
	cma_release_remove(listen_id);
	return ret;
}

static __be64 cma_get_service_id(enum rdma_port_space ps, struct sockaddr *addr)
{
	return cpu_to_be64(((u64)ps << 16) +
	       be16_to_cpu(((struct sockaddr_in *) addr)->sin_port));
}

static void cma_set_compare_data(enum rdma_port_space ps, struct sockaddr *addr,
				 struct ib_cm_compare_data *compare)
{
	struct cma_hdr *cma_data, *cma_mask;
	struct sdp_hh *sdp_data, *sdp_mask;
	__u32 ip4_addr;
	struct in6_addr ip6_addr;

	memset(compare, 0, sizeof *compare);
	cma_data = (void *) compare->data;
	cma_mask = (void *) compare->mask;
	sdp_data = (void *) compare->data;
	sdp_mask = (void *) compare->mask;

	switch (addr->sa_family) {
	case AF_INET:
		ip4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
		if (ps == RDMA_PS_SDP) {
			sdp_set_ip_ver(sdp_data, 4);
			sdp_set_ip_ver(sdp_mask, 0xF);
			sdp_data->dst_addr.ip4.addr = ip4_addr;
			sdp_mask->dst_addr.ip4.addr = ~0;
		} else {
			cma_set_ip_ver(cma_data, 4);
			cma_set_ip_ver(cma_mask, 0xF);
			cma_data->dst_addr.ip4.addr = ip4_addr;
			cma_mask->dst_addr.ip4.addr = ~0;
		}
		break;
	case AF_INET6:
		ip6_addr = ((struct sockaddr_in6 *) addr)->sin6_addr;
		if (ps == RDMA_PS_SDP) {
			sdp_set_ip_ver(sdp_data, 6);
			sdp_set_ip_ver(sdp_mask, 0xF);
			sdp_data->dst_addr.ip6 = ip6_addr;
			memset(&sdp_mask->dst_addr.ip6, 0xFF,
			       sizeof sdp_mask->dst_addr.ip6);
		} else {
			cma_set_ip_ver(cma_data, 6);
			cma_set_ip_ver(cma_mask, 0xF);
			cma_data->dst_addr.ip6 = ip6_addr;
			memset(&cma_mask->dst_addr.ip6, 0xFF,
			       sizeof cma_mask->dst_addr.ip6);
		}
		break;
	default:
		break;
	}
}

static int cma_ib_listen(struct rdma_id_private *id_priv)
{
	struct ib_cm_compare_data compare_data;
	struct sockaddr *addr;
	__be64 svc_id;
	int ret;

	id_priv->cm_id.ib = ib_create_cm_id(id_priv->id.device, cma_req_handler,
					    id_priv);
	if (IS_ERR(id_priv->cm_id.ib))
		return PTR_ERR(id_priv->cm_id.ib);

	addr = &id_priv->id.route.addr.src_addr;
	svc_id = cma_get_service_id(id_priv->id.ps, addr);
	if (cma_any_addr(addr))
		ret = ib_cm_listen(id_priv->cm_id.ib, svc_id, 0, NULL);
	else {
		cma_set_compare_data(id_priv->id.ps, addr, &compare_data);
		ret = ib_cm_listen(id_priv->cm_id.ib, svc_id, 0, &compare_data);
	}

	if (ret) {
		ib_destroy_cm_id(id_priv->cm_id.ib);
		id_priv->cm_id.ib = NULL;
	}

	return ret;
}

static int cma_listen_handler(struct rdma_cm_id *id,
			      struct rdma_cm_event *event)
{
	struct rdma_id_private *id_priv = id->context;

	id->context = id_priv->id.context;
	id->event_handler = id_priv->id.event_handler;
	return id_priv->id.event_handler(id, event);
}

static void cma_listen_on_dev(struct rdma_id_private *id_priv,
			      struct cma_device *cma_dev)
{
	struct rdma_id_private *dev_id_priv;
	struct rdma_cm_id *id;
	int ret;

	id = rdma_create_id(cma_listen_handler, id_priv, id_priv->id.ps);
	if (IS_ERR(id))
		return;

	dev_id_priv = container_of(id, struct rdma_id_private, id);

	dev_id_priv->state = CMA_ADDR_BOUND;
	memcpy(&id->route.addr.src_addr, &id_priv->id.route.addr.src_addr,
	       ip_addr_size(&id_priv->id.route.addr.src_addr));

	cma_attach_to_dev(dev_id_priv, cma_dev);
	list_add_tail(&dev_id_priv->listen_list, &id_priv->listen_list);

	ret = rdma_listen(id, id_priv->backlog);
	if (ret)
		goto err;

	return;
err:
	cma_destroy_listen(dev_id_priv);
}

static void cma_listen_on_all(struct rdma_id_private *id_priv)
{
	struct cma_device *cma_dev;

	mutex_lock(&lock);
	list_add_tail(&id_priv->list, &listen_any_list);
	list_for_each_entry(cma_dev, &dev_list, list)
		cma_listen_on_dev(id_priv, cma_dev);
	mutex_unlock(&lock);
}

static int cma_bind_any(struct rdma_cm_id *id, sa_family_t af)
{
	struct sockaddr_in addr_in;

	memset(&addr_in, 0, sizeof addr_in);
	addr_in.sin_family = af;
	return rdma_bind_addr(id, (struct sockaddr *) &addr_in);
}

int rdma_listen(struct rdma_cm_id *id, int backlog)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (id_priv->state == CMA_IDLE) {
		ret = cma_bind_any(id, AF_INET);
		if (ret)
			return ret;
	}

	if (!cma_comp_exch(id_priv, CMA_ADDR_BOUND, CMA_LISTEN))
		return -EINVAL;

	id_priv->backlog = backlog;
	if (id->device) {
		switch (id->device->node_type) {
		case IB_NODE_CA:
			ret = cma_ib_listen(id_priv);
			if (ret)
				goto err;
			break;
		default:
			ret = -ENOSYS;
			goto err;
		}
	} else
		cma_listen_on_all(id_priv);

	return 0;
err:
	id_priv->backlog = 0;
	cma_comp_exch(id_priv, CMA_LISTEN, CMA_ADDR_BOUND);
	return ret;
}
EXPORT_SYMBOL(rdma_listen);

static void cma_query_handler(int status, struct ib_sa_path_rec *path_rec,
			      void *context)
{
	struct cma_work *work = context;
	struct rdma_route *route;

	route = &work->id->id.route;

	if (!status) {
		route->num_paths = 1;
		*route->path_rec = *path_rec;
	} else {
		work->old_state = CMA_ROUTE_QUERY;
		work->new_state = CMA_ADDR_RESOLVED;
		work->event.event = RDMA_CM_EVENT_ROUTE_ERROR;
	}

	queue_work(cma_wq, &work->work);
}

static int cma_query_ib_route(struct rdma_id_private *id_priv, int timeout_ms,
			      struct cma_work *work)
{
	struct rdma_dev_addr *addr = &id_priv->id.route.addr.dev_addr;
	struct ib_sa_path_rec path_rec;

	memset(&path_rec, 0, sizeof path_rec);
	ib_addr_get_sgid(addr, &path_rec.sgid);
	ib_addr_get_dgid(addr, &path_rec.dgid);
	path_rec.pkey = cpu_to_be16(ib_addr_get_pkey(addr));
	path_rec.numb_path = 1;

	if (tavor_quirk) {
		path_rec.mtu_selector = IB_SA_LT;
		path_rec.mtu = IB_MTU_2048;
	}

	id_priv->query_id = ib_sa_path_rec_get(id_priv->id.device,
				id_priv->id.port_num, &path_rec,
				IB_SA_PATH_REC_DGID | IB_SA_PATH_REC_SGID |
				IB_SA_PATH_REC_PKEY | IB_SA_PATH_REC_NUMB_PATH,
				timeout_ms, GFP_KERNEL,
				cma_query_handler, work, &id_priv->query);

	return (id_priv->query_id < 0) ? id_priv->query_id : 0;
}

static void cma_work_handler(void *data)
{
	struct cma_work *work = data;
	struct rdma_id_private *id_priv = work->id;
	int destroy = 0;

	atomic_inc(&id_priv->dev_remove);
	if (!cma_comp_exch(id_priv, work->old_state, work->new_state))
		goto out;

	if (id_priv->id.event_handler(&id_priv->id, &work->event)) {
		cma_exch(id_priv, CMA_DESTROYING);
		destroy = 1;
	}
out:
	cma_release_remove(id_priv);
	cma_deref_id(id_priv);
	if (destroy)
		rdma_destroy_id(&id_priv->id);
	kfree(work);
}

static int cma_resolve_ib_route(struct rdma_id_private *id_priv, int timeout_ms)
{
	struct rdma_route *route = &id_priv->id.route;
	struct cma_work *work;
	int ret;

	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	work->id = id_priv;
	INIT_WORK(&work->work, cma_work_handler, work);
	work->old_state = CMA_ROUTE_QUERY;
	work->new_state = CMA_ROUTE_RESOLVED;
	work->event.event = RDMA_CM_EVENT_ROUTE_RESOLVED;

	route->path_rec = kmalloc(sizeof *route->path_rec, GFP_KERNEL);
	if (!route->path_rec) {
		ret = -ENOMEM;
		goto err1;
	}

	ret = cma_query_ib_route(id_priv, timeout_ms, work);
	if (ret)
		goto err2;

	return 0;
err2:
	kfree(route->path_rec);
	route->path_rec = NULL;
err1:
	kfree(work);
	return ret;
}

int rdma_set_ib_paths(struct rdma_cm_id *id,
		      struct ib_sa_path_rec *path_rec, int num_paths)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp_exch(id_priv, CMA_ADDR_RESOLVED, CMA_ROUTE_RESOLVED))
		return -EINVAL;

	id->route.path_rec = kmalloc(sizeof *path_rec * num_paths, GFP_KERNEL);
	if (!id->route.path_rec) {
		ret = -ENOMEM;
		goto err;
	}

	memcpy(id->route.path_rec, path_rec, sizeof *path_rec * num_paths);
	return 0;
err:
	cma_comp_exch(id_priv, CMA_ROUTE_RESOLVED, CMA_ADDR_RESOLVED);
	return ret;
}
EXPORT_SYMBOL(rdma_set_ib_paths);

static inline u8 cma_get_ib_remote_timeout(struct rdma_id_private *id_priv)
{
	return	id_priv->options.req ?
		id_priv->options.req->remote_cm_response_timeout :
		CMA_CM_RESPONSE_TIMEOUT;
}

static inline u8 cma_get_ib_local_timeout(struct rdma_id_private *id_priv)
{
	return	id_priv->options.req ?
		id_priv->options.req->local_cm_response_timeout :
		CMA_CM_RESPONSE_TIMEOUT;
}

static inline u8 cma_get_ib_cm_retries(struct rdma_id_private *id_priv)
{
	return	id_priv->options.req ?
		id_priv->options.req->max_cm_retries : CMA_MAX_CM_RETRIES;
}

int rdma_get_ib_req_info(struct rdma_cm_id *id, struct ib_cm_req_opt *info)
{
	struct rdma_id_private *id_priv;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp(id_priv, CMA_ROUTE_RESOLVED))
		return -EINVAL;

	info->remote_cm_response_timeout = cma_get_ib_remote_timeout(id_priv);
	info->local_cm_response_timeout = cma_get_ib_local_timeout(id_priv);
	info->max_cm_retries = cma_get_ib_cm_retries(id_priv);
	return 0;
}
EXPORT_SYMBOL(rdma_get_ib_req_info);

int rdma_set_ib_req_info(struct rdma_cm_id *id, struct ib_cm_req_opt *info)
{
	struct rdma_id_private *id_priv;

	if (info->remote_cm_response_timeout > 0x1F ||
	    info->local_cm_response_timeout > 0x1F ||
	    info->max_cm_retries > 0xF)
		return -EINVAL;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp(id_priv, CMA_ROUTE_RESOLVED))
		return -EINVAL;

	if (!id_priv->options.req) {
		id_priv->options.req = kmalloc(sizeof *info, GFP_KERNEL);
		if (!id_priv->options.req)
			return -ENOMEM;
	}

	*id_priv->options.req = *info;
	return 0;
}
EXPORT_SYMBOL(rdma_set_ib_req_info);

int rdma_resolve_route(struct rdma_cm_id *id, int timeout_ms)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp_exch(id_priv, CMA_ADDR_RESOLVED, CMA_ROUTE_QUERY))
		return -EINVAL;

	atomic_inc(&id_priv->refcount);
	switch (id->device->node_type) {
	case IB_NODE_CA:
		ret = cma_resolve_ib_route(id_priv, timeout_ms);
		break;
	default:
		ret = -ENOSYS;
		break;
	}
	if (ret)
		goto err;

	return 0;
err:
	cma_comp_exch(id_priv, CMA_ROUTE_QUERY, CMA_ADDR_RESOLVED);
	cma_deref_id(id_priv);
	return ret;
}
EXPORT_SYMBOL(rdma_resolve_route);

static int cma_bind_loopback(struct rdma_id_private *id_priv)
{
	struct cma_device *cma_dev;
	struct ib_port_attr port_attr;
	union ib_gid gid;
	u16 pkey;
	int ret;
	u8 p;

	mutex_lock(&lock);
	list_for_each_entry(cma_dev, &dev_list, list)
		for (p = 1; p <= cma_dev->device->phys_port_cnt; ++p)
			if (!ib_query_port (cma_dev->device, p, &port_attr) &&
			    port_attr.state == IB_PORT_ACTIVE)
				goto port_found;

	if (!list_empty(&dev_list)) {
		p = 1;
		cma_dev = list_entry(dev_list.next, struct cma_device, list);
	} else {
		ret = -ENODEV;
		goto out;
	}

port_found:
	ret = ib_get_cached_gid(cma_dev->device, p, 0, &gid);
	if (ret)
		goto out;

	ret = ib_get_cached_pkey(cma_dev->device, p, 0, &pkey);
	if (ret)
		goto out;

	ib_addr_set_sgid(&id_priv->id.route.addr.dev_addr, &gid);
	ib_addr_set_pkey(&id_priv->id.route.addr.dev_addr, pkey);
	id_priv->id.port_num = p;
	cma_attach_to_dev(id_priv, cma_dev);
out:
	mutex_unlock(&lock);
	return ret;
}

static void addr_handler(int status, struct sockaddr *src_addr,
			 struct rdma_dev_addr *dev_addr, void *context)
{
	struct rdma_id_private *id_priv = context;
	enum rdma_cm_event_type event;

	atomic_inc(&id_priv->dev_remove);

	/*
	 * Grab mutex to block rdma_destroy_id() from removing the device while
	 * we're trying to acquire it.
	 */
	mutex_lock(&lock);
	if (!cma_comp_exch(id_priv, CMA_ADDR_QUERY, CMA_ADDR_RESOLVED)) {
		mutex_unlock(&lock);
		goto out;
	}

	if (!status && !id_priv->cma_dev)
		status = cma_acquire_dev(id_priv);
	mutex_unlock(&lock);

	if (status) {
		if (!cma_comp_exch(id_priv, CMA_ADDR_RESOLVED, CMA_ADDR_BOUND))
			goto out;
		event = RDMA_CM_EVENT_ADDR_ERROR;
	} else {
		memcpy(&id_priv->id.route.addr.src_addr, src_addr,
		       ip_addr_size(src_addr));
		event = RDMA_CM_EVENT_ADDR_RESOLVED;
	}

	if (cma_notify_user(id_priv, event, status, NULL, 0)) {
		cma_exch(id_priv, CMA_DESTROYING);
		cma_release_remove(id_priv);
		cma_deref_id(id_priv);
		rdma_destroy_id(&id_priv->id);
		return;
	}
out:
	cma_release_remove(id_priv);
	cma_deref_id(id_priv);
}

static int cma_resolve_loopback(struct rdma_id_private *id_priv)
{
	struct cma_work *work;
	struct sockaddr_in *src_in, *dst_in;
	union ib_gid gid;
	int ret;

	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	if (!id_priv->cma_dev) {
		ret = cma_bind_loopback(id_priv);
		if (ret)
			goto err;
	}

	ib_addr_get_sgid(&id_priv->id.route.addr.dev_addr, &gid);
	ib_addr_set_dgid(&id_priv->id.route.addr.dev_addr, &gid);

	if (cma_zero_addr(&id_priv->id.route.addr.src_addr)) {
		src_in = (struct sockaddr_in *)&id_priv->id.route.addr.src_addr;
		dst_in = (struct sockaddr_in *)&id_priv->id.route.addr.dst_addr;
		src_in->sin_family = dst_in->sin_family;
		src_in->sin_addr.s_addr = dst_in->sin_addr.s_addr;
	}

	work->id = id_priv;
	INIT_WORK(&work->work, cma_work_handler, work);
	work->old_state = CMA_ADDR_QUERY;
	work->new_state = CMA_ADDR_RESOLVED;
	work->event.event = RDMA_CM_EVENT_ADDR_RESOLVED;
	queue_work(cma_wq, &work->work);
	return 0;
err:
	kfree(work);
	return ret;
}

static int cma_bind_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
			 struct sockaddr *dst_addr)
{
	if (src_addr && src_addr->sa_family)
		return rdma_bind_addr(id, src_addr);
	else
		return cma_bind_any(id, dst_addr->sa_family);
}

int rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      struct sockaddr *dst_addr, int timeout_ms)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (id_priv->state == CMA_IDLE) {
		ret = cma_bind_addr(id, src_addr, dst_addr);
		if (ret)
			return ret;
	}

	if (!cma_comp_exch(id_priv, CMA_ADDR_BOUND, CMA_ADDR_QUERY))
		return -EINVAL;

	atomic_inc(&id_priv->refcount);
	memcpy(&id->route.addr.dst_addr, dst_addr, ip_addr_size(dst_addr));
	if (cma_any_addr(dst_addr))
		ret = cma_resolve_loopback(id_priv);
	else
		ret = rdma_resolve_ip(&id->route.addr.src_addr, dst_addr,
				      &id->route.addr.dev_addr,
				      timeout_ms, addr_handler, id_priv);
	if (ret)
		goto err;

	return 0;
err:
	cma_comp_exch(id_priv, CMA_ADDR_QUERY, CMA_ADDR_BOUND);
	cma_deref_id(id_priv);
	return ret;
}
EXPORT_SYMBOL(rdma_resolve_addr);

static void cma_bind_port(struct rdma_bind_list *bind_list,
			  struct rdma_id_private *id_priv)
{
	struct sockaddr_in *sin;

	sin = (struct sockaddr_in *) &id_priv->id.route.addr.src_addr;
	sin->sin_port = htons(bind_list->port);
	id_priv->bind_list = bind_list;
	hlist_add_head(&id_priv->node, &bind_list->owners);
}

static int cma_alloc_port(struct idr *ps, struct rdma_id_private *id_priv,
			  unsigned short snum)
{
	struct rdma_bind_list *bind_list;
	int port, start, ret;

	bind_list = kzalloc(sizeof *bind_list, GFP_KERNEL);
	if (!bind_list)
		return -ENOMEM;

	start = snum ? snum : sysctl_local_port_range[0];

	do {
		ret = idr_get_new_above(ps, bind_list, start, &port);
	} while ((ret == -EAGAIN) && idr_pre_get(ps, GFP_KERNEL));

	if (ret)
		goto err;

	if ((snum && port != snum) ||
	    (!snum && port > sysctl_local_port_range[1])) {
		idr_remove(ps, port);
		ret = -EADDRNOTAVAIL;
		goto err;
	}

	bind_list->ps = ps;
	bind_list->port = (unsigned short) port;
	cma_bind_port(bind_list, id_priv);
	return 0;
err:
	kfree(bind_list);
	return ret;
}

static int cma_use_port(struct idr *ps, struct rdma_id_private *id_priv)
{
	struct rdma_id_private *cur_id;
	struct sockaddr_in *sin, *cur_sin;
	struct rdma_bind_list *bind_list;
	struct hlist_node *node;
	unsigned short snum;

	sin = (struct sockaddr_in *) &id_priv->id.route.addr.src_addr;
	snum = ntohs(sin->sin_port);
	if (snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		return -EACCES;

	bind_list = idr_find(ps, snum);
	if (!bind_list)
		return cma_alloc_port(ps, id_priv, snum);

	/*
	 * We don't support binding to any address if anyone is bound to
	 * a specific address on the same port.
	 */
	if (cma_any_addr(&id_priv->id.route.addr.src_addr))
		return -EADDRNOTAVAIL;

	hlist_for_each_entry(cur_id, node, &bind_list->owners, node) {
		if (cma_any_addr(&cur_id->id.route.addr.src_addr))
			return -EADDRNOTAVAIL;
		
		cur_sin = (struct sockaddr_in *) &cur_id->id.route.addr.src_addr;
		if (sin->sin_addr.s_addr == cur_sin->sin_addr.s_addr)
			return -EADDRINUSE;
	}

	cma_bind_port(bind_list, id_priv);
	return 0;
}

static int cma_get_port(struct rdma_id_private *id_priv)
{
	struct idr *ps;
	int ret;

	switch (id_priv->id.ps) {
	case RDMA_PS_SDP:
		ps = &sdp_ps;
		break;
	case RDMA_PS_TCP:
		ps = &tcp_ps;
		break;
	default:
		return -EPROTONOSUPPORT;
	}

	mutex_lock(&lock);
	if (cma_any_port(&id_priv->id.route.addr.src_addr))
		ret = cma_alloc_port(ps, id_priv, 0);
	else
		ret = cma_use_port(ps, id_priv);
	mutex_unlock(&lock);

	return ret;
}

int rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr)
{
	struct rdma_id_private *id_priv;
	int ret;

	if (addr->sa_family != AF_INET)
		return -EAFNOSUPPORT;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp_exch(id_priv, CMA_IDLE, CMA_ADDR_BOUND))
		return -EINVAL;

	if (!cma_any_addr(addr)) {
		ret = rdma_translate_ip(addr, &id->route.addr.dev_addr);
		if (!ret) {
			mutex_lock(&lock);
			ret = cma_acquire_dev(id_priv);
			mutex_unlock(&lock);
		}
		if (ret)
			goto err;
	}

	memcpy(&id->route.addr.src_addr, addr, ip_addr_size(addr));
	ret = cma_get_port(id_priv);
	if (ret)
		goto err;

	return 0;
err:
	cma_comp_exch(id_priv, CMA_ADDR_BOUND, CMA_IDLE);
	return ret;
}
EXPORT_SYMBOL(rdma_bind_addr);

static int cma_format_hdr(void *hdr, enum rdma_port_space ps,
			  struct rdma_route *route)
{
	struct sockaddr_in *src4, *dst4;
	struct cma_hdr *cma_hdr;
	struct sdp_hh *sdp_hdr;

	src4 = (struct sockaddr_in *) &route->addr.src_addr;
	dst4 = (struct sockaddr_in *) &route->addr.dst_addr;

	switch (ps) {
	case RDMA_PS_SDP:
		sdp_hdr = hdr;
		if (sdp_get_majv(sdp_hdr->sdp_version) != SDP_MAJ_VERSION)
			return -EINVAL;
		sdp_set_ip_ver(sdp_hdr, 4);
		sdp_hdr->src_addr.ip4.addr = src4->sin_addr.s_addr;
		sdp_hdr->dst_addr.ip4.addr = dst4->sin_addr.s_addr;
		sdp_hdr->port = src4->sin_port;
		break;
	default:
		cma_hdr = hdr;
		cma_hdr->cma_version = CMA_VERSION;
		cma_set_ip_ver(cma_hdr, 4);
		cma_hdr->src_addr.ip4.addr = src4->sin_addr.s_addr;
		cma_hdr->dst_addr.ip4.addr = dst4->sin_addr.s_addr;
		cma_hdr->port = src4->sin_port;
		break;
	}
	return 0;
}

static int cma_connect_ib(struct rdma_id_private *id_priv,
			  struct rdma_conn_param *conn_param)
{
	struct ib_cm_req_param req;
	struct rdma_route *route;
	void *private_data;
	int offset, ret;

	memset(&req, 0, sizeof req);
	offset = cma_user_data_offset(id_priv->id.ps);
	req.private_data_len = offset + conn_param->private_data_len;
	private_data = kzalloc(req.private_data_len, GFP_ATOMIC);
	if (!private_data)
		return -ENOMEM;

	if (conn_param->private_data && conn_param->private_data_len)
		memcpy(private_data + offset, conn_param->private_data,
		       conn_param->private_data_len);

	id_priv->cm_id.ib = ib_create_cm_id(id_priv->id.device, cma_ib_handler,
					    id_priv);
	if (IS_ERR(id_priv->cm_id.ib)) {
		ret = PTR_ERR(id_priv->cm_id.ib);
		goto out;
	}

	route = &id_priv->id.route;
	ret = cma_format_hdr(private_data, id_priv->id.ps, route);
	if (ret)
		goto out;
	req.private_data = private_data;

	req.primary_path = &route->path_rec[0];
	if (route->num_paths == 2)
		req.alternate_path = &route->path_rec[1];

	req.service_id = cma_get_service_id(id_priv->id.ps,
					    &route->addr.dst_addr);
	req.qp_num = id_priv->qp_num;
	req.qp_type = id_priv->qp_type;
	req.starting_psn = id_priv->seq_num;
	req.responder_resources = conn_param->responder_resources;
	req.initiator_depth = conn_param->initiator_depth;
	req.flow_control = conn_param->flow_control;
	req.retry_count = conn_param->retry_count;
	req.rnr_retry_count = conn_param->rnr_retry_count;
	req.remote_cm_response_timeout = cma_get_ib_remote_timeout(id_priv);
	req.local_cm_response_timeout = cma_get_ib_local_timeout(id_priv);
	req.max_cm_retries = cma_get_ib_cm_retries(id_priv);
	req.srq = id_priv->srq ? 1 : 0;

	ret = ib_send_cm_req(id_priv->cm_id.ib, &req);
out:
	if (ret && !IS_ERR(id_priv->cm_id.ib)) {
		ib_destroy_cm_id(id_priv->cm_id.ib);
		id_priv->cm_id.ib = NULL;
	}

	kfree(private_data);
	return ret;
}

int rdma_connect(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp_exch(id_priv, CMA_ROUTE_RESOLVED, CMA_CONNECT))
		return -EINVAL;

	if (!id->qp) {
		id_priv->qp_num = conn_param->qp_num;
		id_priv->qp_type = conn_param->qp_type;
		id_priv->srq = conn_param->srq;
	}

	switch (id->device->node_type) {
	case IB_NODE_CA:
		ret = cma_connect_ib(id_priv, conn_param);
		break;
	default:
		ret = -ENOSYS;
		break;
	}
	if (ret)
		goto err;

	return 0;
err:
	cma_comp_exch(id_priv, CMA_CONNECT, CMA_ROUTE_RESOLVED);
	return ret;
}
EXPORT_SYMBOL(rdma_connect);

static int cma_accept_ib(struct rdma_id_private *id_priv,
			 struct rdma_conn_param *conn_param)
{
	struct ib_cm_rep_param rep;
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	if (id_priv->id.qp) {
		ret = cma_modify_qp_rtr(&id_priv->id);
		if (ret)
			goto out;

		qp_attr.qp_state = IB_QPS_RTS;
		ret = ib_cm_init_qp_attr(id_priv->cm_id.ib, &qp_attr,
					 &qp_attr_mask);
		if (ret)
			goto out;

		qp_attr.max_rd_atomic = conn_param->initiator_depth;
		ret = ib_modify_qp(id_priv->id.qp, &qp_attr, qp_attr_mask);
		if (ret)
			goto out;
	}

	memset(&rep, 0, sizeof rep);
	rep.qp_num = id_priv->qp_num;
	rep.starting_psn = id_priv->seq_num;
	rep.private_data = conn_param->private_data;
	rep.private_data_len = conn_param->private_data_len;
	rep.responder_resources = conn_param->responder_resources;
	rep.initiator_depth = conn_param->initiator_depth;
	rep.target_ack_delay = cma_get_ib_local_timeout(id_priv);
	rep.failover_accepted = 0;
	rep.flow_control = conn_param->flow_control;
	rep.rnr_retry_count = conn_param->rnr_retry_count;
	rep.srq = id_priv->srq ? 1 : 0;

	ret = ib_send_cm_rep(id_priv->cm_id.ib, &rep);
out:
	return ret;
}

int rdma_accept(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp(id_priv, CMA_CONNECT))
		return -EINVAL;

	if (!id->qp && conn_param) {
		id_priv->qp_num = conn_param->qp_num;
		id_priv->qp_type = conn_param->qp_type;
		id_priv->srq = conn_param->srq;
	}

	switch (id->device->node_type) {
	case IB_NODE_CA:
		if (conn_param)
			ret = cma_accept_ib(id_priv, conn_param);
		else
			ret = cma_rep_recv(id_priv);
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	if (ret)
		goto reject;

	return 0;
reject:
	cma_modify_qp_err(id);
	rdma_reject(id, NULL, 0);
	return ret;
}
EXPORT_SYMBOL(rdma_accept);

int rdma_establish(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp(id_priv, CMA_CONNECT))
		return -EINVAL;

	switch (id->device->node_type) {
	case IB_NODE_CA:
		ret = ib_cm_establish(id_priv->cm_id.ib);
		break;
	default:
		ret = 0;
		break;
	}
	return ret;
}
EXPORT_SYMBOL(rdma_establish);

int rdma_reject(struct rdma_cm_id *id, const void *private_data,
		u8 private_data_len)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp(id_priv, CMA_CONNECT))
		return -EINVAL;

	switch (id->device->node_type) {
	case IB_NODE_CA:
		ret = ib_send_cm_rej(id_priv->cm_id.ib,
				     IB_CM_REJ_CONSUMER_DEFINED, NULL, 0,
				     private_data, private_data_len);
		break;
	default:
		ret = -ENOSYS;
		break;
	}
	return ret;
}
EXPORT_SYMBOL(rdma_reject);

int rdma_disconnect(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp(id_priv, CMA_CONNECT) &&
	    !cma_comp(id_priv, CMA_DISCONNECT))
		return -EINVAL;

	ret = cma_modify_qp_err(id);
	if (ret)
		goto out;

	switch (id->device->node_type) {
	case IB_NODE_CA:
		/* Initiate or respond to a disconnect. */
		if (ib_send_cm_dreq(id_priv->cm_id.ib, NULL, 0))
			ib_send_cm_drep(id_priv->cm_id.ib, NULL, 0);
		break;
	default:
		break;
	}
out:
	return ret;
}
EXPORT_SYMBOL(rdma_disconnect);

static void cma_add_one(struct ib_device *device)
{
	struct cma_device *cma_dev;
	struct rdma_id_private *id_priv;

	cma_dev = kmalloc(sizeof *cma_dev, GFP_KERNEL);
	if (!cma_dev)
		return;

	cma_dev->device = device;
	cma_dev->node_guid = device->node_guid;
	if (!cma_dev->node_guid)
		goto err;

	init_completion(&cma_dev->comp);
	atomic_set(&cma_dev->refcount, 1);
	INIT_LIST_HEAD(&cma_dev->id_list);
	ib_set_client_data(device, &cma_client, cma_dev);

	mutex_lock(&lock);
	list_add_tail(&cma_dev->list, &dev_list);
	list_for_each_entry(id_priv, &listen_any_list, list)
		cma_listen_on_dev(id_priv, cma_dev);
	mutex_unlock(&lock);
	return;
err:
	kfree(cma_dev);
}

static int cma_remove_id_dev(struct rdma_id_private *id_priv)
{
	enum cma_state state;

	/* Record that we want to remove the device */
	state = cma_exch(id_priv, CMA_DEVICE_REMOVAL);
	if (state == CMA_DESTROYING)
		return 0;

	cma_cancel_operation(id_priv, state);
	wait_event(id_priv->wait_remove, !atomic_read(&id_priv->dev_remove));

	/* Check for destruction from another callback. */
	if (!cma_comp(id_priv, CMA_DEVICE_REMOVAL))
		return 0;

	return cma_notify_user(id_priv, RDMA_CM_EVENT_DEVICE_REMOVAL,
			       0, NULL, 0);
}

static void cma_process_remove(struct cma_device *cma_dev)
{
	struct list_head remove_list;
	struct rdma_id_private *id_priv;
	int ret;

	INIT_LIST_HEAD(&remove_list);

	mutex_lock(&lock);
	while (!list_empty(&cma_dev->id_list)) {
		id_priv = list_entry(cma_dev->id_list.next,
				     struct rdma_id_private, list);

		if (cma_internal_listen(id_priv)) {
			cma_destroy_listen(id_priv);
			continue;
		}

		list_del(&id_priv->list);
		list_add_tail(&id_priv->list, &remove_list);
		atomic_inc(&id_priv->refcount);
		mutex_unlock(&lock);

		ret = cma_remove_id_dev(id_priv);
		cma_deref_id(id_priv);
		if (ret)
			rdma_destroy_id(&id_priv->id);

		mutex_lock(&lock);
	}
	mutex_unlock(&lock);

	cma_deref_dev(cma_dev);
	wait_for_completion(&cma_dev->comp);
}

static void cma_remove_one(struct ib_device *device)
{
	struct cma_device *cma_dev;

	cma_dev = ib_get_client_data(device, &cma_client);
	if (!cma_dev)
		return;

	mutex_lock(&lock);
	list_del(&cma_dev->list);
	mutex_unlock(&lock);

	cma_process_remove(cma_dev);
	kfree(cma_dev);
	ib_sa_flush(device);
}

static int cma_init(void)
{
	int ret;

	cma_wq = create_singlethread_workqueue("rdma_cm_wq");
	if (!cma_wq)
		return -ENOMEM;

	ret = ib_register_client(&cma_client);
	if (ret)
		goto err;
	return 0;

err:
	destroy_workqueue(cma_wq);
	return ret;
}

static void cma_cleanup(void)
{
	ib_unregister_client(&cma_client);
	destroy_workqueue(cma_wq);
	idr_destroy(&sdp_ps);
	idr_destroy(&tcp_ps);
	rdma_addr_flush();
}

module_init(cma_init);
module_exit(cma_cleanup);

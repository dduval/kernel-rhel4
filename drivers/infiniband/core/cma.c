/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2002-2005, Network Appliance, Inc. All rights reserved.
 * Copyright (c) 1999-2005, Mellanox Technologies, Inc. All rights reserved.
 * Copyright (c) 2005 Intel Corporation.  All rights reserved.
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
#include <linux/in.h>
#include <linux/in6.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_sa.h>

MODULE_AUTHOR("Guy German");
MODULE_DESCRIPTION("Generic RDMA CM Agent");
MODULE_LICENSE("Dual BSD/GPL");

#define CMA_CM_RESPONSE_TIMEOUT 20
#define CMA_MAX_CM_RETRIES 3

static void cma_add_one(struct ib_device *device);
static void cma_remove_one(struct ib_device *device);

static struct ib_client cma_client = {
	.name   = "cma",
	.add    = cma_add_one,
	.remove = cma_remove_one
};

static LIST_HEAD(dev_list);
static LIST_HEAD(listen_any_list);
static DECLARE_MUTEX(mutex);

struct cma_device {
	struct list_head	list;
	struct ib_device	*device;
	__be64			node_guid;
	wait_queue_head_t	wait;
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
	CMA_ADDR_BOUND,
	CMA_LISTEN,
	CMA_DEVICE_REMOVAL,
	CMA_DESTROYING
};

/*
 * Device removal can occur at anytime, so we need extra handling to
 * serialize notifying the user of device removal with other callbacks.
 * We do this by disabling removal notification while a callback is in process,
 * and reporting it after the callback completes.
 */
struct rdma_id_private {
	struct rdma_cm_id	id;

	struct list_head	list;
	struct list_head	listen_list;
	struct cma_device	*cma_dev;

	enum cma_state		state;
	spinlock_t		lock;
	wait_queue_head_t	wait;
	atomic_t		refcount;
	wait_queue_head_t	wait_remove;
	atomic_t		dev_remove;

	int			timeout_ms;
	struct ib_sa_query	*query;
	int			query_id;
	struct ib_cm_id		*cm_id;
};

struct cma_addr {
	u8 version;	/* CMA version: 7:4, IP version: 3:0 */
	u8 reserved;
	__u16 port;
	struct {
		union {
			struct in6_addr ip6;
			struct {
				__u32 pad[3];
				__u32 addr;
			} ip4;
		} ver;
	} src_addr, dst_addr;
};

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

static inline u8 cma_get_ip_ver(struct cma_addr *addr)
{
	return addr->version & 0xF;
}

static inline u8 cma_get_cma_ver(struct cma_addr *addr)
{
	return addr->version >> 4;
}

static inline void cma_set_vers(struct cma_addr *addr, u8 cma_ver, u8 ip_ver)
{
	addr->version = (cma_ver << 4) + (ip_ver & 0xF);
}

static void cma_attach_to_dev(struct rdma_id_private *id_priv,
			      struct cma_device *cma_dev)
{
	atomic_inc(&cma_dev->refcount);
	id_priv->cma_dev = cma_dev;
	id_priv->id.device = cma_dev->device;
	list_add_tail(&id_priv->list, &cma_dev->id_list);
}

static void cma_detach_from_dev(struct rdma_id_private *id_priv)
{
	list_del(&id_priv->list);
	if (atomic_dec_and_test(&id_priv->cma_dev->refcount))
		wake_up(&id_priv->cma_dev->wait);
	id_priv->cma_dev = NULL;
}

static int cma_acquire_ib_dev(struct rdma_id_private *id_priv,
			      union ib_gid *gid)
{
	struct cma_device *cma_dev;
	int ret = -ENODEV;
	u8 port;

	down(&mutex);
	list_for_each_entry(cma_dev, &dev_list, list) {
		ret = ib_find_cached_gid(cma_dev->device, gid, &port, NULL);
		if (!ret) {
			cma_attach_to_dev(id_priv, cma_dev);
			break;
		}
	}
	up(&mutex);
	return ret;
}

static void cma_deref_id(struct rdma_id_private *id_priv)
{
	if (atomic_dec_and_test(&id_priv->refcount))
		wake_up(&id_priv->wait);
}

static void cma_release_remove(struct rdma_id_private *id_priv)
{
	if (atomic_dec_and_test(&id_priv->dev_remove))
		wake_up(&id_priv->wait_remove);
}

struct rdma_cm_id* rdma_create_id(rdma_cm_event_handler event_handler,
				  void *context)
{
	struct rdma_id_private *id_priv;

	id_priv = kmalloc(sizeof *id_priv, GFP_KERNEL);
	if (!id_priv)
		return NULL;
	memset(id_priv, 0, sizeof *id_priv);

	id_priv->state = CMA_IDLE;
	id_priv->id.context = context;
	id_priv->id.event_handler = event_handler;
	spin_lock_init(&id_priv->lock);
	init_waitqueue_head(&id_priv->wait);
	atomic_set(&id_priv->refcount, 1);
	init_waitqueue_head(&id_priv->wait_remove);
	atomic_set(&id_priv->dev_remove, 0);
	INIT_LIST_HEAD(&id_priv->listen_list);

	return &id_priv->id;
}
EXPORT_SYMBOL(rdma_create_id);

static int cma_init_ib_qp(struct rdma_id_private *id_priv, struct ib_qp *qp)
{
	struct ib_qp_attr qp_attr;
	struct ib_addr *ibaddr;
	int ret;

	qp_attr.qp_state = IB_QPS_INIT;
	qp_attr.qp_access_flags = IB_ACCESS_LOCAL_WRITE;

	ibaddr = &id_priv->id.route.addr.addr.ibaddr;
	ret = ib_find_cached_gid(id_priv->id.device, &ibaddr->sgid,
				 &qp_attr.port_num, NULL);
	if (ret)
		return ret;

	ret = ib_find_cached_pkey(id_priv->id.device, qp_attr.port_num,
				  ibaddr->pkey, &qp_attr.pkey_index);
	if (ret)
		return ret;

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

static int cma_modify_ib_qp_rtr(struct rdma_id_private *id_priv)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	/* Need to update QP attributes from default values. */
	qp_attr.qp_state = IB_QPS_INIT;
	ret = ib_cm_init_qp_attr(id_priv->cm_id, &qp_attr, &qp_attr_mask);
	if (ret)
		return ret;

	ret = ib_modify_qp(id_priv->id.qp, &qp_attr, qp_attr_mask);
	if (ret)
		return ret;

	qp_attr.qp_state = IB_QPS_RTR;
	ret = ib_cm_init_qp_attr(id_priv->cm_id, &qp_attr, &qp_attr_mask);
	if (ret)
		return ret;

	qp_attr.rq_psn = id_priv->id.qp->qp_num;
	return ib_modify_qp(id_priv->id.qp, &qp_attr, qp_attr_mask);
}

static int cma_modify_ib_qp_rts(struct rdma_id_private *id_priv)
{
	struct ib_qp_attr qp_attr;
	int qp_attr_mask, ret;

	qp_attr.qp_state = IB_QPS_RTS;
	ret = ib_cm_init_qp_attr(id_priv->cm_id, &qp_attr, &qp_attr_mask);
	if (ret)
		return ret;

	return ib_modify_qp(id_priv->id.qp, &qp_attr, qp_attr_mask);
}

static int cma_modify_qp_err(struct rdma_cm_id *id)
{
	struct ib_qp_attr qp_attr;

	qp_attr.qp_state = IB_QPS_ERR;
	return ib_modify_qp(id->qp, &qp_attr, IB_QP_STATE);
}

static int cma_verify_addr(struct cma_addr *addr,
			   struct sockaddr_in *ip_addr)
{
	if (cma_get_cma_ver(addr) != 1 || cma_get_ip_ver(addr) != 4)
		return -EINVAL;

	if (ip_addr->sin_port != addr->port)
		return -EINVAL;

	if (ip_addr->sin_addr.s_addr &&
	    (ip_addr->sin_addr.s_addr != addr->dst_addr.ver.ip4.addr))
		return -EINVAL;

	return 0;
}

static inline int cma_any_addr(struct sockaddr *addr)
{
	return ((struct sockaddr_in *) addr)->sin_addr.s_addr == 0;
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

static void cma_cancel_addr(struct rdma_id_private *id_priv)
{
	switch (id_priv->id.device->node_type) {
	case IB_NODE_CA:
		ib_addr_cancel(&id_priv->id.route.addr.addr.ibaddr);
		break;
	default:
		break;
	}
}

static void cma_cancel_route(struct rdma_id_private *id_priv)
{
	switch (id_priv->id.device->node_type) {
	case IB_NODE_CA:
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

 	if (id_priv->cm_id && !IS_ERR(id_priv->cm_id))
		ib_destroy_cm_id(id_priv->cm_id);

	list_del(&id_priv->listen_list);
	if (id_priv->cma_dev)
		cma_detach_from_dev(id_priv);

	atomic_dec(&id_priv->refcount);
	wait_event(id_priv->wait, !atomic_read(&id_priv->refcount));

	kfree(id_priv);
}

static void cma_cancel_listens(struct rdma_id_private *id_priv)
{
	struct rdma_id_private *dev_id_priv;

	down(&mutex);
	list_del(&id_priv->list);

	while (!list_empty(&id_priv->listen_list)) {
		dev_id_priv = list_entry(id_priv->listen_list.next,
					 struct rdma_id_private, listen_list);
		cma_destroy_listen(dev_id_priv);
	}
	up(&mutex);
}

static void cma_cancel_operation(struct rdma_id_private *id_priv,
				 enum cma_state state)
{
	switch (state) {
	case CMA_ADDR_QUERY:
		cma_cancel_addr(id_priv);
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

void rdma_destroy_id(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv;
	enum cma_state state;

	id_priv = container_of(id, struct rdma_id_private, id);
	state = cma_exch(id_priv, CMA_DESTROYING);
	cma_cancel_operation(id_priv, state);

 	if (id_priv->cm_id && !IS_ERR(id_priv->cm_id))
		ib_destroy_cm_id(id_priv->cm_id);

	if (id_priv->cma_dev) {
	  	down(&mutex);
		cma_detach_from_dev(id_priv);
		up(&mutex);
	}

	atomic_dec(&id_priv->refcount);
	wait_event(id_priv->wait, !atomic_read(&id_priv->refcount));

	kfree(id_priv->id.route.path_rec);
	kfree(id_priv);
}
EXPORT_SYMBOL(rdma_destroy_id);

static int cma_rep_recv(struct rdma_id_private *id_priv)
{
	int ret;

	ret = cma_modify_ib_qp_rtr(id_priv);
	if (ret)
		goto reject;

	ret = cma_modify_ib_qp_rts(id_priv);
	if (ret)
		goto reject;
	
	ret = ib_send_cm_rtu(id_priv->cm_id, NULL, 0);
	if (ret)
		goto reject;

	return 0;
reject:
	cma_modify_qp_err(&id_priv->id);
	ib_send_cm_rej(id_priv->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
		       NULL, 0, NULL, 0);
	return ret;
}

static int cma_rtu_recv(struct rdma_id_private *id_priv)
{
	int ret;

	ret = cma_modify_ib_qp_rts(id_priv);
	if (ret)
		goto reject;

	return 0;
reject:
	cma_modify_qp_err(&id_priv->id);
	ib_send_cm_rej(id_priv->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
		       NULL, 0, NULL, 0);
	return ret;
}

static int cma_ib_handler(struct ib_cm_id *cm_id, struct ib_cm_event *ib_event)
{
	struct rdma_id_private *id_priv = cm_id->context;
	enum rdma_cm_event_type event;
	u8 private_data_len = 0;
	int ret = 0, status = 0;

	if (!cma_comp(id_priv, CMA_CONNECT))
		return 0;

	atomic_inc(&id_priv->dev_remove);
	switch (ib_event->event) {
	case IB_CM_REQ_ERROR:
	case IB_CM_REP_ERROR:
		event = RDMA_CM_EVENT_UNREACHABLE;
		status = -ETIMEDOUT;
		break;
	case IB_CM_REP_RECEIVED:
		status = cma_rep_recv(id_priv);
		event = status ? RDMA_CM_EVENT_CONNECT_ERROR :
				 RDMA_CM_EVENT_ESTABLISHED;
		private_data_len = IB_CM_REP_PRIVATE_DATA_SIZE;
		break;
	case IB_CM_RTU_RECEIVED:
		status = cma_rtu_recv(id_priv);
		event = status ? RDMA_CM_EVENT_CONNECT_ERROR :
				 RDMA_CM_EVENT_ESTABLISHED;
		break;
	case IB_CM_DREQ_ERROR:
		status = -ETIMEDOUT; /* fall through */
	case IB_CM_DREQ_RECEIVED:
	case IB_CM_DREP_RECEIVED:
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
		id_priv->cm_id = NULL;
		cma_exch(id_priv, CMA_DESTROYING);
		cma_release_remove(id_priv);
		rdma_destroy_id(&id_priv->id);
	}
	return ret;
out:
	cma_release_remove(id_priv);
	return ret;
}

static struct rdma_id_private* cma_new_id(struct rdma_cm_id *listen_id,
					  struct ib_cm_event *ib_event)
{
	struct rdma_id_private *id_priv;
	struct rdma_cm_id *id;
	struct rdma_route *route;
	struct sockaddr_in *ip_addr;
	struct ib_sa_path_rec *path_rec;
	struct cma_addr *addr;
	int num_paths;

	ip_addr = (struct sockaddr_in *) &listen_id->route.addr.src_addr;
	if (cma_verify_addr(ib_event->private_data, ip_addr))
		return NULL;

	num_paths = 1 + (ib_event->param.req_rcvd.alternate_path != NULL);
	path_rec = kmalloc(sizeof *path_rec * num_paths, GFP_KERNEL);
	if (!path_rec)
		return NULL;

	id = rdma_create_id(listen_id->event_handler, listen_id->context);
	if (!id)
		goto err;

	route = &id->route;
	route->addr.src_addr = listen_id->route.addr.src_addr;
	route->addr.dst_addr.sa_family = ip_addr->sin_family;

	ip_addr = (struct sockaddr_in *) &route->addr.dst_addr;
	addr = ib_event->private_data;
	ip_addr->sin_addr.s_addr = addr->src_addr.ver.ip4.addr;

	route->num_paths = num_paths;
	route->path_rec = path_rec;
	path_rec[0] = *ib_event->param.req_rcvd.primary_path;
	if (num_paths == 2)
		path_rec[1] = *ib_event->param.req_rcvd.alternate_path;

	route->addr.addr.ibaddr.sgid = path_rec->sgid;
	route->addr.addr.ibaddr.dgid = path_rec->dgid;
	route->addr.addr.ibaddr.pkey = be16_to_cpu(path_rec->pkey);

	id_priv = container_of(id, struct rdma_id_private, id);
	id_priv->state = CMA_CONNECT;
	return id_priv;
err:
	kfree(path_rec);
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

	conn_id->state = CMA_CONNECT;
	atomic_inc(&conn_id->dev_remove);
	ret = cma_acquire_ib_dev(conn_id, &conn_id->id.route.path_rec[0].sgid);
	if (ret) {
		ret = -ENODEV;
		cma_release_remove(conn_id);
		rdma_destroy_id(&conn_id->id);
		goto out;
	}

	conn_id->cm_id = cm_id;
	cm_id->context = conn_id;
	cm_id->cm_handler = cma_ib_handler;

	offset = sizeof(struct cma_addr);
	ret = cma_notify_user(conn_id, RDMA_CM_EVENT_CONNECT_REQUEST, 0,
			      ib_event->private_data + offset,
			      IB_CM_REQ_PRIVATE_DATA_SIZE - offset);
	if (ret) {
		/* Destroy the CM ID by returning a non-zero value. */
		conn_id->cm_id = NULL;
		cma_exch(conn_id, CMA_DESTROYING);
		cma_release_remove(conn_id);
		rdma_destroy_id(&conn_id->id);
	}
out:
	cma_release_remove(listen_id);
	return ret;
}

static __be64 cma_get_service_id(struct sockaddr *addr)
{
	return cpu_to_be64(((u64)IB_OPENIB_OUI << 48) +
	       ((struct sockaddr_in *) addr)->sin_port);
}

static int cma_ib_listen(struct rdma_id_private *id_priv)
{
	__be64 svc_id;
	int ret;

	id_priv->cm_id = ib_create_cm_id(id_priv->id.device, cma_req_handler,
					 id_priv);
	if (IS_ERR(id_priv->cm_id))
		return PTR_ERR(id_priv->cm_id);

	svc_id = cma_get_service_id(&id_priv->id.route.addr.src_addr);
	ret = ib_cm_listen(id_priv->cm_id, svc_id, 0);
	if (ret) {
		ib_destroy_cm_id(id_priv->cm_id);
		id_priv->cm_id = NULL;
	}

	return ret;
}

static int cma_duplicate_listen(struct rdma_id_private *id_priv)
{
	struct rdma_id_private *cur_id_priv;
	struct sockaddr_in *cur_addr, *new_addr;

	new_addr = (struct sockaddr_in *) &id_priv->id.route.addr.src_addr;
	list_for_each_entry(cur_id_priv, &listen_any_list, listen_list) {
		cur_addr = (struct sockaddr_in *)
			    &cur_id_priv->id.route.addr.src_addr;
		if (cur_addr->sin_port == new_addr->sin_port)
			return -EADDRINUSE;
	}
	return 0;
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

	id = rdma_create_id(cma_listen_handler, id_priv);
	if (IS_ERR(id))
		return;

	dev_id_priv = container_of(id, struct rdma_id_private, id);
	ret = rdma_bind_addr(id, &id_priv->id.route.addr.src_addr);
	if (ret)
		goto err;

	cma_attach_to_dev(dev_id_priv, cma_dev);
	list_add_tail(&dev_id_priv->listen_list, &id_priv->listen_list);

	ret = rdma_listen(id);
	if (ret)
		goto err;

	return;
err:
	cma_destroy_listen(dev_id_priv);
}

static int cma_listen_on_all(struct rdma_id_private *id_priv)
{
	struct cma_device *cma_dev;
	int ret;

	down(&mutex);
	ret = cma_duplicate_listen(id_priv);
	if (ret)
		goto out;

	list_add_tail(&id_priv->list, &listen_any_list);
	list_for_each_entry(cma_dev, &dev_list, list)
		cma_listen_on_dev(id_priv, cma_dev);
out:
	up(&mutex);
	return ret;
}

int rdma_listen(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp_exch(id_priv, CMA_ADDR_BOUND, CMA_LISTEN))
		return -EINVAL;

	if (id->device) {
		switch (id->device->node_type) {
		case IB_NODE_CA:
			ret = cma_ib_listen(id_priv);
			break;
		default:
			ret = -ENOSYS;
			break;
		}
	} else
		ret = cma_listen_on_all(id_priv);

	if (ret)
		goto err;

	return 0;
err:
	cma_comp_exch(id_priv, CMA_LISTEN, CMA_ADDR_BOUND);
	return ret;
};
EXPORT_SYMBOL(rdma_listen);

static void cma_query_handler(int status, struct ib_sa_path_rec *path_rec,
			      void *context)
{
	struct rdma_id_private *id_priv = context;
	struct rdma_route *route = &id_priv->id.route;
	enum rdma_cm_event_type event = RDMA_CM_EVENT_ROUTE_RESOLVED;

	atomic_inc(&id_priv->dev_remove);
	if (!status) {
		route->path_rec = kmalloc(sizeof *route->path_rec, GFP_KERNEL);
		if (route->path_rec) {
			route->num_paths = 1;
			*route->path_rec = *path_rec;
			if (!cma_comp_exch(id_priv, CMA_ROUTE_QUERY,
						    CMA_ROUTE_RESOLVED)) {
				kfree(route->path_rec);
				goto out;
			}
		} else
			status = -ENOMEM;
	}

	if (status) {
		if (!cma_comp_exch(id_priv, CMA_ROUTE_QUERY, CMA_ADDR_RESOLVED))
			goto out;
		event = RDMA_CM_EVENT_ROUTE_ERROR;
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

static int cma_resolve_ib_route(struct rdma_id_private *id_priv, int timeout_ms)
{
	struct ib_addr *addr = &id_priv->id.route.addr.addr.ibaddr;
	struct ib_sa_path_rec path_rec;
	int ret;
	u8 port;

	ret = ib_find_cached_gid(id_priv->id.device, &addr->sgid, &port, NULL);
	if (ret)
		return -ENODEV;

	memset(&path_rec, 0, sizeof path_rec);
	path_rec.sgid = addr->sgid;
	path_rec.dgid = addr->dgid;
	path_rec.pkey = addr->pkey;
	path_rec.numb_path = 1;

	id_priv->query_id = ib_sa_path_rec_get(id_priv->id.device,
				port, &path_rec,
				IB_SA_PATH_REC_DGID | IB_SA_PATH_REC_SGID |
				IB_SA_PATH_REC_PKEY | IB_SA_PATH_REC_NUMB_PATH,
				timeout_ms, GFP_KERNEL,
				cma_query_handler, id_priv, &id_priv->query);
	
	return (id_priv->query_id < 0) ? id_priv->query_id : 0;
}

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

static void addr_handler(int status, struct sockaddr *src_addr,
			 struct ib_addr *ibaddr, void *context)
{
	struct rdma_id_private *id_priv = context;
	enum rdma_cm_event_type event;

	atomic_inc(&id_priv->dev_remove);
	if (!status)
		status = cma_acquire_ib_dev(id_priv, &ibaddr->sgid);

	if (status) {
		if (!cma_comp_exch(id_priv, CMA_ADDR_QUERY, CMA_IDLE))
			goto out;
		event = RDMA_CM_EVENT_ADDR_ERROR;
	} else {
		if (!cma_comp_exch(id_priv, CMA_ADDR_QUERY, CMA_ADDR_RESOLVED))
			goto out;
		id_priv->id.route.addr.src_addr = *src_addr;
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

int rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      struct sockaddr *dst_addr, int timeout_ms)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp_exch(id_priv, CMA_IDLE, CMA_ADDR_QUERY))
		return -EINVAL;

	atomic_inc(&id_priv->refcount);
	id->route.addr.dst_addr = *dst_addr;
	ret = ib_resolve_addr(src_addr, dst_addr, &id->route.addr.addr.ibaddr,
			      timeout_ms, addr_handler, id_priv);
	if (ret)
		goto err;

	return 0;
err:
	cma_comp_exch(id_priv, CMA_ADDR_QUERY, CMA_IDLE);
	cma_deref_id(id_priv);
	return ret;
}
EXPORT_SYMBOL(rdma_resolve_addr);

int rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr)
{
	struct rdma_id_private *id_priv;
	struct ib_addr *ibaddr = &id->route.addr.addr.ibaddr;
	int ret;

	if (addr->sa_family != AF_INET)
		return -EINVAL;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp_exch(id_priv, CMA_IDLE, CMA_ADDR_BOUND))
		return -EINVAL;

	if (cma_any_addr(addr)) {
		id->route.addr.src_addr = *addr;
		ret = 0;
	} else {
		ret = ib_translate_addr(addr, &ibaddr->sgid, &ibaddr->pkey);
		if (!ret)
			ret = cma_acquire_ib_dev(id_priv, &ibaddr->sgid);
	}

	if (ret)
		goto err;

	id->route.addr.src_addr = *addr;
	return 0;
err:
	cma_comp_exch(id_priv, CMA_ADDR_BOUND, CMA_IDLE);
	return ret;
}
EXPORT_SYMBOL(rdma_bind_addr);

static void cma_format_addr(struct cma_addr *addr, struct rdma_route *route)
{
	struct sockaddr_in *ip_addr;

	memset(addr, 0, sizeof *addr);
	cma_set_vers(addr, 1, 4);

	ip_addr = (struct sockaddr_in *) &route->addr.src_addr;
	addr->src_addr.ver.ip4.addr = ip_addr->sin_addr.s_addr;

	ip_addr = (struct sockaddr_in *) &route->addr.dst_addr;
	addr->dst_addr.ver.ip4.addr = ip_addr->sin_addr.s_addr;
	addr->port = ip_addr->sin_port;
}

static int cma_connect_ib(struct rdma_id_private *id_priv,
			  struct rdma_conn_param *conn_param)
{
	struct ib_cm_req_param req;
	struct rdma_route *route;
	struct cma_addr *addr;
	void *private_data;
	int ret;

	memset(&req, 0, sizeof req);
	req.private_data_len = sizeof *addr + conn_param->private_data_len;

	private_data = kmalloc(req.private_data_len, GFP_ATOMIC);
	if (!private_data)
		return -ENOMEM;

	id_priv->cm_id = ib_create_cm_id(id_priv->id.device, cma_ib_handler,
					 id_priv);
	if (IS_ERR(id_priv->cm_id)) {
		ret = PTR_ERR(id_priv->cm_id);
		goto out;
	}

	addr = private_data;
	route = &id_priv->id.route;
	cma_format_addr(addr, route);

	if (conn_param->private_data && conn_param->private_data_len)
		memcpy(addr + 1, conn_param->private_data,
		       conn_param->private_data_len);
	req.private_data = private_data;

	req.primary_path = &route->path_rec[0];
	if (route->num_paths == 2)
		req.alternate_path = &route->path_rec[1];

	req.service_id = cma_get_service_id(&route->addr.dst_addr);
	req.qp_num = id_priv->id.qp->qp_num;
	req.qp_type = IB_QPT_RC;
	req.starting_psn = req.qp_num;
	req.responder_resources = conn_param->responder_resources;
	req.initiator_depth = conn_param->initiator_depth;
	req.flow_control = conn_param->flow_control;
	req.retry_count = conn_param->retry_count;
	req.rnr_retry_count = conn_param->rnr_retry_count;
	req.remote_cm_response_timeout = CMA_CM_RESPONSE_TIMEOUT;
	req.local_cm_response_timeout = CMA_CM_RESPONSE_TIMEOUT;
	req.max_cm_retries = CMA_MAX_CM_RETRIES;
	req.srq = id_priv->id.qp->srq ? 1 : 0;

	ret = ib_send_cm_req(id_priv->cm_id, &req);
out:
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
	int ret;

	ret = cma_modify_ib_qp_rtr(id_priv);
	if (ret)
		return ret;

	memset(&rep, 0, sizeof rep);
	rep.qp_num = id_priv->id.qp->qp_num;
	rep.starting_psn = rep.qp_num;
	rep.private_data = conn_param->private_data;
	rep.private_data_len = conn_param->private_data_len;
	rep.responder_resources = conn_param->responder_resources;
	rep.initiator_depth = conn_param->initiator_depth;
	rep.target_ack_delay = CMA_CM_RESPONSE_TIMEOUT;
	rep.failover_accepted = 0;
	rep.flow_control = conn_param->flow_control;
	rep.rnr_retry_count = conn_param->rnr_retry_count;
	rep.srq = id_priv->id.qp->srq ? 1 : 0;

	return ib_send_cm_rep(id_priv->cm_id, &rep);
}

int rdma_accept(struct rdma_cm_id *id, struct rdma_conn_param *conn_param)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp(id_priv, CMA_CONNECT))
		return -EINVAL;

	switch (id->device->node_type) {
	case IB_NODE_CA:
		ret = cma_accept_ib(id_priv, conn_param);
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
		ret = ib_send_cm_rej(id_priv->cm_id, IB_CM_REJ_CONSUMER_DEFINED,
				     NULL, 0, private_data, private_data_len);
		break;
	default:
		ret = -ENOSYS;
		break;
	}
	return ret;
};
EXPORT_SYMBOL(rdma_reject);

int rdma_disconnect(struct rdma_cm_id *id)
{
	struct rdma_id_private *id_priv;
	int ret;

	id_priv = container_of(id, struct rdma_id_private, id);
	if (!cma_comp(id_priv, CMA_CONNECT))
		return -EINVAL;

	ret = cma_modify_qp_err(id);
	if (ret)
		goto out;

	switch (id->device->node_type) {
	case IB_NODE_CA:
		/* Initiate or respond to a disconnect. */
		if (ib_send_cm_dreq(id_priv->cm_id, NULL, 0))
			ib_send_cm_drep(id_priv->cm_id, NULL, 0);
		break;
	default:
		break;
	}
out:
	return ret;
}
EXPORT_SYMBOL(rdma_disconnect);

/* TODO: add this to the device structure - see Roland's patch */
static __be64 get_ca_guid(struct ib_device *device)
{
	struct ib_device_attr *device_attr;
	__be64 guid;
	int ret;

	device_attr = kmalloc(sizeof *device_attr, GFP_KERNEL);
	if (!device_attr)
		return 0;

	ret = ib_query_device(device, device_attr);
	guid = ret ? 0 : device_attr->node_guid;
	kfree(device_attr);
	return guid;
}

static void cma_add_one(struct ib_device *device)
{
	struct cma_device *cma_dev;
	struct rdma_id_private *id_priv;

	cma_dev = kmalloc(sizeof *cma_dev, GFP_KERNEL);
	if (!cma_dev)
		return;

	cma_dev->device = device;
	cma_dev->node_guid = get_ca_guid(device);
	if (!cma_dev->node_guid)
		goto err;

	init_waitqueue_head(&cma_dev->wait);
	atomic_set(&cma_dev->refcount, 1);
	INIT_LIST_HEAD(&cma_dev->id_list);
	ib_set_client_data(device, &cma_client, cma_dev);

	down(&mutex);
	list_add_tail(&cma_dev->list, &dev_list);
	list_for_each_entry(id_priv, &listen_any_list, list)
		cma_listen_on_dev(id_priv, cma_dev);
	up(&mutex);
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

	down(&mutex);
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
		up(&mutex);

		ret = cma_remove_id_dev(id_priv);
		cma_deref_id(id_priv);
		if (ret)
			rdma_destroy_id(&id_priv->id);

		down(&mutex);
	}
	up(&mutex);

	atomic_dec(&cma_dev->refcount);
	wait_event(cma_dev->wait, !atomic_read(&cma_dev->refcount));
}

static void cma_remove_one(struct ib_device *device)
{
	struct cma_device *cma_dev;

	cma_dev = ib_get_client_data(device, &cma_client);
	if (!cma_dev)
		return;

	down(&mutex);
	list_del(&cma_dev->list);
	up(&mutex);

	cma_process_remove(cma_dev);
	kfree(cma_dev);
}

static int cma_init(void)
{
	return ib_register_client(&cma_client);
}

static void cma_cleanup(void)
{
	ib_unregister_client(&cma_client);
}

module_init(cma_init);
module_exit(cma_cleanup);

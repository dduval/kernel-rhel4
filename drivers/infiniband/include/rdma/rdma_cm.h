/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
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

#if !defined(RDMA_CM_H)
#define RDMA_CM_H

#include <linux/socket.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_sa.h>

/*
 * Upon receiving a device removal event, users must destroy the associated
 * RDMA identifier and release all resources allocated with the device.
 */
enum rdma_cm_event_type {
	RDMA_CM_EVENT_ADDR_RESOLVED,
	RDMA_CM_EVENT_ADDR_ERROR,
	RDMA_CM_EVENT_ROUTE_RESOLVED,
	RDMA_CM_EVENT_ROUTE_ERROR,
	RDMA_CM_EVENT_CONNECT_REQUEST,
	RDMA_CM_EVENT_CONNECT_ERROR,
	RDMA_CM_EVENT_UNREACHABLE,
	RDMA_CM_EVENT_REJECTED,
	RDMA_CM_EVENT_ESTABLISHED,
	RDMA_CM_EVENT_DISCONNECTED,
	RDMA_CM_EVENT_DEVICE_REMOVAL,
};

struct rdma_addr {
	struct sockaddr src_addr;
	struct sockaddr dst_addr;
	union {
		struct ib_addr	ibaddr;
	} addr;
};

struct rdma_route {
	struct rdma_addr addr;
	struct ib_sa_path_rec *path_rec;
	int num_paths;
};

struct rdma_cm_event {
	enum rdma_cm_event_type	 event;
	int			 status;
	void			*private_data;
	u8			 private_data_len;
};

struct rdma_cm_id;

/**
 * rdma_cm_event_handler - Callback used to report user events.
 *
 * Notes: Users may not call rdma_destroy_id from this callback to destroy
 *   the passed in id, or a corresponding listen id.  Returning a
 *   non-zero value from the callback will destroy the corresponding id.
 */
typedef int (*rdma_cm_event_handler)(struct rdma_cm_id *id,
				     struct rdma_cm_event *event);

struct rdma_cm_id {
	struct ib_device	*device;
	void			*context;
	struct ib_qp		*qp;
	rdma_cm_event_handler	 event_handler;
	struct rdma_route	 route;
};

struct rdma_cm_id* rdma_create_id(rdma_cm_event_handler event_handler,
				  void *context);

void rdma_destroy_id(struct rdma_cm_id *id);

/**
 * rdma_bind_addr - Bind an RDMA identifier to a source address and
 *   associated RDMA device, if needed.
 *
 * @id: RDMA identifier.
 * @addr: Local address information.  Wildcard values are permitted.
 *
 * This associates a source address with the RDMA identifier before calling
 * rdma_listen.  If a specific local address is given, the RDMA identifier will
 * be bound to a local RDMA device.
 */
int rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr);

/**
 * rdma_resolve_addr - Resolve destination and optional source addresses
 *   from IP addresses to an RDMA address.  If successful, the specified
 *   rdma_cm_id will be bound to a local device.
 *
 * @id: RDMA identifier.
 * @src_addr: Source address information.  This parameter may be NULL.
 * @dst_addr: Destination address information.
 * @timeout_ms: Time to wait for resolution to complete.
 */
int rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      struct sockaddr *dst_addr, int timeout_ms);

/**
 * rdma_resolve_route - Resolve the RDMA address bound to the RDMA identifier
 *   into route information needed to establish a connection.
 *
 * This is called on the client side of a connection.
 * Users must have first called rdma_resolve_addr to resolve a dst_addr
 * into an RDMA address before calling this routine.
 */
int rdma_resolve_route(struct rdma_cm_id *id, int timeout_ms);

/**
 * rdma_create_qp - Allocate a QP and associate it with the specified RDMA
 * identifier.
 */
int rdma_create_qp(struct rdma_cm_id *id, struct ib_pd *pd,
		   struct ib_qp_init_attr *qp_init_attr);

/**
 * rdma_destroy_qp - Deallocate the QP associated with the specified RDMA
 * identifier.
 *
 * Users must destroy any QP associated with an RDMA identifier before
 * destroying the RDMA ID.
 */
void rdma_destroy_qp(struct rdma_cm_id *id);

struct rdma_conn_param {
	const void *private_data;
	u8 private_data_len;
	u8 responder_resources;
	u8 initiator_depth;
	u8 flow_control;
	u8 retry_count;		/* ignored when accepting */
	u8 rnr_retry_count;
};

/**
 * rdma_connect - Initiate an active connection request.
 *
 * Users must have resolved a route for the rdma_cm_id to connect with
 * by having called rdma_resolve_route before calling this routine.
 */
int rdma_connect(struct rdma_cm_id *id, struct rdma_conn_param *conn_param);

/**
 * rdma_listen - This function is called by the passive side to
 *   listen for incoming connection requests.
 *
 * Users must have bound the rdma_cm_id to a local address by calling
 * rdma_bind_addr before calling this routine.
 */
int rdma_listen(struct rdma_cm_id *id);

/**
 * rdma_accept - Called on the passive side to accept a connection request
 */
int rdma_accept(struct rdma_cm_id *id, struct rdma_conn_param *conn_param);

/**
 * rdma_reject - Called on the passive side to reject a connection request.
 */
int rdma_reject(struct rdma_cm_id *id, const void *private_data,
		u8 private_data_len);

/**
 * rdma_disconnect - This function disconnects the associated QP.
 */
int rdma_disconnect(struct rdma_cm_id *id);

#endif /* RDMA_CM_H */


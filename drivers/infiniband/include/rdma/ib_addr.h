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

#if !defined(IB_ADDR_H)
#define IB_ADDR_H

#include <linux/socket.h>
#include <rdma/ib_verbs.h>

struct ib_addr {
	union ib_gid	sgid;
	union ib_gid	dgid;
	u16		pkey;
};

/**
 * ib_translate_addr - Translate a local IP address to an Infiniband GID and
 *   PKey.
 */
int ib_translate_addr(struct sockaddr *addr, union ib_gid *gid, u16 *pkey);

/**
 * ib_resolve_addr - Resolve source and destination IP addresses to
 *   Infiniband network addresses.
 * @src_addr: An optional source address to use in the resolution.  If a
 *   source address is not provided, a usable address will be returned via
 *   the callback.
 * @dst_addr: The destination address to resolve.
 * @addr: A reference to a data location that will receive the resolved
 *   addresses.  The data location must remain valid until the callback has
 *   been invoked.
 * @timeout_ms: Amount of time to wait for the address resolution to complete.
 * @callback: Call invoked once address resolution has completed, timed out,
 *   or been canceled.  A status of 0 indicates success.
 * @context: User-specified context associated with the call.
 */
int ib_resolve_addr(struct sockaddr *src_addr, struct sockaddr *dst_addr,
		    struct ib_addr *addr, int timeout_ms,
		    void (*callback)(int status, struct sockaddr *src_addr,
				     struct ib_addr *addr, void *context),
		    void *context);

void ib_addr_cancel(struct ib_addr *addr);

#endif /* IB_ADDR_H */


/*
 * Copyright (c) 2006 Intel Corporation.  All rights reserved.
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
 */

#ifndef IB_MULTICAST_H
#define IB_MULTICAST_H

#include <rdma/ib_sa.h>

struct ib_multicast {
	struct ib_sa_mcmember_rec rec;
	ib_sa_comp_mask		comp_mask;
	int			(*callback)(int status,
					    struct ib_multicast *multicast);
	void			*context;
};

/**
 * ib_join_multicast - Initiates a join request to the specified multicast
 *   group.
 * @device: Device associated with the multicast group.
 * @port_num: Port on the specified device to associate with the multicast
 *   group.
 * @rec: SA multicast member record specifying group attributes.
 * @comp_mask: Component mask indicating which group attributes of %rec are
 *   valid.
 * @gfp_mask: GFP mask for memory allocations.
 * @callback: User callback invoked once the join operation completes.
 * @context: User specified context stored with the ib_multicast structure.
 *
 * This call initiates a multicast join request with the SA for the specified
 * multicast group.  If the join operation is started successfully, it returns
 * an ib_multicast structure that is used to track the multicast operation.
 * Users must free this structure by calling ib_free_multicast, even if the
 * join operation later fails.  (The callback status is non-zero.)
 */
struct ib_multicast *ib_join_multicast(struct ib_device *device, u8 port_num,
				       struct ib_sa_mcmember_rec *rec,
				       ib_sa_comp_mask comp_mask, gfp_t gfp_mask,
				       int (*callback)(int status,
						       struct ib_multicast
							      *multicast),
				       void *context);

/**
 * ib_free_multicast - Frees the multicast tracking structure, and releases
 *    any reference on the multicast group.
 * @multicast: Multicast tracking structure allocated by ib_join_multicast.
 *
 * This call blocks until the connection identifier is destroyed.  It may
 * not be called from within the multicast callback; however, returning a non-
 * zero value from the callback will result in destroying the multicast
 * tracking structure.
 */
void ib_free_multicast(struct ib_multicast *multicast);

#endif /* IB_MULTICAST_H */

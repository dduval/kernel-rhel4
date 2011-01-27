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
 * $Id: sdp_advt.h 2990 2005-08-05 21:20:55Z tomduffy $
 */

#ifndef _SDP_ADVT_H
#define _SDP_ADVT_H

#include <linux/list.h>

#include "sdp_queue.h"

/*
 * IOCB flags.
 */
#define SDP_ADVT_F_READ 0x00000001 /* ADVT has an active read operation */

/*
 * SDP read/write advertisments
 */
struct sdpc_advt {
	struct list_head list;
	u32                 type; /* element type. (for generic queue) */
	struct sdpc_advt_q *table; /* table to which this object belongs */
	void (*release)(struct sdpc_advt *advt); /* release the object */
	/*
	 * advertisment specific
	 */
	u32 rkey; /* advertised buffer remote key */
	s32 size; /* advertised buffer size */
	s32 post; /* running total of data moved for advert. */
	u64 wrid; /* work request completing this advertisment */
	u32 flag; /* advertisment flags. */
	u64 addr; /* advertised buffer virtual address */
};

/*
 * table for holding SDP advertisments.
 */
struct sdpc_advt_q {
	struct list_head head; /* double linked list of advertisments */
	s32 size;               /* current number of advertisments in table */
};

/*
 * make size a macro.
 */
#define sdp_advt_q_size(table) ((table)->size)

#endif /* _SDP_ADVT_H */

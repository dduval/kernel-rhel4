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
 * $Id: sdp_queue.h 2663 2005-06-20 17:17:58Z libor $
 */

#ifndef _SDP_QUEUE_H
#define _SDP_QUEUE_H
/*
 * defines for object types.
 */
enum sdp_desc_type {
	SDP_DESC_TYPE_UNKOWN = 0x00,
	SDP_DESC_TYPE_BUFF   = 0x01,
	SDP_DESC_TYPE_IOCB   = 0x02,
	SDP_DESC_TYPE_ADVT   = 0x03,
	SDP_DESC_TYPE_NONE
};

/*
 * SDP generic queue for multiple object types
 */

struct sdpc_desc {
	struct sdpc_desc   *next;  /* next structure in table */
	struct sdpc_desc   *prev;  /* previous structure in table */
	u32                 type;  /* element type. (for generic queue) */
	struct sdpc_desc_q *table; /* table to which this object belongs */
	void (*release)(struct sdpc_desc *element); /* release the object */
};

/*
 * table for holding SDP advertisments.
 */
struct sdpc_desc_q {
	struct sdpc_desc *head; /* double linked list of advertisments */
	int size;               /* current number of advertisments in table */
	u16 count[SDP_DESC_TYPE_NONE]; /* object specific counter */
};

/*
 * SDP generic queue inline functions
 */

/*
 * sdp_desc_q_size - return the number of elements in the table
 */
static inline int sdp_desc_q_size(struct sdpc_desc_q *table)
{
	return table->size;
}

/*
 * sdp_desc_q_member - return non-zero if element is in a table
 */
static inline int sdp_desc_q_member(struct sdpc_desc *element)
{
	return (element->table ? 1 : 0);
}

#endif /* _SDP_QUEUE_H */

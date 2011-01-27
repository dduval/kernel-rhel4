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
 * $Id: sdp_advt.c 3033 2005-08-09 12:45:08Z mst $
 */

#include <linux/list.h>

#include "sdp_main.h"

static kmem_cache_t *sdp_advt_cache = NULL;

/*
 * module specific functions
 */

/*
 * public advertisment object functions for FIFO object table
 */

/*
 * sdp_advt_create - create an advertisment object
 */
struct sdpc_advt *sdp_advt_create(void)
{
	struct sdpc_advt *advt;

	advt = kmem_cache_alloc(sdp_advt_cache, SLAB_ATOMIC);
	if (advt) {
		memset(advt, 0, sizeof(*advt));

		advt->type = SDP_DESC_TYPE_ADVT;
		advt->release = sdp_advt_destroy;
	}

	return advt;
}

/*
 * sdp_advt_destroy - destroy an advertisment object
 */
void sdp_advt_destroy(struct sdpc_advt *advt)
{
	/*
	 * return the object to its cache
	 */
	kmem_cache_free(sdp_advt_cache, advt);
}

/*
 * sdp_advt_q_get - get, and remove, the object at the tables head
 */
struct sdpc_advt *sdp_advt_q_get(struct sdpc_advt_q *table)
{
	struct sdpc_advt *advt;

	if (list_empty(&table->head))
		return NULL;

	advt = list_entry(table->head.next, struct sdpc_advt, list);

	list_del(&advt->list);

	table->size--;

	return advt;
}

/*
 * sdp_advt_q_look - get, without removing, the object at the head
 */
struct sdpc_advt *sdp_advt_q_look(struct sdpc_advt_q *table)
{
	if (list_empty(&table->head))
		return NULL;

	return list_entry(table->head.next, struct sdpc_advt, list);
}

/*
 * sdp_advt_q_put - put the advertisment object at the tables tail
 */
void sdp_advt_q_put(struct sdpc_advt_q *table, struct sdpc_advt *advt)
{
	BUG_ON(advt->table);

	list_add_tail(&advt->list, &table->head);

	table->size++;
}

/*
 * sdp_advt_q_init - initialize a new empty advertisment table
 */
void sdp_advt_q_init(struct sdpc_advt_q *table)
{
	INIT_LIST_HEAD(&table->head);
	table->size = 0;
}

/*
 * sdp_advt_q_clear - clear the contents of an advertisment table
 */
void sdp_advt_q_clear(struct sdpc_advt_q *table)
{
	struct sdpc_advt *advt, *tmp;
	/*
	 * drain the table of any objects
	 */
	list_for_each_entry_safe(advt, tmp, &table->head, list)
		sdp_advt_destroy(advt);
}

/*
 * primary initialization/cleanup functions
 */

/*
 * sdp_main_advt_init - initialize the advertisment caches.
 */
int sdp_main_advt_init(void)
{
	sdp_dbg_init("Advertisment cache initialization.");
	/*
	 * initialize the caches only once.
	 */
	if (sdp_advt_cache) {
		sdp_warn("Advertisment caches already initialized.");
		return -EINVAL;
	}

	sdp_advt_cache = kmem_cache_create("sdp_advt",
					     sizeof(struct sdpc_advt),
					     0, SLAB_HWCACHE_ALIGN, NULL,
					     NULL);
	if (!sdp_advt_cache)
		return -ENOMEM;

	return 0;
}

/*
 * sdp_main_advt_cleanup - cleanup the advertisment caches.
 */
void sdp_main_advt_cleanup(void)
{
	sdp_dbg_init("Advertisment cache cleanup.");
	/*
	 * cleanup the caches
	 */
	kmem_cache_destroy(sdp_advt_cache);
	/*
	 * null out entries.
	 */
	sdp_advt_cache = NULL;
}

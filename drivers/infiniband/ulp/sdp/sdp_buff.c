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
 * $Id: sdp_buff.c 3370 2005-09-12 14:15:59Z mst $
 */

#include "sdp_main.h"

static struct sdpc_buff_root main_pool;
/*
 * data buffers managment API
 */

/*
 * do_buff_q_get - Get a buffer from a specific pool
 */
static inline struct sdpc_buff *do_buff_q_get(struct sdpc_buff_q *pool,
					      int fifo,
					      int (*test_func)
						     (struct sdpc_buff *buff,
						      void *arg),
					      void *usr_arg)
{
	struct sdpc_buff *buff;

	if (!pool->head)
		return NULL;

	if (fifo)
		buff = pool->head;
	else
		buff = pool->head->prev;

	if (!test_func || !test_func(buff, usr_arg)) {
		if (buff->next == buff && buff->prev == buff)
			pool->head = NULL;
		else {
			buff->next->prev = buff->prev;
			buff->prev->next = buff->next;

			pool->head = buff->next;
		}

		pool->size--;

		buff->next = NULL;
		buff->prev = NULL;
		buff->pool = NULL;
	}
	else
		buff = NULL;

	return buff;
}

/*
 * do_buff_q_put - Place a buffer into a specific pool
 */
static inline void do_buff_q_put(struct sdpc_buff_q *pool,
				 struct sdpc_buff *buff, int fifo)
{
	/* fifo: false == tail, true == head */
	BUG_ON(buff->pool);

	if (!pool->head) {
		buff->next = buff;
		buff->prev = buff;
		pool->head = buff;
	} else {
		buff->next = pool->head;
		buff->prev = pool->head->prev;

		buff->next->prev = buff;
		buff->prev->next = buff;

		if (fifo)
			pool->head = buff;
	}

	pool->size++;
	buff->pool = pool;
}

/*
 * sdp_buff_q_look - look at a buffer from a specific pool
 */
static inline struct sdpc_buff *sdp_buff_q_look(struct sdpc_buff_q *pool,
						int fifo)
{
	if (!pool->head || fifo)
		return pool->head;
	else
		return pool->head->prev;
}

/*
 * do_buff_q_remove - remove a specific buffer from a specific pool
 */
static inline void do_buff_q_remove(struct sdpc_buff_q *pool,
				    struct sdpc_buff *buff)
{
	struct sdpc_buff *prev;
	struct sdpc_buff *next;

	BUG_ON(pool != buff->pool);

	if (buff->next == buff && buff->prev == buff)
		pool->head = NULL;
	else {
		next = buff->next;
		prev = buff->prev;
		next->prev = prev;
		prev->next = next;

		if (pool->head == buff)
			pool->head = next;
	}

	pool->size--;

	buff->pool = NULL;
	buff->next = NULL;
	buff->prev = NULL;
}

/*
 * sdp_buff_q_init - Init a pool drawing its buffers from the main pool
 */
void sdp_buff_q_init(struct sdpc_buff_q *pool)
{
	pool->head = NULL;
	pool->size = 0;
}

/*
 * sdp_buff_q_get - Get a buffer from a specific pool
 */
struct sdpc_buff *sdp_buff_q_get(struct sdpc_buff_q *pool)
{
	return do_buff_q_get(pool, 1, NULL, NULL);
}

/*
 * sdp_buff_q_get_head - Get the buffer at the front of the pool
 */
struct sdpc_buff *sdp_buff_q_get_head(struct sdpc_buff_q *pool)
{
	return do_buff_q_get(pool, 1, NULL, NULL);
}

/*
 * sdp_buff_q_get_tail - Get the buffer at the end of the pool
 */
struct sdpc_buff *sdp_buff_q_get_tail(struct sdpc_buff_q *pool)
{
	return do_buff_q_get(pool, 0, NULL, NULL);
}

/*
 * sdp_buff_q_look_head - look at the buffer at the front of the pool
 */
struct sdpc_buff *sdp_buff_q_look_head(struct sdpc_buff_q *pool)
{
	return sdp_buff_q_look(pool, 1);
}

/*
 * sdp_buff_q_fetch - Get the first matching buffer from the pool
 */
struct sdpc_buff *sdp_buff_q_fetch(struct sdpc_buff_q *pool,
				   int (*test)(struct sdpc_buff *buff,
					       void *arg),
				   void *usr_arg)
{
	struct sdpc_buff *buff;
	int result = 0;
	int counter;

	/*
	 * check to see if there is anything to traverse.
	 */
	if (pool->head)
		/*
		 * lock to prevent corruption of table
		 */
		for (counter = 0, buff = pool->head;
		     counter < pool->size; counter++, buff = buff->next) {
			result = test(buff, usr_arg);
			if (result > 0) {
				do_buff_q_remove(pool, buff);
				return buff;
			}

			if (result < 0)
				break;
		}

	return NULL;
}

/*
 * sdp_buff_q_trav_head - traverse buffers in pool, from the head
 */
int sdp_buff_q_trav_head(struct sdpc_buff_q *pool,
			 int (*trav_func)(struct sdpc_buff *buff,
					  void *arg),
			 void *usr_arg)
{
	struct sdpc_buff *buff;
	int result = 0;
	int counter;

	/*
	 * check to see if there is anything to traverse.
	 */
	if (pool->head)
		/*
		 * lock to prevent corruption of table
		 */
		for (counter = 0, buff = pool->head;
		     counter < pool->size; counter++, buff = buff->next) {

			result = trav_func(buff, usr_arg);
			if (result < 0)
				break;
		}

	return result;
}

/*
 * sdp_buff_q_put - Place a buffer into a specific pool
 */
void sdp_buff_q_put(struct sdpc_buff_q *pool, struct sdpc_buff *buff)
{
	do_buff_q_put(pool, buff, 1);
}

/*
 * sdp_buff_q_put_head - Place a buffer into the head of a specific pool
 */
void sdp_buff_q_put_head(struct sdpc_buff_q *pool, struct sdpc_buff *buff)
{
	do_buff_q_put(pool, buff, 1);
}

/*
 * sdp_buff_q_put_tail - Place a buffer into the tail of a specific pool
 */
void sdp_buff_q_put_tail(struct sdpc_buff_q *pool, struct sdpc_buff *buff)
{
	do_buff_q_put(pool, buff, 0);
}

/*
 * sdp_buff_q_clear_unmap - clear the buffers out of a specific buffer pool
 */
void sdp_buff_q_clear_unmap(struct sdpc_buff_q *pool, struct device *dev,
			    int direction)
{
	struct sdpc_buff *buff;

	while ((buff = do_buff_q_get(pool, 0, NULL, NULL))) {
		if (dev)
			dma_unmap_single(dev, buff->sge.addr,
					 buff->tail - buff->data, direction);

		sdp_buff_pool_put(buff);
	}
}

/*
 * internal data buffer pool manager
 */

/*
 * sdp_buff_pool_release - release allocated buffers from the main pool
 */
void sdp_buff_pool_put(struct sdpc_buff *buff)
{
	kmem_cache_free(main_pool.pool_cache, buff->head);
	kmem_cache_free(main_pool.buff_cache, buff);
}

/*
 * sdp_buff_pool_alloc - allocate more buffers for the main pool
 */
static struct sdpc_buff *sdp_buff_pool_alloc(void)
{
	struct sdpc_buff *buff;
	buff = kmem_cache_alloc(main_pool.buff_cache, GFP_ATOMIC);
	if (!buff) {
		sdp_warn("Failed to allocate buffer.");
		return NULL;
	}

	buff->head = kmem_cache_alloc(main_pool.pool_cache, GFP_ATOMIC);
	if (!buff->head) {
		sdp_warn("Failed to allocate buffer page");
		kmem_cache_free(main_pool.buff_cache, buff);
		return NULL;
	}

	buff->end         = buff->head + PAGE_SIZE;
	buff->data        = buff->head;
	buff->tail        = buff->head;
	buff->sge.lkey    = 0;
	buff->sge.addr    = 0;
	buff->sge.length  = 0;
	buff->pool        = NULL;
	buff->type        = SDP_DESC_TYPE_BUFF;
	buff->release     = sdp_buff_pool_put;
	return buff;
}

/*
 * sdp_buff_pool_init - Initialize the main buffer pool of memory
 */
int sdp_buff_pool_init(void)
{
	int result;

	main_pool.pool_cache = kmem_cache_create("sdp_buff_pool",
						  PAGE_SIZE,
						  0, 0,
						  NULL, NULL);
	if (!main_pool.pool_cache) {
		sdp_warn("Failed to allocate pool cache.");
		result = -ENOMEM;
		goto error_pool;
	}

	main_pool.buff_cache = kmem_cache_create("sdp_buff_desc",
						  sizeof(struct sdpc_buff),
						  0, SLAB_HWCACHE_ALIGN,
						  NULL, NULL);
	if (!main_pool.buff_cache) {
		sdp_warn("Failed to allocate buffer cache.");
		result = -ENOMEM;
		goto error_buff;
	}
	sdp_dbg_init("Main pool initialized.");

	return 0;

	kmem_cache_destroy(main_pool.buff_cache);
error_buff:
	kmem_cache_destroy(main_pool.pool_cache);
error_pool:
	return result;
}

/*
 * sdp_buff_pool_destroy - Destroy the main buffer pool and free its memory
 */
void sdp_buff_pool_destroy(void)
{
	kmem_cache_destroy(main_pool.pool_cache);
	kmem_cache_destroy(main_pool.buff_cache);
	sdp_dbg_init("Main pool destroyed.");
}

/*
 * sdp_buff_pool_get - Get a buffer from the main buffer pool
 */
struct sdpc_buff *sdp_buff_pool_get(void)
{
	struct sdpc_buff *buff;

	buff = sdp_buff_pool_alloc();
	if (!buff)
		return NULL;

	buff->next = NULL;
	buff->prev = NULL;
	buff->pool = NULL;
	/*
	 * main pool specific reset
	 */
	buff->bsdh_hdr = NULL;
	buff->flags = 0;
	buff->sge.lkey = 0;

	buff->data_size = 0;
	buff->wrid = 0;

	return buff;
}

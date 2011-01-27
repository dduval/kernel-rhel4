/*
 * Copyright (c) 2005 SilverStorm Technologies, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials
 * provided with the distribution.
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
 */

#include "rds.h"

struct rds_buf*	rds_alloc_buf(struct rds_ep *ep, int flag)
{
	struct rds_buf *buf;

	buf = kmem_cache_alloc(ep->kmem_cache, flag);
	if (!buf) {
		printk("rds: kmem_cache	<0x%p> returned	NULL\n", ep->kmem_cache);
		return NULL;
	}
	/* data	starts at the end */
	buf->data = (void*)(buf	+ 1);

	buf->magic = RDS_MAGIC_BUF;
	buf->parent_ep = (void*)ep;

	buf->copied = 0;
	buf->state = BUFFER_AVAILABLE;

	return buf;


}
struct rds_buf*	rds_alloc_send_buffer(struct rds_ep *ep, unsigned int flags)

{
	struct rds_buf *buf;

	buf = rds_alloc_buf(ep,	flags);
	if (!buf)
		return NULL;

	buf->loopback =	FALSE;
	buf->optype = OP_SEND;
	buf->sge.length	= ep->buffer_size;
	buf->sge.addr =	dma_map_single(ep->cma_id->device->dma_device,
					buf->data,
					buf->sge.length,
					DMA_TO_DEVICE);

	pci_unmap_addr_set(buf, mapping, buf->sge.addr);

	buf->sge.lkey =	ep->mr->lkey;

	/* Setup the Work Request ( at least most of it) */
	buf->wr.send_wr.next = NULL;
	buf->wr.send_wr.sg_list	= &buf->sge;
	buf->wr.send_wr.num_sge	= 1;
	buf->wr.send_wr.opcode = IB_WR_SEND;
	buf->wr.send_wr.send_flags = 0;
	buf->wr.send_wr.wr_id =	(unsigned long)buf;

	return buf;


}

struct rds_buf*	rds_alloc_recv_buffer(struct rds_ep *ep, unsigned int flags)

{
	struct rds_buf *buf;

	buf = rds_alloc_buf(ep,	flags);
	if (!buf)
		return NULL;

	buf->loopback =	FALSE;
	buf->optype = OP_RECV;
	buf->sge.length	= ep->buffer_size;
	buf->sge.addr =	dma_map_single(ep->cma_id->device->dma_device,
		buf->data,
		buf->sge.length,
		DMA_FROM_DEVICE);
	buf->sge.lkey =	ep->mr->lkey;

	/* Setup the Work Request ( at least most of it) */
	buf->wr.recv_wr.next = NULL;
	buf->wr.recv_wr.sg_list	= &buf->sge;
	buf->wr.recv_wr.num_sge	= 1;
	buf->wr.recv_wr.wr_id =	(unsigned long)buf;

	return buf;


}

void rds_free_buffer(struct rds_buf *buf)
{
	if (buf) {
		if (!(struct rds_ep*)buf->parent_ep ||
			!((struct rds_ep*)buf->parent_ep)->kmem_cache) {
				printk("rds: free buffer, bad ep or ep->kmem_cache!!\n");
				return;
		}
		dma_unmap_single(
			((struct rds_ep*)buf->parent_ep)->cma_id->device->dma_device,
			pci_unmap_addr(buf,mapping),
			buf->sge.length,
			DMA_TO_DEVICE);

		kmem_cache_free(((struct rds_ep*)buf->parent_ep)->kmem_cache,
				buf);
	}
}


void
rds_init_buf_pool(struct rds_buf_pool *buf_pool)
{
	memset(buf_pool, 0, sizeof (*buf_pool));

	spin_lock_init(&buf_pool->lock);

	INIT_LIST_HEAD(&buf_pool->buffer_list);
	INIT_LIST_HEAD(&buf_pool->coalesce_list);
	init_waitqueue_head(&buf_pool->event);

	//buf_pool->buffer_size	= ep->buffer_size;
	atomic_set(&buf_pool->num_posted, 0);
}

void
rds_free_pool(struct rds_buf_pool *pool)
{
	struct rds_buf *buf;
	if (atomic_read(&pool->num_posted) ) {
		wait_event(pool->event,	!atomic_read(&pool->num_posted));
	}

	while (!list_empty(&pool->buffer_list)) {
		buf = list_entry(pool->buffer_list.next,
		struct rds_buf,	list_item);
		list_del(&buf->list_item);
		rds_free_buffer(buf);
	}
}

int rds_alloc_send_pool(struct rds_ep *ep)
{
	int i;
	struct rds_buf *buf;

	/* Allocate Send Buffer Pool */
	ep->send_pool.buffer_size = ep->buffer_size;

	for ( i=0; i < ep->max_send_bufs; i++) {
		buf = rds_alloc_send_buffer(ep,	GFP_KERNEL);
		if ( !buf) {
			printk("error in allocating send pool\n");
			goto error;
		}
		list_add_tail(&(buf->list_item), &ep->send_pool.buffer_list);
		atomic_inc(&ep->send_pool.num_available);
		ep->send_pool.num_buffers++;

	}
	return 0;
error:
	rds_free_pool(&ep->send_pool);
	return -EFAULT;
}


int rds_alloc_recv_pool(struct rds_ep *ep)
{
	int i;

	struct rds_buf *buf;

	/* Allocate send buffer pool */

	ep->recv_pool.buffer_size = ep->buffer_size;
	ep->recv_pool.coalesce_count = ep->recv_pool.coalesce_max;

	for ( i=0; i < ep->max_recv_bufs; i++) {
		buf = rds_alloc_recv_buffer(ep,	GFP_KERNEL);
		if ( !buf) {
			printk("error in allocating recv pool\n");
			goto error;
		}
		list_add_tail(&(buf->list_item), &ep->recv_pool.buffer_list);
		//ep->recv_pool.num_buffers++;

	}
	return 0;
error:
	rds_free_pool(&ep->recv_pool);
	return -1;

}

struct rds_buf *
rds_alloc_send_buffer_lpbk(struct rds_ep *ep, unsigned int flags)
{
	struct rds_buf *buf;

	buf = rds_alloc_buf(ep,	flags);
	if (!buf) {
		printk(" error allocating loopback buffer\n");
		return NULL;
	}
	buf->loopback =	TRUE;
	return buf;

}

void rds_put_send_list(struct rds_ep *ep,
			struct list_head *send_list,
			u8 avail )
{
	struct rds_buf *buf;

	while (!list_empty(send_list)) {
		buf = list_entry(send_list->next,
		struct rds_buf,	list_item);
		list_del(&buf->list_item);

		if (avail) {
			buf->state = BUFFER_AVAILABLE;
			atomic_inc(&ep->send_pool.num_available);
		}
		list_add_tail(&buf->list_item, &ep->send_pool.buffer_list);
	}

}

void rds_put_send_list_lpbk(struct rds_ep *ep,
			struct list_head *send_list )
{
	struct rds_buf *buf;

	while (!list_empty(send_list)) {
		buf = list_entry(send_list->next,
		struct rds_buf,	list_item);
		list_del(&buf->list_item);

		rds_free_buffer(buf);
	}

}

int rds_get_send_list(struct rds_ep *ep, size_t	length,
			struct list_head *send_list, int *count)
{
	unsigned long flags;
	int pkts;
	struct rds_buf *buf;
	int i;
	struct list_head *entry, *n;

	spin_lock_irqsave(&ep->lock, flags);

	if ( length <= params.mtu)
		pkts = 1;
	else {
		pkts = (length/params.mtu);
		if ( (length % params.mtu) > 0)
			pkts++;
	}

	if (atomic_read(&(ep->send_pool.num_available))	< pkts) {

		spin_unlock_irqrestore(&ep->lock, flags);

		if (!rds_wait_for_space(ep, pkts)) {
			*count = 0;
			return 0;
		}

		spin_lock_irqsave(&ep->lock, flags);
	}

	i=pkts;

	list_for_each_safe(entry, n, &ep->send_pool.buffer_list) {
		if (!i)
			break;
		buf = list_entry(entry,	struct rds_buf,	list_item);
		if (buf->state != BUFFER_AVAILABLE)
			goto cleanup;

		buf->state = BUFFER_SEND_PENDING;
		buf->wr.send_wr.next = NULL;
		atomic_dec(&ep->send_pool.num_available);

		list_del(entry);
		list_add_tail(entry, send_list);
		i--;

	}
	*count = pkts;

	goto done;

cleanup:
	rds_put_send_list(ep, send_list, TRUE);

	*count = 0;

done:
	spin_unlock_irqrestore(&ep->lock, flags);
	return 0;
}

int rds_get_send_list_lpbk(struct rds_ep *ep, size_t length,
			struct list_head *send_list, int *count)
{
	int pkts;
	struct rds_buf *buf;
	int i;

	if ( length <= params.mtu)
		pkts = 1;
	else {
		pkts = (length/params.mtu);
		if ( (length % params.mtu) > 0)
			pkts++;
	}

	for ( i=0; i < pkts; i++) {
		buf = rds_alloc_send_buffer_lpbk(ep, GFP_KERNEL);
		if ( !buf) {
			printk("error in allocating recv pool\n");
			goto error;
		}
		list_add_tail(&(buf->list_item), send_list);

	}

	*count = pkts;

	goto done;

error:
	rds_put_send_list_lpbk(ep, send_list);

	*count = 0;

done:
	return 0;
}

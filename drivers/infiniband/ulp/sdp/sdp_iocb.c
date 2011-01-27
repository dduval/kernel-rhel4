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
 * $Id: sdp_iocb.c 3079 2005-08-14 13:37:59Z mst $
 */

#include <linux/pagemap.h>
#include "sdp_main.h"

static kmem_cache_t *sdp_iocb_cache = NULL;

static void sdp_copy_one_page(struct page *from, struct page* to, 
		      unsigned long iocb_addr, size_t iocb_size,
		      unsigned long uaddr)
{
	size_t size_left = iocb_addr + iocb_size - uaddr;
	size_t size = min(size_left, (size_t)PAGE_SIZE);
	unsigned long offset = uaddr % PAGE_SIZE;
	unsigned long flags;

	void* fptr;
	void* tptr;

	local_irq_save(flags);
	fptr = kmap_atomic(from, KM_IRQ0);
	tptr = kmap_atomic(to, KM_IRQ1);

	memcpy(tptr + offset, fptr + offset, size);

	kunmap_atomic(tptr, KM_IRQ1);
	kunmap_atomic(fptr, KM_IRQ0);
	local_irq_restore(flags);
	set_page_dirty_lock(to);
}

/*
 * sdp_iocb_unlock - unlock the memory for an IOCB
 * Copy if pages moved since.
 * TODO: is this needed?
 */
void sdp_iocb_unlock(struct sdpc_iocb *iocb)
{
 	int result;
	struct page ** pages = NULL;
	unsigned long uaddr;
	int i;

	if (!(iocb->flags & SDP_IOCB_F_LOCKED))
		return;

	/* For read, unlock and we are done */
	if (!(iocb->flags & SDP_IOCB_F_RECV)) {
		for (i = 0;i < iocb->page_count; ++i)
			put_page(iocb->page_array[i]);
		goto done;
	}
 
	/* For write, we must check the virtual pages did not get remapped */
 
	/* As an optimisation (to avoid scanning the vma tree each time),
	 * try to get all pages in one go. */
	/* TODO: use cache for allocations? Allocate by chunks? */
 
	pages = kmalloc(sizeof(struct page *) * iocb->page_count, GFP_KERNEL);
	down_read(&iocb->mm->mmap_sem);
	if (pages) {
		result = get_user_pages(iocb->tsk, iocb->mm, iocb->addr,
					iocb->page_count, 1, 0, pages, NULL);
		if (result != iocb->page_count) {
			kfree(pages);
			pages = NULL;
		}
	}
	for (i = 0, uaddr = iocb->addr; i < iocb->page_count;
	     ++i, uaddr = (uaddr & PAGE_MASK) + PAGE_SIZE)
	{
		struct page* page;
		set_page_dirty_lock(iocb->page_array[i]);

		if (pages)
			page = pages[i];
		else {
			result = get_user_pages(iocb->tsk, iocb->mm,
						uaddr & PAGE_MASK,
						1 , 1, 0, &page, NULL);
			if (result != 1) {
				page = NULL;
			}
		}
		if (page && iocb->page_array[i] != page)
			sdp_copy_one_page(iocb->page_array[i], page,
					  iocb->addr, iocb->size, uaddr);
		if (page)
			put_page(page);
		put_page(iocb->page_array[i]);
 	}
	up_read(&iocb->mm->mmap_sem);
	if (pages)
		kfree(pages);
 
done:
	kfree(iocb->page_array);
 	kfree(iocb->addr_array);

	iocb->page_array = NULL;
 	iocb->addr_array = NULL;
	iocb->mm = NULL;
	iocb->tsk = NULL;
	iocb->flags &= ~SDP_IOCB_F_LOCKED;
}

/*
 * sdp_iocb_lock - lock the memory for an IOCB
 * We do not take a reference on the mm, AIO handles this for us.
 */
int sdp_iocb_lock(struct sdpc_iocb *iocb)
{
	int result = -ENOMEM;
	unsigned long addr;
	size_t size;
	int i;

 	/*
	 * iocb->addr - buffer start address
	 * iocb->size - buffer length
	 * addr       - page aligned
	 * size       - page multiple
 	 */
 	addr = iocb->addr & PAGE_MASK;
	size = PAGE_ALIGN(iocb->size + (iocb->addr & ~PAGE_MASK));
 
	iocb->page_offset = iocb->addr - addr;
	
 	iocb->page_count = size >> PAGE_SHIFT;
 	/*
	 * create array to hold page value which are later needed to register
	 * the buffer with the HCA
 	 */
 
	/* TODO: use cache for allocations? Allocate by chunks? */
	iocb->addr_array = kmalloc(sizeof(u64) * iocb->page_count, GFP_KERNEL);
	if (!iocb->addr_array)
		goto err_addr;
 
	iocb->page_array = kmalloc(sizeof(struct page *) * iocb->page_count,
				   GFP_KERNEL);
	if (!iocb->page_array)
		goto err_page;
 
	down_read(&current->mm->mmap_sem);
 
        result = get_user_pages(current, current->mm,
				iocb->addr, iocb->page_count,
			      !!(iocb->flags & SDP_IOCB_F_RECV), 0,
			      iocb->page_array, NULL);

	up_read(&current->mm->mmap_sem);

	if (result != iocb->page_count) {
		sdp_dbg_err("unable to lock <%lx:%Zu> error <%d> <%d>",
			    iocb->addr, iocb->size, result, iocb->page_count);
		goto err_get;
	}
 
	iocb->flags |= SDP_IOCB_F_LOCKED;
	iocb->mm     = current->mm;
	iocb->tsk    = current;
 
 
	for (i = 0; i< iocb->page_count; ++i) {
		iocb->addr_array[i] = page_to_phys(iocb->page_array[i]);
 	}
 
 	return 0;
 
err_get:
	kfree(iocb->page_array);
err_page:
	kfree(iocb->addr_array);
err_addr:
 	return result;
}

/*
 * IOCB memory registration functions
 */

/*
 * sdp_iocb_register - register an IOCBs memory for advertisment
 */
int sdp_iocb_register(struct sdpc_iocb *iocb, struct sdp_sock *conn)
{
	int result;

	/*
	 * register only once.
	 */
	if (iocb->flags & SDP_IOCB_F_REG)
		return 0;
	/*
	 * prime io address with physical address of first byte?
	 */
	iocb->io_addr = iocb->addr_array[0];
	/*
	 * register IOCBs physical memory
	 */
	iocb->mem = ib_fmr_pool_map_phys(conn->fmr_pool,
					 iocb->addr_array,
					 iocb->page_count,
					 &iocb->io_addr);
	if (IS_ERR(iocb->mem)) {
		result = (int)PTR_ERR(iocb->mem);

		if (result != -EAGAIN)
			sdp_dbg_err("Error <%d> fmr_pool_map_phys <%d:%d:%d>",
				    result,
				    iocb->len,
				    iocb->page_count,
				    iocb->page_offset);
		goto error;
	}

	iocb->l_key = iocb->mem->fmr->lkey;
	iocb->r_key = iocb->mem->fmr->rkey;
	/*
	 * some data may have already been consumed, adjust the io address
	 * to take this into account
	 */
	iocb->io_addr += iocb->page_offset;
	iocb->io_addr += iocb->post;
	iocb->flags   |= SDP_IOCB_F_REG;

	return 0;
error:
	iocb->io_addr = 0;

	return result;
}

/*
 * sdp_iocb_release - unregister an IOCBs memory
 */
void sdp_iocb_release(struct sdpc_iocb *iocb)
{
	int result;

	if (!(iocb->flags & SDP_IOCB_F_REG))
		return;

	result = ib_fmr_pool_unmap(iocb->mem);
	if (result < 0)
		sdp_dbg_err("Error <%d> releasing IOCB <%d> memory <%ld>",
			    result, iocb->key, iocb->addr);

	iocb->flags &= ~(SDP_IOCB_F_REG);
}

/*
 * do_iocb_complete - complete an IOCB for real in thread context
 */
static void do_iocb_complete(void *arg)
{
	struct sdpc_iocb *iocb = (struct sdpc_iocb *)arg;
	long value;
	/*
	 * release memory
	 */
	sdp_iocb_release(iocb);
	/*
	 * unlock now, after aio_complete the mm reference will be released.
	 */
	sdp_iocb_unlock(iocb);
	/*
	 * callback to complete IOCB
	 */
	value = (iocb->post > 0) ? iocb->post : iocb->status;

	sdp_dbg_data(NULL, "IOCB complete. <%d:%d:%08lx> value <%ld>",
		     iocb->req->ki_users, iocb->req->ki_key,
		     iocb->req->ki_flags, value);
	/*
	 * valid result can be 0 or 1 for complete so
	 * we ignore the value.
	 */
	(void)aio_complete(iocb->req, value, 0);
	/*
	 * delete IOCB
	 */
	sdp_iocb_destroy(iocb);
}

/*
 * sdp_iocb_complete - complete an IOCB
 */
void sdp_iocb_complete(struct sdpc_iocb *iocb, ssize_t status)
{
	iocb->status = status;

	if (in_atomic() || irqs_disabled()) {
		INIT_WORK(&iocb->completion, do_iocb_complete, (void *)iocb);
		schedule_work(&iocb->completion);
	} else
		do_iocb_complete(iocb);
}

/*
 * IOCB object managment
 */

/*
 * sdp_iocb_q_remove - remove the object from the table
 */
void sdp_iocb_q_remove(struct sdpc_iocb *iocb)
{
	struct sdpc_iocb_q *table;
	struct sdpc_iocb *next;
	struct sdpc_iocb *prev;

	table = iocb->table;

	if (iocb->next == iocb && iocb->prev == iocb)
		table->head = NULL;
	else {
		next = iocb->next;
		prev = iocb->prev;
		next->prev = prev;
		prev->next = next;

		if (table->head == iocb)
			table->head = next;
	}

	table->size--;

	iocb->table = NULL;
	iocb->next = NULL;
	iocb->prev = NULL;
}

/*
 * sdp_iocb_q_lookup - find an iocb based on key, without removing
 */
struct sdpc_iocb *sdp_iocb_q_lookup(struct sdpc_iocb_q *table, u32 key)
{
	struct sdpc_iocb *iocb = NULL;
	int counter;

	for (counter = 0, iocb = table->head; counter < table->size;
	     counter++, iocb = iocb->next)
		if (iocb->key == key)
			return iocb;

	return NULL;
}

/*
 * sdp_iocb_create - create an IOCB object
 */
struct sdpc_iocb *sdp_iocb_create(void)
{
	struct sdpc_iocb *iocb;

	iocb = kmem_cache_alloc(sdp_iocb_cache, SLAB_KERNEL);
	if (iocb) {
		memset(iocb, 0, sizeof(struct sdpc_iocb));
		/*
		 * non-zero initialization
		 */
		iocb->key     = SDP_IOCB_KEY_INVALID;
		iocb->type    = SDP_DESC_TYPE_IOCB;
		iocb->release = sdp_iocb_destroy;
	}

	return iocb;
}

/*
 * sdp_iocb_destroy - destroy an IOCB object
 */
void sdp_iocb_destroy(struct sdpc_iocb *iocb)
{
	if (!iocb)
		return;

	BUG_ON(iocb->next || iocb->prev);
	/*
	 * release iocb registered memory
	 */
	sdp_iocb_release(iocb);
	/*
	 * unlock IOCB memory
	 */
	sdp_iocb_unlock(iocb);
	/*
	 * array dealloc
	 */
	if (iocb->page_array)
		kfree(iocb->page_array);

	if (iocb->addr_array)
		kfree(iocb->addr_array);
	/*
	 * clear IOCB to check for usage after free...
	 */
#if 0
	memset(iocb, 0, sizeof(struct sdpc_iocb));
#endif
	/*
	 * return the object to its cache
	 */
	kmem_cache_free(sdp_iocb_cache, iocb);
}

/*
 * sdp_iocb_q_look - get, without removing, the object at the head
 */
struct sdpc_iocb *sdp_iocb_q_look(struct sdpc_iocb_q *table)
{
	return table->head;
}

/*
 * sdp_iocb_q_get - get, and remove, the object at the tables head
 */
static struct sdpc_iocb *sdp_iocb_q_get(struct sdpc_iocb_q *table, int head)
{
	struct sdpc_iocb *iocb;
	struct sdpc_iocb *next;
	struct sdpc_iocb *prev;

	if (!table->head)
		return NULL;

	if (head)
		iocb = table->head;
	else
		iocb = table->head->prev;

	if (iocb->next == iocb && iocb->prev == iocb)
		table->head = NULL;
	else {
		next = iocb->next;
		prev = iocb->prev;
		next->prev = prev;
		prev->next = next;

		table->head = next;
	}

	table->size--;

	iocb->table = NULL;
	iocb->next = NULL;
	iocb->prev = NULL;

	return iocb;
}

/*
 * sdp_iocb_q_put - put the IOCB object at the tables tail
 */
static void sdp_iocb_q_put(struct sdpc_iocb_q *table,
			   struct sdpc_iocb *iocb,
			   int head)
{
	struct sdpc_iocb *next;
	struct sdpc_iocb *prev;

	BUG_ON(iocb->table);

	if (!table->head) {
		iocb->next = iocb;
		iocb->prev = iocb;
		table->head = iocb;
	} else {
		next = table->head;
		prev = next->prev;

		prev->next = iocb;
		iocb->prev = prev;
		iocb->next = next;
		next->prev = iocb;

		if (head)
			table->head = iocb;
	}

	table->size++;

	iocb->table = table;
}

/*
 * sdp_iocb_q_get_tail - get an IOCB object from the tables tail
 */
struct sdpc_iocb *sdp_iocb_q_get_tail(struct sdpc_iocb_q *table)
{
	return sdp_iocb_q_get(table, 0);
}

/*
 * sdp_iocb_q_get_head - get an IOCB object from the tables head
 */
struct sdpc_iocb *sdp_iocb_q_get_head(struct sdpc_iocb_q *table)
{
	return sdp_iocb_q_get(table, 1);
}

/*
 * sdp_iocb_q_put_tail - put the IOCB object at the tables tail
 */
void sdp_iocb_q_put_tail(struct sdpc_iocb_q *table, struct sdpc_iocb *iocb)
{
	sdp_iocb_q_put(table, iocb, 0);
}

/*
 * sdp_iocb_q_put_head - put the IOCB object at the tables head
 */
void sdp_iocb_q_put_head(struct sdpc_iocb_q *table, struct sdpc_iocb *iocb)
{
	sdp_iocb_q_put(table, iocb, 1);
}

/*
 * sdp_iocb_q_cancel - cancel all outstanding AIOs in a queue
 */
void sdp_iocb_q_cancel(struct sdpc_iocb_q *table, u32 mask, ssize_t comp)
{
	struct sdpc_iocb *iocb;
	struct sdpc_iocb *next;
	int counter;
	int total;

	/*
	 * loop through IOCBs, completing each one with either a partial data
	 * result, or a cancelled error.
	 */
	for (counter = 0, iocb = table->head, total = table->size;
	     counter < total; counter++) {
		next = iocb->next;

		if ((iocb->flags & mask) || mask == SDP_IOCB_F_ALL) {
			sdp_dbg_err("IOCB <%d> cancel <%Zu> flag <%04x> "
				    "size <%Zu:%d:%d>",
				    iocb->key, comp, iocb->flags, iocb->size,
				    iocb->post, iocb->len);

			sdp_iocb_q_remove(iocb);
			sdp_iocb_complete(iocb, comp);
		}

		iocb = next;
	}
}

/*
 * sdp_iocb_q_init - initialize a new empty IOCB table
 */
void sdp_iocb_q_init(struct sdpc_iocb_q *table)
{
	table->head = NULL;
	table->size = 0;
}

/*
 * sdp_iocb_q_clear - clear the contents of an IOCB table
 */
void sdp_iocb_q_clear(struct sdpc_iocb_q *table)
{
	struct sdpc_iocb *iocb;
	/*
	 * drain the table of any objects
	 */
	while ((iocb = sdp_iocb_q_get_head(table)))
		sdp_iocb_destroy(iocb);
}

/*
 * sdp_main_iocb_init - initialize the advertisment caches
 */
int sdp_main_iocb_init(void)
{
	sdp_dbg_init("IOCB cache initialization.");

	if (sdp_iocb_cache) {
		sdp_warn("IOCB caches already initialized.");
		return -EINVAL;
	}

	sdp_iocb_cache = kmem_cache_create("sdp_iocb",
					     sizeof(struct sdpc_iocb),
					     0, SLAB_HWCACHE_ALIGN, NULL,
					     NULL);
	if (!sdp_iocb_cache)
		return -ENOMEM;

	return 0;
}

/*
 * sdp_main_iocb_cleanup - cleanup the advertisment caches
 */
void sdp_main_iocb_cleanup(void)
{
	sdp_dbg_init("IOCB cache cleanup.");
	/*
	 * cleanup the caches
	 */
	kmem_cache_destroy(sdp_iocb_cache);
	/*
	 * null out entries.
	 */
	sdp_iocb_cache = NULL;
}

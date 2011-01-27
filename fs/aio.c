/*
 *	An async IO implementation for Linux
 *	Written by Benjamin LaHaise <bcrl@redhat.com>
 *
 *	Implements an efficient asynchronous io interface.
 *
 *	Copyright 2000, 2001, 2002 Red Hat, Inc.  All Rights Reserved.
 *
 *	See ../COPYING for licensing terms.
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/aio_abi.h>
#include <linux/module.h>

#define DEBUG 0

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/aio.h>
#include <linux/highmem.h>
#include <linux/workqueue.h>
#include <linux/security.h>

#include <asm/kmap_types.h>
#include <asm/uaccess.h>
#include <asm/mmu_context.h>

#if DEBUG > 1
#define dprintk		printk
#else
#define dprintk(x...)	do { ; } while (0)
#endif

long aio_run = 0; /* for testing only */
long aio_wakeups = 0; /* for testing only */

/*------ sysctl variables----*/
atomic_t aio_nr = ATOMIC_INIT(0);	/* current system wide number of aio requests */
unsigned aio_max_nr = 0x10000;	/* system wide maximum number of aio requests */
/*----end sysctl variables---*/

static kmem_cache_t	*kiocb_cachep;
static kmem_cache_t	*kioctx_cachep;

static struct workqueue_struct *aio_wq;

/* Used for rare fput completion. */
static void aio_fput_routine(void *);
static DECLARE_WORK(fput_work, aio_fput_routine, NULL);

static spinlock_t	fput_lock = SPIN_LOCK_UNLOCKED;
LIST_HEAD(fput_head);

static void aio_kick_handler(void *);

/* aio_setup
 *	Creates the slab caches used by the aio routines, panic on
 *	failure as this is done early during the boot sequence.
 */
static int __init aio_setup(void)
{
	kiocb_cachep = kmem_cache_create("kiocb", sizeof(struct kiocb),
				0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	kioctx_cachep = kmem_cache_create("kioctx", sizeof(struct kioctx),
				0, SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);

	aio_wq = create_workqueue("aio");

	pr_debug("aio_setup: sizeof(struct page) = %d\n", (int)sizeof(struct page));

	return 0;
}

static void aio_free_ring(struct kioctx *ctx)
{
	struct aio_ring_info *info = &ctx->ring_info;
	long i;

	for (i=0; i<info->nr_pages; i++)
		put_page(info->ring_pages[i]);

	if (info->mmap_size) {
		down_write(&ctx->mm->mmap_sem);
		do_munmap(ctx->mm, info->mmap_base, info->mmap_size);
		up_write(&ctx->mm->mmap_sem);
	}

	if (info->ring_pages && info->ring_pages != info->internal_pages)
		kfree(info->ring_pages);
	info->ring_pages = NULL;
	info->nr = 0;
}

static int aio_setup_ring(struct kioctx *ctx)
{
	struct aio_ring *ring;
	struct aio_ring_info *info = &ctx->ring_info;
	unsigned nr_events = ctx->max_reqs;
	unsigned long size;
	int nr_pages;

	/* Compensate for the ring buffer's head/tail overlap entry */
	nr_events += 2;	/* 1 is required, 2 for good luck */

	size = sizeof(struct aio_ring);
	size += sizeof(struct io_event) * nr_events;
	nr_pages = (size + PAGE_SIZE-1) >> PAGE_SHIFT;

	if (nr_pages < 0)
		return -EINVAL;

	nr_events = (PAGE_SIZE * nr_pages - sizeof(struct aio_ring)) / sizeof(struct io_event);

	info->nr = 0;
	info->ring_pages = info->internal_pages;
	if (nr_pages > AIO_RING_PAGES) {
		info->ring_pages = kmalloc(sizeof(struct page *) * nr_pages, GFP_KERNEL);
		if (!info->ring_pages)
			return -ENOMEM;
		memset(info->ring_pages, 0, sizeof(struct page *) * nr_pages);
	}

	info->mmap_size = nr_pages * PAGE_SIZE;
	dprintk("attempting mmap of %lu bytes\n", info->mmap_size);
	down_write(&ctx->mm->mmap_sem);
	info->mmap_base = do_mmap(NULL, 0, info->mmap_size, 
				  PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE,
				  0);
	if (IS_ERR((void *)info->mmap_base)) {
		up_write(&ctx->mm->mmap_sem);
		printk("mmap err: %ld\n", -info->mmap_base);
		info->mmap_size = 0;
		aio_free_ring(ctx);
		return -EAGAIN;
	}

	dprintk("mmap address: 0x%08lx\n", info->mmap_base);
	info->nr_pages = get_user_pages(current, ctx->mm,
					info->mmap_base, nr_pages, 
					1, 0, info->ring_pages, NULL);
	up_write(&ctx->mm->mmap_sem);

	if (unlikely(info->nr_pages != nr_pages)) {
		aio_free_ring(ctx);
		return -EAGAIN;
	}

	ctx->user_id = info->mmap_base;

	info->nr = nr_events;		/* trusted copy */

	ring = kmap_atomic(info->ring_pages[0], KM_USER0);
	ring->nr = nr_events;	/* user copy */
	ring->id = ctx->user_id;
	ring->head = ring->tail = 0;
	ring->magic = AIO_RING_MAGIC;
	ring->compat_features = AIO_RING_COMPAT_FEATURES;
	ring->incompat_features = AIO_RING_INCOMPAT_FEATURES;
	ring->header_length = sizeof(struct aio_ring);
	kunmap_atomic(ring, KM_USER0);

	return 0;
}


/* aio_ring_event: returns a pointer to the event at the given index from
 * kmap_atomic(, km).  Release the pointer with put_aio_ring_event();
 */
#define AIO_EVENTS_PER_PAGE	(PAGE_SIZE / sizeof(struct io_event))
#define AIO_EVENTS_FIRST_PAGE	((PAGE_SIZE - sizeof(struct aio_ring)) / sizeof(struct io_event))
#define AIO_EVENTS_OFFSET	(AIO_EVENTS_PER_PAGE - AIO_EVENTS_FIRST_PAGE)

#define aio_ring_event(info, nr, km) ({					\
	unsigned pos = (nr) + AIO_EVENTS_OFFSET;			\
	struct io_event *__event;					\
	__event = kmap_atomic(						\
			(info)->ring_pages[pos / AIO_EVENTS_PER_PAGE], km); \
	__event += pos % AIO_EVENTS_PER_PAGE;				\
	__event;							\
})

#define put_aio_ring_event(event, km) do {	\
	struct io_event *__event = (event);	\
	(void)__event;				\
	kunmap_atomic((void *)((unsigned long)__event & PAGE_MASK), km); \
} while(0)

/* ioctx_alloc
 *	Allocates and initializes an ioctx.  Returns an ERR_PTR if it failed.
 */
static struct kioctx *ioctx_alloc(unsigned nr_events)
{
	struct mm_struct *mm;
	struct kioctx *ctx;

	/* Prevent overflows */
	if ((nr_events > (0x10000000U / sizeof(struct io_event))) ||
	    (nr_events > (0x10000000U / sizeof(struct kiocb)))) {
		pr_debug("ENOMEM: nr_events too high\n");
		return ERR_PTR(-EINVAL);
	}

	if (nr_events > aio_max_nr)
		return ERR_PTR(-EAGAIN);

	ctx = kmem_cache_alloc(kioctx_cachep, GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	memset(ctx, 0, sizeof(*ctx));
	ctx->max_reqs = nr_events;
	mm = ctx->mm = current->mm;
	atomic_inc(&mm->mm_count);

	atomic_set(&ctx->users, 1);
	spin_lock_init(&ctx->ctx_lock);
	spin_lock_init(&ctx->ring_info.ring_lock);
	init_waitqueue_head(&ctx->wait);

	INIT_LIST_HEAD(&ctx->active_reqs);
	INIT_LIST_HEAD(&ctx->run_list);
	INIT_WORK(&ctx->wq, aio_kick_handler, ctx);

	if (aio_setup_ring(ctx) < 0)
		goto out_freectx;

	/* limit the number of system wide aios */
	atomic_add(ctx->max_reqs, &aio_nr);	/* undone by __put_ioctx */
	if (unlikely(atomic_read(&aio_nr) > aio_max_nr))
		goto out_cleanup;

	/* now link into global list.  kludge.  FIXME */
	write_lock(&mm->ioctx_list_lock);
	ctx->next = mm->ioctx_list;
	mm->ioctx_list = ctx;
	write_unlock(&mm->ioctx_list_lock);

	dprintk("aio: allocated ioctx %p[%ld]: mm=%p mask=0x%x\n",
		ctx, ctx->user_id, current->mm, ctx->ring_info.nr);
	return ctx;

out_cleanup:
	atomic_sub(ctx->max_reqs, &aio_nr);
	ctx->max_reqs = 0;	/* prevent __put_ioctx from sub'ing aio_nr */
	__put_ioctx(ctx);
	return ERR_PTR(-EAGAIN);

out_freectx:
	mmdrop(mm);
	kmem_cache_free(kioctx_cachep, ctx);
	ctx = ERR_PTR(-ENOMEM);

	dprintk("aio: error allocating ioctx %p\n", ctx);
	return ctx;
}

/* aio_cancel_all
 *	Cancels all outstanding aio requests on an aio context.  Used 
 *	when the processes owning a context have all exited to encourage 
 *	the rapid destruction of the kioctx.
 */
static void aio_cancel_all(struct kioctx *ctx)
{
	int (*cancel)(struct kiocb *, struct io_event *);
	struct io_event res;
	spin_lock_irq(&ctx->ctx_lock);
	ctx->dead = 1;
	while (!list_empty(&ctx->active_reqs)) {
		struct list_head *pos = ctx->active_reqs.next;
		struct kiocb *iocb = list_kiocb(pos);
		list_del_init(&iocb->ki_list);
		cancel = iocb->ki_cancel;
		kiocbSetCancelled(iocb);
		if (cancel) {
			iocb->ki_users++;
			spin_unlock_irq(&ctx->ctx_lock);
			cancel(iocb, &res);
			spin_lock_irq(&ctx->ctx_lock);
		}
	}
	spin_unlock_irq(&ctx->ctx_lock);
}

void wait_for_all_aios(struct kioctx *ctx)
{
	struct task_struct *tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);

	if (!ctx->reqs_active)
		return;

	add_wait_queue(&ctx->wait, &wait);
	set_task_state(tsk, TASK_UNINTERRUPTIBLE);
	while (ctx->reqs_active) {
		schedule();
		set_task_state(tsk, TASK_UNINTERRUPTIBLE);
	}
	__set_task_state(tsk, TASK_RUNNING);
	remove_wait_queue(&ctx->wait, &wait);
}

/* wait_on_sync_kiocb:
 *	Waits on the given sync kiocb to complete.
 */
ssize_t fastcall wait_on_sync_kiocb(struct kiocb *iocb)
{
	while (iocb->ki_users) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (!iocb->ki_users)
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);
	return iocb->ki_user_data;
}

/* exit_aio: called when the last user of mm goes away.  At this point, 
 * there is no way for any new requests to be submited or any of the 
 * io_* syscalls to be called on the context.  However, there may be 
 * outstanding requests which hold references to the context; as they 
 * go away, they will call put_ioctx and release any pinned memory
 * associated with the request (held via struct page * references).
 */
void fastcall exit_aio(struct mm_struct *mm)
{
	struct kioctx *ctx = mm->ioctx_list;
	mm->ioctx_list = NULL;
	while (ctx) {
		struct kioctx *next = ctx->next;
		ctx->next = NULL;
		aio_cancel_all(ctx);

		wait_for_all_aios(ctx);
		/*
		 * this is an overkill, but ensures we don't leave
		 * the ctx on the aio_wq
		 */
		flush_workqueue(aio_wq);

		if (1 != atomic_read(&ctx->users))
			printk(KERN_DEBUG
				"exit_aio:ioctx still alive: %d %d %d\n",
				atomic_read(&ctx->users), ctx->dead,
				ctx->reqs_active);
		put_ioctx(ctx);
		ctx = next;
	}
}

/* __put_ioctx
 *	Called when the last user of an aio context has gone away,
 *	and the struct needs to be freed.
 */
void fastcall __put_ioctx(struct kioctx *ctx)
{
	unsigned nr_events = ctx->max_reqs;

	if (unlikely(ctx->reqs_active))
		BUG();

	cancel_delayed_work(&ctx->wq);
	flush_workqueue(aio_wq);
	aio_free_ring(ctx);
	mmdrop(ctx->mm);
	ctx->mm = NULL;
	pr_debug("__put_ioctx: freeing %p\n", ctx);
	kmem_cache_free(kioctx_cachep, ctx);

	atomic_sub(nr_events, &aio_nr);
}

/* aio_get_req
 *	Allocate a slot for an aio request.  Increments the users count
 * of the kioctx so that the kioctx stays around until all requests are
 * complete.  Returns NULL if no requests are free.
 *
 * Returns with kiocb->users set to 2.  The io submit code path holds
 * an extra reference while submitting the i/o.
 * This prevents races between the aio code path referencing the
 * req (after submitting it) and aio_complete() freeing the req.
 */
static struct kiocb *FASTCALL(__aio_get_req(struct kioctx *ctx));
static struct kiocb fastcall *__aio_get_req(struct kioctx *ctx)
{
	struct kiocb *req = NULL;
	struct aio_ring *ring;
	int okay = 0;

	req = kmem_cache_alloc(kiocb_cachep, GFP_KERNEL);
	if (unlikely(!req))
		return NULL;

	req->ki_flags = 1 << KIF_LOCKED;
	req->ki_users = 2;
	req->ki_key = 0;
	req->ki_ctx = ctx;
	req->ki_cancel = NULL;
	req->ki_retry = NULL;
	req->ki_obj.user = NULL;
	req->ki_dtor = NULL;
	req->private = NULL;
	INIT_LIST_HEAD(&req->ki_run_list);

	/* Check if the completion queue has enough free space to
	 * accept an event from this io.
	 */
	spin_lock_irq(&ctx->ctx_lock);
	ring = kmap_atomic(ctx->ring_info.ring_pages[0], KM_USER0);
	if (ctx->reqs_active < aio_ring_avail(&ctx->ring_info, ring)) {
		list_add(&req->ki_list, &ctx->active_reqs);
		get_ioctx(ctx);
		ctx->reqs_active++;
		okay = 1;
	}
	kunmap_atomic(ring, KM_USER0);
	spin_unlock_irq(&ctx->ctx_lock);

	if (!okay) {
		kmem_cache_free(kiocb_cachep, req);
		req = NULL;
	}

	return req;
}

static inline struct kiocb *aio_get_req(struct kioctx *ctx)
{
	struct kiocb *req;
	/* Handle a potential starvation case -- should be exceedingly rare as 
	 * requests will be stuck on fput_head only if the aio_fput_routine is 
	 * delayed and the requests were the last user of the struct file.
	 */
	req = __aio_get_req(ctx);
	if (unlikely(NULL == req)) {
		aio_fput_routine(NULL);
		req = __aio_get_req(ctx);
	}
	return req;
}

static inline void really_put_req(struct kioctx *ctx, struct kiocb *req)
{
	if (req->ki_dtor)
		req->ki_dtor(req);
	req->ki_ctx = NULL;
	req->ki_filp = NULL;
	req->ki_obj.user = NULL;
	req->ki_dtor = NULL;
	req->private = NULL;
	kmem_cache_free(kiocb_cachep, req);
	ctx->reqs_active--;

	if (unlikely(!ctx->reqs_active && ctx->dead))
		wake_up(&ctx->wait);
}

static void aio_fput_routine(void *data)
{
	spin_lock_irq(&fput_lock);
	while (likely(!list_empty(&fput_head))) {
		struct kiocb *req = list_kiocb(fput_head.next);
		struct kioctx *ctx = req->ki_ctx;

		list_del(&req->ki_list);
		spin_unlock_irq(&fput_lock);

		/* Complete the fput */
		__fput(req->ki_filp);

		/* Link the iocb into the context's free list */
		spin_lock_irq(&ctx->ctx_lock);
		really_put_req(ctx, req);
		spin_unlock_irq(&ctx->ctx_lock);

		put_ioctx(ctx);
		spin_lock_irq(&fput_lock);
	}
	spin_unlock_irq(&fput_lock);
}

/* __aio_put_req
 *	Returns true if this put was the last user of the request.
 */
static int __aio_put_req(struct kioctx *ctx, struct kiocb *req)
{
	dprintk(KERN_DEBUG "aio_put(%p): f_count=%d\n",
		req, atomic_read(&req->ki_filp->f_count));

	req->ki_users --;
	if (unlikely(req->ki_users < 0))
		BUG();
	if (likely(req->ki_users))
		return 0;
	list_del(&req->ki_list);		/* remove from active_reqs */
	req->ki_cancel = NULL;
	req->ki_retry = NULL;

	/* Must be done under the lock to serialise against cancellation.
	 * Call this aio_fput as it duplicates fput via the fput_work.
	 */
	if (unlikely(atomic_dec_and_test(&req->ki_filp->f_count))) {
		get_ioctx(ctx);
		spin_lock(&fput_lock);
		list_add(&req->ki_list, &fput_head);
		spin_unlock(&fput_lock);
		queue_work(aio_wq, &fput_work);
	} else
		really_put_req(ctx, req);
	return 1;
}

/* aio_put_req
 *	Returns true if this put was the last user of the kiocb,
 *	false if the request is still in use.
 */
int fastcall aio_put_req(struct kiocb *req)
{
	struct kioctx *ctx = req->ki_ctx;
	int ret;
	spin_lock_irq(&ctx->ctx_lock);
	ret = __aio_put_req(ctx, req);
	spin_unlock_irq(&ctx->ctx_lock);
	if (ret)
		put_ioctx(ctx);
	return ret;
}

/*	Lookup an ioctx id.  ioctx_list is lockless for reads.
 *	FIXME: this is O(n) and is only suitable for development.
 */
struct kioctx *lookup_ioctx(unsigned long ctx_id)
{
	struct kioctx *ioctx;
	struct mm_struct *mm;

	mm = current->mm;
	read_lock(&mm->ioctx_list_lock);
	for (ioctx = mm->ioctx_list; ioctx; ioctx = ioctx->next)
		if (likely(ioctx->user_id == ctx_id && !ioctx->dead)) {
			get_ioctx(ioctx);
			break;
		}
	read_unlock(&mm->ioctx_list_lock);

	return ioctx;
}

/*
 * use_mm
 *	Makes the calling kernel thread take on the specified
 *	mm context.
 *	Called by the retry thread execute retries within the
 *	iocb issuer's mm context, so that copy_from/to_user
 *	operations work seamlessly for aio.
 *	(Note: this routine is intended to be called only
 *	from a kernel thread context)
 */
static void use_mm(struct mm_struct *mm)
{
	struct mm_struct *active_mm;
	struct task_struct *tsk = current;

	task_lock(tsk);
	active_mm = tsk->active_mm;
	atomic_inc(&mm->mm_count);
	tsk->mm = mm;
	tsk->active_mm = mm;
	activate_mm(active_mm, mm);
	task_unlock(tsk);

	mmdrop(active_mm);
}

/*
 * unuse_mm
 *	Reverses the effect of use_mm, i.e. releases the
 *	specified mm context which was earlier taken on
 *	by the calling kernel thread
 *	(Note: this routine is intended to be called only
 *	from a kernel thread context)
 *
 * Comments: Called with ctx->ctx_lock held. This nests
 * task_lock instead ctx_lock.
 */
void unuse_mm(struct mm_struct *mm)
{
	struct task_struct *tsk = current;

	task_lock(tsk);
	tsk->mm = NULL;
	/* active_mm is still 'mm' */
	enter_lazy_tlb(mm, tsk);
	task_unlock(tsk);
}

/*
 * Queue up a kiocb to be retried. Assumes that the kiocb
 * has already been marked as kicked, and places it on
 * the retry run list for the corresponding ioctx, if it
 * isn't already queued. Returns 1 if it actually queued
 * the kiocb (to tell the caller to activate the work
 * queue to process it), or 0, if it found that it was
 * already queued.
 *
 * Should be called with the spin lock iocb->ki_ctx->ctx_lock
 * held
 */
static inline int __queue_kicked_iocb(struct kiocb *iocb)
{
	struct kioctx *ctx = iocb->ki_ctx;

	if (list_empty(&iocb->ki_run_list)) {
		list_add_tail(&iocb->ki_run_list,
			&ctx->run_list);
		iocb->ki_queued++;
		return 1;
	}
	return 0;
}

/* aio_run_iocb
 *	This is the core aio execution routine. It is
 *	invoked both for initial i/o submission and
 *	subsequent retries via the aio_kick_handler.
 *	Expects to be invoked with iocb->ki_ctx->lock
 *	already held. The lock is released and reaquired
 *	as needed during processing.
 *
 * Calls the iocb retry method (already setup for the
 * iocb on initial submission) for operation specific
 * handling, but takes care of most of common retry
 * execution details for a given iocb. The retry method
 * needs to be non-blocking as far as possible, to avoid
 * holding up other iocbs waiting to be serviced by the
 * retry kernel thread.
 *
 * The trickier parts in this code have to do with
 * ensuring that only one retry instance is in progress
 * for a given iocb at any time. Providing that guarantee
 * simplifies the coding of individual aio operations as
 * it avoids various potential races.
 */
static ssize_t aio_run_iocb(struct kiocb *iocb)
{
	struct kioctx	*ctx = iocb->ki_ctx;
	ssize_t (*retry)(struct kiocb *);
	ssize_t ret;

	if (iocb->ki_retried++ > 1024*1024) {
		printk("Maximal retry count.  Bytes done %Zd\n",
			iocb->ki_nbytes - iocb->ki_left);
		return -EAGAIN;
	}

	if (!(iocb->ki_retried & 0xff)) {
		pr_debug("%ld retry: %d of %d (kick %ld, Q %ld run %ld, wake %ld)\n",
			iocb->ki_retried,
			iocb->ki_nbytes - iocb->ki_left, iocb->ki_nbytes,
			iocb->ki_kicked, iocb->ki_queued, aio_run, aio_wakeups);
	}

	if (!(retry = iocb->ki_retry)) {
		printk("aio_run_iocb: iocb->ki_retry = NULL\n");
		return 0;
	}

	/*
	 * We don't want the next retry iteration for this
	 * operation to start until this one has returned and
	 * updated the iocb state. However, wait_queue functions
	 * can trigger a kick_iocb from interrupt context in the
	 * meantime, indicating that data is available for the next
	 * iteration. We want to remember that and enable the
	 * next retry iteration _after_ we are through with
	 * this one.
	 *
	 * So, in order to be able to register a "kick", but
	 * prevent it from being queued now, we clear the kick
	 * flag, but make the kick code *think* that the iocb is
	 * still on the run list until we are actually done.
	 * When we are done with this iteration, we check if
	 * the iocb was kicked in the meantime and if so, queue
	 * it up afresh.
	 */

	kiocbClearKicked(iocb);

	/*
	 * This is so that aio_complete knows it doesn't need to
	 * pull the iocb off the run list (We can't just call
	 * INIT_LIST_HEAD because we don't want a kick_iocb to
	 * queue this on the run list yet)
	 */
	iocb->ki_run_list.next = iocb->ki_run_list.prev = NULL;
	spin_unlock_irq(&ctx->ctx_lock);

	/* Quit retrying if the i/o has been cancelled */
	if (kiocbIsCancelled(iocb)) {
		ret = -EINTR;
		aio_complete(iocb, ret, 0);
		/* must not access the iocb after this */
		goto out;
	}

	/*
	 * Now we are all set to call the retry method in async
	 * context. By setting this thread's io_wait context
	 * to point to the wait queue entry inside the currently
	 * running iocb for the duration of the retry, we ensure
	 * that async notification wakeups are queued by the
	 * operation instead of blocking waits, and when notified,
	 * cause the iocb to be kicked for continuation (through
	 * the aio_wake_function callback).
	 */
	BUG_ON(current->io_wait != NULL);
	current->io_wait = &iocb->ki_wait;
	ret = retry(iocb);
	current->io_wait = NULL;

	if (-EIOCBRETRY != ret) {
 		if (-EIOCBQUEUED != ret) {
			BUG_ON(!list_empty(&iocb->ki_wait.task_list));
			aio_complete(iocb, ret, 0);
			/* must not access the iocb after this */
		}
	} else {
		/*
		 * Issue an additional retry to avoid waiting forever if
		 * no waits were queued (e.g. in case of a short read).
		 */
		if (list_empty(&iocb->ki_wait.task_list))
			kiocbSetKicked(iocb);
	}
out:
	spin_lock_irq(&ctx->ctx_lock);

	if (-EIOCBRETRY == ret) {
		/*
		 * OK, now that we are done with this iteration
		 * and know that there is more left to go,
		 * this is where we let go so that a subsequent
		 * "kick" can start the next iteration
		 */

		/* will make __queue_kicked_iocb succeed from here on */
		INIT_LIST_HEAD(&iocb->ki_run_list);
		/* we must queue the next iteration ourselves, if it
		 * has already been kicked */
		if (kiocbIsKicked(iocb)) {
			__queue_kicked_iocb(iocb);
		}
	}
	return ret;
}

/*
 * __aio_run_iocbs:
 * 	Process all pending retries queued on the ioctx
 * 	run list.
 * Assumes it is operating within the aio issuer's mm
 * context. Expects to be called with ctx->ctx_lock held
 */
static int __aio_run_iocbs(struct kioctx *ctx)
{
	struct kiocb *iocb;
	int count = 0;
	LIST_HEAD(run_list);

	list_splice_init(&ctx->run_list, &run_list);
	while (!list_empty(&run_list)) {
		iocb = list_entry(run_list.next, struct kiocb,
			ki_run_list);
		list_del(&iocb->ki_run_list);
		/*
		 * Hold an extra reference while retrying i/o.
		 */
		iocb->ki_users++;       /* grab extra reference */
		aio_run_iocb(iocb);
		if (__aio_put_req(ctx, iocb))  /* drop extra ref */
			put_ioctx(ctx);
		count++;
 	}
	aio_run++;
	if (!list_empty(&ctx->run_list))
		return 1;
	return 0;
}

static void aio_queue_work(struct kioctx * ctx)
{
	unsigned long timeout;
	/*
	 * if someone is waiting, get the work started right
	 * away, otherwise, use a longer delay
	 */
	smp_mb();
	if (waitqueue_active(&ctx->wait))
		timeout = 1;
	else
		timeout = HZ/10;
	queue_delayed_work(aio_wq, &ctx->wq, timeout);
}


/*
 * aio_run_iocbs:
 * 	Process all pending retries queued on the ioctx
 * 	run list.
 * Assumes it is operating within the aio issuer's mm
 * context.
 */
static inline void aio_run_iocbs(struct kioctx *ctx)
{
	int requeue;

	spin_lock_irq(&ctx->ctx_lock);

	requeue = __aio_run_iocbs(ctx);
	spin_unlock_irq(&ctx->ctx_lock);
	if (requeue)
		aio_queue_work(ctx);
}

/*
 * just like aio_run_iocbs, but keeps running them until
 * the list stays empty
 */
static inline void aio_run_all_iocbs(struct kioctx *ctx)
{
	spin_lock_irq(&ctx->ctx_lock);
	while (__aio_run_iocbs(ctx))
		;
	spin_unlock_irq(&ctx->ctx_lock);
}

/*
 * aio_kick_handler:
 * 	Work queue handler triggered to process pending
 * 	retries on an ioctx. Takes on the aio issuer's
 *	mm context before running the iocbs, so that
 *	copy_xxx_user operates on the issuer's address
 *      space.
 * Run on aiod's context.
 */
static void aio_kick_handler(void *data)
{
	struct kioctx *ctx = data;
	mm_segment_t oldfs = get_fs();
	int requeue;

	set_fs(USER_DS);
	use_mm(ctx->mm);
	spin_lock_irq(&ctx->ctx_lock);
	requeue =__aio_run_iocbs(ctx);
 	unuse_mm(ctx->mm);
	spin_unlock_irq(&ctx->ctx_lock);
	set_fs(oldfs);
	/*
	 * we're in a worker thread already, don't use queue_delayed_work,
	 */
	if (requeue)
		queue_work(aio_wq, &ctx->wq);
}


/*
 * Called by kick_iocb to queue the kiocb for retry
 * and if required activate the aio work queue to process
 * it
 */
void queue_kicked_iocb(struct kiocb *iocb)
{
 	struct kioctx	*ctx = iocb->ki_ctx;
	unsigned long flags;
	int run = 0;

	WARN_ON((!list_empty(&iocb->ki_wait.task_list)));

	spin_lock_irqsave(&ctx->ctx_lock, flags);
	run = __queue_kicked_iocb(iocb);
	spin_unlock_irqrestore(&ctx->ctx_lock, flags);
	if (run) {
		aio_queue_work(ctx);
		aio_wakeups++;
	}
}

/*
 * kick_iocb:
 *      Called typically from a wait queue callback context
 *      (aio_wake_function) to trigger a retry of the iocb.
 *      The retry is usually executed by aio workqueue
 *      threads (See aio_kick_handler).
 */
void fastcall kick_iocb(struct kiocb *iocb)
{
	/* sync iocbs are easy: they can only ever be executing from a 
	 * single context. */
	if (is_sync_kiocb(iocb)) {
		kiocbSetKicked(iocb);
	        wake_up_process(iocb->ki_obj.tsk);
		return;
	}

	iocb->ki_kicked++;
	/* If its already kicked we shouldn't queue it again */
	if (!kiocbTryKick(iocb)) {
		queue_kicked_iocb(iocb);
	}
}
EXPORT_SYMBOL(kick_iocb);

/* aio_complete
 *	Called when the io request on the given iocb is complete.
 *	Returns true if this is the last user of the request.  The 
 *	only other user of the request can be the cancellation code.
 */
int fastcall aio_complete(struct kiocb *iocb, long res, long res2)
{
	struct kioctx	*ctx = iocb->ki_ctx;
	struct aio_ring_info	*info;
	struct aio_ring	*ring;
	struct io_event	*event;
	unsigned long	flags;
	unsigned long	tail;
	int		ret;

	/* Special case handling for sync iocbs: events go directly
	 * into the iocb for fast handling.  Note that this will not 
	 * work if we allow sync kiocbs to be cancelled. in which
	 * case the usage count checks will have to move under ctx_lock
	 * for all cases.
	 */
	if (is_sync_kiocb(iocb)) {
		int ret;

		iocb->ki_user_data = res;
		if (iocb->ki_users == 1) {
			iocb->ki_users = 0;
			ret = 1;
		} else {
			spin_lock_irq(&ctx->ctx_lock);
			iocb->ki_users--;
			ret = (0 == iocb->ki_users);
			spin_unlock_irq(&ctx->ctx_lock);
		}
		/* sync iocbs put the task here for us */
		wake_up_process(iocb->ki_obj.tsk);
		return ret;
	}

	info = &ctx->ring_info;

	/* add a completion event to the ring buffer.
	 * must be done holding ctx->ctx_lock to prevent
	 * other code from messing with the tail
	 * pointer since we might be called from irq
	 * context.
	 */
	spin_lock_irqsave(&ctx->ctx_lock, flags);

	if (iocb->ki_run_list.prev && !list_empty(&iocb->ki_run_list))
		list_del_init(&iocb->ki_run_list);

	/*
	 * cancelled requests don't get events, userland was given one
	 * when the event got cancelled.
	 */
	if (kiocbIsCancelled(iocb))
		goto put_rq;

	ring = kmap_atomic(info->ring_pages[0], KM_IRQ1);

	tail = info->tail;
	event = aio_ring_event(info, tail, KM_IRQ0);
	tail = (tail + 1) % info->nr;

	event->obj = (u64)(unsigned long)iocb->ki_obj.user;
	event->data = iocb->ki_user_data;
	event->res = res;
	event->res2 = res2;

	dprintk("aio_complete: %p[%lu]: %p: %p %Lx %lx %lx\n",
		ctx, tail, iocb, iocb->ki_obj.user, iocb->ki_user_data,
		res, res2);

	/* after flagging the request as done, we
	 * must never even look at it again
	 */
	smp_wmb();	/* make event visible before updating tail */

	info->tail = tail;
	ring->tail = tail;

	put_aio_ring_event(event, KM_IRQ0);
	kunmap_atomic(ring, KM_IRQ1);

	pr_debug("added to ring %p at [%lu]\n", iocb, tail);

	pr_debug("%ld retries: %d of %d (kicked %ld, Q %ld run %ld wake %ld)\n",
		iocb->ki_retried,
		iocb->ki_nbytes - iocb->ki_left, iocb->ki_nbytes,
		iocb->ki_kicked, iocb->ki_queued, aio_run, aio_wakeups);
put_rq:
	/* everything turned out well, dispose of the aiocb. */
	ret = __aio_put_req(ctx, iocb);

	spin_unlock_irqrestore(&ctx->ctx_lock, flags);

	if (waitqueue_active(&ctx->wait))
		wake_up(&ctx->wait);

	if (ret)
		put_ioctx(ctx);

	return ret;
}

/* aio_read_evt
 *	Pull an event off of the ioctx's event ring.  Returns the number of 
 *	events fetched (0 or 1 ;-)
 *	FIXME: make this use cmpxchg.
 *	TODO: make the ringbuffer user mmap()able (requires FIXME).
 */
static int aio_read_evt(struct kioctx *ioctx, struct io_event *ent)
{
	struct aio_ring_info *info = &ioctx->ring_info;
	struct aio_ring *ring;
	unsigned long head;
	int ret = 0;

	ring = kmap_atomic(info->ring_pages[0], KM_USER0);
	dprintk("in aio_read_evt h%lu t%lu m%lu\n",
		 (unsigned long)ring->head, (unsigned long)ring->tail,
		 (unsigned long)ring->nr);

	if (ring->head == ring->tail)
		goto out;

	spin_lock(&info->ring_lock);

	head = ring->head % info->nr;
	if (head != ring->tail) {
		struct io_event *evp = aio_ring_event(info, head, KM_USER1);
		*ent = *evp;
		head = (head + 1) % info->nr;
		smp_mb(); /* finish reading the event before updatng the head */
		ring->head = head;
		ret = 1;
		put_aio_ring_event(evp, KM_USER1);
	}
	spin_unlock(&info->ring_lock);

out:
	kunmap_atomic(ring, KM_USER0);
	dprintk("leaving aio_read_evt: %d  h%lu t%lu\n", ret,
		 (unsigned long)ring->head, (unsigned long)ring->tail);
	return ret;
}

struct aio_timeout {
	struct timer_list	timer;
	int			timed_out;
	struct task_struct	*p;
};

static void timeout_func(unsigned long data)
{
	struct aio_timeout *to = (struct aio_timeout *)data;

	to->timed_out = 1;
	wake_up_process(to->p);
}

static inline void init_timeout(struct aio_timeout *to)
{
	init_timer(&to->timer);
	to->timer.data = (unsigned long)to;
	to->timer.function = timeout_func;
	to->timed_out = 0;
	to->p = current;
}

static inline void set_timeout(long start_jiffies, struct aio_timeout *to,
			       const struct timespec *ts)
{
	to->timer.expires = start_jiffies + timespec_to_jiffies(ts);
	if (time_after(to->timer.expires, jiffies))
		add_timer(&to->timer);
	else
		to->timed_out = 1;
}

static inline void clear_timeout(struct aio_timeout *to)
{
	del_singleshot_timer_sync(&to->timer);
}

static int read_events(struct kioctx *ctx,
			long min_nr, long nr,
			struct io_event __user *event,
			struct timespec __user *timeout)
{
	long			start_jiffies = jiffies;
	struct task_struct	*tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);
	int			ret;
	int			i = 0;
	struct io_event		ent;
	struct aio_timeout	to;
	int 			event_loop = 0; /* testing only */
	int			retry = 0;

	/* needed to zero any padding within an entry (there shouldn't be 
	 * any, but C is fun!
	 */
	memset(&ent, 0, sizeof(ent));
retry:
	ret = 0;
	while (likely(i < nr)) {
		ret = aio_read_evt(ctx, &ent);
		if (unlikely(ret <= 0))
			break;

		dprintk("read event: %Lx %Lx %Lx %Lx\n",
			ent.data, ent.obj, ent.res, ent.res2);

		/* Could we split the check in two? */
		ret = -EFAULT;
		if (unlikely(copy_to_user(event, &ent, sizeof(ent)))) {
			dprintk("aio: lost an event due to EFAULT.\n");
			break;
		}
		ret = 0;

		/* Good, event copied to userland, update counts. */
		event ++;
		i ++;
	}

	if (min_nr <= i)
		return i;
	if (ret)
		return ret;

	/* End fast path */

	/* racey check, but it gets redone */
	if (!retry && unlikely(!list_empty(&ctx->run_list))) {
		retry = 1;
		aio_run_all_iocbs(ctx);
		goto retry;
	}

	init_timeout(&to);
	if (timeout) {
		struct timespec	ts;
		ret = -EFAULT;
		if (unlikely(copy_from_user(&ts, timeout, sizeof(ts))))
			goto out;

		set_timeout(start_jiffies, &to, &ts);
	}

	while (likely(i < nr)) {
		add_wait_queue_exclusive(&ctx->wait, &wait);
		do {
			set_task_state(tsk, TASK_INTERRUPTIBLE);
			ret = aio_read_evt(ctx, &ent);
			if (ret)
				break;
			if (min_nr <= i)
				break;
			ret = 0;
			if (to.timed_out)	/* Only check after read evt */
				break;
			schedule();
			event_loop++;
			if (signal_pending(tsk)) {
				ret = -EINTR;
				break;
			}
			/*ret = aio_read_evt(ctx, &ent);*/
		} while (1) ;

		set_task_state(tsk, TASK_RUNNING);
		remove_wait_queue(&ctx->wait, &wait);

		if (unlikely(ret <= 0))
			break;

		ret = -EFAULT;
		if (unlikely(copy_to_user(event, &ent, sizeof(ent)))) {
			dprintk("aio: lost an event due to EFAULT.\n");
			break;
		}

		/* Good, event copied to userland, update counts. */
		event ++;
		i ++;
	}

	if (timeout)
		clear_timeout(&to);
out:
	pr_debug("event loop executed %d times\n", event_loop);
	pr_debug("aio_run %ld\n", aio_run);
	pr_debug("aio_wakeups %ld\n", aio_wakeups);
	return i ? i : ret;
}

/* Take an ioctx and remove it from the list of ioctx's.  Protects 
 * against races with itself via ->dead.
 */
static void io_destroy(struct kioctx *ioctx)
{
	struct mm_struct *mm = current->mm;
	struct kioctx **tmp;
	int was_dead;

	/* delete the entry from the list is someone else hasn't already */
	write_lock(&mm->ioctx_list_lock);
	was_dead = ioctx->dead;
	ioctx->dead = 1;
	for (tmp = &mm->ioctx_list; *tmp && *tmp != ioctx;
	     tmp = &(*tmp)->next)
		;
	if (*tmp)
		*tmp = ioctx->next;
	write_unlock(&mm->ioctx_list_lock);

	dprintk("aio_release(%p)\n", ioctx);
	if (likely(!was_dead))
		put_ioctx(ioctx);	/* twice for the list */

	aio_cancel_all(ioctx);
	wait_for_all_aios(ioctx);
	put_ioctx(ioctx);	/* once for the lookup */
}

/* sys_io_setup:
 *	Create an aio_context capable of receiving at least nr_events.
 *	ctxp must not point to an aio_context that already exists, and
 *	must be initialized to 0 prior to the call.  On successful
 *	creation of the aio_context, *ctxp is filled in with the resulting 
 *	handle.  May fail with -EINVAL if *ctxp is not initialized,
 *	if the specified nr_events exceeds internal limits.  May fail 
 *	with -EAGAIN if the specified nr_events exceeds the user's limit 
 *	of available events.  May fail with -ENOMEM if insufficient kernel
 *	resources are available.  May fail with -EFAULT if an invalid
 *	pointer is passed for ctxp.  Will fail with -ENOSYS if not
 *	implemented.
 */
asmlinkage long sys_io_setup(unsigned nr_events, aio_context_t __user *ctxp)
{
	struct kioctx *ioctx = NULL;
	unsigned long ctx;
	long ret;

	ret = get_user(ctx, ctxp);
	if (unlikely(ret))
		goto out;

	ret = -EINVAL;
	if (unlikely(ctx || (int)nr_events <= 0)) {
		pr_debug("EINVAL: io_setup: ctx or nr_events > max\n");
		goto out;
	}

	ioctx = ioctx_alloc(nr_events);
	ret = PTR_ERR(ioctx);
	if (!IS_ERR(ioctx)) {
		ret = put_user(ioctx->user_id, ctxp);
		if (!ret)
			return 0;

		get_ioctx(ioctx); /* io_destroy() expects us to hold a ref */
		io_destroy(ioctx);
	}

out:
	return ret;
}

/* sys_io_destroy:
 *	Destroy the aio_context specified.  May cancel any outstanding 
 *	AIOs and block on completion.  Will fail with -ENOSYS if not
 *	implemented.  May fail with -EFAULT if the context pointed to
 *	is invalid.
 */
asmlinkage long sys_io_destroy(aio_context_t ctx)
{
	struct kioctx *ioctx = lookup_ioctx(ctx);
	if (likely(NULL != ioctx)) {
		io_destroy(ioctx);
		return 0;
	}
	pr_debug("EINVAL: io_destroy: invalid context id\n");
	return -EINVAL;
}

/*
 * Default retry method for aio_read (also used for first time submit)
 * Responsible for updating iocb state as retries progress
 */
static ssize_t aio_pread(struct kiocb *iocb)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret = 0;

	ret = file->f_op->aio_read(iocb, iocb->ki_buf,
		iocb->ki_left, iocb->ki_pos);

	/*
	 * Can't just depend on iocb->ki_left to determine
	 * whether we are done. This may have been a short read.
	 */
	if (ret > 0) {
		iocb->ki_buf += ret;
		iocb->ki_left -= ret;
		/*
		 * For pipes and sockets we return once we have
		 * some data; for regular files we retry till we
		 * complete the entire read or find that we can't
		 * read any more data (e.g short reads).
		 */
		if (!S_ISFIFO(inode->i_mode) && !S_ISSOCK(inode->i_mode))
			ret = -EIOCBRETRY;
	}

	/* This means we must have transferred all that we could */
	/* No need to retry anymore */
	if ((ret == 0) || (iocb->ki_left == 0))
		ret = iocb->ki_nbytes - iocb->ki_left;

	return ret;
}

/*
 * Default retry method for aio_write (also used for first time submit)
 * Responsible for updating iocb state as retries progress
 */
static ssize_t aio_pwrite(struct kiocb *iocb)
{
	struct file *file = iocb->ki_filp;
	ssize_t ret = 0;

	ret = file->f_op->aio_write(iocb, iocb->ki_buf,
		iocb->ki_left, iocb->ki_pos);

	if (ret > 0) {
		iocb->ki_buf += ret;
		iocb->ki_left -= ret;

		ret = -EIOCBRETRY;
	}

	/* This means we must have transferred all that we could */
	/* No need to retry anymore */
	if ((ret == 0) || (iocb->ki_left == 0))
		ret = iocb->ki_nbytes - iocb->ki_left;

	return ret;
}

static ssize_t aio_fdsync(struct kiocb *iocb)
{
	struct file *file = iocb->ki_filp;
	ssize_t ret = -EINVAL;

	if (file->f_op->aio_fsync)
		ret = file->f_op->aio_fsync(iocb, 1);
	return ret;
}

static ssize_t aio_fsync(struct kiocb *iocb)
{
	struct file *file = iocb->ki_filp;
	ssize_t ret = -EINVAL;

	if (file->f_op->aio_fsync)
		ret = file->f_op->aio_fsync(iocb, 0);
	return ret;
}

/*
 * aio_setup_iocb:
 *	Performs the initial checks and aio retry method
 *	setup for the kiocb at the time of io submission.
 */
ssize_t aio_setup_iocb(struct kiocb *kiocb)
{
	struct file *file = kiocb->ki_filp;
	ssize_t ret = 0;

	switch (kiocb->ki_opcode) {
	case IOCB_CMD_PREAD:
		ret = -EBADF;
		if (unlikely(!(file->f_mode & FMODE_READ)))
			break;
		ret = -EFAULT;
		if (unlikely(!access_ok(VERIFY_WRITE, kiocb->ki_buf,
			kiocb->ki_left)))
			break;
		ret = -EINVAL;
		if (file->f_op->aio_read)
			kiocb->ki_retry = aio_pread;
		break;
	case IOCB_CMD_PWRITE:
		ret = -EBADF;
		if (unlikely(!(file->f_mode & FMODE_WRITE)))
			break;
		ret = -EFAULT;
		if (unlikely(!access_ok(VERIFY_READ, kiocb->ki_buf,
			kiocb->ki_left)))
			break;
		ret = -EINVAL;
		if (file->f_op->aio_write)
			kiocb->ki_retry = aio_pwrite;
		break;
	case IOCB_CMD_FDSYNC:
		ret = -EINVAL;
		if (file->f_op->aio_fsync)
			kiocb->ki_retry = aio_fdsync;
		break;
	case IOCB_CMD_FSYNC:
		ret = -EINVAL;
		if (file->f_op->aio_fsync)
			kiocb->ki_retry = aio_fsync;
		break;
	default:
		dprintk("EINVAL: io_submit: no operation provided\n");
		ret = -EINVAL;
	}

	if (!kiocb->ki_retry)
		return ret;

	return 0;
}

/*
 * aio_wake_function:
 * 	wait queue callback function for aio notification,
 * 	Simply triggers a retry of the operation via kick_iocb.
 *
 * 	This callback is specified in the wait queue entry in
 *	a kiocb	(current->io_wait points to this wait queue
 *	entry when an aio operation executes; it is used
 * 	instead of a synchronous wait when an i/o blocking
 *	condition is encountered during aio).
 *
 * Note:
 * This routine is executed with the wait queue lock held.
 * Since kick_iocb acquires iocb->ctx->ctx_lock, it nests
 * the ioctx lock inside the wait queue lock. This is safe
 * because this callback isn't used for wait queues which
 * are nested inside ioctx lock (i.e. ctx->wait)
 */
int aio_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	struct kiocb *iocb = container_of(wait, struct kiocb, ki_wait);

	list_del_init(&wait->task_list);
	kick_iocb(iocb);
	return 1;
}

int fastcall io_submit_one(struct kioctx *ctx, struct iocb __user *user_iocb,
			 struct iocb *iocb)
{
	struct kiocb *req;
	struct file *file;
	ssize_t ret;

	/* enforce forwards compatibility on users */
	if (unlikely(iocb->aio_reserved1 || iocb->aio_reserved2 ||
		     iocb->aio_reserved3)) {
		pr_debug("EINVAL: io_submit: reserve field set\n");
		return -EINVAL;
	}

	/* prevent overflows */
	if (unlikely(
	    (iocb->aio_buf != (unsigned long)iocb->aio_buf) ||
	    (iocb->aio_nbytes != (size_t)iocb->aio_nbytes) ||
	    ((ssize_t)iocb->aio_nbytes < 0)
	   )) {
		pr_debug("EINVAL: io_submit: overflow check\n");
		return -EINVAL;
	}

	file = fget(iocb->aio_fildes);
	if (unlikely(!file))
		return -EBADF;

	req = aio_get_req(ctx);		/* returns with 2 references to req */
	if (unlikely(!req)) {
		fput(file);
		return -EAGAIN;
	}

	req->ki_filp = file;
	iocb->aio_key = req->ki_key;
	ret = put_user(iocb->aio_key, &user_iocb->aio_key);
	if (unlikely(ret)) {
		dprintk("EFAULT: aio_key\n");
		goto out_put_req;
	}

	req->ki_obj.user = user_iocb;
	req->ki_user_data = iocb->aio_data;
	req->ki_pos = iocb->aio_offset;

	req->ki_buf = (char __user *)(unsigned long)iocb->aio_buf;
	req->ki_left = req->ki_nbytes = iocb->aio_nbytes;
	req->ki_opcode = iocb->aio_lio_opcode;
	init_waitqueue_func_entry(&req->ki_wait, aio_wake_function);
	INIT_LIST_HEAD(&req->ki_wait.task_list);
	req->ki_run_list.next = req->ki_run_list.prev = NULL;
	req->ki_retry = NULL;
	req->ki_retried = 0;
	req->ki_kicked = 0;
	req->ki_queued = 0;
	aio_run = 0;
	aio_wakeups = 0;

	ret = aio_setup_iocb(req);

	if (ret)
		goto out_put_req;

	spin_lock_irq(&ctx->ctx_lock);
	if (likely(list_empty(&ctx->run_list))) {
		aio_run_iocb(req);
	} else {
		list_add_tail(&req->ki_run_list, &ctx->run_list);
		/* drain the run list */
		while (__aio_run_iocbs(ctx))
			;
	}
	spin_unlock_irq(&ctx->ctx_lock);
	aio_put_req(req);	/* drop extra ref to req */
	return 0;

out_put_req:
	aio_put_req(req);	/* drop extra ref to req */
	aio_put_req(req);	/* drop i/o ref to req */
	return ret;
}

/* sys_io_submit:
 *	Queue the nr iocbs pointed to by iocbpp for processing.  Returns
 *	the number of iocbs queued.  May return -EINVAL if the aio_context
 *	specified by ctx_id is invalid, if nr is < 0, if the iocb at
 *	*iocbpp[0] is not properly initialized, if the operation specified
 *	is invalid for the file descriptor in the iocb.  May fail with
 *	-EFAULT if any of the data structures point to invalid data.  May
 *	fail with -EBADF if the file descriptor specified in the first
 *	iocb is invalid.  May fail with -EAGAIN if insufficient resources
 *	are available to queue any iocbs.  Will return 0 if nr is 0.  Will
 *	fail with -ENOSYS if not implemented.
 */
asmlinkage long sys_io_submit(aio_context_t ctx_id, long nr,
			      struct iocb __user * __user *iocbpp)
{
	struct kioctx *ctx;
	long ret = 0;
	int i;

	if (unlikely(nr < 0))
		return -EINVAL;

	if (unlikely(!access_ok(VERIFY_READ, iocbpp, (nr*sizeof(*iocbpp)))))
		return -EFAULT;

	ctx = lookup_ioctx(ctx_id);
	if (unlikely(!ctx)) {
		pr_debug("EINVAL: io_submit: invalid context id\n");
		return -EINVAL;
	}

	/*
	 * AKPM: should this return a partial result if some of the IOs were
	 * successfully submitted?
	 */
	for (i=0; i<nr; i++) {
		struct iocb __user *user_iocb;
		struct iocb tmp;

		if (unlikely(__get_user(user_iocb, iocbpp + i))) {
			ret = -EFAULT;
			break;
		}

		if (unlikely(copy_from_user(&tmp, user_iocb, sizeof(tmp)))) {
			ret = -EFAULT;
			break;
		}

		ret = io_submit_one(ctx, user_iocb, &tmp);
		if (ret)
			break;
	}

	put_ioctx(ctx);
	return i ? i : ret;
}

/* lookup_kiocb
 *	Finds a given iocb for cancellation.
 *	MUST be called with ctx->ctx_lock held.
 */
struct kiocb *lookup_kiocb(struct kioctx *ctx, struct iocb __user *iocb, u32 key)
{
	struct list_head *pos;
	/* TODO: use a hash or array, this sucks. */
	list_for_each(pos, &ctx->active_reqs) {
		struct kiocb *kiocb = list_kiocb(pos);
		if (kiocb->ki_obj.user == iocb && kiocb->ki_key == key)
			return kiocb;
	}
	return NULL;
}

/* sys_io_cancel:
 *	Attempts to cancel an iocb previously passed to io_submit.  If
 *	the operation is successfully cancelled, the resulting event is
 *	copied into the memory pointed to by result without being placed
 *	into the completion queue and 0 is returned.  May fail with
 *	-EFAULT if any of the data structures pointed to are invalid.
 *	May fail with -EINVAL if aio_context specified by ctx_id is
 *	invalid.  May fail with -EAGAIN if the iocb specified was not
 *	cancelled.  Will fail with -ENOSYS if not implemented.
 */
asmlinkage long sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
			      struct io_event __user *result)
{
	int (*cancel)(struct kiocb *iocb, struct io_event *res);
	struct kioctx *ctx;
	struct kiocb *kiocb;
	u32 key;
	int ret;

	ret = get_user(key, &iocb->aio_key);
	if (unlikely(ret))
		return -EFAULT;

	ctx = lookup_ioctx(ctx_id);
	if (unlikely(!ctx))
		return -EINVAL;

	spin_lock_irq(&ctx->ctx_lock);
	ret = -EAGAIN;
	kiocb = lookup_kiocb(ctx, iocb, key);
	if (kiocb && kiocb->ki_cancel) {
		cancel = kiocb->ki_cancel;
		kiocb->ki_users ++;
		kiocbSetCancelled(kiocb);
	} else
		cancel = NULL;
	spin_unlock_irq(&ctx->ctx_lock);

	if (NULL != cancel) {
		struct io_event tmp;
		pr_debug("calling cancel\n");
		memset(&tmp, 0, sizeof(tmp));
		tmp.obj = (u64)(unsigned long)kiocb->ki_obj.user;
		tmp.data = kiocb->ki_user_data;
		ret = cancel(kiocb, &tmp);
		if (!ret) {
			/* Cancellation succeeded -- copy the result
			 * into the user's buffer.
			 */
			if (copy_to_user(result, &tmp, sizeof(tmp)))
				ret = -EFAULT;
		}
	} else
		ret = -EINVAL;

	put_ioctx(ctx);

	return ret;
}

/* io_getevents:
 *	Attempts to read at least min_nr events and up to nr events from
 *	the completion queue for the aio_context specified by ctx_id.  May
 *	fail with -EINVAL if ctx_id is invalid, if min_nr is out of range,
 *	if nr is out of range, if when is out of range.  May fail with
 *	-EFAULT if any of the memory specified to is invalid.  May return
 *	0 or < min_nr if no events are available and the timeout specified
 *	by when	has elapsed, where when == NULL specifies an infinite
 *	timeout.  Note that the timeout pointed to by when is relative and
 *	will be updated if not NULL and the operation blocks.  Will fail
 *	with -ENOSYS if not implemented.
 */
asmlinkage long sys_io_getevents(aio_context_t ctx_id,
				 long min_nr,
				 long nr,
				 struct io_event __user *events,
				 struct timespec __user *timeout)
{
	struct kioctx *ioctx = lookup_ioctx(ctx_id);
	long ret = -EINVAL;

	if (likely(ioctx)) {
		if (likely(min_nr <= nr && min_nr >= 0 && nr >= 0))
			ret = read_events(ioctx, min_nr, nr, events, timeout);
		put_ioctx(ioctx);
	}

	return ret;
}

__initcall(aio_setup);

EXPORT_SYMBOL(aio_complete);
EXPORT_SYMBOL(aio_put_req);
EXPORT_SYMBOL(wait_on_sync_kiocb);

/*
 * Copyright (C) 2003 Sistina Software Limited.
 *
 * This file is released under the GPL.
 */

#include "dm.h"
#include "dm-bio-list.h"
#include "dm-bio-record.h"
#include "dm-io.h"
#include "dm-log.h"
#include "kcopyd.h"

#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

static struct workqueue_struct *_kmirrord_wq;
static struct work_struct _kmirrord_work;

static inline void wake(void)
{
	queue_work(_kmirrord_wq, &_kmirrord_work);
}

static struct workqueue_struct *_kmir_mon_wq;

/*-----------------------------------------------------------------
 * Region hash
 *
 * The mirror splits itself up into discrete regions.  Each
 * region can be in one of three states: clean, dirty,
 * nosync.  There is no need to put clean regions in the hash.
 *
 * In addition to being present in the hash table a region _may_
 * be present on one of three lists.
 *
 *   clean_regions: Regions on this list have no io pending to
 *   them, they are in sync, we are no longer interested in them,
 *   they are dull.  rh_update_states() will remove them from the
 *   hash table.
 *
 *   quiesced_regions: These regions have been spun down, ready
 *   for recovery.  rh_recovery_start() will remove regions from
 *   this list and hand them to kmirrord, which will schedule the
 *   recovery io with kcopyd.
 *
 *   recovered_regions: Regions that kcopyd has successfully
 *   recovered.  rh_update_states() will now schedule any delayed
 *   io, up the recovery_count, and remove the region from the
 *   hash.
 *
 * There are 2 locks:
 *   A rw spin lock 'hash_lock' protects just the hash table,
 *   this is never held in write mode from interrupt context,
 *   which I believe means that we only have to disable irqs when
 *   doing a write lock.
 *
 *   An ordinary spin lock 'region_lock' that protects the three
 *   lists in the region_hash, with the 'state', 'list' and
 *   'bhs_delayed' fields of the regions.  This is used from irq
 *   context, so all other uses will have to suspend local irqs.
 *---------------------------------------------------------------*/
struct mirror_set;
struct region_hash {
	struct mirror_set *ms;
	uint32_t region_size;
	unsigned region_shift;

	/* holds persistent region state */
	struct dirty_log *log;

	/* hash table */
	rwlock_t hash_lock;
	mempool_t *region_pool;
	unsigned int mask;
	unsigned int nr_buckets;
	struct list_head *buckets;

	spinlock_t region_lock;
	struct semaphore recovery_count;
	struct list_head clean_regions;
	struct list_head quiesced_regions;
	struct list_head recovered_regions;
};

enum {
	RH_CLEAN,
	RH_DIRTY,
	RH_NOSYNC,
	RH_RECOVERING
};

struct region {
	struct region_hash *rh;	/* FIXME: can we get rid of this ? */
	region_t key;
	int state;

	struct list_head hash_list;
	struct list_head list;

	atomic_t pending;
	struct bio_list delayed_bios;
};

/*
 * Conversion fns
 */
static inline region_t bio_to_region(struct region_hash *rh, struct bio *bio)
{
	return bio->bi_sector >> rh->region_shift;
}

static inline sector_t region_to_sector(struct region_hash *rh, region_t region)
{
	return region << rh->region_shift;
}

/* FIXME move this */
static void queue_bio(struct mirror_set *ms, struct bio *bio, int rw);

static void *region_alloc(int gfp_mask, void *pool_data)
{
	return kmalloc(sizeof(struct region), gfp_mask);
}

static void region_free(void *element, void *pool_data)
{
	kfree(element);
}

#define MIN_REGIONS 64
#define MAX_RECOVERY 1
static int rh_init(struct region_hash *rh, struct mirror_set *ms,
		   struct dirty_log *log, uint32_t region_size,
		   region_t nr_regions)
{
	unsigned int nr_buckets, max_buckets;
	size_t i;

	/*
	 * Calculate a suitable number of buckets for our hash
	 * table.
	 */
	max_buckets = nr_regions >> 6;
	for (nr_buckets = 128u; nr_buckets < max_buckets; nr_buckets <<= 1)
		;
	nr_buckets >>= 1;

	rh->ms = ms;
	rh->log = log;
	rh->region_size = region_size;
	rh->region_shift = ffs(region_size) - 1;
	rwlock_init(&rh->hash_lock);
	rh->mask = nr_buckets - 1;
	rh->nr_buckets = nr_buckets;

	rh->buckets = vmalloc(nr_buckets * sizeof(*rh->buckets));
	if (!rh->buckets) {
		DMERR("unable to allocate region hash memory");
		return -ENOMEM;
	}

	for (i = 0; i < nr_buckets; i++)
		INIT_LIST_HEAD(rh->buckets + i);

	spin_lock_init(&rh->region_lock);
	sema_init(&rh->recovery_count, 0);
	INIT_LIST_HEAD(&rh->clean_regions);
	INIT_LIST_HEAD(&rh->quiesced_regions);
	INIT_LIST_HEAD(&rh->recovered_regions);

	rh->region_pool = mempool_create(MIN_REGIONS, region_alloc,
					 region_free, NULL);
	if (!rh->region_pool) {
		vfree(rh->buckets);
		rh->buckets = NULL;
		return -ENOMEM;
	}

	return 0;
}

static void rh_exit(struct region_hash *rh)
{
	unsigned int h;
	struct region *reg, *nreg;

	BUG_ON(!list_empty(&rh->quiesced_regions));
	for (h = 0; h < rh->nr_buckets; h++) {
		list_for_each_entry_safe(reg, nreg, rh->buckets + h, hash_list) {
			BUG_ON(atomic_read(&reg->pending));
			mempool_free(reg, rh->region_pool);
		}
	}

	if (rh->log)
		dm_destroy_dirty_log(rh->log);
	if (rh->region_pool)
		mempool_destroy(rh->region_pool);
	vfree(rh->buckets);
}

#define RH_HASH_MULT 2654435387U

static inline unsigned int rh_hash(struct region_hash *rh, region_t region)
{
	return (unsigned int) ((region * RH_HASH_MULT) >> 12) & rh->mask;
}

static struct region *__rh_lookup(struct region_hash *rh, region_t region)
{
	struct region *reg;

	list_for_each_entry (reg, rh->buckets + rh_hash(rh, region), hash_list)
		if (reg->key == region)
			return reg;

	return NULL;
}

static void __rh_insert(struct region_hash *rh, struct region *reg)
{
	unsigned int h = rh_hash(rh, reg->key);
	list_add(&reg->hash_list, rh->buckets + h);
}

static struct region *__rh_alloc(struct region_hash *rh, region_t region)
{
	struct region *reg, *nreg;

	read_unlock(&rh->hash_lock);
	nreg = mempool_alloc(rh->region_pool, GFP_NOIO);
	nreg->state = rh->log->type->in_sync(rh->log, region, 1) ?
		RH_CLEAN : RH_NOSYNC;
	nreg->rh = rh;
	nreg->key = region;

	INIT_LIST_HEAD(&nreg->list);

	atomic_set(&nreg->pending, 0);
	bio_list_init(&nreg->delayed_bios);
	write_lock_irq(&rh->hash_lock);

	reg = __rh_lookup(rh, region);
	if (reg)
		/* we lost the race */
		mempool_free(nreg, rh->region_pool);

	else {
		__rh_insert(rh, nreg);
		if (nreg->state == RH_CLEAN) {
			spin_lock(&rh->region_lock);
			list_add(&nreg->list, &rh->clean_regions);
			spin_unlock(&rh->region_lock);
		}
		reg = nreg;
	}
	write_unlock_irq(&rh->hash_lock);
	read_lock(&rh->hash_lock);

	return reg;
}

static inline struct region *__rh_find(struct region_hash *rh, region_t region)
{
	struct region *reg;

	reg = __rh_lookup(rh, region);
	if (!reg)
		reg = __rh_alloc(rh, region);

	return reg;
}

static int rh_state(struct region_hash *rh, region_t region, int may_block)
{
	int r;
	struct region *reg;

	read_lock(&rh->hash_lock);
	reg = __rh_lookup(rh, region);
	read_unlock(&rh->hash_lock);

	if (reg)
		return reg->state;

	/*
	 * The region wasn't in the hash, so we fall back to the
	 * dirty log.
	 */
	r = rh->log->type->in_sync(rh->log, region, may_block);

	/*
	 * Any error from the dirty log (eg. -EWOULDBLOCK) gets
	 * taken as a RH_NOSYNC
	 */
	return r == 1 ? RH_CLEAN : RH_NOSYNC;
}

static inline int rh_in_sync(struct region_hash *rh,
			     region_t region, int may_block)
{
	int state = rh_state(rh, region, may_block);
	return state == RH_CLEAN || state == RH_DIRTY;
}

static void dispatch_bios(struct mirror_set *ms, struct bio_list *bio_list)
{
	struct bio *bio;

	while ((bio = bio_list_pop(bio_list))) {
		queue_bio(ms, bio, WRITE);
	}
}

static void rh_update_states(struct region_hash *rh)
{
	struct region *reg, *next;

	LIST_HEAD(clean);
	LIST_HEAD(recovered);

	/*
	 * Quickly grab the lists.
	 */
	write_lock_irq(&rh->hash_lock);
	spin_lock(&rh->region_lock);
	if (!list_empty(&rh->clean_regions)) {
		list_splice(&rh->clean_regions, &clean);
		INIT_LIST_HEAD(&rh->clean_regions);

		list_for_each_entry (reg, &clean, list) {
			rh->log->type->clear_region(rh->log, reg->key);
			list_del(&reg->hash_list);
		}
	}

	if (!list_empty(&rh->recovered_regions)) {
		list_splice(&rh->recovered_regions, &recovered);
		INIT_LIST_HEAD(&rh->recovered_regions);

		list_for_each_entry (reg, &recovered, list)
			list_del(&reg->hash_list);
	}
	spin_unlock(&rh->region_lock);
	write_unlock_irq(&rh->hash_lock);

	/*
	 * All the regions on the recovered and clean lists have
	 * now been pulled out of the system, so no need to do
	 * any more locking.
	 */
	list_for_each_entry_safe (reg, next, &recovered, list) {
		rh->log->type->clear_region(rh->log, reg->key);
		rh->log->type->complete_resync_work(rh->log, reg->key, 1);
		dispatch_bios(rh->ms, &reg->delayed_bios);
		up(&rh->recovery_count);
		mempool_free(reg, rh->region_pool);
	}

	if (!list_empty(&recovered))
		rh->log->type->flush(rh->log);

	list_for_each_entry_safe (reg, next, &clean, list)
		mempool_free(reg, rh->region_pool);
}

static void rh_inc(struct region_hash *rh, region_t region)
{
	struct region *reg;

	read_lock(&rh->hash_lock);
	reg = __rh_find(rh, region);

	spin_lock_irq(&rh->region_lock);
	atomic_inc(&reg->pending);

	if (reg->state == RH_CLEAN) {
		reg->state = RH_DIRTY;
		list_del_init(&reg->list);	/* take off the clean list */
		spin_unlock_irq(&rh->region_lock);

		rh->log->type->mark_region(rh->log, reg->key);
	} else
		spin_unlock_irq(&rh->region_lock);

	read_unlock(&rh->hash_lock);
}

static void rh_inc_pending(struct region_hash *rh, struct bio_list *bios)
{
	struct bio *bio;

	for (bio = bios->head; bio; bio = bio->bi_next)
		rh_inc(rh, bio_to_region(rh, bio));
}

static void rh_dec(struct region_hash *rh, region_t region)
{
	unsigned long flags;
	struct region *reg;
	int should_wake = 0;

	read_lock(&rh->hash_lock);
	reg = __rh_lookup(rh, region);
	read_unlock(&rh->hash_lock);

	spin_lock_irqsave(&rh->region_lock, flags);
	if (atomic_dec_and_test(&reg->pending)) {
		if (reg->state == RH_RECOVERING) {
			list_add_tail(&reg->list, &rh->quiesced_regions);
		} else {
			reg->state = RH_CLEAN;
			list_add(&reg->list, &rh->clean_regions);
		}
		should_wake = 1;
	}
	spin_unlock_irqrestore(&rh->region_lock, flags);

	if (should_wake)
		wake();
}

/*
 * Starts quiescing a region in preparation for recovery.
 */
static int __rh_recovery_prepare(struct region_hash *rh)
{
	int r;
	struct region *reg;
	region_t region;

	/*
	 * Ask the dirty log what's next.
	 */
	r = rh->log->type->get_resync_work(rh->log, &region);
	if (r <= 0)
		return r;

	/*
	 * Get this region, and start it quiescing by setting the
	 * recovering flag.
	 */
	read_lock(&rh->hash_lock);
	reg = __rh_find(rh, region);
	read_unlock(&rh->hash_lock);

	spin_lock_irq(&rh->region_lock);
	reg->state = RH_RECOVERING;

	/* Already quiesced ? */
	if (atomic_read(&reg->pending))
		list_del_init(&reg->list);

	else {
		list_del_init(&reg->list);
		list_add(&reg->list, &rh->quiesced_regions);
	}
	spin_unlock_irq(&rh->region_lock);

	return 1;
}

static void rh_recovery_prepare(struct region_hash *rh)
{
	while (!down_trylock(&rh->recovery_count))
		if (__rh_recovery_prepare(rh) <= 0) {
			up(&rh->recovery_count);
			break;
		}
}

/*
 * Returns any quiesced regions.
 */
static struct region *rh_recovery_start(struct region_hash *rh)
{
	struct region *reg = NULL;

	spin_lock_irq(&rh->region_lock);
	if (!list_empty(&rh->quiesced_regions)) {
		reg = list_entry(rh->quiesced_regions.next,
				 struct region, list);
		list_del_init(&reg->list);	/* remove from the quiesced list */
	}
	spin_unlock_irq(&rh->region_lock);

	return reg;
}

/* FIXME: success ignored for now */
static void rh_recovery_end(struct region *reg, int success)
{
	struct region_hash *rh = reg->rh;

	spin_lock_irq(&rh->region_lock);
	list_add(&reg->list, &reg->rh->recovered_regions);
	spin_unlock_irq(&rh->region_lock);

	wake();
}

static void rh_flush(struct region_hash *rh)
{
	rh->log->type->flush(rh->log);
}

static void rh_delay(struct region_hash *rh, struct bio *bio)
{
	struct region *reg;

	read_lock(&rh->hash_lock);
	reg = __rh_find(rh, bio_to_region(rh, bio));
	bio_list_add(&reg->delayed_bios, bio);
	read_unlock(&rh->hash_lock);
}

static void rh_stop_recovery(struct region_hash *rh)
{
	int i;

	/* wait for any recovering regions */
	for (i = 0; i < MAX_RECOVERY; i++)
		down(&rh->recovery_count);
}

static void rh_start_recovery(struct region_hash *rh)
{
	int i;

	for (i = 0; i < MAX_RECOVERY; i++)
		up(&rh->recovery_count);

	wake();
}

/*-----------------------------------------------------------------
 * Mirror set structures.
 *---------------------------------------------------------------*/
struct mirror {
	atomic_t error_count;  /* Error counter to flag mirror failure */
	struct mirror_set *ms;
	struct dm_dev *dev;
	sector_t offset;
};

struct mirror_set {
	struct dm_target *ti;
	struct list_head list;
	struct region_hash rh;
	struct kcopyd_client *kcopyd_client;

	spinlock_t lock;	/* protects the lists */
	struct bio_list reads;
	struct bio_list writes;
	struct bio_list failures;
	struct work_struct failure_work;
	struct completion failure_completion;

	/* recovery */
	atomic_t suspended;
	region_t nr_regions;
	int in_sync;

	unsigned int nr_mirrors;
	spinlock_t choose_lock; /* protects select in choose_mirror(). */
	atomic_t read_count;    /* Read counter for read balancing. */
	unsigned int read_mirror;       /* Last mirror read. */
	struct mirror *default_mirror;  /* Default mirror. */
 	struct mirror mirror[0];
};

struct bio_map_info {
	struct mirror *bmi_m;
	struct dm_bio_details bmi_bd;
};

static mempool_t *bio_map_info_pool = NULL;

static void *bio_map_info_alloc(int gfp_mask, void *pool_data){
	return kmalloc(sizeof(struct bio_map_info), gfp_mask);
}

static void bio_map_info_free(void *element, void *pool_data){
	kfree(element);
}

/*
 * Every mirror should look like this one.
 */
#define DEFAULT_MIRROR 0

/*
 * This is yucky.  We squirrel the mirror struct away inside
 * bi_next for read/write buffers.  This is safe since the bh
 * doesn't get submitted to the lower levels of block layer.
 */
static struct mirror *bio_get_m(struct bio *bio)
{
	return (struct mirror *) bio->bi_next;
}

static void bio_set_m(struct bio *bio, struct mirror *m)
{
	bio->bi_next = (struct bio *) m;
}

/*-----------------------------------------------------------------
 * Recovery.
 *
 * When a mirror is first activated we may find that some regions
 * are in the no-sync state.  We have to recover these by
 * recopying from the default mirror to all the others.
 *---------------------------------------------------------------*/
static void recovery_complete(int read_err, unsigned int write_err,
			      void *context)
{
	struct region *reg = (struct region *) context;

	/* FIXME: better error handling */
	rh_recovery_end(reg, read_err || write_err);
}

static int recover(struct mirror_set *ms, struct region *reg)
{
	int r;
	unsigned int i;
	struct io_region from, to[KCOPYD_MAX_REGIONS], *dest;
	struct mirror *m;
	unsigned long flags = 0;

	/* fill in the source */
	m = ms->default_mirror;
	from.bdev = m->dev->bdev;
	from.sector = m->offset + region_to_sector(reg->rh, reg->key);
	if (reg->key == (ms->nr_regions - 1)) {
		/*
		 * The final region may be smaller than
		 * region_size.
		 */
		from.count = ms->ti->len & (reg->rh->region_size - 1);
		if (!from.count)
			from.count = reg->rh->region_size;
	} else
		from.count = reg->rh->region_size;

	/* fill in the destinations */
	for (i = 0, dest = to; i < ms->nr_mirrors; i++) {
		if (&ms->mirror[i] == ms->default_mirror)
			continue;

		m = ms->mirror + i;
		dest->bdev = m->dev->bdev;
		dest->sector = m->offset + region_to_sector(reg->rh, reg->key);
		dest->count = from.count;
		dest++;
	}

	/* hand to kcopyd */
	set_bit(KCOPYD_IGNORE_ERROR, &flags);
	r = kcopyd_copy(ms->kcopyd_client, &from, ms->nr_mirrors - 1, to, flags,
			recovery_complete, reg);

	return r;
}

static void do_recovery(struct mirror_set *ms)
{
	int r;
	struct region *reg;
	struct dirty_log *log = ms->rh.log;

	/*
	 * Start quiescing some regions.
	 */
	rh_recovery_prepare(&ms->rh);

	/*
	 * Copy any already quiesced regions.
	 */
	while ((reg = rh_recovery_start(&ms->rh))) {
		r = recover(ms, reg);
		if (r)
			rh_recovery_end(reg, 0);
	}

	/*
	 * Update the in sync flag.
	 */
	if (!ms->in_sync &&
	    (log->type->get_sync_count(log) == ms->nr_regions)) {
		/* the sync is complete */
		dm_table_event(ms->ti->table);
		ms->in_sync = 1;
	}
}

/*-----------------------------------------------------------------
 * Misc Functions
 *---------------------------------------------------------------*/
#define MIN_READS       128
/*
 * choose_mirror
 * @ms: the mirror set
 * @m: mirror that has failed, or NULL if just choosing
 *
 * Returns: chosen mirror, or NULL on failure
 */
static struct mirror *choose_mirror(struct mirror_set *ms, struct mirror *m)
{
	int i, retry;
	unsigned long flags;
	struct mirror *ret = NULL;

	spin_lock_irqsave(&ms->choose_lock, flags);

	if (unlikely(m == ms->default_mirror)) {
		i = DEFAULT_MIRROR;
		atomic_set(&ms->read_count, MIN_READS);
	} else
		i = ms->read_mirror;

	for (retry = 0; retry < ms->nr_mirrors; ) {
		i %= ms->nr_mirrors;
		ret = ms->mirror + i;

		if (unlikely(atomic_read(&ret->error_count))) {
			retry++;
			i++;
		} else {
			/*
			 * Guarantee that a number of read IOs
			 * get queued to the same mirror.
			 */
			if (atomic_dec_and_test(&ms->read_count)) {
				atomic_set(&ms->read_count, MIN_READS);
				i++;
			}

			ms->read_mirror = i;
			break;
		}
	}

	/* Check for failure of default mirror, reset if necessary */
	if (unlikely(m == ms->default_mirror))
		ms->default_mirror = ret;

	spin_unlock_irqrestore(&ms->choose_lock, flags);

	if (unlikely(atomic_read(&ret->error_count))) {
		DMERR("All mirror devices are dead. Unable to choose mirror.");
		return NULL;
	}

	return ret;
}

static void fail_mirror(struct mirror *m)
{
	DMINFO("incrementing error_count on %s", m->dev->name);
	atomic_inc(&m->error_count);

	choose_mirror(m->ms, m);
}

static int default_ok(struct mirror *m)
{
	return !atomic_read(&m->ms->default_mirror->error_count);
}

/*
 * remap a buffer to a particular mirror.
 */
static sector_t map_sector(struct mirror *m, struct bio *bio)
{
	return m->offset + (bio->bi_sector - m->ms->ti->begin);
}

static void map_bio(struct mirror *m, struct bio *bio)
{
	bio->bi_bdev = m->dev->bdev;
	bio->bi_sector = map_sector(m, bio);
}

static void map_region(struct io_region *io, struct mirror *m,
		       struct bio *bio)
{
	io->bdev = m->dev->bdev;
	io->sector = map_sector(m, bio);
	io->count = bio->bi_size >> 9;
}

/*-----------------------------------------------------------------
 * Reads
 *---------------------------------------------------------------*/
static void read_callback(unsigned long error, void *context)
{
	struct bio *bio = (struct bio *)context;
	struct mirror *m;

	m = bio_get_m(bio);
	bio_set_m(bio, NULL);

	if (unlikely(error)) {
		DMWARN("A read failure occurred on a mirror device.");
		fail_mirror(m);
		if (likely(default_ok(m))) {
			DMWARN("Trying different device.");
			queue_bio(m->ms, bio, bio_rw(bio));
		} else {
			DMERR("No other device available, failing I/O.");
			bio_endio(bio, 0, -EIO);
		}
	} else
		bio_endio(bio, bio->bi_size, 0);
}

/* Asynchronous read. */
static void read_async_bio(struct mirror *m, struct bio *bio)
{
	struct io_region io;

	map_region(&io, m, bio);
	bio_set_m(bio, m);
	dm_io_async_bvec(1, &io, READ,
			 bio->bi_io_vec + bio->bi_idx,
			 read_callback, bio);
}

static void do_reads(struct mirror_set *ms, struct bio_list *reads)
{
	struct bio *bio;
	struct mirror *m;

	while ((bio = bio_list_pop(reads))) {
		/*
		 * We can only read balance if the region is in sync.
		 */
		if (likely(rh_in_sync(&ms->rh,
				      bio_to_region(&ms->rh, bio),
				      0)))
			m = choose_mirror(ms, NULL);
		else {
			m = ms->default_mirror;

			/* If the default fails, we give up .*/
			if (unlikely(m && atomic_read(&m->error_count)))
				m = NULL;
		}

		if (likely(m))
			read_async_bio(m, bio);
		else
			bio_endio(bio, 0, -EIO);
	}
}

/*-----------------------------------------------------------------
 * Writes.
 *
 * We do different things with the write io depending on the
 * state of the region that it's in:
 *
 * SYNC: 	increment pending, use kcopyd to write to *all* mirrors
 * RECOVERING:	delay the io until recovery completes
 * NOSYNC:	increment pending, just write to the default mirror
 *---------------------------------------------------------------*/
static void write_failure_handler(void *data)
{
	struct bio *bio;
	struct bio_list failed_writes;
	struct mirror_set *ms = (struct mirror_set *)data;
	struct dirty_log *log = ms->rh.log;

	if (log->type->get_failure_response(log) == DMLOG_IOERR_BLOCK) {
		dm_table_event(ms->ti->table);
		wait_for_completion(&ms->failure_completion);
	}

	/* Take list out to handle endios. */
	spin_lock_irq(&ms->lock);
	failed_writes = ms->failures;
	bio_list_init(&ms->failures);
	spin_unlock_irq(&ms->lock);

	while ((bio = bio_list_pop(&failed_writes)))
		bio_endio(bio, bio->bi_size, 0);
}

static void write_callback(unsigned long error, void *context)
{
	unsigned int i, ret = 0;
	struct bio *bio = (struct bio *) context;
	struct mirror_set *ms;
	int uptodate = 0, run;
 
	ms = (bio_get_m(bio))->ms;
	bio_set_m(bio, NULL);
 
	/*
	 * NOTE: We don't decrement the pending count here,
	 * instead it is done by the targets endio function.
	 * This way we handle both writes to SYNC and NOSYNC
	 * regions with the same code.
	 */
	if (unlikely(error)) {
		DMERR("Error during write occurred.");

		/*
		 * Test all bits - if all failed, fail io.
		 * Otherwise, go through hassle of failing a device...
		 */
		for (i = 0; i < ms->nr_mirrors; i++) {
			if (test_bit(i, &error))
				fail_mirror(ms->mirror + i);
			else
				uptodate = 1;
		}

		if (likely(uptodate)) {
			spin_lock(&ms->lock);
			if (atomic_read(&ms->suspended)) {
				/*
				 * The device is suspended, it is
				 * safe to complete I/O.
				 */
				spin_unlock(&ms->lock);
			} else {
				/*
				 * Need to raise event.  Since raising
				 * events can block, we need to do it in
				 * seperate thread.
				 *
				 * run gets set if this will be the first
				 * bio in the list.
				 */
				run = !ms->failures.head;
				bio_list_add(&ms->failures, bio);
				spin_unlock(&ms->lock);

				if (run)
					queue_work(_kmir_mon_wq,
						   &ms->failure_work);

				return;
			}
		} else {
			DMERR("All replicated volumes dead, failing I/O");
			/* None of the writes succeeded, fail the I/O. */
			ret = -EIO;
		}
	}
 
	bio_endio(bio, bio->bi_size, ret);
}

static void do_write(struct mirror_set *ms, struct bio *bio)
{
	unsigned int i;
	struct io_region io[ms->nr_mirrors], *dest = io;
	struct mirror *m;

	for (i = 0, m = ms->mirror; i < ms->nr_mirrors; i++, m++)
		map_region(dest++, m, bio);

	if (likely(dest - io)) {	
		/*
		 * We can use the default mirror here, because we
		 * only need it in order to retrieve the reference
		 * to the mirror set in write_callback().
		 */
		bio_set_m(bio, ms->default_mirror);
		dm_io_async_bvec(dest - io, io, WRITE,
				 bio->bi_io_vec + bio->bi_idx,
				 write_callback, bio);
	} else
		bio_endio(bio, bio->bi_size, -EIO);
}

static void do_writes(struct mirror_set *ms, struct bio_list *writes)
{
	int state;
	struct bio *bio;
	struct bio_list sync, nosync, recover, *this_list = NULL;
	struct bio_list requeue;
	struct dirty_log *log = ms->rh.log;
	region_t region;

	if (!writes->head)
		return;

	/*
	 * Classify each write.
	 */
	bio_list_init(&sync);
	bio_list_init(&nosync);
	bio_list_init(&recover);
	bio_list_init(&requeue);

	while ((bio = bio_list_pop(writes))) {
		region = bio_to_region(&ms->rh, bio);

		if (log->type->is_remote_recovering &&
		    log->type->is_remote_recovering(log, region)) {
			bio_list_add(&requeue, bio);
			continue;
		}

		state = rh_state(&ms->rh, region, 1);
		switch (state) {
		case RH_CLEAN:
		case RH_DIRTY:
			this_list = &sync;
			break;

		case RH_NOSYNC:
			this_list = &nosync;
			break;

		case RH_RECOVERING:
			this_list = &recover;
			break;
		}

		bio_list_add(this_list, bio);
	}

	bio_list_merge(writes, &requeue);

	/*
	 * Increment the pending counts for any regions that will
	 * be written to (writes to recover regions are going to
	 * be delayed).
	 */
	rh_inc_pending(&ms->rh, &sync);
	rh_inc_pending(&ms->rh, &nosync);
	rh_flush(&ms->rh);

	/*
	 * Dispatch io.
	 */
	while ((bio = bio_list_pop(&sync)))
		do_write(ms, bio);

	while ((bio = bio_list_pop(&recover)))
		rh_delay(&ms->rh, bio);

	while ((bio = bio_list_pop(&nosync))) {
		map_bio(ms->default_mirror, bio);
		generic_make_request(bio);
	}
}

/*-----------------------------------------------------------------
 * kmirrord
 *---------------------------------------------------------------*/
static LIST_HEAD(_mirror_sets);
static DECLARE_RWSEM(_mirror_sets_lock);

static void do_mirror(struct mirror_set *ms)
{
	struct bio_list reads, writes;

	spin_lock_irq(&ms->lock);
	reads = ms->reads;
	writes = ms->writes;
	bio_list_init(&ms->reads);
	bio_list_init(&ms->writes);
	spin_unlock_irq(&ms->lock);

	rh_update_states(&ms->rh);
	do_recovery(ms);
	do_reads(ms, &reads);
	do_writes(ms, &writes);
}

static void do_work(void *ignored)
{
	struct mirror_set *ms;

	down_read(&_mirror_sets_lock);
	list_for_each_entry (ms, &_mirror_sets, list)
		do_mirror(ms);
	up_read(&_mirror_sets_lock);
}

/*-----------------------------------------------------------------
 * Target functions
 *---------------------------------------------------------------*/
static struct mirror_set *alloc_context(unsigned int nr_mirrors,
					uint32_t region_size,
					struct dm_target *ti,
					struct dirty_log *dl)
{
	size_t len;
	struct mirror_set *ms = NULL;

	if (array_too_big(sizeof(*ms), sizeof(ms->mirror[0]), nr_mirrors))
		return NULL;

	len = sizeof(*ms) + (sizeof(ms->mirror[0]) * nr_mirrors);

	ms = kmalloc(len, GFP_KERNEL);
	if (!ms) {
		ti->error = "dm-mirror: Cannot allocate mirror context";
		return NULL;
	}

	memset(ms, 0, len);
	spin_lock_init(&ms->lock);
	spin_lock_init(&ms->choose_lock);

	ms->ti = ti;
	ms->nr_mirrors = nr_mirrors;
	ms->nr_regions = dm_sector_div_up(ti->len, region_size);
	ms->in_sync = 0;
	ms->default_mirror = &ms->mirror[DEFAULT_MIRROR];

	/* a resume must be issued to start the device */
	atomic_set(&ms->suspended, 1);

	if (rh_init(&ms->rh, ms, dl, region_size, ms->nr_regions)) {
		ti->error = "dm-mirror: Error creating dirty region hash";
		kfree(ms);
		return NULL;
	}

	atomic_set(&ms->read_count, MIN_READS);

	bio_list_init(&ms->failures);
	INIT_WORK(&ms->failure_work, write_failure_handler, ms);

	init_completion(&ms->failure_completion);

	return ms;
}

static void free_context(struct mirror_set *ms, struct dm_target *ti,
			 unsigned int m)
{
	while (m--)
		dm_put_device(ti, ms->mirror[m].dev);

	rh_exit(&ms->rh);
	kfree(ms);
}

static inline int _check_region_size(struct dm_target *ti, uint32_t size)
{
	return !(size % (PAGE_SIZE >> 9) || (size & (size - 1)) ||
		 size > ti->len);
}

static int get_mirror(struct mirror_set *ms, struct dm_target *ti,
		      unsigned int mirror, char **argv)
{
	sector_t offset;

	if (sscanf(argv[1], SECTOR_FORMAT, &offset) != 1) {
		ti->error = "dm-mirror: Invalid offset";
		return -EINVAL;
	}

	if (dm_get_device(ti, argv[0], offset, ti->len,
			  dm_table_get_mode(ti->table),
			  &ms->mirror[mirror].dev)) {
		ti->error = "dm-mirror: Device lookup failure";
		return -ENXIO;
	}

	ms->mirror[mirror].offset = offset;
	atomic_set(&(ms->mirror[mirror].error_count), 0);
	ms->mirror[mirror].ms = ms;

	return 0;
}

static int add_mirror_set(struct mirror_set *ms)
{
	down_write(&_mirror_sets_lock);
	list_add_tail(&ms->list, &_mirror_sets);
	up_write(&_mirror_sets_lock);
	wake();

	return 0;
}

static void del_mirror_set(struct mirror_set *ms)
{
	down_write(&_mirror_sets_lock);
	list_del(&ms->list);
	up_write(&_mirror_sets_lock);
}

/*
 * Create dirty log: log_type #log_params <log_params>
 */
static struct dirty_log *create_dirty_log(struct dm_target *ti,
					  unsigned int argc, char **argv,
					  unsigned int *args_used)
{
	unsigned int param_count;
	struct dirty_log *dl;

	if (argc < 2) {
		ti->error = "dm-mirror: Insufficient mirror log arguments";
		return NULL;
	}

	if (sscanf(argv[1], "%u", &param_count) != 1) {
		ti->error = "dm-mirror: Invalid mirror log argument count";
		return NULL;
	}

	*args_used = 2 + param_count;

	if (argc < *args_used) {
		ti->error = "dm-mirror: Insufficient mirror log arguments";
		return NULL;
	}

	dl = dm_create_dirty_log(argv[0], ti, param_count, argv + 2);
	if (!dl) {
		ti->error = "dm-mirror: Error creating mirror dirty log";
		return NULL;
	}

	if (!_check_region_size(ti, dl->type->get_region_size(dl))) {
		ti->error = "dm-mirror: Invalid region size";
		dm_destroy_dirty_log(dl);
		return NULL;
	}

	return dl;
}

/*
 * Construct a mirror mapping:
 *
 * log_type #log_params <log_params>
 * #mirrors [mirror_path offset]{2,}
 *
 * log_type is "core" or "disk"
 * #log_params is between 1 and 3
 */
#define DM_IO_PAGES 64
static int mirror_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	int r;
	unsigned int nr_mirrors, m, args_used;
	struct mirror_set *ms;
	struct dirty_log *dl;

	dl = create_dirty_log(ti, argc, argv, &args_used);
	if (!dl)
		return -EINVAL;

	argv += args_used;
	argc -= args_used;

	if (!argc || sscanf(argv[0], "%u", &nr_mirrors) != 1 ||
	    nr_mirrors < 2 || nr_mirrors > KCOPYD_MAX_REGIONS + 1) {
		ti->error = "dm-mirror: Invalid number of mirrors";
		dm_destroy_dirty_log(dl);
		return -EINVAL;
	}

	argv++, argc--;

	if (argc != nr_mirrors * 2) {
		ti->error = "dm-mirror: Wrong number of mirror arguments";
		dm_destroy_dirty_log(dl);
		return -EINVAL;
	}

	ms = alloc_context(nr_mirrors, dl->type->get_region_size(dl), ti, dl);
	if (!ms) {
		dm_destroy_dirty_log(dl);
		return -ENOMEM;
	}

	/* Get the mirror parameter sets */
	for (m = 0; m < nr_mirrors; m++) {
		r = get_mirror(ms, ti, m, argv);
		if (r) {
			free_context(ms, ti, m);
			return r;
		}
		argv += 2;
		argc -= 2;
	}

	ti->private = ms;
 	ti->split_io = ms->rh.region_size;

	r = kcopyd_client_create(DM_IO_PAGES, &ms->kcopyd_client);
	if (r) {
		free_context(ms, ti, ms->nr_mirrors);
		return r;
	}

	add_mirror_set(ms);
	return 0;
}

static void mirror_dtr(struct dm_target *ti)
{
	struct mirror_set *ms = (struct mirror_set *) ti->private;

	del_mirror_set(ms);
	kcopyd_client_destroy(ms->kcopyd_client);
	free_context(ms, ti, ms->nr_mirrors);
}

static void queue_bio(struct mirror_set *ms, struct bio *bio, int rw)
{
	unsigned long flags;
	int should_wake = 0;
	struct bio_list *bl;

	bl = (rw == WRITE) ? &ms->writes : &ms->reads;
	spin_lock_irqsave(&ms->lock, flags);
	should_wake = !(bl->head);
	bio_list_add(bl, bio);
	spin_unlock_irqrestore(&ms->lock, flags);

	if (should_wake)
		wake();
}

/*
 * Mirror mapping function
 */
static int mirror_map(struct dm_target *ti, struct bio *bio,
		      union map_info *map_context)
{
	int r, rw = bio_rw(bio);
	struct mirror *m;
	struct mirror_set *ms = ti->private;
	struct dm_bio_details *bd;
	struct bio_map_info *bmi;

	if (rw == WRITE) {
		/* Save region for mirror_end_io() handler */
		map_context->ll = bio_to_region(&ms->rh, bio);
		queue_bio(ms, bio, rw);
		return 0;
	}

	/* It's all about the READs now */

	r = ms->rh.log->type->in_sync(ms->rh.log,
				      bio_to_region(&ms->rh, bio), 0);
	if (r < 0 && r != -EWOULDBLOCK)
		return r;

	if (r == -EWOULDBLOCK)
		r = 0;

	if (likely(r)) {
		/*
		 * Optimize reads by avoiding to hand them to daemon.
		 *
		 * In case they fail, queue them for another shot
		 * in the mirror_end_io() function.
		 */
		m = choose_mirror(ms, NULL);
		if (likely(m)) {
			bmi = mempool_alloc(bio_map_info_pool, GFP_NOIO);

			if (likely(bmi)) {
				/* without this, a read is not retryable */
				bd = &bmi->bmi_bd;
				dm_bio_record(bd, bio);
				map_context->ptr = bmi;
				bmi->bmi_m = m;
			} else {
				/* we could fail now, but we can at least  **
				** give it a shot.  The bd is only used to **
				** retry in the event of a failure anyway. **
				** If we fail, we can fail the I/O then.   */
				map_context->ptr = NULL;
			}

			map_bio(m, bio);
			return 1; /* Mapped -> queue request. */
		} else
			return -EIO;
	} else {
		/* Either not clean, or -EWOULDBLOCK */
		if (rw == READA)
			return -EWOULDBLOCK;

		queue_bio(ms, bio, rw);
	}

	return 0;
}

static int mirror_end_io(struct dm_target *ti, struct bio *bio,
			 int error, union map_info *map_context)
{
	int rw = bio_rw(bio);
	struct mirror_set *ms = (struct mirror_set *) ti->private;
	struct mirror *m = NULL;
	struct dm_bio_details *bd = NULL;

	/*
	 * We need to dec pending if this was a write.
	 */
	if (rw == WRITE) {
		rh_dec(&ms->rh, map_context->ll);
		return error;
	}

	if (error == -EOPNOTSUPP)
		goto out;

	if ((error == -EWOULDBLOCK) && bio_rw_ahead(bio))
		goto out;

	if (unlikely(error)) {
		DMERR("A read failure occurred on a mirror device.");
		if (!map_context->ptr) {
			/*
			 * There wasn't enough memory to record necessary
			 * information for a retry.
			 */
			DMERR("Out of memory causing inability to retry read.");
			return -EIO;
		}
		m = ((struct bio_map_info *)map_context->ptr)->bmi_m;
		fail_mirror(m); /* Flag error on mirror. */

		/*
		 * A failed read needs to get queued
		 * to the daemon for another shot to
		 * one (if any) intact mirrors.
		 */
		if (default_ok(m)) {
			bd = &(((struct bio_map_info *)map_context->ptr)->bmi_bd);

			DMWARN("Trying different device.");
			dm_bio_restore(bd, bio);
			mempool_free(map_context->ptr, bio_map_info_pool);
			map_context->ptr = NULL;
			queue_bio(ms, bio, rw);
			return 1; /* We want another shot on the bio. */
		}
		DMERR("All replicated volumes dead, failing I/O");
	}

 out:
	if (map_context->ptr)
		mempool_free(map_context->ptr, bio_map_info_pool);

	return error;
}

static void mirror_presuspend(struct dm_target *ti)
{
	struct mirror_set *ms = (struct mirror_set *) ti->private;
	struct dirty_log *log = ms->rh.log;
	unsigned long flags;
	int run;

	/*
	 * Only run the completion if we are suspending after
	 * a disk failure.
	 */
	spin_lock_irqsave(&ms->lock, flags);
	run = ms->failures.head ? 1 : 0;
	spin_unlock_irqrestore(&ms->lock, flags);

	if (run && (log->type->get_failure_response(log) == DMLOG_IOERR_BLOCK))
		complete(&ms->failure_completion);

	if (log->type->presuspend && log->type->presuspend(log))
		/* FIXME: need better error handling */
		DMWARN("log presuspend failed");

}  

static void mirror_postsuspend(struct dm_target *ti)
{
	struct mirror_set *ms = (struct mirror_set *) ti->private;
	struct dirty_log *log = ms->rh.log;

	rh_stop_recovery(&ms->rh);
	if (log->type->postsuspend && log->type->postsuspend(log))
		/* FIXME: need better error handling */
		DMWARN("log postsuspend failed");
	atomic_set(&ms->suspended, 1);
}

static void mirror_resume(struct dm_target *ti)
{
	struct mirror_set *ms = (struct mirror_set *) ti->private;
	struct dirty_log *log = ms->rh.log;

	if (log->type->resume && log->type->resume(log))
		/* FIXME: need better error handling */
		DMWARN("log resume failed");

	if (atomic_dec_and_test(&ms->suspended))
		rh_start_recovery(&ms->rh);
	atomic_set(&ms->suspended, 0);
}

static int mirror_status(struct dm_target *ti, status_type_t type,
			 char *result, unsigned int maxlen)
{
	unsigned int m, sz = 0;
	struct mirror_set *ms = (struct mirror_set *) ti->private;
	char buffer[ms->nr_mirrors + 1];

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%d ", ms->nr_mirrors);
		for (m = 0; m < ms->nr_mirrors; m++) {
			DMEMIT("%s ", ms->mirror[m].dev->name);
			buffer[m] = atomic_read(&(ms->mirror[m].error_count)) ? 
				'D' : 'A';
		}
		buffer[m] = '\0';

		DMEMIT(SECTOR_FORMAT "/" SECTOR_FORMAT " 1 %s ",
		       ms->rh.log->type->get_sync_count(ms->rh.log),
		       ms->nr_regions, buffer);
		ms->rh.log->type->status(ms->rh.log, type, result+sz, maxlen-sz);
		break;

	case STATUSTYPE_TABLE:
		sz = ms->rh.log->type->status(ms->rh.log, type, result, maxlen);
		DMEMIT("%d ", ms->nr_mirrors);
		for (m = 0; m < ms->nr_mirrors; m++)
			DMEMIT("%s " SECTOR_FORMAT " ",
			       ms->mirror[m].dev->name, ms->mirror[m].offset);
	}

	return 0;
}

static struct target_type mirror_target = {
	.name	 = "mirror",
	.version = {1, 1, 0},
	.module	 = THIS_MODULE,
	.ctr	 = mirror_ctr,
	.dtr	 = mirror_dtr,
	.map	 = mirror_map,
	.end_io	 = mirror_end_io,
	.presuspend = mirror_presuspend,
	.postsuspend = mirror_postsuspend,
	.resume	 = mirror_resume,
	.status	 = mirror_status,
};

static int __init dm_mirror_init(void)
{
	int r;

	bio_map_info_pool = mempool_create(100, bio_map_info_alloc,
					   bio_map_info_free, NULL);
	if (!bio_map_info_pool)
		return -ENOMEM;

	r = dm_dirty_log_init();
	if (r)
		return r;

	_kmirrord_wq = create_singlethread_workqueue("kmirrord");
	if (!_kmirrord_wq) {
		DMERR("couldn't start kmirrord");
		dm_dirty_log_exit();
		return -ENOMEM;
	}
	INIT_WORK(&_kmirrord_work, do_work, NULL);

	_kmir_mon_wq = create_singlethread_workqueue("kmir_mon");
	if (!_kmir_mon_wq) {
		DMERR("couldn't start kmir_mon");
		dm_dirty_log_exit();
		destroy_workqueue(_kmirrord_wq);
		return -ENOMEM;
	}

	r = dm_register_target(&mirror_target);
	if (r < 0) {
		DMERR("%s: Failed to register mirror target",
		      mirror_target.name);
		dm_dirty_log_exit();
		destroy_workqueue(_kmirrord_wq);
		destroy_workqueue(_kmir_mon_wq);
	}

	return r;
}

static void __exit dm_mirror_exit(void)
{
	int r;

	r = dm_unregister_target(&mirror_target);
	if (r < 0)
		DMERR("%s: unregister failed %d", mirror_target.name, r);

	destroy_workqueue(_kmirrord_wq);
	dm_dirty_log_exit();
}

/* Module hooks */
module_init(dm_mirror_init);
module_exit(dm_mirror_exit);

MODULE_DESCRIPTION(DM_NAME " mirror target");
MODULE_AUTHOR("Joe Thornber");
MODULE_LICENSE("GPL");

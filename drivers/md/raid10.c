/*
 * raid10.c : Multiple Devices driver for Linux
 *
 * Copyright (C) 2000-2004 Neil Brown
 *
 * RAID-10 support for md.
 *
 * Base on code in raid1.c.  See raid1.c for futher copyright information.
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * You should have received a copy of the GNU General Public License
 * (for example /usr/src/linux/COPYING); if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/raid/raid10.h>

/*
 * RAID10 provides a combination of RAID0 and RAID1 functionality.
 * The layout of data is defined by
 *    chunk_size
 *    raid_disks
 *    near_copies (stored in low byte of layout)
 *    far_copies (stored in second byte of layout)
 *
 * The data to be stored is divided into chunks using chunksize.
 * Each device is divided into far_copies sections.
 * In each section, chunks are laid out in a style similar to raid0, but
 * near_copies copies of each chunk is stored (each on a different drive).
 * The starting device for each section is offset near_copies from the starting
 * device of the previous section.
 * Thus there are (near_copies*far_copies) of each chunk, and each is on a different
 * drive.
 * near_copies and far_copies must be at least one, and there product is at most
 * raid_disks.
 */

/*
 * Number of guaranteed r10bios in case of extreme VM load:
 */
#define	NR_RAID10_BIOS 256

static void unplug_slaves(mddev_t *mddev);

static void * r10bio_pool_alloc(int gfp_flags, void *data)
{
	conf_t *conf = data;
	r10bio_t *r10_bio;
	int size = offsetof(struct r10bio_s, devs[conf->copies]);

	/* allocate a r10bio with room for raid_disks entries in the bios array */
	r10_bio = kmalloc(size, gfp_flags);
	if (r10_bio)
		memset(r10_bio, 0, size);
	else
		unplug_slaves(conf->mddev);

	return r10_bio;
}

static void r10bio_pool_free(void *r10_bio, void *data)
{
	kfree(r10_bio);
}

#define RESYNC_BLOCK_SIZE (64*1024)
//#define RESYNC_BLOCK_SIZE PAGE_SIZE
#define RESYNC_SECTORS (RESYNC_BLOCK_SIZE >> 9)
#define RESYNC_PAGES ((RESYNC_BLOCK_SIZE + PAGE_SIZE-1) / PAGE_SIZE)
#define RESYNC_WINDOW (2048*1024)

/*
 * When performing a resync, we need to read and compare, so
 * we need as many pages are there are copies.
 * When performing a recovery, we need 2 bios, one for read,
 * one for write (we recover only one drive per r10buf)
 *
 */
static void * r10buf_pool_alloc(int gfp_flags, void *data)
{
	conf_t *conf = data;
	struct page *page;
	r10bio_t *r10_bio;
	struct bio *bio;
	int i, j;
	int nalloc;

	r10_bio = r10bio_pool_alloc(gfp_flags, conf);
	if (!r10_bio) {
		unplug_slaves(conf->mddev);
		return NULL;
	}

	if (test_bit(MD_RECOVERY_SYNC, &conf->mddev->recovery))
		nalloc = conf->copies; /* resync */
	else
		nalloc = 2; /* recovery */

	/*
	 * Allocate bios.
	 */
	for (j = nalloc ; j-- ; ) {
		bio = bio_alloc(gfp_flags, RESYNC_PAGES);
		if (!bio)
			goto out_free_bio;
		r10_bio->devs[j].bio = bio;
	}
	/*
	 * Allocate RESYNC_PAGES data pages and attach them
	 * where needed.
	 */
	for (j = 0 ; j < nalloc; j++) {
		bio = r10_bio->devs[j].bio;
		for (i = 0; i < RESYNC_PAGES; i++) {
			page = alloc_page(gfp_flags);
			if (unlikely(!page))
				goto out_free_pages;

			bio->bi_io_vec[i].bv_page = page;
		}
	}

	return r10_bio;

out_free_pages:
	for ( ; i > 0 ; i--)
		__free_page(bio->bi_io_vec[i-1].bv_page);
	while (j--)
		for (i = 0; i < RESYNC_PAGES ; i++)
			__free_page(r10_bio->devs[j].bio->bi_io_vec[i].bv_page);
	j = -1;
out_free_bio:
	while ( ++j < nalloc )
		bio_put(r10_bio->devs[j].bio);
	r10bio_pool_free(r10_bio, conf);
	return NULL;
}

static void r10buf_pool_free(void *__r10_bio, void *data)
{
	int i;
	conf_t *conf = data;
	r10bio_t *r10bio = __r10_bio;
	int j;

	for (j=0; j < conf->copies; j++) {
		struct bio *bio = r10bio->devs[j].bio;
		if (bio) {
			for (i = 0; i < RESYNC_PAGES; i++) {
				__free_page(bio->bi_io_vec[i].bv_page);
				bio->bi_io_vec[i].bv_page = NULL;
			}
			bio_put(bio);
		}
	}
	r10bio_pool_free(r10bio, conf);
}

static void put_all_bios(conf_t *conf, r10bio_t *r10_bio)
{
	int i;

	for (i = 0; i < conf->copies; i++) {
		struct bio **bio = & r10_bio->devs[i].bio;
		if (*bio)
			bio_put(*bio);
		*bio = NULL;
	}
}

static inline void free_r10bio(r10bio_t *r10_bio)
{
	unsigned long flags;

	conf_t *conf = mddev_to_conf(r10_bio->mddev);

	/*
	 * Wake up any possible resync thread that waits for the device
	 * to go idle.
	 */
	spin_lock_irqsave(&conf->resync_lock, flags);
	if (!--conf->nr_pending) {
		wake_up(&conf->wait_idle);
		wake_up(&conf->wait_resume);
	}
	spin_unlock_irqrestore(&conf->resync_lock, flags);

	put_all_bios(conf, r10_bio);
	mempool_free(r10_bio, conf->r10bio_pool);
}

static inline void put_buf(r10bio_t *r10_bio)
{
	conf_t *conf = mddev_to_conf(r10_bio->mddev);
	unsigned long flags;

	mempool_free(r10_bio, conf->r10buf_pool);

	spin_lock_irqsave(&conf->resync_lock, flags);
	if (!conf->barrier)
		BUG();
	--conf->barrier;
	wake_up(&conf->wait_resume);
	wake_up(&conf->wait_idle);

	if (!--conf->nr_pending) {
		wake_up(&conf->wait_idle);
		wake_up(&conf->wait_resume);
	}
	spin_unlock_irqrestore(&conf->resync_lock, flags);
}

static void reschedule_retry(r10bio_t *r10_bio)
{
	unsigned long flags;
	mddev_t *mddev = r10_bio->mddev;
	conf_t *conf = mddev_to_conf(mddev);

	spin_lock_irqsave(&conf->device_lock, flags);
	list_add(&r10_bio->retry_list, &conf->retry_list);
	spin_unlock_irqrestore(&conf->device_lock, flags);

	md_wakeup_thread(mddev->thread);
}

/*
 * raid_end_bio_io() is called when we have finished servicing a mirrored
 * operation and are ready to return a success/failure code to the buffer
 * cache layer.
 */
static void raid_end_bio_io(r10bio_t *r10_bio)
{
	struct bio *bio = r10_bio->master_bio;

	bio_endio(bio, bio->bi_size,
		test_bit(R10BIO_Uptodate, &r10_bio->state) ? 0 : -EIO);
	free_r10bio(r10_bio);
}

/*
 * Update disk head position estimator based on IRQ completion info.
 */
static inline void update_head_pos(int slot, r10bio_t *r10_bio)
{
	conf_t *conf = mddev_to_conf(r10_bio->mddev);

	conf->mirrors[r10_bio->devs[slot].devnum].head_position =
		r10_bio->devs[slot].addr + (r10_bio->sectors);
}

static int raid10_end_read_request(struct bio *bio, unsigned int bytes_done, int error)
{
	int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	r10bio_t * r10_bio = (r10bio_t *)(bio->bi_private);
	int slot, dev;
	conf_t *conf = mddev_to_conf(r10_bio->mddev);

	if (bio->bi_size)
		return 1;

	slot = r10_bio->read_slot;
	dev = r10_bio->devs[slot].devnum;
	/*
	 * this branch is our 'one mirror IO has finished' event handler:
	 */
	if (!uptodate)
		md_error(r10_bio->mddev, conf->mirrors[dev].rdev);
	else
		/*
		 * Set R10BIO_Uptodate in our master bio, so that
		 * we will return a good error code to the higher
		 * levels even if IO on some other mirrored buffer fails.
		 *
		 * The 'master' represents the composite IO operation to
		 * user-side. So if something waits for IO, then it will
		 * wait for the 'master' bio.
		 */
		set_bit(R10BIO_Uptodate, &r10_bio->state);

	update_head_pos(slot, r10_bio);

	/*
	 * we have only one bio on the read side
	 */
	if (uptodate)
		raid_end_bio_io(r10_bio);
	else {
		/*
		 * oops, read error:
		 */
		char b[BDEVNAME_SIZE];
		if (printk_ratelimit())
			printk(KERN_ERR "raid10: %s: rescheduling sector %llu\n",
			       bdevname(conf->mirrors[dev].rdev->bdev,b), (unsigned long long)r10_bio->sector);
		reschedule_retry(r10_bio);
	}

	rdev_dec_pending(conf->mirrors[dev].rdev, conf->mddev);
	return 0;
}

static int raid10_end_write_request(struct bio *bio, unsigned int bytes_done, int error)
{
	int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	r10bio_t * r10_bio = (r10bio_t *)(bio->bi_private);
	int slot, dev;
	conf_t *conf = mddev_to_conf(r10_bio->mddev);

	if (bio->bi_size)
		return 1;

	for (slot = 0; slot < conf->copies; slot++)
		if (r10_bio->devs[slot].bio == bio)
			break;
	dev = r10_bio->devs[slot].devnum;

	/*
	 * this branch is our 'one mirror IO has finished' event handler:
	 */
	if (!uptodate)
		md_error(r10_bio->mddev, conf->mirrors[dev].rdev);
	else
		/*
		 * Set R10BIO_Uptodate in our master bio, so that
		 * we will return a good error code for to the higher
		 * levels even if IO on some other mirrored buffer fails.
		 *
		 * The 'master' represents the composite IO operation to
		 * user-side. So if something waits for IO, then it will
		 * wait for the 'master' bio.
		 */
		set_bit(R10BIO_Uptodate, &r10_bio->state);

	update_head_pos(slot, r10_bio);

	/*
	 *
	 * Let's see if all mirrored write operations have finished
	 * already.
	 */
	if (atomic_dec_and_test(&r10_bio->remaining)) {
		md_write_end(r10_bio->mddev);
		raid_end_bio_io(r10_bio);
	}

	rdev_dec_pending(conf->mirrors[dev].rdev, conf->mddev);
	return 0;
}


/*
 * RAID10 layout manager
 * Aswell as the chunksize and raid_disks count, there are two
 * parameters: near_copies and far_copies.
 * near_copies * far_copies must be <= raid_disks.
 * Normally one of these will be 1.
 * If both are 1, we get raid0.
 * If near_copies == raid_disks, we get raid1.
 *
 * Chunks are layed out in raid0 style with near_copies copies of the
 * first chunk, followed by near_copies copies of the next chunk and
 * so on.
 * If far_copies > 1, then after 1/far_copies of the array has been assigned
 * as described above, we start again with a device offset of near_copies.
 * So we effectively have another copy of the whole array further down all
 * the drives, but with blocks on different drives.
 * With this layout, and block is never stored twice on the one device.
 *
 * raid10_find_phys finds the sector offset of a given virtual sector
 * on each device that it is on. If a block isn't on a device,
 * that entry in the array is set to MaxSector.
 *
 * raid10_find_virt does the reverse mapping, from a device and a
 * sector offset to a virtual address
 */

static void raid10_find_phys(conf_t *conf, r10bio_t *r10bio)
{
	int n,f;
	sector_t sector;
	sector_t chunk;
	sector_t stripe;
	int dev;

	int slot = 0;

	/* now calculate first sector/dev */
	chunk = r10bio->sector >> conf->chunk_shift;
	sector = r10bio->sector & conf->chunk_mask;

	chunk *= conf->near_copies;
	stripe = chunk;
	dev = sector_div(stripe, conf->raid_disks);

	sector += stripe << conf->chunk_shift;

	/* and calculate all the others */
	for (n=0; n < conf->near_copies; n++) {
		int d = dev;
		sector_t s = sector;
		r10bio->devs[slot].addr = sector;
		r10bio->devs[slot].devnum = d;
		slot++;

		for (f = 1; f < conf->far_copies; f++) {
			d += conf->near_copies;
			if (d >= conf->raid_disks)
				d -= conf->raid_disks;
			s += conf->stride;
			r10bio->devs[slot].devnum = d;
			r10bio->devs[slot].addr = s;
			slot++;
		}
		dev++;
		if (dev >= conf->raid_disks) {
			dev = 0;
			sector += (conf->chunk_mask + 1);
		}
	}
	BUG_ON(slot != conf->copies);
}

static sector_t raid10_find_virt(conf_t *conf, sector_t sector, int dev)
{
	sector_t offset, chunk, vchunk;

	while (sector > conf->stride) {
		sector -= conf->stride;
		if (dev < conf->near_copies)
			dev += conf->raid_disks - conf->near_copies;
		else
			dev -= conf->near_copies;
	}

	offset = sector & conf->chunk_mask;
	chunk = sector >> conf->chunk_shift;
	vchunk = chunk * conf->raid_disks + dev;
	sector_div(vchunk, conf->near_copies);
	return (vchunk << conf->chunk_shift) + offset;
}

/**
 *	raid10_mergeable_bvec -- tell bio layer if a two requests can be merged
 *	@q: request queue
 *	@bio: the buffer head that's been built up so far
 *	@biovec: the request that could be merged to it.
 *
 *	Return amount of bytes we can accept at this offset
 *      If near_copies == raid_disk, there are no striping issues,
 *      but in that case, the function isn't called at all.
 */
static int raid10_mergeable_bvec(request_queue_t *q, struct bio *bio,
				struct bio_vec *bio_vec)
{
	mddev_t *mddev = q->queuedata;
	sector_t sector = bio->bi_sector + get_start_sect(bio->bi_bdev);
	int max;
	unsigned int chunk_sectors = mddev->chunk_size >> 9;
	unsigned int bio_sectors = bio->bi_size >> 9;

	max =  (chunk_sectors - ((sector & (chunk_sectors - 1)) + bio_sectors)) << 9;
	if (max < 0) max = 0; /* bio_add cannot handle a negative return */
	if (max <= bio_vec->bv_len && bio_sectors == 0)
		return bio_vec->bv_len;
	else
		return max;
}

/*
 * This routine returns the disk from which the requested read should
 * be done. There is a per-array 'next expected sequential IO' sector
 * number - if this matches on the next IO then we use the last disk.
 * There is also a per-disk 'last know head position' sector that is
 * maintained from IRQ contexts, both the normal and the resync IO
 * completion handlers update this position correctly. If there is no
 * perfect sequential match then we pick the disk whose head is closest.
 *
 * If there are 2 mirrors in the same 2 devices, performance degrades
 * because position is mirror, not device based.
 *
 * The rdev for the device selected will have nr_pending incremented.
 */

/*
 * FIXME: possibly should rethink readbalancing and do it differently
 * depending on near_copies / far_copies geometry.
 */
static int read_balance(conf_t *conf, r10bio_t *r10_bio)
{
	const unsigned long this_sector = r10_bio->sector;
	int disk, slot, nslot;
	const int sectors = r10_bio->sectors;
	sector_t new_distance, current_distance;

	raid10_find_phys(conf, r10_bio);
	spin_lock_irq(&conf->device_lock);
	/*
	 * Check if we can balance. We can balance on the whole
	 * device if no resync is going on, or below the resync window.
	 * We take the first readable disk when above the resync window.
	 */
	if (conf->mddev->recovery_cp < MaxSector
	    && (this_sector + sectors >= conf->next_resync)) {
		/* make sure that disk is operational */
		slot = 0;
		disk = r10_bio->devs[slot].devnum;

		while (!conf->mirrors[disk].rdev ||
		       !conf->mirrors[disk].rdev->in_sync) {
			slot++;
			if (slot == conf->copies) {
				slot = 0;
				disk = -1;
				break;
			}
			disk = r10_bio->devs[slot].devnum;
		}
		goto rb_out;
	}


	/* make sure the disk is operational */
	slot = 0;
	disk = r10_bio->devs[slot].devnum;
	while (!conf->mirrors[disk].rdev ||
	       !conf->mirrors[disk].rdev->in_sync) {
		slot ++;
		if (slot == conf->copies) {
			disk = -1;
			goto rb_out;
		}
		disk = r10_bio->devs[slot].devnum;
	}


	current_distance = abs(this_sector - conf->mirrors[disk].head_position);

	/* Find the disk whose head is closest */

	for (nslot = slot; nslot < conf->copies; nslot++) {
		int ndisk = r10_bio->devs[nslot].devnum;


		if (!conf->mirrors[ndisk].rdev ||
		    !conf->mirrors[ndisk].rdev->in_sync)
			continue;

		if (!atomic_read(&conf->mirrors[ndisk].rdev->nr_pending)) {
			disk = ndisk;
			slot = nslot;
			break;
		}
		new_distance = abs(r10_bio->devs[nslot].addr -
				   conf->mirrors[ndisk].head_position);
		if (new_distance < current_distance) {
			current_distance = new_distance;
			disk = ndisk;
			slot = nslot;
		}
	}

rb_out:
	r10_bio->read_slot = slot;
/*	conf->next_seq_sect = this_sector + sectors;*/

	if (disk >= 0 && conf->mirrors[disk].rdev)
		atomic_inc(&conf->mirrors[disk].rdev->nr_pending);
	spin_unlock_irq(&conf->device_lock);

	return disk;
}

static void unplug_slaves(mddev_t *mddev)
{
	conf_t *conf = mddev_to_conf(mddev);
	int i;
	unsigned long flags;

	spin_lock_irqsave(&conf->device_lock, flags);
	for (i=0; i<mddev->raid_disks; i++) {
		mdk_rdev_t *rdev = conf->mirrors[i].rdev;
		if (rdev && atomic_read(&rdev->nr_pending)) {
			request_queue_t *r_queue = bdev_get_queue(rdev->bdev);

			atomic_inc(&rdev->nr_pending);
			spin_unlock_irqrestore(&conf->device_lock, flags);

			if (r_queue->unplug_fn)
				r_queue->unplug_fn(r_queue);

			spin_lock_irqsave(&conf->device_lock, flags);
			rdev_dec_pending(rdev, mddev);
		}
	}
	spin_unlock_irqrestore(&conf->device_lock, flags);
}
static void raid10_unplug(request_queue_t *q)
{
	unplug_slaves(q->queuedata);
}

static int raid10_issue_flush(request_queue_t *q, struct gendisk *disk,
			     sector_t *error_sector)
{
	mddev_t *mddev = q->queuedata;
	conf_t *conf = mddev_to_conf(mddev);
	unsigned long flags;
	int i, ret = 0;

	spin_lock_irqsave(&conf->device_lock, flags);
	for (i=0; i<mddev->raid_disks; i++) {
		mdk_rdev_t *rdev = conf->mirrors[i].rdev;
		if (rdev && !rdev->faulty) {
			struct block_device *bdev = rdev->bdev;
			request_queue_t *r_queue = bdev_get_queue(bdev);

			if (r_queue->issue_flush_fn) {
				ret = r_queue->issue_flush_fn(r_queue, bdev->bd_disk, error_sector);
				if (ret)
					break;
			}
		}
	}
	spin_unlock_irqrestore(&conf->device_lock, flags);
	return ret;
}

/*
 * Throttle resync depth, so that we can both get proper overlapping of
 * requests, but are still able to handle normal requests quickly.
 */
#define RESYNC_DEPTH 32

static void device_barrier(conf_t *conf, sector_t sect)
{
	spin_lock_irq(&conf->resync_lock);
	wait_event_lock_irq(conf->wait_idle, !waitqueue_active(&conf->wait_resume),
			    conf->resync_lock, unplug_slaves(conf->mddev));

	if (!conf->barrier++) {
		wait_event_lock_irq(conf->wait_idle, !conf->nr_pending,
				    conf->resync_lock, unplug_slaves(conf->mddev));
		if (conf->nr_pending)
			BUG();
	}
	wait_event_lock_irq(conf->wait_resume, conf->barrier < RESYNC_DEPTH,
			    conf->resync_lock, unplug_slaves(conf->mddev));
	conf->next_resync = sect;
	spin_unlock_irq(&conf->resync_lock);
}

static int make_request(request_queue_t *q, struct bio * bio)
{
	mddev_t *mddev = q->queuedata;
	conf_t *conf = mddev_to_conf(mddev);
	mirror_info_t *mirror;
	r10bio_t *r10_bio;
	struct bio *read_bio;
	int i;
	int chunk_sects = conf->chunk_mask + 1;
	const int do_sync = bio_sync(bio);

	if (unlikely(bio_barrier(bio))) {
		bio_endio(bio, bio->bi_size, -EOPNOTSUPP);
		return 0;
	}

	/* If this request crosses a chunk boundary, we need to
	 * split it.  This will only happen for 1 PAGE (or less) requests.
	 */
	if (unlikely( (bio->bi_sector & conf->chunk_mask) + (bio->bi_size >> 9)
		      > chunk_sects &&
		    conf->near_copies < conf->raid_disks)) {
		struct bio_pair *bp;
		/* Sanity check -- queue functions should prevent this happening */
		if (bio->bi_vcnt != 1 ||
		    bio->bi_idx != 0)
			goto bad_map;
		/* This is a one page bio that upper layers
		 * refuse to split for us, so we need to split it.
		 */
		bp = bio_split(bio, bio_split_pool,
			       chunk_sects - (bio->bi_sector & (chunk_sects - 1)) );
		if (make_request(q, &bp->bio1))
			generic_make_request(&bp->bio1);
		if (make_request(q, &bp->bio2))
			generic_make_request(&bp->bio2);

		bio_pair_release(bp);
		return 0;
	bad_map:
		printk("raid10_make_request bug: can't convert block across chunks"
		       " or bigger than %dk %llu %d\n", chunk_sects/2,
		       (unsigned long long)bio->bi_sector, bio->bi_size >> 10);

		bio_io_error(bio, bio->bi_size);
		return 0;
	}

	/*
	 * Register the new request and wait if the reconstruction
	 * thread has put up a bar for new requests.
	 * Continue immediately if no resync is active currently.
	 */
	spin_lock_irq(&conf->resync_lock);
	wait_event_lock_irq(conf->wait_resume, !conf->barrier, conf->resync_lock, );
	conf->nr_pending++;
	spin_unlock_irq(&conf->resync_lock);

	if (bio_data_dir(bio)==WRITE) {
		disk_stat_inc(mddev->gendisk, writes);
		disk_stat_add(mddev->gendisk, write_sectors, bio_sectors(bio));
	} else {
		disk_stat_inc(mddev->gendisk, reads);
		disk_stat_add(mddev->gendisk, read_sectors, bio_sectors(bio));
	}

	r10_bio = mempool_alloc(conf->r10bio_pool, GFP_NOIO);

	r10_bio->master_bio = bio;
	r10_bio->sectors = bio->bi_size >> 9;

	r10_bio->mddev = mddev;
	r10_bio->sector = bio->bi_sector;

	if (bio_data_dir(bio) == READ) {
		/*
		 * read balancing logic:
		 */
		int disk = read_balance(conf, r10_bio);
		int slot = r10_bio->read_slot;
		if (disk < 0) {
			raid_end_bio_io(r10_bio);
			return 0;
		}
		mirror = conf->mirrors + disk;

		read_bio = bio_clone(bio, GFP_NOIO);

		r10_bio->devs[slot].bio = read_bio;

		read_bio->bi_sector = r10_bio->devs[slot].addr +
			mirror->rdev->data_offset;
		read_bio->bi_bdev = mirror->rdev->bdev;
		read_bio->bi_end_io = raid10_end_read_request;
		read_bio->bi_rw = READ | do_sync;
		read_bio->bi_private = r10_bio;

		generic_make_request(read_bio);
		return 0;
	}

	/*
	 * WRITE:
	 */
	/* first select target devices under spinlock and
	 * inc refcount on their rdev.  Record them by setting
	 * bios[x] to bio
	 */
	raid10_find_phys(conf, r10_bio);
	spin_lock_irq(&conf->device_lock);
	for (i = 0;  i < conf->copies; i++) {
		int d = r10_bio->devs[i].devnum;
		if (conf->mirrors[d].rdev &&
		    !conf->mirrors[d].rdev->faulty) {
			atomic_inc(&conf->mirrors[d].rdev->nr_pending);
			r10_bio->devs[i].bio = bio;
		} else
			r10_bio->devs[i].bio = NULL;
	}
	spin_unlock_irq(&conf->device_lock);

	atomic_set(&r10_bio->remaining, 1);
	md_write_start(mddev);
	for (i = 0; i < conf->copies; i++) {
		struct bio *mbio;
		int d = r10_bio->devs[i].devnum;
		if (!r10_bio->devs[i].bio)
			continue;

		mbio = bio_clone(bio, GFP_NOIO);
		r10_bio->devs[i].bio = mbio;

		mbio->bi_sector	= r10_bio->devs[i].addr+
			conf->mirrors[d].rdev->data_offset;
		mbio->bi_bdev = conf->mirrors[d].rdev->bdev;
		mbio->bi_end_io	= raid10_end_write_request;
		mbio->bi_rw = WRITE | do_sync;
		mbio->bi_private = r10_bio;

		atomic_inc(&r10_bio->remaining);
		generic_make_request(mbio);
	}

	if (atomic_dec_and_test(&r10_bio->remaining)) {
		md_write_end(mddev);
		raid_end_bio_io(r10_bio);
	}

	if (do_sync)
		md_wakeup_thread(mddev->thread);

	return 0;
}

static void status(struct seq_file *seq, mddev_t *mddev)
{
	conf_t *conf = mddev_to_conf(mddev);
	int i;

	if (conf->near_copies < conf->raid_disks)
		seq_printf(seq, " %dK chunks", mddev->chunk_size/1024);
	if (conf->near_copies > 1)
		seq_printf(seq, " %d near-copies", conf->near_copies);
	if (conf->far_copies > 1)
		seq_printf(seq, " %d far-copies", conf->far_copies);

	seq_printf(seq, " [%d/%d] [", conf->raid_disks,
						conf->working_disks);
	for (i = 0; i < conf->raid_disks; i++)
		seq_printf(seq, "%s",
			      conf->mirrors[i].rdev &&
			      conf->mirrors[i].rdev->in_sync ? "U" : "_");
	seq_printf(seq, "]");
}

static void error(mddev_t *mddev, mdk_rdev_t *rdev)
{
	char b[BDEVNAME_SIZE];
	conf_t *conf = mddev_to_conf(mddev);

	/*
	 * If it is not operational, then we have already marked it as dead
	 * else if it is the last working disks, ignore the error, let the
	 * next level up know.
	 * else mark the drive as failed
	 */
	if (rdev->in_sync
	    && conf->working_disks == 1)
		/*
		 * Don't fail the drive, just return an IO error.
		 * The test should really be more sophisticated than
		 * "working_disks == 1", but it isn't critical, and
		 * can wait until we do more sophisticated "is the drive
		 * really dead" tests...
		 */
		return;
	if (rdev->in_sync) {
		mddev->degraded++;
		conf->working_disks--;
		/*
		 * if recovery is running, make sure it aborts.
		 */
		set_bit(MD_RECOVERY_ERR, &mddev->recovery);
	}
	rdev->in_sync = 0;
	rdev->faulty = 1;
	mddev->sb_dirty = 1;
	printk(KERN_ALERT "raid10: Disk failure on %s, disabling device. \n"
		"	Operation continuing on %d devices\n",
		bdevname(rdev->bdev,b), conf->working_disks);
}

static void print_conf(conf_t *conf)
{
	int i;
	mirror_info_t *tmp;

	printk("RAID10 conf printout:\n");
	if (!conf) {
		printk("(!conf)\n");
		return;
	}
	printk(" --- wd:%d rd:%d\n", conf->working_disks,
		conf->raid_disks);

	for (i = 0; i < conf->raid_disks; i++) {
		char b[BDEVNAME_SIZE];
		tmp = conf->mirrors + i;
		if (tmp->rdev)
			printk(" disk %d, wo:%d, o:%d, dev:%s\n",
				i, !tmp->rdev->in_sync, !tmp->rdev->faulty,
				bdevname(tmp->rdev->bdev,b));
	}
}

static void close_sync(conf_t *conf)
{
	spin_lock_irq(&conf->resync_lock);
	wait_event_lock_irq(conf->wait_resume, !conf->barrier,
			    conf->resync_lock, 	unplug_slaves(conf->mddev));
	spin_unlock_irq(&conf->resync_lock);

	if (conf->barrier) BUG();
	if (waitqueue_active(&conf->wait_idle)) BUG();

	mempool_destroy(conf->r10buf_pool);
	conf->r10buf_pool = NULL;
}

static int raid10_spare_active(mddev_t *mddev)
{
	int i;
	conf_t *conf = mddev->private;
	mirror_info_t *tmp;

	spin_lock_irq(&conf->device_lock);
	/*
	 * Find all non-in_sync disks within the RAID10 configuration
	 * and mark them in_sync
	 */
	for (i = 0; i < conf->raid_disks; i++) {
		tmp = conf->mirrors + i;
		if (tmp->rdev
		    && !tmp->rdev->faulty
		    && !tmp->rdev->in_sync) {
			conf->working_disks++;
			mddev->degraded--;
			tmp->rdev->in_sync = 1;
		}
	}
	spin_unlock_irq(&conf->device_lock);

	print_conf(conf);
	return 0;
}


static int raid10_add_disk(mddev_t *mddev, mdk_rdev_t *rdev)
{
	conf_t *conf = mddev->private;
	int found = 0;
	int mirror;
	mirror_info_t *p;

	if (mddev->recovery_cp < MaxSector)
		/* only hot-add to in-sync arrays, as recovery is
		 * very different from resync
		 */
		return 0;
	spin_lock_irq(&conf->device_lock);
	for (mirror=0; mirror < mddev->raid_disks; mirror++)
		if ( !(p=conf->mirrors+mirror)->rdev) {
			p->rdev = rdev;

			blk_queue_stack_limits(mddev->queue,
					       rdev->bdev->bd_disk->queue);
			/* as we don't honour merge_bvec_fn, we must never risk
			 * violating it, so limit ->max_sector to one PAGE, as
			 * a one page request is never in violation.
			 */
			if (rdev->bdev->bd_disk->queue->merge_bvec_fn &&
			    mddev->queue->max_sectors > (PAGE_SIZE>>9))
				mddev->queue->max_sectors = (PAGE_SIZE>>9);

			p->head_position = 0;
			rdev->raid_disk = mirror;
			found = 1;
			break;
		}
	spin_unlock_irq(&conf->device_lock);

	print_conf(conf);
	return found;
}

static int raid10_remove_disk(mddev_t *mddev, int number)
{
	conf_t *conf = mddev->private;
	int err = 1;
	mirror_info_t *p = conf->mirrors+ number;

	print_conf(conf);
	spin_lock_irq(&conf->device_lock);
	if (p->rdev) {
		if (p->rdev->in_sync ||
		    atomic_read(&p->rdev->nr_pending)) {
			err = -EBUSY;
			goto abort;
		}
		p->rdev = NULL;
		err = 0;
	}
	if (err)
		MD_BUG();
abort:
	spin_unlock_irq(&conf->device_lock);

	print_conf(conf);
	return err;
}


static int end_sync_read(struct bio *bio, unsigned int bytes_done, int error)
{
	int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	r10bio_t * r10_bio = (r10bio_t *)(bio->bi_private);
	conf_t *conf = mddev_to_conf(r10_bio->mddev);
	int i,d;

	if (bio->bi_size)
		return 1;

	for (i=0; i<conf->copies; i++)
		if (r10_bio->devs[i].bio == bio)
			break;
	if (i == conf->copies)
		BUG();
	update_head_pos(i, r10_bio);
	d = r10_bio->devs[i].devnum;
	if (!uptodate)
		md_error(r10_bio->mddev,
			 conf->mirrors[d].rdev);

	/* for reconstruct, we always reschedule after a read.
	 * for resync, only after all reads
	 */
	if (test_bit(R10BIO_IsRecover, &r10_bio->state) ||
	    atomic_dec_and_test(&r10_bio->remaining)) {
		/* we have read all the blocks,
		 * do the comparison in process context in raid10d
		 */
		reschedule_retry(r10_bio);
	}
	rdev_dec_pending(conf->mirrors[d].rdev, conf->mddev);
	return 0;
}

static int end_sync_write(struct bio *bio, unsigned int bytes_done, int error)
{
	int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	r10bio_t * r10_bio = (r10bio_t *)(bio->bi_private);
	mddev_t *mddev = r10_bio->mddev;
	conf_t *conf = mddev_to_conf(mddev);
	int i,d;

	if (bio->bi_size)
		return 1;

	for (i = 0; i < conf->copies; i++)
		if (r10_bio->devs[i].bio == bio)
			break;
	d = r10_bio->devs[i].devnum;

	if (!uptodate)
		md_error(mddev, conf->mirrors[d].rdev);
	update_head_pos(i, r10_bio);

	while (atomic_dec_and_test(&r10_bio->remaining)) {
		if (r10_bio->master_bio == NULL) {
			/* the primary of several recovery bios */
			md_done_sync(mddev, r10_bio->sectors, 1);
			put_buf(r10_bio);
			break;
		} else {
			r10bio_t *r10_bio2 = (r10bio_t *)r10_bio->master_bio;
			put_buf(r10_bio);
			r10_bio = r10_bio2;
		}
	}
	rdev_dec_pending(conf->mirrors[d].rdev, mddev);
	return 0;
}

/*
 * Note: sync and recover and handled very differently for raid10
 * This code is for resync.
 * For resync, we read through virtual addresses and read all blocks.
 * If there is any error, we schedule a write.  The lowest numbered
 * drive is authoritative.
 * However requests come for physical address, so we need to map.
 * For every physical address there are raid_disks/copies virtual addresses,
 * which is always are least one, but is not necessarly an integer.
 * This means that a physical address can span multiple chunks, so we may
 * have to submit multiple io requests for a single sync request.
 */
/*
 * We check if all blocks are in-sync and only write to blocks that
 * aren't in sync
 */
static void sync_request_write(mddev_t *mddev, r10bio_t *r10_bio)
{
	conf_t *conf = mddev_to_conf(mddev);
	int i, first;
	struct bio *tbio, *fbio;

	atomic_set(&r10_bio->remaining, 1);

	/* find the first device with a block */
	for (i=0; i<conf->copies; i++)
		if (test_bit(BIO_UPTODATE, &r10_bio->devs[i].bio->bi_flags))
			break;

	if (i == conf->copies)
		goto done;

	first = i;
	fbio = r10_bio->devs[i].bio;

	/* now find blocks with errors */
	for (i=first+1 ; i < conf->copies ; i++) {
		int vcnt, j, d;

		if (!test_bit(BIO_UPTODATE, &r10_bio->devs[i].bio->bi_flags))
			continue;
		/* We know that the bi_io_vec layout is the same for
		 * both 'first' and 'i', so we just compare them.
		 * All vec entries are PAGE_SIZE;
		 */
		tbio = r10_bio->devs[i].bio;
		vcnt = r10_bio->sectors >> (PAGE_SHIFT-9);
		for (j = 0; j < vcnt; j++)
			if (memcmp(page_address(fbio->bi_io_vec[j].bv_page),
				   page_address(tbio->bi_io_vec[j].bv_page),
				   PAGE_SIZE))
				break;
		if (j == vcnt)
			continue;
		/* Ok, we need to write this bio
		 * First we need to fixup bv_offset, bv_len and
		 * bi_vecs, as the read request might have corrupted these
		 */
		tbio->bi_vcnt = vcnt;
		tbio->bi_size = r10_bio->sectors << 9;
		tbio->bi_idx = 0;
		tbio->bi_phys_segments = 0;
		tbio->bi_hw_segments = 0;
		tbio->bi_hw_front_size = 0;
		tbio->bi_hw_back_size = 0;
		tbio->bi_flags &= ~(BIO_POOL_MASK - 1);
		tbio->bi_flags |= 1 << BIO_UPTODATE;
		tbio->bi_next = NULL;
		tbio->bi_rw = WRITE;
		tbio->bi_private = r10_bio;
		tbio->bi_sector = r10_bio->devs[i].addr;

		for (j=0; j < vcnt ; j++) {
			tbio->bi_io_vec[j].bv_offset = 0;
			tbio->bi_io_vec[j].bv_len = PAGE_SIZE;

			memcpy(page_address(tbio->bi_io_vec[j].bv_page),
			       page_address(fbio->bi_io_vec[j].bv_page),
			       PAGE_SIZE);
		}
		tbio->bi_end_io = end_sync_write;

		d = r10_bio->devs[i].devnum;
		atomic_inc(&conf->mirrors[d].rdev->nr_pending);
		atomic_inc(&r10_bio->remaining);
		md_sync_acct(conf->mirrors[d].rdev->bdev, tbio->bi_size >> 9);

		generic_make_request(tbio);
	}

done:
	if (atomic_dec_and_test(&r10_bio->remaining)) {
		md_done_sync(mddev, r10_bio->sectors, 1);
		put_buf(r10_bio);
	}
}

/*
 * Now for the recovery code.
 * Recovery happens across physical sectors.
 * We recover all non-is_sync drives by finding the virtual address of
 * each, and then choose a working drive that also has that virt address.
 * There is a separate r10_bio for each non-in_sync drive.
 * Only the first two slots are in use. The first for reading,
 * The second for writing.
 *
 */

static void recovery_request_write(mddev_t *mddev, r10bio_t *r10_bio)
{
	conf_t *conf = mddev_to_conf(mddev);
	int i, d;
	struct bio *bio, *wbio;


	/* move the pages across to the second bio
	 * and submit the write request
	 */
	bio = r10_bio->devs[0].bio;
	wbio = r10_bio->devs[1].bio;
	for (i=0; i < wbio->bi_vcnt; i++) {
		struct page *p = bio->bi_io_vec[i].bv_page;
		bio->bi_io_vec[i].bv_page = wbio->bi_io_vec[i].bv_page;
		wbio->bi_io_vec[i].bv_page = p;
	}
	d = r10_bio->devs[1].devnum;

	atomic_inc(&conf->mirrors[d].rdev->nr_pending);
	md_sync_acct(conf->mirrors[d].rdev->bdev, wbio->bi_size >> 9);
	generic_make_request(wbio);
}


/*
 * This is a kernel thread which:
 *
 *	1.	Retries failed read operations on working mirrors.
 *	2.	Updates the raid superblock when problems encounter.
 *	3.	Performs writes following reads for array syncronising.
 */

static void raid10d(mddev_t *mddev)
{
	r10bio_t *r10_bio;
	struct bio *bio;
	unsigned long flags;
	conf_t *conf = mddev_to_conf(mddev);
	struct list_head *head = &conf->retry_list;
	int unplug=0;
	mdk_rdev_t *rdev;

	md_check_recovery(mddev);
	md_handle_safemode(mddev);

	for (;;) {
		char b[BDEVNAME_SIZE];
		spin_lock_irqsave(&conf->device_lock, flags);
		if (list_empty(head))
			break;
		r10_bio = list_entry(head->prev, r10bio_t, retry_list);
		list_del(head->prev);
		spin_unlock_irqrestore(&conf->device_lock, flags);

		mddev = r10_bio->mddev;
		conf = mddev_to_conf(mddev);
		if (test_bit(R10BIO_IsSync, &r10_bio->state)) {
			sync_request_write(mddev, r10_bio);
			unplug = 1;
		} else 	if (test_bit(R10BIO_IsRecover, &r10_bio->state)) {
			recovery_request_write(mddev, r10_bio);
			unplug = 1;
		} else {
			int mirror;
			bio = r10_bio->devs[r10_bio->read_slot].bio;
			r10_bio->devs[r10_bio->read_slot].bio = NULL;
			bio_put(bio);
			mirror = read_balance(conf, r10_bio);
			if (mirror == -1) {
				printk(KERN_ALERT "raid10: %s: unrecoverable I/O"
				       " read error for block %llu\n",
				       bdevname(bio->bi_bdev,b),
				       (unsigned long long)r10_bio->sector);
				raid_end_bio_io(r10_bio);
			} else {
				const int do_sync = bio_sync(r10_bio->master_bio);
				rdev = conf->mirrors[mirror].rdev;
				if (printk_ratelimit())
					printk(KERN_ERR "raid10: %s: redirecting sector %llu to"
					       " another mirror\n",
					       bdevname(rdev->bdev,b),
					       (unsigned long long)r10_bio->sector);
				bio = bio_clone(r10_bio->master_bio, GFP_NOIO);
				r10_bio->devs[r10_bio->read_slot].bio = bio;
				bio->bi_sector = r10_bio->devs[r10_bio->read_slot].addr
					+ rdev->data_offset;
				bio->bi_bdev = rdev->bdev;
				bio->bi_rw = READ | do_sync;
				bio->bi_private = r10_bio;
				bio->bi_end_io = raid10_end_read_request;
				unplug = 1;
				generic_make_request(bio);
			}
		}
	}
	spin_unlock_irqrestore(&conf->device_lock, flags);
	if (unplug)
		unplug_slaves(mddev);
}


static int init_resync(conf_t *conf)
{
	int buffs;

	buffs = RESYNC_WINDOW / RESYNC_BLOCK_SIZE;
	if (conf->r10buf_pool)
		BUG();
	conf->r10buf_pool = mempool_create(buffs, r10buf_pool_alloc, r10buf_pool_free, conf);
	if (!conf->r10buf_pool)
		return -ENOMEM;
	conf->next_resync = 0;
	return 0;
}

/*
 * perform a "sync" on one "block"
 *
 * We need to make sure that no normal I/O request - particularly write
 * requests - conflict with active sync requests.
 *
 * This is achieved by tracking pending requests and a 'barrier' concept
 * that can be installed to exclude normal IO requests.
 *
 * Resync and recovery are handled very differently.
 * We differentiate by looking at MD_RECOVERY_SYNC in mddev->recovery.
 *
 * For resync, we iterate over virtual addresses, read all copies,
 * and update if there are differences.  If only one copy is live,
 * skip it.
 * For recovery, we iterate over physical addresses, read a good
 * value for each non-in_sync drive, and over-write.
 *
 * So, for recovery we may have several outstanding complex requests for a
 * given address, one for each out-of-sync device.  We model this by allocating
 * a number of r10_bio structures, one for each out-of-sync device.
 * As we setup these structures, we collect all bio's together into a list
 * which we then process collectively to add pages, and then process again
 * to pass to generic_make_request.
 *
 * The r10_bio structures are linked using a borrowed master_bio pointer.
 * This link is counted in ->remaining.  When the r10_bio that points to NULL
 * has its remaining count decremented to 0, the whole complex operation
 * is complete.
 *
 */

static int sync_request(mddev_t *mddev, sector_t sector_nr, int go_faster)
{
	conf_t *conf = mddev_to_conf(mddev);
	r10bio_t *r10_bio;
	struct bio *biolist = NULL, *bio;
	sector_t max_sector, nr_sectors;
	int disk;
	int i;

	sector_t sectors_skipped = 0;
	int chunks_skipped = 0;

	if (!conf->r10buf_pool)
		if (init_resync(conf))
			return -ENOMEM;

 skipped:
	max_sector = mddev->size << 1;
	if (test_bit(MD_RECOVERY_SYNC, &mddev->recovery))
		max_sector = mddev->resync_max_sectors;
	if (sector_nr >= max_sector) {
		close_sync(conf);
		return sectors_skipped;
	}
	if (chunks_skipped >= conf->raid_disks) {
		/* if there has been nothing to do on any drive,
		 * then there is nothing to do at all..
		 */
		sector_t sec = max_sector - sector_nr;
		md_done_sync(mddev, sec, 1);
		return sec + sectors_skipped;
	}

	/* make sure whole request will fit in a chunk - if chunks
	 * are meaningful
	 */
	if (conf->near_copies < conf->raid_disks &&
	    max_sector > (sector_nr | conf->chunk_mask))
		max_sector = (sector_nr | conf->chunk_mask) + 1;
	/*
	 * If there is non-resync activity waiting for us then
	 * put in a delay to throttle resync.
	 */
	if (!go_faster && waitqueue_active(&conf->wait_resume))
		schedule_timeout(HZ);
	device_barrier(conf, sector_nr + RESYNC_SECTORS);

	/* Again, very different code for resync and recovery.
	 * Both must result in an r10bio with a list of bios that
	 * have bi_end_io, bi_sector, bi_bdev set,
	 * and bi_private set to the r10bio.
	 * For recovery, we may actually create several r10bios
	 * with 2 bios in each, that correspond to the bios in the main one.
	 * In this case, the subordinate r10bios link back through a
	 * borrowed master_bio pointer, and the counter in the master
	 * includes a ref from each subordinate.
	 */
	/* First, we decide what to do and set ->bi_end_io
	 * To end_sync_read if we want to read, and
	 * end_sync_write if we will want to write.
	 */

	if (!test_bit(MD_RECOVERY_SYNC, &mddev->recovery)) {
		/* recovery... the complicated one */
		int i, j, k;
		r10_bio = NULL;

		for (i=0 ; i<conf->raid_disks; i++)
			if (conf->mirrors[i].rdev &&
			    !conf->mirrors[i].rdev->in_sync) {
				/* want to reconstruct this device */
				r10bio_t *rb2 = r10_bio;

				r10_bio = mempool_alloc(conf->r10buf_pool, GFP_NOIO);
				spin_lock_irq(&conf->resync_lock);
				conf->nr_pending++;
				if (rb2) conf->barrier++;
				spin_unlock_irq(&conf->resync_lock);
				atomic_set(&r10_bio->remaining, 0);

				r10_bio->master_bio = (struct bio*)rb2;
				if (rb2)
					atomic_inc(&rb2->remaining);
				r10_bio->mddev = mddev;
				set_bit(R10BIO_IsRecover, &r10_bio->state);
				r10_bio->sector = raid10_find_virt(conf, sector_nr, i);
				raid10_find_phys(conf, r10_bio);
				for (j=0; j<conf->copies;j++) {
					int d = r10_bio->devs[j].devnum;
					if (conf->mirrors[d].rdev &&
					    conf->mirrors[d].rdev->in_sync) {
						/* This is where we read from */
						bio = r10_bio->devs[0].bio;
						bio->bi_next = biolist;
						biolist = bio;
						bio->bi_private = r10_bio;
						bio->bi_end_io = end_sync_read;
						bio->bi_rw = 0;
						bio->bi_sector = r10_bio->devs[j].addr +
							conf->mirrors[d].rdev->data_offset;
						bio->bi_bdev = conf->mirrors[d].rdev->bdev;
						atomic_inc(&conf->mirrors[d].rdev->nr_pending);
						atomic_inc(&r10_bio->remaining);
						/* and we write to 'i' */

						for (k=0; k<conf->copies; k++)
							if (r10_bio->devs[k].devnum == i)
								break;
						bio = r10_bio->devs[1].bio;
						bio->bi_next = biolist;
						biolist = bio;
						bio->bi_private = r10_bio;
						bio->bi_end_io = end_sync_write;
						bio->bi_rw = 1;
						bio->bi_sector = r10_bio->devs[k].addr +
							conf->mirrors[i].rdev->data_offset;
						bio->bi_bdev = conf->mirrors[i].rdev->bdev;

						r10_bio->devs[0].devnum = d;
						r10_bio->devs[1].devnum = i;

						break;
					}
				}
				if (j == conf->copies) {
					BUG();
				}
			}
		if (biolist == NULL) {
			while (r10_bio) {
				r10bio_t *rb2 = r10_bio;
				r10_bio = (r10bio_t*) rb2->master_bio;
				rb2->master_bio = NULL;
				put_buf(rb2);
			}
			goto giveup;
		}
	} else {
		/* resync. Schedule a read for every block at this virt offset */
		int count = 0;
		r10_bio = mempool_alloc(conf->r10buf_pool, GFP_NOIO);

		spin_lock_irq(&conf->resync_lock);
		conf->nr_pending++;
		spin_unlock_irq(&conf->resync_lock);

		r10_bio->mddev = mddev;
		atomic_set(&r10_bio->remaining, 0);

		r10_bio->master_bio = NULL;
		r10_bio->sector = sector_nr;
		set_bit(R10BIO_IsSync, &r10_bio->state);
		raid10_find_phys(conf, r10_bio);
		r10_bio->sectors = (sector_nr | conf->chunk_mask) - sector_nr +1;
		spin_lock_irq(&conf->device_lock);
		for (i=0; i<conf->copies; i++) {
			int d = r10_bio->devs[i].devnum;
			bio = r10_bio->devs[i].bio;
			bio->bi_end_io = NULL;
			if (conf->mirrors[d].rdev == NULL ||
			    conf->mirrors[d].rdev->faulty)
				continue;
			atomic_inc(&conf->mirrors[d].rdev->nr_pending);
			atomic_inc(&r10_bio->remaining);
			bio->bi_next = biolist;
			biolist = bio;
			bio->bi_private = r10_bio;
			bio->bi_end_io = end_sync_read;
			bio->bi_rw = 0;
			bio->bi_sector = r10_bio->devs[i].addr +
				conf->mirrors[d].rdev->data_offset;
			bio->bi_bdev = conf->mirrors[d].rdev->bdev;
			count++;
		}
		spin_unlock_irq(&conf->device_lock);
		if (count < 2) {
			for (i=0; i<conf->copies; i++) {
				int d = r10_bio->devs[i].devnum;
				if (r10_bio->devs[i].bio->bi_end_io)
					rdev_dec_pending(conf->mirrors[d].rdev, mddev);
			}
			put_buf(r10_bio);
			biolist = NULL;
			goto giveup;
		}
	}

	for (bio = biolist; bio ; bio=bio->bi_next) {

		bio->bi_flags &= ~(BIO_POOL_MASK - 1);
		if (bio->bi_end_io)
			bio->bi_flags |= 1 << BIO_UPTODATE;
		bio->bi_vcnt = 0;
		bio->bi_idx = 0;
		bio->bi_phys_segments = 0;
		bio->bi_hw_segments = 0;
		bio->bi_size = 0;
	}

	nr_sectors = 0;
	do {
		struct page *page;
		int len = PAGE_SIZE;
		disk = 0;
		if (sector_nr + (len>>9) > max_sector)
			len = (max_sector - sector_nr) << 9;
		if (len == 0)
			break;
		for (bio= biolist ; bio ; bio=bio->bi_next) {
			page = bio->bi_io_vec[bio->bi_vcnt].bv_page;
			if (bio_add_page(bio, page, len, 0) == 0) {
				/* stop here */
				struct bio *bio2;
				bio->bi_io_vec[bio->bi_vcnt].bv_page = page;
				for (bio2 = biolist; bio2 && bio2 != bio; bio2 = bio2->bi_next) {
					/* remove last page from this bio */
					bio2->bi_vcnt--;
					bio2->bi_size -= len;
					bio2->bi_flags &= ~(1<< BIO_SEG_VALID);
				}
				goto bio_full;
			}
			disk = i;
		}
		nr_sectors += len>>9;
		sector_nr += len>>9;
	} while (biolist->bi_vcnt < RESYNC_PAGES);
 bio_full:
	r10_bio->sectors = nr_sectors;

	while (biolist) {
		bio = biolist;
		biolist = biolist->bi_next;

		bio->bi_next = NULL;
		r10_bio = bio->bi_private;
		r10_bio->sectors = nr_sectors;

		if (bio->bi_end_io == end_sync_read) {
			md_sync_acct(bio->bi_bdev, nr_sectors);
			generic_make_request(bio);
		}
	}

	return sectors_skipped + nr_sectors;
 giveup:
	/* There is nowhere to write, so all non-sync
	 * drives must be failed, so try the next chunk...
	 */
	{
	int sec = max_sector - sector_nr;
	sectors_skipped += sec;
	chunks_skipped ++;
	sector_nr = max_sector;
	md_done_sync(mddev, sec, 1);
	goto skipped;
	}
}

static int run(mddev_t *mddev)
{
	conf_t *conf;
	int i, disk_idx;
	mirror_info_t *disk;
	mdk_rdev_t *rdev;
	struct list_head *tmp;
	int nc, fc;
	sector_t stride, size;

	if (mddev->level != 10) {
		printk(KERN_ERR "raid10: %s: raid level not set correctly... (%d)\n",
		       mdname(mddev), mddev->level);
		goto out;
	}
	nc = mddev->layout & 255;
	fc = (mddev->layout >> 8) & 255;
	if ((nc*fc) <2 || (nc*fc) > mddev->raid_disks ||
	    (mddev->layout >> 16)) {
		printk(KERN_ERR "raid10: %s: unsupported raid10 layout: 0x%8x\n",
		       mdname(mddev), mddev->layout);
		goto out;
	}
	/*
	 * copy the already verified devices into our private RAID10
	 * bookkeeping area. [whatever we allocate in run(),
	 * should be freed in stop()]
	 */
	conf = kmalloc(sizeof(conf_t), GFP_KERNEL);
	mddev->private = conf;
	if (!conf) {
		printk(KERN_ERR "raid10: couldn't allocate memory for %s\n",
			mdname(mddev));
		goto out;
	}
	memset(conf, 0, sizeof(*conf));
	conf->mirrors = kmalloc(sizeof(struct mirror_info)*mddev->raid_disks,
				 GFP_KERNEL);
	if (!conf->mirrors) {
		printk(KERN_ERR "raid10: couldn't allocate memory for %s\n",
		       mdname(mddev));
		goto out_free_conf;
	}
	memset(conf->mirrors, 0, sizeof(struct mirror_info)*mddev->raid_disks);

	conf->near_copies = nc;
	conf->far_copies = fc;
	conf->copies = nc*fc;
	conf->chunk_mask = (sector_t)(mddev->chunk_size>>9)-1;
	conf->chunk_shift = ffz(~mddev->chunk_size) - 9;
	stride = mddev->size >> (conf->chunk_shift-1);
	sector_div(stride, fc);
	conf->stride = stride << conf->chunk_shift;

	conf->r10bio_pool = mempool_create(NR_RAID10_BIOS, r10bio_pool_alloc,
						r10bio_pool_free, conf);
	if (!conf->r10bio_pool) {
		printk(KERN_ERR "raid10: couldn't allocate memory for %s\n",
			mdname(mddev));
		goto out_free_conf;
	}
	mddev->queue->unplug_fn = raid10_unplug;

	mddev->queue->issue_flush_fn = raid10_issue_flush;

	ITERATE_RDEV(mddev, rdev, tmp) {
		disk_idx = rdev->raid_disk;
		if (disk_idx >= mddev->raid_disks
		    || disk_idx < 0)
			continue;
		disk = conf->mirrors + disk_idx;

		disk->rdev = rdev;

		blk_queue_stack_limits(mddev->queue,
				       rdev->bdev->bd_disk->queue);
		/* as we don't honour merge_bvec_fn, we must never risk
		 * violating it, so limit ->max_sector to one PAGE, as
		 * a one page request is never in violation.
		 */
		if (rdev->bdev->bd_disk->queue->merge_bvec_fn &&
		    mddev->queue->max_sectors > (PAGE_SIZE>>9))
			mddev->queue->max_sectors = (PAGE_SIZE>>9);

		disk->head_position = 0;
		if (!rdev->faulty && rdev->in_sync)
			conf->working_disks++;
	}
	conf->raid_disks = mddev->raid_disks;
	conf->mddev = mddev;
	conf->device_lock = SPIN_LOCK_UNLOCKED;
	INIT_LIST_HEAD(&conf->retry_list);

	conf->resync_lock = SPIN_LOCK_UNLOCKED;
	init_waitqueue_head(&conf->wait_idle);
	init_waitqueue_head(&conf->wait_resume);

	if (!conf->working_disks) {
		printk(KERN_ERR "raid10: no operational mirrors for %s\n",
			mdname(mddev));
		goto out_free_conf;
	}

	mddev->degraded = 0;
	for (i = 0; i < conf->raid_disks; i++) {

		disk = conf->mirrors + i;

		if (!disk->rdev) {
			disk->head_position = 0;
			mddev->degraded++;
		}
	}


	mddev->thread = md_register_thread(raid10d, mddev, "%s_raid10");
	if (!mddev->thread) {
		printk(KERN_ERR
		       "raid10: couldn't allocate thread for %s\n",
		       mdname(mddev));
		goto out_free_conf;
	}

	printk(KERN_INFO
		"raid10: raid set %s active with %d out of %d devices\n",
		mdname(mddev), mddev->raid_disks - mddev->degraded,
		mddev->raid_disks);
	/*
	 * Ok, everything is just fine now
	 */
	size = conf->stride * conf->raid_disks;
	sector_div(size, conf->near_copies);
	mddev->array_size = size/2;
	mddev->resync_max_sectors = size;

	/* Calculate max read-ahead size.
	 * We need to readahead at least twice a whole stripe....
	 * maybe...
	 */
	{
		int stripe = conf->raid_disks * mddev->chunk_size / PAGE_CACHE_SIZE;
		stripe /= conf->near_copies;
		if (mddev->queue->backing_dev_info.ra_pages < 2* stripe)
			mddev->queue->backing_dev_info.ra_pages = 2* stripe;
	}

	if (conf->near_copies < mddev->raid_disks)
		blk_queue_merge_bvec(mddev->queue, raid10_mergeable_bvec);
	return 0;

out_free_conf:
	if (conf->r10bio_pool)
		mempool_destroy(conf->r10bio_pool);
	if (conf->mirrors)
		kfree(conf->mirrors);
	kfree(conf);
	mddev->private = NULL;
out:
	return -EIO;
}

static int stop(mddev_t *mddev)
{
	conf_t *conf = mddev_to_conf(mddev);

	md_unregister_thread(mddev->thread);
	mddev->thread = NULL;
	blk_sync_queue(mddev->queue); /* the unplug fn references 'conf'*/
	if (conf->r10bio_pool)
		mempool_destroy(conf->r10bio_pool);
	if (conf->mirrors)
		kfree(conf->mirrors);
	kfree(conf);
	mddev->private = NULL;
	return 0;
}


static mdk_personality_t raid10_personality =
{
	.name		= "raid10",
	.owner		= THIS_MODULE,
	.make_request	= make_request,
	.run		= run,
	.stop		= stop,
	.status		= status,
	.error_handler	= error,
	.hot_add_disk	= raid10_add_disk,
	.hot_remove_disk= raid10_remove_disk,
	.spare_active	= raid10_spare_active,
	.sync_request	= sync_request,
};

static int __init raid_init(void)
{
	return register_md_personality(RAID10, &raid10_personality);
}

static void raid_exit(void)
{
	unregister_md_personality(RAID10);
}

module_init(raid_init);
module_exit(raid_exit);
MODULE_LICENSE("GPL");
MODULE_ALIAS("md-personality-9"); /* RAID10 */

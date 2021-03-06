/*
 * Copyright (C) 2003 Sistina Software
 *
 * This file is released under the LGPL.
 */

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

#include "dm-log.h"
#include "dm-io.h"

static LIST_HEAD(_log_types);
static spinlock_t _lock = SPIN_LOCK_UNLOCKED;

int dm_register_dirty_log_type(struct dirty_log_type *type)
{
	spin_lock(&_lock);
	type->use_count = 0;
	list_add(&type->list, &_log_types);
	spin_unlock(&_lock);

	return 0;
}

int dm_unregister_dirty_log_type(struct dirty_log_type *type)
{
	spin_lock(&_lock);

	if (type->use_count)
		DMWARN("Unregister failed: log type '%s' still in use",
		       type->name);
	else
		list_del(&type->list);

	spin_unlock(&_lock);

	return 0;
}

static struct dirty_log_type *_get_type(const char *type_name)
{
	struct dirty_log_type *type;

	spin_lock(&_lock);
	list_for_each_entry (type, &_log_types, list)
		if (!strcmp(type_name, type->name)) {
			if (!type->use_count && !try_module_get(type->module)){
				spin_unlock(&_lock);
				return NULL;
			}
			type->use_count++;
			spin_unlock(&_lock);
			return type;
		}

	spin_unlock(&_lock);
	return NULL;
}

static int load_log_module(const char *type_name)
{
	int r;

	if (!strncmp(type_name, "clustered_disk", 14) ||
	    !strncmp(type_name, "clustered_core", 14))
		r = request_module("dm-cmirror");
	else
		r = -ENODEV;

	return r < 0 ? r : 0;
}

static struct dirty_log_type *get_type(const char *type_name)
{
	struct dirty_log_type *type;

	if ((type = _get_type(type_name)))
		return type;

	/* Logging type not found.  Try to find module. */
	if (load_log_module(type_name)) {
		DMWARN("Module for logging type \"%s\" not found.", type_name);
		return NULL;
	}

	return _get_type(type_name);
}

static void put_type(struct dirty_log_type *type)
{
	spin_lock(&_lock);
	if (!--type->use_count)
		module_put(type->module);
	spin_unlock(&_lock);
}

struct dirty_log *dm_create_dirty_log(const char *type_name, struct dm_target *ti,
				      unsigned int argc, char **argv)
{
	struct dirty_log_type *type;
	struct dirty_log *log;

	log = kmalloc(sizeof(*log), GFP_KERNEL);
	if (!log)
		return NULL;

	type = get_type(type_name);
	if (!type) {
		kfree(log);
		return NULL;
	}

	log->type = type;
	if (type->ctr(log, ti, argc, argv)) {
		kfree(log);
		put_type(type);
		return NULL;
	}

	return log;
}

void dm_destroy_dirty_log(struct dirty_log *log)
{
	log->type->dtr(log);
	put_type(log->type);
	kfree(log);
}

/*-----------------------------------------------------------------
 * Persistent and core logs share a lot of their implementation.
 * FIXME: need a reload method to be called from a resume
 *---------------------------------------------------------------*/
/*
 * Magic for persistent mirrors: "MiRr"
 */
#define MIRROR_MAGIC 0x4D695272

/*
 * The on-disk version of the metadata.
 */
#define MIRROR_DISK_VERSION 2
#define LOG_OFFSET 2

struct log_header {
	uint32_t magic;

	/*
	 * Simple, incrementing version. no backward
	 * compatibility.
	 */
	uint32_t version;
	sector_t nr_regions;
};

struct log_c {
	struct dm_target *ti;
	int touched;
	uint32_t region_size;
	unsigned int region_count;
	region_t sync_count;

	unsigned bitset_uint32_count;
	uint32_t *clean_bits;
	uint32_t *sync_bits;
	uint32_t *recovering_bits;

	int sync_search;

	/* Resync flag */
	enum sync {
		DEFAULTSYNC,	/* Synchronize if necessary */
		NOSYNC,		/* Devices known to be already in sync */
		FORCESYNC,	/* Force a sync to happen */
	} sync;

	int failure_response;

	struct dm_io_request io_req;

	/*
	 * Disk log fields
	 */
	int log_dev_failed;
	struct dm_dev *log_dev;
	struct log_header header;

	struct io_region header_location;
	struct log_header *disk_header;
};

/*
 * The touched member needs to be updated every time we access
 * one of the bitsets.
 */
static  inline int log_test_bit(uint32_t *bs, unsigned bit)
{
	return ext2_test_bit(bit, (unsigned long *) bs) ? 1 : 0;
}

static inline void log_set_bit(struct log_c *l,
			       uint32_t *bs, unsigned bit)
{
	ext2_set_bit(bit, (unsigned long *) bs);
	l->touched = 1;
}

static inline void log_clear_bit(struct log_c *l,
				 uint32_t *bs, unsigned bit)
{
	ext2_clear_bit(bit, (unsigned long *) bs);
	l->touched = 1;
}

/*----------------------------------------------------------------
 * Header IO
 *--------------------------------------------------------------*/
static void header_to_disk(struct log_header *core, struct log_header *disk)
{
	disk->magic = cpu_to_le32(core->magic);
	disk->version = cpu_to_le32(core->version);
	disk->nr_regions = cpu_to_le64(core->nr_regions);
}

static void header_from_disk(struct log_header *core, struct log_header *disk)
{
	core->magic = le32_to_cpu(disk->magic);
	core->version = le32_to_cpu(disk->version);
	core->nr_regions = le64_to_cpu(disk->nr_regions);
}

static int rw_header(struct log_c *lc, int rw)
{
	lc->io_req.bi_rw = rw;
	lc->io_req.mem.ptr.vma = lc->disk_header;
	lc->io_req.notify.fn = NULL;

	return dm_io(&lc->io_req, 1, &lc->header_location, NULL);
}

static int read_header(struct log_c *log)
{
	int r;

	r = rw_header(log, READ);
	if (r)
		return r;

	header_from_disk(&log->header, log->disk_header);

	/* New log required? */
	if (log->sync != DEFAULTSYNC || log->header.magic != MIRROR_MAGIC) {
		log->header.magic = MIRROR_MAGIC;
		log->header.version = MIRROR_DISK_VERSION;
		log->header.nr_regions = 0;
	}

	/* Version 2 is like version 1 but always little endian on disk. */
#ifdef __LITTLE_ENDIAN
	if (log->header.version == 1)
		log->header.version = 2;
#endif

	if (log->header.version != MIRROR_DISK_VERSION) {
		DMWARN("incompatible disk log version");
		return -EINVAL;
	}

	return 0;
}

static inline int write_header(struct log_c *log)
{
	header_to_disk(&log->header, log->disk_header);
	return rw_header(log, WRITE);
}

/*----------------------------------------------------------------
 * core log constructor/destructor
 *
 * argv contains 1 - 3 arguments:
 * 	<region_size> [[no]sync] [block_on_error]
 *--------------------------------------------------------------*/
#define BYTE_SHIFT 3
static int core_ctr(struct dirty_log *log, struct dm_target *ti,
		    unsigned int argc, char **argv)
{
	enum sync sync = DEFAULTSYNC;
	int failure_response = DMLOG_IOERR_IGNORE;

	struct log_c *lc;
	uint32_t region_size;
	unsigned int region_count;
	size_t bitset_size;
	unsigned i;

	if (argc < 1 || argc > 3) {
		DMWARN("wrong number of arguments to mirror log");
		return -EINVAL;
	}

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "sync"))
			sync = FORCESYNC;
		else if (!strcmp(argv[i], "nosync"))
			sync = NOSYNC;
		else if (!strcmp(argv[i], "block_on_error"))
			failure_response = DMLOG_IOERR_BLOCK;
		else {
			DMWARN("unrecognised sync argument to mirror log: %s",
			       argv[i]);
			return -EINVAL;
		}
	}

	if (sscanf(argv[0], "%u", &region_size) != 1) {
		DMWARN("invalid region size string");
		return -EINVAL;
	}

	region_count = dm_sector_div_up(ti->len, region_size);

	lc = kmalloc(sizeof(*lc), GFP_KERNEL);
	if (!lc) {
		DMWARN("couldn't allocate core log");
		return -ENOMEM;
	}

	lc->ti = ti;
	lc->touched = 0;
	lc->region_size = region_size;
	lc->region_count = region_count;
	lc->sync = sync;
	lc->failure_response = failure_response;

	/*
	 * Work out how many "unsigned long"s we need to hold the bitset.
	 */
	bitset_size = dm_round_up(region_count,
				  sizeof(uint32_t) << BYTE_SHIFT);
	bitset_size >>= BYTE_SHIFT;

	lc->bitset_uint32_count = bitset_size / sizeof(uint32_t);
	lc->clean_bits = vmalloc(bitset_size);
	if (!lc->clean_bits) {
		DMWARN("couldn't allocate clean bitset");
		kfree(lc);
		return -ENOMEM;
	}
	memset(lc->clean_bits, -1, bitset_size);

	lc->sync_bits = vmalloc(bitset_size);
	if (!lc->sync_bits) {
		DMWARN("couldn't allocate sync bitset");
		vfree(lc->clean_bits);
		kfree(lc);
		return -ENOMEM;
	}
	memset(lc->sync_bits, (sync == NOSYNC) ? -1 : 0, bitset_size);
	lc->sync_count = (sync == NOSYNC) ? region_count : 0;

	lc->recovering_bits = vmalloc(bitset_size);
	if (!lc->recovering_bits) {
		DMWARN("couldn't allocate recovering bitset");
		vfree(lc->sync_bits);
		vfree(lc->clean_bits);
		kfree(lc);
		return -ENOMEM;
	}
	memset(lc->recovering_bits, 0, bitset_size);
	lc->sync_search = 0;
	log->context = lc;
	return 0;
}

static void core_dtr(struct dirty_log *log)
{
	struct log_c *lc = (struct log_c *) log->context;
	vfree(lc->clean_bits);
	vfree(lc->sync_bits);
	vfree(lc->recovering_bits);
	kfree(lc);
}

/*----------------------------------------------------------------
 * disk log constructor/destructor
 *
 * argv contains 2 - 4 arguments:
 *	 <log_device> <region_size> [[no]sync] [block_on_error]
 *--------------------------------------------------------------*/
static int disk_ctr(struct dirty_log *log, struct dm_target *ti,
		    unsigned int argc, char **argv)
{
	int r;
	size_t size, bitset_size;
	struct log_c *lc;
	struct dm_dev *dev;
	uint32_t *clean_bits;

	if (argc < 2 || argc > 4) {
		DMWARN("wrong number of arguments to disk mirror log");
		return -EINVAL;
	}

	r = dm_get_device(ti, argv[0], 0, 0 /* FIXME */,
			  FMODE_READ | FMODE_WRITE, &dev);
	if (r)
		return r;

	r = core_ctr(log, ti, argc - 1, argv + 1);
	if (r) {
		dm_put_device(ti, dev);
		return r;
	}

	lc = (struct log_c *) log->context;
	lc->log_dev = dev;
	lc->log_dev_failed = 0;

	/* setup the disk header fields */
	lc->header_location.bdev = lc->log_dev->bdev;
	lc->header_location.sector = 0;

	/* Include both the header and the bitset in one buffer. */
	bitset_size = lc->bitset_uint32_count * sizeof(uint32_t);
	size = dm_round_up((LOG_OFFSET << SECTOR_SHIFT) + bitset_size,
			   ti->limits.hardsect_size);

	if (size > dev->bdev->bd_inode->i_size) {
		DMWARN("log device %s too small: need %llu bytes",
		       dev->name, (unsigned long long)size);
		r = -EINVAL;
		goto bad;
	}

	lc->header_location.count = size >> SECTOR_SHIFT;

	lc->disk_header = vmalloc(size);
	if (!lc->disk_header) {
		r = -ENOMEM;
		goto bad;
	}

	/*
	 * Deallocate the clean_bits buffer that was allocated in core_ctr()
	 * and point it at the appropriate place in the disk_header buffer.
	 */
	clean_bits = lc->clean_bits;
	lc->clean_bits = (void *)lc->disk_header + (LOG_OFFSET << SECTOR_SHIFT);
	memcpy(lc->clean_bits, clean_bits, bitset_size);
	vfree(clean_bits);

	lc->io_req.mem.type = DM_IO_VMA;
	lc->io_req.client = dm_io_client_create(dm_div_up(size, PAGE_SIZE));
	if (IS_ERR(lc->io_req.client)) {
		r = PTR_ERR(lc->io_req.client);
		DMWARN("couldn't allocate disk io client");
		vfree(lc->disk_header);
		goto bad;
	}
	return 0;

 bad:
	dm_put_device(ti, lc->log_dev);
	core_dtr(log);
	return r;
}

static void disk_dtr(struct dirty_log *log)
{
	struct log_c *lc = (struct log_c *) log->context;
	dm_put_device(lc->ti, lc->log_dev);
	dm_io_client_destroy(lc->io_req.client);
	vfree(lc->disk_header);
	lc->clean_bits = NULL;
	core_dtr(log);
}

static int count_bits32(uint32_t *addr, unsigned size)
{
	int count = 0, i;

	for (i = 0; i < size; i++) {
		count += hweight32(*(addr+i));
	}
	return count;
}

static void fail_log_device(struct log_c *lc)
{
	if (lc->log_dev_failed)
		return;

	DMERR("Failing mirror log device %s.",
	      lc->log_dev->name);

	lc->log_dev_failed = 1;
	if (lc->failure_response == DMLOG_IOERR_BLOCK)
		dm_table_event(lc->ti->table);
}

static void restore_log_device(struct log_c *lc)
{
	lc->log_dev_failed = 0;
}

static int disk_resume(struct dirty_log *log)
{
	int r = 0;
	unsigned i;
	struct log_c *lc = (struct log_c *) log->context;
	size_t size = lc->bitset_uint32_count * sizeof(uint32_t);

	/* 
	 * Read the disk header, but only if we know it is good.
	 * Assume the worst in the event of failure.
	 */
	if (!lc->log_dev_failed && (r = read_header(lc))) {
		DMWARN("Read %s failed on mirror log device, %s.",
		      r ? "header" : "bits", lc->log_dev->name);
		fail_log_device(lc);
		lc->header.nr_regions = 0;
	}

	/* set or clear any new bits -- device has grown */
	if (lc->sync == NOSYNC)
		for (i = lc->header.nr_regions; i < lc->region_count; i++)
			/* FIXME: amazingly inefficient */
			log_set_bit(lc, lc->clean_bits, i);
	else
		for (i = lc->header.nr_regions; i < lc->region_count; i++)
			/* FIXME: amazingly inefficient */
			log_clear_bit(lc, lc->clean_bits, i);

	/* clear any old bits if device has shrunk */
	for (i = lc->region_count; i % 32; i++)
		log_clear_bit(lc, lc->clean_bits, i);

	/* copy clean across to sync */
	memcpy(lc->sync_bits, lc->clean_bits, size);
	lc->sync_count = count_bits32(lc->clean_bits, lc->bitset_uint32_count);
	lc->sync_search = 0;

	/* set the correct number of regions in the header */
	lc->header.nr_regions = lc->region_count;

	/* write out the log */
	if ((r = write_header(lc))) {
		DMWARN("Write header failed on mirror log device, %s.",
		      lc->log_dev->name);
		fail_log_device(lc);
	} else
		restore_log_device(lc);

	return r;
}

static sector_t core_get_region_size(struct dirty_log *log)
{
	struct log_c *lc = (struct log_c *) log->context;
	return lc->region_size;
}

static int core_resume(struct dirty_log *log)
{
	struct log_c *lc = (struct log_c *) log->context;

	lc->sync_search = 0;

	return 0;
}

static int core_is_clean(struct dirty_log *log, region_t region)
{
	struct log_c *lc = (struct log_c *) log->context;
	return log_test_bit(lc->clean_bits, region);
}

static int core_in_sync(struct dirty_log *log, region_t region, int block)
{
	struct log_c *lc = (struct log_c *) log->context;
	return log_test_bit(lc->sync_bits, region);
}

static int core_flush(struct dirty_log *log)
{
	/* no op */
	return 0;
}

static int disk_presuspend(struct dirty_log *log)
{
	return 0;
}

static int disk_flush(struct dirty_log *log)
{
	int r;
	struct log_c *lc = (struct log_c *) log->context;

	/* only write if the log has changed */
	if (!lc->touched)
		return 0;

	r = write_header(lc);
	if (r)
		fail_log_device(lc);
	else {
		lc->touched = 0;
		restore_log_device(lc);
	}

	return r;
}

static void core_mark_region(struct dirty_log *log, region_t region)
{
	struct log_c *lc = (struct log_c *) log->context;
	log_clear_bit(lc, lc->clean_bits, region);
}

static void core_clear_region(struct dirty_log *log, region_t region)
{
	struct log_c *lc = (struct log_c *) log->context;

	/* Only clear the region if it is also in sync */
	if (log_test_bit(lc->sync_bits, region))
		log_set_bit(lc, lc->clean_bits, region);
}

static int core_get_resync_work(struct dirty_log *log, region_t *region)
{
	struct log_c *lc = (struct log_c *) log->context;

	if (lc->sync_search >= lc->region_count)
		return 0;

	do {
		*region = ext2_find_next_zero_bit(
					     (unsigned long *) lc->sync_bits,
					     lc->region_count,
					     lc->sync_search);
		lc->sync_search = *region + 1;

		if (*region >= lc->region_count)
			return 0;

	} while (log_test_bit(lc->recovering_bits, *region));

	log_set_bit(lc, lc->recovering_bits, *region);
	return 1;
}

static void core_complete_resync_work(struct dirty_log *log, region_t region,
				      int success)
{
	struct log_c *lc = (struct log_c *) log->context;

	log_clear_bit(lc, lc->recovering_bits, region);
	if (success) {
		log_set_bit(lc, lc->sync_bits, region);
                lc->sync_count++;
        } else if (log_test_bit(lc->sync_bits, region)) {
		lc->sync_count--;
		log_clear_bit(lc, lc->sync_bits, region);
	}
}

static region_t core_get_sync_count(struct dirty_log *log)
{
        struct log_c *lc = (struct log_c *) log->context;

        return lc->sync_count;
}

#define	DMEMIT_SYNC \
	if (lc->sync != DEFAULTSYNC) \
		DMEMIT("%ssync ", lc->sync == NOSYNC ? "no" : "")

static int core_status(struct dirty_log *log, status_type_t status,
		       char *result, unsigned int maxlen)
{
	int sz = 0;
	int params;
	struct log_c *lc = log->context;

	switch(status) {
	case STATUSTYPE_INFO:
		DMEMIT("1 core");
		break;

	case STATUSTYPE_TABLE:
		params = (lc->sync == DEFAULTSYNC) ? 1 : 2;
		params += (lc->failure_response == DMLOG_IOERR_BLOCK) ? 1 : 0;

		DMEMIT("%s %d %u ", log->type->name, params, lc->region_size);
		DMEMIT_SYNC;
		if (lc->failure_response == DMLOG_IOERR_BLOCK)
			DMEMIT("block_on_error ");
	}

	return sz;
}

static int disk_status(struct dirty_log *log, status_type_t status,
		       char *result, unsigned int maxlen)
{
	int sz = 0;
	int params;
	struct log_c *lc = log->context;

	switch(status) {
	case STATUSTYPE_INFO:
		DMEMIT("3 disk %s %c", lc->log_dev->name,
		       lc->log_dev_failed ? 'D' : 'A');
		break;

	case STATUSTYPE_TABLE:
		params = (lc->sync == DEFAULTSYNC) ? 2 : 3;
		params += (lc->failure_response == DMLOG_IOERR_BLOCK) ? 1 : 0;

		DMEMIT("%s %d %s %u ", log->type->name,
		       params,
		       lc->log_dev->name,
		       lc->region_size);
		DMEMIT_SYNC;
		if (lc->failure_response == DMLOG_IOERR_BLOCK)
			DMEMIT("block_on_error ");
	}

	return sz;
}

static int core_get_failure_response(struct dirty_log *log)
{
	struct log_c *lc = log->context;

	return lc->failure_response;
}

static struct dirty_log_type _core_type = {
	.name = "core",
	.module = THIS_MODULE,
	.ctr = core_ctr,
	.dtr = core_dtr,
	.resume = core_resume,
	.get_region_size = core_get_region_size,
	.is_clean = core_is_clean,
	.in_sync = core_in_sync,
	.flush = core_flush,
	.mark_region = core_mark_region,
	.clear_region = core_clear_region,
	.get_resync_work = core_get_resync_work,
	.complete_resync_work = core_complete_resync_work,
	.get_sync_count = core_get_sync_count,
	.status = core_status,
	.get_failure_response = core_get_failure_response,
};

static struct dirty_log_type _disk_type = {
	.name = "disk",
	.module = THIS_MODULE,
	.ctr = disk_ctr,
	.dtr = disk_dtr,
	.presuspend = disk_presuspend,
	.postsuspend = disk_flush,
	.resume = disk_resume,
	.get_region_size = core_get_region_size,
	.is_clean = core_is_clean,
	.in_sync = core_in_sync,
	.flush = disk_flush,
	.mark_region = core_mark_region,
	.clear_region = core_clear_region,
	.get_resync_work = core_get_resync_work,
	.complete_resync_work = core_complete_resync_work,
	.get_sync_count = core_get_sync_count,
	.status = disk_status,
	.get_failure_response = core_get_failure_response,
};

int __init dm_dirty_log_init(void)
{
	int r;

	r = dm_register_dirty_log_type(&_core_type);
	if (r)
		DMWARN("couldn't register core log");

	r = dm_register_dirty_log_type(&_disk_type);
	if (r) {
		DMWARN("couldn't register disk type");
		dm_unregister_dirty_log_type(&_core_type);
	}

	return r;
}

void dm_dirty_log_exit(void)
{
	dm_unregister_dirty_log_type(&_disk_type);
	dm_unregister_dirty_log_type(&_core_type);
}

EXPORT_SYMBOL(dm_register_dirty_log_type);
EXPORT_SYMBOL(dm_unregister_dirty_log_type);
EXPORT_SYMBOL(dm_create_dirty_log);
EXPORT_SYMBOL(dm_destroy_dirty_log);

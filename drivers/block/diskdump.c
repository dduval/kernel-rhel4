/*
 *  linux/drivers/block/diskdump.c
 *
 *  Copyright (C) 2004  FUJITSU LIMITED
 *  Copyright (C) 2002  Red Hat, Inc.
 *  Written by Nobuhiro Tachino (ntachino@jp.fujitsu.com)
 *
 *  Some codes were derived from netdump and copyright belongs to
 *  Red Hat, Inc.
 */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/smp_lock.h>
#include <linux/nmi.h>
#include <linux/crc32.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/diskdump.h>
#include <asm/diskdump.h>

#define Dbg(x, ...)	pr_debug("disk_dump: " x "\n", ## __VA_ARGS__)
#define Err(x, ...)	pr_err  ("disk_dump: " x "\n", ## __VA_ARGS__)
#define Warn(x, ...)	pr_warn ("disk_dump: " x "\n", ## __VA_ARGS__)
#define Info(x, ...)	pr_info ("disk_dump: " x "\n", ## __VA_ARGS__)

#define ROUNDUP(x, y)	(((x) + ((y)-1))/(y))

/* 512byte sectors to blocks */
#define SECTOR_BLOCK(s)	((s) >> (DUMP_BLOCK_SHIFT - 9))

/* The number of block which is used for saving format information */
#define USER_PARAM_BLOCK	2

static int fallback_on_err = 1;
static int allow_risky_dumps = 1;
static unsigned int block_order = 2;
static int sample_rate = 8;
module_param_named(fallback_on_err, fallback_on_err, bool, S_IRUGO|S_IWUSR);
module_param_named(allow_risky_dumps, allow_risky_dumps, bool, S_IRUGO|S_IWUSR);
module_param_named(block_order, block_order, uint, S_IRUGO|S_IWUSR);
module_param_named(sample_rate, sample_rate, int, S_IRUGO|S_IWUSR);

static unsigned long timestamp_1sec;
static uint32_t module_crc;
static char *scratch;
static struct disk_dump_header dump_header;
static struct disk_dump_sub_header dump_sub_header;

/* Registered dump devices */
static LIST_HEAD(disk_dump_devices);

/* Registered dump types, e.g. SCSI, ... */
static LIST_HEAD(disk_dump_types);

static DECLARE_MUTEX(disk_dump_mutex);

static unsigned int header_blocks;		/* The size of all headers */
static unsigned int bitmap_blocks;		/* The size of bitmap header */
static unsigned int total_ram_blocks;		/* The size of memory */
static unsigned int total_blocks;		/* The sum of above */
/*
 * This is not a parameter actually, but used to pass the number of
 * required blocks to userland tools
 */
module_param_named(total_blocks, total_blocks, uint, S_IRUGO);

struct notifier_block *disk_dump_notifier_list;
EXPORT_SYMBOL_GPL(disk_dump_notifier_list);

unsigned long volatile diskdump_base_jiffies;
void *diskdump_stack;
enum disk_dump_states disk_dump_state = DISK_DUMP_INITIAL;
EXPORT_SYMBOL_GPL(disk_dump_state);

extern int panic_timeout;
extern unsigned long max_pfn;

static asmlinkage void disk_dump(struct pt_regs *, void *);


#if CONFIG_SMP
static void freeze_cpu(void *dummy)
{
	unsigned int cpu = smp_processor_id();

	dump_header.tasks[cpu] = current;

	platform_freeze_cpu();
}
#endif

static int lapse = 0;		/* 200msec unit */

static inline unsigned long eta(unsigned long nr, unsigned long maxnr)
{
	unsigned long long eta;

	if (nr == 0)
		nr = 1;

	eta = ((maxnr << 8) / nr) * (unsigned long long)lapse;

	return (unsigned long)(eta >> 8) - lapse;
}

static inline void print_status(unsigned int nr, unsigned int maxnr)
{
	static char *spinner = "/|\\-";
	static unsigned long long prev_timestamp = 0;
	unsigned long long timestamp;

	if (nr == 0)
		nr++;

	platform_timestamp(timestamp);

	if (timestamp - prev_timestamp > (timestamp_1sec/5)) {
		prev_timestamp = timestamp;
		lapse++;
		printk("%u/%u    %lu ETA %c          \r",
			nr, maxnr, eta(nr, maxnr) / 5, spinner[lapse & 3]);
	}
}

static inline void clear_status(int nr, int maxnr)
{
	printk("                                       \r");
	lapse = 0;
}

/*
 * Checking the signature on a block. The format is as follows.
 *
 * 1st word = 'disk'
 * 2nd word = 'dump'
 * 3rd word = block number
 * 4th word = ((block number + 7) * 11) & 0xffffffff
 * 5th word = ((4th word + 7)* 11) & 0xffffffff
 * ..
 *
 * Return 1 if the signature is correct, else return 0
 */
static int check_block_signature(void *buf, unsigned int block_nr)
{
	int word_nr = PAGE_SIZE / sizeof(int);
	int *words = buf;
	unsigned int val;
	int i;

	/*
	 * Block 2 is used for the area which formatter saves options like
	 * the sampling rate or the number of blocks. the Kernel part does not
	 * check this block.
	 */
	if (block_nr == USER_PARAM_BLOCK)
		return 1;

	if (memcmp(buf, DUMP_PARTITION_SIGNATURE, sizeof(*words)))
		return 0;

	val = block_nr;
	for (i = 2; i < word_nr; i++) {
		if (words[i] != val)
			return 0;
		val = (val + 7) * 11;
	}

	return 1;
}

/*
 * Read one block into the dump partition
 */
static int read_blocks(struct disk_dump_partition *dump_part, unsigned int nr,
		       char *buf, int len)
{
	struct disk_dump_device *device = dump_part->device;
	int ret;

	local_irq_disable();
	touch_nmi_watchdog();
	ret = device->ops.rw_block(dump_part, READ, nr, buf, len);
	if (ret < 0) {
		Err("read error on block %u", nr);
		return ret;
	}
	return 0;
}

static int write_blocks(struct disk_dump_partition *dump_part, unsigned int offs, char *buf, int len)
{
	struct disk_dump_device *device = dump_part->device;
	int ret;

	local_irq_disable();
	touch_nmi_watchdog();
	ret = device->ops.rw_block(dump_part, WRITE, offs, buf, len);
	if (ret < 0) {
		Err("write error on block %u", offs);
		return ret;
	}
	return 0;
}

/*
 * Initialize the common header
 */

/*
 * Write the common header
 */
static int write_header(struct disk_dump_partition *dump_part)
{
	memset(scratch, 0, PAGE_SIZE);
	memcpy(scratch, &dump_header, sizeof(dump_header));

	return write_blocks(dump_part, 1, scratch, 1);
}

/*
 * Check the signaures in all blocks of the dump partition
 * Return 1 if the signature is correct, else return 0
 */
static int check_dump_partition(struct disk_dump_partition *dump_part,
				unsigned int partition_size)
{
	unsigned int blk;
	int ret;
	unsigned int chunk_blks, skips;
	int i;

	if (sample_rate < 0)		/* No check */
		return 1;

	/*
	 * If the device has limitations of transfer size, use it.
	 */
	chunk_blks = 1 << block_order;
	if (dump_part->device->max_blocks)
		 chunk_blks = min(chunk_blks, dump_part->device->max_blocks);
	skips = chunk_blks << sample_rate;

	lapse = 0;
	for (blk = 0; blk < partition_size; blk += skips) {
		unsigned int len;
redo:
		len = min(chunk_blks, partition_size - blk);
		if ((ret = read_blocks(dump_part, blk, scratch, len)) < 0)
			return 0;
		print_status(blk + 1, partition_size);
		for (i = 0; i < len; i++)
			if (!check_block_signature(scratch + i * DUMP_BLOCK_SIZE, blk + i)) {
				Err("bad signature in block %u", blk + i);
				return 0;
			}
	}
	/* Check the end of the dump partition */
	if (blk - skips + chunk_blks < partition_size) {
		blk = partition_size - chunk_blks;
		goto redo;
	}
	clear_status(blk, partition_size);
	return 1;
}

/*
 * Write memory bitmap after location of dump headers.
 */
#define PAGE_PER_BLOCK	(PAGE_SIZE * 8)
#define idx_to_pfn(nr, byte, bit) (((nr) * PAGE_SIZE + (byte)) * 8 + (bit))

static int write_bitmap(struct disk_dump_partition *dump_part,
			unsigned int bitmap_offset, unsigned int bitmap_blocks)
{
	unsigned int nr;
	unsigned long pfn, next_ram_pfn;
	int bit, byte;
	int ret = 0;
	unsigned char val;

	for (nr = 0; nr < bitmap_blocks; nr++) {
		pfn = idx_to_pfn(nr, 0, 0);
		next_ram_pfn = next_ram_page(pfn - 1);

		if (pfn + PAGE_PER_BLOCK <= next_ram_pfn)
			memset(scratch, 0, PAGE_SIZE);
		else
			for (byte = 0; byte < PAGE_SIZE; byte++) {
				val = 0;
				for (bit = 0; bit < 8; bit++)
					if (page_is_ram(idx_to_pfn(nr, byte,
								   bit)))
						val |= (1 << bit);
				scratch[byte] = (char)val;
			}
		if ((ret = write_blocks(dump_part, bitmap_offset + nr,
					scratch, 1)) < 0) {
			Err("I/O error %d on block %u", ret, bitmap_offset + nr);
			break;
		}
	}
	return ret;
}

/*
 * Write whole memory to dump partition.
 * Return value is the number of writen blocks.
 */
static int write_memory(struct disk_dump_partition *dump_part, int offset,
			unsigned int max_blocks_written,
			unsigned int *blocks_written)
{
	char *kaddr;
	unsigned int blocks = 0;
	struct page *page;
	unsigned long nr;
	int ret = 0;
	int blk_in_chunk = 0;

	for (nr = next_ram_page(ULONG_MAX); nr < max_pfn; nr = next_ram_page(nr)) {
		print_status(blocks, max_blocks_written);


		if (blocks >= max_blocks_written) {
			Warn("dump device is too small. %lu pages were not saved", max_pfn - blocks);
			goto out;
		}

		page = pfn_to_page(nr);
		if (nr != page_to_pfn(page)) {
			/* page_to_pfn() is called from kmap_atomic().
			 * If page->flag is broken, it specified a wrong
			 * zone and it causes kmap_atomic() fail.
			 */
			Err("Bad page. PFN %lu flags %lx\n",
			    nr, (unsigned long)page->flags);
			memset(scratch + blk_in_chunk * PAGE_SIZE, 0,
			       PAGE_SIZE);
			sprintf(scratch + blk_in_chunk * PAGE_SIZE,
				"Bad page. PFN %lu flags %lx\n",
			 	 nr, (unsigned long)page->flags);
			goto write;
		}

		if (!kern_addr_valid((unsigned long)pfn_to_kaddr(nr))) {
			memset(scratch + blk_in_chunk * PAGE_SIZE, 0,
			       PAGE_SIZE);
			sprintf(scratch + blk_in_chunk * PAGE_SIZE,
				"Unmapped page. PFN %lu\n", nr);
			goto write;
		}

		kaddr = kmap_atomic(page, KM_CRASHDUMP);
		/*
		 * need to copy because adapter drivers use
		 * virt_to_bus()
		 */
		memcpy(scratch + blk_in_chunk * PAGE_SIZE, kaddr, PAGE_SIZE);
		kunmap_atomic(kaddr, KM_CRASHDUMP);

write:
		blk_in_chunk++;
		blocks++;

		if (blk_in_chunk >= (1 << block_order)) {
			ret = write_blocks(dump_part, offset, scratch,
					   blk_in_chunk);
			if (ret < 0) {
				Err("I/O error %d on block %u", ret, offset);
				break;
			}
			offset += blk_in_chunk;
			blk_in_chunk = 0;
		}
	}
	if (ret >= 0 && blk_in_chunk > 0) {
		ret = write_blocks(dump_part, offset, scratch, blk_in_chunk);
		if (ret < 0)
			Err("I/O error %d on block %u", ret, offset);
	}

out:
	clear_status(nr, max_blocks_written);

	*blocks_written = blocks;
	return ret;
}

/*
 * Select most suitable dump device. sanity_check() returns the state
 * of each dump device. 0 means OK, negative value means NG, and
 * positive value means it maybe work. select_dump_partition() first
 * try to select a sane device and if it has no sane device and
 * allow_risky_dumps is set, it select one from maybe OK devices.
 *
 * XXX We cannot handle multiple partitions yet.
 */
static struct disk_dump_partition *select_dump_partition(void)
{
	struct disk_dump_device *dump_device;
	struct disk_dump_partition *dump_part;
	int sanity;
	int strict_check = 1;

redo:
	/*
	 * Select a sane polling driver.
	 */
	list_for_each_entry(dump_device, &disk_dump_devices, list) {
		sanity = 0;
		if (dump_device->ops.sanity_check)
			sanity = dump_device->ops.sanity_check(dump_device);
		if (sanity < 0 || (sanity > 0 && strict_check))
			continue;
		list_for_each_entry(dump_part, &dump_device->partitions, list)
				return dump_part;
	}
	if (allow_risky_dumps && strict_check) {
		strict_check = 0;
		goto redo;
	}
	return NULL;
}

static int dump_err = 0;	/* Indicate Error state which occured in
				 * disk_dump(). We need to make it global
				 * because disk_dump() can't pass
				 * error state as return value.
				 */

static void freeze_other_cpus(void)
{
#if CONFIG_SMP
	int	i;

	smp_call_function(freeze_cpu, NULL, 1, -1);
	diskdump_mdelay(3000);
	printk("CPU frozen: ");
	for (i = 0; i < NR_CPUS; i++) {
		if (dump_header.tasks[i] != NULL)
			printk("#%d", i);

	}
	printk("\n");
	printk("CPU#%d is executing diskdump.\n", smp_processor_id());
#else
	diskdump_mdelay(1000);
#endif
	dump_header.tasks[smp_processor_id()] = current;
}

static void start_disk_dump(struct pt_regs *regs)
{
	unsigned long flags;

	/* Inhibit interrupt and stop other CPUs */
	local_irq_save(flags);
	preempt_disable();

	/*
	 * Check the checksum of myself
	 */
	if (down_trylock(&disk_dump_mutex)) {
		Err("down_trylock(disk_dump_mutex) failed.");
		goto done;
	}

	if (!check_crc_module()) {
		Err("checksum error. diskdump common module may be compromised.");
		goto done;
	}

	disk_dump_state = DISK_DUMP_RUNNING;

	diskdump_mode = 1;

	Dbg("notify dump start.");
	notifier_call_chain(&disk_dump_notifier_list, 0, NULL);

	touch_nmi_watchdog();
	freeze_other_cpus();

	/*
	 *  Some platforms may want to execute netdump on its own stack.
	 */
	platform_start_crashdump(diskdump_stack, disk_dump, regs);

done:
	/*
	 * If diskdump failed and fallback_on_err is set,
	 * We just return and leave panic to netdump.
	 */
	if (dump_err) {
		disk_dump_state = DISK_DUMP_FAILURE;
		if (fallback_on_err && dump_err) {
			Info("diskdump failed, fall back to trying netdump");
			return;
		}
		Info("diskdump failed with error");
	} else {
		disk_dump_state = DISK_DUMP_SUCCESS;
		Info("diskdump succeeded");
	}

	Dbg("notify panic.");
	notifier_call_chain(&panic_notifier_list, 0, NULL);

	if (panic_timeout > 0) {
		int i;
		/*
	 	 * Delay timeout seconds before rebooting the machine. 
		 * We can't use the "normal" timers since we just panicked..
	 	 */
		printk(KERN_EMERG "Rebooting in %d seconds..",panic_timeout);
		for (i = 0; i < panic_timeout; i++) {
			touch_nmi_watchdog();
			diskdump_mdelay(1000);
		}

		/*
		 *	Should we run the reboot notifier. For the moment Im
		 *	choosing not too. It might crash, be corrupt or do
		 *	more harm than good for other reasons.
		 */
		machine_restart(NULL);
	}
	printk(KERN_EMERG "halt\n");
	for (;;) {
		touch_nmi_watchdog();
		machine_halt();
		diskdump_mdelay(1000);
	}
}

static asmlinkage void disk_dump(struct pt_regs *regs, void *platform_arg)
{
	struct pt_regs myregs;
	unsigned int max_written_blocks, written_blocks;
	struct disk_dump_device *dump_device = NULL;
	struct disk_dump_partition *dump_part = NULL;
	int ret;

	dump_err = -EIO;

	/*
	 * Setup timer/tasklet
	 */
	dump_clear_timers();
	dump_clear_tasklet();
	dump_clear_workqueue();

	/* Save original jiffies value */
	diskdump_base_jiffies = jiffies;

	diskdump_setup_timestamp();

	platform_fix_regs();

	if (list_empty(&disk_dump_devices)) {
		Err("adapter driver is not registered.");
		goto done;
	}

	printk("start dumping\n");

	if (!(dump_part = select_dump_partition())) {
		Err("No sane dump device found");
		goto done;
	}
	dump_device = dump_part->device;

	/*
	 * Stop ongoing I/O with polling driver and make the shift to I/O mode
	 * for dump
	 */
	Dbg("do quiesce");
	if (dump_device->ops.quiesce)
		if ((ret = dump_device->ops.quiesce(dump_device)) < 0) {
			Err("quiesce failed. error %d", ret);
			goto done;
		}

	if (SECTOR_BLOCK(dump_part->nr_sects) < header_blocks + bitmap_blocks) {
		Warn("dump partition is too small. Aborted");
		goto done;
	}

	/* Check dump partition */
	printk("check dump partition...\n");
	if (!check_dump_partition(dump_part, total_blocks)) {
		Err("check partition failed.");
		goto done;
	}

	/*
	 * Write the common header
	 */
	memcpy(dump_header.signature, DISK_DUMP_SIGNATURE,
	       sizeof(dump_header.signature));
	dump_header.utsname	     = system_utsname;
	dump_header.timestamp	     = xtime;
	dump_header.status	     = DUMP_HEADER_INCOMPLETED;
	dump_header.block_size	     = PAGE_SIZE;
	dump_header.sub_hdr_size     = size_of_sub_header();
	dump_header.bitmap_blocks    = bitmap_blocks;
	dump_header.max_mapnr	     = max_pfn;
	dump_header.total_ram_blocks = total_ram_blocks;
	dump_header.device_blocks    = SECTOR_BLOCK(dump_part->nr_sects);
	dump_header.current_cpu	     = smp_processor_id();
	dump_header.nr_cpus	     = num_online_cpus();
	dump_header.written_blocks   = 2;

	write_header(dump_part);

	/*
	 * Write the architecture dependent header
	 */
	Dbg("write sub header");
	if ((ret = write_sub_header()) < 0) {
		Err("writing sub header failed. error %d", ret);
		goto done;
	}

	Dbg("writing memory bitmaps..");
	if ((ret = write_bitmap(dump_part, header_blocks, bitmap_blocks)) < 0)
		goto done;

	max_written_blocks = total_ram_blocks;
	if (dump_header.device_blocks < total_blocks) {
		Warn("dump partition is too small. actual blocks %u. expected blocks %u. whole memory will not be saved",
				dump_header.device_blocks, total_blocks);
		max_written_blocks -= (total_blocks - dump_header.device_blocks);
	}

	dump_header.written_blocks += dump_header.sub_hdr_size;
	dump_header.written_blocks += dump_header.bitmap_blocks;
	write_header(dump_part);

	printk("dumping memory..\n");
	if ((ret = write_memory(dump_part, header_blocks + bitmap_blocks,
				max_written_blocks, &written_blocks)) < 0)
		goto done;

	/*
	 * Set the number of block that is written into and write it
	 * into partition again.
	 */
	dump_header.written_blocks += written_blocks;
	dump_header.status = DUMP_HEADER_COMPLETED;
	write_header(dump_part);

	dump_err = 0;

done:
	Dbg("do adapter shutdown.");
	if (dump_device && dump_device->ops.shutdown)
		if (dump_device->ops.shutdown(dump_device))
			Err("adapter shutdown failed.");
}

static struct disk_dump_partition *find_dump_partition(struct block_device *bdev)
{
	struct disk_dump_device *dump_device;
	struct disk_dump_partition *dump_part;

	list_for_each_entry(dump_device, &disk_dump_devices, list)
		list_for_each_entry(dump_part, &dump_device->partitions, list)
			if (dump_part->bdev == bdev)
				return dump_part;
	return NULL;
}

static struct disk_dump_device *find_dump_device(struct disk_dump_device *device)
{
	struct disk_dump_device *dump_device;

	list_for_each_entry(dump_device, &disk_dump_devices, list)
		if (device->device == dump_device->device)
			return  dump_device;
	return NULL;
}

static void *find_real_device(struct device *dev,
			      struct disk_dump_type **_dump_type)
{
	void *real_device;
	struct disk_dump_type *dump_type;

	list_for_each_entry(dump_type, &disk_dump_types, list)
		if ((real_device = dump_type->probe(dev)) != NULL) {
			*_dump_type = dump_type;
			return real_device;
		}
	return NULL;
}

/*
 * Add dump partition structure corresponding to file to the dump device
 * structure.
 */
static int add_dump_partition(struct disk_dump_device *dump_device,
			      struct block_device *bdev)
{
	struct disk_dump_partition *dump_part;
	char buffer[BDEVNAME_SIZE];

	if (!(dump_part = kmalloc(sizeof(*dump_part), GFP_KERNEL)))
		return -ENOMEM;

	dump_part->device = dump_device;
	dump_part->bdev = bdev;

	if (!bdev || !bdev->bd_part)
		return -EINVAL;
	dump_part->nr_sects   = bdev->bd_part->nr_sects;
	dump_part->start_sect = bdev->bd_part->start_sect;

	if (SECTOR_BLOCK(dump_part->nr_sects) < total_blocks)
		Warn("%s is too small to save whole system memory\n",
			bdevname(bdev, buffer));

	list_add(&dump_part->list, &dump_device->partitions);

	return 0;
}

/*
 * Add dump device and partition.
 * Must be called with disk_dump_mutex held.
 */
static int add_dump(struct device *dev, struct block_device *bdev)
{
	struct disk_dump_type *dump_type = NULL;
	struct disk_dump_device *dump_device;
	void *real_device;
	int ret;

	if ((ret = blkdev_get(bdev, FMODE_READ, 0)) < 0)
		return ret;

	/* Check whether this block device is already registered */
	if (find_dump_partition(bdev)) {
		blkdev_put(bdev);
		return -EEXIST;
	}

	/* find dump_type and real device for this inode */
	if (!(real_device = find_real_device(dev, &dump_type))) {
		blkdev_put(bdev);
		return -ENXIO;
	}

	/* Check whether this device is already registered */
	dump_device = find_dump_device(real_device);
	if (dump_device == NULL) {
		/* real_device is not registered. create new dump_device */
		if (!(dump_device = kmalloc(sizeof(*dump_device), GFP_KERNEL))) {
			blkdev_put(bdev);
			return -ENOMEM;
		}

		memset(dump_device, 0, sizeof(*dump_device));
		INIT_LIST_HEAD(&dump_device->partitions);

		dump_device->dump_type = dump_type;
		dump_device->device = real_device;
		if ((ret = dump_type->add_device(dump_device)) < 0) {
			kfree(dump_device);
			blkdev_put(bdev);
			return ret;
		}
		if (!try_module_get(dump_type->owner))
			return -EINVAL;
		list_add(&dump_device->list, &disk_dump_devices);
	}

	ret = add_dump_partition(dump_device, bdev);
	if (ret < 0 && list_empty(&dump_device->list)) {
		dump_type->remove_device(dump_device);
		module_put(dump_type->owner);
		list_del(&dump_device->list);
		kfree(dump_device);
	}
	if (ret < 0)
		blkdev_put(bdev);

	return ret;
}

/*
 * Remove dump partition corresponding to bdev.
 * Must be called with disk_dump_mutex held.
 */
static int remove_dump(struct block_device *bdev)
{
	struct disk_dump_device *dump_device;
	struct disk_dump_partition *dump_part;
	struct disk_dump_type *dump_type;

	if (!(dump_part = find_dump_partition(bdev))) {
		bdput(bdev);
		return -ENOENT;
	}

	blkdev_put(bdev);
	dump_device = dump_part->device;
	list_del(&dump_part->list);
	kfree(dump_part);

	if (list_empty(&dump_device->partitions)) {
		dump_type = dump_device->dump_type;
		dump_type->remove_device(dump_device);
		module_put(dump_type->owner);
		list_del(&dump_device->list);
		kfree(dump_device);
	}

	return 0;
}

#ifdef CONFIG_PROC_FS
static struct disk_dump_partition *dump_part_by_pos(struct seq_file *seq,
						    loff_t pos)
{
	struct disk_dump_device *dump_device;
	struct disk_dump_partition *dump_part;

	list_for_each_entry(dump_device, &disk_dump_devices, list) {
		seq->private = dump_device;
		list_for_each_entry(dump_part, &dump_device->partitions, list)
			if (!pos--)
				return dump_part;
	}
	return NULL;
}

static void *disk_dump_seq_start(struct seq_file *seq, loff_t *pos)
{
	loff_t n = *pos;

	down(&disk_dump_mutex);

	if (!n--)
		return (void *)1;	/* header */

	return dump_part_by_pos(seq, n);
}

static void *disk_dump_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct list_head *partition = v;
	struct list_head *device = seq->private;
	struct disk_dump_device *dump_device;

	(*pos)++;
	if (v == (void *)1)
		return dump_part_by_pos(seq, 0);

	dump_device = list_entry(device, struct disk_dump_device, list);

	partition = partition->next;
	if (partition != &dump_device->partitions)
		return partition;

	device = device->next;
	seq->private = device;
	if (device == &disk_dump_devices)
		return NULL;

	dump_device = list_entry(device, struct disk_dump_device, list);

	return dump_device->partitions.next;
}

static void disk_dump_seq_stop(struct seq_file *seq, void *v)
{
	up(&disk_dump_mutex);
}

static int disk_dump_seq_show(struct seq_file *seq, void *v)
{
	struct disk_dump_partition *dump_part = v;
	char buf[BDEVNAME_SIZE];

	if (v == (void *)1) {	/* header */
		seq_printf(seq, "# sample_rate: %u\n", sample_rate);
		seq_printf(seq, "# block_order: %u\n", block_order);
		seq_printf(seq, "# fallback_on_err: %u\n", fallback_on_err);
		seq_printf(seq, "# allow_risky_dumps: %u\n", allow_risky_dumps);
		seq_printf(seq, "# total_blocks: %u\n", total_blocks);
		seq_printf(seq, "#\n");

		return 0;
	}

	seq_printf(seq, "%s %lu %lu\n", bdevname(dump_part->bdev, buf),
			dump_part->start_sect, dump_part->nr_sects);
	return 0;
}

static struct seq_operations disk_dump_seq_ops = {
	.start	= disk_dump_seq_start,
	.next	= disk_dump_seq_next,
	.stop	= disk_dump_seq_stop,
	.show	= disk_dump_seq_show,
};

static int disk_dump_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &disk_dump_seq_ops);
}

static struct file_operations disk_dump_fops = {
	.owner		= THIS_MODULE,
	.open		= disk_dump_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};
#endif

int register_disk_dump_device(struct device *dev, struct block_device *bdev)
{
	int ret;

	down(&disk_dump_mutex);
	ret = add_dump(dev, bdev);
	set_crc_modules();
	up(&disk_dump_mutex);

	return ret;
}

int unregister_disk_dump_device(struct block_device *bdev)
{
	int ret;

	down(&disk_dump_mutex);
	ret = remove_dump(bdev);
	set_crc_modules();
	up(&disk_dump_mutex);

	return ret;
}

int find_disk_dump_device(struct block_device *bdev)
{
	int ret;

	down(&disk_dump_mutex);
	ret = (find_dump_partition(bdev) != NULL);
	up(&disk_dump_mutex);

	return ret;
}

int register_disk_dump_type(struct disk_dump_type *dump_type)
{
	down(&disk_dump_mutex);
	list_add(&dump_type->list, &disk_dump_types);
	set_crc_modules();
	up(&disk_dump_mutex);

	return 0;
}

EXPORT_SYMBOL_GPL(register_disk_dump_type);

int unregister_disk_dump_type(struct disk_dump_type *dump_type)
{
	down(&disk_dump_mutex);
	list_del(&dump_type->list);
	set_crc_modules();
	up(&disk_dump_mutex);

	return 0;
}

EXPORT_SYMBOL_GPL(unregister_disk_dump_type);

static void compute_total_blocks(void)
{
	unsigned long nr;

	/*
	 * the number of block of the common header and the header
	 * that is depend on the architecture
	 *
	 * block 0:		dump partition header
	 * block 1:		dump header
	 * block 2:		dump subheader
	 * block 3..n:		memory bitmap
	 * block (n + 1)...:	saved memory
	 *
	 * We never overwrite block 0
	 */
	header_blocks = 2 + size_of_sub_header();

	total_ram_blocks = 0;
	for (nr = next_ram_page(ULONG_MAX); nr < max_pfn; nr = next_ram_page(nr))
		total_ram_blocks++;

	bitmap_blocks = ROUNDUP(max_pfn, 8 * PAGE_SIZE);

	/*
	 * The necessary size of area for dump is:
	 * 1 block for common header
	 * m blocks for architecture dependent header
	 * n blocks for memory bitmap
	 * and whole memory
	 */
	total_blocks = header_blocks + bitmap_blocks + total_ram_blocks;

	Info("total blocks required: %u (header %u + bitmap %u + memory %u)",
		total_blocks, header_blocks, bitmap_blocks, total_ram_blocks);
}

struct disk_dump_ops dump_ops = {
	.add_dump	= register_disk_dump_device,
	.remove_dump	= unregister_disk_dump_device,
	.find_dump	= find_disk_dump_device,
};

static int init_diskdump(void)
{
	unsigned long long t0;
	unsigned long long t1;
	struct page *page;

	if (!platform_supports_diskdump) {
		Err("platform does not support diskdump.");
		return -1;
	}

	/* Allocate one block that is used temporally */
	do {
		page = alloc_pages(GFP_KERNEL, block_order);
		if (page != NULL)
			break;
	} while (--block_order >= 0);
	if (!page) {
		Err("alloc_pages failed.");
		return -1;
	}
	scratch = page_address(page);
	Info("Maximum block size: %lu", PAGE_SIZE << block_order);

	if (diskdump_register_hook(start_disk_dump)) {
		Err("failed to register hooks.");
		return -1;
	}

	if (diskdump_register_ops(&dump_ops)) {
		Err("failed to register ops.");
		return -1;
	}

	compute_total_blocks();

	platform_timestamp(t0);
	diskdump_mdelay(1);
	platform_timestamp(t1);
	timestamp_1sec = (unsigned long)(t1 - t0) * 1000;

	/*
	 *  Allocate a separate stack for diskdump.
	 */
	platform_init_stack(&diskdump_stack);

	down(&disk_dump_mutex);
	set_crc_modules();
	up(&disk_dump_mutex);

#ifdef CONFIG_PROC_FS
	{
		struct proc_dir_entry *p;

		p = create_proc_entry("diskdump", S_IRUGO|S_IWUSR, NULL);
		if (p)
			p->proc_fops = &disk_dump_fops;
	}
#endif

	return 0;
}

static void cleanup_diskdump(void)
{
	Info("shut down.");
	diskdump_unregister_hook();
	diskdump_unregister_ops();
	platform_cleanup_stack(diskdump_stack);
	free_pages((unsigned long)scratch, block_order);
#ifdef CONFIG_PROC_FS
	remove_proc_entry("diskdump", NULL);
#endif
}

module_init(init_diskdump);
module_exit(cleanup_diskdump);

MODULE_LICENSE("GPL");

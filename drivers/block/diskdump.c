/*
 *  linux/drivers/block/diskdump.c
 *
 *  Copyright (C) 2004  FUJITSU LIMITED
 *  Copyright (C) 2002  Red Hat, Inc.
 *  Written by Nobuhiro Tachino (ntachino@jp.fujitsu.com)
 *
 *  Some codes were derived from netdump and copyright belongs to
 *  Red Hat, Inc.
 *
 *
 *  The idea and some codes of dump compression were derived from LKCD.
 *
 * Copyright (C) 1999 - 2002 Silicon Graphics, Inc. All rights reserved.
 * Copyright (C) 2001 - 2002 Matt D. Robinson.  All rights reserved.
 * Copyright (C) 2002 International Business Machines Corp. 
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
#include <linux/swap.h>
#include <linux/zlib.h>
#include <linux/vmalloc.h>
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
static int dump_level = 0;
static int compress = 0;
module_param_named(fallback_on_err, fallback_on_err, bool, S_IRUGO|S_IWUSR);
module_param_named(allow_risky_dumps, allow_risky_dumps, bool, S_IRUGO|S_IWUSR);
module_param_named(block_order, block_order, uint, S_IRUGO|S_IWUSR);
module_param_named(sample_rate, sample_rate, int, S_IRUGO|S_IWUSR);
module_param_named(dump_level, dump_level, int, S_IRUGO|S_IWUSR);
module_param_named(compress, compress, int, S_IRUGO);

static unsigned long timestamp_1sec;
static uint32_t module_crc;
static char *scratch;
static struct disk_dump_bitmap dump_bitmap;
static int rewrite_header;
static int free_list_is_valid = 1;
static struct disk_dump_header dump_header;
static struct disk_dump_sub_header dump_sub_header;

/* Registered dump devices */
static LIST_HEAD(disk_dump_devices);

/* Registered dump partitions */
static LIST_HEAD(disk_dump_partitions);

#define NEXT_PART(part)	list_entry((part)->part_list.next, struct disk_dump_partition, part_list)

/* Registered dump types, e.g. SCSI, ... */
static LIST_HEAD(disk_dump_types);

static DECLARE_MUTEX(disk_dump_mutex);

static unsigned int header_blocks;		/* The size of all headers */
static unsigned int bitmap_blocks;		/* The size of bitmap header */
static unsigned int ram_bitmap_blocks;		/* The size of ram bitmaps */
static unsigned int total_ram_blocks;		/* The size of memory */
static unsigned int total_blocks;		/* The sum of above */

static int compress_block_order;
static char *compress_buffer;
static void *deflate_workspace;
static void *curr_buf; /* current position in the dump buffer */
static void *dump_buf; /* starting addr of dump buffer */
static int diskdump_compress_write(struct disk_dump_partition *dump_part,
				   int *offset, unsigned int *blocks,
				   struct page *);
static int diskdump_compress_flush(struct disk_dump_partition *dump_part,
				   int offset, unsigned int *blocks);

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


static inline int check_zero_page(struct page *page)
{
	unsigned long *data;
	int ret;

	data = kmap_atomic(page, KM_CRASHDUMP);
	ret = find_first_bit(data, PAGE_SIZE << 3) == PAGE_SIZE << 3;
	kunmap_atomic(data, KM_CRASHDUMP);

	return ret;
}

static int page_is_dumpable(unsigned long pfn)
{
	struct page *page = pfn_to_page(pfn);

	if (!dump_level)
		return 1;
	if ((pfn != page_to_pfn(page)) ||
	    !kern_addr_valid((unsigned long)pfn_to_kaddr(pfn)))
		return 0;

 	if ((dump_level & DUMP_EXCLUDE_CACHE) &&
	    (dump_level & DUMP_SAVE_PRIVATE) &&
	    PagePrivate(page))
		return 1;
	if ((dump_level & DUMP_EXCLUDE_CACHE) && !PageAnon(page) &&
	    (PageLRU(page) || PageSwapCache(page)))
		return 0;
	if ((dump_level & DUMP_EXCLUDE_CLEAN) && check_zero_page(page))
		return 0;
	if ((dump_level & DUMP_EXCLUDE_FREE) && free_list_is_valid
	    && PageNosaveFree(page))
		return 0;
	if ((dump_level & DUMP_EXCLUDE_ANON) && PageAnon(page))
		return 0;

	return 1;
}

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

static inline void print_status(unsigned int nr, int nr_skipped,
				unsigned int maxnr)
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
		if (nr_skipped >= 0)
			printk("%u(%u skipped)/%u    %lu ETA %c          \r",
				nr + nr_skipped, nr_skipped, maxnr,
				eta(nr + nr_skipped, maxnr) / 5,
				spinner[lapse & 3]);
		else
			printk("%u/%u    %lu ETA %c          \r",
				nr, maxnr, eta(nr, maxnr) / 5,
				spinner[lapse & 3]);
	}
}

static inline void clear_status(int nr, int maxnr)
{
	printk("                                       \r");
	lapse = 0;
}

static inline void print_last_status(int nr, int nr_skipped, int maxnr,
				     int blocks_uncompressed)
{
	if (nr_skipped >= 0)
		printk("%u(%u saved %u skipped)/%u                        \n",
		       blocks_uncompressed + nr_skipped, blocks_uncompressed,
		       nr_skipped, maxnr);
	else
		printk("%u/%u                        \n", blocks_uncompressed,
		       maxnr);
	if (compress)
		printk("%d compressed into %d\n", blocks_uncompressed, nr);
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
 * Write the common header
 */
static int write_header(struct disk_dump_partition *dump_part)
{
	memset(scratch, 0, PAGE_SIZE);
	memcpy(scratch, &dump_header, sizeof(dump_header));

	return write_blocks(dump_part, 1, scratch, 1);
}

/*
 * Check the signatures in all blocks of the dump partition
 * Return 1 if the signature is correct, else return 0
 */
static int check_dump_partition(struct disk_dump_partition *dump_part,
				unsigned int partition_size)
{
	unsigned int blk;
	int ret;
	unsigned int chunk_blks, skips;
	int i;
	unsigned int device_blocks	= SECTOR_BLOCK(dump_part->nr_sects);

	if (!strict_size_check() && device_blocks < partition_size)
		partition_size = device_blocks;

	if (sample_rate < 0)		/* No check */
		return 1;

	/*
	 * If the device has limitations of transfer size, use it.
	 */
	chunk_blks = 1 << block_order;
	if (dump_part->device->max_blocks < chunk_blks)
		Warn("I/O size exceeds the maximum block size of SCSI device. Signature check may fail");
	skips = chunk_blks << sample_rate;

	lapse = 0;
	for (blk = 0; blk < partition_size; blk += skips) {
		unsigned int len;
redo:
		len = min(chunk_blks, partition_size - blk);
		if ((ret = read_blocks(dump_part, blk, scratch, len)) < 0)
			return 0;
		print_status(blk + 1, -1, partition_size);
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
 * Check the signatures in the first blocks of the swap partition
 * Return 1 if the signature is correct, else return 0
 */
static int check_swap_partition(struct disk_dump_partition *dump_part,
				unsigned int partition_size)
{
	int ret;
	union swap_header *swh;

	if ((ret = read_blocks(dump_part, 0, scratch, 1)) < 0)
		return 0;

	swh = (union swap_header *)scratch;

	if (memcmp(swh->magic.magic, "SWAPSPACE2",
					sizeof("SWAPSPACE2") - 1) != 0)
		return 0;

	if (swh->info.version != 1)
		return 0;

	if (swh->info.last_page + 1 != SECTOR_BLOCK(dump_part->nr_sects))
		return 0;

	if (strict_size_check() && (swh->info.last_page < partition_size))
		return 0;

	return 1;
}

/*
 * Shutdown the devices.
 */
static void diskdump_shutdown(void)
{
	struct disk_dump_device *dump_device;

	list_for_each_entry(dump_device, &disk_dump_devices, list) {
		Dbg("do adapter shutdown.");
		if (dump_device->need_shutdown && dump_device->ops.shutdown)
			if (dump_device->ops.shutdown(dump_device))
				Err("adapter shutdown failed.");
	}
}

static int clear_extra_bitmap(struct disk_dump_partition *dump_part,
			unsigned int bitmap_offset, unsigned int bitmap_blocks)
{
	int nr;
	unsigned int offset;
	int ret;

	if (!strict_size_check()) {
		memset(scratch, 0, PAGE_SIZE);
		for (nr = 0; nr < bitmap_blocks; nr++) {
			offset = bitmap_offset + bitmap_blocks + nr;
			if ((ret = write_blocks(dump_part, offset, scratch, 1))
					< 0) {
				Err("I/O error %d on block %u", ret, offset);
				return -1;
			}
		}
	}

	return 0;
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
			return ret;
		}
	}

	if ((ret = clear_extra_bitmap(dump_part, bitmap_offset, bitmap_blocks))
			< 0)
		return ret;

	return 0;
}

/*
 * Flush bitmap buffer to the disk
 */
static int flush_bitmap(struct disk_dump_partition *dump_part)
{
	int ret = 0;

	if (strict_size_check())
		return 0;
	if (dump_bitmap.bit == 0 && dump_bitmap.byte == 0)
		return 0;

	if ((ret = write_blocks(dump_part, dump_bitmap.index,
				dump_bitmap.map, 1)) < 0)
		Err("I/O error %d on block %u", ret, dump_bitmap.index);

	memset(dump_bitmap.map, 0, PAGE_SIZE);
	dump_bitmap.index++;
	dump_bitmap.flushed = 1;

	return ret;
}

/*
 * Set bit of corresponding to the bitmap buffer and flush the buffer
 * to the disk if needed.
 */
static int set_bitmap(struct disk_dump_partition *dump_part, unsigned long val)
{
	int ret = 0;

	if (strict_size_check())
		return 0;

	dump_bitmap.map[dump_bitmap.byte] |= val ? (1<<dump_bitmap.bit) : 0;

	if (++dump_bitmap.bit == 8) {
		dump_bitmap.bit = 0;
		++dump_bitmap.byte;
	}
	if (dump_bitmap.byte == PAGE_SIZE) {
		/* If bitmap is full, write it to the disk. */
		if ((ret = flush_bitmap(dump_part)) < 0)
			return ret;
		dump_bitmap.byte = 0;
	}
	return 0;
}

/*
 * In case of compressed data:
 * Size of data in buffer = current_blks_buff * block size + size of fraction.
 * Size of next data to be buffered <= size of page header + block size.
 * If remaining space in partition becomes less than
 * the current blocks in buffer + 3 blocks, there is
 * chance that (fraction + next data) may not fit into that space.
 *
 * return 0 : data not overflow
 *        1 : data overflow
 *
 */
static int check_overflow(unsigned int current_blks_part,
			unsigned int current_blks_buff,
			unsigned int partition_size)
{
	unsigned int current_total_blks;

	if (compress)
		current_total_blks = current_blks_part + current_blks_buff + 2;
	else
		current_total_blks = current_blks_part;

	if (current_total_blks >= partition_size)
		return 1;
	else
		return 0;
}

/*
 * When the bitmap is flushed, update the dump
 * header to show the size at that time even if
 * the dumping is interrupted by something.
 */
static int update_header(struct disk_dump_partition *dump_part)
{
	if (rewrite_header) {
		rewrite_header = 0;
		if (write_header(dump_part) < 0)
			return -1;
	}

	return 0;
}

/*
 * Write whole memory to dump partition.
 * Return value is the number of writen blocks.
 */
static int write_memory(struct disk_dump_partition *dump_part, int offset,
			unsigned int blocks_written_expected,
			unsigned int max_blocks_written)
{
	char *kaddr;
	unsigned int blocks = 0, blocks_uncompressed = 0;
	int blocks_skipped = dump_level ? 0 : -1;
	struct page *page;
	unsigned long nr;
	int ret = -1, short_area = 0, size = 0;
	int blk_in_chunk = 0;
	int dumpable;

	dump_header.status = DUMP_HEADER_IN_PROGRESS;
	if (compress)
		dump_header.status |= DUMP_HEADER_COMPRESSED;

	for (nr = next_ram_page(ULONG_MAX); nr < max_pfn; nr = next_ram_page(nr)) {
		print_status(blocks_uncompressed, blocks_skipped,
			     blocks_written_expected);

		/* Check the possibility of the partition overflow.
		 */
		if (check_overflow(blocks, (size>>PAGE_SHIFT),
					max_blocks_written))
			short_area = 1;

		if (short_area) {
			int disregarded_pages
				= total_ram_blocks - (blocks_uncompressed
				+ (blocks_skipped == -1 ? 0 : blocks_skipped)); 
			Warn("dump device is too small. %d pages will be disregarded",
				disregarded_pages);
			break;
		}

		if (!pfn_valid(nr)) {
			Err("invalid PFN %lu\n", nr);
			memset(scratch + blk_in_chunk * PAGE_SIZE, 0, PAGE_SIZE);
			sprintf(scratch + blk_in_chunk * PAGE_SIZE,
				"Unmapped page. PFN %lu\n", nr);
			/* pretend the page was dumpable */
			if ((ret = set_bitmap(dump_part, 1)) < 0) {
				Err("bitmap error %d on block %lu", ret, nr);
				break;
			}
			goto write;
		}

		dumpable = page_is_dumpable(nr);
		if ((ret = set_bitmap(dump_part, dumpable)) < 0) {
			Err("bitmap error %d on block %lu", ret, nr);
			break;
		}
		if (!dumpable) {
			blocks_skipped++;
			continue;
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
		if (compress) {
			size = diskdump_compress_write(dump_part, &offset,
						       &blocks, page);
			if (size < 0) {
				ret = size;
				Err("compress error pfn=%lu: %d", nr, ret);
				break;
			}
		} else {
			blk_in_chunk++;
			blocks++;

			if (blk_in_chunk >= (1 << block_order)) {
				ret = write_blocks(dump_part, offset, scratch,
						   blk_in_chunk);
				if (ret < 0) {
					Err("I/O error %d on block %u",
					    ret, offset);
					break;
				}
				offset += blk_in_chunk;
				dump_header.written_blocks += blk_in_chunk;
				blk_in_chunk = 0;
				if (dump_bitmap.flushed) {
					/* Execute update_header() immediately
					 * after write_blocks() not to destroy
					 * scratch.
					 */
					dump_bitmap.flushed = 0;
					rewrite_header = 1;
				}
			}
		}

		if (rewrite_header && (ret = update_header(dump_part)) < 0) {
			Err("updating header failed. error %d", ret);
			goto out;
		}

		blocks_uncompressed++;
	}
	if (ret >= 0) {
		if (compress)
			ret = diskdump_compress_flush(dump_part, offset,
						      &blocks);
		else if (blk_in_chunk > 0) {
			ret = write_blocks(dump_part, offset, scratch,
				blk_in_chunk);
			if (ret < 0)
				Err("I/O error %d on block %u", ret, offset);
			dump_header.written_blocks += blk_in_chunk;
		}
	}

out:
	print_last_status(blocks, blocks_skipped, blocks_written_expected,
			  blocks_uncompressed);
	/*
	 * bitmap.byte or bitmap.bit must not be 0 if dump_level != 0.
	 */
	if (ret >= 0 && (dump_bitmap.byte || dump_bitmap.bit))
		ret = flush_bitmap(dump_part);

	if (ret >= 0 && !strict_size_check()) {
		/* If ret >= 0, blocks must not be 0. */
		ret = short_area;
	}
	return ret;
}

/*
 * Select suitable dump device. sanity_check() returns the state
 * of each dump device. 0 means OK, negative value means NG, and
 * positive value means it maybe work. select_dump_partition() first
 * try to select a sane device and if it has no sane device and
 * allow_risky_dumps is set, it select one from maybe OK devices.
 *
 */
static struct disk_dump_partition *select_dump_partition(struct disk_dump_partition *prev_dump_part)
{
	struct disk_dump_device *dump_device;
	struct disk_dump_partition *dump_part;
	int sanity;
	struct list_head *head, *list;
	int strict_check = 1;

	if (prev_dump_part == NULL)
		head = &disk_dump_partitions;
	else
		head = &prev_dump_part->part_list;
redo:
	/*
	 * Select a sane polling driver.
	 */
	list_for_each(list, head) {
		sanity = 0;
		if (list == &disk_dump_partitions)
			break;
		dump_part = container_of(list, struct disk_dump_partition, part_list);
		dump_device = dump_part->device;
		if (dump_device->ops.sanity_check)
			sanity = dump_device->ops.sanity_check(dump_device);
		if (sanity < 0 || (sanity > 0 && strict_check))
			continue;

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

	dump_smp_call_function(freeze_cpu, NULL);
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
		dump_err = -EIO;
		goto done;
	}

	if (!check_crc_module()) {
		Err("checksum error. diskdump common module may be compromised.");
		dump_err = -EIO;
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
	unsigned int max_written_blocks;
	struct disk_dump_device *dump_device = NULL;
	struct disk_dump_partition *dump_part = NULL;
	int ret, short_area;
	char name[BDEVNAME_SIZE];

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

	/*
	 * The common header
	 */
	memcpy(dump_header.signature, DISK_DUMP_SIGNATURE,
	       sizeof(dump_header.signature));
	dump_header.utsname	     = system_utsname;
	dump_header.timestamp	     = xtime;
	dump_header.block_size	     = PAGE_SIZE;
	dump_header.sub_hdr_size     = size_of_sub_header();
	dump_header.max_mapnr	     = max_pfn;
	dump_header.total_ram_blocks = total_ram_blocks;
	dump_header.current_cpu	     = smp_processor_id();
	dump_header.nr_cpus	     = num_online_cpus();

	platform_fix_regs();

	if ((dump_level & DUMP_EXCLUDE_FREE) && diskdump_mark_free_pages() < 0)
		/*
		 * The free page list is broken.
		 * Free pages will be dumped.
		 */
		free_list_is_valid = 0;

	/* Prepare for compression */
	if ((compress_buffer == NULL) || (deflate_workspace == NULL))
		compress = 0;

	/* partial dump requires an extra bitmap */
	if (!strict_size_check())
		bitmap_blocks <<= 1;


retry:
	short_area = 0;
	dump_bitmap.bit     = 0;
	dump_bitmap.byte    = 0;
	dump_bitmap.flushed = 0;
	rewrite_header = 0;

	if (!(dump_part = select_dump_partition(dump_part))) {
		Err("No more dump device found");
		diskdump_shutdown();
		return;
	}

	dump_device = dump_part->device;
	dump_device->need_shutdown = 1;

	printk("start dumping to %s\n", bdevname(dump_part->bdev, name));

	/*
	 * Stop ongoing I/O with polling driver and make the shift to I/O mode
	 * for dump
	 */
	Dbg("do quiesce");
	if (dump_device->quiesce_done) {
		if (dump_device->quiesce_result < 0)
			goto retry;
	} else if (dump_device->ops.quiesce) {
		dump_device->quiesce_done = 1;
		ret = dump_device->ops.quiesce(dump_device);
		dump_device->quiesce_result = ret;
		if (ret< 0) {
			Err("quiesce failed. error %d", ret);
			goto retry;
		}
	}

	if (compress)
		curr_buf = dump_buf = compress_buffer;

	if (SECTOR_BLOCK(dump_part->nr_sects) < header_blocks + bitmap_blocks) {
		Warn("dump partition is too small. Aborted");
		goto retry;
	}

	/* Check dump partition */
	printk("check dump partition...\n");
	if (!check_swap_partition(dump_part, total_blocks) &&
	    !check_dump_partition(dump_part, total_blocks)) {
		Err("check partition failed.");
		goto retry;
	}

	/*
	 * Write the common header
	 */
	dump_header.status	     = DUMP_HEADER_INCOMPLETED;
	if (compress)
		dump_header.status   |= DUMP_HEADER_COMPRESSED;
	dump_header.bitmap_blocks    = bitmap_blocks;
	dump_header.device_blocks    = SECTOR_BLOCK(dump_part->nr_sects);
	dump_header.written_blocks   = 2;

	if ((ret = write_header(dump_part)) < 0) {
		Err("writing header failed. error %d", ret);
		goto retry;
	}

	/*
	 * Write the architecture dependent header
	 */
	Dbg("write sub header");
	if ((ret = write_sub_header()) < 0) {
		Err("writing sub header failed. error %d", ret);
		goto retry;
	}

	Dbg("writing memory bitmaps..");
	if ((ret = write_bitmap(dump_part, header_blocks, ram_bitmap_blocks)) < 0)
		goto retry;

	max_written_blocks = total_ram_blocks;
	if (strict_size_check() && dump_header.device_blocks < total_blocks) {
		Warn("dump partition is too small. actual blocks %u. expected blocks %u. whole memory will not be saved",
				dump_header.device_blocks, total_blocks);
		max_written_blocks -= (total_blocks - dump_header.device_blocks);
		short_area = 1;
	}

	/* Set start block of the second bitmap */
	dump_bitmap.index = header_blocks + ram_bitmap_blocks;

	dump_header.written_blocks += dump_header.sub_hdr_size;
	dump_header.written_blocks += dump_header.bitmap_blocks;
	if ((ret = write_header(dump_part)) < 0) {
		Err("writing header failed. error %d", ret);
		goto retry;
	}

	printk("dumping memory");
	if (dump_level)
		printk("(partial dump with dump_level %d)", dump_level);
	printk("..\n");
	ret = write_memory(dump_part, header_blocks + bitmap_blocks,
			   max_written_blocks,
			   dump_header.device_blocks - dump_header.written_blocks);

	/*
	 * Set the number of block that is written into and write it
	 * into partition again.
	 */
	if (ret < 0) {
		Err("writing memory failed. error %d", ret);
		goto retry;
	}

	if (!strict_size_check()) { /* ret = 0 or 1. */
		if (!ret)
			dump_header.status = DUMP_HEADER_COMPLETED;
		else
			dump_header.status = DUMP_HEADER_SHORT_AREA;
	} else { /* ret = 0. */
		if (!short_area)
			dump_header.status = DUMP_HEADER_COMPLETED;
		else
			dump_header.status = DUMP_HEADER_INCOMPLETED;
	}
	if (compress)
		dump_header.status |= DUMP_HEADER_COMPRESSED;
	if ((ret = write_header(dump_part)) < 0) {
		Err("writing header failed. error %d", ret);
		goto retry;
	}

	dump_err = 0;

	diskdump_shutdown();
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
		if (device == dump_device->device)
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

	if (strict_size_check() &&
	    SECTOR_BLOCK(dump_part->nr_sects) < total_blocks)
		Warn("%s is too small to save whole system memory\n",
			bdevname(bdev, buffer));

	list_add_tail(&dump_part->list, &dump_device->partitions);
	list_add_tail(&dump_part->part_list, &disk_dump_partitions);

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

		/* If the device has limitations of transfer size, print warning. */
		if (dump_device->max_blocks < (1 << block_order))
			Warn("I/O size exceeds the maximum block size of SCSI device. Signature check may fail");

		if (!try_module_get(dump_type->owner)) {
			kfree(dump_device);
			blkdev_put(bdev);
			return -EINVAL;
		}
		list_add_tail(&dump_device->list, &disk_dump_devices);
	}

	ret = add_dump_partition(dump_device, bdev);
	if (ret < 0 && list_empty(&dump_device->partitions)) {
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
	list_del(&dump_part->part_list);
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
	struct disk_dump_partition *dump_part;

	list_for_each_entry(dump_part, &disk_dump_partitions, part_list) {
		seq->private = dump_part;
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
	struct disk_dump_partition *partition = v;

	(*pos)++;
	if (v == (void *)1)
		return dump_part_by_pos(seq, 0);

	if (partition->part_list.next == &disk_dump_partitions)
		return NULL;
	else
		return NEXT_PART(partition);
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
		seq_printf(seq, "# dump_level: %d\n", dump_level);
		seq_printf(seq, "# compress: %d\n", compress);
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
	list_for_each_entry(dump_type, &disk_dump_types, list)
		if (dump_type->compute_cksum)
			dump_type->compute_cksum();
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

	ram_bitmap_blocks = ROUNDUP(max_pfn, 8 * PAGE_SIZE);
	bitmap_blocks = ram_bitmap_blocks;

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

/*
 * Compress a DUMP_PAGE_SIZE page using gzip-style algorithms (the
 * deflate functions similar to what's used in PPP).
 */
static u32
diskdump_compress_gzip(const u8 *old, u32 oldsize, u8 *new, u32 newsize)
{
	int err;
	z_stream dump_stream;

	dump_stream.workspace = deflate_workspace;
	if ((err = zlib_deflateInit(&dump_stream, Z_BEST_SPEED)) != Z_OK) {
		Err("zlib_deflateInit() failed (%d)!", err);
		return 0;
	}

	if (oldsize > DUMP_PAGE_SIZE) {
		Err("oversize input: %d", oldsize);
		return 0;
	}

	dump_stream.next_in   = (u8 *)old;
	dump_stream.avail_in  = oldsize;
	dump_stream.next_out  = new;
	dump_stream.avail_out = newsize;

	/* deflate the page -- check for error */
	err = zlib_deflate(&dump_stream, Z_FINISH);
	if (err != Z_STREAM_END) {
		/* zero is return code here */
		zlib_deflateEnd(&dump_stream);
		Err("zlib_deflate() failed (%d)!", err);
		return 0;
	}

	/* let's end the deflated compression stream */
	if ((err = zlib_deflateEnd(&dump_stream)) != Z_OK)
		Err("zlib_deflateEnd() failed (%d)!\n", err);

	/* return the compressed byte total (if it's smaller) */
	if (dump_stream.total_out >= oldsize)
		return oldsize;

	return dump_stream.total_out;
}

/* 
 * Base compression function that saves the selected block of data in the dump 
 */
static int diskdump_compress_page(char *addr, struct page *page)
{
	void *buf = curr_buf;
	struct dump_page dp;
	int bytes;
	u32 size;
	int len = PAGE_SIZE;

	/* It must not occur. */
	if (buf >= dump_buf + DUMP_BUFFER_SIZE)
		return -1;

	memset(&dp, 0, sizeof(dp));
	dp.page_flags = page->flags;
	buf += sizeof(dp);

	if (PageAnon(page))
		dp.flags |= DUMP_DH_MAPPING_ANON;

	size = bytes = len;
	/* check for compression */
	size = diskdump_compress_gzip(addr, bytes, buf, DUMP_DPC_PAGE_SIZE);

	/* set the compressed flag if the page did compress */
	if (size && size < bytes) {
		dp.flags |= DUMP_DH_COMPRESSED;
	} else {
		/* compression failed -- default to raw mode */
		memcpy(buf, addr, bytes);
		size = bytes;
	}
	dp.size = size;
	memcpy(curr_buf, &dp, sizeof(dp));
	curr_buf = buf + size;

	return curr_buf - dump_buf;
}

/*
 * return >= 0 : continue
 *        < 0  : error
 */
static int diskdump_compress_write(struct disk_dump_partition *dump_part,
				   int *offset, unsigned int *blocks,
				   struct page *page)
{
	int ret, size, remain;

	if ((size = diskdump_compress_page(scratch, page)) < 0) {
		Err("compression fatal error");
		return -1;
	}

	if (size < DUMP_BUFFER_SIZE)
		return size;

	ret = write_blocks(dump_part, *offset, dump_buf, NR_BUFFER_PAGES);
	remain = size - DUMP_BUFFER_SIZE;
	if (ret < 0) {
		Err("I/O error %d on block %u", ret, *offset);
		return ret;
	}
	*offset += NR_BUFFER_PAGES;
	*blocks += NR_BUFFER_PAGES;
	dump_header.written_blocks += NR_BUFFER_PAGES;
	if (dump_bitmap.flushed) {
		rewrite_header = 1;
		dump_bitmap.flushed = 0;
	}

	if (remain)
		memcpy(dump_buf, dump_buf + DUMP_BUFFER_SIZE, remain);

	curr_buf = dump_buf + remain;
	return remain;
}

static int diskdump_compress_flush(struct disk_dump_partition *dump_part,
				   int offset, unsigned int *blocks)
{
	int len, ret;
	int size = curr_buf - dump_buf;

	len = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
	memset(curr_buf, 'm', len - size);

	ret = write_blocks(dump_part, offset, dump_buf, len >> PAGE_SHIFT);
	if (ret < 0) {
		Err("I/O error %d on block %u", ret, offset);
		return -1;
	}
	dump_header.written_blocks += len >> PAGE_SHIFT;
	*blocks += len >> PAGE_SHIFT;
	return 0;
}

/* Initialize compression mechanism */
static void diskdump_compress_init(void)
{
	struct page *page;

	if (!compress)
		return;

	if (block_order > 2)
		compress_block_order = block_order;
	else
		compress_block_order = 2;

	/* Allocate compress buffer */
	do {
		page = alloc_pages(GFP_KERNEL, compress_block_order);
		if (page != NULL)
			break;
	} while (--compress_block_order >= 2);

	if (page == NULL) {
		Err("Faild to alloc dump buffer");
		compress = 0;
		return;
	}
	compress_buffer = page_address(page);

	deflate_workspace = vmalloc(zlib_deflate_workspacesize());
	if (deflate_workspace == NULL) {
		Err("Failed to alloc %d bytes for deflate workspace",
			zlib_deflate_workspacesize());
		free_pages((unsigned long)compress_buffer,
		           compress_block_order);
		compress = 0;
		return;
	}

	return;
}

/* Clean compression mechanism */
static void diskdump_compress_cleanup(void)
{
	if (compress_buffer) {
		free_pages((unsigned long)compress_buffer,
		           compress_block_order);
		compress_buffer = NULL;
	}

	if (deflate_workspace) {
		vfree(deflate_workspace);
		deflate_workspace = NULL;
	}
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

	/* Allocate one page that is used as bitmap */
	if (!(page = alloc_pages(GFP_KERNEL, 0))) {
		Err("alloc_pages failed.");
		free_pages((unsigned long)scratch, block_order);
		return -1;
	}
	dump_bitmap.map = page_address(page);
	memset(dump_bitmap.map, 0, PAGE_SIZE);

	if (diskdump_register_hook(start_disk_dump)) {
		Err("failed to register hooks.");
		free_pages((unsigned long)scratch, block_order);
		free_pages((unsigned long)dump_bitmap.map, 0);
		return -1;
	}

	if (diskdump_register_ops(&dump_ops)) {
		Err("failed to register ops.");
		free_pages((unsigned long)scratch, block_order);
		free_pages((unsigned long)dump_bitmap.map, 0);
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
	diskdump_compress_init();

	return 0;
}

static void cleanup_diskdump(void)
{
	Info("shut down.");
	diskdump_unregister_hook();
	diskdump_unregister_ops();
	platform_cleanup_stack(diskdump_stack);
	free_pages((unsigned long)scratch, block_order);
	free_pages((unsigned long)dump_bitmap.map, 0);
#ifdef CONFIG_PROC_FS
	remove_proc_entry("diskdump", NULL);
#endif
	diskdump_compress_cleanup();
}

module_init(init_diskdump);
module_exit(cleanup_diskdump);

MODULE_LICENSE("GPL");

#ifndef _LINUX_DISKDUMP_H
#define _LINUX_DISKDUMP_H

/*
 * linux/include/linux/diskdump.h
 *
 * Copyright (c) 2004 FUJITSU LIMITED
 *
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

#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/utsname.h>
#include <linux/device.h>
#include <linux/nmi.h>
#include <linux/version.h>

/* The minimum Dump I/O unit. Must be the same of PAGE_SIZE */
#define DUMP_BLOCK_SIZE		PAGE_SIZE
#define DUMP_BLOCK_SHIFT	PAGE_SHIFT

int diskdump_register_hook(void (*dump_func)(struct pt_regs *));
void diskdump_unregister_hook(void);
int diskdump_mark_free_pages(void);

/*
 * The handler of diskdump module
 */
struct disk_dump_ops {
	int (*add_dump)(struct device *, struct block_device *);
	int (*remove_dump)(struct block_device *);
	int (*find_dump)(struct block_device *);
};

int diskdump_register_ops(struct disk_dump_ops* op);
void diskdump_unregister_ops(void);


/*
 * The handler that adapter driver provides for the common module of
 * dump
 */
struct disk_dump_partition;
struct disk_dump_device;

struct disk_dump_type {
	void *(*probe)(struct device *);
	int (*add_device)(struct disk_dump_device *);
	void (*remove_device)(struct disk_dump_device *);
	void (*compute_cksum)(void);
	struct module *owner;
	struct list_head list;
};

struct disk_dump_device_ops {
	int (*sanity_check)(struct disk_dump_device *);
	int (*quiesce)(struct disk_dump_device *);
	int (*shutdown)(struct disk_dump_device *);
	int (*rw_block)(struct disk_dump_partition *, int rw, unsigned long block_nr, void *buf, int len);
};

/* The data structure for a dump device */
struct disk_dump_device {
	struct list_head list;
	struct disk_dump_device_ops ops;
	struct disk_dump_type *dump_type;
	void *device;
	unsigned int max_blocks;
	struct list_head partitions;
	int	quiesce_result;
	int	quiesce_done		: 1;
	int	need_shutdown		: 1;
};

/* The data structure for a dump partition */
struct disk_dump_partition {
	struct list_head list;
	struct list_head part_list;
	struct disk_dump_device *device;
	struct block_device *bdev;
	unsigned long start_sect;
	unsigned long nr_sects;
};

/* bitmap structure */
struct disk_dump_bitmap {
	char *map;
	int bit;	/* next bit offset to set the bitmap buffer */
	int byte;	/* next byte offset to set the bitmap buffer */
	int flushed;
	unsigned int index;	/* next block to write bitmap */
};

int register_disk_dump_type(struct disk_dump_type *);
int unregister_disk_dump_type(struct disk_dump_type *);


/*
 * sysfs interface
 */
ssize_t diskdump_sysfs_store(struct device *dev, const char *buf, size_t count);
ssize_t diskdump_sysfs_show(struct device *dev, char *buf);
ssize_t diskdump_sysfs_store_disk(struct gendisk *disk, struct device *dev, const char *buf, size_t count);
ssize_t diskdump_sysfs_show_disk(struct gendisk *disk, char *buf);


void diskdump_update(void);
void diskdump_setup_timestamp(void);

/* mdelay() is trapped by WARN_ON if we are in the interrupt context. */
#define diskdump_mdelay(n) 						\
({									\
	unsigned long __ms=(n); 					\
 	if (crashdump_mode())					\
		while (__ms--) {					\
			udelay(1000);					\
			touch_nmi_watchdog();				\
		}							\
 	else								\
 		mdelay(n);						\
})

#define diskdump_msleep(n) 						\
({									\
	unsigned long __ms=(n); 					\
 	if (crashdump_mode())						\
		while (__ms--) {					\
			udelay(1000);					\
			touch_nmi_watchdog();				\
		}							\
 	else								\
 		msleep(n);						\
})

#define spin_unlock_irq_dump(host_lock)					\
	do { 								\
		if (crashdump_mode())					\
			spin_unlock(host_lock);				\
		else							\
			spin_unlock_irq(host_lock);			\
	} while (0)

/*
 * Architecture-independent dump header
 */

/* The signature which is written in each block in the dump partition */
#define DISK_DUMP_SIGNATURE		"DISKDUMP"
#define DISK_DUMP_HEADER_VERSION	1

#define DUMP_PARTITION_SIGNATURE	"diskdump"

#define DUMP_HEADER_COMPLETED	0	/* Dump has completed */
#define DUMP_HEADER_INCOMPLETED	1	/* Dump has started */
#define DUMP_HEADER_IN_PROGRESS	2	/* It has been dumped more than at
					least one block from the main memory. */
#define DUMP_HEADER_SHORT_AREA	4	/* Dump ended because the area was
					   short. */
#define DUMP_HEADER_COMPRESSED	8	/* Dump is compressed */

struct disk_dump_header {
	char			signature[8];	/* = "DISKDUMP" */
	int			header_version;	/* Dump header version */
	struct new_utsname	utsname;	/* copy of system_utsname */
	struct timespec		timestamp;	/* Time stamp */
	unsigned int		status;		/* Above flags */
	int			block_size;	/* Size of a block in byte */
	int			sub_hdr_size;	/* Size of arch dependent
						   header in blocks */
	unsigned int		bitmap_blocks;	/* Size of Memory bitmap in
						   block */
	unsigned int		max_mapnr;	/* = max_mapnr */
	unsigned int		total_ram_blocks;/* Size of Memory in block */
	unsigned int		device_blocks;	/* Number of total blocks in
						 * the dump device */
	unsigned int		written_blocks;	/* Number of written blocks */
	unsigned int		current_cpu;	/* CPU# which handles dump */
	int			nr_cpus;	/* Number of CPUs */
	struct task_struct	*tasks[NR_CPUS];
};

/* Diskdump state */
extern enum disk_dump_states {
	DISK_DUMP_INITIAL,
	DISK_DUMP_RUNNING,
	DISK_DUMP_SUCCESS,
	DISK_DUMP_FAILURE,
}  disk_dump_state;

/*
 * Calculate the check sum of the whole module
 */
#define get_crc_module()						\
({									\
	struct module *module = &__this_module;				\
	crc32_le(0, (char *)(module->module_core),			\
	  ((unsigned long)module - (unsigned long)(module->module_core))); \
})

/* Calculate the checksum of the whole module */
#define set_crc_modules()						\
({									\
	module_crc = 0;							\
	module_crc = get_crc_module();					\
})

/*
 * Compare the checksum value that is stored in module_crc to the check
 * sum of current whole module. Must be called with holding disk_dump_lock.
 * Return TRUE if they are the same, else return FALSE
 *
 */
#define check_crc_module()						\
({									\
	uint32_t orig_crc, cur_crc;					\
									\
	orig_crc = module_crc; module_crc = 0;				\
	cur_crc = get_crc_module();					\
	module_crc = orig_crc;						\
	orig_crc == cur_crc;						\
})


/* Dump Level */
#define DUMP_EXCLUDE_CACHE 0x00000001	/* Exclude LRU & SwapCache pages*/
#define DUMP_EXCLUDE_CLEAN 0x00000002	/* Exclude all-zero pages */
#define DUMP_EXCLUDE_FREE  0x00000004	/* Exclude free pages */
#define DUMP_EXCLUDE_ANON  0x00000008	/* Exclude Anon pages */
#define DUMP_SAVE_PRIVATE  0x00000010	/* Save private pages */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
#define	PG_nosave_free		19	/* Free page not to be dumped */
#define PageNosaveFree(page)		test_bit(PG_nosave_free, &(page)->flags)
#define SetPageNosaveFree(page)		set_bit(PG_nosave_free, &(page)->flags)
#define TestSetPageNosaveFree(page)	test_and_set_bit(PG_nosave_free, &(page)->flags)
#define ClearPageNosaveFree(page)	clear_bit(PG_nosave_free, &(page)->flags)
#define TestClearPageNosaveFree(page)	test_and_clear_bit(PG_nosave_free, &(page)->flags)
#endif

/*
 * definition for compressin
 */
#define DUMP_PAGE_SIZE      PAGE_SIZE
#define DUMP_BUFFER_SIZE    (((1 << compress_block_order) - 2) << PAGE_SHIFT)
#define NR_BUFFER_PAGES     (DUMP_BUFFER_SIZE >> PAGE_SHIFT)

/* page size for gzip compression */
#define DUMP_DPC_PAGE_SIZE	(DUMP_PAGE_SIZE + 512)

/* dump page header flags */
#define DUMP_DH_COMPRESSED	0x1	/* page is compressed */
#define DUMP_DH_MAPPING_ANON	0x2	/* page is mapped as anonymous */

/* header associated to each physical page of memory */
struct dump_page {
	unsigned long long	page_flags;	/* the page flags */
	unsigned int		size;		/* the size */
	unsigned int		flags;		/* the dump flags */
};

#define strict_size_check()	(!dump_level && !compress)

#endif /* _LINUX_DISKDUMP_H */

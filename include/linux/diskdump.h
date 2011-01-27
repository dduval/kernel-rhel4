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

/* The minimum Dump I/O unit. Must be the same of PAGE_SIZE */
#define DUMP_BLOCK_SIZE		PAGE_SIZE
#define DUMP_BLOCK_SHIFT	PAGE_SHIFT

int diskdump_register_hook(void (*dump_func)(struct pt_regs *));
void diskdump_unregister_hook(void);

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
};

/* The data structure for a dump partition */
struct disk_dump_partition {
	struct list_head list;
	struct disk_dump_device *device;
	struct block_device *bdev;
	unsigned long start_sect;
	unsigned long nr_sects;
};

int register_disk_dump_type(struct disk_dump_type *);
int unregister_disk_dump_type(struct disk_dump_type *);


/*
 * sysfs interface
 */
ssize_t diskdump_sysfs_store(struct device *dev, const char *buf, size_t count);
ssize_t diskdump_sysfs_show(struct device *dev, char *buf);


void diskdump_update(void);
void diskdump_setup_timestamp(void);

/* mdelay() is trapped by WARN_ON if we are in the interrupt context. */
#define diskdump_mdelay(n) 						\
({									\
	unsigned long __ms=(n); 					\
	while (__ms--) {						\
		udelay(1000);						\
		touch_nmi_watchdog();					\
	}								\
})


/*
 * Architecture-independent dump header
 */

/* The signature which is written in each block in the dump partition */
#define DISK_DUMP_SIGNATURE		"DISKDUMP"
#define DISK_DUMP_HEADER_VERSION	1

#define DUMP_PARTITION_SIGNATURE	"diskdump"

#define DUMP_HEADER_COMPLETED	0
#define DUMP_HEADER_INCOMPLETED	1

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


#endif /* _LINUX_DISKDUMP_H */

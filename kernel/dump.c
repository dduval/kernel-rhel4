/*
 *  linux/kernel/dump.c
 *
 *  Copyright (C) 2004  FUJITSU LIMITED
 *  Written by Nobuhiro Tachino (ntachino@jp.fujitsu.com)
 *
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

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/nmi.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/genhd.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/diskdump.h>
#include <asm/diskdump.h>
#include <asm/crashdump.h>
#include "../fs/sysfs/sysfs.h"

static DECLARE_MUTEX(dump_ops_mutex);
struct disk_dump_ops* dump_ops = NULL;

int diskdump_mode = 0;
EXPORT_SYMBOL_GPL(diskdump_mode);

void (*diskdump_func) (struct pt_regs *regs) = NULL;
EXPORT_SYMBOL_GPL(diskdump_func);

static unsigned long long timestamp_base;
static unsigned long timestamp_hz;


/*
 * register/unregister diskdump operations
 */
int diskdump_register_ops(struct disk_dump_ops* op)
{
	down(&dump_ops_mutex);
	if (dump_ops) {
		up(&dump_ops_mutex);
		return -EEXIST;
	}
	dump_ops = op;
	up(&dump_ops_mutex);

	return 0;
}

EXPORT_SYMBOL_GPL(diskdump_register_ops);

void diskdump_unregister_ops(void)
{
	down(&dump_ops_mutex);
	dump_ops = NULL;
	up(&dump_ops_mutex);
}

EXPORT_SYMBOL_GPL(diskdump_unregister_ops);


/*
 * sysfs interface
 */
static struct gendisk *device_to_gendisk(struct device *dev)
{
	struct nameidata nd;
	struct sysfs_dirent *sd;
	struct kobject *kobj;
	int rc;

	/* trace symlink to "block" */
	nd.mnt = mntget(sysfs_mount);
	nd.dentry = dget(dev->kobj.dentry);
	nd.flags = LOOKUP_FOLLOW;
	nd.last_type = LAST_ROOT;
	nd.depth = 0;
	rc = link_path_walk("block", &nd);
	if (rc < 0) {
		if (rc == -ENOENT)
			return NULL;
		goto err;
	}
	sd = nd.dentry->d_fsdata;
	kobj = sd ? kobject_get(sd->s_element) : NULL;
	path_release(&nd);
	if (!kobj)
		goto err;
	return container_of(kobj, struct gendisk, kobj);

err:
	printk(KERN_WARNING "dump: device has no block attribute\n");
	return NULL;
}

ssize_t diskdump_sysfs_store(struct device *dev, const char *buf, size_t count)
{
	struct gendisk *disk;

	/* early cutoff */
	if (!dump_ops || !dump_ops->add_dump || !dump_ops->remove_dump)
		return count;

	/* get disk */
	disk = device_to_gendisk(dev);

	if (disk) {
		count = diskdump_sysfs_store_disk(disk, dev, buf, count);
		put_disk(disk);
	}

	return count;
}

EXPORT_SYMBOL_GPL(diskdump_sysfs_store);

ssize_t diskdump_sysfs_store_disk(struct gendisk *disk, struct device *dev, const char *buf, size_t count)
{
	struct block_device *bdev;
	int part, remove = 0;

	if (!dump_ops || !dump_ops->add_dump || !dump_ops->remove_dump)
		return count;

	/* get partition number */
	if (sscanf (buf, "%d\n", &part) != 1)
		return -EINVAL;

	if (part < 0) {
		part = -part;
		remove = 1;
	}

	if (part >= disk->minors)
		return -EINVAL;

	/* get block device */
	if (!(bdev = bdget_disk(disk, part)))
		return count;

	/* add/remove device */
	down(&dump_ops_mutex);
	if (!remove)
		dump_ops->add_dump(dev, bdev);
	else
		dump_ops->remove_dump(bdev);
	up(&dump_ops_mutex);

	return count;
}

EXPORT_SYMBOL_GPL(diskdump_sysfs_store_disk);

ssize_t diskdump_sysfs_show(struct device *dev, char *buf)
{
	struct gendisk *disk;
	ssize_t len;

	/* early cutoff */
	if (!dump_ops || !dump_ops->find_dump)
		return 0;

	/* get gendisk */
	disk = device_to_gendisk(dev);
	if (!disk)
		return 0;

	len = diskdump_sysfs_show_disk(disk, buf);

	put_disk(disk);

	return len;
}

EXPORT_SYMBOL_GPL(diskdump_sysfs_show);

ssize_t diskdump_sysfs_show_disk(struct gendisk *disk, char *buf)
{
	struct block_device *bdev;
	int part, tmp, len = 0, maxlen = 1024;
	char* p = buf; 
	char name[BDEVNAME_SIZE];

	if (!dump_ops || !dump_ops->find_dump)
		return 0;

	if (!disk->part)
		return 0;

	/* print device */
	down(&dump_ops_mutex);
	for (part = 0; part < disk->minors - 1; part++) {
		bdev = bdget_disk(disk, part);
		if (dump_ops->find_dump(bdev)) {
			tmp = sprintf(p, "%s\n", bdevname(bdev, name));
			len += tmp;
			p += tmp;
		}
		bdput(bdev);
		if(len >= maxlen)
			break;
	}
	up(&dump_ops_mutex);

	return len;
}

EXPORT_SYMBOL_GPL(diskdump_sysfs_show_disk);

/*
 * run timer/tasklet/workqueue during dump
 */
void diskdump_setup_timestamp(void)
{
	unsigned long long t;

	platform_timestamp(timestamp_base);
	udelay(1000000/HZ);
	platform_timestamp(t);
	timestamp_hz = (unsigned long)(t - timestamp_base);
	diskdump_update();
}

EXPORT_SYMBOL_GPL(diskdump_setup_timestamp);

void diskdump_update(void)
{
	unsigned long long t;

	touch_nmi_watchdog();

	/* update jiffies */
	platform_timestamp(t);
	while (t > timestamp_base + timestamp_hz) {
		timestamp_base += timestamp_hz;
		jiffies++;
		platform_timestamp(t);
	}

	dump_run_timers();
	dump_run_tasklet();
	dump_run_workqueue();
}

EXPORT_SYMBOL_GPL(diskdump_update);


/*
 * register/unregister hook
 */
int diskdump_register_hook(void (*dump_func) (struct pt_regs *))
{
	if (diskdump_func)
		return -EEXIST;

	diskdump_func = dump_func;

	return 0;
}

EXPORT_SYMBOL_GPL(diskdump_register_hook);

void diskdump_unregister_hook(void)
{
	diskdump_func = NULL;
}

EXPORT_SYMBOL_GPL(diskdump_unregister_hook);

void (*netdump_func) (struct pt_regs *regs) = NULL;
int netdump_mode = 0;
EXPORT_SYMBOL_GPL(netdump_mode);

/*
 * Try crashdump. Diskdump is first, netdump is second.
 * We clear diskdump_func before call of diskdump_func, so
 * If double panic would occur in diskdump, netdump can handle
 * it.
 */
void try_crashdump(struct pt_regs *regs)
{
	void (*func)(struct pt_regs *);

	if (diskdump_func) {
		system_state = SYSTEM_DUMPING;
		func = diskdump_func;
		diskdump_func = NULL;
		func(regs);
	}
	if (netdump_func)
		netdump_func(regs);
}

extern unsigned long max_pfn;

int diskdump_mark_free_pages(void)
{
	struct zone *zone;
	unsigned long start_pfn, err_pfn, i, pfn;
	int order, free_page_cnt = 0;
	struct list_head *curr, *previous, *dlhead;

	/*
	 * This is not necessary if PG_nosave_free is cleared
	 * while allocating new pages.
	 */
	for (pfn = next_ram_page(ULONG_MAX); pfn < max_pfn; pfn = next_ram_page(pfn))
		if (pfn_valid(pfn))
			ClearPageNosaveFree(pfn_to_page(pfn));

	for_each_zone(zone) {
		if (!zone->spanned_pages)
			continue;

		for (order = MAX_ORDER - 1; order >= 0; --order) {
			/*
			 * Emulate a list_for_each.
			 */
			dlhead = &zone->free_area[order].free_list;

			for (previous = dlhead, curr = dlhead->next;
			     curr != dlhead;
			     previous=curr, curr = curr->next) {

				start_pfn = page_to_pfn(
					list_entry(curr, struct page, lru));

				if (!pfn_valid(start_pfn) ||
				    (previous != curr->prev)) {
					err_pfn = start_pfn;
					goto mark_err;
				}

				for (i = 0; i < (1<<order); i++) {
					pfn = start_pfn + i;
					if (!pfn_valid(pfn) ||
					    TestSetPageNosaveFree(
						  pfn_to_page(pfn))) {
						err_pfn = pfn;
						goto mark_err;
					}
				}
				free_page_cnt += i;
			}
		}
	}
	return free_page_cnt;

mark_err:
	printk(KERN_WARNING "dump: Bad page. PFN %lu.", err_pfn);
	printk(KERN_WARNING "DUMP_LEVEL will be ignored. Free pages will be dumped.");
	return -1;
}

EXPORT_SYMBOL_GPL(diskdump_mark_free_pages);

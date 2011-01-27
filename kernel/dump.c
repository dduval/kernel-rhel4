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
	struct dentry *dentry = NULL;
	struct kobject *kobj;
	int rc;

	/* trace symlink to "block" */
	nd.mnt = mntget(sysfs_mount);
	nd.dentry = dget(dev->kobj.dentry);
	nd.flags = LOOKUP_FOLLOW;
	nd.last_type = LAST_ROOT;
	nd.depth = 0;
	rc = link_path_walk("block", &nd);
	if (rc < 0)
		goto err;
	dentry = nd.dentry;
	if (!dentry)
		goto err;
	sd = dentry->d_fsdata;
	if (!sd)
		goto err;
	kobj = sd->s_element;
	if (!kobj)
		goto err;

	dput(dentry);

	return container_of(kobj, struct gendisk, kobj);
err:
	printk(KERN_WARNING "dump: device has no block attribute\n");
	dput(dentry);

	return NULL;
}

ssize_t diskdump_sysfs_store(struct device *dev, const char *buf, size_t count)
{
	struct gendisk *disk;
	struct block_device *bdev;
	int part, remove = 0;

	if (!dump_ops || !dump_ops->add_dump || !dump_ops->remove_dump)
		return count;

	/* get partition number */
	sscanf (buf, "%d\n", &part);
	if (part < 0) {
		part = -part;
		remove = 1;
	}

	/* get block device */
	if (!(disk = device_to_gendisk(dev)) ||
	    !(bdev = bdget_disk(disk, part)))
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

EXPORT_SYMBOL_GPL(diskdump_sysfs_store);

ssize_t diskdump_sysfs_show(struct device *dev, char *buf)
{
	struct gendisk *disk;
	struct block_device *bdev;
	int part, tmp, len = 0, maxlen = 1024;
	char* p = buf; 
	char name[BDEVNAME_SIZE];

	if (!dump_ops || !dump_ops->find_dump)
		return 0;

	/* get gendisk */
	disk = device_to_gendisk(dev);
	if (!disk || !disk->part)
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

EXPORT_SYMBOL_GPL(diskdump_sysfs_show);

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

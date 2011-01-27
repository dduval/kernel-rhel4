/*
 * linux/drivers/block/cciss_dump.c
 *
 * Copyright (C) 2005 Hewlett-Packard Development Company, L.P.
 * Written by Chase Maupin (chase.maupin@hp.com)
 *
 * Driver for cciss drivers  to support diskdump
 * functionality without dependening on diskdump driver.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 21 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/crc32.h>
#include <linux/diskdump.h>
#include "cciss.h"

/* Embedded module documentation macros - see modules.h */
MODULE_AUTHOR("Hewlett-Packard Company");
MODULE_DESCRIPTION("Mid-level Driver for CCISS diskdump support");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CCISS_DUMP_GLUE_MODULE
static uint32_t module_crc;
#endif

/* function prototypes */
static int block_dump_sanity_check(struct disk_dump_device *dump_device);
static int block_dump_rw_block(struct disk_dump_partition *dump_part,
			       int rw, unsigned long dump_block_nr,
			       void *buf, int len);
static int block_dump_quiesce(struct disk_dump_device *dump_device);
static int block_dump_shutdown(struct disk_dump_device *dump_device);
static void *block_dump_probe(struct device *dev);
static int block_dump_add_device(struct disk_dump_device *dump_device);
static void block_dump_remove_device(struct disk_dump_device *dump_device);
static void block_dump_compute_cksum(void);

static struct disk_dump_type block_dump_type = {
	.probe		= block_dump_probe,
	.add_device	= block_dump_add_device,
	.remove_device	= block_dump_remove_device,
	.compute_cksum	= block_dump_compute_cksum,
	.owner		= THIS_MODULE,
};

static struct disk_dump_device_ops block_dump_device_ops = {
	.sanity_check	= block_dump_sanity_check,
	.rw_block	= block_dump_rw_block,
	.quiesce	= block_dump_quiesce,
	.shutdown	= block_dump_shutdown,
};


static int block_dump_shutdown(struct disk_dump_device *dump_device)
{
	struct drv_dynamic *bsdev = dump_device->device;

	if ( bsdev->shutdown != NULL ) {
		return bsdev->shutdown(bsdev->dump_device);
	}

	return -1;
}

static int block_dump_quiesce(struct disk_dump_device *dump_device)
{
	struct drv_dynamic *bsdev = dump_device->device;

	if ( bsdev->quiesce == NULL ) {
		return -1;
	}

	bsdev->quiesce(bsdev->dump_device);

	return 0;
}

static int block_dump_rw_block(struct disk_dump_partition *dump_part,
			       int rw, unsigned long dump_block_nr, void *buf,
			       int len)
{
	struct drv_dynamic *bsdev = ((struct disk_dump_device *)
				dump_part->device)->device;

	if ( bsdev->rw_block != NULL ) {
		return bsdev->rw_block(bsdev->dump_device, rw,
			dump_block_nr, buf, len, dump_part->start_sect,
			dump_part->nr_sects);
	}

	return -1;
}

static int block_dump_sanity_check(struct disk_dump_device *dump_device)
{
	struct drv_dynamic *bsdev = dump_device->device;

#ifdef CONFIG_CCISS_DUMP_GLUE_MODULE
	static int crc_valid = 0;

	if (!crc_valid && !check_crc_module()) {
		printk(KERN_ERR "checksum error.  cciss dump module"
			" may be compromised\n");
		return -1;
	}
	crc_valid = 1;
#endif

	if ( bsdev->sanity_check != NULL ) {
		return bsdev->sanity_check(bsdev->dump_device);
	}

	return -1;
}

static void *block_dump_probe(struct device *dev)
{
	struct drv_dynamic *bsdev;

	if ((dev->driver_data == NULL) || strncmp(dev->driver_data, "cciss", 5))
		return NULL;
			
	bsdev = container_of(dev, struct drv_dynamic, dev);

#ifdef CONFIG_CCISS_DUMP_GLUE_MODULE
	set_crc_modules();
#endif

	if (bsdev->probe != NULL) {
		bsdev->dump_device = bsdev->probe(bsdev->disk);

		if (!bsdev->dump_device)
			return NULL;

		return bsdev;
	}

	return NULL;
}

static int block_dump_add_device(struct disk_dump_device *dump_device)
{
	struct drv_dynamic *bsdev = (struct drv_dynamic*)dump_device->device;

	memcpy(&dump_device->ops, &block_dump_device_ops,
	   sizeof(struct disk_dump_device_ops));

	if ( bsdev->block_add_device != NULL )
		dump_device->max_blocks = bsdev->block_add_device(bsdev->dump_device);

	return 0;
}

static void block_dump_remove_device(struct disk_dump_device *dump_device)
{
	return;
}

static void block_dump_compute_cksum(void)
{
	set_crc_modules();
}

static int __init init_block_dump_module(void)
{
	int ret;

	/* register with diskdump here. */
	if ((ret = register_disk_dump_type(&block_dump_type)) < 0 ) {
		printk(KERN_ERR "cciss_dump: Register of diskdump type"
				" failed\n");
		return ret;
	}

#ifdef CONFIG_CCISS_DUMP_GLUE_MODULE
	set_crc_modules();
#endif

	return ret;
}

static void __exit cleanup_block_dump_module(void)
{
	if (unregister_disk_dump_type(&block_dump_type) < 0 )
		printk(KERN_ERR "cciss_dump: Error unregistering diskdump"
				" type\n");
}

module_init(init_block_dump_module);
module_exit(cleanup_block_dump_module);

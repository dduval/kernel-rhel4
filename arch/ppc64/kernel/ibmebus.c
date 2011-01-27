/*
 * IBM PowerPC eBus Infrastructure Support.
 *
 *  Authors: Heiko J Schick <schickhj@de.ibm.com>
 *
 *  Copyright (c) 2005 IBM Corporation
 *
 *  All rights reserved.
 *
 *  This source code is distributed under a dual license of GPL v2.0 and OpenIB
 *  BSD.
 *
 * OpenIB BSD License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials
 * provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *  $Id: ibmebus_linux-2.6.9-42.3.RHEL.patch,v 1.1 2006/09/22 20:43:31 nguyen Exp $
 */

#include <linux/init.h>
#include <linux/console.h>
#include <linux/kobject.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include "asm-ppc64/prom.h"
#include "asm-ppc64/ibmebus.h"

#define EBUS_NAME "ebus"

static struct ibmebus_dev ebus_bus_device = { /* fake "parent" device */
	.name = ebus_bus_device.ofdev.dev.bus_id,
	.ofdev.dev.bus_id = EBUS_NAME,
	.ofdev.dev.bus = &ibmebus_bus_type,
};

void *ibmebus_alloc_coherent(struct device *dev,
			     size_t size,
			     dma64_addr_t *dma_handle,
			     gfp_t flag)
{
	void *mem;

	mem = kmalloc(size, flag);
	*dma_handle = (dma64_addr_t)mem;

	return mem;
}
EXPORT_SYMBOL(ibmebus_alloc_coherent);

void ibmebus_free_coherent(struct device *dev,
			   size_t size, void *vaddr,
			   dma64_addr_t dma_handle)
{
	kfree(vaddr);
}
EXPORT_SYMBOL(ibmebus_free_coherent);

dma64_addr_t ibmebus_map_single(struct device *dev,
				void *ptr,
				size_t size,
				enum dma_data_direction direction)
{
	return (dma64_addr_t)(ptr);
}
EXPORT_SYMBOL(ibmebus_map_single);

void ibmebus_unmap_single(struct device *dev,
			  dma64_addr_t dma_addr,
			  size_t size,
			  enum dma_data_direction direction)
{
	return;
}
EXPORT_SYMBOL(ibmebus_unmap_single);

int ibmebus_map_sg(struct device *dev,
		   struct scatterlist *sg,
		   int nents, enum dma_data_direction direction)
{
	int i;

	for (i = 0; i < nents; i++) {
		sg[i].dma_address = (dma64_addr_t)page_address(sg[i].page)
			+ sg[i].offset;
		sg[i].dma_length = sg[i].length;
	}

	return nents;
}
EXPORT_SYMBOL(ibmebus_map_sg);

void ibmebus_unmap_sg(struct device *dev,
		      struct scatterlist *sg,
		      int nents, enum dma_data_direction direction)
{
	return;
}
EXPORT_SYMBOL(ibmebus_unmap_sg);

int ibmebus_dma_supported(struct device *dev, u64 mask)
{
	return 1;
}
EXPORT_SYMBOL(ibmebus_dma_supported);

struct of_device_id *ebus_match_device(struct of_device_id *matches,
				       struct of_device *dev)
{
        if (!dev->node)
                return NULL;
        while (matches->name[0]) {
                int match = 1;
                if (matches->name[0])
                        match &= dev->node->name
                                && !strcmp(matches->name, dev->node->name);
                if (match)
                        return matches;
                matches++;
        }
        return NULL;
}

static int ebus_bus_probe(struct device *dev)
{
	struct ibmebus_dev *ebusdev    = to_ibmebus_dev(dev);
	struct ibmebus_driver *ebusdrv = to_ibmebus_driver(dev->driver);
	const struct of_device_id *id;
	int error = -ENODEV;

	if (!ebusdrv->probe)
		return error;

	id = ebus_match_device(ebusdrv->id_table, &ebusdev->ofdev);
	if (id) {
		error = ebusdrv->probe(ebusdev, id);
	}

	return error;
}

static int ebus_bus_remove(struct device *dev)
{
	struct ibmebus_dev *ebusdev    = to_ibmebus_dev(dev);
	struct ibmebus_driver *ebusdrv = to_ibmebus_driver(dev->driver);

	if (ebusdrv->remove) {
		return ebusdrv->remove(ebusdev);
	}

	return 1;
}

static void __devinit ebus_dev_release(struct device *dev)
{
	of_node_put(to_ibmebus_dev(dev)->ofdev.node);
	kfree(to_ibmebus_dev(dev));
}

static ssize_t ebusdev_show_name(struct device *dev,
				 char *buf)
{
	return sprintf(buf, "%s\n", to_ibmebus_dev(dev)->name);
}
static DEVICE_ATTR(name, S_IRUSR | S_IRGRP | S_IROTH, ebusdev_show_name, NULL);

static struct ibmebus_dev* __devinit ebus_register_main(
	struct ibmebus_dev *ebusdev, char *name)
{
	ebusdev->name = name;
	ebusdev->ofdev.dev.parent     = &ebus_bus_device.ofdev.dev;
	ebusdev->ofdev.dev.bus        = &ibmebus_bus_type;
	ebusdev->ofdev.dev.release    = ebus_dev_release;

	if (of_device_register(&ebusdev->ofdev)) {
		printk(KERN_ERR "%s: failed to register device %s\n",
		       __FUNCTION__, ebusdev->ofdev.dev.bus_id);
		return NULL;
	}

	device_create_file(&ebusdev->ofdev.dev, &dev_attr_name);

	return ebusdev;
}

struct ibmebus_dev* __devinit ebus_register_dtnode(struct device_node *dn)
{
	struct ibmebus_dev *ebusdev;
	char *loc_code;
	int length;

	loc_code = (char *)get_property(dn, "ibm,loc-code", NULL);
	if (!loc_code) {
                printk(KERN_WARNING "%s: node %s missing 'ibm,loc-code'\n",
		       __FUNCTION__, dn->name ? dn->name : "<unknown>");
		return NULL;
        }

	if (strlen(loc_code) == 0) {
	        printk(KERN_WARNING "%s: 'ibm,loc-code' is invalid\n",
		       __FUNCTION__);
		return NULL;
	}

	ebusdev = kmalloc(sizeof(struct ibmebus_dev), GFP_KERNEL);
	if (!ebusdev) {
		return NULL;
	}
	memset(ebusdev, 0, sizeof(struct ibmebus_dev));

	ebusdev->ofdev.node = of_node_get(dn);

	length = strlen(loc_code);
	strncpy(ebusdev->ofdev.dev.bus_id, loc_code
		+ length - min(length, BUS_ID_SIZE - 1),
		min(length, BUS_ID_SIZE - 1));

	/* register with generic device framework */
	if (ebus_register_main(ebusdev, dn->name) == NULL) {
		kfree(ebusdev);
		return NULL;
	}

	return ebusdev;
}
EXPORT_SYMBOL(ebus_register_dtnode);

static void probe_bus(char* name)
{
	struct device_node *dn = NULL;

	while ((dn = of_find_node_by_name(dn, name))) {
		ebus_register_dtnode(dn);
	}

	of_node_put(dn);
}

struct ebusdev_find_info
{
	struct ibmebus_dev *dev;
	const char *name;
};

static int ebus_cmp_dev(struct device *dev, void *data)
{
       struct ebusdev_find_info *info = data;
       struct device_node *dn = to_of_device(dev)->node;

       if (strcmp(dev->bus_id, EBUS_NAME) == 0)
	       return 0;

       if (strcmp(dn->name, info->name) == 0) {
	       info->dev = to_ibmebus_dev(dev);
	       return 1;
       }

       return 0;
}

struct ibmebus_dev *ebus_device_find(const char *name)
{
	struct ebusdev_find_info info = { .dev = NULL,
					  .name = name };

	bus_for_each_dev(&ibmebus_bus_type, NULL, &info, ebus_cmp_dev);

	return info.dev;
}

int ibmebus_register_driver(struct ibmebus_driver *ebusdrv)
{
	struct of_device_id *idt;
	struct ibmebus_dev *dev = NULL;

	ebusdrv->driver.name   = ebusdrv->name;
	ebusdrv->driver.bus    = &ibmebus_bus_type;
	ebusdrv->driver.probe  = ebus_bus_probe;
	ebusdrv->driver.remove = ebus_bus_remove;

	idt = ebusdrv->id_table;
	while (strlen(idt->name) > 0) {
		dev = ebus_device_find(idt->name);
		if (dev == NULL) {
			probe_bus(idt->name);
		}
		idt++;
	}

	return driver_register(&ebusdrv->driver);
}

EXPORT_SYMBOL(ibmebus_register_driver);

void ibmebus_unregister_driver(struct ibmebus_driver *ebusdrv)
{
	driver_unregister(&ebusdrv->driver);
}
EXPORT_SYMBOL(ibmebus_unregister_driver);

int ibmebus_request_irq(struct ibmebus_dev *dev,
			u32 ist,
			irqreturn_t(*handler) (int, void *,
					       struct pt_regs *),
			unsigned long irq_flags, const char *devname,
			void *dev_id)
{
	unsigned int irq = virt_irq_create_mapping(ist);
	if (irq == NO_IRQ)
		return -EINVAL;

	irq = irq_offset_up(irq);
	return request_irq(irq, handler, irq_flags, devname, dev_id);
}
EXPORT_SYMBOL(ibmebus_request_irq);

void ibmebus_free_irq(struct ibmebus_dev *dev, __u32 ist, void *dev_id)
{
	unsigned int irq = virt_irq_create_mapping(ist);

	irq = irq_offset_up(irq);
	free_irq(irq, dev_id);
	return;
}
EXPORT_SYMBOL(ibmebus_free_irq);

static int ebus_bus_match(struct device *dev, struct device_driver *drv)
{
	struct ibmebus_dev *ebus_dev    = to_ibmebus_dev(dev);
	struct ibmebus_driver *ebus_drv = to_ibmebus_driver(drv);
	struct of_device_id *ids     = ebus_drv->id_table;
	struct of_device_id *found_id;

	if (!ids)
		return 0;

	found_id = ebus_match_device(ids, &ebus_dev->ofdev);
	if (found_id)
		return 1;

	return 0;
}

struct bus_type ibmebus_bus_type = {
	.name = "ibmebus",
	.match = ebus_bus_match,
};
EXPORT_SYMBOL(ibmebus_bus_type);

static int __init ebus_bus_init(void)
{
	int err;

	printk(KERN_INFO "eBus Device Driver\n");

	err = bus_register(&ibmebus_bus_type);
	if (err) {
		printk(KERN_ERR "failed to register eBus\n");
		return err;
	}

	err = device_register(&ebus_bus_device.ofdev.dev);
	if (err) {
		printk(KERN_WARNING "%s: device_register returned %i\n",
		       __FUNCTION__, err);
		return err;
	}

	return 0;
}

static int __init ebus_init(void)
{
	return ebus_bus_init();
}

static void __exit ebus_exit(void)
{
	device_unregister(&ebus_bus_device.ofdev.dev);
	bus_unregister(&ibmebus_bus_type);

	return;
}

module_init(ebus_init);
module_exit(ebus_exit);

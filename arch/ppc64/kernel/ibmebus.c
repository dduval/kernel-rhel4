/*
 * IBM PowerPC eBus Infrastructure Support.
 *
 *  Authors:
 *    Heiko J Schick <schickhj@de.ibm.com>
 *    Joachim Fenkes <fenkes@de.ibm.com>
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

static struct device ebus_bus_device = { /* fake "parent" device */
	.bus_id = EBUS_NAME
};

struct bus_type ibmebus_bus_type;

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

static int __devinit ebus_register_main(struct ibmebus_dev *ebusdev, char *name)
{
	ebusdev->name = name;
	ebusdev->ofdev.dev.parent     = &ebus_bus_device;
	ebusdev->ofdev.dev.bus        = &ibmebus_bus_type;
	ebusdev->ofdev.dev.release    = ebus_dev_release;

	if (of_device_register(&ebusdev->ofdev)) {
		printk(KERN_ERR "%s: failed to register device %s\n",
		       __FUNCTION__, ebusdev->ofdev.dev.bus_id);
		return -ENODEV;
	}

	return 0;
}

struct ibmebus_dev* __devinit ebus_register_dtnode(struct device_node *dn)
{
	struct ibmebus_dev *ebusdev;
	int i, len, bus_len;

	ebusdev = kmalloc(sizeof(struct ibmebus_dev), GFP_KERNEL);
	if (!ebusdev) {
		return ERR_PTR(-ENOMEM);
	}
	memset(ebusdev, 0, sizeof(struct ibmebus_dev));

	ebusdev->ofdev.node = of_node_get(dn);

	len = strlen(dn->full_name + 1);
	bus_len = min(len, BUS_ID_SIZE - 1);
	memcpy(ebusdev->ofdev.dev.bus_id, dn->full_name + 1
	       + (len - bus_len), bus_len);
	for (i = 0; i < bus_len; i++)
		if (ebusdev->ofdev.dev.bus_id[i] == '/')
			ebusdev->ofdev.dev.bus_id[i] = '_';

	/* register with generic device framework */
	if (ebus_register_main(ebusdev, dn->name)) {
		kfree(ebusdev);
		return ERR_PTR(-ENODEV);
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

static int ibmebus_unregister_device(struct ibmebus_dev *dev)
{
	of_device_unregister(&dev->ofdev);

	return 0;
}

struct ebusdev_find_info
{
	struct ibmebus_dev *dev;
	const char *name;
};

static int ebus_cmp_name(struct device *dev, void *data)
{
       struct ebusdev_find_info *info = data;
       struct device_node *dn = to_of_device(dev)->node;

       if (strcmp(dn->name, info->name) == 0) {
	       info->dev = to_ibmebus_dev(dev);
	       return 1;
       }

       return 0;
}

static int ebus_cmp_path(struct device *dev, void *data)
{
       struct ebusdev_find_info *info = data;
       struct device_node *dn = to_of_device(dev)->node;

       if (dn->full_name && (strcasecmp(info->name, dn->full_name) == 0)) {
	       info->dev = to_ibmebus_dev(dev);
	       return 1;
       }

       return 0;
}

struct ibmebus_dev *ebus_device_find(const char *name,
				     int (*matcher)(struct device *, void *))
{
	struct ebusdev_find_info info = { .dev = NULL,
					  .name = name };

	bus_for_each_dev(&ibmebus_bus_type, NULL, &info, matcher);

	return info.dev;
}

void ibmebus_remove_devices_by_id(struct of_device_id *idt)
{
	struct ibmebus_dev *dev;
	while (strlen(idt->name) > 0) {
		while ((dev = ebus_device_find(idt->name, ebus_cmp_name)))
			ibmebus_unregister_device(dev);
		idt++;
	}
}

void ibmebus_add_devices_by_id(struct of_device_id *idt)
{
	while (strlen(idt->name) > 0) {
		probe_bus(idt->name);
		idt++;
	}
}

int ibmebus_register_driver(struct ibmebus_driver *ebusdrv)
{
	ebusdrv->driver.name   = ebusdrv->name;
	ebusdrv->driver.bus    = &ibmebus_bus_type;
	ebusdrv->driver.probe  = ebus_bus_probe;
	ebusdrv->driver.remove = ebus_bus_remove;

	/* remove all supported devices first, in case someone
	 * probed them manually before registering the driver */
	ibmebus_remove_devices_by_id(ebusdrv->id_table);
	ibmebus_add_devices_by_id(ebusdrv->id_table);

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

static ssize_t name_show(struct device *dev, char *buf)
{
	struct ibmebus_dev *ebus_dev = to_ibmebus_dev(dev);
	return sprintf(buf, "%s\n", ebus_dev->name);
}

static struct device_attribute ibmebus_dev_attrs[] = {
	__ATTR_RO(name),
	__ATTR_NULL
};

static char *ibmebus_chomp(const char *in, size_t count)
{
	char *out = (char*)kmalloc(count + 1, GFP_KERNEL);
	if (!out)
		return NULL;

	memcpy(out, in, count);
	out[count] = '\0';
	if (out[count - 1] == '\n')
		out[count - 1] = '\0';

	return out;
}

static ssize_t ibmebus_store_probe(struct bus_type *bus,
				   const char *buf, size_t count)
{
	struct device_node *dn = NULL;
	struct ibmebus_dev *dev;
	char *path;
	ssize_t rc;

	path = ibmebus_chomp(buf, count);
	if (!path)
		return -ENOMEM;

	if (ebus_device_find(path, ebus_cmp_path)) {
		printk(KERN_WARNING "%s: %s has already been probed\n",
		       __FUNCTION__, path);
		rc = -EINVAL;
		goto out;
	}

	if ((dn = of_find_node_by_path(path))) {
		dev = ebus_register_dtnode(dn);
		of_node_put(dn);
		rc = IS_ERR(dev) ? PTR_ERR(dev) : count;
	} else {
		printk(KERN_WARNING "%s: no such device node: %s\n",
		       __FUNCTION__, path);
		rc = -ENODEV;
	}

out:
	kfree(path);
	return rc;
}

static ssize_t ibmebus_store_remove(struct bus_type *bus,
				    const char *buf, size_t count)
{
	struct ibmebus_dev *dev;
	char *path;

	path = ibmebus_chomp(buf, count);
	if (!path)
		return -ENOMEM;

	if ((dev = ebus_device_find(path, ebus_cmp_path))) {
		ibmebus_unregister_device(dev);

		kfree(path);
		return count;
	} else {
		printk(KERN_WARNING "%s: %s not on the bus\n",
		       __FUNCTION__, path);

		kfree(path);
		return -ENODEV;
	}
}

static struct bus_attribute ibmebus_bus_attrs[] = {
	__ATTR(probe, S_IWUSR, NULL, ibmebus_store_probe),
	__ATTR(remove, S_IWUSR, NULL, ibmebus_store_remove),
	__ATTR_NULL
};

struct bus_type ibmebus_bus_type = {
	.name      = "ibmebus",
	.match     = ebus_bus_match,
	.dev_attrs = ibmebus_dev_attrs,
	.bus_attrs = ibmebus_bus_attrs
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

	err = device_register(&ebus_bus_device);
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
	device_unregister(&ebus_bus_device);
	bus_unregister(&ibmebus_bus_type);

	return;
}

module_init(ebus_init);
module_exit(ebus_exit);

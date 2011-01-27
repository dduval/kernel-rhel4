/*
 * drivers/pci/pci-sysfs.c
 *
 * (C) Copyright 2002-2004 Greg Kroah-Hartman <greg@kroah.com>
 * (C) Copyright 2002-2004 IBM Corp.
 * (C) Copyright 2003 Matthew Wilcox
 * (C) Copyright 2003 Hewlett-Packard
 *
 * File attributes for PCI devices
 *
 * Modeled after usb's driverfs.c 
 *
 */


#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/stat.h>

#include "pci.h"

/* show configuration fields */
#define pci_config_attr(field, format_string)				\
static ssize_t								\
field##_show(struct device *dev, char *buf)				\
{									\
	struct pci_dev *pdev;						\
									\
	pdev = to_pci_dev (dev);					\
	return sprintf (buf, format_string, pdev->field);		\
}

pci_config_attr(vendor, "0x%04x\n");
pci_config_attr(device, "0x%04x\n");
pci_config_attr(subsystem_vendor, "0x%04x\n");
pci_config_attr(subsystem_device, "0x%04x\n");
pci_config_attr(class, "0x%06x\n");
pci_config_attr(irq, "%u\n");

/* show resources */
static ssize_t
resource_show(struct device * dev, char * buf)
{
	struct pci_dev * pci_dev = to_pci_dev(dev);
	char * str = buf;
	int i;
	int max = 7;

	if (pci_dev->subordinate)
		max = DEVICE_COUNT_RESOURCE;

	for (i = 0; i < max; i++) {
		str += sprintf(str,"0x%016lx 0x%016lx 0x%016lx\n",
			       pci_resource_start(pci_dev,i),
			       pci_resource_end(pci_dev,i),
			       pci_resource_flags(pci_dev,i));
	}
	return (str - buf);
}

static ssize_t
msi_bus_show(struct device *dev, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	if (!pdev->subordinate)
		return 0;

	return sprintf (buf, "%u\n",
			!(pdev->subordinate->pad2 & PCI_BUS_FLAGS_NO_MSI));
}

static ssize_t
msi_bus_store(struct device *dev, const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	/* bad things may happen if the no_msi flag is changed
	 * while some drivers are loaded */
	if (!capable(CAP_SYS_ADMIN))
		return count;

	if (!pdev->subordinate)
		return count;

	if (*buf == '0') {
		pdev->subordinate->pad2 |= PCI_BUS_FLAGS_NO_MSI;
		dev_warn(&pdev->dev, "forced subordinate bus to not support MSI,"
			 " bad things could happen.\n");
	}

	if (*buf == '1') {
		pdev->subordinate->pad2 &= ~PCI_BUS_FLAGS_NO_MSI;
		dev_warn(&pdev->dev, "forced subordinate bus to support MSI,"
			 " bad things could happen.\n");
	}

	return count;
}
 
struct device_attribute pci_dev_attrs[] = {
	__ATTR_RO(resource),
	__ATTR_RO(vendor),
	__ATTR_RO(device),
	__ATTR_RO(subsystem_vendor),
	__ATTR_RO(subsystem_device),
	__ATTR_RO(class),
	__ATTR_RO(irq),
	__ATTR(msi_bus, 0644, msi_bus_show, msi_bus_store),
	__ATTR_NULL,
};

static ssize_t
pci_read_config(struct kobject *kobj, char *buf, loff_t off, size_t count)
{
	struct pci_dev *dev = to_pci_dev(container_of(kobj,struct device,kobj));
	unsigned int size = 64;
	loff_t init_off = off;
	u8 *data = (u8*) buf;

	/* Several chips lock up trying to read undefined config space */
	if (capable(CAP_SYS_ADMIN)) {
		size = dev->cfg_size;
	} else if (dev->hdr_type == PCI_HEADER_TYPE_CARDBUS) {
		size = 128;
	}

	if (off > size)
		return 0;
	if (off + count > size) {
		size -= off;
		count = size;
	} else {
		size = count;
	}

	if ((off & 1) && size) {
		u8 val;
		pci_user_read_config_byte(dev, off, &val);
		data[off - init_off] = val;
		off++;
		size--;
	}

	if ((off & 3) && size > 2) {
		u16 val;
		pci_user_read_config_word(dev, off, &val);
		data[off - init_off] = val & 0xff;
		data[off - init_off + 1] = (val >> 8) & 0xff;
		off += 2;
		size -= 2;
	}

	while (size > 3) {
		u32 val;
		pci_user_read_config_dword(dev, off, &val);
		data[off - init_off] = val & 0xff;
		data[off - init_off + 1] = (val >> 8) & 0xff;
		data[off - init_off + 2] = (val >> 16) & 0xff;
		data[off - init_off + 3] = (val >> 24) & 0xff;
		off += 4;
		size -= 4;
	}

	if (size >= 2) {
		u16 val;
		pci_user_read_config_word(dev, off, &val);
		data[off - init_off] = val & 0xff;
		data[off - init_off + 1] = (val >> 8) & 0xff;
		off += 2;
		size -= 2;
	}

	if (size > 0) {
		u8 val;
		pci_user_read_config_byte(dev, off, &val);
		data[off - init_off] = val;
		off++;
		--size;
	}

	return count;
}

static ssize_t
pci_write_config(struct kobject *kobj, char *buf, loff_t off, size_t count)
{
	struct pci_dev *dev = to_pci_dev(container_of(kobj,struct device,kobj));
	unsigned int size = count;
	loff_t init_off = off;
	u8 *data = (u8*) buf;

	if (off > dev->cfg_size)
		return 0;
	if (off + count > dev->cfg_size) {
		size = dev->cfg_size - off;
		count = size;
	}
	
	if ((off & 1) && size) {
		pci_user_write_config_byte(dev, off, buf[off - init_off]);
		off++;
		size--;
	}
	
	if ((off & 3) && size > 2) {
		u16 val = data[off - init_off];
		val |= (unsigned int) data[off - init_off +1] << 8;
		pci_user_write_config_word(dev, off, val);
		off += 2;
		size -= 2;
        }

	while (size > 3) {
		u32 val = data[off - init_off];
		val |= (unsigned int) data[off - init_off + 1] << 8;
		val |= (unsigned int) data[off - init_off + 2] << 16;
		val |= (unsigned int) data[off - init_off + 3] << 24;
		pci_user_write_config_dword(dev, off, val);
		off += 4;
		size -= 4;
	}
	
	if (size >= 2) {
		u16 val = data[off - init_off];
		val |= (unsigned int) data[off - init_off +1] << 8;
		pci_user_write_config_word(dev, off, val);
		off +=2;
		size -= 2;
	}

	if (size) {
		pci_user_write_config_byte(dev, off, data[off - init_off]);
		off++;
		--size;
	}

	return count;
}

static struct bin_attribute pci_config_attr = {
	.attr =	{
		.name = "config",
		.mode = S_IRUGO | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 256,
	.read = pci_read_config,
	.write = pci_write_config,
};

static struct bin_attribute pcie_config_attr = {
	.attr =	{
		.name = "config",
		.mode = S_IRUGO | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 4096,
	.read = pci_read_config,
	.write = pci_write_config,
};

void pci_create_sysfs_dev_files (struct pci_dev *pdev)
{
	if (pdev->cfg_size < 4096)
		sysfs_create_bin_file(&pdev->dev.kobj, &pci_config_attr);
	else
		sysfs_create_bin_file(&pdev->dev.kobj, &pcie_config_attr);

	/* add platform-specific attributes */
	pcibios_add_platform_entries(pdev);
}

/*
 * Copyright (C) 2004 IBM Corporation
 *
 * Implements the generic device dma API for ppc64. Handles
 * the pci and vio busses
 */

#include <linux/device.h>
#include <linux/dma-mapping.h>
/* Include the busses we support */
#include <linux/pci.h>
#include <asm/vio.h>
#include <asm-ppc64/ibmebus.h>
#include <asm/scatterlist.h>
#include <asm/bug.h>

int dma_supported(struct device *dev, u64 mask)
{
	if (dev->bus == &pci_bus_type)
		return pci_dma_supported(to_pci_dev(dev), mask);
	if (dev->bus == &vio_bus_type)
		return vio_dma_supported(to_vio_dev(dev), mask);
#ifdef CONFIG_IBMEBUS
	if (dev->bus == &ibmebus_bus_type)
		return ibmebus_dma_supported(dev, mask);
#endif
	BUG();
	return 0;
}
EXPORT_SYMBOL(dma_supported);

int dma_set_mask(struct device *dev, u64 dma_mask)
{
	if (dev->bus == &pci_bus_type)
		return pci_set_dma_mask(to_pci_dev(dev), dma_mask);
	if (dev->bus == &vio_bus_type)
		return vio_set_dma_mask(to_vio_dev(dev), dma_mask);
#ifdef CONFIG_IBMEBUS
	if (dev->bus == &ibmebus_bus_type)
		return -EIO;
#endif
	BUG();
	return 0;
}
EXPORT_SYMBOL(dma_set_mask);

void *dma_alloc_coherent(struct device *dev, size_t size,
		dma_addr_t *dma_handle, int flag)
{
	if (dev->bus == &pci_bus_type)
		return pci_alloc_consistent(to_pci_dev(dev), size, dma_handle);
	if (dev->bus == &vio_bus_type)
		return vio_alloc_consistent(to_vio_dev(dev), size, dma_handle);
#ifdef CONFIG_IBMEBUS
	if (dev->bus == &ibmebus_bus_type)
		return ibmebus_alloc_coherent(dev, size, dma_handle, flag);
#endif
	BUG();
	return NULL;
}
EXPORT_SYMBOL(dma_alloc_coherent);

void dma_free_coherent(struct device *dev, size_t size, void *cpu_addr,
		dma_addr_t dma_handle)
{
	if (dev->bus == &pci_bus_type)
		pci_free_consistent(to_pci_dev(dev), size, cpu_addr, dma_handle);
	else if (dev->bus == &vio_bus_type)
		vio_free_consistent(to_vio_dev(dev), size, cpu_addr, dma_handle);
#ifdef CONFIG_IBMEBUS
	else if (dev->bus == &ibmebus_bus_type)
		ibmebus_free_coherent(dev, size, cpu_addr, dma_handle);
#endif
	else
		BUG();
}
EXPORT_SYMBOL(dma_free_coherent);

dma_addr_t dma_map_single(struct device *dev, void *cpu_addr, size_t size,
		enum dma_data_direction direction)
{
	if (dev->bus == &pci_bus_type)
		return pci_map_single(to_pci_dev(dev), cpu_addr, size, (int)direction);
	if (dev->bus == &vio_bus_type)
		return vio_map_single(to_vio_dev(dev), cpu_addr, size, direction);
	BUG();
	return (dma_addr_t)0;
}
EXPORT_SYMBOL(dma_map_single);

dma64_addr_t dma64_map_single(struct device *dev, void *cpu_addr, size_t size,
		enum dma_data_direction direction)
{
#ifdef CONFIG_IBMEBUS
	if (dev->bus == &ibmebus_bus_type)
		return ibmebus_map_single(dev, cpu_addr, size, direction);
#endif
	return dma_map_single(dev, cpu_addr, size, direction);
}
EXPORT_SYMBOL(dma64_map_single);

void dma_unmap_single(struct device *dev, dma_addr_t dma_addr, size_t size,
		enum dma_data_direction direction)
{
	if (dev->bus == &pci_bus_type)
		pci_unmap_single(to_pci_dev(dev), dma_addr, size, (int)direction);
	else if (dev->bus == &vio_bus_type)
		vio_unmap_single(to_vio_dev(dev), dma_addr, size, direction);
	else
		BUG();
}
EXPORT_SYMBOL(dma_unmap_single);

void dma64_unmap_single(struct device *dev, dma64_addr_t dma_addr, size_t size,
		enum dma_data_direction direction)
{
#ifdef CONFIG_IBMEBUS
	if (dev->bus == &ibmebus_bus_type) {
		ibmebus_unmap_single(dev, dma_addr, size, direction);
		return;
	}
#endif
	dma_unmap_single(dev, dma_addr, size, direction);
}
EXPORT_SYMBOL(dma64_unmap_single);

dma_addr_t dma_map_page(struct device *dev, struct page *page,
		unsigned long offset, size_t size,
		enum dma_data_direction direction)
{
	if (dev->bus == &pci_bus_type)
		return pci_map_page(to_pci_dev(dev), page, offset, size, (int)direction);
	if (dev->bus == &vio_bus_type)
		return vio_map_page(to_vio_dev(dev), page, offset, size, direction);
	BUG();
	return (dma_addr_t)0;
}
EXPORT_SYMBOL(dma_map_page);

void dma_unmap_page(struct device *dev, dma_addr_t dma_address, size_t size,
		enum dma_data_direction direction)
{
	if (dev->bus == &pci_bus_type)
		pci_unmap_page(to_pci_dev(dev), dma_address, size, (int)direction);
	else if (dev->bus == &vio_bus_type)
		vio_unmap_page(to_vio_dev(dev), dma_address, size, direction);
	else
		BUG();
}
EXPORT_SYMBOL(dma_unmap_page);

int dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
		enum dma_data_direction direction)
{
	if (dev->bus == &pci_bus_type)
		return pci_map_sg(to_pci_dev(dev), sg, nents, (int)direction);
	if (dev->bus == &vio_bus_type)
		return vio_map_sg(to_vio_dev(dev), sg, nents, direction);
#ifdef CONFIG_IBMEBUS
	if (dev->bus == &ibmebus_bus_type)
		return ibmebus_map_sg(dev, sg, nents, direction);
#endif
	BUG();
	return 0;
}
EXPORT_SYMBOL(dma_map_sg);

void dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nhwentries,
		enum dma_data_direction direction)
{
	if (dev->bus == &pci_bus_type)
		pci_unmap_sg(to_pci_dev(dev), sg, nhwentries, (int)direction);
	else if (dev->bus == &vio_bus_type)
		vio_unmap_sg(to_vio_dev(dev), sg, nhwentries, direction);
#ifdef CONFIG_IBMEBUS
	else if (dev->bus == &ibmebus_bus_type)
		ibmebus_unmap_sg(dev, sg, nhwentries, direction);
#endif
	else
		BUG();
}
EXPORT_SYMBOL(dma_unmap_sg);

#ifndef _DMA_MAPPING_BACKPORT_H
#define _DMA_MAPPING_BACKPORT_H

#include_next <linux/dma-mapping.h>

static inline int valid_dma_direction(int dma_direction)
{
	return ((dma_direction == DMA_BIDIRECTIONAL) ||
		(dma_direction == DMA_TO_DEVICE) ||
		(dma_direction == DMA_FROM_DEVICE));
}

#endif /* _DMA_MAPPING_BACKPORT_H */

#ifndef __BACKPORT_LINUX_DMA_MAPPING_H_TO_2_6_25__
#define __BACKPORT_LINUX_DMA_MAPPING_H_TO_2_6_25__

#include_next <linux/dma-mapping.h>

#ifndef CONFIG_HAVE_DMA_ATTRS
struct dma_attrs;

#define dma_map_single_attrs(dev, cpu_addr, size, dir, attrs) \
	dma_map_single(dev, cpu_addr, size, dir)

#define dma_unmap_single_attrs(dev, dma_addr, size, dir, attrs) \
	dma_unmap_single(dev, dma_addr, size, dir)

#define dma_map_sg_attrs(dev, sgl, nents, dir, attrs) \
	dma_map_sg(dev, sgl, nents, dir)

#define dma_unmap_sg_attrs(dev, sgl, nents, dir, attrs) \
	dma_unmap_sg(dev, sgl, nents, dir)

#endif /* CONFIG_HAVE_DMA_ATTRS */

#endif

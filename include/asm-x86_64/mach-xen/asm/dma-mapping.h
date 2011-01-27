#ifndef _X8664_DMA_MAPPING_H
#define _X8664_DMA_MAPPING_H 1

/*
 * IOMMU interface. See Documentation/DMA-mapping.txt and DMA-API.txt for
 * documentation.
 */

#include <linux/config.h>

#include <asm/scatterlist.h>
#include <asm/io.h>
#include <asm/swiotlb.h>

struct dma_mapping_ops {
	int             (*mapping_error)(dma_addr_t dma_addr);
	void*           (*alloc_coherent)(struct device *dev, size_t size,
                                dma_addr_t *dma_handle, gfp_t gfp);
	void            (*free_coherent)(struct device *dev, size_t size,
                                void *vaddr, dma_addr_t dma_handle);
	dma_addr_t      (*map_single)(struct device *hwdev, void *ptr,
                                size_t size, int direction);
	/* like map_single, but doesn't check the device mask */
	dma_addr_t      (*map_simple)(struct device *hwdev, char *ptr,
                                size_t size, int direction);
	void            (*unmap_single)(struct device *dev, dma_addr_t addr,
		                size_t size, int direction);
	void            (*sync_single_for_cpu)(struct device *hwdev,
		                dma_addr_t dma_handle, size_t size,
				int direction);
	void            (*sync_single_for_device)(struct device *hwdev,
                                dma_addr_t dma_handle, size_t size,
				int direction);
	void            (*sync_single_range_for_cpu)(struct device *hwdev,
                                dma_addr_t dma_handle, unsigned long offset,
		                size_t size, int direction);
	void            (*sync_single_range_for_device)(struct device *hwdev,
				dma_addr_t dma_handle, unsigned long offset,
		                size_t size, int direction);
	void            (*sync_sg_for_cpu)(struct device *hwdev,
                                struct scatterlist *sg, int nelems,
				int direction);
	void            (*sync_sg_for_device)(struct device *hwdev,
				struct scatterlist *sg, int nelems,
				int direction);
	int             (*map_sg)(struct device *hwdev, struct scatterlist *sg,
		                int nents, int direction);
	void            (*unmap_sg)(struct device *hwdev,
				struct scatterlist *sg, int nents,
				int direction);
	int             (*dma_supported)(struct device *hwdev, u64 mask);
	int		is_phys;
};

extern dma_addr_t bad_dma_address;
extern struct dma_mapping_ops* dma_ops;
extern int iommu_merge;

#if 0 /* Commented exactly as in Fedora */
static inline int dma_mapping_error(dma_addr_t dma_addr)
{
	if (dma_ops->mapping_error)
		return dma_ops->mapping_error(dma_addr);

	return (dma_addr == bad_dma_address);
}

extern void *dma_alloc_coherent(struct device *dev, size_t size,
				dma_addr_t *dma_handle, gfp_t gfp);
extern void dma_free_coherent(struct device *dev, size_t size, void *vaddr,
			      dma_addr_t dma_handle);

static inline dma_addr_t dma_map_single(struct device *hwdev, void *ptr,
					size_t size, int direction)
{
	dma_addr_t addr;

	if (direction == DMA_NONE)
		out_of_line_bug();
	addr = virt_to_bus(ptr);

	if ((addr+size) & ~*hwdev->dma_mask)
		out_of_line_bug();
	return addr;
}

static inline void dma_unmap_single(struct device *hwdev, dma_addr_t dma_addr,
				    size_t size, int direction)
{
	if (direction == DMA_NONE)
		out_of_line_bug();
	/* Nothing to do */
}


#define dma_map_page(dev,page,offset,size,dir) \
	dma_map_single((dev), page_address(page)+(offset), (size), (dir))

#define dma_unmap_page dma_unmap_single

static inline void dma_sync_single_for_cpu(struct device *hwdev,
					       dma_addr_t dma_handle,
					       size_t size, int direction)
{
	if (direction == DMA_NONE)
		out_of_line_bug();

	if (swiotlb)
		return swiotlb_sync_single_for_cpu(hwdev,dma_handle,size,direction);

	flush_write_buffers();
}

static inline void dma_sync_single_for_device(struct device *hwdev,
						  dma_addr_t dma_handle,
						  size_t size, int direction)
{
        if (direction == DMA_NONE)
		out_of_line_bug();

	if (swiotlb)
		return swiotlb_sync_single_for_device(hwdev,dma_handle,size,direction);

	flush_write_buffers();
}

static inline void dma_sync_single_range_for_cpu(struct device *hwdev,
						 dma_addr_t dma_handle,
						 unsigned long offset,
						 size_t size, int direction)
{
	if (direction == DMA_NONE)
		out_of_line_bug();

	if (swiotlb)
		return swiotlb_sync_single_range_for_cpu(hwdev,dma_handle,offset,size,direction);

	flush_write_buffers();
}

static inline void dma_sync_single_range_for_device(struct device *hwdev,
						    dma_addr_t dma_handle,
						    unsigned long offset,
						    size_t size, int direction)
{
        if (direction == DMA_NONE)
		out_of_line_bug();

	if (swiotlb)
		return swiotlb_sync_single_range_for_device(hwdev,dma_handle,offset,size,direction);

	flush_write_buffers();
}

static inline void dma_sync_sg_for_cpu(struct device *hwdev,
				       struct scatterlist *sg,
				       int nelems, int direction)
{
	if (direction == DMA_NONE)
		out_of_line_bug();

	if (swiotlb)
		return swiotlb_sync_sg_for_cpu(hwdev,sg,nelems,direction);

	flush_write_buffers();
}

static inline void dma_sync_sg_for_device(struct device *hwdev,
					  struct scatterlist *sg,
					  int nelems, int direction)
{
	if (direction == DMA_NONE)
		out_of_line_bug();

	if (swiotlb)
		return swiotlb_sync_sg_for_device(hwdev,sg,nelems,direction);

	flush_write_buffers();
}

extern int dma_supported(struct device *hwdev, u64 mask);

#define dma_is_consistent(h) 1

static inline void
dma_cache_sync(void *vaddr, size_t size, int dir)
{
	flush_write_buffers();
}

extern struct device fallback_dev;
extern int panic_on_overflow;
#endif

/* -- This is a point where we grafted asm-i386/mach-xen/asm/dma-mapping.h -- */
/*
 * IOMMU interface. See Documentation/DMA-mapping.txt and DMA-API.txt for
 * documentation.
 */

#include <linux/mm.h>
#include <asm/cache.h>

#define dma_alloc_noncoherent(d, s, h, f) dma_alloc_coherent(d, s, h, f)
#define dma_free_noncoherent(d, s, v, h) dma_free_coherent(d, s, v, h)

void *dma_alloc_coherent(struct device *dev, size_t size,
			   dma_addr_t *dma_handle, gfp_t flag);

void dma_free_coherent(struct device *dev, size_t size,
			 void *vaddr, dma_addr_t dma_handle);

extern dma_addr_t
dma_map_single(struct device *dev, void *ptr, size_t size, int dir);

extern void
dma_unmap_single(struct device *dev, dma_addr_t dma_addr, size_t size, int dir);

extern int dma_map_sg(struct device *hwdev, struct scatterlist *sg,
		      int nents, int dir);
extern void dma_unmap_sg(struct device *hwdev, struct scatterlist *sg,
			 int nents, int dir);

extern dma_addr_t
dma_map_page(struct device *dev, struct page *page, unsigned long offset,
	     size_t size, int dir);

extern void
dma_unmap_page(struct device *dev, dma_addr_t dma_address, size_t size,
	       int dir);

extern void
dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle, size_t size,
			int dir);

extern void
dma_sync_single_for_device(struct device *dev, dma_addr_t dma_handle, size_t size,
                           int dir);

static inline void
dma_sync_single_range_for_cpu(struct device *dev, dma_addr_t dma_handle,
			      unsigned long offset, size_t size,
			      int direction)
{
	dma_sync_single_for_cpu(dev, dma_handle+offset, size, direction);
}

static inline void
dma_sync_single_range_for_device(struct device *dev, dma_addr_t dma_handle,
				 unsigned long offset, size_t size,
				 int direction)
{
	dma_sync_single_for_device(dev, dma_handle+offset, size, direction);
}

static inline void
dma_sync_sg_for_cpu(struct device *dev, struct scatterlist *sg, int nelems,
		    int direction)
{
	if (swiotlb)
		swiotlb_sync_sg_for_cpu(dev,sg,nelems,direction);
	flush_write_buffers();
}

static inline void
dma_sync_sg_for_device(struct device *dev, struct scatterlist *sg, int nelems,
		    int direction)
{
	if (swiotlb)
		swiotlb_sync_sg_for_device(dev,sg,nelems,direction);
	flush_write_buffers();
}

extern int
dma_mapping_error(dma_addr_t dma_addr);

extern int
dma_supported(struct device *dev, u64 mask);

static inline int
dma_set_mask(struct device *dev, u64 mask)
{
	if(!dev->dma_mask || !dma_supported(dev, mask))
		return -EIO;

	*dev->dma_mask = mask;

	return 0;
}

#ifdef __i386__
static inline int
dma_get_cache_alignment(void)
{
	/* no easy way to get cache size on all x86, so return the
	 * maximum possible, to be safe */
	return (1 << L1_CACHE_SHIFT_MAX);
}
#else
extern int dma_get_cache_alignment(void);
#endif

#define ARCH_HAS_DMA_DECLARE_COHERENT_MEMORY
extern int
dma_declare_coherent_memory(struct device *dev, dma_addr_t bus_addr,
			    dma_addr_t device_addr, size_t size, int flags);

extern void
dma_release_declared_memory(struct device *dev);

extern void *
dma_mark_declared_memory_occupied(struct device *dev,
				  dma_addr_t device_addr, size_t size);

#endif /* _X8664_DMA_MAPPING_H */

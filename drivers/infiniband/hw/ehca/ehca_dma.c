/*
 *  IBM eServer eHCA Infiniband device driver for Linux on POWER
 *
 *  eHCA dma mapping via ibmebus
 *
 *  Authors: Stefan Roscher <stefan.roscher@de.ibm.com>
 *           Hoang-Nam Nguyen <hnguyen@de.ibm.com>
 *
 *  Copyright (c) 2007 IBM Corporation
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
 */

#include <asm/ibmebus.h>
#include <rdma/ib_verbs.h>

static int ehca_mapping_error(struct ib_device *dev, u64 dma_addr);

static u64 ehca_dma_map_single(struct ib_device *dev,
			        void *cpu_addr, size_t size,
			        enum dma_data_direction direction);

static void ehca_dma_unmap_single(struct ib_device *dev,
				   u64 addr, size_t size,
				  enum dma_data_direction direction);

static u64 ehca_dma_map_page(struct ib_device *dev,
			      struct page *page,
			      unsigned long offset,
			      size_t size,
			     enum dma_data_direction direction);

static void ehca_dma_unmap_page(struct ib_device *dev,
				 u64 addr, size_t size,
				enum dma_data_direction direction);

int ehca_map_sg(struct ib_device *dev, struct scatterlist *sg, int nents,
		enum dma_data_direction direction);

static void ehca_unmap_sg(struct ib_device *dev,
			   struct scatterlist *sg, int nents,
			  enum dma_data_direction direction);

static u64 ehca_sg_dma_address(struct ib_device *dev, struct scatterlist *sg);

static unsigned int ehca_sg_dma_len(struct ib_device *dev,
				    struct scatterlist *sg);

static void ehca_sync_single_for_cpu(struct ib_device *dev,
				      u64 addr,
				      size_t size,
				     enum dma_data_direction dir);

static void ehca_sync_single_for_device(struct ib_device *dev,
					 u64 addr,
					 size_t size,
					enum dma_data_direction dir);

static void *ehca_dma_alloc_coherent(struct ib_device *dev, size_t size,
				     u64 *dma_handle, gfp_t flag);

static void ehca_dma_free_coherent(struct ib_device *dev, size_t size,
				   void *cpu_addr, dma_addr_t dma_handle);

struct ib_dma_mapping_ops ehca_dma_mapping_ops = {
	ehca_mapping_error,
	ehca_dma_map_single,
	ehca_dma_unmap_single,
	ehca_dma_map_page,
	ehca_dma_unmap_page,
	ehca_map_sg,
	ehca_unmap_sg,
	ehca_sg_dma_address,
	ehca_sg_dma_len,
	ehca_sync_single_for_cpu,
	ehca_sync_single_for_device,
	ehca_dma_alloc_coherent,
	ehca_dma_free_coherent
};

static int ehca_mapping_error(struct ib_device *dev, u64 dma_addr)
{
	return dma_addr == 0L;
}

static u64 ehca_dma_map_single(struct ib_device *dev,
			        void *cpu_addr, size_t size,
			        enum dma_data_direction direction)
{
	return ibmebus_map_single(dev, cpu_addr, size, direction);
}

static void ehca_dma_unmap_single(struct ib_device *dev,
				   u64 addr, size_t size,
				   enum dma_data_direction direction)
{
	ibmebus_unmap_single(dev, addr, size, direction);
}

static u64 ehca_dma_map_page(struct ib_device *dev,
			      struct page *page,
			      unsigned long offset,
			      size_t size,
			      enum dma_data_direction direction)
{
  	return ibmebus_map_single(dev, (page_address(page) +  offset),
			 	   size, direction);
}

static void ehca_dma_unmap_page(struct ib_device *dev,
				 u64 addr, size_t size,
				 enum dma_data_direction direction)
{
	ibmebus_unmap_single(dev, addr, size, direction);
}

int ehca_map_sg(struct ib_device *dev, struct scatterlist *sg, int nents,
		 enum dma_data_direction direction)
{
	return ibmebus_map_sg(dev, sg, nents, direction);
}

static void ehca_unmap_sg(struct ib_device *dev,
			   struct scatterlist *sg, int nents,
			   enum dma_data_direction direction)
{
	ibmebus_unmap_sg(dev, sg, nents, direction);
}

static u64 ehca_sg_dma_address(struct ib_device *dev, struct scatterlist *sg)
{
	return sg_dma_address(sg);
}

static unsigned int ehca_sg_dma_len(struct ib_device *dev,
				     struct scatterlist *sg)
{
	return sg_dma_len(sg);
}

static void ehca_sync_single_for_cpu(struct ib_device *dev,
				      u64 addr,
				      size_t size,
				      enum dma_data_direction dir)
{
	dma_sync_single_for_cpu(dev->dma_device, addr, size, dir);
}

static void ehca_sync_single_for_device(struct ib_device *dev,
					 u64 addr,
					 size_t size,
					 enum dma_data_direction dir)
{
	dma_sync_single_for_device(dev->dma_device, addr, size, dir);
}

static void *ehca_dma_alloc_coherent(struct ib_device *dev, size_t size,
				      u64 *dma_handle, gfp_t flag)
{
	return ibmebus_alloc_coherent(dev, size, dma_handle, flag);
}

static void ehca_dma_free_coherent(struct ib_device *dev, size_t size,
				    void *cpu_addr, dma_addr_t dma_handle)
{
	ibmebus_free_coherent(dev, size, cpu_addr, dma_handle);
}

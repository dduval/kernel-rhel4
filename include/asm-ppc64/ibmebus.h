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

#ifndef _ASM_EBUS_H
#define _ASM_EBUS_H

#include <asm/of_device.h>
#include <asm-ppc64/types.h>
#include <asm-ppc64/scatterlist.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>

extern struct bus_type ibmebus_bus_type;

struct ibmebus_dev {
	char *name;
	struct of_device ofdev;
};

struct ibmebus_driver {
	struct list_head node;
	char *name;
	struct of_device_id *id_table;
	int (*probe) (struct ibmebus_dev *dev, const struct of_device_id *id);
	int (*remove) (struct ibmebus_dev *dev);
	unsigned long driver_data;

	struct device_driver driver;
};

int ibmebus_register_driver(struct ibmebus_driver *drv);
void ibmebus_unregister_driver(struct ibmebus_driver *drv);

int ibmebus_request_irq(struct ibmebus_dev *dev,
			u32 ist,
			irqreturn_t (*handler)(int, void*, struct pt_regs *),
			unsigned long irq_flags, const char * devname,
			void *dev_id);
void ibmebus_free_irq(struct ibmebus_dev *dev, u32 ist, void *dev_id);

static inline struct ibmebus_driver *to_ibmebus_driver(struct device_driver *drv)
{
	return container_of(drv, struct ibmebus_driver, driver);
}

static inline struct ibmebus_dev *to_ibmebus_dev(struct device *dev)
{
	return container_of(dev, struct ibmebus_dev, ofdev.dev);
}

/*
 * Struct used for matching a device
 */
struct of_device_id
{
        char    name[32];
	char	compatible[128];
};

void *ibmebus_alloc_coherent(struct device *dev,
			     size_t size,
			     dma64_addr_t *dma_handle,
			     gfp_t flag);
void ibmebus_free_coherent(struct device *dev,
			   size_t size, void *vaddr,
			   dma64_addr_t dma_handle);
dma64_addr_t ibmebus_map_single(struct device *dev,
				void *ptr,
				size_t size,
				enum dma_data_direction direction);
void ibmebus_unmap_single(struct device *dev,
			  dma64_addr_t dma_addr,
			  size_t size,
			  enum dma_data_direction direction);
int ibmebus_map_sg(struct device *dev,
		   struct scatterlist *sg,
		   int nents, enum dma_data_direction direction);
void ibmebus_unmap_sg(struct device *dev,
		      struct scatterlist *sg,
		      int nents, enum dma_data_direction direction);
int ibmebus_dma_supported(struct device *dev, u64 mask);

#endif /* _ASM_EBUS_H */

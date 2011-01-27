/*******************************************************************
 * This file is part of the Emulex Linux Device Driver for         *
 * Fibre Channel Host Bus Adapters.                                *
 * Copyright (C) 2003-2005 Emulex.  All rights reserved.           *
 * EMULEX and SLI are trademarks of Emulex.                        *
 * www.emulex.com                                                  *
 *                                                                 *
 * This program is free software; you can redistribute it and/or   *
 * modify it under the terms of version 2 of the GNU General       *
 * Public License as published by the Free Software Foundation.    *
 * This program is distributed in the hope that it will be useful. *
 * ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND          *
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY,  *
 * FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT, ARE      *
 * DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD *
 * TO BE LEGALLY INVALID.  See the GNU General Public License for  *
 * more details, a copy of which can be found in the file COPYING  *
 * included with this package.                                     *
 *******************************************************************/

/*
 * $Id: lpfc_mem.h 2757 2005-12-09 18:21:44Z sf_support $
 */

#ifndef _H_LPFC_MEM
#define _H_LPFC_MEM


struct lpfc_dmabuf {
	struct list_head list;
	void *virt;		/* virtual address ptr */
	dma_addr_t phys;	/* mapped address */
};
struct lpfc_dmabufext {
	struct lpfc_dmabuf dma;
	uint32_t size;
	uint32_t flag;
	struct list_head list;
	uint32_t uniqueid;
	uint32_t data;
};
typedef struct lpfc_dmabufext DMABUFEXT_t;

struct lpfc_dma_pool {
	struct lpfc_dmabuf   *elements;
	uint32_t    max_count;
	uint32_t    current_count;
};


#define MEM_PRI             0x100	/* Priority bit: set to exceed low
					   water */
#define LPFC_MBUF_POOL_SIZE     64      /* max elements in MBUF safety pool */
#define LPFC_MEM_POOL_SIZE      64      /* max elements in non DMA safety
					   pool */
#endif				/* _H_LPFC_MEM */

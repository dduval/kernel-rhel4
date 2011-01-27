/*
 *	Adaptec AAC series RAID controller driver
 *	(c) Copyright 2001 Red Hat Inc.	<alan@redhat.com>
 *
 * Copyright (c) 2004-2007 Adaptec, Inc. (aacraid@adaptec.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
/*
 * This file is for backwards compatibility with older kernel versions
 */



#include <linux/dma-mapping.h>
#ifndef DMA_31BIT_MASK
#define DMA_31BIT_MASK ((dma_addr_t)0x7fffffffULL)
#endif

#ifndef spin_trylock_irqsave
#define spin_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	spin_trylock(lock) ? \
	1 : ({local_irq_restore(flags); 0 ;}); \
})
#endif

#ifndef sdev_printk
#define sdev_printk(prefix, sdev, fmt, a...) \
	printk(prefix " %d:%d:%d:%d: " fmt, sdev->host->host_no, \
		sdev_channel(sdev), sdev_id(sdev), sdev->lun, ##a)
#endif

#ifndef IRQF_SHARED
# define IRQF_SHARED SA_SHIRQ
#endif
#ifndef IRQF_DISABLED
# define IRQF_DISABLED SA_INTERRUPT /* Counter intuitive? */
#endif

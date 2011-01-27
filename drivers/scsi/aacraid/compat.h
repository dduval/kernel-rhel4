/*
 *	Adaptec AAC series RAID controller driver
 *	(c) Copyright 2001 Red Hat Inc.	<alan@redhat.com>
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

#ifndef BUG_ON
#ifndef unlikely
#ifndef __builtin_expect
#define __builtin_expect(x, expected_value) (x)
#endif
#define unlikely(x) __builtin_expect((x),0)
#endif
#define BUG_ON(condition) do { if (unlikely((condition)!=0)) BUG(); } while (0)
#endif
#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif


#ifndef DMA_64BIT_MASK
#define DMA_64BIT_MASK ((dma_addr_t)0xffffffffffffffffULL)
#endif
#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK ((dma_addr_t)0xffffffffULL)
#endif
#ifndef spin_trylock_irqsave
#define spin_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	spin_trylock(lock) ? \
	1 : ({local_irq_restore(flags); 0 ;}); \
})
#endif






    

#ifndef _ASM_GENERIC_NETDUMP_H_
#define _ASM_GENERIC_NETDUMP_H_

/*
 * linux/include/asm-generic/netdump.h
 *
 * Copyright (c) 2003, 2004 Red Hat, Inc. All rights reserved.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <asm-generic/crashdump.h>

#ifdef __KERNEL__

#warning netdump is not supported on this platform
const static int platform_supports_netdump = 0;

static inline int page_is_ram(unsigned long x) { return 0; }

#define platform_machine_type() (EM_NONE)
#define platform_effective_version(x) (0)
#define platform_next_available(x) ((u32)0)
#define platform_freeze_cpu()  do { } while (0)
#define platform_jiffy_cycles(x)  do { } while (0)
#define platform_max_pfn() (0)
#define platform_get_regs(x,y) (0)

#undef kmap_atomic
#undef kunmap_atomic
static inline char *kmap_atomic(void *page, int idx)  { return NULL; }
#define kunmap_atomic(addr, idx)  do { } while (0)

#endif /* __KERNEL__ */

#endif /* _ASM_GENERIC_NETDUMP_H */

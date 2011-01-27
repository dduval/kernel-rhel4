#ifndef _ASM_IA64_NETDUMP_H_
#define _ASM_IA64_NETDUMP_H_

/*
 * linux/include/asm-ia64/netdump.h
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

#ifdef __KERNEL__

#include <asm/crashdump.h>

const static int platform_supports_netdump = 1;

#define platform_machine_type() (EM_IA_64)

#define platform_page_is_ram(x) page_is_ram(x)

static inline unsigned char platform_effective_version(req_t *req)
{
	if (req->from > 0)
		return min_t(unsigned char, req->from, NETDUMP_VERSION_MAX);
	else
		return 0;
}

extern void *high_memory;
#define platform_max_pfn() ((__pa(high_memory)) / PAGE_SIZE)

static inline u32 platform_next_available(unsigned long pfn)
{
	unsigned long pgnum = next_ram_page(pfn);

	if (pgnum < platform_max_pfn()) {
		return (u32)pgnum;
	}
	return 0;
}

static inline void platform_jiffy_cycles(unsigned long long *jcp)
{
        unsigned long long t0, t1;

        platform_timestamp(t0);
        netdump_mdelay(1);
        platform_timestamp(t1);
        if (t1 > t0)
                *jcp = t1 - t0;
}

#define platform_freeze_cpu()                                  \
{                                                              \
       unw_init_running(ia64_freeze_cpu, 0);                   \
}

static inline unsigned int platform_get_regs(char *tmp, struct pt_regs *myregs)
{
	char *tmp2;

	tmp2 = tmp + sprintf(tmp, "Sending register info.\n");
	memcpy(tmp2, myregs, sizeof(struct pt_regs));

	return(strlen(tmp) + sizeof(struct pt_regs));
}
#endif /* __KERNEL__ */

#endif /* _ASM_IA64_NETDUMP_H */

#ifndef _ASM_PPC64_CRASHDUMP_H
#define _ASM_PPC64_CRASHDUMP_H

/*
 * linux/include/asm-ppc64/crashdump.h
 *
 * Copyright (c) 2003, 2004 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2004 IBM Corp.
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
 *
 */

#ifdef __KERNEL__

#include <asm/time.h>

extern int page_is_ram (unsigned long);
extern unsigned long next_ram_page (unsigned long);

#define platform_timestamp(x) (x = get_tb())

#define platform_fix_regs()						\
{									\
       memcpy(&myregs, regs, sizeof(struct pt_regs));			\
};

#define platform_init_stack(stackptr) do { } while (0)
#define platform_cleanup_stack(stackptr) do { } while (0)

typedef asmlinkage void (*crashdump_func_t)(struct pt_regs *, void *);

static inline void platform_start_crashdump(void *stackptr,
					   crashdump_func_t dumpfunc,
					   struct pt_regs *regs)
{
	dumpfunc(regs, NULL);
}

#define platform_freeze_cpu()					\
{								\
	current->thread.ksp = __get_SP();			\
	for (;;) local_irq_disable();				\
}


#endif /* __KERNEL__ */

#endif /* _ASM_PPC64_CRASHDUMP_H */

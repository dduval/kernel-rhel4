#ifndef _ASM_IA64_CRASHDUMP_H
#define _ASM_IA64_CRASHDUMP_H

/*
 * linux/include/asm-ia64/diskdump.h
 *
 * Copyright (c) 2004 FUJITSU LIMITED
 * Copyright (c) 2003 Red Hat, Inc. All rights reserved.
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

#include <linux/elf.h>
#include <asm/unwind.h>
#include <asm/ptrace.h>

extern void ia64_freeze_cpu(struct unw_frame_info *, void *arg);
extern void ia64_start_dump(struct unw_frame_info *, void *arg);
extern int page_is_ram(unsigned long);
extern unsigned long next_ram_page(unsigned long);

#define platform_timestamp(x) ({ x = ia64_get_itc(); })

#define platform_fix_regs()					\
{								\
	struct unw_frame_info *info = platform_arg;		\
								\
	current->thread.ksp = (__u64)info->sw - 16;		\
	myregs = *regs;						\
}

#define platform_init_stack(stackptr) do { } while (0)
#define platform_cleanup_stack(stackptr) do { } while (0)

typedef asmlinkage void (*crashdump_func_t)(struct pt_regs *, void *);

/* Container to hold dump hander information */
struct dump_call_param {
	crashdump_func_t func;
	struct pt_regs	*regs;
};

static inline void platform_start_crashdump(void *stackptr,
					    crashdump_func_t dumpfunc,
					    struct pt_regs *regs)
{
	struct dump_call_param param;

	param.func = dumpfunc;
	param.regs = regs;
	unw_init_running(ia64_start_dump, &param);
}

#endif /* __KERNEL__ */

#endif /* _ASM_IA64_CRASHDUMP_H */

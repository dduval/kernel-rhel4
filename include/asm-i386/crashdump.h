#ifndef _ASM_I386_CRASHDUMP_H
#define _ASM_I386_CRASHDUMP_H

/*
 * linux/include/asm-i386/crashdump.h
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
 *
 */

#ifdef __KERNEL__

#include <asm/irq.h>

extern int page_is_ram (unsigned long);
extern unsigned long next_ram_page (unsigned long);

#define platform_timestamp(x) rdtscll(x)

#define platform_fix_regs()						\
{									\
       unsigned long esp;						\
       unsigned short ss;						\
       esp = (unsigned long) ((char *)regs + sizeof (struct pt_regs));	\
       ss = __KERNEL_DS;						\
       if (regs->xcs & 3) {						\
               esp = regs->esp;						\
               ss = regs->xss & 0xffff;					\
       }								\
       myregs = *regs;							\
       myregs.esp = esp;						\
       myregs.xss = (myregs.xss & 0xffff0000) | ss;			\
};

static inline void platform_init_stack(void **stackptr)
{
#ifdef CONFIG_4KSTACKS
	*stackptr = (void *)kmalloc(sizeof(union irq_ctx), GFP_KERNEL);
	if (*stackptr)
		memset(*stackptr, 0, sizeof(union irq_ctx));
	else
		printk(KERN_WARNING
		       "crashdump: unable to allocate separate stack\n");
#else
	*stackptr = NULL;
#endif
}

typedef asmlinkage void (*crashdump_func_t)(struct pt_regs *, void *);

static inline void platform_start_crashdump(void *stackptr,
					   crashdump_func_t dumpfunc,
					   struct pt_regs *regs)
{
#ifdef CONFIG_4KSTACKS
	u32 *dsp;
	union irq_ctx * curctx;
	union irq_ctx * dumpctx;

	if (!stackptr)
		dumpfunc(regs, NULL);
	else {
		curctx = (union irq_ctx *) current_thread_info();
		dumpctx = (union irq_ctx *) stackptr;

		/* build the stack frame on the IRQ stack */
		dsp = (u32*) ((char*)dumpctx + sizeof(*dumpctx));
		dumpctx->tinfo.task = curctx->tinfo.task;
		dumpctx->tinfo.cpu = curctx->tinfo.cpu;
		dumpctx->tinfo.real_stack = curctx->tinfo.real_stack;
		dumpctx->tinfo.virtual_stack = curctx->tinfo.virtual_stack;
		dumpctx->tinfo.previous_esp = current_stack_pointer();

		*--dsp = (u32) NULL;
		*--dsp = (u32) regs;

		asm volatile(
			"       xchgl   %%ebx,%%esp     \n"
			"	call    *%%eax          \n"
			"	xchgl   %%ebx,%%esp     \n"
			: : "a"(dumpfunc), "b"(dsp)
			: "memory", "cc", "edx", "ecx"
		);
	}
#else
	dumpfunc(regs, NULL);
#endif

}

#define platform_cleanup_stack(stackptr)	\
do {						\
	if (stackptr)				\
		kfree(stackptr);		\
} while (0)

#define platform_freeze_cpu()					\
{								\
	for (;;) local_irq_disable();				\
}


#endif /* __KERNEL__ */

#endif /* _ASM_I386_CRASHDUMP_H */

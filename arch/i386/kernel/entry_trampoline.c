/*
 * linux/arch/i386/kernel/entry_trampoline.c
 *
 * (C) Copyright 2003 Ingo Molnar
 *
 * This file contains the needed support code for 4GB userspace
 */

#include <linux/init.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <asm/desc.h>
#include <asm/atomic_kmap.h>

extern char __entry_tramp_start, __entry_tramp_end, __start___entry_text;

void __init init_entry_mappings(void)
{
#ifdef CONFIG_X86_HIGH_ENTRY

	void *tramp;
	int p;

	/*
	 * We need a high IDT and GDT for the 4G/4G split:
	 */
	trap_init_virtual_IDT();

	__set_fixmap(FIX_ENTRY_TRAMPOLINE_0, __pa((unsigned long)&__entry_tramp_start), PAGE_KERNEL_EXEC);
	__set_fixmap(FIX_ENTRY_TRAMPOLINE_1, __pa((unsigned long)&__entry_tramp_start) + PAGE_SIZE, PAGE_KERNEL_EXEC);
	tramp = (void *)fix_to_virt(FIX_ENTRY_TRAMPOLINE_0);

	printk("mapped 4G/4G trampoline to %p.\n", tramp);
	BUG_ON((void *)&__start___entry_text != tramp);
	/*
	 * Virtual kernel stack:
	 */
	BUG_ON(__kmap_atomic_vaddr(KM_VSTACK_TOP) & (THREAD_SIZE-1));
	BUG_ON(sizeof(struct desc_struct)*NR_CPUS*GDT_ENTRIES > 2*PAGE_SIZE);
	BUG_ON((unsigned int)&__entry_tramp_end - (unsigned int)&__entry_tramp_start > 2*PAGE_SIZE);

	/*
	 * set up the initial thread's virtual stack related
	 * fields:
	 */
	for (p = 0; p < ARRAY_SIZE(current->thread.stack_page); p++)
		current->thread.stack_page[p] = virt_to_page((char *)current->thread_info + (p*PAGE_SIZE));

	current->thread_info->virtual_stack = (void *)__kmap_atomic_vaddr(KM_VSTACK_TOP);

	for (p = 0; p < ARRAY_SIZE(current->thread.stack_page); p++) {
		__kunmap_atomic_type(KM_VSTACK_TOP-p);
		__kmap_atomic(current->thread.stack_page[p], KM_VSTACK_TOP-p);
	}
#endif
	current->thread_info->real_stack = (void *)current->thread_info;
	current->thread_info->user_pgd = NULL;
	current->thread.esp0 = (unsigned long)current->thread_info->real_stack + THREAD_SIZE;
}



void __init entry_trampoline_setup(void)
{
	/*
	 * old IRQ entries set up by the boot code will still hang
	 * around - they are a sign of hw trouble anyway, now they'll
	 * produce a double fault message.
	 */
	trap_init_virtual_GDT();
}

/*
 * linux/kernel/ldt.c
 *
 * Copyright (C) 1992 Krishna Balasubramanian and Linus Torvalds
 * Copyright (C) 1999, 2003 Ingo Molnar <mingo@redhat.com>
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/ldt.h>
#include <asm/desc.h>
#include <linux/highmem.h>
#include <asm/atomic_kmap.h>

#ifdef CONFIG_SMP /* avoids "defined but not used" warnig */
static void flush_ldt(void *null)
{
	if (current->active_mm)
		load_LDT(&current->active_mm->context);
}
#endif

static int alloc_ldt(mm_context_t *pc, int mincount, int reload)
{
	int oldsize, newsize, i;

	if (mincount <= pc->size)
		return 0;
	/*
	 * LDT got larger - reallocate if necessary.
	 */
	oldsize = pc->size;
	mincount = (mincount+511)&(~511);
	newsize = mincount*LDT_ENTRY_SIZE;
	for (i = 0; i < newsize; i += PAGE_SIZE) {
		int nr = i/PAGE_SIZE;
		BUG_ON(i >= 64*1024);
		if (!pc->ldt_pages[nr]) {
			pc->ldt_pages[nr] = alloc_page(GFP_HIGHUSER);
			if (!pc->ldt_pages[nr])
				return -ENOMEM;
			clear_highpage(pc->ldt_pages[nr]);
		}
	}
	pc->size = mincount;
	if (reload) {
#ifdef CONFIG_SMP
		cpumask_t mask;

		local_irq_disable();
		load_LDT(pc);
		local_irq_enable();
		preempt_disable();
		mask = cpumask_of_cpu(smp_processor_id());
		if (!cpus_equal(current->mm->cpu_vm_mask, mask))
			smp_call_function(flush_ldt, NULL, 1, 1);
		preempt_enable();
#else
		load_LDT(pc);
#endif
	}
	return 0;
}

static inline int copy_ldt(mm_context_t *new, mm_context_t *old)
{
	int i, err, size = old->size, nr_pages = (size*LDT_ENTRY_SIZE + PAGE_SIZE-1)/PAGE_SIZE;

	err = alloc_ldt(new, size, 0);
	if (err < 0) {
		new->size = 0;
		return err;
	}
	for (i = 0; i < nr_pages; i++)
		copy_user_highpage(new->ldt_pages[i], old->ldt_pages[i], 0);
	return 0;
}

/*
 * we do not have to muck with descriptors here, that is
 * done in switch_mm() as needed.
 */
int init_new_context(struct task_struct *tsk, struct mm_struct *mm)
{
	struct mm_struct * old_mm;
	int retval = 0;

	init_MUTEX(&mm->context.sem);
	mm->context.size = 0;
	memset(mm->context.ldt_pages, 0, sizeof(struct page *) * MAX_LDT_PAGES);
	old_mm = current->mm;
	if (old_mm && old_mm->context.size > 0) {
		down(&old_mm->context.sem);
		retval = copy_ldt(&mm->context, &old_mm->context);
		up(&old_mm->context.sem);
	}
	return retval;
}

/*
 * No need to lock the MM as we are the last user
 * Do not touch the ldt register, we are already
 * in the next thread.
 */
void destroy_context(struct mm_struct *mm)
{
	int i, nr_pages = (mm->context.size*LDT_ENTRY_SIZE + PAGE_SIZE-1) / PAGE_SIZE;

	for (i = 0; i < nr_pages; i++)
		__free_page(mm->context.ldt_pages[i]);
	mm->context.size = 0;
}

static int read_ldt(void __user * ptr, unsigned long bytecount)
{
	int err, i;
	unsigned long size;
	struct mm_struct * mm = current->mm;

	if (!mm->context.size)
		return 0;
	if (bytecount > LDT_ENTRY_SIZE*LDT_ENTRIES)
		bytecount = LDT_ENTRY_SIZE*LDT_ENTRIES;

	down(&mm->context.sem);
	size = mm->context.size*LDT_ENTRY_SIZE;
	if (size > bytecount)
		size = bytecount;

	err = 0;
	/*
	 * This is necessary just in case we got here straight from a
	 * context-switch where the ptes were set but no tlb flush
	 * was done yet. We rather avoid doing a TLB flush in the
	 * context-switch path and do it here instead.
	 */
	__flush_tlb_global();

	for (i = 0; i < size; i += PAGE_SIZE) {
		int nr = i / PAGE_SIZE, bytes;
		char *kaddr = kmap(mm->context.ldt_pages[nr]);

		bytes = size - i;
		if (bytes > PAGE_SIZE)
			bytes = PAGE_SIZE;
		if (copy_to_user(ptr + i, kaddr, bytes))
			err = -EFAULT;
		kunmap(mm->context.ldt_pages[nr]);
	}
	up(&mm->context.sem);
	if (err < 0)
		goto error_return;
	if (size != bytecount) {
		/* zero-fill the rest */
		if (clear_user(ptr+size, bytecount-size) != 0) {
			err = -EFAULT;
			goto error_return;
		}
	}
	return bytecount;
error_return:
	return err;
}

static int read_default_ldt(void __user * ptr, unsigned long bytecount)
{
	int err;
	unsigned long size;
	void *address;

	err = 0;
	address = &default_ldt[0];
	size = 5*LDT_ENTRY_SIZE;
	if (size > bytecount)
		size = bytecount;

	err = size;
	if (copy_to_user(ptr, address, size))
		err = -EFAULT;

	return err;
}

static int write_ldt(void __user * ptr, unsigned long bytecount, int oldmode)
{
	struct mm_struct * mm = current->mm;
	__u32 entry_1, entry_2, *lp;
	int error;
	struct user_desc ldt_info;

	error = -EINVAL;
	if (bytecount != sizeof(ldt_info))
		goto out;
	error = -EFAULT; 	
	if (copy_from_user(&ldt_info, ptr, sizeof(ldt_info)))
		goto out;

	error = -EINVAL;
	if (ldt_info.entry_number >= LDT_ENTRIES)
		goto out;
	if (ldt_info.contents == 3) {
		if (oldmode)
			goto out;
		if (ldt_info.seg_not_present == 0)
			goto out;
	}

	down(&mm->context.sem);
	if (ldt_info.entry_number >= mm->context.size) {
		error = alloc_ldt(&current->mm->context, ldt_info.entry_number+1, 1);
		if (error < 0)
			goto out_unlock;
	}

	/*
	 * No rescheduling allowed from this point to the install.
	 *
	 * We do a TLB flush for the same reason as in the read_ldt() path.
	 */
	preempt_disable();
	__flush_tlb_global();
	lp = (__u32 *) ((ldt_info.entry_number << 3) +
			(char *) __kmap_atomic_vaddr(KM_LDT_PAGE0));

   	/* Allow LDTs to be cleared by the user. */
   	if (ldt_info.base_addr == 0 && ldt_info.limit == 0) {
		if (oldmode || LDT_empty(&ldt_info)) {
			entry_1 = 0;
			entry_2 = 0;
			goto install;
		}
	}

	entry_1 = LDT_entry_a(&ldt_info);
	entry_2 = LDT_entry_b(&ldt_info);
	if (oldmode)
		entry_2 &= ~(1 << 20);

	/* Install the new entry ...  */
install:
	*lp	= entry_1;
	*(lp+1)	= entry_2;
	error = 0;
	preempt_enable();

out_unlock:
	up(&mm->context.sem);
out:
	return error;
}

asmlinkage int sys_modify_ldt(int func, void __user *ptr, unsigned long bytecount)
{
	int ret = -ENOSYS;

	switch (func) {
	case 0:
		ret = read_ldt(ptr, bytecount);
		break;
	case 1:
		ret = write_ldt(ptr, bytecount, 1);
		break;
	case 2:
		ret = read_default_ldt(ptr, bytecount);
		break;
	case 0x11:
		ret = write_ldt(ptr, bytecount, 0);
		break;
	}
	return ret;
}

/*
 * load one particular LDT into the current CPU
 */
void load_LDT_nolock(mm_context_t *pc, int cpu)
{
	struct page **pages = pc->ldt_pages;
	int count = pc->size;
	int nr_pages, i;

	if (likely(!count)) {
		pages = &default_ldt_page;
		count = 5;
	}
       	nr_pages = (count*LDT_ENTRY_SIZE + PAGE_SIZE-1) / PAGE_SIZE;

	for (i = 0; i < nr_pages; i++) {
		__kunmap_atomic_type(KM_LDT_PAGE0 - i);
		__kmap_atomic(pages[i], KM_LDT_PAGE0 - i);
	}
	set_ldt_desc(cpu, (void *)__kmap_atomic_vaddr(KM_LDT_PAGE0), count);
	load_LDT_desc();
}

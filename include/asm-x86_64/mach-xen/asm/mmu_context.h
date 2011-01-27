#ifndef __X86_64_MMU_CONTEXT_H
#define __X86_64_MMU_CONTEXT_H

#include <linux/config.h>
#include <asm/desc.h>
#include <asm/atomic.h>
#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/pda.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

/*
 * possibly do the LDT unload here?
 */
int init_new_context(struct task_struct *tsk, struct mm_struct *mm);
void destroy_context(struct mm_struct *mm);

#if defined(CONFIG_SMP) && !defined(CONFIG_XEN)

static inline void enter_lazy_tlb(struct mm_struct *mm, struct task_struct *tsk)
{
	if (read_pda(mmu_state) == TLBSTATE_OK) 
		write_pda(mmu_state, TLBSTATE_LAZY);
}
#else
static inline void enter_lazy_tlb(struct mm_struct *mm, struct task_struct *tsk)
{
}
#endif

#define prepare_arch_switch(prev, next)	__prepare_arch_switch()
# define finish_arch_switch(rq, next)	spin_unlock_irq(&(rq)->lock)
# define task_running(rq, p)		((rq)->curr == (p))

static inline void __prepare_arch_switch(void)
{
	/*
	 * Save away %es, %ds, %fs and %gs. Must happen before reload
	 * of cr3/ldt (i.e., not in __switch_to).
	 */
	__asm__ __volatile__ (
		"mov %%es,%0 ; mov %%ds,%1 ; mov %%fs,%2 ; mov %%gs,%3"
		: "=m" (current->thread.es),
		  "=m" (current->thread.ds),
		  "=m" (current->thread.fsindex),
		  "=m" (current->thread.gsindex) );

	if (current->thread.ds)
		__asm__ __volatile__ ( "movl %0,%%ds" : : "r" (0) );

	if (current->thread.es)
		__asm__ __volatile__ ( "movl %0,%%es" : : "r" (0) );

	if (current->thread.fsindex) {
		__asm__ __volatile__ ( "movl %0,%%fs" : : "r" (0) );
		current->thread.fs = 0;
	}

	if (current->thread.gsindex) {
		load_gs_index(0);
		current->thread.gs = 0;
	}
}

extern void mm_pin(struct mm_struct *mm);
extern void mm_unpin(struct mm_struct *mm);
void mm_pin_all(void);

static inline void switch_mm(struct mm_struct *prev, struct mm_struct *next, 
			     struct task_struct *tsk)
{
	unsigned cpu = smp_processor_id();
	struct mmuext_op _op[3], *op = _op;
	pml4_t *pml4;

	if (likely(prev != next)) {
		if (!next->context.pinned)
			mm_pin(next);

		/* stop flush ipis for the previous mm */
		clear_bit(cpu, &prev->cpu_vm_mask);
#if defined(CONFIG_SMP) && !defined(CONFIG_XEN)
		write_pda(mmu_state, TLBSTATE_OK);
		write_pda(active_mm, next);
#endif
		set_bit(cpu, &next->cpu_vm_mask);
		/* Re-load page tables */
		pml4 = (pml4_t*)read_pda(level4_pgt);
		set_pml4(pml4, mk_pml4(__pa(next->pgd)));
		set_pml4(__user_pml4(pml4), mk_pml4(__pa(next->pgd)));

		/* load_cr3(pml4) */
		op->cmd = MMUEXT_NEW_BASEPTR;
		op->arg1.mfn = pfn_to_mfn(__pa(pml4) >> PAGE_SHIFT);
		op++;

		/* xen_new_user_pt(__pa(__user_pml4(pml4))) */
		op->cmd = MMUEXT_NEW_USER_BASEPTR;
		op->arg1.mfn = pfn_to_mfn(__pa(__user_pml4(pml4)) >> PAGE_SHIFT);
		op++;

		if (unlikely(next->context.ldt != prev->context.ldt)) {
			/* load_LDT_nolock(&next->context, cpu); */
			op->cmd = MMUEXT_SET_LDT;
			op->arg1.linear_addr = (unsigned long)next->context.ldt;
			op->arg2.nr_ents     = next->context.size;
			op++;
		}

		BUG_ON(HYPERVISOR_mmuext_op(_op, op-_op, NULL, DOMID_SELF));
	}
#if defined(CONFIG_SMP) && !defined(CONFIG_XEN)
	else {
		write_pda(mmu_state, TLBSTATE_OK);
		if (read_pda(active_mm) != next)
			out_of_line_bug();
		if(!test_and_set_bit(cpu, &next->cpu_vm_mask)) {
			/* We were in lazy tlb mode and leave_mm disabled 
			 * tlb flush IPI delivery. We must flush our tlb.
			 */
			local_flush_tlb();
			load_LDT_nolock(&next->context, cpu);
		}
	}
#endif
}

#define deactivate_mm(tsk,mm)	do { \
	load_gs_index(0); \
	asm volatile("movl %0,%%fs"::"r"(0));  \
} while(0)

#define activate_mm(prev, next) do {		\
	switch_mm((prev),(next),NULL);		\
} while (0)


#endif

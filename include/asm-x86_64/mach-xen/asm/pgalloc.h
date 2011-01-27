#ifndef _X86_64_PGALLOC_H
#define _X86_64_PGALLOC_H

#include <asm/fixmap.h>
#include <asm/pda.h>
#include <linux/threads.h>
#include <linux/mm.h>
#include <asm/io.h>		/* for phys_to_virt and page_to_pseudophys */

#include <xen/features.h>

#define arch_add_exec_range(mm, limit) do { ; } while (0)
#define arch_flush_exec_range(mm)      do { ; } while (0)
#define arch_remove_exec_range(mm, limit) do { ; } while (0)

void make_page_readonly(void *va, unsigned int feature);
void make_page_writable(void *va, unsigned int feature);
void make_pages_readonly(void *va, unsigned int nr, unsigned int feature);
void make_pages_writable(void *va, unsigned int nr, unsigned int feature);

#define __user_pgd(pgd) ((pgd) + PTRS_PER_PGD)

static inline void pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte)
{
	set_pmd(pmd, __pmd(_PAGE_TABLE | __pa(pte)));
}

static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd, struct page *pte)
{
	if (unlikely((mm)->context.pinned)) {
		BUG_ON(HYPERVISOR_update_va_mapping(
			       (unsigned long)__va(page_to_pfn(pte) << PAGE_SHIFT),
			       pfn_pte(page_to_pfn(pte), PAGE_KERNEL_RO), 0));
		set_pmd(pmd, __pmd(_PAGE_TABLE | (page_to_pfn(pte) << PAGE_SHIFT)));
	} else {
		*(pmd) = __pmd(_PAGE_TABLE | (page_to_pfn(pte) << PAGE_SHIFT));
	}
}

/*
 * We need to use the batch mode here, but pgd_populate() won't be
 * be called frequently.
 */
static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, pmd_t *pmd)
{
	if (unlikely((mm)->context.pinned)) {
		BUG_ON(HYPERVISOR_update_va_mapping(
			       (unsigned long)pmd,
			       pfn_pte(virt_to_phys(pmd)>>PAGE_SHIFT, 
				       PAGE_KERNEL_RO), 0));
		set_pgd(pgd, __pgd(_PAGE_TABLE | __pa(pmd)));
	} else {
		*(pgd) =  __pgd(_PAGE_TABLE | __pa(pmd));
	}
}

static inline void pmd_free(pmd_t *pmd)
{
	pte_t *ptep = virt_to_ptep(pmd);

	if (!pte_write(*ptep)) {
		BUG_ON(HYPERVISOR_update_va_mapping(
			(unsigned long)pmd,
			pfn_pte(virt_to_phys(pmd)>>PAGE_SHIFT, PAGE_KERNEL),
			0));
	}
	free_page((unsigned long)pmd);
}

static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
        pmd_t *pmd = (pmd_t *) get_zeroed_page(GFP_KERNEL|__GFP_REPEAT);
        return pmd;
}

/*
 * HACK: Xen can only pin 1st and 4th level page tables, so each
 * process has its own user PML4 for now.  The PGD (3rd level)
 * is the first page, the PML4 the second page.
 */
static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
	pgd_t * pgd = (pgd_t *) __get_free_pages(GFP_KERNEL|__GFP_REPEAT, 1);
	if (pgd) {
		clear_page(pgd);
		clear_page(pgd + PTRS_PER_PGD);
	}
	return pgd;
}

static inline void pgd_free(pgd_t *pgd)
{
	pte_t *ptep = virt_to_ptep(pgd);

	if (!pte_write(*ptep)) {
		pml4_t * pml4 = (pml4_t *)  pgd + PTRS_PER_PGD;
		set_pml4(pml4, __pml4(0));
		xen_pgd_unpin(__pa(pml4));
		make_page_writable(pml4, XENFEAT_writable_page_tables);
		make_page_writable(pgd, XENFEAT_writable_page_tables);
	}

	free_pages((unsigned long)pgd, 1);
}

static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm, unsigned long address)
{
        pte_t *pte = (pte_t *)get_zeroed_page(GFP_KERNEL|__GFP_REPEAT);
        if (pte)
		make_page_readonly(pte, XENFEAT_writable_page_tables);

	return pte;
}

static inline struct page *pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
	struct page *pte;

	pte = alloc_pages(GFP_KERNEL|__GFP_REPEAT, 0);
	if (pte)
		clear_page(page_address(pte));
	return pte;
}

/* Should really implement gc for free page table pages. This could be
   done with a reference count in struct page. */

static inline void pte_free_kernel(pte_t *pte)
{
	BUG_ON((unsigned long)pte & (PAGE_SIZE-1));
        make_page_writable(pte, XENFEAT_writable_page_tables);
	free_page((unsigned long)pte); 
}

extern void pte_free(struct page *pte);

//#define __pte_free_tlb(tlb,pte) tlb_remove_page((tlb),(pte)) 
//#define __pmd_free_tlb(tlb,x)   tlb_remove_page((tlb),virt_to_page(x))

#define __pte_free_tlb(tlb,x)   pte_free((x))
#define __pmd_free_tlb(tlb,x)   pmd_free((x))

#endif /* _X86_64_PGALLOC_H */

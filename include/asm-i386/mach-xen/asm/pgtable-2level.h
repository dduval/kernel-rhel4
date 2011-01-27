#ifndef _I386_PGTABLE_2LEVEL_H
#define _I386_PGTABLE_2LEVEL_H

#define pte_ERROR(e) \
	printk("%s:%d: bad pte %08lx.\n", __FILE__, __LINE__, (e).pte_low)
#define pmd_ERROR(e) \
	printk("%s:%d: bad pmd %08lx.\n", __FILE__, __LINE__, pmd_val(e))
#define pgd_ERROR(e) \
	printk("%s:%d: bad pgd %08lx.\n", __FILE__, __LINE__, pgd_val(e))

/*
 * The "pgd_xxx()" functions here are trivial for a folded two-level
 * setup: the pgd is never bad, and a pmd always exists (as it's folded
 * into the pgd entry)
 */
static inline int pgd_none(pgd_t pgd)		{ return 0; }
static inline int pgd_bad(pgd_t pgd)		{ return 0; }
static inline int pgd_present(pgd_t pgd)	{ return 1; }
#define pgd_clear(xp)				do { } while (0)

/*
 * Certain architectures need to do special things when PTEs
 * within a page table are directly modified.  Thus, the following
 * hook is made available.
 */
static inline void set_pte(pte_t *pteptr, pte_t pte)
{
	mm_track(pteptr);
	*(pteptr) = pte;
}

#define set_pte_at(_mm,addr,ptep,pteval) do {				\
	if (((_mm) != current->mm && (_mm) != &init_mm) ||		\
	    HYPERVISOR_update_va_mapping((addr), (pteval), 0))		\
		set_pte((ptep), (pteval));				\
} while (0)

#define set_pte_at_sync(_mm,addr,ptep,pteval) do {			\
	if (((_mm) != current->mm && (_mm) != &init_mm) ||		\
	    HYPERVISOR_update_va_mapping((addr), (pteval), UVMF_INVLPG)) { \
		set_pte((ptep), (pteval));				\
		xen_invlpg((addr));					\
	}								\
} while (0)

extern void xen_l2_entry_update(pmd_t *ptr, pmd_t val);

#define set_pte_atomic(pteptr, pteval) set_pte(pteptr,pteval)
/*
 * (pmds are folded into pgds so this doesn't get actually called,
 * but the define is needed for a generic inline function.)
 */
static inline void set_pmd(pmd_t *pmdptr, pmd_t pmd)
{
 	mm_track(pmdptr);
	xen_l2_entry_update((pmdptr), (pmd));
}

#define pte_clear(xp)	do { set_pte(xp, __pte(0)); } while (0)

#define set_pgd(pgdptr, pgdval) (*(pgdptr) = pgdval)

#define pgd_page(pgd) \
((unsigned long) __va(pgd_val(pgd) & PAGE_MASK))

static inline pmd_t * pmd_offset(pgd_t * dir, unsigned long address)
{
	return (pmd_t *) dir;
}
static inline pte_t ptep_get_and_clear(pte_t *ptep)
{
	mm_track(ptep);
	return __pte_ma(xchg(&(ptep)->pte_low, 0));
}
#define __pte_mfn(_pte) ((_pte).pte_low >> PAGE_SHIFT)
#define pte_mfn(_pte) ((_pte).pte_low & _PAGE_PRESENT ? \
	__pte_mfn(_pte) : pfn_to_mfn(__pte_mfn(_pte)))
#define pte_pfn(_pte) ((_pte).pte_low & _PAGE_PRESENT ? \
	mfn_to_local_pfn(__pte_mfn(_pte)) : __pte_mfn(_pte))

#define pte_page(x)		pfn_to_page(pte_pfn(x))
#define pte_none(x)		(!(x).pte_low)
#define pfn_pte(pfn, prot)	__pte(((pfn) << PAGE_SHIFT) | pgprot_val(prot))
#define pfn_pmd(pfn, prot)	__pmd(((pfn) << PAGE_SHIFT) | pgprot_val(prot))

/*
 * All present user pages are user-executable:
 */
static inline int pte_exec(pte_t pte)
{
	return pte_user(pte);
}

/*
 * All present pages are kernel-executable:
 */
static inline int pte_exec_kernel(pte_t pte)
{
	return 1;
}

/*
 * Bits 0, 6 and 7 are taken, split up the 29 bits of offset
 * into this range:
 */
#define PTE_FILE_MAX_BITS	29

#define pte_to_pgoff(pte) \
	((((pte).pte_low >> 1) & 0x1f ) + (((pte).pte_low >> 8) << 5 ))

#define pgoff_to_pte(off) \
	((pte_t) { (((off) & 0x1f) << 1) + (((off) >> 5) << 8) + _PAGE_FILE })

/* Encode and de-code a swap entry */
#define __swp_type(x)			(((x).val >> 1) & 0x1f)
#define __swp_offset(x)			((x).val >> 8)
#define __swp_entry(type, offset)	((swp_entry_t) { ((type) << 1) | ((offset) << 8) })
#define __pte_to_swp_entry(pte)		((swp_entry_t) { (pte).pte_low })
#define __swp_entry_to_pte(x)		((pte_t) { (x).val })

#endif /* _I386_PGTABLE_2LEVEL_H */

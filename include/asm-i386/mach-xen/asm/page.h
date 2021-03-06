#ifndef _I386_PAGE_H
#define _I386_PAGE_H

#include <linux/config.h>

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

#ifdef CONFIG_X86_PAE
#define __PHYSICAL_MASK_SHIFT	40
#define __PHYSICAL_MASK		((1ULL << __PHYSICAL_MASK_SHIFT) - 1)
#define PHYSICAL_PAGE_MASK	(~((1ULL << PAGE_SHIFT) - 1) & __PHYSICAL_MASK)
#else
#define __PHYSICAL_MASK_SHIFT	32
#define __PHYSICAL_MASK		(~0UL)
#define PHYSICAL_PAGE_MASK	(PAGE_MASK & __PHYSICAL_MASK)
#endif

#define LARGE_PAGE_MASK (~(LARGE_PAGE_SIZE-1))
#define LARGE_PAGE_SIZE (1UL << PMD_SHIFT)

#ifdef __KERNEL__
#ifndef __ASSEMBLY__
#include <linux/config.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/bug.h>
#include <xen/interface/xen.h>
#include <xen/features.h>
#include <xen/foreign_page.h>

/*
 * Need to repeat this here in order to not include pgtable.h (which in turn
 * depends on definitions made here), but to be able to use the symbolic
 * below. The preprocessor will warn if the two definitions aren't identical.
 */
#define _PAGE_PRESENT	0x001

#define arch_free_page(_page,_order)			\
({	int foreign = PageForeign(_page);		\
	if (foreign)					\
		(PageForeignDestructor(_page))(_page);	\
	foreign;					\
})
#define HAVE_ARCH_FREE_PAGE

#ifdef CONFIG_X86_USE_3DNOW

#include <asm/mmx.h>

#define clear_page(page)	mmx_clear_page((void *)(page))
#define copy_page(to,from)	mmx_copy_page(to,from)

#else
/*
 *	On older X86 processors it's not a win to use MMX here it seems.
 *	Maybe the K6-III ?
 */
 
#define clear_page(page)	memset((void *)(page), 0, PAGE_SIZE)
#define copy_page(to,from)	memcpy((void *)(to), (void *)(from), PAGE_SIZE)

#endif

#define clear_user_page(page, vaddr, pg)	clear_page(page)
#define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)

/*
 * These are used to make use of C type-checking..
 */
#ifdef CONFIG_X86_PAE
extern unsigned long long __supported_pte_mask;
extern int nx_enabled;
typedef struct { unsigned long pte_low, pte_high; } pte_t;
typedef struct { unsigned long long pmd; } pmd_t;
typedef struct { unsigned long long pgd; } pgd_t;
typedef struct { unsigned long long pgprot; } pgprot_t;
#define pgprot_val(x)	((x).pgprot)
#include <asm/maddr.h>
#define __pte(x) ({ unsigned long long _x = (x);        \
    if (_x & _PAGE_PRESENT) _x = pte_phys_to_machine(_x);               \
    ((pte_t) {(unsigned long)(_x), (unsigned long)(_x>>32)}); })
#define __pgd(x) ({ unsigned long long _x = (x); \
    (pgd_t) {((_x) & _PAGE_PRESENT) ? pte_phys_to_machine(_x) : (_x)}; })
#define __pmd(x) ({ unsigned long long _x = (x); \
    (pmd_t) {((_x) & _PAGE_PRESENT) ? pte_phys_to_machine(_x) : (_x)}; })
static inline unsigned long long pte_val_ma(pte_t x)
{
	return ((unsigned long long)x.pte_high << 32) | x.pte_low;
}
static inline unsigned long long pte_val(pte_t x)
{
	unsigned long long ret = pte_val_ma(x);
	if (x.pte_low & _PAGE_PRESENT) ret = pte_machine_to_phys(ret);
	return ret;
}
static inline unsigned long long pmd_val(pmd_t x)
{
	unsigned long long ret = x.pmd;
#ifdef CONFIG_XEN_COMPAT_030002
	if (ret) ret = pte_machine_to_phys(ret) | _PAGE_PRESENT;
#else
	if (ret & _PAGE_PRESENT) ret = pte_machine_to_phys(ret);
#endif
	return ret;
}
static inline unsigned long long pgd_val(pgd_t x)
{
	unsigned long long ret = x.pgd;
	if (ret & _PAGE_PRESENT) ret = pte_machine_to_phys(ret);
	return ret;
}
#define HPAGE_SHIFT	21
#else /* !CONFIG_X86_PAE */
#define nx_enabled 0
typedef struct { unsigned long pte_low; } pte_t;
typedef struct { unsigned long pmd; } pmd_t;
typedef struct { unsigned long pgd; } pgd_t;
typedef struct { unsigned long pgprot; } pgprot_t;
#define pgprot_val(x)	((x).pgprot)
#include <asm/maddr.h>
#define boot_pte_t pte_t /* or would you rather have a typedef */
#define pte_val(x)	(((x).pte_low & _PAGE_PRESENT) ? \
                         machine_to_phys((x).pte_low) : \
			 (x).pte_low)
#define pte_val_ma(x)	((x).pte_low)
#define __pte(x) ({ unsigned long _x = (x); \
    (pte_t) {((_x) & _PAGE_PRESENT) ? phys_to_machine(_x) : (_x)}; })
#define __pgd(x) ({ unsigned long _x = (x); \
    (pgd_t) {((_x) & _PAGE_PRESENT) ? phys_to_machine(_x) : (_x)}; })
static inline unsigned long pgd_val(pgd_t x)
{
	unsigned long ret = x.pgd;
#if CONFIG_XEN_COMPAT <= 0x030002
	if (ret) ret = machine_to_phys(ret) | _PAGE_PRESENT;
#else
	if (ret & _PAGE_PRESENT) ret = machine_to_phys(ret);
#endif
	return ret;
}
#define HPAGE_SHIFT	22

#ifdef CONFIG_XEN
static inline unsigned long pmd_val(pmd_t x)
{
	unsigned long ret = x.pmd;
	if (ret) ret = machine_to_phys(ret) | 1;
	return ret;
}

static inline unsigned long long pmd_val_ma(pmd_t x)
{
	return x.pmd;
}

#define __pmd(x) ({ unsigned long _x = (x); \
	(((_x)&1) ? ((pmd_t) {phys_to_machine(_x)}) : ((pmd_t) {(_x)})); })
#endif /* CONFIG_XEN */
#endif /* CONFIG_X86_PAE */
#define PTE_MASK	PHYSICAL_PAGE_MASK

#ifdef CONFIG_HUGETLB_PAGE
#define HPAGE_SIZE	((1UL) << HPAGE_SHIFT)
#define HPAGE_MASK	(~(HPAGE_SIZE - 1))
#define HUGETLB_PAGE_ORDER	(HPAGE_SHIFT - PAGE_SHIFT)
#define HAVE_ARCH_HUGETLB_UNMAPPED_AREA
#endif

#define __pgprot(x)	((pgprot_t) { (x) } )

#endif /* !__ASSEMBLY__ */

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)	(((addr)+PAGE_SIZE-1)&PAGE_MASK)

/*
 * This handles the memory map.. We could make this a config
 * option, but too many people screw it up, and too few need
 * it.
 *
 * A __PAGE_OFFSET of 0xC0000000 means that the kernel has
 * a virtual address space of one gigabyte, which limits the
 * amount of physical memory you can use to about 950MB. 
 *
 * If you want more physical memory than this then see the CONFIG_HIGHMEM4G
 * and CONFIG_HIGHMEM64G options in the kernel configuration.
 *
 * Note: on PAE the kernel must never go below 32 MB, we use the
 * first 8 entries of the 2-level boot pgd for PAE magic.
 */

#ifdef CONFIG_X86_4G_VM_LAYOUT
#define __PAGE_OFFSET		(0x02000000)
#define TASK_SIZE		((current->personality & 0x8000000) ? 0xc0000000 : 0xff000000)
#else
#define __PAGE_OFFSET		(0xc0000000)
#define TASK_SIZE		(0xc0000000)
#endif

#ifndef __ASSEMBLY__
#define __PHYSICAL_START	(0x100000UL)
#else
#define __PHYSICAL_START	(0x100000)
#endif

#ifndef __ASSEMBLY__

/*
 * This much address space is reserved for vmalloc() and iomap()
 * as well as fixmap mappings.
 */
extern unsigned int __VMALLOC_RESERVE;

/* Pure 2^n version of get_order */
static __inline__ int get_order(unsigned long size)
{
	int order;

	size = (size-1) >> (PAGE_SHIFT-1);
	order = -1;
	do {
		size >>= 1;
		order++;
	} while (size);
	return order;
}

extern int sysctl_legacy_va_layout;

extern int devmem_is_allowed(unsigned long pagenr);

#endif /* __ASSEMBLY__ */

#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)
#define VMALLOC_RESERVE		((unsigned long)__VMALLOC_RESERVE)
#define MAXMEM			(HYPERVISOR_VIRT_START-__PAGE_OFFSET-__VMALLOC_RESERVE)
#define __pa(x)			((unsigned long)(x)-PAGE_OFFSET)
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#define pfn_to_kaddr(pfn)      __va((pfn) << PAGE_SHIFT)
#ifndef CONFIG_DISCONTIGMEM
#define pfn_to_page(pfn)	(mem_map + (pfn))
#define page_to_pfn(page)	((unsigned long)((page) - mem_map))
#define pfn_valid(pfn)		((pfn) < max_mapnr)
#endif /* !CONFIG_DISCONTIGMEM */
#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)

#define virt_addr_valid(kaddr)	pfn_valid(__pa(kaddr) >> PAGE_SHIFT)

#define VM_DATA_DEFAULT_FLAGS \
	(VM_READ | VM_WRITE | \
	((current->personality & READ_IMPLIES_EXEC) ? VM_EXEC : 0 ) | \
		 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

/* VIRT <-> MACHINE conversion */
#define virt_to_machine(v)	(phys_to_machine(__pa(v)))
#define machine_to_virt(m)	(__va(machine_to_phys(m)))
#define virt_to_mfn(v)		(pfn_to_mfn(__pa(v) >> PAGE_SHIFT))
#define mfn_to_virt(m)		(__va(mfn_to_pfn(m) << PAGE_SHIFT))

#define __HAVE_ARCH_GATE_AREA 1

#endif /* __KERNEL__ */

#endif /* _I386_PAGE_H */

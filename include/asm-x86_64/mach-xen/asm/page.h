#ifndef _X86_64_PAGE_H
#define _X86_64_PAGE_H

#include <linux/config.h>
/* #include <linux/string.h> */
#ifndef __ASSEMBLY__
#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/bug.h>
#include <xen/features.h>
#endif
#include <xen/interface/xen.h> 
#include <xen/foreign_page.h>

#define arch_free_page(_page,_order)			\
({	int foreign = PageForeign(_page);		\
	if (foreign)					\
		(PageForeignDestructor(_page))(_page);	\
	foreign;					\
})
#define HAVE_ARCH_FREE_PAGE

#ifdef CONFIG_XEN_SCRUB_PAGES
#define scrub_pages(_p,_n) memset((void *)(_p), 0, (_n) << PAGE_SHIFT)
#else
#define scrub_pages(_p,_n) ((void)0)
#endif

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT	12
#ifdef __ASSEMBLY__
#define PAGE_SIZE	(0x1 << PAGE_SHIFT)
#else
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#endif
#define PAGE_MASK	(~(PAGE_SIZE-1))
/* See Documentation/x86_64/mm.txt for a description of the memory map. */
#define __PHYSICAL_MASK_SHIFT	40
#define __PHYSICAL_MASK		((1UL << __PHYSICAL_MASK_SHIFT) - 1)
#define __VIRTUAL_MASK_SHIFT	48	/* P3: Incorrect, we use 39 in RHEL 4 */
#define __VIRTUAL_MASK		((1UL << __VIRTUAL_MASK_SHIFT) - 1)
#define PHYSICAL_PAGE_MASK	(~(PAGE_SIZE-1) & (__PHYSICAL_MASK << PAGE_SHIFT))
#define PTE_MASK	PHYSICAL_PAGE_MASK

#define THREAD_ORDER 1 
#ifdef __ASSEMBLY__
#define THREAD_SIZE  (1 << (PAGE_SHIFT + THREAD_ORDER))
#else
#define THREAD_SIZE  (1UL << (PAGE_SHIFT + THREAD_ORDER))
#endif
#define CURRENT_MASK (~(THREAD_SIZE-1))

#define EXCEPTION_STACK_ORDER 0
#define EXCEPTION_STKSZ (PAGE_SIZE << EXCEPTION_STACK_ORDER)

#define DEBUG_STACK_ORDER (EXCEPTION_STACK_ORDER + 1)
#define DEBUG_STKSZ (PAGE_SIZE << DEBUG_STACK_ORDER)

#define IRQSTACK_ORDER 2
#define IRQSTACKSIZE (PAGE_SIZE << IRQSTACK_ORDER)

#define STACKFAULT_STACK 1
#define DOUBLEFAULT_STACK 2
#define NMI_STACK 3
#define DEBUG_STACK 4
#define MCE_STACK 5
#define N_EXCEPTION_STACKS 5  /* hw limit: 7 */

#define LARGE_PAGE_MASK (~(LARGE_PAGE_SIZE-1))
#define LARGE_PAGE_SIZE (1UL << PMD_SHIFT)

#define HPAGE_SHIFT PMD_SHIFT
#define HPAGE_SIZE	((1UL) << HPAGE_SHIFT)
#define HPAGE_MASK	(~(HPAGE_SIZE - 1))
#define HUGETLB_PAGE_ORDER	(HPAGE_SHIFT - PAGE_SHIFT)
#define HAVE_ARCH_HUGETLB_UNMAPPED_AREA

#ifdef __KERNEL__
#ifndef __ASSEMBLY__

extern unsigned long end_pfn;

#include <asm/maddr.h>

void clear_page(void *);
void copy_page(void *, void *);

#define clear_user_page(page, vaddr, pg)	clear_page(page)
#define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)

#define alloc_zeroed_user_highpage(vma, vaddr) alloc_page_vma(GFP_HIGHUSER | __GFP_ZERO, vma, vaddr)
#define __HAVE_ARCH_ALLOC_ZEROED_USER_HIGHPAGE

/*
 * These are used to make use of C type-checking..
 */
typedef struct { unsigned long pte; } pte_t;
typedef struct { unsigned long pmd; } pmd_t;
typedef struct { unsigned long pgd; } pgd_t;
typedef struct { unsigned long pml4; } pml4_t;

typedef struct { unsigned long pgprot; } pgprot_t;

static inline paddr_t pte_machine_to_phys(maddr_t machine)
{
	paddr_t phys = mfn_to_pfn((machine & PTE_MASK) >> PAGE_SHIFT);
	phys = (phys << PAGE_SHIFT) | (machine & ~PTE_MASK);
	return phys;
}

#define pte_val(x)	(((x).pte & 1) ? pte_machine_to_phys((x).pte) : \
			 (x).pte)
#define pte_val_ma(x)	((x).pte)

static inline unsigned long pmd_val(pmd_t x)
{
	unsigned long ret = x.pmd;
	if (ret) ret = pte_machine_to_phys(ret);
	return ret;
}

static inline unsigned long pgd_val(pgd_t x)
{
	unsigned long ret = x.pgd;
	if (ret) ret = pte_machine_to_phys(ret);
	return ret;
}

static inline unsigned long pml4_val(pml4_t x)
{
	unsigned long ret = x.pml4;
	if (ret) ret = pte_machine_to_phys(ret);
	return ret;
}

#define pgprot_val(x)	((x).pgprot)

#define __pte_ma(x)	((pte_t) { (x) } )

static inline pte_t __pte(unsigned long x)
{
	if (x & 1) x = phys_to_machine(x);
	return ((pte_t) { (x) });
}

static inline pmd_t __pmd(unsigned long x)
{
	if ((x & 1)) x = phys_to_machine(x);
	return ((pmd_t) { (x) });
}

static inline pgd_t __pgd(unsigned long x)
{
	if ((x & 1)) x = phys_to_machine(x);
	return ((pgd_t) { (x) });
}

static inline pml4_t __pml4(unsigned long x)
{
	if ((x & 1)) x = phys_to_machine(x);
	return ((pml4_t) { (x) });
}

#define __pgprot(x)	((pgprot_t) { (x) } )

extern unsigned long vm_stack_flags, vm_stack_flags32;
extern unsigned long vm_data_default_flags, vm_data_default_flags32;
extern unsigned long vm_force_exec32;

#define __PHYSICAL_START	          0x100000UL
#define __START_KERNEL		0xffffffff80100000UL
#define __START_KERNEL_map	0xffffffff80000000UL
#define __PAGE_OFFSET           0xffffff8000000000UL	/* 1 << 39 */

#else
#define __PHYSICAL_START	          0x100000
#define __START_KERNEL		0xffffffff80100000
#define __START_KERNEL_map	0xffffffff80000000
#define __PAGE_OFFSET           0xffffff8000000000	/* 1 << 39 */
#endif /* !__ASSEMBLY__ */

#undef LOAD_OFFSET
#define LOAD_OFFSET		0

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)	(((addr)+PAGE_SIZE-1)&PAGE_MASK)

#define KERNEL_TEXT_SIZE  (40UL*1024*1024)
#define KERNEL_TEXT_START 0xffffffff80000000UL 

#ifndef __ASSEMBLY__

/* Pure 2^n version of get_order */
extern __inline__ int get_order(unsigned long size)
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

#endif /* __ASSEMBLY__ */

#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)

/* Note: __pa(&symbol_visible_to_c) should be always replaced with __pa_symbol.
   Otherwise you risk miscompilation. */ 
/* Optimized __pa() didn't work on xen, because we also use it for kernel addresses */
/* #define __pa(x)			((unsigned long)(x) - PAGE_OFFSET) */
#define __pa(x)			(((unsigned long)(x)>=__START_KERNEL_map)?(unsigned long)(x) - (unsigned long)__START_KERNEL_map:(unsigned long)(x) - PAGE_OFFSET)
/* __pa_symbol should be used for C visible symbols.
   This seems to be the official gcc blessed way to do such arithmetic. */ 
#define __pa_symbol(x)		\
	({unsigned long v;  \
	  asm("" : "=r" (v) : "0" (x)); \
	  __pa(v); })

#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#ifndef CONFIG_DISCONTIGMEM
#define pfn_to_page(pfn)	(mem_map + (pfn))
#define page_to_pfn(page)	((unsigned long)((page) - mem_map))
#define pfn_valid(pfn)		((pfn) < max_mapnr)
#endif

#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
#define virt_addr_valid(kaddr)	pfn_valid(__pa(kaddr) >> PAGE_SHIFT)
#define pfn_to_kaddr(pfn)      __va((pfn) << PAGE_SHIFT)

/* VIRT <-> MACHINE conversion */
#define virt_to_machine(v)	(phys_to_machine(__pa(v)))
#define virt_to_mfn(v)		(pfn_to_mfn(__pa(v) >> PAGE_SHIFT))
#define mfn_to_virt(m)		(__va(mfn_to_pfn(m) << PAGE_SHIFT))

#define __VM_DATA_DEFAULT_FLAGS	(VM_READ | VM_WRITE | VM_EXEC | \
				 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)
#define __VM_STACK_FLAGS 	(VM_GROWSDOWN | VM_READ | VM_WRITE | VM_EXEC | \
				 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC | \
				 VM_ACCOUNT)

#define VM_DATA_DEFAULT_FLAGS \
	(test_thread_flag(TIF_IA32) ? vm_data_default_flags32 : \
	  vm_data_default_flags) 

#define VM_STACK_DEFAULT_FLAGS \
	(test_thread_flag(TIF_IA32) ? vm_stack_flags32 : vm_stack_flags) 
	
#define CONFIG_ARCH_GATE_AREA 1	

#ifndef __ASSEMBLY__
struct task_struct;
struct vm_area_struct *get_gate_vma(struct task_struct *tsk);
int in_gate_area(struct task_struct *task, unsigned long addr);
extern int devmem_is_allowed(unsigned long pagenr);
#endif

#endif /* __KERNEL__ */

#endif /* _X86_64_PAGE_H */

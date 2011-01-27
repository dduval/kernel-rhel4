/*
 * atomic_kmap.h: temporary virtual kernel memory mappings
 *
 * Copyright (C) 2003 Ingo Molnar <mingo@redhat.com>
 */

#ifndef _ASM_ATOMIC_KMAP_H
#define _ASM_ATOMIC_KMAP_H

#ifdef __KERNEL__

#include <linux/config.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_DEBUG_HIGHMEM
#define HIGHMEM_DEBUG 1
#else
#define HIGHMEM_DEBUG 0
#endif

extern pte_t *kmap_pte;
#define kmap_prot PAGE_KERNEL
#define kmap_prot_nocache PAGE_KERNEL_NOCACHE

#ifndef CONFIG_XEN
#define PKMAP_BASE (0xff000000UL)
#else
#define PKMAP_BASE ((FIXADDR_BOOT_START - PAGE_SIZE*(LAST_PKMAP+1)) & PMD_MASK)
#endif
#define NR_SHARED_PMDS ((0xffffffff-PKMAP_BASE+1)/PMD_SIZE)

static inline unsigned long __kmap_atomic_vaddr(enum km_type type)
{
	enum fixed_addresses idx;

	idx = type + KM_TYPE_NR*smp_processor_id();
	return __fix_to_virt(FIX_KMAP_BEGIN + idx);
}

static inline void *__kmap_atomic_noflush(struct page *page, enum km_type type)
{
	enum fixed_addresses idx;
	unsigned long vaddr;

	idx = type + KM_TYPE_NR*smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
	/*
	 * NOTE: entries that rely on some secondary TLB-flush
	 * effect must not be global:
	 */
	set_pte(kmap_pte-idx, mk_pte(page, PAGE_KERNEL));

	return (void*) vaddr;
}

static inline void *__kmap_atomic(struct page *page, enum km_type type)
{
	enum fixed_addresses idx;
	unsigned long vaddr;

	idx = type + KM_TYPE_NR*smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
#if HIGHMEM_DEBUG
	BUG_ON(!pte_none(*(kmap_pte-idx)));
#else
	/*
	 * Performance optimization - do not flush if the new
	 * pte is the same as the old one:
	 */
	if (pte_val(*(kmap_pte-idx)) == pte_val(mk_pte(page, kmap_prot)))
		return (void *) vaddr;
#endif
	set_pte(kmap_pte-idx, mk_pte(page, kmap_prot));
	__flush_tlb_one(vaddr);

	return (void*) vaddr;
}

static inline void __kunmap_atomic(void *kvaddr, enum km_type type)
{
#if HIGHMEM_DEBUG
	unsigned long vaddr = (unsigned long) kvaddr & PAGE_MASK;
	enum fixed_addresses idx = type + KM_TYPE_NR*smp_processor_id();

	BUG_ON(vaddr != __fix_to_virt(FIX_KMAP_BEGIN+idx));
	/*
	 * force other mappings to Oops if they'll try to access
	 * this pte without first remap it
	 */
	pte_clear(kmap_pte-idx);
	__flush_tlb_one(vaddr);
#endif
}

#define __kunmap_atomic_type(type) \
		__kunmap_atomic((void *)__kmap_atomic_vaddr(type), (type))

#endif /* __KERNEL__ */

#endif /* _ASM_ATOMIC_KMAP_H */

/*
 *  linux/arch/x86_64/mm/init.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *  Copyright (C) 2000  Pavel Machek <pavel@suse.cz>
 *  Copyright (C) 2002,2003 Andi Kleen <ak@suse.de>
 *
 *  Jun Nakajima <jun.nakajima@intel.com>
 *     Modified for Xen.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/proc_fs.h>
#include <linux/module.h>

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/dma.h>
#include <asm/fixmap.h>
#include <asm/e820.h>
#include <asm/apic.h>
#include <asm/tlb.h>
#include <asm/mmu_context.h>
#include <asm/proto.h>
#include <asm/smp.h>

#include <xen/features.h>

#ifndef Dprintk
#define Dprintk(x...)
#endif

#ifdef CONFIG_GART_IOMMU
extern int swiotlb;
#endif

extern char _stext[];

DEFINE_PER_CPU(struct mmu_gather, mmu_gathers);

extern unsigned long *contiguous_bitmap;

extern unsigned long start_pfn;

/*
 * Use this until direct mapping is established, i.e. before __va() is
 * available in init_memory_mapping().
 */

#define addr_to_page(addr, page)				\
	(addr) &= PHYSICAL_PAGE_MASK;				\
	(page) = ((unsigned long *) ((unsigned long)		\
	(((mfn_to_pfn((addr) >> PAGE_SHIFT)) << PAGE_SHIFT) +	\
	__START_KERNEL_map)))

static void early_make_page_readonly(void *va, unsigned int feature)
{
	unsigned long addr, _va = (unsigned long)va;
	pte_t pte, *ptep;
	unsigned long *page = (unsigned long *) init_level4_pgt;

	/* FIXME: check if this feature is always set before fixing the
	   code below for 4 level page tables. -- Rik */
	if (xen_feature(feature))
		return;

	addr = (unsigned long) page[pml4_index(_va)];
	addr_to_page(addr, page);

	addr = page[pgd_index(_va)];
	addr_to_page(addr, page);

	addr = page[pmd_index(_va)];
	addr_to_page(addr, page);

	ptep = (pte_t *) &page[pte_index(_va)];

	pte.pte = ptep->pte & ~_PAGE_RW;
	if (HYPERVISOR_update_va_mapping(_va, pte, 0))
		BUG();
}

void make_page_readonly(void *va, unsigned int feature)
{
	pgd_t *pgd; pmd_t *pmd; pte_t pte, *ptep;
	unsigned long addr = (unsigned long) va;

	if (xen_feature(feature))
		return;

	pgd = pgd_offset_k(addr);
	pmd = pmd_offset(pgd, addr);
	ptep = pte_offset_kernel(pmd, addr);

	pte.pte = ptep->pte & ~_PAGE_RW;
	if (HYPERVISOR_update_va_mapping(addr, pte, 0))
		xen_l1_entry_update(ptep, pte); /* fallback */

	if ((addr >= VMALLOC_START) && (addr < VMALLOC_END))
		make_page_readonly(__va(pte_pfn(pte) << PAGE_SHIFT), feature);
}

void make_page_writable(void *va, unsigned int feature)
{
	pgd_t *pgd; pmd_t *pmd; pte_t pte, *ptep;
	unsigned long addr = (unsigned long) va;

	if (xen_feature(feature))
		return;

	pgd = pgd_offset_k(addr);
	pmd = pmd_offset(pgd, addr);
	ptep = pte_offset_kernel(pmd, addr);

	pte.pte = ptep->pte | _PAGE_RW;
	if (HYPERVISOR_update_va_mapping(addr, pte, 0))
		xen_l1_entry_update(ptep, pte); /* fallback */

	if ((addr >= VMALLOC_START) && (addr < VMALLOC_END))
		make_page_writable(__va(pte_pfn(pte) << PAGE_SHIFT), feature);
}

void make_pages_readonly(void *va, unsigned nr, unsigned int feature)
{
	if (xen_feature(feature))
		return;

	while (nr-- != 0) {
		make_page_readonly(va, feature);
		va = (void*)((unsigned long)va + PAGE_SIZE);
	}
}

void make_pages_writable(void *va, unsigned nr, unsigned int feature)
{
	if (xen_feature(feature))
		return;

	while (nr-- != 0) {
		make_page_writable(va, feature);
		va = (void*)((unsigned long)va + PAGE_SIZE);
	}
}

/*
 * NOTE: pagetable_init alloc all the fixmap pagetables contiguous on the
 * physical space so we can cache the place of the first one and move
 * around without checking the pgd every time.
 */

void show_mem(void)
{
	int i, total = 0, reserved = 0;
	int shared = 0, cached = 0;
	pg_data_t *pgdat;
	struct page *page;

	printk("Mem-info:\n");
	show_free_areas();
	printk("Free swap:       %6ldkB\n", nr_swap_pages<<(PAGE_SHIFT-10));

	for_each_pgdat(pgdat) {
               for (i = 0; i < pgdat->node_spanned_pages; ++i) {
                       page = pgdat->node_mem_map + i;
		total++;
                       if (PageReserved(page))
			reserved++;
                       else if (PageSwapCache(page))
			cached++;
                       else if (page_count(page))
                               shared += page_count(page) - 1;
               }
	}
	printk("%d pages of RAM\n", total);
	printk("%d reserved pages\n",reserved);
	printk("%d pages shared\n",shared);
	printk("%d pages swap cached\n",cached);
}

EXPORT_SYMBOL_GPL(show_mem);

/* References to section boundaries */

extern char _text, _etext, _edata, __bss_start, _end[];
extern char __init_begin, __init_end;

int after_bootmem;

static void *spp_getpage(void)
{ 
	void *ptr;
	if (after_bootmem)
		ptr = (void *) get_zeroed_page(GFP_ATOMIC); 
	else
		ptr = alloc_bootmem_pages(PAGE_SIZE);
	if (!ptr || ((unsigned long)ptr & ~PAGE_MASK))
		panic("set_pte_phys: cannot allocate page data %s\n", after_bootmem?"after bootmem":"");

	Dprintk("spp_getpage %p\n", ptr);
	return ptr;
} 

#define pml4_offset_u(address) (init_level4_user_pgt + pml4_index(address))

static inline pgd_t *pgd_offset_u(unsigned long address)
{
	pgd_t *pgd = level3_user_pgt;

	return pgd + pgd_index(address);
}

static void set_pte_phys(unsigned long vaddr,
			 unsigned long phys, pgprot_t prot, int user_mode)
{
	pml4_t *level4;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte, new_pte;

	Dprintk("set_pte_phys %lx to %lx\n", vaddr, phys);

	level4 = (user_mode ? pml4_offset_u(vaddr) : pml4_offset_k(vaddr));
	if (pml4_none(*level4)) {
		printk("PML4 FIXMAP MISSING, it should be setup in head.S!\n");
		return;
	}

	pgd = (user_mode ? pgd_offset_u(vaddr) : pgd_offset_k(vaddr));
	if (pgd_none(*pgd)) {
		pmd = (pmd_t *) spp_getpage(); 
		make_page_readonly(pmd, XENFEAT_writable_page_tables);
		set_pgd(pgd, __pgd(__pa(pmd) | _KERNPG_TABLE | _PAGE_USER));
		if (pmd != pmd_offset(pgd, 0)) {
			printk("PAGETABLE BUG #01! %p <-> %p\n", pmd, pmd_offset(pgd,0));
			return;
		}
	}
	pmd = pmd_offset(pgd, vaddr);
	if (pmd_none(*pmd)) {
		pte = (pte_t *) spp_getpage();
		make_page_readonly(pte, XENFEAT_writable_page_tables);
		set_pmd(pmd, __pmd(__pa(pte) | _KERNPG_TABLE | _PAGE_USER));
		if (pte != pte_offset_kernel(pmd, 0)) {
			printk("PAGETABLE BUG #02!\n");
			return;
		}
	}
	new_pte = pfn_pte(phys >> PAGE_SHIFT, prot);
	pte = pte_offset_kernel(pmd, vaddr);
	if (!pte_none(*pte) &&
	    pte_val(*pte) != (pte_val(new_pte) & __supported_pte_mask))
		pte_ERROR(*pte);
	set_pte(pte, new_pte);

	/*
	 * It's enough to flush this one mapping.
	 * (PGE mappings get flushed as well)
	 */
	__flush_tlb_one(vaddr);
}

static void set_pte_phys_ma(unsigned long vaddr,
			unsigned long phys, pgprot_t prot)
{
	pml4_t *pml4;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte, new_pte;

	Dprintk("set_pte_phys %lx to %lx\n", vaddr, phys);

	pml4 = pml4_offset_k(vaddr);
	if (pml4_none(*pml4)) {
		printk("PML4 FIXMAP MISSING, it should be setup in head.S!\n");
		return;
	}

	pgd = pgd_offset_k(vaddr);
	if (pgd_none(*pgd)) {
		pmd = (pmd_t *) spp_getpage();
		make_page_readonly(pmd, XENFEAT_writable_page_tables);

		set_pgd(pgd, __pgd(__pa(pmd) | _KERNPG_TABLE | _PAGE_USER));
		if (pmd != pmd_offset(pgd, 0)) {
			printk("PAGETABLE BUG #01! %p <-> %p\n", pmd, pmd_offset(pgd,0));
			return;
		}
	}
	pmd = pmd_offset(pgd, vaddr);
	if (pmd_none(*pmd)) {
		pte = (pte_t *) spp_getpage();
		make_page_readonly(pte, XENFEAT_writable_page_tables);

		set_pmd(pmd, __pmd(__pa(pte) | _KERNPG_TABLE | _PAGE_USER));
		if (pte != pte_offset_kernel(pmd, 0)) {
			printk("PAGETABLE BUG #02!\n");
			return;
		}
	}

	new_pte = pfn_pte_ma(phys >> PAGE_SHIFT, prot);
	pte = pte_offset_kernel(pmd, vaddr);

	/*
	 * Note that the pte page is already RO, thus we want to use
	 * xen_l1_entry_update(), not set_pte().
	 */
	xen_l1_entry_update(pte, pfn_pte_ma(phys >> PAGE_SHIFT, prot));

	/*
	 * It's enough to flush this one mapping.
	 * (PGE mappings get flushed as well)
	 */
	__flush_tlb_one(vaddr);
}

#define SET_FIXMAP_KERNEL 0
#define SET_FIXMAP_USER   1

/* NOTE: this is meant to be run only at boot */
void __set_fixmap (enum fixed_addresses idx, unsigned long phys, pgprot_t prot)
{
	unsigned long address = __fix_to_virt(idx);

	if (idx >= __end_of_fixed_addresses) {
		printk("Invalid __set_fixmap\n");
		return;
	}
	switch (idx) {
	case VSYSCALL_FIRST_PAGE:
		set_pte_phys(address, phys, prot, SET_FIXMAP_KERNEL);
		break;
	default:
		set_pte_phys_ma(address, phys, prot);
		break;
	}
}

/*
 * At this point it only supports vsyscall area.
 */
void __set_fixmap_user (enum fixed_addresses idx, unsigned long phys, pgprot_t prot)
{
	unsigned long address = __fix_to_virt(idx);

	if (idx >= __end_of_fixed_addresses) {
		printk("Invalid __set_fixmap\n");
		return;
	}

	set_pte_phys(address, phys, prot, SET_FIXMAP_USER);
}

unsigned long __initdata table_start, tables_space;

unsigned long get_machine_pfn(unsigned long addr)
{
	pgd_t *pgd = pgd_offset_k(addr);
	pmd_t* pmd = pmd_offset(pgd, addr);
	pte_t *pte = pte_offset_kernel(pmd, addr);

	return pte_mfn(*pte);
}

static __init void *alloc_static_page(unsigned long *phys)
{ 
	unsigned long va = (start_pfn << PAGE_SHIFT) + __START_KERNEL_map;

	if (after_bootmem) {
		void *adr = (void *)get_zeroed_page(GFP_ATOMIC);
		*phys = __pa(adr);
		return adr;
	}

	*phys = start_pfn << PAGE_SHIFT;
	start_pfn++;
	memset((void *)va, 0, PAGE_SIZE);
	return (void *)va; 
} 

#define PTE_SIZE PAGE_SIZE

static inline void __set_pte(pte_t *dst, pte_t val)
{
	*dst = val;
}

static inline int make_readonly(unsigned long paddr)
{
	int readonly = 0;

	/* Make old and new page tables read-only. */
	if (!xen_feature(XENFEAT_writable_page_tables)
	    && (paddr >= (xen_start_info->pt_base - __START_KERNEL_map))
	    && (paddr < ((table_start << PAGE_SHIFT) + tables_space)))
		readonly = 1;
	/*
	 * No need for writable mapping of kernel image. This also ensures that
	 * page and descriptor tables embedded inside don't have writable
	 * mappings.
	 */
	if ((paddr >= __pa_symbol(&_text)) && (paddr < __pa_symbol(&_end)))
		readonly = 1;

	return readonly;
}

static void __init
phys_pmd_init(pmd_t *pmd, unsigned long address, unsigned long end)
{
	int j, k;

	for (j = 0; j < PTRS_PER_PMD; pmd++, j++) {
		unsigned long pte_phys;
		pte_t *pte, *pte_save;

		if (address >= end) { 
			for (; j < PTRS_PER_PMD; j++, pmd++)
				set_pmd(pmd,  __pmd(0)); 
			break;
		}
		pte = alloc_static_page(&pte_phys);
		pte_save = pte;
		for (k = 0; k < PTRS_PER_PTE; pte++, k++, address += PTE_SIZE) {
			if ((address >= end) ||
			    ((address >> PAGE_SHIFT) >=
			     xen_start_info->nr_pages)) {
				__set_pte(pte, __pte(0));
				continue;
			}
			if (make_readonly(address)) {
				__set_pte(pte, 
					  __pte(address | (_KERNPG_TABLE & ~_PAGE_RW)));
				continue;
			}
			__set_pte(pte, __pte(address | _KERNPG_TABLE));
		}
		pte = pte_save;
		early_make_page_readonly(pte, XENFEAT_writable_page_tables);
		set_pmd(pmd, __pmd(pte_phys | _KERNPG_TABLE));
	}
}

static void __init phys_pgd_init(pgd_t *pgd, unsigned long address, unsigned long end)
{ 
	long i = pgd_index(address);

	pgd = pgd + i;

	for (; i < PTRS_PER_PGD; pgd++, i++) {
		unsigned long paddr, pmd_phys;
		pmd_t *pmd;

		paddr = (address & PML4_MASK) + i*PGDIR_SIZE;
		if (paddr >= end)
			break;

		// if (!e820_mapped(paddr, paddr+PGDIR_SIZE, 0)) { 
		// 	set_pgd(pgd, __pgd(0)); 
		// 	continue;
		// } 

		pmd = alloc_static_page(&pmd_phys);
		early_make_page_readonly(pmd, XENFEAT_writable_page_tables);
		set_pgd(pgd, __pgd(pmd_phys | _KERNPG_TABLE));
		phys_pmd_init(pmd, paddr, end);
	}
	__flush_tlb();
} 

void __init xen_init_pt(void)
{
	unsigned long addr, *page;

	memset((void *)init_level4_pgt,   0, PAGE_SIZE);
	memset((void *)level3_kernel_pgt, 0, PAGE_SIZE);
	memset((void *)level2_kernel_pgt, 0, PAGE_SIZE);

	/* Find the initial pte page that was built for us. */
	page = (unsigned long *)xen_start_info->pt_base;
	addr = page[pml4_index(__START_KERNEL_map)];
	addr_to_page(addr, page);
	addr = page[pgd_index(__START_KERNEL_map)];
	addr_to_page(addr, page);

	/* Construct mapping of initial pte page in our own directories. */
	init_level4_pgt[pml4_index(__START_KERNEL_map)] =
		mk_kernel_pml4(__pa_symbol(level3_kernel_pgt));
	level3_kernel_pgt[pgd_index(__START_KERNEL_map)] =
		__pgd(__pa_symbol(level2_kernel_pgt) |
		      _KERNPG_TABLE | _PAGE_USER);
	memcpy((void *)level2_kernel_pgt, page, PAGE_SIZE);

	early_make_page_readonly(init_level4_pgt,
				XENFEAT_writable_page_tables);
	early_make_page_readonly(init_level4_user_pgt,
				XENFEAT_writable_page_tables);
	early_make_page_readonly(level3_kernel_pgt,
				XENFEAT_writable_page_tables);
	early_make_page_readonly(level3_user_pgt,
				XENFEAT_writable_page_tables);
	early_make_page_readonly(level2_kernel_pgt,
				XENFEAT_writable_page_tables);
	early_make_page_readonly(boot_vmalloc_pgt,
				XENFEAT_writable_page_tables);
	early_make_page_readonly(swapper_pg_dir,
				XENFEAT_writable_page_tables);

	/* FIXME: would xen_pml4_pin be different? */
	xen_pgd_pin(__pa_symbol(init_level4_pgt));
	xen_pgd_pin(__pa_symbol(init_level4_user_pgt));

	set_pml4(init_level4_user_pgt + 511,
		mk_kernel_pml4(__pa_symbol(level3_user_pgt)));
}

void __init extend_init_mapping(void)
{
	unsigned long va = __START_KERNEL_map;
	unsigned long phys, addr, *pte_page;
	pmd_t *pmd;
	pte_t *pte, new_pte;
	unsigned long *page = (unsigned long *)init_level4_pgt;

	addr = page[pml4_index(va)];
	addr_to_page(addr, page);
	addr = page[pgd_index(va)];
	addr_to_page(addr, page);

	/* Kill mapping of low 1MB. */
	while (va < (unsigned long)&_text) {
		HYPERVISOR_update_va_mapping(va, __pte_ma(0), 0);
		va += PAGE_SIZE;
	}

	/* Ensure init mappings cover kernel text/data and initial tables. */
	while (va < (__START_KERNEL_map
		     + (start_pfn << PAGE_SHIFT)
		     + tables_space)) {
		pmd = (pmd_t *)&page[pmd_index(va)];
		if (pmd_none(*pmd)) {
			pte_page = alloc_static_page(&phys);
			early_make_page_readonly(
				pte_page, XENFEAT_writable_page_tables);
				set_pmd(pmd, __pmd(phys | _KERNPG_TABLE | _PAGE_USER));
		} else {
			addr = page[pmd_index(va)];
			addr_to_page(addr, pte_page);
		}
		pte = (pte_t *)&pte_page[pte_index(va)];
		if (pte_none(*pte)) {
			new_pte = pfn_pte(
				(va - __START_KERNEL_map) >> PAGE_SHIFT,
				__pgprot(_KERNPG_TABLE | _PAGE_USER));
			xen_l1_entry_update(pte, new_pte);
		}
		va += PAGE_SIZE;
	}

	/* Finally, blow away any spurious initial mappings. */
	while (1) {
		pmd = (pmd_t *)&page[pmd_index(va)];
		if (pmd_none(*pmd))
			break;
		HYPERVISOR_update_va_mapping(va, __pte_ma(0), 0);
		va += PAGE_SIZE;
	}
}

static void __init find_early_table_space(unsigned long end)
{
	unsigned long pmds, ptes; 

	pmds = (end + PMD_SIZE - 1) >> PMD_SHIFT;
	ptes = (end + PTE_SIZE - 1) >> PAGE_SHIFT;

	tables_space =
		round_up(pmds * 8, PAGE_SIZE) + 
		round_up(ptes * 8, PAGE_SIZE); 

	extend_init_mapping();

	table_start = start_pfn;

	printk("kernel direct mapping tables up to %lx @ %lx-%lx\n",
		end, table_start << PAGE_SHIFT,
		(start_pfn << PAGE_SHIFT) + tables_space);
}

/* Setup the direct mapping of the physical memory at PAGE_OFFSET.
   This runs before bootmem is initialized and gets pages directly from the 
   physical memory. To access them they are temporarily mapped. */
void __init init_memory_mapping(void) 
{ 
#if 0 /* We only have one PGD in the 3-level model. */
	unsigned long adr;	       
	unsigned long end;
	unsigned long next; 

	Dprintk("init_memory_mapping\n");

	end = end_pfn_map << PAGE_SHIFT;

	find_early_table_space(end);

	end += __PAGE_OFFSET; /* turn virtual */  	

	for (adr = PAGE_OFFSET; adr < end; adr = next) { 
		unsigned long pgd_phys; 
		pgd_t *pgd = alloc_static_page(&pgd_phys);
		early_make_page_readonly(pgd, XENFEAT_writable_page_tables);
		next = adr + PML4_SIZE;
		if (next > end) 
			next = end; 
		phys_pgd_init(pgd, adr-PAGE_OFFSET, next-PAGE_OFFSET); 
		set_pml4(init_level4_pgt + pml4_index(adr), mk_kernel_pml4(pgd_phys));
	}
#else
	find_early_table_space(end_pfn_map << PAGE_SHIFT);
	phys_pgd_init(level3_kernel_pgt, 0, end_pfn_map << PAGE_SHIFT); 
#endif
	asm volatile("movq %%cr4,%0" : "=r" (mmu_cr4_features));
	__flush_tlb_all();
}

extern struct x8664_pda cpu_pda[NR_CPUS];

static unsigned long low_pml4[NR_CPUS];

void swap_low_mappings(void)
{
	int i;
	for (i = 0; i < NR_CPUS; i++) {
	        unsigned long t;
		if (!cpu_pda[i].level4_pgt) 
			continue;
		t = cpu_pda[i].level4_pgt[0];
		cpu_pda[i].level4_pgt[0] = low_pml4[i];
		low_pml4[i] = t;
	}
	flush_tlb_all();
}

void zap_low_mappings(void)
{
	/* this is not required for Xen */
#if 0
	swap_low_mappings();
#endif
}

#ifndef CONFIG_DISCONTIGMEM
void __init paging_init(void)
{
	{
		unsigned long zones_size[MAX_NR_ZONES] = {0, 0, 0};
		int i;
#ifndef CONFIG_XEN
		unsigned int max_dma;

		max_dma = virt_to_phys((char *)MAX_DMA_ADDRESS) >> PAGE_SHIFT;

		if (end_pfn < max_dma)
			zones_size[ZONE_DMA] = end_pfn;
		else {
			zones_size[ZONE_DMA] = max_dma;
			zones_size[ZONE_NORMAL] = end_pfn - max_dma;
		}
#else
		zones_size[ZONE_DMA] = end_pfn;
#endif
		free_area_init(zones_size);

		if (!xen_feature(XENFEAT_auto_translated_physmap) ||
		    xen_start_info->shared_info >= xen_start_info->nr_pages) {
			/* Switch to the real shared_info page, and clear the
			 * dummy page. */
			set_fixmap(FIX_SHARED_INFO, xen_start_info->shared_info);
			HYPERVISOR_shared_info =
				(shared_info_t *)fix_to_virt(FIX_SHARED_INFO);
			memset(empty_zero_page, 0, sizeof(empty_zero_page));
		}

		init_mm.context.pinned = 1;

		/* Setup mapping of lower 1st MB */
		for (i = 0; i < NR_FIX_ISAMAPS; i++)
			if (xen_start_info->flags & SIF_PRIVILEGED)
				set_fixmap(FIX_ISAMAP_BEGIN - i, i * PAGE_SIZE);
			else
				__set_fixmap(FIX_ISAMAP_BEGIN - i,
					virt_to_mfn(empty_zero_page) << PAGE_SHIFT,
						PAGE_KERNEL_RO);
	}
	return;
}
#endif

/* Unmap a kernel mapping if it exists. This is useful to avoid prefetches
   from the CPU leading to inconsistent cache lines. address and size
   must be aligned to 2MB boundaries. 
   Does nothing when the mapping doesn't exist. */
void __init clear_kernel_mapping(unsigned long address, unsigned long size) 
{
	unsigned long end = address + size;

	BUG_ON(address & ~LARGE_PAGE_MASK);
	BUG_ON(size & ~LARGE_PAGE_MASK); 
	
	for (; address < end; address += LARGE_PAGE_SIZE) { 
		pgd_t *pgd = pgd_offset_k(address);
		pmd_t *pmd, local_pmd;
		if (!pgd || pgd_none(*pgd))
			continue; 
		pmd = pmd_offset(pgd, address);
		if (!pmd || pmd_none(*pmd))
			continue; 
		if (0 == (pmd_val(*pmd) & _PAGE_PSE)) {
			local_pmd = __pmd(pmd_val(*pmd) & ~_PAGE_NX);
			pte_free(pmd_page(local_pmd));
		}
		set_pmd(pmd, __pmd(0)); 		
	}
	__flush_tlb_all();
} 

static inline int page_is_ram (unsigned long pagenr)
{
	return 1;
}

extern int swiotlb_force;

unsigned long next_ram_page (unsigned long pagenr)
{
	int i;
	unsigned long min_pageno = ULONG_MAX;

	pagenr++;

	for (i = 0; i < e820.nr_map; i++) {
		unsigned long addr, end;

		if (e820.map[i].type != E820_RAM)	/* not usable memory */
			continue;
		/*
		 *	!!!FIXME!!! Some BIOSen report areas as RAM that
		 *	are not. Notably the 640->1Mb area. We need a sanity
		 *	check here.
		 */
		addr = (e820.map[i].addr+PAGE_SIZE-1) >> PAGE_SHIFT;
		end = (e820.map[i].addr+e820.map[i].size) >> PAGE_SHIFT;
		if  ((pagenr >= addr) && (pagenr < end))
			return pagenr;
		if ((pagenr < addr) && (addr < min_pageno))
			min_pageno = addr;
	}
	return min_pageno;
}

EXPORT_SYMBOL_GPL(next_ram_page);

/*
 * devmem_is_allowed() checks to see if /dev/mem access to a certain address is
 * valid. The argument is a physical page number.
 *
 *
 * On x86-64, access has to be given to the first megabyte of ram because that area
 * contains bios code and data regions used by X and dosemu and similar apps.
 * Access has to be given to non-kernel-ram areas as well, these contain the PCI
 * mmio resources as well as potential bios/acpi data regions.
 */
int devmem_is_allowed(unsigned long pagenr)
{
	if (pagenr <= 256)
		return 1;
	if (!page_is_ram(pagenr))
		return 1;
	return 0;
}


EXPORT_SYMBOL_GPL(page_is_ram);

static struct kcore_list kcore_mem, kcore_vmalloc, kcore_kernel, kcore_modules,
			 kcore_vsyscall;

void __init mem_init(void)
{
	int codesize, reservedpages, datasize, initsize;
	int tmp;

	contiguous_bitmap = alloc_bootmem_low_pages(
		(end_pfn + 2*BITS_PER_LONG) >> 3);
	BUG_ON(!contiguous_bitmap);
	memset(contiguous_bitmap, 0, (end_pfn + 2*BITS_PER_LONG) >> 3);
#ifdef CONFIG_SWIOTLB
	if (!iommu_aperture &&
	    (end_pfn >= 0xffffffff>>PAGE_SHIFT || force_iommu))
	       swiotlb = 1;
	if (swiotlb)
		swiotlb_init();	
#endif

	/* How many end-of-memory variables you have, grandma! */
	max_low_pfn = end_pfn;
	max_pfn = end_pfn;
	num_physpages = end_pfn;
	high_memory = (void *) __va(end_pfn * PAGE_SIZE);

	/* clear the zero-page */
	memset(empty_zero_page, 0, PAGE_SIZE);

	reservedpages = 0;

	/* this will put all low memory onto the freelists */
#ifdef CONFIG_DISCONTIGMEM
	totalram_pages += numa_free_all_bootmem();
	tmp = 0;
	/* should count reserved pages here for all nodes */ 
#else
	max_mapnr = end_pfn;
	if (!mem_map) BUG();

	totalram_pages += free_all_bootmem();

	for (tmp = 0; tmp < end_pfn; tmp++)
		/*
		 * Only count reserved RAM pages
		 */
		if (page_is_ram(tmp) && PageReserved(mem_map+tmp))
			reservedpages++;
#endif

	after_bootmem = 1;

	codesize =  (unsigned long) &_etext - (unsigned long) &_text;
	datasize =  (unsigned long) &_edata - (unsigned long) &_etext;
	initsize =  (unsigned long) &__init_end - (unsigned long) &__init_begin;

	/* Register memory areas for /proc/kcore */
	kclist_add(&kcore_mem, __va(0), max_low_pfn << PAGE_SHIFT); 
	kclist_add(&kcore_vmalloc, (void *)VMALLOC_START, 
		   VMALLOC_END-VMALLOC_START);
	kclist_add(&kcore_kernel, &_stext, _end - _stext);
	kclist_add(&kcore_modules, (void *)MODULES_VADDR, MODULES_LEN);
	kclist_add(&kcore_vsyscall, (void *)VSYSCALL_START, 
				 VSYSCALL_END - VSYSCALL_START);

	printk("Memory: %luk/%luk available (%dk kernel code, %dk reserved, %dk data, %dk init)\n",
		(unsigned long) nr_free_pages() << (PAGE_SHIFT-10),
		end_pfn << (PAGE_SHIFT-10),
		codesize >> 10,
		reservedpages << (PAGE_SHIFT-10),
		datasize >> 10,
		initsize >> 10);

	/*
	 * Subtle. SMP is doing its boot stuff late (because it has to
	 * fork idle threads) - but it also needs low mappings for the
	 * protected-mode entry to work. We zap these entries only after
	 * the WP-bit has been tested.
	 */
#ifndef CONFIG_SMP
	zap_low_mappings();
#endif
}

void free_initmem(void)
{
#ifdef __DO_LATER__
	/*
	 * Some pages can be pinned, but some are not. Unpinning such pages
	 * triggers BUG().
	 */
	unsigned long addr;

	addr = (unsigned long)(&__init_begin);
	for (; addr < (unsigned long)(&__init_end); addr += PAGE_SIZE) {
		ClearPageReserved(virt_to_page(addr));
		set_page_count(virt_to_page(addr), 1);
#ifdef CONFIG_INIT_DEBUG
		memset((void *)(addr & ~(PAGE_SIZE-1)), 0xcc, PAGE_SIZE); 
#endif
		make_page_writable(
			__va(__pa(addr)), XENFEAT_writable_page_tables);
		/*
		 * Make pages from __PAGE_OFFSET address as well
		 */
		make_page_writable(
			(void *)addr, XENFEAT_writable_page_tables);
		free_page(addr);
		totalram_pages++;
	}
	printk ("Freeing unused kernel memory: %luk freed\n", (&__init_end - &__init_begin) >> 10);
#endif
}

#ifdef CONFIG_BLK_DEV_INITRD
void free_initrd_mem(unsigned long start, unsigned long end)
{
	if (start < (unsigned long)&_end)
		return;
	printk ("Freeing initrd memory: %ldk freed\n", (end - start) >> 10);
	for (; start < end; start += PAGE_SIZE) {
		ClearPageReserved(virt_to_page(start));
		set_page_count(virt_to_page(start), 1);
		free_page(start);
		totalram_pages++;
	}
}
#endif

void __init reserve_bootmem_generic(unsigned long phys, unsigned len) 
{ 
	/* Should check here against the e820 map to avoid double free */ 
#ifdef CONFIG_DISCONTIGMEM
	int nid = phys_to_nid(phys);
  	reserve_bootmem_node(NODE_DATA(nid), phys, len);
#else       		
	reserve_bootmem(phys, len);    
#endif
}

int kern_addr_valid(unsigned long addr) 
{ 
	unsigned long above = ((long)addr) >> __VIRTUAL_MASK_SHIFT;
       pml4_t *pml4;
       pgd_t *pgd;
       pmd_t *pmd;
       pte_t *pte;

	if (above != 0 && above != -1UL)
		return 0; 
	
       pml4 = pml4_offset_k(addr);
	if (pml4_none(*pml4))
		return 0;

       pgd = pgd_offset_k(addr);
	if (pgd_none(*pgd))
		return 0; 

       pmd = pmd_offset(pgd, addr);
	if (pmd_none(*pmd))
		return 0;
	if (pmd_large(*pmd))
		return pfn_valid(pmd_pfn(*pmd));

       pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte))
		return 0;
	return pfn_valid(pte_pfn(*pte));
}
EXPORT_SYMBOL_GPL(kern_addr_valid);

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>

extern int exception_trace, page_fault_trace;

static ctl_table debug_table2[] = {
	{ 99, "exception-trace", &exception_trace, sizeof(int), 0644, NULL,
	  proc_dointvec },
#ifdef CONFIG_CHECKING
	{ 100, "page-fault-trace", &page_fault_trace, sizeof(int), 0644, NULL,
	  proc_dointvec },
#endif
	{ 0, }
}; 

static ctl_table debug_root_table2[] = { 
	{ .ctl_name = CTL_DEBUG, .procname = "debug", .mode = 0555, 
	   .child = debug_table2 }, 
	{ 0 }, 
}; 

static __init int x8664_sysctl_init(void)
{ 
	register_sysctl_table(debug_root_table2, 1);
	return 0;
}
__initcall(x8664_sysctl_init);
#endif

/* A pseudo VMA to allow ptrace access for the vsyscall page.  This only
   covers the 64bit vsyscall page now. 32bit has a real VMA now and does
   not need special handling anymore. */

static struct vm_area_struct gate_vma = {
	.vm_start = VSYSCALL_START,
	.vm_end = VSYSCALL_START + PAGE_SIZE,
	.vm_page_prot = PAGE_READONLY_EXEC,
	.vm_flags = VM_READ | VM_EXEC
};

struct vm_area_struct *get_gate_vma(struct task_struct *tsk)
{
#ifdef CONFIG_IA32_EMULATION
	if (test_tsk_thread_flag(tsk, TIF_IA32))
		return NULL;
#endif
	return &gate_vma;
}

int in_gate_area(struct task_struct *task, unsigned long addr)
{
	struct vm_area_struct *vma = get_gate_vma(task);
	if (!vma)
		return 0;
	return (addr >= vma->vm_start) && (addr < vma->vm_end);
}

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */

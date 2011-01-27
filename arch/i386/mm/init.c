/*
 *  linux/arch/i386/mm/init.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
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
#include <linux/hugetlb.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/bootmem.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/efi.h>

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/dma.h>
#include <asm/fixmap.h>
#include <asm/e820.h>
#include <asm/apic.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/desc.h>

unsigned int __VMALLOC_RESERVE = 128 << 20;

DEFINE_PER_CPU(struct mmu_gather, mmu_gathers);
unsigned long highstart_pfn, highend_pfn;

static int noinline do_test_wp_bit(void);

static inline int page_kills_ppro(unsigned long pagenr)
{
	if (pagenr >= 0x70000 && pagenr <= 0x7003F)
		return 1;
	return 0;
}

extern int is_available_memory(efi_memory_desc_t *);

static inline int page_is_ram(unsigned long pagenr)
{
	int i;
	unsigned long addr, end;

	if (efi_enabled) {
		efi_memory_desc_t *md;

		for (i = 0; i < memmap.nr_map; i++) {
			md = &memmap.map[i];
			if (!is_available_memory(md))
				continue;
			addr = (md->phys_addr+PAGE_SIZE-1) >> PAGE_SHIFT;
			end = (md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT)) >> PAGE_SHIFT;

			if ((pagenr >= addr) && (pagenr < end))
				return 1;
		}
		return 0;
	}

	for (i = 0; i < e820.nr_map; i++) {

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
			return 1;
	}
	return 0;
}

unsigned long next_ram_page(unsigned long pagenr)
{
	int i;
	unsigned long addr, end;
	unsigned long min_pageno = ULONG_MAX;

	pagenr++;

	if (efi_enabled) {
		efi_memory_desc_t *md;

		for (i = 0; i < memmap.nr_map; i++) {
			md = &memmap.map[i];
			if (!is_available_memory(md))
				continue;
			addr = (md->phys_addr+PAGE_SIZE-1) >> PAGE_SHIFT;
			end = (md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT)) >> PAGE_SHIFT;

			if ((pagenr >= addr) && (pagenr < end))
				return pagenr;
			if ((pagenr < addr) && (addr < min_pageno))
				min_pageno = addr;
		}
		return min_pageno;
	}

	for (i = 0; i < e820.nr_map; i++) {

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
 * On x86, access has to be given to the first megabyte of ram because that area
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


pte_t *kmap_pte;

EXPORT_SYMBOL(kmap_pte);

#define kmap_get_fixmap_pte(vaddr)					\
	pte_offset_kernel(pmd_offset(pgd_offset_k(vaddr), (vaddr)), (vaddr))

void __init kmap_init(void)
{
	kmap_pte = kmap_get_fixmap_pte(__fix_to_virt(FIX_KMAP_BEGIN));
}

void __init one_highpage_init(struct page *page, int pfn, int bad_ppro)
{
	if (page_is_ram(pfn) && !(bad_ppro && page_kills_ppro(pfn))) {
		ClearPageReserved(page);
		set_bit(PG_highmem, &page->flags);
		set_page_count(page, 1);
		__free_page(page);
		totalhigh_pages++;
	} else
		SetPageReserved(page);
}

EXPORT_SYMBOL_GPL(page_is_ram);

#ifdef CONFIG_HIGHMEM

#ifndef CONFIG_DISCONTIGMEM
void __init set_highmem_pages_init(int bad_ppro) 
{
	int pfn;
	for (pfn = highstart_pfn; pfn < highend_pfn; pfn++)
		one_highpage_init(pfn_to_page(pfn), pfn, bad_ppro);
	totalram_pages += totalhigh_pages;
}
#else
extern void set_highmem_pages_init(int);
#endif /* !CONFIG_DISCONTIGMEM */
#else
# define set_highmem_pages_init(bad_ppro) do { } while (0)
#endif

unsigned long long __PAGE_KERNEL = _PAGE_KERNEL;
unsigned long long __PAGE_KERNEL_EXEC = _PAGE_KERNEL_EXEC;

#ifndef CONFIG_DISCONTIGMEM
#define remap_numa_kva() do {} while (0)
#else
extern void __init remap_numa_kva(void);
#endif

static __init void prepare_pagetables(pgd_t *pgd_base, unsigned long address)
{
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_base + pgd_index(address);
	pmd = pmd_offset(pgd, address);
	if (!pmd_present(*pmd)) {
		pte = (pte_t *) alloc_bootmem_low_pages(PAGE_SIZE);
		set_pmd(pmd, __pmd(_PAGE_TABLE + __pa(pte)));
	}
}

static void __init fixrange_init (unsigned long start, unsigned long end, pgd_t *pgd_base)
{
	unsigned long vaddr;

	for (vaddr = start; vaddr != end; vaddr += PAGE_SIZE)
		prepare_pagetables(pgd_base, vaddr);
}

void setup_identity_mappings(pgd_t *pgd_base, unsigned long start, unsigned long end)
{
	unsigned long vaddr;
	pgd_t *pgd;
	int i, j, k;
	pmd_t *pmd;
	pte_t *pte, *pte_base;

	pgd = pgd_base;

	for (i = 0; i < PTRS_PER_PGD; pgd++, i++) {
		vaddr = i*PGDIR_SIZE;
		if (end && (vaddr >= end))
			break;
		pmd = pmd_offset(pgd, 0);
		for (j = 0; j < PTRS_PER_PMD; pmd++, j++) {
			vaddr = i*PGDIR_SIZE + j*PMD_SIZE;
			if (end && (vaddr >= end))
				break;
			if (vaddr < start)
				continue;
			if (cpu_has_pse) {
				unsigned long __pe;

				set_in_cr4(X86_CR4_PSE);
				boot_cpu_data.wp_works_ok = 1;
				__pe = _KERNPG_TABLE + _PAGE_PSE + vaddr - start;
				/* Make it "global" too if supported */
				if (cpu_has_pge) {
					set_in_cr4(X86_CR4_PGE);
#if !defined(CONFIG_X86_SWITCH_PAGETABLES)
					__pe += _PAGE_GLOBAL;
					__PAGE_KERNEL |= _PAGE_GLOBAL;
#endif
				}
				set_pmd(pmd, __pmd(__pe));
				continue;
			}
			if (!pmd_present(*pmd))
				pte_base = (pte_t *) alloc_bootmem_low_pages(PAGE_SIZE);
			else
				pte_base = pte_offset_kernel(pmd, 0);
			pte = pte_base;
			for (k = 0; k < PTRS_PER_PTE; pte++, k++) {
				vaddr = i*PGDIR_SIZE + j*PMD_SIZE + k*PAGE_SIZE;
				if (end && (vaddr >= end))
					break;
				if (vaddr < start)
					continue;
				*pte = mk_pte_phys(vaddr-start, PAGE_KERNEL);
			}
			set_pmd(pmd, __pmd(_KERNPG_TABLE + __pa(pte_base)));
		}
	}
}

static void __init pagetable_init (void)
{
	unsigned long vaddr, end;
	pgd_t *pgd_base;
#ifdef CONFIG_X86_PAE
	int i;
#endif

	/*
	 * This can be zero as well - no problem, in that case we exit
	 * the loops anyway due to the PTRS_PER_* conditions.
	 */
	end = (unsigned long)__va(max_low_pfn*PAGE_SIZE);

	pgd_base = swapper_pg_dir;
#ifdef CONFIG_X86_PAE
	/*
	 * It causes too many problems if there's no proper pmd set up
	 * for all 4 entries of the PGD - so we allocate all of them.
	 * PAE systems will not miss this extra 4-8K anyway ...
	 */
	for (i = 0; i < PTRS_PER_PGD; i++) {
		pmd_t *pmd = (pmd_t *) alloc_bootmem_low_pages(PAGE_SIZE);
		set_pgd(pgd_base + i, __pgd(__pa(pmd) + 0x1));
	}
#endif
	/*
	 * Set up lowmem-sized identity mappings at PAGE_OFFSET:
	 */
	setup_identity_mappings(pgd_base, PAGE_OFFSET, end);

	/*
	 * Add flat-mode identity-mappings - SMP needs it when
	 * starting up on an AP from real-mode. (In the non-PAE
	 * case we already have these mappings through head.S.)
	 * All user-space mappings are explicitly cleared after
	 * SMP startup.
	 */
#if defined(CONFIG_SMP) && defined(CONFIG_X86_PAE)
	setup_identity_mappings(pgd_base, 0, 16*1024*1024);
#endif
	remap_numa_kva();

	/*
	 * Fixed mappings, only the page table structure has to be
	 * created - mappings will be set by set_fixmap():
	 */
	vaddr = __fix_to_virt(__end_of_fixed_addresses - 1) & PMD_MASK;
	fixrange_init(vaddr, 0, pgd_base);

#ifdef CONFIG_HIGHMEM
	{
		pgd_t *pgd;
		pmd_t *pmd;
		pte_t *pte;

		/*
		 * Permanent kmaps:
		 */
		vaddr = PKMAP_BASE;
		fixrange_init(vaddr, vaddr + PAGE_SIZE*LAST_PKMAP, pgd_base);

		pgd = swapper_pg_dir + pgd_index(vaddr);
		pmd = pmd_offset(pgd, vaddr);
		pte = pte_offset_kernel(pmd, vaddr);
		pkmap_page_table = pte;
	}
#endif
}

/*
 * Clear kernel pagetables in a PMD_SIZE-aligned range.
 */
static void clear_mappings(pgd_t *pgd_base, unsigned long start, unsigned long end)
{
	unsigned long vaddr;
	pgd_t *pgd;
	pmd_t *pmd;
	int i, j;

	pgd = pgd_base;

	for (i = 0; i < PTRS_PER_PGD; pgd++, i++) {
		vaddr = i*PGDIR_SIZE;
		if (end && (vaddr >= end))
			break;
		pmd = pmd_offset(pgd, 0);
		for (j = 0; j < PTRS_PER_PMD; pmd++, j++) {
			vaddr = i*PGDIR_SIZE + j*PMD_SIZE;
			if (end && (vaddr >= end))
				break;
			if (vaddr < start)
				continue;
			pmd_clear(pmd);
		}
	}
	flush_tlb_all();
}

void zap_low_mappings(void)
{
	printk("zapping low mappings.\n");
	/*
	 * Zap initial low-memory mappings.
	 */
	clear_mappings(swapper_pg_dir, 0, 16*1024*1024);
}

#ifndef CONFIG_DISCONTIGMEM
void __init zone_sizes_init(void)
{
	unsigned long zones_size[MAX_NR_ZONES] = {0, 0, 0};
	unsigned int max_dma, high, low;
	
	max_dma = virt_to_phys((char *)MAX_DMA_ADDRESS) >> PAGE_SHIFT;
	low = max_low_pfn;
	high = highend_pfn;
	
	if (low < max_dma)
		zones_size[ZONE_DMA] = low;
	else {
		zones_size[ZONE_DMA] = max_dma;
		zones_size[ZONE_NORMAL] = low - max_dma;
#ifdef CONFIG_HIGHMEM
		zones_size[ZONE_HIGHMEM] = high - low;
#endif
	}
	free_area_init(zones_size);	
}
#else
extern void zone_sizes_init(void);
#endif /* !CONFIG_DISCONTIGMEM */

static int disable_nx __initdata = 0;
u64 __supported_pte_mask = ~_PAGE_NX;

/*
 * noexec = on|off
 *
 * Control non executable mappings.
 *
 * on      Enable
 * off     Disable (disables exec-shield too)
 */
static int __init noexec_setup(char *str)
{
	if (!strncmp(str, "on",2) && cpu_has_nx) {
		__supported_pte_mask |= _PAGE_NX;
		disable_nx = 0;
	} else if (!strncmp(str,"off",3)) {
		disable_nx = 1;
		__supported_pte_mask &= ~_PAGE_NX;
		exec_shield = 0;
	}
	return 1;
}

__setup("noexec=", noexec_setup);

#ifdef CONFIG_X86_PAE
int nx_enabled = 0;

static void __init set_nx(void)
{
	unsigned int v[4], l, h;

	if (cpu_has_pae && (cpuid_eax(0x80000000) > 0x80000001)) {
		cpuid(0x80000001, &v[0], &v[1], &v[2], &v[3]);
		if ((v[3] & (1 << 20)) && !disable_nx) {
			rdmsr(MSR_EFER, l, h);
			l |= EFER_NX;
			wrmsr(MSR_EFER, l, h);
			nx_enabled = 1;
			__supported_pte_mask |= _PAGE_NX;
		}
	}
}
/*
 * Enables/disables executability of a given kernel page and
 * returns the previous setting.
 */
int __init set_kernel_exec(unsigned long vaddr, int enable)
{
	pte_t *pte;
	int ret = 1;

	if (!nx_enabled)
		goto out;

	pte = lookup_address(vaddr);
	BUG_ON(!pte);

	if (!pte_exec_kernel(*pte))
		ret = 0;

	if (enable)
		pte->pte_high &= ~(1 << (_PAGE_BIT_NX - 32));
	else
		pte->pte_high |= 1 << (_PAGE_BIT_NX - 32);
	__flush_tlb_all();
out:
	return ret;
}

#endif

/*
 * paging_init() sets up the page tables - note that the first 8MB are
 * already mapped by head.S.
 *
 * This routines also unmaps the page at virtual kernel address 0, so
 * that we can trap those pesky NULL-reference errors in the kernel.
 */
void __init paging_init(void)
{
#ifdef CONFIG_X86_PAE
	set_nx();
	if (nx_enabled)
		printk("NX (Execute Disable) protection: active\n");
	else
#endif
	if (exec_shield)
		printk("Using x86 segment limits to approximate NX protection\n");

	pagetable_init();

	load_cr3(swapper_pg_dir);

#ifdef CONFIG_X86_PAE
	/*
	 * We will bail out later - printk doesn't work right now so
	 * the user would just see a hanging kernel.
	 */
	if (cpu_has_pae)
		set_in_cr4(X86_CR4_PAE);
#endif
	__flush_tlb_all();
	/*
	 * Subtle. SMP is doing it's boot stuff late (because it has to
	 * fork idle threads) - but it also needs low mappings for the
	 * protected-mode entry to work. We zap these entries only after
	 * the WP-bit has been tested.
	 */
#ifndef CONFIG_SMP
	zap_low_mappings();
#endif
	kmap_init();
	zone_sizes_init();
}

/*
 * Test if the WP bit works in supervisor mode. It isn't supported on 386's
 * and also on some strange 486's (NexGen etc.). All 586+'s are OK. This
 * used to involve black magic jumps to work around some nasty CPU bugs,
 * but fortunately the switch to using exceptions got rid of all that.
 */

void __init test_wp_bit(void)
{
	printk("Checking if this processor honours the WP bit even in supervisor mode... ");

	/* Any page-aligned address will do, the test is non-destructive */
	__set_fixmap(FIX_WP_TEST, __pa(&swapper_pg_dir), PAGE_READONLY);
	boot_cpu_data.wp_works_ok = do_test_wp_bit();
	clear_fixmap(FIX_WP_TEST);

	if (!boot_cpu_data.wp_works_ok) {
		printk("No.\n");
#ifdef CONFIG_X86_WP_WORKS_OK
		panic("This kernel doesn't support CPU's with broken WP. Recompile it for a 386!");
#endif
	} else {
		printk("Ok.\n");
	}
}

#ifndef CONFIG_DISCONTIGMEM
static void __init set_max_mapnr_init(void)
{
#ifdef CONFIG_HIGHMEM
	highmem_start_page = pfn_to_page(highstart_pfn);
	max_mapnr = num_physpages = highend_pfn;
#else
	max_mapnr = num_physpages = max_low_pfn;
#endif
}
#define __free_all_bootmem() free_all_bootmem()
#else
#define __free_all_bootmem() free_all_bootmem_node(NODE_DATA(0))
extern void set_max_mapnr_init(void);
#endif /* !CONFIG_DISCONTIGMEM */

static struct kcore_list kcore_mem, kcore_vmalloc; 

void __init mem_init(void)
{
	extern int ppro_with_ram_bug(void);
	int codesize, reservedpages, datasize, initsize;
	int tmp;
	int bad_ppro;

#ifndef CONFIG_DISCONTIGMEM
	if (!mem_map)
		BUG();
#endif
	
	bad_ppro = ppro_with_ram_bug();

#ifdef CONFIG_HIGHMEM
	/* check that fixmap and pkmap do not overlap */
	if (PKMAP_BASE+LAST_PKMAP*PAGE_SIZE >= FIXADDR_START) {
		printk(KERN_ERR "fixmap and kmap areas overlap - this will crash\n");
		printk(KERN_ERR "pkstart: %lxh pkend: %lxh fixstart %lxh\n",
				PKMAP_BASE, PKMAP_BASE+LAST_PKMAP*PAGE_SIZE, FIXADDR_START);
		BUG();
	}
#endif
 
	set_max_mapnr_init();

#ifdef CONFIG_HIGHMEM
	high_memory = (void *) __va(highstart_pfn * PAGE_SIZE);
#else
	high_memory = (void *) __va(max_low_pfn * PAGE_SIZE);
#endif

	/* this will put all low memory onto the freelists */
	totalram_pages += __free_all_bootmem();

	reservedpages = 0;
	for (tmp = 0; tmp < max_low_pfn; tmp++)
		/*
		 * Only count reserved RAM pages
		 */
		if (page_is_ram(tmp) && PageReserved(pfn_to_page(tmp)))
			reservedpages++;

	set_highmem_pages_init(bad_ppro);

	codesize =  (unsigned long) &_etext - (unsigned long) &_text;
	datasize =  (unsigned long) &_edata - (unsigned long) &_etext;
	initsize =  (unsigned long) &__init_end - (unsigned long) &__init_begin;

	kclist_add(&kcore_mem, __va(0), max_low_pfn << PAGE_SHIFT); 
	kclist_add(&kcore_vmalloc, (void *)VMALLOC_START, 
		   VMALLOC_END-VMALLOC_START);

	printk(KERN_INFO "Memory: %luk/%luk available (%dk kernel code, %dk reserved, %dk data, %dk init, %ldk highmem)\n",
		(unsigned long) nr_free_pages() << (PAGE_SHIFT-10),
		num_physpages << (PAGE_SHIFT-10),
		codesize >> 10,
		reservedpages << (PAGE_SHIFT-10),
		datasize >> 10,
		initsize >> 10,
		(unsigned long) (totalhigh_pages << (PAGE_SHIFT-10))
	       );

#ifdef CONFIG_X86_PAE
	if (!cpu_has_pae)
		panic("cannot execute a PAE-enabled kernel on a PAE-less CPU!");
#endif
	if (boot_cpu_data.wp_works_ok < 0)
		test_wp_bit();

	entry_trampoline_setup();
	default_ldt_page = virt_to_page(default_ldt);
	load_LDT(&init_mm.context);
}

kmem_cache_t *pgd_cache, *pmd_cache, *kpmd_cache;

void __init pgtable_cache_init(void)
{
	void (*ctor)(void *, kmem_cache_t *, unsigned long);
	void (*dtor)(void *, kmem_cache_t *, unsigned long);

	if (PTRS_PER_PMD > 1) {
		pmd_cache = kmem_cache_create("pmd",
					PTRS_PER_PMD*sizeof(pmd_t),
					PTRS_PER_PMD*sizeof(pmd_t),
					0,
					pmd_ctor,
					NULL);
		if (!pmd_cache)
			panic("pgtable_cache_init(): cannot create pmd cache");

		if (TASK_SIZE > PAGE_OFFSET) {
			kpmd_cache = kmem_cache_create("kpmd",
					PTRS_PER_PMD*sizeof(pmd_t),
					PTRS_PER_PMD*sizeof(pmd_t),
					0,
					kpmd_ctor,
					NULL);
			if (!kpmd_cache)
				panic("pgtable_cache_init(): "
						"cannot create kpmd cache");
		}
	}

	if (PTRS_PER_PMD == 1 || TASK_SIZE <= PAGE_OFFSET)
		ctor = pgd_ctor;
	else
		ctor = NULL;

	if (PTRS_PER_PMD == 1 && TASK_SIZE <= PAGE_OFFSET)
		dtor = pgd_dtor;
	else
		dtor = NULL;

	pgd_cache = kmem_cache_create("pgd",
				PTRS_PER_PGD*sizeof(pgd_t),
				PTRS_PER_PGD*sizeof(pgd_t),
				0,
				ctor,
				dtor);
	if (!pgd_cache)
		panic("pgtable_cache_init(): Cannot create pgd cache");
}

/*
 * This function cannot be __init, since exceptions don't work in that
 * section.  Put this after the callers, so that it cannot be inlined.
 */
static int noinline do_test_wp_bit(void)
{
	char tmp_reg;
	int flag;

	__asm__ __volatile__(
		"	movb %0,%1	\n"
		"1:	movb %1,%0	\n"
		"	xorl %2,%2	\n"
		"2:			\n"
		".section __ex_table,\"a\"\n"
		"	.align 4	\n"
		"	.long 1b,2b	\n"
		".previous		\n"
		:"=m" (*(char *)fix_to_virt(FIX_WP_TEST)),
		 "=q" (tmp_reg),
		 "=r" (flag)
		:"2" (1)
		:"memory");
	
	return flag;
}

void free_initmem(void)
{
	unsigned long addr;

	addr = (unsigned long)(&__init_begin);
	for (; addr < (unsigned long)(&__init_end); addr += PAGE_SIZE) {
		ClearPageReserved(virt_to_page(addr));
		set_page_count(virt_to_page(addr), 1);
		free_page(addr);
		totalram_pages++;
	}
	printk (KERN_INFO "Freeing unused kernel memory: %dk freed\n", (__init_end - __init_begin) >> 10);
}

#ifdef CONFIG_BLK_DEV_INITRD
void free_initrd_mem(unsigned long start, unsigned long end)
{
	if (start < end)
		printk (KERN_INFO "Freeing initrd memory: %ldk freed\n", (end - start) >> 10);
	for (; start < end; start += PAGE_SIZE) {
		ClearPageReserved(virt_to_page(start));
		set_page_count(virt_to_page(start), 1);
		free_page(start);
		totalram_pages++;
	}
}
#endif

#ifdef CONFIG_MEM_MIRROR
/*
 * For memory-tracking purposes, see mm_track.h for details.
 */
struct mm_tracker mm_tracking_struct = {0, ATOMIC_INIT(0), 0, 0};
EXPORT_SYMBOL_GPL(mm_tracking_struct);

/* The do_mm_track routine is needed by macros in the pgtable-2level.h
 * and pgtable-3level.h.
 */
void do_mm_track(void * val)
{
	pte_t *ptep = (pte_t*)val;
	unsigned long pfn;

	if (!pte_present(*ptep))
		return;

	pfn = pte_pfn(*ptep);
	pfn &= ((1LL << (PFN_BITS - PAGE_SHIFT)) - 1);

	if (pfn >= mm_tracking_struct.bitcnt)
		return;

	if (!test_and_set_bit(pfn, mm_tracking_struct.vector))
		atomic_inc(&mm_tracking_struct.count);
}
EXPORT_SYMBOL_GPL(do_mm_track);
#endif

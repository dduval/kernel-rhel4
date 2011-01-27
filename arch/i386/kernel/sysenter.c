/*
 * linux/arch/i386/kernel/sysenter.c
 *
 * (C) Copyright 2002 Linus Torvalds
 *
 * This file contains the needed initializations to support sysenter.
 */

#include <linux/init.h>
#include <linux/smp.h>
#include <linux/thread_info.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/elf.h>
#include <linux/mman.h>

#include <asm/cpufeature.h>
#include <asm/msr.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>
#include <linux/highmem.h>

extern asmlinkage void sysenter_entry(void);

void enable_sep_cpu(void *info)
{
	int cpu = get_cpu();
#ifdef CONFIG_X86_HIGH_ENTRY
	struct tss_struct *tss = (struct tss_struct *) __fix_to_virt(FIX_TSS_0) + cpu;
#else
	struct tss_struct *tss = init_tss + cpu;
#endif

	tss->ss1 = __KERNEL_CS;
	tss->esp1 = sizeof(struct tss_struct) + (unsigned long) tss;
	wrmsr(MSR_IA32_SYSENTER_CS, __KERNEL_CS, 0);
	wrmsr(MSR_IA32_SYSENTER_ESP, tss->esp1, 0);
	wrmsr(MSR_IA32_SYSENTER_EIP, (unsigned long) sysenter_entry, 0);
	put_cpu();	
}

/*
 * These symbols are defined by vsyscall.o to mark the bounds
 * of the ELF DSO images included therein.
 */
extern const char vsyscall_int80_start, vsyscall_int80_end;
extern const char vsyscall_sysenter_start, vsyscall_sysenter_end;

struct page *sysenter_page;

static int __init sysenter_setup(void)
{
	void *page = (void *)get_zeroed_page(GFP_ATOMIC);

	__set_fixmap(FIX_VSYSCALL, __pa(page), PAGE_KERNEL_RO);
	sysenter_page = virt_to_page(page);

	if (!boot_cpu_has(X86_FEATURE_SEP)) {
		memcpy(page,
		       &vsyscall_int80_start,
		       &vsyscall_int80_end - &vsyscall_int80_start);
		return 0;
	}

	memcpy(page,
	       &vsyscall_sysenter_start,
	       &vsyscall_sysenter_end - &vsyscall_sysenter_start);

	on_each_cpu(enable_sep_cpu, NULL, 1, 1);

	return 0;
}

__initcall(sysenter_setup);

extern void SYSENTER_RETURN_OFFSET;

unsigned int vdso_enabled = 0;

void map_vsyscall(void)
{
	struct thread_info *ti = current_thread_info();
	struct vm_area_struct *vma;
	unsigned long addr;

	if (unlikely(!vdso_enabled)) {
		current->mm->context.vdso = NULL;
		return;
	}

	/*
	 * Map the vDSO (it will be randomized):
	 */
	down_write(&current->mm->mmap_sem);
	addr = do_mmap(NULL, 0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, 0);
	current->mm->context.vdso = (void *)addr;
	ti->sysenter_return = (void *)addr + (long)&SYSENTER_RETURN_OFFSET;
	if (addr != -1) {
		vma = find_vma(current->mm, addr);
		if (vma) {
			pgprot_val(vma->vm_page_prot) &= ~_PAGE_RW;
			get_page(sysenter_page);
			install_page(current->mm, vma, addr,
					sysenter_page, vma->vm_page_prot);
			
		}
	}
	up_write(&current->mm->mmap_sem);
}

static int __init vdso_setup(char *str)
{
        vdso_enabled = simple_strtoul(str, NULL, 0);
        return 1;
}
__setup("vdso=", vdso_setup);


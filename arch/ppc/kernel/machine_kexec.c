/*
 * machine_kexec.c - handle transition of Linux booting another kernel
 * Copyright (C) 2002-2003 Eric Biederman  <ebiederm@xmission.com>
 *
 * GAMECUBE/PPC32 port Copyright (C) 2004 Albert Herranz
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <linux/mm.h>
#include <linux/kexec.h>
#include <linux/delay.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/io.h>
#include <asm/hw_irq.h>
#include <asm/cacheflush.h>

typedef void (*relocate_new_kernel_t)(
	unsigned long indirection_page, unsigned long reboot_code_buffer,
	unsigned long start_address);

const extern unsigned char relocate_new_kernel[];
const extern unsigned int relocate_new_kernel_size;
extern void use_mm(struct mm_struct *mm);

static int identity_map_pages(struct page *pages, int order)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int error;

	mm = &init_mm;
	vma = NULL;

	down_write(&mm->mmap_sem);
	error = -ENOMEM;
	vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (!vma) {
		goto out;
	}

	memset(vma, 0, sizeof(*vma));
	vma->vm_mm = mm;
	vma->vm_start = page_to_pfn(pages) << PAGE_SHIFT;
	vma->vm_end = vma->vm_start + (1 << (order + PAGE_SHIFT));
	vma->vm_ops = NULL;
	vma->vm_flags = VM_SHARED \
		| VM_READ | VM_WRITE | VM_EXEC \
		| VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC \
		| VM_DONTCOPY | VM_RESERVED;
	vma->vm_page_prot = protection_map[vma->vm_flags & 0xf];
	vma->vm_file = NULL;
	vma->vm_private_data = NULL;
	insert_vm_struct(mm, vma);

	error = remap_page_range(vma, vma->vm_start, vma->vm_start,
		vma->vm_end - vma->vm_start, vma->vm_page_prot);
	if (error) {
		goto out;
	}

	error = 0;
 out:
	if (error && vma) {
		kmem_cache_free(vm_area_cachep, vma);
		vma = NULL;
	}
	up_write(&mm->mmap_sem);

	return error;
}

/*
 * Do what every setup is needed on image and the
 * reboot code buffer to allow us to avoid allocations
 * later.
 */
int machine_kexec_prepare(struct kimage *image)
{
	unsigned int order;
	order = get_order(KEXEC_CONTROL_CODE_SIZE);
	return identity_map_pages(image->control_code_page, order);
}

void machine_kexec_cleanup(struct kimage *image)
{
	unsigned int order;
	order = get_order(KEXEC_CONTROL_CODE_SIZE);
	do_munmap(&init_mm,
		page_to_pfn(image->control_code_page) << PAGE_SHIFT,
		1 << (order + PAGE_SHIFT));
}

void machine_shutdown(void)
{
}

/*
 * Do not allocate memory (or fail in any way) in machine_kexec().
 * We are past the point of no return, committed to rebooting now.
 */
void machine_kexec(struct kimage *image)
{
	unsigned long indirection_page;
	unsigned long reboot_code_buffer;
	relocate_new_kernel_t rnk;

	/* switch to an mm where the reboot_code_buffer is identity mapped */
	use_mm(&init_mm);

	/* Interrupts aren't acceptable while we reboot */
	local_irq_disable();

	reboot_code_buffer = page_to_pfn(image->control_code_page) <<PAGE_SHIFT;
	indirection_page = image->head & PAGE_MASK;

	/* copy it out */
	memcpy((void *)reboot_code_buffer,
		relocate_new_kernel, relocate_new_kernel_size);

	flush_icache_range(reboot_code_buffer,
		reboot_code_buffer + KEXEC_CONTROL_CODE_SIZE);
	printk(KERN_INFO "Bye!\n");

	/* now call it */
	rnk = (relocate_new_kernel_t) reboot_code_buffer;
	(*rnk)(indirection_page, reboot_code_buffer, image->start);
}


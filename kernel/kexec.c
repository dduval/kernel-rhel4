/*
 * kexec.c - kexec system call
 * Copyright (C) 2002-2004 Eric Biederman  <ebiederm@xmission.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <linux/mm.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/kexec.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <net/checksum.h>
#include <asm/page.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/system.h>

/*
 * When kexec transitions to the new kernel there is a one-to-one
 * mapping between physical and virtual addresses.  On processors
 * where you can disable the MMU this is trivial, and easy.  For
 * others it is still a simple predictable page table to setup.
 *
 * In that environment kexec copies the new kernel to its final
 * resting place.  This means I can only support memory whose
 * physical address can fit in an unsigned long.  In particular
 * addresses where (pfn << PAGE_SHIFT) > ULONG_MAX cannot be handled.
 * If the assembly stub has more restrictive requirements
 * KEXEC_SOURCE_MEMORY_LIMIT and KEXEC_DEST_MEMORY_LIMIT can be
 * defined more restrictively in <asm/kexec.h>.
 *
 * The code for the transition from the current kernel to the
 * the new kernel is placed in the control_code_buffer, whose size
 * is given by KEXEC_CONTROL_CODE_SIZE.  In the best case only a single
 * page of memory is necessary, but some architectures require more.
 * Because this memory must be identity mapped in the transition from
 * virtual to physical addresses it must live in the range
 * 0 - TASK_SIZE, as only the user space mappings are arbitrarily
 * modifiable.
 *
 * The assembly stub in the control code buffer is passed a linked list
 * of descriptor pages detailing the source pages of the new kernel,
 * and the destination addresses of those source pages.  As this data
 * structure is not used in the context of the current OS, it must
 * be self-contained.
 *
 * The code has been made to work with highmem pages and will use a
 * destination page in its final resting place (if it happens
 * to allocate it).  The end product of this is that most of the
 * physical address space, and most of RAM can be used.
 *
 * Future directions include:
 *  - allocating a page table with the control code buffer identity
 *    mapped, to simplify machine_kexec and make kexec_on_panic more
 *    reliable.
 */

/*
 * KIMAGE_NO_DEST is an impossible destination address..., for
 * allocating pages whose destination address we do not care about.
 */
#define KIMAGE_NO_DEST (-1UL)

static int kimage_is_destination_range(
	struct kimage *image, unsigned long start, unsigned long end);
static struct page *kimage_alloc_page(struct kimage *image, unsigned int gfp_mask, unsigned long dest);


static int kimage_alloc(struct kimage **rimage,
	unsigned long nr_segments, struct kexec_segment *segments)
{
	int result;
	struct kimage *image;
	size_t segment_bytes;
	unsigned long i;

	/* Allocate a controlling structure */
	result = -ENOMEM;
	image = kmalloc(sizeof(*image), GFP_KERNEL);
	if (!image) {
		goto out;
	}
	memset(image, 0, sizeof(*image));
	image->head = 0;
	image->entry = &image->head;
	image->last_entry = &image->head;

	/* Initialize the list of control pages */
	INIT_LIST_HEAD(&image->control_pages);

	/* Initialize the list of destination pages */
	INIT_LIST_HEAD(&image->dest_pages);

	/* Initialize the list of unuseable pages */
	INIT_LIST_HEAD(&image->unuseable_pages);

	/* Read in the segments */
	image->nr_segments = nr_segments;
	segment_bytes = nr_segments * sizeof*segments;
	result = copy_from_user(image->segment, segments, segment_bytes);
	if (result)
		goto out;

	/*
	 * Verify we have good destination addresses.  The caller is
	 * responsible for making certain we don't attempt to load
	 * the new image into invalid or reserved areas of RAM.  This
	 * just verifies it is an address we can use.
	 */
	result = -EADDRNOTAVAIL;
	for (i = 0; i < nr_segments; i++) {
		unsigned long mend;
		mend = ((unsigned long)(image->segment[i].mem)) +
			image->segment[i].memsz;
		if (mend >= KEXEC_DESTINATION_MEMORY_LIMIT)
			goto out;
	}

	/*
	 * Find a location for the control code buffer, and add it
	 * the vector of segments so that it's pages will also be
	 * counted as destination pages.
	 */
	result = -ENOMEM;
	image->control_code_page = kimage_alloc_control_pages(image,
		get_order(KEXEC_CONTROL_CODE_SIZE));
	if (!image->control_code_page) {
		printk(KERN_ERR "Could not allocate control_code_buffer\n");
		goto out;
	}

	result = 0;
 out:
	if (result == 0) {
		*rimage = image;
	} else {
		kfree(image);
	}
	return result;
}

static int kimage_is_destination_range(
	struct kimage *image, unsigned long start, unsigned long end)
{
	unsigned long i;

	for (i = 0; i < image->nr_segments; i++) {
		unsigned long mstart, mend;
		mstart = (unsigned long)image->segment[i].mem;
		mend   = mstart + image->segment[i].memsz;
		if ((end > mstart) && (start < mend)) {
			return 1;
		}
	}
	return 0;
}

static struct page *kimage_alloc_pages(unsigned int gfp_mask, unsigned int order)
{
	struct page *pages;
	pages = alloc_pages(gfp_mask, order);
	if (pages) {
		unsigned int count, i;
		pages->mapping = NULL;
		pages->private = order;
		count = 1 << order;
		for(i = 0; i < count; i++) {
			SetPageReserved(pages + i);
		}
	}
	return pages;
}

static void kimage_free_pages(struct page *page)
{
	unsigned int order, count, i;
	order = page->private;
	count = 1 << order;
	for(i = 0; i < count; i++) {
		ClearPageReserved(page + i);
	}
	__free_pages(page, order);
}

static void kimage_free_page_list(struct list_head *list)
{
	struct list_head *pos, *next;
	list_for_each_safe(pos, next, list) {
		struct page *page;

		page = list_entry(pos, struct page, lru);
		list_del(&page->lru);

		kimage_free_pages(page);
	}
}

struct page *kimage_alloc_control_pages(struct kimage *image, unsigned int order)
{
	/* Control pages are special, they are the intermediaries
	 * that are needed while we copy the rest of the pages
	 * to their final resting place.  As such they must
	 * not conflict with either the destination addresses
	 * or memory the kernel is already using.
	 *
	 * The only case where we really need more than one of
	 * these are for architectures where we cannot disable
	 * the MMU and must instead generate an identity mapped
	 * page table for all of the memory.
	 *
	 * At worst this runs in O(N) of the image size.
	 */
	struct list_head extra_pages;
	struct page *pages;
	unsigned int count;

	count = 1 << order;
	INIT_LIST_HEAD(&extra_pages);

	/* Loop while I can allocate a page and the page allocated
	 * is a destination page.
	 */
	do {
		unsigned long pfn, epfn, addr, eaddr;
		pages = kimage_alloc_pages(GFP_KERNEL, order);
		if (!pages)
			break;
		pfn   = page_to_pfn(pages);
		epfn  = pfn + count;
		addr  = pfn << PAGE_SHIFT;
		eaddr = epfn << PAGE_SHIFT;
		if ((epfn >= (KEXEC_CONTROL_MEMORY_LIMIT >> PAGE_SHIFT)) ||
			kimage_is_destination_range(image, addr, eaddr))
		{
			list_add(&pages->lru, &extra_pages);
			pages = NULL;
		}
	} while(!pages);
	if (pages) {
		/* Remember the allocated page... */
		list_add(&pages->lru, &image->control_pages);

		/* Because the page is already in it's destination
		 * location we will never allocate another page at
		 * that address.  Therefore kimage_alloc_pages
		 * will not return it (again) and we don't need
		 * to give it an entry in image->segment[].
		 */
	}
	/* Deal with the destination pages I have inadvertently allocated.
	 *
	 * Ideally I would convert multi-page allocations into single
	 * page allocations, and add everyting to image->dest_pages.
	 *
	 * For now it is simpler to just free the pages.
	 */
	kimage_free_page_list(&extra_pages);
	return pages;

}

static int kimage_add_entry(struct kimage *image, kimage_entry_t entry)
{
	if (*image->entry != 0) {
		image->entry++;
	}
	if (image->entry == image->last_entry) {
		kimage_entry_t *ind_page;
		struct page *page;
		page = kimage_alloc_page(image, GFP_KERNEL, KIMAGE_NO_DEST);
		if (!page) {
			return -ENOMEM;
		}
		ind_page = page_address(page);
		*image->entry = virt_to_phys(ind_page) | IND_INDIRECTION;
		image->entry = ind_page;
		image->last_entry =
			ind_page + ((PAGE_SIZE/sizeof(kimage_entry_t)) - 1);
	}
	*image->entry = entry;
	image->entry++;
	*image->entry = 0;
	return 0;
}

static int kimage_set_destination(
	struct kimage *image, unsigned long destination)
{
	int result;

	destination &= PAGE_MASK;
	result = kimage_add_entry(image, destination | IND_DESTINATION);
	if (result == 0) {
		image->destination = destination;
	}
	return result;
}


static int kimage_add_page(struct kimage *image, unsigned long page)
{
	int result;

	page &= PAGE_MASK;
	result = kimage_add_entry(image, page | IND_SOURCE);
	if (result == 0) {
		image->destination += PAGE_SIZE;
	}
	return result;
}


static void kimage_free_extra_pages(struct kimage *image)
{
	/* Walk through and free any extra destination pages I may have */
	kimage_free_page_list(&image->dest_pages);

	/* Walk through and free any unuseable pages I have cached */
	kimage_free_page_list(&image->unuseable_pages);

}
static int kimage_terminate(struct kimage *image)
{
	int result;

	result = kimage_add_entry(image, IND_DONE);
	if (result == 0) {
		/* Point at the terminating element */
		image->entry--;
		kimage_free_extra_pages(image);
	}
	return result;
}

#define for_each_kimage_entry(image, ptr, entry) \
	for (ptr = &image->head; (entry = *ptr) && !(entry & IND_DONE); \
		ptr = (entry & IND_INDIRECTION)? \
			phys_to_virt((entry & PAGE_MASK)): ptr +1)

static void kimage_free_entry(kimage_entry_t entry)
{
	struct page *page;

	page = pfn_to_page(entry >> PAGE_SHIFT);
	kimage_free_pages(page);
}

static void kimage_free(struct kimage *image)
{
	kimage_entry_t *ptr, entry;
	kimage_entry_t ind = 0;

	if (!image)
		return;
	kimage_free_extra_pages(image);
	for_each_kimage_entry(image, ptr, entry) {
		if (entry & IND_INDIRECTION) {
			/* Free the previous indirection page */
			if (ind & IND_INDIRECTION) {
				kimage_free_entry(ind);
			}
			/* Save this indirection page until we are
			 * done with it.
			 */
			ind = entry;
		}
		else if (entry & IND_SOURCE) {
			kimage_free_entry(entry);
		}
	}
	/* Free the final indirection page */
	if (ind & IND_INDIRECTION) {
		kimage_free_entry(ind);
	}

	/* Handle any machine specific cleanup */
	machine_kexec_cleanup(image);

	/* Free the kexec control pages... */
	kimage_free_page_list(&image->control_pages);
	kfree(image);
}

static kimage_entry_t *kimage_dst_used(struct kimage *image, unsigned long page)
{
	kimage_entry_t *ptr, entry;
	unsigned long destination = 0;

	for_each_kimage_entry(image, ptr, entry) {
		if (entry & IND_DESTINATION) {
			destination = entry & PAGE_MASK;
		}
		else if (entry & IND_SOURCE) {
			if (page == destination) {
				return ptr;
			}
			destination += PAGE_SIZE;
		}
	}
	return 0;
}

static struct page *kimage_alloc_page(struct kimage *image, unsigned int gfp_mask, unsigned long destination)
{
	/*
	 * Here we implement safeguards to ensure that a source page
	 * is not copied to its destination page before the data on
	 * the destination page is no longer useful.
	 *
	 * To do this we maintain the invariant that a source page is
	 * either its own destination page, or it is not a
	 * destination page at all.
	 *
	 * That is slightly stronger than required, but the proof
	 * that no problems will not occur is trivial, and the
	 * implementation is simply to verify.
	 *
	 * When allocating all pages normally this algorithm will run
	 * in O(N) time, but in the worst case it will run in O(N^2)
	 * time.   If the runtime is a problem the data structures can
	 * be fixed.
	 */
	struct page *page;
	unsigned long addr;

	/*
	 * Walk through the list of destination pages, and see if I
	 * have a match.
	 */
	list_for_each_entry(page, &image->dest_pages, lru) {
		addr = page_to_pfn(page) << PAGE_SHIFT;
		if (addr == destination) {
			list_del(&page->lru);
			return page;
		}
	}
	page = NULL;
	while (1) {
		kimage_entry_t *old;

		/* Allocate a page, if we run out of memory give up */
		page = kimage_alloc_pages(gfp_mask, 0);
		if (!page) {
			return 0;
		}
		/* If the page cannot be used file it away */
		if (page_to_pfn(page) > (KEXEC_SOURCE_MEMORY_LIMIT >> PAGE_SHIFT)) {
			list_add(&page->lru, &image->unuseable_pages);
			continue;
		}
		addr = page_to_pfn(page) << PAGE_SHIFT;

		/* If it is the destination page we want use it */
		if (addr == destination)
			break;

		/* If the page is not a destination page use it */
		if (!kimage_is_destination_range(image, addr, addr + PAGE_SIZE))
			break;

		/*
		 * I know that the page is someones destination page.
		 * See if there is already a source page for this
		 * destination page.  And if so swap the source pages.
		 */
		old = kimage_dst_used(image, addr);
		if (old) {
			/* If so move it */
			unsigned long old_addr;
			struct page *old_page;

			old_addr = *old & PAGE_MASK;
			old_page = pfn_to_page(old_addr >> PAGE_SHIFT);
			copy_highpage(page, old_page);
			*old = addr | (*old & ~PAGE_MASK);

			/* The old page I have found cannot be a
			 * destination page, so return it.
			 */
			addr = old_addr;
			page = old_page;
			break;
		}
		else {
			/* Place the page on the destination list I
			 * will use it later.
			 */
			list_add(&page->lru, &image->dest_pages);
		}
	}
	return page;
}

static int kimage_load_segment(struct kimage *image,
	struct kexec_segment *segment)
{
	unsigned long mstart;
	int result;
	unsigned long offset;
	unsigned long offset_end;
	unsigned char *buf;

	result = 0;
	buf = segment->buf;
	mstart = (unsigned long)segment->mem;

	offset_end = segment->memsz;

	result = kimage_set_destination(image, mstart);
	if (result < 0) {
		goto out;
	}
	for (offset = 0;  offset < segment->memsz; offset += PAGE_SIZE) {
		struct page *page;
		char *ptr;
		size_t size, leader;
		page = kimage_alloc_page(image, GFP_HIGHUSER, mstart + offset);
		if (page == 0) {
			result  = -ENOMEM;
			goto out;
		}
		result = kimage_add_page(image, page_to_pfn(page) << PAGE_SHIFT);
		if (result < 0) {
			goto out;
		}
		ptr = kmap(page);
		if (segment->bufsz < offset) {
			/* We are past the end zero the whole page */
			memset(ptr, 0, PAGE_SIZE);
			kunmap(page);
			continue;
		}
		size = PAGE_SIZE;
		leader = 0;
		if ((offset == 0)) {
			leader = mstart & ~PAGE_MASK;
		}
		if (leader) {
			/* We are on the first page zero the unused portion */
			memset(ptr, 0, leader);
			size -= leader;
			ptr += leader;
		}
		if (size > (segment->bufsz - offset)) {
			size = segment->bufsz - offset;
		}
		if (size < (PAGE_SIZE - leader)) {
			/* zero the trailing part of the page */
			memset(ptr + size, 0, (PAGE_SIZE - leader) - size);
		}
		result = copy_from_user(ptr, buf + offset, size);
		kunmap(page);
		if (result) {
			result = (result < 0) ? result : -EIO;
			goto out;
		}
	}
 out:
	return result;
}

/*
 * Exec Kernel system call: for obvious reasons only root may call it.
 *
 * This call breaks up into three pieces.
 * - A generic part which loads the new kernel from the current
 *   address space, and very carefully places the data in the
 *   allocated pages.
 *
 * - A generic part that interacts with the kernel and tells all of
 *   the devices to shut down.  Preventing on-going dmas, and placing
 *   the devices in a consistent state so a later kernel can
 *   reinitialize them.
 *
 * - A machine specific part that includes the syscall number
 *   and the copies the image to it's final destination.  And
 *   jumps into the image at entry.
 *
 * kexec does not sync, or unmount filesystems so if you need
 * that to happen you need to do that yourself.
 */
struct kimage *kexec_image = NULL;

asmlinkage long sys_kexec_load(unsigned long entry, unsigned long nr_segments,
	struct kexec_segment *segments, unsigned long flags)
{
	struct kimage *image;
	int result;

	/* We only trust the superuser with rebooting the system. */
	if (!capable(CAP_SYS_BOOT))
		return -EPERM;

	/*
	 * In case we need just a little bit of special behavior for
	 * reboot on panic.
	 */
	if (flags != 0)
		return -EINVAL;

	if (nr_segments > KEXEC_SEGMENT_MAX)
		return -EINVAL;

	image = NULL;
	result = 0;

	if (nr_segments > 0) {
		unsigned long i;
		result = kimage_alloc(&image, nr_segments, segments);
		if (result) {
			goto out;
		}
		result = machine_kexec_prepare(image);
		if (result) {
			goto out;
		}
		image->start = entry;
		for (i = 0; i < nr_segments; i++) {
			result = kimage_load_segment(image, &image->segment[i]);
			if (result) {
				goto out;
			}
		}
		result = kimage_terminate(image);
		if (result) {
			goto out;
		}
	}

	image = xchg(&kexec_image, image);

 out:
	kimage_free(image);
	return result;
}

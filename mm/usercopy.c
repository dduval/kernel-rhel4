/*
 * linux/mm/usercopy.c
 *
 * (C) Copyright 2003 Ingo Molnar
 *
 * Generic implementation of all the user-VM access functions, without
 * relying on being able to access the VM directly.
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>
#include <linux/ptrace.h>
#include <linux/interrupt.h>

#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/atomic_kmap.h>

/*
 * Get kernel address of the user page and pin it.
 */
static inline struct page *pin_page(unsigned long addr, int write,
				    pte_t *pte)
{
	struct mm_struct *mm = current->mm ? : &init_mm;
	struct page *page = NULL;
	int ret;

	/*
	 * Do a quick atomic lookup first - this is the fastpath.
	 */
retry:
	page = follow_page_pte(mm, addr, write, pte);
	if (likely(page != NULL)) {
		if (!PageReserved(page))
			get_page(page);
		return page;
	}
	if (pte_present(*pte))
		return NULL;
	/*
	 * No luck - bad address or need to fault in the page:
	 */

	/* Release the lock so get_user_pages can sleep */
	spin_unlock(&mm->page_table_lock);

	/*
	 * In the context of filemap_copy_from_user(), we are not allowed
	 * to sleep.  We must fail this usercopy attempt and allow
	 * filemap_copy_from_user() to recover: drop its atomic kmap and use
	 * a sleeping kmap instead.
	 */
	if (in_atomic()) {
		spin_lock(&mm->page_table_lock);
		return NULL;
	}

	down_read(&mm->mmap_sem);
	ret = get_user_pages(current, mm, addr, 1, write, 0, NULL, NULL);
	up_read(&mm->mmap_sem);
	spin_lock(&mm->page_table_lock);

	if (ret <= 0)
		return NULL;

	/*
	 * Go try the follow_page again.
	 */
	goto retry;
}

static inline void unpin_page(struct page *page)
{
	put_page(page);
}

/*
 * Access another process' address space.
 * Source/target buffer must be kernel space,
 * Do not walk the page table directly, use get_user_pages
 */
static int rw_vm(unsigned long addr, void *buf, int len, int write)
{
	struct mm_struct *mm = current->mm ? : &init_mm;

	if (!len)
		return 0;

	spin_lock(&mm->page_table_lock);

	/* ignore errors, just check how much was sucessfully transfered */
	while (len) {
		struct page *page = NULL;
		pte_t pte;
		int bytes, offset;
		void *maddr;

		page = pin_page(addr, write, &pte);
		if (!page && !pte_present(pte))
			break;

		bytes = len;
		offset = addr & (PAGE_SIZE-1);
		if (bytes > PAGE_SIZE-offset)
			bytes = PAGE_SIZE-offset;

		if (page)
			maddr = kmap_atomic(page, KM_USER_COPY);
		else
			/* we will map with user pte
			 */
			maddr = kmap_atomic_pte(&pte, KM_USER_COPY);

#define HANDLE_TYPE(type) \
	case sizeof(type): *(type *)(maddr+offset) = *(type *)(buf); break;

		if (write) {
			switch (bytes) {
			HANDLE_TYPE(char);
			HANDLE_TYPE(int);
			HANDLE_TYPE(long long);
			default:
				memcpy(maddr + offset, buf, bytes);
			}
		} else {
#undef HANDLE_TYPE
#define HANDLE_TYPE(type) \
	case sizeof(type): *(type *)(buf) = *(type *)(maddr+offset); break;
			switch (bytes) {
			HANDLE_TYPE(char);
			HANDLE_TYPE(int);
			HANDLE_TYPE(long long);
			default:
				memcpy(buf, maddr + offset, bytes);
			}
#undef HANDLE_TYPE
		}
		kunmap_atomic(maddr, KM_USER_COPY);
		if (page)
			unpin_page(page);
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	spin_unlock(&mm->page_table_lock);

	return len;
}

static int str_vm(unsigned long addr, void *buf0, int len, int copy)
{
	struct mm_struct *mm = current->mm ? : &init_mm;
	struct page *page;
	void *buf = buf0;

	if (!len)
		return len;

	spin_lock(&mm->page_table_lock);

	/* ignore errors, just check how much was sucessfully transfered */
	while (len) {
		int bytes, offset, left, copied;
		pte_t pte;
		char *maddr;

		page = pin_page(addr, copy == 2, &pte);
		if (!page && !pte_present(pte)) {
			spin_unlock(&mm->page_table_lock);
			return -EFAULT;
		}
		bytes = len;
		offset = addr & (PAGE_SIZE-1);
		if (bytes > PAGE_SIZE-offset)
			bytes = PAGE_SIZE-offset;

		if (page)
			maddr = kmap_atomic(page, KM_USER_COPY);
		else
			/* we will map with user pte
			 */
			maddr = kmap_atomic_pte(&pte, KM_USER_COPY);
		if (copy == 2) {
			memset(maddr + offset, 0, bytes);
			copied = bytes;
			left = 0;
		} else if (copy == 1) {
			left = strncpy_count(buf, maddr + offset, bytes);
			copied = bytes - left;
		} else {
			copied = strnlen(maddr + offset, bytes);
			left = bytes - copied;
		}
		BUG_ON(bytes < 0 || copied < 0);
		kunmap_atomic(maddr, KM_USER_COPY);
		if (page)
			unpin_page(page);
		len -= copied;
		buf += copied;
		addr += copied;
		if (left)
			break;
	}
	spin_unlock(&mm->page_table_lock);

	return len;
}

/*
 * Copies memory from userspace (ptr) into kernelspace (val).
 *
 * returns # of bytes not copied.
 */
int get_user_size(unsigned int size, void *val, const void *ptr)
{
	int ret;

	if (unlikely(segment_eq(get_fs(), KERNEL_DS)))
		ret = __direct_copy_from_user_inatomic(val, ptr, size);
	else
		ret = rw_vm((unsigned long)ptr, val, size, 0);
	if (ret)
		/*
		 * Zero the rest:
		 */
		memset(val + size - ret, 0, ret);
	return ret;
}

/*
 * Copies memory from kernelspace (val) into userspace (ptr).
 *
 * returns # of bytes not copied.
 */
int put_user_size(unsigned int size, const void *val, void *ptr)
{
	if (unlikely(segment_eq(get_fs(), KERNEL_DS)))
		return __direct_copy_to_user_inatomic(ptr, val, size);
	else
		return rw_vm((unsigned long)ptr, (void *)val, size, 1);
}

int copy_str_fromuser_size(unsigned int size, void *val, const void *ptr)
{
	int copied, left;

	if (unlikely(segment_eq(get_fs(), KERNEL_DS))) {
		left = strncpy_count(val, ptr, size);
		copied = size - left;
		BUG_ON(copied < 0);

		return copied;
	}
	left = str_vm((unsigned long)ptr, val, size, 1);
	if (left < 0)
		return left;
	copied = size - left;
	BUG_ON(copied < 0);

	return copied;
}

int strlen_fromuser_size(unsigned int size, const void *ptr)
{
	int copied, left;

	if (unlikely(segment_eq(get_fs(), KERNEL_DS))) {
		copied = strnlen(ptr, size) + 1;
		BUG_ON(copied < 0);

		return copied;
	}
	left = str_vm((unsigned long)ptr, NULL, size, 0);
	if (left < 0)
		return 0;
	copied = size - left + 1;
	BUG_ON(copied < 0);

	return copied;
}

int zero_user_size(unsigned int size, void *ptr)
{
	int left;

	if (unlikely(segment_eq(get_fs(), KERNEL_DS))) {
		memset(ptr, 0, size);
		return 0;
	}
	left = str_vm((unsigned long)ptr, NULL, size, 2);
	if (left < 0)
		return size;
	return left;
}

EXPORT_SYMBOL(get_user_size);
EXPORT_SYMBOL(put_user_size);
EXPORT_SYMBOL(zero_user_size);
EXPORT_SYMBOL(copy_str_fromuser_size);
EXPORT_SYMBOL(strlen_fromuser_size);

#ifndef _ASM_KMAP_TYPES_H
#define _ASM_KMAP_TYPES_H

#include <linux/config.h>
#include <linux/thread_info.h>

enum km_type {
	/*
	 * IMPORTANT: don't move these 3 entries, be wary when adding entries,
	 * the 4G/4G virtual stack must be THREAD_SIZE aligned on each cpu.
	 */
	KM_BOUNCE_READ,
	KM_VSTACK_BASE,
	KM_VSTACK_TOP = KM_VSTACK_BASE + STACK_PAGE_COUNT-1,

	KM_LDT_PAGE15,
	KM_LDT_PAGE0 = KM_LDT_PAGE15 + 16-1,
	KM_USER_COPY,
	KM_VSTACK_HOLE,
	KM_SKB_SUNRPC_DATA,
	KM_SKB_DATA_SOFTIRQ,
	KM_USER0,
	KM_USER1,
	KM_BIO_SRC_IRQ,
	KM_BIO_DST_IRQ,
	KM_PTE0,
	KM_PTE1,
	KM_IRQ0,
	KM_IRQ1,
	KM_SOFTIRQ0,
	KM_SOFTIRQ1,
	KM_CRASHDUMP,
	KM_UNUSED,
	KM_SWIOTLB,
	KM_TYPE_NR
};

#endif

#ifndef __i386_MMU_H
#define __i386_MMU_H

#include <asm/semaphore.h>
/*
 * The i386 doesn't have a mmu context, but
 * we put the segment information here.
 *
 * cpu_vm_mask is used to optimize ldt flushing.
 *
 * exec_limit is used to track the range PROT_EXEC
 * mappings span.
 */

#define MAX_LDT_PAGES 16

typedef struct { 
	int size;
	struct semaphore sem;
	struct page *ldt_pages[MAX_LDT_PAGES];
	struct desc_struct user_cs;
	unsigned long exec_limit;
	void *vdso;
} mm_context_t;

#endif

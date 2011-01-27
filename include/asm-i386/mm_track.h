#ifndef __I386_MMTRACK_H__
#define __I386_MMTRACK_H__

#ifndef CONFIG_MEM_MIRROR

#define mm_track(ptep) do { ; } while (0)

#else

#include <asm/page.h>
#include <asm/atomic.h>
 /*
  * For memory-tracking purposes, if active is true (non-zero), the other
  * elements of the structure are available for use.  Each time mm_track
  * is called, it increments count and sets a bit in the bitvector table.
  * Each bit in the bitvector represents a physical page in memory.
  *
  * This is declared in arch/i386/mm/init.c.
  *
  * The in_use element is used in the code which drives the memory tracking
  * environment.  When tracking is complete, the vector may be freed, but 
  * only after the active flag is set to zero and the in_use count goes to
  * zero.
  *
  * The count element indicates how many pages have been stored in the
  * bitvector.  This is an optimization to avoid counting the bits in the
  * vector between harvest operations.
  */
struct mm_tracker {
	int active;		// non-zero if this structure in use
	atomic_t count;		// number of pages tracked by mm_track()
	unsigned long * vector;	// bit vector of modified pages
	unsigned long bitcnt;	// number of bits in vector
};
extern struct mm_tracker mm_tracking_struct;

#ifdef CONFIG_X86_PAE
#define PFN_BITS	36
#else /* !CONFIG_X86_PAE */
#define PFN_BITS	32
#endif /* !CONFIG_X86_PAE */

extern void do_mm_track(void *);

/* The mm_track routine is needed by macros in the pgtable-2level.h
 * and pgtable-3level.h.  The pte manipulation is all longhand below
 * because the required order of header files makes all the useful
 * definitions happen after the following code.
 */
static __inline__ void mm_track(void * val)
{
	if (unlikely(mm_tracking_struct.active))
		do_mm_track(val);
}
#endif /* CONFIG_MEM_MIRROR */

#endif /* __I386_MMTRACK_H__ */

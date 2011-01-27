#ifndef __X86_64_MMTRACK_H__
#define __X86_64_MMTRACK_H__

#ifndef CONFIG_MEM_MIRROR

#define mm_track_pte(ptep)		do { ; } while (0)
#define mm_track_pmd(ptep)		do { ; } while (0)
#define mm_track_pgd(ptep)		do { ; } while (0)
#define mm_track_pml4(ptep)		do { ; } while (0)
#define mm_track_phys(x)		do { ; } while (0)

#else

#include <asm/page.h>
#include <asm/atomic.h>
 /*
  * For memory-tracking purposes, if active is true (non-zero), the other
  * elements of the structure are available for use.  Each time mm_track
  * is called, it increments count and sets a bit in the bitvector table.
  * Each bit in the bitvector represents a physical page in memory.
  *
  * This is declared in arch/x86_64/mm/init.c.
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

extern void (*do_mm_track_pte)(void *);
extern void (*do_mm_track_pmd)(void *);
extern void (*do_mm_track_pgd)(void *);
extern void (*do_mm_track_pml4)(void *);
extern void (*do_mm_track_phys)(void *);

/* The mm_track routine is needed by macros in the pgtable-2level.h
 * and pgtable-3level.h.
 */
static __inline__ void mm_track_pte(void * val)
{
	if (unlikely(mm_tracking_struct.active))
		do_mm_track_pte(val);
}
static __inline__ void mm_track_pmd(void * val)
{
	if (unlikely(mm_tracking_struct.active))
		do_mm_track_pmd(val);
}
static __inline__ void mm_track_pgd(void * val)
{
	if (unlikely(mm_tracking_struct.active))
		do_mm_track_pgd(val);
}
static __inline__ void mm_track_pml4(void * val)
{
	if (unlikely(mm_tracking_struct.active))
		do_mm_track_pml4(val);
}
static __inline__ void mm_track_phys(void * val)
{
	if (unlikely(mm_tracking_struct.active))
		do_mm_track_phys(val);
}
#endif /* CONFIG_MEM_MIRROR */

#endif /* __X86_64_MMTRACK_H__ */

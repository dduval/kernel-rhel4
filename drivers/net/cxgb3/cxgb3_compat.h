
#ifndef __CXGB3_COMPAT_H__
#define __CXGB3_COMPAT_H__

/**
 * cancel_rearming_delayed_workqueue - reliably kill off a delayed
 *                      work whose handler rearms the delayed work.
 * @wq:   the controlling workqueue structure
 * @work: the delayed work struct
 */
static inline
void cancel_rearming_delayed_workqueue(struct workqueue_struct *wq,
                                       struct work_struct *work)
{
	while (!cancel_delayed_work(work))
		flush_workqueue(wq);
}

#include <linux/rtnetlink.h>
static inline int rtnl_trylock(void)
{
	/* need to invert value since down_trylock() returns zero
	   if we can acquire the lock */
	return !rtnl_shlock_nowait();
}


#define IRQF_SHARED		SA_SHIRQ

#define ADVERTISED_Pause		(1 << 13)
#define ADVERTISED_Asym_Pause		(1 << 14)

#define PCI_EXP_LNKCAP		12	/* Link Capabilities */
#define PCI_EXP_LNKCTL		16	/* Link Control */
#define PCI_EXP_LNKSTA		18	/* Link Status */

#endif 

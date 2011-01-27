#ifndef _LINUX_NETDEVICE_BACKPORT_TO_2_6_16
#define _LINUX_NETDEVICE_BACKPORT_TO_2_6_16

#include_next <linux/netdevice.h>

static inline void netif_tx_lock(struct net_device *dev)
{
	spin_lock(&dev->xmit_lock);
	dev->xmit_lock_owner = smp_processor_id();
}

static inline void netif_tx_unlock(struct net_device *dev)
{
	dev->xmit_lock_owner = -1;
	spin_unlock(&dev->xmit_lock);
}

#endif

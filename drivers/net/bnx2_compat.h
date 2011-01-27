#ifndef __BNX2_COMPAT_H__
#define __BNX2_COMPAT_H__

#include <linux/types.h>

#define skb_header_cloned(skb) 0

static inline int skb_is_tso(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->tso_size;
}

static inline void netif_tx_lock(struct net_device *dev)
{
        spin_lock(&dev->xmit_lock);
}

static inline void netif_tx_unlock(struct net_device *dev)
{
        spin_unlock(&dev->xmit_lock);
}

typedef u32 pm_message_t;

typedef int __bitwise pci_power_t;

#define PCI_D0	((pci_power_t __force) 0)
#define PCI_D1	((pci_power_t __force) 1)
#define PCI_D2	((pci_power_t __force) 2)
#define PCI_D3hot	((pci_power_t __force) 3)
#define PCI_D3cold	((pci_power_t __force) 4)

#define pci_choose_state(pdev, state)	(state)

#define IRQF_SHARED	SA_SHIRQ
#define DMA_40BIT_MASK	0x000000ffffffffffULL

#endif /* __BNX2_COMPAT_H__ */

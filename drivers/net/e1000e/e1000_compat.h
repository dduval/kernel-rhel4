#ifndef __E1000E_COMPAT_H__
#define __E1000E_COMPAT_H__

#include <linux/if_vlan.h>
#include <linux/etherdevice.h>

typedef u32 pm_message_t;
typedef unsigned int bool;
#define true	1
#define false	0

typedef int __bitwise pci_power_t;

#define IRQF_SHARED		SA_SHIRQ
#define IRQF_PROBE_SHARED	0

#define ETH_FCS_LEN		4

#define PMSG_SUSPEND		3

#define PCI_D0  ((pci_power_t __force) 0)
#define PCI_D1  ((pci_power_t __force) 1)
#define PCI_D2  ((pci_power_t __force) 2)
#define PCI_D3hot       ((pci_power_t __force) 3)
#define PCI_D3cold      ((pci_power_t __force) 4)

#define pci_choose_state(pdev, state)   (state)
#define skb_header_cloned(skb) 0
#define round_jiffies(jiffies)	jiffies

#define PCI_EXP_LNKCTL                  16      /* Link Control */
#define PCI_EXP_LNKCTL_CLKREQ_EN        0x100   /* Enable clkreq */

#define PCI_EXP_LNKCAP          12      /* Link Capabilities */
#define PCI_EXP_LNKSTA          18      /* Link Status */


static inline struct net_device *vlan_group_get_device(struct vlan_group *vg,
						       int vlan_id)
{
	return vg->vlan_devices[vlan_id];
}

static inline void vlan_group_set_device(struct vlan_group *vg, int vlan_id,
					 struct net_device *dev)
{
	vg->vlan_devices[vlan_id] = NULL;
}


static inline struct sk_buff *netdev_alloc_skb(struct net_device *dev,
		unsigned int length)
{
	struct sk_buff *skb = dev_alloc_skb(length);
	
	if (likely(skb)) 
		skb->dev = dev;
	return skb;
}

#endif 

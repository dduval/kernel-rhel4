#ifndef __R8169_COMPAT_H__
#define __R8169_COMPAT_H__

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/workqueue.h>

#ifndef uninitialized_var
#define uninitialized_var(x) x = x
#endif

#define PCI_D0	((pci_power_t __force) 0)
#define PCI_D1	((pci_power_t __force) 1)
#define PCI_D2	((pci_power_t __force) 2)
#define PCI_D3hot	((pci_power_t __force) 3)
#define PCI_D3cold	((pci_power_t __force) 4)

#define pci_choose_state(pdev, state)	(state)

#define ADVERTISED_Pause	(1 << 13)
#define ADVERTISED_Asym_Pause	(1 << 14)

#define PCI_VENDOR_ID_AT	0x1259

#define CHECKSUM_PARTIAL	CHECKSUM_HW

#define IRQF_SHARED		SA_SHIRQ

#define PCI_EXP_LNKCTL			16	/* Link Control */
#define PCI_EXP_LNKCTL_CLKREQ_EN	0x100	/* Enable clkreq */

#define synchronize_sched	synchronize_kernel

typedef u32 pm_message_t;

typedef int __bitwise pci_power_t;

typedef _Bool bool;

enum {
	false = 0,
	true = 1
};

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
        return skb->nh.raw;
}

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_network_header(skb);
}

static inline void skb_copy_from_linear_data(const struct sk_buff *skb,
					     void *to,
					     const unsigned int len)
{
	memcpy(to, skb->data, len);
}

static inline __be16 backport_eth_type_trans(struct sk_buff *skb,
					     struct net_device *dev)
{
	skb->dev = dev;
	return eth_type_trans(skb, dev);
}

#define eth_type_trans backport_eth_type_trans

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

typedef void (*work_func_t)(struct work_struct *work);

struct delayed_work {
	struct work_struct work;
};

static inline void backport_INIT_WORK(struct work_struct *work, void *func)
{
	INIT_WORK(work, func, work);
}

static inline void backport_PREPARE_WORK(struct work_struct *work, void *func)
{
	PREPARE_WORK(work, func, work);
}

static inline int backport_schedule_delayed_work(struct delayed_work *work,
						 unsigned long delay)
{
	if (likely(!delay))
		return schedule_work(&work->work);
	else
		return schedule_delayed_work(&work->work, delay);
}


#undef INIT_WORK
#define INIT_WORK(_work, _func) backport_INIT_WORK(_work, _func)
#define INIT_DELAYED_WORK(_work,_func) INIT_WORK(&(_work)->work, _func)

#undef PREPARE_WORK
#define PREPARE_WORK(_work, _func) backport_PREPARE_WORK(_work, _func)
#define PREPARE_DELAYED_WORK(_work, _func) PREPARE_WORK(&(_work)->work, _func)

#define schedule_delayed_work backport_schedule_delayed_work

#define ETH_FCS_LEN 4

#endif /* __R8169_COMPAT_H__ */


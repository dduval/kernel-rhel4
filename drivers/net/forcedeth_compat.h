#ifndef __FORCEDETH_COMPAT_H__
#define __FORCEDETH_COMPAT_H__

#define CHECKSUM_PARTIAL CHECKSUM_HW

#define round_jiffies(j) (j)

typedef u32 pm_message_t;
typedef int __bitwise pci_power_t;

#define PCI_D0 ((pci_power_t __force) 0)
#define pci_choose_state(pdev, state) (state)

#define DMA_39BIT_MASK 0x0000007fffffffffULL

typedef _Bool bool;

enum {
	false = 0,
	true = 1
};

#define device_init_wakeup(dev, val)

#define netif_tx_lock_bh(dev) spin_lock_bh(&(dev)->xmit_lock)
#define netif_tx_unlock_bh(dev) spin_unlock_bh(&(dev)->xmit_lock)

#define netif_addr_lock(dev)
#define netif_addr_unlock(dev)

#endif /* __FORCEDETH_COMPAT_H__ */


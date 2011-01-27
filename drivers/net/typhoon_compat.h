#ifndef __TYPHOON_COMPAT_H__
#define __TYPHOON_COMPAT_H__

#include <linux/types.h>

#define skb_header_cloned(skb) 0

typedef u32 pm_message_t;

typedef int __bitwise pci_power_t;

#define PCI_D0	((pci_power_t __force) 0)
#define PCI_D1	((pci_power_t __force) 1)
#define PCI_D2	((pci_power_t __force) 2)
#define PCI_D3hot	((pci_power_t __force) 3)
#define PCI_D3cold	((pci_power_t __force) 4)

#define pci_choose_state(pdev, state)	(state)

#endif /* __TYPHOON_COMPAT_H__ */

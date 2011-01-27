#ifndef __E1000_COMPAT_H__
#define __E1000_COMPAT_H__

#define PMSG_SUSPEND 3

#define IRQF_PROBE_SHARED	0
#define IRQF_SHARED		SA_SHIRQ
#define IRQF_SAMPLE_RANDOM	SA_SAMPLE_RANDOM

#define skb_header_cloned(skb) 0

typedef u32 pm_message_t;

typedef int __bitwise pci_power_t;

#define PCI_D0	((pci_power_t __force) 0)
#define PCI_D1	((pci_power_t __force) 1)
#define PCI_D2	((pci_power_t __force) 2)
#define PCI_D3hot	((pci_power_t __force) 3)
#define PCI_D3cold	((pci_power_t __force) 4)

#define pci_choose_state(pdev, state)	(state)

typedef _Bool bool;

enum {
	false = 0,
	true = 1
};

#endif /* __E1000_COMPAT_H__ */

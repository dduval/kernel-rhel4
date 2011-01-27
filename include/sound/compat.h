#ifdef CONFIG_PCI
#include <linux/pci.h>
#define PCI_D0		0
#define PCI_D3hot	3
#define pci_intx(pci,x) do { } while (0)
#define pci_choose_state(pci,state) ((state) ? PCI_D3hot : PCI_D0)
#endif

#define IRQF_SHARED SA_SHIRQ

#define module_param_array1(name, type, nump, perm) \
	static unsigned int boot_devs_##name;  \
	module_param_array_named(name, name, type, boot_devs_##name, perm)

#include <linux/pm.h>
#ifndef PMSG_FREEZE
typedef u32 __bitwise pm_message_t;
#define PMSG_FREEZE     3
#define PMSG_SUSPEND    3
#define PMSG_ON         0
#endif

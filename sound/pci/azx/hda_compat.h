#ifndef __HDA_COMPAT_H__
#define __HDA_COMPAT_H__

#include <linux/pci.h>

typedef unsigned int pm_message_t;

#define SNDRV_DEV_BUS	SNDRV_DEV_LOWLEVEL

static inline void
pci_intx(struct pci_dev *pdev, int enable)
{
        u16 pci_command, new;

        pci_read_config_word(pdev, PCI_COMMAND, &pci_command);

        if (enable) {
                new = pci_command & ~PCI_COMMAND_INTX_DISABLE;
        } else {
                new = pci_command | PCI_COMMAND_INTX_DISABLE;
        }

        if (new != pci_command) {
                pci_write_config_word(pdev, PCI_COMMAND, new);
        }
}

#endif /* __HDA_COMPAT_H__ */

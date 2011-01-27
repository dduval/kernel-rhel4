#ifndef LINUX_PCI_BACKPORT_TO_2_6_9_H
#define LINUX_PCI_BACKPORT_TO_2_6_9_H

#include_next <linux/pci.h>

#define PCI_EXP_LNKCTL          16      /* Link Control */
#define PCI_EXP_LNKSTA          18      /* Link Status */
#define  PCI_CAP_ID_HT          0x08    /* HyperTransport */

#endif

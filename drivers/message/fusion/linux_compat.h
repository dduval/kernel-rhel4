/* drivers/message/fusion/linux_compat.h */

#ifndef FUSION_LINUX_COMPAT_H
#define FUSION_LINUX_COMPAT_H

#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/sched.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>

/* define pm_message_t which came in lk 2.6.11
 * to be backward compatible to older variants of lk 2.6
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
typedef u32 pm_message_t;
#endif

/* exporting of pci_disable_msi which came in lk 2.6.8
 * to be backward compatible to older variants of lk 2.6
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8))
static inline void pci_disable_msi(struct pci_dev* dev) {}
#endif

/* defines for SAS controlers, to be eventually added to inlcude/linux/pci_ids.h
 */
#ifndef PCI_DEVICE_ID_LSI_SAS1064
#define PCI_DEVICE_ID_LSI_SAS1064	(0x0050)
#endif

#ifndef PCI_DEVICE_ID_LSI_SAS1066
#define PCI_DEVICE_ID_LSI_SAS1066	(0x005E)
#endif

#ifndef PCI_DEVICE_ID_LSI_SAS1068
#define PCI_DEVICE_ID_LSI_SAS1068	(0x0054)
#endif

#ifndef PCI_DEVICE_ID_LSI_SAS1064A
#define PCI_DEVICE_ID_LSI_SAS1064A	(0x005C)
#endif

#ifndef PCI_DEVICE_ID_LSI_SAS1064E
#define PCI_DEVICE_ID_LSI_SAS1064E	(0x0056)
#endif

#ifndef PCI_DEVICE_ID_LSI_SAS1066E
#define PCI_DEVICE_ID_LSI_SAS1066E	(0x005A)
#endif

#ifndef PCI_DEVICE_ID_LSI_SAS1068E
#define PCI_DEVICE_ID_LSI_SAS1068E	(0x0058)
#endif

#ifndef PCI_DEVICE_ID_LSI_FC939X
#define PCI_DEVICE_ID_LSI_FC939X	(0x0642)
#endif

#ifndef PCI_DEVICE_ID_LSI_FC949X
#define PCI_DEVICE_ID_LSI_FC949X	(0x0640)
#endif

#ifndef PCI_DEVICE_ID_LSI_FC949ES
#define PCI_DEVICE_ID_LSI_FC949ES	(0x0646)
#endif
/*}-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
#endif /* _LINUX_COMPAT_H */

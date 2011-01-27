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

/*}-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
#endif /* _LINUX_COMPAT_H */

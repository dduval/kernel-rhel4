/* drivers/message/fusion/linux_compat.h */

#ifndef FUSION_LINUX_COMPAT_H
#define FUSION_LINUX_COMPAT_H

#include <linux/version.h>
#include <linux/sched.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>

/* scsi_print_command() came in lk 2.6.8 kernel,
 * prior kernels it was called print_Scsi_Cmnd()
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8))
extern void print_Scsi_Cmnd(struct scsi_cmnd *cmd);
#else
extern void scsi_print_command(struct scsi_cmnd *cmd);
#endif
static void inline mptscsih_scsi_print_command(struct scsi_cmnd *cmd){
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8))
	print_Scsi_Cmnd(cmd);
#else
	scsi_print_command(cmd);
#endif
}

/* define scsi_device_online which came in lk 2.6.6,
 * to be backward compatible to older variants of lk 2.6
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,6))
static int inline scsi_device_online(struct scsi_device *sdev)
{
	return sdev->online;
}
#endif

/* define msleep, msleep_interruptible which came in lk 2.6.8
 * to be backward compatible to older variants of lk 2.6
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8))
#ifndef msecs_to_jiffies
static inline unsigned long msecs_to_jiffies(const unsigned int m)
{
#if HZ <= 1000 && !(1000 % HZ)
        return (m + (1000 / HZ) - 1) / (1000 / HZ);
#elif HZ > 1000 && !(HZ % 1000)
        return m * (HZ / 1000);
#else
        return (m * HZ + 999) / 1000;
#endif
}
#endif
static void inline msleep(unsigned long msecs)
{
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(msecs_to_jiffies(msecs) + 1);
}
static void inline msleep_interruptible(unsigned long msecs)
{
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(msecs_to_jiffies(msecs) + 1);
}
#endif

/* define __iomem which came in lk 2.6.9
 * to be backward compatible to older variants of lk 2.6
 */
#ifndef __iomem
#define __iomem
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

/*}-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
#endif /* _LINUX_COMPAT_H */
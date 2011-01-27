/*
 *  linux/drivers/message/fusion/mptsas.c
 *      For use with LSI Logic PCI chip/adapter(s)
 *      running LSI Logic Fusion MPT (Message Passing Technology) firmware.
 *
 *  Copyright (c) 1999-2005 LSI Logic Corporation
 *  (mailto:mpt_linux_developer@lsil.com)
 *
 */
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; version 2 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    NO WARRANTY
    THE PROGRAM IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED INCLUDING, WITHOUT
    LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT,
    MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is
    solely responsible for determining the appropriateness of using and
    distributing the Program and assumes all risks associated with its
    exercise of rights under this Agreement, including but not limited to
    the risks and costs of program errors, damage to or loss of data,
    programs or equipment, and unavailability or interruption of operations.

    DISCLAIMER OF LIABILITY
    NEITHER RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY FOR ANY
    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
    TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE OF ANY RIGHTS GRANTED
    HEREUNDER, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/kdev_t.h>
#include <linux/blkdev.h>
#include <linux/delay.h>	/* for mdelay */
#include <linux/interrupt.h>	/* needed for in_interrupt() proto */
#include <linux/reboot.h>	/* notifier code */
#include <linux/sched.h>
#include <linux/workqueue.h>

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>

#include "mptbase.h"
#include "mptscsih.h"

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
#define my_NAME		"Fusion MPT SAS Host driver"
#define my_VERSION	MPT_LINUX_VERSION_COMMON
#define MYNAM		"mptsas"

MODULE_AUTHOR(MODULEAUTHOR);
MODULE_DESCRIPTION(my_NAME);
MODULE_LICENSE("GPL");

/* Command line args */
static int mpt_pq_filter = 0;
module_param(mpt_pq_filter, int, 0);
MODULE_PARM_DESC(mpt_pq_filter, " Enable peripheral qualifier filter: enable=1  (default=0)");

static int mpt_pt_clear = 0;
module_param(mpt_pt_clear, int, 0);
MODULE_PARM_DESC(mpt_pt_clear, " Clear persistency table: enable=1  (default=MPTSCSIH_PT_CLEAR=0)");

static int mpt_sas_hot_plug_enable = 1;
module_param(mpt_sas_hot_plug_enable, int, 0);
MODULE_PARM_DESC(mpt_sas_hot_plug_enable, " Enable SAS Hot Plug Support: enable=1 (default=1)");

extern int	mptscsih_TMHandler(MPT_SCSI_HOST *hd, u8 type, u8 channel, u8 target, u8 lun, int ctx2abort, ulong timeout);
static int	mptsasDoneCtx = -1;
static int	mptsasTaskCtx = -1;
static int	mptsasInternalCtx = -1; /* Used only for internal commands */


enum mptsas_hotplug_action {
	MPTSAS_ADD_DEVICE,
	MPTSAS_DEL_DEVICE,
};

struct mptsas_hotplug_event {
	struct work_struct	work;
	MPT_ADAPTER		*ioc;
	enum mptsas_hotplug_action event_type;
	u64			sas_address;
	u32			channel;
	u32			id;
	u32			device_info;
	u16			handle;
	u16			parent_handle;
	u8			phy_id;
	u8			isRaid;
};

static int
mptsas_qcmd(struct scsi_cmnd *SCpnt, void (*done)(struct scsi_cmnd *))
{
	MPT_SCSI_HOST *hd = (MPT_SCSI_HOST *) SCpnt->device->host->hostdata;
	int	 id = SCpnt->device->id;

	/* Device has been removed, so inhibit any more IO */
	if (hd->Targets[id] &&
	    hd->Targets[id]->tflags & MPT_TARGET_FLAGS_DELETED) {
		SCpnt->result = DID_NO_CONNECT << 16;
		done(SCpnt);
		return 0;
	}

	return mptscsih_qcmd(SCpnt,done);
}

/* Show the ioc state for this card */
static ssize_t
mptsas_show_iocstate(struct class_device *class_dev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(class_dev);
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)host->hostdata;

	return snprintf(buf, 8, "%u\n", (hd->ioc->last_state >> MPI_IOC_STATE_SHIFT));
}

/* Create sysfs 'iocnum' entry */
static struct class_device_attribute mptsas_host_iocstate_attr = {
        .attr = {
                .name =         "iocstate",
                .mode =         S_IRUSR,
        },
        .show = mptsas_show_iocstate
};

/* Host attributes initializer */
static struct class_device_attribute *mptsas_host_attrs[] = {
        &mptsas_host_iocstate_attr,
        NULL,
};

static struct scsi_host_template mptsas_driver_template = {
	.module				= THIS_MODULE,
	.proc_name			= "mptsas",
	.proc_info			= mptscsih_proc_info,
	.name				= "MPT SAS Host",
	.info				= mptscsih_info,
	.queuecommand			= mptsas_qcmd,
	.slave_alloc			= mptscsih_slave_alloc,
	.slave_configure		= mptscsih_slave_configure,
	.slave_destroy			= mptscsih_slave_destroy,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11))
	.change_queue_depth 		= mptscsih_change_queue_depth,
#endif
	.eh_abort_handler		= mptscsih_abort,
	.eh_device_reset_handler	= mptscsih_dev_reset,
	.eh_bus_reset_handler		= mptscsih_bus_reset,
	.eh_host_reset_handler		= mptscsih_host_reset,
	.bios_param			= mptscsih_bios_param,
	.can_queue			= MPT_FC_CAN_QUEUE,
	.this_id			= -1,
	.sg_tablesize			= MPT_SCSI_SG_DEPTH,
	.max_sectors			= 8192,
	.cmd_per_lun			= 7,
	.use_clustering			= ENABLE_CLUSTERING,
	.shost_attrs			= mptsas_host_attrs,
	.dump_sanity_check		= mptscsih_sanity_check,
	.dump_poll			= mptscsih_poll,
};

static void __devexit mptsas_remove(struct pci_dev *pdev)
{
	flush_scheduled_work();
	mptscsih_remove(pdev);
}

static void
mptsas_target_reset(MPT_ADAPTER *ioc, VirtDevice * vdevice)
{
	MPT_SCSI_HOST		*hd = (MPT_SCSI_HOST *)ioc->sh->hostdata;

	if (mptscsih_TMHandler(hd,
	     MPI_SCSITASKMGMT_TASKTYPE_TARGET_RESET,
	     vdevice->bus_id, vdevice->target_id, 0, 0, 5) < 0) {
		hd->tmPending = 0;
		hd->tmState = TM_STATE_NONE;
		printk(MYIOC_s_WARN_FMT
	       "Error processing TaskMgmt id=%d TARGET_RESET\n",
			ioc->name, vdevice->target_id);
	}
}

/****************************************************************************
 * Supported hardware
 */

static struct pci_device_id mptsas_pci_table[] = {
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVID_SAS1064,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVID_SAS1068,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVID_SAS1064E,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVID_SAS1068E,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVID_SAS1078,
		PCI_ANY_ID, PCI_ANY_ID },
	{0}	/* Terminating entry */
};
MODULE_DEVICE_TABLE(pci, mptsas_pci_table);


static void
mptscsih_sas_persist_clear_table(void * arg)
{
	MPT_ADAPTER *ioc = (MPT_ADAPTER *)arg;

	mptbase_sas_persist_operation(ioc, MPI_SAS_OP_CLEAR_NOT_PRESENT);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* mptbase_sas_update_device_list -
 * This is called from the work queue.
 * Purpose is to called when a logical volume has been created, deleted,
 * or status change.
 * Since in SAS the phydisk can be moved to different location, we will need
 * to refresh the device list by recreating it.
 */
static void
mptscsih_sas_update_device_list(MPT_ADAPTER *ioc )
{
	sas_device_info_t *sasDevice, *pNext;

	/*
	 * Kill everything in the device list, then rediscover
	 */
	list_for_each_entry_safe(sasDevice, pNext, &ioc->sasDeviceList, list) {
		list_del(&sasDevice->list);
		kfree(sasDevice);
		ioc->alloc_total -= sizeof (sas_device_info_t);
	}

	if (ioc->sasPhyInfo != NULL) {
		kfree(ioc->sasPhyInfo);
		ioc->sasPhyInfo = NULL;
		ioc->alloc_total -=
		    ioc->numPhys * sizeof (sas_phy_info_t);
	}
	ioc->numPhys = 0;

	/*
	 *  Rescsan list
	 */
	mpt_sas_get_info(ioc);
}

static void
mptsas_hotplug_print(MPT_ADAPTER *ioc, struct mptsas_hotplug_event *hot_plug_info,  u32 lun, u8 * msg_string)
{
	char *ds = NULL;
	u32 	id = hot_plug_info->id;

	if ( id > ioc->pfacts->MaxDevices ) {
		printk(MYIOC_s_WARN_FMT "%s: Invalid id=%d, MaxDevices=%d\n",
		    ioc->name, __FUNCTION__, id, ioc->pfacts->MaxDevices);
		return;
	}

	if (hot_plug_info->isRaid) {
		printk(MYIOC_s_INFO_FMT
		    "%s device, channel %d, id %d, lun %d\n",
			ioc->name, msg_string,
			hot_plug_info->channel,
			id, lun);
	} else {
		if (hot_plug_info->device_info &
		    MPI_SAS_DEVICE_INFO_SSP_TARGET)
			ds = "sas";
		if (hot_plug_info->device_info &
		    MPI_SAS_DEVICE_INFO_STP_TARGET)
			ds = "stp";
		if (hot_plug_info->device_info &
		    MPI_SAS_DEVICE_INFO_SATA_DEVICE)
			ds = "sata";
		printk(MYIOC_s_INFO_FMT
		    "%s %s device, channel %d, id %d, lun %d,"
		    "  phy %d\n", ioc->name, msg_string, ds,
		    hot_plug_info->channel, id, lun,
		    hot_plug_info->phy_id);
	}
}

/*
 * mptsas_remove_target - try to remove a target and all its devices
 *
 * In newer kernels there is scsi_remove_target(), which does
 * the same.
 */
static void
mptsas_remove_target(MPT_ADAPTER *ioc, struct mptsas_hotplug_event *hot_plug_info)
{
	struct Scsi_Host *shost = ioc->sh;
	unsigned long flags;
	struct scsi_device *sdev;
	u32 channel, id;
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)ioc->sh->hostdata;

	id = hot_plug_info->id;

	if ( id > ioc->pfacts->MaxDevices ) {
		printk(MYIOC_s_WARN_FMT "%s: Invalid id=%d, MaxDevices=%d\n",
		    ioc->name, __FUNCTION__, id, ioc->pfacts->MaxDevices);
		return;
	}

	mptsas_target_reset(ioc, hd->Targets[id]);

	channel = hot_plug_info->channel;
	spin_lock_irqsave(shost->host_lock, flags);
 restart:
	list_for_each_entry(sdev, &shost->__devices, siblings) {
		if (sdev->channel != channel || sdev->id != id ||
		    sdev->sdev_state == SDEV_DEL)
			continue;
		spin_unlock_irqrestore(shost->host_lock, flags);
		mptsas_hotplug_print(ioc, hot_plug_info, sdev->lun, "removing");
		scsi_remove_device(sdev);
		spin_lock_irqsave(shost->host_lock, flags);
		goto restart;
	}
	spin_unlock_irqrestore(shost->host_lock, flags);
}

static void
mptsas_add_device(MPT_ADAPTER *ioc, struct mptsas_hotplug_event *hot_plug_info,
    u32 lun)
{
	u32 	channel, id;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
	struct scsi_device *sdev;
#else
        int 	error;
#endif

	id = hot_plug_info->id;

	if ( id > ioc->pfacts->MaxDevices ) {
		printk(MYIOC_s_WARN_FMT "%s: Invalid id=%d, MaxDevices=%d\n",
		    ioc->name, __FUNCTION__, id, ioc->pfacts->MaxDevices);
		return;
	}

	channel = hot_plug_info->channel;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
	sdev = scsi_add_device(ioc->sh, channel, id, lun);
	if (!IS_ERR(sdev))
		mptsas_hotplug_print(ioc, hot_plug_info, lun,
		    "attaching");
#else
	error = scsi_add_device(ioc->sh, channel, id, lun);
	if (!error) /* no error */
		mptsas_hotplug_print(ioc, hot_plug_info, lun,
		    "attaching");
#endif
}

static int scsilun_to_int(struct scsi_lun *scsilun)
{
	int i;
	unsigned int lun;

	lun = 0;
	for (i = 0; i < sizeof(lun); i += 2)
		lun = lun | (((scsilun->scsi_lun[i] << 8) |
			scsilun->scsi_lun[i + 1]) << (i * 8));
	return lun;
}

/*
 * mptsas_scan_target - scan a target id, possibly including all LUNs on the
 *     target.
 *
 * In newer kernels there is scsi_scan_target(), which does the same.
 *
 */
static void
mptsas_scan_target(MPT_ADAPTER *ioc, struct mptsas_hotplug_event *hot_plug_info)
{
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)ioc->sh->hostdata;
	INTERNAL_CMD	iocmd;
	struct scsi_lun *lunp, *lun_data;
	dma_addr_t	lun_data_dma;
	u32		lun_data_len;
	u32 		length, channel, id, lun, num_luns;
	u8 		*data;
	u32		retries;
	int 		completion_code;

	id = hot_plug_info->id;

	if ( id > ioc->pfacts->MaxDevices ) {
		printk(MYIOC_s_WARN_FMT "%s: Invalid id=%d, MaxDevices=%d\n",
		    ioc->name, __FUNCTION__, id, ioc->pfacts->MaxDevices);
		return;
	}

	channel = hot_plug_info->channel;
	lun = 0;

	/*
	 * Integrated RAID doesn't support luns greater than 0
	 */
	if (hot_plug_info->isRaid) {
		mptsas_add_device(ioc, hot_plug_info, lun);
		return;
	}

	lun_data_len = (MPT_LAST_LUN + 1) * sizeof(struct scsi_lun);
	lun_data = pci_alloc_consistent(ioc->pcidev, lun_data_len,
	    &lun_data_dma);
	if (!lun_data)
		goto out;

	iocmd.cmd = REPORT_LUNS;
	iocmd.data_dma = lun_data_dma;
	iocmd.data = (u8 *)lun_data;
	iocmd.size = lun_data_len;
	iocmd.bus = channel;
	iocmd.id = id;
	iocmd.lun = lun;
	iocmd.flags = 0;

	/*
	 * While loop for 3 sec retrying REPORT_LUNS, this is done
	 * because some devices return MPI_SCSI_STATUS_BUSY for several
	 * seconds.
	 */
//	for (retries = 0; retries < 3; retries++) {  /* EDM - TRY 10 */
	for (retries = 0; retries < 10; retries++) {
		memset(lun_data, 0, lun_data_len);
		completion_code = mptscsih_do_cmd(hd, &iocmd);
		if (!completion_code)
			break;
		msleep(1000);
	}

	/*
	 * Attaching lun=0
	 */
	mptsas_add_device(ioc, hot_plug_info, lun);

	/*
	 * Get the length from the first four bytes of lun_data.
	 */
	data = (u8 *)lun_data;
	length = ((data[0] << 24) | (data[1] << 16) |
	    (data[2] << 8) | (data[3] << 0));

	num_luns = (length / sizeof(struct scsi_lun));
	if (!num_luns)
		goto out;
	if (num_luns > MPT_LAST_LUN)
		num_luns = MPT_LAST_LUN;

	/*
	 * Scan the luns in lun_data. The entry at offset 0 is really
	 * the header, so start at 1 and go up to and including num_luns.
	 */
	for (lunp = &lun_data[1]; lunp <= &lun_data[num_luns]; lunp++) {
		lun = scsilun_to_int(lunp);
		/*
		 * Skiping lun=0, as it was completed above
		 */
		if (lun == 0)
			continue;
		mptsas_add_device(ioc, hot_plug_info, lun);
	}
 out:
	if (lun_data)
		pci_free_consistent(ioc->pcidev, lun_data_len, lun_data,
		    lun_data_dma);
}

static void
mptsas_hotplug_work(void *arg)
{
	struct mptsas_hotplug_event *hot_plug_info = arg;
	MPT_ADAPTER 		*ioc = hot_plug_info->ioc;
	MPT_SCSI_HOST		*hd = (MPT_SCSI_HOST *)ioc->sh->hostdata;
	VirtDevice		*pTarget;
	u32 			id = hot_plug_info->id;


	dhotpprintk((MYIOC_s_WARN_FMT "Entering %s for channel=%d id=%d\n",
		ioc->name,__FUNCTION__, 
		hot_plug_info->channel, id));


	if ( id > ioc->pfacts->MaxDevices ) {
		printk(MYIOC_s_WARN_FMT "%s: Invalid id=%d, MaxDevices=%d\n",
		    ioc->name, __FUNCTION__, id, ioc->pfacts->MaxDevices);
		return;
	}

	down(&ioc->hot_plug_semaphore);

	pTarget = hd->Targets[id];
	dhotpprintk((MYIOC_s_WARN_FMT "hot_plug_info=%p ioc=%p hd=%p pTarget=%p\n",
		    ioc->name, hot_plug_info, ioc, hd, pTarget));

	switch  (hot_plug_info->event_type) {
	case MPTSAS_DEL_DEVICE:
		dhotpprintk((MYIOC_s_WARN_FMT
		    "MPTSAS_DEL_DEVICE: channel=%d id=%d\n",
			ioc->name,
			hot_plug_info->channel,
			id));
		if (pTarget == NULL) {
			dhotpprintk((MYIOC_s_WARN_FMT
			    "hot_plug id=%d not found in Targets array",
				ioc->name,
				id));
			goto out;
		}
		pTarget->tflags &= ~MPT_TARGET_FLAGS_TLR_DONE;
		pTarget->tflags |= MPT_TARGET_FLAGS_DELETED;
		mptsas_remove_target(ioc, hot_plug_info);
		break;

	case MPTSAS_ADD_DEVICE:
		dhotpprintk((MYIOC_s_WARN_FMT
		    "MPTSAS_ADD_DEVICE: channel=%d id=%d\n",
			ioc->name,
			hot_plug_info->channel,
			id));
		if (pTarget) {
			dhotpprintk((MYIOC_s_WARN_FMT
			    "hot_plug id=%d already in Targets array",
				ioc->name,
				id));
			goto out;
		}
		mptsas_scan_target(ioc, hot_plug_info);
		break;
	default:
		dhotpprintk((MYIOC_s_WARN_FMT
		    "Unknown hot_plug event_type=%x: channel=%d id=%d\n",
			ioc->name,
			hot_plug_info->event_type,
			hot_plug_info->channel,
			id));
		break;
	}

	/* If there has been a change to raid, then we need to
	 * refresh the config raid data, and sas device link list
	 */
	if (hot_plug_info->isRaid) {
		mpt_findImVolumes(ioc);
		mptscsih_sas_update_device_list(ioc);
	}

 out:
	dhotpprintk((MYIOC_s_WARN_FMT "%s: kfree hot_plug_info=%p\n",
		    ioc->name,__FUNCTION__, hot_plug_info));
	kfree(hot_plug_info);
	up(&ioc->hot_plug_semaphore);
}


static void
mptsas_send_sas_event(MPT_ADAPTER *ioc,
		EVENT_DATA_SAS_DEVICE_STATUS_CHANGE *sas_event_data)
{
	struct mptsas_hotplug_event *ev;
	u32 device_info = le32_to_cpu(sas_event_data->DeviceInfo);
	u64 sas_address;

	if ((device_info &
	     (MPI_SAS_DEVICE_INFO_SSP_TARGET |
	      MPI_SAS_DEVICE_INFO_STP_TARGET |
	      MPI_SAS_DEVICE_INFO_SATA_DEVICE )) == 0)
		return;

	if (sas_event_data->ReasonCode ==
		    MPI_EVENT_SAS_DEV_STAT_RC_NO_PERSIST_ADDED) {
		INIT_WORK(&ioc->mptscsih_persistTask,
		    mptscsih_sas_persist_clear_table,
		    (void *)ioc);
		schedule_work(&ioc->mptscsih_persistTask);
		return;
	}

	switch (sas_event_data->ReasonCode) {
	case MPI_EVENT_SAS_DEV_STAT_RC_ADDED:
	case MPI_EVENT_SAS_DEV_STAT_RC_NOT_RESPONDING:
		ev = kmalloc(sizeof(*ev), GFP_ATOMIC);
		if (!ev) {
			printk(KERN_WARNING "mptsas: lost hotplug event\n");
			break;
		}

		memset(ev, 0, sizeof(*ev));
		INIT_WORK(&ev->work, mptsas_hotplug_work, ev);
		ev->ioc = ioc;
		ev->handle = le16_to_cpu(sas_event_data->DevHandle);
		ev->parent_handle =
		    le16_to_cpu(sas_event_data->ParentDevHandle);
		ev->channel = sas_event_data->Bus;
		ev->id = sas_event_data->TargetID;
		ev->phy_id = sas_event_data->PhyNum;
		memcpy(&sas_address, &sas_event_data->SASAddress,
		    sizeof(u64));
		ev->sas_address = le64_to_cpu(sas_address);
		ev->device_info = device_info;

		if (sas_event_data->ReasonCode &
		    MPI_EVENT_SAS_DEV_STAT_RC_ADDED)
			ev->event_type = MPTSAS_ADD_DEVICE;
		else
			ev->event_type = MPTSAS_DEL_DEVICE;
		schedule_work(&ev->work);
		break;
	case MPI_EVENT_SAS_DEV_STAT_RC_NO_PERSIST_ADDED:
	/*
	 * Persistent table is full.
	 */
		INIT_WORK(&ioc->mptscsih_persistTask,
		    mptscsih_sas_persist_clear_table,
		    (void *)ioc);
		schedule_work(&ioc->mptscsih_persistTask);
		break;
	case MPI_EVENT_SAS_DEV_STAT_RC_SMART_DATA:
	/* TODO */
	case MPI_EVENT_SAS_DEV_STAT_RC_INTERNAL_DEVICE_RESET:
	/* TODO */
	default:
		break;
	}
}

static void
mptsas_send_raid_event(MPT_ADAPTER *ioc,
		EVENT_DATA_RAID *raid_event_data)
{
	struct mptsas_hotplug_event *ev;
	RAID_VOL0_STATUS * volumeStatus;

	if (ioc->bus_type != SAS)
		return;

	ev = kmalloc(sizeof(*ev), GFP_ATOMIC);
	if (!ev) {
		printk(KERN_WARNING "mptsas: lost hotplug event\n");
		return;
	}

	memset(ev,0,sizeof(struct mptsas_hotplug_event));
	INIT_WORK(&ev->work, mptsas_hotplug_work, ev);
	ev->ioc = ioc;
	ev->id = raid_event_data->VolumeID;
	ev->isRaid=1;

	switch (raid_event_data->ReasonCode) {
	case MPI_EVENT_RAID_RC_PHYSDISK_DELETED:
		ev->event_type = MPTSAS_ADD_DEVICE;
		break;
	case MPI_EVENT_RAID_RC_PHYSDISK_CREATED:
		ev->event_type = MPTSAS_DEL_DEVICE;
		break;
	case MPI_EVENT_RAID_RC_VOLUME_DELETED:
		ev->event_type = MPTSAS_DEL_DEVICE;
		break;
	case MPI_EVENT_RAID_RC_VOLUME_CREATED:
		ev->event_type = MPTSAS_ADD_DEVICE;
		break;
	case MPI_EVENT_RAID_RC_VOLUME_STATUS_CHANGED:
		volumeStatus = (RAID_VOL0_STATUS *) &
		    raid_event_data->SettingsStatus;
		ev->event_type = (volumeStatus->State ==
		    MPI_RAIDVOL0_STATUS_STATE_FAILED) ?
		    MPTSAS_DEL_DEVICE : MPTSAS_ADD_DEVICE;
		break;
	default:
		break;
	}
	schedule_work(&ev->work);
}

static int
mptsas_event_process(MPT_ADAPTER *ioc, EventNotificationReply_t *reply)
{
	int rc=1;
	u8 event = le32_to_cpu(reply->Event) & 0xFF;

	dhotpprintk((MYIOC_s_WARN_FMT "Entering %s\n",
		    ioc->name,__FUNCTION__));

	if (!ioc->sh)
		goto out;

	switch (event) {
	case MPI_EVENT_SAS_DEVICE_STATUS_CHANGE:
		mptsas_send_sas_event(ioc,
			(EVENT_DATA_SAS_DEVICE_STATUS_CHANGE *)reply->Data);
		break;
	case MPI_EVENT_INTEGRATED_RAID:
		mptsas_send_raid_event(ioc,
			(EVENT_DATA_RAID *)reply->Data);
		break;
	case MPI_EVENT_PERSISTENT_TABLE_FULL:
		INIT_WORK(&ioc->mptscsih_persistTask,
		    mptscsih_sas_persist_clear_table,
		    (void *)ioc);
		schedule_work(&ioc->mptscsih_persistTask);
		break;
	default:
		rc = mptscsih_event_process(ioc, reply);
		break;
	}
 out:

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptsas_probe - Installs scsi devices per bus.
 *	@pdev: Pointer to pci_dev structure
 *
 *	Returns 0 for success, non-zero for failure.
 *
 */
static int
mptsas_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct Scsi_Host	*sh;
	MPT_SCSI_HOST		*hd;
	MPT_ADAPTER 		*ioc;
	unsigned long		 flags;
	int			 sz, ii;
	int			 numSGE = 0;
	int			 scale;
	int			 ioc_cap;
	u8			*mem;
	int			error=0;
	int			r;

	if ((r = mpt_attach(pdev,id)) != 0)
		return r;

	ioc = pci_get_drvdata(pdev);
	ioc->DoneCtx = mptsasDoneCtx;
	ioc->TaskCtx = mptsasTaskCtx;
	ioc->InternalCtx = mptsasInternalCtx;

	/*  Added sanity check on readiness of the MPT adapter.
	 */
	if (ioc->last_state != MPI_IOC_STATE_OPERATIONAL) {
		printk(MYIOC_s_WARN_FMT
		  "Skipping because it's not operational!\n",
		  ioc->name);
		error = -ENODEV;
		goto out_mptsas_probe;
	}

	if (!ioc->active) {
		printk(MYIOC_s_WARN_FMT "Skipping because it's disabled!\n",
		  ioc->name);
		error = -ENODEV;
		goto out_mptsas_probe;
	}

	/*  Sanity check - ensure at least 1 port is INITIATOR capable
	 */
	ioc_cap = 0;
	for (ii=0; ii < ioc->facts.NumberOfPorts; ii++) {
		if (ioc->pfacts[ii].ProtocolFlags &
		    MPI_PORTFACTS_PROTOCOL_INITIATOR)
			ioc_cap ++;
	}

	if (!ioc_cap) {
		printk(MYIOC_s_WARN_FMT
			"Skipping ioc=%p because SCSI Initiator mode is NOT enabled!\n",
			ioc->name, ioc);
		return 0;
	}

	sh = scsi_host_alloc(&mptsas_driver_template, sizeof(MPT_SCSI_HOST));

	if (!sh) {
		printk(MYIOC_s_WARN_FMT
			"Unable to register controller with SCSI subsystem\n",
			ioc->name);
		error = -1;
		goto out_mptsas_probe;
        }

	spin_lock_irqsave(&ioc->FreeQlock, flags);

	/* Attach the SCSI Host to the IOC structure
	 */
	ioc->sh = sh;

	sh->io_port = 0;
	sh->n_io_port = 0;
	sh->irq = 0;

	/* set 16 byte cdb's */
	sh->max_cmd_len = 16;

	if ( mpt_can_queue < ioc->req_depth )
		sh->can_queue = mpt_can_queue;
	else
		sh->can_queue = ioc->req_depth;
	dinitprintk((MYIOC_s_INFO_FMT
		"mpt_can_queue=%d req_depth=%d can_queue=%d\n",
		ioc->name, mpt_can_queue, ioc->req_depth,
		sh->can_queue));

	sh->max_id = ioc->pfacts->MaxDevices + 1;

	sh->max_lun = MPT_LAST_LUN + 1;
	sh->max_channel = 0;
	sh->this_id = ioc->pfacts[0].PortSCSIID;

	/* Required entry.
	 */
	sh->unique_id = ioc->id;

	/* Verify that we won't exceed the maximum
	 * number of chain buffers
	 * We can optimize:  ZZ = req_sz/sizeof(SGE)
	 * For 32bit SGE's:
	 *  numSGE = 1 + (ZZ-1)*(maxChain -1) + ZZ
	 *               + (req_sz - 64)/sizeof(SGE)
	 * A slightly different algorithm is required for
	 * 64bit SGEs.
	 */
	scale = ioc->req_sz/(sizeof(dma_addr_t) + sizeof(u32));
	if (sizeof(dma_addr_t) == sizeof(u64)) {
		numSGE = (scale - 1) *
		  (ioc->facts.MaxChainDepth-1) + scale +
		  (ioc->req_sz - 60) / (sizeof(dma_addr_t) +
		  sizeof(u32));
	} else {
		numSGE = 1 + (scale - 1) *
		  (ioc->facts.MaxChainDepth-1) + scale +
		  (ioc->req_sz - 64) / (sizeof(dma_addr_t) +
		  sizeof(u32));
	}

	if (numSGE < sh->sg_tablesize) {
		/* Reset this value */
		dprintk((MYIOC_s_INFO_FMT
		  "Resetting sg_tablesize to %d from %d\n",
		  ioc->name, numSGE, sh->sg_tablesize));
		sh->sg_tablesize = numSGE;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13))
	/* Set the pci device pointer in Scsi_Host structure.
	 */
	scsi_set_device(sh, &ioc->pcidev->dev);
#endif

	spin_unlock_irqrestore(&ioc->FreeQlock, flags);

	hd = (MPT_SCSI_HOST *) sh->hostdata;
	hd->ioc = ioc;

	/* SCSI needs scsi_cmnd lookup table!
	 * (with size equal to req_depth*PtrSz!)
	 */
	sz = ioc->req_depth * sizeof(void *);
	mem = kmalloc(sz, GFP_ATOMIC);
	if (mem == NULL) {
		error = -ENOMEM;
		goto out_mptsas_probe;
	}

	memset(mem, 0, sz);
	hd->ScsiLookup = (struct scsi_cmnd **) mem;

	dprintk((MYIOC_s_INFO_FMT "ScsiLookup @ %p, sz=%d\n",
		 ioc->name, hd->ScsiLookup, sz));

	/* Allocate memory for the device structures.
	 * A non-Null pointer at an offset
	 * indicates a device exists.
	 * max_id = 1 + maximum id (hosts.h)
	 */
	sz = sh->max_id * sizeof(void *);
	mem = kmalloc(sz, GFP_ATOMIC);
	if (mem == NULL) {
		error = -ENOMEM;
		goto out_mptsas_probe;
	}

	memset(mem, 0, sz);
	hd->Targets = (VirtDevice **) mem;

	dprintk((KERN_INFO
	  "  Targets @ %p, sz=%d\n", hd->Targets, sz));

	/* Clear the TM flags
	 */
	hd->tmPending = 0;
	hd->tmState = TM_STATE_NONE;
	hd->resetPending = 0;
	hd->abortSCpnt = NULL;

	/* Clear the pointer used to store
	 * single-threaded commands, i.e., those
	 * issued during a bus scan, dv and
	 * configuration pages.
	 */
	hd->cmdPtr = NULL;

	/* Initialize this SCSI Hosts' timers
	 * To use, set the timer expires field
	 * and add_timer
	 */
	init_timer(&hd->timer);
	hd->timer.data = (unsigned long) hd;
	hd->timer.function = mptscsih_timer_expired;

	init_MUTEX(&ioc->hot_plug_semaphore);

	hd->mpt_pq_filter = mpt_pq_filter;
	ioc->sas_data.ptClear = mpt_pt_clear;
	ioc->sas_data.mpt_sas_hot_plug_enable =
	    mpt_sas_hot_plug_enable;

	if(ioc->sas_data.ptClear==1) {
		mptbase_sas_persist_operation(
		    ioc, MPI_SAS_OP_CLEAR_ALL_PERSISTENT);
	}

	ddvprintk((MYIOC_s_INFO_FMT
		"mpt_pq_filter %x mpt_pq_filter %x\n",
		ioc->name,
		mpt_pq_filter,
		mpt_pq_filter));

	init_waitqueue_head(&hd->scandv_waitq);
	hd->scandv_wait_done = 0;
	hd->last_queue_full = 0;

	error = scsi_add_host (sh, &ioc->pcidev->dev);
	if(error) {
		dprintk((KERN_ERR MYNAM
		  "scsi_add_host failed\n"));
		goto out_mptsas_probe;
	}

	scsi_scan_host(sh);
	return 0;

out_mptsas_probe:

	mptscsih_remove(pdev);
	return error;
}

static struct pci_driver mptsas_driver = {
	.name		= "mptsas",
	.id_table	= mptsas_pci_table,
	.probe		= mptsas_probe,
	.remove		= __devexit_p(mptsas_remove),
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13))
	.driver         = {
		.shutdown = mptscsih_shutdown,
        },
#else
	.shutdown       = mptscsih_shutdown,
#endif
#ifdef CONFIG_PM
	.suspend	= mptscsih_suspend,
	.resume		= mptscsih_resume,
#endif
};

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptsas_init - Register MPT adapter(s) as SCSI host(s) with
 *	linux scsi mid-layer.
 *
 *	Returns 0 for success, non-zero for failure.
 */
static int __init
mptsas_init(void)
{

	show_mptmod_ver(my_NAME, my_VERSION);

	mptsasDoneCtx = mpt_register(mptscsih_io_done, MPTSAS_DRIVER);
	mptsasTaskCtx = mpt_register(mptscsih_taskmgmt_complete, MPTSAS_DRIVER);
	mptsasInternalCtx = mpt_register(mptscsih_scandv_complete, MPTSAS_DRIVER);

	if (mpt_event_register(mptsasDoneCtx, mptsas_event_process) == 0) {
		devtprintk((KERN_INFO MYNAM
		  ": Registered for sas IOC event notifications\n"));
	}

	if (mpt_reset_register(mptsasDoneCtx, mptscsih_ioc_reset) == 0) {
		dprintk((KERN_INFO MYNAM
		  ": Registered for IOC reset notifications\n"));
	}

	return pci_register_driver(&mptsas_driver);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptsas_exit - Unregisters MPT adapter(s)
 *
 */
static void __exit
mptsas_exit(void)
{
	pci_unregister_driver(&mptsas_driver);

	mpt_reset_deregister(mptsasDoneCtx);
	dprintk((KERN_INFO MYNAM
	  ": Deregistered for IOC reset notifications\n"));

	mpt_event_deregister(mptsasDoneCtx);
	dprintk((KERN_INFO MYNAM
	  ": Deregistered for IOC event notifications\n"));

	mpt_deregister(mptsasInternalCtx);
	mpt_deregister(mptsasTaskCtx);
	mpt_deregister(mptsasDoneCtx);
}

module_init(mptsas_init);
module_exit(mptsas_exit);

int mptsas_dummy_symbol;
EXPORT_SYMBOL(mptsas_dummy_symbol);

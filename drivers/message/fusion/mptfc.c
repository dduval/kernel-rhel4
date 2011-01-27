/*
 *  linux/drivers/message/fusion/mptfc.c
 *      For use with LSI PCI chip/adapter(s)
 *      running LSI Fusion MPT (Message Passing Technology) firmware.
 *
 *  Copyright (c) 1999-2007 LSI Corporation
 *  (mailto:DL-MPTFusionLinux@lsi.com)
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

#include <linux/config.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
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
#include <scsi/scsi_transport.h>
#include <scsi/scsi_transport_fc.h>

#include "mptbase.h"
#include "mptscsih.h"

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
#define my_NAME		"Fusion MPT FC Host driver"
#define my_VERSION	MPT_LINUX_VERSION_COMMON
#define MYNAM		"mptfc"

MODULE_AUTHOR(MODULEAUTHOR);
MODULE_DESCRIPTION(my_NAME);
MODULE_LICENSE("GPL");
MODULE_VERSION(my_VERSION);

/* Command line args */
static int mpt_pq_filter = 0;
module_param(mpt_pq_filter, int, 0);
MODULE_PARM_DESC(mpt_pq_filter, " Enable peripheral qualifier filter: enable=1  (default=0)");

static int mptfc_device_queue_depth = MPT_SCSI_CMD_PER_DEV_HIGH;
module_param(mptfc_device_queue_depth, int, 0);
MODULE_PARM_DESC(mptfc_device_queue_depth, " Max Device Queue Depth (default=" __MODULE_STRING(MPT_SCSI_CMD_PER_DEV_HIGH) ")");

static int	mptfcDoneCtx = -1;
static int	mptfcTaskCtx = -1;
static int	mptfcInternalCtx = -1; /* Used only for internal commands */

static int mptfc_slave_configure(struct scsi_device *sdev);

static struct device_attribute mptfc_queue_depth_attr = {
	.attr = {
		.name = 	"queue_depth",
		.mode =		S_IWUSR,
	},
	.store = mptscsih_store_queue_depth,
};

static struct device_attribute *mptfc_dev_attrs[] = {
	&mptfc_queue_depth_attr,
	NULL,
};

/* Show the ioc state for this card */
static ssize_t
mptfc_show_iocstate(struct class_device *class_dev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(class_dev);
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)host->hostdata;

	return snprintf(buf, 8, "%u\n", (hd->ioc->last_state >> MPI_IOC_STATE_SHIFT));
}

/* Create sysfs 'iocnum' entry */
static struct class_device_attribute mptfc_host_iocstate_attr = {
        .attr = {
                .name =         "iocstate",
                .mode =         S_IRUSR,
        },
        .show = mptfc_show_iocstate
};

/* Host attributes initializer */
static struct class_device_attribute *mptfc_host_attrs[] = {
        &mptfc_host_iocstate_attr,
        NULL,
};

static struct scsi_host_template mptfc_driver_template = {
	.module				= THIS_MODULE,
	.proc_name			= "mptfc",
	.proc_info			= mptscsih_proc_info,
	.name				= "MPT FC Host",
	.info				= mptscsih_info,
	.queuecommand			= mptscsih_qcmd,
	.slave_alloc			= mptscsih_slave_alloc,
	.slave_configure		= mptfc_slave_configure,
	.slave_destroy			= mptscsih_slave_destroy,
	.eh_abort_handler		= mptscsih_abort,
	.eh_device_reset_handler	= mptscsih_dev_reset,
	.eh_bus_reset_handler		= mptscsih_bus_reset,
	.eh_host_reset_handler		= mptscsih_host_reset,
	.bios_param			= mptscsih_bios_param,
	.can_queue			= MPT_FC_CAN_QUEUE,
	.this_id			= -1,
	.sg_tablesize			= CONFIG_FUSION_MAX_SGE,
	.max_sectors			= 8192,
	.cmd_per_lun			= 7,
	.use_clustering			= ENABLE_CLUSTERING,
	.shost_attrs			= mptfc_host_attrs,
	.sdev_attrs			= mptfc_dev_attrs,
	.dump_sanity_check		= mptscsih_sanity_check,
	.dump_poll			= mptscsih_poll,
};

/****************************************************************************
 * Supported hardware
 */

static struct pci_device_id mptfc_pci_table[] = {
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVICEID_FC909,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVICEID_FC919,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVICEID_FC929,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVICEID_FC919X,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVICEID_FC929X,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVICEID_FC939X,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVICEID_FC949X,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVICEID_FC949E,
		PCI_ANY_ID, PCI_ANY_ID },
	{ 0x1657, MPI_MANUFACTPAGE_DEVICEID_FC949E,
		PCI_ANY_ID, PCI_ANY_ID },
	{0}	/* Terminating entry */
};
MODULE_DEVICE_TABLE(pci, mptfc_pci_table);

/**
 * mptfc_slave_configure
 *
 *
 * @sdev
 *
 **/
static int
mptfc_slave_configure(struct scsi_device *sdev)
{
#ifdef MPT_DEBUG_INIT
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)sdev->host->hostdata;
	MPT_ADAPTER *ioc = hd->ioc;
	int		channel;
	int		id;

	channel = sdev->channel;
	id = sdev->id;

	dinitprintk((MYIOC_s_INFO_FMT
		"%s: id=%d channel=%d sdev->queue_depth=%d mptfc_device_queue_depth=%d\n",
		ioc->name, __FUNCTION__, id, channel, sdev->queue_depth,
		mptfc_device_queue_depth));
#endif

	return mptscsih_slave_configure(sdev, mptfc_device_queue_depth);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptfc_probe - Installs scsi devices per bus.
 *	@pdev: Pointer to pci_dev structure
 *
 *	Returns 0 for success, non-zero for failure.
 *
 */
static int
mptfc_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct Scsi_Host	*sh;
	MPT_SCSI_HOST		*hd;
	MPT_ADAPTER 		*ioc;
	unsigned long		 flags;
	int			 sz, ii;
	int			 ioc_cap;
	u8			*mem;
	int			error=0;
	int			r;

	if ((r = mpt_attach(pdev,id)) != 0)
		return r;

	ioc = pci_get_drvdata(pdev);
	ioc->DoneCtx = mptfcDoneCtx;
	ioc->TaskCtx = mptfcTaskCtx;
	ioc->InternalCtx = mptfcInternalCtx;

	/*  Added sanity check on readiness of the MPT adapter.
	 */
	if (ioc->last_state != MPI_IOC_STATE_OPERATIONAL) {
		printk(MYIOC_s_WARN_FMT
		  "Skipping because it's not operational!\n",
		  ioc->name);
		error = -ENODEV;
		goto out_mptfc_probe;
	}

	if (!ioc->active) {
		printk(MYIOC_s_WARN_FMT "Skipping because it's disabled!\n",
		  ioc->name);
		error = -ENODEV;
		goto out_mptfc_probe;
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

	sh = scsi_host_alloc(&mptfc_driver_template, sizeof(MPT_SCSI_HOST));

	if (!sh) {
		printk(MYIOC_s_WARN_FMT
			"Unable to register controller with SCSI subsystem\n",
			ioc->name);
		error = -1;
		goto out_mptfc_probe;
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

	sh->max_id = ioc->DevicesPerBus;

	sh->max_lun = MPT_LAST_LUN + 1;
	sh->max_channel = ioc->NumberOfBuses - 1;
	sh->this_id = ioc->pfacts[0].PortSCSIID;

	/* Required entry.
	 */
	sh->unique_id = ioc->id;
	sh->sg_tablesize = ioc->sg_tablesize;

	/* Set the pci device pointer in Scsi_Host structure.
	 */
	scsi_set_device(sh, &ioc->pcidev->dev);

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
		goto out_mptfc_probe;
	}

	memset(mem, 0, sz);
	ioc->ScsiLookup = (struct scsi_cmnd **) mem;

	dprintk((MYIOC_s_INFO_FMT "ScsiLookup @ %p, sz=%d\n",
		 ioc->name, ioc->ScsiLookup, sz));

	for (ii=0; ii < ioc->NumberOfBuses; ii++) {
		/* Allocate memory for the device structures.
		 * A non-Null pointer at an offset
		 * indicates a device exists.
		 */
		sz = ioc->DevicesPerBus * sizeof(void *);
		mem = kmalloc(sz, GFP_ATOMIC);
		if (mem == NULL) {
			error = -ENOMEM;
			goto out_mptfc_probe;
		}

		memset(mem, 0, sz);
		ioc->Target_List[ii] = (struct _MPT_DEVICE *) mem;

		dinitprintk((KERN_INFO
		  " For Bus=%d, Target_List=%p sz=%d\n", ii, mem, sz));
	}

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

	/* Initialize this IOC's timers
	 * To use, set the timer expires field
	 * and add_timer.  Used for internally
	 * generated commands.
	 */
	init_timer(&hd->InternalCmdTimer);
	hd->InternalCmdTimer.data = (unsigned long) hd;
	hd->InternalCmdTimer.function = mptscsih_InternalCmdTimer_expired;

	init_timer(&ioc->TMtimer);
	ioc->TMtimer.data = (unsigned long) ioc;
	ioc->TMtimer.function = mptscsih_TM_timeout;

	hd->mpt_pq_filter = mpt_pq_filter;

	ddvprintk((MYIOC_s_INFO_FMT
		"mpt_pq_filter %x\n",
		ioc->name,
		mpt_pq_filter));

	init_waitqueue_head(&hd->scandv_waitq);
	hd->scandv_wait_done = 0;
	hd->last_queue_full = 0;

	init_waitqueue_head(&hd->TM_waitq);
	hd->TM_wait_done = 0;

	error = scsi_add_host (sh, &ioc->pcidev->dev);
	if(error) {
		dprintk((KERN_ERR MYNAM
		  "scsi_add_host failed\n"));
		goto out_mptfc_probe;
	}

	scsi_scan_host(sh);
	return 0;

out_mptfc_probe:

	mptscsih_remove(pdev);
	return error;
}

static struct pci_driver mptfc_driver = {
	.name		= "mptfc",
	.id_table	= mptfc_pci_table,
	.probe		= mptfc_probe,
	.remove		= __devexit_p(mptscsih_remove),
	.driver         = {
		.shutdown = mptscsih_shutdown,
        },
#ifdef CONFIG_PM
	.suspend	= mptscsih_suspend,
	.resume		= mptscsih_resume,
#endif
};

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
int
mptfc_event_process(MPT_ADAPTER *ioc, EventNotificationReply_t *pEvReply)
{
	MPT_SCSI_HOST *hd;
	u8 event = le32_to_cpu(pEvReply->Event) & 0xFF;

//	devtprintk((MYIOC_s_INFO_FMT "MPT event (=%02Xh) routed to FC host driver!\n",
//			ioc->name, event));

	if (ioc->sh == NULL ||
		((hd = (MPT_SCSI_HOST *)ioc->sh->hostdata) == NULL))
		return 1;

	switch (event) {
	case MPI_EVENT_UNIT_ATTENTION:			/* 03 */
		/* FIXME! */
		break;
	case MPI_EVENT_IOC_BUS_RESET:			/* 04 */
	case MPI_EVENT_EXT_BUS_RESET:			/* 05 */
		if (hd && (ioc->bus_type == SPI) && (hd->soft_resets < -1))
			hd->soft_resets++;
		break;
	case MPI_EVENT_LOGOUT:				/* 09 */
		/* FIXME! */
		break;

		/*
		 *  CHECKME! Don't think we need to do
		 *  anything for these, but...
		 */
	case MPI_EVENT_RESCAN:				/* 06 */
	case MPI_EVENT_LINK_STATUS_CHANGE:		/* 07 */
	case MPI_EVENT_LOOP_STATE_CHANGE:		/* 08 */
		/*
		 *  CHECKME!  Falling thru...
		 */
		break;

	case MPI_EVENT_NONE:				/* 00 */
	case MPI_EVENT_LOG_DATA:			/* 01 */
	case MPI_EVENT_STATE_CHANGE:			/* 02 */
	case MPI_EVENT_EVENT_CHANGE:			/* 0A */
	case MPI_EVENT_INTEGRATED_RAID:			/* 0B */
	default:
		devtprintk((KERN_INFO "%s:  Ignoring event (=%02Xh)\n", 
			__FUNCTION__, event));
		break;
	}

	return 1;		/* currently means nothing really */
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptfc_init - Register MPT adapter(s) as SCSI host(s) with
 *	linux scsi mid-layer.
 *
 *	Returns 0 for success, non-zero for failure.
 */
static int __init
mptfc_init(void)
{

	show_mptmod_ver(my_NAME, my_VERSION);

	mptfcDoneCtx = mpt_register(mptscsih_io_done, MPTFC_DRIVER);
	mptfcTaskCtx = mpt_register(mptscsih_taskmgmt_complete, MPTFC_DRIVER);
	mptfcInternalCtx = mpt_register(mptscsih_scandv_complete, MPTFC_DRIVER);

	if (mpt_event_register(mptfcDoneCtx, mptfc_event_process) == 0) {
		devtprintk((KERN_INFO MYNAM
		  ": mptfc_event_process Registered for IOC event notifications\n"));
	}

	if (mpt_reset_register(mptfcDoneCtx, mptscsih_ioc_reset) == 0) {
		dprintk((KERN_INFO MYNAM
		  ": Registered for IOC reset notifications\n"));
	}

	return pci_register_driver(&mptfc_driver);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptfc_exit - Unregisters MPT adapter(s)
 *
 */
static void __exit
mptfc_exit(void)
{
	pci_unregister_driver(&mptfc_driver);

	mpt_reset_deregister(mptfcDoneCtx);
	dprintk((KERN_INFO MYNAM
	  ": Deregistered for IOC reset notifications\n"));

	mpt_event_deregister(mptfcDoneCtx);
	dprintk((KERN_INFO MYNAM
	  ": Deregistered for IOC event notifications\n"));

	mpt_deregister(mptfcInternalCtx);
	mpt_deregister(mptfcTaskCtx);
	mpt_deregister(mptfcDoneCtx);
}

module_init(mptfc_init);
module_exit(mptfc_exit);

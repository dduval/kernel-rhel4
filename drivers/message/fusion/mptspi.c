/*
 *  linux/drivers/message/fusion/mptspi.c
 *      For use with LSI PCI chip/adapter(s)
 *      running LSI Fusion MPT (Message Passing Technology) firmware.
 *
 *  Copyright (c) 1999-2008 LSI Corporation
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

#include "mptbase.h"
#include "mptscsih.h"

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
#define my_NAME		"Fusion MPT SPI Host driver"
#define my_VERSION	MPT_LINUX_VERSION_COMMON
#define MYNAM		"mptspi"

MODULE_AUTHOR(MODULEAUTHOR);
MODULE_DESCRIPTION(my_NAME);
MODULE_LICENSE("GPL");
MODULE_VERSION(my_VERSION);

/* Command line args */
#ifdef MPTSCSIH_ENABLE_DOMAIN_VALIDATION
static int mpt_dv = MPTSCSIH_DOMAIN_VALIDATION;
module_param(mpt_dv, int, 0);
MODULE_PARM_DESC(mpt_dv, " DV Algorithm: enhanced=1, basic=0 (default=MPTSCSIH_DOMAIN_VALIDATION=1)");

static int mpt_width = MPTSCSIH_MAX_WIDTH;
module_param(mpt_width, int, 0);
MODULE_PARM_DESC(mpt_width, " Max Bus Width: wide=1, narrow=0 (default=MPTSCSIH_MAX_WIDTH=1)");

static ushort mpt_factor = MPTSCSIH_MIN_SYNC;
module_param(mpt_factor, ushort, 0);
MODULE_PARM_DESC(mpt_factor, " Min Sync Factor (default=MPTSCSIH_MIN_SYNC=0x08)");

static int mpt_qas_disable = 0;
module_param(mpt_qas_disable, int, 0);
MODULE_PARM_DESC(mpt_qas_disable, " Disable QAS Support (default=0)");

#endif

static int mpt_saf_te = MPTSCSIH_SAF_TE;
module_param(mpt_saf_te, int, 0);
MODULE_PARM_DESC(mpt_saf_te, " Force enabling SEP Processor: enable=1  (default=MPTSCSIH_SAF_TE=0)");

static int mpt_pq_filter = 0;
module_param(mpt_pq_filter, int, 0);
MODULE_PARM_DESC(mpt_pq_filter, " Enable peripheral qualifier filter: enable=1  (default=0)");

static int mptspi_device_queue_depth = MPT_SCSI_CMD_PER_DEV_HIGH;
module_param(mptspi_device_queue_depth, int, 0);
MODULE_PARM_DESC(mptspi_device_queue_depth, " Max Device Queue Depth (default=" __MODULE_STRING(MPT_SCSI_CMD_PER_DEV_HIGH) ")");

static int mptspi_slave_configure(struct scsi_device *sdev);

static int	mptspiDoneCtx = -1;
static int	mptspiTaskCtx = -1;
static int	mptspiInternalCtx = -1; /* Used only for internal commands */
static int	mptspiDVCtx = -1; /* Used only for DV commands */

static struct device_attribute mptspi_queue_depth_attr = {
	.attr = {
		.name = 	"queue_depth",
		.mode =		S_IWUSR,
	},
	.store = mptscsih_store_queue_depth,
};

static struct device_attribute *mptspi_dev_attrs[] = {
	&mptspi_queue_depth_attr,
	NULL,
};

/* Show the ioc state for this card */
static ssize_t
mptspi_show_iocstate(struct class_device *class_dev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(class_dev);
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)host->hostdata;

	return snprintf(buf, 8, "%u\n", (hd->ioc->last_state >> MPI_IOC_STATE_SHIFT));
}

/* Create sysfs 'iocnum' entry */
static struct class_device_attribute mptspi_host_iocstate_attr = {
        .attr = {
                .name =         "iocstate",
                .mode =         S_IRUSR,
        },
        .show = mptspi_show_iocstate
};

/* Host attributes initializer */
static struct class_device_attribute *mptspi_host_attrs[] = {
        &mptspi_host_iocstate_attr,
        NULL,
};

static struct scsi_host_template mptspi_driver_template = {
	.module				= THIS_MODULE,
	.proc_name			= "mptspi",
	.proc_info			= mptscsih_proc_info,
	.name				= "MPT SPI Host",
	.info				= mptscsih_info,
	.queuecommand			= mptscsih_qcmd,
	.slave_alloc			= mptscsih_slave_alloc,
	.slave_configure		= mptspi_slave_configure,
	.slave_destroy			= mptscsih_slave_destroy,
	.eh_abort_handler		= mptscsih_abort,
	.eh_device_reset_handler	= mptscsih_dev_reset,
	.eh_bus_reset_handler		= mptscsih_bus_reset,
	.eh_host_reset_handler		= mptscsih_host_reset,
	.bios_param			= mptscsih_bios_param,
	.can_queue			= MPT_SCSI_CAN_QUEUE,
	.this_id			= -1,
	.sg_tablesize			= CONFIG_FUSION_MAX_SGE,
	.max_sectors			= 8192,
	.cmd_per_lun			= 7,
	.use_clustering			= ENABLE_CLUSTERING,
	.shost_attrs			= mptspi_host_attrs,
	.sdev_attrs			= mptspi_dev_attrs,
	.dump_sanity_check		= mptscsih_sanity_check,
	.dump_poll			= mptscsih_poll,
};

/****************************************************************************
 * Supported hardware
 */

static struct pci_device_id mptspi_pci_table[] = {
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVID_53C1030,
		PCI_ANY_ID, PCI_ANY_ID },
	{ PCI_VENDOR_ID_LSI_LOGIC, MPI_MANUFACTPAGE_DEVID_53C1035,
		PCI_ANY_ID, PCI_ANY_ID },
	{0}	/* Terminating entry */
};
MODULE_DEVICE_TABLE(pci, mptspi_pci_table);


/**
 * mptspi_slave_configure
 *
 *
 * @sdev
 *
 **/
static int
mptspi_slave_configure(struct scsi_device *sdev)
{
#ifdef MPT_DEBUG_INIT
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)sdev->host->hostdata;
	MPT_ADAPTER *ioc = hd->ioc;
	int		channel;
	int		id;

	channel = sdev->channel;
	id = sdev->id;

	dinitprintk((MYIOC_s_INFO_FMT
		"%s: id=%d channel=%d sdev->queue_depth=%d mptspi_device_queue_depth=%d\n",
		ioc->name, __FUNCTION__, id, channel, sdev->queue_depth,
		mptspi_device_queue_depth));
#endif

	return mptscsih_slave_configure(sdev, mptspi_device_queue_depth);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptspi_probe - Installs scsi devices per bus.
 *	@pdev: Pointer to pci_dev structure
 *
 *	Returns 0 for success, non-zero for failure.
 *
 */
static int
mptspi_probe(struct pci_dev *pdev, const struct pci_device_id *id)
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
	ioc->DoneCtx = mptspiDoneCtx;
	ioc->TaskCtx = mptspiTaskCtx;
	ioc->InternalCtx = mptspiInternalCtx;
	ioc->DVCtx = mptspiDVCtx;

	/*  Added sanity check on readiness of the MPT adapter.
	 */
	if (ioc->last_state != MPI_IOC_STATE_OPERATIONAL) {
		printk(MYIOC_s_WARN_FMT
		  "Skipping because it's not operational!\n",
		  ioc->name);
		error = -ENODEV;
		goto out_mptspi_probe;
	}

	if (!ioc->active) {
		printk(MYIOC_s_WARN_FMT "Skipping because it's disabled!\n",
		  ioc->name);
		error = -ENODEV;
		goto out_mptspi_probe;
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

	sh = scsi_host_alloc(&mptspi_driver_template, sizeof(MPT_SCSI_HOST));

	if (!sh) {
		printk(MYIOC_s_WARN_FMT
			"Unable to register controller with SCSI subsystem\n",
			ioc->name);
		error = -1;
		goto out_mptspi_probe;
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
	sh->max_channel = 0;
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
		goto out_mptspi_probe;
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
			goto out_mptspi_probe;
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
	init_waitqueue_head(&hd->InternalCmd_waitq);
	hd->InternalCmd_wait_done = 0;

	init_timer(&hd->DVCmdTimer);
	hd->DVCmdTimer.data = (unsigned long) hd;
	hd->DVCmdTimer.function = mptscsih_DVCmdTimer_expired;

	init_timer(&ioc->TMtimer);
	ioc->TMtimer.data = (unsigned long) ioc;
	ioc->TMtimer.function = mptscsih_TM_timeout;

	ioc->spi_data.Saf_Te = mpt_saf_te;
	hd->mpt_pq_filter = mpt_pq_filter;

#ifdef MPTSCSIH_ENABLE_DOMAIN_VALIDATION
	if (ioc->spi_data.maxBusWidth > mpt_width)
		ioc->spi_data.maxBusWidth = mpt_width;
	if (ioc->spi_data.minSyncFactor < mpt_factor)
		ioc->spi_data.minSyncFactor = mpt_factor;
	if (ioc->spi_data.minSyncFactor == MPT_ASYNC) {
		ioc->spi_data.maxSyncOffset = 0;
	}
	ioc->spi_data.mpt_dv = mpt_dv;

	ddvprintk((MYIOC_s_INFO_FMT
		"dv %x width %x factor %x saf_te %x mpt_pq_filter %x\n",
		ioc->name,
		mpt_dv,
		mpt_width,
		mpt_factor,
		mpt_saf_te,
		mpt_pq_filter));
#else
	ddvprintk((MYIOC_s_INFO_FMT
		"saf_te %x mpt_pq_filter %x\n",
		ioc->name,
		mpt_saf_te,
		mpt_pq_filter));
#endif

	ioc->spi_data.forceDv = 0;
	if (mpt_qas_disable)  /* Is command-line QAS Disable requested */
		ioc->spi_data.noQas |= MPT_TARGET_NO_NEGO_QAS;
	else
		ioc->spi_data.noQas = 0;

	/* enable domain validation flags */
	for (ii=0; ii < MPT_MAX_SCSI_DEVICES; ii++)
		ioc->spi_data.dvStatus[ii] =
		  (MPT_SCSICFG_NEGOTIATE | MPT_SCSICFG_DV_NOT_DONE);

	init_waitqueue_head(&hd->DVCmd_waitq);
	hd->DVCmd_wait_done = 0;
	hd->last_queue_full = 0;

	init_waitqueue_head(&hd->TM_waitq);
	hd->TM_wait_done = 0;

	error = scsi_add_host (sh, &ioc->pcidev->dev);
	if(error) {
		dprintk((KERN_ERR MYNAM
		  "scsi_add_host failed\n"));
		goto out_mptspi_probe;
	}

	/* issue internal bus reset */
	if (ioc->spi_data.bus_reset) {
		 mptscsih_TMHandler(hd,
		    MPI_SCSITASKMGMT_TASKTYPE_RESET_BUS,
		    0, 0, 0, 0, 5 /* 5 second timeout */);
	}

	dnegoprintk((MYIOC_s_WARN_FMT "%s: writeSDP1: ALL_IDS\n",
		ioc->name, __FUNCTION__));
	mpt_writeSDP1(ioc, 0, 0, MPT_SCSICFG_ALL_IDS);

	scsi_scan_host(sh);
	return 0;

out_mptspi_probe:

	mptscsih_remove(pdev);
	return error;
}

static struct pci_driver mptspi_driver = {
	.name		= "mptspi",
	.id_table	= mptspi_pci_table,
	.probe		= mptspi_probe,
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
/**
 *	mptspi_init - Register MPT adapter(s) as SCSI host(s) with
 *	linux scsi mid-layer.
 *
 *	Returns 0 for success, non-zero for failure.
 */
static int __init
mptspi_init(void)
{

	show_mptmod_ver(my_NAME, my_VERSION);

	mptspiDoneCtx = mpt_register(mptscsih_io_done, MPTSPI_DRIVER);
	mptspiTaskCtx = mpt_register(mptscsih_taskmgmt_complete, MPTSPI_DRIVER);
	mptspiDVCtx = mpt_register(mptscsih_DVCmd_complete, MPTSPI_DRIVER);
	mptspiInternalCtx = mpt_register(mptscsih_InternalCmd_complete, MPTSPI_DRIVER);

	if (mpt_event_register(mptspiDoneCtx, mptscsih_event_process) == 0) {
		devtprintk((KERN_INFO MYNAM
		   	": Registered for IOC event notifications mptspiDoneCtx=%08x\n", mptspiDoneCtx));
	}

	if (mpt_reset_register(mptspiDoneCtx, mptscsih_ioc_reset) == 0) {
		dprintk((KERN_INFO MYNAM
		  ": Registered for IOC reset notifications\n"));
	}

	return pci_register_driver(&mptspi_driver);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptspi_exit - Unregisters MPT adapter(s)
 *
 */
static void __exit
mptspi_exit(void)
{
	pci_unregister_driver(&mptspi_driver);

	mpt_reset_deregister(mptspiDoneCtx);
	dprintk((KERN_INFO MYNAM
	  ": Deregistered for IOC reset notifications\n"));

	mpt_event_deregister(mptspiDoneCtx);
	dprintk((KERN_INFO MYNAM
	  ": Deregistered for IOC event notifications\n"));

	mpt_deregister(mptspiInternalCtx);
	mpt_deregister(mptspiDVCtx);
	mpt_deregister(mptspiTaskCtx);
	mpt_deregister(mptspiDoneCtx);
}

module_init(mptspi_init);
module_exit(mptspi_exit);

int mptspi_dummy_symbol;
EXPORT_SYMBOL(mptspi_dummy_symbol);

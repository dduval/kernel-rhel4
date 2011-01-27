/*
 *  linux/drivers/message/fusion/mptsas.c
 *      For use with LSI PCI SAS chip/adapter(s)
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

#include "mptbase.h"
#include "mptscsih.h"
#include "mptsas.h"

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
#define my_NAME		"Fusion MPT SAS Host driver"
#define my_VERSION	MPT_LINUX_VERSION_COMMON
#define MYNAM		"mptsas"

MODULE_AUTHOR(MODULEAUTHOR);
MODULE_DESCRIPTION(my_NAME);
MODULE_LICENSE("GPL");
MODULE_VERSION(my_VERSION);

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

static int mpt_cmd_retry_count = 144;
module_param(mpt_cmd_retry_count, int, 0);
MODULE_PARM_DESC(mpt_cmd_retry_count, " Device discovery TUR command retry count: default=144");

static int mptsas_device_queue_depth = MPT_SCSI_CMD_PER_DEV_HIGH;
module_param(mptsas_device_queue_depth, int, 0);
MODULE_PARM_DESC(mptsas_device_queue_depth, " Max Device Queue Depth (default=" __MODULE_STRING(MPT_SCSI_CMD_PER_DEV_HIGH) ")");

extern int mpt_enable_deadioc_detect;
extern int	mptscsih_TMHandler(MPT_SCSI_HOST *hd, u8 type, u8 bus, u8 id, u8 lun, int ctx2abort, ulong timeout);
static int	mptsasDoneCtx = -1;
static int	mptsasTaskCtx = -1;
static int	mptsasInternalCtx = -1; /* Used only for internal commands */

static void mptsas_hotplug_work(void *arg);

/**
 * mptsas_sas_io_unit_pg0
 *
 * obtaining SAS_IO_UNIT page 0
 *
 * @ioc
 * @port_info
 *
 **/
static int
mptsas_sas_io_unit_pg0(MPT_ADAPTER *ioc, struct mptsas_portinfo *port_info)
{
	ConfigExtendedPageHeader_t hdr;
	CONFIGPARMS cfg;
	SasIOUnitPage0_t *buffer;
	dma_addr_t dma_handle;
	int error, i;

	hdr.PageVersion = MPI_SASIOUNITPAGE0_PAGEVERSION;
	hdr.ExtPageLength = 0;
	hdr.PageNumber = 0;
	hdr.Reserved1 = 0;
	hdr.Reserved2 = 0;
	hdr.PageType = MPI_CONFIG_PAGETYPE_EXTENDED;
	hdr.ExtPageType = MPI_CONFIG_EXTPAGETYPE_SAS_IO_UNIT;

	cfg.cfghdr.ehdr = &hdr;
	cfg.physAddr = -1;
	cfg.pageAddr = 0;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;	/* read */
	cfg.timeout = 10;

	error = mpt_config(ioc, &cfg);
	if (error)
		goto out;
	if (!hdr.ExtPageLength) {
		error = -ENXIO;
		goto out;
	}

	buffer = pci_alloc_consistent(ioc->pcidev, hdr.ExtPageLength * 4,
					    &dma_handle);
	if (!buffer) {
		error = -ENOMEM;
		goto out;
	}

	cfg.physAddr = dma_handle;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

	error = mpt_config(ioc, &cfg);
	if (error)
		goto out_free_consistent;

	port_info->num_phys = buffer->NumPhys;
	port_info->phy_info = kmalloc(port_info->num_phys *
		sizeof(*port_info->phy_info),GFP_KERNEL);
	if (!port_info->phy_info) {
		error = -ENOMEM;
		goto out_free_consistent;
	}
	
	if (port_info->num_phys)
		port_info->handle =
		    le16_to_cpu(buffer->PhyData[0].ControllerDevHandle);
	for (i = 0; i < port_info->num_phys; i++) {
		port_info->phy_info[i].phy_id = i;
		port_info->phy_info[i].port_id =
		    buffer->PhyData[i].Port;
		port_info->phy_info[i].negotiated_link_rate =
		    buffer->PhyData[i].NegotiatedLinkRate;
		port_info->phy_info[i].portinfo = port_info;
		port_info->phy_info[i].port_flags =
		    buffer->PhyData[i].PortFlags;
	}

 out_free_consistent:
	pci_free_consistent(ioc->pcidev, hdr.ExtPageLength * 4,
			    buffer, dma_handle);
 out:
	return error;
}

/**
 * mptsas_sas_device_pg0
 *
 * obtaining SAS_DEVICE page 0
 * 
 * @ioc
 * device_info
 *
 **/
static int
mptsas_sas_device_pg0(MPT_ADAPTER *ioc, struct mptsas_devinfo *device_info,
		u32 form, u32 form_specific)
{
	ConfigExtendedPageHeader_t hdr;
	CONFIGPARMS cfg;
	SasDevicePage0_t *buffer;
	dma_addr_t dma_handle;
	u64 sas_address;
	int error=0;

	hdr.PageVersion = MPI_SASDEVICE0_PAGEVERSION;
	hdr.ExtPageLength = 0;
	hdr.PageNumber = 0;
	hdr.Reserved1 = 0;
	hdr.Reserved2 = 0;
	hdr.PageType = MPI_CONFIG_PAGETYPE_EXTENDED;
	hdr.ExtPageType = MPI_CONFIG_EXTPAGETYPE_SAS_DEVICE;

	cfg.cfghdr.ehdr = &hdr;
	cfg.pageAddr = form + form_specific;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;	/* read */
	cfg.timeout = 10;

	memset(device_info, 0, sizeof(struct mptsas_devinfo));
	error = mpt_config(ioc, &cfg);
	if (error)
		goto out;
	if (!hdr.ExtPageLength) {
		error = -ENXIO;
		goto out;
	}

	buffer = pci_alloc_consistent(ioc->pcidev, hdr.ExtPageLength * 4,
				      &dma_handle);
	if (!buffer) {
		error = -ENOMEM;
		goto out;
	}

	cfg.physAddr = dma_handle;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

	error = mpt_config(ioc, &cfg);
	if (error)
		goto out_free_consistent;

	device_info->handle = le16_to_cpu(buffer->DevHandle);
	device_info->handle_parent = le16_to_cpu(buffer->ParentDevHandle);
	device_info->handle_enclosure =
	    le16_to_cpu(buffer->EnclosureHandle);
	device_info->slot = le16_to_cpu(buffer->Slot);
	device_info->phy_id = buffer->PhyNum;
	device_info->port_id = buffer->PhysicalPort;
	device_info->id = buffer->TargetID;
	device_info->channel = buffer->Bus;
	memcpy(&sas_address, &buffer->SASAddress, sizeof(u64));
	device_info->sas_address = le64_to_cpu(sas_address);
	device_info->device_info =
	    le32_to_cpu(buffer->DeviceInfo);

 out_free_consistent:
	pci_free_consistent(ioc->pcidev, hdr.ExtPageLength * 4,
			    buffer, dma_handle);
 out:
	return error;
}

/**
 *	mptsas_get_number_hotspares - returns num hot spares in this ioc
 *	@ioc: Pointer to MPT_ADAPTER structure
 *
 *	Return: number of hotspares
 *
 **/
static int
mptsas_get_number_hotspares(MPT_ADAPTER *ioc)
{
	ConfigPageHeader_t	 hdr;
	CONFIGPARMS		 cfg;
	IOCPage5_t		 *buffer = NULL;
	dma_addr_t		 dma_handle;
	int			 data_sz=0;
	int			 rc;

	memset(&hdr, 0, sizeof(ConfigPageHeader_t));
	memset(&cfg, 0, sizeof(CONFIGPARMS));

	rc = 0;
	hdr.PageNumber = 5;
	hdr.PageType = MPI_CONFIG_PAGETYPE_IOC;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.timeout = 10;

	if ((rc = mpt_config(ioc, &cfg)) != 0)
		goto get_ioc_pg5;

	if (hdr.PageLength == 0)
		goto get_ioc_pg5;

	data_sz = hdr.PageLength * 4;
	buffer = (IOCPage5_t *) pci_alloc_consistent(ioc->pcidev,
		data_sz, &dma_handle);
	if (!buffer)
		goto get_ioc_pg5;

	memset((u8 *)buffer, 0, data_sz);
	cfg.physAddr = dma_handle;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

	if ((rc = mpt_config(ioc, &cfg)) != 0)
		goto get_ioc_pg5;

	rc = buffer->NumHotSpares;

 get_ioc_pg5:

	if (buffer)
		pci_free_consistent(ioc->pcidev, data_sz,
		    (u8 *) buffer, dma_handle);

	return rc;
}

/**
 *	mptsas_get_ioc_pg5 - ioc Page 5 hot spares
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@pIocPage5: ioc page 5
 *
 *	Return: 0 for success
 *	-ENOMEM if no memory available
 *		-EPERM if not allowed due to ISR context
 *		-EAGAIN if no msg frames currently available
 *		-EFAULT for non-successful reply or no reply (timeout)
 **/
static int
mptsas_get_ioc_pg5(MPT_ADAPTER *ioc, IOCPage5_t *iocPage5)
{
	ConfigPageHeader_t	 hdr;
	CONFIGPARMS		 cfg;
	IOCPage5_t		 *buffer = NULL;
	dma_addr_t		 dma_handle;
	int			 data_sz=0;
	int			 rc;

	memset(&hdr, 0, sizeof(ConfigPageHeader_t));
	memset(&cfg, 0, sizeof(CONFIGPARMS));

	rc = 0;
	hdr.PageNumber = 5;
	hdr.PageType = MPI_CONFIG_PAGETYPE_IOC;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.timeout = 10;

	if ((rc = mpt_config(ioc, &cfg)) != 0)
		goto get_ioc_pg5;

	if (hdr.PageLength == 0) {
		rc = -EFAULT;
		goto get_ioc_pg5;
	}

	data_sz = hdr.PageLength * 4;
	buffer = (IOCPage5_t *) pci_alloc_consistent(ioc->pcidev,
		data_sz, &dma_handle);
	if (!buffer) {
		rc = -ENOMEM;
		goto get_ioc_pg5;
	}

	memset((u8 *)buffer, 0, data_sz);
	cfg.physAddr = dma_handle;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

	if ((rc = mpt_config(ioc, &cfg)) != 0)
		goto get_ioc_pg5;

	memcpy(iocPage5, buffer, sizeof(*iocPage5));

 get_ioc_pg5:

	if (buffer)
		pci_free_consistent(ioc->pcidev, data_sz,
		    (u8 *) buffer, dma_handle);

	return rc;
}

/**
 * mptsas_add_device_component
 *
 * @ioc
 * @channel - fw mapped id's
 * @id
 * @sas_address
 * @device_info
 *
 **/
static void
mptsas_add_device_component(MPT_ADAPTER *ioc, u8 channel, u8 id,
	u64 sas_address, u32 device_info)
{
	struct sas_device_info	*sas_info, *next;

	down(&ioc->sas_device_info_mutex);

	/*
	 * Delete all matching sas_address's out of tree
	 */
	list_for_each_entry_safe(sas_info, next, &ioc->sas_device_info_list, list) {
		if (sas_info->sas_address != sas_address)
			continue;
		list_del(&sas_info->list);
		kfree(sas_info);
	}

	/*
	 * If there is a matching channel/id, then swap out with new target info
	 */
	list_for_each_entry(sas_info, &ioc->sas_device_info_list, list) {
		if (sas_info->fw.channel == channel && sas_info->fw.id == id)
			goto initialize_data;
	}

	if (!(sas_info = kmalloc(sizeof(*sas_info), GFP_KERNEL)))
		goto out;
	memset(sas_info, 0, sizeof(*sas_info));

	/*
	 * mapping - is for compatibility with drivers supporting sas transport layer
	 */
	sas_info->fw.id = id;
	sas_info->fw.channel = channel;
	sas_info->os.id = id;
	sas_info->os.channel = channel;
	list_add_tail(&sas_info->list, &ioc->sas_device_info_list);

 initialize_data:

	sas_info->sas_address = sas_address;
	sas_info->device_info = device_info;
	sas_info->is_cached = 0;
	sas_info->is_logical_volume = 0;
	devtprintk((KERN_INFO "%s: adding channel=%d id=%d "
	    "sas_address=0x%llX\n", __FUNCTION__, channel, id, sas_address));

 out:
	up(&ioc->sas_device_info_mutex);
	return;
}

/**
 * mptsas_add_device_component_single
 *
 * @ioc
 * @channel
 * @id
 *
 **/
static void
mptsas_add_device_component_single(MPT_ADAPTER *ioc, u8 channel, u8 id)
{
	struct mptsas_devinfo sas_device;
	int rc;

	rc = mptsas_sas_device_pg0(ioc, &sas_device,
	    (MPI_SAS_DEVICE_PGAD_FORM_BUS_TARGET_ID <<
	     MPI_SAS_DEVICE_PGAD_FORM_SHIFT),
	    (channel << 8) + id);
	if (rc)
		return;

	mptsas_add_device_component(ioc, sas_device.channel,
	    sas_device.id, sas_device.sas_address, sas_device.device_info);
}

/**
 * mptsas_add_device_component_hotspare
 *
 * Handle adding hotspares into the list
 *
 * @ioc
 *
 **/
static void
mptsas_add_device_component_hotspare(MPT_ADAPTER *ioc)
{
	int		num_hotspares;
	IOCPage5_t 	*iocPage5;
	RaidPhysDiskPage0_t	phys_disk;
	int 		i;

	iocPage5 = NULL;
	num_hotspares = mptsas_get_number_hotspares(ioc);
	if (!num_hotspares)
		goto out;

	iocPage5 = kmalloc(offsetof(IOCPage5_t,HotSpare) +
	    num_hotspares * sizeof(IOC_5_HOT_SPARE), GFP_KERNEL);
	if (!iocPage5)
		goto out;
	memset(iocPage5, 0, sizeof(*iocPage5));
	if (mptsas_get_ioc_pg5(ioc, iocPage5) != 0)
		goto out;
	for(i = 0; i < num_hotspares; i++) {
		mpt_raid_phys_disk_pg0(ioc,
		    iocPage5->HotSpare[i].PhysDiskNum, &phys_disk );
		mptsas_add_device_component_single(ioc,
		    phys_disk.PhysDiskBus, phys_disk.PhysDiskID);
	}
 out:
	kfree(iocPage5);

}

/**
 * mptsas_add_device_component_ir
 *
 * Handle Integrated RAID, adding each individual device to list
 *
 * @ioc
 * @channel
 * @id
 *
 **/
static void
mptsas_add_device_component_ir(MPT_ADAPTER *ioc, u8 channel, u8 id)
{
	CONFIGPARMS			cfg;
	ConfigPageHeader_t		hdr;
	dma_addr_t			dma_handle;
	pRaidVolumePage0_t		buffer = NULL;
	int				i;
	RaidPhysDiskPage0_t 		phys_disk;
	struct sas_device_info		*sas_info;

	memset(&cfg, 0 , sizeof(CONFIGPARMS));
	memset(&hdr, 0 , sizeof(ConfigPageHeader_t));
	hdr.PageType = MPI_CONFIG_PAGETYPE_RAID_VOLUME;
	cfg.pageAddr = (channel << 8) + id;
	cfg.cfghdr.hdr = &hdr;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;

	if (mpt_config(ioc, &cfg) != 0)
		goto out;

	if (!hdr.PageLength)
		goto out;

	buffer = pci_alloc_consistent(ioc->pcidev, hdr.PageLength * 4,
	    &dma_handle);

	if (!buffer)
		goto out;

	cfg.physAddr = dma_handle;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

	if (mpt_config(ioc, &cfg) != 0)
		goto out;

	if (!buffer->NumPhysDisks)
		goto out;

	/*
	 * Adding entry for hidden components
	 */
	for (i = 0; i < buffer->NumPhysDisks; i++) {

		if(mpt_raid_phys_disk_pg0(ioc,
		    buffer->PhysDisk[i].PhysDiskNum, &phys_disk) != 0)
			continue;

		mptsas_add_device_component_single(ioc, phys_disk.PhysDiskBus,
		    phys_disk.PhysDiskID);
	}

	/*
	 * Adding entry for logical volume in list
	 */
	list_for_each_entry(sas_info, &ioc->sas_device_info_list, list) {
		if (sas_info->fw.channel == channel && sas_info->fw.id ==  id)
			goto initialize_data;
	}

	if (!(sas_info = kmalloc(sizeof(*sas_info), GFP_KERNEL)))
		goto out;
	memset(sas_info, 0, sizeof(*sas_info));

	sas_info->fw.id = id;
	sas_info->fw.channel = channel; /* channel zero */
	down(&ioc->sas_device_info_mutex);
	list_add_tail(&sas_info->list, &ioc->sas_device_info_list);
	up(&ioc->sas_device_info_mutex);

 initialize_data:

	sas_info->os.id = id;
	sas_info->os.channel = channel;
	sas_info->sas_address = 0;
	sas_info->device_info = 0;
	sas_info->is_logical_volume = 1;
	sas_info->is_cached = 0;

	devtprintk((KERN_INFO "%s: adding volume at channel=%d id=%d\n",
	    __FUNCTION__, channel, id));

	mptsas_add_device_component_hotspare(ioc);
 out:
	if (buffer)
		pci_free_consistent(ioc->pcidev, hdr.PageLength * 4, buffer,
		    dma_handle);
}


/**
 * mptsas_del_device_component
 *
 * Once a device has been removed, we mark the
 * entry in the list as being cached
 *
 * @ioc
 * @channel - os mapped id's
 * @id
 *
 **/
static void
mptsas_del_device_component(MPT_ADAPTER *ioc, u8 channel, u8 id)
{
	struct sas_device_info	*sas_info, *next;

	/*
	 * Set is_cached flag
	 */
	list_for_each_entry_safe(sas_info, next, &ioc->sas_device_info_list, list) {
		if (sas_info->os.channel == channel && sas_info->os.id == id) {
			sas_info->is_cached = 1;
			devtprintk((KERN_INFO
			    "%s: deleting channel=%d id=%d "
			    "sas_address=0x%llX\n", __FUNCTION__, channel, id,
			    sas_info->sas_address));
		}
	}
}

/**
 * mptsas_del_device_components
 *
 * Cleaning the list
 *
 * @ioc
 *
 **/
static void
mptsas_del_device_components(MPT_ADAPTER *ioc)
{
	struct sas_device_info	*sas_info, *next;

	down(&ioc->sas_device_info_mutex);
	list_for_each_entry_safe(sas_info, next, &ioc->sas_device_info_list, list) {
		list_del(&sas_info->list);
		kfree(sas_info);
	}
	up(&ioc->sas_device_info_mutex);
}

/**
 * mptsas_find_vdevice
 *
 * @ioc
 * @channel
 * @id
 *
 **/
static VirtDevice *
mptsas_find_vdevice(MPT_ADAPTER *ioc, u8 channel, u8 id)
{
	struct _MPT_DEVICE *pMptTarget;

	if (id >= ioc->DevicesPerBus || channel >= ioc->NumberOfBuses)
		return NULL;

	pMptTarget = ioc->Target_List[channel];
	return pMptTarget->Target[id];
}

/**
 * mptsas_qcmd
 *
 * receiving a scsi_cmnd from upper layers
 *
 * @SCpnt
 * @done
 *
 **/
static int
mptsas_qcmd(struct scsi_cmnd *SCpnt, void (*done)(struct scsi_cmnd *))
{
	MPT_SCSI_HOST *hd = (MPT_SCSI_HOST *) SCpnt->device->host->hostdata;
	MPT_ADAPTER *ioc = hd->ioc;
	static VirtDevice *pTarget;
	int id = SCpnt->device->id;
	int channel = SCpnt->device->channel;

	/* If Device has been removed, inhibit any more IO */
	pTarget = mptsas_find_vdevice(ioc, channel, id);
	if (pTarget && (pTarget->tflags & MPT_TARGET_FLAGS_DELETED)) {
		SCpnt->result = DID_NO_CONNECT << 16;
		done(SCpnt);
		return 0;
	}

	return mptscsih_qcmd(SCpnt,done);
}

/**
 * mptsas_slave_configure
 *
 *
 * @sdev
 *
 **/
static int
mptsas_slave_configure(struct scsi_device *sdev)
{
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)sdev->host->hostdata;
	MPT_ADAPTER *ioc = hd->ioc;
	int		channel;
	int		id;

	channel = sdev->channel;
	id = sdev->id;

	dinitprintk((MYIOC_s_INFO_FMT
		"%s: id=%d channel=%d sdev->queue_depth=%d mptsas_device_queue_depth=%d\n",
		ioc->name, __FUNCTION__, id, channel, sdev->queue_depth,
		mptsas_device_queue_depth));
	if ((ioc->raid_data.isRaid & (1 << id)) == 0)
		mptsas_add_device_component_single(ioc, channel, id);
	return mptscsih_slave_configure(sdev, mptsas_device_queue_depth);
}

static struct device_attribute mptsas_queue_depth_attr = {
	.attr = {
		.name = 	"queue_depth",
		.mode =		S_IWUSR,
	},
	.store = mptscsih_store_queue_depth,
};


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

static ssize_t mptsas_show_sas_address (struct device *dev, char *buf)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	MPT_SCSI_HOST *hd = (MPT_SCSI_HOST *) sdev->host->hostdata;
	MPT_ADAPTER *ioc = hd->ioc;
	struct sas_device_info  *si, *sas_info = NULL;
	ssize_t len = -ENXIO;

	down(&ioc->sas_device_info_mutex);
	list_for_each_entry(si, &ioc->sas_device_info_list, list) {
		if (si->os.channel == sdev->channel &&
		    si->os.id == sdev->id) {
			sas_info = si;
			goto out;
		}
	}

out:
	if (sas_info)
		len = snprintf(buf, 20, "0x%016llx\n",
				(unsigned long long) sas_info->sas_address);

	up(&ioc->sas_device_info_mutex);
	return len;
}

static struct device_attribute mptsas_sas_address_attr = {
	.attr = {
		.name =		"suse_sas_address",
		.mode =		S_IRUSR,
	},
	.show = mptsas_show_sas_address
};

/* Device attributes */
static struct device_attribute *mptsas_dev_attrs[] = {
	&mptsas_queue_depth_attr,
	&mptsas_sas_address_attr,
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
	.slave_configure		= mptsas_slave_configure,
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
	.shost_attrs			= mptsas_host_attrs,
	.sdev_attrs			= mptsas_dev_attrs,
	.dump_sanity_check		= mptscsih_sanity_check,
	.dump_poll			= mptscsih_poll,
};

/**
 * mptsas_remove
 *
 *
 * @pdev
 *
 **/
static void __devexit mptsas_remove(struct pci_dev *pdev)
{
	MPT_ADAPTER *ioc = pci_get_drvdata(pdev);
	if(ioc->sh != NULL)
		mptsas_del_device_components(ioc);

	flush_scheduled_work();
	mptscsih_remove(pdev);
}

/**
 * mptsas_target_reset
 *
 * Issues TARGET_RESET to end device using handshaking method
 *
 * @ioc
 * @channel
 * @id
 *
 * Returns (1) success
 *         (0) failure
 *
 **/
static int
mptsas_target_reset(MPT_ADAPTER *ioc, u8 channel, u8 id)
{
	MPT_FRAME_HDR	*mf;
	SCSITaskMgmt_t	*pScsiTm;

	if ((mf = mpt_get_msg_frame(ioc->TaskCtx, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames @%d!!\n",
		    ioc->name,__FUNCTION__, __LINE__));
		return 0;
	}

	/* Format the Request
	 */
	pScsiTm = (SCSITaskMgmt_t *) mf;
	memset (pScsiTm, 0, sizeof(SCSITaskMgmt_t));
	pScsiTm->TargetID = id;
	pScsiTm->Bus = channel;
	pScsiTm->Function = MPI_FUNCTION_SCSI_TASK_MGMT;
	pScsiTm->TaskType = MPI_SCSITASKMGMT_TASKTYPE_TARGET_RESET;
	pScsiTm->MsgFlags = MPI_SCSITASKMGMT_MSGFLAGS_LIPRESET_RESET_OPTION;

// EDM	printk("tm target reset : issue : channel=%d id=%d\n", channel, id);
	DBG_DUMP_TM_REQUEST_FRAME(mf);

	if (mpt_send_handshake_request(ioc->TaskCtx, ioc,
	    sizeof(SCSITaskMgmt_t), (u32 *)mf, 10, NO_SLEEP)) {
		mpt_free_msg_frame(ioc, mf);
		dfailprintk((MYIOC_s_WARN_FMT "%s, tm handshake failed @%d!!\n",
		    ioc->name,__FUNCTION__, __LINE__));
		return 0;
	}

	return 1;
}

/**
 * mptsas_target_reset_queue
 *
 * Receive request for TARGET_RESET after recieving an firmware
 * event NOT_RESPONDING_EVENT, then put command in link list
 * and queue if task_queue already in use.
 *
 * @ioc
 * @sas_event_data
 *
 **/
static void
mptsas_target_reset_queue(MPT_ADAPTER *ioc,
    EVENT_DATA_SAS_DEVICE_STATUS_CHANGE *sas_event_data)
{
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)ioc->sh->hostdata;
	VirtDevice *vdevice = NULL;
	struct mptscsih_target_reset	*target_reset_list;
	u8		id, channel;

	id = sas_event_data->TargetID;
	channel = sas_event_data->Bus;

	if (!(vdevice = mptsas_find_vdevice(ioc, channel, id)))
		return;

	vdevice->tflags |= MPT_TARGET_FLAGS_DELETED;

	target_reset_list = kmalloc(sizeof(*target_reset_list),
	    GFP_ATOMIC);
	if (!target_reset_list) {
		dfailprintk((MYIOC_s_WARN_FMT
			"%s, failed to allocate mem @%d..!!\n",
		    ioc->name,__FUNCTION__, __LINE__));
		return;
	}

	memset(target_reset_list, 0, sizeof(*target_reset_list));
// EDM	printk("tm target reset : queue : channel=%d id=%d\n", channel, id);

	memcpy(&target_reset_list->sas_event_data, sas_event_data,
		sizeof(*sas_event_data));
	list_add_tail(&target_reset_list->list, &hd->target_reset_list);

	if (hd->resetPending)
		return;

	if (mptsas_target_reset(ioc, channel, id)) {
		target_reset_list->target_reset_issued = 1;
		hd->resetPending = 1;
	}
}

/**
 * mptsas_dev_reset_complete
 *
 * Completion for TARGET_RESET after NOT_RESPONDING_EVENT,
 * enable work queue to finish off removing device from upper layers.
 * then send next TARGET_RESET in the queue.
 *
 * @ioc
 *
 **/
static void
mptsas_dev_reset_complete(MPT_ADAPTER *ioc)
{
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)ioc->sh->hostdata;
        struct list_head *head = &hd->target_reset_list;
	struct mptscsih_target_reset	*target_reset_list;
	struct mptsas_hotplug_event *ev;
	EVENT_DATA_SAS_DEVICE_STATUS_CHANGE *sas_event_data;
	u8		id, channel;
	u64		sas_address;

	if (list_empty(head))
		return;

	target_reset_list = list_entry(head->next,
	    struct mptscsih_target_reset, list);

	sas_event_data = &target_reset_list->sas_event_data;
	id = sas_event_data->TargetID;
	channel = sas_event_data->Bus;
	hd->resetPending = 0;

	/*
	 * retry target reset
	 */
	if (!target_reset_list->target_reset_issued) {
		if (mptsas_target_reset(ioc, channel, id)) {
			target_reset_list->target_reset_issued = 1;
			hd->resetPending = 1;
		}
		return;
	}

// EDM	printk("tm target reset : complete : channel=%d id=%d\n", channel, id);

	/*
	 * enable work queue to remove device from upper layers
	 */
	list_del(&target_reset_list->list);

	ev = kmalloc(sizeof(*ev), GFP_ATOMIC);
	if (!ev) {
		dfailprintk((MYIOC_s_WARN_FMT
		    "%s, failed to allocate mem @%d..!!\n",
		    ioc->name,__FUNCTION__, __LINE__));
		return;
	}

	memset(ev, 0, sizeof(*ev));
	INIT_WORK(&ev->work, mptsas_hotplug_work, ev);
	ev->ioc = ioc;
	ev->handle = le16_to_cpu(sas_event_data->DevHandle);
	ev->parent_handle = le16_to_cpu(sas_event_data->ParentDevHandle);
	ev->channel = channel;
	ev->id = id;
	ev->phy_id = sas_event_data->PhyNum;
	memcpy(&sas_address, &sas_event_data->SASAddress, sizeof(u64));
	ev->sas_address = le64_to_cpu(sas_address);
	ev->device_info = le32_to_cpu(sas_event_data->DeviceInfo);
	ev->event_type = MPTSAS_DEL_DEVICE;
	schedule_work(&ev->work);
	kfree(target_reset_list);

	/*
	 * issue target reset to next device in the queue
	 */

	head = &hd->target_reset_list;
	if (list_empty(head))
		return;

	target_reset_list = list_entry(head->next, struct mptscsih_target_reset,
	    list);

	sas_event_data = &target_reset_list->sas_event_data;
	id = sas_event_data->TargetID;
	channel = sas_event_data->Bus;

	if (mptsas_target_reset(ioc, channel, id)) {
		target_reset_list->target_reset_issued = 1;
		hd->resetPending = 1;
	}
}

/**
 * mptsas_taskmgmt_complete
 *
 * @ioc
 * @mf
 * @mr
 *
 **/
static int
mptsas_taskmgmt_complete(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf, MPT_FRAME_HDR *mr)
{
	mptsas_dev_reset_complete(ioc);
	return mptscsih_taskmgmt_complete(ioc, mf, mr);
}

/**
 * mptscsih_ioc_reset
 *
 * @ioc
 * @reset_phase
 *
 **/
static int
mptsas_ioc_reset(MPT_ADAPTER *ioc, int reset_phase)
{
	MPT_SCSI_HOST	*hd =NULL;	
	struct mptscsih_target_reset	*target_reset_list, *n;
	int rc;
	
	if ((ioc->sh != NULL) && (ioc->sh->hostdata != NULL))
 		hd = (MPT_SCSI_HOST *)ioc->sh->hostdata;

	rc = mptscsih_ioc_reset(ioc, reset_phase);

	if (reset_phase != MPT_IOC_POST_RESET)
		goto out;

	if (ioc->bus_type != SAS)
		goto out;
	
	if(hd == NULL)
		goto out;

	if (list_empty(&hd->target_reset_list))
		goto out;

	/* flush the target_reset_list */
	list_for_each_entry_safe(target_reset_list, n,
	    &hd->target_reset_list, list) {
		list_del(&target_reset_list->list);
		kfree(target_reset_list);
	}

 out:
	return rc;
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


/**
 * mptscsih_sas_persist_clear_table
 *
 *
 * @ioc
 *
 **/
static void
mptscsih_sas_persist_clear_table(void * arg)
{
	MPT_ADAPTER *ioc = (MPT_ADAPTER *)arg;

	mptbase_sas_persist_operation(ioc, MPI_SAS_OP_CLEAR_NOT_PRESENT);
}

/**
 * mptsas_hotplug_print
 *
 *
 * @ioc
 * @hot_plug_info
 * @msg_string
 *
 **/
static void
mptsas_hotplug_print(MPT_ADAPTER *ioc, struct mptsas_hotplug_event *hot_plug_info,  u32 lun, u8 * msg_string)
{
	char *ds;
	u32 	id = hot_plug_info->id;
	u32 	channel = hot_plug_info->channel;

	if ( id >= ioc->DevicesPerBus ) {
		printk(MYIOC_s_WARN_FMT "%s: Invalid id=%d, DevicesPerBus=%d\n",
		    ioc->name, __FUNCTION__, id, ioc->DevicesPerBus);
		return;
	}

	if ( channel >= ioc->NumberOfBuses ) {
		printk(MYIOC_s_WARN_FMT
		    "%s: Invalid channel=%d, NumberOfBuses=%d\n",
		    ioc->name, __FUNCTION__, channel, ioc->NumberOfBuses);
		return;
	}

	if (hot_plug_info->device_info &
	    MPI_SAS_DEVICE_INFO_SSP_TARGET)
		ds = "sas ";
	else if (hot_plug_info->device_info &
	    MPI_SAS_DEVICE_INFO_STP_TARGET)
		ds = "stp ";
	else if (hot_plug_info->device_info &
	    MPI_SAS_DEVICE_INFO_SATA_DEVICE)
		ds = "sata ";
	else
		ds = "";

	printk(MYIOC_s_INFO_FMT
	    "%s %sdevice, channel %d, id %d, lun %d,"
	    "  phy %d\n", ioc->name, msg_string, ds,
	    channel, id, lun,
	    hot_plug_info->phy_id);
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
	static VirtDevice *pTarget;
	u32 channel, id;

	id = hot_plug_info->id;
	channel = hot_plug_info->channel;

	if ( id >= ioc->DevicesPerBus ) {
		printk(MYIOC_s_WARN_FMT "%s: Invalid id=%d, DevicesPerBus=%d\n",
		    ioc->name, __FUNCTION__, id, ioc->DevicesPerBus);
		return;
	}

	if ( channel >= ioc->NumberOfBuses ) {
		printk(MYIOC_s_WARN_FMT
		    "%s: Invalid channel=%d, NumberOfBuses=%d\n",
		    ioc->name, __FUNCTION__, channel, ioc->NumberOfBuses);
		return;
	}

	pTarget = mptsas_find_vdevice(ioc, channel, id);
	if (!pTarget)
		return;

	pTarget->tflags &= ~MPT_TARGET_FLAGS_TLR_DONE;


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

/**
 * mptsas_add_device
 *
 *
 * @ioc
 * @hot_plug_info
 *
 **/
static void
mptsas_add_device(MPT_ADAPTER *ioc, struct mptsas_hotplug_event *hot_plug_info,
    u32 lun)
{
	u32 	channel, id;
	struct scsi_device *sdev;

	id = hot_plug_info->id;

	if ( id >= ioc->DevicesPerBus ) {
		printk(MYIOC_s_WARN_FMT "%s: Invalid id=%d, DevicesPerBus=%d\n",
		    ioc->name, __FUNCTION__, id, ioc->DevicesPerBus);
		return;
	}

	channel = hot_plug_info->channel;
	if ( channel >= ioc->NumberOfBuses ) {
		printk(MYIOC_s_WARN_FMT
		    "%s: Invalid channel=%d, NumberOfBuses=%d\n",
		    ioc->name, __FUNCTION__, channel, ioc->NumberOfBuses);
		return;
	}

	/*
	 * avoid adding a device that is already present
	 */
	sdev = scsi_device_lookup(ioc->sh, channel, id, lun);
	if (sdev) {
		scsi_device_put(sdev);
		return;
	}

	sdev = scsi_add_device(ioc->sh, channel, id, lun);
	if (!IS_ERR(sdev))
		mptsas_hotplug_print(ioc, hot_plug_info, lun,
		    "attaching");
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
	int 		rc;

	id = hot_plug_info->id;
	channel = hot_plug_info->channel;

	if ( id > ioc->DevicesPerBus ) {
		printk(MYIOC_s_WARN_FMT "%s: Invalid id=%d, DevicesPerBus=%d\n",
		    ioc->name, __FUNCTION__, id, ioc->DevicesPerBus);
		return;
	}

	if ( channel >= ioc->NumberOfBuses ) {
		printk(MYIOC_s_WARN_FMT
		    "%s: Invalid channel=%d, NumberOfBuses=%d\n",
		    ioc->name, __FUNCTION__, channel, ioc->NumberOfBuses);
		return;
	}

	/*
	 * Integrated RAID doesn't support REPORT_LUNS, it will timeout
	 */
	if (ioc->raid_data.isRaid & (1 << id)) {
		mptsas_add_device(ioc, hot_plug_info, 0);
		return;
	}

	/* initialize REPORT_LUN params */
	lun = 0;
	lun_data_len = 0;
	lun_data = NULL;
	lunp = NULL;

	/*
	 * Test Unit Ready
	 */
	iocmd.cmd = TEST_UNIT_READY;
	iocmd.bus = channel;
	iocmd.id = id;
	iocmd.lun = lun;
	iocmd.flags = 0;
	iocmd.data_dma = -1;
	iocmd.data = NULL;
	iocmd.size = 0;
	dinitprintk((MYIOC_s_INFO_FMT "Sending TURs to channel=%d id=%d \n",
		ioc->name, channel, id));
	for (retries = 0; retries < mpt_cmd_retry_count; retries++) {
		if (mptscsih_do_cmd(hd, &iocmd) < 0) {
			dinitprintk((MYIOC_s_INFO_FMT
			    "TUR: mptscsih_do_cmd failed\n",
			    ioc->name));
			goto tur_done;
		}

		if (hd->pLocal == NULL) {
			dinitprintk((MYIOC_s_INFO_FMT "TUR: no pLocal\n",
			    ioc->name));
			goto tur_done;
		}

		rc = hd->pLocal->completion;
		if (rc == MPT_SCANDV_GOOD) {
			dinitprintk((MYIOC_s_INFO_FMT "TUR: succeeded\n",
			    ioc->name));
			goto tur_done;
		} else if (rc == MPT_SCANDV_BUSY) {
			dinitprintk((MYIOC_s_INFO_FMT "TUR: BUSY\n",
				ioc->name));
			msleep(1000);  /* sleep 1 second */
			continue;
		} else if (rc == MPT_SCANDV_SENSE) {
			u8 skey = hd->pLocal->sense[2] & 0x0F;
			u8 asc = hd->pLocal->sense[12];
			u8 ascq = hd->pLocal->sense[13];
			dinitprintk((MYIOC_s_INFO_FMT
			    "SenseKey:ASC:ASCQ = (%x:%02x:%02x)\n",
			    ioc->name, skey, asc, ascq));

			if (skey == UNIT_ATTENTION) {
				dinitprintk((MYIOC_s_INFO_FMT
				    "TUR: UNIT ATTENTION\n",
				    ioc->name));
				continue;
			} else if ((skey == NOT_READY) &&
			    (asc == 0x04)&&(ascq == 0x01)) {
				dinitprintk((MYIOC_s_INFO_FMT
				    "TUR: Becoming Ready\n",
				    ioc->name));
				msleep(1000);  /* sleep 1 second */
				continue;
			}
		}
	}

 tur_done:

	lun_data_len = (MPT_LAST_LUN + 1) * sizeof(struct scsi_lun);
	lun_data = pci_alloc_consistent(ioc->pcidev, lun_data_len,
	    &lun_data_dma);
	if (!lun_data)
		goto report_luns_done;

	/*
	 * Report Luns
	 */
	iocmd.cmd = REPORT_LUNS;
	iocmd.data_dma = lun_data_dma;
	iocmd.data = (u8 *)lun_data;
	iocmd.size = lun_data_len;
	iocmd.flags = 0;

	/*
	 * While loop for 10 sec retrying REPORT_LUNS, this is done
	 * because some devices return MPI_SCSI_STATUS_BUSY for several
	 * seconds.
	 */
	dinitprintk((MYIOC_s_INFO_FMT
	   "Sending REPORT_LUNS to channel=%d id=%d \n",
	    ioc->name, channel, id));
	for (retries = 0; retries < 10; retries++) {
		memset(lun_data, 0, lun_data_len);
		if (mptscsih_do_cmd(hd, &iocmd) < 0) {
			dinitprintk((MYIOC_s_INFO_FMT
			    "RL: mptscsih_do_cmd failed\n", ioc->name));
			goto report_luns_done;
		}

		if (hd->pLocal == NULL) {
			dinitprintk((MYIOC_s_INFO_FMT "RL: no pLocal\n",
			    ioc->name));
			goto report_luns_done;
		}

		rc = hd->pLocal->completion;
		if (rc == MPT_SCANDV_GOOD) {
			dinitprintk((MYIOC_s_INFO_FMT "RL: succeeded\n",
			    ioc->name));
			goto report_luns_done;
		} else if (rc == MPT_SCANDV_BUSY) {
			dinitprintk((MYIOC_s_INFO_FMT "RL: BUSY\n", ioc->name));
			msleep(1000);  /* sleep 1 second */
			continue;
		} else if (rc == MPT_SCANDV_SENSE) {
			u8 skey = hd->pLocal->sense[2] & 0x0F;
			u8 asc = hd->pLocal->sense[12];
			u8 ascq = hd->pLocal->sense[13];
			dinitprintk((MYIOC_s_INFO_FMT
			    "SenseKey:ASC:ASCQ = (%x:%02x:%02x)\n", ioc->name,
			    skey, asc, ascq));

			if (skey == UNIT_ATTENTION) {
				dinitprintk((MYIOC_s_INFO_FMT
				   "RL: UNIT ATTENTION\n", ioc->name));
				continue;
			} else if ((skey == NOT_READY) &&
			    (asc == 0x04)&&(ascq == 0x01)) {
				dinitprintk((MYIOC_s_INFO_FMT
				    "RL: Becoming Ready\n", ioc->name));
				msleep(1000);  /* sleep 1 second */
				continue;
			}
		}
	}

 report_luns_done:
	/*
	 * Attaching lun=0
	 */
	mptsas_add_device(ioc, hot_plug_info, lun);

	/*
	 * Get the length from the first four bytes of lun_data.
	 */
	if (!lun_data)
		goto out;
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

/**
 * mptsas_hotplug_work
 *
 *
 * @hot_plug_info
 *
 **/
static void
mptsas_hotplug_work(void *arg)
{
	struct mptsas_hotplug_event *hot_plug_info = arg;
	MPT_ADAPTER 		*ioc = hot_plug_info->ioc;
	u32 			id, channel;

	id = hot_plug_info->id;
	channel = hot_plug_info->channel;

	dhotpprintk((MYIOC_s_WARN_FMT "Entering %s for channel=%d id=%d\n",
		ioc->name,__FUNCTION__, channel, id));

	down(&ioc->hot_plug_semaphore);

	/* If there has been a change to raid, then we need to
	 * refresh the config raid data
	 */
	if (hot_plug_info->refresh_raid_config_pages)
		mpt_findImVolumes(ioc);

	switch  (hot_plug_info->event_type) {
	case MPTSAS_DEL_DEVICE:
		mptsas_del_device_component(ioc, channel, id);
		if (hot_plug_info->refresh_raid_config_pages)
			mptsas_add_device_component_hotspare(ioc);
		dhotpprintk((MYIOC_s_WARN_FMT
		    "MPTSAS_DEL_DEVICE: channel=%d id=%d\n",
		    ioc->name, channel, id));
		mptsas_remove_target(ioc, hot_plug_info);
		break;

	case MPTSAS_ADD_DEVICE:
		if (ioc->raid_data.isRaid & (1 << id))
			mptsas_add_device_component_ir(ioc, channel, id);
		dhotpprintk((MYIOC_s_WARN_FMT
		    "MPTSAS_ADD_DEVICE: channel=%d id=%d\n",
		    ioc->name, channel, id));
		mptsas_scan_target(ioc, hot_plug_info);
		break;
	case MPTSAS_ADD_INACTIVE_VOLUME:
		dhotpprintk((MYIOC_s_WARN_FMT
		    "MPTSAS_ADD_INACTIVE_VOLUME: channel=%d id=%d\n",
		    ioc->name, channel, id));
		mptsas_add_device_component_ir(ioc, channel, id);
		break;
	case MPTSAS_PHYSDISK_ADD:
		mptsas_add_device_component_single(ioc, channel, id);
		break;
	default:
		dhotpprintk((MYIOC_s_WARN_FMT
		    "Unknown hot_plug event_type=%x: channel=%d id=%d "
		    " skipping\n", ioc->name, hot_plug_info->event_type,
		    channel, id));
		goto out;
	}

 out:
	dhotpprintk((MYIOC_s_WARN_FMT "%s: kfree hot_plug_info=%p\n",
	    ioc->name,__FUNCTION__, hot_plug_info));
	kfree(hot_plug_info);
	up(&ioc->hot_plug_semaphore);
}

/**
 * mptsas_send_sas_event
 *
 *
 * @ioc
 * @sas_event_data
 *
 **/
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
	case MPI_EVENT_SAS_DEV_STAT_RC_NOT_RESPONDING:
		mptsas_target_reset_queue(ioc, sas_event_data);
		break;

	case MPI_EVENT_SAS_DEV_STAT_RC_ADDED:
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

/**
 * mptsas_send_raid_event
 *
 *
 * @ioc
 * @raid_event_data
 *
 **/
static void
mptsas_send_raid_event(MPT_ADAPTER *ioc,
		EVENT_DATA_RAID *raid_event_data)
{
	struct mptsas_hotplug_event *ev;
	int status = le32_to_cpu(raid_event_data->SettingsStatus);
	int state = (status >> 8) & 0xff;

	if (ioc->bus_type != SAS)
		return;

	ev = kmalloc(sizeof(*ev), GFP_ATOMIC);
	if (!ev) {
		printk(KERN_WARNING "mptsas: lost hotplug event\n");
		return;
	}

	memset(ev,0,sizeof(struct mptsas_hotplug_event));
	ev->ioc = ioc;
	ev->id = raid_event_data->VolumeID;
	ev->channel = raid_event_data->VolumeBus;
	ev->refresh_raid_config_pages = 1;

	devtprintk((KERN_INFO MYNAM ": VolumeID=%d Reason=%x received\n",
	    ev->id, raid_event_data->ReasonCode));
	switch (raid_event_data->ReasonCode) {
	case MPI_EVENT_RAID_RC_PHYSDISK_DELETED:
		ev->event_type = MPTSAS_ADD_DEVICE;
		break;
	case MPI_EVENT_RAID_RC_PHYSDISK_CREATED:
		ev->event_type = MPTSAS_DEL_DEVICE;
		break;
	case MPI_EVENT_RAID_RC_PHYSDISK_STATUS_CHANGED:
		switch (state) {
		case MPI_PD_STATE_ONLINE:
		case MPI_PD_STATE_NOT_COMPATIBLE:
			ev->event_type = MPTSAS_PHYSDISK_ADD;
			break;
		case MPI_PD_STATE_MISSING:
		case MPI_PD_STATE_OFFLINE_AT_HOST_REQUEST:
		case MPI_PD_STATE_FAILED_AT_HOST_REQUEST:
		case MPI_PD_STATE_OFFLINE_FOR_ANOTHER_REASON:
			ev->event_type = MPTSAS_DEL_DEVICE;
			break;
		default:
			devtprintk((KERN_INFO MYNAM
			    ": ignoring this event! %d\n", __LINE__));
			return;
		}
		break;
	case MPI_EVENT_RAID_RC_VOLUME_DELETED:
		ev->event_type = MPTSAS_DEL_DEVICE;
		break;
	case MPI_EVENT_RAID_RC_VOLUME_CREATED:
		ev->event_type = MPTSAS_ADD_DEVICE;
		break;
/*	case MPI_EVENT_RAID_RC_VOLUME_STATUS_CHANGED:
		switch (state) {
		case MPI_RAIDVOL0_STATUS_STATE_FAILED:
		case MPI_RAIDVOL0_STATUS_STATE_MISSING:
			ev->event_type = MPTSAS_DEL_DEVICE;
			break;
		case MPI_RAIDVOL0_STATUS_STATE_OPTIMAL:
		case MPI_RAIDVOL0_STATUS_STATE_DEGRADED:
			ev->event_type = MPTSAS_ADD_DEVICE;
			break;
		default:
			devtprintk((KERN_INFO MYNAM
			    ": ignoring this event! %d\n", __LINE__));
			return;
		}
		break; */
	default:
		devtprintk((KERN_INFO MYNAM
		    ": ignoring this event! %d\n", __LINE__));
		return;
	}
	INIT_WORK(&ev->work, mptsas_hotplug_work, ev);
	schedule_work(&ev->work);
}

/*
 * mptsas_send_ir2_event
 *
 * This handle exposing hidden disk when an inactive raid volume is added
 */
static void
mptsas_send_ir2_event(MPT_ADAPTER *ioc, PTR_MPI_EVENT_DATA_IR2 ir2_data)
{
	struct mptsas_hotplug_event *ev;

	if (ir2_data->ReasonCode !=
	    MPI_EVENT_IR2_RC_FOREIGN_CFG_DETECTED)
		return;

	ev = kmalloc(sizeof(*ev), GFP_ATOMIC);
	if (!ev)
		return;
	memset(ev, 0, sizeof(*ev));
	ev->ioc = ioc;
	ev->id = ir2_data->TargetID;
	ev->channel = ir2_data->Bus;
	ev->refresh_raid_config_pages = 1;
	ev->event_type = MPTSAS_ADD_INACTIVE_VOLUME;

	INIT_WORK(&ev->work, mptsas_hotplug_work, ev);
	schedule_work(&ev->work);
};


/**
 *	mptsas_broadcast_primative_work - Work queue thread to handle
 *	broadcast primitive events
 *	@arg: work queue payload containing info describing the event
 *
 **/
static void
mptsas_broadcast_primative_work(void *arg)
{
	struct mptsas_broadcast_primative_event *ev = arg;
	MPT_ADAPTER		*ioc = ev->ioc;
	MPT_SCSI_HOST		*hd;
	MPT_FRAME_HDR		*mf;
	VirtDevice		*vdevice;
	int			ii;
	struct scsi_cmnd	*sc;
	int			task_context;
	u8			channel, id;
	int			 lun;

	hd = (MPT_SCSI_HOST *) ioc->sh->hostdata;
	mpt_findImVolumes(ioc);
	down(&ioc->AEN_semaphore);
	dtmprintk((MYIOC_s_WARN_FMT "%s - enter\n", ioc->name, __FUNCTION__));
	for (ii = 0; ii < ioc->req_depth; ii++) {
		sc = ioc->ScsiLookup[ii];
		if (!sc)
			continue;
		mf = MPT_INDEX_2_MFPTR(ioc, ii);
		if (!mf)
			continue;
		task_context = mf->u.frame.hwhdr.msgctxu.MsgContext;
		channel = sc->device->channel;
		id = sc->device->id;
		lun = sc->device->lun;
		vdevice = mptsas_find_vdevice(ioc, channel, id);
		if (!vdevice)
			continue;
		if (vdevice->raidVolume)
			continue; /* skip raid volumes */
		if (mptscsih_IssueTaskMgmt(hd,
		    MPI_SCSITASKMGMT_TASKTYPE_QUERY_TASK,
		    channel, id, lun, task_context, 30)) {
			dtmprintk((MYIOC_s_WARN_FMT "%s: QUERY_TASK "
			    "failed!\n", ioc->name, __FUNCTION__));
			continue;
		}
		if ((hd->tm_iocstatus == MPI_IOCSTATUS_SUCCESS) &&
		    (hd->tm_response_code == MPI_SCSITASKMGMT_RSP_TM_SUCCEEDED
		     || hd->tm_response_code ==
		     MPI_SCSITASKMGMT_RSP_IO_QUEUED_ON_IOC))
			continue;
		if (mptscsih_IssueTaskMgmt(hd,
		    MPI_SCSITASKMGMT_TASKTYPE_ABRT_TASK_SET,
		    channel, id, lun, 0, 30))
			dtmprintk((MYIOC_s_WARN_FMT "%s: ABRT_TASK_SET "
			    "failed!\n", ioc->name, __FUNCTION__));
		else
			dtmprintk((MYIOC_s_WARN_FMT "%s: ABRT_TASK_SET "
			    "successful!\n", ioc->name, __FUNCTION__));
	}

	ioc->broadcast_aen_busy = 0;
	dtmprintk((MYIOC_s_WARN_FMT "%s - exit\n", ioc->name, __FUNCTION__));
	up(&ioc->AEN_semaphore);
	kfree(ev);
}

/**
 *	mptsas_send_broadcast_primative_event - processing of event data
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	broadcast_event_data: event data
 *
 **/
static void
mptsas_send_broadcast_primative_event(MPT_ADAPTER * ioc,
	EVENT_DATA_SAS_BROADCAST_PRIMITIVE *broadcast_event_data)
{
	struct mptsas_broadcast_primative_event *ev;

	if (ioc->broadcast_aen_busy)
		return;

	if (broadcast_event_data->Primitive !=
	    MPI_EVENT_PRIMITIVE_ASYNCHRONOUS_EVENT)
		return;

	ev = kmalloc(sizeof(*ev), GFP_ATOMIC);
	if (!ev)
		return;

	ioc->broadcast_aen_busy = 1;
	memset(ev, 0, sizeof(*ev));
	INIT_WORK(&ev->work, mptsas_broadcast_primative_work, ev);
	ev->ioc = ioc;
	schedule_work(&ev->work);
}

/**
 * mptsas_event_process
 *
 *
 * @ioc
 * @reply
 *
 **/
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
		ioc->csmi_change_count++;
		mptsas_send_sas_event(ioc,
			(EVENT_DATA_SAS_DEVICE_STATUS_CHANGE *)reply->Data);
		break;
	case MPI_EVENT_INTEGRATED_RAID:
		ioc->csmi_change_count++;
		mptsas_send_raid_event(ioc,
			(EVENT_DATA_RAID *)reply->Data);
		break;
	case MPI_EVENT_PERSISTENT_TABLE_FULL:
		INIT_WORK(&ioc->mptscsih_persistTask,
		    mptscsih_sas_persist_clear_table,
		    (void *)ioc);
		schedule_work(&ioc->mptscsih_persistTask);
		break;
	case MPI_EVENT_IR2:
		ioc->csmi_change_count++;
		mptsas_send_ir2_event(ioc,
		    (PTR_MPI_EVENT_DATA_IR2)reply->Data);
		break;
	case MPI_EVENT_SAS_BROADCAST_PRIMITIVE:
		mptsas_send_broadcast_primative_event(ioc,
			(EVENT_DATA_SAS_BROADCAST_PRIMITIVE *)reply->Data);
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
	int			 ioc_cap;
	u8			*mem;
	int			error=0;
	int			r;
	struct mptsas_portinfo	*port_info;

	if ((r = mpt_attach(pdev,id)) != 0)
		return r;

	ioc = pci_get_drvdata(pdev);
	ioc->DoneCtx = mptsasDoneCtx;
	ioc->TaskCtx = mptsasTaskCtx;
	ioc->InternalCtx = mptsasInternalCtx;

	/*  Added sanity check on readiness of the MPT adapter.
	 */
	if (ioc->last_state != MPI_IOC_STATE_OPERATIONAL) {
		if(mpt_enable_deadioc_detect)
			return 0;
		else {
			printk(MYIOC_s_WARN_FMT
		  		"Skipping because it's not operational!\n",
		  		ioc->name);
			error = -ENODEV;
			goto out_mptsas_probe;
		}
	}

	if (!ioc->active) {
		if(mpt_enable_deadioc_detect)
			return 0;
		else {
			printk(MYIOC_s_WARN_FMT "Skipping because it's disabled!\n",
		  	ioc->name);
			error = -ENODEV;
			goto out_mptsas_probe;
		}
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
		printk(MYIOC_s_WARN_FMT "Skipping ioc=%p because SCSI "
		    "Initiator mode is NOT enabled!\n", ioc->name, ioc);
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
	    ioc->name, mpt_can_queue, ioc->req_depth, sh->can_queue));

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
	mem = kmalloc(sz, GFP_KERNEL);
	if (mem == NULL) {
		error = -ENOMEM;
		goto out_mptsas_probe;
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
		mem = kmalloc(sz, GFP_KERNEL);
		if (mem == NULL) {
			error = -ENOMEM;
			goto out_mptsas_probe;
		}

		memset(mem, 0, sz);
		ioc->Target_List[ii] = (struct _MPT_DEVICE *) mem;

		dinitprintk((KERN_INFO " For Bus=%d, Target_List=%p sz=%d\n",
		    ii, mem, sz));
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

	init_MUTEX(&ioc->AEN_semaphore);
	init_MUTEX(&ioc->hot_plug_semaphore);

	hd->mpt_pq_filter = mpt_pq_filter;
	ioc->sas_data.ptClear = mpt_pt_clear;
	ioc->sas_data.mpt_sas_hot_plug_enable =
	    mpt_sas_hot_plug_enable;
	ioc->sas_data.mptsas_device_queue_depth = mptsas_device_queue_depth;

	if(ioc->sas_data.ptClear==1) {
		mptbase_sas_persist_operation(
		    ioc, MPI_SAS_OP_CLEAR_ALL_PERSISTENT);
	}

	ddvprintk((MYIOC_s_INFO_FMT "mpt_pq_filter %x mpt_pq_filter %x\n",
	    ioc->name, mpt_pq_filter, mpt_pq_filter));

	init_waitqueue_head(&hd->scandv_waitq);
	hd->scandv_wait_done = 0;
	hd->last_queue_full = 0;

	init_waitqueue_head(&hd->TM_waitq);
	hd->TM_wait_done = 0;

	INIT_LIST_HEAD(&hd->target_reset_list);

	INIT_LIST_HEAD(&ioc->sas_device_info_list);
	init_MUTEX(&ioc->sas_device_info_mutex);
	port_info = kmalloc(sizeof(*port_info), GFP_KERNEL);
	if (port_info && !mptsas_sas_io_unit_pg0(ioc, port_info))
		ioc->num_ports = port_info->num_phys;
	kfree(port_info);

	error = scsi_add_host (sh, &ioc->pcidev->dev);
	if(error) {
		dprintk((KERN_ERR MYNAM "scsi_add_host failed\n"));
		goto out_mptsas_probe;
	}

	scsi_scan_host(sh);

	/*
	 * Handling Inactive Volumes
	 */
	if (!ioc->ir_firmware ||
	    !ioc->raid_data.pIocPg2 ||
	    !ioc->raid_data.pIocPg2->NumActiveVolumes)
	return 0;

	for (ii = 0; ii < ioc->raid_data.pIocPg2->NumActiveVolumes; ii++)
		mptsas_add_device_component_ir(ioc,
		    ioc->raid_data.pIocPg2->RaidVolume[ii].VolumeBus,
		    ioc->raid_data.pIocPg2->RaidVolume[ii].VolumeID);

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
	mptsasTaskCtx = mpt_register(mptsas_taskmgmt_complete, MPTSAS_DRIVER);
	mptsasInternalCtx = mpt_register(mptscsih_scandv_complete, MPTSAS_DRIVER);

	if (mpt_event_register(mptsasDoneCtx, mptsas_event_process) == 0) {
		devtprintk((KERN_INFO MYNAM
		    ": Registered for sas IOC event notifications\n"));
	}

	if (mpt_reset_register(mptsasDoneCtx, mptsas_ioc_reset) == 0) {
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

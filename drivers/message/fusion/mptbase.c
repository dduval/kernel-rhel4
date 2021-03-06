/*
 *  linux/drivers/message/fusion/mptbase.c
 *      This is the Fusion MPT base driver which supports multiple
 *      (SCSI + LAN) specialized protocol drivers.
 *      For use with LSI PCI chip/adapter(s)
 *      running LSI Fusion MPT (Message Passing Technology) firmware.
 *
 *  Copyright (c) 1999-2008 LSI Corporation
 *  (mailto:DL-MPTFusionLinux@lsi.com)
 *
 *  $Id: mptbase.c,v 1.130 2003/05/07 14:08:30 Exp $
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
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/kdev_t.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/interrupt.h>		/* needed for in_interrupt() proto */
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <asm/io.h>
#ifdef CONFIG_MTRR
#include <asm/mtrr.h>
#endif
#ifdef __sparc__
#include <asm/irq.h>			/* needed for __irq_itoa() proto */
#endif

#include "mptbase.h"

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
#define my_NAME		"Fusion MPT base driver"
#define my_VERSION	MPT_LINUX_VERSION_COMMON
#define MYNAM		"mptbase"

MODULE_AUTHOR(MODULEAUTHOR);
MODULE_DESCRIPTION(my_NAME);
MODULE_LICENSE("GPL");
MODULE_VERSION(my_VERSION);

/*
 *  cmd line parameters
 */

/* Evaluate the command line arguments, if any.
 * Example with loadable module:
 * insmod mptbase mpt_sg_tablesize=200 mpt_can_queue=1000
 * Example with boot:  add an option line in /etc/modules.conf
 * options mptbase mpt_sg_tablesize=200 mpt_can_queue=1000
 */
char *mptbase = NULL;

/* Command line args */

int mpt_can_queue = 128;
module_param(mpt_can_queue, int, 0);
MODULE_PARM_DESC(mpt_can_queue, " Max IO depth per controller (default=128)");

int mpt_sg_tablesize = CONFIG_FUSION_MAX_SGE;
module_param(mpt_sg_tablesize, int, 0);
MODULE_PARM_DESC(mpt_sg_tablesize, " Max SG count per IO (default=" __MODULE_STRING(CONFIG_FUSION_MAX_SGE) ")");

static int mpt_reply_depth = 128;
module_param(mpt_reply_depth, int, 0);
MODULE_PARM_DESC(mpt_reply_depth, " Max reply buffers per controller (default=128)");

static int mpt_chain_alloc_percent = 100;
module_param(mpt_chain_alloc_percent, int, 0);
MODULE_PARM_DESC(mpt_chain_alloc_percent, " SG Chain buffer allocation percent (default=100)");

static int mpt_msi_enable = 0;
module_param(mpt_msi_enable, int, 0);
MODULE_PARM_DESC(mpt_msi_enable, " MSI Support Enable (default=0)");

int mpt_enable_deadioc_detect = 0;
module_param(mpt_enable_deadioc_detect, int, 0);
MODULE_PARM_DESC(mpt_enable_deadioc_detect, "Detection of Dead IOC Enable (default=0)");

int mpt_fwfault_debug = 0;
module_param(mpt_fwfault_debug, int, 0);
MODULE_PARM_DESC(mpt_fwfault_debug, "Enable detection of Firmware fault"
		" and halt Firmware on fault - (default=0)");

#ifdef MFCNT
static int mfcounter = 0;
#define PRINT_MF_COUNT 20000
#endif

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *  Public data...
 */
int mpt_lan_index = -1;
int mpt_stm_index = -1;

struct proc_dir_entry *mpt_proc_root_dir;

#define WHOINIT_UNKNOWN		0xAA

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *  Private data...
 */
					/* Adapter link list */
LIST_HEAD(ioc_list);
					/* Callback lookup table */
static MPT_CALLBACK		 MptCallbacks[MPT_MAX_PROTOCOL_DRIVERS];
					/* Protocol driver class lookup table */
static int			 MptDriverClass[MPT_MAX_PROTOCOL_DRIVERS];
					/* Event handler lookup table */
static MPT_EVHANDLER		 MptEvHandlers[MPT_MAX_PROTOCOL_DRIVERS];
					/* Reset handler lookup table */
static MPT_RESETHANDLER		 MptResetHandlers[MPT_MAX_PROTOCOL_DRIVERS];
static struct mpt_pci_driver 	*MptDeviceDriverHandlers[MPT_MAX_PROTOCOL_DRIVERS];

static int	mpt_base_index = -1;
static int	last_drv_idx = -1;

static DECLARE_WAIT_QUEUE_HEAD(mpt_waitq);

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *  Forward protos...
 */
static irqreturn_t mpt_interrupt(int irq, void *bus_id, struct pt_regs *r);
static int	mpt_base_reply(MPT_ADAPTER *ioc, MPT_FRAME_HDR *req, MPT_FRAME_HDR *reply);
int	mpt_handshake_req_reply_wait(MPT_ADAPTER *ioc, int reqBytes,
		u32 *req, int replyBytes, u16 *u16reply, int maxwait,
		int sleepFlag);
int             mpt_do_ioc_recovery(MPT_ADAPTER *ioc, u32 reason, int sleepFlag);
int		mpt_writeSDP1(MPT_ADAPTER *hd, int portnum, int id, int flags);
void		mpt_setSDP1parameters (u8 width, u8 factor, u8 offset, u8 flags, int *requestedPtr, int *configurationPtr);
static void	mpt_detect_bound_ports(MPT_ADAPTER *ioc, struct pci_dev *pdev);
static void	mpt_adapter_disable(MPT_ADAPTER *ioc);
static void	mpt_adapter_dispose(MPT_ADAPTER *ioc);

static void	pci_disable_io_access(struct pci_dev *pdev);
static void	pci_enable_io_access(struct pci_dev *pdev);

static void	MptDisplayIocCapabilities(MPT_ADAPTER *ioc);
static int	MakeIocReady(MPT_ADAPTER *ioc, int force, int sleepFlag);
static int	GetIocFacts(MPT_ADAPTER *ioc, int sleepFlag, int reason);
static int	GetPortFacts(MPT_ADAPTER *ioc, int portnum, int sleepFlag);
static int	SendIocInit(MPT_ADAPTER *ioc, int sleepFlag);
static int	SendPortEnable(MPT_ADAPTER *ioc, int portnum, int sleepFlag);
static int	mpt_do_upload(MPT_ADAPTER *ioc, int sleepFlag);
int		mpt_downloadboot(MPT_ADAPTER *ioc, MpiFwHeader_t *pFwHeader, int sleepFlag);
static void	mpt_put_msg_frame_hi_pri(int handle, MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf);
static int	mpt_diag_reset(MPT_ADAPTER *ioc, int ignore, int sleepFlag);
static int	KickStart(MPT_ADAPTER *ioc, int ignore, int sleepFlag);
int             mpt_SendIocReset(MPT_ADAPTER *ioc, u8 reset_type, int sleepFlag);
static int	PrimeIocFifos(MPT_ADAPTER *ioc);
static int	WaitForDoorbellAck(MPT_ADAPTER *ioc, int howlong, int sleepFlag);
static int	WaitForDoorbellInt(MPT_ADAPTER *ioc, int howlong, int sleepFlag);
static int	WaitForDoorbellReply(MPT_ADAPTER *ioc, int howlong, int sleepFlag);
static int	GetLanConfigPages(MPT_ADAPTER *ioc);
static int	GetFcPortPage0(MPT_ADAPTER *ioc, int portnum);
static int	GetIoUnitPage2(MPT_ADAPTER *ioc);
static int	GetManufPage5(MPT_ADAPTER *ioc, int numPorts);
static int	GetManufPage0(MPT_ADAPTER *ioc);
int		mptbase_sas_persist_operation(MPT_ADAPTER *ioc, u8 persist_opcode);
static void	mptbase_raid_process_event_data(MPT_ADAPTER *ioc,
		    MpiEventDataRaid_t * pRaidEventData);
static int	mpt_GetScsiPortSettings(MPT_ADAPTER *ioc, int portnum);
static int	mpt_readScsiDevicePageHeaders(MPT_ADAPTER *ioc, int portnum);
static void 	mpt_read_ioc_pg_1(MPT_ADAPTER *ioc);
static void 	mpt_read_ioc_pg_4(MPT_ADAPTER *ioc);
static void 	mpt_read_ioc_pg_6(MPT_ADAPTER *ioc);
static void	mpt_timer_expired(unsigned long data);
static int	SendEventNotification(MPT_ADAPTER *ioc, u8 EvSwitch);
static int	SendEventAck(MPT_ADAPTER *ioc, EventNotificationReply_t *evnp);
static int	mpt_host_page_access_control(MPT_ADAPTER *ioc, u8 access_control_value, int sleepFlag);
static int	mpt_host_page_alloc(MPT_ADAPTER *ioc, pIOCInit_t ioc_init);

#ifdef CONFIG_PROC_FS
static int	procmpt_summary_read(char *buf, char **start, off_t offset,
				int request, int *eof, void *data);
static int	procmpt_version_read(char *buf, char **start, off_t offset,
				int request, int *eof, void *data);
static int	procmpt_iocinfo_read(char *buf, char **start, off_t offset,
				int request, int *eof, void *data);
#endif
static void	mpt_get_fw_exp_ver(char *buf, MPT_ADAPTER *ioc);

//int		mpt_HardResetHandler(MPT_ADAPTER *ioc, int sleepFlag);
static int	ProcessEventNotification(MPT_ADAPTER *ioc, EventNotificationReply_t *evReply, int *evHandlers);
static void	mpt_sp_ioc_info(MPT_ADAPTER *ioc, u32 ioc_status, MPT_FRAME_HDR *mf);
static void	mpt_fc_log_info(MPT_ADAPTER *ioc, u32 log_info);
static void	mpt_spi_log_info(MPT_ADAPTER *ioc, u32 log_info);
static void	mpt_sas_log_info(MPT_ADAPTER *ioc, u32 log_info);
static void	mpt_inactive_raid_list_free(MPT_ADAPTER *ioc);

/* module entry point */
static int  __init    fusion_init  (void);
static void __exit    fusion_exit  (void);

#define CHIPREG_READ32(addr) 		readl_relaxed(addr)
#define CHIPREG_READ32_dmasync(addr)	readl(addr)
#define CHIPREG_WRITE32(addr,val) 	writel(val, addr)
#define CHIPREG_PIO_WRITE32(addr,val)	outl(val, (unsigned long)addr)
#define CHIPREG_PIO_READ32(addr) 	inl((unsigned long)addr)

#define PCI_D0		( 0)
#define PCI_D1		( 1)
#define PCI_D2		( 2)
#define PCI_D3hot	( 3)
#define PCI_D3cold	( 4)
#define PCI_UNKNOWN	( 5)
#define PCI_POWER_ERROR	( -1)

/**
 *	mpt_mapresources - map in memory mapped io
 *	@ioc: Pointer to pointer to IOC adapter
 *
 **/
static int
mpt_mapresources(MPT_ADAPTER *ioc)
{
	u8		__iomem *mem;
	int		 ii;
	unsigned long	 mem_phys;
	unsigned long	 port;
	u32		 msize;
	u32		 psize;
	int		 r = -ENODEV;
	struct pci_dev *pdev;
	u8		 revision;

	pdev = ioc->pcidev;

	pci_read_config_byte(pdev, PCI_CLASS_REVISION, &revision);

	if (pci_enable_device(pdev)) {
		printk(MYIOC_s_WARN_FMT "pci_enable_device: failed\n",
		    ioc->name);
		return r;
	}

	if (((pdev->device == MPI_MANUFACTPAGE_DEVID_SAS1064E) ||
	    (pdev->device == MPI_MANUFACTPAGE_DEVID_SAS1068E)) &&
	    (revision <= 2)) {
		if (!pci_set_dma_mask(pdev, DMA_32BIT_MASK)
		    && !pci_set_consistent_dma_mask(pdev, DMA_32BIT_MASK)) {
			ioc->dma_mask = DMA_32BIT_MASK;
			dinitprintk((MYIOC_s_INFO_FMT
			    ": 32 BIT PCI BUS DMA ADDRESSING SUPPORTED\n",
			    ioc->name));
		} else {
			printk(MYIOC_s_WARN_FMT "no suitable DMA mask for %s\n",
			    ioc->name, pci_name(pdev));
			return r;
		}
	} else {
		if (!pci_set_dma_mask(pdev, DMA_64BIT_MASK)
		    && !pci_set_consistent_dma_mask(pdev, DMA_64BIT_MASK)) {
			ioc->dma_mask = DMA_64BIT_MASK;
			dinitprintk((MYIOC_s_INFO_FMT
			    ": 64 BIT PCI BUS DMA ADDRESSING SUPPORTED\n",
			    ioc->name));
		} else if (!pci_set_dma_mask(pdev, DMA_32BIT_MASK)
		    && !pci_set_consistent_dma_mask(pdev, DMA_32BIT_MASK)) {
			ioc->dma_mask = DMA_32BIT_MASK;
			dinitprintk((MYIOC_s_INFO_FMT
			    ": 32 BIT PCI BUS DMA ADDRESSING SUPPORTED\n",
			    ioc->name));
		} else {
			printk(MYIOC_s_WARN_FMT "no suitable DMA mask for %s\n",
			    ioc->name, pci_name(pdev));
			return r;
		}
	}

	mem_phys = msize = 0;
	port = psize = 0;
	for (ii=0; ii < DEVICE_COUNT_RESOURCE; ii++) {
		if (pci_resource_flags(pdev, ii) & PCI_BASE_ADDRESS_SPACE_IO) {
			if (psize)
				continue;
			/* Get I/O space! */
			port = pci_resource_start(pdev, ii);
			psize = pci_resource_len(pdev,ii);
		} else {
			if (msize)
				continue;
			/* Get memmap */
			mem_phys = pci_resource_start(pdev, ii);
			msize = pci_resource_len(pdev,ii);
		}
	}
	ioc->mem_size = msize;

	mem = NULL;
	/* Get logical ptr for PciMem0 space */
	/*mem = ioremap(mem_phys, msize);*/
	mem = ioremap(mem_phys, msize);
	if (mem == NULL) {
		printk(MYIOC_s_ERR_FMT ": ERROR - Unable to map adapter memory!\n", ioc->name);
		return -EINVAL;
	}
	ioc->memmap = mem;
	dinitprintk((MYIOC_s_WARN_FMT
		"mem = %p, mem_phys = %lx\n",
		ioc->name, mem, mem_phys));

	ioc->mem_phys = mem_phys;
	ioc->chip = (SYSIF_REGS __iomem *)mem;

	/* Save Port IO values in case we need to do downloadboot */
	{
		u8 *pmem = (u8*)port;
		ioc->pio_mem_phys = port;
		ioc->pio_chip = (SYSIF_REGS __iomem *)pmem;
	}

	return 0;
}

/**
 *	mpt_halt_firmware - Halts the firmware if it is operational and panic the kernel
 *	@ioc: Pointer to MPT_ADAPTER structure
 *
 **/
void
mpt_halt_firmware(MPT_ADAPTER *ioc)
{
	u32	 ioc_raw_state;

	ioc_raw_state = mpt_GetIocState(ioc, 0);

	if ((ioc_raw_state & MPI_IOC_STATE_MASK) == MPI_IOC_STATE_FAULT) {
		printk(MYIOC_s_ERR_FMT "IOC is in FAULT state (%04xh)!!!\n",
			ioc->name, ioc_raw_state & MPI_DOORBELL_DATA_MASK);
		panic("%s: IOC Fault (%04xh)!!!\n",
			ioc->name, ioc_raw_state & MPI_DOORBELL_DATA_MASK);
	} else {
		CHIPREG_WRITE32(&ioc->chip->Doorbell, 0xC0FFEE00);
		panic("%s: Firmware is halted due to command timeout\n", ioc->name);
	}
}

static void
pci_disable_io_access(struct pci_dev *pdev)
{
	u16 command_reg;

	pci_read_config_word(pdev, PCI_COMMAND, &command_reg);
	command_reg &= ~1;
	pci_write_config_word(pdev, PCI_COMMAND, command_reg);
}

static void
pci_enable_io_access(struct pci_dev *pdev)
{
	u16 command_reg;

	pci_read_config_word(pdev, PCI_COMMAND, &command_reg);
	command_reg |= 1;
	pci_write_config_word(pdev, PCI_COMMAND, command_reg);
}


/*
 *  Process turbo (context) reply...
 */
static void
mpt_turbo_reply(MPT_ADAPTER *ioc, u32 pa)
{
	MPT_FRAME_HDR *mf = NULL;
	MPT_FRAME_HDR *mr = NULL;
	int req_idx;
	int cb_idx;

	switch (pa >> MPI_CONTEXT_REPLY_TYPE_SHIFT) {
	case MPI_CONTEXT_REPLY_TYPE_SCSI_INIT:
		req_idx = pa & 0x0000FFFF;
		cb_idx = (pa & 0x00FF0000) >> 16;
		mf = MPT_INDEX_2_MFPTR(ioc, req_idx);
		break;
	case MPI_CONTEXT_REPLY_TYPE_LAN:
		cb_idx = mpt_lan_index;
		/*
		 *  Blind set of mf to NULL here was fatal
		 *  after lan_reply says "freeme"
		 *  Fix sort of combined with an optimization here;
		 *  added explicit check for case where lan_reply
		 *  was just returning 1 and doing nothing else.
		 *  For this case skip the callback, but set up
		 *  proper mf value first here:-)
		 */
		if ((pa & 0x58000000) == 0x58000000) {
			req_idx = pa & 0x0000FFFF;
			mf = MPT_INDEX_2_MFPTR(ioc, req_idx);
			mpt_free_msg_frame(ioc, mf);
			mb();
			return;
		}
		mr = (MPT_FRAME_HDR *) CAST_U32_TO_PTR(pa);
		break;
	case MPI_CONTEXT_REPLY_TYPE_SCSI_TARGET:
		cb_idx = mpt_stm_index;
		mr = (MPT_FRAME_HDR *) CAST_U32_TO_PTR(pa);
		break;
	default:
		cb_idx = 0;
		printk(MYIOC_s_WARN_FMT "%s: Invalid REPLY_TYPE in pa=%08x!\n",
			__FUNCTION__, ioc->name, pa);
//		BUG();
	}

	/*  Check for (valid) IO callback!  */
	if (cb_idx < 1 || cb_idx >= MPT_MAX_PROTOCOL_DRIVERS ||
			MptCallbacks[cb_idx] == NULL) {
		printk(MYIOC_s_WARN_FMT "%s: Invalid cb_idx (%d)!\n",
				__FUNCTION__, ioc->name, cb_idx);
		goto out;
	}

	if (MptCallbacks[cb_idx](ioc, mf, mr))
		mpt_free_msg_frame(ioc, mf);
 out:
	mb();
}

static void
mpt_reply(MPT_ADAPTER *ioc, u32 pa)
{
	MPT_FRAME_HDR	*mf;
	MPT_FRAME_HDR	*mr;
	int		 req_idx;
	int		 cb_idx;
	int		 freeme;

	u32 reply_dma_low;
	u16 ioc_stat;
#ifdef MPT_DEBUG_REPLY
	u8  function;
	MPT_FRAME_HDR *chain;
	int chain_idx, chain_number, next;
#endif


	/* non-TURBO reply!  Hmmm, something may be up...
	 *  Newest turbo reply mechanism; get address
	 *  via left shift 1 (get rid of MPI_ADDRESS_REPLY_A_BIT)!
	 */

	/* Map DMA address of reply header to cpu address.
	 * pa is 32 bits - but the dma address may be 32 or 64 bits
	 * get offset based only only the low addresses
	 */

	reply_dma_low = (pa <<= 1);
	mr = (MPT_FRAME_HDR *)((u8 *)ioc->reply_frames +
			 (reply_dma_low - ioc->reply_frames_low_dma));

	req_idx = le16_to_cpu(mr->u.frame.hwhdr.msgctxu.fld.req_idx);
	cb_idx = mr->u.frame.hwhdr.msgctxu.fld.cb_idx;
	mf = MPT_INDEX_2_MFPTR(ioc, req_idx);

	ioc_stat = le16_to_cpu(mr->u.reply.IOCStatus);
#ifdef MPT_DEBUG_REPLY
	if ((ioc_stat != MPI_IOCSTATUS_SCSI_DEVICE_NOT_THERE) && /* 0x0043 */
	    (ioc_stat != MPI_IOCSTATUS_SCSI_DATA_UNDERRUN)) {    /* 0x0045 */
		function = mr->u.hdr.Function;
		dreplyprintk((MYIOC_s_WARN_FMT "non-TURBO reply context=%04x%04x Function=%x IOCStatus=%04x\n",
			ioc->name, cb_idx, req_idx, function, ioc_stat));
		DBG_DUMP_REPLY_FRAME(mr)
	
		if ((function != MPI_FUNCTION_EVENT_NOTIFICATION) ||
			((((EventNotificationReply_t *)mr)->MsgFlags & MPI_MSGFLAGS_CONTINUATION_REPLY) == 0)) {
			printk("Request: mf=%p\n", mf);
			DBG_DUMP_REPLYS_REQUEST_FRAME(ioc, mf)
			chain_number = 1;
			chain_idx = ioc->ReqToChain[req_idx];
			while (chain_idx != MPT_HOST_NO_CHAIN) {
				next = ioc->ChainToChain[chain_idx];
				chain = (MPT_FRAME_HDR *) (ioc->ChainBuffer
					+ (chain_idx * ioc->req_sz));
				printk("Chain %d:\n", chain_number++);
				DBG_DUMP_REPLYS_REQUEST_FRAME(ioc, chain)
				chain_idx = next;
			}
		}
	}
#endif

	 /*  Check/log IOC log info
	 */
	if (ioc_stat & MPI_IOCSTATUS_FLAG_LOG_INFO_AVAILABLE) {
		u32	 log_info = le32_to_cpu(mr->u.reply.IOCLogInfo);
		if (ioc->bus_type == FC)
			mpt_fc_log_info(ioc, log_info);
		else if (ioc->bus_type == SPI)
			mpt_spi_log_info(ioc, log_info);
		else if (ioc->bus_type == SAS) {
			printk(MYIOC_s_INFO_FMT
				"IOCStatus=%04x LogInfo=%08x\n",
				ioc->name, ioc_stat, log_info);
			mpt_sas_log_info(ioc, log_info);
		}
	}
	if (ioc_stat & MPI_IOCSTATUS_MASK) {
		if (ioc->bus_type == SPI &&
		    cb_idx != mpt_stm_index &&
		    cb_idx != mpt_lan_index)
			mpt_sp_ioc_info(ioc, (u32)ioc_stat, mf);
	}


	/*  Check for (valid) IO callback!  */
	if (cb_idx < 1 || cb_idx >= MPT_MAX_PROTOCOL_DRIVERS ||
			MptCallbacks[cb_idx] == NULL) {
		printk(MYIOC_s_WARN_FMT "%s: Invalid cb_idx (%d)!\n",
				__FUNCTION__, ioc->name, cb_idx);
		freeme = 0;
		goto out;
	}

	freeme = MptCallbacks[cb_idx](ioc, mf, mr);

 out:
	/*  Flush (non-TURBO) reply with a WRITE!  */
	CHIPREG_WRITE32(&ioc->chip->ReplyFifo, pa);

	if (freeme)
		mpt_free_msg_frame(ioc, mf);
	mb();

	if (ioc->CheckFcLinkSpeed &&
	    ioc->FcLinkSpeedCheckNeeded &&
	    ioc->FcLinkSpeedReqActive == NULL &&
	    (mf = mpt_get_msg_frame(mpt_base_index, ioc))) {
		pConfig_t	pConfigMsg;
		dma_addr_t	physAddr;

		ioc->FcLinkSpeedCheckNeeded = 0;
		ioc->FcLinkSpeedReqActive = mf;
		pConfigMsg = (pConfig_t)mf;
		/* there's enough room, so FCPortPage0 will be put in the mf */
		physAddr = ioc->req_frames_dma + sizeof(pConfig_t) +
			(u8 *)mf - (u8 *)ioc->req_frames;
		memset(pConfigMsg, 0, ioc->req_sz);
		pConfigMsg->Action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
		pConfigMsg->Function = MPI_FUNCTION_CONFIG;
		pConfigMsg->Header.PageType = MPI_CONFIG_PAGETYPE_FC_PORT;
		pConfigMsg->Header.PageNumber = 0;
		pConfigMsg->Header.PageLength = sizeof(FCPortPage0_t) / 4;
		pConfigMsg->Header.PageVersion = MPI_FCPORTPAGE0_PAGEVERSION;
		ioc->add_sge((char *)&pConfigMsg->PageBufferSGE,
			MPT_SGE_FLAGS_SSIMPLE_READ + sizeof(FCPortPage0_t),
			physAddr);
		mpt_put_msg_frame(mpt_base_index, ioc, mf);
        }
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_interrupt - MPT adapter (IOC) specific interrupt handler.
 *	@irq: irq number (not used)
 *	@bus_id: bus identifier cookie == pointer to MPT_ADAPTER structure
 *	@r: pt_regs pointer (not used)
 *
 *	This routine is registered via the request_irq() kernel API call,
 *	and handles all interrupts generated from a specific MPT adapter
 *	(also referred to as a IO Controller or IOC).
 *	This routine must clear the interrupt from the adapter and does
 *	so by reading the reply FIFO.  Multiple replies may be processed
 *	per single call to this routine.
 *
 *	This routine handles register-level access of the adapter but
 *	dispatches (calls) a protocol-specific callback routine to handle
 *	the protocol-specific details of the MPT request completion.
 */
static irqreturn_t
mpt_interrupt(int irq, void *bus_id, struct pt_regs *r)
{
	MPT_ADAPTER *ioc = bus_id;
	u32 pa = CHIPREG_READ32_dmasync(&ioc->chip->ReplyFifo);

	if (pa == 0xFFFFFFFF)
		return IRQ_HANDLED;

	/*
	 *  Drain the reply FIFO!
	 */
	do {
	    if (pa & MPI_ADDRESS_REPLY_A_BIT)
		mpt_reply(ioc, pa);
	    else
		mpt_turbo_reply(ioc, pa);
	    pa = CHIPREG_READ32_dmasync(&ioc->chip->ReplyFifo);
	} while (pa != 0xFFFFFFFF);

	return IRQ_HANDLED;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_base_reply - MPT base driver's callback routine; all base driver
 *	"internal" request/reply processing is routed here.
 *	Currently used for EventNotification and EventAck handling.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@mf: Pointer to original MPT request frame
 *	@reply: Pointer to MPT reply frame (NULL if TurboReply)
 *
 *	Returns 1 indicating original alloc'd request frame ptr
 *	should be freed, or 0 if it shouldn't.
 */
static int
mpt_base_reply(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf, MPT_FRAME_HDR *reply)
{
	int freereq = 1;
	u8 func;

	func = reply->u.hdr.Function;

	if (func == MPI_FUNCTION_EVENT_NOTIFICATION) {
		EventNotificationReply_t *pEvReply = (EventNotificationReply_t *) reply;
		int evHandlers = 0;
		int results;

		results = ProcessEventNotification(ioc, pEvReply, &evHandlers);
		if (results != evHandlers) {
			/* CHECKME! Any special handling needed here? */
			devtprintk((MYIOC_s_WARN_FMT "Called %d event handlers, sum results = %d\n",
					ioc->name, evHandlers, results));
		}

		/*
		 *	EventNotificationReply is an exception
		 *	to the rule of one reply per request.
		 */
		if (pEvReply->MsgFlags & MPI_MSGFLAGS_CONTINUATION_REPLY) {
			freereq = 0;
		} else {
			devtprintk((MYIOC_s_WARN_FMT "EVENT_NOTIFICATION reply %p returns mf=%p evnp=%p\n",
				ioc->name, pEvReply, mf, ioc->evnp));
			if ( (MPT_FRAME_HDR *)ioc->evnp == mf ) {
				ioc->evnp = NULL;
			}
		}
		devtprintk((MYIOC_s_WARN_FMT "EVENT_NOTIFICATION reply %p freereq=%d\n",
				ioc->name, pEvReply, freereq));

#ifdef CONFIG_PROC_FS
//		LogEvent(ioc, pEvReply);
#endif

	} else if (func == MPI_FUNCTION_EVENT_ACK) {
		devtprintk((MYIOC_s_INFO_FMT "mpt_base_reply, EventAck reply received\n",
				ioc->name));
	} else if (func == MPI_FUNCTION_CONFIG ) {
		CONFIGPARMS *pCfg;
		unsigned long flags;

		dcprintk((MYIOC_s_INFO_FMT "config_complete (mf=%p,mr=%p)\n",
				ioc->name, mf, reply));

		pCfg = * ((CONFIGPARMS **)((u8 *) mf + ioc->req_sz - sizeof(void *)));

		if (pCfg) {
			/* disable timer and remove from linked list */
			del_timer(&pCfg->timer);

			spin_lock_irqsave(&ioc->FreeQlock, flags);
			list_del(&pCfg->linkage);
			spin_unlock_irqrestore(&ioc->FreeQlock, flags);

			/*
			 *	If IOC Status is SUCCESS, save the header
			 *	and set the status code to GOOD.
			 */
			pCfg->status = MPT_CONFIG_ERROR;
			if (reply) {
				ConfigReply_t	*pReply = (ConfigReply_t *)reply;
				u16		 status;

				status = le16_to_cpu(pReply->IOCStatus) & MPI_IOCSTATUS_MASK;
				dcprintk((KERN_NOTICE "  IOCStatus=%04xh, IOCLogInfo=%08xh\n",
				     status, le32_to_cpu(pReply->IOCLogInfo)));

				pCfg->status = status;
				if (status == MPI_IOCSTATUS_SUCCESS) {
					if ((pReply->Header.PageType &
					    MPI_CONFIG_PAGETYPE_MASK) ==
					    MPI_CONFIG_PAGETYPE_EXTENDED) {
						pCfg->cfghdr.ehdr->ExtPageLength =
						    le16_to_cpu(pReply->ExtPageLength);
						pCfg->cfghdr.ehdr->ExtPageType =
						    pReply->ExtPageType;
					}
					pCfg->cfghdr.hdr->PageVersion = pReply->Header.PageVersion;

					/* If this is a regular header, save PageLength. */
					/* LMP Do this better so not using a reserved field! */
					pCfg->cfghdr.hdr->PageLength = pReply->Header.PageLength;
					pCfg->cfghdr.hdr->PageNumber = pReply->Header.PageNumber;
					pCfg->cfghdr.hdr->PageType = pReply->Header.PageType;
				}
			}

			/*
			 *	Wake up the original calling thread
			 */
			pCfg->wait_done = 1;
			wake_up(&mpt_waitq);
		} else if (mf == ioc->FcLinkSpeedReqActive) {
			pFCPortPage0_t	pFCPortPage0 = (pFCPortPage0_t)((u8 *)mf + sizeof(pConfig_t));
			u8		OldSpeed = ioc->FcLinkSpeed;
			u8		NewSpeed = pFCPortPage0->CurrentSpeed;
			u8		State = pFCPortPage0->PortState;

			ioc->FcLinkSpeedReqActive = NULL;
			if (State != MPI_FCPORTPAGE0_PORTSTATE_OFFLINE &&
			    NewSpeed != MPI_FCPORTPAGE0_CURRENT_SPEED_UKNOWN) {
				char	*old;
				char	*new;

				old = OldSpeed == MPI_FCPORTPAGE0_CURRENT_SPEED_1GBIT ? "1 Gbps" :
				       OldSpeed == MPI_FCPORTPAGE0_CURRENT_SPEED_2GBIT ? "2 Gbps" :
					OldSpeed == MPI_FCPORTPAGE0_CURRENT_SPEED_4GBIT ? "4 Gbps" :
					 "Unknown";
				new = NewSpeed == MPI_FCPORTPAGE0_CURRENT_SPEED_1GBIT ? "1 Gbps" :
				       NewSpeed == MPI_FCPORTPAGE0_CURRENT_SPEED_2GBIT ? "2 Gbps" :
					NewSpeed == MPI_FCPORTPAGE0_CURRENT_SPEED_4GBIT ? "4 Gbps" :
					 "Unknown";
				if (OldSpeed == 0) {
					printk(MYIOC_s_NOTE_FMT
						"FC Link Established, Speed = %s\n",
						ioc->name, new);
				} else if (OldSpeed != NewSpeed) {
					printk(MYIOC_s_WARN_FMT
						"FC Link Speed Change, Old Speed = %s, New Speed = %s\n",
						ioc->name, old, new);
				}

				ioc->FcLinkSpeed = NewSpeed;
			}
		}
	} else if (func == MPI_FUNCTION_SAS_IO_UNIT_CONTROL) {
		/* we should be always getting a reply frame */
		memcpy(ioc->persist_reply_frame, reply,
		    min(MPT_DEFAULT_FRAME_SIZE,
		    4*reply->u.reply.MsgLength));
		del_timer(&ioc->persist_timer);
		ioc->persist_wait_done = 1;
		wake_up(&mpt_waitq);
	} else {
		printk(MYIOC_s_ERR_FMT "Unexpected msg function (=%02Xh) reply received!\n",
				ioc->name, func);
	}

	/*
	 *	Conditionally tell caller to free the original
	 *	EventNotification/EventAck/unexpected request frame!
	 */
	return freereq;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_register - Register protocol-specific main callback handler.
 *	@cbfunc: callback function pointer
 *	@dclass: Protocol driver's class (%MPT_DRIVER_CLASS enum value)
 *
 *	This routine is called by a protocol-specific driver (SCSI host,
 *	LAN, SCSI target) to register it's reply callback routine.  Each
 *	protocol-specific driver must do this before it will be able to
 *	use any IOC resources, such as obtaining request frames.
 *
 *	NOTES: The SCSI protocol driver currently calls this routine thrice
 *	in order to register separate callbacks; one for "normal" SCSI IO;
 *	one for MptScsiTaskMgmt requests; one for Scan/DV requests.
 *
 *	Returns a positive integer valued "handle" in the
 *	range (and S.O.D. order) {N,...,7,6,5,...,1} if successful.
 *	Any non-positive return value (including zero!) should be considered
 *	an error by the caller.
 */
int
mpt_register(MPT_CALLBACK cbfunc, MPT_DRIVER_CLASS dclass)
{
	int i;

	last_drv_idx = -1;

	/*
	 *  Search for empty callback slot in this order: {N,...,7,6,5,...,1}
	 *  (slot/handle 0 is reserved!)
	 */
	for (i = MPT_MAX_PROTOCOL_DRIVERS-1; i; i--) {
		if (MptCallbacks[i] == NULL) {
			MptCallbacks[i] = cbfunc;
			MptDriverClass[i] = dclass;
			MptEvHandlers[i] = NULL;
			last_drv_idx = i;
			break;
		}
	}

	return last_drv_idx;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_deregister - Deregister a protocol drivers resources.
 *	@cb_idx: previously registered callback handle
 *
 *	Each protocol-specific driver should call this routine when it's
 *	module is unloaded.
 */
void
mpt_deregister(int cb_idx)
{
	if ((cb_idx >= 0) && (cb_idx < MPT_MAX_PROTOCOL_DRIVERS)) {
		MptCallbacks[cb_idx] = NULL;
		MptDriverClass[cb_idx] = MPTUNKNOWN_DRIVER;
		MptEvHandlers[cb_idx] = NULL;

		last_drv_idx++;
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_event_register - Register protocol-specific event callback
 *	handler.
 *	@cb_idx: previously registered (via mpt_register) callback handle
 *	@ev_cbfunc: callback function
 *
 *	This routine can be called by one or more protocol-specific drivers
 *	if/when they choose to be notified of MPT events.
 *
 *	Returns 0 for success.
 */
int
mpt_event_register(int cb_idx, MPT_EVHANDLER ev_cbfunc)
{
	if (cb_idx < 1 || cb_idx >= MPT_MAX_PROTOCOL_DRIVERS)
		return -1;

	MptEvHandlers[cb_idx] = ev_cbfunc;
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_event_deregister - Deregister protocol-specific event callback
 *	handler.
 *	@cb_idx: previously registered callback handle
 *
 *	Each protocol-specific driver should call this routine
 *	when it does not (or can no longer) handle events,
 *	or when it's module is unloaded.
 */
void
mpt_event_deregister(int cb_idx)
{
	if (cb_idx < 1 || cb_idx >= MPT_MAX_PROTOCOL_DRIVERS)
		return;

	MptEvHandlers[cb_idx] = NULL;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_reset_register - Register protocol-specific IOC reset handler.
 *	@cb_idx: previously registered (via mpt_register) callback handle
 *	@reset_func: reset function
 *
 *	This routine can be called by one or more protocol-specific drivers
 *	if/when they choose to be notified of IOC resets.
 *
 *	Returns 0 for success.
 */
int
mpt_reset_register(int cb_idx, MPT_RESETHANDLER reset_func)
{
	if (cb_idx < 1 || cb_idx >= MPT_MAX_PROTOCOL_DRIVERS)
		return -1;

	MptResetHandlers[cb_idx] = reset_func;
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_reset_deregister - Deregister protocol-specific IOC reset handler.
 *	@cb_idx: previously registered callback handle
 *
 *	Each protocol-specific driver should call this routine
 *	when it does not (or can no longer) handle IOC reset handling,
 *	or when it's module is unloaded.
 */
void
mpt_reset_deregister(int cb_idx)
{
	if (cb_idx < 1 || cb_idx >= MPT_MAX_PROTOCOL_DRIVERS)
		return;

	MptResetHandlers[cb_idx] = NULL;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_device_driver_register - Register device driver hooks
 */
int
mpt_device_driver_register(struct mpt_pci_driver * dd_cbfunc, int cb_idx)
{
	MPT_ADAPTER	*ioc;

	if (cb_idx < 1 || cb_idx >= MPT_MAX_PROTOCOL_DRIVERS) {
		return -EINVAL;
	}

	MptDeviceDriverHandlers[cb_idx] = dd_cbfunc;

	/* call per pci device probe entry point */
	list_for_each_entry(ioc, &ioc_list, list) {
		if(dd_cbfunc->probe) {
			dd_cbfunc->probe(ioc->pcidev,
			  ioc->pcidev->driver->id_table);
  		}
	 }

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_device_driver_deregister - DeRegister device driver hooks
 */
void
mpt_device_driver_deregister(int cb_idx)
{
	struct mpt_pci_driver *dd_cbfunc;
	MPT_ADAPTER	*ioc;

	if (cb_idx < 1 || cb_idx >= MPT_MAX_PROTOCOL_DRIVERS)
		return;

	dd_cbfunc = MptDeviceDriverHandlers[cb_idx];

	list_for_each_entry(ioc, &ioc_list, list) {
		if (dd_cbfunc->remove)
			dd_cbfunc->remove(ioc->pcidev);
	}

	MptDeviceDriverHandlers[cb_idx] = NULL;
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_get_msg_frame - Obtain a MPT request frame from the pool (of 1024)
 *	allocated per MPT adapter.
 *	@handle: Handle of registered MPT protocol driver
 *	@ioc: Pointer to MPT adapter structure
 *
 *	Returns pointer to a MPT request frame or %NULL if none are available
 *	or IOC is not active.
 */
MPT_FRAME_HDR*
mpt_get_msg_frame(int handle, MPT_ADAPTER *ioc)
{
	MPT_FRAME_HDR *mf;
#ifdef MPT_DEBUG_FAIL
	u8	*mem;
#endif
	unsigned long flags;
	u16	 req_idx;	/* Request index */

	/* validate handle and ioc identifier */
	if (!ioc->active) {
#ifdef MFCNT
		printk(KERN_WARNING "IOC Not Active! mpt_get_msg_frame!!\n");
#endif
		return NULL;
	}

	spin_lock_irqsave(&ioc->FreeQlock, flags);
	if (!list_empty(&ioc->FreeQ)) {
		int req_offset;

		mf = list_entry(ioc->FreeQ.next, MPT_FRAME_HDR,
				u.frame.linkage.list);
		list_del(&mf->u.frame.linkage.list);
		mf->u.frame.linkage.arg1 = 0;
		mf->u.frame.hwhdr.msgctxu.fld.cb_idx = handle;	/* byte */
		req_offset = (u8 *)mf - (u8 *)ioc->req_frames;
								/* u16! */
		req_idx = req_offset / ioc->req_sz;
		mf->u.frame.hwhdr.msgctxu.fld.req_idx = cpu_to_le16(req_idx);
		mf->u.frame.hwhdr.msgctxu.fld.rsvd = 0;
		ioc->RequestNB[req_idx] = ioc->NB_for_64_byte_frame; /* Default, will be changed if necessary in SG generation */
#ifdef MFCNT
		ioc->mfcnt++;
#endif
	} else {
#ifdef MPT_DEBUG_FAIL
		dfailprintk((MYIOC_s_WARN_FMT "%s, No Free Message Frame!!\n",
		    ioc->name,__FUNCTION__));
		mem = (u8 *) ioc->req_frames;
		for (req_idx = 0; req_idx < 10; req_idx++) {
	{
		u32 	*m = (u32 *)(mem);
		int	 ii, n;

		printk(KERN_WARNING MYNAM ": %s: msg frame %d @ %p:\n" KERN_INFO " ",
				ioc->name, req_idx, m);
		n = ioc->req_sz/4;
		for (ii=0; ii<n; ii++) {
			if (ii && ((ii%8)==0))
				printk("\n");
			printk("%08x ", le32_to_cpu(m[ii]));
		}
		printk("\n");
	}
			mem += ioc->req_sz;
		}

//		panic ("No free Message Frame!!!!!\n");
#endif
		mf = NULL;
	}
	spin_unlock_irqrestore(&ioc->FreeQlock, flags);

#ifdef MFCNT
	if (mf == NULL)
		printk(KERN_WARNING "IOC Active. No free Msg Frames! Count 0x%x Max 0x%x\n", ioc->mfcnt, ioc->req_depth);
	mfcounter++;
	if (mfcounter == PRINT_MF_COUNT)
		printk(KERN_INFO "MF Count 0x%x Max 0x%x \n", ioc->mfcnt, ioc->req_depth);
#endif

	return mf;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_put_msg_frame - Send a protocol specific MPT request frame
 *	to a IOC.
 *	@handle: Handle of registered MPT protocol driver
 *	@ioc: Pointer to MPT adapter structure
 *	@mf: Pointer to MPT request frame
 *
 *	This routine posts a MPT request frame to the request post FIFO of a
 *	specific MPT adapter.
 */
void
mpt_put_msg_frame(int handle, MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf)
{
	u32 mf_dma_addr;
	int req_offset;
	u16	 req_idx;	/* Request index */

	/* ensure values are reset properly! */
	mf->u.frame.hwhdr.msgctxu.fld.cb_idx = handle;		/* byte */
	req_offset = (u8 *)mf - (u8 *)ioc->req_frames;
								/* u16! */
	req_idx = req_offset / ioc->req_sz;
	mf->u.frame.hwhdr.msgctxu.fld.req_idx = cpu_to_le16(req_idx);
	mf->u.frame.hwhdr.msgctxu.fld.rsvd = 0;

	mf_dma_addr = (ioc->req_frames_low_dma + req_offset) | ioc->RequestNB[req_idx]; 
	dsgprintk((MYIOC_s_INFO_FMT "mf_dma_addr=%x req_idx=%d RequestNB=%x\n", ioc->name, mf_dma_addr, req_idx, ioc->RequestNB[req_idx]));
	CHIPREG_WRITE32(&ioc->chip->RequestFifo, mf_dma_addr);
}

/**
 *	mpt_put_msg_frame_hi_pri - Send a protocol specific MPT request frame
 *	to a IOC using hi priority request queue.
 *	@handle: Handle of registered MPT protocol driver
 *	@ioc: Pointer to MPT adapter structure
 *	@mf: Pointer to MPT request frame
 *
 *	This routine posts a MPT request frame to the request post FIFO of a
 *	specific MPT adapter.
 **/
static void
mpt_put_msg_frame_hi_pri(int handle, MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf) {
	u32 mf_dma_addr;
	int req_offset;
	u16	 req_idx;	/* Request index */

	/* ensure values are reset properly! */
	mf->u.frame.hwhdr.msgctxu.fld.cb_idx = handle;
	req_offset = (u8 *)mf - (u8 *)ioc->req_frames;
	req_idx = req_offset / ioc->req_sz;
	mf->u.frame.hwhdr.msgctxu.fld.req_idx = cpu_to_le16(req_idx);
	mf->u.frame.hwhdr.msgctxu.fld.rsvd = 0;

	mf_dma_addr = (ioc->req_frames_low_dma + req_offset);
	dsgprintk((MYIOC_s_DEBUG_FMT "mf_dma_addr=%x req_idx=%d\n",
		ioc->name, mf_dma_addr, req_idx));
	CHIPREG_WRITE32(&ioc->chip->RequestHiPriFifo, mf_dma_addr);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_free_msg_frame - Place MPT request frame back on FreeQ.
 *	@handle: Handle of registered MPT protocol driver
 *	@ioc: Pointer to MPT adapter structure
 *	@mf: Pointer to MPT request frame
 *
 *	This routine places a MPT request frame back on the MPT adapter's
 *	FreeQ.
 */
void
mpt_free_msg_frame(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf)
{
	unsigned long flags;

	/*  Put Request back on FreeQ!  */
	spin_lock_irqsave(&ioc->FreeQlock, flags);
	mf->u.frame.linkage.arg1 = 0xdeadbeaf; /* signature to know if this mf is freed */
	list_add_tail(&mf->u.frame.linkage.list, &ioc->FreeQ);
#ifdef MFCNT
	ioc->mfcnt--;
#endif
	spin_unlock_irqrestore(&ioc->FreeQlock, flags);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_freeChainBuffers - Function to free chain buffers associated
 *	with a SCSI IO request
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@req_idx: Index of the SCSI IO request frame.
 *
 *	Called if SG chain buffer allocation fails and mptscsih callbacks.
 *	No return.
 */
void
mpt_freeChainBuffers(MPT_ADAPTER *ioc, int req_idx)
{
	MPT_FRAME_HDR *chain;
	unsigned long flags;
	int chain_idx;
	int next;

	/* Get the first chain index and reset
	 * tracker state.
	 */
	chain_idx = ioc->ReqToChain[req_idx];
	ioc->ReqToChain[req_idx] = MPT_HOST_NO_CHAIN;

	while (chain_idx != MPT_HOST_NO_CHAIN) {

		/* Save the next chain buffer index */
		next = ioc->ChainToChain[chain_idx];

		/* Free this chain buffer and reset
		 * tracker
		 */
		ioc->ChainToChain[chain_idx] = MPT_HOST_NO_CHAIN;

		chain = (MPT_FRAME_HDR *) (ioc->ChainBuffer
					+ (chain_idx * ioc->req_sz));
		spin_lock_irqsave(&ioc->FreeQlock, flags);
		list_add_tail(&chain->u.frame.linkage.list, &ioc->FreeChainQ);
		spin_unlock_irqrestore(&ioc->FreeQlock, flags);

		/* handle next */
		chain_idx = next;
	}
	return;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_add_sge - Place a simple u32 SGE at address pAddr.
 *	@pAddr: virtual address for SGE
 *	@flagslength: SGE flags and data transfer length
 *	@dma_addr: Physical address
 *
 */
void
mpt_add_sge(char *pAddr, u32 flagslength, dma_addr_t dma_addr)
{
	SGESimple32_t *pSge = (SGESimple32_t *) pAddr;
	pSge->FlagsLength = cpu_to_le32(flagslength);
	pSge->Address = cpu_to_le32(dma_addr);
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_add_sge_64bit - Place a simple u64 SGE at address pAddr.
 *	@pAddr: virtual address for SGE
 *	@flagslength: SGE flags and data transfer length
 *	@dma_addr: Physical address
 *
 */
void
mpt_add_sge_64bit(char *pAddr, u32 flagslength, dma_addr_t dma_addr)
{
	SGESimple64_t *pSge = (SGESimple64_t *) pAddr;
	u32 tmp = dma_addr & 0xFFFFFFFF;

	pSge->FlagsLength = cpu_to_le32(
		(flagslength | MPT_SGE_FLAGS_64_BIT_ADDRESSING));
	pSge->Address.Low = cpu_to_le32(tmp);
	tmp = (u32) ((u64)dma_addr >> 32);
	pSge->Address.High = cpu_to_le32(tmp);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_add_sge_64bit_1078 - Place a simple u64 SGE at address pAddr for
 *	the 1078.
 *	@pAddr: virtual address for SGE
 *	@flagslength: SGE flags and data transfer length
 *	@dma_addr: Physical address
 *
 */
void
mpt_add_sge_64bit_1078(char *pAddr, u32 flagslength, dma_addr_t dma_addr)
{
	SGESimple64_t *pSge = (SGESimple64_t *) pAddr;
	u32 tmp;

	tmp = dma_addr & 0xFFFFFFFF;
	pSge->Address.Low = cpu_to_le32(tmp);
	tmp = (u32) ((u64)dma_addr >> 32);

	/*
	 * 1078 errata workaround for the 36GB limitation
	 */
	if ( (((u64)dma_addr + MPI_SGE_LENGTH(flagslength)) >> 32)  == 9) {
		flagslength |=
		    MPI_SGE_SET_FLAGS(MPI_SGE_FLAGS_LOCAL_ADDRESS);
		tmp |= (1<<31);
		d36GBprintk ((KERN_WARNING MYNAM ": 1078 36GB address hit flagslength=%x tmp=%x\n",
			flagslength, tmp));
	}

	pSge->FlagsLength = cpu_to_le32(
		(flagslength | MPT_SGE_FLAGS_64_BIT_ADDRESSING));
	pSge->Address.High = cpu_to_le32(tmp);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_add_chain - Place a chain SGE at address pAddr.
 *	@pAddr: virtual address for SGE
 *	@next: nextChainOffset value (u32's)
 *	@length: length of next SGL segment
 *	@dma_addr: Physical address
 *
 */
void
mpt_add_chain(char *pAddr, u8 next, u16 length, dma_addr_t dma_addr)
{
		SGEChain32_t *pChain = (SGEChain32_t *) pAddr;
		pChain->Length = cpu_to_le16(length);
		pChain->Flags = MPI_SGE_FLAGS_CHAIN_ELEMENT;
		pChain->NextChainOffset = next;
		pChain->Address = cpu_to_le32(dma_addr);
}

void
mpt_add_chain_64bit(char *pAddr, u8 next, u16 length, dma_addr_t dma_addr)
{
		SGEChain64_t *pChain = (SGEChain64_t *) pAddr;
		u32 tmp = dma_addr & 0xFFFFFFFF;

		pChain->Length = cpu_to_le16(length);
		pChain->Flags = (MPI_SGE_FLAGS_CHAIN_ELEMENT |
				 MPI_SGE_FLAGS_64_BIT_ADDRESSING);

		pChain->NextChainOffset = next;

		pChain->Address.Low = cpu_to_le32(tmp);
		tmp = (u32) ((u64)dma_addr >> 32);
		pChain->Address.High = cpu_to_le32(tmp);
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_send_special_message - Send MPT request via doorbell
 *	handshake method.
 *	@handle: Handle of registered MPT protocol driver
 *	@ioc: Pointer to MPT adapter structure
 *	@reqBytes: Size of the request in bytes
 *	@req: Pointer to MPT request frame
 *	@sleepFlag: Use schedule if CAN_SLEEP else use udelay.
 *
 *	This routine is used exclusively to send MptScsiTaskMgmt
 *	requests since they are required to be sent via doorbell handshake.
 *
 *	NOTE: It is the callers responsibility to byte-swap fields in the
 *	request which are greater than 1 byte in size.
 *
 *	Returns 0 for success, non-zero for failure.
 */
int
mpt_send_special_message(int handle, MPT_ADAPTER *ioc, int reqBytes, u32 *req, ulong timeout, int sleepFlag)
{
	MPT_FRAME_HDR *mf;
	u8	*req_as_bytes;
	int	ii, retval;


	mf = (MPT_FRAME_HDR*)req;
	if ((ioc->facts.IOCCapabilities & MPI_IOCFACTS_CAPABILITY_HIGH_PRI_Q) &&
	    (ioc->facts.MsgVersion >= MPI_VERSION_01_05)) {
		dtmprintk((KERN_WARNING MYNAM ": %s: send hi_priority mf=%p\n",
			ioc->name, mf));
		mpt_put_msg_frame_hi_pri(handle, ioc, mf);
		return 0;
	}

	dtmprintk((KERN_WARNING MYNAM ": %s: mpt_send_special_message reqBytes=%d\n",
		ioc->name, reqBytes));
	/*
	 * Emulate what mpt_put_msg_frame() does /wrt to sanity
	 * setting cb_idx/req_idx.  But ONLY if this request
	 * is in proper (pre-alloc'd) request buffer range...
	 */
	ii = MFPTR_2_MPT_INDEX(ioc,(MPT_FRAME_HDR*)req);
	if (ii >= 0 && ii < ioc->req_depth) {
		mf->u.frame.hwhdr.msgctxu.fld.req_idx = cpu_to_le16(ii);
		mf->u.frame.hwhdr.msgctxu.fld.cb_idx = handle;
	}

	retval = 0;
	ioc->tmPtr = (MPT_FRAME_HDR *)req;
	ioc->TMtimer.expires = jiffies + HZ*timeout;  /* seconds */
	add_timer(&ioc->TMtimer);

	/* Make sure there are no doorbells */
	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);

	CHIPREG_WRITE32(&ioc->chip->Doorbell,
			((MPI_FUNCTION_HANDSHAKE<<MPI_DOORBELL_FUNCTION_SHIFT) |
			 ((reqBytes/4)<<MPI_DOORBELL_ADD_DWORDS_SHIFT)));

	/* Wait for IOC doorbell int */
	if ((ii = WaitForDoorbellInt(ioc, 5, sleepFlag)) < 0) {
		retval = ii;
		goto mpt_send_special_message_failed;
	}

	/* Read doorbell and check for active bit */
	if (!(CHIPREG_READ32(&ioc->chip->Doorbell) & MPI_DOORBELL_ACTIVE)) {
		retval = -5;
		goto mpt_send_special_message_failed;
	}

	dtmprintk((KERN_WARNING MYNAM ": %s: mpt_send_special_message start, WaitCnt=%d\n",
		ioc->name, ii));

	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);

	if ((WaitForDoorbellAck(ioc, 5, sleepFlag)) < 0) {
		retval = -2;
		goto mpt_send_special_message_failed;
	}

	/* Send request via doorbell handshake */
	req_as_bytes = (u8 *) req;
	for (ii = 0; ii < reqBytes/4; ii++) {
		u32 word;

		word = ((req_as_bytes[(ii*4) + 0] <<  0) |
			(req_as_bytes[(ii*4) + 1] <<  8) |
			(req_as_bytes[(ii*4) + 2] << 16) |
			(req_as_bytes[(ii*4) + 3] << 24));
			dtmprintk((KERN_WARNING MYNAM ": %s: mpt_send_special_message word=%08x ii=%d\n",
		ioc->name, word, ii));
		CHIPREG_WRITE32(&ioc->chip->Doorbell, word);
		if (WaitForDoorbellAck(ioc, 5, sleepFlag) < 0) {
			retval = -3;
			goto mpt_send_special_message_failed;
		}
	}

	dtmprintk((KERN_WARNING MYNAM ": %s: mpt_send_special_message reqBytes=%d sent, WaitForDoorbellInt\n",
		ioc->name, reqBytes));
	if (WaitForDoorbellInt(ioc, 10, sleepFlag) < 0)
		retval = -4;

	/* Make sure there are no doorbells */
	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);

mpt_send_special_message_failed:
	if (retval) {
		del_timer(&ioc->TMtimer);
		ioc->tmPtr = NULL;
	}
	dtmprintk((KERN_WARNING MYNAM ": %s: mpt_send_special_message retval=%d\n",
		ioc->name, retval));
	return retval;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 * mpt_host_page_access_control - provides mechanism for the host
 * driver to control the IOC's Host Page Buffer access.
 * @ioc: Pointer to MPT adapter structure
 * @access_control_value: define bits below
 *
 * Access Control Value - bits[15:12]
 * 0h Reserved
 * 1h Enable Access { MPI_DB_HPBAC_ENABLE_ACCESS }
 * 2h Disable Access { MPI_DB_HPBAC_DISABLE_ACCESS }
 * 3h Free Buffer { MPI_DB_HPBAC_FREE_BUFFER }
 *
 * Returns 0 for success, non-zero for failure.
 */

static int
mpt_host_page_access_control(MPT_ADAPTER *ioc, u8 access_control_value, int sleepFlag)
{
	/* return if in use */
	if (CHIPREG_READ32(&ioc->chip->Doorbell)
	    & MPI_DOORBELL_ACTIVE)
	    return -1;

	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);

	CHIPREG_WRITE32(&ioc->chip->Doorbell,
		((MPI_FUNCTION_HOST_PAGEBUF_ACCESS_CONTROL
		 <<MPI_DOORBELL_FUNCTION_SHIFT) |
		 (access_control_value<<12)));

	/* Wait for IOC to clear Doorbell Status bit */
	if ((WaitForDoorbellAck(ioc, 5, sleepFlag)) < 0) {
		return -2;
	} else
		return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_host_page_alloc - allocate system memory for the fw
 *	If we already allocated memory in past, then resend the same pointer.
 *	ioc@: Pointer to pointer to IOC adapter
 *	ioc_init@: Pointer to ioc init config page
 *
 *	Returns 0 for success, non-zero for failure.
 */
static int
mpt_host_page_alloc(MPT_ADAPTER *ioc, pIOCInit_t ioc_init)
{
	char	*psge;
	int	flags_length;
	u32	host_page_buffer_sz=0;

	if(!ioc->HostPageBuffer) {

		host_page_buffer_sz =
		    le32_to_cpu(ioc->facts.HostPageBufferSGE.FlagsLength) & 0xFFFFFF;

		if(!host_page_buffer_sz)
			return 0; /* fw doesn't need any host buffers */

		/* spin till we get enough memory */
		while(host_page_buffer_sz > 0) {

			if((ioc->HostPageBuffer = pci_alloc_consistent(
			    ioc->pcidev,
			    host_page_buffer_sz,
			    &ioc->HostPageBuffer_dma)) != NULL) {

				dinitprintk((MYIOC_s_INFO_FMT
				    "host_page_buffer @ %p, dma @ %x, sz=%d bytes\n",
				    ioc->name,
				    ioc->HostPageBuffer,
				    (u32)ioc->HostPageBuffer_dma,
				    host_page_buffer_sz));
				ioc->alloc_total += host_page_buffer_sz;
				ioc->HostPageBuffer_sz = host_page_buffer_sz;
				break;
			}

			host_page_buffer_sz -= (4*1024);
		}
	}

	if(!ioc->HostPageBuffer) {
		printk(MYIOC_s_ERR_FMT
		    "Failed to alloc memory for host_page_buffer!\n",
		    ioc->name);
		return -999;
	}

	psge = (char *)&ioc_init->HostPageBufferSGE;
	flags_length = MPI_SGE_FLAGS_SIMPLE_ELEMENT |
	    MPI_SGE_FLAGS_SYSTEM_ADDRESS |
	    MPI_SGE_FLAGS_HOST_TO_IOC |
	    MPI_SGE_FLAGS_END_OF_BUFFER;
	flags_length = flags_length << MPI_SGE_FLAGS_SHIFT;
	flags_length |= ioc->HostPageBuffer_sz;
	ioc->add_sge(psge, flags_length, ioc->HostPageBuffer_dma);
	ioc->facts.HostPageBufferSGE = ioc_init->HostPageBufferSGE;

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_verify_adapter - Given a unique IOC identifier, set pointer to
 *	the associated MPT adapter structure.
 *	@iocid: IOC unique identifier (integer)
 *	@iocpp: Pointer to pointer to IOC adapter
 *
 *	Returns iocid and sets iocpp.
 */
int
mpt_verify_adapter(int iocid, MPT_ADAPTER **iocpp)
{
	MPT_ADAPTER *ioc;

	list_for_each_entry(ioc,&ioc_list,list) {
		if (ioc->id == iocid) {
			*iocpp =ioc;
			return iocid;
		}
	}

	*iocpp = NULL;
	return -1;
}

int
mpt_alt_ioc_wait(MPT_ADAPTER *ioc)
{
	int loop_count = 30 * 4;  /* Wait 30 seconds */
	int status = -1; /* -1 means failed to get board READY */

	do {
		spin_lock(&ioc->initializing_hba_lock);
		if (ioc->initializing_hba_lock_flag == 0) {
			ioc->initializing_hba_lock_flag=1;
			spin_unlock(&ioc->initializing_hba_lock);
			status = 0;
			break;
		}
		spin_unlock(&ioc->initializing_hba_lock);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ/4);
	} while (--loop_count);

	return status;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_bringup_adapter - This is a wrapper function for mpt_do_ioc_recovery
 *	@ioc: Pointer to MPT adapter structure
 *	@sleepFlag: Use schedule if CAN_SLEEP else use udelay.
 *
 *	This routine performs all the steps necessary to bring the IOC
 *	to a OPERATIONAL state.
 *
 *      Special Note: This function was added with spin lock's so as to allow
 *      the dv(domain validation) work thread to succeed on the other channel
 *      that maybe occuring at the same time when this function is called.
 *      Without this lock, the dv would fail when message frames were
 *      requested during hba bringup on the alternate ioc.
 */
static int
mpt_bringup_adapter(MPT_ADAPTER *ioc, int sleepFlag)
{
	int r;

	r = mpt_do_ioc_recovery(ioc, MPT_HOSTEVENT_IOC_BRINGUP,
	    CAN_SLEEP);

	return r;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_attach - Install a PCI intelligent MPT adapter.
 *	@pdev: Pointer to pci_dev structure
 *
 *	This routine performs all the steps necessary to bring the IOC of
 *	a MPT adapter to a OPERATIONAL state.  This includes registering
 *	memory regions, registering the interrupt, and allocating request
 *	and reply memory pools.
 *
 *	This routine also pre-fetches the LAN MAC address of a Fibre Channel
 *	MPT adapter.
 *
 *	Returns 0 for success, non-zero for failure.
 *
 *	TODO: Add support for polled controllers
 */
int
mpt_attach(struct pci_dev *pdev, const struct pci_device_id *id)
{
	MPT_ADAPTER	*ioc;
	int		 ii;
	int		 r = -ENODEV;
	u8		 pcixcmd;
	static int	 mpt_ids = 0;
	unsigned long flags;
	u8		 revision;
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *dent, *ent;
#endif

	if (pci_enable_device(pdev))
		return r;

	dinitprintk((KERN_INFO MYNAM ": %s entered\n", __FUNCTION__));
	pci_read_config_byte(pdev, PCI_CLASS_REVISION, &revision);


	ioc = kmalloc(sizeof(MPT_ADAPTER), GFP_ATOMIC);
	if (ioc == NULL) {
		printk(KERN_ERR MYNAM ": ERROR - Insufficient memory to add adapter!\n");
		return -ENOMEM;
	}
	memset(ioc, 0, sizeof(MPT_ADAPTER));
	ioc->alloc_total = sizeof(MPT_ADAPTER);
	ioc->req_sz = MPT_DEFAULT_FRAME_SIZE;		/* avoid div by zero! */
	ioc->reply_sz = MPT_REPLY_FRAME_SIZE;

	ioc->pcidev = pdev;
	if (mpt_mapresources(ioc)) {
		kfree(ioc);
		return r;
	}

	ioc->ioc_reset_in_progress = 0;
	ioc->diagPending = 0;
	spin_lock_init(&ioc->diagLock);
	spin_lock_init(&ioc->initializing_hba_lock);

	/* Initialize the event logging.
	 */
	ioc->eventTypes = 0;	/* None */
	ioc->eventContext = 0;
	ioc->events = NULL;

#ifdef MFCNT
	ioc->mfcnt = 0;
#endif

	ioc->cached_fw = NULL;

	for ( ii = 0; ii < MPI_DIAG_BUF_TYPE_COUNT; ii++) {
		ioc->DiagBuffer[ii] = NULL;
		ioc->DiagBuffer_Status[ii] = 0;
	}

	/* Initilize SCSI Config Data structure
	 */
	memset(&ioc->spi_data, 0, sizeof(SpiCfgData));

	/* Initialize the running configQ head.
	 */
	INIT_LIST_HEAD(&ioc->configQ);

	/* Find lookup slot. */
	INIT_LIST_HEAD(&ioc->list);
	ioc->id = mpt_ids++;

	ioc->deviceID = pdev->device;
	ioc->vendorID = pdev->vendor;

	if (ioc->dma_mask == DMA_64BIT_MASK) {
		ioc->add_sge = &mpt_add_sge_64bit;
		ioc->add_chain = &mpt_add_chain_64bit;
		ioc->sg_addr_size = 8;
		dinitprintk((MYIOC_s_WARN_FMT "add_sge is mpt_add_sge_64bit\n",
			ioc->name));
	} else {
		ioc->add_sge = &mpt_add_sge;
		ioc->add_chain = &mpt_add_chain;
		ioc->sg_addr_size = 4;
		dinitprintk((MYIOC_s_WARN_FMT "add_sge is 32 bit mpt_add_sge\n",
			ioc->name));
	}

	ioc->SGE_size = sizeof(u32) + ioc->sg_addr_size;

	if (pdev->device == MPI_MANUFACTPAGE_DEVICEID_FC909) {
		ioc->prod_name = "LSIFC909";
		ioc->bus_type = FC;
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVICEID_FC929) {
		ioc->prod_name = "LSIFC929";
		ioc->bus_type = FC;
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVICEID_FC919) {
		ioc->prod_name = "LSIFC919";
		ioc->bus_type = FC;
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVICEID_FC929X) {
		ioc->bus_type = FC;
		if (revision < XL_929) {
			ioc->prod_name = "LSIFC929X";
			/* 929X Chip Fix. Set Split transactions level
		 	* for PCIX. Set MOST bits to zero.
		 	*/
			pci_read_config_byte(pdev, 0x6a, &pcixcmd);
			pcixcmd &= 0x8F;
			pci_write_config_byte(pdev, 0x6a, pcixcmd);
		} else {
			ioc->prod_name = "LSIFC929XL";
			/* 929XL Chip Fix. Set MMRBC to 0x08.
		 	*/
			pci_read_config_byte(pdev, 0x6a, &pcixcmd);
			pcixcmd |= 0x08;
			pci_write_config_byte(pdev, 0x6a, pcixcmd);
		}
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVICEID_FC919X) {
		ioc->prod_name = "LSIFC919X";
		ioc->bus_type = FC;
		/* 919X Chip Fix. Set Split transactions level
		 * for PCIX. Set MOST bits to zero.
		 */
		pci_read_config_byte(pdev, 0x6a, &pcixcmd);
		pcixcmd &= 0x8F;
		pci_write_config_byte(pdev, 0x6a, pcixcmd);
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVICEID_FC939X) {
		ioc->prod_name = "LSIFC939X";
		ioc->bus_type = FC;
		ioc->errata_flag_1064 = 1;
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVICEID_FC949X) {
		ioc->prod_name = "LSIFC949X";
		ioc->bus_type = FC;
		ioc->errata_flag_1064 = 1;
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVICEID_FC949E) {
		ioc->bus_type = FC;
		if (pdev->vendor == 0x1657)
			ioc->prod_name = "   BRE040";
		else
			ioc->prod_name = "LSIFC949E";
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVID_53C1030) {
		ioc->prod_name = "LSI53C1030";
		ioc->bus_type = SPI;
		/* 1030 Chip Fix. Disable Split transactions
		 * for PCIX. Set MOST bits to zero if Rev < C0( = 8).
		 */
		if (revision < C0_1030) {
			pci_read_config_byte(pdev, 0x6a, &pcixcmd);
			pcixcmd &= 0x8F;
			pci_write_config_byte(pdev, 0x6a, pcixcmd);
		}
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVID_SAS1064) {
		ioc->prod_name = "LSISAS1064";
		ioc->bus_type = SAS;
		ioc->errata_flag_1064 = 1;
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVID_SAS1068) {
		ioc->prod_name = "LSISAS1068";
		ioc->bus_type = SAS;
		ioc->errata_flag_1064 = 1;
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVID_SAS1064E) {
		ioc->prod_name = "LSISAS1064E";
		ioc->bus_type = SAS;
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVID_SAS1068E) {
		ioc->prod_name = "LSISAS1068E";
		ioc->bus_type = SAS;
	}
	else if (pdev->device == MPI_MANUFACTPAGE_DEVID_SAS1078) {
		ioc->prod_name = "LSISAS1078";
		ioc->bus_type = SAS;
		if (ioc->dma_mask == DMA_64BIT_MASK) {
			ioc->add_sge = &mpt_add_sge_64bit_1078;
			dinitprintk((MYIOC_s_WARN_FMT "resetting add_sge to mpt_add_sge_64bit_1078\n", 
				ioc->name));
		}
	}

	if (ioc->bus_type == SAS)
		ioc->msi_enable = 1;
	else
		ioc->msi_enable = mpt_msi_enable;

	if(ioc->errata_flag_1064) {
		pci_disable_io_access(pdev);
	}

	if(ioc->bus_type == FC) {
		ioc->CheckFcLinkSpeed = 1;
		ioc->FcLinkSpeed = 0;
	}

	sprintf(ioc->name, "ioc%d", ioc->id);

	spin_lock_init(&ioc->FreeQlock);
	spin_lock_init(&ioc->PendingMFlock);
	spin_lock_init(&ioc->TargetResetlock);
	spin_lock_init(&ioc->HotPluglock);

	/* Disable all! */
	CHIPREG_WRITE32(&ioc->chip->IntMask, 0xFFFFFFFF);
	ioc->active = 0;
	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);

	/* Set lookup ptr. */
	list_add_tail(&ioc->list, &ioc_list);

	ioc->pci_irq = -1;
	if (pdev->irq) {

		if ((mpt_msi_enable == 1) &&
		    (pci_enable_msi(pdev)==0)) {
			printk(MYIOC_s_INFO_FMT
			    "PCI-MSI enabled for this hotplug controller\n",
			    ioc->name);
		}

		/* Installs the interrupt handler */
		r = request_irq(pdev->irq, mpt_interrupt, SA_SHIRQ, ioc->name, ioc);

		if (r < 0) {
#ifndef __sparc__
			printk(MYIOC_s_ERR_FMT "Unable to allocate interrupt %d!\n",
					ioc->name, pdev->irq);
#else
			printk(MYIOC_s_ERR_FMT "Unable to allocate interrupt %s!\n",
					ioc->name, __irq_itoa(pdev->irq));
#endif
			list_del(&ioc->list);
			iounmap(ioc->memmap);
			kfree(ioc);
			return -EBUSY;
		}

		ioc->pci_irq = pdev->irq;

		pci_set_master(pdev);			/* ?? */
		pci_set_drvdata(pdev, ioc);

#ifndef __sparc__
		dprintk((KERN_INFO MYNAM ": %s installed at interrupt %d\n", ioc->name, pdev->irq));
#else
		dprintk((KERN_INFO MYNAM ": %s installed at interrupt %s\n", ioc->name, __irq_itoa(pdev->irq)));
#endif
	}

	/* Check for "bound ports" (929, 929X, 1030, 1035) to reduce redundant resets.
	 */
	mpt_detect_bound_ports(ioc, pdev);
	
	if(mpt_enable_deadioc_detect){
		/* The following list initializations is moved from PrimeIocFifos
	   	because the lists will not get initialize for non-operational
	   	IOCs and which cause a crash when the lists are accessed later
		*/
		/* Initialize the free chain Q.*/

		INIT_LIST_HEAD(&ioc->FreeChainQ);

		spin_lock_irqsave(&ioc->FreeQlock, flags);
		INIT_LIST_HEAD(&ioc->FreeQ);
		spin_unlock_irqrestore(&ioc->FreeQlock, flags);
		
		init_MUTEX(&ioc->raid_data.inactive_list_mutex);
		INIT_LIST_HEAD(&ioc->raid_data.inactive_list);

		/* Even If there is any error in IOC bringup, the IOC is allowed to
	   	be attached with MPT drivers, This change is done to support
	   	Firmware download boot functionality for FW dead IOC */
		mpt_bringup_adapter(ioc, CAN_SLEEP);
	}
	else {
		if ((r = mpt_bringup_adapter(ioc, CAN_SLEEP)) != 0){
			printk(KERN_WARNING MYNAM
		  	": WARNING - %s did not initialize properly! (%d)\n",
		  	ioc->name, r);

			list_del(&ioc->list);
			free_irq(ioc->pci_irq, ioc);
			if (mpt_msi_enable == 1) {
				pci_disable_msi(pdev);
			}
			iounmap(ioc->memmap);
			kfree(ioc);
			pci_set_drvdata(pdev, NULL);
			return r;
		}
	}

	/* call per device driver probe entry point */
	for(ii=0; ii<MPT_MAX_PROTOCOL_DRIVERS; ii++) {
		if(MptDeviceDriverHandlers[ii] &&
		  MptDeviceDriverHandlers[ii]->probe) {
			MptDeviceDriverHandlers[ii]->probe(pdev,id);
		}
	}

#ifdef CONFIG_PROC_FS
	/*
	 *  Create "/proc/mpt/iocN" subdirectory entry for each MPT adapter.
	 */
	dent = proc_mkdir(ioc->name, mpt_proc_root_dir);
	if (dent) {
		ent = create_proc_entry("info", S_IFREG|S_IRUGO, dent);
		if (ent) {
			ent->read_proc = procmpt_iocinfo_read;
			ent->data = ioc;
		}
		ent = create_proc_entry("summary", S_IFREG|S_IRUGO, dent);
		if (ent) {
			ent->read_proc = procmpt_summary_read;
			ent->data = ioc;
		}
	}
#endif

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_detach - Remove a PCI intelligent MPT adapter.
 *	@pdev: Pointer to pci_dev structure
 *
 */
void
mpt_detach(struct pci_dev *pdev)
{
	MPT_ADAPTER 	*ioc = pci_get_drvdata(pdev);
	char pname[32];
	int ii;
#ifdef MPT_DEBUG_EXIT
	u32 doorbell;
#endif

	sprintf(pname, MPT_PROCFS_MPTBASEDIR "/%s/summary", ioc->name);
	remove_proc_entry(pname, NULL);
	sprintf(pname, MPT_PROCFS_MPTBASEDIR "/%s/info", ioc->name);
	remove_proc_entry(pname, NULL);
	sprintf(pname, MPT_PROCFS_MPTBASEDIR "/%s", ioc->name);
	remove_proc_entry(pname, NULL);

	/* call per device driver remove entry point */
	for(ii=0; ii<MPT_MAX_PROTOCOL_DRIVERS; ii++) {
		if(MptDeviceDriverHandlers[ii] &&
		  MptDeviceDriverHandlers[ii]->remove) {
			MptDeviceDriverHandlers[ii]->remove(pdev);
		}
	}

	/* Disable interrupts! */
	CHIPREG_WRITE32(&ioc->chip->IntMask, 0xFFFFFFFF);

	ioc->active = 0;
	synchronize_irq(pdev->irq);

	/* Clear any lingering interrupt */
	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);

	CHIPREG_READ32(&ioc->chip->IntStatus);

	/* put ioc into READY_STATE */
	if(mpt_SendIocReset(ioc, MPI_FUNCTION_IOC_MESSAGE_UNIT_RESET, CAN_SLEEP)) {
		printk(MYIOC_s_ERR_FMT
		"%s:  IOC msg unit reset failed!\n", ioc->name, __FUNCTION__);
	}

#ifdef MPT_DEBUG_EXIT
	doorbell = CHIPREG_READ32(&ioc->chip->Doorbell);
	if (doorbell == MPI_IOC_STATE_READY) {
		dexitprintk((MYIOC_s_INFO_FMT "IOC is in READY state after MUR at driver detach\n",
			ioc->name));
	} else {
		dexitprintk((MYIOC_s_INFO_FMT "Doorbell=%08x after MUR at driver detach\n",
			ioc->name, doorbell));
	}
#endif

	mpt_adapter_dispose(ioc);

	pci_set_drvdata(pdev, NULL);
}

/**************************************************************************
 * Power Management
 */
#ifdef CONFIG_PM
/**
 *	mpt_suspend - Fusion MPT base driver suspend routine.
 *	@pdev: Pointer to pci_dev structure
 *	@state: new state to enter
 **/
int
mpt_suspend(struct pci_dev *pdev, pm_message_t state)
{
	u32 device_state = pdev->current_state;
	MPT_ADAPTER *ioc = pci_get_drvdata(pdev);

	switch(state)
	{
		case 1: /* S1 */
			device_state=1; /* D1 */;
			break;
		case 3: /* S3 */
		case 4: /* S4 */
			device_state=3; /* D3 */;
			break;
		default:
			return -EAGAIN /*FIXME*/;
			break;
	}
	printk(MYIOC_s_INFO_FMT "pci-suspend: pdev=0x%p, slot=%s, Entering "
	    "operating state [D%d]\n", ioc->name, pdev, pci_name(pdev),
	    device_state);

	/* put ioc into READY_STATE */
	if(mpt_SendIocReset(ioc, MPI_FUNCTION_IOC_MESSAGE_UNIT_RESET, CAN_SLEEP)) {
		printk(MYIOC_s_ERR_FMT
		"pci-suspend:  IOC msg unit reset failed!\n", ioc->name);
	}

	/* disable interrupts */
	CHIPREG_WRITE32(&ioc->chip->IntMask, 0xFFFFFFFF);
	ioc->active = 0;
	/* Clear any lingering interrupt */
	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);

	free_irq(ioc->pci_irq, ioc);
	if (ioc->msi_enable)
		pci_disable_msi(ioc->pcidev);
	ioc->pci_irq = -1;
	pci_save_state(pdev, &ioc->PciState[0]);
	pci_disable_device(pdev);
	pci_set_power_state(pdev, state);
	return 0;
}

/**
 *	mpt_resume - Fusion MPT base driver resume routine.
 *	@pdev: Pointer to pci_dev structure
 **/
int
mpt_resume(struct pci_dev *pdev)
{
	MPT_ADAPTER *ioc = pci_get_drvdata(pdev);
	u32 device_state = pdev->current_state;
	int recovery_state;
	int err;

	printk(MYIOC_s_INFO_FMT "pci-resume: pdev=0x%p, slot=%s, Previous "
	    "operating state [D%d]\n", ioc->name, pdev, pci_name(pdev),
	    device_state);

	pci_set_power_state(pdev, PCI_D0);
	pci_enable_wake(pdev, PCI_D0, 0);
	pci_restore_state(pdev, &ioc->PciState[0]);
	ioc->pcidev = pdev;
	err = mpt_mapresources(ioc);
	if (err)
		return err;

	printk(MYIOC_s_INFO_FMT "pci-resume: ioc-state=0x%x,doorbell=0x%x\n",
	    ioc->name, (mpt_GetIocState(ioc, 1) >> MPI_IOC_STATE_SHIFT),
	    CHIPREG_READ32(&ioc->chip->Doorbell));

	/*
	 * Errata workaround for SAS pci express:
	 * Upon returning to the D0 state, the contents of the doorbell will be
	 * stale data, and this will incorrectly signal to the host driver
	 * to issue a diagnostic reset.
	 */
	if (ioc->bus_type == SAS && (pdev->device ==
	    MPI_MANUFACTPAGE_DEVID_SAS1068E || pdev->device ==
	    MPI_MANUFACTPAGE_DEVID_SAS1064E)) {
		if (KickStart(ioc, 1, CAN_SLEEP) < 0) {
			printk(MYIOC_s_WARN_FMT "pci-resume: Cannot recover\n",
			    ioc->name);
			goto out;
		}
	}

	/* bring ioc to operational state */
	printk(MYIOC_s_INFO_FMT "Sending mpt_do_ioc_recovery\n", ioc->name);
	if ((recovery_state = mpt_do_ioc_recovery(ioc, MPT_HOSTEVENT_IOC_BRINGUP, CAN_SLEEP)) != 0)
		printk(MYIOC_s_WARN_FMT "pci-resume: Cannot recover, "
		    "error:[%x]\n", ioc->name, recovery_state);
	else
		printk(MYIOC_s_INFO_FMT
		    "pci-resume: success\n", ioc->name);
 out:
	return 0;
}
#endif


/*
 *	mpt_flush_running_cmds - For each command found, search
 *		Scsi_Host instance taskQ and reply to OS.
 *		Called only if recovering from a FW reload.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *
 *	Returns: None.
 *
 */
static void
mpt_flush_running_cmds(MPT_ADAPTER *ioc)
{
	struct scsi_cmnd	*SCpnt;
	MPT_FRAME_HDR	*mf;
	int		 ii;
	int		 max = ioc->req_depth;

	drsprintk((MYIOC_s_WARN_FMT ": %s entered\n", 
		ioc->name, __FUNCTION__));
	if (ioc->ScsiLookup == NULL)
		return;
	for (ii= 0; ii < max; ii++) {
		if ((SCpnt = ioc->ScsiLookup[ii]) != NULL) {

			/* Command found.
			 */

			/* Null ScsiLookup index
			 */
			ioc->ScsiLookup[ii] = NULL;

			mf = MPT_INDEX_2_MFPTR(ioc, ii);

			drsprintk((MYIOC_s_WARN_FMT "flush mf=%p sc=%p\n",
		    		ioc->name, mf, SCpnt));
			DBG_DUMP_RESET_REQUEST_FRAME(ioc, mf)

			/* Free Chain buffers */
			mpt_freeChainBuffers(ioc, ii);

			/* Free Message frame */
			mpt_free_msg_frame(ioc, mf);

			if ((unsigned char *)mf != SCpnt->host_scribble) {
				drsprintk(( "%s Skipping scsi_done mf=%p host_scribble=%p\n",
					__FUNCTION__, mf, SCpnt->host_scribble));
				continue;
			}

			/* Set status, free OS resources (SG DMA buffers)
			 * Do OS callback
			 * Free driver resources (chain, msg buffers)
			 */
			if (SCpnt->use_sg) {
				pci_unmap_sg(ioc->pcidev,
					(struct scatterlist *) SCpnt->request_buffer,
					SCpnt->use_sg,
					SCpnt->sc_data_direction);
			} else if (SCpnt->request_bufflen) {
				pci_unmap_single(ioc->pcidev,
					SCpnt->SCp.dma_handle,
					SCpnt->request_bufflen,
					SCpnt->sc_data_direction);
			}
			SCpnt->result = (DID_BUS_BUSY << 16);
//			SCpnt->result = (DID_RESET << 16);
			SCpnt->host_scribble = NULL;
			SCpnt->scsi_done(SCpnt);	/* Issue the command callback */
		}
	}
	drsprintk((MYIOC_s_WARN_FMT ": %s exiting\n", 
		ioc->name, __FUNCTION__));
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_do_ioc_recovery - Initialize or recover MPT adapter.
 *	@ioc: Pointer to MPT adapter structure
 *	@reason: Event word / reason
 *	@sleepFlag: Use schedule if CAN_SLEEP else use udelay.
 *
 *	This routine performs all the steps necessary to bring the IOC
 *	to a OPERATIONAL state.
 *
 *	This routine also pre-fetches the LAN MAC address of a Fibre Channel
 *	MPT adapter.
 *
 *	Returns:
 *		 0 for success
 *		-1 if failed to get board READY
 *		-2 if READY but IOCFacts Failed
 *		-3 if READY but PrimeIOCFifos Failed
 *		-4 if READY but IOCInit Failed
 */
int
mpt_do_ioc_recovery(MPT_ADAPTER *ioc, u32 reason, int sleepFlag)
{
	unsigned long flags;
	int	 hard_reset_done = 0;
	int	 hard;
	int	 rc = 0;
	int	 ii;
	int	 ret = 0;

	printk(KERN_WARNING MYNAM ": Initiating %s %s\n",
			ioc->name, reason==MPT_HOSTEVENT_IOC_BRINGUP ? "bringup" : "recovery");

	/* Disable reply interrupts (also blocks FreeQ) */
	CHIPREG_WRITE32(&ioc->chip->IntMask, 0xFFFFFFFF);

	spin_lock_irqsave(&ioc->diagLock, flags);
	ioc->ioc_reset_in_progress = 1;
	spin_unlock_irqrestore(&ioc->diagLock, flags);

	mpt_flush_running_cmds(ioc);
	ioc->active = 0;

	/* If an event notification has not returned
	 * its request frame,
	 * free resources associated with this request.
	 */
	if (ioc->evnp) {
		drsprintk((MYIOC_s_WARN_FMT "do_ioc_recovery: freeing evnp=%p\n",
			   ioc->name, ioc->evnp));
		mpt_free_msg_frame(ioc, (MPT_FRAME_HDR *)ioc->evnp);
		ioc->evnp = NULL;
	}

	hard = 1;
	if (reason == MPT_HOSTEVENT_IOC_BRINGUP)
		hard = 0;

	if ((hard_reset_done = MakeIocReady(ioc, hard, sleepFlag)) < 0) {
		if (hard_reset_done == -4) {
			printk(KERN_WARNING MYNAM ": %s Owned by PEER..skipping!\n",
					ioc->name);
		} else {
			printk(KERN_WARNING MYNAM ": %s NOT READY WARNING!\n",
					ioc->name);
		}
		spin_lock_irqsave(&ioc->diagLock, flags);
		ioc->ioc_reset_in_progress = 0;
		spin_unlock_irqrestore(&ioc->diagLock, flags);
		return -1;
	}

	if (reason == MPT_HOSTEVENT_IOC_BRINGUP || 
	    mpt_enable_deadioc_detect){
		for (ii=0; ii<5; ii++) {
			/* Get IOC facts! Allow 5 retries */
			if ((rc = GetIocFacts(ioc, sleepFlag, reason)) == 0)
				break;
		}


		if (ii == 5) {
			dinitprintk((MYIOC_s_INFO_FMT "Retry IocFacts failed rc=%x\n", ioc->name, rc));
			ret = -2;
		} else {
			if (reason == MPT_HOSTEVENT_IOC_BRINGUP)
				MptDisplayIocCapabilities(ioc);
		}
	}

	/* Prime reply & request queues!
	 * (mucho alloc's) Must be done prior to
	 * init as upper addresses are needed for init.
	 */
	if ((ret == 0) && ((rc = PrimeIocFifos(ioc)) != 0))
		ret = -3;

	/* May need to check/upload firmware & data here!
	 * If fails, continue with alt-ioc processing
	 */
	if ((ret == 0) && ((rc = SendIocInit(ioc, sleepFlag)) != 0))
		ret = -4;

	if (reason == MPT_HOSTEVENT_IOC_BRINGUP){
		if (ioc->upload_fw) {
			ddlprintk((MYIOC_s_INFO_FMT
				"firmware upload required!\n", ioc->name));

			/* Controller is not operational, cannot do upload
			 */
			if (ret == 0) {
				rc = mpt_do_upload(ioc, sleepFlag);
				if (rc == 0) {
					if (ioc->alt_ioc && ioc->alt_ioc->cached_fw) {
						/*
						 * Maintain only one pointer to FW memory
						 * so there will not be two attempt to
						 * downloadboot onboard dual function
						 * chips (mpt_adapter_disable,
						 * mpt_diag_reset)
						 */
						ddlprintk((MYIOC_s_INFO_FMT ": mpt_upload:  alt_%s has cached_fw=%p \n",
							ioc->name, ioc->alt_ioc->name, ioc->alt_ioc->cached_fw));
						ioc->alt_ioc->cached_fw = NULL;
					}
				} else {
					printk(KERN_WARNING MYNAM ": firmware upload failure!\n");
					ret = -5;
				}
			}
		}
	}

	if (ret == 0) {
		/* Enable! (reply interrupt) */
		CHIPREG_WRITE32(&ioc->chip->IntMask, MPI_HIM_DIM);
		ioc->active = 1;
	}


	/*  Enable MPT base driver management of EventNotification
	 *  and EventAck handling.
	 */
	if ((ret == 0) && (!ioc->facts.EventState))
		(void) SendEventNotification(ioc, 1);	/* 1=Enable EventNotification */

	/*	Add additional "reason" check before call to GetLanConfigPages
	 *	(combined with GetIoUnitPage2 call).  This prevents a somewhat
	 *	recursive scenario; GetLanConfigPages times out, timer expired
	 *	routine calls HardResetHandler, which calls into here again,
	 *	and we try GetLanConfigPages again...
	 */
	if ((ret == 0) && (reason == MPT_HOSTEVENT_IOC_BRINGUP)) {

		/*
		 * Initalize link list for inactive raid volumes.
		 */
		init_MUTEX(&ioc->raid_data.inactive_list_mutex);
		INIT_LIST_HEAD(&ioc->raid_data.inactive_list);

		if (ioc->bus_type == SAS) {
			/*
			 * Pre-fetch SAS Address for each port
			 */
			GetManufPage5(ioc, ioc->facts.NumberOfPorts);

			/* clear persistency table */
			if(ioc->facts.IOCExceptions &
			    MPI_IOCFACTS_EXCEPT_PERSISTENT_TABLE_FULL) {
				ret = mptbase_sas_persist_operation(ioc,
				    MPI_SAS_OP_CLEAR_NOT_PRESENT);
				if(ret != 0) {
					spin_lock_irqsave(&ioc->diagLock, flags);
					ioc->ioc_reset_in_progress = 0;
					spin_unlock_irqrestore(&ioc->diagLock, flags);
					return -1;
				}
			}

			/* Find IM volumes
			 */
			mpt_findImVolumes(ioc);

			/* Check, and possibly reset, the coalescing value
			 */
			mpt_read_ioc_pg_1(ioc);

		} else if (ioc->bus_type == FC) {
			/*
			 *  Pre-fetch FC port WWN and stuff...
			 *  (FCPortPage0_t stuff)
			 */
			for (ii=0; ii < ioc->facts.NumberOfPorts; ii++) {
				(void) GetFcPortPage0(ioc, ii);
			}

			if ((ioc->pfacts[0].ProtocolFlags & MPI_PORTFACTS_PROTOCOL_LAN) &&
			    (ioc->lan_cnfg_page0.Header.PageLength == 0)) {
				/*
				 *  Pre-fetch the ports LAN MAC address!
				 *  (LANPage1_t stuff)
				 */
				(void) GetLanConfigPages(ioc);
#ifdef MPT_DEBUG
				{
					u8 *a = (u8*)&ioc->lan_cnfg_page1.HardwareAddressLow;
					dprintk((MYIOC_s_INFO_FMT "LanAddr = %02X:%02X:%02X:%02X:%02X:%02X\n",
							ioc->name, a[5], a[4], a[3], a[2], a[1], a[0] ));
				}
#endif
			}
		} else {
			/* Get NVRAM and adapter maximums from SPP 0 and 2
			 */
			mpt_GetScsiPortSettings(ioc, 0);

			/* Get version and length of SDP 1
			 */
			mpt_readScsiDevicePageHeaders(ioc, 0);

			/* Find IM volumes
			 */
			if (ioc->facts.MsgVersion >= MPI_VERSION_01_02)
				mpt_findImVolumes(ioc);

			/* Check, and possibly reset, the coalescing value
			 */
			mpt_read_ioc_pg_1(ioc);

			mpt_read_ioc_pg_4(ioc);
		}

		GetIoUnitPage2(ioc);

		/*
		 * Pre-fetch Serial number for the board.
		 */
		GetManufPage0(ioc);
	}

	/*
	 * Call each currently registered protocol IOC reset handler
	 * with post-reset indication.
	 * NOTE: If we're doing _IOC_BRINGUP, there can be no
	 * MptResetHandlers[] registered yet.
	 */
	if (ret == 0) {
		rc = 0;
		for (ii=MPT_MAX_PROTOCOL_DRIVERS-1; ii; ii--) {
			if (MptResetHandlers[ii]) {
				drsprintk((MYIOC_s_INFO_FMT "Calling IOC post_reset handler #%d\n",
						ioc->name, ii));
				rc += (*(MptResetHandlers[ii]))(ioc, MPT_IOC_POST_RESET);
			}
		}
	}

	if (ioc->bus_type == FC) {
		ioc->FcLinkSpeedCheckNeeded = 1;
	}

	if (ioc->bus_type == SPI) {
		drsprintk((MYIOC_s_WARN_FMT "%s: calling writeSDP1: ALL_IDS USE_NVRAM\n",
			ioc->name, __FUNCTION__));
		dnegoprintk((MYIOC_s_WARN_FMT "%s: calling writeSDP1: ALL_IDS USE_NVRAM\n",
			ioc->name, __FUNCTION__));
		mpt_writeSDP1(ioc, 0, 0, (MPT_SCSICFG_ALL_IDS | MPT_SCSICFG_USE_NVRAM));
	}

	spin_lock_irqsave(&ioc->diagLock, flags);
	ioc->ioc_reset_in_progress = 0;
	spin_unlock_irqrestore(&ioc->diagLock, flags);
	return ret;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_detect_bound_ports - Search for PCI bus/dev_function
 *	which matches PCI bus/dev_function (+/-1) for newly discovered 929,
 *	929X, 1030 or 1035.
 *	@ioc: Pointer to MPT adapter structure
 *	@pdev: Pointer to (struct pci_dev) structure
 *
 *	If match on PCI dev_function +/-1 is found, bind the two MPT adapters
 *	using alt_ioc pointer fields in their %MPT_ADAPTER structures.
 */
static void
mpt_detect_bound_ports(MPT_ADAPTER *ioc, struct pci_dev *pdev)
{
	struct pci_dev *peer=NULL;
	unsigned int slot = PCI_SLOT(pdev->devfn);
	unsigned int func = PCI_FUNC(pdev->devfn);
	MPT_ADAPTER *ioc_srch;

	dprintk((MYIOC_s_INFO_FMT "PCI device %s devfn=%x/%x,"
	    " searching for devfn match on %x or %x\n",
		ioc->name, pci_name(pdev), pdev->bus->number,
		pdev->devfn, func-1, func+1));

	peer = pci_get_slot(pdev->bus, PCI_DEVFN(slot,func-1));
	if (!peer) {
		peer = pci_get_slot(pdev->bus, PCI_DEVFN(slot,func+1));
		if (!peer)
			return;
	}

	list_for_each_entry(ioc_srch, &ioc_list, list) {
		struct pci_dev *_pcidev = ioc_srch->pcidev;
		if (_pcidev == peer) {
			/* Paranoia checks */
			if (ioc->alt_ioc != NULL) {
				printk(KERN_WARNING MYNAM ": Oops, already bound (%s <==> %s)!\n",
					ioc->name, ioc->alt_ioc->name);
				break;
			} else if (ioc_srch->alt_ioc != NULL) {
				printk(KERN_WARNING MYNAM ": Oops, already bound (%s <==> %s)!\n",
					ioc_srch->name, ioc_srch->alt_ioc->name);
				break;
			}
			dprintk((KERN_INFO MYNAM ": FOUND! binding %s <==> %s\n",
				ioc->name, ioc_srch->name));
			ioc_srch->alt_ioc = ioc;
			ioc->alt_ioc = ioc_srch;
		}
	}
	pci_dev_put(peer);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_adapter_disable - Disable misbehaving MPT adapter.
 *	@ioc: Pointer to MPT adapter structure
 */
static void
mpt_adapter_disable(MPT_ADAPTER *ioc)
{
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	int sz;
	int ret, ii;
	int bus, id;
	void *			request_data;
	dma_addr_t		request_data_dma;
	u32			request_data_sz;

	if (ioc->cached_fw != NULL) {
		ddlprintk((KERN_INFO MYNAM ": mpt_adapter_disable: Pushing FW onto adapter\n"));
		if ((ret = mpt_downloadboot(ioc, (MpiFwHeader_t *)ioc->cached_fw, NO_SLEEP)) < 0) {
			printk(KERN_WARNING MYNAM
				": firmware downloadboot failure (%d)!\n", ret);
		}
	}

	/* Disable adapter interrupts! */
	CHIPREG_WRITE32(&ioc->chip->IntMask, 0xFFFFFFFF);
	ioc->active = 0;
	/* Clear any lingering interrupt */
	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);

	for ( ii = 0; ii < MPI_DIAG_BUF_TYPE_COUNT; ii++) {
		request_data = ioc->DiagBuffer[ii];

		if ( request_data ) {
			request_data_sz = ioc->DiagBuffer_sz[ii];
			request_data_dma = ioc->DiagBuffer_dma[ii];
			dexitprintk((KERN_INFO MYNAM ": %s: free DiagBuffer[%d] @ %p, sz=%d bytes\n",
		 		ioc->name, ii, request_data, request_data_sz));
			pci_free_consistent(ioc->pcidev, request_data_sz,
				request_data,
				request_data_dma);

			ioc->DiagBuffer[ii] = NULL;
		}
	}
	if (ioc->alloc != NULL) {
		sz = ioc->alloc_sz;
		dexitprintk((KERN_INFO MYNAM ": %s: free alloc @ %p, sz=%d bytes\n",
		 	ioc->name, ioc->alloc, ioc->alloc_sz));
		pci_free_consistent(ioc->pcidev, sz,
				ioc->alloc, ioc->alloc_dma);
		ioc->reply_frames = NULL;
		ioc->req_frames = NULL;
		ioc->alloc = NULL;
		ioc->alloc_total -= sz;
	}

	if (ioc->sense_buf_pool != NULL) {
		sz = (ioc->req_depth * MPT_SENSE_BUFFER_ALLOC);
		dexitprintk((KERN_INFO MYNAM ": %s: free sense_buf_pool @ %p, sz=%d bytes\n",
		 	ioc->name, ioc->sense_buf_pool, sz));
		pci_free_consistent(ioc->pcidev, sz,
				ioc->sense_buf_pool, ioc->sense_buf_pool_dma);
		ioc->sense_buf_pool = NULL;
		ioc->alloc_total -= sz;
	}

	if (ioc->events != NULL){
		sz = MPTCTL_EVENT_LOG_SIZE * sizeof(MPT_IOCTL_EVENTS);
		dexitprintk((KERN_INFO MYNAM ": %s: free events @ %p, sz=%d bytes\n",
		 	ioc->name, ioc->events, sz));
		kfree(ioc->events);
		ioc->events = NULL;
		ioc->alloc_total -= sz;
	}

	if (ioc->cached_fw != NULL) {
		sz = ioc->facts.FWImageSize;
		dexitprintk((KERN_INFO MYNAM ": %s: free cached_fw @ %p, sz=%d bytes\n",
		 	ioc->name, ioc->cached_fw, sz));
		pci_free_consistent(ioc->pcidev, sz,
			ioc->cached_fw, ioc->cached_fw_dma);
		ioc->cached_fw = NULL;
		ioc->alloc_total -= sz;
	}

	if (ioc->spi_data.nvram != NULL) {
		dexitprintk((KERN_INFO MYNAM ": %s: free spi_data.nvram @ %p\n",
		 	ioc->name, ioc->spi_data.nvram));
		kfree(ioc->spi_data.nvram);
		ioc->spi_data.nvram = NULL;
	}

	if (ioc->raid_data.pIocPg3 != NULL) {
		dexitprintk((KERN_INFO MYNAM ": %s: free spi_data.pIocPg3 @ %p\n",
		 	ioc->name, ioc->raid_data.pIocPg3));
		kfree(ioc->raid_data.pIocPg3);
		ioc->raid_data.pIocPg3 = NULL;
	}

	if (ioc->raid_data.pIocPg6 != NULL) {
		dexitprintk((KERN_INFO MYNAM ": %s: free raid_data.pIocPg6 @ %p\n",
		 	ioc->name, ioc->raid_data.pIocPg6));
		kfree(ioc->raid_data.pIocPg6);
		ioc->raid_data.pIocPg6 = NULL;
	}

	if (ioc->spi_data.pIocPg4 != NULL) {
		sz = ioc->spi_data.IocPg4Sz;
		dexitprintk((KERN_INFO MYNAM ": %s: free spi_data.pIocPg4 @ %p size=%d\n",
		 	ioc->name, ioc->spi_data.pIocPg4, sz));
		pci_free_consistent(ioc->pcidev, sz,
			ioc->spi_data.pIocPg4,
			ioc->spi_data.IocPg4_dma);
		ioc->spi_data.pIocPg4 = NULL;
		ioc->alloc_total -= sz;
	}

	if (ioc->ReqToChain != NULL) {
		dexitprintk((KERN_INFO MYNAM ": %s: free ReqToChain @ %p\n",
		 	ioc->name, ioc->ReqToChain));
		kfree(ioc->ReqToChain);
		ioc->ReqToChain = NULL;
	}

	if (ioc->RequestNB != NULL) {
		dexitprintk((KERN_INFO MYNAM ": %s: free RequestNB @ %p\n",
		 	ioc->name, ioc->RequestNB));
		kfree(ioc->RequestNB);
		ioc->RequestNB = NULL;
	}

	if (ioc->ChainToChain != NULL) {
		dexitprintk((KERN_INFO MYNAM ": %s: free ChainToChain @ %p\n",
		 	ioc->name, ioc->ChainToChain));
		kfree(ioc->ChainToChain);
		ioc->ChainToChain = NULL;
	}

	mpt_inactive_raid_list_free(ioc);

	for (bus = 0; bus < ioc->NumberOfBuses; bus++) {
		if ((pMptTarget = ioc->Target_List[bus])) {
			for (id = 0; id < ioc->DevicesPerBus; id++) {
				if ((pTarget = pMptTarget->Target[id])) {
					dexitprintk((KERN_INFO MYNAM ": %s: free bus=%d id=%d pTarget=%p\n",
	 					ioc->name, bus, id, pTarget));
					kfree (pTarget);
				}
			}
			dexitprintk((KERN_INFO MYNAM ": %s: free bus=%d pMptTarget=%p\n",
	 			ioc->name, bus, pMptTarget));
			kfree (pMptTarget);
		}
	}
			
/* emoore@lsil.com : Host Page Buffer Suport, start */
	if (ioc->HostPageBuffer != NULL) {
		if((ret = mpt_host_page_access_control(ioc,
		    MPI_DB_HPBAC_FREE_BUFFER, NO_SLEEP)) != 0) {
			printk(KERN_ERR MYNAM
			   ": %s: host page buffers free failed (%d)!\n",
			    __FUNCTION__, ret);
		}
		dexitprintk((KERN_INFO MYNAM ": %s: HostPageBuffer free  @ %p, sz=%d bytes\n",
		 	ioc->name, ioc->HostPageBuffer, ioc->HostPageBuffer_sz));
		pci_free_consistent(ioc->pcidev, ioc->HostPageBuffer_sz,
				ioc->HostPageBuffer,
				ioc->HostPageBuffer_dma);
		ioc->HostPageBuffer = NULL;
		ioc->HostPageBuffer_sz = 0;
		ioc->alloc_total -= ioc->HostPageBuffer_sz;
	}
/* emoore@lsil.com : Host Page Buffer Suport, end */
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_adapter_dispose - Free all resources associated with a MPT
 *	adapter.
 *	@ioc: Pointer to MPT adapter structure
 *
 *	This routine unregisters h/w resources and frees all alloc'd memory
 *	associated with a MPT adapter structure.
 */
static void
mpt_adapter_dispose(MPT_ADAPTER *ioc)
{
	int sz_first, sz_last;

	if (ioc == NULL)
		return;

	sz_first = ioc->alloc_total;

	mpt_adapter_disable(ioc);

	if (ioc->pci_irq != -1) {
		free_irq(ioc->pci_irq, ioc);
		if (mpt_msi_enable == 1) {
			pci_disable_msi(ioc->pcidev);
		}
		ioc->pci_irq = -1;
	}

	if (ioc->memmap != NULL) {
		iounmap((u8 *) ioc->memmap);
		ioc->memmap = NULL;
	}

#if defined(CONFIG_MTRR) && 0
	if (ioc->mtrr_reg > 0) {
		mtrr_del(ioc->mtrr_reg, 0, 0);
		dprintk((KERN_INFO MYNAM ": %s: MTRR region de-registered\n", ioc->name));
	}
#endif

	/*  Zap the adapter lookup ptr!  */
	list_del(&ioc->list);

	sz_last = ioc->alloc_total;
	dexitprintk((KERN_INFO MYNAM ": %s: free'd %d of %d bytes\n",
		ioc->name, sz_first-sz_last+(int)sizeof(MPT_ADAPTER), sz_first));
	dexitprintk((KERN_INFO MYNAM ": %s: sz_first=%d sz_last=%d sizeof(MPT_ADAPTER)=%d\n",
		ioc->name, sz_first, sz_last, (int)sizeof(MPT_ADAPTER)));

	if (ioc->alt_ioc)
		ioc->alt_ioc->alt_ioc = NULL;

	kfree(ioc);

}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	MptDisplayIocCapabilities - Disply IOC's capacilities.
 *	@ioc: Pointer to MPT adapter structure
 */
static void
MptDisplayIocCapabilities(MPT_ADAPTER *ioc)
{
	int i = 0;

	printk(KERN_INFO "%s: ", ioc->name);
	if (ioc->prod_name && strlen(ioc->prod_name) > 3)
		printk("%s: ", ioc->prod_name+3);
	printk("Capabilities={");

	if (ioc->pfacts[0].ProtocolFlags & MPI_PORTFACTS_PROTOCOL_INITIATOR) {
		printk("Initiator");
		i++;
	}

	if (ioc->pfacts[0].ProtocolFlags & MPI_PORTFACTS_PROTOCOL_TARGET) {
		printk("%sTarget", i ? "," : "");
		i++;
	}

	if (ioc->pfacts[0].ProtocolFlags & MPI_PORTFACTS_PROTOCOL_LAN) {
		printk("%sLAN", i ? "," : "");
		i++;
	}

#if 0
	/*
	 *  This would probably evoke more questions than it's worth
	 */
	if (ioc->pfacts[0].ProtocolFlags & MPI_PORTFACTS_PROTOCOL_TARGET) {
		printk("%sLogBusAddr", i ? "," : "");
		i++;
	}
#endif

	printk("}\n");
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	MakeIocReady - Get IOC to a READY state, using KickStart if needed.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@force: Force hard KickStart of IOC
 *	@sleepFlag: Specifies whether the process can sleep
 *
 *	Returns:
 *		 1 - DIAG reset and READY
 *		 0 - READY initially OR soft reset and READY
 *		-1 - Any failure on KickStart
 *		-2 - Msg Unit Reset Failed
 *		-3 - IO Unit Reset Failed
 *		-4 - IOC owned by a PEER
 */
static int
MakeIocReady(MPT_ADAPTER *ioc, int force, int sleepFlag)
{
	u32	 ioc_state;
	int	 statefault = 0;
	int	 cntdn;
	int	 hard_reset_done = 0;
	int	 r;
	int	 ii;
	int	 whoinit;

	/* Get current [raw] IOC state  */
	ioc_state = mpt_GetIocState(ioc, 0);
	drsprintk((KERN_INFO MYNAM ": %s : MakeIocReady [raw] state=%08x\n", ioc->name, ioc_state));

	for ( ii = 0; ii < MPI_DIAG_BUF_TYPE_COUNT; ii++) {
		ioc->DiagBuffer[ii] = NULL;
		ioc->DiagBuffer_Status[ii] = 0;
	}

	if (ioc->bus_type == FC) {
		ioc->FcLinkSpeedCheckNeeded = 0;
		ioc->FcLinkSpeedReqActive = NULL;
	}

	/*
	 *	Check to see if IOC got left/stuck in doorbell handshake
	 *	grip of death.  If so, hard reset the IOC.
	 */
	if (ioc_state & MPI_DOORBELL_ACTIVE) {
		statefault = 1;
		printk(MYIOC_s_WARN_FMT "Unexpected doorbell active!\n",
				ioc->name);
	}

	/* Is it already READY? */
	if (!statefault && (ioc_state & MPI_IOC_STATE_MASK) == MPI_IOC_STATE_READY) 
	{
		drsprintk((KERN_INFO MYNAM ": %s : MakeIocReady ioc_state=%08x = READY\n", ioc->name, ioc_state));
		/* Dont return for SAS IOCs */
		if (ioc->bus_type != SAS)
			return 0;
	}

	/*
	 *	Check to see if IOC is in FAULT state.
	 */
	if ((ioc_state & MPI_IOC_STATE_MASK) == MPI_IOC_STATE_FAULT) {
		statefault = 2;
		printk(MYIOC_s_WARN_FMT "IOC is in FAULT state!!!\n",
				ioc->name);
		printk(KERN_WARNING "           FAULT code = %04xh\n",
				ioc_state & MPI_DOORBELL_DATA_MASK);
//		panic ("Chip FAULT!!!!!!!!!!!!!!");
	}

	/*
	 *	Hmmm...  Did it get left operational?
	 */
	if ((ioc_state & MPI_IOC_STATE_MASK) == MPI_IOC_STATE_OPERATIONAL) {
		dinitprintk((MYIOC_s_INFO_FMT "IOC operational unexpected\n",
				ioc->name));

		/* Check WhoInit.
		 * If PCI Peer, exit.
		 * Else, if no fault conditions are present, issue a MessageUnitReset
		 * Else, fall through to KickStart case
		 */
		whoinit = (ioc_state & MPI_DOORBELL_WHO_INIT_MASK) >> MPI_DOORBELL_WHO_INIT_SHIFT;
		dinitprintk((KERN_INFO MYNAM
			": whoinit 0x%x statefault %d force %d\n",
			whoinit, statefault, force));
		if (whoinit == MPI_WHOINIT_PCI_PEER)
			return -4;
		else {
			if ((statefault == 0 ) && (force == 0)) {
				if ((r = mpt_SendIocReset(ioc, MPI_FUNCTION_IOC_MESSAGE_UNIT_RESET, sleepFlag)) == 0)
					return 0;
			}
			statefault = 3;
		}
	}

	hard_reset_done = KickStart(ioc, statefault||force, sleepFlag);
	if (hard_reset_done < 0)
		return -1;

	/*
	 *  Loop here waiting for IOC to come READY.
	 */
	ii = 0;
	cntdn = ((sleepFlag == CAN_SLEEP) ? HZ : 1000) * 5;	/* 5 seconds */

	while ((ioc_state = mpt_GetIocState(ioc, 1)) != MPI_IOC_STATE_READY) {
		if (ioc_state == MPI_IOC_STATE_OPERATIONAL) {
			/*
			 *  BIOS or previous driver load left IOC in OP state.
			 *  Reset messaging FIFOs.
			 */
			if ((r = mpt_SendIocReset(ioc, MPI_FUNCTION_IOC_MESSAGE_UNIT_RESET, sleepFlag)) != 0) {
				printk(MYIOC_s_ERR_FMT "IOC msg unit reset failed!\n", ioc->name);
				return -2;
			}
		} else if (ioc_state == MPI_IOC_STATE_RESET) {
			/*
			 *  Something is wrong.  Try to get IOC back
			 *  to a known state.
			 */
			if ((r = mpt_SendIocReset(ioc, MPI_FUNCTION_IO_UNIT_RESET, sleepFlag)) != 0) {
				printk(MYIOC_s_ERR_FMT "IO unit reset failed!\n", ioc->name);
				return -3;
			}
		}

		ii++; cntdn--;
		if (!cntdn) {
			printk(MYIOC_s_ERR_FMT "Wait IOC_READY state timeout(%d)!\n",
					ioc->name, (int)((ii+5)/HZ));
			return -ETIME;
		}

		if (sleepFlag == CAN_SLEEP)
			msleep_interruptible(1);
		else
			MPT_MDELAY(1);	/* 1 msec delay */

	}

	if (statefault < 3) {
		dinitprintk((MYIOC_s_INFO_FMT "Recovered from %s\n",
				ioc->name,
				statefault==1 ? "stuck handshake" : "IOC FAULT"));
	}

	return hard_reset_done;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_GetIocState - Get the current state of a MPT adapter.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@cooked: Request raw or cooked IOC state
 *
 *	Returns all IOC Doorbell register bits if cooked==0, else just the
 *	Doorbell bits in MPI_IOC_STATE_MASK.
 */
u32
mpt_GetIocState(MPT_ADAPTER *ioc, int cooked)
{
	u32 s, sc;

	/*  Get!  */
	s = CHIPREG_READ32(&ioc->chip->Doorbell);
//	dprintk((MYIOC_s_INFO_FMT "raw state = %08x\n", ioc->name, s));
	sc = s & MPI_IOC_STATE_MASK;

	/*  Save!  */
	ioc->last_state = sc;

	return cooked ? sc : s;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	GetIocFacts - Send IOCFacts request to MPT adapter.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@sleepFlag: Specifies whether the process can sleep
 *	@reason: If recovery, only update facts.
 *
 *	Returns 0 for success, non-zero for failure.
 */
static int
GetIocFacts(MPT_ADAPTER *ioc, int sleepFlag, int reason)
{
	IOCFacts_t		 get_facts;
	IOCFactsReply_t		*facts;
	int			 r;
	int			 req_sz;
	int			 reply_sz;
	int			 sz;
	u32			 status, vv;
	u8			 shiftFactor=1;

	/* IOC *must* NOT be in RESET state! */
	if (ioc->last_state == MPI_IOC_STATE_RESET) {
		printk(KERN_ERR MYNAM ": ERROR - Can't get IOCFacts, %s NOT READY! (%08x)\n",
				ioc->name,
				ioc->last_state );
		return -44;
	}

	facts = &ioc->facts;

	/* Destination (reply area)... */
	reply_sz = sizeof(*facts);
	memset(facts, 0, reply_sz);

	/* Request area (get_facts on the stack right now!) */
	req_sz = sizeof(get_facts);
	memset(&get_facts, 0, req_sz);

	get_facts.Function = MPI_FUNCTION_IOC_FACTS;
	/* Assert: All other get_facts fields are zero! */

	dinitprintk((MYIOC_s_INFO_FMT 
	    "Sending get IocFacts request req_sz=%d reply_sz=%d\n", 
	    ioc->name, req_sz, reply_sz));

	/* No non-zero fields in the get_facts request are greater than
	 * 1 byte in size, so we can just fire it off as is.
	 */
	r = mpt_handshake_req_reply_wait(ioc, req_sz, (u32*)&get_facts,
			reply_sz, (u16*)facts, 5 /*seconds*/, sleepFlag);
	if (r != 0)
		return r;

	/*
	 * Now byte swap (GRRR) the necessary fields before any further
	 * inspection of reply contents.
	 *
	 * But need to do some sanity checks on MsgLength (byte) field
	 * to make sure we don't zero IOC's req_sz!
	 */
	/* Did we get a valid reply? */
	if (facts->MsgLength > offsetof(IOCFactsReply_t, RequestFrameSize)/sizeof(u32)) {
		if (reason == MPT_HOSTEVENT_IOC_BRINGUP) {
			/*
			 * If not been here, done that, save off first WhoInit value
			 */
			if (ioc->FirstWhoInit == WHOINIT_UNKNOWN)
				ioc->FirstWhoInit = facts->WhoInit;
		}

		facts->MsgVersion = le16_to_cpu(facts->MsgVersion);
		facts->MsgContext = le32_to_cpu(facts->MsgContext);
		facts->IOCExceptions = le16_to_cpu(facts->IOCExceptions);
		facts->IOCStatus = le16_to_cpu(facts->IOCStatus);
		facts->IOCLogInfo = le32_to_cpu(facts->IOCLogInfo);
		status = le16_to_cpu(facts->IOCStatus) & MPI_IOCSTATUS_MASK;
		/* CHECKME! IOCStatus, IOCLogInfo */

		facts->ReplyQueueDepth = le16_to_cpu(facts->ReplyQueueDepth);
		facts->RequestFrameSize = le16_to_cpu(facts->RequestFrameSize);

		/*
		 * FC f/w version changed between 1.1 and 1.2
		 *	Old: u16{Major(4),Minor(4),SubMinor(8)}
		 *	New: u32{Major(8),Minor(8),Unit(8),Dev(8)}
		 */
		if (facts->MsgVersion < 0x0102) {
			/*
			 *	Handle old FC f/w style, convert to new...
			 */
			u16	 oldv = le16_to_cpu(facts->Reserved_0101_FWVersion);
			facts->FWVersion.Word =
					((oldv<<12) & 0xFF000000) |
					((oldv<<8)  & 0x000FFF00);
		} else
			facts->FWVersion.Word = le32_to_cpu(facts->FWVersion.Word);

		facts->ProductID = le16_to_cpu(facts->ProductID);
		if ((ioc->facts.ProductID & MPI_FW_HEADER_PID_PROD_MASK)
		    > MPI_FW_HEADER_PID_PROD_TARGET_SCSI)
			ioc->ir_firmware = 1;
		facts->CurrentHostMfaHighAddr =
				le32_to_cpu(facts->CurrentHostMfaHighAddr);
		facts->GlobalCredits = le16_to_cpu(facts->GlobalCredits);
		facts->CurrentSenseBufferHighAddr =
				le32_to_cpu(facts->CurrentSenseBufferHighAddr);
		facts->CurReplyFrameSize =
				le16_to_cpu(facts->CurReplyFrameSize);
		facts->IOCCapabilities = le32_to_cpu(facts->IOCCapabilities);

		/*
		 * Handle NEW (!) IOCFactsReply fields in MPI-1.01.xx
		 * Older MPI-1.00.xx struct had 13 dwords, and enlarged
		 * to 14 in MPI-1.01.0x.
		 */
		if (facts->MsgLength >= (offsetof(IOCFactsReply_t,FWImageSize) + 7)/4 &&
		    facts->MsgVersion > 0x0100) {
			facts->FWImageSize = le32_to_cpu(facts->FWImageSize);
		}

		sz = facts->FWImageSize;
		if ( sz & 0x01 )
			sz += 1;
		if ( sz & 0x02 )
			sz += 2;
		facts->FWImageSize = sz;

		if (!facts->RequestFrameSize) {
			/*  Something is wrong!  */
			printk(MYIOC_s_ERR_FMT "IOC reported invalid 0 request size!\n",
					ioc->name);
			return -55;
		}

		r = sz = facts->BlockSize;
		vv = ((63 / (sz * 4)) + 1) & 0x03;
		ioc->NB_for_64_byte_frame = vv;
		while ( sz )
		{
			shiftFactor++;
			sz = sz >> 1;
		}
		ioc->NBShiftFactor  = shiftFactor;
		dinitprintk((MYIOC_s_INFO_FMT "NB_for_64_byte_frame=%x NBShiftFactor=%x BlockSize=%x\n",
					ioc->name, vv, shiftFactor, r));

		/* Allow dead IOCs to get detected after FWDLB*/
		if (reason == MPT_HOSTEVENT_IOC_BRINGUP || 
						mpt_enable_deadioc_detect) {
			/*
			 * Set values for this IOC's request & reply frame sizes,
			 * and request & reply queue depths...
			 */
			ioc->reply_sz = MPT_REPLY_FRAME_SIZE;
			if (mpt_reply_depth < facts->ReplyQueueDepth)
				ioc->reply_depth = mpt_reply_depth;
			else
				ioc->reply_depth = facts->ReplyQueueDepth;

			dinitprintk((MYIOC_s_INFO_FMT "reply_sz=%d mpt_reply_depth=%d ReplyQueueDepth=%d reply_depth=%d\n",
				ioc->name, ioc->reply_sz, mpt_reply_depth, facts->ReplyQueueDepth, ioc->reply_depth));

			ioc->req_sz = min(MPT_DEFAULT_FRAME_SIZE, facts->RequestFrameSize * 4);
			if (mpt_can_queue+ioc->reply_depth+12 < facts->GlobalCredits)
				ioc->req_depth = mpt_can_queue + ioc->reply_depth + 12;
			else
				ioc->req_depth = facts->GlobalCredits;
			dinitprintk((MYIOC_s_INFO_FMT "req_sz=%d mpt_can_queue=%d GlobalCredits=%d req_depth=%d\n",
				ioc->name, ioc->req_sz, mpt_can_queue, facts->GlobalCredits, ioc->req_depth));

			/* Get port facts! */
			if ( (r = GetPortFacts(ioc, 0, sleepFlag)) != 0 )
				return r;
		}
	} else {
		printk(MYIOC_s_ERR_FMT 
		     "Invalid IOC facts reply, msgLength=%d offsetof=%zd!\n",
		     ioc->name, facts->MsgLength, (offsetof(IOCFactsReply_t,
		     RequestFrameSize)/sizeof(u32)));
		return -66;
	}

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	GetPortFacts - Send PortFacts request to MPT adapter.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@portnum: Port number
 *	@sleepFlag: Specifies whether the process can sleep
 *
 *	Returns 0 for success, non-zero for failure.
 */
static int
GetPortFacts(MPT_ADAPTER *ioc, int portnum, int sleepFlag)
{
	PortFacts_t		 get_pfacts;
	PortFactsReply_t	*pfacts;
	int			 ii;
	int			 req_sz;
	int			 reply_sz;
	int			 max_id;

	/* IOC *must* NOT be in RESET state! */
	if (ioc->last_state == MPI_IOC_STATE_RESET) {
		printk(KERN_ERR MYNAM ": ERROR - Can't get PortFacts, %s NOT READY! (%08x)\n",
				ioc->name,
				ioc->last_state );
		return -4;
	}

	pfacts = &ioc->pfacts[portnum];

	/* Destination (reply area)...  */
	reply_sz = sizeof(*pfacts);
	memset(pfacts, 0, reply_sz);

	/* Request area (get_pfacts on the stack right now!) */
	req_sz = sizeof(get_pfacts);
	memset(&get_pfacts, 0, req_sz);

	get_pfacts.Function = MPI_FUNCTION_PORT_FACTS;
	get_pfacts.PortNumber = portnum;
	/* Assert: All other get_pfacts fields are zero! */

	dinitprintk((MYIOC_s_INFO_FMT "Sending get PortFacts(%d) request\n",
			ioc->name, portnum));

	/* No non-zero fields in the get_pfacts request are greater than
	 * 1 byte in size, so we can just fire it off as is.
	 */
	ii = mpt_handshake_req_reply_wait(ioc, req_sz, (u32*)&get_pfacts,
				reply_sz, (u16*)pfacts, 5 /*seconds*/, sleepFlag);
	if (ii != 0)
		return ii;

	/* Did we get a valid reply? */

	/* Now byte swap the necessary fields in the response. */
	pfacts->MsgContext = le32_to_cpu(pfacts->MsgContext);
	pfacts->IOCStatus = le16_to_cpu(pfacts->IOCStatus);
	pfacts->IOCLogInfo = le32_to_cpu(pfacts->IOCLogInfo);
	pfacts->MaxDevices = le16_to_cpu(pfacts->MaxDevices);
	pfacts->PortSCSIID = le16_to_cpu(pfacts->PortSCSIID);

	switch (ioc->bus_type) {
	case SAS:
		max_id = pfacts->PortSCSIID;
		break;
	case FC:
		max_id = pfacts->MaxDevices;
		break;
	case SPI:
	default:
		max_id = MPT_MAX_SCSI_DEVICES;
		break;
	}


	ioc->DevicesPerBus = (max_id > 255) ? 256 : max_id;
	ioc->NumberOfBuses = (ioc->DevicesPerBus < 256) ? 1 : max_id/256;
	if ( ioc->NumberOfBuses > MPT_MAX_BUSES ) {
		dinitprintk((MYIOC_s_WARN_FMT "NumberOfBuses=%d > MPT_MAX_BUSES=%d\n",
		   ioc->name, ioc->NumberOfBuses, MPT_MAX_BUSES));
		ioc->NumberOfBuses = MPT_MAX_BUSES;
	}

	dinitprintk((MYIOC_s_WARN_FMT "Buses=%d MaxDevices=%d DevicesPerBus=%d\n",
		   ioc->name, ioc->NumberOfBuses, max_id, ioc->DevicesPerBus));

	pfacts->ProtocolFlags = le16_to_cpu(pfacts->ProtocolFlags);
	pfacts->MaxPostedCmdBuffers = le16_to_cpu(pfacts->MaxPostedCmdBuffers);
	pfacts->MaxPersistentIDs = le16_to_cpu(pfacts->MaxPersistentIDs);
	pfacts->MaxLanBuckets = le16_to_cpu(pfacts->MaxLanBuckets);

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	SendIocInit - Send IOCInit request to MPT adapter.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@sleepFlag: Specifies whether the process can sleep
 *
 *	Send IOCInit followed by PortEnable to bring IOC to OPERATIONAL state.
 *
 *	Returns 0 for success, non-zero for failure.
 */
static int
SendIocInit(MPT_ADAPTER *ioc, int sleepFlag)
{
	IOCInit_t		 ioc_init;
	MPIDefaultReply_t	 init_reply;
	u32			 state;
	int			 r;
	int			 count;
	int			 cntdn;

	memset(&ioc_init, 0, sizeof(ioc_init));
	memset(&init_reply, 0, sizeof(init_reply));

	ioc_init.WhoInit = MPI_WHOINIT_HOST_DRIVER;
	ioc_init.Function = MPI_FUNCTION_IOC_INIT;

	/* If we are in a recovery mode and we uploaded the FW image,
	 * then this pointer is not NULL. Skip the upload a second time.
	 * Set this flag if cached_fw set for either IOC.
	 */
	if (ioc->facts.Flags & MPI_IOCFACTS_FLAGS_FW_DOWNLOAD_BOOT)
		ioc->upload_fw = 1;
	else
		ioc->upload_fw = 0;
	dinitprintk((MYIOC_s_INFO_FMT "upload_fw %d facts.Flags=%x\n",
		   ioc->name, ioc->upload_fw, ioc->facts.Flags));

	ioc_init.MaxDevices = ioc->DevicesPerBus;
	ioc_init.MaxBuses = ioc->NumberOfBuses;

	dinitprintk((MYIOC_s_INFO_FMT "ioc_init.MaxDevices=%d MaxBuses=%d\n",
		   ioc->name, ioc_init.MaxDevices, ioc_init.MaxBuses));
	dinitprintk((MYIOC_s_INFO_FMT "facts.MsgVersion=%x\n",
		   ioc->name, ioc->facts.MsgVersion));
/* emoore@lsil.com : Host Page Buffer Suport, start */
	if (ioc->facts.MsgVersion >= MPI_VERSION_01_05) {
		// set MsgVersion and HeaderVersion host driver was built with
		ioc_init.MsgVersion = cpu_to_le16(MPI_VERSION);
	        ioc_init.HeaderVersion = cpu_to_le16(MPI_HEADER_VERSION);

		if (ioc->facts.Flags & MPI_IOCFACTS_FLAGS_HOST_PAGE_BUFFER_PERSISTENT) {
			ioc_init.HostPageBufferSGE = ioc->facts.HostPageBufferSGE;
		} else if(mpt_host_page_alloc(ioc, &ioc_init))
			return -99;
	}
/* emoore@lsil.com : Host Page Buffer Suport, end */
	ioc_init.ReplyFrameSize = cpu_to_le16(ioc->reply_sz);	/* in BYTES */

	if (ioc->sg_addr_size == sizeof(u64)) {
		/* Save the upper 32-bits of the request
		 * (reply) and sense buffers.
		 */
		ioc_init.HostMfaHighAddr = cpu_to_le32((u32)((u64)ioc->alloc_dma >> 32));
		ioc_init.SenseBufferHighAddr = cpu_to_le32((u32)((u64)ioc->sense_buf_pool_dma >> 32));
	} else {
		/* Force 32-bit addressing */
		ioc_init.HostMfaHighAddr = cpu_to_le32(0);
		ioc_init.SenseBufferHighAddr = cpu_to_le32(0);
	}

	ioc->facts.CurrentHostMfaHighAddr = ioc_init.HostMfaHighAddr;
	ioc->facts.CurrentSenseBufferHighAddr = ioc_init.SenseBufferHighAddr;
	ioc->facts.MaxDevices = ioc_init.MaxDevices;
	ioc->facts.MaxBuses = ioc_init.MaxBuses;

	dinitprintk((MYIOC_s_INFO_FMT "Sending IOCInit (req @ %p)\n",
			ioc->name, &ioc_init));

	r = mpt_handshake_req_reply_wait(ioc, sizeof(IOCInit_t), (u32*)&ioc_init,
				sizeof(MPIDefaultReply_t), (u16*)&init_reply, 10 /*seconds*/, sleepFlag);
	if (r != 0) {
		printk(MYIOC_s_ERR_FMT "Sending IOCInit failed(%d)!\n",ioc->name, r);
		return r;
	}

	/* No need to byte swap the multibyte fields in the reply
	 * since we don't even look at it's contents.
	 */

	dinitprintk((MYIOC_s_INFO_FMT "Sending PortEnable (req @ %p)\n",
			ioc->name, &ioc_init));

	if ((r = SendPortEnable(ioc, 0, sleepFlag)) != 0) {
		printk(MYIOC_s_ERR_FMT "Sending PortEnable failed(%d)!\n",ioc->name, r);
		return r;
	}

	/* YIKES!  SUPER IMPORTANT!!!
	 *  Poll IocState until _OPERATIONAL while IOC is doing
	 *  LoopInit and TargetDiscovery!
	 */
	count = 0;
	cntdn = ((sleepFlag == CAN_SLEEP) ? HZ : 1000) * 60;	/* 60 seconds */
	state = mpt_GetIocState(ioc, 1);
	while (state != MPI_IOC_STATE_OPERATIONAL && --cntdn) {
		if (sleepFlag == CAN_SLEEP)
			msleep_interruptible(1);
		else
			MPT_MDELAY(1);	/* 1 msec delay */

		if (!cntdn) {
			printk(MYIOC_s_ERR_FMT "Wait IOC_OP state timeout(%d)!\n",
					ioc->name, (int)((count+5)/HZ));
			return -9;
		}

		state = mpt_GetIocState(ioc, 1);
		count++;
	}
	dinitprintk((MYIOC_s_INFO_FMT "INFO - Wait IOC_OPERATIONAL state (cnt=%d)\n",
			ioc->name, count));

        ioc->aen_event_read_flag=0;
	return r;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	SendPortEnable - Send PortEnable request to MPT adapter port.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@portnum: Port number to enable
 *	@sleepFlag: Specifies whether the process can sleep
 *
 *	Send PortEnable to bring IOC to OPERATIONAL state.
 *
 *	Returns 0 for success, non-zero for failure.
 */
static int
SendPortEnable(MPT_ADAPTER *ioc, int portnum, int sleepFlag)
{
	PortEnable_t		 port_enable;
	MPIDefaultReply_t	 reply_buf;
	int	 rc;
	int	 req_sz;
	int	 reply_sz;

	/*  Destination...  */
	reply_sz = sizeof(MPIDefaultReply_t);
	memset(&reply_buf, 0, reply_sz);

	req_sz = sizeof(PortEnable_t);
	memset(&port_enable, 0, req_sz);

	port_enable.Function = MPI_FUNCTION_PORT_ENABLE;
	port_enable.PortNumber = portnum;
/*	port_enable.ChainOffset = 0;		*/
/*	port_enable.MsgFlags = 0;		*/
/*	port_enable.MsgContext = 0;		*/

	dinitprintk((MYIOC_s_INFO_FMT "Sending Port(%d)Enable (req @ %p)\n",
			ioc->name, portnum, &port_enable));

	/* RAID FW may take a long time to enable
	 */
	if (ioc->ir_firmware || ioc->bus_type == SAS) {
		rc = mpt_handshake_req_reply_wait(ioc, req_sz,
		(u32*)&port_enable, reply_sz, (u16*)&reply_buf,
		300 /*seconds*/, sleepFlag);
	} else {
		rc = mpt_handshake_req_reply_wait(ioc, req_sz,
		(u32*)&port_enable, reply_sz, (u16*)&reply_buf,
		30 /*seconds*/, sleepFlag);
	}
	return rc;
}

/*
 *	ioc: Pointer to MPT_ADAPTER structure
 *      size - total FW bytes
 */
void
mpt_alloc_fw_memory(MPT_ADAPTER *ioc, int size)
{
	if (ioc->cached_fw)
		return;  /* use already allocated memory */
	if (ioc->alt_ioc && ioc->alt_ioc->cached_fw) {
		ioc->cached_fw = ioc->alt_ioc->cached_fw;  /* use alt_ioc's memory */
		ioc->cached_fw_dma = ioc->alt_ioc->cached_fw_dma;
		ioc->alloc_total += size;
		ioc->alt_ioc->alloc_total -= size;
	} else {
		if ( (ioc->cached_fw = pci_alloc_consistent(ioc->pcidev, size, &ioc->cached_fw_dma) ) )
			ioc->alloc_total += size;
	}
}
/*
 * If alt_img is NULL, delete from ioc structure.
 * Else, delete a secondary image in same format.
 */
void
mpt_free_fw_memory(MPT_ADAPTER *ioc)
{
	int sz;

	sz = ioc->facts.FWImageSize;
	dinitprintk((KERN_INFO MYNAM ": free_fw_memory: FW Image  @ %p[%p], sz=%d[%x] bytes\n",
		 ioc->cached_fw, (void *)(ulong)ioc->cached_fw_dma, sz, sz));
	pci_free_consistent(ioc->pcidev, sz,
			ioc->cached_fw, ioc->cached_fw_dma);
	ioc->cached_fw = NULL;

	return;
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_do_upload - Construct and Send FWUpload request to MPT adapter port.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@sleepFlag: Specifies whether the process can sleep
 *
 *	Returns 0 for success, >0 for handshake failure
 *		<0 for fw upload failure.
 *
 *	Remark: If bound IOC and a successful FWUpload was performed
 *	on the bound IOC, the second image is discarded
 *	and memory is free'd. Both channels must upload to prevent
 *	IOC from running in degraded mode.
 */
static int
mpt_do_upload(MPT_ADAPTER *ioc, int sleepFlag)
{
	u8			 request[ioc->req_sz];
	u8			 reply[sizeof(FWUploadReply_t)];
	FWUpload_t		*prequest;
	FWUploadReply_t		*preply;
	FWUploadTCSGE_t		*ptcsge;
	int			 sgeoffset;
	u32			 flagsLength;
	int			 ii, sz, reply_sz;
	int			 cmdStatus;

	/* If the image size is 0, we are done.
	 */
	if ((sz = ioc->facts.FWImageSize) == 0)
		return 0;

	mpt_alloc_fw_memory(ioc, sz);

	dinitprintk((KERN_INFO MYNAM ": FW Image  @ %p[%p], sz=%d[%x] bytes\n",
		 ioc->cached_fw, (void *)(ulong)ioc->cached_fw_dma, sz, sz));

	if (ioc->cached_fw == NULL) {
		/* Major Failure.
		 */
		return -ENOMEM;
	}

	prequest = (FWUpload_t *)&request;
	preply = (FWUploadReply_t *)&reply;

	/*  Destination...  */
	memset(prequest, 0, ioc->req_sz);

	reply_sz = sizeof(reply);
	memset(preply, 0, reply_sz);

	prequest->ImageType = MPI_FW_UPLOAD_ITYPE_FW_IOC_MEM;
	prequest->Function = MPI_FUNCTION_FW_UPLOAD;

	ptcsge = (FWUploadTCSGE_t *) &prequest->SGL;
	ptcsge->DetailsLength = 12;
	ptcsge->Flags = MPI_SGE_FLAGS_TRANSACTION_ELEMENT;
	ptcsge->ImageSize = cpu_to_le32(sz);

	sgeoffset = sizeof(FWUpload_t) - sizeof(SGE_MPI_UNION) + sizeof(FWUploadTCSGE_t);

	flagsLength = MPT_SGE_FLAGS_SSIMPLE_READ | sz;
	ioc->add_sge(&request[sgeoffset], flagsLength, ioc->cached_fw_dma);

	sgeoffset += ioc->SGE_size;
	dinitprintk((KERN_INFO MYNAM ": Sending FW Upload (req @ %p) sgeoffset=%d \n",
			prequest, sgeoffset));
	DBG_DUMP_FW_REQUEST_FRAME(prequest)

	ii = mpt_handshake_req_reply_wait(ioc, sgeoffset, (u32*)prequest,
				reply_sz, (u16*)preply, 65 /*seconds*/, sleepFlag);

	dinitprintk((KERN_INFO MYNAM ": FW Upload completed rc=%x \n", ii));

	cmdStatus = -EFAULT;
	if (ii == 0) {
		/* Handshake transfer was complete and successful.
		 * Check the Reply Frame.
		 */
		int status, transfer_sz;
		status = le16_to_cpu(preply->IOCStatus);
		if (status == MPI_IOCSTATUS_SUCCESS) {
			transfer_sz = le32_to_cpu(preply->ActualImageSize);
			if (transfer_sz == sz)
				cmdStatus = 0;
		}
	}
	dinitprintk((MYIOC_s_INFO_FMT ": do_upload cmdStatus=%d \n",
			ioc->name, cmdStatus));


	if (cmdStatus) {

		ddlprintk((MYIOC_s_INFO_FMT ": fw upload failed, freeing image \n",
			ioc->name));
		mpt_free_fw_memory(ioc);
	}

	return cmdStatus;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_downloadboot - DownloadBoot code
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@flag: Specify which part of IOC memory is to be uploaded.
 *	@sleepFlag: Specifies whether the process can sleep
 *
 *	FwDownloadBoot requires Programmed IO access.
 *
 *	Returns 0 for success
 *		-1 FW Image size is 0
 *		-2 No valid cached_fw Pointer
 *		<0 for fw upload failure.
 */
int
mpt_downloadboot(MPT_ADAPTER *ioc, MpiFwHeader_t *pFwHeader, int sleepFlag)
{
	MpiExtImageHeader_t	*pExtImage;
	u32			 fwSize;
	u32			 diag0val;
	int			 count;
	u32			*ptrFw;
	u32			 diagRwData, doorbell;
	u32			 nextImage;
	u32			 load_addr;

	ddlprintk((MYIOC_s_WARN_FMT "downloadboot: pFwHeader=%p\n",
		ioc->name, pFwHeader));

	nextImage = pFwHeader->NextImageHeaderOffset;
	if (ioc->bus_type == SAS) {
		while (nextImage) {
			if ( (pExtImage = (MpiExtImageHeader_t *) ((char *)pFwHeader + nextImage)) ) {
				ddlprintk((MYIOC_s_WARN_FMT "downloadboot: SAS nextImage=%x pExtImage=%p ImageType=%x\n",
					ioc->name, nextImage, pExtImage, 
					pExtImage->ImageType));
			} else {
				ddlprintk((MYIOC_s_WARN_FMT "downloadboot: SAS nextImage=%x pExtImage=%p is NULL!\n",
					ioc->name, nextImage, pExtImage));
				return -EFAULT;
			}

			if ( pExtImage->ImageType == MPI_EXT_IMAGE_TYPE_BOOTLOADER ) {
				fwSize = (pExtImage->ImageSize + 3)/4;
				ptrFw = (u32 *) pExtImage;
				load_addr = pExtImage->LoadStartAddress;
				goto imageFound;
			}
			nextImage = pExtImage->NextImageHeaderOffset;
		}
		ddlprintk((MYIOC_s_WARN_FMT "downloadboot: SAS BOOTLOADER not found\n",
			ioc->name));
		/* Allow this image to be downloaded */
	}
	fwSize = (pFwHeader->ImageSize + 3)/4;
	ptrFw = (u32 *) pFwHeader;
	load_addr = pFwHeader->LoadStartAddress;

imageFound:
	ddlprintk((MYIOC_s_WARN_FMT "downloadboot: fw size 0x%x (%d), FW Ptr %p load_addr=%x\n",
		ioc->name, fwSize, fwSize, ptrFw, load_addr));

	CHIPREG_WRITE32(&ioc->chip->WriteSequence, 0xFF);
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_1ST_KEY_VALUE);
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_2ND_KEY_VALUE);
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_3RD_KEY_VALUE);
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_4TH_KEY_VALUE);
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_5TH_KEY_VALUE);

	CHIPREG_WRITE32(&ioc->chip->Diagnostic, (MPI_DIAG_PREVENT_IOC_BOOT | MPI_DIAG_DISABLE_ARM));

	/* wait 1 msec */
	if (sleepFlag == CAN_SLEEP)
		msleep_interruptible(1);
	else
		MPT_MDELAY(1);	/* 1 msec delay */

	diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
	CHIPREG_WRITE32(&ioc->chip->Diagnostic, diag0val | MPI_DIAG_RESET_ADAPTER);

	for (count = 0; count < 30; count ++) {
		diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
		if (!(diag0val & MPI_DIAG_RESET_ADAPTER)) {
			ddlprintk((MYIOC_s_WARN_FMT "RESET_ADAPTER cleared, count=%d\n",
				ioc->name, count));
			break;
		}
		/* wait .1 sec */
		if (sleepFlag == CAN_SLEEP)
			msleep_interruptible(100);
		else
			MPT_MDELAY(100);	/* 100 msec delay */
	}

	if ( count == 30 ) {
		ddlprintk((MYIOC_s_WARN_FMT "downloadboot failed! Unable to get MPI_DIAG_DRWE mode, diag0val=%x\n",
		ioc->name, diag0val));
		return -3;
	}

	CHIPREG_WRITE32(&ioc->chip->WriteSequence, 0xFF);
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_1ST_KEY_VALUE);
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_2ND_KEY_VALUE);
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_3RD_KEY_VALUE);
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_4TH_KEY_VALUE);
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_5TH_KEY_VALUE);

	/* Set the DiagRwEn and Disable ARM bits */
	diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
	CHIPREG_WRITE32(&ioc->chip->Diagnostic, diag0val | (MPI_DIAG_RW_ENABLE | MPI_DIAG_DISABLE_ARM));

	/* Write the LoadStartAddress to the DiagRw Address Register
	 * using Programmed IO
	 */
	if(ioc->errata_flag_1064) {
		pci_enable_io_access(ioc->pcidev);
	}
	CHIPREG_PIO_WRITE32(&ioc->pio_chip->DiagRwAddress, load_addr);
	ddlprintk((MYIOC_s_WARN_FMT "LoadStart addr written 0x%x \n",
		ioc->name, load_addr));

	ddlprintk((MYIOC_s_WARN_FMT "Write FW Image: 0x%x (%d) bytes @ %p\n",
				ioc->name, fwSize*4, fwSize*4, ptrFw));
	while (fwSize--) {
		CHIPREG_PIO_WRITE32(&ioc->pio_chip->DiagRwData, *ptrFw++);
	}

	if (ioc->bus_type == SAS) {
		pFwHeader->IopResetVectorValue = load_addr + 0x18;
	} else {

		while (nextImage) {
			pExtImage = (MpiExtImageHeader_t *) ((char *)pFwHeader + nextImage);

			load_addr = pExtImage->LoadStartAddress;

			fwSize = (pExtImage->ImageSize + 3) >> 2;
			ptrFw = (u32 *)pExtImage;

			ddlprintk((MYIOC_s_WARN_FMT "Write Ext Image: 0x%x (%d) bytes @ %p load_addr=%x\n",
				ioc->name, fwSize*4, fwSize*4, ptrFw, load_addr));
			CHIPREG_PIO_WRITE32(&ioc->pio_chip->DiagRwAddress, load_addr);

			while (fwSize--) {
				CHIPREG_PIO_WRITE32(&ioc->pio_chip->DiagRwData, *ptrFw++);
			}
			nextImage = pExtImage->NextImageHeaderOffset;
		}
	}

	/* Write the IopResetVectorRegAddr */
	ddlprintk((MYIOC_s_WARN_FMT "Write IopResetVector Addr=%x! \n", 			ioc->name, pFwHeader->IopResetRegAddr));
	CHIPREG_PIO_WRITE32(&ioc->pio_chip->DiagRwAddress, pFwHeader->IopResetRegAddr);

	/* Write the IopResetVectorValue */
	ddlprintk((MYIOC_s_WARN_FMT "Write IopResetVector Value=%x! \n", 
		ioc->name, pFwHeader->IopResetVectorValue));
	CHIPREG_PIO_WRITE32(&ioc->pio_chip->DiagRwData, pFwHeader->IopResetVectorValue);

	if (ioc->bus_type == SPI) {
		/*
		 * 1030 H/W errata, workaround to access
		 * the ClearFlashBadSignatureBit
		 */
		CHIPREG_PIO_WRITE32(&ioc->pio_chip->DiagRwAddress, 0x3F000000);
		diagRwData = CHIPREG_PIO_READ32(&ioc->pio_chip->DiagRwData);
		diagRwData |= 0x40000000;
		CHIPREG_PIO_WRITE32(&ioc->pio_chip->DiagRwAddress, 0x3F000000);
		CHIPREG_PIO_WRITE32(&ioc->pio_chip->DiagRwData, diagRwData);

	}

	if(ioc->errata_flag_1064) {
		pci_disable_io_access(ioc->pcidev);
	}
	
	diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
	ddlprintk((MYIOC_s_WARN_FMT "downloadboot: diag0val=%x, turning off PREVENT_IOC_BOOT, DISABLE_ARM\n",
		ioc->name, diag0val));
	diag0val &= ~(MPI_DIAG_PREVENT_IOC_BOOT | MPI_DIAG_DISABLE_ARM);
	ddlprintk((MYIOC_s_WARN_FMT "downloadboot: now diag0val=%x\n",
		ioc->name, diag0val));
	CHIPREG_WRITE32(&ioc->chip->Diagnostic, diag0val);
	if (ioc->bus_type == SAS ) {
		/* wait 1 sec */
		if (sleepFlag == CAN_SLEEP)
		{
			msleep_interruptible(1000);
		}
		else
			MPT_MDELAY(1000);	/* 1000 msec delay */
	

		diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
		ddlprintk((MYIOC_s_WARN_FMT "downloadboot: diag0val=%x, turning off RW_ENABLE\n",
			ioc->name, diag0val));
		diag0val &= ~(MPI_DIAG_RW_ENABLE);
		ddlprintk((MYIOC_s_WARN_FMT "downloadboot: now diag0val=%x\n",
			ioc->name, diag0val));
		CHIPREG_WRITE32(&ioc->chip->Diagnostic, diag0val);

		diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
		if (diag0val & MPI_DIAG_FLASH_BAD_SIG) {
			diag0val |= MPI_DIAG_CLEAR_FLASH_BAD_SIG;
			CHIPREG_WRITE32(&ioc->chip->Diagnostic, diag0val);
			diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
		}
		diag0val &= ~(MPI_DIAG_DISABLE_ARM);
		CHIPREG_WRITE32(&ioc->chip->Diagnostic, diag0val);
		diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
		CHIPREG_WRITE32(&ioc->chip->DiagRwAddress, 0x3f000004);
	}
	/* Write 0xFF to reset the sequencer */
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, 0xFF);

	for (count = 0; count < 30; count ++) {
		doorbell = CHIPREG_READ32(&ioc->chip->Doorbell);

		doorbell &= MPI_IOC_STATE_MASK;

		if (doorbell == MPI_IOC_STATE_READY) {
			if (ioc->bus_type == SAS) {
				return 0;
			}
			if ((SendIocInit(ioc, sleepFlag)) != 0) {
				ddlprintk((MYIOC_s_WARN_FMT "downloadboot: SendIocInit failed\n",
					ioc->name));
				return -EFAULT;
			}
			ddlprintk((MYIOC_s_WARN_FMT "downloadboot: SendIocInit successful\n",
				ioc->name));
			return 0;
		}
		ddlprintk((MYIOC_s_WARN_FMT "downloadboot: looking for READY STATE: doorbell=%x count=%d\n", 
			ioc->name, doorbell, count));
		/* wait 1 sec */
		if (sleepFlag == CAN_SLEEP)
		{
			msleep_interruptible(1000);
		}
		else
			MPT_MDELAY(1000);	/* 1000 msec delay */
	}
	ddlprintk((MYIOC_s_WARN_FMT "downloadboot failed! IocState=%x\n",
		ioc->name, doorbell));
	return -EFAULT;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	KickStart - Perform hard reset of MPT adapter.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@force: Force hard reset
 *	@sleepFlag: Specifies whether the process can sleep
 *
 *	This routine places MPT adapter in diagnostic mode via the
 *	WriteSequence register, and then performs a hard reset of adapter
 *	via the Diagnostic register.
 *
 *	Inputs:   sleepflag - CAN_SLEEP (non-interrupt thread)
 *			or NO_SLEEP (interrupt thread, use mdelay)
 *		  force - 1 if doorbell active, board fault state
 *				board operational, IOC_RECOVERY or
 *				IOC_BRINGUP and there is an alt_ioc.
 *			  0 else
 *
 *	Returns:
 *		 1 - hard reset, READY
 *		 0 - no reset due to History bit, READY
 *		-1 - no reset due to History bit but not READY
 *		     OR reset but failed to come READY
 *		-2 - no reset, could not enter DIAG mode
 *		-3 - reset but bad FW bit
 */
static int
KickStart(MPT_ADAPTER *ioc, int force, int sleepFlag)
{
	int hard_reset_done = 0;
	u32 ioc_state=0;
	int cnt,cntdn;

	dinitprintk((KERN_INFO MYNAM ": KickStarting %s!\n", ioc->name));
	if (ioc->bus_type == SPI) {
		/* Always issue a Msg Unit Reset first. This will clear some
		 * SCSI bus hang conditions.
		 */
		mpt_SendIocReset(ioc, MPI_FUNCTION_IOC_MESSAGE_UNIT_RESET, sleepFlag);

		if (sleepFlag == CAN_SLEEP)
			msleep_interruptible(1000);
		else
			MPT_MDELAY(1000);	/* 1000 msec delay */
	}

	hard_reset_done = mpt_diag_reset(ioc, force, sleepFlag);
	if (hard_reset_done < 0)
		return hard_reset_done;

	dinitprintk((MYIOC_s_INFO_FMT "Diagnostic reset successful!\n",
			ioc->name));

	cntdn = ((sleepFlag == CAN_SLEEP) ? HZ : 1000) * 2;	/* 2 seconds */
	for (cnt=0; cnt<cntdn; cnt++) {
		ioc_state = mpt_GetIocState(ioc, 1);
		if ((ioc_state == MPI_IOC_STATE_READY) || (ioc_state == MPI_IOC_STATE_OPERATIONAL)) {
			dinitprintk((MYIOC_s_INFO_FMT "KickStart successful! (cnt=%d)\n",
 					ioc->name, cnt));
			return hard_reset_done;
		}
		if (sleepFlag == CAN_SLEEP)
			msleep_interruptible(10);
		else
			MPT_MDELAY(10);		/* 10 msec delay */
	}

	printk(MYIOC_s_ERR_FMT "Failed to come READY after reset! IocState=%x\n",
			ioc->name, ioc_state);
	return -1;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_diag_reset - Perform hard reset of the adapter.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@ignore: Set if to honor and clear to ignore
 *		the reset history bit
 *	@sleepflag: CAN_SLEEP if called in a non-interrupt thread,
 *		else set to NO_SLEEP (use mdelay instead)
 *
 *	This routine places the adapter in diagnostic mode via the
 *	WriteSequence register and then performs a hard reset of adapter
 *	via the Diagnostic register. Adapter should be in ready state
 *	upon successful completion.
 *
 *	Returns:  1  hard reset successful
 *		  0  no reset performed because reset history bit set
 *		 -2  enabling diagnostic mode failed
 *		 -3  diagnostic reset failed
 */
static int
mpt_diag_reset(MPT_ADAPTER *ioc, int ignore, int sleepFlag)
{
	MPT_ADAPTER	*iocp=NULL;
	u32 diag0val;
	u32 doorbell;
	int hard_reset_done = 0;
	int count = 0;
#ifdef MPT_DEBUG
	u32 diag1val = 0;
#endif

	if (ioc->pcidev->device == MPI_MANUFACTPAGE_DEVID_SAS1078) {
		drsprintk((MYIOC_s_WARN_FMT "%s: Doorbell=%p; 1078 reset address=%p\n",
			ioc->name, __FUNCTION__, &ioc->chip->Doorbell, &ioc->chip->Reset_1078));
		CHIPREG_WRITE32(&ioc->chip->Reset_1078, 0x07);
		if (sleepFlag == CAN_SLEEP)
			msleep_interruptible(1);
		else
			MPT_MDELAY(1);		/* 1 msec delay */

		/*
		 * Call each currently registered protocol IOC reset handler
		 * with post-reset indication.
		 * NOTE: If we're doing _IOC_BRINGUP, there can be no
		 * MptResetHandlers[] registered yet.
		 */
		{
			int	 ii;
			int	 r = 0;

			for (ii=MPT_MAX_PROTOCOL_DRIVERS-1; ii; ii--) {
				if (MptResetHandlers[ii]) {
					drsprintk((MYIOC_s_INFO_FMT "Calling IOC post_reset handler #%d\n",
							ioc->name, ii));
					r += (*(MptResetHandlers[ii]))(ioc, MPT_IOC_POST_RESET);
				}
			}
			/* FIXME?  Examine results here? */
		}

		for (count = 0; count < 60; count ++) {
			doorbell = CHIPREG_READ32(&ioc->chip->Doorbell);
			doorbell &= MPI_IOC_STATE_MASK;

			drsprintk((MYIOC_s_INFO_FMT "looking for READY STATE: doorbell=%x count=%d\n", 
				ioc->name, doorbell, count));
			if (doorbell == MPI_IOC_STATE_READY) {
				return 0;
			}

			/* wait 1 sec */
			if (sleepFlag == CAN_SLEEP)
				msleep_interruptible(1000);
			else
				MPT_MDELAY(1000);	/* 1000 msec delay */
		}
		return -1;
	}

	/* Clear any existing interrupts */
	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);

	/* Use "Diagnostic reset" method! (only thing available!) */
	diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);

#ifdef MPT_DEBUG
	if (ioc->alt_ioc)
		diag1val = CHIPREG_READ32(&ioc->alt_ioc->chip->Diagnostic);
	dprintk((MYIOC_s_INFO_FMT "DbG1: diag0=%08x, diag1=%08x\n",
			ioc->name, diag0val, diag1val));
#endif

	/* Do the reset if we are told to ignore the reset history
	 * or if the reset history is 0
	 */
	if (ignore || !(diag0val & MPI_DIAG_RESET_HISTORY)) {
		while ((diag0val & MPI_DIAG_DRWE) == 0) {
			/* Write magic sequence to WriteSequence register
			 * Loop until in diagnostic mode
			 */
			CHIPREG_WRITE32(&ioc->chip->WriteSequence, 0xFF);
			CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_1ST_KEY_VALUE);
			CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_2ND_KEY_VALUE);
			CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_3RD_KEY_VALUE);
			CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_4TH_KEY_VALUE);
			CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_5TH_KEY_VALUE);

			/* wait 100 msec */
			if (sleepFlag == CAN_SLEEP)
				msleep_interruptible(100);
			else
				MPT_MDELAY(100);	/* 100 msec delay */

			count++;
			if (count > 20) {
				printk(MYIOC_s_ERR_FMT "Enable Diagnostic mode FAILED! (%02xh)\n",
						ioc->name, diag0val);
				return -2;

			}

			diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);

			drsprintk((MYIOC_s_INFO_FMT "Wrote magic DiagWriteEn sequence (%x)\n",
					ioc->name, diag0val));
		}

#ifdef MPT_DEBUG
		if (ioc->alt_ioc)
			diag1val = CHIPREG_READ32(&ioc->alt_ioc->chip->Diagnostic);
		dprintk((MYIOC_s_INFO_FMT "DbG2: diag0=%08x, diag1=%08x\n",
				ioc->name, diag0val, diag1val));
#endif
		/*
		 * Disable the ARM (Bug fix)
		 *
		 */
		CHIPREG_WRITE32(&ioc->chip->Diagnostic, diag0val | MPI_DIAG_DISABLE_ARM);
		MPT_MDELAY(1);

		/*
		 * Now hit the reset bit in the Diagnostic register
		 * (THE BIG HAMMER!) (Clears DRWE bit).
		 */
		CHIPREG_WRITE32(&ioc->chip->Diagnostic, diag0val | MPI_DIAG_RESET_ADAPTER);
		hard_reset_done = 1;
		drsprintk((MYIOC_s_INFO_FMT "Diagnostic reset performed\n",
				ioc->name));

		/*
		 * Call each currently registered protocol IOC reset handler
		 * with pre-reset indication.
		 * NOTE: If we're doing _IOC_BRINGUP, there can be no
		 * MptResetHandlers[] registered yet.
		 */
		{
			int	 ii;
			int	 r = 0;

			for (ii=MPT_MAX_PROTOCOL_DRIVERS-1; ii; ii--) {
				if (MptResetHandlers[ii]) {
					drsprintk((MYIOC_s_INFO_FMT "Calling IOC pre_reset handler #%d\n",
							ioc->name, ii));
					r += (*(MptResetHandlers[ii]))(ioc, MPT_IOC_PRE_RESET);
					if (ioc->alt_ioc) {
						drsprintk((MYIOC_s_INFO_FMT "Calling alt-%s pre_reset handler #%d\n",
								ioc->name, ioc->alt_ioc->name, ii));
						r += (*(MptResetHandlers[ii]))(ioc->alt_ioc, MPT_IOC_PRE_RESET);
					}
				}
			}
			/* FIXME?  Examine results here? */
		}

		if (ioc->cached_fw) 
			iocp = ioc;
		else if (ioc->alt_ioc && ioc->alt_ioc->cached_fw)
			iocp = ioc->alt_ioc;
		if (iocp) {
			/* If the DownloadBoot operation fails, the
			 * IOC will be left unusable. This is a fatal error
			 * case.  _diag_reset will return < 0
			 */
			for (count = 0; count < 30; count ++) {
				diag0val = CHIPREG_READ32(&iocp->chip->Diagnostic);
				if (!(diag0val & MPI_DIAG_RESET_ADAPTER)) {
					break;
				}

				dprintk((MYIOC_s_INFO_FMT "cached_fw: diag0val=%x count=%d\n",
					iocp->name, diag0val, count));
				/* wait 1 sec */
				if (sleepFlag == CAN_SLEEP)
					msleep_interruptible(1000);
				else
					MPT_MDELAY(1000);
			}
			if ((count = mpt_downloadboot(iocp, (MpiFwHeader_t *)iocp->cached_fw, sleepFlag)) < 0) {
				printk(KERN_WARNING MYNAM
					": firmware downloadboot failure (%d)!\n", count);
			}

		} else {
			/* Wait for FW to reload and for board
			 * to go to the READY state.
			 * Maximum wait is 60 seconds.
			 * If fail, no error will check again
			 * with calling program.
			 */
			for (count = 0; count < 60; count ++) {
				doorbell = CHIPREG_READ32(&ioc->chip->Doorbell);
				doorbell &= MPI_IOC_STATE_MASK;

				if (doorbell == MPI_IOC_STATE_READY) {
					break;
				}

				dprintk((MYIOC_s_INFO_FMT "looking for READY STATE: doorbell=%x count=%d\n", 
					ioc->name, doorbell, count));
				/* wait 1 sec */
				if (sleepFlag == CAN_SLEEP)
					msleep_interruptible(1000);
				else
					MPT_MDELAY(1000);
			}
		}
	}

	diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
#ifdef MPT_DEBUG
	if (ioc->alt_ioc)
		diag1val = CHIPREG_READ32(&ioc->alt_ioc->chip->Diagnostic);
	dprintk((MYIOC_s_INFO_FMT "DbG3: diag0=%08x, diag1=%08x\n",
		ioc->name, diag0val, diag1val));
#endif

	/* Clear RESET_HISTORY bit!  Place board in the
	 * diagnostic mode to update the diag register.
	 */
	diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
	count = 0;
	while ((diag0val & MPI_DIAG_DRWE) == 0) {
		/* Write magic sequence to WriteSequence register
		 * Loop until in diagnostic mode
		 */
		CHIPREG_WRITE32(&ioc->chip->WriteSequence, 0xFF);
		CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_1ST_KEY_VALUE);
		CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_2ND_KEY_VALUE);
		CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_3RD_KEY_VALUE);
		CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_4TH_KEY_VALUE);
		CHIPREG_WRITE32(&ioc->chip->WriteSequence, MPI_WRSEQ_5TH_KEY_VALUE);

		/* wait 100 msec */
		if (sleepFlag == CAN_SLEEP)
			msleep_interruptible(100);
		else
			MPT_MDELAY(100);

		count++;
		if (count > 20) {
			printk(MYIOC_s_ERR_FMT "Enable Diagnostic mode FAILED! (%02xh)\n",
					ioc->name, diag0val);
			break;
		}
		diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
	}
	diag0val &= ~MPI_DIAG_RESET_HISTORY;
	CHIPREG_WRITE32(&ioc->chip->Diagnostic, diag0val);
	diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
	if (diag0val & MPI_DIAG_RESET_HISTORY) {
		printk(MYIOC_s_WARN_FMT "ResetHistory bit failed to clear!\n",
				ioc->name);
	}

	/* Disable Diagnostic Mode
	 */
	CHIPREG_WRITE32(&ioc->chip->WriteSequence, 0xFFFFFFFF);

	/* Check FW reload status flags.
	 */
	diag0val = CHIPREG_READ32(&ioc->chip->Diagnostic);
	if (diag0val & (MPI_DIAG_FLASH_BAD_SIG | MPI_DIAG_RESET_ADAPTER | MPI_DIAG_DISABLE_ARM)) {
		printk(MYIOC_s_ERR_FMT "Diagnostic reset FAILED! (%02xh)\n",
				ioc->name, diag0val);
		return -3;
	}

#ifdef MPT_DEBUG
	if (ioc->alt_ioc)
		diag1val = CHIPREG_READ32(&ioc->alt_ioc->chip->Diagnostic);
	dprintk((MYIOC_s_INFO_FMT "DbG4: diag0=%08x, diag1=%08x\n",
			ioc->name, diag0val, diag1val));
#endif

	/*
	 * Reset flag that says we've enabled event notification
	 */
	ioc->facts.EventState = 0;

	if (ioc->alt_ioc)
		ioc->alt_ioc->facts.EventState = 0;

	return hard_reset_done;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	SendIocReset - Send IOCReset request to MPT adapter.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@reset_type: reset type, expected values are
 *	%MPI_FUNCTION_IOC_MESSAGE_UNIT_RESET or %MPI_FUNCTION_IO_UNIT_RESET
 *
 *	Send IOCReset request to the MPT adapter.
 *
 *	Returns 0 for success, non-zero for failure.
 */
int
mpt_SendIocReset(MPT_ADAPTER *ioc, u8 reset_type, int sleepFlag)
{
	unsigned long flags;
	int r;
	u32 state, Doorbell;
	int cntdn, count;

	Doorbell = (reset_type<<MPI_DOORBELL_FUNCTION_SHIFT);
	drsprintk((MYIOC_s_WARN_FMT ": %s: reset_type=%02x Doorbell=%08x!\n",
			ioc->name, __FUNCTION__, reset_type, Doorbell));
	CHIPREG_WRITE32(&ioc->chip->Doorbell, Doorbell);
	if ((r = WaitForDoorbellAck(ioc, 15, sleepFlag)) < 0) {
		drsprintk((MYIOC_s_WARN_FMT ": %s: WaitForDoorbellAck failed r=%d after IOC Reset type=%02x!\n",
			ioc->name, __FUNCTION__, r, reset_type));
		return r;
	}

	spin_lock_irqsave(&ioc->diagLock, flags);
	ioc->ioc_reset_in_progress = 1;
	spin_unlock_irqrestore(&ioc->diagLock, flags);

	/* FW ACK'd request, wait for READY state
	 */
	count = 0;
	cntdn = ((sleepFlag == CAN_SLEEP) ? HZ : 1000) * 15;	/* 15 seconds */

	while ((state = mpt_GetIocState(ioc, 1)) != MPI_IOC_STATE_READY) {
		cntdn--;
		count++;
		if (!cntdn) {
			if (sleepFlag != CAN_SLEEP)
				count *= 10;

			printk(KERN_ERR MYNAM ": %s: ERROR - Wait IOC_READY state timeout(%d)!\n",
					ioc->name, (int)((count+5)/HZ));
			return -ETIME;
		}

		if (sleepFlag == CAN_SLEEP)
			msleep_interruptible(1);
		else
			MPT_MDELAY(1);
	}

	if (ioc->facts.Function)
		ioc->facts.EventState = 0;

	spin_lock_irqsave(&ioc->diagLock, flags);
	ioc->ioc_reset_in_progress = 0;
	spin_unlock_irqrestore(&ioc->diagLock, flags);
	drsprintk((MYIOC_s_WARN_FMT ": %s: IOC reset completed successfully state=%08x count=%d\n",
		ioc->name, __FUNCTION__, state, count));

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_initChainBuffers - Allocate memory for and initialize
 *	chain buffer control arrays and spinlock.
 *	@ioc: Pointer to MPT_ADAPTER structure
 */
static int
mpt_initChainBuffers (MPT_ADAPTER *ioc)
{
	u8		*mem;
	int		sz, ii;

	/* ReqToChain size must equal the req_depth
	 */
	if (ioc->ReqToChain == NULL) {
		sz = ioc->req_depth * sizeof(int);
		mem = kmalloc(sz, GFP_ATOMIC);
		if (mem == NULL) {
			dinitprintk((KERN_INFO MYNAM ": %s ReqToChain %d alloc failed\n",
			 	ioc->name, sz));
			return -1;
		}

		ioc->ReqToChain = (int *) mem;
		dinitprintk((KERN_INFO MYNAM ": %s ReqToChain alloc  @ %p, sz=%d bytes\n",
			 	ioc->name, mem, sz));

		mem = kmalloc(sz, GFP_ATOMIC);
		if (mem == NULL) {
			dinitprintk((KERN_INFO MYNAM ": %s RequestNB %d alloc failed\n",
			 	ioc->name, sz));
			kfree (ioc->ReqToChain);
			ioc->ReqToChain = NULL;
			return -1;
		}
		ioc->RequestNB = (int *) mem;
		dinitprintk((KERN_INFO MYNAM ": %s RequestNB alloc  @ %p, sz=%d bytes\n",
			 	ioc->name, mem, sz));
	}
	for (ii = 0; ii < ioc->req_depth; ii++) {
		ioc->ReqToChain[ii] = MPT_HOST_NO_CHAIN;
	}

	sz = ioc->num_chain * sizeof(int);
	if (ioc->ChainToChain == NULL) {
		mem = kmalloc(sz, GFP_ATOMIC);
		if (mem == NULL) {
			dinitprintk((KERN_INFO MYNAM ": %s ChainToChain %d alloc failed\n",
			 	ioc->name, sz));
			kfree (ioc->ReqToChain);
			ioc->ReqToChain = NULL;
			kfree (ioc->RequestNB);
			ioc->RequestNB = NULL;
			return -1;
		}

		ioc->ChainToChain = (int *) mem;
		dinitprintk((KERN_INFO MYNAM ": %s ChainToChain alloc @ %p, sz=%d bytes\n",
			 	ioc->name, mem, sz));
	} else {
		mem = (u8 *) ioc->ChainToChain;
	}
	memset(mem, 0xFF, sz);
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	PrimeIocFifos - Initialize IOC request and reply FIFOs.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *
 *	This routine allocates memory for the MPT reply and request frame
 *	pools (if necessary), and primes the IOC reply FIFO with
 *	reply frames.
 *
 *	Returns 0 for success, non-zero for failure.
 */
static int
PrimeIocFifos(MPT_ADAPTER *ioc)
{
	MPT_FRAME_HDR *mf;
	unsigned long flags;
	dma_addr_t alloc_dma;
	u8 *mem;
	int i, reply_sz, req_sz, sz, total_size, num_chain, total_num_chain;
	int scale, scale1, num_sge, numSGE, maxSGEs, SGE_size;
	int max_sg_tablesize;
	u64	dma_mask;

	dma_mask = 0;
	/*  Prime reply FIFO...  */

	if (ioc->reply_frames == NULL) {
 
		/*
		 * 1078 errata workaround for the 36GB limitation
		 */
		if (ioc->pcidev->device == MPI_MANUFACTPAGE_DEVID_SAS1078 &&
		    ioc->dma_mask > MPT_DMA_35BIT_MASK) {
			if (!pci_set_dma_mask(ioc->pcidev,
			    MPT_DMA_35BIT_MASK)) {
				dma_mask = MPT_DMA_35BIT_MASK;
				dinitprintk((KERN_INFO MYNAM
				    ": %s: setting 35 bit addressing for "
				    "Request/Reply/Chain and Sense Buffers\n",
				    ioc->name));
			}
		}

		/* Calculate the number of chain buffers needed per I/O
		 * then multiply by the maximum number of simultaneous cmds
		 *
		 * scale = num sge per chain buffer if no chain element
		 * scale1 = num sge in intermediate chain buffers
		 * num_sge = num sge in request frame + last chain buffer
		 * numSGE = total num sge in intermediate chain buffers
		 * maxSGEs = maximum number of SGE's per IO
		 */
		SGE_size = ioc->SGE_size;
		scale = ioc->req_sz/SGE_size;
		scale1 = scale - 1;
		dinitprintk((KERN_INFO MYNAM ": %s dma_addr_t size=%d u64 size=%d sg_addr_size=%d\n",
			ioc->name, (int)sizeof(dma_addr_t), (int)sizeof(u64), ioc->sg_addr_size));
		num_sge =  scale + (ioc->req_sz - 48 - SGE_size) / (SGE_size);

		numSGE = scale1 * (ioc->facts.MaxChainDepth-1);
		maxSGEs = num_sge + numSGE;
		dinitprintk((KERN_INFO MYNAM ": %s req_sz=%d SGE_size=%d scale=%d num_sge=%d"
			" numSGE=%d MaxChainDepth=%d maxSGEs=%d mpt_sg_tablesize=%d\n",
			ioc->name, ioc->req_sz, SGE_size, scale, num_sge, numSGE, 
			ioc->facts.MaxChainDepth, maxSGEs, mpt_sg_tablesize));
		max_sg_tablesize = mpt_sg_tablesize;
		if (max_sg_tablesize > maxSGEs) {
			max_sg_tablesize = maxSGEs;
			dinitprintk((KERN_INFO MYNAM ": %s max_sg_tablesize=%d now\n",
				ioc->name, max_sg_tablesize));
		} else if (max_sg_tablesize < maxSGEs) {
			numSGE = max_sg_tablesize - num_sge;
			dinitprintk((KERN_INFO MYNAM ": %s numSGE=%d now\n",
				ioc->name, numSGE));
		}

		num_chain = 1;
		while (numSGE > 0) {
			num_chain++;
			numSGE -= scale1;
		}

		dinitprintk((KERN_INFO MYNAM ": %s Now num_chain=%d\n",
			ioc->name, num_chain));

		num_chain *= ioc->req_depth;

		total_num_chain = num_chain * mpt_chain_alloc_percent / 100;

		numSGE = scale1 * (total_num_chain-1);
		maxSGEs = num_sge + numSGE;
		if (max_sg_tablesize > maxSGEs) {
			max_sg_tablesize = maxSGEs;
			dinitprintk((KERN_INFO MYNAM ": %s max_sg_tablesize=%d now, maxSGEs=%d numSGE=%d\n",
				ioc->name, max_sg_tablesize, maxSGEs, numSGE));
		}
		ioc->sg_tablesize = max_sg_tablesize;

		dinitprintk((KERN_INFO MYNAM ": %s req_depth=%d max num_chain=%d mpt_chain_alloc_percent=%d total_num_chain=%d\n",
			ioc->name, ioc->req_depth, num_chain, mpt_chain_alloc_percent, total_num_chain));
		ioc->num_chain = total_num_chain;

		total_size = reply_sz = (ioc->reply_sz * ioc->reply_depth);
		dinitprintk((KERN_INFO MYNAM ": %s ReplyBuffer sz=%d bytes, ReplyDepth=%d\n",
			 	ioc->name, ioc->reply_sz, ioc->reply_depth));
		dinitprintk((KERN_INFO MYNAM ": %s Total ReplyBuffer sz=%d[%x] bytes\n",
			 	ioc->name, reply_sz, reply_sz));

		req_sz = ioc->req_sz;
		sz = (req_sz * ioc->req_depth);
		dinitprintk((KERN_INFO MYNAM ": %s RequestBuffer sz=%d bytes, RequestDepth=%d\n",
			 	ioc->name, req_sz, ioc->req_depth));
		dinitprintk((KERN_INFO MYNAM ": %s Total RequestBuffer sz=%d[%x] bytes\n",
			 	ioc->name, sz, sz));
		total_size += sz;

		sz = total_num_chain * req_sz; /* chain buffer pool size */
		dinitprintk((KERN_INFO MYNAM ": %s Total ChainBuffer sz=%d[%x] bytes total_num_chain=%d\n",
			 	ioc->name, sz, sz, total_num_chain));

		total_size += sz;
		dinitprintk((KERN_INFO MYNAM ": %s Total ioc alloc size=%d[%x] bytes\n",
			 	ioc->name, total_size, total_size));

		mem = pci_alloc_consistent(ioc->pcidev, total_size, &alloc_dma);
		if (mem == NULL) {
			printk(MYIOC_s_ERR_FMT "Unable to allocate Reply, Request, Chain Buffers for size=%d[%x] bytes!\n",
				ioc->name, total_size, total_size);
			goto out_fail;
		}

		dinitprintk((KERN_INFO MYNAM ": %s Total ioc alloc @ %p[%p]\n",
			 	ioc->name, mem, (void *)(ulong)alloc_dma));

		memset(mem, 0, total_size);
		ioc->alloc_total += total_size;
		ioc->alloc = mem;
		ioc->alloc_dma = alloc_dma;
		ioc->alloc_sz = total_size;
		ioc->reply_frames = (MPT_FRAME_HDR *) mem;
		ioc->reply_frames_low_dma = (u32) (alloc_dma & 0xFFFFFFFF);

		dinitprintk((KERN_INFO MYNAM ": %s ReplyBuffers @ %p[%p]\n",
	 		ioc->name, ioc->reply_frames, (void *)(ulong)alloc_dma));

		alloc_dma += reply_sz;
		mem += reply_sz;

		/*  Request FIFO - WE manage this!  */

		ioc->req_frames = (MPT_FRAME_HDR *) mem;
		ioc->req_frames_dma = alloc_dma;

		dinitprintk((KERN_INFO MYNAM ": %s RequestBuffers @ %p[%p]\n",
			 	ioc->name, mem, (void *)(ulong)alloc_dma));

		ioc->req_frames_low_dma = (u32) (alloc_dma & 0xFFFFFFFF);

#if defined(CONFIG_MTRR) && 0
		/*
		 *  Enable Write Combining MTRR for IOC's memory region.
		 *  (at least as much as we can; "size and base must be
		 *  multiples of 4 kiB"
		 */
		ioc->mtrr_reg = mtrr_add(ioc->req_frames_dma,
					 sz,
					 MTRR_TYPE_WRCOMB, 1);
		dprintk((MYIOC_s_INFO_FMT "MTRR region registered (base:size=%08x:%x)\n",
				ioc->name, ioc->req_frames_dma, sz));
#endif

		for (i = 0; i < ioc->req_depth; i++) {
			alloc_dma += req_sz;
			mem += req_sz;
		}

		ioc->ChainBuffer = mem;
		ioc->ChainBufferDMA = alloc_dma;

		dinitprintk((KERN_INFO MYNAM ": %s ChainBuffers @ %p(%p)\n",
			ioc->name, ioc->ChainBuffer, (void *)(ulong)ioc->ChainBufferDMA));

		/* Initialize the free chain Q.
	 	*/

		INIT_LIST_HEAD(&ioc->FreeChainQ);

		/* Post the chain buffers to the FreeChainQ.
	 	*/
		mem = (u8 *)ioc->ChainBuffer;
		for (i=0; i < total_num_chain; i++) {
			mf = (MPT_FRAME_HDR *) mem;
			list_add_tail(&mf->u.frame.linkage.list, &ioc->FreeChainQ);
//			dinitprintk((MYIOC_s_INFO_FMT "Adding %p to FreeChainQ at %d\n",
 //				ioc->name, mf, i));
			mem += req_sz;
		}

		/* Initialize Request frames linked list
		 */
		alloc_dma = ioc->req_frames_dma;
		mem = (u8 *) ioc->req_frames;

		spin_lock_irqsave(&ioc->FreeQlock, flags);
		INIT_LIST_HEAD(&ioc->FreeQ);
		for (i = 0; i < ioc->req_depth; i++) {
			mf = (MPT_FRAME_HDR *) mem;

			/*  Queue REQUESTs *internally*!  */
			list_add_tail(&mf->u.frame.linkage.list, &ioc->FreeQ);
			mem += req_sz;
		}
		spin_unlock_irqrestore(&ioc->FreeQlock, flags);

		sz = (ioc->req_depth * MPT_SENSE_BUFFER_ALLOC);
		ioc->sense_buf_pool =
			pci_alloc_consistent(ioc->pcidev, sz, &ioc->sense_buf_pool_dma);
		if (ioc->sense_buf_pool == NULL) {
			printk(MYIOC_s_ERR_FMT "Unable to allocate Sense Buffers req_depth=%d sz=%d!\n",
				ioc->name, ioc->req_depth, sz);
			goto out_fail;
		}

		ioc->sense_buf_low_dma = (u32) (ioc->sense_buf_pool_dma & 0xFFFFFFFF);
		ioc->alloc_total += sz;
		dinitprintk((KERN_INFO MYNAM ": %s SenseBuffers @ %p[%p]\n",
			ioc->name, ioc->sense_buf_pool, (void *)(ulong)ioc->sense_buf_pool_dma));

	}

	if ( mpt_initChainBuffers(ioc) < 0)
		goto out_fail;

	/* Post Reply frames to FIFO
	 */
	alloc_dma = ioc->alloc_dma;
	for (i = 0; i < ioc->reply_depth; i++) {
		/*  Write each address to the IOC!  */
		CHIPREG_WRITE32(&ioc->chip->ReplyFifo, alloc_dma);
		alloc_dma += ioc->reply_sz;
	}

	if (dma_mask == MPT_DMA_35BIT_MASK) {
		if (pci_set_dma_mask(ioc->pcidev, ioc->dma_mask)) {
			dinitprintk((MYIOC_s_WARN_FMT "%s at %d: resetting dma_mask failed\n",
			   ioc->name, __FUNCTION__, __LINE__));
		}
	}

	return 0;

out_fail:
	if (ioc->alloc != NULL) {
		sz = ioc->alloc_sz;
		pci_free_consistent(ioc->pcidev,
				sz,
				ioc->alloc, ioc->alloc_dma);
		ioc->reply_frames = NULL;
		ioc->req_frames = NULL;
		ioc->alloc_total -= sz;
	}
	if (ioc->sense_buf_pool != NULL) {
		sz = (ioc->req_depth * MPT_SENSE_BUFFER_ALLOC);
		pci_free_consistent(ioc->pcidev,
				sz,
				ioc->sense_buf_pool, ioc->sense_buf_pool_dma);
		ioc->sense_buf_pool = NULL;
	}

	if (dma_mask == MPT_DMA_35BIT_MASK) {
		if (pci_set_dma_mask(ioc->pcidev, ioc->dma_mask)) {
			dinitprintk((MYIOC_s_WARN_FMT "out_fail in %s at %d: resetting dma_mask failed\n",
			   ioc->name, __FUNCTION__, __LINE__));
		}
	}

	return -1;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_handshake_req_reply_wait - Send MPT request to and receive reply
 *	from IOC via doorbell handshake method.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@reqBytes: Size of the request in bytes
 *	@req: Pointer to MPT request frame
 *	@replyBytes: Expected size of the reply in bytes
 *	@u16reply: Pointer to area where reply should be written
 *	@maxwait: Max wait time for a reply (in seconds)
 *	@sleepFlag: Specifies whether the process can sleep
 *
 *	NOTES: It is the callers responsibility to byte-swap fields in the
 *	request which are greater than 1 byte in size.  It is also the
 *	callers responsibility to byte-swap response fields which are
 *	greater than 1 byte in size.
 *
 *	Returns 0 for success, non-zero for failure.
 */
int mpt_handshake_req_reply_wait(MPT_ADAPTER *ioc, int reqBytes, u32 *req,
		int replyBytes, u16 *u16reply, int maxwait, int sleepFlag)
{
	MPIDefaultReply_t *mptReply;
	int failcnt = 0;
	int t;

	/*
	 * Get ready to cache a handshake reply
	 */
	ioc->hs_reply_idx = 0;
	mptReply = (MPIDefaultReply_t *) ioc->hs_reply;
	mptReply->MsgLength = 0;

	/*
	 * Make sure there are no doorbells (WRITE 0 to IntStatus reg),
	 * then tell IOC that we want to handshake a request of N words.
	 * (WRITE u32val to Doorbell reg).
	 */
	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);
	CHIPREG_WRITE32(&ioc->chip->Doorbell,
			((MPI_FUNCTION_HANDSHAKE<<MPI_DOORBELL_FUNCTION_SHIFT) |
			 ((reqBytes/4)<<MPI_DOORBELL_ADD_DWORDS_SHIFT)));

	/*
	 * Wait for IOC's doorbell handshake int
	 */
	if ((t = WaitForDoorbellInt(ioc, 5, sleepFlag)) < 0)
		failcnt++;

	dhsprintk((MYIOC_s_INFO_FMT "HandShake request start reqBytes=%d, WaitCnt=%d%s\n",
			ioc->name, reqBytes, t, failcnt ? " - MISSING DOORBELL HANDSHAKE!" : ""));

	/* Read doorbell and check for active bit */
	if (!(CHIPREG_READ32(&ioc->chip->Doorbell) & MPI_DOORBELL_ACTIVE))
			return -1;

	/*
	 * Clear doorbell int (WRITE 0 to IntStatus reg),
	 * then wait for IOC to ACKnowledge that it's ready for
	 * our handshake request.
	 */
	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);
	if (!failcnt && (t = WaitForDoorbellAck(ioc, 5, sleepFlag)) < 0)
		failcnt++;

	if (!failcnt) {
		int	 ii;
		u8	*req_as_bytes = (u8 *) req;

		/*
		 * Stuff request words via doorbell handshake,
		 * with ACK from IOC for each.
		 */
		for (ii = 0; !failcnt && ii < reqBytes/4; ii++) {
			u32 word = ((req_as_bytes[(ii*4) + 0] <<  0) |
				    (req_as_bytes[(ii*4) + 1] <<  8) |
				    (req_as_bytes[(ii*4) + 2] << 16) |
				    (req_as_bytes[(ii*4) + 3] << 24));

			CHIPREG_WRITE32(&ioc->chip->Doorbell, word);
			if ((t = WaitForDoorbellAck(ioc, 5, sleepFlag)) < 0)
				failcnt++;
		}

		dhsprintk((KERN_INFO MYNAM ": Handshake request frame (@%p) header\n", req));
		DBG_DUMP_REQUEST_FRAME_HDR(req)

		dhsprintk((MYIOC_s_INFO_FMT "HandShake request post done, WaitCnt=%d%s\n",
				ioc->name, t, failcnt ? " - MISSING DOORBELL ACK!" : ""));

		/*
		 * Wait for completion of doorbell handshake reply from the IOC
		 */
		if (!failcnt && (t = WaitForDoorbellReply(ioc, maxwait, sleepFlag)) < 0)
			failcnt++;

		dhsprintk((MYIOC_s_INFO_FMT "HandShake reply count=%d%s\n",
				ioc->name, t, failcnt ? " - MISSING DOORBELL REPLY!" : ""));

		/*
		 * Copy out the cached reply...
		 */
		for (ii=0; ii < min(replyBytes/2,mptReply->MsgLength*2); ii++)
			u16reply[ii] = ioc->hs_reply[ii];
	} else {
		return -99;
	}

	return -failcnt;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	WaitForDoorbellAck - Wait for IOC to clear the IOP_DOORBELL_STATUS bit
 *	in it's IntStatus register.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@howlong: How long to wait (in seconds)
 *	@sleepFlag: Specifies whether the process can sleep
 *
 *	This routine waits (up to ~2 seconds max) for IOC doorbell
 *	handshake ACKnowledge.
 *
 *	Returns a negative value on failure, else wait loop count.
 */
static int
WaitForDoorbellAck(MPT_ADAPTER *ioc, int howlong, int sleepFlag)
{
	int cntdn;
	int count = 0;
	u32 intstat=0;

	cntdn = 1000 * howlong;

	if (sleepFlag == CAN_SLEEP) {
		while (--cntdn) {
			intstat = CHIPREG_READ32(&ioc->chip->IntStatus);
			if (! (intstat & MPI_HIS_IOP_DOORBELL_STATUS))
				break;
			msleep_interruptible(10);
			count++;
		}
	} else {
		while (--cntdn) {
			intstat = CHIPREG_READ32(&ioc->chip->IntStatus);
			if (! (intstat & MPI_HIS_IOP_DOORBELL_STATUS))
				break;
			udelay(1000);
			count++;
		}
	}

	if (cntdn) {
		dprintk((MYIOC_s_INFO_FMT "WaitForDoorbell ACK (count=%d)\n",
				ioc->name, count));
		return count;
	}

	printk(MYIOC_s_ERR_FMT "Doorbell ACK timeout (count=%d), IntStatus=%x!\n",
			ioc->name, count, intstat);
	return -1;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	WaitForDoorbellInt - Wait for IOC to set the HIS_DOORBELL_INTERRUPT bit
 *	in it's IntStatus register.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@howlong: How long to wait (in seconds)
 *	@sleepFlag: Specifies whether the process can sleep
 *
 *	This routine waits (up to ~2 seconds max) for IOC doorbell interrupt.
 *
 *	Returns a negative value on failure, else wait loop count.
 */
static int
WaitForDoorbellInt(MPT_ADAPTER *ioc, int howlong, int sleepFlag)
{
	int cntdn;
	int count = 1;
	u32 intstat=0;

	cntdn = 1000 * howlong;
	if (sleepFlag == CAN_SLEEP) {
		while (--cntdn) {
			intstat = CHIPREG_READ32(&ioc->chip->IntStatus);
			if (intstat & MPI_HIS_DOORBELL_INTERRUPT)
				break;
			msleep_interruptible(10);
			count++;
		}
	} else {
		while (--cntdn) {
			intstat = CHIPREG_READ32(&ioc->chip->IntStatus);
			if (intstat & MPI_HIS_DOORBELL_INTERRUPT)
				break;
			udelay(1000);
			count++;
		}
	}

	if (cntdn) {
		dprintk((MYIOC_s_INFO_FMT "WaitForDoorbell INT (cnt=%d) howlong=%d\n",
				ioc->name, count, howlong));
		return count;
	}

	printk(MYIOC_s_ERR_FMT "Doorbell INT timeout (count=%d), IntStatus=%x!\n",
			ioc->name, count, intstat);
	return -1;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	WaitForDoorbellReply - Wait for and capture a IOC handshake reply.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@howlong: How long to wait (in seconds)
 *	@sleepFlag: Specifies whether the process can sleep
 *
 *	This routine polls the IOC for a handshake reply, 16 bits at a time.
 *	Reply is cached to IOC private area large enough to hold a maximum
 *	of 128 bytes of reply data.
 *
 *	Returns a negative value on failure, else size of reply in WORDS.
 */
static int
WaitForDoorbellReply(MPT_ADAPTER *ioc, int howlong, int sleepFlag)
{
	int u16cnt = 0;
	int failcnt = 0;
	int t;
	u16 *hs_reply = ioc->hs_reply;
	volatile MPIDefaultReply_t *mptReply = (MPIDefaultReply_t *) ioc->hs_reply;
	u16 hword;

	hs_reply[0] = hs_reply[1] = hs_reply[7] = 0;

	/*
	 * Get first two u16's so we can look at IOC's intended reply MsgLength
	 */
	u16cnt=0;
	if ((t = WaitForDoorbellInt(ioc, howlong, sleepFlag)) < 0) {
		failcnt++;
	} else {
		hs_reply[u16cnt++] = le16_to_cpu(CHIPREG_READ32(&ioc->chip->Doorbell) & 0x0000FFFF);
		CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);
		if ((t = WaitForDoorbellInt(ioc, 5, sleepFlag)) < 0)
			failcnt++;
		else {
			hs_reply[u16cnt++] = le16_to_cpu(CHIPREG_READ32(&ioc->chip->Doorbell) & 0x0000FFFF);
			CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);
		}
	}

	dhsprintk((MYIOC_s_INFO_FMT "WaitCnt=%d First handshake reply word=%08x%s\n",
			ioc->name, t, le32_to_cpu(*(u32 *)hs_reply), 
			failcnt ? " - MISSING DOORBELL HANDSHAKE!" : ""));

	/*
	 * If no error (and IOC said MsgLength is > 0), piece together
	 * reply 16 bits at a time.
	 */
	for (u16cnt=2; !failcnt && u16cnt < (2 * mptReply->MsgLength); u16cnt++) {
		if ((t = WaitForDoorbellInt(ioc, 5, sleepFlag)) < 0)
			failcnt++;
		hword = le16_to_cpu(CHIPREG_READ32(&ioc->chip->Doorbell) & 0x0000FFFF);
		/* don't overflow our IOC hs_reply[] buffer! */
		if (u16cnt < sizeof(ioc->hs_reply) / sizeof(ioc->hs_reply[0]))
			hs_reply[u16cnt] = hword;
		CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);
	}

	if (!failcnt && (t = WaitForDoorbellInt(ioc, 5, sleepFlag)) < 0)
		failcnt++;
	CHIPREG_WRITE32(&ioc->chip->IntStatus, 0);

	if (failcnt) {
		printk(MYIOC_s_ERR_FMT "Handshake reply failure!\n",
				ioc->name);
		return -failcnt;
	}
#if 0
	else if (u16cnt != (2 * mptReply->MsgLength)) {
		return -101;
	}
	else if ((mptReply->IOCStatus & MPI_IOCSTATUS_MASK) != MPI_IOCSTATUS_SUCCESS) {
		return -102;
	}
#endif

	dhsprintk((MYIOC_s_INFO_FMT "Got Handshake reply:\n", ioc->name));
	DBG_DUMP_REPLY_FRAME(mptReply)

	dhsprintk((MYIOC_s_INFO_FMT "WaitForDoorbell REPLY WaitCnt=%d (sz=%d)\n",
			ioc->name, t, u16cnt/2));
	return u16cnt/2;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	GetLanConfigPages - Fetch LANConfig pages.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *
 *	Return: 0 for success
 *	-ENOMEM if no memory available
 *		-EPERM if not allowed due to ISR context
 *		-EAGAIN if no msg frames currently available
 *		-EFAULT for non-successful reply or no reply (timeout)
 */
static int
GetLanConfigPages(MPT_ADAPTER *ioc)
{
	ConfigPageHeader_t	 hdr;
	CONFIGPARMS		 cfg;
	LANPage0_t		*ppage0_alloc;
	dma_addr_t		 page0_dma;
	LANPage1_t		*ppage1_alloc;
	dma_addr_t		 page1_dma;
	int			 rc = 0;
	int			 data_sz;
	int			 copy_sz;

	/* Get LAN Page 0 header */
	hdr.PageVersion = 0;
	hdr.PageLength = 0;
	hdr.PageNumber = 0;
	hdr.PageType = MPI_CONFIG_PAGETYPE_LAN;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.pageAddr = 0;
	cfg.timeout = 0;

	if ((rc = mpt_config(ioc, &cfg)) != 0)
		return rc;

	if (hdr.PageLength > 0) {
		data_sz = hdr.PageLength * 4;
		ppage0_alloc = (LANPage0_t *) pci_alloc_consistent(ioc->pcidev, data_sz, &page0_dma);
		rc = -ENOMEM;
		if (ppage0_alloc) {
			memset((u8 *)ppage0_alloc, 0, data_sz);
			cfg.physAddr = page0_dma;
			cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

			if ((rc = mpt_config(ioc, &cfg)) == 0) {
				/* save the data */
				copy_sz = min_t(int, sizeof(LANPage0_t), data_sz);
				memcpy(&ioc->lan_cnfg_page0, ppage0_alloc, copy_sz);

			}

			pci_free_consistent(ioc->pcidev, data_sz, (u8 *) ppage0_alloc, page0_dma);

			/* FIXME!
			 *	Normalize endianness of structure data,
			 *	by byte-swapping all > 1 byte fields!
			 */

		}

		if (rc)
			return rc;
	}

	/* Get LAN Page 1 header */
	hdr.PageVersion = 0;
	hdr.PageLength = 0;
	hdr.PageNumber = 1;
	hdr.PageType = MPI_CONFIG_PAGETYPE_LAN;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.pageAddr = 0;

	if ((rc = mpt_config(ioc, &cfg)) != 0)
		return rc;

	if (hdr.PageLength == 0)
		return 0;

	data_sz = hdr.PageLength * 4;
	rc = -ENOMEM;
	ppage1_alloc = (LANPage1_t *) pci_alloc_consistent(ioc->pcidev, data_sz, &page1_dma);
	if (ppage1_alloc) {
		memset((u8 *)ppage1_alloc, 0, data_sz);
		cfg.physAddr = page1_dma;
		cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

		if ((rc = mpt_config(ioc, &cfg)) == 0) {
			/* save the data */
			copy_sz = min_t(int, sizeof(LANPage1_t), data_sz);
			memcpy(&ioc->lan_cnfg_page1, ppage1_alloc, copy_sz);
		}

		pci_free_consistent(ioc->pcidev, data_sz, (u8 *) ppage1_alloc, page1_dma);

		/* FIXME!
		 *	Normalize endianness of structure data,
		 *	by byte-swapping all > 1 byte fields!
		 */

	}

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	GetFcPortPage0 - Fetch FCPort config Page0.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@portnum: IOC Port number
 *
 *	Return: 0 for success
 *	-ENOMEM if no memory available
 *		-EPERM if not allowed due to ISR context
 *		-EAGAIN if no msg frames currently available
 *		-EFAULT for non-successful reply or no reply (timeout)
 */
static int
GetFcPortPage0(MPT_ADAPTER *ioc, int portnum)
{
	ConfigPageHeader_t	 hdr;
	CONFIGPARMS		 cfg;
	FCPortPage0_t		*ppage0_alloc;
	FCPortPage0_t		*pp0dest;
	dma_addr_t		 page0_dma;
	int			 data_sz;
	int			 copy_sz;
	int			 rc;

	/* Get FCPort Page 0 header */
	hdr.PageVersion = 0;
	hdr.PageLength = 0;
	hdr.PageNumber = 0;
	hdr.PageType = MPI_CONFIG_PAGETYPE_FC_PORT;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.pageAddr = portnum;
	cfg.timeout = 0;

	if ((rc = mpt_config(ioc, &cfg)) != 0)
		return rc;

	if (hdr.PageLength == 0)
		return 0;

	data_sz = hdr.PageLength * 4;
	rc = -ENOMEM;
	ppage0_alloc = (FCPortPage0_t *) pci_alloc_consistent(ioc->pcidev, data_sz, &page0_dma);
	if (ppage0_alloc) {
		memset((u8 *)ppage0_alloc, 0, data_sz);
		cfg.physAddr = page0_dma;
		cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

		if ((rc = mpt_config(ioc, &cfg)) == 0) {
			/* save the data */
			pp0dest = &ioc->fc_port_page0[portnum];
			copy_sz = min_t(int, sizeof(FCPortPage0_t), data_sz);
			memcpy(pp0dest, ppage0_alloc, copy_sz);

			/*
			 *	Normalize endianness of structure data,
			 *	by byte-swapping all > 1 byte fields!
			 */
			pp0dest->Flags = le32_to_cpu(pp0dest->Flags);
			pp0dest->PortIdentifier = le32_to_cpu(pp0dest->PortIdentifier);
			pp0dest->WWNN.Low = le32_to_cpu(pp0dest->WWNN.Low);
			pp0dest->WWNN.High = le32_to_cpu(pp0dest->WWNN.High);
			pp0dest->WWPN.Low = le32_to_cpu(pp0dest->WWPN.Low);
			pp0dest->WWPN.High = le32_to_cpu(pp0dest->WWPN.High);
			pp0dest->SupportedServiceClass = le32_to_cpu(pp0dest->SupportedServiceClass);
			pp0dest->SupportedSpeeds = le32_to_cpu(pp0dest->SupportedSpeeds);
			pp0dest->CurrentSpeed = le32_to_cpu(pp0dest->CurrentSpeed);
			pp0dest->MaxFrameSize = le32_to_cpu(pp0dest->MaxFrameSize);
			pp0dest->FabricWWNN.Low = le32_to_cpu(pp0dest->FabricWWNN.Low);
			pp0dest->FabricWWNN.High = le32_to_cpu(pp0dest->FabricWWNN.High);
			pp0dest->FabricWWPN.Low = le32_to_cpu(pp0dest->FabricWWPN.Low);
			pp0dest->FabricWWPN.High = le32_to_cpu(pp0dest->FabricWWPN.High);
			pp0dest->DiscoveredPortsCount = le32_to_cpu(pp0dest->DiscoveredPortsCount);
			pp0dest->MaxInitiators = le32_to_cpu(pp0dest->MaxInitiators);

		}

		pci_free_consistent(ioc->pcidev, data_sz, (u8 *) ppage0_alloc, page0_dma);
	}

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	GetManufPage5 - Fetch Manufacturing config Page5.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@numPorts: number of ports for this IOC
 *
 *	Return: 0 for success
 *	-ENOMEM if no memory available
 *		-EPERM if not allowed due to ISR context
 *		-EAGAIN if no msg frames currently available
 *		-EFAULT for non-successful reply or no reply (timeout)
 */
static int
GetManufPage5(MPT_ADAPTER *ioc, int numPorts)
{
	ConfigPageHeader_t	hdr;
	CONFIGPARMS		cfg;
	ManufacturingPage5_t	*mfgPage5=NULL;
	dma_addr_t		mfgPage5_dma;
	int			data_sz=0;
	int			rc;
	int			ii;

	/* Get Manufacturing Page 5 header */
	hdr.PageVersion = MPI_MANUFACTURING5_PAGEVERSION;
	hdr.PageLength = 0;
	hdr.PageNumber = 5;
	hdr.PageType = MPI_CONFIG_PAGETYPE_MANUFACTURING;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.pageAddr = 0;
	cfg.timeout = 0;

	if ((rc = mpt_config(ioc, &cfg)) != 0) {
		goto GetManufPage5_exit;
	}

	if (hdr.PageLength == 0) {
		rc = -EFAULT;
		goto GetManufPage5_exit;
	}

	data_sz = hdr.PageLength * 4;
	mfgPage5 = (ManufacturingPage5_t *) pci_alloc_consistent(ioc->pcidev,
	    data_sz, &mfgPage5_dma);
	if (!mfgPage5) {
		rc = -ENOMEM;
		goto GetManufPage5_exit;
	}

	memset((u8 *)mfgPage5, 0, data_sz);
	cfg.physAddr = mfgPage5_dma;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

	if ((rc = mpt_config(ioc, &cfg)) != 0) {
		goto GetManufPage5_exit;
	}

	/*
	 * Normalize endianness of structure data,
	 * by byte-swapping all > 1 byte fields!
	 */

	ioc->sas_port_WWID[0].Low =
	    le32_to_cpu(mfgPage5->BaseWWID.Low);
	ioc->sas_port_WWID[0].High =
	    le32_to_cpu(mfgPage5->BaseWWID.High);

	/* The rest of the ports are numbered by
	 * incrementing the base WWID.
	 */
	for (ii = 1; ii < numPorts; ii++) {
		if (ioc->sas_port_WWID[ii-1].Low != 0xFFFFFFFF){
			ioc->sas_port_WWID[ii].Low =
			    ioc->sas_port_WWID[ii -1].Low + 1;
			ioc->sas_port_WWID[ii].High =
			    ioc->sas_port_WWID[ii-1].High;
		} else {
			ioc->sas_port_WWID[ii].Low = 0;
			ioc->sas_port_WWID[ii].High =
			    ioc->sas_port_WWID[ii-1].High + 1;
		}

	}

GetManufPage5_exit:

	if (mfgPage5)
		pci_free_consistent(ioc->pcidev, data_sz,
		    (u8 *) mfgPage5, mfgPage5_dma);

	return rc;
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	GetManufPage0 - Fetch Manufacturing config Page0.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@numPorts: number of ports for this IOC
 *
 *	Return: 0 for success
 *	-ENOMEM if no memory available
 *		-EPERM if not allowed due to ISR context
 *		-EAGAIN if no msg frames currently available
 *		-EFAULT for non-successful reply or no reply (timeout)
 */
static int
GetManufPage0(MPT_ADAPTER *ioc)
{

	ConfigPageHeader_t	 hdr;
	CONFIGPARMS		 cfg;
	ManufacturingPage0_t	*mfgPage0=NULL;
	dma_addr_t		 mfgPage0_dma;
	int			 data_sz=0;
	int			 rc;

	/* Get Manufacturing Page 0 header */
	hdr.PageVersion = MPI_MANUFACTURING0_PAGEVERSION;
	hdr.PageLength = 0;
	hdr.PageNumber = 0;
	hdr.PageType = MPI_CONFIG_PAGETYPE_MANUFACTURING;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.pageAddr = 0;
	cfg.timeout = 0;

	if ((rc = mpt_config(ioc, &cfg)) != 0) {
		return rc;
		goto GetManufPage0_exit;
	}

	if (hdr.PageLength == 0) {
		rc = -EFAULT;
		goto GetManufPage0_exit;
	}

	data_sz = hdr.PageLength * 4;
	mfgPage0 = (ManufacturingPage0_t *) pci_alloc_consistent(ioc->pcidev,
		data_sz, &mfgPage0_dma);
	if (!mfgPage0) {
		rc = -ENOMEM;
		goto GetManufPage0_exit;
	}

	memset((u8 *)mfgPage0, 0, data_sz);
	cfg.physAddr = mfgPage0_dma;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

	if ((rc = mpt_config(ioc, &cfg)) != 0) {
		return rc;
		goto GetManufPage0_exit;
	}

	/*
	 *	Normalize endianness of structure data,
	 *	by byte-swapping all > 1 byte fields!
	 */
	memcpy( ioc->board_tracer,
	    mfgPage0->BoardTracerNumber, 16 );


GetManufPage0_exit:

	if (mfgPage0)
		pci_free_consistent(ioc->pcidev, data_sz,
		    (u8 *) mfgPage0, mfgPage0_dma);


	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptbase_sas_persist_operation - Perform operation on SAS Persitent Table
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@sas_address: 64bit SAS Address for operation.
 *	@target_id: specified target for operation
 *	@bus: specified bus for operation
 *	@persist_opcode: see below
 *
 *	MPI_SAS_OP_CLEAR_NOT_PRESENT - Free all persist TargetID mappings for
 *		devices not currently present.
 *	MPI_SAS_OP_CLEAR_ALL_PERSISTENT - Clear al persist TargetID mappings
 *
 *	NOTE: Don't use not this function during interrupt time.
 *
 *	Returns: 0 for success, non-zero error
 */

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
int
mptbase_sas_persist_operation(MPT_ADAPTER *ioc, u8 persist_opcode)
{
	SasIoUnitControlRequest_t	*sasIoUnitCntrReq;
	SasIoUnitControlReply_t		*sasIoUnitCntrReply;
	MPT_FRAME_HDR			*mf = NULL;
	MPIHeader_t			*mpi_hdr;


	/* insure garbage is not sent to fw */
	switch(persist_opcode) {

	case MPI_SAS_OP_CLEAR_NOT_PRESENT:
	case MPI_SAS_OP_CLEAR_ALL_PERSISTENT:
		break;

	default:
		return -1;
		break;
	}

	printk("%s: persist_opcode=%x\n",__FUNCTION__, persist_opcode);

	/* Get a MF for this command.
	 */
	if ((mf = mpt_get_msg_frame(mpt_base_index, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return -1;
        }

	mpi_hdr = (MPIHeader_t *) mf;
	sasIoUnitCntrReq = (SasIoUnitControlRequest_t *)mf;
	memset(sasIoUnitCntrReq,0,sizeof(SasIoUnitControlRequest_t));
	sasIoUnitCntrReq->Function = MPI_FUNCTION_SAS_IO_UNIT_CONTROL;
	sasIoUnitCntrReq->MsgContext = mpi_hdr->MsgContext;
	sasIoUnitCntrReq->Operation = persist_opcode;

	init_timer(&ioc->persist_timer);
	ioc->persist_timer.data = (unsigned long) ioc;
	ioc->persist_timer.function = mpt_timer_expired;
	ioc->persist_timer.expires = jiffies + HZ*10 /* 10 sec */;
	ioc->persist_wait_done=0;
	add_timer(&ioc->persist_timer);
	mpt_put_msg_frame(mpt_base_index, ioc, mf);
	wait_event(mpt_waitq, ioc->persist_wait_done);

	sasIoUnitCntrReply =
	    (SasIoUnitControlReply_t *)ioc->persist_reply_frame;
	if ( le16_to_cpu(sasIoUnitCntrReply->IOCStatus) != MPI_IOCSTATUS_SUCCESS) {
		printk("%s: IOCStatus=0x%X IOCLogInfo=0x%X\n",
		    __FUNCTION__,
		    sasIoUnitCntrReply->IOCStatus,
		    sasIoUnitCntrReply->IOCLogInfo);
		return -1;
	}

	printk("%s: success\n",__FUNCTION__);
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/

static void
mptbase_raid_process_event_data(MPT_ADAPTER *ioc,
    MpiEventDataRaid_t * pRaidEventData)
{
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	int 	id, bus;
	int 	reason;
	int 	disk;
	int 	status;
	int 	flags;
	int 	state;

	id	= pRaidEventData->VolumeID;
	reason	= pRaidEventData->ReasonCode;
	disk	= pRaidEventData->PhysDiskNum;
	status	= le32_to_cpu(pRaidEventData->SettingsStatus);
	flags	= (status >> 0) & 0xff;
	state	= (status >> 8) & 0xff;

	if (reason == MPI_EVENT_RAID_RC_DOMAIN_VAL_NEEDED) {
		return;
	}

	if ((reason >= MPI_EVENT_RAID_RC_PHYSDISK_CREATED &&
	     reason <= MPI_EVENT_RAID_RC_PHYSDISK_STATUS_CHANGED) ||
	    (reason == MPI_EVENT_RAID_RC_SMART_DATA)) {
		printk(MYIOC_s_INFO_FMT "RAID STATUS CHANGE for PhysDisk %d\n",
			ioc->name, disk);
	} else {
		printk(MYIOC_s_INFO_FMT "RAID STATUS CHANGE for VolumeID %d\n",
			ioc->name, id);
	}

	switch(reason) {
	case MPI_EVENT_RAID_RC_VOLUME_CREATED:
		printk(MYIOC_s_INFO_FMT "  volume has been created\n",
			ioc->name);
		break;

	case MPI_EVENT_RAID_RC_VOLUME_DELETED:

		printk(MYIOC_s_INFO_FMT "  volume has been deleted\n",
			ioc->name);
		break;

	case MPI_EVENT_RAID_RC_VOLUME_SETTINGS_CHANGED:
		printk(MYIOC_s_INFO_FMT "  volume settings have been changed\n",
			ioc->name);
		break;

	case MPI_EVENT_RAID_RC_VOLUME_STATUS_CHANGED:
		bus	= pRaidEventData->VolumeBus;
		pMptTarget = ioc->Target_List[bus];
		pTarget = (VirtDevice *)pMptTarget->Target[id];
		if (pTarget) {
			if ((state == MPI_RAIDVOL0_STATUS_STATE_FAILED) ||
			    (state == MPI_RAIDVOL0_STATUS_STATE_MISSING)) {
				pTarget->tflags |= MPT_TARGET_FLAGS_DELETED;
			} else {
				pTarget->tflags &= ~MPT_TARGET_FLAGS_DELETED;
			}
		}
		printk(MYIOC_s_INFO_FMT "  volume is now %s%s%s%s\n",
			ioc->name,
			state == MPI_RAIDVOL0_STATUS_STATE_OPTIMAL
			 ? "optimal"
			 : state == MPI_RAIDVOL0_STATUS_STATE_DEGRADED
			  ? "degraded"
			  : state == MPI_RAIDVOL0_STATUS_STATE_FAILED
			   ? "failed"
			   : state == MPI_RAIDVOL0_STATUS_STATE_MISSING
			    ? "missing"
			    : "state unknown",
			flags & MPI_RAIDVOL0_STATUS_FLAG_ENABLED
			 ? ", enabled" : "",
			flags & MPI_RAIDVOL0_STATUS_FLAG_QUIESCED
			 ? ", quiesced" : "",
			flags & MPI_RAIDVOL0_STATUS_FLAG_RESYNC_IN_PROGRESS
			 ? ", resync in progress" : "" );
		break;

	case MPI_EVENT_RAID_RC_VOLUME_PHYSDISK_CHANGED:
		printk(MYIOC_s_INFO_FMT "  volume membership of PhysDisk %d has changed\n",
			ioc->name, disk);
		break;

	case MPI_EVENT_RAID_RC_PHYSDISK_CREATED:
		printk(MYIOC_s_INFO_FMT "  PhysDisk has been created\n",
			ioc->name);
		break;

	case MPI_EVENT_RAID_RC_PHYSDISK_DELETED:
		printk(MYIOC_s_INFO_FMT "  PhysDisk has been deleted\n",
			ioc->name);
		break;

	case MPI_EVENT_RAID_RC_PHYSDISK_SETTINGS_CHANGED:
		printk(MYIOC_s_INFO_FMT "  PhysDisk settings have been changed\n",
			ioc->name);
		break;

	case MPI_EVENT_RAID_RC_PHYSDISK_STATUS_CHANGED:
		printk(MYIOC_s_INFO_FMT "  PhysDisk is now %s%s%s\n",
			ioc->name,
			state == MPI_PHYSDISK0_STATUS_ONLINE
			 ? "online"
			 : state == MPI_PHYSDISK0_STATUS_MISSING
			  ? "missing"
			  : state == MPI_PHYSDISK0_STATUS_NOT_COMPATIBLE
			   ? "not compatible"
			   : state == MPI_PHYSDISK0_STATUS_FAILED
			    ? "failed"
			    : state == MPI_PHYSDISK0_STATUS_INITIALIZING
			     ? "initializing"
			     : state == MPI_PHYSDISK0_STATUS_OFFLINE_REQUESTED
			      ? "offline requested"
			      : state == MPI_PHYSDISK0_STATUS_FAILED_REQUESTED
			       ? "failed requested"
			       : state == MPI_PHYSDISK0_STATUS_OTHER_OFFLINE
			        ? "offline"
			        : "state unknown",
			flags & MPI_PHYSDISK0_STATUS_FLAG_OUT_OF_SYNC
			 ? ", out of sync" : "",
			flags & MPI_PHYSDISK0_STATUS_FLAG_QUIESCED
			 ? ", quiesced" : "" );
		break;

	case MPI_EVENT_RAID_RC_DOMAIN_VAL_NEEDED:
		printk(MYIOC_s_INFO_FMT "  Domain Validation needed for PhysDisk %d\n",
			ioc->name, disk);
		break;

	case MPI_EVENT_RAID_RC_SMART_DATA:
		printk(MYIOC_s_INFO_FMT "  SMART data received, ASC/ASCQ = %02xh/%02xh\n",
			ioc->name, pRaidEventData->ASC, pRaidEventData->ASCQ);
		break;

	case MPI_EVENT_RAID_RC_REPLACE_ACTION_STARTED:
		printk(MYIOC_s_INFO_FMT "  replacement of PhysDisk %d has started\n",
			ioc->name, disk);
		break;
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	GetIoUnitPage2 - Retrieve BIOS version and boot order information.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *
 *	Returns: 0 for success
 *	-ENOMEM if no memory available
 *		-EPERM if not allowed due to ISR context
 *		-EAGAIN if no msg frames currently available
 *		-EFAULT for non-successful reply or no reply (timeout)
 */
static int
GetIoUnitPage2(MPT_ADAPTER *ioc)
{
	ConfigPageHeader_t	 hdr;
	CONFIGPARMS		 cfg;
	IOUnitPage2_t		*ppage_alloc;
	dma_addr_t		 page_dma;
	int			 data_sz;
	int			 rc;

	/* Get the page header */
	hdr.PageVersion = 0;
	hdr.PageLength = 0;
	hdr.PageNumber = 2;
	hdr.PageType = MPI_CONFIG_PAGETYPE_IO_UNIT;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.pageAddr = 0;
	cfg.timeout = 0;

	if ((rc = mpt_config(ioc, &cfg)) != 0)
		return rc;

	if (hdr.PageLength == 0)
		return 0;

	/* Read the config page */
	data_sz = hdr.PageLength * 4;
	rc = -ENOMEM;
	ppage_alloc = (IOUnitPage2_t *) pci_alloc_consistent(ioc->pcidev, data_sz, &page_dma);
	if (ppage_alloc) {
		memset((u8 *)ppage_alloc, 0, data_sz);
		cfg.physAddr = page_dma;
		cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

		/* If Good, save data */
		if ((rc = mpt_config(ioc, &cfg)) == 0)
			ioc->biosVersion = le32_to_cpu(ppage_alloc->BiosVersion);

		pci_free_consistent(ioc->pcidev, data_sz, (u8 *) ppage_alloc, page_dma);
	}

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mpt_GetScsiPortSettings - read SCSI Port Page 0 and 2
 *	@ioc: Pointer to a Adapter Strucutre
 *	@portnum: IOC port number
 *
 *	Return: -EFAULT if read of config page header fails
 *			or if no nvram
 *	If read of SCSI Port Page 0 fails,
 *		NVRAM = MPT_HOST_NVRAM_INVALID  (0xFFFFFFFF)
 *		Adapter settings: async, narrow
 *		Return 1
 *	If read of SCSI Port Page 2 fails,
 *		Adapter settings valid
 *		NVRAM = MPT_HOST_NVRAM_INVALID  (0xFFFFFFFF)
 *		Return 1
 *	Else
 *		Both valid
 *		Return 0
 *	CHECK - what type of locking mechanisms should be used????
 */
static int
mpt_GetScsiPortSettings(MPT_ADAPTER *ioc, int portnum)
{
	u8			*pbuf;
	dma_addr_t		 buf_dma;
	CONFIGPARMS		 cfg;
	ConfigPageHeader_t	 header;
	int			 ii;
	int			 data, rc = 0;

	/* Allocate memory
	 */
	if (!ioc->spi_data.nvram) {
		int	 sz;
		u8	*mem;
		sz = MPT_MAX_SCSI_DEVICES * sizeof(int);
		mem = kmalloc(sz, GFP_ATOMIC);
		if (mem == NULL)
			return -EFAULT;

		ioc->spi_data.nvram = (int *) mem;

		dprintk((MYIOC_s_INFO_FMT "SCSI device NVRAM settings @ %p, sz=%d\n",
			ioc->name, ioc->spi_data.nvram, sz));
	}

	/* Invalidate NVRAM information
	 */
	for (ii=0; ii < MPT_MAX_SCSI_DEVICES; ii++) {
		ioc->spi_data.nvram[ii] = MPT_HOST_NVRAM_INVALID;
	}

	/* Read SPP0 header, allocate memory, then read page.
	 */
	header.PageVersion = 0;
	header.PageLength = 0;
	header.PageNumber = 0;
	header.PageType = MPI_CONFIG_PAGETYPE_SCSI_PORT;
	cfg.cfghdr.hdr = &header;
	cfg.physAddr = -1;
	cfg.pageAddr = portnum;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.timeout = 0;	/* use default */
	if (mpt_config(ioc, &cfg) != 0)
		 return -EFAULT;

	if (header.PageLength > 0) {
		pbuf = pci_alloc_consistent(ioc->pcidev, header.PageLength * 4, &buf_dma);
		if (pbuf) {
			cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
			cfg.physAddr = buf_dma;
			if (mpt_config(ioc, &cfg) != 0) {
				ioc->spi_data.maxBusWidth = MPT_NARROW;
				ioc->spi_data.maxSyncOffset = 0;
				ioc->spi_data.minSyncFactor = MPT_ASYNC;
				ioc->spi_data.busType = MPT_HOST_BUS_UNKNOWN;
				rc = 1;
				ddvprintk((MYIOC_s_INFO_FMT "Unable to read PortPage0 minSyncFactor=%x\n",
					ioc->name, ioc->spi_data.minSyncFactor));
			} else {
				/* Save the Port Page 0 data
				 */
				SCSIPortPage0_t  *pPP0 = (SCSIPortPage0_t  *) pbuf;
				pPP0->Capabilities = le32_to_cpu(pPP0->Capabilities);
				pPP0->PhysicalInterface = le32_to_cpu(pPP0->PhysicalInterface);

				if ( (pPP0->Capabilities & MPI_SCSIPORTPAGE0_CAP_QAS) == 0 ) {
					ioc->spi_data.noQas |= MPT_TARGET_NO_NEGO_QAS;
					ddvprintk((KERN_INFO MYNAM ": %s noQas due to Capabilities=%x\n",
						ioc->name, pPP0->Capabilities));
				}
				ioc->spi_data.maxBusWidth = pPP0->Capabilities & MPI_SCSIPORTPAGE0_CAP_WIDE ? 1 : 0;
				data = pPP0->Capabilities & MPI_SCSIPORTPAGE0_CAP_MAX_SYNC_OFFSET_MASK;
				if (data) {
					ioc->spi_data.maxSyncOffset = (u8) (data >> 16);
					data = pPP0->Capabilities & MPI_SCSIPORTPAGE0_CAP_MIN_SYNC_PERIOD_MASK;
					ioc->spi_data.minSyncFactor = (u8) (data >> 8);
					ddvprintk((MYIOC_s_INFO_FMT "PortPage0 minSyncFactor=%x\n",
						ioc->name, ioc->spi_data.minSyncFactor));
				} else {
					ioc->spi_data.maxSyncOffset = 0;
					ioc->spi_data.minSyncFactor = MPT_ASYNC;
				}

				ioc->spi_data.busType = pPP0->PhysicalInterface & MPI_SCSIPORTPAGE0_PHY_SIGNAL_TYPE_MASK;

				/* Update the minSyncFactor based on bus type.
				 */
				if ((ioc->spi_data.busType == MPI_SCSIPORTPAGE0_PHY_SIGNAL_HVD) ||
					(ioc->spi_data.busType == MPI_SCSIPORTPAGE0_PHY_SIGNAL_SE))  {

					if (ioc->spi_data.minSyncFactor < MPT_ULTRA) {
						ioc->spi_data.minSyncFactor = MPT_ULTRA;
						ddvprintk((MYIOC_s_INFO_FMT "HVD or SE detected, minSyncFactor=%x\n",
							ioc->name, ioc->spi_data.minSyncFactor));
					}
				}
			}
			if (pbuf) {
				pci_free_consistent(ioc->pcidev, header.PageLength * 4, pbuf, buf_dma);
			}
		}
	}

	/* SCSI Port Page 2 - Read the header then the page.
	 */
	header.PageVersion = 0;
	header.PageLength = 0;
	header.PageNumber = 2;
	header.PageType = MPI_CONFIG_PAGETYPE_SCSI_PORT;
	cfg.cfghdr.hdr = &header;
	cfg.physAddr = -1;
	cfg.pageAddr = portnum;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	if (mpt_config(ioc, &cfg) != 0)
		return -EFAULT;

	if (header.PageLength > 0) {
		/* Allocate memory and read SCSI Port Page 2
		 */
		pbuf = pci_alloc_consistent(ioc->pcidev, header.PageLength * 4, &buf_dma);
		if (pbuf) {
			cfg.action = MPI_CONFIG_ACTION_PAGE_READ_NVRAM;
			cfg.physAddr = buf_dma;
			if (mpt_config(ioc, &cfg) != 0) {
				/* Nvram data is left with INVALID mark
				 */
				rc = 1;
			} else {
				SCSIPortPage2_t *pPP2 = (SCSIPortPage2_t  *) pbuf;
				MpiDeviceInfo_t	*pdevice = NULL;

				/* save "Set to Avoid SCSI Bus Resets" flag */
				ioc->spi_data.bus_reset =
				    (le32_to_cpu(pPP2->PortFlags) &
			        MPI_SCSIPORTPAGE2_PORT_FLAGS_AVOID_SCSI_RESET) ?
				    0 : 1 ;

				/* Save the Port Page 2 data
				 * (reformat into a 32bit quantity)
				 */
				data = le32_to_cpu(pPP2->PortFlags) & MPI_SCSIPORTPAGE2_PORT_FLAGS_DV_MASK;
				ioc->spi_data.PortFlags = data;
				ddvprintk((MYIOC_s_NOTE_FMT "DV PortFlags=%x\n",
					ioc->name, ioc->spi_data.PortFlags));
				for (ii=0; ii < MPT_MAX_SCSI_DEVICES; ii++) {
					pdevice = &pPP2->DeviceSettings[ii];
					data = (le16_to_cpu(pdevice->DeviceFlags) << 16) |
						(pdevice->SyncFactor << 8) | pdevice->Timeout;
					ioc->spi_data.nvram[ii] = data;
 					ddvprintk((MYIOC_s_INFO_FMT "PortPage2 nvram=%x for id=%d\n",
 						ioc->name, data, ii));
				}
			}
			pci_free_consistent(ioc->pcidev, header.PageLength * 4, pbuf, buf_dma);
		}
	}

	/* Update Adapter limits with those from NVRAM
	 * Comment: Don't need to do this. Target performance
	 * parameters will never exceed the adapters limits.
	 */

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mpt_readScsiDevicePageHeaders - save version and length of SDP1
 *	@ioc: Pointer to a Adapter Strucutre
 *	@portnum: IOC port number
 *
 *	Return: -EFAULT if read of config page header fails
 *		or 0 if success.
 */
static int
mpt_readScsiDevicePageHeaders(MPT_ADAPTER *ioc, int portnum)
{
	CONFIGPARMS		 cfg;
	ConfigPageHeader_t	 header;

	/* Read the SCSI Device Page 1 header
	 */
	header.PageVersion = 0;
	header.PageLength = 0;
	header.PageNumber = 1;
	header.PageType = MPI_CONFIG_PAGETYPE_SCSI_DEVICE;
	cfg.cfghdr.hdr = &header;
	cfg.physAddr = -1;
	cfg.pageAddr = portnum;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.timeout = 0;
	if (mpt_config(ioc, &cfg) != 0)
		 return -EFAULT;

	ioc->spi_data.sdp1version = cfg.cfghdr.hdr->PageVersion;
	ioc->spi_data.sdp1length = cfg.cfghdr.hdr->PageLength;

	header.PageVersion = 0;
	header.PageLength = 0;
	header.PageNumber = 0;
	header.PageType = MPI_CONFIG_PAGETYPE_SCSI_DEVICE;
	if (mpt_config(ioc, &cfg) != 0)
		 return -EFAULT;

	ioc->spi_data.sdp0version = cfg.cfghdr.hdr->PageVersion;
	ioc->spi_data.sdp0length = cfg.cfghdr.hdr->PageLength;

	dcprintk((MYIOC_s_INFO_FMT "Headers: 0: version %d length %d\n",
			ioc->name, ioc->spi_data.sdp0version, ioc->spi_data.sdp0length));

	dcprintk((MYIOC_s_INFO_FMT "Headers: 1: version %d length %d\n",
			ioc->name, ioc->spi_data.sdp1version, ioc->spi_data.sdp1length));
	return 0;
}

/**
 *	mpt_raid_phys_disk_pg0 - returns phys disk page zero
 *	@ioc: Pointer to a Adapter Structure
 *	@phys_disk_num: io unit unique phys disk num generated by the ioc
 *	@phys_disk: requested payload data returned
 *
 *	Return:
 *	0 on success
 *	-EFAULT if read of config page header fails or data pointer not NULL
 *	-ENOMEM if pci_alloc failed
 **/
int
mpt_raid_phys_disk_pg0(MPT_ADAPTER *ioc, u8 phys_disk_num, pRaidPhysDiskPage0_t phys_disk)
{
	CONFIGPARMS		 	cfg;
	ConfigPageHeader_t	 	hdr;
	dma_addr_t			dma_handle;
	pRaidPhysDiskPage0_t		buffer = NULL;
	int				rc;

	memset(&cfg, 0 , sizeof(CONFIGPARMS));
	memset(&hdr, 0 , sizeof(ConfigPageHeader_t));

	hdr.PageType = MPI_CONFIG_PAGETYPE_RAID_PHYSDISK;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;

	if (mpt_config(ioc, &cfg) != 0) {
		rc = -EFAULT;
		goto out;
	}

	if (!hdr.PageLength) {
		rc = -EFAULT;
		goto out;
	}

	buffer = pci_alloc_consistent(ioc->pcidev, hdr.PageLength * 4,
	    &dma_handle);

	if (!buffer) {
		rc = -ENOMEM;
		goto out;
	}

	cfg.physAddr = dma_handle;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
	cfg.pageAddr = phys_disk_num;

	if (mpt_config(ioc, &cfg) != 0) {
		rc = -EFAULT;
		goto out;
	}

	rc = 0;
	memcpy(phys_disk, buffer, sizeof(*buffer));
	phys_disk->MaxLBA = le32_to_cpu(buffer->MaxLBA);

 out:

	if (buffer)
		pci_free_consistent(ioc->pcidev, hdr.PageLength * 4, buffer,
		    dma_handle);

	return rc;
}

/**
 *	mpt_raid_phys_disk_get_num_paths - returns number paths associated to this phys_num
 *	@ioc: Pointer to a Adapter Structure
 *	@phys_disk_num: io unit unique phys disk num generated by the ioc
 *
 *	Return:
 *	returns number paths
 **/
int
mpt_raid_phys_disk_get_num_paths(MPT_ADAPTER *ioc, u8 phys_disk_num)
{
	CONFIGPARMS		 	cfg;
	ConfigPageHeader_t	 	hdr;
	dma_addr_t			dma_handle;
	pRaidPhysDiskPage1_t		buffer = NULL;
	int				rc;

	memset(&cfg, 0 , sizeof(CONFIGPARMS));
	memset(&hdr, 0 , sizeof(ConfigPageHeader_t));

	hdr.PageVersion = MPI_RAIDPHYSDISKPAGE1_PAGEVERSION;
	hdr.PageType = MPI_CONFIG_PAGETYPE_RAID_PHYSDISK;
	hdr.PageNumber = 1;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;

	if (mpt_config(ioc, &cfg) != 0) {
		rc = 0;
		goto out;
	}

	if (!hdr.PageLength) {
		rc = 0;
		goto out;
	}

	buffer = pci_alloc_consistent(ioc->pcidev, hdr.PageLength * 4,
	    &dma_handle);

	if (!buffer) {
		rc = 0;
		goto out;
	}

	cfg.physAddr = dma_handle;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
	cfg.pageAddr = phys_disk_num;

	if (mpt_config(ioc, &cfg) != 0) {
		rc = 0;
		goto out;
	}

	rc = buffer->NumPhysDiskPaths;
 out:

	if (buffer)
		pci_free_consistent(ioc->pcidev, hdr.PageLength * 4, buffer,
		    dma_handle);

	return rc;
}

/**
 *	mpt_raid_phys_disk_pg1 - returns phys disk page 1
 *	@ioc: Pointer to a Adapter Structure
 *	@phys_disk_num: io unit unique phys disk num generated by the ioc
 *	@phys_disk: requested payload data returned
 *
 *	Return:
 *	0 on success
 *	-EFAULT if read of config page header fails or data pointer not NULL
 *	-ENOMEM if pci_alloc failed
 **/
int
mpt_raid_phys_disk_pg1(MPT_ADAPTER *ioc, u8 phys_disk_num, RaidPhysDiskPage1_t *phys_disk)
{
	CONFIGPARMS		 	cfg;
	ConfigPageHeader_t	 	hdr;
	dma_addr_t			dma_handle;
	pRaidPhysDiskPage1_t		buffer = NULL;
	int				rc;
	int				i;
	u64				sas_address;

	memset(&cfg, 0 , sizeof(CONFIGPARMS));
	memset(&hdr, 0 , sizeof(ConfigPageHeader_t));
	rc = 0;

	hdr.PageVersion = MPI_RAIDPHYSDISKPAGE1_PAGEVERSION;
	hdr.PageType = MPI_CONFIG_PAGETYPE_RAID_PHYSDISK;
	hdr.PageNumber = 1;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;

	if (mpt_config(ioc, &cfg) != 0) {
		rc = -EFAULT;
		goto out;
	}

	if (!hdr.PageLength) {
		rc = -EFAULT;
		goto out;
	}

	buffer = pci_alloc_consistent(ioc->pcidev, hdr.PageLength * 4,
	    &dma_handle);

	if (!buffer) {
		rc = -ENOMEM;
		goto out;
	}

	cfg.physAddr = dma_handle;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
	cfg.pageAddr = phys_disk_num;

	if (mpt_config(ioc, &cfg) != 0) {
		rc = -EFAULT;
		goto out;
	}

	phys_disk->NumPhysDiskPaths = buffer->NumPhysDiskPaths;
	phys_disk->PhysDiskNum = phys_disk_num;
	for (i = 0; i < phys_disk->NumPhysDiskPaths; i++) {
		phys_disk->Path[i].PhysDiskID = buffer->Path[i].PhysDiskID;
		phys_disk->Path[i].PhysDiskBus = buffer->Path[i].PhysDiskBus;
		phys_disk->Path[i].OwnerIdentifier = buffer->Path[i].OwnerIdentifier;
		phys_disk->Path[i].Flags = le16_to_cpu(buffer->Path[i].Flags);
		memcpy(&sas_address, &buffer->Path[i].WWID, sizeof(u64));
		sas_address = le64_to_cpu(sas_address);
		memcpy(&phys_disk->Path[i].WWID, &sas_address, sizeof(u64));
		memcpy(&sas_address, &buffer->Path[i].OwnerWWID, sizeof(u64));
		sas_address = le64_to_cpu(sas_address);
		memcpy(&phys_disk->Path[i].OwnerWWID, &sas_address, sizeof(u64));
	}

 out:

	if (buffer)
		pci_free_consistent(ioc->pcidev, hdr.PageLength * 4, buffer,
		    dma_handle);

	return rc;
}

/**
 * mpt_inactive_raid_list_free
 *
 * This clears this link list.
 *
 * @ioc - pointer to per adapter structure
 *
 **/
static void
mpt_inactive_raid_list_free(MPT_ADAPTER *ioc)
{
	struct inactive_raid_component_info *component_info, *pNext;

	if (list_empty(&ioc->raid_data.inactive_list))
		return;

	down(&ioc->raid_data.inactive_list_mutex);
	list_for_each_entry_safe(component_info, pNext,
	    &ioc->raid_data.inactive_list, list) {
		list_del(&component_info->list);
		kfree(component_info);
	}
	up(&ioc->raid_data.inactive_list_mutex);
}

/**
 * mpt_inactive_raid_volumes
 *
 * This sets up link list of phy_disk_nums for devices belonging in an inactive volume
 *
 * @ioc - pointer to per adapter structure
 * @channel - volume channel
 * @id - volume target id
 *
 *
 **/
static void
mpt_inactive_raid_volumes(MPT_ADAPTER *ioc, u8 channel, u8 id)
{
	CONFIGPARMS			cfg;
	ConfigPageHeader_t		hdr;
	dma_addr_t			dma_handle;
	pRaidVolumePage0_t		buffer = NULL;
	int				i;
	RaidPhysDiskPage0_t 		phys_disk;
	struct inactive_raid_component_info *component_info;
	int				handle_inactive_volumes;

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

	handle_inactive_volumes =
	   (buffer->VolumeStatus.Flags & MPI_RAIDVOL0_STATUS_FLAG_VOLUME_INACTIVE ||
	   (buffer->VolumeStatus.Flags & MPI_RAIDVOL0_STATUS_FLAG_ENABLED) == 0 ||
	    buffer->VolumeStatus.State == MPI_RAIDVOL0_STATUS_STATE_FAILED ||
	    buffer->VolumeStatus.State == MPI_RAIDVOL0_STATUS_STATE_MISSING) ? 1 : 0;

	if (!handle_inactive_volumes)
		goto out;

	down(&ioc->raid_data.inactive_list_mutex);
	for (i = 0; i < buffer->NumPhysDisks; i++) {
		if(mpt_raid_phys_disk_pg0(ioc,
		    buffer->PhysDisk[i].PhysDiskNum, &phys_disk) != 0)
			continue;

		if ((component_info = kmalloc(sizeof (*component_info),
		 GFP_KERNEL)) == NULL)
			continue;

		component_info->volumeID = id;
		component_info->volumeBus = channel;
		component_info->d.PhysDiskNum = phys_disk.PhysDiskNum;
		component_info->d.PhysDiskBus = phys_disk.PhysDiskBus;
		component_info->d.PhysDiskID = phys_disk.PhysDiskID;
		component_info->d.PhysDiskIOC = phys_disk.PhysDiskIOC;

		list_add_tail(&component_info->list,
		    &ioc->raid_data.inactive_list);
	}
	up(&ioc->raid_data.inactive_list_mutex);

 out:
	if (buffer)
		pci_free_consistent(ioc->pcidev, hdr.PageLength * 4, buffer,
		    dma_handle);
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_findImVolumes - Identify IDs of hidden disks and RAID Volumes
 *	@ioc: Pointer to a Adapter Strucutre
 *	@portnum: IOC port number
 *
 *	Return:
 *	0 on success
 *	-EFAULT if read of config page header fails or data pointer not NULL
 *	-ENOMEM if pci_alloc failed
 */
int
mpt_findImVolumes(MPT_ADAPTER *ioc)
{
	IOCPage2_t		*pIoc2;
	u8			*mem;
	ConfigPageIoc2RaidVol_t	*pIocRv;
	dma_addr_t		 ioc2_dma;
	CONFIGPARMS		 cfg;
	ConfigPageHeader_t	 header;
	int			 jj;
	int			 rc = 0;
	int			 iocpage2sz;

	if (!ioc->ir_firmware)
		return 0;

	/* Free the old page
	 */
	kfree(ioc->raid_data.pIocPg2);
	ioc->raid_data.pIocPg2 = NULL;
	mpt_inactive_raid_list_free(ioc);
	ioc->raid_data.isRaid = 0;
	
	/* Read IOCP2 header then the page.
	 */
	header.PageVersion = 0;
	header.PageLength = 0;
	header.PageNumber = 2;
	header.PageType = MPI_CONFIG_PAGETYPE_IOC;
	cfg.cfghdr.hdr = &header;
	cfg.physAddr = -1;
	cfg.pageAddr = 0;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.timeout = 0;
	if (mpt_config(ioc, &cfg) != 0)
		 return -EFAULT;

	if (header.PageLength == 0)
		return -EFAULT;

	iocpage2sz = header.PageLength * 4;
	pIoc2 = pci_alloc_consistent(ioc->pcidev, iocpage2sz, &ioc2_dma);
	if (!pIoc2)
		return -ENOMEM;

	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
	cfg.physAddr = ioc2_dma;
	if (mpt_config(ioc, &cfg) != 0)
		goto done_and_free;

	mem = kmalloc(iocpage2sz, GFP_ATOMIC);
	if (!mem)
		goto done_and_free;

	memcpy(mem, (u8 *)pIoc2, iocpage2sz);
	ioc->raid_data.pIocPg2 = (IOCPage2_t *) mem;

	/* Identify RAID Volume Id's */
	if (pIoc2->NumActiveVolumes) {

		pIocRv = pIoc2->RaidVolume;
		/* 
		 * WARNING - ioc->raid_data.isRaid 
		 * doesn't consider channels 
		 */
		for (jj = 0; jj < pIoc2->NumActiveVolumes; jj++, pIocRv++) {
			if (pIocRv->VolumeBus)
				continue;
			ioc->raid_data.isRaid |= (1 << pIocRv->VolumeID);
			mpt_inactive_raid_volumes(ioc,
			    pIoc2->RaidVolume[jj].VolumeBus,
			    pIoc2->RaidVolume[jj].VolumeID);
		}
		mpt_read_ioc_pg_3(ioc);
		mpt_read_ioc_pg_6(ioc);
	}

 done_and_free:
	pci_free_consistent(ioc->pcidev, iocpage2sz, pIoc2, ioc2_dma);

	return rc;
}

int
mpt_read_ioc_pg_3(MPT_ADAPTER *ioc)
{
	IOCPage3_t		*pIoc3;
	u8			*mem;
	CONFIGPARMS		 cfg;
	ConfigPageHeader_t	 header;
	dma_addr_t		 ioc3_dma;
	int			 iocpage3sz = 0;

	/* Free the old page
	 */
	if (ioc->raid_data.pIocPg3) {
		kfree(ioc->raid_data.pIocPg3);
		ioc->raid_data.pIocPg3 = NULL;
	}

	/* There is at least one physical disk.
	 * Read and save IOC Page 3
	 */
	header.PageVersion = 0;
	header.PageLength = 0;
	header.PageNumber = 3;
	header.PageType = MPI_CONFIG_PAGETYPE_IOC;
	cfg.cfghdr.hdr = &header;
	cfg.physAddr = -1;
	cfg.pageAddr = 0;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.timeout = 0;
	if (mpt_config(ioc, &cfg) != 0)
		return 0;

	if (header.PageLength == 0)
		return 0;

	/* Read Header good, alloc memory
	 */
	iocpage3sz = header.PageLength * 4;
	pIoc3 = pci_alloc_consistent(ioc->pcidev, iocpage3sz, &ioc3_dma);
	if (!pIoc3)
		return 0;

	/* Read the Page and save the data
	 * into malloc'd memory.
	 */
	cfg.physAddr = ioc3_dma;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
	if (mpt_config(ioc, &cfg) == 0) {
		mem = kmalloc(iocpage3sz, GFP_ATOMIC);
		if (mem) {
			memcpy(mem, (u8 *)pIoc3, iocpage3sz);
			ioc->raid_data.pIocPg3 = (IOCPage3_t *) mem;
		}
	}

	pci_free_consistent(ioc->pcidev, iocpage3sz, pIoc3, ioc3_dma);

	return 0;
}

static void
mpt_read_ioc_pg_4(MPT_ADAPTER *ioc)
{
	IOCPage4_t		*pIoc4;
	CONFIGPARMS		 cfg;
	ConfigPageHeader_t	 header;
	dma_addr_t		 ioc4_dma;
	int			 iocpage4sz;

	/* Read and save IOC Page 4
	 */
	header.PageVersion = 0;
	header.PageLength = 0;
	header.PageNumber = 4;
	header.PageType = MPI_CONFIG_PAGETYPE_IOC;
	cfg.cfghdr.hdr = &header;
	cfg.physAddr = -1;
	cfg.pageAddr = 0;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.timeout = 0;
	if (mpt_config(ioc, &cfg) != 0)
		return;

	if (header.PageLength == 0)
		return;

	if ( (pIoc4 = ioc->spi_data.pIocPg4) == NULL ) {
		iocpage4sz = (header.PageLength + 4) * 4; /* Allow 4 additional SEP's */
		pIoc4 = pci_alloc_consistent(ioc->pcidev, iocpage4sz, &ioc4_dma);
		if (!pIoc4)
			return;
		ioc->alloc_total += iocpage4sz;
	} else {
		ioc4_dma = ioc->spi_data.IocPg4_dma;
		iocpage4sz = ioc->spi_data.IocPg4Sz;
	}

	/* Read the Page into dma memory.
	 */
	cfg.physAddr = ioc4_dma;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
	if (mpt_config(ioc, &cfg) == 0) {
		ioc->spi_data.pIocPg4 = (IOCPage4_t *) pIoc4;
		ioc->spi_data.IocPg4_dma = ioc4_dma;
		ioc->spi_data.IocPg4Sz = iocpage4sz;
	} else {
		pci_free_consistent(ioc->pcidev, iocpage4sz, pIoc4, ioc4_dma);
		ioc->spi_data.pIocPg4 = NULL;
		ioc->alloc_total -= iocpage4sz;
	}
}

static void
mpt_read_ioc_pg_6(MPT_ADAPTER *ioc)
{
	IOCPage6_t		*pIoc6;
	u8			*mem;
	CONFIGPARMS		 cfg;
	ConfigPageHeader_t	 header;
	dma_addr_t		 ioc6_dma;
	int			 iocpage6sz = 0;

	/* Free the old page
	 */
	if (ioc->raid_data.pIocPg6) {
		kfree(ioc->raid_data.pIocPg6);
		ioc->raid_data.pIocPg6 = NULL;
	}

	/* There is at least one physical disk.
	 * Read and save IOC Page 3
	 */
	header.PageVersion = 0;
	header.PageLength = 0;
	header.PageNumber = 6;
	header.PageType = MPI_CONFIG_PAGETYPE_IOC;
	cfg.cfghdr.hdr = &header;
	cfg.physAddr = -1;
	cfg.pageAddr = 0;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.timeout = 0;
	if (mpt_config(ioc, &cfg) != 0)
		return;

	if (header.PageLength == 0)
		return;

	/* Read Header good, alloc memory
	 */
	iocpage6sz = header.PageLength * 4;
	pIoc6 = pci_alloc_consistent(ioc->pcidev, iocpage6sz, &ioc6_dma);
	if (!pIoc6)
		return;

	/* Read the Page and save the data
	 * into malloc'd memory.
	 */
	cfg.physAddr = ioc6_dma;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
	if (mpt_config(ioc, &cfg) == 0) {
		mem = kmalloc(iocpage6sz, GFP_ATOMIC);
		if (mem) {
			memcpy(mem, (u8 *)pIoc6, iocpage6sz);
			ioc->raid_data.pIocPg6 = (IOCPage6_t *) mem;
		}
	}

	pci_free_consistent(ioc->pcidev, iocpage6sz, pIoc6, ioc6_dma);
}

static void
mpt_read_ioc_pg_1(MPT_ADAPTER *ioc)
{
	IOCPage1_t		*pIoc1;
	CONFIGPARMS		 cfg;
	ConfigPageHeader_t	 header;
	dma_addr_t		 ioc1_dma;
	int			 iocpage1sz = 0;
	u32			 tmp;

	/* Check the Coalescing Timeout in IOC Page 1
	 */
	header.PageVersion = 0;
	header.PageLength = 0;
	header.PageNumber = 1;
	header.PageType = MPI_CONFIG_PAGETYPE_IOC;
	cfg.cfghdr.hdr = &header;
	cfg.physAddr = -1;
	cfg.pageAddr = 0;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.timeout = 0;
	if (mpt_config(ioc, &cfg) != 0)
		return;

	if (header.PageLength == 0)
		return;

	/* Read Header good, alloc memory
	 */
	iocpage1sz = header.PageLength * 4;
	pIoc1 = pci_alloc_consistent(ioc->pcidev, iocpage1sz, &ioc1_dma);
	if (!pIoc1)
		return;

	/* Read the Page and check coalescing timeout
	 */
	cfg.physAddr = ioc1_dma;
	cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
	if (mpt_config(ioc, &cfg) == 0) {

		ioc->pci_slot_number = pIoc1->PCISlotNum;

		tmp = le32_to_cpu(pIoc1->Flags) & MPI_IOCPAGE1_REPLY_COALESCING;
		if (tmp == MPI_IOCPAGE1_REPLY_COALESCING) {
			tmp = le32_to_cpu(pIoc1->CoalescingTimeout);

			dprintk((MYIOC_s_INFO_FMT "Coalescing Enabled Timeout = %d\n",
					ioc->name, tmp));

			if (tmp > MPT_COALESCING_TIMEOUT) {
				pIoc1->CoalescingTimeout = cpu_to_le32(MPT_COALESCING_TIMEOUT);

				/* Write NVRAM and current
				 */
				cfg.dir = 1;
				cfg.action = MPI_CONFIG_ACTION_PAGE_WRITE_CURRENT;
				if (mpt_config(ioc, &cfg) == 0) {
					dprintk((MYIOC_s_INFO_FMT "Reset Current Coalescing Timeout to = %d\n",
							ioc->name, MPT_COALESCING_TIMEOUT));

					cfg.action = MPI_CONFIG_ACTION_PAGE_WRITE_NVRAM;
					if (mpt_config(ioc, &cfg) == 0) {
						dprintk((MYIOC_s_INFO_FMT "Reset NVRAM Coalescing Timeout to = %d\n",
								ioc->name, MPT_COALESCING_TIMEOUT));
					} else {
						dprintk((MYIOC_s_INFO_FMT "Reset NVRAM Coalescing Timeout Failed\n",
									ioc->name));
					}

				} else {
					dprintk((MYIOC_s_WARN_FMT "Reset of Current Coalescing Timeout Failed!\n",
								ioc->name));
				}
			}

		} else {
			dprintk((MYIOC_s_WARN_FMT "Coalescing Disabled\n", ioc->name));
		}
	}

	pci_free_consistent(ioc->pcidev, iocpage1sz, pIoc1, ioc1_dma);

	return;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	SendEventNotification - Send EventNotification (on or off) request
 *	to MPT adapter.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@EvSwitch: Event switch flags
 */
static int
SendEventNotification(MPT_ADAPTER *ioc, u8 EvSwitch)
{
	EventNotification_t	*evnp;

	evnp = (EventNotification_t *) mpt_get_msg_frame(mpt_base_index, ioc);
	dinitprintk((MYIOC_s_WARN_FMT "%s: evnp=%p\n",
			   ioc->name, __FUNCTION__, evnp));
	if (evnp == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return 0;
	}
	ioc->evnp = evnp;

	memset(evnp, 0, sizeof(*evnp));

	devtprintk((MYIOC_s_WARN_FMT "%s: (%d) request %p\n", 
		ioc->name, __FUNCTION__, EvSwitch, evnp));

	evnp->Function = MPI_FUNCTION_EVENT_NOTIFICATION;
	evnp->Switch = EvSwitch;

	mpt_put_msg_frame(mpt_base_index, ioc, (MPT_FRAME_HDR *)evnp);

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	SendEventAck - Send EventAck request to MPT adapter.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@evnp: Pointer to original EventNotification request
 */
static int
SendEventAck(MPT_ADAPTER *ioc, EventNotificationReply_t *evnp)
{
	EventAck_t	*pAck;

	if ((pAck = (EventAck_t *) mpt_get_msg_frame(mpt_base_index, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return -1;
	}

	devtprintk((MYIOC_s_INFO_FMT "Sending EventAck\n", ioc->name));

	memset(pAck, 0, sizeof(*pAck));

	pAck->Function     = MPI_FUNCTION_EVENT_ACK;
	pAck->Event        = evnp->Event;
	pAck->EventContext = evnp->EventContext;
	DBG_DUMP_EVENT_REQUEST_FRAME(pAck);

	mpt_put_msg_frame(mpt_base_index, ioc, (MPT_FRAME_HDR *)pAck);

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_config - Generic function to issue config message
 *	@ioc - Pointer to an adapter structure
 *	@cfg - Pointer to a configuration structure. Struct contains
 *		action, page address, direction, physical address
 *		and pointer to a configuration page header
 *		Page header is updated.
 *
 *	Returns 0 for success
 *	-EPERM if not allowed due to ISR context
 *	-EAGAIN if no msg frames currently available
 *	-EFAULT for non-successful reply or no reply (timeout)
 */
int
mpt_config(MPT_ADAPTER *ioc, CONFIGPARMS *pCfg)
{
	Config_t	*pReq;
	ConfigExtendedPageHeader_t  *pExtHdr = NULL;
	MPT_FRAME_HDR	*mf;
	unsigned long	 flags;
	int		 ii, rc;
	int		 flagsLength;
	int		 in_isr;

	/*	Prevent calling wait_event() (below), if caller happens
	 *	to be in ISR context, because that is fatal!
	 */
	in_isr = in_interrupt();
	if (in_isr) {
		dfailprintk((MYIOC_s_WARN_FMT "Config request not allowed in ISR context!\n",
				ioc->name));
		return -EPERM;
	}

	/* Get and Populate a free Frame
	 */
	if ((mf = mpt_get_msg_frame(mpt_base_index, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return -EAGAIN;
	}
	pReq = (Config_t *)mf;
	pReq->Action = pCfg->action;
	pReq->Reserved = 0;
	pReq->ChainOffset = 0;
	pReq->Function = MPI_FUNCTION_CONFIG;

	/* Assume page type is not extended and clear "reserved" fields. */
	pReq->ExtPageLength = 0;
	pReq->ExtPageType = 0;
	pReq->MsgFlags = 0;

	for (ii=0; ii < 8; ii++)
		pReq->Reserved2[ii] = 0;

	pReq->Header.PageVersion = pCfg->cfghdr.hdr->PageVersion;
	pReq->Header.PageLength = pCfg->cfghdr.hdr->PageLength;
	pReq->Header.PageNumber = pCfg->cfghdr.hdr->PageNumber;
	pReq->Header.PageType = (pCfg->cfghdr.hdr->PageType & MPI_CONFIG_PAGETYPE_MASK);

	if ((pCfg->cfghdr.hdr->PageType & MPI_CONFIG_PAGETYPE_MASK) == MPI_CONFIG_PAGETYPE_EXTENDED) {
		pExtHdr = (ConfigExtendedPageHeader_t *)pCfg->cfghdr.ehdr;
		pReq->ExtPageLength = cpu_to_le16(pExtHdr->ExtPageLength);
		pReq->ExtPageType = pExtHdr->ExtPageType;
		pReq->Header.PageType = MPI_CONFIG_PAGETYPE_EXTENDED;

		/* Page Length must be treated as a reserved field for the extended header. */
		pReq->Header.PageLength = 0;
	}

	pReq->PageAddress = cpu_to_le32(pCfg->pageAddr);

	/* Add a SGE to the config request.
	 */
	if (pCfg->dir)
		flagsLength = MPT_SGE_FLAGS_SSIMPLE_WRITE;
	else
		flagsLength = MPT_SGE_FLAGS_SSIMPLE_READ;

	if ((pCfg->cfghdr.hdr->PageType & MPI_CONFIG_PAGETYPE_MASK) == MPI_CONFIG_PAGETYPE_EXTENDED) {
		flagsLength |= pExtHdr->ExtPageLength * 4;

		dcprintk((MYIOC_s_INFO_FMT "Sending Config request type %d Extended page %d and action %d\n",
			ioc->name, pReq->ExtPageType, pReq->Header.PageNumber, pReq->Action));
	}
	else {
		flagsLength |= pCfg->cfghdr.hdr->PageLength * 4;

		dcprintk((MYIOC_s_INFO_FMT "Sending Config request type %d, page %d and action %d\n",
			ioc->name, pReq->Header.PageType, pReq->Header.PageNumber, pReq->Action));
	}

	ioc->add_sge((char *)&pReq->PageBufferSGE, flagsLength, pCfg->physAddr);

	/* Append pCfg pointer to end of mf
	 */
	*((void **) (((u8 *) mf) + (ioc->req_sz - sizeof(void *)))) =  (void *) pCfg;

	/* Initalize the timer
	 */
	init_timer(&pCfg->timer);
	pCfg->timer.data = (unsigned long) ioc;
	pCfg->timer.function = mpt_timer_expired;
	pCfg->wait_done = 0;

	/* Set the timer; ensure 10 second minimum */
	if (pCfg->timeout < 10)
		pCfg->timer.expires = jiffies + HZ*10;
	else
		pCfg->timer.expires = jiffies + HZ*pCfg->timeout;

	/* Add to end of Q, set timer and then issue this command */
	spin_lock_irqsave(&ioc->FreeQlock, flags);
	list_add_tail(&pCfg->linkage, &ioc->configQ);
	spin_unlock_irqrestore(&ioc->FreeQlock, flags);

	add_timer(&pCfg->timer);
	mpt_put_msg_frame(mpt_base_index, ioc, mf);
	wait_event(mpt_waitq, pCfg->wait_done);

	/* mf has been freed - do not access */

	rc = pCfg->status;

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_timer_expired - Call back for timer process.
 *	Used only internal config functionality.
 *	@data: Pointer to MPT_SCSI_HOST recast as an unsigned long
 */
static void
mpt_timer_expired(unsigned long data)
{
	MPT_ADAPTER *ioc = (MPT_ADAPTER *) data;

	dfailprintk((MYIOC_s_WARN_FMT "mpt_timer_expired! \n", ioc->name));

	/* Perform a FW reload */
	if (mpt_HardResetHandler(ioc, NO_SLEEP) < 0)
		printk(MYIOC_s_WARN_FMT "Firmware Reload FAILED!\n", ioc->name);

	/* No more processing.
	 * Hard reset clean-up will wake up
	 * process and free all resources.
	 */
	dcprintk((MYIOC_s_WARN_FMT "mpt_timer_expired complete!\n", ioc->name));

	return;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_ioc_reset - Base cleanup for hard reset
 *	@ioc: Pointer to the adapter structure
 *	@reset_phase: Indicates pre- or post-reset functionality
 *
 *	Remark: Free's resources with internally generated commands.
 */
static int
mpt_ioc_reset(MPT_ADAPTER *ioc, int reset_phase)
{
	CONFIGPARMS *pCfg;
	unsigned long flags;

	dprintk((KERN_INFO MYNAM
			": IOC %s_reset routed to MPT base driver!\n",
			reset_phase==MPT_IOC_PRE_RESET ? "pre" : "post"));

	if (reset_phase == MPT_IOC_PRE_RESET) {
		/* If the internal config Q is not empty -
		 * delete timer. MF resources will be freed when
		 * the FIFO's are primed.
		 */
		spin_lock_irqsave(&ioc->FreeQlock, flags);
		list_for_each_entry(pCfg, &ioc->configQ, linkage)
			del_timer(&pCfg->timer);
		spin_unlock_irqrestore(&ioc->FreeQlock, flags);

	} else {
		CONFIGPARMS *pNext;

		/* Search the configQ for internal commands.
		 * Flush the Q, and wake up all suspended threads.
		 */
		spin_lock_irqsave(&ioc->FreeQlock, flags);
		list_for_each_entry_safe(pCfg, pNext, &ioc->configQ, linkage) {
			list_del(&pCfg->linkage);

			pCfg->status = MPT_CONFIG_ERROR;
			pCfg->wait_done = 1;
			wake_up(&mpt_waitq);
		}
		spin_unlock_irqrestore(&ioc->FreeQlock, flags);
	}

	return 1;		/* currently means nothing really */
}


#ifdef CONFIG_PROC_FS		/* { */
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	procfs (%MPT_PROCFS_MPTBASEDIR/...) support stuff...
 */
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	procmpt_create - Create %MPT_PROCFS_MPTBASEDIR entries.
 *
 *	Returns 0 for success, non-zero for failure.
 */
static int
procmpt_create(void)
{
	struct proc_dir_entry	*ent;

	mpt_proc_root_dir = proc_mkdir(MPT_PROCFS_MPTBASEDIR, NULL);
	if (mpt_proc_root_dir == NULL)
		return -ENOTDIR;

	ent = create_proc_entry("summary", S_IFREG|S_IRUGO, mpt_proc_root_dir);
	if (ent)
		ent->read_proc = procmpt_summary_read;

	ent = create_proc_entry("version", S_IFREG|S_IRUGO, mpt_proc_root_dir);
	if (ent)
		ent->read_proc = procmpt_version_read;

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	procmpt_destroy - Tear down %MPT_PROCFS_MPTBASEDIR entries.
 *
 *	Returns 0 for success, non-zero for failure.
 */
static void
procmpt_destroy(void)
{
	remove_proc_entry("version", mpt_proc_root_dir);
	remove_proc_entry("summary", mpt_proc_root_dir);
	remove_proc_entry(MPT_PROCFS_MPTBASEDIR, NULL);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	procmpt_summary_read - Handle read request from /proc/mpt/summary
 *	or from /proc/mpt/iocN/summary.
 *	@buf: Pointer to area to write information
 *	@start: Pointer to start pointer
 *	@offset: Offset to start writing
 *	@request:
 *	@eof: Pointer to EOF integer
 *	@data: Pointer
 *
 *	Returns number of characters written to process performing the read.
 */
static int
procmpt_summary_read(char *buf, char **start, off_t offset, int request, int *eof, void *data)
{
	MPT_ADAPTER *ioc;
	char *out = buf;
	int len;

	if (data) {
		int more = 0;

		ioc = data;
		mpt_print_ioc_summary(ioc, out, &more, 0, 1);

		out += more;
	} else {
		list_for_each_entry(ioc, &ioc_list, list) {
			int	more = 0;

			mpt_print_ioc_summary(ioc, out, &more, 0, 1);

			out += more;
			if ((out-buf) >= request)
				break;
		}
	}

	len = out - buf;

	MPT_PROC_READ_RETURN(buf,start,offset,request,eof,len);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	procmpt_version_read - Handle read request from /proc/mpt/version.
 *	@buf: Pointer to area to write information
 *	@start: Pointer to start pointer
 *	@offset: Offset to start writing
 *	@request:
 *	@eof: Pointer to EOF integer
 *	@data: Pointer
 *
 *	Returns number of characters written to process performing the read.
 */
static int
procmpt_version_read(char *buf, char **start, off_t offset, int request, int *eof, void *data)
{
	int	 ii;
	int	 scsi, fc, sas, lan, ctl, targ, dmp;
	char	*drvname;
	int	 len;

	len = sprintf(buf, "%s-%s\n", "mptlinux", MPT_LINUX_VERSION_COMMON);
	len += sprintf(buf+len, "  Fusion MPT base driver\n");

	scsi = fc = sas = lan = ctl = targ = dmp = 0;
	for (ii=MPT_MAX_PROTOCOL_DRIVERS-1; ii; ii--) {
		drvname = NULL;
		if (MptCallbacks[ii]) {
			switch (MptDriverClass[ii]) {
			case MPTSPI_DRIVER:
				if (!scsi++) drvname = "SPI host";
				break;
			case MPTFC_DRIVER:
				if (!fc++) drvname = "FC host";
				break;
			case MPTSAS_DRIVER:
				if (!sas++) drvname = "SAS host";
				break;
			case MPTLAN_DRIVER:
				if (!lan++) drvname = "LAN";
				break;
			case MPTSTM_DRIVER:
				if (!targ++) drvname = "SCSI target";
				break;
			case MPTCTL_DRIVER:
				if (!ctl++) drvname = "ioctl";
				break;
			}

			if (drvname)
				len += sprintf(buf+len, "  Fusion MPT %s driver\n", drvname);
		}
	}

	MPT_PROC_READ_RETURN(buf,start,offset,request,eof,len);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	procmpt_iocinfo_read - Handle read request from /proc/mpt/iocN/info.
 *	@buf: Pointer to area to write information
 *	@start: Pointer to start pointer
 *	@offset: Offset to start writing
 *	@request:
 *	@eof: Pointer to EOF integer
 *	@data: Pointer
 *
 *	Returns number of characters written to process performing the read.
 */
static int
procmpt_iocinfo_read(char *buf, char **start, off_t offset, int request, int *eof, void *data)
{
	MPT_ADAPTER	*ioc = data;
	int		 len;
	char		 expVer[32];
	int		 sz;
	int		 p;

	mpt_get_fw_exp_ver(expVer, ioc);

	len = sprintf(buf, "%s:", ioc->name);
	if (ioc->facts.Flags & MPI_IOCFACTS_FLAGS_FW_DOWNLOAD_BOOT)
		len += sprintf(buf+len, "  (f/w download boot flag set)");
//	if (ioc->facts.IOCExceptions & MPI_IOCFACTS_EXCEPT_CONFIG_CHECKSUM_FAIL)
//		len += sprintf(buf+len, "  CONFIG_CHECKSUM_FAIL!");

	len += sprintf(buf+len, "\n  ProductID = 0x%04x (%s)\n",
			ioc->facts.ProductID,
			ioc->prod_name);
	len += sprintf(buf+len, "  FWVersion = 0x%08x%s", ioc->facts.FWVersion.Word, expVer);
	if (ioc->facts.FWImageSize)
		len += sprintf(buf+len, " (fw_size=%d)", ioc->facts.FWImageSize);
	len += sprintf(buf+len, "\n  MsgVersion = 0x%04x\n", ioc->facts.MsgVersion);
	len += sprintf(buf+len, "  FirstWhoInit = 0x%02x\n", ioc->FirstWhoInit);
	len += sprintf(buf+len, "  EventState = 0x%02x\n", ioc->facts.EventState);

	len += sprintf(buf+len, "  CurrentHostMfaHighAddr = 0x%08x\n",
			ioc->facts.CurrentHostMfaHighAddr);
	len += sprintf(buf+len, "  CurrentSenseBufferHighAddr = 0x%08x\n",
			ioc->facts.CurrentSenseBufferHighAddr);

	len += sprintf(buf+len, "  MaxChainDepth = 0x%02x frames\n", ioc->facts.MaxChainDepth);
	len += sprintf(buf+len, "  MinBlockSize = 0x%02x bytes\n", 4*ioc->facts.BlockSize);

	len += sprintf(buf+len, "  RequestFrames @ 0x%p (Dma @ 0x%p)\n",
					(void *)ioc->req_frames, (void *)(ulong)ioc->req_frames_dma);
	/*
	 *  Rounding UP to nearest 4-kB boundary here...
	 */
	sz = (ioc->req_sz * ioc->req_depth) + 128;
	sz = ((sz + 0x1000UL - 1UL) / 0x1000) * 0x1000;
	len += sprintf(buf+len, "    {CurReqSz=%d} x {CurReqDepth=%d} = %d bytes ^= 0x%x\n",
					ioc->req_sz, ioc->req_depth, ioc->req_sz*ioc->req_depth, sz);
	len += sprintf(buf+len, "    {MaxReqSz=%d}   {MaxReqDepth=%d}\n",
					4*ioc->facts.RequestFrameSize,
					ioc->facts.GlobalCredits);

	len += sprintf(buf+len, "  Frames   @ 0x%p (Dma @ 0x%p)\n",
					(void *)ioc->alloc, (void *)(ulong)ioc->alloc_dma);
	sz = (ioc->reply_sz * ioc->reply_depth) + 128;
	len += sprintf(buf+len, "    {CurRepSz=%d} x {CurRepDepth=%d} = %d bytes ^= 0x%x\n",
					ioc->reply_sz, ioc->reply_depth, ioc->reply_sz*ioc->reply_depth, sz);
	len += sprintf(buf+len, "    {MaxRepSz=%d}   {MaxRepDepth=%d}\n",
					ioc->facts.CurReplyFrameSize,
					ioc->facts.ReplyQueueDepth);

	len += sprintf(buf+len, "  MaxDevices = %d\n",
			(ioc->facts.MaxDevices==0) ? 255 : ioc->facts.MaxDevices);
	len += sprintf(buf+len, "  MaxBuses = %d\n", ioc->facts.MaxBuses);

	/* per-port info */
	for (p=0; p < ioc->facts.NumberOfPorts; p++) {
		len += sprintf(buf+len, "  PortNumber = %d (of %d)\n",
				p+1,
				ioc->facts.NumberOfPorts);
	    if (ioc->bus_type == SAS) {
			len += sprintf(buf+len, "    WWN = %08X%08X\n",
				ioc->sas_port_WWID[p].High,
				ioc->sas_port_WWID[p].Low);
		}
		else if (ioc->bus_type == FC) {
			if (ioc->pfacts[p].ProtocolFlags & MPI_PORTFACTS_PROTOCOL_LAN) {
				u8 *a = (u8*)&ioc->lan_cnfg_page1.HardwareAddressLow;
				len += sprintf(buf+len, "    LanAddr = %02X:%02X:%02X:%02X:%02X:%02X\n",
						a[5], a[4], a[3], a[2], a[1], a[0]);
			}
			len += sprintf(buf+len, "    WWN = %08X%08X:%08X%08X\n",
					ioc->fc_port_page0[p].WWNN.High,
					ioc->fc_port_page0[p].WWNN.Low,
					ioc->fc_port_page0[p].WWPN.High,
					ioc->fc_port_page0[p].WWPN.Low);
		}
	}

	MPT_PROC_READ_RETURN(buf,start,offset,request,eof,len);
}

#endif		/* CONFIG_PROC_FS } */

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void
mpt_get_fw_exp_ver(char *buf, MPT_ADAPTER *ioc)
{
	buf[0] ='\0';
	if ((ioc->facts.FWVersion.Word >> 24) == 0x0E) {
		sprintf(buf, " (Exp %02d%02d)",
			(ioc->facts.FWVersion.Word >> 16) & 0x00FF,	/* Month */
			(ioc->facts.FWVersion.Word >> 8) & 0x1F);	/* Day */

		/* insider hack! */
		if ((ioc->facts.FWVersion.Word >> 8) & 0x80)
			strcat(buf, " [MDBG]");
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_print_ioc_summary - Write ASCII summary of IOC to a buffer.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@buffer: Pointer to buffer where IOC summary info should be written
 *	@size: Pointer to number of bytes we wrote (set by this routine)
 *	@len: Offset at which to start writing in buffer
 *	@showlan: Display LAN stuff?
 *
 *	This routine writes (english readable) ASCII text, which represents
 *	a summary of IOC information, to a buffer.
 */
void
mpt_print_ioc_summary(MPT_ADAPTER *ioc, char *buffer, int *size, int len, int showlan)
{
	char expVer[32];
	int y;

	mpt_get_fw_exp_ver(expVer, ioc);

	/*
	 *  Shorter summary of attached ioc's...
	 */
	y = sprintf(buffer+len, "%s: %s, %s%08xh%s, Ports=%d, MaxQ=%d",
			ioc->name,
			ioc->prod_name,
			MPT_FW_REV_MAGIC_ID_STRING,	/* "FwRev=" or somesuch */
			ioc->facts.FWVersion.Word,
			expVer,
			ioc->facts.NumberOfPorts,
			ioc->req_depth);

	if (showlan && (ioc->pfacts[0].ProtocolFlags & MPI_PORTFACTS_PROTOCOL_LAN)) {
		u8 *a = (u8*)&ioc->lan_cnfg_page1.HardwareAddressLow;
		y += sprintf(buffer+len+y, ", LanAddr=%02X:%02X:%02X:%02X:%02X:%02X",
			a[5], a[4], a[3], a[2], a[1], a[0]);
	}

#ifndef __sparc__
	y += sprintf(buffer+len+y, ", IRQ=%d", ioc->pci_irq);
#else
	y += sprintf(buffer+len+y, ", IRQ=%s", __irq_itoa(ioc->pci_irq));
#endif

	if (!ioc->active)
		y += sprintf(buffer+len+y, " (disabled)");

	y += sprintf(buffer+len+y, "\n");

	*size = y;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	Reset Handling
 */
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_HardResetHandler - Generic reset handler, issue SCSI Task
 *	Management call based on input arg values.  If TaskMgmt fails,
 *	return associated SCSI request.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@sleepFlag: Indicates if sleep or schedule must be called.
 *
 *	Remark: _HardResetHandler can be invoked from an interrupt thread (timer)
 *	or a non-interrupt thread.  In the former, must not call schedule().
 *
 *	Remark: A return of -1 is a FATAL error case, as it means a
 *	FW reload/initialization failed.
 *
 *	Returns 0 for SUCCESS or -1 if FAILED.
 */
int
mpt_HardResetHandler(MPT_ADAPTER *ioc, int sleepFlag)
{
	int		 rc;
	u32	 ioc_state;
	unsigned long	 flags;

	dtmprintk((MYIOC_s_INFO_FMT "HardResetHandler Entered!\n", ioc->name));
#ifdef MFCNT
	printk(MYIOC_s_INFO_FMT "HardResetHandler Entered!\n", ioc->name);
	printk("MF count 0x%x !\n", ioc->mfcnt);
#endif

	if(mpt_fwfault_debug)
		mpt_halt_firmware(ioc);

	/* Reset the adapter. Prevent more than 1 call to
	 * mpt_do_ioc_recovery at any instant in time.
	 */
	spin_lock_irqsave(&ioc->diagLock, flags);
	if (ioc->ioc_reset_in_progress){
		spin_unlock_irqrestore(&ioc->diagLock, flags);
		dtmprintk((MYIOC_s_INFO_FMT "HardResetHandler: ioc_reset_in_progress!\n",
			   ioc->name));
		return 0;
	}
	spin_unlock_irqrestore(&ioc->diagLock, flags);

	dtmprintk((MYIOC_s_WARN_FMT "Calling mpt_SendIocReset MUR!\n",
		ioc->name));
	if ((rc = mpt_SendIocReset(ioc, MPI_FUNCTION_IOC_MESSAGE_UNIT_RESET, sleepFlag)) != 0) {
		ioc_state = mpt_GetIocState(ioc, 0);
		dfailprintk((MYIOC_s_WARN_FMT "IOC MUR failed! ioc_state=%08x\n", ioc->name, ioc_state));
		ioc->ioc_reset_in_progress = 0;

	} else {
		dtmprintk((MYIOC_s_WARN_FMT "IOC MUR succeeded\n", ioc->name));
		dtmprintk((MYIOC_s_WARN_FMT "Calling do_ioc_recovery! \n", ioc->name));
		if ((rc = mpt_do_ioc_recovery(ioc, MPT_HOSTEVENT_IOC_RECOVER, sleepFlag)) != 0) {
			dfailprintk((MYIOC_s_ERR_FMT "- (%d) ioc_recovery failed\n", ioc->name, rc));
		} else {
			dtmprintk((MYIOC_s_WARN_FMT "Successful do_ioc_recovery! \n", ioc->name));
			return 0;
		}
	}

	/* FIXME: If do_ioc_recovery fails, repeat....
	 */

	if ((rc = mpt_do_ioc_recovery(ioc, MPT_HOSTEVENT_IOC_RECOVER, sleepFlag)) != 0) {
		printk(KERN_WARNING MYNAM ": WARNING - (%d) Cannot recover %s\n",
			rc, ioc->name);
	}
	ioc->reload_fw = 0;
	if (ioc->alt_ioc)
                ioc->alt_ioc->reload_fw = 0;

	dtmprintk((MYIOC_s_INFO_FMT "HardResetHandler rc = %d!\n", ioc->name, rc));

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mpt_writeSDP1  - write SCSI Device Page 1
 *	@ioc: Pointer to a SCSI Host Adapter Structure 
 *	@portnum: IOC port number
 *	@id: writeSDP1 for single ID
 *	@flags: MPT_SCSICFG_ALL_IDS, MPT_SCSICFG_USE_NVRAM, MPT_SCSICFG_BLK_NEGO
 *
 *	Return: -EFAULT if read of config page header fails
 *		or 0 if success.
 *
 *	Remark: If a target has been found, the settings from the
 *		target structure are used, else the device is set
 *		to async/narrow.
 *
 *	Remark: Called during init and after a FW reload.
 *	Remark: We do not wait for a return, write pages sequentially.
 */
int
mpt_writeSDP1(MPT_ADAPTER *ioc, int portnum, int id, int flags)
{
	Config_t		*pReq;
	SCSIDevicePage1_t	*pData;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	MPT_FRAME_HDR		*mf;
	dma_addr_t		 dataDma;
	u16			 req_idx;
	u32			 frameOffset;
	u32			 requested, configuration, flagsLength;
	int			 ii, nvram;
	int			 loop_id, loop_end;
	u8			 width;
	u8			 factor;
	u8			 offset;
	u8			 bus = 0;
	u8			 negoFlags;
	u8			 maxwidth, maxoffset, maxfactor;

	if ((pMptTarget = ioc->Target_List[0]) == NULL)
		return 0;

	if (ioc->spi_data.sdp1length == 0)
		return 0;

	if (flags & MPT_SCSICFG_ALL_IDS) {
		loop_id = 0;
		loop_end = ioc->DevicesPerBus;
	} else {
		loop_id = id;
		loop_end = id+1;
	}

	for (; loop_id < loop_end; loop_id++) {

		if (loop_id == ioc->pfacts[portnum].PortSCSIID)
			continue;

		
		pTarget = pMptTarget->Target[loop_id];

		/* Use NVRAM to get adapter and target maximums
		 * Data over-riden by target structure information, if present
		 */
		maxwidth = ioc->spi_data.maxBusWidth;
		maxoffset = ioc->spi_data.maxSyncOffset;
		maxfactor = ioc->spi_data.minSyncFactor;
		if (ioc->spi_data.nvram && (ioc->spi_data.nvram[loop_id] != MPT_HOST_NVRAM_INVALID)) {
			nvram = ioc->spi_data.nvram[loop_id];

			if (maxwidth)
				maxwidth = nvram & MPT_NVRAM_WIDE_DISABLE ? 0 : 1;

			if (maxoffset > 0) {
				maxfactor = (nvram & MPT_NVRAM_SYNC_MASK) >> 8;
				if (maxfactor == 0) {
					/* Key for async */
					maxfactor = MPT_ASYNC;
					maxoffset = 0;
				} else if (maxfactor < ioc->spi_data.minSyncFactor) {
					maxfactor = ioc->spi_data.minSyncFactor;
				}
			} else
				maxfactor = MPT_ASYNC;
		}

		/* Set the negotiation flags.
		 */
		negoFlags = ioc->spi_data.noQas;
		if (!maxwidth)
			negoFlags |= MPT_TARGET_NO_NEGO_WIDE;

		if (!maxoffset)
			negoFlags |= MPT_TARGET_NO_NEGO_SYNC;

		if (flags & MPT_SCSICFG_USE_NVRAM) {
			width = maxwidth;
			factor = maxfactor;
			offset = maxoffset;
			dnegoprintk(("%s: writeSDP1: USE_NVRAM id=%d width=%d factor=%x offset=%x negoFlags=%x\n",
				ioc->name, loop_id, width, factor, offset, negoFlags));
		} else {
			width = 0;
			factor = MPT_ASYNC;
			offset = 0;
			//negoFlags = 0;
			//negoFlags = MPT_TARGET_NO_NEGO_SYNC;
			dnegoprintk(("%s: writeSDP1: !USE_NVRAM: Going Async/Narrow id=%d width=%d factor=%x offset=%x negoFlags=%x\n",
				ioc->name, loop_id, width, factor, offset, negoFlags));
		}

		/* If id is not a raid volume, get the updated
		 * transmission settings from the target structure.
		 */
		if ( pTarget && !pTarget->raidVolume) {
			width = pTarget->maxWidth;
			factor = pTarget->minSyncFactor;
			offset = pTarget->maxOffset;
			negoFlags |= pTarget->negoFlags;
			dnegoprintk(("%s: writeSDP1: NOT RAID id=%d width=%d factor=%x offset=%x negoFlags=%x\n",
				ioc->name, loop_id, width, factor, offset, negoFlags));
		}

#ifdef MPTSCSIH_ENABLE_DOMAIN_VALIDATION
		/* Force to async and narrow if DV has not been executed
		 * for this ID
		 */
		if ((ioc->spi_data.dvStatus[loop_id] & MPT_SCSICFG_DV_NOT_DONE) != 0) {
			width = 0;
			factor = MPT_ASYNC;
			offset = 0;
			dnegoprintk(("%s: writeSDP1: DV_NOT_DONE: Going Async/Narrow id=%d width=%d factor=%x offset=%x negoFlags=%x\n",
				ioc->name, loop_id, width, factor, offset, negoFlags));
		}
#endif

		if (flags & MPT_SCSICFG_BLK_NEGO) {
			negoFlags |= MPT_TARGET_NO_NEGO_WIDE | MPT_TARGET_NO_NEGO_SYNC;
			dnegoprintk(("%s: writeSDP1: BLK_NEGO id=%d width=%d factor=%x offset=%x negoFlags=%x\n",
				ioc->name, loop_id, width, factor, offset, negoFlags));
		}

		mpt_setSDP1parameters(width, factor, offset, negoFlags,
				&requested, &configuration);

		/* Get a MF for this command.
		 */
		if ((mf = mpt_get_msg_frame(ioc->DoneCtx, ioc)) == NULL) {
			dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
			    ioc->name,__FUNCTION__));
			return -EAGAIN;
		}

		/* Set the request and the data pointers.
		 * Request takes: 36 bytes (32 bit SGE)
		 * SCSI Device Page 1 requires 16 bytes
		 * 40 + 16 <= size of SCSI IO Request = 56 bytes
		 * and MF size >= 64 bytes.
		 * Place data at end of MF.
		 */
		pReq = (Config_t *)mf;

		req_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
		frameOffset = ioc->req_sz - sizeof(SCSIDevicePage1_t);

		pData = (SCSIDevicePage1_t *)((u8 *) mf + frameOffset);
		dataDma = ioc->req_frames_dma + (req_idx * ioc->req_sz) + frameOffset;

		/* Complete the request frame (same for all requests).
		 */
		pReq->Action = MPI_CONFIG_ACTION_PAGE_WRITE_CURRENT;
		pReq->Reserved = 0;
		pReq->ChainOffset = 0;
		pReq->Function = MPI_FUNCTION_CONFIG;
		pReq->ExtPageLength = 0;
		pReq->ExtPageType = 0;
		pReq->MsgFlags = 0;
		for (ii=0; ii < 8; ii++) {
			pReq->Reserved2[ii] = 0;
		}
		pReq->Header.PageVersion = ioc->spi_data.sdp1version;
		pReq->Header.PageLength = ioc->spi_data.sdp1length;
		pReq->Header.PageNumber = 1;
		pReq->Header.PageType = MPI_CONFIG_PAGETYPE_SCSI_DEVICE;
		pReq->PageAddress = cpu_to_le32(loop_id | (bus << 8 ));

		/* Add a SGE to the config request.
		 */
		flagsLength = MPT_SGE_FLAGS_SSIMPLE_WRITE | ioc->spi_data.sdp1length * 4;

		ioc->add_sge((char *)&pReq->PageBufferSGE, flagsLength, dataDma);

		/* Set up the common data portion
		 */
		pData->Header.PageVersion = pReq->Header.PageVersion;
		pData->Header.PageLength = pReq->Header.PageLength;
		pData->Header.PageNumber = pReq->Header.PageNumber;
		pData->Header.PageType = pReq->Header.PageType;
		pData->RequestedParameters = cpu_to_le32(requested);
		pData->Reserved = 0;
		pData->Configuration = cpu_to_le32(configuration);

		if ( pTarget ) {
			if ( requested & MPI_SCSIDEVPAGE1_RP_IU ) {
				pTarget->last_lun = MPT_LAST_LUN;
			} else {
				pTarget->last_lun = MPT_NON_IU_LAST_LUN;
			}
			dsprintk((MYIOC_s_INFO_FMT
				"writeSDP1: last_lun=%d on id=%d\n",
				ioc->name, pTarget->last_lun, loop_id));
		}

		dnegoprintk((MYIOC_s_INFO_FMT
			"write SDP1: id=%d pgaddr=0x%x requested=%08x configuration=%08x\n",
				ioc->name, loop_id, (loop_id | (bus<<8)),
				requested, configuration));

		mpt_put_msg_frame(ioc->DoneCtx, ioc, mf);
	}
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mpt_setSDP1parameters  - set SDP1 Requested and Configuration 
 *	fields based on width, factor, offset and flags parameters.
 *	@width: bus width
 *	@factor: sync factor
 *	@offset: sync offset
 *	@flags: flags to block WDTR or SDTR negotiation
 *	@requestedPtr: pointer to SDP1 Requested value (updated)
 *	@configurationPtr: pointer to SDP1 Configuration value (updated)
 *
 *	Return: None.
 *
 *	Remark: Called by writeSDP1 and _dv_params
 */
void
mpt_setSDP1parameters (u8 width, u8 factor, u8 offset, u8 flags, int *requestedPtr, int *configurationPtr)
{
	u8 nowide = flags & MPT_TARGET_NO_NEGO_WIDE;
	u8 nosync = flags & MPT_TARGET_NO_NEGO_SYNC;

	*configurationPtr = 0;
	*requestedPtr = width ? MPI_SCSIDEVPAGE1_RP_WIDE : 0;
	*requestedPtr |= (offset << 16) | (factor << 8);

	if (width && offset && !nowide && !nosync) {
		if (factor < MPT_ULTRA160) {
			*requestedPtr |= (MPI_SCSIDEVPAGE1_RP_IU + MPI_SCSIDEVPAGE1_RP_DT);
			if ((flags & MPT_TARGET_NO_NEGO_QAS) == 0)
				*requestedPtr |= MPI_SCSIDEVPAGE1_RP_QAS;
			if (flags & MPT_TAPE_NEGO_IDP)
				*requestedPtr |= 0x08000000;
		} else if (factor < MPT_ULTRA2) {
			*requestedPtr |= MPI_SCSIDEVPAGE1_RP_DT;
		}
	}

	if (nowide)
		*configurationPtr |= MPI_SCSIDEVPAGE1_CONF_WDTR_DISALLOWED;

	if (nosync)
		*configurationPtr |= MPI_SCSIDEVPAGE1_CONF_SDTR_DISALLOWED;

	return;
}

# define EVENT_DESCR_STR_SZ		100

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void
EventDescriptionStr(u8 event, u32 evData0, char *evStr)
{
	char *ds = NULL;

	switch(event) {
	case MPI_EVENT_NONE:
		ds = "None";
		break;
	case MPI_EVENT_LOG_DATA:
		ds = "Log Data";
		break;
	case MPI_EVENT_STATE_CHANGE:
		ds = "State Change";
		break;
	case MPI_EVENT_UNIT_ATTENTION:
		ds = "Unit Attention";
		break;
	case MPI_EVENT_IOC_BUS_RESET:
		ds = "IOC Bus Reset";
		break;
	case MPI_EVENT_EXT_BUS_RESET:
		ds = "External Bus Reset";
		break;
	case MPI_EVENT_RESCAN:
		ds = "Bus Rescan Event";
		break;
	case MPI_EVENT_LINK_STATUS_CHANGE:
		if (evData0 == MPI_EVENT_LINK_STATUS_FAILURE)
			ds = "Link Status(FAILURE) Change";
		else
			ds = "Link Status(ACTIVE) Change";
		break;
	case MPI_EVENT_LOOP_STATE_CHANGE:
		if (evData0 == MPI_EVENT_LOOP_STATE_CHANGE_LIP)
			ds = "Loop State(LIP) Change";
		else if (evData0 == MPI_EVENT_LOOP_STATE_CHANGE_LPE)
			ds = "Loop State(LPE) Change";		/* ??? */
		else
			ds = "Loop State(LPB) Change";		/* ??? */
		break;
	case MPI_EVENT_LOGOUT:
		ds = "Logout";
		break;
	case MPI_EVENT_EVENT_CHANGE:
		if (evData0)
			ds = "Events ON";
		else
			ds = "Events OFF";
		break;
	case MPI_EVENT_INTEGRATED_RAID:
	{
		u8 ReasonCode = (u8)(evData0 >> 16);
		switch (ReasonCode) {
		case MPI_EVENT_RAID_RC_VOLUME_CREATED :
			ds = "Integrated Raid: Volume Created";
			break;
		case MPI_EVENT_RAID_RC_VOLUME_DELETED :
			ds = "Integrated Raid: Volume Deleted";
			break;
		case MPI_EVENT_RAID_RC_VOLUME_SETTINGS_CHANGED :
			ds = "Integrated Raid: Volume Settings Changed";
			break;
		case MPI_EVENT_RAID_RC_VOLUME_STATUS_CHANGED :
			ds = "Integrated Raid: Volume Status Changed";
			break;
		case MPI_EVENT_RAID_RC_VOLUME_PHYSDISK_CHANGED :
			ds = "Integrated Raid: Volume Physdisk Changed";
			break;
		case MPI_EVENT_RAID_RC_PHYSDISK_CREATED :
			ds = "Integrated Raid: Physdisk Created";
			break;
		case MPI_EVENT_RAID_RC_PHYSDISK_DELETED :
			ds = "Integrated Raid: Physdisk Deleted";
			break;
		case MPI_EVENT_RAID_RC_PHYSDISK_SETTINGS_CHANGED :
			ds = "Integrated Raid: Physdisk Settings Changed";
			break;
		case MPI_EVENT_RAID_RC_PHYSDISK_STATUS_CHANGED :
			ds = "Integrated Raid: Physdisk Status Changed";
			break;
		case MPI_EVENT_RAID_RC_DOMAIN_VAL_NEEDED :
			ds = "Integrated Raid: Domain Validation Needed";
			break;
		case MPI_EVENT_RAID_RC_SMART_DATA :
			ds = "Integrated Raid; Smart Data";
			break;
		case MPI_EVENT_RAID_RC_REPLACE_ACTION_STARTED :
			ds = "Integrated Raid: Replace Action Started";
			break;
		default:
			ds = "Integrated Raid";
		break;
		}
		break;
	}
	case MPI_EVENT_SCSI_DEVICE_STATUS_CHANGE:
		ds = "SCSI Device Status Change";
		break;
	case MPI_EVENT_SAS_DEVICE_STATUS_CHANGE:
	{
		u8 id = (u8)(evData0);
		u8 channel = (u8)(evData0 >> 8);
		u8 ReasonCode = (u8)(evData0 >> 16);
		u8 ioc_id = (u8)(evData0 >> 24);
		switch (ReasonCode) {
		case MPI_EVENT_SAS_DEV_STAT_RC_ADDED:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS Device Status Change: Added: "
			    "ha%d channel=%d id=%d", ioc_id, channel, id);
			break;
		case MPI_EVENT_SAS_DEV_STAT_RC_NOT_RESPONDING:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS Device Status Change: Deleted: "
			    "ha%d channel=%d id=%d", ioc_id, channel, id);
			break;
		case MPI_EVENT_SAS_DEV_STAT_RC_SMART_DATA:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS Device Status Change: SMART Data: "
			    "ha%d channel=%d id=%d", ioc_id, channel, id);
			break;
		case MPI_EVENT_SAS_DEV_STAT_RC_NO_PERSIST_ADDED:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS Device Status Change: No Persistancy: "
			    "ha%d channel=%d id=%d", ioc_id, channel, id);
			break;
		case MPI_EVENT_SAS_DEV_STAT_RC_UNSUPPORTED:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS Device Status Change: Unsupported Device: "
			    "ha%d channel=%d id=%d", ioc_id, channel, id);
			break;
		case MPI_EVENT_SAS_DEV_STAT_RC_INTERNAL_DEVICE_RESET:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS Device Status Change: Internal Device Reset: "
			    "ha%d channel=%d id=%d", ioc_id, channel, id);
			break;
		case MPI_EVENT_SAS_DEV_STAT_RC_TASK_ABORT_INTERNAL:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS Device Status Change: Internal Task Abort: "
			    "ha%d channel=%d id=%d", ioc_id, channel, id);
			break;
		case MPI_EVENT_SAS_DEV_STAT_RC_ABORT_TASK_SET_INTERNAL:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS Device Status Change: Internal Abort Task Set: "
			    "ha%d channel=%d id=%d", ioc_id, channel, id);
			break;
		case MPI_EVENT_SAS_DEV_STAT_RC_CLEAR_TASK_SET_INTERNAL:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS Device Status Change: Internal Clear Task Set: "
			    "ha%d channel=%d id=%d", ioc_id, channel, id);
			break;
		case MPI_EVENT_SAS_DEV_STAT_RC_QUERY_TASK_INTERNAL:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS Device Status Change: Internal Query Task: "
			    "ha%d channel=%d id=%d", ioc_id, channel, id);
			break;
		default:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS Device Status Change: Unknown Event: "
			    "ha%d channel=%d id=%d", ioc_id, channel, id);
			break;
		}
		break;
	}
	case MPI_EVENT_ON_BUS_TIMER_EXPIRED:
		ds = "Bus Timer Expired";
		break;
	case MPI_EVENT_QUEUE_FULL:
		ds = "Queue Full";
		break;
	case MPI_EVENT_SAS_SES:
		ds = "SAS SES Event";
		break;
	case MPI_EVENT_PERSISTENT_TABLE_FULL:
		ds = "Persistent Table Full";
		break;
	case MPI_EVENT_SAS_PHY_LINK_STATUS:
	{
		u8 LinkRates = (u8)(evData0 >> 8);
		u8 PhyNumber = (u8)(evData0);
		LinkRates = (LinkRates & MPI_EVENT_SAS_PLS_LR_CURRENT_MASK) >>
			MPI_EVENT_SAS_PLS_LR_CURRENT_SHIFT;
		switch (LinkRates) {
		case MPI_EVENT_SAS_PLS_LR_RATE_UNKNOWN:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			   "SAS PHY Link Status: Phy=%d:"
			   " Rate Unknown",PhyNumber);
			break;
		case MPI_EVENT_SAS_PLS_LR_RATE_PHY_DISABLED:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			   "SAS PHY Link Status: Phy=%d:"
			   " Phy Disabled",PhyNumber);
			break;
		case MPI_EVENT_SAS_PLS_LR_RATE_FAILED_SPEED_NEGOTIATION:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			   "SAS PHY Link Status: Phy=%d:"
			   " Failed Speed Nego",PhyNumber);
			break;
		case MPI_EVENT_SAS_PLS_LR_RATE_SATA_OOB_COMPLETE:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			   "SAS PHY Link Status: Phy=%d:"
			   " Sata OOB Completed",PhyNumber);
			break;
		case MPI_EVENT_SAS_PLS_LR_RATE_1_5:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			   "SAS PHY Link Status: Phy=%d:"
			   " Rate 1.5 Gbps",PhyNumber);
			break;
		case MPI_EVENT_SAS_PLS_LR_RATE_3_0:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			   "SAS PHY Link Status: Phy=%d:"
			   " Rate 3.0 Gpbs",PhyNumber);
			break;
		default:
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			   "SAS PHY Link Status: Phy=%d", PhyNumber);
			break;
		}
		break;
	}
	case MPI_EVENT_SAS_DISCOVERY_ERROR:
		ds = "SAS Discovery Error";
		break;
	case MPI_EVENT_IR_RESYNC_UPDATE:
	{
		u8 resync_complete = (u8)(evData0 >> 16);
		snprintf(evStr, EVENT_DESCR_STR_SZ,
		    "IR Resync Update: Complete = %d:",resync_complete);
		break;
	}
	case MPI_EVENT_IR2:
	{
		u8 ReasonCode = (u8)(evData0 >> 16);
		switch (ReasonCode) {
		case MPI_EVENT_IR2_RC_LD_STATE_CHANGED:
			ds = "IR2: LD State Changed";
			break;
		case MPI_EVENT_IR2_RC_PD_STATE_CHANGED:
			ds = "IR2: PD State Changed";
			break;
		case MPI_EVENT_IR2_RC_BAD_BLOCK_TABLE_FULL:
			ds = "IR2: Bad Block Table Full";
			break;
		case MPI_EVENT_IR2_RC_PD_INSERTED:
			ds = "IR2: PD Inserted";
			break;
		case MPI_EVENT_IR2_RC_PD_REMOVED:
			ds = "IR2: PD Removed";
			break;
		case MPI_EVENT_IR2_RC_FOREIGN_CFG_DETECTED:
			ds = "IR2: Foreign CFG Detected";
			break;
		case MPI_EVENT_IR2_RC_REBUILD_MEDIUM_ERROR:
			ds = "IR2: Rebuild Medium Error";
			break;
		default:
			ds = "IR2";
		break;
		}
		break;
	}
	case MPI_EVENT_SAS_DISCOVERY:
	{
		if (evData0)
			ds = "SAS Discovery: Start";
		else
			ds = "SAS Discovery: Stop";
		break;
	}
	case MPI_EVENT_LOG_ENTRY_ADDED:
		ds = "SAS Log Entry Added";
		break;

	case MPI_EVENT_SAS_BROADCAST_PRIMITIVE:
	{
		u8 phy_num = (u8)(evData0);
		u8 port_num = (u8)(evData0 >> 8);
		u8 port_width = (u8)(evData0 >> 16);
		u8 primitive = (u8)(evData0 >> 24);
		snprintf(evStr, EVENT_DESCR_STR_SZ,
		    "SAS Broadcast Primative: phy=%d port=%d "
		    "width=%d primitive=0x%02x",
		    phy_num, port_num, port_width, primitive);
		break;
	}

	case MPI_EVENT_SAS_INIT_DEVICE_STATUS_CHANGE:
	{
		u8 reason = (u8)(evData0);
		u8 port_num = (u8)(evData0 >> 8);
		u16 handle = le16_to_cpu(evData0 >> 16);

		snprintf(evStr, EVENT_DESCR_STR_SZ,
		    "SAS Initiator Device Status Change: reason=0x%02x "
		    "port=%d handle=0x%04x",
		    reason, port_num, handle);
		break;
	}

	case MPI_EVENT_SAS_INIT_TABLE_OVERFLOW:
	{
		u8 max_init = (u8)(evData0);
		u8 current_init = (u8)(evData0 >> 8);

		snprintf(evStr, EVENT_DESCR_STR_SZ,
		    "SAS Initiator Device Table Overflow: max initiators=%02d "
		    "current initators=%02d",
		    max_init, current_init);
		break;
	}
	case MPI_EVENT_SAS_SMP_ERROR:
	{
		u8 status = (u8)(evData0);
		u8 port_num = (u8)(evData0 >> 8);
		u8 result = (u8)(evData0 >> 16);

		if (status == MPI_EVENT_SAS_SMP_FUNCTION_RESULT_VALID)
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS SMP Error: port=%d result=0x%02x",
			    port_num, result);
		else if (status == MPI_EVENT_SAS_SMP_CRC_ERROR)
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS SMP Error: port=%d : CRC Error",
			    port_num);
		else if (status == MPI_EVENT_SAS_SMP_TIMEOUT)
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS SMP Error: port=%d : Timeout",
			    port_num);
		else if (status == MPI_EVENT_SAS_SMP_NO_DESTINATION)
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS SMP Error: port=%d : No Destination",
			    port_num);
		else if (status == MPI_EVENT_SAS_SMP_BAD_DESTINATION)
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS SMP Error: port=%d : Bad Destination",
			    port_num);
		else
			snprintf(evStr, EVENT_DESCR_STR_SZ,
			    "SAS SMP Error: port=%d : status=0x%02x",
			    port_num, status);
		break;
	}

	/*
	 *  MPT base "custom" events may be added here...
	 */
	default:
		ds = "Unknown";
		break;
	}
	if (ds)
		strncpy(evStr, ds, EVENT_DESCR_STR_SZ);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	ProcessEventNotification - Route a received EventNotificationReply to
 *	all currently regeistered event handlers.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@pEventReply: Pointer to EventNotification reply frame
 *	@evHandlers: Pointer to integer, number of event handlers
 *
 *	Returns sum of event handlers return values.
 */
static int
ProcessEventNotification(MPT_ADAPTER *ioc, EventNotificationReply_t *pEventReply, int *evHandlers)
{
	u16 evDataLen;
	u32 evData0 = 0;
//	u32 evCtx;
	int ii;
	int r = 0;
	int handlers = 0;
	char evStr[100];
	u8 event;

	/*
	 *  Do platform normalization of values
	 */
	event = le32_to_cpu(pEventReply->Event) & 0xFF;
//	evCtx = le32_to_cpu(pEventReply->EventContext);
	evDataLen = le16_to_cpu(pEventReply->EventDataLength);
	if (evDataLen) {
		evData0 = le32_to_cpu(pEventReply->Data[0]);
		evData0 &= 0x00fffff;
		evData0 |= (u32)(ioc->id << 24);
	}

	EventDescriptionStr(event, evData0, evStr);
	devtprintk((MYIOC_s_WARN_FMT "MPT event:(%02Xh) : %s\n",
	    ioc->name, event, evStr));
	devt1printk((MYIOC_s_WARN_FMT "MPT event:(%02Xh) : %s\n",
	    ioc->name, event, evStr));

//#if defined(MPT_DEBUG) || defined(MPT_DEBUG_EVENTS)
//	printk(KERN_WARNING MYNAM ": %s: Event data:\n", ioc->name);
//	for (ii = 0; ii < evDataLen; ii++)
//		printk(" %08x", le32_to_cpu(pEventReply->Data[ii]));
//	printk("\n");
//#endif

	/*
	 *  Do general / base driver event processing
	 */
	switch(event) {
	case MPI_EVENT_EVENT_CHANGE:		/* 0A */
		if (evDataLen) {
			u8 evState = evData0 & 0xFF;

			/* CHECKME! What if evState unexpectedly says OFF (0)? */

			/* Update EventState field in cached IocFacts */
			if (ioc->facts.Function) {
				ioc->facts.EventState = evState;
			}
		}
		break;
	case MPI_EVENT_INTEGRATED_RAID:
		mptbase_raid_process_event_data(ioc,
		    (MpiEventDataRaid_t *)pEventReply->Data);
		break;
	case MPI_EVENT_RESCAN:
	case MPI_EVENT_LINK_STATUS_CHANGE:
		ioc->FcLinkSpeedCheckNeeded = 1;
		break;
	default:
		break;
	}

	/*
	 * Should this event be logged? Events are written sequentially.
	 * When buffer is full, start again at the top.
	 */
	if (ioc->events && (ioc->eventTypes & ( 1 << event))) {
		int idx;

		idx = ioc->eventContext % MPTCTL_EVENT_LOG_SIZE;

		ioc->events[idx].event = event;
		ioc->events[idx].eventContext = ioc->eventContext;

		for (ii = 0; ii < 2; ii++) {
			if (ii < evDataLen)
				ioc->events[idx].data[ii] = le32_to_cpu(pEventReply->Data[ii]);
			else
				ioc->events[idx].data[ii] =  0;
		}

		ioc->eventContext++;
	}


	/*
	 *  Call each currently registered protocol event handler.
	 */
	for (ii=MPT_MAX_PROTOCOL_DRIVERS-1; ii; ii--) {
		if (MptEvHandlers[ii]) {
//			devtprintk((MYIOC_s_WARN_FMT "Routing Event to event handler #%d\n",
//					ioc->name, ii));
			r += (*(MptEvHandlers[ii]))(ioc, pEventReply);
			handlers++;
		}
	}
	/* FIXME?  Examine results here? */

	/*
	 *  If needed, send (a single) EventAck.
	 */
	if (pEventReply->AckRequired == MPI_EVENT_NOTIFICATION_ACK_REQUIRED) {
		devtprintk((MYIOC_s_INFO_FMT
			"EventAck required\n",ioc->name));
		if ((ii = SendEventAck(ioc, pEventReply)) != 0) {
			devtprintk((MYIOC_s_WARN_FMT "SendEventAck returned %d\n",
					ioc->name, ii));
		}
	}

	*evHandlers = handlers;
	return r;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_fc_log_info - Log information returned from Fibre Channel IOC.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@log_info: U32 LogInfo reply word from the IOC
 *
 *	Refer to lsi/mpi_log_fc.h.
 */
static void
mpt_fc_log_info(MPT_ADAPTER *ioc, u32 log_info)
{
	static char *subcl_str[8] = {
		"FCP Initiator", "FCP Target", "LAN", "MPI Message Layer",
		"FC Link", "Context Manager", "Invalid Field Offset", "State Change Info"
	};
	u8 subcl = (log_info >> 24) & 0x7;

	printk(MYIOC_s_INFO_FMT "LogInfo(0x%08x): SubCl={%s}\n",
			ioc->name, log_info, subcl_str[subcl]);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_spi_log_info - Log information returned from SCSI Parallel IOC.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@mr: Pointer to MPT reply frame
 *	@log_info: U32 LogInfo word from the IOC
 *
 *	Refer to lsi/sp_log.h.
 */
static void
mpt_spi_log_info(MPT_ADAPTER *ioc, u32 log_info)
{
	u32 info = log_info & 0x00FF0000;
	char *desc = "unknown";

	switch (info) {
	case 0x00010000:
		desc = "bug! MID not found";
		if (ioc->reload_fw == 0)
			ioc->reload_fw++;
		break;

	case 0x00020000:
		desc = "Parity Error";
		break;

	case 0x00030000:
		desc = "ASYNC Outbound Overrun";
		break;

	case 0x00040000:
		desc = "SYNC Offset Error";
		break;

	case 0x00050000:
		desc = "BM Change";
		break;

	case 0x00060000:
		desc = "Msg In Overflow";
		break;

	case 0x00070000:
		desc = "DMA Error";
		break;

	case 0x00080000:
		desc = "Outbound DMA Overrun";
		break;

	case 0x00090000:
		desc = "Task Management";
		break;

	case 0x000A0000:
		desc = "Device Problem";
		break;

	case 0x000B0000:
		desc = "Invalid Phase Change";
		break;

	case 0x000C0000:
		desc = "Untagged Table Size";
		break;

	}

	printk(MYIOC_s_INFO_FMT "LogInfo(0x%08x): F/W: %s\n", ioc->name, log_info, desc);
}

/* strings for sas loginfo */
	static char *originator_str[] = {
		"IOP",						/* 00h */
		"PL",						/* 01h */
		"IR"						/* 02h */
	};
	static char *iop_code_str[] = {
		NULL,						/* 00h */
		"Invalid SAS Address",				/* 01h */
		NULL,						/* 02h */
		"Invalid Page",					/* 03h */
		NULL,						/* 04h */
		"Task Terminated"				/* 05h */
	};
	static char *pl_code_str[] = {
		NULL,						/* 00h */
		"Open Failure",					/* 01h */
		"Invalid Scatter Gather List",			/* 02h */
		"Wrong Relative Offset or Frame Length",	/* 03h */
		"Frame Transfer Error",				/* 04h */
		"Transmit Frame Connected Low",			/* 05h */
		"SATA Non-NCQ RW Error Bit Set",		/* 06h */
		"SATA Read Log Receive Data Error",		/* 07h */
		"SATA NCQ Fail All Commands After Error",	/* 08h */
		"SATA Error in Receive Set Device Bit FIS",	/* 09h */
		"Receive Frame Invalid Message",		/* 0Ah */
		"Receive Context Message Valid Error",		/* 0Bh */
		"Receive Frame Current Frame Error",		/* 0Ch */
		"SATA Link Down",				/* 0Dh */
		"Discovery SATA Init W IOS",			/* 0Eh */
		"Config Invalid Page",				/* 0Fh */
		"Discovery SATA Init Timeout",			/* 10h */
		"Reset",					/* 11h */
		"Abort",					/* 12h */
		"IO Not Yet Executed",				/* 13h */
		"IO Executed",					/* 14h */
		NULL,						/* 15h */
		NULL,						/* 16h */
		NULL,						/* 17h */
		NULL,						/* 18h */
		NULL,						/* 19h */
		NULL,						/* 1Ah */
		NULL,						/* 1Bh */
		NULL,						/* 1Ch */
		NULL,						/* 1Dh */
		NULL,						/* 1Eh */
		NULL,						/* 1Fh */
		"Enclosure Management"				/* 20h */
	};

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_sas_log_info - Log information returned from SAS IOC.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@log_info: U32 LogInfo reply word from the IOC
 *
 *	Refer to lsi/mpi_log_sas.h.
 */
static void
mpt_sas_log_info(MPT_ADAPTER *ioc, u32 log_info)
{
union loginfo_type {
	u32	loginfo;
	struct {
		u32	subcode:16;
		u32	code:8;
		u32	originator:4;
		u32	bus_type:4;
	}dw;
};
	union loginfo_type sas_loginfo;
	char *code_desc = NULL;

	sas_loginfo.loginfo = log_info;
	if ((sas_loginfo.dw.bus_type != 3 /*SAS*/) &&
	    (sas_loginfo.dw.originator < sizeof(originator_str)/sizeof(char*)))
		return;
	if ((sas_loginfo.dw.originator == 0 /*IOP*/) &&
	    (sas_loginfo.dw.code < sizeof(iop_code_str)/sizeof(char*))) {
		code_desc = iop_code_str[sas_loginfo.dw.code];
	}else if ((sas_loginfo.dw.originator == 1 /*PL*/) &&
	    (sas_loginfo.dw.code < sizeof(pl_code_str)/sizeof(char*) )) {
		code_desc = pl_code_str[sas_loginfo.dw.code];
	}

	if (code_desc != NULL)
		printk("Originator={%s}, Code={%s},"
			" SubCode(0x%04x)\n",
			originator_str[sas_loginfo.dw.originator],
			code_desc,
			sas_loginfo.dw.subcode);
	else
		printk("Originator={%s}, Code=(0x%02x),"
			" SubCode(0x%04x)\n",
			originator_str[sas_loginfo.dw.originator],
			sas_loginfo.dw.code,
			sas_loginfo.dw.subcode);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mpt_sp_ioc_info - IOC information returned from SCSI Parallel IOC.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@ioc_status: U32 IOCStatus word from IOC
 *	@mf: Pointer to MPT request frame
 *
 *	Refer to lsi/mpi.h.
 */
static void
mpt_sp_ioc_info(MPT_ADAPTER *ioc, u32 ioc_status, MPT_FRAME_HDR *mf)
{
	u32 status = ioc_status & MPI_IOCSTATUS_MASK;
	char *desc = NULL;

	SCSIIORequest_t *pScsiReq = (SCSIIORequest_t *) mf;
	U8 cdb = pScsiReq->CDB[0];
	U8 id = pScsiReq->TargetID;
	U8 lun = pScsiReq->LUN[1];

	switch (status) {
	case MPI_IOCSTATUS_INVALID_FUNCTION: /* 0x0001 */
		desc = "Invalid Function";
		break;

	case MPI_IOCSTATUS_BUSY: /* 0x0002 */
		desc = "Busy";
		ddvprintk (("%s IOCSTATUS_BUSY", ioc->name));
		DBG_DUMP_RESET_REQUEST_FRAME(ioc, mf)
		break;

	case MPI_IOCSTATUS_INVALID_SGL: /* 0x0003 */
		desc = "Invalid SGL";
		break;

	case MPI_IOCSTATUS_INTERNAL_ERROR: /* 0x0004 */
		desc = "Internal Error";
		break;

	case MPI_IOCSTATUS_RESERVED: /* 0x0005 */
		desc = "Reserved";
		break;

	case MPI_IOCSTATUS_INSUFFICIENT_RESOURCES: /* 0x0006 */
		desc = "Insufficient Resources";
		break;

	case MPI_IOCSTATUS_INVALID_FIELD: /* 0x0007 */
		desc = "Invalid Field";
		break;

	case MPI_IOCSTATUS_INVALID_STATE: /* 0x0008 */
		desc = "Invalid State";
		break;

	case MPI_IOCSTATUS_CONFIG_INVALID_ACTION: /* 0x0020 */
	case MPI_IOCSTATUS_CONFIG_INVALID_TYPE:   /* 0x0021 */
	case MPI_IOCSTATUS_CONFIG_INVALID_PAGE:   /* 0x0022 */
	case MPI_IOCSTATUS_CONFIG_INVALID_DATA:   /* 0x0023 */
	case MPI_IOCSTATUS_CONFIG_NO_DEFAULTS:    /* 0x0024 */
	case MPI_IOCSTATUS_CONFIG_CANT_COMMIT:    /* 0x0025 */
		/* No message for Config IOCStatus values */
		break;

	case MPI_IOCSTATUS_SCSI_RECOVERED_ERROR: /* 0x0040 */
		/* No message for recovered error
		desc = "SCSI Recovered Error";
		*/
		break;

	case MPI_IOCSTATUS_SCSI_INVALID_BUS: /* 0x0041 */
		desc = "SCSI Invalid Bus";
		break;

	case MPI_IOCSTATUS_SCSI_INVALID_TARGETID: /* 0x0042 */
		desc = "SCSI Invalid TargetID";
		break;

	case MPI_IOCSTATUS_SCSI_DEVICE_NOT_THERE: /* 0x0043 */
	  {
#ifdef MPT_DEBUG_REPLY
		if (cdb != 0x12) { /* Inquiry is issued for device scanning */
			desc = "SCSI Device Not There";
		}
#endif
		break;
	  }

	case MPI_IOCSTATUS_SCSI_DATA_OVERRUN: /* 0x0044 */
		desc = "SCSI Data Overrun";
		break;

	case MPI_IOCSTATUS_SCSI_DATA_UNDERRUN: /* 0x0045 */
		/* This error is checked in scsi_io_done(). Skip. 
		desc = "SCSI Data Underrun";
		*/
		break;

	case MPI_IOCSTATUS_SCSI_IO_DATA_ERROR: /* 0x0046 */
		desc = "SCSI I/O Data Error";
		break;

	case MPI_IOCSTATUS_SCSI_PROTOCOL_ERROR: /* 0x0047 */
		desc = "SCSI Protocol Error";
		break;

	case MPI_IOCSTATUS_SCSI_TASK_TERMINATED: /* 0x0048 */
		desc = "SCSI Task Terminated";
		break;

	case MPI_IOCSTATUS_SCSI_RESIDUAL_MISMATCH: /* 0x0049 */
		desc = "SCSI Residual Mismatch";
		break;

	case MPI_IOCSTATUS_SCSI_TASK_MGMT_FAILED: /* 0x004A */
		desc = "SCSI Task Management Failed";
		break;

	case MPI_IOCSTATUS_SCSI_IOC_TERMINATED: /* 0x004B */
		desc = "SCSI IOC Terminated";
		break;

	case MPI_IOCSTATUS_SCSI_EXT_TERMINATED: /* 0x004C */
		desc = "SCSI Ext Terminated";
		break;

	case MPI_IOCSTATUS_DIAGNOSTIC_RELEASED: /* 0x00A0 */
		desc = "Diag Buffer Released";
		break;

	default:
		desc = "Others";
		break;
	}
	if (desc != NULL) {
		U8 function = pScsiReq->Function;
		if (function == MPI_FUNCTION_SCSI_IO_REQUEST ||
		    function == MPI_FUNCTION_RAID_SCSI_IO_PASSTHROUGH) {
			printk(MYIOC_s_WARN_FMT "IOCStatus(0x%04x): %s on CDB=%x id=%d lun=%d\n", ioc->name, status, desc, cdb, id, lun);
		} else {
			printk(MYIOC_s_WARN_FMT "IOCStatus(0x%04x): %s on Function=%02x\n", ioc->name, status, desc, function);
		}
		DBG_DUMP_REPLYS_REQUEST_FRAME(ioc, mf)
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mpt_poll_interrupt - Check the status of interrupt and if any interrupt
 *	are triggered, call interrupt handler.
 *	@ioc: Pointer to MPT_ADAPTER structure
 */
void
mpt_poll_interrupt(MPT_ADAPTER *ioc)
{
	u32 intstat;

	intstat = CHIPREG_READ32(&ioc->chip->IntStatus);

	if (intstat & MPI_HIS_REPLY_MESSAGE_INTERRUPT)
		mpt_interrupt(0, ioc, NULL);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
EXPORT_SYMBOL(mpt_attach);
EXPORT_SYMBOL(mpt_detach);
#ifdef CONFIG_PM
EXPORT_SYMBOL(mpt_resume);
EXPORT_SYMBOL(mpt_suspend);
#endif
EXPORT_SYMBOL(ioc_list);
EXPORT_SYMBOL(mpt_can_queue);
EXPORT_SYMBOL(mpt_fwfault_debug);
EXPORT_SYMBOL(mpt_proc_root_dir);
EXPORT_SYMBOL(mpt_register);
EXPORT_SYMBOL(mpt_deregister);
EXPORT_SYMBOL(mpt_event_register);
EXPORT_SYMBOL(mpt_event_deregister);
EXPORT_SYMBOL(mpt_reset_register);
EXPORT_SYMBOL(mpt_reset_deregister);
EXPORT_SYMBOL(mpt_downloadboot);
EXPORT_SYMBOL(mpt_device_driver_register);
EXPORT_SYMBOL(mpt_device_driver_deregister);
EXPORT_SYMBOL(mpt_get_msg_frame);
EXPORT_SYMBOL(mpt_put_msg_frame);
EXPORT_SYMBOL(mpt_free_msg_frame);
EXPORT_SYMBOL(mpt_freeChainBuffers);
EXPORT_SYMBOL(mpt_send_special_message);
EXPORT_SYMBOL(mpt_verify_adapter);
EXPORT_SYMBOL(mpt_GetIocState);
EXPORT_SYMBOL(mpt_print_ioc_summary);
EXPORT_SYMBOL(mpt_lan_index);
EXPORT_SYMBOL(mpt_stm_index);
EXPORT_SYMBOL(mpt_HardResetHandler);
EXPORT_SYMBOL(mpt_SendIocReset);
EXPORT_SYMBOL(mpt_do_ioc_recovery);
EXPORT_SYMBOL(mpt_writeSDP1);
EXPORT_SYMBOL(mpt_setSDP1parameters);
EXPORT_SYMBOL(mpt_config);
EXPORT_SYMBOL(mpt_findImVolumes);
EXPORT_SYMBOL(mpt_read_ioc_pg_3);
EXPORT_SYMBOL(mpt_alloc_fw_memory);
EXPORT_SYMBOL(mpt_free_fw_memory);
EXPORT_SYMBOL(mptbase_sas_persist_operation);
EXPORT_SYMBOL(mpt_alt_ioc_wait);
EXPORT_SYMBOL(mpt_raid_phys_disk_pg0);
EXPORT_SYMBOL(mpt_raid_phys_disk_pg1);
EXPORT_SYMBOL(mpt_raid_phys_disk_get_num_paths);
EXPORT_SYMBOL(mpt_enable_deadioc_detect);
EXPORT_SYMBOL(mpt_handshake_req_reply_wait);
EXPORT_SYMBOL(mpt_halt_firmware);
EXPORT_SYMBOL(mpt_poll_interrupt);
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	fusion_init - Fusion MPT base driver initialization routine.
 *
 *	Returns 0 for success, non-zero for failure.
 */
static int __init
fusion_init(void)
{
	int i;

	show_mptmod_ver(my_NAME, my_VERSION);
	printk(KERN_INFO COPYRIGHT "\n");

	for (i = 0; i < MPT_MAX_PROTOCOL_DRIVERS; i++) {
		MptCallbacks[i] = NULL;
		MptDriverClass[i] = MPTUNKNOWN_DRIVER;
		MptEvHandlers[i] = NULL;
		MptResetHandlers[i] = NULL;
	}

	/*  Register ourselves (mptbase) in order to facilitate
	 *  EventNotification handling.
	 */
	mpt_base_index = mpt_register(mpt_base_reply, MPTBASE_DRIVER);

	/* Register for hard reset handling callbacks.
	 */
	if (mpt_reset_register(mpt_base_index, mpt_ioc_reset) == 0) {
		dprintk((KERN_INFO MYNAM ": Register for IOC reset notification\n"));
	} else {
		/* FIXME! */
	}

#ifdef CONFIG_PROC_FS
	(void) procmpt_create();
#endif

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	fusion_exit - Perform driver unload cleanup.
 *
 *	This routine frees all resources associated with each MPT adapter
 *	and removes all %MPT_PROCFS_MPTBASEDIR entries.
 */
static void __exit
fusion_exit(void)
{

	dexitprintk((KERN_INFO MYNAM ": fusion_exit() called!\n"));

	mpt_reset_deregister(mpt_base_index);

#ifdef CONFIG_PROC_FS
	procmpt_destroy();
#endif
}


module_init(fusion_init);
module_exit(fusion_exit);

/*
 *  linux/drivers/message/fusion/mptctl.c
 *      mpt Ioctl driver.
 *      For use with LSI PCI chip/adapters
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

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/delay.h>	/* for mdelay */
#include <linux/miscdevice.h>
#include <linux/smp_lock.h>
#include <linux/compat.h>

#include <asm/io.h>
#include <asm/uaccess.h>

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>

#define COPYRIGHT	"Copyright (c) 1999-2007 LSI Corporation"
#define MODULEAUTHOR	"LSI Corporation"
#include "mptbase.h"
#include "mptctl.h"

#if defined(CPQ_CIM)
#include "mptsas.h"
#include "csmi/csmisas.h"
#endif // CPQ_CIM

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
#define my_NAME		"Fusion MPT misc device (ioctl) driver"
#define my_VERSION	MPT_LINUX_VERSION_COMMON
#define MYNAM		"mptctl"

MODULE_AUTHOR(MODULEAUTHOR);
MODULE_DESCRIPTION(my_NAME);
MODULE_LICENSE("GPL");
MODULE_VERSION(my_VERSION);

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/

extern	int mpt_downloadboot(MPT_ADAPTER *ioc, MpiFwHeader_t *pFwHeader, int sleepFlag);

extern int	mpt_handshake_req_reply_wait(MPT_ADAPTER *ioc, int reqBytes, u32 *req, int replyBytes, u16 *u16reply, int maxwait, int sleepFlag);

static int mptctl_id = -1;
static int mptctl_taskmgmt_id = -1;

static DECLARE_WAIT_QUEUE_HEAD ( mptctl_wait );
static DECLARE_WAIT_QUEUE_HEAD ( mptctl_taskmgmt_wait );


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/

struct buflist {
	u8	*kptr;
	int	 len;
};

/*
 * Function prototypes. Called from OS entry point mptctl_ioctl.
 * arg contents specific to function.
 */
static int mptctl_fw_download(unsigned long arg);
static int mptctl_fw_downloadboot(unsigned long arg);
static int mptctl_getiocinfo(unsigned long arg, unsigned int cmd);
static int mptctl_gettargetinfo(unsigned long arg);
static int mptctl_readtest(unsigned long arg);
static int mptctl_mpt_command(unsigned long arg);
static int mptctl_eventquery(unsigned long arg);
static int mptctl_eventenable(unsigned long arg);
static int mptctl_eventreport(unsigned long arg);
static int mptctl_replace_fw(unsigned long arg);
#ifdef MPT_SUPPORT_FWDLB_IOCTL
static int mptctl_hba_pciinfo(unsigned long arg);
#endif

static int mptctl_do_reset(unsigned long arg);
static int mptctl_hp_hostinfo(unsigned long arg, unsigned int cmd);
static int mptctl_hp_targetinfo(unsigned long arg);

static int mptctl_register_diag_buffer(unsigned long arg);
static int mptctl_release_diag_buffer(unsigned long arg);
static int mptctl_unregister_diag_buffer(unsigned long arg);
static int mptctl_query_diag_buffer(unsigned long arg);
static int mptctl_read_diag_buffer(unsigned long arg);
#if defined(CPQ_CIM)
static int csmisas_get_driver_info(unsigned long arg);
static int csmisas_get_cntlr_status(unsigned long arg);
static int csmisas_get_cntlr_config(unsigned long arg);
static int csmisas_get_phy_info(unsigned long arg);
static int csmisas_get_scsi_address(unsigned long arg);
static int csmisas_get_link_errors(unsigned long arg);
static int csmisas_smp_passthru(unsigned long arg);
static int csmisas_firmware_download(unsigned long arg);
static int csmisas_get_raid_info(unsigned long arg);
static int csmisas_get_raid_config(unsigned long arg);
static int csmisas_get_raid_features(unsigned long arg);
static int csmisas_set_raid_control(unsigned long arg);
static int csmisas_get_raid_element(unsigned long arg);
static int csmisas_set_raid_operation(unsigned long arg);
static int csmisas_set_phy_info(unsigned long arg);
static int csmisas_ssp_passthru(unsigned long arg);
static int csmisas_stp_passthru(unsigned long arg);
static int csmisas_get_sata_signature(unsigned long arg);
static int csmisas_get_device_address(unsigned long arg);
static int csmisas_task_managment(unsigned long arg);
static int csmisas_phy_control(unsigned long arg);
static int csmisas_get_connector_info(unsigned long arg);
static int csmisas_get_location(unsigned long arg);
#endif // CPQ_CIM

static int  mptctl_probe(struct pci_dev *, const struct pci_device_id *);
static void mptctl_remove(struct pci_dev *);

/*
 * Private function calls.
 */
static int mptctl_do_mpt_command(struct mpt_ioctl_command karg, void __user *mfPtr);
static int mptctl_do_fw_download(int ioc, char __user *ufwbuf, size_t fwlen);
static int mptctl_do_fw_downloadboot(int ioc, char *ufwbuf, size_t fwlen);
static MptSge_t *kbuf_alloc_2_sgl(int bytes, u32 dir, int sge_offset, int *frags,
		struct buflist **blp, dma_addr_t *sglbuf_dma, MPT_ADAPTER *ioc);
static void kfree_sgl(MptSge_t *sgl, dma_addr_t sgl_dma,
		struct buflist *buflist, MPT_ADAPTER *ioc);
static void mptctl_timeout_expired (MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf);
static int  mptctl_bus_reset(MPT_IOCTL *ioctl);
static int mptctl_set_tm_flags(MPT_SCSI_HOST *hd);
static void mptctl_free_tm_flags(MPT_ADAPTER *ioc);

/*
 * Reset Handler cleanup function
 */
static int  mptctl_ioc_reset(MPT_ADAPTER *ioc, int reset_phase);

/*
 * Event Handler function
 */
static int mptctl_event_process(MPT_ADAPTER *ioc, EventNotificationReply_t *pEvReply);
struct fasync_struct *async_queue=NULL;

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 * Scatter gather list (SGL) sizes and limits...
 */
//#define MAX_SCSI_FRAGS	9
#define MAX_FRAGS_SPILL1	9
#define MAX_FRAGS_SPILL2	15
#define FRAGS_PER_BUCKET	(MAX_FRAGS_SPILL2 + 1)

//#define MAX_CHAIN_FRAGS	64
//#define MAX_CHAIN_FRAGS	(15+15+15+16)
#define MAX_CHAIN_FRAGS		(4 * MAX_FRAGS_SPILL2 + 1)

//  Define max sg LIST bytes ( == (#frags + #chains) * 8 bytes each)
//  Works out to: 592d bytes!     (9+1)*8 + 4*(15+1)*8
//                  ^----------------- 80 + 512
#define MAX_SGL_BYTES		((MAX_FRAGS_SPILL1 + 1 + (4 * FRAGS_PER_BUCKET)) * 8)

/* linux only seems to ever give 128kB MAX contiguous (GFP_USER) mem bytes */
#define MAX_KMALLOC_SZ		(128*1024)

#define MPT_IOCTL_DEFAULT_TIMEOUT 10	/* Default timeout value (seconds) */

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptctl_syscall_down - Down the MPT adapter syscall semaphore.
 *	@ioc: Pointer to MPT adapter
 *	@nonblock: boolean, non-zero if O_NONBLOCK is set
 *
 *	All of the ioctl commands can potentially sleep, which is illegal
 *	with a spinlock held, thus we perform mutual exclusion here.
 *
 *	Returns negative errno on error, or zero for success.
 */
static inline int
mptctl_syscall_down(MPT_ADAPTER *ioc, int nonblock)
{
	int rc = 0;
	dctlprintk((KERN_INFO MYNAM ": mptctl_syscall_down(%p,%d) called\n", ioc, nonblock));

	if (nonblock) {
		if (down_trylock(&ioc->ioctl->sem_ioc))
			rc = -EAGAIN;
	} else {
		if (down_interruptible(&ioc->ioctl->sem_ioc))
			rc = -ERESTARTSYS;
	}
	dctlprintk((KERN_INFO MYNAM ": mptctl_syscall_down return %d\n", rc));
	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *  This is the callback for any message we have posted. The message itself
 *  will be returned to the message pool when we return from the IRQ
 *
 *  This runs in irq context so be short and sweet.
 *
 *  Returns 1 indicating alloc'd request frame ptr should be freed.
 */
static int
mptctl_reply(MPT_ADAPTER *ioc, MPT_FRAME_HDR *req, MPT_FRAME_HDR *reply)
{
	char *sense_data;
	int sz, req_index;
	u16 iocStatus;
	u8 cmd;
	u8 buffType;

	dctlprintk(("mptctl_reply()!\n"));
	if (req)
		 cmd = req->u.hdr.Function;
	else
		return 1;

	if (ioc->ioctl) {

		if (reply==NULL) {

			dctlprintk(("mptctl_reply() NULL Reply Function=%x!\n", cmd));

			ioc->ioctl->status |= MPT_IOCTL_STATUS_COMMAND_GOOD;
			ioc->ioctl->reset &= ~MPTCTL_RESET_OK;

			/* We are done, issue wake up
	 		*/
			ioc->ioctl->wait_done = 1;
			wake_up (&mptctl_wait);
			return 1;

		}

		dctlprintk(("mptctl_reply() with req=%p reply=%p Function=%x!\n", req, reply, cmd));

		/* Copy the reply frame (which much exist
		 * for non-SCSI I/O) to the IOC structure.
		 */
		dctlprintk(("Copying Reply Frame @%p to ioc%d!\n",
			reply, ioc->id));
		memcpy(ioc->ioctl->reply, reply,
			min(ioc->reply_sz, 4*reply->u.reply.MsgLength));
		ioc->ioctl->status |= MPT_IOCTL_STATUS_RF_VALID;

		/* Set the command status to GOOD if IOC Status is GOOD
		 * OR if SCSI I/O cmd and data underrun or recovered error.
		 */
		iocStatus = le16_to_cpu(reply->u.reply.IOCStatus) & MPI_IOCSTATUS_MASK;
		if (iocStatus  == MPI_IOCSTATUS_SUCCESS)
			ioc->ioctl->status |= MPT_IOCTL_STATUS_COMMAND_GOOD;

		if ((cmd == MPI_FUNCTION_SCSI_IO_REQUEST) ||
			(cmd == MPI_FUNCTION_RAID_SCSI_IO_PASSTHROUGH)) {

			dcsmisasprintk(ioc, printk(KERN_DEBUG "\tiocstatus = 0x%x, "
				"scsi_status = 0x%x, scsi_state = 0x%x\n",
				reply->u.sreply.IOCStatus,
				reply->u.sreply.SCSIStatus,
				reply->u.sreply.SCSIState));

			ioc->ioctl->reset &= ~MPTCTL_RESET_OK;

			if ((iocStatus == MPI_IOCSTATUS_SCSI_DATA_UNDERRUN) ||
				(iocStatus == MPI_IOCSTATUS_SCSI_RESIDUAL_MISMATCH) ||
				(iocStatus == MPI_IOCSTATUS_SCSI_RECOVERED_ERROR)) {
				ioc->ioctl->status |= MPT_IOCTL_STATUS_COMMAND_GOOD;
			}
		}

		/* Copy the sense data - if present
		 */
		if ((cmd == MPI_FUNCTION_SCSI_IO_REQUEST) &&
			(reply->u.sreply.SCSIState & MPI_SCSI_STATE_AUTOSENSE_VALID)){
			sz = req->u.scsireq.SenseBufferLength;
			req_index = le16_to_cpu(req->u.frame.hwhdr.msgctxu.fld.req_idx);
			sense_data = ((u8 *)ioc->sense_buf_pool + (req_index * MPT_SENSE_BUFFER_ALLOC));
			memcpy(ioc->ioctl->sense, sense_data, sz);
			ioc->ioctl->status |= MPT_IOCTL_STATUS_SENSE_VALID;
		}

		if (cmd == MPI_FUNCTION_SCSI_TASK_MGMT) {
			mptctl_free_tm_flags(ioc);
			del_timer(&ioc->TMtimer);
			dctlprintk((MYIOC_s_INFO_FMT "%s: TM completed\n",
				ioc->name, __FUNCTION__));
		}

		if (cmd == MPI_FUNCTION_DIAG_BUFFER_POST) {

			DiagBufferPostReply_t *DiagBufferPostReply =
				(DiagBufferPostReply_t *)reply;
			buffType = DiagBufferPostReply->BufferType;

			if ( le16_to_cpu(DiagBufferPostReply->IOCStatus) ==
				MPI_IOCSTATUS_DIAGNOSTIC_RELEASED) {
				ioc->DiagBuffer_Status[buffType] |=
					MPT_DIAG_BUFFER_IS_RELEASED;
			}
			if ( reply->u.reply.MsgLength > 5) {
				ioc->DataSize[buffType] =
					le32_to_cpu(DiagBufferPostReply->TransferLength);
			}
			dctlprintk((MYIOC_s_INFO_FMT "DIAG_BUFFER_POST reply status=%x MsgLength=%d\n",
				ioc->name, DiagBufferPostReply->IOCStatus,
				reply->u.reply.MsgLength));
		}


		/* We are done, issue wake up
		 */
		ioc->ioctl->wait_done = 1;
		wake_up (&mptctl_wait);
	}
	return 1;
}

static int
mptctl_taskmgmt_reply(MPT_ADAPTER *ioc, MPT_FRAME_HDR *req, MPT_FRAME_HDR *reply)
{
	u16 iocStatus;

	dctlprintk(("mptctl_taskmgmt_reply()!\n"));
	if (!req)
		return 1;

	if (reply==NULL) {

		dctlprintk(("mptctl_taskmgmt_reply() NULL Reply Function\n"));

		ioc->taskmgmt_cmds.status |= MPT_IOCTL_STATUS_COMMAND_GOOD;
		ioc->taskmgmt_cmds.reset &= ~MPTCTL_RESET_OK;

		/* We are done, issue wake up
 		*/
		ioc->taskmgmt_cmds.wait_done = 1;
		wake_up (&mptctl_taskmgmt_wait);
		return 1;

	}

	/* Copy the reply frame (which much exist
	 * for non-SCSI I/O) to the IOC structure.
	 */
	dctlprintk(("Copying Reply Frame @%p to ioc%d!\n",
		reply, ioc->id));
	memcpy(ioc->taskmgmt_cmds.reply, reply,
		min(ioc->reply_sz, 4*reply->u.reply.MsgLength));
	ioc->taskmgmt_cmds.status |= MPT_IOCTL_STATUS_RF_VALID;

	/* Set the command status to GOOD if IOC Status is GOOD
	 * OR if SCSI I/O cmd and data underrun or recovered error.
	 */
	iocStatus = le16_to_cpu(reply->u.reply.IOCStatus) & MPI_IOCSTATUS_MASK;
	if (iocStatus  == MPI_IOCSTATUS_SUCCESS)
		ioc->taskmgmt_cmds.status |= MPT_IOCTL_STATUS_COMMAND_GOOD;

	mptctl_free_tm_flags(ioc);


	/* We are done, issue wake up
	 */
	ioc->taskmgmt_cmds.wait_done = 1;
	wake_up (&mptctl_taskmgmt_wait);
	return 1;
}



/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* mptctl_timer_expired
 *
 * Call back for timer process. Used only for ioctl functionality.
 *
 */
static void
mptctl_timeout_expired (MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf)
{
	int rc = 1;
	MPT_IOCTL *ioctl = ioc->ioctl;

	dctlprintk((KERN_NOTICE MYNAM ": Timeout Expired! Host %d\n",
				ioc->id));

	ioctl->wait_done = 0;
	if (ioctl->reset & MPTCTL_RESET_OK)
		rc = mptctl_bus_reset(ioctl);

	if (rc) {
		/* Issue a reset for this device.
		 * The IOC is not responding.
		 */
		dctlprintk((MYIOC_s_INFO_FMT "Calling HardReset! \n",
			 ioctl->ioc->name));
		mpt_HardResetHandler(ioctl->ioc, NO_SLEEP);
	}
	return;

}

/* mptctl_bus_reset
 *
 * Bus reset code.
 *
 */
static int
mptctl_bus_reset(MPT_IOCTL *ioctl)
{
	MPT_FRAME_HDR	*mf;
	SCSITaskMgmt_t	*pScsiTm;
	MPT_SCSI_HOST	*hd;
	int		 ii;
	int		 retval;


	ioctl->reset &= ~MPTCTL_RESET_OK;

	if (ioctl->ioc->sh == NULL)
		return -EPERM;

	hd = (MPT_SCSI_HOST *) ioctl->ioc->sh->hostdata;
	if (hd == NULL)
		return -EPERM;

	/* Single threading ....
	 */
	if (mptctl_set_tm_flags(hd) != 0)
		return -EPERM;

	/* Send request
	 */
	if ((mf = mpt_get_msg_frame(mptctl_id, ioctl->ioc)) == NULL) {
		dctlprintk(("iod%d: IssueTaskMgmt, no msg frames!!\n",
				ioctl->ioc->id));

		mptctl_free_tm_flags(ioctl->ioc);
		return -ENOMEM;
	}

	dtmprintk((MYIOC_s_INFO_FMT "IssueTaskMgmt request @ %p\n",
			ioctl->ioc->name, mf));

	pScsiTm = (SCSITaskMgmt_t *) mf;
	pScsiTm->TargetID = ioctl->id;
	pScsiTm->Bus = ioctl->bus;
	pScsiTm->ChainOffset = 0;
	pScsiTm->Function = MPI_FUNCTION_SCSI_TASK_MGMT;
	pScsiTm->Reserved = 0;
	pScsiTm->TaskType = MPI_SCSITASKMGMT_TASKTYPE_RESET_BUS;
	pScsiTm->Reserved1 = 0;
	pScsiTm->MsgFlags = MPI_SCSITASKMGMT_MSGFLAGS_LIPRESET_RESET_OPTION;

	for (ii= 0; ii < 8; ii++)
		pScsiTm->LUN[ii] = 0;

	for (ii=0; ii < 7; ii++)
		pScsiTm->Reserved2[ii] = 0;

	pScsiTm->TaskMsgContext = 0;
	dtmprintk((MYIOC_s_INFO_FMT "mptctl_bus_reset: issued.\n", ioctl->ioc->name));

	DBG_DUMP_TM_REQUEST_FRAME((u32 *)mf);

	ioctl->wait_done=0;
	if ((retval = mpt_send_handshake_request(mptctl_id, ioctl->ioc,
	    sizeof(SCSITaskMgmt_t), (u32*)pScsiTm, 10, CAN_SLEEP)) != 0) {
		dfailprintk((MYIOC_s_ERR_FMT "_send_handshake FAILED!"
			" (hd %p, ioc %p, mf %p) \n", hd->ioc->name, hd,
			hd->ioc, mf));
		goto mptctl_bus_reset_done;
	}

	/* Now wait for the command to complete */
	ii = wait_event_timeout(mptctl_wait,
	     ioctl->wait_done == 1,
	     HZ*5 /* 5 second timeout */);

	if(ii <=0 && (ioctl->wait_done != 1 ))  {
		mpt_free_msg_frame(hd->ioc, mf);
		ioctl->wait_done = 0;
		retval = -1; /* return failure */
	}

mptctl_bus_reset_done:

	mptctl_free_tm_flags(ioctl->ioc);
	return retval;
}

static int
mptctl_set_tm_flags(MPT_SCSI_HOST *hd) {
	unsigned long flags;

	spin_lock_irqsave(&hd->ioc->FreeQlock, flags);

	if (hd->tmState == TM_STATE_NONE) {
		hd->tmState = TM_STATE_IN_PROGRESS;
		hd->tmPending = 1;
		spin_unlock_irqrestore(&hd->ioc->FreeQlock, flags);
	} else {
		spin_unlock_irqrestore(&hd->ioc->FreeQlock, flags);
		return -EBUSY;
	}

	return 0;
}

static void
mptctl_free_tm_flags(MPT_ADAPTER *ioc)
{
	MPT_SCSI_HOST * hd;
	unsigned long flags;

	hd = (MPT_SCSI_HOST *) ioc->sh->hostdata;
	if (hd == NULL)
		return;

	spin_lock_irqsave(&ioc->FreeQlock, flags);

	hd->tmState = TM_STATE_NONE;
	hd->tmPending = 0;
	spin_unlock_irqrestore(&ioc->FreeQlock, flags);

	return;
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* mptctl_ioc_reset
 *
 * Clean-up functionality. Used only if there has been a
 * reload of the FW due.
 *
 */
static int
mptctl_ioc_reset(MPT_ADAPTER *ioc, int reset_phase)
{
	MPT_IOCTL *ioctl = ioc->ioctl;
	dctlprintk((KERN_INFO MYNAM ": IOC %s_reset routed to IOCTL driver!\n",
		reset_phase==MPT_IOC_PRE_RESET ? "pre" : "post"));

	if(ioctl == NULL)
		return 1;

	switch(reset_phase) {
	case MPT_IOC_POST_RESET:
		ioctl->status &= ~MPT_IOCTL_STATUS_DID_IOCRESET;
		break;
	case MPT_IOC_PRE_RESET:
	default:
		break;
	}

	return 1;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* ASYNC Event Notification Support */
static int
mptctl_event_process(MPT_ADAPTER *ioc, EventNotificationReply_t *pEvReply)
{
	u8 event;

	event = le32_to_cpu(pEvReply->Event) & 0xFF;

	dctlprintk(("%s() called\n", __FUNCTION__));
	if(async_queue == NULL)
		return 1;

	/* Raise SIGIO for persistent events.
	 * TODO - this define is not in MPI spec yet,
	 * but they plan to set it to 0x21
	 */
	 if (event == 0x21 ) {
		ioc->aen_event_read_flag=1;
		dctlprintk(("Raised SIGIO to application\n"));
		devtprintk(("Raised SIGIO to application\n"));
		kill_fasync(&async_queue, SIGIO, POLL_IN);
		return 1;
	 }

	/* This flag is set after SIGIO was raised, and
	 * remains set until the application has read
	 * the event log via ioctl=MPTEVENTREPORT
	 */
	if(ioc->aen_event_read_flag)
		return 1;

	/* Signal only for the events that are
	 * requested for by the application
	 */
	if (ioc->events && (ioc->eventTypes & ( 1 << event))) {
		ioc->aen_event_read_flag=1;
		dctlprintk(("Raised SIGIO to application\n"));
		devtprintk(("Raised SIGIO to application\n"));
		kill_fasync(&async_queue, SIGIO, POLL_IN);
	}
	return 1;
}

static int
mptctl_fasync(int fd, struct file *filep, int mode)
{
	MPT_ADAPTER	*ioc;

	list_for_each_entry(ioc, &ioc_list, list)
		ioc->aen_event_read_flag=0;

	dctlprintk(("%s() called\n", __FUNCTION__));
	return fasync_helper(fd, filep, mode, &async_queue);
}

static int mptctl_open(struct inode *inode, struct file *file)
{
	dctlprintk(("%s() called\n", __FUNCTION__));
	/*
	 * Should support multiple management users
	 */
	return 0;
}

static int
mptctl_release(struct inode *inode, struct file *filep)
{
	dctlprintk(("%s() called\n", __FUNCTION__));
	return fasync_helper(-1, filep, 0, &async_queue);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *  MPT ioctl handler
 *  cmd - specify the particular IOCTL command to be issued
 *  arg - data specific to the command. Must not be null.
 */
static int
mptctl_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	mpt_ioctl_header __user *uhdr = (void __user *) arg;
	mpt_ioctl_header	 khdr;
	int iocnum;
	unsigned iocnumX;
	int nonblock = (file->f_flags & O_NONBLOCK);
	int ret;
	MPT_ADAPTER *iocp = NULL;

	dctlprintk(("mptctl_ioctl() called with cmd=%x\n", cmd));

	if (copy_from_user(&khdr, uhdr, sizeof(khdr))) {
		printk(KERN_ERR "%s: mptctl_ioctl() @%d - "
				"Unable to copy mpt_ioctl_header data @ %p\n",
				__FILE__, __LINE__, uhdr);
		return -EFAULT;
	}
	ret = -ENXIO;				/* (-6) No such device or address */

	/* Verify intended MPT adapter - set iocnum and the adapter
	 * pointer (iocp)
	 */
	iocnumX = khdr.iocnum & 0xFF;
	if (((iocnum = mpt_verify_adapter(iocnumX, &iocp)) < 0) ||
	    (iocp == NULL)) {
		dctlprintk(("mptctl_ioctl: ioc%d not found!\n",
				iocnumX));
		return -ENODEV;
	}

	/* Handle those commands that are just returning
	 * information stored in the driver.
	 * These commands should never time out and are unaffected
	 * by TM and FW reloads.
	 */
	if ((cmd & ~IOCSIZE_MASK) == (MPTIOCINFO & ~IOCSIZE_MASK)) {
		return mptctl_getiocinfo(arg, _IOC_SIZE(cmd));
	} else if (cmd == MPTTARGETINFO) {
		return mptctl_gettargetinfo(arg);
	} else if (cmd == MPTTEST) {
		return mptctl_readtest(arg);
	} else if (cmd == MPTEVENTQUERY) {
		return mptctl_eventquery(arg);
	} else if (cmd == MPTEVENTENABLE) {
		return mptctl_eventenable(arg);
	} else if (cmd == MPTEVENTREPORT) {
		return mptctl_eventreport(arg);
	} else if (cmd == MPTFWREPLACE) {
		return mptctl_replace_fw(arg);
	} else if (cmd == MPTDIAGQUERY) {
		return mptctl_query_diag_buffer(arg);
	} else if (cmd == MPTDIAGUNREGISTER) {
		return mptctl_unregister_diag_buffer(arg);

	}
#ifdef MPT_SUPPORT_FWDLB_IOCTL
	 else if (cmd == MPTHBAPCIINFO) {
		return mptctl_hba_pciinfo(arg);
	}
#endif

#if defined(CPQ_CIM)
	else if (cmd == CC_CSMI_SAS_GET_DRIVER_INFO) {
		return csmisas_get_driver_info(arg);
	} else if (cmd == CC_CSMI_SAS_GET_CNTLR_CONFIG) {
		return csmisas_get_cntlr_config(arg);
	} else if (cmd == CC_CSMI_SAS_GET_CNTLR_STATUS) {
		return csmisas_get_cntlr_status(arg);
	} else if (cmd == CC_CSMI_SAS_GET_SCSI_ADDRESS) {
		return csmisas_get_scsi_address(arg);
	} else if (cmd == CC_CSMI_SAS_GET_DEVICE_ADDRESS){
		return csmisas_get_device_address(arg);
	}
#endif // CPQ_CIM

	dctlprintk(("mptctl_ioctl() called with cmd=%x, interrupt required\n", cmd));
	/* All of these commands require an interrupt or
	 * are unknown/illegal.
	 */
	if ((ret = mptctl_syscall_down(iocp, nonblock)) != 0) {
		dctlprintk(("mptctl_ioctl() called with cmd=%x ret=%d, syscall_down failed\n", cmd, ret));
		return ret;
	}

	dctlprintk(("mptctl_ioctl() called with cmd=%x, syscall_down completed\n", cmd));
	if (cmd == MPTFWDOWNLOAD)
		ret = mptctl_fw_download(arg);
	else if (cmd == MPTFWDOWNLOADBOOT)
		ret = mptctl_fw_downloadboot(arg);
	else if (cmd == MPTCOMMAND)
		ret = mptctl_mpt_command(arg);
	else if (cmd == MPTHARDRESET)
		ret = mptctl_do_reset(arg);
	else if ((cmd & ~IOCSIZE_MASK) == (HP_GETHOSTINFO & ~IOCSIZE_MASK))
		ret = mptctl_hp_hostinfo(arg, _IOC_SIZE(cmd));
	else if (cmd == HP_GETTARGETINFO)
		ret = mptctl_hp_targetinfo(arg);
	else if (cmd == MPTDIAGREGISTER)
		ret = mptctl_register_diag_buffer(arg);
	else if (cmd == MPTDIAGRELEASE)
		ret = mptctl_release_diag_buffer(arg);
	else if (cmd == MPTDIAGREADBUFFER)
		ret = mptctl_read_diag_buffer(arg);
#if defined(CPQ_CIM)
	else if (cmd == CC_CSMI_SAS_GET_PHY_INFO)
		ret = csmisas_get_phy_info(arg);
	else if (cmd == CC_CSMI_SAS_GET_SATA_SIGNATURE)
		ret = csmisas_get_sata_signature(arg);
	else if (cmd == CC_CSMI_SAS_GET_LINK_ERRORS)
		ret = csmisas_get_link_errors(arg);
	else if (cmd == CC_CSMI_SAS_SMP_PASSTHRU)
		ret = csmisas_smp_passthru(arg);
	else if (cmd == CC_CSMI_SAS_SSP_PASSTHRU)
		ret = csmisas_ssp_passthru(arg);
	else if (cmd == CC_CSMI_SAS_FIRMWARE_DOWNLOAD)
		ret = csmisas_firmware_download(arg);
	else if (cmd == CC_CSMI_SAS_GET_RAID_INFO)
		ret = csmisas_get_raid_info(arg);
	else if (cmd == CC_CSMI_SAS_GET_RAID_CONFIG)
		ret = csmisas_get_raid_config(arg);
	else if (cmd == CC_CSMI_SAS_GET_RAID_FEATURES)
		ret = csmisas_get_raid_features(arg);
	else if (cmd == CC_CSMI_SAS_SET_RAID_CONTROL)
		ret = csmisas_set_raid_control(arg);
	else if (cmd == CC_CSMI_SAS_GET_RAID_ELEMENT)
		ret = csmisas_get_raid_element(arg);
	else if (cmd == CC_CSMI_SAS_SET_RAID_OPERATION)
		ret = csmisas_set_raid_operation(arg);
	else if (cmd == CC_CSMI_SAS_SET_PHY_INFO)
		ret = csmisas_set_phy_info(arg);
	else if (cmd == CC_CSMI_SAS_STP_PASSTHRU)
		ret = csmisas_stp_passthru(arg);
	else if (cmd == CC_CSMI_SAS_TASK_MANAGEMENT)
		ret = csmisas_task_managment(arg);
	else if (cmd == CC_CSMI_SAS_PHY_CONTROL)
		ret = csmisas_phy_control(arg);
	else if (cmd == CC_CSMI_SAS_GET_CONNECTOR_INFO)
		ret = csmisas_get_connector_info(arg);
	else if (cmd == CC_CSMI_SAS_GET_LOCATION)
		ret = csmisas_get_location(arg);
#endif // CPQ_CIM
	else {
		dctlprintk(("mptctl_ioctl() cmd=%x not found\n", cmd));
		ret = -EINVAL;
	}

	up(&iocp->ioctl->sem_ioc);

	dctlprintk(("mptctl_ioctl() called with cmd=%x ret=%d, up completed\n", cmd, ret));
	return ret;
}

static int mptctl_do_reset(unsigned long arg)
{
	struct mpt_ioctl_diag_reset __user *urinfo = (void __user *) arg;
	struct mpt_ioctl_diag_reset krinfo;
	MPT_ADAPTER		*iocp;

	dctlprintk(("mptctl_do_reset called.\n"));

	if (copy_from_user(&krinfo, urinfo, sizeof(struct mpt_ioctl_diag_reset))) {
		printk(KERN_ERR "%s@%d: mptctl_do_reset - "
				"Unable to copy mpt_ioctl_diag_reset struct @ %p\n",
				__FILE__, __LINE__, urinfo);
		return -EFAULT;
	}

	if (mpt_verify_adapter(krinfo.hdr.iocnum, &iocp) < 0) {
		dctlprintk(("mptctl_do_reset: ioc%d not found!\n",
				krinfo.hdr.iocnum));
		return -ENODEV; /* (-6) No such device or address */
	}

	if (mpt_HardResetHandler(iocp, CAN_SLEEP) != 0) {
		dctlprintk(("mptctl_do_reset: reset failed.\n"));
		return -1;
	}

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 * MPT FW download function.  Cast the arg into the mpt_fw_xfer structure.
 * This structure contains: iocnum, firmware length (bytes),
 *      pointer to user space memory where the fw image is stored.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-ENXIO  if no such device
 *		-EAGAIN if resource problem
 *		-ENOMEM if no memory for SGE
 *		-EMLINK if too many chain buffers required
 *		-EBADRQC if adapter does not support FW download
 *		-EBUSY if adapter is busy
 *		-ENOMSG if FW upload returned bad status
 */
static int
mptctl_fw_download(unsigned long arg)
{
	struct mpt_fw_xfer __user *ufwdl = (void __user *) arg;
	struct mpt_fw_xfer	 kfwdl;

	dctlprintk(("mptctl_fwdl called. mptctl_id = %xh\n", mptctl_id)); //tc
	if (copy_from_user(&kfwdl, ufwdl, sizeof(struct mpt_fw_xfer))) {
		printk(KERN_ERR "%s@%d: _ioctl_fwdl - "
				"Unable to copy mpt_fw_xfer struct @ %p\n",
				__FILE__, __LINE__, ufwdl);
		return -EFAULT;
	}

	return mptctl_do_fw_download(kfwdl.iocnum, kfwdl.bufp, kfwdl.fwlen);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 * FW Download engine.
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-ENXIO  if no such device
 *		-EAGAIN if resource problem
 *		-ENOMEM if no memory for SGE
 *		-EMLINK if too many chain buffers required
 *		-EBADRQC if adapter does not support FW download
 *		-EBUSY if adapter is busy
 *		-ENOMSG if FW upload returned bad status
 */
static int
mptctl_do_fw_download(int ioc, char __user *ufwbuf, size_t fwlen)
{
	FWDownload_t		*dlmsg;
	MPT_FRAME_HDR		*mf;
	MPT_ADAPTER		*iocp;
	FWDownloadTCSGE_t	*ptsge;
	MptSge_t		*sgl, *sgIn;
	char			*sgOut;
	struct buflist		*buflist;
	struct buflist		*bl;
	dma_addr_t		 sgl_dma;
	int			 ret;
	int			 numfrags = 0;
	int			 maxfrags;
	int			 n = 0;
	u32			 sgdir;
	u32			 nib;
	int			 fw_bytes_copied = 0;
	int			 i;
	int			 sge_offset = 0;
	u16			 iocstat;
	pFWDownloadReply_t	 ReplyMsg = NULL;

	dctlprintk(("mptctl_do_fwdl called. mptctl_id = %xh.\n", mptctl_id));

	dctlprintk(("DbG: kfwdl.bufp  = %p\n", ufwbuf));
	dctlprintk(("DbG: kfwdl.fwlen = %d\n", (int)fwlen));
	dctlprintk(("DbG: kfwdl.ioc   = %04xh\n", ioc));

	if (mpt_verify_adapter(ioc, &iocp) < 0) {
		dctlprintk(("ioctl_fwdl - ioc%d not found!\n",
				 ioc));
		return -ENODEV; /* (-6) No such device or address */
	} else {

		/*  Valid device. Get a message frame and construct the FW download message.
	 	*/
		if ((mf = mpt_get_msg_frame(mptctl_id, iocp)) == NULL)
			return -EAGAIN;
	}
	dlmsg = (FWDownload_t*) mf;
	ptsge = (FWDownloadTCSGE_t *) &dlmsg->SGL;
	sgOut = (char *) (ptsge + 1);

	/*
	 * Construct f/w download request
	 */
	dlmsg->ImageType = MPI_FW_DOWNLOAD_ITYPE_FW;
	dlmsg->Reserved = 0;
	dlmsg->ChainOffset = 0;
	dlmsg->Function = MPI_FUNCTION_FW_DOWNLOAD;
	dlmsg->Reserved1[0] = dlmsg->Reserved1[1] = dlmsg->Reserved1[2] = 0;
	if (iocp->facts.MsgVersion >= MPI_VERSION_01_05)
		dlmsg->MsgFlags = MPI_FW_DOWNLOAD_MSGFLGS_LAST_SEGMENT;
	else
		dlmsg->MsgFlags = 0;


	/* Set up the Transaction SGE.
	 */
	ptsge->Reserved = 0;
	ptsge->ContextSize = 0;
	ptsge->DetailsLength = 12;
	ptsge->Flags = MPI_SGE_FLAGS_TRANSACTION_ELEMENT;
	ptsge->Reserved_0100_Checksum = 0;
	ptsge->ImageOffset = 0;
	ptsge->ImageSize = cpu_to_le32(fwlen);

	/* Add the SGL
	 */

	/*
	 * Need to kmalloc area(s) for holding firmware image bytes.
	 * But we need to do it piece meal, using a proper
	 * scatter gather list (with 128kB MAX hunks).
	 *
	 * A practical limit here might be # of sg hunks that fit into
	 * a single IOC request frame; 12 or 8 (see below), so:
	 * For FC9xx: 12 x 128kB == 1.5 mB (max)
	 * For C1030:  8 x 128kB == 1   mB (max)
	 * We could support chaining, but things get ugly(ier:)
	 *
	 * Set the sge_offset to the start of the sgl (bytes).
	 */
	sgdir = 0x04000000;		/* IOC will READ from sys mem */
	sge_offset = sizeof(MPIHeader_t) + sizeof(FWDownloadTCSGE_t);
	if ((sgl = kbuf_alloc_2_sgl(fwlen, sgdir, sge_offset,
				    &numfrags, &buflist, &sgl_dma, iocp)) == NULL)
		return -ENOMEM;

	/*
	 * We should only need SGL with 2 simple_32bit entries (up to 256 kB)
	 * for FC9xx f/w image, but calculate max number of sge hunks
	 * we can fit into a request frame, and limit ourselves to that.
	 * (currently no chain support)
	 * maxfrags = (Request Size - FWdownload Size ) / Size of 32 bit SGE
	 *	Request		maxfrags
	 *	128		12
	 *	96		8
	 *	64		4
	 */
	maxfrags = (iocp->req_sz - sizeof(MPIHeader_t) - sizeof(FWDownloadTCSGE_t))
			/ (sizeof(dma_addr_t) + sizeof(u32));
	if (numfrags > maxfrags) {
		ret = -EMLINK;
		goto fwdl_out;
	}

	dctlprintk(("DbG: sgl buffer  = %p, sgfrags = %d\n", sgl, numfrags));

	/*
	 * Parse SG list, copying sgl itself,
	 * plus f/w image hunks from user space as we go...
	 */
	ret = -EFAULT;
	sgIn = sgl;
	bl = buflist;
	for (i=0; i < numfrags; i++) {

		/* Get the SGE type: 0 - TCSGE, 3 - Chain, 1 - Simple SGE
		 * Skip everything but Simple. If simple, copy from
		 *	user space into kernel space.
		 * Note: we should not have anything but Simple as
		 *	Chain SGE are illegal.
		 */
		nib = (sgIn->FlagsLength & 0x30000000) >> 28;
		if (nib == 0 || nib == 3) {
			;
		} else if (sgIn->Address) {
			iocp->add_sge(sgOut, sgIn->FlagsLength, sgIn->Address);
			n++;
			if (copy_from_user(bl->kptr, ufwbuf+fw_bytes_copied, bl->len)) {
				printk(KERN_ERR "%s@%d: _ioctl_fwdl - "
						"Unable to copy f/w buffer hunk#%d @ %p\n",
						__FILE__, __LINE__, n, ufwbuf);
				goto fwdl_out;
			}
			fw_bytes_copied += bl->len;
		}
		sgIn++;
		bl++;
		sgOut += (sizeof(dma_addr_t) + sizeof(u32));
	}

#ifdef MPT_DEBUG
	{
		u32 *m = (u32 *)mf;
		printk(KERN_INFO MYNAM ": F/W download request:\n" KERN_INFO " ");
		for (i=0; i < 7+numfrags*2; i++)
			printk(" %08x", le32_to_cpu(m[i]));
		printk("\n");
	}
#endif

	/*
	 * Finally, perform firmware download.
	 */
	ReplyMsg = NULL;
	iocp->ioctl->wait_done = 0;
	INITIALIZE_IOCTL_STATUS(iocp->ioctl->status)

	mpt_put_msg_frame(mptctl_id, iocp, mf);

	/* Now wait for the command to complete */
	ret = wait_event_timeout(mptctl_wait,
	     iocp->ioctl->wait_done == 1,
	     HZ*60);

	if(ret <=0 && (iocp->ioctl->wait_done != 1 )) {
	/* Now we need to reset the board */
		mptctl_timeout_expired(iocp, mf);
		ret = -ENODATA;
		goto fwdl_out;
	}

	if (sgl)
		kfree_sgl(sgl, sgl_dma, buflist, iocp);

	ReplyMsg = (pFWDownloadReply_t)iocp->ioctl->reply;
	iocstat = le16_to_cpu(ReplyMsg->IOCStatus) & MPI_IOCSTATUS_MASK;
	if (iocstat == MPI_IOCSTATUS_SUCCESS) {
		printk(KERN_INFO MYNAM ": F/W update successfully sent to %s!\n", iocp->name);
		return 0;
	} else if (iocstat == MPI_IOCSTATUS_INVALID_FUNCTION) {
		printk(KERN_WARNING MYNAM ": ?Hmmm...  %s says it doesn't support F/W download!?!\n",
				iocp->name);
		printk(KERN_WARNING MYNAM ": (time to go bang on somebodies door)\n");
		return -EBADRQC;
	} else if (iocstat == MPI_IOCSTATUS_BUSY) {
		printk(KERN_WARNING MYNAM ": Warning!  %s says: IOC_BUSY!\n", iocp->name);
		printk(KERN_WARNING MYNAM ": (try again later?)\n");
		return -EBUSY;
	} else {
		printk(KERN_WARNING MYNAM ": ioctl_fwdl() ERROR!  %s returned [bad] status = %04xh\n",
				    iocp->name, iocstat);
		printk(KERN_WARNING MYNAM ": (bad VooDoo)\n");
		return -ENOMSG;
	}
	return 0;

fwdl_out:
        kfree_sgl(sgl, sgl_dma, buflist, iocp);
	return ret;
}
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 * MPT FW downloadboot function.  Cast the arg into the mpt_fw_xfer structure.
 * This structure contains: iocnum, firmware length (bytes),
 *      pointer to user space memory where the fw image is stored.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-ENXIO  if no such device
 *		-EAGAIN if resource problem
 *		-ENOMEM if no memory for SGE
 *		-EMLINK if too many chain buffers required
 *		-EBADRQC if adapter does not support FW downloadboot
 *		-EBUSY if adapter is busy
 *		-ENOMSG if FW upload returned bad status
 */
static int
mptctl_fw_downloadboot(unsigned long arg)
{
	struct mpt_fw_xfer __user *ufwdl = (void __user *) arg;
	struct mpt_fw_xfer	 kfwdl;

	dctlprintk(("mptctl_fwdlboot called. mptctl_id = %xh\n", mptctl_id)); //tc
	if (copy_from_user(&kfwdl, ufwdl, sizeof(struct mpt_fw_xfer))) {
		printk(KERN_ERR "%s@%d: _ioctl_fwdl - "
				"Unable to copy mpt_fw_xfer struct @ %p\n",
				__FILE__, __LINE__, ufwdl);
		return -EFAULT;
	}

	dctlprintk(("mptctl_fwdlboot fwlen = 0x%x (%d) bufp=%p\n", kfwdl.fwlen, kfwdl.fwlen, kfwdl.bufp)); //tc
	return mptctl_do_fw_downloadboot(kfwdl.iocnum, kfwdl.bufp, kfwdl.fwlen);
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptctl_downloadboot - DownloadBoot code
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
static int
mptctl_do_fw_downloadboot(int ioc_num, char *ufwbuf, size_t fwlen)
{
	MPT_ADAPTER		*ioc;
	char			*pbuf;
	int			rc;

	if (mpt_verify_adapter(ioc_num, &ioc) < 0) {
		dctlprintk(("ioctl_fwdl - ioc%d not found!\n",
				 ioc_num));
		return -ENODEV; /* (-6) No such device or address */
	}

	pbuf = (char *)__get_free_pages(GFP_KERNEL, get_order(fwlen));
	
	if (pbuf==NULL) {
		printk(KERN_ERR "%s@%d: _ioctl_fwdlboot - "
				"Unable to allocate memory\n",
				__FILE__, __LINE__);
		return -ENOMEM;
	}

	if (copy_from_user(pbuf, ufwbuf, fwlen)) {
		printk(KERN_ERR "%s@%d: _ioctl_fwdlboot - "
				"Unable to copy mpt_fw @ %p\n",
				__FILE__, __LINE__, (void*)ufwbuf);
		free_pages((unsigned long)pbuf, get_order(fwlen));
		return -EFAULT;
	}

	ddlprintk((MYIOC_s_INFO_FMT "mptctl_do_fw_downloadboot fwlen=%d pbuf=%p\n",
				ioc->name, (int)fwlen, pbuf));

	rc = mpt_downloadboot(ioc, (MpiFwHeader_t *)pbuf, CAN_SLEEP);
	ddlprintk((MYIOC_s_INFO_FMT "mptctl_do_fw_downloadboot rc=%x\n",
				ioc->name, rc));
#if 0
	if ( (rc == 0) && (ioc->bus_type == SAS) ) {
/*		if ((rc = mptctl_syscall_down(ioc, nonblock)) != 0)
			return rc; */

		rc = mptctl_do_fw_download(ioc_num, ufwbuf, fwlen);

//		up(&ioc->mptctl_syscall_sem_ioc);

		ddlprintk((MYIOC_s_INFO_FMT "SAS mptctl_do_fw_download rc=%x\n",
				ioc->name, rc));

/*		if ( (rc = mpt_diag_reset(ioc, 1, sleepFlag)) < 0) {
			ddlprintk((MYIOC_s_INFO_FMT "SAS Diagnostic reset after downloadboot failed!\n",
				ioc->name));
		} else {
		ddlprintk((MYIOC_s_INFO_FMT "SAS Diagnostic reset after downloadboot successful!\n",
			ioc->name));
		} */
	}
#endif
	free_pages((unsigned long)pbuf, get_order(fwlen));
	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 * SGE Allocation routine
 *
 * Inputs:	bytes - number of bytes to be transferred
 *		sgdir - data direction
 *		sge_offset - offset (in bytes) from the start of the request
 *			frame to the first SGE
 *		ioc - pointer to the mptadapter
 * Outputs:	frags - number of scatter gather elements
 *		blp - point to the buflist pointer
 *		sglbuf_dma - pointer to the (dma) sgl
 * Returns:	Null if failes
 *		pointer to the (virtual) sgl if successful.
 */
static MptSge_t *
kbuf_alloc_2_sgl(int bytes, u32 sgdir, int sge_offset, int *frags,
		 struct buflist **blp, dma_addr_t *sglbuf_dma, MPT_ADAPTER *ioc)
{
	MptSge_t	*sglbuf = NULL;		/* pointer to array of SGE */
						/* and chain buffers */
	struct buflist	*buflist = NULL;	/* kernel routine */
	MptSge_t	*sgl;
	int		 numfrags = 0;
	int		 fragcnt = 0;
	int		 alloc_sz = min(bytes,MAX_KMALLOC_SZ);	// avoid kernel warning msg!
	int		 bytes_allocd = 0;
	int		 this_alloc;
	dma_addr_t	 pa;					// phys addr
	int		 i, buflist_ent;
	int		 sg_spill = MAX_FRAGS_SPILL1;
	int		 dir;
	/* initialization */
	*frags = 0;
	*blp = NULL;

	/* Allocate and initialize an array of kernel
	 * structures for the SG elements.
	 */
	i = MAX_SGL_BYTES / 8;
	buflist = kmalloc(i, GFP_USER);
	if (buflist == NULL)
		return NULL;
	memset(buflist, 0, i);
	buflist_ent = 0;

	/* Allocate a single block of memory to store the sg elements and
	 * the chain buffers.  The calling routine is responsible for
	 * copying the data in this array into the correct place in the
	 * request and chain buffers.
	 */
	sglbuf = pci_alloc_consistent(ioc->pcidev, MAX_SGL_BYTES, sglbuf_dma);
	if (sglbuf == NULL)
		goto free_and_fail;

	if (sgdir & 0x04000000)
		dir = PCI_DMA_TODEVICE;
	else
		dir = PCI_DMA_FROMDEVICE;

	/* At start:
	 *	sgl = sglbuf = point to beginning of sg buffer
	 *	buflist_ent = 0 = first kernel structure
	 *	sg_spill = number of SGE that can be written before the first
	 *		chain element.
	 *
	 */
	sgl = sglbuf;
	sg_spill = ((ioc->req_sz - sge_offset)/(sizeof(dma_addr_t) + sizeof(u32))) - 1;
	while (bytes_allocd < bytes) {
		this_alloc = min(alloc_sz, bytes-bytes_allocd);
		buflist[buflist_ent].len = this_alloc;
		buflist[buflist_ent].kptr = pci_alloc_consistent(ioc->pcidev,
								 this_alloc,
								 &pa);
		if (buflist[buflist_ent].kptr == NULL) {
			alloc_sz = alloc_sz / 2;
			if (alloc_sz == 0) {
				printk(KERN_WARNING MYNAM ": -SG: No can do - "
						    "not enough memory!   :-(\n");
				printk(KERN_WARNING MYNAM ": -SG: (freeing %d frags)\n",
						    numfrags);
				goto free_and_fail;
			}
			continue;
		} else {
			dma_addr_t dma_addr;

			bytes_allocd += this_alloc;
			sgl->FlagsLength = (0x10000000|MPT_SGE_FLAGS_ADDRESSING|sgdir|this_alloc);
			dma_addr = pci_map_single(ioc->pcidev, buflist[buflist_ent].kptr, this_alloc, dir);
			sgl->Address = dma_addr;

			fragcnt++;
			numfrags++;
			sgl++;
			buflist_ent++;
		}

		if (bytes_allocd >= bytes)
			break;

		/* Need to chain? */
		if (fragcnt == sg_spill) {
			printk(KERN_WARNING MYNAM ": -SG: No can do - " "Chain required!   :-(\n");
			printk(KERN_WARNING MYNAM ": (freeing %d frags)\n", numfrags);
			goto free_and_fail;
		}

		/* overflow check... */
		if (numfrags*8 > MAX_SGL_BYTES){
			/* GRRRRR... */
			printk(KERN_WARNING MYNAM ": -SG: No can do - "
					    "too many SG frags!   :-(\n");
			printk(KERN_WARNING MYNAM ": -SG: (freeing %d frags)\n",
					    numfrags);
			goto free_and_fail;
		}
	}

	/* Last sge fixup: set LE+eol+eob bits */
	sgl[-1].FlagsLength |= 0xC1000000;

	*frags = numfrags;
	*blp = buflist;

	dctlprintk(("-SG: kbuf_alloc_2_sgl() - "
			   "%d SG frags generated!\n",
			   numfrags));

	dctlprintk(("-SG: kbuf_alloc_2_sgl() - "
			   "last (big) alloc_sz=%d\n",
			   alloc_sz));

	return sglbuf;

free_and_fail:
	if (sglbuf != NULL) {
		int i;

		for (i = 0; i < numfrags; i++) {
			dma_addr_t dma_addr;
			u8 *kptr;
			int len;

			if ((sglbuf[i].FlagsLength >> 24) == 0x30)
				continue;

			dma_addr = sglbuf[i].Address;
			kptr = buflist[i].kptr;
			len = buflist[i].len;

			pci_free_consistent(ioc->pcidev, len, kptr, dma_addr);
		}
		pci_free_consistent(ioc->pcidev, MAX_SGL_BYTES, sglbuf, *sglbuf_dma);
	}
	kfree(buflist);
	return NULL;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 * Routine to free the SGL elements.
 */
static void
kfree_sgl(MptSge_t *sgl, dma_addr_t sgl_dma, struct buflist *buflist, MPT_ADAPTER *ioc)
{
	MptSge_t	*sg = sgl;
	struct buflist	*bl = buflist;
	u32		 nib;
	int		 dir;
	int		 n = 0;

	if (sg->FlagsLength & 0x04000000)
		dir = PCI_DMA_TODEVICE;
	else
		dir = PCI_DMA_FROMDEVICE;

	nib = (sg->FlagsLength & 0xF0000000) >> 28;
	while (! (nib & 0x4)) { /* eob */
		/* skip ignore/chain. */
		if (nib == 0 || nib == 3) {
			;
		} else if (sg->Address) {
			dma_addr_t dma_addr;
			void *kptr;
			int len;

			dma_addr = sg->Address;
			kptr = bl->kptr;
			len = bl->len;
			pci_unmap_single(ioc->pcidev, dma_addr, len, dir);
			pci_free_consistent(ioc->pcidev, len, kptr, dma_addr);
			n++;
		}
		sg++;
		bl++;
		nib = (le32_to_cpu(sg->FlagsLength) & 0xF0000000) >> 28;
	}

	/* we're at eob! */
	if (sg->Address) {
		dma_addr_t dma_addr;
		void *kptr;
		int len;

		dma_addr = sg->Address;
		kptr = bl->kptr;
		len = bl->len;
		pci_unmap_single(ioc->pcidev, dma_addr, len, dir);
		pci_free_consistent(ioc->pcidev, len, kptr, dma_addr);
		n++;
	}

	pci_free_consistent(ioc->pcidev, MAX_SGL_BYTES, sgl, sgl_dma);
	kfree(buflist);
	dctlprintk(("-SG: Free'd 1 SGL buf + %d kbufs!\n", n));
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptctl_getiocinfo - Query the host adapter for IOC information.
 *	@arg: User space argument
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-ENODEV  if no such device/adapter
 */
static int
mptctl_getiocinfo (unsigned long arg, unsigned int data_size)
{
	struct mpt_ioctl_iocinfo __user *uarg = (void __user *) arg;
	struct mpt_ioctl_iocinfo *karg;
	MPT_ADAPTER		*ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	struct pci_dev		*pdev;
	int			iocnum;
	int			numDevices = 0;
	int			id, bus;
	unsigned int		port;
	int			cim_rev;
	u8			revision;

	/* Add of PCI INFO results in unaligned access for
	 * IA64 and Sparc. Reset long to int. Return no PCI
	 * data for obsolete format.
	 */
	if (data_size == sizeof(struct mpt_ioctl_iocinfo_rev0))
		cim_rev = 0;
	else if (data_size == sizeof(struct mpt_ioctl_iocinfo_rev1))
		cim_rev = 1;
	else if (data_size == sizeof(struct mpt_ioctl_iocinfo))
		cim_rev = 2;
	else if (data_size == (sizeof(struct mpt_ioctl_iocinfo_rev0)+12))
		cim_rev = 0;	/* obsolete */
	else {
		dctlprintk(("mptctl_getiocinfo called.i Invalid data_size=%d\n", data_size));
		return -EFAULT;
	}

	karg = kmalloc(data_size, GFP_KERNEL);
	if (karg == NULL) {
		printk(KERN_ERR "%s: mpt_ioctl_iocinfo() @%d - no memory available!\n",
				__FILE__, __LINE__);
		return -ENOMEM;
	}

	if (copy_from_user(karg, uarg, data_size)) {
		printk(KERN_ERR "%s@%d: mptctl_getiocinfo - "
			"Unable to read in mpt_ioctl_iocinfo struct @ %p\n",
				__FILE__, __LINE__, (void*)uarg);
		kfree(karg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg->hdr.iocnum, &ioc)) < 0) ||
	    (ioc == NULL)) {
		dctlprintk(("mptctl_getiocinfo(): ioc%d not found!\n",
				iocnum));
		kfree(karg);
		return -ENODEV;
	}
	dctlprintk(("ioc%d: mptctl_getiocinfo called.\n", iocnum));

	/* Verify the data transfer size is correct. */
	if (karg->hdr.maxDataSize != data_size) {
		printk(KERN_ERR "%s@%d: mptctl_getiocinfo - "
			"Structure size mismatch. Command not completed.\n",
				__FILE__, __LINE__);
		kfree(karg);
		return -EFAULT;
	}

	/* Fill in the data and return the structure to the calling
	 * program
	 */
	if (ioc->bus_type == SAS)
		karg->adapterType = MPT_IOCTL_INTERFACE_SAS;
	else if (ioc->bus_type == FC)
		karg->adapterType = MPT_IOCTL_INTERFACE_FC;
	else
		karg->adapterType = MPT_IOCTL_INTERFACE_SCSI;

	if (karg->hdr.port > 1)
		return -EINVAL;
	port = karg->hdr.port;

	karg->port = port;
	pdev = ioc->pcidev;

	karg->pciId = pdev->device;
	pci_read_config_byte(pdev, PCI_CLASS_REVISION, &revision);
	karg->hwRev = revision;
	karg->subSystemDevice = pdev->subsystem_device;
	karg->subSystemVendor = pdev->subsystem_vendor;

	if (cim_rev == 1) {
		/* Get the PCI bus, device, and function numbers for the IOC
		 */
		karg->pciInfo.u.bits.busNumber = pdev->bus->number;
		karg->pciInfo.u.bits.deviceNumber = PCI_SLOT( pdev->devfn );
		karg->pciInfo.u.bits.functionNumber = PCI_FUNC( pdev->devfn );
	} else if (cim_rev == 2) {
		/* Get the PCI bus, device, function and segment ID numbers
		   for the IOC */
		karg->pciInfo.u.bits.busNumber = pdev->bus->number;
		karg->pciInfo.u.bits.deviceNumber = PCI_SLOT( pdev->devfn );
		karg->pciInfo.u.bits.functionNumber = PCI_FUNC( pdev->devfn );
		karg->pciInfo.segmentID = pci_domain_nr(pdev->bus);
	}

	/* Get number of devices
         */
	for (bus = 0; bus < ioc->NumberOfBuses; bus++) {
		if ((pMptTarget = ioc->Target_List[bus])) {
			for (id = 0; id < ioc->DevicesPerBus; id++) {
				pTarget = pMptTarget->Target[id];
				if (pTarget)
					numDevices++;
			}
		}
	}
	karg->numDevices = numDevices;

	/* Set the BIOS and FW Version
	 */
	karg->FWVersion = ioc->facts.FWVersion.Word;
	karg->BIOSVersion = ioc->biosVersion;

	/* Set the Version Strings.
	 */
	strncpy (karg->driverVersion, MPT_LINUX_PACKAGE_NAME, MPT_IOCTL_VERSION_LENGTH);
	karg->driverVersion[MPT_IOCTL_VERSION_LENGTH-1]='\0';

	karg->busChangeEvent = 0;
	karg->hostId = ioc->pfacts[port].PortSCSIID;
	karg->rsvd[0] = karg->rsvd[1] = 0;

	/* Copy the data from kernel memory to user memory
	 */
	if (copy_to_user((char __user *)arg, karg, data_size)) {
		printk(KERN_ERR "%s@%d: mptctl_getiocinfo - "
			"Unable to write out mpt_ioctl_iocinfo struct @ %p\n",
				__FILE__, __LINE__, uarg);
		kfree(karg);
		return -EFAULT;
	}

	kfree(karg);
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptctl_gettargetinfo - Query the host adapter for target information.
 *	@arg: User space argument
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-ENODEV  if no such device/adapter
 */
static int
mptctl_gettargetinfo (unsigned long arg)
{
	struct mpt_ioctl_targetinfo __user *uarg = (void __user *) arg;
	struct mpt_ioctl_targetinfo karg;
	MPT_ADAPTER		*ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	char			*pmem;
	int			*pdata;
	IOCPage2_t		*pIoc2;
	IOCPage3_t		*pIoc3;
	int			iocnum;
	int			numDevices = 0;
	int			id, jj, indexed_lun, lun_index;
	u32			lun;
	int			maxWordsLeft;
	int			numBytes;
	u8			port, devType, bus;

	if (copy_from_user(&karg, uarg, sizeof(struct mpt_ioctl_targetinfo))) {
		printk(KERN_ERR "%s@%d: mptctl_gettargetinfo - "
			"Unable to read in mpt_ioctl_targetinfo struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
	    (ioc == NULL)) {
		dctlprintk(("mptctl_gettargetinfo: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	dctlprintk(("ioc%ds: mptctl_gettargetinfo called.\n", iocnum));
	/* Get the port number and set the maximum number of bytes
	 * in the returned structure.
	 * Ignore the port setting.
	 */
	numBytes = karg.hdr.maxDataSize - sizeof(mpt_ioctl_header);
	maxWordsLeft = numBytes/sizeof(int);
	port = karg.hdr.port;

	if (maxWordsLeft <= 0) {
		printk(KERN_ERR "%s: mptctl_gettargetinfo() @%d - no memory available!\n",
				__FILE__, __LINE__);
		return -ENOMEM;
	}

	/* Fill in the data and return the structure to the calling
	 * program
	 */

	/* struct mpt_ioctl_targetinfo does not contain sufficient space
	 * for the target structures so when the IOCTL is called, there is
	 * not sufficient stack space for the structure. Allocate memory,
	 * populate the memory, copy back to the user, then free memory.
	 * targetInfo format:
	 * bits 31-24: reserved
	 *      23-16: LUN
	 *      15- 8: Bus Number
	 *       7- 0: Target ID
	 */
	pmem = kmalloc(numBytes, GFP_KERNEL);
	if (pmem == NULL) {
		printk(KERN_ERR "%s: mptctl_gettargetinfo() @%d - no memory available!\n",
				__FILE__, __LINE__);
		return -ENOMEM;
	}
	memset(pmem, 0, numBytes);
	pdata =  (int *) pmem;

	/* Get number of devices
         */
	/* Check all of the target structures.
	 * Save the Id and increment the counter,
	 * if ptr non-null.
	 */
	mpt_findImVolumes(ioc);
	pIoc2 = ioc->raid_data.pIocPg2;
	for (bus = 0; bus < ioc->NumberOfBuses; bus++) {
		for ( id = 0; id < ioc->DevicesPerBus; ) {
			if ( pIoc2 && pIoc2->NumActiveVolumes ) {
				if ( id == pIoc2->RaidVolume[0].VolumeID ) {
					if (maxWordsLeft <= 0) {
						printk(KERN_ERR "mptctl_gettargetinfo - "
		"buffer is full but volume is available on ioc %d\n, numDevices=%d", iocnum, numDevices);
						goto data_space_full;
					}
					if ( ( pIoc2->RaidVolume[0].Flags & MPI_IOCPAGE2_FLAG_VOLUME_INACTIVE ) == 0 )
                       				devType = 0x80;
					else
                       				devType = 0xC0;
					if ( bus == pIoc2->RaidVolume[0].VolumeBus) {
            					numDevices++;
						*pdata = ( (devType << 24) | (bus<< 8) | id );
						dctlprintk((KERN_ERR "mptctl_gettargetinfo - "
		"volume ioc=%d target=%x numDevices=%d pdata=%p\n", iocnum, *pdata, numDevices, pdata));
						pdata++;
						--maxWordsLeft;
						goto next_id;
					}
				} else {
					pIoc3 = ioc->raid_data.pIocPg3;
					if (pIoc3)
						for ( jj = 0; jj < pIoc3->NumPhysDisks; jj++ ) {
							if ((pIoc3->PhysDisk[jj].PhysDiskID == id) && (pIoc3->PhysDisk[jj].PhysDiskBus == bus))
								goto next_id;
						}
				}
			}
			if ((pMptTarget = ioc->Target_List[bus])) {
				pTarget = pMptTarget->Target[id];
				if (pTarget) {
					for (jj = 0; jj <= MPT_LAST_LUN; jj++) {
						lun_index = (jj >> 5);
						indexed_lun = (jj % 32);
						lun = (1 << indexed_lun);
						if (pTarget->luns[lun_index] & lun) {
							if (maxWordsLeft <= 0) {
								printk(KERN_ERR "mptctl_gettargetinfo - "
				"buffer is full but more targets are available on ioc %d numDevices=%d\n", iocnum, numDevices);
								goto data_space_full;
							}
							bus = pTarget->bus;
							numDevices++;
							*pdata = ( (jj << 16) | (bus << 8) | id );
							dctlprintk((KERN_ERR "mptctl_gettargetinfo - "
			"target ioc=%d target=%x numDevices=%d pdata=%p\n", iocnum, *pdata, numDevices, pdata));
							pdata++;
							--maxWordsLeft;
						}
					}
				}
			}
next_id:
			id++;
		}
	}
data_space_full:
	karg.numDevices = numDevices;

	/* Copy part of the data from kernel memory to user memory
	 */
	if (copy_to_user((char __user *)arg, &karg,
				sizeof(struct mpt_ioctl_targetinfo))) {
		printk(KERN_ERR "%s@%d: mptctl_gettargetinfo - "
			"Unable to write out mpt_ioctl_targetinfo struct @ %p\n",
				__FILE__, __LINE__, uarg);
		kfree(pmem);
		return -EFAULT;
	}

	/* Copy the remaining data from kernel memory to user memory
	 */
	if (copy_to_user(uarg->targetInfo, pmem, numBytes)) {
		printk(KERN_ERR "%s@%d: mptctl_gettargetinfo - "
			"Unable to write out mpt_ioctl_targetinfo struct @ %p\n",
				__FILE__, __LINE__, pdata);
		kfree(pmem);
		return -EFAULT;
	}

	kfree(pmem);

	return 0;
}
#ifdef MPT_SUPPORT_FWDLB_IOCTL
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptctl_hba_pciinfo - Obtain all mpt HBAs pci (Config Space) information.
 *	@arg: User space argument
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 */
static int
mptctl_hba_pciinfo (unsigned long arg)
{
	struct mpt_ioctl_hbapciinfo *uarg = (struct mpt_ioctl_hbapciinfo *) arg;
	struct mpt_ioctl_hbapciinfo karg;

	MPT_ADAPTER	*ioc;
	int		ioc_num=0, data_size;
	u8			revision;

	data_size = sizeof(mpt_ioctl_header)+4;
	/* Clear the struct before filling in data. */
	memset( &karg, 0, (uarg->hdr.maxDataSize + data_size) );

	dctlprintk((KERN_INFO MYNAM ": Checking for MPT adapters...maxDataSize=%d data_size=%d\n", uarg->hdr.maxDataSize, data_size));

	list_for_each_entry(ioc,&ioc_list,list) {
		data_size += sizeof (struct mpt_ioctl_mptpciinfo);
		if ( data_size >= uarg->hdr.maxDataSize ) {
			dctlprintk((KERN_INFO MYNAM ": data_size=%d >= maxDataSize=%d\n", data_size, uarg->hdr.maxDataSize));
			break;
		}
		karg.hbapciinfo[ioc_num].iocNumber = ioc_num;
		karg.hbapciinfo[ioc_num].deviceID = ioc->deviceID;
		karg.hbapciinfo[ioc_num].vendorID = ioc->vendorID;
		
		pci_read_config_byte(ioc->pcidev, PCI_CLASS_REVISION, &revision);

		karg.hbapciinfo[ioc_num].subSystemVendorID = ioc->pcidev->subsystem_vendor;
		karg.hbapciinfo[ioc_num].subSystemID = ioc->pcidev->subsystem_device;

		karg.hbapciinfo[ioc_num].revisionID = revision;
		mpt_GetIocState(ioc, 1);
		karg.hbapciinfo[ioc_num++].iocState = (ioc->last_state >> MPI_IOC_STATE_SHIFT);
	}

	karg.totalIOC = ioc_num;

	dctlprintk((KERN_INFO MYNAM ": %d MPT adapters found, arg=%p karg=%p size=%d\n",
		 karg.totalIOC, (char *)arg, &karg, (int)sizeof(struct mpt_ioctl_hbapciinfo)));

	/* Copy the data from kernel memory to user memory
	 */
	if (copy_to_user((char *)arg, &karg, sizeof(struct mpt_ioctl_hbapciinfo))) {
		printk(KERN_ERR "%s@%d::mptctl_eventquery - "
			"Unable to write out mpt_ioctl_eventquery struct @ %p\n",
				__FILE__, __LINE__, (void*)uarg);
		return -EFAULT;
	}
	return 0;
}
#endif

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* MPT IOCTL Test function.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-ENODEV  if no such device/adapter
 */
static int
mptctl_readtest (unsigned long arg)
{
	struct mpt_ioctl_test __user *uarg = (void __user *) arg;
	struct mpt_ioctl_test	 karg;
	MPT_ADAPTER *ioc;
	int iocnum;

	dctlprintk(("mptctl_readtest called.\n"));
	if (copy_from_user(&karg, uarg, sizeof(struct mpt_ioctl_test))) {
		printk(KERN_ERR "%s@%d: mptctl_readtest - "
			"Unable to read in mpt_ioctl_test struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
	    (ioc == NULL)) {
		dctlprintk(("mptctl_readtest: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	/* Fill in the data and return the structure to the calling
	 * program
	 */

#ifdef MFCNT
	karg.chip_type = ioc->mfcnt;
#else
	karg.chip_type = ioc->deviceID;
#endif
	strncpy (karg.name, ioc->name, MPT_MAX_NAME);
	karg.name[MPT_MAX_NAME-1]='\0';
	strncpy (karg.product, ioc->prod_name, MPT_PRODUCT_LENGTH);
	karg.product[MPT_PRODUCT_LENGTH-1]='\0';

	/* Copy the data from kernel memory to user memory
	 */
	if (copy_to_user((char __user *)arg, &karg, sizeof(struct mpt_ioctl_test))) {
		printk(KERN_ERR "%s@%d: mptctl_readtest - "
			"Unable to write out mpt_ioctl_test struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptctl_eventquery - Query the host adapter for the event types
 *	that are being logged.
 *	@arg: User space argument
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-ENODEV  if no such device/adapter
 */
static int
mptctl_eventquery (unsigned long arg)
{
	struct mpt_ioctl_eventquery __user *uarg = (void __user *) arg;
	struct mpt_ioctl_eventquery	 karg;
	MPT_ADAPTER *ioc;
	int iocnum;

	dctlprintk(("mptctl_eventquery called.\n"));
	if (copy_from_user(&karg, uarg, sizeof(struct mpt_ioctl_eventquery))) {
		printk(KERN_ERR "%s@%d: mptctl_eventquery - "
			"Unable to read in mpt_ioctl_eventquery struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
	    (ioc == NULL)) {
		dctlprintk(("mptctl_eventquery: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	karg.eventEntries = MPTCTL_EVENT_LOG_SIZE;
	karg.eventTypes = ioc->eventTypes;

	/* Copy the data from kernel memory to user memory
	 */
	if (copy_to_user((char __user *)arg, &karg, sizeof(struct mpt_ioctl_eventquery))) {
		printk(KERN_ERR "%s@%d: mptctl_eventquery - "
			"Unable to write out mpt_ioctl_eventquery struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int
mptctl_eventenable (unsigned long arg)
{
	struct mpt_ioctl_eventenable __user *uarg = (void __user *) arg;
	struct mpt_ioctl_eventenable	 karg;
	MPT_ADAPTER *ioc;
	int iocnum;

	dctlprintk(("mptctl_eventenable called.\n"));
	if (copy_from_user(&karg, uarg, sizeof(struct mpt_ioctl_eventenable))) {
		printk(KERN_ERR "%s@%d: mptctl_eventenable - "
			"Unable to read in mpt_ioctl_eventenable struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
	    (ioc == NULL)) {
		dctlprintk(("mptctl_eventenable: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	if (ioc->events == NULL) {
		/* Have not yet allocated memory - do so now.
		 */
		int sz = MPTCTL_EVENT_LOG_SIZE * sizeof(MPT_IOCTL_EVENTS);
		ioc->events = kmalloc(sz, GFP_KERNEL);
		if (ioc->events == NULL) {
			printk(KERN_ERR MYNAM ": ERROR - Insufficient memory to add adapter!\n");
			return -ENOMEM;
		}
		memset(ioc->events, 0, sz);
		ioc->alloc_total += sz;

		ioc->eventContext = 0;
        }

	/* Update the IOC event logging flag.
	 */
	ioc->eventTypes = karg.eventTypes;

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int
mptctl_eventreport (unsigned long arg)
{
	struct mpt_ioctl_eventreport __user *uarg = (void __user *) arg;
	struct mpt_ioctl_eventreport	 karg;
	MPT_ADAPTER		 *ioc;
	int			 iocnum;
	int			 numBytes, maxEvents, max;

	dctlprintk(("mptctl_eventreport called.\n"));
	if (copy_from_user(&karg, uarg, sizeof(struct mpt_ioctl_eventreport))) {
		printk(KERN_ERR "%s@%d: mptctl_eventreport - "
			"Unable to read in mpt_ioctl_eventreport struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
	    (ioc == NULL)) {
		dctlprintk(("mptctl_eventreport: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	numBytes = karg.hdr.maxDataSize - sizeof(mpt_ioctl_header);
	maxEvents = numBytes/sizeof(MPT_IOCTL_EVENTS);


	max = MPTCTL_EVENT_LOG_SIZE < maxEvents ? MPTCTL_EVENT_LOG_SIZE : maxEvents;

	/* If fewer than 1 event is requested, there must have
	 * been some type of error.
	 */
	if ((max < 1) || !ioc->events)
		return -ENODATA;

	/* reset this flag so SIGIO can restart */
	ioc->aen_event_read_flag=0;

	/* Copy the data from kernel memory to user memory
	 */
	numBytes = max * sizeof(MPT_IOCTL_EVENTS);
	if (copy_to_user(uarg->eventData, ioc->events, numBytes)) {
		printk(KERN_ERR "%s@%d: mptctl_eventreport - "
			"Unable to write out mpt_ioctl_eventreport struct @ %p\n",
				__FILE__, __LINE__, ioc->events);
		return -EFAULT;
	}

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int
mptctl_replace_fw (unsigned long arg)
{
	struct mpt_ioctl_replace_fw __user *uarg = (void __user *) arg;
	struct mpt_ioctl_replace_fw	 karg;
	MPT_ADAPTER		 *ioc;
	int			 iocnum;
	int			 newFwSize;

	dctlprintk(("mptctl_replace_fw called.\n"));
	if (copy_from_user(&karg, uarg, sizeof(struct mpt_ioctl_replace_fw))) {
		printk(KERN_ERR "%s@%d: mptctl_replace_fw - "
			"Unable to read in mpt_ioctl_replace_fw struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
	    (ioc == NULL)) {
		dctlprintk(("mptctl_replace_fw: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	/* If caching FW, Free the old FW image
	 */
	if (ioc->cached_fw == NULL)
		return 0;

	mpt_free_fw_memory(ioc);

	/* Allocate memory for the new FW image
	 */
	newFwSize = karg.newImageSize;

	if (newFwSize & 0x01)
		newFwSize += 1;
	if (newFwSize & 0x02)
		newFwSize += 2;

	mpt_alloc_fw_memory(ioc, newFwSize);
	if (ioc->cached_fw == NULL)
		return -ENOMEM;

	/* Copy the data from user memory to kernel space
	 */
	if (copy_from_user(ioc->cached_fw, uarg->newImage, newFwSize)) {
		printk(KERN_ERR "%s@%d: mptctl_replace_fw - "
			"Unable to read in mpt_ioctl_replace_fw image @ %p\n",
			__FILE__, __LINE__, uarg);
		mpt_free_fw_memory(ioc);
		return -EFAULT;
	}

	/* Update IOCFactsReply
	 */
	ioc->facts.FWImageSize = newFwSize;
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* MPT IOCTL MPTCOMMAND function.
 * Cast the arg into the mpt_ioctl_mpt_command structure.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EBUSY  if previous command timout and IOC reset is not complete.
 *		-EFAULT if data unavailable
 *		-ENODEV if no such device/adapter
 *		-ETIME	if timer expires
 *		-ENOMEM if memory allocation error
 */
static int
mptctl_mpt_command (unsigned long arg)
{
	struct mpt_ioctl_command __user *uarg = (void __user *) arg;
	struct mpt_ioctl_command  karg;
	MPT_ADAPTER	*ioc;
	int		iocnum;
	int		rc;

	dctlprintk(("mptctl_command called.\n"));

	if (copy_from_user(&karg, uarg, sizeof(struct mpt_ioctl_command))) {
		printk(KERN_ERR "%s@%d: mptctl_mpt_command - "
			"Unable to read in mpt_ioctl_command struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
	    (ioc == NULL)) {
		dctlprintk(("mptctl_mpt_command: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	rc = mptctl_do_mpt_command (karg, &uarg->MF);

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* Worker routine for the IOCTL MPTCOMMAND and MPTCOMMAND32 (sparc) commands.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EBUSY  if previous command timout and IOC reset is not complete.
 *		-EFAULT if data unavailable
 *		-ENODEV if no such device/adapter
 *		-ETIME	if timer expires
 *		-ENOMEM if memory allocation error
 *		-EPERM if SCSI I/O and target is untagged
 */
static int
mptctl_do_mpt_command (struct mpt_ioctl_command karg, void __user *mfPtr)
{
	MPT_ADAPTER	*ioc;
	MPT_FRAME_HDR	*mf = NULL;
	MPIHeader_t	*hdr;
	char		*psge;
	struct buflist	bufIn;	/* data In buffer */
	struct buflist	bufOut; /* data Out buffer */
	dma_addr_t	dma_addr_in;
	dma_addr_t	dma_addr_out;
	int		sgSize = 0;	/* Num SG elements */
	int		iocnum, flagsLength;
	int		sz, rc = 0;
	int		msgContext;
	u16		req_idx=0;
	ulong 		timeout;
	MPT_FRAME_HDR	*SAS_handshake_mf=NULL;
	char		*SAS_handshake_reply=NULL;
	u16		msgSize=0;

	bufIn.kptr = bufOut.kptr = NULL;

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
	    (ioc == NULL)) {
		dctlprintk(("mptctl_do_mpt_command: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}
	dctlprintk(("ioc%d: mptctl_do_mpt_command called.\n", iocnum));
	if (!ioc->ioctl) {
		printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
			"No memory available during driver init.\n",
				__FILE__, __LINE__);
		return -ENOMEM;
	} else if (ioc->ioctl->status & MPT_IOCTL_STATUS_DID_IOCRESET) {
		printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
			"Busy with IOC Reset \n", __FILE__, __LINE__);
		return -EBUSY;
	}

	/* Verify that the final request frame will not be too large.
	 */
	sz = karg.dataSgeOffset * 4;
	if (karg.dataInSize > 0)
		sz += sizeof(dma_addr_t) + sizeof(u32);
	if (karg.dataOutSize > 0)
		sz += sizeof(dma_addr_t) + sizeof(u32);

	if (sz > ioc->req_sz) {
		printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
			"Request frame too large (%d) maximum (%d)\n",
				__FILE__, __LINE__, sz, ioc->req_sz);
		return -EFAULT;
	}

	/* Get a free request frame and save the message context.
	 */
	if (((MPIHeader_t *)(mfPtr))->MsgContext == 0x02012020) {
		msgSize = karg.hdr.port >> 16;
		if ( (mf = (MPT_FRAME_HDR *)kmalloc(msgSize, GFP_KERNEL)) == NULL) {
			dfailprintk(("%s: mptctl_do_mpt_command, Unable to kmalloc msgSize=%d for SAS_handshake!!\n",
			ioc->name, msgSize));
               		return -ENOMEM;
		}
		SAS_handshake_mf = mf; 
		if (karg.maxReplyBytes) {
			if ( (SAS_handshake_reply = (char *)kmalloc(karg.maxReplyBytes, GFP_KERNEL)) == NULL) {
				kfree(SAS_handshake_mf);
				dfailprintk(("%s: mptctl_do_mpt_command, Unable to kmalloc maxReplyBytes=%d for SAS_handshake!!\n",
					ioc->name, karg.maxReplyBytes));
               			return -ENOMEM;
			}
		}
		hdr = (MPIHeader_t *) mf;
		msgContext = le32_to_cpu(0x02012020);
		karg.hdr.port &= 0x0000ffff;
	} else {
        	if ((mf = mpt_get_msg_frame(mptctl_id, ioc)) == NULL) {
			dfailprintk((MYIOC_s_WARN_FMT "%s: no msg frames!!\n",
			    ioc->name,__FUNCTION__));
               		return -EAGAIN;
		} else {
			hdr = (MPIHeader_t *) mf;
			msgContext = le32_to_cpu(hdr->MsgContext);
			req_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
		}
	}

	/* Copy the request frame
	 * Reset the saved message context.
	 */
	if (copy_from_user(mf, mfPtr, karg.dataSgeOffset * 4)) {
		printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
			"Unable to read MF from mpt_ioctl_command struct @ %p\n",
			__FILE__, __LINE__, mfPtr);
		rc = -EFAULT;
		goto done_free_mem;
	}
	hdr->MsgContext = cpu_to_le32(msgContext);


	/* Verify that this request is allowed.
	 */
	switch (hdr->Function) {
	case MPI_FUNCTION_IOC_FACTS:
	case MPI_FUNCTION_PORT_FACTS:
		karg.dataOutSize  = karg.dataInSize = 0;
		break;

	case MPI_FUNCTION_CONFIG:
	case MPI_FUNCTION_FC_COMMON_TRANSPORT_SEND:
	case MPI_FUNCTION_FC_EX_LINK_SRVC_SEND:
	case MPI_FUNCTION_FW_UPLOAD:
	case MPI_FUNCTION_SCSI_ENCLOSURE_PROCESSOR:
	case MPI_FUNCTION_FW_DOWNLOAD:
	case MPI_FUNCTION_FC_PRIMITIVE_SEND:
	case MPI_FUNCTION_TOOLBOX:
	case MPI_FUNCTION_SAS_IO_UNIT_CONTROL:
		break;

	case MPI_FUNCTION_SCSI_IO_REQUEST:
		if (ioc->sh) {
			SCSIIORequest_t *pScsiReq = (SCSIIORequest_t *) mf;
			struct _MPT_DEVICE	*pMptTarget;
			VirtDevice	*pTarget = NULL;
			MPT_SCSI_HOST	*hd = NULL;
			int qtag = MPI_SCSIIO_CONTROL_UNTAGGED;
			int scsidir = 0;
			int id = (int) pScsiReq->TargetID;
			int bus = (int) pScsiReq->Bus;
			int dataSize;

			if ((id < 0) || (id > ioc->DevicesPerBus)) {
				printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
					"Target ID=%d out of bounds.  DevicesPerBus=%d\n",
					__FILE__, __LINE__, id, ioc->DevicesPerBus);
				rc = -ENODEV;
				goto done_free_mem;
			}

			if ((bus < 0) || (bus >= ioc->NumberOfBuses)) {
				printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
					"Target Bus=%d out of bounds.  NumberOfBuses=%d\n",
					__FILE__, __LINE__, bus, ioc->NumberOfBuses);
				rc = -ENODEV;
				goto done_free_mem;
			}
			if ((pMptTarget = ioc->Target_List[bus]) == NULL) {
				printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
					"Target_List=NULL for %s bus=%d\n",
					__FILE__, __LINE__, ioc->name, bus);
				rc = -ENODEV;
				goto done_free_mem;
			}

			pScsiReq->MsgFlags &= ~MPI_SCSIIO_MSGFLGS_SENSE_WIDTH;
			pScsiReq->MsgFlags |= mpt_msg_flags();

			/* verify that app has not requested
			 * more sense data than driver
			 * can provide, if so, reset this parameter
			 * set the sense buffer pointer low address
			 * update the control field to specify Q type
			 */
			if (karg.maxSenseBytes > MPT_SENSE_BUFFER_SIZE)
				pScsiReq->SenseBufferLength = MPT_SENSE_BUFFER_SIZE;
			else
				pScsiReq->SenseBufferLength = karg.maxSenseBytes;

			pScsiReq->SenseBufferLowAddr =
				cpu_to_le32(ioc->sense_buf_low_dma
				   + (req_idx * MPT_SENSE_BUFFER_ALLOC));

			if ((hd = (MPT_SCSI_HOST *) ioc->sh->hostdata)) {
				pTarget = pMptTarget->Target[id];
			}

			if (pTarget &&(pTarget->tflags & MPT_TARGET_FLAGS_Q_YES))
				qtag = MPI_SCSIIO_CONTROL_SIMPLEQ;

			/* Have the IOCTL driver set the direction based
			 * on the dataOutSize (ordering issue with Sparc).
			 */
			if (karg.dataOutSize > 0) {
				scsidir = MPI_SCSIIO_CONTROL_WRITE;
				dataSize = karg.dataOutSize;
			} else {
				scsidir = MPI_SCSIIO_CONTROL_READ;
				dataSize = karg.dataInSize;
			}

			pScsiReq->Control = cpu_to_le32(scsidir | qtag);
			pScsiReq->DataLength = cpu_to_le32(dataSize);

			ioc->ioctl->reset = MPTCTL_RESET_OK;
			ioc->ioctl->id = id;

		} else {
			printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
				"SCSI driver is not loaded. \n",
					__FILE__, __LINE__);
			rc = -EFAULT;
			goto done_free_mem;
		}
		break;

	case MPI_FUNCTION_SMP_PASSTHROUGH:
		/* Check mf->PassthruFlags to determine if
		 * transfer is ImmediateMode or not.
		 * Immediate mode returns data in the ReplyFrame.
		 * Else, we are sending request and response data
		 * in two SGLs at the end of the mf.
		 */
		break;

	case MPI_FUNCTION_SATA_PASSTHROUGH:
		if (!ioc->sh) {
			printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
				"SCSI driver is not loaded. \n",
					__FILE__, __LINE__);
			rc = -EFAULT;
			goto done_free_mem;
		}
		break;

	case MPI_FUNCTION_RAID_ACTION:
		/* Just add a SGE
		 */
		break;

	case MPI_FUNCTION_RAID_SCSI_IO_PASSTHROUGH:
		if (ioc->sh) {
			SCSIIORequest_t *pScsiReq = (SCSIIORequest_t *) mf;
			int qtag = MPI_SCSIIO_CONTROL_SIMPLEQ;
			int scsidir = MPI_SCSIIO_CONTROL_READ;
			int dataSize;

			pScsiReq->MsgFlags &= ~MPI_SCSIIO_MSGFLGS_SENSE_WIDTH;
			pScsiReq->MsgFlags |= mpt_msg_flags();

			/* verify that app has not requested
			 *	more sense data than driver
			 *	can provide, if so, reset this parameter
			 * set the sense buffer pointer low address
			 * update the control field to specify Q type
			 */
			if (karg.maxSenseBytes > MPT_SENSE_BUFFER_SIZE)
				pScsiReq->SenseBufferLength = MPT_SENSE_BUFFER_SIZE;
			else
				pScsiReq->SenseBufferLength = karg.maxSenseBytes;

			pScsiReq->SenseBufferLowAddr =
				cpu_to_le32(ioc->sense_buf_low_dma
				   + (req_idx * MPT_SENSE_BUFFER_ALLOC));

			/* All commands to physical devices are tagged
			 */

			/* Have the IOCTL driver set the direction based
			 * on the dataOutSize (ordering issue with Sparc).
			 */
			if (karg.dataOutSize > 0) {
				scsidir = MPI_SCSIIO_CONTROL_WRITE;
				dataSize = karg.dataOutSize;
			} else {
				scsidir = MPI_SCSIIO_CONTROL_READ;
				dataSize = karg.dataInSize;
			}

			pScsiReq->Control = cpu_to_le32(scsidir | qtag);
			pScsiReq->DataLength = cpu_to_le32(dataSize);

			ioc->ioctl->reset = MPTCTL_RESET_OK;
			ioc->ioctl->id = pScsiReq->TargetID;
			ioc->ioctl->bus = pScsiReq->Bus;
		} else {
			printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
				"SCSI driver is not loaded. \n",
					__FILE__, __LINE__);
			rc = -EFAULT;
			goto done_free_mem;
		}
		break;

	case MPI_FUNCTION_SCSI_TASK_MGMT:
		{
			MPT_SCSI_HOST *hd = NULL;
			if ((ioc->sh == NULL) || ((hd = (MPT_SCSI_HOST *)ioc->sh->hostdata) == NULL)) {
				printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
					"SCSI driver not loaded or SCSI host not found. \n",
					__FILE__, __LINE__);
				rc = -EFAULT;
				goto done_free_mem;
			} else if (mptctl_set_tm_flags(hd) != 0) {
				rc = -EPERM;
				goto done_free_mem;
			}
		}
		break;

	case MPI_FUNCTION_IOC_INIT:
		{
			IOCInit_t	*pInit = (IOCInit_t *) mf;
			u32		high_addr, sense_high;

			/* Verify that all entries in the IOC INIT match
			 * existing setup (and in LE format).
			 */
			if (sizeof(dma_addr_t) == sizeof(u64)) {
				high_addr = cpu_to_le32((u32)((u64)ioc->req_frames_dma >> 32));
				sense_high= cpu_to_le32((u32)((u64)ioc->sense_buf_pool_dma >> 32));
			} else {
				high_addr = 0;
				sense_high= 0;
			}

			if ((pInit->MaxDevices == 0) && (pInit->MaxBuses == 0)) {
				/* Fix for SR 2-188096080:
				 * lsiutil fails to program SAS WWN */
				pInit->MaxDevices = ioc->facts.MaxDevices;
				pInit->MaxBuses = ioc->facts.MaxBuses;
			}

			if ((pInit->Flags != 0) || (pInit->MaxDevices != ioc->facts.MaxDevices) ||
				(pInit->MaxBuses != ioc->facts.MaxBuses) ||
				(pInit->ReplyFrameSize != cpu_to_le16(ioc->reply_sz)) ||
				(pInit->HostMfaHighAddr != high_addr) ||
				(pInit->SenseBufferHighAddr != sense_high)) {
				printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
					"IOC_INIT issued with 1 or more incorrect parameters. Rejected.\n",
					__FILE__, __LINE__);
				rc = -EFAULT;
				goto done_free_mem;
			}
		}
		break;
	default:
		/*
		 * MPI_FUNCTION_PORT_ENABLE
		 * MPI_FUNCTION_TARGET_CMD_BUFFER_POST
		 * MPI_FUNCTION_TARGET_ASSIST
		 * MPI_FUNCTION_TARGET_STATUS_SEND
		 * MPI_FUNCTION_TARGET_MODE_ABORT
		 * MPI_FUNCTION_IOC_MESSAGE_UNIT_RESET
		 * MPI_FUNCTION_IO_UNIT_RESET
		 * MPI_FUNCTION_HANDSHAKE
		 * MPI_FUNCTION_REPLY_FRAME_REMOVAL
		 * MPI_FUNCTION_EVENT_NOTIFICATION
		 *  (driver handles event notification)
		 * MPI_FUNCTION_EVENT_ACK
		 */

		/*  What to do with these???  CHECK ME!!!
			MPI_FUNCTION_FC_LINK_SRVC_BUF_POST
			MPI_FUNCTION_FC_LINK_SRVC_RSP
			MPI_FUNCTION_FC_ABORT
			MPI_FUNCTION_LAN_SEND
			MPI_FUNCTION_LAN_RECEIVE
		 	MPI_FUNCTION_LAN_RESET
		*/

		printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
			"Illegal request (function 0x%x) \n",
			__FILE__, __LINE__, hdr->Function);
		rc = -EFAULT;
		goto done_free_mem;
	}

	/* Add the SGL ( at most one data in SGE and one data out SGE )
	 * In the case of two SGE's - the data out (write) will always
	 * preceede the data in (read) SGE. psgList is used to free the
	 * allocated memory.
	 */
	psge = (char *) (((int *) mf) + karg.dataSgeOffset);
	flagsLength = 0;

	/* bufIn and bufOut are used for user to kernel space transfers
	 */
	bufIn.kptr = bufOut.kptr = NULL;
	bufIn.len = bufOut.len = 0;

	if (karg.dataOutSize > 0)
		sgSize ++;

	if (karg.dataInSize > 0)
		sgSize ++;

	if (sgSize > 0) {

		/* Set up the dataOut memory allocation */
		if (karg.dataOutSize > 0) {
			if (karg.dataInSize > 0) {
				flagsLength = ( MPI_SGE_FLAGS_SIMPLE_ELEMENT |
						MPI_SGE_FLAGS_END_OF_BUFFER |
						MPI_SGE_FLAGS_DIRECTION |
						mpt_addr_size() )
						<< MPI_SGE_FLAGS_SHIFT;
			} else {
				flagsLength = MPT_SGE_FLAGS_SSIMPLE_WRITE;
			}
			flagsLength |= karg.dataOutSize;
			bufOut.len = karg.dataOutSize;
			bufOut.kptr = pci_alloc_consistent(
					ioc->pcidev, bufOut.len, &dma_addr_out);

			if (bufOut.kptr == NULL) {
				rc = -ENOMEM;
				goto done_free_mem;
			} else {
				/* Set up this SGE.
				 * Copy to MF and to sglbuf
				 */
				ioc->add_sge(psge, flagsLength, dma_addr_out);
				psge += (sizeof(u32) + sizeof(dma_addr_t));

				/* Copy user data to kernel space.
				 */
				if (copy_from_user(bufOut.kptr,
						karg.dataOutBufPtr,
						bufOut.len)) {
					printk(KERN_ERR
						"%s@%d: mptctl_do_mpt_command - Unable "
						"to read user data "
						"struct @ %p\n",
						__FILE__, __LINE__,karg.dataOutBufPtr);
					rc =  -EFAULT;
					goto done_free_mem;
				}
			}
		}

		if (karg.dataInSize > 0) {
			flagsLength = MPT_SGE_FLAGS_SSIMPLE_READ;
			flagsLength |= karg.dataInSize;

			bufIn.len = karg.dataInSize;
			bufIn.kptr = pci_alloc_consistent(ioc->pcidev,
					bufIn.len, &dma_addr_in);

			if (bufIn.kptr == NULL) {
				rc = -ENOMEM;
				goto done_free_mem;
			} else {
				/* Set up this SGE
				 * Copy to MF and to sglbuf
				 */
				ioc->add_sge(psge, flagsLength, dma_addr_in);
			}
		}
	} else  {
		/* Add a NULL SGE
		 */
		ioc->add_sge(psge, flagsLength, (dma_addr_t) -1);
	}

	ioc->ioctl->wait_done = 0;
	INITIALIZE_IOCTL_STATUS(ioc->ioctl->status)

	if (hdr->Function == MPI_FUNCTION_SCSI_TASK_MGMT) {

		DBG_DUMP_TM_REQUEST_FRAME((u32 *)mf);

		if (mpt_send_handshake_request(mptctl_id, ioc,
		    sizeof(SCSITaskMgmt_t), (u32*)mf, 10, CAN_SLEEP) != 0) {
			dfailprintk((MYIOC_s_ERR_FMT "_send_handshake FAILED!"
				" (ioc %p, mf %p) \n", ioc->name,
				ioc, mf));
			mptctl_free_tm_flags(ioc);
			rc = -ENODATA;
			goto done_free_mem;
		}
		timeout = (karg.timeout > 0) ? karg.timeout : MPT_IOCTL_DEFAULT_TIMEOUT;
		timeout = wait_event_timeout(mptctl_wait,
	     		ioc->ioctl->wait_done == 1,
	     		HZ*timeout);

		if(timeout <=0 && (ioc->ioctl->wait_done != 1 )) {
		/* Now we need to reset the board */
			mptctl_free_tm_flags(ioc);
			mptctl_timeout_expired(ioc, mf);
			rc = -ENODATA;
			goto done_free_mem;
		}
	} else {
		if ( SAS_handshake_mf ) {
			dctlprintk(("SAS_handshake_message Function=%x\n",
				hdr->Function));

			timeout = (karg.timeout > 0) ? karg.timeout : MPT_IOCTL_DEFAULT_TIMEOUT;
			rc = mpt_handshake_req_reply_wait(ioc,
				msgSize, 
				(u32*)SAS_handshake_mf,
				karg.maxReplyBytes, 
				(u16*)SAS_handshake_reply, timeout /*seconds*/, 
				CAN_SLEEP);
			kfree(SAS_handshake_mf);
			SAS_handshake_mf = NULL;
			if (rc == 0) {
				dctlprintk(("SAS_handshake_message Function=%x completed successfully\n",
				hdr->Function));
				sz = karg.maxReplyBytes;

				if (sz > 0) {
					if (copy_to_user((char *)karg.replyFrameBufPtr,
						 SAS_handshake_reply, sz)){

					 	printk(KERN_ERR "%s@%d::mptctl_do_mpt_command - "
					 	"Unable to write out reply frame %p\n",
					 	__FILE__, __LINE__, (void*)karg.replyFrameBufPtr);
						rc =  -ENODATA;
					}
				} else {
					rc =  -ENODATA;
					dctlprintk(("SAS_handshake_message failed sz=%d\n", sz));
				}
				
				kfree(SAS_handshake_reply);
				SAS_handshake_reply = NULL;
				goto done_free_mem;
			}
			else
			{
				rc = -ENODATA;
				kfree(SAS_handshake_reply);
				SAS_handshake_reply = NULL;
				goto done_free_mem;
			}
		} else {
			mpt_put_msg_frame(mptctl_id, ioc, mf);
			/* Now wait for the command to complete */
			timeout = (karg.timeout > 0) ? karg.timeout : MPT_IOCTL_DEFAULT_TIMEOUT;
			timeout = wait_event_timeout(mptctl_wait,
	    		 ioc->ioctl->wait_done == 1,
			     HZ*timeout);

			if(timeout <=0 && (ioc->ioctl->wait_done != 1 )) {
			/* Now we need to reset the board */

				mptctl_timeout_expired(ioc, mf);
				rc = -ENODATA;
				goto done_free_mem;
			}

		}
	}

	mf = NULL;

	/* If a valid reply frame, copy to the user.
	 * Offset 2: reply length in U32's
	 */
	if (ioc->ioctl->status & MPT_IOCTL_STATUS_RF_VALID) {
		if (karg.maxReplyBytes < ioc->reply_sz) {
			 sz = min(karg.maxReplyBytes, 4*ioc->ioctl->reply[2]);
		} else {
			 sz = min(ioc->reply_sz, 4*ioc->ioctl->reply[2]);
		}

		if (sz > 0) {
			if (copy_to_user(karg.replyFrameBufPtr,
				 &ioc->ioctl->reply, sz)){

				 printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
				 "Unable to write out reply frame %p\n",
				 __FILE__, __LINE__, karg.replyFrameBufPtr);
				 rc =  -ENODATA;
				 goto done_free_mem;
			}
		}
	}

	/* If valid sense data, copy to user.
	 */
	if (ioc->ioctl->status & MPT_IOCTL_STATUS_SENSE_VALID) {
		sz = min(karg.maxSenseBytes, MPT_SENSE_BUFFER_SIZE);
		if (sz > 0) {
			if (copy_to_user(karg.senseDataPtr, ioc->ioctl->sense, sz)) {
				printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
				"Unable to write sense data to user %p\n",
				__FILE__, __LINE__,
				karg.senseDataPtr);
				rc =  -ENODATA;
				goto done_free_mem;
			}
		}
	}

	/* If the overall status is _GOOD and data in, copy data
	 * to user.
	 */
	if ((ioc->ioctl->status & MPT_IOCTL_STATUS_COMMAND_GOOD) &&
				(karg.dataInSize > 0) && (bufIn.kptr)) {
		if (copy_to_user(karg.dataInBufPtr,
			 bufIn.kptr, karg.dataInSize)) {
			printk(KERN_ERR "%s@%d: mptctl_do_mpt_command - "
				"Unable to write data to user %p\n",
				__FILE__, __LINE__,
				karg.dataInBufPtr);
			rc =  -ENODATA;
		}
	}

done_free_mem:

	/* Free the allocated memory.
	 */
	 if (bufOut.kptr != NULL) {
		pci_free_consistent(ioc->pcidev,
			bufOut.len, (void *) bufOut.kptr, dma_addr_out);
	}

	if (bufIn.kptr != NULL) {
		pci_free_consistent(ioc->pcidev,
			bufIn.len, (void *) bufIn.kptr, dma_addr_in);
	}
	
	if (SAS_handshake_mf) {
		kfree(SAS_handshake_mf);
		mf=NULL;
	}
	if (SAS_handshake_reply)
		kfree(SAS_handshake_reply);

	/* mf is null if command issued successfully
	 * otherwise, failure occured after mf acquired.
	 */
	if (mf)
		mpt_free_msg_frame(ioc, mf);

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* Prototype Routine for the HOST INFO command.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-EBUSY  if previous command timout and IOC reset is not complete.
 *		-ENODEV if no such device/adapter
 *		-ETIME	if timer expires
 *		-ENOMEM if memory allocation error
 */
static int
mptctl_hp_hostinfo(unsigned long arg, unsigned int data_size)
{
	hp_host_info_t	__user *uarg = (void __user *) arg;
	MPT_ADAPTER		*ioc;
	struct pci_dev		*pdev;
	char			*pbuf=NULL;
	dma_addr_t		buf_dma;
	hp_host_info_t		karg;
	int			iocnum;
	int			rc, cim_rev;
	ToolboxIstwiReadWriteRequest_t	*IstwiRWRequest;
	MPT_FRAME_HDR		*mf = NULL;
	MPIHeader_t		*mpi_hdr;

	dctlprintk(("mptctl_hp_hostinfo called.\n"));
	/* Reset long to int. Should affect IA64 and SPARC only
	 */
	if (data_size == sizeof(hp_host_info_t))
		cim_rev = 1;
	else if (data_size == sizeof(hp_host_info_rev0_t))
		cim_rev = 0; /* obsolete */
	else
		return -EFAULT;

	if (copy_from_user(&karg, uarg, sizeof(hp_host_info_t))) {
		printk(KERN_ERR "%s@%d: mptctl_hp_host_info - "
			"Unable to read in hp_host_info struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
	    (ioc == NULL)) {
		dctlprintk(("mptctl_hp_hostinfo: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	/* Fill in the data and return the structure to the calling
	 * program
	 */
	pdev = ioc->pcidev;

	karg.vendor = pdev->vendor;
	karg.device = pdev->device;
	karg.subsystem_id = pdev->subsystem_device;
	karg.subsystem_vendor = pdev->subsystem_vendor;
	karg.devfn = pdev->devfn;
	karg.bus = pdev->bus->number;

	/* Save the SCSI host no. if
	 * SCSI driver loaded
	 */
	if (ioc->sh != NULL)
		karg.host_no = ioc->sh->host_no;
	else
		karg.host_no =  -1;

	/* Reformat the fw_version into a string
	 */
	karg.fw_version[0] = ioc->facts.FWVersion.Struct.Major >= 10 ?
		((ioc->facts.FWVersion.Struct.Major / 10) + '0') : '0';
	karg.fw_version[1] = (ioc->facts.FWVersion.Struct.Major % 10 ) + '0';
	karg.fw_version[2] = '.';
	karg.fw_version[3] = ioc->facts.FWVersion.Struct.Minor >= 10 ?
		((ioc->facts.FWVersion.Struct.Minor / 10) + '0') : '0';
	karg.fw_version[4] = (ioc->facts.FWVersion.Struct.Minor % 10 ) + '0';
	karg.fw_version[5] = '.';
	karg.fw_version[6] = ioc->facts.FWVersion.Struct.Unit >= 10 ?
		((ioc->facts.FWVersion.Struct.Unit / 10) + '0') : '0';
	karg.fw_version[7] = (ioc->facts.FWVersion.Struct.Unit % 10 ) + '0';
	karg.fw_version[8] = '.';
	karg.fw_version[9] = ioc->facts.FWVersion.Struct.Dev >= 10 ?
		((ioc->facts.FWVersion.Struct.Dev / 10) + '0') : '0';
	karg.fw_version[10] = (ioc->facts.FWVersion.Struct.Dev % 10 ) + '0';
	karg.fw_version[11] = '\0';

	if (ioc->bus_type == SAS) {
		strncpy(karg.serial_number, ioc->board_tracer, 24);
		karg.serial_number[24-1]='\0';
	}

	rc = mpt_GetIocState(ioc, 1);
	switch (rc) {
	case MPI_IOC_STATE_OPERATIONAL:
		karg.ioc_status =  HP_STATUS_OK;
		break;

	case MPI_IOC_STATE_FAULT:
		karg.ioc_status =  HP_STATUS_FAILED;
		break;

	case MPI_IOC_STATE_RESET:
	case MPI_IOC_STATE_READY:
	default:
		karg.ioc_status =  HP_STATUS_OTHER;
		break;
	}

	karg.base_io_addr = pci_resource_start(pdev, 0);

	if ((ioc->bus_type == SAS) || (ioc->bus_type == FC))
		karg.bus_phys_width = HP_BUS_WIDTH_UNK;
	else
		karg.bus_phys_width = HP_BUS_WIDTH_16;

	karg.hard_resets = 0;
	karg.soft_resets = 0;
	karg.timeouts = 0;
	if (ioc->sh != NULL) {
		MPT_SCSI_HOST *hd =  (MPT_SCSI_HOST *)ioc->sh->hostdata;

		if (hd && (cim_rev == 1)) {
			karg.hard_resets = hd->hard_resets;
			karg.soft_resets = hd->soft_resets;
			karg.timeouts = hd->timeouts;
		}
	}

	/* Gather ISTWI(Industry Standard Two Wire Interface) Data */
	if ((mf = mpt_get_msg_frame(mptctl_id, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		goto out;
	}

	IstwiRWRequest = (ToolboxIstwiReadWriteRequest_t *)mf;
	mpi_hdr = (MPIHeader_t *) mf;
	memset(IstwiRWRequest,0,sizeof(ToolboxIstwiReadWriteRequest_t));
	IstwiRWRequest->Function = MPI_FUNCTION_TOOLBOX;
	IstwiRWRequest->Tool = MPI_TOOLBOX_ISTWI_READ_WRITE_TOOL;
	IstwiRWRequest->MsgContext = mpi_hdr->MsgContext;
	IstwiRWRequest->Flags = MPI_TB_ISTWI_FLAGS_READ;
	IstwiRWRequest->NumAddressBytes = 0x01;
	IstwiRWRequest->DataLength = cpu_to_le16(0x04);
	if (pdev->devfn & 1)
		IstwiRWRequest->DeviceAddr = 0xB2;
	else
		IstwiRWRequest->DeviceAddr = 0xB0;

	pbuf = pci_alloc_consistent(ioc->pcidev, 4, &buf_dma);
	if (!pbuf)
		goto out;
	ioc->add_sge((char *)&IstwiRWRequest->SGL,
	    (MPT_SGE_FLAGS_SSIMPLE_READ|4), buf_dma);

	ioc->ioctl->wait_done = 0;
	INITIALIZE_IOCTL_STATUS(ioc->ioctl->status)

	mpt_put_msg_frame(mptctl_id, ioc, mf);

	rc = wait_event_timeout(mptctl_wait,
	     ioc->ioctl->wait_done == 1,
	     HZ*MPT_IOCTL_DEFAULT_TIMEOUT /* 10 sec */);

	if(rc <=0 && (ioc->ioctl->wait_done != 1 )) {
	/* Now we need to reset the board */
		mptctl_timeout_expired(ioc, mf);
		mpt_free_msg_frame(ioc, mf);
		goto out;
	}

	/* ISTWI Data Definition
	 * pbuf[0] = FW_VERSION = 0x4
	 * pbuf[1] = Bay Count = 6 or 4 or 2, depending on
	 *  the config, you should be seeing one out of these three values
	 * pbuf[2] = Drive Installed Map = bit pattern depend on which
	    bays have drives in them
	 * pbuf[3] = Checksum (0x100 = (byte0 + byte2 + byte3)
	 */
	if (ioc->ioctl->status & MPT_IOCTL_STATUS_RF_VALID)
		karg.rsvd = *(u32 *)pbuf;

 out:
	if (pbuf)
		pci_free_consistent(ioc->pcidev, 4, pbuf, buf_dma);

	/* Copy the data from kernel memory to user memory
	 */
	if (copy_to_user((char __user *)arg, &karg, sizeof(hp_host_info_t))) {
		printk(KERN_ERR "%s@%d: mptctl_hpgethostinfo - "
			"Unable to write out hp_host_info @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	return 0;

}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* Prototype Routine for the TARGET INFO command.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-EBUSY  if previous command timout and IOC reset is not complete.
 *		-ENODEV if no such device/adapter
 *		-ETIME	if timer expires
 *		-ENOMEM if memory allocation error
 */
static int
mptctl_hp_targetinfo(unsigned long arg)
{
	hp_target_info_t __user *uarg = (void __user *) arg;
	SCSIDevicePage0_t	*pg0_alloc;
	SCSIDevicePage3_t	*pg3_alloc;
	MPT_ADAPTER		*ioc;
	MPT_SCSI_HOST 		*hd = NULL;
	hp_target_info_t	karg;
	int			iocnum;
	int			data_sz;
	dma_addr_t		page_dma;
	CONFIGPARMS	 	cfg;
	ConfigPageHeader_t	hdr;
	int			tmp, np, rc = 0;

	dctlprintk(("mptctl_hp_targetinfo called.\n"));
	if (copy_from_user(&karg, uarg, sizeof(hp_target_info_t))) {
		printk(KERN_ERR "%s@%d: mptctl_hp_targetinfo - "
			"Unable to read in hp_host_targetinfo struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
		(ioc == NULL)) {
		dctlprintk(("mptctl_hp_targetinfo - ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	/*  There is nothing to do for FCP parts.
	 */
	if ((ioc->bus_type == SAS) || (ioc->bus_type == FC))
		return 0;

	if ((ioc->spi_data.sdp0length == 0) || (ioc->sh == NULL))
		return 0;

	if (ioc->sh->host_no != karg.hdr.host)
		return -ENODEV;

       /* Get the data transfer speeds
        */
	data_sz = ioc->spi_data.sdp0length * 4;
	pg0_alloc = (SCSIDevicePage0_t *) pci_alloc_consistent(ioc->pcidev, data_sz, &page_dma);
	if (pg0_alloc) {
		hdr.PageVersion = ioc->spi_data.sdp0version;
		hdr.PageLength = data_sz;
		hdr.PageNumber = 0;
		hdr.PageType = MPI_CONFIG_PAGETYPE_SCSI_DEVICE;

		cfg.cfghdr.hdr = &hdr;
		cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
		cfg.dir = 0;
		cfg.timeout = 0;
		cfg.physAddr = page_dma;

		cfg.pageAddr = (karg.hdr.channel << 8) | karg.hdr.id;

		if ((rc = mpt_config(ioc, &cfg)) == 0) {
			np = le32_to_cpu(pg0_alloc->NegotiatedParameters);
			karg.negotiated_width = np & MPI_SCSIDEVPAGE0_NP_WIDE ?
					HP_BUS_WIDTH_16 : HP_BUS_WIDTH_8;

			if (np & MPI_SCSIDEVPAGE0_NP_NEG_SYNC_OFFSET_MASK) {
				tmp = (np & MPI_SCSIDEVPAGE0_NP_NEG_SYNC_PERIOD_MASK) >> 8;
				if (tmp < 0x09)
					karg.negotiated_speed = HP_DEV_SPEED_ULTRA320;
				else if (tmp <= 0x09)
					karg.negotiated_speed = HP_DEV_SPEED_ULTRA160;
				else if (tmp <= 0x0A)
					karg.negotiated_speed = HP_DEV_SPEED_ULTRA2;
				else if (tmp <= 0x0C)
					karg.negotiated_speed = HP_DEV_SPEED_ULTRA;
				else if (tmp <= 0x25)
					karg.negotiated_speed = HP_DEV_SPEED_FAST;
				else
					karg.negotiated_speed = HP_DEV_SPEED_ASYNC;
			} else
				karg.negotiated_speed = HP_DEV_SPEED_ASYNC;
		}

		pci_free_consistent(ioc->pcidev, data_sz, (u8 *) pg0_alloc, page_dma);
	}

	/* Set defaults
	 */
	karg.message_rejects = -1;
	karg.phase_errors = -1;
	karg.parity_errors = -1;
	karg.select_timeouts = -1;

	/* Get the target error parameters
	 */
	hdr.PageVersion = 0;
	hdr.PageLength = 0;
	hdr.PageNumber = 3;
	hdr.PageType = MPI_CONFIG_PAGETYPE_SCSI_DEVICE;

	cfg.cfghdr.hdr = &hdr;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;
	cfg.timeout = 0;
	cfg.physAddr = -1;
	if ((mpt_config(ioc, &cfg) == 0) && (cfg.cfghdr.hdr->PageLength > 0)) {
		/* Issue the second config page request */
		cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
		data_sz = (int) cfg.cfghdr.hdr->PageLength * 4;
		pg3_alloc = (SCSIDevicePage3_t *) pci_alloc_consistent(
							ioc->pcidev, data_sz, &page_dma);
		if (pg3_alloc) {
			cfg.physAddr = page_dma;
			cfg.pageAddr = (karg.hdr.channel << 8) | karg.hdr.id;
			if ((rc = mpt_config(ioc, &cfg)) == 0) {
				karg.message_rejects = (u32) le16_to_cpu(pg3_alloc->MsgRejectCount);
				karg.phase_errors = (u32) le16_to_cpu(pg3_alloc->PhaseErrorCount);
				karg.parity_errors = (u32) le16_to_cpu(pg3_alloc->ParityErrorCount);
			}
			pci_free_consistent(ioc->pcidev, data_sz, (u8 *) pg3_alloc, page_dma);
		}
	}
	hd = (MPT_SCSI_HOST *) ioc->sh->hostdata;
	if (hd != NULL)
		karg.select_timeouts = hd->sel_timeout[karg.hdr.id];

	/* Copy the data from kernel memory to user memory
	 */
	if (copy_to_user((char __user *)arg, &karg, sizeof(hp_target_info_t))) {
		printk(KERN_ERR "%s@%d: mptctl_hp_target_info - "
			"Unable to write out mpt_ioctl_targetinfo struct @ %p\n",
				__FILE__, __LINE__, uarg);
		return -EFAULT;
	}

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* REGISTER DIAG BUFFER Routine.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-EBUSY  if previous command timout and IOC reset is not complete.
 *		-ENODEV if no such device/adapter
 *		-ETIME	if timer expires
 *		-ENOMEM if memory allocation error
 */
static int
mptctl_register_diag_buffer (unsigned long arg)
{
	mpt_diag_register_t	__user *uarg = (void __user *) arg;
	mpt_diag_register_t	karg;
	MPT_ADAPTER		*ioc;
	int			iocnum, rc=0, ii;
	void *			request_data;
	dma_addr_t		request_data_dma;
	u32			request_data_sz;
	MPT_FRAME_HDR		*mf;
  	DiagBufferPostRequest_t *DiagBufferPostRequest;
  	DiagBufferPostReply_t	*DiagBufferPostReply;
	u32 			tmp;
	u8			buffType;

	dctlprintk(("mptctl_register_diag_buffer called.\n"));
	if (copy_from_user(&karg, uarg, sizeof(mpt_diag_register_t))) {
		printk(KERN_ERR "mptctl_register_diag_buffer: "
			"Unable to read mpt_diag_register_t data @ %p\n",
				uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
		(ioc == NULL)) {
		dctlprintk(("mptctl_register_diag_buffer: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	buffType = karg.data.BufferType;
	if ( !(ioc->facts.IOCCapabilities &
		MPT_DIAG_CAPABILITY(buffType)) ) {
		printk("mptctl_register_diag_buffer: ioc%d does not have Capability for BufferType=%x\n",
				iocnum, buffType);
		return -ENODEV;
	}

	if ( ioc->DiagBuffer_Status[buffType] & MPT_DIAG_BUFFER_IS_REGISTERED ) {
		printk("mptctl_register_diag_buffer: ioc%d already has a Registered buffer for BufferType=%x\n",
			iocnum, buffType);
		return -EFAULT;
	}

	/* Get a free request frame and save the message context.
	 */
        if ((mf = mpt_get_msg_frame(mptctl_id, ioc)) == NULL)
                return -EAGAIN;

	request_data = ioc->DiagBuffer[buffType];
	request_data_sz = karg.data.RequestedBufferSize;

	if ( request_data == NULL ) {
allocDiagBuffer:
		request_data = pci_alloc_consistent(
	    		ioc->pcidev, request_data_sz, &request_data_dma);

		if (request_data == NULL) {
			printk("mptctl_register_diag_buffer: pci_alloc_consistent FAILED\n");
			mpt_free_msg_frame(ioc, mf);
                	return -EAGAIN;
		}
		ioc->DiagBuffer[buffType] = request_data;
		ioc->DiagBuffer_sz[buffType] = request_data_sz;
		ioc->DiagBuffer_dma[buffType] = request_data_dma;
		ioc->DataSize[buffType] = 0;
	} else {
		request_data_dma = ioc->DiagBuffer_dma[buffType];
		if ( request_data_sz != ioc->DiagBuffer_sz[buffType] ) {
			pci_free_consistent(ioc->pcidev, ioc->DiagBuffer_sz[buffType],
				request_data,
				request_data_dma);
			goto allocDiagBuffer;
		}
	}
	ioc->DiagBuffer_Status[buffType] = 0;

  	DiagBufferPostRequest = (DiagBufferPostRequest_t *)mf;
	DiagBufferPostRequest->Function = MPI_FUNCTION_DIAG_BUFFER_POST;
	DiagBufferPostRequest->ChainOffset = 0;
	DiagBufferPostRequest->BufferType = karg.data.BufferType;
	DiagBufferPostRequest->TraceLevel =
		ioc->TraceLevel[buffType] =
		karg.data.TraceLevel;
	DiagBufferPostRequest->MsgFlags = 0;
	DiagBufferPostRequest->Reserved1 = 0;
	DiagBufferPostRequest->Reserved2 = 0;
	DiagBufferPostRequest->Reserved3 = 0;
	if ( buffType == MPI_DIAG_BUF_TYPE_EXTENDED ) {
		ioc->ExtendedType[buffType] = karg.data.ExtendedType;
	} else {
		ioc->ExtendedType[buffType] = (u32)0;
	}
	DiagBufferPostRequest->ExtendedType = 
		cpu_to_le32(ioc->ExtendedType[buffType]);
	ioc->UniqueId[buffType] = karg.data.UniqueId;
	DiagBufferPostRequest->BufferLength = cpu_to_le32(request_data_sz);
	for ( ii = 0; ii < 4; ii++ ) {
		ioc->ProductSpecific[buffType][ii] = 
			karg.data.ProductSpecific[ii];
		DiagBufferPostRequest->ProductSpecific[ii] =
			cpu_to_le32(ioc->ProductSpecific[buffType][ii]);
	}
	if (sizeof(dma_addr_t) == sizeof(u64)) {
		tmp = (u32) ((u64)request_data_dma >> 32);
		DiagBufferPostRequest->BufferAddress.High = cpu_to_le32(tmp);
	} else {
		DiagBufferPostRequest->BufferAddress.High = (u32)0;
	}
	tmp = request_data_dma & 0xFFFFFFFF;
	DiagBufferPostRequest->BufferAddress.Low = cpu_to_le32(tmp);

	ioc->ioctl->wait_done = 0;
	INITIALIZE_IOCTL_STATUS(ioc->ioctl->status)

	mpt_put_msg_frame(mptctl_id, ioc, mf);

	/* Now wait for the command to complete */
	ii = wait_event_timeout(mptctl_wait,
	     ioc->ioctl->wait_done == 1,
	     HZ*MPT_IOCTL_DEFAULT_TIMEOUT /* 10 sec */);

	if(ii <=0 && (ioc->ioctl->wait_done != 1 )) {
	/* Now we need to reset the board */
		mptctl_timeout_expired(ioc, mf);
		mpt_free_msg_frame(ioc, mf);
		rc = -ENODATA;
		goto mptctl_register_diag_buffer_out;
	}

	/* process the completed Reply Message Frame */
	if (ioc->ioctl->status & MPT_IOCTL_STATUS_RF_VALID) {

		DiagBufferPostReply =
		    (DiagBufferPostReply_t *)ioc->ioctl->reply;

		if ( le16_to_cpu(DiagBufferPostReply->IOCStatus) == MPI_IOCSTATUS_SUCCESS) {
			if ( DiagBufferPostReply->MsgLength > 5 ) {
				ioc->DataSize[buffType] = 
					le32_to_cpu(DiagBufferPostReply->TransferLength);
			}
			ioc->DiagBuffer_Status[buffType] |= 
				MPT_DIAG_BUFFER_IS_REGISTERED;
		} else {
			dctlprintk(("DiagBufferPostReply: IOCStatus=%x IOCLogInfo=%x\n",
			    DiagBufferPostReply->IOCStatus,
			    DiagBufferPostReply->IOCLogInfo));
			rc = -EFAULT;
		}
	} else {
		dctlprintk(("DiagBufferPostReply: status=%x\n",
			ioc->ioctl->status));
		rc = -EFAULT;
	}

mptctl_register_diag_buffer_out:

	if ( rc ) {
		pci_free_consistent(ioc->pcidev, request_data_sz,
			request_data,
			request_data_dma);
	}
	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* RELEASE DIAG BUFFER Routine.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-EBUSY  if previous command timout and IOC reset is not complete.
 *		-ENODEV if no such device/adapter
 *		-ETIME	if timer expires
 *		-ENOMEM if memory allocation error
 */
static int
mptctl_release_diag_buffer (unsigned long arg)
{
	mpt_diag_release_t	__user *uarg = (void __user *) arg;
	mpt_diag_release_t	karg;
	MPT_ADAPTER		*ioc;
	void *			request_data;
	int			iocnum, ii, rc=0;
	MPT_FRAME_HDR		*mf;
  	DiagReleaseRequest_t 	*DiagRelease;
  	DiagReleaseReply_t	*DiagReleaseReply;
	u8			buffType;

	dctlprintk(("mptctl_release_diag_buffer called.\n"));
	if (copy_from_user(&karg, uarg, sizeof(mpt_diag_release_t))) {
		printk(KERN_ERR "mptctl_release_diag_buffer: "
			"Unable to read mpt_diag_release_t data @ %p\n",
				uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
		(ioc == NULL)) {
		dctlprintk(("mptctl_release_diag_buffer: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	buffType = karg.data.UniqueId & 0x000000ff;
	if ( !(ioc->facts.IOCCapabilities &
		MPT_DIAG_CAPABILITY(buffType)) ) {
		printk("mptctl_release_diag_buffer: ioc%d does not have Capability for BufferType=%x\n",
				iocnum, buffType);
		return -ENODEV;
	}

	if ( (ioc->DiagBuffer_Status[buffType] & MPT_DIAG_BUFFER_IS_REGISTERED) == 0 ) {
		printk("mptctl_release_diag_buffer: ioc%d BufferType=%x is not registered\n",
				iocnum, buffType);
		return -EFAULT;
	}

	if (karg.data.UniqueId != ioc->UniqueId[buffType]) {
		printk("mptctl_release_diag_buffer: UniqueId=%x is not registered\n",
			karg.data.UniqueId);
		return -EFAULT;
	}

	if ( ioc->DiagBuffer_Status[buffType] & MPT_DIAG_BUFFER_IS_RELEASED) {
		dctlprintk(("mptctl_release_diag_buffer: ioc%d BufferType=%x is already released\n",
			iocnum, buffType));
		return rc;
	}

	request_data = ioc->DiagBuffer[buffType];

	if ( request_data == NULL ) {
		printk("mptctl_release_diag_buffer: ioc%d does not have buffer for BufferType=%x\n",
				iocnum, buffType);
		return -ENODEV;
	}

	/* Get a free request frame and save the message context.
	 */
        if ((mf = mpt_get_msg_frame(mptctl_id, ioc)) == NULL)
                return -EAGAIN;

  	DiagRelease = (DiagReleaseRequest_t *)mf;
	DiagRelease->Function = MPI_FUNCTION_DIAG_RELEASE;
	DiagRelease->BufferType = buffType;
	DiagRelease->ChainOffset = 0;
	DiagRelease->Reserved1 = 0;
	DiagRelease->Reserved2 = 0;
	DiagRelease->Reserved3 = 0;
	DiagRelease->MsgFlags = 0;

	ioc->ioctl->wait_done = 0;
	INITIALIZE_IOCTL_STATUS(ioc->ioctl->status)

	mpt_put_msg_frame(mptctl_id, ioc, mf);

	/* Now wait for the command to complete */
	ii = wait_event_timeout(mptctl_wait,
	     ioc->ioctl->wait_done == 1,
	     HZ*MPT_IOCTL_DEFAULT_TIMEOUT /* 10 sec */);

	if(ii <=0 && (ioc->ioctl->wait_done != 1 )) {
	/* Now we need to reset the board */
		mptctl_timeout_expired(ioc, mf);
		mpt_free_msg_frame(ioc, mf);
		rc = -ENODATA;
		goto mptctl_release_diag_buffer_out;
	}

	/* process the completed Reply Message Frame */
	if (ioc->ioctl->status & MPT_IOCTL_STATUS_RF_VALID) {
		DiagReleaseReply =
		    (DiagReleaseReply_t *)ioc->ioctl->reply;

		if ( le16_to_cpu(DiagReleaseReply->IOCStatus) != MPI_IOCSTATUS_DIAGNOSTIC_RELEASED) {
			dctlprintk(("DiagReleaseReply: IOCStatus=%x IOCLogInfo=%x\n",
			    DiagReleaseReply->IOCStatus,
			    DiagReleaseReply->IOCLogInfo));
			rc = -EFAULT;
		} else {
			ioc->DiagBuffer_Status[buffType] |=
				MPT_DIAG_BUFFER_IS_RELEASED;
		}
	} else {
		dctlprintk(("DiagReleaseReply: status=%x\n",
			ioc->ioctl->status));
		rc = -EFAULT;
	}

mptctl_release_diag_buffer_out:

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* UNREGISTER DIAG BUFFER Routine.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-EBUSY  if previous command timout and IOC reset is not complete.
 *		-ENODEV if no such device/adapter
 *		-ETIME	if timer expires
 *		-ENOMEM if memory allocation error
 */
static int
mptctl_unregister_diag_buffer (unsigned long arg)
{
	mpt_diag_unregister_t	__user *uarg = (void __user *) arg;
	mpt_diag_unregister_t	karg;
	MPT_ADAPTER		*ioc;
	int			iocnum;
	void *			request_data;
	dma_addr_t		request_data_dma;
	u32			request_data_sz;
	u8			buffType;

	dctlprintk(("mptctl_unregister_diag_buffer called.\n"));
	if (copy_from_user(&karg, uarg, sizeof(mpt_diag_unregister_t))) {
		printk(KERN_ERR "mptctl_unregister_diag_buffer: "
			"Unable to read pt_diag_unregister_t data @ %p\n",
				uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
		(ioc == NULL)) {
		dctlprintk(("mptctl_unregister_diag_buffer: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	buffType = karg.data.UniqueId & 0x000000ff;
	if ( !(ioc->facts.IOCCapabilities &
		MPT_DIAG_CAPABILITY(buffType)) ) {
		printk("mptctl_unregister_diag_buffer: ioc%d does not have Capability for BufferType=%x\n",
				iocnum, buffType);
		return -ENODEV;
	}

	if ( (ioc->DiagBuffer_Status[buffType] & MPT_DIAG_BUFFER_IS_REGISTERED) == 0 ) {
		printk("mptctl_unregister_diag_buffer: ioc%d BufferType=%x is not registered\n",
				iocnum, buffType);
		return -EFAULT;
	}
	if ( (ioc->DiagBuffer_Status[buffType] & MPT_DIAG_BUFFER_IS_RELEASED) == 0 ) {
		printk("mptctl_unregister_diag_buffer: ioc%d BufferType=%x has not been released\n",
			iocnum, buffType);
		return -EFAULT;
	}

	if (karg.data.UniqueId != ioc->UniqueId[buffType]) {
		printk("mptctl_unregister_diag_buffer: UniqueId=%x is not registered\n",
			karg.data.UniqueId);
		return -EFAULT;
	}

	request_data = ioc->DiagBuffer[buffType];

	if ( request_data ) {
		request_data_sz = ioc->DiagBuffer_sz[buffType];
		request_data_dma = ioc->DiagBuffer_dma[buffType];
		pci_free_consistent(ioc->pcidev, request_data_sz,
			request_data,
			request_data_dma);

		ioc->DiagBuffer[buffType] = NULL;
		ioc->DiagBuffer_Status[buffType] = 0;
		return 0;
	} else {
		printk("mptctl_unregister_diag_buffer: ioc%d does not have buffer for BufferType=%x\n",
				iocnum, buffType);
		return -ENODEV;
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* QUERY DIAG BUFFER Routine.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-EBUSY  if previous command timout and IOC reset is not complete.
 *		-ENODEV if no such device/adapter
 *		-ETIME	if timer expires
 *		-ENOMEM if memory allocation error
 */
static int
mptctl_query_diag_buffer (unsigned long arg)
{
	mpt_diag_query_t	*uarg = (mpt_diag_query_t *) arg;
	mpt_diag_query_t	karg;
	MPT_ADAPTER		*ioc;
	void *			request_data;
	int			iocnum, ii, rc=-EFAULT;
	u8			buffType;

	dctlprintk(("mptctl_query_diag_buffer called.\n"));
	if (copy_from_user(&karg, uarg, sizeof(mpt_diag_query_t))) {
		printk(KERN_ERR "mptctl_query_diag_buffer: "
			"Unable to read mpt_diag_query_t data @ %p\n",
				(void*)uarg);
		return -EFAULT;
	}

	karg.data.Flags = 0;
	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
		(ioc == NULL)) {
		dctlprintk(("mptctl_query_diag_buffer: ioc%d not found!\n",
			iocnum));
		goto copy_back;
	}

	buffType = karg.data.BufferType;
	if ( !(ioc->facts.IOCCapabilities &
		MPT_DIAG_CAPABILITY(buffType)) ) {
		printk("mptctl_query_diag_buffer: ioc%d does not have Capability for BufferType=%x\n",
			iocnum, buffType);
		goto copy_back;
	}

	if ( (ioc->DiagBuffer_Status[buffType] & MPT_DIAG_BUFFER_IS_REGISTERED) == 0 ) {
		printk("mptctl_query_diag_buffer: ioc%d BufferType=%x is not registered\n",
			iocnum, buffType);
		goto copy_back;
	}

	if (karg.data.UniqueId & 0xffffff00) {
		if (karg.data.UniqueId != ioc->UniqueId[buffType]) {
			printk("mptctl_query_diag_buffer: UniqueId=%x is not registered\n",
				karg.data.UniqueId);
			goto copy_back;
		}
	}

	request_data = ioc->DiagBuffer[buffType];

	if ( request_data ) {
		if ( buffType == MPI_DIAG_BUF_TYPE_EXTENDED ) {
			if (karg.data.ExtendedType != ioc->ExtendedType[buffType])
				goto copy_back;
		} else
			karg.data.ExtendedType = 0;

		if ( ioc->DiagBuffer_Status[buffType] & MPT_DIAG_BUFFER_IS_RELEASED )
			karg.data.Flags = 3;
		else
			karg.data.Flags = 7;
		karg.data.TraceLevel = ioc->TraceLevel[buffType];
		for ( ii = 0; ii < 4; ii++ ) {
			karg.data.ProductSpecific[ii] =
				ioc->ProductSpecific[buffType][ii];
		}
		karg.data.DataSize = ioc->DataSize[buffType];
		karg.data.DriverAddedBufferSize = 0;
		karg.data.UniqueId = ioc->UniqueId[buffType];
	} else {
		printk( "mptctl_query_diag_buffer: ioc%d does not have buffer for BufferType=%x\n",
			iocnum, buffType);
	}
copy_back:
	if (copy_to_user((char *)arg, &karg, sizeof(mpt_diag_query_t))) {
		printk(KERN_ERR "mptctl_query_diag_buffer: "
			"Unable to write mpt_diag_query_t data @ %p\n",
			(void*)uarg);
		return -EFAULT;
	}
	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* READ DIAG BUFFER Routine.
 *
 * Outputs:	None.
 * Return:	0 if successful
 *		-EFAULT if data unavailable
 *		-EBUSY  if previous command timout and IOC reset is not complete.
 *		-ENODEV if no such device/adapter
 *		-ETIME	if timer expires
 *		-ENOMEM if memory allocation error
 */
static int
mptctl_read_diag_buffer (unsigned long arg)
{
	mpt_diag_read_buffer_t	__user *uarg = (void __user *) arg;
	mpt_diag_read_buffer_t	karg;
	MPT_ADAPTER		*ioc;
	void			*request_data, *diagData;
	dma_addr_t		request_data_dma;
  	DiagBufferPostRequest_t *DiagBufferPostRequest;
  	DiagBufferPostReply_t	*DiagBufferPostReply;
	MPT_FRAME_HDR		*mf;
	int			iocnum, rc=0, ii;
	u8			buffType;
	u32 			tmp;

	dctlprintk(("mptctl_read_diag_buffer called.\n"));
	if (copy_from_user(&karg, uarg, sizeof(mpt_diag_read_buffer_t))) {
		printk(KERN_ERR "mptctl_read_diag_buffer: "
			"Unable to read mpt_diag_read_buffer_t data @ %p\n",
				uarg);
		return -EFAULT;
	}

	if (((iocnum = mpt_verify_adapter(karg.hdr.iocnum, &ioc)) < 0) ||
		(ioc == NULL)) {
		dctlprintk((KERN_INFO "mptctl_read_diag_buffer: ioc%d not found!\n",
				iocnum));
		return -ENODEV;
	}

	buffType = karg.data.UniqueId & 0x000000ff;
	if ( !(ioc->facts.IOCCapabilities &
		MPT_DIAG_CAPABILITY(buffType)) ) {
		printk("mptctl_read_diag_buffer: ioc%d does not have Capability for BufferType=%x\n",
				iocnum, buffType);
		return -EFAULT;
	}

	if (karg.data.UniqueId != ioc->UniqueId[buffType]) {
		printk("mptctl_read_diag_buffer: UniqueId=%x is not registered\n",
			karg.data.UniqueId);
		return -EFAULT;
	}

	request_data = ioc->DiagBuffer[buffType];

	if ( request_data ) {
		diagData = (void *)(request_data + karg.data.StartingOffset);
		dctlprintk(("mptctl_read_diag_buffer: ioc%d diagData=%p request_data=%p StartingOffset=%x\n",
				iocnum, diagData, request_data, karg.data.StartingOffset));
		if (copy_to_user((char *)&uarg->data.DiagnosticData[0],
				diagData, karg.data.BytesToRead)) {
			printk(KERN_ERR "mptctl_read_diag_buffer: "
			"Unable to write mpt_diag_read_buffer_t data @ %p\n",
				diagData);
			return -EFAULT;
		}
	} else {
		printk("mptctl_read_diag_buffer: ioc%d does not have buffer for BufferType=%x\n",
			iocnum, buffType);
		return -EFAULT;
	}

	if ( karg.data.Flags & MPI_FW_DIAG_FLAG_REREGISTER ) {
		dctlprintk(("mptctl_read_diag_buffer: ioc%d Reregister BufferType=%x\n",
			iocnum, buffType));
		if ( (ioc->DiagBuffer_Status[buffType] & MPT_DIAG_BUFFER_IS_RELEASED) == 0 ) {
			dctlprintk(("mptctl_read_diag_buffer: ioc%d BufferType=%x is still registered\n",
				iocnum, buffType));
			return rc;
		}
		/* Get a free request frame and save the message context.
	 	*/
        	if ((mf = mpt_get_msg_frame(mptctl_id, ioc)) == NULL)
                	return -EAGAIN;

  		DiagBufferPostRequest = (DiagBufferPostRequest_t *)mf;
		DiagBufferPostRequest->Function = MPI_FUNCTION_DIAG_BUFFER_POST;
		DiagBufferPostRequest->ChainOffset = 0;
		DiagBufferPostRequest->BufferType = buffType;
		DiagBufferPostRequest->TraceLevel =
			ioc->TraceLevel[buffType];
		DiagBufferPostRequest->MsgFlags = 0;
		DiagBufferPostRequest->Reserved1 = 0;
		DiagBufferPostRequest->Reserved2 = 0;
		DiagBufferPostRequest->Reserved3 = 0;
		if ( buffType == MPI_DIAG_BUF_TYPE_EXTENDED ) {
			DiagBufferPostRequest->ExtendedType = 
				cpu_to_le32(ioc->ExtendedType[buffType]);
		}
		DiagBufferPostRequest->BufferLength = cpu_to_le32(ioc->DiagBuffer_sz[buffType]);
		for ( ii = 0; ii < 4; ii++ ) {
			DiagBufferPostRequest->ProductSpecific[ii] =
				cpu_to_le32(ioc->ProductSpecific[buffType][ii]);
		}
		request_data_dma = ioc->DiagBuffer_dma[buffType];
		if (sizeof(dma_addr_t) == sizeof(u64)) {
			tmp = (u32) ((u64)request_data_dma >> 32);
			DiagBufferPostRequest->BufferAddress.High = cpu_to_le32(tmp);
		} else {
			DiagBufferPostRequest->BufferAddress.High = (u32)0;
		}
		tmp = request_data_dma & 0xFFFFFFFF;
		DiagBufferPostRequest->BufferAddress.Low = cpu_to_le32(tmp);

		ioc->ioctl->wait_done = 0;
		INITIALIZE_IOCTL_STATUS(ioc->ioctl->status)

		mpt_put_msg_frame(mptctl_id, ioc, mf);

		/* Now wait for the command to complete */
		ii = wait_event_timeout(mptctl_wait,
		     ioc->ioctl->wait_done == 1,
		     HZ*MPT_IOCTL_DEFAULT_TIMEOUT /* 10 sec */);

		if(ii <=0 && (ioc->ioctl->wait_done != 1 )) {
		/* Now we need to reset the board */
			mptctl_timeout_expired(ioc, mf);
			mpt_free_msg_frame(ioc, mf);
			rc = -ENODATA;
			goto mptctl_read_diag_buffer_out;
		}

		/* process the completed Reply Message Frame */
		if (ioc->ioctl->status & MPT_IOCTL_STATUS_RF_VALID) {
			DiagBufferPostReply =
			    (DiagBufferPostReply_t *)ioc->ioctl->reply;

			if ( le16_to_cpu(DiagBufferPostReply->IOCStatus) == MPI_IOCSTATUS_SUCCESS) {
				if ( DiagBufferPostReply->MsgLength > 5 ) {
					ioc->DataSize[buffType] = 
						le32_to_cpu(DiagBufferPostReply->TransferLength);
				}
				ioc->DiagBuffer_Status[buffType] |= 
					MPT_DIAG_BUFFER_IS_REGISTERED;
			} else {
				dctlprintk(("DiagBufferPostReply: IOCStatus=%x IOCLogInfo=%x\n",
			    		DiagBufferPostReply->IOCStatus,
			    		DiagBufferPostReply->IOCLogInfo));
				rc = -EFAULT;
			}
		} else {
			dctlprintk(("DiagBufferPostReply: status=%x\n", 
				ioc->ioctl->status));
			rc = -EFAULT;
		}
	}
mptctl_read_diag_buffer_out:
	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/

static struct file_operations mptctl_fops = {
	.owner =	THIS_MODULE,
	.llseek =	no_llseek,
	.open =		mptctl_open,
	.release =	mptctl_release,
	.fasync = 	mptctl_fasync,
	.ioctl =	mptctl_ioctl,
};

static struct miscdevice mptctl_miscdev = {
	MPT_MINOR,
	MYNAM,
	&mptctl_fops
};

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/

#ifdef CONFIG_COMPAT

#include <linux/ioctl32.h>

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* compat_XXX functions are used to provide a conversion between
 * pointers and u32's. If the arg does not contain any pointers, then
 * a specialized function (compat_XXX) is not needed. If the arg
 * does contain pointer(s), then the specialized function is used
 * to ensure the structure contents is properly processed by mptctl.
 */
static int
compat_mptctl_ioctl(unsigned int fd, unsigned int cmd,
			unsigned long arg, struct file *filp)
{
	int ret;

	lock_kernel();
	dctlprintk((KERN_INFO MYNAM ": compat_mptctl_ioctl() called\n"));
	ret = mptctl_ioctl(filp->f_dentry->d_inode, filp, cmd, arg);
	unlock_kernel();
	return ret;
}

static int
compat_mptfwxfer_ioctl(unsigned int fd, unsigned int cmd,
			unsigned long arg, struct file *filp)
{
	struct mpt_fw_xfer32 kfw32;
	struct mpt_fw_xfer kfw;
	MPT_ADAPTER *iocp = NULL;
	int iocnum, iocnumX;
	int nonblock = (filp->f_flags & O_NONBLOCK);
	int ret;

	dctlprintk((KERN_INFO MYNAM ": compat_mptfwxfer_ioctl() called\n"));

	if (copy_from_user(&kfw32, (char __user *)arg, sizeof(kfw32)))
		return -EFAULT;

	/* Verify intended MPT adapter */
	iocnumX = kfw32.iocnum & 0xFF;
	if (((iocnum = mpt_verify_adapter(iocnumX, &iocp)) < 0) ||
	    (iocp == NULL)) {
		dctlprintk((KERN_ERR MYNAM ": compat_mptfwxfer_ioctl @%d - ioc%d not found!\n",
				__LINE__, iocnumX));
		return -ENODEV;
	}

	if ((ret = mptctl_syscall_down(iocp, nonblock)) != 0)
		return ret;

	kfw.iocnum = iocnum;
	kfw.fwlen = kfw32.fwlen;
	kfw.bufp = compat_ptr(kfw32.bufp);

	ret = mptctl_do_fw_download(kfw.iocnum, kfw.bufp, kfw.fwlen);

	up(&iocp->ioctl->sem_ioc);

	return ret;
}

static int
compat_mpt_command(unsigned int fd, unsigned int cmd,
			unsigned long arg, struct file *filp)
{
	struct mpt_ioctl_command32 karg32;
	struct mpt_ioctl_command32 __user *uarg = (struct mpt_ioctl_command32 __user *) arg;
	struct mpt_ioctl_command karg;
	MPT_ADAPTER *iocp = NULL;
	int iocnum, iocnumX;
	int nonblock = (filp->f_flags & O_NONBLOCK);
	int ret;

	dctlprintk((KERN_INFO MYNAM ": compat_mpt_command() called\n"));

	if (copy_from_user(&karg32, (char __user *)arg, sizeof(karg32)))
		return -EFAULT;

	/* Verify intended MPT adapter */
	iocnumX = karg32.hdr.iocnum & 0xFF;
	if (((iocnum = mpt_verify_adapter(iocnumX, &iocp)) < 0) ||
	    (iocp == NULL)) {
		dctlprintk((KERN_ERR MYNAM ": compat_mpt_command @%d - ioc%d not found!\n",
				__LINE__, iocnumX));
		return -ENODEV;
	}

	if ((ret = mptctl_syscall_down(iocp, nonblock)) != 0)
		return ret;

	/* Copy data to karg */
	karg.hdr.iocnum = karg32.hdr.iocnum;
	karg.hdr.port = karg32.hdr.port;
	karg.timeout = karg32.timeout;
	karg.maxReplyBytes = karg32.maxReplyBytes;

	karg.dataInSize = karg32.dataInSize;
	karg.dataOutSize = karg32.dataOutSize;
	karg.maxSenseBytes = karg32.maxSenseBytes;
	karg.dataSgeOffset = karg32.dataSgeOffset;

	karg.replyFrameBufPtr = (char __user *)(unsigned long)karg32.replyFrameBufPtr;
	karg.dataInBufPtr = (char __user *)(unsigned long)karg32.dataInBufPtr;
	karg.dataOutBufPtr = (char __user *)(unsigned long)karg32.dataOutBufPtr;
	karg.senseDataPtr = (char __user *)(unsigned long)karg32.senseDataPtr;

	/* Pass new structure to do_mpt_command
	 */
	ret = mptctl_do_mpt_command (karg, &uarg->MF);

	up(&iocp->ioctl->sem_ioc);

	return ret;
}

#endif /* CONFIG_COMPAT */


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptctl_probe - Installs ioctl devices per bus.
 *	@pdev: Pointer to pci_dev structure
 *
 *	Returns 0 for success, non-zero for failure.
 *
 */

static int
mptctl_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	MPT_ADAPTER *ioc = pci_get_drvdata(pdev);

	memset(&ioc->ioctl_cmds, 0, sizeof(MPT_IOCTL));
	ioc->ioctl = &ioc->ioctl_cmds;
	ioc->ioctl->ioc = ioc;
	sema_init(&ioc->ioctl->sem_ioc, 1);
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptctl_remove - Removed ioctl devices
 *	@pdev: Pointer to pci_dev structure
 *
 *
 */
static void
mptctl_remove(struct pci_dev *pdev)
{
	//MPT_ADAPTER *ioc = pci_get_drvdata(pdev);

}

static struct mpt_pci_driver mptctl_driver = {
  .probe		= mptctl_probe,
  .remove		= mptctl_remove,
};

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static int __init mptctl_init(void)
{
	int err;
	int where = 1;

	show_mptmod_ver(my_NAME, my_VERSION);

	if(mpt_device_driver_register(&mptctl_driver,
	  MPTCTL_DRIVER) != 0 ) {
		dprintk((KERN_INFO MYNAM
		": failed to register dd callbacks\n"));
	}

#ifdef CONFIG_COMPAT
	err = register_ioctl32_conversion(MPTIOCINFO, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTIOCINFO1, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTIOCINFO2, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTTARGETINFO, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTTEST, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTEVENTQUERY, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTEVENTENABLE, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTEVENTREPORT, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTHARDRESET, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTCOMMAND32, compat_mpt_command);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTFWDOWNLOAD32,
					  compat_mptfwxfer_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTFWDOWNLOADBOOT, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(HP_GETHOSTINFO, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(HP_GETTARGETINFO, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;

	err = register_ioctl32_conversion(MPTDIAGREGISTER, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTDIAGRELEASE, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTDIAGUNREGISTER, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTDIAGQUERY, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(MPTDIAGREADBUFFER, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
#if defined(CPQ_CIM)
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_DRIVER_INFO, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_CNTLR_CONFIG, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_CNTLR_STATUS, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_SCSI_ADDRESS, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_DEVICE_ADDRESS, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_PHY_INFO, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_SATA_SIGNATURE, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_LINK_ERRORS, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_SMP_PASSTHRU, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_SSP_PASSTHRU, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_FIRMWARE_DOWNLOAD, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_INFO, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_CONFIG, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_FEATURES, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_SET_RAID_CONTROL, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_ELEMENT, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_SET_RAID_OPERATION, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_SET_PHY_INFO, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_STP_PASSTHRU, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_TASK_MANAGEMENT, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_PHY_CONTROL, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_CONNECTOR_INFO, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
	err = register_ioctl32_conversion(CC_CSMI_SAS_GET_LOCATION, compat_mptctl_ioctl);
	if (++where && err) goto out_fail;
#endif /* CPQ_CIM */
#endif /* CONFIG_COMPAT */

	/* Register this device */
	err = misc_register(&mptctl_miscdev);
	if (err < 0) {
		printk(KERN_ERR MYNAM ": Can't register misc device [minor=%d].\n", MPT_MINOR);
		goto out_fail;
	}
	printk(KERN_INFO MYNAM ": Registered with Fusion MPT base driver\n");
	printk(KERN_INFO MYNAM ": /dev/%s @ (major,minor=%d,%d)\n",
			 mptctl_miscdev.name, MISC_MAJOR, mptctl_miscdev.minor);

	/*
	 *  Install our handler
	 */
	++where;
	if ((mptctl_id = mpt_register(mptctl_reply, MPTCTL_DRIVER)) < 0) {
		printk(KERN_ERR MYNAM ": ERROR: Failed to register with Fusion MPT base driver\n");
		misc_deregister(&mptctl_miscdev);
		err = -EBUSY;
		goto out_fail;
	}
	mptctl_taskmgmt_id = mpt_register(mptctl_taskmgmt_reply, MPTCTL_DRIVER);

	if (mpt_reset_register(mptctl_id, mptctl_ioc_reset) == 0) {
		dprintk((KERN_INFO MYNAM ": Registered for IOC reset notifications\n"));
	} else {
		/* FIXME! */
	}

	if (mpt_event_register(mptctl_id, mptctl_event_process) == 0) {
		devtprintk((KERN_INFO MYNAM
		  ": Registered for IOC event notifications\n"));
	}

	return 0;

out_fail:

#ifdef CONFIG_COMPAT
	printk(KERN_ERR MYNAM ": ERROR: Failed to register ioctl32_conversion!"
			" (%d:err=%d)\n", where, err);
	unregister_ioctl32_conversion(MPTIOCINFO);
	unregister_ioctl32_conversion(MPTIOCINFO1);
	unregister_ioctl32_conversion(MPTIOCINFO2);
	unregister_ioctl32_conversion(MPTTARGETINFO);
	unregister_ioctl32_conversion(MPTTEST);
	unregister_ioctl32_conversion(MPTEVENTQUERY);
	unregister_ioctl32_conversion(MPTEVENTENABLE);
	unregister_ioctl32_conversion(MPTEVENTREPORT);
	unregister_ioctl32_conversion(MPTHARDRESET);
	unregister_ioctl32_conversion(MPTCOMMAND32);
	unregister_ioctl32_conversion(MPTFWDOWNLOAD32);
	unregister_ioctl32_conversion(MPTFWDOWNLOADBOOT);
	unregister_ioctl32_conversion(HP_GETHOSTINFO);
	unregister_ioctl32_conversion(HP_GETTARGETINFO);

	unregister_ioctl32_conversion(MPTDIAGREGISTER);
	unregister_ioctl32_conversion(MPTDIAGRELEASE);
	unregister_ioctl32_conversion(MPTDIAGUNREGISTER);
	unregister_ioctl32_conversion(MPTDIAGQUERY);
	unregister_ioctl32_conversion(MPTDIAGREADBUFFER);
#if defined(CPQ_CIM)
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_DRIVER_INFO);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_CNTLR_CONFIG);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_CNTLR_STATUS);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_SCSI_ADDRESS);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_DEVICE_ADDRESS);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_PHY_INFO);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_SATA_SIGNATURE);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_LINK_ERRORS);
	unregister_ioctl32_conversion(CC_CSMI_SAS_SMP_PASSTHRU);
	unregister_ioctl32_conversion(CC_CSMI_SAS_SSP_PASSTHRU);
	unregister_ioctl32_conversion(CC_CSMI_SAS_FIRMWARE_DOWNLOAD);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_INFO);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_CONFIG);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_FEATURES);
	unregister_ioctl32_conversion(CC_CSMI_SAS_SET_RAID_CONTROL);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_ELEMENT);
	unregister_ioctl32_conversion(CC_CSMI_SAS_SET_RAID_OPERATION);
	unregister_ioctl32_conversion(CC_CSMI_SAS_SET_PHY_INFO);
	unregister_ioctl32_conversion(CC_CSMI_SAS_STP_PASSTHRU);
	unregister_ioctl32_conversion(CC_CSMI_SAS_TASK_MANAGEMENT);
	unregister_ioctl32_conversion(CC_CSMI_SAS_PHY_CONTROL);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_CONNECTOR_INFO);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_LOCATION);
#endif /* CPQ_CIM */
#endif /* CONFIG_COMPAT */

	mpt_device_driver_deregister(MPTCTL_DRIVER);

	return err;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void mptctl_exit(void)
{
	misc_deregister(&mptctl_miscdev);
	printk(KERN_INFO MYNAM ": Deregistered /dev/%s @ (major,minor=%d,%d)\n",
			 mptctl_miscdev.name, MISC_MAJOR, mptctl_miscdev.minor);

	/* De-register reset handler from base module */
	mpt_reset_deregister(mptctl_id);
	dprintk((KERN_INFO MYNAM ": Deregistered for IOC reset notifications\n"));

	mpt_event_deregister(mptctl_id);
	dprintk((KERN_INFO MYNAM ": Deregistered for IOC event notifications\n"));

	mpt_deregister(mptctl_taskmgmt_id);
	/* De-register callback handler from base module */
	mpt_deregister(mptctl_id);
	printk(KERN_INFO MYNAM ": Deregistered from Fusion MPT base driver\n");

        mpt_device_driver_deregister(MPTCTL_DRIVER);

#ifdef CONFIG_COMPAT
	unregister_ioctl32_conversion(MPTIOCINFO);
	unregister_ioctl32_conversion(MPTIOCINFO1);
	unregister_ioctl32_conversion(MPTIOCINFO2);
	unregister_ioctl32_conversion(MPTTARGETINFO);
	unregister_ioctl32_conversion(MPTTEST);
	unregister_ioctl32_conversion(MPTEVENTQUERY);
	unregister_ioctl32_conversion(MPTEVENTENABLE);
	unregister_ioctl32_conversion(MPTEVENTREPORT);
	unregister_ioctl32_conversion(MPTHARDRESET);
	unregister_ioctl32_conversion(MPTCOMMAND32);
	unregister_ioctl32_conversion(MPTFWDOWNLOAD32);
	unregister_ioctl32_conversion(MPTFWDOWNLOADBOOT);
	unregister_ioctl32_conversion(HP_GETHOSTINFO);
	unregister_ioctl32_conversion(HP_GETTARGETINFO);

	unregister_ioctl32_conversion(MPTDIAGREGISTER);
	unregister_ioctl32_conversion(MPTDIAGRELEASE);
	unregister_ioctl32_conversion(MPTDIAGUNREGISTER);
	unregister_ioctl32_conversion(MPTDIAGQUERY);
	unregister_ioctl32_conversion(MPTDIAGREADBUFFER);
#if defined(CPQ_CIM)
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_DRIVER_INFO);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_CNTLR_CONFIG);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_CNTLR_STATUS);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_SCSI_ADDRESS);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_DEVICE_ADDRESS);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_PHY_INFO);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_SATA_SIGNATURE);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_LINK_ERRORS);
	unregister_ioctl32_conversion(CC_CSMI_SAS_SMP_PASSTHRU);
	unregister_ioctl32_conversion(CC_CSMI_SAS_SSP_PASSTHRU);
	unregister_ioctl32_conversion(CC_CSMI_SAS_FIRMWARE_DOWNLOAD);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_INFO);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_CONFIG);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_FEATURES);
	unregister_ioctl32_conversion(CC_CSMI_SAS_SET_RAID_CONTROL);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_RAID_ELEMENT);
	unregister_ioctl32_conversion(CC_CSMI_SAS_SET_RAID_OPERATION);
	unregister_ioctl32_conversion(CC_CSMI_SAS_SET_PHY_INFO);
	unregister_ioctl32_conversion(CC_CSMI_SAS_STP_PASSTHRU);
	unregister_ioctl32_conversion(CC_CSMI_SAS_TASK_MANAGEMENT);
	unregister_ioctl32_conversion(CC_CSMI_SAS_PHY_CONTROL);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_CONNECTOR_INFO);
	unregister_ioctl32_conversion(CC_CSMI_SAS_GET_LOCATION);
#endif /* CPQ_CIM */
#endif /* CONFIG_COMPAT */

}

#if defined(CPQ_CIM)
#include "csmi/csmisas.c"
#endif // CPQ_CIM

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/

module_init(mptctl_init);
module_exit(mptctl_exit);

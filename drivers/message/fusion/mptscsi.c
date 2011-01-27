/*
 *  linux/drivers/message/fusion/mptscsih.c
 *      For use with LSI PCI chip/adapter(s)
 *      running LSI Fusion MPT (Message Passing Technology) firmware.
 *
 *  Copyright (c) 1999-2007 LSI Corporation
 *  (mailto:DL-MPTFusionLinux@lsi.com)
 *
 *  $Id: mptscsih.c,v 1.1.2.4 2003/05/07 14:08:34 Exp $
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
#define my_NAME		"Fusion MPT SCSI Host driver"
#define my_VERSION	MPT_LINUX_VERSION_COMMON
#define MYNAM		"mptscsi"

MODULE_AUTHOR(MODULEAUTHOR);
MODULE_DESCRIPTION(my_NAME);
MODULE_LICENSE("GPL");
MODULE_VERSION(my_VERSION);

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
typedef struct _BIG_SENSE_BUF {
	u8		data[MPT_SENSE_BUFFER_ALLOC];
} BIG_SENSE_BUF;

#define OEM_TLR_COMMAND			0xC2

#define MPT_SCANDV_MAX_RETRIES		(10)

#define MPT_ICFLAG_BUF_CAP	0x01	/* ReadBuffer Read Capacity format */
#define MPT_ICFLAG_ECHO		0x02	/* ReadBuffer Echo buffer format */
#define MPT_ICFLAG_EBOS		0x04	/* ReadBuffer Echo buffer has EBOS */
#define MPT_ICFLAG_PHYS_DISK	0x08	/* Any SCSI IO but do Phys Disk Format */
#define MPT_ICFLAG_TAGGED_CMD	0x10	/* Do tagged IO */
#define MPT_ICFLAG_DID_RESET	0x20	/* Bus Reset occurred with this command */
#define MPT_ICFLAG_RESERVED	0x40	/* Reserved has been issued */

typedef struct _negoparms {
	u8 width;
	u8 offset;
	u8 factor;
	u8 flags;
} NEGOPARMS;

typedef struct _dv_parameters {
	NEGOPARMS	 max;
	NEGOPARMS	 now;
	u8		 cmd;
	u8		 id;
	u16		 pad1;
} DVPARAMETERS;


/*
 *  Other private/forward protos...
 */

static int	SCPNT_TO_LOOKUP_IDX(struct scsi_cmnd *sc);
int		mptscsih_io_done(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf, MPT_FRAME_HDR *r);
static void	mptscsih_report_queue_full(struct scsi_cmnd *sc, SCSIIOReply_t *pScsiReply, SCSIIORequest_t *pScsiReq);
int		mptscsih_taskmgmt_complete(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf, MPT_FRAME_HDR *r);
static int	mptscsih_AddSGE(MPT_ADAPTER *ioc, struct scsi_cmnd *SCpnt,
				 SCSIIORequest_t *pReq, int req_idx);
static void	mptscsih_copy_sense_data(struct scsi_cmnd *sc, MPT_SCSI_HOST *hd, MPT_FRAME_HDR *mf, SCSIIOReply_t *pScsiReply);
static int	mptscsih_tm_pending_wait(MPT_SCSI_HOST * hd);
int		mptscsih_TMHandler(MPT_SCSI_HOST *hd, u8 type, u8 channel, u8 id, u8 lun, int ctx2abort, ulong timeout);
int		mptscsih_ioc_reset(MPT_ADAPTER *ioc, int post_reset);
int		mptscsih_event_process(MPT_ADAPTER *ioc, EventNotificationReply_t *pEvReply);
static void	mptscsih_initTarget(MPT_SCSI_HOST *hd, int bus, int id, u8 lun, char *data, int dlen);
static void	mptscsih_setTargetNegoParms(MPT_SCSI_HOST *hd, VirtDevice *pTarget, char byte56);
static void	mptscsih_no_negotiate(MPT_SCSI_HOST *hd, int id);
static int	mptscsih_writeIOCPage4(MPT_SCSI_HOST *hd, int id, int bus);
int		mptscsih_scandv_complete(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf, MPT_FRAME_HDR *r);
void		mptscsih_InternalCmdTimer_expired(unsigned long data);
void		mptscsih_DVCmdTimer_expired(unsigned long data);
static int	mptscsih_synchronize_cache(MPT_SCSI_HOST *hd, int portnum);

#ifdef MPTSCSIH_ENABLE_DOMAIN_VALIDATION
static int	mptscsih_do_raid(MPT_SCSI_HOST *hd, u8 action, INTERNAL_CMD *io);
static void	mptscsih_domainValidation(void *hd);
static int	mptscsih_is_phys_disk(MPT_ADAPTER *ioc, int channel, int id);
static void	mptscsih_qas_check(MPT_SCSI_HOST *hd, int id);
static int	mptscsih_doDv(MPT_SCSI_HOST *hd, int channel, int id);
static void	mptscsih_post_PendingMF_command(MPT_ADAPTER *ioc);
static void	mptscsih_dv_parms(MPT_SCSI_HOST *hd, DVPARAMETERS *dv,void *pPage);
static MPT_FRAME_HDR * mptscsih_search_PendingMF(MPT_ADAPTER *ioc, struct scsi_cmnd * sc);
static void	mptscsih_fillbuf(char *buffer, int size, int index, int width);
#endif
static void	mpt_IssueTLR(MPT_SCSI_HOST *hd, VirtDevice *pTarget);

void		mptscsih_remove(struct pci_dev *);
void		mptscsih_shutdown(struct device *);

#ifdef CONFIG_PM
int mptscsih_suspend(struct pci_dev *pdev, pm_message_t state);
int mptscsih_resume(struct pci_dev *pdev);
#endif

#define SNS_LEN(scp)	sizeof((scp)->sense_buffer)

#ifdef MPTSCSIH_ENABLE_DOMAIN_VALIDATION
/*
 * Domain Validation task structure
 */
static spinlock_t dvtaskQ_lock = SPIN_LOCK_UNLOCKED;
static int dvtaskQ_active = 0;
#endif


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_add_chain - Place a chain SGE at address pAddr.
 *	@pAddr: virtual address for SGE
 *	@next: nextChainOffset value (u32's)
 *	@length: length of next SGL segment
 *	@dma_addr: Physical address
 *
 *	This routine places a MPT request frame back on the MPT adapter's
 *	FreeQ.
 */
static inline void
mptscsih_add_chain(char *pAddr, u8 next, u16 length, dma_addr_t dma_addr)
{
	if (sizeof(dma_addr_t) == sizeof(u64)) {
		SGEChain64_t *pChain = (SGEChain64_t *) pAddr;
		u32 tmp = dma_addr & 0xFFFFFFFF;

		pChain->Length = cpu_to_le16(length);
		pChain->Flags = MPI_SGE_FLAGS_CHAIN_ELEMENT | mpt_addr_size();

		pChain->NextChainOffset = next;

		pChain->Address.Low = cpu_to_le32(tmp);
		tmp = (u32) ((u64)dma_addr >> 32);
		pChain->Address.High = cpu_to_le32(tmp);
	} else {
		SGEChain32_t *pChain = (SGEChain32_t *) pAddr;
		pChain->Length = cpu_to_le16(length);
		pChain->Flags = MPI_SGE_FLAGS_CHAIN_ELEMENT | mpt_addr_size();
		pChain->NextChainOffset = next;
		pChain->Address = cpu_to_le32(dma_addr);
	}
} /* mptscsih_add_chain() */

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_getFreeChainBuffer - Function to get a free chain
 *	from the MPT_SCSI_HOST FreeChainQ.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@req_idx: Index of the SCSI IO request frame. (output)
 *
 *	return SUCCESS or FAILED
 */
static inline int
mptscsih_getFreeChainBuffer(MPT_ADAPTER *ioc, int *retIndex)
{
	MPT_FRAME_HDR *chainBuf;
	unsigned long flags;
	int rc;
	int chain_idx;

	dsgprintk((MYIOC_s_INFO_FMT "getFreeChainBuffer called\n",
			ioc->name));
	spin_lock_irqsave(&ioc->FreeQlock, flags);
	if (!list_empty(&ioc->FreeChainQ)) {
		int offset;

		chainBuf = list_entry(ioc->FreeChainQ.next, MPT_FRAME_HDR,
				u.frame.linkage.list);
		list_del(&chainBuf->u.frame.linkage.list);
		offset = (u8 *)chainBuf - (u8 *)ioc->ChainBuffer;
		chain_idx = offset / ioc->req_sz;
		rc = SUCCESS;
		dsgprintk((MYIOC_s_ERR_FMT "getFreeChainBuffer chainBuf=%p ChainBuffer=%p offset=%d chain_idx=%d\n",
			ioc->name, chainBuf, ioc->ChainBuffer, offset, chain_idx));
	} else {
		rc = FAILED;
		chain_idx = MPT_HOST_NO_CHAIN;
		dfailprintk((MYIOC_s_INFO_FMT "getFreeChainBuffer failed\n",
			ioc->name));
	}
	spin_unlock_irqrestore(&ioc->FreeQlock, flags);

	*retIndex = chain_idx;
	return rc;
} /* mptscsih_getFreeChainBuffer() */

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_AddSGE - Add a SGE (plus chain buffers) to the
 *	SCSIIORequest_t Message Frame.
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@SCpnt: Pointer to scsi_cmnd structure
 *	@pReq: Pointer to SCSIIORequest_t structure
 *
 *	Returns ...
 */
static int
mptscsih_AddSGE(MPT_ADAPTER *ioc, struct scsi_cmnd *SCpnt,
		SCSIIORequest_t *pReq, int req_idx)
{
	char 	*psge;
	char	*chainSge;
	struct scatterlist *sg;
	int	 frm_sz;
	int	 sges_left, sg_done;
	int	 chain_idx = MPT_HOST_NO_CHAIN;
	int	 sgeOffset;
	int	 numSgeSlots, numSgeThisFrame;
	u32	 sgflags, sgdir, thisxfer = 0;
	int	 chain_dma_off = 0;
	int	 newIndex;
	int	 ii;
	dma_addr_t v2;
	u32	RequestNB;

	sgdir = le32_to_cpu(pReq->Control) & MPI_SCSIIO_CONTROL_DATADIRECTION_MASK;
	if (sgdir == MPI_SCSIIO_CONTROL_WRITE)  {
		sgdir = MPT_TRANSFER_HOST_TO_IOC;
	} else {
		sgdir = MPT_TRANSFER_IOC_TO_HOST;
	}

	psge = (char *) &pReq->SGL;
	frm_sz = ioc->req_sz;

	/* Map the data portion, if any.
	 * sges_left  = 0 if no data transfer.
	 */
	if ( (sges_left = SCpnt->use_sg) ) {
		sges_left = pci_map_sg(ioc->pcidev,
			       (struct scatterlist *) SCpnt->request_buffer,
 			       SCpnt->use_sg,
			       SCpnt->sc_data_direction);
		if (sges_left == 0)
			return FAILED;
	} else if (SCpnt->request_bufflen) {
		SCpnt->SCp.dma_handle = pci_map_single(ioc->pcidev,
				      SCpnt->request_buffer,
				      SCpnt->request_bufflen,
				      SCpnt->sc_data_direction);
		dsgprintk((MYIOC_s_INFO_FMT "SG: non-SG for %p, len=%d\n",
				ioc->name, SCpnt, SCpnt->request_bufflen));
		ioc->add_sge((char *) &pReq->SGL,
			0xD1000000|MPT_SGE_FLAGS_ADDRESSING|sgdir|SCpnt->request_bufflen,
			SCpnt->SCp.dma_handle);

		return SUCCESS;
	}

	/* Handle the SG case.
	 */
	sg = (struct scatterlist *) SCpnt->request_buffer;
	sg_done  = 0;
	sgeOffset = sizeof(SCSIIORequest_t) - sizeof(SGE_IO_UNION);
	chainSge = NULL;

	/* Prior to entering this loop - the following must be set
	 * current MF:  sgeOffset (bytes)
	 *              chainSge (Null if original MF is not a chain buffer)
	 *              sg_done (num SGE done for this MF)
	 */

nextSGEset:
	numSgeSlots = ((frm_sz - sgeOffset) / (sizeof(u32) + sizeof(dma_addr_t)) );
	numSgeThisFrame = (sges_left < numSgeSlots) ? sges_left : numSgeSlots;

	sgflags = MPT_SGE_FLAGS_SIMPLE_ELEMENT | MPT_SGE_FLAGS_ADDRESSING | sgdir;

	/* Get first (num - 1) SG elements
	 * Skip any SG entries with a length of 0
	 * NOTE: at finish, sg and psge pointed to NEXT data/location positions
	 */
	for (ii=0; ii < (numSgeThisFrame-1); ii++) {
		thisxfer = sg_dma_len(sg);
		if (thisxfer == 0) {
			sg ++; /* Get next SG element from the OS */
			sg_done++;
			continue;
		}

		v2 = sg_dma_address(sg);
		ioc->add_sge(psge, sgflags | thisxfer, v2);

		sg++;		/* Get next SG element from the OS */
		psge += (sizeof(u32) + sizeof(dma_addr_t));
		sgeOffset += (sizeof(u32) + sizeof(dma_addr_t));
		sg_done++;
	}

	if (numSgeThisFrame == sges_left) {
		/* Add last element, end of buffer and end of list flags.
		 */
		sgflags |= MPT_SGE_FLAGS_LAST_ELEMENT |
				MPT_SGE_FLAGS_END_OF_BUFFER |
				MPT_SGE_FLAGS_END_OF_LIST;

		/* Add last SGE and set termination flags.
		 * Note: Last SGE may have a length of 0 - which should be ok.
		 */
		thisxfer = sg_dma_len(sg);

		v2 = sg_dma_address(sg);
		ioc->add_sge(psge, sgflags | thisxfer, v2);
		/*
		sg++;
		psge += (sizeof(u32) + sizeof(dma_addr_t));
		*/
		sgeOffset += (sizeof(u32) + sizeof(dma_addr_t));
		sg_done++;

		if (chainSge) {
			/* The current buffer is a chain buffer,
			 * but there is not another one.
			 * Update the chain element
			 * Offset and Length fields.
			 */
			mptscsih_add_chain((char *)chainSge, 0, sgeOffset, ioc->ChainBufferDMA + chain_dma_off);
		} else {
			/* The current buffer is the original MF
			 * and there is no Chain buffer.
			 */
			pReq->ChainOffset = 0;
			RequestNB = (((sgeOffset - 1) >> ioc->NBShiftFactor)  + 1) & 0x03;
			dsgprintk((MYIOC_s_INFO_FMT
			    "Single Buffer RequestNB=%x, sgeOffset=%d\n", ioc->name, RequestNB, sgeOffset));
			ioc->RequestNB[req_idx] = RequestNB;
		}
	} else {
		/* At least one chain buffer is needed.
		 * Complete the first MF
		 *  - last SGE element, set the LastElement bit
		 *  - set ChainOffset (words) for orig MF
		 *             (OR finish previous MF chain buffer)
		 *  - update MFStructPtr ChainIndex
		 *  - Populate chain element
		 * Also
		 * Loop until done.
		 */

		dsgprintk((MYIOC_s_INFO_FMT "SG: Chain Required! sg done %d\n",
				ioc->name, sg_done));

		/* Set LAST_ELEMENT flag for last non-chain element
		 * in the buffer. Since psge points at the NEXT
		 * SGE element, go back one SGE element, update the flags
		 * and reset the pointer. (Note: sgflags & thisxfer are already
		 * set properly).
		 */
		if (sg_done) {
			u32 *ptmp = (u32 *) (psge - (sizeof(u32) + sizeof(dma_addr_t)));
			sgflags = le32_to_cpu(*ptmp);
			sgflags |= MPT_SGE_FLAGS_LAST_ELEMENT;
			*ptmp = cpu_to_le32(sgflags);
		}

		if (chainSge) {
			/* The current buffer is a chain buffer.
			 * chainSge points to the previous Chain Element.
			 * Update its chain element Offset and Length (must
			 * include chain element size) fields.
			 * Old chain element is now complete.
			 */
			u8 nextChain = (u8) (sgeOffset >> 2);
			sgeOffset += (sizeof(u32) + sizeof(dma_addr_t));
			mptscsih_add_chain((char *)chainSge, nextChain, sgeOffset, ioc->ChainBufferDMA + chain_dma_off);
		} else {
			/* The original MF buffer requires a chain buffer -
			 * set the offset.
			 * Last element in this MF is a chain element.
			 */
			pReq->ChainOffset = (u8) (sgeOffset >> 2);
			RequestNB = (((sgeOffset - 1) >> ioc->NBShiftFactor)  + 1) & 0x03;
			dsgprintk((MYIOC_s_ERR_FMT "Chain Buffer Needed, RequestNB=%x sgeOffset=%d\n", ioc->name, RequestNB, sgeOffset));
			ioc->RequestNB[req_idx] = RequestNB;
		}

		sges_left -= sg_done;


		/* NOTE: psge points to the beginning of the chain element
		 * in current buffer. Get a chain buffer.
		 */
		if ((mptscsih_getFreeChainBuffer(ioc, &newIndex)) == FAILED) {
			dfailprintk((MYIOC_s_INFO_FMT
			    "getFreeChainBuffer FAILED SCSI cmd=%02x (%p)\n",
 			    ioc->name, pReq->CDB[0], SCpnt));
			return FAILED;
		}

		/* Update the tracking arrays.
		 * If chainSge == NULL, update ReqToChain, else ChainToChain
		 */
		if (chainSge) {
			ioc->ChainToChain[chain_idx] = newIndex;
		} else {
			ioc->ReqToChain[req_idx] = newIndex;
		}
		chain_idx = newIndex;
		chain_dma_off = ioc->req_sz * chain_idx;

		/* Populate the chainSGE for the current buffer.
		 * - Set chain buffer pointer to psge and fill
		 *   out the Address and Flags fields.
		 */
		chainSge = (char *) psge;
		dsgprintk((KERN_INFO "  Current buff @ %p (index 0x%x)",
				psge, req_idx));

		/* Start the SGE for the next buffer
		 */
		psge = (char *) (ioc->ChainBuffer + chain_dma_off);
		sgeOffset = 0;
		sg_done = 0;

		dsgprintk((KERN_INFO "  Chain buff @ %p (index 0x%x)\n",
				psge, chain_idx));

		/* Start the SGE for the next buffer
		 */

		goto nextSGEset;
	}

	return SUCCESS;
} /* mptscsih_AddSGE() */

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_io_done - Main SCSI IO callback routine registered to
 *	Fusion MPT (base) driver
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@mf: Pointer to original MPT request frame
 *	@r: Pointer to MPT reply frame (NULL if TurboReply)
 *
 *	This routine is called from mpt.c::mpt_interrupt() at the completion
 *	of any SCSI IO request.
 *	This routine is registered with the Fusion MPT (base) driver at driver
 *	load/init time via the mpt_register() API call.
 *
 *	Returns 1 indicating alloc'd request frame ptr should be freed.
 */
int
mptscsih_io_done(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf, MPT_FRAME_HDR *mr)
{
	struct scsi_cmnd	*sc;
	MPT_SCSI_HOST	*hd;
	SCSIIORequest_t	*pScsiReq;
	SCSIIOReply_t	*pScsiReply;
	u16		 req_idx, req_idx_MR;

	hd = (MPT_SCSI_HOST *) ioc->sh->hostdata;

	req_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
	req_idx_MR = (mr != NULL) ?
	    le16_to_cpu(mr->u.frame.hwhdr.msgctxu.fld.req_idx) : req_idx;
	if ((req_idx != req_idx_MR) ||
	    (mf->u.frame.linkage.arg1 == 0xdeadbeaf)) {
		printk(MYIOC_s_ERR_FMT "Received a mf that was already freed\n",
		    ioc->name);
		printk (MYIOC_s_ERR_FMT
		    "req_idx=%x req_idx_MR=%x mf=%p mr=%p sc=%p\n",
		    ioc->name, req_idx, req_idx_MR, mf, mr, 
		    ioc->ScsiLookup[req_idx_MR]);
		return 0;
	}

	sc = ioc->ScsiLookup[req_idx];
	ioc->ScsiLookup[req_idx] = NULL;
	if (sc == NULL) {
		MPIHeader_t *hdr = (MPIHeader_t *)mf;

		/* Remark: writeSDP1 will use the ScsiDoneCtx
		 * If a SCSI I/O cmd, device disabled by OS and
		 * completion done. Cannot touch sc struct. Just free mem.
		 */
		if (hdr->Function == MPI_FUNCTION_SCSI_IO_REQUEST) {
			printk(MYIOC_s_ERR_FMT "NULL ScsiCmd ptr!\n",
			ioc->name);
			DBG_DUMP_REPLYS_REQUEST_FRAME(ioc, mf)
//			panic ("NULL ScsiCmd ptr panic!\n");
		}

		mpt_freeChainBuffers(ioc, req_idx);
		return 1;
	}
	if ((unsigned char *)mf != sc->host_scribble) {
		dfailprintk((MYIOC_s_WARN_FMT "mf=%p != sc->host_scribble=%p sc=%p!!\n",
		    ioc->name, mf, sc->host_scribble, sc));
		mpt_freeChainBuffers(ioc, req_idx);
		return 1;
	}

	sc->result = DID_OK << 16;		/* Set default reply as OK */
	pScsiReq = (SCSIIORequest_t *) mf;
	pScsiReply = (SCSIIOReply_t *) mr;

	if (pScsiReply == NULL) {
		dmfprintk((MYIOC_s_WARN_FMT
			"Trbo mf=%p sc=%p idx=%04x\n",
			ioc->name, mf, sc, req_idx));
		/* special context reply handling */
		;
	} else {
		u32	 xfer_cnt;
		u16	 ioc_status;
		u8	 scsi_state, scsi_status;
#ifdef MPT_DEBUG_ERROR
		u8	 ii, skey, asc, ascq;
#endif
		struct _MPT_DEVICE	*pMptTarget;
		VirtDevice	*pTarget;
		int	 bus, id;

		dmfprintk((MYIOC_s_WARN_FMT
			"Addr mf=%p sc=%p idx=%04x mr=%p\n",
			ioc->name, mf, sc, req_idx, mr));

		ioc_status = le16_to_cpu(pScsiReply->IOCStatus) & MPI_IOCSTATUS_MASK;
		scsi_state = pScsiReply->SCSIState;
		scsi_status = pScsiReply->SCSIStatus;
		xfer_cnt = le32_to_cpu(pScsiReply->TransferCount);
		sc->resid = sc->request_bufflen - xfer_cnt;

		bus = pScsiReq->Bus;
		id = pScsiReq->TargetID;
		pMptTarget = ioc->Target_List[bus];
		pTarget = (VirtDevice *)pMptTarget->Target[id];

		/*
		 *  if we get a data underrun indication, yet no data was
		 *  transferred and the SCSI status indicates that the
		 *  command was never started, change the data underrun
		 *  to success
		 */
		if (ioc_status == MPI_IOCSTATUS_SCSI_DATA_UNDERRUN && xfer_cnt == 0 &&
		    (scsi_status == MPI_SCSI_STATUS_BUSY ||
		     scsi_status == MPI_SCSI_STATUS_RESERVATION_CONFLICT ||
		     scsi_status == MPI_SCSI_STATUS_TASK_SET_FULL)) {
			ioc_status = MPI_IOCSTATUS_SUCCESS;
		}

#ifdef MPT_DEBUG_ERR
		if (ioc_status != MPI_IOCSTATUS_SCSI_DEVICE_NOT_THERE) {	/* 0x0043 */
			derrprintk((KERN_NOTICE "Reply ha=%d id=%d lun=%d:\n"
				"IOCStatus=%04x SCSIState=%02x SCSIStatus=%02x\n"
				"resid=%d bufflen=%d xfer_cnt=%d\n",
				ioc->id, pScsiReq->TargetID, pScsiReq->LUN[1],
				ioc_status, scsi_state, scsi_status, sc->resid,
				sc->request_bufflen, xfer_cnt));
		}
#endif

		if (scsi_state & MPI_SCSI_STATE_AUTOSENSE_VALID) {
			mptscsih_copy_sense_data(sc, hd, mf, pScsiReply);
#ifdef MPT_DEBUG_ERROR
			skey = sc->sense_buffer[2];
			asc  = sc->sense_buffer[12];
			ascq = sc->sense_buffer[13];
			derrprintk((MYIOC_s_WARN_FMT
				"id=%d SenseKey:ASC:ASCQ = (%x:%02x:%02x) CDB:\n",
				ioc->name, pScsiReq->TargetID, 
				skey, asc, ascq));
 
			for (ii=0; ii<pScsiReq->CDBLength; ii++) {
				printk("%02x ", pScsiReq->CDB[ii]);
			}
			printk("\n");
#endif
		} else if (scsi_state & MPI_SCSI_STATE_RESPONSE_INFO_VALID &&
		    pScsiReply->ResponseInfo) {
			printk(KERN_NOTICE "ha=%d id=%d lun=%d: "
			"FCP_ResponseInfo=%08xh\n",
			ioc->id, pScsiReq->TargetID, pScsiReq->LUN[1],
			le32_to_cpu(pScsiReply->ResponseInfo));
		}

		switch(ioc_status) {
		case MPI_IOCSTATUS_BUSY:			/* 0x0002 */
			/* CHECKME!
			 * Maybe: DRIVER_BUSY | SUGGEST_RETRY | DID_SOFT_ERROR (retry)
			 * But not: DID_BUS_BUSY lest one risk
			 * killing interrupt handler:-(
			 */
			sc->result = SAM_STAT_BUSY;
#ifdef MPT_DEBUG_FAIL
			derrprintk((MYIOC_s_ERR_FMT
				"id=%d MPI_IOCSTATUS_BUSY\n",
				ioc->name, pScsiReq->TargetID)); 
//			panic ("IOCSTATUS_BUSY!!!!!\n");
#endif
			break;

		case MPI_IOCSTATUS_SCSI_INVALID_BUS:		/* 0x0041 */
		case MPI_IOCSTATUS_SCSI_INVALID_TARGETID:	/* 0x0042 */
			sc->result = DID_BAD_TARGET << 16;
			break;

		case MPI_IOCSTATUS_SCSI_DEVICE_NOT_THERE:	/* 0x0043 */
			/* Spoof to SCSI Selection Timeout! */
			sc->result = DID_NO_CONNECT << 16;

			if ( ioc->bus_type == SPI ) {
				if (hd->sel_timeout[id] < 0xFFFF)
					hd->sel_timeout[pScsiReq->TargetID]++;
			}

			if ( pTarget ) {
				if (pTarget->tflags & MPT_TARGET_FLAGS_LED_ON) {
					MPT_FRAME_HDR		*mf;
					SEPRequest_t *SEPMsg;
					/* Get a MF for this command.
	 				*/
					if ((mf = mpt_get_msg_frame(ioc->InternalCtx, ioc)) == NULL) {
						dfailprintk((MYIOC_s_WARN_FMT "%s: no msg frames!!\n",
						    ioc->name,__FUNCTION__));
					} else {
						SEPMsg = (SEPRequest_t *)mf;
						SEPMsg->Function = MPI_FUNCTION_SCSI_ENCLOSURE_PROCESSOR;
						SEPMsg->Bus = pTarget->bus;
						SEPMsg->TargetID = pTarget->id;
						SEPMsg->Action = MPI_SEP_REQ_ACTION_WRITE_STATUS;
						SEPMsg->SlotStatus = MPI_SEP_REQ_SLOTSTATUS_UNCONFIGURED;
						pTarget->tflags &= ~MPT_TARGET_FLAGS_LED_ON;
						devtprintk((MYIOC_s_WARN_FMT "Sending SEP UNCONFIGURED cmd id=%d bus=%d\n",
							ioc->name, SEPMsg->TargetID, SEPMsg->Bus));
						mpt_put_msg_frame(ioc->DoneCtx, ioc, mf);
					}
				}
			}
			break;

		case MPI_IOCSTATUS_SCSI_TASK_TERMINATED:	/* 0x0048 */
			/* DID_RESET causes a retry but does not bump the 
			 * retries counter in the sc structure */
			sc->result = DID_RESET << 16;
			dreplyprintk((MYIOC_s_WARN_FMT "TASK_TERMINATED: "
				"id=%d "
				"IOCStatus=%04x SCSIState=%02x\n"
				"SCSIStatus=%02x "
				"sc->result=%08x retries=%d sc=%p\n",
				ioc->name, pScsiReq->TargetID, 
				le16_to_cpu(pScsiReply->IOCStatus),
				scsi_state, 
				scsi_status, sc->result, 
				sc->retries, sc));
			break;

		case MPI_IOCSTATUS_SCSI_IOC_TERMINATED:		/* 0x004B */
			if ( ioc->bus_type == SAS ) {
				u16	 status = le16_to_cpu(pScsiReply->IOCStatus);
				u32	 log_info = le32_to_cpu(mr->u.reply.IOCLogInfo);
// 				sc->result = DID_RESET << 16;
				sc->result = DID_SOFT_ERROR << 16;
				if (status & MPI_IOCSTATUS_FLAG_LOG_INFO_AVAILABLE) {
					if ((log_info & 0xFFFF0000) == 
						SAS_LOGINFO_NEXUS_LOSS) {
						sc->result = (DID_BUS_BUSY << 16);
					}
				}
				derrprintk((KERN_NOTICE "IOC_TERMINATED: "
					"ha=%d id=%d lun=%d "
					"IOCStatus=%04x SCSIState=%02x\n"
					"SCSIStatus=%02x LogInfo=%08x "
					"sc->result=%08x sc=%p\n",
					ioc->id, pScsiReq->TargetID, 
					pScsiReq->LUN[1], status, scsi_state, 
					scsi_status, log_info, sc->result, sc));
				break;	
			}  /* allow non-SAS & non-NEXUS_LOSS to drop into below code */
		case MPI_IOCSTATUS_SCSI_EXT_TERMINATED:		/* 0x004C */
			/* Linux handles an unsolicited DID_RESET better
			 * than an unsolicited DID_ABORT.
			 */
			sc->result = DID_RESET << 16;

			/* GEM Workaround. */
			if (ioc->bus_type == SPI)
				mptscsih_no_negotiate(hd, sc->device->id);
			break;

		case MPI_IOCSTATUS_SCSI_RESIDUAL_MISMATCH:	/* 0x0049 */
/* Larry Stephens FC cable break fix from 2.05.15 driver is commented out June 30, 2005 */
#if 0 
			if ( xfer_cnt >= sc->underflow ) {
				/* Sufficient data transfer occurred */
				sc->result = (DID_OK << 16) | scsi_status;
			} else if ( xfer_cnt == 0 ) {
				/* A CRC Error causes this condition; retry */ 
				sc->result = (DRIVER_SENSE << 24) | (DID_OK << 16) | 
					(CHECK_CONDITION << 1);
				sc->sense_buffer[0] = 0x70;
				sc->sense_buffer[2] = NO_SENSE;
				sc->sense_buffer[12] = 0;
				sc->sense_buffer[13] = 0;
			} else {
				sc->result = DID_SOFT_ERROR << 16;
			}
//			derrprintk((KERN_NOTICE "RESIDUAL_MISMATCH: result=%x on id=%d\n", sc->result, sc->target));
			printk("RESIDUAL_MISMATCH: result=%x on id=%d\n", sc->result, sc->device->id);
			break;
#else
			sc->resid = sc->request_bufflen - xfer_cnt;
			if((xfer_cnt==0)||(sc->underflow > xfer_cnt))
				sc->result=DID_SOFT_ERROR << 16;
			else /* Sufficient data transfer occurred */
				sc->result = (DID_OK << 16) | scsi_status;
			derrprintk((KERN_NOTICE 
			    "RESIDUAL_MISMATCH: result=%x on id=%d\n", sc->result, sc->device->id));
			break;
#endif
		case MPI_IOCSTATUS_SCSI_DATA_UNDERRUN:		/* 0x0045 */
			/*
			 *  Do upfront check for valid SenseData and give it
			 *  precedence!
			 */
			sc->result = (DID_OK << 16) | scsi_status;

			if (!(scsi_state & MPI_SCSI_STATE_AUTOSENSE_VALID)) {

				/*
				 * For an Errata on LSI53C1030
				 * When the length of request data
				 * and transfer data are different
				 * with result of command (READ or VERIFY),
				 * DID_SOFT_ERROR is set.
				 */
				if (ioc->bus_type == SPI && pTarget &&
		 			(pTarget->inq_data[0] == TYPE_DISK)){
					if (pScsiReq->CDB[0] == READ_6  ||
					    pScsiReq->CDB[0] == READ_10 ||
					    pScsiReq->CDB[0] == READ_12 ||
					    pScsiReq->CDB[0] == READ_16 ||
					    pScsiReq->CDB[0] == VERIFY  ||
					    pScsiReq->CDB[0] == VERIFY_16) {
						if (sc->request_bufflen !=
						    xfer_cnt) {
						    sc->result = DID_SOFT_ERROR << 16;
						    printk(KERN_WARNING "Errata"
						    "on LSI53C1030 occurred. sc->request_bufflen=0x%02x, "
						    "xfer_cnt=0x%02x\n", sc->request_bufflen, xfer_cnt);
						}
					}
				}

				if (xfer_cnt < sc->underflow) {
					if (scsi_status == SAM_STAT_BUSY)
						sc->result = SAM_STAT_BUSY;
					else
						sc->result = DID_SOFT_ERROR << 16;
				}
				if (scsi_state & (MPI_SCSI_STATE_AUTOSENSE_FAILED | MPI_SCSI_STATE_NO_SCSI_STATUS)) {
					/* What to do?
				 	*/
					sc->result = DID_SOFT_ERROR << 16;
				}
				else if (scsi_state & MPI_SCSI_STATE_TERMINATED) {
					/*  Not real sure here either...  */
					sc->result = DID_RESET << 16;
				}
			}

			/* Report Queue Full
			 */
			if (scsi_status == MPI_SCSI_STATUS_TASK_SET_FULL)
				mptscsih_report_queue_full(sc, pScsiReply, pScsiReq);

			break;

		case MPI_IOCSTATUS_SCSI_DATA_OVERRUN:		/* 0x0044 */
			sc->resid=0;
		case MPI_IOCSTATUS_SCSI_RECOVERED_ERROR:	/* 0x0040 */
		case MPI_IOCSTATUS_SUCCESS:			/* 0x0000 */
			if (scsi_status == MPI_SCSI_STATUS_BUSY)
				sc->result = (DID_COND_REQUEUE << 16) | scsi_status;
			else
				sc->result = (DID_OK << 16) | scsi_status;
			if (scsi_state == 0) {
				;
			} else if (scsi_state & MPI_SCSI_STATE_AUTOSENSE_VALID) {

				/*
				 * For potential trouble on LSI53C1030. (date:2007.xx.)
				 * It is checked whether the length of request data is equal to
				 * the length of transfer and residual.
				 * MEDIUM_ERROR is set by incorrect data.
				 */
				if (ioc->bus_type == SPI && pTarget &&
		 			(pTarget->inq_data[0] == TYPE_DISK)){
					if (sc->sense_buffer[2] & 0x20) {
					    u32	 difftransfer;
					    difftransfer =
					    sc->sense_buffer[3] << 24 |
					    sc->sense_buffer[4] << 16 |
					    sc->sense_buffer[5] << 8 |
					    sc->sense_buffer[6];
					    if ((sc->sense_buffer[3] & 0x80) == 0x80) {
						if (sc->request_bufflen != xfer_cnt) {
						    sc->sense_buffer[2] = MEDIUM_ERROR;
						    sc->sense_buffer[12] = 0xff;
						    sc->sense_buffer[13] = 0xff;
						    printk(KERN_WARNING "Errata on "
						    "LSI53C1030 occurred. sc->request_bufflen=0x%02x,"
						    "xfer_cnt=0x%02x\n" ,sc->request_bufflen, xfer_cnt);
						}
					} else {
						if (sc->request_bufflen != xfer_cnt + difftransfer) {
						    sc->sense_buffer[2] = MEDIUM_ERROR;
						    sc->sense_buffer[12] = 0xff;
						    sc->sense_buffer[13] = 0xff;
						    printk(KERN_WARNING "Errata on "
						    "LSI53C1030 occurred. sc->request_bufflen=0x%02x,"
						    " xfer_cnt=0x%02x, difftransfer=0x%02x\n",
						    sc->request_bufflen , xfer_cnt, difftransfer);
						}
						}
					}
				}
				/*
				 * If running against circa 200003dd 909 MPT f/w,
				 * may get this (AUTOSENSE_VALID) for actual TASK_SET_FULL
				 * (QUEUE_FULL) returned from device! --> get 0x0000?128
				 * and with SenseBytes set to 0.
				 */
				if (pScsiReply->SCSIStatus == MPI_SCSI_STATUS_TASK_SET_FULL)
					mptscsih_report_queue_full(sc, pScsiReply, pScsiReq);

			}
			else if (scsi_state &
			         (MPI_SCSI_STATE_AUTOSENSE_FAILED | MPI_SCSI_STATE_NO_SCSI_STATUS)
			   ) {
				/*
				 * What to do?
				 */
				sc->result = DID_SOFT_ERROR << 16;
			}
			else if (scsi_state & MPI_SCSI_STATE_TERMINATED) {
				/*  Not real sure here either...  */
				sc->result = DID_RESET << 16;
			}
			else if (scsi_state & MPI_SCSI_STATE_QUEUE_TAG_REJECTED) {
				/* Device Inq. data indicates that it supports
				 * QTags, but rejects QTag messages.
				 * This command completed OK.
				 *
				 * Not real sure here either so do nothing...  */
			}

			if (sc->result == MPI_SCSI_STATUS_TASK_SET_FULL)
				mptscsih_report_queue_full(sc, pScsiReply, pScsiReq);

			/* Add handling of:
			 * Reservation Conflict, Busy,
			 * Command Terminated, CHECK
			 */
			break;

		case MPI_IOCSTATUS_SCSI_PROTOCOL_ERROR:		/* 0x0047 */
			sc->result = DID_SOFT_ERROR << 16;
			break;

		case MPI_IOCSTATUS_INVALID_FUNCTION:		/* 0x0001 */
		case MPI_IOCSTATUS_INVALID_SGL:			/* 0x0003 */
		case MPI_IOCSTATUS_INTERNAL_ERROR:		/* 0x0004 */
		case MPI_IOCSTATUS_RESERVED:			/* 0x0005 */
		case MPI_IOCSTATUS_INSUFFICIENT_RESOURCES:	/* 0x0006 */
		case MPI_IOCSTATUS_INVALID_FIELD:		/* 0x0007 */
		case MPI_IOCSTATUS_INVALID_STATE:		/* 0x0008 */
		case MPI_IOCSTATUS_SCSI_IO_DATA_ERROR:		/* 0x0046 */
		case MPI_IOCSTATUS_SCSI_TASK_MGMT_FAILED:	/* 0x004A */
		default:
			/*
			 * What to do?
			 */
			sc->result = DID_SOFT_ERROR << 16;
			break;

		}	/* switch(ioc_status) */

		if (ioc_status != MPI_IOCSTATUS_SCSI_DATA_UNDERRUN) {
			derrprintk((KERN_NOTICE "ha=%d id=%d lun=%d "
				"IOCStatus=%04x SCSIState=%02x\n"
				"SCSIStatus=%02x "
				"sc->result=%08x sc=%p\n",
				ioc->id, pScsiReq->TargetID, 
				pScsiReq->LUN[1], ioc_status, 
				scsi_state, scsi_status, sc->result,
				sc));
		}
	} /* end of address reply case */

	/* Unmap the DMA buffers, if any. */
	if (sc->use_sg) {
		pci_unmap_sg(ioc->pcidev, (struct scatterlist *) sc->request_buffer,
			    sc->use_sg, sc->sc_data_direction);
	} else if (sc->request_bufflen) {
		pci_unmap_single(ioc->pcidev, sc->SCp.dma_handle,
				sc->request_bufflen, sc->sc_data_direction);
	}

	sc->host_scribble = NULL;
	sc->scsi_done(sc);		/* Issue the command callback */

	/* Free Chain buffers */
	mpt_freeChainBuffers(ioc, req_idx);
	return 1;
}

/*
 *	mptscsih_search_running_cmds - Delete any commands associated
 *		with the specified target and lun. Function called only
 *		when a lun is disable by mid-layer.
 *		Do NOT access the referenced scsi_cmnd structure or
 *		members. Will cause either a paging or NULL ptr error.
 *	@hd: Pointer to a SCSI HOST structure
 *	@id: target id
 *	@lun: lun
 *
 *	Returns: None.
 *
 *	Called from slave_destroy.
 */
static void
mptscsih_search_running_cmds(MPT_SCSI_HOST *hd, uint id, uint lun)
{
	MPT_ADAPTER		*ioc = hd->ioc;
	SCSIIORequest_t	*mf = NULL;
	int		 ii;
	int		 max = ioc->req_depth;
	struct scsi_cmnd *sc;

	dsprintk((KERN_INFO MYNAM ": search_running id %d lun %d max %d\n",
			id, lun, max));

	for (ii=0; ii < max; ii++) {
		if ((sc = ioc->ScsiLookup[ii]) != NULL) {

			mf = (SCSIIORequest_t *)MPT_INDEX_2_MFPTR(ioc, ii);

			dsprintk(( "search_running: found (sc=%p, mf = %p)\n",
					ioc->ScsiLookup[ii], mf));
			if (mf == NULL)
				continue;
			dsprintk(( "search_running: found (sc=%p, mf = %p) id %d, lun %d \n",
					ioc->ScsiLookup[ii], mf, mf->TargetID, mf->LUN[1]));

			if ((mf->TargetID != ((u8)id)) || (mf->LUN[1] != ((u8) lun)))
				continue;

			/* Cleanup
			 */
			ioc->ScsiLookup[ii] = NULL;
			mpt_freeChainBuffers(ioc, ii);
			mpt_free_msg_frame(ioc, (MPT_FRAME_HDR *)mf);
			if ((unsigned char *)mf != sc->host_scribble) {
				continue;
			}
			if (sc->use_sg) {
				pci_unmap_sg(ioc->pcidev,
				(struct scatterlist *) sc->request_buffer,
					sc->use_sg,
					sc->sc_data_direction);
			} else if (sc->request_bufflen) {
				pci_unmap_single(ioc->pcidev,
					sc->SCp.dma_handle,
					sc->request_bufflen,
					sc->sc_data_direction);
			}
			sc->host_scribble = NULL;
			sc->result = DID_NO_CONNECT << 16;
			sc->scsi_done(sc);
		}
	}
	dsprintk((KERN_INFO MYNAM ": search_running id %d lun %d completed\n",
			id, lun));
	return;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_report_queue_full - Report QUEUE_FULL status returned
 *	from a SCSI target device.
 *	@sc: Pointer to scsi_cmnd structure
 *	@pScsiReply: Pointer to SCSIIOReply_t
 *	@pScsiReq: Pointer to original SCSI request
 *
 *	This routine periodically reports QUEUE_FULL status returned from a
 *	SCSI target device.  It reports this to the console via kernel
 *	printk() API call, not more than once every 10 seconds.
 */
static void
mptscsih_report_queue_full(struct scsi_cmnd *sc, SCSIIOReply_t *pScsiReply, SCSIIORequest_t *pScsiReq)
{
	long time = jiffies;
	MPT_SCSI_HOST		*hd;

	if (sc->device == NULL)
		return;
	if (sc->device->host == NULL)
		return;
	if ((hd = (MPT_SCSI_HOST *)sc->device->host->hostdata) == NULL)
		return;

	if (time - hd->last_queue_full > 10 * HZ) {
		dprintk((MYIOC_s_WARN_FMT "Device (%d:%d:%d) reported QUEUE_FULL!\n",
				hd->ioc->name, 0, sc->device->id, sc->device->lun));
		hd->last_queue_full = time;
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mptscsih_sendIOCInit  - send IOC Init
 *	@hd: Pointer to a SCSI Host Structure
 *
 *	Return: -EAGAIN if unable to obtain a Message Frame
 *		or 0 if success.
 *
 *	Remark: We do not wait for a return, just dump and run.
 */
static int
mptscsih_sendIOCInit(MPT_SCSI_HOST *hd)
{
	MPT_ADAPTER		*ioc = hd->ioc;
	IOCInit_t		*pReq;
	MPT_FRAME_HDR		*mf;
	u16			 req_idx;

	/* Get a MF for this command.
	 */
	if ((mf = mpt_get_msg_frame(ioc->DoneCtx, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return -EAGAIN;
	}

	/* Set the request pointer.
	 */
	pReq = (IOCInit_t *)mf;

	req_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
	ioc->RequestNB[req_idx] = 0;

	/* Complete the request frame (same for all requests).
	 */
	pReq->WhoInit = MPI_WHOINIT_HOST_DRIVER;
	pReq->Reserved = 0;
	pReq->ChainOffset = 0;
	pReq->Function = MPI_FUNCTION_IOC_INIT;
	pReq->Flags = 0;
	pReq->MaxDevices = ioc->facts.MaxDevices;
	pReq->MaxBuses = ioc->facts.MaxBuses;
	pReq->MsgFlags = 0;
	pReq->ReplyFrameSize = cpu_to_le16(ioc->reply_sz);
	pReq->Reserved1[0] = 0;
	pReq->Reserved1[1] = 0;
	pReq->HostMfaHighAddr = ioc->facts.CurrentHostMfaHighAddr;
	pReq->SenseBufferHighAddr = ioc->facts.CurrentSenseBufferHighAddr;
	pReq->ReplyFifoHostSignalingAddr = ioc->facts.ReplyFifoHostSignalingAddr;
	if (ioc->facts.Flags & MPI_IOCFACTS_FLAGS_REPLY_FIFO_HOST_SIGNAL) {
		pReq->Flags |= MPI_IOCINIT_FLAGS_REPLY_FIFO_HOST_SIGNAL;
	}
	pReq->HostPageBufferSGE = ioc->facts.HostPageBufferSGE;
	pReq->MsgVersion = cpu_to_le16(MPI_VERSION);
	pReq->HeaderVersion = cpu_to_le16(MPI_HEADER_VERSION);

	drsprintk((MYIOC_s_INFO_FMT "sendIOCInit\n", ioc->name));

	mpt_put_msg_frame(ioc->DoneCtx, ioc, mf);

	return 0;
}

/**
 * mptscsih_reset_bus_noblock
 *
 * Issues RESET_BUS to the specified channel using handshaking method
 *
 * @ioc
 * @channel
 *
 * Returns (0) success
 *         (1) failure
 *
 **/
static int
mptscsih_reset_bus_noblock(MPT_ADAPTER *ioc, u8 channel)
{
	MPT_FRAME_HDR	*mf;
	SCSITaskMgmt_t	*pScsiTm;

	if ((mf = mpt_get_msg_frame(ioc->TaskCtx, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames @%d!!\n",
		    ioc->name,__FUNCTION__, __LINE__));
		return 1;
	}

	/* Format the Request
	 */
	pScsiTm = (SCSITaskMgmt_t *) mf;
	memset (pScsiTm, 0, sizeof(SCSITaskMgmt_t));
	pScsiTm->Bus = channel;
	pScsiTm->Function = MPI_FUNCTION_SCSI_TASK_MGMT;
	pScsiTm->TaskType = MPI_SCSITASKMGMT_TASKTYPE_RESET_BUS;
	pScsiTm->MsgFlags = MPI_SCSITASKMGMT_MSGFLAGS_LIPRESET_RESET_OPTION;

	DBG_DUMP_TM_REQUEST_FRAME(mf);

	if (mpt_send_handshake_request(ioc->TaskCtx, ioc,
	    sizeof(SCSITaskMgmt_t), (u32 *)mf, 10, NO_SLEEP)) {
		mpt_free_msg_frame(ioc, mf);
		dfailprintk((MYIOC_s_WARN_FMT "%s, tm handshake failed @%d!!\n",
		    ioc->name,__FUNCTION__, __LINE__));
		return 1;
	}

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mptscsih_TM_timeout - Call back for timeout on a
 *	task management request.
 *	@data: Pointer to MPT_ADAPTER recast as an unsigned long
 *
 */
void mptscsih_TM_timeout(unsigned long data)
{
	MPT_ADAPTER	*ioc=(MPT_ADAPTER *)data;
	MPT_SCSI_HOST	*hd =(MPT_SCSI_HOST *)ioc->sh->hostdata;
	int		 retval;
	u32              ioc_state;

	dtmprintk((KERN_INFO MYNAM ": %s: mptscsih_TM_timeout: "
		   "TM request timed out!\n", ioc->name));

	/* Delete the timer that triggered this callback.
	 * Remark: DEL_TIMER checks to make sure timer is active
	 * before deleting.
	 */
	del_timer(&ioc->TMtimer);

	mpt_free_msg_frame(ioc, ioc->tmPtr);

	ioc->tmPtr = NULL;

	dtmprintk((MYIOC_s_WARN_FMT "%s: Calling mpt_SendIocReset MUR!\n", 
		ioc->name, __FUNCTION__));
	if ((retval = mpt_SendIocReset(ioc, MPI_FUNCTION_IOC_MESSAGE_UNIT_RESET, NO_SLEEP)) != 0) {
		ioc_state = mpt_GetIocState(ioc, 0);
		dfailprintk((MYIOC_s_WARN_FMT "%s: IOC MUR failed! ioc_state=%08x\n",
			ioc->name, __FUNCTION__, ioc_state));
//		panic ("IOC MUR Failed");
		ioc->ioc_reset_in_progress = 0;

		if ((retval = mpt_HardResetHandler(ioc, NO_SLEEP)) < 0){
			printk(KERN_WARNING "%s: %s: HardResetHandler FAILED!!\n",
				ioc->name, __FUNCTION__);
		} else {
			dtmprintk((MYIOC_s_WARN_FMT "%s: HardResetHandler succeeded!!\n", 
				ioc->name, __FUNCTION__));
		}
	} else {
		dtmprintk((MYIOC_s_WARN_FMT "IOC MUR succeeded\n", ioc->name));
		dtmprintk((MYIOC_s_WARN_FMT "Calling do_ioc_recovery! \n", ioc->name));
		if ((retval = mpt_do_ioc_recovery(ioc, MPT_HOSTEVENT_IOC_RECOVER, NO_SLEEP)) != 0) {
			dfailprintk((MYIOC_s_ERR_FMT "%s: (%d) ioc_recovery failed\n", ioc->name, __FUNCTION__, retval));
		} else {
			dtmprintk((MYIOC_s_WARN_FMT "%s:Successful do_ioc_recovery! \n", ioc->name, __FUNCTION__));
		}
	}
	hd->TM_wait_done = 1;
	wake_up(&hd->TM_waitq);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mptscsih_writeFCPortPage3  - write FC Port Page 3
 *	@hd: Pointer to a SCSI Host Structure
 *	@bus: write FC Port Page 3 for this bus
 *	@id: write FC Port Page 3 for this target ID
 *
 *	Return: -EAGAIN if unable to obtain a Message Frame
 *		or 0 if success.
 *
 *	Remark: We do not wait for a return, write pages sequentially.
 */
static int
mptscsih_writeFCPortPage3(MPT_SCSI_HOST *hd, int bus, int id)
{
	MPT_ADAPTER		*ioc = hd->ioc;
	Config_t		*pReq;
	FCPortPage3_t		*FCPort3;
	MPT_FRAME_HDR		*mf;
	dma_addr_t		 dataDma;
	u16			 req_idx;
	u32			 frameOffset;
	u32			 flagsLength;
	int			 ii;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;

	/* Get a MF for this command.
	 */
	if ((mf = mpt_get_msg_frame(ioc->DoneCtx, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return -EAGAIN;
	}

	/* Set the request and the data pointers.
	 * Place data at end of MF.
	 */
	pReq = (Config_t *)mf;

	req_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
	frameOffset = sizeof(Config_t);

	FCPort3 = (FCPortPage3_t *)((u8 *)mf + frameOffset);
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
	pReq->Header.PageVersion = MPI_FCPORTPAGE3_PAGEVERSION;
	pReq->Header.PageLength = sizeof(FCPortPage3_t) / 4;
	pReq->Header.PageNumber = 3;
       	pReq->Header.PageType = MPI_CONFIG_PAGETYPE_FC_PORT |
				MPI_CONFIG_PAGEATTR_PERSISTENT;
	pReq->PageAddress = cpu_to_le32(MPI_FC_PORT_PGAD_FORM_INDEX |
					id);

	pMptTarget = ioc->Target_List[bus];
	pTarget = pMptTarget->Target[id];

	FCPort3->Header.PageVersion = MPI_FCPORTPAGE3_PAGEVERSION;
	FCPort3->Header.PageLength = sizeof(FCPortPage3_t) / 4;
	FCPort3->Header.PageNumber = 3;
       	FCPort3->Header.PageType = MPI_CONFIG_PAGETYPE_FC_PORT |
				   MPI_CONFIG_PAGEATTR_PERSISTENT;
       	FCPort3->Entry[0].PhysicalIdentifier.WWN.WWPN = pTarget->WWPN;
       	FCPort3->Entry[0].PhysicalIdentifier.WWN.WWNN = pTarget->WWNN;
       	FCPort3->Entry[0].TargetID = id;
       	FCPort3->Entry[0].Bus = bus;
	FCPort3->Entry[0].Flags = cpu_to_le16(MPI_PERSISTENT_FLAGS_ENTRY_VALID);

	/* Add a SGE to the config request.
	 */
	flagsLength = MPT_SGE_FLAGS_SSIMPLE_READ | sizeof(FCPortPage3_t);
	ioc->add_sge((char *)&pReq->PageBufferSGE, flagsLength, dataDma);

	drsprintk((MYIOC_s_INFO_FMT "writeFCPortPage3: bus=%d id=%d\n", 
		ioc->name, bus, id));

	mpt_put_msg_frame(ioc->DoneCtx, ioc, mf);

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_readFCDevicePage0 - returns FC Device Page 0 data
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@bus: bus id
 *	@id: target id
 *	@fcDevicePage: FC Device Page 0 data
 *
 *	Returns count of number bytes copied into @fcDevicePage
 *
 */

int
mptscsih_readFCDevicePage0(MPT_ADAPTER *ioc, u8 bus, u8 id, pFCDevicePage0_t fcDevicePage)
{
	ConfigPageHeader_t	 hdr;
	CONFIGPARMS		 cfg;
	pFCDevicePage0_t	 ppage0_alloc;
	dma_addr_t		 page0_dma;
	int			 data_sz;
	int			 copy_sz=0;
	int			 rc;

	/* Get FCPort Page 0 header */
	hdr.PageVersion = 0;
	hdr.PageLength = 0;
	hdr.PageNumber = 0;
	hdr.PageType = MPI_CONFIG_PAGETYPE_FC_DEVICE;
	cfg.cfghdr.hdr = &hdr;
	cfg.physAddr = -1;
	cfg.action = MPI_CONFIG_ACTION_PAGE_HEADER;
	cfg.dir = 0;

	cfg.pageAddr = (bus << 8) + id + MPI_FC_DEVICE_PGAD_FORM_BUS_TID;
	cfg.timeout = 0;

	if ((rc = mpt_config(ioc, &cfg)) != 0)
		return 0;

	if (hdr.PageLength == 0)
		return 0;

	data_sz = hdr.PageLength * 4;
	rc = -ENOMEM;
	ppage0_alloc = (pFCDevicePage0_t ) pci_alloc_consistent(ioc->pcidev,
	    data_sz, &page0_dma);
	if (ppage0_alloc) {
		memset((u8 *)ppage0_alloc, 0, data_sz);
		cfg.physAddr = page0_dma;
		cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;

		if ((rc = mpt_config(ioc, &cfg)) == 0) {
			/* save the data */
			copy_sz = min_t(int, sizeof(FCDevicePage0_t), data_sz);
			memcpy(fcDevicePage, ppage0_alloc, copy_sz);
		}

		pci_free_consistent(ioc->pcidev, data_sz, (u8 *) ppage0_alloc,
		    page0_dma);
	}

	return copy_sz;
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_remove - Removed scsi devices
 *	@pdev: Pointer to pci_dev structure
 *
 *
 */
void
mptscsih_remove(struct pci_dev *pdev)
{
	MPT_ADAPTER 		*ioc;
	struct Scsi_Host 	*host;
	MPT_SCSI_HOST		*hd;
	int 		 	count;
	unsigned long	 	flags;
	int 			sz1;

	dexitprintk((KERN_INFO MYNAM ": %s called pdev=%p\n",
		__FUNCTION__, pdev));

	if (pdev == NULL) {
		dexitprintk((KERN_INFO MYNAM ": NULL pdev!!!\n"));
		return;
	}

	ioc = pci_get_drvdata(pdev);
	if (ioc == NULL) {
		dexitprintk((KERN_INFO MYNAM ": NULL ioc!!!\n"));
		return;
	}

	host = ioc->sh;
	if (host == NULL) {
		dexitprintk((KERN_INFO MYNAM ": NULL host!!!\n"));
		mpt_detach(pdev);
		return;
	}


	if((hd = (MPT_SCSI_HOST *)host->hostdata) == NULL)
		return;

#ifdef MPTSCSIH_ENABLE_DOMAIN_VALIDATION
	/* Check DV thread active */
	count = 10 * HZ;
	spin_lock_irqsave(&dvtaskQ_lock, flags);
	if (dvtaskQ_active) {
		spin_unlock_irqrestore(&dvtaskQ_lock, flags);
		while(dvtaskQ_active && --count) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(1);
		}
	} else {
		spin_unlock_irqrestore(&dvtaskQ_lock, flags);
	}
	if (!count)
		printk(KERN_ERR MYNAM ": %s: ERROR - DV thread still active!\n",
			ioc->name);
#ifdef MPT_DEBUG_DV
	else
		printk(KERN_ERR MYNAM ": %s: DV thread orig %d, count %d\n", ioc->name, 10 * HZ, count);
#endif
#endif

	dexitprintk((KERN_INFO MYNAM ": %s ioc=%p hd=%p MaxDevices=%d\n", 
		ioc->name, ioc, hd, ioc->facts.MaxDevices));
	mptscsih_shutdown(&pdev->dev);

	dexitprintk((KERN_INFO MYNAM ": %s: calling scsi_remove_host ioc=%p host=%p\n", 
		ioc->name, ioc, host));

	scsi_remove_host(host);
	dexitprintk((KERN_INFO MYNAM ": %s: scsi_remove_host completed\n", ioc->name));

	if (ioc->ScsiLookup != NULL) {
		sz1 = ioc->req_depth * sizeof(void *);
		kfree(ioc->ScsiLookup);
		ioc->ScsiLookup = NULL;
		dprintk((MYIOC_s_INFO_FMT
			"Free'd ScsiLookup (%d) memory\n",
			ioc->name, sz1));
	}

	if (hd->info_kbuf != NULL)
		kfree(hd->info_kbuf);

	/* NULL the Scsi_Host pointer
	 */
	ioc->sh = NULL;

	scsi_host_put(host);

	mpt_detach(pdev);

}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_shutdown - reboot notifier
 *
 */
void
mptscsih_shutdown(struct device * dev)
{
	MPT_ADAPTER 		*ioc = pci_get_drvdata(to_pci_dev(dev));
	struct Scsi_Host 	*host;
	MPT_SCSI_HOST		*hd;

	host = ioc->sh;

	if(!host)
		return;

	hd = (MPT_SCSI_HOST *)host->hostdata;

	dexitprintk((KERN_INFO MYNAM ": %s: ioc=%p hd=%p\n",
		__FUNCTION__, ioc, hd));

	/* Flush the cache of this adapter
	 */
	if(hd != NULL) {
		dexitprintk((KERN_INFO MYNAM ": Calling mptscsih_synchronize_cache for %s\n",
			ioc->name));
		mptscsih_synchronize_cache(hd, 0);
		dexitprintk((KERN_INFO MYNAM ": mptscsih_synchronize_cache for %s completed\n",
			ioc->name));
	}
	dexitprintk((KERN_INFO MYNAM ": %s done: ioc=%p hd=%p\n",
		__FUNCTION__, ioc, hd));
}

#ifdef CONFIG_PM
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_suspend - Fusion MPT scsi driver suspend routine.
 *
 *
 */
int
mptscsih_suspend(struct pci_dev *pdev, pm_message_t state)
{
	mptscsih_shutdown(&pdev->dev);
	return mpt_suspend(pdev,state);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_resume - Fusion MPT scsi driver resume routine.
 *
 *
 */
int
mptscsih_resume(struct pci_dev *pdev)
{
	MPT_ADAPTER 		*ioc = pci_get_drvdata(pdev);
	struct Scsi_Host 	*host = ioc->sh;
	MPT_SCSI_HOST		*hd;

	mpt_resume(pdev);

	if(!host)
		return 0;

	hd = (MPT_SCSI_HOST *)host->hostdata;
	if(!hd)
		return 0;

#ifdef MPTSCSIH_ENABLE_DOMAIN_VALIDATION
/*	{
	unsigned long lflags;
	spin_lock_irqsave(&dvtaskQ_lock, lflags);
	if (!dvtaskQ_active) {
		dvtaskQ_active = 1;
		spin_unlock_irqrestore(&dvtaskQ_lock, lflags);
		INIT_WORK(&dvTaskQ_task,
		  mptscsih_domainValidation, (void *) hd);
		schedule_work(&dvTaskQ_task);
	} else {
		spin_unlock_irqrestore(&dvtaskQ_lock, lflags);
	}
	} */
#endif
	return 0;
}

#endif

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_info - Return information about MPT adapter
 *	@SChost: Pointer to Scsi_Host structure
 *
 *	(linux scsi_host_template.info routine)
 *
 *	Returns pointer to buffer where information was written.
 */
const char *
mptscsih_info(struct Scsi_Host *SChost)
{
	MPT_SCSI_HOST *h;
	int size = 0;

	h = (MPT_SCSI_HOST *)SChost->hostdata;

	if (h) {
		if (h->info_kbuf == NULL)
			if ((h->info_kbuf = kmalloc(0x1000 /* 4Kb */, GFP_KERNEL)) == NULL)
				return h->info_kbuf;
		h->info_kbuf[0] = '\0';

		mpt_print_ioc_summary(h->ioc, h->info_kbuf, &size, 0, 0);
		h->info_kbuf[size-1] = '\0';
	}

	return h->info_kbuf;
}

struct info_str {
	char *buffer;
	int   length;
	int   offset;
	int   pos;
};

static void
mptscsih_copy_mem_info(struct info_str *info, char *data, int len)
{
	if (info->pos + len > info->length)
		len = info->length - info->pos;

	if (info->pos + len < info->offset) {
		info->pos += len;
		return;
	}

	if (info->pos < info->offset) {
	        data += (info->offset - info->pos);
	        len  -= (info->offset - info->pos);
	}

	if (len > 0) {
                memcpy(info->buffer + info->pos, data, len);
                info->pos += len;
	}
}

static int
mptscsih_copy_info(struct info_str *info, char *fmt, ...)
{
	va_list args;
	char buf[81];
	int len;

	va_start(args, fmt);
	len = vsprintf(buf, fmt, args);
	va_end(args);

	mptscsih_copy_mem_info(info, buf, len);
	return len;
}

static int
mptscsih_host_info(MPT_ADAPTER *ioc, char *pbuf, off_t offset, int len)
{
	struct info_str info;

	info.buffer	= pbuf;
	info.length	= len;
	info.offset	= offset;
	info.pos	= 0;

	mptscsih_copy_info(&info, "%s: %s, ", ioc->name, ioc->prod_name);
	mptscsih_copy_info(&info, "%s%08xh, ", MPT_FW_REV_MAGIC_ID_STRING, ioc->facts.FWVersion.Word);
	mptscsih_copy_info(&info, "Ports=%d, ", ioc->facts.NumberOfPorts);
	mptscsih_copy_info(&info, "MaxQ=%d\n", ioc->req_depth);

	return ((info.pos > info.offset) ? info.pos - info.offset : 0);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_proc_info - Return information about MPT adapter
 *
 *	(linux scsi_host_template.info routine)
 *
 * 	buffer: if write, user data; if read, buffer for user
 * 	length: if write, return length;
 * 	offset: if write, 0; if read, the current offset into the buffer from
 * 		the previous read.
 * 	hostno: scsi host number
 *	func:   if write = 1; if read = 0
 */
int
mptscsih_proc_info(struct Scsi_Host *host, char *buffer, char **start, off_t offset,
			int length, int func)
{
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)host->hostdata;
	MPT_ADAPTER	*ioc = hd->ioc;
	int size = 0;

	if (func) {
		/*
		 * write is not supported
		 */
	} else {
		if (start)
			*start = buffer;

		size = mptscsih_host_info(ioc, buffer, offset, length);
	}

	return size;
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
#define ADD_INDEX_LOG(req_ent)	do { } while(0)

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_qcmd - Primary Fusion MPT SCSI initiator IO start routine.
 *	@SCpnt: Pointer to scsi_cmnd structure
 *	@done: Pointer SCSI mid-layer IO completion function
 *
 *	(linux scsi_host_template.queuecommand routine)
 *	This is the primary SCSI IO start routine.  Create a MPI SCSIIORequest
 *	from a linux scsi_cmnd request and send it to the IOC.
 *
 *	Returns 0. (rtn value discarded by linux scsi mid-layer)
 */
int
mptscsih_qcmd(struct scsi_cmnd *SCpnt, void (*done)(struct scsi_cmnd *))
{
	MPT_SCSI_HOST		*hd;
	MPT_ADAPTER		*ioc;
	MPT_FRAME_HDR		*mf;
	SCSIIORequest_t		*pScsiReq;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	unsigned long	 	flags;
	int	 bus, id;
	int	 lun;
	u32	 datalen;
	u32	 scsictl;
	u32	 cmd_len;
	int	 my_idx;
	int	 ii;

	hd = (MPT_SCSI_HOST *) SCpnt->device->host->hostdata;
	ioc = hd->ioc;
	bus = SCpnt->device->channel;
	id = SCpnt->device->id;
	lun = SCpnt->device->lun;
	SCpnt->scsi_done = done;

	spin_lock_irqsave(&ioc->diagLock, flags);
	if (ioc->ioc_reset_in_progress) {
		dfailprintk((MYIOC_s_WARN_FMT "qcmd, SCpnt=%p IOCResetInProgress!!\n",
			     ioc->name, SCpnt));
		spin_unlock_irqrestore(&ioc->diagLock, flags);
		return SCSI_MLQUEUE_HOST_BUSY;
	} else if (ioc->broadcast_aen_busy) {
		dfailprintk((MYIOC_s_WARN_FMT "qcmd, SCpnt=%p broadcast_aen_busy!!\n",
			     ioc->name, SCpnt));
		spin_unlock_irqrestore(&ioc->diagLock, flags);
		return SCSI_MLQUEUE_HOST_BUSY;
	}
	spin_unlock_irqrestore(&ioc->diagLock, flags);

	pMptTarget = ioc->Target_List[bus];
	pTarget = pMptTarget->Target[id];

	if ( pTarget ) {
		if ( lun > pTarget->last_lun ) {
			dsprintk((MYIOC_s_INFO_FMT
				"qcmd: lun=%d > last_lun=%d on id=%d\n",
				ioc->name, lun, pTarget->last_lun, id));
			SCpnt->result = DID_BAD_TARGET << 16;
			SCpnt->scsi_done(SCpnt);
			return 0;
		}
		/* Default to untagged. Once a target structure has been
		 * allocated, use the Inquiry data to determine if device
		 * supports tagged.
	 	*/
		if (pTarget->tflags & MPT_TARGET_FLAGS_Q_YES)
			scsictl = MPI_SCSIIO_CONTROL_SIMPLEQ;
		else
			scsictl = MPI_SCSIIO_CONTROL_UNTAGGED;
	} else {
		scsictl = MPI_SCSIIO_CONTROL_UNTAGGED;
		dioprintk((MYIOC_s_WARN_FMT "qcmd: CDB=%02x id=%d lun=%d Null pTarget, sending Untagged\n",
			ioc->name, SCpnt->cmnd[0], id, lun));
		if (ioc->bus_type == SPI) {
			dnegoprintk(("writeSDP1: id=%d Async/Narrow\n", 
				id));
			mpt_writeSDP1(ioc, 0, id, 0);
		}
	}

#ifdef MPT_DEBUG_REPLY
	if (SCpnt->retries) {
		dreplyprintk((MYIOC_s_WARN_FMT "qcmd, SCpnt=%p retries=%d\n",
			     ioc->name, SCpnt, SCpnt->retries));
	}
#endif

	/*
	 *  Put together a MPT SCSI request...
	 */
	if ((mf = mpt_get_msg_frame(ioc->DoneCtx, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return SCSI_MLQUEUE_HOST_BUSY;
	}

	pScsiReq = (SCSIIORequest_t *) mf;

	my_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);

	ADD_INDEX_LOG(my_idx);

	/*    TUR's being issued with scsictl=0x02000000 (DATA_IN)!
	 *    Seems we may receive a buffer (datalen>0) even when there
	 *    will be no data transfer!  GRRRRR...
	 */
	if (SCpnt->sc_data_direction == DMA_FROM_DEVICE) {
		datalen = SCpnt->request_bufflen;
		scsictl |= MPI_SCSIIO_CONTROL_READ;	/* DATA IN  (host<--ioc<--dev) */
	} else if (SCpnt->sc_data_direction == DMA_TO_DEVICE) {
		datalen = SCpnt->request_bufflen;
		scsictl |= MPI_SCSIIO_CONTROL_WRITE;	/* DATA OUT (host-->ioc-->dev) */
	} else {
		datalen = 0;
		scsictl |= MPI_SCSIIO_CONTROL_NODATATRANSFER;
	}

	/* Use the above information to set up the message frame
	 */
	pScsiReq->TargetID = (u8) id;
	pScsiReq->Bus = (u8) bus;
	pScsiReq->ChainOffset = 0;
	pScsiReq->Function = MPI_FUNCTION_SCSI_IO_REQUEST;
	pScsiReq->CDBLength = SCpnt->cmd_len;
	pScsiReq->SenseBufferLength = MPT_SENSE_BUFFER_SIZE;
	pScsiReq->Reserved = 0;
	pScsiReq->MsgFlags = mpt_msg_flags();
	pScsiReq->LUN[0] = 0;
	pScsiReq->LUN[1] = lun;
	pScsiReq->LUN[2] = 0;
	pScsiReq->LUN[3] = 0;
	pScsiReq->LUN[4] = 0;
	pScsiReq->LUN[5] = 0;
	pScsiReq->LUN[6] = 0;
	pScsiReq->LUN[7] = 0;
	pScsiReq->Control = cpu_to_le32(scsictl);

	/*
	 *  Write SCSI CDB into the message
	 */
	cmd_len = SCpnt->cmd_len;
	for (ii=0; ii < cmd_len; ii++)
		pScsiReq->CDB[ii] = SCpnt->cmnd[ii];

	for (ii=cmd_len; ii < 16; ii++)
		pScsiReq->CDB[ii] = 0;

	/* DataLength */
	pScsiReq->DataLength = cpu_to_le32(datalen);

	/* SenseBuffer low address */
	pScsiReq->SenseBufferLowAddr = cpu_to_le32(ioc->sense_buf_low_dma
					   + (my_idx * MPT_SENSE_BUFFER_ALLOC));

	/* Now add the SG list
	 * Always have a SGE even if null length.
	 */
	if (datalen == 0) {
		/* Add a NULL SGE */
		ioc->add_sge((char *)&pScsiReq->SGL, MPT_SGE_FLAGS_SSIMPLE_READ | 0,
			(dma_addr_t) -1);
	} else {
		/* Add a 32 or 64 bit SGE */
		if (mptscsih_AddSGE(ioc, SCpnt, pScsiReq, my_idx) != SUCCESS) {
			mpt_freeChainBuffers(ioc, my_idx);
			mpt_free_msg_frame(ioc, mf);
			return SCSI_MLQUEUE_HOST_BUSY;
		}
	}

	SCpnt->host_scribble = (unsigned char *)mf;

	if (ioc->bus_type == SPI &&
		ioc->spi_data.dvStatus[id] & MPT_SCSICFG_DV_IN_PROGRESS) {
		spin_lock_irqsave(&ioc->PendingMFlock, flags);
		ioc->PendingMF = mf;
		ioc->PendingSCpnt = SCpnt;
		spin_unlock_irqrestore(&ioc->PendingMFlock, flags);
		dpendprintk((KERN_INFO " qcmd: %s: DV In Progress id=%d mf=%p sc=%p into PendingMF\n",
			ioc->name, id, mf, SCpnt));
		DBG_DUMP_REQUEST_FRAME(ioc, mf)
//		mod_timer(&SCpnt->eh_timeout, jiffies + 40 * HZ);
		return 0;
	}

	ioc->ScsiLookup[my_idx] = SCpnt;
	mpt_put_msg_frame(ioc->DoneCtx, ioc, mf);
	dmfprintk((MYIOC_s_WARN_FMT "qcmd mf=%p sc=%p idx=%04x\n",
			ioc->name, mf, SCpnt, my_idx));
	DBG_DUMP_REQUEST_FRAME(ioc, mf)
	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	Reset Handling
 */

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_IssueTaskMgmt - Generic send Task Management function.
 *	@hd: Pointer to MPT_SCSI_HOST structure
 *	@type: Task Management type
 *	@id: Logical Target ID for reset (if appropriate)
 *	@lun: Logical Unit for reset (if appropriate)
 *	@ctx2abort: Context for the task to be aborted (if appropriate)
 *
 *	Remark: _HardResetHandler can be invoked from an interrupt thread (timer)
 *	or a non-interrupt thread.  In the former, must not call schedule().
 *
 *	Not all fields are meaningfull for all task types.
 *
 *	Returns 0 for SUCCESS, -999 for "no msg frames",
 *	else other non-zero value returned.
 */
int
mptscsih_IssueTaskMgmt(MPT_SCSI_HOST *hd, u8 type, u8 bus, u8 id, u8 lun, int ctx2abort, ulong timeout)
{
	MPT_ADAPTER		*ioc = hd->ioc;
	MPT_FRAME_HDR	*mf;
	SCSITaskMgmt_t	*pScsiTm;
	int		 ii;
	int		 retval;
	u32              ioc_state;
	unsigned long	 flags;

	/* Return Fail to calling function if no message frames available.
	 */
	if ((mf = mpt_get_msg_frame(ioc->TaskCtx, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return FAILED;
	}
	dtmprintk((MYIOC_s_WARN_FMT "IssueTaskMgmt request @ %p\n",
			ioc->name, mf));

	/* Format the Request
	 */
	pScsiTm = (SCSITaskMgmt_t *) mf;
	pScsiTm->TargetID = id;
	pScsiTm->Bus = bus;
	pScsiTm->ChainOffset = 0;
	pScsiTm->Function = MPI_FUNCTION_SCSI_TASK_MGMT;

	pScsiTm->Reserved = 0;
	pScsiTm->TaskType = type;
	pScsiTm->Reserved1 = 0;
	pScsiTm->MsgFlags = (type == MPI_SCSITASKMGMT_TASKTYPE_RESET_BUS)
                    ? MPI_SCSITASKMGMT_MSGFLAGS_LIPRESET_RESET_OPTION : 0;

	for (ii= 0; ii < 8; ii++) {
		pScsiTm->LUN[ii] = 0;
	}
	pScsiTm->LUN[1] = lun;

	for (ii=0; ii < 7; ii++)
		pScsiTm->Reserved2[ii] = 0;

	pScsiTm->TaskMsgContext = ctx2abort;

	dtmprintk((MYIOC_s_WARN_FMT "IssueTaskMgmt: ctx2abort (0x%08x) type=%d\n",
			ioc->name, ctx2abort, type));

	DBG_DUMP_TM_REQUEST_FRAME((u32 *)pScsiTm);

	hd->TM_wait_done = 0;
	if ((retval = mpt_send_handshake_request(ioc->TaskCtx, ioc,
		sizeof(SCSITaskMgmt_t), (u32*)pScsiTm, timeout, CAN_SLEEP)) != 0) {
		dfailprintk((MYIOC_s_WARN_FMT "%s: send_handshake FAILED!\n", 
			ioc->name, __FUNCTION__));
		mpt_free_msg_frame(ioc, mf);

		dtmprintk((MYIOC_s_WARN_FMT "Calling mpt_SendIocReset MUR!\n", 
			ioc->name));
		if ((retval = mpt_SendIocReset(ioc, MPI_FUNCTION_IOC_MESSAGE_UNIT_RESET, CAN_SLEEP)) != 0) {
			ioc_state = mpt_GetIocState(ioc, 0);
			dfailprintk((MYIOC_s_WARN_FMT "IOC MUR failed! ioc_state=%08x\n", ioc->name, ioc_state));
//			panic ("IOC MUR Failed");
			ioc->ioc_reset_in_progress = 0;

			if ((retval = mpt_HardResetHandler(ioc, CAN_SLEEP)) < 0){
				printk((KERN_WARNING " HardResetHandler FAILED!!\n"));			}
			else {
				dtmprintk((MYIOC_s_WARN_FMT " HardResetHandler succeeded!!\n", ioc->name));
			}
		} else {
			dtmprintk((MYIOC_s_WARN_FMT "IOC MUR succeeded\n", ioc->name));
			dtmprintk((MYIOC_s_WARN_FMT "Calling do_ioc_recovery! \n", ioc->name));
			if ((retval = mpt_do_ioc_recovery(ioc, MPT_HOSTEVENT_IOC_RECOVER, CAN_SLEEP)) != 0) {
				dfailprintk((MYIOC_s_ERR_FMT "- (%d) ioc_recovery failed\n", ioc->name, retval));
			} else {
				dtmprintk((MYIOC_s_WARN_FMT "Successful do_ioc_recovery! \n", ioc->name));
			}
		}
	} else {
		dtmprintk((MYIOC_s_WARN_FMT "%s: send_handshake SUCCESS!\n", 
			ioc->name, __FUNCTION__));
		if (hd->TM_wait_done == 0) {
			wait_event(hd->TM_waitq, hd->TM_wait_done);
		}
	}
	spin_lock_irqsave(&ioc->FreeQlock, flags);
	hd->tmPending = 0;
	hd->tmState = TM_STATE_NONE;
	spin_unlock_irqrestore(&ioc->FreeQlock, flags);
	return retval;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_TMHandler - Generic handler for SCSI Task Management.
 *	Fall through to mpt_HardResetHandler if: not operational, too many
 *	failed TM requests or handshake failure.
 *
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@type: Task Management type
 *	@bus: Logical Bus for reset (if appropriate)
 *	@id: Logical Target ID for reset (if appropriate)
 *	@lun: Logical Unit for reset (if appropriate)
 *	@ctx2abort: Context for the task to be aborted (if appropriate)
 *
 *	Remark: Currently invoked from a non-interrupt thread (_bh).
 *
 *	Remark: With old EH code, at most 1 SCSI TaskMgmt function per IOC
 *	will be active.
 *
 *	Returns 0 for SUCCESS.
 */
int
mptscsih_TMHandler(MPT_SCSI_HOST *hd, u8 type, u8 bus, u8 id, u8 lun, int ctx2abort, ulong timeout)
{
	MPT_ADAPTER	*ioc;
	int		 rc = -1;
	int		 doTask = 1;
	u32		 ioc_raw_state;
	unsigned long	 flags;

	/* If FW is being reloaded currently, return success to
	 * the calling function.
	 */
	if (hd == NULL)
		return 0;

	ioc = hd->ioc;
	dtmprintk((MYIOC_s_INFO_FMT "TMHandler Entered!\n", ioc->name));

	// SJR - CHECKME - Can we avoid this here?
	// (mpt_HardResetHandler has this check...)
	spin_lock_irqsave(&ioc->diagLock, flags);
	if (ioc->ioc_reset_in_progress) {
		dtmprintk((KERN_INFO MYNAM ": %s: TMHandler failing: "
			   "IOCResetInProgress\n", ioc->name));
		spin_unlock_irqrestore(&ioc->diagLock, flags);
		return FAILED;
	}
	spin_unlock_irqrestore(&ioc->diagLock, flags);

	/*  Wait a fixed amount of time for the TM pending flag to be cleared.
	 *  If we time out and not bus reset, then we return a FAILED status to the caller.
	 *  The call to mptscsih_tm_pending_wait() will set the pending flag if we are
	 *  successful. Otherwise, reload the FW.
	 */
	if (mptscsih_tm_pending_wait(hd) == FAILED) {
		if (type == MPI_SCSITASKMGMT_TASKTYPE_ABORT_TASK) {
			dtmprintk((KERN_INFO MYNAM ": %s: TMHandler abort: "
			   "Timed out waiting for last TM (%d) to complete! \n",
			   ioc->name, hd->tmPending));
			return FAILED;
		} else if (type == MPI_SCSITASKMGMT_TASKTYPE_TARGET_RESET) {
			dtmprintk((KERN_INFO MYNAM ": %s: TMHandler target reset: "
			   "Timed out waiting for last TM (%d) to complete! \n",
			   ioc->name, hd->tmPending));
			return FAILED;
		} else if (type == MPI_SCSITASKMGMT_TASKTYPE_RESET_BUS) {
			dtmprintk((KERN_INFO MYNAM ": %s: TMHandler bus reset: "
			   "Timed out waiting for last TM (%d) to complete! \n",
			   ioc->name, hd->tmPending));
			if (hd->tmPending & (1 << MPI_SCSITASKMGMT_TASKTYPE_RESET_BUS))
				return FAILED;

			doTask = 0;
		}
	} else {
		spin_lock_irqsave(&ioc->FreeQlock, flags);
		hd->tmPending |=  (1 << type);
		spin_unlock_irqrestore(&ioc->FreeQlock, flags);
	}

	/* Is operational?
	 */
	ioc_raw_state = mpt_GetIocState(ioc, 0);

#ifdef MPT_DEBUG_RESET
	if ((ioc_raw_state & MPI_IOC_STATE_MASK) != MPI_IOC_STATE_OPERATIONAL) {
		printk(MYIOC_s_WARN_FMT
			"TMHandler: IOC Not operational(0x%x)!\n",
			ioc->name, ioc_raw_state);
		return FAILED;
//		panic (	"TMHandler: IOC Not operational!");
	}
#endif

	if (doTask && ((ioc_raw_state & MPI_IOC_STATE_MASK) == MPI_IOC_STATE_OPERATIONAL)
				&& !(ioc_raw_state & MPI_DOORBELL_ACTIVE)) {

		/* Issue the Task Mgmt request.
		 */
		if (hd->hard_resets < -1)
			hd->hard_resets++;
		rc = mptscsih_IssueTaskMgmt(hd, type, bus, id, lun, ctx2abort, timeout);
		if (rc) {
			printk(MYIOC_s_INFO_FMT "Issue of TaskMgmt failed!\n", ioc->name);
		} else {
			dtmprintk((MYIOC_s_INFO_FMT "Issue of TaskMgmt Successful!\n", ioc->name));
		}
	}

	/* Only fall through to the HRH if this is a bus reset
	 */
	if ((type == MPI_SCSITASKMGMT_TASKTYPE_RESET_BUS) && (rc ||
		ioc->reload_fw || (ioc->alt_ioc && ioc->alt_ioc->reload_fw))) {
		dtmprintk((MYIOC_s_INFO_FMT "Calling HardReset! \n",
			 ioc->name));
		rc = mpt_HardResetHandler(ioc, CAN_SLEEP);
	}

	/*
	 * Check IOCStatus from TM reply message
	 */
	if (hd->tm_iocstatus == MPI_IOCSTATUS_SUCCESS ||
	    hd->tm_iocstatus == MPI_IOCSTATUS_SCSI_TASK_TERMINATED ||
	    hd->tm_iocstatus == MPI_IOCSTATUS_SCSI_IOC_TERMINATED)
		rc = 0;
	else
		rc = FAILED;

	dtmprintk((MYIOC_s_INFO_FMT "TMHandler rc = %d tm_iocstatus=%08x!\n", 
		ioc->name, rc, hd->tm_iocstatus));

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_abort - Abort linux scsi_cmnd routine, new_eh variant
 *	@SCpnt: Pointer to scsi_cmnd structure, IO to be aborted
 *
 *	(linux scsi_host_template.eh_abort_handler routine)
 *
 *	Returns SUCCESS or FAILED.
 */
int
mptscsih_abort(struct scsi_cmnd * SCpnt)
{
	MPT_SCSI_HOST	*hd;
	MPT_ADAPTER	*ioc;
	MPT_FRAME_HDR	*mf;
	u32		 ctx2abort;
	int		 scpnt_idx;
	int		 retval;
	int		 tm_timeout;
	unsigned long	 flags;
	unsigned long	 sn = SCpnt->serial_number;
#ifdef MPT_DEBUG_TM
	MPT_FRAME_HDR *chain;
	int chain_idx, chain_number, next;
#endif

	spinlock_t	*host_lock = SCpnt->device->host->host_lock;

	/* If we can't locate our host adapter structure, return FAILED status.
	 */
	if ((hd = (MPT_SCSI_HOST *) SCpnt->device->host->hostdata) == NULL) {
		SCpnt->result = DID_RESET << 16;
		SCpnt->scsi_done(SCpnt);
		dfailprintk((KERN_INFO MYNAM ": mptscsih_abort: "
			   "Can't locate host! (sc=%p)\n",
			   SCpnt));
		return FAILED;
	}

	ioc = hd->ioc;
	spin_lock_irqsave(&ioc->diagLock, flags);
	if (ioc->ioc_reset_in_progress) {
		dtmprintk((KERN_INFO ": %s: abort: "
			   "IOCResetInProgress (sc=%p)\n",
			   ioc->name, SCpnt));
		spin_unlock_irqrestore(&ioc->diagLock, flags);
		return FAILED;
	}
	spin_unlock_irqrestore(&ioc->diagLock, flags);

	if (hd->timeouts < -1)
		hd->timeouts++;

	printk(KERN_WARNING MYNAM ": %s: attempting task abort! (sc=%p)\n",
	       ioc->name, SCpnt);
	scsi_print_command(SCpnt);

//	printk(KERN_WARNING MYNAM ": %s: Delaying 30 seconds\n", ioc->name);
//	mdelay (30000);
	/* If this command is pended, then timeout/hang occurred
	 * during DV. Post command and flush pending Q
	 * and then following up with the reset request.
	 */
	if ( (mf = mptscsih_search_PendingMF(ioc, SCpnt)) != NULL) {
		/* Cmd was in PendingMF.
		 */
		dpendprintk((KERN_INFO MYNAM ": %s: mptscsih_abort: "
			   "Command was in PendingMF! (sc=%p)\n",
			   ioc->name, SCpnt));
		return SUCCESS;
	}

	/* Find this command
	 */
	if ((scpnt_idx = SCPNT_TO_LOOKUP_IDX(SCpnt)) < 0) {
		/* Cmd not found in ScsiLookup.
		 * Do OS callback.
		 */
//		SCpnt->result = DID_RESET << 16;
		dtmprintk((KERN_INFO MYNAM ": %s: mptscsih_abort: "
			   "Command not in the active list! (sc=%p)\n",
			   ioc->name, SCpnt));
		return SUCCESS;
	}

	/* Most important!  Set TaskMsgContext to SCpnt's MsgContext!
	 * (the IO to be ABORT'd)
	 *
	 * NOTE: Since we do not byteswap MsgContext, we do not
	 *	 swap it here either.  It is an opaque cookie to
	 *	 the controller, so it does not matter. -DaveM
	 */
	mf = MPT_INDEX_2_MFPTR(ioc, scpnt_idx);
	ctx2abort = mf->u.frame.hwhdr.msgctxu.MsgContext;

	hd->abortSCpnt = SCpnt;

	spin_unlock_irq(host_lock);
	/* set timeout in seconds */
	switch (ioc->bus_type) {
	case FC:
		tm_timeout=40;
		break;
	case SAS:
		tm_timeout=10;
		break;
	case SPI:
	default:
//		tm_timeout=2;
		tm_timeout=10;
		break;
	}
#ifdef MPT_DEBUG_TM
	printk("Abort this Request: sc=%p retries=%d\n", SCpnt, SCpnt->retries);
	DBG_DUMP_REPLYS_REQUEST_FRAME(ioc, mf)
	chain_number = 1;
	chain_idx = ioc->ReqToChain[scpnt_idx];
	while (chain_idx != MPT_HOST_NO_CHAIN) {
		next = ioc->ChainToChain[chain_idx];
		chain = (MPT_FRAME_HDR *) (ioc->ChainBuffer
			+ (chain_idx * ioc->req_sz));
		printk("Chain %d:\n", chain_number++);
		DBG_DUMP_REPLYS_REQUEST_FRAME(ioc, chain)
		chain_idx = next;
	}
#endif
//	panic ("Abort Task panic!!\n");
	retval = mptscsih_TMHandler(hd, MPI_SCSITASKMGMT_TASKTYPE_ABORT_TASK,
		SCpnt->device->channel, SCpnt->device->id, SCpnt->device->lun,
		ctx2abort, tm_timeout);
	spin_lock_irq(host_lock);

	if (ioc->bus_type == FC) {
		if (SCPNT_TO_LOOKUP_IDX(SCpnt) == scpnt_idx &&
		    SCpnt->serial_number == sn) {
			dtmprintk((KERN_INFO MYNAM ": %s: mptscsih_abort: "
			   "scpnt_idx=%08x sn=%lx (sc=%p)\n",
			   ioc->name, scpnt_idx, sn, SCpnt));
			retval = FAILED;
		}
	}

//	panic ("Task Abort completed");
	spin_lock_irqsave(&hd->ioc->FreeQlock, flags);
	hd->tmPending = 0;
	hd->tmState = TM_STATE_NONE;
	spin_unlock_irqrestore(&hd->ioc->FreeQlock, flags);

	if (retval == 0) {
		printk (KERN_WARNING MYNAM ": %s: task abort: SUCCESS (sc=%p)\n",
			ioc->name, SCpnt);
		/* Remove ScsiLookup entry only on TM Success */
		ioc->ScsiLookup[scpnt_idx] = NULL;
		return SUCCESS;
	} else {
		printk (KERN_WARNING MYNAM ": %s: task abort: FAILED (sc=%p)\n",
			ioc->name, SCpnt);
		/* Failed Abort will be followed by a Target Reset */
		return FAILED;
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_dev_reset - Perform a SCSI TARGET_RESET!  new_eh variant
 *	@SCpnt: Pointer to scsi_cmnd structure, IO which reset is due to
 *
 *	(linux scsi_host_template.eh_dev_reset_handler routine)
 *
 *	Returns SUCCESS or FAILED.
 */
int
mptscsih_dev_reset(struct scsi_cmnd * SCpnt)
{
	MPT_SCSI_HOST	*hd;
	MPT_ADAPTER	*ioc;
	int		 id, retval;
	int		 tm_timeout;
	unsigned long	 flags;

	spinlock_t	*host_lock = SCpnt->device->host->host_lock;

	/* If we can't locate our host adapter structure, return FAILED status.
	 */
	if ((hd = (MPT_SCSI_HOST *) SCpnt->device->host->hostdata) == NULL){
		dtmprintk((KERN_INFO MYNAM ": mptscsih_dev_reset: "
			   "Can't locate host! (sc=%p)\n",
			   SCpnt));
		return FAILED;
	}

	ioc = hd->ioc;
	id = SCpnt->device->id;
	spin_lock_irqsave(&ioc->diagLock, flags);
	if (ioc->ioc_reset_in_progress) {
		dtmprintk((KERN_INFO ": %s: target reset: "
			   "IOCResetInProgress (sc=%p)\n",
			   ioc->name, SCpnt));
		spin_unlock_irqrestore(&ioc->diagLock, flags);
		return FAILED;
	}
	spin_unlock_irqrestore(&ioc->diagLock, flags);

	printk(KERN_WARNING MYNAM ": %s: attempting target reset! (sc=%p)\n",
	       ioc->name, SCpnt);
	scsi_print_command(SCpnt);

	spin_unlock_irq(host_lock);
	switch (ioc->bus_type) {
	case FC:
		tm_timeout=40;
		break;
	case SAS:
		tm_timeout=10;
		break;
	case SPI:
	default:
//		tm_timeout=5;
		tm_timeout=10;
		break;
	}
	retval = mptscsih_TMHandler(hd, MPI_SCSITASKMGMT_TASKTYPE_TARGET_RESET,
		SCpnt->device->channel, id, 0, 0, tm_timeout);
	spin_lock_irq(host_lock);
	printk (KERN_WARNING MYNAM ": %s: target reset: %s (sc=%p)\n",
		ioc->name,
		((retval == 0) ? "SUCCESS" : "FAILED" ), SCpnt);

	spin_lock_irqsave(&hd->ioc->FreeQlock, flags);
	hd->tmPending = 0;
	hd->tmState = TM_STATE_NONE;
	spin_unlock_irqrestore(&hd->ioc->FreeQlock, flags);

	if (retval == 0) {
		if (ioc->bus_type == SPI) {
			dnegoprintk(("writeSDP1: id=%d USE_NVRAM\n", 
				id));
			mpt_writeSDP1(ioc, 0, id, MPT_SCSICFG_USE_NVRAM);
		}
		return SUCCESS;
	}
	return FAILED;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_bus_reset - Perform a SCSI BUS_RESET!	new_eh variant
 *	@SCpnt: Pointer to scsi_cmnd structure, IO which reset is due to
 *
 *	(linux scsi_host_template.eh_bus_reset_handler routine)
 *
 *	Returns SUCCESS or FAILED.
 */
int
mptscsih_bus_reset(struct scsi_cmnd * SCpnt)
{
	MPT_SCSI_HOST	*hd;
	MPT_ADAPTER	*ioc;
	int		 retval;
	int		 tm_timeout;
	unsigned long	 flags;

	spinlock_t	*host_lock = SCpnt->device->host->host_lock;

	/* If we can't locate our host adapter structure, return FAILED status.
	 */
	if ((hd = (MPT_SCSI_HOST *) SCpnt->device->host->hostdata) == NULL){
		dtmprintk((KERN_INFO MYNAM ": mptscsih_bus_reset: "
			   "Can't locate host! (sc=%p)\n",
			   SCpnt ) );
		return FAILED;
	}

	ioc = hd->ioc;
	printk(KERN_WARNING MYNAM ": %s: attempting bus reset! (sc=%p)\n",
	       ioc->name, SCpnt);
	scsi_print_command(SCpnt);

	if (hd->timeouts < -1)
		hd->timeouts++;

	/* We are now ready to execute the task management request. */
	spin_unlock_irq(host_lock);
	switch (ioc->bus_type) {
	case FC:
		tm_timeout=40;
		break;
	case SAS:
		tm_timeout=10;
		break;
	case SPI:
	default:
//		tm_timeout=5;
		tm_timeout=10;
		break;
	}
	retval = mptscsih_TMHandler(hd, MPI_SCSITASKMGMT_TASKTYPE_RESET_BUS,
		SCpnt->device->channel, 0, 0, 0, tm_timeout);
	spin_lock_irq(host_lock);

	printk (KERN_WARNING MYNAM ": %s: bus reset: %s (sc=%p)\n",
		ioc->name,
		((retval == 0) ? "SUCCESS" : "FAILED" ), SCpnt);

	spin_lock_irqsave(&hd->ioc->FreeQlock, flags);
	hd->tmPending = 0;
	hd->tmState = TM_STATE_NONE;
	spin_unlock_irqrestore(&hd->ioc->FreeQlock, flags);

	if (retval == 0)
		return SUCCESS;

	return FAILED;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_host_reset - Perform a SCSI host adapter RESET!
 *	new_eh variant
 *	@SCpnt: Pointer to scsi_cmnd structure, IO which reset is due to
 *
 *	(linux scsi_host_template.eh_host_reset_handler routine)
 *
 *	Returns SUCCESS or FAILED.
 */
int
mptscsih_host_reset(struct scsi_cmnd *SCpnt)
{
	MPT_SCSI_HOST *  hd;
	MPT_ADAPTER	*ioc;
	int              status = SUCCESS;
	unsigned long	 flags;

	spinlock_t	*host_lock = SCpnt->device->host->host_lock;

	/*  If we can't locate the host to reset, then we failed. */
	if ((hd = (MPT_SCSI_HOST *) SCpnt->device->host->hostdata) == NULL){
		dtmprintk( ( KERN_INFO MYNAM ": mptscsih_host_reset: "
			     "Can't locate host! (sc=%p)\n",
			     SCpnt ) );
		return FAILED;
	}

	ioc = hd->ioc;
	printk(KERN_WARNING MYNAM ": %s: Attempting host reset! (sc=%p)\n",
	       ioc->name, SCpnt);

	/*  If our attempts to reset the host failed, then return a failed
	 *  status.  The host will be taken off line by the SCSI mid-layer.
	 */
	MPT_HOST_UNLOCK(host_lock);
	if (mpt_HardResetHandler(ioc,
	    	crashdump_mode() ? NO_SLEEP : CAN_SLEEP) < 0) {
		dfailprintk((MYIOC_s_ERR_FMT "host reset: HardResetHandler failed\n", ioc->name));
		status = FAILED;
	} else {
		dtmprintk((MYIOC_s_ERR_FMT "host reset: HardResetHandler succeeded\n", ioc->name));
		status = SUCCESS;
	}

	MPT_HOST_LOCK(host_lock);

	spin_lock_irqsave(&hd->ioc->FreeQlock, flags);
	hd->tmPending = 0;
	hd->tmState = TM_STATE_NONE;
	spin_unlock_irqrestore(&hd->ioc->FreeQlock, flags);

	return status;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* Search the pendingMF for a command with specific index.
 * If found, delete and return mf pointer
 * If not found, return NULL
 */
static MPT_FRAME_HDR *
mptscsih_search_PendingMF(MPT_ADAPTER *ioc, struct scsi_cmnd * sc)
{
	MPT_FRAME_HDR	*mf;
	unsigned long	 flags;
	u16		 req_idx;

	dpendprintk((MYIOC_s_WARN_FMT "%s entered\n", 
		ioc->name, __FUNCTION__));

	spin_lock_irqsave(&ioc->PendingMFlock, flags);
	if ((mf=ioc->PendingMF) == NULL) {
		spin_unlock_irqrestore(&ioc->PendingMFlock, flags);
		return NULL;
	}

	req_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
	if (sc == ioc->ScsiLookup[req_idx]) {
		ioc->PendingMF = NULL;
		spin_unlock_irqrestore(&ioc->PendingMFlock, flags);

		dpendprintk((MYIOC_s_WARN_FMT "%s: found mf=%p\n", 
			ioc->name, __FUNCTION__, mf));
		DBG_DUMP_PENDING_REQUEST_FRAME(ioc, mf)
		/* Free Chain buffers */
		mpt_freeChainBuffers(ioc, req_idx);
		/* Free Message frames */
		mpt_free_msg_frame(ioc, mf);
		ioc->ScsiLookup[req_idx] = NULL;
		sc->result = (DID_RESET << 16);
		sc->host_scribble = NULL;
		sc->scsi_done(sc);	/* Issue the command callback */
		dpendprintk(( "%s Executed scsi_done mf=%p sc=%p\n",
			__FUNCTION__, mf, sc));
		return mf;
	}
	spin_unlock_irqrestore(&ioc->PendingMFlock, flags);
	dpendprintk((MYIOC_s_WARN_FMT "%s exiting mf=%p not in ScsiLookup\n", 
		ioc->name, __FUNCTION__, mf));
	return NULL;
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_tm_pending_wait - wait for pending task management request to
 *		complete.
 *	@hd: Pointer to MPT host structure.
 *
 *	Returns {SUCCESS,FAILED}.
 */
static int
mptscsih_tm_pending_wait(MPT_SCSI_HOST * hd)
{
	MPT_ADAPTER	*ioc = hd->ioc;
	unsigned long  flags;
	int            loop_count = 4 * 10;  /* Wait 10 seconds */
	int            status = FAILED;

	do {
		spin_lock_irqsave(&ioc->FreeQlock, flags);
		if (hd->tmState == TM_STATE_NONE) {
			hd->tmState = TM_STATE_IN_PROGRESS;
			hd->tmPending = 1;
			spin_unlock_irqrestore(&ioc->FreeQlock, flags);
			status = SUCCESS;
			break;
		}
		spin_unlock_irqrestore(&ioc->FreeQlock, flags);
		msleep(250);
	} while (--loop_count);

	return status;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
static void
mptscsih_taskmgmt_response_code(MPT_ADAPTER *ioc, u8 response_code)
{
	char *desc;

	switch (response_code) {
	case MPI_SCSITASKMGMT_RSP_TM_COMPLETE:
		desc = "The task completed.";
		break;
	case MPI_SCSITASKMGMT_RSP_INVALID_FRAME:
		desc = "The IOC received an invalid frame status.";
		break;
	case MPI_SCSITASKMGMT_RSP_TM_NOT_SUPPORTED:
		desc = "The task type is not supported.";
		break;
	case MPI_SCSITASKMGMT_RSP_TM_FAILED:
		desc = "The requested task failed.";
		break;
	case MPI_SCSITASKMGMT_RSP_TM_SUCCEEDED:
		desc = "The task completed successfully.";
		break;
	case MPI_SCSITASKMGMT_RSP_TM_INVALID_LUN:
		desc = "The LUN request is invalid.";
		break;
	case MPI_SCSITASKMGMT_RSP_IO_QUEUED_ON_IOC:
		desc = "The task is in the IOC queue and has not been sent to target.";
		break;
	default:
		desc = "unknown";
		break;
	}
	printk(MYIOC_s_INFO_FMT "Response Code(0x%08x): F/W: %s\n",
		ioc->name, response_code, desc);
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_taskmgmt_complete - Registered with Fusion MPT base driver
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@mf: Pointer to SCSI task mgmt request frame
 *	@mr: Pointer to SCSI task mgmt reply frame
 *
 *	This routine is called from mptbase.c::mpt_interrupt() at the completion
 *	of any SCSI task management request.
 *	This routine is registered with the MPT (base) driver at driver
 *	load/init time via the mpt_register() API call.
 *
 *	Returns 1 indicating alloc'd request frame ptr should be freed.
 */
int
mptscsih_taskmgmt_complete(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf, MPT_FRAME_HDR *mr)
{
	SCSITaskMgmtReply_t	*pScsiTmReply;
	SCSITaskMgmt_t		*pScsiTmReq;
	MPT_SCSI_HOST		*hd;
	unsigned long		 flags;
	u16			 iocstatus = MPI_IOCSTATUS_SUCCESS;
	u8			 tmType;
	u32			 termination_count;

	dtmprintk((MYIOC_s_WARN_FMT "TaskMgmt completed (mf=%p,mr=%p)\n",
			ioc->name, mf, mr));
		/* Depending on the thread, a timer is activated for
		 * the TM request.  Delete this timer on completion of TM.
		 * Decrement count of outstanding TM requests.
		 */
	hd = (MPT_SCSI_HOST *)ioc->sh->hostdata;
	if (ioc->tmPtr) {
		del_timer(&ioc->TMtimer);
		mpt_free_msg_frame(ioc, ioc->tmPtr);
		ioc->tmPtr = NULL;
	}

	hd->tm_response_code = 0;
	
	if (mr == NULL) {
		dtmprintk((MYIOC_s_WARN_FMT "ERROR! TaskMgmt Turbo Reply: Request %p\n",
			ioc->name, mf));
	} else {
		pScsiTmReply = (SCSITaskMgmtReply_t*)mr;
		pScsiTmReq = (SCSITaskMgmt_t*)mf;

		/* Figure out if this was ABORT_TASK, TARGET_RESET, or BUS_RESET! */
		tmType = pScsiTmReq->TaskType;
		hd->tm_response_code = pScsiTmReply->ResponseCode;

		if (ioc->facts.MsgVersion >= MPI_VERSION_01_05 &&
		    pScsiTmReply->ResponseCode)
			mptscsih_taskmgmt_response_code(ioc,
			    pScsiTmReply->ResponseCode);

		termination_count = le32_to_cpu(pScsiTmReply->TerminationCount);

		iocstatus = le16_to_cpu(pScsiTmReply->IOCStatus) & MPI_IOCSTATUS_MASK;
		dtmprintk((MYIOC_s_WARN_FMT "  SCSI TaskMgmt (%d) IOCStatus=%04x IOCLogInfo=%08x TerminationCount=%d\n",
			ioc->name, tmType, iocstatus, le32_to_cpu(pScsiTmReply->IOCLogInfo), termination_count));
		DBG_DUMP_TM_REPLY_FRAME((u32 *)pScsiTmReply);

		/* Error?  (anything non-zero?) */
		if (iocstatus) {

			/* clear flags and continue.
			 */
			if (tmType == MPI_SCSITASKMGMT_TASKTYPE_ABORT_TASK) {
				if (termination_count == 1) {
					iocstatus = MPI_IOCSTATUS_SCSI_TASK_TERMINATED;
					dtmprintk((MYIOC_s_WARN_FMT "  SCSI Abort Task IOCStatus is now %04x\n",
						ioc->name, iocstatus));
				}
				hd->abortSCpnt = NULL;
			}

			/* If an internal command is present
			 * or the TM failed - reload the FW.
			 * FC FW may respond FAILED to an ABORT
			 */
			else if (tmType == MPI_SCSITASKMGMT_TASKTYPE_RESET_BUS) {
				if (iocstatus == MPI_IOCSTATUS_SCSI_TASK_MGMT_FAILED) {
					if (mpt_HardResetHandler(ioc, NO_SLEEP) < 0) {
						printk((KERN_WARNING
							" Firmware Reload FAILED!!\n"));
						dfailprintk((MYIOC_s_ERR_FMT "taskmgmt_complete: HardReset failed\n", ioc->name));
					} else {
						dtmprintk((MYIOC_s_ERR_FMT "taskmgmt_complete: HardReset succeeded\n", ioc->name));
					}
				}
			}
		} else {
			dtmprintk((MYIOC_s_WARN_FMT " TaskMgmt SUCCESS\n", ioc->name));

			hd->abortSCpnt = NULL;

		}
	}

	spin_lock_irqsave(&ioc->FreeQlock, flags);
	hd->tmPending = 0;
	hd->tm_iocstatus = iocstatus;
	hd->tmState = TM_STATE_NONE;
	spin_unlock_irqrestore(&ioc->FreeQlock, flags);

	hd->TM_wait_done = 1;
	wake_up(&hd->TM_waitq);
	return 1;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	This is anyones guess quite frankly.
 */
int
mptscsih_bios_param(struct scsi_device * sdev, struct block_device *bdev,
		sector_t capacity, int geom[])
{
	int		heads;
	int		sectors;
	sector_t	cylinders;
	ulong 		dummy;

	heads = 64;
	sectors = 32;

	dummy = heads * sectors;
	cylinders = capacity;
	sector_div(cylinders,dummy);

	/*
	 * Handle extended translation size for logical drives
	 * > 1Gb
	 */
	if ((ulong)capacity >= 0x200000) {
		heads = 255;
		sectors = 63;
		dummy = heads * sectors;
		cylinders = capacity;
		sector_div(cylinders,dummy);
	}

	/* return result */
	geom[0] = heads;
	geom[1] = sectors;
	geom[2] = cylinders;

	dprintk((KERN_NOTICE
		": bios_param: Id=%i Lun=%i Channel=%i CHS=%i/%i/%i\n",
		sdev->id, sdev->lun,sdev->channel,(int)cylinders,heads,sectors));

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	OS entry point to allow host driver to alloc memory
 *	for each scsi device. Called once per device the bus scan.
 *	Return non-zero if allocation fails.
 *	Init memory once per id (not LUN).
 */
int
mptscsih_slave_alloc(struct scsi_device *device)
{
	struct Scsi_Host	*host = device->host;
	MPT_SCSI_HOST		*hd = (MPT_SCSI_HOST *)host->hostdata;
	MPT_ADAPTER		*ioc = hd->ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
        SpiCfgData		*pSpi;
	uint			bus=device->channel, id=device->id, lun=device->lun;
	int			indexed_lun, lun_index;

	pMptTarget = ioc->Target_List[bus];
	pTarget = pMptTarget->Target[id];

	if (pTarget) {
		dinitprintk((MYIOC_s_ERR_FMT "slave_alloc: pTarget=%p already allocated!\n",
			ioc->name, pTarget));
		goto out;
	}

	pTarget = kmalloc(sizeof(VirtDevice), GFP_KERNEL);
	if (!pTarget) {
		printk(MYIOC_s_ERR_FMT "slave_alloc kmalloc(%zd) FAILED!\n",
			ioc->name, sizeof(VirtDevice));
		return -ENOMEM;
	}

	memset(pTarget, 0, sizeof(VirtDevice));
	if (ioc->bus_type != SPI)
		pTarget->tflags = MPT_TARGET_FLAGS_Q_YES;
	pTarget->ioc = ioc;
	pTarget->id = id;
	pTarget->bus = bus;
	pTarget->last_lun = MPT_LAST_LUN;
	pMptTarget->Target[id] = pTarget;
	if (ioc->raid_data.isRaid & (1 << device->id)) {
		pTarget->raidVolume = 1;
		ddvprintk((KERN_INFO
		    "RAID Volume @ id %d\n", device->id));
	}
	if (ioc->bus_type == SPI) {
		pSpi = &ioc->spi_data;
		pSpi->dvStatus[id] |= (MPT_SCSICFG_NEED_DV |
				       MPT_SCSICFG_DV_NOT_DONE);
	}

out:
	pTarget->num_luns++;

	lun_index = (lun >> 5);  /* 32 luns per lun_index */
	indexed_lun = (lun % 32);
	pTarget->luns[lun_index] |= (1 << indexed_lun);

	dinitprintk((MYIOC_s_WARN_FMT "mptscsih_slave_alloc: bus=%d id=%d lun=%d pTarget=%p num_luns=%d\n",
			ioc->name, bus, id, lun, pTarget, pTarget->num_luns));
	return 0;
}

/*
 *	OS entry point to allow for host driver to free allocated memory
 *	Called if no device present or device being unloaded
 */
void
mptscsih_slave_destroy(struct scsi_device *device)
{
	struct Scsi_Host	*host = device->host;
	MPT_SCSI_HOST		*hd = (MPT_SCSI_HOST *)host->hostdata;
	MPT_ADAPTER		*ioc = hd->ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	uint			bus=device->channel, id=device->id, lun=device->lun;
	int			indexed_lun, lun_index;

	pMptTarget = ioc->Target_List[bus];
	pTarget = pMptTarget->Target[id];
	if (pTarget == NULL) {
		printk(MYIOC_s_WARN_FMT " mptscsih_slave_destroy bus=%d id=%d lun=%d pTarget=%p is NULL\n",
			ioc->name, bus, id, lun, pTarget);
		return;
	}
	dsprintk((MYIOC_s_INFO_FMT " mptscsih_slave_destroy bus=%d id=%d lun=%d type=%x pTarget=%p\n",
			ioc->name, bus, id, lun, pTarget->inq_data[0], pTarget));

	if((ioc->bus_type == SPI) &&
		mptscsih_is_phys_disk(ioc, bus, id)) {
	; /* this target reset shouldn't be issued to hidden
	   * phys disk in a raid volume.  The result would
	   * kill domain validation on that disk; e.g. disk
	   * will be running at asyn/narrow speeds = 2MB/s
	   * This workaround only impacts spi/raid volumes
	   * with dv enabled.
	   */
	}else if(pTarget->configured_lun){
		/* kill oustanding tasks for this
		 * device out in firmware stack
		 */
	    /* GEM, processor WORKAROUND
	     */
	}

	mptscsih_search_running_cmds(hd, id, lun);

	lun_index = (lun >> 5);  /* 32 luns per lun_index */
	indexed_lun = (lun % 32);
	pTarget->luns[lun_index] &= ~(1 << indexed_lun);

	if (--pTarget->num_luns) {
		dsprintk((MYIOC_s_INFO_FMT " mptscsih_slave_destroy bus=%d id=%d lun=%d pTarget=%p num_luns=%d luns[0]=%x returning\n",
			ioc->name, bus, id, lun, pTarget, pTarget->num_luns, pTarget->luns[0]));
		return;
	}

	dsprintk((MYIOC_s_INFO_FMT " mptscsih_slave_destroy bus=%d id=%d lun=%d freeing pTarget=%p\n",
			ioc->name, bus, id, lun, pTarget));

	if (ioc->bus_type == SPI) {
		if (mptscsih_is_phys_disk(ioc, bus, id)) {
			ioc->spi_data.forceDv |= MPT_SCSICFG_RELOAD_IOC_PG3;
			dsprintk((MYIOC_s_INFO_FMT " mptscsih_slave_destroy PhysDisk bus=%d id=%d lun=%d pTarget=%p retained\n",
			ioc->name, bus, id, lun, pTarget));
		} else {
			ioc->spi_data.dvStatus[id] =
				(MPT_SCSICFG_NEGOTIATE | MPT_SCSICFG_DV_NOT_DONE);
			kfree(pTarget);
			pMptTarget->Target[id] = NULL;
			dsprintk((MYIOC_s_INFO_FMT " mptscsih_slave_destroy bus=%d id=%d lun=%d pTarget=%p completed\n",
				ioc->name, bus, id, lun, pTarget));
		}
	} else {
		kfree(pTarget);
		pMptTarget->Target[id] = NULL;
		dsprintk((MYIOC_s_INFO_FMT " mptscsih_slave_destroy bus=%d id=%d lun=%d pTarget=%p completed\n",
			ioc->name, bus, id, lun, pTarget));
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_change_queue_depth - This function will set a device's queue 
 *	depth
 *	@sdev: per scsi_device pointer
 *	@qdepth: requested queue depth
 *
 *	Adding support for new 'change_queue_depth' api.
*/
int
mptscsih_change_queue_depth(struct scsi_device *sdev, int qdepth)
{
	MPT_SCSI_HOST	*hd = (MPT_SCSI_HOST *)sdev->host->hostdata;
	MPT_ADAPTER	*ioc = hd->ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice *pTarget;
	int	max_depth;
	int	tagged;

	pMptTarget = ioc->Target_List[sdev->channel];
	pTarget = pMptTarget->Target[sdev->id];
	if (pTarget == NULL)
		return 0;

	if (ioc->bus_type == SPI) {
		if (sdev->type == TYPE_DISK &&
		    pTarget->minSyncFactor <= MPT_ULTRA160)
			max_depth = MPT_SCSI_CMD_PER_DEV_HIGH;
		else
			max_depth = MPT_SCSI_CMD_PER_DEV_LOW;
	} else
		max_depth = ioc->sh->can_queue;

	if (!sdev->tagged_supported)
		max_depth = 1;

	if (qdepth > max_depth)
		qdepth = max_depth;
	if (qdepth == 1)
		tagged = 0;
	else
		tagged = MSG_SIMPLE_TAG;

	scsi_adjust_queue_depth(sdev, tagged, qdepth);
	return sdev->queue_depth;
}

/*
 *	OS entry point to adjust the queue_depths on a per-device basis.
 *	Called once per device the bus scan. Use it to force the queue_depth
 *	member to 1 if a device does not support Q tags.
 *	Return non-zero if fails.
 */
int
mptscsih_slave_configure(struct scsi_device *device, int device_queue_depth)
{
	struct Scsi_Host	*sh = device->host;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	MPT_SCSI_HOST		*hd = (MPT_SCSI_HOST *)sh->hostdata;
	MPT_ADAPTER		*ioc = hd->ioc;
	int			rc;

	dinitprintk((MYIOC_s_INFO_FMT
		"%s: device @ %p, id=%d, LUN=%d, channel=%d\n",
		ioc->name, __FUNCTION__, device, device->id, device->lun, 
		device->channel));
	dinitprintk((MYIOC_s_INFO_FMT
		"sdtr %d wdtr %d ppr %d inq length=%d\n",
		ioc->name, device->sdtr, device->wdtr,
		device->ppr, device->inquiry_len));

	if (device->id >= ioc->DevicesPerBus) {
		/* error case, should never happen */
		scsi_adjust_queue_depth(device, 0, 1);
		goto slave_configure_exit;
	}

	pMptTarget = ioc->Target_List[device->channel];

	pTarget = pMptTarget->Target[device->id];

	if (pTarget == NULL) {
		/* Driver doesn't know about this device.
		 * Kernel may generate a "Dummy Lun 0" which
		 * may become a real Lun if a
		 * "scsi add-single-device" command is executed
		 * while the driver is active (hot-plug a
		 * device).  LSI Raid controllers need
		 * queue_depth set to DEV_HIGH for this reason.
		 */
		scsi_adjust_queue_depth(device, MSG_SIMPLE_TAG,
			device_queue_depth);
		goto slave_configure_exit;
	} else
		pTarget->configured_lun=1;

	/* LUN persistancy support */
	if (ioc->bus_type == FC) {
		FCDevicePage0_t fcDevicePage;

		rc = mptscsih_readFCDevicePage0(ioc,
		    pTarget->bus, pTarget->id, &fcDevicePage);

		if (rc > offsetof(FCDevicePage0_t,PortIdentifier)) {
			pTarget->WWPN = fcDevicePage.WWPN;
			pTarget->WWNN = fcDevicePage.WWNN;

			dsprintk((MYIOC_s_INFO_FMT
			"  bus=%d id=%d is WWPN = %08x%08x, WWNN = %08x%08x\n",
				ioc->name, pTarget->bus, pTarget->id,
				le32_to_cpu(fcDevicePage.WWPN.High),
				le32_to_cpu(fcDevicePage.WWPN.Low),
				le32_to_cpu(fcDevicePage.WWNN.High),
				le32_to_cpu(fcDevicePage.WWNN.Low)));
		}
	}

	mptscsih_initTarget(hd, device->channel, device->id, device->lun,
		device->inquiry, device->inquiry_len );
	mptscsih_change_queue_depth(device, device_queue_depth);

	dinitprintk((MYIOC_s_INFO_FMT
		"Queue depth=%d, tflags=%x, device_queue_depth=%d\n",
		ioc->name, device->queue_depth, pTarget->tflags, device_queue_depth));

	if (ioc->bus_type == SPI) {
		dinitprintk((MYIOC_s_INFO_FMT
			"negoFlags=%x, maxOffset=%x, SyncFactor=%x\n",
			ioc->name, pTarget->negoFlags, pTarget->maxOffset, 
			pTarget->minSyncFactor));
	}

slave_configure_exit:

	dinitprintk((MYIOC_s_INFO_FMT
		"tagged %d, simple %d, ordered %d\n",
		ioc->name,device->tagged_supported, device->simple_tags,
		device->ordered_tags));

	return 0;
}

ssize_t
mptscsih_store_queue_depth(struct device *dev, const char *buf, size_t count)
{
	int			 depth;
	struct scsi_device	*sdev = to_scsi_device(dev);

	depth = simple_strtoul(buf, NULL, 0);
	if (depth == 0)
		return -EINVAL;
	mptscsih_change_queue_depth(sdev, depth);
	return count;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	OS entry point to check whether the host drivier is sane enough
 *	to be used for saving crash dump. Called once when system crash
 *	occurs.
 */
int
mptscsih_sanity_check(struct scsi_device *sdev)
{
	MPT_ADAPTER    *ioc;
	MPT_SCSI_HOST  *hd;

	hd = (MPT_SCSI_HOST *) sdev->host->hostdata;
	if (!hd)
		return -ENXIO;
	ioc = hd->ioc;

	/* message frame freeQ is busy */
	if (spin_is_locked(&ioc->FreeQlock))
		return -EBUSY;

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	OS entry point to poll whether the adapter issue the interrupts.
 *	Called repeatedly after I/O commands are issued to this adapter.
 */
void
mptscsih_poll(struct scsi_device *sdev)
{
	MPT_SCSI_HOST  *hd;

	hd = (MPT_SCSI_HOST *) sdev->host->hostdata;
	if (!hd)
		return;

	/* check interrupt pending */
	mpt_poll_interrupt(hd->ioc);
}


/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *  Private routines...
 */

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/* Utility function to copy sense data from the scsi_cmnd buffer
 * to the FC and SCSI target structures.
 *
 */
static void
mptscsih_copy_sense_data(struct scsi_cmnd *sc, MPT_SCSI_HOST *hd, MPT_FRAME_HDR *mf, SCSIIOReply_t *pScsiReply)
{
	MPT_ADAPTER	*ioc = hd->ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice	*pTarget;
	SCSIIORequest_t	*pReq;
	u32		 sense_count = le32_to_cpu(pScsiReply->SenseCount);
	int		 bus, id;

	/* Get target structure
	 */
	pReq = (SCSIIORequest_t *) mf;
	bus = (int) pReq->Bus;
	id = (int) pReq->TargetID;
	pMptTarget = ioc->Target_List[bus];
	pTarget = pMptTarget->Target[id];

	if (sense_count) {
		u8 *sense_data;
		int req_index;

		/* Copy the sense received into the scsi command block. */
		req_index = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
		sense_data = ((u8 *)ioc->sense_buf_pool + (req_index * MPT_SENSE_BUFFER_ALLOC));
		memcpy(sc->sense_buffer, sense_data, SNS_LEN(sc));
		DBG_DUMP_SENSE_DATA(sense_data);

		/* Log SMART data (asc = 0x5D, non-IM case only) if required.
		 */
		if ((ioc->events) && (ioc->eventTypes & (1 << MPI_EVENT_SCSI_DEVICE_STATUS_CHANGE))) {
			if ((sense_data[12] == 0x5D) && (pTarget->raidVolume == 0)) {
				int idx;

				idx = ioc->eventContext % MPTCTL_EVENT_LOG_SIZE;
				ioc->events[idx].event = MPI_EVENT_SCSI_DEVICE_STATUS_CHANGE;
				ioc->events[idx].eventContext = ioc->eventContext;

				ioc->events[idx].data[0] = 
					(pReq->LUN[1] << 24) |
					(MPI_EVENT_SCSI_DEV_STAT_RC_SMART_DATA << 16) |
					(pReq->Bus << 8) | pReq->TargetID;

				ioc->events[idx].data[1] = 
					(sense_data[13] << 8) | sense_data[12];

				ioc->eventContext++;
				/* OEM Specific to light the fault light */
				if (ioc->vendorID == 0x1014) {
					MPT_FRAME_HDR		*mf;
					SEPRequest_t *SEPMsg;
					/* Get a MF for this command.
	 				*/
					if ((mf = mpt_get_msg_frame(ioc->InternalCtx, ioc)) == NULL) {
						dfailprintk((MYIOC_s_WARN_FMT "%s: no msg frames!!\n",
						    ioc->name,__FUNCTION__));
					}
					SEPMsg = (SEPRequest_t *)mf;
					SEPMsg->Function = MPI_FUNCTION_SCSI_ENCLOSURE_PROCESSOR;
					SEPMsg->Bus = pReq->Bus;
					SEPMsg->TargetID = pReq->TargetID;
					SEPMsg->Action = MPI_SEP_REQ_ACTION_WRITE_STATUS;
					SEPMsg->SlotStatus = MPI_SEP_REQ_SLOTSTATUS_PREDICTED_FAULT;
					pTarget->tflags |= MPT_TARGET_FLAGS_LED_ON;
					devtprintk((MYIOC_s_WARN_FMT "Sending SEP LED_ON cmd id=%d bus=%d\n",
						ioc->name, SEPMsg->TargetID, SEPMsg->Bus));
					mpt_put_msg_frame(ioc->DoneCtx, ioc, mf);
				}
			}
		}
	} else {
		dprintk((MYIOC_s_INFO_FMT "Hmmm... SenseData len=0! (?)\n",
				ioc->name));
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
int
mptscsih_ioc_reset(MPT_ADAPTER *ioc, int reset_phase)
{
	MPT_SCSI_HOST	*hd;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice	*pTarget;
	unsigned long	 flags;
	int 		bus, id, ii;
	int		n;

	dtmprintk((KERN_INFO MYNAM
			": IOC %s_reset routed to SCSI host driver!\n",
			reset_phase==MPT_IOC_PRE_RESET ? "pre" : "post"));

	/* If a FW reload request arrives after base installed but
	 * before all scsi hosts have been attached, then an alt_ioc
	 * may have a NULL sh pointer.
	 */
	if ((ioc->sh == NULL) || (ioc->sh->hostdata == NULL))
		return 0;
	else
		hd = (MPT_SCSI_HOST *) ioc->sh->hostdata;

	if (reset_phase == MPT_IOC_PRE_RESET) {
		dtmprintk((MYIOC_s_WARN_FMT "Pre-Diag Reset\n", ioc->name));

		/* 2. Flush running commands
		 *	Clean ScsiLookup (and associated memory)
		 *	AND clean mytaskQ
		 */

		/* 2b. Reply to OS all known outstanding I/O commands.
		 */
//		mptscsih_flush_running_cmds(hd);

		/* 2c. If there was an internal command that
		 * has not completed, configuration or io request,
		 * free these resources.
		 */
		if (hd->cmdPtr) {
			del_timer(&hd->InternalCmdTimer);
			mpt_free_msg_frame(ioc, hd->cmdPtr);
			hd->cmdPtr = NULL;
		}

		if (hd->DVcmdPtr) {
			del_timer(&hd->DVCmdTimer);
			mpt_free_msg_frame(ioc, hd->DVcmdPtr);
			hd->DVcmdPtr = NULL;
		} 

		/* 2d. If a task management has not completed,
		 * free resources associated with this request.
		 */
		if (ioc->tmPtr) {
			del_timer(&ioc->TMtimer);
			mpt_free_msg_frame(ioc, ioc->tmPtr);
			ioc->tmPtr = NULL;
		}

		dtmprintk((MYIOC_s_WARN_FMT "Pre-Reset complete.\n", ioc->name));

	} else {
		dtmprintk((MYIOC_s_WARN_FMT "Post-Diag Reset\n", ioc->name));

		if (ioc->bus_type == FC) {
			n = 0;
			for (bus = 0; bus < ioc->NumberOfBuses; bus++) {
				pMptTarget = ioc->Target_List[bus];
				for (id=0; id < ioc->DevicesPerBus; id++) {
					pTarget = pMptTarget->Target[id];
					if (pTarget) {
						dsprintk((MYIOC_s_INFO_FMT
							"bus=%d id=%d is known to be WWPN %08x%08x, WWNN %08x%08x\n",
							ioc->name, bus, id,
							le32_to_cpu(pTarget->WWPN.High),
							le32_to_cpu(pTarget->WWPN.Low),
							le32_to_cpu(pTarget->WWNN.High),
							le32_to_cpu(pTarget->WWNN.Low)));
						mptscsih_writeFCPortPage3(hd, bus, id);
						n++;
					}
				}
			}

			if (n) {
				mptscsih_sendIOCInit(hd);
			}
		}

		/* Once a FW reload begins, all new OS commands are
		 * redirected to the doneQ w/ a reset status.
		 * Init all control structures.
		 */

		/* ScsiLookup initialization
		 */
		for (ii=0; ii < ioc->req_depth; ii++)
			ioc->ScsiLookup[ii] = NULL;

		/* 2. Chain Buffer initialization
		 */

		/* 4. Renegotiate to all devices, if SCSI
		 */
		if (ioc->bus_type == SPI) {
			dnegoprintk((MYIOC_s_WARN_FMT "%s: writeSDP1: ALL_IDS USE_NVRAM\n",
				ioc->name, __FUNCTION__));
			mpt_writeSDP1(ioc, 0, 0, (MPT_SCSICFG_ALL_IDS | MPT_SCSICFG_USE_NVRAM));
		}

		/* 5. Enable new commands to be posted
		 */
		spin_lock_irqsave(&ioc->FreeQlock, flags);
		hd->tmPending = 0;
		hd->tmState = TM_STATE_NONE;
		spin_unlock_irqrestore(&ioc->FreeQlock, flags);

		/* 6. If there was an internal command,
		 * wake this process up.
		 */
		if (hd->cmdPtr || hd->DVcmdPtr) {
			/*
			 * Wake up the original calling thread
			 */
			hd->pLocal = &hd->localReply;
			hd->pLocal->completion = MPT_SCANDV_DID_RESET;
			hd->scandv_wait_done = 1;
			wake_up(&hd->scandv_waitq);
			hd->cmdPtr = NULL;
			hd->DVcmdPtr = NULL;
		}

		/* 7. Set flag to force DV and re-read IOC Page 3
		 */
		if (ioc->bus_type == SPI) {
			ioc->spi_data.forceDv = MPT_SCSICFG_RELOAD_IOC_PG3;
			ddvprintk(("Set reload IOC Pg3 Flag\n"));
		}

		dtmprintk((MYIOC_s_WARN_FMT "Post-Reset complete.\n", ioc->name));

	}

	return 1;		/* currently means nothing really */
}

static int
SCPNT_TO_LOOKUP_IDX(struct scsi_cmnd *sc)
{
	MPT_SCSI_HOST *hd;
	MPT_ADAPTER	*ioc;
	int i;

	hd = (MPT_SCSI_HOST *) sc->device->host->hostdata;

	ioc = hd->ioc;
	for (i = 0; i < ioc->req_depth; i++) {
		if (ioc->ScsiLookup[i] == sc) {
			return i;
		}
	}

	return -1;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
int
mptscsih_event_process(MPT_ADAPTER *ioc, EventNotificationReply_t *pEvReply)
{
	MPT_SCSI_HOST *hd;
	u8 event = le32_to_cpu(pEvReply->Event) & 0xFF;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	int	 physDiskNum, bus, id;

//	devtprintk((MYIOC_s_WARN_FMT "MPT event (=%02Xh) routed to SCSI host driver!\n",
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

#ifdef MPTSCSIH_ENABLE_DOMAIN_VALIDATION
	case MPI_EVENT_INTEGRATED_RAID:			/* 0B */
	{
#ifdef MPTSCSIH_ENABLE_DOMAIN_VALIDATION
                pMpiEventDataRaid_t pRaidEventData =
                    (pMpiEventDataRaid_t) &pEvReply->Data;

                /* Domain Validation Needed */
	        if (ioc->bus_type == SPI &&
			pRaidEventData->ReasonCode ==
				MPI_EVENT_RAID_RC_DOMAIN_VAL_NEEDED) {
       			SpiCfgData	*pSpi;

			physDiskNum = pRaidEventData->PhysDiskNum;
			if (ioc->raid_data.pIocPg3) {
				id = ioc->raid_data.pIocPg3->PhysDisk[physDiskNum].PhysDiskID;
				bus = ioc->raid_data.pIocPg3->PhysDisk[physDiskNum].PhysDiskBus;
				pMptTarget = ioc->Target_List[bus];
				pTarget = (VirtDevice *)pMptTarget->Target[id];
				ddvprintk((KERN_WARNING "%s: Raid Event: DV Requested for PhysDiskNum=%d bus=%d id=%d pTarget=%p\n",
					ioc->name, physDiskNum, bus, id, pTarget));
			} else {
				ddvprintk((KERN_WARNING "%s: Raid Event: DV Requested for PhysDiskNum=%d but raid_data.pIocPg3 is NULL\n",
					ioc->name, physDiskNum));
				break;
			}
			pSpi = &ioc->spi_data;
			pSpi->dvStatus[id] |= (MPT_SCSICFG_PHYSDISK_DV_ONLY |
					      MPT_SCSICFG_NEED_DV |
					      MPT_SCSICFG_DV_NOT_DONE);

			if (pTarget == NULL) {
				ddvprintk((KERN_WARNING " Raid Event: DV Requested for PhysDiskNum=%d bus=%d id=%d but pTarget is NULL\n",
					physDiskNum, bus, id));
				mptscsih_initTarget(hd, bus, id, 0,
					NULL, 0 );
				pTarget = (VirtDevice *)pMptTarget->Target[id];
				ddvprintk((KERN_WARNING "%s: Raid Event: DV Requested for PhysDiskNum=%d bus=%d id=%d pTarget%p now\n",
					ioc->name, physDiskNum, bus, id, pTarget));
			}
			pSpi->forceDv |= MPT_SCSICFG_RELOAD_IOC_PG3;
			ddvprintk((KERN_WARNING "%s: Raid Event: Scheduling DV for PhysDiskNum=%d bus=%d id=%d pTarget=%p\n",
				ioc->name, physDiskNum, bus, id, pTarget));
			INIT_WORK(&pTarget->dvTask, mptscsih_domainValidation, (void *) pTarget);
			schedule_work(&pTarget->dvTask);
			ddvprintk((KERN_WARNING "%s: Raid Event: DV Scheduled for PhysDiskNum=%d bus=%d id=%d pTarget=%p\n",
				ioc->name, physDiskNum, bus, id, pTarget));
#endif
		}
		break;
	}
#endif

	case MPI_EVENT_NONE:				/* 00 */
	case MPI_EVENT_LOG_DATA:			/* 01 */
	case MPI_EVENT_STATE_CHANGE:			/* 02 */
	case MPI_EVENT_EVENT_CHANGE:			/* 0A */
	default:
		dprintk((KERN_INFO "  Ignoring event (=%02Xh)\n", event));
		break;
	}

	return 1;		/* currently means nothing really */
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_initTarget - Target, LUN alloc/free functionality.
 *	@hd: Pointer to MPT_SCSI_HOST structure
 *	@bus: Bus number (?)
 *	@id: SCSI target id
 *	@lun: SCSI LUN id
 *	@data: Pointer to data
 *	@dlen: Number of INQUIRY bytes
 *
 *	NOTE: It's only SAFE to call this routine if data points to
 *	sane & valid STANDARD INQUIRY data!
 *
 *	Allocate and initialize memory for this target.
 *	Save inquiry data.
 *
 */
static void
mptscsih_initTarget(MPT_SCSI_HOST *hd, int bus, int id, u8 lun, char *data, int dlen)
{
	int		indexed_lun, lun_index;
	MPT_ADAPTER	*ioc = hd->ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice	*pTarget;
	SpiCfgData	*pSpi;
	char		data_56;

	dinitprintk((MYIOC_s_WARN_FMT "initTarget bus=%d id=%d lun=%d\n",
			ioc->name, bus, id, lun));

	/*
	 * If the peripheral qualifier filter is enabled then if the target reports a 0x1
	 * (i.e. The targer is capable of supporting the specified peripheral device type
	 * on this logical unit; however, the physical device is not currently connected
	 * to this logical unit) it will be converted to a 0x3 (i.e. The target is not
	 * capable of supporting a physical device on this logical unit). This is to work
	 * around a bug in th emid-layer in some distributions in which the mid-layer will
	 * continue to try to communicate to the LUN and evntually create a dummy LUN.
	*/
	if (hd->mpt_pq_filter && dlen && (data[0] & 0x20))
		data[0] |= 0x40;

	/* Is LUN supported? If so, upper 2 bits will be 0
	* in first byte of inquiry data.
	*/
	if (dlen && (data[0] & 0xe0))
		return;

	pMptTarget = ioc->Target_List[bus];
	pTarget = pMptTarget->Target[id];
	if (pTarget == NULL) {
		dinitprintk((MYIOC_s_INFO_FMT "initTarget bus=%d id=%d lun=%d pTarget is NULL\n",
			ioc->name, bus, id, lun));
		pTarget = kmalloc(sizeof(VirtDevice), GFP_KERNEL);
		if (!pTarget) {
			printk(MYIOC_s_ERR_FMT "initTarget kmalloc(%zd) FAILED!\n",
				ioc->name, sizeof(VirtDevice));
			return;
		}

		memset(pTarget, 0, sizeof(VirtDevice));
		if (ioc->bus_type != SPI)
			pTarget->tflags = MPT_TARGET_FLAGS_Q_YES;
		pTarget->ioc = ioc;
		pTarget->id = id;
		pTarget->bus = bus;
		pTarget->last_lun = MPT_LAST_LUN;
		pTarget->raidVolume = 0;
		pMptTarget->Target[id] = pTarget;
		if (ioc->raid_data.isRaid & (1 << id)) {
			pTarget->raidVolume = 1;
			ddvprintk((KERN_INFO
			    "RAID Volume @ id %d\n", id));
		}
		return;
	}

	dinitprintk((MYIOC_s_WARN_FMT "initTarget bus=%d id=%d lun=%d pTarget=%p\n",
			ioc->name, bus, id, lun, pTarget));

	pSpi = &ioc->spi_data;
	pTarget->ioc = ioc;
	pTarget->tflags &= ~MPT_TARGET_FLAGS_DELETED;
	lun_index = (lun >> 5);  /* 32 luns per lun_index */
	indexed_lun = (lun % 32);
	pTarget->luns[lun_index] |= (1 << indexed_lun);

	if (!(pTarget->tflags & MPT_TARGET_FLAGS_VALID_INQUIRY)) {
		if ( dlen > 8 ) {
			memcpy (pTarget->inq_data, data, 8);
		} else {
			memcpy (pTarget->inq_data, data, dlen);
		}
	}
	if (ioc->bus_type == SPI) {
		if ((data[0] == TYPE_PROCESSOR) && (ioc->spi_data.Saf_Te)) {
			/* Treat all Processors as SAF-TE if
			 * command line option is set */
			pTarget->tflags |= MPT_TARGET_FLAGS_SAF_TE_ISSUED;
			mptscsih_writeIOCPage4(hd, id, bus);
		} else if ((data[0] == TYPE_PROCESSOR) &&
			!(pTarget->tflags & MPT_TARGET_FLAGS_SAF_TE_ISSUED )) {
			if ( dlen > 49 ) {
//				pTarget->tflags |= MPT_TARGET_FLAGS_VALID_INQUIRY;
				if ( data[44] == 'S' &&
				     data[45] == 'A' &&
				     data[46] == 'F' &&
				     data[47] == '-' &&
				     data[48] == 'T' &&
				     data[49] == 'E' ) {
					pTarget->tflags |= MPT_TARGET_FLAGS_SAF_TE_ISSUED;
					mptscsih_writeIOCPage4(hd, id, bus);
				}
			}
		}
		data_56 = 0x00;  /* Default to no Ultra 160 or 320 capabilities if Inq data length is < 57 */
		if (!(pTarget->tflags & MPT_TARGET_FLAGS_VALID_INQUIRY)) {

			pTarget->tflags |= MPT_TARGET_FLAGS_VALID_INQUIRY;

			if (dlen > 56) {
				if ( (!(pTarget->tflags & MPT_TARGET_FLAGS_VALID_56))) {
				/* Update the target capabilities
				 */
					data_56 = data[56];
					pTarget->tflags |= MPT_TARGET_FLAGS_VALID_56;
				}
			}
		} else {
			/* Initial Inquiry may not request enough data bytes to
			 * obtain byte 57.  DV will; if target doesn't return
			 * at least 57 bytes, data[56] will be zero. */
			if (dlen > 56) {
				if ( (!(pTarget->tflags & MPT_TARGET_FLAGS_VALID_56))) {
				/* Update the target capabilities
				 */
					data_56 = data[56];
					pTarget->tflags |= MPT_TARGET_FLAGS_VALID_56;
				}
			}
		}
		mptscsih_setTargetNegoParms(hd, pTarget, data_56);
		if (pSpi->dvStatus[id] & MPT_SCSICFG_NEED_DV) {
			ddvprintk((MYIOC_s_WARN_FMT "%s: DV Scheduled for non-PhysDisk id %d\n",
				ioc->name, __FUNCTION__, id));
			INIT_WORK(&pTarget->dvTask, mptscsih_domainValidation, (void *) pTarget);
			schedule_work(&pTarget->dvTask);
		}
	} else {
		pTarget->tflags |= MPT_TARGET_FLAGS_VALID_INQUIRY;
		if (ioc->bus_type == SAS) {
			if ( (pTarget->inq_data[7] & 0x02) == 0) {
				pTarget->tflags &= ~MPT_TARGET_FLAGS_Q_YES;
			}
			if ((data[0] == TYPE_TAPE)) {
				if (ioc->facts.IOCCapabilities & 
					MPI_IOCFACTS_CAPABILITY_TLR ) {
					if ((pTarget->tflags & MPT_TARGET_FLAGS_TLR_DONE) == 0) {
						if ( data[8]  == 'H' &&
						     data[9]  == 'P' &&
						     data[10] == ' ' &&
						     data[11] == ' ' &&
						     data[12] == ' ' &&
						     data[13] == ' ' &&
						     data[14] == ' ' &&
						     data[15] == ' ' ) {
							mpt_IssueTLR(hd, pTarget);
							pTarget->tflags |= MPT_TARGET_FLAGS_TLR_DONE;
						}
					}
				}
			}
		}
	}
}


static void
mpt_IssueTLR(MPT_SCSI_HOST *hd, VirtDevice *pTarget)
{
	MPT_ADAPTER		*ioc = hd->ioc;
	INTERNAL_CMD		 iocmd;
	int			 lun, indexed_lun, lun_index;

	iocmd.id = pTarget->id;
	iocmd.bus = pTarget->bus;
	for (lun=0; lun <= MPT_LAST_LUN; lun++) {
		/* If LUN present, issue the command
		 */
		lun_index = (lun >> 5);  /* 32 luns per lun_index */
		indexed_lun = (lun % 32);
		if (pTarget->luns[lun_index] & (1<<indexed_lun)) {
			iocmd.lun = lun;
			goto issueTLR;
		}
	}
	printk(MYIOC_s_INFO_FMT "mpt_IssueTLR: Unable find a lun on id=%d\n",
		ioc->name, iocmd.id);
	return;
issueTLR:
	iocmd.flags = 0;
	iocmd.physDiskNum = -1;
	iocmd.rsvd = iocmd.rsvd2 = 0;
	iocmd.cmd = OEM_TLR_COMMAND;
	iocmd.data_dma = -1;
	iocmd.data = NULL;
	iocmd.size = 0;
	if (mptscsih_do_cmd(hd, &iocmd) < 0) {
		if (mptscsih_do_cmd(hd, &iocmd) < 0) {
			printk(MYIOC_s_INFO_FMT "Unable to set TLR on id=%d\n",
				ioc->name, iocmd.id);
		}
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *  Update the target negotiation parameters based on the
 *  the Inquiry data, adapter capabilities, and NVRAM settings.
 *
 */
static void
mptscsih_setTargetNegoParms(MPT_SCSI_HOST *hd, VirtDevice *pTarget, char byte56)
{
	MPT_ADAPTER	*ioc = hd->ioc;
	SpiCfgData *pspi_data = &ioc->spi_data;
	int  id = (int) pTarget->id;
	int  nvram;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice	*loop_pTarget;
	int ii;
	u8 width = MPT_NARROW;
	u8 factor = MPT_ASYNC;
	u8 offset = 0;
	u8 version, nfactor;
	u8 noQas = 1;

	pTarget->negoFlags = pspi_data->noQas;

	ddvprintk((KERN_INFO "Command-line QAS setting sets noQas=%02x on id=%d!\n", 
		pspi_data->noQas, id));
	/* noQas == 0 => device supports QAS. Need byte 56 of Inq to determine
	 * support. If available, default QAS to off and allow enabling.
	 * If not available, default QAS to on, turn off for non-disks.
	 */

	/* Set flags based on Inquiry data
	 */
	version = pTarget->inq_data[2] & 0x07;
	if (version < 2) {
		width = 0;
		factor = MPT_ULTRA2;
		offset = pspi_data->maxSyncOffset;
		pTarget->tflags &= ~MPT_TARGET_FLAGS_Q_YES;
	} else {
		if (pTarget->inq_data[7] & 0x20) {
			width = 1;
		}
		if (pTarget->inq_data[7] & 0x02) 
			pTarget->tflags |= MPT_TARGET_FLAGS_Q_YES;
		else
			pTarget->tflags &= ~MPT_TARGET_FLAGS_Q_YES;


		if (pTarget->inq_data[7] & 0x10) {
			factor = pspi_data->minSyncFactor;
			if (pTarget->tflags & MPT_TARGET_FLAGS_VALID_56) {
				/* bits 2 & 3 show Clocking support */
				if ((byte56 & 0x0C) == 0)
					factor = MPT_ULTRA2;
				else {
					if ((byte56 & 0x03) == 0)
						factor = MPT_ULTRA160;
					else {
						factor = MPT_ULTRA320;
						if (byte56 & 0x02)
						{
							ddvprintk((KERN_INFO "Enabling QAS due to byte56=%02x on id=%d!\n", byte56, id));
							noQas = 0;
						}
						if (pTarget->inq_data[0] == TYPE_TAPE) {
							if (byte56 & 0x01)
								pTarget->negoFlags |= MPT_TAPE_NEGO_IDP;
						}
					}
				}
			} else {
				ddvprintk((KERN_INFO "Ultra 80 on id=%d due to ~TARGET_FLAGS_VALID_56!\n", id));
				factor = MPT_ULTRA2;
			}

			offset = pspi_data->maxSyncOffset;

			/* If RAID, never disable QAS
			 * else if non RAID, do not disable
			 *   QAS if bit 1 is set
			 * bit 1 QAS support, non-raid only
			 * bit 0 IU support
			 */
			if (pTarget->raidVolume == 1) {
				noQas = 0;
			}
		} else {
			factor = MPT_ASYNC;
			offset = 0;
		}
	}

	/* Update tflags based on NVRAM settings. (SCSI only)
	 */
	if (pspi_data->nvram && (pspi_data->nvram[id] != MPT_HOST_NVRAM_INVALID)) {
		nvram = pspi_data->nvram[id];
		nfactor = (nvram & MPT_NVRAM_SYNC_MASK) >> 8;

		if (width)
			width = nvram & MPT_NVRAM_WIDE_DISABLE ? 0 : 1;

		if (offset > 0) {
			/* Ensure factor is set to the
			 * maximum of: adapter, nvram, inquiry
			 */
			if (nfactor) {
				if (nfactor < pspi_data->minSyncFactor )
					nfactor = pspi_data->minSyncFactor;

				factor = max(factor, nfactor);
				if (factor == MPT_ASYNC)
					offset = 0;
			} else {
				offset = 0;
				factor = MPT_ASYNC;
		}
		} else {
			factor = MPT_ASYNC;
		}
	}

	/* Make sure data is consistent
	 */
	if ((!width) && (factor < MPT_ULTRA2)) {
		factor = MPT_ULTRA2;
	}

	/* Save the data to the target structure.
	 */
	pTarget->minSyncFactor = factor;
	pTarget->maxOffset = offset;
	pTarget->maxWidth = width;

	pTarget->tflags |= MPT_TARGET_FLAGS_VALID_NEGO;

	/* Disable unused features.
	 */
	if (!width)
		pTarget->negoFlags |= MPT_TARGET_NO_NEGO_WIDE;

	if (!offset)
		pTarget->negoFlags |= MPT_TARGET_NO_NEGO_SYNC;

	if ( factor > MPT_ULTRA320 )
		noQas = 0;

	/* GEM, processor WORKAROUND
	 */
	if ((pTarget->inq_data[0] == TYPE_PROCESSOR) || (pTarget->inq_data[0] > 0x08)) {
		pTarget->negoFlags |= (MPT_TARGET_NO_NEGO_WIDE | MPT_TARGET_NO_NEGO_SYNC);
		pspi_data->dvStatus[id] |= MPT_SCSICFG_BLK_NEGO;
	} else {
		if (noQas && (pspi_data->noQas == 0)) {
			pspi_data->noQas |= MPT_TARGET_NO_NEGO_QAS;
			pTarget->negoFlags |= MPT_TARGET_NO_NEGO_QAS;

			/* Disable QAS in a mixed configuration case
	 		*/

			ddvprintk((KERN_INFO "Disabling QAS due to noQas=%02x on id=%d!\n", noQas, id));
			pMptTarget = ioc->Target_List[0];
			for (ii = 0; ii < id; ii++) {
				loop_pTarget = pMptTarget->Target[id];
				if ((loop_pTarget)) {
					loop_pTarget->negoFlags |= MPT_TARGET_NO_NEGO_QAS;
					mpt_writeSDP1(ioc, 0, ii, loop_pTarget->negoFlags);
				}
			}
		}
	}

	/* Write SDP1 on this I/O to this target */
	if (pspi_data->dvStatus[id] & MPT_SCSICFG_NEGOTIATE) {
		dnegoprintk((KERN_INFO "MPT_SCSICFG_NEGOTIATE on id=%d!\n", id));
		/* First IO to this device; NEED_DV will cause async/narrow */
		mpt_writeSDP1(ioc, 0, id, 0);
		pspi_data->dvStatus[id] &= ~MPT_SCSICFG_NEGOTIATE;
	} else if (pspi_data->dvStatus[id] & MPT_SCSICFG_BLK_NEGO) {
		dnegoprintk((KERN_INFO "MPT_SCSICFG_BLK_NEGO on id=%d!\n", id));
		mpt_writeSDP1(ioc, 0, id, MPT_SCSICFG_BLK_NEGO);
		pspi_data->dvStatus[id] &= ~MPT_SCSICFG_BLK_NEGO;
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 * If no Target, bus reset on 1st I/O. Set the flag to
 * prevent any future negotiations to this device.
 */
static void
mptscsih_no_negotiate(MPT_SCSI_HOST *hd, int id)
{
	MPT_ADAPTER	*ioc = hd->ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice	*pTarget;

	pMptTarget = ioc->Target_List[0];
	pTarget = pMptTarget->Target[id];
	if (pTarget == NULL)
		ioc->spi_data.dvStatus[id] |= MPT_SCSICFG_BLK_NEGO;

	return;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *  SCSI Config Page functionality ...
 */
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mptscsih_writeIOCPage4  - write IOC Page 4
 *	@hd: Pointer to a SCSI Host Structure
 *	@id: write IOC Page4 for this ID & Bus
 *
 *	Return: -EAGAIN if unable to obtain a Message Frame
 *		or 0 if success.
 *
 *	Remark: We do not wait for a return, write pages sequentially.
 */
static int
mptscsih_writeIOCPage4(MPT_SCSI_HOST *hd, int id, int bus)
{
	MPT_ADAPTER		*ioc = hd->ioc;
	Config_t		*pReq;
	IOCPage4_t		*IOCPage4Ptr;
	MPT_FRAME_HDR		*mf;
	dma_addr_t		 dataDma;
	u16			 req_idx;
	u32			 frameOffset;
	u32			 flagsLength;
	int			 ii;

	/* Get a MF for this command.
	 */
	if ((mf = mpt_get_msg_frame(ioc->DoneCtx, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return -EAGAIN;
	}

	/* Set the request and the data pointers.
	 * Place data at end of MF.
	 */
	pReq = (Config_t *)mf;

	req_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
	frameOffset = ioc->req_sz - sizeof(IOCPage4_t);

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

       	IOCPage4Ptr = ioc->spi_data.pIocPg4;
       	dataDma = ioc->spi_data.IocPg4_dma;
       	ii = IOCPage4Ptr->ActiveSEP++;
       	IOCPage4Ptr->SEP[ii].SEPTargetID = id;
       	IOCPage4Ptr->SEP[ii].SEPBus = bus;
       	pReq->Header = IOCPage4Ptr->Header;
	pReq->PageAddress = cpu_to_le32(id | (bus << 8 ));

	/* Add a SGE to the config request.
	 */
	flagsLength = MPT_SGE_FLAGS_SSIMPLE_WRITE |
		(IOCPage4Ptr->Header.PageLength + ii) * 4;

	ioc->add_sge((char *)&pReq->PageBufferSGE, flagsLength, dataDma);

	dinitprintk((MYIOC_s_INFO_FMT
		"writeIOCPage4: MaxSEP=%d ActiveSEP=%d id=%d bus=%d\n",
			ioc->name, IOCPage4Ptr->MaxSEP, IOCPage4Ptr->ActiveSEP, id, bus));

	mpt_put_msg_frame(ioc->DoneCtx, ioc, mf);

	return 0;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *  Bus Scan and Domain Validation functionality ...
 */

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	mptscsih_scandv_complete - Scan and DV callback routine registered
 *	to Fustion MPT (base) driver.
 *
 *	@ioc: Pointer to MPT_ADAPTER structure
 *	@mf: Pointer to original MPT request frame
 *	@mr: Pointer to MPT reply frame (NULL if TurboReply)
 *
 *	This routine is called from mpt.c::mpt_interrupt() at the completion
 *	of any SCSI IO request.
 *	This routine is registered with the Fusion MPT (base) driver at driver
 *	load/init time via the mpt_register() API call.
 *
 *	Returns 1 indicating alloc'd request frame ptr should be freed.
 *
 *	Remark: Sets a completion code and (possibly) saves sense data
 *	in the IOC member localReply structure.
 *	Used ONLY for DV and other internal commands.
 */
int
mptscsih_scandv_complete(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf, MPT_FRAME_HDR *mr)
{
	MPT_SCSI_HOST	*hd;
	SCSIIORequest_t *pReq;
	int		 completionCode;
	u16		 req_idx;

	hd = (MPT_SCSI_HOST *) ioc->sh->hostdata;

	if (hd->DVcmdPtr) {
		del_timer(&hd->DVCmdTimer);
		hd->DVcmdPtr = NULL;
	} else {
		 if (hd->cmdPtr) {
			del_timer(&hd->InternalCmdTimer);
			hd->cmdPtr = NULL;
		}
	}
	if ((mf == NULL) ||
	    (mf >= MPT_INDEX_2_MFPTR(ioc, ioc->req_depth))) {
		printk(MYIOC_s_ERR_FMT
			"ScanDvComplete, %s req frame ptr! (=%p)\n",
				ioc->name, mf?"BAD":"NULL", (void *) mf);
		goto wakeup;
	}

	req_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
	ioc->ScsiLookup[req_idx] = NULL;
	pReq = (SCSIIORequest_t *) mf;

	ddvprintk((MYIOC_s_WARN_FMT "ScanDvComplete mf=%p mr=%p id=%d CDB=%02x\n",
			ioc->name, mf, mr, pReq->TargetID, pReq->CDB[0]));

	hd->pLocal = &hd->localReply;
	hd->pLocal->scsiStatus = 0;

	/* If target struct exists, clear sense valid flag.
	 */
	if (mr == NULL) {
		completionCode = MPT_SCANDV_GOOD;
	} else {
		SCSIIOReply_t	*pReply;
		u16		 status;
		u8		 scsi_status;

		pReply = (SCSIIOReply_t *) mr;

		status = le16_to_cpu(pReply->IOCStatus) & MPI_IOCSTATUS_MASK;
		scsi_status = pReply->SCSIStatus;

		ddvprintk((MYIOC_s_WARN_FMT "%s: IOCStatus=%04xh SCSIState=%02xh SCSIStatus=%02xh IOCLogInfo=%08xh\n",
		     ioc->name, __FUNCTION__, status, pReply->SCSIState, scsi_status,
		     le32_to_cpu(pReply->IOCLogInfo)));

		switch(status) {

		case MPI_IOCSTATUS_SCSI_DEVICE_NOT_THERE:	/* 0x0043 */
			completionCode = MPT_SCANDV_SELECTION_TIMEOUT;
			break;

		case MPI_IOCSTATUS_SCSI_IO_DATA_ERROR:		/* 0x0046 */
		case MPI_IOCSTATUS_SCSI_TASK_TERMINATED:	/* 0x0048 */
		case MPI_IOCSTATUS_SCSI_IOC_TERMINATED:		/* 0x004B */
		case MPI_IOCSTATUS_SCSI_EXT_TERMINATED:		/* 0x004C */
			completionCode = MPT_SCANDV_DID_RESET;
			break;

		case MPI_IOCSTATUS_SCSI_DATA_UNDERRUN:		/* 0x0045 */
		case MPI_IOCSTATUS_SCSI_RECOVERED_ERROR:	/* 0x0040 */
		case MPI_IOCSTATUS_SUCCESS:			/* 0x0000 */
			if (pReply->Function == MPI_FUNCTION_CONFIG) {
				ConfigReply_t *pr = (ConfigReply_t *)mr;
				completionCode = MPT_SCANDV_GOOD;
				hd->pLocal->header.PageVersion = pr->Header.PageVersion;
				hd->pLocal->header.PageLength = pr->Header.PageLength;
				hd->pLocal->header.PageNumber = pr->Header.PageNumber;
				hd->pLocal->header.PageType = pr->Header.PageType;

			} else if (pReply->Function == MPI_FUNCTION_RAID_ACTION) {
				/* If the RAID Volume request is successful,
				 * return GOOD, else indicate that
				 * some type of error occurred.
				 */
				MpiRaidActionReply_t	*pr = (MpiRaidActionReply_t *)mr;
				if (le16_to_cpu(pr->ActionStatus) == MPI_RAID_ACTION_ASTATUS_SUCCESS)
					completionCode = MPT_SCANDV_GOOD;
				else
					completionCode = MPT_SCANDV_SOME_ERROR;

			} else if (pReply->SCSIState & MPI_SCSI_STATE_AUTOSENSE_VALID) {
				u8		*sense_data;
				int		 sz;

				/* save sense data in global structure
				 */
				completionCode = MPT_SCANDV_SENSE;
				hd->pLocal->scsiStatus = scsi_status;
				sense_data = ((u8 *)ioc->sense_buf_pool +
					(req_idx * MPT_SENSE_BUFFER_ALLOC));

				sz = min_t(int, pReq->SenseBufferLength,
							SCSI_STD_SENSE_BYTES);
				memcpy(hd->pLocal->sense, sense_data, sz);

				DBG_DUMP_SENSE_DATA(sense_data);
				ddvprintk((KERN_NOTICE "  Check Condition, sense ptr %p\n",
						sense_data));
			} else if (pReply->SCSIState & MPI_SCSI_STATE_AUTOSENSE_FAILED) {
				if (pReq->CDB[0] == INQUIRY)
					completionCode = MPT_SCANDV_ISSUE_SENSE;
				else
					completionCode = MPT_SCANDV_DID_RESET;
			}
			else if (pReply->SCSIState & MPI_SCSI_STATE_NO_SCSI_STATUS)
				completionCode = MPT_SCANDV_DID_RESET;
			else if (pReply->SCSIState & MPI_SCSI_STATE_TERMINATED)
				completionCode = MPT_SCANDV_DID_RESET;
			else if (scsi_status == MPI_SCSI_STATUS_BUSY)
				completionCode = MPT_SCANDV_BUSY;
			else {
				completionCode = MPT_SCANDV_GOOD;
				hd->pLocal->scsiStatus = scsi_status;
			}
			break;

		case MPI_IOCSTATUS_SCSI_PROTOCOL_ERROR:		/* 0x0047 */
			if (pReply->SCSIState & MPI_SCSI_STATE_TERMINATED)
				completionCode = MPT_SCANDV_DID_RESET;
			else
				completionCode = MPT_SCANDV_SOME_ERROR;
			break;

		default:
			completionCode = MPT_SCANDV_SOME_ERROR;
			break;

		}	/* switch(status) */
		ddvprintk((MYIOC_s_WARN_FMT ": completionCode=%08xh\n",
			ioc->name, completionCode));


	} /* end of address reply case */

	hd->pLocal->completion = completionCode;

	/* MF and RF are freed in mpt_interrupt
	 */
wakeup:
	/* Free Chain buffers (will never chain) in scan or dv */
	//mpt_freeChainBuffers(ioc, req_idx);

	/*
	 * Wake up the original calling thread
	 */
	hd->scandv_wait_done = 1;
	wake_up(&hd->scandv_waitq);

	return 1;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mptscsih_InternalCmdTimer_expired - Call back for InternalCmd timer 
 *	process.
 *	Used only for Internal Command functionality.
 *	@data: Pointer to MPT_SCSI_HOST recast as an unsigned long
 *
 */
void mptscsih_InternalCmdTimer_expired(unsigned long data)
{
	MPT_SCSI_HOST *hd = (MPT_SCSI_HOST *) data;
	MPT_ADAPTER	*ioc=hd->ioc;
	MPIHeader_t *cmd = (MPIHeader_t *)hd->cmdPtr;

	dicprintk((MYIOC_s_WARN_FMT "InternalCmdTimer_expired! cmdPtr=%p\n", 
		ioc->name, cmd));

	if (cmd->Function == MPI_FUNCTION_SCSI_IO_REQUEST) {
#ifdef MPT_DEBUG_IC
		SCSIIORequest_t	*pScsiReq = (SCSIIORequest_t *) cmd;
		int	 id = pScsiReq->TargetID;

		dicprintk((MYIOC_s_WARN_FMT "InternalCmd Timeout: id=%d CDB=%02x\n", 
			ioc->name, id, pScsiReq->CDB[0]));
#endif
	}
	hd->cmdPtr = NULL;
	/* Perform a Diagnostic Reset */
	if (mpt_HardResetHandler(ioc, NO_SLEEP) < 0) {
		printk(MYIOC_s_WARN_FMT "InternalCmdTimer_expired: HardReset FAILED!\n", ioc->name);
		dfailprintk((MYIOC_s_ERR_FMT "InternalCmdTimer_expired: HardReset failed\n", ioc->name));
	} else {
		dicprintk((MYIOC_s_ERR_FMT "InternalCmdTimer_expired: HardReset succeeded\n", ioc->name));
	}
	dicprintk((MYIOC_s_WARN_FMT "InternalCmdTimer_expired Complete!\n", ioc->name));
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mptscsih_DVCmdTimer_expired - Call back for DV timer process.
 *	Used only for dv functionality.
 *	@data: Pointer to MPT_SCSI_HOST recast as an unsigned long
 *
 */
void mptscsih_DVCmdTimer_expired(unsigned long data)
{
	MPT_SCSI_HOST *hd = (MPT_SCSI_HOST *) data;
	MPT_ADAPTER	*ioc=hd->ioc;
	MPIHeader_t *cmd = (MPIHeader_t *)hd->DVcmdPtr;

	ddvprintk((MYIOC_s_WARN_FMT "DVCmdTimer_expired! DVcmdPtr=%p\n", 
		ioc->name, cmd));

	hd->DVcmdPtr = NULL;
	if (cmd->Function == MPI_FUNCTION_SCSI_IO_REQUEST) {
		SCSIIORequest_t	*pScsiReq = (SCSIIORequest_t *) cmd;
		int	 bus = pScsiReq->Bus;
		

		ddvprintk((MYIOC_s_WARN_FMT "DV Cmd Timeout: channel=%d id=%d CDB=%02x\n", 
			ioc->name, bus, pScsiReq->TargetID, pScsiReq->CDB[0]));

		if (mptscsih_reset_bus_noblock(ioc, bus) == 0) {
			/*
			 * Wake up the original calling thread
			 */
			hd->pLocal = &hd->localReply;
			hd->pLocal->completion = MPT_SCANDV_FALLBACK;
			hd->scandv_wait_done = 1;
			wake_up(&hd->scandv_waitq);
			ddvprintk((MYIOC_s_WARN_FMT "DVCmdTimer_expired bus_reset completed, request DV FALLBACK\n", ioc->name));
			return;
		}
	}
	/* Perform a Diagnostic Reset */
	if (mpt_HardResetHandler(ioc, NO_SLEEP) < 0) {
		printk(MYIOC_s_WARN_FMT "DVCmdTimer_expired: HardReset FAILED!\n", ioc->name);
		dfailprintk((MYIOC_s_ERR_FMT "DVCmdTimer_expired: HardReset failed\n", ioc->name));
	} else {
		ddvprintk((MYIOC_s_ERR_FMT "DVCmdTimer_expired: HardReset succeeded\n", ioc->name));
	}
}

#ifdef MPTSCSIH_ENABLE_DOMAIN_VALIDATION
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mptscsih_do_raid - Format and Issue a RAID volume request message.
 *	@hd: Pointer to scsi host structure
 *	@action: What do be done.
 *	@id: Logical target id.
 *	@bus: Target locations bus.
 *
 *	Returns: < 0 on a fatal error
 *		0 on success
 *
 *	Remark: Wait to return until reply processed by the ISR.
 */
static int
mptscsih_do_raid(MPT_SCSI_HOST *hd, u8 action, INTERNAL_CMD *io)
{
	MPT_ADAPTER		*ioc = hd->ioc;
	MpiRaidActionRequest_t	*pReq;
	MPT_FRAME_HDR		*mf;
	int			in_isr;

	in_isr = in_interrupt();
	if (in_isr) {
		dfailprintk((MYIOC_s_WARN_FMT "Internal raid request not allowed in ISR context!\n",
       				ioc->name));
		return -EPERM;
	}

	/* Get and Populate a free Frame
	 */
	if ((mf = mpt_get_msg_frame(ioc->InternalCtx, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return -EAGAIN;
	}
	pReq = (MpiRaidActionRequest_t *)mf;
	pReq->Action = action;
	pReq->Reserved1 = 0;
	pReq->ChainOffset = 0;
	pReq->Function = MPI_FUNCTION_RAID_ACTION;
	pReq->VolumeID = io->id;
	pReq->VolumeBus = io->bus;
	pReq->PhysDiskNum = io->physDiskNum;
	pReq->MsgFlags = 0;
	pReq->Reserved2 = 0;
	pReq->ActionDataWord = 0; /* Reserved for this action */
	//pReq->ActionDataSGE = 0;

	ioc->add_sge((char *)&pReq->ActionDataSGE,
		MPT_SGE_FLAGS_SSIMPLE_READ | 0, (dma_addr_t) -1);

	ddvprintk((MYIOC_s_INFO_FMT "RAID Volume action %x id %d\n",
			ioc->name, action, io->id));

	hd->pLocal = NULL;
	hd->DVCmdTimer.expires = jiffies + HZ*10; /* 10 second timeout */
	hd->scandv_wait_done = 0;

	/* Save cmd pointer, for resource free if timeout or
	 * FW reload occurs
	 */
	hd->DVcmdPtr = mf;

	add_timer(&hd->DVCmdTimer);
	mpt_put_msg_frame(ioc->InternalCtx, ioc, mf);
	wait_event(hd->scandv_waitq, hd->scandv_wait_done);

	if ((hd->pLocal == NULL) || (hd->pLocal->completion != MPT_SCANDV_GOOD))
		return -1;

	return 0;
}
#endif /* ~MPTSCSIH_ENABLE_DOMAIN_VALIDATION */

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_do_DVcmd - Do DV command.
 *	@hd: MPT_SCSI_HOST pointer
 *	@io: INTERNAL_CMD pointer.
 *
 *	Issue the specified internally generated command and do command
 *	specific cleanup. For bus scan / DV only.
 *	NOTES: If command is Inquiry and status is good,
 *	initialize a target structure, save the data
 *
 *	Remark: Single threaded access only.
 *
 *	Return:
 *		< 0 if an illegal command or no resources
 *
 *		   0 if good
 *
 *		 > 0 if command complete but some type of completion error.
 */
int
mptscsih_do_DVcmd(MPT_SCSI_HOST *hd, INTERNAL_CMD *io)
{
	MPT_ADAPTER	*ioc = hd->ioc;
	MPT_FRAME_HDR	*mf;
	SCSIIORequest_t	*pScsiReq;
	SCSIIORequest_t	 ReqCopy;
	int		 my_idx, ii, dir;
	int		 rc, cmdTimeout;
	int		in_isr;
	u8		 cmdLen;
	u8		 CDB[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	u8		 cmd = io->cmd;

	in_isr = in_interrupt();
	if (in_isr) {
		dfailprintk((MYIOC_s_WARN_FMT "Internal SCSI IO request not allowed in ISR context!\n",
       				ioc->name));
		return -EPERM;
	}


	/* Set command specific information
	 */
	switch (cmd) {
	case INQUIRY:
		cmdLen = 6;
		dir = MPI_SCSIIO_CONTROL_READ;
		CDB[0] = cmd;
		CDB[4] = io->size;
		cmdTimeout = 1;
		break;

	case TEST_UNIT_READY:
		cmdLen = 6;
		dir = MPI_SCSIIO_CONTROL_READ;
		cmdTimeout = 1;
		break;

	case REQUEST_SENSE:
		cmdLen = 6;
		CDB[0] = cmd;
		CDB[4] = io->size;
		dir = MPI_SCSIIO_CONTROL_READ;
		cmdTimeout = 1;
		break;

	case READ_BUFFER:
		cmdLen = 10;
		dir = MPI_SCSIIO_CONTROL_READ;
		CDB[0] = cmd;
		if (io->flags & MPT_ICFLAG_ECHO) {
			CDB[1] = 0x0A;
		} else {
			CDB[1] = 0x02;
		}

		if (io->flags & MPT_ICFLAG_BUF_CAP) {
			CDB[1] |= 0x01;
		}
		CDB[6] = (io->size >> 16) & 0xFF;
		CDB[7] = (io->size >>  8) & 0xFF;
		CDB[8] = io->size & 0xFF;
		cmdTimeout = 1;
		break;

	case WRITE_BUFFER:
		cmdLen = 10;
		dir = MPI_SCSIIO_CONTROL_WRITE;
		CDB[0] = cmd;
		if (io->flags & MPT_ICFLAG_ECHO) {
			CDB[1] = 0x0A;
		} else {
			CDB[1] = 0x02;
		}
		CDB[6] = (io->size >> 16) & 0xFF;
		CDB[7] = (io->size >>  8) & 0xFF;
		CDB[8] = io->size & 0xFF;
		cmdTimeout = 1;
		break;

	case RESERVE:
		cmdLen = 6;
		dir = MPI_SCSIIO_CONTROL_READ;
		CDB[0] = cmd;
		cmdTimeout = 1;
		break;

	case RELEASE:
		cmdLen = 6;
		dir = MPI_SCSIIO_CONTROL_READ;
		CDB[0] = cmd;
		cmdTimeout = 1;
		break;

	default:
		/* Error Case */
		dfailprintk((MYIOC_s_WARN_FMT "%s,Unknown cmd=%02x!!\n",
		    ioc->name,__FUNCTION__, cmd));
		return -EFAULT;
	}

	/* Get and Populate a free Frame
	 */
	if ((mf = mpt_get_msg_frame(ioc->InternalCtx, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return -EBUSY;
	}

	pScsiReq = (SCSIIORequest_t *) mf;

	/* Get the request index */
	my_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
	ADD_INDEX_LOG(my_idx); /* for debug */

	if (io->flags & MPT_ICFLAG_PHYS_DISK) {
		pScsiReq->TargetID = io->physDiskNum;
		pScsiReq->Bus = 0;
		pScsiReq->ChainOffset = 0;
		pScsiReq->Function = MPI_FUNCTION_RAID_SCSI_IO_PASSTHROUGH;
	} else {
		pScsiReq->TargetID = io->id;
		pScsiReq->Bus = io->bus;
		pScsiReq->ChainOffset = 0;
		pScsiReq->Function = MPI_FUNCTION_SCSI_IO_REQUEST;
	}

	pScsiReq->CDBLength = cmdLen;
	pScsiReq->SenseBufferLength = MPT_SENSE_BUFFER_SIZE;

	pScsiReq->Reserved = 0;

	pScsiReq->MsgFlags = mpt_msg_flags();
	/* MsgContext set in mpt_get_msg_fram call  */

	for (ii=0; ii < 8; ii++)
		pScsiReq->LUN[ii] = 0;
	pScsiReq->LUN[1] = io->lun;

	if (io->flags & MPT_ICFLAG_TAGGED_CMD)
		pScsiReq->Control = cpu_to_le32(dir | MPI_SCSIIO_CONTROL_SIMPLEQ);
	else
		pScsiReq->Control = cpu_to_le32(dir | MPI_SCSIIO_CONTROL_UNTAGGED);

	if (cmd == REQUEST_SENSE) {
		pScsiReq->Control = cpu_to_le32(dir | MPI_SCSIIO_CONTROL_UNTAGGED);
		ddvprintk((MYIOC_s_INFO_FMT "Untagged! 0x%2x\n",
			ioc->name, cmd));
	}

	for (ii=0; ii < 16; ii++)
		pScsiReq->CDB[ii] = CDB[ii];

	pScsiReq->DataLength = cpu_to_le32(io->size);
	pScsiReq->SenseBufferLowAddr = cpu_to_le32(ioc->sense_buf_low_dma
					   + (my_idx * MPT_SENSE_BUFFER_ALLOC));

	ddvprintk((MYIOC_s_INFO_FMT "Sending Command 0x%x for (%d:%d:%d) mf=%p\n",
			ioc->name, cmd, io->bus, io->id, io->lun, pScsiReq));

	if (dir == MPI_SCSIIO_CONTROL_READ) {
		ioc->add_sge((char *) &pScsiReq->SGL,
			MPT_SGE_FLAGS_SSIMPLE_READ | io->size,
			io->data_dma);
	} else {
		ioc->add_sge((char *) &pScsiReq->SGL,
			MPT_SGE_FLAGS_SSIMPLE_WRITE | io->size,
			io->data_dma);
	}

	/* The ISR will free the request frame, but we need
	 * the information to initialize the target. Duplicate.
	 */
	memcpy(&ReqCopy, pScsiReq, sizeof(SCSIIORequest_t));

	/* Issue this command after:
	 *	finish init
	 *	add timer
	 * Wait until the reply has been received
	 *  ScsiScanDvCtx callback function will
	 *	set hd->pLocal;
	 *	set scandv_wait_done and call wake_up
	 */
	hd->pLocal = NULL;
	hd->DVCmdTimer.expires = jiffies + HZ*cmdTimeout;
	hd->scandv_wait_done = 0;

	/* Save cmd pointer, for resource free if timeout or
	 * FW reload occurs
	 */
	hd->DVcmdPtr = mf;

	add_timer(&hd->DVCmdTimer);
	mpt_put_msg_frame(ioc->InternalCtx, ioc, mf);
	wait_event(hd->scandv_waitq, hd->scandv_wait_done);

	if (hd->pLocal) {
		rc = hd->pLocal->completion;
		hd->pLocal->skip = 0;

		/* Always set fatal error codes in some cases.
		 */
		if (rc == MPT_SCANDV_SELECTION_TIMEOUT)
			rc = -ENXIO;
		else if (rc == MPT_SCANDV_SOME_ERROR)
			rc =  -rc;
	} else {
		rc = -EFAULT;
		/* This should never happen. */
		ddvprintk((MYIOC_s_INFO_FMT "_do_DVcmd: Null pLocal!!!\n",
				ioc->name));
	}

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_do_cmd - Do internal command.
 *	@hd: MPT_SCSI_HOST pointer
 *	@io: INTERNAL_CMD pointer.
 *
 *	Issue the specified internally generated command and do command
 *	specific cleanup. For bus scan / DV only.
 *	NOTES: If command is Inquiry and status is good,
 *	initialize a target structure, save the data
 *
 *	Remark: Single threaded access only.
 *
 *	Return:
 *		< 0 if an illegal command or no resources
 *
 *		   0 if good
 *
 *		 > 0 if command complete but some type of completion error.
 */
int
mptscsih_do_cmd(MPT_SCSI_HOST *hd, INTERNAL_CMD *io)
{
	MPT_ADAPTER	*ioc = hd->ioc;
	MPT_FRAME_HDR	*mf;
	SCSIIORequest_t	*pScsiReq;
	SCSIIORequest_t	 ReqCopy;
	int		 my_idx, ii, dir;
	int		 rc, cmdTimeout;
	int		in_isr;
	u8		 cmdLen;
	u8		 CDB[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	u8		 cmd = io->cmd;

	in_isr = in_interrupt();
	if (in_isr) {
		dfailprintk((MYIOC_s_WARN_FMT "Internal SCSI IO request not allowed in ISR context!\n",
       				ioc->name));
		return -EPERM;
	}


	/* Set command specific information
	 */
	switch (cmd) {
	case TEST_UNIT_READY:
		cmdLen = 6;
		dir = MPI_SCSIIO_CONTROL_READ;
		cmdTimeout = 10;
		break;

	case SYNCHRONIZE_CACHE:
		cmdLen = 10;
		dir = MPI_SCSIIO_CONTROL_READ;
		CDB[0] = cmd;
//		CDB[1] = 0x02;	/* set immediate bit */
		cmdTimeout = 10;
		break;

	case REPORT_LUNS:
		cmdLen = 12;
		dir = MPI_SCSIIO_CONTROL_READ;
		CDB[0] = cmd;
		CDB[6] = (io->size >> 24) & 0xFF;
		CDB[7] = (io->size >> 16) & 0xFF;
		CDB[8] = (io->size >>  8) & 0xFF;
		CDB[9] = io->size & 0xFF;
		cmdTimeout = 10;
		break;

	case OEM_TLR_COMMAND:
		CDB[0] = cmd;
		CDB[1] = 0x01;
		cmdLen = 6;
		dir = MPI_SCSIIO_CONTROL_READ;
		cmdTimeout = 10;
		break;

	default:
		/* Error Case */
		dfailprintk((MYIOC_s_WARN_FMT "%s,Unknown cmd=%02x!!\n",
		    ioc->name,__FUNCTION__, cmd));
		return -EFAULT;
	}

	/* Get and Populate a free Frame
	 */
	if ((mf = mpt_get_msg_frame(ioc->InternalCtx, ioc)) == NULL) {
		dfailprintk((MYIOC_s_WARN_FMT "%s, no msg frames!!\n",
		    ioc->name,__FUNCTION__));
		return -EBUSY;
	}

	pScsiReq = (SCSIIORequest_t *) mf;

	/* Get the request index */
	my_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
	ADD_INDEX_LOG(my_idx); /* for debug */

	if (io->flags & MPT_ICFLAG_PHYS_DISK) {
		pScsiReq->TargetID = io->physDiskNum;
		pScsiReq->Bus = 0;
		pScsiReq->ChainOffset = 0;
		pScsiReq->Function = MPI_FUNCTION_RAID_SCSI_IO_PASSTHROUGH;
	} else {
		pScsiReq->TargetID = io->id;
		pScsiReq->Bus = io->bus;
		pScsiReq->ChainOffset = 0;
		pScsiReq->Function = MPI_FUNCTION_SCSI_IO_REQUEST;
	}

	pScsiReq->CDBLength = cmdLen;
	pScsiReq->SenseBufferLength = MPT_SENSE_BUFFER_SIZE;

	pScsiReq->Reserved = 0;

	pScsiReq->MsgFlags = mpt_msg_flags();
	/* MsgContext set in mpt_get_msg_fram call  */

	for (ii=0; ii < 8; ii++)
		pScsiReq->LUN[ii] = 0;
	pScsiReq->LUN[1] = io->lun;

	if (io->flags & MPT_ICFLAG_TAGGED_CMD)
		pScsiReq->Control = cpu_to_le32(dir | MPI_SCSIIO_CONTROL_SIMPLEQ);
	else
		pScsiReq->Control = cpu_to_le32(dir | MPI_SCSIIO_CONTROL_UNTAGGED);

	for (ii=0; ii < 16; ii++)
		pScsiReq->CDB[ii] = CDB[ii];

	pScsiReq->DataLength = cpu_to_le32(io->size);
	pScsiReq->SenseBufferLowAddr = cpu_to_le32(ioc->sense_buf_low_dma
					   + (my_idx * MPT_SENSE_BUFFER_ALLOC));

	dicprintk((MYIOC_s_INFO_FMT "Sending Command 0x%x for (%d:%d:%d) mf=%p\n",
			ioc->name, cmd, io->bus, io->id, io->lun, pScsiReq));

	if (dir == MPI_SCSIIO_CONTROL_READ) {
		ioc->add_sge((char *) &pScsiReq->SGL,
			MPT_SGE_FLAGS_SSIMPLE_READ | io->size,
			io->data_dma);
	} else {
		ioc->add_sge((char *) &pScsiReq->SGL,
			MPT_SGE_FLAGS_SSIMPLE_WRITE | io->size,
			io->data_dma);
	}

	/* The ISR will free the request frame, but we need
	 * the information to initialize the target. Duplicate.
	 */
	memcpy(&ReqCopy, pScsiReq, sizeof(SCSIIORequest_t));

	/* Issue this command after:
	 *	finish init
	 *	add timer
	 * Wait until the reply has been received
	 *  ScsiScanDvCtx callback function will
	 *	set hd->pLocal;
	 *	set scandv_wait_done and call wake_up
	 */
	hd->pLocal = NULL;
	hd->InternalCmdTimer.expires = jiffies + HZ*cmdTimeout;
	hd->scandv_wait_done = 0;

	/* Save cmd pointer, for resource free if timeout or
	 * FW reload occurs
	 */
	hd->cmdPtr = mf;

	add_timer(&hd->InternalCmdTimer);
	mpt_put_msg_frame(ioc->InternalCtx, ioc, mf);
	wait_event(hd->scandv_waitq, hd->scandv_wait_done);

	if (hd->pLocal) {
		rc = hd->pLocal->completion;
		hd->pLocal->skip = 0;

		/* Always set fatal error codes in some cases.
		 */
		if (rc == MPT_SCANDV_SELECTION_TIMEOUT)
			rc = -ENXIO;
		else if (rc == MPT_SCANDV_SOME_ERROR)
			rc =  -rc;
	} else {
		rc = -EFAULT;
		/* This should never happen. */
		dicprintk((MYIOC_s_INFO_FMT "_do_cmd: Null pLocal!!!\n",
				ioc->name));
	}

	return rc;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_synchronize_cache - Send SYNCHRONIZE_CACHE to all disks.
 *	@hd: Pointer to MPT_SCSI_HOST structure
 *	@portnum: IOC port number
 *
 *	Uses the ISR, but with special processing.
 *	MUST be single-threaded.
 *
 *	Return: 0 on completion
 */
static int
mptscsih_synchronize_cache(MPT_SCSI_HOST *hd, int portnum)
{
	MPT_ADAPTER		*ioc= hd->ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	SCSIDevicePage1_t	*pcfg1Data = NULL;
	INTERNAL_CMD		 iocmd;
	CONFIGPARMS		 cfg;
	dma_addr_t		 cfg1_dma_addr = -1;
	ConfigPageHeader_t	 header1;
	int			 bus = 0;
	int			 id = 0;
	int			 lun;
	int			 indexed_lun, lun_index;
	int			 hostId = ioc->pfacts[portnum].PortSCSIID;
	int			 requested, configuration, data;
	int			 doConfig = 0;
	u8			 flags, factor;

	dexitprintk((KERN_INFO MYNAM ": %s called\n",
		__FUNCTION__));

	/* Following parameters will not change
	 * in this routine.
	 */
	iocmd.cmd = SYNCHRONIZE_CACHE;
	iocmd.flags = 0;
	iocmd.physDiskNum = -1;
	iocmd.data = NULL;
	iocmd.data_dma = -1;
	iocmd.size = 0;
	iocmd.rsvd = iocmd.rsvd2 = 0;

	/* Write SDP1 for all SCSI devices
	 * Alloc memory and set up config buffer
	 */
	if (ioc->bus_type == SPI) {
		if (ioc->spi_data.sdp1length > 0) {
			pcfg1Data = (SCSIDevicePage1_t *)pci_alloc_consistent(ioc->pcidev,
				ioc->spi_data.sdp1length * 4, &cfg1_dma_addr);

			if (pcfg1Data != NULL) {
				doConfig = 1;
				header1.PageVersion = ioc->spi_data.sdp1version;
				header1.PageLength = ioc->spi_data.sdp1length;
				header1.PageNumber = 1;
				header1.PageType = MPI_CONFIG_PAGETYPE_SCSI_DEVICE;
				cfg.cfghdr.hdr = &header1;
				cfg.physAddr = cfg1_dma_addr;
				cfg.action = MPI_CONFIG_ACTION_PAGE_WRITE_CURRENT;
				cfg.dir = 1;
				cfg.timeout = 0;
			}
		}
	}

	/* loop through all devices on this port
	 */
	while (bus < ioc->NumberOfBuses) {
		iocmd.bus = bus;
		iocmd.id = id;
		pMptTarget = ioc->Target_List[bus];
		pTarget = pMptTarget->Target[id];

		if (doConfig) {

			/* Set the negotiation flags */
			if (pTarget && !pTarget->raidVolume) {
				flags = pTarget->negoFlags;
			} else {
				flags = ioc->spi_data.noQas;
				if (ioc->spi_data.nvram && (ioc->spi_data.nvram[id] != MPT_HOST_NVRAM_INVALID)) {
					data = ioc->spi_data.nvram[id];

					if (data & MPT_NVRAM_WIDE_DISABLE)
						flags |= MPT_TARGET_NO_NEGO_WIDE;

					factor = (data & MPT_NVRAM_SYNC_MASK) >> MPT_NVRAM_SYNC_SHIFT;
					if ((factor == 0) || (factor == MPT_ASYNC))
						flags |= MPT_TARGET_NO_NEGO_SYNC;
				}
			}

			/* Force to async, narrow */
			mpt_setSDP1parameters(0, MPT_ASYNC, 0, flags, 
				&requested, &configuration);
			dnegoprintk(("%s: syncronize cache: id=%d width=0 factor=MPT_ASYNC "
				"offset=0 negoFlags=%x requested=%x configuration=%x\n",
				ioc->name, id, flags, requested, configuration));
			pcfg1Data->RequestedParameters = cpu_to_le32(requested);
			pcfg1Data->Reserved = 0;
			pcfg1Data->Configuration = cpu_to_le32(configuration);
			cfg.pageAddr = (bus<<8) | id;
			mpt_config(ioc, &cfg);
		}

		/* If target Ptr NULL or if this target is NOT a disk, skip.
		 */
		if ((pTarget) && (pTarget->inq_data[0] == TYPE_DISK)){
			for (lun=0; lun <= MPT_LAST_LUN; lun++) {
				/* If LUN present, issue the command
				 */
				lun_index = (lun >> 5);  /* 32 luns per lun_index */
				indexed_lun = (lun % 32);
				if (pTarget->luns[lun_index] & (1<<indexed_lun)) {
					dexitprintk((KERN_INFO MYNAM ": %s: synchronize_cache for bus=%d id=%d lun=%d\n",
						ioc->name, bus, id, lun));

					iocmd.lun = lun;
					(void) mptscsih_do_cmd(hd, &iocmd);
				}
			}
		}

		/* get next relevant device */
		id++;

		if (id == hostId)
			id++;

		if (id >= ioc->DevicesPerBus) {
			id = 0;
			bus++;
		}
	}

	dexitprintk((KERN_INFO MYNAM ": %s: synchronize_cache commands done\n",
		ioc->name));

	if (pcfg1Data) {
		dexitprintk((KERN_INFO MYNAM ": %s: free pcfg1Data=%p\n",
			ioc->name, pcfg1Data));
		pci_free_consistent(ioc->pcidev, header1.PageLength * 4, pcfg1Data, cfg1_dma_addr);
	}

	dexitprintk((KERN_INFO MYNAM ": %s: synchronize_cache done\n",
		ioc->name));
	return 0;
}

#ifdef MPTSCSIH_ENABLE_DOMAIN_VALIDATION
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_domainValidation - Top level handler for domain validation.
 *	@hd: Pointer to MPT_SCSI_HOST structure.
 *
 *	Uses the ISR, but with special processing.
 *	Called from schedule, should not be in interrupt mode.
 *	While thread alive, do dv for all devices needing dv
 *
 *	Return: None.
 */
static void
mptscsih_domainValidation(void *arg)
{
	VirtDevice	*pTarget=(VirtDevice *)arg;
	MPT_SCSI_HOST	*hd;
	MPT_ADAPTER	*ioc;
	unsigned long	 flags;
	int 		 id, dvStatus;
	int		 ii;

	spin_lock_irqsave(&dvtaskQ_lock, flags);
	dvtaskQ_active = 1;
	spin_unlock_irqrestore(&dvtaskQ_lock, flags);

	if (pTarget == NULL) {
		ddvprintk((KERN_WARNING "domainValidation called with NULL pTarget\n"));
		goto mptscsih_domainValidation_exit;
	}
	id = pTarget->id;
	ioc = pTarget->ioc;
	if (ioc == NULL) {
		ddvprintk((KERN_WARNING "domainValidation called with NULL pTarget->ioc id=%d\n", id));
		goto mptscsih_domainValidation_exit;
	}
//	set_current_state(TASK_INTERRUPTIBLE);
//	schedule_timeout(MPT_HZ/4);

	hd = (MPT_SCSI_HOST *) ioc->sh->hostdata;

	ddvprintk((KERN_WARNING "domainValidation pTarget=%p ioc=%p hd=%p id=%d\n",
		pTarget, ioc, hd, id));
	if (hd == NULL) {
		ddvprintk((KERN_WARNING "domainValidation called with NULL hd id=%d\n", id));
		goto mptscsih_domainValidation_exit;
	}
	
	if ((ioc->spi_data.forceDv & MPT_SCSICFG_RELOAD_IOC_PG3) != 0) {
		mpt_read_ioc_pg_3(ioc);
		if (ioc->spi_data.dvStatus[id] & MPT_SCSICFG_PHYSDISK_DV_ONLY) {
			ddvprintk((KERN_WARNING "PHYSDISK_DV_ONLY id=%d\n", id));
			ioc->spi_data.dvStatus[id] &=
				~MPT_SCSICFG_PHYSDISK_DV_ONLY;
			if (mptscsih_doDv(hd, 0, id) == 1) {
				/* Untagged device was busy, try again
				 */
				ioc->spi_data.dvStatus[id] |= MPT_SCSICFG_NEED_DV;
			} else {
				/* DV is complete. Clear flags.
				 */
				ioc->spi_data.dvStatus[id] &= ~MPT_SCSICFG_DV_NOT_DONE;
			}
			goto mptscsih_domainValidation_exit;
		}

		if (ioc->raid_data.pIocPg3) {
			Ioc3PhysDisk_t *pPDisk = ioc->raid_data.pIocPg3->PhysDisk;
			int	numPDisk = ioc->raid_data.pIocPg3->NumPhysDisks;

			while (numPDisk) {
				if (ioc->spi_data.dvStatus[pPDisk->PhysDiskID] & MPT_SCSICFG_DV_NOT_DONE)
					ioc->spi_data.dvStatus[pPDisk->PhysDiskID] |= MPT_SCSICFG_NEED_DV;

				pPDisk++;
				numPDisk--;
			}
		}
		ioc->spi_data.forceDv &= ~MPT_SCSICFG_RELOAD_IOC_PG3;
	}

	dvStatus = ioc->spi_data.dvStatus[id];

	if (dvStatus & MPT_SCSICFG_NEED_DV) {
		ioc->spi_data.dvStatus[id] |= MPT_SCSICFG_DV_IN_PROGRESS;
		ioc->spi_data.dvStatus[id] &= ~MPT_SCSICFG_NEED_DV;

//		set_current_state(TASK_INTERRUPTIBLE);
//		schedule_timeout(MPT_HZ/4);

		/* If hidden phys disk, block IO's to all
		 *	raid volumes
		 * else, process normally
		 */
		if (ioc->raid_data.isRaid & (1 << id)) {
			Ioc3PhysDisk_t *pPDisk =  ioc->raid_data.pIocPg3->PhysDisk;
			int numPDisk = ioc->raid_data.pIocPg3->NumPhysDisks;
			while (numPDisk) {
				ii = pPDisk->PhysDiskID;
				if ( ioc->spi_data.dvStatus[ii] & MPT_SCSICFG_DV_NOT_DONE) {
					ddvprintk((KERN_WARNING "doDv for PhysDiskNum=%d PhysDiskID=%d numPDisk=%d\n",
						pPDisk->PhysDiskNum, ii, numPDisk));
					if (mptscsih_doDv(hd, 0, ii) == 1) {
						/* Untagged device was busy, try again
						 */
						ioc->spi_data.dvStatus[ii] |= MPT_SCSICFG_NEED_DV;
					} else {
						ddvprintk((KERN_WARNING "doDv successful for PhysDiskNum=%d PhysDiskID=%d\n",
							pPDisk->PhysDiskNum, ii));
						/* DV is complete. Clear flags.
						 */
						ioc->spi_data.dvStatus[ii] &= ~MPT_SCSICFG_DV_NOT_DONE;
					}
				}
				pPDisk++;
				numPDisk--;
			}
		} else {
			ddvprintk((KERN_WARNING "doDv for id=%d\n",
				id));
			if (mptscsih_doDv(hd, 0, id) == 1) {
				/* Untagged device was busy, try again
				 */
				ioc->spi_data.dvStatus[id] |= MPT_SCSICFG_NEED_DV;
			} else {
				ddvprintk((KERN_WARNING "doDv successful for id=%d\n",
					id));
				/* DV is complete. Clear flags.
				 */
				ioc->spi_data.dvStatus[id] &= ~MPT_SCSICFG_DV_NOT_DONE;
			}
		}

		if (ioc->spi_data.noQas)
			mptscsih_qas_check(hd, id);
	} else {
		ddvprintk((KERN_INFO "~NEED_DV dvStatus=%x for id %d\n",
			dvStatus, id));
//		panic( "~NEED_DV");
	}
mptscsih_domainValidation_exit:
	spin_lock_irqsave(&dvtaskQ_lock, flags);
	dvtaskQ_active = 0;
	spin_unlock_irqrestore(&dvtaskQ_lock, flags);
}


/* Post command on the PendingMF to the FW.
 */
void
mptscsih_post_PendingMF_command(MPT_ADAPTER *ioc)
{
	MPT_SCSI_HOST	*hd;
	MPT_FRAME_HDR	*mf;
	struct scsi_cmnd *SCpnt;
	unsigned long	 flags;
	u16		 req_idx;

	spin_lock_irqsave(&ioc->PendingMFlock, flags);
	if ((mf=ioc->PendingMF) == NULL) {
		spin_unlock_irqrestore(&ioc->PendingMFlock, flags);
		dpendprintk((MYIOC_s_INFO_FMT "%s: PendingMF is empty\n", 
			ioc->name, __FUNCTION__));
		return;
	}

	mf = ioc->PendingMF;
	SCpnt = ioc->PendingSCpnt;
	ioc->PendingMF = NULL;
	spin_unlock_irqrestore(&ioc->PendingMFlock, flags);

	dpendprintk((MYIOC_s_INFO_FMT "mptscsih_post_PendingMF_command: mf=%p\n", 
		ioc->name, mf));
	DBG_DUMP_PENDING_REQUEST_FRAME(ioc, mf)

	hd = (MPT_SCSI_HOST *) ioc->sh->hostdata;
	req_idx = le16_to_cpu(mf->u.frame.hwhdr.msgctxu.fld.req_idx);
	ioc->ScsiLookup[req_idx] = SCpnt;
	mpt_put_msg_frame(ioc->DoneCtx, ioc, mf);
}


/* Search IOC page 3 to determine if this is hidden physical disk
 */
static int
mptscsih_is_phys_disk(MPT_ADAPTER *ioc, int channel, int id)
{
	struct inactive_raid_component_info *component_info;
	int i;
	int rc = 0;

	if (!ioc->raid_data.pIocPg3)
		goto out;
	for (i = 0; i < ioc->raid_data.pIocPg3->NumPhysDisks; i++) {
		if ((id == ioc->raid_data.pIocPg3->PhysDisk[i].PhysDiskID) &&
		    (channel == ioc->raid_data.pIocPg3->PhysDisk[i].PhysDiskBus)) {
			rc = 1;
			goto out;
		}
	}
	
	/*
	 * Check inactive list for matching phys disks
	 */
	if (list_empty(&ioc->raid_data.inactive_list))
		goto out;

	down(&ioc->raid_data.inactive_list_mutex);
	list_for_each_entry(component_info,
	    &ioc->raid_data.inactive_list, list) {
		if ((component_info->d.PhysDiskID == id) &&
		    (component_info->d.PhysDiskBus == channel))
			rc = 1;
	}
	up(&ioc->raid_data.inactive_list_mutex);

 out:
	return rc;
}

/* Write SDP1 if no QAS has been enabled
 */
static void
mptscsih_qas_check(MPT_SCSI_HOST *hd, int id)
{
	MPT_ADAPTER	*ioc = hd->ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice *pTarget;
	int ii;

	pMptTarget = ioc->Target_List[0];
	for (ii=0; ii < MPT_MAX_SCSI_DEVICES; ii++) {
		if (ii == id)
			continue;

		if ((ioc->spi_data.dvStatus[ii] & MPT_SCSICFG_DV_NOT_DONE) != 0)
			continue;

		pTarget = pMptTarget->Target[ii];

		if (pTarget) {
			if (!pTarget->raidVolume) {
				if ((pTarget->negoFlags & ioc->spi_data.noQas) == 0) {
					pTarget->negoFlags |= ioc->spi_data.noQas;
					dnegoprintk(("mptscsih_qas_check: writeSDP1: id=%d negoFlags=%d\n", ii, pTarget->negoFlags));
					mpt_writeSDP1(ioc, 0, ii, MPT_SCSICFG_USE_NVRAM);
				}
			} else {
				if (mptscsih_is_phys_disk(ioc, 0, ii) == 1) {
					dnegoprintk(("mptscsih_qas_check: is_phys_disk writeSDP1: id=%d SCSICFG_USE_NVRAM\n", ii));
					mpt_writeSDP1(ioc, 0, ii, MPT_SCSICFG_USE_NVRAM);
				}
			}
		}
	}
}


#define MPT_GET_NVRAM_VALS	0x01
#define MPT_UPDATE_MAX		0x02
#define MPT_SET_MAX		0x04
#define MPT_SET_MIN		0x08
#define MPT_FALLBACK		0x10
#define MPT_SAVE		0x20

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/**
 *	mptscsih_doDv - Perform domain validation to a target.
 *	@hd: Pointer to MPT_SCSI_HOST structure.
 *	@portnum: IOC port number.
 *	@target: Physical ID of this target
 *
 *	Uses the ISR, but with special processing.
 *	MUST be single-threaded.
 *	Test will exit if target is at async & narrow.
 *
 *	Return: None.
 */
static int
mptscsih_doDv(MPT_SCSI_HOST *hd, int bus, int id)
{
	MPT_ADAPTER		*ioc = hd->ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	SCSIDevicePage1_t	*pcfg1Data;
	SCSIDevicePage0_t	*pcfg0Data;
	u8			*pbuf1;
	u8			*pbuf2;
	u8			*pDvBuf=NULL;
	dma_addr_t		 dvbuf_dma = -1;
	dma_addr_t		 buf1_dma = -1;
	dma_addr_t		 buf2_dma = -1;
	dma_addr_t		 cfg1_dma_addr = -1;
	dma_addr_t		 cfg0_dma_addr = -1;
	ConfigPageHeader_t	 header1;
	ConfigPageHeader_t	 header0;
	DVPARAMETERS		 dv;
	INTERNAL_CMD		 iocmd;
	CONFIGPARMS		 cfg;
	int			 dv_alloc = 0;
	int			 rc, sz = 0;
	int			 bufsize = 0;
	int			 dataBufSize = 0;
	int			 echoBufSize = 0;
	int			 notDone;
	int			 patt;
	int			 repeat;
	int			 retcode = 0;
	int			 nfactor =  MPT_ULTRA320;
	char			 firstPass = 1;
	char			 doFallback = 0;
	char			 readPage0;
	char			 lun;
	char			 inq0 = 0;

	if (ioc->spi_data.sdp1length == 0)
		return 0;

	if (ioc->spi_data.sdp0length == 0)
		return 0;

	/* If multiple buses are used, require that the initiator
	 * id be the same on all buses.
	 */
	if (id == ioc->pfacts[0].PortSCSIID)
		return 0;

	ioc->spi_data.dvStatus[id] |= MPT_SCSICFG_DV_IN_PROGRESS;

	lun = 0;
	ddvprintk((MYIOC_s_INFO_FMT
			"DV Started: bus=%d id=%d dv @ %p\n",
			ioc->name, bus, id, &dv));

	/* Prep DV structure
	 */
	memset (&dv, 0, sizeof(DVPARAMETERS));
	dv.id = id;

	/* Populate tmax with the current maximum
	 * transfer parameters for this target.
	 * Exit if narrow and async.
	 */
	dv.cmd = MPT_GET_NVRAM_VALS;
	mptscsih_dv_parms(hd, &dv, NULL);

	/* Prep SCSI IO structure
	 */
	iocmd.id = id;
	iocmd.bus = bus;
	iocmd.lun = lun;
	iocmd.flags = 0;
	iocmd.physDiskNum = -1;
	iocmd.rsvd = iocmd.rsvd2 = 0;

	pMptTarget = ioc->Target_List[bus];
	pTarget = pMptTarget->Target[id];

	/* Use tagged commands if possible.
	 */
	if (pTarget) {
		if (pTarget->tflags & MPT_TARGET_FLAGS_Q_YES)
			iocmd.flags |= MPT_ICFLAG_TAGGED_CMD;
		else {
			if (ioc->facts.FWVersion.Word < 0x01000600)
				goto doDv_done;

			if ((ioc->facts.FWVersion.Word >= 0x01010000) &&
				(ioc->facts.FWVersion.Word < 0x01010B00))
				goto doDv_done;
		}
	}

	/* Prep cfg structure
	 */
	cfg.pageAddr = (bus<<8) | id;
	cfg.cfghdr.hdr = NULL;

	/* Prep SDP0 header
	 */
	header0.PageVersion = ioc->spi_data.sdp0version;
	header0.PageLength = ioc->spi_data.sdp0length;
	header0.PageNumber = 0;
	header0.PageType = MPI_CONFIG_PAGETYPE_SCSI_DEVICE;

	/* Prep SDP1 header
	 */
	header1.PageVersion = ioc->spi_data.sdp1version;
	header1.PageLength = ioc->spi_data.sdp1length;
	header1.PageNumber = 1;
	header1.PageType = MPI_CONFIG_PAGETYPE_SCSI_DEVICE;

	if (header0.PageLength & 1)
		dv_alloc = (header0.PageLength * 4) + 4;

	dv_alloc +=  (2048 + (header1.PageLength * 4));

	pDvBuf = pci_alloc_consistent(ioc->pcidev, dv_alloc, &dvbuf_dma);
	if (pDvBuf == NULL)
		goto doDv_done;

	sz = 0;
	pbuf1 = (u8 *)pDvBuf;
	buf1_dma = dvbuf_dma;
	sz +=1024;

	pbuf2 = (u8 *) (pDvBuf + sz);
	buf2_dma = dvbuf_dma + sz;
	sz +=1024;

	pcfg0Data = (SCSIDevicePage0_t *) (pDvBuf + sz);
	cfg0_dma_addr = dvbuf_dma + sz;
	sz += header0.PageLength * 4;

	/* 8-byte alignment
	 */
	if (header0.PageLength & 1)
		sz += 4;

	pcfg1Data = (SCSIDevicePage1_t *) (pDvBuf + sz);
	cfg1_dma_addr = dvbuf_dma + sz;

	/* Skip this ID? Set cfg.cfghdr.hdr to force config page write
	 */
	{
		SpiCfgData *pspi_data = &ioc->spi_data;
		if (pspi_data->nvram && (pspi_data->nvram[id] != MPT_HOST_NVRAM_INVALID)) {
			/* Set the factor from nvram */
			nfactor = (pspi_data->nvram[id] & MPT_NVRAM_SYNC_MASK) >> 8;
			if (nfactor < pspi_data->minSyncFactor )
				nfactor = pspi_data->minSyncFactor;

			if (!(pspi_data->nvram[id] & MPT_NVRAM_ID_SCAN_ENABLE) ||
				(pspi_data->PortFlags == MPI_SCSIPORTPAGE2_PORT_FLAGS_OFF_DV) ) {

				ddvprintk((MYIOC_s_INFO_FMT "DV Skipped: bus, id, lun (%d, %d, %d)\n",
					ioc->name, bus, id, lun));

				dv.cmd = MPT_SET_MAX;
				mptscsih_dv_parms(hd, &dv, (void *)pcfg1Data);
				cfg.cfghdr.hdr = &header1;

				/* Save the final negotiated settings to
				 * SCSI device page 1.
				 */
				cfg.physAddr = cfg1_dma_addr;
				cfg.action = MPI_CONFIG_ACTION_PAGE_WRITE_CURRENT;
				cfg.dir = 1;
				mpt_config(ioc, &cfg);
				goto target_done;
			}
		}
	}

	/* Finish iocmd inititialization - hidden or visible disk? */
	if (ioc->raid_data.pIocPg3) {
		/* Search IOC page 3 for matching id
		 */
		Ioc3PhysDisk_t *pPDisk =  ioc->raid_data.pIocPg3->PhysDisk;
		int		numPDisk = ioc->raid_data.pIocPg3->NumPhysDisks;

		while (numPDisk) {
			if (pPDisk->PhysDiskID == id) {
				/* match */
				iocmd.flags |= MPT_ICFLAG_PHYS_DISK;
				iocmd.physDiskNum = pPDisk->PhysDiskNum;

				/* Quiesce the IM
				 */
				if (mptscsih_do_raid(hd, MPI_RAID_ACTION_QUIESCE_PHYS_IO, &iocmd) < 0) {
					ddvprintk((MYIOC_s_ERR_FMT "RAID Queisce FAILED!\n", ioc->name));
					goto target_done;
				}
				break;
			}
			pPDisk++;
			numPDisk--;
		}
	}

	/* RAID Volume ID's may double for a physical device. If RAID but
	 * not a physical ID as well, skip DV.
	 */
	if ((ioc->raid_data.isRaid & (1 << id)) && !(iocmd.flags & MPT_ICFLAG_PHYS_DISK))
		goto target_done;


	/* Basic Test.
	 * Async & Narrow - Inquiry
	 * Async & Narrow - Inquiry
	 * Maximum transfer rate - Inquiry
	 * Compare buffers:
	 *	If compare, test complete.
	 *	If miscompare and first pass, repeat
	 *	If miscompare and not first pass, fall back and repeat
	 */
	hd->pLocal = NULL;
	readPage0 = 0;
	sz = SCSI_MAX_INQUIRY_BYTES;
	rc = MPT_SCANDV_GOOD;
start_DV:
	while (1) {
		ddvprintk((MYIOC_s_INFO_FMT "DV: Start Basic test on id=%d\n", ioc->name, id));
		retcode = 0;
		dv.cmd = MPT_SET_MIN;
		mptscsih_dv_parms(hd, &dv, (void *)pcfg1Data);

		cfg.cfghdr.hdr = &header1;
		cfg.physAddr = cfg1_dma_addr;
		cfg.action = MPI_CONFIG_ACTION_PAGE_WRITE_CURRENT;
		cfg.dir = 1;
		if (mpt_config(ioc, &cfg) != 0)
			goto target_done;

		/* Wide - narrow - wide workaround case
		 */
		if ((rc == MPT_SCANDV_ISSUE_SENSE) && dv.max.width) {
			/* Send an untagged command to reset disk Qs corrupted
			 * when a parity error occurs on a Request Sense.
			 */
			if ((ioc->facts.FWVersion.Word >= 0x01000600) ||
				((ioc->facts.FWVersion.Word >= 0x01010000) &&
				(ioc->facts.FWVersion.Word < 0x01010B00)) ) {

				iocmd.cmd = REQUEST_SENSE;
				iocmd.data_dma = buf1_dma;
				iocmd.data = pbuf1;
				iocmd.size = 0x12;
				if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
					goto target_done;
				else {
					if (hd->pLocal == NULL)
						goto target_done;
					rc = hd->pLocal->completion;
					if ((rc == MPT_SCANDV_GOOD) || (rc == MPT_SCANDV_SENSE)) {
						dv.max.width = 0;
						doFallback = 0;
					} else
						goto target_done;
				}
			} else
				goto target_done;
		}

		iocmd.cmd = INQUIRY;
		iocmd.data_dma = buf1_dma;
		iocmd.data = pbuf1;
		iocmd.size = sz;
		memset(pbuf1, 0x00, sz);
		if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
			goto target_done;
		else {
			if (hd->pLocal == NULL)
				goto target_done;
			rc = hd->pLocal->completion;
			if (rc == MPT_SCANDV_GOOD) {
				if (hd->pLocal->scsiStatus == SAM_STAT_BUSY) {
					if ((iocmd.flags & MPT_ICFLAG_TAGGED_CMD) == 0)
						retcode = 1;
					else
						retcode = 0;

					goto target_done;
				}
			} else if  (rc == MPT_SCANDV_SENSE) {
				;
			} else {
				/* If first command doesn't complete
				 * with a good status or with a check condition,
				 * exit.
				 */
				goto target_done;
			}
		}

		/* Reset the size for disks
		 */
		inq0 = (*pbuf1) & 0x1F;
		if ((inq0 == 0) && pTarget && !pTarget->raidVolume) {
			sz = 0x40;
			iocmd.size = sz;
		}

		/* Another GEM workaround. Check peripheral device type,
		 * if PROCESSOR, quit DV.
		 */
		if (inq0 == TYPE_PROCESSOR) {
			goto target_done;
		}

		if (inq0 > 0x08)
			goto target_done;

		if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
			goto target_done;

		if (sz == 0x40) {
			if ((pTarget->maxWidth == 1) && (pTarget->maxOffset) && (nfactor < 0x0A)
				&& (pTarget->minSyncFactor > 0x09)) {
				if ((pbuf1[56] & 0x04) == 0)
					;
				else if ((pbuf1[56] & 0x01) == 1) {
					pTarget->minSyncFactor =
					    nfactor > MPT_ULTRA320 ? nfactor : MPT_ULTRA320;
				} else {
					pTarget->minSyncFactor =
					    nfactor > MPT_ULTRA160 ? nfactor : MPT_ULTRA160;
				}

				dv.max.factor = pTarget->minSyncFactor;

				if ((pbuf1[56] & 0x02) == 0) {
					pTarget->negoFlags |= MPT_TARGET_NO_NEGO_QAS;
					ioc->spi_data.noQas = MPT_TARGET_NO_NEGO_QAS;
					ddvprintk((MYIOC_s_INFO_FMT 
					    "DV: Start Basic noQas on id=%d due to pbuf1[56]=%x\n", 
					    ioc->name, id, pbuf1[56]));
				}
			}
		}

		if (doFallback)
			dv.cmd = MPT_FALLBACK;
		else
			dv.cmd = MPT_SET_MAX;

		mptscsih_dv_parms(hd, &dv, (void *)pcfg1Data);
		if (mpt_config(ioc, &cfg) != 0)
			goto target_done;

		if ((!dv.now.width) && (!dv.now.offset))
			goto target_done;

		iocmd.cmd = INQUIRY;
		iocmd.data_dma = buf2_dma;
		iocmd.data = pbuf2;
		iocmd.size = sz;
		memset(pbuf2, 0x00, sz);
		if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
			goto target_done;
		else if (hd->pLocal == NULL)
			goto target_done;
		else {
			/* Save the return code.
			 * If this is the first pass,
			 * read SCSI Device Page 0
			 * and update the target max parameters.
			 */
			rc = hd->pLocal->completion;
			doFallback = 0;
			if (rc == MPT_SCANDV_GOOD) {
				if (!readPage0) {
					u32 sdp0_info;
					u32 sdp0_nego;

					cfg.cfghdr.hdr = &header0;
					cfg.physAddr = cfg0_dma_addr;
					cfg.action = MPI_CONFIG_ACTION_PAGE_READ_CURRENT;
					cfg.dir = 0;

					if (mpt_config(ioc, &cfg) != 0)
						goto target_done;

					sdp0_info = le32_to_cpu(pcfg0Data->Information) & 0x0E;
					sdp0_nego = (le32_to_cpu(pcfg0Data->NegotiatedParameters) & 0xFF00 ) >> 8;

					/* Quantum and Fujitsu workarounds.
					 * Quantum: PPR U320 -> PPR reply with Ultra2 and wide
					 * Fujitsu: PPR U320 -> Msg Reject and Ultra2 and wide
					 * Resetart with a request for U160.
					 */
					if ((dv.now.factor == MPT_ULTRA320) && (sdp0_nego == MPT_ULTRA2)) {
							doFallback = 1;
					} else {
						dv.cmd = MPT_UPDATE_MAX;
						mptscsih_dv_parms(hd, &dv, (void *)pcfg0Data);
						/* Update the SCSI device page 1 area
						 */
						pcfg1Data->RequestedParameters = pcfg0Data->NegotiatedParameters;
						readPage0 = 1;
					}
				}

				/* Quantum workaround. Restart this test will the fallback
				 * flag set.
				 */
				if (doFallback == 0) {
					if (memcmp(pbuf1, pbuf2, sz) != 0) {
						if (!firstPass)
							doFallback = 1;
					} else {
						break;	/* test complete */
					}
				}
			} else if (rc == MPT_SCANDV_ISSUE_SENSE)
				doFallback = 1;	/* set fallback flag */
			else if ((rc == MPT_SCANDV_DID_RESET) ||
				 (rc == MPT_SCANDV_SENSE) ||
				 (rc == MPT_SCANDV_FALLBACK))
				doFallback = 1;	/* set fallback flag */
			else
				goto target_done;

			firstPass = 0;
		}
	}
	ddvprintk((MYIOC_s_INFO_FMT "DV: Basic test on id=%d completed OK.\n", ioc->name, id));

	if (ioc->spi_data.mpt_dv == 0)
		goto target_done;

	inq0 = (*pbuf1) & 0x1F;

	/* Continue only for disks
	 */
	if (inq0 != 0)
		goto target_done;

	ddvprintk((MYIOC_s_INFO_FMT "DV: bus, id, lun (%d, %d, %d) PortFlags=%x\n",
			ioc->name, bus, id, lun, ioc->spi_data.PortFlags));
	if ( ioc->spi_data.PortFlags == MPI_SCSIPORTPAGE2_PORT_FLAGS_BASIC_DV_ONLY ) {
		ddvprintk((MYIOC_s_INFO_FMT "DV Basic Only: bus, id, lun (%d, %d, %d) PortFlags=%x\n",
			ioc->name, bus, id, lun, ioc->spi_data.PortFlags));
		goto target_done;
	}

	/* Start the Enhanced Test.
	 * 0) issue TUR to clear out check conditions
	 * 1) read capacity of echo (regular) buffer
	 * 2) reserve device
	 * 3) do write-read-compare data pattern test
	 * 4) release
	 * 5) update nego parms to target struct
	 */
	cfg.cfghdr.hdr = &header1;
	cfg.physAddr = cfg1_dma_addr;
	cfg.action = MPI_CONFIG_ACTION_PAGE_WRITE_CURRENT;
	cfg.dir = 1;

	iocmd.cmd = TEST_UNIT_READY;
	iocmd.data_dma = -1;
	iocmd.data = NULL;
	iocmd.size = 0;
	notDone = 1;
	while (notDone) {
		if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
			goto target_done;

		if (hd->pLocal == NULL)
			goto target_done;

		rc = hd->pLocal->completion;
		if (rc == MPT_SCANDV_GOOD)
			notDone = 0;
		else if (rc == MPT_SCANDV_SENSE) {
			u8 skey = hd->pLocal->sense[2] & 0x0F;
			u8 asc = hd->pLocal->sense[12];
			u8 ascq = hd->pLocal->sense[13];
			ddvprintk((MYIOC_s_WARN_FMT
				"SenseKey:ASC:ASCQ = (%x:%02x:%02x)\n",
				ioc->name, skey, asc, ascq));

			if (skey == UNIT_ATTENTION)
				notDone++; /* repeat */
			else if ((skey == NOT_READY) &&
					(asc == 0x04)&&(ascq == 0x01)) {
				/* wait then repeat */
				mdelay(2000);
				notDone++;
			} else if ((skey == NOT_READY) && (asc == 0x3A)) {
				/* no medium, try read test anyway */
				notDone = 0;
			} else {
				/* All other errors are fatal.
				 */
				ddvprintk((MYIOC_s_INFO_FMT "DV: fatal error.",
						ioc->name));
				goto target_done;
			}
		} else
			goto target_done;
	}

	iocmd.cmd = READ_BUFFER;
	iocmd.data_dma = buf1_dma;
	iocmd.data = pbuf1;
	iocmd.size = 4;
	iocmd.flags |= MPT_ICFLAG_BUF_CAP;

	dataBufSize = 0;
	echoBufSize = 0;
	for (patt = 0; patt < 2; patt++) {
		if (patt == 0)
			iocmd.flags |= MPT_ICFLAG_ECHO;
		else
			iocmd.flags &= ~MPT_ICFLAG_ECHO;

		notDone = 1;
		while (notDone) {
			bufsize = 0;

			/* If not ready after 8 trials,
			 * give up on this device.
			 */
			if (notDone > 8)
				goto target_done;

			if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
				goto target_done;
			else if (hd->pLocal == NULL)
				goto target_done;
			else {
				rc = hd->pLocal->completion;
				ddvprintk(("ReadBuffer Comp Code %d", rc));
				ddvprintk(("  buff: %0x %0x %0x %0x\n",
					pbuf1[0], pbuf1[1], pbuf1[2], pbuf1[3]));

				if (rc == MPT_SCANDV_GOOD) {
					notDone = 0;
					if (iocmd.flags & MPT_ICFLAG_ECHO) {
						bufsize =  ((pbuf1[2] & 0x1F) <<8) | pbuf1[3];
						if (pbuf1[0] & 0x01)
							iocmd.flags |= MPT_ICFLAG_EBOS;
					} else {
						bufsize =  pbuf1[1]<<16 | pbuf1[2]<<8 | pbuf1[3];
					}
				} else if (rc == MPT_SCANDV_SENSE) {
					u8 skey = hd->pLocal->sense[2] & 0x0F;
					u8 asc = hd->pLocal->sense[12];
					u8 ascq = hd->pLocal->sense[13];
					ddvprintk((MYIOC_s_WARN_FMT
						"SenseKey:ASC:ASCQ = (%x:%02x:%02x)\n",
						ioc->name, skey, asc, ascq));
					if (skey == ILLEGAL_REQUEST) {
						notDone = 0;
					} else if (skey == UNIT_ATTENTION) {
						notDone++; /* repeat */
					} else if ((skey == NOT_READY) &&
						(asc == 0x04)&&(ascq == 0x01)) {
						/* wait then repeat */
						mdelay(2000);
						notDone++;
					} else {
						/* All other errors are fatal.
						 */
						ddvprintk((MYIOC_s_INFO_FMT "DV: fatal error.",
							ioc->name));
						goto target_done;
					}
				} else if (rc == MPT_SCANDV_FALLBACK) {
					doFallback = 1;	/* set fallback flag */
					notDone++;
					goto start_DV;
				} else {
					/* All other errors are fatal
					 */
					goto target_done;
				}
			}
		}

		if (iocmd.flags & MPT_ICFLAG_ECHO)
			echoBufSize = bufsize;
		else
			dataBufSize = bufsize;
	}
	sz = 0;
	iocmd.flags &= ~MPT_ICFLAG_BUF_CAP;

	/* Use echo buffers if possible,
	 * Exit if both buffers are 0.
	 */
	if (echoBufSize > 0) {
		iocmd.flags |= MPT_ICFLAG_ECHO;
		if (dataBufSize > 0)
			bufsize = min(echoBufSize, dataBufSize);
		else
			bufsize = echoBufSize;
	} else if (dataBufSize == 0)
		goto target_done;

	ddvprintk((MYIOC_s_INFO_FMT "%s Buffer Capacity %d\n", ioc->name,
		(iocmd.flags & MPT_ICFLAG_ECHO) ? "Echo" : " ", bufsize));

	/* Data buffers for write-read-compare test max 1K.
	 */
	sz = min(bufsize, 1024);

	/* --- loop ----
	 * On first pass, always issue a reserve.
	 * On additional loops, only if a reset has occurred.
	 * iocmd.flags indicates if echo or regular buffer
	 */
	for (patt = 0; patt < 4; patt++) {
		ddvprintk(("Pattern %d\n", patt));
		if ((iocmd.flags & MPT_ICFLAG_RESERVED) && (iocmd.flags & MPT_ICFLAG_DID_RESET)) {
			iocmd.cmd = TEST_UNIT_READY;
			iocmd.data_dma = -1;
			iocmd.data = NULL;
			iocmd.size = 0;
			if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
				goto target_done;

			iocmd.cmd = RELEASE;
			iocmd.data_dma = -1;
			iocmd.data = NULL;
			iocmd.size = 0;
			if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
				goto target_done;
			else if (hd->pLocal == NULL)
				goto target_done;
			else {
				rc = hd->pLocal->completion;
				ddvprintk(("Release rc %d\n", rc));
				if (rc == MPT_SCANDV_GOOD)
					iocmd.flags &= ~MPT_ICFLAG_RESERVED;
				else
					goto target_done;
			}
			iocmd.flags &= ~MPT_ICFLAG_RESERVED;
		}
		iocmd.flags &= ~MPT_ICFLAG_DID_RESET;

		if (iocmd.flags & MPT_ICFLAG_EBOS)
			goto skip_Reserve;

		repeat = 5;
		while (repeat && (!(iocmd.flags & MPT_ICFLAG_RESERVED))) {
			iocmd.cmd = RESERVE;
			iocmd.data_dma = -1;
			iocmd.data = NULL;
			iocmd.size = 0;
			if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
				goto target_done;
			else if (hd->pLocal == NULL)
				goto target_done;
			else {
				rc = hd->pLocal->completion;
				if (rc == MPT_SCANDV_GOOD) {
					iocmd.flags |= MPT_ICFLAG_RESERVED;
				} else if (rc == MPT_SCANDV_SENSE) {
					/* Wait if coming ready
					 */
					u8 skey = hd->pLocal->sense[2] & 0x0F;
					u8 asc = hd->pLocal->sense[12];
					u8 ascq = hd->pLocal->sense[13];
					ddvprintk((MYIOC_s_INFO_FMT
						"DV: Reserve Failed: ", ioc->name));
					ddvprintk(("SenseKey:ASC:ASCQ = (%x:%02x:%02x)\n",
							skey, asc, ascq));

					if ((skey == NOT_READY) && (asc == 0x04)&&
									(ascq == 0x01)) {
						/* wait then repeat */
						mdelay(2000);
						notDone++;
					} else {
						ddvprintk((MYIOC_s_INFO_FMT
							"DV: Reserved Failed.", ioc->name));
						goto target_done;
					}
				} else {
					ddvprintk((MYIOC_s_INFO_FMT "DV: Reserved Failed.",
							 ioc->name));
					goto target_done;
				}
			}
		}

skip_Reserve:
		mptscsih_fillbuf(pbuf1, sz, patt, 1);
		iocmd.cmd = WRITE_BUFFER;
		iocmd.data_dma = buf1_dma;
		iocmd.data = pbuf1;
		iocmd.size = sz;
		if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
			goto target_done;
		else if (hd->pLocal == NULL)
			goto target_done;
		else {
			rc = hd->pLocal->completion;
			if (rc == MPT_SCANDV_GOOD)
				;		/* Issue read buffer */
			else if (rc == MPT_SCANDV_DID_RESET) {
				/* If using echo buffers, reset to data buffers.
				 * Else do Fallback and restart
				 * this test (re-issue reserve
				 * because of bus reset).
				 */
				if ((iocmd.flags & MPT_ICFLAG_ECHO) && (dataBufSize >= bufsize)) {
					iocmd.flags &= ~MPT_ICFLAG_ECHO;
				} else {
					dv.cmd = MPT_FALLBACK;
					mptscsih_dv_parms(hd, &dv, (void *)pcfg1Data);

					if (mpt_config(ioc, &cfg) != 0)
						goto target_done;

					if ((!dv.now.width) && (!dv.now.offset))
						goto target_done;
				}

				iocmd.flags |= MPT_ICFLAG_DID_RESET;
				patt = -1;
				continue;
			} else if (rc == MPT_SCANDV_SENSE) {
				/* Restart data test if UA, else quit.
				 */
				u8 skey = hd->pLocal->sense[2] & 0x0F;
				ddvprintk((MYIOC_s_WARN_FMT
					"SenseKey:ASC:ASCQ = (%x:%02x:%02x)\n", ioc->name, skey,
					hd->pLocal->sense[12], hd->pLocal->sense[13]));
				if (skey == UNIT_ATTENTION) {
					patt = -1;
					continue;
				} else if (skey == ILLEGAL_REQUEST) {
					if (iocmd.flags & MPT_ICFLAG_ECHO) {
						if (dataBufSize >= bufsize) {
							iocmd.flags &= ~MPT_ICFLAG_ECHO;
							patt = -1;
							continue;
						}
					}
					goto target_done;
				}
				else
					goto target_done;
			} else {
				/* fatal error */
				goto target_done;
			}
		}

		iocmd.cmd = READ_BUFFER;
		iocmd.data_dma = buf2_dma;
		iocmd.data = pbuf2;
		iocmd.size = sz;
		if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
			goto target_done;
		else if (hd->pLocal == NULL)
			goto target_done;
		else {
			rc = hd->pLocal->completion;
			if (rc == MPT_SCANDV_GOOD) {
				 /* If buffers compare,
				  * go to next pattern,
				  * else, do a fallback and restart
				  * data transfer test.
				  */
				if (memcmp (pbuf1, pbuf2, sz) == 0) {
					; /* goto next pattern */
				} else {
					/* Miscompare with Echo buffer, go to data buffer,
					 * if that buffer exists.
					 * Miscompare with Data buffer, check first 4 bytes,
					 * some devices return capacity. Exit in this case.
					 */
					if (iocmd.flags & MPT_ICFLAG_ECHO) {
						if (dataBufSize >= bufsize)
							iocmd.flags &= ~MPT_ICFLAG_ECHO;
						else
							goto target_done;
					} else {
						if (dataBufSize == (pbuf2[1]<<16 | pbuf2[2]<<8 | pbuf2[3])) {
							/* Argh. Device returning wrong data.
							 * Quit DV for this device.
							 */
							goto target_done;
						}

						/* Had an actual miscompare. Slow down.*/
						dv.cmd = MPT_FALLBACK;
						mptscsih_dv_parms(hd, &dv, (void *)pcfg1Data);

						if (mpt_config(ioc, &cfg) != 0)
							goto target_done;

						if ((!dv.now.width) && (!dv.now.offset))
							goto target_done;
					}

					patt = -1;
					continue;
				}
			} else if (rc == MPT_SCANDV_DID_RESET) {
				/* Do Fallback and restart
				 * this test (re-issue reserve
				 * because of bus reset).
				 */
				dv.cmd = MPT_FALLBACK;
				mptscsih_dv_parms(hd, &dv, (void *)pcfg1Data);

				if (mpt_config(ioc, &cfg) != 0)
					 goto target_done;

				if ((!dv.now.width) && (!dv.now.offset))
					goto target_done;

				iocmd.flags |= MPT_ICFLAG_DID_RESET;
				patt = -1;
				continue;
			} else if (rc == MPT_SCANDV_SENSE) {
				/* Restart data test if UA, else quit.
				 */
				u8 skey = hd->pLocal->sense[2] & 0x0F;
				ddvprintk((MYIOC_s_WARN_FMT
					"SenseKey:ASC:ASCQ = (%x:%02x:%02x)\n", ioc->name, skey,
					hd->pLocal->sense[12], hd->pLocal->sense[13]));
				if (skey == UNIT_ATTENTION) {
					patt = -1;
					continue;
				}
				else
					goto target_done;
			} else {
				/* fatal error */
				goto target_done;
			}
		}

	} /* --- end of patt loop ---- */

target_done:
	if (iocmd.flags & MPT_ICFLAG_RESERVED) {
		iocmd.cmd = RELEASE;
		iocmd.data_dma = -1;
		iocmd.data = NULL;
		iocmd.size = 0;
		if (mptscsih_do_DVcmd(hd, &iocmd) < 0)
			printk(MYIOC_s_INFO_FMT "DV: Release failed. id %d",
					ioc->name, id);
		else if (hd->pLocal) {
			if (hd->pLocal->completion == MPT_SCANDV_GOOD)
				iocmd.flags &= ~MPT_ICFLAG_RESERVED;
		} else {
			printk(MYIOC_s_INFO_FMT "DV: Release failed. id %d",
						ioc->name, id);
		}
	}


	/* Set if cfg1_dma_addr contents is valid
	 */
	if ((cfg.cfghdr.hdr != NULL) && (retcode == 0)){
		/* If disk, not U320, disable QAS
		 */
		if ((inq0 == 0) && (dv.now.factor > MPT_ULTRA320)) {
			ioc->spi_data.noQas = MPT_TARGET_NO_NEGO_QAS;
			ddvprintk((MYIOC_s_INFO_FMT
			    "noQas set due to id=%d has factor=%x\n", ioc->name, id, dv.now.factor));
		}

		dv.cmd = MPT_SAVE;
		mptscsih_dv_parms(hd, &dv, (void *)pcfg1Data);

		/* Double writes to SDP1 can cause problems,
		 * skip save of the final negotiated settings to
		 * SCSI device page 1.
		 *
		cfg.cfghdr.hdr = &header1;
		cfg.physAddr = cfg1_dma_addr;
		cfg.action = MPI_CONFIG_ACTION_PAGE_WRITE_CURRENT;
		cfg.dir = 1;
		mpt_config(ioc, &cfg);
		 */
	}

	/* If this is a RAID Passthrough, enable internal IOs
	 */
	if (iocmd.flags & MPT_ICFLAG_PHYS_DISK) {
		if (mptscsih_do_raid(hd, MPI_RAID_ACTION_ENABLE_PHYS_IO, &iocmd) < 0)
			ddvprintk((MYIOC_s_ERR_FMT "RAID Enable FAILED!\n", ioc->name));
	}

doDv_done:
	/* Done with the DV scan of the current target
	 */
	if (pDvBuf)
		pci_free_consistent(ioc->pcidev, dv_alloc, pDvBuf, dvbuf_dma);

	ddvprintk((MYIOC_s_WARN_FMT "DV Done id=%d retcode=%x\n",
			ioc->name, id, retcode));

	ioc->spi_data.dvStatus[id] &= ~(MPT_SCSICFG_DV_NOT_DONE | MPT_SCSICFG_DV_IN_PROGRESS);
	/* Post an IO that was pended while
	 * DV was running.
	 */
	mptscsih_post_PendingMF_command(ioc);

	return retcode;
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mptscsih_dv_parms - perform a variety of operations on the
 *	parameters used for negotiation.
 *	@hd: Pointer to a SCSI host.
 *	@dv: Pointer to a structure that contains the maximum and current
 *		negotiated parameters.
 */
static void
mptscsih_dv_parms(MPT_SCSI_HOST *hd, DVPARAMETERS *dv,void *pPage)
{
	MPT_ADAPTER		*ioc = hd->ioc;
	struct _MPT_DEVICE	*pMptTarget;
	VirtDevice		*pTarget;
	SCSIDevicePage0_t	*pPage0;
	SCSIDevicePage1_t	*pPage1;
	int			val = 0, data, configuration;
	u8			width = 0;
	u8			offset = 0;
	u8			factor = 0;
	u8			negoFlags = 0;
	u8			cmd = dv->cmd;
	u8			id = dv->id;

	switch (cmd) {
	case MPT_GET_NVRAM_VALS:
		ddvprintk((MYIOC_s_INFO_FMT "Getting NVRAM: ",
			ioc->name));
		/* Get the NVRAM values and save in tmax
		 * If not an LVD bus, the adapter minSyncFactor has been
		 * already throttled back.
		 */
		negoFlags = ioc->spi_data.noQas;
		pMptTarget = ioc->Target_List[0];
		pTarget = pMptTarget->Target[id];
		if (ioc->spi_data.nvram && (ioc->spi_data.nvram[id] != MPT_HOST_NVRAM_INVALID)) {
			data = ioc->spi_data.nvram[id];
			width = data & MPT_NVRAM_WIDE_DISABLE ? 0 : 1;
			if ((offset = ioc->spi_data.maxSyncOffset) == 0)
				factor = MPT_ASYNC;
			else {
				factor = (data & MPT_NVRAM_SYNC_MASK) >> MPT_NVRAM_SYNC_SHIFT;
				if ((factor == 0) || (factor == MPT_ASYNC)){
					factor = MPT_ASYNC;
					offset = 0;
				}
			ddvprintk(("NVRAM id=%d width=%d factor=%x offset=%x negoFlags=%x\n",
				id, width, factor, offset, negoFlags));
			}
		} else {
			width = MPT_NARROW;
			offset = 0;
			factor = MPT_ASYNC;
			ddvprintk(("NVRAM_INVALID id=%d width=%d factor=%x offset=%x negoFlags=%x\n",
				id, width, factor, offset, negoFlags));
		}

		/* Set the negotiation flags */
		if (!width)
			negoFlags |= MPT_TARGET_NO_NEGO_WIDE;

		if (!offset)
			negoFlags |= MPT_TARGET_NO_NEGO_SYNC;

		/* limit by adapter capabilities */
		width = min(width, ioc->spi_data.maxBusWidth);
		offset = min(offset, ioc->spi_data.maxSyncOffset);
		factor = max(factor, ioc->spi_data.minSyncFactor);

		/* Check Consistency */
		if (offset && (factor < MPT_ULTRA2) && !width)
			factor = MPT_ULTRA2;

		dv->max.width = width;
		dv->max.offset = offset;
		dv->max.factor = factor;
		dv->max.flags = negoFlags;
		ddvprintk(("id=%d width=%d factor=%x offset=%x negoFlags=%x\n",
				id, width, factor, offset, negoFlags));
		break;

	case MPT_UPDATE_MAX:
		ddvprintk((MYIOC_s_INFO_FMT
			"Updating with SDP0 Data: ", ioc->name));
		/* Update tmax values with those from Device Page 0.*/
		pPage0 = (SCSIDevicePage0_t *) pPage;
		if (pPage0) {
			val = le32_to_cpu(pPage0->NegotiatedParameters);
			dv->max.width = val & MPI_SCSIDEVPAGE0_NP_WIDE ? 1 : 0;
			dv->max.offset = (val&MPI_SCSIDEVPAGE0_NP_NEG_SYNC_OFFSET_MASK) >> 16;
			dv->max.factor = (val&MPI_SCSIDEVPAGE0_NP_NEG_SYNC_PERIOD_MASK) >> 8;
		}

		dv->now.width = dv->max.width;
		dv->now.offset = dv->max.offset;
		dv->now.factor = dv->max.factor;
		ddvprintk(("id=%d width=%d factor=%x offset=%x negoFlags=%x\n",
			id, dv->now.width, dv->now.factor, dv->now.offset, dv->now.flags));
		break;

	case MPT_SET_MAX:
		/* Set current to the max values. Update the config page.*/
		dv->now.width = dv->max.width;
		dv->now.offset = dv->max.offset;
		dv->now.factor = dv->max.factor;
		dv->now.flags = dv->max.flags;

		pPage1 = (SCSIDevicePage1_t *)pPage;
		if (pPage1) {
			mpt_setSDP1parameters (dv->now.width, dv->now.factor, dv->now.offset, dv->now.flags, 
				&val, &configuration);
			pPage1->RequestedParameters = cpu_to_le32(val);
			pPage1->Reserved = 0;
			pPage1->Configuration = cpu_to_le32(configuration);
		}

		dnegoprintk(("%s: Setting Max: id=%d width=%d factor=%x offset=%x negoFlags=%x requested=%08x configuration=%08x\n",
				ioc->name, id, dv->now.width, dv->now.factor, dv->now.offset, dv->now.flags, val, configuration));
		break;

	case MPT_SET_MIN:
		/* Set page to asynchronous and narrow
		 * Do not update now, breaks fallback routine. */
		width = MPT_NARROW;
		offset = 0;
		factor = MPT_ASYNC;
		negoFlags = dv->max.flags;

		pPage1 = (SCSIDevicePage1_t *)pPage;
		if (pPage1) {
			mpt_setSDP1parameters (width, factor, offset, negoFlags,
				&val, &configuration);
			pPage1->RequestedParameters = cpu_to_le32(val);
			pPage1->Reserved = 0;
			pPage1->Configuration = cpu_to_le32(configuration);
		}
		dnegoprintk(("%s: Setting Min: id=%d width=%d factor=%x offset=%x negoFlags=%x requested=%08x configuration=%08x\n",
				ioc->name, id, width, factor, offset, negoFlags, val, configuration));
		break;

	case MPT_FALLBACK:
		ddvprintk((MYIOC_s_INFO_FMT
			"Fallback: Start: offset %d, factor %x, width %d \n",
				ioc->name, dv->now.offset,
				dv->now.factor, dv->now.width));
		width = dv->now.width;
		offset = dv->now.offset;
		factor = dv->now.factor;
		if ((offset) && (dv->max.width)) {
			if (factor < MPT_ULTRA160)
				factor = MPT_ULTRA160;
			else if (factor < MPT_ULTRA2) {
				factor = MPT_ULTRA2;
				width = MPT_WIDE;
			} else if ((factor == MPT_ULTRA2) && width) {
				factor = MPT_ULTRA2;
				width = MPT_NARROW;
			} else if (factor < MPT_ULTRA) {
				factor = MPT_ULTRA;
				width = MPT_WIDE;
			} else if ((factor == MPT_ULTRA) && width) {
				width = MPT_NARROW;
			} else if (factor < MPT_FAST) {
				factor = MPT_FAST;
				width = MPT_WIDE;
			} else if ((factor == MPT_FAST) && width) {
				factor = MPT_FAST;
				width = MPT_NARROW;
			} else if (factor < MPT_SCSI) {
				factor = MPT_SCSI;
				width = MPT_WIDE;
			} else if ((factor == MPT_SCSI) && width) {
				factor = MPT_SCSI;
				width = MPT_NARROW;
			} else {
				factor = MPT_ASYNC;
				offset = 0;
			}

		} else if (offset) {
			width = MPT_NARROW;
			if (factor < MPT_ULTRA)
				factor = MPT_ULTRA;
			else if (factor < MPT_FAST)
				factor = MPT_FAST;
			else if (factor < MPT_SCSI)
				factor = MPT_SCSI;
			else {
				factor = MPT_ASYNC;
				offset = 0;
			}

		} else {
			width = MPT_NARROW;
			factor = MPT_ASYNC;
		}
		dv->max.flags |= MPT_TARGET_NO_NEGO_QAS;
		dv->max.flags &= ~MPT_TAPE_NEGO_IDP;

		dv->now.width = width;
		dv->now.offset = offset;
		dv->now.factor = factor;
		dv->now.flags = dv->max.flags;

		pPage1 = (SCSIDevicePage1_t *)pPage;
		if (pPage1) {
			mpt_setSDP1parameters (width, factor, offset, dv->now.flags,
				&val, &configuration);

			pPage1->RequestedParameters = cpu_to_le32(val);
			pPage1->Reserved = 0;
			pPage1->Configuration = cpu_to_le32(configuration);
		}

		ddvprintk(("%s: Finish: id=%d width=%d offset=%d factor=%x negoFlags=%x requested=%08x configuration=%08x\n",
			     ioc->name, id, width, offset, factor, dv->now.flags, val, configuration));
		break;

	case MPT_SAVE:
		ddvprintk((MYIOC_s_INFO_FMT
			"Saving to pTarget: "
			"id=%d width=%x factor=%x offset=%d negoFlags=%x\n",
				ioc->name, id, dv->now.width, dv->now.factor, 
				dv->now.offset, dv->now.flags));

		/* Save these values to target structures
		 * or overwrite nvram (phys disks only).
		 */

		pMptTarget = ioc->Target_List[0];
		pTarget = pMptTarget->Target[id];
		if (pTarget && !pTarget->raidVolume ) {
			pTarget->maxWidth = dv->now.width;
			pTarget->maxOffset = dv->now.offset;
			pTarget->minSyncFactor = dv->now.factor;
			pTarget->negoFlags = dv->now.flags;
		} else {
			/* Preserv all flags, use
			 * read-modify-write algorithm
			 */
			if (ioc->spi_data.nvram) {
				data = ioc->spi_data.nvram[id];

				if (dv->now.width)
					data &= ~MPT_NVRAM_WIDE_DISABLE;
				else
					data |= MPT_NVRAM_WIDE_DISABLE;

				if (!dv->now.offset)
					factor = MPT_ASYNC;

				data &= ~MPT_NVRAM_SYNC_MASK;
				data |= (dv->now.factor << MPT_NVRAM_SYNC_SHIFT) & MPT_NVRAM_SYNC_MASK;

				ioc->spi_data.nvram[id] = data;
			}
		}
		break;
	}
}

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*	mptscsih_fillbuf - fill a buffer with a special data pattern
 *		cleanup. For bus scan only.
 *
 *	@buffer: Pointer to data buffer to be filled.
 *	@size: Number of bytes to fill
 *	@index: Pattern index
 *	@width: bus width, 0 (8 bits) or 1 (16 bits)
 */
static void
mptscsih_fillbuf(char *buffer, int size, int index, int width)
{
	char *ptr = buffer;
	int ii;
	char byte;
	short val;

	switch (index) {
	case 0:

		if (width) {
			/* Pattern:  0000 FFFF 0000 FFFF
			 */
			for (ii=0; ii < size; ii++, ptr++) {
				if (ii & 0x02)
					*ptr = 0xFF;
				else
					*ptr = 0x00;
			}
		} else {
			/* Pattern:  00 FF 00 FF
			 */
			for (ii=0; ii < size; ii++, ptr++) {
				if (ii & 0x01)
					*ptr = 0xFF;
				else
					*ptr = 0x00;
			}
		}
		break;

	case 1:
		if (width) {
			/* Pattern:  5555 AAAA 5555 AAAA 5555
			 */
			for (ii=0; ii < size; ii++, ptr++) {
				if (ii & 0x02)
					*ptr = 0xAA;
				else
					*ptr = 0x55;
			}
		} else {
			/* Pattern:  55 AA 55 AA 55
			 */
			for (ii=0; ii < size; ii++, ptr++) {
				if (ii & 0x01)
					*ptr = 0xAA;
				else
					*ptr = 0x55;
			}
		}
		break;

	case 2:
		/* Pattern:  00 01 02 03 04 05
		 * ... FE FF 00 01..
		 */
		for (ii=0; ii < size; ii++, ptr++)
			*ptr = (char) ii;
		break;

	case 3:
		if (width) {
			/* Wide Pattern:  FFFE 0001 FFFD 0002
			 * ...  4000 DFFF 8000 EFFF
			 */
			byte = 0;
			for (ii=0; ii < size/2; ii++) {
				/* Create the base pattern
				 */
				val = (1 << byte);
				/* every 64 (0x40) bytes flip the pattern
				 * since we fill 2 bytes / iteration,
				 * test for ii = 0x20
				 */
				if (ii & 0x20)
					val = ~(val);

				if (ii & 0x01) {
					*ptr = (char)( (val & 0xFF00) >> 8);
					ptr++;
					*ptr = (char)(val & 0xFF);
					byte++;
					byte &= 0x0F;
				} else {
					val = ~val;
					*ptr = (char)( (val & 0xFF00) >> 8);
					ptr++;
					*ptr = (char)(val & 0xFF);
				}

				ptr++;
			}
		} else {
			/* Narrow Pattern:  FE 01 FD 02 FB 04
			 * .. 7F 80 01 FE 02 FD ...  80 7F
			 */
			byte = 0;
			for (ii=0; ii < size; ii++, ptr++) {
				/* Base pattern - first 32 bytes
				 */
				if (ii & 0x01) {
					*ptr = (1 << byte);
					byte++;
					byte &= 0x07;
				} else {
					*ptr = (char) (~(1 << byte));
				}

				/* Flip the pattern every 32 bytes
				 */
				if (ii & 0x20)
					*ptr = ~(*ptr);
			}
		}
		break;
	}
}
#endif /* ~MPTSCSIH_ENABLE_DOMAIN_VALIDATION */

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/

EXPORT_SYMBOL(mptscsih_remove);
EXPORT_SYMBOL(mptscsih_shutdown);
#ifdef CONFIG_PM
EXPORT_SYMBOL(mptscsih_suspend);
EXPORT_SYMBOL(mptscsih_resume);
#endif
EXPORT_SYMBOL(mptscsih_proc_info);
EXPORT_SYMBOL(mptscsih_info);
EXPORT_SYMBOL(mptscsih_qcmd);
EXPORT_SYMBOL(mptscsih_slave_alloc);
EXPORT_SYMBOL(mptscsih_slave_destroy);
EXPORT_SYMBOL(mptscsih_slave_configure);
EXPORT_SYMBOL(mptscsih_abort);
EXPORT_SYMBOL(mptscsih_dev_reset);
EXPORT_SYMBOL(mptscsih_bus_reset);
EXPORT_SYMBOL(mptscsih_host_reset);
EXPORT_SYMBOL(mptscsih_bios_param);
EXPORT_SYMBOL(mptscsih_io_done);
EXPORT_SYMBOL(mptscsih_taskmgmt_complete);
EXPORT_SYMBOL(mptscsih_scandv_complete);
EXPORT_SYMBOL(mptscsih_event_process);
EXPORT_SYMBOL(mptscsih_ioc_reset);
EXPORT_SYMBOL(mptscsih_store_queue_depth);
EXPORT_SYMBOL(mptscsih_InternalCmdTimer_expired);
EXPORT_SYMBOL(mptscsih_DVCmdTimer_expired);
EXPORT_SYMBOL(mptscsih_readFCDevicePage0);
EXPORT_SYMBOL(mptscsih_change_queue_depth);
EXPORT_SYMBOL(mptscsih_TMHandler);
EXPORT_SYMBOL(mptscsih_TM_timeout);
EXPORT_SYMBOL(mptscsih_do_cmd);
EXPORT_SYMBOL(mptscsih_IssueTaskMgmt);
EXPORT_SYMBOL(mptscsih_sanity_check);
EXPORT_SYMBOL(mptscsih_poll);
/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/

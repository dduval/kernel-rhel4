/*
 *  linux/drivers/message/fusion/mptscsih.h
 *      High performance SCSI / Fibre Channel SCSI Host device driver.
 *      For use with PCI chip/adapter(s):
 *          LSIFC9xx/LSI409xx Fibre Channel
 *      running LSI Fusion MPT (Message Passing Technology) firmware.
 *
 *  Copyright (c) 1999-2007 LSI Corporation
 *  (mailto:DL-MPTFusionLinux@lsi.com)
 *
 *  $Id: mptscsih.h,v 1.1.2.2 2003/05/07 14:08:35 Exp $
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

#ifndef SCSIHOST_H_INCLUDED
#define SCSIHOST_H_INCLUDED

/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
/*
 *	SCSI Public stuff...
 */

#define MPT_SCANDV_GOOD			(0x00000000) /* must be 0 */
#define MPT_SCANDV_DID_RESET		(0x00000001)
#define MPT_SCANDV_SENSE		(0x00000002)
#define MPT_SCANDV_SOME_ERROR		(0x00000004)
#define MPT_SCANDV_SELECTION_TIMEOUT	(0x00000008)
#define MPT_SCANDV_ISSUE_SENSE		(0x00000010)
#define MPT_SCANDV_FALLBACK		(0x00000020)
#define MPT_SCANDV_BUSY			(0x00000040)

//#define MPT_SCSI_CMD_PER_DEV_HIGH	64
#define MPT_SCSI_CMD_PER_DEV_HIGH	48
#define MPT_SCSI_CMD_PER_DEV_LOW	32

#define MPT_SCSI_CMD_PER_LUN		7

#define MPT_SCSI_MAX_SECTORS    8192

/* To disable domain validation, uncomment the
 * following line. No effect for FC devices.
 * For SCSI devices, driver will negotiate to
 * NVRAM settings (if available) or to maximum adapter
 * capabilities.
 */

#define MPTSCSIH_ENABLE_DOMAIN_VALIDATION


/* SCSI driver setup structure. Settings can be overridden
 * by command line options.
 */
#define MPTSCSIH_DOMAIN_VALIDATION      1
#define MPTSCSIH_MAX_WIDTH              1
#define MPTSCSIH_MIN_SYNC               0x08
#define MPTSCSIH_SAF_TE                 0
#define MPTSCSIH_PT_CLEAR               0

#endif

typedef struct _internal_cmd {
	char		*data;		/* data pointer */
	dma_addr_t	data_dma;	/* data dma address */
	int		size;		/* transfer size */
	u8		cmd;		/* SCSI Op Code */
	u8		bus;		/* bus number */
	u8		id;		/* SCSI ID (virtual) */
	u8		lun;
	u8		flags;		/* Bit Field - See above */
	u8		physDiskNum;	/* Phys disk number, -1 else */
	u8		rsvd2;
	u8		rsvd;
} INTERNAL_CMD;

extern void mptscsih_remove(struct pci_dev *);
// This was changed in the 2.6.13 kernel
extern void mptscsih_shutdown(struct device *);
#ifdef CONFIG_PM
extern int mptscsih_suspend(struct pci_dev *pdev, pm_message_t state);
extern int mptscsih_resume(struct pci_dev *pdev);
#endif
extern int mptscsih_proc_info(struct Scsi_Host *host, char *buffer, char **start, off_t offset, int length, int func);
extern const char * mptscsih_info(struct Scsi_Host *SChost);
extern int mptscsih_qcmd(struct scsi_cmnd *SCpnt, void (*done)(struct scsi_cmnd *));
extern int mptscsih_slave_alloc(struct scsi_device *device);
extern void mptscsih_slave_destroy(struct scsi_device *device);
extern int mptscsih_slave_configure(struct scsi_device *device, int queue_depth);
extern int mptscsih_abort(struct scsi_cmnd * SCpnt);
extern int mptscsih_dev_reset(struct scsi_cmnd * SCpnt);
extern int mptscsih_bus_reset(struct scsi_cmnd * SCpnt);
extern int mptscsih_host_reset(struct scsi_cmnd *SCpnt);
extern int mptscsih_bios_param(struct scsi_device * sdev, struct block_device *bdev, sector_t capacity, int geom[]);
extern int mptscsih_io_done(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf, MPT_FRAME_HDR *r);
extern int mptscsih_taskmgmt_complete(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf, MPT_FRAME_HDR *r);
extern int mptscsih_scandv_complete(MPT_ADAPTER *ioc, MPT_FRAME_HDR *mf, MPT_FRAME_HDR *r);
extern int mptscsih_event_process(MPT_ADAPTER *ioc, EventNotificationReply_t *pEvReply);
extern int mptscsih_ioc_reset(MPT_ADAPTER *ioc, int post_reset);
extern ssize_t mptscsih_store_queue_depth(struct device *dev, const char *buf, size_t count);
extern void mptscsih_InternalCmdTimer_expired(unsigned long data);
extern void mptscsih_DVCmdTimer_expired(unsigned long data);
extern int mptscsih_readFCDevicePage0(MPT_ADAPTER *ioc, u8 bus, u8 targetId, pFCDevicePage0_t fcDevicePage);
extern void mptscsih_hot_plug_worker_thread(void * arg);
extern int mptscsih_TMHandler(MPT_SCSI_HOST *hd, u8 type, u8 channel, u8 target, u8 lun, int ctx2abort, ulong timeout);
extern int mptscsih_change_queue_depth(struct scsi_device *sdev, int qdepth);
extern int mptscsih_do_cmd(MPT_SCSI_HOST *hd, INTERNAL_CMD *iocmd);
extern int mptscsih_sanity_check(struct scsi_device *sdev);
extern void mptscsih_poll(struct scsi_device *sdev);
extern int	 mptscsih_IssueTaskMgmt(MPT_SCSI_HOST *hd, u8 type, u8 channel, u8 id, u8 lun, int ctx2abort, ulong timeout);

/*******************************************************************
 * This file is part of the Emulex Linux Device Driver for         *
 * Fibre Channel Host Bus Adapters.                                *
 * Copyright (C) 2003-2005 Emulex.  All rights reserved.           *
 * EMULEX and SLI are trademarks of Emulex.                        *
 * www.emulex.com                                                  *
 *                                                                 *
 * This program is free software; you can redistribute it and/or   *
 * modify it under the terms of version 2 of the GNU General       *
 * Public License as published by the Free Software Foundation.    *
 * This program is distributed in the hope that it will be useful. *
 * ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND          *
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY,  *
 * FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT, ARE      *
 * DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD *
 * TO BE LEGALLY INVALID.  See the GNU General Public License for  *
 * more details, a copy of which can be found in the file COPYING  *
 * included with this package.                                     *
 *******************************************************************/

/*
 * $Id: lpfc_scsi.h 2912 2006-04-15 23:15:36Z sf_support $
 */

#ifndef _H_LPFC_SCSI
#define _H_LPFC_SCSI

#include "lpfc_disc.h"
#include "lpfc_mem.h"
#include "lpfc_sli.h"

struct lpfc_hba;

#define lpfc_list_first_entry(pos, head, member)                \
	(pos = ((list_empty(head)) ? NULL :                     \
		list_entry((head)->next, typeof(*pos), member)))

struct lpfc_target {
	struct lpfc_nodelist *pnode;	/* Pointer to the node structure. */
	uint16_t  scsi_id;
	uint32_t  qcmdcnt;
	uint32_t  iodonecnt;
	uint32_t  errorcnt;
	uint32_t  slavecnt;
#if defined(RHEL_FC) || defined(SLES_FC)
	uint16_t  blocked;
#endif
#ifdef RHEL_FC
	struct scsi_target *starget;		/* Pointer to midlayer target
						   structure. */
#endif
#ifdef SLES_FC
	struct timer_list dev_loss_timer;
#endif
	unsigned long last_ramp_up_time;
	unsigned long last_q_full_time;
};

struct lpfc_scsi_buf {
	struct scsi_cmnd *pCmd;
	struct lpfc_hba *scsi_hba;
	struct lpfc_target *target;
	uint32_t lun;

	uint32_t timeout;

	uint16_t status;	/* From IOCB Word 7- ulpStatus */
	uint32_t result;	/* From IOCB Word 4. */

	uint32_t   seg_cnt;	/* Number of scatter-gather segments returned by
				 * dma_map_sg.  The driver needs this for calls
				 * to dma_unmap_sg. */
	dma_addr_t nonsg_phys;	/* Non scatter-gather physical address. */

	/* dma_ext has both virt, phys to dma-able buffer
	 * which contains fcp_cmd, fcp_rsp and scatter gather list fro upto
	 * 68 (LPFC_SCSI_BPL_SIZE) BDE entries,
	 * xfer length, cdb, data direction....
	 */
	struct lpfc_dmabuf dma_ext;
	struct fcp_cmnd *fcp_cmnd;
	struct fcp_rsp *fcp_rsp;
	struct ulp_bde64 *fcp_bpl;

	/* cur_iocbq has phys of the dma-able buffer.
	 * Iotag is in here
	 */
	struct lpfc_iocbq cur_iocbq;
};

#define LPFC_SCSI_INITIAL_BPL_SIZE  4	/* Number of scsi buf BDEs in fcp_bpl */

#define LPFC_SCSI_DMA_EXT_SIZE 264
#define LPFC_BPL_SIZE          1024

#define MDAC_DIRECT_CMD                  0x22

#if defined(RHEL_FC) && defined(DISKDUMP_FC)
#include <linux/diskdump.h>
#define LPFC_MDELAY(n)				diskdump_mdelay(n)
#else
#define LPFC_MDELAY(n)				mdelay(n)
#define spin_unlock_irq_dump(host_lock)		spin_unlock_irq(host_lock)
#endif


#endif				/* _H_LPFC_SCSI */

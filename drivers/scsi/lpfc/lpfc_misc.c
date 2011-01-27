/*******************************************************************
 * This file is part of the Emulex Linux Device Driver for         *
 * Fibre Channel Host Bus Adapters.                                *
 * Copyright (C) 2003-2008 Emulex.  All rights reserved.           *
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
 * $Id: lpfc_misc.c 3137 2008-02-07 22:09:26Z sf_support $
 */

#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_cmnd.h>

#include "lpfc_sli.h"
#include "lpfc_disc.h"
#include "lpfc_scsi.h"
#include "lpfc.h"
#include "lpfc_crtn.h"
#include "lpfc_hw.h"
#include "lpfc_logmsg.h"
#include "lpfc_mem.h"
#define LPFC_DEF_IOCTL_ICFG
#include "lpfc_misc.h"
#include "lpfc_fcp.h"
#include "lpfc_compat.h"

int
lpfc_issue_ct_rsp(struct lpfc_hba * phba, uint32_t tag,
				struct lpfc_dmabuf * bmp, DMABUFEXT_t * inp)
{
	struct lpfc_sli *psli;
	IOCB_t *icmd;
	struct lpfc_iocbq *ctiocb;
	struct lpfc_sli_ring *pring;
	uint32_t num_entry;
	unsigned long iflag;
	int rc = 0;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	psli = &phba->sli;
	pring = &psli->ring[LPFC_ELS_RING];
	num_entry = inp->flag;
	inp->flag = 0;

	/* Allocate buffer for  command iocb */
	ctiocb = mempool_alloc(phba->iocb_mem_pool, GFP_ATOMIC);
	if (!ctiocb) {
		rc = ENOMEM;
		goto issue_ct_rsp_exit;
	}
	memset(ctiocb, 0, sizeof (struct lpfc_iocbq));
	icmd = &ctiocb->iocb;

	icmd->un.xseq64.bdl.ulpIoTag32 = 0;
	icmd->un.xseq64.bdl.addrHigh = putPaddrHigh(bmp->phys);
	icmd->un.xseq64.bdl.addrLow = putPaddrLow(bmp->phys);
	icmd->un.xseq64.bdl.bdeFlags = BUFF_TYPE_BDL;
	icmd->un.xseq64.bdl.bdeSize = (num_entry * sizeof (struct ulp_bde64));
	icmd->un.xseq64.w5.hcsw.Fctl = (LS | LA);
	icmd->un.xseq64.w5.hcsw.Dfctl = 0;
	icmd->un.xseq64.w5.hcsw.Rctl = FC_SOL_CTL;
	icmd->un.xseq64.w5.hcsw.Type = FC_COMMON_TRANSPORT_ULP;

	pci_dma_sync_single_for_device(phba->pcidev, bmp->phys, LPFC_BPL_SIZE,
							PCI_DMA_TODEVICE);

	/* Fill in rest of iocb */
	icmd->ulpCommand = CMD_XMIT_SEQUENCE64_CX;
	icmd->ulpBdeCount = 1;
	icmd->ulpLe = 1;
	icmd->ulpClass = CLASS3;
	icmd->ulpContext = (ushort) tag;
	icmd->ulpTimeout = phba->fc_ratov * 2;

	/* Xmit CT response on exchange <xid> */
	lpfc_printf_log(phba,
			KERN_INFO,
			LOG_ELS,
			"%d:0118 Xmit CT response on exchange x%x Data: x%x "
			"x%x\n",
			phba->brd_no,
			icmd->ulpContext, icmd->ulpIoTag, phba->hba_state);

	ctiocb->iocb_cmpl = 0;
	ctiocb->iocb_flag |= LPFC_IO_LIBDFC;
	rc = lpfc_sli_issue_iocb_wait(phba, pring, ctiocb, 0,
				     phba->fc_ratov * 2 + LPFC_DRVR_TIMEOUT);

	if (rc == IOCB_TIMEDOUT) {
		ctiocb->context1 = NULL;
		ctiocb->context2 = NULL;
		ctiocb->iocb_cmpl = lpfc_ioctl_timeout_iocb_cmpl;
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return (rc);
	}

	/* Calling routine takes care of IOCB_ERROR => EIO translation */
	if (rc != IOCB_SUCCESS)
		rc = IOCB_ERROR;

	mempool_free(ctiocb, phba->iocb_mem_pool);
issue_ct_rsp_exit:
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return (rc);
}

void
lpfc_sli_wake_mbox_wait(struct lpfc_hba * phba, LPFC_MBOXQ_t * pmboxq)
{
	wait_queue_head_t *pdone_q;

	/* 
	 * If pdone_q is empty, the driver thread gave up waiting and
	 * continued running.
	 */
	pdone_q = (wait_queue_head_t *) pmboxq->context1;
	if (pdone_q)
		wake_up_interruptible(pdone_q);
	return;
}

int
lpfc_sleep(struct lpfc_hba * phba, void *wait_q_head, long tmo)
{
	wait_queue_t wq_entry;
	int rc = 1;
	long left;

	init_waitqueue_entry(&wq_entry, current);
	/* start to sleep before we wait, to avoid races */
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue((wait_queue_head_t *) wait_q_head, &wq_entry);
	if (tmo > 0) {
		left = schedule_timeout(tmo * HZ);
	} else {
		schedule();
		left = 0;
	}
	remove_wait_queue((wait_queue_head_t *) wait_q_head, &wq_entry);

	if (signal_pending(current))
		return (EINTR);
	if (rc > 0)
		return (0);
	else
		return (ETIMEDOUT);
}
int
lpfc_geportname(struct lpfc_name * pn1, struct lpfc_name * pn2)
{
	int i;
	uint8_t *cp1, *cp2;

	i = sizeof (struct lpfc_name);
	cp1 = (uint8_t *) pn1;
	cp2 = (uint8_t *) pn2;
	while (i--) {
		if (*cp1 < *cp2) {
			return (0);
		}
		if (*cp1 > *cp2) {
			return (1);
		}
		cp1++;
		cp2++;
	}

	return (2);		/* equal */
}


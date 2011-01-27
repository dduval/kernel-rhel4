/*******************************************************************
 * This file is part of the Emulex Linux Device Driver for         *
 * Fibre Channel Host Bus Adapters.                                *
 * Copyright (C) 2003-2006 Emulex.  All rights reserved.           *
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
 * $Id: lpfc_sli.c 2905 2006-04-13 17:11:39Z sf_support $
 */

#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/spinlock.h>

#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>

#include "lpfc_sli.h"
#include "lpfc_disc.h"
#include "lpfc_scsi.h"
#include "lpfc.h"
#include "lpfc_crtn.h"
#include "lpfc_hw.h"
#include "lpfc_logmsg.h"
#include "lpfc_mem.h"
#include "lpfc_compat.h"
#include "lpfc_fcp.h"

extern void
lpfc_scsi_cmd_iocb_cmpl(struct lpfc_hba *, struct lpfc_iocbq *, struct lpfc_iocbq *);
/*
 * Define macro to log: Mailbox command x%x cannot issue Data
 * This allows multiple uses of lpfc_msgBlk0311
 * w/o perturbing log msg utility.
*/
#define LOG_MBOX_CANNOT_ISSUE_DATA( phba, mb, psli, flag) \
			lpfc_printf_log(phba, \
				KERN_INFO, \
				LOG_MBOX | LOG_SLI, \
				"%d:0311 Mailbox command x%x cannot issue " \
				"Data: x%x x%x x%x\n", \
				phba->brd_no, \
				mb->mbxCommand,		\
				phba->hba_state,	\
				psli->sliinit.sli_flag,	\
				flag);


/* This will save a huge switch to determine if the IOCB cmd
 * is unsolicited or solicited.
 */
#define LPFC_UNKNOWN_IOCB 0
#define LPFC_UNSOL_IOCB   1
#define LPFC_SOL_IOCB     2
#define LPFC_ABORT_IOCB   3
static uint8_t lpfc_sli_iocb_cmd_type[CMD_MAX_IOCB_CMD] = {
	LPFC_UNKNOWN_IOCB,	/* 0x00 */
	LPFC_UNSOL_IOCB,	/* CMD_RCV_SEQUENCE_CX     0x01 */
	LPFC_SOL_IOCB,		/* CMD_XMIT_SEQUENCE_CR    0x02 */
	LPFC_SOL_IOCB,		/* CMD_XMIT_SEQUENCE_CX    0x03 */
	LPFC_SOL_IOCB,		/* CMD_XMIT_BCAST_CN       0x04 */
	LPFC_SOL_IOCB,		/* CMD_XMIT_BCAST_CX       0x05 */
	LPFC_UNKNOWN_IOCB,	/* CMD_QUE_RING_BUF_CN     0x06 */
	LPFC_UNKNOWN_IOCB,	/* CMD_QUE_XRI_BUF_CX      0x07 */
	LPFC_UNKNOWN_IOCB,	/* CMD_IOCB_CONTINUE_CN    0x08 */
	LPFC_UNKNOWN_IOCB,	/* CMD_RET_XRI_BUF_CX      0x09 */
	LPFC_SOL_IOCB,		/* CMD_ELS_REQUEST_CR      0x0A */
	LPFC_SOL_IOCB,		/* CMD_ELS_REQUEST_CX      0x0B */
	LPFC_UNKNOWN_IOCB,	/* 0x0C */
	LPFC_UNSOL_IOCB,	/* CMD_RCV_ELS_REQ_CX      0x0D */
	LPFC_ABORT_IOCB,	/* CMD_ABORT_XRI_CN        0x0E */
	LPFC_ABORT_IOCB,	/* CMD_ABORT_XRI_CX        0x0F */
	LPFC_ABORT_IOCB,	/* CMD_CLOSE_XRI_CR        0x10 */
	LPFC_ABORT_IOCB,	/* CMD_CLOSE_XRI_CX        0x11 */
	LPFC_SOL_IOCB,		/* CMD_CREATE_XRI_CR       0x12 */
	LPFC_SOL_IOCB,		/* CMD_CREATE_XRI_CX       0x13 */
	LPFC_SOL_IOCB,		/* CMD_GET_RPI_CN          0x14 */
	LPFC_SOL_IOCB,		/* CMD_XMIT_ELS_RSP_CX     0x15 */
	LPFC_SOL_IOCB,		/* CMD_GET_RPI_CR          0x16 */
	LPFC_ABORT_IOCB,	/* CMD_XRI_ABORTED_CX      0x17 */
	LPFC_SOL_IOCB,		/* CMD_FCP_IWRITE_CR       0x18 */
	LPFC_SOL_IOCB,		/* CMD_FCP_IWRITE_CX       0x19 */
	LPFC_SOL_IOCB,		/* CMD_FCP_IREAD_CR        0x1A */
	LPFC_SOL_IOCB,		/* CMD_FCP_IREAD_CX        0x1B */
	LPFC_SOL_IOCB,		/* CMD_FCP_ICMND_CR        0x1C */
	LPFC_SOL_IOCB,		/* CMD_FCP_ICMND_CX        0x1D */
	LPFC_UNKNOWN_IOCB,	/* 0x1E */
	LPFC_SOL_IOCB,		/* CMD_FCP_TSEND_CX        0x1F */
	LPFC_SOL_IOCB,		/* CMD_ADAPTER_MSG         0x20 */
	LPFC_SOL_IOCB,		/* CMD_FCP_TRECEIVE_CX     0x21 */
	LPFC_SOL_IOCB,		/* CMD_ADAPTER_DUMP        0x22 */
	LPFC_SOL_IOCB,		/* CMD_FCP_TRSP_CX         0x23 */
	/* 0x24 - 0x80 */
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	/* 0x30 */
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB,
	/* 0x40 */
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB,
	/* 0x50 */
	LPFC_SOL_IOCB,
	LPFC_SOL_IOCB,
	LPFC_UNKNOWN_IOCB,
	LPFC_SOL_IOCB,
	LPFC_SOL_IOCB,
	LPFC_UNSOL_IOCB,
	LPFC_UNSOL_IOCB,
	LPFC_SOL_IOCB,
	LPFC_SOL_IOCB,

	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB,
	/* 0x60 */
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB,
	/* 0x70 */
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB,
	/* 0x80 */
	LPFC_UNKNOWN_IOCB,
	LPFC_UNSOL_IOCB,	/* CMD_RCV_SEQUENCE64_CX   0x81 */
	LPFC_SOL_IOCB,		/* CMD_XMIT_SEQUENCE64_CR  0x82 */
	LPFC_SOL_IOCB,		/* CMD_XMIT_SEQUENCE64_CX  0x83 */
	LPFC_SOL_IOCB,		/* CMD_XMIT_BCAST64_CN     0x84 */
	LPFC_SOL_IOCB,		/* CMD_XMIT_BCAST64_CX     0x85 */
	LPFC_UNKNOWN_IOCB,	/* CMD_QUE_RING_BUF64_CN   0x86 */
	LPFC_UNKNOWN_IOCB,	/* CMD_QUE_XRI_BUF64_CX    0x87 */
	LPFC_UNKNOWN_IOCB,	/* CMD_IOCB_CONTINUE64_CN  0x88 */
	LPFC_UNSOL_IOCB,	/* CMD_RET_XRI_BUF64_CX    0x89 */
	LPFC_SOL_IOCB,		/* CMD_ELS_REQUEST64_CR    0x8A */
	LPFC_SOL_IOCB,		/* CMD_ELS_REQUEST64_CX    0x8B */
	LPFC_ABORT_IOCB,	/* CMD_ABORT_MXRI64_CN     0x8C */
	LPFC_UNSOL_IOCB,	/* CMD_RCV_ELS_REQ64_CX    0x8D */
	/* 0x8E - 0x94 */
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB,
	LPFC_SOL_IOCB,		/* CMD_XMIT_ELS_RSP64_CX   0x95 */
	LPFC_UNKNOWN_IOCB,	/* 0x96 */
	LPFC_UNKNOWN_IOCB,	/* 0x97 */
	LPFC_SOL_IOCB,		/* CMD_FCP_IWRITE64_CR     0x98 */
	LPFC_SOL_IOCB,		/* CMD_FCP_IWRITE64_CX     0x99 */
	LPFC_SOL_IOCB,		/* CMD_FCP_IREAD64_CR      0x9A */
	LPFC_SOL_IOCB,		/* CMD_FCP_IREAD64_CX      0x9B */
	LPFC_SOL_IOCB,		/* CMD_FCP_ICMND64_CR      0x9C */
	LPFC_SOL_IOCB,		/* CMD_FCP_ICMND64_CX      0x9D */
	LPFC_UNKNOWN_IOCB,	/* 0x9E */
	LPFC_SOL_IOCB,		/* CMD_FCP_TSEND64_CX      0x9F */
	LPFC_UNKNOWN_IOCB,	/* 0xA0 */
	LPFC_SOL_IOCB,		/* CMD_FCP_TRECEIVE64_CX   0xA1 */
	LPFC_UNKNOWN_IOCB,	/* 0xA2 */
	LPFC_SOL_IOCB,		/* CMD_FCP_TRSP64_CX       0xA3 */
	/* 0xA4 - 0xC1 */
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_SOL_IOCB,		/* CMD_GEN_REQUEST64_CR    0xC2 */
	LPFC_SOL_IOCB,		/* CMD_GEN_REQUEST64_CX    0xC3 */
	/* 0xC4 - 0xCF */
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,

	LPFC_SOL_IOCB,
	LPFC_SOL_IOCB,		/* CMD_SENDTEXT_CR              0xD1 */
	LPFC_SOL_IOCB,		/* CMD_SENDTEXT_CX              0xD2 */
	LPFC_SOL_IOCB,		/* CMD_RCV_LOGIN                0xD3 */
	LPFC_SOL_IOCB,		/* CMD_ACCEPT_LOGIN             0xD4 */
	LPFC_SOL_IOCB,		/* CMD_REJECT_LOGIN             0xD5 */
	LPFC_UNSOL_IOCB,
	/* 0xD7 - 0xDF */
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB, LPFC_UNKNOWN_IOCB,
	/* 0xE0 */
	LPFC_UNSOL_IOCB,
	LPFC_SOL_IOCB,
	LPFC_SOL_IOCB,
	LPFC_SOL_IOCB,
	LPFC_SOL_IOCB,
	LPFC_UNSOL_IOCB
};

static void
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



static int
lpfc_sli_ring_map(struct lpfc_hba * phba)
{
	struct lpfc_sli *psli;
	LPFC_MBOXQ_t *pmb;
	MAILBOX_t *pmbox;
	int i;

	psli = &phba->sli;

	/* Get a Mailbox buffer to setup mailbox commands for HBA
	   initialization */
	if ((pmb = (LPFC_MBOXQ_t *) mempool_alloc(phba->mbox_mem_pool,
						  GFP_ATOMIC)) == 0) {
		phba->hba_state = LPFC_HBA_ERROR;
		return -ENOMEM;
	}
	pmbox = &pmb->mb;

	/* Initialize the struct lpfc_sli_ring structure for each ring */
	for (i = 0; i < psli->sliinit.num_rings; i++) {
		/* Issue a CONFIG_RING mailbox command for each ring */
		phba->hba_state = LPFC_INIT_MBX_CMDS;
		lpfc_config_ring(phba, i, pmb);
		if (lpfc_sli_issue_mbox(phba, pmb, MBX_POLL) != MBX_SUCCESS) {
			/* Adapter failed to init, mbxCmd <cmd> CFG_RING,
			   mbxStatus <status>, ring <num> */
			lpfc_printf_log(phba,
					KERN_ERR,
					LOG_INIT,
					"%d:0446 Adapter failed to init, "
					"mbxCmd x%x CFG_RING, mbxStatus x%x, "
					"ring %d\n",
					phba->brd_no,
					pmbox->mbxCommand,
					pmbox->mbxStatus,
					i);
			phba->hba_state = LPFC_HBA_ERROR;
			mempool_free( pmb, phba->mbox_mem_pool);
			return -ENXIO;
		}
	}
	mempool_free( pmb, phba->mbox_mem_pool);
	return 0;
}

static int
lpfc_sli_ringtxcmpl_put(struct lpfc_hba * phba,
			struct lpfc_sli_ring * pring, struct lpfc_iocbq * piocb)
{
	uint16_t iotag;

	list_add_tail(&piocb->list, &pring->txcmplq);
	pring->txcmplq_cnt++;
	if (unlikely(pring->ringno == LPFC_ELS_RING))
		mod_timer(&phba->els_tmofunc,
					jiffies + HZ * (phba->fc_ratov << 1));

	if (pring->fast_lookup) {
		/* Setup fast lookup based on iotag for completion */
		iotag = piocb->iocb.ulpIoTag;
		if (iotag && (iotag
		      < phba->sli.sliinit.ringinit[pring->ringno].fast_iotag))
			*(pring->fast_lookup + iotag) = piocb;
		else {

			/* Cmd ring <ringno> put: iotag <iotag> greater then
			   configured max <fast_iotag> wd0 <icmd> */
			lpfc_printf_log(phba,
					KERN_ERR,
					LOG_SLI,
					"%d:0316 Cmd ring %d put: iotag x%x "
					"greater then configured max x%x "
					"wd0 x%x\n",
					phba->brd_no,
					pring->ringno, iotag, phba->sli.sliinit
					.ringinit[pring->ringno].fast_iotag,
					*(((uint32_t *)(&piocb->iocb)) + 7));
		}
	}
	return (0);
}

static int
lpfc_sli_ringtx_put(struct lpfc_hba * phba, struct lpfc_sli_ring * pring,
		    struct lpfc_iocbq * piocb)
{
	/* Insert the caller's iocb in the txq tail for later processing. */
	list_add_tail(&piocb->list, &pring->txq);
	pring->txq_cnt++;
	return (0);
}

static struct lpfc_iocbq *
lpfc_sli_ringtx_get(struct lpfc_hba * phba, struct lpfc_sli_ring * pring)
{
	struct list_head *dlp;
	struct lpfc_iocbq *cmd_iocb;
	struct lpfc_iocbq *next_iocb;

	dlp = &pring->txq;
	cmd_iocb = NULL;
	next_iocb = (struct lpfc_iocbq *) pring->txq.next;
	if (next_iocb != (struct lpfc_iocbq *) & pring->txq) {
		/* If the first ptr is not equal to the list header,
		 * deque the IOCBQ_t and return it.
		 */
		cmd_iocb = next_iocb;
		list_del(&cmd_iocb->list);
		pring->txq_cnt--;
	}
	return (cmd_iocb);
}

static IOCB_t *
lpfc_sli_next_iocb_slot (struct lpfc_hba *phba, struct lpfc_sli_ring *pring)
{
	MAILBOX_t *mbox = (MAILBOX_t *)phba->sli.MBhostaddr;
	PGP *pgp = (PGP *)&mbox->us.s2.port[pring->ringno];
	uint32_t  max_cmd_idx =
		phba->sli.sliinit.ringinit[pring->ringno].numCiocb;
	IOCB_t *iocb = NULL;

	if((pring->next_cmdidx == pring->cmdidx) &&
	   (++pring->next_cmdidx >= max_cmd_idx))
		pring->next_cmdidx = 0;

	if (unlikely(pring->local_getidx == pring->next_cmdidx)) {

		pring->local_getidx = le32_to_cpu(pgp->cmdGetInx);

		if (unlikely(pring->local_getidx >= max_cmd_idx)) {
			lpfc_printf_log(phba, KERN_ERR, LOG_SLI,
					"%d:0315 Ring %d issue: portCmdGet %d "
					"is bigger then cmd ring %d\n",
					phba->brd_no, pring->ringno,
					pring->local_getidx, max_cmd_idx);

			phba->hba_state = LPFC_HBA_ERROR;
			/*
			   All error attention handlers are posted to
			   discovery tasklet
			*/
			lpfc_discq_post_event(phba, (void *)HS_FFER3, NULL,
					      LPFC_EVT_ERR_ATTN);

			return NULL;
		}

		if (pring->local_getidx == pring->next_cmdidx)
			return NULL;
	}

	iocb = IOCB_ENTRY(pring->cmdringaddr, pring->cmdidx);

	return iocb;
}

static uint32_t
lpfc_sli_next_iotag(struct lpfc_hba * phba, struct lpfc_sli_ring * pring)
{
	LPFC_RING_INIT_t *pringinit;
	struct lpfc_sli *psli;
	uint32_t search_start;

	psli = &phba->sli;
	pringinit = &psli->sliinit.ringinit[pring->ringno];

	if (pring->fast_lookup == NULL) {
		pringinit->iotag_ctr++;
		if (pringinit->iotag_ctr >= pringinit->iotag_max)
			pringinit->iotag_ctr = 1;
		return pringinit->iotag_ctr;
	}

	search_start = pringinit->iotag_ctr;

	do {
		pringinit->iotag_ctr++;
		if (pringinit->iotag_ctr >= pringinit->fast_iotag)
			pringinit->iotag_ctr = 1;

		if(*(pring->fast_lookup + pringinit->iotag_ctr) == NULL)
			return pringinit->iotag_ctr;

	} while (pringinit->iotag_ctr != search_start);

	/*
	 * Outstanding I/O count for ring <ringno> is at max <fast_iotag>
	 */
	lpfc_printf_log(phba,
		KERN_ERR,
		LOG_SLI,
		"%d:0318 Outstanding I/O count for ring %d is at max x%x\n",
		phba->brd_no,
		pring->ringno,
		psli->sliinit.ringinit[pring->ringno].fast_iotag);
	return (0);
}

static int
lpfc_sli_submit_iocb(struct lpfc_hba *phba, struct lpfc_sli_ring *pring,
		IOCB_t *iocb, struct lpfc_iocbq *nextiocb)
{
	struct lpfc_sli *psli = &phba->sli;
	int ringno = pring->ringno;

	/*
	 * Alloocate and set up an iotag
	 */
	if ((nextiocb->iocb.ulpIoTag =
	     lpfc_sli_next_iotag(phba, &psli->ring[psli->fcp_ring])) == 0)
		return (1);

	/*
	 * Issue iocb command to adapter
	 */
	lpfc_sli_pcimem_bcopy((uint32_t *)&nextiocb->iocb,
			      (uint32_t *)(iocb), sizeof (IOCB_t));
	wmb();
	psli->slistat.iocbCmd[ringno]++;

	/*
	 * If there is no completion routine to call, we can release the
	 * IOCB buffer back right now. For IOCBs, like QUE_RING_BUF,
	 * that have no rsp ring completion, iocb_cmpl MUST be NULL.
	 */
	if (nextiocb->iocb_cmpl)
		lpfc_sli_ringtxcmpl_put(phba, pring, nextiocb);
	else
		mempool_free(nextiocb, phba->iocb_mem_pool);

	/*
	 * Let the HBA know what IOCB slot will be the next one the
	 * driver will put a command into.
	 */
	pring->cmdidx = pring->next_cmdidx;
	writel((uint32_t)pring->cmdidx,
	       (u8 *)phba->MBslimaddr + (SLIMOFF + (ringno * 2)) * 4);

	return (0);
}

static void
lpfc_sli_update_full_ring(struct lpfc_hba * phba,
			  struct lpfc_sli_ring *pring)
{
	int ringno = pring->ringno;

	pring->flag |= LPFC_CALL_RING_AVAILABLE;

	wmb();

	/*
	 * Set ring 'ringno' to SET R0CE_REQ in Chip Att register.
	 * The HBA will tell us when an IOCB entry is available.
	 */
	writel((CA_R0ATT|CA_R0CE_REQ) << (ringno*4), phba->CAregaddr);
	readl(phba->CAregaddr); /* flush */

	phba->sli.slistat.iocbCmdFull[ringno]++;
}

static void
lpfc_sli_update_ring(struct lpfc_hba * phba,
		     struct lpfc_sli_ring *pring)
{
	int ringno = pring->ringno;

	/*
	 * Tell the HBA that there is work to do in this ring.
	 */
	wmb();
	writel(CA_R0ATT << (ringno * 4), phba->CAregaddr);
	readl(phba->CAregaddr); /* flush */
}

static void
lpfc_sli_resume_iocb(struct lpfc_hba * phba, struct lpfc_sli_ring * pring)
{
	struct lpfc_sli *psli = &phba->sli;
	IOCB_t *iocb;
	struct lpfc_iocbq *nextiocb;

	/*
	 * Check to see if:
	 *  (a) there is anything on the txq to send
	 *  (b) link is up
	 *  (c) link attention events can be processed (fcp ring only)
	 *  (d) IOCB processing is not blocked by the outstanding mbox command.
	 */
	if (pring->txq_cnt &&
	    (phba->hba_state > LPFC_LINK_DOWN) &&
	    (pring->ringno != psli->fcp_ring ||
	     psli->sliinit.sli_flag & LPFC_PROCESS_LA) &&
	    !(pring->flag & LPFC_STOP_IOCB_MBX)) {

		while ((iocb = lpfc_sli_next_iocb_slot(phba, pring)) &&
		       (nextiocb = lpfc_sli_ringtx_get(phba, pring)))
			if (lpfc_sli_submit_iocb(phba, pring, iocb, nextiocb)) {
				lpfc_sli_ringtx_put(phba, pring, nextiocb);
				break;
			}

		if (iocb)
			lpfc_sli_update_ring(phba, pring);
		else
			lpfc_sli_update_full_ring(phba, pring);
	}

	return;
}

/* lpfc_sli_turn_on_ring is only called by lpfc_sli_handle_mb_event below */
static void
lpfc_sli_turn_on_ring(struct lpfc_hba * phba, int ringno)
{
	struct lpfc_sli *psli;
	struct lpfc_sli_ring *pring;
	PGP *pgp;

	psli = &phba->sli;
	pring = &psli->ring[ringno];
	pgp = (PGP *) & (((MAILBOX_t *)psli->MBhostaddr)->us.s2.port[ringno]);

	/* If the ring is active, flag it */
	if (psli->ring[ringno].cmdringaddr) {
		if (psli->ring[ringno].flag & LPFC_STOP_IOCB_MBX) {
			psli->ring[ringno].flag &= ~LPFC_STOP_IOCB_MBX;
			/*
			 * Force update of the local copy of cmdGetInx
			 */
			pring->local_getidx = le32_to_cpu(pgp->cmdGetInx);
			lpfc_sli_resume_iocb(phba, pring);
		}
	}
}

static int
lpfc_sli_chk_mbx_command(uint8_t mbxCommand)
{
	uint8_t ret;

	switch (mbxCommand) {
	case MBX_LOAD_SM:
	case MBX_READ_NV:
	case MBX_WRITE_NV:
	case MBX_RUN_BIU_DIAG:
	case MBX_INIT_LINK:
	case MBX_DOWN_LINK:
	case MBX_CONFIG_LINK:
	case MBX_CONFIG_RING:
	case MBX_RESET_RING:
	case MBX_READ_CONFIG:
	case MBX_READ_RCONFIG:
	case MBX_READ_SPARM:
	case MBX_READ_STATUS:
	case MBX_READ_RPI:
	case MBX_READ_XRI:
	case MBX_READ_REV:
	case MBX_READ_LNK_STAT:
	case MBX_REG_LOGIN:
	case MBX_UNREG_LOGIN:
	case MBX_READ_LA:
	case MBX_CLEAR_LA:
	case MBX_DUMP_MEMORY:
	case MBX_DUMP_CONTEXT:
	case MBX_RUN_DIAGS:
	case MBX_RESTART:
	case MBX_UPDATE_CFG:
	case MBX_DOWN_LOAD:
	case MBX_DEL_LD_ENTRY:
	case MBX_RUN_PROGRAM:
	case MBX_SET_MASK:
	case MBX_SET_SLIM:
	case MBX_UNREG_D_ID:
	case MBX_KILL_BOARD:
	case MBX_CONFIG_FARP:
	case MBX_BEACON:
	case MBX_LOAD_AREA:
	case MBX_RUN_BIU_DIAG64:
	case MBX_CONFIG_PORT:
	case MBX_READ_SPARM64:
	case MBX_READ_RPI64:
	case MBX_REG_LOGIN64:
	case MBX_READ_LA64:
	case MBX_FLASH_WR_ULA:
	case MBX_SET_DEBUG:
	case MBX_LOAD_EXP_ROM:
		ret = mbxCommand;
		break;
	default:
		ret = MBX_SHUTDOWN;
		break;
	}
	return (ret);
}

void
lpfc_sli_def_mbox_cmpl(struct lpfc_hba * phba, LPFC_MBOXQ_t * pmb)
{
	struct lpfc_dmabuf *mp;
	mp = (struct lpfc_dmabuf *) (pmb->context1);
	if (mp) {
		lpfc_mbuf_free(phba, mp->virt, mp->phys);
		kfree(mp);
	}
	mempool_free( pmb, phba->mbox_mem_pool);
	return;
}

static int
lpfc_sli_handle_mb_event(struct lpfc_hba * phba)
{
	MAILBOX_t *mbox;
	MAILBOX_t *pmbox;
	LPFC_MBOXQ_t *pmb;
	struct lpfc_dmabuf *mp;
	struct lpfc_sli *psli;
	int i;
	unsigned long iflag;
	uint32_t process_next;


	psli = &phba->sli;
	/* We should only get here if we are in SLI2 mode */
	if (!(psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE)) {
		return (1);
	}

	spin_lock_irqsave(phba->host->host_lock, iflag);

	psli->slistat.mboxEvent++;

	/* Get a Mailbox buffer to setup mailbox commands for callback */
	if ((pmb = psli->mbox_active)) {
		pmbox = &pmb->mb;
		mbox = (MAILBOX_t *) psli->MBhostaddr;

		/* First check out the status word */
		lpfc_sli_pcimem_bcopy((uint32_t *) mbox, (uint32_t *) pmbox,
				     sizeof (uint32_t));

		/* Sanity check to ensure the host owns the mailbox */
		if (pmbox->mbxOwner != OWN_HOST) {
			/* Lets try for a while */
			for (i = 0; i < 10240; i++) {
				/* First copy command data */
				lpfc_sli_pcimem_bcopy((uint32_t *) mbox,
						     (uint32_t *) pmbox,
						     sizeof (uint32_t));
				if (pmbox->mbxOwner == OWN_HOST)
					goto mbout;
			}
			/* Stray Mailbox Interrupt, mbxCommand <cmd> mbxStatus
			   <status> */
			lpfc_printf_log(phba,
					KERN_ERR,
					LOG_MBOX | LOG_SLI,
					"%d:0304 Stray Mailbox Interrupt "
					"mbxCommand x%x mbxStatus x%x\n",
					phba->brd_no,
					pmbox->mbxCommand,
					pmbox->mbxStatus);

			psli->sliinit.sli_flag |= LPFC_SLI_MBOX_ACTIVE;
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			return (1);
		}

	      mbout:
		psli->mbox_active = NULL;
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		del_timer_sync(&psli->mbox_tmo);
		spin_lock_irqsave(phba->host->host_lock, iflag);
		phba->work_hba_events &= ~WORKER_MBOX_TMO;

		/*
		 * It is a fatal error if unknown mbox command completion.
		 */
		if (lpfc_sli_chk_mbx_command(pmbox->mbxCommand) ==
		    MBX_SHUTDOWN) {

			/* Unknow mailbox command compl */
			lpfc_printf_log(phba,
				KERN_ERR,
				LOG_MBOX | LOG_SLI,
				"%d:0323 Unknown Mailbox command %x Cmpl\n",
				phba->brd_no,
				pmbox->mbxCommand);
			phba->hba_state = LPFC_HBA_ERROR;

			/* cleanup mbox resources */
			mp = (struct lpfc_dmabuf *) (pmb->context1);
			if (mp) {
				lpfc_mbuf_free(phba, mp->virt, mp->phys);
				kfree(mp);
			}
			mempool_free( pmb, phba->mbox_mem_pool);

			/*
			   All error attention handlers are posted to
			   discovery tasklet
			*/
			lpfc_discq_post_event(phba, (void *)HS_FFER3, NULL,
					      LPFC_EVT_ERR_ATTN);
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			return (0);
		}

		if (pmbox->mbxStatus) {
			psli->slistat.mboxStatErr++;
			if (pmbox->mbxStatus == MBXERR_NO_RESOURCES) {
				/* Mbox cmd cmpl error - RETRYing */
				lpfc_printf_log(phba,
					KERN_INFO,
					LOG_MBOX | LOG_SLI,
					"%d:0305 Mbox cmd cmpl error - "
					"RETRYing Data: x%x x%x x%x x%x\n",
					phba->brd_no,
					pmbox->mbxCommand,
					pmbox->mbxStatus,
					pmbox->un.varWords[0],
					phba->hba_state);
				pmbox->mbxStatus = 0;
				pmbox->mbxOwner = OWN_HOST;
				psli->sliinit.sli_flag &= ~LPFC_SLI_MBOX_ACTIVE;
				if (lpfc_sli_issue_mbox(phba, pmb, MBX_NOWAIT)
				    == MBX_SUCCESS) {
					spin_unlock_irqrestore(
						       phba->host->host_lock,
						       iflag);
					return (0);
				}
			}
		}

		/* Mailbox cmd <cmd> Cmpl <cmpl> */
		lpfc_printf_log(phba,
				KERN_INFO,
				LOG_MBOX | LOG_SLI,
				"%d:0307 Mailbox cmd x%x Cmpl x%p "
				"Data: x%x x%x x%x x%x x%x x%x x%x x%x x%x\n",
				phba->brd_no,
				pmbox->mbxCommand,
				pmb->mbox_cmpl,
				*((uint32_t *) pmbox),
				mbox->un.varWords[0],
				mbox->un.varWords[1],
				mbox->un.varWords[2],
				mbox->un.varWords[3],
				mbox->un.varWords[4],
				mbox->un.varWords[5],
				mbox->un.varWords[6],
				mbox->un.varWords[7]);

		if (pmb->mbox_cmpl) {
			/* Copy entire mbox completion over buffer */
			lpfc_sli_pcimem_bcopy((uint32_t *) mbox,
						(uint32_t *) pmbox,
						(sizeof (uint32_t) *
						(MAILBOX_CMD_WSIZE)));
			/* All mbox cmpls are posted to discovery tasklet */
			lpfc_discq_post_event(phba, pmb, NULL,
						LPFC_EVT_MBOX);

		}
	}


	do {
		process_next = 0;	/* by default don't loop */
		psli->sliinit.sli_flag &= ~LPFC_SLI_MBOX_ACTIVE;

		/* Process next mailbox command if there is one */
		if ((pmb = lpfc_mbox_get(phba))) {
			if (lpfc_sli_issue_mbox(phba, pmb, MBX_NOWAIT) ==
			    MBX_NOT_FINISHED) {
				pmb->mb.mbxStatus = MBX_NOT_FINISHED;
				/* All mbox cmpls are posted to discovery tasklet */
				lpfc_discq_post_event(phba, pmb, NULL,
							LPFC_EVT_MBOX);
				process_next = 1;
				continue;       /* loop back */
                        }
		} else {
			/* Turn on IOCB processing */
			for (i = 0; i < psli->sliinit.num_rings; i++) {
				lpfc_sli_turn_on_ring(phba, i);
			}

			/* Free any lpfc_dmabuf's waiting for mbox cmd cmpls */
			while (!list_empty(&phba->freebufList)) {
				struct lpfc_dmabuf *mp;

				mp = (struct lpfc_dmabuf *)
					(phba->freebufList.next);
				if (mp) {
					lpfc_mbuf_free(phba, mp->virt,
						       mp->phys);
					list_del(&mp->list);
					kfree(mp);
				}
			}
		}

	} while (process_next);

	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return (0);
}
static int
lpfc_sli_process_unsol_iocb(struct lpfc_hba *phba, struct lpfc_sli_ring *pring,
			    struct lpfc_iocbq *saveq)
{
	struct lpfc_sli       * psli;
	IOCB_t           * irsp;
	LPFC_RING_INIT_t * pringinit;
	WORD5            * w5p;
	uint32_t           Rctl, Type;
	uint32_t           match, ringno, i;
	unsigned long	   iflag;
	struct lpfc_dmabuf *mp;

	psli = &phba->sli;
	match = 0;
	ringno = pring->ringno;
	irsp = &(saveq->iocb);
	if (irsp->ulpCommand == CMD_RET_XRI_BUF64_CX) {
		for (match = 0; match < irsp->ulpBdeCount; match++) {
			mp = lpfc_sli_ringpostbuf_get(phba, pring,
						      getPaddr(irsp->un.
							       cont64[match].
							       addrHigh,
							       irsp->un.
							       cont64[match].
							       addrLow));
			dma_free_coherent(&phba->pcidev->dev,
					  irsp->un.cont64[match].tus.f.bdeSize,
					  mp->virt, mp->phys);
			kfree(mp);
		}
	} else {
		if ((irsp->ulpCommand == CMD_RCV_ELS_REQ64_CX)
		    || (irsp->ulpCommand == CMD_RCV_ELS_REQ_CX)) {
			Rctl = FC_ELS_REQ;
			Type = FC_ELS_DATA;
		} else {
			w5p =
				(WORD5 *) & (saveq->iocb.un.
					     ulpWord[5]);
			Rctl = w5p->hcsw.Rctl;
			Type = w5p->hcsw.Type;

			/* Firmware Workaround */
			if ((Rctl == 0) && (pring->ringno == LPFC_ELS_RING) &&
			    (irsp->ulpCommand == CMD_RCV_SEQUENCE64_CX)) {
				Rctl = FC_ELS_REQ;
				Type = FC_ELS_DATA;
				w5p->hcsw.Rctl = Rctl;
				w5p->hcsw.Type = Type;
			}
		}
		/* unSolicited Responses */
		pringinit = &psli->sliinit.ringinit[ringno];
		if (pringinit->prt[0].profile) {

			if (!pringinit->prt[0].
				 lpfc_sli_rcv_unsol_event) 
				return 1;

			/* If this ring has a profile set, just
			   send it to prt[0] */
			/* All unsol iocbs for LPFC_ELS_RING
			 * are posted to discovery tasklet.
			 */
			if (ringno == LPFC_ELS_RING) {
				spin_lock_irqsave(phba->host->host_lock, iflag);
				lpfc_discq_post_event(phba,
					(void *)&pringinit->prt[0],
					(void *)saveq,
					LPFC_EVT_UNSOL_IOCB);
				spin_unlock_irqrestore(phba->host->host_lock,
						       iflag);
			}
			else {
				(pringinit->prt[0].
				 lpfc_sli_rcv_unsol_event) (phba, pring, saveq);
			}
			match = 1;
		} else {
			/* We must search, based on rctl / type
			   for the right routine */
			for (i = 0; i < pringinit->num_mask;
			     i++) {
				if ((pringinit->prt[i].rctl ==
				     Rctl)
				    && (pringinit->prt[i].
					type == Type)) {

					if (!pringinit->prt[i].
				 		lpfc_sli_rcv_unsol_event) 
						return 1;

					/* All unsol iocbs for LPFC_ELS_RING
					 * are posted to discovery tasklet.
					 */
					if (ringno == LPFC_ELS_RING) {
						spin_lock_irqsave(
							phba->host->host_lock,
							iflag);
						lpfc_discq_post_event(phba,
						     (void *)&pringinit->prt[i],
						     (void *)saveq,
						     LPFC_EVT_UNSOL_IOCB);
						spin_unlock_irqrestore(
							phba->host->host_lock,
							iflag);
					}
					else {
						(pringinit->prt[i].
						 lpfc_sli_rcv_unsol_event)
							(phba, pring, saveq);
					}
					match = 1;
					break;
				}
			}
		}
		if (match == 0) {
			/* Unexpected Rctl / Type received */
			/* Ring <ringno> handler: unexpected
			   Rctl <Rctl> Type <Type> received */
			lpfc_printf_log(phba,
					KERN_WARNING,
					LOG_SLI,
					"%d:0313 Ring %d handler: "
					"unexpected Rctl x%x "
					"Type x%x received \n",
					phba->brd_no,
					ringno,
					Rctl,
					Type);
		}
	}
	return(1);
}
static struct lpfc_iocbq *
lpfc_search_txcmpl(struct lpfc_sli_ring * pring, struct lpfc_iocbq * prspiocb)
{
	IOCB_t *icmd = NULL;
	IOCB_t *irsp = NULL;
	struct lpfc_iocbq *cmd_iocb;
	struct lpfc_iocbq *iocb, *next_iocb;
	uint16_t iotag;

	irsp = &prspiocb->iocb;
	iotag = irsp->ulpIoTag;
	cmd_iocb = NULL;

	/* Search through txcmpl from the begining */
	list_for_each_entry_safe(iocb, next_iocb, &(pring->txcmplq), list) {
		icmd = &iocb->iocb;
		if (iotag == icmd->ulpIoTag) {
			/* Found a match.  */
			cmd_iocb = iocb;
			list_del(&iocb->list);
			pring->txcmplq_cnt--;
			break;
		}
	}

	return (cmd_iocb);
}
static struct lpfc_iocbq *
lpfc_sli_ringtxcmpl_get(struct lpfc_hba * phba,
			struct lpfc_sli_ring * pring,
			struct lpfc_iocbq * prspiocb, uint32_t srch)
{
	struct list_head *dlp;
	IOCB_t *irsp = NULL;
	struct lpfc_iocbq *cmd_iocb;
	struct lpfc_sli *psli;
	uint16_t iotag;


	dlp = &pring->txcmplq;
	cmd_iocb = NULL;
	if (pring->fast_lookup && (srch == 0)) {
		/*
		 *  Use fast lookup based on iotag for completion
		 */
		psli = &phba->sli;
		irsp = &prspiocb->iocb;
		iotag = irsp->ulpIoTag;
		if (iotag < psli->sliinit.ringinit[pring->ringno].fast_iotag) {
			cmd_iocb = *(pring->fast_lookup + iotag);
			*(pring->fast_lookup + iotag) = NULL;
			if (cmd_iocb) {
				list_del(&cmd_iocb->list);
				pring->txcmplq_cnt--;
				return cmd_iocb;
			}
		} else {
			/*
			 * Rsp ring <ringno> get: iotag <iotag> greater then
			 *  configured max <fast_iotag> wd0 <irsp>
			 */
			lpfc_printf_log(phba,
					KERN_ERR,
					LOG_SLI,
					"%d:0317 Rsp ring %d get: iotag x%x "
					"greater then configured max x%x "
					"wd7 x%x\n",
					phba->brd_no,
					pring->ringno, iotag,
					psli->sliinit.ringinit[pring->ringno]
					.fast_iotag,
					*(((uint32_t *) irsp) + 7));
		}
	} else
		cmd_iocb = lpfc_search_txcmpl(pring, prspiocb);

	return cmd_iocb;
}

static int
lpfc_sli_process_sol_iocb(struct lpfc_hba * phba, struct lpfc_sli_ring * pring,
			  struct lpfc_iocbq *saveq)
{
	struct lpfc_iocbq * cmdiocbp;
	int            ringno, rc;
	unsigned long iflag;

	rc = 1;
	ringno = pring->ringno;
	/* Solicited Responses */
	/* Based on the iotag field, get the cmd IOCB
	   from the txcmplq */
	spin_lock_irqsave(phba->host->host_lock, iflag);
	if ((cmdiocbp =
	     lpfc_sli_ringtxcmpl_get(phba, pring, saveq,
				     0))) {
		/* Call the specified completion
		   routine */
		if (cmdiocbp->iocb_cmpl) {
			/* All iocb cmpls for LPFC_ELS_RING
			 * are posted to discovery tasklet.
			 */
			if (ringno == LPFC_ELS_RING) {
				lpfc_discq_post_event(phba, (void *)cmdiocbp,
					(void *)saveq,  LPFC_EVT_SOL_IOCB);
			}
			else {
				if (cmdiocbp->iocb_flag & LPFC_IO_POLL) {
					rc = 0;
				}

				if (cmdiocbp->iocb_cmpl == lpfc_scsi_cmd_iocb_cmpl)
					(cmdiocbp->iocb_cmpl) (phba, cmdiocbp, saveq);
				else {
					spin_unlock_irqrestore(phba->host->host_lock,
							       iflag);
					(cmdiocbp->iocb_cmpl) (phba, cmdiocbp, saveq);
					spin_lock_irqsave(phba->host->host_lock, iflag);
                                }
			}
		} else {
			mempool_free( cmdiocbp, phba->iocb_mem_pool);
		}
	} else {
		/* Could not find the initiating command
		 * based of the response iotag.
		 * This is expected on ELS ring because of lpfc_els_abort().
		 */
		if (ringno != LPFC_ELS_RING) {
			/* Ring <ringno> handler: unexpected
			   completion IoTag <IoTag> */
			lpfc_printf_log(phba,
				KERN_WARNING,
				LOG_SLI,
				"%d:0322 Ring %d handler: unexpected "
				"completion IoTag x%x Data: x%x x%x x%x x%x\n",
				phba->brd_no,
				ringno,
				saveq->iocb.ulpIoTag,
				saveq->iocb.ulpStatus,
				saveq->iocb.un.ulpWord[4],
				saveq->iocb.ulpCommand,
				saveq->iocb.ulpContext);
		}
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return(rc);
}
static int
lpfc_sli_handle_ring_event(struct lpfc_hba * phba,
			   struct lpfc_sli_ring * pring, uint32_t mask)
{
	struct lpfc_sli       * psli;
	IOCB_t           * entry;
	IOCB_t           * irsp;
	struct lpfc_iocbq     * rspiocbp, *next_iocb;
	struct lpfc_iocbq     * cmdiocbp;
	struct lpfc_iocbq     * saveq;
	HGP              * hgp;
	PGP              * pgp;
	MAILBOX_t        * mbox;
	uint32_t           status, free_saveq;
	uint32_t           portRspPut, portRspMax;
	int                ringno, loopcnt, rc;
	uint8_t            type;
	unsigned long	   iflag;
	void *to_slim;

	psli   = &phba->sli;
	ringno = pring->ringno;
	irsp   = NULL;
	rc     = 1;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	psli->slistat.iocbEvent[ringno]++;

	/* At this point we assume SLI-2 */
	mbox = (MAILBOX_t *) psli->MBhostaddr;
	pgp = (PGP *) & mbox->us.s2.port[ringno];
	hgp = (HGP *) & mbox->us.s2.host[ringno];

	/* portRspMax is the number of rsp ring entries for this specific
	   ring. */
	portRspMax = psli->sliinit.ringinit[ringno].numRiocb;

	rspiocbp = NULL;
	loopcnt = 0;

	/* Gather iocb entries off response ring.
	 * rspidx is the IOCB index of the next IOCB that the driver
	 * is going to process.
	 */
	entry = IOCB_ENTRY(pring->rspringaddr, pring->rspidx);
	portRspPut = le32_to_cpu(pgp->rspPutInx);

	if (portRspPut >= portRspMax) {

		/* Ring <ringno> handler: portRspPut <portRspPut> is bigger then
		   rsp ring <portRspMax> */
		lpfc_printf_log(phba,
				KERN_ERR,
				LOG_SLI,
				"%d:0312 Ring %d handler: portRspPut %d "
				"is bigger then rsp ring %d\n",
				phba->brd_no,
				ringno, portRspPut, portRspMax);
		/*
		 * Treat it as adapter hardware error.
		 */
		phba->hba_state = LPFC_HBA_ERROR;
		/*
		   All error attention handlers are posted to
		   discovery tasklet
		*/
		lpfc_discq_post_event(phba, (void *)HS_FFER3, NULL,
				      LPFC_EVT_ERR_ATTN);
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return (1);
	}

	rmb();

	/* Get the next available response iocb.
	 * rspidx is the IOCB index of the next IOCB that the driver
	 * is going to process.
	 */
	while (pring->rspidx != portRspPut) {
		/* get an iocb buffer to copy entry into */
		if ((rspiocbp = mempool_alloc(phba->iocb_mem_pool,
					      GFP_ATOMIC)) == 0) {
			break;
		}

		lpfc_sli_pcimem_bcopy((uint32_t *) entry,
				      (uint32_t *) & rspiocbp->iocb,
				      sizeof (IOCB_t));
		irsp = &rspiocbp->iocb;

		/* bump iocb available response index */
		if (++pring->rspidx >= portRspMax) {
			pring->rspidx = 0;
		}

		/* Let the HBA know what IOCB slot will be the next one the
		 * driver will read a response from.
		 */
		to_slim = (uint8_t *) phba->MBslimaddr +
			(SLIMOFF + (ringno * 2) + 1) * 4;
		writel( (uint32_t)pring->rspidx, to_slim);

		/* chain all iocb entries until LE is set */
		if (list_empty(&(pring->iocb_continueq))) {
			list_add(&rspiocbp->list, &(pring->iocb_continueq));
		} else {
			list_add_tail(&rspiocbp->list,
				      &(pring->iocb_continueq));
		}
		pring->iocb_continueq_cnt++;

		/*
		 * When the ulpLe field is set, the entire Command has been
		 * received. Start by getting a pointer to the first iocb entry
		 * in the chain.
		 */
		if (irsp->ulpLe) {
			/*
			 * By default, the driver expects to free all resources
			 * associated with this iocb completion.
			 */
			free_saveq = 0;
			saveq = list_entry(pring->iocb_continueq.next,
					   struct lpfc_iocbq, list);
			irsp = &(saveq->iocb);
			list_del_init(&pring->iocb_continueq);
			pring->iocb_continueq_cnt = 0;

			psli->slistat.iocbRsp[ringno]++;

			if(irsp->ulpStatus) {
				/* Rsp ring <ringno> error: IOCB */
				lpfc_printf_log(phba,
					KERN_WARNING,
					LOG_SLI,
					"%d:0326 Rsp Ring %d error: IOCB Data: "
					"x%x x%x x%x x%x x%x x%x x%x x%x\n",
					phba->brd_no,
					ringno,
					irsp->un.ulpWord[0],
					irsp->un.ulpWord[1],
					irsp->un.ulpWord[2],
					irsp->un.ulpWord[3],
					irsp->un.ulpWord[4],
					irsp->un.ulpWord[5],
					*(((uint32_t *) irsp) + 6),
					*(((uint32_t *) irsp) + 7));
			}

			/* Determine if IOCB command is a solicited or
			   unsolicited event */
			type =
			    lpfc_sli_iocb_cmd_type[(irsp->
						    ulpCommand &
						    CMD_IOCB_MASK)];
			if (type == LPFC_SOL_IOCB) {
				spin_unlock_irqrestore(phba->host->host_lock,
						       iflag);
				rc = lpfc_sli_process_sol_iocb(phba, pring,
					saveq);
				spin_lock_irqsave(phba->host->host_lock, iflag);
				/*
				 * If this solicted completion is an FCP
				 * command, free the resources now because
				 * no one uses the IOCB later.
				 */
				if (pring->ringno == LPFC_FCP_RING)
					free_saveq = 1;

			} else if (type == LPFC_UNSOL_IOCB) {
				spin_unlock_irqrestore(phba->host->host_lock,
						       iflag);
				rc = lpfc_sli_process_unsol_iocb(phba, pring,
					saveq);
				spin_lock_irqsave(phba->host->host_lock, iflag);

				/*
				 * If this unsolicted completion is an FCP
				 * command, free the resources now because
				 * no one uses the IOCB later.
				 */
				if (pring->ringno == LPFC_FCP_RING)
					free_saveq = 1;

			} else if (type == LPFC_ABORT_IOCB) {
				/* Solicited ABORT Responses */
				/* Based on the iotag field, get the cmd IOCB
				   from the txcmplq */
				if ((irsp->ulpCommand != CMD_XRI_ABORTED_CX) &&
				    ((cmdiocbp =
				      lpfc_sli_ringtxcmpl_get(phba, pring,
							      saveq, 0)))) {
					/* Call the specified completion
					   routine */
					if (cmdiocbp->iocb_cmpl) {
						spin_unlock_irqrestore(
						       phba->host->host_lock,
						       iflag);
						(cmdiocbp->iocb_cmpl) (phba,
							     cmdiocbp, saveq);
						spin_lock_irqsave(
							  phba->host->host_lock,
							  iflag);
					} else {
						mempool_free(cmdiocbp,
						     phba->iocb_mem_pool);
					}
				}
			} else if (type == LPFC_UNKNOWN_IOCB) {
				if (irsp->ulpCommand == CMD_ADAPTER_MSG) {

					char adaptermsg[LPFC_MAX_ADPTMSG];

					memset(adaptermsg, 0,
					       LPFC_MAX_ADPTMSG);
					memcpy(&adaptermsg[0], (uint8_t *) irsp,
					       MAX_MSG_DATA);
					dev_warn(&((phba->pcidev)->dev),
						 "lpfc%d: %s",
						 phba->brd_no, adaptermsg);
				} else {
					/* Unknown IOCB command */
					lpfc_printf_log(phba,
						KERN_ERR,
						LOG_SLI,
						"%d:0321 Unknown IOCB command "
						"Data: x%x x%x x%x x%x\n",
						phba->brd_no,
						irsp->ulpCommand,
						irsp->ulpStatus,
						irsp->ulpIoTag,
						irsp->ulpContext);
				}
			}

			if (free_saveq) {
				/*
				 * Free up iocb buffer chain for command just
				 * processed
				 */
				if (!list_empty(&pring->iocb_continueq)) {
					list_for_each_entry_safe(rspiocbp,
						 next_iocb,
						 &pring->iocb_continueq, list) {
					list_del_init(&rspiocbp->list);
					mempool_free(rspiocbp,
						     phba->iocb_mem_pool);
					}
				}
			mempool_free( saveq, phba->iocb_mem_pool);
			}
		}

		/* Entire Command has been received */
		entry = IOCB_ENTRY(pring->rspringaddr, pring->rspidx);

		/* If the port response put pointer has not been updated, sync
		 * the pgp->rspPutInx in the MAILBOX_tand fetch the new port
		 * response put pointer.
		 */
		if (pring->rspidx == portRspPut) {
			portRspPut = le32_to_cpu(pgp->rspPutInx);
		}
	}			/* while (pring->rspidx != portRspPut) */

	if ((rspiocbp != 0) && (mask & HA_R0RE_REQ)) {
		/* At least one response entry has been freed */
		psli->slistat.iocbRspFull[ringno]++;
		/* SET RxRE_RSP in Chip Att register */
		status = ((CA_R0ATT | CA_R0RE_RSP) << (ringno * 4));
		writel(status, phba->CAregaddr);
		readl(phba->CAregaddr); /* flush */
	}
	if ((mask & HA_R0CE_RSP) && (pring->flag & LPFC_CALL_RING_AVAILABLE)) {
		pring->flag &= ~LPFC_CALL_RING_AVAILABLE;
		psli->slistat.iocbCmdEmpty[ringno]++;
		/*
		 * Force update of the local copy of cmdGetInx
		 */
		pring->local_getidx = le32_to_cpu(pgp->cmdGetInx);
		lpfc_sli_resume_iocb(phba, pring);

		if ((psli->sliinit.ringinit[ringno].lpfc_sli_cmd_available))
			(psli->sliinit.ringinit[ringno].
			 lpfc_sli_cmd_available) (phba, pring);

	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return (rc);
}

static uint32_t
lpfc_intr_prep(struct lpfc_hba * phba)
{
	uint32_t ha_copy;

	/* Ignore all interrupts during initialization. */
	if (phba->hba_state < LPFC_LINK_DOWN)
		return (0);

	/* Read host attention register to determine interrupt source */
	ha_copy = readl(phba->HAregaddr);

	/* Clear Attention Sources, except ERATT (to preserve status) & LATT
	 *    (ha_copy & ~(HA_ERATT | HA_LATT));
	 */
	writel((ha_copy & ~(HA_LATT | HA_ERATT)), phba->HAregaddr);
	readl(phba->HAregaddr); /* flush */
	return (ha_copy);
}				/* lpfc_intr_prep */

int
lpfc_sli_intr(struct lpfc_hba * phba)
{
	struct lpfc_sli *psli;
	struct lpfc_sli_ring *pring;
	uint32_t ha_copy;
	unsigned long status;
	int i;
	unsigned long iflag;

	psli = &phba->sli;
	psli->slistat.sliIntr++;

	/*
	 * Call the HBA to see if it is interrupting.  If not, don't claim
	 * the interrupt
	 */
	spin_lock_irqsave(phba->host->host_lock, iflag);
	ha_copy = lpfc_intr_prep(phba);
	if (!ha_copy) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return (1);
	}

	if (ha_copy & HA_ERATT) {
		/*
		 * There was a link/board error.  Read the status register to
		 * retrieve the error event and process it.
		 */
		psli->slistat.errAttnEvent++;
		status = readl(phba->HSregaddr);
		/* Clear Chip error bit */
		writel(HA_ERATT, phba->HAregaddr);
		readl(phba->HAregaddr); /* flush */
		phba->stopped = 1;
	       /*
	      	  All error attention handlers are posted to
		  discovery tasklet
	       */

		lpfc_discq_post_event(phba, (void *)status, NULL,
				      LPFC_EVT_ERR_ATTN);
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return (0);
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	if (ha_copy & HA_MBATT) {
		/* There was a Mailbox event. */
		lpfc_sli_handle_mb_event(phba);
	}

	if (ha_copy & HA_LATT) {
		/*
		 * There was a link attention event.  Provided the driver is in
		 * a state to handle link events, handle this event.
		 */
		if (psli->sliinit.sli_flag & LPFC_PROCESS_LA) {
			lpfc_handle_latt(phba);
		}
	}

	/* Process all events on each ring */
	for (i = 0; i < psli->sliinit.num_rings; i++) {
		pring = &psli->ring[i];
		if ((ha_copy & HA_RXATT)
		    || (pring->flag & LPFC_DEFERRED_RING_EVENT)) {
			if (pring->flag & LPFC_STOP_IOCB_MASK) {
				pring->flag |= LPFC_DEFERRED_RING_EVENT;
			} else {
				lpfc_sli_handle_ring_event(phba, pring,
							   (ha_copy &
							    HA_RXMASK));
				pring->flag &= ~LPFC_DEFERRED_RING_EVENT;
			}
		}
		ha_copy = (ha_copy >> 4);
	}

	return (0);
}

int
lpfc_sli_abort_iocb_ring(struct lpfc_hba * phba, struct lpfc_sli_ring * pring,
			 uint32_t flag)
{
	struct lpfc_sli *psli;
	struct lpfc_iocbq *iocb, *next_iocb;
	struct lpfc_iocbq *abtsiocbp;
	IOCB_t *icmd = NULL, *cmd = NULL;
	int errcnt;
	uint16_t iotag;

	psli = &phba->sli;
	errcnt = 0;

	/* Error everything on txq and txcmplq
	 * First do the txq.
	 */
	list_for_each_entry_safe(iocb, next_iocb, &pring->txq, list) {
		list_del_init(&iocb->list);
		if (iocb->iocb_cmpl) {
			icmd = &iocb->iocb;
			icmd->ulpStatus = IOSTAT_LOCAL_REJECT;
			icmd->un.ulpWord[4] = IOERR_SLI_ABORTED;
			(iocb->iocb_cmpl) (phba, iocb, iocb);
		} else {
			mempool_free( iocb, phba->iocb_mem_pool);
		}
	}

	pring->txq_cnt = 0;
	INIT_LIST_HEAD(&(pring->txq));

	/* Next issue ABTS for everything on the txcmplq */
	list_for_each_entry_safe(iocb, next_iocb, &pring->txcmplq, list) {
		cmd = &iocb->iocb;

		if (flag == LPFC_SLI_ABORT_IMED) {
			/*
			 * Imediate abort of IOCB, clear fast_lookup entry,
			 * if any, deque and call compl
			 */
			iotag = cmd->ulpIoTag;
			if (pring->fast_lookup &&
			    iotag &&
			    (iotag <
			     psli->sliinit.ringinit[pring->ringno].fast_iotag))
				*(pring->fast_lookup + iotag) = NULL;

			list_del_init(&iocb->list);
			pring->txcmplq_cnt--;

			if (iocb->iocb_cmpl) {
				cmd->ulpStatus = IOSTAT_LOCAL_REJECT;
				cmd->un.ulpWord[4] = IOERR_SLI_ABORTED;
				(iocb->iocb_cmpl) (phba, iocb, iocb);
			} else {
				mempool_free( iocb, phba->iocb_mem_pool);
			}
			continue;
		}

		/* issue ABTS for this IOCB based on iotag */

		if ((abtsiocbp = mempool_alloc(phba->iocb_mem_pool,
					       GFP_ATOMIC)) == 0) {
			errcnt++;
			continue;
		}
		memset(abtsiocbp, 0, sizeof (struct lpfc_iocbq));
		icmd = &abtsiocbp->iocb;

		icmd->un.acxri.abortType = ABORT_TYPE_ABTS;
		icmd->un.acxri.abortContextTag = cmd->ulpContext;
		icmd->un.acxri.abortIoTag = cmd->ulpIoTag;

		icmd->ulpLe = 1;
		icmd->ulpClass = cmd->ulpClass;
		if (phba->hba_state >= LPFC_LINK_UP) {
			icmd->ulpCommand = CMD_ABORT_XRI_CN;
		} else {
			icmd->ulpCommand = CMD_CLOSE_XRI_CN;

		}

		if (lpfc_sli_issue_iocb
		    (phba, pring, abtsiocbp, 0) == IOCB_ERROR) {
			mempool_free(abtsiocbp, phba->iocb_mem_pool);
			errcnt++;
			continue;
		}
		/* The rsp ring completion will remove IOCB from txcmplq when
		 * abort is read by HBA.
		 */
	}

	if (flag == LPFC_SLI_ABORT_IMED) {
		INIT_LIST_HEAD(&(pring->txcmplq));
		pring->txcmplq_cnt = 0;
	}

	return (errcnt);
}


#define BARRIER_TEST_PATTERN (0xdeadbeef)

void lpfc_reset_barrier(struct lpfc_hba * phba)
{
	uint32_t * resp_buf;
	uint32_t * mbox_buf;
	volatile uint32_t mbox;
	uint32_t hc_copy;
	int  i;
	uint8_t hdrtype;

	pci_read_config_byte(phba->pcidev, PCI_HEADER_TYPE, &hdrtype);
	if (hdrtype != 0x80 ||
	    (FC_JEDEC_ID(phba->vpd.rev.biuRev) != HELIOS_JEDEC_ID &&
	     FC_JEDEC_ID(phba->vpd.rev.biuRev) != THOR_JEDEC_ID))
		return;

	/*
	 * Tell the other part of the chip to suspend temporarily all
	 * its DMA activity.
	 */
	resp_buf =  (uint32_t *)phba->MBslimaddr;

	/* Disable the error attention */
	hc_copy = readl(phba->HCregaddr);
	writel((hc_copy & ~HC_ERINT_ENA), phba->HCregaddr);
	readl(phba->HCregaddr); /* flush */

	mbox = 0;
	((MAILBOX_t *)&mbox)->mbxCommand = MBX_KILL_BOARD;
	((MAILBOX_t *)&mbox)->mbxOwner = OWN_CHIP;

	writel(BARRIER_TEST_PATTERN, (resp_buf + 1));
	mbox_buf = (uint32_t *)phba->MBslimaddr;
	writel(mbox, mbox_buf);

	for (i = 0;
	     readl(resp_buf + 1) != ~(BARRIER_TEST_PATTERN) && i < 50; i++)
		LPFC_MDELAY(1);

	if (readl(resp_buf + 1) != ~(BARRIER_TEST_PATTERN)) {
		if (phba->sli.sliinit.sli_flag & LPFC_SLI2_ACTIVE ||
		    phba->stopped)
			goto restore_hc;
		else
			goto clear_errat;
	}

	((MAILBOX_t *)&mbox)->mbxOwner = OWN_HOST;
	for (i = 0; readl(resp_buf) != mbox &&  i < 500; i++)
		LPFC_MDELAY(1);

clear_errat:

	while (!(readl(phba->HAregaddr) & HA_ERATT) && ++i < 500)
		LPFC_MDELAY(1);

	/* Clear Chip error bit */
	if (readl(phba->HAregaddr) & HA_ERATT) {
		writel(HA_ERATT, phba->HAregaddr);
		readl(phba->HAregaddr); /* flush */
		phba->stopped = 1;
	}

restore_hc:
	writel(hc_copy, phba->HCregaddr);
	readl(phba->HCregaddr); /* flush */
}

int
lpfc_sli_brdkill(struct lpfc_hba * phba)
{
	struct lpfc_sli *psli;
	LPFC_MBOXQ_t *pmb;
	uint32_t status;
	uint32_t ha_copy;
	int retval;
	int i = 0;

	psli = &phba->sli;

	/* Kill HBA */
	lpfc_printf_log(phba,
		KERN_INFO,
		LOG_SLI,
		"%d:0329 Kill HBA Data: x%x x%x\n",
		phba->brd_no,
		phba->hba_state,
		psli->sliinit.sli_flag);

	if ((pmb = (LPFC_MBOXQ_t *) mempool_alloc(phba->mbox_mem_pool,
						  GFP_KERNEL)) == 0) {
		return 1;
	}

	spin_lock_irq(phba->host->host_lock);

	/* Disable the error attention */
	status = readl(phba->HCregaddr);
	status &= ~HC_ERINT_ENA;
	writel(status, phba->HCregaddr);
	readl(phba->HCregaddr); /* flush */

	lpfc_kill_board(phba, pmb);
	pmb->mbox_cmpl = lpfc_sli_def_mbox_cmpl;
	retval = lpfc_sli_issue_mbox(phba, pmb, MBX_NOWAIT);
	/* Disable SLI2 */
	psli->sliinit.sli_flag &= ~LPFC_SLI2_ACTIVE;

	spin_unlock_irq_dump(phba->host->host_lock);
	if (retval != MBX_SUCCESS) {
		if (retval != MBX_BUSY)
			mempool_free(pmb, phba->mbox_mem_pool);
		return 1;
	}

	mempool_free(pmb, phba->mbox_mem_pool);

	/* There is no completion for a KILL_BOARD mbox cmd. Check for an error
	 * attention every 100ms for 3 seconds. If we don't get ERATT after
	 * 3 seconds we still set HBA_ERROR state because the status of the
	 * board is now undefined.
	 */
	ha_copy = readl(phba->HAregaddr);

	while ((i++ < 30) && !(ha_copy & HA_ERATT)) {
		LPFC_MDELAY(100);
		ha_copy = readl(phba->HAregaddr);
	}

	del_timer_sync(&psli->mbox_tmo);

	if (ha_copy & HA_ERATT) {
		writel(HA_ERATT, phba->HAregaddr);
		phba->stopped = 1;
	}

	spin_lock_irq(phba->host->host_lock);

	psli->sliinit.sli_flag &= ~LPFC_SLI_MBOX_ACTIVE;
	psli->mbox_active = NULL;

	lpfc_hba_down_post(phba);

	phba->hba_state = LPFC_HBA_ERROR;

	spin_unlock_irq_dump(phba->host->host_lock);

	return (ha_copy & HA_ERATT ? 0 : 1);
}

int
lpfc_sli_brdreset(struct lpfc_hba * phba)
{
	struct lpfc_sli *psli;
	struct lpfc_sli_ring *pring;
	uint16_t cfg_value;
	int i;

	psli = &phba->sli;

	/* Reset HBA */
	lpfc_printf_log(phba,
		KERN_INFO,
		LOG_SLI,
		"%d:0325 Reset HBA Data: x%x x%x\n",
		phba->brd_no,
		phba->hba_state,
		psli->sliinit.sli_flag);

	/* perform board reset */
	phba->fc_eventTag = 0;
	phba->fc_myDID = 0;
	phba->fc_prevDID = 0;

	psli->sliinit.sli_flag = 0;

	/* Turn off parity checking and serr during the physical reset */
	pci_read_config_word(phba->pcidev, PCI_COMMAND, &cfg_value);
	pci_write_config_word(phba->pcidev, PCI_COMMAND,
			      (cfg_value &
			       ~(PCI_COMMAND_PARITY | PCI_COMMAND_SERR)));

	/* Disable SLI2 */
	psli->sliinit.sli_flag &= ~LPFC_SLI2_ACTIVE;
	/* Now toggle INITFF bit in the Host Control Register */
	writel(HC_INITFF, phba->HCregaddr);
	LPFC_MDELAY(1);
	readl(phba->HCregaddr); /* flush */
	writel(0, phba->HCregaddr);
	readl(phba->HCregaddr); /* flush */

	/* Restore PCI cmd register */
	pci_write_config_word(phba->pcidev, PCI_COMMAND, cfg_value);

	/* Initialize relevant SLI info */
	for (i = 0; i < psli->sliinit.num_rings; i++) {
		pring = &psli->ring[i];
		pring->flag = 0;
		pring->rspidx = 0;
		pring->next_cmdidx  = 0;
		pring->local_getidx = 0;
		pring->cmdidx = 0;
		pring->missbufcnt = 0;
	}

	phba->hba_state = LPFC_WARM_START;
	return 0;
}

int
lpfc_sli_brdrestart(struct lpfc_hba * phba)
{
	MAILBOX_t *mb;
	struct lpfc_sli *psli;
	uint16_t skip_post;
	volatile uint32_t word0;
	void *to_slim;

	spin_lock_irq(phba->host->host_lock);
	lpfc_reset_barrier(phba);
	psli = &phba->sli;
	/* Restart HBA */
	lpfc_printf_log(phba,
		KERN_INFO,
		LOG_SLI,
		"%d:0328 Restart HBA Data: x%x x%x\n",
		phba->brd_no,
		phba->hba_state,
		psli->sliinit.sli_flag);

	word0 = 0;
	mb = (MAILBOX_t *) &word0;
	mb->mbxCommand = MBX_RESTART;
	mb->mbxHc = 1;

	to_slim = phba->MBslimaddr;
	writel(*(uint32_t *) mb, to_slim);
	readl(to_slim); /* flush */

	/* Only skip post after fc_ffinit is completed */
	if (phba->hba_state) {
		skip_post = 1;
		word0 = 1;	/* This is really setting up word1 */
	} else {
		skip_post = 0;
		word0 = 0;	/* This is really setting up word1 */
	}
	to_slim = (uint8_t *) phba->MBslimaddr + sizeof (uint32_t);
	writel(*(uint32_t *) mb, to_slim);
	readl(to_slim); /* flush */

	lpfc_sli_brdreset(phba);
	phba->stopped = 0;
	phba->hba_state = LPFC_INIT_START;

	spin_unlock_irq_dump(phba->host->host_lock);

	if (skip_post) {
		LPFC_MDELAY(100);
	} else {
		LPFC_MDELAY(2000);
	}

	lpfc_hba_down_post(phba);

	return 0;
}

static void
lpfc_setup_slim_access(struct lpfc_hba *phba)
{
	phba->MBslimaddr = phba->slim_memmap_p;
	phba->HAregaddr = (uint32_t *) (phba->ctrl_regs_memmap_p) +
		HA_REG_OFFSET;
	phba->HCregaddr = (uint32_t *) (phba->ctrl_regs_memmap_p) +
		HC_REG_OFFSET;
	phba->CAregaddr = (uint32_t *) (phba->ctrl_regs_memmap_p) +
		CA_REG_OFFSET;
	phba->HSregaddr = (uint32_t *) (phba->ctrl_regs_memmap_p) +
		HS_REG_OFFSET;
	return;
}

int
lpfc_sli_hba_setup(struct lpfc_hba * phba)
{
	struct lpfc_sli *psli;
	LPFC_MBOXQ_t *pmb;
	int read_rev_reset, i, rc;
	uint32_t status;

	psli = &phba->sli;

	/* Setep SLI interface for HBA register and HBA SLIM access */
	lpfc_setup_slim_access(phba);

	read_rev_reset = 0;

	/* On some platforms/OS's, the driver can't rely on the state the
	 * adapter may be in.  For this reason, the driver is allowed to reset
	 * the HBA before initialization.
	 */
	phba->hba_state = LPFC_STATE_UNKNOWN;	/* Do post */
	lpfc_sli_brdrestart(phba);

	/* Sleep for 2.5 sec */
	msleep(2500);

top:
	/* Read the HBA Host Status Register */
	status = readl(phba->HSregaddr);

	/* Check status register to see what current state is */
	i = 0;
	while ((status & (HS_FFRDY | HS_MBRDY)) != (HS_FFRDY | HS_MBRDY)) {

		/* Check every 100ms for 5 retries, then every 500ms for 5, then
		 * every 2.5 sec for 5, then reset board and every 2.5 sec for
		 * 4.
		 */
		if (i++ >= 20) {
			/* Adapter failed to init, timeout, status reg
			   <status> */
			lpfc_printf_log(phba,
					KERN_ERR,
					LOG_INIT,
					"%d:0436 Adapter failed to init, "
					"timeout, status reg x%x\n",
					phba->brd_no,
					status);
			phba->hba_state = LPFC_HBA_ERROR;
			return -ETIMEDOUT;
		}

		/* Check to see if any errors occurred during init */
		if (status & HS_FFERM) {
			/* ERROR: During chipset initialization */
			/* Adapter failed to init, chipset, status reg
			   <status> */
			lpfc_printf_log(phba,
					KERN_ERR,
					LOG_INIT,
					"%d:0437 Adapter failed to init, "
					"chipset, status reg x%x\n",
					phba->brd_no,
					status);
			phba->hba_state = LPFC_HBA_ERROR;
			return -EIO;
		}

		if (i <= 5) {
			msleep(10);
		} else if (i <= 10) {
			msleep(500);
		} else {
			msleep(2500);
		}

		if (i == 15) {
			phba->hba_state = LPFC_STATE_UNKNOWN; /* Do post */
			lpfc_sli_brdrestart(phba);
		}
		/* Read the HBA Host Status Register */
		status = readl(phba->HSregaddr);
	}

	/* Check to see if any errors occurred during init */
	if (status & HS_FFERM) {
		/* ERROR: During chipset initialization */
		/* Adapter failed to init, chipset, status reg <status> */
		lpfc_printf_log(phba,
				KERN_ERR,
				LOG_INIT,
				"%d:0438 Adapter failed to init, chipset, "
				"status reg x%x\n",
				phba->brd_no,
				status);
		phba->hba_state = LPFC_HBA_ERROR;
		return -EIO;
	}

	/* Clear all interrupt enable conditions */
	writel(0, phba->HCregaddr);
	readl(phba->HCregaddr); /* flush */

	/* setup host attn register */
	writel(0xffffffff, phba->HAregaddr);
	readl(phba->HAregaddr); /* flush */

	/* Get a Mailbox buffer to setup mailbox commands for HBA
	   initialization */
	if ((pmb = (LPFC_MBOXQ_t *) mempool_alloc(phba->mbox_mem_pool,
						  GFP_ATOMIC)) == 0) {
		phba->hba_state = LPFC_HBA_ERROR;
		return -ENOMEM;
	}

	/* Call pre CONFIG_PORT mailbox command initialization.  A value of 0
	 * means the call was successful.  Any other nonzero value is a failure,
	 * but if ERESTART is returned, the driver may reset the HBA and try
	 * again.
	 */
	if ((rc = lpfc_config_port_prep(phba))) {
		if ((rc == -ERESTART) && (read_rev_reset == 0)) {
			mempool_free( pmb, phba->mbox_mem_pool);
			phba->hba_state = LPFC_STATE_UNKNOWN; /* Do post */
			lpfc_sli_brdrestart(phba);
			msleep(500);
			read_rev_reset = 1;
			goto top;
		}
		phba->hba_state = LPFC_HBA_ERROR;
		mempool_free( pmb, phba->mbox_mem_pool);
		return -ENXIO;
	}

	/* Setup and issue mailbox CONFIG_PORT command */
	phba->hba_state = LPFC_INIT_MBX_CMDS;
	lpfc_config_port(phba, pmb);
	if (lpfc_sli_issue_mbox(phba, pmb, MBX_POLL) != MBX_SUCCESS) {
		/* Adapter failed to init, mbxCmd <cmd> CONFIG_PORT,
		   mbxStatus <status> */
		lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
				"%d:0442 Adapter failed to init, mbxCmd x%x "
				"CONFIG_PORT, mbxStatus x%x Data: x%x\n",
				phba->brd_no, pmb->mb.mbxCommand,
				pmb->mb.mbxStatus, 0);

		/* This clause gives the config_port call is given multiple
		   chances to succeed. */
		if (read_rev_reset == 0) {
			mempool_free( pmb, phba->mbox_mem_pool);
			phba->hba_state = LPFC_STATE_UNKNOWN; /* Do post */
			lpfc_sli_brdrestart(phba);
			msleep(2500);
			read_rev_reset = 1;
			goto top;
		}

		psli->sliinit.sli_flag &= ~LPFC_SLI2_ACTIVE;
		phba->hba_state = LPFC_HBA_ERROR;
		mempool_free( pmb, phba->mbox_mem_pool);
		return -ENXIO;
	}

	if ((rc = lpfc_sli_ring_map(phba))) {
		phba->hba_state = LPFC_HBA_ERROR;
		mempool_free( pmb, phba->mbox_mem_pool);
		return -ENXIO;
	}
	psli->sliinit.sli_flag |= LPFC_PROCESS_LA;

	/* Call post CONFIG_PORT mailbox command initialization. */
	if ((rc = lpfc_config_port_post(phba))) {
		phba->hba_state = LPFC_HBA_ERROR;
		mempool_free( pmb, phba->mbox_mem_pool);
		return -ENXIO;
	}
	mempool_free( pmb, phba->mbox_mem_pool);
	return 0;
}


static void
lpfc_mbox_abort(struct lpfc_hba * phba)
{
	struct lpfc_sli *psli;
	LPFC_MBOXQ_t *pmbox;
	MAILBOX_t *mb;

	psli = &phba->sli;

	if (psli->mbox_active) {
		spin_unlock_irq_dump(phba->host->host_lock);
		del_timer_sync(&psli->mbox_tmo);
		spin_lock_irq(phba->host->host_lock);
		phba->work_hba_events &= ~WORKER_MBOX_TMO;
		pmbox = psli->mbox_active;
		mb = &pmbox->mb;
		psli->mbox_active = NULL;
		if (pmbox->mbox_cmpl) {
			mb->mbxStatus = MBX_NOT_FINISHED;
			(pmbox->mbox_cmpl) (phba, pmbox);
		}
		psli->sliinit.sli_flag &= ~LPFC_SLI_MBOX_ACTIVE;
	}

	/* Abort all the non active mailbox commands. */
	pmbox = lpfc_mbox_get(phba);
	while (pmbox) {
		mb = &pmbox->mb;
		if (pmbox->mbox_cmpl) {
			mb->mbxStatus = MBX_NOT_FINISHED;
			(pmbox->mbox_cmpl) (phba, pmbox);
		}
		pmbox = lpfc_mbox_get(phba);
	}
	return;
}
/*! lpfc_mbox_timeout
 *
 * \pre
 * \post
 * \param hba Pointer to per struct lpfc_hba structure
 * \param l1  Pointer to the driver's mailbox queue.
 * \return
 *   void
 *
 * \b Description:
 *
 * This routine handles mailbox timeout events at timer interrupt context.
 */
void
lpfc_mbox_timeout(unsigned long ptr)
{
	struct lpfc_hba *phba;
	unsigned long iflag;

	phba = (struct lpfc_hba *)ptr;
	spin_lock_irqsave(phba->host->host_lock, iflag);
	if (!(phba->work_hba_events & WORKER_MBOX_TMO)) {
		phba->work_hba_events |= WORKER_MBOX_TMO;
		if (phba->dpc_wait)
			up(phba->dpc_wait);
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
}

void
lpfc_mbox_timeout_handler(struct lpfc_hba *phba)
{
	struct lpfc_sli *psli;
	LPFC_MBOXQ_t *pmbox;
	MAILBOX_t *mb;

	psli = &phba->sli;
	spin_lock_irq(phba->host->host_lock);
	if (!(phba->work_hba_events & WORKER_MBOX_TMO)) {
		spin_unlock_irq_dump(phba->host->host_lock);
		return;
	}
	
	phba->work_hba_events &= ~WORKER_MBOX_TMO;

	pmbox = psli->mbox_active;
	mb = &pmbox->mb;

	/* Mbox cmd <mbxCommand> timeout */
	lpfc_printf_log(phba,
		KERN_ERR,
		LOG_MBOX | LOG_SLI,
		"%d:0310 Mailbox command x%x timeout Data: x%x x%x x%p\n",
		phba->brd_no,
		mb->mbxCommand,
		phba->hba_state,
		psli->sliinit.sli_flag,
		psli->mbox_active);

	if (psli->mbox_active == pmbox) {
		psli->mbox_active = NULL;
		if (pmbox->mbox_cmpl) {
			mb->mbxStatus = MBX_NOT_FINISHED;
			(pmbox->mbox_cmpl) (phba, pmbox);
		}
		psli->sliinit.sli_flag &= ~LPFC_SLI_MBOX_ACTIVE;
	}

	lpfc_mbox_abort(phba);
	spin_unlock_irq_dump(phba->host->host_lock);
	return;
}


int
lpfc_sli_issue_mbox(struct lpfc_hba * phba, LPFC_MBOXQ_t * pmbox, uint32_t flag)
{
	MAILBOX_t *mbox;
	MAILBOX_t *mb;
	struct lpfc_sli *psli;
	uint32_t status, evtctr;
	uint32_t ha_copy;
	int i;
	unsigned long drvr_flag = 0;
	volatile uint32_t word0, ldata;
	void *to_slim;

	psli = &phba->sli;
	if (flag & MBX_POLL) {
		spin_lock_irqsave(phba->host->host_lock, drvr_flag);
	}

	mb = &pmbox->mb;
	status = MBX_SUCCESS;

	if (phba->hba_state == LPFC_HBA_ERROR) {
		if (flag & MBX_POLL) {
			spin_unlock_irqrestore(phba->host->host_lock,
					       drvr_flag);
		}

		/* Mbox command <mbxCommand> cannot issue */
		LOG_MBOX_CANNOT_ISSUE_DATA( phba, mb, psli, flag)
		return (MBX_NOT_FINISHED);
	}

	if (mb->mbxCommand != MBX_KILL_BOARD && flag & MBX_NOWAIT &&
	    !(readl(phba->HCregaddr) & HC_MBINT_ENA)) {
		LOG_MBOX_CANNOT_ISSUE_DATA( phba, mb, psli, flag)
		return (MBX_NOT_FINISHED);
	}

	if (psli->sliinit.sli_flag & LPFC_SLI_MBOX_ACTIVE) {
		/* Polling for a mbox command when another one is already active
		 * is not allowed in SLI. Also, the driver must have established
		 * SLI2 mode to queue and process multiple mbox commands.
		 */

		if (flag & MBX_POLL) {
			spin_unlock_irqrestore(phba->host->host_lock,
					       drvr_flag);

			/* Mbox command <mbxCommand> cannot issue */
			LOG_MBOX_CANNOT_ISSUE_DATA( phba, mb, psli, flag)
			return (MBX_NOT_FINISHED);
		}

		if (!(psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE)) {

			/* Mbox command <mbxCommand> cannot issue */
			LOG_MBOX_CANNOT_ISSUE_DATA( phba, mb, psli, flag)
			return (MBX_NOT_FINISHED);
		}

		/* Handle STOP IOCB processing flag. This is only meaningful
		 * if we are not polling for mbox completion.
		 */
		if (flag & MBX_STOP_IOCB) {
			flag &= ~MBX_STOP_IOCB;
			/* Now flag each ring */
			for (i = 0; i < psli->sliinit.num_rings; i++) {
				/* If the ring is active, flag it */
				if (psli->ring[i].cmdringaddr) {
					psli->ring[i].flag |=
					    LPFC_STOP_IOCB_MBX;
				}
			}
		}

		/* Another mailbox command is still being processed, queue this
		 * command to be processed later.
		 */
		lpfc_mbox_put(phba, pmbox);

		/* Mbox cmd issue - BUSY */
		lpfc_printf_log(phba,
			KERN_INFO,
			LOG_MBOX | LOG_SLI,
			"%d:0308 Mbox cmd issue - BUSY Data: x%x x%x x%x x%x\n",
			phba->brd_no,
			mb->mbxCommand,
			phba->hba_state,
			psli->sliinit.sli_flag,
			flag);

		psli->slistat.mboxBusy++;
		if (flag == MBX_POLL) {
			spin_unlock_irqrestore(phba->host->host_lock,
					       drvr_flag);
		}
		return (MBX_BUSY);
	}

	/* Handle STOP IOCB processing flag. This is only meaningful
	 * if we are not polling for mbox completion.
	 */
	if (flag & MBX_STOP_IOCB) {
		flag &= ~MBX_STOP_IOCB;
		if (flag == MBX_NOWAIT) {
			/* Now flag each ring */
			for (i = 0; i < psli->sliinit.num_rings; i++) {
				/* If the ring is active, flag it */
				if (psli->ring[i].cmdringaddr) {
					psli->ring[i].flag |=
					    LPFC_STOP_IOCB_MBX;
				}
			}
		}
	}

	psli->sliinit.sli_flag |= LPFC_SLI_MBOX_ACTIVE;

	/* If we are not polling, we MUST be in SLI2 mode */
	if (flag != MBX_POLL) {
		if (!(psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE) &&
		    (mb->mbxCommand != MBX_KILL_BOARD)) {
			psli->sliinit.sli_flag &= ~LPFC_SLI_MBOX_ACTIVE;

			/* Mbox command <mbxCommand> cannot issue */
			LOG_MBOX_CANNOT_ISSUE_DATA( phba, mb, psli, flag);
			return (MBX_NOT_FINISHED);
		}
		/* timeout active mbox command */
		mod_timer(&psli->mbox_tmo, jiffies + HZ * LPFC_MBOX_TMO);
	}

	/* Mailbox cmd <cmd> issue */
	lpfc_printf_log(phba,
		KERN_INFO,
		LOG_MBOX | LOG_SLI,
		"%d:0309 Mailbox cmd x%x issue Data: x%x x%x x%x\n",
		phba->brd_no,
		mb->mbxCommand,
		phba->hba_state,
		psli->sliinit.sli_flag,
		flag);

	psli->slistat.mboxCmd++;
	evtctr = psli->slistat.mboxEvent;

	/* next set own bit for the adapter and copy over command word */
	mb->mbxOwner = OWN_CHIP;

	if (psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE) {

		/* First copy command data to host SLIM area */
		mbox = (MAILBOX_t *) psli->MBhostaddr;
		lpfc_sli_pcimem_bcopy((uint32_t *) mb, (uint32_t *) mbox,
				      (sizeof (uint32_t) *
				       (MAILBOX_CMD_WSIZE)));

	} else {
		if (mb->mbxCommand == MBX_CONFIG_PORT) {
			/* copy command data into host mbox for cmpl */
			mbox = (MAILBOX_t *) psli->MBhostaddr;
			lpfc_sli_pcimem_bcopy((uint32_t *) mb,
					      (uint32_t *) mbox,
					      (sizeof (uint32_t) *
					       (MAILBOX_CMD_WSIZE)));
		}

		/* First copy mbox command data to HBA SLIM, skip past first
		   word */
		to_slim = (uint8_t *) phba->MBslimaddr + sizeof (uint32_t);
		lpfc_memcpy_to_slim(to_slim, (void *)&mb->un.varWords[0],
			    (MAILBOX_CMD_WSIZE - 1) * sizeof (uint32_t));

		/* Next copy over first word, with mbxOwner set */
		ldata = *((volatile uint32_t *)mb);
		to_slim = phba->MBslimaddr;
		writel(ldata, to_slim);
		readl(to_slim); /* flush */

		if (mb->mbxCommand == MBX_CONFIG_PORT) {
			/* switch over to host mailbox */
			psli->sliinit.sli_flag |= LPFC_SLI2_ACTIVE;
		}
	}

	wmb();
	/* interrupt board to doit right away */
	writel(CA_MBATT, phba->CAregaddr);
	readl(phba->CAregaddr); /* flush */

	switch (flag) {
	case MBX_NOWAIT:
		/* Don't wait for it to finish, just return */
		psli->mbox_active = pmbox;
		break;

	case MBX_POLL:
		i = 0;
		psli->mbox_active = NULL;
		if (psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE) {
			/* First read mbox status word */
			mbox = (MAILBOX_t *) psli->MBhostaddr;
			word0 = *((volatile uint32_t *)mbox);
			word0 = le32_to_cpu(word0);
		} else {
			/* First read mbox status word */
			word0 = readl(phba->MBslimaddr);
		}

		/* Read the HBA Host Attention Register */
		ha_copy = readl(phba->HAregaddr);

		/* Wait for command to complete */
		while (((word0 & OWN_CHIP) == OWN_CHIP) ||
		       (!(ha_copy & HA_MBATT) &&
			(phba->hba_state > LPFC_WARM_START))) {
			if (i++ >= 5000) {
				psli->sliinit.sli_flag &= ~LPFC_SLI_MBOX_ACTIVE;
				spin_unlock_irqrestore(phba->host->host_lock,
						       drvr_flag);
				return (MBX_NOT_FINISHED);
			}

			/* Check if we took a mbox interrupt while we were
			   polling */
			if (((word0 & OWN_CHIP) != OWN_CHIP)
			    && (evtctr != psli->slistat.mboxEvent))
				break;

			/* Can be in interrupt context, do not sleep */
			/* (or might be called with interrupts disabled) */
			udelay(1000);


			if (psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE) {
				/* First copy command data */
				mbox = (MAILBOX_t *) psli->MBhostaddr;
				word0 = *((volatile uint32_t *)mbox);
				word0 = le32_to_cpu(word0);
				if (mb->mbxCommand == MBX_CONFIG_PORT) {
					MAILBOX_t *slimmb;
					volatile uint32_t slimword0;
					/* Check real SLIM for any errors */
					slimword0 = readl(phba->MBslimaddr);
					slimmb = (MAILBOX_t *) & slimword0;
					if (((slimword0 & OWN_CHIP) != OWN_CHIP)
					    && slimmb->mbxStatus) {
						psli->sliinit.sli_flag &=
						    ~LPFC_SLI2_ACTIVE;
						word0 = slimword0;
					}
				}
			} else {
				/* First copy command data */
				word0 = readl(phba->MBslimaddr);
			}
			/* Read the HBA Host Attention Register */
			ha_copy = readl(phba->HAregaddr);
		}

		if (psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE) {
			/* First copy command data */
			mbox = (MAILBOX_t *) psli->MBhostaddr;
			/* copy results back to user */
			lpfc_sli_pcimem_bcopy((uint32_t *) mbox,
					      (uint32_t *) mb,
					      (sizeof (uint32_t) *
					       MAILBOX_CMD_WSIZE));
		} else {
			/* First copy command data */
			lpfc_memcpy_from_slim((void *)mb,
				      phba->MBslimaddr,
				      sizeof (uint32_t) * (MAILBOX_CMD_WSIZE));
         		if ((mb->mbxCommand == MBX_DUMP_MEMORY) &&
				pmbox->context2) {
				lpfc_memcpy_from_slim((void *)pmbox->context2,
				      phba->MBslimaddr + DMP_RSP_OFFSET,
               			      mb->un.varDmp.word_cnt);
			}
		}

		writel(HA_MBATT, phba->HAregaddr);
		readl(phba->HAregaddr); /* flush */

		psli->sliinit.sli_flag &= ~LPFC_SLI_MBOX_ACTIVE;
		status = mb->mbxStatus;
	}

	if (flag == MBX_POLL) {
		spin_unlock_irqrestore(phba->host->host_lock, drvr_flag);
	}
	return (status);
}

static struct lpfc_iocbq *
lpfc_sli_next_iocb(struct lpfc_hba *phba, struct lpfc_sli_ring *pring,
		   struct lpfc_iocbq ** piocb)
{
	struct lpfc_iocbq * nextiocb;

	nextiocb = lpfc_sli_ringtx_get(phba, pring);
	if (!nextiocb) {
		nextiocb = *piocb;
		*piocb = NULL;
	}

	return nextiocb;
}

int
lpfc_sli_issue_iocb(struct lpfc_hba *phba, struct lpfc_sli_ring *pring,
		    struct lpfc_iocbq *piocb, uint32_t flag)
{
	struct lpfc_sli *psli = &phba->sli;
	int ringno = pring->ringno;
	struct lpfc_iocbq *nextiocb;
	IOCB_t *iocb;

	/*
	 * We should never get an IOCB if we are in a < LINK_DOWN state
	 */
	if (unlikely(phba->hba_state < LPFC_LINK_DOWN))
		return IOCB_ERROR;

	/*
	 * Check to see if we are blocking IOCB processing because of a
	 * outstanding mbox command.
	 */
	if (unlikely(pring->flag & LPFC_STOP_IOCB_MBX))
		goto iocb_busy;

	if (unlikely(phba->hba_state == LPFC_LINK_DOWN)) {
		/*
		 * Only CREATE_XRI, CLOSE_XRI, ABORT_XRI, and QUE_RING_BUF
		 * can be issued if the link is not up.
		 */
		switch (piocb->iocb.ulpCommand) {
		case CMD_QUE_RING_BUF_CN:
		case CMD_QUE_RING_BUF64_CN:
			/*
			 * For IOCBs, like QUE_RING_BUF, that have no rsp ring
			 * completion, iocb_cmpl MUST be 0.
			 */
			if (piocb->iocb_cmpl)
				piocb->iocb_cmpl = NULL;
			/*FALLTHROUGH*/
		case CMD_CREATE_XRI_CR:
			break;
		default:
			goto iocb_busy;
		}

	/*
	 * For FCP commands, we must be in a state where we can process link
	 * attention events.
	 */
	} else if (unlikely(pring->ringno == psli->fcp_ring &&
		   !(psli->sliinit.sli_flag & LPFC_PROCESS_LA)))
		goto iocb_busy;

	/*
	 * Check to see if this is a high priority command.
	 * If so bypass tx queue processing.
	 */
	if (unlikely((flag & SLI_IOCB_HIGH_PRIORITY) &&
		     (iocb = lpfc_sli_next_iocb_slot(phba, pring)))) {
		if (lpfc_sli_submit_iocb(phba, pring, iocb, piocb))
			goto iocb_busy;
		piocb = NULL;
	}

	while ((iocb = lpfc_sli_next_iocb_slot(phba, pring)) &&
	       (nextiocb = lpfc_sli_next_iocb(phba, pring, &piocb)))
		if (lpfc_sli_submit_iocb(phba, pring, iocb, nextiocb))
			break;

	if (iocb)
		lpfc_sli_update_ring(phba, pring);
	else
		lpfc_sli_update_full_ring(phba, pring);

	if (!piocb)
		return IOCB_SUCCESS;

	goto out_busy;

 iocb_busy:
	psli->slistat.iocbCmdDelay[ringno]++;

 out_busy:

	if (!(flag & SLI_IOCB_RET_IOCB)) {
		lpfc_sli_ringtx_put(phba, pring, piocb);
		return IOCB_SUCCESS;
	}

	return IOCB_BUSY;
}

int
lpfc_sli_queue_setup(struct lpfc_hba * phba)
{
	struct lpfc_sli *psli;
	struct lpfc_sli_ring *pring;
	int i, cnt;

	psli = &phba->sli;
	INIT_LIST_HEAD(&psli->mboxq);
	/* Initialize list headers for txq and txcmplq as double linked lists */
	for (i = 0; i < psli->sliinit.num_rings; i++) {
		pring = &psli->ring[i];
		pring->ringno = i;
		pring->next_cmdidx  = 0;
		pring->local_getidx = 0;
		pring->cmdidx = 0;
		INIT_LIST_HEAD(&pring->txq);
		INIT_LIST_HEAD(&pring->txcmplq);
		INIT_LIST_HEAD(&pring->iocb_continueq);
		INIT_LIST_HEAD(&pring->postbufq);
		cnt = psli->sliinit.ringinit[i].fast_iotag;
		if (cnt) {
			pring->fast_lookup =
				kmalloc(cnt * sizeof (struct lpfc_iocbq *),
					GFP_KERNEL);
			if (pring->fast_lookup == 0) {
				return (0);
			}
			memset((char *)pring->fast_lookup, 0,
			       cnt * sizeof (struct lpfc_iocbq *));
		}
	}
	return (1);
}

int
lpfc_sli_hba_down(struct lpfc_hba * phba)
{
	struct lpfc_sli *psli;
	struct lpfc_sli_ring *pring;
	LPFC_MBOXQ_t *pmb;
	struct lpfc_iocbq *iocb, *next_iocb;
	IOCB_t *icmd = NULL;
	int i;

	psli = &phba->sli;
	lpfc_hba_down_prep(phba);

	for (i = 0; i < psli->sliinit.num_rings; i++) {
		pring = &psli->ring[i];
		pring->flag |= LPFC_DEFERRED_RING_EVENT;

		/*
		 * Error everything on the txq since these iocbs have not been
		 * given to the FW yet.
		 */
		pring->txq_cnt = 0;

		list_for_each_entry_safe(iocb, next_iocb, &pring->txq, list) {
			list_del_init(&iocb->list);
			if (iocb->iocb_cmpl) {
				icmd = &iocb->iocb;
				icmd->ulpStatus = IOSTAT_LOCAL_REJECT;
				icmd->un.ulpWord[4] = IOERR_SLI_DOWN;
				(iocb->iocb_cmpl) (phba, iocb, iocb);
			} else {
				mempool_free( iocb, phba->iocb_mem_pool);
			}
		}

		INIT_LIST_HEAD(&(pring->txq));

		if (pring->fast_lookup) {
			kfree(pring->fast_lookup);
			pring->fast_lookup = NULL;
		}

	}

	/* Return any active mbox cmds */
	spin_unlock_irq_dump(phba->host->host_lock);
	del_timer_sync(&psli->mbox_tmo);
	spin_lock_irq(phba->host->host_lock);
	phba->work_hba_events &= ~WORKER_MBOX_TMO;
	if ((psli->mbox_active)) {
		pmb = psli->mbox_active;
		pmb->mb.mbxStatus = MBX_NOT_FINISHED;
		if (pmb->mbox_cmpl)
			pmb->mbox_cmpl(phba,pmb);
	}
	psli->sliinit.sli_flag &= ~LPFC_SLI_MBOX_ACTIVE;
	psli->mbox_active = NULL;

	/* Return any pending mbox cmds */
	while ((pmb = lpfc_mbox_get(phba)) != NULL) {
		pmb->mb.mbxStatus = MBX_NOT_FINISHED;
		if (pmb->mbox_cmpl)
			pmb->mbox_cmpl(phba,pmb);
	}

	INIT_LIST_HEAD(&psli->mboxq);

	return 1;
}

void
lpfc_sli_pcimem_bcopy(uint32_t * src, uint32_t * dest, uint32_t cnt)
{
	uint32_t ldata;
	int i;

	for (i = 0; i < (int)cnt; i += sizeof (uint32_t)) {
		ldata = *src++;
		ldata = le32_to_cpu(ldata);
		*dest++ = ldata;
	}
}

int
lpfc_sli_ringpostbuf_put(struct lpfc_hba * phba, struct lpfc_sli_ring * pring,
			 struct lpfc_dmabuf * mp)
{
	/* Stick struct lpfc_dmabuf at end of postbufq so driver can look it up
	   later */
	list_add_tail(&mp->list, &pring->postbufq);

	pring->postbufq_cnt++;
	return 0;
}


struct lpfc_dmabuf *
lpfc_sli_ringpostbuf_get(struct lpfc_hba *phba, struct lpfc_sli_ring *pring,
			 dma_addr_t phys)
{
	struct lpfc_dmabuf *mp, *next_mp;
	struct list_head *slp = &pring->postbufq;

	/* Search postbufq, from the begining, looking for a match on phys */
	list_for_each_entry_safe(mp, next_mp, &pring->postbufq, list) {
		if (mp->phys == phys) {
			list_del_init(&mp->list);
			pring->postbufq_cnt--;
			return mp;
		}
	}

	lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
			"%d:0410 Cannot find virtual addr for mapped buf on "
			"ring %d Data x%llx x%p x%p x%x\n",
			phba->brd_no, pring->ringno, (unsigned long long)phys,
			slp->next, slp->prev, pring->postbufq_cnt);
	return NULL;
}

static void
lpfc_sli_abort_elsreq_cmpl(struct lpfc_hba * phba, struct lpfc_iocbq * cmdiocb,
			   struct lpfc_iocbq * rspiocb)
{
	struct lpfc_dmabuf *buf_ptr, *buf_ptr1;
	/* Free the resources associated with the ELS_REQUEST64 IOCB the driver
	 * just aborted.
	 * In this case, context2  = cmd,  context2->next = rsp, context3 = bpl
	 */
	if (cmdiocb->context2) {
		buf_ptr1 = (struct lpfc_dmabuf *) cmdiocb->context2;

		/* Free the response IOCB before completing the abort
		   command.  */
		if (!list_empty(&buf_ptr1->list)) {

			buf_ptr = list_entry(buf_ptr1->list.next,
					     struct lpfc_dmabuf, list);

			list_del(&buf_ptr->list);
			lpfc_mbuf_free(phba, buf_ptr->virt, buf_ptr->phys);
			kfree(buf_ptr);
		}
		lpfc_mbuf_free(phba, buf_ptr1->virt, buf_ptr1->phys);
		kfree(buf_ptr1);
	}

	if (cmdiocb->context3) {
		buf_ptr = (struct lpfc_dmabuf *) cmdiocb->context3;
		lpfc_mbuf_free(phba, buf_ptr->virt, buf_ptr->phys);
		kfree(buf_ptr);
	}
	mempool_free( cmdiocb, phba->iocb_mem_pool);
	return;
}

int
lpfc_sli_issue_abort_iotag32(struct lpfc_hba * phba,
			     struct lpfc_sli_ring * pring,
			     struct lpfc_iocbq * cmdiocb)
{
	struct lpfc_sli *psli;
	struct lpfc_iocbq *abtsiocbp;
	IOCB_t *icmd = NULL;
	IOCB_t *iabt = NULL;
	uint32_t iotag32;

	psli = &phba->sli;

	/* issue ABTS for this IOCB based on iotag */
	if ((abtsiocbp = mempool_alloc(phba->iocb_mem_pool, GFP_ATOMIC)) == 0) {
		return (0);
	}
	memset(abtsiocbp, 0, sizeof (struct lpfc_iocbq));
	iabt = &abtsiocbp->iocb;

	icmd = &cmdiocb->iocb;
	switch (icmd->ulpCommand) {
	case CMD_ELS_REQUEST64_CR:
		iotag32 = icmd->un.elsreq64.bdl.ulpIoTag32;
		/* Even though we abort the ELS command, the firmware may access
		 * the BPL or other resources before it processes our
		 * ABORT_MXRI64. Thus we must delay reusing the cmdiocb
		 * resources till the actual abort request completes.
		 */
		abtsiocbp->context1 = (void *)((unsigned long)icmd->ulpCommand);
		abtsiocbp->context2 = cmdiocb->context2;
		abtsiocbp->context3 = cmdiocb->context3;
		cmdiocb->context2 = NULL;
		cmdiocb->context3 = NULL;
		abtsiocbp->iocb_cmpl = lpfc_sli_abort_elsreq_cmpl;
		break;
	default:
		mempool_free( abtsiocbp, phba->iocb_mem_pool);
		return (0);
	}

	iabt->un.amxri.abortType = ABORT_TYPE_ABTS;
	iabt->un.amxri.iotag32 = iotag32;

	iabt->ulpLe = 1;
	iabt->ulpClass = CLASS3;
	iabt->ulpCommand = CMD_ABORT_MXRI64_CN;

	if (lpfc_sli_issue_iocb(phba, pring, abtsiocbp, 0) == IOCB_ERROR) {
		mempool_free( abtsiocbp, phba->iocb_mem_pool);
		return (0);
	}

	return (1);
}

void
lpfc_sli_abort_fcp_cmpl(struct lpfc_hba * phba, struct lpfc_iocbq * cmdiocb,
                           struct lpfc_iocbq * rspiocb)
{
	/*
	 * Just free the iocbq resources back to the memory pool.  This was an
	 * abort command and has no other outstanding resources associated with
	 * it.
	 */
	mempool_free(cmdiocb, phba->iocb_mem_pool);
}


int
lpfc_sli_abort_iocb_ctx(struct lpfc_hba * phba, struct lpfc_sli_ring * pring,
			uint32_t ctx)
{
	struct lpfc_sli *psli;
	struct lpfc_iocbq *iocb, *next_iocb;
	struct lpfc_iocbq *abtsiocbp;
	IOCB_t *icmd = NULL, *cmd = NULL;
	int errcnt;

	psli = &phba->sli;
	errcnt = 0;

	/* Error matching iocb on txq or txcmplq
	 * First check the txq.
	 */
	list_for_each_entry_safe(iocb, next_iocb, &pring->txq, list) {
		cmd = &iocb->iocb;
		if (cmd->ulpContext != ctx) {
			continue;
		}

		list_del_init(&iocb->list);
		pring->txq_cnt--;
		if (iocb->iocb_cmpl) {
			icmd = &iocb->iocb;
			icmd->ulpStatus = IOSTAT_LOCAL_REJECT;
			icmd->un.ulpWord[4] = IOERR_SLI_ABORTED;
			(iocb->iocb_cmpl) (phba, iocb, iocb);
		} else {
			mempool_free( iocb, phba->iocb_mem_pool);
		}
	}

	/* Next check the txcmplq */
	list_for_each_entry_safe(iocb, next_iocb, &pring->txcmplq, list) {
		cmd = &iocb->iocb;
		if (cmd->ulpContext != ctx) {
			continue;
		}

		/* issue ABTS for this IOCB based on iotag */
		if ((abtsiocbp = mempool_alloc(phba->iocb_mem_pool,
					       GFP_ATOMIC)) == 0) {
			errcnt++;
			continue;
		}
		memset(abtsiocbp, 0, sizeof (struct lpfc_iocbq));
		icmd = &abtsiocbp->iocb;

		icmd->un.acxri.abortType = ABORT_TYPE_ABTS;
		icmd->un.acxri.abortContextTag = cmd->ulpContext;
		icmd->un.acxri.abortIoTag = cmd->ulpIoTag;

		icmd->ulpLe = 1;
		icmd->ulpClass = cmd->ulpClass;
		abtsiocbp->iocb_cmpl = lpfc_sli_abort_fcp_cmpl;
		if (phba->hba_state >= LPFC_LINK_UP) {
			icmd->ulpCommand = CMD_ABORT_XRI_CN;
		} else {
			icmd->ulpCommand = CMD_CLOSE_XRI_CN;
		}

		if (lpfc_sli_issue_iocb(phba, pring, abtsiocbp, 0) ==
								IOCB_ERROR) {
			mempool_free( abtsiocbp, phba->iocb_mem_pool);
			errcnt++;
			continue;
		}
		/* The rsp ring completion will remove IOCB from txcmplq when
		 * abort is read by HBA.
		 */
	}
	return (errcnt);
}

int
lpfc_sli_sum_iocb_host(struct lpfc_hba * phba,
			struct lpfc_sli_ring * pring)
{
	struct lpfc_sli *psli;
	struct lpfc_iocbq *iocb, *next_iocb;
	IOCB_t *cmd = NULL;
	struct lpfc_scsi_buf *lpfc_cmd;
	int sum;

	psli = &phba->sli;
	sum = 0;

	/* Error matching iocb on txq or txcmplq
	 * First check the txq.
	 */
	list_for_each_entry_safe(iocb, next_iocb, &pring->txq, list) {
		cmd = &iocb->iocb;

		/* Must be a FCP command */
		if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
		    (cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
		    (cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
			continue;
		}

		/* context1 MUST be a struct lpfc_scsi_buf */
		lpfc_cmd = (struct lpfc_scsi_buf *) (iocb->context1);
		if (lpfc_cmd == 0) {
			continue;
		}
		sum++;
	}

	/* Next check the txcmplq */
	list_for_each_entry_safe(iocb, next_iocb, &pring->txcmplq, list) {
		cmd = &iocb->iocb;

		/* Must be a FCP command */
		if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
		    (cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
		    (cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
			continue;
		}

		/* context1 MUST be a struct lpfc_scsi_buf */
		lpfc_cmd = (struct lpfc_scsi_buf *) (iocb->context1);
		if (lpfc_cmd == 0) {
			continue;
		}
		sum++;
	}
	return (sum);
}

int
lpfc_sli_abort_iocb_host(struct lpfc_hba * phba,
			struct lpfc_sli_ring * pring, int flag)
{
	struct lpfc_sli *psli;
	struct lpfc_iocbq *iocb, *next_iocb;
	struct lpfc_iocbq *abtsiocbp;
	IOCB_t *icmd = NULL, *cmd = NULL;
	struct lpfc_scsi_buf *lpfc_cmd;
	int errcnt;

	psli = &phba->sli;
	errcnt = 0;

	/* Error matching iocb on txq or txcmplq
	 * First check the txq.
	 */
	if(flag & LPFC_ABORT_TXQ) {
		list_for_each_entry_safe(iocb, next_iocb, &pring->txq, list) {
			cmd = &iocb->iocb;

			/* Must be a FCP command */
			if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
		    	(cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
		    	(cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
				continue;
			}

			/* context1 MUST be a struct lpfc_scsi_buf */
			lpfc_cmd = (struct lpfc_scsi_buf *) (iocb->context1);
			if (lpfc_cmd == 0) {
				continue;
			}

			list_del_init(&iocb->list);
			pring->txq_cnt--;
			if (iocb->iocb_cmpl) {
				icmd = &iocb->iocb;
				icmd->ulpStatus = IOSTAT_LOCAL_REJECT;
				icmd->un.ulpWord[4] = IOERR_SLI_ABORTED;
				(iocb->iocb_cmpl) (phba, iocb, iocb);
			} else {
				mempool_free( iocb, phba->iocb_mem_pool);
			}
		}
	}

	if(flag & LPFC_ABORT_TXCMPLQ) {
		/* Next check the txcmplq */
		list_for_each_entry_safe(iocb, next_iocb, &pring->txcmplq,
					 list) {
			cmd = &iocb->iocb;

			/* Must be a FCP command */
			if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
			    (cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
			    (cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
				continue;
			}

			/* context1 MUST be a struct lpfc_scsi_buf */
			lpfc_cmd = (struct lpfc_scsi_buf *) (iocb->context1);
			if (lpfc_cmd == 0) {
				continue;
			}

			/* issue ABTS for this IOCB based on iotag */
			if ((abtsiocbp = mempool_alloc(phba->iocb_mem_pool,
						       GFP_ATOMIC)) == 0) {
				errcnt++;
				continue;
			}
			memset(abtsiocbp, 0, sizeof (struct lpfc_iocbq));
			icmd = &abtsiocbp->iocb;

			icmd->un.acxri.abortType = ABORT_TYPE_ABTS;
			icmd->un.acxri.abortContextTag = cmd->ulpContext;
			icmd->un.acxri.abortIoTag = cmd->ulpIoTag;

			icmd->ulpLe = 1;
			icmd->ulpClass = cmd->ulpClass;
			abtsiocbp->iocb_cmpl = lpfc_sli_abort_fcp_cmpl;
			if (phba->hba_state >= LPFC_LINK_UP) {
				icmd->ulpCommand = CMD_ABORT_XRI_CN;
			} else {
				icmd->ulpCommand = CMD_CLOSE_XRI_CN;
			}

			if (lpfc_sli_issue_iocb(phba, pring, abtsiocbp, 0) ==
								IOCB_ERROR) {
				mempool_free( abtsiocbp, phba->iocb_mem_pool);
				errcnt++;
				continue;
			}
			/* The rsp ring completion will remove IOCB from
			 * tacmplq when abort is read by HBA.
			 */
		}
	}
	return (errcnt);
}

int
lpfc_sli_sum_iocb_lun(struct lpfc_hba * phba,
			struct lpfc_sli_ring * pring,
			uint16_t scsi_target, uint64_t scsi_lun)
{
	struct lpfc_sli *psli;
	struct lpfc_iocbq *iocb, *next_iocb;
	IOCB_t *cmd = NULL;
	struct lpfc_scsi_buf *lpfc_cmd;
	int sum;

	psli = &phba->sli;
	sum = 0;

	/* Error matching iocb on txq or txcmplq
	 * First check the txq.
	 */
	list_for_each_entry_safe(iocb, next_iocb, &pring->txq, list) {
		cmd = &iocb->iocb;

		/* Must be a FCP command */
		if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
		    (cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
		    (cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
			continue;
		}

		/* context1 MUST be a struct lpfc_scsi_buf */
		lpfc_cmd = (struct lpfc_scsi_buf *) (iocb->context1);
		if ((lpfc_cmd == 0) ||
		    (lpfc_cmd->target == 0) ||
		    (lpfc_cmd->target->scsi_id != scsi_target) ||
		    (lpfc_cmd->lun != scsi_lun)) {
			continue;
		}
		sum++;
	}

	/* Next check the txcmplq */
	list_for_each_entry_safe(iocb, next_iocb, &pring->txcmplq, list) {
		cmd = &iocb->iocb;

		/* Must be a FCP command */
		if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
		    (cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
		    (cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
			continue;
		}

		/* context1 MUST be a struct lpfc_scsi_buf */
		lpfc_cmd = (struct lpfc_scsi_buf *) (iocb->context1);
		if ((lpfc_cmd == 0) ||
		    (lpfc_cmd->target == 0) ||
		    (lpfc_cmd->target->scsi_id != scsi_target) ||
		    (lpfc_cmd->lun != scsi_lun)) {
			continue;
		}

		sum++;
	}
	return (sum);
}

int
lpfc_sli_abort_iocb_lun(struct lpfc_hba * phba,
			struct lpfc_sli_ring * pring,
			uint16_t scsi_target, uint64_t scsi_lun, int flag)
{
	struct lpfc_sli *psli;
	struct lpfc_iocbq *iocb, *next_iocb;
	struct lpfc_iocbq *abtsiocbp;
	IOCB_t *icmd = NULL, *cmd = NULL;
	struct lpfc_scsi_buf *lpfc_cmd;
	int errcnt;

	psli = &phba->sli;
	errcnt = 0;

	/* Error matching iocb on txq or txcmplq
	 * First check the txq.
	 */
	if(flag & LPFC_ABORT_TXQ) {
		list_for_each_entry_safe(iocb, next_iocb, &pring->txq, list) {
			cmd = &iocb->iocb;

			/* Must be a FCP command */
			if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
			    (cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
			    (cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
				continue;
			}

			/* context1 MUST be a struct lpfc_scsi_buf */
			lpfc_cmd = (struct lpfc_scsi_buf *) (iocb->context1);
			if ((lpfc_cmd == 0) ||
			    (lpfc_cmd->target == 0) ||
			    (lpfc_cmd->target->scsi_id != scsi_target) ||
			    (lpfc_cmd->lun != scsi_lun)) {
				continue;
			}

			list_del_init(&iocb->list);
			pring->txq_cnt--;
			if (iocb->iocb_cmpl) {
				icmd = &iocb->iocb;
				icmd->ulpStatus = IOSTAT_LOCAL_REJECT;
				icmd->un.ulpWord[4] = IOERR_SLI_ABORTED;
				(iocb->iocb_cmpl) (phba, iocb, iocb);
			} else {
				mempool_free( iocb, phba->iocb_mem_pool);
			}
		}
	}

	if(flag & LPFC_ABORT_TXCMPLQ) {
		/* Next check the txcmplq */
		list_for_each_entry_safe(iocb, next_iocb, &pring->txcmplq,
					 list) {
			cmd = &iocb->iocb;

			/* Must be a FCP command */
			if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
			    (cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
			    (cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
				continue;
			}

			/* context1 MUST be a struct lpfc_scsi_buf */
			lpfc_cmd = (struct lpfc_scsi_buf *) (iocb->context1);
			if ((lpfc_cmd == 0) ||
			    (lpfc_cmd->target == 0) ||
			    (lpfc_cmd->target->scsi_id != scsi_target) ||
			    (lpfc_cmd->lun != scsi_lun)) {
				continue;
			}

			/* issue ABTS for this IOCB based on iotag */
			if ((abtsiocbp = mempool_alloc(phba->iocb_mem_pool,
						       GFP_ATOMIC)) == 0) {
				errcnt++;
				continue;
			}
			memset(abtsiocbp, 0, sizeof (struct lpfc_iocbq));
			icmd = &abtsiocbp->iocb;

			icmd->un.acxri.abortType = ABORT_TYPE_ABTS;
			icmd->un.acxri.abortContextTag = cmd->ulpContext;
			icmd->un.acxri.abortIoTag = cmd->ulpIoTag;

			icmd->ulpLe = 1;
			icmd->ulpClass = cmd->ulpClass;
			abtsiocbp->iocb_cmpl = lpfc_sli_abort_fcp_cmpl;
			if (phba->hba_state >= LPFC_LINK_UP) {
				icmd->ulpCommand = CMD_ABORT_XRI_CN;
			} else {
				icmd->ulpCommand = CMD_CLOSE_XRI_CN;
			}

			if (lpfc_sli_issue_iocb(phba, pring, abtsiocbp, 0) ==
								IOCB_ERROR) {
				mempool_free( abtsiocbp, phba->iocb_mem_pool);
				errcnt++;
				continue;
			}
			/* The rsp ring completion will remove IOCB from
			 * tacmplq when abort is read by HBA.
			 */
		}
	}
	return (errcnt);
}

int
lpfc_sli_abort_iocb_tgt(struct lpfc_hba * phba,
			struct lpfc_sli_ring * pring,
			uint16_t scsi_target, int flag)
{
	struct lpfc_sli *psli;
	struct lpfc_iocbq *iocb, *next_iocb;
	struct lpfc_iocbq *abtsiocbp;
	IOCB_t *icmd = NULL, *cmd = NULL;
	struct lpfc_scsi_buf *lpfc_cmd;
	int errcnt;

	psli = &phba->sli;
	errcnt = 0;

	/* Error matching iocb on txq or txcmplq
	 * First check the txq.
	 */
	if(flag & LPFC_ABORT_TXQ) {
		list_for_each_entry_safe(iocb, next_iocb, &pring->txq, list) {
			cmd = &iocb->iocb;

			/* Must be a FCP command */
			if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
			    (cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
			    (cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
				continue;
			}

			/* context1 MUST be a struct lpfc_scsi_buf */
			lpfc_cmd = (struct lpfc_scsi_buf *) (iocb->context1);
			if ((lpfc_cmd == 0) ||
			    (lpfc_cmd->target == 0) ||
			    (lpfc_cmd->target->scsi_id != scsi_target)) {
				continue;
			}

			list_del_init(&iocb->list);
			pring->txq_cnt--;
			if (iocb->iocb_cmpl) {
				icmd = &iocb->iocb;
				icmd->ulpStatus = IOSTAT_LOCAL_REJECT;
				icmd->un.ulpWord[4] = IOERR_SLI_ABORTED;
				(iocb->iocb_cmpl) (phba, iocb, iocb);
			} else {
				mempool_free( iocb, phba->iocb_mem_pool);
			}
		}
	}

	if(flag & LPFC_ABORT_TXCMPLQ) {
		/* Next check the txcmplq */
		list_for_each_entry_safe(iocb, next_iocb, &pring->txcmplq,
					 list) {
			cmd = &iocb->iocb;

			/* Must be a FCP command */
			if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
			    (cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
			    (cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
				continue;
			}

			/* context1 MUST be a struct lpfc_scsi_buf */
			lpfc_cmd = (struct lpfc_scsi_buf *) (iocb->context1);
			if ((lpfc_cmd == 0) ||
			    (lpfc_cmd->target == 0) ||
			    (lpfc_cmd->target->scsi_id != scsi_target)) {
				continue;
			}

			/* issue ABTS for this IOCB based on iotag */
			if ((abtsiocbp = mempool_alloc(phba->iocb_mem_pool,
				GFP_ATOMIC)) == 0) {
				errcnt++;
				continue;
			}
			memset(abtsiocbp, 0, sizeof (struct lpfc_iocbq));
			icmd = &abtsiocbp->iocb;

			icmd->un.acxri.abortType = ABORT_TYPE_ABTS;
			icmd->un.acxri.abortContextTag = cmd->ulpContext;
			icmd->un.acxri.abortIoTag = cmd->ulpIoTag;

			icmd->ulpLe = 1;
			icmd->ulpClass = cmd->ulpClass;
			abtsiocbp->iocb_cmpl = lpfc_sli_abort_fcp_cmpl;
			if (phba->hba_state >= LPFC_LINK_UP) {
				icmd->ulpCommand = CMD_ABORT_XRI_CN;
			} else {
				icmd->ulpCommand = CMD_CLOSE_XRI_CN;
			}

			if (lpfc_sli_issue_iocb(phba, pring, abtsiocbp, 0) ==
								IOCB_ERROR) {
				mempool_free( abtsiocbp, phba->iocb_mem_pool);
				errcnt++;
				continue;
			}
			/* The rsp ring completion will remove IOCB from
			 * txcmplq when abort is read by HBA.
			 */
		}
	}
	return (errcnt);
}



void
lpfc_sli_wake_iocb_high_priority(struct lpfc_hba * phba,
				 struct lpfc_iocbq * queue1,
				 struct lpfc_iocbq * queue2)
{
	if (queue1->context2 && queue2)
		memcpy(queue1->context2, queue2, sizeof (struct lpfc_iocbq));

	/* The waiter is looking for LPFC_IO_HIPRI bit to be set
	   as a signal to wake up */
	queue1->iocb_flag |= LPFC_IO_HIPRI;
	return;
}

static void
lpfc_sli_wake_iocb_high_priority_cleanup(struct lpfc_hba * phba,
					struct lpfc_iocbq * queue1,
					struct lpfc_iocbq * queue2)
{
	struct lpfc_scsi_buf *lpfc_cmd = queue1->context1;

	/*
	 * Just free the iocbq back to the mempool.  The driver
	 * has stopped polling and this routine will execute as
	 * a result of the subsequent abort.
	 */
	mempool_free(queue1->context2, phba->iocb_mem_pool);
	lpfc_free_scsi_buf(lpfc_cmd);
	return;
}

int
lpfc_sli_issue_iocb_wait_high_priority(struct lpfc_hba * phba,
				       struct lpfc_sli_ring * pring,
				       struct lpfc_iocbq * piocb,
				       uint32_t flag,
				       struct lpfc_iocbq * prspiocbq)
{
	int wait_time = 0, retval = IOCB_ERROR;

	/* The caller must left context1 empty.  */
	if (piocb->context_un.hipri_wait_queue != 0) {
		return IOCB_ERROR;
	}

	/*
	 * If the caller has provided a response iocbq buffer, context2 must
	 * be NULL or its an error.
	 */
	if (prspiocbq && piocb->context2) {
		return IOCB_ERROR;
	}

	piocb->context2 = prspiocbq;

	/* Setup callback routine and issue the command. */
	piocb->iocb_cmpl = lpfc_sli_wake_iocb_high_priority;
	retval = lpfc_sli_issue_iocb(phba, pring, piocb,
					flag | SLI_IOCB_HIGH_PRIORITY);
	if (retval != IOCB_SUCCESS) {
		piocb->context2 = NULL;
		return IOCB_ERROR;
	}

	/*
	 * This high-priority iocb was sent out-of-band.  Poll for its
	 * completion rather than wait for a signal.  Note that the host_lock
	 * is held by the midlayer and must be released here to allow the
	 * interrupt handlers to complete the IO and signal this routine via
	 * the iocb_flag.
	 * The driver waits a maximum of 600 seconds to give the FW ample time
	 * to complete the target reset ABTS.  The race is not waiting long 
	 * enough and then having the FW complete the request before the driver
	 * can issue the second abort.  Since a solicited completion is required
	 * by the FW, this wait period should be enough time for the FW to
	 * complete the abts successfully or give up.
	 */

	retval = IOCB_TIMEDOUT;
	spin_unlock_irq_dump(phba->host->host_lock);
	while (wait_time <= 600000) {
#ifdef SLES_FC
		mdelay(100);
#else
		msleep(100);
#endif

#if defined(RHEL_FC) && defined(DISKDUMP_FC)
		/* Call SLI to handle the interrupt event. */
		if(crashdump_mode())
			lpfc_sli_intr(phba);
#endif
		if (piocb->iocb_flag & LPFC_IO_HIPRI) {
			piocb->iocb_flag &= ~LPFC_IO_HIPRI;
			retval = IOCB_SUCCESS;
			break;
		}
		wait_time += 100;
	}

	spin_lock_irq(phba->host->host_lock);

	/*
	 * If the polling attempt failed to get a completion from the HBA, 
	 * then substitute the initial completion function with one that
	 * releases the piocb back to the mempool.  Failure to do this 
	 * results in a memory leak.  Also note the small timing race that
	 * exists between the driver giving up and a completion coming in.
	 */
	if ((retval == IOCB_TIMEDOUT) && !(piocb->iocb_flag & LPFC_IO_HIPRI)) {
		lpfc_printf_log(phba, KERN_ERR, LOG_SLI,
				"%d:0327 waited %d mSecs for high priority "
				"IOCB %p - giving up\n",
				phba->brd_no, wait_time, piocb);
		piocb->iocb_cmpl = lpfc_sli_wake_iocb_high_priority_cleanup;
	}

	piocb->context2 = NULL;

	return retval;
}

int
lpfc_sli_issue_mbox_wait(struct lpfc_hba * phba, LPFC_MBOXQ_t * pmboxq,
			 uint32_t timeout)
{
	DECLARE_WAIT_QUEUE_HEAD(done_q);
	DECLARE_WAITQUEUE(wq_entry, current);
	uint32_t timeleft = 0;
	int retval;

	/* The caller must leave context1 empty. */
	if (pmboxq->context1 != 0) {
		return (MBX_NOT_FINISHED);
	}

	/* setup wake call as IOCB callback */
	pmboxq->mbox_cmpl = lpfc_sli_wake_mbox_wait;
	/* setup context field to pass wait_queue pointer to wake function  */
	pmboxq->context1 = &done_q;

	/* start to sleep before we wait, to avoid races */
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&done_q, &wq_entry);

	/* now issue the command */
	spin_lock_irq(phba->host->host_lock);
	retval = lpfc_sli_issue_mbox(phba, pmboxq, MBX_NOWAIT);
	spin_unlock_irq_dump(phba->host->host_lock);

	if (retval == MBX_BUSY || retval == MBX_SUCCESS) {
		timeleft = schedule_timeout(timeout * HZ);
		pmboxq->context1 = NULL;
		/* if schedule_timeout returns 0, we timed out and were not
		   woken up */
		if ((timeleft == 0) || signal_pending(current))
			retval = MBX_TIMEOUT;
		else
			retval = MBX_SUCCESS;
	}


	set_current_state(TASK_RUNNING);
	remove_wait_queue(&done_q, &wq_entry);
	return retval;
}

static void
lpfc_sli_wake_iocb_wait(struct lpfc_hba * phba,
			struct lpfc_iocbq * queue1, struct lpfc_iocbq * queue2)
{
	wait_queue_head_t *pdone_q;

	queue1->iocb_flag |= LPFC_IO_WAIT;
	if (queue1->context2 && queue2)
		memcpy(queue1->context2, queue2, sizeof (struct lpfc_iocbq));

	/*
	 * If pdone_q is empty, the waiter gave up and returned and this
	 * call has nothing to do.
	 */
	pdone_q = queue1->context_un.hipri_wait_queue;
	if (pdone_q) {
		wake_up(pdone_q);
	}

	return;
}

int
lpfc_sli_issue_iocb_wait(struct lpfc_hba * phba,
			 struct lpfc_sli_ring * pring,
			 struct lpfc_iocbq * piocb,
			 struct lpfc_iocbq * prspiocbq, uint32_t timeout)
{
	DECLARE_WAIT_QUEUE_HEAD(done_q);
	DECLARE_WAITQUEUE(wq_entry, current);
	uint32_t timeleft = 0;
	int retval;

	/* The caller must leave context1 empty for the driver. */
	if (piocb->context_un.hipri_wait_queue != 0)
		return (IOCB_ERROR);

	/* If the caller has provided a response iocbq buffer, then context2
	 * is NULL or its an error.
	 */
	if (prspiocbq) {
		if (piocb->context2)
			return (IOCB_ERROR);
		piocb->context2 = prspiocbq;
	}

	/* setup wake call as IOCB callback */
	piocb->iocb_cmpl = lpfc_sli_wake_iocb_wait;
	/* setup context field to pass wait_queue pointer to wake function  */
	piocb->context_un.hipri_wait_queue = &done_q;

	/* start to sleep before we wait, to avoid races */
	set_current_state(TASK_UNINTERRUPTIBLE);
	add_wait_queue(&done_q, &wq_entry);

	/* now issue the command */
	retval = lpfc_sli_issue_iocb(phba, pring, piocb, 0);
	if (retval == IOCB_SUCCESS) {
		/* Give up thread time and wait for the iocb to complete or for
		 * the alloted time to expire.
		 */
		spin_unlock_irq_dump(phba->host->host_lock);
		timeleft = schedule_timeout(timeout * HZ);
		spin_lock_irq(phba->host->host_lock);

		piocb->context_un.hipri_wait_queue = NULL;
		piocb->iocb_cmpl = NULL;
		if (piocb->context2 == prspiocbq)
			piocb->context2 = NULL;

		/*
		 * Catch the error cases.  A timeleft of zero is an error since
		 * the iocb should have completed.  The iocb_flag not have value
		 * LPFC_IO_WAIT is also an error since the wakeup callback sets
		 * this flag when it runs.  Handle each.
		 */
		if (!(piocb->iocb_flag & LPFC_IO_WAIT)) {
			printk(KERN_ERR "%s: Timeleft is %d, iocb_flags is 0x%x ring_no %d ulpCommand 0x%x`\n ",
			       __FUNCTION__, timeleft, piocb->iocb_flag,
				pring->ringno, piocb->iocb.ulpCommand);
			retval = IOCB_TIMEDOUT;
		}
	}

	remove_wait_queue(&done_q, &wq_entry);
	set_current_state(TASK_RUNNING);
	piocb->context2 = NULL;
	return retval;
}

irqreturn_t
lpfc_intr_handler(int irq, void *dev_id, struct pt_regs * regs)
{
	struct lpfc_hba *phba;
	int intr_status;

	/*
	 * Get the driver's phba structure from the dev_id and
	 * assume the HBA is not interrupting.
	 */
	phba = (struct lpfc_hba *) dev_id;

	if (phba) {
		/* Call SLI to handle the interrupt event. */
		intr_status = lpfc_sli_intr(phba);
		if (intr_status == 0)
			return IRQ_HANDLED;
	}

	return IRQ_NONE;

} /* lpfc_intr_handler */

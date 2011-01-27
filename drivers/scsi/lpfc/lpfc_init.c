/*******************************************************************
 * This file is part of the Emulex Linux Device Driver for         *
 * Fibre Channel Host Bus Adapters.                                *
 * Copyright (C) 2003-2007 Emulex.  All rights reserved.           *
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
 * $Id: lpfc_init.c 3039 2007-05-22 14:40:23Z sf_support $
 */

#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/ctype.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/spinlock.h>

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
#include "lpfc_version.h"
#include "lpfc_compat.h"

static int lpfc_parse_vpd(struct lpfc_hba *, uint8_t *, int);
static void lpfc_get_hba_model_desc(struct lpfc_hba *, uint8_t *, uint8_t *);
static int lpfc_post_rcv_buf(struct lpfc_hba *);
static int lpfc_rdrev_wd30 = 0;

/************************************************************************/
/*                                                                      */
/*    lpfc_config_port_prep                                             */
/*    This routine will do LPFC initialization prior to the             */
/*    CONFIG_PORT mailbox command. This will be initialized             */
/*    as a SLI layer callback routine.                                  */
/*    This routine returns 0 on success or -ERESTART if it wants        */
/*    the SLI layer to reset the HBA and try again. Any                 */
/*    other return value indicates an error.                            */
/*                                                                      */
/************************************************************************/
int
lpfc_config_port_prep(struct lpfc_hba * phba)
{
	lpfc_vpd_t *vp = &phba->vpd;
	int i = 0;
	LPFC_MBOXQ_t *pmb;
	MAILBOX_t *mb;
	uint32_t *lpfc_vpd_data = 0;
	uint16_t offset = 0;

	/* Get a Mailbox buffer to setup mailbox commands for HBA
	   initialization */
	pmb = mempool_alloc(phba->mbox_mem_pool, GFP_ATOMIC);
	if (!pmb) {
		phba->hba_state = LPFC_HBA_ERROR;
		return -ENOMEM;
	}

	mb = &pmb->mb;
	phba->hba_state = LPFC_INIT_MBX_CMDS;

	/* special handling for LC HBAs */
	if (lpfc_is_LC_HBA(phba->pcidev->device)) {
		char licensed[56] =
		    "key unlock for use with gnu public licensed code only\0";
		uint32_t *ptext = (uint32_t *) licensed;

		for (i = 0; i < 56; i += sizeof (uint32_t), ptext++)
			*ptext = cpu_to_be32(*ptext);

		/* Setup and issue mailbox READ NVPARAMS command */
		lpfc_read_nv(phba, pmb);
		memset((char*)mb->un.varRDnvp.rsvd3, 0,
			sizeof (mb->un.varRDnvp.rsvd3));
		memcpy((char*)mb->un.varRDnvp.rsvd3, licensed,
			 sizeof (licensed));

		if (lpfc_sli_issue_mbox(phba, pmb, MBX_POLL) != MBX_SUCCESS) {
			/* Adapter initialization error, mbxCmd <cmd>
			   READ_NVPARM, mbxStatus <status> */
			lpfc_printf_log(phba,
					KERN_ERR,
					LOG_MBOX,
					"%d:0324 Config Port initialization "
					"error, mbxCmd x%x READ_NVPARM, "
					"mbxStatus x%x\n",
					phba->brd_no,
					mb->mbxCommand, mb->mbxStatus);
			mempool_free( pmb, phba->mbox_mem_pool);
			return -ERESTART;
		}
		memcpy(phba->wwnn, (char *)mb->un.varRDnvp.nodename,
		       sizeof (mb->un.varRDnvp.nodename));
	}

	/* Setup and issue mailbox READ REV command */
	lpfc_read_rev(phba, pmb);
	if (lpfc_sli_issue_mbox(phba, pmb, MBX_POLL) != MBX_SUCCESS) {
		/* Adapter failed to init, mbxCmd <mbxCmd> READ_REV, mbxStatus
		   <status> */
		lpfc_printf_log(phba,
				KERN_ERR,
				LOG_INIT,
				"%d:0439 Adapter failed to init, mbxCmd x%x "
				"READ_REV, mbxStatus x%x\n",
				phba->brd_no,
				mb->mbxCommand, mb->mbxStatus);
		mempool_free( pmb, phba->mbox_mem_pool);
		return -ERESTART;
	}

	/*
	 * The value of rr must be 1 since the driver set the cv field to 1.
	 * This setting requires the FW to set all revision fields.
	 */
	if (mb->un.varRdRev.rr == 0) {
		vp->rev.rBit = 0;
		lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
				"%d:0440 Adapter failed to init, READ_REV has "
				"missing revision information.\n",
				phba->brd_no);
		mempool_free(pmb, phba->mbox_mem_pool);
		return -ERESTART;
	}

	/* Save information as VPD data */
	vp->rev.rBit = 1;
	vp->rev.sli1FwRev = mb->un.varRdRev.sli1FwRev;
	memcpy(vp->rev.sli1FwName, (char*) mb->un.varRdRev.sli1FwName, 16);
	vp->rev.sli2FwRev = mb->un.varRdRev.sli2FwRev;
	memcpy(vp->rev.sli2FwName, (char *) mb->un.varRdRev.sli2FwName, 16);
	vp->rev.biuRev = mb->un.varRdRev.biuRev;
	vp->rev.smRev = mb->un.varRdRev.smRev;
	vp->rev.smFwRev = mb->un.varRdRev.un.smFwRev;
	vp->rev.endecRev = mb->un.varRdRev.endecRev;
	vp->rev.fcphHigh = mb->un.varRdRev.fcphHigh;
	vp->rev.fcphLow = mb->un.varRdRev.fcphLow;
	vp->rev.feaLevelHigh = mb->un.varRdRev.feaLevelHigh;
	vp->rev.feaLevelLow = mb->un.varRdRev.feaLevelLow;
	vp->rev.postKernRev = mb->un.varRdRev.postKernRev;
	vp->rev.opFwRev = mb->un.varRdRev.opFwRev;
	lpfc_rdrev_wd30 = mb->un.varWords[30];

	if (lpfc_is_LC_HBA(phba->pcidev->device))
		memcpy(phba->RandomData, (char *)&mb->un.varWords[24],
			sizeof (phba->RandomData));

	/* Get adapter VPD information */
	pmb->context2 = kmalloc(DMP_RSP_SIZE, GFP_ATOMIC);
	if (!pmb->context2)
		goto out_free_mbox;
	lpfc_vpd_data = kmalloc(DMP_VPD_SIZE, GFP_ATOMIC);
	if (!lpfc_vpd_data)
		goto out_free_context2;

	do {
		lpfc_dump_mem(phba, pmb, offset);
		if (lpfc_sli_issue_mbox(phba, pmb, MBX_POLL) != MBX_SUCCESS) {
			/* Let it go through even if failed. */
			/* Adapter failed to init, mbxCmd <cmd> DUMP VPD,
			   mbxStatus <status> */
			lpfc_printf_log(phba,
					KERN_INFO,
					LOG_INIT,
					"%d:0441 VPD not present on adapter, mbxCmd "
					"x%x DUMP VPD, mbxStatus x%x\n",
					phba->brd_no,
					mb->mbxCommand, mb->mbxStatus);
			mb->un.varDmp.word_cnt = 0;
		}
		if (mb->un.varDmp.word_cnt > DMP_VPD_SIZE - offset)
			mb->un.varDmp.word_cnt = DMP_VPD_SIZE - offset;
		lpfc_sli_pcimem_bcopy((uint32_t *)pmb->context2,
                                      (uint32_t*)((uint8_t*)lpfc_vpd_data + offset),
                                      mb->un.varDmp.word_cnt);

		offset += mb->un.varDmp.word_cnt;
	} while (mb->un.varDmp.word_cnt && offset < DMP_VPD_SIZE);

	lpfc_parse_vpd(phba, (uint8_t*)lpfc_vpd_data, offset);

	kfree(lpfc_vpd_data);
out_free_context2:
	kfree(pmb->context2);
out_free_mbox:
	mempool_free(pmb, phba->mbox_mem_pool);
	return 0;
}

/* Completion handler for config async event mailbox command. */
static void
lpfc_config_async_cmpl(struct lpfc_hba * phba, LPFC_MBOXQ_t * pmboxq)
{
	if (pmboxq->mb.mbxStatus == MBX_SUCCESS)
		phba->temp_sensor_support = 1;
	else
		phba->temp_sensor_support = 0;
	mempool_free(pmboxq, phba->mbox_mem_pool);
	return;
}

/************************************************************************/
/*                                                                      */
/*    lpfc_config_port_post                                             */
/*    This routine will do LPFC initialization after the                */
/*    CONFIG_PORT mailbox command. This will be initialized             */
/*    as a SLI layer callback routine.                                  */
/*    This routine returns 0 on success. Any other return value         */
/*    indicates an error.                                               */
/*                                                                      */
/************************************************************************/
int
lpfc_config_port_post(struct lpfc_hba * phba)
{
	LPFC_MBOXQ_t *pmb;
	MAILBOX_t *mb;
	struct lpfc_dmabuf *mp;
	struct lpfc_sli *psli = &phba->sli;
	uint32_t status, timeout;
	int i, j, k;
	unsigned long isr_cnt, clk_cnt;
	int rc;


	/* Get a Mailbox buffer to setup mailbox commands for HBA
	   initialization */
	pmb = mempool_alloc(phba->mbox_mem_pool, GFP_ATOMIC);
	if (!pmb) {
		phba->hba_state = LPFC_HBA_ERROR;
		return -ENOMEM;
	}
	mb = &pmb->mb;

	/* Setup link timers */
	lpfc_config_link(phba, pmb);
	if (lpfc_sli_issue_mbox(phba, pmb, MBX_POLL) != MBX_SUCCESS) {
		lpfc_printf_log(phba,
				KERN_ERR,
				LOG_INIT,
				"%d:0447 Adapter failed init, mbxCmd x%x "
				"CONFIG_LINK mbxStatus x%x\n",
				phba->brd_no,
				mb->mbxCommand, mb->mbxStatus);
		phba->hba_state = LPFC_HBA_ERROR;
		mempool_free( pmb, phba->mbox_mem_pool);
		return -EIO;
	}

	/* Get login parameters for NID.  */
	lpfc_read_sparam(phba, pmb);
	if (lpfc_sli_issue_mbox(phba, pmb, MBX_POLL) != MBX_SUCCESS) {
		lpfc_printf_log(phba,
				KERN_ERR,
				LOG_INIT,
				"%d:0448 Adapter failed init, mbxCmd x%x "
				"READ_SPARM mbxStatus x%x\n",
				phba->brd_no,
				mb->mbxCommand, mb->mbxStatus);
		phba->hba_state = LPFC_HBA_ERROR;
		mp = (struct lpfc_dmabuf *) pmb->context1;
		lpfc_mbuf_free(phba, mp->virt, mp->phys);
		kfree(mp);
		mempool_free( pmb, phba->mbox_mem_pool);
		return -EIO;
	}

	mp = (struct lpfc_dmabuf *) pmb->context1;

	memcpy(&phba->fc_sparam, mp->virt, sizeof (struct serv_parm));
	lpfc_mbuf_free(phba, mp->virt, mp->phys);
	kfree(mp);
	pmb->context1 = NULL;

	if (phba->cfg_soft_wwpn)
		lpfc_u64_to_wwn(phba->cfg_soft_wwpn, (uint8_t *)&phba->fc_sparam.portName);
	memcpy(&phba->fc_nodename, &phba->fc_sparam.nodeName,
	       sizeof (struct lpfc_name));
	memcpy(&phba->fc_portname, &phba->fc_sparam.portName,
	       sizeof (struct lpfc_name));
	/* If no serial number in VPD data, use low 6 bytes of WWNN */
	/* This should be consolidated into parse_vpd ? - mr */
	if (phba->SerialNumber[0] == 0) {
		uint8_t *outptr;

		outptr = (uint8_t *) & phba->fc_nodename.IEEE[0];
		for (i = 0; i < 12; i++) {
			status = *outptr++;
			j = ((status & 0xf0) >> 4);
			if (j <= 9)
				phba->SerialNumber[i] =
				    (char)((uint8_t) 0x30 + (uint8_t) j);
			else
				phba->SerialNumber[i] =
				    (char)((uint8_t) 0x61 + (uint8_t) (j - 10));
			i++;
			j = (status & 0xf);
			if (j <= 9)
				phba->SerialNumber[i] =
				    (char)((uint8_t) 0x30 + (uint8_t) j);
			else
				phba->SerialNumber[i] =
				    (char)((uint8_t) 0x61 + (uint8_t) (j - 10));
		}
	}

	lpfc_read_config(phba, pmb);
	if (lpfc_sli_issue_mbox(phba, pmb, MBX_POLL) != MBX_SUCCESS) {
		lpfc_printf_log(phba,
				KERN_ERR,
				LOG_INIT,
				"%d:0453 Adapter failed to init, mbxCmd x%x "
				"READ_CONFIG, mbxStatus x%x\n",
				phba->brd_no,
				mb->mbxCommand, mb->mbxStatus);
		phba->hba_state = LPFC_HBA_ERROR;
		mempool_free( pmb, phba->mbox_mem_pool);
		return -EIO;
	}

	/* Reset the hba_queue_depth  to the max xri  */
	if (phba->cfg_hba_queue_depth > (mb->un.varRdConfig.max_xri+1))
		phba->cfg_hba_queue_depth =
			mb->un.varRdConfig.max_xri + 1;

	phba->lmt = mb->un.varRdConfig.lmt;

	/* Get the default values for Model Name and Description */
	lpfc_get_hba_model_desc(phba, phba->ModelName, phba->ModelDesc);

	if ((phba->cfg_link_speed > LINK_SPEED_10G)
	    || ((phba->cfg_link_speed == LINK_SPEED_1G)
		&& !(phba->lmt & LMT_1Gb))
	    || ((phba->cfg_link_speed == LINK_SPEED_2G)
		&& !(phba->lmt & LMT_2Gb))
	    || ((phba->cfg_link_speed == LINK_SPEED_4G)
		&& !(phba->lmt & LMT_4Gb))
	    || ((phba->cfg_link_speed == LINK_SPEED_8G)
		&& !(phba->lmt & LMT_8Gb))
	    || ((phba->cfg_link_speed == LINK_SPEED_10G)
		&& !(phba->lmt & LMT_10Gb))) {
		/* Reset link speed to auto */
		lpfc_printf_log(phba,
			KERN_WARNING,
			LOG_LINK_EVENT,
			"%d:1302 Invalid speed for this board: "
			"Reset link speed to auto: x%x\n",
			phba->brd_no,
			phba->cfg_link_speed);
			phba->cfg_link_speed = LINK_SPEED_AUTO;
	}

	if (!phba->intr_inited) {
		/* Add our interrupt routine to kernel's interrupt chain &
		   enable it */

		if (request_irq(phba->pcidev->irq,
				lpfc_intr_handler,
				SA_SHIRQ,
				LPFC_DRIVER_NAME,
				phba) != 0) {
			/* Enable interrupt handler failed */
			lpfc_printf_log(phba,
					KERN_ERR,
					LOG_INIT,
					"%d:0451 Enable interrupt handler "
					"failed\n",
					phba->brd_no);
			phba->hba_state = LPFC_HBA_ERROR;
			mempool_free(pmb, phba->mbox_mem_pool);
			return -EIO;
		}
		phba->intr_inited =
			(HC_MBINT_ENA | HC_ERINT_ENA | HC_LAINT_ENA);
	}

	phba->hba_state = LPFC_LINK_DOWN;

	/* Only process IOCBs on ring 0 till hba_state is READY */
	if (psli->ring[psli->extra_ring].cmdringaddr)
		psli->ring[psli->extra_ring].flag |= LPFC_STOP_IOCB_EVENT;
	if (psli->ring[psli->fcp_ring].cmdringaddr)
		psli->ring[psli->fcp_ring].flag |= LPFC_STOP_IOCB_EVENT;
	if (psli->ring[psli->next_ring].cmdringaddr)
		psli->ring[psli->next_ring].flag |= LPFC_STOP_IOCB_EVENT;

	/* Post receive buffers for desired rings */
	lpfc_post_rcv_buf(phba);

	/* Enable appropriate host interrupts */
	status = readl(phba->HCregaddr);
	status |= phba->intr_inited;
	if (psli->sliinit.num_rings > 0)
		status |= HC_R0INT_ENA;
	if (psli->sliinit.num_rings > 1)
		status |= HC_R1INT_ENA;
	if (psli->sliinit.num_rings > 2)
		status |= HC_R2INT_ENA;
	if (psli->sliinit.num_rings > 3)
		status |= HC_R3INT_ENA;

	writel(status, phba->HCregaddr);
	readl(phba->HCregaddr); /* flush */

	/* Setup and issue mailbox INITIALIZE LINK command */
	lpfc_init_link(phba, pmb, phba->cfg_topology,
		       phba->cfg_link_speed);

	isr_cnt = psli->slistat.sliIntr;
	clk_cnt = jiffies;

	pmb->mbox_cmpl = lpfc_sli_def_mbox_cmpl;
	if (lpfc_sli_issue_mbox(phba, pmb, MBX_NOWAIT) != MBX_SUCCESS) {
		lpfc_printf_log(phba,
				KERN_ERR,
				LOG_INIT,
				"%d:0454 Adapter failed to init, mbxCmd x%x "
				"INIT_LINK, mbxStatus x%x\n",
				phba->brd_no,
				mb->mbxCommand, mb->mbxStatus);

		/* Clear all interrupt enable conditions */
		writel(0, phba->HCregaddr);
		readl(phba->HCregaddr); /* flush */
		/* Clear all pending interrupts */
		writel(0xffffffff, phba->HAregaddr);
		readl(phba->HAregaddr); /* flush */

		free_irq(phba->pcidev->irq, phba);
		phba->hba_state = LPFC_HBA_ERROR;
		mempool_free(pmb, phba->mbox_mem_pool);
		return -EIO;
	}
	/* MBOX buffer will be freed in mbox compl */

	pmb = mempool_alloc(phba->mbox_mem_pool, GFP_KERNEL);
	lpfc_config_async(phba, pmb, LPFC_ELS_RING);
	pmb->mbox_cmpl = lpfc_config_async_cmpl;
	rc = lpfc_sli_issue_mbox(phba, pmb, MBX_NOWAIT);

	if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
		lpfc_printf_log(phba,
				KERN_ERR,
				LOG_INIT,
				"%d:0456 Adapter failed to issue "
				"ASYNCEVT_ENABLE mbox status x%x \n.",
				phba->brd_no,
				rc);
		mempool_free(pmb, phba->mbox_mem_pool);
	}

	/*
	 * Setup the ring 0 (els)  timeout handler
	 */
	timeout = phba->fc_ratov << 1;

	phba->els_tmofunc.expires = jiffies + HZ * timeout;
	add_timer(&phba->els_tmofunc);

	mod_timer(&phba->hb_tmofunc, jiffies + HZ * LPFC_HB_MBOX_INTERVAL);
	phba->hb_outstanding = 0;
	phba->last_completion_time = jiffies;

	phba->fc_prevDID = Mask_DID;
	i = 0;
	j = 0;
	k = 0;
	/*
	 * Wait until discovery is done. Wait is aborted if link was
	 * down for more then "linkup_wait_limit" seconds or if total
	 * wait time is limited and the threshold
	 * "discovery_wait_limit" seconds is reached.
	 *
	 * Discovery has to run for at least "discovery_min_wait"
	 * seconds to cover cases when remote ports do show up only
	 * after second link up event.
	 *
	 * Discovery is done when host state is LPFC_HBA_READY and
	 * FC_NDISC_ACTIVE flag is cleared. FC_NDISC_ACTIVE flag is
	 * cleared a bit prematurely. We have to make sure all
	 * REG_LOGIN mailbox commands are completed and there are no
	 * outstanding PRLI.
	 */
	while ((j < phba->cfg_linkup_wait_limit) &&
	       (i < phba->cfg_discovery_wait_limit) &&
	       (((phba->fc_map_cnt == 0) &&
		 (k < phba->cfg_discovery_min_wait)) ||
		(phba->hba_state != LPFC_HBA_READY) ||
		(phba->fc_flag & FC_NDISC_ACTIVE) ||
		(psli->sliinit.sli_flag & LPFC_SLI_MBOX_ACTIVE) ||
		(phba->fc_prli_sent != 0))) {

		i = (phba->cfg_discovery_wait_limit != CFG_DISC_INFINITE_WAIT)
			? (i + 1) : 0;
		j = (phba->hba_state <= LPFC_LINK_DOWN)
			? (j + 1) : 0;
		k++;
		if (!(k%30))
			lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
					"%d:0452 Waiting for discovery to stop "
					"Data: x%x x%x x%x x%x\n",
					phba->brd_no, phba->hba_state,
					phba->fc_flag,
					psli->sliinit.sli_flag,
					phba->fc_prli_sent);
		msleep(1000);
	}

	if (isr_cnt == psli->slistat.sliIntr) {
		lpfc_sli_intr(phba);
	}

	return (0);
}

/************************************************************************/
/*                                                                      */
/*    lpfc_hba_down_prep                                                */
/*    This routine will do LPFC uninitialization before the             */
/*    HBA is reset when bringing down the SLI Layer. This will be       */
/*    initialized as a SLI layer callback routine.                      */
/*    This routine returns 0 on success. Any other return value         */
/*    indicates an error.                                               */
/*                                                                      */
/************************************************************************/
int
lpfc_hba_down_prep(struct lpfc_hba * phba)
{
	/* Disable interrupts */
	writel(0, phba->HCregaddr);
	readl(phba->HCregaddr); /* flush */

	/* Cleanup potential discovery resources */
	lpfc_els_flush_rscn(phba);
	lpfc_els_flush_cmd(phba);
	lpfc_disc_flush_list(phba);

	return (0);
}

/************************************************************************/
/*                                                                      */
/*    lpfc_hba_down_post                                                */
/*    This routine will do uninitialization after the HBA is reset      */
/*    when bringing down the SLI Layer.                                 */
/*    This routine returns 0 on success. Any other return value         */
/*    indicates an error.                                               */
/*                                                                      */
/************************************************************************/
int
lpfc_hba_down_post(struct lpfc_hba * phba)
{
	struct lpfc_sli *psli = &phba->sli;
	struct lpfc_sli_ring *pring;
	struct lpfc_dmabuf *mp, *next_mp;
	int i;

	/* Cleanup preposted buffers on the ELS ring */
	pring = &psli->ring[LPFC_ELS_RING];
	list_for_each_entry_safe(mp, next_mp, &pring->postbufq, list) {
		list_del(&mp->list);
		pring->postbufq_cnt--;
		lpfc_mbuf_free(phba, mp->virt, mp->phys);
		kfree(mp);
	}

	for (i = 0; i < psli->sliinit.num_rings; i++) {
		pring = &psli->ring[i];
		lpfc_sli_abort_iocb_ring(phba, pring, LPFC_SLI_ABORT_IMED);
	}

	return 0;
}

/* HBA heart beat timeout handler */
void
lpfc_hb_timeout(unsigned long ptr)
{
	struct lpfc_hba *phba;
	unsigned long iflag;

	phba = (struct lpfc_hba *)ptr;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	if (!(phba->work_hba_events & WORKER_HB_TMO)) {
		phba->work_hba_events |= WORKER_HB_TMO;
		if (phba->dpc_wait)
			up(phba->dpc_wait);
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return;
}

static void
lpfc_hb_mbox_cmpl(struct lpfc_hba * phba, LPFC_MBOXQ_t * pmboxq)
{
	phba->hb_outstanding = 0;

	mempool_free(pmboxq, phba->mbox_mem_pool);
	if (!(phba->fc_flag & FC_OFFLINE_MODE) &&
		!(phba->hba_state == LPFC_HBA_ERROR))
		mod_timer(&phba->hb_tmofunc,
			jiffies + HZ * LPFC_HB_MBOX_INTERVAL);
	return;
}

void
lpfc_hb_timeout_handler(struct lpfc_hba *phba)
{
	LPFC_MBOXQ_t *pmboxq;
	int retval;
	struct lpfc_sli *psli = &phba->sli;

	if ((phba->hba_state == LPFC_HBA_ERROR) ||
		(phba->fc_flag & FC_OFFLINE_MODE))
		return;

	spin_lock_irq(phba->host->host_lock);

	if (time_after(phba->last_completion_time + LPFC_HB_MBOX_INTERVAL * HZ,
		jiffies)) {
		spin_unlock_irq(phba->host->host_lock);
		if (!phba->hb_outstanding)
			mod_timer(&phba->hb_tmofunc,
				jiffies + HZ * LPFC_HB_MBOX_INTERVAL);
		else
			mod_timer(&phba->hb_tmofunc,
				jiffies + HZ * LPFC_HB_MBOX_TIMEOUT);
		return;
	}
	spin_unlock_irq(phba->host->host_lock);

	/* If there is no heart beat outstanding, issue a heartbeat command */
	if (!phba->hb_outstanding) {
		pmboxq = mempool_alloc(phba->mbox_mem_pool,GFP_KERNEL);
		if (!pmboxq) {
			mod_timer(&phba->hb_tmofunc,
				jiffies + HZ * LPFC_HB_MBOX_INTERVAL);
			return;
		}

		lpfc_heart_beat(phba, pmboxq);
		pmboxq->mbox_cmpl = lpfc_hb_mbox_cmpl;
		retval = lpfc_sli_issue_mbox(phba, pmboxq, MBX_NOWAIT);

		if (retval != MBX_BUSY && retval != MBX_SUCCESS) {
			mempool_free(pmboxq, phba->mbox_mem_pool);
			mod_timer(&phba->hb_tmofunc,
				jiffies + HZ * LPFC_HB_MBOX_INTERVAL);
			return;
		}
		mod_timer(&phba->hb_tmofunc,
			jiffies + HZ * LPFC_HB_MBOX_TIMEOUT);
		phba->hb_outstanding = 1;
		return;
	} else {
		/*
		 * If heart beat timeout called with hb_outstanding set we
		 * need to take the HBA offline.
		 */
		lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
			"%d:0459 Adapter heartbeat failure, taking "
			"this port offline.\n", phba->brd_no);

		psli->sliinit.sli_flag &= ~LPFC_SLI2_ACTIVE;

		lpfc_offline(phba);
		phba->hba_state = LPFC_HBA_ERROR;
		spin_lock_irq(phba->host->host_lock);
		lpfc_hba_down_post(phba);
		spin_unlock_irq(phba->host->host_lock);

		/*
		 * Restart all traffic to this host.  Since the fc_transport
		 * block functions (future) were not called in lpfc_offline,
		 * don't call them here.
		 */
		lpfc_unblock_requests(phba);
	}
}

/************************************************************************/
/*                                                                      */
/*    lpfc_handle_eratt                                                 */
/*    This routine will handle processing a Host Attention              */
/*    Error Status event. This will be initialized                      */
/*    as a SLI layer callback routine.                                  */
/*                                                                      */
/************************************************************************/
void
lpfc_handle_eratt(struct lpfc_hba * phba, uint32_t status)
{
	struct lpfc_sli *psli;
	struct lpfc_sli_ring  *pring;
	struct lpfc_iocbq     *iocb, *next_iocb;
	IOCB_t          *icmd = NULL, *cmd = NULL;
	struct lpfc_scsi_buf  *lpfc_cmd;
	volatile uint32_t status1, status2;
	void *from_slim;
	unsigned long iflag;
	unsigned long temperature;

	psli = &phba->sli;
	from_slim = ((uint8_t *)phba->MBslimaddr + 0xa8);
	status1 = readl( from_slim);
	from_slim =  ((uint8_t *)phba->MBslimaddr + 0xac);
	status2 = readl( from_slim);

	if (status & HS_FFER6) {
		/* Re-establishing Link */
		spin_lock_irqsave(phba->host->host_lock, iflag);
		lpfc_printf_log(phba, KERN_INFO, LOG_LINK_EVENT,
				"%d:1301 Re-establishing Link "
				"Data: x%x x%x x%x\n",
				phba->brd_no, status, status1, status2);
		phba->fc_flag |= FC_ESTABLISH_LINK;
		/* Disable SLI2 */
		psli->sliinit.sli_flag &= ~LPFC_SLI2_ACTIVE;

		/*
		* Firmware stops when it triggled erratt with HS_FFER6.
		* That could cause the I/Os dropped by the firmware.
		* Error iocb (I/O) on txcmplq and let the SCSI layer
		* retry it after re-establishing link.
		*/
		pring = &psli->ring[psli->fcp_ring];

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
			lpfc_cmd = (struct lpfc_scsi_buf *)(iocb->context1);
			if (lpfc_cmd == 0) {
				continue;
			}

			/* Clear fast_lookup entry */
			if (cmd->ulpIoTag &&
			    (cmd->ulpIoTag <
			     psli->sliinit.ringinit[pring->ringno].fast_iotag))
				*(pring->fast_lookup + cmd->ulpIoTag) = NULL;
			
			list_del(&iocb->list);
			pring->txcmplq_cnt--;

			if (iocb->iocb_cmpl) {
				icmd = &iocb->iocb;
				icmd->ulpStatus = IOSTAT_LOCAL_REJECT;
				icmd->un.ulpWord[4] = IOERR_SLI_ABORTED;
				(iocb->iocb_cmpl)(phba, iocb, iocb);
			} else {
				mempool_free( iocb, phba->iocb_mem_pool);
			}
		}

		/*
		 * There was a firmware error.  Take the hba offline and then
		 * attempt to restart it.
		 */
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		lpfc_offline(phba);
		lpfc_sli_brdrestart(phba);
		if (lpfc_online(phba) == 0) {	/* Initialize the HBA */
			mod_timer(&phba->fc_estabtmo, jiffies + HZ * 60);
			return;
		}
	} else if (status & HS_CRIT_TEMP) {
		temperature = readl(phba->MBslimaddr + TEMPERATURE_OFFSET);

		lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
				"%d:0459 Adapter maximum temperature exceeded "
				"(%ld), taking this port offline "
				"Data: x%x x%x x%x\n",
				phba->brd_no, temperature, status,
				status1, status2);

		/* FC_REG_TEMPERATURE_EVENT for applications */
		lpfc_put_event(phba, HBA_EVENT_TEMP, LPFC_CRIT_TEMP,
			       (void *)temperature, 0,0);

		/* Disable SLI2 */
		psli->sliinit.sli_flag &= ~LPFC_SLI2_ACTIVE;
		lpfc_offline(phba);
		phba->hba_state = LPFC_HBA_ERROR;
		spin_lock_irqsave(phba->host->host_lock, iflag);
		lpfc_hba_down_post(phba);
		spin_unlock_irqrestore(phba->host->host_lock, iflag);

		/*
		 * Restart all traffic to this host.  Since the fc_transport
		 * block functions (future) were not called in lpfc_offline,
		 * don't call them here.
		 */
		lpfc_unblock_requests(phba);
	} else {
		/* The if clause above forces this code path when the status
		 * failure is a value other than FFER6.  Do not call the offline
		 *  twice. This is the adapter hardware error path.
		 */
		lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
				"%d:0457 Adapter Hardware Error "
				"Data: x%x x%x x%x\n",
				phba->brd_no, status, status1, status2);

		/* Disable SLI2 */
		psli->sliinit.sli_flag &= ~LPFC_SLI2_ACTIVE;
		lpfc_offline(phba);
		phba->hba_state = LPFC_HBA_ERROR;
		spin_lock_irqsave(phba->host->host_lock, iflag);
		/* FC_REG_DUMP_EVENT for diagnostic dump event handling */
		lpfc_put_event(phba, HBA_EVENT_DUMP, phba->fc_myDID,
			       NULL, 0, 0);

		lpfc_hba_down_post(phba);
		spin_unlock_irqrestore(phba->host->host_lock, iflag);

		/*
		 * Restart all traffic to this host.  Since the fc_transport
		 * block functions (future) were not called in lpfc_offline,
		 * don't call them here.
		 */
		lpfc_unblock_requests(phba);
	}
	return;
}

/************************************************************************/
/*                                                                      */
/*    lpfc_handle_latt                                                  */
/*    This routine will handle processing a Host Attention              */
/*    Link Status event. This will be initialized                       */
/*    as a SLI layer callback routine.                                  */
/*                                                                      */
/************************************************************************/
void
lpfc_handle_latt(struct lpfc_hba * phba)
{
	struct lpfc_sli *psli;
	LPFC_MBOXQ_t *pmb;
	volatile uint32_t control;
	unsigned long iflag;


	spin_lock_irqsave(phba->host->host_lock, iflag);

	/* called from host_interrupt, to process LATT */
	psli = &phba->sli;
	psli->slistat.linkEvent++;

	/* Cleanup any outstanding ELS commands */
	lpfc_els_flush_cmd(phba);

	/* Get a buffer which will be used for mailbox commands */
	if ((pmb = (LPFC_MBOXQ_t *) mempool_alloc(phba->mbox_mem_pool,
						  GFP_ATOMIC))) {
		if (lpfc_read_la(phba, pmb) == 0) {
			pmb->mbox_cmpl = lpfc_mbx_cmpl_read_la;
			if (lpfc_sli_issue_mbox
			    (phba, pmb, (MBX_NOWAIT | MBX_STOP_IOCB))
			    != MBX_NOT_FINISHED) {
				/* Turn off Link Attention interrupts until
				   CLEAR_LA done */
				psli->sliinit.sli_flag &= ~LPFC_PROCESS_LA;
				control = readl(phba->HCregaddr);
				control &= ~HC_LAINT_ENA;
				writel(control, phba->HCregaddr);
				readl(phba->HCregaddr); /* flush */

				/* Clear Link Attention in HA REG */
				writel(HA_LATT, phba->HAregaddr);
				readl(phba->HAregaddr); /* flush */
				spin_unlock_irqrestore(phba->host->host_lock,
						       iflag);
				return;
			} else {
				mempool_free(pmb, phba->mbox_mem_pool);
			}
		} else {
			mempool_free(pmb, phba->mbox_mem_pool);
		}
	}

	/* Clear Link Attention in HA REG */
	writel(HA_LATT, phba->HAregaddr);
	readl(phba->HAregaddr); /* flush */
	lpfc_linkdown(phba);
	phba->hba_state = LPFC_HBA_ERROR;
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return;
}

/************************************************************************/
/*                                                                      */
/*   lpfc_parse_vpd                                                     */
/*   This routine will parse the VPD data                               */
/*                                                                      */
/************************************************************************/
static int
lpfc_parse_vpd(struct lpfc_hba * phba, uint8_t * vpd, int len)
{
	uint8_t lenlo, lenhi;
	int Length;
	int i, j;
	int finished = 0;
	int index = 0;

	if(!vpd)
		return 0;

	/* Vital Product */
	lpfc_printf_log(phba,
			KERN_INFO,
			LOG_INIT,
			"%d:0455 Vital Product Data: x%x x%x x%x x%x\n",
			phba->brd_no,
			(uint32_t) vpd[0], (uint32_t) vpd[1], (uint32_t) vpd[2],
			(uint32_t) vpd[3]);
	while (!finished && (index < (len - 4))) {
		switch (vpd[index]) {
		case 0x82:
		case 0x91:
			index += 1;
			lenlo = vpd[index];
			index += 1;
			lenhi = vpd[index];
			index += 1;
			i = ((((unsigned short)lenhi) << 8) + lenlo);
			index += i;
			break;
		case 0x90:
			index += 1;
			lenlo = vpd[index];
			index += 1;
			lenhi = vpd[index];
			index += 1;
			Length = ((((unsigned short)lenhi) << 8) + lenlo);
			if (Length > len - index)
				Length = len - index;
			while (Length > 0) {
			/* Look for Serial Number */
			if ((vpd[index] == 'S') && (vpd[index+1] == 'N')) {
				index += 2;
				i = vpd[index];
				index += 1;
				j = 0;
				Length -= (3+i);
				while(i--) {
					phba->SerialNumber[j++] = vpd[index++];
					if(j == 31)
						break;
				}
				phba->SerialNumber[j] = 0;
				continue;
			}
			else if ((vpd[index] == 'V') && (vpd[index+1] == '1')) {
				phba->vpd_flag |= VPD_MODEL_DESC;
				index += 2;
				i = vpd[index];
				index += 1;
				j = 0;
				Length -= (3+i);
				while(i--) {
					phba->ModelDesc[j++] = vpd[index++];
					if(j == 255)
						break;
				}
				phba->ModelDesc[j] = 0;
				continue;
			}
			else if ((vpd[index] == 'V') && (vpd[index+1] == '2')) {
				phba->vpd_flag |= VPD_MODEL_NAME;
				index += 2;
				i = vpd[index];
				index += 1;
				j = 0;
				Length -= (3+i);
				while(i--) {
					phba->ModelName[j++] = vpd[index++];
					if(j == 79)
						break;
				}
				phba->ModelName[j] = 0;
				continue;
			}
			else if ((vpd[index] == 'V') && (vpd[index+1] == '3')) {
				phba->vpd_flag |= VPD_PROGRAM_TYPE;
				index += 2;
				i = vpd[index];
				index += 1;
				j = 0;
				Length -= (3+i);
				while(i--) {
					phba->ProgramType[j++] = vpd[index++];
					if(j == 255)
						break;
				}
				phba->ProgramType[j] = 0;
				continue;
			}
			else if ((vpd[index] == 'V') && (vpd[index+1] == '4')) {
				phba->vpd_flag |= VPD_PORT;
				index += 2;
				i = vpd[index];
				index += 1;
				j = 0;
				Length -= (3+i);
				while(i--) {
				phba->Port[j++] = vpd[index++];
				if(j == 19)
					break;
				}
				phba->Port[j] = 0;
				continue;
			}
			else {
				index += 2;
				i = vpd[index];
				index += 1;
				index += i;
				Length -= (3 + i);
			}
		}
		finished = 0;
		break;
		case 0x78:
			finished = 1;
			break;
		default:
			index ++;
			break;
		}
	}

	return(1);
}

static void
lpfc_get_hba_model_desc(struct lpfc_hba * phba, uint8_t * mdp, uint8_t * descp)
{
	lpfc_vpd_t *vp;
	uint16_t dev_id = phba->pcidev->device;
	int max_speed;
	struct {
		char * name;
		int    max_speed;
		char * bus;
	} m = {"<Unknown>", 0, ""};

	if (mdp && mdp[0] != '\0'
		&& descp && descp[0] != '\0')
		return;

	if (phba->lmt & LMT_10Gb)
		max_speed = 10;
	else if (phba->lmt & LMT_8Gb)
		max_speed = 8;
	else if (phba->lmt & LMT_4Gb)
		max_speed = 4;
	else if (phba->lmt & LMT_2Gb)
		max_speed = 2;
	else
		max_speed = 1;

	vp = &phba->vpd;

	switch (dev_id) {
	case PCI_DEVICE_ID_FIREFLY:
		m = (typeof(m)){"LP6000", max_speed, "PCI"};
		break;
	case PCI_DEVICE_ID_SUPERFLY:
		if (vp->rev.biuRev >= 1 && vp->rev.biuRev <= 3)
			m = (typeof(m)){"LP7000", max_speed, "PCI"};
		else
			m = (typeof(m)){"LP7000E", max_speed, "PCI"};
		break;
	case PCI_DEVICE_ID_DRAGONFLY:
		m = (typeof(m)){"LP8000", max_speed, "PCI"};
		break;
	case PCI_DEVICE_ID_CENTAUR:
		if (FC_JEDEC_ID(vp->rev.biuRev) == CENTAUR_2G_JEDEC_ID)
			m = (typeof(m)){"LP9002", max_speed, "PCI"};
		else
			m = (typeof(m)){"LP9000", max_speed, "PCI"};
		break;
	case PCI_DEVICE_ID_RFLY:
		m = (typeof(m)){"LP952", max_speed, "PCI"};
		break;
	case PCI_DEVICE_ID_PEGASUS:
		m = (typeof(m)){"LP9802", max_speed, "PCI-X"};
		break;
	case PCI_DEVICE_ID_THOR:
		m = (typeof(m)){"LP10000",
			max_speed, "PCI-X"};
		break;
	case PCI_DEVICE_ID_VIPER:
		m = (typeof(m)){"LPX1000", max_speed, "PCI-X"};
		break;
	case PCI_DEVICE_ID_PFLY:
		m = (typeof(m)){"LP982", max_speed, "PCI-X"};
		break;
	case PCI_DEVICE_ID_TFLY:
		m = (typeof(m)){"LP1050", max_speed, "PCI-X"};
		break;
	case PCI_DEVICE_ID_HELIOS:
		m = (typeof(m)){"LP11000", max_speed, "PCI-X2"};
		break;
	case PCI_DEVICE_ID_HELIOS_SCSP:
		m = (typeof(m)){"LP11000-SP", max_speed, "PCI-X2"};
		break;
	case PCI_DEVICE_ID_HELIOS_DCSP:
		m = (typeof(m)){"LP11002-SP", max_speed, "PCI-X2"};
		break;
	case PCI_DEVICE_ID_NEPTUNE:
		m = (typeof(m)){"LPe1000", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_NEPTUNE_SCSP:
		m = (typeof(m)){"LPe1000-SP", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_NEPTUNE_DCSP:
		m = (typeof(m)){"LPe1002-SP", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_BMID:
		m = (typeof(m)){"LP1150", max_speed, "PCI-X2"};
		break;
	case PCI_DEVICE_ID_BSMB:
		m = (typeof(m)){"LP111", max_speed, "PCI-X2"};
		break;
	case PCI_DEVICE_ID_ZEPHYR:
		m = (typeof(m)){"LPe11000", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_ZEPHYR_SCSP:
		m = (typeof(m)){"LPe11000", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_ZEPHYR_DCSP:
		m = (typeof(m)){"LPe11002-SP", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_ZMID:
		m = (typeof(m)){"LPe1150", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_ZSMB:
		m = (typeof(m)){"LPe111", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_LP101:
		m = (typeof(m)){"LP101", max_speed, "PCI-X"};
		break;
	case PCI_DEVICE_ID_LP10000S:
		m = (typeof(m)){"LP10000-S", max_speed, "PCI"};
		break;
	case PCI_DEVICE_ID_LP11000S:
		m = (typeof(m)){"LP11000-S", max_speed,
			"PCI-X2"};
		break;
	case PCI_DEVICE_ID_LPE11000S:
		m = (typeof(m)){"LPe11000-S", max_speed,
			"PCIe"};
		break;
	case PCI_DEVICE_ID_SAT:
		m = (typeof(m)){"LPe12000", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_SAT_MID:
		m = (typeof(m)){"LPe1250", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_SAT_SMB:
		m = (typeof(m)){"LPe121", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_SAT_DCSP:
		m = (typeof(m)){"LPe12002-SP", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_SAT_SCSP:
		m = (typeof(m)){"LPe12000-SP", max_speed, "PCIe"};
		break;
	case PCI_DEVICE_ID_SAT_S:
		m = (typeof(m)){"LPe12000-S", max_speed, "PCIe"};
		break;
	default:
		break;
	}

	if (mdp && mdp[0] == '\0')
		snprintf(mdp, 79,"%s", m.name);
	if (descp && descp[0] == '\0')
		snprintf(descp, 255,
			 "Emulex %s %dGb %s Fibre Channel Adapter",
			 m.name, m.max_speed, m.bus);
}

/**************************************************/
/*   lpfc_post_buffer                             */
/*                                                */
/*   This routine will post count buffers to the  */
/*   ring with the QUE_RING_BUF_CN command. This  */
/*   allows 3 buffers / command to be posted.     */
/*   Returns the number of buffers NOT posted.    */
/**************************************************/
int
lpfc_post_buffer(struct lpfc_hba * phba, struct lpfc_sli_ring * pring, int cnt,
		 int type)
{
	IOCB_t *icmd;
	struct lpfc_iocbq *iocb;
	struct lpfc_dmabuf *mp1, *mp2;

	cnt += pring->missbufcnt;

	/* While there are buffers to post */
	while (cnt > 0) {
		/* Allocate buffer for  command iocb */
		if ((iocb = mempool_alloc(phba->iocb_mem_pool, GFP_ATOMIC))
		    == 0) {
			pring->missbufcnt = cnt;
			return (cnt);
		}
		memset(iocb, 0, sizeof (struct lpfc_iocbq));
		icmd = &iocb->iocb;

		/* 2 buffers can be posted per command */
		/* Allocate buffer to post */
		mp1 = kmalloc(sizeof (struct lpfc_dmabuf), GFP_ATOMIC);
		if (mp1)
		    mp1->virt = lpfc_mbuf_alloc(phba, MEM_PRI,
						&mp1->phys);
		if (mp1 == 0 || mp1->virt == 0) {
			if (mp1)
				kfree(mp1);

			mempool_free( iocb, phba->iocb_mem_pool);
			pring->missbufcnt = cnt;
			return (cnt);
		}

		INIT_LIST_HEAD(&mp1->list);
		/* Allocate buffer to post */
		if (cnt > 1) {
			mp2 = kmalloc(sizeof (struct lpfc_dmabuf), GFP_ATOMIC);
			if (mp2)
				mp2->virt = lpfc_mbuf_alloc(phba, MEM_PRI,
							    &mp2->phys);
			if (mp2 == 0 || mp2->virt == 0) {
				if (mp2)
					kfree(mp2);
				lpfc_mbuf_free(phba, mp1->virt, mp1->phys);
				kfree(mp1);
				mempool_free( iocb, phba->iocb_mem_pool);
				pring->missbufcnt = cnt;
				return (cnt);
			}

			INIT_LIST_HEAD(&mp2->list);
		} else {
			mp2 = NULL;
		}

		icmd->un.cont64[0].addrHigh = putPaddrHigh(mp1->phys);
		icmd->un.cont64[0].addrLow = putPaddrLow(mp1->phys);
		icmd->un.cont64[0].tus.f.bdeSize = FCELSSIZE;
		icmd->ulpBdeCount = 1;
		cnt--;
		if (mp2) {
			icmd->un.cont64[1].addrHigh = putPaddrHigh(mp2->phys);
			icmd->un.cont64[1].addrLow = putPaddrLow(mp2->phys);
			icmd->un.cont64[1].tus.f.bdeSize = FCELSSIZE;
			cnt--;
			icmd->ulpBdeCount = 2;
		}

		icmd->ulpCommand = CMD_QUE_RING_BUF64_CN;
		icmd->ulpLe = 1;

		if (lpfc_sli_issue_iocb(phba, pring, iocb, 0) == IOCB_ERROR) {
			lpfc_mbuf_free(phba, mp1->virt, mp1->phys);
			kfree(mp1);
			cnt++;
			if (mp2) {
				lpfc_mbuf_free(phba, mp2->virt, mp2->phys);
				kfree(mp2);
				cnt++;
			}
			mempool_free( iocb, phba->iocb_mem_pool);
			pring->missbufcnt = cnt;
			return (cnt);
		}
		lpfc_sli_ringpostbuf_put(phba, pring, mp1);
		if (mp2) {
			lpfc_sli_ringpostbuf_put(phba, pring, mp2);
		}
	}
	pring->missbufcnt = 0;
	return (0);
}

/************************************************************************/
/*                                                                      */
/*   lpfc_post_rcv_buf                                                  */
/*   This routine post initial rcv buffers to the configured rings      */
/*                                                                      */
/************************************************************************/
static int
lpfc_post_rcv_buf(struct lpfc_hba * phba)
{
	struct lpfc_sli *psli = &phba->sli;

	/* Ring 0, ELS / CT buffers */
	lpfc_post_buffer(phba, &psli->ring[LPFC_ELS_RING], LPFC_BUF_RING0, 1);
	/* Ring 2 - FCP no buffers needed */

	return 0;
}

#define S(N,V) (((V)<<(N))|((V)>>(32-(N))))

/************************************************************************/
/*                                                                      */
/*   lpfc_sha_init                                                      */
/*                                                                      */
/************************************************************************/
static void
lpfc_sha_init(uint32_t * HashResultPointer)
{
	HashResultPointer[0] = 0x67452301;
	HashResultPointer[1] = 0xEFCDAB89;
	HashResultPointer[2] = 0x98BADCFE;
	HashResultPointer[3] = 0x10325476;
	HashResultPointer[4] = 0xC3D2E1F0;
}

/************************************************************************/
/*                                                                      */
/*   lpfc_sha_iterate                                                   */
/*                                                                      */
/************************************************************************/
static void
lpfc_sha_iterate(uint32_t * HashResultPointer, uint32_t * HashWorkingPointer)
{
	int t;
	uint32_t TEMP;
	uint32_t A, B, C, D, E;
	t = 16;
	do {
		HashWorkingPointer[t] =
		    S(1,
		      HashWorkingPointer[t - 3] ^ HashWorkingPointer[t -
								     8] ^
		      HashWorkingPointer[t - 14] ^ HashWorkingPointer[t - 16]);
	} while (++t <= 79);
	t = 0;
	A = HashResultPointer[0];
	B = HashResultPointer[1];
	C = HashResultPointer[2];
	D = HashResultPointer[3];
	E = HashResultPointer[4];

	do {
		if (t < 20) {
			TEMP = ((B & C) | ((~B) & D)) + 0x5A827999;
		} else if (t < 40) {
			TEMP = (B ^ C ^ D) + 0x6ED9EBA1;
		} else if (t < 60) {
			TEMP = ((B & C) | (B & D) | (C & D)) + 0x8F1BBCDC;
		} else {
			TEMP = (B ^ C ^ D) + 0xCA62C1D6;
		}
		TEMP += S(5, A) + E + HashWorkingPointer[t];
		E = D;
		D = C;
		C = S(30, B);
		B = A;
		A = TEMP;
	} while (++t <= 79);

	HashResultPointer[0] += A;
	HashResultPointer[1] += B;
	HashResultPointer[2] += C;
	HashResultPointer[3] += D;
	HashResultPointer[4] += E;

}

/************************************************************************/
/*                                                                      */
/*   lpfc_challenge_key                                                 */
/*                                                                      */
/************************************************************************/
static void
lpfc_challenge_key(uint32_t * RandomChallenge, uint32_t * HashWorking)
{
	*HashWorking = (*RandomChallenge ^ *HashWorking);
}

/************************************************************************/
/*                                                                      */
/*   lpfc_hba_init                                                      */
/*                                                                      */
/************************************************************************/
void
lpfc_hba_init(struct lpfc_hba *phba, uint32_t *hbainit)
{
	int t;
	uint32_t *HashWorking;
	uint32_t *pwwnn = phba->wwnn;

	HashWorking = kmalloc(80 * sizeof(uint32_t), GFP_ATOMIC);
	if (!HashWorking)
		return;

	memset(HashWorking, 0, (80 * sizeof(uint32_t)));
	HashWorking[0] = HashWorking[78] = *pwwnn++;
	HashWorking[1] = HashWorking[79] = *pwwnn;

	for (t = 0; t < 7; t++)
		lpfc_challenge_key(phba->RandomData + t, HashWorking + t);

	lpfc_sha_init(hbainit);
	lpfc_sha_iterate(hbainit, HashWorking);
	kfree(HashWorking);
}

static void
lpfc_consistent_bind_cleanup(struct lpfc_hba * phba)
{
	struct lpfc_bindlist *bdlp;

	while (lpfc_list_first_entry(bdlp, &phba->fc_nlpbind_list,
				     nlp_listp)) {
		list_del(&bdlp->nlp_listp);
		mempool_free( bdlp, phba->bind_mem_pool);
	}

	phba->fc_bind_cnt = 0;
}

void
lpfc_cleanup(struct lpfc_hba * phba, uint32_t save_bind)
{
	struct lpfc_nodelist *ndlp;

	/* clean up phba - lpfc specific */
	lpfc_can_disctmo(phba);
	while (lpfc_list_first_entry (ndlp, &phba->fc_nlpunmap_list,
				      nlp_listp))
	      lpfc_nlp_remove(phba, ndlp);

	while (lpfc_list_first_entry(ndlp, &phba->fc_nlpmap_list,
				     nlp_listp))
	      lpfc_nlp_remove(phba, ndlp);

	while (lpfc_list_first_entry(ndlp, &phba->fc_unused_list,
				     nlp_listp))
	      lpfc_nlp_remove(phba, ndlp);

	while (lpfc_list_first_entry(ndlp, &phba->fc_plogi_list,
				     nlp_listp))
	      lpfc_nlp_remove(phba, ndlp);

	while (lpfc_list_first_entry(ndlp, &phba->fc_adisc_list,
				     nlp_listp))
	      lpfc_nlp_remove(phba, ndlp);

	while (lpfc_list_first_entry(ndlp, &phba->fc_reglogin_list,
				     nlp_listp))
	      lpfc_nlp_remove(phba, ndlp);

	while (lpfc_list_first_entry(ndlp, &phba->fc_prli_list,
				     nlp_listp))
	      lpfc_nlp_remove(phba, ndlp);

	while (lpfc_list_first_entry(ndlp, &phba->fc_npr_list,
				     nlp_listp))
	      lpfc_nlp_remove(phba, ndlp);

	if (save_bind == 0) {
		lpfc_consistent_bind_cleanup(phba);
	}

	INIT_LIST_HEAD(&phba->fc_nlpmap_list);
	INIT_LIST_HEAD(&phba->fc_nlpunmap_list);
	INIT_LIST_HEAD(&phba->fc_unused_list);
	INIT_LIST_HEAD(&phba->fc_plogi_list);
	INIT_LIST_HEAD(&phba->fc_adisc_list);
	INIT_LIST_HEAD(&phba->fc_reglogin_list);
	INIT_LIST_HEAD(&phba->fc_prli_list);
	INIT_LIST_HEAD(&phba->fc_npr_list);

	phba->fc_map_cnt   = 0;
	phba->fc_unmap_cnt = 0;
	phba->fc_plogi_cnt = 0;
	phba->fc_adisc_cnt = 0;
	phba->fc_reglogin_cnt = 0;
	phba->fc_prli_cnt  = 0;
	phba->fc_npr_cnt   = 0;
	phba->fc_unused_cnt= 0;
	return;
}

void
lpfc_establish_link_tmo(unsigned long ptr)
{
	struct lpfc_hba *phba = (struct lpfc_hba *)ptr;
	unsigned long iflag;

	spin_lock_irqsave(phba->host->host_lock, iflag);

	/* Re-establishing Link, timer expired */
	lpfc_printf_log(phba, KERN_ERR, LOG_LINK_EVENT,
			"%d:1300 Re-establishing Link, timer expired "
			"Data: x%x x%x\n",
			phba->brd_no, phba->fc_flag, phba->hba_state);
	phba->fc_flag &= ~FC_ESTABLISH_LINK;
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
}

int
lpfc_online(struct lpfc_hba * phba)
{
	if (!phba)
		return 0;

	if (!(phba->fc_flag & FC_OFFLINE_MODE))
		return 0;

	lpfc_printf_log(phba,
		       KERN_WARNING,
		       LOG_INIT,
		       "%d:0458 Bring Adapter online\n",
		       phba->brd_no);

	if (!lpfc_sli_queue_setup(phba))
		return 1;

	if (lpfc_sli_hba_setup(phba))	/* Initialize the HBA */
		return 1;

	phba->fc_flag &= ~FC_OFFLINE_MODE;

	/*
	 * Restart all traffic to this host.  Since the fc_transport block
	 * functions (future) were not called in lpfc_offline, don't call them
	 * here.
	 */
	lpfc_unblock_requests(phba);
	mod_timer(&phba->hatt_tmo, jiffies + HZ/10);
	return 0;
}

int
lpfc_offline(struct lpfc_hba * phba)
{
	struct lpfc_sli_ring *pring;
	struct lpfc_sli *psli;
	unsigned long iflag;
	int i;
	int cnt = 0;

	if (!phba)
		return 0;

	if (phba->fc_flag & FC_OFFLINE_MODE)
		return 0;

	/*
	 * Don't call the fc_transport block api (future).  The device is
	 * going offline and causing a timer to fire in the midlayer is
	 * unproductive.  Just block all new requests until the driver
	 * comes back online.
	 */
	lpfc_block_requests(phba);
	psli = &phba->sli;
	pring = &psli->ring[psli->fcp_ring];

	spin_lock_irqsave(phba->host->host_lock, iflag);
	lpfc_linkdown(phba);
	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	for (i = 0; i < psli->sliinit.num_rings; i++) {
		pring = &psli->ring[i];
		/* The linkdown event takes 30 seconds to timeout. */
		while (pring->txcmplq_cnt) {
			LPFC_MDELAY(10);
			if (cnt++ > 3000) {
				lpfc_printf_log(phba,
					KERN_WARNING, LOG_INIT,
					"%d:0466 Outstanding IO when "
					"bringing Adapter offline\n",
					phba->brd_no);
				break;
			}
		}
	}

	/* stop all timers associated with this hba */
	lpfc_stop_timer(phba);

	lpfc_printf_log(phba,
		       KERN_WARNING,
		       LOG_INIT,
		       "%d:0460 Bring Adapter offline\n",
		       phba->brd_no);

	/* Bring down the SLI Layer and cleanup.  The HBA is offline
	   now.  */
	spin_lock_irqsave(phba->host->host_lock, iflag);
	phba->work_hba_events = 0;
	lpfc_sli_hba_down(phba);
	lpfc_cleanup(phba, 1);
	phba->fc_flag |= FC_OFFLINE_MODE;
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return 0;
}

/******************************************************************************
* Function name : lpfc_scsi_free
*
* Description   : Called from fc_detach to free scsi tgt / lun resources
*
******************************************************************************/
int
lpfc_scsi_free(struct lpfc_hba * phba)
{
	struct lpfc_target *targetp;
	int i;

	for (i = 0; i < LPFC_MAX_TARGET; i++) {
		targetp = phba->device_queue_hash[i];
		if (targetp) {
			kfree(targetp);
			phba->device_queue_hash[i] = NULL;
		}
	}
	return 0;
}

static void
lpfc_wakeup_event(struct lpfc_hba * phba, fcEVTHDR_t * ep)
{
	ep->e_mode &= ~E_SLEEPING_MODE;
	switch (ep->e_mask) {
	case FC_REG_LINK_EVENT:
		wake_up_interruptible(&phba->linkevtwq);
		break;
	case FC_REG_RSCN_EVENT:
		wake_up_interruptible(&phba->rscnevtwq);
		break;
	case FC_REG_CT_EVENT:
		wake_up_interruptible(&phba->ctevtwq);
		break;
	case FC_REG_DUMP_EVENT:
		wake_up_interruptible(&phba->dumpevtwq);
		break;
	case FC_REG_TEMPERATURE_EVENT:
		wake_up_interruptible(&phba->tempevtwq);
		break;
	}
	return;
}

int
lpfc_put_event(struct lpfc_hba * phba, uint32_t evcode, uint32_t evdata0,
	       void * evdata1, uint32_t evdata2, uint32_t evdata3)
{
	fcEVT_t *ep;
	fcEVTHDR_t *ehp = phba->fc_evt_head;
	int found = 0;
	void *fstype = NULL;
	struct lpfc_dmabuf *mp;
	struct lpfc_sli_ct_request *ctp;
	struct lpfc_hba_event *rec;
	uint32_t evtype;

	switch (evcode) {
		case HBA_EVENT_RSCN:
			evtype = FC_REG_RSCN_EVENT;
			break;
		case HBA_EVENT_LINK_DOWN:
		case HBA_EVENT_LINK_UP:
			evtype = FC_REG_LINK_EVENT;
			break;
		case HBA_EVENT_DUMP:
			evtype = FC_REG_DUMP_EVENT;
			break;
		case HBA_EVENT_TEMP:
			evtype = FC_REG_TEMPERATURE_EVENT;
			break;
		default:
			evtype = FC_REG_CT_EVENT;
	}

	if (evtype == FC_REG_RSCN_EVENT || evtype == FC_REG_LINK_EVENT) {
		rec = &phba->hbaevt[phba->hba_event_put];
		rec->fc_eventcode = evcode;
		rec->fc_evdata1 = evdata0;
		rec->fc_evdata2 = (uint32_t)(unsigned long)evdata1;
		rec->fc_evdata3 = evdata2;
		rec->fc_evdata4 = evdata3;

		phba->hba_event_put++;
		if (phba->hba_event_put >= MAX_HBAEVT)
			phba->hba_event_put = 0;

		if (phba->hba_event_put == phba->hba_event_get) {
			phba->hba_event_missed++;
			phba->hba_event_get++;
			if (phba->hba_event_get >= MAX_HBAEVT)
				phba->hba_event_get = 0;
		}
	}

	if (evtype == FC_REG_CT_EVENT) {
		mp = (struct lpfc_dmabuf *) evdata1;
		ctp = (struct lpfc_sli_ct_request *) mp->virt;
		fstype = (void *)(ulong) (ctp->FsType);
	}

	while (ehp && ((ehp->e_mask != evtype) || (ehp->e_type != fstype)))
		ehp = (fcEVTHDR_t *) ehp->e_next_header;

	if (!ehp)
		return (0);

	ep = ehp->e_head;

	while (ep && !(found)) {
		if (ep->evt_sleep) {
			switch (evtype) {
			case FC_REG_CT_EVENT:
				if ((ep->evt_type ==
				     (void *)(ulong) FC_FSTYPE_ALL)
				    || (ep->evt_type == fstype)) {
					found++;
					ep->evt_data0 = evdata0; /* tag */
					ep->evt_data1 = evdata1; /* buffer
								    ptr */
					ep->evt_data2 = evdata2; /* count */
					ep->evt_sleep = 0;
					if (ehp->e_mode & E_SLEEPING_MODE) {
						ehp->e_flag |=
						    E_GET_EVENT_ACTIVE;
						lpfc_wakeup_event(phba, ehp);
					}
					/* For FC_REG_CT_EVENT just give it to
					   first one found */
				}
				break;
			case FC_REG_DUMP_EVENT:
				found++;
				ep->evt_data0 = evdata0;
				ep->evt_data1 = evdata1;
				ep->evt_data2 = evdata2;
				ep->evt_sleep = 0;
				if (ehp->e_mode & E_SLEEPING_MODE) {
					ehp->e_flag |= E_GET_EVENT_ACTIVE;
					lpfc_wakeup_event(phba, ehp);
				}
				/* For FC_REG_DUMP_EVENT just give it to
				   first one found */
				break;
			default:
				found++;
				ep->evt_data0 = evdata0;
				ep->evt_data1 = evdata1;
				ep->evt_data2 = evdata2;
				ep->evt_sleep = 0;
				if ((ehp->e_mode & E_SLEEPING_MODE)
				    && !(ehp->e_flag & E_GET_EVENT_ACTIVE)) {
					ehp->e_flag |= E_GET_EVENT_ACTIVE;
					lpfc_wakeup_event(phba, ehp);
				}
				/* For all other events, give it to every one
				   waiting */
				break;
			}
		}
		ep = ep->evt_next;
	}
	if (evtype == FC_REG_LINK_EVENT)
		phba->nport_event_cnt++;

	return (found);
}

int
lpfc_stop_timer(struct lpfc_hba * phba)
{
	unsigned long iflag;

	/* Instead of a timer, this has been converted to a
	 * deferred procedding list.
	 */
	spin_lock_irqsave(phba->host->host_lock, iflag);
	while (!list_empty(&phba->freebufList)) {
		struct lpfc_dmabuf *mp;

		mp = (struct lpfc_dmabuf *)(phba->freebufList.next);
		if (mp) {
			lpfc_mbuf_free(phba, mp->virt, mp->phys);
			list_del(&mp->list);
			kfree(mp);
		}
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	del_timer_sync(&phba->fc_estabtmo);
	del_timer_sync(&phba->fc_disctmo);
	del_timer_sync(&phba->fc_scantmo);
	del_timer_sync(&phba->fc_lnkdwntmo);
	del_timer_sync(&phba->fc_fdmitmo);
	del_timer_sync(&phba->els_tmofunc);
	del_timer_sync(&phba->sli.mbox_tmo);
	del_timer_sync(&phba->hatt_tmo);
	phba->hb_outstanding = 0;
	del_timer_sync(&phba->hb_tmofunc);
	return(1);
}

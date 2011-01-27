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
 * $Id: lpfc_debug_ioctl.c 3167 2008-04-11 15:31:09Z sf_support $
 */
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include <linux/string.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/unistd.h>
#include <linux/timex.h>
#include <linux/timer.h>

#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <asm/system.h>
#include <asm/bitops.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <asm/irq.h>
#include <linux/blkdev.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <asm/pci.h>

#include "lpfc_hw.h"
#include "lpfc_sli.h"
#include "lpfc_mem.h"
#include "lpfc_disc.h"
#include "lpfc_scsi.h"
#include "lpfc.h"
#include "lpfc_logmsg.h"
#include "lpfc_fcp.h"
#include "lpfc_diag.h"
#include "lpfc_ioctl.h"
#include "lpfc_diag.h"
#include "lpfc_crtn.h"
#include "lpfc_debug_ioctl.h"
#include "lpfc_misc.h"
#include "lpfc_compat.h"

int
lpfc_process_ioctl_dfc(LPFCCMDINPUT_t * cip)
{
	struct lpfc_hba *phba;
	int rc = -1;
	uint32_t outshift;
	uint32_t total_mem;
	void   *dataout;

	if ((phba = lpfc_get_phba_by_inst(cip->lpfc_brd)) == NULL)
			return EINVAL;

	/* libdfc debug entry */
	lpfc_printf_log(phba,
			KERN_INFO,
			LOG_LIBDFC,
			"%d:1600 libdfc debug entry Data: x%x x%lx x%lx x%x\n",
			phba->brd_no, cip->lpfc_cmd,
			(ulong) cip->lpfc_arg1,(ulong) cip->lpfc_arg2,
			cip->lpfc_outsz);

	outshift = 0;
	if (cip->lpfc_outsz >= 4096) {

		/* Allocate memory for ioctl data. If buffer is bigger than 64k, then we
		 * allocate 64k and re-use that buffer over and over to xfer the whole 
		 * block. This is because Linux kernel has a problem allocating more than
		 * 120k of kernel space memory. Saw problem with GET_FCPTARGETMAPPING...
		 */
		if (cip->lpfc_outsz <= (64 * 1024))
			total_mem = cip->lpfc_outsz;
		else
			total_mem = 64 * 1024;		
	} else {
		/* Allocate memory for ioctl data */
		total_mem = 4096;
	}
	dataout = kmalloc(total_mem, GFP_KERNEL);
	if (!dataout)
		return (ENOMEM);

	switch (cip->lpfc_cmd) {

	/* Debug Interface Support - dfc */
	case LPFC_LIP:
		rc = lpfc_ioctl_lip(phba, cip, dataout);
		break;

	case LPFC_INST:
		rc = lpfc_ioctl_inst(phba, cip, dataout);
		break;

	case LPFC_READ_BPLIST:
		rc = lpfc_ioctl_read_bplist(phba, cip, dataout, total_mem);
		break;

	case LPFC_LISTN:
		rc = lpfc_ioctl_listn(phba, cip, dataout, total_mem);
		break;

	case LPFC_RESET:
		rc = lpfc_ioctl_reset(phba, cip);
		break;

	case LPFC_READ_HBA:
		rc = lpfc_ioctl_read_hba(phba, cip, dataout, total_mem);
		break;

	case LPFC_STAT:
		rc = lpfc_ioctl_stat(phba, cip, dataout);
		break;
	}

	if (rc != -1) {
		/* dfc_ioctl exit */
		lpfc_printf_log(phba,
			KERN_INFO,
			LOG_LIBDFC,
			"%d:1601 libdfc debug exit Data: x%x x%x x%x\n",
			phba->brd_no,
			rc,
			cip->lpfc_outsz,
			(uint32_t) ((ulong) cip->lpfc_dataout));
	}


	/* Copy data to user space config method */
	if (rc == 0) {
		if (cip->lpfc_outsz) {
			if (copy_to_user
			    ((uint8_t *) cip->lpfc_dataout,
			     (uint8_t *) dataout, (int)cip->lpfc_outsz)) {
				rc = EIO;
			}
		}
	}


	kfree(dataout);
	return(rc);
}

int
lpfc_ioctl_lip(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{
	struct lpfc_sli *psli;
	struct lpfc_sli_ring *pring;
	LPFC_MBOXQ_t *pmboxq;
	int mbxstatus;
	int i, rc;

	psli = &phba->sli;

	rc = 0;

	mbxstatus = MBXERR_ERROR;
	if (phba->hba_state == LPFC_HBA_READY) {
		if ((pmboxq = mempool_alloc(phba->mbox_mem_pool, GFP_ATOMIC)) == 0) {
			return ENOMEM;
		}

		scsi_block_requests(phba->host);

		i = 0;
		pring = &psli->ring[psli->fcp_ring];
		while (pring->txcmplq_cnt) {
			if (i++ > 500) {	/* wait up to 5 seconds */
				break;
			}

			mdelay(10);
		}
		memset((void *)pmboxq, 0, sizeof (LPFC_MBOXQ_t));
		lpfc_init_link(phba, pmboxq, phba->cfg_topology,
			       phba->cfg_link_speed);

		mbxstatus =
			lpfc_sli_issue_mbox_wait(phba, pmboxq, phba->fc_ratov * 2);

		if (mbxstatus == MBX_TIMEOUT) {
			/*
			 * Let SLI layer to release mboxq if mbox command completed after timeout.
			 */
			pmboxq->mbox_cmpl = lpfc_sli_def_mbox_cmpl;
		} else {
			mempool_free( pmboxq, phba->mbox_mem_pool);
		}

		if ((mbxstatus != MBX_SUCCESS) || (pmboxq->mb.mbxStatus))
			rc = ENODEV;

		scsi_unblock_requests(phba->host);
	} else
		rc = EACCES;

	memcpy(dataout, (char *)&mbxstatus, sizeof (uint16_t));

	return (rc);
}

int
copy_sli_info(dfcsli_t * pdfcsli, struct lpfc_sli * psli)
{
	int i, j;

	for (i = 0; i < LPFC_MAX_RING; ++i) {
		for (j = 0; j < LPFC_MAX_RING_MASK; ++j) {
			pdfcsli->sliinit.ringinit[i].prt[j].rctl =
				psli->sliinit.ringinit[i].prt[j].rctl;
			pdfcsli->sliinit.ringinit[i].prt[j].type =
				psli->sliinit.ringinit[i].prt[j].type;
		}
		pdfcsli->sliinit.ringinit[i].num_mask =
			psli->sliinit.ringinit[i].num_mask;
		pdfcsli->sliinit.ringinit[i].iotag_ctr =
			psli->sliinit.ringinit[i].iotag_ctr;
		pdfcsli->sliinit.ringinit[i].numCiocb =
			psli->sliinit.ringinit[i].numCiocb;
		pdfcsli->sliinit.ringinit[i].numRiocb =
			psli->sliinit.ringinit[i].numRiocb;
	}
	pdfcsli->sliinit.num_rings = psli->sliinit.num_rings;
	pdfcsli->sliinit.sli_flag = psli->sliinit.sli_flag;
	pdfcsli->MBhostaddr.addrlo =
		(uint64_t)((unsigned long)psli->MBhostaddr) & 0xffffffff;
	pdfcsli->MBhostaddr.addrhi =
		(uint64_t)((unsigned long)psli->MBhostaddr) >> 32;
	for (i = 0; i < LPFC_MAX_RING; ++i) {
		pdfcsli->ring[i].rspidx = psli->ring[i].rspidx;
		pdfcsli->ring[i].cmdidx = psli->ring[i].cmdidx;
		pdfcsli->ring[i].txq_cnt = psli->ring[i].txq_cnt;
		pdfcsli->ring[i].txq_max = psli->ring[i].txq_max;
		pdfcsli->ring[i].txcmplq_cnt = psli->ring[i].txcmplq_cnt;
		pdfcsli->ring[i].txcmplq_max = psli->ring[i].txcmplq_max;
		pdfcsli->ring[i].cmdringaddr.addrlo =
			(uint64_t)((unsigned long)psli->ring[i].cmdringaddr)
			& 0xffffffff;
		pdfcsli->ring[i].cmdringaddr.addrhi =
			(uint64_t)((unsigned long)psli->ring[i].cmdringaddr)
			>> 32;
		pdfcsli->ring[i].rspringaddr.addrlo =
			(uint64_t)((unsigned long)psli->ring[i].rspringaddr)
			& 0xffffffff;
		pdfcsli->ring[i].rspringaddr.addrhi =
			(uint64_t)((unsigned long)psli->ring[i].rspringaddr)
			>> 32;
		pdfcsli->ring[i].missbufcnt = psli->ring[i].missbufcnt;
		pdfcsli->ring[i].postbufq_cnt = psli->ring[i].postbufq_cnt;
		pdfcsli->ring[i].postbufq_max = psli->ring[i].postbufq_max;
	}
	pdfcsli->mboxq_cnt = psli->mboxq_cnt;
	pdfcsli->mboxq_max = psli->mboxq_max;
	for (i = 0; i < LPFC_MAX_RING; ++i) {
		pdfcsli->slistat.iocbEvent[i].lo =
			(uint64_t)((unsigned long)psli->slistat.iocbEvent[i])
			& 0xffffffff;
		pdfcsli->slistat.iocbEvent[i].hi =
			(uint64_t)((unsigned long)psli->slistat.iocbEvent[i])
			>> 32;
		pdfcsli->slistat.iocbCmd[i].lo =
			(uint64_t)((unsigned long)psli->slistat.iocbCmd[i])
			& 0xffffffff;
		pdfcsli->slistat.iocbCmd[i].hi =
			(uint64_t)((unsigned long)psli->slistat.iocbCmd[i])
			>> 32;
		pdfcsli->slistat.iocbRsp[i].lo =
			(uint64_t)((unsigned long)psli->slistat.iocbRsp[i])
			& 0xffffffff;
		pdfcsli->slistat.iocbRsp[i].hi =
			(uint64_t)((unsigned long)psli->slistat.iocbRsp[i])
			>> 32;
		pdfcsli->slistat.iocbCmdFull[i].lo =
			(uint64_t)((unsigned long)psli->slistat.iocbCmdFull[i])
			& 0xffffffff;
		pdfcsli->slistat.iocbCmdFull[i].hi =
			(uint64_t)((unsigned long)psli->slistat.iocbCmdFull[i])
			>> 32;
		pdfcsli->slistat.iocbCmdEmpty[i].lo =
			(uint64_t)((unsigned long)psli->slistat.iocbCmdEmpty[i])
			& 0xffffffff;
		pdfcsli->slistat.iocbCmdEmpty[i].hi =
			(uint64_t)((unsigned long)psli->slistat.iocbCmdEmpty[i])
			>> 32;
		pdfcsli->slistat.iocbRspFull[i].lo =
			(uint64_t)((unsigned long)psli->slistat.iocbRspFull[i])
			& 0xffffffff;
		pdfcsli->slistat.iocbRspFull[i].hi =
			(uint64_t)((unsigned long)psli->slistat.iocbRspFull[i])
			>> 32;
	}
	pdfcsli->slistat.mboxStatErr.lo =
		(uint64_t)((unsigned long)psli->slistat.mboxStatErr)
		& 0xffffffff;
	pdfcsli->slistat.mboxStatErr.hi =
		(uint64_t)((unsigned long)psli->slistat.mboxStatErr)
		>> 32;
	pdfcsli->slistat.mboxCmd.lo =
		(uint64_t)((unsigned long)psli->slistat.mboxCmd)
		& 0xffffffff;
	pdfcsli->slistat.mboxCmd.hi =
		(uint64_t)((unsigned long)psli->slistat.mboxCmd)
		>> 32;
	pdfcsli->slistat.sliIntr.lo =
		(uint64_t)((unsigned long)psli->slistat.sliIntr)
		& 0xffffffff;
	pdfcsli->slistat.sliIntr.hi =
		(uint64_t)((unsigned long)psli->slistat.sliIntr)
		>> 32;
	pdfcsli->slistat.errAttnEvent = psli->slistat.errAttnEvent;
	pdfcsli->slistat.linkEvent = psli->slistat.linkEvent;
	pdfcsli->fcp_ring = (uint32_t)psli->fcp_ring;
	return (0);
}

int
lpfc_ioctl_inst(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{
	int *p_int;
	int rc = 0, devcount = 0;
	struct lpfc_hba *iphba;
	unsigned long iflag;
	extern struct list_head *lpfcdfc_hba_list;

	p_int = dataout;
	*p_int++;

	/* Store instance number of each device */
	spin_lock_irqsave(phba->host->host_lock, iflag); /* hba_list_head move/remove */
	list_for_each_entry(iphba, lpfcdfc_hba_list, hba_list) {
		*p_int++ = iphba->brd_no;
		devcount++;
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* hba_list_head move/remove */
	/* Store the number of devices */
	p_int = dataout;
	*p_int = devcount;
	
	return (rc);
}

int
copy_node_list(dfcnodelist_t *pdfcndl, struct lpfc_nodelist *pndl)
{
	pdfcndl->nlp_failMask = pndl->nlp_failMask;
	pdfcndl->nlp_type = pndl->nlp_type;
	pdfcndl->nlp_rpi = pndl->nlp_rpi;
	pdfcndl->nlp_state = pndl->nlp_state;
	pdfcndl->nlp_xri = pndl->nlp_xri;
	pdfcndl->nlp_flag = pndl->nlp_flag;
	pdfcndl->nlp_DID = pndl->nlp_DID;
	memcpy(pdfcndl->nlp_portname,
	       (uint8_t *)&(pndl->nlp_portname),
	       sizeof(pdfcndl->nlp_portname));
	memcpy(pdfcndl->nlp_nodename,
	       (uint8_t *)&(pndl->nlp_nodename),
	       sizeof(pdfcndl->nlp_nodename));
	pdfcndl->nlp_sid = pndl->nlp_sid;

	return (sizeof (dfcnodelist_t));
}

int
lpfc_ioctl_listn(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip,  void *dataout, int size)
{

	dfcbindlist_t   *bpp;
	struct lpfc_bindlist *blp;
	dfcnodelist_t   *npp;
	struct lpfc_nodelist *pndl;
	struct list_head *pos;
	uint32_t offset;
	uint32_t lcnt;
	uint32_t *lcntp;
	int rc = 0;
	uint32_t total_mem = size;
	unsigned long iflag;

	offset = (ulong) cip->lpfc_arg1;
	/* If the value of offset is 1, the driver is handling
	 * the bindlist.  Correct the total memory to account for the 
	 * bindlist's different size 
	 */
	if (offset == 1) {
		total_mem -= sizeof (struct lpfc_bindlist);
	} else {
		total_mem -= sizeof (struct lpfc_nodelist);
	}

	lcnt = 0;
	spin_lock_irqsave(phba->host->host_lock, iflag); /* move/remove */
	switch (offset) {
	case 0:		/* unused */
		lcntp = dataout;
		memcpy(dataout, (uint8_t *) & lcnt, sizeof (uint32_t));
		npp = (dfcnodelist_t *) ((uint8_t *) (dataout) + sizeof (uint32_t));
		list_for_each(pos, &phba->fc_unused_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}
		*lcntp = lcnt;
		break;
	case 1:		/* plogi */
		lcntp = dataout;
		memcpy(dataout, (uint8_t *) & lcnt, sizeof (uint32_t));
		npp = (dfcnodelist_t *) ((uint8_t *) (dataout) + sizeof (uint32_t));
		list_for_each(pos, &phba->fc_plogi_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}
		*lcntp = lcnt;
		break;
	case 2:		/* adisc */
		lcntp = dataout;
		memcpy(dataout, (uint8_t *) & lcnt, sizeof (uint32_t));
		npp = (dfcnodelist_t *) ((uint8_t *) (dataout) + sizeof (uint32_t));
		list_for_each(pos, &phba->fc_adisc_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}
		*lcntp = lcnt;
		break;
	case 3:		/* reglogin */
		lcntp = dataout;
		memcpy(dataout, (uint8_t *) & lcnt, sizeof (uint32_t));
		npp = (dfcnodelist_t *) ((uint8_t *) (dataout) + sizeof (uint32_t));
		list_for_each(pos, &phba->fc_reglogin_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}
		*lcntp = lcnt;
		break;
	case 4:		/* prli */
		lcntp = dataout;
		memcpy(dataout, (uint8_t *) & lcnt, sizeof (uint32_t));
		npp = (dfcnodelist_t *) ((uint8_t *) (dataout) + sizeof (uint32_t));
		list_for_each(pos, &phba->fc_prli_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);		
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;   
		}
		*lcntp = lcnt;
		break;
	case 5:		/* unmapped */
		lcntp = dataout;
		memcpy(dataout, (uint8_t *) & lcnt, sizeof (uint32_t));
		npp = (dfcnodelist_t *) ((uint8_t *) (dataout) + sizeof (uint32_t));
		
		list_for_each(pos, &phba->fc_nlpunmap_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}
		*lcntp = lcnt;
		break;
	case 6:		/* map */
		lcntp = dataout;
		memcpy(dataout, (uint8_t *) & lcnt, sizeof (uint32_t));
		npp = (dfcnodelist_t *) ((uint8_t *) (dataout) + sizeof (uint32_t));
		
		list_for_each(pos, &phba->fc_nlpmap_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);		
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}
		*lcntp = lcnt;
		break;
	case 7:		/* npr */
		lcntp = dataout;
		memcpy(dataout, (uint8_t *) & lcnt, sizeof (uint32_t));
		npp = (dfcnodelist_t *) ((uint8_t *) (dataout) + sizeof (uint32_t));
		
		list_for_each(pos, &phba->fc_npr_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);		
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}
		*lcntp = lcnt;
		break;
	case 8:		/* all except bind list */
		lcntp = dataout;
		memcpy(dataout, (uint8_t *) & lcnt, sizeof (uint32_t));
		npp =
		    (dfcnodelist_t *) ((uint8_t *) (dataout) +
					 sizeof (uint32_t));

		list_for_each(pos, &phba->fc_unused_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}

		list_for_each(pos, &phba->fc_plogi_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}

		list_for_each(pos, &phba->fc_adisc_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}

		list_for_each(pos, &phba->fc_reglogin_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}

		list_for_each(pos, &phba->fc_prli_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}

		list_for_each(pos, &phba->fc_nlpunmap_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}

		list_for_each(pos, &phba->fc_nlpmap_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}

		list_for_each(pos, &phba->fc_npr_list) {
			if (total_mem <= 0)
				break;
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			total_mem -= copy_node_list(npp, pndl);
			npp++;
			lcnt++;
		}

		*lcntp = lcnt;
		break;
	case 9:		/* bind */
		lcntp = dataout;
		memcpy(dataout, (uint8_t *) & lcnt, sizeof (uint32_t));
		bpp =
		    (dfcbindlist_t *) ((uint8_t *) (dataout) +
					 sizeof (uint32_t));

		list_for_each(pos, &phba->fc_nlpbind_list) {
			if (total_mem <= 0)
				break;
			blp = list_entry(pos, struct lpfc_bindlist, nlp_listp);

			memcpy(bpp->nlp_portname,
			       (uint8_t *)&(blp->nlp_portname),
			       sizeof(bpp->nlp_portname));
			memcpy(bpp->nlp_nodename,
			       (uint8_t *)&(blp->nlp_nodename),
			       sizeof(bpp->nlp_nodename));
			bpp->nlp_bind_type = blp->nlp_bind_type;
			bpp->nlp_sid = blp->nlp_sid;
			bpp->nlp_DID = blp->nlp_DID;
			total_mem -= sizeof (dfcbindlist_t);
			bpp++;
			lcnt++;
		}
		*lcntp = lcnt;
		break;
	default:
		rc = ERANGE;
		break;
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* move/remove */

	cip->lpfc_outsz = (sizeof (uint32_t) + (lcnt * sizeof (struct lpfc_nodelist)));

	return (rc);
}

int
lpfc_ioctl_read_bplist(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, 
		       void *dataout, int size)
{
	struct lpfc_sli_ring *rp;
	struct list_head *dlp;
	struct lpfc_dmabuf *mm;
	uint32_t *lptr;
	struct lpfc_sli *psli;
	int rc = 0;
	struct list_head *pos;
	uint32_t total_mem = size;
	unsigned long iflag;

	psli = &phba->sli;
	rp = &psli->ring[LPFC_ELS_RING];	/* RING 0 */
	dlp = &rp->postbufq;
	lptr = (uint32_t *) dataout;
	total_mem -= (3 * sizeof (uint32_t));

	spin_lock_irqsave(phba->host->host_lock, iflag); /* rp->postbufq */
	list_for_each(pos, &rp->postbufq) {
		if (total_mem <= 0)
			break;
		mm = list_entry(pos, struct lpfc_dmabuf, list);
		if ((cip->lpfc_ring == LPFC_ELS_RING)
		    || (cip->lpfc_ring == LPFC_FCP_NEXT_RING)) {
			*lptr++ = (uint32_t) ((ulong) mm);
			*lptr++ = (uint32_t) ((ulong) mm->virt);
			*lptr++ = (uint32_t) ((ulong) mm->phys);
		}
		total_mem -= (3 * sizeof (uint32_t));
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* rp->postbufq */
	*lptr++ = 0;

	cip->lpfc_outsz = ((uint8_t *) lptr - (uint8_t *) (dataout));

	return (rc);
}

int
lpfc_ioctl_reset(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip)
{
	uint32_t offset;
	struct lpfc_sli *psli;
	int rc = 0;

	if (!phba->cfg_enable_hba_reset)
		return (EIO);

	psli = &phba->sli;
	offset = (ulong) cip->lpfc_arg1;

	switch (offset) {
	case 1:		/* Selective reset */
	case 2:		/* Coordinated reset */
		lpfc_offline(phba);
		lpfc_sli_brdrestart(phba);
		lpfc_online(phba);
		break;

	default:
		rc = ERANGE;
		break;
	}

	return (rc);
}

int
copy_hba_info(void *dataout, struct lpfc_hba * phba)
{
	dfchba_t * pdfchba;

	pdfchba = (dfchba_t*)dataout;

	pdfchba->hba_state = phba->hba_state;
	pdfchba->fc_busflag = 0;
	copy_sli_info(&pdfchba->sli, &phba->sli);
	return (0);
}

int
copy_stat_info(void *dataout, struct lpfc_hba * phba)
{
	dfcstats_t * pdfcstat;
	pdfcstat = (dfcstats_t*)dataout;

	pdfcstat->elsRetryExceeded = phba->fc_stat.elsRetryExceeded;
	pdfcstat->elsXmitRetry = phba->fc_stat.elsXmitRetry;
	pdfcstat->elsRcvDrop = phba->fc_stat.elsRcvDrop;
	pdfcstat->elsRcvFrame = phba->fc_stat.elsRcvFrame;
	pdfcstat->elsRcvRSCN = phba->fc_stat.elsRcvRSCN;
	pdfcstat->elsRcvRNID = phba->fc_stat.elsRcvRNID;
	pdfcstat->elsRcvFARP = phba->fc_stat.elsRcvFARP;
	pdfcstat->elsRcvFARPR = phba->fc_stat.elsRcvFARPR;
	pdfcstat->elsRcvFLOGI = phba->fc_stat.elsRcvFLOGI;
	pdfcstat->elsRcvPLOGI = phba->fc_stat.elsRcvPLOGI;
	pdfcstat->elsRcvADISC = phba->fc_stat.elsRcvADISC;
	pdfcstat->elsRcvPDISC = phba->fc_stat.elsRcvPDISC;
	pdfcstat->elsRcvFAN = phba->fc_stat.elsRcvFAN;
	pdfcstat->elsRcvLOGO = phba->fc_stat.elsRcvLOGO;
	pdfcstat->elsRcvPRLO = phba->fc_stat.elsRcvPRLO;
	pdfcstat->elsRcvPRLI = phba->fc_stat.elsRcvPRLI;
	pdfcstat->elsRcvLIRR = phba->fc_stat.elsRcvLIRR;
	pdfcstat->elsRcvRPS = phba->fc_stat.elsRcvRPS;
	pdfcstat->elsRcvRPL = phba->fc_stat.elsRcvRPL;
	pdfcstat->frameRcvBcast = phba->fc_stat.frameRcvBcast;
	pdfcstat->frameRcvMulti = phba->fc_stat.frameRcvMulti;
	pdfcstat->strayXmitCmpl = phba->fc_stat.strayXmitCmpl;
	pdfcstat->frameXmitDelay = phba->fc_stat.frameXmitDelay;
	pdfcstat->xriCmdCmpl = phba->fc_stat.xriCmdCmpl;
	pdfcstat->xriStatErr = phba->fc_stat.xriStatErr;
	pdfcstat->LinkUp = phba->fc_stat.LinkUp;
	pdfcstat->LinkDown = phba->fc_stat.LinkDown;
	pdfcstat->LinkMultiEvent = phba->fc_stat.LinkMultiEvent;
	pdfcstat->NoRcvBuf = phba->fc_stat.NoRcvBuf;
	pdfcstat->fcpCmd = phba->fc_stat.fcpCmd;
	pdfcstat->fcpCmpl = phba->fc_stat.fcpCmpl;
	pdfcstat->fcpRspErr = phba->fc_stat.fcpRspErr;
	pdfcstat->fcpRemoteStop = phba->fc_stat.fcpRemoteStop;
	pdfcstat->fcpPortRjt = phba->fc_stat.fcpPortRjt;
	pdfcstat->fcpPortBusy = phba->fc_stat.fcpPortBusy;
	pdfcstat->fcpError = phba->fc_stat.fcpError;
	return(0);
}

int
lpfc_ioctl_read_hba(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout, int size)
{

	struct lpfc_sli *psli;
	int rc = 0;
	int cnt = 0;
	unsigned long iflag;
	void* psavbuf = 0;

	psli = &phba->sli;
	if (cip->lpfc_arg1) {

		spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA SLI state */

		if (psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE) {

			/* The SLIM2 size is stored in the next field.  We cannot exceed
			 * the size of the dataout buffer so if it's not big enough we need
			 * to allocate a temp buffer.
			 */
			cnt = SLI2_SLIM_SIZE;
			if (cnt > size) {
				psavbuf = dataout;
				dataout = kmalloc(cnt, GFP_ATOMIC);
				if (!dataout) {
					spin_unlock_irqrestore(phba->host->host_lock, iflag);
					return (ENOMEM);
				}
			}
		} else {
			cnt = 4096;
		}

		if (psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE) {
			/* copy results back to user */
			lpfc_sli_pcimem_bcopy((uint32_t *) psli->MBhostaddr,
					     (uint32_t *) dataout, cnt);
		} else {
			/* First copy command data */
			lpfc_memcpy_from_slim( dataout, phba->MBslimaddr, cnt);
		}

		spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA SLI state */
		if (copy_to_user
		    ((uint8_t *) cip->lpfc_arg1, (uint8_t *) dataout,
		     cnt)) {
			rc = EIO;
		}
		if (psavbuf) {
			kfree(dataout);
			dataout = psavbuf;
			psavbuf = 0;
		}
		if (rc)
			return (rc);
	}
	copy_hba_info(dataout, phba);
	return (rc);
}

int
lpfc_ioctl_stat(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{
	int rc = 0;

	if ((ulong) cip->lpfc_arg1 == 1) {
		copy_hba_info(dataout, phba);
	}

	/* Copy struct lpfc_stats */
	if ((ulong) cip->lpfc_arg1 == 2) {
		copy_stat_info(dataout, phba);
	}

	return (rc);
}

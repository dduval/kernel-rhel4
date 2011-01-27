/*******************************************************************
 * This file is part of the Emulex Linux Device Driver for         *
 * Fibre Channel Host Bus Adapters.                                *
 * Copyright (C) 2008 Emulex.  All rights reserved.                *
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
 * $Id: lpfc_menlo.c 3026 2008-02-06 14:03:17Z sf_support $
 *
 * Hornet/Menlo support
 */

#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/utsname.h>
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


typedef struct menlo_get_cmd
{
	uint32_t code;          /* Command code */
	uint32_t context;       /* Context */
	uint32_t length;        /* Max response length */
} menlo_get_cmd_t;

typedef struct menlo_init_rsp
{
	uint32_t code;
	uint32_t bb_credit;     /* Menlo FC BB Credit */
	uint32_t frame_size;    /* Menlo FC receive frame size */
	uint32_t fw_version;    /* Menlo firmware version   */
	uint32_t reset_status;  /* Reason for previous reset */

#define MENLO_RESET_STATUS_NORMAL               0
#define MENLO_RESET_STATUS_PANIC                1

	uint32_t maint_status;  /* Menlo Maintenance Mode status at link up */


#define MENLO_MAINTENANCE_MODE_DISABLE  0
#define MENLO_MAINTENANCE_MODE_ENABLE   1
	uint32_t fw_type;
	uint32_t fru_data_valid; /* 0=invalid, 1=valid */
} menlo_init_rsp_t;

#define MENLO_CMD_GET_INIT 0x00000007
#define MENLO_FW_TYPE_OPERATIONAL 0xABCD0001
#define MENLO_FW_TYPE_GOLDEN    0xABCD0002
#define MENLO_FW_TYPE_DIAG      0xABCD0003



void
BE_swap32_buffer(void *srcp, uint32_t cnt)
{
	uint32_t *src = srcp;
	uint32_t *dest = srcp;
	uint32_t ldata;
	int i;

	for (i = 0; i < (int)cnt; i += sizeof (uint32_t)) {
		ldata = *src;
		ldata = cpu_to_le32(ldata);
		*dest = ldata;
		src++;
		dest++;
	}
}

/*
 * lpfc_check_menlo_cfg_cmpl
 * Description:
 *    Issue Cmd to MENLO
 *       SLI_CTNS_GID_FT
 *       LI_CTNS_RFT_ID
 */
static void
lpfc_check_menlo_cfg_cmpl(struct lpfc_hba * phba, struct lpfc_iocbq * cmdiocb,
			struct lpfc_iocbq * rspiocb)
{
	IOCB_t *irsp;
	struct lpfc_dmabuf *bmp;
	struct lpfc_dmabuf *inp;
	struct lpfc_dmabuf *outp;
	menlo_init_rsp_t *mlorsp = NULL;

	inp = (struct lpfc_dmabuf *) cmdiocb->context1;
	outp = (struct lpfc_dmabuf *) cmdiocb->context2;
	bmp = (struct lpfc_dmabuf *) cmdiocb->context3;
	lpfc_printf_log (phba, KERN_ERR, LOG_LINK_EVENT,
			"%d:1298 FCoE chip firmware callback.\n ",
			phba->brd_no );

	irsp = &rspiocb->iocb;
	if (irsp->ulpStatus) {
		lpfc_printf_log (phba, KERN_ERR, LOG_LINK_EVENT,
				"%d:1296 Checking FRU data Failed 0x%x/0x%x.\n",
				phba->brd_no,
				irsp->ulpStatus,
				irsp->un.ulpWord[4]);
		if((irsp->ulpStatus == IOSTAT_LOCAL_REJECT) &&
				((irsp->un.ulpWord[4] == IOERR_SLI_DOWN) ||
				 (irsp->un.ulpWord[4] == IOERR_SLI_ABORTED)))
			goto out;


	} else {
		/* Good status, continue checking */
		mlorsp = (menlo_init_rsp_t *) outp->virt;
		BE_swap32_buffer ((uint8_t *) mlorsp, sizeof(menlo_init_rsp_t));
		switch (mlorsp->fw_type)
		{
			case MENLO_FW_TYPE_OPERATIONAL: /* Menlo Operational */
				break;
			case MENLO_FW_TYPE_GOLDEN:      /* Menlo Golden */
				lpfc_printf_log (phba, KERN_ERR, LOG_LINK_EVENT,
						"%d:1246 FCoE chip is running golden firmware. "
						"Update FCoE chip firmware immediately %x\n",
						phba->brd_no,
						mlorsp->fw_type);
				break;
			case MENLO_FW_TYPE_DIAG:        /* Menlo Diag */
				lpfc_printf_log (phba, KERN_ERR, LOG_LINK_EVENT,
						"%d:1247 FCoE chip is running diagnostic "
						"firmware. Operational use suspended. %x\n",
						phba->brd_no,
						mlorsp->fw_type);
				break;
			default:
				lpfc_printf_log (phba, KERN_ERR, LOG_LINK_EVENT,
						"%d:1248 FCoE chip is running unknown "
						"firmware x%x.\n",
						phba->brd_no,
						mlorsp->fw_type);
				break;
		}
		if (!mlorsp->fru_data_valid &&
			(mlorsp->fw_type == MENLO_FW_TYPE_OPERATIONAL) &&
			(!mlorsp->maint_status))
			lpfc_printf_log (phba, KERN_ERR, LOG_LINK_EVENT,
					"%d:1249 Invalid FRU data found on adapter."
					"Return adapter to Emulex for repair\n",
					phba->brd_no );

	}
out:
	lpfc_mbuf_free(phba, outp->virt, outp->phys);
	lpfc_mbuf_free(phba, inp->virt, inp->phys);
	lpfc_mbuf_free(phba, bmp->virt, bmp->phys);
	kfree(outp);
	kfree(inp);
	kfree(bmp);
	mempool_free( cmdiocb, phba->iocb_mem_pool);
	return;
}


/*
 * lpfc_check_menlo_cfg
 * Description:
 *    Issue Cmd to MENLO
 *       SLI_CTNS_GID_FT
 *       LI_CTNS_RFT_ID
 */
void
lpfc_check_menlo_cfg(struct lpfc_hba * phba)
{
	struct lpfc_dmabuf *mp, *outmp, *bmp;
	struct ulp_bde64 *bpl;
        menlo_get_cmd_t *cmd = NULL;
	void (*cmpl) (struct lpfc_hba *, struct lpfc_iocbq *,
		      struct lpfc_iocbq *) = NULL;
	uint32_t rsp_size = 0;
	uint32_t cmd_size = sizeof(menlo_get_cmd_t);
	struct lpfc_iocbq * cmdiocbq;
	IOCB_t *iocb = NULL;
	struct lpfc_sli *psli = &phba->sli;
	struct lpfc_sli_ring *pring = &psli->ring[LPFC_ELS_RING];

	/* fill in BDEs for command */
	/* Allocate buffer for command payload */
	lpfc_printf_log (phba, KERN_ERR, LOG_LINK_EVENT,
			"%d:1299 Checking FRU data found on adapter.\n",
			phba->brd_no );
	mp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_ATOMIC);
	if (!mp)
		goto menlo_cmd_exit;

	INIT_LIST_HEAD(&mp->list);
	mp->virt = lpfc_mbuf_alloc(phba, MEM_PRI, &(mp->phys));
	if (!mp->virt)
		goto menlo_cmd_free_mp;

	/* Allocate buffer for Buffer ptr list */
	bmp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_ATOMIC);
	if (!bmp)
		goto menlo_cmd_free_mpvirt;

	INIT_LIST_HEAD(&bmp->list);
	bmp->virt = lpfc_mbuf_alloc(phba, MEM_PRI, &(bmp->phys));
	if (!bmp->virt)
		goto menlo_cmd_free_bmp;


	bpl = (struct ulp_bde64 *) bmp->virt;
	memset(bpl, 0, sizeof(struct ulp_bde64));
	bpl->addrHigh = le32_to_cpu( putPaddrHigh(mp->phys) );
	bpl->addrLow = le32_to_cpu( putPaddrLow(mp->phys) );
	bpl->tus.f.bdeFlags = 0;
	bpl->tus.f.bdeSize = cmd_size;
	bpl->tus.w = le32_to_cpu(bpl->tus.w);

	cmd = (menlo_get_cmd_t *) mp->virt;
	memset(cmd, 0, sizeof (menlo_get_cmd_t));
        cmd->code = MENLO_CMD_GET_INIT;
        cmd->context = cmd_size;
        rsp_size = sizeof (menlo_init_rsp_t);
        cmd->length = rsp_size;
        BE_swap32_buffer ((uint8_t *) cmd, cmd_size);
	cmpl = lpfc_check_menlo_cfg_cmpl;

	bpl++;			/* Skip past cmd request */

	outmp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_ATOMIC);
	if (!outmp)
		 goto menlo_cmd_free_bmp_virt;

	/* Put buffer(s) for ct rsp in bpl */
	outmp->virt = lpfc_mbuf_alloc(phba, MEM_PRI, &(outmp->phys));
	if (!outmp->virt)
		 goto menlo_cmd_free_outmp;

	bpl->addrHigh = le32_to_cpu( putPaddrHigh(outmp->phys) );
	bpl->addrLow = le32_to_cpu( putPaddrLow(outmp->phys) );
	bpl->tus.f.bdeFlags = BUFF_USE_RCV;
	bpl->tus.f.bdeSize = rsp_size;
	bpl->tus.w = le32_to_cpu(bpl->tus.w);

	cmdiocbq = mempool_alloc(phba->iocb_mem_pool, GFP_ATOMIC);
	if (!cmdiocbq)
		goto menlo_cmd_free_outmp_virt;
	memset(cmdiocbq, 0, sizeof (struct lpfc_iocbq));
	iocb = &cmdiocbq->iocb;

	iocb->un.genreq64.bdl.ulpIoTag32 = 0;
	iocb->un.genreq64.bdl.addrHigh = putPaddrHigh(bmp->phys);
	iocb->un.genreq64.bdl.addrLow = putPaddrLow(bmp->phys);
	iocb->un.genreq64.bdl.bdeFlags = BUFF_TYPE_BDL;
	iocb->un.genreq64.bdl.bdeSize = 2 * sizeof (struct ulp_bde64);
	iocb->ulpCommand = CMD_GEN_REQUEST64_CR;
	iocb->un.genreq64.w5.hcsw.Fctl = (SI | LA);
	iocb->un.genreq64.w5.hcsw.Dfctl = 0;
	iocb->un.genreq64.w5.hcsw.Rctl = FC_FCP_CMND;
	iocb->un.genreq64.w5.hcsw.Type = MENLO_TRANSPORT_TYPE; /* 0xfe */
	iocb->un.ulpWord[4] = MENLO_DID; /* 0x0000FC0E */
	iocb->ulpBdeCount = 1;
	iocb->ulpLe = 1;
	iocb->ulpPU = MENLO_PU;
	iocb->ulpClass = CLASS3;
	iocb->ulpOwner = OWN_CHIP;
	cmdiocbq->iocb_flag |= LPFC_IO_LIBDFC;
	cmdiocbq->context1 = (uint8_t *) mp;
	cmdiocbq->context2 = (uint8_t *) outmp;
	cmdiocbq->context3 = (uint8_t *) bmp;
	cmdiocbq->iocb_cmpl = cmpl;

        iocb->ulpTimeout = 65; /* if this IOCB has to wait for the
				* config_link mail box command.
				*/

	if (lpfc_sli_issue_iocb(phba, pring, cmdiocbq, 0) != IOCB_ERROR) {
		return ; /* completion routine will do the frees */
	}

	mempool_free( cmdiocbq, phba->iocb_mem_pool);
	lpfc_printf_log (phba, KERN_ERR, LOG_LINK_EVENT,
			"%d:1297 Checking FRU data Failed.\n",
			phba->brd_no);

menlo_cmd_free_outmp_virt:
	lpfc_mbuf_free(phba,outmp->virt, outmp->phys);
menlo_cmd_free_outmp:
	kfree(outmp);
menlo_cmd_free_bmp_virt:
	lpfc_mbuf_free(phba, bmp->virt, bmp->phys);
menlo_cmd_free_bmp:
	kfree(bmp);
menlo_cmd_free_mpvirt:
	lpfc_mbuf_free(phba, mp->virt, mp->phys);
menlo_cmd_free_mp:
	kfree(mp);
menlo_cmd_exit:
	return ;
}

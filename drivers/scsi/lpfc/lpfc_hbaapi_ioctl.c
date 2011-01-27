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
 * $Id: lpfc_hbaapi_ioctl.c 3194 2008-09-05 15:28:23Z sf_support $
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
#include <linux/blkdev.h>

#include <asm/system.h>
#include <asm/bitops.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <asm/irq.h>


#include <asm/pci.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi.h>

#include "lpfc_version.h"
#include "lpfc_hw.h"
#include "lpfc_sli.h"
#include "lpfc_mem.h"
#include "lpfc_disc.h"
#include "lpfc_scsi.h"
#include "lpfc.h"
#include "lpfc_fcp.h"
#include "lpfc_hw.h"
#include "lpfc_diag.h"
#include "lpfc_ioctl.h"
#include "lpfc_diag.h"
#include "lpfc_crtn.h"
#include "hbaapi.h"
#include "lpfc_hbaapi_ioctl.h"
#include "lpfc_misc.h"

extern unsigned long lpfc_loadtime;

/* Routine Declaration - Local */

int
lpfc_process_ioctl_hbaapi(LPFCCMDINPUT_t *cip)
{
	struct lpfc_hba *phba;
	int rc = -1;
	int do_cp = 0; 
	uint32_t outshift;
	uint32_t total_mem;
	void   *dataout;

	if ((phba = lpfc_get_phba_by_inst(cip->lpfc_brd)) == NULL)
		return EINVAL;

	/* libdfc hbaapi entry */
	lpfc_printf_log(phba,
			KERN_INFO,
			LOG_LIBDFC,
			"%d:1602 libdfc hbaapi entry Data: x%x x%lx x%lx x%x\n",
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

	/* Diagnostic Interface Library Support - hbaapi */
	case LPFC_HBA_ADAPTERATTRIBUTES:
		rc = lpfc_ioctl_hba_adapterattributes(phba, cip, dataout);
		break;

	case LPFC_HBA_PORTATTRIBUTES:
		rc = lpfc_ioctl_hba_portattributes(phba, cip, dataout);
		break;

	case LPFC_HBA_PORTSTATISTICS:
		rc = lpfc_ioctl_hba_portstatistics(phba, cip, dataout);
		break;

	case LPFC_HBA_WWPNPORTATTRIBUTES:
		rc = lpfc_ioctl_hba_wwpnportattributes(phba, cip, dataout);
		break;

	case LPFC_HBA_DISCPORTATTRIBUTES:
		rc = lpfc_ioctl_hba_discportattributes(phba, cip, dataout);
		break;

	case LPFC_HBA_INDEXPORTATTRIBUTES:
		rc = lpfc_ioctl_hba_indexportattributes(phba, cip, dataout);
		break;

	case LPFC_HBA_SETMGMTINFO:
		rc = lpfc_ioctl_hba_setmgmtinfo(phba, cip);
		break;

	case LPFC_HBA_GETMGMTINFO:
		rc = lpfc_ioctl_hba_getmgmtinfo(phba, cip, dataout);
		break;

	case LPFC_HBA_REFRESHINFO:
		rc = lpfc_ioctl_hba_refreshinfo(phba, cip, dataout);
		break;

	case LPFC_HBA_RNID:
		rc = lpfc_ioctl_hba_rnid(phba, cip, dataout);
		break;

	case LPFC_HBA_GETEVENT:
		rc = lpfc_ioctl_hba_getevent(phba, cip, dataout);
		break;
	}

	if (rc != -1) {
	/* dfc_ioctl exit */
		lpfc_printf_log(phba,
			KERN_INFO,
			LOG_LIBDFC,
			"%d:1603 libdfc hbaapi exit Data: x%x x%x x%x\n",
			phba->brd_no,
			rc,
			cip->lpfc_outsz,
			(uint32_t) ((ulong) cip->lpfc_dataout));
	}


	/* Copy data to user space config method */
	if (rc == 0 || do_cp == 1) {
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
lpfc_ioctl_hba_adapterattributes(struct lpfc_hba * phba,
				 LPFCCMDINPUT_t * cip, void *dataout)
{
	HBA_ADAPTERATTRIBUTES *ha;
	struct pci_dev *pdev;
	char *pNodeSymbolicName;
	char fwrev[32];
	uint32_t incr;
	lpfc_vpd_t *vp;
	int rc = 0;
	int i, j = 0;		/* loop index */
	unsigned long iflag;

	/* Allocate mboxq structure */
	pNodeSymbolicName = kmalloc(256, GFP_KERNEL);
	if (!pNodeSymbolicName)
		return(ENOMEM);

	spin_lock_irqsave(phba->host->host_lock, iflag); /* remove */

	pdev = phba->pcidev;
	vp = &phba->vpd;
	ha = (HBA_ADAPTERATTRIBUTES *) dataout;
	memset(dataout, 0, (sizeof (HBA_ADAPTERATTRIBUTES)));
	ha->NumberOfPorts = 1;
	ha->VendorSpecificID = 
	    ((((uint32_t) pdev->device) << 16) | (uint32_t) (pdev->vendor));
	memcpy(ha->DriverVersion, LPFC_DRIVER_VERSION, DFC_DRVID_STR_SZ);
	lpfc_decode_firmware_rev(phba, fwrev, 1);
	memcpy(ha->FirmwareVersion, fwrev, 32);
	memcpy((uint8_t *) & ha->NodeWWN,
	       (uint8_t *) & phba->fc_sparam.nodeName, sizeof (HBA_WWN));
	memcpy(ha->Manufacturer, "Emulex Corporation", 20);
	memcpy(ha->Model, phba->ModelName, 80);
	memcpy(ha->ModelDescription, phba->ModelDesc, 256);
	memcpy(ha->DriverName, LPFC_DRIVER_NAME, 7);
	memcpy(ha->SerialNumber, phba->SerialNumber, 32);
	memcpy(ha->OptionROMVersion, phba->OptionROMVersion, 32);
	/* Convert JEDEC ID to ascii for hardware version */
	incr = vp->rev.biuRev;
	for (i = 0; i < 8; i++) {
		j = (incr & 0xf);
		if (j <= 9)
			ha->HardwareVersion[7 - i] =
			    (char)((uint8_t) 0x30 + (uint8_t) j);
		else
			ha->HardwareVersion[7 - i] =
			    (char)((uint8_t) 0x61 + (uint8_t) (j - 10));
		incr = (incr >> 4);
	}
	ha->HardwareVersion[8] = 0;

	sprintf(pNodeSymbolicName, "Emulex %s FV%s DV%s", ha->Model, ha->FirmwareVersion, LPFC_DRIVER_VERSION);

	memcpy(ha->NodeSymbolicName, pNodeSymbolicName, 256);

	/* Free allocated block of memory */
	if (pNodeSymbolicName)
		kfree(pNodeSymbolicName);

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* remove */

	return (rc);
}
int
lpfc_ioctl_hba_portattributes(struct lpfc_hba * phba,
			      LPFCCMDINPUT_t * cip, void *dataout)
{
	lpfc_vpd_t *vp;
	struct serv_parm *hsp;
	HBA_PORTATTRIBUTES *hp;
	HBA_OSDN *osdn;
	unsigned long iflag;
	uint32_t cnt;
	int rc = 0;

	hp = (HBA_PORTATTRIBUTES *) dataout;
	memset(dataout, 0, (sizeof (HBA_PORTATTRIBUTES)));

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state:  */

	vp = &phba->vpd;
	hsp = (struct serv_parm *) (&phba->fc_sparam);

	memcpy((uint8_t *) & hp->NodeWWN,
	       (uint8_t *) & phba->fc_sparam.nodeName, sizeof (HBA_WWN));
	memcpy((uint8_t *) & hp->PortWWN,
	       (uint8_t *) & phba->fc_sparam.portName, sizeof (HBA_WWN));
	switch(phba->fc_linkspeed) {
		case LA_1GHZ_LINK:
			hp->PortSpeed = HBA_PORTSPEED_1GBIT;
		break;
		case LA_2GHZ_LINK:
			hp->PortSpeed = HBA_PORTSPEED_2GBIT;
		break;
		case LA_4GHZ_LINK:
			hp->PortSpeed = HBA_PORTSPEED_4GBIT;
		break;
		case LA_8GHZ_LINK:
			hp->PortSpeed = HBA_PORTSPEED_8GBIT;
		break;
		default:
			hp->PortSpeed = HBA_PORTSPEED_UNKNOWN;
		break;
	}

	hp->PortSupportedSpeed = 0;
	if (phba->lmt & LMT_10Gb)
		hp->PortSupportedSpeed |= HBA_PORTSPEED_10GBIT;
	if (phba->lmt & LMT_8Gb)
		hp->PortSupportedSpeed |= HBA_PORTSPEED_8GBIT;
	if (phba->lmt & LMT_4Gb)
		hp->PortSupportedSpeed |= HBA_PORTSPEED_4GBIT;
	if (phba->lmt & LMT_2Gb)
		hp->PortSupportedSpeed |= HBA_PORTSPEED_2GBIT;
	if (phba->lmt & LMT_1Gb)
		hp->PortSupportedSpeed |= HBA_PORTSPEED_1GBIT;

	hp->PortFcId = phba->fc_myDID;
	hp->PortType = HBA_PORTTYPE_UNKNOWN;
	if (phba->fc_topology == TOPOLOGY_LOOP) {
		if (phba->fc_flag & FC_PUBLIC_LOOP) {
			hp->PortType = HBA_PORTTYPE_NLPORT;
			memcpy((uint8_t *) & hp->FabricName,
			       (uint8_t *) & phba->fc_fabparam.nodeName,
			       sizeof (HBA_WWN));
		} else {
			hp->PortType = HBA_PORTTYPE_LPORT;
		}
	} else {
		if (phba->fc_flag & FC_FABRIC) {
			hp->PortType = HBA_PORTTYPE_NPORT;
			memcpy((uint8_t *) & hp->FabricName,
			       (uint8_t *) & phba->fc_fabparam.nodeName,
			       sizeof (HBA_WWN));
		} else {
			hp->PortType = HBA_PORTTYPE_PTP;
		}
	}

	if (phba->fc_flag & FC_BYPASSED_MODE) {
		hp->PortState = HBA_PORTSTATE_BYPASSED;
	} else if (phba->fc_flag & FC_OFFLINE_MODE) {
		hp->PortState = HBA_PORTSTATE_DIAGNOSTICS;
	} else {
		switch (phba->hba_state) {
		case LPFC_STATE_UNKNOWN:
		case LPFC_WARM_START:
		case LPFC_INIT_START:
		case LPFC_INIT_MBX_CMDS:
			hp->PortState = HBA_PORTSTATE_UNKNOWN;
			break;
		case LPFC_LINK_DOWN:
		case LPFC_LINK_UP:
		case LPFC_LOCAL_CFG_LINK:
		case LPFC_FLOGI:
		case LPFC_FABRIC_CFG_LINK:
		case LPFC_NS_REG:
		case LPFC_NS_QRY:
		case LPFC_BUILD_DISC_LIST:
		case LPFC_DISC_AUTH:
		case LPFC_CLEAR_LA:
			hp->PortState = HBA_PORTSTATE_LINKDOWN;
			break;
		case LPFC_HBA_READY:
			hp->PortState = HBA_PORTSTATE_ONLINE;
			break;
		case LPFC_HBA_ERROR:
		default:
			hp->PortState = HBA_PORTSTATE_ERROR;
			break;
		}
	}
	cnt = phba->fc_map_cnt + phba->fc_unmap_cnt;
	hp->NumberofDiscoveredPorts = cnt;
	if (hsp->cls1.classValid) {
		hp->PortSupportedClassofService |= 2;	/* bit 1 */
	}
	if (hsp->cls2.classValid) {
		hp->PortSupportedClassofService |= 4;	/* bit 2 */
	}
	if (hsp->cls3.classValid) {
		hp->PortSupportedClassofService |= 8;	/* bit 3 */
	}
	hp->PortMaxFrameSize = (((uint32_t) hsp->cmn.bbRcvSizeMsb) << 8) |
	    (uint32_t) hsp->cmn.bbRcvSizeLsb;

	hp->PortSupportedFc4Types.bits[2] = 0x1;
	hp->PortSupportedFc4Types.bits[7] = 0x1;
	hp->PortActiveFc4Types.bits[2] = 0x1;
	hp->PortActiveFc4Types.bits[7] = 0x1;

	/* OSDeviceName is the device info filled into the HBA_OSDN structure */
	osdn = (HBA_OSDN *) & hp->OSDeviceName[0];
	memcpy(osdn->drvname, LPFC_DRIVER_NAME, 4);
	osdn->instance = phba->brd_no;
	osdn->target = (uint32_t) (-1);
	osdn->lun = (uint32_t) (-1);
	osdn->bus = phba->host->host_no;

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* remove */

	return (rc);
}

int
lpfc_ioctl_hba_portstatistics(struct lpfc_hba * phba,
			      LPFCCMDINPUT_t * cip, void *dataout)
{

	HBA_PORTSTATISTICS *hs;
	LPFC_MBOXQ_t *pmboxq;
	MAILBOX_t *pmb;
	int rc = 0;
	struct lpfc_sli *psli = &phba->sli;

	if ((pmboxq = mempool_alloc(phba->mbox_mem_pool, GFP_ATOMIC)) == 0) {
		return ENOMEM;
	}

	pmb = &pmboxq->mb;

	hs = (HBA_PORTSTATISTICS *) dataout;
	memset(dataout, 0, (sizeof (HBA_PORTSTATISTICS)));
	memset((void *)pmboxq, 0, sizeof (LPFC_MBOXQ_t));
	pmb->mbxCommand = MBX_READ_STATUS;
	pmb->mbxOwner = OWN_HOST;
	pmboxq->context1 = (uint8_t *) 0;

	if ((phba->fc_flag & FC_OFFLINE_MODE) ||
	    (!(psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE))){
		rc = lpfc_sli_issue_mbox(phba, pmboxq, MBX_POLL);
	} else
		rc = lpfc_sli_issue_mbox_wait(phba, pmboxq, phba->fc_ratov * 2);

	if (rc != MBX_SUCCESS) {
		if (pmboxq) {
			if (rc == MBX_TIMEOUT) {
				/*
				 * Let SLI layer to release mboxq if mbox command completed after timeout.
				 */
				pmboxq->mbox_cmpl = lpfc_sli_def_mbox_cmpl;
			} else {
				mempool_free( pmboxq, phba->mbox_mem_pool);
			}
		}
		rc = ENODEV;
		return (rc);
	}


	hs->TxFrames = pmb->un.varRdStatus.xmitFrameCnt;
	hs->RxFrames = pmb->un.varRdStatus.rcvFrameCnt;
	/* Convert KBytes to words */
	hs->TxWords = (pmb->un.varRdStatus.xmitByteCnt * 256);
	hs->RxWords = (pmb->un.varRdStatus.rcvByteCnt * 256);
	memset((void *)pmboxq, 0, sizeof (LPFC_MBOXQ_t));
	pmb->mbxCommand = MBX_READ_LNK_STAT;
	pmb->mbxOwner = OWN_HOST;
	pmboxq->context1 = (uint8_t *) 0;

	if ((phba->fc_flag & FC_OFFLINE_MODE) ||
	    (!(psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE))){
		rc = lpfc_sli_issue_mbox(phba, pmboxq, MBX_POLL);
	} else
		rc = lpfc_sli_issue_mbox_wait(phba, pmboxq, phba->fc_ratov * 2);

	if (rc != MBX_SUCCESS) {
		if (pmboxq) {
			if (rc == MBX_TIMEOUT) {
				/*
				 * Let SLI layer to release mboxq if mbox command completed after timeout.
				 */
				pmboxq->mbox_cmpl = lpfc_sli_def_mbox_cmpl;
			} else {
				mempool_free( pmboxq, phba->mbox_mem_pool);
			}
		}
		rc = ENODEV;
		return (rc);
	}

	hs->LinkFailureCount = pmb->un.varRdLnk.linkFailureCnt;
	hs->LossOfSyncCount = pmb->un.varRdLnk.lossSyncCnt;
	hs->LossOfSignalCount = pmb->un.varRdLnk.lossSignalCnt;
	hs->PrimitiveSeqProtocolErrCount = pmb->un.varRdLnk.primSeqErrCnt;
	hs->InvalidTxWordCount = pmb->un.varRdLnk.invalidXmitWord;
	hs->InvalidCRCCount = pmb->un.varRdLnk.crcCnt;
	hs->ErrorFrames = pmb->un.varRdLnk.crcCnt;

	if (phba->fc_topology == TOPOLOGY_LOOP) {
		hs->LIPCount = (phba->fc_eventTag >> 1);
		hs->NOSCount = -1;
	} else {
		hs->LIPCount = -1;
		hs->NOSCount = (phba->fc_eventTag >> 1);
	}

	hs->DumpedFrames = -1;

	hs->SecondsSinceLastReset = (jiffies - lpfc_loadtime) / HZ;

	/* Free allocated mboxq memory */
	if (pmboxq) {
		mempool_free( pmboxq, phba->mbox_mem_pool);
	}

	return (rc);
}

int
lpfc_ioctl_hba_wwpnportattributes(struct lpfc_hba * phba,
				  LPFCCMDINPUT_t * cip, void *dataout)
{
	HBA_WWN findwwn;
	struct lpfc_nodelist *pndl;
	struct list_head *pos, *listp;
	struct list_head *node_list[2];
	HBA_PORTATTRIBUTES *hp;
	lpfc_vpd_t *vp;
	MAILBOX_t *pmbox;
	int rc = 0;
	unsigned long iflag;
	int i;

	/* Allocate mboxq structure */
	pmbox = kmalloc(sizeof (MAILBOX_t), GFP_KERNEL);

	if (!pmbox)
		return(ENOMEM);

	hp = (HBA_PORTATTRIBUTES *) dataout;
	vp = &phba->vpd;
	memset(dataout, 0, (sizeof (HBA_PORTATTRIBUTES)));

	if (copy_from_user((uint8_t *) & findwwn, (uint8_t *) cip->lpfc_arg1,
			   (ulong) (sizeof (HBA_WWN)))) {
		rc = EIO;
		/* Free allocated mbox memory */
		kfree((void *)pmbox);
		return (rc);
	}

	/* First Mapped ports, then unMapped ports */
	node_list[0] = &phba->fc_nlpmap_list;
	node_list[1] = &phba->fc_nlpunmap_list;
	for (i = 0; i < 2; i++) {
		listp = node_list[i];
		if (list_empty(listp)) 
			continue;

		spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state: fc_nlpmap_list, fc_nlpunmap_list */

		list_for_each(pos, listp) {
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);	
			if (lpfc_geportname(&pndl->nlp_portname, 
						(struct lpfc_name *) &findwwn) == 2) {
				spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state: fc_nlpmap_list, fc_nlpunmap_list */

				/* handle found port */
				rc = lpfc_ioctl_found_port(phba, pndl, dataout, pmbox, hp);

				/* Free allocated mbox memory */
				kfree((void *)pmbox);
				return (rc);
			}
		}

		spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state: fc_nlpmap_list, fc_nlpunmap_list */
	}


	/* Free allocated mbox memory */
	kfree((void *)pmbox);

	rc = ERANGE;
	return (rc);
}

int
lpfc_ioctl_hba_discportattributes(struct lpfc_hba * phba,
				  LPFCCMDINPUT_t * cip, void *dataout)
{
	HBA_PORTATTRIBUTES *hp;
	struct lpfc_nodelist *pndl;
	struct list_head *pos, *listp;
	struct list_head *node_list[2];
	lpfc_vpd_t *vp;
	struct lpfc_sli *psli;
	uint32_t refresh, offset, cnt;
	MAILBOX_t *pmbox;
	int rc = 0;
	int i;
	unsigned long iflag;

	/* Allocate mboxq structure */
	pmbox = kmalloc(sizeof (MAILBOX_t), GFP_KERNEL);
	if (!pmbox)
		return (ENOMEM);

	psli = &phba->sli;
	hp = (HBA_PORTATTRIBUTES *) dataout;
	vp = &phba->vpd;
	memset(dataout, 0, (sizeof (HBA_PORTATTRIBUTES)));
	offset = (ulong) cip->lpfc_arg2;
	refresh = (ulong) cip->lpfc_arg3;

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state: fc_nlpmap_list, fc_nlpunmap_list */

	if (refresh != phba->nport_event_cnt) {
		/* This is an error, need refresh, just return zero'ed out
		 * portattr and FcID as -1.
		 */
		hp->PortFcId = 0xffffffff;

		spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state: nport_event_cnt, fc_nlpmap_list, fc_nlpunmap_list */

		/* Free allocated mbox memory */
		kfree((void *)pmbox);
		return (rc);
	}
	cnt = 0;

	/* First Mapped ports, then unMapped ports */
	node_list[0] = &phba->fc_nlpmap_list;
	node_list[1] = &phba->fc_nlpunmap_list;
	for (i = 0; i < 2; i++) {
		listp = node_list[i];
		if (list_empty(listp)) 
			continue;
		list_for_each(pos, listp) {
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);	
			if (cnt == offset) {
				spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state: nport_event_cnt, fc_nlpmap_list, fc_nlpunmap_list */

				/* handle found port */
				rc = lpfc_ioctl_found_port(phba, pndl, dataout, pmbox, hp);

				/* Free allocated mbox memory */
				kfree((void *)pmbox);
				return (rc);
			}
		cnt++;
		}
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state: nport_event_cnt, fc_nlpmap_list, fc_nlpunmap_list */

	rc = ERANGE;

	/* Free allocated mbox memory */
	kfree((void *)pmbox);

	return (rc);
}

int
lpfc_ioctl_hba_indexportattributes(struct lpfc_hba * phba,
				   LPFCCMDINPUT_t * cip, void *dataout)
{
	HBA_PORTATTRIBUTES *hp;
	lpfc_vpd_t *vp;
	struct lpfc_nodelist *pndl;
	struct list_head *pos;
	uint32_t refresh, offset, cnt;
	MAILBOX_t *pmbox;
	int rc = 0;
	unsigned long iflag;

	/* Allocate mboxq structure */
	pmbox = kmalloc(sizeof (MAILBOX_t), GFP_KERNEL);
	if (!pmbox)
		return (ENOMEM);

	vp = &phba->vpd;
	hp = (HBA_PORTATTRIBUTES *) dataout;
	memset(dataout, 0, (sizeof (HBA_PORTATTRIBUTES)));
	offset = (ulong) cip->lpfc_arg2;
	refresh = (ulong) cip->lpfc_arg3;

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state: nport_event_cnt, fc_nlpmap_list */

	if (refresh != phba->nport_event_cnt) {
		/* This is an error, need refresh, just return zero'ed out
		 * portattr and FcID as -1.
		 */
		hp->PortFcId = 0xffffffff;

		spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state: nport_event_cnt, fc_nlpmap_list */

		/* Free allocated mbox memory */
		kfree((void *)pmbox);

		return (rc);
	}
	cnt = 0;
	/* Mapped NPorts only */
	list_for_each(pos, &phba->fc_nlpmap_list) {
		pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
		if (cnt == offset) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state: nport_event_cnt, fc_nlpmap_list */

			/* handle found port */
			rc = lpfc_ioctl_found_port(phba, pndl, dataout, pmbox, hp);

			/* Free allocated mbox memory */
			kfree((void *)pmbox);
			return (rc);
		}
		cnt++;
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state: nport_event_cnt, fc_nlpmap_list */

	/* Free allocated mbox memory */
	kfree((void *)pmbox);

	rc = ERANGE;
	return (rc);
}

int
lpfc_ioctl_hba_setmgmtinfo(struct lpfc_hba * phba,
			   LPFCCMDINPUT_t * cip)
{

	HBA_MGMTINFO *mgmtinfo;
	int rc = 0;
	unsigned long iflag;

	mgmtinfo = kmalloc(4096, GFP_KERNEL);
	if (!mgmtinfo)
		return(ENOMEM);

	if (copy_from_user
	    ((uint8_t *) mgmtinfo, (uint8_t *) cip->lpfc_arg1,
	     sizeof (HBA_MGMTINFO))) {
		rc = EIO;
		kfree(mgmtinfo);
		return (rc);
	}

	spin_lock_irqsave(phba->host->host_lock, iflag);  /* HBA state: ipVersion,  UDPport, ipAddr */

	/* Can ONLY set UDP port and IP Address */

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state: ipVersion,  UDPport, ipAddr */

	kfree(mgmtinfo);
	return (rc);
}

int
lpfc_ioctl_hba_getmgmtinfo(struct lpfc_hba * phba,
			   LPFCCMDINPUT_t * cip, void *dataout)
{

	HBA_MGMTINFO *mgmtinfo;
	int rc = 0;

	mgmtinfo = (HBA_MGMTINFO *) dataout;
	memset((void *)mgmtinfo, 0, sizeof (HBA_MGMTINFO));
	memcpy((uint8_t *) & mgmtinfo->wwn, (uint8_t *) & phba->fc_nodename, 8);
	mgmtinfo->unittype = RNID_HBA;
	mgmtinfo->PortId = phba->fc_myDID;
	mgmtinfo->NumberOfAttachedNodes = 0;
	mgmtinfo->TopologyDiscoveryFlags = 0;

	return (rc);
}

int
lpfc_ioctl_hba_refreshinfo(struct lpfc_hba * phba,
			   LPFCCMDINPUT_t * cip, void *dataout)
{
	uint32_t *lptr;
	int rc = 0;

	lptr = (uint32_t *) dataout;
	*lptr = phba->nport_event_cnt;

	return (rc);
}

int
lpfc_ioctl_hba_rnid(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{

	HBA_WWN idn;
	struct lpfc_sli *psli;
	struct lpfc_iocbq *cmdiocbq = 0;
	struct lpfc_iocbq *rspiocbq = 0;
	RNID *prsp;
	uint32_t *pcmd;
	uint32_t *psta;
	IOCB_t *rsp;
	struct lpfc_sli_ring *pring;
	void *context2;
	int i0;
	unsigned long iflag;
	int rtnbfrsiz;
	struct lpfc_nodelist *pndl;
	int rc = 0;

	psli = &phba->sli;
	pring = &psli->ring[LPFC_ELS_RING];

	if (copy_from_user((uint8_t *) & idn, (uint8_t *) cip->lpfc_arg1,
			   (ulong) (sizeof (HBA_WWN)))) {
		rc = EIO;
		return (rc);
	}

	spin_lock_irqsave(phba->host->host_lock, iflag);

	if (cip->lpfc_flag == NODE_WWN) {
		pndl = lpfc_findnode_wwnn(phba,
					NLP_SEARCH_MAPPED | NLP_SEARCH_UNMAPPED,
					(struct lpfc_name *) &idn);
	} else {
		pndl = lpfc_findnode_wwpn(phba,
					NLP_SEARCH_MAPPED | NLP_SEARCH_UNMAPPED,
					(struct lpfc_name *) &idn);
	}

	if (!pndl) {
		rc = ENODEV;
		goto sndrndqwt;
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	for (i0 = 0;
	     i0 < 10 && (pndl->nlp_flag & NLP_ELS_SND_MASK) == NLP_RNID_SND;
	     i0++) {
		msleep(1000);
	}
	spin_lock_irqsave(phba->host->host_lock, iflag);

	if (i0 == 10) {
		rc = EBUSY;
		pndl->nlp_flag &= ~NLP_RNID_SND;
		goto sndrndqwt;
	}

	cmdiocbq = lpfc_prep_els_iocb(phba, 1, (2 * sizeof(uint32_t)), 0, pndl,
						pndl->nlp_DID, ELS_CMD_RNID);
	if (!cmdiocbq) {
		rc = ENOMEM;
		goto sndrndqwt;
	}

	/*
	 *  Context2 is used by prep/free to locate cmd and rsp buffers,
	 *  but context2 is also used by iocb_wait to hold a rspiocb ptr.
	 *  The rsp iocbq can be returned from the completion routine for
	 *  iocb_wait, so save the prep/free value locally . It will be
	 *  restored after returning from iocb_wait.
	 */
	context2 = cmdiocbq->context2;

	if ((rspiocbq = mempool_alloc(phba->iocb_mem_pool, GFP_ATOMIC)) == 0) {
		rc = ENOMEM;
		goto sndrndqwt;
	}

	memset((void *)rspiocbq, 0, sizeof (struct lpfc_iocbq));
	rsp = &(rspiocbq->iocb);

	pcmd = (uint32_t *) (((struct lpfc_dmabuf *) cmdiocbq->context2)->virt);
	*pcmd++ = ELS_CMD_RNID;

	memset((void *) pcmd, 0, sizeof (RNID));
	((RNID *) pcmd)->Format = 0;
	((RNID *) pcmd)->Format = RNID_TOPOLOGY_DISC;
	cmdiocbq->context1 = (uint8_t *) 0;
	cmdiocbq->context2 = (uint8_t *) 0;
	cmdiocbq->iocb_flag |= LPFC_IO_LIBDFC;

	pndl->nlp_flag |= NLP_RNID_SND;
	cmdiocbq->iocb.ulpTimeout = (phba->fc_ratov * 2) + 3 ;

	rc = lpfc_sli_issue_iocb_wait(phba, pring, cmdiocbq, rspiocbq,
				(phba->fc_ratov * 2) + LPFC_DRVR_TIMEOUT);
	pndl->nlp_flag &= ~NLP_RNID_SND;
	cmdiocbq->context2 = context2;

	if (rc == IOCB_TIMEDOUT) {
		mempool_free(rspiocbq, phba->iocb_mem_pool);
		cmdiocbq->context1 = NULL;
		cmdiocbq->iocb_cmpl = lpfc_ioctl_timeout_iocb_cmpl;
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return EIO;
	}

	if (rc != IOCB_SUCCESS) {
		rc = EIO;
		goto sndrndqwt;
	}

	if (rsp->ulpStatus == IOSTAT_SUCCESS) {
		struct lpfc_dmabuf *buf_ptr1, *buf_ptr;
		buf_ptr1 = (struct lpfc_dmabuf *)(cmdiocbq->context2);
                buf_ptr = list_entry(buf_ptr1->list.next, struct lpfc_dmabuf,
                                                                        list);
                psta = (uint32_t*)buf_ptr->virt;
		prsp = (RNID *) (psta + 1);	/*  then rnid response data */
		rtnbfrsiz = prsp->CommonLen + prsp->SpecificLen +
							sizeof (uint32_t);
		memcpy((uint8_t *) dataout, (uint8_t *) psta, rtnbfrsiz);

		if (rtnbfrsiz > cip->lpfc_outsz)
			rtnbfrsiz = cip->lpfc_outsz;
		if (copy_to_user
		    ((uint8_t *) cip->lpfc_arg2, (uint8_t *) & rtnbfrsiz,
		     sizeof (int)))
			rc = EIO;
	} else if (rsp->ulpStatus == IOSTAT_LS_RJT)  {
		uint8_t ls_rjt[8];
		uint32_t *ls_rjtrsp;

		ls_rjtrsp = (uint32_t*)(ls_rjt + 4);

		/* construct the LS_RJT payload */
		ls_rjt[0] = 0x01;
		ls_rjt[1] = 0x00;
		ls_rjt[2] = 0x00;
		ls_rjt[3] = 0x00;

		*ls_rjtrsp = be32_to_cpu(rspiocbq->iocb.un.ulpWord[4]);
		rtnbfrsiz = 8;
		memcpy((uint8_t *) dataout, (uint8_t *) ls_rjt, rtnbfrsiz);
		if (copy_to_user
		    ((uint8_t *) cip->lpfc_arg2, (uint8_t *) & rtnbfrsiz,
		     sizeof (int)))
			rc = EIO;
	} else {
		rc = EACCES;
	}

sndrndqwt:
	if (cmdiocbq)
		lpfc_els_free_iocb(phba, cmdiocbq);
	if (rspiocbq)
		mempool_free(rspiocbq, phba->iocb_mem_pool);

	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return (rc);
}

int
lpfc_ioctl_hba_getevent(struct lpfc_hba * phba,
			LPFCCMDINPUT_t * cip, void *dataout)
{

	uint32_t outsize, size = (ulong)cip->lpfc_arg1;
	struct lpfc_hba_event *rec;
	struct lpfc_hba_event *recout = (struct lpfc_hba_event *) dataout;
	int j, rc = 0;
	unsigned long iflag;

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state: hba_event_put,  hba_event_get*/
	for (j = 0; j < MAX_HBAEVT; j++) {
		if ((j == (int)size) ||
		    (phba->hba_event_get == phba->hba_event_put))
			goto getevent_lock_exit;
		rec = &phba->hbaevt[phba->hba_event_get];
		memcpy((uint8_t *) recout, (uint8_t *) rec,
		       sizeof (struct lpfc_hba_event));
		recout++;
		phba->hba_event_get++;
		if (phba->hba_event_get >= MAX_HBAEVT) {
			phba->hba_event_get = 0;
		}
	}

getevent_lock_exit:
	outsize = j;
	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state: hba_event_put,  hba_event_get*/

	/* copy back size of response */
	if (copy_to_user((uint8_t *) cip->lpfc_arg2, (uint8_t *) & outsize,
			 sizeof (uint32_t))) {
		rc = EIO;
		return (rc);
	}

	/* copy back number of missed records */
	if (copy_to_user
	    ((uint8_t *) cip->lpfc_arg3, (uint8_t *) & phba->hba_event_missed,
	     sizeof (uint32_t))) {
		rc = EIO;
		return (rc);
	}

	phba->hba_event_missed = 0;

	cip->lpfc_outsz = (uint32_t) (outsize * sizeof (HBA_EVENTINFO));

	return (rc);
}


int
lpfc_ioctl_found_port(struct lpfc_hba * phba,
		      struct lpfc_nodelist * pndl,
		      void *dataout,
		      MAILBOX_t * pmbox, HBA_PORTATTRIBUTES * hp)
{
	struct lpfc_sli *psli = &phba->sli;
	struct serv_parm *hsp;
	struct lpfc_dmabuf *mp;
	HBA_OSDN *osdn;
	LPFC_MBOXQ_t *mboxq;
	int mbxstatus;
	int rc = 0;

	/* Check if its the local port */
	if (phba->fc_myDID == pndl->nlp_DID) {
		/* handle localport */
		rc = lpfc_ioctl_hba_portattributes(phba, NULL, dataout);
		return rc;
	}

	memset((void *)pmbox, 0, sizeof (MAILBOX_t));
	pmbox->un.varRdRPI.reqRpi = (volatile uint16_t)pndl->nlp_rpi;
	pmbox->mbxCommand = MBX_READ_RPI64;
	pmbox->mbxOwner = OWN_HOST;

	if ((mp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_KERNEL)) == 0)
		return ENOMEM;

	if ((mp->virt = lpfc_mbuf_alloc(phba, 0, &(mp->phys))) == 0) {
		kfree(mp);
		return ENOMEM;
	}

	INIT_LIST_HEAD(&mp->list);

	if ((mboxq = mempool_alloc(phba->mbox_mem_pool, GFP_ATOMIC)) == 0) {
		lpfc_mbuf_free(phba, mp->virt, mp->phys);
		kfree(mp);
		return ENOMEM;
	}

	hsp = (struct serv_parm *) mp->virt;
	if (psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE) {
		pmbox->un.varRdRPI.un.sp64.addrHigh = putPaddrHigh(mp->phys);
		pmbox->un.varRdRPI.un.sp64.addrLow = putPaddrLow(mp->phys);
		pmbox->un.varRdRPI.un.sp64.tus.f.bdeSize =
			sizeof (struct serv_parm);
	} else {
		pmbox->un.varRdRPI.un.sp.bdeAddress = putPaddrLow(mp->phys);
		pmbox->un.varRdRPI.un.sp.bdeSize = sizeof (struct serv_parm);
	}

	memset((void *)mboxq, 0, sizeof (LPFC_MBOXQ_t));
	mboxq->mb.mbxCommand = pmbox->mbxCommand;
	mboxq->mb.mbxOwner = pmbox->mbxOwner;
	mboxq->mb.un = pmbox->un;
	mboxq->mb.us = pmbox->us;
	mboxq->context1 = (uint8_t *) 0;

	if ((phba->fc_flag & FC_OFFLINE_MODE) ||
	    (!(psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE))){
		mbxstatus = lpfc_sli_issue_mbox(phba, mboxq, MBX_POLL);
	} else
		mbxstatus =
		    lpfc_sli_issue_mbox_wait(phba, mboxq, phba->fc_ratov * 2);

	if (mbxstatus != MBX_SUCCESS) {
		if (mbxstatus == MBX_TIMEOUT) {
			/*
			 * Let SLI layer to release mboxq if mbox command completed after timeout.
			 */
			mboxq->mbox_cmpl = lpfc_sli_def_mbox_cmpl;
		} else {
			mempool_free( mboxq, phba->mbox_mem_pool);
			lpfc_mbuf_free(phba, mp->virt, mp->phys);
			kfree(mp);
		}
		return ENODEV;
	}

	pmbox->mbxCommand = mboxq->mb.mbxCommand;
	pmbox->mbxOwner = mboxq->mb.mbxOwner;
	pmbox->un = mboxq->mb.un;
	pmbox->us = mboxq->mb.us;

	if (hsp->cls1.classValid) {
		hp->PortSupportedClassofService |= 2;	/* bit 1 */
	}
	if (hsp->cls2.classValid) {
		hp->PortSupportedClassofService |= 4;	/* bit 2 */
	}
	if (hsp->cls3.classValid) {
		hp->PortSupportedClassofService |= 8;	/* bit 3 */
	}

	hp->PortMaxFrameSize = (((uint32_t) hsp->cmn.bbRcvSizeMsb) << 8) |
	    (uint32_t) hsp->cmn.bbRcvSizeLsb;

	lpfc_mbuf_free(phba, mp->virt, mp->phys);
	kfree(mp);
	mempool_free( mboxq, phba->mbox_mem_pool);

	memcpy((uint8_t *) & hp->NodeWWN, (uint8_t *) & pndl->nlp_nodename,
	       sizeof (HBA_WWN));
	memcpy((uint8_t *) & hp->PortWWN, (uint8_t *) & pndl->nlp_portname,
	       sizeof (HBA_WWN));
	hp->PortSpeed = 0;
	/* We only know the speed if the device is on the same loop as us */
	if (((phba->fc_myDID & 0xffff00) == (pndl->nlp_DID & 0xffff00)) &&
	    (phba->fc_topology == TOPOLOGY_LOOP)) {
		if (phba->fc_linkspeed == LA_2GHZ_LINK)
			hp->PortSpeed = HBA_PORTSPEED_2GBIT;
		else
			hp->PortSpeed = HBA_PORTSPEED_1GBIT;
	}

	hp->PortFcId = pndl->nlp_DID;
	if ((phba->fc_flag & FC_FABRIC) &&
	    ((phba->fc_myDID & 0xff0000) == (pndl->nlp_DID & 0xff0000))) {
		/* If remote node is in the same domain we are in */
		memcpy((uint8_t *) & hp->FabricName,
		       (uint8_t *) & phba->fc_fabparam.nodeName,
		       sizeof (HBA_WWN));
	}
	hp->PortState = HBA_PORTSTATE_ONLINE;
	if (pndl->nlp_type & NLP_FCP_TARGET) {
		hp->PortActiveFc4Types.bits[2] = 0x1;
	}

	hp->PortActiveFc4Types.bits[7] = 0x1;

	hp->PortType = HBA_PORTTYPE_UNKNOWN;
	if (phba->fc_topology == TOPOLOGY_LOOP) {
		if (phba->fc_flag & FC_PUBLIC_LOOP) {
			/* Check if Fabric port */
			if (lpfc_geportname(&pndl->nlp_nodename,
					    (struct lpfc_name *) & (phba->fc_fabparam.
							     nodeName)) == 2) {
				hp->PortType = HBA_PORTTYPE_FLPORT;
			} else {
				/* Based on DID */
				if ((pndl->nlp_DID & 0xff) == 0) {
					hp->PortType = HBA_PORTTYPE_NPORT;
				} else {
					if ((pndl->nlp_DID & 0xff0000) !=
					    0xff0000) {
						hp->PortType =
						    HBA_PORTTYPE_NLPORT;
					}
				}
			}
		} else {
			hp->PortType = HBA_PORTTYPE_LPORT;
		}
	} else {
		if (phba->fc_flag & FC_FABRIC) {
			/* Check if Fabric port */
			if (lpfc_geportname(&pndl->nlp_nodename,
					    (struct lpfc_name *) & (phba->fc_fabparam.
							     nodeName)) == 2) {
				hp->PortType = HBA_PORTTYPE_FPORT;
			} else {
				/* Based on DID */
				if ((pndl->nlp_DID & 0xff) == 0) {
					hp->PortType = HBA_PORTTYPE_NPORT;
				} else {
					if ((pndl->nlp_DID & 0xff0000) !=
					    0xff0000) {
						hp->PortType =
						    HBA_PORTTYPE_NLPORT;
					}
				}
			}
		} else {
			hp->PortType = HBA_PORTTYPE_PTP;
		}
	}

	/* for mapped devices OSDeviceName is device info filled into HBA_OSDN 
	 * structure */
	if ((pndl->nlp_flag & NLP_LIST_MASK) == NLP_MAPPED_LIST) {
		osdn = (HBA_OSDN *) & hp->OSDeviceName[0];
		memcpy(osdn->drvname, LPFC_DRIVER_NAME, 4);
		osdn->instance = phba->brd_no;
		osdn->target = pndl->nlp_sid;
		osdn->lun = (uint32_t) (-1);
	}


	return rc;
}

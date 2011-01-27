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
 * $Id: lpfc_util_ioctl.c 2886 2006-03-07 21:56:50Z sf_support $
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
#include <scsi/scsi.h>
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
#include "hbaapi.h"
#include "lpfc_util_ioctl.h"
#define LPFC_ICFG
#include "lpfc_misc.h"
#include "lpfc_version.h"
#include "lpfcdfc_version.h"
#include "lpfc_compat.h"

extern int lpfc_scsi_req_tmo;

#define LPFC_MAX_EVENT 4 /* Default events we can queue before dropping them */
/* the icfgparam structure - internal use only */


typedef struct tagiCfgParam {
	char *a_string;
	uint32_t a_low;
	uint32_t a_hi;
	uint32_t a_default;
	uint32_t a_current;
	uint16_t a_flag;
	uint16_t a_changestate;
	char *a_help;
} iCfgParam;

#define LPFC_TOTAL_NUM_OF_CFG_PARAM 15

/* The order of the icfgparam[] entries must match that of LPFC_CORE_CFG defs */
iCfgParam lpfc_iCfgParam[LPFC_TOTAL_NUM_OF_CFG_PARAM] = {
	/* The driver now exports the cfg name. So it needs to be consistent
	   with lpfc.conf param name */

	/* general driver parameters */
	{"log_verbose",
	 0, 0xffff, FALSE, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_DYNAMIC,
	 "Verbose logging bit-mask"},

	{"lun_queue_depth",
	 1, LPFC_MAX_LUN_Q_DEPTH, LPFC_DFT_LUN_Q_DEPTH, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "Max number of FCP commands we can queue to a specific LUN"},

	{"scan_down",
	 0, 1, 1, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "Start scanning for devices from highest ALPA to lowest"},

	{"nodev_tmo",
	 0, LPFC_MAX_NODEV_TIMEOUT, LPFC_DFT_NODEV_TIMEOUT, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_DYNAMIC,
	 "Seconds driver will hold I/O waiting for a device to come back"},

	{"topology",
	 0, 6, LPFC_DFT_TOPOLOGY, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "Select Fibre Channel topology"},

	{"link_speed",
	 0, 4, 0, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "Select link speed"},

	/* Start of product specific (lpfc) config params */

	{"fcp_class",
	 2, 3, LPFC_DFT_FC_CLASS, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "Select Fibre Channel class of service for FCP sequences"},

	{"use_adisc",
	 0, 1, FALSE, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_DYNAMIC,
	 "Use ADISC on rediscovery to authenticate FCP devices"},

	/* Fibre Channel specific parameters */
	{"ack0",
	 0, 1, FALSE, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "Enable ACK0 support"},

	{"fcp_bind_method",
	 1, 4, 2, 2,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "Select the bind method to be used."},

	{"cr_delay",
	 0, 63, 0, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "A count of milliseconds after which an interrupt response is "
	 "generated"},

	{"cr_count",
	 1, 255, 1, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "A count of I/O completions after which an interrupt response is "
	 "generated"},

	{"fdmi_on",
	 0, 2, FALSE, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "Enable FDMI support"},

	{"discovery_threads",
	 1, LPFC_MAX_DISC_THREADS, LPFC_DFT_DISC_THREADS, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "Maximum number of ELS commands during discovery"},

	{"max_luns",
	 1, 32768, 256, 0,
	 (ushort) (CFG_EXPORT),
	 (ushort) CFG_RESTART,
	 "Maximum number of LUNs support per SCSI target"},
};

int
lpfc_ioctl_initboard(struct lpfc_hba *phba, LPFCCMDINPUT_t *cip, void *dataout)
{
	struct pci_dev *pdev;
	struct dfc_info * di;
	char lpfc_fwrevision[32];
	unsigned long iflag;

	pdev = phba->pcidev;

	/* must have the pci struct */
	if (!pdev)
		return 1;

	spin_lock_irqsave(phba->host->host_lock, iflag);

	di = (struct dfc_info *) dataout;

	di->a_onmask = (ONDI_MBOX | ONDI_RMEM | ONDI_RPCI | ONDI_RCTLREG |
			ONDI_IOINFO | ONDI_LNKINFO | ONDI_NODEINFO |
			ONDI_CFGPARAM | ONDI_CT | ONDI_HBAAPI | ONDI_SLI2);
	di->a_offmask = (OFFDI_MBOX | OFFDI_RMEM | OFFDI_WMEM | OFFDI_RPCI |
			 OFFDI_WPCI | OFFDI_RCTLREG | OFFDI_WCTLREG);

	if (phba->fc_flag & FC_OFFLINE_MODE)
		di->a_offmask |= OFFDI_OFFLINE;

	/* set endianness of driver diagnotic interface */
#if __BIG_ENDIAN
	di->a_onmask |= ONDI_BIG_ENDIAN;
#else	/*  __LITTLE_ENDIAN */
	di->a_onmask |= ONDI_LTL_ENDIAN;
#endif

	di->a_pci = ((((uint32_t) pdev->device) << 16) |
		     (uint32_t) (pdev->vendor));
	di->a_ddi = phba->brd_no;

	if (pdev->bus)
		di->a_busid = (uint32_t) (pdev->bus->number);
	else
		di->a_busid = 0;
	di->a_devid = (uint32_t) (pdev->devfn);

	memcpy(di->a_drvrid, LPFC_DRIVER_VERSION, 16);
	lpfc_decode_firmware_rev(phba, lpfc_fwrevision, 1);
	memcpy(di->a_fwname, lpfc_fwrevision, 32);
	memcpy(di->a_wwpn, &phba->fc_portname, 8);

	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	cip->lpfc_outsz = sizeof (struct dfc_info);

	return 0;
}

/* Routine Declaration - Local */

int
lpfc_process_ioctl_util(LPFCCMDINPUT_t *cip)
{
	struct lpfc_hba *phba = NULL;
	int rc = -1;
	int do_cp = 0;
	uint32_t outshift;
	uint32_t total_mem;
	void   *dataout;

	/* Some ioctls are per module and do not need phba  */
	if (cip->lpfc_cmd != LPFC_GET_DFC_REV)
		if ((phba = lpfc_get_phba_by_inst(cip->lpfc_brd)) == NULL)
			return EINVAL;

	/* libdfc util entry */
	if (phba)
		lpfc_printf_log(phba,
			KERN_INFO,
			LOG_LIBDFC,
			"%d:1606 libdfc util entry Data: x%x x%lx x%lx x%x\n",
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

	/* Diagnostic Interface Library Support - util */
	case LPFC_WRITE_PCI:
		rc = lpfc_ioctl_write_pci(phba, cip);
		break;

	case LPFC_READ_PCI:
		rc = lpfc_ioctl_read_pci(phba, cip, dataout);
		break;

	case LPFC_WRITE_MEM:
		rc = lpfc_ioctl_write_mem(phba, cip);
		break;

	case LPFC_READ_MEM:
		rc = lpfc_ioctl_read_mem(phba, cip, dataout);
		break;

	case LPFC_WRITE_CTLREG:
		rc = lpfc_ioctl_write_ctlreg(phba, cip);
		break;

	case LPFC_READ_CTLREG:
		rc = lpfc_ioctl_read_ctlreg(phba, cip, dataout);
		break;

	case LPFC_GET_DFC_REV:
		((DfcRevInfo *) dataout)->a_Major = DFC_MAJOR_REV;
		((DfcRevInfo *) dataout)->a_Minor = DFC_MINOR_REV;
		cip->lpfc_outsz = sizeof (DfcRevInfo);
		printk(KERN_INFO
		       "lpfcdfc: %d:1608 libdfc get rev Data: x%x x%x\n",
		       cip->lpfc_brd,
		       DFC_MAJOR_REV,
		       DFC_MINOR_REV);
		rc = 0;
		break;

	case LPFC_INITBRDS:
		rc = lpfc_ioctl_initboard(phba, cip, dataout);
		break;

	case LPFC_SETDIAG:
		rc = lpfc_ioctl_setdiag(phba, cip, dataout);
		break;

	case LPFC_HBA_SEND_SCSI:
	case LPFC_HBA_SEND_FCP:
		rc = lpfc_ioctl_send_scsi_fcp(phba, cip);
		break;

	case LPFC_SEND_ELS:
		rc = lpfc_ioctl_send_els(phba, cip, dataout);
		break;

	case LPFC_HBA_SEND_MGMT_RSP:
		rc = lpfc_ioctl_send_mgmt_rsp(phba, cip);
		break;

	case LPFC_HBA_SEND_MGMT_CMD:
	case LPFC_CT:
		rc = lpfc_ioctl_send_mgmt_cmd(phba, cip, dataout);
		break;

	case LPFC_MBOX:
		rc = lpfc_ioctl_mbox(phba, cip, dataout);
		break;

	case LPFC_LINKINFO:
		rc = lpfc_ioctl_linkinfo(phba, cip, dataout);
		break;

	case LPFC_IOINFO:
		rc = lpfc_ioctl_ioinfo(phba, cip, dataout);
		break;

	case LPFC_NODEINFO:
		rc = lpfc_ioctl_nodeinfo(phba, cip, dataout, total_mem);
		break;

	case LPFC_GETCFG:
		rc = lpfc_ioctl_getcfg(phba, cip, dataout);
		break;

	case LPFC_SETCFG:
		rc = lpfc_ioctl_setcfg(phba, cip);
		break;

	case LPFC_HBA_GET_EVENT:
		rc = lpfc_ioctl_hba_get_event(phba, cip, dataout, total_mem);
		break;

	case LPFC_HBA_SET_EVENT:
		rc = lpfc_ioctl_hba_set_event(phba, cip);
		break;

	case LPFC_LIST_BIND:
		rc = lpfc_ioctl_list_bind(phba, cip, dataout, &do_cp);
		break;

	case LPFC_GET_VPD:
		rc = lpfc_ioctl_get_vpd(phba, cip, dataout, &do_cp);
		break;

	case LPFC_GET_DUMPREGION:
		rc = lpfc_ioctl_get_dumpregion(phba, cip, dataout, &do_cp);
		break;

	case LPFC_GET_LPFCDFC_INFO:
		rc = lpfc_ioctl_get_lpfcdfc_info(phba, cip, dataout);
		break;

	case LPFC_LOOPBACK_MODE:
		rc = lpfc_ioctl_loopback_mode(phba, cip, dataout);
		break;

	case LPFC_LOOPBACK_TEST:
		rc = lpfc_ioctl_loopback_test(phba, cip, dataout);
		break;
	}

	if ((rc != -1) && phba) {
		/* dfc_ioctl exit */
		lpfc_printf_log(phba,
			KERN_INFO,
			LOG_LIBDFC,
			"%d:1607 libdfc util exit Data: x%x x%x x%x\n",
			cip->lpfc_brd,
			rc,
			cip->lpfc_outsz,
			(uint32_t) ((ulong) cip->lpfc_dataout));
	}

	if (rc == 0) {

	/* Copy data to user space config method */
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
lpfc_ioctl_write_pci(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip)
{
	uint32_t offset, cnt;
	int i, rc = 0;
	unsigned long iflag;
	uint32_t *buffer;

	offset = (ulong) cip->lpfc_arg1;
	cnt = (ulong) cip->lpfc_arg2;

	if ((cnt + offset) > 256) {
		rc = ERANGE;
		return (rc);
	}

	buffer = kmalloc(4096, GFP_KERNEL);
	if (!buffer) {
		return (ENOMEM);
	}

	if (copy_from_user(buffer, cip->lpfc_dataout,
			   cnt)) {
		rc = EIO;
		kfree(buffer);
		return (rc);
	}

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state */
	
	if (!(phba->fc_flag & FC_OFFLINE_MODE)) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		rc = EPERM;
		return (rc);
	}

	for (i = offset; i < (offset + cnt); i += 4) {
		pci_write_config_dword(phba->pcidev, i, *buffer);
		buffer++;
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state */

	kfree(buffer);
	return (rc);
}

int
lpfc_ioctl_read_pci(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{
	uint32_t offset, cnt;
	uint32_t *destp;
	int rc = 0;
	int i;
	unsigned long iflag;

	offset = (ulong) cip->lpfc_arg1;
	cnt = (ulong) cip->lpfc_arg2;
	destp = (uint32_t *) dataout;

	if ((cnt + offset) > 256) {
		rc = ERANGE;
		return (rc);
	}

	spin_lock_irqsave(phba->host->host_lock, iflag);  /* PCI config state */

	for (i = offset; i < (offset + cnt); i += 4) {
		pci_read_config_dword(phba->pcidev, i, destp);
		destp++;
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag);  /* PCI config state */

	return (rc);
}

int
lpfc_ioctl_write_mem(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip)
{
	uint32_t offset, cnt;
	struct lpfc_sli *psli;
	int rc = 0;
	unsigned long iflag;
	uint8_t *buffer;

	psli = &phba->sli;
	offset = (ulong) cip->lpfc_arg1;
	cnt = (ulong) cip->lpfc_arg2;

	if (offset >= 4096) {
		rc = ERANGE;
		return (rc);
	}

	cnt = (ulong) cip->lpfc_arg2;

	if ((cnt + offset) > 4096) {
		rc = ERANGE;
		return (rc);
	}

	buffer =  kmalloc(4096, GFP_KERNEL);
	if (!buffer)
		return(ENOMEM);

	if (copy_from_user((uint8_t *) buffer, (uint8_t *) cip->lpfc_dataout,
			   (ulong) cnt)) {
		rc = EIO;
		kfree(buffer);
		return (rc);
	}

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state */

	if (!(phba->fc_flag & FC_OFFLINE_MODE)) {
		/* Allow writing of first 128 bytes after mailbox in online mode */
		if (offset != 256 || cnt > 128) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state */
			rc = EPERM;
			return (rc);
		}
	}

	if (psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE) {
		/* copy into SLIM2 */
		lpfc_sli_pcimem_bcopy((uint32_t *) buffer,
				     ((uint32_t *) phba->slim2p + offset),
				     cnt >> 2);
	} else {
		/* First copy command data */
		lpfc_memcpy_to_slim( phba->MBslimaddr, (void *)buffer, cnt);
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state */

	kfree(buffer);
	return (rc);
}

int
lpfc_ioctl_read_mem(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{
	uint32_t offset, cnt;
	struct lpfc_sli *psli;
	int i, rc = 0;
	unsigned long iflag;

	psli = &phba->sli;
	offset = (ulong) cip->lpfc_arg1;
	cnt = (ulong) cip->lpfc_arg2;

	if (psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE) {
		/* The SLIM2 size is stored in the next field */
		i = SLI2_SLIM_SIZE;
	} else {
		i = 4096;
	}

	if (offset >= i) {
		rc = ERANGE;
		return (rc);
	}

	if ((cnt + offset) > i) {
		/* Adjust cnt instead of error ret */
		cnt = (i - offset);
	}

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state */

	if (psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE) {
		/* copy results back to user */
		lpfc_sli_pcimem_bcopy((uint32_t *) psli->MBhostaddr,
				     (uint32_t *) dataout, cnt);
	} else {
		/* First copy command data from SLIM */
		lpfc_memcpy_from_slim( dataout,
			       phba->MBslimaddr,
			       sizeof (uint32_t) * (MAILBOX_CMD_WSIZE) );		
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state */

	return (rc);
}

int
lpfc_ioctl_write_ctlreg(struct lpfc_hba * phba,
			LPFCCMDINPUT_t * cip)
{
	uint32_t offset, incr;
	struct lpfc_sli *psli;
	int rc = 0;
	unsigned long iflag;

	psli = &phba->sli;
	offset = (ulong) cip->lpfc_arg1;
	incr = (ulong) cip->lpfc_arg2;

	if (offset > 255) {
		rc = ERANGE;
		return (rc);
	}

	if (offset % 4) {
		rc = EINVAL;
		return (rc);
	}

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state */

	if (!(phba->fc_flag & FC_OFFLINE_MODE)) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state */
		rc = EPERM;
		return (rc);
	}
	writel(incr, (phba->ctrl_regs_memmap_p) + offset);

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state */

	return (rc);
}

int
lpfc_ioctl_read_ctlreg(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{
	uint32_t offset, incr;
	int rc = 0;

	offset = (ulong) cip->lpfc_arg1;

	if (offset > 255) {
		rc = ERANGE;
		return (rc);
	}

	if (offset % 4) {
		rc = EINVAL;
		return (rc);
	}

	incr = readl((phba->ctrl_regs_memmap_p) + offset);
	*((uint32_t *) dataout) = incr;

	return (rc);
}

int
lpfc_ioctl_setdiag(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{
	unsigned long iflag;
	uint32_t offset;
	int rc = 0;

	offset = (ulong) cip->lpfc_arg1;

	switch (offset) {
	case DDI_BRD_ONDI:
		if (phba->hba_state < LPFC_LINK_DOWN) {
			if (lpfc_online(phba))
				rc = EIO;
		}

		*((uint32_t *) (dataout)) = DDI_ONDI;
		break;

	case DDI_BRD_OFFDI:
		if (phba->hba_state >= LPFC_LINK_DOWN) {
			lpfc_offline(phba);
		}

		lpfc_sli_brdrestart(phba);

		msleep(2500);
		rc = lpfc_sli_brdready(phba, HS_FFRDY | HS_MBRDY);

		*((uint32_t *) (dataout)) = DDI_OFFDI;
		break;

	case DDI_BRD_WARMDI:
		if (phba->hba_state >= LPFC_LINK_DOWN) {
			lpfc_offline(phba);
		}

		spin_lock_irqsave(phba->host->host_lock, iflag);
		lpfc_reset_barrier(phba);
		lpfc_sli_brdreset(phba);
		lpfc_hba_down_post(phba);
		spin_unlock_irqrestore(phba->host->host_lock, iflag);

		msleep(2500);
		rc = lpfc_sli_brdready(phba, HS_MBRDY);

		*((uint32_t *) (dataout)) = DDI_WARMDI;
		break;

	case DDI_BRD_DIAGDI:
		if (phba->hba_state >= LPFC_LINK_DOWN) {
			lpfc_offline(phba);
		}

		lpfc_sli_brdkill(phba);

		*((uint32_t *) (dataout)) = DDI_DIAGDI;
		break;

	case DDI_BRD_SHOW:
		if (phba->hba_state == LPFC_HBA_ERROR) {
			*((uint32_t *) (dataout)) = DDI_DIAGDI;
		} else if (phba->hba_state == LPFC_WARM_START) {
			*((uint32_t *) (dataout)) = DDI_WARMDI;
		} else if (phba->hba_state == LPFC_INIT_START) {
			*((uint32_t *) (dataout)) = DDI_OFFDI;
		} else {
			*((uint32_t *) (dataout)) = DDI_ONDI;
		}
		break;

	case DDI_ONDI:
	case DDI_OFFDI:
	case DDI_SHOW:
		rc = ENXIO;
		break;

	default:
		rc = ERANGE;
		break;
	}

	return (rc);
}

void
lpfc_ioctl_timeout_iocb_cmpl(struct lpfc_hba * phba,
			     struct lpfc_iocbq * cmd_iocb_q, 
			     struct lpfc_iocbq * rsp_iocb_q)
{
	struct lpfc_timedout_iocb_ctxt *iocb_ctxt = cmd_iocb_q->context1;

	if (!iocb_ctxt) {
		if (cmd_iocb_q->context2) {
			lpfc_els_free_iocb(phba, cmd_iocb_q);
		} else {
			mempool_free( cmd_iocb_q, phba->iocb_mem_pool);
		}
		return;
	}

	if (iocb_ctxt->outdmp)
		dfc_cmd_data_free(phba, iocb_ctxt->outdmp);

	if (iocb_ctxt->indmp)
		dfc_cmd_data_free(phba, iocb_ctxt->indmp);

	if (iocb_ctxt->mp) {
		lpfc_mbuf_free(phba, 
			       iocb_ctxt->mp->virt, 
			       iocb_ctxt->mp->phys);
		kfree(iocb_ctxt->mp);
	}

	if (iocb_ctxt->bmp) {
		lpfc_mbuf_free(phba, 
			       iocb_ctxt->bmp->virt, 
			       iocb_ctxt->bmp->phys);
		kfree(iocb_ctxt->bmp);
	}

	if (iocb_ctxt->lpfc_cmd)
		lpfc_free_scsi_buf(iocb_ctxt->lpfc_cmd);

	mempool_free( cmd_iocb_q, phba->iocb_mem_pool);

	if (iocb_ctxt->rspiocbq)
		mempool_free( iocb_ctxt->rspiocbq, phba->iocb_mem_pool);

	kfree(iocb_ctxt);
}

int
lpfc_ioctl_send_scsi_fcp(struct lpfc_hba * phba,
			 LPFCCMDINPUT_t * cip)
{

	struct lpfc_sli *psli = &phba->sli;
	int reqbfrcnt;
	int snsbfrcnt;
	int j = 0;
	HBA_WWN wwpn;
	struct fcp_cmnd *fcpcmd;
	struct fcp_rsp *fcprsp;
	struct ulp_bde64 *bpl;
	struct lpfc_nodelist *pndl;
	struct lpfc_sli_ring *pring = &psli->ring[LPFC_FCP_RING];
	struct lpfc_iocbq *cmdiocbq = 0;
	struct lpfc_iocbq *rspiocbq = 0;
	DMABUFEXT_t *outdmp = 0;
	IOCB_t *cmd = 0;
	IOCB_t *rsp = 0;
	struct lpfc_dmabuf *mp = 0;
	struct lpfc_dmabuf *bmp = 0;
	char *outdta;
	uint32_t clear_count;
	int rc = 0;
	unsigned long iflag;
	uint32_t iocb_wait_timeout = cip->lpfc_arg5;
	uint32_t iocb_retries;
	struct lpfc_timedout_iocb_ctxt *iocb_ctxt;

	/*
	 * Rspcnt is really data buffer size
	 * Snscnt is sense count in case of LPFC_HBA_SEND_SCSI or
	 * it is fcp response size in case of LPFC_HBA_SEND_FCP
	 */
	struct {
		uint32_t rspcnt;
		uint32_t snscnt;
	} count;

	spin_lock_irqsave(phba->host->host_lock, iflag);

	reqbfrcnt = cip->lpfc_arg4;
	snsbfrcnt = cip->lpfc_flag;
	if ((reqbfrcnt + cip->lpfc_outsz) > (80 * 4096)) {
		/* lpfc_ioctl:error <idx> */
		lpfc_printf_log(phba,
			       KERN_ERR,
				LOG_LIBDFC,
			       "%d:1604 libdfc error Data: %d\n",
				phba->brd_no,
			       0);
		rc = ERANGE;
		goto sndsczout;
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	if (copy_from_user((uint8_t *) & wwpn, (uint8_t *) cip->lpfc_arg3,
			   (ulong) (sizeof (HBA_WWN)))) {
		rc = EIO;
		spin_lock_irqsave(phba->host->host_lock, iflag);
		goto sndsczout;
	}
	spin_lock_irqsave(phba->host->host_lock, iflag);

	pndl = lpfc_findnode_wwpn(phba, NLP_SEARCH_MAPPED,
				  (struct lpfc_name *) & wwpn);
	if (!pndl) {
		pndl = lpfc_findnode_wwpn(phba, NLP_SEARCH_UNMAPPED,
					   (struct lpfc_name *) & wwpn);
		 if (!pndl || !(pndl->nlp_flag & NLP_TGT_NO_SCSIID))
			pndl = (struct lpfc_nodelist *) 0;
	}

	if (!pndl || !(psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE)) {
		rc = EACCES;
		goto sndsczout;
	}

	if (pndl->nlp_flag & NLP_ELS_SND_MASK) {
		rc = ENODEV;
		goto sndsczout;
	}

	/* Allocate buffer for command iocb */
	if ((cmdiocbq = mempool_alloc(phba->iocb_mem_pool, GFP_ATOMIC)) == 0) {
		rc = ENOMEM;
		goto sndsczout;
	}
	memset((void *)cmdiocbq, 0, sizeof (struct lpfc_iocbq));
	cmd = &(cmdiocbq->iocb);

	/* Allocate buffer for response iocb */
	if ((rspiocbq = mempool_alloc(phba->iocb_mem_pool, GFP_ATOMIC)) == 0) {
		rc = ENOMEM;
		goto sndsczout;
	}
	memset((void *)rspiocbq, 0, sizeof (struct lpfc_iocbq));
	rsp = &(rspiocbq->iocb);

	/* Allocate buffer for Buffer ptr list */
	if (((bmp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_ATOMIC)) == 0) ||
	    ((bmp->virt = lpfc_mbuf_alloc(phba, 0, &(bmp->phys))) == 0)) {
		if (bmp)
			kfree(bmp);
		bmp = NULL;
		rc = ENOMEM;
		goto sndsczout;
	}
	INIT_LIST_HEAD(&bmp->list);
	bpl = (struct ulp_bde64 *) bmp->virt;

	/* Allocate buffer for FCP CMND / FCP RSP */
	if (((mp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_ATOMIC)) == 0) ||
	    ((mp->virt = lpfc_mbuf_alloc(phba, MEM_PRI, &(mp->phys))) == 0)) {
		if (mp)
			kfree(mp);
		mp = NULL;
		rc = ENOMEM;
		goto sndsczout;
	}

	INIT_LIST_HEAD(&mp->list);
	fcpcmd = (struct fcp_cmnd *) mp->virt;
	fcprsp = (struct fcp_rsp *) ((uint8_t *) mp->virt
						+ sizeof (struct fcp_cmnd));

	memset((void *)fcpcmd, 0, sizeof (struct fcp_cmnd)
						+ sizeof (struct fcp_rsp));

	/* Setup FCP CMND and FCP RSP */
	bpl->addrHigh = le32_to_cpu(putPaddrHigh(mp->phys));
	bpl->addrLow = le32_to_cpu(putPaddrLow(mp->phys));
	bpl->tus.f.bdeSize = sizeof (struct fcp_cmnd);
	bpl->tus.f.bdeFlags = BUFF_USE_CMND;
	bpl->tus.w = le32_to_cpu(bpl->tus.w);
	bpl++;
	bpl->addrHigh = le32_to_cpu( putPaddrHigh(mp->phys
						  + sizeof (struct fcp_cmnd)));
	bpl->addrLow = le32_to_cpu( putPaddrLow(mp->phys
						+ sizeof (struct fcp_cmnd)));
	bpl->tus.f.bdeSize = sizeof (struct fcp_rsp);
	bpl->tus.f.bdeFlags = (BUFF_USE_CMND | BUFF_USE_RCV);
	bpl->tus.w = le32_to_cpu(bpl->tus.w);
	bpl++;

	/*
	 * Copy user data into fcpcmd buffer at this point to see if its a read
	 * or a write.
	 */
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	if (copy_from_user((uint8_t *) fcpcmd, (uint8_t *) cip->lpfc_arg1,
			   (ulong) (reqbfrcnt))) {
		rc = EIO;
		spin_lock_irqsave(phba->host->host_lock, iflag);
		goto sndsczout;
	}

	outdta = (fcpcmd->fcpCntl3 == WRITE_DATA ? cip->lpfc_dataout : 0);

	/* Allocate data buffer, and fill it if its a write */
	if (cip->lpfc_outsz == 0) {
		outdmp = dfc_cmd_data_alloc(phba, outdta, bpl, 512);
	} else {
		outdmp = dfc_cmd_data_alloc(phba, outdta, bpl, cip->lpfc_outsz);
	}
	spin_lock_irqsave(phba->host->host_lock, iflag);
	if (outdmp == 0) {
		rc = ENOMEM;
		goto sndsczout;
	}

	cmd->un.fcpi64.bdl.ulpIoTag32 = 0;
	cmd->un.fcpi64.bdl.addrHigh = putPaddrHigh(bmp->phys);
	cmd->un.fcpi64.bdl.addrLow = putPaddrLow(bmp->phys);
	cmd->un.fcpi64.bdl.bdeSize = (3 * sizeof (struct ulp_bde64));
	cmd->un.fcpi64.bdl.bdeFlags = BUFF_TYPE_BDL;
	cmd->ulpBdeCount = 1;
	cmd->ulpContext = pndl->nlp_rpi;
	cmd->ulpClass = pndl->nlp_fcp_info & 0x0f;
	cmd->ulpOwner = OWN_CHIP;
	cmd->ulpTimeout = lpfc_scsi_req_tmo + 2 * phba->fc_ratov;
	cmd->ulpLe = 1;

	if (pndl->nlp_fcp_info & NLP_FCP_2_DEVICE) {
		cmd->ulpFCP2Rcvy = 1;
	}

	switch (fcpcmd->fcpCntl3) {
	case READ_DATA:
		cmd->ulpCommand = CMD_FCP_IREAD64_CR;
		cmd->ulpPU = PARM_READ_CHECK;
		cmd->un.fcpi.fcpi_parm = cip->lpfc_outsz;
		cmd->un.fcpi64.bdl.bdeSize = 
			((outdmp->flag + 2) * sizeof (struct ulp_bde64));
		break;
	case WRITE_DATA:
		cmd->ulpCommand = CMD_FCP_IWRITE64_CR;
		cmd->un.fcpi64.bdl.bdeSize =
			((outdmp->flag + 2) * sizeof (struct ulp_bde64));
		break;
	default:
		cmd->ulpCommand = CMD_FCP_ICMND64_CR;
		cmd->un.fcpi64.bdl.bdeSize = (2 * sizeof (struct ulp_bde64));
		break;
	}

	cmdiocbq->context1 = (uint8_t *) 0;
	cmdiocbq->iocb_flag |= LPFC_IO_LIBDFC;

	/* Set up the timeout value for the iocb wait command */
	if (iocb_wait_timeout == 0) {
		iocb_wait_timeout = lpfc_scsi_req_tmo + 2 * phba->fc_ratov +
							LPFC_DRVR_TIMEOUT;
		iocb_retries = 4;
	} else {
		iocb_retries = 1;
	}

	rc = lpfc_sli_issue_iocb_wait(phba, pring, cmdiocbq, rspiocbq,
					 iocb_wait_timeout);

	if (rc == IOCB_TIMEDOUT) {
		iocb_ctxt = kmalloc(sizeof(struct lpfc_timedout_iocb_ctxt),
				    GFP_ATOMIC);
		if (!iocb_ctxt) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			return EIO;
		}
		cmdiocbq->context1 = iocb_ctxt;
		cmdiocbq->context2 = NULL;
		iocb_ctxt->rspiocbq = rspiocbq;
		iocb_ctxt->mp = mp;
		iocb_ctxt->bmp = bmp;
		iocb_ctxt->outdmp = outdmp;
		iocb_ctxt->lpfc_cmd = NULL;
		iocb_ctxt->indmp = NULL;
		
		cmdiocbq->iocb_cmpl = lpfc_ioctl_timeout_iocb_cmpl;
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return EIO;
	}

	if (rc != IOCB_SUCCESS) {
		rc = EIO;
		goto sndsczout;
	}

	/*
	 * For LPFC_HBA_SEND_FCP, just return struct fcp_rsp unless we got
	 * an IOSTAT_LOCAL_REJECT.
	 *
	 * For SEND_FCP case, snscnt is really struct fcp_rsp length. In the
	 * switch statement below, the snscnt should not get destroyed.
	 */
	if (cmd->ulpCommand == CMD_FCP_IWRITE64_CX) {
		clear_count = (rsp->ulpStatus == IOSTAT_SUCCESS ? 1 : 0);
	} else {
		clear_count = cmd->un.fcpi.fcpi_parm;
	}

	if ((cip->lpfc_cmd == LPFC_HBA_SEND_FCP) &&
	    (rsp->ulpStatus != IOSTAT_LOCAL_REJECT)) {
		if (snsbfrcnt < sizeof (struct fcp_rsp)) {
			count.snscnt = snsbfrcnt;
		} else {
			count.snscnt = sizeof (struct fcp_rsp);
		}

		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		if (copy_to_user((uint8_t *) cip->lpfc_arg2, (uint8_t *) fcprsp,
				 count.snscnt)) {
			rc = EIO;
			spin_lock_irqsave(phba->host->host_lock, iflag);
			goto sndsczout;
		}
		spin_lock_irqsave(phba->host->host_lock, iflag);
	}
	switch (rsp->ulpStatus) {
	case IOSTAT_SUCCESS:
	      cpdata:
		if (cip->lpfc_outsz < clear_count) {
			cip->lpfc_outsz = 0;
			rc = ERANGE;
			break;
		}
		cip->lpfc_outsz = clear_count;
		if (cip->lpfc_cmd == LPFC_HBA_SEND_SCSI) {
			count.rspcnt = cip->lpfc_outsz;
			count.snscnt = 0;
		} else {
			/* For LPFC_HBA_SEND_FCP, snscnt is already set */
			count.rspcnt = cip->lpfc_outsz;
		}

		/* Return data length */
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		if (copy_to_user((uint8_t *) cip->lpfc_arg3, (uint8_t *) & count,
				 (2 * sizeof (uint32_t)))) {
			rc = EIO;
			spin_lock_irqsave(phba->host->host_lock, iflag);
			break;
		}

		cip->lpfc_outsz = 0;
		if (count.rspcnt) {
			if (dfc_rsp_data_copy
			    (phba, (uint8_t *) cip->lpfc_dataout, outdmp,
			     count.rspcnt)) {
				rc = EIO;
				spin_lock_irqsave(phba->host->host_lock, iflag);
				break;
			}
		}
		spin_lock_irqsave(phba->host->host_lock, iflag);
		break;

	case IOSTAT_LOCAL_REJECT:
		cip->lpfc_outsz = 0;
		if (rsp->un.grsp.perr.statLocalError == IOERR_SEQUENCE_TIMEOUT) {
			rc = ETIMEDOUT;
			break;
		}
		rc = EFAULT;

		/* count.rspcnt and count.snscnt are already 0 */
		goto sndsczout;

	case IOSTAT_FCP_RSP_ERROR:
		/*
		 * At this point, clear_count is the residual count. 
		 * Just change it to the amount actually transfered.
		 */
		if (fcpcmd->fcpCntl3 == READ_DATA) {
			if ((fcprsp->rspStatus2 & RESID_UNDER)
			    && (fcprsp->rspStatus3 == SAM_STAT_GOOD)) {
				goto cpdata;
			}
		} else {
			clear_count = 0;
		}

		count.rspcnt = (uint32_t) clear_count;
		cip->lpfc_outsz = 0;
		if (fcprsp->rspStatus2 & RSP_LEN_VALID) {
			j = be32_to_cpu(fcprsp->rspRspLen);
		}

		if (fcprsp->rspStatus2 & SNS_LEN_VALID) {
			if (cip->lpfc_cmd == LPFC_HBA_SEND_SCSI) {
				if (snsbfrcnt < be32_to_cpu(fcprsp->rspSnsLen))
					count.snscnt = snsbfrcnt;
				else
					count.snscnt =
					    be32_to_cpu(fcprsp->rspSnsLen);

				/* Return sense info from rsp packet */
				spin_unlock_irqrestore(phba->host->host_lock, iflag);
				if (copy_to_user((uint8_t *) cip->lpfc_arg2,
					((uint8_t *) & fcprsp->rspInfo0) + j,
								count.snscnt)) {
					rc = EIO;
					spin_lock_irqsave(phba->host->host_lock, iflag);
					break;
				}
				spin_lock_irqsave(phba->host->host_lock, iflag);
			}
		} else {
			rc = EFAULT;
			break;
		}

		spin_unlock_irqrestore(phba->host->host_lock, iflag);

		/* return data length */
		if (copy_to_user((uint8_t *) cip->lpfc_arg3,
				 (uint8_t *) & count,
				 (2 * sizeof (uint32_t)))) {
			rc = EIO;
			spin_lock_irqsave(phba->host->host_lock, iflag);
			break;
		}

		/* return data for read */
		if (count.rspcnt) {
			if (dfc_rsp_data_copy
			    (phba, (uint8_t *) cip->lpfc_dataout, outdmp,
			     count.rspcnt)) {
				rc = EIO;
				spin_lock_irqsave(phba->host->host_lock, iflag);
				break;
			}
		}
		spin_lock_irqsave(phba->host->host_lock, iflag);
		break;
	default:
		cip->lpfc_outsz = 0;
		rc = EFAULT;
		break;
	}
sndsczout:
	dfc_cmd_data_free(phba, outdmp);
	if (mp) {
		lpfc_mbuf_free(phba, mp->virt, mp->phys);
		kfree(mp);
	}

	if (bmp) {
		lpfc_mbuf_free(phba, bmp->virt, bmp->phys);
		kfree(bmp);
	}

	if (cmdiocbq)
		mempool_free( cmdiocbq, phba->iocb_mem_pool);

	if (rspiocbq)
		mempool_free( rspiocbq, phba->iocb_mem_pool);

	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return (rc);
}

int
lpfc_ioctl_send_els(struct lpfc_hba * phba,
		    LPFCCMDINPUT_t * cip, void *dataout)
{
	struct lpfc_sli *psli = &phba->sli;
	struct lpfc_sli_ring *pring = &psli->ring[LPFC_ELS_RING];
	struct lpfc_iocbq *cmdiocbq, *rspiocbq;
	DMABUFEXT_t *pcmdext = 0, *prspext = 0;
	struct lpfc_nodelist *pndl;
	struct ulp_bde64 *bpl;
	IOCB_t *rsp;
	struct lpfc_dmabuf *pcmd, *prsp, *pbuflist = 0;
	unsigned long iflag;
	uint16_t rpi = 0;
	DestID destID;
	int rc = 0;
	uint32_t cmdsize;
	uint32_t rspsize;
	uint32_t elscmd;

	elscmd = *(uint32_t *)cip->lpfc_arg2;
	cmdsize = cip->lpfc_arg4;
	rspsize = cip->lpfc_outsz;

	if (copy_from_user((uint8_t *)&destID, (uint8_t *)cip->lpfc_arg1,
			   (ulong)(sizeof(DestID)))) {
		return EIO;
	}

	if ((rspiocbq = mempool_alloc(phba->iocb_mem_pool, GFP_ATOMIC)) == 0) {
		return ENOMEM;
	}

	memset(rspiocbq, 0, sizeof (struct lpfc_iocbq));
	rsp = &rspiocbq->iocb;

	spin_lock_irqsave(phba->host->host_lock, iflag);

	if (destID.idType == 0) {
		pndl = lpfc_findnode_wwpn(phba, NLP_SEARCH_ALL,
					  (struct lpfc_name *)&destID.wwpn);
	} else {
		destID.d_id = (destID.d_id & Mask_DID);
		pndl = lpfc_findnode_did(phba, NLP_SEARCH_ALL, destID.d_id);
	}

	if (pndl == 0) {
		if (destID.idType == 0) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			mempool_free(rspiocbq, phba->iocb_mem_pool);
			return ENODEV;
		}
		pndl = kmalloc(sizeof (struct lpfc_nodelist), GFP_ATOMIC);
		if (!pndl) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			mempool_free(rspiocbq, phba->iocb_mem_pool);
			return ENODEV;
		}
		lpfc_nlp_init(phba, pndl, destID.d_id);
	} else {
		rpi = pndl->nlp_rpi;
	}

	cmdiocbq = lpfc_prep_els_iocb(phba, 1, cmdsize, 0, pndl, elscmd);
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	if (rpi == 0) {
		kfree(pndl);
	}
	if (cmdiocbq == 0) {
		mempool_free(rspiocbq, phba->iocb_mem_pool);
		return EIO;
	}

	pcmd = (struct lpfc_dmabuf *) cmdiocbq->context2;
	prsp = (struct lpfc_dmabuf *) pcmd->list.next;

	/* If we exceed the size of the allocated mbufs we need to */
	/* free them and allocate our own. */
	if ((cmdsize > LPFC_BPL_SIZE) || (rspsize > LPFC_BPL_SIZE)) {
		lpfc_mbuf_free(phba, pcmd->virt, pcmd->phys);
		kfree(pcmd);
		lpfc_mbuf_free(phba, prsp->virt, prsp->phys);
		kfree(prsp);
		cmdiocbq->context2 = 0;

		pbuflist = (struct lpfc_dmabuf *) cmdiocbq->context3;
		bpl = (struct ulp_bde64 *) pbuflist->virt;
		pcmdext = dfc_cmd_data_alloc(phba, cip->lpfc_arg2,
					     bpl, cmdsize);
		if (!pcmdext) {
			lpfc_els_free_iocb(phba, cmdiocbq);
			mempool_free(rspiocbq, phba->iocb_mem_pool);
			return ENOMEM;
		}
		bpl += pcmdext->flag; 
		prspext = dfc_cmd_data_alloc(phba, 0, bpl, rspsize);
		if (!prspext) {
			dfc_cmd_data_free(phba, pcmdext);
			lpfc_els_free_iocb(phba, cmdiocbq);
			mempool_free(rspiocbq, phba->iocb_mem_pool);
			return ENOMEM;
		}
	} else {
		/* Copy the command from user space */
		if (copy_from_user((uint8_t *) pcmd->virt,
				   (uint8_t *) cip->lpfc_arg2,
				   cmdsize)) {
			lpfc_els_free_iocb(phba, cmdiocbq);
			mempool_free(rspiocbq, phba->iocb_mem_pool);
			return EIO;
		}
	}

	cmdiocbq->iocb.ulpContext = rpi;
	cmdiocbq->iocb_flag |= LPFC_IO_LIBDFC;
	cmdiocbq->context1 = 0;
	cmdiocbq->context2 = 0;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	rc = lpfc_sli_issue_iocb_wait(phba, pring, cmdiocbq, rspiocbq,
				      (phba->fc_ratov*2) + LPFC_DRVR_TIMEOUT);

	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	if (rc == IOCB_SUCCESS) {
		if (rsp->ulpStatus == IOSTAT_SUCCESS) {
			if (rspsize < (rsp->un.ulpWord[0] & 0xffffff)) {
				rc = ERANGE;
			} else {
				rspsize = rsp->un.ulpWord[0] & 0xffffff;
				if (pbuflist) {
					if (dfc_rsp_data_copy(
						phba,
						(uint8_t *) cip->lpfc_dataout,
						prspext,
						rspsize)) {
						rc = EIO;
					} else {
						cip->lpfc_outsz = 0;
					}
				} else {
					if (copy_to_user(
						(uint8_t *) cip->lpfc_dataout,
						(uint8_t *) prsp->virt,
						rspsize)) {
						rc = EIO;
					} else {
						cip->lpfc_outsz = 0;
					}
				}
			}
		} else if (rsp->ulpStatus == IOSTAT_LS_RJT) {
			uint8_t ls_rjt[8];

			/* construct the LS_RJT payload */
			ls_rjt[0] = 0x01;
			ls_rjt[1] = 0x00;
			ls_rjt[2] = 0x00;
			ls_rjt[3] = 0x00;
			memcpy(&ls_rjt[4], (uint8_t *) &rsp->un.ulpWord[4],
			       sizeof(uint32_t));

			if (rspsize < 8) {
				rc = ERANGE;
			} else {
				rspsize = 8;
			}

			memcpy(dataout, ls_rjt, rspsize);
		} else {
			rc = EIO;
		}

		if (copy_to_user((uint8_t *)cip->lpfc_arg3,
				 (uint8_t *)&rspsize, sizeof(uint32_t))) {
			rc = EIO;
		}
	} else {
		rc = EIO;
	}

	if (pbuflist) {
		dfc_cmd_data_free(phba, pcmdext);
		dfc_cmd_data_free(phba, prspext);
	} else {
		cmdiocbq->context2 = (uint8_t *) pcmd;
	}
	lpfc_els_free_iocb(phba, cmdiocbq);
	mempool_free(rspiocbq, phba->iocb_mem_pool);
	return rc;
}

int
lpfc_ioctl_send_mgmt_rsp(struct lpfc_hba * phba,
			 LPFCCMDINPUT_t * cip)
{
	struct ulp_bde64 *bpl;
	struct lpfc_dmabuf *bmp = NULL;
	DMABUFEXT_t *indmp = NULL;
	uint32_t tag =  (uint32_t)cip->lpfc_flag; /* XRI for XMIT_SEQUENCE */
	int reqbfrcnt = (int)(unsigned long)cip->lpfc_arg2;
	int rc = 0;
	unsigned long iflag;

	if (!reqbfrcnt || (reqbfrcnt > (80 * 4096))) {
		rc = ERANGE;
		return (rc);
	}

	bmp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_KERNEL);
	if (!bmp) {
		rc = ENOMEM;
		goto send_mgmt_rsp_exit;
	}
	spin_lock_irqsave(phba->host->host_lock, iflag);
	bmp->virt = lpfc_mbuf_alloc(phba, 0, &bmp->phys);
	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* remove */
	if (!bmp->virt) {
		rc = ENOMEM;
		goto send_mgmt_rsp_free_bmp;
	}

	INIT_LIST_HEAD(&bmp->list);
	bpl = (struct ulp_bde64 *) bmp->virt;

	indmp = dfc_cmd_data_alloc(phba, cip->lpfc_arg1, bpl, reqbfrcnt);
	if (!indmp) {
		rc = ENOMEM;
		goto send_mgmt_rsp_free_bmpvirt;
	}
	rc = lpfc_issue_ct_rsp(phba, tag, bmp, indmp);
	if (rc) {
		if (rc == IOCB_TIMEDOUT)
			rc = ETIMEDOUT;
		else if (rc == IOCB_ERROR)
			rc = EACCES;
	}

	dfc_cmd_data_free(phba, indmp);
send_mgmt_rsp_free_bmpvirt:
	lpfc_mbuf_free(phba, bmp->virt, bmp->phys);
send_mgmt_rsp_free_bmp:
	kfree(bmp);
send_mgmt_rsp_exit:
	return (rc);
}

int
lpfc_ioctl_send_mgmt_cmd(struct lpfc_hba * phba,
			 LPFCCMDINPUT_t * cip, void *dataout)
{
	struct lpfc_nodelist *pndl = NULL;
	struct ulp_bde64 *bpl = NULL;
	struct lpfc_name findwwn;
	uint32_t finddid, timeout;
	struct lpfc_iocbq *cmdiocbq = NULL, *rspiocbq = NULL;
	DMABUFEXT_t *indmp = NULL, *outdmp = NULL;
	IOCB_t *cmd = NULL, *rsp = NULL;
	struct lpfc_dmabuf *bmp = NULL;
	struct lpfc_sli *psli = NULL;
	struct lpfc_sli_ring *pring = NULL;
	int i0 = 0, rc = 0, reqbfrcnt, snsbfrcnt;
	unsigned long iflag;
	struct lpfc_timedout_iocb_ctxt *iocb_ctxt;

	spin_lock_irqsave(phba->host->host_lock, iflag);

	psli = &phba->sli;
	pring = &psli->ring[LPFC_ELS_RING];

	if (!(psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE)) {
		rc = EACCES;
		goto send_mgmt_cmd_exit;
	}

	reqbfrcnt = cip->lpfc_arg4;
	snsbfrcnt = cip->lpfc_arg5;

	if (!reqbfrcnt || !snsbfrcnt || (reqbfrcnt + snsbfrcnt > 80 * 4096)) {
		rc = ERANGE;
		goto send_mgmt_cmd_exit;
	}


	if (cip->lpfc_cmd == LPFC_HBA_SEND_MGMT_CMD) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		rc = copy_from_user(&findwwn, cip->lpfc_arg3,
						sizeof(struct lpfc_name));
		spin_lock_irqsave(phba->host->host_lock, iflag);
		if (rc) { 
			rc = EIO;
			goto send_mgmt_cmd_exit;
		}
		pndl = lpfc_findnode_wwpn(phba, NLP_SEARCH_MAPPED |
			 NLP_SEARCH_UNMAPPED, &findwwn);
	} else {
		finddid = (uint32_t)(unsigned long)cip->lpfc_arg3;
		pndl = lpfc_findnode_did(phba, NLP_SEARCH_MAPPED |
					NLP_SEARCH_UNMAPPED, finddid);
		if (!pndl) {
			if (phba->fc_flag & FC_FABRIC) {
				pndl = kmalloc(sizeof (struct lpfc_nodelist),
						GFP_ATOMIC);
				if (!pndl) {
					rc = ENODEV;
					goto send_mgmt_cmd_exit;
				}
				
				memset(pndl, 0, sizeof (struct lpfc_nodelist));
				pndl->nlp_DID = finddid;
				lpfc_nlp_init(phba, pndl, finddid);
				pndl->nlp_state = NLP_STE_PLOGI_ISSUE;
				lpfc_nlp_list(phba, pndl, NLP_PLOGI_LIST);
				if (lpfc_issue_els_plogi(phba, pndl, 0)) {
					lpfc_nlp_list(phba, pndl, NLP_JUST_DQ);
					kfree(pndl);
					rc = ENODEV;
					goto send_mgmt_cmd_exit;
				}

				/* Allow the node to complete discover */
				while ((i0++ < 4) &&
					! (pndl = lpfc_findnode_did(phba,
							NLP_SEARCH_MAPPED |
							NLP_SEARCH_UNMAPPED,
							 finddid))) {
					spin_unlock_irqrestore(
						phba->host->host_lock, iflag);
					if (in_interrupt())
						mdelay(500);
					else
						msleep(500);
					spin_lock_irqsave(
						phba->host->host_lock, iflag);
				}

				if (i0 == 4) {
					rc = ENODEV;
					goto send_mgmt_cmd_exit;
				}
			}
			else {
				rc = ENODEV;
				goto send_mgmt_cmd_exit;
			}
		}
	}

	if (!pndl) {
		rc = ENODEV;
		goto send_mgmt_cmd_exit;
	}

	if (pndl->nlp_flag & NLP_ELS_SND_MASK) {
		rc = ENODEV;
		goto send_mgmt_cmd_exit;
	}

	cmdiocbq = mempool_alloc(phba->iocb_mem_pool, GFP_ATOMIC);
	if (!cmdiocbq) {
		rc = ENOMEM;
		goto send_mgmt_cmd_exit;
	}

	memset(cmdiocbq, 0, sizeof (struct lpfc_iocbq));
	cmd = &cmdiocbq->iocb;

	rspiocbq = mempool_alloc(phba->iocb_mem_pool, GFP_ATOMIC);
	if (!rspiocbq) {
		rc = ENOMEM;
		goto send_mgmt_cmd_free_cmdiocbq;
	}

	memset(rspiocbq, 0, sizeof (struct lpfc_iocbq));
	rsp = &rspiocbq->iocb;

	bmp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_ATOMIC);
	if (!bmp) {
		rc = ENOMEM;
		goto send_mgmt_cmd_free_rspiocbq;
	}

	bmp->virt = lpfc_mbuf_alloc(phba, 0, &bmp->phys);
	if (!bmp->virt) {
		rc = ENOMEM;
		goto send_mgmt_cmd_free_bmp;
	}

	INIT_LIST_HEAD(&bmp->list);
	bpl = (struct ulp_bde64 *) bmp->virt;
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	indmp = dfc_cmd_data_alloc(phba, cip->lpfc_arg1, bpl, reqbfrcnt);
	spin_lock_irqsave(phba->host->host_lock, iflag);
	if (!indmp) {
		rc = ENOMEM;
		goto send_mgmt_cmd_free_bmpvirt;
	}

	/* flag contains total number of BPLs for xmit */
	bpl += indmp->flag; 

	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	outdmp = dfc_cmd_data_alloc(phba, 0, bpl, snsbfrcnt);
	spin_lock_irqsave(phba->host->host_lock, iflag);
	if (!outdmp) {
		rc = ENOMEM;
		goto send_mgmt_cmd_free_indmp;
	}

	cmd->un.genreq64.bdl.ulpIoTag32 = 0;
	cmd->un.genreq64.bdl.addrHigh = putPaddrHigh(bmp->phys);
	cmd->un.genreq64.bdl.addrLow = putPaddrLow(bmp->phys);
	cmd->un.genreq64.bdl.bdeFlags = BUFF_TYPE_BDL;
	cmd->un.genreq64.bdl.bdeSize =
	    (outdmp->flag + indmp->flag) * sizeof (struct ulp_bde64);
	cmd->ulpCommand = CMD_GEN_REQUEST64_CR;
	cmd->un.genreq64.w5.hcsw.Fctl = (SI | LA);
	cmd->un.genreq64.w5.hcsw.Dfctl = 0;
	cmd->un.genreq64.w5.hcsw.Rctl = FC_UNSOL_CTL;
	cmd->un.genreq64.w5.hcsw.Type = FC_COMMON_TRANSPORT_ULP;
	cmd->ulpBdeCount = 1;
	cmd->ulpLe = 1;
	cmd->ulpClass = CLASS3;
	cmd->ulpContext = pndl->nlp_rpi;
	cmd->ulpOwner = OWN_CHIP;
	cmdiocbq->context1 = (uint8_t *) 0;
	cmdiocbq->context2 = (uint8_t *) 0;
	cmdiocbq->iocb_flag |= LPFC_IO_LIBDFC;

	if (cip->lpfc_flag == 0 ) 
		timeout = phba->fc_ratov * 2 ;
	else
		timeout = cip->lpfc_flag;

	cmd->ulpTimeout = timeout;

	rc = lpfc_sli_issue_iocb_wait(phba, pring, cmdiocbq, rspiocbq, timeout + LPFC_DRVR_TIMEOUT);

	if (rc == IOCB_TIMEDOUT) {
		mempool_free( rspiocbq, phba->iocb_mem_pool);
		iocb_ctxt = kmalloc(sizeof(struct lpfc_timedout_iocb_ctxt),
				    GFP_ATOMIC);
		if (!iocb_ctxt) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			return EACCES;
		}
		
		cmdiocbq->context1 = iocb_ctxt;
		cmdiocbq->context2 = NULL;
		iocb_ctxt->rspiocbq = NULL;
		iocb_ctxt->mp = NULL;
		iocb_ctxt->bmp = bmp;
		iocb_ctxt->outdmp = outdmp;
		iocb_ctxt->lpfc_cmd = NULL;
		iocb_ctxt->indmp = indmp;
		
		cmdiocbq->iocb_cmpl = lpfc_ioctl_timeout_iocb_cmpl;
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return EACCES;			
	}

	if (rc != IOCB_SUCCESS) {
		rc = EACCES;
		goto send_mgmt_cmd_free_outdmp;
	}

	if (rsp->ulpStatus) {
		if (rsp->ulpStatus == IOSTAT_LOCAL_REJECT) {
			switch (rsp->un.ulpWord[4] & 0xff) {
			case IOERR_SEQUENCE_TIMEOUT:
				rc = ETIMEDOUT;
				break;
			case IOERR_INVALID_RPI:
				rc = EFAULT;
				break;
			default:
				rc = EACCES;
				break;
			}
			goto send_mgmt_cmd_free_outdmp;
		}
	} else {
		outdmp->flag = rsp->un.genreq64.bdl.bdeSize;
	}

	/* Copy back response data */
	if (outdmp->flag > snsbfrcnt) {
		rc = ERANGE;
		lpfc_printf_log(phba,
				KERN_INFO,
				LOG_LIBDFC,
			       "%d:1209 C_CT Request error Data: x%x x%x\n",
				phba->brd_no,
			       outdmp->flag, 4096);
		goto send_mgmt_cmd_free_outdmp;
	}

	/* copy back size of response, and response itself */
	memcpy(dataout, &outdmp->flag, sizeof (int));
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	rc = dfc_rsp_data_copy (phba, cip->lpfc_arg2, outdmp, outdmp->flag);
	spin_lock_irqsave(phba->host->host_lock, iflag);
	if (rc)
		rc = EIO;

send_mgmt_cmd_free_outdmp:
	dfc_cmd_data_free(phba, outdmp);
send_mgmt_cmd_free_indmp:
	dfc_cmd_data_free(phba, indmp);
send_mgmt_cmd_free_bmpvirt:
	lpfc_mbuf_free(phba, bmp->virt, bmp->phys);
send_mgmt_cmd_free_bmp:
	kfree(bmp);
send_mgmt_cmd_free_rspiocbq:
	mempool_free( rspiocbq, phba->iocb_mem_pool);
send_mgmt_cmd_free_cmdiocbq:
	mempool_free(cmdiocbq, phba->iocb_mem_pool);
send_mgmt_cmd_exit:
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return rc;
}

int
lpfc_ioctl_mbox(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{
	MAILBOX_t *pmbox = NULL;
	MAILBOX_t *pmb;
	dma_addr_t lptr = 0;
	LPFC_MBOXQ_t *pmboxq = NULL;
	struct lpfc_sli *psli = NULL;
	struct lpfc_dmabuf *pbfrnfo = NULL;
	struct lpfc_dmabuf *pxmitbuf = NULL;
	unsigned long iflag = 0;
	int size = 0, mbxstatus = 0, rc = 1;
	uint8_t *kbuff;
	uint32_t incnt = (uint32_t)(unsigned long) cip->lpfc_arg2;
	uint32_t outcnt = (uint32_t)cip->lpfc_outsz;
	
	/* Redundant/arguable kmalloc, but should keep the locking tight */
	kbuff = kmalloc(incnt, GFP_KERNEL);
	if (!kbuff)
		return ENOMEM;

	rc = copy_from_user(kbuff, cip->lpfc_arg1, incnt);
	if (rc) {
		rc = EIO;
		goto lpfc_ioctl_mbox_free_kbuff;
	}

	spin_lock_irqsave(phba->host->host_lock, iflag);
	psli = &phba->sli;

	pmbox = mempool_alloc(phba->mbox_mem_pool, GFP_ATOMIC);
	if (!pmbox) {
		rc = ENOMEM;
		goto lpfc_ioctl_mbox_out;
	}
	memset((uint8_t*)pmbox, 0, sizeof(MAILBOX_t));
	memcpy((uint8_t*)pmbox, kbuff, incnt);

	pxmitbuf = kmalloc(sizeof (struct lpfc_dmabuf), GFP_ATOMIC);
	if (!pxmitbuf) {
		rc = ENOMEM;
		goto lpfc_ioctl_mbox_free_pmbox;
	}

	pxmitbuf->virt = lpfc_mbuf_alloc(phba, 0, &pxmitbuf->phys);
	if(!pxmitbuf->virt) {
		rc = ENOMEM;
		goto lpfc_ioctl_mbox_free_pxmitbuf;
	}

	INIT_LIST_HEAD(&pxmitbuf->list);

	pbfrnfo = kmalloc(sizeof (struct lpfc_dmabuf), GFP_ATOMIC);
	if (!pbfrnfo) {
		rc = ENOMEM;
		goto lpfc_ioctl_mbox_free_pxmitbuf_virt;
	}

	pbfrnfo->virt = lpfc_mbuf_alloc(phba, 0, &pbfrnfo->phys);
	if(!pbfrnfo->virt) {
		rc = ENOMEM;
		goto lpfc_ioctl_mbox_free_pbfrnfo;
	}

	INIT_LIST_HEAD(&pbfrnfo->list);


	switch (pmbox->mbxCommand) {
		/* Offline only */
	case MBX_WRITE_NV:
	case MBX_INIT_LINK:
	case MBX_DOWN_LINK:
	case MBX_CONFIG_LINK:
	case MBX_CONFIG_RING:
	case MBX_RESET_RING:
	case MBX_UNREG_LOGIN:
	case MBX_CLEAR_LA:
	case MBX_DUMP_CONTEXT:
	case MBX_RUN_DIAGS:
	case MBX_RESTART:
	case MBX_FLASH_WR_ULA:
	case MBX_SET_MASK:
	case MBX_SET_SLIM:
	case MBX_SET_DEBUG:
		if (!(phba->fc_flag & FC_OFFLINE_MODE)) {
			rc = ENODEV;
			goto lpfc_ioctl_mbox_free_pbfrnfo_virt;
		}
		break;
		/* Online / Offline */
	case MBX_LOAD_SM:
	case MBX_READ_NV:
	case MBX_READ_CONFIG:
	case MBX_READ_RCONFIG:
	case MBX_READ_STATUS:
	case MBX_READ_XRI:
	case MBX_READ_REV:
	case MBX_READ_LNK_STAT:
	case MBX_DUMP_MEMORY:
	case MBX_DOWN_LOAD:
	case MBX_UPDATE_CFG:
	case MBX_KILL_BOARD:
	case MBX_LOAD_AREA:
	case MBX_LOAD_EXP_ROM:
	case MBX_BEACON:
	case MBX_DEL_LD_ENTRY:
		break;

		/* Online / Offline - with DMA */
	case MBX_READ_SPARM64:
		lptr = getPaddr(pmbox->un.varRdSparm.un.sp64.addrHigh,
					pmbox->un.varRdSparm.un.sp64.addrLow);
		size = pmbox->un.varRdSparm.un.sp64.tus.f.bdeSize;
		if (lptr) {
			pmbox->un.varRdSparm.un.sp64.addrHigh =
						putPaddrHigh(pbfrnfo->phys);
			pmbox->un.varRdSparm.un.sp64.addrLow =
						putPaddrLow(pbfrnfo->phys);
		}
		break;

	case MBX_READ_RPI64:
		/* This is only allowed when online is SLI2 mode */
		lptr = getPaddr(pmbox->un.varRdRPI.un.sp64.addrHigh,
					pmbox->un.varRdRPI.un.sp64.addrLow);
		size = pmbox->un.varRdRPI.un.sp64.tus.f.bdeSize;
		if (lptr) {
			pmbox->un.varRdRPI.un.sp64.addrHigh =
						putPaddrHigh(pbfrnfo->phys);
			pmbox->un.varRdRPI.un.sp64.addrLow =
						putPaddrLow(pbfrnfo->phys);
		}
		break;

	case MBX_RUN_BIU_DIAG64:
		lptr = getPaddr(pmbox->un.varBIUdiag.un.s2.xmit_bde64.addrHigh,
				pmbox->un.varBIUdiag.un.s2.xmit_bde64.addrLow);
		size = pmbox->un.varBIUdiag.un.s2.xmit_bde64.tus.f.bdeSize;
		if (lptr) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			rc = copy_from_user((uint8_t *)pxmitbuf->virt,
					    (uint8_t *)(unsigned long)lptr,
					    size);
			spin_lock_irqsave(phba->host->host_lock, iflag);
			if (rc) {
				rc = EIO;
				goto lpfc_ioctl_mbox_free_pbfrnfo_virt;
			}

			pmbox->un.varBIUdiag.un.s2.xmit_bde64.addrHigh =
						putPaddrHigh(pxmitbuf->phys);
			pmbox->un.varBIUdiag.un.s2.xmit_bde64.addrLow =
						putPaddrLow(pxmitbuf->phys);
		}

		lptr = getPaddr(pmbox->un.varBIUdiag.un.s2.rcv_bde64.addrHigh,
				pmbox->un.varBIUdiag.un.s2.rcv_bde64.addrLow);
		size = pmbox->un.varBIUdiag.un.s2.rcv_bde64.tus.f.bdeSize;
		if (lptr) {
			pmbox->un.varBIUdiag.un.s2.rcv_bde64.addrHigh =
						putPaddrHigh(pbfrnfo->phys);
			pmbox->un.varBIUdiag.un.s2.rcv_bde64.addrLow =
						putPaddrLow(pbfrnfo->phys);
		}
		break;

	case MBX_READ_LA:
	case MBX_READ_LA64:
	case MBX_REG_LOGIN:
	case MBX_REG_LOGIN64:
	case MBX_CONFIG_PORT:
	case MBX_RUN_BIU_DIAG:
		/* Do not allow SLI-2 commands */
		rc = ENODEV;
		goto lpfc_ioctl_mbox_free_pbfrnfo_virt;
		break;
	default:
		/* Offline only
		 * Let firmware return error for unsupported commands
		 */
		if (!(phba->fc_flag & FC_OFFLINE_MODE)) {
			rc = ENODEV;
			goto lpfc_ioctl_mbox_free_pbfrnfo_virt;
		}
		break;
	}		/* switch pmbox->command */


	pmboxq = mempool_alloc(phba->mbox_mem_pool, GFP_ATOMIC);
	if (!pmboxq) {
		rc = ENOMEM;
		goto lpfc_ioctl_mbox_free_pbfrnfo_virt;
	}
	memset(pmboxq, 0, sizeof (LPFC_MBOXQ_t));

	pmb = &pmboxq->mb;
	pmb->mbxCommand = pmbox->mbxCommand;
	pmb->mbxOwner = pmbox->mbxOwner;
	pmb->un = pmbox->un;
	pmb->us = pmbox->us;
	pmboxq->context1 = NULL;

	if ((phba->fc_flag & FC_OFFLINE_MODE) ||
	    (!(psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE))) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		mbxstatus = lpfc_sli_issue_mbox(phba, pmboxq, MBX_POLL);
		spin_lock_irqsave(phba->host->host_lock, iflag);
	} else {
		DECLARE_WAIT_QUEUE_HEAD(done_q);
		DECLARE_WAITQUEUE(wq_entry, current);
		uint32_t timeleft = 0;
		int retval;

		/* The caller must leave context1 empty. */
		if (pmboxq->context1 != 0) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			return (MBX_NOT_FINISHED);
		}

		/* setup wake call as IOCB callback */
		if (pmb->mbxCommand != MBX_KILL_BOARD) {
			pmboxq->mbox_cmpl = lpfc_sli_wake_mbox_wait;
		}

		/* setup context field to pass wait_queue pointer to wake
		   function  */
		pmboxq->context1 = &done_q;

		/* start to sleep before we wait, to avoid races */
		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue(&done_q, &wq_entry);

		/* now issue the command */
		retval = lpfc_sli_issue_mbox(phba, pmboxq, MBX_NOWAIT);

		if (retval == MBX_BUSY || retval == MBX_SUCCESS) {
			if (retval == MBX_SUCCESS &&
			    pmb->mbxCommand == MBX_KILL_BOARD) {
				psli->sliinit.sli_flag &= ~LPFC_SLI_MBOX_ACTIVE;
			} else {
				spin_unlock_irqrestore(phba->host->host_lock,
						       iflag);
				timeleft = schedule_timeout(LPFC_MBOX_TMO * HZ);
				spin_lock_irqsave(phba->host->host_lock, iflag);
				pmboxq->context1 = NULL;
				/* if schedule_timeout returns 0, we timed out
				   and were not woken up */
				if (timeleft == 0) {
					retval = MBX_TIMEOUT;
				} else {
					retval = MBX_SUCCESS;
				}
			}
		}
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&done_q, &wq_entry);
		mbxstatus = retval;
	}

	if (mbxstatus == MBX_TIMEOUT) {
		rc = EBUSY;
		goto lpfc_ioctl_mbox_free_pmboxq;
	} else if (mbxstatus != MBX_SUCCESS) {
		rc = ENODEV;
		goto lpfc_ioctl_mbox_free_pmboxq;
	}

	rc = 0;
	memcpy(dataout, (uint8_t*)pmb, outcnt);
	if (lptr) {
		kfree(kbuff);
		kbuff = kmalloc(size, GFP_ATOMIC);
		if (!kbuff) {
			rc = ENOMEM;
			goto lpfc_ioctl_mbox_free_pmboxq;
		}
		memcpy(kbuff, pbfrnfo->virt, size);
	}

lpfc_ioctl_mbox_free_pmboxq:
	mempool_free(pmboxq, phba->mbox_mem_pool);
lpfc_ioctl_mbox_free_pbfrnfo_virt:
	lpfc_mbuf_free(phba, pbfrnfo->virt, pbfrnfo->phys);
lpfc_ioctl_mbox_free_pbfrnfo:
	kfree(pbfrnfo);
lpfc_ioctl_mbox_free_pxmitbuf_virt:
	lpfc_mbuf_free(phba, pxmitbuf->virt, pxmitbuf->phys);
lpfc_ioctl_mbox_free_pxmitbuf:
	kfree(pxmitbuf);
lpfc_ioctl_mbox_free_pmbox:
	mempool_free((LPFC_MBOXQ_t*)pmbox, phba->mbox_mem_pool);
lpfc_ioctl_mbox_out:
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
lpfc_ioctl_mbox_free_kbuff:
	if (lptr && !rc) {
		rc = copy_to_user((void*)(unsigned long)lptr, kbuff, size);
		if (rc)
			rc = EIO;
	}
	kfree(kbuff);
	return rc;
}
int
lpfc_ioctl_linkinfo(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{
	LinkInfo *linkinfo;
	int rc = 0;
	unsigned long iflag;

	linkinfo = (LinkInfo *) dataout;

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state */

	linkinfo->a_linkEventTag = phba->fc_eventTag;
	linkinfo->a_linkUp = phba->fc_stat.LinkUp;
	linkinfo->a_linkDown = phba->fc_stat.LinkDown;
	linkinfo->a_linkMulti = phba->fc_stat.LinkMultiEvent;
	linkinfo->a_DID = phba->fc_myDID;
	if (phba->fc_topology == TOPOLOGY_LOOP) {
		if (phba->fc_flag & FC_PUBLIC_LOOP) {
			linkinfo->a_topology = LNK_PUBLIC_LOOP;
			memcpy((uint8_t *) linkinfo->a_alpaMap,
			       (uint8_t *) phba->alpa_map, 128);
			linkinfo->a_alpaCnt = phba->alpa_map[0];
		} else {
			linkinfo->a_topology = LNK_LOOP;
			memcpy((uint8_t *) linkinfo->a_alpaMap,
			       (uint8_t *) phba->alpa_map, 128);
			linkinfo->a_alpaCnt = phba->alpa_map[0];
		}
	} else {
		memset((uint8_t *) linkinfo->a_alpaMap, 0, 128);
		linkinfo->a_alpaCnt = 0;
		if (phba->fc_flag & FC_FABRIC) {
			linkinfo->a_topology = LNK_FABRIC;
		} else {
			linkinfo->a_topology = LNK_PT2PT;
		}
	}
	linkinfo->a_linkState = 0;
	switch (phba->hba_state) {
	case LPFC_STATE_UNKNOWN:
	case LPFC_WARM_START:
	case LPFC_INIT_START:

	case LPFC_LINK_DOWN:
		linkinfo->a_linkState = LNK_DOWN;
		memset((uint8_t *) linkinfo->a_alpaMap, 0, 128);
		linkinfo->a_alpaCnt = 0;
		break;
	case LPFC_LINK_UP:

	case LPFC_LOCAL_CFG_LINK:
		linkinfo->a_linkState = LNK_UP;
		break;
	case LPFC_FLOGI:
		linkinfo->a_linkState = LNK_FLOGI;
		break;
	case LPFC_DISC_AUTH:
	case LPFC_FABRIC_CFG_LINK:
	case LPFC_NS_REG:
	case LPFC_NS_QRY:

	case LPFC_CLEAR_LA:
		linkinfo->a_linkState = LNK_DISCOVERY;
		break;
	case LPFC_HBA_READY:
		linkinfo->a_linkState = LNK_READY;
		break;
	}
	linkinfo->a_alpa = (uint8_t) (phba->fc_myDID & 0xff);
	memcpy((uint8_t *) linkinfo->a_wwpName,
	       (uint8_t *) & phba->fc_portname, 8);
	memcpy((uint8_t *) linkinfo->a_wwnName,
	       (uint8_t *) & phba->fc_nodename, 8);

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state */

	return (rc);
}

int
lpfc_ioctl_ioinfo(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{

	IOinfo *ioinfo;
	struct lpfc_sli *psli;
	int rc = 0;
	unsigned long iflag;

	ioinfo = (IOinfo *) dataout;
	memset((void *)ioinfo, 0, sizeof (IOinfo));

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state */

	psli = &phba->sli;

	ioinfo->a_mbxCmd = psli->slistat.mboxCmd;
	ioinfo->a_mboxCmpl = psli->slistat.mboxEvent;
	ioinfo->a_mboxErr = psli->slistat.mboxStatErr;
	ioinfo->a_iocbCmd = psli->slistat.iocbCmd[cip->lpfc_ring];
	ioinfo->a_iocbRsp = psli->slistat.iocbRsp[cip->lpfc_ring];
	ioinfo->a_adapterIntr = (psli->slistat.linkEvent +
				 psli->slistat.iocbRsp[cip->lpfc_ring] +
				 psli->slistat.mboxEvent);
	ioinfo->a_fcpCmd = phba->fc_stat.fcpCmd;
	ioinfo->a_fcpCmpl = phba->fc_stat.fcpCmpl;
	ioinfo->a_fcpErr = phba->fc_stat.fcpRspErr +
	    phba->fc_stat.fcpRemoteStop + phba->fc_stat.fcpPortRjt +
	    phba->fc_stat.fcpPortBusy + phba->fc_stat.fcpError +
	    phba->fc_stat.fcpLocalErr;
	ioinfo->a_bcastRcv = phba->fc_stat.frameRcvBcast;
	ioinfo->a_RSCNRcv = phba->fc_stat.elsRcvRSCN;

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state */

	return (rc);
}

int
lpfc_ioctl_nodeinfo(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout, int size)
{
	NodeInfo *np;
	struct lpfc_nodelist *pndl;
	struct lpfc_bindlist *pbdl;
	uint32_t cnt;
	int rc = 0;
	uint32_t total_mem = size;
	struct list_head *pos, *listp;
	struct list_head *node_list[7];
	int i;
	unsigned long iflag;
	int list;

	np = (NodeInfo *) dataout;
	cnt = 0;

	/* Since the size of bind & others are different,
	   get the node list of bind first
	 */
	total_mem -= sizeof (struct lpfc_bindlist);

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state, nlpbind_list */

	list_for_each(pos, &phba->fc_nlpbind_list) {
		if (total_mem <= 0)
			break;
		pbdl = list_entry(pos, struct lpfc_bindlist, nlp_listp);
		memset((uint8_t *) np, 0, sizeof (struct lpfc_bindlist));
		if (pbdl->nlp_bind_type & FCP_SEED_WWPN)
			np->a_flag |= NODE_SEED_WWPN;
		if (pbdl->nlp_bind_type & FCP_SEED_WWNN)
			np->a_flag |= NODE_SEED_WWNN;
		if (pbdl->nlp_bind_type & FCP_SEED_DID)
			np->a_flag |= NODE_SEED_DID;
		if (pbdl->nlp_bind_type & FCP_SEED_AUTO)
			np->a_flag |= NODE_AUTOMAP;
		np->a_state = NODE_SEED;
		np->a_did = pbdl->nlp_DID;
		np->a_targetid = pbdl->nlp_sid;
		memcpy(np->a_wwpn, &pbdl->nlp_portname, 8);
		memcpy(np->a_wwnn, &pbdl->nlp_nodename, 8);
		total_mem -= sizeof (struct lpfc_bindlist);
		np++;
		cnt++;
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state, nlpbind_list */

	/* Get the node list of unmap, map, plogi and adisc
	 */
	total_mem -= sizeof (struct lpfc_nodelist);

	node_list[0] = &phba->fc_plogi_list;
	node_list[1] = &phba->fc_adisc_list;
	node_list[2] = &phba->fc_reglogin_list;
	node_list[3] = &phba->fc_prli_list;
	node_list[4] = &phba->fc_nlpunmap_list;
	node_list[5] = &phba->fc_nlpmap_list;
	node_list[6] = &phba->fc_npr_list;

	for (i = 0; i < 7; i++) {

		listp = node_list[i];

		spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state, node_list[i] list */

		if (list_empty(listp)) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state, node_list[i] list */
			continue;
		}

		list_for_each(pos, listp) {
			pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
			if (total_mem <= 0) {
				break;
			}

			memset((uint8_t *) np, 0, sizeof (struct lpfc_nodelist));
			np->a_state = NODE_LIMBO;
			list = (pndl->nlp_flag & NLP_LIST_MASK);
			if (list == NLP_ADISC_LIST) {
				np->a_flag |= NODE_ADDR_AUTH;
				np->a_state = NODE_LIMBO;
			}
			if (list == NLP_PLOGI_LIST) {
				np->a_state = NODE_PLOGI;
			}
			if (list == NLP_REGLOGIN_LIST) {
				np->a_state = NODE_PLOGI;
			}
			if (list == NLP_PRLI_LIST) {
				np->a_state = NODE_PLOGI;
			}
			if (list == NLP_MAPPED_LIST) {
				np->a_state = NODE_ALLOC;
			}
			if (list == NLP_UNMAPPED_LIST) {
				np->a_state = NODE_PRLI;
			}
			if (pndl->nlp_type & NLP_FABRIC)
				np->a_flag |= NODE_FABRIC;
			if (pndl->nlp_type & NLP_FCP_TARGET)
				np->a_flag |= NODE_FCP_TARGET;
			if (pndl->nlp_flag & NLP_ELS_SND_MASK)	/* Sent ELS mask  -- Check this */
				np->a_flag |= NODE_REQ_SND;
			if (pndl->nlp_flag & NLP_SEED_WWPN)
				np->a_flag |= NODE_SEED_WWPN;
			if (pndl->nlp_flag & NLP_SEED_WWNN)
				np->a_flag |= NODE_SEED_WWNN;
			if (pndl->nlp_flag & NLP_SEED_DID)
				np->a_flag |= NODE_SEED_DID;
			if (pndl->nlp_flag & NLP_AUTOMAP)
				np->a_flag |= NODE_AUTOMAP;
			np->a_did = pndl->nlp_DID;
			np->a_targetid = pndl->nlp_sid;
			memcpy(np->a_wwpn, &pndl->nlp_portname, 8);
			memcpy(np->a_wwnn, &pndl->nlp_nodename, 8);


			total_mem -= sizeof (struct lpfc_nodelist);
			np++;
			cnt++;
		}
		spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state, node_list[i] list */
	}
	cip->lpfc_outsz = (uint32_t) (cnt * sizeof (NodeInfo));

	return (rc);
}

int
lpfc_ioctl_getcfg(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip, void *dataout)
{
	int rc = 0;
	CfgParam *cp;
	iCfgParam *icp;
	uint32_t cnt;
	int i, astringi;
	unsigned long iflag;

	/* First uint32_t word will be count */
	cp = (CfgParam *) dataout;
	cnt = 0;

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state, cfg */

	for (i = 0; i < LPFC_TOTAL_NUM_OF_CFG_PARAM; i++) {
		icp = (iCfgParam *) & lpfc_iCfgParam[i];
		if (!(icp->a_flag & CFG_EXPORT))
			continue;
		cp->a_low = icp->a_low;
		cp->a_hi = icp->a_hi;
		cp->a_flag = icp->a_flag;
		cp->a_default = icp->a_default;
		switch (i) {
		case 0:
			cp->a_current = phba->cfg_log_verbose;
			break;
		case 1:
			cp->a_current = phba->cfg_lun_queue_depth;
			break;
		case 2:
			cp->a_current = phba->cfg_scan_down;
			break;
		case 3:
			cp->a_current = phba->cfg_nodev_tmo;
			break;
		case 4:
			cp->a_current = phba->cfg_topology;
			break;
		case 5:
			cp->a_current = phba->cfg_link_speed;
			break;
		case 6:
			cp->a_current = phba->cfg_fcp_class;
			break;
		case 7:
			cp->a_current = phba->cfg_use_adisc;
			break;
		case 8:
			cp->a_current = phba->cfg_ack0;
			break;
		case 9:
			cp->a_current = phba->cfg_fcp_bind_method;
			break;
		case 10:
			cp->a_current = phba->cfg_cr_delay;
			break;
		case 11:
			cp->a_current = phba->cfg_cr_count;
			break;
		case 12:
			cp->a_current = phba->cfg_fdmi_on;
			break;
		case 13:
			cp->a_current = phba->cfg_discovery_threads;
			break;
		case 14:
			cp->a_current = phba->cfg_max_luns;
			break;
		default:
			printk(KERN_ERR "%s: Ignoring unknown ioctl cmd %d\n",
				__FUNCTION__, i);
			break;
		}
		cp->a_changestate = icp->a_changestate;
		memcpy(cp->a_string, icp->a_string, 32);

		/* Translate all "_" to "-" to preserve backwards compatibility
		with older drivers that used "_" */
		astringi=0;
		while(cp->a_string[astringi++])
			if(cp->a_string[astringi] == '_')
				cp->a_string[astringi] = '-';

		memcpy(cp->a_help, icp->a_help, 80);
		cp++;
		cnt++;
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state, cfg */

	if (cnt) {
		cip->lpfc_outsz = (uint32_t) (cnt * sizeof (CfgParam));
	}

	return (rc);
}

int
lpfc_ioctl_setcfg(struct lpfc_hba * phba, LPFCCMDINPUT_t * cip)
{
	iCfgParam *icp;
	uint32_t offset, cnt;
	struct lpfc_sli *psli;
	int rc = 0;
	int i, j;
	unsigned long iflag;

	psli = &phba->sli;
	offset = (ulong) cip->lpfc_arg1;
	cnt = (ulong) cip->lpfc_arg2;
	if (offset >= LPFC_TOTAL_NUM_OF_CFG_PARAM) {
		rc = ERANGE;
		return (rc);
	}
	j = offset;
	for (i = 0; i < LPFC_TOTAL_NUM_OF_CFG_PARAM; i++) {
		icp = (iCfgParam *) & lpfc_iCfgParam[i];
		if (!(icp->a_flag & CFG_EXPORT))
			continue;
		if (j == 0)
			break;
		j--;
	}
	if (icp->a_changestate != CFG_DYNAMIC) {
		rc = EPERM;
		return (rc);
	}
	if (((icp->a_low != 0) && (cnt < icp->a_low)) || (cnt > icp->a_hi)) {
		rc = ERANGE;
		return (rc);
	}
	if (!(icp->a_flag & CFG_EXPORT)) {
		rc = EPERM;
		return (rc);
	}

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state, cfg */

		switch (i) {
		case 0:
			phba->cfg_log_verbose = cnt;
			break;
		case 1:
			phba->cfg_lun_queue_depth = cnt;
			break;
		case 2:
			phba->cfg_scan_down = cnt;
			break;
		case 3:
			phba->cfg_nodev_tmo = cnt;
			break;
		case 4:
			phba->cfg_topology = cnt;
			break;
		case 5:
			phba->cfg_link_speed = cnt;
			break;
		case 6:
			phba->cfg_fcp_class = cnt;
			break;
		case 7:
			phba->cfg_use_adisc = cnt;
			break;
		case 8:
			phba->cfg_ack0 = cnt;
			break;
		case 9:
			phba->cfg_fcp_bind_method = cnt;
			break;
		case 10:
			phba->cfg_cr_delay = cnt;
			break;
		case 11:
			phba->cfg_cr_count = cnt;
			break;
		case 12:
			phba->cfg_fdmi_on = cnt;
			break;
		case 13:
			phba->cfg_discovery_threads = cnt;
			break;
		case 14:
			phba->cfg_max_luns = cnt;
			break;
		default:
			printk(KERN_ERR "%s: Ignoring unknown ioctl cmd %d\n",
				__FUNCTION__, i);
			break;
		}

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state, cfg */

	return (rc);
}

int
lpfc_ioctl_hba_get_event(struct lpfc_hba * phba,
			 LPFCCMDINPUT_t * cip, 
			 void *dataout, int data_size)
{
	fcEVT_t *ep;
	fcEVT_t *oep;
	fcEVTHDR_t *ehp;
	uint8_t *cp;
	void *type;
	uint32_t offset, incr, cnt, i, gstype;
	struct lpfc_dmabuf *mm;
	int no_more;
	int rc = 0;
	uint32_t total_mem = data_size;
	unsigned long iflag;
	struct list_head head, *pos, *tmp_pos;

	no_more = 1;

	offset = ((ulong) cip->lpfc_arg3 & FC_REG_EVENT_MASK); /* event mask */
	incr = (uint32_t) cip->lpfc_flag;	               /* event id   */

	type = 0;

	if (offset == FC_REG_CT_EVENT) {
		if (copy_from_user
		    ((uint8_t *) & gstype, (uint8_t *) cip->lpfc_arg2,
		     (ulong) (sizeof (uint32_t)))) {
			rc = EIO;
			return (rc);
		}
		type = (void *)(ulong) gstype;
	}

	spin_lock_irqsave(phba->host->host_lock, iflag);

	ehp = (fcEVTHDR_t *) phba->fc_evt_head;

	while (ehp) {
		if ((ehp->e_mask == offset) && (ehp->e_type == type))
			break;
		ehp = (fcEVTHDR_t *) ehp->e_next_header;
	}

	if (!ehp) {
		rc = ENOENT;
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return (rc);
	}

	ep = ehp->e_head;
	oep = 0;
	while (ep) {
		/* Find an event that matches the event mask */
		if (ep->evt_sleep == 0) {
			/* dequeue event from event list */
			if (oep == 0) {
				ehp->e_head = ep->evt_next;
			} else {
				oep->evt_next = ep->evt_next;
			}
			if (ehp->e_tail == ep)
				ehp->e_tail = oep;

			switch (offset) {
			case FC_REG_LINK_EVENT:
				break;
			case FC_REG_RSCN_EVENT:
				/* Return data length */
				cnt = sizeof (uint32_t);
				spin_unlock_irqrestore(phba->host->host_lock,
						       iflag);
				if (copy_to_user
				    ((uint8_t *) cip->lpfc_arg1,
				     (uint8_t *) & cnt, sizeof (uint32_t))) {
					rc = EIO;
				}
				spin_lock_irqsave(phba->host->host_lock, iflag);
				memcpy(dataout, (char *)&ep->evt_data0,
				       cnt);
				cip->lpfc_outsz = (uint32_t) cnt;
				break;
			case FC_REG_CT_EVENT:
				/* Return data length */
				cnt = (ulong) (ep->evt_data2);
				spin_unlock_irqrestore(phba->host->host_lock,
						       iflag);
				if (copy_to_user
				    ((uint8_t *) cip->lpfc_arg1,
				     (uint8_t *) & cnt, sizeof (uint32_t))) {
					rc = EIO;
				} else {
					if (copy_to_user
					    ((uint8_t *) cip->lpfc_arg2,
					     (uint8_t *) & ep->evt_data0,
					     sizeof (uint32_t))) {
						rc = EIO;
					}
				}
				spin_lock_irqsave(phba->host->host_lock, iflag);

				cip->lpfc_outsz = (uint32_t) cnt;
				i = cnt;
				mm = (struct lpfc_dmabuf *) ep->evt_data1;
				cp = (uint8_t *) dataout;
				list_add_tail(&head, &mm->list);
				list_for_each_safe(pos, tmp_pos, &head) {
					mm = list_entry(pos, struct lpfc_dmabuf,
							list);

					if (cnt > FCELSSIZE)
						i = FCELSSIZE;
					else
						i = cnt;

					if (total_mem > 0) {
						memcpy(cp, (char *)mm->virt, i);
						total_mem -= i;
					}

					cp += i;
					lpfc_mbuf_free(phba, mm->virt,
						       mm->phys);
					list_del(pos);
					kfree(mm);
				}
				list_del(&head);
				break;
			case FC_REG_DUMP_EVENT:
				break;
			}

			if ((offset == FC_REG_CT_EVENT) && (ep->evt_next) &&
			    (((fcEVT_t *) (ep->evt_next))->evt_sleep == 0)) {
				/* More events are waiting */
				ep->evt_data0 |= 0x80000000;
				spin_unlock_irqrestore(phba->host->host_lock,
						       iflag);
				if (copy_to_user
				    ((uint8_t *) cip->lpfc_arg2,
				     (uint8_t *) & ep->evt_data0,
				     sizeof (uint32_t))) {
					rc = EIO;
				}
				spin_lock_irqsave(phba->host->host_lock, iflag);
				no_more = 0;
			}

			/* Requeue event entry */
			ep->evt_next = 0;
			ep->evt_data0 = 0;
			ep->evt_data1 = 0;
			ep->evt_data2 = 0;
			ep->evt_sleep = 1;
			ep->evt_flags = 0;

			if (ehp->e_head == 0) {
				ehp->e_head = ep;
				ehp->e_tail = ep;
			} else {
				ehp->e_tail->evt_next = ep;
				ehp->e_tail = ep;
			}

			if (offset == FC_REG_LINK_EVENT) {
				ehp->e_flag &= ~E_GET_EVENT_ACTIVE;
				spin_unlock_irqrestore(phba->host->host_lock,
						       iflag);
				rc = lpfc_ioctl_linkinfo(phba, cip, dataout);
				return (rc);
			}

			if (no_more)
				ehp->e_flag &= ~E_GET_EVENT_ACTIVE;

			spin_unlock_irqrestore(phba->host->host_lock, iflag);

			return (rc);
		}
		oep = ep;
		ep = ep->evt_next;
	}

	if (ep == 0) {
		/* No event found */
		rc = ENOENT;
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return (rc);
}

int
lpfc_sleep_event(struct lpfc_hba * phba, fcEVTHDR_t * ep)
{

	ep->e_mode |= E_SLEEPING_MODE;
	switch (ep->e_mask) {
	case FC_REG_LINK_EVENT:
		return (lpfc_sleep(phba, &phba->linkevtwq, 0));
	case FC_REG_RSCN_EVENT:
		return (lpfc_sleep(phba, &phba->rscnevtwq, 0));
	case FC_REG_CT_EVENT:
		return (lpfc_sleep(phba, &phba->ctevtwq, 0));
	case FC_REG_DUMP_EVENT:
		return (lpfc_sleep(phba, &phba->dumpevtwq, 0));
	}
	return (0);
}

int
lpfc_ioctl_hba_set_event(struct lpfc_hba * phba,
			 LPFCCMDINPUT_t * cip)
{
	fcEVT_t *evp;
	fcEVT_t *ep;
	fcEVT_t *oep;
	fcEVTHDR_t *ehp;
	fcEVTHDR_t *oehp;
	int found;
	void *type;
	uint32_t offset, incr;
	int rc = 0;
	unsigned long iflag;

	offset = ((ulong) cip->lpfc_arg3 & FC_REG_EVENT_MASK); /* event mask */
	incr = (uint32_t) cip->lpfc_flag;	               /* event id   */

	switch (offset) {
	case FC_REG_CT_EVENT:
		type = cip->lpfc_arg2;
		found = LPFC_MAX_EVENT;	/* Number of events we can queue up + 1,
					 * before dropping events for this event
					 * id.  */
		break;
	case FC_REG_RSCN_EVENT:
		type = (void *)0;
		found = LPFC_MAX_EVENT;	/* Number of events we can queue up + 1,
					 * before dropping events for this event
					 * id.  */
		break;
	case FC_REG_LINK_EVENT:
		type = (void *)0;
		found = 2;		/* Number of events we can queue up + 1,
					 * before dropping events for this event
					 * id.  */
		break;
	case FC_REG_DUMP_EVENT:
		type  = (void *)0;
		found = 1;		/* Number of events we can queue up + 1,
					 * before dropping events for this event
					 * id.  */
          break;
	default:
		found = 0;
		rc = EINTR;
		return (rc);
	}

	/*
	 * find the fcEVT_t header for this Event, allocate a header
	 * if not found.
	 */
	oehp = 0;

	spin_lock_irqsave(phba->host->host_lock, iflag);

	ehp = (fcEVTHDR_t *) phba->fc_evt_head;
	while (ehp) {
		if ((ehp->e_mask == offset) && (ehp->e_type == type)) {
			found = 0;
			break;
		}
		oehp = ehp;
		ehp = (fcEVTHDR_t *) ehp->e_next_header;
	}

	if (!ehp) {
		ehp = kmalloc (sizeof (fcEVTHDR_t),
			       GFP_ATOMIC);
		if (ehp == 0 ) {
			rc = EINTR;
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			return (rc);
		}
		memset((char *)ehp, 0, sizeof (fcEVTHDR_t));
		if (phba->fc_evt_head == 0) {
			phba->fc_evt_head = ehp;
			phba->fc_evt_tail = ehp;
		} else {
			((fcEVTHDR_t *) (phba->fc_evt_tail))->e_next_header =
			    ehp;
			phba->fc_evt_tail = (void *)ehp;
		}
		ehp->e_handle = incr;
		ehp->e_mask = offset;
		ehp->e_type = type;
		ehp->e_refcnt++;
	} else {
		ehp->e_refcnt++;
	}

	while (found) {
		/* Save event id for C_GET_EVENT */
		oep = kmalloc (sizeof (fcEVT_t),
			       GFP_ATOMIC);
		if ( oep ==  0) {
			rc = EINTR;
			break;
		}
		memset((char *)oep, 0, sizeof (fcEVT_t));

		oep->evt_sleep = 1;
		oep->evt_handle = incr;
		oep->evt_mask = offset;
		oep->evt_type = type;

		if (ehp->e_head == 0) {
			ehp->e_head = oep;
			ehp->e_tail = oep;
		} else {
			ehp->e_tail->evt_next = (void *)oep;
			ehp->e_tail = oep;
		}
		oep->evt_next = 0;
		found--;
	}

	switch (offset) {
	case FC_REG_CT_EVENT:
	case FC_REG_RSCN_EVENT:
	case FC_REG_LINK_EVENT:
	case FC_REG_DUMP_EVENT:
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		if (rc || lpfc_sleep_event(phba, ehp)) {
			rc = EINTR;

			spin_lock_irqsave(phba->host->host_lock, iflag);

			ehp->e_mode &= ~E_SLEEPING_MODE;
			ehp->e_refcnt--;
			if (ehp->e_refcnt) {
				goto setout;
			}
			/* Remove all eventIds from queue */
			ep = ehp->e_head;
			oep = 0;
			found = 0;
			while (ep) {
				if (ep->evt_handle == incr) {
					/* dequeue event from event list */
					if (oep == 0) {
						ehp->e_head = ep->evt_next;
					} else {
						oep->evt_next = ep->evt_next;
					}
					if (ehp->e_tail == ep)
						ehp->e_tail = oep;
					evp = ep;
					ep = ep->evt_next;
					kfree(evp);
				} else {
					oep = ep;
					ep = ep->evt_next;
				}
			}

			/*
			 * No more fcEVT_t pointer under this fcEVTHDR_t
			 * Free the fcEVTHDR_t
			 */
			if (ehp->e_head == 0) {
				oehp = 0;
				ehp = (fcEVTHDR_t *) phba->fc_evt_head;
				while (ehp) {
					if ((ehp->e_mask == offset) &&
					    (ehp->e_type == type)) {
						found = 0;
						break;
					}
					oehp = ehp;
					ehp = (fcEVTHDR_t *) ehp->e_next_header;
				}
				if (oehp == 0) {
					phba->fc_evt_head = ehp->e_next_header;
				} else {
					oehp->e_next_header =
					    ehp->e_next_header;
				}
				if (phba->fc_evt_tail == ehp)
					phba->fc_evt_tail = oehp;

				kfree(ehp);
			}
			goto setout;
		}
		spin_lock_irqsave(phba->host->host_lock, iflag);
		ehp->e_refcnt--;
		break;
	}
setout:

	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	return (rc);
}

int
lpfc_ioctl_list_bind(struct lpfc_hba * phba,
		     LPFCCMDINPUT_t * cip, void *dataout, int *do_cp)
{

	unsigned long next_index = 0;
	unsigned long max_index = (unsigned long)cip->lpfc_arg1;
	HBA_BIND_LIST *bind_list;
	HBA_BIND_ENTRY *bind_array;
	struct lpfc_bindlist *pbdl;
	struct lpfc_nodelist *pndl;
	struct list_head *pos;
	int rc;
	unsigned long iflag;

	bind_list = (HBA_BIND_LIST *) dataout;
	bind_array = &bind_list->entry[0];

	/* Iterate through the mapped list */

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state, fc_nlpmap_list */

	list_for_each(pos, &phba->fc_nlpmap_list) {
		pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
		if (next_index >= max_index) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state, fc_nlpmap_list */
			rc = ERANGE;
			*do_cp = 0;
			return (rc);
		}

		memset(&bind_array[next_index], 0, sizeof (HBA_BIND_ENTRY));
		bind_array[next_index].scsi_id = pndl->nlp_sid;
		bind_array[next_index].did = pndl->nlp_DID;
		memcpy(&bind_array[next_index].wwpn, &pndl->nlp_portname,
		       sizeof (HBA_WWN));
		memcpy(&bind_array[next_index].wwnn, &pndl->nlp_nodename,
		       sizeof (HBA_WWN));
		if (pndl->nlp_flag & NLP_AUTOMAP)
			bind_array[next_index].flags |= HBA_BIND_AUTOMAP;
		if (pndl->nlp_flag & NLP_SEED_WWNN)
			bind_array[next_index].bind_type = BIND_WWNN;
		if (pndl->nlp_flag & NLP_SEED_WWPN)
			bind_array[next_index].bind_type = BIND_WWPN;
		if (pndl->nlp_flag & NLP_SEED_ALPA)
			bind_array[next_index].bind_type = BIND_ALPA;
		else if (pndl->nlp_flag & NLP_SEED_DID)
			bind_array[next_index].bind_type = BIND_DID;
		bind_array[next_index].flags |= HBA_BIND_MAPPED;
		if (pndl->nlp_flag & NLP_NODEV_TMO)
			bind_array[next_index].flags |= HBA_BIND_NODEVTMO;
		next_index++;
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state, fc_nlpmap_list */


	/* Iterate through the unmapped list */

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state, fc_nlpunmap_list */

	list_for_each(pos, &phba->fc_nlpunmap_list) {
		pndl = list_entry(pos, struct lpfc_nodelist, nlp_listp);
		if (next_index >= max_index) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state, fc_nlpunmap_list */
			rc = ERANGE;
			*do_cp = 0;
			return (rc);
		}

		memset(&bind_array[next_index], 0, sizeof (HBA_BIND_ENTRY));
		bind_array[next_index].did = pndl->nlp_DID;
		memcpy(&bind_array[next_index].wwpn, &pndl->nlp_portname,
		       sizeof (HBA_WWN));
		memcpy(&bind_array[next_index].wwnn, &pndl->nlp_nodename,
		       sizeof (HBA_WWN));
		bind_array[next_index].flags |= HBA_BIND_UNMAPPED;
		if (pndl->nlp_flag & NLP_TGT_NO_SCSIID)
			bind_array[next_index].flags |= HBA_BIND_NOSCSIID;
		if (pndl->nlp_flag & NLP_NODEV_TMO)
			bind_array[next_index].flags |= HBA_BIND_NODEVTMO;

		next_index++;
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state, fc_nlpunmap_list */

	/* Iterate through the bind list */

	spin_lock_irqsave(phba->host->host_lock, iflag); /* HBA state, fc_nlpbind_list */

	list_for_each(pos, &phba->fc_nlpbind_list) {
		pbdl = list_entry(pos, struct lpfc_bindlist, nlp_listp);
	
		if (next_index >= max_index) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state, fc_nlpbind_list */
			rc = ERANGE;
			*do_cp = 0;
			return (rc);
		}
		memset(&bind_array[next_index], 0, sizeof (HBA_BIND_ENTRY));
		bind_array[next_index].scsi_id = pbdl->nlp_sid;

		if (pbdl->nlp_bind_type & FCP_SEED_DID) {
			bind_array[next_index].bind_type = BIND_DID;
			bind_array[next_index].did = pbdl->nlp_DID;

		}

		if (pbdl->nlp_bind_type & FCP_SEED_WWPN) {
			bind_array[next_index].bind_type = BIND_WWPN;
			memcpy((uint8_t *) & bind_array[next_index].wwpn,
			       &pbdl->nlp_portname, sizeof (HBA_WWN));
		}

		if (pbdl->nlp_bind_type & FCP_SEED_WWNN) {
			bind_array[next_index].bind_type = BIND_WWNN;
			memcpy((uint8_t *) & bind_array[next_index].wwnn,
			       &pbdl->nlp_nodename, sizeof (HBA_WWN));
		}
		bind_array[next_index].flags |= HBA_BIND_BINDLIST;
		
		next_index++;
	}
	bind_list->NumberOfEntries = next_index;

	spin_unlock_irqrestore(phba->host->host_lock, iflag); /* HBA state, fc_nlpbind_list */

	return 0;
}

int
lpfc_ioctl_get_vpd(struct lpfc_hba * phba,
		   LPFCCMDINPUT_t * cip, void *dataout, int *do_cp)
{
	struct vpd *dp;
	int rc = 0;

	dp = (struct vpd *) dataout;

	if (cip->lpfc_arg4 != VPD_VERSION1) {
		rc = EINVAL;
		*do_cp = 1;
	}

	dp->version = VPD_VERSION1;

	memset(dp->ModelDescription, 0, 256);
	memset(dp->Model, 0, 80);
	memset(dp->ProgramType, 0, 256);
	memset(dp->PortNum, 0, 20);

	if (phba->vpd_flag & VPD_MASK) {
		if (phba->vpd_flag & VPD_MODEL_DESC) {
			memcpy(dp->ModelDescription, phba->ModelDesc, 256);
		}
		if (phba->vpd_flag & VPD_MODEL_NAME) {
			memcpy(dp->Model, phba->ModelName, 80);
		}
		if (phba->vpd_flag & VPD_PROGRAM_TYPE) {
			memcpy(dp->ProgramType, phba->ProgramType, 256);
		}
		if (phba->vpd_flag & VPD_PORT) {
			memcpy(dp->PortNum, phba->Port, 20);
		}
	}

	return rc;
}

int
lpfc_ioctl_get_dumpregion(struct lpfc_hba * phba,
		   LPFCCMDINPUT_t  * cip, void * dataout, int *do_cp)
{
	uint32_t identifier = (uint32_t)(unsigned long) cip->lpfc_arg1;
	uint32_t size = cip->lpfc_outsz;
	uint32_t * bufp = (uint32_t *) dataout;
	int rc = 0;

	switch (identifier) {
	case 0:		/* SLI Registers */
		if (size < 16) {
			rc = ENOMEM;
			*do_cp = 1;
		}
		size = 16;

		*bufp++ = readl((phba->ctrl_regs_memmap_p) + 0);
		*bufp++ = readl((phba->ctrl_regs_memmap_p) + 4);
		*bufp++ = readl((phba->ctrl_regs_memmap_p) + 8);
		*bufp++ = readl((phba->ctrl_regs_memmap_p) + 12);

		if (cip->lpfc_outsz > size)
			cip->lpfc_outsz = size;

		if (copy_to_user((uint8_t *)cip->lpfc_arg2,
				 (uint8_t *)&size, sizeof(uint32_t))) {
			rc = EIO;
		}
		break;
	case 1:		/* Board SLIM */
	case 2:		/* Port Control Block */
	case 3:		/* Mailbox in Host Memory */
	case 4:		/* Host Get/Put pointer array */
	case 5:		/* Port Get/Put pointer array */
	case 6:		/* Command/Response Ring */
	case 7:		/* DriverInternal Structures */
		rc = ENOENT;
		break;
	default:
		rc = EINVAL;
		break;
	}

	return rc;
}

int
lpfc_ioctl_get_lpfcdfc_info(struct lpfc_hba * phba,
		   LPFCCMDINPUT_t * cip, void *dataout)
{
	LPFCDFCDrvInfo *info;

	info = (LPFCDFCDrvInfo *) dataout;

	memcpy(info->version, LPFCDFC_DRIVER_VERSION, 16);
	memcpy(info->name, LPFCDFC_DRIVER_NAME, 8);
	return 0;
}

int
lpfc_ioctl_loopback_mode(struct lpfc_hba *phba,
		   LPFCCMDINPUT_t  *cip, void *dataout)
{
	struct lpfc_sli *psli = &phba->sli;
	struct lpfc_sli_ring *pring = &psli->ring[LPFC_FCP_RING];
	uint32_t link_flags = cip->lpfc_arg4;
	uint32_t timeout = cip->lpfc_arg5 * 100;
	LPFC_MBOXQ_t *pmboxq;
	int mbxstatus;
	int i = 0;
	int rc = 0;

	if ((phba->hba_state == LPFC_HBA_ERROR) ||
	    (!(psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE)))
		return EACCES;

	if ((pmboxq = mempool_alloc(phba->mbox_mem_pool,GFP_KERNEL)) == 0)
		return ENOMEM;

	scsi_block_requests(phba->host);

	while (pring->txcmplq_cnt) {
		if (i++ > 500) {	/* wait up to 5 seconds */
			break;
		}

		mdelay(10);
	}

	memset((void *)pmboxq, 0, sizeof (LPFC_MBOXQ_t));
	pmboxq->mb.mbxCommand = MBX_DOWN_LINK;
	pmboxq->mb.mbxOwner = OWN_HOST;

	mbxstatus = lpfc_sli_issue_mbox_wait(phba, pmboxq, LPFC_MBOX_TMO);

	if ((mbxstatus == MBX_SUCCESS) && (pmboxq->mb.mbxStatus == 0)) {

		/* wait for link down before proceeding */
		i = 0;
		while (phba->hba_state != LPFC_LINK_DOWN) {
			if (i++ > timeout) {
				rc = ETIMEDOUT;
				goto loopback_mode_exit;
			}
			msleep(10);
		}

		memset((void *)pmboxq, 0, sizeof (LPFC_MBOXQ_t));
		pmboxq->mb.un.varInitLnk.link_flags = link_flags;
		pmboxq->mb.mbxCommand = MBX_INIT_LINK;
		pmboxq->mb.mbxOwner = OWN_HOST;

		mbxstatus = lpfc_sli_issue_mbox_wait(phba, pmboxq,
						     LPFC_MBOX_TMO);

		if ((mbxstatus != MBX_SUCCESS) || (pmboxq->mb.mbxStatus))
			rc = ENODEV;
		else {
			/* wait for the link attention interrupt */
			msleep(100);

			i = 0;
			while (phba->hba_state != LPFC_HBA_READY) {
				if (i++ > timeout) {
					rc = ETIMEDOUT;
					break;
				}
				msleep(10);
			}
		}
	} else
		rc = ENODEV;

loopback_mode_exit:
	scsi_unblock_requests(phba->host);
	mempool_free(pmboxq, phba->mbox_mem_pool);
	return rc;
}

int
lpfc_ioctl_loopback_test(struct lpfc_hba *phba,
		   LPFCCMDINPUT_t  *cip, void *dataout)
{
	struct lpfc_sli *psli = &phba->sli;
	struct lpfc_sli_ring *pring = &psli->ring[LPFC_ELS_RING];
	struct lpfc_timedout_iocb_ctxt *iocb_ctxt;
	uint32_t size = cip->lpfc_outsz;
	LPFC_MBOXQ_t *pmboxq;
	int mbxstatus;
	uint16_t rpi;
	struct lpfc_iocbq *cmdiocbq, *rspiocbq;
	IOCB_t *cmd, *rsp;
	struct lpfc_dmabuf *txbmp, *rxbmp;
	struct ulp_bde64 *txbpl, *rxbpl;
	DMABUFEXT_t *txbuffer, *rxbuffer;
	struct list_head head, *curr, *next;
	unsigned long iflag;
	struct lpfc_dmabuf *dmp;
	struct lpfc_dmabuf *mp[2] = {0, 0};
	uint16_t txxri, rxxri;
	uint32_t num_bde;
	uint8_t *ptr;
	struct ulp_bde64 *bpl;
	int rc = 0;
	int i = 0;

	if ((phba->hba_state == LPFC_HBA_ERROR) ||
	    (!(psli->sliinit.sli_flag & LPFC_SLI2_ACTIVE))) {
		rc = EACCES;
		goto loopback_exit;
	}

	if ((size == 0) || (size > 80 * 4096)) {
		rc = ERANGE;
		goto loopback_exit;
	}

	/* Allocate mboxq structure */
	if ((pmboxq = mempool_alloc(phba->mbox_mem_pool, GFP_KERNEL)) == 0) {
		rc = ENOMEM;
		goto loopback_exit;
	}

	/* Acquire a rpi for the HBA */
	if (lpfc_reg_login(phba, phba->fc_myDID, (uint8_t *)&phba->fc_sparam,
			   pmboxq, 0)) {
		rc = ENOMEM;
		goto loopback_free_mbox;
	}

	dmp = (struct lpfc_dmabuf *) pmboxq->context1;
	pmboxq->context1 = NULL;

	mbxstatus = lpfc_sli_issue_mbox_wait(phba, pmboxq, LPFC_MBOX_TMO);
	if ((mbxstatus != MBX_SUCCESS) || (pmboxq->mb.mbxStatus)) {
		lpfc_mbuf_free(phba, dmp->virt, dmp->phys);
		kfree(dmp);
		rc = ENODEV;
		goto loopback_free_mbox;
	}

	rpi = pmboxq->mb.un.varWords[0];

	lpfc_mbuf_free(phba, dmp->virt, dmp->phys);
	kfree(dmp);

	if ((cmdiocbq = mempool_alloc(phba->iocb_mem_pool, GFP_KERNEL)) == 0) {
		rc = ENOMEM;
		goto loopback_unreg_login;
	}

	memset((void *)cmdiocbq, 0, sizeof (struct lpfc_iocbq));
	cmd = &cmdiocbq->iocb;

	if ((rspiocbq = mempool_alloc(phba->iocb_mem_pool, GFP_KERNEL)) == 0) {
		rc = ENOMEM;
		goto loopback_free_cmdiocbq;
	}

	memset((void *)rspiocbq, 0, sizeof (struct lpfc_iocbq));
	rsp = &rspiocbq->iocb;

	if ((txbmp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_KERNEL)) == 0) {
		rc = ENOMEM;
		goto loopback_free_rspiocbq;
	}

	if ((txbmp->virt = lpfc_mbuf_alloc(phba, 0, &txbmp->phys)) == 0) {
		rc = ENOMEM;
		goto loopback_free_txbmp;
	}

	INIT_LIST_HEAD(&txbmp->list);
	txbpl = (struct ulp_bde64 *) txbmp->virt;

	txbuffer = dfc_cmd_data_alloc(phba, cip->lpfc_arg1, txbpl, size);
	if (!txbuffer) {
		rc = ENOMEM;
		goto loopback_free_txvirt;
	}

	if ((rxbmp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_KERNEL)) == 0) {
		rc = ENOMEM;
		goto loopback_free_txbuffer;
	}

	if ((rxbmp->virt = lpfc_mbuf_alloc(phba, 0, &rxbmp->phys)) == 0) {
		rc = ENOMEM;
		goto loopback_free_rxbmp;
	}

	INIT_LIST_HEAD(&rxbmp->list);
	rxbpl = (struct ulp_bde64 *) rxbmp->virt;

	rxbuffer = dfc_cmd_data_alloc(phba, 0, rxbpl, size);
	if (!rxbuffer) {
		rc = ENOMEM;
		goto loopback_free_rxvirt;
	}

	phba->fc_loopback_rxxri = 0;

	/* Send initial XMIT_SEQUENCE64_CR to obtain an xri */

	if ((dmp = kmalloc(sizeof (struct lpfc_dmabuf), GFP_KERNEL)) == 0) {
		dfc_cmd_data_free(phba, rxbuffer);
		rc = ENOMEM;
		goto loopback_free_rxvirt;
	}

	if ((dmp->virt = lpfc_mbuf_alloc(phba, 0, &dmp->phys)) == 0) {
		kfree(dmp);
		dfc_cmd_data_free(phba, rxbuffer);
		rc = ENOMEM;
		goto loopback_free_rxvirt;
	}

	INIT_LIST_HEAD(&dmp->list);
	bpl = (struct ulp_bde64 *) dmp->virt;
	memset(bpl, 0, sizeof (struct ulp_bde64));

	memset((void *)cmdiocbq, 0, sizeof (struct lpfc_iocbq));
	memset((void *)rspiocbq, 0, sizeof (struct lpfc_iocbq));

	cmd->un.xseq64.bdl.addrHigh = putPaddrHigh(dmp->phys);
	cmd->un.xseq64.bdl.addrLow = putPaddrLow(dmp->phys);
	cmd->un.xseq64.bdl.bdeFlags = BUFF_TYPE_BDL;
	cmd->un.xseq64.bdl.bdeSize = sizeof(struct ulp_bde64);

	cmd->un.xseq64.w5.hcsw.Fctl = LA;
	cmd->un.xseq64.w5.hcsw.Dfctl = 0;
	cmd->un.xseq64.w5.hcsw.Rctl = FC_UNSOL_DATA;
	cmd->un.xseq64.w5.hcsw.Type = FC_VENDOR_SPECIFIC;

	cmd->ulpCommand = CMD_XMIT_SEQUENCE64_CR;
	cmd->ulpBdeCount = 1;
	cmd->ulpLe = 1;
	cmd->ulpClass = CLASS3;
	cmd->ulpContext = rpi;

	cmdiocbq->iocb_flag |= LPFC_IO_LIBDFC;
	spin_lock_irqsave(phba->host->host_lock, iflag);
	rc = lpfc_sli_issue_iocb_wait(phba, pring, cmdiocbq, rspiocbq,
				      (phba->fc_ratov * 2) + LPFC_DRVR_TIMEOUT);

	lpfc_mbuf_free(phba, dmp->virt, dmp->phys);
	kfree(dmp);

	if (rc == IOCB_TIMEDOUT) {
		dfc_cmd_data_free(phba, rxbuffer);
		mempool_free(rspiocbq, phba->iocb_mem_pool);
		iocb_ctxt = kmalloc(sizeof(struct lpfc_timedout_iocb_ctxt),
				    GFP_ATOMIC);
		if (!iocb_ctxt) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			rc = EACCES;
			goto loopback_unreg_login;
		}
		
		cmdiocbq->context1 = iocb_ctxt;
		cmdiocbq->context2 = NULL;
		iocb_ctxt->rspiocbq = NULL;
		iocb_ctxt->mp = txbmp;
		iocb_ctxt->bmp = rxbmp;
		iocb_ctxt->outdmp = NULL;
		iocb_ctxt->lpfc_cmd = NULL;
		iocb_ctxt->indmp = txbuffer;
		
		cmdiocbq->iocb_cmpl = lpfc_ioctl_timeout_iocb_cmpl;

		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		rc = EACCES;			
		goto loopback_unreg_login;
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	if ((rc != IOCB_SUCCESS) || (rsp->ulpStatus != IOCB_SUCCESS)) {
		dfc_cmd_data_free(phba, rxbuffer);
		rc = EIO;
		goto loopback_free_rxvirt;
	}

	while ((phba->fc_loopback_rxxri == 0) && (i++ < 10)) {
		msleep(10);
	}

	txxri = rsp->ulpContext;
	rxxri = phba->fc_loopback_rxxri;

	if (rxxri == 0) {
		dfc_cmd_data_free(phba, rxbuffer);
		rc = EIO;
		goto loopback_free_rxvirt;
	}

	/* Queue buffers for the receive exchange */
	num_bde = (uint32_t)rxbuffer->flag;
	dmp = &rxbuffer->dma;

	memset((void *)cmdiocbq, 0, sizeof (struct lpfc_iocbq));
	i = 0;

	INIT_LIST_HEAD(&head);
	list_add_tail(&head, &dmp->list);
	list_for_each_safe(curr, next, &head) {
		mp[i] = list_entry(curr, struct lpfc_dmabuf, list);
		list_del(curr);

		cmd->un.cont64[i].addrHigh = putPaddrHigh(mp[i]->phys);
		cmd->un.cont64[i].addrLow = putPaddrLow(mp[i]->phys);
		cmd->un.cont64[i].tus.f.bdeSize = ((DMABUFEXT_t *)mp[i])->size;
		cmd->ulpBdeCount = ++i;

		if ((--num_bde > 0) && (i < 2)) {
			continue;
		}

		cmd->ulpCommand = CMD_QUE_XRI_BUF64_CX;
		cmd->ulpLe = 1;
		cmd->ulpClass = CLASS3;
		cmd->ulpContext = rxxri;

		spin_lock_irqsave(phba->host->host_lock, iflag);
		rc = lpfc_sli_issue_iocb(phba, pring, cmdiocbq, 0);
		spin_unlock_irqrestore(phba->host->host_lock, iflag);

		if (rc == IOCB_ERROR) {
			dfc_cmd_data_free(phba, (DMABUFEXT_t *)mp[0]);
			if (mp[1])
				dfc_cmd_data_free(phba, (DMABUFEXT_t *)mp[1]);
			dmp = list_entry(next, struct lpfc_dmabuf, list);
			rc = EIO;
			goto loopback_free_dmp;
		}

		spin_lock_irqsave(phba->host->host_lock, iflag);
		lpfc_sli_ringpostbuf_put(phba, pring, mp[0]);
		if (mp[1]) {
			lpfc_sli_ringpostbuf_put(phba, pring, mp[1]);
			mp[1] = NULL;
		}
		spin_unlock_irqrestore(phba->host->host_lock, iflag);

		/* The iocb was freed by lpfc_sli_issue_iocb */
		if ((cmdiocbq = mempool_alloc(phba->iocb_mem_pool,
					      GFP_KERNEL)) == 0) {
			dmp = list_entry(next, struct lpfc_dmabuf, list);
			rc = EIO;
			goto loopback_free_dmp;
		}

		memset((void *)cmdiocbq, 0, sizeof (struct lpfc_iocbq));
		cmd = &cmdiocbq->iocb;
		i = 0;
	}
	list_del(&head);

	phba->fc_loopback_data = NULL;

	/* Build the XMIT_SEQUENCE iocb */
	memset((void *)cmdiocbq, 0, sizeof (struct lpfc_iocbq));
	memset((void *)rspiocbq, 0, sizeof (struct lpfc_iocbq));

	num_bde = (uint32_t)txbuffer->flag;

	cmd->un.xseq64.bdl.addrHigh = putPaddrHigh(txbmp->phys);
	cmd->un.xseq64.bdl.addrLow = putPaddrLow(txbmp->phys);
	cmd->un.xseq64.bdl.bdeFlags = BUFF_TYPE_BDL;
	cmd->un.xseq64.bdl.bdeSize = (num_bde * sizeof(struct ulp_bde64));

	cmd->un.xseq64.w5.hcsw.Fctl = (LS | LA);
	cmd->un.xseq64.w5.hcsw.Dfctl = 0;
	cmd->un.xseq64.w5.hcsw.Rctl = FC_UNSOL_DATA;
	cmd->un.xseq64.w5.hcsw.Type = FC_VENDOR_SPECIFIC;

	cmd->ulpCommand = CMD_XMIT_SEQUENCE64_CX;
	cmd->ulpBdeCount = 1;
	cmd->ulpLe = 1;
	cmd->ulpClass = CLASS3;
	cmd->ulpContext = txxri;

	cmdiocbq->iocb_flag |= LPFC_IO_LIBDFC;
	spin_lock_irqsave(phba->host->host_lock, iflag);
	rc = lpfc_sli_issue_iocb_wait(phba, pring, cmdiocbq, rspiocbq,
				      (phba->fc_ratov * 2) + LPFC_DRVR_TIMEOUT);

	if (rc == IOCB_TIMEDOUT) {
		mempool_free(rspiocbq, phba->iocb_mem_pool);
		iocb_ctxt = kmalloc(sizeof(struct lpfc_timedout_iocb_ctxt),
				    GFP_ATOMIC);
		if (!iocb_ctxt) {
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			rc = EACCES;
			goto loopback_unreg_login;
		}
		
		cmdiocbq->context1 = iocb_ctxt;
		cmdiocbq->context2 = NULL;
		iocb_ctxt->rspiocbq = NULL;
		iocb_ctxt->mp = txbmp;
		iocb_ctxt->bmp = rxbmp;
		iocb_ctxt->outdmp = NULL;
		iocb_ctxt->lpfc_cmd = NULL;
		iocb_ctxt->indmp = txbuffer;
		
		cmdiocbq->iocb_cmpl = lpfc_ioctl_timeout_iocb_cmpl;

		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		rc = EACCES;			
		goto loopback_unreg_login;
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	if ((rc != IOCB_SUCCESS) || (rsp->ulpStatus != IOCB_SUCCESS)) {
		rc = EIO;
		goto loopback_free_rxvirt;
	}

	i = 0;
	while ((phba->fc_loopback_data == 0) && (i++ < 10)) {
		msleep(10);
	}

	/* copy the received payload */
	ptr = dataout;
	dmp = phba->fc_loopback_data;
	phba->fc_loopback_data = NULL;

	if (dmp == NULL) {
		rc = EIO;
		goto loopback_free_rxvirt;
	}

	INIT_LIST_HEAD(&head);
	list_add_tail(&head, &dmp->list);
	list_for_each_safe(curr, next, &head) {
		dmp = list_entry(curr, struct lpfc_dmabuf, list);
		memcpy(ptr, dmp->virt, ((DMABUFEXT_t *)dmp)->size);
		ptr += ((DMABUFEXT_t *)dmp)->size;
	}
	list_del(&head);

loopback_free_dmp:
	dfc_cmd_data_free(phba, (DMABUFEXT_t *)dmp);
loopback_free_rxvirt:
	lpfc_mbuf_free(phba, rxbmp->virt, rxbmp->phys);
loopback_free_rxbmp:
	kfree(rxbmp);
loopback_free_txbuffer:
	dfc_cmd_data_free(phba, txbuffer);
loopback_free_txvirt:
	lpfc_mbuf_free(phba, txbmp->virt, txbmp->phys);
loopback_free_txbmp:
	kfree(txbmp);
loopback_free_rspiocbq:
	mempool_free(rspiocbq, phba->iocb_mem_pool);
loopback_free_cmdiocbq:
	if (cmdiocbq)
		mempool_free(cmdiocbq, phba->iocb_mem_pool);
loopback_unreg_login:
	lpfc_unreg_login(phba, rpi, pmboxq);
	mbxstatus = lpfc_sli_issue_mbox_wait(phba, pmboxq, LPFC_MBOX_TMO);
	if ((mbxstatus != MBX_SUCCESS) || (pmboxq->mb.mbxStatus)) {
		rc = EIO;
	}
loopback_free_mbox:
	mempool_free(pmboxq, phba->mbox_mem_pool);
loopback_exit:
	return (rc);
}

int
dfc_rsp_data_copy(struct lpfc_hba * phba,
		  uint8_t * outdataptr, DMABUFEXT_t * mlist, uint32_t size)
{
	DMABUFEXT_t *mlast = 0;
	int cnt, offset = 0;
	struct list_head head, *curr, *next;

	if (!mlist)
		return(0);

	list_add_tail(&head, &mlist->dma.list);

	list_for_each_safe(curr, next, &head) {
		mlast = list_entry(curr, DMABUFEXT_t , dma.list);
		if (!size)
			break;

		/* We copy chucks of 4K */
		if (size > 4096)
			cnt = 4096;
		else
			cnt = size;

		if (outdataptr) {
			pci_dma_sync_single_for_device(phba->pcidev,
			    mlast->dma.phys, LPFC_BPL_SIZE, PCI_DMA_TODEVICE);

			/* Copy data to user space */
			if (copy_to_user
			    ((uint8_t *) (outdataptr + offset),
			     (uint8_t *) mlast->dma.virt, (ulong) cnt)) {
				return (1);
			}
		}
		offset += cnt;
		size -= cnt;
	}
	list_del(&head);
	return (0);
}

DMABUFEXT_t *
dfc_cmd_data_alloc(struct lpfc_hba * phba,
		   char *indataptr, struct ulp_bde64 * bpl, uint32_t size)
{
	DMABUFEXT_t *mlist = 0;
	DMABUFEXT_t *dmp;
	int cnt, offset = 0, i = 0;
	struct pci_dev *pcidev;

	pcidev = phba->pcidev;

	while (size) {
		/* We get chucks of 4K */
		if (size > 4096)
			cnt = 4096;
		else
			cnt = size;

		/* allocate DMABUFEXT_t buffer header */
		dmp = kmalloc(sizeof (DMABUFEXT_t), GFP_KERNEL);
		if ( dmp == 0 ) {
			goto out;
		}

		INIT_LIST_HEAD(&dmp->dma.list);

		/* Queue it to a linked list */
		if (mlist)
			list_add_tail(&dmp->dma.list, &mlist->dma.list);
		else
			mlist = dmp;

		/* allocate buffer */
		dmp->dma.virt = dma_alloc_coherent(&pcidev->dev, 
						   cnt, 
						   &(dmp->dma.phys), 
						   GFP_KERNEL);

		if (dmp->dma.virt == 0) {
			goto out;
		}
		dmp->size = cnt;

		if (indataptr) {
			/* Copy data from user space in */
			if (copy_from_user
			    ((uint8_t *) dmp->dma.virt,
			     (uint8_t *) (indataptr + offset), (ulong) cnt)) {
				goto out;
			}
			bpl->tus.f.bdeFlags = 0;

			pci_dma_sync_single_for_device(phba->pcidev,
			        dmp->dma.phys, LPFC_BPL_SIZE, PCI_DMA_TODEVICE);

		} else {
			memset((uint8_t *)dmp->dma.virt, 0, cnt);
			bpl->tus.f.bdeFlags = BUFF_USE_RCV;
		}

		/* build buffer ptr list for IOCB */
		bpl->addrLow = le32_to_cpu( putPaddrLow(dmp->dma.phys) );
		bpl->addrHigh = le32_to_cpu( putPaddrHigh(dmp->dma.phys) );
		bpl->tus.f.bdeSize = (ushort) cnt;
		bpl->tus.w = le32_to_cpu(bpl->tus.w);
		bpl++;

		i++;
		offset += cnt;
		size -= cnt;
	}

	mlist->flag = i;
	return (mlist);
out:
	dfc_cmd_data_free(phba, mlist);
	return (0);
}

int
dfc_cmd_data_free(struct lpfc_hba * phba, DMABUFEXT_t * mlist)
{
	DMABUFEXT_t *mlast;
	struct pci_dev *pcidev;
	struct list_head head, *curr, *next;

	if (!mlist)
		return(0);

	pcidev = phba->pcidev;
	list_add_tail(&head, &mlist->dma.list);

	list_for_each_safe(curr, next, &head) {
		mlast = list_entry(curr, DMABUFEXT_t , dma.list);
		if (mlast->dma.virt) {

			dma_free_coherent(&pcidev->dev, 
					  mlast->size, 
					  mlast->dma.virt, 
					  mlast->dma.phys);

		}
		kfree(mlast);
	}
	return (0);
}

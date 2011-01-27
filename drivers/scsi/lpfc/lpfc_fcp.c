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
 * $Id: lpfc_fcp.c 2905 2006-04-13 17:11:39Z sf_support $
 */

#include <linux/version.h>
#include <linux/config.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/utsname.h>

#include <asm/byteorder.h>

#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_transport_fc.h>

#include "lpfc_sli.h"
#include "lpfc_disc.h"
#include "lpfc_scsi.h"
#include "lpfc.h"
#include "lpfc_fcp.h"
#include "lpfc_hw.h"
#include "lpfc_logmsg.h"
#include "lpfc_mem.h"
#include "lpfc_version.h"
#include "lpfc_crtn.h"
#include "lpfc_compat.h"

static char *lpfc_drvr_name = LPFC_DRIVER_NAME;

static struct scsi_transport_template *lpfc_transport_template = NULL;

static struct list_head lpfc_hba_list = LIST_HEAD_INIT(lpfc_hba_list);

static const char *
lpfc_info(struct Scsi_Host *host)
{
	struct lpfc_hba    *phba = (struct lpfc_hba *) host->hostdata[0];
	int len;
	static char  lpfcinfobuf[384];

	memset(lpfcinfobuf,0,384);
	if (phba && phba->pcidev){
		strncpy(lpfcinfobuf, phba->ModelDesc, 256);
		len = strlen(lpfcinfobuf);
		snprintf(lpfcinfobuf + len,
			384-len,
	       		" on PCI bus %02x device %02x irq %d",
			phba->pcidev->bus->number,
		 	phba->pcidev->devfn,
			phba->pcidev->irq);
		len = strlen(lpfcinfobuf);
		if (phba->Port[0]) {
			snprintf(lpfcinfobuf + len,
				 384-len,
				 " port %s",
				 phba->Port);
		}
	}
	return lpfcinfobuf;
}

static void
lpfc_jedec_to_ascii(int incr, char hdw[])
{
	int i, j;
	for (i = 0; i < 8; i++) {
		j = (incr & 0xf);
		if (j <= 9)
			hdw[7 - i] = 0x30 +  j;
		 else
			hdw[7 - i] = 0x61 + j - 10;
		incr = (incr >> 4);
	}
	hdw[8] = 0;
	return;
}

static ssize_t
lpfc_drvr_version_show(struct class_device *cdev, char *buf)
{
	return snprintf(buf, PAGE_SIZE, LPFC_MODULE_DESC "\n");
}

static ssize_t
management_version_show(struct class_device *cdev, char *buf)
{
	return snprintf(buf, PAGE_SIZE, DFC_API_VERSION "\n");
}

static ssize_t
lpfc_info_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	return snprintf(buf, PAGE_SIZE, "%s\n",lpfc_info(host));
}

static ssize_t
lpfc_serialnum_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	return snprintf(buf, PAGE_SIZE, "%s\n",phba->SerialNumber);
}

static ssize_t
lpfc_modeldesc_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	return snprintf(buf, PAGE_SIZE, "%s\n",phba->ModelDesc);
}

static ssize_t
lpfc_modelname_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	return snprintf(buf, PAGE_SIZE, "%s\n",phba->ModelName);
}

static ssize_t
lpfc_programtype_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	return snprintf(buf, PAGE_SIZE, "%s\n",phba->ProgramType);
}

static ssize_t
lpfc_portnum_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	return snprintf(buf, PAGE_SIZE, "%s\n",phba->Port);
}

static ssize_t
lpfc_fwrev_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	char fwrev[32];
	lpfc_decode_firmware_rev(phba, fwrev, 1);
	return snprintf(buf, PAGE_SIZE, "%s\n",fwrev);
}

static ssize_t
lpfc_hdw_show(struct class_device *cdev, char *buf)
{
	char hdw[9];
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	lpfc_vpd_t *vp = &phba->vpd;
	lpfc_jedec_to_ascii(vp->rev.biuRev, hdw);
	return snprintf(buf, PAGE_SIZE, "%s\n", hdw);
}
static ssize_t
lpfc_option_rom_version_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	return snprintf(buf, PAGE_SIZE, "%s\n", phba->OptionROMVersion);
}
static ssize_t
lpfc_state_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	int len = 0;
	switch (phba->hba_state) {
	case LPFC_STATE_UNKNOWN:
	case LPFC_WARM_START:
	case LPFC_INIT_START:
	case LPFC_INIT_MBX_CMDS:
	case LPFC_LINK_DOWN:
		len += snprintf(buf + len, PAGE_SIZE-len, "Link Down\n");
		break;
	case LPFC_LINK_UP:
	case LPFC_LOCAL_CFG_LINK:
		len += snprintf(buf + len, PAGE_SIZE-len, "Link Up\n");
		break;
	case LPFC_FLOGI:
	case LPFC_FABRIC_CFG_LINK:
	case LPFC_NS_REG:
	case LPFC_NS_QRY:
	case LPFC_BUILD_DISC_LIST:
	case LPFC_DISC_AUTH:
	case LPFC_CLEAR_LA:
		len += snprintf(buf + len, PAGE_SIZE-len,
				"Link Up - Discovery\n");
		break;
	case LPFC_HBA_READY:
		len += snprintf(buf + len, PAGE_SIZE-len,
				"Link Up - Ready:\n");
		if (phba->fc_topology == TOPOLOGY_LOOP) {
			if (phba->fc_flag & FC_PUBLIC_LOOP)
				len += snprintf(buf + len, PAGE_SIZE-len,
						"   Public Loop\n");
			else
				len += snprintf(buf + len, PAGE_SIZE-len,
						"   Private Loop\n");
		} else {
			if (phba->fc_flag & FC_FABRIC)
				len += snprintf(buf + len, PAGE_SIZE-len,
						"   Fabric\n");
			else
				len += snprintf(buf + len, PAGE_SIZE-len,
						"   Point-2-Point\n");
		}
	}
	return len;
}

static ssize_t
lpfc_num_discovered_ports_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	return snprintf(buf, PAGE_SIZE, "%d\n", phba->fc_map_cnt +
							phba->fc_unmap_cnt);
}

/*
 * These are replaced by Generic FC transport attributes
 */
static ssize_t
lpfc_speed_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	int len = 0;
	if (phba->fc_linkspeed == LA_4GHZ_LINK)
		len += snprintf(buf + len, PAGE_SIZE-len, "4 Gigabit\n");
	else
	if (phba->fc_linkspeed == LA_2GHZ_LINK)
		len += snprintf(buf + len, PAGE_SIZE-len, "2 Gigabit\n");
	else
	if (phba->fc_linkspeed == LA_1GHZ_LINK)
		len += snprintf(buf + len, PAGE_SIZE-len, "1 Gigabit\n");
	else
		len += snprintf(buf + len, PAGE_SIZE-len, "Unknown\n");
	return len;
}

static ssize_t
lpfc_node_name_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	uint64_t node_name = 0;
	memcpy (&node_name, &phba->fc_nodename, sizeof (struct lpfc_name));
	return snprintf(buf, PAGE_SIZE, "0x%llx\n",
				(unsigned long long) be64_to_cpu(node_name));
}
static ssize_t
lpfc_port_name_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	uint64_t port_name = 0;
	memcpy (&port_name, &phba->fc_portname, sizeof (struct lpfc_name));
	return snprintf(buf, PAGE_SIZE, "0x%llx\n",
				(unsigned long long) be64_to_cpu(port_name));
}
static ssize_t
lpfc_did_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	return snprintf(buf, PAGE_SIZE, "0x%x\n", phba->fc_myDID);
}

static ssize_t
lpfc_port_type_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];

	size_t retval = -EPERM;

	if (phba->fc_topology == TOPOLOGY_LOOP) {
		if (phba->fc_flag & FC_PUBLIC_LOOP)
			retval = snprintf(buf, PAGE_SIZE, "NL_Port\n");
		else
		        retval = snprintf(buf, PAGE_SIZE, "L_Port\n");
	} else {
		if (phba->fc_flag & FC_FABRIC)
			retval = snprintf(buf, PAGE_SIZE, "N_Port\n");
		else
			retval = snprintf(buf, PAGE_SIZE,
					  "Point-to-Point N_Port\n");
	}

	return retval;
}

static ssize_t
lpfc_fabric_name_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	uint64_t node_name = 0;
	memcpy (&node_name, &phba->fc_nodename, sizeof (struct lpfc_name));

	if ((phba->fc_flag & FC_FABRIC) ||
	    ((phba->fc_topology == TOPOLOGY_LOOP) &&
	     (phba->fc_flag & FC_PUBLIC_LOOP))) {
			memcpy(&node_name,
			       & phba->fc_fabparam.nodeName,
			       sizeof (struct lpfc_name));
	}

	return snprintf(buf, PAGE_SIZE, "0x%08llx\n",
				(unsigned long long) be64_to_cpu(node_name));
}

static ssize_t
lpfc_events_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	int i = 0, len = 0, get = phba->hba_event_put;
	struct lpfc_hba_event *rec;

	if (get == phba->hba_event_get)
		 return snprintf(buf, PAGE_SIZE, "None\n");

	for (i = 0; i < MAX_HBAEVT; i++) {
		if (get == 0)
			get = MAX_HBAEVT;
		get--;
		rec = &phba->hbaevt[get];
		switch (rec->fc_eventcode) {
			case 0:
				len += snprintf(buf+len, PAGE_SIZE-len,
						"---------");
				break;
			case HBA_EVENT_RSCN:
				len += snprintf(buf+len, PAGE_SIZE-len,
						"RSCN     ");
				break;
			case HBA_EVENT_LINK_UP:
				len += snprintf(buf+len, PAGE_SIZE-len,
						 "LINK UP  ");
				break;
			case HBA_EVENT_LINK_DOWN:
				len += snprintf(buf+len, PAGE_SIZE-len,
							"LINK DOWN");
				break;
			default:
				len += snprintf(buf+len, PAGE_SIZE-len,
						"?????????");
				break;

		}
		len += snprintf(buf+len, PAGE_SIZE-len, " %d,%d,%d,%d\n",
				 rec->fc_evdata1, rec->fc_evdata2,
				 rec->fc_evdata3, rec->fc_evdata4);
	}
	return len;
}

static int
__lpfc_issue_lip(struct lpfc_hba *phba)
{
	LPFC_MBOXQ_t *pmboxq;
	int mbxstatus = MBXERR_ERROR;

	if ((phba->fc_flag & FC_OFFLINE_MODE) ||
	    (phba->hba_state != LPFC_HBA_READY))
		return -EPERM;

	pmboxq = mempool_alloc(phba->mbox_mem_pool,GFP_KERNEL);

	if (!pmboxq)
		return -ENOMEM;

	memset((void *)pmboxq, 0, sizeof (LPFC_MBOXQ_t));
	lpfc_init_link(phba, pmboxq, phba->cfg_topology, phba->cfg_link_speed);
	mbxstatus = lpfc_sli_issue_mbox_wait(phba, pmboxq, phba->fc_ratov * 2);

	if (mbxstatus == MBX_TIMEOUT)
		pmboxq->mbox_cmpl = lpfc_sli_def_mbox_cmpl;
	else
		mempool_free( pmboxq, phba->mbox_mem_pool);

	if (mbxstatus == MBXERR_ERROR)
		return -EIO;

	return 0;
}

/*
 * backwards compat scsi host issue lip attr
 */
static ssize_t
lpfc_issue_lip (struct class_device *cdev, const char *buf, size_t count)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba *) host->hostdata[0];
 	int val = 0, err;

 	if ((sscanf(buf, "%d", &val) != 1) ||
	    (val != 1))
		return -EINVAL;

	err = __lpfc_issue_lip(phba);
	if (err)
		return err;

	return strlen(buf);
}

#ifdef RHEL_U3_FC_XPORT
/*
 * fc class host issue lip attr
 */
static int
lpfc_issue_fc_host_lip(struct Scsi_Host *host)
{
	struct lpfc_hba *phba = (struct lpfc_hba *) host->hostdata[0];
	return __lpfc_issue_lip(phba);
}
#endif

static ssize_t
lpfc_nport_evt_cnt_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	return snprintf(buf, PAGE_SIZE, "%d\n", phba->nport_event_cnt);
}

static ssize_t
lpfc_board_online_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];

	if (!phba) return -EPERM;

	if (phba->fc_flag & FC_OFFLINE_MODE)
		return snprintf(buf, PAGE_SIZE, "0\n");
	else
		return snprintf(buf, PAGE_SIZE, "1\n");
}

static ssize_t
lpfc_board_online_store(struct class_device *cdev, const char *buf,
								size_t count)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
 	int val=0;

	if (!phba) return -EPERM;

 	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (val && (phba->fc_flag & FC_OFFLINE_MODE)) {
		lpfc_online(phba);
	}
	else if (!val && !(phba->fc_flag & FC_OFFLINE_MODE)) {
		lpfc_offline(phba);
		lpfc_sli_brdrestart(phba);
	}

	return strlen(buf);
}

static int
lpfc_disc_ndlp_show(struct lpfc_hba * phba, struct lpfc_nodelist *ndlp,
			char *buf, int offset)
{
	int len = 0, pgsz = PAGE_SIZE;
	uint8_t name[sizeof (struct lpfc_name)];

	buf += offset;
	pgsz -= offset;
	len += snprintf(buf + len, pgsz -len,
			"DID %06x WWPN ", ndlp->nlp_DID);

	/* A Fibre Channel node or port name is 8 octets
	 * long and delimited by colons.
	 */
	memcpy (&name[0], &ndlp->nlp_portname,
		sizeof (struct lpfc_name));
	len += snprintf(buf + len, pgsz-len,
			"%02x:%02x:%02x:%02x:%02x:%02x:"
			"%02x:%02x",
			name[0], name[1], name[2],
			name[3], name[4], name[5],
			name[6], name[7]);

	len += snprintf(buf + len, pgsz-len,
			" WWNN ");
	memcpy (&name[0], &ndlp->nlp_nodename,
		sizeof (struct lpfc_name));
	len += snprintf(buf + len, pgsz-len,
			"%02x:%02x:%02x:%02x:%02x:%02x:"
			"%02x:%02x\n",
			name[0], name[1], name[2],
			name[3], name[4], name[5],
			name[6], name[7]);
	len += snprintf(buf + len, pgsz-len,
			"    INFO %02x:%08x:%02x:%02x:%02x:%02x:"
			"%02x:%02x:%02x\n",
			ndlp->nlp_state, ndlp->nlp_flag, ndlp->nlp_type,
			ndlp->nlp_rpi, ndlp->nlp_sid, ndlp->nlp_failMask,
			ndlp->nlp_retry, ndlp->nlp_disc_refcnt,
			ndlp->nlp_fcp_info);
	return len;
}

#define LPFC_MAX_SYS_DISC_ENTRIES 35

static ssize_t
lpfc_disc_npr_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	struct lpfc_nodelist  *ndlp, *next_ndlp;
	struct list_head *listp;
	unsigned long iflag;
	int i = 0, len = 0;

	if (!phba) return -EPERM;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	listp = &phba->fc_npr_list;
	if (list_empty(listp)) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return snprintf(buf, PAGE_SIZE, "NPR    list: Empty\n");
	}

	len += snprintf(buf+len, PAGE_SIZE-len, "NPR    list: %d Entries\n",
		phba->fc_npr_cnt);
	list_for_each_entry_safe(ndlp, next_ndlp, listp, nlp_listp) {
		i++;
		if(i > LPFC_MAX_SYS_DISC_ENTRIES) {
			len += snprintf(buf+len, PAGE_SIZE-len,
			"Missed %d entries - sysfs %ld limit exceeded\n",
			(phba->fc_npr_cnt - i + 1), PAGE_SIZE);
			break;
		}
		if(len > (PAGE_SIZE-1))  /* double check */
			break;
		len += lpfc_disc_ndlp_show(phba, ndlp, buf, len);
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return len;
}

static ssize_t
lpfc_disc_map_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	struct lpfc_nodelist  *ndlp, *next_ndlp;
	struct list_head *listp;
	unsigned long iflag;
	int i = 0, len = 0;

	if (!phba) return -EPERM;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	listp = &phba->fc_nlpmap_list;
	if (list_empty(listp)) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return snprintf(buf, PAGE_SIZE, "Map    list: Empty\n");
	}

	len += snprintf(buf+len, PAGE_SIZE-len, "Map    list: %d Entries\n",
		phba->fc_map_cnt);
	list_for_each_entry_safe(ndlp, next_ndlp, listp, nlp_listp) {
		i++;
		if(i > LPFC_MAX_SYS_DISC_ENTRIES) {
			len += snprintf(buf+len, PAGE_SIZE-len,
			"Missed %d entries - sysfs %ld limit exceeded\n",
			(phba->fc_map_cnt - i + 1), PAGE_SIZE);
			break;
		}
		if(len > (PAGE_SIZE-1))  /* double check */
			break;
		len += lpfc_disc_ndlp_show(phba, ndlp, buf, len);
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return len;
}

static ssize_t
lpfc_disc_unmap_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	struct lpfc_nodelist  *ndlp, *next_ndlp;
	struct list_head *listp;
	unsigned long iflag;
	int i = 0, len = 0;

	if (!phba) return -EPERM;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	listp = &phba->fc_nlpunmap_list;
	if (list_empty(listp)) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return snprintf(buf, PAGE_SIZE, "Unmap  list: Empty\n");
	}

	len += snprintf(buf+len, PAGE_SIZE-len, "Unmap  list: %d Entries\n",
		phba->fc_unmap_cnt);
	list_for_each_entry_safe(ndlp, next_ndlp, listp, nlp_listp) {
		i++;
		if(i > LPFC_MAX_SYS_DISC_ENTRIES) {
			len += snprintf(buf+len, PAGE_SIZE-len,
			"Missed %d entries - sysfs %ld limit exceeded\n",
			(phba->fc_unmap_cnt - i + 1), PAGE_SIZE);
			break;
		}
		if(len > (PAGE_SIZE-1))  /* double check */
			break;
		len += lpfc_disc_ndlp_show(phba, ndlp, buf, len);
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return len;
}

static ssize_t
lpfc_disc_prli_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	struct lpfc_nodelist  *ndlp, *next_ndlp;
	struct list_head *listp;
	unsigned long iflag;
	int i = 0, len = 0;

	if (!phba) return -EPERM;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	listp = &phba->fc_prli_list;
	if (list_empty(listp)) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return snprintf(buf, PAGE_SIZE, "PRLI   list: Empty\n");
	}

	len += snprintf(buf+len, PAGE_SIZE-len, "PRLI   list: %d Entries\n",
		phba->fc_prli_cnt);
	list_for_each_entry_safe(ndlp, next_ndlp, listp, nlp_listp) {
		i++;
		if(i > LPFC_MAX_SYS_DISC_ENTRIES) {
			len += snprintf(buf+len, PAGE_SIZE-len,
			"Missed %d entries - sysfs %ld limit exceeded\n",
			(phba->fc_prli_cnt - i + 1), PAGE_SIZE);
			break;
		}
		if(len > (PAGE_SIZE-1))  /* double check */
			break;
		len += lpfc_disc_ndlp_show(phba, ndlp, buf, len);
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return len;
}

static ssize_t
lpfc_disc_reglgn_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	struct lpfc_nodelist  *ndlp, *next_ndlp;
	struct list_head *listp;
	unsigned long iflag;
	int i = 0, len = 0;

	if (!phba) return -EPERM;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	listp = &phba->fc_reglogin_list;
	if (list_empty(listp)) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return snprintf(buf, PAGE_SIZE, "RegLgn list: Empty\n");
	}

	len += snprintf(buf+len, PAGE_SIZE-len, "RegLgn list: %d Entries\n",
		phba->fc_reglogin_cnt);
	list_for_each_entry_safe(ndlp, next_ndlp, listp, nlp_listp) {
		i++;
		if(i > LPFC_MAX_SYS_DISC_ENTRIES) {
			len += snprintf(buf+len, PAGE_SIZE-len,
			"Missed %d entries - sysfs %ld limit exceeded\n",
			(phba->fc_reglogin_cnt - i + 1), PAGE_SIZE);
			break;
		}
		if(len > (PAGE_SIZE-1))  /* double check */
			break;
		len += lpfc_disc_ndlp_show(phba, ndlp, buf, len);
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return len;
}

static ssize_t
lpfc_disc_adisc_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	struct lpfc_nodelist  *ndlp, *next_ndlp;
	struct list_head *listp;
	unsigned long iflag;
	int i = 0, len = 0;

	if (!phba) return -EPERM;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	listp = &phba->fc_adisc_list;
	if (list_empty(listp)) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return snprintf(buf, PAGE_SIZE, "ADISC  list: Empty\n");
	}

	len += snprintf(buf+len, PAGE_SIZE-len, "ADISC  list: %d Entries\n",
		phba->fc_adisc_cnt);
	list_for_each_entry_safe(ndlp, next_ndlp, listp, nlp_listp) {
		i++;
		if(i > LPFC_MAX_SYS_DISC_ENTRIES) {
			len += snprintf(buf+len, PAGE_SIZE-len,
			"Missed %d entries - sysfs %ld limit exceeded\n",
			(phba->fc_adisc_cnt - i + 1), PAGE_SIZE);
			break;
		}
		if(len > (PAGE_SIZE-1))  /* double check */
			break;
		len += lpfc_disc_ndlp_show(phba, ndlp, buf, len);
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return len;
}

static ssize_t
lpfc_disc_plogi_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	struct lpfc_nodelist  *ndlp, *next_ndlp;
	struct list_head *listp;
	unsigned long iflag;
	int i = 0, len = 0;

	if (!phba) return -EPERM;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	listp = &phba->fc_plogi_list;
	if (list_empty(listp)) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return snprintf(buf, PAGE_SIZE, "PLOGI  list: Empty\n");
	}

	len += snprintf(buf+len, PAGE_SIZE-len, "PLOGI  list: %d Entries\n",
		phba->fc_plogi_cnt);
	list_for_each_entry_safe(ndlp, next_ndlp, listp, nlp_listp) {
		i++;
		if(i > LPFC_MAX_SYS_DISC_ENTRIES) {
			len += snprintf(buf+len, PAGE_SIZE-len,
			"Missed %d entries - sysfs %ld limit exceeded\n",
			(phba->fc_plogi_cnt - i + 1), PAGE_SIZE);
			break;
		}
		if(len > (PAGE_SIZE-1))  /* double check */
			break;
		len += lpfc_disc_ndlp_show(phba, ndlp, buf, len);
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return len;
}

static ssize_t
lpfc_disc_unused_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	struct lpfc_nodelist  *ndlp, *next_ndlp;
	struct list_head *listp;
	unsigned long iflag;
	int i = 0, len = 0;

	if (!phba) return -EPERM;

	spin_lock_irqsave(phba->host->host_lock, iflag);
	listp = &phba->fc_unused_list;
	if (list_empty(listp)) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return snprintf(buf, PAGE_SIZE, "Unused list: Empty\n");
	}

	len += snprintf(buf+len, PAGE_SIZE-len, "Unused list: %d Entries\n",
		phba->fc_unused_cnt);
	list_for_each_entry_safe(ndlp, next_ndlp, listp, nlp_listp) {
		i++;
		if(i > LPFC_MAX_SYS_DISC_ENTRIES) {
			len += snprintf(buf+len, PAGE_SIZE-len,
			"Missed %d entries - sysfs %ld limit exceeded\n",
			(phba->fc_unused_cnt - i + 1), PAGE_SIZE);
			break;
		}
		if(len > (PAGE_SIZE-1))  /* double check */
			break;
		len += lpfc_disc_ndlp_show(phba, ndlp, buf, len);
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return len;
}

#define LPFC_MAX_SYS_OUTFCPIO_ENTRIES 50

static ssize_t
lpfc_outfcpio_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *host = class_to_shost(cdev);
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	struct lpfc_sli      *psli;
	struct lpfc_sli_ring *pring;
	struct lpfc_target   *targetp;
	struct lpfc_nodelist *ndlp;
	struct lpfc_scsi_buf *lpfc_cmd;
	struct list_head *curr, *next;
	struct lpfc_iocbq *iocb;
	struct lpfc_iocbq *next_iocb;
	IOCB_t *cmd;
	unsigned long iflag;
	int i = 0, len = 0;
	int cnt = 0, unused = 0, total = 0;
	int tx_count, txcmpl_count;

	if (!phba) return -EPERM;
	psli = &phba->sli;
	pring = &psli->ring[psli->fcp_ring];


	spin_lock_irqsave(phba->host->host_lock, iflag);

	for(i=0;i<LPFC_MAX_TARGET;i++) {
		targetp = phba->device_queue_hash[i];
		if(targetp) {
			if(cnt >= LPFC_MAX_SYS_OUTFCPIO_ENTRIES) {
				unused++;
				continue;
			}
			cnt++;
			len += snprintf(buf+len, PAGE_SIZE-len,
				"ID %03d:qcmd %08x done %08x err %08x "
				"slv %03x ", targetp->scsi_id, targetp->qcmdcnt,
				targetp->iodonecnt, targetp->errorcnt,
				targetp->slavecnt);
			total += (targetp->qcmdcnt - targetp->iodonecnt);

			tx_count = 0;
			txcmpl_count = 0;

			/* Count I/Os on txq and txcmplq. */
			list_for_each_safe(curr, next, &pring->txq) {
				next_iocb = list_entry(curr, struct lpfc_iocbq,
					list);
				iocb = next_iocb;
				cmd = &iocb->iocb;

				/* Must be a FCP command */
				if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
				    (cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
				    (cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
					continue;
				}

				/* context1 MUST be a struct lpfc_scsi_buf */
				lpfc_cmd =
				    (struct lpfc_scsi_buf *) (iocb->context1);
				if ((lpfc_cmd == 0)
				    || (lpfc_cmd->target->scsi_id !=
					targetp->scsi_id)) {
					continue;
				}
				tx_count++;
			}

			/* Next check the txcmplq */
			list_for_each_safe(curr, next, &pring->txcmplq) {
				next_iocb = list_entry(curr, struct lpfc_iocbq,
					list);
				iocb = next_iocb;
				cmd = &iocb->iocb;

				/* Must be a FCP command */
				if ((cmd->ulpCommand != CMD_FCP_ICMND64_CR) &&
				    (cmd->ulpCommand != CMD_FCP_IWRITE64_CR) &&
				    (cmd->ulpCommand != CMD_FCP_IREAD64_CR)) {
					continue;
				}

				/* context1 MUST be a struct lpfc_scsi_buf */
				lpfc_cmd =
				    (struct lpfc_scsi_buf *) (iocb->context1);
				if ((lpfc_cmd == 0)
				    || (lpfc_cmd->target->scsi_id !=
					targetp->scsi_id)) {
					continue;
				}

				txcmpl_count++;
			}
			len += snprintf(buf+len, PAGE_SIZE-len,
				"tx %04x txc %04x ",
				tx_count, txcmpl_count);

			ndlp = targetp->pnode;
			if(ndlp == NULL) {
				len += snprintf(buf+len, PAGE_SIZE-len,
					"DISAPPEARED\n");
			}
			else {
				if(ndlp->nlp_state == NLP_STE_MAPPED_NODE) {
					len += snprintf(buf+len, PAGE_SIZE-len,
						"MAPPED\n");
				}
				else {
					len += snprintf(buf+len, PAGE_SIZE-len,
						"RECOVERY (%d)\n",
						ndlp->nlp_state);
				}
			}
		}
		if(len > (PAGE_SIZE-1))  /* double check */
			break;
	}
	if(unused) {
		len += snprintf(buf+len, PAGE_SIZE-len,
		"Missed x%x entries - sysfs %ld limit exceeded\n",
		unused, PAGE_SIZE);
	}
	len += snprintf(buf+len, PAGE_SIZE-len,
		"x%x total I/Os outstanding\n", total);

	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	return len;
}

#define lpfc_param_show(attr)	\
static ssize_t \
lpfc_##attr##_show(struct class_device *cdev, char *buf) \
{ \
 	struct Scsi_Host *host = class_to_shost(cdev);\
 	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];\
 	int val = 0;\
 	if (phba){\
 		val = phba->cfg_##attr;\
 		return snprintf(buf, PAGE_SIZE, "%d\n",\
 				phba->cfg_##attr);\
 	}\
 	return -EPERM;\
}

#define lpfc_param_init(attr, default, minval, maxval)	\
static int \
lpfc_##attr##_init(struct lpfc_hba *phba, int val) \
{ \
 	if (val >= minval && val <= maxval) {\
 		phba->cfg_##attr = val;\
 		return 0;\
 	}\
	lpfc_printf_log(phba, KERN_ERR, LOG_INIT, \
			"%d:0449 lpfc_"#attr" attribute cannot be set to %d, "\
			"allowed range is ["#minval", "#maxval"]\n", \
			phba->brd_no, val); \
 	phba->cfg_##attr = default;\
 	return -EINVAL;\
}

#define lpfc_param_set(attr, default, minval, maxval)	\
static int \
lpfc_##attr##_set(struct lpfc_hba *phba, int val) \
{ \
 	if (val >= minval && val <= maxval) {\
 		phba->cfg_##attr = val;\
 		return 0;\
 	}\
	lpfc_printf_log(phba, KERN_ERR, LOG_INIT, \
			"%d:0450 lpfc_"#attr" attribute cannot be set to %d, "\
			"allowed range is ["#minval", "#maxval"]\n", \
			phba->brd_no, val); \
 	return -EINVAL;\
}

#define lpfc_param_store(attr)	\
static ssize_t \
lpfc_##attr##_store(struct class_device *cdev, const char *buf, size_t count) \
{ \
 	struct Scsi_Host *host = class_to_shost(cdev);\
 	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];\
 	int val=0;\
 	if (sscanf(buf, "%d", &val) != 1)\
 		return -EPERM;\
 	if (phba){\
 		if (lpfc_##attr##_set(phba, val) == 0) \
 			return strlen(buf);\
 	}\
 	return -EINVAL;\
}

#define LPFC_ATTR(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_param_init(name, defval, minval, maxval)\


#define LPFC_ATTR_R(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_param_show(name)\
lpfc_param_init(name, defval, minval, maxval)\
static CLASS_DEVICE_ATTR(lpfc_##name, S_IRUGO , lpfc_##name##_show, NULL)

#define LPFC_ATTR_RW(name, defval, minval, maxval, desc) \
static int lpfc_##name = defval;\
module_param(lpfc_##name, int, 0);\
MODULE_PARM_DESC(lpfc_##name, desc);\
lpfc_param_show(name)\
lpfc_param_init(name, defval, minval, maxval)\
lpfc_param_set(name, defval, minval, maxval)\
lpfc_param_store(name)\
static CLASS_DEVICE_ATTR(lpfc_##name, S_IRUGO | S_IWUSR,\
			 lpfc_##name##_show, lpfc_##name##_store)

static CLASS_DEVICE_ATTR(info, S_IRUGO, lpfc_info_show, NULL);
static CLASS_DEVICE_ATTR(serialnum, S_IRUGO, lpfc_serialnum_show, NULL);
static CLASS_DEVICE_ATTR(modeldesc, S_IRUGO, lpfc_modeldesc_show, NULL);
static CLASS_DEVICE_ATTR(modelname, S_IRUGO, lpfc_modelname_show, NULL);
static CLASS_DEVICE_ATTR(programtype, S_IRUGO, lpfc_programtype_show, NULL);
static CLASS_DEVICE_ATTR(portnum, S_IRUGO, lpfc_portnum_show, NULL);
static CLASS_DEVICE_ATTR(fwrev, S_IRUGO, lpfc_fwrev_show, NULL);
static CLASS_DEVICE_ATTR(hdw, S_IRUGO, lpfc_hdw_show, NULL);
static CLASS_DEVICE_ATTR(state, S_IRUGO, lpfc_state_show, NULL);
static CLASS_DEVICE_ATTR(option_rom_version, S_IRUGO,
					lpfc_option_rom_version_show, NULL);
static CLASS_DEVICE_ATTR(num_discovered_ports, S_IRUGO,
					lpfc_num_discovered_ports_show, NULL);
static CLASS_DEVICE_ATTR(speed, S_IRUGO, lpfc_speed_show, NULL);
static CLASS_DEVICE_ATTR(node_name, S_IRUGO, lpfc_node_name_show, NULL);
static CLASS_DEVICE_ATTR(port_name, S_IRUGO, lpfc_port_name_show, NULL);
static CLASS_DEVICE_ATTR(portfcid, S_IRUGO, lpfc_did_show, NULL);
static CLASS_DEVICE_ATTR(port_type, S_IRUGO, lpfc_port_type_show, NULL);
static CLASS_DEVICE_ATTR(fabric_name, S_IRUGO, lpfc_fabric_name_show, NULL);
static CLASS_DEVICE_ATTR(events, S_IRUGO, lpfc_events_show, NULL);
static CLASS_DEVICE_ATTR(nport_evt_cnt, S_IRUGO, lpfc_nport_evt_cnt_show, NULL);
static CLASS_DEVICE_ATTR(lpfc_drvr_version, S_IRUGO, lpfc_drvr_version_show,
			 NULL);
static CLASS_DEVICE_ATTR(management_version, S_IRUGO, management_version_show,
			 NULL);
static CLASS_DEVICE_ATTR(issue_lip, S_IWUSR, NULL, lpfc_issue_lip);
static CLASS_DEVICE_ATTR(board_online, S_IRUGO | S_IWUSR,
			 lpfc_board_online_show, lpfc_board_online_store);

static CLASS_DEVICE_ATTR(disc_npr, S_IRUGO, lpfc_disc_npr_show, NULL);
static CLASS_DEVICE_ATTR(disc_map, S_IRUGO, lpfc_disc_map_show, NULL);
static CLASS_DEVICE_ATTR(disc_unmap, S_IRUGO, lpfc_disc_unmap_show, NULL);
static CLASS_DEVICE_ATTR(disc_prli, S_IRUGO, lpfc_disc_prli_show, NULL);
static CLASS_DEVICE_ATTR(disc_reglgn, S_IRUGO, lpfc_disc_reglgn_show, NULL);
static CLASS_DEVICE_ATTR(disc_adisc, S_IRUGO, lpfc_disc_adisc_show, NULL);
static CLASS_DEVICE_ATTR(disc_plogi, S_IRUGO, lpfc_disc_plogi_show, NULL);
static CLASS_DEVICE_ATTR(disc_unused, S_IRUGO, lpfc_disc_unused_show, NULL);
static CLASS_DEVICE_ATTR(outfcpio, S_IRUGO, lpfc_outfcpio_show, NULL);

/*
# lpfc_log_verbose: Only turn this flag on if you are willing to risk being
# deluged with LOTS of information.
# You can set a bit mask to record specific types of verbose messages:
#
# LOG_ELS                       0x1        ELS events
# LOG_DISCOVERY                 0x2        Link discovery events
# LOG_MBOX                      0x4        Mailbox events
# LOG_INIT                      0x8        Initialization events
# LOG_LINK_EVENT                0x10       Link events
# LOG_IP                        0x20       IP traffic history
# LOG_FCP                       0x40       FCP traffic history
# LOG_NODE                      0x80       Node table events
# LOG_MISC                      0x400      Miscellaneous events
# LOG_SLI                       0x800      SLI events
# LOG_CHK_COND                  0x1000     FCP Check condition flag
# LOG_LIBDFC                    0x2000     LIBDFC events
# LOG_ALL_MSG                   0xffff     LOG all messages
*/
LPFC_ATTR_RW(log_verbose, 0x0, 0x0, 0xffff, "Verbose logging bit-mask");

/*
# lun_queue_depth:  This parameter is used to limit the number of outstanding
# commands per FCP LUN. Value range is [1,128]. Default value is 30.
*/
LPFC_ATTR_R(lun_queue_depth, 30, 1, 128,
	    "Max number of FCP commands we can queue to a specific LUN");

/*
# hba_queue_depth:  This parameter is used to limit the number of outstanding
# commands per lpfc HBA. Value range is [32,8192]. If this parameter
# value is greater than the maximum number of exchanges supported by the HBA,
# then maximum number of exchanges supported by the HBA is used to determine
# the hba_queue_depth.
*/
LPFC_ATTR_R(hba_queue_depth, 8192, 32, 8192,
	    "Max number of FCP commands we can queue to a lpfc HBA");


/*
# Some disk devices have a "select ID" or "select Target" capability.
# From a protocol standpoint "select ID" usually means select the
# Fibre channel "ALPA".  In the FC-AL Profile there is an "informative
# annex" which contains a table that maps a "select ID" (a number
# between 0 and 7F) to an ALPA.  By default, for compatibility with
# older drivers, the lpfc driver scans this table from low ALPA to high
# ALPA.
#
# Turning on the scan-down variable (on  = 1, off = 0) will
# cause the lpfc driver to use an inverted table, effectively
# scanning ALPAs from high to low. Value range is [0,1]. Default value is 1.
#
# (Note: This "select ID" functionality is a LOOP ONLY characteristic
# and will not work across a fabric. Also this parameter will take
# effect only in the case when ALPA map is not available.)
*/
LPFC_ATTR_R(scan_down, 1, 0, 1,
	     "Start scanning for devices from highest ALPA to lowest");

/*
# lpfc_nodev_tmo: If set, it will hold all I/O errors on devices that disappear
# until the timer expires. Value range is [0,255]. Default value is 20.
# NOTE: this MUST be less then the SCSI Layer command timeout - 1.
*/
LPFC_ATTR_RW(nodev_tmo, 30, 0, 255,
	     "Seconds driver will hold I/O waiting for a device to come back");

/*
# lpfc_topology:  link topology for init link
#            0x0  = attempt loop mode then point-to-point
#            0x02 = attempt point-to-point mode only
#            0x04 = attempt loop mode only
#            0x06 = attempt point-to-point mode then loop
# Set point-to-point mode if you want to run as an N_Port.
# Set loop mode if you want to run as an NL_Port. Value range is [0,0x6].
# Default value is 0.
*/
LPFC_ATTR_R(topology, 0, 0, 6, "Select Fibre Channel topology");

/*
# lpfc_link_speed: Link speed selection for initializing the Fibre Channel
# connection.
#       0  = auto select (default)
#       1  = 1 Gigabaud
#       2  = 2 Gigabaud
#       4  = 4 Gigabaud
# Value range is [0,4]. Default value is 0.
*/
LPFC_ATTR_R(link_speed, 0, 0, 4, "Select link speed");

/*
# lpfc_fcp_class:  Determines FC class to use for the FCP protocol.
# Value range is [2,3]. Default value is 3.
*/
LPFC_ATTR_R(fcp_class, 3, 2, 3,
	     "Select Fibre Channel class of service for FCP sequences");

/*
# lpfc_use_adisc: Use ADISC for FCP rediscovery instead of PLOGI. Value range
# is [0,1]. Default value is 0.
*/
LPFC_ATTR_RW(use_adisc, 0, 0, 1,
	     "Use ADISC on rediscovery to authenticate FCP devices");

/*
# lpfc_ack0: Use ACK0, instead of ACK1 for class 2 acknowledgement. Value
# range is [0,1]. Default value is 0.
*/
LPFC_ATTR_R(ack0, 0, 0, 1, "Enable ACK0 support");

/*
# lpfc_fcp_bind_method: It specifies the method of binding to be used for each
# port. This  binding method is used for consistent binding and mapped
# binding. A value of 1 will force WWNN binding, value of 2 will force WWPN
# binding, value of 3 will force DID binding and value of 4 will force the
# driver to derive binding from ALPA. Any consistent binding whose type does
# not match with the bind method of the port will be ignored. Value range
# is [1,4]. Default value is 2.
*/
LPFC_ATTR_R(fcp_bind_method, 2, 0, 4,
	    "Select the bind method to be used");

/*
# lpfc_cr_delay & lpfc_cr_count: Default values for I/O colaesing
# cr_delay (msec) or cr_count outstanding commands. cr_delay can take
# value [0,63]. cr_count can take value [0,255]. Default value of cr_delay
# is 0. Default value of cr_count is 1. The cr_count feature is disabled if
# cr_delay is set to 0.
*/
LPFC_ATTR(cr_delay, 0, 0, 63, "A count of milliseconds after which an "
		"interrupt response is generated");

LPFC_ATTR(cr_count, 1, 1, 255, "A count of I/O completions after which an "
		"interrupt response is generated");

/*
# lpfc_multi_ring_support:  Determines how many rings to spread available
# cmd /rsp IOCB entries across.
# Value range is [1,2]. Default value is 1.
*/
LPFC_ATTR(multi_ring_support, LPFC_1_PRIMARY_RING, LPFC_1_PRIMARY_RING,
	     LPFC_2_PRIMARY_RING, "Determines number of primary SLI rings to "
	     "spread IOCB entries across");

/*
# lpfc_fdmi_on: controls FDMI support.
#       0 = no FDMI support
#       1 = support FDMI without attribute of hostname
#       2 = support FDMI with attribute of hostname
# Value range [0,2]. Default value is 0.
*/
LPFC_ATTR_RW(fdmi_on, 0, 0, 2, "Enable FDMI support");

/*
# Specifies the maximum number of ELS cmds we can have outstanding (for
# discovery). Value range is [1,64]. Default value = 32.
*/
LPFC_ATTR(discovery_threads, 32, 1, 64, "Maximum number of ELS commands "
		 "during discovery");

/*
# lpfc_max_luns: maximum number of LUNs per target driver will support
# Value range is [1,32768]. Default value is 256.
# NOTE: The SCSI layer will scan each target for this many luns
*/
LPFC_ATTR_R(max_luns, 256, 1, 32768,
	     "Maximum number of LUNs per target driver will support");

/*
# lpfc_linkup_wait_limit: The number of seconds driver waits for link
# to be brought up.
# Value range is [0,60]. Default value is 15.
*/
LPFC_ATTR_RW(linkup_wait_limit, 15, 0, 60,
	     "The number of seconds driver waits for link to be brought up");

/*
# lpfc_discovery_min_wait: The minimum number of seconds driver waits
# for the discovery of the remote ports during the HBA initialization.
# Value range is [0, 60]. Default value is 3.
# NOTE: In some configurations, link comes up for a first time without
# targets.  The minimum wait time allows to driver to ignore results of
# the initial discovery.
*/
LPFC_ATTR_RW(discovery_min_wait, 3, 0, 60,
	     "The minimum number of seconds driver waits for the discovery "
	     "to complete");
/*
# lpfc_discovery_wait_limit: The maximum number of seconds driver
# waits for the discovery of the remote ports to stop during the HBA
# initialization.
# Value range is [0,CFG_DISC_INFINITE_WAIT]. Default value is
# CFG_DISC_INFINITE_WAIT.
# NOTE: Setting parameter to a maximum value of CFG_DISC_INFINITE_WAIT
# seconds removes the limit. 
*/
LPFC_ATTR_RW(discovery_wait_limit, CFG_DISC_INFINITE_WAIT, 0,
	     CFG_DISC_INFINITE_WAIT,
	     "The maximum number of seconds driver waits for the discovery "
	     "to complete");

static ssize_t
sysfs_ctlreg_write(struct kobject *kobj, char *buf, loff_t off, size_t count)
{
	unsigned long iflag;
	size_t buf_off;
	struct Scsi_Host *host = class_to_shost(container_of(kobj,
					     struct class_device, kobj));
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];

	if ((off + count) > FF_REG_AREA_SIZE)
		return -ERANGE;

	if (count == 0) return 0;

	if (off % 4 || count % 4 || (unsigned long)buf % 4)
		return -EINVAL;

	spin_lock_irqsave(phba->host->host_lock, iflag);

	if (!(phba->fc_flag & FC_OFFLINE_MODE)) {
		spin_unlock_irqrestore(phba->host->host_lock, iflag);
		return -EPERM;
	}

	for (buf_off = 0; buf_off < count; buf_off += sizeof(uint32_t))
		writel(*((uint32_t *)(buf + buf_off)),
		       (uint8_t *)phba->ctrl_regs_memmap_p + off + buf_off);

	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	return count;
}

static ssize_t
sysfs_ctlreg_read(struct kobject *kobj, char *buf, loff_t off, size_t count)
{
	unsigned long iflag;
	size_t buf_off;
	uint32_t * tmp_ptr;
	struct Scsi_Host *host = class_to_shost(container_of(kobj,
					     struct class_device, kobj));
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];

	if (off > FF_REG_AREA_SIZE)
		return -ERANGE;

	if ((off + count) > FF_REG_AREA_SIZE)
		count = FF_REG_AREA_SIZE - off;

	if (count == 0) return 0;

	if (off % 4 || count % 4 || (unsigned long)buf % 4)
		return -EINVAL;

	spin_lock_irqsave(phba->host->host_lock, iflag);

	for (buf_off = 0; buf_off < count; buf_off += sizeof(uint32_t)) {
		tmp_ptr = (uint32_t *)(buf + buf_off);
		*tmp_ptr = readl((uint8_t *)(phba->ctrl_regs_memmap_p
					     + off + buf_off));
	}

	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	return count;
}

static struct bin_attribute sysfs_ctlreg_attr = {
	.attr = {
		.name = "ctlreg",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 256,
	.read = sysfs_ctlreg_read,
	.write = sysfs_ctlreg_write,
};


#define MBOX_BUFF_SIZE (MAILBOX_CMD_WSIZE*sizeof(uint32_t))

static void
sysfs_mbox_idle (struct lpfc_hba * phba)
{
	phba->sysfs_mbox.state = SMBOX_IDLE;
	phba->sysfs_mbox.offset = 0;

	if (phba->sysfs_mbox.mbox) {
		mempool_free(phba->sysfs_mbox.mbox,
			     phba->mbox_mem_pool);
		phba->sysfs_mbox.mbox = NULL;
	}
}

static ssize_t
sysfs_mbox_write(struct kobject *kobj, char *buf, loff_t off, size_t count)
{
	unsigned long iflag;
	struct Scsi_Host * host =
		class_to_shost(container_of(kobj, struct class_device, kobj));
	struct lpfc_hba * phba = (struct lpfc_hba*)host->hostdata[0];
	struct lpfcMboxq * mbox = NULL;

	if ((count + off) > MBOX_BUFF_SIZE)
		return -ERANGE;

	if (off % 4 ||  count % 4 || (unsigned long)buf % 4)
		return -EINVAL;

	if (count == 0)
		return 0;

	if (off == 0) {
		mbox = mempool_alloc(phba->mbox_mem_pool, GFP_KERNEL);
		if (!mbox)
			return -ENOMEM;
		memset(mbox, 0, sizeof (LPFC_MBOXQ_t));
	}

	spin_lock_irqsave(host->host_lock, iflag);

	if (off == 0) {
		if (phba->sysfs_mbox.mbox)
			mempool_free(mbox, phba->mbox_mem_pool);
		else
			phba->sysfs_mbox.mbox = mbox;
		phba->sysfs_mbox.state = SMBOX_WRITING;
	}
	else {
		if (phba->sysfs_mbox.state  != SMBOX_WRITING ||
		    phba->sysfs_mbox.offset != off           ||
		    phba->sysfs_mbox.mbox   == NULL ) {
			sysfs_mbox_idle(phba);
			spin_unlock_irqrestore(host->host_lock, iflag);
			return -EINVAL;
		}
	}

	memcpy((uint8_t *) & phba->sysfs_mbox.mbox->mb + off,
	       buf, count);

	phba->sysfs_mbox.offset = off + count;

	spin_unlock_irqrestore(host->host_lock, iflag);

	return count;
}

static ssize_t
sysfs_mbox_read(struct kobject *kobj, char *buf, loff_t off, size_t count)
{
	unsigned long iflag;
	struct Scsi_Host *host =
		class_to_shost(container_of(kobj, struct class_device,
					    kobj));
	struct lpfc_hba *phba = (struct lpfc_hba*)host->hostdata[0];
	int rc;

	if (off > sizeof(MAILBOX_t))
		return -ERANGE;

	if ((count + off) > sizeof(MAILBOX_t))
		count = sizeof(MAILBOX_t) - off;

	if (off % 4 ||  count % 4 || (unsigned long)buf % 4)
		return -EINVAL;

	if (off && count == 0)
		return 0;

	spin_lock_irqsave(phba->host->host_lock, iflag);

	if (off == 0 &&
	    phba->sysfs_mbox.state  == SMBOX_WRITING &&
	    phba->sysfs_mbox.offset >= 2 * sizeof(uint32_t)) {

		switch (phba->sysfs_mbox.mbox->mb.mbxCommand) {
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
				printk(KERN_WARNING "mbox_read:Command 0x%x "
				       "is illegal in on-line state\n",
				       phba->sysfs_mbox.mbox->mb.mbxCommand);
				sysfs_mbox_idle(phba);
				spin_unlock_irqrestore(phba->host->host_lock,
						       iflag);
				return -EPERM;
			}
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
		case MBX_LOAD_AREA:
		case MBX_LOAD_EXP_ROM:
			break;
		case MBX_READ_SPARM64:
		case MBX_READ_LA:
		case MBX_READ_LA64:
		case MBX_REG_LOGIN:
		case MBX_REG_LOGIN64:
		case MBX_CONFIG_PORT:
		case MBX_RUN_BIU_DIAG:
			printk(KERN_WARNING "mbox_read: Illegal Command 0x%x\n",
			       phba->sysfs_mbox.mbox->mb.mbxCommand);
			sysfs_mbox_idle(phba);
			spin_unlock_irqrestore(phba->host->host_lock,
					       iflag);
			return -EPERM;
		default:
			printk(KERN_WARNING "mbox_read: Unknown Command 0x%x\n",
			       phba->sysfs_mbox.mbox->mb.mbxCommand);
			sysfs_mbox_idle(phba);
			spin_unlock_irqrestore(phba->host->host_lock,
					       iflag);
			return -EPERM;
		}

		if ((phba->fc_flag & FC_OFFLINE_MODE) ||
		    (!(phba->sli.sliinit.sli_flag & LPFC_SLI2_ACTIVE))){
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			rc = lpfc_sli_issue_mbox (phba,
						  phba->sysfs_mbox.mbox,
						  MBX_POLL);
			spin_lock_irqsave(phba->host->host_lock, iflag);
		} else {
			spin_unlock_irqrestore(phba->host->host_lock, iflag);
			rc = lpfc_sli_issue_mbox_wait (phba,
						       phba->sysfs_mbox.mbox,
						       phba->fc_ratov * 2);
			spin_lock_irqsave(phba->host->host_lock, iflag);
		}

		if (rc != MBX_SUCCESS) {
			sysfs_mbox_idle(phba);
			spin_unlock_irqrestore(host->host_lock, iflag);
			return -ENODEV;
		}
		phba->sysfs_mbox.state = SMBOX_READING;
	}
	else if (phba->sysfs_mbox.offset != off ||
		 phba->sysfs_mbox.state  != SMBOX_READING) {
		printk(KERN_WARNING  "mbox_read: Bad State\n");
		sysfs_mbox_idle(phba);
		spin_unlock_irqrestore(host->host_lock, iflag);
		return -EINVAL;
	}

	memcpy(buf, (uint8_t *) & phba->sysfs_mbox.mbox->mb + off, count);

	phba->sysfs_mbox.offset = off + count;

	if (phba->sysfs_mbox.offset == sizeof(MAILBOX_t))
		sysfs_mbox_idle(phba);

	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	return count;
}

static struct bin_attribute sysfs_mbox_attr = {
	.attr = {
		.name = "mbox",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = sizeof(MAILBOX_t),
	.read = sysfs_mbox_read,
	.write = sysfs_mbox_write,
};


#ifdef  RHEL_FC
/*
 * The LPFC driver treats linkdown handling as target loss events so there
 * are no sysfs handlers for link_down_tmo.
 */
static void
lpfc_get_starget_port_id(struct scsi_target *starget)
{
	struct lpfc_nodelist *ndlp = NULL;
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	struct lpfc_hba *phba = (struct lpfc_hba *) shost->hostdata[0];
	uint32_t did = -1;

	spin_lock_irq(shost->host_lock);
	/* Search the mapped list for this target ID */
	list_for_each_entry(ndlp, &phba->fc_nlpmap_list, nlp_listp) {
		if (starget->id == ndlp->nlp_sid) {
			did = ndlp->nlp_DID;
			break;
		}
	}
	spin_unlock_irq_dump(shost->host_lock);

	fc_starget_port_id(starget) = did;
}

static void
lpfc_get_starget_node_name(struct scsi_target *starget)
{
	struct lpfc_nodelist *ndlp = NULL;
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	struct lpfc_hba *phba = (struct lpfc_hba *) shost->hostdata[0];
	uint64_t node_name = 0;

	spin_lock_irq(shost->host_lock);
	/* Search the mapped list for this target ID */
	list_for_each_entry(ndlp, &phba->fc_nlpmap_list, nlp_listp) {
		if (starget->id == ndlp->nlp_sid) {
			memcpy(&node_name, &ndlp->nlp_nodename,
						sizeof(struct lpfc_name));
			break;
		}
	}
	spin_unlock_irq_dump(shost->host_lock);

	fc_starget_node_name(starget) = be64_to_cpu(node_name);
}

static void
lpfc_get_starget_port_name(struct scsi_target *starget)
{
	struct lpfc_nodelist *ndlp = NULL;
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	struct lpfc_hba *phba = (struct lpfc_hba *) shost->hostdata[0];
	uint64_t port_name = 0;

	spin_lock_irq(shost->host_lock);
	/* Search the mapped list for this target ID */
	list_for_each_entry(ndlp, &phba->fc_nlpmap_list, nlp_listp) {
		if (starget->id == ndlp->nlp_sid) {
			memcpy(&port_name, &ndlp->nlp_portname,
						sizeof(struct lpfc_name));
			break;
		}
	}
	spin_unlock_irq_dump(shost->host_lock);

	fc_starget_port_name(starget) = be64_to_cpu(port_name);
}

static void
lpfc_get_starget_loss_tmo(struct scsi_target *starget)
{
	/*
	 * Return the driver's global value for device loss timeout plus
	 * five seconds to allow the driver's nodev timer to run.
	 */
	fc_starget_dev_loss_tmo(starget) = lpfc_nodev_tmo + 5;
}

static void
lpfc_set_starget_loss_tmo(struct scsi_target *starget, uint32_t timeout)
{
	/*
	 * The driver doesn't have a per-target timeout setting.  Set
	 * this value globally. Keep lpfc_nodev_tmo >= 1.
	 */
	if (timeout)
		lpfc_nodev_tmo = timeout;
	else
		lpfc_nodev_tmo = 1;
}

#ifdef RHEL_U3_FC_XPORT
static void
lpfc_get_host_port_id(struct Scsi_Host *shost)
{
	struct lpfc_hba *phba = (struct lpfc_hba*)shost->hostdata[0];
	/* note: fc_myDID already in cpu endianness */
	fc_host_port_id(shost) = phba->fc_myDID;
}
#endif

#else /* not RHEL_FC */

static void
lpfc_get_port_id(struct scsi_device *sdev)
{
	struct lpfc_target *target = sdev->hostdata;
	if (sdev->host->transportt && target->pnode)
		fc_port_id(sdev) = target->pnode->nlp_DID;
}

static void
lpfc_get_node_name(struct scsi_device *sdev)
{
	struct lpfc_target *target = sdev->hostdata;
	uint64_t node_name = 0;
	if (sdev->host->transportt && target->pnode)
		memcpy(&node_name, &target->pnode->nlp_nodename,
						sizeof(struct lpfc_name));
	fc_node_name(sdev) = be64_to_cpu(node_name);
}

static void
lpfc_get_port_name(struct scsi_device *sdev)
{
	struct lpfc_target *target = sdev->hostdata;
	uint64_t port_name = 0;
	if (sdev->host->transportt && target->pnode)
		memcpy(&port_name, &target->pnode->nlp_portname,
						sizeof(struct lpfc_name));
	fc_port_name(sdev) = be64_to_cpu(port_name);
}
#endif /* not RHEL_FC */

static struct fc_function_template lpfc_transport_functions = {
#ifdef RHEL_FC
	.get_starget_port_id  = lpfc_get_starget_port_id,
	.show_starget_port_id = 1,

	.get_starget_node_name = lpfc_get_starget_node_name,
	.show_starget_node_name = 1,

	.get_starget_port_name = lpfc_get_starget_port_name,
	.show_starget_port_name = 1,

	.get_starget_dev_loss_tmo = lpfc_get_starget_loss_tmo,
	.set_starget_dev_loss_tmo = lpfc_set_starget_loss_tmo,
	.show_starget_dev_loss_tmo = 1,

#ifdef RHEL_U3_FC_XPORT
	.get_host_port_id  = lpfc_get_host_port_id,
	.show_host_port_id = 1,

	.issue_fc_host_lip = lpfc_issue_fc_host_lip,
#endif

#else /* not RHEL_FC */
	.get_port_id  = lpfc_get_port_id,
	.show_port_id = 1,

	.get_node_name = lpfc_get_node_name,
	.show_node_name = 1,

	.get_port_name = lpfc_get_port_name,
	.show_port_name = 1,
#endif /* not RHEL_FC */
};

static int
lpfc_proc_info(struct Scsi_Host *host,
	       char *buf, char **start, off_t offset, int count, int rw)
{
	struct lpfc_hba *phba = (struct lpfc_hba *)host->hostdata[0];
	struct lpfc_nodelist *ndlp;
	int len = 0;

	/* Sufficient bytes to hold a port or node name. */
	uint8_t name[sizeof (struct lpfc_name)];

	/* If rw = 0, then read info
	 * If rw = 1, then write info (NYI)
	 */
	if (rw)
		return -EINVAL;

	spin_lock_irq(phba->host->host_lock);
	list_for_each_entry(ndlp, &phba->fc_nlpmap_list, nlp_listp) {
		if (ndlp->nlp_state == NLP_STE_MAPPED_NODE){
			len += snprintf(buf + len, PAGE_SIZE -len,
					"lpfc%dt%02x DID %06x WWPN ",
					phba->brd_no,
					ndlp->nlp_sid, ndlp->nlp_DID);

			memcpy (&name[0], &ndlp->nlp_portname,
				sizeof (struct lpfc_name));
			len += snprintf(buf + len, PAGE_SIZE-len,
					"%02x:%02x:%02x:%02x:%02x:%02x:"
					"%02x:%02x",
					name[0], name[1], name[2],
					name[3], name[4], name[5],
					name[6], name[7]);
			len += snprintf(buf + len, PAGE_SIZE-len, " WWNN ");
			memcpy (&name[0], &ndlp->nlp_nodename,
				sizeof (struct lpfc_name));
			len += snprintf(buf + len, PAGE_SIZE-len,
					"%02x:%02x:%02x:%02x:%02x:%02x:"
					"%02x:%02x\n",
					name[0], name[1], name[2],
					name[3], name[4], name[5],
					name[6], name[7]);
			}
		if (PAGE_SIZE - len < 90)
			break;
	}
	if (&ndlp->nlp_listp != &phba->fc_nlpmap_list)
		len += snprintf(buf+len, PAGE_SIZE-len, "...\n");

	spin_unlock_irq_dump(phba->host->host_lock);
	return (len);
}

static int
lpfc_slave_alloc(struct scsi_device *scsi_devs)
{
	struct lpfc_hba *phba;
	struct lpfc_target *target;

	/*
	 * Store the lun pointer in the scsi_device hostdata pointer provided
	 * the driver has already discovered the target id.
	 */
	phba = (struct lpfc_hba *) scsi_devs->host->hostdata[0];
	target = lpfc_find_target(phba, scsi_devs->id, NULL);
	if (target) {
		scsi_devs->hostdata = target;
		target->slavecnt++;
		return 0;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
	return -ENXIO;
#else

	/*
	 * The driver does not have a target id matching that in the scsi
	 * device.  Allocate a dummy target initialized to zero so that
	 * the driver's queuecommand entry correctly fails the call
	 * forcing the midlayer to call lpfc_slave_destroy.  This code
	 * will be removed in a subsequent kernel patch.
	 */

	target = kmalloc(sizeof (struct lpfc_target), GFP_KERNEL);
	if (!target)
		return 1;

	memset(target, 0, sizeof (struct lpfc_target));
#ifdef SLES_FC
	init_timer(&target->dev_loss_timer);
#endif
	scsi_devs->hostdata = target;
	target->slavecnt++;
	return 0;
#endif
}

static int
lpfc_slave_configure(struct scsi_device *sdev)
{
	struct lpfc_hba *phba = (struct lpfc_hba *) sdev->host->hostdata[0];

#ifdef RHEL_FC
	struct lpfc_target *target = (struct lpfc_target *) sdev->hostdata;
#endif

	if (sdev->tagged_supported)
		scsi_activate_tcq(sdev, phba->cfg_lun_queue_depth);
	else
		scsi_deactivate_tcq(sdev, phba->cfg_lun_queue_depth);

#ifdef RHEL_FC
	if ((target) && (sdev->sdev_target)) {
		/*
		 * Initialize the fc transport attributes for the target
		 * containing this scsi device.  Also note that the driver's
		 * target pointer is stored in the starget_data for the
		 * driver's sysfs entry point functions.
		 */
		target->starget = sdev->sdev_target;
		fc_starget_dev_loss_tmo(target->starget) = lpfc_nodev_tmo + 5;
	}
#endif /* RHEL_FC */

	return 0;
}

static void
lpfc_slave_destroy(struct scsi_device *sdev)
{
	struct lpfc_hba *phba;
	struct lpfc_target *target;
	int i;

	phba = (struct lpfc_hba *) sdev->host->hostdata[0];
	target = sdev->hostdata;
	if (target) {
		target->slavecnt--;

		/* Double check for valid lpfc_target */
		for (i = 0; i < LPFC_MAX_TARGET; i++) {
			if(target == phba->device_queue_hash[i]) {
				if ((!target->slavecnt) && !(target->pnode)) {
					kfree(target);
					phba->device_queue_hash[i] = NULL;
				}
				sdev->hostdata = NULL;
				return;
			}
		}
		/* If we get here, this was a dummy lpfc_target allocated
		 * in lpfc_slave_alloc.
		 */
		if (!target->slavecnt)
			kfree(target);
	}

	/*
	 * Set this scsi device's hostdata to NULL since it is going
	 * away.  Also, (future) don't set the starget_dev_loss_tmo
	 * this value is global to all targets managed by this
	 * host.
	 */
	sdev->hostdata = NULL;
	return;
}

static struct class_device_attribute *lpfc_host_attrs[] = {
	&class_device_attr_info,
	&class_device_attr_serialnum,
	&class_device_attr_modeldesc,
	&class_device_attr_modelname,
	&class_device_attr_programtype,
	&class_device_attr_portnum,
	&class_device_attr_fwrev,
	&class_device_attr_hdw,
	&class_device_attr_option_rom_version,
	&class_device_attr_state,
	&class_device_attr_num_discovered_ports,
	&class_device_attr_speed,
	&class_device_attr_node_name,
	&class_device_attr_port_name,
	&class_device_attr_portfcid,
	&class_device_attr_port_type,
	&class_device_attr_fabric_name,
	&class_device_attr_events,
	&class_device_attr_lpfc_drvr_version,
	&class_device_attr_lpfc_log_verbose,
	&class_device_attr_lpfc_lun_queue_depth,
	&class_device_attr_lpfc_hba_queue_depth,
	&class_device_attr_lpfc_nodev_tmo,
	&class_device_attr_lpfc_fcp_class,
	&class_device_attr_lpfc_use_adisc,
	&class_device_attr_lpfc_ack0,
	&class_device_attr_lpfc_topology,
	&class_device_attr_lpfc_scan_down,
	&class_device_attr_lpfc_link_speed,
	&class_device_attr_lpfc_fdmi_on,
	&class_device_attr_lpfc_fcp_bind_method,
	&class_device_attr_lpfc_max_luns,
	&class_device_attr_nport_evt_cnt,
	&class_device_attr_management_version,
	&class_device_attr_issue_lip,
	&class_device_attr_board_online,
	&class_device_attr_disc_npr,
	&class_device_attr_disc_map,
	&class_device_attr_disc_unmap,
	&class_device_attr_disc_prli,
	&class_device_attr_disc_reglgn,
	&class_device_attr_disc_adisc,
	&class_device_attr_disc_plogi,
	&class_device_attr_disc_unused,
	&class_device_attr_outfcpio,
	&class_device_attr_lpfc_linkup_wait_limit,
	&class_device_attr_lpfc_discovery_min_wait,
	&class_device_attr_lpfc_discovery_wait_limit,
	NULL,
};

#if defined(RHEL_FC) && defined(DISKDUMP_FC)
static int
lpfc_scsih_sanity_check(struct scsi_device *sdev)
{
	struct lpfc_hba *phba;
	uint32_t id;

	phba = (struct lpfc_hba *) sdev->host->hostdata[0];
	if (!phba)
		return -ENXIO;

	/*
	 * message frame freeQ is busy
	 */
	if (spin_is_locked(phba->host->host_lock))
		return -EBUSY;

	/*
	 * We should never get an IOCB if we are in a LINK_DOWN state
	 */
	if (phba->hba_state < LPFC_LINK_UP)
		return -ENXIO;

	/* Check for Verndor ID */
	pci_read_config_dword(phba->pcidev, PCI_VENDOR_ID, &id);
	if(id == 0xffffffff) {
		printk(KERN_WARNING "lpfc sanity check for diskdump: HBA is not available!\n");
		return -ENXIO;
	}

	return 0;
}

static void
lpfc_scsih_poll(struct scsi_device *sdev)
{
	struct lpfc_hba *phba;

	phba = (struct lpfc_hba *) sdev->host->hostdata[0];
	if (!phba)
		return;

	/* Call SLI to handle the interrupt event. */
	lpfc_sli_intr(phba);

	spin_lock(phba->host->host_lock);
	lpfc_disc_done_entrance(phba);
	spin_unlock(phba->host->host_lock);
}
#endif

static struct scsi_host_template driver_template = {
	.module			= THIS_MODULE,
	.name			= LPFC_DRIVER_NAME,
	.info			= lpfc_info,
	.queuecommand		= lpfc_queuecommand,
	.eh_abort_handler	= lpfc_abort_handler,
	.eh_device_reset_handler= lpfc_reset_lun_handler,
	.eh_bus_reset_handler	= lpfc_reset_bus_handler,
	.slave_alloc		= lpfc_slave_alloc,
	.slave_configure	= lpfc_slave_configure,
	.slave_destroy		= lpfc_slave_destroy,
	.proc_info		= lpfc_proc_info,
	.proc_name		= LPFC_DRIVER_NAME,
	.this_id		= -1,
	.sg_tablesize		= SG_ALL,
	.cmd_per_lun		= 3,
	.max_sectors		= 0xFFFF,
	.shost_attrs		= lpfc_host_attrs,
	.use_clustering		= ENABLE_CLUSTERING,
#if defined(RHEL_FC) && defined(DISKDUMP_FC)
	.dump_sanity_check	= lpfc_scsih_sanity_check,
	.dump_poll		= lpfc_scsih_poll,
#endif
};

static int
lpfc_extra_ring_setup( struct lpfc_hba *phba)
{
	struct lpfc_sli *psli;
	LPFC_RING_INIT_t *pring;

	psli = &phba->sli;

	/* Adjust cmd/rsp ring iocb entries more evenly */
	pring = &psli->sliinit.ringinit[psli->fcp_ring];
	pring->numCiocb -= SLI2_IOCB_CMD_R1XTRA_ENTRIES;
	pring->numRiocb -= SLI2_IOCB_RSP_R1XTRA_ENTRIES;
	pring->numCiocb -= SLI2_IOCB_CMD_R3XTRA_ENTRIES;
	pring->numRiocb -= SLI2_IOCB_RSP_R3XTRA_ENTRIES;

	pring = &psli->sliinit.ringinit[1];
	pring->numCiocb += SLI2_IOCB_CMD_R1XTRA_ENTRIES;
	pring->numRiocb += SLI2_IOCB_RSP_R1XTRA_ENTRIES;
	pring->numCiocb += SLI2_IOCB_CMD_R3XTRA_ENTRIES;
	pring->numRiocb += SLI2_IOCB_RSP_R3XTRA_ENTRIES;

	/* Setup default profile for this ring */
	pring->iotag_max = 4096;
	pring->num_mask = 1;
	pring->prt[0].profile = 0;	/* Mask 0 */
	pring->prt[0].rctl = FC_UNSOL_DATA;
	pring->prt[0].type = 5;
	pring->prt[0].lpfc_sli_rcv_unsol_event = NULL;
	return 0;
}

static int
lpfc_sli_setup(struct lpfc_hba * phba)
{
	int i, totiocb = 0;
	struct lpfc_sli *psli = &phba->sli;
	LPFC_RING_INIT_t *pring;

	psli->sliinit.num_rings = MAX_CONFIGURED_RINGS;
	psli->fcp_ring = LPFC_FCP_RING;
	psli->next_ring = LPFC_FCP_NEXT_RING;
	psli->ip_ring = LPFC_IP_RING;

	for (i = 0; i < psli->sliinit.num_rings; i++) {
		pring = &psli->sliinit.ringinit[i];
		switch (i) {
		case LPFC_FCP_RING:	/* ring 0 - FCP */
			/* numCiocb and numRiocb are used in config_port */
			pring->numCiocb = SLI2_IOCB_CMD_R0_ENTRIES;
			pring->numRiocb = SLI2_IOCB_RSP_R0_ENTRIES;
			pring->numCiocb += SLI2_IOCB_CMD_R1XTRA_ENTRIES;
			pring->numRiocb += SLI2_IOCB_RSP_R1XTRA_ENTRIES;
			pring->numCiocb += SLI2_IOCB_CMD_R3XTRA_ENTRIES;
			pring->numRiocb += SLI2_IOCB_RSP_R3XTRA_ENTRIES;
			pring->iotag_ctr = 0;
			pring->iotag_max =
			    (phba->cfg_hba_queue_depth * 2);
			pring->fast_iotag = pring->iotag_max;
			pring->num_mask = 0;
			break;
		case LPFC_IP_RING:	/* ring 1 - IP */
			/* numCiocb and numRiocb are used in config_port */
			pring->numCiocb = SLI2_IOCB_CMD_R1_ENTRIES;
			pring->numRiocb = SLI2_IOCB_RSP_R1_ENTRIES;
			pring->num_mask = 0;
			break;
		case LPFC_ELS_RING:	/* ring 2 - ELS / CT */
			/* numCiocb and numRiocb are used in config_port */
			pring->numCiocb = SLI2_IOCB_CMD_R2_ENTRIES;
			pring->numRiocb = SLI2_IOCB_RSP_R2_ENTRIES;
			pring->fast_iotag = 0;
			pring->iotag_ctr = 0;
			pring->iotag_max = 4096;
			pring->num_mask = 5;
			pring->prt[0].profile = 0;	/* Mask 0 */
			pring->prt[0].rctl = FC_ELS_REQ;
			pring->prt[0].type = FC_ELS_DATA;
			pring->prt[0].lpfc_sli_rcv_unsol_event =
			    lpfc_els_unsol_event;
			pring->prt[1].profile = 0;	/* Mask 1 */
			pring->prt[1].rctl = FC_ELS_RSP;
			pring->prt[1].type = FC_ELS_DATA;
			pring->prt[1].lpfc_sli_rcv_unsol_event =
			    lpfc_els_unsol_event;
			pring->prt[2].profile = 0;	/* Mask 2 */
			/* NameServer Inquiry */
			pring->prt[2].rctl = FC_UNSOL_CTL;
			/* NameServer */
			pring->prt[2].type = FC_COMMON_TRANSPORT_ULP;
			pring->prt[2].lpfc_sli_rcv_unsol_event =
			    lpfc_ct_unsol_event;
			pring->prt[3].profile = 0;	/* Mask 3 */
			/* NameServer response */
			pring->prt[3].rctl = FC_SOL_CTL;
			/* NameServer */
			pring->prt[3].type = FC_COMMON_TRANSPORT_ULP;
			pring->prt[3].lpfc_sli_rcv_unsol_event =
			    lpfc_ct_unsol_event;
			pring->prt[4].profile = 0;	/* Mask 4 */
			pring->prt[4].rctl = FC_UNSOL_DATA;
			pring->prt[4].type = FC_VENDOR_SPECIFIC;
			pring->prt[4].lpfc_sli_rcv_unsol_event =
			    lpfc_loopback_event;
			break;
		}
		totiocb += (pring->numCiocb + pring->numRiocb);
	}
	if (totiocb > MAX_SLI2_IOCB) {
		/* Too many cmd / rsp ring entries in SLI2 SLIM */
		lpfc_printf_log(phba, KERN_ERR, LOG_INIT,
				"%d:0462 Too many cmd / rsp ring entries in "
				"SLI2 SLIM Data: x%x x%x\n",
				phba->brd_no, totiocb, MAX_SLI2_IOCB);
	}

	if (lpfc_multi_ring_support == LPFC_2_PRIMARY_RING)
		lpfc_extra_ring_setup(phba);

	psli->sliinit.sli_flag = 0;
	return (0);
}

static int
lpfc_set_bind_type(struct lpfc_hba * phba)
{
	int bind_type = phba->cfg_fcp_bind_method;
	int ret = LPFC_BIND_WW_NN_PN;

	switch (bind_type) {
	case 1:
		phba->fcp_mapping = FCP_SEED_WWNN;
		break;

	case 2:
		phba->fcp_mapping = FCP_SEED_WWPN;
		break;

	case 3:
		phba->fcp_mapping = FCP_SEED_DID;
		ret = LPFC_BIND_DID;
		break;

	case 4:
		phba->fcp_mapping = FCP_SEED_DID;
		ret = LPFC_BIND_DID;
		break;
	}

	return (ret);
}

static void
lpfc_get_cfgparam(struct lpfc_hba *phba)
{
	lpfc_log_verbose_init(phba, lpfc_log_verbose);
	lpfc_fcp_bind_method_init(phba, lpfc_fcp_bind_method);
	lpfc_cr_delay_init(phba, lpfc_cr_delay);
	lpfc_cr_count_init(phba, lpfc_cr_count);
	lpfc_multi_ring_support_init(phba, lpfc_multi_ring_support);
	lpfc_lun_queue_depth_init(phba, lpfc_lun_queue_depth);
	lpfc_fcp_class_init(phba, lpfc_fcp_class);
	lpfc_use_adisc_init(phba, lpfc_use_adisc);
	lpfc_ack0_init(phba, lpfc_ack0);
	lpfc_topology_init(phba, lpfc_topology);
	lpfc_scan_down_init(phba, lpfc_scan_down);
	lpfc_nodev_tmo_init(phba, lpfc_nodev_tmo);
	lpfc_link_speed_init(phba, lpfc_link_speed);
	lpfc_fdmi_on_init(phba, lpfc_fdmi_on);
	lpfc_discovery_threads_init(phba, lpfc_discovery_threads);
	lpfc_max_luns_init(phba, lpfc_max_luns);
	lpfc_linkup_wait_limit_init(phba, lpfc_linkup_wait_limit);
	lpfc_discovery_min_wait_init(phba, lpfc_discovery_min_wait);
	lpfc_discovery_wait_limit_init(phba, lpfc_discovery_wait_limit);
	phba->cfg_scsi_hotplug = 0;

	switch (phba->pcidev->device) {
	case PCI_DEVICE_ID_LP101:
	case PCI_DEVICE_ID_BSMB:
	case PCI_DEVICE_ID_ZSMB:
		phba->cfg_hba_queue_depth = LPFC_LP101_HBA_Q_DEPTH;
		break;
	case PCI_DEVICE_ID_RFLY:
	case PCI_DEVICE_ID_PFLY:
	case PCI_DEVICE_ID_BMID:
	case PCI_DEVICE_ID_ZMID:
	case PCI_DEVICE_ID_TFLY:
		phba->cfg_hba_queue_depth = LPFC_LC_HBA_Q_DEPTH;
		break;
	default:
		phba->cfg_hba_queue_depth = LPFC_DFT_HBA_Q_DEPTH;
	}

	if (phba->cfg_hba_queue_depth > lpfc_hba_queue_depth) {
		lpfc_hba_queue_depth_init(phba, lpfc_hba_queue_depth);
	}
	return;
}

static void
lpfc_consistent_bind_setup(struct lpfc_hba * phba)
{
	INIT_LIST_HEAD(&phba->fc_nlpbind_list);
	phba->fc_bind_cnt = 0;
}

static uint8_t
lpfc_get_brd_no(struct lpfc_hba * phba)
{
	uint8_t    brd, found = 1;

 	brd = 0;
	while(found) {
		phba = NULL;
		found = 0;
		list_for_each_entry(phba, &lpfc_hba_list, hba_list) {
			if (phba->brd_no == brd) {
				found = 1;
				brd++;
				break;
			}
		}
	}
	return (brd);
}


static int __devinit
lpfc_pci_probe_one(struct pci_dev *pdev, const struct pci_device_id *pid)
{
	struct Scsi_Host *host;
	struct lpfc_hba  *phba;
	struct lpfc_sli  *psli;
	unsigned long iflag;
	unsigned long bar0map_len, bar2map_len;
	int error = -ENODEV, retval;

	if (pci_enable_device(pdev))
		goto out;
	if (pci_request_regions(pdev, LPFC_DRIVER_NAME))
		goto out_disable_device;

	/*
	 * Allocate space for adapter info structure
	 */
	phba = kmalloc(sizeof(*phba), GFP_KERNEL);
	if (!phba)
		goto out_release_regions;
	memset(phba, 0, sizeof (struct lpfc_hba));

	host = scsi_host_alloc(&driver_template, sizeof (unsigned long));
	if (!host) {
		printk (KERN_WARNING "%s: scsi_host_alloc failed.\n",
							 lpfc_drvr_name);
		error = -ENOMEM;
		goto out_kfree_phba;
	}

	phba->fc_flag |= FC_LOADING;
	phba->pcidev = pdev;
	phba->host = host;

	init_MUTEX(&phba->hba_can_block);
	INIT_LIST_HEAD(&phba->ctrspbuflist);
	INIT_LIST_HEAD(&phba->rnidrspbuflist);
	INIT_LIST_HEAD(&phba->freebufList);

	/* Initialize timers used by driver */
	init_timer(&phba->fc_estabtmo);
	phba->fc_estabtmo.function = lpfc_establish_link_tmo;
	phba->fc_estabtmo.data = (unsigned long)phba;
	init_timer(&phba->fc_disctmo);
	phba->fc_disctmo.function = lpfc_disc_timeout;
	phba->fc_disctmo.data = (unsigned long)phba;
	init_timer(&phba->fc_scantmo);
	phba->fc_scantmo.function = lpfc_scan_timeout;
	phba->fc_scantmo.data = (unsigned long)phba;

	init_timer(&phba->fc_fdmitmo);
	phba->fc_fdmitmo.function = lpfc_fdmi_tmo;
	phba->fc_fdmitmo.data = (unsigned long)phba;
	init_timer(&phba->els_tmofunc);
	phba->els_tmofunc.function = lpfc_els_timeout;
	phba->els_tmofunc.data = (unsigned long)phba;
	psli = &phba->sli;
	init_timer(&psli->mbox_tmo);
	psli->mbox_tmo.function = lpfc_mbox_timeout;
	psli->mbox_tmo.data = (unsigned long)phba;

	/* Assign an unused board number */
 	phba->brd_no = lpfc_get_brd_no(phba);
	host->unique_id = phba->brd_no;

	/*
	 * Get all the module params for configuring this host and then
	 * establish the host parameters.
	 */
	lpfc_get_cfgparam(phba);

	host->max_id = LPFC_MAX_TARGET;
	host->max_lun = phba->cfg_max_luns;
	host->this_id = -1;

	if(phba->cfg_scsi_hotplug) {
		lpfc_printf_log(phba, KERN_ERR, LOG_FCP,
			"%d:0264 HotPlug Support Enabled\n",
			phba->brd_no);
	}

	/* Add adapter structure to list */
	list_add_tail(&phba->hba_list, &lpfc_hba_list);

	/* Initialize all internally managed lists. */
	INIT_LIST_HEAD(&phba->fc_nlpmap_list);
	INIT_LIST_HEAD(&phba->fc_nlpunmap_list);
	INIT_LIST_HEAD(&phba->fc_unused_list);
	INIT_LIST_HEAD(&phba->fc_plogi_list);
	INIT_LIST_HEAD(&phba->fc_adisc_list);
	INIT_LIST_HEAD(&phba->fc_reglogin_list);
	INIT_LIST_HEAD(&phba->fc_prli_list);
	INIT_LIST_HEAD(&phba->fc_npr_list);
	lpfc_consistent_bind_setup(phba);

	init_waitqueue_head(&phba->linkevtwq);
	init_waitqueue_head(&phba->rscnevtwq);
	init_waitqueue_head(&phba->ctevtwq);
	init_waitqueue_head(&phba->dumpevtwq);

	pci_set_master(pdev);
	retval = pci_set_mwi(pdev);
	if (retval)
		dev_printk(KERN_WARNING, &pdev->dev,
			   "Warning: pci_set_mwi returned %d\n", retval);

	/* Configure DMA attributes. */
	if (dma_set_mask(&phba->pcidev->dev, 0xffffffffffffffffULL) &&
	    dma_set_mask(&phba->pcidev->dev, 0xffffffffULL))
		goto out_list_del;

	/*
	 * Get the physical address of Bar0 and Bar2 and the number of bytes
	 * required by each mapping.
	 */
	phba->pci_bar0_map = pci_resource_start(phba->pcidev, 0);
	bar0map_len        = pci_resource_len(phba->pcidev, 0);

	phba->pci_bar2_map = pci_resource_start(phba->pcidev, 2);
	bar2map_len        = pci_resource_len(phba->pcidev, 2);

	/* Map HBA SLIM and Control Registers to a kernel virtual address. */
	phba->slim_memmap_p      = ioremap(phba->pci_bar0_map, bar0map_len);
	if (!phba->slim_memmap_p) {
		dev_printk(KERN_ERR, &pdev->dev,
			   "%s ioremap failed for SLIM memory.\n",
			   lpfc_drvr_name);
		goto out_list_del;
	}

	phba->ctrl_regs_memmap_p = ioremap(phba->pci_bar2_map, bar2map_len);
	if (!phba->ctrl_regs_memmap_p) {
		dev_printk(KERN_ERR, &pdev->dev,
			   "%s ioremap failed for HBA control registers.\n",
			   lpfc_drvr_name);
		goto out_iounmap_slim;
	}

	/*
	 * Allocate memory for SLI-2 structures
	 */
	phba->slim2p = dma_alloc_coherent(&phba->pcidev->dev, SLI2_SLIM_SIZE,
					  &phba->slim2p_mapping, GFP_KERNEL);
	if (!phba->slim2p)
		goto out_iounmap;

	memset((char *)phba->slim2p, 0, SLI2_SLIM_SIZE);

	lpfc_sli_setup(phba);	/* Setup SLI Layer to run over lpfc HBAs */
	lpfc_sli_queue_setup(phba);	/* Initialize the SLI Layer */

	error = lpfc_mem_alloc(phba);
	if (error)
		goto out_dec_nhbas;

	lpfc_set_bind_type(phba);

	/* Initialize HBA structure */
	phba->fc_edtov = FF_DEF_EDTOV;
	phba->fc_ratov = FF_DEF_RATOV;
	phba->fc_altov = FF_DEF_ALTOV;
	phba->fc_arbtov = FF_DEF_ARBTOV;

	INIT_LIST_HEAD(&phba->dpc_disc);
	init_completion(&phba->dpc_startup);
	init_completion(&phba->dpc_exiting);

	/*
	* Startup the kernel thread for this host adapter
	*/
	phba->dpc_kill = 0;
	phba->dpc_pid = kernel_thread(lpfc_do_dpc, phba, 0);
	if (phba->dpc_pid < 0) {
		error = phba->dpc_pid;
		goto out_free_mem;
	}
	wait_for_completion(&phba->dpc_startup);

	/* Call SLI to initialize the HBA. */
	error = lpfc_sli_hba_setup(phba);
	if (error)
		goto out_hba_down;

	/* We can rely on a queue depth attribute only after SLI HBA setup */
	host->can_queue = phba->cfg_hba_queue_depth - 10;

	/*
	 * Starting with 2.4.0 kernel, Linux can support commands longer
	 * than 12 bytes. However, scsi_register() always sets it to 12.
	 * For it to be useful to the midlayer, we have to set it here.
	 */
	host->max_cmd_len = 16;

	/*
	 * Queue depths per lun
	 */
	host->transportt = lpfc_transport_template;
	host->hostdata[0] = (unsigned long)phba;
	pci_set_drvdata(pdev, host);
	error = scsi_add_host(host, &pdev->dev);
	if (error)
		goto out_hba_down;

	sysfs_create_bin_file(&host->shost_classdev.kobj, &sysfs_ctlreg_attr);
	sysfs_create_bin_file(&host->shost_classdev.kobj, &sysfs_mbox_attr);
	scsi_scan_host(host);
	phba->fc_flag &= ~FC_LOADING;
	return 0;

out_hba_down:
	/* Stop any timers that were started during this attach. */
	spin_lock_irqsave(phba->host->host_lock, iflag);
	lpfc_sli_hba_down(phba);
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	lpfc_sli_brdrestart(phba);
	lpfc_stop_timer(phba);
	spin_lock_irqsave(phba->host->host_lock, iflag);
	phba->work_hba_events = 0;
	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	/* Kill the kernel thread for this host */
	if (phba->dpc_pid >= 0) {
		phba->dpc_kill = 1;
		wmb();
		kill_proc(phba->dpc_pid, SIGHUP, 1);
		wait_for_completion(&phba->dpc_exiting);
	}

out_free_mem:
	lpfc_mem_free(phba);
out_dec_nhbas:
	dma_free_coherent(&pdev->dev, SLI2_SLIM_SIZE,
			  phba->slim2p, phba->slim2p_mapping);
out_iounmap:
	iounmap(phba->ctrl_regs_memmap_p);
out_iounmap_slim:
	iounmap(phba->slim_memmap_p);
out_list_del:
	list_del_init(&phba->hba_list);
	scsi_host_put(host);
out_kfree_phba:
	kfree(phba);
out_release_regions:
	pci_release_regions(pdev);
out_disable_device:
	pci_disable_device(pdev);
out:
	return error;
}

static void __devexit
lpfc_pci_remove_one(struct pci_dev *pdev)
{
	struct Scsi_Host   *host = pci_get_drvdata(pdev);
	struct lpfc_hba    *phba = (struct lpfc_hba *)host->hostdata[0];
	struct lpfc_target *targetp;
	int i;
	unsigned long iflag;

	sysfs_remove_bin_file(&host->shost_classdev.kobj, &sysfs_mbox_attr);
	sysfs_remove_bin_file(&host->shost_classdev.kobj, &sysfs_ctlreg_attr);

	if (phba->fc_flag & FC_OFFLINE_MODE)
		scsi_unblock_requests(phba->host);

	spin_lock_irqsave(phba->host->host_lock, iflag);

	/* Since we are going to scsi_remove_host(), disassociate scsi_dev
	 * from lpfc_target, and make sure its unblocked.
	 */
	for (i = 0; i < LPFC_MAX_TARGET; i++) {
		targetp = phba->device_queue_hash[i];
		if (!targetp)
			continue;

		if(targetp->pnode) {
			if(targetp->blocked) {
				/* If we are blocked, force a nodev_tmo */
				spin_unlock_irqrestore(phba->host->host_lock,
									iflag);
				del_timer_sync(&targetp->pnode->nlp_tmofunc);
				spin_lock_irqsave(phba->host->host_lock, iflag);
				if (!list_empty(&targetp->pnode->
						nodev_timeout_evt.evt_listp))
					list_del_init(&targetp->pnode->
						      nodev_timeout_evt.
						      evt_listp);
				lpfc_process_nodev_timeout(phba,
					targetp->pnode);
			}
			else {
				/* If we are unblocked, just remove
				 * the scsi device.
				 */
				lpfc_target_remove(phba, targetp);
			}
		}

#ifdef RHEL_FC
		targetp->starget = NULL;
#endif
	}
	spin_unlock_irqrestore(phba->host->host_lock, iflag);

	list_del(&phba->hba_list);
	scsi_remove_host(phba->host);

	/* detach the board */

	/* Kill the kernel thread for this host */
	if (phba->dpc_pid >= 0) {
		phba->dpc_kill = 1;
		wmb();
		kill_proc(phba->dpc_pid, SIGHUP, 1);
		wait_for_completion(&phba->dpc_exiting);
	}

	/*
	 * Bring down the SLI Layer. This step disable all interrupts,
	 * clears the rings, discards all mailbox commands, and resets
	 * the HBA.
	 */
	spin_lock_irqsave(phba->host->host_lock, iflag);
	lpfc_sli_hba_down(phba);
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	lpfc_sli_brdrestart(phba);

	/* Release the irq reservation */
	free_irq(phba->pcidev->irq, phba);

	spin_lock_irqsave(phba->host->host_lock, iflag);
	lpfc_cleanup(phba, 0);
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	lpfc_stop_timer(phba);
	spin_lock_irqsave(phba->host->host_lock, iflag);
	phba->work_hba_events = 0;
	spin_unlock_irqrestore(phba->host->host_lock, iflag);
	lpfc_scsi_free(phba);

	lpfc_mem_free(phba);

	/* Free resources associated with SLI2 interface */
	dma_free_coherent(&pdev->dev, SLI2_SLIM_SIZE,
			  phba->slim2p, phba->slim2p_mapping);

	/* unmap adapter SLIM and Control Registers */
	iounmap(phba->ctrl_regs_memmap_p);
	iounmap(phba->slim_memmap_p);

	pci_release_regions(phba->pcidev);
	pci_disable_device(phba->pcidev);

	scsi_host_put(phba->host);
	kfree(phba);

	pci_set_drvdata(pdev, NULL);
}

static struct pci_device_id lpfc_id_table[] = {
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_VIPER,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_THOR,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_PEGASUS,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_CENTAUR,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_DRAGONFLY,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_SUPERFLY,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_RFLY,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_PFLY,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_NEPTUNE,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_NEPTUNE_SCSP,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_NEPTUNE_DCSP,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_HELIOS,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_HELIOS_SCSP,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_HELIOS_DCSP,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_BMID,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_BSMB,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_ZEPHYR,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_ZEPHYR_SCSP,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_ZEPHYR_DCSP,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_ZMID,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_ZSMB,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_TFLY,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_LP101,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_LP10000S,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_LP11000S,
		PCI_ANY_ID, PCI_ANY_ID, },
	{PCI_VENDOR_ID_EMULEX, PCI_DEVICE_ID_LPE11000S,
		PCI_ANY_ID, PCI_ANY_ID, },
	{ 0 }
};
MODULE_DEVICE_TABLE(pci, lpfc_id_table);


static struct pci_driver lpfc_driver = {
	.name		= LPFC_DRIVER_NAME,
	.id_table	= lpfc_id_table,
	.probe		= lpfc_pci_probe_one,
	.remove		= __devexit_p(lpfc_pci_remove_one),
};

static int __init
lpfc_init(void)
{
	int rc;

	printk(LPFC_MODULE_DESC "\n");
	printk(LPFC_COPYRIGHT "\n");

	lpfc_transport_template =
		fc_attach_transport(&lpfc_transport_functions);
	if (!lpfc_transport_template)
		return -ENODEV;
	rc = pci_module_init(&lpfc_driver);
	return rc;

}

static void __exit
lpfc_exit(void)
{
	pci_unregister_driver(&lpfc_driver);
	fc_release_transport(lpfc_transport_template);
}
module_init(lpfc_init);
module_exit(lpfc_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(LPFC_MODULE_DESC);
MODULE_AUTHOR("Emulex Corporation - tech.support@emulex.com");
MODULE_VERSION("0:" LPFC_DRIVER_VERSION);
EXPORT_SYMBOL(lpfc_hba_list);

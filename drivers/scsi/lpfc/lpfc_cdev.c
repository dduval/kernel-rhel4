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
 * $Id: lpfc_cdev.c 3028 2007-04-03 01:47:15Z sf_support $
 */

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif
#include <linux/version.h>
#include <linux/config.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/list.h>
#include <linux/utsname.h>
#include <linux/pci.h>
#include <linux/timer.h>
#include <linux/if_arp.h>
#include <linux/spinlock.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <linux/ctype.h>

#include "lpfc_version.h"
#include "lpfc_hw.h"
#include "lpfc_sli.h"
#include "lpfc_mem.h"
#include "lpfc_disc.h"
#include "lpfc_scsi.h"
/* Configuration parameters defined */
#include "lpfc.h"
#include "lpfc_logmsg.h"
#include "lpfc_diag.h"
#if defined(CONFIG_COMPAT) && !defined(__ia64__)
#include <linux/ioctl32.h>
#include <linux/syscalls.h>
#endif
#include "lpfc_ioctl.h"
#include "lpfcdfc_version.h"

#include <linux/rtnetlink.h>
#include <asm/byteorder.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "lpfc_crtn.h"
#include "lpfc_util_ioctl.h"
#include "lpfc_hbaapi_ioctl.h"
#include "lpfc_debug_ioctl.h"
#include "lpfc_misc.h"
#include "lpfc_compat.h"

#define LPFC_IOCTL_MODULE_DESC "Emulex LightPulse FC SCSI IOCTL " LPFCDFC_DRIVER_VERSION


#define LPFC_PASTE(x,y) x##_##y
#define LPFC_PASTEX(x,y) LPFC_PASTE(x,y)


typedef int (*LPFC_IOCTL_FN)(LPFCCMDINPUT_t *);
struct list_head *lpfcdfc_hba_list;

int lpfc_diag_init(void);
int lpfc_diag_uninit(void);
static int lpfc_major = 0;
unsigned long lpfc_loadtime;

/* Keep state of the last known LPFC driver version check */
static struct version_check {
	int vc_done;
	int vc_status;
} vcheck = {0, 0};

#define LPFC_SCSI_REQ_TMO_DEFAULT 30
int lpfc_scsi_req_tmo = LPFC_SCSI_REQ_TMO_DEFAULT;
module_param(lpfc_scsi_req_tmo, int, 0);
MODULE_PARM_DESC(lpfc_scsi_req_tmo, "ioctl scsi timeout value");

/* A chrdev is used for diagnostic interface */
int lpfcdiag_ioctl(struct inode *inode, struct file *file,
		   unsigned int cmd, unsigned long arg);

static struct file_operations lpfc_fops = {
	.owner = THIS_MODULE,
	.ioctl = lpfcdiag_ioctl,
};

static int
lpfc_diag_match_version (void)
{
	struct pci_dev * dev = NULL;
	struct Scsi_Host   * host = NULL;
	struct class_device * host_cdev;
	struct class_device_attribute ** attributes;
	char * buf = NULL;
	int    ret_val = -ENODEV;

	/* If we already did the version check, just return the last
	   known check status */
	if (vcheck.vc_done)
		return (vcheck.vc_status);

	while ((dev = pci_get_device(PCI_VENDOR_ID_EMULEX, PCI_ANY_ID, dev))
		 != NULL) {

		host = pci_get_drvdata(dev);

		if (host != NULL && host->hostt != NULL
			&& host->hostt->shost_attrs != NULL)
			break;
	}

	if (dev == NULL || host == NULL) {
		printk(KERN_WARNING "The lpfcdfc driver detected that"
			" no HBA ports are available.\n");
		return -ENODEV;
        }

	buf = kmalloc (PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	spin_lock_irq(host->host_lock);
	host_cdev = &(host->shost_classdev);
	attributes = host->hostt->shost_attrs;

	while ((*attributes != NULL)
	       && (strcmp((*attributes)->attr.name, "lpfc_drvr_version") != 0))
		attributes++;

	spin_unlock_irq(host->host_lock);

	if (*attributes != NULL) {
		((*attributes)->show)(host_cdev, buf);
		ret_val = 0;
		if (strncmp(buf, LPFC_MODULE_DESC,
			    (sizeof(LPFC_MODULE_DESC) - 1))) {
			printk(KERN_ERR "Wrong version of the lpfc driver: %s\n"
			       "Required version: %s\n", buf, LPFC_MODULE_DESC);
			ret_val = -EACCES;
		}

	}

	kfree (buf);

	/* Version check was done, update status */
	vcheck.vc_done = 1;
	vcheck.vc_status = ret_val;

	return ret_val;
}

int
lpfc_diag_init(void)
{
	int result;

	result = register_chrdev(lpfc_major, LPFCDFC_DRIVER_NAME, &lpfc_fops);
	if (result < 0)
		return result;
	if (lpfc_major == 0)
		lpfc_major = result;	/* dynamic */
	return 0;
}

int
lpfc_diag_uninit(void)
{
	if (lpfc_major) {
		unregister_chrdev(lpfc_major, LPFCDFC_DRIVER_NAME);
		lpfc_major = 0;
	}
	return (0);
}

struct ioctls_registry_entry {
	struct list_head list;
	LPFC_IOCTL_FN lpfc_ioctl_fn;
};

struct ioctls_registry_entry lpfc_ioctls_registry = {
	.list = LIST_HEAD_INIT(lpfc_ioctls_registry.list)
};

int
reg_ioctl_entry(LPFC_IOCTL_FN fn)
{
	struct ioctls_registry_entry *new_lpfc_ioctls_registry_entry =
	    kmalloc(sizeof (struct ioctls_registry_entry), GFP_KERNEL);
	if (new_lpfc_ioctls_registry_entry == 0)
		return -ENOMEM;
	new_lpfc_ioctls_registry_entry->lpfc_ioctl_fn = fn;
	if (fn != 0) {
		list_add(&(new_lpfc_ioctls_registry_entry->list),
			 &(lpfc_ioctls_registry.list));
	}
	return 0;
}

int
unreg_ioctl_entry(LPFC_IOCTL_FN fn)
{
	struct list_head *p, *n;
	struct ioctls_registry_entry *entry;

	list_for_each_safe(p, n, &(lpfc_ioctls_registry.list)) {
		entry = list_entry(p, struct ioctls_registry_entry, list);
		if (entry->lpfc_ioctl_fn == fn) {
			list_del(p);
			kfree(entry);
			break;
		}
	}
	return 0;
}

void
unreg_all_ioctl_entries(void)
{
	struct list_head *p,*n;
	struct ioctls_registry_entry *entry;

	list_for_each_safe(p, n, &(lpfc_ioctls_registry.list)) {
		entry = list_entry(p, struct ioctls_registry_entry, list);
		list_del(p);
		kfree(entry);
	}
	return ;
}

/*
 * Retrieve lpfc_hba * matching instance (board no)
 * If found return lpfc_hba *
 * If not found return NULL
 */
struct lpfc_hba *
lpfc_get_phba_by_inst(int inst)
{
	struct lpfc_hba * phba;
	extern struct list_head *lpfcdfc_hba_list;
	int found = 0;

	if ( lpfc_diag_match_version() < 0 )
		return NULL;

	list_for_each_entry(phba, lpfcdfc_hba_list, hba_list) {
		if (phba->brd_no == inst) {
			found = 1;
			break;
		}
	}
	if (found)
		return phba;
	else
		return NULL;
}

int
lpfcdiag_ioctl(struct inode *inode,
	       struct file *file, unsigned int cmd, unsigned long arg)
{
	int rc = EINVAL;
	LPFCCMDINPUT_t *ci;
	struct list_head *p;
	struct ioctls_registry_entry *entry;

	if (!arg)
		return (-EINVAL);


	ci = (LPFCCMDINPUT_t *) kmalloc(sizeof (LPFCCMDINPUT_t), GFP_KERNEL);

	if (!ci)
		return (-ENOMEM);

	if (copy_from_user
	    ((uint8_t *) ci, (uint8_t *) arg, sizeof (LPFCCMDINPUT_t))) {
		kfree(ci);
		return (-EIO);
	}

	list_for_each(p, &(lpfc_ioctls_registry.list)) {
		entry = list_entry(p, struct ioctls_registry_entry, list);
		if (entry->lpfc_ioctl_fn) {
			rc = entry->lpfc_ioctl_fn(ci);
			/* For GET_DFC_REV we should continue even if
                           phba not valid */
			if ((ci->lpfc_cmd == LPFC_GET_DFC_REV) &&
				(rc == EINVAL))
					continue;
			if (rc != -1)
				break;	/* This IOCTL has been serviced. Do not
					 bother to pass it to the ohter entries in
					 the registry */
		}
	}

	kfree(ci);
	return (-rc);
}
#if defined(CONFIG_COMPAT) && !defined(__ia64__)
int
lpfc_ioctl32_handler(unsigned int fd, unsigned int cmd, unsigned long arg, struct file *file)
{
	LPFCCMDINPUT32_t arg32;
	LPFCCMDINPUT_t arg64;
	mm_segment_t old_fs;
	int ret;

	if(copy_from_user(&arg32, (void*)arg, sizeof(LPFCCMDINPUT32_t)))
		return -EFAULT;


	arg64.lpfc_brd = arg32.lpfc_brd;
	arg64.lpfc_ring = arg32.lpfc_ring;
	arg64.lpfc_iocb = arg32.lpfc_iocb;
	arg64.lpfc_flag = arg32.lpfc_flag;
	arg64.lpfc_arg1 = (void*)(unsigned long) arg32.lpfc_arg1;
	arg64.lpfc_arg2 = (void *)(unsigned long)arg32.lpfc_arg2;
	arg64.lpfc_arg3 = (void *)(unsigned long) arg32.lpfc_arg3;
	arg64.lpfc_dataout = (void *)(unsigned long) arg32.lpfc_dataout;
	arg64.lpfc_cmd = arg32.lpfc_cmd;
	arg64.lpfc_outsz = arg32.lpfc_outsz;
	arg64.lpfc_arg4 = arg32.lpfc_arg4;
	arg64.lpfc_arg5 = arg32.lpfc_arg5;


	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = sys_ioctl(fd, LPFC_DFC_CMD_IOCTL , (unsigned long)&arg64);
	set_fs(old_fs);


	arg32.lpfc_brd = arg64.lpfc_brd;
	arg32.lpfc_ring = arg64.lpfc_ring;
	arg32.lpfc_iocb = arg64.lpfc_iocb;
	arg32.lpfc_flag = arg64.lpfc_flag;
	arg32.lpfc_arg1 = (u32)(unsigned long)(arg64.lpfc_arg1);
	arg32.lpfc_arg2 = (u32)(unsigned long)(arg64.lpfc_arg2);
	arg32.lpfc_arg3 = (u32)(unsigned long) (arg64.lpfc_arg3);
	arg32.lpfc_dataout = (u32)(unsigned long) (arg64.lpfc_dataout);
	arg32.lpfc_cmd = arg64.lpfc_cmd;
	arg32.lpfc_outsz = arg64.lpfc_outsz;
	arg32.lpfc_arg4 = arg64.lpfc_arg4;
	arg32.lpfc_arg5 = arg64.lpfc_arg5;

	if(copy_to_user((void*)arg, &arg32, sizeof(LPFCCMDINPUT32_t)))
		return -EFAULT;

	return ret;
}
#endif
static int __init
lpfc_cdev_init(void)
{
	extern struct list_head *lpfcdfc_hba_list;
	extern struct list_head lpfc_hba_list;
	lpfcdfc_hba_list = &lpfc_hba_list;

	printk(LPFC_IOCTL_MODULE_DESC "\n");
	printk(LPFCDFC_COPYRIGHT "\n");
	if(unlikely(reg_ioctl_entry(lpfc_process_ioctl_util) != 0)) goto errexit;
	if(unlikely(reg_ioctl_entry(lpfc_process_ioctl_hbaapi) != 0)) goto errexit;
	if(unlikely(reg_ioctl_entry(lpfc_process_ioctl_dfc) != 0)) goto errexit;
	if(unlikely(lpfc_diag_init()!=0 )) goto errexit;
#if defined(CONFIG_COMPAT) && !defined(__ia64__)
	if(register_ioctl32_conversion(LPFC_DFC_CMD_IOCTL32, lpfc_ioctl32_handler) !=0) goto errexit;
#endif
	lpfc_loadtime = jiffies;

	if (lpfc_scsi_req_tmo > LPFC_MAX_SCSI_REQ_TMO) {
		lpfc_scsi_req_tmo =  LPFC_DFT_SCSI_REQ_TMO;
	}

	if (lpfc_scsi_req_tmo != LPFC_SCSI_REQ_TMO_DEFAULT) {
		printk("%s: setting scsi request timeout, lpfc_scsi_req_tmo, to %d secs\n",
			__FUNCTION__, lpfc_scsi_req_tmo);
	}

	return 0;

	errexit:
	unreg_all_ioctl_entries();
	return -ENODEV;
}

static void __exit
lpfc_cdev_exit(void)
{
	unreg_ioctl_entry(lpfc_process_ioctl_util);
	unreg_ioctl_entry(lpfc_process_ioctl_hbaapi);
	unreg_ioctl_entry(lpfc_process_ioctl_dfc);
	lpfc_diag_uninit();
#if defined(CONFIG_COMPAT) && !defined(__ia64__)
	unregister_ioctl32_conversion(LPFC_DFC_CMD_IOCTL32);
#endif
}

module_init(lpfc_cdev_init);
module_exit(lpfc_cdev_exit);

MODULE_DESCRIPTION("Emulex LightPulse Fibre Channel driver IOCTL support");
MODULE_AUTHOR("Emulex Corporation - tech.support@emulex.com");
MODULE_LICENSE("GPL");
MODULE_VERSION("0:" LPFCDFC_DRIVER_VERSION);

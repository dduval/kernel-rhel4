/*
 * iSCSI driver for Linux
 * Copyright (C) 2001 Cisco Systems, Inc.
 * Copyright (C) 2004 Mike Christie
 * Copyright (C) 2004 IBM Corporation
 * maintained by linux-iscsi-devel@lists.sourceforge.net
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 *
 * $Id: iscsi-ioctl.c,v 1.1.2.20 2005/04/12 19:18:33 mikenc Exp $
 *
 * This file handles iscsi ioctl calls
 */
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/ioctl32.h>
#include <asm/uaccess.h>

#include "iscsi-session.h"
#include "iscsi-ioctl.h"
#include "iscsi-sfnet.h"

static int
iscsi_ioctl_establish_session(void __user *arg)
{
	int rc;
	struct iscsi_session *session;
	struct iscsi_session_ioctl *ioctld;

	ioctld = kmalloc(sizeof(*ioctld), GFP_KERNEL);
	if (!ioctld) {
		iscsi_err("Couldn't allocate space for session ioctl data\n");
		return -ENOMEM;
	}

	if (copy_from_user(ioctld, (void *)arg, sizeof(*ioctld))) {
		iscsi_err("Cannot copy session ioctl data\n");
		kfree(ioctld);
		return -EFAULT;
	}

	if (ioctld->ioctl_version != ISCSI_SESSION_IOCTL_VERSION) {
		iscsi_err("ioctl version %u incorrect, expecting %u\n",
			  ioctld->ioctl_version, ISCSI_SESSION_IOCTL_VERSION);
		return -EINVAL;
	}

	/*
	 * TODO - should update wait for the relogin?
	 */
	session = iscsi_find_session(ioctld->target_name, ioctld->isid,
				     ioctld->portal.tag);
	if (session) {
		rc = iscsi_update_session(session, ioctld);
		scsi_host_put(session->shost);
	} else if (ioctld->update) {
		iscsi_err("Could not find session to update\n");
		rc = -EAGAIN;
	} else
		rc = iscsi_create_host(ioctld);

	kfree(ioctld);
	return rc;
}

static int
iscsi_ctl_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
		unsigned long arg)
{
	void __user *_arg = (void __user *) arg;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (_IOC_TYPE(cmd) != ISCSI_IOCTL)
		return -ENOTTY;

	if (cmd == ISCSI_ESTABLISH_SESSION)
		return iscsi_ioctl_establish_session(_arg);

	iscsi_err("Requested ioctl not found\n");
	return -EINVAL;
}

static struct class_simple *iscsictl_sysfs_class;
static int control_major;
static const char *control_name = "iscsictl";

static struct file_operations control_fops = {
      .owner = THIS_MODULE,
      .ioctl = iscsi_ctl_ioctl,
};

int
iscsi_register_interface(void)
{
	control_major = register_chrdev(0, control_name, &control_fops);
	if (control_major < 0) {
		iscsi_err("Failed to register the control device\n");
		return -ENODEV;
	}
	iscsi_notice("Control device major number %d\n", control_major);

	 /* Provide udev support for the control device. */
	iscsictl_sysfs_class = class_simple_create(THIS_MODULE,
						   "iscsi_control");
	if (!iscsictl_sysfs_class)
		goto unreg_chrdev;

	if (!class_simple_device_add(iscsictl_sysfs_class,
				     MKDEV(control_major, 0), NULL,
				     "iscsictl"))
		goto destroy_iscsictl_cls;

	if (register_ioctl32_conversion(ISCSI_ESTABLISH_SESSION, NULL))
		goto remove_iscsictl_cls;

	return 0;

 remove_iscsictl_cls:
	class_simple_device_remove(MKDEV(control_major, 0));
 destroy_iscsictl_cls:
	class_simple_destroy(iscsictl_sysfs_class);
 unreg_chrdev:
	unregister_chrdev(control_major, control_name);
	return -ENODEV;
}

void
iscsi_unregister_interface(void)
{
	unregister_ioctl32_conversion(ISCSI_ESTABLISH_SESSION);
	class_simple_device_remove(MKDEV(control_major, 0));
	class_simple_destroy(iscsictl_sysfs_class);
	unregister_chrdev(control_major, control_name);
}

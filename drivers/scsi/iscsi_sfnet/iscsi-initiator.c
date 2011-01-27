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
 * $Id: iscsi-initiator.c,v 1.1.2.47 2005/04/27 06:26:20 mikenc Exp $
 *
 * This file contains interfaces required by SCSI mid layer, module
 * initialization and shutdown routines.
 */
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/moduleparam.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/in.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_transport.h>

#include "iscsi-sfnet.h"
#include "iscsi-session.h"
#include "iscsi-protocol.h"
#include "iscsi-task.h"

/*
 *  IMPORTANT NOTE: to prevent deadlock, when holding multiple locks,
 *  the following locking order must be followed at all times:
 *
 *  session->portal_lock      - access to a session's portal info
 *  session->task_lock        - access to a session's collections of tasks
 *  host_lock                 - mid-layer acquires before calling queuecommand,
 * 				and eh_*.
 *
 *  Note for grabbing task_lock: queuecommand and eh_timed_out are invoked in
 *  soft_irq context. The former can be invoked in process context as well. 
 *  Every other function where we grab task_lock, we have process context.
 *  Hence we use spin_lock in replacement_timed_out and spin_lock_bh every
 *  where else to grab the task lock.
 */

MODULE_AUTHOR("Mike Christie and Cisco Systems, Inc.");
MODULE_DESCRIPTION("iSCSI initiator");
MODULE_LICENSE("GPL");
MODULE_VERSION(ISCSI_DRIVER_VERSION);

kmem_cache_t *iscsi_task_cache;
static struct scsi_transport_template *iscsi_transportt;

static unsigned short iscsi_max_sg = 64;
module_param_named(max_sg, iscsi_max_sg, ushort, S_IRUGO);

static unsigned short iscsi_max_sectors = 256;
module_param_named(max_sectors, iscsi_max_sectors, ushort, S_IRUGO);

static unsigned int iscsi_can_queue = 512;
module_param_named(can_queue, iscsi_can_queue, uint, S_IRUGO);

/* Serial Number Arithmetic, 32 bits, less than, RFC1982 */
#define SNA32_CHECK 2147483648UL

int
iscsi_sna_lt(u32 n1, u32 n2)
{
	return n1 != n2 && ((n1 < n2 && (n2 - n1 < SNA32_CHECK)) ||
			    (n1 > n2 && (n2 - n1 < SNA32_CHECK)));
}

/* Serial Number Arithmetic, 32 bits, less than, RFC1982 */
int
iscsi_sna_lte(u32 n1, u32 n2)
{
	return n1 == n2 || ((n1 < n2 && (n2 - n1 < SNA32_CHECK)) ||
			    (n1 > n2 && (n2 - n1 < SNA32_CHECK)));
}

/* mark a scsi_cmnd as having a LUN communication failure */
static inline void
set_lun_comm_failure(struct scsi_cmnd *sc)
{
	sc->sense_buffer[0] = 0x70;
	sc->sense_buffer[2] = NOT_READY;
	sc->sense_buffer[7] = 0x6;
	sc->sense_buffer[12] = 0x08;
	sc->sense_buffer[13] = 0x00;
}

u32
iscsi_command_attr(struct scsi_cmnd *cmd)
{
	unsigned int attr = ISCSI_ATTR_UNTAGGED;
	char msg[2];

	if (scsi_populate_tag_msg(cmd, msg) == 2) {
		switch (msg[0]) {
		case MSG_SIMPLE_TAG:
			attr = ISCSI_ATTR_SIMPLE;
			break;
		case MSG_HEAD_TAG:
			attr = ISCSI_ATTR_HEAD_OF_QUEUE;
			break;
		case MSG_ORDERED_TAG:
			attr = ISCSI_ATTR_ORDERED;
			break;
		};
	}

	return attr;
}

static int
iscsi_slave_configure(struct scsi_device *sdev)
{
	int depth = 1, tag = 0;

        /*
	 * TODO (one day) - when tcq is not supported we should
	 * internally queue a command to have one ready to go right
	 * away when the outstanding one completes.
         */
	if (sdev->tagged_supported) {
		scsi_activate_tcq(sdev, ISCSI_CMDS_PER_LUN);
		depth = ISCSI_CMDS_PER_LUN;
		tag = MSG_ORDERED_TAG;
	}

	scsi_adjust_queue_depth(sdev, tag, depth);
	return 0;
}

static int
iscsi_eh_abort(struct scsi_cmnd *sc)
{
	struct Scsi_Host *shost = sc->device->host;
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;
	struct iscsi_task *task, *tmf_task;
	int ret = FAILED;

	spin_unlock_irq(shost->host_lock);
	spin_lock_bh(&session->task_lock);

	/*
	 * TODO must fix these type of tests
	 */
	if (!test_bit(SESSION_ESTABLISHED, &session->control_bits))
		goto done;

	task = (struct iscsi_task *)sc->SCp.ptr;
	if (!task) {
		iscsi_host_err(session, "eh_abort cmnd already done\n");
		ret = SUCCESS;
		goto done;
	}

	if (task->itt == ISCSI_RSVD_TASK_TAG) {
		__iscsi_complete_task(task);
		ret = SUCCESS;
		goto done;
	}

	/*
	 * TODO need a iscsi_dev_info
	 */
	iscsi_host_info(session, "Sending ABORT TASK for task itt %u\n",
			task->itt);

	tmf_task = session->mgmt_task;
	memset(tmf_task, 0, sizeof(*tmf_task));
	iscsi_init_task(tmf_task);
	tmf_task->session = session;
	tmf_task->lun = task->lun;
	/*
	 * this will become the refcmdsn
	 */
	tmf_task->cmdsn = task->cmdsn;
	tmf_task->rtt = task->itt;
	set_bit(ISCSI_TASK_ABORT, &tmf_task->flags);

	if (!iscsi_exec_task_mgmt(tmf_task, session->abort_timeout)) {
		ret = SUCCESS;
		goto done;
	}
	/*
	 * TMF may have failed if the task completed first (check here)
	 */
	if (!sc->SCp.ptr)
		ret = SUCCESS;
 done:
	spin_unlock_bh(&session->task_lock);
	spin_lock_irq(shost->host_lock);

	return ret;
}

static int
iscsi_eh_device_reset(struct scsi_cmnd *sc)
{
	struct Scsi_Host *shost = sc->device->host;
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;
	struct iscsi_task *task;
	int ret = FAILED;

	spin_unlock_irq(shost->host_lock);
	spin_lock_bh(&session->task_lock);

	if (!test_bit(SESSION_ESTABLISHED, &session->control_bits))
		goto done;

	task = session->mgmt_task;
	memset(task, 0, sizeof(*task));
	iscsi_init_task(task);
	task->session = session;
	task->lun = sc->device->lun;
	__set_bit(ISCSI_TASK_ABORT_TASK_SET, &task->flags);

	/*
	 * need a iscsi_dev_info
	 */
	iscsi_host_info(session, "Sending ABORT TASK SET\n");
	if (!iscsi_exec_task_mgmt(task, session->abort_timeout)) {
		ret = SUCCESS;
		goto done;
	}

	iscsi_init_task(task);
	__set_bit(ISCSI_TASK_LU_RESET, &task->flags);

	iscsi_host_info(session, "Sending LU RESET\n");
 	if (!iscsi_exec_task_mgmt(task, session->reset_timeout))
		ret = SUCCESS;
 done:
	spin_unlock_bh(&session->task_lock);
	spin_lock_irq(shost->host_lock);

	return ret;
}

static int
iscsi_eh_host_reset(struct scsi_cmnd *sc)
{
	struct Scsi_Host *shost = sc->device->host;
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;
	struct iscsi_task *task;
	int ret = FAILED;

	spin_unlock_irq(shost->host_lock);
	spin_lock_bh(&session->task_lock);

	if (!test_bit(SESSION_ESTABLISHED, &session->control_bits))
		goto done;

	task = session->mgmt_task;
	memset(task, 0, sizeof(*task));
	iscsi_init_task(task);
	task->session = session;
	__set_bit(ISCSI_TASK_TGT_WARM_RESET, &task->flags);

	iscsi_host_info(session, "Sending TARGET WARM RESET\n");
	if (iscsi_exec_task_mgmt(task, session->reset_timeout))
		/*
		 * no other options
		 */
		iscsi_drop_session(session);

 done:
	/*
	 * if we failed, scsi-ml will put us offline
	 * and if we were successful it will redrive the
	 * commands, so we clean everything up from our side
	 * so scsi-ml can retake ownership of the commands.
	 * (At this point the tx and rx threads will not be
	 * touching the commands since either the session
	 * was dropped or we just did a target reset)
	 */
	iscsi_flush_queues(session, ISCSI_MAX_LUNS, DID_BUS_BUSY);

	spin_unlock_bh(&session->task_lock);
	if (iscsi_wait_for_session(session, 0))
		ret = SUCCESS;
	spin_lock_irq(shost->host_lock);

	return ret;
}

void
iscsi_complete_command(struct scsi_cmnd *sc)
{
	sc->SCp.ptr = NULL;
	sc->scsi_done(sc);
}

/**
 * iscsi_queuecommand - queuecommand interface for the iSCSI driver.
 * @sc: scsi command from the midlayer
 * @done: Call back function to be called once the command is executed.
 **/
static int
iscsi_queuecommand(struct scsi_cmnd *sc, void (*done) (struct scsi_cmnd *))
{
	struct Scsi_Host *host = sc->device->host;
	struct iscsi_session *session = (struct iscsi_session *)host->hostdata;
	struct iscsi_task *task;
	int ret = 0;

	spin_unlock_irq(host->host_lock);
	
	spin_lock_bh(&session->task_lock);
	if (test_bit(SESSION_REPLACEMENT_TIMEDOUT, &session->control_bits)) {
		spin_unlock_bh(&session->task_lock);
		if (printk_ratelimit())
			iscsi_host_warn(session, "lun%u: Session terminating, "
					"failing to queue cdb 0x%x and any "
					"following commands\n", sc->device->lun,					sc->cmnd[0]);
		goto fail;
	}

	/* make sure we can complete it properly later */
	sc->scsi_done = done;
	sc->result = 0;
	memset(&sc->SCp, 0, sizeof(sc->SCp));

	/*
	 * alloc a task and add it to the pending queue so
	 * the tx-thread will run it
	 */ 
	task = iscsi_alloc_task(session);
	if (!task) {
		ret = SCSI_MLQUEUE_HOST_BUSY;
		goto done;
	}

	task->lun = sc->device->lun;
	task->scsi_cmnd = sc;
	sc->SCp.ptr = (char *)task;
	list_add_tail(&task->queue, &session->pending_queue);

	iscsi_wake_tx_thread(TX_SCSI_COMMAND, session);
 done:
	spin_unlock_bh(&session->task_lock);
	spin_lock_irq(host->host_lock);
	return ret;

 fail:
	spin_lock_irq(host->host_lock);
	sc->result = DID_NO_CONNECT << 16;
	sc->resid = sc->request_bufflen;
	set_lun_comm_failure(sc);

	done(sc);
	return 0;
}

int
iscsi_destroy_host(struct Scsi_Host *shost)
{
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;

	if (!test_bit(SESSION_CREATED, &session->control_bits))
		return -EINVAL;

	if (test_and_set_bit(SESSION_RELEASING, &session->control_bits))
		return -EINVAL;

	scsi_remove_host(shost);
	iscsi_destroy_session(session);
	scsi_host_put(shost);
	return 0;
}

static struct scsi_host_template iscsi_driver_template = {
	.name = "SFNet iSCSI driver",
	.proc_name = ISCSI_PROC_NAME,
	.module = THIS_MODULE,
	.queuecommand = iscsi_queuecommand,
	.eh_abort_handler = iscsi_eh_abort,
	.eh_device_reset_handler = iscsi_eh_device_reset,
	.eh_host_reset_handler = iscsi_eh_host_reset,
	.skip_settle_delay = 1,
	.slave_configure = iscsi_slave_configure,
	.this_id = -1,
	.cmd_per_lun = ISCSI_CMDS_PER_LUN,
	.use_clustering = ENABLE_CLUSTERING,
	.emulated = 1,
	.shost_attrs = iscsi_host_attrs,
	.sdev_attrs = iscsi_dev_attrs,
};

int
iscsi_create_host(struct iscsi_session_ioctl *ioctld)
{
	struct Scsi_Host *shost;
	struct iscsi_session *session;
	int rc;

	shost = scsi_host_alloc(&iscsi_driver_template, sizeof(*session));
	if (!shost) 
		return -ENOMEM;

	shost->max_id = ISCSI_MAX_TARGETS;
	shost->max_lun = ISCSI_MAX_LUNS;
	shost->max_channel = ISCSI_MAX_CHANNELS;
	shost->max_cmd_len = ISCSI_MAX_CMD_LEN;
	shost->transportt = iscsi_transportt;

	shost->max_sectors = iscsi_max_sectors;
	if (!shost->max_sectors || shost->max_sectors > ISCSI_MAX_SECTORS) {
		iscsi_err("Invalid max_sectors of %d using %d\n",
			  shost->max_sectors, ISCSI_MAX_SECTORS);
		shost->max_sectors = ISCSI_MAX_SECTORS;
	}

	shost->sg_tablesize = iscsi_max_sg;
	if (!shost->sg_tablesize || shost->sg_tablesize > ISCSI_MAX_SG) {
		iscsi_err("Invalid max_sq of %d using %d\n",
			  shost->sg_tablesize, ISCSI_MAX_SG);
		shost->sg_tablesize = ISCSI_MAX_SG;
	}

	shost->can_queue = iscsi_can_queue;
	if (!shost->can_queue || shost->can_queue > ISCSI_MAX_CAN_QUEUE) {
		iscsi_err("Invalid can_queue of %d using %d\n",
			  shost->can_queue, ISCSI_MAX_CAN_QUEUE);
		shost->can_queue = ISCSI_MAX_CAN_QUEUE;
	}

	session = (struct iscsi_session *)shost->hostdata;
	memset(session, 0, sizeof(*session));
	session->shost = shost;

	rc = iscsi_create_session(session, ioctld);
	if (rc) {
		scsi_host_put(shost);
		return rc;
	}

	rc = scsi_add_host(shost, NULL);
	if (rc) {
		iscsi_destroy_session(session);
		scsi_host_put(shost);
		return rc;
	}

	scsi_scan_host(shost);
	set_bit(SESSION_CREATED, &session->control_bits);

	return 0;
}

/*
 * This function must only be called when the sysfs and
 * ioctl interfaces are inaccessible. For example when
 * the module_exit function is executed the driver's sysfs
 * and ioctl entry points will return "no device".
 */
static void
iscsi_destroy_all_hosts(void)
{
	struct iscsi_session *session, *tmp;

	list_for_each_entry_safe(session, tmp, &iscsi_sessions, list)
		iscsi_destroy_host(session->shost);
}

static int
iscsi_reboot_notifier_function(struct notifier_block *this,
			       unsigned long code, void *unused)
{
	iscsi_destroy_all_hosts();
	iscsi_notice("Driver shutdown completed\n");
	return NOTIFY_DONE;
}

/* XXX move this to driver model shutdown */
static struct notifier_block iscsi_reboot_notifier = {
	.notifier_call = iscsi_reboot_notifier_function,
	.next = NULL,
	.priority = 255, /* priority, might need to have a
			  * relook at the value
			  */
};

static int
__init iscsi_init(void)
{
	iscsi_notice("Loading iscsi_sfnet version %s\n", ISCSI_DRIVER_VERSION);

	/* pool of iscsi tasks */
	iscsi_task_cache = kmem_cache_create("iscsi_task_cache",
					     sizeof(struct iscsi_task), 0,
					     SLAB_NO_REAP, NULL, NULL);

	if (!iscsi_task_cache) {
		iscsi_err("kmem_cache_create failed\n");
		return -ENOMEM;
	}

	iscsi_transportt = iscsi_attach_transport(&iscsi_fnt);
	if (!iscsi_transportt)
		goto free_cache;

	if (iscsi_register_interface())
		goto release_transport;

	register_reboot_notifier(&iscsi_reboot_notifier);
	return 0;

 release_transport:
	iscsi_release_transport(iscsi_transportt);
 free_cache:
	kmem_cache_destroy(iscsi_task_cache);
	iscsi_err("Failed to init driver\n");
	return -ENODEV;
}

static void
__exit iscsi_cleanup(void)
{
	unregister_reboot_notifier(&iscsi_reboot_notifier);
	iscsi_unregister_interface();
	iscsi_destroy_all_hosts();
	iscsi_release_transport(iscsi_transportt);
	kmem_cache_destroy(iscsi_task_cache);
}
module_init(iscsi_init);
module_exit(iscsi_cleanup);

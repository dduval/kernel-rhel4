/*
 * Serial Attached SCSI (SAS) class SCSI Host glue.
 *
 * Copyright (C) 2005 Adaptec, Inc.  All rights reserved.
 * Copyright (C) 2005 Luben Tuikov <luben_tuikov@adaptec.com>
 *
 * This file is licensed under GPLv2.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 * $Id: //depot/sas-class/sas_scsi_host.c#60 $
 */

#include "sas_internal.h"
#include <scsi/sas/sas_discover.h>
#include <scsi/sas/sas_task.h>

#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi.h>

#include <linux/err.h>
#include <linux/blkdev.h>
#include <linux/kobject.h>
#include <asm/scatterlist.h>

/* The SAM LUN structure should be _completely_ opaque to SCSI Core.
 * This is why this macro here, and not using the broken
 * scsilun_to_int().  Ideally, a SCSI LUN should be communicated in
 * its entirety, and not as an integer.  For some unknown to myself
 * reason, SCSI Core thinks that SCSI LUNs can be interpreted as
 * integers.
 */
#define SCSI_LUN(_sam_lun)   ((unsigned int)be32_to_cpu(*(__be32 *)_sam_lun))

/* ---------- SCSI Core device registration ---------- */

int  sas_register_with_scsi(struct LU *lu)
{
	struct scsi_device *sdev;

	lu->map.channel = lu->parent->port->id;
	lu->map.id      = sas_reserve_free_id(lu->parent->port);
	if (lu->map.id == -ENOMEM)
		return -ENOMEM;

	sdev = scsi_add_device(lu->parent->port->ha->core.shost,
			      lu->map.channel, lu->map.id,
			      SCSI_LUN(lu->LUN));
	return IS_ERR(sdev) ? PTR_ERR(sdev) : 0;
}

void sas_unregister_with_scsi(struct LU *lu)
{
	if (lu->uldd_dev) {
		struct scsi_device *scsi_dev = lu->uldd_dev;
		scsi_remove_device(scsi_dev);
	}
}

/* ---------- SCSI Host glue ---------- */

#define TO_SAS_TASK(_scsi_cmd)  ((void *)(_scsi_cmd)->host_scribble)
#define ASSIGN_SAS_TASK(_sc, _t) do { (_sc)->host_scribble = (void *) _t; } while (0)

static void sas_scsi_task_done(struct sas_task *task)
{
	struct task_status_struct *ts = &task->task_status;
	struct scsi_cmnd *sc = task->uldd_task;
	unsigned ts_flags = task->task_state_flags;
	int hs = 0, stat = 0;

	if (unlikely(!sc)) {
		SAS_DPRINTK("task_done called with non existing SCSI cmnd!\n");
		list_del_init(&task->list);
		sas_free_task(task);
		return;
	}

	if (ts->resp == SAS_TASK_UNDELIVERED) {
		/* transport error */
		hs = DID_NO_CONNECT;
	} else { /* ts->resp == SAS_TASK_COMPLETE */
		/* task delivered, what happened afterwards? */
		switch (ts->stat) {
		case SAS_DEV_NO_RESPONSE:
		case SAS_INTERRUPTED:
		case SAS_PHY_DOWN:
		case SAS_NAK_R_ERR:
		case SAS_OPEN_TO:
			hs = DID_NO_CONNECT;
			break;
		case SAS_DATA_UNDERRUN:
			sc->resid = ts->residual;
			if (sc->request_bufflen - sc->resid < sc->underflow)
				hs = DID_ERROR;
			break;
		case SAS_DATA_OVERRUN:
			hs = DID_ERROR;
			break;
		case SAS_QUEUE_FULL:
			hs = DID_SOFT_ERROR; /* retry */
			break;
		case SAS_DEVICE_UNKNOWN:
			hs = DID_BAD_TARGET;
			break;
		case SAS_SG_ERR:
			hs = DID_PARITY;
			break;
		case SAS_OPEN_REJECT:
			if (ts->open_rej_reason == SAS_OREJ_RSVD_RETRY)
				hs = DID_SOFT_ERROR; /* retry */
			else
				hs = DID_ERROR;
			break;
		case SAS_PROTO_RESPONSE:
			SAS_DPRINTK("LLDD:%s sent SAS_PROTO_RESP for an SSP "
				    "task; please report this\n",
				    task->dev->port->ha->sas_ha_name);
			break;
		case SAS_ABORTED_TASK:
			hs = DID_ABORT;
			break;
		case SAM_CHECK_COND:
			memcpy(sc->sense_buffer, ts->buf,
			       max(SCSI_SENSE_BUFFERSIZE, ts->buf_valid_size));
			stat = SAM_CHECK_COND;
			break;
		default:
			stat = ts->stat;
			break;
		}
	}
	ASSIGN_SAS_TASK(sc, NULL);
	sc->result = (hs << 16) | stat;
	list_del_init(&task->list);
	sas_free_task(task);
	/* This is very ugly but this is how SCSI Core works. */
	if (ts_flags & SAS_TASK_STATE_ABORTED)
		scsi_finish_command(sc);
	else
		sc->scsi_done(sc);
}

static inline enum task_attribute sas_scsi_get_task_attr(struct scsi_cmnd *cmd)
{
	enum task_attribute ta = TASK_ATTR_SIMPLE;
	if (cmd->request && blk_rq_tagged(cmd->request)) {
		if (cmd->device->ordered_tags &&
		    (cmd->request->flags & REQ_HARDBARRIER))
			ta = TASK_ATTR_HOQ;
	}
	return ta;
}

static inline struct sas_task *sas_create_task(struct scsi_cmnd *cmd,
					       struct LU *lu,
					       unsigned long gfp_flags)
{
	struct sas_task *task = sas_alloc_task(gfp_flags);

	if (!task)
		return NULL;

	*(u32 *)cmd->sense_buffer = 0;
	task->uldd_task = cmd;
	ASSIGN_SAS_TASK(cmd, task);

	task->dev = lu->parent;
	task->task_proto = task->dev->tproto; /* BUG_ON(!SSP) */

	task->ssp_task.retry_count = 1;
	memcpy(task->ssp_task.LUN, lu->LUN, 8);
	task->ssp_task.task_attr = sas_scsi_get_task_attr(cmd);
	memcpy(task->ssp_task.cdb, cmd->cmnd, 16);

	task->scatter = cmd->request_buffer;
	task->num_scatter = cmd->use_sg;
	task->total_xfer_len = cmd->request_bufflen;
	task->data_dir = cmd->sc_data_direction;

	task->task_done = sas_scsi_task_done;

	return task;
}

static inline int sas_queue_up(struct sas_task *task)
{
	struct sas_ha_struct *sas_ha = task->dev->port->ha;
	struct scsi_core *core = &sas_ha->core;
	unsigned long flags;
	LIST_HEAD(list);

	spin_lock_irqsave(&core->task_queue_lock, flags);
	if (sas_ha->lldd_queue_size < core->task_queue_size + 1) {
		spin_unlock_irqrestore(&core->task_queue_lock, flags);
		return -SAS_QUEUE_FULL;
	}
	list_add_tail(&task->list, &core->task_queue);
	core->task_queue_size += 1;
	spin_unlock_irqrestore(&core->task_queue_lock, flags);
	up(&core->queue_thread_sema);

	return 0;
}

/**
 * sas_queuecommand -- Enqueue a command for processing
 * @parameters: See SCSI Core documentation
 *
 * Note: XXX: Remove the host unlock/lock pair when SCSI Core can
 * call us without holding an IRQ spinlock...
 */
int sas_queuecommand(struct scsi_cmnd *cmd,
		     void (*scsi_done)(struct scsi_cmnd *))
{
	int res = 0;
	struct LU *lu = cmd->device->hostdata;
	struct Scsi_Host *host = cmd->device->host;

	spin_unlock_irq(host->host_lock);
	if (!lu) {
		SAS_DPRINTK("scsi cmd 0x%p sent to non existing LU\n",
			    cmd);
		cmd->result = DID_BAD_TARGET << 16;
		scsi_done(cmd);
		goto out;
	} else {
		struct sas_ha_struct *sas_ha = lu->parent->port->ha;
		struct sas_task *task;

		res = -ENOMEM;
		task = sas_create_task(cmd, lu, GFP_ATOMIC);
		if (!task)
			goto out;

		cmd->scsi_done = scsi_done;
		/* Queue up, Direct Mode or Task Collector Mode. */
		if (sas_ha->lldd_max_execute_num < 2)
			res = sas_ha->lldd_execute_task(task, 1, GFP_ATOMIC);
		else
			res = sas_queue_up(task);

		/* Examine */
		if (res) {
			SAS_DPRINTK("lldd_execute_task returned: %d\n", res);
			ASSIGN_SAS_TASK(cmd, NULL);
			sas_free_task(task);
			if (res == -SAS_QUEUE_FULL) {
				cmd->result = DID_SOFT_ERROR << 16; /* retry */
				res = 0;
				scsi_done(cmd);
			}
			goto out;
		}
	}
out:
	spin_lock_irq(host->host_lock);
	return res;
}

static void sas_scsi_clear_queue_lu(struct list_head *error_q, struct LU *lu)
{
	struct scsi_cmnd *cmd, *n;

	list_for_each_entry_safe(cmd, n, error_q, eh_entry) {
		struct LU *x = cmd->device->hostdata;

		if (x == lu)
			list_del_init(&cmd->eh_entry);
	}
}

static void sas_scsi_clear_queue_I_T(struct list_head *error_q,
				     struct domain_device *dev)
{
	struct scsi_cmnd *cmd, *n;

	list_for_each_entry_safe(cmd, n, error_q, eh_entry) {
		struct LU *y = cmd->device->hostdata;
		struct domain_device *x = y->parent;

		if (x == dev)
			list_del_init(&cmd->eh_entry);
	}
}

static void sas_scsi_clear_queue_port(struct list_head *error_q,
				      struct sas_port *port)
{
	struct scsi_cmnd *cmd, *n;

	list_for_each_entry_safe(cmd, n, error_q, eh_entry) {
		struct LU *y = cmd->device->hostdata;
		struct sas_port *x = y->parent->port;

		if (x == port)
			list_del_init(&cmd->eh_entry);
	}
}

enum task_disposition {
	TASK_IS_DONE,
	TASK_IS_ABORTED,
	TASK_IS_AT_LU,
	TASK_IS_NOT_AT_LU,
};

static enum task_disposition sas_scsi_find_task(struct sas_task *task)
{
	struct sas_ha_struct *ha = task->dev->port->ha;
	unsigned long flags;
	int i, res;

	if (ha->lldd_max_execute_num > 1) {
		struct scsi_core *core = &ha->core;
		struct sas_task *t, *n;

		spin_lock_irqsave(&core->task_queue_lock, flags);
		list_for_each_entry_safe(t, n, &core->task_queue, list) {
			if (task == t) {
				list_del_init(&t->list);
				spin_unlock_irqrestore(&core->task_queue_lock,
						       flags);
				SAS_DPRINTK("%s: task 0x%p aborted from "
					    "task_queue\n",
					    __FUNCTION__, task);
				return TASK_IS_ABORTED;
			}
		}
		spin_unlock_irqrestore(&core->task_queue_lock, flags);
	}

	for (i = 0; i < 5; i++) {
		SAS_DPRINTK("%s: aborting task 0x%p\n", __FUNCTION__, task);
		res = task->dev->port->ha->lldd_abort_task(task);

		spin_lock_irqsave(&task->task_state_lock, flags);
		if (task->task_state_flags & SAS_TASK_STATE_DONE) {
			spin_unlock_irqrestore(&task->task_state_lock, flags);
			SAS_DPRINTK("%s: task 0x%p is done\n", __FUNCTION__,
				    task);
			return TASK_IS_DONE;
		}
		spin_unlock_irqrestore(&task->task_state_lock, flags);

		if (res == TMF_RESP_FUNC_COMPLETE) {
			SAS_DPRINTK("%s: task 0x%p is aborted\n",
				    __FUNCTION__, task);
			return TASK_IS_ABORTED;
		} else if (ha->lldd_query_task) {
			SAS_DPRINTK("%s: querying task 0x%p\n",
				    __FUNCTION__, task);
			res = ha->lldd_query_task(task);
			if (res == TMF_RESP_FUNC_SUCC) {
				SAS_DPRINTK("%s: task 0x%p at LU\n",
					    __FUNCTION__, task);
				return TASK_IS_AT_LU;
			} else if (res == TMF_RESP_FUNC_COMPLETE) {
				SAS_DPRINTK("%s: task 0x%p not at LU\n",
					    __FUNCTION__, task);
				return TASK_IS_NOT_AT_LU;
			}
		}
	}
	return res;
}

static int sas_recover_lu(struct domain_device *dev, struct LU *lu)
{
	struct sas_ha_struct *ha = dev->port->ha;
	int res = TMF_RESP_FUNC_FAILED;

	SAS_DPRINTK("eh: device %llx LUN %llx has the task\n",
		    SAS_ADDR(dev->sas_addr),
		    SAS_ADDR(lu->LUN));

	if (ha->lldd_abort_task_set)
		res = ha->lldd_abort_task_set(dev, lu->LUN);

	if (res == TMF_RESP_FUNC_FAILED) {
		if (ha->lldd_clear_task_set)
			res = ha->lldd_clear_task_set(dev, lu->LUN);
	}

	if (res == TMF_RESP_FUNC_FAILED) {
		if (ha->lldd_lu_reset)
			res = ha->lldd_lu_reset(dev, lu->LUN);
	}

	return res;
}

static int sas_recover_I_T(struct domain_device *dev)
{
	struct sas_ha_struct *ha = dev->port->ha;
	int res = TMF_RESP_FUNC_FAILED;

	SAS_DPRINTK("I_T nexus reset for dev %016llx\n",
		    SAS_ADDR(dev->sas_addr));

	if (ha->lldd_I_T_nexus_reset)
		res = ha->lldd_I_T_nexus_reset(dev);

	return res;
}

int sas_scsi_recover_host(struct Scsi_Host *shost)
{
	struct sas_ha_struct *ha = SHOST_TO_SAS_HA(shost);
	unsigned long flags;
	LIST_HEAD(error_q);
	struct scsi_cmnd *cmd, *n;
	enum task_disposition res = TASK_IS_DONE;
	int tmf_resp;

	spin_lock_irqsave(shost->host_lock, flags);
	list_splice_init(&shost->eh_cmd_q, &error_q);
	spin_unlock_irqrestore(shost->host_lock, flags);

	SAS_DPRINTK("Enter %s\n", __FUNCTION__);

	/* All tasks on this list were marked SAS_TASK_STATE_ABORTED
	 * by sas_scsi_timed_out() callback.
	 */
Again:
	SAS_DPRINTK("going over list...\n");
	list_for_each_entry_safe(cmd, n, &error_q, eh_entry) {
		struct sas_task *task = TO_SAS_TASK(cmd);
		struct LU *lu = cmd->device->hostdata;

		SAS_DPRINTK("trying to find task 0x%p\n", task);
		list_del_init(&cmd->eh_entry);
		res = sas_scsi_find_task(task);

		cmd->eh_eflags = 0;
		shost->host_failed--;

		switch (res) {
		case TASK_IS_DONE:
			SAS_DPRINTK("%s: task 0x%p is done\n", __FUNCTION__,
				    task);
			task->task_done(task);
			continue;
		case TASK_IS_ABORTED:
			SAS_DPRINTK("%s: task 0x%p is aborted\n",
				    __FUNCTION__, task);
			task->task_done(task);
			continue;
		case TASK_IS_AT_LU:
			SAS_DPRINTK("task 0x%p is at LU: lu recover\n", task);
			tmf_resp = sas_recover_lu(task->dev, lu);
			if (tmf_resp == TMF_RESP_FUNC_COMPLETE) {
				SAS_DPRINTK("dev %016llx LU %016llx is "
					    "recovered\n",
					    SAS_ADDR(task->dev),
					    SAS_ADDR(lu->LUN));
				task->task_done(task);
				sas_scsi_clear_queue_lu(&error_q, lu);
				goto Again;
			}
			/* fallthrough */
		case TASK_IS_NOT_AT_LU:
			SAS_DPRINTK("task 0x%p is not at LU: I_T recover\n",
				    task);
			tmf_resp = sas_recover_I_T(task->dev);
			if (tmf_resp == TMF_RESP_FUNC_COMPLETE) {
				SAS_DPRINTK("I_T %016llx recovered\n",
					    SAS_ADDR(task->dev->sas_addr));
				task->task_done(task);
				sas_scsi_clear_queue_I_T(&error_q, task->dev);
				goto Again;
			}
			/* Hammer time :-) */
			if (ha->lldd_clear_nexus_port) {
				struct sas_port *port = task->dev->port;
				SAS_DPRINTK("clearing nexus for port:%d\n",
					    port->id);
				res = ha->lldd_clear_nexus_port(port);
				if (res == TMF_RESP_FUNC_COMPLETE) {
					SAS_DPRINTK("clear nexus port:%d "
						    "succeeded\n", port->id);
					task->task_done(task);
					sas_scsi_clear_queue_port(&error_q,
								  port);
					goto Again;
				}
			}
			if (ha->lldd_clear_nexus_ha) {
				SAS_DPRINTK("clear nexus ha\n");
				res = ha->lldd_clear_nexus_ha(ha);
				if (res == TMF_RESP_FUNC_COMPLETE) {
					SAS_DPRINTK("clear nexus ha "
						    "succeeded\n");
					task->task_done(task);
					goto out;
				}
			}
			/* If we are here -- this means that no amount
			 * of effort could recover from errors.  Quite
			 * possibly the HA just disappeared.
			 */
			SAS_DPRINTK("error from  device %llx, LUN %llx "
				    "couldn't be recovered in any way\n",
				    SAS_ADDR(task->dev->sas_addr),
				    SAS_ADDR(lu->LUN));

			task->task_done(task);
			goto clear_q;
		}
	}
out:
	SAS_DPRINTK("--- Exit %s\n", __FUNCTION__);
	return 0;
clear_q:
	SAS_DPRINTK("--- Exit %s -- clear_q\n", __FUNCTION__);
	list_for_each_entry_safe(cmd, n, &error_q, eh_entry) {
		struct sas_task *task = TO_SAS_TASK(cmd);
		list_del_init(&cmd->eh_entry);
		task->task_done(task);
	}
	return 0;
}

enum scsi_eh_timer_return sas_scsi_timed_out(struct scsi_cmnd *cmd)
{
	struct sas_task *task = TO_SAS_TASK(cmd);
	unsigned long flags;

	if (!task) {
		SAS_DPRINTK("command 0x%p, task 0x%p, timed out: EH_HANDLED\n",
			    cmd, task);
		return EH_HANDLED;
	}

	spin_lock_irqsave(&task->task_state_lock, flags);
	if (task->task_state_flags & SAS_TASK_STATE_DONE) {
		spin_unlock_irqrestore(&task->task_state_lock, flags);
		SAS_DPRINTK("command 0x%p, task 0x%p, timed out: EH_HANDLED\n",
			    cmd, task);
		return EH_HANDLED;
	}
	task->task_state_flags |= SAS_TASK_STATE_ABORTED;
	spin_unlock_irqrestore(&task->task_state_lock, flags);

	SAS_DPRINTK("command 0x%p, task 0x%p, timed out: EH_NOT_HANDLED\n",
		    cmd, task);

	return EH_NOT_HANDLED;
}

/**
 * sas_slave_alloc -- configure an LU which SCSI Core wants to poke at
 * @scsi_dev: pointer to scsi device
 *
 * The kludge here is that the only token we have to go by in order to
 * identify which device SCSI Core has just found about, is channel,
 * id and lun/2.  Of course this is 1) incredibly broken and 2)
 * leftover from when SCSI Core was SPI-centric.  A solution would be
 * to pass an opaque token to scsi_add_device, which SCSI Core treats
 * as that, an opaque token, which it sets inside scsi_dev, so we can
 * find out which device SCSI Core is talking about.  That is, how
 * SCSI Core is _addressing_ the device is not the business of LLDD
 * and vice versa.  An even _better_ solution is if SCSI Core knew
 * about a "SCSI device with Target ports" so we can register only the
 * targets, and then it would do its own LU discovery...  See comment
 * in sas_do_lu_discovery().
 */
int sas_slave_alloc(struct scsi_device *scsi_dev)
{
	struct sas_ha_struct *sas_ha = SHOST_TO_SAS_HA(scsi_dev->host);
	struct sas_port *port = sas_ha->sas_port[scsi_dev->channel];
        unsigned id = scsi_dev->id;
	unsigned lun = scsi_dev->lun;

	struct domain_device *dev = NULL;
	struct LU *lu = NULL;

	scsi_dev->hostdata = NULL;

	list_for_each_entry(dev, &port->dev_list, dev_list_node) {
		if (dev->dev_type == SAS_END_DEV) {
			list_for_each_entry(lu, &dev->end_dev.LU_list, list) {
				if (lu->map.id == id &&
				    SCSI_LUN(lu->LUN) == lun) {
					scsi_dev->hostdata = lu;
					lu->uldd_dev = scsi_dev;
					goto out_loop;
				}
			}
		}
	}
out_loop:
	if (!scsi_dev->hostdata) {
		SAS_DPRINTK("sas device not found! How is this possible?\n");
		return -ENODEV;
	}
	kobject_get(&lu->lu_obj);
	return 0;
}

#define SAS_DEF_QD 32
#define SAS_MAX_QD 64

int sas_slave_configure(struct scsi_device *scsi_dev)
{
	struct LU *lu = scsi_dev->hostdata;
	struct domain_device *dev;
	struct sas_ha_struct *sas_ha;

	if (!lu) {
		SAS_DPRINTK("slave configure and no LU?!\n");
		return -ENODEV;
	}

	dev = lu->parent;
	sas_ha = dev->port->ha;

	if (scsi_dev->inquiry_len > 7) {
		u8 bq = (scsi_dev->inquiry[6] & 0x80) ? 1 : 0;
		u8 cq = (scsi_dev->inquiry[7] & 0x02) ? 1 : 0;

		if (bq ^ cq) {
			lu->tm_type = (bq<<1) | cq;
			scsi_dev->tagged_supported = 1;
			if (cq)
				scsi_set_tag_type(scsi_dev, MSG_ORDERED_TAG);
			else
				scsi_set_tag_type(scsi_dev, MSG_SIMPLE_TAG);
			scsi_activate_tcq(scsi_dev, SAS_DEF_QD);
		} else {
			SAS_DPRINTK("device %llx, LUN %llx doesn't support "
				    "TCQ\n", SAS_ADDR(dev->sas_addr),
				    SAS_ADDR(lu->LUN));
			scsi_dev->tagged_supported = 0;
			scsi_set_tag_type(scsi_dev, 0);
			scsi_deactivate_tcq(scsi_dev, 1);
		}
	}

	if (dev->end_dev.itnl_timeout > 0)
		scsi_dev->timeout = HZ +
			msecs_to_jiffies(dev->end_dev.itnl_timeout);

	return 0;
}

void sas_slave_destroy(struct scsi_device *scsi_dev)
{
	struct LU *lu = scsi_dev->hostdata;

	if (lu) {
		scsi_dev->hostdata = NULL;
		lu->uldd_dev = NULL;
		kobject_put(&lu->lu_obj);
	}
}

int sas_change_queue_depth(struct scsi_device *scsi_dev, int new_depth)
{
	int res = min(new_depth, SAS_MAX_QD);

	if (scsi_dev->tagged_supported)
		scsi_adjust_queue_depth(scsi_dev, scsi_get_tag_type(scsi_dev),
					res);
	else {
		struct LU *lu = scsi_dev->hostdata;
		sas_printk("device %llx LUN %llx queue depth changed to 1\n",
			   SAS_ADDR(lu->parent->sas_addr),
			   SAS_ADDR(lu->LUN));
		scsi_adjust_queue_depth(scsi_dev, 0, 1);
		res = 1;
	}

	return res;
}

int sas_change_queue_type(struct scsi_device *scsi_dev, int qt)
{
	struct LU *lu = scsi_dev->hostdata;

	if (!scsi_dev->tagged_supported)
		return 0;

	scsi_deactivate_tcq(scsi_dev, 1);

	switch (qt) {
	case MSG_ORDERED_TAG:
		if (lu->tm_type != TASK_MANAGEMENT_FULL)
			qt = MSG_SIMPLE_TAG;
		break;
	case MSG_SIMPLE_TAG:
	default:
		;
	}

	scsi_set_tag_type(scsi_dev, qt);
	scsi_activate_tcq(scsi_dev, scsi_dev->queue_depth);

	return qt;
}

int sas_bios_param(struct scsi_device *scsi_dev,
			  struct block_device *bdev,
			  sector_t capacity, int *hsc)
{
	hsc[0] = 255;
	hsc[1] = 63;
	sector_div(capacity, 255*63);
	hsc[2] = capacity;

	return 0;
}

static inline void sas_init_host_template(struct sas_ha_struct *sas_ha,
			      const struct scsi_host_template *scsi_ht)
{
	struct scsi_host_template *sht = sas_ha->core.sht;

	memcpy(sht, scsi_ht, sizeof(struct scsi_host_template));

	sht->name = sas_ha->sas_ha_name;
	sht->can_queue = sas_ha->lldd_queue_size;
	sht->cmd_per_lun = sht->can_queue;
}

int sas_register_scsi_host(struct sas_ha_struct *sas_ha,
			   const struct scsi_host_template *scsi_ht)
{
	int err = -ENOMEM;

	sas_ha->core.sht = kzalloc(sizeof(*sas_ha->core.sht), GFP_KERNEL);
	if (!sas_ha->core.sht)
		return -ENOMEM;

	sas_init_host_template(sas_ha, scsi_ht);

	sas_ha->core.shost = scsi_host_alloc(sas_ha->core.sht, sizeof(void *));
	if (!sas_ha->core.shost) {
		printk(KERN_NOTICE "couldn't allocate scsi host\n");
		goto out_err;
	}
	SHOST_TO_SAS_HA(sas_ha->core.shost) = sas_ha;

	/* XXX: SCSI Core should really fix this (max vs. num of) */
	sas_ha->core.shost->max_channel = sas_ha->num_phys - 1;
	sas_ha->core.shost->max_id = ~0 - 1;
	sas_ha->core.shost->max_lun = ~0 - 1;

	sas_ha->core.shost->max_cmd_len = 16;

	err = scsi_add_host(sas_ha->core.shost, &sas_ha->pcidev->dev);
	if (err) {
		scsi_host_put(sas_ha->core.shost);
		sas_ha->core.shost = NULL;
		goto out_err;
	}
	return 0;

out_err:
	kfree(sas_ha->core.sht);
	sas_ha->core.sht = NULL;
	return err;
}

void sas_unregister_scsi_host(struct sas_ha_struct *sas_ha)
{
	scsi_remove_host(sas_ha->core.shost);
	scsi_host_put(sas_ha->core.shost);
	sas_ha->core.shost = NULL;
	kfree(sas_ha->core.sht);
	sas_ha->core.sht = NULL;
}

/* ---------- Task Collector Thread implementation ---------- */

static void sas_queue(struct sas_ha_struct *sas_ha)
{
	struct scsi_core *core = &sas_ha->core;
	unsigned long flags;
	LIST_HEAD(q);
	int can_queue;
	int res;

	spin_lock_irqsave(&core->task_queue_lock, flags);
	while (!core->queue_thread_kill &&
	       !list_empty(&core->task_queue)) {

		can_queue = sas_ha->lldd_queue_size - core->task_queue_size;
		if (can_queue >= 0) {
			can_queue = core->task_queue_size;
			list_splice_init(&core->task_queue, &q);
		} else {
			struct list_head *a, *n;

			can_queue = sas_ha->lldd_queue_size;
			list_for_each_safe(a, n, &core->task_queue) {
				list_move_tail(a, &q);
				if (--can_queue == 0)
					break;
			}
			can_queue = sas_ha->lldd_queue_size;
		}
		core->task_queue_size -= can_queue;
		spin_unlock_irqrestore(&core->task_queue_lock, flags);
		{
			struct sas_task *task = list_entry(q.next,
							   struct sas_task,
							   list);
			list_del_init(&q);
			res = sas_ha->lldd_execute_task(task, can_queue,
							GFP_KERNEL);
			if (unlikely(res))
				__list_add(&q, task->list.prev, &task->list);
		}
		spin_lock_irqsave(&core->task_queue_lock, flags);
		if (res) {
			list_splice_init(&q, &core->task_queue); /*at head*/
			core->task_queue_size += can_queue;
		}
	}
	spin_unlock_irqrestore(&core->task_queue_lock, flags);
}

static DECLARE_COMPLETION(queue_th_comp);

/**
 * sas_queue_thread -- The Task Collector thread
 * @_sas_ha: pointer to struct sas_ha
 */
static int sas_queue_thread(void *_sas_ha)
{
	struct sas_ha_struct *sas_ha = _sas_ha;
	struct scsi_core *core = &sas_ha->core;

	daemonize("sas_queue_%d", core->shost->host_no);
	current->flags |= PF_NOFREEZE;

	complete(&queue_th_comp);

	while (1) {
		down_interruptible(&core->queue_thread_sema);
		sas_queue(sas_ha);
		if (core->queue_thread_kill)
			break;
	}

	complete(&queue_th_comp);

	return 0;
}

/* ---------- SCSI Core struct attributes ---------- */

static ssize_t show_task_queue_size(struct scsi_core *core, char *page)
{
	return sprintf(page, "%d\n", core->task_queue_size);
}

struct scsi_core_attribute {
	struct attribute attr;
	ssize_t (*show)(struct scsi_core *, char *);
	ssize_t (*store)(struct scsi_core *, const char *, size_t len);
};

#define to_scsi_core(_obj) container_of((_obj), struct scsi_core, \
					scsi_core_obj)
#define to_sc_attr(_attr) container_of((_attr), struct scsi_core_attribute,\
				       attr)

static ssize_t sc_show_attr(struct kobject *kobj, struct attribute *attr,
			    char *page)
{
	ssize_t ret = 0;
	struct scsi_core *core = to_scsi_core(kobj);
	struct scsi_core_attribute *sc_attr = to_sc_attr(attr);

	if (sc_attr->show)
		ret = sc_attr->show(core, page);
	return ret;
}

static struct scsi_core_attribute sc_attrs[] = {
	__ATTR(task_queue_size, 0444, show_task_queue_size, NULL),
	__ATTR_NULL,
};

static struct attribute *sc_def_attrs[ARRAY_SIZE(sc_attrs)];

static struct sysfs_ops sc_sysfs_ops = {
	.show = sc_show_attr,
};

static struct kobj_type scsi_core_ktype = {
	.sysfs_ops = &sc_sysfs_ops,
	.default_attrs = sc_def_attrs,
};

int sas_init_queue(struct sas_ha_struct *sas_ha)
{
	int res;
	struct scsi_core *core = &sas_ha->core;

	spin_lock_init(&core->task_queue_lock);
	core->task_queue_size = 0;
	INIT_LIST_HEAD(&core->task_queue);
	init_MUTEX_LOCKED(&core->queue_thread_sema);

	res = kernel_thread(sas_queue_thread, sas_ha, 0);
	if (res >= 0) {
		int i;
		wait_for_completion(&queue_th_comp);

		for (i = 0; i < ARRAY_SIZE(sc_attrs)-1; i++)
			sc_def_attrs[i] = &sc_attrs[i].attr;
		sc_def_attrs[i] = NULL;

		core->scsi_core_obj.kset = &sas_ha->ha_kset;
		kobject_set_name(&core->scsi_core_obj, "%s", "scsi_core");
		core->scsi_core_obj.ktype = &scsi_core_ktype;
	}

	return res < 0 ? res : 0;
}

void sas_shutdown_queue(struct sas_ha_struct *sas_ha)
{
	unsigned long flags;
	struct scsi_core *core = &sas_ha->core;
	struct sas_task *task, *n;

	init_completion(&queue_th_comp);
	core->queue_thread_kill = 1;
	up(&core->queue_thread_sema);
	wait_for_completion(&queue_th_comp);

	if (!list_empty(&core->task_queue))
		SAS_DPRINTK("HA: %llx: scsi core task queue is NOT empty!?\n",
			    SAS_ADDR(sas_ha->sas_addr));

	spin_lock_irqsave(&core->task_queue_lock, flags);
	list_for_each_entry_safe(task, n, &core->task_queue, list) {
		struct scsi_cmnd *cmd = task->uldd_task;

		list_del_init(&task->list);

		ASSIGN_SAS_TASK(cmd, NULL);
		sas_free_task(task);
		cmd->result = DID_ABORT << 16;
		cmd->scsi_done(cmd);
	}
	spin_unlock_irqrestore(&core->task_queue_lock, flags);
}

EXPORT_SYMBOL_GPL(sas_queuecommand);
EXPORT_SYMBOL_GPL(sas_scsi_recover_host);
EXPORT_SYMBOL_GPL(sas_scsi_timed_out);
EXPORT_SYMBOL_GPL(sas_slave_alloc);
EXPORT_SYMBOL_GPL(sas_slave_configure);
EXPORT_SYMBOL_GPL(sas_slave_destroy);
EXPORT_SYMBOL_GPL(sas_change_queue_depth);
EXPORT_SYMBOL_GPL(sas_change_queue_type);
EXPORT_SYMBOL_GPL(sas_bios_param);

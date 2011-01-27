/*
 * Serial Attached SCSI (SAS) Discover process
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * $Id: //depot/sas-class/sas_discover.c#140 $
 */

#include <linux/pci.h>
#include <asm/scatterlist.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_eh.h>
#include "sas_internal.h"
#include <scsi/sas/sas_task.h>
#include <scsi/sas/sas_discover.h>

/* ---------- Domain device attributes ---------- */

int scsi_normalize_sense(const u8 *sense_buffer, int sb_len,
                         struct scsi_sense_hdr *sshdr)
{
	if (!sense_buffer || !sb_len)
		return 0;

	memset(sshdr, 0, sizeof(struct scsi_sense_hdr));

	sshdr->response_code = (sense_buffer[0] & 0x7f);

	if (!scsi_sense_valid(sshdr))
		return 0;

	if (sshdr->response_code >= 0x72) {
		/*
		 * descriptor format
		 */
		if (sb_len > 1)
			sshdr->sense_key = (sense_buffer[1] & 0xf);
		if (sb_len > 2)
			sshdr->asc = sense_buffer[2];
		if (sb_len > 3)
			sshdr->ascq = sense_buffer[3];
		if (sb_len > 7)
			sshdr->additional_length = sense_buffer[7];
	} else {
		/* 
		 * fixed format
		 */
		if (sb_len > 2)
			sshdr->sense_key = (sense_buffer[2] & 0xf);
		if (sb_len > 7) {
			sb_len = (sb_len < (sense_buffer[7] + 8)) ?
					 sb_len : (sense_buffer[7] + 8);
			if (sb_len > 12)
				sshdr->asc = sense_buffer[12];
			if (sb_len > 13)
				sshdr->ascq = sense_buffer[13];
		}
	}

	return 1;
}
ssize_t dev_show_type(struct domain_device *dev, char *page)
{
	static const char *dev_type[] = {
		"no device",
		"end device",
		"edge expander",
		"fanout expander",
		"host adapter",
		"sata device",
		"sata port multiplier",
		"sata port multiplier port",
	};
	return sprintf(page, "%s\n", dev_type[dev->dev_type]);
}

ssize_t dev_show_iproto(struct domain_device *dev, char *page)
{
	return sas_show_proto(dev->iproto, page);
}

ssize_t dev_show_tproto(struct domain_device *dev, char *page)
{
	return sas_show_proto(dev->tproto, page);
}

ssize_t dev_show_sas_addr(struct domain_device *dev, char *page)
{
	return sprintf(page, "%llx\n", SAS_ADDR(dev->sas_addr));
}

ssize_t dev_show_linkrate(struct domain_device *dev, char *page)
{
	return sas_show_linkrate(dev->linkrate, page);
}

ssize_t dev_show_min_linkrate(struct domain_device *dev, char *page)
{
	return sas_show_linkrate(dev->min_linkrate, page);
}

ssize_t dev_show_max_linkrate(struct domain_device *dev, char *page)
{
	return sas_show_linkrate(dev->max_linkrate, page);
}

ssize_t dev_show_pathways(struct domain_device *dev, char *page)
{
	return sprintf(page, "%d\n", dev->pathways);
}

/* ---------- SATA specific sysfs ---------- */

static ssize_t sata_show_command_set(struct domain_device *dev, char *page)
{
	static const char *cs[] = {
		"ATA",
		"ATAPI",
	};
	return sprintf(page, "%s\n", cs[dev->sata_dev.command_set]);
}

static ssize_t sata_show_rps_resp(struct domain_device *dev, char *page)
{
	char *buf = page;
	if ((dev->tproto & SAS_PROTO_STP) &&
	    dev->sata_dev.rps_resp.frame_type == SMP_RESPONSE &&
	    dev->sata_dev.rps_resp.function == SMP_REPORT_PHY_SATA &&
	    dev->sata_dev.rps_resp.result == SMP_RESP_FUNC_ACC) {
		int i = 0;
		u8 *p = (u8 *) &dev->sata_dev.rps_resp;
		for (i = 0; i < sizeof(struct smp_resp); i+=4, p+=4) {
			buf += sprintf(buf, "%02x %02x %02x %02x\n",
				       *(p+0), *(p+1), *(p+2), *(p+3));
		}
	}
	return buf-page;
}

static inline int show_chars(__le16 *p, int start, int words, char *page)
{
	int i;
	char *buf = page;

	for (i = start; i < start+words; i++) {
		u16  s = le16_to_cpu(p[i]);
		char a = (s&0xFF00)>>8;
		char b = s&0x00FF;

		if (a == 0)
			break;
		buf += sprintf(buf, "%c", a);
		if (b == 0)
			break;
		buf += sprintf(buf, "%c", b);
	}
	return buf-page;
}

static ssize_t sata_show_serial_number(struct domain_device *dev, char *page)
{
	char *buf = page;
	__le16 *identify_x = NULL;

	if (dev->sata_dev.command_set == ATA_COMMAND_SET)
		identify_x = dev->sata_dev.identify_device;
	else
		identify_x = dev->sata_dev.identify_packet_device;

	if (identify_x &&
	    (dev->dev_type == SATA_DEV || dev->dev_type == SATA_PM_PORT)) {
		buf += show_chars(identify_x, 10, 10, buf);
		buf += sprintf(buf, "\n");
	}
	return buf-page;
}

static ssize_t sata_show_firmware_rev(struct domain_device *dev, char *page)
{
	char *buf = page;
	__le16 *identify_x = NULL;

	if (dev->sata_dev.command_set == ATA_COMMAND_SET)
		identify_x = dev->sata_dev.identify_device;
	else
		identify_x = dev->sata_dev.identify_packet_device;

	if (identify_x &&
	    (dev->dev_type == SATA_DEV || dev->dev_type == SATA_PM_PORT)) {
		buf += show_chars(identify_x, 23, 4, buf);
		buf += sprintf(buf, "\n");
	}
	return buf-page;
}

static ssize_t sata_show_model_number(struct domain_device *dev, char *page)
{
	char *buf = page;
	__le16 *identify_x = NULL;

	if (dev->sata_dev.command_set == ATA_COMMAND_SET)
		identify_x = dev->sata_dev.identify_device;
	else
		identify_x = dev->sata_dev.identify_packet_device;

	if (identify_x &&
	    (dev->dev_type == SATA_DEV || dev->dev_type == SATA_PM_PORT)) {
		buf += show_chars(identify_x, 27, 20, buf);
		buf += sprintf(buf, "\n");
	}
	return buf-page;
}

static ssize_t sata_show_identify_device(struct domain_device *dev, char *page)
{
	char *buf = page;

	if (dev->sata_dev.identify_device &&
	    (dev->dev_type == SATA_DEV || dev->dev_type == SATA_PM_PORT)) {
		__le16 *p = dev->sata_dev.identify_device;
		int i;

		for (i = 0; i < 16; i++) {
			int k;
			for (k = 0; k < 16; k++)
				buf += sprintf(buf, "%04x%s",
					      le16_to_cpu(p[i*16+k]),
					      k==15 ? "\n" : " ");
		}
	}
	return buf-page;
}

static ssize_t sata_show_identify_packet(struct domain_device *dev, char *page)
{
	char *buf = page;

	if (dev->sata_dev.identify_packet_device &&
	    (dev->dev_type == SATA_DEV || dev->dev_type == SATA_PM_PORT)) {
		__le16 *p = dev->sata_dev.identify_packet_device;
		int i;

		for (i = 0; i < 16; i++) {
			int k;
			for (k = 0; k < 16; k++)
				buf += sprintf(buf, "%04x%s",
					      le16_to_cpu(p[i*16+k]),
					      k==15 ? "\n" : " ");
		}
	}

	return buf-page;
}

static ssize_t sata_show_port_no(struct domain_device *dev, char *page)
{
	int res = 0;

	if (dev->dev_type == SATA_PM || dev->dev_type == SATA_PM_PORT)
		res = sprintf(page, "%02Xh\n", dev->sata_dev.port_no);
	return res;
}

/* ---------- SAS end device specific ---------- */

static ssize_t sas_show_rled_meaning(struct domain_device *dev, char *page)
{
	return sprintf(page, "%d\n", dev->end_dev.ready_led_meaning);
}

static ssize_t sas_show_itnl_timeout(struct domain_device *dev, char *page)
{
	return sprintf(page, "0x%04x\n", dev->end_dev.itnl_timeout);
}

static ssize_t sas_show_iresp_timeout(struct domain_device *dev, char *page)
{
	return sprintf(page, "0x%04x\n", dev->end_dev.iresp_timeout);
}

static ssize_t sas_show_rl_wlun(struct domain_device *dev, char *page)
{
	return sprintf(page, "%d\n", dev->end_dev.rl_wlun);
}

/* ---------- LU specific ---------- */

static ssize_t lu_show_lun(struct LU *lu, char *page)
{
	return sprintf(page, "%016llx\n", SAS_ADDR(lu->LUN));
}

static ssize_t lu_show_inq(struct LU *lu, char *_page)
{
	int i;
	char *buf = _page;
	if (lu->inquiry_valid_data_len <= 0)
		return 0;
	for (i = 0; i < lu->inquiry_valid_data_len; i += 4) {
		buf += sprintf(buf, "%02x %02x %02x %02x\n",
			       lu->inquiry_data[i+0], lu->inquiry_data[i+1],
			       lu->inquiry_data[i+2], lu->inquiry_data[i+3]);
	}
	return buf-_page;
}

static ssize_t lu_show_tm_type(struct LU *lu, char *page)
{
	static const char *tm_type[] = {
		"none",
		"full",
		"basic",
	};
	return sprintf(page, "%s\n", tm_type[lu->tm_type]);
}

static ssize_t lu_show_channel(struct LU *lu, char *page)
{
	if (lu->uldd_dev)
		return sprintf(page, "%d\n", lu->map.channel);
	return 0;
}

static ssize_t lu_show_id(struct LU *lu, char *page)
{
	if (lu->uldd_dev)
		return sprintf(page, "%d\n", lu->map.id);
	return 0;
}

/* ---------- Sysfs attribute implementation ---------- */

struct lu_dev_attribute {
	struct attribute attr;
	ssize_t (*show)(struct LU *lu, char *);
	ssize_t (*store)(struct LU *lu, const char *, size_t);
};

static struct lu_dev_attribute lu_attrs[] = {
	__ATTR(lun, 0444, lu_show_lun, NULL),
	__ATTR(inquiry_data, 0444, lu_show_inq, NULL),
	__ATTR(channel, 0444, lu_show_channel, NULL),
	__ATTR(id, 0444, lu_show_id, NULL),
	__ATTR(task_management, 0444, lu_show_tm_type, NULL),
	__ATTR_NULL,
};

static struct domain_dev_attribute dev_attrs[] = {
	__ATTR(dev_type, 0444, dev_show_type, NULL),
	__ATTR(iproto, 0444, dev_show_iproto, NULL),
	__ATTR(tproto, 0444, dev_show_tproto, NULL),
	__ATTR(sas_addr, 0444, dev_show_sas_addr, NULL),
	__ATTR(ready_led_meaning, 0444, sas_show_rled_meaning, NULL),
	__ATTR(itnl_timeout, 0444, sas_show_itnl_timeout, NULL),
	__ATTR(iresp_timeout, 0444, sas_show_iresp_timeout, NULL),
	__ATTR(rl_wlun, 0444, sas_show_rl_wlun, NULL),
	__ATTR(linkrate, 0444, dev_show_linkrate, NULL),
	__ATTR(min_linkrate, 0444, dev_show_min_linkrate, NULL),
	__ATTR(max_linkrate, 0444, dev_show_max_linkrate, NULL),
	__ATTR(pathways, 0444, dev_show_pathways, NULL),
	__ATTR_NULL,
};

static struct domain_dev_attribute sata_attrs[] = {
	__ATTR(dev_type, 0444, dev_show_type, NULL),
	__ATTR(iproto, 0444, dev_show_iproto, NULL),
	__ATTR(tproto, 0444, dev_show_tproto, NULL),
	__ATTR(sas_addr, 0444, dev_show_sas_addr, NULL),
	__ATTR(linkrate, 0444, dev_show_linkrate, NULL),
	__ATTR(min_linkrate, 0444, dev_show_min_linkrate, NULL),
	__ATTR(max_linkrate, 0444, dev_show_max_linkrate, NULL),
	__ATTR(command_set, 0444, sata_show_command_set, NULL),
	__ATTR(report_phy_sata_resp, 0444, sata_show_rps_resp, NULL),
	__ATTR(serial_number, 0444, sata_show_serial_number, NULL),
	__ATTR(firmware_rev, 0444, sata_show_firmware_rev, NULL),
	__ATTR(model_number, 0444, sata_show_model_number, NULL),
	__ATTR(identify_device, 0444, sata_show_identify_device, NULL),
	__ATTR(identify_packet_device, 0444, sata_show_identify_packet, NULL),
	__ATTR(port_no, 0444, sata_show_port_no, NULL),
	__ATTR_NULL,
};

static void end_dev_release(struct kobject *obj)
{
	struct domain_device *dev = to_dom_device(obj);
	BUG_ON(!list_empty(&dev->end_dev.LU_list));
	SAS_DPRINTK("freeing dev %llx\n", SAS_ADDR(dev->sas_addr));
	kfree(dev);
}

static void sata_dev_release(struct kobject *obj)
{
	struct domain_device *dev = to_dom_device(obj);

	SAS_DPRINTK("freeing SATA dev %llx\n", SAS_ADDR(dev->sas_addr));
	/* XXX Hint: unregister this SATA device with SATL.
	if (dev->sata_dev->lu)
		sas_satl_unregister_dev(dev);
	*/
	if (dev->sata_dev.identify_device) {
		void *p = dev->sata_dev.identify_device;
		mb();
		dev->sata_dev.identify_device = NULL;
		kfree(p);
	}
	if (dev->sata_dev.identify_packet_device) {
		void *p = dev->sata_dev.identify_packet_device;
		mb();
		dev->sata_dev.identify_packet_device = NULL;
		kfree(p);
	}
	kfree(dev);
}

static void sas_lu_release(struct kobject *obj)
{
	struct LU *lu = to_lu_device(obj);
	SAS_DPRINTK("freeing LUN %016llx\n", SAS_ADDR(lu->LUN));
	sas_release_scsi_id(lu->parent->port, lu->map.id);
	kfree(lu);
}

static ssize_t dev_show_attr(struct kobject *kobj, struct attribute *attr,
			     char *page)
{
	ssize_t ret = 0;
	struct domain_device *dev = to_dom_device(kobj);
	struct domain_dev_attribute *dev_attr = to_dev_attr(attr);

	if (dev_attr->show)
		ret = dev_attr->show(dev, page);
	return ret;
}

static ssize_t lu_show_attr(struct kobject *obj, struct attribute *attr,
			    char *page)
{
	ssize_t ret = 0;
	struct LU *lu = to_lu_device(obj);
	struct lu_dev_attribute *lu_attr = to_lu_attr(attr);

	if (lu_attr->show)
		ret = lu_attr->show(lu, page);
	return ret;
}

struct sysfs_ops dev_sysfs_ops = {
	.show = dev_show_attr,
};
static struct sysfs_ops lu_sysfs_ops = {
	.show = lu_show_attr,
};

static struct attribute *end_dev_attrs[ARRAY_SIZE(dev_attrs)];
static struct attribute *sata_dev_attrs[ARRAY_SIZE(sata_attrs)];
static struct attribute *lu_dev_attrs[ARRAY_SIZE(lu_attrs)];

static struct kobj_type end_dev_ktype = {
	.release = end_dev_release,
	.sysfs_ops = &dev_sysfs_ops,
	.default_attrs = end_dev_attrs,
};
static struct kobj_type sata_dev_ktype = {
	.release = sata_dev_release,
	.sysfs_ops = &dev_sysfs_ops,
	.default_attrs = sata_dev_attrs,
};
static struct kobj_type lu_dev_ktype = {
	.release = sas_lu_release,
	.sysfs_ops = &lu_sysfs_ops,
	.default_attrs = lu_dev_attrs,
};

struct kobj_type *dev_ktype[] = {
	NULL,
	&end_dev_ktype,
	&ex_dev_ktype,
	&ex_dev_ktype,
	NULL,
	&sata_dev_ktype,
	NULL,
	NULL,
};

/* ---------- Basic task processing for discovery purposes ---------- */

static void sas_task_timedout(unsigned long _task)
{
	struct sas_task *task = (void *) _task;
	unsigned long flags;

	spin_lock_irqsave(&task->task_state_lock, flags);
	if (!(task->task_state_flags & SAS_TASK_STATE_DONE))
		task->task_state_flags |= SAS_TASK_STATE_ABORTED;
	spin_unlock_irqrestore(&task->task_state_lock, flags);

	complete(&task->completion);
}

static void sas_disc_task_done(struct sas_task *task)
{
	if (!del_timer(&task->timer))
		return;
	complete(&task->completion);
}

#define SAS_DEV_TIMEOUT 10

/**
 * sas_execute_task -- Basic task processing for discovery
 * @task: the task to be executed
 * @buffer: pointer to buffer to do I/O
 * @size: size of @buffer
 * @pci_dma_dir: PCI_DMA_...
 */
static int sas_execute_task(struct sas_task *task, void *buffer, int size,
			    int pci_dma_dir)
{
	int res = 0;
	struct scatterlist *scatter = NULL;
	struct task_status_struct *ts = &task->task_status;
	int num_scatter = 0;
	int retries = 0;

	if (pci_dma_dir != PCI_DMA_NONE) {
		scatter = kzalloc(sizeof(*scatter), GFP_KERNEL);
		if (!scatter)
			goto out;

		sg_init_one(scatter, buffer, size);
		num_scatter = 1;
	}

	task->task_proto = task->dev->tproto;
	task->scatter = scatter;
	task->num_scatter = num_scatter;
	task->total_xfer_len = size;
	task->data_dir = pci_dma_dir;
	task->task_done = sas_disc_task_done;

	for (retries = 0; retries < 5; retries++) {
		task->task_state_flags = SAS_TASK_STATE_PENDING;
		init_completion(&task->completion);

		task->timer.data = (unsigned long) task;
		task->timer.function = sas_task_timedout;
		task->timer.expires = jiffies + SAS_DEV_TIMEOUT*HZ;
		add_timer(&task->timer);

		res = task->dev->port->ha->lldd_execute_task(task, 1,
							     GFP_KERNEL);
		if (res) {
			del_timer(&task->timer);
			SAS_DPRINTK("executing SAS discovery task failed:%d\n",
				    res);
			goto ex_err;
		}
		wait_for_completion(&task->completion);
		res = -ETASK;
		if (task->task_state_flags & SAS_TASK_STATE_ABORTED) {
			int res2;
			SAS_DPRINTK("task aborted, flags:0x%x\n",
				    task->task_state_flags);
			res2 = task->dev->port->ha->lldd_abort_task(task);
			SAS_DPRINTK("came back from abort task\n");
			if (!(task->task_state_flags & SAS_TASK_STATE_DONE)) {
				if (res2 == TMF_RESP_FUNC_COMPLETE)
					continue; /* Retry the task */
				else
					goto ex_err;
			}
		}
		if (task->task_status.stat == SAM_BUSY ||
			   task->task_status.stat == SAM_TASK_SET_FULL ||
			   task->task_status.stat == SAS_QUEUE_FULL) {
			SAS_DPRINTK("task: q busy, sleeping...\n");
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ);
		} else if (task->task_status.stat == SAM_CHECK_COND) {
			struct scsi_sense_hdr shdr;

			if (!scsi_normalize_sense(ts->buf, ts->buf_valid_size,
						  &shdr)) {
				SAS_DPRINTK("couldn't normalize sense\n");
				continue;
			}
			if ((shdr.sense_key == 6 && shdr.asc == 0x29) ||
			    (shdr.sense_key == 2 && shdr.asc == 4 &&
			     shdr.ascq == 1)) {
				SAS_DPRINTK("device %016llx LUN: %016llx "
					    "powering up or not ready yet, "
					    "sleeping...\n",
					    SAS_ADDR(task->dev->sas_addr),
					    SAS_ADDR(task->ssp_task.LUN));

				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(5*HZ);
			} else if (shdr.sense_key == 1) {
				res = 0;
				break;
			} else if (shdr.sense_key == 5) {
				break;
			} else {
				SAS_DPRINTK("dev %016llx LUN: %016llx "
					    "sense key:0x%x ASC:0x%x ASCQ:0x%x"
					    "\n",
					    SAS_ADDR(task->dev->sas_addr),
					    SAS_ADDR(task->ssp_task.LUN),
					    shdr.sense_key,
					    shdr.asc, shdr.ascq);
			}
		} else if (task->task_status.resp != SAS_TASK_COMPLETE ||
			   task->task_status.stat != SAM_GOOD) {
			SAS_DPRINTK("task finished with resp:0x%x, "
				    "stat:0x%x\n",
				    task->task_status.resp,
				    task->task_status.stat);
			goto ex_err;
		} else {
			res = 0;
			break;
		}
	}
ex_err:
	if (pci_dma_dir != PCI_DMA_NONE)
		kfree(scatter);
out:
	return res;
}

/* ---------- Domain device discovery ---------- */

/**
 * sas_get_port_device -- Discover devices which caused port creation
 * @port: pointer to struct sas_port of interest
 *
 * Devices directly attached to a HA port, have no parent.  This is
 * how we know they are (domain) "root" devices.  All other devices
 * do, and should have their "parent" pointer set appropriately as
 * soon as a child device is discovered.
 */
static int sas_get_port_device(struct sas_port *port)
{
	unsigned long flags;
	struct sas_phy *phy;
	struct domain_device *dev;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	spin_lock_irqsave(&port->phy_list_lock, flags);
	if (list_empty(&port->phy_list)) {
		spin_unlock_irqrestore(&port->phy_list_lock, flags);
		kfree(dev);
		return -ENODEV;
	}
	phy = container_of(port->phy_list.next, struct sas_phy, port_phy_el);
	spin_lock(&phy->frame_rcvd_lock);
	memcpy(dev->frame_rcvd, phy->frame_rcvd, min(sizeof(dev->frame_rcvd),
					     (size_t)phy->frame_rcvd_size));
	spin_unlock(&phy->frame_rcvd_lock);
	spin_unlock_irqrestore(&port->phy_list_lock, flags);

	if (dev->frame_rcvd[0] == 0x34 && port->oob_mode == SATA_OOB_MODE) {
		struct dev_to_host_fis *fis =
			(struct dev_to_host_fis *) dev->frame_rcvd;
		if (fis->interrupt_reason == 1 && fis->lbal == 1 &&
		    fis->byte_count_low==0x69 && fis->byte_count_high == 0x96
		    && (fis->device & ~0x10) == 0)
			dev->dev_type = SATA_PM;
		else
			dev->dev_type = SATA_DEV;
		dev->tproto = SATA_PROTO;
	} else {
		struct sas_identify_frame *id =
			(struct sas_identify_frame *) dev->frame_rcvd;
		dev->dev_type = id->dev_type;
		dev->iproto = id->initiator_bits;
		dev->tproto = id->target_bits;
	}

	sas_init_dev(dev);

	memcpy(dev->sas_addr, port->attached_sas_addr, SAS_ADDR_SIZE);
	sas_hash_addr(dev->hashed_sas_addr, dev->sas_addr);
	port->port_dev = dev;
	dev->port = port;
	dev->linkrate = port->linkrate;
	dev->min_linkrate = port->linkrate;
	dev->max_linkrate = port->linkrate;
	dev->pathways = port->num_phys;
	memset(port->disc.fanout_sas_addr, 0, SAS_ADDR_SIZE);
	memset(port->disc.eeds_a, 0, SAS_ADDR_SIZE);
	memset(port->disc.eeds_b, 0, SAS_ADDR_SIZE);
	port->disc.max_level = 0;

	return 0;
}

/* ---------- Discover and Revalidate ---------- */

/* ---------- SATA ---------- */

static inline void sas_get_ata_command_set(struct domain_device *dev)
{
	struct dev_to_host_fis *fis =
		(struct dev_to_host_fis *) dev->frame_rcvd;

	if ((fis->sector_count == 1 && /* ATA */
	     fis->lbal         == 1 &&
	     fis->lbam         == 0 &&
	     fis->lbah         == 0 &&
	     fis->device       == 0)
	    ||
	    (fis->sector_count == 0 && /* CE-ATA (mATA) */
	     fis->lbal         == 0 &&
	     fis->lbam         == 0xCE &&
	     fis->lbah         == 0xAA &&
	     (fis->device & ~0x10) == 0))

		dev->sata_dev.command_set = ATA_COMMAND_SET;

	else if ((fis->interrupt_reason == 1 &&	/* ATAPI */
		  fis->lbal             == 1 &&
		  fis->byte_count_low   == 0x14 &&
		  fis->byte_count_high  == 0xEB &&
		  (fis->device & ~0x10) == 0))

		dev->sata_dev.command_set = ATAPI_COMMAND_SET;

	else if ((fis->sector_count == 1 && /* SEMB */
		  fis->lbal         == 1 &&
		  fis->lbam         == 0x3C &&
		  fis->lbah         == 0xC3 &&
		  fis->device       == 0)
		||
		 (fis->interrupt_reason == 1 &&	/* SATA PM */
		  fis->lbal             == 1 &&
		  fis->byte_count_low   == 0x69 &&
		  fis->byte_count_high  == 0x96 &&
		  (fis->device & ~0x10) == 0))

		/* Treat it as a superset? */
		dev->sata_dev.command_set = ATAPI_COMMAND_SET;
}

/**
 * sas_issue_ata_cmd -- Basic SATA command processing for discovery
 * @dev: the device to send the command to
 * @command: the command register
 * @features: the features register
 * @buffer: pointer to buffer to do I/O
 * @size: size of @buffer
 * @pci_dma_dir: PCI_DMA_...
 */
static int sas_issue_ata_cmd(struct domain_device *dev, u8 command,
			     u8 features, void *buffer, int size,
			     int pci_dma_dir)
{
	int res = 0;
	struct sas_task *task;
	struct dev_to_host_fis *d2h_fis = (struct dev_to_host_fis *)
		&dev->frame_rcvd[0];

	res = -ENOMEM;
	task = sas_alloc_task(GFP_KERNEL);
	if (!task)
		goto out;

	task->dev = dev;

	task->ata_task.fis.command = command;
	task->ata_task.fis.features = features;
	task->ata_task.fis.device = d2h_fis->device;
	task->ata_task.retry_count = 1;

	res = sas_execute_task(task, buffer, size, pci_dma_dir);

	sas_free_task(task);
out:
	return res;
}

static void sas_sata_propagate_sas_addr(struct domain_device *dev)
{
	unsigned long flags;
	struct sas_port *port = dev->port;
	struct sas_phy  *phy;

	BUG_ON(dev->parent);

	memcpy(port->attached_sas_addr, dev->sas_addr, SAS_ADDR_SIZE);
	spin_lock_irqsave(&port->phy_list_lock, flags);
	list_for_each_entry(phy, &port->phy_list, port_phy_el)
		memcpy(phy->attached_sas_addr, dev->sas_addr, SAS_ADDR_SIZE);
	spin_unlock_irqrestore(&port->phy_list_lock, flags);
}

#define ATA_IDENTIFY_DEV         0xEC
#define ATA_IDENTIFY_PACKET_DEV  0xA1
#define ATA_SET_FEATURES         0xEF
#define ATA_FEATURE_PUP_STBY_SPIN_UP 0x07

/**
 * sas_discover_sata_dev -- discover a STP/SATA device (SATA_DEV)
 * @dev: STP/SATA device of interest (ATA/ATAPI)
 *
 * The LLDD has already been notified of this device, so that we can
 * send FISes to it.  Here we try to get IDENTIFY DEVICE or IDENTIFY
 * PACKET DEVICE, if ATAPI device, so that the LLDD can fine-tune its
 * performance for this device.
 */
static int sas_discover_sata_dev(struct domain_device *dev)
{
	int     res;
	__le16  *identify_x;
	u8      command;

	identify_x = kzalloc(512, GFP_KERNEL);
	if (!identify_x)
		return -ENOMEM;

	if (dev->sata_dev.command_set == ATA_COMMAND_SET) {
		dev->sata_dev.identify_device = identify_x;
		command = ATA_IDENTIFY_DEV;
	} else {
		dev->sata_dev.identify_packet_device = identify_x;
		command = ATA_IDENTIFY_PACKET_DEV;
	}

	res = sas_issue_ata_cmd(dev, command, 0, identify_x, 512,
				PCI_DMA_FROMDEVICE);
	if (res)
		goto out_err;

	/* lives on the media? */
	if (le16_to_cpu(identify_x[0]) & 4) {
		/* incomplete response */
		SAS_DPRINTK("sending SET FEATURE/PUP_STBY_SPIN_UP to "
			    "dev %llx\n", SAS_ADDR(dev->sas_addr));
		if (!le16_to_cpu(identify_x[83] & (1<<6)))
			goto cont1;
		res = sas_issue_ata_cmd(dev, ATA_SET_FEATURES,
					ATA_FEATURE_PUP_STBY_SPIN_UP,
					NULL, 0, PCI_DMA_NONE);
		if (res)
			goto cont1;

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(5*HZ); /* More time? */
		res = sas_issue_ata_cmd(dev, command, 0, identify_x, 512,
					PCI_DMA_FROMDEVICE);
		if (res)
			goto out_err;
	}
cont1:
	/* Get WWN */
	if (dev->port->oob_mode != SATA_OOB_MODE) {
		memcpy(dev->sas_addr, dev->sata_dev.rps_resp.rps.stp_sas_addr,
		       SAS_ADDR_SIZE);
	} else if (dev->sata_dev.command_set == ATA_COMMAND_SET &&
		   (le16_to_cpu(dev->sata_dev.identify_device[108]) & 0xF000)
		   == 0x5000) {
		int i;

		for (i = 0; i < 4; i++) {
			dev->sas_addr[2*i] =
	     (le16_to_cpu(dev->sata_dev.identify_device[108+i]) & 0xFF00) >> 8;
			dev->sas_addr[2*i+1] =
	      le16_to_cpu(dev->sata_dev.identify_device[108+i]) & 0x00FF;
		}
	}
	sas_hash_addr(dev->hashed_sas_addr, dev->sas_addr);
	if (!dev->parent)
		sas_sata_propagate_sas_addr(dev);

	/* XXX Hint: register this SATA device with SATL.
	   When this returns, dev->sata_dev->lu is alive and
	   present.
	sas_satl_register_dev(dev);
	*/
	return 0;
out_err:
	dev->sata_dev.identify_packet_device = NULL;
	dev->sata_dev.identify_device = NULL;
	kfree(identify_x);
	return res;
}

static int sas_discover_sata_pm(struct domain_device *dev)
{
	return -ENODEV;
}

/* ---------- SAS end devices ---------- */

static int sas_get_itnl_timeout(struct domain_device *dev)
{
	static const u8 mode_sense_6[16]  = { 0x1a, };
	static const u8 mode_sense_10[16] = { 0x5a, };

	int res = -ENOMEM;
	struct sas_task *task;
	u8 *buffer, *__buf;
	const int buffer_size = 12;

	task = sas_alloc_task(GFP_KERNEL);
	if (!task)
		return -ENOMEM;
	buffer = kzalloc(buffer_size, GFP_KERNEL);
	if (!buffer)
		goto out;
	__buf = buffer;

	task->dev = dev;

	task->ssp_task.retry_count = 1;
	memcpy(task->ssp_task.cdb, mode_sense_6, 16);
	task->ssp_task.cdb[1] |= (1 << 3);
	task->ssp_task.cdb[2] = 0x19;
	task->ssp_task.cdb[4] = buffer_size;

	res = sas_execute_task(task, buffer, buffer_size, PCI_DMA_FROMDEVICE);
	if (res) {
		SAS_DPRINTK("task to device %llx returned stat 0x%x for "
			    "MODE SENSE 6\n",
			    SAS_ADDR(dev->sas_addr), task->task_status.stat);
		memcpy(task->ssp_task.cdb, mode_sense_10, 16);
		task->ssp_task.cdb[1] |= (1 << 3);
		task->ssp_task.cdb[2] = 0x19;
		task->ssp_task.cdb[8] = buffer_size;

		res = sas_execute_task(task, buffer, buffer_size,
				       PCI_DMA_FROMDEVICE);
		if (res) {
			SAS_DPRINTK("task to device %llx returned stat 0x%x "
				    "for MODE SENSE 10\n",
				    SAS_ADDR(dev->sas_addr),
				    task->task_status.stat);
			goto out_buf;
		}
		dev->end_dev.ms_10 = 1;
		buffer += 4;
	}

	buffer += 4;		  /* skip mode parameter header */

	dev->end_dev.ready_led_meaning = (buffer[2] & (1<<4)) ? 1 : 0;
	dev->end_dev.itnl_timeout = be16_to_cpu(*(__be16 *)(buffer+4));
	dev->end_dev.iresp_timeout= be16_to_cpu(*(__be16 *)(buffer+6));

	res = 0;

out_buf:
	kfree(__buf);
out:
	sas_free_task(task);
	return res;
}

static int sas_get_report_luns(struct domain_device *dev, u8 **buffer,
			       int *size)
{
	static const u8 report_luns[16] = { 0xA0, };
	static const u8 RL_WLUN[8] = { 0xC1, 0x01, };

	int res = -ENOMEM;
	struct sas_task *task;
	u8 *buf;
	int buffer_size = 16;
	u32 len;

	*buffer = kzalloc(buffer_size, GFP_KERNEL);
	if (!*buffer)
		return -ENOMEM;
	buf = *buffer;

	task = sas_alloc_task(GFP_KERNEL);
	if (!task)
		goto out_err;

	task->dev = dev;
	task->ssp_task.retry_count = 1;
	memcpy(task->ssp_task.cdb, report_luns, 16);
	*(__be32 *)(&task->ssp_task.cdb[6]) = cpu_to_be32(buffer_size);

	res = sas_execute_task(task, buf, buffer_size, PCI_DMA_FROMDEVICE);
	if (res) {
		SAS_DPRINTK("REPORT LUNS to LUN0 failed for device %llx "
			    "with status:0x%x\n",
			    SAS_ADDR(dev->sas_addr), task->task_status.stat);
		memcpy(task->ssp_task.LUN, RL_WLUN, 8);
		res = sas_execute_task(task, buf, buffer_size,
				       PCI_DMA_FROMDEVICE);
		if (res) {
			SAS_DPRINTK("REPORT LUNS to REPORT LUNS W-LUN failed "
				    "for device %llx with status:0x%x\n",
				    SAS_ADDR(dev->sas_addr),
				    task->task_status.stat);
			goto out_err_task;
		}
		dev->end_dev.rl_wlun = 1;
	}

	len = be32_to_cpu(*(__be32 *)buf);
	if (len + 8 > buffer_size) {
		SAS_DPRINTK("need bigger buffer for REPORT LUNS\n");
		buffer_size = len + 8;
		res = -ENOMEM;
		buf = kzalloc(buffer_size, GFP_KERNEL);
		if (!buf)
			goto out_err_task;
		kfree(*buffer);
		*buffer = buf;
		if (dev->end_dev.rl_wlun)
			memcpy(task->ssp_task.LUN, RL_WLUN, 8);
		else
			memset(task->ssp_task.LUN, 0, 8);
		res = sas_execute_task(task, buf, buffer_size,
				       PCI_DMA_FROMDEVICE);
		if (res) {
			SAS_DPRINTK("2nd REPORT LUNS to %s failed "
				    "for device %llx with status:0x%x\n",
				    dev->end_dev.rl_wlun ? "REPORT LUNS W-LUN"
				    : "LUN0",
				    SAS_ADDR(dev->sas_addr),
				    task->task_status.stat);
			goto out_err_task;
		}
	}

	*size = len+8;
	sas_free_task(task);
	return 0;

out_err_task:
	sas_free_task(task);
out_err:
	kfree(*buffer);
	*buffer = NULL;
	size = 0;
	return res;
}

static int sas_get_inquiry(struct LU *lu)
{
	static const u8 inquiry_cmd[16] = { 0x12, };
	struct sas_task *task;
	int res;

	task = sas_alloc_task(GFP_KERNEL);
	if (!task)
		return -ENOMEM;

	task->dev = lu->parent;
	task->ssp_task.retry_count = 1;
	memcpy(task->ssp_task.LUN, lu->LUN, 8);
	memcpy(task->ssp_task.cdb, inquiry_cmd, 16);
	*(__be16 *)(task->ssp_task.cdb+3) = cpu_to_be16(SAS_INQUIRY_DATA_LEN);

	res = sas_execute_task(task, lu->inquiry_data, SAS_INQUIRY_DATA_LEN,
			       PCI_DMA_FROMDEVICE);
	if (!res)
		lu->inquiry_valid_data_len = min(SAS_INQUIRY_DATA_LEN,
						 lu->inquiry_data[4]+5);
	sas_free_task(task);
	return res;
}

static struct LU *sas_alloc_lu(void)
{
	struct LU *lu = kzalloc(sizeof(*lu), GFP_KERNEL);
	if (lu)
		INIT_LIST_HEAD(&lu->list);
	return lu;
}

static int sas_register_lu(struct domain_device *dev, u8 *buf, int size)
{
	int res;

	for (buf = buf+8, size -= 8; size > 0; size -= 8, buf += 8) {
		struct LU *lu = sas_alloc_lu();

		SAS_DPRINTK("%016llx probing LUN:%016llx\n",
			    SAS_ADDR(dev->sas_addr),
			    be64_to_cpu(*(__be64 *)buf));
		if (lu) {
			lu->parent = dev;
			memcpy(lu->LUN, buf, 8);
			res = sas_get_inquiry(lu);
			if (res) {
				SAS_DPRINTK("dev %llx LUN %016llx didn't reply"
					    " to INQUIRY, forgotten\n",
					    SAS_ADDR(dev->sas_addr),
					    SAS_ADDR(lu->LUN));
				kfree(lu);
				continue;
			}
			lu->lu_obj.kset = &dev->end_dev.LU_kset;
			kobject_set_name(&lu->lu_obj, "%016llx",
					 SAS_ADDR(lu->LUN));
			lu->lu_obj.ktype = dev->end_dev.LU_kset.ktype;
			list_add_tail(&lu->list, &dev->end_dev.LU_list);
		}
	}

	return list_empty(&dev->end_dev.LU_list) ? -ENODEV : 0;
}

/**
 * sas_do_lu_discovery -- Discover LUs of a SCSI device
 * @dev: pointer to a domain device of interest
 *
 * Discover logical units present in the SCSI device.  I'd like this
 * to be moved to SCSI Core, but SCSI Core has no concept of a "SCSI
 * device with a SCSI Target port".  A SCSI device with a SCSI Target
 * port is a device which the _transport_ found, but other than that,
 * the transport has little or _no_ knowledge about the device.
 * Ideally, a LLDD would register a "SCSI device with a SCSI Target
 * port" with SCSI Core and then SCSI Core would do LU discovery of
 * that device.
 *
 * REPORT LUNS is mandatory.  If a device doesn't support it,
 * it is broken and you should return it.  Nevertheless, we
 * assume (optimistically) that the link hasn't been severed and
 * that maybe we can get to the device anyhow.
 */
static int sas_do_lu_discovery(struct domain_device *dev)
{
	int  res;
	u8  *buffer;
	int  size;

	res = sas_get_report_luns(dev, &buffer, &size);
	if (res) {
		SAS_DPRINTK("dev %llx didn't reply to REPORT LUNS, trying "
			    "LUN 0 anyway\n",
			    SAS_ADDR(dev->sas_addr));
		size = 16;
		buffer = kzalloc(size, GFP_KERNEL);
	}

	res = sas_register_lu(dev, buffer, size);
	if (res) {
		SAS_DPRINTK("dev %llx didn't report any LUs\n",
			    SAS_ADDR(dev->sas_addr));
		res = 0;
	}

	kfree(buffer);
	return res;
}

/* ---------- Common/dispatchers ---------- */

void sas_kobj_set(struct domain_device *dev)
{
	if (!dev->parent) {
		/* device directly attached to the host adapter */
		dev->dev_obj.kset = &dev->port->dev_kset;
	} else {
		/* parent is an expander */
		dev->dev_obj.parent = &dev->parent->dev_obj;
		dev->port = dev->parent->port;
	}

	list_add_tail(&dev->dev_list_node, &dev->port->dev_list);
	kobject_set_name(&dev->dev_obj, "%016llx", SAS_ADDR(dev->sas_addr));
	dev->dev_obj.ktype = dev_ktype[dev->dev_type];
}

/**
 * sas_discover_sata -- discover an STP/SATA domain device
 * @dev: pointer to struct domain_device of interest
 *
 * First we notify the LLDD of this device, so we can send frames to
 * it.  Then depending on the type of device we call the appropriate
 * discover functions.  Once device discover is done, we notify the
 * LLDD so that it can fine-tune its parameters for the device, by
 * removing it and then adding it.  That is, the second time around,
 * the driver would have certain fields, that it is looking at, set.
 * Finally we initialize the kobj so that the device can be added to
 * the system at registration time.  Devices directly attached to a HA
 * port, have no parents.  All other devices do, and should have their
 * "parent" pointer set appropriately before calling this function.
 */
int sas_discover_sata(struct domain_device *dev)
{
	int res;

	sas_get_ata_command_set(dev);

	res = sas_notify_lldd_dev_found(dev);
	if (res)
		return res;

	switch (dev->dev_type) {
	case SATA_DEV:
		res = sas_discover_sata_dev(dev);
		break;
	case SATA_PM:
		res = sas_discover_sata_pm(dev);
		break;
	default:
		break;
	}

	sas_notify_lldd_dev_gone(dev);
	if (!res) {
		sas_notify_lldd_dev_found(dev);
		sas_kobj_set(dev);
	}
	return res;
}

/**
 * sas_discover_end_dev -- discover an end device (SSP, etc)
 * @end: pointer to domain device of interest
 *
 * See comment in sas_discover_sata().
 */
int sas_discover_end_dev(struct domain_device *dev)
{
	int res;

	res = sas_notify_lldd_dev_found(dev);
	if (res)
		return res;

	res = sas_get_itnl_timeout(dev);
	if (!res) {
		sas_notify_lldd_dev_gone(dev);
		sas_notify_lldd_dev_found(dev);
	}

	dev->end_dev.LU_kset.kobj.parent = &dev->dev_obj;
	dev->end_dev.LU_kset.ktype  = &lu_dev_ktype;

	res = sas_do_lu_discovery(dev);
	if (res)
		goto out_err;

	kobject_set_name(&dev->end_dev.LU_kset.kobj, "%s", "LUNS");

	sas_kobj_set(dev);
	return 0;

out_err:
	sas_notify_lldd_dev_gone(dev);
	return res;
}

/* ---------- Device registration and unregistration ---------- */

static inline void sas_unregister_common_dev(struct domain_device *dev)
{
	sas_notify_lldd_dev_gone(dev);
	if (!dev->parent)
		dev->port->port_dev = NULL;
	else
		list_del_init(&dev->siblings);
	list_del_init(&dev->dev_list_node);
	kobject_unregister(&dev->dev_obj);
}

static int sas_register_end_dev(struct domain_device *dev)
{
	struct LU *lu;

	kobject_register(&dev->dev_obj);
	kset_register(&dev->end_dev.LU_kset);

	list_for_each_entry(lu, &dev->end_dev.LU_list, list) {
		kobject_register(&lu->lu_obj);
		sas_register_with_scsi(lu);
	}

	return 0;
}

static void sas_unregister_end_dev(struct domain_device *dev)
{
	struct LU *lu, *n;

	list_for_each_entry_safe(lu, n, &dev->end_dev.LU_list, list) {
		sas_unregister_with_scsi(lu);
		list_del_init(&lu->list);
		kobject_unregister(&lu->lu_obj);
	}
	kset_unregister(&dev->end_dev.LU_kset);
	sas_unregister_common_dev(dev);
}

static int sas_register_sata(struct domain_device *dev)
{
	/* XXX Hint: Register the SATL supported LU with SCSI.
	if (dev->sata_dev->lu)
		sas_register_with_scsi(dev->sata_dev->lu)
	*/
	kobject_register(&dev->dev_obj);
	return 0;
}

static void sas_unregister_sata(struct domain_device *dev)
{
	/* XXX Hint: See hint above.
	if (dev->sata_dev->lu)
		sas_unregister_with_scsi(dev->sata_dev->lu);
	*/
	sas_unregister_common_dev(dev);
}

/**
 * sas_register_ex_dev -- Register this expander
 * @ex: pointer to domain device
 *
 * It is imperative that this is done breadth-first.  Other parts of
 * the code rely on that.
 */
static int sas_register_ex_dev(struct domain_device *dev)
{
	kobject_register(&dev->dev_obj);
	sysfs_create_bin_file(&dev->dev_obj, &dev->ex_dev.smp_bin_attr);
	return 0;
}

static void sas_unregister_ex_dev(struct domain_device *dev)
{
	BUG_ON(!list_empty(&dev->ex_dev.children));
	sas_unregister_common_dev(dev);
}

/**
 * sas_register_domain_devs -- register the domain devices with sysfs
 * @port: the port to the domain
 *
 * This function registers the domain devices with sysfs and with
 * the SCSI subsystem.
 */
static int sas_register_domain_devs(struct sas_port *port)
{
	struct domain_device *dev;

	list_for_each_entry(dev, &port->dev_list, dev_list_node) {
		if (dev->dev_obj.dentry)
			continue;
		switch (dev->dev_type) {
		case SAS_END_DEV:
			sas_register_end_dev(dev);
			break;
		case EDGE_DEV:
		case FANOUT_DEV:
			sas_register_ex_dev(dev);
			break;
		case SATA_DEV:
		case SATA_PM:
			sas_register_sata(dev);
			break;
		default:
			SAS_DPRINTK("%s: unknown device type %d\n",
				    __FUNCTION__, dev->dev_type);
			break;
		}
	}

	return 0;
}

void sas_unregister_dev(struct domain_device *dev)
{
	switch (dev->dev_type) {
	case SAS_END_DEV:
		sas_unregister_end_dev(dev);
		break;
	case EDGE_DEV:
	case FANOUT_DEV:
		sas_unregister_ex_dev(dev);
		break;
	case SATA_DEV:
	case SATA_PM:
		sas_unregister_sata(dev);
		break;
	default:
		SAS_DPRINTK("%s: unknown device type %d\n",
			    __FUNCTION__, dev->dev_type);
		BUG_ON(dev);
		break;
	}
}

static void sas_unregister_domain_devices(struct sas_port *port)
{
	struct domain_device *dev, *n;

	list_for_each_entry_reverse_safe(dev,n,&port->dev_list,dev_list_node)
		sas_unregister_dev(dev);
}

/* ---------- Discovery and Revalidation ---------- */

/**
 * sas_discover_domain -- discover the domain
 * @port: port to the domain of interest
 *
 * NOTE: this process _must_ quit (return) as soon as any connection
 * errors are encountered.  Connection recovery is done elsewhere.
 * Discover process only interrogates devices in order to discover the
 * domain.
 */
static int sas_discover_domain(struct sas_port *port)
{
	int error = 0;

	if (port->port_dev)
		return 0;
	else {
		error = sas_get_port_device(port);
		if (error)
			return error;
	}

	SAS_DPRINTK("DOING DISCOVERY on port %d, pid:%d\n", port->id,
		    current->pid);

	switch (port->port_dev->dev_type) {
	case SAS_END_DEV:
		error = sas_discover_end_dev(port->port_dev);
		break;
	case EDGE_DEV:
	case FANOUT_DEV:
		error = sas_discover_root_expander(port->port_dev);
		break;
	case SATA_DEV:
	case SATA_PM:
		error = sas_discover_sata(port->port_dev);
		break;
	default:
		SAS_DPRINTK("unhandled device %d\n", port->port_dev->dev_type);
		break;
	}

	if (error) {
		kfree(port->port_dev); /* not kobject_register-ed yet */
		port->port_dev = NULL;
	} else
		sas_register_domain_devs(port);

	SAS_DPRINTK("DONE DISCOVERY on port %d, pid:%d, result:%d\n", port->id,
		    current->pid, error);

	return error;
}

static int sas_revalidate_domain(struct sas_port *port)
{
	int res = 0;

	SAS_DPRINTK("REVALIDATING DOMAIN on port %d, pid:%d\n", port->id,
		    current->pid);
	if (port->port_dev) {
		res = sas_ex_revalidate_domain(port->port_dev);
		if (!res)
			sas_register_domain_devs(port);
	}
	SAS_DPRINTK("done REVALIDATING DOMAIN on port %d, pid:%d, res 0x%x\n",
		    port->id, current->pid, res);
	return res;
}

/* ---------- Threads and events ---------- */

static DECLARE_COMPLETION(disc_comp_start);

static int sas_discover_thread(void *_sas_port)
{
	struct sas_port *port = _sas_port;
	struct sas_ha_struct *sas_ha = port->ha;
	struct sas_discovery *disc = &port->disc;

	daemonize("sas_disc_h%dp%d", sas_ha->core.shost->host_no, port->id);

	spin_lock(&disc->disc_event_lock);
	disc->disc_thread = current;
	complete(&disc_comp_start);
	while (!disc->disc_thread_quit && !list_empty(&disc->disc_event_list)){
		struct list_head *head = disc->disc_event_list.next;
		enum discover_event disc_ev = container_of(head,
							   struct sas_event,
							   el)->event;
		list_del_init(head);
		spin_unlock(&disc->disc_event_lock);

		switch (disc_ev) {
		case DISCE_DISCOVER_DOMAIN:
			sas_discover_domain(port);
			break;
		case DISCE_REVALIDATE_DOMAIN:
			sas_revalidate_domain(port);
			break;
		case DISCE_PORT_GONE:
			sas_unregister_domain_devices(port);
			complete(&port->port_gone_completion);
			break;
		}
		spin_lock(&disc->disc_event_lock);
	}
	INIT_LIST_HEAD(&disc->disc_event_list);
	disc->disc_thread = NULL;
	spin_unlock(&disc->disc_event_lock);
	up(&disc->disc_sema);

	return 0;
}

static int sas_create_discover_thread(struct sas_port *port)
{
	int i;

	init_completion(&disc_comp_start);
	i = kernel_thread(sas_discover_thread, port, 0);
	if (i >= 0)
		wait_for_completion(&disc_comp_start);

	return i < 0 ? i : 0;
}

int sas_discover_event(struct sas_port *port, enum discover_event ev)
{
	int res;
	struct sas_discovery *disc = &port->disc;

	spin_lock(&disc->disc_event_lock);
	list_move_tail(&disc->disc_events[ev].el,
		       &disc->disc_event_list);
	if (disc->disc_thread) {
		spin_unlock(&disc->disc_event_lock);
		return 0;
	}
	down_interruptible(&disc->disc_sema);
	disc->disc_thread_quit = 0;
	spin_unlock(&disc->disc_event_lock);

	/* The event thread (caller) is single threaded so this is safe. */
	res = sas_create_discover_thread(port);
	if (res) {
		SAS_DPRINTK("sas port%d: couldn't create discovery thread!\n",
			    port->id);
		up(&disc->disc_sema);
	}
	return res;
}

void sas_kill_disc_thread(struct sas_port *port)
{
	struct sas_discovery *disc = &port->disc;

	spin_lock(&disc->disc_event_lock);
	disc->disc_thread_quit = 1;
	if (disc->disc_thread) {
		wake_up_process(disc->disc_thread);
		spin_unlock(&disc->disc_event_lock);
		down_interruptible(&disc->disc_sema);
		return;
	}
	spin_unlock(&disc->disc_event_lock);
}

/**
 * sas_init_disc -- initialize the discovery struct in the port
 * @port: pointer to struct port
 *
 * Called when the ports are being initialized.
 */
void sas_init_disc(struct sas_discovery *disc, struct sas_port *port)
{
	int i;

	if (!end_dev_attrs[0]) {
		for (i = 0; i < ARRAY_SIZE(dev_attrs)-1; i++)
			end_dev_attrs[i] = &dev_attrs[i].attr;
		end_dev_attrs[i] = NULL;
		sas_init_ex_attr();
		for (i = 0; i < ARRAY_SIZE(sata_attrs)-1; i++)
			sata_dev_attrs[i] = &sata_attrs[i].attr;
		sata_dev_attrs[i] = NULL;
		for (i = 0; i < ARRAY_SIZE(lu_attrs)-1; i++)
			lu_dev_attrs[i] = &lu_attrs[i].attr;
		lu_dev_attrs[i] = NULL;
	}

	spin_lock_init(&disc->disc_event_lock);
	INIT_LIST_HEAD(&disc->disc_event_list);
	init_MUTEX(&disc->disc_sema);
	disc->disc_thread = NULL;
	disc->disc_thread_quit = 0;

	for (i = 0; i < DISC_NUM_EVENTS; i++) {
		struct sas_event *ev = &disc->disc_events[i];
		ev->event = i;
		INIT_LIST_HEAD(&ev->el);
	}
}

void sas_unregister_devices(struct sas_ha_struct *sas_ha)
{
	int i;

	for (i = 0; i < sas_ha->num_phys; i++)
		sas_unregister_domain_devices(sas_ha->sas_port[i]);
}

/*
 * Copyright (c) 2004, 2005 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2004, 2005 Infinicon Corporation.  All rights reserved.
 * Copyright (c) 2004, 2005 Intel Corporation.  All rights reserved.
 * Copyright (c) 2004, 2005 Topspin Corporation.  All rights reserved.
 * Copyright (c) 2004, 2005 Voltaire Corporation.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id: ping.c 3861 2005-10-25 15:40:27Z sean.hefty $
 */

#include <linux/dma-mapping.h>
#include <linux/utsname.h>
#include <asm/bug.h>

#include <rdma/ib_mad.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("kernel IB ping agent");
MODULE_AUTHOR("Shahar Frank");

/* this may ultimately be in ib_mad.h */
#define IB_MGMT_CLASS_OPENIB_PING       (IB_MGMT_CLASS_VENDOR_RANGE2_START+2)

#define SPFX "ib_ping: "

struct ib_ping_port_private {
	struct list_head port_list;
	int port_num;
	struct ib_mad_agent *pingd_agent;     /* OpenIB Ping class */
};

static spinlock_t ib_ping_port_list_lock;
static LIST_HEAD(ib_ping_port_list);

/*
 * Caller must hold ib_ping_port_list_lock
 */
static inline struct ib_ping_port_private *
__ib_get_ping_port(struct ib_device *device, int port_num,
		   struct ib_mad_agent *mad_agent)
{
	struct ib_ping_port_private *entry;

	BUG_ON(!(!!device ^ !!mad_agent));  /* Exactly one MUST be (!NULL) */

	if (device) {
		list_for_each_entry(entry, &ib_ping_port_list, port_list) {
			if (entry->pingd_agent->device == device &&
			    entry->port_num == port_num)
				return entry;
		}
	} else {
		list_for_each_entry(entry, &ib_ping_port_list, port_list) {
			if (entry->pingd_agent == mad_agent)
				return entry;
		}
	}
	return NULL;
}

static inline struct ib_ping_port_private *
ib_get_ping_port(struct ib_device *device, int port_num,
		 struct ib_mad_agent *mad_agent)
{
	struct ib_ping_port_private *entry;
	unsigned long flags;

	spin_lock_irqsave(&ib_ping_port_list_lock, flags);
	entry = __ib_get_ping_port(device, port_num, mad_agent);
	spin_unlock_irqrestore(&ib_ping_port_list_lock, flags);

	return entry;
}

static void pingd_recv_handler(struct ib_mad_agent *mad_agent,
			       struct ib_mad_recv_wc *mad_recv_wc)
{
	struct ib_ping_port_private *port_priv;
	struct ib_ah *ah;
	struct ib_mad_send_buf *msg;
	struct ib_vendor_mad *vend;
	int ret;

	/* Find matching MAD agent */
	port_priv = ib_get_ping_port(NULL, 0, mad_agent);
	if (!port_priv) {
		printk(KERN_ERR SPFX "pingd_recv_handler: no matching MAD "
		       "agent %p\n", mad_agent);
		goto error1;
	}

	ah = ib_create_ah_from_wc(mad_agent->qp->pd, mad_recv_wc->wc,
				  mad_recv_wc->recv_buf.grh,
				  mad_agent->port_num);
	if (IS_ERR(ah)) {
		printk(KERN_ERR SPFX "pingd_recv_handler: failed to create AH from recv WC\n");
		goto error1;
	}

	msg = ib_create_send_mad(mad_agent, mad_recv_wc->wc->src_qp,
				 mad_recv_wc->wc->pkey_index, 0,
				 IB_MGMT_VENDOR_HDR,
				 mad_recv_wc->mad_len - IB_MGMT_VENDOR_HDR,
				 GFP_KERNEL);
	if (IS_ERR(msg)) {
		printk(KERN_ERR SPFX "pingd_recv_handler: failed to create response MAD\n");
		goto error2;
	}

	msg->ah = ah;
	vend = msg->mad;
	memcpy(vend, mad_recv_wc->recv_buf.mad, sizeof(*vend));
	vend->mad_hdr.method |= IB_MGMT_METHOD_RESP;
	vend->mad_hdr.status = 0;
	if (!system_utsname.domainname[0])
		strncpy(vend->data, system_utsname.nodename, sizeof vend->data);
	else
		snprintf(vend->data, sizeof vend->data, "%s.%s",
			 system_utsname.nodename, system_utsname.domainname);

	/* Send response */
	ret = ib_post_send_mad(msg, NULL);
	if (!ret) {
		ib_free_recv_mad(mad_recv_wc);
		return;
	}

	ib_free_send_mad(msg);
	printk(KERN_ERR SPFX "pingd_recv_handler: reply failed\n");

error2:
	ib_destroy_ah(ah);
error1:
	ib_free_recv_mad(mad_recv_wc);
}

static void pingd_send_handler(struct ib_mad_agent *mad_agent,
			       struct ib_mad_send_wc *mad_send_wc)
{
	struct ib_mad_send_buf *msg = mad_send_wc->send_buf;

	ib_destroy_ah(msg->ah);
	if (mad_send_wc->status != IB_WC_SUCCESS)
		printk(KERN_ERR SPFX "pingd_send_handler: Error sending MAD: %d\n", mad_send_wc->status);
	ib_free_send_mad(msg);
}

static int ib_ping_port_open(struct ib_device *device, int port_num)
{
	int ret;
	struct ib_ping_port_private *port_priv;
	struct ib_mad_reg_req pingd_reg_req;
	unsigned long flags;

	/* Create new device info */
	port_priv = kmalloc(sizeof *port_priv, GFP_KERNEL);
	if (!port_priv) {
		printk(KERN_ERR SPFX "No memory for ib_ping_port_private\n");
		ret = -ENOMEM;
		goto error1;
	}

	memset(port_priv, 0, sizeof *port_priv);
	port_priv->port_num = port_num;
	pingd_reg_req.mgmt_class = IB_MGMT_CLASS_OPENIB_PING;
	pingd_reg_req.mgmt_class_version = 1;
	pingd_reg_req.oui[0] = (IB_OPENIB_OUI >> 16) & 0xff;
	pingd_reg_req.oui[1] = (IB_OPENIB_OUI >> 8) & 0xff;
	pingd_reg_req.oui[2] = IB_OPENIB_OUI & 0xff;
	set_bit(IB_MGMT_METHOD_GET, pingd_reg_req.method_mask);

	/* Obtain server MAD agent for OpenIB Ping class (GSI QP) */
	port_priv->pingd_agent = ib_register_mad_agent(device, port_num,
						       IB_QPT_GSI,
						      &pingd_reg_req, 0,
						      &pingd_send_handler,
						      &pingd_recv_handler,
						       NULL);
	if (IS_ERR(port_priv->pingd_agent)) {
		ret = PTR_ERR(port_priv->pingd_agent);
		goto error2;
	}

	spin_lock_irqsave(&ib_ping_port_list_lock, flags);
	list_add_tail(&port_priv->port_list, &ib_ping_port_list);
	spin_unlock_irqrestore(&ib_ping_port_list_lock, flags);

	return 0;

error2:
	kfree(port_priv);
error1:
	return ret;
}

static int ib_ping_port_close(struct ib_device *device, int port_num)
{
	struct ib_ping_port_private *port_priv;
	unsigned long flags;

	spin_lock_irqsave(&ib_ping_port_list_lock, flags);
	port_priv = __ib_get_ping_port(device, port_num, NULL);
	if (port_priv == NULL) {
		spin_unlock_irqrestore(&ib_ping_port_list_lock, flags);
		printk(KERN_ERR SPFX "Port %d not found\n", port_num);
		return -ENODEV;
	}
	list_del(&port_priv->port_list);
	spin_unlock_irqrestore(&ib_ping_port_list_lock, flags);

	ib_unregister_mad_agent(port_priv->pingd_agent);
	kfree(port_priv);

	return 0;
}

static void ib_ping_init_device(struct ib_device *device)
{
	int num_ports, cur_port, i;

	if (device->node_type == IB_NODE_SWITCH) {
		num_ports = 1;
		cur_port = 0;
	} else {
		num_ports = device->phys_port_cnt;
		cur_port = 1;
	}

	for (i = 0; i < num_ports; i++, cur_port++) {
		if (ib_ping_port_open(device, cur_port))
			printk(KERN_ERR SPFX "Couldn't open %s port %d\n",
			       device->name, cur_port);
			goto error_device_open;
	}
	return;

error_device_open:
	while (i > 0) {
		cur_port--;
		if (ib_ping_port_close(device, cur_port))
			printk(KERN_ERR SPFX "Couldn't close %s port %d "
			       "for ping agent\n",
			       device->name, cur_port);
		i--;
	}
}

static void ib_ping_remove_device(struct ib_device *device)
{
	int i, num_ports, cur_port;

	if (device->node_type == IB_NODE_SWITCH) {
		num_ports = 1;
		cur_port = 0;
	} else {
		num_ports = device->phys_port_cnt;
		cur_port = 1;
	}
	for (i = 0; i < num_ports; i++, cur_port++) {
		if (ib_ping_port_close(device, cur_port))
			printk(KERN_ERR SPFX "Couldn't close %s port %d "
			       "for ping agent\n",
			       device->name, cur_port);
	}
}

static struct ib_client ping_client = {
        .name   = "ping",
        .add = ib_ping_init_device,
        .remove = ib_ping_remove_device
};

static int __init ib_ping_init_module(void)
{
	spin_lock_init(&ib_ping_port_list_lock);
	INIT_LIST_HEAD(&ib_ping_port_list);

	if (ib_register_client(&ping_client)) {
		printk(KERN_ERR SPFX "Couldn't register ib_ping client\n");
		return -EINVAL;
	}

	return 0;
}

static void __exit ib_ping_cleanup_module(void)
{
	ib_unregister_client(&ping_client);
}

module_init(ib_ping_init_module)
module_exit(ib_ping_cleanup_module)


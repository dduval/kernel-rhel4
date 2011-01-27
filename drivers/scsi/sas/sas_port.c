/*
 * Serial Attached SCSI (SAS) Port class
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
 * $Id: //depot/sas-class/sas_port.c#44 $
 */

#include "sas_internal.h"
#include <scsi/sas/sas_discover.h>

/* called only when num_phys increments, afterwards */
static void sas_create_port_sysfs_links(struct sas_phy *phy)
{
	struct sas_port *port = phy->port;

	if (port->num_phys == 1) {
		kobject_register(&port->port_kobj);
		kset_register(&port->phy_kset);
		kset_register(&port->dev_kset);
	}
	/* add port->phy link */
	sysfs_create_link(&port->phy_kset.kobj, &phy->phy_kobj,
			  kobject_name(&phy->phy_kobj));
	/* add phy->port link */
	sysfs_create_link(&phy->phy_kobj, &port->port_kobj, "port");
}

/* called only when num_phys decrements, just before it does */
static void sas_remove_port_sysfs_links(struct sas_phy *phy)
{
	struct sas_port *port = phy->port;

	/* remove phy->port link */
	sysfs_remove_link(&phy->phy_kobj, "port");
	/* remove port to phy link */
	sysfs_remove_link(&port->phy_kset.kobj, kobject_name(&phy->phy_kobj));

	if (port->num_phys == 1) {
		kset_unregister(&port->dev_kset);
		kset_unregister(&port->phy_kset);
		kobject_unregister(&port->port_kobj);
	}
}

/**
 * sas_form_port -- add this phy to a port
 * @phy: the phy of interest
 *
 * This function adds this phy to an existing port, thus creating a wide
 * port, or it creates a port and adds the phy to the port.
 */
static void sas_form_port(struct sas_phy *phy)
{
	int i;
	struct sas_ha_struct *sas_ha = phy->ha;
	struct sas_port *port = phy->port;

	if (port) {
		if (memcmp(port->attached_sas_addr, phy->attached_sas_addr,
			   SAS_ADDR_SIZE) == 0)
			sas_deform_port(phy);
		else {
			SAS_DPRINTK("%s: phy%d belongs to port%d already(%d)!\n",
				    __FUNCTION__, phy->id, phy->port->id,
				    phy->port->num_phys);
			return;
		}
	}

	/* find a port */
	spin_lock(&sas_ha->phy_port_lock);
	for (i = 0; i < sas_ha->num_phys; i++) {
		port = sas_ha->sas_port[i];
		spin_lock(&port->phy_list_lock);
		if (*(u64 *) port->sas_addr &&
		    memcmp(port->attached_sas_addr,
			   phy->attached_sas_addr, SAS_ADDR_SIZE) == 0 &&
		    port->num_phys > 0) {
			/* wide port */
			SAS_DPRINTK("phy%d matched wide port%d\n", phy->id,
				    port->id);
			break;
		} else if (*(u64 *) port->sas_addr == 0 && port->num_phys==0) {
			memcpy(port->sas_addr, phy->sas_addr, SAS_ADDR_SIZE);
			break;
		}
		spin_unlock(&port->phy_list_lock);
	}

	if (i >= sas_ha->num_phys) {
		printk(KERN_NOTICE "%s: couldn't find a free port, bug?\n",
		       __FUNCTION__);
		spin_unlock(&sas_ha->phy_port_lock);
		return;
	}

	/* add the phy to the port */
	list_add_tail(&phy->port_phy_el, &port->phy_list);
	phy->port = port;
	port->num_phys++;
	port->phy_mask |= (1U << phy->id);

	SAS_DPRINTK("phy%d added to port%d, phy_mask:0x%x\n", phy->id,
		    port->id, port->phy_mask);

	if (*(u64 *)port->attached_sas_addr == 0) {
		port->class = phy->class;
		memcpy(port->attached_sas_addr, phy->attached_sas_addr,
		       SAS_ADDR_SIZE);
		port->iproto = phy->iproto;
		port->tproto = phy->tproto;
		port->oob_mode = phy->oob_mode;
		port->linkrate = phy->linkrate;
	} else
		port->linkrate = max(port->linkrate, phy->linkrate);
	spin_unlock(&port->phy_list_lock);
	spin_unlock(&sas_ha->phy_port_lock);

	if (port->port_dev)
		port->port_dev->pathways = port->num_phys;

	sas_create_port_sysfs_links(phy);
	/* Tell the LLDD about this port formation. */
	if (sas_ha->lldd_port_formed)
		sas_ha->lldd_port_formed(phy);

	sas_discover_event(phy->port, DISCE_DISCOVER_DOMAIN);
}

/**
 * sas_deform_port -- remove this phy from the port it belongs to
 * @phy: the phy of interest
 *
 * This is called when the physical link to the other phy has been
 * lost (on this phy), in Event thread context. We cannot delay here.
 */
void sas_deform_port(struct sas_phy *phy)
{
	struct sas_ha_struct *sas_ha = phy->ha;
	struct sas_port *port = phy->port;

	if (!port)
		return;		  /* done by a phy event */

	if (port->port_dev)
		port->port_dev->pathways--;

	if (port->num_phys == 1) {
		init_completion(&port->port_gone_completion);
		sas_discover_event(port, DISCE_PORT_GONE);
		wait_for_completion(&port->port_gone_completion);
	}

	if (sas_ha->lldd_port_deformed)
		sas_ha->lldd_port_deformed(phy);

	sas_remove_port_sysfs_links(phy);

	spin_lock(&sas_ha->phy_port_lock);
	spin_lock(&port->phy_list_lock);

	list_del_init(&phy->port_phy_el);
	phy->port = NULL;
	port->num_phys--;
	port->phy_mask &= ~(1U << phy->id);

	if (port->num_phys == 0) {
		INIT_LIST_HEAD(&port->phy_list);
		memset(port->sas_addr, 0, SAS_ADDR_SIZE);
		memset(port->attached_sas_addr, 0, SAS_ADDR_SIZE);
		port->class = 0;
		port->iproto = 0;
		port->tproto = 0;
		port->oob_mode = 0;
		port->phy_mask = 0;
	}
	spin_unlock(&port->phy_list_lock);
	spin_unlock(&sas_ha->phy_port_lock);

	return;
}

/* ---------- SAS port events ---------- */

void sas_porte_bytes_dmaed(struct sas_phy *phy)
{
	sas_form_port(phy);
}

void sas_porte_broadcast_rcvd(struct sas_phy *phy)
{
	unsigned long flags;
	u32 prim;

	spin_lock_irqsave(&phy->sas_prim_lock, flags);
	prim = phy->sas_prim;
	spin_unlock_irqrestore(&phy->sas_prim_lock, flags);

	SAS_DPRINTK("broadcast received: %d\n", prim);
	sas_discover_event(phy->port, DISCE_REVALIDATE_DOMAIN);
}

void sas_porte_link_reset_err(struct sas_phy *phy)
{
	sas_deform_port(phy);
}

void sas_porte_timer_event(struct sas_phy *phy)
{
	sas_deform_port(phy);
}

void sas_porte_hard_reset(struct sas_phy *phy)
{
	sas_deform_port(phy);
}

/* ---------- SAS port attributes ---------- */

static ssize_t sas_port_id_show(struct sas_port *port, char *buf)
{
	return sprintf(buf, "%d\n", port->id);
}

static ssize_t sas_port_class_show(struct sas_port *port, char *buf)
{
	return sas_show_class(port->class, buf);
}

static ssize_t sas_port_sas_addr_show(struct sas_port *port, char *buf)
{
	return sprintf(buf, "%llx\n", SAS_ADDR(port->sas_addr));
}

static ssize_t sas_port_attached_sas_addr_show(struct sas_port *port,char *buf)
{
	return sprintf(buf, "%llx\n", SAS_ADDR(port->attached_sas_addr));
}

static ssize_t sas_port_iproto_show(struct sas_port *port, char *buf)
{
	return sas_show_proto(port->iproto, buf);
}

static ssize_t sas_port_tproto_show(struct sas_port *port, char *buf)
{
	return sas_show_proto(port->tproto, buf);
}

static ssize_t sas_port_oob_mode_show(struct sas_port *port, char *buf)
{
	return sas_show_oob_mode(port->oob_mode, buf);
}

struct port_attribute {
	struct attribute attr;
	ssize_t (*show)(struct sas_port *port, char *);
	ssize_t (*store)(struct sas_port *port, const char *, size_t);
};

static struct port_attribute port_attrs[] = {
	__ATTR(id, 0444, sas_port_id_show, NULL),
	__ATTR(class, 0444, sas_port_class_show, NULL),
	__ATTR(port_identifier, 0444, sas_port_sas_addr_show, NULL),
	__ATTR(attached_port_identifier, 0444, sas_port_attached_sas_addr_show, NULL),
	__ATTR(iproto, 0444, sas_port_iproto_show, NULL),
	__ATTR(tproto, 0444, sas_port_tproto_show, NULL),
	__ATTR(oob_mode, 0444, sas_port_oob_mode_show, NULL),
	__ATTR_NULL,
};

static struct attribute *def_attrs[ARRAY_SIZE(port_attrs)];

#define to_sas_port(_obj) container_of(_obj, struct sas_port, port_kobj)
#define to_port_attr(_attr) container_of(_attr, struct port_attribute, attr)

static ssize_t port_show_attr(struct kobject *kobj, struct attribute *attr,
			      char *page)
{
	ssize_t ret = 0;
	struct sas_port *port = to_sas_port(kobj);
	struct port_attribute *port_attr = to_port_attr(attr);

	if (port_attr->show)
		ret = port_attr->show(port, page);
	return ret;
}

static struct sysfs_ops port_sysfs_ops = {
	.show = port_show_attr,
};

static struct kobj_type port_type = {
	.sysfs_ops = &port_sysfs_ops,
	.default_attrs = def_attrs,
};

/* ---------- SAS port registration ---------- */

static void sas_init_port(struct sas_port *port,
			  struct sas_ha_struct *sas_ha, int i,
			  struct kset *parent_kset)
{
	port->id = i;
	INIT_LIST_HEAD(&port->dev_list);
	spin_lock_init(&port->phy_list_lock);
	INIT_LIST_HEAD(&port->phy_list);
	port->num_phys = 0;
	port->phy_mask = 0;
	port->ha = sas_ha;

	memset(&port->port_kobj, 0, sizeof(port->port_kobj));
	memset(&port->phy_kset, 0, sizeof(port->phy_kset));
	memset(&port->dev_kset, 0, sizeof(port->dev_kset));

	kobject_set_name(&port->port_kobj, "%d", port->id);
	port->port_kobj.kset = parent_kset;
	port->port_kobj.ktype= parent_kset->ktype;

	kobject_set_name(&port->phy_kset.kobj, "%s", "phys");
	port->phy_kset.kobj.parent = &port->port_kobj;
	port->phy_kset.ktype = NULL;

	kobject_set_name(&port->dev_kset.kobj, "%s", "domain");
	port->dev_kset.kobj.parent = &port->port_kobj;
	port->dev_kset.ktype = NULL;

	port->id_map.max_ids = 128;
	port->id_map.id_bitmap_size =
		BITS_TO_LONGS(port->id_map.max_ids)*sizeof(long);
	port->id_map.id_bitmap = kmalloc(port->id_map.id_bitmap_size,
					 GFP_KERNEL);
	memset(port->id_map.id_bitmap, 0, port->id_map.id_bitmap_size);
	spin_lock_init(&port->id_map.id_bitmap_lock);
}

int sas_register_ports(struct sas_ha_struct *sas_ha)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(def_attrs)-1; i++)
		def_attrs[i] = &port_attrs[i].attr;
	def_attrs[i] = NULL;

	/* make sas/ha/ports/ appear */
	kobject_set_name(&sas_ha->port_kset.kobj, "%s", "ports");
	sas_ha->port_kset.kobj.kset = &sas_ha->ha_kset; /* parent */
	/* no type inheritance */
	sas_ha->port_kset.kobj.ktype = NULL;
	sas_ha->port_kset.ktype = &port_type; /* children are of this type */

	/* initialize the ports and discovery */
	for (i = 0; i < sas_ha->num_phys; i++) {
		struct sas_port *port = sas_ha->sas_port[i];

		sas_init_port(port, sas_ha, i, &sas_ha->port_kset);
		sas_init_disc(&port->disc, port);
	}

	return kset_register(&sas_ha->port_kset);
}

void sas_unregister_ports(struct sas_ha_struct *sas_ha)
{
	int i;

	for (i = 0; i < sas_ha->num_phys; i++)
		if (sas_ha->sas_phy[i]->port)
			sas_deform_port(sas_ha->sas_phy[i]);

	for (i = 0; i < sas_ha->num_phys; i++) {
		kfree(sas_ha->sas_port[i]->id_map.id_bitmap);
		sas_ha->sas_port[i]->id_map.id_bitmap = NULL;
	}

	kset_unregister(&sas_ha->port_kset);
}

int sas_reserve_free_id(struct sas_port *port)
{
	int id;

	spin_lock(&port->id_map.id_bitmap_lock);
	id = find_first_zero_bit(port->id_map.id_bitmap, port->id_map.max_ids);
	if (id >= port->id_map.max_ids) {
		id = -ENOMEM;
		spin_unlock(&port->id_map.id_bitmap_lock);
		goto out;
	}
	set_bit(id, port->id_map.id_bitmap);
	spin_unlock(&port->id_map.id_bitmap_lock);
out:
	return id;
}

void sas_reserve_scsi_id(struct sas_port *port, int id)
{
	if (0 > id || id >= port->id_map.max_ids)
		return;
	spin_lock(&port->id_map.id_bitmap_lock);
	set_bit(id, port->id_map.id_bitmap);
	spin_unlock(&port->id_map.id_bitmap_lock);
}

void sas_release_scsi_id(struct sas_port *port, int id)
{
	if (0 > id || id >= port->id_map.max_ids)
		return;
	spin_lock(&port->id_map.id_bitmap_lock);
	clear_bit(id, port->id_map.id_bitmap);
	spin_unlock(&port->id_map.id_bitmap_lock);
}

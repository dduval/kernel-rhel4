/*
 * Serial Attached SCSI (SAS) Phy class
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
 * $Id: //depot/sas-class/sas_phy.c#38 $
 */

#include "sas_internal.h"

/* ---------- Phy events ---------- */

void sas_phye_loss_of_signal(struct sas_phy *phy)
{
	phy->error = 0;
	sas_deform_port(phy);
}

void sas_phye_oob_done(struct sas_phy *phy)
{
	phy->error = 0;
}

void sas_phye_oob_error(struct sas_phy *phy)
{
	struct sas_ha_struct *sas_ha = phy->ha;
	struct sas_port *port = phy->port;

	sas_deform_port(phy);

	if (!port && phy->enabled && sas_ha->lldd_control_phy) {
		phy->error++;
		switch (phy->error) {
		case 1:
		case 2:
			sas_ha->lldd_control_phy(phy, PHY_FUNC_HARD_RESET);
			break;
		case 3:
		default:
			phy->error = 0;
			phy->enabled = 0;
			sas_ha->lldd_control_phy(phy, PHY_FUNC_DISABLE);
			break;
		}
	}
}

void sas_phye_spinup_hold(struct sas_phy *phy)
{
	struct sas_ha_struct *sas_ha = phy->ha;

	phy->error = 0;
	sas_ha->lldd_control_phy(phy, PHY_FUNC_RELEASE_SPINUP_HOLD);
}

/* ---------- Phy attributes ---------- */

static ssize_t sas_phy_id_show(struct sas_phy *phy, char *buf)
{
	return sprintf(buf, "%d\n", phy->id);
}

static ssize_t sas_phy_enabled_show(struct sas_phy *phy, char *buf)
{
	return sprintf(buf, "%d\n", phy->enabled);
}

static ssize_t sas_phy_enabled_store(struct sas_phy *phy, const char *buf,
				     size_t size)
{
	if (size > 0) {
		if (buf[0] == '1')
			phy->ha->lldd_control_phy(phy, PHY_FUNC_LINK_RESET);
	}
	return size;
}

static ssize_t sas_phy_class_show(struct sas_phy *phy, char *buf)
{
	if (!phy->enabled)
		return 0;
	return sas_show_class(phy->class, buf);
}

static ssize_t sas_phy_iproto_show(struct sas_phy *phy, char *page)
{
	if (!phy->enabled)
		return 0;
	return sas_show_proto(phy->iproto, page);
}

static ssize_t sas_phy_tproto_show(struct sas_phy *phy, char *page)
{
	if (!phy->enabled)
		return 0;
	return sas_show_proto(phy->tproto, page);
}

static ssize_t sas_phy_type_show(struct sas_phy *phy, char *buf)
{
	static const char *phy_type_str[] = {
		[PHY_TYPE_PHYSICAL] = "physical",
		[PHY_TYPE_VIRTUAL] = "virtual",
	};
	if (!phy->enabled)
		return 0;
	return sprintf(buf, "%s\n", phy_type_str[phy->type]);
}

static ssize_t sas_phy_role_show(struct sas_phy *phy, char *page)
{
	static const char *phy_role_str[] = {
		[PHY_ROLE_NONE] = "none",
		[PHY_ROLE_TARGET] = "target",
		[PHY_ROLE_INITIATOR] = "initiator",
	};
	int  v;
	char *buf = page;

	if (!phy->enabled)
		return 0;

	if (phy->role == PHY_ROLE_NONE)
		return sprintf(buf, "%s\n", phy_role_str[PHY_ROLE_NONE]);

	for (v = 1; v <= PHY_ROLE_INITIATOR; v <<= 1) {
		if (v & phy->role) {
			buf += sprintf(buf, "%s", phy_role_str[v]);
			if (phy->role & ~((v<<1)-1))
				buf += sprintf(buf, "|");
			else
				buf += sprintf(buf, "\n");
		}
	}
	return buf-page;
}

static ssize_t sas_phy_linkrate_show(struct sas_phy *phy, char *buf)
{
	if (!phy->enabled)
		return 0;
	return sas_show_linkrate(phy->linkrate, buf);
}

static ssize_t sas_phy_addr_show(struct sas_phy *phy, char *buf)
{
	if (!phy->enabled)
		return 0;
	return sprintf(buf, "%llx\n", SAS_ADDR(phy->sas_addr));
}

static ssize_t sas_phy_oob_mode_show(struct sas_phy *phy, char *buf)
{
	if (!phy->enabled)
		return 0;
	return sas_show_oob_mode(phy->oob_mode, buf);
}

struct phy_attribute {
	struct attribute attr;
	ssize_t (*show)(struct sas_phy *phy, char *);
	ssize_t (*store)(struct sas_phy *phy, const char *, size_t);
};

static struct phy_attribute phy_attrs[] = {
	/* port is a symlink */
	__ATTR(id, 0444, sas_phy_id_show, NULL),
	__ATTR(enabled, 0644, sas_phy_enabled_show, sas_phy_enabled_store),
	__ATTR(class, 0444, sas_phy_class_show, NULL),
	__ATTR(iproto, 0444, sas_phy_iproto_show, NULL),
	__ATTR(tproto, 0444, sas_phy_tproto_show, NULL),
	__ATTR(type, 0444, sas_phy_type_show, NULL),
	__ATTR(role, 0444, sas_phy_role_show, NULL),
	__ATTR(linkrate, 0444, sas_phy_linkrate_show, NULL),
	__ATTR(sas_addr, 0444, sas_phy_addr_show, NULL),
	__ATTR(oob_mode, 0444, sas_phy_oob_mode_show, NULL),
	__ATTR_NULL,
};

static struct attribute *def_attrs[ARRAY_SIZE(phy_attrs)];

#define to_sas_phy(_obj) container_of(_obj, struct sas_phy, phy_kobj)
#define to_phy_attr(_attr) container_of(_attr, struct phy_attribute, attr)

static ssize_t phy_show_attr(struct kobject *kobj,
			     struct attribute *attr,
			     char *page)
{
	ssize_t ret = 0;
	struct sas_phy *phy = to_sas_phy(kobj);
	struct phy_attribute *phy_attr = to_phy_attr(attr);

	if (phy_attr->show)
		ret = phy_attr->show(phy, page);
	return ret;
}

static ssize_t phy_store_attr(struct kobject *kobj,
			      struct attribute *attr,
			      const char *page, size_t size)
{
	ssize_t ret = 0;
	struct sas_phy *phy = to_sas_phy(kobj);
	struct phy_attribute *phy_attr = to_phy_attr(attr);

	if (phy_attr->store)
		ret = phy_attr->store(phy, page, size);
	return ret;
}

static struct sysfs_ops phy_sysfs_ops = {
	.show = phy_show_attr,
	.store = phy_store_attr,
};

static struct kobj_type phy_ktype = {
	.sysfs_ops = &phy_sysfs_ops,
	.default_attrs = def_attrs,
};

/* ---------- Phy class registration ---------- */

int sas_register_phys(struct sas_ha_struct *sas_ha)
{
	int i, error;

	for (i = 0; i < ARRAY_SIZE(def_attrs)-1; i++)
		def_attrs[i] = &phy_attrs[i].attr;
	def_attrs[i] = NULL;

	/* make sas/ha/phys/ appear */
	kobject_set_name(&sas_ha->phy_kset.kobj, "%s", "phys");
	sas_ha->phy_kset.kobj.kset = &sas_ha->ha_kset; /* parent */
	/* we do not inherit the type of the parent */
	sas_ha->phy_kset.kobj.ktype = NULL;
	sas_ha->phy_kset.ktype = &phy_ktype;
	error = kset_register(&sas_ha->phy_kset);
	if (error)
		return error;

	/* Now register the phys. */
	for (i = 0; i < sas_ha->num_phys; i++) {
		int k;
		struct sas_phy *phy = sas_ha->sas_phy[i];

		phy->error = 0;
		INIT_LIST_HEAD(&phy->port_phy_el);
		INIT_LIST_HEAD(&phy->port_event_list);
		INIT_LIST_HEAD(&phy->phy_event_list);
		for (k = 0; k < PORT_NUM_EVENTS; k++) {
			struct sas_event *ev = &phy->port_events[k];
			ev->event = k;
			INIT_LIST_HEAD(&ev->el);
		}
		for (k = 0; k < PHY_NUM_EVENTS; k++) {
			struct sas_event *ev = &phy->phy_events[k];
			ev->event = k;
			INIT_LIST_HEAD(&ev->el);
		}
		phy->port = NULL;
		phy->ha = sas_ha;
		spin_lock_init(&phy->frame_rcvd_lock);
		spin_lock_init(&phy->sas_prim_lock);
		phy->frame_rcvd_size = 0;

		kobject_set_name(&phy->phy_kobj, "%d", i);
		phy->phy_kobj.kset = &sas_ha->phy_kset; /* parent */
		phy->phy_kobj.ktype = sas_ha->phy_kset.ktype;
		error = kobject_register(&phy->phy_kobj);
		if (error)
			goto unroll;
	}

	return 0;
unroll:
	for (i--; i >= 0; i--)
		kobject_unregister(&sas_ha->sas_phy[i]->phy_kobj);

	return error;
}

void sas_unregister_phys(struct sas_ha_struct *sas_ha)
{
	int i;

	for (i = 0; i < sas_ha->num_phys; i++)
		kobject_unregister(&sas_ha->sas_phy[i]->phy_kobj);

	kset_unregister(&sas_ha->phy_kset);
}

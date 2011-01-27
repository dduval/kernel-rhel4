/*
 * Serial Attached SCSI (SAS) class internal header file
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
 * $Id: //depot/sas-class/sas_internal.h#35 $
 */

#ifndef _SAS_INTERNAL_H_
#define _SAS_INTERNAL_H_

#include <scsi/sas/sas_class.h>

#define sas_printk(fmt, ...) printk(KERN_NOTICE "sas: " fmt, ## __VA_ARGS__)

static inline void *kzalloc(size_t size, int flags)
{
	void *mem=kmalloc(size, flags);
	if (mem)
		memset(mem, 0, size);
	return mem;
}

static inline void sg_set_buf(struct scatterlist *sg, void *buf,
			      unsigned int buflen)
{
	sg->page = virt_to_page(buf);
	sg->offset = offset_in_page(buf);
	sg->length = buflen;
}

static inline void sg_init_one(struct scatterlist *sg, void *buf,
			       unsigned int buflen)
{
	memset(sg, 0, sizeof(*sg));
	sg_set_buf(sg, buf, buflen);
}
#ifdef SAS_DEBUG
#define SAS_DPRINTK(fmt, ...) printk(KERN_NOTICE "sas: " fmt, ## __VA_ARGS__)
#else
#define SAS_DPRINTK(fmt, ...)
#endif

int sas_show_class(enum sas_class class, char *buf);
int sas_show_proto(enum sas_proto proto, char *buf);
int sas_show_linkrate(enum sas_phy_linkrate linkrate, char *buf);
int sas_show_oob_mode(enum sas_oob_mode oob_mode, char *buf);

int  sas_register_phys(struct sas_ha_struct *sas_ha);
void sas_unregister_phys(struct sas_ha_struct *sas_ha);

int  sas_register_ports(struct sas_ha_struct *sas_ha);
void sas_unregister_ports(struct sas_ha_struct *sas_ha);

extern int  sas_register_scsi_host(struct sas_ha_struct *,
				   const struct scsi_host_template *);
void sas_unregister_scsi_host(struct sas_ha_struct *sas_ha);

int  sas_start_event_thread(struct sas_ha_struct *sas_ha);
void sas_kill_event_thread(struct sas_ha_struct *sas_ha);

int  sas_init_queue(struct sas_ha_struct *sas_ha);
void sas_shutdown_queue(struct sas_ha_struct *sas_ha);

void sas_phye_loss_of_signal(struct sas_phy *phy);
void sas_phye_oob_done(struct sas_phy *phy);
void sas_phye_oob_error(struct sas_phy *phy);
void sas_phye_spinup_hold(struct sas_phy *phy);

void sas_deform_port(struct sas_phy *phy);

void sas_porte_bytes_dmaed(struct sas_phy *phy);
void sas_porte_broadcast_rcvd(struct sas_phy *phy);
void sas_porte_link_reset_err(struct sas_phy *phy);
void sas_porte_timer_event(struct sas_phy *phy);
void sas_porte_hard_reset(struct sas_phy *phy);

int  sas_reserve_free_id(struct sas_port *port);
void sas_reserve_scsi_id(struct sas_port *port, int id);
void sas_release_scsi_id(struct sas_port *port, int id);

void sas_hae_reset(struct sas_ha_struct *sas_ha);

#endif /* _SAS_INTERNAL_H_ */

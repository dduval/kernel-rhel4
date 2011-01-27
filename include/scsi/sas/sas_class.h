/*
 * Serial Attached SCSI (SAS) class header file
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
 * $Id: //depot/sas-class/sas_class.h#66 $
 */

#ifndef _SAS_CLASS_H_
#define _SAS_CLASS_H_

#include <linux/list.h>
#include <linux/pci.h>
#include <asm/semaphore.h>
#include <scsi/scsi_device.h>
#include <scsi/sas/sas.h>

enum sas_class {
	SAS,
	EXPANDER
};

enum sas_phy_role {
	PHY_ROLE_NONE = 0,
	PHY_ROLE_TARGET = 0x40,
	PHY_ROLE_INITIATOR = 0x80,
};

enum sas_phy_type {
        PHY_TYPE_PHYSICAL,
        PHY_TYPE_VIRTUAL
};

/* The events are mnemonically described in sas_dump.c
 * so when updating/adding events here, please also
 * update the other file too.
 */
enum ha_event {
	HAE_RESET = 0U,
};
#define HA_NUM_EVENTS 1

enum port_event {
	PORTE_BYTES_DMAED     = 0U,
	PORTE_BROADCAST_RCVD  = 1,
	PORTE_LINK_RESET_ERR  = 2,
	PORTE_TIMER_EVENT     = 3,
	PORTE_HARD_RESET      = 4,
};
#define PORT_NUM_EVENTS 5

enum phy_event {
	PHYE_LOSS_OF_SIGNAL   = 0U,
	PHYE_OOB_DONE         = 1,
	PHYE_OOB_ERROR        = 2,
	PHYE_SPINUP_HOLD      = 3, /* hot plug SATA, no COMWAKE sent */
};
#define PHY_NUM_EVENTS 4

enum discover_event {
	DISCE_DISCOVER_DOMAIN   = 0U,
	DISCE_REVALIDATE_DOMAIN = 1,
	DISCE_PORT_GONE         = 2,
};
#define DISC_NUM_EVENTS 3

struct sas_event {
	int    event;
	struct list_head el;
};

/* The phy pretty much is controlled by the LLDD.
 * The class only reads those fields.
 */
struct sas_phy {
/* private: */
	struct kobject phy_kobj;

	/* protected by ha->event_lock */
	struct list_head   port_event_list;
	struct list_head   phy_event_list;
	struct sas_event   port_events[PORT_NUM_EVENTS];
	struct sas_event   phy_events[PHY_NUM_EVENTS];

	int error;

/* public: */
	/* The following are class:RO, driver:R/W */
	int            enabled;	  /* must be set */

	int            id;	  /* must be set */
	enum sas_class class;
	enum sas_proto iproto;
	enum sas_proto tproto;

	enum sas_phy_type  type;
	enum sas_phy_role  role;
	enum sas_oob_mode  oob_mode;
	enum sas_phy_linkrate linkrate;

	u8   *sas_addr;		  /* must be set */
	u8   attached_sas_addr[SAS_ADDR_SIZE]; /* class:RO, driver: R/W */

	spinlock_t     frame_rcvd_lock;
	u8             *frame_rcvd; /* must be set */
	int            frame_rcvd_size;

	spinlock_t     sas_prim_lock;
	u32            sas_prim;

	struct list_head port_phy_el; /* driver:RO */
	struct sas_port      *port; /* Class:RW, driver: RO */

	struct sas_ha_struct *ha; /* may be set; the class sets it anyway */

	void *lldd_phy;		  /* not touched by the sas_class_code */
};

struct sas_port;

struct sas_discovery {
	spinlock_t disc_event_lock;
	int        disc_thread_quit;
	struct list_head disc_event_list;
	struct sas_event disc_events[DISC_NUM_EVENTS];
	struct task_struct *disc_thread;
	struct semaphore  disc_sema;

	u8     fanout_sas_addr[8];
	u8     eeds_a[8];
	u8     eeds_b[8];
	int    max_level;
};

struct scsi_id_map {
	int         max_ids;
	spinlock_t  id_bitmap_lock;
	int         id_bitmap_size;
	void       *id_bitmap;
};

struct domain_device;

/* The port struct is Class:RW, driver:RO */
struct sas_port {
/* private: */
	struct kobject port_kobj;
	struct kset    phy_kset;
	struct kset    dev_kset;

	struct completion port_gone_completion;

	struct sas_discovery disc;
	struct domain_device *port_dev;
	struct list_head dev_list;
	enum   sas_phy_linkrate linkrate;

	struct scsi_id_map id_map;

/* public: */
	int id;

	enum sas_class   class;
	u8               sas_addr[SAS_ADDR_SIZE];
	u8               attached_sas_addr[SAS_ADDR_SIZE];
	enum sas_proto   iproto;
	enum sas_proto   tproto;

	enum sas_oob_mode oob_mode;

	spinlock_t       phy_list_lock;
	struct list_head phy_list;
	int              num_phys;
	u32              phy_mask;

	struct sas_ha_struct *ha;

	void *lldd_port;	  /* not touched by the sas class code */
};

struct sas_task;

struct scsi_core {
	struct kobject scsi_core_obj;

	struct scsi_host_template *sht;
	struct Scsi_Host *shost;

	spinlock_t        task_queue_lock;
	struct list_head  task_queue;
	int               task_queue_size;

	struct semaphore  queue_thread_sema;
	int               queue_thread_kill;
};

struct sas_ha_struct {
/* private: */
	struct kset      ha_kset; /* "this" */
	struct kset      phy_kset;
	struct kset      port_kset;

	struct semaphore event_sema;
	int              event_thread_kill;

	spinlock_t       event_lock;
	struct list_head ha_event_list;
	struct sas_event ha_events[HA_NUM_EVENTS];
	u32              porte_mask; /* mask of phys for port events */
	u32              phye_mask; /* mask of phys for phy events */

	struct scsi_core core;

/* public: */
	char *sas_ha_name;
	struct pci_dev *pcidev;	  /* should be set */
	struct module *lldd_module; /* should be set */

	u8 *sas_addr;		  /* must be set */
	u8 hashed_sas_addr[HASHED_SAS_ADDR_SIZE];

	spinlock_t      phy_port_lock;
	struct sas_phy  **sas_phy; /* array of valid pointers, must be set */
	struct sas_port **sas_port; /* array of valid pointers, must be set */
	int             num_phys; /* must be set, gt 0, static */

	/* LLDD calls these to notify the class of an event. */
	void (*notify_ha_event)(struct sas_ha_struct *, enum ha_event);
	void (*notify_port_event)(struct sas_phy *, enum port_event);
	void (*notify_phy_event)(struct sas_phy *, enum phy_event);

	/* The class calls these to notify the LLDD of an event. */
	void (*lldd_port_formed)(struct sas_phy *);
	void (*lldd_port_deformed)(struct sas_phy *);

	/* The class calls these when a device is found or gone. */
	int  (*lldd_dev_found)(struct domain_device *);
	void (*lldd_dev_gone)(struct domain_device *);

	/* The class calls this to send a task for execution. */
	int lldd_max_execute_num;
	int lldd_queue_size;
	int (*lldd_execute_task)(struct sas_task *, int num,
				 unsigned long gfp_flags);

	/* Task Management Functions. Must be called from process context. */
	int (*lldd_abort_task)(struct sas_task *);
	int (*lldd_abort_task_set)(struct domain_device *, u8 *lun);
	int (*lldd_clear_aca)(struct domain_device *, u8 *lun);
	int (*lldd_clear_task_set)(struct domain_device *, u8 *lun);
	int (*lldd_I_T_nexus_reset)(struct domain_device *);
	int (*lldd_lu_reset)(struct domain_device *, u8 *lun);
	int (*lldd_query_task)(struct sas_task *);

	/* Port and Adapter management */
	int (*lldd_clear_nexus_port)(struct sas_port *);
	int (*lldd_clear_nexus_ha)(struct sas_ha_struct *);

	/* Phy management */
	int (*lldd_control_phy)(struct sas_phy *, enum phy_func);

	void *lldd_ha;		  /* not touched by sas class code */
};

#define SHOST_TO_SAS_HA(_shost) (*(struct sas_ha_struct **)(_shost)->hostdata)

void sas_hash_addr(u8 *hashed, const u8 *sas_addr);

/* Before calling a notify event, LLDD should use this function
 * when the link is severed (possibly from its tasklet).
 * The idea is that the Class only reads those, while the LLDD,
 * can R/W these (thus avoiding a race).
 */
static inline void sas_phy_disconnected(struct sas_phy *phy)
{
	phy->oob_mode = OOB_NOT_CONNECTED;
	phy->linkrate = PHY_LINKRATE_NONE;
}

extern int sas_register_ha(struct sas_ha_struct *, const struct scsi_host_template *);
extern int sas_unregister_ha(struct sas_ha_struct *);

extern int sas_queuecommand(struct scsi_cmnd *cmd,
		     void (*scsi_done)(struct scsi_cmnd *));
extern int sas_scsi_recover_host(struct Scsi_Host *shost);
extern enum scsi_eh_timer_return sas_scsi_timed_out(struct scsi_cmnd *cmd);
extern int sas_slave_alloc(struct scsi_device *scsi_dev);
extern int sas_slave_configure(struct scsi_device *scsi_dev);
extern void sas_slave_destroy(struct scsi_device *scsi_dev);
extern int sas_change_queue_depth(struct scsi_device *scsi_dev, int new_depth);
extern int sas_change_queue_type(struct scsi_device *scsi_dev, int qt);
extern int sas_bios_param(struct scsi_device *scsi_dev,
			  struct block_device *bdev,
			  sector_t capacity, int *hsc);

#endif /* _SAS_CLASS_H_ */

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
 * $Id: iscsi-sfnet.h,v 1.3.2.8 2005/04/27 06:26:21 mikenc Exp $
 *
 * Misc definitions for the iSCSI kernel module
 */
#ifndef ISCSI_SFNET_H_
#define ISCSI_SFNET_H_

#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/random.h>
#include <asm/scatterlist.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_transport_iscsi.h>

struct iscsi_session;
struct iscsi_session_ioctl;
struct iscsi_task;
struct iscsi_hdr;

#define ISCSI_DRIVER_VERSION	"4:0.1.11-3"
#define ISCSI_MAX_CMD_LEN	16
#define ISCSI_CMDS_PER_LUN	32
/*
 * we rely on scsi-ml's starvation code here
 */
#define ISCSI_MAX_CAN_QUEUE	1024
#define ISCSI_MAX_SG		SG_ALL
#define ISCSI_MAX_SECTORS	1024
#define ISCSI_MAX_LUNS		256
#define ISCSI_MAX_TARGETS	1
#define ISCSI_MAX_CHANNELS	0

#define ISCSI_PROC_NAME 	"iscsi-sfnet"

#define iscsi_host_err(s, fmt, args...) \
	printk(KERN_ERR "iscsi-sfnet:host%d: "fmt, s->shost->host_no, ##args)
#define iscsi_err(fmt, args...) \
	printk(KERN_ERR "iscsi-sfnet: "fmt, ##args)

#define iscsi_host_warn(s, fmt, args...) \
	printk(KERN_WARNING "iscsi-sfnet:host%d: "fmt, s->shost->host_no, \
	       ##args)
#define iscsi_warn(fmt, args...) \
	printk(KERN_WARNING "iscsi-sfnet: "fmt, ##args)

#define iscsi_host_notice(s, fmt, args...) \
	printk(KERN_NOTICE "iscsi-sfnet:host%d: "fmt, s->shost->host_no, ##args)
#define iscsi_notice(fmt, args...) \
	printk(KERN_NOTICE "iscsi-sfnet: "fmt, ##args)

#define iscsi_host_info(s, fmt, args...) \
	printk(KERN_INFO "iscsi-sfnet:host%d: "fmt, s->shost->host_no, ##args)
#define iscsi_info(fmt, args...) \
	printk(KERN_INFO "iscsi-sfnet: "fmt, ##args)

/* miscalleneous routines */
extern unsigned int iscsi_command_attr(struct scsi_cmnd *sc);
extern void iscsi_complete_command(struct scsi_cmnd *sc);

/* Routines related to Serial Number Arithmetic */
extern int iscsi_sna_lt(u32 n1, u32 n2);
extern int iscsi_sna_lte(u32 n1, u32 n2);

/*
 * IO return values the driver uses in the send, recv
 * and network code. 
 */
enum {
	ISCSI_IO_SUCCESS,
	ISCSI_IO_ERR,
	ISCSI_IO_CRC32C_ERR,
	ISCSI_IO_INTR,
	ISCSI_IO_INVALID_OP,
};

/* Routines to build and transmit iSCSI PDUs and/or data */
extern void iscsi_send_scsi_cmnd(struct iscsi_task *task);
extern void iscsi_send_task_mgmt(struct iscsi_session *session);
extern void iscsi_send_r2t_data(struct iscsi_session *session);
extern void iscsi_send_nop_replys(struct iscsi_session *session);
extern void iscsi_send_logout(struct iscsi_session *session);
extern void iscsi_send_nop_out(struct iscsi_session *session);
extern void iscsi_queue_unsolicited_data(struct iscsi_task *task);
extern int iscsi_send_pdu(struct iscsi_session *session, struct iscsi_hdr *hdr,
			  int hdr_digest, char *data, int data_digest);
extern int iscsi_recv_pdu(struct iscsi_session *session, struct iscsi_hdr *hdr,
			  int hdr_digest, char *data, int data_len,
			  int data_digest);

/* Routines to send and receive data on TCP/IP sockets */
extern int iscsi_recvmsg(struct iscsi_session *session, struct kvec *iov,
			 size_t iovn, size_t size);
extern int iscsi_sendmsg(struct iscsi_session *session, struct kvec *iov,
			 size_t iovn, size_t size);
extern int iscsi_sendpage(struct iscsi_session *session, int flags,
			  struct page *pg, unsigned int pg_offset,
			  unsigned int len);
extern int iscsi_connect(struct iscsi_session *session);
extern void iscsi_disconnect(struct iscsi_session *session);

/* Register a driver interface */
extern int iscsi_register_interface(void);
extern void iscsi_unregister_interface(void);

/* ioctl and sysfs uses these routines to interact with the initiator */
extern int iscsi_destroy_host(struct Scsi_Host *shost);
extern int iscsi_create_host(struct iscsi_session_ioctl *ioctld);

/* Global variables */
extern struct class_device_attribute *iscsi_host_attrs[];
extern struct device_attribute *iscsi_dev_attrs[];
extern struct iscsi_function_template iscsi_fnt;
extern unsigned int iscsi_cmds_per_lun;

static inline void sg_init_one(struct scatterlist *sg,
                               u8 *buf, unsigned int buflen)
{
        memset(sg, 0, sizeof(*sg));

        sg->page = virt_to_page(buf);
        sg->offset = offset_in_page(buf);
        sg->length = buflen;
}

#endif

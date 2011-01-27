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
 * $Id: iscsi-session.h,v 1.1.2.34 2005/04/26 17:44:50 mikenc Exp $
 *
 * define the iSCSI session structure needed by the login library
 */
#ifndef ISCSI_SESSION_H_
#define ISCSI_SESSION_H_

#include <linux/crypto.h>
#include <linux/socket.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>

#include "iscsi-auth-client.h"
#include "iscsi-portal.h"

struct iscsi_session_ioctl;
struct iscsi_task;

/* used for replying to NOPs - kill me */
struct iscsi_nop_info {
	struct list_head	reply_list;
	u32			ttt;
	unsigned char		lun[8];
};

#define ISCSI_RXCTRL_SIZE 4096

struct iscsi_session {
	struct Scsi_Host	*shost;
	struct list_head	list;
	/*
	 * the config mutex along with the portal lock protect
	 * and serialize the creation and update of session info
	 */
	struct semaphore	config_mutex;
	u32			config_number;
	/*
	 * iSCSI settings
	 */
	unsigned char		*initiator_name;
	unsigned char		*initiator_alias;
	unsigned char		*target_name;
	unsigned char		*target_alias;
	u8			isid[6];
	u16			tsih;
	u32			cmd_sn;
	u32			exp_cmd_sn;
	u32			max_cmd_sn;
	u32			exp_stat_sn;
	int			immediate_data;
	int			initial_r2t;
	/* the value we declare */
	int			max_recv_data_segment_len; 
	/* the value declared by the target */
	int			max_xmit_data_segment_len;
	int			first_burst_len;
	int			max_burst_len;
	int			data_pdu_in_order;
	int			data_seq_in_order;
	int			def_time2wait;
	int			def_time2retain;
	int			header_digest;
	int			data_digest;
	int			type;
	int			current_stage;
	int			next_stage;
	int			partial_response;
	int			portal_group_tag;
	int			vendor_specific_keys;
	int			send_async_text;
	unsigned int		irrelevant_keys_bitmap;
	u32			next_itt;
	long			time2wait;
	/*
	 * Authentication settings
	 */
	char			*username;
	unsigned char		*password;
	int			password_length;
	char			*username_in;
	unsigned char		*password_in;
	int			password_length_in;
	struct crypto_tfm	*md5_tfm;
	int			bidirectional_auth;
	struct iscsi_acl	*auth_client_block;
	struct auth_str_block	*auth_recv_string_block;
	struct auth_str_block	*auth_send_string_block;
	struct auth_large_binary *auth_recv_binary_block;
	struct auth_large_binary *auth_send_binary_block;
	/*
	 * Portal/Network settings
	 * support ipv4 when we finish the interface
	 */
	struct socket		*socket;
	/* we only support ipv4 until we can find a setup to test */
	struct sockaddr 	addr;
	int			tcp_window_size;
	/*
	 * The portal lock protects the portal and related fields
	 */
	spinlock_t		portal_lock;
	struct iscsi_portal_info portal;
	/*
	 * various accounting sutff
	 */

	/*
	 * *_time fields used to detect sessions that die as soo
	 * as we hit FF
	 */
	unsigned long		session_drop_time;
	unsigned long		session_established_time;
	/*
	 * timer fields
	 *
	 * The transport and tmf timers and timeouts are accessed
	 * under the task lock.
	 *
	 * The replacement timer and login timer and their timeouts
	 * are accessed under the portal lock.
	 */
	struct timer_list	transport_timer;
	struct timer_list	logout_timer;
	struct timer_list       login_timer;
	struct timer_list	replacement_timer;
	struct timer_list       tmf_timer;
	unsigned long		last_rx;
	unsigned long		last_ping;
	unsigned long		window_closed;
	int			login_timeout;
	int			active_timeout;
	int			idle_timeout;
	int			ping_timeout;
	int			abort_timeout;
	int			reset_timeout;
	int			replacement_timeout;
	int			logout_response_timeout;
	/*
	 * iSCSI task/request
	 * - Requests originating from SCSI-ml like scsi cmnds and
	 * management functions are task backed.
	 * - iSCSI requests like Nop, Logout or Login do not
	 * have a struct iscsi_task to avoid allocating memory
	 * when not needed.
	 *
	 * The task lock protects the task/cmnd queues and the
	 * access to the task when the tx and rx thread could
	 * be accessing it at the same time.
	 */
	spinlock_t		task_lock;
	struct iscsi_task	*preallocated_task;
	struct list_head	pending_queue;
	struct list_head	active_queue;
	struct list_head	done_queue;
	struct list_head	tx_task_head;
	int			num_active_tasks;
	struct iscsi_nop_info	nop_reply;
	struct list_head	nop_reply_list;
	/* itt of the last mgmt task we sent */
	u32			last_mgmt_itt;
	/* preallocated task for TMFs */
	struct iscsi_task	*mgmt_task;
	struct completion	*mgmt_task_complete;
	/*
	 * thread control stuff
	 */
	unsigned long		control_bits;
	wait_queue_head_t	tx_wait_q;
	wait_queue_head_t	login_wait_q;
	struct semaphore	tx_blocked;
	struct task_struct	*rx_task;
	struct task_struct	*tx_task;
	struct crypto_tfm	*rx_tfm;
	struct crypto_tfm	*tx_tfm;
	/*
	 * preallocated buffer for iSCSI requests that have
	 * data, and do not originate from scsi-ml
	 */
	unsigned char		rx_buffer[ISCSI_RXCTRL_SIZE];
};

/* session control bits */
enum {
	/*
	 * the tx bits match the tx_request array in
	 * iscsi-initiator.c, so if you modify this don't forget
	 */
	TX_PING,		/* NopOut, reply requested */
	TX_TMF,
	TX_SCSI_COMMAND,
	TX_NOP_REPLY,		/* reply to a Nop-in from the target */
	TX_DATA,
	TX_LOGOUT,
	TX_WAKE,

	SESSION_CREATED,
	SESSION_RELEASING,
	/*
	 * must hold the task lock when accessing the
	 * SESSION_REPLACEMENT_TIMEDOUT and SESSION_ESTABLISHED bits
	 */
	SESSION_REPLACEMENT_TIMEDOUT,
	SESSION_ESTABLISHED,
	/*
	 * SESSION_IN_LOGIN is accessed under the portal_lock and is used for
	 * moding the login_timer.
	 */
	SESSION_IN_LOGIN,
	SESSION_LOGOUT_REQUESTED,
	SESSION_IN_LOGOUT,
	SESSION_WINDOW_CLOSED,
	SESSION_TERMINATING,
	SESSION_TERMINATED,
};

extern void iscsi_wake_tx_thread(int control_bit,
				 struct iscsi_session *session);
extern void iscsi_request_logout(struct iscsi_session *session, int logout,
				 int logout_response);
extern void iscsi_drop_session(struct iscsi_session *session);
extern void iscsi_update_replacement_timeout(struct iscsi_session *session,
					     int timeout);
extern void iscsi_update_login_timeout(struct iscsi_session *session,
				       int timeout);
extern void iscsi_update_ping_timeout(struct iscsi_session *session,
				      int timeout);
extern void iscsi_update_active_timeout(struct iscsi_session *session,
					int timeout);
extern void iscsi_update_idle_timeout(struct iscsi_session *session,
				      int timeout);
extern int iscsi_update_session(struct iscsi_session *session,
				struct iscsi_session_ioctl *ioctld);
extern int iscsi_create_session(struct iscsi_session *session,
				struct iscsi_session_ioctl *ioctld);
extern void iscsi_destroy_session(struct iscsi_session *session);
extern struct iscsi_session *iscsi_find_session(const char *target_name,
						u8 isid[6], int tpgt);
extern int iscsi_update_address(struct iscsi_session *session, char *address);
extern int iscsi_wait_for_session(struct iscsi_session *session,
				  int ignore_timeout);
extern void iscsi_mod_session_timer(struct iscsi_session *session, int timeout);

extern struct list_head iscsi_sessions;

#endif

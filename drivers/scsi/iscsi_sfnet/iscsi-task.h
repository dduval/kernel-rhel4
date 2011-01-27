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
 * $Id: iscsi-task.h,v 1.1.2.12 2005/04/26 17:44:50 mikenc Exp $
 *
 * define the iSCSI task structure needed by the kernel module
 */
#ifndef ISCSI_TASK_H_
#define ISCSI_TASK_H_

#include <scsi/scsi_cmnd.h>

struct iscsi_session;
struct iscsi_hdr;
struct iscsi_scsi_rsp_hdr;

/* task flags */
enum {
	/*
	 * ops
	 */
	ISCSI_TASK_WRITE,
	ISCSI_TASK_READ,
	ISCSI_TASK_ABORT,
	ISCSI_TASK_ABORT_TASK_SET,
	ISCSI_TASK_LU_RESET,
	ISCSI_TASK_TGT_WARM_RESET,
	/*
	 * internal driver state for the task
	 */
	ISCSI_TASK_INITIAL_R2T,
	ISCSI_TASK_COMPLETED,
	ISCSI_TASK_CRC_ERROR,
	ISCSI_TASK_TMF_SUCCESS,
	ISCSI_TASK_TMF_FAILED,
	ISCSI_TASK_IMM_REJECT,
};

/*
 * you must either have the task lock to access these fileds
 * or be assured that the tx and rx thread are not going
 * to able to access the filed at the same time.
 */
struct iscsi_task {
	struct list_head	queue;
	struct list_head	task_group_link;
	struct scsi_cmnd	*scsi_cmnd;
	struct iscsi_session	*session;
	int			refcount;
	u32			rxdata;
	unsigned long		flags;
	/*
	 * need to record so that aborts
	 * can set RefCmdSN properly
	 */
	u32			cmdsn;
	u32			itt;
	u32			ttt;
	u32			rtt;
	unsigned int		data_offset;	/* explicit R2T */
	int			data_length;	/* explicit R2T */
	unsigned int		lun;
};

extern kmem_cache_t *iscsi_task_cache;
extern struct iscsi_task *iscsi_find_session_task(struct iscsi_session *session,
						   u32 itt);
extern struct iscsi_task *iscsi_alloc_task(struct iscsi_session *session);
extern void iscsi_init_task(struct iscsi_task *task);
extern void __iscsi_put_task(struct iscsi_task *task);
extern u32 iscsi_alloc_itt(struct iscsi_session *session);
extern struct iscsi_task *iscsi_dequeue_r2t(struct iscsi_session *session);
extern void iscsi_queue_r2t(struct iscsi_session *session,
			    struct iscsi_task *task);
extern void iscsi_process_task_response(struct iscsi_task *task,
					struct iscsi_scsi_rsp_hdr *stsrh,
					unsigned char *sense_data,
					unsigned int senselen);
extern void iscsi_process_task_status(struct iscsi_task *task,
				      struct iscsi_hdr *sth);
extern void iscsi_run_pending_queue(struct iscsi_session *session);
extern void iscsi_flush_queues(struct iscsi_session *session, unsigned int lun,
			       int requeue);
extern void iscsi_complete_task(struct iscsi_task *task);
extern void __iscsi_complete_task(struct iscsi_task *task);
extern void iscsi_complete_tmf_task(struct iscsi_task *task, int state);
extern int iscsi_exec_task_mgmt(struct iscsi_task *task, unsigned long tmo);
extern void iscsi_update_abort_timeout(struct iscsi_session *session,
				       int timeout);
extern void iscsi_update_reset_timeout(struct iscsi_session *session,
				       int timeout);
extern void iscsi_tmf_times_out(unsigned long data);

#endif

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
 * $Id: iscsi-task.c,v 1.1.2.29 2005/04/28 17:28:19 mikenc Exp $
 *
 * Task creation, management and completion functions are defined here.
 */
#include <linux/delay.h>
#include <linux/blkdev.h>
#include <linux/interrupt.h>
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_eh.h>

#include "iscsi-protocol.h"
#include "iscsi-session.h"
#include "iscsi-task.h"
#include "iscsi-sfnet.h"

void
iscsi_init_task(struct iscsi_task *task)
{
	task->flags = 0;
	task->itt = ISCSI_RSVD_TASK_TAG;
	task->ttt = ISCSI_RSVD_TASK_TAG;
	task->rtt = ISCSI_RSVD_TASK_TAG;
	INIT_LIST_HEAD(&task->queue);
	INIT_LIST_HEAD(&task->task_group_link);
	task->refcount = 1;
	task->scsi_cmnd = NULL;
}

/* caller must hold the session's task lock */
struct iscsi_task *
iscsi_alloc_task(struct iscsi_session *session)
{
	struct iscsi_task *task;

	task = kmem_cache_alloc(iscsi_task_cache, GFP_ATOMIC);
	if (!task) {
		if (!session->preallocated_task)
			return NULL;

		task = session->preallocated_task;
		session->preallocated_task = NULL;
	}

	memset(task, 0, sizeof(*task));
	iscsi_init_task(task);
	task->session = session;

	return task;
}

/**
 * __iscsi_get_task - get a handle to a task
 * @task: task to get a handle on
 *
 * Note:
 *    task_lock must be held when calling.
 **/
static inline void
__iscsi_get_task(struct iscsi_task *task)
{
	task->refcount++;
}

/**
 * __iscsi_put_task - release handle to a task
 * @task: task to release a handle on
 **/
void
__iscsi_put_task(struct iscsi_task *task)
{
	struct scsi_cmnd *scmnd;
	struct iscsi_session *session;

	if (--task->refcount)
		return;

	BUG_ON(!list_empty(&task->task_group_link));

	list_del(&task->queue);
	scmnd = task->scsi_cmnd;
	session = task->session;

	if (!session->preallocated_task)
		session->preallocated_task = task;
	else
		kmem_cache_free(iscsi_task_cache, task);

	iscsi_complete_command(scmnd);
}

/*
 * Caller must hold task lock
 */
static inline void
queue_active_task(struct iscsi_task *task)
{
	struct iscsi_session *session = task->session;

	task->itt = iscsi_alloc_itt(session);
	list_add_tail(&task->queue, &session->active_queue);

	if (session->num_active_tasks == 0)
		iscsi_mod_session_timer(session, session->active_timeout);
	session->num_active_tasks++;
}

/**
 * iscsi_complete_task - Complete a task
 * @task: task to complete
 *
 * Note:
 *    This should only be used to complete pending commands
 *    or by iscsi_complete_task. See notes for iscsi_complete_task.
 **/
inline void
__iscsi_complete_task(struct iscsi_task *task)
{
	__set_bit(ISCSI_TASK_COMPLETED, &task->flags);
	list_del_init(&task->queue);
	list_add_tail(&task->queue, &task->session->done_queue);
	/*
	 * release handle obtained from allocation in queuecommand
	 */
	__iscsi_put_task(task);
}

/**
 * iscsi_complete_task - Complete a task in the active queue.
 * @task: task to complete
 *
 * Note:
 *    The caller must hold the task lock. This function does not actually
 *    complete the scsi command for the task. That is performed when all
 *    handles have been released. You should also have set the scsi cmnd
 *    status before calling this function.
 **/
void
iscsi_complete_task(struct iscsi_task *task)
{
	struct iscsi_session *session = task->session;

	if (list_empty(&task->queue)) {
		iscsi_host_info(session, "task itt %u already removed from "
				"active task queue\n", task->itt);
		return;
	}

	--session->num_active_tasks;
	if (session->num_active_tasks == 0) {
		iscsi_mod_session_timer(session, session->idle_timeout);

		if (test_bit(SESSION_LOGOUT_REQUESTED, &session->control_bits))
			iscsi_wake_tx_thread(TX_LOGOUT, session);
	}
	    
	if (session->mgmt_task_complete &&
	    session->mgmt_task->rtt == task->itt) {
		iscsi_host_info(session, "Completed task %u while abort "
				"in progress. Waking scsi_eh thread.\n",
				task->itt);
		iscsi_complete_tmf_task(session->mgmt_task,
					ISCSI_TASK_TMF_FAILED);
	}

	__iscsi_complete_task(task);
}

/**
 * wait_for_task - wait for a task being accessed by the tx_thread to be freed
 * @s: iscsi session
 * @field: task field to test
 * @val: value to test field for
 *
 * Note:
 *    This function only gets run by the eh, so performance is not
 *    critical. It is only used to wait when the tx thread is in
 *    the middle of transmitting a task and a TMF response is
 *    recieved for it at the same time.
 *
 *    Caller must hold the task lock. Ignore drop signals becuase
 *    we want to wait for the tx thread to finish up first and
 *    release its ref to this task.
 **/
#define wait_for_task(s, field, val)				\
do {								\
	struct iscsi_task *tsk;					\
								\
 retry_##field: 						\
	list_for_each_entry(tsk, &s->done_queue, queue) 	\
		if (tsk->field == val) {			\
			spin_unlock_bh(&s->task_lock);		\
			ssleep(1);				\
			spin_lock_bh(&s->task_lock);		\
			goto retry_##field;			\
		}						\
} while (0)

/**
 * iscsi_complete_tmf_task - Complete a task mgmt task.
 * @task: task to complete
 * @state: which task state bit to set.
 *
 * Note:
 *    The caller must hold the task lock.
 **/
void
iscsi_complete_tmf_task(struct iscsi_task *task, int state)
{
	struct iscsi_session *session = task->session;
	struct iscsi_task *aborted_task;
	struct completion *tmf_complete;

	if (list_empty(&task->queue))
		return;
	list_del_init(&task->queue);
	__set_bit(state, &task->flags);
	tmf_complete = session->mgmt_task_complete;
	session->mgmt_task_complete = NULL;

	--session->num_active_tasks;
	if (session->num_active_tasks == 0) {
		iscsi_mod_session_timer(session, session->idle_timeout);

		if (test_bit(SESSION_LOGOUT_REQUESTED, &session->control_bits))
			iscsi_wake_tx_thread(TX_LOGOUT, session);
	}

	if (state != ISCSI_TASK_TMF_SUCCESS)
		goto done;

	if (test_bit(ISCSI_TASK_ABORT, &task->flags)) {
		/*
		 * if the abort failed becuase the task completed this is
		 * handled by the caller
		 */
		aborted_task = iscsi_find_session_task(session, task->rtt);
		if (aborted_task) {
			iscsi_host_info(session, "Cleaning up aborted task "
					"itt %u\n", task->rtt);
			/*
			 * abort succeeded, so cleanup that task here.
			 */
			if (!list_empty(&aborted_task->task_group_link)) {
				list_del_init(&aborted_task->task_group_link);
				__iscsi_put_task(aborted_task);
			}
			iscsi_complete_task(aborted_task);
			__iscsi_put_task(aborted_task);
		}

		wait_for_task(session, itt, task->rtt);

	} else if (test_bit(ISCSI_TASK_LU_RESET, &task->flags) ||
		   test_bit(ISCSI_TASK_ABORT_TASK_SET, &task->flags)) {
		iscsi_flush_queues(session, task->lun, DID_BUS_BUSY);
		wait_for_task(session, lun, task->lun);
	} else {
		iscsi_flush_queues(session, ISCSI_MAX_LUNS, DID_BUS_BUSY);
		wait_for_task(session, session, session);
	}
 done:
	complete(tmf_complete);
}

/*
 * must hold the task lock
 */
u32
iscsi_alloc_itt(struct iscsi_session *session)
{
	u32 itt = session->next_itt++;
	/* iSCSI reserves 0xFFFFFFFF, this driver reserves 0 */
	if (session->next_itt == ISCSI_RSVD_TASK_TAG)
		session->next_itt = 1;
	return itt;
}

/**
 * iscsi_process_task_status - process the status and flag bits
 * @task: iscsi task
 * @sth: either a scsi respoonse or scsi data (with status flag set ) header
 *
 * Description:
 *    Perform status and flags processing, and handle common errors like
 *    digest errors or missing data.
 **/
void
iscsi_process_task_status(struct iscsi_task *task, struct iscsi_hdr *sth)
{
	struct iscsi_scsi_rsp_hdr *stsrh = (struct iscsi_scsi_rsp_hdr *)sth;
	struct scsi_cmnd *sc = task->scsi_cmnd;

	sc->result = DID_OK << 16 | stsrh->cmd_status;

	if (test_bit(ISCSI_TASK_CRC_ERROR, &task->flags)) {
		/*
		 * There was a digest error during data receive.
		 * Cause a command retry.
		 */
		if (sc->device->type == TYPE_TAPE) 
			sc->result = DID_PARITY << 16;
		else
			sc->result = DID_IMM_RETRY << 16;
		sc->resid = sc->request_bufflen;
		return;
        }

	if (stsrh->flags & ISCSI_FLAG_DATA_UNDERFLOW)
		sc->resid = ntohl(stsrh->residual_count);
	else if (stsrh->flags & ISCSI_FLAG_DATA_OVERFLOW) {
		/*
		 * Only report the error to scsi-ml for IO (do not report
		 * for sg and scsi-ml inserted commands) by using the underflow
		 * value to detect where it is coming from. This is what
		 * we should be doing for underflow, and is really not
		 * 100% correct for either since for scsi-ml commands
		 * underflow is not set and it does not check resid
		 * (and for overflow resid does not really matter anyways but
		 * this is to get the Cisco HW working with little headaches
		 * (we should have just done a blacklist if we are really
		 * breaking out the hacks in this version))
		 */
		if (sc->underflow)
			/*
			 * FIXME: not sure how to tell the SCSI layer
			 * of an overflow, so just give it an error
			 */
			sc->result = DID_ERROR << 16 | stsrh->cmd_status;
	 } else if (test_bit(ISCSI_TASK_READ, &task->flags) &&
		 task->rxdata != sc->request_bufflen)
		/*
		 * All the read data did not arrive. we don't know
		 * which parts of the buffer didn't get data, so
		 * report the whole buffer missing
		 */
		sc->resid = sc->request_bufflen;
}

void
iscsi_process_task_response(struct iscsi_task *task,
			    struct iscsi_scsi_rsp_hdr *stsrh,
			    unsigned char *sense_data, unsigned int sense_len)
{
	struct scsi_cmnd *sc = task->scsi_cmnd;

	iscsi_process_task_status(task, (struct iscsi_hdr *)stsrh);
	/*
	 * If the target bothered to send sense (even without a check
	 * condition), we pass it along, since it may indicate a problem,
	 * and it's safer to report a possible problem than it is to assume
	 * everything is fine.
	 */
	if (sense_len) {
		memset(sc->sense_buffer, 0, sizeof(sc->sense_buffer));
		memcpy(sc->sense_buffer, sense_data,
		       min((size_t)sense_len, sizeof(sc->sense_buffer)));
	}
}

void
iscsi_tmf_times_out(unsigned long data)
{
	struct iscsi_task *task = (struct iscsi_task *)data;
	struct iscsi_session *session = task->session;

	spin_lock(&session->task_lock);
	iscsi_host_err(session, "itt %u timed out\n", task->itt);
	iscsi_complete_tmf_task(task, ISCSI_TASK_TMF_FAILED);
	spin_unlock(&session->task_lock);
}

/*
 * for iscsi_update_*_timeout we rely on the eh thread
 * not waking (and deleting the tmf timer) until a outstanding
 * mgmt task is removed the session's active queue (iscsi_find_session_task
 * == NULL) so that we do not need to hold a lock around the timer
 * update.
 */
void
iscsi_update_abort_timeout(struct iscsi_session *session, int timeout)
{
	struct iscsi_task *task;

	if (timeout < 0) {
		iscsi_host_err(session, "Cannot set negative timeout value of"
			       "%d\n", timeout);
		return;
	}

	spin_lock_bh(&session->task_lock);
	if (timeout == session->abort_timeout)
		goto done;

	task = iscsi_find_session_task(session, session->last_mgmt_itt);
	if (!task)
		goto done;

	if ((!test_bit(ISCSI_TASK_ABORT, &task->flags) &&
	     !test_bit(ISCSI_TASK_ABORT_TASK_SET, &task->flags)))
		goto done;

	if ((del_timer(&session->tmf_timer) && timeout) ||
	    (!session->abort_timeout && timeout))
		mod_timer(&session->tmf_timer, jiffies + (timeout * HZ));
 done:
	session->abort_timeout = timeout;
	spin_unlock_bh(&session->task_lock);
}

void
iscsi_update_reset_timeout(struct iscsi_session *session, int timeout)
{
	struct iscsi_task *task;

	if (timeout < 0) {
		iscsi_host_err(session, "Cannot set negative timeout value of"
			       "%d\n", timeout);
		return;
	}

	spin_lock_bh(&session->task_lock);
	if (timeout == session->reset_timeout)
		goto done;

	task = iscsi_find_session_task(session, session->last_mgmt_itt);
	if (!task)
		goto done;

	if ((!test_bit(ISCSI_TASK_LU_RESET, &task->flags) &&
	     !test_bit(ISCSI_TASK_TGT_WARM_RESET, &task->flags)))
		goto done;

	if ((del_timer(&session->tmf_timer) && timeout) ||
	    (!session->reset_timeout && timeout))
		mod_timer(&session->tmf_timer, jiffies + (timeout * HZ));
 done:
	session->reset_timeout = timeout;
	spin_unlock_bh(&session->task_lock);
}

int
iscsi_exec_task_mgmt(struct iscsi_task *task, unsigned long timeout)
{
	struct iscsi_session *session = task->session;
	DECLARE_COMPLETION(complete);
	unsigned int reject_retry = 40;

	/*
	 * Did the last task mgmt fn timeout?
	 */
	if (session->last_mgmt_itt != ISCSI_RSVD_TASK_TAG) {
		iscsi_host_info(session, "Outstanding task mgmt function %u "
			       "exists.\n", session->last_mgmt_itt);
		return -1;
	}
 retry:
	/*
	 * set this incase of timer updates that start a timer
	 */
	session->tmf_timer.data = (unsigned long)task;
	if (timeout)
		mod_timer(&session->tmf_timer, jiffies + (timeout * HZ));
	session->mgmt_task_complete = &complete;

	queue_active_task(task);
	session->last_mgmt_itt = task->itt;
	spin_unlock_bh(&session->task_lock);

	iscsi_host_info(session, "Waking tx_thread to send task mgmt "
			"function itt %u\n", task->itt);
	iscsi_wake_tx_thread(TX_TMF, session);
	wait_for_completion(&complete);
	del_timer_sync(&session->tmf_timer);

	spin_lock_bh(&session->task_lock);

	session->mgmt_task_complete = NULL;
	/*
	 * we do not retry aborts on immediate rejects here, instead
	 * the caller should redrive it
	 */
	if (!test_bit(ISCSI_TASK_ABORT, &task->flags) &&
	    __test_and_clear_bit(ISCSI_TASK_IMM_REJECT, &task->flags)) {
		iscsi_host_err(session, "itt %u recieved immediate "
			       "reject. Sleeping for %u ms before retry\n",
			       task->itt, reject_retry);

		if (reject_retry <= 1280) {
			spin_unlock_bh(&session->task_lock);
			msleep_interruptible(reject_retry);
			spin_lock_bh(&session->task_lock);

			reject_retry *= 2;
			goto retry;
		}
	}

	return test_bit(ISCSI_TASK_TMF_SUCCESS, &task->flags) ? 0 : -1;
}

static void
iscsi_set_direction(struct iscsi_task *task)
{
	switch (task->scsi_cmnd->sc_data_direction) {
	case DMA_FROM_DEVICE:
		__set_bit(ISCSI_TASK_READ, &task->flags);
		break;
	case DMA_TO_DEVICE:
		__set_bit(ISCSI_TASK_WRITE, &task->flags);
		break;
	case DMA_BIDIRECTIONAL:
		/* We do not yet support this */
	case DMA_NONE:
		break;
	}
}

/**
 * iscsi_run_pending_queue - process pending tasks.
 * @session: the session to process.
 *
 * Note:
 *    Caller must not hold the task lock.
 **/
void
iscsi_run_pending_queue(struct iscsi_session *session)
{
	struct iscsi_task *task;

	spin_lock_bh(&session->task_lock);

	while (!signal_pending(current)) {

		if (!iscsi_sna_lte(session->cmd_sn, session->max_cmd_sn))
			break;

		if (test_bit(SESSION_LOGOUT_REQUESTED, &session->control_bits))
			break;

		if (list_empty(&session->pending_queue))
			break;

		task = list_entry(session->pending_queue.next,
				  struct iscsi_task, queue);
		list_del_init(&task->queue);

		iscsi_set_direction(task);
		queue_active_task(task);

		__iscsi_get_task(task);
		iscsi_queue_unsolicited_data(task);
		spin_unlock_bh(&session->task_lock);
		/*
		 * we don't bother to check if the xmit works, since if it
		 * fails, the session will drop, and all tasks and cmnds
		 * will be completed by the drop.
		 */
		iscsi_send_scsi_cmnd(task);
		spin_lock_bh(&session->task_lock);
		__iscsi_put_task(task);
	}

	spin_unlock_bh(&session->task_lock);
}

static void
fail_task(struct iscsi_task *task, int result)
{
	struct scsi_cmnd *sc = task->scsi_cmnd;

	sc->resid = sc->request_bufflen;
	sc->result = result << 16;
	sc->sense_buffer[0] = 0x70;
	sc->sense_buffer[2] = NOT_READY;
	sc->sense_buffer[7] = 0x0;

	iscsi_host_err(task->session, "Failing command cdb 0x%02x task %u "
		       "with return code = 0x%x\n", sc->cmnd[0], task->itt,
		       sc->result);
	/*
	 * was it pending
	 */
	if (task->itt == ISCSI_RSVD_TASK_TAG)
		__iscsi_complete_task(task);
	else {
		if (!list_empty(&task->task_group_link)) {
			list_del_init(&task->task_group_link);
			__iscsi_put_task(task);
		}
		iscsi_complete_task(task);
	}
}

/**
 * iscsi_flush_queues - Flush the active and pending queues.
 * @session: session to search tasks for
 * @lun: if lun is a valid value then only work on tasks on that lun
 * if lun is greater than or equal to ISCSI_MAX_LUNS then work on all tasks
 * @result: this should be a scsi-ml host_byte value
 *
 * Note:
 *    Caller must hold the task lock.
 *    The driver uses DID_BUS_BUSY to inidcate that it may be worth it
 *    to retry the command, but scsi-ml should have the final say (for
 *    tape, failfast, etc). And it uses DID_NO_CONNECT to indicate
 *    the session is gone and according to the replacment timeout not
 *    coming back so there is no point in retyring
 **/
void
iscsi_flush_queues(struct iscsi_session *session, unsigned int lun, int result)
{
	struct iscsi_task *task, *tmp;

	/*
	 * failing a task that is being aborted will lead to
	 * the TMF task being removed too, or completing a tmf could
	 * result in multiple tasks being removed. The task lock can also
	 * be dropped by iscsi_complete_tmf_task.
	 */
 restart:
        list_for_each_entry_safe(task, tmp, &session->active_queue, queue) {

		if (lun < ISCSI_MAX_LUNS && task->lun != lun)
			continue;

		if (task->scsi_cmnd)
			fail_task(task, result);
		else
			/*
			 * This should only occur during session drops or
			 * session replacement timeouts. We report success
			 * since we are not going to get a response and all
			 * the cmnds are going to be returned back to scsi-ml.
			 */
			iscsi_complete_tmf_task(task, ISCSI_TASK_TMF_SUCCESS);

		goto restart;
	}

	list_for_each_entry_safe(task, tmp, &session->pending_queue, queue) {

		if (lun < ISCSI_MAX_LUNS && task->lun != lun)
			continue;
		/*
		 * These commands have not even been sent, so there is
		 * no requirement to fail the command, but for a requeue
		 * there is no way to tell that the incoming commands
		 * were meant to be placed before the pending head or tail.
		 */
		fail_task(task, result);
	}
}

/*
 * must hold the task_lock to call this
 * TODO: if we cannot use the block layer tags we
 * should use a non-linear algorithm.
 */
struct iscsi_task *
iscsi_find_session_task(struct iscsi_session *session, u32 itt)
{
	struct iscsi_task *task = NULL;

	list_for_each_entry(task, &session->active_queue, queue)
		if (task->itt == itt) {
			__iscsi_get_task(task);
			return task;
		}
	return NULL;
}

/*
 * must hold the task_lock when calling this, and must release the
 * handle acquired when adding the task to the collection
 */
inline struct iscsi_task *
iscsi_dequeue_r2t(struct iscsi_session *session)
{
	struct list_head *p;

	if (!list_empty(&session->tx_task_head)) {
		p = session->tx_task_head.next;
		list_del_init(p);
		return list_entry(p, struct iscsi_task, task_group_link);
	}
	return NULL;
}

/*
 * Add a task to the collection.  Must hold the task_lock to do this.
 * This acquires a handle to the task that must be released when
 * the task is dequeued and that caller is done using it
 */
inline void
iscsi_queue_r2t(struct iscsi_session *session, struct iscsi_task *task)
{
	if (list_empty(&task->task_group_link)) {
		__iscsi_get_task(task);	
		list_add_tail(&task->task_group_link, &session->tx_task_head);
	}
}

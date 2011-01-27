/*
 *  IBM eServer eHCA Infiniband device driver for Linux on POWER
 *
 *  Functions for EQs, NEQs and interrupts
 *
 *  Authors: Heiko J Schick <schickhj@de.ibm.com>
 *           Khadija Souissi <souissi@de.ibm.com>
 *
 *  Copyright (c) 2005 IBM Corporation
 *
 *  All rights reserved.
 *
 *  This source code is distributed under a dual license of GPL v2.0 and OpenIB
 *  BSD.
 *
 * OpenIB BSD License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials
 * provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define DEB_PREFIX "eirq"

#include "ehca_classes.h"
#include "ehca_irq.h"
#include "ehca_iverbs.h"
#include "ehca_tools.h"
#include "hcp_if.h"
#include "hipz_fns.h"

#define EQE_COMPLETION_EVENT   EHCA_BMASK_IBM(1,1)
#define EQE_CQ_QP_NUMBER       EHCA_BMASK_IBM(8,31)
#define EQE_EE_IDENTIFIER      EHCA_BMASK_IBM(2,7)
#define EQE_CQ_NUMBER          EHCA_BMASK_IBM(8,31)
#define EQE_QP_NUMBER          EHCA_BMASK_IBM(8,31)
#define EQE_QP_TOKEN           EHCA_BMASK_IBM(32,63)
#define EQE_CQ_TOKEN           EHCA_BMASK_IBM(32,63)

#define NEQE_COMPLETION_EVENT  EHCA_BMASK_IBM(1,1)
#define NEQE_EVENT_CODE        EHCA_BMASK_IBM(2,7)
#define NEQE_PORT_NUMBER       EHCA_BMASK_IBM(8,15)
#define NEQE_PORT_AVAILABILITY EHCA_BMASK_IBM(16,16)

#define ERROR_DATA_LENGTH      EHCA_BMASK_IBM(52,63)
#define ERROR_DATA_TYPE        EHCA_BMASK_IBM(0,7)

static inline void comp_event_callback(struct ehca_cq *cq)
{
	EDEB_EN(7, "cq=%p", cq);

	if (!cq->ib_cq.comp_handler)
		return;

	spin_lock(&cq->cb_lock);
	cq->ib_cq.comp_handler(&cq->ib_cq, cq->ib_cq.cq_context);
	spin_unlock(&cq->cb_lock);

	EDEB_EX(7, "cq=%p", cq);

	return;
}

static void print_error_data(struct ehca_shca * shca, void* data,
			     u64* rblock, int length)
{
	u64 type = EHCA_BMASK_GET(ERROR_DATA_TYPE, rblock[2]);
	u64 resource = rblock[1];

	EDEB_EN(7, "shca=%p data=%p rblock=%p length=%x",
		shca, data, rblock, length);

	switch (type) {
	case 0x1: /* Queue Pair */
	{
		struct ehca_qp *qp = (struct ehca_qp*)data;

		/* only print error data if AER is set */
		if (rblock[6] == 0)
			return;

		EDEB_ERR(4, "QP 0x%x (resource=%lx) has errors.",
			 qp->ib_qp.qp_num, resource);
		break;
	}
	case 0x4: /* Completion Queue */
	{
		struct ehca_cq *cq = (struct ehca_cq*)data;

		EDEB_ERR(4, "CQ 0x%x (resource=%lx) has errors.",
			 cq->cq_number, resource);
		break;
	}
	default:
		EDEB_ERR(4, "Unknown errror type: %lx on %s.",
			 type, shca->ib_device.name);
		break;
	}

	EDEB_ERR(4, "Error data is available: %lx.", resource);
	EDEB_ERR(4, "EHCA ----- error data begin "
		 "---------------------------------------------------");
	EDEB_DMP(4, rblock, length, "resource=%lx", resource);
	EDEB_ERR(4, "EHCA ----- error data end "
		 "----------------------------------------------------");

	EDEB_EX(7, "");

	return;
}

int ehca_error_data(struct ehca_shca *shca, void *data,
		    u64 resource)
{

	unsigned long ret = 0;
	u64 *rblock;
	unsigned long block_count;

	EDEB_EN(7, "shca=%p data=%p resource=%lx", shca, data, resource);

	rblock = kzalloc(H_CB_ALIGNMENT, GFP_KERNEL);
	if (!rblock) {
		EDEB_ERR(4, "Cannot allocate rblock memory.");
		ret = -ENOMEM;
		goto error_data1;
	}

	ret = hipz_h_error_data(shca->ipz_hca_handle,
				resource,
				rblock,
				&block_count);

	if (ret == H_R_STATE) {
		EDEB_ERR(4, "No error data is available: %lx.", resource);
	}
	else if (ret == H_SUCCESS) {
		int length;

		length = EHCA_BMASK_GET(ERROR_DATA_LENGTH, rblock[0]);

		if (length > PAGE_SIZE)
			length = PAGE_SIZE;

		print_error_data(shca, data, rblock, length);
	}
	else {
		EDEB_ERR(4, "Error data could not be fetched: %lx", resource);
	}

	kfree(rblock);

error_data1:
	return ret;

}

static void qp_event_callback(struct ehca_shca *shca,
			      u64 eqe,
			      enum ib_event_type event_type)
{
	struct ib_event event;
	struct ehca_qp *qp;
	unsigned long flags;
	u32 token = EHCA_BMASK_GET(EQE_QP_TOKEN, eqe);

	EDEB_EN(7, "eqe=%lx", eqe);

	spin_lock_irqsave(&ehca_qp_idr_lock, flags);
	qp = idr_find(&ehca_qp_idr, token);
	spin_unlock_irqrestore(&ehca_qp_idr_lock, flags);


	if (!qp)
		return;

	ehca_error_data(shca, qp, qp->ipz_qp_handle.handle);

	if (!qp->ib_qp.event_handler)
		return;

	event.device     = &shca->ib_device;
	event.event      = event_type;
	event.element.qp = &qp->ib_qp;

	qp->ib_qp.event_handler(&event, qp->ib_qp.qp_context);

	EDEB_EX(7, "qp=%p", qp);

	return;
}

static void cq_event_callback(struct ehca_shca *shca,
					  u64 eqe)
{
	struct ehca_cq *cq;
	unsigned long flags;
	u32 token = EHCA_BMASK_GET(EQE_CQ_TOKEN, eqe);

	EDEB_EN(7, "eqe=%lx", eqe);

	spin_lock_irqsave(&ehca_cq_idr_lock, flags);
	cq = idr_find(&ehca_cq_idr, token);
	spin_unlock_irqrestore(&ehca_cq_idr_lock, flags);

	if (!cq)
		return;

	ehca_error_data(shca, cq, cq->ipz_cq_handle.handle);

	EDEB_EX(7, "cq=%p", cq);

	return;
}

static void parse_identifier(struct ehca_shca *shca, u64 eqe)
{
	u8 identifier = EHCA_BMASK_GET(EQE_EE_IDENTIFIER, eqe);

	EDEB_EN(7, "shca=%p eqe=%lx", shca, eqe);

	switch (identifier) {
	case 0x02: /* path migrated */
		qp_event_callback(shca, eqe, IB_EVENT_PATH_MIG);
		break;
	case 0x03: /* communication established */
		qp_event_callback(shca, eqe, IB_EVENT_COMM_EST);
		break;
	case 0x04: /* send queue drained */
		qp_event_callback(shca, eqe, IB_EVENT_SQ_DRAINED);
		break;
	case 0x05: /* QP error */
	case 0x06: /* QP error */
		qp_event_callback(shca, eqe, IB_EVENT_QP_FATAL);
		break;
	case 0x07: /* CQ error */
	case 0x08: /* CQ error */
		cq_event_callback(shca, eqe);
		break;
	case 0x09: /* MRMWPTE error */
		EDEB_ERR(4, "MRMWPTE error.");
		break;
	case 0x0A: /* port event */
		EDEB_ERR(4, "Port event.");
		break;
	case 0x0B: /* MR access error */
		EDEB_ERR(4, "MR access error.");
		break;
	case 0x0C: /* EQ error */
		EDEB_ERR(4, "EQ error.");
		break;
	case 0x0D: /* P/Q_Key mismatch */
		EDEB_ERR(4, "P/Q_Key mismatch.");
		break;
	case 0x10: /* sampling complete */
		EDEB_ERR(4, "Sampling complete.");
		break;
	case 0x11: /* unaffiliated access error */
		EDEB_ERR(4, "Unaffiliated access error.");
		break;
	case 0x12: /* path migrating error */
		EDEB_ERR(4, "Path migration error.");
		break;
	case 0x13: /* interface trace stopped */
		EDEB_ERR(4, "Interface trace stopped.");
		break;
	case 0x14: /* first error capture info available */
	default:
		EDEB_ERR(4, "Unknown identifier: %x on %s.",
			 identifier, shca->ib_device.name);
		break;
	}

	EDEB_EX(7, "eqe=%lx identifier=%x", eqe, identifier);

	return;
}

static void parse_ec(struct ehca_shca *shca, u64 eqe)
{
	struct ib_event event;
	u8 ec   = EHCA_BMASK_GET(NEQE_EVENT_CODE, eqe);
	u8 port = EHCA_BMASK_GET(NEQE_PORT_NUMBER, eqe);

	EDEB_EN(7, "shca=%p eqe=%lx", shca, eqe);

	switch (ec) {
	case 0x30:		/* port availability change */
		if (EHCA_BMASK_GET(NEQE_PORT_AVAILABILITY, eqe)) {
			EDEB(4, "%s: port %x is active.",
			     shca->ib_device.name, port);
			event.device = &shca->ib_device;
			event.event = IB_EVENT_PORT_ACTIVE;
			event.element.port_num = port;
			shca->sport[port - 1].port_state = IB_PORT_ACTIVE;
			ib_dispatch_event(&event);
		} else {
			EDEB(4, "%s: port %x is inactive.",
			     shca->ib_device.name, port);
			event.device = &shca->ib_device;
			event.event = IB_EVENT_PORT_ERR;
			event.element.port_num = port;
			shca->sport[port - 1].port_state = IB_PORT_DOWN;
			ib_dispatch_event(&event);
		}
		break;
	case 0x31:
		/* port configuration change      */
		/* disruptive change is caused by */
		/* LID, PKEY or SM change         */
		EDEB(4, "EHCA disruptive port %x "
		     "configuration change.", port);

		EDEB(4, "%s: port %x is inactive.",
		     shca->ib_device.name, port);
		event.device = &shca->ib_device;
		event.event = IB_EVENT_PORT_ERR;
		event.element.port_num = port;
		shca->sport[port - 1].port_state = IB_PORT_DOWN;
		ib_dispatch_event(&event);

		EDEB(4, "%s: port %x is active.",
			     shca->ib_device.name, port);
		event.device = &shca->ib_device;
		event.event = IB_EVENT_PORT_ACTIVE;
		event.element.port_num = port;
		shca->sport[port - 1].port_state = IB_PORT_ACTIVE;
		ib_dispatch_event(&event);
		break;
	case 0x32: /* adapter malfunction */
		EDEB_ERR(4, "Adapter malfunction.");
		break;
	case 0x33:  /* trace stopped */
		EDEB_ERR(4, "Traced stopped.");
		break;
	default:
		EDEB_ERR(4, "Unknown event code: %x on %s.",
			 ec, shca->ib_device.name);
		break;
	}

	EDEB_EN(7, "eqe=%lx ec=%x", eqe, ec);

	return;
}

static inline void reset_eq_pending(struct ehca_cq *cq)
{
	u64 CQx_EP = 0;
	struct h_galpa gal = cq->galpas.kernel;

	EDEB_EN(7, "cq=%p", cq);

	hipz_galpa_store_cq(gal, cqx_ep, 0x0);
	CQx_EP = hipz_galpa_load(gal, CQTEMM_OFFSET(cqx_ep));
	EDEB(7, "CQx_EP=%lx", CQx_EP);

	EDEB_EX(7, "cq=%p", cq);

	return;
}

irqreturn_t ehca_interrupt_neq(int irq, void *dev_id, struct pt_regs *regs)
{
	struct ehca_shca *shca = (struct ehca_shca*)dev_id;

	EDEB_EN(7, "dev_id=%p", dev_id);

	tasklet_hi_schedule(&shca->neq.interrupt_task);

	EDEB_EX(7, "");

	return IRQ_HANDLED;
}

void ehca_tasklet_neq(unsigned long data)
{
	struct ehca_shca *shca = (struct ehca_shca*)data;
	struct ehca_eqe *eqe;
	u64 ret = H_SUCCESS;

	EDEB_EN(7, "shca=%p", shca);

	eqe = (struct ehca_eqe *)ehca_poll_eq(shca, &shca->neq);

	while (eqe) {
		if (!EHCA_BMASK_GET(NEQE_COMPLETION_EVENT, eqe->entry))
			parse_ec(shca, eqe->entry);

		eqe = (struct ehca_eqe *)ehca_poll_eq(shca, &shca->neq);
	}

	ret = hipz_h_reset_event(shca->ipz_hca_handle,
				 shca->neq.ipz_eq_handle, 0xFFFFFFFFFFFFFFFFL);

	if (ret != H_SUCCESS)
		EDEB_ERR(4, "Can't clear notification events.");

	EDEB_EX(7, "shca=%p", shca);

	return;
}

irqreturn_t ehca_interrupt_eq(int irq, void *dev_id, struct pt_regs *regs)
{
	struct ehca_shca *shca = (struct ehca_shca*)dev_id;

	EDEB_EN(7, "dev_id=%p", dev_id);

	tasklet_hi_schedule(&shca->eq.interrupt_task);

	EDEB_EX(7, "");

	return IRQ_HANDLED;
}

void ehca_tasklet_eq(unsigned long data)
{
	struct ehca_shca *shca = (struct ehca_shca*)data;
	struct ehca_eqe *eqe;
	int int_state;

	EDEB_EN(7, "shca=%p", shca);

	do {
		eqe = (struct ehca_eqe *)ehca_poll_eq(shca, &shca->eq);

		if ((shca->hw_level >= 2) && eqe)
			int_state = 1;
		else
			int_state = 0;

		while ((int_state == 1) || eqe) {
			while (eqe) {
				u64 eqe_value = eqe->entry;

				EDEB(7, "eqe_value=%lx", eqe_value);

				/* TODO: better structure */
				if (EHCA_BMASK_GET(EQE_COMPLETION_EVENT,
						   eqe_value)) {
					extern struct ehca_comp_pool* ehca_pool;
					extern struct idr ehca_cq_idr;
					unsigned long flags;
					u32 token;
					struct ehca_cq *cq;

					EDEB(6, "... completion event");
					token =
						EHCA_BMASK_GET(EQE_CQ_TOKEN,
							       eqe_value);
					spin_lock_irqsave(&ehca_cq_idr_lock,
							  flags);
					cq = idr_find(&ehca_cq_idr, token);

					if (cq == NULL) {
						spin_unlock(&ehca_cq_idr_lock);
						break;
					}

					reset_eq_pending(cq);
					ehca_queue_comp_task(ehca_pool, cq);
					spin_unlock_irqrestore(&ehca_cq_idr_lock,
							       flags);
				} else {
					EDEB(6, "... non completion event");
					parse_identifier(shca, eqe_value);
				}
				eqe =
					(struct ehca_eqe *)ehca_poll_eq(shca,
								    &shca->eq);
			}

			if (shca->hw_level >= 2)
				int_state =
				    hipz_h_query_int_state(shca->ipz_hca_handle,
							   shca->eq.ist);
			eqe = (struct ehca_eqe *)ehca_poll_eq(shca, &shca->eq);

		}
	} while (int_state != 0);

	EDEB_EX(7, "shca=%p", shca);

	return;
}

static inline int find_next_online_cpu(struct ehca_comp_pool* pool)
{
	unsigned long flags_last_cpu;

	spin_lock_irqsave(&pool->last_cpu_lock, flags_last_cpu);
	pool->last_cpu = next_cpu(pool->last_cpu, cpu_online_map);

	if (pool->last_cpu == NR_CPUS)
		pool->last_cpu = 0;

	spin_unlock_irqrestore(&pool->last_cpu_lock, flags_last_cpu);

	return pool->last_cpu;
}

void ehca_queue_comp_task(struct ehca_comp_pool *pool, struct ehca_cq *__cq)
{
	int cpu;
	int cpu_id;
	struct ehca_cpu_comp_task *cct;
	unsigned long flags_cct;
	unsigned long flags_cq;

	cpu = get_cpu();
	cpu_id = find_next_online_cpu(pool);

	EDEB_EN(7, "pool=%p cq=%p cq_nr=%x CPU=%x:%x:%x:%x",
		pool, __cq, __cq->cq_number,
		cpu, cpu_id, num_online_cpus(), num_possible_cpus());

	BUG_ON(!cpu_online(cpu_id));

	cct = per_cpu_ptr(pool->cpu_comp_tasks, cpu_id);

	spin_lock_irqsave(&cct->task_lock, flags_cct);
	spin_lock_irqsave(&__cq->task_lock, flags_cq);

	if (__cq->nr_callbacks == 0) {
		__cq->nr_callbacks++;
		list_add_tail(&__cq->entry, &cct->cq_list);
		wake_up(&cct->wait_queue);
	}
	else
		__cq->nr_callbacks++;

	spin_unlock_irqrestore(&__cq->task_lock, flags_cq);
	spin_unlock_irqrestore(&cct->task_lock, flags_cct);

	put_cpu();

	EDEB_EX(7, "cct=%p", cct);

	return;
}

static void run_comp_task(struct ehca_cpu_comp_task* cct)
{
	struct ehca_cq *cq = NULL;
	unsigned long flags_cct;
	unsigned long flags_cq;


	EDEB_EN(7, "cct=%p", cct);

	spin_lock_irqsave(&cct->task_lock, flags_cct);

	while (!list_empty(&cct->cq_list)) {
		cq = list_entry(cct->cq_list.next, struct ehca_cq, entry);
		spin_unlock_irqrestore(&cct->task_lock, flags_cct);
		comp_event_callback(cq);
		spin_lock_irqsave(&cct->task_lock, flags_cct);

		spin_lock_irqsave(&cq->task_lock, flags_cq);
		cq->nr_callbacks--;
		if (cq->nr_callbacks == 0)
			list_del_init(cct->cq_list.next);
		spin_unlock_irqrestore(&cq->task_lock, flags_cq);

	}

	spin_unlock_irqrestore(&cct->task_lock, flags_cct);

	EDEB_EX(7, "cct=%p cq=%p", cct, cq);

	return;
}

static int comp_task(void *__cct)
{
	struct ehca_cpu_comp_task* cct = __cct;
	DECLARE_WAITQUEUE(wait, current);

	EDEB_EN(7, "cct=%p", cct);

	set_current_state(TASK_INTERRUPTIBLE);
	while(!kthread_should_stop()) {
		add_wait_queue(&cct->wait_queue, &wait);

		if (list_empty(&cct->cq_list))
			schedule();
		else
			__set_current_state(TASK_RUNNING);

		remove_wait_queue(&cct->wait_queue, &wait);

		if (!list_empty(&cct->cq_list))
			run_comp_task(__cct);

		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);

	EDEB_EX(7, "");

	return 0;
}

static struct task_struct *create_comp_task(struct ehca_comp_pool *pool,
					    int cpu)
{
	struct ehca_cpu_comp_task *cct;

	EDEB_EN(7, "cpu=%d:%d", cpu, NR_CPUS);

	cct = per_cpu_ptr(pool->cpu_comp_tasks, cpu);
	spin_lock_init(&cct->task_lock);
	INIT_LIST_HEAD(&cct->cq_list);
	init_waitqueue_head(&cct->wait_queue);
	cct->task = kthread_create(comp_task, cct, "ehca_comp/%d", cpu);

	EDEB_EX(7, "cct/%d=%p", cpu, cct);

	return cct->task;
}

static void destroy_comp_task(struct ehca_comp_pool *pool,
			      int cpu)
{
	struct ehca_cpu_comp_task *cct;
	struct task_struct *task;

	EDEB_EN(7, "pool=%p cpu=%d:%d", pool, cpu, NR_CPUS);

	cct = per_cpu_ptr(pool->cpu_comp_tasks, cpu);
	cct->task = NULL;
	task = cct->task;

	if (task)
		kthread_stop(task);

	EDEB_EX(7, "");

	return;
}

struct ehca_comp_pool *ehca_create_comp_pool(void)
{
	struct ehca_comp_pool *pool;
	int cpu;
	struct task_struct *task;

	EDEB_EN(7, "");

	pool = kzalloc(sizeof(struct ehca_comp_pool), GFP_KERNEL);
	if (pool == NULL)
		return NULL;

	spin_lock_init(&pool->last_cpu_lock);
	pool->last_cpu = any_online_cpu(cpu_online_map);

	pool->cpu_comp_tasks = alloc_percpu(struct ehca_cpu_comp_task);
	if (pool->cpu_comp_tasks == NULL) {
		kfree(pool);
		return NULL;
	}

	for_each_online_cpu(cpu) {
		task = create_comp_task(pool, cpu);
		if (task) {
			kthread_bind(task, cpu);
			wake_up_process(task);
		}
	}

	EDEB_EX(7, "pool=%p", pool);

	return pool;
}

void ehca_destroy_comp_pool(struct ehca_comp_pool *pool)
{
	int i;

	EDEB_EN(7, "pool=%p", pool);

	for (i = 0; i < NR_CPUS; i++) {
		if (cpu_online(i))
			destroy_comp_task(pool, i);
	}

	EDEB_EN(7, "");

	return;
}

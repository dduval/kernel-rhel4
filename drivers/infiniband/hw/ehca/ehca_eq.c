/*
 *  IBM eServer eHCA Infiniband device driver for Linux on POWER
 *
 *  Event queue handling
 *
 *  Authors: Waleri Fomin <fomin@de.ibm.com>
 *           Khadija Souissi <souissi@de.ibm.com>
 *           Reinhard Ernst <rernst@de.ibm.com>
 *           Heiko J Schick <schickhj@de.ibm.com>
 *           Hoang-Nam Nguyen <hnguyen@de.ibm.com>
 *
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

#define DEB_PREFIX "e_eq"

#include "ehca_classes.h"
#include "ehca_irq.h"
#include "ehca_iverbs.h"
#include "ehca_qes.h"
#include "hcp_if.h"
#include "ipz_pt_fn.h"

int ehca_create_eq(struct ehca_shca *shca,
		   struct ehca_eq *eq,
		   const enum ehca_eq_type type, const u32 length)
{
	u64 ret = H_SUCCESS;
	u32 nr_pages = 0;
	u32 i;
	void *vpage = NULL;

	EDEB_EN(7, "shca=%p eq=%p length=%x", shca, eq, length);
	EHCA_CHECK_ADR(shca);
	EHCA_CHECK_ADR(eq);

	spin_lock_init(&eq->spinlock);
	eq->is_initialized = 0;

	if (type != EHCA_EQ && type != EHCA_NEQ) {
		EDEB_ERR(4, "Invalid EQ type %x. eq=%p", type, eq);
		return -EINVAL;
	}
	if (length == 0) {
		EDEB_ERR(4, "EQ length must not be zero. eq=%p", eq);
		return -EINVAL;
	}

	ret = hipz_h_alloc_resource_eq(shca->ipz_hca_handle,
				       &eq->pf,
				       type,
				       length,
				       &eq->ipz_eq_handle,
				       &eq->length,
				       &nr_pages, &eq->ist);

	if (ret != H_SUCCESS) {
		EDEB_ERR(4, "Can't allocate EQ / NEQ. eq=%p", eq);
		return -EINVAL;
	}

	ret = ipz_queue_ctor(&eq->ipz_queue, nr_pages,
			     EHCA_PAGESIZE, sizeof(struct ehca_eqe), 0);
	if (!ret) {
		EDEB_ERR(4, "Can't allocate EQ pages. eq=%p", eq);
		goto create_eq_exit1;
	}

	for (i = 0; i < nr_pages; i++) {
		u64 rpage;

		if (!(vpage = ipz_qpageit_get_inc(&eq->ipz_queue))) {
			ret = H_RESOURCE;
			goto create_eq_exit2;
		}

		rpage = virt_to_abs(vpage);
		ret = hipz_h_register_rpage_eq(shca->ipz_hca_handle,
					       eq->ipz_eq_handle,
					       &eq->pf,
					       0, 0, rpage, 1);

		if (i == (nr_pages - 1)) {
			/* last page */
			vpage = ipz_qpageit_get_inc(&eq->ipz_queue);
			if (ret != H_SUCCESS || vpage)
				goto create_eq_exit2;
		} else {
			if (ret != H_PAGE_REGISTERED || !vpage)
				goto create_eq_exit2;
		}
	}

	ipz_qeit_reset(&eq->ipz_queue);

	/* register interrupt handlers and initialize work queues */
	if (type == EHCA_EQ) {
		ret = ibmebus_request_irq(NULL, eq->ist, ehca_interrupt_eq,
					  SA_INTERRUPT, "ehca_eq",
					  (void *)shca);
		if (ret < 0)
			EDEB_ERR(4, "Can't map interrupt handler.");

		tasklet_init(&eq->interrupt_task, ehca_tasklet_eq, (long)shca);
	} else if (type == EHCA_NEQ) {
		ret = ibmebus_request_irq(NULL, eq->ist, ehca_interrupt_neq,
					  SA_INTERRUPT, "ehca_neq",
					  (void *)shca);
		if (ret < 0)
			EDEB_ERR(4, "Can't map interrupt handler.");

		tasklet_init(&eq->interrupt_task, ehca_tasklet_neq, (long)shca);
	}

	eq->is_initialized = 1;

	EDEB_EX(7, "ret=%lx", ret);

	return 0;

create_eq_exit2:
	ipz_queue_dtor(&eq->ipz_queue);

create_eq_exit1:
	hipz_h_destroy_eq(shca->ipz_hca_handle, eq);

	EDEB_EX(7, "ret=%lx", ret);

	return -EINVAL;
}

void *ehca_poll_eq(struct ehca_shca *shca, struct ehca_eq *eq)
{
	unsigned long flags = 0;
	void *eqe = NULL;

	EDEB_EN(7, "shca=%p  eq=%p", shca, eq);
	EHCA_CHECK_ADR_P(shca);
	EHCA_CHECK_EQ_P(eq);

	spin_lock_irqsave(&eq->spinlock, flags);
	eqe = ipz_eqit_eq_get_inc_valid(&eq->ipz_queue);
	spin_unlock_irqrestore(&eq->spinlock, flags);

	EDEB_EX(7, "eq=%p eqe=%p", eq, eqe);

	return eqe;
}

void ehca_poll_eqs(unsigned long data)
{
	struct ehca_shca *shca;
	struct ehca_module *module = (struct ehca_module*)data;

	spin_lock(&module->shca_lock);
	list_for_each_entry(shca, &module->shca_list, shca_list) {
		if (shca->eq.is_initialized)
			ehca_tasklet_eq((unsigned long)(void*)shca);
	}
	mod_timer(&module->timer, jiffies + HZ);
	spin_unlock(&module->shca_lock);

	return;
}

int ehca_destroy_eq(struct ehca_shca *shca, struct ehca_eq *eq)
{
	unsigned long flags = 0;
	u64 h_ret = H_SUCCESS;

	EDEB_EN(7, "shca=%p  eq=%p", shca, eq);
	EHCA_CHECK_ADR(shca);
	EHCA_CHECK_EQ(eq);

	spin_lock_irqsave(&eq->spinlock, flags);
	ibmebus_free_irq(NULL, eq->ist, (void *)shca);

	h_ret = hipz_h_destroy_eq(shca->ipz_hca_handle, eq);

	spin_unlock_irqrestore(&eq->spinlock, flags);

	if (h_ret != H_SUCCESS) {
		EDEB_ERR(4, "Can't free EQ resources.");
		return -EINVAL;
	}
	ipz_queue_dtor(&eq->ipz_queue);

	EDEB_EX(7, "h_ret=%lx", h_ret);

	return h_ret;
}

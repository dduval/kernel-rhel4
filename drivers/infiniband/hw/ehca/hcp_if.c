/*
 *  IBM eServer eHCA Infiniband device driver for Linux on POWER
 *
 *  Firmware Infiniband Interface code for POWER
 *
 *  Authors: Christoph Raisch <raisch@de.ibm.com>
 *           Hoang-Nam Nguyen <hnguyen@de.ibm.com>
 *           Gerd Bayer <gerd.bayer@de.ibm.com>
 *           Waleri Fomin <fomin@de.ibm.com>
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

#include <asm/hvcall.h>
#include "ehca_tools.h"
#include "hcp_if.h"
#include "hcp_phyp.h"
#include "hipz_fns.h"
#include "ipz_pt_fn.h"

#define H_ALL_RES_QP_ENHANCED_OPS       EHCA_BMASK_IBM(9,11)
#define H_ALL_RES_QP_PTE_PIN            EHCA_BMASK_IBM(12,12)
#define H_ALL_RES_QP_SERVICE_TYPE       EHCA_BMASK_IBM(13,15)
#define H_ALL_RES_QP_LL_RQ_CQE_POSTING  EHCA_BMASK_IBM(18,18)
#define H_ALL_RES_QP_LL_SQ_CQE_POSTING  EHCA_BMASK_IBM(19,21)
#define H_ALL_RES_QP_SIGNALING_TYPE     EHCA_BMASK_IBM(22,23)
#define H_ALL_RES_QP_UD_AV_LKEY_CTRL    EHCA_BMASK_IBM(31,31)
#define H_ALL_RES_QP_RESOURCE_TYPE      EHCA_BMASK_IBM(56,63)

#define H_ALL_RES_QP_MAX_OUTST_SEND_WR  EHCA_BMASK_IBM(0,15)
#define H_ALL_RES_QP_MAX_OUTST_RECV_WR  EHCA_BMASK_IBM(16,31)
#define H_ALL_RES_QP_MAX_SEND_SGE       EHCA_BMASK_IBM(32,39)
#define H_ALL_RES_QP_MAX_RECV_SGE       EHCA_BMASK_IBM(40,47)

#define H_ALL_RES_QP_ACT_OUTST_SEND_WR  EHCA_BMASK_IBM(16,31)
#define H_ALL_RES_QP_ACT_OUTST_RECV_WR  EHCA_BMASK_IBM(48,63)
#define H_ALL_RES_QP_ACT_SEND_SGE       EHCA_BMASK_IBM(8,15)
#define H_ALL_RES_QP_ACT_RECV_SGE       EHCA_BMASK_IBM(24,31)

#define H_ALL_RES_QP_SQUEUE_SIZE_PAGES  EHCA_BMASK_IBM(0,31)
#define H_ALL_RES_QP_RQUEUE_SIZE_PAGES  EHCA_BMASK_IBM(32,63)

/* direct access qp controls */
#define DAQP_CTRL_ENABLE    0x01
#define DAQP_CTRL_SEND_COMP 0x20
#define DAQP_CTRL_RECV_COMP 0x40

static u32 get_longbusy_msecs(int longbusy_rc)
{
	switch (longbusy_rc) {
	case H_LONG_BUSY_ORDER_1_MSEC:
		return 1;
	case H_LONG_BUSY_ORDER_10_MSEC:
		return 10;
	case H_LONG_BUSY_ORDER_100_MSEC:
		return 100;
	case H_LONG_BUSY_ORDER_1_SEC:
		return 1000;
	case H_LONG_BUSY_ORDER_10_SEC:
		return 10000;
	case H_LONG_BUSY_ORDER_100_SEC:
		return 100000;
	default:
		return 1;
	}
}

static long ehca_hcall_7arg_7ret(unsigned long opcode,
				 unsigned long arg1,
				 unsigned long arg2,
				 unsigned long arg3,
				 unsigned long arg4,
				 unsigned long arg5,
				 unsigned long arg6,
				 unsigned long arg7,
				 unsigned long *out1,
				 unsigned long *out2,
				 unsigned long *out3,
				 unsigned long *out4,
				 unsigned long *out5,
				 unsigned long *out6,
				 unsigned long *out7)
{
	long ret;
	int i, sleep_msecs;

	ehca_gen_dbg("opcode=%lx arg1=%lx arg2=%lx arg3=%lx arg4=%lx arg5=%lx "
		     "arg6=%lx arg7=%lx", opcode, arg1, arg2, arg3, arg4, arg5,
		     arg6, arg7);

	for (i = 0; i < 5; i++) {
		ret = plpar_hcall_7arg_7ret(opcode,
					    arg1, arg2, arg3, arg4,
					    arg5, arg6, arg7,
					    out1, out2, out3, out4,
					    out5, out6,out7);

		if (H_IS_LONG_BUSY(ret)) {
			sleep_msecs = get_longbusy_msecs(ret);
			msleep_interruptible(sleep_msecs);
			continue;
		}

		if (ret < H_SUCCESS)
			ehca_gen_err("opcode=%lx ret=%lx"
				     " arg1=%lx arg2=%lx arg3=%lx arg4=%lx"
				     " arg5=%lx arg6=%lx arg7=%lx"
				     " out1=%lx out2=%lx out3=%lx out4=%lx"
				     " out5=%lx out6=%lx out7=%lx",
				     opcode, ret,
				     arg1, arg2, arg3, arg4,
				     arg5, arg6, arg7,
				     *out1, *out2, *out3, *out4,
				     *out5, *out6, *out7);

		ehca_gen_dbg("opcode=%lx ret=%lx out1=%lx out2=%lx out3=%lx "
			     "out4=%lx out5=%lx out6=%lx out7=%lx",
			     opcode, ret, *out1, *out2, *out3, *out4, *out5,
			     *out6, *out7);
		return ret;
	}

	return H_BUSY;
}

static long ehca_hcall_9arg_9ret(unsigned long opcode,
				 unsigned long arg1,
				 unsigned long arg2,
				 unsigned long arg3,
				 unsigned long arg4,
				 unsigned long arg5,
				 unsigned long arg6,
				 unsigned long arg7,
				 unsigned long arg8,
				 unsigned long arg9,
				 unsigned long *out1,
				 unsigned long *out2,
				 unsigned long *out3,
				 unsigned long *out4,
				 unsigned long *out5,
				 unsigned long *out6,
				 unsigned long *out7,
				 unsigned long *out8,
				 unsigned long *out9)
{
	long ret;
	int i, sleep_msecs;

	ehca_gen_dbg("opcode=%lx arg1=%lx arg2=%lx arg3=%lx arg4=%lx "
		     "arg5=%lx arg6=%lx arg7=%lx arg8=%lx arg9=%lx",
		     opcode, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
		     arg8, arg9);

	for (i = 0; i < 5; i++) {
		ret = plpar_hcall_9arg_9ret(opcode,
					    arg1, arg2, arg3, arg4,
					    arg5, arg6, arg7, arg8,
					    arg9,
					    out1, out2, out3, out4,
					    out5, out6, out7, out8,
					    out9);

		if (H_IS_LONG_BUSY(ret)) {
			sleep_msecs = get_longbusy_msecs(ret);
			msleep_interruptible(sleep_msecs);
			continue;
		}

		if (ret < H_SUCCESS)
			ehca_gen_err("opcode=%lx ret=%lx"
				     " arg1=%lx arg2=%lx arg3=%lx arg4=%lx"
				     " arg5=%lx arg6=%lx arg7=%lx arg8=%lx"
				     " arg9=%lx"
				     " out1=%lx out2=%lx out3=%lx out4=%lx"
				     " out5=%lx out6=%lx out7=%lx out8=%lx"
				     " out9=%lx",
				     opcode, ret,
				     arg1, arg2, arg3, arg4,
				     arg5, arg6, arg7, arg8,
				     arg9,
				     *out1, *out2, *out3, *out4,
				     *out5, *out6, *out7, *out8,
				     *out9);

		ehca_gen_dbg("opcode=%lx ret=%lx out1=%lx out2=%lx out3=%lx "
			     "out4=%lx out5=%lx out6=%lx out7=%lx out8=%lx "
			     "out9=%lx", opcode, ret,*out1, *out2, *out3, *out4,
			     *out5, *out6, *out7, *out8, *out9);
		return ret;

	}

	return H_BUSY;
}

u64 hipz_h_alloc_resource_eq(const struct ipz_adapter_handle adapter_handle,
			     struct ehca_pfeq *pfeq,
			     const u32 neq_control,
			     const u32 number_of_entries,
			     struct ipz_eq_handle *eq_handle,
			     u32 * act_nr_of_entries,
			     u32 * act_pages,
			     u32 * eq_ist)
{
	u64 ret;
	u64 dummy;
	u64 allocate_controls;
	u64 act_nr_of_entries_out, act_pages_out, eq_ist_out;

	/* resource type */
	allocate_controls = 3ULL;

	/* ISN is associated */
	if (neq_control != 1)
		allocate_controls = (1ULL << (63 - 7)) | allocate_controls;
	else /* notification event queue */
		allocate_controls = (1ULL << 63) | allocate_controls;

	ret = ehca_hcall_7arg_7ret(H_ALLOC_RESOURCE,
				   adapter_handle.handle,  /* r4 */
				   allocate_controls,      /* r5 */
				   number_of_entries,      /* r6 */
				   0, 0, 0, 0,
				   &eq_handle->handle,     /* r4 */
				   &dummy,	           /* r5 */
				   &dummy,	           /* r6 */
				   &act_nr_of_entries_out, /* r7 */
				   &act_pages_out,	   /* r8 */
				   &eq_ist_out,            /* r8 */
				   &dummy);

	*act_nr_of_entries = (u32)act_nr_of_entries_out;
	*act_pages         = (u32)act_pages_out;
	*eq_ist            = (u32)eq_ist_out;

	if (ret == H_NOT_ENOUGH_RESOURCES)
		ehca_gen_err("Not enough resource - ret=%lx ", ret);

	return ret;
}

u64 hipz_h_reset_event(const struct ipz_adapter_handle adapter_handle,
		       struct ipz_eq_handle eq_handle,
		       const u64 event_mask)
{
	u64 dummy;

	return ehca_hcall_7arg_7ret(H_RESET_EVENTS,
				    adapter_handle.handle, /* r4 */
				    eq_handle.handle,      /* r5 */
				    event_mask,	           /* r6 */
				    0, 0, 0, 0,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy);
}

u64 hipz_h_alloc_resource_cq(const struct ipz_adapter_handle adapter_handle,
			     struct ehca_cq *cq,
			     struct ehca_alloc_cq_parms *param)
{
	u64 ret;
	u64 dummy;
	u64 act_nr_of_entries_out, act_pages_out;
	u64 g_la_privileged_out, g_la_user_out;

	ret = ehca_hcall_7arg_7ret(H_ALLOC_RESOURCE,
				   adapter_handle.handle,     /* r4  */
				   2,	                      /* r5  */
				   param->eq_handle.handle,   /* r6  */
				   cq->token,	              /* r7  */
				   param->nr_cqe,             /* r8  */
				   0, 0,
				   &cq->ipz_cq_handle.handle, /* r4  */
				   &dummy,	              /* r5  */
				   &dummy,	              /* r6  */
				   &act_nr_of_entries_out,    /* r7  */
				   &act_pages_out,	      /* r8  */
				   &g_la_privileged_out,      /* r9  */
				   &g_la_user_out);           /* r10 */

	param->act_nr_of_entries = (u32)act_nr_of_entries_out;
	param->act_pages = (u32)act_pages_out;

	if (ret == H_SUCCESS)
		hcp_galpas_ctor(&cq->galpas, g_la_privileged_out, g_la_user_out);

	if (ret == H_NOT_ENOUGH_RESOURCES)
		ehca_gen_err("Not enough resources. ret=%lx", ret);

	return ret;
}

u64 hipz_h_alloc_resource_qp(const struct ipz_adapter_handle adapter_handle,
			     struct ehca_qp *qp,
			     struct ehca_alloc_qp_parms *parms)
{
	u64 ret;
	u64 dummy, allocate_controls, max_r10_reg;
	u64 qp_nr_out, r6_out, r7_out, r8_out, g_la_user_out, r11_out;
	u16 max_nr_receive_wqes = qp->init_attr.cap.max_recv_wr + 1;
	u16 max_nr_send_wqes = qp->init_attr.cap.max_send_wr + 1;
	int daqp_ctrl = parms->daqp_ctrl;

	allocate_controls =
		EHCA_BMASK_SET(H_ALL_RES_QP_ENHANCED_OPS,
			       (daqp_ctrl & DAQP_CTRL_ENABLE) ? 1 : 0)
		| EHCA_BMASK_SET(H_ALL_RES_QP_PTE_PIN, 0)
		| EHCA_BMASK_SET(H_ALL_RES_QP_SERVICE_TYPE, parms->servicetype)
		| EHCA_BMASK_SET(H_ALL_RES_QP_SIGNALING_TYPE, parms->sigtype)
		| EHCA_BMASK_SET(H_ALL_RES_QP_LL_RQ_CQE_POSTING,
				 (daqp_ctrl & DAQP_CTRL_RECV_COMP) ? 1 : 0)
		| EHCA_BMASK_SET(H_ALL_RES_QP_LL_SQ_CQE_POSTING,
				 (daqp_ctrl & DAQP_CTRL_SEND_COMP) ? 1 : 0)
		| EHCA_BMASK_SET(H_ALL_RES_QP_UD_AV_LKEY_CTRL,
				 parms->ud_av_l_key_ctl)
		| EHCA_BMASK_SET(H_ALL_RES_QP_RESOURCE_TYPE, 1);

	max_r10_reg =
		EHCA_BMASK_SET(H_ALL_RES_QP_MAX_OUTST_SEND_WR,
			       max_nr_send_wqes)
		| EHCA_BMASK_SET(H_ALL_RES_QP_MAX_OUTST_RECV_WR,
				 max_nr_receive_wqes)
		| EHCA_BMASK_SET(H_ALL_RES_QP_MAX_SEND_SGE,
				 parms->max_send_sge)
		| EHCA_BMASK_SET(H_ALL_RES_QP_MAX_RECV_SGE,
				 parms->max_recv_sge);


	ret = ehca_hcall_9arg_9ret(H_ALLOC_RESOURCE,
				   adapter_handle.handle,	      /* r4  */
				   allocate_controls,	              /* r5  */
				   qp->send_cq->ipz_cq_handle.handle,
				   qp->recv_cq->ipz_cq_handle.handle,
				   parms->ipz_eq_handle.handle,
				   ((u64)qp->token << 32) | parms->pd.value,
				   max_r10_reg,	                      /* r10 */
				   parms->ud_av_l_key_ctl,            /* r11 */
				   0,
				   &qp->ipz_qp_handle.handle,
				   &qp_nr_out,	                      /* r5  */
				   &r6_out,	                      /* r6  */
				   &r7_out,	                      /* r7  */
				   &r8_out,	                      /* r8  */
				   &dummy,	                      /* r9  */
				   &g_la_user_out,	              /* r10 */
				   &r11_out,
				   &dummy);

	/* extract outputs */
	qp->real_qp_num = (u32)qp_nr_out;

	parms->act_nr_send_sges =
		(u16)EHCA_BMASK_GET(H_ALL_RES_QP_ACT_OUTST_SEND_WR, r6_out);
	parms->act_nr_recv_wqes =
		(u16)EHCA_BMASK_GET(H_ALL_RES_QP_ACT_OUTST_RECV_WR, r6_out);
	parms->act_nr_send_sges =
		(u8)EHCA_BMASK_GET(H_ALL_RES_QP_ACT_SEND_SGE, r7_out);
	parms->act_nr_recv_sges =
		(u8)EHCA_BMASK_GET(H_ALL_RES_QP_ACT_RECV_SGE, r7_out);
	parms->nr_sq_pages =
		(u32)EHCA_BMASK_GET(H_ALL_RES_QP_SQUEUE_SIZE_PAGES, r8_out);
	parms->nr_rq_pages =
		(u32)EHCA_BMASK_GET(H_ALL_RES_QP_RQUEUE_SIZE_PAGES, r8_out);

	if (ret == H_SUCCESS)
		hcp_galpas_ctor(&qp->galpas, g_la_user_out, g_la_user_out);

	if (ret == H_NOT_ENOUGH_RESOURCES)
		ehca_gen_err("Not enough resources. ret=%lx",ret);

	return ret;
}

u64 hipz_h_query_port(const struct ipz_adapter_handle adapter_handle,
		      const u8 port_id,
		      struct hipz_query_port *query_port_response_block)
{
	u64 ret;
	u64 dummy;
	u64 r_cb = virt_to_abs(query_port_response_block);

	if (r_cb & (EHCA_PAGESIZE-1)) {
		ehca_gen_err("response block not page aligned");
		return H_PARAMETER;
	}

	ret = ehca_hcall_7arg_7ret(H_QUERY_PORT,
				   adapter_handle.handle, /* r4 */
				   port_id,	          /* r5 */
				   r_cb,	          /* r6 */
				   0, 0, 0, 0,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy);

	if (ehca_debug_level)
		ehca_dmp(query_port_response_block, 64, "response_block");

	return ret;
}

u64 hipz_h_query_hca(const struct ipz_adapter_handle adapter_handle,
		     struct hipz_query_hca *query_hca_rblock)
{
	u64 dummy;
	u64 r_cb = virt_to_abs(query_hca_rblock);

	if (r_cb & (EHCA_PAGESIZE-1)) {
		ehca_gen_err("response_block=%p not page aligned",
			     query_hca_rblock);
		return H_PARAMETER;
	}

	return ehca_hcall_7arg_7ret(H_QUERY_HCA,
				    adapter_handle.handle, /* r4 */
				    r_cb,                  /* r5 */
				    0, 0, 0, 0, 0,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy);
}

u64 hipz_h_register_rpage(const struct ipz_adapter_handle adapter_handle,
			  const u8 pagesize,
			  const u8 queue_type,
			  const u64 resource_handle,
			  const u64 logical_address_of_page,
			  u64 count)
{
	u64 dummy;

	return ehca_hcall_7arg_7ret(H_REGISTER_RPAGES,
				    adapter_handle.handle,      /* r4  */
				    queue_type | pagesize << 8, /* r5  */
				    resource_handle,	        /* r6  */
				    logical_address_of_page,    /* r7  */
				    count,	                /* r8  */
				    0, 0,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy);
}

u64 hipz_h_register_rpage_eq(const struct ipz_adapter_handle adapter_handle,
			     const struct ipz_eq_handle eq_handle,
			     struct ehca_pfeq *pfeq,
			     const u8 pagesize,
			     const u8 queue_type,
			     const u64 logical_address_of_page,
			     const u64 count)
{
	if (count != 1) {
		ehca_gen_err("Ppage counter=%lx", count);
		return H_PARAMETER;
	}
	return hipz_h_register_rpage(adapter_handle,
				     pagesize,
				     queue_type,
				     eq_handle.handle,
				     logical_address_of_page, count);
}

u32 hipz_h_query_int_state(const struct ipz_adapter_handle adapter_handle,
			   u32 ist)
{
	u32 ret;
	u64 dummy;

	ret = ehca_hcall_7arg_7ret(H_QUERY_INT_STATE,
				   adapter_handle.handle, /* r4 */
				   ist,                   /* r5 */
				   0, 0, 0, 0, 0,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy);

	if (ret != H_SUCCESS && ret != H_BUSY)
		ehca_gen_err("Could not query interrupt state.");

	return ret;
}

u64 hipz_h_register_rpage_cq(const struct ipz_adapter_handle adapter_handle,
			     const struct ipz_cq_handle cq_handle,
			     struct ehca_pfcq *pfcq,
			     const u8 pagesize,
			     const u8 queue_type,
			     const u64 logical_address_of_page,
			     const u64 count,
			     const struct h_galpa gal)
{
	if (count != 1) {
		ehca_gen_err("Page counter=%lx", count);
		return H_PARAMETER;
	}

	return hipz_h_register_rpage(adapter_handle, pagesize, queue_type,
				     cq_handle.handle, logical_address_of_page,
				     count);
}

u64 hipz_h_register_rpage_qp(const struct ipz_adapter_handle adapter_handle,
			     const struct ipz_qp_handle qp_handle,
			     struct ehca_pfqp *pfqp,
			     const u8 pagesize,
			     const u8 queue_type,
			     const u64 logical_address_of_page,
			     const u64 count,
			     const struct h_galpa galpa)
{
	if (count != 1) {
		ehca_gen_err("Page counter=%lx", count);
		return H_PARAMETER;
	}

	return hipz_h_register_rpage(adapter_handle,pagesize,queue_type,
				     qp_handle.handle,logical_address_of_page,
				     count);
}

u64 hipz_h_disable_and_get_wqe(const struct ipz_adapter_handle adapter_handle,
			       const struct ipz_qp_handle qp_handle,
			       struct ehca_pfqp *pfqp,
			       void **log_addr_next_sq_wqe2processed,
			       void **log_addr_next_rq_wqe2processed,
			       int dis_and_get_function_code)
{
	u64 dummy, dummy1, dummy2;

	if (!log_addr_next_sq_wqe2processed)
		log_addr_next_sq_wqe2processed = (void**)&dummy1;
	if (!log_addr_next_rq_wqe2processed)
		log_addr_next_rq_wqe2processed = (void**)&dummy2;

	return ehca_hcall_7arg_7ret(H_DISABLE_AND_GETC,
				    adapter_handle.handle,     /* r4 */
				    dis_and_get_function_code, /* r5 */
				    qp_handle.handle,	       /* r6 */
				    0, 0, 0, 0,
				    (void*)log_addr_next_sq_wqe2processed,
				    (void*)log_addr_next_rq_wqe2processed,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy);
}

u64 hipz_h_modify_qp(const struct ipz_adapter_handle adapter_handle,
		     const struct ipz_qp_handle qp_handle,
		     struct ehca_pfqp *pfqp,
		     const u64 update_mask,
		     struct hcp_modify_qp_control_block *mqpcb,
		     struct h_galpa gal)
{
	u64 ret;
	u64 dummy;
	u64 invalid_attribute_identifier, rc_attrib_mask;

	ret = ehca_hcall_7arg_7ret(H_MODIFY_QP,
				   adapter_handle.handle,         /* r4 */
				   qp_handle.handle,	          /* r5 */
				   update_mask,	                  /* r6 */
				   virt_to_abs(mqpcb),	          /* r7 */
				   0, 0, 0,
				   &invalid_attribute_identifier, /* r4 */
				   &dummy,	                  /* r5 */
				   &dummy,	                  /* r6 */
				   &dummy,                        /* r7 */
				   &dummy,	                  /* r8 */
				   &rc_attrib_mask,               /* r9 */
				   &dummy);

	if (ret == H_NOT_ENOUGH_RESOURCES)
		ehca_gen_err("Insufficient resources ret=%lx", ret);

	return ret;
}

u64 hipz_h_query_qp(const struct ipz_adapter_handle adapter_handle,
		    const struct ipz_qp_handle qp_handle,
		    struct ehca_pfqp *pfqp,
		    struct hcp_modify_qp_control_block *qqpcb,
		    struct h_galpa gal)
{
	u64 dummy;

	return ehca_hcall_7arg_7ret(H_QUERY_QP,
				    adapter_handle.handle, /* r4 */
				    qp_handle.handle,      /* r5 */
				    virt_to_abs(qqpcb),	   /* r6 */
				    0, 0, 0, 0,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy);
}

u64 hipz_h_destroy_qp(const struct ipz_adapter_handle adapter_handle,
		      struct ehca_qp *qp)
{
	u64 ret;
	u64 dummy;
	u64 ladr_next_sq_wqe_out, ladr_next_rq_wqe_out;

	ret = hcp_galpas_dtor(&qp->galpas);
	if (ret) {
		ehca_gen_err("Could not destruct qp->galpas");
		return H_RESOURCE;
	}
	ret = ehca_hcall_7arg_7ret(H_DISABLE_AND_GETC,
				   adapter_handle.handle,     /* r4 */
				   /* function code */
				   1,	                      /* r5 */
				   qp->ipz_qp_handle.handle,  /* r6 */
				   0, 0, 0, 0,
				   &ladr_next_sq_wqe_out,     /* r4 */
				   &ladr_next_rq_wqe_out,     /* r5 */
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy);
	if (ret == H_HARDWARE)
		ehca_gen_err("HCA not operational. ret=%lx", ret);

	ret = ehca_hcall_7arg_7ret(H_FREE_RESOURCE,
				   adapter_handle.handle,     /* r4 */
				   qp->ipz_qp_handle.handle,  /* r5 */
				   0, 0, 0, 0, 0,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy);

	if (ret == H_RESOURCE)
		ehca_gen_err("Resource still in use. ret=%lx", ret);

	return ret;
}

u64 hipz_h_define_aqp0(const struct ipz_adapter_handle adapter_handle,
		       const struct ipz_qp_handle qp_handle,
		       struct h_galpa gal,
		       u32 port)
{
	u64 dummy;

	return ehca_hcall_7arg_7ret(H_DEFINE_AQP0,
				    adapter_handle.handle, /* r4 */
				    qp_handle.handle,      /* r5 */
				    port,                  /* r6 */
				    0, 0, 0, 0,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy);
}

u64 hipz_h_define_aqp1(const struct ipz_adapter_handle adapter_handle,
		       const struct ipz_qp_handle qp_handle,
		       struct h_galpa gal,
		       u32 port, u32 * pma_qp_nr,
		       u32 * bma_qp_nr)
{
	u64 ret;
	u64 dummy;
	u64 pma_qp_nr_out, bma_qp_nr_out;

	ret = ehca_hcall_7arg_7ret(H_DEFINE_AQP1,
				   adapter_handle.handle, /* r4 */
				   qp_handle.handle,      /* r5 */
				   port,	          /* r6 */
				   0, 0, 0, 0,
				   &pma_qp_nr_out,        /* r4 */
				   &bma_qp_nr_out,        /* r5 */
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy);

	*pma_qp_nr = (u32)pma_qp_nr_out;
	*bma_qp_nr = (u32)bma_qp_nr_out;

	if (ret == H_ALIAS_EXIST)
		ehca_gen_err("AQP1 already exists. ret=%lx", ret);

	return ret;
}

u64 hipz_h_attach_mcqp(const struct ipz_adapter_handle adapter_handle,
		       const struct ipz_qp_handle qp_handle,
		       struct h_galpa gal,
		       u16 mcg_dlid,
		       u64 subnet_prefix, u64 interface_id)
{
	u64 ret;
	u64 dummy;

	ret = ehca_hcall_7arg_7ret(H_ATTACH_MCQP,
				   adapter_handle.handle,     /* r4 */
				   qp_handle.handle,          /* r5 */
				   mcg_dlid,                  /* r6 */
				   interface_id,              /* r7 */
				   subnet_prefix,             /* r8 */
				   0, 0,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy);

	if (ret == H_NOT_ENOUGH_RESOURCES)
		ehca_gen_err("Not enough resources. ret=%lx", ret);

	return ret;
}

u64 hipz_h_detach_mcqp(const struct ipz_adapter_handle adapter_handle,
		       const struct ipz_qp_handle qp_handle,
		       struct h_galpa gal,
		       u16 mcg_dlid,
		       u64 subnet_prefix, u64 interface_id)
{
	u64 dummy;

	return ehca_hcall_7arg_7ret(H_DETACH_MCQP,
				    adapter_handle.handle, /* r4 */
				    qp_handle.handle,	   /* r5 */
				    mcg_dlid,	           /* r6 */
				    interface_id,          /* r7 */
				    subnet_prefix,         /* r8 */
				    0, 0,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy);
}

u64 hipz_h_destroy_cq(const struct ipz_adapter_handle adapter_handle,
		      struct ehca_cq *cq,
		      u8 force_flag)
{
	u64 ret;
	u64 dummy;

	ret = hcp_galpas_dtor(&cq->galpas);
	if (ret) {
		ehca_gen_err("Could not destruct cp->galpas");
		return H_RESOURCE;
	}

	ret = ehca_hcall_7arg_7ret(H_FREE_RESOURCE,
				   adapter_handle.handle,     /* r4 */
				   cq->ipz_cq_handle.handle,  /* r5 */
				   force_flag != 0 ? 1L : 0L, /* r6 */
				   0, 0, 0, 0,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy);

	if (ret == H_RESOURCE)
		ehca_gen_err("H_FREE_RESOURCE failed ret=%lx ", ret);

	return ret;
}

u64 hipz_h_destroy_eq(const struct ipz_adapter_handle adapter_handle,
		      struct ehca_eq *eq)
{
	u64 ret;
	u64 dummy;

	ret = hcp_galpas_dtor(&eq->galpas);
	if (ret) {
		ehca_gen_err("Could not destruct eq->galpas");
		return H_RESOURCE;
	}

	ret = ehca_hcall_7arg_7ret(H_FREE_RESOURCE,
				   adapter_handle.handle,     /* r4 */
				   eq->ipz_eq_handle.handle,  /* r5 */
				   0, 0, 0, 0, 0,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy,
				   &dummy);


	if (ret == H_RESOURCE)
		ehca_gen_err("Resource in use. ret=%lx ", ret);

	return ret;
}

u64 hipz_h_alloc_resource_mr(const struct ipz_adapter_handle adapter_handle,
			     const struct ehca_mr *mr,
			     const u64 vaddr,
			     const u64 length,
			     const u32 access_ctrl,
			     const struct ipz_pd pd,
			     struct ehca_mr_hipzout_parms *outparms)
{
	u64 ret;
	u64 dummy;
	u64 lkey_out;
	u64 rkey_out;

	ret = ehca_hcall_7arg_7ret(H_ALLOC_RESOURCE,
				   adapter_handle.handle,            /* r4 */
				   5,                                /* r5 */
				   vaddr,                            /* r6 */
				   length,                           /* r7 */
				   (((u64)access_ctrl) << 32ULL),    /* r8 */
				   pd.value,                         /* r9 */
				   0,
				   &(outparms->handle.handle),       /* r4 */
				   &dummy,                           /* r5 */
				   &lkey_out,                        /* r6 */
				   &rkey_out,                        /* r7 */
				   &dummy,
				   &dummy,
				   &dummy);
	outparms->lkey = (u32)lkey_out;
	outparms->rkey = (u32)rkey_out;

	return ret;
}

u64 hipz_h_register_rpage_mr(const struct ipz_adapter_handle adapter_handle,
			     const struct ehca_mr *mr,
			     const u8 pagesize,
			     const u8 queue_type,
			     const u64 logical_address_of_page,
			     const u64 count)
{
	u64 ret;

	if ((count > 1) && (logical_address_of_page & (EHCA_PAGESIZE-1))) {
		ehca_gen_err("logical_address_of_page not on a 4k boundary "
			     "adapter_handle=%lx mr=%p mr_handle=%lx "
			     "pagesize=%x queue_type=%x "
			     "logical_address_of_page=%lx count=%lx",
			     adapter_handle.handle, mr,
			     mr->ipz_mr_handle.handle, pagesize, queue_type,
			     logical_address_of_page, count);
		ret = H_PARAMETER;
	} else
		ret = hipz_h_register_rpage(adapter_handle, pagesize,
					    queue_type,
					    mr->ipz_mr_handle.handle,
					    logical_address_of_page, count);

	return ret;
}

u64 hipz_h_query_mr(const struct ipz_adapter_handle adapter_handle,
		    const struct ehca_mr *mr,
		    struct ehca_mr_hipzout_parms *outparms)
{
	u64 ret;
	u64 dummy;
	u64 remote_len_out, remote_vaddr_out, acc_ctrl_pd_out, r9_out;

	ret = ehca_hcall_7arg_7ret(H_QUERY_MR,
				   adapter_handle.handle,     /* r4 */
				   mr->ipz_mr_handle.handle,  /* r5 */
				   0, 0, 0, 0, 0,
				   &outparms->len,            /* r4 */
				   &outparms->vaddr,          /* r5 */
				   &remote_len_out,           /* r6 */
				   &remote_vaddr_out,         /* r7 */
				   &acc_ctrl_pd_out,          /* r8 */
				   &r9_out,
				   &dummy);

	outparms->acl  = acc_ctrl_pd_out >> 32;
	outparms->lkey = (u32)(r9_out >> 32);
	outparms->rkey = (u32)(r9_out & (0xffffffff));

	return ret;
}

u64 hipz_h_free_resource_mr(const struct ipz_adapter_handle adapter_handle,
			    const struct ehca_mr *mr)
{
	u64 dummy;

	return ehca_hcall_7arg_7ret(H_FREE_RESOURCE,
				    adapter_handle.handle,    /* r4 */
				    mr->ipz_mr_handle.handle, /* r5 */
				    0, 0, 0, 0, 0,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy);
}

u64 hipz_h_reregister_pmr(const struct ipz_adapter_handle adapter_handle,
			  const struct ehca_mr *mr,
			  const u64 vaddr_in,
			  const u64 length,
			  const u32 access_ctrl,
			  const struct ipz_pd pd,
			  const u64 mr_addr_cb,
			  struct ehca_mr_hipzout_parms *outparms)
{
	u64 ret;
	u64 dummy;
	u64 lkey_out, rkey_out;

	ret = ehca_hcall_7arg_7ret(H_REREGISTER_PMR,
				   adapter_handle.handle,    /* r4 */
				   mr->ipz_mr_handle.handle, /* r5 */
				   vaddr_in,	             /* r6 */
				   length,                   /* r7 */
				   /* r8 */
				   ((((u64)access_ctrl) << 32ULL) | pd.value),
				   mr_addr_cb,               /* r9 */
				   0,
				   &dummy,                   /* r4 */
				   &outparms->vaddr,         /* r5 */
				   &lkey_out,                /* r6 */
				   &rkey_out,                /* r7 */
				   &dummy,
				   &dummy,
				   &dummy);

	outparms->lkey = (u32)lkey_out;
	outparms->rkey = (u32)rkey_out;

	return ret;
}

u64 hipz_h_register_smr(const struct ipz_adapter_handle adapter_handle,
			const struct ehca_mr *mr,
			const struct ehca_mr *orig_mr,
			const u64 vaddr_in,
			const u32 access_ctrl,
			const struct ipz_pd pd,
			struct ehca_mr_hipzout_parms *outparms)
{
	u64 ret;
	u64 dummy;
	u64 lkey_out, rkey_out;

	ret = ehca_hcall_7arg_7ret(H_REGISTER_SMR,
				   adapter_handle.handle,            /* r4 */
				   orig_mr->ipz_mr_handle.handle,    /* r5 */
				   vaddr_in,                         /* r6 */
				   (((u64)access_ctrl) << 32ULL),    /* r7 */
				   pd.value,                         /* r8 */
				   0, 0,
				   &(outparms->handle.handle),       /* r4 */
				   &dummy,                           /* r5 */
				   &lkey_out,                        /* r6 */
				   &rkey_out,                        /* r7 */
				   &dummy,
				   &dummy,
				   &dummy);
	outparms->lkey = (u32)lkey_out;
	outparms->rkey = (u32)rkey_out;

	return ret;
}

u64 hipz_h_alloc_resource_mw(const struct ipz_adapter_handle adapter_handle,
			     const struct ehca_mw *mw,
			     const struct ipz_pd pd,
			     struct ehca_mw_hipzout_parms *outparms)
{
	u64 ret;
	u64 dummy;
	u64 rkey_out;

	ret = ehca_hcall_7arg_7ret(H_ALLOC_RESOURCE,
				   adapter_handle.handle,      /* r4 */
				   6,                          /* r5 */
				   pd.value,                   /* r6 */
				   0, 0, 0, 0,
				   &(outparms->handle.handle), /* r4 */
				   &dummy,                     /* r5 */
				   &dummy,                     /* r6 */
				   &rkey_out,                  /* r7 */
				   &dummy,
				   &dummy,
				   &dummy);

	outparms->rkey = (u32)rkey_out;

	return ret;
}

u64 hipz_h_query_mw(const struct ipz_adapter_handle adapter_handle,
		    const struct ehca_mw *mw,
		    struct ehca_mw_hipzout_parms *outparms)
{
	u64 ret;
	u64 dummy;
	u64 pd_out, rkey_out;

	ret = ehca_hcall_7arg_7ret(H_QUERY_MW,
				   adapter_handle.handle,    /* r4 */
				   mw->ipz_mw_handle.handle, /* r5 */
				   0, 0, 0, 0, 0,
				   &dummy,                   /* r4 */
				   &dummy,                   /* r5 */
				   &dummy,                   /* r6 */
				   &rkey_out,                /* r7 */
				   &pd_out,                  /* r8 */
				   &dummy,
				   &dummy);
	outparms->rkey = (u32)rkey_out;

	return ret;
}

u64 hipz_h_free_resource_mw(const struct ipz_adapter_handle adapter_handle,
			    const struct ehca_mw *mw)
{
	u64 dummy;

	return ehca_hcall_7arg_7ret(H_FREE_RESOURCE,
				    adapter_handle.handle,    /* r4 */
				    mw->ipz_mw_handle.handle, /* r5 */
				    0, 0, 0, 0, 0,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy);
}

u64 hipz_h_error_data(const struct ipz_adapter_handle adapter_handle,
		      const u64 ressource_handle,
		      void *rblock,
		      unsigned long *byte_count)
{
	u64 dummy;
	u64 r_cb = virt_to_abs(rblock);

	if (r_cb & (EHCA_PAGESIZE-1)) {
		ehca_gen_err("rblock not page aligned.");
		return H_PARAMETER;
	}

	return ehca_hcall_7arg_7ret(H_ERROR_DATA,
				    adapter_handle.handle,
				    ressource_handle,
				    r_cb,
				    0, 0, 0, 0,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy,
				    &dummy);
}

/*
 *  IBM eServer eHCA Infiniband device driver for Linux on POWER
 *
 *  module start stop, hca detection
 *
 *  Authors: Heiko J Schick <schickhj@de.ibm.com>
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

#define DEB_PREFIX "shca"

#include "ehca_classes.h"
#include "ehca_iverbs.h"
#include "ehca_mrmw.h"
#include "ehca_tools.h"
#include "hcp_if.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Christoph Raisch <raisch@de.ibm.com>");
MODULE_DESCRIPTION("IBM eServer HCA InfiniBand Device Driver");
MODULE_VERSION("SVNEHCA_0006");

struct ehca_comp_pool* ehca_pool;

int ehca_open_aqp1     = 0;
int ehca_debug_level   = -1;
int ehca_hw_level      = 0;
int ehca_nr_ports      = 2;
int ehca_use_hp_mr     = 0;
int ehca_port_act_time = 30;
int ehca_poll_all_eqs  = 1;
int ehca_static_rate   = -1;

module_param_named(open_aqp1,     ehca_open_aqp1,     int, 0);
module_param_named(debug_level,   ehca_debug_level,   int, 0);
module_param_named(hw_level,      ehca_hw_level,      int, 0);
module_param_named(nr_ports,      ehca_nr_ports,      int, 0);
module_param_named(use_hp_mr,     ehca_use_hp_mr,     int, 0);
module_param_named(port_act_time, ehca_port_act_time, int, 0);
module_param_named(poll_all_eqs,  ehca_poll_all_eqs,  int, 0);
module_param_named(static_rate,   ehca_static_rate,   int, 0);

MODULE_PARM_DESC(open_aqp1,
		 "AQP1 on startup (0: no (default), 1: yes)");
MODULE_PARM_DESC(debug_level,
		 "debug level"
		 " (0: node, 6: only errors (default), 9: all)");
MODULE_PARM_DESC(hw_level,
		 "hardware level"
		 " (0: autosensing (default), 1: v. 0.20, 2: v. 0.21)");
MODULE_PARM_DESC(nr_ports,
		 "number of connected ports (default: 2)");
MODULE_PARM_DESC(use_hp_mr,
		 "high performance MRs (0: no (default), 1: yes)");
MODULE_PARM_DESC(port_act_time,
		 "time to wait for port activation (default: 30 sec)");
MODULE_PARM_DESC(poll_all_eqs,
		 "polls all event queues periodically"
		 " (0: no, 1: yes (default))");
MODULE_PARM_DESC(static_rate,
		 "set permanent static rate (default: disabled)");

/* This external trace mask controls what will end up in the
 * kernel ring buffer. Number 6 means, that everything between
 * 0 and 5 will be stored.
 */
u8 ehca_edeb_mask[EHCA_EDEB_TRACE_MASK_SIZE]={6, 6, 6, 6,
					      6, 6, 6, 6,
					      6, 6, 6, 6,
					      6, 6, 6, 6,
					      6, 6, 6, 6,
					      6, 6, 6, 6,
					      6, 6, 6, 6,
					      6, 6, 0, 0};

spinlock_t ehca_qp_idr_lock;
spinlock_t ehca_cq_idr_lock;
DEFINE_IDR(ehca_qp_idr);
DEFINE_IDR(ehca_cq_idr);

struct ehca_module ehca_module;

void ehca_init_trace(void)
{
	EDEB_EN(7, "");

	if (ehca_debug_level != -1) {
		int i;
		for (i = 0; i < EHCA_EDEB_TRACE_MASK_SIZE; i++)
			ehca_edeb_mask[i] = ehca_debug_level;
	}

	EDEB_EX(7, "");
}

int ehca_create_slab_caches(struct ehca_module *ehca_module)
{
	int ret = 0;

	EDEB_EN(7, "");

	ehca_module->cache_pd =
		kmem_cache_create("ehca_cache_pd",
				  sizeof(struct ehca_pd),
				  0, SLAB_HWCACHE_ALIGN,
				  NULL, NULL);
	if (!ehca_module->cache_pd) {
		EDEB_ERR(4, "Cannot create PD SLAB cache.");
		ret = -ENOMEM;
		goto create_slab_caches1;
	}

	ehca_module->cache_cq =
		kmem_cache_create("ehca_cache_cq",
				  sizeof(struct ehca_cq),
				  0, SLAB_HWCACHE_ALIGN,
				  NULL, NULL);
	if (!ehca_module->cache_cq) {
		EDEB_ERR(4, "Cannot create CQ SLAB cache.");
		ret = -ENOMEM;
		goto create_slab_caches2;
	}

	ehca_module->cache_qp =
		kmem_cache_create("ehca_cache_qp",
				  sizeof(struct ehca_qp),
				  0, SLAB_HWCACHE_ALIGN,
				  NULL, NULL);
	if (!ehca_module->cache_qp) {
		EDEB_ERR(4, "Cannot create QP SLAB cache.");
		ret = -ENOMEM;
		goto create_slab_caches3;
	}

	ehca_module->cache_av =
		kmem_cache_create("ehca_cache_av",
				  sizeof(struct ehca_av),
				  0, SLAB_HWCACHE_ALIGN,
				  NULL, NULL);
	if (!ehca_module->cache_av) {
		EDEB_ERR(4, "Cannot create AV SLAB cache.");
		ret = -ENOMEM;
		goto create_slab_caches4;
	}

	ehca_module->cache_mw =
		kmem_cache_create("ehca_cache_mw",
				  sizeof(struct ehca_mw),
				  0, SLAB_HWCACHE_ALIGN,
				  NULL, NULL);
	if (!ehca_module->cache_mw) {
		EDEB_ERR(4, "Cannot create MW SLAB cache.");
		ret = -ENOMEM;
		goto create_slab_caches5;
	}

	ehca_module->cache_mr =
		kmem_cache_create("ehca_cache_mr",
				  sizeof(struct ehca_mr),
				  0, SLAB_HWCACHE_ALIGN,
				  NULL, NULL);
	if (!ehca_module->cache_mr) {
		EDEB_ERR(4, "Cannot create MR SLAB cache.");
		ret = -ENOMEM;
		goto create_slab_caches6;
	}

	EDEB_EX(7, "ret=%x", ret);

	return ret;

create_slab_caches6:
	kmem_cache_destroy(ehca_module->cache_mw);

create_slab_caches5:
	kmem_cache_destroy(ehca_module->cache_av);

create_slab_caches4:
	kmem_cache_destroy(ehca_module->cache_qp);

create_slab_caches3:
	kmem_cache_destroy(ehca_module->cache_cq);

create_slab_caches2:
	kmem_cache_destroy(ehca_module->cache_pd);

create_slab_caches1:
	EDEB_EX(7, "ret=%x", ret);

	return ret;
}

int ehca_destroy_slab_caches(struct ehca_module *ehca_module)
{
	int ret;

	EDEB_EN(7, "");

	ret = kmem_cache_destroy(ehca_module->cache_pd);
	if (ret)
		EDEB_ERR(4, "Cannot destroy PD SLAB cache. ret=%x", ret);

	ret = kmem_cache_destroy(ehca_module->cache_cq);
	if (ret)
		EDEB_ERR(4, "Cannot destroy CQ SLAB cache. ret=%x", ret);

	ret = kmem_cache_destroy(ehca_module->cache_qp);
	if (ret)
		EDEB_ERR(4, "Cannot destroy QP SLAB cache. ret=%x", ret);

	ret = kmem_cache_destroy(ehca_module->cache_av);
	if (ret)
		EDEB_ERR(4, "Cannot destroy AV SLAB cache. ret=%x", ret);

	ret = kmem_cache_destroy(ehca_module->cache_mw);
	if (ret)
		EDEB_ERR(4, "Cannot destroy MW SLAB cache. ret=%x", ret);

	ret = kmem_cache_destroy(ehca_module->cache_mr);
	if (ret)
		EDEB_ERR(4, "Cannot destroy MR SLAB cache. ret=%x", ret);

	EDEB_EX(7, "");

	return 0;
}

#define EHCA_HCAAVER  EHCA_BMASK_IBM(32,39)
#define EHCA_REVID    EHCA_BMASK_IBM(40,63)

int ehca_sense_attributes(struct ehca_shca *shca)
{
	int ret = -EINVAL;
	u64 h_ret = H_SUCCESS;
	struct hipz_query_hca *rblock;

	EDEB_EN(7, "shca=%p", shca);

	rblock = kzalloc(H_CB_ALIGNMENT, GFP_KERNEL);
	if (!rblock) {
		EDEB_ERR(4, "Cannot allocate rblock memory.");
		ret = -ENOMEM;
		goto num_ports0;
	}

	h_ret = hipz_h_query_hca(shca->ipz_hca_handle, rblock);
	if (h_ret != H_SUCCESS) {
		EDEB_ERR(4, "Cannot query device properties. h_ret=%lx", h_ret);
		ret = -EPERM;
		goto num_ports1;
	}

	if (ehca_nr_ports == 1)
		shca->num_ports = 1;
	else
		shca->num_ports = (u8)rblock->num_ports;

	EDEB(6, " ... found %x ports", rblock->num_ports);

	if (ehca_hw_level == 0) {
		u32 hcaaver;
		u32 revid;

		hcaaver = EHCA_BMASK_GET(EHCA_HCAAVER, rblock->hw_ver);
		revid   = EHCA_BMASK_GET(EHCA_REVID, rblock->hw_ver);

		EDEB(6, " ... hardware version=%x:%x",
		     hcaaver, revid);

		if ((hcaaver == 1) && (revid == 0))
			shca->hw_level = 0;
		else if ((hcaaver == 1) && (revid == 1))
			shca->hw_level = 1;
		else if ((hcaaver == 1) && (revid == 2))
			shca->hw_level = 2;
	}
	EDEB(6, " ... hardware level=%x", shca->hw_level);

	shca->sport[0].rate = IB_RATE_30_GBPS;
	shca->sport[1].rate = IB_RATE_30_GBPS;

	ret = 0;

num_ports1:
	kfree(rblock);

num_ports0:
	EDEB_EX(7, "ret=%x", ret);

	return ret;
}

static int init_node_guid(struct ehca_shca* shca)
{
	int ret = 0;
	struct hipz_query_hca *rblock;

	EDEB_EN(7, "");

	rblock = kzalloc(H_CB_ALIGNMENT, GFP_KERNEL);
	if (!rblock) {
		EDEB_ERR(4, "Can't allocate rblock memory.");
		ret = -ENOMEM;
		goto init_node_guid0;
	}

	if (hipz_h_query_hca(shca->ipz_hca_handle, rblock) != H_SUCCESS) {
		EDEB_ERR(4, "Can't query device properties");
		ret = -EINVAL;
		goto init_node_guid1;
	}

	memcpy(&shca->ib_device.node_guid, &rblock->node_guid, (sizeof(u64)));

init_node_guid1:
	kfree(rblock);

init_node_guid0:
	EDEB_EX(7, "node_guid=%lx ret=%x", shca->ib_device.node_guid, ret);

	return ret;
}

int ehca_register_device(struct ehca_shca *shca)
{
	int ret = 0;

	EDEB_EN(7, "shca=%p", shca);

	ret = init_node_guid(shca);
	if (ret)
		return ret;

	strlcpy(shca->ib_device.name, "ehca%d", IB_DEVICE_NAME_MAX);
	shca->ib_device.owner               = THIS_MODULE;

	shca->ib_device.uverbs_abi_ver	    = 5;
	shca->ib_device.uverbs_cmd_mask	    =
		(1ull << IB_USER_VERBS_CMD_GET_CONTEXT)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE)	|
		(1ull << IB_USER_VERBS_CMD_QUERY_PORT)		|
		(1ull << IB_USER_VERBS_CMD_ALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_DEALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_REG_MR)		|
		(1ull << IB_USER_VERBS_CMD_DEREG_MR)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL)	|
		(1ull << IB_USER_VERBS_CMD_CREATE_CQ)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_CQ)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_QP)		|
		(1ull << IB_USER_VERBS_CMD_MODIFY_QP)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_QP)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_QP)		|
		(1ull << IB_USER_VERBS_CMD_ATTACH_MCAST)	|
		(1ull << IB_USER_VERBS_CMD_DETACH_MCAST);

	shca->ib_device.node_type           = RDMA_NODE_IB_CA;
	shca->ib_device.phys_port_cnt       = shca->num_ports;
	shca->ib_device.dma_device          = &shca->ibmebus_dev->ofdev.dev;
	shca->ib_device.query_device        = ehca_query_device;
	shca->ib_device.query_port          = ehca_query_port;
	shca->ib_device.query_gid           = ehca_query_gid;
	shca->ib_device.query_pkey          = ehca_query_pkey;
	/* shca->in_device.modify_device    = ehca_modify_device    */
	shca->ib_device.modify_port         = ehca_modify_port;
	shca->ib_device.alloc_ucontext      = ehca_alloc_ucontext;
	shca->ib_device.dealloc_ucontext    = ehca_dealloc_ucontext;
	shca->ib_device.alloc_pd            = ehca_alloc_pd;
	shca->ib_device.dealloc_pd          = ehca_dealloc_pd;
	shca->ib_device.create_ah	    = ehca_create_ah;
	/* shca->ib_device.modify_ah	    = ehca_modify_ah;	    */
	shca->ib_device.query_ah	    = ehca_query_ah;
	shca->ib_device.destroy_ah	    = ehca_destroy_ah;
	shca->ib_device.create_qp	    = ehca_create_qp;
	shca->ib_device.modify_qp	    = ehca_modify_qp;
	shca->ib_device.query_qp	    = ehca_query_qp;
	shca->ib_device.destroy_qp	    = ehca_destroy_qp;
	shca->ib_device.post_send	    = ehca_post_send;
	shca->ib_device.post_recv	    = ehca_post_recv;
	shca->ib_device.create_cq	    = ehca_create_cq;
	shca->ib_device.destroy_cq	    = ehca_destroy_cq;
	shca->ib_device.resize_cq	    = ehca_resize_cq;
	shca->ib_device.poll_cq		    = ehca_poll_cq;
	/* shca->ib_device.peek_cq	    = ehca_peek_cq;	    */
	shca->ib_device.req_notify_cq	    = ehca_req_notify_cq;
	/* shca->ib_device.req_ncomp_notif  = ehca_req_ncomp_notif; */
	shca->ib_device.get_dma_mr	    = ehca_get_dma_mr;
	shca->ib_device.reg_phys_mr	    = ehca_reg_phys_mr;
	shca->ib_device.reg_user_mr	    = ehca_reg_user_mr;
	shca->ib_device.query_mr	    = ehca_query_mr;
	shca->ib_device.dereg_mr	    = ehca_dereg_mr;
	shca->ib_device.rereg_phys_mr	    = ehca_rereg_phys_mr;
	shca->ib_device.alloc_mw	    = ehca_alloc_mw;
	shca->ib_device.bind_mw		    = ehca_bind_mw;
	shca->ib_device.dealloc_mw	    = ehca_dealloc_mw;
	shca->ib_device.alloc_fmr	    = ehca_alloc_fmr;
	shca->ib_device.map_phys_fmr	    = ehca_map_phys_fmr;
	shca->ib_device.unmap_fmr	    = ehca_unmap_fmr;
	shca->ib_device.dealloc_fmr	    = ehca_dealloc_fmr;
	shca->ib_device.attach_mcast	    = ehca_attach_mcast;
	shca->ib_device.detach_mcast	    = ehca_detach_mcast;
	/* shca->ib_device.process_mad	    = ehca_process_mad;	    */
	shca->ib_device.mmap		    = ehca_mmap;

	ret = ib_register_device(&shca->ib_device);

	EDEB_EX(7, "ret=%x", ret);

	return ret;
}

static int ehca_create_aqp1(struct ehca_shca *shca, u32 port)
{
	struct ehca_sport *sport;
	struct ib_cq *ibcq;
	struct ib_qp *ibqp;
	struct ib_qp_init_attr qp_init_attr;
	int ret = 0;

	EDEB_EN(7, "shca=%p port=%x", shca, port);

	sport = &shca->sport[port - 1];

	if (sport->ibcq_aqp1) {
		EDEB_ERR(4, "AQP1 CQ is already created.");
		return -EPERM;
	}

	ibcq = ib_create_cq(&shca->ib_device, NULL, NULL, (void*)(-1), 10);
	if (IS_ERR(ibcq)) {
		EDEB_ERR(4, "Cannot create AQP1 CQ.");
		return PTR_ERR(ibcq);
	}
	sport->ibcq_aqp1 = ibcq;

	if (sport->ibqp_aqp1) {
		EDEB_ERR(4, "AQP1 QP is already created.");
		ret = -EPERM;
		goto create_aqp1;
	}

	memset(&qp_init_attr, 0, sizeof(struct ib_qp_init_attr));
	qp_init_attr.send_cq          = ibcq;
	qp_init_attr.recv_cq          = ibcq;
	qp_init_attr.sq_sig_type      = IB_SIGNAL_ALL_WR;
	qp_init_attr.cap.max_send_wr  = 100;
	qp_init_attr.cap.max_recv_wr  = 100;
	qp_init_attr.cap.max_send_sge = 2;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.qp_type          = IB_QPT_GSI;
	qp_init_attr.port_num         = port;
	qp_init_attr.qp_context       = NULL;
	qp_init_attr.event_handler    = NULL;
	qp_init_attr.srq              = NULL;

	ibqp = ib_create_qp(&shca->pd->ib_pd, &qp_init_attr);
	if (IS_ERR(ibqp)) {
		EDEB_ERR(4, "Cannot create AQP1 QP.");
		ret = PTR_ERR(ibqp);
		goto create_aqp1;
	}
	sport->ibqp_aqp1 = ibqp;

	EDEB_EX(7, "ret=%x", ret);

	return ret;

create_aqp1:
	ib_destroy_cq(sport->ibcq_aqp1);

	EDEB_EX(7, "ret=%x", ret);

	return ret;
}

static int ehca_destroy_aqp1(struct ehca_sport *sport)
{
	int ret = 0;

	EDEB_EN(7, "sport=%p", sport);

	ret = ib_destroy_qp(sport->ibqp_aqp1);
	if (ret) {
		EDEB_ERR(4, "Cannot destroy AQP1 QP. ret=%x", ret);
		goto destroy_aqp1;
	}

	ret = ib_destroy_cq(sport->ibcq_aqp1);
	if (ret)
		EDEB_ERR(4, "Cannot destroy AQP1 CQ. ret=%x", ret);

destroy_aqp1:
	EDEB_EX(7, "ret=%x", ret);

	return ret;
}

static ssize_t ehca_show_debug_mask(struct device_driver *ddp, char *buf)
{
	int i;
	int total = 0;
	total += snprintf(buf + total, PAGE_SIZE - total, "%d",
			  ehca_edeb_mask[0]);
	for (i = 1; i < EHCA_EDEB_TRACE_MASK_SIZE; i++) {
		total += snprintf(buf + total, PAGE_SIZE - total, "%d",
				  ehca_edeb_mask[i]);
	}

	total += snprintf(buf + total, PAGE_SIZE - total, "\n");

	return total;
}

static ssize_t ehca_store_debug_mask(struct device_driver *ddp,
				     const char *buf, size_t count)
{
	int i;
	for (i = 0; i < EHCA_EDEB_TRACE_MASK_SIZE; i++) {
		char value = buf[i] - '0';
		if ((value <= 9) && (count >= i)) {
			ehca_edeb_mask[i] = value;
		}
	}
	return count;
}
DRIVER_ATTR(debug_mask, S_IRUSR | S_IWUSR,
	    ehca_show_debug_mask, ehca_store_debug_mask);

void ehca_create_driver_sysfs(struct ibmebus_driver *drv)
{
	driver_create_file(&drv->driver, &driver_attr_debug_mask);
}

void ehca_remove_driver_sysfs(struct ibmebus_driver *drv)
{
	driver_remove_file(&drv->driver, &driver_attr_debug_mask);
}

#define EHCA_RESOURCE_ATTR(name)                                           \
static ssize_t  ehca_show_##name(struct device *dev,                       \
				 struct device_attribute *attr,            \
				 char *buf)                                \
{									   \
	struct ehca_shca *shca;						   \
	struct hipz_query_hca *rblock;				           \
	int data;                                                          \
									   \
	shca = dev->driver_data;					   \
									   \
	rblock = kzalloc(H_CB_ALIGNMENT, GFP_KERNEL);			   \
	if (!rblock) {						           \
		EDEB_ERR(4, "Can't allocate rblock memory.");		   \
		return 0;						   \
	}								   \
									   \
	if (hipz_h_query_hca(shca->ipz_hca_handle, rblock) != H_SUCCESS) { \
			EDEB_ERR(4, "Can't query device properties");	   \
			kfree(rblock);					   \
			return 0;					   \
	}								   \
                                                                           \
	data = rblock->name;                                               \
	kfree(rblock);                                                     \
									   \
	if ((strcmp(#name, "num_ports") == 0) && (ehca_nr_ports == 1))	   \
		return snprintf(buf, 256, "1\n");			   \
	else								   \
		return snprintf(buf, 256, "%d\n", data);		   \
									   \
}									   \
static DEVICE_ATTR(name, S_IRUGO, ehca_show_##name, NULL);

EHCA_RESOURCE_ATTR(num_ports);
EHCA_RESOURCE_ATTR(hw_ver);
EHCA_RESOURCE_ATTR(max_eq);
EHCA_RESOURCE_ATTR(cur_eq);
EHCA_RESOURCE_ATTR(max_cq);
EHCA_RESOURCE_ATTR(cur_cq);
EHCA_RESOURCE_ATTR(max_qp);
EHCA_RESOURCE_ATTR(cur_qp);
EHCA_RESOURCE_ATTR(max_mr);
EHCA_RESOURCE_ATTR(cur_mr);
EHCA_RESOURCE_ATTR(max_mw);
EHCA_RESOURCE_ATTR(cur_mw);
EHCA_RESOURCE_ATTR(max_pd);
EHCA_RESOURCE_ATTR(max_ah);

static ssize_t ehca_show_adapter_handle(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct ehca_shca *shca = dev->driver_data;

	return sprintf(buf, "%lx\n", shca->ipz_hca_handle.handle);

}
static DEVICE_ATTR(adapter_handle, S_IRUGO, ehca_show_adapter_handle, NULL);



void ehca_create_device_sysfs(struct ibmebus_dev *dev)
{
	device_create_file(&dev->ofdev.dev, &dev_attr_adapter_handle);
	device_create_file(&dev->ofdev.dev, &dev_attr_num_ports);
	device_create_file(&dev->ofdev.dev, &dev_attr_hw_ver);
	device_create_file(&dev->ofdev.dev, &dev_attr_max_eq);
	device_create_file(&dev->ofdev.dev, &dev_attr_cur_eq);
	device_create_file(&dev->ofdev.dev, &dev_attr_max_cq);
	device_create_file(&dev->ofdev.dev, &dev_attr_cur_cq);
	device_create_file(&dev->ofdev.dev, &dev_attr_max_qp);
	device_create_file(&dev->ofdev.dev, &dev_attr_cur_qp);
	device_create_file(&dev->ofdev.dev, &dev_attr_max_mr);
	device_create_file(&dev->ofdev.dev, &dev_attr_cur_mr);
	device_create_file(&dev->ofdev.dev, &dev_attr_max_mw);
	device_create_file(&dev->ofdev.dev, &dev_attr_cur_mw);
	device_create_file(&dev->ofdev.dev, &dev_attr_max_pd);
	device_create_file(&dev->ofdev.dev, &dev_attr_max_ah);
}

void ehca_remove_device_sysfs(struct ibmebus_dev *dev)
{
	device_remove_file(&dev->ofdev.dev, &dev_attr_adapter_handle);
	device_remove_file(&dev->ofdev.dev, &dev_attr_num_ports);
	device_remove_file(&dev->ofdev.dev, &dev_attr_hw_ver);
	device_remove_file(&dev->ofdev.dev, &dev_attr_max_eq);
	device_remove_file(&dev->ofdev.dev, &dev_attr_cur_eq);
	device_remove_file(&dev->ofdev.dev, &dev_attr_max_cq);
	device_remove_file(&dev->ofdev.dev, &dev_attr_cur_cq);
	device_remove_file(&dev->ofdev.dev, &dev_attr_max_qp);
	device_remove_file(&dev->ofdev.dev, &dev_attr_cur_qp);
	device_remove_file(&dev->ofdev.dev, &dev_attr_max_mr);
	device_remove_file(&dev->ofdev.dev, &dev_attr_cur_mr);
	device_remove_file(&dev->ofdev.dev, &dev_attr_max_mw);
	device_remove_file(&dev->ofdev.dev, &dev_attr_cur_mw);
	device_remove_file(&dev->ofdev.dev, &dev_attr_max_pd);
	device_remove_file(&dev->ofdev.dev, &dev_attr_max_ah);
}

static int __devinit ehca_probe(struct ibmebus_dev *dev,
				const struct of_device_id *id)
{
	struct ehca_shca *shca;
	u64 *handle;
	struct ib_pd *ibpd;
	int ret = 0;

	EDEB_EN(7, "name=%s", dev->name);

	handle = (u64 *)get_property(dev->ofdev.node, "ibm,hca-handle", NULL);
	if (!handle) {
		EDEB_ERR(4, "Cannot get eHCA handle for adapter: %s.",
			 dev->ofdev.node->full_name);
		return -ENODEV;
	}

	if (!(*handle)) {
		EDEB_ERR(4, "Wrong eHCA handle for adapter: %s.",
			 dev->ofdev.node->full_name);
		return -ENODEV;
	}

	shca = (struct ehca_shca *)ib_alloc_device(sizeof(*shca));
	if (shca == NULL) {
		EDEB_ERR(4, "Cannot allocate shca memory.");
		return -ENOMEM;
	}

	shca->ibmebus_dev = dev;
	shca->ipz_hca_handle.handle = *handle;
	dev->ofdev.dev.driver_data = shca;

	ret = ehca_sense_attributes(shca);
	if (ret < 0) {
		EDEB_ERR(4, "Cannot sense eHCA attributes.");
		goto probe1;
	}

	/* create event queues */
	ret = ehca_create_eq(shca, &shca->eq, EHCA_EQ, 2048);
	if (ret) {
		EDEB_ERR(4, "Cannot create EQ.");
		goto probe1;
	}

	ret = ehca_create_eq(shca, &shca->neq, EHCA_NEQ, 513);
	if (ret) {
		EDEB_ERR(4, "Cannot create NEQ.");
		goto probe2;
	}

	/* create internal protection domain */
	ibpd = ehca_alloc_pd(&shca->ib_device, (void*)(-1), NULL);
	if (IS_ERR(ibpd)) {
		EDEB_ERR(4, "Cannot create internal PD.");
		ret = PTR_ERR(ibpd);
		goto probe3;
	}

	shca->pd = container_of(ibpd, struct ehca_pd, ib_pd);
	shca->pd->ib_pd.device = &shca->ib_device;

	/* create internal max MR */
	ret = ehca_reg_internal_maxmr(shca, shca->pd, &shca->maxmr);
	if (ret) {
		EDEB_ERR(4, "Cannot create internal MR. ret=%x", ret);
		goto probe4;
	}

	ret = ehca_register_device(shca);
	if (ret) {
		EDEB_ERR(4, "Cannot register Infiniband device.");
		goto probe5;
	}

	/* create AQP1 for port 1 */
	if (ehca_open_aqp1 == 1) {
		shca->sport[0].port_state = IB_PORT_DOWN;
		ret = ehca_create_aqp1(shca, 1);
		if (ret) {
			EDEB_ERR(4, "Cannot create AQP1 for port 1.");
			goto probe6;
		}
	}

	/* create AQP1 for port 2 */
	if ((ehca_open_aqp1 == 1) && (shca->num_ports == 2)) {
		shca->sport[1].port_state = IB_PORT_DOWN;
		ret = ehca_create_aqp1(shca, 2);
		if (ret) {
			EDEB_ERR(4, "Cannot create AQP1 for port 2.");
			goto probe7;
		}
	}

	ehca_create_device_sysfs(dev);

	spin_lock(&ehca_module.shca_lock);
	list_add(&shca->shca_list, &ehca_module.shca_list);
	spin_unlock(&ehca_module.shca_lock);

	EDEB_EX(7, "ret=%x", ret);

	return 0;

probe7:
	ret = ehca_destroy_aqp1(&shca->sport[0]);
	if (ret)
		EDEB_ERR(4, "Cannot destroy AQP1 for port 1. ret=%x", ret);

probe6:
	ib_unregister_device(&shca->ib_device);

probe5:
	ret = ehca_dereg_internal_maxmr(shca);
	if (ret)
		EDEB_ERR(4, "Cannot destroy internal MR. ret=%x", ret);

probe4:
	ret = ehca_dealloc_pd(&shca->pd->ib_pd);
	if (ret != 0)
		EDEB_ERR(4, "Cannot destroy internal PD. ret=%x", ret);

probe3:
	ret = ehca_destroy_eq(shca, &shca->neq);
	if (ret != 0)
		EDEB_ERR(4, "Cannot destroy NEQ. ret=%x", ret);

probe2:
	ret = ehca_destroy_eq(shca, &shca->eq);
	if (ret != 0)
		EDEB_ERR(4, "Cannot destroy EQ. ret=%x", ret);

probe1:
	ib_dealloc_device(&shca->ib_device);

	EDEB_EX(4, "ret=%x", ret);

	return -EINVAL;
}

static int __devexit ehca_remove(struct ibmebus_dev *dev)
{
	struct ehca_shca *shca = dev->ofdev.dev.driver_data;
	int ret;

	EDEB_EN(7, "shca=%p", shca);

	ehca_remove_device_sysfs(dev);

	if (ehca_open_aqp1 == 1) {
		int i;

		for (i = 0; i < shca->num_ports; i++) {
			ret = ehca_destroy_aqp1(&shca->sport[i]);
			if (ret != 0)
				EDEB_ERR(4, "Cannot destroy AQP1 for port %x."
					 " ret=%x", ret, i);
		}
	}

	ib_unregister_device(&shca->ib_device);

	ret = ehca_dereg_internal_maxmr(shca);
	if (ret)
		EDEB_ERR(4, "Cannot destroy internal MR. ret=%x", ret);

	ret = ehca_dealloc_pd(&shca->pd->ib_pd);
	if (ret)
		EDEB_ERR(4, "Cannot destroy internal PD. ret=%x", ret);

	ret = ehca_destroy_eq(shca, &shca->eq);
	if (ret)
		EDEB_ERR(4, "Cannot destroy EQ. ret=%x", ret);

	ret = ehca_destroy_eq(shca, &shca->neq);
	if (ret)
		EDEB_ERR(4, "Canot destroy NEQ. ret=%x", ret);

	ib_dealloc_device(&shca->ib_device);

	spin_lock(&ehca_module.shca_lock);
	list_del(&shca->shca_list);
	spin_unlock(&ehca_module.shca_lock);

	EDEB_EX(7, "ret=%x", ret);

	return ret;
}

static struct of_device_id ehca_device_table[] =
{
	{
		.name       = "lhca",
		.compatible = "IBM,lhca",
	},
	{},
};

static struct ibmebus_driver ehca_driver = {
	.name     = "ehca",
	.id_table = ehca_device_table,
	.probe    = ehca_probe,
	.remove   = ehca_remove,
};

int __init ehca_module_init(void)
{
	int ret = 0;

	printk(KERN_INFO "eHCA Infiniband Device Driver "
	                 "(Rel.: SVNEHCA_0006)\n");
	EDEB_EN(7, "");

	idr_init(&ehca_qp_idr);
	idr_init(&ehca_cq_idr);
	spin_lock_init(&ehca_qp_idr_lock);
	spin_lock_init(&ehca_cq_idr_lock);

	INIT_LIST_HEAD(&ehca_module.shca_list);
	spin_lock_init(&ehca_module.shca_lock);

	ehca_init_trace();

	ehca_pool = ehca_create_comp_pool();
	if (ehca_pool == NULL) {
		EDEB_ERR(4, "Cannot create comp pool.");
		ret = -EINVAL;
		goto module_init0;
	}

	if ((ret = ehca_create_slab_caches(&ehca_module))) {
		EDEB_ERR(4, "Cannot create SLAB caches");
		ret = -ENOMEM;
		goto module_init1;
	}

	if ((ret = ibmebus_register_driver(&ehca_driver))) {
		EDEB_ERR(4, "Cannot register eHCA device driver");
		ret = -EINVAL;
		goto module_init2;
	}

	ehca_create_driver_sysfs(&ehca_driver);

	if (ehca_poll_all_eqs != 1) {
		EDEB_ERR(4, "WARNING!!!");
		EDEB_ERR(4, "It is possible to lose interrupts.");

		return 0;
	}

	init_timer(&ehca_module.timer);
	ehca_module.timer.function = ehca_poll_eqs;
	ehca_module.timer.data = (unsigned long)(void*)&ehca_module;
	ehca_module.timer.expires = jiffies + HZ;
	add_timer(&ehca_module.timer);

	EDEB_EX(7, "ret=%x", ret);

	return 0;

module_init2:
	ehca_destroy_slab_caches(&ehca_module);

module_init1:
	ehca_destroy_comp_pool(ehca_pool);

module_init0:
	EDEB_EX(7, "ret=%x", ret);

	return ret;
};

void __exit ehca_module_exit(void)
{
	EDEB_EN(7, "");

	if (ehca_poll_all_eqs == 1)
		del_timer_sync(&ehca_module.timer);

	ehca_remove_driver_sysfs(&ehca_driver);
	ibmebus_unregister_driver(&ehca_driver);

	if (ehca_destroy_slab_caches(&ehca_module) != 0)
		EDEB_ERR(4, "Cannot destroy SLAB caches");

	ehca_destroy_comp_pool(ehca_pool);

	idr_destroy(&ehca_cq_idr);
	idr_destroy(&ehca_qp_idr);

	EDEB_EX(7, "");
};

module_init(ehca_module_init);
module_exit(ehca_module_exit);

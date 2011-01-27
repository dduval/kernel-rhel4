/*
 *  IBM eServer eHCA Infiniband device driver for Linux on POWER
 *
 *  mcast  functions
 *
 *  Authors: Khadija Souissi <souissik@de.ibm.com>
 *           Waleri Fomin <fomin@de.ibm.com>
 *           Reinhard Ernst <rernst@de.ibm.com>
 *           Hoang-Nam Nguyen <hnguyen@de.ibm.com>
 *           Heiko J Schick <schickhj@de.ibm.com>
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

#define DEB_PREFIX "mcas"

#include <linux/module.h>
#include <linux/err.h>
#include "ehca_classes.h"
#include "ehca_tools.h"
#include "ehca_qes.h"
#include "ehca_iverbs.h"

#include "hcp_if.h"

#define MAX_MC_LID 0xFFFE
#define MIN_MC_LID 0xC000	/* Multicast limits */
#define EHCA_VALID_MULTICAST_GID(gid)  ((gid)[0] == 0xFF)
#define EHCA_VALID_MULTICAST_LID(lid)  (((lid) >= MIN_MC_LID) && ((lid) <= MAX_MC_LID))

int ehca_attach_mcast(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	struct ehca_qp *my_qp = NULL;
	struct ehca_shca *shca = NULL;
	union ib_gid my_gid;
	u64 h_ret = H_SUCCESS;
	int ret = 0;

	EHCA_CHECK_ADR(ibqp);
	EHCA_CHECK_ADR(gid);

	my_qp = container_of(ibqp, struct ehca_qp, ib_qp);

	EHCA_CHECK_QP(my_qp);
	if (ibqp->qp_type != IB_QPT_UD) {
		EDEB_ERR(4, "invalid qp_type %x gid, ret=%x",
			 ibqp->qp_type, EINVAL);
		return -EINVAL;
	}

	shca = container_of(ibqp->pd->device, struct ehca_shca, ib_device);
	EHCA_CHECK_ADR(shca);

	if (!(EHCA_VALID_MULTICAST_GID(gid->raw))) {
		EDEB_ERR(4, "gid is not valid mulitcast gid ret=%x",
			 EINVAL);
		return -EINVAL;
	} else if ((lid < MIN_MC_LID) || (lid > MAX_MC_LID)) {
		EDEB_ERR(4, "lid=%x is not valid mulitcast lid ret=%x",
			 lid, EINVAL);
		return -EINVAL;
	}

	memcpy(&my_gid.raw, gid->raw, sizeof(union ib_gid));

	h_ret = hipz_h_attach_mcqp(shca->ipz_hca_handle,
				     my_qp->ipz_qp_handle,
				     my_qp->galpas.kernel,
				     lid, my_gid.global.subnet_prefix,
				     my_gid.global.interface_id);
	if (h_ret != H_SUCCESS) {
		EDEB_ERR(4,
			 "ehca_qp=%p qp_num=%x hipz_h_attach_mcqp() failed "
			 "h_ret=%lx", my_qp, ibqp->qp_num, h_ret);
	}
	ret = ehca2ib_return_code(h_ret);

	EDEB_EX(7, "mcast attach ret=%x\n"
		   "ehca_qp=%p qp_num=%x  lid=%x\n"
		   "my_gid=  %x %x %x %x\n"
		   "         %x %x %x %x\n"
		   "         %x %x %x %x\n"
		   "         %x %x %x %x\n",
		   ret, my_qp, ibqp->qp_num, lid,
		   my_gid.raw[0], my_gid.raw[1],
		   my_gid.raw[2], my_gid.raw[3],
		   my_gid.raw[4], my_gid.raw[5],
		   my_gid.raw[6], my_gid.raw[7],
		   my_gid.raw[8], my_gid.raw[9],
		   my_gid.raw[10], my_gid.raw[11],
		   my_gid.raw[12], my_gid.raw[13],
		   my_gid.raw[14], my_gid.raw[15]);

	return ret;
}

int ehca_detach_mcast(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	struct ehca_qp *my_qp = NULL;
	struct ehca_shca *shca = NULL;
	union ib_gid my_gid;
	u64 h_ret = H_SUCCESS;
	int ret = 0;

	EHCA_CHECK_ADR(ibqp);
	EHCA_CHECK_ADR(gid);

	my_qp = container_of(ibqp, struct ehca_qp, ib_qp);

	EHCA_CHECK_QP(my_qp);
	if (ibqp->qp_type != IB_QPT_UD) {
		EDEB_ERR(4, "invalid qp_type %x gid, ret=%x",
			 ibqp->qp_type, EINVAL);
		return -EINVAL;
	}

	shca = container_of(ibqp->pd->device, struct ehca_shca, ib_device);
	EHCA_CHECK_ADR(shca);

	if (!(EHCA_VALID_MULTICAST_GID(gid->raw))) {
		EDEB_ERR(4, "gid is not valid mulitcast gid ret=%x",
			 EINVAL);
		return -EINVAL;
	} else if ((lid < MIN_MC_LID) || (lid > MAX_MC_LID)) {
		EDEB_ERR(4, "lid=%x is not valid mulitcast lid ret=%x",
			 lid, EINVAL);
		return -EINVAL;
	}

	EDEB_EN(7, "dgid=%p qp_numl=%x lid=%x",
		gid, ibqp->qp_num, lid);

	memcpy(&my_gid.raw, gid->raw, sizeof(union ib_gid));

	h_ret = hipz_h_detach_mcqp(shca->ipz_hca_handle,
				     my_qp->ipz_qp_handle,
				     my_qp->galpas.kernel,
				     lid, my_gid.global.subnet_prefix,
				     my_gid.global.interface_id);
	if (h_ret != H_SUCCESS) {
		EDEB_ERR(4,
			 "ehca_qp=%p qp_num=%x hipz_h_detach_mcqp() failed "
			 "h_ret=%lx", my_qp, ibqp->qp_num, h_ret);
	}
	ret = ehca2ib_return_code(h_ret);

	EDEB_EX(7, "mcast detach ret=%x\n"
		"ehca_qp=%p qp_num=%x  lid=%x\n"
		"my_gid=  %x %x %x %x\n"
		"         %x %x %x %x\n"
		"         %x %x %x %x\n"
		"         %x %x %x %x\n",
		ret, my_qp, ibqp->qp_num, lid,
		my_gid.raw[0], my_gid.raw[1],
		my_gid.raw[2], my_gid.raw[3],
		my_gid.raw[4], my_gid.raw[5],
		my_gid.raw[6], my_gid.raw[7],
		my_gid.raw[8], my_gid.raw[9],
		my_gid.raw[10], my_gid.raw[11],
		my_gid.raw[12], my_gid.raw[13],
		my_gid.raw[14], my_gid.raw[15]);

	return ret;
}

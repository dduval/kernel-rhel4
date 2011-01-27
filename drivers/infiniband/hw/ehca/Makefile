#  Authors: Heiko J Schick <schickhj@de.ibm.com>
#           Christoph Raisch <raisch@de.ibm.com>
#
#  Copyright (c) 2005 IBM Corporation
#
#  All rights reserved.
#
#  This source code is distributed under a dual license of GPL v2.0 and OpenIB BSD.

obj-$(CONFIG_INFINIBAND_EHCA) += hcad_mod.o

hcad_mod-objs = ehca_main.o ehca_hca.o ehca_mcast.o ehca_pd.o ehca_av.o ehca_eq.o \
		ehca_cq.o ehca_qp.o ehca_sqp.o ehca_mrmw.o ehca_reqs.o ehca_irq.o \
		ehca_uverbs.o hcp_if.o hcp_phyp.o ipz_pt_fn.o

CFLAGS += -DEHCA_USE_HCALL -DEHCA_USE_HCALL_KERNEL

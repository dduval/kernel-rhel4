/*
 *  IBM eServer eHCA Infiniband device driver for Linux on POWER
 *
 *  Generalized functions for code shared between kernel and userspace
 *
 *  Authors: Christoph Raisch <raisch@de.ibm.com>
 *           Hoang-Nam Nguyen <hnguyen@de.ibm.com>
 *           Khadija Souissi <souissik@de.ibm.com>
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
 *
 *  $Id: ehca_kernel.h,v 1.13 2006/04/03 06:40:54 schickhj Exp $
 */

#ifndef _EHCA_KERNEL_H_
#define _EHCA_KERNEL_H_

#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/idr.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/vmalloc.h>
#include <linux/version.h>

#include <asm/abs_addr.h>
#include <asm/ibmebus.h>
#include <asm/io.h>
#include <asm/pgtable.h>

/**
 * ehca_adr_bad - Handle to be used for adress translation mechanisms,
 * currently a placeholder.
 */
inline static int ehca_adr_bad(void *adr)
{
	return (adr == 0);
};

/* We will remove this lines in SVN when it is included in the Linux kernel.
 * We don't want to introducte unnecessary dependencies to a patched kernel.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#include <asm/hvcall.h>
#define H_SUCCESS              0
#define H_BUSY		       1
#define H_CONSTRAINED	       4
#define H_LONG_BUSY_ORDER_1_MSEC   9900
#define H_LONG_BUSY_ORDER_10_MSEC  9901
#define H_LONG_BUSY_ORDER_100_MSEC 9902
#define H_LONG_BUSY_ORDER_1_SEC    9903
#define H_LONG_BUSY_ORDER_10_SEC   9904
#define H_LONG_BUSY_ORDER_100_SEC  9905

#define H_IS_LONG_BUSY(x)  ((x >= H_LongBusyStartRange) && (x <= H_LongBusyEndRange))

#define H_PARTIAL_STORE        16
#define H_PAGE_REGISTERED      15
#define H_IN_PROGRESS          14
#define H_PARTIAL              5
#define H_NOT_AVAILABLE        3
#define H_Closed               2

#define H_HARDWARE	       -1
#define H_PARAMETER	       -4
#define H_NO_MEM               -9
#define H_RESOURCE             -16

#define H_ADAPTER_PARM         -17
#define H_RH_PARM              -18
#define H_RCQ_PARM             -19
#define H_SCQ_PARM             -20
#define H_EQ_PARM              -21
#define H_RT_PARM              -22
#define H_ST_PARM              -23
#define H_SIGT_PARM            -24
#define H_TOKEN_PARM           -25
#define H_MLENGTH_PARM         -27
#define H_MEM_PARM             -28
#define H_MEM_ACCESS_PARM      -29
#define H_ATTR_PARM            -30
#define H_PORT_PARM            -31
#define H_MCG_PARM             -32
#define H_VL_PARM              -33
#define H_TSIZE_PARM           -34
#define H_TRACE_PARM           -35
#define H_MASK_PARM            -37
#define H_MCG_FULL             -38
#define H_ALIAS_EXIST          -39
#define H_P_COUNTER            -40
#define H_TABLE_FULL           -41
#define H_ALT_TABLE            -42
#define H_MR_CONDITION         -43
#define H_NOT_ENOUGH_RESOURCES -44
#define H_R_STATE              -45
#define H_RESCINDEND           -46

/* H call defines to be moved to kernel */
#define H_RESET_EVENTS         0x15C
#define H_ALLOC_RESOURCE       0x160
#define H_FREE_RESOURCE        0x164
#define H_MODIFY_QP            0x168
#define H_QUERY_QP             0x16C
#define H_REREGISTER_PMR       0x170
#define H_REGISTER_SMR         0x174
#define H_QUERY_MR             0x178
#define H_QUERY_MW             0x17C
#define H_QUERY_HCA            0x180
#define H_QUERY_PORT           0x184
#define H_MODIFY_PORT          0x188
#define H_DEFINE_AQP1          0x18C
#define H_GET_TRACE_BUFFER     0x190
#define H_DEFINE_AQP0          0x194
#define H_RESIZE_MR            0x198
#define H_ATTACH_MCQP          0x19C
#define H_DETACH_MCQP          0x1A0
#define H_CREATE_RPT           0x1A4
#define H_REMOVE_RPT           0x1A8
#define H_REGISTER_RPAGES      0x1AC
#define H_DISABLE_AND_GETC     0x1B0
#define H_ERROR_DATA           0x1B4
#define H_GET_HCA_INFO         0x1B8
#define H_GET_PERF_COUNT       0x1BC
#define H_MANAGE_TRACE         0x1C0
#define H_QUERY_INT_STATE      0x1E4
#define H_CB_ALIGNMENT         4096
#endif /* LINUX_VERSION_CODE */

#endif /* _EHCA_KERNEL_H_ */

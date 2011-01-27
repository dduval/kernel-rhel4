/*
 *  IBM eServer eHCA Infiniband device driver for Linux on POWER
 *
 *  auxiliary functions
 *
 *  Authors: Christoph Raisch <raisch@de.ibm.com>
 *           Hoang-Nam Nguyen <hnguyen@de.ibm.com>
 *           Khadija Souissi <souissik@de.ibm.com>
 *           Waleri Fomin <fomin@de.ibm.com>
 *           Heiko J Schick <schickhj@de.ibm.com>
 *
 *  Copyright (c) 2005 IBM Corporation
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


#ifndef EHCA_TOOLS_H
#define EHCA_TOOLS_H

#include <linux/kernel.h>
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

#define EHCA_EDEB_TRACE_MASK_SIZE 32
extern u8 ehca_edeb_mask[EHCA_EDEB_TRACE_MASK_SIZE];
#define EDEB_ID_TO_U32(str4) (str4[3] | (str4[2] << 8) | (str4[1] << 16) | \
			      (str4[0] << 24))

static inline u64 ehca_edeb_filter(const u32 level,
				   const u32 id, const u32 line)
{
	u64 ret = 0;
	u32 filenr = 0;
	u32 filter_level = 9;
	u32 dynamic_level = 0;

	/* This is code written for the gcc -O2 optimizer which should colapse
	 * to two single ints filter_level is the first level kicked out by
	 * compiler means trace everythin below 6. */
	if (id == EDEB_ID_TO_U32("ehav")) {
		filenr = 0x01;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("clas")) {
		filenr = 0x02;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("cqeq")) {
		filenr = 0x03;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("shca")) {
		filenr = 0x05;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("eirq")) {
		filenr = 0x06;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("lMad")) {
		filenr = 0x07;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("mcas")) {
		filenr = 0x08;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("mrmw")) {
		filenr = 0x09;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("vpd ")) {
		filenr = 0x0a;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("e_qp")) {
		filenr = 0x0b;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("uqes")) {
		filenr = 0x0c;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("PHYP")) {
		filenr = 0x0d;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("hcpi")) {
		filenr = 0x0e;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("iptz")) {
		filenr = 0x0f;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("spta")) {
		filenr = 0x10;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("simp")) {
		filenr = 0x11;
		filter_level = 8;
	}
	if (id == EDEB_ID_TO_U32("reqs")) {
		filenr = 0x12;
		filter_level = 8;
	}

	if ((filenr - 1) > sizeof(ehca_edeb_mask)) {
		filenr = 0;
	}

	if (filenr == 0) {
		filter_level = 9;
	} /* default */
	ret = filenr * 0x10000 + line;
	if (filter_level <= level) {
		return ret | 0x100000000L; /* this is the flag to not trace */
	}
	dynamic_level = ehca_edeb_mask[filenr];
	if (likely(dynamic_level <= level)) {
		ret = ret | 0x100000000L;
	};
	return ret;
}

#ifdef EHCA_USE_HCALL_KERNEL
#ifdef CONFIG_PPC_PSERIES

#include <asm/paca.h>

/**
 * IS_EDEB_ON - Checks if debug is on for the given level.
 */
#define IS_EDEB_ON(level) \
    ((ehca_edeb_filter(level, EDEB_ID_TO_U32(DEB_PREFIX), __LINE__) & 0x100000000L)==0)

#define EDEB_P_GENERIC(level,idstring,format,args...) \
do { \
	u64 ehca_edeb_filterresult =					\
		ehca_edeb_filter(level, EDEB_ID_TO_U32(DEB_PREFIX), __LINE__);\
	if ((ehca_edeb_filterresult & 0x100000000L) == 0)		\
		printk("PU%04x %08x:%s " idstring " "format "\n",	\
		       get_paca()->paca_index, (u32)(ehca_edeb_filterresult), \
		       __func__,  ##args);				\
} while (1 == 0)

#elif REAL_HCALL

#define EDEB_P_GENERIC(level,idstring,format,args...) \
do { \
	u64 ehca_edeb_filterresult =					\
		ehca_edeb_filter(level, EDEB_ID_TO_U32(DEB_PREFIX), __LINE__); \
	if ((ehca_edeb_filterresult & 0x100000000L) == 0)		\
		printk("%08x:%s " idstring " "format "\n",	\
			(u32)(ehca_edeb_filterresult), \
			__func__,  ##args); \
} while (1 == 0)

#endif
#else

#define IS_EDEB_ON(level) (1)

#define EDEB_P_GENERIC(level,idstring,format,args...) \
do { \
	printk("%s " idstring " "format "\n",	\
	       __func__,  ##args);		\
} while (1 == 0)

#endif

/**
 * EDEB - Trace output macro.
 * @level tracelevel
 * @format optional format string, use "" if not desired
 * @args printf like arguments for trace, use %Lx for u64, %x for u32
 *       %p for pointer
 */
#define EDEB(level,format,args...) \
	EDEB_P_GENERIC(level,"",format,##args)
#define EDEB_ERR(level,format,args...) \
	EDEB_P_GENERIC(level,"HCAD_ERROR ",format,##args)
#define EDEB_EN(level,format,args...) \
	EDEB_P_GENERIC(level,">>>",format,##args)
#define EDEB_EX(level,format,args...) \
	EDEB_P_GENERIC(level,"<<<",format,##args)

/**
 * EDEB macro to dump a memory block, whose length is n*8 bytes.
 * Each line has the following layout:
 * <format string> adr=X ofs=Y <8 bytes hex> <8 bytes hex>
 */
#define EDEB_DMP(level,adr,len,format,args...) \
	do {				       \
		unsigned int x;			      \
		unsigned int l = (unsigned int)(len); \
		unsigned char *deb = (unsigned char*)(adr);	\
		for (x = 0; x < l; x += 16) { \
		        EDEB(level, format " adr=%p ofs=%04x %016lx %016lx", \
			     ##args, deb, x, *((u64 *)&deb[0]), *((u64 *)&deb[8])); \
			deb += 16; \
		} \
	} while (0)

/* define a bitmask, little endian version */
#define EHCA_BMASK(pos,length) (((pos)<<16)+(length))
/* define a bitmask, the ibm way... */
#define EHCA_BMASK_IBM(from,to) (((63-to)<<16)+((to)-(from)+1))
/* internal function, don't use */
#define EHCA_BMASK_SHIFTPOS(mask) (((mask)>>16)&0xffff)
/* internal function, don't use */
#define EHCA_BMASK_MASK(mask) (0xffffffffffffffffULL >> ((64-(mask))&0xffff))
/* return value shifted and masked by mask\n
 * variable|=HCA_BMASK_SET(MY_MASK,0x4711) ORs the bits in variable\n
 * variable&=~HCA_BMASK_SET(MY_MASK,-1) clears the bits from the mask
 * in variable
 */
#define EHCA_BMASK_SET(mask,value) \
	((EHCA_BMASK_MASK(mask) & ((u64)(value)))<<EHCA_BMASK_SHIFTPOS(mask))
/* extract a parameter from value by mask\n
 * param=EHCA_BMASK_GET(MY_MASK,value)
 */
#define EHCA_BMASK_GET(mask,value) \
	( EHCA_BMASK_MASK(mask)& (((u64)(value))>>EHCA_BMASK_SHIFTPOS(mask)))

#define PARANOIA_MODE
#ifdef PARANOIA_MODE

#define EHCA_CHECK_ADR_P(adr)					\
	if (unlikely(adr == 0)) {					\
		EDEB_ERR(4, "adr=%p check failed line %i", adr,	\
			 __LINE__);				\
		return ERR_PTR(-EFAULT); }

#define EHCA_CHECK_ADR(adr)					\
	if (unlikely(adr == 0)) {					\
		EDEB_ERR(4, "adr=%p check failed line %i", adr,	\
			 __LINE__);				\
		return -EFAULT; }

#define EHCA_CHECK_DEVICE_P(device)				\
	if (unlikely(device == 0)) {				\
		EDEB_ERR(4, "device=%p check failed", device);	\
		return ERR_PTR(-EFAULT); }

#define EHCA_CHECK_DEVICE(device)				\
	if (unlikely(device == 0)) {				\
		EDEB_ERR(4, "device=%p check failed", device);	\
		return -EFAULT; }

#define EHCA_CHECK_PD(pd)				\
	if (unlikely(pd == 0)) {				\
		EDEB_ERR(4, "pd=%p check failed", pd);	\
		return -EFAULT; }

#define EHCA_CHECK_PD_P(pd)				\
	if (unlikely(pd == 0)) {				\
		EDEB_ERR(4, "pd=%p check failed", pd);	\
		return ERR_PTR(-EFAULT); }

#define EHCA_CHECK_AV(av)				\
	if (unlikely(av == 0)) {				\
		EDEB_ERR(4, "av=%p check failed", av);	\
		return -EFAULT; }

#define EHCA_CHECK_AV_P(av)				\
	if (unlikely(av == 0)) {				\
		EDEB_ERR(4, "av=%p check failed", av);	\
		return ERR_PTR(-EFAULT); }

#define EHCA_CHECK_CQ(cq)				\
	if (unlikely(cq == 0)) {				\
		EDEB_ERR(4, "cq=%p check failed", cq);	\
		return -EFAULT; }

#define EHCA_CHECK_CQ_P(cq)				\
	if (unlikely(cq == 0)) {				\
		EDEB_ERR(4, "cq=%p check failed", cq);	\
		return ERR_PTR(-EFAULT); }

#define EHCA_CHECK_EQ(eq)				\
	if (unlikely(eq == 0)) {				\
		EDEB_ERR(4, "eq=%p check failed", eq);	\
		return -EFAULT; }

#define EHCA_CHECK_EQ_P(eq)				\
	if (unlikely(eq == 0)) {				\
		EDEB_ERR(4, "eq=%p check failed", eq);	\
		return ERR_PTR(-EFAULT); }

#define EHCA_CHECK_QP(qp)				\
	if (unlikely(qp == 0)) {				\
		EDEB_ERR(4, "qp=%p check failed", qp);	\
		return -EFAULT; }

#define EHCA_CHECK_QP_P(qp)				\
	if (unlikely(qp == 0)) {				\
		EDEB_ERR(4, "qp=%p check failed", qp);	\
		return ERR_PTR(-EFAULT); }

#define EHCA_CHECK_MR(mr)				\
	if (unlikely(mr == 0)) {				\
		EDEB_ERR(4, "mr=%p check failed", mr);	\
		return -EFAULT; }

#define EHCA_CHECK_MR_P(mr)				\
	if (unlikely(mr == 0)) {				\
		EDEB_ERR(4, "mr=%p check failed", mr);	\
		return ERR_PTR(-EFAULT); }

#define EHCA_CHECK_MW(mw)				\
	if (unlikely(mw == 0)) {				\
		EDEB_ERR(4, "mw=%p check failed", mw);	\
		return -EFAULT; }

#define EHCA_CHECK_MW_P(mw)				\
	if (unlikely(mw == 0)) {				\
		EDEB_ERR(4, "mw=%p check failed", mw);	\
		return ERR_PTR(-EFAULT); }

#define EHCA_CHECK_FMR(fmr)					\
	if (unlikely(fmr == 0)) {					\
		EDEB_ERR(4, "fmr=%p check failed", fmr);	\
		return -EFAULT; }

#define EHCA_CHECK_FMR_P(fmr)					\
	if (unlikely(fmr == 0)) {					\
		EDEB_ERR(4, "fmr=%p check failed", fmr);	\
		return ERR_PTR(-EFAULT); }

#define EHCA_REGISTER_PD(device,pd)
#define EHCA_REGISTER_AV(pd,av)
#define EHCA_DEREGISTER_PD(PD)
#define EHCA_DEREGISTER_AV(av)
#else
#define EHCA_CHECK_DEVICE_P(device)

#define EHCA_CHECK_PD(pd)
#define EHCA_REGISTER_PD(device,pd)
#define EHCA_DEREGISTER_PD(PD)
#endif

/**
 * ehca_adr_bad - Handle to be used for adress translation mechanisms,
 * currently a placeholder.
 */
static inline int ehca_adr_bad(void *adr)
{
	return !adr;
}

/**
 * ehca2ib_return_code - Returns ib return code corresponding to the given
 * ehca return code.
 */
static inline int ehca2ib_return_code(u64 ehca_rc)
{
	switch (ehca_rc) {
	case H_SUCCESS:
		return 0;
	case H_BUSY:
		return -EBUSY;
	case H_NO_MEM:
		return -ENOMEM;
	default:
		return -EINVAL;
	}
}

#endif /* EHCA_TOOLS_H */

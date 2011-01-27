/*
 *  IBM eServer eHCA Infiniband device driver for Linux on POWER
 *
 *  userspace support verbs
 *
 *  Authors: Christoph Raisch <raisch@de.ibm.com>
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

#undef DEB_PREFIX
#define DEB_PREFIX "uver"

#include <asm/current.h>

#include "ehca_classes.h"
#include "ehca_iverbs.h"
#include "ehca_mrmw.h"
#include "ehca_tools.h"
#include "hcp_if.h"

struct ib_ucontext *ehca_alloc_ucontext(struct ib_device *device,
					struct ib_udata *udata)
{
	struct ehca_ucontext *my_context = NULL;

	EHCA_CHECK_ADR_P(device);
	EDEB_EN(7, "device=%p name=%s", device, device->name);

	my_context = kzalloc(sizeof *my_context, GFP_KERNEL);
	if (!my_context) {
		EDEB_ERR(4, "Out of memory device=%p", device);
		return ERR_PTR(-ENOMEM);
	}

	EDEB_EX(7, "device=%p ucontext=%p", device, my_context);

	return &my_context->ib_ucontext;
}

int ehca_dealloc_ucontext(struct ib_ucontext *context)
{
	struct ehca_ucontext *my_context = NULL;
	EHCA_CHECK_ADR(context);
	EDEB_EN(7, "ucontext=%p", context);
	my_context = container_of(context, struct ehca_ucontext, ib_ucontext);
	kfree(my_context);
	EDEB_EN(7, "ucontext=%p", context);
	return 0;
}

struct page *ehca_nopage(struct vm_area_struct *vma,
			 unsigned long address, int *type)
{
	struct page *mypage = NULL;
	u64 fileoffset = vma->vm_pgoff << PAGE_SHIFT;
	u32 idr_handle = fileoffset >> 32;
	u32 q_type = (fileoffset >> 28) & 0xF;	  /* CQ, QP,...        */
	u32 rsrc_type = (fileoffset >> 24) & 0xF; /* sq,rq,cmnd_window */
	u32 cur_pid = current->tgid;
	unsigned long flags;

	EDEB_EN(7, "vm_start=%lx vm_end=%lx vm_page_prot=%lx vm_fileoff=%lx "
		"address=%lx",
		vma->vm_start, vma->vm_end, vma->vm_page_prot, fileoffset,
		address);

	if (q_type == 1) { /* CQ */
		struct ehca_cq *cq = NULL;
		u64 offset;
		void *vaddr = NULL;

		spin_lock_irqsave(&ehca_cq_idr_lock, flags);
		cq = idr_find(&ehca_cq_idr, idr_handle);
		spin_unlock_irqrestore(&ehca_cq_idr_lock, flags);

		if (cq->ownpid != cur_pid) {
			EDEB_ERR(4, "Invalid caller pid=%x ownpid=%x",
				 cur_pid, cq->ownpid);
			return NOPAGE_SIGBUS;
		}

		/* make sure this mmap really belongs to the authorized user */
		if (!cq) {
			EDEB_ERR(4, "cq is NULL ret=NOPAGE_SIGBUS");
			return NOPAGE_SIGBUS;
		}
		if (rsrc_type == 2) {
			EDEB(6, "cq=%p cq queuearea", cq);
			offset = address - vma->vm_start;
			vaddr = ipz_qeit_calc(&cq->ipz_queue, offset);
			EDEB(6, "offset=%lx vaddr=%p", offset, vaddr);
			mypage = virt_to_page(vaddr);
		}
	} else if (q_type == 2) { /* QP */
		struct ehca_qp *qp = NULL;
		struct ehca_pd *pd = NULL;
		u64 offset;
		void *vaddr = NULL;

		spin_lock_irqsave(&ehca_qp_idr_lock, flags);
		qp = idr_find(&ehca_qp_idr, idr_handle);
		spin_unlock_irqrestore(&ehca_qp_idr_lock, flags);


		pd = container_of(qp->ib_qp.pd, struct ehca_pd, ib_pd);
		if (pd->ownpid != cur_pid) {
			EDEB_ERR(4, "Invalid caller pid=%x ownpid=%x",
				 cur_pid, pd->ownpid);
			return NOPAGE_SIGBUS;
		}

		/* make sure this mmap really belongs to the authorized user */
		if (!qp) {
			EDEB_ERR(4, "qp is NULL ret=NOPAGE_SIGBUS");
			return NOPAGE_SIGBUS;
		}
		if (rsrc_type == 2) {	/* rqueue */
			EDEB(6, "qp=%p qp rqueuearea", qp);
			offset = address - vma->vm_start;
			vaddr = ipz_qeit_calc(&qp->ipz_rqueue, offset);
			EDEB(6, "offset=%lx vaddr=%p", offset, vaddr);
			mypage = virt_to_page(vaddr);
		} else if (rsrc_type == 3) {	/* squeue */
			EDEB(6, "qp=%p qp squeuearea", qp);
			offset = address - vma->vm_start;
			vaddr = ipz_qeit_calc(&qp->ipz_squeue, offset);
			EDEB(6, "offset=%lx vaddr=%p", offset, vaddr);
			mypage = virt_to_page(vaddr);
		}
	}

	if (!mypage) {
		EDEB_ERR(4, "Invalid page adr==NULL ret=NOPAGE_SIGBUS");
		return NOPAGE_SIGBUS;
	}
	get_page(mypage);
	EDEB_EX(7, "page adr=%p", mypage);
	return mypage;
}

static struct vm_operations_struct ehcau_vm_ops = {
	.nopage = ehca_nopage,
};

int ehca_mmap(struct ib_ucontext *context, struct vm_area_struct *vma)
{
	u64 fileoffset = vma->vm_pgoff << PAGE_SHIFT;
	u32 idr_handle = fileoffset >> 32;
	u32 q_type = (fileoffset >> 28) & 0xF;	  /* CQ, QP,...        */
	u32 rsrc_type = (fileoffset >> 24) & 0xF; /* sq,rq,cmnd_window */
	u32 ret = -EFAULT;	/* assume the worst             */
	u64 vsize = 0;		/* must be calculated/set below */
	u64 physical = 0;	/* must be calculated/set below */
	u32 cur_pid = current->tgid;
	unsigned long flags;

	EDEB_EN(7, "vm_start=%lx vm_end=%lx vm_page_prot=%lx vm_fileoff=%lx",
		vma->vm_start, vma->vm_end, vma->vm_page_prot, fileoffset);

	if (q_type == 1) { /* CQ */
		struct ehca_cq *cq;

		spin_lock_irqsave(&ehca_cq_idr_lock, flags);
		cq = idr_find(&ehca_cq_idr, idr_handle);
		spin_unlock_irqrestore(&ehca_cq_idr_lock, flags);

		if (cq->ownpid != cur_pid) {
			EDEB_ERR(4, "Invalid caller pid=%x ownpid=%x",
				 cur_pid, cq->ownpid);
			return -ENOMEM;
		}

		/* make sure this mmap really belongs to the authorized user */
		if (!cq)
			return -EINVAL;
		if (!cq->ib_cq.uobject)
			return -EINVAL;
		if (cq->ib_cq.uobject->context != context)
			return -EINVAL;
		if (rsrc_type == 1) {	/* galpa fw handle */
			EDEB(6, "cq=%p cq triggerarea", cq);
			vma->vm_flags |= VM_RESERVED;
			vsize = vma->vm_end - vma->vm_start;
			if (vsize != EHCA_PAGESIZE) {
				EDEB_ERR(4, "invalid vsize=%lx",
					 vma->vm_end - vma->vm_start);
				ret = -EINVAL;
				goto mmap_exit0;
			}

			physical = cq->galpas.user.fw_handle;
			vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
			vma->vm_flags |= VM_IO | VM_RESERVED;

			EDEB(6, "vsize=%lx physical=%lx", vsize, physical);
			ret = remap_pfn_range(vma, vma->vm_start,
					      physical >> PAGE_SHIFT, vsize,
					      vma->vm_page_prot);
			if (ret) {
				EDEB_ERR(4, "remap_pfn_range() failed ret=%x",
					 ret);
				ret = -ENOMEM;
			}
			goto mmap_exit0;
		} else if (rsrc_type == 2) {	/* cq queue_addr */
			EDEB(6, "cq=%p cq q_addr", cq);
			/* vma->vm_page_prot =
			 * pgprot_noncached(vma->vm_page_prot); */
			vma->vm_flags |= VM_RESERVED;
			vma->vm_ops = &ehcau_vm_ops;
			ret = 0;
			goto mmap_exit0;
		} else {
			EDEB_ERR(6, "bad resource type %x", rsrc_type);
			ret = -EINVAL;
			goto mmap_exit0;
		}
	} else if (q_type == 2) { /* QP */
		struct ehca_qp *qp = NULL;
		struct ehca_pd *pd = NULL;

		spin_lock_irqsave(&ehca_qp_idr_lock, flags);
		qp = idr_find(&ehca_qp_idr, idr_handle);
		spin_unlock_irqrestore(&ehca_qp_idr_lock, flags);

		pd = container_of(qp->ib_qp.pd, struct ehca_pd, ib_pd);
		if (pd->ownpid != cur_pid) {
			EDEB_ERR(4, "Invalid caller pid=%x ownpid=%x",
				 cur_pid, pd->ownpid);
			return -ENOMEM;
		}

		/* make sure this mmap really belongs to the authorized user */
		if (!qp || !qp->ib_qp.uobject ||
		    qp->ib_qp.uobject->context != context) {
			EDEB(6, "qp=%p, uobject=%p, context=%p",
			     qp, qp->ib_qp.uobject, qp->ib_qp.uobject->context);
			ret = -EINVAL;
			goto mmap_exit0;
		}
		if (rsrc_type == 1) {	/* galpa fw handle */
			EDEB(6, "qp=%p qp triggerarea", qp);
			vma->vm_flags |= VM_RESERVED;
			vsize = vma->vm_end - vma->vm_start;
			if (vsize != EHCA_PAGESIZE) {
				EDEB_ERR(4, "invalid vsize=%lx",
					 vma->vm_end - vma->vm_start);
				ret = -EINVAL;
				goto mmap_exit0;
			}

			physical = qp->galpas.user.fw_handle;
			vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
			vma->vm_flags |= VM_IO | VM_RESERVED;

			EDEB(6, "vsize=%lx physical=%lx", vsize, physical);
			ret = remap_pfn_range(vma, vma->vm_start,
					      physical >> PAGE_SHIFT, vsize,
					      vma->vm_page_prot);
			if (ret) {
				EDEB_ERR(4, "remap_pfn_range() failed ret=%x",
					 ret);
				ret = -ENOMEM;
			}
			goto mmap_exit0;
		} else if (rsrc_type == 2) {	/* qp rqueue_addr */
			EDEB(6, "qp=%p qp rqueue_addr", qp);
			vma->vm_flags |= VM_RESERVED;
			vma->vm_ops = &ehcau_vm_ops;
			ret = 0;
			goto mmap_exit0;
		} else if (rsrc_type == 3) {	/* qp squeue_addr */
			EDEB(6, "qp=%p qp squeue_addr", qp);
			vma->vm_flags |= VM_RESERVED;
			vma->vm_ops = &ehcau_vm_ops;
			ret = 0;
			goto mmap_exit0;
		} else {
			EDEB_ERR(4, "bad resource type %x", rsrc_type);
			ret = -EINVAL;
			goto mmap_exit0;
		}
	} else {
		EDEB_ERR(4, "bad queue type %x", q_type);
		ret = -EINVAL;
		goto mmap_exit0;
	}

mmap_exit0:
	EDEB_EX(7, "ret=%x", ret);
	return ret;
}

int ehca_mmap_nopage(u64 foffset, u64 length, void ** mapped,
		     struct vm_area_struct ** vma)
{
	EDEB_EN(7, "foffset=%lx length=%lx", foffset, length);
	down_write(&current->mm->mmap_sem);
	*mapped = (void*)
		do_mmap(NULL,0,
			length,
			PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
			foffset);
	up_write(&current->mm->mmap_sem);
	if (*mapped) {
		*vma = find_vma(current->mm,(u64)*mapped);
		if (*vma) {
			(*vma)->vm_flags |= VM_RESERVED;
			(*vma)->vm_ops = &ehcau_vm_ops;
		} else
			EDEB_ERR(4, "couldn't find queue vma queue=%p", *mapped);
	} else
		EDEB_ERR(4, "couldn't create mmap length=%lx", length);
	EDEB_EX(7, "mapped=%p", *mapped);
	return 0;
}

int ehca_mmap_register(u64 physical, void ** mapped,
		       struct vm_area_struct ** vma)
{
	int ret = 0;
	unsigned long vsize;
	/* ehca hw supports only 4k page */
	ehca_mmap_nopage(0, EHCA_PAGESIZE, mapped, vma);
	(*vma)->vm_flags |= VM_RESERVED;
	vsize = (*vma)->vm_end - (*vma)->vm_start;
	if (vsize != EHCA_PAGESIZE) {
		EDEB_ERR(4, "invalid vsize=%lx",
			 (*vma)->vm_end - (*vma)->vm_start);
		ret = -EINVAL;
		return ret;
	}

	(*vma)->vm_page_prot = pgprot_noncached((*vma)->vm_page_prot);
	(*vma)->vm_flags |= VM_IO | VM_RESERVED;

	EDEB(6, "vsize=%lx physical=%lx", vsize, physical);
	ret = remap_pfn_range((*vma), (*vma)->vm_start,
			      physical >> PAGE_SHIFT, vsize,
			      (*vma)->vm_page_prot);
	if (ret) {
		EDEB_ERR(4, "remap_pfn_range() failed ret=%x", ret);
		ret = -ENOMEM;
	}
	return ret;

}

int ehca_munmap(unsigned long addr, size_t len) {
	int ret = 0;
	struct mm_struct *mm = current->mm;
	if (mm) {
		down_write(&mm->mmap_sem);
		ret = do_munmap(mm, addr, len);
		up_write(&mm->mmap_sem);
	}
	return ret;
}

/*******************************************************************
 * This file is part of the Emulex Linux Device Driver for         *
 * Fibre Channel Host Bus Adapters.                                *
 * Copyright (C) 2003-2005 Emulex.  All rights reserved.           *
 * EMULEX and SLI are trademarks of Emulex.                        *
 * www.emulex.com                                                  *
 *                                                                 *
 * This program is free software; you can redistribute it and/or   *
 * modify it under the terms of version 2 of the GNU General       *
 * Public License as published by the Free Software Foundation.    *
 * This program is distributed in the hope that it will be useful. *
 * ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND          *
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY,  *
 * FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT, ARE      *
 * DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD *
 * TO BE LEGALLY INVALID.  See the GNU General Public License for  *
 * more details, a copy of which can be found in the file COPYING  *
 * included with this package.                                     *
 *******************************************************************/

/*
 * $Id: lpfc_misc.h 3192 2008-09-04 13:21:27Z sf_support $
 */

#ifndef _H_LPFC_MISC
#define _H_LPFC_MISC

#define LPFC_MAX_HOST 256

#ifndef SLI_IOCB_USE_TXQ
#define SLI_IOCB_USE_TXQ    1       /* Queue IOCB to txq if cmd ring full */
#endif

#ifndef FC_BYPASSED_MODE
#define FC_BYPASSED_MODE    0x8000 /* Interface is offline for diag */
#endif

#define LPFC_DFT_POST_IP_BUF            128
#define LPFC_MIN_POST_IP_BUF            64
#define LPFC_MAX_POST_IP_BUF            1024
#define LPFC_DFT_XMT_QUE_SIZE           256
#define LPFC_MIN_XMT_QUE_SIZE           128
#define LPFC_MAX_XMT_QUE_SIZE           10240
#define LPFC_DFT_TOPOLOGY               0
#define LPFC_DFT_FC_CLASS               3

#define LPFC_DFT_NO_DEVICE_DELAY        1	/* 1 sec */
#define LPFC_MAX_NO_DEVICE_DELAY        30	/* 30 sec */
#define LPFC_DFT_EXTRA_IO_TIMEOUT       0
#define LPFC_MAX_EXTRA_IO_TIMEOUT       255	/* 255 sec */
#define LPFC_DFT_LNKDWN_TIMEOUT         30
#define LPFC_MAX_LNKDWN_TIMEOUT         255	/* 255 sec */
#define LPFC_DFT_NODEV_TIMEOUT          20
#define LPFC_MAX_NODEV_TIMEOUT          255	/* 255 sec */
#define LPFC_DFT_RSCN_NS_DELAY          0
#define LPFC_MAX_RSCN_NS_DELAY          255	/* 255 sec */

#define LPFC_MAX_HBA_Q_DEPTH            10240	/* max cmds allowed per hba */
#define LPFC_DFT_HBA_Q_DEPTH            2048	/* max cmds per hba */
#define LPFC_LC_HBA_Q_DEPTH             1024	/* max cmds per low cost hba */
#define LPFC_LP101_HBA_Q_DEPTH          128	/* max cmds per low cost hba */

#define LPFC_MAX_TGT_Q_DEPTH            10240	/* max cmds allowed per tgt */
#define LPFC_DFT_TGT_Q_DEPTH            0	/* default max cmds per tgt */

#define LPFC_MAX_LUN_Q_DEPTH            128	/* max cmds to allow per lun */
#define LPFC_DFT_LUN_Q_DEPTH            30	/* default max cmds per lun */

#define LPFC_MAX_DQFULL_THROTTLE        1	/* Boolean (max value) */

#define LPFC_MAX_DISC_THREADS           64	/* max outstanding discovery els
						   requests */
#define LPFC_DFT_DISC_THREADS           32	/* default outstanding discovery
						   els requests */

#define LPFC_MAX_NS_RETRY               3	/* Try to get to the NameServer
						   3 times and then give up. */

#define LPFC_MAX_SCSI_REQ_TMO           255	/* Max timeout value for SCSI
						   passthru requests */
#define LPFC_DFT_SCSI_REQ_TMO           30	/* Default timeout value for
						   SCSI passthru requests */

#define LPFC_MAX_TARGET                 256	/* max nunber of targets
						   supported */
#define LPFC_DFT_MAX_TARGET             256	/* default max number of targets
						   supported */

#define LPFC_DFT_MAX_LUN                32768	/* default max number of LUNs
						   supported */

/*
 * This file declares the functions exported by lpfc_misc.c
 */

struct lpfc_nodelist *lpfc_findnode_wwpn(struct lpfc_hba *, uint32_t,
				    struct lpfc_name *);
struct lpfc_nodelist *lpfc_findnode_wwnn(struct lpfc_hba *, uint32_t,
				    struct lpfc_name *);

int
lpfc_issue_ct_rsp(struct lpfc_hba * phba, uint32_t tag, struct lpfc_dmabuf * bmp,
		  DMABUFEXT_t * inp);

void
lpfc_sli_wake_iocb_wait(struct lpfc_hba *, struct lpfc_iocbq *,
				    struct lpfc_iocbq *);
void
lpfc_sli_wake_mbox_wait(struct lpfc_hba * phba, LPFC_MBOXQ_t * pmboxq);

int
lpfc_sleep(struct lpfc_hba * phba, void *wait_q_head, long tmo);

/* Forward declarations to prevent compiler warnings */
int lpfc_scsi_lun_reset(struct lpfc_scsi_buf *, struct lpfc_hba *, uint32_t);
int lpfc_scsi_tgt_reset(struct lpfc_scsi_buf *, struct lpfc_hba *, uint32_t);
struct lpfc_iocbq *lpfc_prep_els_iocb(struct lpfc_hba *, uint8_t expectRsp,
				      uint16_t, uint8_t, struct lpfc_nodelist *,
				      uint32_t, uint32_t);
struct lpfc_bindlist *lpfc_assign_scsid(struct lpfc_hba *,
					struct lpfc_nodelist *, int);
struct  lpfc_scsi_buf * lpfc_get_scsi_buf(struct lpfc_hba *phba, int gfp_flags);
int lpfc_geportname(struct lpfc_name * pn1, struct lpfc_name * pn2);
int lpfc_sli_brdready(struct lpfc_hba * phba, uint32_t mask);

#define LPFC_EXTERNAL_RESET 1
#define LPFC_ISSUE_LUN_RESET 2
#define LPFC_ISSUE_ABORT_TSET 4

#define TRUE 1
#define FALSE 0
/* values for a_flag */
#define CFG_EXPORT      0x1	/* Export this parameter to the end user */
#define CFG_IGNORE      0x2	/* Ignore this parameter */
#define CFG_DEFAULT     0x8000	/* Reestablishing Link */

/* values for a_changestate */
#define CFG_REBOOT      0x0	/* Changes effective after ystem reboot */
#define CFG_DYNAMIC     0x1	/* Changes effective immediately */
#define CFG_RESTART     0x2	/* Changes effective after driver restart */

#define LPFC_SCSI_BUF_SZ        1024  /* used for driver generated scsi cmds */
#define LPFC_SCSI_PAGE_BUF_SZ   4096  /* used for driver RPTLUN cmds */
#define LPFC_INQSN_SZ           64    /* Max size of Inquiry serial number */

/* 
   This is the context structure used for a timed-out iocb
   to free resources used for the iocb.
*/
void
lpfc_ioctl_timeout_iocb_cmpl(struct lpfc_hba *,
			     struct lpfc_iocbq *, struct lpfc_iocbq *);

struct lpfc_timedout_iocb_ctxt {
       struct lpfc_iocbq *rspiocbq;
       struct lpfc_dmabuf *mp;
       struct lpfc_dmabuf *bmp;
       struct lpfc_scsi_buf *lpfc_cmd;
       DMABUFEXT_t *outdmp;
       DMABUFEXT_t *indmp;
};

struct lpfc_hba * lpfc_get_phba_by_inst(int inst);

#endif				/* _H_LPFC_MISC */

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
 * $Id: lpfc_util_ioctl.h 3088 2007-11-02 13:51:08Z sf_support $
 */

#ifndef  _H_LPFC_UTIL_IOCTL
#define _H_LPFC_UTIL_IOCTL

int lpfc_process_ioctl_util(LPFCCMDINPUT_t *cip);
int lpfc_ioctl_write_pci(struct lpfc_hba *, LPFCCMDINPUT_t *);
int lpfc_ioctl_read_pci(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_write_mem(struct lpfc_hba *, LPFCCMDINPUT_t *);
int lpfc_ioctl_read_mem(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_write_ctlreg(struct lpfc_hba *, LPFCCMDINPUT_t *);
int lpfc_ioctl_read_ctlreg(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_setdiag(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_send_scsi_fcp(struct lpfc_hba *, LPFCCMDINPUT_t *);
int lpfc_ioctl_send_els(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_send_mgmt_rsp(struct lpfc_hba *, LPFCCMDINPUT_t *);
int lpfc_ioctl_send_mgmt_cmd(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_mbox(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_linkinfo(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_ioinfo(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_nodeinfo(struct lpfc_hba *, LPFCCMDINPUT_t *, void *, int);
int lpfc_ioctl_getcfg(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_setcfg(struct lpfc_hba *, LPFCCMDINPUT_t *);
int lpfc_ioctl_hba_get_event(struct lpfc_hba *, LPFCCMDINPUT_t *, void *, int);
int lpfc_ioctl_hba_set_event(struct lpfc_hba *, LPFCCMDINPUT_t *);
int lpfc_ioctl_del_bind(struct lpfc_hba *, LPFCCMDINPUT_t *);
int lpfc_ioctl_list_bind(struct lpfc_hba *, LPFCCMDINPUT_t *, void *, int *);
int lpfc_ioctl_get_vpd(struct lpfc_hba *, LPFCCMDINPUT_t *, void *, int *);
int lpfc_ioctl_get_dumpregion(struct lpfc_hba *, LPFCCMDINPUT_t  *, void *, int *);
int lpfc_ioctl_get_lpfcdfc_info(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_loopback_mode(struct lpfc_hba *, LPFCCMDINPUT_t  *, void *);
int lpfc_ioctl_loopback_test(struct lpfc_hba *, LPFCCMDINPUT_t  *, void *);
int dfc_rsp_data_copy(struct lpfc_hba *, uint8_t *, DMABUFEXT_t *, uint32_t);
DMABUFEXT_t *dfc_cmd_data_alloc(struct lpfc_hba *, char *, struct ulp_bde64*,
				uint32_t);
DMABUFEXT_t *dfc_fcp_cmd_data_alloc(struct lpfc_hba *, char *, struct ulp_bde64*,
				uint32_t, struct lpfc_dmabuf *);

int dfc_cmd_data_free(struct lpfc_hba *, DMABUFEXT_t *);

#endif

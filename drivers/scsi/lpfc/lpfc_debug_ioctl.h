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
 * $Id: lpfc_debug_ioctl.h 2757 2005-12-09 18:21:44Z sf_support $
 */

#ifndef H_LPFC_DFC_IOCTL
#define H_LPFC_DFC_IOCTL
int lpfc_process_ioctl_dfc(LPFCCMDINPUT_t * cip);
int lpfc_ioctl_lip(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_inst(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_listn(struct lpfc_hba *, LPFCCMDINPUT_t *,  void *, int);
int lpfc_ioctl_read_bplist(struct lpfc_hba *, LPFCCMDINPUT_t *, void *, int);
int lpfc_ioctl_reset(struct lpfc_hba *, LPFCCMDINPUT_t *);
int lpfc_ioctl_read_hba(struct lpfc_hba *, LPFCCMDINPUT_t *, void *, int);
int lpfc_ioctl_stat(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
#endif

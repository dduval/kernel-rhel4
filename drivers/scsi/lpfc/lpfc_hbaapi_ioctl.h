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
 * $Id: lpfc_hbaapi_ioctl.h 2757 2005-12-09 18:21:44Z sf_support $
 */

#include "hbaapi.h"
#ifndef H_LPFC_HBAAPI_IOCTL
#define H_LPFC_HBAAPI_IOCTL
int lpfc_process_ioctl_hbaapi(LPFCCMDINPUT_t *cip);
int lpfc_ioctl_hba_adapterattributes(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_hba_portattributes(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_hba_portstatistics(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_hba_wwpnportattributes(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_hba_discportattributes(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_hba_indexportattributes(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_hba_setmgmtinfo(struct lpfc_hba *, LPFCCMDINPUT_t *);
int lpfc_ioctl_hba_getmgmtinfo(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_hba_refreshinfo(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_hba_rnid(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_hba_getevent(struct lpfc_hba *, LPFCCMDINPUT_t *, void *);
int lpfc_ioctl_hba_fcptargetmapping(struct lpfc_hba *, LPFCCMDINPUT_t *, void *, int *);
int lpfc_ioctl_port_attrib(struct lpfc_hba *, void *);
int lpfc_ioctl_found_port(struct lpfc_hba *, struct lpfc_nodelist *, void *, MAILBOX_t *, HBA_PORTATTRIBUTES *);
#endif

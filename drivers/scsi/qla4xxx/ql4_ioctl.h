/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2007 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */

#ifndef _QL4_IOCTL_H_
#define _QL4_IOCTL_H_

#include <linux/blkdev.h>
#include <asm/uaccess.h>

/*---------------------------------------------------------------------------*/

typedef struct {
	int cmd;
	char *s;
} ioctl_tbl_row_t;

#define	QL_KMEM_ZALLOC(siz)	ql4_kzmalloc((siz), GFP_ATOMIC)
#define	QL_KMEM_FREE(ptr)	kfree((ptr))

/* Defines for Passthru */
#define IOCTL_INVALID_STATUS			0xffff
#define IOCTL_PASSTHRU_TOV			60

/*
 * extern from ql4_xioctl.c
 */
extern void *
Q64BIT_TO_PTR(uint64_t);

extern void *
ql4_kzmalloc(int, int);

extern char *
IOCTL_TBL_STR(int, int);

extern int
qla4xxx_alloc_ioctl_mem(scsi_qla_host_t *);

extern void
qla4xxx_free_ioctl_mem(scsi_qla_host_t *);

extern int
qla4xxx_get_ioctl_scrap_mem(scsi_qla_host_t *, void **, uint32_t);

extern void
qla4xxx_free_ioctl_scrap_mem(scsi_qla_host_t *);

/*
 * from ql4_inioct.c
 */
extern ioctl_tbl_row_t IOCTL_SCMD_IGET_DATA_TBL[];
extern ioctl_tbl_row_t IOCTL_SCMD_ISET_DATA_TBL[];

extern int
qla4intioctl_logout_iscsi(scsi_qla_host_t *, EXT_IOCTL_ISCSI *);

extern int
qla4intioctl_copy_fw_flash(scsi_qla_host_t *, EXT_IOCTL_ISCSI *);

extern int
qla4intioctl_iocb_passthru(scsi_qla_host_t *, EXT_IOCTL_ISCSI *);

extern int
qla4intioctl_ping(scsi_qla_host_t *, EXT_IOCTL_ISCSI *);

extern int
qla4intioctl_get_data(scsi_qla_host_t *, EXT_IOCTL_ISCSI *);

extern int
qla4intioctl_set_data(scsi_qla_host_t *, EXT_IOCTL_ISCSI *);

extern int
qla4intioctl_hba_reset(scsi_qla_host_t *, EXT_IOCTL_ISCSI *);

#endif

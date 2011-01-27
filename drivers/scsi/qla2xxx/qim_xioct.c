/******************************************************************************
 *                  QLOGIC LINUX SOFTWARE
 *
 * QLogic ioctl module for ISP2x00 device driver for Linux 2.6.x
 * Copyright (C) 2005 QLogic Corporation
 * (www.qlogic.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 ******************************************************************************/

#include "qim_def.h"
#include "exioct.h"
#include "inioct.h"
#include "qim_sup.h"
#include "qim_mbx.h"
#include "qlfo.h"

#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <scsi/scsi_tcq.h>
#include <asm/uaccess.h>


#define QLA_PT_CMD_TOV		66
int ql2xioctltimeout = QLA_PT_CMD_TOV;
#define QLA_PT_CMD_DRV_TOV		(ql2xioctltimeout + 1) /* drv timeout */
#define QLA_IOCTL_ACCESS_WAIT_TIME	(ql2xioctltimeout + 10) /* wait_q tov */
#define QLA_INITIAL_IOCTLMEM_SIZE	8192
#define QLA_IOCTL_SCRAP_SIZE		16384 /* scrap memory for local use. */

/* ELS related defines */
#define FC_HEADER_LEN		24
#define ELS_RJT_LENGTH		0x08	/* 8  */
#define ELS_RPS_ACC_LENGTH	0x40	/* 64 */
#define ELS_RLS_ACC_LENGTH	0x1C	/* 28 */

/* ELS cmd Reply Codes */
#define ELS_STAT_LS_RJT		0x01
#define ELS_STAT_LS_ACC		0x02

#define IOCTL_INVALID_STATUS    0xffff


int extended_error_logging = 0;

/*
 * From qim_fo.c
 */
extern int
qim_fo_ioctl(struct qla_host_ioctl *, int, EXT_IOCTL *, int);

/*
 * From qim_inioctl.c
 */
extern int qim_read_nvram(struct qla_host_ioctl *, EXT_IOCTL *, int);
extern int qim_update_nvram(struct qla_host_ioctl *, EXT_IOCTL *, int);
extern int qim_send_loopback(struct qla_host_ioctl *, EXT_IOCTL *, int);
extern int qim_read_option_rom(struct qla_host_ioctl *, EXT_IOCTL *, int);
extern int qim_update_option_rom(struct qla_host_ioctl *, EXT_IOCTL *, int);
extern int qim_get_option_rom_layout(struct qla_host_ioctl *, EXT_IOCTL *, int);
extern int qim_get_vpd(struct qla_host_ioctl *, EXT_IOCTL *, int);
extern int qim_update_vpd(struct qla_host_ioctl *, EXT_IOCTL *, int);
extern int qim2x00_update_port_param(struct qla_host_ioctl *, EXT_IOCTL *, int);

/*
 * Local prototypes
 */
static int qim_get_new_ioctl_dma_mem(struct qla_host_ioctl *, uint32_t);

static int qim_find_curr_ha(uint16_t, struct qla_host_ioctl **);

static int qim_get_driver_specifics(EXT_IOCTL *, struct qla_host_ioctl *);

#if 0
static int qim_aen_reg(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_aen_get(struct qla_host_ioctl *, EXT_IOCTL *, int);
#endif

static int qim_query(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_query_hba_node(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_query_hba_port(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_query_disc_port(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_query_disc_tgt(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_query_chip(struct qla_host_ioctl *, EXT_IOCTL *, int);

static int qim_get_data(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_get_statistics(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_get_fc_statistics(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_get_port_summary(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_get_fcport_summary(struct qla_host_ioctl *, EXT_DEVICEDATAENTRY *,
    void *, uint32_t, uint32_t, uint32_t *, uint32_t *);
/*
static int qim_std_missing_port_summary(struct qla_host_ioctl *,
    EXT_DEVICEDATAENTRY *, void *, uint32_t, uint32_t *, uint32_t *);
*/
static int qim_query_driver(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_query_fw(struct qla_host_ioctl *, EXT_IOCTL *, int);

static int qim_msiocb_passthru(struct qla_host_ioctl *, EXT_IOCTL *, int, int);
#if 0
static int qim_send_els_passthru(struct qla_host_ioctl *, EXT_IOCTL *,
    struct scsi_cmnd *, fc_port_t *, fc_lun_t *, int);
#endif
static int qim_send_fcct(struct qla_host_ioctl *, EXT_IOCTL *,
    struct scsi_cmnd *, fc_port_t *, fc_lun_t *, int);
static int qim_ioctl_ms_queuecommand(struct qla_host_ioctl *, EXT_IOCTL *,
    struct scsi_cmnd *, fc_port_t *, fc_lun_t *, EXT_ELS_PT_REQ *);
static int qim_start_ms_cmd(struct qla_host_ioctl *, EXT_IOCTL *, srb_t *,
    EXT_ELS_PT_REQ *);

static int qim_wwpn_to_scsiaddr(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_scsi_passthru(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_sc_scsi_passthru(struct qla_host_ioctl *, EXT_IOCTL *,
    struct scsi_cmnd *, struct scsi_device *, int);
static int qim_sc_fc_scsi_passthru(struct qla_host_ioctl *, EXT_IOCTL *,
    struct scsi_cmnd *, struct scsi_device *, int);
#if 0
static int qim_sc_scsi3_passthru(struct qla_host_ioctl *, EXT_IOCTL *,
    struct scsi_cmnd *, struct scsi_device *, int);
#endif
static int qim_ioctl_scsi_queuecommand(struct qla_host_ioctl *, EXT_IOCTL *,
    struct scsi_cmnd *, struct scsi_device *, fc_port_t *, fc_lun_t *);

static int qim_send_els_rnid(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_get_rnid_params(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_set_host_data(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_set_rnid_params(struct qla_host_ioctl *, EXT_IOCTL *, int);

#if 0
static int qim_get_led_state(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_set_led_state(struct qla_host_ioctl *, EXT_IOCTL *, int);
static int qim_set_led_23xx(struct qla_host_ioctl *, EXT_BEACON_CONTROL *,
    uint32_t *, uint32_t *);
static int qim_set_led_24xx(struct qla_host_ioctl *, EXT_BEACON_CONTROL *,
    uint32_t *, uint32_t *);
#endif

static srb_t *
qim_get_new_sp(scsi_qla_host_t *);


void *
Q64BIT_TO_PTR(uint64_t buf_addr, uint16_t addr_mode)
{
#if (defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)) || !defined(CONFIG_64BIT)
	union ql_doublelong {
		struct {
			uint32_t	lsl;
			uint32_t	msl;
		} longs;
		uint64_t	dl;
	};

	union ql_doublelong tmpval;

	tmpval.dl = buf_addr;

#if defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)
	/* 32bit user - 64bit kernel */
	if (addr_mode == EXT_DEF_ADDR_MODE_32) {
		DEBUG9(printk("%s: got 32bit user address.\n", __func__);)
		return((void *)(uint64_t)(tmpval.longs.lsl));
	} else {
		DEBUG9(printk("%s: got 64bit user address.\n", __func__);)
		return((void *)buf_addr);
	}
#else
	return((void *)(tmpval.longs.lsl));
#endif
#else
	return((void *)buf_addr);
#endif
}

void
qim_dump_buffer(uint8_t * b, uint32_t size) 
{
	uint32_t cnt;
	uint8_t c;

	printk(" 0   1   2   3   4   5   6   7   8   9  "
	    "Ah  Bh  Ch  Dh  Eh  Fh\n");
	printk("----------------------------------------"
	    "----------------------\n");

	for (cnt = 0; cnt < size;) {
		c = *b++;
		printk("%02x",(uint32_t) c);
		cnt++;
		if (!(cnt % 16))
			printk("\n");
		else
			printk("  ");
	}
	if (cnt % 16)
		printk("\n");
}

/*****************************************************************************/

/*
 * qim_ioctl_sleep_done
 *
 * Description:
 *   This is the callback function to wakeup ioctl completion semaphore
 *   for the ioctl request that is waiting.
 *
 * Input:
 *   sem - pointer to the ioctl completion semaphore.
 *
 * Returns:
 */
static void
qim_ioctl_sleep_done(struct semaphore * sem)
{
	DEBUG9(printk("%s: entered.\n", __func__);)

	if (sem != NULL){
		DEBUG9(printk("ioctl_sleep: wake up sem.\n");)
		up(sem);
	}

	DEBUG9(printk("%s: exiting.\n", __func__);)
}

/*
 * qim_ioctl_sem_init
 *
 * Description:
 *   Initialize the ioctl timer and semaphore used to wait for passthru
 *   completion.
 *
 * Input:
 *   ha - pointer to struct qla_host_ioctl structure used for initialization.
 *
 * Returns:
 *   None.
 */
static void
qim_ioctl_sem_init(struct qla_host_ioctl *ha)
{
	init_MUTEX_LOCKED(&ha->ioctl->cmpl_sem);
	init_timer(&(ha->ioctl->cmpl_timer));
	ha->ioctl->cmpl_timer.data = (unsigned long)&ha->ioctl->cmpl_sem;
	ha->ioctl->cmpl_timer.function =
	    (void (*)(unsigned long))qim_ioctl_sleep_done;
}

static uint32_t
qim_match_drha_to_ha(struct scsi_qla_host *drha, struct qla_host_ioctl **ha)
{
	uint32_t		found = FALSE;
	struct qla_host_ioctl	*tmp_ha;
	struct list_head	*ioctll;

	list_for_each(ioctll, &qim_haioctl_list) {
		tmp_ha = list_entry(ioctll, struct qla_host_ioctl, list);
		if (tmp_ha->dr_data == drha) {
			*ha = tmp_ha;
			found = TRUE;
			break;
		}
	}

	DEBUG9(printk(
	    "qim_match_drha_to_ha: returning found=%d ha=%p.\n",
	    found, *ha);)

	return (found);
}

/*
 * qim_scsi_pt_done
 *
 * Description:
 *   Resets ioctl progress flag and wakes up the ioctl completion semaphore.
 *
 * Input:
 *   pscsi_cmd - pointer to the passthru Scsi cmd structure which has completed.
 *
 * Returns:
 */
static void
qim_scsi_pt_done(struct scsi_cmnd *pscsi_cmd)
{
	struct Scsi_Host *host;
	struct qla_host_ioctl  *ha;
	struct scsi_qla_host  *dr_ha;

	DEBUG9(printk("%s post function entered.\n", __func__);)

	host = pscsi_cmd->device->host;
	dr_ha = (struct scsi_qla_host *) host->hostdata;

	DEBUG9(printk("%s post function going to match ha to drha %p.\n",
	    __func__, dr_ha);)

	if (qim_match_drha_to_ha(dr_ha, &ha) == TRUE) {

		DEBUG9(printk("%s(%ld): got ha=%p.\n",
		    __func__, ha->host_no, ha);)

		/* save detail status for IOCTL reporting */
		ha->ioctl->SCSIPT_InProgress = 0;
		ha->ioctl->ioctl_tov = 0;
		ha->ioctl_err_cmd = NULL;

		DEBUG9(printk("%s post function going to signal wake up.\n",
		    __func__);)
		up(&ha->ioctl->cmpl_sem);
	}

	DEBUG9(printk("%s: exiting.\n", __func__);)

	return;
}

/*
 * qim_msiocb_done
 *
 * Description:
 *   Resets MSIOCB ioctl progress flag and wakes up the ioctl completion
 *   semaphore.
 *
 * Input:
 *   cmd - pointer to the passthru Scsi cmd structure which has completed.
 *
 * Returns:
 */
static void
qim_msiocb_done(struct scsi_cmnd *pscsi_cmd)
{
	struct Scsi_Host *host;
	struct qla_host_ioctl  *ha;

	host = pscsi_cmd->device->host;
	ha = (struct qla_host_ioctl *) host->hostdata;

	DEBUG9(printk("%s post function called OK\n", __func__);)

	ha->ioctl->MSIOCB_InProgress = 0;
	ha->ioctl->ioctl_tov = 0;

	up(&ha->ioctl->cmpl_sem);

	DEBUG9(printk("%s: exiting.\n", __func__);)
		
	return;
}

static uint32_t
qim_get_host_count(void)
{
	uint32_t		host_count = 0;
	struct list_head	*hal;

	list_for_each(hal, *qim_hostlist_ptr)
		host_count++;

	DEBUG9(printk(
	    "qim_get_host_count: returning host_count=%d.\n",
	    host_count);)

	return (host_count);
}

static int
qim_validate_hostptr(struct qla_host_ioctl *ha)
{
	int			ret = 0;
	struct list_head	*hal;
	struct scsi_qla_host	*drvr_ha;


	DEBUG9(printk(
	    "qim_validate_hostptr: entered. assumed got hostlist lock.\n");)

	/* Allocate our host_ioctl list */
	list_for_each(hal, *qim_hostlist_ptr) {
		drvr_ha = list_entry(hal, struct scsi_qla_host, list);
		if (drvr_ha == ha->dr_data &&
		    drvr_ha->host_no == ha->host_no) {
			/* our dr_data is assumed still valid */
			break;
		}
	}

	if (hal == NULL) {
		/* not found. our dr_data is assumed no longer valid */
		ret = -1;
	}

	DEBUG9(printk("qim_validate_hostptr: exiting.\n");)

	return (ret);
}


/*************************************************************************
 * qim_send_ioctl
 *
 * Description:
 *   Performs additional ioctl requests not satisfied by the upper levels.
 *
 * Returns:
 *   ret  = 0    Success
 *   ret != 0    Failed; detailed status copied to EXT_IOCTL structure
 *               if possible
 *************************************************************************/
int
qim_send_ioctl(struct scsi_device *dev, int cmd, void *arg)
{
	int		mode = 0;
	int		tmp_rval = 0;
	int		ret = -EINVAL;

	uint8_t		*temp;
	uint8_t		tempbuf[8];
	uint8_t		wait_cnt;
	uint32_t	i;
	uint32_t	num_hosts = 0;
	uint32_t	status;

	EXT_IOCTL	*pext;

	struct qla_host_ioctl	*ha;


	DEBUG9(printk("%s: entry to command (%x), arg (%p)\n",
	    __func__, cmd, arg);)

	/* Catch any non-exioct ioctls */
	if (_IOC_TYPE(cmd) != QLMULTIPATH_MAGIC) {
		return (ret);
	}

	/* Allocate ioctl structure buffer to support multiple concurrent
	 * entries.
	 */
	pext = kmalloc(sizeof(EXT_IOCTL), GFP_KERNEL);
	if (pext == NULL) {
		/* error */
		printk(KERN_WARNING
		    "qim: ERROR in main ioctl buffer allocation.\n");
		return (-ENOMEM);
	}

	DEBUG9(printk("%s: going to copy from user.\n",
	    __func__);)

	/* copy in application layer EXT_IOCTL */
	ret = copy_from_user(pext, arg, sizeof(EXT_IOCTL));
	if (ret) {
		DEBUG9_10(printk("%s: ERROR COPY_FROM_USER "
		    "EXT_IOCTL sturct. cmd=%x arg=%p.\n",
		    __func__, cmd, arg);)

		kfree(pext);
		return (ret);
	}

	/* check signature of this ioctl */
	temp = (uint8_t *) &pext->Signature;

	for (i = 0; i < 4; i++, temp++)
		tempbuf[i] = *temp;

	if ((tempbuf[0] == 'Q') && (tempbuf[1] == 'L') &&
	    (tempbuf[2] == 'O') && (tempbuf[3] == 'G'))
		status = 0;
	else
		status = 1;

	if (status != 0) {
		DEBUG9_10(printk("%s: signature did not match. "
		    "cmd=%x arg=%p.\n", __func__, cmd, arg);)
		pext->Status = EXT_STATUS_INVALID_PARAM;
		if ((ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL))) != 0) {
			ret = -EFAULT;
		}

		kfree(pext);
		return (ret);
	}

	/* check version of this ioctl */
	if (pext->Version > EXT_VERSION) {
		printk(KERN_WARNING
		    "qim: ioctl interface version not supported = %d.\n",
		    pext->Version);

		kfree(pext);
		return (-EINVAL);
	}

	DEBUG9(printk("%s: verified to be QLOGIC ioctl cmd.\n",
	    __func__);)

	if (!(pext->VendorSpecificData & EXT_DEF_USE_HBASELECT)) {
		/* Not supported */

		DEBUG9_10(printk("%s: ERROR user not using "
		    "EXT_DEF_USE_HBASELECT bit.\n",
		    __func__);)

		pext->Status = EXT_STATUS_INVALID_PARAM;
		if ((ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL))) != 0) {
			ret = -EFAULT;
		}

		kfree(pext);
		return (ret);
	}

	/* check for special cmds used during application's setup time. */
	switch (cmd) {
	case EXT_CC_GET_HBA_CNT:
		DEBUG9(printk("%s: got startioctl command.\n", __func__);)

		read_lock(*qim_hostlist_lock_ptr);
		num_hosts = qim_get_host_count();
		read_unlock(*qim_hostlist_lock_ptr);

		pext->Instance = num_hosts;
		pext->Status = EXT_STATUS_OK;
		ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL));

		kfree(pext);
		return (ret);

	case EXT_CC_SETINSTANCE:
		/* This call is used to return the HBA's host number to
		 * ioctl caller.  All subsequent ioctl commands will put
		 * the host number in HbaSelect field to tell us which
		 * HBA is the destination.
		 */
		DEBUG9(printk("%s: got set_instance cmd.\n",
		    __func__);)

		read_lock(*qim_hostlist_lock_ptr);
		num_hosts = qim_get_host_count();
		read_unlock(*qim_hostlist_lock_ptr);

		if (pext->Instance < num_hosts) {
			/*
			 * Return host number via pext->HbaSelect for
			 * specified API instance number.
			 */
			if (qim_find_curr_ha(pext->Instance, &ha) != 0) {
				pext->Status = EXT_STATUS_DEV_NOT_FOUND;
				ret = copy_to_user(arg, pext,
				    sizeof(EXT_IOCTL));
				DEBUG9_10(printk("%s: SETINSTANCE invalid inst "
				    "%d. num_hosts=%d ha=%p ret=%d.\n",
				    __func__, pext->Instance, num_hosts, ha,
				    ret);)

				kfree(pext);
				return (ret); /* ioctl completed ok */
			}

			pext->HbaSelect = ha->host_no;
			pext->Status = EXT_STATUS_OK;

			DEBUG9(printk("%s: Matching instance %d to hba "
			    "%ld.\n", __func__, pext->Instance, ha->host_no);)
		} else {
			DEBUG9_10(printk("%s: ERROR EXT_SETINSTANCE."
			    " Instance=%d num_hosts=%d ha=%p.\n",
			    __func__, pext->Instance, num_hosts, ha);)

			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		}
		ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL));
		if (ret)
			ret = -EFAULT;
		kfree(pext);

		DEBUG9(printk("%s: SETINSTANCE exiting. ret=%d.\n",
		    __func__, ret);)

		return (ret);

	case EXT_CC_DRIVER_SPECIFIC:
		if (qim_find_curr_ha(pext->HbaSelect, &ha) != 0) {
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
			ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL));
		} else {
			ret = qim_get_driver_specifics(pext, ha);
			tmp_rval = copy_to_user(arg, pext, sizeof(EXT_IOCTL));

			if (ret == 0 && tmp_rval != 0) {
				DEBUG9_10(printk("%s: DRIVER_SPECIFIC copy "
				    "error. tmp_rval=%d.\n",
				    __func__, tmp_rval);)
				ret = -EFAULT;
			}
		}

		DEBUG9(printk("%s: DRIVER_SPECIFIC exiting. ret=%d estat=%d.\n",
		    __func__, ret, pext->Status);)

		kfree(pext);
		return (ret);

	default:
		break;
	}


	/* Use HbaSelect value to get a matching ha instance
	 * for this ioctl command.
	 */
	if (qim_find_curr_ha(pext->HbaSelect, &ha) != 0) {

		DEBUG9_10(printk("%s: ERROR matching pext->HbaSelect "
		    "%d to an HBA Instance.\n",
		    __func__, pext->HbaSelect);)

		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		if ((ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL))) != 0) {
			ret = -EFAULT;
		}

		kfree(pext);
		return (ret);
	}

	DEBUG9(printk("%s: active host_inst=%ld CC=%x SC=%x.\n",
	    __func__, ha->instance, cmd, pext->SubCode);)

	/*
	 * Get permission to process ioctl command. Only one will proceed
	 * at a time.
	 */
	if (qim_down_timeout(&ha->ioctl->access_sem,
	    QLA_IOCTL_ACCESS_WAIT_TIME * HZ) != 0) {
		/* error timed out */
		DEBUG9_10(printk("%s: ERROR timeout getting ioctl "
		    "access. host no=%d.\n", __func__, pext->HbaSelect);)

		pext->Status = EXT_STATUS_BUSY;
		if ((ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL))) != 0)
			ret = -EFAULT;

		kfree(pext);
		return (ret);
	}

	DEBUG9(printk("%s(%ld): going to get read lock on %p.\n",
	    __func__, ha->host_no, *qim_hostlist_lock_ptr);)
	read_lock(*qim_hostlist_lock_ptr);

	if (qim_validate_hostptr(ha) != 0) {
		/* error hba no longer present?? */
		DEBUG9_10(printk("%s: ERROR HBA not found.\n",
		    __func__);)

		read_unlock(*qim_hostlist_lock_ptr);

		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		if ((ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL))) != 0)
			ret = -EFAULT;

		kfree(pext);
		return (ret);
	}

	DEBUG9(printk("%s(%ld): going to test for dpc_active.\n",
	    __func__, ha->host_no);)
	wait_cnt = 0;
	while (test_bit(CFG_ACTIVE, &ha->dr_data->cfg_flags) ||
	    ha->dr_data->dpc_active) {
		if (signal_pending(current))
			break;   /* get out */

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
		wait_cnt++;

		if (wait_cnt >= 5)
			break;
	}

	if (test_bit(CFG_ACTIVE, &ha->dr_data->cfg_flags) ||
	    ha->dr_data->dpc_active) {
		/* error hba not ready */
		DEBUG9_10(printk("%s: ERROR HBA not ready for ioctl "
		    "access. host no=%d.\n", __func__, pext->HbaSelect);)

		read_unlock(*qim_hostlist_lock_ptr);

		pext->Status = EXT_STATUS_HBA_NOT_READY;
		if ((ret = copy_to_user(arg, pext, sizeof(EXT_IOCTL))) != 0)
			ret = -EFAULT;

		kfree(pext);
		return (ret);
	}

	switch (cmd) { /* switch on EXT IOCTL COMMAND CODE */

	case EXT_CC_QUERY:
		DEBUG9(printk("%s: got query command.\n", __func__);)

		ret = qim_query(ha, pext, 0);

		break;

	case EXT_CC_GET_DATA:
		DEBUG9(printk("%s: got get_data command.\n", __func__);)

		ret = qim_get_data(ha, pext, 0);

		break;

	case EXT_CC_SEND_SCSI_PASSTHRU:
		DEBUG9(printk("%s: got SCSI passthru cmd.\n", __func__));

		ret = qim_scsi_passthru(ha, pext, mode);

		break;

#if 0
	case EXT_CC_REG_AEN:
		ret = qim_aen_reg(ha, pext, mode);

		break;

	case EXT_CC_GET_AEN:
		ret = qim_aen_get(ha, pext, mode);

		break;
#endif

	case EXT_CC_WWPN_TO_SCSIADDR:
		ret = qim_wwpn_to_scsiaddr(ha, pext, 0);
		break;

	case EXT_CC_SEND_ELS_PASSTHRU:
		if (IS_QLA2100(ha->dr_data) || IS_QLA2200(ha->dr_data))
			goto fail;
		/*FALLTHROUGH*/
	case EXT_CC_SEND_FCCT_PASSTHRU:
		ret = qim_msiocb_passthru(ha, pext, cmd, mode);

		break;

	case EXT_CC_SEND_ELS_RNID:
		DEBUG9(printk("%s: got ELS RNID cmd.\n", __func__));

		ret = qim_send_els_rnid(ha, pext, mode);
		break;

	case EXT_CC_SET_DATA:
		ret = qim_set_host_data(ha, pext, mode);
		break;                                                          

	case INT_CC_READ_NVRAM:
		ret = qim_read_nvram(ha, pext, mode);
		break;

	case INT_CC_UPDATE_NVRAM:
		ret = qim_update_nvram(ha, pext, mode);
		break;

	case INT_CC_LOOPBACK:
		ret = qim_send_loopback(ha, pext, mode);
		break;

	case INT_CC_READ_OPTION_ROM:
		ret = qim_read_option_rom(ha, pext, mode);
		break;

	case INT_CC_UPDATE_OPTION_ROM:
		ret = qim_update_option_rom(ha, pext, mode);
		break;

	case INT_CC_GET_OPTION_ROM_LAYOUT:
		ret = qim_get_option_rom_layout(ha, pext, mode);
		break; 

	case INT_CC_GET_VPD:
		ret = qim_get_vpd(ha, pext, mode);
		break; 

	case INT_CC_UPDATE_VPD:
		ret = qim_update_vpd(ha, pext, mode);
		break; 

	case INT_CC_PORT_PARAM:
		ret = qim2x00_update_port_param(ha, pext, mode);
		break;

	/* all others go here */
	/*
	   case EXT_CC_PLATFORM_REG:
	   break;
	 */

	/* Failover IOCTLs */
	case FO_CC_GET_PARAMS:
	case FO_CC_SET_PARAMS:
	case FO_CC_GET_PATHS:
	case FO_CC_SET_CURRENT_PATH:
	/*
	case FO_CC_RESET_HBA_STAT:
	case FO_CC_GET_HBA_STAT:
	*/
	case FO_CC_GET_LUN_DATA:
	case FO_CC_SET_LUN_DATA:
	case FO_CC_GET_TARGET_DATA:
	case FO_CC_SET_TARGET_DATA:
		DEBUG9(printk("%s: failover arg (%p):\n", __func__, arg);)

		qim_fo_ioctl(ha, cmd, pext, mode);

		break;

	default:
	fail:
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		break;

	} /* end of CC decode switch */

	read_unlock(*qim_hostlist_lock_ptr);
	DEBUG9(printk("%s(%ld): unlocked hostlist_lock_ptr.\n",
	    __func__, ha->host_no);)

	/* Always try to copy values back regardless what happened before. */
	tmp_rval = copy_to_user(arg, pext, sizeof(EXT_IOCTL));

	if (ret == 0 && tmp_rval != 0)
		ret = -EFAULT;

	DEBUG9(printk("%s: exiting. tmp_rval(%d) ret(%d)\n",
	    __func__, tmp_rval, ret);)

	up(&ha->ioctl->access_sem);

	kfree(pext);
	return (ret);
}

/*
 * qim_alloc_ioctl_mem
 *	Allocates memory needed by IOCTL code.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	qim local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qim_alloc_ioctl_mem(struct qla_host_ioctl *ha)
{
	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (qim_get_new_ioctl_dma_mem(ha, QLA_INITIAL_IOCTLMEM_SIZE) !=
	    QIM_SUCCESS) {
		printk(KERN_WARNING
		    "qim: ERROR in ioctl physical memory allocation\n");

		return QLA_MEMORY_ALLOC_FAILED;
	}

	/* Allocate context memory buffer */
	ha->ioctl = kmalloc(sizeof(struct hba_ioctl), GFP_KERNEL);
	if (ha->ioctl == NULL) {
		/* error */
		printk(KERN_WARNING
		    "qim: ERROR in ioctl context allocation.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(ha->ioctl, 0, sizeof(struct hba_ioctl));

#if 0
/* RLU: this need to be handled later */
	/* Allocate AEN tracking buffer */
	ha->ioctl->aen_tracking_queue =
	    kmalloc(EXT_DEF_MAX_AEN_QUEUE * sizeof(EXT_ASYNC_EVENT), GFP_KERNEL);
	if (ha->ioctl->aen_tracking_queue == NULL) {
		printk(KERN_WARNING
		    "qim: ERROR in ioctl aen_queue allocation.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(ha->ioctl->aen_tracking_queue, 0, 
	    EXT_DEF_MAX_AEN_QUEUE * sizeof(EXT_ASYNC_EVENT));
#endif

	ha->ioctl->ioctl_tq = kmalloc(sizeof(os_tgt_t), GFP_KERNEL);
	if (ha->ioctl->ioctl_tq == NULL) {
		printk(KERN_WARNING
		    "qim: ERROR in ioctl tgt queue allocation.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(ha->ioctl->ioctl_tq, 0, sizeof(os_tgt_t));

	ha->ioctl->ioctl_lq = kmalloc(sizeof(os_lun_t), GFP_KERNEL);
	if (ha->ioctl->ioctl_lq == NULL) {
		printk(KERN_WARNING
		    "qim: ERROR in ioctl lun queue allocation.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(ha->ioctl->ioctl_lq, 0, sizeof(os_lun_t));

	/* Pick the largest size we'll need per ha of all ioctl cmds.
	 * Use this size when freeing.
	 */
	ha->ioctl->scrap_mem = kmalloc(QLA_IOCTL_SCRAP_SIZE, GFP_KERNEL);
	if (ha->ioctl->scrap_mem == NULL) {
		printk(KERN_WARNING
		    "qim: ERROR in ioctl scrap_mem allocation.\n");
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(ha->ioctl->scrap_mem, 0, QLA_IOCTL_SCRAP_SIZE);

	ha->ioctl->scrap_mem_size = QLA_IOCTL_SCRAP_SIZE;
	ha->ioctl->scrap_mem_used = 0;
	DEBUG9(printk("%s(%ld): scrap_mem_size=%d.\n",
	    __func__, ha->host_no, ha->ioctl->scrap_mem_size);)

	ha->ioctl->ioctl_lq->q_state = LUN_STATE_READY;
	ha->ioctl->ioctl_lq->q_lock = SPIN_LOCK_UNLOCKED;

	init_MUTEX(&ha->ioctl->access_sem);

 	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
 	    __func__, ha->host_no, ha->instance);)
  
 	return QIM_SUCCESS;
}

/*
 * qim_get_new_ioctl_dma_mem
 *	Allocates dma memory of the specified size.
 *	This is done to replace any previously allocated ioctl dma buffer.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	qim local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
qim_get_new_ioctl_dma_mem(struct qla_host_ioctl *ha, uint32_t size)
{
	struct scsi_qla_host	*dr_ha = ha->dr_data;

	DEBUG9(printk("%s entered.\n", __func__);)

	if (ha->ioctl_mem) {
		DEBUG9(printk("%s: ioctl_mem was previously allocated. "
		    "Dealloc old buffer.\n", __func__);)

	 	/* free the memory first */
	 	pci_free_consistent(dr_ha->pdev, ha->ioctl_mem_size, ha->ioctl_mem,
		    ha->ioctl_mem_phys);
	}

	/* Get consistent memory allocated for ioctl I/O operations. */
	ha->ioctl_mem = dma_alloc_coherent(&dr_ha->pdev->dev, size,
	    &ha->ioctl_mem_phys, GFP_KERNEL);
	if (ha->ioctl_mem == NULL) {
		printk(KERN_WARNING
		    "%s: ERROR in ioctl physical memory allocation. "
		    "Requested length=%x.\n", __func__, size);

		ha->ioctl_mem_size = 0;
		return QLA_MEMORY_ALLOC_FAILED;
	}
	ha->ioctl_mem_size = size;

	DEBUG9(printk("%s exiting.\n", __func__);)

	return QIM_SUCCESS;
}

/*
 * qim_free_ioctl_mem
 *	Frees memory used by IOCTL code for the specified ha.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
void
qim_free_ioctl_mem(struct qla_host_ioctl *ha)
{
	struct scsi_qla_host	*dr_ha = ha->dr_data;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (ha->ioctl) {
		kfree(ha->ioctl->scrap_mem);
		ha->ioctl->scrap_mem = NULL;
		ha->ioctl->scrap_mem_size = 0;

		kfree(ha->ioctl->ioctl_tq);
		ha->ioctl->ioctl_tq = NULL;

		kfree(ha->ioctl->ioctl_lq);
		ha->ioctl->ioctl_lq = NULL;

#if 0
/* RLU: this need to be handled later */
		kfree(ha->ioctl->aen_tracking_queue);
		ha->ioctl->aen_tracking_queue = NULL;
#endif

		kfree(ha->ioctl);
		ha->ioctl = NULL;
	}

	/* free memory allocated for ioctl operations */
	dma_free_coherent(&dr_ha->pdev->dev, ha->ioctl_mem_size, ha->ioctl_mem,
	    ha->ioctl_mem_phys);
	ha->ioctl_mem = NULL;

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

}

/*
 * qim_get_ioctl_scrap_mem
 *	Returns pointer to memory of the specified size from the scrap buffer.
 *	This can be called multiple times before the free call as long
 *	as the memory is to be used by the same ioctl command and
 *	there's still memory left in the scrap buffer.
 *
 * Input:
 *	ha = adapter state pointer.
 *	ppmem = pointer to return a buffer pointer.
 *	size = size of buffer to return.
 *
 * Returns:
 *	qim local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qim_get_ioctl_scrap_mem(struct qla_host_ioctl *ha, void **ppmem, uint32_t size)
{
	int		ret = QIM_SUCCESS;
	uint32_t	free_mem;

	DEBUG9(printk("%s(%ld): inst=%ld entered. size=%d.\n",
	    __func__, ha->host_no, ha->instance, size);)

	free_mem = ha->ioctl->scrap_mem_size - ha->ioctl->scrap_mem_used;
	if (free_mem >= size) {
		*ppmem = ha->ioctl->scrap_mem + ha->ioctl->scrap_mem_used;
		ha->ioctl->scrap_mem_used += size;
	} else {
		DEBUG10(printk("%s(%ld): no more scrap memory.\n",
		    __func__, ha->host_no);)

		ret = QIM_FAILED;
	}

	DEBUG9(printk("%s(%ld): exiting. ret=%d.\n",
	    __func__, ha->host_no, ret);)

	return (ret);
}

/*
 * qim_free_ioctl_scrap_mem
 *	Makes the entire scrap buffer free for use.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	qim local function return status code.
 *
 */
void
qim_free_ioctl_scrap_mem(struct qla_host_ioctl *ha)
{
	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	memset(ha->ioctl->scrap_mem, 0, ha->ioctl->scrap_mem_size);
	ha->ioctl->scrap_mem_used = 0;

	DEBUG9(printk("%s(%ld): exiting.\n",
	    __func__, ha->host_no);)
}

/*
 * qim_find_curr_ha
 *	Searches and returns the pointer to the adapter host_no specified.
 *
 * Input:
 *	host_inst = driver internal adapter instance number to search.
 *	ha = adapter state pointer of the instance requested.
 *
 * Returns:
 *	qim local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qim_find_curr_ha(uint16_t host_inst, struct qla_host_ioctl **ret_ha)
{
	int	rval = QIM_SUCCESS;
	int	found;
	struct list_head	*ioctll;
	struct qla_host_ioctl	*search_ha = NULL;

	/*
 	 * Set ha context for this IOCTL by matching host_no.
	 */
	found = 0;
	read_lock(&qim_haioctl_list_lock);
	list_for_each(ioctll, &qim_haioctl_list) {
		search_ha = list_entry(ioctll, struct qla_host_ioctl, list);

		if (search_ha->instance == host_inst) {
			found++;
			break;
		}
	}
	read_unlock(&qim_haioctl_list_lock);

	if (!found) {
 		DEBUG10(printk("%s: ERROR matching host_inst "
 		    "%d to an HBA Instance.\n", __func__, host_inst);)
		rval = QIM_FAILED;
	} else {
		DEBUG9(printk("%s: found matching host_inst "
		    "%d to an HBA Instance.\n", __func__, host_inst);)
		*ret_ha = search_ha;
	}

	return rval;
}

/*
 * qim_get_driver_specifics
 *	Returns driver specific data in the response buffer.
 *
 * Input:
 *	pext = pointer to EXT_IOCTL structure containing values from user.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_get_driver_specifics(EXT_IOCTL *pext, struct qla_host_ioctl *ha)
{
	int			ret = 0;
	EXT_LN_DRIVER_DATA	data;

	DEBUG9(printk("%s: entered.\n", __func__);)

	if (pext->ResponseLen < sizeof(EXT_LN_DRIVER_DATA)) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk("%s: ERROR ResponseLen too small.\n",
		    __func__);)

		return (ret);
	}

	data.DrvVer.Major = ha->drv_major;
	data.DrvVer.Minor = ha->drv_minor;
	data.DrvVer.Patch = ha->drv_patch;
	data.DrvVer.Beta = ha->drv_beta;

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    &data, sizeof(EXT_LN_DRIVER_DATA));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s: ERROR copy resp buf = %d.\n",
		    __func__, ret);)
		ret = -EFAULT;
	} else {
		pext->Status = EXT_STATUS_OK;
	}

	DEBUG9(printk("%s: exiting. ret=%d.\n", __func__, ret);)

	return (ret);
}

#if 0
/*
 * qim_aen_reg
 *	IOCTL management server Asynchronous Event Tracking Enable/Disable.
 *
 * Input:
 *	ha = pointer to the adapter struct of the adapter to register.
 *	cmd = pointer to EXT_IOCTL structure containing values from user.
 *	mode = flags. not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_aen_reg(struct qla_host_ioctl *ha, EXT_IOCTL *cmd, int mode)
{
	int		rval = 0;
	EXT_REG_AEN	reg_struct;

	DEBUG9(printk("%s(%ld): inst %ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	rval = copy_from_user(&reg_struct, Q64BIT_TO_PTR(cmd->RequestAdr,
	    cmd->AddrMode), sizeof(EXT_REG_AEN));
	if (rval == 0) {
		cmd->Status = EXT_STATUS_OK;
		if (reg_struct.Enable) {
			ha->ioctl->flags |= IOCTL_AEN_TRACKING_ENABLE;
		} else {
			ha->ioctl->flags &= ~IOCTL_AEN_TRACKING_ENABLE;
		}
	} else {
		DEBUG9(printk("%s(%ld): inst %ld copy error=%d.\n",
		    __func__, ha->host_no, ha->instance, rval);)

		cmd->Status = EXT_STATUS_COPY_ERR;
		rval = -EFAULT;
	}

	DEBUG9(printk("%s(%ld): inst %ld reg_struct.Enable(%d) "
	    "ha->ioctl_flag(%x) cmd->Status(%d).",
	    __func__, ha->host_no, ha->instance, reg_struct.Enable,
	    ha->ioctl->flags, cmd->Status);)

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (rval);
}

/*
 * qim_aen_get
 *	Asynchronous Event Record Transfer to user.
 *	The entire queue will be emptied and transferred back.
 *
 * Input:
 *	ha = pointer to the adapter struct of the specified adapter.
 *	pext = pointer to EXT_IOCTL structure containing values from user.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 *
 * NOTE: Need to use hardware lock to protect the queues from updates
 *	 via isr/enqueue_aen after we get rid of io_request_lock.
 */
static int
qim_aen_get(struct qla_host_ioctl *ha, EXT_IOCTL *cmd, int mode)
{
	int		rval = 0;
	EXT_ASYNC_EVENT	*tmp_q;
	EXT_ASYNC_EVENT	*paen;
	uint8_t		i;
	uint8_t		queue_cnt;
	uint8_t		request_cnt;
	uint32_t	stat = EXT_STATUS_OK;
	uint32_t	ret_len = 0;
	unsigned long   cpu_flags = 0;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	request_cnt = (uint8_t)(cmd->ResponseLen / sizeof(EXT_ASYNC_EVENT));

	if (request_cnt < EXT_DEF_MAX_AEN_QUEUE) {
		/* We require caller to alloc for the maximum request count */
		cmd->Status       = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk("%s(%ld): inst=%ld Buffer size %ld too small. "
		    "Exiting normally.",
		    __func__, ha->host_no, ha->instance,
		    (ulong)cmd->ResponseLen);)

		return (rval);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&paen,
	    sizeof(EXT_ASYNC_EVENT) * EXT_DEF_MAX_AEN_QUEUE)) {
		/* not enough memory */
		cmd->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_ASYNC_EVENT)*EXT_DEF_MAX_AEN_QUEUE);)
		return (rval);
	}

	/* 1st: Make a local copy of the entire queue content. */
	tmp_q = (EXT_ASYNC_EVENT *)ha->ioctl->aen_tracking_queue;
	queue_cnt = 0;

	spin_lock_irqsave(&ha->hardware_lock, cpu_flags);
	i = ha->ioctl->aen_q_head;

	for (; queue_cnt < EXT_DEF_MAX_AEN_QUEUE;) {
		if (tmp_q[i].AsyncEventCode != 0) {
			memcpy(&paen[queue_cnt], &tmp_q[i],
			    sizeof(EXT_ASYNC_EVENT));
			queue_cnt++;
			tmp_q[i].AsyncEventCode = 0; /* empty out the slot */
		}

		if (i == ha->ioctl->aen_q_tail) {
			/* done. */
			break;
		}

		i++;

		if (i == EXT_DEF_MAX_AEN_QUEUE) {
			i = 0;
		}
	}

	/* Empty the queue. */
	ha->ioctl->aen_q_head = 0;
	ha->ioctl->aen_q_tail = 0;

	spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);

	/* 2nd: Now transfer the queue content to user buffer */
	/* Copy the entire queue to user's buffer. */
	ret_len = (uint32_t)(queue_cnt * sizeof(EXT_ASYNC_EVENT));
	if (queue_cnt != 0) {
		rval = copy_to_user(Q64BIT_TO_PTR(cmd->ResponseAdr,
		    cmd->AddrMode), paen, ret_len);
	}
	cmd->ResponseLen = ret_len;

	if (rval != 0) {
		DEBUG9_10(printk("%s(%ld): inst=%ld copy FAILED. error = %d\n",
		    __func__, ha->host_no, ha->instance, rval);)
		rval = -EFAULT;
		stat = EXT_STATUS_COPY_ERR;
	} else {
		stat = EXT_STATUS_OK;
	}

	cmd->Status = stat;
	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting. rval=%d.\n",
	     __func__, ha->host_no, ha->instance, rval);)

	return (rval);
}
#endif

#if 0
/*
 * qim_enqueue_aen
 *
 * Input:
 *	ha = adapter state pointer.
 *	event_code = async event code of the event to add to queue.
 *	payload = event payload for the queue.
 *
 * Context:
 *	Interrupt context.
 * NOTE: Need to hold the hardware lock to protect the queues from
 *	 aen_get after we get rid of the io_request_lock.
 */
void
qim_enqueue_aen(struct qla_host_ioctl *ha, uint16_t event_code, void *payload)
{
	uint8_t			new_entry; /* index to current entry */
	uint16_t		*mbx;
	EXT_ASYNC_EVENT		*aen_queue;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (!(ha->ioctl->flags & IOCTL_AEN_TRACKING_ENABLE))
		return;

	aen_queue = (EXT_ASYNC_EVENT *)ha->ioctl->aen_tracking_queue;
	if (aen_queue[ha->ioctl->aen_q_tail].AsyncEventCode != 0) {
		/* Need to change queue pointers to make room. */

		/* Increment tail for adding new entry. */
		ha->ioctl->aen_q_tail++;
		if (ha->ioctl->aen_q_tail == EXT_DEF_MAX_AEN_QUEUE) {
			ha->ioctl->aen_q_tail = 0;
		}

		if (ha->ioctl->aen_q_head == ha->ioctl->aen_q_tail) {
			/*
			 * We're overwriting the oldest entry, so need to
			 * update the head pointer.
			 */
			ha->ioctl->aen_q_head++;
			if (ha->ioctl->aen_q_head == EXT_DEF_MAX_AEN_QUEUE) {
				ha->ioctl->aen_q_head = 0;
			}
		}
	}

	DEBUG9(printk("%s(%ld): inst=%ld Adding code 0x%x to aen_q %p @ %d\n",
	    __func__, ha->host_no, ha->instance, event_code, aen_queue,
	    ha->ioctl->aen_q_tail);)

	new_entry = ha->ioctl->aen_q_tail;
	aen_queue[new_entry].AsyncEventCode = event_code;

		/* Update payload */
	switch (event_code) {
	case MBA_LIP_OCCURRED:
	case MBA_LOOP_UP:
	case MBA_LOOP_DOWN:
	case MBA_LIP_RESET:
	case MBA_PORT_UPDATE:
		/* empty */
		break;

	case MBA_RSCN_UPDATE:
		mbx = (uint16_t *)payload;
		aen_queue[new_entry].Payload.RSCN.AddrFormat = MSB(mbx[1]);
		/* domain */
		aen_queue[new_entry].Payload.RSCN.RSCNInfo[0] = LSB(mbx[1]);
		/* area */
		aen_queue[new_entry].Payload.RSCN.RSCNInfo[1] = MSB(mbx[2]);
		/* al_pa */
		aen_queue[new_entry].Payload.RSCN.RSCNInfo[2] = LSB(mbx[2]);

		break;

	default:
		/* Not supported */
		aen_queue[new_entry].AsyncEventCode = 0;
		break;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)
}
#endif

/*
 * qim_query
 *	Handles all subcommands of the EXT_CC_QUERY command.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_query(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int rval = 0;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	/* All Query type ioctls are done here */
	switch(pext->SubCode) {

	case EXT_SC_QUERY_HBA_NODE:
		/* fill in HBA NODE Information */
		rval = qim_query_hba_node(ha, pext, mode);
		break;

	case EXT_SC_QUERY_HBA_PORT:
		/* return HBA PORT related info */
		rval = qim_query_hba_port(ha, pext, mode);
		break;

	case EXT_SC_QUERY_DISC_PORT:
		/* return discovered port information */
		rval = qim_query_disc_port(ha, pext, mode);
		break;

	case EXT_SC_QUERY_DISC_TGT:
		/* return discovered target information */
		rval = qim_query_disc_tgt(ha, pext, mode);
		break;

	case EXT_SC_QUERY_CHIP:
		rval = qim_query_chip(ha, pext, mode);
		break;

	case EXT_SC_QUERY_DISC_LUN:
		pext->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;

	default:
 		DEBUG9_10(printk("%s(%ld): inst=%ld unknown SubCode %d.\n",
 		    __func__, ha->host_no, ha->instance, pext->SubCode);)
		pext->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;
	}

 	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
 	    __func__, ha->host_no, ha->instance);)
	return rval;
}

/*
 * qim_query_hba_node
 *	Handles EXT_SC_QUERY_HBA_NODE subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_query_hba_node(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint32_t	i, transfer_size;
	EXT_HBA_NODE	*ptmp_hba_node;
	uint8_t		*next_str;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


 	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
 	    __func__, ha->host_no, ha->instance);)

 	if (qim_get_ioctl_scrap_mem(ha, (void **)&ptmp_hba_node,
 	    sizeof(EXT_HBA_NODE))) {
 		/* not enough memory */
 		pext->Status = EXT_STATUS_NO_MEMORY;
 		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
 		    "size requested=%ld.\n",
 		    __func__, ha->host_no, ha->instance,
 		    (ulong)sizeof(EXT_HBA_NODE));)
 		return (ret);
 	}

	/* fill all available HBA NODE Information */
	for (i = 0; i < 8 ; i++)
		ptmp_hba_node->WWNN[i] = ha->node_name[i];

	sprintf((char *)(ptmp_hba_node->Manufacturer), "QLogic Corporation");
	sprintf((char *)(ptmp_hba_node->Model), dr_ha->model_number);

	ptmp_hba_node->SerialNum[0] = dr_ha->serial0;
	ptmp_hba_node->SerialNum[1] = dr_ha->serial1;
	ptmp_hba_node->SerialNum[2] = dr_ha->serial2;
	sprintf((char *)(ptmp_hba_node->DriverVersion), "ioctl-%s",
	    dr_ha->driver_verstr);

	sprintf((char *)(ptmp_hba_node->FWVersion),"%2d.%02d.%02d",
	    dr_ha->fw_major_version, 
	    dr_ha->fw_minor_version, 
	    dr_ha->fw_subminor_version);

 	DEBUG9(printk("%s(%ld): inst=%ld, returning fw ver str= %s.\n",
 	    __func__, ha->host_no, ha->instance,
	    ptmp_hba_node->FWVersion);)

	/* Option ROM version string. */
	memset(ptmp_hba_node->OptRomVersion, 0,
	    sizeof(ptmp_hba_node->OptRomVersion));
	next_str = ptmp_hba_node->OptRomVersion;
	sprintf(next_str, "0.00");
	if (test_bit(ROM_CODE_TYPE_BIOS, &ha->code_types)) {
		sprintf(next_str, "%d.%02d", ha->bios_revision[1],
		    ha->bios_revision[0]);
	}
 	DEBUG9(printk("%s(%ld): inst=%ld, returning bios ver str= %s.\n",
 	    __func__, ha->host_no, ha->instance,
	    next_str);)

	/* Extended Option ROM versions. */
	ptmp_hba_node->BIValid = 0;
	memset(ptmp_hba_node->BIEfiVersion, 0,
	    sizeof(ptmp_hba_node->BIEfiVersion));
	memset(ptmp_hba_node->BIFCodeVersion, 0,
	    sizeof(ptmp_hba_node->BIFCodeVersion));
	if (test_bit(ROM_CODE_TYPE_FCODE, &ha->code_types)) {
		if (IS_QLA24XX(dr_ha) || IS_QLA54XX(dr_ha)) {
			ptmp_hba_node->BIValid |= EXT_HN_BI_FCODE_VALID;
			ptmp_hba_node->BIFCodeVersion[0] = ha->fcode_revision[1];
			ptmp_hba_node->BIFCodeVersion[1] = ha->fcode_revision[0];
		} else {
			unsigned int barray[3];

			memset (barray, 0, sizeof(barray));
			ptmp_hba_node->BIValid |= EXT_HN_BI_FCODE_VALID;
			sscanf(ha->fcode_revision, "%u.%u.%u", &barray[0],
			    &barray[1], &barray[2]);
			ptmp_hba_node->BIFCodeVersion[0] = barray[0];
			ptmp_hba_node->BIFCodeVersion[1] = barray[1];
			ptmp_hba_node->BIFCodeVersion[2] = barray[2];
		}
		DEBUG9(printk(
		    "%s(%ld): inst=%ld, opt rom: fcode version = %d.%d.%d.\n",
		    __func__, ha->host_no, ha->instance,
		    ptmp_hba_node->BIFCodeVersion[0],
		    ptmp_hba_node->BIFCodeVersion[1],
		    ptmp_hba_node->BIFCodeVersion[2]);)
	}
	if (test_bit(ROM_CODE_TYPE_EFI, &ha->code_types)) {
		ptmp_hba_node->BIValid |= EXT_HN_BI_EFI_VALID;
		ptmp_hba_node->BIEfiVersion[0] = ha->efi_revision[1];
		ptmp_hba_node->BIEfiVersion[1] = ha->efi_revision[0];

		DEBUG9(printk(
		    "%s(%ld): inst=%ld, opt rom: efi revision = %d.%d.\n",
		    __func__, ha->host_no, ha->instance,
		    ptmp_hba_node->BIEfiVersion[0],
		    ptmp_hba_node->BIEfiVersion[1]);)
	}
	if (IS_QLA24XX(dr_ha) || IS_QLA54XX(dr_ha)) {
		ptmp_hba_node->BIValid |= EXT_HN_BI_FW_VALID;
		ptmp_hba_node->BIFwVersion[0] = ha->fw_revision[0];
		ptmp_hba_node->BIFwVersion[1] = ha->fw_revision[1];
		ptmp_hba_node->BIFwVersion[2] = ha->fw_revision[2];
		ptmp_hba_node->BIFwVersion[3] = ha->fw_revision[3];

		DEBUG9(printk(
		    "%s(%ld): inst=%ld, opt rom: fw revision = %d.%d.%d.\n",
		    __func__, ha->host_no, ha->instance,
		    ptmp_hba_node->BIFwVersion[0],
		    ptmp_hba_node->BIFwVersion[1],
		    ptmp_hba_node->BIFwVersion[2]);)
	}

	ptmp_hba_node->InterfaceType = EXT_DEF_FC_INTF_TYPE;
	ptmp_hba_node->PortCount = 1;
	ptmp_hba_node->DriverAttr = 0;

	/* now copy up the HBA_NODE to user */
	if (pext->ResponseLen < sizeof(EXT_HBA_NODE))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_HBA_NODE);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_hba_node, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	qim_free_ioctl_scrap_mem(ha);
	return (ret);
}

/*
 * qim_query_hba_port
 *	Handles EXT_SC_QUERY_HBA_PORT subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_query_hba_port(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint32_t	tgt_cnt, tgt, transfer_size;
	uint32_t	port_cnt;
	fc_port_t	*fcport;
	struct scsi_qla_host *dr_ha = ha->dr_data;
	EXT_HBA_PORT	*ptmp_hba_port;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (qim_get_ioctl_scrap_mem(ha, (void **)&ptmp_hba_port,
	    sizeof(EXT_HBA_PORT))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_HBA_PORT));)
		return (ret);
	}

	/* reflect all HBA PORT related info */
	ptmp_hba_port->WWPN[7] = ha->port_name[7];
	ptmp_hba_port->WWPN[6] = ha->port_name[6];
	ptmp_hba_port->WWPN[5] = ha->port_name[5];
	ptmp_hba_port->WWPN[4] = ha->port_name[4];
	ptmp_hba_port->WWPN[3] = ha->port_name[3];
	ptmp_hba_port->WWPN[2] = ha->port_name[2];
	ptmp_hba_port->WWPN[1] = ha->port_name[1];
	ptmp_hba_port->WWPN[0] = ha->port_name[0];
	ptmp_hba_port->Id[0] = 0;
	ptmp_hba_port->Id[1] = dr_ha->d_id.r.d_id[2];
	ptmp_hba_port->Id[2] = dr_ha->d_id.r.d_id[1];
	ptmp_hba_port->Id[3] = dr_ha->d_id.r.d_id[0];
	ptmp_hba_port->Type =  EXT_DEF_INITIATOR_DEV;

	switch (dr_ha->current_topology) {
	case ISP_CFG_NL:
	case ISP_CFG_FL:
		ptmp_hba_port->Mode = EXT_DEF_LOOP_MODE;
		break;

	case ISP_CFG_N:
	case ISP_CFG_F:
		ptmp_hba_port->Mode = EXT_DEF_P2P_MODE;
		break;

	default:
		ptmp_hba_port->Mode = EXT_DEF_UNKNOWN_MODE;
		break;
	}

	port_cnt = 0;
	list_for_each_entry(fcport, &dr_ha->fcports, list) {
		if (fcport->port_type != FCT_TARGET) {
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld port "
			    "%02x%02x%02x%02x%02x%02x%02x%02x not target dev\n",
			    __func__, ha->host_no, ha->instance,
			    fcport->port_name[0], fcport->port_name[1],
			    fcport->port_name[2], fcport->port_name[3],
			    fcport->port_name[4], fcport->port_name[5],
			    fcport->port_name[6], fcport->port_name[7]));
			continue;
		}

		/* if removed or missing */
		if (atomic_read(&fcport->state) != FCS_ONLINE) {
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld port "
			    "%02x%02x%02x%02x%02x%02x%02x%02x not online\n",
			    __func__, ha->host_no, ha->instance,
			    fcport->port_name[0], fcport->port_name[1],
			    fcport->port_name[2], fcport->port_name[3],
			    fcport->port_name[4], fcport->port_name[5],
			    fcport->port_name[6], fcport->port_name[7]));
			continue;
		}
		port_cnt++;
	}

	tgt_cnt  = 0;
	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		if (dr_ha->otgt[tgt] == NULL) {
			continue;
		}
		if (dr_ha->otgt[tgt]->fcport == NULL) {
			/* port doesn't exist */
			DEBUG9(printk("%s(%ld): tgt %d port not exist.\n",
			    __func__, ha->host_no, tgt);)
			continue;
		}
		tgt_cnt++;
	}

	DEBUG9(printk("%s(%ld): inst=%ld disc_port cnt=%d, tgt cnt=%d.\n",
	    __func__, ha->host_no, ha->instance,
	    port_cnt, tgt_cnt);)

	ptmp_hba_port->DiscPortCount   = port_cnt;
	ptmp_hba_port->DiscTargetCount = tgt_cnt;

	if (atomic_read(&dr_ha->loop_state) == LOOP_DOWN ||
	    atomic_read(&dr_ha->loop_state) == LOOP_DEAD) {
		ptmp_hba_port->State = EXT_DEF_HBA_LOOP_DOWN;
	} else if (atomic_read(&dr_ha->loop_state) != LOOP_READY ||
	    test_bit(ABORT_ISP_ACTIVE, &dr_ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &dr_ha->dpc_flags) ||
	    test_bit(CFG_ACTIVE, &dr_ha->cfg_flags)) {

		ptmp_hba_port->State = EXT_DEF_HBA_SUSPENDED;
	} else {
		ptmp_hba_port->State = EXT_DEF_HBA_OK;
	}

	ptmp_hba_port->DiscPortNameType = EXT_DEF_USE_PORT_NAME;

	/* Return supported FC4 type depending on driver support. */
	ptmp_hba_port->PortSupportedFC4Types = EXT_DEF_FC4_TYPE_SCSI;
	ptmp_hba_port->PortActiveFC4Types = EXT_DEF_FC4_TYPE_SCSI;
	if (!IS_QLA2100(dr_ha) && !IS_QLA2200(dr_ha)) {
		ptmp_hba_port->PortSupportedFC4Types |= EXT_DEF_FC4_TYPE_IP;
		ptmp_hba_port->PortActiveFC4Types |= EXT_DEF_FC4_TYPE_IP;
	}

	/* Return supported speed depending on adapter type */
	if (IS_QLA2100(dr_ha) || IS_QLA2200(dr_ha))
		ptmp_hba_port->PortSupportedSpeed = EXT_DEF_PORTSPEED_1GBIT;
	else
		ptmp_hba_port->PortSupportedSpeed = EXT_DEF_PORTSPEED_2GBIT;

	switch (dr_ha->link_data_rate) {
	case 0:
		ptmp_hba_port->PortSpeed = EXT_DEF_PORTSPEED_1GBIT;
		break;
	case 1:
		ptmp_hba_port->PortSpeed = EXT_DEF_PORTSPEED_2GBIT;
		break;
	case 3:
		ptmp_hba_port->PortSpeed = EXT_DEF_PORTSPEED_4GBIT;
		break;
	case 4:
		ptmp_hba_port->PortSpeed = EXT_DEF_PORTSPEED_10GBIT;
		break;
	default:
		/* unknown */
		ptmp_hba_port->PortSpeed = 0;
		break;
	}

	/* now copy up the HBA_PORT to user */
	if (pext->ResponseLen < sizeof(EXT_HBA_PORT))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_HBA_PORT);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_hba_port, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return ret;
}

/*
 * qim_query_disc_port
 *	Handles EXT_SC_QUERY_DISC_PORT subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_query_disc_port(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	int		found;
	uint32_t	tgt, transfer_size, inst;
	fc_port_t	*fcport;
	os_tgt_t	*tq;
	EXT_DISC_PORT	*ptmp_disc_port;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): inst=%ld entered. Port inst=%02d.\n",
	    __func__, ha->host_no, ha->instance, pext->Instance);)

	inst = 0;
	found = 0;
	fcport = NULL;
	list_for_each_entry(fcport, &dr_ha->fcports, list) {
		if(fcport->port_type != FCT_TARGET)
			continue;

		if (atomic_read(&fcport->state) != FCS_ONLINE) {
			/* port does not exist anymore */
			DEBUG9(printk("%s(%ld): fcport marked lost. "
			    "port=%02x%02x%02x%02x%02x%02x%02x%02x "
			    "loop_id=%02x not online.\n",
			    __func__, ha->host_no,
			    fcport->port_name[0], fcport->port_name[1],
			    fcport->port_name[2], fcport->port_name[3],
			    fcport->port_name[4], fcport->port_name[5],
			    fcport->port_name[6], fcport->port_name[7],
			    fcport->loop_id);)
			continue;
		}

		if (inst != pext->Instance) {
			DEBUG9(printk("%s(%ld): found fcport %02d "
			    "d_id=%02x%02x%02x. Skipping.\n",
			    __func__, ha->host_no, inst,
			    fcport->d_id.b.domain,
			    fcport->d_id.b.area,
			    fcport->d_id.b.al_pa));

			inst++;
			continue;
		}

		DEBUG9(printk("%s(%ld): inst=%ld found matching fcport %02d "
		    "online. d_id=%02x%02x%02x loop_id=%02x online.\n",
		    __func__, ha->host_no, ha->instance, inst,
		    fcport->d_id.b.domain,
		    fcport->d_id.b.area,
		    fcport->d_id.b.al_pa,
		    fcport->loop_id);)

		/* Found the matching port still connected. */
		found++;
		break;
	}

	if (!found) {
		DEBUG9_10(printk("%s(%ld): inst=%ld dev not found.\n",
		    __func__, ha->host_no, ha->instance);)

		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&ptmp_disc_port,
	    sizeof(EXT_DISC_PORT))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_DISC_PORT));)
		return (ret);
	}

	memcpy(ptmp_disc_port->WWNN, fcport->node_name, WWN_SIZE);
	memcpy(ptmp_disc_port->WWPN, fcport->port_name, WWN_SIZE);

	ptmp_disc_port->Id[0] = 0;
	ptmp_disc_port->Id[1] = fcport->d_id.r.d_id[2];
	ptmp_disc_port->Id[2] = fcport->d_id.r.d_id[1];
	ptmp_disc_port->Id[3] = fcport->d_id.r.d_id[0];

	/* Currently all devices on fcport list are target capable devices */
	/* This default value may need to be changed after we add non target
	 * devices also to this list.
	 */
	ptmp_disc_port->Type = EXT_DEF_TARGET_DEV;

	if (fcport->flags & FCF_FABRIC_DEVICE) {
		ptmp_disc_port->Type |= EXT_DEF_FABRIC_DEV;
	}
	if (fcport->flags & FCF_TAPE_PRESENT) {
		ptmp_disc_port->Type |= EXT_DEF_TAPE_DEV;
	}
	if (fcport->port_type == FCT_INITIATOR) {
		ptmp_disc_port->Type |= EXT_DEF_INITIATOR_DEV;
	}

	ptmp_disc_port->LoopID = fcport->loop_id;
	ptmp_disc_port->Status = 0;
	ptmp_disc_port->Bus    = 0;

	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		if ((tq = dr_ha->otgt[tgt]) == NULL) {
			continue;
		}

		if (tq->fcport == NULL)  /* dg 08/14/01 */
			continue;

		if (memcmp(fcport->port_name, tq->fcport->port_name,
		    EXT_DEF_WWN_NAME_SIZE) == 0) {
			ptmp_disc_port->TargetId = tgt;
			break;
		}
	}

	/* now copy up the DISC_PORT to user */
	if (pext->ResponseLen < sizeof(EXT_DISC_PORT))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_DISC_PORT);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_disc_port, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

/*
 * qim_query_disc_tgt
 *	Handles EXT_SC_QUERY_DISC_TGT subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_query_disc_tgt(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint32_t	tgt, transfer_size, inst;
	uint32_t	cnt, i;
	fc_port_t	*tgt_fcport;
	os_tgt_t	*tq;
	EXT_DISC_TARGET	*ptmp_disc_target;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): inst=%ld entered for tgt inst %d.\n",
	    __func__, ha->host_no, ha->instance, pext->Instance);)

	tq = NULL;
	for (tgt = 0, inst = 0; tgt < MAX_TARGETS; tgt++) {
		if (dr_ha->otgt[tgt] == NULL) {
			continue;
		}
		/* if wrong target id then skip to next entry */
		if (inst != pext->Instance) {
			inst++;
			continue;
		}
		tq = dr_ha->otgt[tgt];
		break;
	}

	if (tq == NULL || tgt == MAX_TARGETS) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld target dev not found. "
		    "tq=%p, tgt=%d.\n",
		    __func__, ha->host_no, ha->instance, tq, tgt);)
		return (ret);
	}

	if (tq->fcport == NULL) { 	/* dg 08/14/01 */
		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld target %d port not found. "
		    "tq=%p.\n",
		    __func__, ha->host_no, ha->instance, tgt, tq);)
		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&ptmp_disc_target,
	    sizeof(EXT_DISC_TARGET))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_DISC_TARGET));)
		return (ret);
	}

	tgt_fcport = tq->fcport;
	if (tgt_fcport->flags & FCF_XP_DEVICE)
		memcpy(ptmp_disc_target->WWNN, tq->node_name, WWN_SIZE);
	else
		memcpy(ptmp_disc_target->WWNN, tgt_fcport->node_name, WWN_SIZE);
	memcpy(ptmp_disc_target->WWPN, tgt_fcport->port_name, WWN_SIZE);

	ptmp_disc_target->Id[0] = 0;
	ptmp_disc_target->Id[1] = tgt_fcport->d_id.r.d_id[2];
	ptmp_disc_target->Id[2] = tgt_fcport->d_id.r.d_id[1];
	ptmp_disc_target->Id[3] = tgt_fcport->d_id.r.d_id[0];

	/* All devices on dr_ha->otgt list are target capable devices. */
	ptmp_disc_target->Type = EXT_DEF_TARGET_DEV;

	if (tgt_fcport->flags & FCF_FABRIC_DEVICE) {
		ptmp_disc_target->Type |= EXT_DEF_FABRIC_DEV;
	}
	if (tgt_fcport->flags & FCF_TAPE_PRESENT) {
		ptmp_disc_target->Type |= EXT_DEF_TAPE_DEV;
	}
	if (tgt_fcport->port_type & FCT_INITIATOR) {
		ptmp_disc_target->Type |= EXT_DEF_INITIATOR_DEV;
	}

	ptmp_disc_target->LoopID   = tgt_fcport->loop_id;
	ptmp_disc_target->Status   = 0;
	if (atomic_read(&tq->fcport->state) != FCS_ONLINE) {
		ptmp_disc_target->Status |= EXT_DEF_TGTSTAT_OFFLINE;
	}
	if (qim_is_fcport_in_config(dr_ha, tq->fcport)) {
		ptmp_disc_target->Status |= EXT_DEF_TGTSTAT_IN_CFG;
	}

	ptmp_disc_target->Bus      = 0;
	ptmp_disc_target->TargetId = tgt;

	cnt = 0;
	/* enumerate available LUNs under this TGT (if any) */
	if (dr_ha->otgt[tgt] != NULL) {
		for (i = 0; i < MAX_LUNS ; i++) {
			if ((dr_ha->otgt[tgt])->olun[i] !=0)
				cnt++;
		}
	}

	ptmp_disc_target->LunCount = cnt;

	DEBUG9(printk("%s(%ld): copying data for tgt id %d. ",
	    __func__, ha->host_no, tgt);)
	DEBUG9(printk("port=%p:%02x%02x%02x%02x%02x%02x%02x%02x. "
	    "lun cnt=%d.\n",
	    tgt_fcport,
	    tgt_fcport->port_name[0],
	    tgt_fcport->port_name[1],
	    tgt_fcport->port_name[2],
	    tgt_fcport->port_name[3],
	    tgt_fcport->port_name[4],
	    tgt_fcport->port_name[5],
	    tgt_fcport->port_name[6],
	    tgt_fcport->port_name[7],
	    cnt);)

	/* now copy up the DISC_PORT to user */
	if (pext->ResponseLen < sizeof(EXT_DISC_PORT))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_DISC_TARGET);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_disc_target, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

/*
 * qim_query_chip
 *	Handles EXT_SC_QUERY_CHIP subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_query_chip(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint32_t	transfer_size, i;
	EXT_CHIP		*ptmp_isp;
	struct Scsi_Host	*host;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

 	if (qim_get_ioctl_scrap_mem(ha, (void **)&ptmp_isp,
 	    sizeof(EXT_CHIP))) {
 		/* not enough memory */
 		pext->Status = EXT_STATUS_NO_MEMORY;
 		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
 		    "size requested=%ld.\n",
 		    __func__, ha->host_no, ha->instance,
 		    (ulong)sizeof(EXT_CHIP));)
 		return (ret);
 	}

	host = dr_ha->host;
	ptmp_isp->VendorId       = dr_ha->pdev->vendor;
	ptmp_isp->DeviceId       = dr_ha->pdev->device;
	ptmp_isp->SubVendorId    = dr_ha->pdev->subsystem_vendor;
	ptmp_isp->SubSystemId    = dr_ha->pdev->subsystem_device;
	ptmp_isp->PciBusNumber   = dr_ha->pdev->bus->number;
	ptmp_isp->PciDevFunc     = dr_ha->pdev->devfn;
	ptmp_isp->PciSlotNumber  = PCI_SLOT(dr_ha->pdev->devfn);
	ptmp_isp->DomainNr       = pci_domain_nr(dr_ha->pdev->bus);
	/* These values are not 64bit architecture safe. */
	ptmp_isp->IoAddr         = 0; //(UINT32)dr_ha->pio_address;
	ptmp_isp->IoAddrLen      = 0; //(UINT32)dr_ha->pio_length;
	ptmp_isp->MemAddr        = 0; //(UINT32)dr_ha->mmio_address;
	ptmp_isp->MemAddrLen     = 0; //(UINT32)dr_ha->mmio_length;
	ptmp_isp->ChipType       = 0; /* ? */
	ptmp_isp->InterruptLevel = dr_ha->pdev->irq;

	for (i = 0; i < 8; i++)
		ptmp_isp->OutMbx[i] = 0;

	/* now copy up the ISP to user */
	if (pext->ResponseLen < sizeof(EXT_CHIP))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_CHIP);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_isp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

/*
 * qim_get_data
 *	Handles all subcommands of the EXT_CC_GET_DATA command.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_get_data(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int	tmp_rval = 0;

	switch(pext->SubCode) {
	case EXT_SC_GET_STATISTICS:
		tmp_rval = qim_get_statistics(ha, pext, mode);
		break;

	case EXT_SC_GET_FC_STATISTICS:
		tmp_rval = qim_get_fc_statistics(ha, pext, mode);
		break;

	case EXT_SC_GET_PORT_SUMMARY:
		tmp_rval = qim_get_port_summary(ha, pext, mode);
		break;

	case EXT_SC_QUERY_DRIVER:
		tmp_rval = qim_query_driver(ha, pext, mode);
		break;

	case EXT_SC_QUERY_FW:
		tmp_rval = qim_query_fw(ha, pext, mode);
		break;

	case EXT_SC_GET_RNID:
		tmp_rval = qim_get_rnid_params(ha, pext, mode);
		break;

#if 0
/* RLU: this need to be handled later */
	case EXT_SC_GET_BEACON_STATE:
		if (!IS_QLA2100(ha) && !IS_QLA2200(ha)) {
			tmp_rval = qim_get_led_state(ha, pext, mode);
			break;
		}
		/*FALLTHROUGH*/

#endif
	default:
		DEBUG10(printk("%s(%ld): inst=%ld unknown SubCode %d.\n",
		    __func__, ha->host_no, ha->instance, pext->SubCode);)
		pext->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;
	 }

	return (tmp_rval);
}

/*
 * qim_get_statistics
 *	Issues get_link_status mbx cmd and returns statistics
 *	relavent to the specified adapter.
 *
 * Input:
 *	ha = pointer to adapter struct of the specified adapter.
 *	pext = pointer to EXT_IOCTL structure containing values from user.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_get_statistics(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	EXT_HBA_PORT_STAT	*ptmp_stat;
	int		ret = 0;
	link_stat_t	stat_buf;
	uint8_t		rval;
	uint8_t		*usr_temp, *kernel_tmp;
	uint16_t	mb_stat[1];
	uint32_t	transfer_size;
	struct scsi_qla_host	*dr_ha;

	dr_ha = ha->dr_data;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	/* check on loop down */
	if ((!IS_QLA24XX(ha->dr_data) && !IS_QLA54XX(ha->dr_data) &&
	    atomic_read(&ha->dr_data->loop_state) != LOOP_READY) ||
	    test_bit(CFG_ACTIVE, &ha->dr_data->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dr_data->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dr_data->dpc_flags) ||
	    ha->dr_data->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		    __func__, ha->host_no, ha->instance);)
		printk("%s(%ld): inst=%ld loop not ready.\n",
		    __func__, ha->host_no, ha->instance);

		return (ret);
	}

	/* Send mailbox cmd to get additional link stats. */
	if (IS_QLA24XX(ha->dr_data) || IS_QLA54XX(ha->dr_data))
		rval = qim_get_isp_stats(ha, (uint32_t *)&stat_buf,
		    sizeof(stat_buf) / 4, 0, mb_stat);
	else
		rval = qim_get_link_status(ha, ha->dr_data->loop_id, 0,
		    &stat_buf, mb_stat);

	if (rval != QIM_SUCCESS) {
		if (rval == BIT_0) {
			pext->Status = EXT_STATUS_NO_MEMORY;
		} else if (rval == BIT_1) {
			pext->Status = EXT_STATUS_MAILBOX;
			pext->DetailStatus = EXT_DSTATUS_NOADNL_INFO;
		} else {
			pext->Status = EXT_STATUS_ERR;
		}

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR mailbox failed. "
		    "mb[0]=%x.\n",
		    __func__, ha->host_no, ha->instance, mb_stat[0]);)
		printk(KERN_WARNING
		     "%s(%ld): inst=%ld ERROR mailbox failed. mb[0]=%x.\n",
		    __func__, ha->host_no, ha->instance, mb_stat[0]);

		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&ptmp_stat,
	    sizeof(EXT_HBA_PORT_STAT))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_HBA_PORT_STAT));)
		return (ret);
	}

	ptmp_stat->ControllerErrorCount   =  dr_ha->total_isp_aborts;
	ptmp_stat->DeviceErrorCount       =  dr_ha->total_dev_errs;
	ptmp_stat->TotalIoCount           =  dr_ha->total_ios;
	ptmp_stat->TotalMBytes            =  dr_ha->total_bytes >> 20;
	ptmp_stat->TotalLipResets         =  dr_ha->total_lip_cnt;
	/*
	   ptmp_stat->TotalInterrupts        =  dr_ha->total_isr_cnt;
	 */

	ptmp_stat->TotalLinkFailures               = stat_buf.link_fail_cnt;
	ptmp_stat->TotalLossOfSync                 = stat_buf.loss_sync_cnt;
	ptmp_stat->TotalLossOfSignals              = stat_buf.loss_sig_cnt;
	ptmp_stat->PrimitiveSeqProtocolErrorCount  = stat_buf.prim_seq_err_cnt;
	ptmp_stat->InvalidTransmissionWordCount    = stat_buf.inval_xmit_word_cnt;
	ptmp_stat->InvalidCRCCount                 = stat_buf.inval_crc_cnt;

	/* now copy up the STATISTICS to user */
	if (pext->ResponseLen < sizeof(EXT_HBA_PORT_STAT))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_HBA_PORT_STAT);

	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,pext->AddrMode);
	kernel_tmp = (uint8_t *)ptmp_stat;
	ret = copy_to_user(usr_temp, kernel_tmp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

/*
 * qim_get_fc_statistics
 *	Issues get_link_status mbx cmd to the target device with
 *	the specified WWN and returns statistics relavent to the
 *	device.
 *
 * Input:
 *	ha = pointer to adapter struct of the specified device.
 *	pext = pointer to EXT_IOCTL structure containing values from user.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_get_fc_statistics(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	EXT_HBA_PORT_STAT	*ptmp_stat;
	EXT_DEST_ADDR		addr_struct;
	fc_port_t	*fcport;
	int		port_found;
	link_stat_t	stat_buf;
	int		ret = 0;
	uint8_t		rval;
	uint8_t		*usr_temp, *kernel_tmp;
	uint8_t		*req_name;
	uint16_t	mb_stat[1];
	uint32_t	transfer_size;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	ret = copy_from_user(&addr_struct, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy req buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		return (-EFAULT);
	}

	DEBUG9(printk("%s:(%ld): going to find loopid for port "
	    "%02x%02x%02x%02x%02x%02x%02x%02x.\n",
	    __func__, ha->host_no,
	    addr_struct.DestAddr.WWPN[0],
	    addr_struct.DestAddr.WWPN[1],
	    addr_struct.DestAddr.WWPN[2],
	    addr_struct.DestAddr.WWPN[3],
	    addr_struct.DestAddr.WWPN[4],
	    addr_struct.DestAddr.WWPN[5],
	    addr_struct.DestAddr.WWPN[6],
	    addr_struct.DestAddr.WWPN[7]));

	/* find the device's loop_id */
	port_found = 0;
	fcport = NULL;
	switch (addr_struct.DestType) {
	case EXT_DEF_DESTTYPE_WWPN:
		req_name = addr_struct.DestAddr.WWPN;
		list_for_each_entry(fcport, &dr_ha->fcports, list) {
			if (memcmp(fcport->port_name, req_name,
			    EXT_DEF_WWN_NAME_SIZE) == 0) {
				port_found = 1;
				break;
			}
		}
		break;

	case EXT_DEF_DESTTYPE_WWNN:
	case EXT_DEF_DESTTYPE_PORTID:
	case EXT_DEF_DESTTYPE_FABRIC:
	case EXT_DEF_DESTTYPE_SCSI:
	default:
		pext->Status = EXT_STATUS_INVALID_PARAM;
		pext->DetailStatus = EXT_DSTATUS_NOADNL_INFO;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR Unsupported subcode "
		    "address type.\n", __func__, ha->host_no, ha->instance);)
		return (ret);

		break;
	}

	if (!port_found) {
		/* not found */
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		pext->DetailStatus = EXT_DSTATUS_TARGET;
		return (ret);
	}

	/* check for suspended/lost device */
	/*
	   if (ha->fcport is suspended/lost) {
	   pext->Status = EXT_STATUS_SUSPENDED;
	   pext->DetailStatus = EXT_DSTATUS_TARGET;
	   return pext->Status;
	   }
	 */

	/* check on loop down */
	if (atomic_read(&dr_ha->loop_state) != LOOP_READY ||
	    test_bit(CFG_ACTIVE, &dr_ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &dr_ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &dr_ha->dpc_flags) ||
	    dr_ha->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		     __func__, ha->host_no, ha->instance);)
		return (ret);
	}

	DEBUG9(printk("%s:(%ld): going to call get_link_status with "
	    "loopid=%x.\n", __func__, ha->host_no, fcport->loop_id));

	/* Send mailbox cmd to get more. */
	if ((rval = qim_get_link_status(ha, fcport->loop_id, 0,
	    &stat_buf, mb_stat)) != QIM_SUCCESS) {
		/* try again with D_ID */
		DEBUG10(printk(
		    "%s(%ld): inst=%ld ERROR 1st mailbox failed. mb[0]=%x.\n",
		    __func__, ha->host_no, ha->instance, mb_stat[0]);)

		if ((qim_get_link_status(ha, fcport->loop_id, BIT_3,
		    &stat_buf, mb_stat)) != QIM_SUCCESS) {

			if (rval == BIT_0) {
				pext->Status = EXT_STATUS_NO_MEMORY;
			} else if (rval == BIT_1) {
				pext->Status = EXT_STATUS_MAILBOX;
				pext->DetailStatus = EXT_DSTATUS_NOADNL_INFO;
			} else {
				pext->Status = EXT_STATUS_ERR;
			}

			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR mailbox failed. "
			    "mb[0]=%x.\n",
			    __func__, ha->host_no, ha->instance, mb_stat[0]);)
			return (ret);
		}
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&ptmp_stat,
	    sizeof(EXT_HBA_PORT_STAT))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_HBA_PORT_STAT));)
		return (ret);
	}

	ptmp_stat->ControllerErrorCount   =  dr_ha->total_isp_aborts;
	ptmp_stat->DeviceErrorCount       =  dr_ha->total_dev_errs;
	ptmp_stat->TotalIoCount           =  dr_ha->total_ios;
	ptmp_stat->TotalMBytes            =  dr_ha->total_bytes >> 20;
	ptmp_stat->TotalLipResets         =  dr_ha->total_lip_cnt;
	/*
	   ptmp_stat->TotalInterrupts        =  dr_ha->total_isr_cnt;
	 */

	ptmp_stat->TotalLinkFailures               = stat_buf.link_fail_cnt;
	ptmp_stat->TotalLossOfSync                 = stat_buf.loss_sync_cnt;
	ptmp_stat->TotalLossOfSignals              = stat_buf.loss_sig_cnt;
	ptmp_stat->PrimitiveSeqProtocolErrorCount  = stat_buf.prim_seq_err_cnt;
	ptmp_stat->InvalidTransmissionWordCount    = stat_buf.inval_xmit_word_cnt;
	ptmp_stat->InvalidCRCCount                 = stat_buf.inval_crc_cnt;

	/* now copy up the STATISTICS to user */
	if (pext->ResponseLen < sizeof(EXT_HBA_PORT_STAT))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_HBA_PORT_STAT);

	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,pext->AddrMode);
	kernel_tmp = (uint8_t *)ptmp_stat;
	ret = copy_to_user(usr_temp, kernel_tmp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

/*
 * qim_get_port_summary
 *	Handles EXT_SC_GET_PORT_SUMMARY subcommand.
 *	Returns values of devicedata and dd_entry list.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_get_port_summary(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	entry_cnt = 0;
	uint32_t	port_cnt = 0;
	uint32_t	top_xfr_size;
	uint32_t	usr_no_of_entries = 0;
	uint32_t	device_types;
	void		*start_of_entry_list;
	fc_port_t	*fcport;
	struct scsi_qla_host	*dr_ha = ha->dr_data;

	EXT_DEVICEDATA		*pdevicedata;
	EXT_DEVICEDATAENTRY	*pdd_entry;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pdevicedata,
	    sizeof(EXT_DEVICEDATA))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "pdevicedata requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_DEVICEDATA));)
		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pdd_entry,
	    sizeof(EXT_DEVICEDATAENTRY))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "pdd_entry requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_DEVICEDATAENTRY));)
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* Get device types to query. */
	device_types = 0;
	ret = copy_from_user(&device_types, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), sizeof(device_types));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR"
		    "copy_from_user() of struct failed ret=%d.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	/* Get maximum number of entries allowed in response buf */
	usr_no_of_entries = pext->ResponseLen / sizeof(EXT_DEVICEDATAENTRY);

	/* reserve some spaces to be filled in later. */
	top_xfr_size = sizeof(pdevicedata->ReturnListEntryCount) +
	    sizeof(pdevicedata->TotalDevices);

	start_of_entry_list = Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode) +
	    top_xfr_size;

	/* Start copying from devices that exist. */
	ret = qim_get_fcport_summary(ha, pdd_entry, start_of_entry_list,
	    device_types, usr_no_of_entries, &entry_cnt, &pext->Status);

	DEBUG9(printk("%s(%ld): after get_fcport_summary, entry_cnt=%d.\n",
	    __func__, ha->host_no, entry_cnt);)

#if 0
	/* If there's still space in user buffer, return devices found
	 * in config file which don't actually exist (missing).
	 */
	if (ret == 0) {
		if (!qim_failover_enabled(ha)) {
			ret = qim_std_missing_port_summary(ha, pdd_entry,
			    start_of_entry_list, usr_no_of_entries,
			    &entry_cnt, &pext->Status);
		} else {
			ret = qim_fo_missing_port_summary(ha, pdd_entry,
			    start_of_entry_list, usr_no_of_entries,
			    &entry_cnt, &pext->Status);

		}
	}

	DEBUG9(printk(
	    "%s(%ld): after get_missing_port_summary. entry_cnt=%d.\n",
	    __func__, ha->host_no, entry_cnt);)
#endif

	if (ret) {
		DEBUG9_10(printk("%s(%ld): failed getting port info.\n",
		    __func__, ha->host_no);)
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	pdevicedata->ReturnListEntryCount = entry_cnt;
	list_for_each_entry(fcport, &dr_ha->fcports, list) {
		if (fcport->port_type != FCT_TARGET)
			continue;

		port_cnt++;
	}
	if (port_cnt > entry_cnt)
		pdevicedata->TotalDevices = port_cnt;
	else
		pdevicedata->TotalDevices = entry_cnt;

	DEBUG9(printk("%s(%ld): inst=%ld EXT_SC_GET_PORT_SUMMARY "
	    "return entry cnt=%d port_cnt=%d.\n",
	    __func__, ha->host_no, ha->instance,
	    entry_cnt, port_cnt);)

	/* copy top of devicedata, which is everything other than the
	 * actual entry list data.
	 */
	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,pext->AddrMode);
	kernel_tmp = (uint8_t *)pdevicedata;
	ret = copy_to_user(usr_temp, kernel_tmp, top_xfr_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp "
		    "devicedata buffer=%d.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

/*
 * qim_get_fcport_summary
 *	Returns port values in user's dd_entry list.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pdd_entry = pointer to a temporary EXT_DEVICEDATAENTRY struct
 *	pstart_of_entry_list = start of user addr of buffer for dd_entry entries
 *	max_entries = max number of entries allowed by user buffer
 *	pentry_cnt = pointer to total number of entries so far
 *	ret_status = pointer to ioctl status field
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_get_fcport_summary(struct qla_host_ioctl *ha,
    EXT_DEVICEDATAENTRY *pdd_entry, void *pstart_of_entry_list,
    uint32_t device_types, uint32_t max_entries, uint32_t *pentry_cnt,
    uint32_t *ret_status)
{
	int		ret = QIM_SUCCESS;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	b;
	uint32_t	current_offset;
	uint32_t	tgt;
	uint32_t	transfer_size;
	fc_port_t	*fcport;
	os_tgt_t	*tq;
	/*
	uint16_t	idx;
	mp_host_t	*host = NULL;
	mp_device_t	*tmp_dp = NULL;
	*/
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	list_for_each_entry(fcport, &dr_ha->fcports, list) {
		if (*pentry_cnt >= max_entries)
			break;
		if (fcport->port_type != FCT_TARGET) {
			/* Don't report initiators or broadcast devices. */
			DEBUG2_9_10(printk("%s(%ld): not reporting non-target "
			    "fcport %02x%02x%02x%02x%02x%02x%02x%02x. "
			    "port_type=%x.\n",
			    __func__, ha->host_no, fcport->port_name[0],
			    fcport->port_name[1], fcport->port_name[2],
			    fcport->port_name[3], fcport->port_name[4],
			    fcport->port_name[5], fcport->port_name[6],
			    fcport->port_name[7], fcport->port_type));
			continue;
		}

		/*
		if ((atomic_read(&fcport->state) != FCS_ONLINE) &&
		    !qim_is_fcport_in_config(dr_ha, fcport)) {
		*/
		if (atomic_read(&fcport->state) != FCS_ONLINE) {
			/* no need to report */
			DEBUG2_9_10(printk("%s(%ld): not reporting "
			    "fcport %02x%02x%02x%02x%02x%02x%02x%02x. "
			    "state=%i, flags=%02x.\n",
			    __func__, ha->host_no, fcport->port_name[0],
			    fcport->port_name[1], fcport->port_name[2],
			    fcport->port_name[3], fcport->port_name[4],
			    fcport->port_name[5], fcport->port_name[6],
			    fcport->port_name[7], atomic_read(&fcport->state),
			    fcport->flags));
			continue;
		}

		/* copy from fcport to dd_entry */

		for (b = 0; b < 3 ; b++)
			pdd_entry->PortID[b] = fcport->d_id.r.d_id[2-b];

		if (fcport->flags & FCF_FABRIC_DEVICE) {
			pdd_entry->ControlFlags = EXT_DEF_GET_FABRIC_DEVICE;
		} else {
			pdd_entry->ControlFlags = 0;
		}

		pdd_entry->TargetAddress.Bus    = 0;
		/* Retrieve 'Target' number for port */
		for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
			if ((tq = dr_ha->otgt[tgt]) == NULL) {
				continue;
			}

			if (tq->fcport == NULL)
				continue;

			if (memcmp(fcport->port_name, tq->fcport->port_name,
			    EXT_DEF_WWN_NAME_SIZE) == 0) {
				pdd_entry->TargetAddress.Target = tgt;
				if ((fcport->flags & FCF_XP_DEVICE) &&
				    !(device_types &
					EXT_DEF_GET_TRUE_NN_DEVICE)) {
					memcpy(pdd_entry->NodeWWN,
					    tq->node_name, WWN_SIZE);
				} else {
					memcpy(pdd_entry->NodeWWN,
					    fcport->node_name, WWN_SIZE);
				}
				break;
			}
		}
		if (tgt == MAX_TARGETS) {
#if 0
			if (qim_failover_enabled(ha)) {
				if (((host = qim_cfg_find_host(ha)) !=
				    NULL) && (fcport->flags & FCF_XP_DEVICE) &&
					!(device_types &
					    EXT_DEF_GET_TRUE_NN_DEVICE)) {
					if ((tmp_dp =
					    qim_find_mp_dev_by_portname(
						    host, fcport->port_name,
						    &idx)) != NULL)
						memcpy(pdd_entry->NodeWWN,
						    tmp_dp->nodename, WWN_SIZE);
				} else
					memcpy(pdd_entry->NodeWWN,
					    fcport->node_name, WWN_SIZE);
			} else
#endif
				memcpy(pdd_entry->NodeWWN, fcport->node_name,
				    WWN_SIZE);
		}
		memcpy(pdd_entry->PortWWN, fcport->port_name, WWN_SIZE);

		pdd_entry->TargetAddress.Lun    = 0;
		pdd_entry->DeviceFlags          = 0;
		pdd_entry->LoopID               = fcport->loop_id;
		pdd_entry->BaseLunNumber        = 0;

		DEBUG9_10(printk("%s(%ld): reporting "
		    "fcport %02x%02x%02x%02x%02x%02x%02x%02x.\n",
		    __func__, ha->host_no, fcport->port_name[0],
		    fcport->port_name[1], fcport->port_name[2],
		    fcport->port_name[3], fcport->port_name[4],
		    fcport->port_name[5], fcport->port_name[6],
		    fcport->port_name[7]));

		current_offset = *pentry_cnt * sizeof(EXT_DEVICEDATAENTRY);

		transfer_size = sizeof(EXT_DEVICEDATAENTRY);

		/* now copy up this dd_entry to user */
		usr_temp = (uint8_t *)pstart_of_entry_list + current_offset;
		kernel_tmp = (uint8_t *)pdd_entry;
	 	ret = copy_to_user(usr_temp, kernel_tmp, transfer_size);
		if (ret) {
			*ret_status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp "
			    "entry list buf=%d.\n",
			    __func__, ha->host_no, ha->instance, ret);)
			return (-EFAULT);
		}

		*pentry_cnt += 1;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

#if 0
/* RLU: this need to be handled later */
/*
 * qim_fo_missing_port_summary is in qla_fo.c
 */

static int
qim_std_missing_port_summary(struct qla_host_ioctl *ha,
    EXT_DEVICEDATAENTRY *pdd_entry, void *pstart_of_entry_list,
    uint32_t max_entries, uint32_t *pentry_cnt, uint32_t *ret_status)
{
	int		ret = QIM_SUCCESS;
	uint8_t		*usr_temp, *kernel_tmp;
	uint16_t	idx;
	uint32_t	b;
	uint32_t	current_offset;
	uint32_t	transfer_size;
	os_tgt_t	*tq;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	for (idx = 0; idx < MAX_FIBRE_DEVICES && *pentry_cnt < max_entries;
	    idx++) {
		if ((tq = TGT_Q(ha, idx)) == NULL)
			continue;

		/* Target present in configuration data but 
		 * missing during device discovery*/
		if (tq->fcport == NULL) {
			DEBUG10(printk("%s: returning missing device "
			    "%02x%02x%02x%02x%02x%02x%02x%02x.\n",
			    __func__,
			    tq->port_name[0],tq->port_name[1],
			    tq->port_name[2],tq->port_name[3],
			    tq->port_name[4],tq->port_name[5],
			    tq->port_name[6],tq->port_name[7]);)

			/* This device was not found. Return
			 * as unconfigured.
			 */
			memcpy(pdd_entry->NodeWWN, tq->node_name, WWN_SIZE);
			memcpy(pdd_entry->PortWWN, tq->port_name, WWN_SIZE);

			for (b = 0; b < 3 ; b++)
				pdd_entry->PortID[b] = 0;

			/* assume fabric dev so api won't translate 
			 * the portid from loopid */
			pdd_entry->ControlFlags = EXT_DEF_GET_FABRIC_DEVICE;

			pdd_entry->TargetAddress.Bus    = 0;
			pdd_entry->TargetAddress.Target = idx;
			pdd_entry->TargetAddress.Lun    = 0;
			pdd_entry->DeviceFlags          = 0;
			pdd_entry->LoopID               = 0;
			pdd_entry->BaseLunNumber        = 0;

			current_offset = *pentry_cnt *
			    sizeof(EXT_DEVICEDATAENTRY);

			transfer_size = sizeof(EXT_DEVICEDATAENTRY);

			/* now copy up this dd_entry to user */
			usr_temp = (uint8_t *)pstart_of_entry_list +
			    current_offset;
			kernel_tmp = (uint8_t *)pdd_entry;
			ret = copy_to_user(usr_temp, kernel_tmp,
			    transfer_size);
			if (ret) {
				*ret_status = EXT_STATUS_COPY_ERR;
				DEBUG9_10(printk("%s(%ld): inst=%ld "
				    "ERROR copy rsp list buffer.\n",
				    __func__, ha->host_no,
				    ha->instance);)
				ret = -EFAULT;
				break;
			} else {
				*pentry_cnt+=1;
			}
		}
		if (ret || *ret_status)
			break;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting. ret=%d.\n", __func__,
	    ha->host_no, ha->instance, ret);)

	return (ret);
}
#endif

/*
 * qim_query_driver
 *	Handles EXT_SC_QUERY_DRIVER subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_query_driver(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	transfer_size;
	EXT_DRIVER	*pdriver_prop;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pdriver_prop,
	    sizeof(EXT_DRIVER))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_DRIVER));)
		return (ret);
	}

	sprintf(pdriver_prop->Version, dr_ha->driver_verstr);
	pdriver_prop->NumOfBus = MAX_BUSES;
	pdriver_prop->TargetsPerBus = MAX_FIBRE_DEVICES;
	pdriver_prop->LunsPerTarget = MAX_LUNS;
	pdriver_prop->MaxTransferLen  = 0xffffffff;
	pdriver_prop->MaxDataSegments = dr_ha->host->sg_tablesize;

	if (dr_ha->flags.enable_64bit_addressing == 1)
		pdriver_prop->DmaBitAddresses = 64;
	else
		pdriver_prop->DmaBitAddresses = 32;

	if (pext->ResponseLen < sizeof(EXT_DRIVER))
		transfer_size = pext->ResponseLen;
	else
		transfer_size = sizeof(EXT_DRIVER);

	/* now copy up the ISP to user */
	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,pext->AddrMode);
	kernel_tmp = (uint8_t *)pdriver_prop;
 	ret = copy_to_user(usr_temp, kernel_tmp, transfer_size);
 	if (ret) {
 		pext->Status = EXT_STATUS_COPY_ERR;
 		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
 		    __func__, ha->host_no, ha->instance);)
 		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
 	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qim_free_ioctl_scrap_mem(ha);

 	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
 	    __func__, ha->host_no, ha->instance);)

 	return (ret);
}

/*
 * qim_query_fw
 *	Handles EXT_SC_QUERY_FW subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_query_fw(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
 	int		ret = 0;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	transfer_size;
 	EXT_FW		*pfw_prop;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


 	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
 	    __func__, ha->host_no, ha->instance);)

 	if (qim_get_ioctl_scrap_mem(ha, (void **)&pfw_prop,
 	    sizeof(EXT_FW))) {
 		/* not enough memory */
 		pext->Status = EXT_STATUS_NO_MEMORY;
 		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
 		    "size requested=%ld.\n",
 		    __func__, ha->host_no, ha->instance,
 		    (ulong)sizeof(EXT_FW));)
 		return (ret);
 	}

	pfw_prop->Version[0] = dr_ha->fw_major_version; 
	pfw_prop->Version[1] = dr_ha->fw_minor_version; 
	pfw_prop->Version[2] = dr_ha->fw_subminor_version;

	transfer_size = sizeof(EXT_FW);

	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,pext->AddrMode);
	kernel_tmp = (uint8_t *)pfw_prop;
	ret = copy_to_user(usr_temp, kernel_tmp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;
	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

static int
qim_msiocb_passthru(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int cmd,
    int mode)
{
	int		ret = 0;
	fc_lun_t	*ptemp_fclun = NULL;	/* buf from scrap mem */
	fc_port_t	*ptemp_fcport = NULL;	/* buf from scrap mem */
	struct scsi_cmnd *pscsi_cmd = NULL;	/* buf from scrap mem */
	struct scsi_device *pscsi_dev = NULL;	/* buf from scrap mem */
	struct request *request = NULL;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	/* check on current topology */
	if ((dr_ha->current_topology != ISP_CFG_F) &&
	    (dr_ha->current_topology != ISP_CFG_FL)) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR not in F/FL mode\n",
		    __func__, ha->host_no, ha->instance);)
		return (ret);
	}

	if (ha->ioctl_mem_size <= 0) {
		if (qim_get_new_ioctl_dma_mem(ha,
		    QLA_INITIAL_IOCTLMEM_SIZE) != QIM_SUCCESS) {

			DEBUG9_10(printk("%s: ERROR cannot alloc DMA "
			    "buffer size=%x.\n",
			    __func__, QLA_INITIAL_IOCTLMEM_SIZE);)

			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}
	}

	if (pext->ResponseLen > ha->ioctl_mem_size) {
		if (qim_get_new_ioctl_dma_mem(ha, pext->ResponseLen) !=
		    QIM_SUCCESS) {

			DEBUG9_10(printk("%s: ERROR cannot alloc requested"
			    "DMA buffer size %x.\n",
			    __func__, pext->ResponseLen);)

			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}

		DEBUG9(printk("%s(%ld): inst=%ld rsp buf length larger than "
		    "existing size. Additional mem alloc successful.\n",
		    __func__, ha->host_no, ha->instance);)
	}

	DEBUG9(printk("%s(%ld): inst=%ld req buf verified.\n",
	    __func__, ha->host_no, ha->instance);)

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pscsi_cmd,
	    sizeof(struct scsi_cmnd))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "cmd size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct scsi_cmnd));)
		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pscsi_dev,
	    sizeof(struct scsi_device))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "cmd size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct scsi_device));)
		return (ret);
	}

	pscsi_cmd->device = pscsi_dev;

	if (qim_get_ioctl_scrap_mem(ha, (void **)&request,
	    sizeof(struct request))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct request));)
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}
	pscsi_cmd->request = request;
	pscsi_cmd->request->nr_hw_segments = 1;

	if (qim_get_ioctl_scrap_mem(ha, (void **)&ptemp_fcport,
	    sizeof(fc_port_t))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "fcport size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(fc_port_t));)
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&ptemp_fclun,
	    sizeof(fc_lun_t))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "fclun size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(fc_lun_t));)
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* initialize */
	memset(ha->ioctl_mem, 0, ha->ioctl_mem_size);

	switch (cmd) {
	case EXT_CC_SEND_FCCT_PASSTHRU:
		DEBUG9(printk("%s: got CT passthru cmd.\n", __func__));
		ret = qim_send_fcct(ha, pext, pscsi_cmd, ptemp_fcport,
		    ptemp_fclun, mode);
		break;
#if 0
	case EXT_CC_SEND_ELS_PASSTHRU:
		DEBUG9(printk("%s: got ELS passthru cmd.\n", __func__));
		if (!IS_QLA2100(dr_ha) && !IS_QLA2200(dr_ha)) {
			ret = qim_send_els_passthru(ha, pext, pscsi_cmd,
			    ptemp_fcport, ptemp_fclun, mode);
			break;
		}
#endif
		/*FALLTHROUGH */
	default:
		DEBUG9_10(printk("%s: got invalid cmd.\n", __func__));
		break;
	}

	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

#if 0
/* RLU: this need to be handled later */
/*
 * qim_send_els_passthru
 *	Passes the ELS command down to firmware as MSIOCB and
 *	copies the response back when it completes.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_send_els_passthru(struct qla_host_ioctl *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi_cmd, fc_port_t *ptmp_fcport, fc_lun_t *ptmp_fclun,
    int mode)
{
	int		ret = 0;

	uint8_t		invalid_wwn = 0;
	uint8_t		*ptmp_stat;
	uint8_t		*pusr_req_buf;
	uint8_t		*presp_payload;
	uint32_t	payload_len;
	uint32_t	usr_req_len;

	int		found;
	uint16_t	next_loop_id;
	fc_port_t	*fcport;

	EXT_ELS_PT_REQ	*pels_pt_req;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	usr_req_len = pext->RequestLen - sizeof(EXT_ELS_PT_REQ);
	if (usr_req_len > ha->ioctl_mem_size) {
		pext->Status = EXT_STATUS_INVALID_PARAM;

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR ReqLen too big=%x.\n",
		    __func__, ha->host_no, ha->instance, pext->RequestLen);)

		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pels_pt_req,
	    sizeof(EXT_ELS_PT_REQ))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "els_pt_req size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_ELS_PT_REQ));)
		return (ret);
	}

	/* copy request buffer */
	
	ret = copy_from_user(pels_pt_req, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), sizeof(EXT_ELS_PT_REQ));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR"
		    "copy_from_user() of struct failed (%d).\n",
		    __func__, ha->host_no, ha->instance, ret);)

		return (-EFAULT);
	}

	pusr_req_buf = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode) + sizeof(EXT_ELS_PT_REQ);
	
	ret = copy_from_user(ha->ioctl_mem, pusr_req_buf, usr_req_len);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR"
		    "copy_from_user() of request buf failed (%d).\n",
		    __func__, ha->host_no, ha->instance, ret);)

		return (-EFAULT);
	}

	DEBUG9(printk("%s(%ld): inst=%ld after copy request.\n",
	    __func__, ha->host_no, ha->instance);)
	
	/* check on loop down (1) */
	if (atomic_read(&ha->loop_state) != LOOP_READY || 
	    test_bit(CFG_ACTIVE, &ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags)) {

		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld before dest port validation- loop not "
		    "ready; cannot proceed.\n",
		    __func__, ha->host_no, ha->instance);)

		pext->Status = EXT_STATUS_BUSY;

		return (ret);
	}

	/*********************************/
	/* Validate the destination port */
	/*********************************/

	/* first: WWN cannot be zero if no PID is specified */
	invalid_wwn = qim_is_wwn_zero(pels_pt_req->WWPN);
	if (invalid_wwn && !(pels_pt_req->ValidMask & EXT_DEF_PID_VALID)) {
		/* error: both are not set. */
		pext->Status = EXT_STATUS_INVALID_PARAM;

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR no valid WWPN/PID\n",
		    __func__, ha->host_no, ha->instance);)

		return (ret);
	}

	/* second: it cannot be the local/current HBA itself */
	if (!invalid_wwn) {
		if (memcmp(ha->port_name, pels_pt_req->WWPN,
		    EXT_DEF_WWN_NAME_SIZE) == 0) {

			/* local HBA specified. */

			pext->Status = EXT_STATUS_INVALID_PARAM;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR local HBA's "
			    "WWPN found.\n",
			    __func__, ha->host_no, ha->instance);)

			return (ret);
		}
	} else { /* using PID */
		if (pels_pt_req->Id[1] == ha->d_id.r.d_id[2]
		    && pels_pt_req->Id[2] == ha->d_id.r.d_id[1]
		    && pels_pt_req->Id[3] == ha->d_id.r.d_id[0]) {

			/* local HBA specified. */

			pext->Status = EXT_STATUS_INVALID_PARAM;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR local HBA's "
			    "PID found.\n",
			    __func__, ha->host_no, ha->instance);)

			return (ret);
		}
	}

	/************************/
	/* Now find the loop ID */
	/************************/

	found = 0;
	fcport = NULL;
	list_for_each_entry(fcport, &ha->fcports, list) {
		if (fcport->port_type != FCT_INITIATOR ||
		    fcport->port_type != FCT_TARGET)
			continue;

		if (!invalid_wwn) {
			/* search with WWPN */
			if (memcmp(pels_pt_req->WWPN, fcport->port_name,
			    EXT_DEF_WWN_NAME_SIZE))
				continue;
		} else {
			/* search with PID */
			if (pels_pt_req->Id[1] != fcport->d_id.r.d_id[2]
			    || pels_pt_req->Id[2] != fcport->d_id.r.d_id[1]
			    || pels_pt_req->Id[3] != fcport->d_id.r.d_id[0])
				continue;
		}

		found++;
	}

	if (!found) {
		/* invalid WWN or PID specified */
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR WWPN/PID invalid.\n",
		    __func__, ha->host_no, ha->instance);)

		return (ret);
	}

	/* If this is for a host device, check if we need to perform login */
	if (fcport->port_type == FCT_INITIATOR &&
	    fcport->loop_id >= ha->last_loop_id) {

		next_loop_id = 0;
		ret = qim_fabric_login(ha, fcport, &next_loop_id);
		if (ret != QIM_SUCCESS) {
			/* login failed. */
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;

			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR login to "
			    "host port failed. loop_id=%02x pid=%02x%02x%02x "
			    "ret=%d.\n",
			    __func__, ha->host_no, ha->instance,
			    fcport->loop_id, fcport->d_id.b.domain,
			    fcport->d_id.b.area, fcport->d_id.b.al_pa, ret);)

			return (ret);
		}
	}

	/* queue command */
	pels_pt_req->Lid = fcport->loop_id;

	if ((ret = qim_ioctl_ms_queuecommand(ha, pext, pscsi_cmd,
	    ptmp_fcport, ptmp_fclun, pels_pt_req))) {
		return (ret);
	}

	if ((CMD_COMPL_STATUS(pscsi_cmd) != 0 &&
	    CMD_COMPL_STATUS(pscsi_cmd) != CS_DATA_UNDERRUN &&
	    CMD_COMPL_STATUS(pscsi_cmd) != CS_DATA_OVERRUN)||
	    CMD_ENTRY_STATUS(pscsi_cmd) != 0) {
		DEBUG9_10(printk("%s(%ld): inst=%ld cmd returned error=%x.\n",
			__func__, ha->host_no, ha->instance,
			CMD_COMPL_STATUS(pscsi_cmd)));
			pext->Status = EXT_STATUS_ERR;
		return (ret);
	}

	/* check on data returned */
	ptmp_stat = (uint8_t *)ha->ioctl_mem + FC_HEADER_LEN;

	if (*ptmp_stat == ELS_STAT_LS_RJT) {
		payload_len = FC_HEADER_LEN + ELS_RJT_LENGTH;

	} else if (*ptmp_stat == ELS_STAT_LS_ACC) {
		payload_len = pext->ResponseLen - sizeof(EXT_ELS_PT_REQ);

	} else {
		/* invalid. just copy the status word. */
		DEBUG9_10(printk("%s(%ld): inst=%ld invalid stat "
		    "returned =0x%x.\n",
		    __func__, ha->host_no, ha->instance, *ptmp_stat);)

		payload_len = FC_HEADER_LEN + 4;
	}

	DEBUG9(printk("%s(%ld): inst=%ld data dump-\n",
	    __func__, ha->host_no, ha->instance);)
	DEBUG9(qim_dump_buffer((uint8_t *)ptmp_stat,
	    pext->ResponseLen - sizeof(EXT_ELS_PT_REQ) - FC_HEADER_LEN);)
	
	/* Verify response buffer to be written */
	/* The data returned include FC frame header */
	presp_payload = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode) + sizeof(EXT_ELS_PT_REQ);

	/* copy back data returned to response buffer */
	ret = copy_to_user(presp_payload, ha->ioctl_mem, payload_len);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance);)
		return (-EFAULT);
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting normally.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}
#endif

/*
 * qim_send_fcct
 *	Passes the FC CT command down to firmware as MSIOCB and
 *	copies the response back when it completes.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_send_fcct(struct qla_host_ioctl *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi_cmd, fc_port_t *ptmp_fcport, fc_lun_t *ptmp_fclun,
    int mode)
{
	int		ret = 0;
	int		tmp_rval = 0;
	uint16_t	mb[MAILBOX_REGISTER_COUNT];
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (pext->RequestLen > ha->ioctl_mem_size) {
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR ReqLen too big=%x.\n",
		    __func__, ha->host_no, ha->instance, pext->RequestLen);)

		return (ret);
	}

	/* copy request buffer */
	ret = copy_from_user(ha->ioctl_mem, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf. ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret);)

		return (-EFAULT);
	}

	DEBUG9(printk("%s(%ld): inst=%ld after copy request.\n",
	    __func__, ha->host_no, ha->instance);)

	/* check on management server login status */
	if (dr_ha->flags.management_server_logged_in == 0) {
		/* login to management server device */

		tmp_rval = qim_login_fabric(dr_ha, MANAGEMENT_SERVER,
		    0xff, 0xff, 0xfa, &mb[0], BIT_1);

		if (tmp_rval != 0 || mb[0] != 0x4000) {
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;

	 		DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR login to MS.\n",
			    __func__, ha->host_no, ha->instance);)

			return (ret);
		}

		dr_ha->flags.management_server_logged_in = 1;
	}

	DEBUG9(printk("%s(%ld): success login to MS.\n",
	    __func__, ha->host_no);)

	/* queue command */
	if ((ret = qim_ioctl_ms_queuecommand(ha, pext, pscsi_cmd,
	    ptmp_fcport, ptmp_fclun, NULL))) {
		return (ret);
	}

	if ((CMD_COMPL_STATUS(pscsi_cmd) != 0 &&
	    CMD_COMPL_STATUS(pscsi_cmd) != CS_DATA_UNDERRUN &&
	    CMD_COMPL_STATUS(pscsi_cmd) != CS_DATA_OVERRUN)||
	    CMD_ENTRY_STATUS(pscsi_cmd) != 0) {
		DEBUG9_10(printk("%s(%ld): inst=%ld cmd returned error=%x.\n",
		    __func__, ha->host_no, ha->instance,
		    CMD_COMPL_STATUS(pscsi_cmd));)
		pext->Status = EXT_STATUS_ERR;
		return (ret);
	}

	/* sending back data returned from Management Server */
	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ha->ioctl_mem, pext->ResponseLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance);)
		return (-EFAULT);
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

static int
qim_ioctl_ms_queuecommand(struct qla_host_ioctl *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi_cmd, fc_port_t *pfcport, fc_lun_t *pfclun,
    EXT_ELS_PT_REQ *pels_pt_req)
{
	int		ret = 0;
	int		tmp_rval = 0;
	os_lun_t	*plq;
	os_tgt_t	*ptq;
	srb_t		*sp = NULL;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	/* alloc sp */
	if ((sp = qim_get_new_sp(dr_ha)) == NULL) {

		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s: ERROR cannot alloc sp %p.\n",
		    __func__, sp);)

		return (ret);
	}

	DEBUG9(printk("%s(%ld): inst=%ld after alloc sp.\n",
	    __func__, ha->host_no, ha->instance);)

	DEBUG9(printk("%s(%ld): ioctl_tq=%p ioctl_lq=%p.\n",
	    __func__, ha->host_no, ha->ioctl->ioctl_tq, ha->ioctl->ioctl_lq);)

	/* setup sp for this command */
	ptq = ha->ioctl->ioctl_tq;
	plq = ha->ioctl->ioctl_lq;

	DEBUG9(printk("%s(%ld): pfclun=%p pfcport=%p pscsi_cmd=%p.\n",
	    __func__, ha->host_no, pfclun, pfcport, pscsi_cmd);)

	sp->cmd = pscsi_cmd;
	sp->flags = SRB_IOCTL;
	sp->lun_queue = plq;
	sp->tgt_queue = ptq;
	pfclun->fcport = pfcport;
	pfclun->lun = 0;
	plq->fclun = pfclun;
	plq->fclun->fcport->ha = dr_ha;

	DEBUG9(printk("%s(%ld): pscsi_cmd->device=%p.\n",
	    __func__, ha->host_no, pscsi_cmd->device);)

	/* init scsi_cmd */
	pscsi_cmd->device->host = dr_ha->host;
	pscsi_cmd->scsi_done = qim_msiocb_done;

	/* check on loop down (2)- check again just before sending cmd out. */
	if (atomic_read(&dr_ha->loop_state) != LOOP_READY || 
	    test_bit(CFG_ACTIVE, &dr_ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &dr_ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &dr_ha->dpc_flags)) {

		DEBUG9_10(printk("%s(%ld): inst=%ld before issue cmd- loop "
		    "not ready.\n",
		    __func__, ha->host_no, ha->instance);)

		pext->Status = EXT_STATUS_BUSY;

		atomic_set(&sp->ref_count, 0);
		add_to_free_queue (dr_ha, sp);

		return (ret);
	}

	DEBUG9(printk("%s(%ld): inst=%ld going to issue command.\n",
	    __func__, ha->host_no, ha->instance);)

	tmp_rval = qim_start_ms_cmd(ha, pext, sp, pels_pt_req);

	DEBUG9(printk("%s(%ld): inst=%ld after issue command.\n",
	    __func__, ha->host_no, ha->instance);)

	if (tmp_rval != 0) {
		/* We waited and post function did not get called */
		DEBUG9_10(printk("%s(%ld): inst=%ld command timed out.\n",
		    __func__, ha->host_no, ha->instance);)
	
		if (tmp_rval == QLA_MEMORY_ALLOC_FAILED) {
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (dr_ha, sp);
		}

		pext->Status = EXT_STATUS_MS_NO_RESPONSE;

		return (ret);
	}

	return (ret);
}


/*
 * qim_start_ms_cmd
 *	Allocates an MSIOCB request pkt and sends out the passthru cmd.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	qim local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
qim_start_ms_cmd(struct qla_host_ioctl *ha, EXT_IOCTL *pext, srb_t *sp,
    EXT_ELS_PT_REQ *pels_pt_req)
{
#define	ELS_REQUEST_RCTL	0x22
#define ELS_REPLY_RCTL		0x23

#if 0
	uint32_t	usr_req_len;
	uint32_t	usr_resp_len;

	ms_iocb_entry_t		*pkt;
	unsigned long		cpu_flags = 0;
	struct scsi_qla_host	*dr_ha = ha->dr_data;
#endif


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

#if 0
	/* get spin lock for this operation */
	spin_lock_irqsave(&dr_ha->hardware_lock, cpu_flags);

	/* Get MS request packet. */
	pkt = (ms_iocb_entry_t *)qim_ms_req_pkt(dr_ha, sp);
	if (pkt == NULL) {
		/* release spin lock and return error. */
		spin_unlock_irqrestore(&dr_ha->hardware_lock, cpu_flags);

		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld MSIOCB PT - could not get "
		    "Request Packet.\n", __func__, ha->host_no, ha->instance);)
		return (QLA_MEMORY_ALLOC_FAILED);
	}

	usr_req_len = pext->RequestLen;
	usr_resp_len = pext->ResponseLen;

	if (IS_QLA24XX(dr_ha) || IS_QLA54XX(dr_ha)) {
		struct ct_entry_24xx *ct_pkt;
		struct els_entry_24xx *els_pkt;

		ct_pkt = (struct ct_entry_24xx *)pkt;
		els_pkt = (struct els_entry_24xx *)pkt;

		if (pels_pt_req != NULL) {
			/* ELS Passthru */
			usr_req_len -= sizeof(EXT_ELS_PT_REQ);
			usr_resp_len -= sizeof(EXT_ELS_PT_REQ);

			els_pkt->entry_type = ELS_IOCB_TYPE;
			els_pkt->entry_count = 1;
			els_pkt->nport_handle = cpu_to_le16(pels_pt_req->Lid);
			els_pkt->tx_dsd_count = __constant_cpu_to_le16(1);
			els_pkt->rx_dsd_count = __constant_cpu_to_le16(1);
			els_pkt->rx_byte_count = cpu_to_le32(usr_resp_len);
			els_pkt->tx_byte_count = cpu_to_le32(usr_req_len);
			els_pkt->sof_type = EST_SOFI3; /* assume class 3 */
			els_pkt->opcode = 0;
			els_pkt->control_flags = 0;

			if (pext->ResponseLen == 0) {
				memcpy(els_pkt->port_id, &pels_pt_req->Id[1],
				    3);
			}

			els_pkt->tx_address[0] =
			    cpu_to_le32(LSD(ha->ioctl_mem_phys));
			els_pkt->tx_address[1] =
			    cpu_to_le32(MSD(ha->ioctl_mem_phys));
			els_pkt->tx_len = els_pkt->tx_byte_count;
			els_pkt->rx_address[0] =
			    cpu_to_le32(LSD(ha->ioctl_mem_phys));
			els_pkt->rx_address[1] =
			    cpu_to_le32(MSD(ha->ioctl_mem_phys));
			els_pkt->rx_len = els_pkt->rx_byte_count;
		} else {
			/* CT Passthru */
			ct_pkt->entry_type = CT_IOCB_TYPE;
			ct_pkt->entry_count = 1;
			ct_pkt->nport_handle =
			    __constant_cpu_to_le16(NPH_SNS);
			ct_pkt->timeout = cpu_to_le16(ql2xioctltimeout);
			ct_pkt->cmd_dsd_count = __constant_cpu_to_le16(1);
			ct_pkt->rsp_dsd_count = __constant_cpu_to_le16(1);
			ct_pkt->rsp_byte_count = cpu_to_le32(usr_resp_len);
			ct_pkt->cmd_byte_count = cpu_to_le32(usr_req_len);
			ct_pkt->dseg_0_address[0] =
			    cpu_to_le32(LSD(ha->ioctl_mem_phys));
			ct_pkt->dseg_0_address[1] =
			    cpu_to_le32(MSD(ha->ioctl_mem_phys));
			ct_pkt->dseg_0_len = ct_pkt->cmd_byte_count;
			ct_pkt->dseg_1_address[0] =
			    cpu_to_le32(LSD(ha->ioctl_mem_phys));
			ct_pkt->dseg_1_address[1] =
			    cpu_to_le32(MSD(ha->ioctl_mem_phys));
			ct_pkt->dseg_1_len = ct_pkt->rsp_byte_count;
		}
	} else {
		pkt->entry_type  = MS_IOCB_TYPE;
		pkt->entry_count = 1;

		if (pels_pt_req != NULL) {
			/* process ELS passthru command */
			usr_req_len -= sizeof(EXT_ELS_PT_REQ);
			usr_resp_len -= sizeof(EXT_ELS_PT_REQ);

			/* ELS passthru enabled */
			pkt->control_flags = cpu_to_le16(BIT_15); 
			SET_TARGET_ID(dr_ha, pkt->loop_id, pels_pt_req->Lid);
			pkt->type    = 1; /* ELS frame */

			if (pext->ResponseLen != 0) {
				pkt->r_ctl = ELS_REQUEST_RCTL;
				pkt->rx_id = 0;
			} else {
				pkt->r_ctl = ELS_REPLY_RCTL;
				pkt->rx_id =
				    cpu_to_le16(pels_pt_req->Rxid);
			}
		} else {
			usr_req_len = pext->RequestLen;
			usr_resp_len = pext->ResponseLen;
			SET_TARGET_ID(dr_ha, pkt->loop_id, MANAGEMENT_SERVER);
		}

		DEBUG9_10(printk("%s(%ld): inst=%ld using loop_id=%02x "
		    "req_len=%d, resp_len=%d. Initializing pkt.\n",
		    __func__, ha->host_no, ha->instance,
		    pkt->loop_id.extended, usr_req_len, usr_resp_len);)

		pkt->timeout = cpu_to_le16(ql2xioctltimeout);
		pkt->cmd_dsd_count = __constant_cpu_to_le16(1);
		pkt->total_dsd_count = __constant_cpu_to_le16(2);
		pkt->rsp_bytecount = cpu_to_le32(usr_resp_len);
		pkt->req_bytecount = cpu_to_le32(usr_req_len);

		/*
		 * Loading command payload address. user request is assumed
		 * to have been copied to ioctl_mem.
		 */
		pkt->dseg_req_address[0] = cpu_to_le32(LSD(ha->ioctl_mem_phys));
		pkt->dseg_req_address[1] = cpu_to_le32(MSD(ha->ioctl_mem_phys));
		pkt->dseg_req_length = cpu_to_le32(usr_req_len);

		/* loading response payload address */
		pkt->dseg_rsp_address[0] = cpu_to_le32(LSD(ha->ioctl_mem_phys));
		pkt->dseg_rsp_address[1] =cpu_to_le32(MSD(ha->ioctl_mem_phys));
		pkt->dseg_rsp_length = cpu_to_le32(usr_resp_len);
	}

	/* set flag to indicate IOCTL MSIOCB cmd in progress */
	ha->ioctl->MSIOCB_InProgress = 1;

	/* prepare for receiving completion. */
	qim_ioctl_sem_init(ha);

	sp->flags |= SRB_NO_TIMER;

	/* Issue command to ISP */
	sp->state = SRB_ACTIVE_STATE;
	qim_isp_cmd(dr_ha);

	DEBUG9(printk("%s(%ld): inst=%ld releasing hardware_lock.\n",
	    __func__, ha->host_no, ha->instance);)
	spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);

	DEBUG9(printk("%s(%ld): inst=%ld sleep for completion.\n",
	    __func__, ha->host_no, ha->instance);)

	down(&ha->ioctl->cmpl_sem);

	if (ha->ioctl->MSIOCB_InProgress == 1) {
	 	DEBUG9_10(printk("%s(%ld): inst=%ld timed out. exiting.\n",
		    __func__, ha->host_no, ha->instance);)
		return QIM_FAILED;
	}

#endif
	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return QIM_SUCCESS;
}

/*
 * qim_wwpn_to_scsiaddr
 *	Handles the EXT_CC_WWPN_TO_SCSIADDR command.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_wwpn_to_scsiaddr(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	fc_port_t	*tgt_fcport;
	os_tgt_t	*tq;
	uint8_t		tmp_wwpn[EXT_DEF_WWN_NAME_SIZE];
	uint32_t	b, tgt, l;
	EXT_SCSI_ADDR	tmp_addr;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (pext->RequestLen != EXT_DEF_WWN_NAME_SIZE ||
	    pext->ResponseLen < sizeof(EXT_SCSI_ADDR)) {
		/* error */
		DEBUG9_10(printk("%s(%ld): inst=%ld invalid WWN buffer size %d "
		    "received.\n",
		    __func__, ha->host_no, ha->instance, pext->ResponseLen);)
		pext->Status = EXT_STATUS_INVALID_PARAM;

		return (ret);
	}

	ret = copy_from_user(tmp_wwpn, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (ret) {
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy_from_user "
		    "failed(%d) on request buf.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		pext->Status = EXT_STATUS_COPY_ERR;
		return (-EFAULT);
	}

	tq = NULL;
	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		if (dr_ha->otgt[tgt] == NULL) {
			continue;
		}

		tq = dr_ha->otgt[tgt];
		if (tq->fcport == NULL) {
			break;
		}

		tgt_fcport = tq->fcport;
		if (memcmp(tmp_wwpn, tgt_fcport->port_name,
		    EXT_DEF_WWN_NAME_SIZE) == 0) {
			break;
		}
	}

	if (tq == NULL || tgt >= MAX_TARGETS) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld target dev not found. "
		    "tq=%p, tgt=%x.\n", __func__, ha->host_no, ha->instance,
		    tq, tgt);)
		return (ret);
	}

	if (tq->fcport == NULL) { 	/* dg 08/14/01 */
		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld target port not found. "
		    "tq=%p, tgt=%x.\n",
		    __func__, ha->host_no, ha->instance, tq, tgt);)
		return (ret);
	}	

	/* Currently we only have bus 0 and no translation on LUN */
	b = 0;
	l = 0;

	/*
	 * Return SCSI address. Currently no translation is done for
	 * LUN.
	 */
	tmp_addr.Bus = b;
	tmp_addr.Target = tgt;
	tmp_addr.Lun = l;
	if (pext->ResponseLen > sizeof(EXT_SCSI_ADDR))
		pext->ResponseLen = sizeof(EXT_SCSI_ADDR);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    &tmp_addr, pext->ResponseLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance);)
		return (-EFAULT);
	}

	DEBUG9(printk(KERN_INFO
	    "%s(%ld): Found t%d l%d for %02x%02x%02x%02x%02x%02x%02x%02x.\n",
	    __func__, ha->host_no,
	    tmp_addr.Target, tmp_addr.Lun,
	    tmp_wwpn[0], tmp_wwpn[1], tmp_wwpn[2], tmp_wwpn[3],
	    tmp_wwpn[4], tmp_wwpn[5], tmp_wwpn[6], tmp_wwpn[7]);)

	pext->Status = EXT_STATUS_OK;

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

/*
 * qim_scsi_passthru
 *	Handles all subcommands of the EXT_CC_SEND_SCSI_PASSTHRU command.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_scsi_passthru(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	struct scsi_cmnd *pscsi_cmd = NULL;
	struct scsi_device *pscsi_device = NULL;
	struct request *request = NULL;

	DEBUG9(printk("%s(%ld): entered.\n",
	    __func__, ha->host_no);)

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pscsi_cmd,
	    sizeof(struct scsi_cmnd))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct scsi_cmnd));)
		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pscsi_device,
	    sizeof(struct scsi_device))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct scsi_device));)
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}
	pscsi_cmd->device = pscsi_device;

	if (qim_get_ioctl_scrap_mem(ha, (void **)&request,
	    sizeof(struct request))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(struct request));)
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}
	pscsi_cmd->request = request;
	pscsi_cmd->request->nr_hw_segments = 1;

	switch(pext->SubCode) {
	case EXT_SC_SEND_SCSI_PASSTHRU:
		DEBUG9(printk("%s(%ld): got SCSI passthru cmd.\n",
		    __func__, ha->host_no);)
		ret = qim_sc_scsi_passthru(ha, pext, pscsi_cmd,
		    pscsi_device, mode);
		break;
	case EXT_SC_SEND_FC_SCSI_PASSTHRU:
		DEBUG9(printk("%s(%ld): got FC SCSI passthru cmd.\n",
		    __func__, ha->host_no);)
		ret = qim_sc_fc_scsi_passthru(ha, pext, pscsi_cmd,
		    pscsi_device, mode);
		break;
#if 0
/* RLU: this need to be handled later */
	case EXT_SC_SCSI3_PASSTHRU:
		DEBUG9(printk("%s(%ld): got SCSI3 passthru cmd.\n",
		    __func__, ha->host_no);)
		ret = qim_sc_scsi3_passthru(ha, pext, pscsi_cmd,
		    pscsi_device, mode);
		break;
#endif
	default:
		DEBUG9_10(printk("%s: got invalid cmd.\n", __func__));
		break;
	}

	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): exiting.\n",
	    __func__, ha->host_no);)

	return (ret);
}

/* RLU: this need to be handled later */
/**************************************************************************
*   qim_check_tgt_status
*
* Description:
*     Checks to see if the target or loop is down.
*
* Input:
*     cmd - pointer to Scsi cmd structure
*
* Returns:
*   1 - if target is present
*   0 - if target is not present
*
**************************************************************************/
static int
qim_check_tgt_status(struct scsi_qla_host *dr_ha, struct scsi_cmnd *cmd)
{
	os_lun_t        *lq;
	unsigned int	b, t, l;
	fc_port_t	*fcport;

	/* Generate LU queue on bus, target, LUN */
	b = cmd->device->channel;
	t = cmd->device->id;
	l = cmd->device->lun;

	if ((lq = GET_LU_Q(dr_ha,t,l)) == NULL) {
		return (QIM_FAILED);
	}

	fcport = lq->fclun->fcport;

	if (TGT_Q(dr_ha, t) == NULL ||
	    l >= dr_ha->max_luns ||
	    atomic_read(&fcport->state) == FCS_DEVICE_DEAD ||
	    atomic_read(&dr_ha->loop_state) == LOOP_DEAD ||
	    (!atomic_read(&dr_ha->loop_down_timer) &&
		atomic_read(&dr_ha->loop_state) == LOOP_DOWN) ||
	    test_bit(ABORT_ISP_ACTIVE, &dr_ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &dr_ha->dpc_flags) ||
	    atomic_read(&dr_ha->loop_state) != LOOP_READY) {

		DEBUG(printk(KERN_INFO
		    "scsi(%ld:%2d:%2d:%2d): %s connection is down\n",
		    dr_ha->host_no,
		    b, t, l,
		    __func__));

		cmd->result = DID_NO_CONNECT << 16;
		return (QIM_FAILED);
	}
	return (QIM_SUCCESS);
}

/**************************************************************************
*   qim_check_port_status
*
* Description:
*     Checks to see if the port or loop is down.
*
* Input:
*     fcport - pointer to fc_port_t structure.
*
* Returns:
*   1 - if port is present
*   0 - if port is not present
*
**************************************************************************/
static int
qim_check_port_status(struct scsi_qla_host *dr_ha, fc_port_t *fcport)
{
	if (fcport == NULL) {
		return (QIM_FAILED);
	}

	if (atomic_read(&fcport->state) == FCS_DEVICE_DEAD ||
	    atomic_read(&dr_ha->loop_state) == LOOP_DEAD) {
		return (QIM_FAILED);
	}

	if ((atomic_read(&fcport->state) != FCS_ONLINE) || 
	    (!atomic_read(&dr_ha->loop_down_timer) &&
		atomic_read(&dr_ha->loop_state) == LOOP_DOWN) ||
	    (test_bit(ABORT_ISP_ACTIVE, &dr_ha->dpc_flags)) ||
	    test_bit(CFG_ACTIVE, &dr_ha->cfg_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &dr_ha->dpc_flags) ||
	    atomic_read(&dr_ha->loop_state) != LOOP_READY) {

		DEBUG(printk(KERN_INFO
		    "scsi(%ld): Connection is down. fcport=%p.\n",
		    dr_ha->host_no, fcport));

		return (QLA_BUSY);
	}

	return (QIM_SUCCESS);
}

/*
 * This routine will allocate SP from the free queue
 * input:
 *        scsi_qla_host_t *
 * output:
 *        srb_t * or NULL
 */
static srb_t *
qim_get_new_sp(scsi_qla_host_t *dr_ha)
{
	srb_t *sp;

	sp = mempool_alloc(dr_ha->srb_mempool, GFP_ATOMIC);
	if (sp)
		atomic_set(&sp->ref_count, 1);
	return (sp);
}

/**
 * qim_req_pkt() - Retrieve a request packet from the request ring.
 * @ha: HA context
 *
 * Note: The caller must hold the hardware lock before calling this routine.
 *
 * Returns NULL if function failed, else, a pointer to the request packet.
 */
static request_t *
qim_req_pkt(scsi_qla_host_t *ha)
{
	device_reg_t __iomem *reg = ha->iobase;
	struct device_reg_24xx __iomem *reg24 =
	    (struct device_reg_24xx __iomem *) ha->iobase;
	request_t	*pkt = NULL;
	uint16_t	cnt;
	uint32_t	*dword_ptr;
	uint16_t	req_cnt = 1;


	if ((req_cnt + 2) >= ha->req_q_cnt) {
		/* Calculate number of free request entries. */
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha))
			cnt = (uint16_t)RD_REG_DWORD(&reg24->req_q_out);
		else
			cnt = qla2x00_debounce_register(
			    ISP_REQ_Q_OUT(ha, reg));
		if  (ha->req_ring_index < cnt)
			ha->req_q_cnt = cnt - ha->req_ring_index;
		else
			ha->req_q_cnt = ha->request_q_length -
			    (ha->req_ring_index - cnt);
	}
	/* If room for request in request ring. */
	if ((req_cnt + 2) < ha->req_q_cnt) {
		ha->req_q_cnt--;
		pkt = ha->request_ring_ptr;

		/* Zero out packet. */
		dword_ptr = (uint32_t *)pkt;
		for (cnt = 0; cnt < REQUEST_ENTRY_SIZE / 4; cnt++)
			*dword_ptr++ = 0;

		/* Set system defined field. */
		pkt->sys_define = (uint8_t)ha->req_ring_index;

		/* Set entry count. */
		pkt->entry_count = 1;

	}

	if (!pkt) {
		DEBUG2_3(printk("%s(): **** FAILED ****\n", __func__));
	}

	return (pkt);
}

/**
 * qim_isp_cmd() - Modify the request ring pointer.
 * @ha: HA context
 *
 * Note: The caller must hold the hardware lock before calling this routine.
 */
void
qim_isp_cmd(scsi_qla_host_t *ha)
{
	device_reg_t __iomem *reg = ha->iobase;

#if 0
	DEBUG5(printk("%s(): IOCB data:\n", __func__));
	DEBUG5(qim_dump_buffer(
	    (uint8_t *)ha->request_ring_ptr, REQUEST_ENTRY_SIZE));
#endif

	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else
		ha->request_ring_ptr++;

	/* Set chip new ring index. */
	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		struct device_reg_24xx __iomem *reg24 =
		    (struct device_reg_24xx __iomem *) ha->iobase;
		WRT_REG_DWORD(&reg24->req_q_in, ha->req_ring_index);
		RD_REG_DWORD_RELAXED(&reg24->req_q_in);	/* PCI Posting. */
	} else {
		WRT_REG_WORD(ISP_REQ_Q_IN(ha, reg), ha->req_ring_index);
		RD_REG_WORD_RELAXED(ISP_REQ_Q_IN(ha, reg)); /* PCI Posting. */
	}

}

/**
 * qim_marker() - Send a marker IOCB to the firmware.
 * @ha: HA context
 * @loop_id: loop ID
 * @lun: LUN
 * @type: marker modifier
 *
 * Can be called from both normal and interrupt context.
 *
 * Returns non-zero if a failure occured, else zero.
 */
int 
__qim_marker(scsi_qla_host_t *ha, uint16_t loop_id, uint16_t lun,
    uint8_t type)
{
	mrk_entry_t *mrk;
	struct mrk_entry_24xx *mrk24;

	mrk24 = NULL;
	mrk = (mrk_entry_t *)qim_req_pkt(ha);
	if (mrk == NULL) {
		DEBUG2_3(printk("%s(%ld): failed to allocate Marker IOCB.\n",
		    __func__, ha->host_no));

		return (QLA_FUNCTION_FAILED);
	}

	mrk->entry_type = MARKER_TYPE;
	mrk->modifier = type;
	if (type != MK_SYNC_ALL) {
		if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
			mrk24 = (struct mrk_entry_24xx *) mrk;
			mrk24->nport_handle = cpu_to_le16(loop_id);
			mrk24->lun[1] = LSB(lun);
			mrk24->lun[2] = MSB(lun);
		} else {
			SET_TARGET_ID(ha, mrk->target, loop_id);
			mrk->lun = cpu_to_le16(lun);
		}
	}
	wmb();

	qim_isp_cmd(ha);

	return (QLA_SUCCESS);
}

int 
qim_marker(scsi_qla_host_t *ha, uint16_t loop_id, uint16_t lun,
    uint8_t type)
{
	int ret;
	unsigned long flags = 0;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	ret = __qim_marker(ha, loop_id, lun, type);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return (ret);
}

static inline uint16_t
qim24xx_calc_iocbs(uint16_t dsds)
{
	uint16_t iocbs;

	iocbs = 1;
	if (dsds > 1) {
		iocbs += (dsds - 1) / 5;
		if ((dsds - 1) % 5)
			iocbs++;
	}
	return (iocbs);
}

static inline cont_a64_entry_t *
qim_prep_cont_type1_iocb(scsi_qla_host_t *ha)
{
	cont_a64_entry_t *cont_pkt;

	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else {
		ha->request_ring_ptr++;
	}

	cont_pkt = (cont_a64_entry_t *)ha->request_ring_ptr;

	/* Load packet defaults. */
	*((uint32_t *)(&cont_pkt->entry_type)) =
	    __constant_cpu_to_le32(CONTINUE_A64_TYPE);

	return (cont_pkt);
}

static inline void
qim24xx_build_scsi_iocbs(srb_t *sp, struct cmd_type_7 *cmd_pkt,
    uint16_t tot_dsds)
{
	uint16_t	avail_dsds;
	uint32_t	*cur_dsd;
	scsi_qla_host_t	*ha;
	struct scsi_cmnd *cmd;

	cmd = sp->cmd;

	/* Update entry type to indicate Command Type 3 IOCB */
	*((uint32_t *)(&cmd_pkt->entry_type)) =
	    __constant_cpu_to_le32(COMMAND_TYPE_7);

	/* No data transfer */
	if (cmd->request_bufflen == 0 || cmd->sc_data_direction == DMA_NONE) {
		cmd_pkt->byte_count = __constant_cpu_to_le32(0);
		return;
	}

	ha = sp->ha;

	/* Set transfer direction */
	if (cmd->sc_data_direction == DMA_TO_DEVICE)
		cmd_pkt->task_mgmt_flags =
		    __constant_cpu_to_le16(TMF_WRITE_DATA);
	else if (cmd->sc_data_direction == DMA_FROM_DEVICE)
		cmd_pkt->task_mgmt_flags =
		    __constant_cpu_to_le16(TMF_READ_DATA);

	/* One DSD is available in the Command Type 3 IOCB */
	avail_dsds = 1;
	cur_dsd = (uint32_t *)&cmd_pkt->dseg_0_address;

	/* Load data segments */
	if (cmd->use_sg != 0) {
		struct	scatterlist *cur_seg;
		struct	scatterlist *end_seg;

		cur_seg = (struct scatterlist *)cmd->request_buffer;
		end_seg = cur_seg + tot_dsds;
		while (cur_seg < end_seg) {
			dma_addr_t	sle_dma;
			cont_a64_entry_t *cont_pkt;

			/* Allocate additional continuation packets? */
			if (avail_dsds == 0) {
				/*
				 * Five DSDs are available in the Continuation
				 * Type 1 IOCB.
				 */
				cont_pkt = qim_prep_cont_type1_iocb(ha);
				cur_dsd = (uint32_t *)cont_pkt->dseg_0_address;
				avail_dsds = 5;
			}

			sle_dma = sg_dma_address(cur_seg);
			*cur_dsd++ = cpu_to_le32(LSD(sle_dma));
			*cur_dsd++ = cpu_to_le32(MSD(sle_dma));
			*cur_dsd++ = cpu_to_le32(sg_dma_len(cur_seg));
			avail_dsds--;

			cur_seg++;
		}
	} else {
		dma_addr_t	req_dma;
		struct page	*page;
		unsigned long	offset;

		page = virt_to_page(cmd->request_buffer);
		offset = ((unsigned long)cmd->request_buffer & ~PAGE_MASK);
		req_dma = pci_map_page(ha->pdev, page, offset,
		    cmd->request_bufflen, cmd->sc_data_direction);

		sp->dma_handle = req_dma;

		*cur_dsd++ = cpu_to_le32(LSD(req_dma));
		*cur_dsd++ = cpu_to_le32(MSD(req_dma));
		*cur_dsd++ = cpu_to_le32(cmd->request_bufflen);
	}
}

int
qim24xx_start_scsi(srb_t *sp)
{
	int		ret;
	unsigned long   flags;
	scsi_qla_host_t	*ha;
	fc_lun_t	*fclun;
	struct scsi_cmnd *cmd;
	uint32_t	*clr_ptr;
	uint32_t        index;
	uint32_t	handle;
	struct cmd_type_7 *cmd_pkt;
	uint32_t        timeout;
	struct scatterlist *sg;
	uint16_t	cnt;
	uint16_t	req_cnt;
	uint16_t	tot_dsds;
	struct device_reg_24xx __iomem *reg;
	char		tag[2];

	/* Setup device pointers. */
	ret = 0;
	fclun = sp->lun_queue->fclun;
	ha = fclun->fcport->ha;
	reg = (struct device_reg_24xx __iomem *)ha->iobase;
	cmd = sp->cmd;

	/* Send marker if required */
	if (ha->marker_needed != 0) {
		if (qim_marker(ha, 0, 0, MK_SYNC_ALL) != QLA_SUCCESS) {
			return (QIM_FAILED);
		}
		ha->marker_needed = 0;
	}

	/* Acquire ring specific lock */
	DEBUG9(printk("%s(%ld): inst=%ld getting hardware lock.\n",
	    __func__, ha->host_no, ha->instance);)
	spin_lock_irqsave(&ha->hardware_lock, flags);

	DEBUG9(printk("%s(%ld): inst=%ld got hardware lock.\n",
	    __func__, ha->host_no, ha->instance);)

	/* Check for room in outstanding command list. */
	handle = ha->current_outstanding_cmd;
	for (index = 1; index < MAX_OUTSTANDING_COMMANDS; index++) {
		handle++;
		if (handle == MAX_OUTSTANDING_COMMANDS)
			handle = 1;
		if (ha->outstanding_cmds[handle] == 0)
			break;
	}
	if (index == MAX_OUTSTANDING_COMMANDS)
		goto queuing_error_24xx;

	/* Calculate the number of request entries needed. */
	tot_dsds = 0;
	sg = NULL;
	if (cmd->use_sg) {
		sg = (struct scatterlist *) cmd->request_buffer;
		tot_dsds = pci_map_sg(ha->pdev, sg, cmd->use_sg,
		    cmd->sc_data_direction);
		if (tot_dsds == 0)
			goto queuing_error_24xx;
	} else if (cmd->request_bufflen) {
		tot_dsds++;
	}

	req_cnt = qim24xx_calc_iocbs(tot_dsds);
	if (ha->req_q_cnt < (req_cnt + 2)) {
		cnt = (uint16_t)RD_REG_DWORD_RELAXED(&reg->req_q_out);
		if (ha->req_ring_index < cnt)
			ha->req_q_cnt = cnt - ha->req_ring_index;
		else
			ha->req_q_cnt = ha->request_q_length -
				(ha->req_ring_index - cnt);
	}
	if (ha->req_q_cnt < (req_cnt + 2)) {
		if  (cmd->use_sg)
			pci_unmap_sg(ha->pdev, sg, cmd->use_sg,
			    cmd->sc_data_direction);
		goto queuing_error_24xx;
	}

	/* Build command packet. */
	ha->current_outstanding_cmd = handle;
	ha->outstanding_cmds[handle] = sp;
	sp->ha = ha;
	sp->cmd->host_scribble = (unsigned char *)(unsigned long)handle;
	ha->req_q_cnt -= req_cnt;

	cmd_pkt = (struct cmd_type_7 *)ha->request_ring_ptr;
	cmd_pkt->handle = handle;

	/* Zero out remaining portion of packet. */
	clr_ptr = (uint32_t *)cmd_pkt + 2;
	memset(clr_ptr, 0, REQUEST_ENTRY_SIZE - 8);

	cmd_pkt->nport_handle = cpu_to_le16(fclun->fcport->loop_id);
	cmd_pkt->port_id[0] = fclun->fcport->d_id.b.al_pa;
	cmd_pkt->port_id[1] = fclun->fcport->d_id.b.area;
	cmd_pkt->port_id[2] = fclun->fcport->d_id.b.domain;

	/* Update timeout. */
	timeout = (uint32_t)(cmd->timeout_per_command / HZ);
	if (timeout > FW_MAX_TIMEOUT)
		cmd_pkt->timeout =
		    __constant_cpu_to_le16(FW_MAX_TIMEOUT);
	else if (timeout > 25)
		cmd_pkt->timeout = cpu_to_le16((uint16_t)timeout -
		    (5 + QLA_CMD_TIMER_DELTA));
	else
		cmd_pkt->timeout = cpu_to_le16((uint16_t)timeout);

	cmd_pkt->dseg_count = cpu_to_le16(tot_dsds);

	/* Set LUN number*/
	cmd_pkt->lun[1] = LSB(fclun->lun);
	cmd_pkt->lun[2] = MSB(fclun->lun);
	host_to_fcp_swap(cmd_pkt->lun, sizeof(cmd_pkt->lun));

	/* Update tagged queuing modifier -- default is TSK_SIMPLE (0). */
	if (scsi_populate_tag_msg(cmd, tag)) {
		switch (tag[0]) {
		case MSG_HEAD_TAG:
			cmd_pkt->task = TSK_HEAD_OF_QUEUE;
			break;
		case MSG_ORDERED_TAG:
			cmd_pkt->task = TSK_ORDERED;
			break;
		}
	}

	/* Load SCSI command packet. */
	memcpy(cmd_pkt->fcp_cdb, cmd->cmnd, cmd->cmd_len);
	host_to_fcp_swap(cmd_pkt->fcp_cdb, sizeof(cmd_pkt->fcp_cdb));

	cmd_pkt->byte_count = cpu_to_le32((uint32_t)cmd->request_bufflen);

	/* Build IOCB segments */
	qim24xx_build_scsi_iocbs(sp, cmd_pkt, tot_dsds);

	/* Set total data segment count. */
	cmd_pkt->entry_count = (uint8_t)req_cnt;

	DEBUG9(printk("%s(%ld): inst=%ld calling wmb.\n",
	    __func__, ha->host_no, ha->instance);)

	wmb();

	DEBUG9(printk("%s(%ld): inst=%ld adjust ring index.\n",
	    __func__, ha->host_no, ha->instance);)

	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else
		ha->request_ring_ptr++;

	ha->actthreads++;
	ha->total_ios++;
	sp->lun_queue->out_cnt++;
	sp->flags |= SRB_DMA_VALID;
	sp->state = SRB_ACTIVE_STATE;
	sp->u_start = jiffies;

	/* Set chip new ring index. */
	WRT_REG_DWORD(&reg->req_q_in, ha->req_ring_index);
	RD_REG_DWORD_RELAXED(&reg->req_q_in);		/* PCI Posting. */

	DEBUG9(printk("%s(%ld): inst=%ld releasing hardware lock and exit.\n",
	    __func__, ha->host_no, ha->instance);)

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return (QLA_SUCCESS);

queuing_error_24xx:
	DEBUG9(printk("%s(%ld): inst=%ld releasing hardware lock w/ error.\n",
	    __func__, ha->host_no, ha->instance);)

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return (QLA_FUNCTION_FAILED);
}

/**
 * qim_start_scsi() - Send a SCSI command to the ISP
 * @sp: command to send to the ISP
 *
 * Returns non-zero if a failure occured, else zero.
 */
int
qim_start_scsi(srb_t *sp)
{
	unsigned long   flags;
	scsi_qla_host_t	*ha;
	fc_lun_t	*fclun;
	struct scsi_cmnd *cmd;
	uint32_t	*clr_ptr;
	uint32_t        index;
	uint32_t	handle;
	cmd_entry_t	*cmd_pkt;
	uint32_t        timeout;
	struct scatterlist *sg;
	uint16_t	cnt;
	uint16_t	req_cnt;
	uint16_t	tot_dsds;
	device_reg_t __iomem *reg;
	char		tag[2];


	/* Setup device pointers. */
	/* So we know we haven't pci_map'ed anything yet */
	fclun = sp->lun_queue->fclun;
	ha = fclun->fcport->ha;

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		DEBUG9(printk("%s(%ld): inst=%ld calling qim24xx_start_scsi.\n",
		    __func__, ha->host_no, ha->instance);)
		return qim24xx_start_scsi(sp);
	}

	tot_dsds = 0;
	reg = ha->iobase;
	cmd = sp->cmd;

	/* Send marker if required */
	if (ha->marker_needed != 0) {
		if (qim_marker(ha, 0, 0, MK_SYNC_ALL) != QIM_SUCCESS) {
			return (QIM_FAILED);
		}
		ha->marker_needed = 0;
	}

	/* Acquire ring specific lock */
	DEBUG9(printk("%s(%ld): inst=%ld getting hardware lock.\n",
	    __func__, ha->host_no, ha->instance);)

	spin_lock_irqsave(&ha->hardware_lock, flags);

	DEBUG9(printk("%s(%ld): inst=%ld got hardware lock.\n",
	    __func__, ha->host_no, ha->instance);)

	/* Check for room in outstanding command list. */
	handle = ha->current_outstanding_cmd;
	for (index = 1; index < MAX_OUTSTANDING_COMMANDS; index++) {
		handle++;
		if (handle == MAX_OUTSTANDING_COMMANDS)
			handle = 1;
		if (ha->outstanding_cmds[handle] == 0)
			break;
	}
	if (index == MAX_OUTSTANDING_COMMANDS)
		goto queuing_error;

	/* Map the sg table so we have an accurate count of sg entries needed */
	if (cmd->use_sg) {
		sg = (struct scatterlist *) cmd->request_buffer;
		tot_dsds = pci_map_sg(ha->pdev, sg, cmd->use_sg,
		    cmd->sc_data_direction);
		if (tot_dsds == 0)
			goto queuing_error;
	} else if (cmd->request_bufflen) {
		dma_addr_t	req_dma;
		struct page	*page;
		unsigned long	offset;

		page = virt_to_page(cmd->request_buffer);
		offset = ((unsigned long)cmd->request_buffer & ~PAGE_MASK);
		req_dma = pci_map_page(ha->pdev, page, offset,
		    cmd->request_bufflen, cmd->sc_data_direction);

		if (dma_mapping_error(req_dma))
			goto queuing_error;

		sp->dma_handle = req_dma;
		tot_dsds = 1;
	}

	/* Calculate the number of request entries needed. */
	req_cnt = (ha->calc_request_entries)(tot_dsds);
	if (ha->req_q_cnt < (req_cnt + 2)) {
		cnt = RD_REG_WORD_RELAXED(ISP_REQ_Q_OUT(ha, reg));
		if (ha->req_ring_index < cnt)
			ha->req_q_cnt = cnt - ha->req_ring_index;
		else
			ha->req_q_cnt = ha->request_q_length -
			    (ha->req_ring_index - cnt);
	}
	if (ha->req_q_cnt < (req_cnt + 2))
		goto queuing_error;

	/* Build command packet */
	ha->current_outstanding_cmd = handle;
	ha->outstanding_cmds[handle] = sp;
	sp->ha = ha;
	sp->cmd->host_scribble = (unsigned char *)(unsigned long)handle;
	ha->req_q_cnt -= req_cnt;

	cmd_pkt = (cmd_entry_t *)ha->request_ring_ptr;
	cmd_pkt->handle = handle;
	/* Zero out remaining portion of packet. */
	clr_ptr = (uint32_t *)cmd_pkt + 2;
	memset(clr_ptr, 0, REQUEST_ENTRY_SIZE - 8);
	cmd_pkt->dseg_count = cpu_to_le16(tot_dsds);

	/* Set target ID */
	SET_TARGET_ID(ha, cmd_pkt->target, fclun->fcport->loop_id);

	/* Set LUN number*/
	cmd_pkt->lun = cpu_to_le16(fclun->lun);

	/* Update tagged queuing modifier */
	cmd_pkt->control_flags = __constant_cpu_to_le16(CF_SIMPLE_TAG);
	if (scsi_populate_tag_msg(cmd, tag)) {
		switch (tag[0]) {
		case MSG_HEAD_TAG:
			cmd_pkt->control_flags =
			    __constant_cpu_to_le16(CF_HEAD_TAG);
			break;
		case MSG_ORDERED_TAG:
			cmd_pkt->control_flags =
			    __constant_cpu_to_le16(CF_ORDERED_TAG);
			break;
		}
	}

	/*
	 * Allocate at least 5 (+ QLA_CMD_TIMER_DELTA) seconds for RISC timeout.
	 */
	timeout = (uint32_t)(cmd->timeout_per_command / HZ);
	if (timeout > 65535)
		cmd_pkt->timeout = __constant_cpu_to_le16(0);
	else if (timeout > 25)
		cmd_pkt->timeout = cpu_to_le16((uint16_t)timeout -
		    (5 + QLA_CMD_TIMER_DELTA));
	else
		cmd_pkt->timeout = cpu_to_le16((uint16_t)timeout);

	/* Load SCSI command packet. */
	memcpy(cmd_pkt->scsi_cdb, cmd->cmnd, cmd->cmd_len);
	cmd_pkt->byte_count = cpu_to_le32((uint32_t)cmd->request_bufflen);

	/* Build IOCB segments */
	(ha->build_scsi_iocbs)(sp, cmd_pkt, tot_dsds);

	/* Set total data segment count. */
	cmd_pkt->entry_count = (uint8_t)req_cnt;
	wmb();

	/* Adjust ring index. */
	ha->req_ring_index++;
	if (ha->req_ring_index == ha->request_q_length) {
		ha->req_ring_index = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else
		ha->request_ring_ptr++;

	ha->actthreads++;
	ha->total_ios++;
	sp->lun_queue->out_cnt++;
	sp->flags |= SRB_DMA_VALID;
	sp->state = SRB_ACTIVE_STATE;
	sp->u_start = jiffies;

	/* Set chip new ring index. */
	WRT_REG_WORD(ISP_REQ_Q_IN(ha, reg), ha->req_ring_index);
	RD_REG_WORD_RELAXED(ISP_REQ_Q_IN(ha, reg));	/* PCI Posting. */

	DEBUG9(printk("%s(%ld): inst=%ld releasing hardware lock and exit.\n",
	    __func__, ha->host_no, ha->instance);)

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	return (QIM_SUCCESS);

queuing_error:
	if (cmd->use_sg && tot_dsds) {
		sg = (struct scatterlist *) cmd->request_buffer;
		pci_unmap_sg(ha->pdev, sg, cmd->use_sg,
		    cmd->sc_data_direction);
	} else if (tot_dsds) {
		pci_unmap_page(ha->pdev, sp->dma_handle, cmd->request_bufflen,
		    cmd->sc_data_direction);
	}

	DEBUG9(printk("%s(%ld): inst=%ld releasing hardware lock w/ error.\n",
	    __func__, ha->host_no, ha->instance);)

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return (QIM_FAILED);
}

/**************************************************************************
*   qim_cmd_timeout
*
* Description:
*       Handles the command if it times out in any state.
*
* Input:
*     sp - pointer to validate
*
* Returns:
* None.
* Note:Need to add the support for if( sp->state == SRB_FAILOVER_STATE).
**************************************************************************/
void
qim_cmd_timeout(srb_t *sp)
{
	int t, l;
	int processed;
	scsi_qla_host_t *vis_ha, *dest_ha;
	struct scsi_cmnd *cmd;
	unsigned long flags, cpu_flags;
	fc_port_t *fcport;

	cmd = sp->cmd;
	vis_ha = (scsi_qla_host_t *)cmd->device->host->hostdata;

	DEBUG9(printk("cmd_timeout: Entering sp->state = %x\n", sp->state);)
	printk("cmd_timeout: Entering sp->state = %x\n", sp->state);

	t = cmd->device->id;
	l = cmd->device->lun;
	fcport = sp->fclun->fcport;
	dest_ha = sp->ha;

	/*
	 * If IO is found either in retry Queue 
	 *    OR in Lun Queue
	 * Return this IO back to host
	 */
	spin_lock_irqsave(&vis_ha->list_lock, flags);
	processed = 0;
	if (sp->state == SRB_PENDING_STATE) {
		__del_from_pending_queue(vis_ha, sp);
		DEBUG10(printk("scsi(%ld): Found in Pending queue pid %ld, "
		    "State = %x., fcport state=%d sjiffs=%lx njiffs=%lx\n",
		    vis_ha->host_no, cmd->serial_number, sp->state,
		    atomic_read(&fcport->state), sp->r_start, jiffies));

		/*
		 * If FC_DEVICE is marked as dead return the cmd with
		 * DID_NO_CONNECT status.  Otherwise set the host_byte to
		 * DID_BUS_BUSY to let the OS  retry this cmd.
		 */
		if (atomic_read(&fcport->state) == FCS_DEVICE_DEAD ||
		    atomic_read(&fcport->ha->loop_state) == LOOP_DEAD) {
			cmd->result = DID_NO_CONNECT << 16;
			if (atomic_read(&fcport->ha->loop_state) == LOOP_DOWN) 
				sp->err_id = SRB_ERR_LOOP;
			else
				sp->err_id = SRB_ERR_PORT;
		} else {
			cmd->result = DID_BUS_BUSY << 16;
		}
		__add_to_done_queue(vis_ha, sp);
		processed++;
	} 
	spin_unlock_irqrestore(&vis_ha->list_lock, flags);

	if (processed) {
		/*
		printk("cmd_timeout: calling done().\n");
		qla2x00_done(vis_ha);
		*/
		printk("cmd_timeout: setting RESTART_Q flag.\n");
		set_bit(RESTART_QUEUES_NEEDED, &vis_ha->dpc_flags);
		up(vis_ha->dpc_wait);
		return;
	}

#if 0
	spin_lock_irqsave(&dest_ha->list_lock, flags);
	if ((sp->state == SRB_RETRY_STATE) ||
	    (sp->state == SRB_SCSI_RETRY_STATE)) {

		DEBUG10(printk("scsi(%ld): Found in (Scsi) Retry queue or "
		    "failover Q pid %ld, State = %x., fcport state=%d "
		    "jiffies=%lx retried=%d\n",
		    dest_ha->host_no, cmd->serial_number, sp->state,
		    atomic_read(&fcport->state), jiffies, cmd->retries));

		if ((sp->state == SRB_RETRY_STATE)) {
			__del_from_retry_queue(dest_ha, sp);
		} else if ((sp->state == SRB_SCSI_RETRY_STATE)) {
			__del_from_scsi_retry_queue(dest_ha, sp);
		} 

		/*
		 * If FC_DEVICE is marked as dead return the cmd with
		 * DID_NO_CONNECT status.  Otherwise set the host_byte to
		 * DID_BUS_BUSY to let the OS  retry this cmd.
		 */
		if ((atomic_read(&fcport->state) == FCS_DEVICE_DEAD) ||
		    atomic_read(&dest_ha->loop_state) == LOOP_DEAD) {
			qla2x00_extend_timeout(cmd, EXTEND_CMD_TIMEOUT);
			cmd->result = DID_NO_CONNECT << 16;
			if (atomic_read(&dest_ha->loop_state) == LOOP_DOWN) 
				sp->err_id = SRB_ERR_LOOP;
			else
				sp->err_id = SRB_ERR_PORT;
		} else {
			cmd->result = DID_BUS_BUSY << 16;
		}

		__add_to_done_queue(dest_ha, sp);
		processed++;
	} 
	spin_unlock_irqrestore(&dest_ha->list_lock, flags);

	if (processed) {
		qla2x00_done(dest_ha);
		return;
	}
#endif

	spin_lock_irqsave(&dest_ha->list_lock, cpu_flags);
	if (sp->state == SRB_DONE_STATE) {
		/* IO in done_q  -- leave it */
		DEBUG9(printk("scsi(%ld): Found in Done queue pid %ld sp=%p.\n",
		    dest_ha->host_no, cmd->serial_number, sp));
		printk("scsi(%ld): Found in Done queue pid %ld sp=%p.\n",
		    dest_ha->host_no, cmd->serial_number, sp);
	} else if (sp->state == SRB_SUSPENDED_STATE) {
		DEBUG9(printk("scsi(%ld): Found SP %p in suspended state  "
		    "- pid %ld:\n",
		    dest_ha->host_no, sp, cmd->serial_number));
		printk("scsi(%ld): Found SP %p in suspended state  "
		    "- pid %ld:\n",
		    dest_ha->host_no, sp, cmd->serial_number);
#if 0
		DEBUG9(printk("scsi(%ld): Found SP %p in suspended state  "
		    "- pid %ld:\n",
		    dest_ha->host_no, sp, cmd->serial_number));
		DEBUG9(qim_dump_buffer((uint8_t *)sp, sizeof(srb_t));)
#endif
	} else if (sp->state == SRB_ACTIVE_STATE) {
		/*
		 * IO is with ISP find the command in our active list.
		 */
		spin_unlock_irqrestore(&dest_ha->list_lock, cpu_flags);
		spin_lock_irqsave(&dest_ha->hardware_lock, flags);

		if (sp == dest_ha->outstanding_cmds[
		    (unsigned long)sp->cmd->host_scribble]) {

			DEBUG9(printk("scsi(%ld): Found in ISP pid=%ld "
			    "hdl=%ld\n", dest_ha->host_no, cmd->serial_number,
			    (unsigned long)sp->cmd->host_scribble));
			printk("scsi(%ld): Found in ISP pid=%ld "
			    "hdl=%ld\n", dest_ha->host_no, cmd->serial_number,
			    (unsigned long)sp->cmd->host_scribble);

#if 0
			if (sp->flags & SRB_TAPE) {
				/*
				 * We cannot allow the midlayer error handler
				 * to wakeup and begin the abort process.
				 * Extend the timer so that the firmware can
				 * properly return the IOCB.
				 */
				DEBUG9(printk("cmd_timeout: Extending timeout "
				    "of FCP2 tape command!\n"));
				qla2x00_extend_timeout(sp->cmd,
				    EXTEND_CMD_TIMEOUT);
			}
#endif
			printk("cmd_timeout: setting ISP_ABORT_NEEDED flag.\n");
			set_bit(ISP_ABORT_NEEDED, &dest_ha->dpc_flags);

			sp->state = SRB_ACTIVE_TIMEOUT_STATE;
			spin_unlock_irqrestore(&dest_ha->hardware_lock, flags);
			up(dest_ha->dpc_wait);
		} else {
			spin_unlock_irqrestore(&dest_ha->hardware_lock, flags);
			printk(KERN_INFO 
				"qla_cmd_timeout: State indicates it is with "
				"ISP, But not in active array\n");
		}
		spin_lock_irqsave(&dest_ha->list_lock, cpu_flags);
	} else if (sp->state == SRB_ACTIVE_TIMEOUT_STATE) {
		DEBUG9(printk("qla2100%ld: Found in Active timeout state"
			"pid %ld, State = %x., \n",
			dest_ha->host_no,
			sp->cmd->serial_number, sp->state);)
		printk("qla2100%ld: Found in Active timeout state"
			"pid %ld, State = %x., \n",
			dest_ha->host_no,
			sp->cmd->serial_number, sp->state);
	} else {
		/* EMPTY */
		DEBUG10(printk("cmd_timeout%ld: LOST command state = "
			"0x%x, sp=%p\n",
			vis_ha->host_no, sp->state,sp);)

		qla_printk(KERN_INFO, vis_ha,
			"cmd_timeout: LOST command state = 0x%x\n", sp->state);
	}
	spin_unlock_irqrestore(&dest_ha->list_lock, cpu_flags);

	DEBUG9(printk("cmd_timeout: Leaving\n");)
	printk("cmd_timeout: Leaving\n");
}

static inline void
qim_add_timer_to_cmd(struct scsi_qla_host *dr_ha, srb_t *sp, int timeout)
{
	init_timer(&sp->timer);
	sp->timer.expires = jiffies + timeout * HZ;
	sp->timer.data = (unsigned long) sp;
	sp->timer.function = (void (*) (unsigned long))qim_cmd_timeout;
	add_timer(&sp->timer);
        sp_get(dr_ha, sp); /* take command timeout reference */
}

static inline void
qim_delete_timer_from_cmd(srb_t *sp)
{
	if (sp->flags & SRB_NO_TIMER)
		return;

	if (del_timer(&sp->timer))
		sp_put((scsi_qla_host_t *)sp->cmd->device->host->hostdata, sp);
}

static int
qim_ioctl_scsi_queuecommand(struct qla_host_ioctl *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi_cmd, struct scsi_device *pscsi_dev,
    fc_port_t *pfcport, fc_lun_t *pfclun)
{
	int		ret = 0;
	int		ret2 = 0;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	lun = 0, tgt = 0;
#if defined(QL_DEBUG_LEVEL_9)
	uint32_t	b, t, l;
#endif
	os_lun_t	*lq = NULL;
	os_tgt_t	*tq = NULL;
	srb_t		*sp = NULL;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): entered.\n",
	    __func__, ha->host_no);)

	if ((sp = qim_get_new_sp(dr_ha)) == NULL) {

		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR cannot alloc sp.\n",
		    __func__, ha->host_no, ha->instance);)

		pext->Status = EXT_STATUS_NO_MEMORY;
		return (QIM_FAILED);
	}

	switch(pext->SubCode) {
	case EXT_SC_SEND_SCSI_PASSTHRU:

		tgt = pscsi_cmd->device->id;
		lun = pscsi_cmd->device->lun;

		tq = (os_tgt_t *)TGT_Q(dr_ha, tgt);
		lq = (os_lun_t *)LUN_Q(dr_ha, tgt, lun);

		break;
	case EXT_SC_SEND_FC_SCSI_PASSTHRU:
		if (pfcport == NULL || pfclun == NULL) {
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
			DEBUG9_10(printk("%s(%ld): inst=%ld received invalid "
			    "pointers. fcport=%p fclun=%p.\n",
			    __func__, ha->host_no, ha->instance, pfcport, pfclun);)
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (dr_ha, sp);
			return (QIM_FAILED);
		}

		if (pscsi_cmd->cmd_len != 6 && pscsi_cmd->cmd_len != 0x0A &&
		    pscsi_cmd->cmd_len != 0x0C && pscsi_cmd->cmd_len != 0x10) {
			DEBUG9_10(printk(KERN_WARNING
			    "%s(%ld): invalid Cdb Length 0x%x received.\n",
			    __func__, ha->host_no,
			    pscsi_cmd->cmd_len);)
			pext->Status = EXT_STATUS_INVALID_PARAM;
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (dr_ha, sp);
			return (QIM_FAILED);
		}
		tq = ha->ioctl->ioctl_tq;
		lq = ha->ioctl->ioctl_lq;

		break;
	case EXT_SC_SCSI3_PASSTHRU:
		if (pfcport == NULL || pfclun == NULL) {
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
			DEBUG9_10(printk("%s(%ld): inst=%ld received invalid "
			    "pointers. fcport=%p fclun=%p.\n",
			    __func__,
			    ha->host_no, ha->instance, pfcport, pfclun);)
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (dr_ha, sp);
			return (QIM_FAILED);
		}

		tq = ha->ioctl->ioctl_tq;
		lq = ha->ioctl->ioctl_lq;

		break;
	default:
		break;
	}

	sp->ha                = dr_ha;
	sp->cmd               = pscsi_cmd;
	sp->flags             = SRB_IOCTL;

	/* set local fc_scsi_cmd's sp pointer to sp */
	CMD_SP(pscsi_cmd)  = (void *) sp;

	if (pscsi_cmd->sc_data_direction == DMA_TO_DEVICE) {
		/* sending user data from pext->ResponseAdr to device */
		usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)ha->ioctl_mem;
		ret = copy_from_user(kernel_tmp, usr_temp, pext->ResponseLen);
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy "
			    "failed(%d) on rsp buf.\n",
			    __func__, ha->host_no, ha->instance, ret);)
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (dr_ha, sp);

			return (-EFAULT);
		}
	}

	pscsi_cmd->device->host    = dr_ha->host;

	/* mark this as a special delivery and collection command */
	pscsi_cmd->scsi_done = qim_scsi_pt_done;
	pscsi_cmd->device->tagged_supported = 0;
	pscsi_cmd->use_sg               = 0; /* no ScatterGather */
	pscsi_cmd->request_bufflen      = pext->ResponseLen;
	pscsi_cmd->request_buffer       = ha->ioctl_mem;
	if (pscsi_cmd->timeout_per_command == 0)
		pscsi_cmd->timeout_per_command  = ql2xioctltimeout * HZ;

	if (tq && lq) {
		if (pext->SubCode == EXT_SC_SEND_SCSI_PASSTHRU) {
			pfcport = lq->fclun->fcport;
			pfclun = lq->fclun;

			if (pfcport == NULL || pfclun == NULL) {
				pext->Status = EXT_STATUS_DEV_NOT_FOUND;
				DEBUG9_10(printk("%s(%ld): inst=%ld scsi pt "
				    "rcvd invalid ptrs. fcport=%p fclun=%p.\n",
				    __func__, ha->host_no, ha->instance,
				    pfcport, pfclun);)
				atomic_set(&sp->ref_count, 0);
				add_to_free_queue (dr_ha, sp);
				return (QIM_FAILED);
			}

		} else {
			if (pext->SubCode == EXT_SC_SCSI3_PASSTHRU)
				/* The LUN value is of FCP LUN format */
				tq->olun[pfclun->lun & 0xff] = lq;
			else
				tq->olun[pfclun->lun] = lq;

			tq->ha = dr_ha;
			lq->fclun = pfclun;
		}

		sp->lun_queue = lq;
		sp->tgt_queue = tq;
		sp->fclun = pfclun;
	} else {
		/* cannot send command without a queue. force error. */
		pfcport = NULL;
		DEBUG9_10(printk("%s(%ld): error dev q not found. tq=%p lq=%p.\n",
		    __func__, ha->host_no, tq, lq);)
	}

	DEBUG9({
		b = pscsi_cmd->device->channel;
		t = pscsi_cmd->device->id;
		l = pscsi_cmd->device->lun;
	})
	DEBUG9(printk("%s(%ld): ha instance=%ld tq=%p lq=%p "
	    "pfclun=%p pfcport=%p.\n",
	    __func__, ha->host_no, ha->instance, tq, lq, pfclun,
	    pfcport);)
	DEBUG9(printk("\tCDB=%02x %02x %02x %02x; b=%x t=%x l=%x.\n",
	    pscsi_cmd->cmnd[0], pscsi_cmd->cmnd[1], pscsi_cmd->cmnd[2],
	    pscsi_cmd->cmnd[3], b, t, l);)

	/*
	 * Check the status of the port
	 */
	if (pext->SubCode == EXT_SC_SEND_SCSI_PASSTHRU) {
		if (qim_check_tgt_status(dr_ha, pscsi_cmd)) {
			DEBUG9_10(printk("%s(%ld): inst=%ld check_tgt_status "
			    "failed.\n",
			    __func__, ha->host_no, ha->instance);)
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (dr_ha, sp);
			return (QIM_FAILED);
		}
	} else {
		ret2 = qim_check_port_status(dr_ha, pfcport);
		if (ret2 != QIM_SUCCESS) {
			DEBUG9_10(printk("%s(%ld): inst=%ld check_port_status "
			    "failed.\n",
			    __func__, ha->host_no, ha->instance);)
			if (ret2 == QLA_BUSY)
				pext->Status = EXT_STATUS_BUSY;
			else
				pext->Status = EXT_STATUS_ERR;
			atomic_set(&sp->ref_count, 0);
			add_to_free_queue (dr_ha, sp);
			return (QIM_FAILED);
		}
	}

	/* set flag to indicate IOCTL SCSI PassThru in progress */
	ha->ioctl->SCSIPT_InProgress = 1;
	ha->ioctl->ioctl_tov = (int)QLA_PT_CMD_DRV_TOV;

	/* prepare for receiving completion. */
	qim_ioctl_sem_init(ha);
	CMD_COMPL_STATUS(pscsi_cmd) = (int) IOCTL_INVALID_STATUS;

	/* send command to adapter */
	DEBUG9(printk("%s(%ld): inst=%ld sending command.\n",
	    __func__, ha->host_no, ha->instance);)

	/* Time the command via our standard driver-timer */
	  if ((pscsi_cmd->timeout_per_command / HZ) > ql2xcmdtimermin)
		qim_add_timer_to_cmd(dr_ha, sp,
		    (pscsi_cmd->timeout_per_command/HZ) -
		    QLA_CMD_TIMER_DELTA);
	else
		sp->flags |= SRB_NO_TIMER;

	if (qim_start_scsi(sp) != QIM_SUCCESS) {
		qim_delete_timer_from_cmd(sp);
		pext->Status = EXT_STATUS_ERR;
		ret = QIM_FAILED;
	}
#if 0
	add_to_pending_queue(dr_ha, sp);

	/*
	qim_next(dr_ha);
	*/
#endif

	DEBUG9(printk("%s(%ld): exiting.\n",
	    __func__, ha->host_no);)
	return (ret);
}

/*
 * qim_sc_scsi_passthru
 *	Handles EXT_SC_SEND_SCSI_PASSTHRU subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_sc_scsi_passthru(struct qla_host_ioctl *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi_cmd, struct scsi_device *pscsi_device, int mode)
{
	int		ret = 0;
	uint8_t		*usr_temp, *kernel_tmp;
	uint32_t	i;
	uint32_t	transfer_len;
	struct scsi_qla_host	*dr_ha = ha->dr_data;

	EXT_SCSI_PASSTHRU	*pscsi_pass;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (test_bit(FAILOVER_EVENT_NEEDED, &dr_ha->dpc_flags) ||
	    test_bit(FAILOVER_EVENT, &dr_ha->dpc_flags) ||
	    test_bit(FAILOVER_NEEDED, &dr_ha->dpc_flags)) {
		/* Stall intrusive passthru commands until failover complete */
		DEBUG9_10(printk("%s(%ld): inst=%ld failover in progress -- "
		    "returning busy.\n",
 		    __func__, ha->host_no, ha->instance);)
		pext->Status = EXT_STATUS_BUSY;
 		return (ret);
 	}

	if (pext->ResponseLen > ha->ioctl_mem_size) {
		if (qim_get_new_ioctl_dma_mem(ha, pext->ResponseLen) !=
		    QIM_SUCCESS) {
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR cannot alloc "
			    "requested DMA buffer size %x.\n",
			    __func__, ha->host_no, ha->instance,
			    pext->ResponseLen);)
			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pscsi_pass,
	    sizeof(EXT_SCSI_PASSTHRU))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_SCSI_PASSTHRU));)
		return (ret);
	}

	/* clear ioctl_mem to be used */
	memset(ha->ioctl_mem, 0, ha->ioctl_mem_size);

	/* Copy request buffer */
	usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode);
	kernel_tmp = (uint8_t *)pscsi_pass;
	ret = copy_from_user(kernel_tmp, usr_temp, sizeof(EXT_SCSI_PASSTHRU));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret);)
		return (-EFAULT);
	}

	/* set target coordinates */
	pscsi_cmd->device->id = pscsi_pass->TargetAddr.Target;
	pscsi_cmd->device->lun = pscsi_pass->TargetAddr.Lun;

	/* Verify target exists */
	if (TGT_Q(dr_ha, pscsi_cmd->device->id) == NULL) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR tgt %d not found.\n",
		    __func__,
		    ha->host_no, ha->instance, pscsi_cmd->device->id));
		return (ret);
	}

	/* Copy over cdb */

	if (pscsi_pass->CdbLength == 6) {
		pscsi_cmd->cmd_len = 6;

	} else if (pscsi_pass->CdbLength == 10) {
		pscsi_cmd->cmd_len = 0x0A;

	} else if (pscsi_pass->CdbLength == 12) {
		pscsi_cmd->cmd_len = 0x0C;

	} else {
		printk(KERN_WARNING
		    "%s: Unsupported Cdb Length=%x.\n",
		    __func__, pscsi_pass->CdbLength);

		pext->Status = EXT_STATUS_INVALID_PARAM;

		return (ret);
	}

	memcpy(pscsi_cmd->data_cmnd, pscsi_pass->Cdb, pscsi_cmd->cmd_len);
	memcpy(pscsi_cmd->cmnd, pscsi_pass->Cdb, pscsi_cmd->cmd_len);

	DEBUG9(printk("%s Dump of cdb buffer:\n", __func__);)
	DEBUG9(qim_dump_buffer((uint8_t *)&pscsi_cmd->data_cmnd[0],
	    pscsi_cmd->cmd_len);)

	switch (pscsi_pass->Direction) {
	case EXT_DEF_SCSI_PASSTHRU_DATA_OUT:
		pscsi_cmd->sc_data_direction = DMA_TO_DEVICE;
		break;
	case EXT_DEF_SCSI_PASSTHRU_DATA_IN:
		pscsi_cmd->sc_data_direction = DMA_FROM_DEVICE;
		break;
	default :	
		pscsi_cmd->sc_data_direction = DMA_NONE;
		break;
	}

	/* send command to adapter */
	DEBUG9(printk("%s(%ld): inst=%ld sending command.\n",
	    __func__, ha->host_no, ha->instance);)

//	read_lock(&qim_haioctl_list_lock);
	if ((ret = qim_ioctl_scsi_queuecommand(ha, pext, pscsi_cmd,
	    pscsi_device, NULL, NULL))) {
//		read_unlock(&qim_haioctl_list_lock);
		if (ret > 0)
			/* this is not a system error. only return system
			 * errors which are negative.
			 */
			ret = 0;

		return (ret);
	}
//	read_unlock(&qim_haioctl_list_lock);

	DEBUG9(printk("%s(%ld): inst=%ld waiting for completion.\n",
	    __func__, ha->host_no, ha->instance);)

	/* Wait for completion */
	down(&ha->ioctl->cmpl_sem);

	DEBUG9(printk("%s(%ld): inst=%ld completed.\n",
	    __func__, ha->host_no, ha->instance);)

#if 0
	if (ha->ioctl->SCSIPT_InProgress == 1) {

		printk(KERN_WARNING
		    "qim: scsi%ld ERROR passthru command timeout.\n",
		    ha->host_no);

		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (ret);
	}
#endif

	if (CMD_COMPL_STATUS(pscsi_cmd) == (int)IOCTL_INVALID_STATUS) {

		DEBUG10(printk("%s(%ld): inst=%ld ERROR - cmd not completed "
		    "or timed out.\n",
		    __func__, ha->host_no, ha->instance);)

		pext->Status = EXT_STATUS_ERR;
		return (ret);
	}

	switch (CMD_COMPL_STATUS(pscsi_cmd)) {
	case CS_INCOMPLETE:
	case CS_ABORTED:
	case CS_PORT_UNAVAILABLE:
	case CS_PORT_LOGGED_OUT:
	case CS_PORT_CONFIG_CHG:
	case CS_PORT_BUSY:
		DEBUG9_10(printk("%s(%ld): inst=%ld cs err = %x.\n",
		    __func__, ha->host_no, ha->instance,
		    CMD_COMPL_STATUS(pscsi_cmd));)
		pext->Status = EXT_STATUS_BUSY;

		return (ret);
	}

	if ((CMD_SCSI_STATUS(pscsi_cmd) & 0xff) != 0) {

		/* have done the post function */
		pext->Status       = EXT_STATUS_SCSI_STATUS;
		pext->DetailStatus = CMD_SCSI_STATUS(pscsi_cmd) & 0xff;

		DEBUG9_10(printk(KERN_INFO "%s(%ld): inst=%ld scsi err. "
		    "host status =0x%x, scsi status = 0x%x.\n",
		    __func__, ha->host_no, ha->instance,
		    CMD_COMPL_STATUS(pscsi_cmd), CMD_SCSI_STATUS(pscsi_cmd));)
	} else {
		if (CMD_COMPL_STATUS(pscsi_cmd) == CS_DATA_OVERRUN) {
			pext->Status = EXT_STATUS_DATA_OVERRUN;

			DEBUG9_10(printk(KERN_INFO
			    "%s(%ld): inst=%ld return overrun.\n",
			    __func__, ha->host_no, ha->instance);)

		} else if (CMD_COMPL_STATUS(pscsi_cmd) == CS_DATA_UNDERRUN &&
		    (CMD_SCSI_STATUS(pscsi_cmd) & SS_RESIDUAL_UNDER)) {
 			pext->Status = EXT_STATUS_DATA_UNDERRUN;

			DEBUG9_10(printk(KERN_INFO
			    "%s(%ld): inst=%ld return underrun.\n",
			    __func__, ha->host_no, ha->instance);)

		} else if (CMD_COMPL_STATUS(pscsi_cmd) != 0 ||
		    CMD_SCSI_STATUS(pscsi_cmd) != 0) {
			pext->Status = EXT_STATUS_ERR;

			DEBUG9_10(printk(KERN_INFO
			    "%s(%ld): inst=%ld, cs err=%x, scsi err=%x.\n",
			    __func__, ha->host_no, ha->instance,
			    CMD_COMPL_STATUS(pscsi_cmd),
			    CMD_SCSI_STATUS(pscsi_cmd));)

			return (ret);
		}
 	}

	/* copy up structure to make sense data available to user */
	pscsi_pass->SenseLength = CMD_ACTUAL_SNSLEN(pscsi_cmd);
	if (CMD_ACTUAL_SNSLEN(pscsi_cmd)) {
		for (i = 0; i < CMD_ACTUAL_SNSLEN(pscsi_cmd); i++)
			pscsi_pass->SenseData[i] = pscsi_cmd->sense_buffer[i];

		DEBUG10(printk("%s: sense len = %d. Dump of sense buffer:\n",
		    __func__, pscsi_pass->SenseLength);)
		DEBUG10(qim_dump_buffer(
		    (uint8_t *)&pscsi_pass->SenseData[0],
		    CMD_ACTUAL_SNSLEN(pscsi_cmd));)

	}

	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode);
	kernel_tmp = (uint8_t *)pscsi_pass;
	ret = copy_to_user(usr_temp, kernel_tmp,
	    sizeof(EXT_SCSI_PASSTHRU));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy sense "
		    "buffer.\n",
		    __func__, ha->host_no, ha->instance);)
		return (-EFAULT);
	}

	if (pscsi_pass->Direction == EXT_DEF_SCSI_PASSTHRU_DATA_IN) {
		DEBUG9(printk("%s(%ld): inst=%ld copying data.\n",
		    __func__, ha->host_no, ha->instance);)

		/* now copy up the READ data to user */
		if ((CMD_COMPL_STATUS(pscsi_cmd) == CS_DATA_UNDERRUN) &&
		    (CMD_RESID_LEN(pscsi_cmd))) {

			transfer_len = pext->ResponseLen -
			    CMD_RESID_LEN(pscsi_cmd);

			pext->ResponseLen = transfer_len;
		} else {
			transfer_len = pext->ResponseLen;
		}

		DEBUG9_10(printk(KERN_INFO
		    "%s(%ld): final transferlen=%d.\n",
		    __func__, ha->host_no, transfer_len);)

		usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)ha->ioctl_mem;
		ret = copy_to_user(usr_temp, kernel_tmp, transfer_len);
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR copy rsp buf\n",
			    __func__, ha->host_no, ha->instance);)
			return (-EFAULT);
		}
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

/*
 * qim_sc_fc_scsi_passthru
 *	Handles EXT_SC_SEND_FC_SCSI_PASSTHRU subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_sc_fc_scsi_passthru(struct qla_host_ioctl *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pfc_scsi_cmd, struct scsi_device *pfc_scsi_device,
    int mode)
{
	int			ret = 0;
	int			port_found, lun_found;
	fc_lun_t		temp_fclun;
	struct list_head	*fcpl;
	fc_port_t		*fcport;
	struct list_head	*fcll;
	fc_lun_t		*fclun;
	uint8_t			*usr_temp, *kernel_tmp;
	uint32_t		i;
	uint32_t		transfer_len;
	struct scsi_qla_host	*dr_ha = ha->dr_data;

	EXT_FC_SCSI_PASSTHRU	*pfc_scsi_pass;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)
	DEBUG9_10(
		if (!pfc_scsi_cmd || !pfc_scsi_device) {
			printk("%s(%ld): invalid pointer received. "
			    "pfc_scsi_cmd=%p, pfc_scsi_device=%p.\n",
			    __func__, ha->host_no, pfc_scsi_cmd,
			    pfc_scsi_device);
			return (ret);
		}
	)

	if (test_bit(FAILOVER_EVENT_NEEDED, &dr_ha->dpc_flags) ||
	    test_bit(FAILOVER_EVENT, &dr_ha->dpc_flags) ||
	    test_bit(FAILOVER_NEEDED, &dr_ha->dpc_flags)) {
		/* Stall intrusive passthru commands until failover complete */
		DEBUG9_10(printk("%s(%ld): inst=%ld failover in progress -- "
		    "returning busy.\n",
		    __func__, ha->host_no, ha->instance);)
		pext->Status = EXT_STATUS_BUSY;
		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pfc_scsi_pass,
	    sizeof(EXT_FC_SCSI_PASSTHRU))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_FC_SCSI_PASSTHRU));)
		return (ret);
	}

	if (pext->ResponseLen > ha->ioctl_mem_size) {
		if (qim_get_new_ioctl_dma_mem(ha, pext->ResponseLen) !=
		    QIM_SUCCESS) {

			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR cannot alloc "
			    "requested DMA buffer size %x.\n",
			    __func__, ha->host_no, ha->instance,
			    pext->ResponseLen);)

			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}
	}

	/* clear ioctl_mem to be used */
	memset(ha->ioctl_mem, 0, ha->ioctl_mem_size);

	/* Copy request buffer */
	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode);
	kernel_tmp = (uint8_t *)pfc_scsi_pass;
	ret = copy_from_user(kernel_tmp, usr_temp,
	    sizeof(EXT_FC_SCSI_PASSTHRU));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret);)

		return (-EFAULT);
	}

	if (pfc_scsi_pass->FCScsiAddr.DestType != EXT_DEF_DESTTYPE_WWPN) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR -wrong Dest type. \n",
		    __func__, ha->host_no, ha->instance);)
		return (ret);
	}

	DEBUG9(printk("%s(%ld): inst=%ld going to find fcport.\n",
	    __func__, ha->host_no, ha->instance);)

	fcport = NULL;
	fclun = NULL;
 	port_found = lun_found = 0;
 	list_for_each(fcpl, &dr_ha->fcports) {
 		fcport = list_entry(fcpl, fc_port_t, list);
 
		if (memcmp(fcport->port_name,
		    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN, 8) != 0) {
			continue;

		}
 		port_found++;
 
 		list_for_each(fcll, &fcport->fcluns) {
 			fclun = list_entry(fcll, fc_lun_t, list);

			if (fclun->lun == pfc_scsi_pass->FCScsiAddr.Lun) {
				/* Found the right LUN */
				lun_found++;
				break;
			}
		}
		break;
	}

	if (!port_found) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld FC AddrFormat - DID NOT "
		    "FIND Port matching WWPN.\n",
		    __func__, ha->host_no, ha->instance);)
		return (ret);
	}

	/* v5.21b9 - use a temporary fclun */
	if (!lun_found) {
		fclun = &temp_fclun;
		fclun->fcport = fcport;
		fclun->lun = pfc_scsi_pass->FCScsiAddr.Lun;
	}

	/* set target coordinates */
	pfc_scsi_cmd->device->id = 0xff; /* not used. just put something there. */
	pfc_scsi_cmd->device->lun = pfc_scsi_pass->FCScsiAddr.Lun;

	DEBUG9(printk("%s(%ld): inst=%ld got cmd for loopid=%04x L=%04x "
	    "WWPN=%02x%02x%02x%02x%02x%02x%02x%02x.\n",
	    __func__, ha->host_no, ha->instance, fclun->fcport->loop_id,
	    pfc_scsi_cmd->device->lun,
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[0],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[1],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[2],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[3],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[4],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[5],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[6],
	    pfc_scsi_pass->FCScsiAddr.DestAddr.WWPN[7]);)

	if (pfc_scsi_pass->CdbLength == 6) {
		pfc_scsi_cmd->cmd_len = 6;

	} else if (pfc_scsi_pass->CdbLength == 0x0A) {
		pfc_scsi_cmd->cmd_len = 0x0A;

	} else if (pfc_scsi_pass->CdbLength == 0x0C) {
		pfc_scsi_cmd->cmd_len = 0x0C;

	} else if (pfc_scsi_pass->CdbLength == 0x10) {
		pfc_scsi_cmd->cmd_len = 0x10;
	} else {
		printk(KERN_WARNING
		    "qim_ioctl: FC_SCSI_PASSTHRU Unknown Cdb Length=%x.\n",
		    pfc_scsi_pass->CdbLength);
		pext->Status = EXT_STATUS_INVALID_PARAM;

		return (ret);
	}

	memcpy(pfc_scsi_cmd->data_cmnd, pfc_scsi_pass->Cdb,
	    pfc_scsi_cmd->cmd_len);
	memcpy(pfc_scsi_cmd->cmnd, pfc_scsi_pass->Cdb,
	    pfc_scsi_cmd->cmd_len);

	DEBUG9(printk("%s Dump of cdb buffer:\n", __func__);)
	DEBUG9(qim_dump_buffer((uint8_t *)&pfc_scsi_cmd->data_cmnd[0], 16);)

	switch (pfc_scsi_pass->Direction) {
	case EXT_DEF_SCSI_PASSTHRU_DATA_OUT:
		pfc_scsi_cmd->sc_data_direction = DMA_TO_DEVICE;
		break;
	case EXT_DEF_SCSI_PASSTHRU_DATA_IN:
		pfc_scsi_cmd->sc_data_direction = DMA_FROM_DEVICE;
		break;
	default :	
		pfc_scsi_cmd->sc_data_direction = DMA_NONE;
		break;
	}

	/* send command to adapter */
	DEBUG9(printk("%s(%ld): inst=%ld queuing command.\n",
	    __func__, ha->host_no, ha->instance);)

	if ((ret = qim_ioctl_scsi_queuecommand(ha, pext, pfc_scsi_cmd,
	    pfc_scsi_device, fcport, fclun))) {
		if (ret > 0)
			/* this is not a system error. only return system
			 * errors which are negative.
			 */
			ret = 0;

		return (ret);
	}

	DEBUG9(printk("%s(%ld): inst=%ld waiting for completion.\n",
	    __func__, ha->host_no, ha->instance);)
	/* Wait for comletion */
	down(&ha->ioctl->cmpl_sem);

	DEBUG9(printk("%s(%ld): inst=%ld waking up.\n",
	    __func__, ha->host_no, ha->instance);)

	if (ha->ioctl->SCSIPT_InProgress == 1) {

		printk(KERN_WARNING
		    "qim: scsi%ld ERROR passthru command timeout.\n",
		    ha->host_no);

		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (ret);
	}

	if (CMD_COMPL_STATUS(pfc_scsi_cmd) == (int)IOCTL_INVALID_STATUS) {

		DEBUG9(printk("%s(%ld): inst=%ld ERROR. cmd not completed "
		    "or timed out.\n",
		    __func__, ha->host_no, ha->instance);)

		pext->Status = EXT_STATUS_ERR;
		return (ret);
	}

	switch (CMD_COMPL_STATUS(pfc_scsi_cmd)) {
	case CS_INCOMPLETE:
	case CS_ABORTED:
	case CS_PORT_UNAVAILABLE:
	case CS_PORT_LOGGED_OUT:
	case CS_PORT_CONFIG_CHG:
	case CS_PORT_BUSY:
		DEBUG9_10(printk("%s(%ld): inst=%ld cs err = %x.\n",
		    __func__, ha->host_no, ha->instance,
		    CMD_COMPL_STATUS(pfc_scsi_cmd));)
		pext->Status = EXT_STATUS_BUSY;

		return (ret);
	}

	if ((CMD_COMPL_STATUS(pfc_scsi_cmd) == CS_DATA_UNDERRUN) ||
	    (CMD_SCSI_STATUS(pfc_scsi_cmd) != 0))  {

		/* have done the post function */
		pext->Status       = EXT_STATUS_SCSI_STATUS;
		/* The SDMAPI is only concerned with the low-order byte */
		pext->DetailStatus = CMD_SCSI_STATUS(pfc_scsi_cmd) & 0xff;

		DEBUG9_10(printk("%s(%ld): inst=%ld data underrun or scsi err. "
		    "host status =0x%x, scsi status = 0x%x.\n",
		    __func__, ha->host_no, ha->instance,
		    CMD_COMPL_STATUS(pfc_scsi_cmd),
		    CMD_SCSI_STATUS(pfc_scsi_cmd));)

	} else if (CMD_COMPL_STATUS(pfc_scsi_cmd) != 0) {
		DEBUG9_10(printk("%s(%ld): inst=%ld cs err=%x.\n",
		    __func__, ha->host_no, ha->instance,
		    CMD_COMPL_STATUS(pfc_scsi_cmd));)
		pext->Status = EXT_STATUS_ERR;

		return (ret);
	}

	/* Process completed command */
	DEBUG9(printk("%s(%ld): inst=%ld done. host status=0x%x, "
	    "scsi status=0x%x.\n",
	    __func__, ha->host_no, ha->instance, CMD_COMPL_STATUS(pfc_scsi_cmd),
	    CMD_SCSI_STATUS(pfc_scsi_cmd));)

	/* copy up structure to make sense data available to user */
	pfc_scsi_pass->SenseLength = CMD_ACTUAL_SNSLEN(pfc_scsi_cmd);
	if (CMD_ACTUAL_SNSLEN(pfc_scsi_cmd)) {
		DEBUG9_10(printk("%s(%ld): inst=%ld sense[0]=%x sense[2]=%x.\n",
		    __func__, ha->host_no, ha->instance,
		    pfc_scsi_cmd->sense_buffer[0],
		    pfc_scsi_cmd->sense_buffer[2]);)

		for (i = 0; i < CMD_ACTUAL_SNSLEN(pfc_scsi_cmd); i++) {
			pfc_scsi_pass->SenseData[i] =
			pfc_scsi_cmd->sense_buffer[i];
		}

	}

	DEBUG9(printk("%s(%ld): inst=%ld copying sense buf to user.\n",
	    __func__, ha->host_no, ha->instance);)

	usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode);
	kernel_tmp = (uint8_t *)pfc_scsi_pass;
	ret = copy_to_user(usr_temp, kernel_tmp,
	    sizeof(EXT_FC_SCSI_PASSTHRU));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy sense "
		    "buffer.\n",
		    __func__, ha->host_no, ha->instance);)
		return (-EFAULT);
	}

	if (pfc_scsi_pass->Direction == EXT_DEF_SCSI_PASSTHRU_DATA_IN) {

		DEBUG9(printk("%s(%ld): inst=%ld copying data.\n",
		    __func__, ha->host_no, ha->instance);)

		/* now copy up the READ data to user */
		if ((CMD_COMPL_STATUS(pfc_scsi_cmd) == CS_DATA_UNDERRUN) &&
		    (CMD_RESID_LEN(pfc_scsi_cmd))) {

			transfer_len = pext->ResponseLen -
			    CMD_RESID_LEN(pfc_scsi_cmd);

			pext->ResponseLen = transfer_len;
		} else {
			transfer_len = pext->ResponseLen;
		}

		usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)ha->ioctl_mem;
		ret = copy_to_user(usr_temp, kernel_tmp, transfer_len);
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR copy rsp buf\n",
			    __func__, ha->host_no, ha->instance);)
			return (-EFAULT);
		}
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

#if 0
/* RLU: this need to be handled later */
/*
 * qim_sc_scsi3_passthru
 *	Handles EXT_SC_SCSI3_PASSTHRU subcommand.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = EXT_IOCTL structure pointer.
 *	mode = not used.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_sc_scsi3_passthru(struct qla_host_ioctl *ha, EXT_IOCTL *pext,
    struct scsi_cmnd *pscsi3_cmd, struct scsi_device *pscsi3_device, int mode)
{
#define MAX_SCSI3_CDB_LEN	16

	int			ret = 0;
	int			found;
	fc_lun_t		temp_fclun;
	fc_lun_t		*fclun = NULL;
	struct list_head	*fcpl;
	fc_port_t		*fcport;
	uint8_t			*usr_temp, *kernel_tmp;
	uint32_t		transfer_len;
	uint32_t		i;

	EXT_FC_SCSI_PASSTHRU	*pscsi3_pass;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)
	DEBUG9_10(
		if (!pscsi3_cmd || !pscsi3_device) {
			printk("%s(%ld): invalid pointer received. "
			    "pfc_scsi_cmd=%p, pfc_scsi_device=%p.\n",
			    __func__, ha->host_no, pscsi3_cmd,
			    pscsi3_device);
			return (ret);
		}
	)

	if (test_bit(FAILOVER_EVENT_NEEDED, &ha->dpc_flags) ||
	    test_bit(FAILOVER_EVENT, &ha->dpc_flags) ||
	    test_bit(FAILOVER_NEEDED, &ha->dpc_flags)) {
		/* Stall intrusive passthru commands until failover complete */
		DEBUG9_10(printk("%s(%ld): inst=%ld failover in progress -- "
		    "returning busy.\n",
		    __func__, ha->host_no, ha->instance);)
		pext->Status = EXT_STATUS_BUSY;
		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pscsi3_pass,
	    sizeof(EXT_FC_SCSI_PASSTHRU))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_FC_SCSI_PASSTHRU));)
		return (ret);
	}


	if (pext->ResponseLen > ha->ioctl_mem_size) {
		if (qim_get_new_ioctl_dma_mem(ha, pext->ResponseLen) !=
		    QIM_SUCCESS) {

			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR cannot "
			    "alloc requested DMA buffer size=%x.\n",
			    __func__, ha->host_no, ha->instance,
			    pext->ResponseLen);)

			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}
	}

	/* clear ioctl_mem to be used */
	memset(ha->ioctl_mem, 0, ha->ioctl_mem_size);

	/* Copy request buffer */
	usr_temp   = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode);
	kernel_tmp = (uint8_t *)pscsi3_pass;
	ret = copy_from_user(kernel_tmp, usr_temp,
	    sizeof(EXT_FC_SCSI_PASSTHRU));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret);)
		return (-EFAULT);
	}

	if (pscsi3_pass->FCScsiAddr.DestType != EXT_DEF_DESTTYPE_WWPN) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR - wrong Dest type.\n",
		    __func__, ha->host_no, ha->instance);)
		ret = EXT_STATUS_ERR;

		return (ret);
	}

	/*
	 * For this ioctl command we always assume all 16 bytes are
	 * initialized.
	 */
	if (pscsi3_pass->CdbLength != MAX_SCSI3_CDB_LEN) {
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR -wrong Cdb Len %d.\n",
		    __func__, ha->host_no, ha->instance,
		    pscsi3_pass->CdbLength);)
		return (ret);
	}

 	fcport = NULL;
 	found = 0;
 	list_for_each(fcpl, &ha->fcports) {
 		fcport = list_entry(fcpl, fc_port_t, list);

		if (memcmp(fcport->port_name,
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN, 8) == 0) {
			found++;
			break;
		}
	}
	if (!found) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;

		DEBUG9_10(printk("%s(%ld): inst=%ld DID NOT FIND Port for WWPN "
		    "%02x%02x%02x%02x%02x%02x%02x%02x.\n",
		    __func__, ha->host_no, ha->instance,
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[0],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[1],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[2],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[3],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[4],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[5],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[6],
		    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[7]);)

		return (ret);
	}

	/* Use a temporary fclun to send out the command. */
	fclun = &temp_fclun;
	fclun->fcport = fcport;
	fclun->lun = pscsi3_pass->FCScsiAddr.Lun;

	/* set target coordinates */
	pscsi3_cmd->device->id = 0xff;  /* not used. just put something there. */
	pscsi3_cmd->device->lun = pscsi3_pass->FCScsiAddr.Lun;

	DEBUG9(printk("%s(%ld): inst=%ld cmd for loopid=%04x L=%04x "
	    "WWPN=%02x%02x%02x%02x%02x%02x%02x%02x.\n",
	    __func__, ha->host_no, ha->instance,
	    fclun->fcport->loop_id, pscsi3_cmd->device->lun,
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[0],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[1],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[2],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[3],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[4],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[5],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[6],
	    pscsi3_pass->FCScsiAddr.DestAddr.WWPN[7]);)

	pscsi3_cmd->cmd_len = MAX_SCSI3_CDB_LEN;
	memcpy(pscsi3_cmd->data_cmnd, pscsi3_pass->Cdb, pscsi3_cmd->cmd_len);
	memcpy(pscsi3_cmd->cmnd, pscsi3_pass->Cdb, pscsi3_cmd->cmd_len);

	switch (pscsi3_pass->Direction) {
	case EXT_DEF_SCSI_PASSTHRU_DATA_OUT:
		pscsi3_cmd->sc_data_direction = DMA_TO_DEVICE;
		break;
	case EXT_DEF_SCSI_PASSTHRU_DATA_IN:
		pscsi3_cmd->sc_data_direction = DMA_FROM_DEVICE;
		break;
	default :	
		pscsi3_cmd->sc_data_direction = DMA_NONE;
		break;
	}

 	if (pscsi3_pass->Timeout)
		pscsi3_cmd->timeout_per_command = pscsi3_pass->Timeout * HZ;

	DEBUG9(printk("%s(%ld): inst=%ld cdb buffer dump:\n",
	    __func__, ha->host_no, ha->instance);)
	DEBUG9(qim_dump_buffer((uint8_t *)&pscsi3_cmd->data_cmnd[0], 16);)

	if ((ret = qim_ioctl_scsi_queuecommand(ha, pext, pscsi3_cmd,
	    pscsi3_device, fcport, fclun))) {
		if (ret > 0)
			/* this is not a system error. only return system
			 * errors which are negative.
			 */
			ret = 0;

		return (ret);
	}

	/* Wait for comletion */
	down(&ha->ioctl->cmpl_sem);

	if (ha->ioctl->SCSIPT_InProgress == 1) {

		printk(KERN_WARNING
		    "qim: inst=%ld scsi%ld ERROR PT command timeout.\n",
		    ha->host_no, ha->instance);

		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (ret);

	}
	if (CMD_COMPL_STATUS(pscsi3_cmd) == (int)IOCTL_INVALID_STATUS) {

		DEBUG9(printk("%s(%ld): inst=%ld ERROR - cmd not completed.\n",
		    __func__, ha->host_no, ha->instance);)

		pext->Status = EXT_STATUS_ERR;
		return (ret);
	}

	if ((CMD_SCSI_STATUS(pscsi3_cmd) & 0xff) != 0) {

		/* have done the post function */
		pext->Status       = EXT_STATUS_SCSI_STATUS;
		pext->DetailStatus = CMD_SCSI_STATUS(pscsi3_cmd) & 0xff;

		DEBUG9_10(printk(KERN_INFO "%s(%ld): inst=%ld scsi err. "
		    "host status =0x%x, scsi status = 0x%x.\n",
		    __func__, ha->host_no, ha->instance,
		    CMD_COMPL_STATUS(pscsi3_cmd), CMD_SCSI_STATUS(pscsi3_cmd));)

	} else {
		if (CMD_COMPL_STATUS(pscsi3_cmd) == CS_DATA_OVERRUN) {
			pext->Status = EXT_STATUS_DATA_OVERRUN;

			DEBUG9_10(printk(KERN_INFO
			    "%s(%ld): inst=%ld return overrun.\n",
			    __func__, ha->host_no, ha->instance);)

		} else if (CMD_COMPL_STATUS(pscsi3_cmd) == CS_DATA_UNDERRUN &&
		    (CMD_SCSI_STATUS(pscsi3_cmd) & SS_RESIDUAL_UNDER)) {
 			pext->Status = EXT_STATUS_DATA_UNDERRUN;

			DEBUG9_10(printk(KERN_INFO
			    "%s(%ld): inst=%ld return underrun.\n",
			    __func__, ha->host_no, ha->instance);)

		} else if (CMD_COMPL_STATUS(pscsi3_cmd) != 0 ||
		    CMD_SCSI_STATUS(pscsi3_cmd) != 0) {
			pext->Status = EXT_STATUS_ERR;

			DEBUG9_10(printk(KERN_INFO
			    "%s(%ld): inst=%ld, cs err=%x, scsi err=%x.\n",
			    __func__, ha->host_no, ha->instance,
			    CMD_COMPL_STATUS(pscsi3_cmd),
			    CMD_SCSI_STATUS(pscsi3_cmd));)

			return (ret);
		}
	}

	/* Process completed command */
	DEBUG9(printk("%s(%ld): inst=%ld done. host status=0x%x, "
	    "scsi status=0x%x.\n",
	    __func__, ha->host_no, ha->instance, CMD_COMPL_STATUS(pscsi3_cmd),
	    CMD_SCSI_STATUS(pscsi3_cmd));)

	/* copy up structure to make sense data available to user */
	pscsi3_pass->SenseLength = CMD_ACTUAL_SNSLEN(pscsi3_cmd);
	if (CMD_ACTUAL_SNSLEN(pscsi3_cmd)) {
		DEBUG9_10(printk("%s(%ld): inst=%ld sense[0]=%x sense[2]=%x.\n",
		    __func__, ha->host_no, ha->instance,
		    pscsi3_cmd->sense_buffer[0],
		    pscsi3_cmd->sense_buffer[2]);)

		for (i = 0; i < CMD_ACTUAL_SNSLEN(pscsi3_cmd); i++) {
			pscsi3_pass->SenseData[i] =
			    pscsi3_cmd->sense_buffer[i];
		}

		usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)pscsi3_pass;
		ret = copy_to_user(usr_temp, kernel_tmp,
		    sizeof(EXT_FC_SCSI_PASSTHRU));
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy sense "
			    "buffer.\n",
			    __func__, ha->host_no, ha->instance);)
			return (-EFAULT);
		}
	}

	if (pscsi3_pass->Direction == EXT_DEF_SCSI_PASSTHRU_DATA_IN) {

		DEBUG9(printk("%s(%ld): inst=%ld copying data.\n",
		    __func__, ha->host_no, ha->instance);)

		/* now copy up the READ data to user */
		if ((CMD_COMPL_STATUS(pscsi3_cmd) == CS_DATA_UNDERRUN) &&
		    (CMD_RESID_LEN(pscsi3_cmd))) {

			transfer_len = pext->ResponseLen -
			    CMD_RESID_LEN(pscsi3_cmd);

			pext->ResponseLen = transfer_len;
		} else {
			transfer_len = pext->ResponseLen;
		}

		DEBUG9_10(printk(KERN_INFO
		    "%s(%ld): final transferlen=%d.\n",
		    __func__, ha->host_no, transfer_len);)

		usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode);
		kernel_tmp = (uint8_t *)ha->ioctl_mem;
		ret = copy_to_user(usr_temp, kernel_tmp, transfer_len);
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR copy rsp buf\n",
			    __func__, ha->host_no, ha->instance);)
			return (-EFAULT);
		}
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}
#endif

/*
 * qim_send_els_rnid
 *	IOCTL to send extended link service RNID command to a target.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_send_els_rnid(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
#if 0
	EXT_RNID_REQ	*tmp_rnid;
	uint16_t	mb[MAILBOX_REGISTER_COUNT];
	uint32_t	copy_len;
	int		found;
	uint16_t	next_loop_id;
	fc_port_t	*fcport;
#endif

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

#if 0
/* RLU: this need to be handled later */
	if (ha->ioctl_mem_size < SEND_RNID_RSP_SIZE) {
		if (qim_get_new_ioctl_dma_mem(ha,
		    SEND_RNID_RSP_SIZE) != QIM_SUCCESS) {

			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR cannot alloc "
			    "DMA buffer. size=%x.\n",
			    __func__, ha->host_no, ha->instance,
			    SEND_RNID_RSP_SIZE);)

			pext->Status = EXT_STATUS_NO_MEMORY;
			return (ret);
		}
	}

	if (pext->RequestLen != sizeof(EXT_RNID_REQ)) {
		/* parameter error */
		DEBUG9_10(printk("%s(%ld): inst=%ld invalid req length %d.\n",
		    __func__, ha->host_no, ha->instance, pext->RequestLen);)
		pext->Status = EXT_STATUS_INVALID_PARAM;
		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&tmp_rnid,
	    sizeof(EXT_RNID_REQ))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_RNID_REQ));)
		return (ret);
	}

	ret = copy_from_user(tmp_rnid, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n",
		    __func__, ha->host_no, ha->instance, ret);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	/* Find loop ID of the device */
	found = 0;
	fcport = NULL;
	switch (tmp_rnid->Addr.Type) {
	case EXT_DEF_TYPE_WWNN:
		DEBUG9(printk("%s(%ld): inst=%ld got node name.\n",
		    __func__, ha->host_no, ha->instance);)

		list_for_each_entry(fcport, &ha->fcports, list) {
			if (fcport->port_type != FCT_INITIATOR ||
			    fcport->port_type != FCT_TARGET)
				continue;

			if (memcmp(tmp_rnid->Addr.FcAddr.WWNN,
			    fcport->node_name, EXT_DEF_WWN_NAME_SIZE))
				continue;

			if (fcport->port_type == FCT_TARGET) {
				if (atomic_read(&fcport->state) != FCS_ONLINE)
					continue;
			} else { /* FCT_INITIATOR */
				if (!fcport->d_id.b24)
					continue;
			}

			found++;
		}
		break;

	case EXT_DEF_TYPE_WWPN:
		DEBUG9(printk("%s(%ld): inst=%ld got port name.\n",
		    __func__, ha->host_no, ha->instance);)

		list_for_each_entry(fcport, &ha->fcports, list) {
			if (fcport->port_type != FCT_INITIATOR ||
			    fcport->port_type != FCT_TARGET)
				continue;

			if (memcmp(tmp_rnid->Addr.FcAddr.WWPN,
			    fcport->port_name, EXT_DEF_WWN_NAME_SIZE))
				continue;

			if (fcport->port_type == FCT_TARGET) {
				if (atomic_read(&fcport->state) != FCS_ONLINE)
					continue;
			} else { /* FCT_INITIATOR */
				if (!fcport->d_id.b24)
					continue;
			}

			found++;
		}
		break;

	case EXT_DEF_TYPE_PORTID:
		DEBUG9(printk("%s(%ld): inst=%ld got port ID.\n",
		    __func__, ha->host_no, ha->instance);)

		list_for_each_entry(fcport, &ha->fcports, list) {
			if (fcport->port_type != FCT_INITIATOR ||
			    fcport->port_type != FCT_TARGET)
				continue;

			/* PORTID bytes entered must already be big endian */
			if (memcmp(&tmp_rnid->Addr.FcAddr.Id[1],
			    &fcport->d_id, EXT_DEF_PORTID_SIZE_ACTUAL))
				continue;

			if (fcport->port_type == FCT_TARGET) {
				if (atomic_read(&fcport->state) != FCS_ONLINE)
					continue;
			}

			found++;
		}
		break;
	default:
		/* parameter error */
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk("%s(%ld): inst=%ld invalid addressing type.\n",
		    __func__, ha->host_no, ha->instance);)
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	if (!found || (fcport->port_type == FCT_TARGET &&
	    fcport->loop_id > ha->last_loop_id)) {
		/*
		 * No matching device or the target device is not configured;
		 * just return error.
		 */
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* check on loop down */
	if (atomic_read(&ha->loop_state) != LOOP_READY || 
	    test_bit(CFG_ACTIVE, &ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags) || ha->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		    __func__, ha->host_no, ha->instance);)

		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* If this is for a host device, check if we need to perform login */
	if (fcport->port_type == FCT_INITIATOR &&
	    fcport->loop_id >= ha->last_loop_id) {
		next_loop_id = 0;
		ret = qim_fabric_login(ha, fcport, &next_loop_id);
		if (ret != QIM_SUCCESS) {
			/* login failed. */
			pext->Status = EXT_STATUS_DEV_NOT_FOUND;

			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR login to "
			    "host port failed. loop_id=%02x pid=%02x%02x%02x "
			    "ret=%d.\n",
			    __func__, ha->host_no, ha->instance,
			    fcport->loop_id, fcport->d_id.b.domain,
			    fcport->d_id.b.area, fcport->d_id.b.al_pa, ret);)

			qim_free_ioctl_scrap_mem(ha);
			return (ret);
		}
	}

	/* Send command */
	DEBUG9(printk("%s(%ld): inst=%ld sending rnid cmd.\n",
	    __func__, ha->host_no, ha->instance);)

	ret = qim_send_rnid_mbx(ha, fcport->loop_id,
	    (uint8_t)tmp_rnid->DataFormat, ha->ioctl_mem_phys,
	    SEND_RNID_RSP_SIZE, &mb[0]);

	if (ret != QIM_SUCCESS) {
		/* error */
		pext->Status = EXT_STATUS_ERR;

                DEBUG9_10(printk("%s(%ld): inst=%ld FAILED. rval = %x.\n",
                    __func__, ha->host_no, ha->instance, mb[0]);)
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	DEBUG9(printk("%s(%ld): inst=%ld rnid cmd sent ok.\n",
	    __func__, ha->host_no, ha->instance);)

	/* Copy the response */
	copy_len = (pext->ResponseLen > SEND_RNID_RSP_SIZE) ?
	    SEND_RNID_RSP_SIZE : pext->ResponseLen;

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ha->ioctl_mem, copy_len);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy rsp buf\n",
		    __func__, ha->host_no, ha->instance);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	if (SEND_RNID_RSP_SIZE > pext->ResponseLen) {
		pext->Status = EXT_STATUS_DATA_OVERRUN;
		DEBUG9(printk("%s(%ld): inst=%ld data overrun. "
		    "exiting normally.\n",
		    __func__, ha->host_no, ha->instance);)
	} else {
		pext->Status = EXT_STATUS_OK;
		DEBUG9(printk("%s(%ld): inst=%ld exiting normally.\n",
		    __func__, ha->host_no, ha->instance);)
	}
	pext->ResponseLen = copy_len;

	qim_free_ioctl_scrap_mem(ha);
#endif

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)
	return (ret);
}

/*
 * qim_get_rnid_params
 *	IOCTL to get RNID parameters of the adapter.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_get_rnid_params(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	int		tmp_rval = 0;
	uint32_t	copy_len;
	uint16_t	mb[MAILBOX_REGISTER_COUNT];
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	/* check on loop down */
	if (atomic_read(&dr_ha->loop_state) != LOOP_READY || 
	    test_bit(CFG_ACTIVE, &dr_ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &dr_ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &dr_ha->dpc_flags) ||
	    dr_ha->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		    __func__, ha->host_no, ha->instance);)

		return (ret);
	}

	/* Send command */
	tmp_rval = qim_get_rnid_params_mbx(dr_ha, ha->ioctl_mem_phys,
	    sizeof(EXT_RNID_DATA), &mb[0]);

	if (tmp_rval != QIM_SUCCESS) {
		/* error */
		pext->Status = EXT_STATUS_ERR;

		DEBUG9_10(printk("%s(%ld): inst=%ld cmd FAILED=%x.\n",
		    __func__, ha->host_no, ha->instance, mb[0]);)
		return (ret);
	}

	/* Copy the response */
	copy_len = (pext->ResponseLen > sizeof(EXT_RNID_DATA)) ?
	    (uint32_t)sizeof(EXT_RNID_DATA) : pext->ResponseLen;
	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ha->ioctl_mem, copy_len);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buf\n",
		    __func__, ha->host_no, ha->instance);)
		return (-EFAULT);
	}

	pext->ResponseLen = copy_len;
	if (copy_len < sizeof(EXT_RNID_DATA)) {
		pext->Status = EXT_STATUS_DATA_OVERRUN;
		DEBUG9_10(printk("%s(%ld): inst=%ld data overrun. "
		    "exiting normally.\n",
		    __func__, ha->host_no, ha->instance);)
	} else if (pext->ResponseLen > sizeof(EXT_RNID_DATA)) {
		pext->Status = EXT_STATUS_DATA_UNDERRUN;
		DEBUG9_10(printk("%s(%ld): inst=%ld data underrun. "
		    "exiting normally.\n",
		    __func__, ha->host_no, ha->instance);)
	} else {
		pext->Status = EXT_STATUS_OK;
		DEBUG9(printk("%s(%ld): inst=%ld exiting normally.\n",
		    __func__, ha->host_no, ha->instance);)
	}

	return (ret);
}

#if 0
/* RLU: this need to be handled later */
/*
 *qim_get_led_state
 *	IOCTL to get QLA2XXX HBA LED state
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_get_led_state(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int			ret = 0;
	EXT_BEACON_CONTROL	tmp_led_state;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (pext->ResponseLen < sizeof(EXT_BEACON_CONTROL)) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk("%s: ERROR ResponseLen too small.\n",
		    __func__);)

		return (ret);
	}

	if (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) {
		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		    __func__, ha->host_no, ha->instance);)
		return (ret);
	}

	/* Return current state */
	if (ha->beacon_blink_led) {
		tmp_led_state.State = EXT_DEF_GRN_BLINK_ON;
	} else {
		tmp_led_state.State = EXT_DEF_GRN_BLINK_OFF;
	}

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    &tmp_led_state, sizeof(EXT_BEACON_CONTROL));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance);)
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);

}
#endif

/*
 * qim_set_host_data
 *	IOCTL command to set host/adapter related data.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_set_host_data(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int	ret = 0;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	/* switch on command subcode */
	switch (pext->SubCode) {
	case EXT_SC_SET_RNID:
		ret = qim_set_rnid_params(ha, pext, mode);
		break;
#if 0
/* RLU: this need to be handled later */
	case EXT_SC_SET_BEACON_STATE:
		if (!IS_QLA2100(ha) && !IS_QLA2200(ha)) {
			ret = qim_set_led_state(ha, pext, mode);
			break;
		}
		/*FALLTHROUGH*/
#endif
	default:
		/* function not supported. */
		pext->Status = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

/*
 * qim_set_rnid_params
 *	IOCTL to set RNID parameters of the adapter.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_set_rnid_params(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	EXT_SET_RNID_REQ	*tmp_set;
	EXT_RNID_DATA	*tmp_buf;
	int		ret = 0;
	int		tmp_rval = 0;
	uint16_t	mb[MAILBOX_REGISTER_COUNT];
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	/* check on loop down */
	if (atomic_read(&dr_ha->loop_state) != LOOP_READY || 
	    test_bit(CFG_ACTIVE, &dr_ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &dr_ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &dr_ha->dpc_flags) ||
	    dr_ha->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld loop not ready.\n",
		    __func__, ha->host_no, ha->instance);)

		return (ret);
	}

	if (pext->RequestLen != sizeof(EXT_SET_RNID_REQ)) {
		/* parameter error */
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk("%s(%ld): inst=%ld invalid request length.\n",
		    __func__, ha->host_no, ha->instance);)
		return(ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&tmp_set,
	    sizeof(EXT_SET_RNID_REQ))) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n",
		    __func__, ha->host_no, ha->instance,
		    (ulong)sizeof(EXT_SET_RNID_REQ));)
		return (ret);
	}

	ret = copy_from_user(tmp_set, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n", 
		    __func__, ha->host_no, ha->instance, ret);)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	tmp_rval = qim_get_rnid_params_mbx(dr_ha, ha->ioctl_mem_phys,
	    sizeof(EXT_RNID_DATA), &mb[0]);
	if (tmp_rval != QIM_SUCCESS) {
		/* error */
		pext->Status = EXT_STATUS_ERR;

                DEBUG9_10(printk("%s(%ld): inst=%ld read cmd FAILED=%x.\n",
                    __func__, ha->host_no, ha->instance, mb[0]);)
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	tmp_buf = (EXT_RNID_DATA *)ha->ioctl_mem;

	/* Now set the params. */
	memcpy(tmp_buf->IPVersion, tmp_set->IPVersion, 2);
	memcpy(tmp_buf->UDPPortNumber, tmp_set->UDPPortNumber, 2);
	memcpy(tmp_buf->IPAddress, tmp_set->IPAddress, 16);

	tmp_rval = qim_set_rnid_params_mbx(dr_ha, ha->ioctl_mem_phys,
	    sizeof(EXT_RNID_DATA), &mb[0]);

	if (tmp_rval != QIM_SUCCESS) {
		/* error */
		pext->Status = EXT_STATUS_ERR;

		DEBUG9_10(printk("%s(%ld): inst=%ld set cmd FAILED=%x.\n",
		    __func__, ha->host_no, ha->instance, mb[0]);)
	} else {
		pext->Status = EXT_STATUS_OK;
		DEBUG9(printk("%s(%ld): inst=%ld exiting normally.\n",
		    __func__, ha->host_no, ha->instance);)
	}

	qim_free_ioctl_scrap_mem(ha);
	return (ret);
}

#if 0
/* RLU: this need to be handled later */
/*
 *qim_set_led_state
 *	IOCTL to set QLA2XXX HBA LED state
 *
 * Input:
 *	ha = adapter state pointer.
 *	pext = User space CT arguments pointer.
 *	mode = flags.
 *
 * Returns:
 *	0 = success
 *	others = errno value
 *
 * Context:
 *	Kernel context.
 */
static int
qim_set_led_state(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int			ret = 0;
	uint32_t		tmp_ext_stat = 0;
	uint32_t		tmp_ext_dstat = 0;
	EXT_BEACON_CONTROL	tmp_led_state;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (pext->RequestLen < sizeof(EXT_BEACON_CONTROL)) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk("%s: ERROR RequestLen too small.\n",
		    __func__);)
		return (ret);
	}

	if (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) {
		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld abort isp active.\n",
		     __func__, ha->host_no, ha->instance);)
		return (ret);
	}

	ret = copy_from_user(&tmp_led_state, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), sizeof(EXT_BEACON_CONTROL));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy req buf=%d.\n",
		    __func__, ha->host_no, ha->instance, ret);)
		return (-EFAULT);
	}

	if (IS_QLA23XX(ha)) {
		ret = qim_set_led_23xx(ha, &tmp_led_state, &tmp_ext_stat,
		    &tmp_ext_dstat);
	} else if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		ret = qim_set_led_24xx(ha, &tmp_led_state, &tmp_ext_stat,
		    &tmp_ext_dstat);
	} else {
		/* not supported */
		tmp_ext_stat = EXT_STATUS_UNSUPPORTED_SUBCODE;
	}

	pext->Status       = tmp_ext_stat;
	pext->DetailStatus = tmp_ext_dstat;

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

static int
qim_set_led_23xx(struct qla_host_ioctl *ha, EXT_BEACON_CONTROL *ptmp_led_state,
    uint32_t *pext_stat, uint32_t *pext_dstat)
{
	int			ret = 0;
	device_reg_t __iomem	*reg = ha->iobase;
	uint16_t		gpio_enable, gpio_data;
	unsigned long		cpu_flags = 0;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	if (ptmp_led_state->State != EXT_DEF_GRN_BLINK_ON &&
	    ptmp_led_state->State != EXT_DEF_GRN_BLINK_OFF) {
		*pext_stat = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld Unknown Led State set "
		    "operation recieved %x.\n",
		    __func__, ha->host_no, ha->instance,
		    ptmp_led_state->State);)
		return (ret);
	}

	if (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) {
		*pext_stat = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld abort isp active.\n",
		     __func__, ha->host_no, ha->instance);)
		return (ret);
	}

	switch (ptmp_led_state->State) {
	case EXT_DEF_GRN_BLINK_ON:

		DEBUG9(printk("%s(%ld): inst=%ld start blinking led \n",
		    __func__, ha->host_no, ha->instance);)

		DEBUG9(printk("%s(%ld): inst=%ld orig firmware options "
		    "fw_options1=0x%x fw_options2=0x%x fw_options3=0x%x.\n",
		     __func__, ha->host_no, ha->instance, ha->fw_options[1],
		     ha->fw_options[2], ha->fw_options[3]);)

		ha->fw_options[1] &= ~FO1_SET_EMPHASIS_SWING;
		ha->fw_options[1] |= FO1_DISABLE_GPIO6_7;

		if (qim_set_fw_options(ha, ha->fw_options) != QIM_SUCCESS) {
			*pext_stat = EXT_STATUS_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld set"
			    "firmware  options failed.\n",
			    __func__, ha->host_no, ha->instance);)
			break;
		}

		if (ha->pio_address)
			reg = (device_reg_t *)ha->pio_address;

		/* Turn off LEDs */
		spin_lock_irqsave(&ha->hardware_lock, cpu_flags);
		if (ha->pio_address) {
			gpio_enable = RD_REG_WORD_PIO(&reg->gpioe);
			gpio_data   = RD_REG_WORD_PIO(&reg->gpiod);
		} else {
			gpio_enable = RD_REG_WORD(&reg->gpioe);
			gpio_data   = RD_REG_WORD(&reg->gpiod);
		}
		gpio_enable |= GPIO_LED_MASK;

		/* Set the modified gpio_enable values */
		if (ha->pio_address)
			WRT_REG_WORD_PIO(&reg->gpioe, gpio_enable);
		else {
			WRT_REG_WORD(&reg->gpioe, gpio_enable);
			RD_REG_WORD(&reg->gpioe);
		}

		/* Clear out previously set LED colour */
		gpio_data &= ~GPIO_LED_MASK;
		if (ha->pio_address)
			WRT_REG_WORD_PIO(&reg->gpiod, gpio_data);
		else {
			WRT_REG_WORD(&reg->gpiod, gpio_data);
			RD_REG_WORD(&reg->gpiod);
		}
		spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);

		/* Let the per HBA timer kick off the blinking process based on
		 * the following flags. No need to do anything else now.
		 */
		ha->beacon_blink_led = 1;
		ha->beacon_color_state = 0;

		/* end of if(ptmp_led_state.State == EXT_DEF_GRN_BLINK_ON) ) */

		*pext_stat  = EXT_STATUS_OK;
		*pext_dstat = EXT_STATUS_OK;
		break;

	case EXT_DEF_GRN_BLINK_OFF:
		DEBUG9(printk("%s(%ld): inst=%ld stop blinking led \n",
		    __func__, ha->host_no, ha->instance);)

		ha->beacon_blink_led = 0;
		/* Set the on flag so when it gets flipped it will be off */
		if (IS_QLA2322(ha)) {
			ha->beacon_color_state = QLA_LED_RGA_ON;
		} else {
			ha->beacon_color_state = QLA_LED_GRN_ON;
		}
		qla23xx_blink_led(ha);	/* This turns green LED off */

		DEBUG9(printk("%s(%ld): inst=%ld orig firmware"
		    " options fw_options1=0x%x fw_options2=0x%x "
		    "fw_options3=0x%x.\n",
		    __func__, ha->host_no, ha->instance, ha->fw_options[1],
		    ha->fw_options[2], ha->fw_options[3]);)

		ha->fw_options[1] &= ~FO1_SET_EMPHASIS_SWING;
		ha->fw_options[1] &= ~FO1_DISABLE_GPIO6_7;

		if (qim_set_fw_options(ha, ha->fw_options) != QIM_SUCCESS) {
			*pext_stat = EXT_STATUS_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld set"
			    "firmware  options failed.\n",
			    __func__, ha->host_no, ha->instance);)
			break;
		}

		/* end of if(ptmp_led_state.State == EXT_DEF_GRN_BLINK_OFF) */

		*pext_stat  = EXT_STATUS_OK;
		*pext_dstat = EXT_STATUS_OK;
		break;
	default:
		*pext_stat = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (ret);
}

static int
qim_set_led_24xx(struct qla_host_ioctl *ha,
    EXT_BEACON_CONTROL *ptmp_led_state, uint32_t *pext_stat,
    uint32_t *pext_dstat)
{
	int			rval = 0;
	struct device_reg_24xx __iomem *reg24 = 
	    (struct device_reg_24xx __iomem *)ha->iobase;
	uint32_t		gpio_data;
	uint32_t		led_state;
	unsigned long		cpu_flags = 0;


	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance);)

	led_state = ptmp_led_state->State;
	if (led_state != EXT_DEF_GRN_BLINK_ON &&
	    led_state != EXT_DEF_GRN_BLINK_OFF) {
		*pext_stat = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld Unknown Led State set "
		    "operation recieved %x.\n",
		    __func__, ha->host_no, ha->instance,
		    ptmp_led_state->State);)
		return (rval);
	}

	if (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) {
		*pext_stat = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s(%ld): inst=%ld abort isp active.\n",
		     __func__, ha->host_no, ha->instance);)
		return (rval);
	}

	DEBUG9_10(printk("%s(%ld): inst=%ld orig firmware options "
	    "fw_options1=0x%x fw_options2=0x%x fw_options3=0x%x.\n",
	     __func__, ha->host_no, ha->instance, ha->fw_options[1],
	     ha->fw_options[2], ha->fw_options[3]);)

	switch (led_state) {
	case EXT_DEF_GRN_BLINK_ON:

		DEBUG9(printk("%s(%ld): inst=%ld start blinking led \n",
		    __func__, ha->host_no, ha->instance);)

		if (!ha->beacon_blink_led) {
			/* Enable firmware for update */
			ha->fw_options[1] |= ADD_FO1_DISABLE_GPIO_LED_CTRL;

			if (qim_set_fw_options(ha, ha->fw_options) !=
			    QIM_SUCCESS) {
				*pext_stat = EXT_STATUS_MAILBOX;
				*pext_dstat = ha->fw_options[0];
				DEBUG9_10(printk("%s(%ld): inst=%ld set"
				    "firmware options failed.\n",
				    __func__, ha->host_no, ha->instance);)
				break;
			}

			if (qim_get_fw_options(ha, ha->fw_options) !=
			    QIM_SUCCESS) {
				*pext_stat = EXT_STATUS_MAILBOX;
				*pext_dstat = ha->fw_options[0];
				DEBUG9_10(printk("%s(%ld): inst=%ld get"
				    "firmware options failed.\n",
				    __func__, ha->host_no, ha->instance);)
				break;
			}

			spin_lock_irqsave(&ha->hardware_lock, cpu_flags);
			gpio_data = RD_REG_DWORD(&reg24->gpiod);

			/* Enable the gpio_data reg for update */
			gpio_data |= GPDX_LED_UPDATE_MASK;
			WRT_REG_DWORD(&reg24->gpiod, gpio_data);
			RD_REG_DWORD(&reg24->gpiod);

			spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);
		}

		ha->beacon_color_state = 0; /* so all colors blink together */

		/* Let the per HBA timer kick off the blinking process*/
		ha->beacon_blink_led = 1;

		*pext_stat  = EXT_STATUS_OK;
		*pext_dstat = EXT_STATUS_OK;

		DEBUG9(printk("%s(%ld): inst=%ld LED setup to blink.\n",
		    __func__, ha->host_no, ha->instance);)

		break;

	case EXT_DEF_GRN_BLINK_OFF:
		DEBUG9(printk("%s(%ld): inst=%ld stop blinking led \n",
		    __func__, ha->host_no, ha->instance);)

		ha->beacon_blink_led = 0;
		ha->beacon_color_state = QLA_LED_ALL_ON;
		qla24xx_blink_led(ha); /* will flip to all off */

		/* give control back to firmware */
		spin_lock_irqsave(&ha->hardware_lock, cpu_flags);
		gpio_data = RD_REG_DWORD(&reg24->gpiod);

		/* Disable the gpio_data reg for update */
		gpio_data &= ~GPDX_LED_UPDATE_MASK;
		WRT_REG_DWORD(&reg24->gpiod, gpio_data);
		RD_REG_DWORD(&reg24->gpiod);
		spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);

		ha->fw_options[1] &= ~ADD_FO1_DISABLE_GPIO_LED_CTRL;

		if (qim_set_fw_options(ha, ha->fw_options) != QIM_SUCCESS) {
			*pext_stat = EXT_STATUS_MAILBOX;
			*pext_dstat = ha->fw_options[0];
			DEBUG9_10(printk("%s(%ld): inst=%ld set"
			    "firmware options failed.\n",
			    __func__, ha->host_no, ha->instance);)
			break;
		}

		if (qim_get_fw_options(ha, ha->fw_options) !=
		    QIM_SUCCESS) {
			*pext_stat = EXT_STATUS_MAILBOX;
			*pext_dstat = ha->fw_options[0];
			DEBUG9_10(printk("%s(%ld): inst=%ld get"
			    "firmware options failed.\n",
			    __func__, ha->host_no, ha->instance);)
			break;
		}

		*pext_stat  = EXT_STATUS_OK;
		*pext_dstat = EXT_STATUS_OK;

		DEBUG9(printk("%s(%ld): inst=%ld all LED blinking stopped.\n",
		    __func__, ha->host_no, ha->instance);)

		break;

	default:
		DEBUG9_10(printk("%s(%ld): inst=%ld invalid state received=%x.\n",
		    __func__, ha->host_no, ha->instance, led_state);)

		*pext_stat = EXT_STATUS_UNSUPPORTED_SUBCODE;
		break;
	}

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance);)

	return (rval);
}
#endif


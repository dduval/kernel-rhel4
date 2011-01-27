/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2007 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */

/******************************************************************************
 *             Please see release.txt for revision history.                   *
 *                                                                            *
 ******************************************************************************
 * Function Table of Contents:
 *      qla4xxx_alloc_dma_memory
 *      qla4xxx_free_dma_memory
 *      qla4xxx_free_lun
 *      qla4xxx_free_ddb
 *      qla4xxx_free_ddb_list
 *      qla4xxx_init_rings
 *      qla4xxx_validate_mac_address
 *	qla4xxx_init_local_data
 *	qla4xxx_initialize_fw_cb
 *      qla4xxx_init_firmware
 *      qla4xxx_send_internal_scsi_passthru
 *      qla4xxx_send_inquiry_cmd
 *      qla4xxx_send_report_luns_cmd
 *	qla4xxx_is_discovered_target
 *      qla4xxx_update_ddb_entry
 *      qla4xxx_alloc_lun
 *      qla4xxx_discover_target_luns
 *      qla4xxx_map_targets_to_ddbs
 *      qla4xxx_alloc_ddb
 *      qla4xxx_build_ddb_list
 *      qla4xxx_initialize_ddb_list
 *      qla4xxx_reinitialize_ddb_list
 *      qla4xxx_relogin_device
 *	qla4xxx_start_firmware
 *      qla4xxx_initialize_adapter
 *      qla4xxx_find_propname
 *      qla4xxx_get_prop_12chars
 *	qla4xxx_add_device_dynamically
 *	qla4xxx_process_ddb_changed
 *	qla4xxx_flush_all_srbs
 ****************************************************************************/

#include "ql4_def.h"

#include <linux/delay.h>

/*
 *  External Function Prototypes.
 */
extern int ql4xkeepalive;
extern int ql4xdiscoverywait;
extern char *ql4xdevconf;

/*
 * Local routines
 */
static fc_port_t *
qla4xxx_find_or_alloc_fcport(scsi_qla_host_t *ha, ddb_entry_t *ddb_entry);
static void qla4xxx_config_os(scsi_qla_host_t *ha);
static uint16_t
qla4xxx_fcport_bind(scsi_qla_host_t *ha, fc_port_t *fcport);
os_lun_t *
qla4xxx_fclun_bind(scsi_qla_host_t *ha, fc_port_t *fcport, fc_lun_t *fclun);
os_tgt_t *
qla4xxx_tgt_alloc(scsi_qla_host_t *ha, uint16_t tgt);
void
qla4xxx_tgt_free(scsi_qla_host_t *ha, uint16_t tgt);
os_lun_t *
qla4xxx_lun_alloc(scsi_qla_host_t *ha, uint16_t tgt, uint16_t lun);
static void
qla4xxx_lun_free(scsi_qla_host_t *ha, uint16_t tgt, uint16_t lun);
fc_lun_t *
qla4xxx_add_fclun(fc_port_t *fcport, uint16_t lun);
static ddb_entry_t *
qla4xxx_get_ddb_entry(scsi_qla_host_t *ha, uint32_t fw_ddb_index);


static void ql4xxx_set_mac_number(scsi_qla_host_t * ha)
{
    uint32_t                     value;
    uint8_t                      func_number;
    unsigned long	flags;

    /* Get the function number */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	value = RD_REG_DWORD(&ha->reg->ctrl_status);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

    	func_number = (uint8_t)((value >> 4) & 0x30);
	switch (value & ISP_CONTROL_FN_MASK) {
        case ISP_CONTROL_FN0_SCSI:
            ha->mac_index = 1;
            break;
        case ISP_CONTROL_FN1_SCSI:
            ha->mac_index = 3;
            break;
        default:
            DEBUG2(printk("scsi%d: %s: Invalid function number, ispControlStatus = 0x%x\n",
			  ha->host_no, __func__,value));
            break;
    }
	DEBUG2(printk("scsi%d: %s: mac_index %d.\n",  ha->host_no,__func__,ha->mac_index)) ;
}

/**
 * qla4xxx_alloc_fcport() - Allocate a generic fcport.
 * @ha: HA context
 * @flags: allocation flags
 *
 * Returns a pointer to the allocated fcport, or NULL, if none available.
 */
static fc_port_t *
qla4xxx_alloc_fcport(scsi_qla_host_t *ha, int flags)
{
	fc_port_t *fcport;

	fcport = kmalloc(sizeof(fc_port_t), flags);
	if (fcport == NULL)
		return(fcport);

	/* Setup fcport template structure. */
	memset(fcport, 0, sizeof (fc_port_t));
	fcport->ha = ha;
	fcport->port_type = FCT_UNKNOWN;
	atomic_set(&fcport->state, FCS_DEVICE_DEAD);
	fcport->flags = FCF_RLC_SUPPORT;
	INIT_LIST_HEAD(&fcport->fcluns);

	return(fcport);
}

/*
* qla4xxx_init_tgt_map
*      Initializes target map.
*
* Input:
*      ha = adapter block pointer.
*
* Output:
*      TGT_Q initialized
*/
static void
qla4xxx_init_tgt_map(scsi_qla_host_t *ha)
{
	uint32_t t;

	ENTER(__func__);

	for (t = 0; t < MAX_TARGETS; t++)
		TGT_Q(ha, t) = (os_tgt_t *) NULL;

	LEAVE(__func__);
}




/*
 * qla4xxx_update_fcport
 *	Updates device on list.
 *
 * Input:
 *	ha = adapter block pointer.
 *	fcport = port structure pointer.
 *
 * Return:
 *	0  - Success
 *  BIT_0 - error
 *
 * Context:
 *	Kernel context.
 */
static void
qla4xxx_update_fcport(scsi_qla_host_t *ha, fc_port_t *fcport)
{
#if 0
	uint16_t        index;
	unsigned long flags;
	srb_t *sp;
#endif

	if (fcport == NULL)
		return;

	ENTER(__func__);
	fcport->ha = ha;

	/* XXX need to get this info from option field of DDB entry */
	fcport->port_type = FCT_TARGET;
	fcport->iscsi_name = fcport->ddbptr->iscsi_name;

	/*
	 * Check for outstanding cmd on tape Bypass LUN discovery if active
	 * command on tape.
	 */
#if 0
	if (fcport->flags & FCF_TAPE_PRESENT) {
		spin_lock_irqsave(&ha->hardware_lock, flags);
		for (index = 1; index < MAX_OUTSTANDING_COMMANDS; index++) {
			if ((sp = ha->outstanding_cmds[index]) != 0) {
				if (sp->fclun->fcport == fcport) {
					atomic_set(&fcport->state, FCS_ONLINE);
					spin_unlock_irqrestore(
							      &ha->hardware_lock, flags);
					return;
				}
			}
		}
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
	}
#endif

	/* Always set online */
	atomic_set(&fcport->state, FCS_ONLINE);
	LEAVE(__func__);
}



/*
 * qla4xxx_add_fclun
 *	Adds LUN to database
 *
 * Input:
 *	fcport:		FC port structure pointer.
 *	lun:		LUN number.
 *
 * Context:
 *	Kernel context.
 */
fc_lun_t *
qla4xxx_add_fclun(fc_port_t *fcport, uint16_t lun)
{
	int             found;
	fc_lun_t        *fclun;

	if (fcport == NULL) {
		DEBUG2(printk("scsi: %s: Unable to add lun to NULL port\n", __func__));
		return(NULL);
	}

	/* Allocate LUN if not already allocated. */
	found = 0;
	list_for_each_entry(fclun, &fcport->fcluns, list) {
		if (fclun->lun == lun) {
			found++;
			break;
		}
	}
	if (found) {
		return(fclun);
	}

	fclun = kmalloc(sizeof(fc_lun_t), GFP_ATOMIC);
	if (fclun == NULL) {
		printk(KERN_WARNING
		       "%s(): Memory Allocation failed - FCLUN\n",
		       __func__);
		return(NULL);
	}

	/* Setup LUN structure. */
	memset(fclun, 0, sizeof(fc_lun_t));
	fclun->lun = lun;
	fclun->fcport = fcport;
	fclun->device_type = fcport->device_type;

	list_add_tail(&fclun->list, &fcport->fcluns);

	return(fclun);
}




/*
 * qla4xxx_config_os
 *	Setup OS target and LUN structures.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Kernel context.
 */
static void
qla4xxx_config_os(scsi_qla_host_t *ha)
{
	fc_port_t       *fcport;
	fc_lun_t        *fclun;
	os_tgt_t        *tq;
	uint16_t        tgt;


	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		if ((tq = TGT_Q(ha, tgt)) == NULL)
			continue;

		tq->flags &= ~TQF_ONLINE;
	}

	list_for_each_entry(fcport, &ha->fcports, list)
	{
		if (atomic_read(&fcport->state) != FCS_ONLINE) {
			fcport->os_target_id = MAX_TARGETS;
			continue;
		}

		/* Bind FC port to OS target number. */
		if (qla4xxx_fcport_bind(ha, fcport) == MAX_TARGETS) {
			continue;
		}

		/* Bind FC LUN to OS LUN number. */
		list_for_each_entry(fclun, &fcport->fcluns, list)
		{
			qla4xxx_fclun_bind(ha, fcport, fclun);
		}
	}
}

/*
 * qla4xxx_fcport_bind
 *	Locates a target number for FC port.
 *
 * Input:
 *	ha = adapter state pointer.
 *	fcport = FC port structure pointer.
 *
 * Returns:
 *	target number
 *
 * Context:
 *	Kernel context.
 */
static uint16_t
qla4xxx_fcport_bind(scsi_qla_host_t *ha, fc_port_t *fcport)
{
	uint16_t        tgt;
	os_tgt_t        *tq = NULL;

	if (fcport->ddbptr == NULL)
		return(MAX_TARGETS);

	/* Check for persistent binding. */
	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		if ((tq = TGT_Q(ha, tgt)) == NULL)
			continue;

		if (memcmp(fcport->ddbptr->iscsi_name, tq->iscsi_name,
			   ISCSI_NAME_SIZE) == 0) {
			break;
		}
	}
	/* TODO: honor the ConfigRequired flag */
	if (tgt == MAX_TARGETS) {
		tgt = 0;

		/* Check if targetID 0 available. */
		if (TGT_Q(ha, tgt) != NULL) {
			/* Locate first free target for device. */
			for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
				if (TGT_Q(ha, tgt) == NULL) {
					break;
				}
			}
		}
		if (tgt != MAX_TARGETS) {
			if ((tq = qla4xxx_tgt_alloc(ha, tgt)) != NULL) {
				memcpy(tq->iscsi_name, fcport->ddbptr->iscsi_name,
				       ISCSI_NAME_SIZE);
			}
		}
	}

	/* Reset target numbers incase it changed. */
	fcport->os_target_id = tgt;
	if (tgt != MAX_TARGETS && tq != NULL) {
		DEBUG2(printk("scsi%d: %s: Assigning target ID=%02d @ %p to "
			      "ddb[%d], fcport %p, port state=0x%x, port down retry=%d\n",
			      ha->host_no, __func__, tgt, tq,
			      fcport->ddbptr->fw_ddb_index,
			      fcport,
			      atomic_read(&fcport->state),
			      atomic_read(&fcport->ddbptr->port_down_timer)));

		fcport->ddbptr->target = tgt;
		fcport->tgt_queue = tq;
		fcport->flags |= FCF_PERSISTENT_BOUND;
		tq->fcport = fcport;
		tq->flags |= TQF_ONLINE;
		tq->id = tgt;
	}

	if (tgt == MAX_TARGETS) {
		QL4PRINT(QLP2, printk(KERN_WARNING
				      "Unable to bind fcport, loop_id=%x\n", fcport->loop_id));
	}

	return(tgt);
}

/*
 * qla4xxx_fclun_bind
 *	Binds all FC device LUNS to OS LUNS.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	fcport:		FC port structure pointer.
 *
 * Returns:
 *	target number
 *
 * Context:
 *	Kernel context.
 */
os_lun_t *
qla4xxx_fclun_bind(scsi_qla_host_t *ha, fc_port_t *fcport, fc_lun_t *fclun)
{
	os_lun_t        *lq;
	uint16_t        tgt;
	uint16_t        lun;

	tgt = fcport->os_target_id;
	lun = fclun->lun;

	/* Allocate LUNs */
	if (lun >= MAX_LUNS) {
		DEBUG2(printk("scsi%d: %s: Unable to bind lun, invalid "
			      "lun=(%x).\n", ha->host_no, __func__, lun));
		return(NULL);
	}

	if ((lq = qla4xxx_lun_alloc(ha, tgt, lun)) == NULL) {
		printk(KERN_WARNING "scso%d: %s: Unable to bind fclun, lun=%x\n",
		       ha->host_no, __func__, lun);
		return(NULL);
	}

	lq->fclun = fclun;

	return(lq);
}

/*
 * qla4xxx_tgt_alloc
 *	Allocate and pre-initialize target queue.
 *
 * Input:
 *	ha = adapter block pointer.
 *	t = SCSI target number.
 *
 * Returns:
 *	NULL = failure
 *
 * Context:
 *	Kernel context.
 */
os_tgt_t *
qla4xxx_tgt_alloc(scsi_qla_host_t *ha, uint16_t tgt)
{
	os_tgt_t        *tq;

	/*
	 * If SCSI addressing OK, allocate TGT queue and lock.
	 */
	if (tgt >= MAX_TARGETS) {
		DEBUG2(printk("scsi%d: %s: Unable to allocate target, invalid "
			      "target number %d.\n", ha->host_no, __func__, tgt));
		return(NULL);
	}

	tq = TGT_Q(ha, tgt);
	if (tq == NULL) {
		tq = kmalloc(sizeof(os_tgt_t), GFP_ATOMIC);
		if (tq != NULL) {
			DEBUG3(printk("scsi%d: %s: Alloc Target %d @ %p\n",
				      ha->host_no, __func__, tgt, tq));

			memset(tq, 0, sizeof(os_tgt_t));
			tq->ha = ha;

			TGT_Q(ha, tgt) = tq;
		}
	}
	if (tq != NULL) {
		tq->port_down_retry_count = ha->port_down_retry_count;
	}
	else {
		printk(KERN_WARNING "Unable to allocate target.\n");
	}

	return(tq);
}

/*
 * qla4xxx_tgt_free
 *	Frees target and LUN queues.
 *
 * Input:
 *	ha = adapter block pointer.
 *	t = SCSI target number.
 *
 * Context:
 *	Kernel context.
 */
void
qla4xxx_tgt_free(scsi_qla_host_t *ha, uint16_t tgt)
{
	os_tgt_t        *tq;
	uint16_t        lun;

	/*
	 * If SCSI addressing OK, allocate TGT queue and lock.
	 */
	if (tgt >= MAX_TARGETS) {
		DEBUG2(printk("scsi%d: %s: Unable to de-allocate target, "
			      "invalid target number %d.\n", ha->host_no, __func__, tgt));

		return;
	}

	tq = TGT_Q(ha, tgt);
	if (tq != NULL) {
		TGT_Q(ha, tgt) = NULL;

		/* Free LUN structures. */
		for (lun = 0; lun < MAX_LUNS; lun++)
			qla4xxx_lun_free(ha, tgt, lun);

		kfree(tq);
	}

	return;
}

/*
 * qla4xxx_lun_alloc
 *	Allocate and initialize LUN queue.
 *
 * Input:
 *	ha = adapter block pointer.
 *	t = SCSI target number.
 *	l = LUN number.
 *
 * Returns:
 *	NULL = failure
 *
 * Context:
 *	Kernel context.
 */
os_lun_t *
qla4xxx_lun_alloc(scsi_qla_host_t *ha, uint16_t tgt, uint16_t lun)
{
	os_lun_t        *lq;

	/*
	 * If SCSI addressing OK, allocate LUN queue.
	 */
	if (lun >= MAX_LUNS || TGT_Q(ha, tgt) == NULL) {
		DEBUG2(printk("scsi%d: %s: Unable to allocate lun, invalid "
			      "parameter.\n", ha->host_no, __func__));

		return(NULL);
	}

	lq = LUN_Q(ha, tgt, lun);
	if (lq == NULL) {
		lq = kmalloc(sizeof(os_lun_t), GFP_ATOMIC);

		if (lq != NULL) {
			DEBUG3(printk("scsi%d: Alloc Lun %d @ tgt %d.\n",
				      ha->host_no, lun, tgt));

			memset(lq, 0, sizeof (os_lun_t));
			LUN_Q(ha, tgt, lun) = lq;

			/*
			 * The following lun queue initialization code
			 * must be duplicated in alloc_ioctl_mem function
			 * for ioctl_lq.
			 */
			lq->lun_state = LS_LUN_READY;
			spin_lock_init(&lq->lun_lock);
			DEBUG2(printk("Allocating Lun %d @ %p \n",lun,lq);)
		}
	}

	if (lq == NULL) {
		printk(KERN_WARNING "Unable to allocate lun.\n");
	}

	return(lq);
}

/*
 * qla4xxx_lun_free
 *	Frees LUN queue.
 *
 * Input:
 *	ha = adapter block pointer.
 *	t = SCSI target number.
 *
 * Context:
 *	Kernel context.
 */
static void
qla4xxx_lun_free(scsi_qla_host_t *ha, uint16_t tgt, uint16_t lun)
{
	os_lun_t        *lq;

	/*
	 * If SCSI addressing OK, allocate TGT queue and lock.
	 */
	if (tgt >= MAX_TARGETS || lun >= MAX_LUNS) {
		DEBUG2(printk("scsi%d: %s: Unable to deallocate lun, invalid "
			      "parameter.\n", ha->host_no, __func__));

		return;
	}

	if (TGT_Q(ha, tgt) != NULL && (lq = LUN_Q(ha, tgt, lun)) != NULL) {
		LUN_Q(ha, tgt, lun) = NULL;
		kfree(lq);
	}

	return;
}

/**************************************************************************
 * qla4xxx_free_ddb
 *	This routine deallocates and unlinks the specified ddb_entry from the
 *	adapter's
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *	ddb_entry - Pointer to device database entry
 *
 * Returns:
 *	None
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
void
qla4xxx_free_ddb(scsi_qla_host_t *ha, ddb_entry_t *ddb_entry)
{
	fc_port_t       *fcport;

	ENTER("qla4xxx_free_ddb");

	/* Remove device entry from list */
	list_del_init(&ddb_entry->list_entry);

	/* Remove device pointer from index mapping arrays */
	ha->fw_ddb_index_map[ddb_entry->fw_ddb_index] = (ddb_entry_t *) INVALID_ENTRY;
	ha->tot_ddbs--;

	fcport = ddb_entry->fcport;
	if (fcport) {
		atomic_set(&fcport->state, FCS_DEVICE_DEAD);
		fcport->ddbptr = NULL;
	}

	/* Free memory for device entry */
	kfree(ddb_entry);
	ddb_entry = NULL;
	LEAVE("qla4xxx_free_ddb");
}

/**************************************************************************
 * qla4xxx_free_ddb_list
 *	This routine deallocates and removes all devices on the sppecified
 *	adapter.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Returns:
 *	None
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
void
qla4xxx_free_ddb_list(scsi_qla_host_t *ha)
{
	struct list_head *ptr;
	ddb_entry_t *ddb_entry;
	fc_port_t       *fcport;

	ENTER("qla4xxx_free_ddb_list");

	while (!list_empty(&ha->ddb_list)) {
		/* Remove device entry from head of list */
		ptr = ha->ddb_list.next;
		list_del_init(ptr);

		/* Free memory for device entry */
		ddb_entry = list_entry(ptr, ddb_entry_t, list_entry);
		if (ddb_entry) {
			fcport = ddb_entry->fcport;
			if (fcport) {
				atomic_set(&fcport->state, FCS_DEVICE_DEAD);
				fcport->ddbptr = NULL;
			}
			kfree(ddb_entry);
		}
	}

	LEAVE("qla4xxx_free_ddb_list");
}

/**************************************************************************
 * qla4xxx_init_rings
 *	This routine initializes the internal queues for the specified adapter.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Remarks:
 *	The QLA4010 requires us to restart the queues at index 0.
 *	The QLA4000 doesn't care, so just default to QLA4010's requirement.
 * Returns:
 *	QLA_SUCCESS - Always return success.
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_init_rings(scsi_qla_host_t *ha)
{
	uint16_t    i;
	unsigned long flags = 0;

	ENTER("qla4xxx_init_rings");

	/* Initialize request queue. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	ha->request_out = 0;
	ha->request_in = 0;
	ha->request_ptr = &ha->request_ring[ha->request_in];
	ha->req_q_count = REQUEST_QUEUE_DEPTH;

	/* Initialize response queue. */
	ha->response_in = 0;
	ha->response_out = 0;
	ha->response_ptr = &ha->response_ring[ha->response_out];

	QL4PRINT(QLP7, printk("scsi%d: %s response_ptr=%p\n", ha->host_no,
			      __func__, ha->response_ptr));

	/*
	 * Initialize DMA Shadow registers.  The firmware is really supposed to
	 * take care of this, but on some uniprocessor systems, the shadow
	 * registers aren't cleared-- causing the interrupt_handler to think
	 * there are responses to be processed when there aren't.
	 */
	ha->shadow_regs->req_q_out = __constant_cpu_to_le32(0);
	ha->shadow_regs->rsp_q_in = __constant_cpu_to_le32(0);
	wmb();

	WRT_REG_DWORD(&ha->reg->req_q_in, 0);
	WRT_REG_DWORD(&ha->reg->rsp_q_out, 0);
	PCI_POSTING(&ha->reg->rsp_q_out);

	/* Initialize active array */
	for (i = 0; i < MAX_SRBS; i++)
		ha->active_srb_array[i] = NULL;
	ha->active_srb_count = 0;

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	LEAVE("qla4xxx_init_rings");

	return(QLA_SUCCESS);
}


#define qla4xxx_mac_is_equal(mac1, mac2) (memcmp(mac1, mac2, MAC_ADDR_LEN) == 0)

/**************************************************************************
 * qla4xxx_validate_mac_address
 *	This routine validates the M.A.C. Address(es) of the adapter
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully validated M.A.C. address
 *	QLA_ERROR   - Failed to validate M.A.C. address
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
static uint8_t
qla4xxx_validate_mac_address(scsi_qla_host_t *ha)
{
	FLASH_SYS_INFO *sys_info = NULL;
	dma_addr_t sys_info_dma;
	uint8_t status = QLA_ERROR;

	ENTER("qla4xxx_validate_mac_address");
	sys_info = (FLASH_SYS_INFO *) pci_alloc_consistent(ha->pdev,
							   sizeof(*sys_info),
							   &sys_info_dma);
	if (sys_info == NULL) {
		QL4PRINT(QLP2, printk("scsi%d: %s: Unable to allocate dma "
				      "buffer.\n", ha->host_no, __func__));
		goto exit_validate_mac;
	}
	memset(sys_info, 0, sizeof(*sys_info));

	/* Get flash sys info */
	if (qla4xxx_get_flash(ha, sys_info_dma, FLASH_OFFSET_SYS_INFO,
			      sizeof(*sys_info)) != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: %s: get_flash "
				      "FLASH_OFFSET_SYS_INFO failed\n",
				      ha->host_no, __func__));
		goto exit_validate_mac;
	}

	/* Save M.A.C. address & serial_number */
	memcpy(ha->my_mac, &sys_info->physAddr[0].address[0],
	       MIN(sizeof(ha->my_mac), sizeof(sys_info->physAddr[0].address)));
	memcpy(ha->serial_number, &sys_info->acSerialNumber,
	       MIN(sizeof(ha->serial_number), sizeof(sys_info->acSerialNumber)));

	/* Display Debug Print Info */
	QL4PRINT(QLP10, printk("scsi%d: Flash Sys Info\n", ha->host_no));
	qla4xxx_dump_bytes(QLP10, sys_info, sizeof(*sys_info));

	/*
	 * If configuration information was specified on the command line,
	 * validate the mac address here.
	 */
	if (ql4xdevconf) {
		char *propbuf;
		uint8_t cfg_mac[MAC_ADDR_LEN];

		propbuf = kmalloc(LINESIZE, GFP_ATOMIC);
		if (propbuf == NULL) {
			QL4PRINT(QLP2, printk("scsi%d: %s: Unable to "
					      "allocate memory.\n",
					      ha->host_no, __func__));
			goto exit_validate_mac;
		}

		/* Get mac address from configuration file. */
		sprintf(propbuf, "scsi-qla%d-mac", ha->instance);
		qla4xxx_get_prop_12chars(ha, propbuf, &cfg_mac[0], ql4xdevconf);

		if (qla4xxx_mac_is_equal(&ha->my_mac, cfg_mac)) {
			QL4PRINT(QLP7, printk("scsi%d: %s: This is a "
					      "registered adapter.\n",
					      ha->host_no, __func__));
			status = QLA_SUCCESS;
		} else {
			QL4PRINT(QLP7, printk("scsi%d: %s: This is NOT a "
					      "registered adapter.\n",
					      ha->host_no, __func__));
		}
		kfree(propbuf);
	} else {
		status = QLA_SUCCESS;
	}

	exit_validate_mac:
	if (sys_info)
		pci_free_consistent(ha->pdev, sizeof(*sys_info), sys_info,
				    sys_info_dma);

	LEAVE("qla4xxx_validate_mac_address");

	return(status);
}

/**************************************************************************
 * qla4xxx_init_local_data
 *	This routine initializes the local data for the specified adapter.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully initialized local data
 *	QLA_ERROR   - Failed to initialize local data
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
static uint8_t
qla4xxx_init_local_data(scsi_qla_host_t *ha)
{
	int i;

	/* Initialize passthru PDU list */
	for (i = 0; i < (MAX_PDU_ENTRIES - 1); i++) {
		ha->pdu_queue[i].Next = &ha->pdu_queue[i+1];
	}
	ha->free_pdu_top = &ha->pdu_queue[0];
	ha->free_pdu_bottom = &ha->pdu_queue[MAX_PDU_ENTRIES - 1];
	ha->free_pdu_bottom->Next = NULL;
	ha->pdu_active = 0;

	/* Initilize aen queue */
	ha->aen_count = 0;
	ha->aen_report = 0;

#if ENABLE_ISNS
	/* Initialize local iSNS data */
	qla4xxx_isns_init_attributes(ha);
	ha->isns_flags = 0;
	atomic_set(&ha->isns_restart_timer, 0);
	ha->isns_connection_id = 0;
	ha->isns_remote_port_num = 0;
	ha->isns_scn_port_num = 0;
	ha->isns_esi_port_num = 0;
	ha->isns_nsh_port_num = 0;
	memset(ha->isns_entity_id, 0, sizeof(ha->isns_entity_id));
	ha->isns_num_discovered_targets = 0;
#endif

	return(qla4xxx_get_firmware_status(ha));
}

/**************************************************************************
 * qla4xxx_initialize_fw_cb
 *	This routine initializes the firmware control block for the
 *	specified adapter.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully initialized firmware ctrl block
 *	QLA_ERROR   - Failed to initialize firmware ctrl block
 *
 * Remarks:
 *	Initially, we use the size of the ifcb to determine if IPv6 is
 *	supported.  Subsequently, after we retrieve the ifcb,
 *	we use the saved ipv6_options to dermine if ipv6 is supported.
 *	We make the assumption that if ipv6 is enabled, then the ifcb
 *	structure is large enough to access ipv6 fields.
 *
 *	For legacy support, the IFCB is essentially the first 200h bytes
 *	of the primary ACB.  For IPv6 support, the overall size of the
 *	IFCB is two ACB structures concatenated.  However, the initiator
 *	driver only needs to access the primary ACB.
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
static uint8_t
qla4xxx_initialize_fw_cb(scsi_qla_host_t *ha)
{
	ADDRESS_CTRL_BLK  *init_fw_cb = NULL;
	dma_addr_t	  init_fw_cb_dma;
	uint32_t    	  mbox_cmd[MBOX_REG_COUNT];
	uint32_t    	  mbox_sts[MBOX_REG_COUNT];
	uint8_t     	  status = QLA_ERROR;
	uint8_t 	  ip_addr_str[IP_ADDR_STR_SIZE];

	ENTER(__func__);

	/* Default to Legacy IFCB Size */
	ha->ifcb_size = LEGACY_IFCB_SIZE;

	/*
	 * Determine if larger IFCB is supported
	 */
	if (qla4xxx_get_ifcb(ha, &mbox_cmd[0], &mbox_sts[0], 0) != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: %s: get ifcb failed\n",
			ha->host_no, __func__));
		LEAVE(__func__);
		return QLA_ERROR;
	}
	if (mbox_sts[0] == MBOX_STS_COMMAND_PARAMETER_ERROR &&
	    mbox_sts[4] > LEGACY_IFCB_SIZE) {
		/* Supports larger ifcb size */
	       ha->ifcb_size = mbox_sts[4];
	}

	init_fw_cb = pci_alloc_consistent(ha->pdev, ha->ifcb_size,
	  &init_fw_cb_dma);
	if (init_fw_cb == NULL) {
		printk("scsi%d: %s: Unable to alloc init_cb, size=0x%x\n",
		       ha->host_no, __func__, ha->ifcb_size);
		return 10;
	}
	memset(init_fw_cb, 0, ha->ifcb_size);

	/*
	 * Get Initialize Firmware Control Block
	 */
	if (qla4xxx_get_ifcb(ha, &mbox_cmd[0], &mbox_sts[0], init_fw_cb_dma)
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2,
			 printk("scsi%d: %s: Failed to get init_fw_ctrl_blk\n",
				ha->host_no, __func__));
		goto exit_init_fw_cb;
	}

	QL4PRINT(QLP10, printk("scsi%d: Get Init Fw Ctrl Blk\n", ha->host_no));
	qla4xxx_dump_bytes(QLP10, init_fw_cb, ha->ifcb_size);

	/*
	 * Initialize request and response queues
	 */
	qla4xxx_init_rings(ha);

	/*
	 * Fill in the request and response queue information
	 */
	if (IS_QLA4010(ha)) {
		init_fw_cb->ReqQConsumerIndex = cpu_to_le16(ha->request_out);
		init_fw_cb->ComplQProducerIndex = cpu_to_le16(ha->response_in);
	}
	init_fw_cb->ReqQLen = __constant_cpu_to_le16(REQUEST_QUEUE_DEPTH);
	init_fw_cb->ComplQLen = __constant_cpu_to_le16(RESPONSE_QUEUE_DEPTH);
	init_fw_cb->ReqQAddrLo = cpu_to_le32(LSDW(ha->request_dma));
	init_fw_cb->ReqQAddrHi = cpu_to_le32(MSDW(ha->request_dma));
	init_fw_cb->ComplQAddrLo = cpu_to_le32(LSDW(ha->response_dma));
	init_fw_cb->ComplQAddrHi = cpu_to_le32(MSDW(ha->response_dma));
	init_fw_cb->ShadowRegBufAddrLo = cpu_to_le32(LSDW(ha->shadow_regs_dma));
	init_fw_cb->ShadowRegBufAddrHi = cpu_to_le32(MSDW(ha->shadow_regs_dma));

	/*
	 * Set up required options
	 */
	init_fw_cb->FwOptions |=
	    __constant_cpu_to_le16(FWOPT_SESSION_MODE | FWOPT_INITIATOR_MODE);
	init_fw_cb->FwOptions &= __constant_cpu_to_le16(~FWOPT_TARGET_MODE);
	
	/*
	 * Send Initialize Firmware Control Block
	 */
	QL4PRINT(QLP10, printk("scsi%d: Pre Set Init Fw Ctrl Blk\n", ha->host_no));
	qla4xxx_dump_bytes(QLP10, init_fw_cb, ha->ifcb_size);

	if (qla4xxx_set_ifcb(ha, &mbox_cmd[0], &mbox_sts[0], init_fw_cb_dma)
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2,
                         printk("scsi%d: %s: Failed to set init_fw_ctrl_blk\n",
					     ha->host_no, __func__));
		goto exit_init_fw_cb;
	}

	if (qla4xxx_get_ifcb(ha, &mbox_cmd[0], &mbox_sts[0], init_fw_cb_dma)
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2,
			 printk("scsi%d: %s: Failed to get init_fw_ctrl_blk\n",
				ha->host_no, __func__));
		goto exit_init_fw_cb;
	}

	QL4PRINT(QLP7, printk("scsi%d: Post Set Init Fw Ctrl Blk\n", ha->host_no));
	qla4xxx_dump_bytes(QLP7, init_fw_cb, ha->ifcb_size);

	/*
	 * Save some info in adapter structure
	 */
	ha->firmware_options = le16_to_cpu(init_fw_cb->FwOptions);
	ha->ip_options = le16_to_cpu(init_fw_cb->IPOptions);
	ha->tcp_options = le16_to_cpu(init_fw_cb->TCPOptions);
	ha->heartbeat_interval = init_fw_cb->HeartbeatInterval;
	ha->isns_server_port_number =
	    le16_to_cpu(init_fw_cb->iSNSServerPortNumber);
	ha->acb_version = init_fw_cb->ACBVersion;

	memcpy(ha->ip_address, init_fw_cb->IPAddr,
	    MIN(sizeof(ha->ip_address), sizeof(init_fw_cb->IPAddr)));
	memcpy(ha->subnet_mask, init_fw_cb->SubnetMask,
	    MIN(sizeof(ha->subnet_mask), sizeof(init_fw_cb->SubnetMask)));
	memcpy(ha->gateway, init_fw_cb->GatewayIPAddr,
	    MIN(sizeof(ha->gateway), sizeof(init_fw_cb->GatewayIPAddr)));
	memcpy(ha->isns_server_ip_addr, init_fw_cb->iSNSIPAddr,
	    MIN(sizeof(ha->isns_server_ip_addr), sizeof(init_fw_cb->iSNSIPAddr)));
	memcpy(ha->name_string, init_fw_cb->iSCSINameString,
	    MIN(sizeof(ha->name_string), sizeof(init_fw_cb->iSCSINameString)));
	memcpy(ha->alias, init_fw_cb->iSCSIAlias,
	    MIN(sizeof(ha->alias), sizeof(init_fw_cb->iSCSIAlias)));

	if (ha->acb_version == ACB_SUPPORTED) {
                ha->ipv6_options = init_fw_cb->IPv6Options;
	}

	/* Save Command Line Paramater info */
	ha->port_down_retry_count = (ql4xkeepalive != 0xDEAD)
		? ql4xkeepalive : le16_to_cpu(init_fw_cb->KeepAliveTimeout);
	ha->discovery_wait = ql4xdiscoverywait;

	QL4PRINT(QLP7, printk("scsi%d: %s: Driver Version        %s\n",
	    ha->host_no, __func__, QLA4XXX_DRIVER_VERSION));

	if (!IS_IPv4_ENABLED(ha) && !IS_IPv6_ENABLED(ha)) {
		QL4PRINT(QLP7, printk("scsi%d: %s: ERROR: Neither IPv4 nor "
				      "IPv6 address configured.\n",
				       ha->host_no, __func__));
	}

	if ((ha->acb_version == ACB_NOT_SUPPORTED) || IS_IPv4_ENABLED(ha)) {
		/* --- IP v4 --- */
		IPv4Addr2Str(init_fw_cb->IPAddr, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "IP Address            %s\n",
		    ha->host_no, __func__, &ip_addr_str[0]));

		IPv4Addr2Str(init_fw_cb->SubnetMask, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "Subnet Mask           %s\n",
		    ha->host_no, __func__, &ip_addr_str[0]));

		IPv4Addr2Str(init_fw_cb->GatewayIPAddr, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "Default Gateway       %s\n",
		    ha->host_no, __func__, &ip_addr_str[0]));

		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "Auto-Negotiate        %s\n", ha->host_no, __func__,
		    ((le16_to_cpu(init_fw_cb->AddFwOptions) & 0x10) != 0) ?
		    "ON" : "OFF"));
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "SLP Use DA Enable     %s\n", ha->host_no, __func__,
		    ((ha->tcp_options & TOPT_SLP_USE_DA_ENABLE) != 0) ?
		    "ON" : "OFF"));
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "SLP UA Enable         %s\n", ha->host_no, __func__,
		    ((ha->tcp_options & TOPT_SLP_UA_ENABLE) != 0) ?
		    "ON" : "OFF"));
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "DHCP Enable           %s\n", ha->host_no, __func__,
		    ((ha->tcp_options & TOPT_DHCP_ENABLE) != 0) ?
		    "ON" : "OFF"));
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "DNS via DHCP Enable   %s\n", ha->host_no, __func__,
		    ((ha->tcp_options & TOPT_GET_DNS_VIA_DHCP_ENABLE) != 0) ?
		    "ON" : "OFF"));
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "SLP via DHCP Enable   %s\n", ha->host_no, __func__,
		    ((ha->tcp_options & TOPT_GET_SLP_VIA_DHCP_ENABLE) != 0) ?
		    "ON" : "OFF"));
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "Auto Discovery Enable %s\n", ha->host_no, __func__,
		    ((ha->tcp_options & TOPT_AUTO_DISCOVERY_ENABLE) != 0) ?
		    "ON" : "OFF"));
		QL4PRINT(QLP7|QLP20, printk("scsi%d: %s: "
		    "iSNS Enable           %s\n", ha->host_no, __func__,
		    ((ha->tcp_options & TOPT_ISNSv4_ENABLE) != 0) ?
		    "ON" : "OFF"));
#if ENABLE_ISNS
		if (ha->tcp_options & TOPT_ISNSv4_ENABLE) {
			set_bit(ISNS_FLAG_ISNS_ENABLED_IN_ISP, &ha->isns_flags);

			IPv4Addr2Str(ha->isns_server_ip_addr, &ip_addr_str[0]);
			QL4PRINT(QLP7|QLP20, printk("scsi%d: %s: "
			    "iSNSv4 IP Address     %s\n",
			    ha->host_no, __func__, &ip_addr_str[0]));
			QL4PRINT(QLP7|QLP20, printk("scsi%d: %s: "
			    "iSNS Server Port Number %d\n", ha->host_no,
			    __func__, ha->isns_server_port_number));
		}
#endif
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "Heartbeat Enable      %s\n", ha->host_no, __func__,
		    ((ha->firmware_options & FWOPT_HEARTBEAT_ENABLE) != 0) ?
		    "ON" : "OFF"));
		if (ha->firmware_options & FWOPT_HEARTBEAT_ENABLE)
			QL4PRINT(QLP7, printk("scsi%d: %s: "
			    "Heartbeat Interval    %d\n", ha->host_no, __func__,
			    ha->heartbeat_interval));

		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "Execution Throttle    %d\n", ha->host_no, __func__,
		    le16_to_cpu(init_fw_cb->ExecThrottle)));

		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "ACB Supported  (%d)    %s\n", ha->host_no, __func__,
		    ha->acb_version,
		    (ha->acb_version == ACB_SUPPORTED) ? "ON" : "OFF"));
	}

	if (IS_IPv6_ENABLED(ha)){
		/* --- IP v6 --- */
	
		ha->ipv6_addl_options = init_fw_cb->IPv6AddOptions;
		ha->ipv6_tcp_options = init_fw_cb->IPv6TCPOptions;
		ha->ipv6_link_local_state = init_fw_cb->IPv6LinkLocalAddrState;
		ha->ipv6_addr0_state = init_fw_cb->IPv6Addr0State;
		ha->ipv6_addr1_state = init_fw_cb->IPv6Addr1State;
		ha->ipv6_default_router_state = init_fw_cb->IPv6DefaultRouterState;
		ha->ipv6_link_local_addr[0] = 0xFE;
		ha->ipv6_link_local_addr[1] = 0x80;
		memcpy(&ha->ipv6_link_local_addr[8], init_fw_cb->IPv6InterfaceID,
		    MIN(sizeof(ha->ipv6_link_local_addr)/2, sizeof(init_fw_cb->IPv6InterfaceID)));
		memcpy(ha->ipv6_addr0, init_fw_cb->IPv6Addr0,
		    MIN(sizeof(ha->ipv6_addr0), sizeof(init_fw_cb->IPv6Addr0)));
		memcpy(ha->ipv6_addr1, init_fw_cb->IPv6Addr1,
		    MIN(sizeof(ha->ipv6_addr1), sizeof(init_fw_cb->IPv6Addr1)));
		memcpy(ha->ipv6_default_router_addr, init_fw_cb->IPv6DefaultRouterAddr,
		    MIN(sizeof(ha->ipv6_default_router_addr), sizeof(init_fw_cb->IPv6DefaultRouterAddr)));
	
		IPv6Addr2Str(ha->ipv6_link_local_addr, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
			"IPv6 Link Local       %s (%d)\n",
			ha->host_no, __func__, &ip_addr_str[0],
			ha->ipv6_link_local_state));
	
		IPv6Addr2Str(ha->ipv6_addr0, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
			"IPv6 IP Address0      %s (%d)\n",
			ha->host_no, __func__, &ip_addr_str[0],
			ha->ipv6_addr0_state));
	
		IPv6Addr2Str(ha->ipv6_addr1, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
			"IPv6 IP Address1      %s (%d)\n",
			ha->host_no, __func__, &ip_addr_str[0],
			ha->ipv6_addr1_state));
	
		IPv6Addr2Str(ha->ipv6_default_router_addr, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
			"IPv6 Default Router   %s (%d)\n",
			ha->host_no, __func__, &ip_addr_str[0],
			ha->ipv6_default_router_state));
	
#if ENABLE_ISNS
		/* In IPv6 mode, iSNS may either be IPv4 or IPv6, not both */
		if (ha->tcp_options & TOPT_ISNSv4_ENABLE) {
			set_bit(ISNS_FLAG_ISNS_ENABLED_IN_ISP, &ha->isns_flags);
	
			memcpy(ha->isns_server_ip_addr, init_fw_cb->iSNSIPAddr,
			    MIN(sizeof(ha->isns_server_ip_addr), sizeof(init_fw_cb->iSNSIPAddr)));

			IPv4Addr2Str(ha->isns_server_ip_addr, &ip_addr_str[0]);
			QL4PRINT(QLP7, printk("scsi%d: %s: "
				"IPv4 iSNS IP Address      %s\n",
				ha->host_no, __func__, &ip_addr_str[0]));
			QL4PRINT(QLP7|QLP20, printk("scsi%d: %s: "
				"iSNS Server Port Number   %d\n", ha->host_no,
				__func__, ha->isns_server_port_number));
		}
		else if (ha->ipv6_tcp_options & IPV6_TCPOPT_ISNSv6_ENABLE) {
			set_bit(ISNS_FLAG_ISNS_ENABLED_IN_ISP, &ha->isns_flags);
	
			memcpy(ha->isns_server_ip_addr, init_fw_cb->IPv6iSNSIPAddr,
			    MIN(sizeof(ha->isns_server_ip_addr), sizeof(init_fw_cb->IPv6iSNSIPAddr)));

			IPv6Addr2Str(ha->isns_server_ip_addr, &ip_addr_str[0]);
			QL4PRINT(QLP7, printk("scsi%d: %s: "
				"IPv6 iSNS IP Address  %s\n",
				ha->host_no, __func__, &ip_addr_str[0]));
			QL4PRINT(QLP7|QLP20, printk("scsi%d: %s: "
			    "iSNS Server Port Number   %d\n", ha->host_no,
			    __func__, ha->isns_server_port_number));
		}
#endif	
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "IPv6 Protocol Enable      %s\n", ha->host_no, __func__,
		    (IS_IPv6_ENABLED(ha)) ? "ON" : "OFF"));
	
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "IPv6 Autoconfig LinkLocal %s\n", ha->host_no, __func__,
		    ((ha->ipv6_addl_options & IPV6_ADDOPT_AUTOCONFIG_LINK_LOCAL_ADDR) != 0) ?
		    "ON" : "OFF"));

#if ENABLE_ISNS
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "IPv6 iSNS Enabled         %s\n", ha->host_no, __func__,
		    ((ha->ipv6_tcp_options & IPV6_TCPOPT_ISNSv6_ENABLE) != 0) ?
		    "ON" : "OFF"));
#endif
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "IPv6 Options              0x%04x\n", ha->host_no, __func__,
		    ha->ipv6_options));
	
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "IPv6 Additional Options   0x%04x\n", ha->host_no, __func__,
		    ha->ipv6_addl_options));
	
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "IPv6 TCP Options          0x%04x\n", ha->host_no, __func__,
		    ha->ipv6_tcp_options));

		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "ACB Supported             %s\n", ha->host_no, __func__,
		    (ha->acb_version == ACB_SUPPORTED) ?
		    "ON" : "OFF"));
	}

	status = QLA_SUCCESS;

exit_init_fw_cb:
	pci_free_consistent(ha->pdev, ha->ifcb_size, init_fw_cb, init_fw_cb_dma);
	LEAVE(__func__);
	return status;
}

static uint8_t
qla4xxx_wait_for_ip_config(scsi_qla_host_t *ha)
{
	uint8_t ipv4_wait = 0;
	uint8_t ipv6_wait = 0;

	/* If both IPv4 & IPv6 are enabled, possibly only one
	 * IP address may be acquired, so check to see if we
	 * need to wait for another */
	if (IS_IPv4_ENABLED(ha) && IS_IPv6_ENABLED(ha)) {
		if (((ha->addl_fw_state & FW_ADDSTATE_DHCPv4_ENABLED) != 0) &&
		    ((ha->addl_fw_state & FW_ADDSTATE_DHCPv4_LEASE_ACQUIRED) == 0)) {
			ipv4_wait = 1;
		}
		if (((ha->ipv6_addl_options & IPV6_ADDOPT_NEIGHBOR_DISCOVERY_ADDR_ENABLE) != 0) &&
		     ((ha->ipv6_link_local_state == IPV6_ADDRSTATE_ACQUIRING) ||
                      (ha->ipv6_addr0_state == IPV6_ADDRSTATE_ACQUIRING) ||
		      (ha->ipv6_addr1_state == IPV6_ADDRSTATE_ACQUIRING))) {

			ipv6_wait = 1;

			if ((ha->ipv6_link_local_state == IPV6_ADDRSTATE_PREFERRED) ||
			    (ha->ipv6_addr0_state == IPV6_ADDRSTATE_PREFERRED) ||
			    (ha->ipv6_addr1_state == IPV6_ADDRSTATE_PREFERRED)) {
				QL4PRINT(QLP7, printk("scsi%d: %s: "
					"Preferred IP configured.  Don't wait! \n",
					ha->host_no, __func__));
				ipv6_wait = 0;
			}
			if (IPv6AddrIsZero(ha->ipv6_default_router_addr)) {
				QL4PRINT(QLP7, printk("scsi%d: %s: "
					"No Router configured.  Don't wait! \n",
					ha->host_no, __func__));
				ipv6_wait = 0;
			}
			if ((ha->ipv6_default_router_state == IPV6_RTRSTATE_MANUAL) &&
			    (ha->ipv6_link_local_state == IPV6_ADDRSTATE_TENTATIVE) &&
			    (ha->ipv6_link_local_addr[0] == ha->ipv6_default_router_addr[0]) &&
                            (ha->ipv6_link_local_addr[1] == ha->ipv6_default_router_addr[1]) &&
                            (ha->ipv6_link_local_addr[2] == ha->ipv6_default_router_addr[2]) &&
                            (ha->ipv6_link_local_addr[3] == ha->ipv6_default_router_addr[3])) {
				QL4PRINT(QLP7, printk("scsi%d: %s: "
					"LinkLocal Router & IP configured.  Don't wait! \n",
					ha->host_no, __func__));
				ipv6_wait = 0;
			}
		}
		if (ipv4_wait || ipv6_wait) {
			QL4PRINT(QLP7, printk("scsi%d: %s: Wait for additional IP(s) \"",
					ha->host_no, __func__));
			if (ipv4_wait)
				QL4PRINT(QLP7, printk("IPv4 "));
			if (ha->ipv6_link_local_state == IPV6_ADDRSTATE_ACQUIRING)
				QL4PRINT(QLP7, printk("IPv6LinkLocal "));
			if (ha->ipv6_addr0_state == IPV6_ADDRSTATE_ACQUIRING)
				QL4PRINT(QLP7, printk("IPv6Addr0 "));
			if (ha->ipv6_addr1_state == IPV6_ADDRSTATE_ACQUIRING)
				QL4PRINT(QLP7, printk("IPv6Addr1 "));
			QL4PRINT(QLP7, printk("\"\n"));
		}
	}

       return (ipv4_wait|ipv6_wait);
}

static int
qla4xxx_fw_ready (scsi_qla_host_t *ha)
{
	uint32_t timeout_count;
	int     ready = 0;
#if ENABLE_ISNS
	uint8_t isns_ip_addr_is_valid;
#endif

	ql4_printk(KERN_INFO, ha,
		   "Waiting for Firmware Ready..\n");
	for (timeout_count = ADAPTER_INIT_TOV; timeout_count > 0;
	    timeout_count--) {

		/* If DHCP IP Addr is available, retrieve it now. */
		if (test_and_clear_bit(DPC_GET_DHCP_IP_ADDR, &ha->dpc_flags))
			qla4xxx_get_dhcp_ip_address(ha);

		/* Get firmware state. */
		if (qla4xxx_get_firmware_state(ha) != QLA_SUCCESS) {
			DEBUG2(printk("scsi%d: %s: unable to get "
				      "firmware state\n", ha->host_no, __func__));
			LEAVE("qla4xxx_init_firmware");
			break;
		}
		if (ha->firmware_state & FW_STATE_ERROR) {
			DEBUG2(printk("scsi%d: %s: an unrecoverable "
				      "error has occurred\n", ha->host_no, __func__));
			LEAVE("qla4xxx_init_firmware");
			break;
		}
		if (ha->firmware_state & FW_STATE_CONFIG_WAIT) {
			/*
			 * The firmware has not yet been issued an Initialize
			 * Firmware command, so issue it now.
			 */
			if (qla4xxx_initialize_fw_cb(ha) == QLA_ERROR) {
				LEAVE("qla4xxx_init_firmware");
				break;
			}

			/* Go back and test for ready state - no wait. */
			continue;
		}

		if (ha->firmware_state & FW_STATE_WAIT_AUTOCONNECT) {
			QL4PRINT(QLP7, printk("scsi%d: %s: fwstate:"
					      "AUTOCONNECT in progress\n", ha->host_no, __func__));
		}

		if (ha->firmware_state & FW_STATE_CONFIGURING_IP) {
			QL4PRINT(QLP7, printk("scsi%d: %s: fwstate: CONFIGURING IP\n",
					      ha->host_no, __func__));
		}

		if (ha->firmware_state == FW_STATE_READY) {
			/* If DHCP IP Addr is available, retrieve it now. */
			if (test_and_clear_bit(DPC_GET_DHCP_IP_ADDR, &ha->dpc_flags))
				qla4xxx_get_dhcp_ip_address(ha);

			if (!qla4xxx_wait_for_ip_config(ha) || timeout_count == 1) {
				ql4_printk(KERN_INFO, ha, "Firmware Ready..\n");
				/* The firmware is ready to process SCSI commands. */
				QL4PRINT(QLP7, printk("scsi%d: %s: FW STATE - READY\n",
						      ha->host_no, __func__));
				QL4PRINT(QLP7, printk("scsi%d: %s: MEDIA TYPE - %s\n",
						      ha->host_no, __func__,
						      ((ha->addl_fw_state & FW_ADDSTATE_OPTICAL_MEDIA) !=
						       0) ? "OPTICAL" : "COPPER"));
				QL4PRINT(QLP7, printk("scsi%d: %s: LINK  %s\n",
						      ha->host_no, __func__,
						      ((ha->addl_fw_state & FW_ADDSTATE_LINK_UP) != 0) ?
						      "UP" : "DOWN"));
				if (IS_IPv4_ENABLED(ha)){
					QL4PRINT(QLP7, printk("scsi%d: %s: DHCPv4 STATE Enabled "
							      "%s\n", ha->host_no, __func__,
							      ((ha->addl_fw_state & FW_ADDSTATE_DHCPv4_ENABLED) !=
							       0) ? "YES" : "NO"));
					QL4PRINT(QLP7, printk("scsi%d: %s: DHCPv4 STATE Lease "
							      "Acquired  %s\n", ha->host_no, __func__,
							      ((ha->addl_fw_state &
								FW_ADDSTATE_DHCPv4_LEASE_ACQUIRED) != 0) ?
							      "YES" : "NO"));
					QL4PRINT(QLP7, printk("scsi%d: %s: DHCPv4 STATE Lease "
							      "Expired  %s\n", ha->host_no, __func__,
							      ((ha->addl_fw_state &
								FW_ADDSTATE_DHCPv4_LEASE_ACQUIRED) != 0) ?
							      "YES" : "NO"));
				}
				ready = 1;
	
	#if ENABLE_ISNS
				
				/* If iSNS is enabled, start the iSNS service now. */
				isns_ip_addr_is_valid = !IPAddrIsZero(ha, ha->isns_server_ip_addr);
	
				if (test_bit(ISNS_FLAG_ISNS_ENABLED_IN_ISP, &ha->isns_flags) &&
				    isns_ip_addr_is_valid) {
					ql4_printk(KERN_INFO, ha, "Initializing ISNS..\n");
					qla4xxx_isns_reenable(ha, ha->isns_server_ip_addr, ha->isns_server_port_number);
				}
	#endif
				break;
			}
		}

		DEBUG2(printk("scsi%d: %s: waiting on fw, state=%x:%x - "
			      "seconds expired= %d\n", ha->host_no,
			      __func__, ha->firmware_state,
			      ha->addl_fw_state, timeout_count));
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(1 * HZ);

		if (qla4xxx_poll_and_ack_scsi_reset(ha) == QLA_SUCCESS)
			break;
	} /* for */

	if (timeout_count <= 0) {
		DEBUG2(printk("scsi%d: %s: FW Initialization timed out!\n",
			      ha->host_no, __func__));

		if (ha->firmware_state & FW_STATE_CONFIGURING_IP) {
			QL4PRINT(QLP2, printk("scsi%d: %s: FW is reporting it's waiting to"
					      " configure an IP address\n",
					      ha->host_no, __func__));
			ready = 1;
		}
	}

	return ready;
}

/**************************************************************************
 * qla4xxx_init_firmware
 *	This routine initializes the firmware.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully initialized firmware
 *	QLA_ERROR   - Failed to initialize firmware
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
static uint8_t
qla4xxx_init_firmware(scsi_qla_host_t *ha)
{
	uint8_t  status = QLA_ERROR;

	ENTER("qla4xxx_init_firmware");

	ql4_printk(KERN_INFO, ha, "Initializing firmware..\n");
	if (qla4xxx_initialize_fw_cb(ha) == QLA_ERROR) {
		DEBUG2(printk("scsi%d: %s: Failed to initialize "
			      "firmware control block\n", ha->host_no, __func__));
		LEAVE("qla4xxx_init_firmware");
		return(status);
	}

	if (!qla4xxx_fw_ready(ha)) {
		LEAVE("qla4xxx_init_firmware");
		return(status);
	}

	set_bit(AF_ONLINE, &ha->flags);

	status = qla4xxx_get_firmware_status(ha);
	LEAVE("qla4xxx_init_firmware");
	return(status);
}


#if ENABLE_ISNS
/**************************************************************************
 * qla4xxx_is_discovered_target
 *	This routine locates a device handle given iSNS information.
 *	If device doesn't exist, returns NULL.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *      ip_addr - Pointer to IP address
 *      alias - Pointer to iSCSI alias
 *
 * Returns:
 *	Pointer to the corresponding internal device database structure
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
static inline uint8_t
qla4xxx_is_discovered_target(scsi_qla_host_t *ha,
			     uint8_t *ip_addr,
			     uint8_t *alias,
			     uint8_t *name_str)
{
	ISNS_DISCOVERED_TARGET *discovered_target = NULL;
	int i,j;

	for (i=0; i < ha->isns_num_discovered_targets; i++) {
		discovered_target = &ha->isns_disc_tgt_databasev[i];

		for (j = 0; j < discovered_target->NumPortals; j++) {
			if (memcmp(discovered_target->Portal[j].IPAddr, ip_addr,
				   MIN(sizeof(discovered_target->Portal[j].IPAddr),
				       sizeof(*ip_addr)) == 0) &&
			    memcmp(discovered_target->Alias, alias,
				   MIN(sizeof(discovered_target->Alias),
				       sizeof(*alias)) == 0) &&
			    memcmp(discovered_target->NameString, name_str,
				   MIN(sizeof(discovered_target->Alias),
				       sizeof(*name_str)) == 0)) {

				return(QLA_SUCCESS);
			}
		}
	}

	return(QLA_ERROR);
}
#endif

static ddb_entry_t *
qla4xxx_get_ddb_entry(scsi_qla_host_t *ha, uint32_t fw_ddb_index)
{
	DEV_DB_ENTRY    *fw_ddb_entry = NULL;
	dma_addr_t      fw_ddb_entry_dma;
	ddb_entry_t     *ddb_entry = NULL;
	uint32_t        device_state;


	ENTER(__func__);

	/* Make sure the dma buffer is valid */
	fw_ddb_entry = pci_alloc_consistent(ha->pdev, sizeof(*fw_ddb_entry),
					    &fw_ddb_entry_dma);
	if (fw_ddb_entry == NULL) {
		DEBUG2(printk("scsi%d: %s: Unable to allocate dma "
			      "buffer.\n", ha->host_no, __func__));
		LEAVE(__func__);
		return NULL;
	}

	/* Retrieve F/W's copy of ddb */
	if (qla4xxx_get_fwddb_entry(ha, fw_ddb_index, fw_ddb_entry,
				    fw_ddb_entry_dma, NULL, NULL, &device_state, NULL, NULL,
				    NULL) == QLA_ERROR) {
		DEBUG2(printk("scsi%d: %s: failed get_ddb_entry for "
			      "fw_ddb_index %d\n", ha->host_no, __func__, fw_ddb_index));

		pci_free_consistent(ha->pdev, sizeof(*fw_ddb_entry),
				    fw_ddb_entry, fw_ddb_entry_dma);
		LEAVE(__func__);
		return NULL;
	}

	/* Allocate Local DDB if not already allocated. */
	if (fw_ddb_index < MAX_DDB_ENTRIES) {
		ddb_entry = qla4xxx_lookup_ddb_by_fw_index(ha, fw_ddb_index);
		if (ddb_entry == NULL) {
			DEBUG2(printk("scsi%d: %s: DDB[%d] allocated\n",
				     ha->host_no, __func__, fw_ddb_index));
			ddb_entry = qla4xxx_alloc_ddb(ha, fw_ddb_index);
		}
	} else {
		DEBUG2(printk("scsi%d: %s: ERROR: fw_ddb_index %d out of range\n",
			      ha->host_no, __func__, fw_ddb_index));
 	}

	/* Free  F/W's copy of ddb */
	if (fw_ddb_entry)
		pci_free_consistent(ha->pdev, sizeof(*fw_ddb_entry),
				    fw_ddb_entry, fw_ddb_entry_dma);

	LEAVE(__func__);

	return ddb_entry;
}

/**************************************************************************
 * qla4xxx_update_ddb_entry
 *	This routine updates the driver's internal device database entry
 *	with information retrieved from the firmware's device database
 *	entry for the specified device.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *	ddb_entry - Pointer to device database entry
 *
 * Output:
 *	ddb_entry - Structure filled in.
 *
 * Remarks:
 *	The ddb_entry->fw_ddb_index field must be initialized prior to
 *	calling this routine
 *
 * Returns:
 *	QLA_SUCCESS - Successfully update ddb_entry
 *	QLA_ERROR   - Failed to update ddb_entry
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_update_ddb_entry(scsi_qla_host_t *ha, ddb_entry_t *ddb_entry,
			 uint32_t fw_ddb_index)
{
	DEV_DB_ENTRY *fw_ddb_entry = NULL;
	dma_addr_t   fw_ddb_entry_dma;
	uint8_t      status = QLA_ERROR;

	ENTER(__func__);

	if (ddb_entry == NULL) {
		DEBUG2(printk("scsi%d: %s: ddb_entry is NULL\n",
			      ha->host_no, __func__));
		goto exit_update_ddb;
	}

	/* Make sure the dma buffer is valid */
	fw_ddb_entry = pci_alloc_consistent(ha->pdev, sizeof(*fw_ddb_entry),
					    &fw_ddb_entry_dma);
	if (fw_ddb_entry == NULL) {
		DEBUG2(printk("scsi%d: %s: Unable to allocate dma "
			      "buffer.\n", ha->host_no, __func__));

		goto exit_update_ddb;
	}

	if (qla4xxx_get_fwddb_entry(ha, fw_ddb_index, fw_ddb_entry,
				    fw_ddb_entry_dma, NULL, NULL,
				    &ddb_entry->fw_ddb_device_state,
				    NULL, &ddb_entry->tcp_source_port_num,
				    &ddb_entry->connection_id) == QLA_ERROR) {
		DEBUG2(printk("scsi%d: %s: failed get_ddb_entry for "
			      "fw_ddb_index %d\n", ha->host_no, __func__, fw_ddb_index));

		goto exit_update_ddb;
	}

	status = QLA_SUCCESS;

	ddb_entry->options = le16_to_cpu(fw_ddb_entry->options);
	ddb_entry->target_session_id = le16_to_cpu(fw_ddb_entry->TSID);
	ddb_entry->task_mgmt_timeout =
	le16_to_cpu(fw_ddb_entry->taskMngmntTimeout);
	ddb_entry->CmdSn = 0;
	ddb_entry->exe_throttle =
	le16_to_cpu(fw_ddb_entry->exeThrottle);
	ddb_entry->default_relogin_timeout =
	le16_to_cpu(fw_ddb_entry->taskMngmntTimeout);
	ddb_entry->default_time2wait = le16_to_cpu(fw_ddb_entry->DefaultTime2Wait);

	memcpy(&ddb_entry->iscsi_name[0], &fw_ddb_entry->iscsiName[0],
	       MIN(sizeof(ddb_entry->iscsi_name),
		   sizeof(fw_ddb_entry->iscsiName)));
	memcpy(&ddb_entry->remote_ip_addr[0], &fw_ddb_entry->RemoteIPAddr[0],
	       MIN(sizeof(ddb_entry->remote_ip_addr),
		   sizeof(fw_ddb_entry->RemoteIPAddr)));
	memcpy(&ddb_entry->ipv6_local_ip_addr[0], &fw_ddb_entry->IPv6LocalIPAddress[0],
	       MIN(sizeof(ddb_entry->ipv6_local_ip_addr),
		   sizeof(fw_ddb_entry->IPv6LocalIPAddress)));

#if ENABLE_ISNS
	if (qla4xxx_is_discovered_target(ha, fw_ddb_entry->RemoteIPAddr,
					 fw_ddb_entry->iSCSIAlias,
					 fw_ddb_entry->iscsiName) ==
	    QLA_SUCCESS) {
		set_bit(DF_ISNS_DISCOVERED, &ddb_entry->flags);
	}
#endif

	DEBUG2(printk("scsi%d: %s: DDB[%d] - State= %x status= %d.\n",
		      ha->host_no, __func__, fw_ddb_index,
		      ddb_entry->fw_ddb_device_state, status);)

	exit_update_ddb:
	if (fw_ddb_entry)
		pci_free_consistent(ha->pdev, sizeof(*fw_ddb_entry),
				    fw_ddb_entry, fw_ddb_entry_dma);

	LEAVE(__func__);
	return(status);
}

uint8_t
qla4xxx_reindex_ddb(scsi_qla_host_t *ha,
		    uint32_t old_fw_ddb_index,
		    uint32_t new_fw_ddb_index)
{
	uint8_t status = QLA_ERROR;
	ddb_entry_t *ddb_entry = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(ha->host->host_lock, flags);
	ddb_entry = qla4xxx_lookup_ddb_by_fw_index(ha, new_fw_ddb_index);
	if (ddb_entry != NULL) {
		if (atomic_read(&ddb_entry->state) != DEV_STATE_DEAD) {
			QL4PRINT(QLP2, printk(
				"scsi%d: %s: ERROR: new DDB index [%d] "
				"already present.\n", ha->host_no,
				__func__, new_fw_ddb_index));
			goto exit_reindex_ddb;
		}
	} else if (new_fw_ddb_index >= MAX_DDB_ENTRIES) {
		QL4PRINT(QLP2, printk("scsi%d: %s: ERROR: new DDB index [%d] "
				      "out of range\n", ha->host_no, __func__,
				      new_fw_ddb_index));
		goto exit_reindex_ddb;
	}

	ddb_entry = qla4xxx_lookup_ddb_by_fw_index(ha, old_fw_ddb_index);
	if (ddb_entry == NULL) {
		QL4PRINT(QLP2, printk("scsi%d: %s: ERROR: old DDB index [%d] "
				      "not present\n", ha->host_no, __func__,
				      old_fw_ddb_index));
		goto exit_reindex_ddb;
	}

	QL4PRINT(QLP7, printk("scsi%d: %s: remap DDB index [%d] "
			      "to DDB index [%d]\n",
			      ha->host_no, __func__,
			      old_fw_ddb_index, new_fw_ddb_index));

	ha->fw_ddb_index_map[old_fw_ddb_index] = (ddb_entry_t *) INVALID_ENTRY;
	ddb_entry->fw_ddb_index = new_fw_ddb_index;
	ha->fw_ddb_index_map[new_fw_ddb_index] = ddb_entry;
	
	status = QLA_SUCCESS;

exit_reindex_ddb:
	spin_unlock_irqrestore(ha->host->host_lock, flags);
	return (status);
}

static  void
qla4xxx_configure_fcports(scsi_qla_host_t *ha)
{
	fc_port_t       *fcport;

	list_for_each_entry(fcport, &ha->fcports, list) {
		qla4xxx_update_fcport(ha, fcport);
	}
}

static fc_port_t *
qla4xxx_find_or_alloc_fcport(scsi_qla_host_t *ha, ddb_entry_t *ddb_entry)
{
	fc_port_t       *fcport;
	int     found;

	ENTER(__func__);
	/* Check for matching device in port list. */
	found = 0;
	fcport = NULL;
	list_for_each_entry(fcport, &ha->fcports, list) {
		if (fcport->ddbptr == ddb_entry) {
			fcport->flags &= ~(FCF_PERSISTENT_BOUND);
			found++;
			break;
		}
	}

	if (!found) {
		/* Allocate a new replacement fcport. */
		fcport = qla4xxx_alloc_fcport(ha, GFP_ATOMIC);
		if (fcport != NULL) {
			/* New device, add to fcports list. */
			list_add_tail(&fcport->list, &ha->fcports);
			fcport->ddbptr = ddb_entry;
		}
	}

	LEAVE(__func__);

	return(fcport);
}


/**************************************************************************
 * qla4xxx_alloc_ddb
 *	This routine allocates a ddb_entry, ititializes some values, and
 *	inserts it into the ddb list.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *      fw_ddb_index - Firmware's device database index
 *
 * Returns:
 *	Pointer to internal device database structure
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
ddb_entry_t *
qla4xxx_alloc_ddb(scsi_qla_host_t *ha, uint32_t fw_ddb_index)
{
	ddb_entry_t *ddb_entry;

	QL4PRINT(QLP12, printk("scsi%d: %s: fw_ddb_index [%d]\n", ha->host_no,
			       __func__, fw_ddb_index));

	ddb_entry = (ddb_entry_t *) kmalloc(sizeof(*ddb_entry), GFP_ATOMIC);
	if (ddb_entry == NULL) {
		DEBUG2(printk("scsi%d: %s: Unable to allocate memory "
			      "to add fw_ddb_index [%d]\n", ha->host_no, __func__,
			      fw_ddb_index));
	} else {
		memset(ddb_entry, 0, sizeof(*ddb_entry));
		ddb_entry->fw_ddb_index = fw_ddb_index;
		atomic_set(&ddb_entry->port_down_timer,
			   ha->port_down_retry_count);
		atomic_set(&ddb_entry->retry_relogin_timer, INVALID_ENTRY);
		atomic_set(&ddb_entry->relogin_timer, 0);
		atomic_set(&ddb_entry->relogin_retry_count, 0);
		atomic_set(&ddb_entry->state, DEV_STATE_ONLINE);
		list_add_tail(&ddb_entry->list_entry, &ha->ddb_list);
		ha->fw_ddb_index_map[fw_ddb_index] = ddb_entry;
		ha->tot_ddbs++;
                ddb_entry->fcport = qla4xxx_find_or_alloc_fcport(ha, ddb_entry);
	}
	return(ddb_entry);
}

void
qla4xxx_add_ddb_to_list(scsi_qla_host_t *ha,
			uint32_t fw_ddb_index,
			uint32_t *next_fw_ddb_index)
{
	uint32_t        ddb_state;
	uint32_t        conn_err, err_code;
	ddb_entry_t *ddb_entry;

	/* First, let's see if a device exists here */
	if (qla4xxx_get_fwddb_entry(ha, fw_ddb_index, NULL, 0, NULL,
		next_fw_ddb_index, &ddb_state,
		&conn_err, NULL, NULL) == QLA_ERROR) {
		DEBUG2(printk("scsi%d: %s: get_ddb_entry, "
			"fw_ddb_index %d failed", ha->host_no, __func__,
			fw_ddb_index));
		return;
	}

	if (next_fw_ddb_index) {
		DEBUG2(printk("scsi%d: %s: Getting DDB[%d] ddbstate=0x%x, "
			"next_fw_ddb_index=%d.\n",
			ha->host_no, __func__, fw_ddb_index, ddb_state,
			*next_fw_ddb_index));
	} else {
		DEBUG2(printk("scsi%d: %s: Getting DDB[%d] ddbstate=0x%x\n",
			ha->host_no, __func__, fw_ddb_index, ddb_state));
	}

	/*
	 * Add DDB to internal our ddb list.
	 * --------------------------------
	 */
	ddb_entry = qla4xxx_get_ddb_entry(ha, fw_ddb_index);
	if (ddb_entry == NULL) {
		DEBUG2(printk("scsi%d: %s: Unable to "
			"allocate memory for device at "
			"fw_ddb_index %d\n", ha->host_no, __func__,
			fw_ddb_index));
		return;
	}

	/* Fill in the device structure */
	if (qla4xxx_update_ddb_entry(ha, ddb_entry,
		fw_ddb_index) == QLA_ERROR) {
		qla4xxx_free_ddb(ha, ddb_entry);

		DEBUG2(printk("scsi%d: %s: "
			"update_ddb_entry failed for fw_ddb_index"
			"%d.\n",
			ha->host_no, __func__, fw_ddb_index));
		return;
	}

	/* if fw_ddb with session active state found,
	 * add to ddb_list */
	DEBUG2(printk("scsi%d: %s: DDB[%d] "
		"added to list\n", ha->host_no, __func__,
		fw_ddb_index));

	/*
	 * Issue relogin, if necessary
	 * ---------------------------
	 */
	if (ddb_state == DDB_DS_SESSION_FAILED ||
		ddb_state == DDB_DS_NO_CONNECTION_ACTIVE) {

		atomic_set(&ddb_entry->state, DEV_STATE_DEAD);

		/* Try and login to device */
		DEBUG2(printk("scsi%d: %s: Login to DDB[%d]\n",
			ha->host_no, __func__, fw_ddb_index));
		err_code = ((conn_err & 0x00ff0000) >>16);
		if (err_code == 0x1c || err_code == 0x06) {
			DEBUG2(printk("scsi%d: %s send target completed"
				" or access denied failure\n",
				ha->host_no, __func__));
		} else {
			qla4xxx_set_ddb_entry(ha, fw_ddb_index, NULL, 0);
		}
	}

}

/**************************************************************************
 * qla4xxx_build_ddb_list
 *	This routine searches for all valid firmware ddb entries and builds
 *	an internal ddb list.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Remarks:
 *	Ddbs that are considered valid are those with a device state of
 *	SESSION_ACTIVE.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully built internal ddb list, if targets available
 *	QLA_ERROR   - Error on a mailbox command
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
static uint8_t
qla4xxx_build_ddb_list(scsi_qla_host_t *ha)
{
	uint8_t         status = QLA_SUCCESS;
	uint32_t        fw_ddb_index = 0;
	uint32_t        next_fw_ddb_index = 0;

	ENTER("qla4xxx_build_ddb_list");

	ql4_printk(KERN_INFO, ha, "Initializing DDBs ...\n");
	for (fw_ddb_index = 0; fw_ddb_index < MAX_DDB_ENTRIES;
             fw_ddb_index = next_fw_ddb_index) {

		qla4xxx_add_ddb_to_list(ha, fw_ddb_index, &next_fw_ddb_index);

		/* We know we've reached the last device when
		 * next_fw_ddb_index is 0 */
		if (next_fw_ddb_index == 0)
			break;
	}

	ql4_printk(KERN_INFO, ha, "DDB list done..\n");
	LEAVE("qla4xxx_build_ddb_list");

	return(status);
}

/**************************************************************************
 * qla4xxx_devices_ready
 *	This routine waits up to ql4xdiscoverywait seconds
 *	F/W database during driver load time.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully (re)built internal ddb list
 *	QLA_ERROR   - Failed to (re)build internal ddb list
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
static uint8_t
qla4xxx_devices_ready(scsi_qla_host_t *ha)
{
	uint8_t         halt_wait;
	unsigned long   discovery_wtime;
	ddb_entry_t     *ddb_entry;
	uint32_t fw_ddb_index;
	uint32_t        next_fw_ddb_index;
	uint32_t fw_ddb_device_state;
	uint32_t        conn_err;
	uint32_t        err_code;

	discovery_wtime = jiffies + (ql4xdiscoverywait * HZ);

	DEBUG(printk("Waiting (%d) for devices ...\n", ql4xdiscoverywait));
	QL4PRINT(QLP7, printk("scsi%d: Waiting (%d) for devices ...\n",
			      ha->host_no, ql4xdiscoverywait));

	do {
		/* poll for AEN
		 * ------------ */
		qla4xxx_get_firmware_state(ha);
		if (test_and_clear_bit(DPC_AEN, &ha->dpc_flags)) {
			/* Set time-between-relogin timer */
			qla4xxx_process_aen(ha, RELOGIN_DDB_CHANGED_AENS);
		}

		/* if no relogins active or needed, halt discvery wait */
		halt_wait = 1;

		/* scan for relogins
		 * ----------------- */
		for (fw_ddb_index = 0;
		    fw_ddb_index < MAX_DDB_ENTRIES;
		    fw_ddb_index = next_fw_ddb_index) {
			if (qla4xxx_get_fwddb_entry(ha,
						    fw_ddb_index,
						    NULL, 0, NULL,
						    &next_fw_ddb_index,
						    &fw_ddb_device_state,
						    &conn_err,
						    NULL, NULL) == QLA_ERROR) {
				QL4PRINT(QLP7,
					 printk("scsi%d: %s: ERROR retrieving "
						"get_ddb_entry for fw_ddb_index %d \n",
						ha->host_no, __func__, fw_ddb_index));
				return(QLA_ERROR);
			}

			
			if (fw_ddb_device_state == DDB_DS_LOGIN_IN_PROCESS) {
				QL4PRINT(QLP7,
					 printk("scsi%d: %s: get_ddb_entry, "
						"fw_ddb_index %d state=0x%x conn_err=0x%x\n",
						ha->host_no, __func__, fw_ddb_index,
						fw_ddb_device_state, conn_err));
				halt_wait = 0;
			}

			if ((fw_ddb_device_state == DDB_DS_SESSION_FAILED) ||
			    (fw_ddb_device_state == DDB_DS_NO_CONNECTION_ACTIVE)) {
				QL4PRINT(QLP7,
					 printk("scsi%d: %s: get_ddb_entry, "
						"fw_ddb_index %d state=0x%x conn_err=0x%x\n",
						ha->host_no, __func__, fw_ddb_index,
						fw_ddb_device_state, conn_err));

				/* Don't want to do a relogin if connection error is 0x1c */
				err_code = ((conn_err & 0x00ff0000) >>16);
				if (err_code == 0x1c || err_code == 0x06) {
					DEBUG2(printk("scsi%d: %s send target completed"
					       " or access denied failure\n",
					       ha->host_no, __func__);)
				}
				else {
					/* We either have a device that is in
					 * the process of relogging in or a
					 * device that is waiting to be
					 * relogged in */
					halt_wait = 0;

					ddb_entry = qla4xxx_lookup_ddb_by_fw_index(ha, fw_ddb_index);
					if (ddb_entry == NULL) {
						QL4PRINT(QLP7,
							 printk("scsi%d: %s: ERROR retrieving "
								"ddb_entry for fw_ddb_index %d \n",
								ha->host_no, __func__, fw_ddb_index));
						return(QLA_ERROR);
					}

					if (ddb_entry->dev_scan_wait_to_start_relogin != 0 &&
					    time_after_eq(jiffies, ddb_entry->dev_scan_wait_to_start_relogin)) {
						ddb_entry->dev_scan_wait_to_start_relogin = 0;
						qla4xxx_set_ddb_entry(ha, fw_ddb_index, NULL, 0);
					}
				}
			}

			/* We know we've reached the last device when
			 * next_fw_ddb_index is 0 */
			if (next_fw_ddb_index == 0)
				break;
		}

		if (halt_wait) {
			DEBUG2( printk("scsi%d: %s: Delay halted.  Devices Ready.\n",
				       ha->host_no, __func__));
			return(QLA_SUCCESS);
		}

		/* delay */
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(HZ * 2);
	} while (!time_after_eq(jiffies, discovery_wtime));

	DEBUG2( printk("scsi%d: %s: Delay complete.\n",
		       ha->host_no, __func__));

	if (halt_wait == 0) {
		DEBUG2( printk("scsi%d: %s: all devices not logged in\n",
			       ha->host_no, __func__));
	}

	//DEBUG2(qla4xxx_get_conn_event_log(ha);)

	return(QLA_SUCCESS);
}

static uint8_t
qla4xxx_initialize_ddb_list(scsi_qla_host_t *ha)
{
	uint16_t fw_ddb_index;
	uint8_t status = QLA_SUCCESS;
	unsigned long   wtime;

	ENTER("qla4xxx_initialize_ddb_list");

	/* free the ddb list if is not empty */
	if (!list_empty(&ha->ddb_list))
		qla4xxx_free_ddb_list(ha);

	/* Initialize internal DDB list and mappingss */
	qla4xxx_init_tgt_map(ha);

	for (fw_ddb_index = 0; fw_ddb_index < MAX_DDB_ENTRIES; fw_ddb_index++)
		ha->fw_ddb_index_map[fw_ddb_index] =
		(ddb_entry_t *) INVALID_ENTRY;

	ha->tot_ddbs = 0;

	/* Flush the 0x8014 AEN from the firmware as a result of
 	 * Auto connect. We are basically doing get_firmware_ddb()
	 * to determine whether we need to log back in or not.
	 *  Trying to do a set ddb before we have processed 0x8014
	 *  will result in another set_ddb() for the same ddb. In other
	 *  words there will be stale entries in the aen_q.	
	 */
	wtime = jiffies + (2 * HZ);
	do {
		if (qla4xxx_get_firmware_state(ha) == QLA_SUCCESS) {
			/* error */
			if (ha->firmware_state & (BIT_2|BIT_0)) {
				return(QLA_ERROR);
			}
		}

		if (test_and_clear_bit(DPC_AEN, &ha->dpc_flags)) {
			qla4xxx_process_aen(ha, FLUSH_DDB_CHANGED_AENS);
		}
		/* delay */
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(HZ * 1);

	} while (!time_after_eq(jiffies,wtime));


	/*
	 * First perform device discovery for active fw ddb indexes
	 * and build the ddb list.  Initiate relogins for non-active ddbs.
	 *
	 * Retry initializing adapter for cases of fw_ddb_index mismatch
	 * and in cases of memory alloc failure.
	 */
	if ((status = qla4xxx_build_ddb_list(ha)) == QLA_ERROR)
		return(status);

	/* Wait for non-active targets to become active */
	qla4xxx_devices_ready(ha);


	/*
	 * Here we map a SCSI target to a fw_ddb_index and discover all
	 * possible luns.
	 */
	qla4xxx_configure_fcports(ha);
	qla4xxx_config_os(ha);

	/*
	 * Targets can come online after the inital discovery, so processing
	 * the aens here will catch them.
	 */
	if (test_and_clear_bit(DPC_AEN, &ha->dpc_flags))
		qla4xxx_process_aen(ha, PROCESS_ALL_AENS);
#if 0
	if (!ha->tot_ddbs)
		status = QLA_ERROR;
#endif

	LEAVE("qla4xxx_initialize_ddb_list");

	return(status);
}

/**************************************************************************
 * qla4xxx_reinitialize_ddb_list
 *	This routine obtains device information from the F/W database after
 *	firmware or adapter resets.  The device table is preserved.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully updated internal ddb list
 *	QLA_ERROR   - Failed to update internal ddb list
 *
* Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_reinitialize_ddb_list(scsi_qla_host_t *ha)
{
	uint8_t         status = QLA_SUCCESS;
	ddb_entry_t     *ddb_entry, *detemp;

	ENTER("qla4xxx_reinitialize_ddb_list");

	/* Update the device information for all devices. */
	list_for_each_entry_safe(ddb_entry, detemp, &ha->ddb_list, list_entry) {
		if (qla4xxx_update_ddb_entry(ha, ddb_entry,
					 ddb_entry->fw_ddb_index) != QLA_SUCCESS) {
			QL4PRINT(QLP2, printk("scsi%d: %s: update_ddb_entry failed\n",
				ha->host_no, __func__));
			status = QLA_ERROR;
			break;
		}
		if (ddb_entry->fw_ddb_device_state == DDB_DS_SESSION_ACTIVE) {
			atomic_set(&ddb_entry->state, DEV_STATE_ONLINE);
			qla4xxx_update_fcport(ha, ddb_entry->fcport);

			QL4PRINT(QLP3|QLP7,
				 printk("scsi%d:%d:%d: %s: index [%d] marked ONLINE\n",
                                        ha->host_no, ddb_entry->bus, ddb_entry->target,
                                        __func__, ddb_entry->fw_ddb_index));
		} else {
			/* Since this routine is invoked after a reset,
			 * we want to make sure the NO_RELOGIN flag is cleared */
			clear_bit(DF_NO_RELOGIN, &ddb_entry->flags);
			atomic_set(&ddb_entry->state, DEV_STATE_DEAD);

			if (ddb_entry->fw_ddb_device_state == DDB_DS_SESSION_FAILED ||
                            ddb_entry->fw_ddb_device_state == DDB_DS_NO_CONNECTION_ACTIVE) {
				DEBUG2(printk("scsi%d: %s: Login to DDB[%d]\n",
					ha->host_no, __func__, ddb_entry->fw_ddb_index));
				qla4xxx_set_ddb_entry(ha, ddb_entry->fw_ddb_index, NULL, 0);
			}
		}
	}

	LEAVE("qla4xxx_reinitialize_ddb_list");
	return(status);
}

/**************************************************************************
 * qla4xxx_relogin_device
 *	This routine does a session relogin with the specified device.
 *	The ddb entry must be assigned prior to making this call.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *	ddb_entry - Pointer to device database entry
 *
 * Returns:
 *    QLA_SUCCESS = Successfully relogged in device
 *    QLA_ERROR   = Failed to relogin device
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_relogin_device(scsi_qla_host_t *ha, ddb_entry_t *ddb_entry)
{
	uint16_t relogin_timer;

	ENTER("qla4xxx_relogin_device");

	relogin_timer = MAX(ddb_entry->default_relogin_timeout, RELOGIN_TOV);
	atomic_set(&ddb_entry->relogin_timer, relogin_timer);

	QL4PRINT(QLP2, printk(KERN_WARNING
			      "scsi%d:%d:%d: Relogin index [%d]. TOV=%d\n", ha->host_no,
			      ddb_entry->bus, ddb_entry->target, ddb_entry->fw_ddb_index,
			      relogin_timer));

	qla4xxx_set_ddb_entry(ha, ddb_entry->fw_ddb_index, NULL, 0);

	LEAVE("qla4xxx_relogin_device");

	return(QLA_SUCCESS);
}

int qla4xxx_lock_drvr_wait(struct scsi_qla_host *a)
{
	#define QL4_LOCK_DRVR_WAIT	3
	#define QL4_LOCK_DRVR_SLEEP	1

	int drvr_wait = QL4_LOCK_DRVR_WAIT;
	while (drvr_wait) {
		if(QL4XXX_LOCK_DRVR(a) == 0) {
			ssleep(QL4_LOCK_DRVR_SLEEP);
			if (drvr_wait) {
				DEBUG2(printk("scsi%d: %s: Waiting for "
					      "Global Init Semaphore(%d)...\n",
					      a->host_no,__func__, drvr_wait));
			}
			drvr_wait -= QL4_LOCK_DRVR_SLEEP;
		} else {
			DEBUG2(printk("scsi%d: %s: Global Init Semaphore "
				      "acquired.\n",a->host_no,__func__));
			return QLA_SUCCESS;
		}
	}
	return QLA_ERROR;
}

/**************************************************************************
 * qla4xxx_start_firmware
 *	This routine performs the neccessary steps to start the firmware for
 *	the QLA4010 adapter.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully started QLA4xxx firmware
 *	QLA_ERROR   - Failed to start QLA4xxx firmware
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
static uint8_t
qla4xxx_start_firmware(scsi_qla_host_t *ha)
{
	unsigned long flags = 0;
	uint32_t mbox_status;
	uint8_t status = QLA_ERROR;
	uint8_t soft_reset = 1;
	uint8_t boot_firmware = 0;
	uint8_t config_chip = 0;

	ENTER("qla4xxx_start_firmware");

	if (qla4xxx_poll_and_ack_scsi_reset(ha) == QLA_SUCCESS) {
		LEAVE(__func__);
		return QLA_ERROR;
	}

	ql4xxx_set_mac_number(ha);

	(void)qla4xxx_lock_drvr_wait(ha);

	spin_lock_irqsave(&ha->hardware_lock, flags);

	/* Enable scsi function, so that if another function
	 * issues a soft reset or a fatal error occurs before
	 * initialization completes, we'll get notified.
	 * NOTE: THIS STEP IS NOT DOCUMENTED IN THE SPEC
	 */
	if (IS_QLA4032(ha)) {
		DEBUG2(printk("scsi%d: %s: Enable function - 4032\n", ha->host_no, __func__);)
		WRT_REG_DWORD(&ha->reg->u2.isp4022.p0.u3.fcn_spec_ctrl, SET_RMASK(BIT_5));
	} else if (IS_QLA4022(ha)) {
		DEBUG2(printk("scsi%d: %s: Enable function - 4022\n", ha->host_no, __func__);)
		WRT_REG_DWORD(ISP_PORT_CTRL(ha), SET_RMASK(PCR_ENABLE_FUNCTION));
	}
	PCI_POSTING(&ha->reg->ctrl_status);
	DEBUG2(printk("scsi%d: %s: port_ctrl   = 0x%08X\n", ha->host_no, __func__,
    				RD_REG_DWORD(ISP_PORT_CTRL(ha)));)
	DEBUG2(printk("scsi%d: %s: port_status = 0x%08X\n", ha->host_no, __func__,
    				RD_REG_DWORD(ISP_PORT_STATUS(ha)));)
	DEBUG2(printk("scsi%d: %s: ctrl_status = 0x%08X\n", ha->host_no, __func__,
    				RD_REG_DWORD(&ha->reg->ctrl_status));)

	/* Is Hardware already initialized? */
	if ((RD_REG_DWORD(ISP_PORT_CTRL(ha)) & PCR_CONFIG_COMPLETE) != 0) {
		QL4PRINT(QLP7, printk("scsi%d: %s: Hardware has already been "
				      "initialized\n", ha->host_no, __func__));

		/* Receive firmware boot acknowledgement */
		mbox_status = RD_REG_DWORD(&ha->reg->mailbox[0]);

		DEBUG2(printk("scsi%d: %s: H/W Config complete - mbox[0]= 0x%x\n",
			      ha->host_no,  __func__, mbox_status);)

		/* Is firmware already booted? */
		if (mbox_status == 0) {
			/* F/W not running, must be config by net driver */
			config_chip = 1;
			soft_reset = 0;
		} else {
			WRT_REG_DWORD(&ha->reg->ctrl_status, SET_RMASK(CSR_SCSI_PROCESSOR_INTR));
			PCI_POSTING(&ha->reg->ctrl_status);
			spin_unlock_irqrestore(&ha->hardware_lock, flags);
			if (qla4xxx_get_firmware_state(ha) == QLA_SUCCESS) {
				DEBUG2(printk("scsi%d: %s: "
					      "Get firmware state "
					      "-- state = 0x%x\n",
					      ha->host_no, __func__,ha->firmware_state));
				/* F/W is running */
				if ((ha->firmware_state & FW_STATE_CONFIG_WAIT)) {
					DEBUG2(printk("scsi%d: %s: "
						      "Firmware in known state "
						      "-- config and boot, state = 0x%x\n",
						      ha->host_no, __func__,ha->firmware_state));
					config_chip = 1;
					soft_reset = 0;
				}
			} else {
				DEBUG2(printk("scsi%d: %s: "
					      "Firmware in unknown state "
					      "-- resetting, state = 0x%x\n",
					      ha->host_no, __func__,ha->firmware_state));
			}
			spin_lock_irqsave(&ha->hardware_lock, flags);
		}
	} else {
		QL4PRINT(QLP7, printk("scsi%d: %s: H/W initialization hasn't been started "
				      " - resetting\n", ha->host_no, __func__));
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	QL4PRINT(QLP7, printk("scsi%d: %s: Flags soft_rest=%d, config= %d\n"
			      , ha->host_no, __func__,soft_reset,config_chip));
	if (soft_reset) {
		QL4PRINT(QLP7, printk("scsi%d: %s: Issue Soft Reset\n",
				      ha->host_no, __func__));

		status = qla4xxx_soft_reset(ha);
		if (status == QLA_ERROR) {
			QL4PRINT(QLP3|QLP7, printk("scsi%d: %s: Soft Reset "
						   "failed!\n", ha->host_no, __func__));
			QL4XXX_UNLOCK_DRVR(ha);
			LEAVE(__func__);
			return QLA_ERROR;
		}
		
		config_chip = 1;

		if (qla4xxx_poll_and_ack_scsi_reset(ha) == QLA_SUCCESS) {
			LEAVE(__func__);
			return QLA_ERROR;
		}

		/* Reset clears the semaphore, so aquire again */
		(void)qla4xxx_lock_drvr_wait(ha);
	}

	if (config_chip) {
		EXTERNAL_HW_CONFIG_REG  extHwConfig;

		QL4PRINT(QLP7, printk("scsi%d: %s: Get EEProm parameters "
				      "\n", ha->host_no, __func__));

		QL4XXX_LOCK_FLASH(ha);
		QL4XXX_LOCK_NVRAM(ha);

		/* Get EEPRom Parameters  */
		ql4_printk(KERN_INFO, ha, "Configuring NVRAM ...\n");
		if (qla4xxx_is_NVRAM_configuration_valid(ha) == QLA_SUCCESS) {

			spin_lock_irqsave(&ha->hardware_lock, flags);
			extHwConfig.AsUINT32 = RD_NVRAM_WORD(ha,
				EEPROM_EXT_HW_CONF_OFFSET());
			spin_unlock_irqrestore(&ha->hardware_lock, flags);
		}
		else {
			/*
			 * QLogic adapters should always have a valid NVRAM.
			 * If not valid, do not load.
			 */
			printk(KERN_INFO "scsi%d: %s: EEProm checksum "
			       "invalid.  Please update your EEPROM\n",
			       ha->host_no, __func__);

			/* set defaults */
			if (IS_QLA4010(ha))
				extHwConfig.AsUINT32 = 0x1912;
			else
				extHwConfig.AsUINT32 = 0x0023;

		}

		QL4PRINT(QLP7, printk("scsi%d: %s: Setting extHwConfig "
				      "to 0xFFFF%04x\n", ha->host_no, __func__,
				      extHwConfig.AsUINT32));

		spin_lock_irqsave(&ha->hardware_lock, flags);
		WRT_REG_DWORD(ISP_EXT_HW_CONF(ha),
			      ((0xFFFF << 16) | extHwConfig.AsUINT32));
		PCI_POSTING(ISP_EXT_HW_CONF(ha));
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		QL4XXX_UNLOCK_NVRAM(ha);
		QL4XXX_UNLOCK_FLASH(ha);

		status = QLA_SUCCESS;

		boot_firmware = 1;
	}

	if (boot_firmware) {
		uint32_t        max_wait_time;

		/*
		 * Start firmware from flash ROM
		 *
		 * WORKAROUND: Stuff a non-constant value that the firmware can
		 * use as a seed for a random number generator in MB7 prior to
		 * setting BOOT_ENABLE.  Fixes problem where the TCP
		 * connections use the same TCP ports after each reboot,
		 * causing some connections to not get re-established.
		 */
		QL4PRINT(QLP7, printk("scsi%d: %s: Start firmware from flash "
				      "ROM\n", ha->host_no, __func__));

		spin_lock_irqsave(&ha->hardware_lock, flags);
		WRT_REG_DWORD(&ha->reg->mailbox[7], jiffies);
		if (!IS_QLA4010(ha)) {
			/*
			 * Firmware must be informed that the driver supports
			 * ACB firmware features while starting firmware.
			 * If the firmware also supports these features it will
			 * be indicated in the IFCB offset 0x3A (acb_version).
			 */
			WRT_REG_DWORD(&ha->reg->mailbox[6], ACB_SUPPORTED);	
			WRT_REG_DWORD(&ha->reg->u1.isp4022.nvram,
				      SET_RMASK(NVR_WRITE_ENABLE));
		}

		WRT_REG_DWORD(&ha->reg->ctrl_status,
			      SET_RMASK(CSR_BOOT_ENABLE));
		PCI_POSTING(&ha->reg->ctrl_status);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		/* Wait for firmware to come UP. */
		max_wait_time = FIRMWARE_UP_TOV * 4;
		do {
			uint32_t ctrl_status;

			spin_lock_irqsave(&ha->hardware_lock, flags);
			ctrl_status = RD_REG_DWORD(&ha->reg->ctrl_status);
			mbox_status = RD_REG_DWORD(&ha->reg->mailbox[0]);
			spin_unlock_irqrestore(&ha->hardware_lock, flags);

			if (ctrl_status & SET_RMASK(CSR_SCSI_PROCESSOR_INTR))
				break;
			if (mbox_status == MBOX_STS_COMMAND_COMPLETE)
				break;

			DEBUG2(printk("scsi%d: %s: Waiting for "
				      "boot firmware to complete... ctrl_sts=0x%x, "
				      "remaining=%d\n", ha->host_no, __func__,
				      ctrl_status, max_wait_time));

			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(HZ/4);
		} while ((max_wait_time--));

		if (mbox_status == MBOX_STS_COMMAND_COMPLETE) {
			QL4PRINT(QLP7, printk("scsi%d: %s: Firmware has "
					      "started\n", ha->host_no, __func__));

			spin_lock_irqsave(&ha->hardware_lock, flags);
			WRT_REG_DWORD(&ha->reg->ctrl_status,
				      SET_RMASK(CSR_SCSI_PROCESSOR_INTR));
			PCI_POSTING(&ha->reg->ctrl_status);
			spin_unlock_irqrestore(&ha->hardware_lock, flags);

			status = QLA_SUCCESS;
		} else {
			QL4PRINT(QLP2, printk("scsi%d: %s: Boot firmware failed "
					      "-  mbox status 0x%x\n",
					      ha->host_no, __func__, mbox_status));

			status = QLA_ERROR;
		}
	}
	QL4XXX_UNLOCK_DRVR(ha);

	if (status == QLA_SUCCESS) {
		status = qla4xxx_get_fw_version(ha);
	}

	if (status == QLA_SUCCESS) {
		if (test_and_clear_bit(AF_GET_CRASH_RECORD, &ha->flags))
			qla4xxx_get_crash_record(ha);
	} else {
		QL4PRINT(QLP7, printk("scsi%d: %s: Firmware has NOT started\n",
				      ha->host_no, __func__));

		qla4xxx_dump_registers(QLP7, ha);
	}

	LEAVE("qla4xxx_start_firmware");
	return status;
}

static void
qla4x00_pci_config(scsi_qla_host_t *ha)
{
	uint16_t        w, mwi;

	ql4_printk(KERN_INFO, ha, "Configuring PCI space...\n");

	pci_set_master(ha->pdev);
	mwi = 0;
	if (pci_set_mwi(ha->pdev))
		mwi = PCI_COMMAND_INVALIDATE;

	/*
	 * We want to respect framework's setting of PCI configuration space
	 * command register and also want to make sure that all bits of
	 * interest to us are properly set in command register.
	 */
	pci_read_config_word(ha->pdev, PCI_COMMAND, &w);
	w |= mwi | (PCI_COMMAND_PARITY | PCI_COMMAND_SERR);
	w &= ~PCI_COMMAND_INTX_DISABLE;
	pci_write_config_word(ha->pdev, PCI_COMMAND, w);
}

/**************************************************************************
 * qla4xxx_initialize_adapter
 *	This routine parforms all of the steps necessary to initialize the
 *	adapter.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *	renew_ddb_list - Indicates what to do with the adapter's ddb list
 *			after adapter recovery has completed.
 *			0=preserve ddb list, 1=destroy and rebuild ddb list
 *
 * Returns:
 *	QLA_SUCCESS - Successfully initialized adapter
 *	QLA_ERROR   - Failed to initialize adapter
 *
 * Context:
 *	Kernel context.
 **************************************************************************/

uint8_t
qla4xxx_initialize_adapter(scsi_qla_host_t *ha, uint8_t renew_ddb_list)
{
	uint8_t status = QLA_ERROR;
	uint8_t	found = 0;

	ENTER("qla4xxx_initialize_adapter");

	qla4x00_pci_config(ha);

	qla4xxx_disable_intrs(ha);
	/* Initialize the Host adapter request/response queues and firmware */
	if (qla4xxx_start_firmware(ha) == QLA_ERROR) {
		QL4PRINT(QLP2, printk(
				      "scsi%d: Failed to start QLA4xxx firmware\n",
				      ha->host_no));
		goto exit_init_hba;
	}
	if (qla4xxx_validate_mac_address(ha) == QLA_ERROR) {
		QL4PRINT(QLP2, printk(
				      "scsi%d: Failed to validate mac address\n",
				      ha->host_no));
		goto exit_init_hba;
	}
	if (qla4xxx_init_local_data(ha) == QLA_ERROR) {
		QL4PRINT(QLP2, printk(
				      "scsi%d: Failed to initialize local data\n",
				      ha->host_no));
		goto exit_init_hba;
	}

	status = qla4xxx_init_firmware(ha);
	if (status == QLA_ERROR) {
		QL4PRINT(QLP2, printk(
				      "scsi%d: Failed to initialize firmware\n",
				      ha->host_no));
		goto exit_init_hba;
	}

	if (ha->firmware_state & FW_STATE_CONFIGURING_IP) {
		QL4PRINT(QLP2, printk("%s(%d) FW is waiting to configure"
				      " an IP address : Skip building"
				      " the ddb_list and wait for DHCP lease"
				      " acquired aen to come in followed by 0x8014 aen"
				      " to trigger the tgt discovery process\n",
				      __func__, ha->host_no));
		/* NOTE: status = QLA_SUCCESS */
		goto exit_init_hba;
	}

	if (IS_IPv4_ENABLED(ha)) {
		if(IPv4AddrIsZero(ha->ip_address) ||
		   IPv4AddrIsZero(ha->subnet_mask)) {
		    if (IS_IPv6_ENABLED(ha)) {
			    /* Also check for IPv6 below ... */
		    } else {
			    QL4PRINT(QLP2, printk("scsi%d: %s: Null IP address "
						  "and/or Subnet Mask.  "
						  "Skip device discovery.\n",
						  ha->host_no, __func__));
			    /* NOTE: status = QLA_SUCCESS */
			    goto exit_init_hba;
		    }
		} else {
			found = 1;
		}

	}
	if (!found && IS_IPv6_ENABLED(ha)) {
		if (IPv6AddrIsZero(ha->ipv6_link_local_addr) &&
		    IPv6AddrIsZero(ha->ipv6_addr0) &&
		    IPv6AddrIsZero(ha->ipv6_addr1)) {
			QL4PRINT(QLP2, printk("scsi%d: %s: Null IPv6 address(es).  "
					      "Skip device discovery.\n",
					      ha->host_no, __func__));
			/* NOTE: status = QLA_SUCCESS */
			goto exit_init_hba;
		}
	}

#if ENABLE_ISNS
	/* If iSNS Enabled, wait for iSNS targets */
	if (test_bit(ISNS_FLAG_ISNS_ENABLED_IN_ISP, &ha->isns_flags)) {
		unsigned long wait_cnt = jiffies + ql4xdiscoverywait * HZ;

		QL4PRINT(QLP7,
			 printk("scsi%d: Delay up "
				"to %d seconds while iSNS targets "
				"are being discovered.\n",
				ha->host_no,
				ql4xdiscoverywait));

		while (!time_after_eq(jiffies,wait_cnt)) {
			if (test_bit(ISNS_FLAG_DEV_SCAN_DONE,
				     &ha->isns_flags))
				break;
			qla4xxx_get_firmware_state(ha);
			QL4PRINT(QLP7, printk("."));
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(1 * HZ);
		}

		if (!test_bit(ISNS_FLAG_ISNS_SRV_ENABLED,
			      &ha->isns_flags)) {
			QL4PRINT(QLP2, printk(
					      "scsi%d: iSNS service failed to start\n",
					      ha->host_no));
		}
		else {
			if (!ha->isns_num_discovered_targets) {
				QL4PRINT(QLP2, printk(
						      "scsi%d: Failed to "
						      "discover iSNS targets\n",
						      ha->host_no));
			}
		}
	}
#endif

	if (renew_ddb_list == PRESERVE_DDB_LIST) {
		/*
		 * We want to preserve lun states (i.e. suspended, etc.)
		 * for recovery initiated by the driver.  So just update
		 * the device states for the existing ddb_list
		 */
		qla4xxx_reinitialize_ddb_list(ha);
	}
	else if (renew_ddb_list == REBUILD_DDB_LIST) {
		/*
		 * We want to build the ddb_list from scratch during
		 * driver initialization and recovery initiated by the
		 * INT_HBA_RESET IOCTL.
		 */
		status = qla4xxx_initialize_ddb_list(ha);
		if (status == QLA_ERROR) {
			printk("scsi%d: %s Error occurred during build ddb list\n",
			       ha->host_no, __func__);
			goto exit_init_hba;
		}

	}

	if (!ha->tot_ddbs) {
			QL4PRINT(QLP2, printk("scsi%d:"
				" Failed to initialize devices or none present"
				" in Firmware device database\n",
					      ha->host_no));
	}

	exit_init_hba:
	LEAVE("qla4xxx_initialize_adapter");
	return(status);
}

/**************************************************************************
 * qla4xxx_find_propname
 *	Get property in database.
 *
 * Input:
 *	ha = adapter structure pointer.
 *      db = pointer to database
 *      propstr = pointer to dest array for string
 *	propname = name of property to search for.
 *	siz = size of property
 *
 * Returns:
 *	0 = no property
 *      size = index of property
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
static uint8_t
qla4xxx_find_propname(scsi_qla_host_t *ha,
		      char *propname, char *propstr,
		      char *db, int siz)
{
	char    *cp;

	/* find the specified string */
	if (db) {
		/* find the property name */
		if ((cp = strstr(db,propname)) != NULL) {
			while ((*cp)  && *cp != '=')
				cp++;
			if (*cp) {
				strncpy(propstr, cp, siz+1);
				propstr[siz+1] = '\0';
				QL4PRINT(QLP7, printk("scsi%d: %s: found "
						      "property = {%s}\n",
						      ha->host_no, __func__,
						      propstr));
				return(siz);	       /* match */
			}
		}
	}

	return(0);
}


/**************************************************************************
 * qla4xxx_get_prop_12chars
 *	Get a 6-byte property value for the specified property name by
 *      converting from the property string found in the configuration file.
 *      The resulting converted value is in big endian format (MSB at byte0).
 *
 * Input:
 *	ha = adapter state pointer.
 *	propname = property name pointer.
 *	propval  = pointer to location for the converted property val.
 *      db = pointer to database
 *
 * Returns:
 *	0 = value returned successfully.
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
int
qla4xxx_get_prop_12chars(scsi_qla_host_t *ha, uint8_t *propname,
			 uint8_t *propval, uint8_t *db)
{
	char            *propstr;
	int             i, k;
	int             rval;
	uint8_t         nval;
	uint8_t         *pchar;
	uint8_t         *ret_byte;
	uint8_t         *tmp_byte;
	uint8_t         *retval = (uint8_t*)propval;
	uint8_t         tmpval[6] = {0, 0, 0, 0, 0, 0};
	uint16_t        max_byte_cnt = 6;	  /* 12 chars = 6 bytes */
	uint16_t        max_strlen = 12;
	static char     buf[LINESIZE];

	rval = qla4xxx_find_propname(ha, propname, buf, db, max_strlen);

	propstr = &buf[0];
	if (*propstr == '=')
		propstr++;	     /* ignore equal sign */

	if (rval == 0) {
		return(1);
	}

	/* Convert string to numbers. */
	pchar = (uint8_t *)propstr;
	tmp_byte = (uint8_t *)tmpval;

	rval = 0;
	for (i = 0; i < max_strlen; i++) {
		/*
		 * Check for invalid character, two at a time,
		 * then convert them starting with first byte.
		 */

		if ((pchar[i] >= '0') && (pchar[i] <= '9')) {
			nval = pchar[i] - '0';
		}
		else if ((pchar[i] >= 'A') && (pchar[i] <= 'F')) {
			nval = pchar[i] - 'A' + 10;
		}
		else if ((pchar[i] >= 'a') && (pchar[i] <= 'f')) {
			nval = pchar[i] - 'a' + 10;
		}
		else {
			/* invalid character */
			rval = 1;
			break;
		}

		if (i & 0x01) {
			*tmp_byte = *tmp_byte | nval;
			tmp_byte++;
		}
		else {
			*tmp_byte = *tmp_byte | nval << 4;
		}
	}

	if (rval != 0) {
		/* Encountered invalid character. */
		return(rval);
	}

	/* Copy over the converted value. */
	ret_byte = retval;
	tmp_byte = tmpval;

	i = max_byte_cnt;
	k = 0;
	while (i--) {
		*ret_byte++ = *tmp_byte++;
	}

	/* big endian retval[0]; */
	return(QLA_SUCCESS);
}

/**************************************************************************
 * qla4xxx_add_device_dynamically
 *	This routine processes adds a device as a result of an 8014h AEN.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *      fw_ddb_index - Firmware's device database index
 *
 * Returns:
 *	None
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
static void
qla4xxx_add_device_dynamically(scsi_qla_host_t *ha, uint32_t fw_ddb_index)
{
	ddb_entry_t *ddb_entry;

	ENTER("qla4xxx_add_device_dynamically");

	/* First allocate a device structure */
	ddb_entry = qla4xxx_get_ddb_entry(ha, fw_ddb_index);
	if (ddb_entry == NULL) {
		QL4PRINT(QLP2, printk(KERN_WARNING
				      "scsi%d: Unable to allocate memory to add fw_ddb_index "
				      "%d\n", ha->host_no, fw_ddb_index));
	} else if (qla4xxx_update_ddb_entry(ha, ddb_entry, fw_ddb_index) ==
		 QLA_ERROR) {
		qla4xxx_free_ddb(ha, ddb_entry);
		QL4PRINT(QLP2, printk(KERN_WARNING
				      "scsi%d: failed to add new device at index [%d]\n"
				      "Unable to retrieve fw ddb entry\n", ha->host_no,
				      fw_ddb_index));
	} else {
		/* New device. Let's add it to the database */
		DEBUG2(printk("scsi%d: %s: new device at index [%d]\n",
			      ha->host_no, __func__, fw_ddb_index));

		qla4xxx_update_fcport(ha, ddb_entry->fcport);
			qla4xxx_config_os(ha);

	}

	LEAVE("qla4xxx_add_device_dynamically");
}


/**************************************************************************
 * qla4xxx_process_ddb_changed
 *	This routine processes a Decive Database Changed AEN Event.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *      fw_ddb_index - Firmware's device database index
 *      state - Device state
 *
 * Returns:
 *	QLA_SUCCESS - Successfully processed ddb_changed aen
 *	QLA_ERROR   - Failed to process ddb_changed aen
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_process_ddb_changed(scsi_qla_host_t *ha, uint32_t fw_ddb_index,
			    uint32_t state)
{
	ddb_entry_t *ddb_entry;
	uint32_t    old_fw_ddb_device_state;

	ENTER(__func__);

	/* check for out of range index */
	if (fw_ddb_index >= MAX_DDB_ENTRIES) {
		QL4PRINT(QLP2, printk("scsi%d: %s: device index [%d] out of "
				      "range\n", ha->host_no, __func__, fw_ddb_index));

		LEAVE(__func__);
		return(QLA_ERROR);
	}

	/* Get the corresponging ddb entry */
	ddb_entry = qla4xxx_lookup_ddb_by_fw_index(ha, fw_ddb_index);

	/* Device does not currently exist in our database. */
	if (ddb_entry == NULL) {
		qla4xxx_add_device_dynamically(ha, fw_ddb_index);
		LEAVE(__func__);
		return(QLA_SUCCESS);
	}

	/* Device already exists in our database. */
	old_fw_ddb_device_state = ddb_entry->fw_ddb_device_state;
	DEBUG2(printk("scsi%d: %s DDB - old state= 0x%x, "
		      "new state=0x%x for index [%d]\n",
		      ha->host_no, __func__, ddb_entry->fw_ddb_device_state,
		      state,
		      fw_ddb_index));

	if ((old_fw_ddb_device_state == state) && (state == DDB_DS_SESSION_ACTIVE)) {
		/* Do nothing, state not changed. */
		LEAVE(__func__);
		return(QLA_SUCCESS);
	}

	if ((old_fw_ddb_device_state == DDB_DS_UNASSIGNED) &&
	    (state != DDB_DS_UNASSIGNED)) {
		/* Update the ddb info, as a new ddb can be added to the
		 * same ddb index as a previously deleted one. */
		(void)qla4xxx_update_ddb_entry(ha, ddb_entry, fw_ddb_index);

		clear_bit(DF_RELOGIN, &ddb_entry->flags);
		clear_bit(DF_NO_RELOGIN, &ddb_entry->flags);
	} else {
		ddb_entry->fw_ddb_device_state = state;
	}

	/* Device is back online. */
	if (ddb_entry->fw_ddb_device_state == DDB_DS_SESSION_ACTIVE) {
		atomic_set(&ddb_entry->port_down_timer,
			   ha->port_down_retry_count);
		atomic_set(&ddb_entry->state, DEV_STATE_ONLINE);
		atomic_set(&ddb_entry->relogin_retry_count, 0);
		atomic_set(&ddb_entry->relogin_timer, 0);
		clear_bit(DF_RELOGIN, &ddb_entry->flags);
		clear_bit(DF_NO_RELOGIN, &ddb_entry->flags);
		qla4xxx_update_fcport(ha, ddb_entry->fcport);
		(void)qla4xxx_update_ddb_entry(ha, ddb_entry, fw_ddb_index);

/* XXX FIXUP LUN_READY/SUSPEND code -- dg */
		/*
		 * Change the lun state to READY in case the lun TIMEOUT before
		 * the device came back.
		 */
		if (ddb_entry->fcport->vis_ha) {
			int t, l;
			unsigned long cpu_flags;
			os_lun_t *lq;
			scsi_qla_host_t *os_ha;

			os_ha = ddb_entry->fcport->vis_ha;
			for (t = 0; t < MAX_TARGETS; t++) {
				for (l = 0; l < MAX_LUNS; l++) {
					if (!(lq = GET_LU_Q(os_ha, t, l)))
						continue;

					spin_lock_irqsave(&lq->lun_lock,
							  cpu_flags);
					lq->lun_state = LS_LUN_READY;
					ddb_entry->fcport->vis_ha = NULL;
					spin_unlock_irqrestore(&lq->lun_lock,
							       cpu_flags);

				}
			}
		}

	} else {		
		/* Device went away, try to relogin. */
		/* Mark device missing */
		if (atomic_read(&ddb_entry->state) == DEV_STATE_ONLINE)
			qla4xxx_mark_device_missing(ha, ddb_entry);

		/*
		 * Relogin if device state changed to a not active state.
		 * However, do not relogin if this aen is a result of an IOCTL
		 * logout (DF_NO_RELOGIN).
		 */
		if (ddb_entry->fw_ddb_device_state == DDB_DS_SESSION_FAILED &&
		    (!test_bit(DF_RELOGIN, &ddb_entry->flags)) &&
		    (!test_bit(DF_NO_RELOGIN, &ddb_entry->flags)) &&
		    (!test_bit(DF_ISNS_DISCOVERED, &ddb_entry->flags))) {

			/*
			 * This triggers a relogin.  After the relogin_timer
			 * expires, the relogin gets scheduled.  We must wait a
			 * minimum amount of time since receiving an 0x8014 AEN
			 * with failed device_state or a logout response before
			 * we can issue another relogin.
			 */
			/* Firmware pads this timeout: (time2wait +1).
			 * Driver retry to login should be longer than F/W.
			 * Otherwise F/W will fail
			 * set_ddb() mbx cmd with 0x4005 since it still
			 * counting down its time2wait.
			 */
			atomic_set(&ddb_entry->relogin_timer, 0);
			atomic_set(&ddb_entry->retry_relogin_timer,
				   ddb_entry->default_time2wait + 4);
			QL4PRINT(QLP2, printk("scsi%d:%d:%d: index [%d] "
					      "initate relogin after %d seconds\n", ha->host_no,
					      ddb_entry->bus, ddb_entry->target,
					      ddb_entry->fw_ddb_index,
					      ddb_entry->default_time2wait));
		} else {
			QL4PRINT(QLP2, printk("scsi%d:%d:%d: index [%d] "
					      "relogin not initated, State=%d, "
					      "ddb_entry->flags=0x%lx\n", ha->host_no,
					      ddb_entry->bus, ddb_entry->target,
					      ddb_entry->fw_ddb_index,
					      ddb_entry->fw_ddb_device_state,
					      ddb_entry->flags));
		}
	}

	LEAVE(__func__);

	return(QLA_SUCCESS);
}

void
qla4xxx_flush_all_srbs(scsi_qla_host_t *ha, ddb_entry_t *ddb_entry,
		       os_lun_t *lun_entry)
{
	int         i;
	unsigned long flags;
	srb_t       *srb;

	if (lun_entry == NULL || ddb_entry == NULL)
		return;

	/* free active commands */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	if (lun_entry->out_count != 0) {
		for (i = 1; i < MAX_SRBS; i++) {
			srb = ha->active_srb_array[i];
			if (!srb)
				continue;

			QL4PRINT(QLP3, printk("scsi%d:%d:%d:%d: %s: found srb "
					      "%p in active_q\n", ha->host_no, ddb_entry->bus,
					      ddb_entry->target, lun_entry->lun, __func__, srb));

			if (srb->lun_queue != lun_entry)
				continue;

			del_from_active_array(ha, i);
			srb->cmd->result = DID_NO_CONNECT << 16;
			add_to_done_srb_q(ha,srb);
		}
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	/* Send all srbs back to OS */
	if (!list_empty(&ha->done_srb_q)) {
		qla4xxx_done(ha);
	}
}

/*
 * Overrides for Emacs so that we almost follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-indent-level: 2
 * c-brace-imaginary-offset: 0
 * c-brace-offset: -2
 * c-argdecl-indent: 2
 * c-label-offset: -2
 * c-continued-statement-offset: 2
 * c-continued-brace-offset: 0
 * indent-tabs-mode: nil
 * tab-width: 8
 * End:
 */

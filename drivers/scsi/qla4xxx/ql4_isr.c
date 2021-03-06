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
 *      qla4xxx_suspend_lun
 *      qla4xxx_status_entry
 *      qla4xxx_process_response_queue
 *	qla4xxx_isr_decode_mailbox
 *      qla4xxx_interrupt_service_routine
 *      qla4xxx_intr_handler
 *	qla4xxx_ok2relogin
 *	qla4xxx_process_aen
 ****************************************************************************/

#include "ql4_def.h"

#include <scsi/scsi_tcq.h>

static void
qla4xxx_process_completed_request(struct scsi_qla_host *ha, uint32_t index);

/*
 * String messages for various state values (used for print statements)
 *---------------------------------------------------------------------------*/
const char *host_sts_msg[] = HOST_STS_TBL();


/**************************************************************************
 * qla4xxx_suspend_lun
 *	This routine suspends the lun queue for the specified lun and places
 *	all requests for this lun onto the retry queue for a specified
 *	amount of time.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *	srb - Pointer to SCSI Request Block
 *	lun_entry - lun structure
 *	time - Number of seconds to suspend queue
 *	retries - Max retry count for this lun
 *  	delay = non-zero, if lun should be delayed rather than suspended
 *
 * Remarks:
 *	The suspend queue algorithm is provided as a method to keep commands
 *	within the driver while a device is attempting to recover from certain
 *	failures.  By keeping the commands within the driver, it prevents the
 *	kernel's retries from being exhausted so quickly and minimizes failures
 *	at the application level.
 *
 * Returns:
 *	None
 *
 * Context:
 *	Interrupt context.
 **************************************************************************/
void
__qla4xxx_suspend_lun(scsi_qla_host_t *ha,
		    srb_t *srb,
		    os_lun_t *lun_entry,
		    uint16_t time,
		    uint16_t retries, int delay)
{
	unsigned long flags;
	uint8_t status = 0 ;

	if (lun_entry == NULL)
		return;

	spin_lock_irqsave(&lun_entry->lun_lock, flags);

	if (lun_entry->lun_state == LS_LUN_READY ||
	    lun_entry->lun_state == LS_LUN_RETRY) {
		if (lun_entry->lun_state == LS_LUN_READY) {
			lun_entry->max_retry_count = retries;
			lun_entry->retry_count = 0;
		}

		/* Set the suspend time */
		atomic_set(&lun_entry->suspend_timer, time);
		DEBUG2( printk("scsi%d: %s lun %d retry count = %d\n",
				ha->host_no, __func__, lun_entry->lun,
				lun_entry->retry_count));

		/* now suspend the lun */
		lun_entry->lun_state = LS_LUN_SUSPENDED;
		if (delay) {
			set_bit(LF_LUN_DELAYED, &lun_entry->flags);
		}
		status = 1;

	}

	if( srb )
		__add_to_retry_srb_q(ha,srb);

	spin_unlock_irqrestore(&lun_entry->lun_lock, flags);
}

/**************************************************************************
 * qla4xxx_check_and_copy_sense
 *	This routine processes Status IOCBs
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *      sts_entry - Pointer to status entry structure
 *	srb - Pointer to internal SCSI request block structure.
 *
 * Returns:
 *	QLA_SUCCESS - We want the caller to complete the command
 *	QLA_ERROR - We do not want the caller to complete the request
 *
 * Context:
 *	Interrupt context.
 **************************************************************************/
static uint8_t
qla4xxx_check_and_copy_sense(scsi_qla_host_t *ha, STATUS_ENTRY *sts_entry, srb_t *srb)
{
	struct scsi_cmnd *cmd = srb->cmd;
	scsi_qla_host_t *osha;
	uint16_t        sensebytecnt;
	fc_port_t *fcport;
	os_lun_t *lun_entry = srb->lun_queue;
	osha = (scsi_qla_host_t *) cmd->device->host->hostdata;

	memset(cmd->sense_buffer, 0, sizeof(cmd->sense_buffer));

	sensebytecnt = le16_to_cpu(sts_entry->senseDataByteCnt);
	if (sensebytecnt == 0)
		return(QLA_SUCCESS);

	/* always perform the copy to cmd fields */
	CMD_ACTUAL_SNSLEN(cmd) = sensebytecnt;

	memcpy(cmd->sense_buffer,
	       sts_entry->senseData,
	       MIN(sensebytecnt, sizeof(cmd->sense_buffer)));

	if ((srb->flags & (SRB_IOCTL_CMD | SRB_TAPE)))
		return(QLA_SUCCESS);

	/* check for vaild sense data */
	if ((sts_entry->senseData[0] & 0x70) != 0x70)
		return(QLA_SUCCESS);

	DEBUG2(printk("scsi%d:%d:%d:%d: %s: "
			"sense key = "
			"%x, ASC/ASCQ = %02x/%02x\n",
			ha->host_no, cmd->device->channel,
			cmd->device->id, cmd->device->lun, __func__,
			sts_entry->senseData[2] & 0x0f,
			sts_entry->senseData[12],
			sts_entry->senseData[13]));

	srb->flags |= SRB_GOT_SENSE;

	switch (sts_entry->senseData[2] & 0x0f) {
	case NOT_READY:
	case HARDWARE_ERROR:
		fcport = lun_entry->fclun->fcport;

		/*
		 * Suspend the lun only for hard disk device type.
		 */
		if (test_bit(AF_INIT_DONE, &ha->flags) &&
		    lun_entry != NULL &&
		    lun_entry->lun_state != LS_LUN_TIMEOUT) {
			/*
			 * If target is in process of being ready then suspend
			 * lun for 6 secs and retry all the commands.
			 */
			if (sts_entry->senseData[12] == 0x4 &&
			    sts_entry->senseData[13] == 0x1) {
				/* To give the lun more time to become ready,
				 * suspend lun then retry command */
				qla4xxx_suspend_lun(osha, srb, lun_entry,
						    SUSPEND_SECONDS,
						    SUSPEND_RETRIES);
				return(QLA_ERROR);
			}
			else if (sts_entry->senseData[12] == 0x8 &&
				 sts_entry->senseData[13] == 0x0) {
				/* To give the lun more time to become ready,
				 * suspend lun then retry command */
				qla4xxx_suspend_lun(osha, srb, lun_entry,
						    SUSPEND_SECONDS,
						    (ha->port_down_retry_count /
						     SUSPEND_SECONDS)) ;
				return(QLA_ERROR);
			}
		}
		break;
	}

	return(QLA_SUCCESS);
}

static inline void
qla4xxx_adjust_queue_depth(scsi_qla_host_t *ha, srb_t *srb, struct scsi_cmnd *cmd)
{
	struct scsi_device *isdev;
	fc_port_t *fcport;
	
	fcport = srb->fclun->fcport;
	fcport->last_queue_full = jiffies;
	shost_for_each_device(isdev, cmd->device->host) {
		if (isdev->channel != cmd->device->channel ||
		    isdev->id != cmd->device->id)
			continue;
		
		if (!scsi_track_queue_full(isdev, isdev->queue_depth - 1))
			continue;
		
		DEBUG2(ql4_printk(KERN_INFO, ha,
			"scsi%d:%d:%d:%d: Queue depth "
			"adjusted-down to %d.\n", ha->host_no,
			isdev->channel, isdev->id, isdev->lun,
			isdev->queue_depth));
	}
}

/**************************************************************************
 * qla4xxx_status_entry
 *	This routine processes Status IOCBs
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *      sts_entry - Pointer to status entry structure.
 *
 * Returns:
 *	None
 *
 * Context:
 *	Interrupt context.
 **************************************************************************/
static void
qla4xxx_status_entry(scsi_qla_host_t *ha, STATUS_ENTRY *sts_entry)
{
	srb_t *srb;
	uint8_t scsi_status;

	/* Fast path completion. */
	if (sts_entry->completionStatus == SCS_COMPLETE &&
	    sts_entry->scsiStatus == 0) {
		qla4xxx_process_completed_request(ha,
		    le32_to_cpu(sts_entry->handle));
		return;
	}

	srb = del_from_active_array(ha, le32_to_cpu(sts_entry->handle));
	if (srb) {
		struct scsi_cmnd *cmd = srb->cmd;
		uint32_t residual = le32_to_cpu(sts_entry->residualByteCnt);
		ddb_entry_t *ddb_entry;

		if (cmd == NULL) {
			DEBUG2(printk("scsi%d: %s: Command already returned back to OS "
				      "pkt->handle=%d srb=%p srb->state:%d\n",
				      ha->host_no, __func__, sts_entry->handle, srb, srb->state));
			printk(KERN_WARNING
			       "Command is NULL: already returned to OS (srb=%p)\n", srb);
			return;
		}

		if (srb->lun_queue == NULL) {
			DEBUG2(printk("scsi%d: %s: Status Entry invalid lun pointer.\n",
				      ha->host_no, __func__));
		}

		if (srb->fclun == NULL) {
			printk("%s srb_flags=0x%x no fclun\n", __func__,
					srb->flags);
			cmd->result = DID_NO_CONNECT << 16;
	
			set_bit(DPC_RESET_HA, &ha->dpc_flags);
			if (ha->dpc_wait && !ha->dpc_active)
				up(ha->dpc_wait);
			return;
		}
		if (srb->fclun->fcport == NULL) {
			printk("%s srb_flags=0x%x no fcport\n", __func__,
					srb->flags);
			cmd->result = DID_NO_CONNECT << 16;
	
			set_bit(DPC_RESET_HA, &ha->dpc_flags);
			if (ha->dpc_wait && !ha->dpc_active)
				up(ha->dpc_wait);
			return;
		}

		ddb_entry = srb->fclun->fcport->ddbptr;
		if (ddb_entry == NULL) {
			cmd->result = DID_NO_CONNECT << 16;
	
			set_bit(DPC_RESET_HA, &ha->dpc_flags);
			if (ha->dpc_wait && !ha->dpc_active)
				up(ha->dpc_wait);
			return;
		}
		/*
		 * Translate ISP error to a Linux SCSI error
		 */
		scsi_status = sts_entry->scsiStatus;

		switch (sts_entry->completionStatus) {
		case SCS_COMPLETE:
		case SCS_QUEUE_FULL:

			if (scsi_status == 0) {
				cmd->result = DID_OK << 16;
				break;
			}

			if (sts_entry->iscsiFlags & ISCSI_FLAG_RESIDUAL_OVER) {
				cmd->result = DID_ERROR << 16;
				break;
			}

			if (sts_entry->iscsiFlags & ISCSI_FLAG_RESIDUAL_UNDER) {
				cmd->resid = residual;
				/* Retry the cmd if target reports underrun */
				/* Handle mid-layer underflow */
				if (!(scsi_status & STATUS_MASK) &&
				    ((unsigned)(cmd->request_bufflen - residual) <
				     cmd->underflow)) {
					ql4_printk(KERN_INFO, ha,
					    "scsi%d:%d:%d:%d: Mid-layer underflow "
					    "detected (%x of %x bytes)...returning "
					    "error status.\n", ha->host_no,
					    cmd->device->channel, cmd->device->id,
					    cmd->device->lun, residual,
					    cmd->request_bufflen);

					cmd->result = DID_ERROR << 16;
					break;
				}
			}

			cmd->result = DID_OK << 16 | scsi_status;

			if (scsi_status == SAM_STAT_TASK_SET_FULL) {
				DEBUG2(printk("scsi%d:%d:%d:%d: QUEUE FULL detected "
                                              "compl=%02x, scsi=%02x, state=%02x, "
					      "iFlags=%02x, iResp=%02x\n",
					      ha->host_no, cmd->device->channel,
					      cmd->device->id, cmd->device->lun,
					      sts_entry->completionStatus,
					      sts_entry->scsiStatus,
					      sts_entry->state_flags,
					      sts_entry->iscsiFlags,
					      sts_entry->iscsiResponse));

				/* Adjust queue depth for all luns on the port */
				qla4xxx_adjust_queue_depth(ha, srb ,cmd);
				break;

			}

			if (scsi_status != SCSISTAT_CHECK_CONDITION)
				break;

			/* Check for sense errors */
			if (qla4xxx_check_and_copy_sense(ha, sts_entry ,srb) == QLA_ERROR) {
				return;	 /* DO NOT complete request, lun suspended */
			}

			break;

		case SCS_INCOMPLETE:
			/* Always set the status to DID_ERROR, since
			 * all conditions result in that status anyway */
			cmd->result = DID_ERROR << 16;
			break;

		case SCS_RESET_OCCURRED:
			DEBUG2(printk("scsi%d:%d:%d:%d: %s: "
						   "Device RESET occurred\n",
						   ha->host_no,
						   cmd->device->channel,
						   cmd->device->id,
						   cmd->device->lun,
						   __func__));

			if (srb->flags & (SRB_IOCTL_CMD | SRB_TAPE)) {
				cmd->result = DID_RESET << 16;
			}
			else {
				qla4xxx_device_suspend(ha, srb);
				return;
			}

			break;

		case SCS_ABORTED:
			QL4PRINT(QLP2|QLP3, printk("scsi%d:%d:%d:%d: %s: "
						   "Abort occurred\n",
						   ha->host_no,
						   cmd->device->channel,
						   cmd->device->id,
						   cmd->device->lun,
						   __func__));

			cmd->result = DID_ABORT << 16;
			break;

		case SCS_TIMEOUT:
			QL4PRINT(QLP2, printk("scsi%d:%d:%d:%d: cmd=%p pid=%ld"
					      "Timeout\n",
					      ha->host_no, cmd->device->channel,
					      cmd->device->id,
					      cmd->device->lun, cmd,
					      cmd->serial_number));

			/* F/W logout the connection when this occurs */
			cmd->result = DID_BUS_BUSY << 16;

			/*
			 * Mark device missing so that we won't continue to send
			 * I/O to this device.  We should get a ddb state change
			 * AEN soon.
			 */
			if ((atomic_read(&ddb_entry->state) == DEV_STATE_ONLINE))
				qla4xxx_set_device_state(ha, ddb_entry, DEV_STATE_MISSING);
			break;

		case SCS_DATA_UNDERRUN:
		case SCS_DATA_OVERRUN:
			if ((sts_entry->iscsiFlags & ISCSI_FLAG_RESIDUAL_OVER) ||
                            (sts_entry->completionStatus == SCS_DATA_OVERRUN)) {
				QL4PRINT(QLP2,
					 printk("scsi%d:%d:%d:%d: %s: "
						"Data overrun, "
						"residual = 0x%x\n",
						ha->host_no,
						cmd->device->channel,
						cmd->device->id,
						cmd->device->lun,
						__func__, residual));

				QL4PRINT(QLP10,
					 printk("scsi%d: %s: "
						"response packet data\n",
						ha->host_no, __func__));
				qla4xxx_dump_bytes(QLP10, sts_entry,
						   (sizeof(*sts_entry) *
						    sts_entry->hdr.entryCount));

				cmd->result = DID_ERROR << 16;
				break;
			}

			cmd->resid = residual;

			/*
			 * If there is scsi_status, it takes precedense over
			 * underflow condition.
			 */
			if (scsi_status != 0) {
				cmd->result = DID_OK << 16 | scsi_status;

				if (scsi_status == SAM_STAT_TASK_SET_FULL) {
					DEBUG2(printk("scsi%d:%d:%d:%d: QUEUE FULL detected "
							"compl=%02x, scsi=%02x, state=%02x, "
							"iFlags=%02x, iResp=%02x\n",
							ha->host_no, cmd->device->channel,
							cmd->device->id, cmd->device->lun,
							sts_entry->completionStatus,
							sts_entry->scsiStatus,
							sts_entry->state_flags,
							sts_entry->iscsiFlags,
							sts_entry->iscsiResponse));

					/* Adjust queue depth for all luns on the port */
					qla4xxx_adjust_queue_depth(ha, srb ,cmd);
					break;
				}

				if (scsi_status != SCSISTAT_CHECK_CONDITION)
					break;

				/* Check for sense errors */
				if (qla4xxx_check_and_copy_sense(ha, sts_entry ,srb) == QLA_ERROR) {
					return;	 /* DO NOT complete request, lun suspended */
				}
			}
			else {
				/*
				 * If RISC reports underrun and target does not
				 * report it then we must have a lost frame, so
				 * tell upper layer to retry it by reporting a
				 * bus busy.
				 */
				if ((sts_entry->iscsiFlags & ISCSI_FLAG_RESIDUAL_UNDER) == 0) {
					QL4PRINT(QLP2,
						 printk("scsi%d:%d:%d:%d: "
							"%s: Dropped frame(s) "
							"detected (%x of %x bytes)..."
							" retrying command.\n",
							ha->host_no,
							cmd->device->channel,
							cmd->device->id,
							cmd->device->lun,
							__func__,
							residual,
							cmd->request_bufflen));

					cmd->result = DID_BUS_BUSY << 16;
				}
				else if ((cmd->request_bufflen - residual) < cmd->underflow) {
					/*
					 * Handle mid-layer underflow???
					 *
					 * For kernels less than 2.4, the driver must
					 * return an error if an underflow is detected.
					 * For kernels equal-to and above 2.4, the
					 * mid-layer will appearantly handle the
					 * underflow by detecting the residual count --
					 * unfortunately, we do not see where this is
					 * actually being done.  In the interim, we
					 * will return DID_ERROR.
					 */
					QL4PRINT(QLP2,
						 printk("scsi%d:%d:%d:%d: %s: "
							"Mid-layer Data underrun, "
							"xferlen = 0x%x, "
							"residual = 0x%x\n",
							ha->host_no,
							cmd->device->channel,
							cmd->device->id,
							cmd->device->lun,
							__func__, cmd->request_bufflen,
							residual));

					cmd->result = DID_ERROR << 16;
					CMD_RESID_LEN(cmd) = residual;
				}
				else {
					cmd->result = DID_OK << 16;
				}
			}
			break;

		case SCS_DEVICE_LOGGED_OUT:
		case SCS_DEVICE_UNAVAILABLE:
			QL4PRINT(QLP2, printk("scsi%d:%d:%d:%d: cmd=%p pid=%ld %s,  req_q_cnt=%d, num_entries=%d\n",
					      ha->host_no, cmd->device->channel,
					      cmd->device->id,
					      cmd->device->lun,	cmd, cmd->serial_number,
					      (sts_entry->completionStatus == SCS_DEVICE_LOGGED_OUT)?
					      "DEVICE_LOGGED_OUT": "DEVICE_UNAVAILABLE",
				ha->req_q_count, srb->entry_count));
			/*
			 * Mark device missing so that we won't continue to
			 * send I/O to this device.  We should get a ddb
			 * state change AEN soon.
			 */

			if ((atomic_read(&ddb_entry->state) ==
			    	DEV_STATE_ONLINE))
				qla4xxx_set_device_state(ha, ddb_entry, DEV_STATE_MISSING);

			if ((srb->flags & (SRB_IOCTL_CMD | SRB_TAPE))) {
				cmd->result = DID_NO_CONNECT << 16;
			}
			else {
				cmd->result = DID_ERROR << 16;
				qla4xxx_device_suspend(ha, srb);
				return;	 /* DO NOT complete request */
			}

			break;

		case SCS_DMA_ERROR:
		case SCS_TRANSPORT_ERROR:
		case SCS_DATA_DIRECTION_ERROR:
		case SCS_DEVICE_CONFIG_CHANGED:
		default:
			cmd->result = DID_ERROR << 16;
			break;
		}

		/* fill in info for passthru command */
		CMD_SCSI_STATUS(cmd)    = sts_entry->scsiStatus;

		if (srb->flags & (SRB_IOCTL_CMD | SRB_TAPE)) {
			CMD_COMPL_STATUS(cmd)   = sts_entry->completionStatus;
			CMD_ISCSI_RESPONSE(cmd) = sts_entry->iscsiResponse;
			CMD_STATE_FLAGS(cmd)    = sts_entry->state_flags;
			CMD_HOST_STATUS(cmd)    = host_byte(cmd->result);
		}

		/* complete the request */
		srb->cc_stat   = sts_entry->completionStatus;
		if (host_byte(cmd->result) == DID_RESET ||
	    	    host_byte(cmd->result) == DID_BUS_BUSY ||
	    	    host_byte(cmd->result) == DID_ABORT ||
	    	    host_byte(cmd->result) == DID_ERROR) {
			    DEBUG2(printk("scsi%d:%d:%d:%d: %s: "
				"did_error=%d,  comp-scsi=0x%x-0x%x, "
				"pid=%ld\n",
				ha->host_no, cmd->device->channel, cmd->device->id,
				cmd->device->lun,
				__func__,
				host_byte(cmd->result),
				sts_entry->completionStatus,
				sts_entry->scsiStatus,
    				cmd->serial_number));
		}


		add_to_done_srb_q(ha, srb);
	}
	else {
		DEBUG2(printk(KERN_WARNING "scsi%d: %s: Status Entry invalid "
				"handle 0x%x, sp=%p. "
				"This cmd may have already been completed.\n",
				ha->host_no, __func__, le32_to_cpu(sts_entry->handle),
				srb));

		// QL4PRINT(QLP2, printk("scsi%d: %s: sts_entry 0x%p\n",
				      // ha->host_no, __func__, sts_entry));
		// qla4xxx_dump_bytes(QLP2, sts_entry, sizeof(*sts_entry));

		set_bit(DPC_RESET_HA, &ha->dpc_flags);
		if (ha->dpc_wait && !ha->dpc_active)
			up(ha->dpc_wait);
	}
}

static inline void
qla4xxx_ramp_up_queue_depth(scsi_qla_host_t *ha, srb_t *srb)
{
	fc_port_t *fcport;
	struct scsi_device *sdev, *isdev;

	sdev = srb->cmd->device;
	if (sdev->queue_depth >= ql4xmaxqdepth)
		return;

	fcport = srb->fclun->fcport;
	if (time_before(jiffies,
	    fcport->last_ramp_up + ql4xqfullrampup * HZ))
		return;
	if (time_before(jiffies,
		fcport->last_queue_full + ql4xqfullrampup * HZ))
		return;

	shost_for_each_device(isdev, sdev->host) {
		if (isdev->channel != sdev->channel || isdev->id != sdev->id)
			continue;

		if (ql4xmaxqdepth <= isdev->queue_depth)
			continue;

		if (isdev->ordered_tags)
			scsi_adjust_queue_depth(isdev, MSG_ORDERED_TAG,
			    isdev->queue_depth + 1);
		else
			scsi_adjust_queue_depth(isdev, MSG_SIMPLE_TAG,
			    isdev->queue_depth + 1);

		fcport->last_ramp_up = jiffies;

		DEBUG2(ql4_printk(KERN_INFO, ha,
		    "scsi%d:%d:%d:%d: Queue depth adjusted-up to %d.\n",
		    ha->host_no, isdev->channel, isdev->id, isdev->lun,
		    isdev->queue_depth));
	}
}

/**
 * qla4xxx_process_completed_request() - Process a Fast Post response.
 * @ha: SCSI driver HA context
 * @index: SRB index
 */
static void
qla4xxx_process_completed_request(struct scsi_qla_host *ha, uint32_t index)
{
	srb_t *srb;

	srb = del_from_active_array(ha, index);

	if (srb) {
		CMD_COMPL_STATUS(srb->cmd) = 0L;
		CMD_SCSI_STATUS(srb->cmd) = 0L;

		/* Save ISP completion status */
		srb->cmd->result = DID_OK << 16;
		qla4xxx_ramp_up_queue_depth(ha, srb);
		add_to_done_srb_q(ha, srb);
	}
	else {
		DEBUG2(printk(
		    "scsi%d: Invalid ISP SCSI completion handle = %d\n",
		      ha->host_no, index));
		 ql4_printk(KERN_WARNING, ha,
		    "Invalid ISP SCSI completion handle\n");

		set_bit(DPC_RESET_HA, &ha->dpc_flags);
	}
}

/**************************************************************************
 * qla4xxx_process_response_queue
 *	This routine handles the Response Queue Completion.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Output:
 *	None
 *
 * Remarks:
 *	hardware_lock locked upon entry
 *
 * Returns:
 *	QLA_SUCCESS - Successfully processed response queue
 *	QLA_ERROR   - Failed to process response queue
 *
 * Context:
 *	Interrupt context.
 **************************************************************************/
static uint32_t
qla4xxx_process_response_queue(scsi_qla_host_t *ha)
{
	uint32_t count = 0;
	srb_t    *srb = NULL;
	STATUS_ENTRY *sts_entry;

	/* Process all responses from response queue */
	while ((ha->response_in = (uint16_t)
	    le32_to_cpu(ha->shadow_regs->rsp_q_in)) != ha->response_out) {
		sts_entry = (STATUS_ENTRY *) ha->response_ptr;
		count++;

		/* Advance pointers for next entry */
		if (ha->response_out == (RESPONSE_QUEUE_DEPTH - 1)) {
			ha->response_out = 0;
			ha->response_ptr = ha->response_ring;
		}
		else {
			ha->response_out++;
			ha->response_ptr++;
		}

		/* process entry */
		switch (sts_entry->hdr.entryType) {
		case ET_STATUS:
			/* Common status - Single completion posted in single
			 * IOSB */
			qla4xxx_status_entry(ha, sts_entry);
			break;
#if ENABLE_ISNS
		case ET_PASSTHRU_STATUS:
			qla4xxx_isns_process_response(ha,
			    (PASSTHRU_STATUS_ENTRY *) sts_entry);
			break;
#endif
                case ET_ASYNC_PDU:
		{
			ASYNC_PDU_ENTRY *apdu;
			ISCSI_PDU_HEADER *iscsi_hdr;
			async_pdu_iocb_t *apdu_iocb;
 
			apdu = (ASYNC_PDU_ENTRY *)sts_entry;
			if (apdu->status != APDU_STATUS_OK)
				break;
 
			iscsi_hdr = (ISCSI_PDU_HEADER *)apdu->iscsi_pdu_header;
			if (iscsi_hdr->addl_hdr_seg_len ||
			    iscsi_hdr->data_seg_len[0] ||
			    iscsi_hdr->data_seg_len[1] ||
			    iscsi_hdr->data_seg_len[2]) {

				apdu_iocb = kmalloc(sizeof(*apdu_iocb),
						    GFP_ATOMIC);
				if (apdu_iocb) {
					memcpy(&apdu_iocb->iocb, apdu,
					       sizeof(ASYNC_PDU_ENTRY));
					list_add_tail(&apdu_iocb->list_entry,
						      &ha->async_iocb_list);
					set_bit(DPC_ASYNC_PDU, &ha->dpc_flags);
				} else {
					QL4PRINT(QLP2, printk("scsi%d: %s: "
						"Unable to alloc ASYNC PDU\n",
						ha->host_no, __func__));
				}
			}
			break;
		}
		case ET_STATUS_CONTINUATION:
			/* Just throw away the status continuation entries */
			QL4PRINT(QLP2,
				 printk("scsi%d: %s: Status Continuation entry "
					"- ignoring\n", ha->host_no, __func__));
			break;

		case ET_COMMAND:
			/* ISP device queue is full. Command not accepted by
			 * ISP.  Queue command for later */

			srb = del_from_active_array(ha, le32_to_cpu(sts_entry->handle));
			if (srb == NULL)
				goto exit_prq_invalid_handle;

			QL4PRINT(QLP2, printk("scsi%d: %s: FW device queue full, "
					      "srb %p\n",
					      ha->host_no, __func__, srb));

			/* Let's RETRY normally by sending it back with DID_BUS_BUSY */
			srb->cmd->result = DID_BUS_BUSY << 16;
			sp_put(ha, srb);
			break;

		case ET_CONTINUE:
			/* Just throw away the continuation entries */
			QL4PRINT(QLP2, printk("scsi%d: %s: Continuation entry - "
					      "ignoring\n",
					      ha->host_no, __func__));
			break;

		default:
			/* Invalid entry in response queue, reset RISC
			 * firmware */
			QL4PRINT(QLP2, printk("scsi%d: %s: Invalid entry %x "
					      "in response queue \n",
					      ha->host_no, __func__,
					      sts_entry->hdr.entryType));

			QL4PRINT(QLP10, printk("scsi%d: %s: Dumping Response Entry "
					       "%p:%x out %x in%x\n",
					       ha->host_no, __func__,
					       sts_entry,
					       le32_to_cpu(((QUEUE_ENTRY*)sts_entry)->
							   signature),
					       ha->response_out,
					       ha->response_in));

			qla4xxx_dump_bytes(QLP10, sts_entry,
					   sizeof(*sts_entry));
			goto exit_prq_error;
		}
	}

	if (ha->response_out == ha->response_in) {
		QL4PRINT(QLP5,
			 printk("scsi%d: %s: Response count %x out %x "
				"in %x, next %p:%x.  Finished!\n",
				ha->host_no, __func__, count,
				ha->response_out, ha->response_in,
				ha->request_ptr,
				ha->response_ptr->signature));
	}

	/* Done with responses, update the ISP
	 * For QLA4010, this also clears the interrupt.
	 */
	WRT_REG_DWORD(&ha->reg->rsp_q_out, ha->response_out);
	PCI_POSTING(&ha->reg->rsp_q_out);

	return(QLA_SUCCESS);

	exit_prq_invalid_handle:
	DEBUG2(printk("scsi%d: %s: Invalid handle(srb)=%p type=%x "
			      "IOCS=%x\n", ha->host_no, __func__,
			      srb, sts_entry->hdr.entryType,
			      sts_entry->completionStatus));

	exit_prq_error:
	WRT_REG_DWORD(&ha->reg->rsp_q_out, ha->response_out);
	PCI_POSTING(&ha->reg->rsp_q_out);

	set_bit(DPC_RESET_HA, &ha->dpc_flags);
	return(QLA_ERROR);
}

/**************************************************************************
 * qla4xxx_isr_decode_mailbox
 *	This routine decodes the mailbox status during the ISR.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *	mailbox_status - Mailbox status.
 *
 * Remarks:
 *      hardware_lock locked upon entry
 *
 * Returns:
 *	None.
 *
 * Context:
 *	Interrupt context.
 **************************************************************************/
static void
qla4xxx_isr_decode_mailbox(scsi_qla_host_t *ha, uint32_t  mbox_status)
{
	uint32_t   mbox_sts[MBOX_REG_COUNT];

	if ((mbox_status == MBOX_STS_BUSY) ||
	    (mbox_status == MBOX_STS_INTERMEDIATE_COMPLETION) ||
	    (mbox_status >>12 == MBOX_COMPLETION_STATUS)) {
		ha->mbox_status[0] = mbox_status;

		if (test_bit(AF_MBOX_COMMAND, &ha->flags)) {
			/*
			 * Copy all mailbox registers to a temporary
			 * location and set mailbox command done flag
			 */
			uint8_t i;

			for (i = 1; i < ha->mbox_status_count; i++) {
				ha->mbox_status[i] =
				    RD_REG_DWORD(&ha->reg->mailbox[i]);
			}

			QL4PRINT(QLP11,
				 printk("scsi%d: %s: mailbox cmd done!\n",
					ha->host_no, __func__));

			ha->f_end = jiffies;
			set_bit(AF_MBOX_COMMAND_DONE, &ha->flags);
			wake_up(&ha->mailbox_wait_queue);
		}
	}
	else if (mbox_status >> 12 == MBOX_ASYNC_EVENT_STATUS) {
		/*
		 * If EXT_DEF_ENABLE_AENS, capture and report all AENs to SDMAPI.
		 * If EXT_DEF_ENABLE_NO_AENS, only capture DATABASE_CHANGED AENs,
		 * as they need to be processed in the DPC, but do not report
		 * to the SDMAPI.
		 * ------------------------------------------------------*/
		if ((ha->aen_reg_mask == EXT_DEF_ENABLE_AENS) ||
		    (ha->aen_reg_mask == EXT_DEF_ENABLE_NO_AENS &&
		     mbox_status == MBOX_ASTS_DATABASE_CHANGED)) {
			int i;

			for (i = 0; i < MBOX_AEN_REG_COUNT; i++) {
				mbox_sts[i] = RD_REG_DWORD(&ha->reg->mailbox[i]);
			}
			qla4xxx_queue_aen(ha, &mbox_sts[0]);
		}


		/*
		 * Immediately process the non database_changed AENs.
		 * The database_changed AENs will get processed in the DPC.
		 * --------------------------------------------------------*/
		switch (mbox_status) {
		case MBOX_ASTS_SYSTEM_ERROR:
			/* Log Mailbox registers */
			QL4PRINT(QLP2,
				 printk(
					"scsi%d: AEN %04x, System Error, "
					"Dump Mailboxes\n",
					ha->host_no, mbox_status));
			__dump_mailbox_registers(QLP2, ha);
			if(ql4xdontresethba) {
				DEBUG2(printk("%s:Dont Reset HBA\n",__func__);)
			} else {
				set_bit(AF_GET_CRASH_RECORD, &ha->flags);
				set_bit(DPC_RESET_HA, &ha->dpc_flags);
			}
			break;

		case MBOX_ASTS_REQUEST_TRANSFER_ERROR:
		case MBOX_ASTS_RESPONSE_TRANSFER_ERROR:
		case MBOX_ASTS_NVRAM_INVALID:
		case MBOX_ASTS_IP_ADDRESS_CHANGED:   /* ACB Version 1 */
		case MBOX_ASTS_DHCP_LEASE_EXPIRED:   /* ACB Version 1 */
			QL4PRINT(QLP2,
				 printk("scsi%d: AEN %04x, "
					"ERROR Status, Reset HA\n",
					ha->host_no, mbox_status));

			set_bit(DPC_RESET_HA, &ha->dpc_flags);
			break;

		case MBOX_ASTS_LINK_UP:
			QL4PRINT(QLP2,
				 printk("scsi%d: AEN %04x "
					"Adapter LINK UP\n",
					ha->host_no, mbox_status));
			set_bit(AF_LINK_UP, &ha->flags);
			break;

		case MBOX_ASTS_LINK_DOWN:
			QL4PRINT(QLP2,
				 printk("scsi%d: AEN %04x "
					"Adapter LINK DOWN\n",
					ha->host_no, mbox_status));
			clear_bit(AF_LINK_UP, &ha->flags);
			break;

		case MBOX_ASTS_HEARTBEAT:
			QL4PRINT(QLP7,
				 printk("scsi%d: AEN %04x "
					"HEARTBEAT\n",
					ha->host_no, mbox_status));
			ha->seconds_since_last_heartbeat = 0;
			break;

		case MBOX_ASTS_DHCP_LEASE_ACQUIRED:	/* ACB Version 1 */
			QL4PRINT(QLP2, printk("scsi%d: AEN %04x "
					      "DHCP LEASE ACQUIRED\n",
					      ha->host_no, mbox_status));
			set_bit(DPC_GET_DHCP_IP_ADDR, &ha->dpc_flags);
			break;

		case MBOX_ASTS_SUBNET_STATE_CHANGE:
			QL4PRINT(QLP2,
				 printk(KERN_INFO "scsi%d: AEN %04x "
					"SUBNET STATE CHANGE\n",
					ha->host_no, mbox_status));
			clear_bit(AF_WAIT4DISABLE_ACB_COMPLETE, &ha->flags);
			break;

		case MBOX_ASTS_IP_ADDR_STATE_CHANGED:	/* ACB Version 2 */
		{
			uint32_t old_state = RD_REG_DWORD(&ha->reg->mailbox[2]);
			uint32_t new_state = RD_REG_DWORD(&ha->reg->mailbox[3]);

			QL4PRINT(QLP2,
				 printk(KERN_INFO "scsi%d: AEN %04x "
					"IP ADDR STATE CHANGED "
					"mb1=%04x, mb2=%04x, mb3=%04x, "
					"mb4=%04x, mb5=%04x\n",
					ha->host_no, mbox_status,
					RD_REG_DWORD(&ha->reg->mailbox[1]),
					RD_REG_DWORD(&ha->reg->mailbox[2]),
					RD_REG_DWORD(&ha->reg->mailbox[3]),
					RD_REG_DWORD(&ha->reg->mailbox[4]),
					RD_REG_DWORD(&ha->reg->mailbox[5])));

			if (old_state != ACB_STATE_VALID &&
			    new_state == ACB_STATE_VALID) {
				if (ha->reg->mailbox[4] == IP_ADDR_CFG_DHCP) {
					set_bit(DPC_GET_DHCP_IP_ADDR, &ha->dpc_flags);
				}
			} else if (old_state == ACB_STATE_VALID &&
				    new_state != ACB_STATE_VALID) {
				QL4PRINT(QLP2,
					 printk("scsi%d: AEN %04x  Reset HA\n",
						ha->host_no, mbox_status));
				set_bit(DPC_RESET_HA, &ha->dpc_flags);
			}
			break;
		}
		
		case MBOX_ASTS_PROTOCOL_STATISTIC_ALARM:
		case MBOX_ASTS_SCSI_COMMAND_PDU_REJECTED:	  /* Target mode only */
		case MBOX_ASTS_UNSOLICITED_PDU_RECEIVED:	  /* connection mode only */
		case MBOX_ASTS_DUPLICATE_IP:
		case MBOX_ASTS_ARP_COMPLETE:
		case MBOX_ASTS_RESPONSE_QUEUE_FULL:
		case MBOX_ASTS_IPV6_LINK_MTU_CHANGE:
		case MBOX_ASTS_IPV6_ND_PREFIX_IGNORED:
		case MBOX_ASTS_IPV6_LCL_PREFIX_IGNORED:
		case MBOX_ASTS_ICMPV6_ERROR_MSG_RCVD:
			/* No action */
			QL4PRINT(QLP2, printk("scsi%d: AEN %04x\n",
					      ha->host_no, mbox_status));
			break;

		case MBOX_ASTS_IPV6_DEFAULT_ROUTER_CHANGED:
			if ((ql_dbg_level & QLP20) != 0) {
				uint8_t ip_addr_str[IP_ADDR_STR_SIZE];

				mbox_sts[2] = RD_REG_DWORD(&ha->reg->mailbox[2]);
				mbox_sts[3] = RD_REG_DWORD(&ha->reg->mailbox[3]);
				mbox_sts[4] = RD_REG_DWORD(&ha->reg->mailbox[4]);
				mbox_sts[5] = RD_REG_DWORD(&ha->reg->mailbox[5]);

				memcpy(&ha->ipv6_default_router_addr[0], &mbox_sts[2], 4);
				memcpy(&ha->ipv6_default_router_addr[4], &mbox_sts[3], 4);
				memcpy(&ha->ipv6_default_router_addr[8], &mbox_sts[4], 4);
				memcpy(&ha->ipv6_default_router_addr[12],&mbox_sts[5], 4);

				IPv6Addr2Str(ha->ipv6_default_router_addr, &ip_addr_str[0]);
				QL4PRINT(QLP2, printk("scsi%d: AEN %04x IPv6 "
						      "DEFAULT ROUTER CHANGED %s\n",
						      ha->host_no, mbox_status, &ip_addr_str[0]));
			}
			break;

		case MBOX_ASTS_MAC_ADDRESS_CHANGED:
		case MBOX_ASTS_DNS:
			/* No action */
			QL4PRINT(QLP2,
				 printk("scsi%d: AEN %04x, "
					"mbox_sts[1]=%04x, "
					"mbox_sts[2]=%04x\n",
					ha->host_no, mbox_status,
					RD_REG_DWORD(&ha->reg->mailbox[1]),
					RD_REG_DWORD(&ha->reg->mailbox[2])));
			break;

		case MBOX_ASTS_SELF_TEST_FAILED:
		case MBOX_ASTS_LOGIN_FAILED:
			/* No action */
			QL4PRINT(QLP2,
				 printk("scsi%d: AEN %04x, "
					"mbox_sts[1]=%04x, "
					"mbox_sts[2]=%04x, mbox_sts[3]=%04x\n",
					ha->host_no, mbox_status,
					RD_REG_DWORD(&ha->reg->mailbox[1]),
					RD_REG_DWORD(&ha->reg->mailbox[2]),
					RD_REG_DWORD(&ha->reg->mailbox[3])));
			break;

		case MBOX_ASTS_DATABASE_CHANGED:
				DEBUG2( printk("scsi%d: AEN[%d] %04x queued"
						" mb1:0x%x mb2:0x%x mb3:0x%x"
						" mb4:0x%x\n",
						ha->host_no, ha->aen_in,
						mbox_status,
					ha->aen_q[ha->aen_in].mbox_sts[1],
					ha->aen_q[ha->aen_in].mbox_sts[2],
					ha->aen_q[ha->aen_in].mbox_sts[3],
					ha->aen_q[ha->aen_in].mbox_sts[4]);)

				/* The DPC routine will process the aen */
				set_bit(DPC_AEN, &ha->dpc_flags);
			break;

#if ENABLE_ISNS
		case MBOX_ASTS_ISNS_UNSOLICITED_PDU_RECEIVED:
			memset(&mbox_sts, 0, sizeof(mbox_sts));
			mbox_sts[0] = mbox_status;
			mbox_sts[1] = RD_REG_DWORD(&ha->reg->mailbox[1]);
			mbox_sts[2] = RD_REG_DWORD(&ha->reg->mailbox[2]);
			mbox_sts[3] = RD_REG_DWORD(&ha->reg->mailbox[3]);
			mbox_sts[4] = RD_REG_DWORD(&ha->reg->mailbox[4]);
			mbox_sts[5] = RD_REG_DWORD(&ha->reg->mailbox[5]);

			if (mbox_sts[1] == ISNS_EVENT_DATA_RECEIVED) {
				QL4PRINT(QLP2, printk("scsi%d: AEN %04x, mbox_sts[1]=%04x, "
						      "mbox_sts[2]=%04x, mbox_sts[3]=%04x, mbox_sts[4]=%04x\n",
						      ha->host_no, mbox_status, mbox_sts[1],
						      mbox_sts[2], mbox_sts[3], mbox_sts[4]));

				if (qla4xxx_isns_get_server_request(ha,
								    mbox_sts[3],
								    mbox_sts[2])
				    != QLA_SUCCESS) {
					QL4PRINT(QLP2,
						 printk("scsi%d: %s: AEN %04x, "
							"isns_get_server_request FAILED!!\n",
							ha->host_no, __func__, mbox_status));
				}
			}
			else if (mbox_sts[1] == ISNS_EVENT_CONNECTION_OPENED) {
				QL4PRINT(QLP2, printk("scsi%d: AEN %04x, iSNS Service "
						      "Connection Opened!\n"
						      "mbox_sts[2]=%08x, mbox_sts[3]=%08x, "
						      "mbox_sts[4]=%08x, mbox_sts[5]=%08x\n",
						      ha->host_no, mbox_status, mbox_sts[2],
						      mbox_sts[3], mbox_sts[4], mbox_sts[5]));

				qla4xxx_isns_enable_callback(ha,
							     mbox_sts[2],
							     mbox_sts[3],
							     mbox_sts[4],
							     mbox_sts[5]);
			}
			else if (mbox_sts[1] == ISNS_EVENT_CONNECTION_FAILED) {
				QL4PRINT(QLP2, printk("scsi%d: AEN %04x, iSNS Service"
						      " Connection FAILED! reason %04x\n",
						      ha->host_no, mbox_status, mbox_sts[2]));
			}
			break;
#endif
		default:
			QL4PRINT(QLP2,
				 printk("scsi%d: AEN %04x UNKNOWN\n",
					ha->host_no, mbox_status));
		}
	}
	else {
		QL4PRINT(QLP2,
			 printk("scsi%d: Unknown mailbox status %08X\n",
				ha->host_no, mbox_status));

		ha->mbox_status[0] = mbox_status;
		__dump_registers(QLP2, ha);
	}
}

/**************************************************************************
 * qla4xxx_interrupt_service_routine
 *	This routine services the interrupt
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Remarks:
 *      hardware_lock locked upon entry
 *
 * Returns:
 *      QLA_SUCCESS - success, An interrupt was found and processed
 *	QLA_ERROR - failure, The adapter was not interrupting
 *
 * Context:
 *	Interrupt context.
 **************************************************************************/
void
qla4xxx_interrupt_service_routine(scsi_qla_host_t *ha, uint32_t intr_status)
{
	if (intr_status & CSR_SCSI_COMPLETION_INTR) {
		qla4xxx_process_response_queue(ha);
	}

	if (intr_status & CSR_SCSI_PROCESSOR_INTR) {
		uint32_t mbox_status = RD_REG_DWORD(&ha->reg->mailbox[0]);
		qla4xxx_isr_decode_mailbox(ha, mbox_status);

		/* Clear Mailbox Interrupt */
		WRT_REG_DWORD(&ha->reg->ctrl_status,
		    SET_RMASK(CSR_SCSI_PROCESSOR_INTR));
		PCI_POSTING(&ha->reg->ctrl_status);
	}
}

uint8_t
qla4xxx_poll_and_ack_scsi_reset(scsi_qla_host_t *ha)
{
	uint8_t status = QLA_ERROR;
	unsigned long flags = 0;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	if (RD_REG_DWORD(&ha->reg->ctrl_status) & CSR_SCSI_RESET_INTR) {
		QL4PRINT(QLP2, printk("scsi%d: Soft Reset requested by "
			"Network function or RISC\n", ha->host_no));

		clear_bit(AF_ONLINE, &ha->flags);
		__qla4xxx_disable_intrs(ha);

		QL4PRINT(QLP2, printk("scsi%d: Clear SCSI Reset Interrupt\n",
			ha->host_no));
		WRT_REG_DWORD(&ha->reg->ctrl_status, SET_RMASK(CSR_SCSI_RESET_INTR));
		PCI_POSTING(&ha->reg->ctrl_status);

		if (!ql4_mod_unload)
			set_bit(DPC_RESET_HA_INTR, &ha->dpc_flags);
		status = QLA_SUCCESS;
	}

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	return (status);
 }

/**************************************************************************
 * qla4xxx_intr_handler
 *	This routine handles the H/W interrupt
 *
 * Input:
 *	irq - Unused
 *	dev_id - Pointer to host adapter structure
 *	regs - Unused
 *
 * Returns:
 *	None
 *
 * Context:
 *	Interrupt context.
 **************************************************************************/
irqreturn_t
qla4xxx_intr_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	scsi_qla_host_t *ha;
	uint32_t intr_status;
	unsigned long flags = 0;
	uint8_t reqs_count = 0;

	ha = (scsi_qla_host_t *) dev_id;
	if (!ha) {
		DEBUG2( printk("qla4xxx: Interrupt with NULL host ptr\n"));
		return IRQ_NONE;
	}

	ha->isr_count++;

	/*
	 * Check for pending interrupts
	 */
	spin_lock_irqsave(&ha->hardware_lock, flags);

	/*
	 * Repeatedly service interrupts up to a maximum of
	 * MAX_REQS_SERVICED_PER_INTR
	 */
	while (1) {
		/*
		 * Read interrupt status
		 */
		if (le32_to_cpu(ha->shadow_regs->rsp_q_in) !=
		    ha->response_out) {
			intr_status = CSR_SCSI_COMPLETION_INTR;
		}
		else {
			intr_status = RD_REG_DWORD(&ha->reg->ctrl_status);
		}

		if ((intr_status & (CSR_SCSI_RESET_INTR|CSR_FATAL_ERROR|INTR_PENDING)) == 0) {
			if (reqs_count == 0)
				ha->spurious_int_count++;
			break;
		}

		/*
		 * Service interrupt
		 */
		if (intr_status & CSR_FATAL_ERROR) {
			ql4_printk(KERN_WARNING, ha,  "Fatal Error, "
				  "Status 0x%04x\n",
                                  RD_REG_DWORD(ISP_PORT_ERROR_STATUS(ha)));
			QL4PRINT(QLP2,
				 printk("scsi%d: Fatal Error, "
					"Status 0x%04x\n", ha->host_no,
					RD_REG_DWORD(ISP_PORT_ERROR_STATUS(ha))));

			QL4PRINT(QLP2,
				 printk("scsi%d: Dump Registers:\n", ha->host_no));
			__dump_registers(QLP2, ha);

			/* Issue Soft Reset to clear this error condition.
			 * This will prevent the RISC from repeatedly
			 * interrupting the driver; thus, allowing the DPC to
			 * get scheduled to continue error recovery.
			 * NOTE: Disabling RISC interrupts does not work in
			 * this case, as CSR_FATAL_ERROR overrides
			 * CSR_SCSI_INTR_ENABLE */
			QL4PRINT(QLP2, printk("scsi%d: Issue SOFT RESET\n",
                                              ha->host_no));
			WRT_REG_DWORD(&ha->reg->ctrl_status, SET_RMASK((CSR_SOFT_RESET|CSR_SCSI_RESET_INTR)));
			PCI_POSTING(&ha->reg->ctrl_status);

			QL4PRINT(QLP2, printk("scsi%d: Acknowledge fatal error\n",
                                              ha->host_no));
			WRT_REG_DWORD(&ha->reg->ctrl_status, SET_RMASK(CSR_FATAL_ERROR));
			PCI_POSTING(&ha->reg->ctrl_status);

			__qla4xxx_disable_intrs(ha);

			if (!ql4_mod_unload)
				set_bit(DPC_RESET_HA, &ha->dpc_flags);

			break;
		}
		else if (intr_status & CSR_SCSI_RESET_INTR) {
			QL4PRINT(QLP2,
				 printk("scsi%d: Soft Reset requested by "
					"Network function or RISC\n", ha->host_no));

			clear_bit(AF_ONLINE, &ha->flags);
			__qla4xxx_disable_intrs(ha);

			QL4PRINT(QLP2,
				 printk("scsi%d: Clear SCSI Reset Interrupt\n",
					ha->host_no));
			WRT_REG_DWORD(&ha->reg->ctrl_status, SET_RMASK(CSR_SCSI_RESET_INTR));
			PCI_POSTING(&ha->reg->ctrl_status);

			if (!ql4_mod_unload)
				set_bit(DPC_RESET_HA_INTR, &ha->dpc_flags);

			break;
		}
		else if (intr_status & INTR_PENDING) {
			qla4xxx_interrupt_service_routine(ha, intr_status);
			ha->total_io_count++;
			if (++reqs_count == MAX_REQS_SERVICED_PER_INTR) {
				QL4PRINT(QLP11,
					 printk("scsi%d: %s: exiting, %d "
						"requests serviced\n",
						ha->host_no, __func__,
						reqs_count));
				break;
			}
			intr_status = 0;
		}
	}

	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (!list_empty(&ha->done_srb_q))
		qla4xxx_done(ha);

	return IRQ_HANDLED;
}

/**************************************************************************
 * qla4xxx_process_aen
 *	This routine processes Asynchronous Events received from the firmware.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *	process_aen -
 *      	PROCESS_ALL_AENS	 0
 *      	FLUSH_DDB_CHANGED_AENS	 1
 *      	RELOGIN_DDB_CHANGED_AENS 2
 *
 * Returns:
 *	None
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
void
qla4xxx_process_aen(scsi_qla_host_t *ha, uint8_t process_aen)
{
	uint32_t mbox_sts[MBOX_AEN_REG_COUNT];
	aen_t   *aen;
	int     i;
	unsigned long flags;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	while (ha->aen_out != ha->aen_in) {

		/* Advance pointers for next entry */
		if (ha->aen_out == (MAX_AEN_ENTRIES - 1))
			ha->aen_out = 0;
		else
			ha->aen_out++;

		aen = &ha->aen_q[ha->aen_out];

		/* copy aen information to local structure */
		for (i=0; i < MBOX_AEN_REG_COUNT; i++)
			mbox_sts[i] = aen->mbox_sts[i];

		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		QL4PRINT(QLP2|QLP7, printk(
		    "scsi%d: AEN[%d] %04x, DDB [%d] state=%04x mod=%x conerr=%08x \n",
		    ha->host_no, ha->aen_out, mbox_sts[0], mbox_sts[2],
		    mbox_sts[3], mbox_sts[1], mbox_sts[4]));

		switch (mbox_sts[0]) {
		case MBOX_ASTS_DATABASE_CHANGED:
			switch (process_aen) {
			case FLUSH_DDB_CHANGED_AENS:
				DEBUG2(printk(
				    "scsi%d: AEN[%d] %04x, DDB [%d] "
				    "state=%04x FLUSHED!\n", ha->host_no,
				    ha->aen_out, mbox_sts[0], mbox_sts[2],
				    mbox_sts[3]));
				break;
			case RELOGIN_DDB_CHANGED_AENS:
			{
				/* For use during init time, we want to relogin
				 * non-active ddbs and update device state of
				 * ddbs that are now active */
				ddb_entry_t *ddb_entry;
				uint32_t fw_ddb_device_state =  mbox_sts[3];
				uint32_t fw_ddb_index =  mbox_sts[2];

				ddb_entry = qla4xxx_find_ddb_internally(ha, fw_ddb_index);
				if (ddb_entry) {
					qla4xxx_update_ddb_entry (ha, ddb_entry, fw_ddb_index);

					if (fw_ddb_device_state == DDB_DS_SESSION_ACTIVE) {
						/* Updated device state will now
						 * allow a SCSI target to get
						 * mapped to this ddb */
						QL4PRINT(QLP7, printk(
						    "scsi%d: DDB [%d] now active\n",
						    ha->host_no,
						    ddb_entry->fw_ddb_index));

						qla4xxx_set_device_state(ha, ddb_entry, DEV_STATE_ONLINE);
					} else if ((fw_ddb_device_state == DDB_DS_SESSION_FAILED) ||
                                                   (fw_ddb_device_state == DDB_DS_NO_CONNECTION_ACTIVE)){
						ddb_entry->dev_scan_wait_to_complete_relogin = 0;
						ddb_entry->dev_scan_wait_to_start_relogin =
							jiffies + ((ddb_entry->default_time2wait + 4) * HZ);

						QL4PRINT(QLP7, printk(
						    "scsi%d: DDB [%d] initate relogin "
						    "after %d seconds\n", ha->host_no,
						    ddb_entry->fw_ddb_index,
						    ddb_entry->default_time2wait+4));
					}
				} else {
					qla4xxx_add_ddb_to_list(ha, fw_ddb_index, NULL);
				}
				break;
			}
			case PROCESS_ALL_AENS:
			default:
				/* Post init only */

				if (mbox_sts[1] == 0) {	 /* Global DB change. */
					QL4PRINT(QLP2|QLP7, printk("scsi%d: %s: "
					    "global database changed aen\n",
					    ha->host_no, __func__));
					qla4xxx_reinitialize_ddb_list(ha);
				} else if (mbox_sts[1] == 1) {	/* Specific device. */
					qla4xxx_process_ddb_changed(ha,
								    mbox_sts[2],
								    mbox_sts[3]);
				} else {
					QL4PRINT(QLP2|QLP7, printk("scsi%d: %s: "
					    "invalid database changed aen modifier, "
					    "mbox_sts[1]=%04x\n", ha->host_no,
					    __func__, mbox_sts[1]));
				}
				break;
			}  /* switch process_aen */
		}  /* switch mbox_sts[0] */
		spin_lock_irqsave(&ha->hardware_lock, flags);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
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


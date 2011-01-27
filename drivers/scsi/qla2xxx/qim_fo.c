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


#include "qim_ioctl.h"
#include "qlfo.h"
#include "qlfolimits.h"

#define LUN_DATA_ENABLED		BIT_7
#define LUN_DATA_PREFERRED_PATH		BIT_6


/*
 * Global variables
 */
SysFoParams_t qla_fo_params;


/*
 * qim_fo_init_params
 *	Gets driver configuration file failover properties to initalize
 *	the global failover parameters structure.
 *
 * Input:
 *	ha = adapter block pointer.
 *
 * Context:
 *	Kernel context.
 */
void
qim_fo_init_params(void)
{
	DEBUG3(printk("%s: entered.\n", __func__);)

	/* Return some hard-coded values for a non-failover driver. */

	memset(&qla_fo_params, 0, sizeof(qla_fo_params));

	qla_fo_params.MaxPathsPerDevice = 1 ;
	qla_fo_params.MaxRetriesPerPath = FO_MAX_RETRIES_PER_PATH_DEF;
	qla_fo_params.MaxRetriesPerIo = FO_MAX_RETRIES_PER_IO_DEF;

	qla_fo_params.Flags =  0;
	qla_fo_params.FailoverNotifyType = FO_NOTIFY_TYPE_NONE;
	
	DEBUG3(printk("%s: exiting.\n", __func__);)
}

/*
 * qim_fo_get_params
 *	Process an ioctl request to get system wide failover parameters.
 *
 * Input:
 *	pp = Pointer to FO_PARAMS structure.
 *
 * Returns:
 *	EXT_STATUS code.
 *
 * Context:
 *	Kernel context.
 */
static uint32_t
qim_fo_get_params(PFO_PARAMS pp)
{
	DEBUG9(printk("%s: entered.\n", __func__);)

	pp->MaxPathsPerDevice = qla_fo_params.MaxPathsPerDevice;
	pp->MaxRetriesPerPath = qla_fo_params.MaxRetriesPerPath;
	pp->MaxRetriesPerIo = qla_fo_params.MaxRetriesPerIo;
	pp->Flags = qla_fo_params.Flags;
	pp->FailoverNotifyType = qla_fo_params.FailoverNotifyType;
	pp->FailoverNotifyCdbLength = qla_fo_params.FailoverNotifyCdbLength;
	memset(pp->FailoverNotifyCdb, 0, sizeof(pp->FailoverNotifyCdb));
	memcpy(pp->FailoverNotifyCdb,
	    &qla_fo_params.FailoverNotifyCdb[0], sizeof(pp->FailoverNotifyCdb));

	DEBUG9(printk("%s: exiting.\n", __func__);)

	return EXT_STATUS_OK;
}

/*
 * qim_fo_set_params
 *	Process an ioctl request to set system wide failover parameters.
 *
 * Input:
 *	pp = Pointer to FO_PARAMS structure.
 *
 * Returns:
 *	EXT_STATUS code.
 *
 * Context:
 *	Kernel context.
 */
static uint32_t
qim_fo_set_params(PFO_PARAMS pp)
{
	DEBUG9(printk("%s: entered.\n", __func__);)

	/* Check values for defined MIN and MAX */
	if ((pp->MaxPathsPerDevice > SDM_DEF_MAX_PATHS_PER_DEVICE) ||
	    (pp->MaxRetriesPerPath < FO_MAX_RETRIES_PER_PATH_MIN) ||
	    (pp->MaxRetriesPerPath > FO_MAX_RETRIES_PER_PATH_MAX) ||
	    (pp->MaxRetriesPerIo < FO_MAX_RETRIES_PER_IO_MIN) ||
	    (pp->MaxRetriesPerPath > FO_MAX_RETRIES_PER_IO_MAX)) {
		DEBUG2_9_10(printk("%s: got invalid params.\n", __func__);)
		return EXT_STATUS_INVALID_PARAM;
	}

	/* Update the global structure. */
	qla_fo_params.MaxPathsPerDevice = pp->MaxPathsPerDevice;
	qla_fo_params.MaxRetriesPerPath = pp->MaxRetriesPerPath;
	qla_fo_params.MaxRetriesPerIo = pp->MaxRetriesPerIo;
	qla_fo_params.Flags = pp->Flags;
	qla_fo_params.FailoverNotifyType = pp->FailoverNotifyType;
	qla_fo_params.FailoverNotifyCdbLength = pp->FailoverNotifyCdbLength;
	if (pp->FailoverNotifyType & FO_NOTIFY_TYPE_CDB) {
		if (pp->FailoverNotifyCdbLength >
		    sizeof(qla_fo_params.FailoverNotifyCdb)) {
			DEBUG2_9_10(printk("%s: got invalid cdb length.\n",
			    __func__);)
			return EXT_STATUS_INVALID_PARAM;
		}

		memcpy(qla_fo_params.FailoverNotifyCdb,
		    pp->FailoverNotifyCdb,
		    sizeof(qla_fo_params.FailoverNotifyCdb));
	}

	DEBUG9(printk("%s: exiting.\n", __func__);)

	return EXT_STATUS_OK;
}

/*
 * qim_get_hba
 *	Searches the hba structure chain for the requested instance
 *      aquires the mutex and returns a pointer to the hba structure.
 *
 * Input:
 *	inst = adapter instance number.
 *
 * Returns:
 *	Return value is a pointer to the adapter structure or
 *      NULL if instance not found.
 *
 * Context:
 *	Kernel context.
 */
scsi_qla_host_t *
qim_get_hba(unsigned long instance)
{
	int	found;
	scsi_qla_host_t *ha;

	ha = NULL;
	found = 0;
	read_lock(*qim_hostlist_lock_ptr);
	list_for_each_entry(ha, *qim_hostlist_ptr, list) {
		if (ha->instance == instance) {
			found++;
			break;
		}
	}
	read_unlock(*qim_hostlist_lock_ptr);

	return (found ? ha : NULL);
}

/*
 * qim_cfg_get_paths
 *      Get list of paths EXT_FO_GET_PATHS.
 *
 * Input:
 *      ha = pointer to adapter
 *      bp = pointer to buffer
 *      cmd = Pointer to kernel copy of EXT_IOCTL.
 *
 * Return;
 *      0 on success or errno.
 *	driver ioctl errors are returned via cmd->Status.
 *
 * Context:
 *      Kernel context.
 */
int
qim_cfg_get_paths(EXT_IOCTL *cmd, FO_GET_PATHS *bp, int mode)
{
#define STD_MAX_PATH_CNT	1
#define STD_VISIBLE_INDEX	0

	int	rval = 0;

	FO_PATHS_INFO	*paths,	*u_paths;
	FO_PATH_ENTRY	*entry;
	EXT_DEST_ADDR   *sap = &bp->HbaAddr;
	scsi_qla_host_t *ha = NULL;
	int found;
	fc_port_t *fcport = NULL;


	DEBUG9(printk("%s: entered.\n", __func__);)

	u_paths = (FO_PATHS_INFO *)Q64BIT_TO_PTR(cmd->ResponseAdr,
	    cmd->AddrMode);
	ha = qim_get_hba((int)bp->HbaInstance);

	if (!ha) {
		DEBUG2_9_10(printk(KERN_INFO "%s: no ha matching inst %d.\n",
		    __func__, bp->HbaInstance);)

		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (rval);
	}
	DEBUG9(printk("%s(%ld): found matching ha inst %d.\n",
	    __func__, ha->host_no, bp->HbaInstance);)

	if (sap->DestType != EXT_DEF_DESTTYPE_WWNN &&
	    sap->DestType != EXT_DEF_DESTTYPE_WWPN) {
		/* Scan for mp_dev by nodename or portname *ONLY* */

		cmd->Status = EXT_STATUS_INVALID_PARAM;
		cmd->DetailStatus = EXT_DSTATUS_TARGET;
		return (rval);
	}

	paths = kmalloc(sizeof(FO_PATHS_INFO), GFP_KERNEL);
	if (paths == NULL) {
		DEBUG4(printk("%s: failed to allocate memory of size (%d)\n",
		    __func__, (int)sizeof(FO_PATHS_INFO));)
		DEBUG9_10(printk("%s: failed allocate memory size(%d).\n",
		    __func__, (int)sizeof(FO_PATHS_INFO));)

		cmd->Status = EXT_STATUS_NO_MEMORY;

		return -ENOMEM;
	}
	DEBUG9(printk("%s(%ld): found matching ha inst %d.\n",
	    __func__, ha->host_no, bp->HbaInstance);)

	memset(paths, 0, sizeof(FO_PATHS_INFO));

	/* non-fo case. There's only one path. */

	DEBUG9(printk("%s: non-fo case.\n", __func__);)

	found = 0;
	if (sap->DestType != EXT_DEF_DESTTYPE_WWNN) {
		list_for_each_entry(fcport, &ha->fcports, list) {
			if (memcmp(fcport->node_name, sap->DestAddr.WWNN,
			    EXT_DEF_WWN_NAME_SIZE) == 0) {
				found++;
				break;
			}
		}
	} else if (sap->DestType != EXT_DEF_DESTTYPE_WWPN) {
		list_for_each_entry(fcport, &ha->fcports, list) {
			if (memcmp(fcport->port_name, sap->DestAddr.WWPN,
			    EXT_DEF_WWN_NAME_SIZE) == 0) {
				found++;
				break;
			}
		}
	}

	if (found) {
		DEBUG9(printk("%s: found fcport:"
		    "(%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x)\n.",
		    __func__,
		    sap->DestAddr.WWNN[0], sap->DestAddr.WWNN[1],
		    sap->DestAddr.WWNN[2], sap->DestAddr.WWNN[3],
		    sap->DestAddr.WWNN[4], sap->DestAddr.WWNN[5],
		    sap->DestAddr.WWNN[6], sap->DestAddr.WWNN[7]);)

		paths->HbaInstance         = bp->HbaInstance;
		paths->PathCount           = STD_MAX_PATH_CNT;
		paths->VisiblePathIndex    = STD_VISIBLE_INDEX;

		/* set current path value, which is the first one (0) for all
		 * LUNs.
		 */
		memset(paths->CurrentPathIndex, 0,
		    sizeof(paths->CurrentPathIndex));

		entry = &(paths->PathEntry[STD_VISIBLE_INDEX]);

		entry->Visible     = 1;
		entry->HbaInstance = bp->HbaInstance;

		memcpy(entry->PortName, fcport->port_name,
		    EXT_DEF_WWP_NAME_SIZE);

		/* Copy data to user */
		if (rval == 0)
			rval = copy_to_user(&u_paths->PathCount,
			    &paths->PathCount, 4);
		if (rval == 0)
			rval = copy_to_user(&u_paths->CurrentPathIndex,
			    &paths->CurrentPathIndex,
			    sizeof(paths->CurrentPathIndex));
		if (rval == 0)
			rval = copy_to_user(&u_paths->PathEntry,
			    &paths->PathEntry,
			    sizeof(paths->PathEntry));

		if (rval) { /* if any of the above failed */
			DEBUG9_10(printk("%s: data copy failed.\n",
			    __func__);)

			cmd->Status = EXT_STATUS_COPY_ERR;
		}
	} else {
		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		cmd->DetailStatus = EXT_DSTATUS_TARGET;

		DEBUG10(printk("%s: cannot find fcport "
		    "(%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x)\n.",
		    __func__,
		    sap->DestAddr.WWNN[0],
		    sap->DestAddr.WWNN[1],
		    sap->DestAddr.WWNN[2],
		    sap->DestAddr.WWNN[3],
		    sap->DestAddr.WWNN[4],
		    sap->DestAddr.WWNN[5],
		    sap->DestAddr.WWNN[6],
		    sap->DestAddr.WWNN[7]);)
		DEBUG4(printk("%s: cannot find fcport "
		    "(%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x)\n.",
		    __func__,
		    sap->DestAddr.WWNN[0],
		    sap->DestAddr.WWNN[1],
		    sap->DestAddr.WWNN[2],
		    sap->DestAddr.WWNN[3],
		    sap->DestAddr.WWNN[4],
		    sap->DestAddr.WWNN[5],
		    sap->DestAddr.WWNN[6],
		    sap->DestAddr.WWNN[7]);)
	}

	kfree(paths);

	DEBUG9(printk("%s: exiting. rval=%d.\n", __func__, rval);)

	return rval;

} /* qim_cfg_get_paths */

/*
 * qim_cfg_set_current_path
 *      Set the current failover path EXT_FO_GET_PATHS IOCTL call.
 *
 * Input:
 *      ha = pointer to adapter
 *      bp = pointer to buffer
 *      cmd = Pointer to kernel copy of EXT_IOCTL.
 *
 * Return;
 *      0 on success or errno.
 *
 * Context:
 *      Kernel context.
 */
int
qim_cfg_set_current_path(EXT_IOCTL *cmd, FO_SET_CURRENT_PATH *bp, int mode )
{
	uint32_t        rval = 0;
	scsi_qla_host_t *ha;


	DEBUG9(printk("%s: entered.\n", __func__);)

	/* First find the adapter with the instance number. */
	ha = qim_get_hba((int)bp->HbaInstance);
	if (!ha) {
		DEBUG2_9_10(printk(KERN_INFO "%s: no ha matching inst %d.\n",
		    __func__, bp->HbaInstance);)

		cmd->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (rval);
	}

	/* non-failover mode. nothing to be done. */
	DEBUG9_10(printk("%s(%ld): Assumed non-failover driver mode.\n",
	    __func__, ha->host_no);)

	DEBUG9(printk("%s: exiting. rval = %d.\n", __func__, rval);)

	return rval;
}

/*
 * qim_fo_get_lun_data
 *      Get lun data from all devices attached to a HBA (FO_GET_LUN_DATA).
 *      Gets lun mask if failover not enabled.
 *
 * Input:
 *      ha = pointer to adapter
 *      bp = pointer to buffer
 *
 * Return;
 *      0 on success or errno.
 *
 * Context:
 *      Kernel context.
 */
static int
qim_fo_get_lun_data(EXT_IOCTL *pext, FO_LUN_DATA_INPUT *bp, int mode)
{
	scsi_qla_host_t  *ha;
	struct list_head	*fcports;
	fc_port_t        *fcport;
	int              ret = 0;
	os_tgt_t         *ostgt;
	uint16_t         cnt;
	uint16_t         lun;
	FO_EXTERNAL_LUN_DATA_ENTRY *u_entry, *entry;
	FO_LUN_DATA_LIST *u_list, *list;


	DEBUG9(printk("%s: entered.\n", __func__);)

	ha = qim_get_hba((unsigned long)bp->HbaInstance);

	if (!ha) {
		DEBUG2_9_10(printk("%s: no ha matching inst %d.\n",
		    __func__, bp->HbaInstance);)

		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (ret);
	}

	DEBUG9(printk("%s: ha inst %ld, buff %p.\n",
	    __func__, ha->instance, bp);)
	DEBUG4(printk("%s: hba %p, buff %p bp->HbaInstance(%x).\n",
	    __func__, ha, bp, (int)bp->HbaInstance));

	list = kmalloc(sizeof(FO_LUN_DATA_LIST), GFP_KERNEL);
	if (list == NULL) {
		DEBUG2_9_10(printk("%s: failed to alloc memory of size (%d)\n",
		    __func__, (int)sizeof(FO_LUN_DATA_LIST));)
		pext->Status = EXT_STATUS_NO_MEMORY;
		return (-ENOMEM);
	}
	memset(list, 0, sizeof(FO_LUN_DATA_LIST));

	entry = &list->DataEntry[0];

	u_list = (FO_LUN_DATA_LIST *)Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode);
	u_entry = &u_list->DataEntry[0];

	/* assumed non-failover; get the fcport list */
	fcports = &ha->fcports;

	/* Check thru this adapter's fcport list */
	fcport = NULL;
	list_for_each_entry(fcport, fcports, list) {
		if (fcport->port_type != FCT_TARGET)
			continue;
#if 0
                if ((atomic_read(&fcport->state) != FCS_ONLINE) &&
		    !qla2x00_is_fcport_in_config(ha, fcport)) {
			/* no need to report */
			DEBUG2_9_10(printk("%s(%ld): not reporting fcport "
			    "%02x%02x%02x%02x%02x%02x%02x%02x. state=%i,"
			    " flags=%02x.\n",
			    __func__, ha->host_no, fcport->port_name[0],
			    fcport->port_name[1], fcport->port_name[2],
			    fcport->port_name[3], fcport->port_name[4],
			    fcport->port_name[5], fcport->port_name[6],
			    fcport->port_name[7], atomic_read(&fcport->state),
			    fcport->flags);)
			continue;
		}
#endif

		memcpy(entry->PortName,
		    fcport->port_name, EXT_DEF_WWN_NAME_SIZE);

		/*
		 * Failover disabled. Just return LUN mask info
		 * in lun data entry of this port.
		 */
		memcpy(entry->NodeName,
		    fcport->node_name, EXT_DEF_WWN_NAME_SIZE);
		entry->TargetId = 0;
		for (cnt = 0; cnt < MAX_FIBRE_DEVICES; cnt++) {
			if (!(ostgt = ha->otgt[cnt])) {
				continue;
			}

			if (ostgt->fcport == fcport) {
				entry->TargetId = cnt;
				break;
			}
		}
		if (cnt == MAX_FIBRE_DEVICES) {
			/* Not found?  For now just go to next port. */
#if defined(QL_DEBUG_LEVEL_2) || defined(QL_DEBUG_LEVEL_10)
			uint8_t          *tmp_name;

			tmp_name = fcport->port_name;

			printk("%s(%ld): ERROR - port "
			    "%02x%02x%02x%02x%02x%02x%02x%02x "
			    "not configured.\n",
			    __func__, ha->host_no,
			    tmp_name[0], tmp_name[1], tmp_name[2],
			    tmp_name[3], tmp_name[4], tmp_name[5],
			    tmp_name[6], tmp_name[7]);
#endif /* DEBUG */

			continue;
		}

		/* Got a valid port */
		list->EntryCount++;

		entry->LunCount = MAX_LUNS;
		for (lun = 0; lun < MAX_LUNS; lun++) {
			/* set MSB if masked */
			entry->Data[lun] = LUN_DATA_PREFERRED_PATH;
			if (!EXT_IS_LUN_BIT_SET(&(fcport->lun_mask),
			    lun)) {
				entry->Data[lun] |= LUN_DATA_ENABLED;
			}
		}

		DEBUG9(printk("%s: got lun_mask for tgt %d\n",
		    __func__, cnt);)
		DEBUG9(qim_dump_buffer((char *)&(fcport->lun_mask),
		    sizeof(lun_bit_mask_t));)

		ret = copy_to_user(u_entry, entry,
		    sizeof(FO_EXTERNAL_LUN_DATA_ENTRY));

		if (ret) {
			/* error */
			DEBUG9_10(printk("%s: u_entry %p copy "
			    "error. list->EntryCount=%d.\n",
			    __func__, u_entry, list->EntryCount);)
			pext->Status = EXT_STATUS_COPY_ERR;
			break;
		}

		/* Go to next port */
		u_entry++;
		continue;
	}

	DEBUG9(printk("%s: get_lun_data - entry count = [%d]\n",
	    __func__, list->EntryCount);)
	DEBUG4(printk("%s: get_lun_data - entry count = [%d]\n",
	    __func__, list->EntryCount);)

	if (ret == 0) {
		/* copy number of entries */
		ret = copy_to_user(&u_list->EntryCount, &list->EntryCount,
		    sizeof(list->EntryCount));
		pext->ResponseLen = FO_LUN_DATA_LIST_MAX_SIZE;
	}

	kfree(list);
	DEBUG9(printk("%s: exiting. ret=%d.\n", __func__, ret);)
	return ret;
}

/*
 * qim_fo_set_lun_data
 *      Set lun data for the specified device on the attached hba
 *      (FO_SET_LUN_DATA).
 *      Sets lun mask if failover not enabled.
 *
 * Input:
 *      bp = pointer to buffer
 *
 * Return;
 *      0 on success or errno.
 *
 * Context:
 *      Kernel context.
 */
static int
qim_fo_set_lun_data(EXT_IOCTL *pext, FO_LUN_DATA_INPUT  *bp, int mode)
{
	scsi_qla_host_t  *ha;
	int              ret = 0;


	DEBUG9(printk("%s: entered.\n", __func__);)

	ha = qim_get_hba((unsigned long)bp->HbaInstance);

	if (!ha) {
		DEBUG2_9_10(printk("%s: no ha matching inst %d.\n",
		    __func__, bp->HbaInstance);)

		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (ret);
	}

	DEBUG9(printk("%s: ha inst %ld, buff %p.\n",
	    __func__, ha->instance, bp);)

	/* Assuming no persistent configuration is supported by driver. */

	DEBUG9(printk("%s: exiting. ret = %d.\n", __func__, ret);)

	return ret;
}

static int
qim_std_get_tgt(scsi_qla_host_t *ha, EXT_IOCTL *pext, FO_DEVICE_DATA *entry)
{
	int		ret = 0;
	uint16_t 	i, tgt;
	uint32_t	b;
	fc_port_t	*fcport;
	os_tgt_t	*ostgt;
	FO_DEVICE_DATA	*u_entry;

	DEBUG9(printk("%s(%ld): entered.\n", __func__, ha->host_no);)

	u_entry = (FO_DEVICE_DATA *)Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode);

	if (pext->ResponseLen < sizeof(FO_DEVICE_DATA)) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk("%s: ERROR ResponseLen %d too small.\n",
		    __func__, pext->ResponseLen);)

		return (ret);
	}

	DEBUG9(printk("%s(%ld): user buffer size=%d. Copying fcport list\n",
	    __func__, ha->host_no, pext->ResponseLen);)

	/* Loop through and return ports found. */
	/* Check thru this adapter's fcport list */
	i = 0;
	fcport = NULL;
	list_for_each_entry(fcport, &ha->fcports, list) {
		if (fcport->port_type != FCT_TARGET)
			continue;
	
		if (i >= MAX_TARGETS)
			break;

		/* clear for a new entry */
		memset(entry, 0, sizeof(FO_DEVICE_DATA));

		memcpy(entry->WorldWideName,
		    fcport->node_name, EXT_DEF_WWN_NAME_SIZE);
		memcpy(entry->PortName,
		    fcport->port_name, EXT_DEF_WWN_NAME_SIZE);

		for (b = 0; b < 3 ; b++)
			entry->PortId[b] = fcport->d_id.r.d_id[2-b];

		DEBUG9(printk("%s(%ld): found fcport %p:%02x%02x%02x%02x"
		    "%02x%02x%02x%02x.\n",
		    __func__, ha->host_no,
		    fcport,
		    fcport->port_name[0],
		    fcport->port_name[1],
		    fcport->port_name[2],
		    fcport->port_name[3],
		    fcport->port_name[4],
		    fcport->port_name[5],
		    fcport->port_name[6],
		    fcport->port_name[7]);)

		/*
		 * Just find the port and return target info.
		 */
		for (tgt = 0; tgt < MAX_FIBRE_DEVICES; tgt++) {
			if (!(ostgt = ha->otgt[tgt])) {
				continue;
			}

			if (ostgt->fcport == fcport) {
				DEBUG9(printk("%s(%ld): Found target %d.\n",
				    __func__, ha->host_no, tgt);)

				entry->TargetId = tgt;
				break;
			}
		}

		entry->MultipathControl = 0; /* always configured */

		ret = copy_to_user(u_entry, entry, sizeof(FO_DEVICE_DATA));
		if (ret) {
			/* error */
			DEBUG2_9_10(printk("%s(%ld): u_entry %p copy "
			    "out err. tgt id = %d, port id=%02x%02x%02x.\n",
			    __func__, ha->host_no, u_entry, tgt,
			    fcport->d_id.r.d_id[2],
			    fcport->d_id.r.d_id[1],
			    fcport->d_id.r.d_id[0]);)
			pext->Status = EXT_STATUS_COPY_ERR;
			break;
		}

		u_entry++;
	}

	DEBUG9(printk("%s(%ld): done copying fcport list entries.\n",
	    __func__, ha->host_no);)


	DEBUG9(printk("%s(%ld): exiting. ret = %d.\n",
	    __func__, ha->host_no, ret);)

	return (ret);
}

/*
 * qim_fo_get_target_data
 *      Get the target control byte for all devices attached to a HBA.
 *
 * Input:
 *      bp = pointer to buffer
 *
 * Return;
 *      0 on success or errno.
 *
 * Context:
 *      Kernel context.
 */
static int
qim_fo_get_target_data(EXT_IOCTL *pext, FO_TARGET_DATA_INPUT *bp, int mode)
{
	scsi_qla_host_t  *ha;
	int              ret = 0;
	FO_DEVICE_DATA   *entry;


	DEBUG9(printk("%s: entered.\n", __func__);)

	ha = qim_get_hba((unsigned long)bp->HbaInstance);

	if (!ha) {
		DEBUG2_9_10(printk("%s: no ha matching inst %d.\n",
		    __func__, bp->HbaInstance);)

		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (ret);
	}

	DEBUG9(printk("%s: ha inst %ld, buff %p.\n",
	    __func__, ha->instance, bp);)

	if ((entry = (FO_DEVICE_DATA *)kmalloc(sizeof(FO_DEVICE_DATA),
	    GFP_KERNEL)) == NULL) {
		DEBUG2_9_10(printk("%s: failed to alloc memory of size (%d)\n",
		    __func__, (int)sizeof(FO_DEVICE_DATA));)
		pext->Status = EXT_STATUS_NO_MEMORY;
		return (-ENOMEM);
	}

	/* Return data assuming non-failover driver. */
	ret = qim_std_get_tgt(ha, pext, entry);


	if (ret == 0) {
		pext->ResponseLen = sizeof(FO_DEVICE_DATABASE);
	}

	kfree(entry);

	DEBUG9(printk("%s: exiting. ret = %d.\n", __func__, ret);)

	return (ret);
}

/*
 * qim_fo_set_target_data
 *      Set multipath control byte for all devices on the attached hba
 *
 * Input:
 *      bp = pointer to buffer
 *
 * Return;
 *      0 on success or errno.
 *
 * Context:
 *      Kernel context.
 */
static int
qim_fo_set_target_data(EXT_IOCTL *pext, FO_TARGET_DATA_INPUT  *bp, int mode)
{
	scsi_qla_host_t  *ha;
	int              ret = 0;

	DEBUG9(printk("%s: entered.\n", __func__);)

	ha = qim_get_hba((unsigned long)bp->HbaInstance);

	if (!ha) {
		DEBUG2_9_10(printk("%s: no ha matching inst %d.\n",
		    __func__, bp->HbaInstance);)

		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return (ret);
	}

	DEBUG9(printk("%s: ha inst %ld, buff %p.\n",
	    __func__, ha->instance, bp);)

	/* Assume no persistent config is supported. nothing to be done. */

	DEBUG9(printk("%s: exiting. ret = %d.\n", __func__, ret);)

	return (ret);

}

/*
 * qim_fo_ioctl
 *	Provides functions for failover ioctl() calls.
 *
 * Input:
 *	ha = adapter state pointer.
 *	ioctl_code = ioctl function to perform
 *	arg = Address of application EXT_IOCTL cmd data
 *	mode = flags
 *
 * Returns:
 *	Return value is the ioctl rval_p return value.
 *	0 = success
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
int
qim_fo_ioctl(struct qla_host_ioctl *ha, int ioctl_code, EXT_IOCTL *pext,
    int mode)
{
	int	rval = 0;
	size_t	in_size, out_size;
	union _buff {
		FO_PARAMS params;
		FO_GET_PATHS path;
		FO_SET_CURRENT_PATH set_path;
		FO_HBA_STAT_INPUT stat;
		FO_LUN_DATA_INPUT lun_data;
		FO_TARGET_DATA_INPUT target_data;
	} buff;

	ENTER("qim_fo_ioctl");
	DEBUG9(printk("%s: entered. arg (%p):\n", __func__, pext);)

	/*
	 * default case for this switch not needed,
	 * ioctl_code validated by caller.
	 */
	in_size = out_size = 0;
	switch (ioctl_code) {
		case FO_CC_GET_PARAMS:
			out_size = sizeof(FO_PARAMS);
			break;
		case FO_CC_SET_PARAMS:
			in_size = sizeof(FO_PARAMS);
			break;
		case FO_CC_GET_PATHS:
			in_size = sizeof(FO_GET_PATHS);
			break;
		case FO_CC_SET_CURRENT_PATH:
			in_size = sizeof(FO_SET_CURRENT_PATH);
			break;
			/*
		case FO_CC_GET_HBA_STAT:
		case FO_CC_RESET_HBA_STAT:
			in_size = sizeof(FO_HBA_STAT_INPUT);
			break;
			*/
		case FO_CC_GET_LUN_DATA:
			in_size = sizeof(FO_LUN_DATA_INPUT);
			break;
		case FO_CC_SET_LUN_DATA:
			in_size = sizeof(FO_LUN_DATA_INPUT);
			break;
		case FO_CC_GET_TARGET_DATA:
			in_size = sizeof(FO_TARGET_DATA_INPUT);
			break;
		case FO_CC_SET_TARGET_DATA:
			in_size = sizeof(FO_TARGET_DATA_INPUT);
			break;

	}
	if (in_size != 0) {
		if ((int)pext->RequestLen < in_size) {
			pext->Status = EXT_STATUS_INVALID_PARAM;
			pext->DetailStatus = EXT_DSTATUS_REQUEST_LEN;
			DEBUG10(printk("%s: got invalie req len (%d).\n",
			    __func__, pext->RequestLen);)

		} else {
			rval = copy_from_user(&buff,
			    Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode),
			    in_size);
			if (rval) {
				DEBUG2_9_10(printk("%s: req buf copy error. "
				    "size=%ld.\n",
				    __func__, (ulong)in_size);)

				pext->Status = EXT_STATUS_COPY_ERR;
			} else {
				DEBUG9(printk("qim_fo_ioctl: req buf "
				    "copied ok.\n"));
			}
		}
	} else if (out_size != 0 && (ulong)pext->ResponseLen < out_size) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		pext->DetailStatus = out_size;
		DEBUG10(printk("%s: got invalie resp len (%d).\n",
		    __func__, pext->ResponseLen);)
	}

	if (rval != 0 || pext->Status != 0)
		goto done_fo_ioctl;

	pext->Status = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	switch (ioctl_code) {
		case FO_CC_GET_PARAMS:
			rval = qim_fo_get_params(&buff.params);
			break;
		case FO_CC_SET_PARAMS:
			rval = qim_fo_set_params(&buff.params);
			break;
		case FO_CC_GET_PATHS:
			rval = qim_cfg_get_paths(pext, &buff.path,mode);
			if (rval != 0)
				out_size = 0;
			break;
		case FO_CC_SET_CURRENT_PATH:
			rval = qim_cfg_set_current_path(pext,
			    &buff.set_path,mode);
			break;
			/*
		case FO_CC_RESET_HBA_STAT:
			rval = qim_fo_stats(&buff.stat, 1);
			break;
		case FO_CC_GET_HBA_STAT:
			rval = qim_fo_stats(&buff.stat, 0);
			break;
			*/
		case FO_CC_GET_LUN_DATA:

			DEBUG4(printk("calling qim_fo_get_lun_data\n");)
			DEBUG4(printk("pext->RequestAdr (%p):\n",
			    Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode));)

			rval = qim_fo_get_lun_data(pext,
			    &buff.lun_data, mode);

			if (rval != 0)
				out_size = 0;
			break;
		case FO_CC_SET_LUN_DATA:

			DEBUG4(printk("calling qim_fo_set_lun_data\n");)
			DEBUG4(printk("	pext->RequestAdr (%p):\n",
			    Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode));)

			rval = qim_fo_set_lun_data(pext,
			    &buff.lun_data, mode);
			break;
		case FO_CC_GET_TARGET_DATA:
			DEBUG4(printk("calling qim_fo_get_target_data\n");)
			DEBUG4(printk("pext->RequestAdr (%p):\n",
			    Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode));)

			rval = qim_fo_get_target_data(pext,
			    &buff.target_data, mode);

			if (rval != 0) {
				out_size = 0;
			}
			break;
		case FO_CC_SET_TARGET_DATA:
			DEBUG4(printk("calling qim_fo_set_target_data\n");)
			DEBUG4(printk("	pext->RequestAdr (%p):\n",
			    Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode));)
			rval = qim_fo_set_target_data(pext,
			    &buff.target_data, mode);
			break;

	}

	if (rval == 0) {
		rval = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode), &buff, out_size);
		if (rval != 0) {
			DEBUG10(printk("%s: resp buf copy error. size=%ld.\n",
			    __func__, (ulong)out_size);)
			pext->Status = EXT_STATUS_COPY_ERR;
		}
	}

done_fo_ioctl:

	if (rval != 0) {
		/*EMPTY*/
		DEBUG10(printk("%s: **** FAILED ****\n", __func__);)
	} else {
		/*EMPTY*/
		DEBUG9(printk("%s: exiting normally\n", __func__);)
	}

	return rval;
}


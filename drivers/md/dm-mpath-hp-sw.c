/*
 * Copyright (C) 2005 Mike Christie, All rights reserved.
 * Copyright (C) 2007 Red Hat, Inc. All rights reserved.
 * Authors: Mike Christie
 *          Dave Wysochanski
 *
 * This file is released under the GPL.
 *
 * This module implements the specific path activation code for
 * HP StorageWorks and FSC FibreCat Asymmetric (Active/Passive)
 * storage arrays.
 * These storage arrays have controller-based failover, not
 * LUN-based failover.  However, LUN-based failover is the design
 * of dm-multipath. Thus, this module is written for LUN-based failover.
 */
#include <linux/blkdev.h>
#include <linux/list.h>
#include <linux/types.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_request.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_dbg.h>

#include "dm.h"
#include "dm-hw-handler.h"

#define DM_MSG_PREFIX "multipath hp-sw: "
#define DM_HP_HWH_NAME "hp-sw"
#define DM_HP_HWH_VER "1.0.0"

/*
 * hp_sw_error_is_retryable - Is an HP-specific check condition retryable?
 * @sc: scsi_cmnd completing with error status
 *
 * Examine error codes of request and determine whether the error is retryable.
 * Some error codes are already retried by scsi-ml (see
 * scsi_decide_disposition), but some HP specific codes are not.
 * The intent of this routine is to supply the logic for the HP specific
 * check conditions.
 *
 * Returns:
 *  1 - command completed with retryable error
 *  0 - command completed with non-retryable error
 *
 * Possible optimizations
 * 1. More hardware-specific error codes
 */
static int hp_sw_error_is_retryable(struct scsi_cmnd *sc)
{
	struct scsi_request *srq = sc->sc_request;

	/*
	 * NOT_READY is known to be retryable
	 * For now we just dump out the sense data and call it retryable
	 */
	if ((status_byte(sc->result) == CHECK_CONDITION) &&
	    (driver_byte(srq->sr_result) & DRIVER_SENSE))
			scsi_print_sense("", sc);

	/*
	 * At this point we don't have complete information about all the error
	 * codes from this hardware, so we are just conservative and retry
	 * when in doubt.
	 */
	return 1;
}

static unsigned char cdb[MAX_COMMAND_SIZE];

/*
 * hp_sw_cmd_done - Completion handler for HP path activation.
 * @sc: scsi_cmnd that is completed
 *
 *  Check sense data, free scsi_request structure, and notify dm that
 *  pg initialization has completed.
 *
 * Context: scsi-ml softirq
 *
 */
static void hp_sw_cmd_done(struct scsi_cmnd * sc)
{
	struct scsi_request *srq;
	struct path *path;
	unsigned err_flags = 0;

	srq = sc->sc_request;
	path = srq->upper_private_data;
	if (!sc->result)
		goto out;

	if (hp_sw_error_is_retryable(sc)) {
		err_flags = MP_RETRY;
		goto out;
	}

	DMWARN(DM_MSG_PREFIX "%s path activation fail - error=0x%x",
	       path->dev->name, srq->sr_result);
	err_flags = MP_FAIL_PATH;

out:
	scsi_release_request(srq);
	dm_pg_init_complete(path, err_flags);
}

/*
 * hp_sw_get_request - Allocate an HP specific path activation request
 * @path: path on which request will be sent (needed for request queue)
 *
 * The START command is used for path activation request.
 * These arrays are controller-based failover, not LUN based.
 * One START command issued to a single path will fail over all
 * LUNs for the same controller.
 *
 * Possible optimizations
 * 1. Make timeout configurable
 * 2. Preallocate request
 */
static struct scsi_request *hp_sw_get_request(struct path *path)
{
	struct scsi_device *sdp;
	struct scsi_request *srq;

	/*
	 * Get scsi_device from sysfs struct device, then allocate the
	 * request.
	 */
	sdp = to_scsi_device(path->dev->bdev->bd_disk->driverfs_dev);

	srq = scsi_allocate_request(sdp, GFP_NOIO);
	if (!srq) {
		DMERR(DM_MSG_PREFIX "scsi_allocate_request() failed.");
		return NULL;
	}
	srq->upper_private_data = path;

	return srq;
}

/*
 * hp_sw_pg_init - HP path activation implementation.
 * @hwh: hardware handler specific data
 * @bypassed: unused; is the path group bypassed? (see dm-mpath.c)
 * @path: path to send initialization command
 *
 * Send an HP-specific path activation command on 'path'.
 * Do not try to optimize in any way, just send the activation command.
 * More than one path activation command may be sent to the same controller.
 * This seems to work fine for basic failover support.
 *
 * Possible optimizations
 * 1. Detect an in-progress activation request and avoid submitting another one
 * 2. Model the controller and only send a single activation request at a time
 * 3. Determine the state of a path before sending an activation request
 *
 * Context: kmpathd (see process_queued_ios() in dm-mpath.c)
 */
static void hp_sw_pg_init(struct hw_handler *hwh, unsigned bypassed,
			  struct path *path)
{
	struct scsi_request *srq;

	srq = hp_sw_get_request(path);
	if (!srq)
		goto retry;

	scsi_do_req(srq, cdb, NULL, 0, hp_sw_cmd_done, 60*HZ, 0);
	return;

retry:
	dm_pg_init_complete(path, MP_RETRY);
}

static int hp_sw_create(struct hw_handler *hwh, unsigned argc, char **argv)
{
	return 0;
}

static void hp_sw_destroy(struct hw_handler *hwh)
{
}

static struct hw_handler_type hp_sw_hwh = {
	.name = DM_HP_HWH_NAME,
	.module = THIS_MODULE,
	.create = hp_sw_create,
	.destroy = hp_sw_destroy,
	.pg_init = hp_sw_pg_init,
};

static int __init hp_sw_init(void)
{
	int r;

	cdb[0] = START_STOP;
	cdb[4] = 1;

	r = dm_register_hw_handler(&hp_sw_hwh);
	if (r < 0)
		DMERR(DM_MSG_PREFIX "register failed %d", r);
	else
		DMINFO(DM_MSG_PREFIX "version " DM_HP_HWH_VER " loaded");

	return r;
}

static void __exit hp_sw_exit(void)
{
	int r;

	r = dm_unregister_hw_handler(&hp_sw_hwh);
	if (r < 0)
		DMERR(DM_MSG_PREFIX "unregister failed %d", r);
}

module_init(hp_sw_init);
module_exit(hp_sw_exit);

MODULE_DESCRIPTION("DM Multipath HP StorageWorks / FSC FibreCat (A/P) support");
MODULE_AUTHOR("Mike Christie, Dave Wysochanski <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION(DM_HP_HWH_VER);

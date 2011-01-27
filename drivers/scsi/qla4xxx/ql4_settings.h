/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2006 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */

/*
 * Compile time Options:
 *            0 - Disable and 1 - Enable
 ****************************************/

/*
 * The following compile time options are temporary,
 * used for debug purposes only.
 ****************************************/
#define ISP_RESET_TEST		0 /* Issues BIG HAMMER (reset) every 3 minutes */
#define NIC_RESET_TEST		0 /* Simulates NIC card reset every 3 minutes */

/*
 * Compile time Options:
 *     0 - Disable and 1 - Enable
 */
#define	DISABLE_HBA_RESETS	0

#define ENABLE_MSI		0	/* Need kernel version 2.6.10 and newer */

#define ENABLE_ISNS		0


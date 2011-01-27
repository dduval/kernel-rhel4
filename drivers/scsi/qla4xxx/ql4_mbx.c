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
 *	qla4xxx_mailbox_command
 *	qla4xxx_mbx_test
 *	qla4xxx_send_noop
 *	qla4xxx_conn_close_sess_logout
 *	qla4xxx_clear_database_entry
 *	qla4xxx_get_fw_version
 *	qla4xxx_get_firmware_state
 *	qla4xxx_get_fwddb_entry
 *	qla4xxx_set_ddb_entry
 *	qla4xxx_get_crash_record
 *	qla4xxx_reset_lun
 *	qla4xxx_isns_enable
 *	qla4xxx_isns_disable
 *	qla4xxx_isns_status
 *	qla4xxx_get_flash
 * 	qla4xxx_restore_factory_defaults
 ****************************************************************************/

#include "ql4_def.h"

#include <linux/delay.h>

extern void qla4xxx_isns_build_entity_id(scsi_qla_host_t *ha);
extern int qla4xxx_eh_wait_for_active_target_commands(scsi_qla_host_t *ha, int target, int lun);

/**************************************************************************
 * qla4xxx_mailbox_command
 *	This routine sssue mailbox commands and waits for completion.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *	inCount	 - number of mailbox registers to load.
 *      outCount - number of mailbox registers to return.
 *      mbx_cmd  - data pointer for mailbox in registers.
 *      mbx_sts  - data pointer for mailbox out registers.
 *
 * Output:
 *      mbx_sts - returned mailbox out data.
 *
 * Remarks:
 *	If outCount is 0, this routine completes successfully WITHOUT waiting
 *	for the mailbox command to complete.
 *
 * Returns:
 *	QLA_SUCCESS - Mailbox command completed successfully
 *	QLA_ERROR   - Mailbox command competed in error.
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_mailbox_command(scsi_qla_host_t *ha,
			uint8_t inCount,
			uint8_t outCount,
			uint32_t *mbx_cmd,
			uint32_t *mbx_sts)
{
	uint8_t      status = QLA_ERROR;
	uint8_t      i;
	u_long     wait_count;
	uint32_t     intr_status;
	unsigned long flags = 0;
	DECLARE_WAITQUEUE(wait, current);


	ENTER("qla4xxx_mailbox_command");

	down(&ha->mbox_sem);


	set_bit(AF_MBOX_COMMAND, &ha->flags);


	/* Make sure that pointers are valid */
	if (!mbx_cmd || !mbx_sts) {
		QL4PRINT(QLP2,
			 printk("scsi%d: %s: Invalid mbx_cmd or mbx_sts pointer\n",
				ha->host_no, __func__));

		goto mbox_exit;
	}

	/* To prevent overwriting mailbox registers for a command that has
	 * not yet been serviced, check to see if a previously issued
	 * mailbox command is interrupting.
	 * -----------------------------------------------------------------
	 */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	intr_status = RD_REG_DWORD(&ha->reg->ctrl_status);
	if (intr_status & CSR_SCSI_PROCESSOR_INTR) {
		QL4PRINT(QLP5,
			 printk("scsi%d: %s: Trying to execute a mailbox request, "
				"while another one is interrupting\n"
				"Service existing interrupt first\n",
				ha->host_no, __func__));

		/* Service existing interrupt */
		qla4xxx_interrupt_service_routine(ha, intr_status);

		clear_bit(AF_MBOX_COMMAND_DONE, &ha->flags);
	}


	/* Send the mailbox command to the firmware
	 * ----------------------------------------
	 */
	ha->f_start = jiffies;
	ha->mbox_status_count = outCount;
	for (i=0; i < MBOX_REG_COUNT; i++) {
		ha->mbox_status[i] = 0;
	}

	for (i=0; i<inCount; i++) {
		QL4PRINT(QLP11, printk("scsi%d: %s: Mailbox In[%d]  0x%08X\n",
				       ha->host_no, __func__, i, mbx_cmd[i]));
	}

	/* Load all mailbox registers, except mailbox 0.*/
	for (i = 1; i < inCount; i++) {
		WRT_REG_DWORD(&ha->reg->mailbox[i], mbx_cmd[i]);
	}
	for (i = inCount; i < MBOX_REG_COUNT; i++) {
		WRT_REG_DWORD(&ha->reg->mailbox[i], 0);
	}

	/* Write Mailbox 0 to alert the firmware that the mailbox registers
	 * contain a command to be processed.  NOTE: We could be interrupted
	 * here if system interrupts are enabled */
	WRT_REG_DWORD(&ha->reg->mailbox[0], mbx_cmd[0]);
	PCI_POSTING(&ha->reg->mailbox[0]);
	WRT_REG_DWORD(&ha->reg->ctrl_status, SET_RMASK(CSR_INTR_RISC));
	PCI_POSTING(&ha->reg->ctrl_status);

	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	add_wait_queue(&ha->mailbox_wait_queue,&wait);

	/*
	 * If we don't want status, don't wait for the mailbox command to
	 * complete.  For example, MBOX_CMD_RESET_FW doesn't return status,
	 * you must poll the inbound Interrupt Mask for completion.
	 */
	if (outCount == 0) {
		status = QLA_SUCCESS;
		remove_wait_queue(&ha->mailbox_wait_queue,&wait);
		ha->f_end = jiffies;
		goto mbox_exit;
	}

	/*
	 * Wait for command to complete
	 * -----------------------------
	 */
	wait_count = jiffies + MBOX_TOV * HZ;
	while (test_bit(AF_MBOX_COMMAND_DONE, &ha->flags) == 0) {
		if (time_after_eq(jiffies, wait_count)) {	
			break;
		}

		spin_lock_irqsave(&ha->hardware_lock, flags);

		intr_status = RD_REG_DWORD(&ha->reg->ctrl_status);

		QL4PRINT(QLP11, printk("scsi%d: %s: INTR_STATUS = 0x%X\n",
				       ha->host_no, __func__, intr_status));

		if (intr_status & INTR_PENDING) {
			/*
			 * Service the interrupt.
			 * The ISR will save the mailbox status registers
			 * to a temporary storage location in the adapter
			 * structure.
			 */
			ha->mbox_status_count = outCount;
			qla4xxx_interrupt_service_routine(ha, intr_status);
		}
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		mdelay(10);
	} /* wait loop */

	remove_wait_queue(&ha->mailbox_wait_queue,&wait);

	/*
	 * Check for mailbox timeout
	 */
	if (!test_bit(AF_MBOX_COMMAND_DONE, &ha->flags)) {
		QL4PRINT(QLP2,
			 printk("scsi%d: Mailbox Cmd 0x%08X timed out ...,"
				" Scheduling Adapter Reset\n",
				ha->host_no, mbx_cmd[0]));

		ha->mailbox_timeout_count++;
		mbx_sts[0] = (-1);

		set_bit(DPC_RESET_HA, &ha->dpc_flags);
		goto mbox_exit;
	}

	QL4PRINT(QLP11,
		 printk("scsi%d: %s: mailbox cmd done!\n",
			ha->host_no, __func__));

	/*
	 * Copy the mailbox out registers to the caller's mailbox in/out
	 * structure.
	 */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	for (i=0; i < outCount; i++) {
		mbx_sts[i] = ha->mbox_status[i];
		QL4PRINT(QLP11,
			 printk("scsi%d: %s: Mailbox Status[%d]  0x%08X\n",
				ha->host_no, __func__, i, mbx_sts[i]));
	}

	/*
	 * Set return status and error flags (if applicable)
	 */
	switch (ha->mbox_status[0]) {
	
	case MBOX_STS_COMMAND_COMPLETE:
		status = QLA_SUCCESS;
		break;

	case MBOX_STS_INTERMEDIATE_COMPLETION:
		status = QLA_SUCCESS;
		QL4PRINT(QLP5,
			 printk("scsi%d: %s: Cmd = %08X, Intermediate completion\n",
				ha->host_no, __func__, mbx_cmd[0]));
		break;

	case MBOX_STS_BUSY:
		QL4PRINT(QLP2, printk("scsi%d: %s: Cmd = %08X, ISP BUSY\n",
				      ha->host_no, __func__, mbx_cmd[0]));

		ha->mailbox_timeout_count++;
		break;

	case MBOX_STS_COMMAND_PARAMETER_ERROR:
		break;

	case MBOX_STS_INVALID_COMMAND:
	case MBOX_STS_HOST_INTERFACE_ERROR:
	case MBOX_STS_TEST_FAILED:
	case MBOX_STS_COMMAND_ERROR:
	default:
		QL4PRINT(QLP2,
			 printk("scsi%d: %s: **** FAILED, cmd = %08X, "
				"sts = %08X ****\n",
				ha->host_no, __func__, mbx_cmd[0], mbx_sts[0]));


		__dump_registers(QLP2, ha);
		break;
	} /* switch mbox status */
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	mbox_exit:
	clear_bit(AF_MBOX_COMMAND, &ha->flags);
	clear_bit(AF_MBOX_COMMAND_DONE, &ha->flags);
	LEAVE("qla4xxx_mailbox_command");
	up(&ha->mbox_sem);

	return(status);
}


#if 0
/*
 * Mailbox commands available for testing purposes,
 * just in case we need them.
 */
uint8_t qla4xxx_send_noop(scsi_qla_host_t *ha)
{
	uint32_t   mbox_cmd[MBOX_REG_COUNT];
	uint32_t   mbox_sts[MBOX_REG_COUNT];

	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_NOP;

	if (qla4xxx_mailbox_command(ha, 1, 1, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: NOP failed\n", ha->host_no));
		return(QLA_ERROR);
	}
	else {
		QL4PRINT(QLP2, printk("scsi%d: NOP succeded\n", ha->host_no));
		return(QLA_SUCCESS);
	}
}

uint8_t qla4xxx_mbx_test(scsi_qla_host_t *ha)
{
	uint32_t   mbox_cmd[MBOX_REG_COUNT];
	uint32_t   mbox_sts[MBOX_REG_COUNT];
	int i;
	uint8_t status;

	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_REGISTER_TEST;
	mbox_cmd[1] = 0x11111111;
	mbox_cmd[2] = 0x22222222;
	mbox_cmd[3] = 0x33333333;
	mbox_cmd[4] = 0x44444444;
	mbox_cmd[5] = 0x55555555;
	mbox_cmd[6] = 0x66666666;
	mbox_cmd[7] = 0x77777777;

	if (qla4xxx_mailbox_command(ha, 8, 8, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: REGISTER_TEST failed, mbox_sts = 0x%x\n",
				      ha->host_no, mbox_sts[0]));
		return(QLA_ERROR);
	}

	if (mbox_sts[1] != 0x11111111 ||
	    mbox_sts[2] != 0x22222222 ||
	    mbox_sts[3] != 0x33333333 ||
	    mbox_sts[4] != 0x44444444 ||
	    mbox_sts[5] != 0x55555555 ||
	    mbox_sts[6] != 0x66666666 ||
	    mbox_sts[7] != 0x77777777) {
		QL4PRINT(QLP2, printk("scsi%d: REGISTER_TEST failed\n", ha->host_no));
		status = QLA_ERROR;

	}
	else {
		QL4PRINT(QLP2, printk("scsi%d: REGISTER_TEST succeded\n", ha->host_no));
		status = QLA_SUCCESS;
	}

	for (i = 0; i < 8; i++) {
		QL4PRINT(QLP2, printk("scsi%d: %s: MBX%d = 0x%x\n",
				      ha->host_no, __func__, i, mbox_cmd[i]));
	}
	return(status);
}
#endif

/*
 * qla4xxx_issue_iocb
 *	Issue IOCB using mailbox command
 *
 * Input:
 *	ha = adapter state pointer.
 *	buffer = buffer pointer.
 *	phys_addr = physical address of buffer.
 *	size = size of buffer.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
uint8_t
qla4xxx_issue_iocb(scsi_qla_host_t *ha, void*  buffer,
		   dma_addr_t phys_addr, size_t size)
{
	uint32_t   mbox_cmd[MBOX_REG_COUNT];
	uint32_t   mbox_sts[MBOX_REG_COUNT];
	uint8_t	   status;

	ENTER("qla4xxx_issue_iocb: started");

	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_EXECUTE_IOCB_A64;
	mbox_cmd[1] = 0;
	mbox_cmd[2] = LSDW(phys_addr);
	mbox_cmd[3] = MSDW(phys_addr);
	status = qla4xxx_mailbox_command(ha, 4, 1, &mbox_cmd[0], &mbox_sts[0]);

	if (status != QLA_SUCCESS) {
		/*EMPTY*/
		QL4PRINT(QLP2, printk("qla4xxx_issue_iocb(%d): failed statis 0x%x",
		    ha->host_no, status));
	} else {
		/*EMPTY*/
		LEAVE("qla4xxx_issue_iocb: exiting normally");
	}

	return status;
}

uint8_t
qla4xxx_conn_close_sess_logout(scsi_qla_host_t *ha, uint16_t fw_ddb_index,
			       uint16_t connection_id, uint16_t option)
{
	uint32_t    mbox_cmd[MBOX_REG_COUNT];
	uint32_t    mbox_sts[MBOX_REG_COUNT];

	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_CONN_CLOSE_SESS_LOGOUT;
	mbox_cmd[1] = fw_ddb_index;
	mbox_cmd[2] = connection_id;
	mbox_cmd[3] = LOGOUT_OPTION_RELOGIN;

	if (qla4xxx_mailbox_command(ha, 4, 2, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2,
			 printk("scsi%d: %s: MBOX_CMD_CONN_CLOSE_SESS_LOGOUT "
				"option %04x failed sts %04X %04X",
				ha->host_no, __func__, option,
				mbox_sts[0], mbox_sts[1]));

		if (mbox_sts[0] == 0x4005) {
			QL4PRINT(QLP2, printk(", reason %04X\n", mbox_sts[1]));
		}
		else {
			QL4PRINT(QLP2, printk("\n"));
		}
	}

	return(QLA_SUCCESS);
}

uint8_t
qla4xxx_clear_database_entry(scsi_qla_host_t *ha, uint16_t fw_ddb_index)
{
	uint32_t    mbox_cmd[MBOX_REG_COUNT];
	uint32_t    mbox_sts[MBOX_REG_COUNT];

	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_CLEAR_DATABASE_ENTRY;
	mbox_cmd[1] = fw_ddb_index;

	if (qla4xxx_mailbox_command(ha, 2, 5, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2,
		    printk("scsi%d: %s: MBOX_CMD_CLEAR_DATABASE_ENTRY "
		    "failed sts %04X index [%d], state %04x\n",
		    ha->host_no, __func__, mbox_sts[0], fw_ddb_index,
		    mbox_sts[4]));
		return(QLA_ERROR);
	}

	return(QLA_SUCCESS);
}

uint8_t
qla4xxx_set_ifcb(scsi_qla_host_t *ha, uint32_t *mbox_cmd, uint32_t *mbox_sts,
		 dma_addr_t init_fw_cb_dma)
{
	ENTER(__func__);

	memset(mbox_cmd, 0, sizeof(mbox_cmd[0]) * MBOX_REG_COUNT);
	memset(mbox_sts, 0, sizeof(mbox_sts[0]) * MBOX_REG_COUNT);
	mbox_cmd[0] = MBOX_CMD_INITIALIZE_FIRMWARE;
	mbox_cmd[1] = 0;
	mbox_cmd[2] = LSDW(init_fw_cb_dma);
	mbox_cmd[3] = MSDW(init_fw_cb_dma);
	if (ha->ifcb_size > LEGACY_IFCB_SIZE){
		mbox_cmd[4] = ha->ifcb_size;
		mbox_cmd[5] = (IFCB_VER_MAX << 8) | IFCB_VER_MIN;
	}
	if (qla4xxx_mailbox_command(ha, 6, 6, mbox_cmd, mbox_sts)
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: %s: "
		    "MBOX_CMD_INITIALIZE_FIRMWARE failed w/ status %04X\n",
		    ha->host_no, __func__, mbox_sts[0]));
		{
			int i;
			for (i=0; i<MBOX_REG_COUNT; i++) {
                                QL4PRINT(QLP2, printk("mbox_cmd[%d] = %08x,     "
                                       "mbox_sts[%d] = %08x\n",
                                       i, mbox_cmd[i], i, mbox_sts[i]));
			}
		}
		LEAVE(__func__);
		return (QLA_ERROR);
	}
	LEAVE(__func__);
	return (QLA_SUCCESS);
}

uint8_t
qla4xxx_get_ifcb(scsi_qla_host_t *ha, uint32_t *mbox_cmd, uint32_t *mbox_sts,
		 dma_addr_t init_fw_cb_dma)
{
	ENTER(__func__);

	memset(mbox_cmd, 0, sizeof(mbox_cmd[0]) * MBOX_REG_COUNT);
	memset(mbox_sts, 0, sizeof(mbox_sts[0]) * MBOX_REG_COUNT);
	mbox_cmd[0] = MBOX_CMD_GET_INIT_FW_CTRL_BLOCK;
	mbox_cmd[2] = LSDW(init_fw_cb_dma);
	mbox_cmd[3] = MSDW(init_fw_cb_dma);
	if (init_fw_cb_dma != 0 && ha->ifcb_size > LEGACY_IFCB_SIZE){
		mbox_cmd[4] = ha->ifcb_size;
	}

	if (qla4xxx_mailbox_command(ha, 5, 5, mbox_cmd, mbox_sts)
	    != QLA_SUCCESS) {

		if (init_fw_cb_dma == 0 &&
		    mbox_sts[0] == MBOX_STS_COMMAND_PARAMETER_ERROR)
		{
			LEAVE(__func__);
			return (QLA_SUCCESS);
		}

		QL4PRINT(QLP2, printk("scsi%d: %s: "
                        "MBOX_CMD_GET_INIT_FW_CTRL_BLOCK failed w/ status %04X\n",
                        ha->host_no, __func__, mbox_sts[0]));
		{
			int i;
			for (i=0; i<MBOX_REG_COUNT; i++) {
                                QL4PRINT(QLP2, printk("mbox_cmd[%d] = %08x,     "
                                       "mbox_sts[%d] = %08x\n",
                                       i, mbox_cmd[i], i, mbox_sts[i]));
			}
		}
		LEAVE(__func__);
		return (QLA_ERROR);
	}
	LEAVE(__func__);
	return (QLA_SUCCESS);
}

/**************************************************************************
 * qla4xxx_get_dhcp_ip_address
 *	This routine retrieves the IP Address obtained via DHCP for the
 *	specified adapter.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully obtained DHCP IP Address
 *	QLA_ERROR   - Failed to obtained
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_get_dhcp_ip_address(scsi_qla_host_t *ha)
{
	ADDRESS_CTRL_BLK  *init_fw_cb;
	dma_addr_t	  init_fw_cb_dma;
	uint32_t     	  mbox_cmd[MBOX_REG_COUNT];
	uint32_t     	  mbox_sts[MBOX_REG_COUNT];
	uint8_t 	  ip_addr_str[IP_ADDR_STR_SIZE];

	ENTER(__func__);

	init_fw_cb = pci_alloc_consistent(ha->pdev, ha->ifcb_size,
	  &init_fw_cb_dma);
	if (init_fw_cb == NULL) {
		printk("scsi%d: %s: Unable to alloc init_cb\n", ha->host_no,
		    __func__);
		LEAVE(__func__);
		return 10;
	}

	/*
	 * Get Initialize Firmware Control Block
	 */
	memset(init_fw_cb, 0, ha->ifcb_size);
	if (qla4xxx_get_ifcb(ha, &mbox_cmd[0], &mbox_sts[0], init_fw_cb_dma)
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2,
			 printk("scsi%d: %s: Failed to get init_fw_ctrl_blk\n",
				ha->host_no, __func__));
		pci_free_consistent(ha->pdev, ha->ifcb_size,
		    init_fw_cb, init_fw_cb_dma);
		LEAVE(__func__);
		return QLA_ERROR;
	}

	if ((ha->acb_version == ACB_NOT_SUPPORTED) || IS_IPv4_ENABLED(ha)) {
		/*
		 * Save IPv4 Address
		 */
		memcpy(ha->ip_address, init_fw_cb->IPAddr,
		    MIN(sizeof(ha->ip_address), sizeof(init_fw_cb->IPAddr)));
		memcpy(ha->subnet_mask, init_fw_cb->SubnetMask,
		    MIN(sizeof(ha->subnet_mask), sizeof(init_fw_cb->SubnetMask)));
		memcpy(ha->gateway, init_fw_cb->GatewayIPAddr,
		    MIN(sizeof(ha->gateway), sizeof(init_fw_cb->GatewayIPAddr)));

		IPv4Addr2Str(ha->ip_address, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "IP Address            %s\n",
		    ha->host_no, __func__, &ip_addr_str[0]));
		
		IPv4Addr2Str(ha->subnet_mask, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "Subnet Mask           %s\n",
		    ha->host_no, __func__, &ip_addr_str[0]));
		
		IPv4Addr2Str(ha->gateway, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
		    "Default Gateway       %s\n",
		    ha->host_no, __func__, &ip_addr_str[0]));
	}
	if (IS_IPv6_ENABLED(ha)) {
		/*
		 * Save IPv6 Address
		 */

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
			"IPv6 Link Local       %s\n",
			ha->host_no, __func__, &ip_addr_str[0]));

		IPv6Addr2Str(ha->ipv6_addr0, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
			"IPv6 IP Address0      %s\n",
			ha->host_no, __func__, &ip_addr_str[0]));

		IPv6Addr2Str(ha->ipv6_addr1, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
			"IPv6 IP Address1      %s\n",
			ha->host_no, __func__, &ip_addr_str[0]));

		IPv6Addr2Str(ha->ipv6_default_router_addr, &ip_addr_str[0]);
		QL4PRINT(QLP7, printk("scsi%d: %s: "
			"IPv6 Default Router   %s\n",
			ha->host_no, __func__, &ip_addr_str[0]));
	}

	pci_free_consistent(ha->pdev, ha->ifcb_size, init_fw_cb,
	    init_fw_cb_dma);

	LEAVE(__func__);
	return QLA_SUCCESS;
}

/**************************************************************************
 * qla4xxx_get_firmware_state
 *	This routine retrieves the firmware state for the specified adapter.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully retrieved firmware state
 *	QLA_ERROR   - Failed to retrieve firmware state
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_get_firmware_state(scsi_qla_host_t *ha)
{
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];

	ENTER("qla4xxx_get_firmware_state");

	/* Get firmware version */
	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_GET_FW_STATE;
	if (qla4xxx_mailbox_command(ha, 1, 4, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2,
			 printk("scsi%d: %s: MBOX_CMD_GET_FW_STATE failed w/ "
				"status %04X\n",
				ha->host_no, __func__, mbox_sts[0]));
		return(QLA_ERROR);
	}

	ha->firmware_state = mbox_sts[1];
	ha->board_id       = mbox_sts[2];
	ha->addl_fw_state  = mbox_sts[3];
	DEBUG2(printk("scsi%d: %s firmware_state=0x%x\n",
		      ha->host_no, __func__, ha->firmware_state);)
	LEAVE("qla4xxx_get_firmware_state");
	return(QLA_SUCCESS);
}

/**************************************************************************
 * qla4xxx_get_firmware_status
 *	This routine retrieves the firmware status for the specified adapter.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully retrieved firmware status
 *	QLA_ERROR   - Failed to retrieve firmware status
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_get_firmware_status(scsi_qla_host_t *ha)
{
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];

	ENTER(__func__);

	/* Get firmware version */
	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_GET_FW_STATUS;
	if (qla4xxx_mailbox_command(ha, 1, 3, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2,
			 printk("scsi%d: %s: MBOX_CMD_GET_FW_STATUS failed w/ "
				"status %04X\n",
				ha->host_no, __func__, mbox_sts[0]));
		return(QLA_ERROR);
	}

	/* High-water mark of IOCBs */
	ha->iocb_hiwat = mbox_sts[2];
	if (ha->iocb_hiwat > IOCB_HIWAT_CUSHION)
		ha->iocb_hiwat -= IOCB_HIWAT_CUSHION;
	else
		ql4_printk(KERN_INFO, ha, "WARNING!!!  You have less "
			   "than %d firmare IOCBs available (%d).\n",
			   IOCB_HIWAT_CUSHION, ha->iocb_hiwat);

	LEAVE(__func__);
	return(QLA_SUCCESS);
}

/**************************************************************************
 * qla4xxx_get_fwddb_entry
 *	This routine retrieves the firmware's device database entry.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *      fw_ddb_index - Firmware's device database index
 *      fw_ddb_entry - Pointer to firmware's device database entry structure
 *      num_valid_ddb_entries - Pointer to number of valid ddb entries
 *      next_ddb_index - Pointer to next valid device database index
 *      fw_ddb_device_state - Pointer to device state
 *
 * Output:
 *      fw_ddb_entry - Fills in structure if pointer is supplied
 *      num_valid_ddb_entries - Fills in if pointer is supplied
 *      next_ddb_index - Fills in if pointer is supplied
 *      fw_ddb_device_state - Fills in if pointer is supplied
 *
 * Returns:
 *	QLA_SUCCESS - Successfully retrieved ddb info from firmware
 *	QLA_ERROR   - Failed to retrieve ddb info from firmware
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_get_fwddb_entry(scsi_qla_host_t *ha,
		      uint16_t        fw_ddb_index,
		      DEV_DB_ENTRY    *fw_ddb_entry,
		      dma_addr_t      fw_ddb_entry_dma,
		      uint32_t        *num_valid_ddb_entries,
		      uint32_t        *next_ddb_index,
		      uint32_t        *fw_ddb_device_state,
		      uint32_t        *conn_err_detail,
		      uint16_t        *tcp_source_port_num,
		      uint16_t        *connection_id)
{
	uint8_t         status = QLA_ERROR;
	uint32_t	mbox_cmd[MBOX_REG_COUNT];
	uint32_t	mbox_sts[MBOX_REG_COUNT];
	uint8_t 	ip_addr_str[IP_ADDR_STR_SIZE];

	ENTER(__func__);

	/* Make sure the device index is valid */
	if (fw_ddb_index >= MAX_DDB_ENTRIES) {
		DEBUG2( printk("scsi%d: %s: index [%d] out of range.\n",
				ha->host_no, __func__, fw_ddb_index));
		goto exit_get_fwddb;
	}

	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_GET_DATABASE_ENTRY;
	mbox_cmd[1] = (uint32_t) fw_ddb_index;
	mbox_cmd[2] = LSDW(fw_ddb_entry_dma);
	mbox_cmd[3] = MSDW(fw_ddb_entry_dma);

	if (qla4xxx_mailbox_command(ha, 4, 7, &mbox_cmd[0], &mbox_sts[0])
	    == QLA_ERROR) {
		DEBUG2(printk("scsi%d: %s: MBOX_CMD_GET_DATABASE_ENTRY failed "
		    "with status 0x%04X\n",
		    ha->host_no, __func__, mbox_sts[0]));
		goto exit_get_fwddb;
	}

	if (fw_ddb_index != mbox_sts[1]) {
		DEBUG2(printk("scsi%d: %s: index mismatch [%d] != [%d].\n",
		    ha->host_no, __func__, fw_ddb_index,
		    mbox_sts[1]));
		goto exit_get_fwddb;
	}

	if (fw_ddb_entry) {
		if ((fw_ddb_entry->options & DDB_OPT_IPv6_DEVICE) != 0)	{
			IPv6Addr2Str(fw_ddb_entry->RemoteIPAddr, &ip_addr_str[0]);
		} else {
			IPv4Addr2Str(fw_ddb_entry->RemoteIPAddr, &ip_addr_str[0]);
		}

		ql4_printk(KERN_INFO, ha,
		    "DDB[%d] MB0 %04x Tot %d Next %d "
		    "State %04x ConnErr %08x %s:%04d \"%s\"\n",
		    fw_ddb_index,
		    mbox_sts[0], mbox_sts[2], mbox_sts[3], mbox_sts[4], mbox_sts[5],
		    &ip_addr_str[0],
		    le16_to_cpu(fw_ddb_entry->RemoteTCPPortNumber),
		    fw_ddb_entry->iscsiName);
	}

	if (num_valid_ddb_entries)
		*num_valid_ddb_entries = mbox_sts[2];

	if (next_ddb_index)
		*next_ddb_index = mbox_sts[3];

	if (fw_ddb_device_state)
		*fw_ddb_device_state = mbox_sts[4];
	/* RA: This mailbox has been changed to pass connection error and details.
	 * Its true for ISP4010 as per Version E - Not sure when it was changed.
	 * Get the defaultTime2wait from the fw_dd_entry field : defaultTime2wait which
 	 * we call it as minTime2Wait DEV_DB_ENTRY struct.
	 */
	if (conn_err_detail)
		*conn_err_detail = mbox_sts[5];

	if (tcp_source_port_num)
		*tcp_source_port_num = (uint16_t) mbox_sts[6] >> 16;

	if (connection_id)
		*connection_id = (uint16_t) mbox_sts[6] & 0x00FF;

	status = QLA_SUCCESS;

exit_get_fwddb:
	LEAVE(__func__);
	return(status);
}


/**************************************************************************
 * qla4xxx_set_fwddb_entry
 *	This routine initializes or updates the adapter's device database
 *	entry for the specified device.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *      fw_ddb_index - Firmware's device database index
 *      fw_ddb_entry - Pointer to firmware's device database entry
 *		       structure, or NULL.
 *
 * Output:
 *	None
 *
 * Remarks:
 *	This routine also triggers a login for the specified device.
 *	Therefore, it may also be used as a secondary login routine when
 *	a NULL pointer is specified for the fw_ddb_entry.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully set ddb_entry in firmware
 *	QLA_ERROR   - Failed to set ddb_entry in firmware
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_set_ddb_entry(scsi_qla_host_t *ha,
		      uint16_t        fw_ddb_index,
		      DEV_DB_ENTRY    *fw_ddb_entry,
		      dma_addr_t      fw_ddb_entry_dma)
{
	uint8_t         status = QLA_ERROR;
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];

	ENTER("qla4xxx_set_fwddb_entry");

	QL4PRINT(QLP7, printk("scsi%d: %s: index [%d]\n",
			      ha->host_no, __func__, fw_ddb_index));

	/* Do not wait for completion. The firmware will send us an
	 * ASTS_DATABASE_CHANGED (0x8014) to notify us of the login status.
	 */
	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_SET_DATABASE_ENTRY;
	mbox_cmd[1] = (uint32_t) fw_ddb_index;
	mbox_cmd[2] = LSDW(fw_ddb_entry_dma);
	mbox_cmd[3] = MSDW(fw_ddb_entry_dma);

	status = qla4xxx_mailbox_command(ha, 4, 1, &mbox_cmd[0], &mbox_sts[0]);
	if (status == QLA_SUCCESS) {
		QL4PRINT(QLP7, printk("scsi%d: %s: mbx[0] = 0x%04x\n",
				      ha->host_no, __func__, mbox_sts[0]));
	}

	LEAVE("qla4xxx_set_fwddb_entry");
	return(status);
}

/**************************************************************************
 * qla4xxx_get_crash_record
 *	This routine retrieves a crash record from the QLA4010 after an
 *	8002h aen.
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
qla4xxx_get_crash_record(scsi_qla_host_t *ha)
{
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];
	CRASH_RECORD    *crash_record = NULL;
	dma_addr_t      crash_record_dma = 0;
	uint32_t        crash_record_size = 0;

	ENTER("qla4xxx_get_crash_record");
	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_cmd));

	/*
	 * Get size of crash record
	 */
	mbox_cmd[0] = MBOX_CMD_GET_CRASH_RECORD;

	if (qla4xxx_mailbox_command(ha, 5, 5, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: %s: ERROR: Unable to retrieve size!\n",
				      ha->host_no, __func__));
		goto exit_get_crash_record;
	}

	crash_record_size = mbox_sts[4];
	if (crash_record_size == 0) {
		QL4PRINT(QLP2, printk("scsi%d: %s: ERROR: Crash record size is 0!\n",
				      ha->host_no, __func__));
		goto exit_get_crash_record;
	}

	/*
	 * Alloc Memory for Crash Record
	 */
	crash_record = (CRASH_RECORD *) pci_alloc_consistent(ha->pdev,
						crash_record_size,
						&crash_record_dma);

	if (crash_record == NULL){
		QL4PRINT(QLP2, printk("scsi%d: %s: ERROR: Unable to allocate "
				      " memory (%d bytes) for crash record!\n",
				      ha->host_no, __func__, crash_record_size));
		goto exit_get_crash_record;
	}

	/*
	 * Get Crash Record
	 */
	mbox_cmd[0] = MBOX_CMD_GET_CRASH_RECORD;
	mbox_cmd[2] = LSDW(crash_record_dma);
	mbox_cmd[3] = MSDW(crash_record_dma);
	mbox_cmd[4] = crash_record_size;

	if (qla4xxx_mailbox_command(ha, 5, 5, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: %s: ERROR: Unable to retrieve crash"
				      " record!\n", ha->host_no, __func__));
		goto exit_get_crash_record;
	}

	/*
	 * Dump Crash Record
	 */
	QL4PRINT(QLP1, printk("scsi%d: Crash Record Dump:\n",
			      ha->host_no));
	QL4PRINT( QLP1,
		  printk("Firmware Version: %02d.%02d.%02d.%02d\n",
			 crash_record->fw_major_version,
			 crash_record->fw_minor_version,
			 crash_record->fw_patch_version,
			 crash_record->fw_build_version));
	QL4PRINT(QLP1, printk("Build Date: %s\n",
			      crash_record->build_date));
	QL4PRINT(QLP1, printk("Build Time: %s\n",
			      crash_record->build_time));
	QL4PRINT(QLP1, printk("Build User: %s\n",
			      crash_record->build_user));
	QL4PRINT(QLP1, printk("Card Serial #: %s\n",
			      crash_record->card_serial_num));
	QL4PRINT(QLP1, printk("Time of Crash (in seconds): %d (0x%x)\n",
			crash_record->time_of_crash_in_secs,
			crash_record->time_of_crash_in_secs));
	QL4PRINT(QLP1, printk("Time of Crash (in milliseconds): "
			"%d (0x%x)\n",
			crash_record->time_of_crash_in_ms,
			crash_record->time_of_crash_in_ms));
	QL4PRINT(QLP1, printk("# frames in OUT RISC processor stack dump: "
			"%d (0x%x)\n",
			crash_record->out_RISC_sd_num_frames,
			crash_record->out_RISC_sd_num_frames));
	QL4PRINT(QLP1, printk("# words in OAP stack dump: %d (0x%x)\n",
			crash_record->OAP_sd_num_words,
			crash_record->OAP_sd_num_words));
	QL4PRINT(QLP1, printk("# frames in IAP stack dump: %d (0x%x)\n",
			crash_record->IAP_sd_num_frames,
			crash_record->IAP_sd_num_frames));
	QL4PRINT(QLP1, printk("# words in IN RISC processor stack dump: "
			"%d (0x%x)\n",
			crash_record->in_RISC_sd_num_words,
			crash_record->in_RISC_sd_num_words));
	QL4PRINT(QLP1, printk("\nOUT RISC processor register dump:\n"));
	qla4xxx_dump_dwords(QLP1, &crash_record->out_RISC_reg_dump,
			    sizeof(crash_record->out_RISC_reg_dump));
	QL4PRINT(QLP1, printk("\nIN RISC processor register dump:\n"));
	qla4xxx_dump_dwords(QLP1, &crash_record->in_RISC_reg_dump,
			    sizeof(crash_record->in_RISC_reg_dump));
	QL4PRINT(QLP1, printk("\nOUT RISC processor stack dump:\n"));
	qla4xxx_dump_dwords(QLP1, &crash_record->in_out_RISC_stack_dump,
			    crash_record->OAP_sd_num_words);
	QL4PRINT(QLP1, printk("\nIN RISC processor stack dump:\n"));
	qla4xxx_dump_dwords(QLP1, &crash_record->in_out_RISC_stack_dump[0] +
			    crash_record->OAP_sd_num_words,
			    crash_record->in_RISC_sd_num_words);


	exit_get_crash_record:
	if (crash_record)
		pci_free_consistent(ha->pdev,
				    crash_record_size,
				    crash_record,
				    crash_record_dma);
	LEAVE("qla4xxx_get_crash_record");
}

/**************************************************************************
 * qla4xxx_get_conn_event_log
 *	This routine retrieves the connection event log
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
qla4xxx_get_conn_event_log(scsi_qla_host_t *ha)
{
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];
	CONN_EVENT_LOG_ENTRY    *event_log = NULL;
	dma_addr_t      event_log_dma = 0;
	uint32_t        event_log_size = 0;
	uint32_t	num_valid_entries;
	uint32_t	oldest_entry = 0;
	uint32_t	max_event_log_entries;
	uint8_t		i;

	ENTER(__func__);
	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_cmd));

	/*
	 * Get size of crash record
	 */
	mbox_cmd[0] = MBOX_CMD_GET_CONN_EVENT_LOG;

	if (qla4xxx_mailbox_command(ha, 4, 5, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: %s: ERROR: Unable to retrieve size!\n",
				      ha->host_no, __func__));
		goto exit_get_event_log;
	}

	event_log_size = mbox_sts[4];
	if (event_log_size == 0) {
		QL4PRINT(QLP2, printk("scsi%d: %s: ERROR: Event log size is 0!\n",
				      ha->host_no, __func__));
		goto exit_get_event_log;
	}

	/*
	 * Alloc Memory for Crash Record
	 */
	event_log = (CONN_EVENT_LOG_ENTRY *) pci_alloc_consistent(ha->pdev,
						event_log_size,
						&event_log_dma);

	if (event_log == NULL){
		QL4PRINT(QLP2, printk("scsi%d: %s: ERROR: Unable to allocate "
				      " memory (%d bytes) for event log!\n",
				      ha->host_no, __func__, event_log_size));
		goto exit_get_event_log;
	}

	/*
	 * Get Crash Record
	 */
	mbox_cmd[0] = MBOX_CMD_GET_CONN_EVENT_LOG;
	mbox_cmd[2] = LSDW(event_log_dma);
	mbox_cmd[3] = MSDW(event_log_dma);

	if (qla4xxx_mailbox_command(ha, 4, 5, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: %s: ERROR: Unable to retrieve "
				      "event log!\n", ha->host_no, __func__));
		goto exit_get_event_log;
	}

	/*
	 * Dump Event Log
	 */
	num_valid_entries = mbox_sts[1];
	max_event_log_entries = event_log_size / sizeof(CONN_EVENT_LOG_ENTRY);

	if (num_valid_entries > max_event_log_entries)
		oldest_entry = num_valid_entries % max_event_log_entries;

	QL4PRINT(QLP1, printk("scsi%d: Connection Event Log Dump (%d entries):\n",
			      ha->host_no, num_valid_entries));

	if (ql_dbg_level & QLP1) {
		if (oldest_entry == 0) {
			/* Circular Buffer has not wrapped around */
			for (i=0; i < num_valid_entries; i++) {
				qla4xxx_dump_buffer((uint8_t *)event_log+
						    (i*sizeof(*event_log)),
						    sizeof(*event_log));
			}
		}
		else {
			/* Circular Buffer has wrapped around - display accordingly*/
			for (i=oldest_entry; i < max_event_log_entries; i++) {
				qla4xxx_dump_buffer((uint8_t *)event_log+
						    (i*sizeof(*event_log)),
						    sizeof(*event_log));
			}
			for (i=0; i < oldest_entry; i++) {
				qla4xxx_dump_buffer((uint8_t *)event_log+
						    (i*sizeof(*event_log)),
						    sizeof(*event_log));
			}
		}
	}

	exit_get_event_log:
	if (event_log)
		pci_free_consistent(ha->pdev,
				    event_log_size,
				    event_log,
				    event_log_dma);
	LEAVE(__func__);
}

/**************************************************************************
 * qla4xxx_reset_lun
 *	This routine performs a LUN RESET on the specified target/lun.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *	ddb_entry - Pointer to device database entry
 *	lun_entry - Pointer to lun entry structure
 *
 * Remarks:
 *	The caller must ensure that the ddb_entry and lun_entry pointers
 *	are valid before calling this routine.
 *
 * Returns:
 *	QLA_SUCCESS - lun reset completed successfully
 *	QLA_ERROR   - lun reset failed
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_reset_lun(scsi_qla_host_t *ha,
		  ddb_entry_t *ddb_entry,
		  fc_lun_t *lun_entry)
{
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];
	uint8_t target = ddb_entry->target;
	uint8_t lun = lun_entry->lun;
	uint8_t status = QLA_SUCCESS;

	ENTER("qla4xxx_reset_lun");

	//spin_unlock_irq(ha->host->host_lock);

	QL4PRINT(QLP2, printk("scsi%d:%d:%d:%d: lun reset issued\n",
			      ha->host_no, ddb_entry->bus, target, lun));

	/*
	 * Send lun reset command to ISP, so that the ISP will return all
	 * outstanding requests with RESET status
	 */
	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_LUN_RESET;
	mbox_cmd[1] = ddb_entry->fw_ddb_index;
	mbox_cmd[2] = lun << 8;
	mbox_cmd[5] = 0x01; /* Immediate Command Enable */

	qla4xxx_mailbox_command(ha, 6, 1, &mbox_cmd[0], &mbox_sts[0]);
	if ((mbox_sts[0] == MBOX_STS_COMMAND_COMPLETE) ||
	    (mbox_sts[0] == MBOX_STS_COMMAND_ERROR)) {
		QL4PRINT(QLP2, printk(
		    "scsi%d:%d:%d:%d: lun reset SUCCEEDED\n", ha->host_no,
		    ddb_entry->bus, target, lun));
	} else {
		QL4PRINT(QLP2, printk(
		    "scsi%d:%d:%d:%d: lun reset FAILED w/ status %04x\n",
		    ha->host_no, ddb_entry->bus, target, lun, mbox_sts[0]));

		status = QLA_ERROR;
	}

	//spin_lock_irq(ha->host->host_lock);

	LEAVE("qla4xxx_reset_lun");

	return (status);
}

#if ENABLE_ISNS
uint8_t
qla4xxx_isns_enable(scsi_qla_host_t *ha,
		    uint32_t isns_ip_addr,
		    uint16_t isns_server_port_num)
{
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];

	QL4PRINT(QLP20, printk("scsi%d: %s: isns_ip_addr %08x\n",
			       ha->host_no, __func__, isns_ip_addr));

	qla4xxx_isns_build_entity_id(ha);

	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_SET_ISNS_SERVICE;
	mbox_cmd[1] = ISNS_ENABLE;
	mbox_cmd[2] = isns_ip_addr;
	mbox_cmd[3] = isns_server_port_num;

	if (qla4xxx_mailbox_command(ha, 4, 6, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2,
			 printk("scsi%d: %s: MBOX_CMD_SET_ISNS_SERVICE failed "
				"w/ status %04X %04X\n",
				ha->host_no, __func__, mbox_sts[0], mbox_sts[1]));
		return(QLA_ERROR);
	}

	QL4PRINT(QLP7|QLP20, printk("scsi%d: Start iSNS Service "
				    "%d.%d.%d.%d Port %04d . . .\n", ha->host_no,
				    (isns_ip_addr & 0x000000FF),
				    (isns_ip_addr & 0x0000FF00) >> 8,
				    (isns_ip_addr & 0x00FF0000) >> 16,
				    (isns_ip_addr & 0xFF000000) >> 24,
				    isns_server_port_num));

	return(QLA_SUCCESS);
}

uint8_t
qla4xxx_isns_disable(scsi_qla_host_t *ha)
{
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];

	if (test_bit(ISNS_FLAG_ISNS_SRV_ENABLED, &ha->isns_flags)) {
		memset(&mbox_cmd, 0, sizeof(mbox_cmd));
		memset(&mbox_sts, 0, sizeof(mbox_sts));
		mbox_cmd[0] = MBOX_CMD_SET_ISNS_SERVICE;
		mbox_cmd[1] = ISNS_DISABLE;

		if (qla4xxx_mailbox_command(ha, 2, 2, &mbox_cmd[0], &mbox_sts[0])
		    != QLA_SUCCESS) {
			QL4PRINT(QLP2,
				 printk("scsi%d: %s: MBOX_CMD_SET_ISNS_SERVICE failed "
					"w/ status %04X %04X\n",
					ha->host_no, __func__, mbox_sts[0], mbox_sts[1]));
			return(QLA_ERROR);
		}
	}

	clear_bit(ISNS_FLAG_ISNS_SRV_ENABLED, &ha->isns_flags);
	ISNS_CLEAR_FLAGS(ha);

	ha->isns_connection_id   = 0;
	//ha->isns_scn_conn_id     = 0;
	//ha->isns_esi_conn_id     = 0;
	//ha->isns_nsh_conn_id     = 0;

	ha->isns_remote_port_num = 0;
	ha->isns_scn_port_num    = 0;
	ha->isns_esi_port_num    = 0;
	ha->isns_nsh_port_num    = 0;

	ha->isns_num_discovered_targets = 0;
	memset(ha->isns_entity_id, 0, sizeof(ha->isns_entity_id));
	return(QLA_SUCCESS);
}

uint8_t
qla4xxx_isns_status(scsi_qla_host_t *ha)
{
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];

	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_SET_ISNS_SERVICE;
	mbox_cmd[1] = ISNS_STATUS;

	if (qla4xxx_mailbox_command(ha, 2, 2, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2,
			 printk("scsi%d: %s: MBOX_CMD_SET_ISNS_SERVICE failed "
				"w/ status %04X %04X\n",
				ha->host_no, __func__, mbox_sts[0], mbox_sts[1]));
		return(QLA_ERROR);
	}

	QL4PRINT(QLP20, printk("scsi%d: %s: = %s\n",
			       ha->host_no, __func__,
			       ((mbox_sts[1] & 1) == 0) ? "DISABLED" : "ENABLED"));
	return(QLA_SUCCESS);
}
#endif

uint8_t
qla4xxx_get_flash(scsi_qla_host_t *ha, dma_addr_t dma_addr, uint32_t offset, uint32_t len)
{
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];

	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));

	mbox_cmd[0] = MBOX_CMD_READ_FLASH;
	mbox_cmd[1] = LSDW(dma_addr);
	mbox_cmd[2] = MSDW(dma_addr);
	mbox_cmd[3] = offset;
	mbox_cmd[4] = len;

	if (qla4xxx_mailbox_command(ha, 5, 2, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: %s: MBOX_CMD_READ_FLASH, failed w/ "
				      "status %04X %04X, offset %08x, len %08x\n",
				      ha->host_no, __func__, mbox_sts[0], mbox_sts[1],
				      offset, len));
		return(QLA_ERROR);
	}
	return(QLA_SUCCESS);
}

/**************************************************************************
 * qla4xxx_get_fw_version
 *	This routine retrieves the firmware version for the specified adapter.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Output:
 *	None
 *
 * Remarks:
 *	In QLA4010, mailboxes 2 & 3 may hold an address for data.  Make sure
 *	that we write 0 to those mailboxes, if unused.
 *
 * Returns:
 *	QLA_SUCCESS - Successfully retrieved firmware version
 *	QLA_ERROR   - Failed to retrieve firmware version
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_get_fw_version(scsi_qla_host_t *ha)
{
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];

	/*
	 * Get firmware version
	 */
	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_ABOUT_FW;
	if (qla4xxx_mailbox_command(ha, 4, 5, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: %s: MBOX_CMD_ABOUT_FW failed w/ "
				      "status %04X\n",
				      ha->host_no, __func__, mbox_sts[0]));
		return(QLA_ERROR);
	}

	/*
	 * Save firmware version information
	 */
	ha->firmware_version[0] = mbox_sts[1];
	ha->firmware_version[1] = mbox_sts[2];
	ha->patch_number        = mbox_sts[3];
	ha->build_number        = mbox_sts[4];

	QL4PRINT(QLP7, printk("scsi%d: FW Version %02d.%02d Patch %02d Build %02d\n",
			      ha->host_no, ha->firmware_version[0], ha->firmware_version[1],
			      ha->patch_number, ha->build_number));

	return(QLA_SUCCESS);
}

/**************************************************************************
 * qla4xxx_restore_factory_defaults
 *	This routine restores the factory defaults for the specified adapter.
 *
 * Input:
 * 	ha - Pointer to host adapter structure.
 *
 * Output:
 *	None
 *
 * Returns:
 *	QLA_SUCCESS - Successfully restored defaults
 *	QLA_ERROR   - Failed to restore defaults
 *
 * Context:
 *	Kernel context.
 **************************************************************************/
uint8_t
qla4xxx_restore_factory_defaults(scsi_qla_host_t *ha,
				 uint32_t block_mask,
				 uint32_t ifcb_mask1,
				 uint32_t ifcb_mask2)
{
	uint32_t mbox_cmd[MBOX_REG_COUNT];
	uint32_t mbox_sts[MBOX_REG_COUNT];

	memset(&mbox_cmd, 0, sizeof(mbox_cmd));
	memset(&mbox_sts, 0, sizeof(mbox_sts));
	mbox_cmd[0] = MBOX_CMD_RESTORE_FACTORY_DEFAULTS;
	mbox_cmd[3] = block_mask;
        mbox_cmd[4] = ifcb_mask1;
        mbox_cmd[5] = ifcb_mask2;

	if (qla4xxx_mailbox_command(ha, 6, 1, &mbox_cmd[0], &mbox_sts[0])
	    != QLA_SUCCESS) {
		QL4PRINT(QLP2, printk("scsi%d: %s: MBOX_CMD_RESTORE_FACTORY_DEFAULTS"
				      " failed w/ status %04X\n",
				      ha->host_no, __func__, mbox_sts[0]));
		return(QLA_ERROR);
	}

	return(QLA_SUCCESS);
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


/*
 *                  QLOGIC LINUX SOFTWARE
 *
 * QLogic ISP2x00 device driver for Linux 2.6.x
 * Copyright (C) 2003-2005 QLogic Corporation
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
 */
#include "qim_def.h"
#include "exioctln.h"
#include "exioct.h"
#include "inioct.h"

#include <linux/delay.h>

/* qim_sup.c */
extern int
qim_down_timeout(struct semaphore *, unsigned long);


/*
 * qim_mbx_sem_timeout
 *	Issue mailbox command and waits for completion.
 *
 * Input:
 *	ha = adapter block pointer.
 *	mcp = driver internal mbx struct pointer.
 *
 * Output:
 *	mb[MAX_MAILBOX_REGISTER_COUNT] = returned mailbox data.
 *
 * Returns:
 *	0 : QLA_SUCCESS = cmd performed success
 *	1 : QLA_FUNCTION_FAILED   (error encountered)
 *	6 : QLA_FUNCTION_TIMEOUT (timeout condition encountered)
 *
 * Context:
 *	Kernel context.
 */
static void
qim_mbx_sem_timeout(unsigned long data)
{
	struct semaphore	*sem_ptr = (struct semaphore *)data;

	DEBUG11(printk("qim_sem_timeout: entered.\n");)

	if (sem_ptr != NULL) {
		up(sem_ptr);
	}

	DEBUG11(printk("qim_mbx_sem_timeout: exiting.\n");)
}

static int
qim_mailbox_command(struct scsi_qla_host *dr_ha, mbx_cmd_t *mcp)
{
	int		rval;
	unsigned long	flags = 0;
	struct device_reg_2xxx __iomem *reg = &dr_ha->iobase->isp;
	struct device_reg_24xx __iomem *reg24 = &dr_ha->iobase->isp24;
	struct timer_list tmp_intr_timer;
	uint8_t		abort_active;
	uint8_t		io_lock_on = dr_ha->flags.init_done;
	uint16_t	command;
	uint16_t	*iptr;
	uint16_t __iomem *optr;
	uint32_t	cnt;
	uint32_t	mboxes;
	unsigned long	mbx_flags = 0;


	rval = QLA_SUCCESS;
	abort_active = test_bit(ABORT_ISP_ACTIVE, &dr_ha->dpc_flags);

	DEBUG11(printk("%s(%ld): entered.\n", __func__, dr_ha->host_no);)

	/*
	 * Wait for active mailbox commands to finish by waiting at most tov
	 * seconds. This is to serialize actual issuing of mailbox cmds during
	 * non ISP abort time.
	 */
	if (!abort_active) {
		if (qim_down_timeout(&dr_ha->mbx_cmd_sem, mcp->tov * HZ)) {
			/* Timeout occurred. Return error. */
			DEBUG2_3_11(printk("%s(%ld): cmd access timeout. "
			    "Exiting.\n", __func__, dr_ha->host_no);)
			return QLA_FUNCTION_TIMEOUT;
		}
	} else {
		/* return error */
		DEBUG2_3_11(printk("%s(%ld): abort in progress. "
		    "Exiting.\n", __func__, dr_ha->host_no);)
		return QLA_BUSY;
	}

	dr_ha->flags.mbox_busy = 1;
	/* Save mailbox command for debug */
	dr_ha->mcp = mcp;

	/* Try to get mailbox register access */
	abort_active = test_bit(ABORT_ISP_ACTIVE, &dr_ha->dpc_flags);
	if (!abort_active && io_lock_on) {
		spin_lock_irqsave(&dr_ha->mbx_reg_lock, mbx_flags);
	} else {
		/* return error */
		DEBUG2_3_11(printk("%s(%ld): abort in progress. Exiting. "
		    "abort_active=%d.\n",
		    __func__, dr_ha->host_no, abort_active);)
		return QLA_BUSY;
	}

	DEBUG11(printk("scsi(%ld): prepare to issue mbox cmd=0x%x.\n",
	    dr_ha->host_no, mcp->mb[0]);)

	spin_lock_irqsave(&dr_ha->hardware_lock, flags);

	/* Load mailbox registers. */
	if (IS_FWI2_CAPABLE(dr_ha)) {
		reg24 = &dr_ha->iobase->isp24;
		optr = (uint16_t __iomem *)&reg24->mailbox0;
	} else {
		reg = &dr_ha->iobase->isp;
		optr = (uint16_t __iomem *)MAILBOX_REG(dr_ha, reg, 0);
	}

	DEBUG11(printk("scsi(%ld): mbx_count = %d.\n",
	    dr_ha->host_no, dr_ha->mbx_count);)

	iptr = mcp->mb;
	command = mcp->mb[0];
	mboxes = mcp->out_mb;

	for (cnt = 0; cnt < dr_ha->mbx_count; cnt++) {
		if (IS_QLA2200(dr_ha) && cnt == 8)
			optr = (uint16_t __iomem *)MAILBOX_REG(dr_ha, reg, 8);
		if (mboxes & BIT_0)
			WRT_REG_WORD(optr, *iptr);

		mboxes >>= 1;
		optr++;
		iptr++;
	}

#if 0
	printk("%s(%ld): Loaded MBX registers (displayed in bytes) = \n",
	    __func__, dr_ha->host_no);
	qim_dump_buffer((uint8_t *)mcp->mb, 16);
	printk("\n");
	qim_dump_buffer(((uint8_t *)mcp->mb + 0x10), 16);
	printk("\n");
	qim_dump_buffer(((uint8_t *)mcp->mb + 0x20), 8);
	printk("\n");
	printk("%s(%ld): I/O address = %p.\n", __func__, ha->host_no, optr);
	qim_dump_regs(dr_ha);
#endif

	/* Issue set host interrupt command to send cmd out. */
	dr_ha->flags.mbox_int = 0;
	clear_bit(MBX_INTERRUPT, &dr_ha->mbx_cmd_flags);

	/* Unlock mbx registers and wait for interrupt */
	DEBUG11(printk("%s(%ld): going to unlock irq & waiting for interrupt. "
	    "jiffies=%lx.\n", __func__, dr_ha->host_no, jiffies);)

	/* Wait for mbx cmd completion until timeout */

	/* sleep on completion semaphore */
	DEBUG11(printk("%s(%ld): INTERRUPT MODE. Initializing timer.\n",
	    __func__, dr_ha->host_no);)

	init_timer(&tmp_intr_timer);
	tmp_intr_timer.data = (unsigned long)&dr_ha->mbx_intr_sem;
	tmp_intr_timer.expires = jiffies + mcp->tov * HZ;
	tmp_intr_timer.function =
	    (void (*)(unsigned long))qim_mbx_sem_timeout;

	DEBUG11(printk("%s(%ld): Adding timer.\n", __func__,
	    dr_ha->host_no);)
	add_timer(&tmp_intr_timer);

	DEBUG11(printk("%s(%ld): going to unlock & sleep. "
	    "time=0x%lx.\n", __func__, dr_ha->host_no, jiffies);)

	set_bit(MBX_INTR_WAIT, &dr_ha->mbx_cmd_flags);

	if (IS_FWI2_CAPABLE(dr_ha))
		WRT_REG_DWORD(&reg24->hccr, HCCRX_SET_HOST_INT);
	else
		WRT_REG_WORD(&reg->hccr, HCCR_SET_HOST_INT);

	spin_unlock_irqrestore(&dr_ha->hardware_lock, flags);

	if (!abort_active)
		spin_unlock_irqrestore(&dr_ha->mbx_reg_lock, mbx_flags);

	/* Wait for either the timer to expire
	 * or the mbox completion interrupt
	 */
	down(&dr_ha->mbx_intr_sem);

	DEBUG11(printk("%s(%ld): waking up. time=0x%lx\n", __func__,
	    dr_ha->host_no, jiffies);)
	clear_bit(MBX_INTR_WAIT, &dr_ha->mbx_cmd_flags);

	/* delete the timer */
	del_timer(&tmp_intr_timer);


	/* Check whether we timed out */
	spin_lock_irqsave(&dr_ha->mbx_reg_lock, mbx_flags);

	if (dr_ha->flags.mbox_int) {
		uint16_t *iptr2;

		DEBUG3_11(printk("%s(%ld): cmd %x completed.\n", __func__,
		    dr_ha->host_no, command);)

		/* Got interrupt. Clear the flag. */
		dr_ha->flags.mbox_int = 0;
		clear_bit(MBX_INTERRUPT, &dr_ha->mbx_cmd_flags);

		if (dr_ha->mailbox_out[0] != MBS_COMMAND_COMPLETE) {
			/*
			qim_stats.mboxerr++;
			*/
			rval = QLA_FUNCTION_FAILED;
		}

		/* Load return mailbox registers. */
		iptr2 = mcp->mb;
		iptr = (uint16_t *)&dr_ha->mailbox_out[0];
		mboxes = mcp->in_mb;
		for (cnt = 0; cnt < dr_ha->mbx_count; cnt++) {
			if (mboxes & BIT_0)
				*iptr2 = *iptr;

			mboxes >>= 1;
			iptr2++;
			iptr++;
		}
	} else {

		uint16_t mb0;
		uint32_t ictrl;

		if (IS_FWI2_CAPABLE(dr_ha)) {
			mb0 = RD_REG_WORD(&reg24->mailbox0);
			ictrl = RD_REG_DWORD(&reg24->ictrl);
		} else {
			mb0 = RD_MAILBOX_REG(dr_ha, reg, 0);
			ictrl = RD_REG_WORD(&reg->ictrl);
		}

		printk("%s(%ld): **** MB Command Timeout for cmd %x ****\n",
		    __func__, dr_ha->host_no, command);
		printk("%s(%ld): icontrol=%x jiffies=%lx\n", __func__,
		    dr_ha->host_no, ictrl, jiffies);
		printk("%s(%ld): *** mailbox[0] = 0x%x ***\n", __func__,
		    dr_ha->host_no, mb0);
#if 0
		qim_dump_regs(dr_ha);
#endif

		/*
		qim_stats.mboxtout++;
		*/
		dr_ha->total_mbx_timeout++;
		rval = QLA_FUNCTION_TIMEOUT;
	}

	spin_unlock_irqrestore(&dr_ha->mbx_reg_lock, mbx_flags);

	dr_ha->flags.mbox_busy = 0;

	/* Clean up */
	dr_ha->mcp = NULL;

	/* Allow next mbx cmd to come in. */
	up(&dr_ha->mbx_cmd_sem);

	if (rval) {
		DEBUG2_3_11(printk("%s(%ld): **** FAILED. mbx0=%x, mbx1=%x, "
		    "mbx2=%x, cmd=%x ****\n", __func__, dr_ha->host_no,
		    mcp->mb[0], mcp->mb[1], mcp->mb[2], command);)
	} else {
		DEBUG11(printk("%s(%ld): done.\n", __func__, dr_ha->host_no);)
	}

	return rval;
}

/*
 * qim_get_link_status
 *
 * Input:
 *	ha = adapter block pointer.
 *	loop_id = device loop ID.
 *	ret_buf = pointer to link status return buffer.
 *
 * Returns:
 *	0 = success.
 *	BIT_0 = mem alloc error.
 *	BIT_1 = mailbox error.
 */
uint8_t
qim_get_link_status(struct qla_host_ioctl *ioctlha, uint16_t loop_id,
    uint16_t optbits, link_stat_t *ret_buf, uint16_t *status)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	link_stat_t *stat_buf;
	dma_addr_t stat_buf_dma;
	struct scsi_qla_host *ha = ioctlha->dr_data;

	DEBUG11(printk("%s(%ld): entered.\n", __func__, ha->host_no);)

	stat_buf = dma_pool_alloc(ha->s_dma_pool, GFP_ATOMIC, &stat_buf_dma);
	if (stat_buf == NULL) {
		DEBUG2_3_11(printk("%s(%ld): Failed to allocate memory.\n",
		    __func__, ha->host_no));
		return BIT_0;
	}

	memset(stat_buf, 0, sizeof(link_stat_t));
	DEBUG11(printk("%s(%ld): going to send mailbox cmd.\n",
	    __func__, ha->host_no);)

	mcp->mb[0] = MBC_GET_LINK_STATUS;
	mcp->mb[2] = MSW(stat_buf_dma);
	mcp->mb[3] = LSW(stat_buf_dma);
	mcp->mb[6] = MSW(MSD(stat_buf_dma));
	mcp->mb[7] = LSW(MSD(stat_buf_dma));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	mcp->in_mb = MBX_0;

	if (IS_FWI2_CAPABLE(ha)) {
		mcp->mb[1] = loop_id;
		mcp->mb[4] = 0;
		mcp->mb[10] = optbits;
		mcp->out_mb |= MBX_10|MBX_4|MBX_1;
		mcp->in_mb |= MBX_1;
	} else if (HAS_EXTENDED_IDS(ha)) {
		mcp->mb[1] = loop_id;
		mcp->mb[10] = optbits;
		mcp->out_mb |= MBX_10|MBX_1;
		DEBUG11(printk(
		    "%s(%ld): extended id=%x mb1=%x mb6=%x mb10=%x.\n",
		    __func__, ha->host_no, loop_id, mcp->mb[1],
		    mcp->mb[6], mcp->mb[10]);)
	} else {
		mcp->mb[1] = (optbits & 0xff) | loop_id << 8;
		mcp->out_mb |= MBX_1;
		DEBUG11(printk("%s(%ld): id=%x.\n",
		    __func__, ha->host_no, mcp->mb[1]);)
	}

	mcp->tov = 30;
	mcp->flags = IOCTL_CMD;
	rval = qim_mailbox_command(ha, mcp);

	if (rval != QLA_FUNCTION_TIMEOUT) {
		if (mcp->mb[0] != MBS_COMMAND_COMPLETE) {
			DEBUG2_3_11(printk(
			    "%s(%ld): cmd failed=%x. mbx0=%x mbx1=%x.\n",
			    __func__, ha->host_no, rval, mcp->mb[0],
			    mcp->mb[1]);)
			status[0] = mcp->mb[0];
			rval = BIT_1;
		} else {
			/* copy over data -- firmware data is LE. */
			ret_buf->link_fail_cnt =
			    le32_to_cpu(stat_buf->link_fail_cnt);
			ret_buf->loss_sync_cnt =
			    le32_to_cpu(stat_buf->loss_sync_cnt);
			ret_buf->loss_sig_cnt =
			    le32_to_cpu(stat_buf->loss_sig_cnt);
			ret_buf->prim_seq_err_cnt =
			    le32_to_cpu(stat_buf->prim_seq_err_cnt);
			ret_buf->inval_xmit_word_cnt =
			    le32_to_cpu(stat_buf->inval_xmit_word_cnt);
			ret_buf->inval_crc_cnt =
			    le32_to_cpu(stat_buf->inval_crc_cnt);

			DEBUG11(printk("%s(%ld): stat dump: fail_cnt=%d "
			    "loss_sync=%d loss_sig=%d seq_err=%d "
			    "inval_xmt_word=%d inval_crc=%d.\n", __func__,
			    ha->host_no, stat_buf->link_fail_cnt,
			    stat_buf->loss_sync_cnt, stat_buf->loss_sig_cnt,
			    stat_buf->prim_seq_err_cnt,
			    stat_buf->inval_xmit_word_cnt,
			    stat_buf->inval_crc_cnt);)
		}
	} else {
		/* Failed. */
		DEBUG2_3_11(printk("%s(%ld): failed=%x.\n", __func__,
		    ha->host_no, rval);)
		rval = BIT_1;
	}

	dma_pool_free(ha->s_dma_pool, stat_buf, stat_buf_dma);

	return rval;
}

uint8_t
qim_get_isp_stats(struct qla_host_ioctl *ioctlha, uint32_t *dwbuf,
    uint32_t dwords, uint16_t optbits, uint16_t *status)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;
	uint32_t *sbuf, *siter;
	dma_addr_t sbuf_dma;
	struct scsi_qla_host *ha = ioctlha->dr_data;


	DEBUG11(printk("%s(%ld): entered.\n", __func__, ha->host_no);)

	if (dwords > (DMA_POOL_SIZE / 4)) {
		DEBUG2_3_11(printk("%s(%ld): Unabled to retrieve %d DWORDs "
		    "(max %d).\n", __func__, ha->host_no, dwords,
		    DMA_POOL_SIZE / 4));
		return BIT_0;
	}
	sbuf = dma_pool_alloc(ha->s_dma_pool, GFP_ATOMIC, &sbuf_dma);
	if (sbuf == NULL) {
		DEBUG2_3_11(printk("%s(%ld): Failed to allocate memory.\n",
		    __func__, ha->host_no));
		return BIT_0;
	}
	memset(sbuf, 0, DMA_POOL_SIZE);

	mcp->mb[0] = MBC_GET_LINK_PRIV_STATS;
	mcp->mb[2] = MSW(sbuf_dma);
	mcp->mb[3] = LSW(sbuf_dma);
	mcp->mb[6] = MSW(MSD(sbuf_dma));
	mcp->mb[7] = LSW(MSD(sbuf_dma));
	mcp->mb[8] = dwords;
	mcp->mb[10] = optbits;
	mcp->out_mb = MBX_10|MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	mcp->tov = 30;
	mcp->flags = IOCTL_CMD;
	rval = qim_mailbox_command(ha, mcp);

	if (rval != QLA_FUNCTION_TIMEOUT) {
		if (mcp->mb[0] != MBS_COMMAND_COMPLETE) {
			DEBUG2_3_11(printk("%s(%ld): cmd failed. mbx0=%x.\n",
			    __func__, ha->host_no, mcp->mb[0]));
			status[0] = mcp->mb[0];
			rval = BIT_1;
		} else {
			/* Copy over data -- firmware data is LE. */
			siter = sbuf;
			while (dwords--)
				*dwbuf++ = le32_to_cpu(*siter++);
		}
	} else {
		/* Failed. */
		DEBUG2_3_11(printk("%s(%ld): failed=%x.\n", __func__,
		    ha->host_no, rval));
		rval = BIT_1;
	}

	dma_pool_free(ha->s_dma_pool, sbuf, sbuf_dma);

	return rval;
}

int
qim_issue_iocb_timeout(scsi_qla_host_t *ha, void*  buffer, dma_addr_t phys_addr,
    size_t size, uint32_t tov)
{
	int		rval;
	mbx_cmd_t	mc;
	mbx_cmd_t	*mcp = &mc;

	mcp->mb[0] = MBC_IOCB_COMMAND_A64;
	mcp->mb[1] = 0;
	mcp->mb[2] = MSW(phys_addr);
	mcp->mb[3] = LSW(phys_addr);
	mcp->mb[6] = MSW(MSD(phys_addr));
	mcp->mb[7] = LSW(MSD(phys_addr));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_2|MBX_0;
	mcp->tov = tov;
	mcp->flags = 0;
	rval = qim_mailbox_command(ha, mcp);

	if (rval != QLA_SUCCESS) {
		/*EMPTY*/
		DEBUG2_11(printk("qim_issue_iocb(%ld): failed rval 0x%x\n",
		    ha->host_no,rval);)
	} else {
		sts_entry_t *sts_entry = (sts_entry_t *) buffer;

		/* Mask reserved bits. */
		if (IS_FWI2_CAPABLE(ha))
			sts_entry->entry_status &= RF_MASK_24XX;
		else
			sts_entry->entry_status &= RF_MASK;
	}

	return rval;
}

int
qim_issue_iocb(scsi_qla_host_t *ha, void *buffer, dma_addr_t phys_addr,
    size_t size)
{
	return qim_issue_iocb_timeout(ha, buffer, phys_addr, size,
	    MBX_TOV_SECONDS);
}

int
qim24xx_login_fabric(scsi_qla_host_t *ha, uint16_t loop_id, uint8_t domain,
    uint8_t area, uint8_t al_pa, uint16_t *mb, uint8_t opt)
{
	int		rval;

	struct logio_entry_24xx *lg;
	dma_addr_t	lg_dma;
	uint32_t	iop[2];

	DEBUG11(printk("%s(%ld): entered.\n", __func__, ha->host_no);)

	lg = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &lg_dma);
	if (lg == NULL) {
		DEBUG2_3(printk("%s(%ld): failed to allocate Login IOCB.\n",
		    __func__, ha->host_no));
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(lg, 0, sizeof(struct logio_entry_24xx));

	lg->entry_type = LOGINOUT_PORT_IOCB_TYPE;
	lg->entry_count = 1;
	lg->nport_handle = cpu_to_le16(loop_id);
	lg->control_flags = __constant_cpu_to_le16(LCF_COMMAND_PLOGI);
	if (opt & BIT_0)
		lg->control_flags |= __constant_cpu_to_le16(LCF_COND_PLOGI);
	lg->port_id[0] = al_pa;
	lg->port_id[1] = area;
	lg->port_id[2] = domain;
	rval = qim_issue_iocb(ha, lg, lg_dma, 0);
	if (rval != QLA_SUCCESS) {
		DEBUG2_3_11(printk("%s(%ld): failed to issue Login IOCB "
		    "(%x).\n", __func__, ha->host_no, rval);)
	} else if (lg->entry_status != 0) {
		DEBUG2_3_11(printk("%s(%ld): failed to complete IOCB "
		    "-- error status (%x).\n", __func__, ha->host_no,
		    lg->entry_status));
		rval = QLA_FUNCTION_FAILED;
	} else if (lg->comp_status != __constant_cpu_to_le16(CS_COMPLETE)) {
		iop[0] = le32_to_cpu(lg->io_parameter[0]);
		iop[1] = le32_to_cpu(lg->io_parameter[1]);

		DEBUG2_3_11(printk("%s(%ld): failed to complete IOCB "
		    "-- completion status (%x)  ioparam=%x/%x.\n", __func__,
		    ha->host_no, le16_to_cpu(lg->comp_status), iop[0],
		    iop[1]));

		switch (iop[0]) {
		case LSC_SCODE_PORTID_USED:
			mb[0] = MBS_PORT_ID_USED;
			mb[1] = LSW(iop[1]);
			break;
		case LSC_SCODE_NPORT_USED:
			mb[0] = MBS_LOOP_ID_USED;
			break;
		case LSC_SCODE_NOLINK:
		case LSC_SCODE_NOIOCB:
		case LSC_SCODE_NOXCB:
		case LSC_SCODE_CMD_FAILED:
		case LSC_SCODE_NOFABRIC:
		case LSC_SCODE_FW_NOT_READY:
		case LSC_SCODE_NOT_LOGGED_IN:
		case LSC_SCODE_NOPCB:
		case LSC_SCODE_ELS_REJECT:
		case LSC_SCODE_CMD_PARAM_ERR:
		case LSC_SCODE_NONPORT:
		case LSC_SCODE_LOGGED_IN:
		case LSC_SCODE_NOFLOGI_ACC:
		default:
			mb[0] = MBS_COMMAND_ERROR;
			break;
		}
	} else {
		DEBUG11(printk("%s(%ld): done.\n", __func__, ha->host_no);)

		iop[0] = le32_to_cpu(lg->io_parameter[0]);

		mb[0] = MBS_COMMAND_COMPLETE;
		mb[1] = 0;
		if (iop[0] & BIT_4) {
			if (iop[0] & BIT_8)
				mb[1] |= BIT_1;
		} else
			mb[1] = BIT_0;
	}

	dma_pool_free(ha->s_dma_pool, lg, lg_dma);

	return rval;
}

/*
 * qim_login_fabric
 *	Issue login fabric port mailbox command.
 *
 * Input:
 *	ha = adapter block pointer.
 *	loop_id = device loop ID.
 *	domain = device domain.
 *	area = device area.
 *	al_pa = device AL_PA.
 *	status = pointer for return status.
 *	opt = command options.
 *	TARGET_QUEUE_LOCK must be released.
 *	ADAPTER_STATE_LOCK must be released.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qim_login_fabric(scsi_qla_host_t *ha, uint16_t loop_id, uint8_t domain,
    uint8_t area, uint8_t al_pa, uint16_t *mb, uint8_t opt)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	if (IS_FWI2_CAPABLE(ha))
		return qim24xx_login_fabric(ha, loop_id, domain, area, al_pa,
		    mb, opt);

	DEBUG11(printk("qim_login_fabric(%ld): entered.\n", ha->host_no);)

	mcp->mb[0] = MBC_LOGIN_FABRIC_PORT;
	mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	if (HAS_EXTENDED_IDS(ha)) {
		mcp->mb[1] = loop_id;
		mcp->mb[10] = opt;
		mcp->out_mb |= MBX_10;
	} else {
		mcp->mb[1] = (loop_id << 8) | opt;
	}
	mcp->mb[2] = domain;
	mcp->mb[3] = area << 8 | al_pa;

	mcp->in_mb = MBX_7|MBX_6|MBX_2|MBX_1|MBX_0;
	mcp->tov = (ha->login_timeout * 2) + (ha->login_timeout / 2);
	mcp->flags = 0;
	rval = qim_mailbox_command(ha, mcp);

	/* Return mailbox statuses. */
	if (mb != NULL) {
		mb[0] = mcp->mb[0];
		mb[1] = mcp->mb[1];
		mb[2] = mcp->mb[2];
		mb[6] = mcp->mb[6];
		mb[7] = mcp->mb[7];
	}

	if (rval != QLA_SUCCESS) {
		/* RLU tmp code: need to change main mailbox_command function to
		 * return ok even when the mailbox completion value is not
		 * SUCCESS. The caller needs to be responsible to interpret
		 * the return values of this mailbox command if we're not
		 * to change too much of the existing code.
		 */
		if (mcp->mb[0] == 0x4001 || mcp->mb[0] == 0x4002 ||
		    mcp->mb[0] == 0x4003 || mcp->mb[0] == 0x4005 ||
		    mcp->mb[0] == 0x4006)
			rval = QLA_SUCCESS;

		/*EMPTY*/
		DEBUG2_3_11(printk("qim_login_fabric(%ld): failed=%x "
		    "mb[0]=%x mb[1]=%x mb[2]=%x.\n", ha->host_no, rval,
		    mcp->mb[0], mcp->mb[1], mcp->mb[2]);)
	} else {
		/*EMPTY*/
		DEBUG11(printk("qim_login_fabric(%ld): done.\n",
		    ha->host_no);)
	}

	return rval;
}

int
qim_loopback_test(struct qla_host_ioctl *ha, INT_LOOPBACK_REQ *req,
    uint16_t *ret_mb)
{
	int		rval;
	mbx_cmd_t	mc;
	mbx_cmd_t	*mcp = &mc;

	DEBUG11(printk("qim_send_loopback: req.Options=%x iterations=%x "
	    "MAILBOX_CNT=%d.\n", req->Options, req->IterationCount,
	    MAILBOX_REGISTER_COUNT);)

	memset(mcp->mb, 0 , sizeof(mcp->mb));

	mcp->mb[0] = MBC_DIAGNOSTIC_LOOP_BACK;
	mcp->mb[1] = req->Options | MBX_6;
	mcp->mb[10] = LSW(req->TransferCount);
	mcp->mb[11] = MSW(req->TransferCount);
	mcp->mb[14] = LSW(ha->ioctl_mem_phys); /* send data address */
	mcp->mb[15] = MSW(ha->ioctl_mem_phys);
	mcp->mb[20] = LSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[21] = MSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[16] = LSW(ha->ioctl_mem_phys); /* rcv data address */
	mcp->mb[17] = MSW(ha->ioctl_mem_phys);
	mcp->mb[6] = LSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[7] = MSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[18] = LSW(req->IterationCount); /* iteration count lsb */
	mcp->mb[19] = MSW(req->IterationCount); /* iteration count msb */
	mcp->out_mb = MBX_21|MBX_20|MBX_19|MBX_18|MBX_17|MBX_16|MBX_15|
	    MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_7|MBX_6|MBX_1|MBX_0;
	mcp->in_mb = MBX_19|MBX_18|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->buf_size = req->TransferCount;
	mcp->flags = MBX_DMA_OUT|MBX_DMA_IN|IOCTL_CMD;
	mcp->tov = 30;
	rval = qim_mailbox_command(ha->dr_data, mcp);

	/* Always copy back return mailbox values. */
	memcpy((void *)ret_mb, (void *)mcp->mb, sizeof(mcp->mb));

	if (rval != QLA_SUCCESS) {
		/* Empty. */
		DEBUG2_3_11(printk(
		    "qim_loopback_test(%ld): mailbox command FAILED=%x.\n",
		    ha->host_no, mcp->mb[0]);)
	} else {
		/* Empty. */
		DEBUG11(printk(
		    "qim_loopback_test(%ld): done.\n", ha->host_no);)
	}

	return rval;
}

int
qim_echo_test(struct qla_host_ioctl *ha, INT_LOOPBACK_REQ *req,
    uint16_t *ret_mb)
{
	int		rval;
	mbx_cmd_t	mc;
	mbx_cmd_t	*mcp = &mc;

	memset(mcp->mb, 0 , sizeof(mcp->mb));

	mcp->mb[0] = MBC_DIAGNOSTIC_ECHO;
	mcp->mb[1] = BIT_6; /* use 64bit DMA addr */
	mcp->mb[10] = req->TransferCount;
	mcp->mb[14] = LSW(ha->ioctl_mem_phys); /* send data address */
	mcp->mb[15] = MSW(ha->ioctl_mem_phys);
	mcp->mb[20] = LSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[21] = MSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[16] = LSW(ha->ioctl_mem_phys); /* rcv data address */
	mcp->mb[17] = MSW(ha->ioctl_mem_phys);
	mcp->mb[6] = LSW(MSD(ha->ioctl_mem_phys));
	mcp->mb[7] = MSW(MSD(ha->ioctl_mem_phys));
	mcp->out_mb = MBX_21|MBX_20|MBX_17|MBX_16|MBX_15|MBX_14|MBX_10|
	    MBX_7|MBX_6|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->buf_size = req->TransferCount;
	mcp->flags = MBX_DMA_OUT|MBX_DMA_IN|IOCTL_CMD;
	mcp->tov = 30;
	rval = qim_mailbox_command(ha->dr_data, mcp);

	/* Always copy back return mailbox values. */
	memcpy((void *)ret_mb, (void *)mcp->mb, sizeof(mcp->mb));

	if (rval != QLA_SUCCESS) {
		/* Empty. */
		DEBUG2_3_11(printk(
		    "%s(%ld): mailbox command FAILED=%x/%x.\n", __func__,
		    ha->host_no, mcp->mb[0], mcp->mb[1]);)
	} else {
		/* Empty. */
		DEBUG11(printk("%s(%ld): done.\n", __func__, ha->host_no);)
	}

	return rval;
}

/*
 * qim_set_rnid_params_mbx
 *	Set RNID parameters using mailbox command
 *
 * Input:
 *	ha = adapter state pointer.
 *	buffer = buffer pointer.
 *	buf_size = size of buffer.
 *	mb_reg = pointer to return mailbox registers.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qim_set_rnid_params_mbx(scsi_qla_host_t *ha, dma_addr_t buf_phys_addr,
    size_t buf_size, uint16_t *mb_reg)
{
	int		rval;
	mbx_cmd_t	mc;
	mbx_cmd_t	*mcp = &mc;

	DEBUG11(printk("qim_set_rnid_params_mbx(%ld): entered.\n",
	    ha->host_no);)

	mcp->mb[0] = MBC_SET_RNID_PARAMS;
	mcp->mb[1] = 0;
	mcp->mb[2] = MSW(buf_phys_addr);
	mcp->mb[3] = LSW(buf_phys_addr);
	mcp->mb[6] = MSW(MSD(buf_phys_addr));
	mcp->mb[7] = LSW(MSD(buf_phys_addr));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->buf_size = buf_size;
	mcp->flags = MBX_DMA_OUT;
	mcp->tov = 30;
	rval = qim_mailbox_command(ha, mcp);

	if (rval != QLA_SUCCESS) {
		memcpy(mb_reg, mcp->mb, 2 * 2); /* 2 status regs */

		DEBUG2_3_11(printk("qim_set_rnid_params_mbx(%ld): "
		    "failed=%x mb[1]=%x.\n", ha->host_no, mcp->mb[0],
		    mcp->mb[1]);)
	} else {
		/*EMPTY*/
		DEBUG11(printk("qim_set_rnid_params_mbx(%ld): done.\n",
		    ha->host_no);)
	}

	return (rval);
}

/*
 * qim_get_rnid_params_mbx
 *	Get RNID parameters using mailbox command
 *
 * Input:
 *	ha = adapter state pointer.
 *	buffer = buffer pointer.
 *	buf_size = size of buffer.
 *	mb_reg = pointer to return mailbox registers.
 *
 * Returns:
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
qim_get_rnid_params_mbx(scsi_qla_host_t *ha, dma_addr_t buf_phys_addr,
    size_t buf_size, uint16_t *mb_reg)
{
	int		rval;
	mbx_cmd_t	mc;
	mbx_cmd_t	*mcp = &mc;

	DEBUG11(printk("qim_get_rnid_params_mbx(%ld): entered.\n",
	    ha->host_no);)

	mcp->mb[0] = MBC_GET_RNID_PARAMS;
	mcp->mb[1] = 0;
	mcp->mb[2] = MSW(buf_phys_addr);
	mcp->mb[3] = LSW(buf_phys_addr);
	mcp->mb[6] = MSW(MSD(buf_phys_addr));
	mcp->mb[7] = LSW(MSD(buf_phys_addr));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->buf_size = buf_size;
	mcp->flags = MBX_DMA_IN;
	mcp->tov = 30;
	rval = qim_mailbox_command(ha, mcp);

	if (rval != QLA_SUCCESS) {
		memcpy(mb_reg, mcp->mb, 2 * 2); /* 2 status regs */

		DEBUG2_3_11(printk("qim_get_rnid_params_mbx(%ld): "
		    "failed=%x mb[1]=%x.\n", ha->host_no, mcp->mb[0],
		    mcp->mb[1]);)
	} else {
		/*EMPTY*/
		DEBUG11(printk("qim_get_rnid_params_mbx(%ld): done.\n",
		    ha->host_no);)
	}

	return (rval);
}


int
qim84xx_reset_chip(struct scsi_qla_host *ha, uint16_t enable_diagnostic,
    uint16_t *cmd_status)
{
	int rval;
	mbx_cmd_t mc;
	mbx_cmd_t *mcp = &mc;

	DEBUG16(printk("%s(%ld): enable_diag=%d entered.\n", __func__,
	    ha->host_no, enable_diagnostic));

	mcp->mb[0] = MBC_ISP84XX_RESET;
	mcp->mb[1] = enable_diagnostic;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->tov = 30;
	mcp->flags = 0;
	rval = qim_mailbox_command(ha, mcp);

	/* Return mailbox statuses. */
	*cmd_status = mcp->mb[0];
	if (rval != QLA_SUCCESS)
		DEBUG16(printk("%s(%ld): failed=%x.\n", __func__, ha->host_no,
		    rval));
	else
		DEBUG16(printk("%s(%ld): done.\n", __func__, ha->host_no));

	return rval;
}

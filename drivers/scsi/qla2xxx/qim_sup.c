/******************************************************************************
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
 ******************************************************************************/

#include "qim_def.h"

int qim24xx_write_flash_data(scsi_qla_host_t *ha, uint32_t *dwptr, uint32_t faddr,
			     uint32_t dwords);
uint32_t *qim24xx_read_flash_data(scsi_qla_host_t *ha, uint32_t *dwptr,
				  uint32_t faddr, uint32_t dwords);

/*
 * The ISP2312 v2 chip cannot access the FLASH/GPIO registers via MMIO in an
 * 133Mhz slot.
 */
#define RD_REG_WORD_PIO(addr)		(inw((unsigned long)addr))
#define WRT_REG_WORD_PIO(addr, data)	(outw(data,(unsigned long)addr))

#define QIM_IS_OEM_001(ha) \
	((ha)->pdev->device == PCI_DEVICE_ID_QLOGIC_ISP2322 && \
	(ha)->pdev->subsystem_vendor == 0x1028 && \
	(ha)->pdev->subsystem_device == 0x0170)

inline void
qla2xxx_schedule_udelay(unsigned long usecs)
{
	schedule();
	udelay(usecs);
}

inline void 
qim_enable_intrs(scsi_qla_host_t *ha)
{
	unsigned long flags = 0;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;
	struct device_reg_24xx __iomem *reg24 = &ha->iobase->isp24;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	if (IS_FWI2_CAPABLE(ha)) {
		reg24 = (struct device_reg_24xx __iomem *)ha->iobase;
		WRT_REG_DWORD(&reg24->ictrl, ICRX_EN_RISC_INT);
		RD_REG_DWORD(&reg24->ictrl);
	} else {
		WRT_REG_WORD(&reg->ictrl, ICR_EN_INT | ICR_EN_RISC);
		RD_REG_WORD(&reg->ictrl);
	}
	ha->interrupts_on = 1;
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

}

inline void 
qim_disable_intrs(scsi_qla_host_t *ha)
{
	unsigned long flags = 0;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;
	struct device_reg_24xx __iomem *reg24 = &ha->iobase->isp24;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	ha->interrupts_on = 0;
	if (IS_FWI2_CAPABLE(ha)) {
		reg24 = (struct device_reg_24xx __iomem *)ha->iobase;
		WRT_REG_DWORD(&reg24->ictrl, 0);
		RD_REG_DWORD(&reg24->ictrl);

	} else {
		WRT_REG_WORD(&reg->ictrl, 0);
		RD_REG_WORD(&reg->ictrl);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
}


static __inline__ uint16_t qim_debounce_register(volatile uint16_t __iomem *);
/*
 * qim_debounce_register
 *      Debounce register.
 *
 * Input:
 *      port = register address.
 *
 * Returns:
 *      register value.
 */
static __inline__ uint16_t
qim_debounce_register(volatile uint16_t __iomem *addr) 
{
	volatile uint16_t first;
	volatile uint16_t second;

	do {
		first = RD_REG_WORD(addr);
		barrier();
		cpu_relax();
		second = RD_REG_WORD(addr);
	} while (first != second);

	return (first);
}

static inline uint32_t
flash_conf_to_access_addr(uint32_t faddr)
{
	return FARX_ACCESS_FLASH_CONF | faddr;
}

static inline uint32_t
flash_data_to_access_addr(uint32_t faddr)
{
	return FARX_ACCESS_FLASH_DATA | faddr;
}

/* qim_cmd_wait
 *	Stall driver until all outstanding commands are returned.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Return;
 *  0 -- Done
 *  1 -- cmds still outstanding
 *
 * Context:
 *  This routine must be called without hardware_lock held.
 */
int
qim_cmd_wait(scsi_qla_host_t *ha) 
{
	int status = 0;
	int index = 0;
#if 0
	int wait_cnt = 30; 
#endif
	unsigned long cpu_flags;


	DEBUG(printk("%s(%ld): entered\n",__func__,ha->host_no));
	printk("%s(%ld): entered\n",__func__,ha->host_no);

#if 0
	while (wait_cnt) {
#endif
		/* Find a command that hasn't completed. */
		for (index = 1; index < MAX_OUTSTANDING_COMMANDS; index++) {
			spin_lock_irqsave(&ha->hardware_lock, cpu_flags);  
			if (ha->outstanding_cmds[index] != NULL) {
				spin_unlock_irqrestore(&ha->hardware_lock,
				    cpu_flags); 
				break;
			}
			spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);  
		}

		/* If No Commands are pending return ok */
		if (index != MAX_OUTSTANDING_COMMANDS)
			status = 1;

#if 0
		/* If No Commands are pending wait is complete */
		if (index == MAX_OUTSTANDING_COMMANDS)
			break;

		/*
		 * If we timed out on waiting for commands to come back Reset
		 * the ISP
		 */
		wait_cnt--;
		if (wait_cnt == 0) {
			set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
			status = 1;
			DEBUG(printk("%s(%ld): ISP abort - handle %d\n",
			    __func__, ha->host_no, index));
		} else {
			/* sleep a second */
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(HZ);
		}
	}
#endif

	DEBUG(printk("%s(%ld): Done waiting on commands - ind=%d\n",
	    __func__, ha->host_no, index));
	printk("%s(%ld): exiting - ind=%d, status=%d.\n",
	    __func__, ha->host_no, index, status);

	return status;
}

static inline uint32_t
nvram_conf_to_access_addr(uint32_t naddr)
{
	return FARX_ACCESS_NVRAM_CONF | naddr;
}

static inline uint32_t
nvram_data_to_access_addr(uint32_t naddr)
{
	return FARX_ACCESS_NVRAM_DATA | naddr;
}

static void
qim_nv_deselect(scsi_qla_host_t *ha)
{
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	WRT_REG_WORD(&reg->nvram, NVR_DESELECT);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	NVRAM_DELAY();
}

/* XXX(hch): crude hack to emulate a down_timeout() */
int
qim_down_timeout(struct semaphore *sema, unsigned long timeout)
{
	const unsigned int step = HZ/10;

	do {
		if (!down_trylock(sema))
			return 0;
		set_current_state(TASK_INTERRUPTIBLE);
		if (schedule_timeout(step))
			break;
	} while ((timeout -= step) > 0);

	return -ETIMEDOUT;
}

uint32_t
qim24xx_read_flash_dword(scsi_qla_host_t *ha, uint32_t addr)
{
	int rval;
	uint32_t cnt, data;
	struct device_reg_24xx __iomem *reg =
	    (struct device_reg_24xx __iomem *)ha->iobase;

	WRT_REG_DWORD(&reg->flash_addr, addr & ~FARX_DATA_FLAG);
	/* Wait for READ cycle to complete. */
	rval = QLA_SUCCESS;
	for (cnt = 3000;
	    (RD_REG_DWORD(&reg->flash_addr) & FARX_DATA_FLAG) == 0 &&
	    rval == QLA_SUCCESS; cnt--) {
		if (cnt)
			qla2xxx_schedule_udelay(10);
		else {
			printk("%s: read reg %x timed out. addr=%x.\n",
			    __func__, addr & ~FARX_DATA_FLAG, addr);
			rval = QLA_FUNCTION_TIMEOUT;
		}
	}

	/* TODO: What happens if we time out? */
	data = 0xDEADDEAD;
	if (rval == QLA_SUCCESS)
		data = RD_REG_DWORD(&reg->flash_data);

	return data;
}

int
qim24xx_write_flash_dword(scsi_qla_host_t *ha, uint32_t addr, uint32_t data)
{
	int rval;
	uint32_t cnt;
	struct device_reg_24xx __iomem *reg =
	    (struct device_reg_24xx __iomem *)ha->iobase;

	WRT_REG_DWORD(&reg->flash_data, data);
	RD_REG_DWORD(&reg->flash_data);		/* PCI Posting. */
	WRT_REG_DWORD(&reg->flash_addr, addr | FARX_DATA_FLAG);
	/* Wait for Write cycle to complete. */
	rval = QLA_SUCCESS;
	for (cnt = 500000; (RD_REG_DWORD(&reg->flash_addr) & FARX_DATA_FLAG) &&
	    rval == QLA_SUCCESS; cnt--) {
		if (cnt)
			qla2xxx_schedule_udelay(10);
		else {
			printk("%s: read reg %x timed out. addr=%x.\n",
			    __func__, addr & ~FARX_DATA_FLAG, addr);
			rval = QLA_FUNCTION_TIMEOUT;
		}
	}
	return rval;
}

/**
 * qim_nv_write() - Prepare for NVRAM read/write operation.
 * @ha: HA context
 * @data: Serial interface selector
 */
static void
qim_nv_write(scsi_qla_host_t *ha, uint16_t data)
{
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	WRT_REG_WORD(&reg->nvram, data | NVR_SELECT | NVR_WRT_ENABLE);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	NVRAM_DELAY();
	WRT_REG_WORD(&reg->nvram, data | NVR_SELECT| NVR_CLOCK |
	    NVR_WRT_ENABLE);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	NVRAM_DELAY();
	WRT_REG_WORD(&reg->nvram, data | NVR_SELECT | NVR_WRT_ENABLE);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	NVRAM_DELAY();
}

/**
 * qim_nvram_request() - Sends read command to NVRAM and gets data from
 *	NVRAM.
 * @ha: HA context
 * @nv_cmd: NVRAM command
 *
 * Bit definitions for NVRAM command:
 *
 *	Bit 26     = start bit
 *	Bit 25, 24 = opcode
 *	Bit 23-16  = address
 *	Bit 15-0   = write data
 *
 * Returns the word read from nvram @addr.
 */
static uint16_t
qim_nvram_request(scsi_qla_host_t *ha, uint32_t nv_cmd)
{
	uint8_t		cnt;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;
	uint16_t	data = 0;
	uint16_t	reg_data;

	/* Send command to NVRAM. */
	nv_cmd <<= 5;
	for (cnt = 0; cnt < 11; cnt++) {
		if (nv_cmd & BIT_31)
			qim_nv_write(ha, NVR_DATA_OUT);
		else
			qim_nv_write(ha, 0);

		nv_cmd <<= 1;
	}

	/* Read data from NVRAM. */
	for (cnt = 0; cnt < 16; cnt++) {
		WRT_REG_WORD(&reg->nvram, NVR_SELECT | NVR_CLOCK);
		NVRAM_DELAY();
		data <<= 1;
		reg_data = RD_REG_WORD(&reg->nvram);
		if (reg_data & NVR_DATA_IN)
			data |= BIT_0;
		WRT_REG_WORD(&reg->nvram, NVR_SELECT);
		RD_REG_WORD(&reg->nvram);	/* PCI Posting. */
		NVRAM_DELAY();
	}

	/* Deselect chip. */
	WRT_REG_WORD(&reg->nvram, NVR_DESELECT);
	RD_REG_WORD(&reg->nvram);		/* PCI Posting. */
	NVRAM_DELAY();

	return (data);
}

/**
 * qim_get_nvram_word() - Calculates word position in NVRAM and calls the
 *	request routine to get the word from NVRAM.
 * @ha: HA context
 * @addr: Address in NVRAM to read
 *
 * Returns the word read from nvram @addr.
 */
uint16_t
qim_get_nvram_word(scsi_qla_host_t *ha, uint32_t addr)
{
	uint16_t	data;
	uint32_t	nv_cmd;

	nv_cmd = addr << 16;
	nv_cmd |= NV_READ_OP;
	data = qim_nvram_request(ha, nv_cmd);

	return (data);
}

/**
 * qim_lock_nvram_access() - 
 * @ha: HA context
 */
void
qim_lock_nvram_access(scsi_qla_host_t *ha)
{
	uint16_t data;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	if (!IS_QLA2100(ha) && !IS_QLA2200(ha) && !IS_QLA2300(ha)) {
		data = RD_REG_WORD(&reg->nvram);
		while (data & NVR_BUSY) {
			qla2xxx_schedule_udelay(100);
			data = RD_REG_WORD(&reg->nvram);
		}

		/* Lock resource */
		WRT_REG_WORD(&reg->u.isp2300.host_semaphore, 0x1);
		RD_REG_WORD(&reg->u.isp2300.host_semaphore);
		qla2xxx_schedule_udelay(5);
		data = RD_REG_WORD(&reg->u.isp2300.host_semaphore);
		while ((data & BIT_0) == 0) {
			/* Lock failed */
			qla2xxx_schedule_udelay(100);
			WRT_REG_WORD(&reg->u.isp2300.host_semaphore, 0x1);
			RD_REG_WORD(&reg->u.isp2300.host_semaphore);
			qla2xxx_schedule_udelay(5);
			data = RD_REG_WORD(&reg->u.isp2300.host_semaphore);
		}
	}
}

/**
 * qim_unlock_nvram_access() - 
 * @ha: HA context
 */
void
qim_unlock_nvram_access(scsi_qla_host_t *ha)
{
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	if (!IS_QLA2100(ha) && !IS_QLA2200(ha) && !IS_QLA2300(ha)) {
		WRT_REG_WORD(&reg->u.isp2300.host_semaphore, 0);
		RD_REG_WORD(&reg->u.isp2300.host_semaphore);
	}
}

static int
qim_write_nvram_word_tmo(scsi_qla_host_t *ha, uint32_t addr, uint16_t data,
    uint32_t tmo)
{
	int ret, count;
	uint16_t word;
	uint32_t nv_cmd;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	ret = QLA_SUCCESS;

	qim_nv_write(ha, NVR_DATA_OUT);
	qim_nv_write(ha, 0);
	qim_nv_write(ha, 0);

	for (word = 0; word < 8; word++)
		qim_nv_write(ha, NVR_DATA_OUT);

	qim_nv_deselect(ha);

	/* Write data */
	nv_cmd = (addr << 16) | NV_WRITE_OP;
	nv_cmd |= data;
	nv_cmd <<= 5;
	for (count = 0; count < 27; count++) {
		if (nv_cmd & BIT_31)
			qim_nv_write(ha, NVR_DATA_OUT);
		else
			qim_nv_write(ha, 0);

		nv_cmd <<= 1;
	}

	qim_nv_deselect(ha);

	/* Wait for NVRAM to become ready */
	WRT_REG_WORD(&reg->nvram, NVR_SELECT);
	do {
		NVRAM_DELAY();
		word = RD_REG_WORD(&reg->nvram);
		if (!--tmo) {
			ret = QLA_FUNCTION_FAILED;
			break;
		}
	} while ((word & NVR_DATA_IN) == 0);

	qim_nv_deselect(ha);

	/* Disable writes */
	qim_nv_write(ha, NVR_DATA_OUT);
	for (count = 0; count < 10; count++)
		qim_nv_write(ha, 0);

	qim_nv_deselect(ha);

	return ret;
}

/**
 * qim_write_nvram_word() - Write NVRAM data.
 * @ha: HA context
 * @addr: Address in NVRAM to write
 * @data: word to program
 */
void
qim_write_nvram_word(scsi_qla_host_t *ha, uint32_t addr, uint16_t data)
{
	int count;
	uint16_t word;
	uint32_t nv_cmd;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	qim_nv_write(ha, NVR_DATA_OUT);
	qim_nv_write(ha, 0);
	qim_nv_write(ha, 0);

	for (word = 0; word < 8; word++)
		qim_nv_write(ha, NVR_DATA_OUT);

	qim_nv_deselect(ha);

	/* Write data */
	nv_cmd = (addr << 16) | NV_WRITE_OP;
	nv_cmd |= data;
	nv_cmd <<= 5;
	for (count = 0; count < 27; count++) {
		if (nv_cmd & BIT_31)
			qim_nv_write(ha, NVR_DATA_OUT);
		else
			qim_nv_write(ha, 0);

		nv_cmd <<= 1;
	}

	qim_nv_deselect(ha);

	/* Wait for NVRAM to become ready */
	WRT_REG_WORD(&reg->nvram, NVR_SELECT);
	do {
		NVRAM_DELAY();
		word = RD_REG_WORD(&reg->nvram);
	} while ((word & NVR_DATA_IN) == 0);

	qim_nv_deselect(ha);

	/* Disable writes */
	qim_nv_write(ha, NVR_DATA_OUT);
	for (count = 0; count < 10; count++)
		qim_nv_write(ha, 0);

	qim_nv_deselect(ha);
}

/**
 * qim_clear_nvram_protection() -
 * @ha: HA context
 */
static int
qim_clear_nvram_protection(scsi_qla_host_t *ha)
{
	int ret, stat;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;
	uint32_t word;
	uint16_t wprot, wprot_old;


	/* Clear NVRAM write protection. */
	ret = QLA_FUNCTION_FAILED;
	wprot_old = cpu_to_le16(qim_get_nvram_word(ha, 0));
	stat = qim_write_nvram_word_tmo(ha, 0,
	    __constant_cpu_to_le16(0x1234), 100000);
	wprot = cpu_to_le16(qim_get_nvram_word(ha, 0));
	if (stat != QLA_SUCCESS || wprot != __constant_cpu_to_le16(0x1234)) {
		/* Write enable. */
		qim_nv_write(ha, NVR_DATA_OUT);
		qim_nv_write(ha, 0);
		qim_nv_write(ha, 0);
		for (word = 0; word < 8; word++)
			qim_nv_write(ha, NVR_DATA_OUT);

		qim_nv_deselect(ha);

		/* Enable protection register. */
		qim_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
		qim_nv_write(ha, NVR_PR_ENABLE);
		qim_nv_write(ha, NVR_PR_ENABLE);
		for (word = 0; word < 8; word++)
			qim_nv_write(ha, NVR_DATA_OUT | NVR_PR_ENABLE);

		qim_nv_deselect(ha);

		/* Clear protection register (ffff is cleared). */
		qim_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
		qim_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
		qim_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
		for (word = 0; word < 8; word++)
			qim_nv_write(ha, NVR_DATA_OUT | NVR_PR_ENABLE);

		qim_nv_deselect(ha);

		/* Wait for NVRAM to become ready. */
		WRT_REG_WORD(&reg->nvram, NVR_SELECT);
		do {
			NVRAM_DELAY();
			word = RD_REG_WORD(&reg->nvram);
		} while ((word & NVR_DATA_IN) == 0);

		ret = QLA_SUCCESS;
	} else
		qim_write_nvram_word(ha, 0, wprot_old);

	return ret;
}

static void
qim_set_nvram_protection(scsi_qla_host_t *ha, int stat)
{
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;
	uint32_t word;

	if (stat != QLA_SUCCESS)
		return;

	/* Set NVRAM write protection. */
	/* Write enable. */
	qim_nv_write(ha, NVR_DATA_OUT);
	qim_nv_write(ha, 0);
	qim_nv_write(ha, 0);
	for (word = 0; word < 8; word++)
		qim_nv_write(ha, NVR_DATA_OUT);

	qim_nv_deselect(ha);

	/* Enable protection register. */
	qim_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
	qim_nv_write(ha, NVR_PR_ENABLE);
	qim_nv_write(ha, NVR_PR_ENABLE);
	for (word = 0; word < 8; word++)
		qim_nv_write(ha, NVR_DATA_OUT | NVR_PR_ENABLE);

	qim_nv_deselect(ha);

	/* Enable protection register. */
	qim_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
	qim_nv_write(ha, NVR_PR_ENABLE);
	qim_nv_write(ha, NVR_PR_ENABLE | NVR_DATA_OUT);
	for (word = 0; word < 8; word++)
		qim_nv_write(ha, NVR_PR_ENABLE);

	qim_nv_deselect(ha);

	/* Wait for NVRAM to become ready. */
	WRT_REG_WORD(&reg->nvram, NVR_SELECT);
	do {
		NVRAM_DELAY();
		word = RD_REG_WORD(&reg->nvram);
	} while ((word & NVR_DATA_IN) == 0);
}

static void
qim2xxx_read_flash_data(struct scsi_qla_host *ha, uint8_t *buf,
    uint32_t offset, uint32_t length)
{
	/* XXX, Marcus slow path code for now */
	qim24xx_read_flash_data(ha, (uint32_t *)buf, offset >> 2,
			length >> 2);
}

uint8_t *
qim_read_nvram_data(scsi_qla_host_t *ha, uint8_t *buf, uint32_t naddr,
    uint32_t bytes)
{
	uint32_t i;
	uint16_t *wptr;
	uint32_t *dwptr;

	if (IS_QLA25XX(ha)) {
		qim2xxx_read_flash_data(ha, buf,
		    ((FA_VPD_NVRAM_ADDR << 2) | (naddr << 2)), bytes);
	} else if (IS_QLA24XX_TYPE(ha)) {
		/* Dword reads to flash. */
		dwptr = (uint32_t *)buf;
		for (i = 0; i < bytes >> 2; i++, naddr++)
			dwptr[i] = cpu_to_le32(qim24xx_read_flash_dword(ha,
			    nvram_data_to_access_addr(naddr)));
	} else {
		/* Word reads to NVRAM via registers. */
		wptr = (uint16_t *)buf;
		qim_lock_nvram_access(ha);
		for (i = 0; i < bytes >> 1; i++, naddr++)
			wptr[i] = cpu_to_le16(qim_get_nvram_word(ha,
			    naddr));
		qim_unlock_nvram_access(ha);
	}
	return buf;
}

int
qim_write_nvram_data(scsi_qla_host_t *ha, uint8_t *buf, uint32_t naddr,
    uint32_t bytes)
{
	int ret;
	uint32_t i;
	uint16_t *wptr;
	uint32_t *dwptr;
	struct device_reg_24xx __iomem *reg =
	    (struct device_reg_24xx __iomem *)ha->iobase;

	ret = QLA_SUCCESS;

	if (IS_QLA25XX(ha)) {
		ret = qim24xx_write_flash_data(ha, (uint32_t *)buf,
		    FA_VPD_NVRAM_ADDR | naddr, bytes >> 2);
        } else if (IS_QLA24XX_TYPE(ha)) {
		/* Enable flash write. */
		WRT_REG_DWORD(&reg->ctrl_status,
		    RD_REG_DWORD(&reg->ctrl_status) | CSRX_FLASH_ENABLE);
		RD_REG_DWORD(&reg->ctrl_status);	/* PCI Posting. */

		/* Disable NVRAM write-protection. */
		qim24xx_write_flash_dword(ha, nvram_conf_to_access_addr(0x101),
		    0);
		qim24xx_write_flash_dword(ha, nvram_conf_to_access_addr(0x101),
		    0);

		/* Dword writes to flash. */
		dwptr = (uint32_t *)buf;
		for (i = 0; i < bytes >> 2; i++, naddr++, dwptr++) {
			ret = qim24xx_write_flash_dword(ha,
			    nvram_data_to_access_addr(naddr),
			    cpu_to_le32(*dwptr));
			if (ret != QLA_SUCCESS) {
				DEBUG9(printk("%s(%ld) Unable to program "
				    "nvram address=%x data=%x.\n", __func__,
				    ha->host_no, naddr, *dwptr));
				break;
			}
		}

		/* Enable NVRAM write-protection. */
		qim24xx_write_flash_dword(ha, nvram_conf_to_access_addr(0x101),
		    0x8c);

		/* Disable flash write. */
		WRT_REG_DWORD(&reg->ctrl_status,
		    RD_REG_DWORD(&reg->ctrl_status) & ~CSRX_FLASH_ENABLE);
		RD_REG_DWORD(&reg->ctrl_status);	/* PCI Posting. */
	} else {
		int stat;

		qim_lock_nvram_access(ha);

		/* Disable NVRAM write-protection. */
		stat = qim_clear_nvram_protection(ha);

		wptr = (uint16_t *)buf;
		for (i = 0; i < bytes >> 1; i++, naddr++) {
			qim_write_nvram_word(ha, naddr,
			    cpu_to_le16(*wptr));
			wptr++;
		}

		/* Enable NVRAM write-protection. */
		qim_set_nvram_protection(ha, stat);

		qim_unlock_nvram_access(ha);
	}

	return ret;
}

/*
 * qim_wait_for_hba_online
 *    Wait till the HBA is online after going through 
 *    <= MAX_RETRIES_OF_ISP_ABORT  or
 *    finally HBA is disabled ie marked offline
 *
 * Input:
 *     ha - pointer to host adapter structure
 * 
 * Note:    
 *    Does context switching-Release SPIN_LOCK
 *    (if any) before calling this routine.
 *
 * Return:
 *    Success (Adapter is online) : 0
 *    Failed  (Adapter is offline/disabled) : 1
 */
int 
qim_wait_for_hba_online(scsi_qla_host_t *ha)
{
	int		return_status;
	unsigned long	wait_online;

	wait_online = jiffies + (MAX_LOOP_TIMEOUT * HZ); 
	while (((test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags)) ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_RETRY, &ha->dpc_flags) ||
	    ha->dpc_active) && time_before(jiffies, wait_online)) {

		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(HZ);
	}
	if (ha->flags.online) 
		return_status = QLA_SUCCESS; 
	else
		return_status = QLA_FUNCTION_FAILED;

	DEBUG2(printk("%s return_status=%d\n",__func__,return_status));

	return (return_status);
}

/**
 * qim_flash_enable() - Setup flash for reading and writing.
 * @ha: HA context
 */
void
qim_flash_enable(scsi_qla_host_t *ha)
{
	uint16_t	data;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	data = RD_REG_WORD(&reg->ctrl_status);
	data |= CSR_FLASH_ENABLE;
	WRT_REG_WORD(&reg->ctrl_status, data);
	RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */
}

/**
 * qim_flash_disable() - Disable flash and allow RISC to run.
 * @ha: HA context
 */
void
qim_flash_disable(scsi_qla_host_t *ha)
{
	uint16_t	data;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	data = RD_REG_WORD(&reg->ctrl_status);
	data &= ~(CSR_FLASH_ENABLE);
	WRT_REG_WORD(&reg->ctrl_status, data);
	RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */
}

/**
 * qim_read_flash_byte() - Reads a byte from flash
 * @ha: HA context
 * @addr: Address in flash to read
 *
 * A word is read from the chip, but, only the lower byte is valid.
 *
 * Returns the byte read from flash @addr.
 */
uint8_t
qim_read_flash_byte(scsi_qla_host_t *ha, uint32_t addr)
{
	uint16_t	data;
	uint16_t	bank_select;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	bank_select = RD_REG_WORD(&reg->ctrl_status);

	if (IS_QLA2322(ha) || IS_QLA6322(ha)) {
		/* Specify 64K address range: */
		/*  clear out Module Select and Flash Address bits [19:16]. */
		bank_select &= ~0xf8;
		bank_select |= addr >> 12 & 0xf0;
		bank_select |= CSR_FLASH_64K_BANK;
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */

		WRT_REG_WORD(&reg->flash_address, (uint16_t)addr);
		data = RD_REG_WORD(&reg->flash_data);

		return ((uint8_t)data);
	}

	/* Setup bit 16 of flash address. */
	if ((addr & BIT_16) && ((bank_select & CSR_FLASH_64K_BANK) == 0)) {
		bank_select |= CSR_FLASH_64K_BANK;
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */
	} else if (((addr & BIT_16) == 0) &&
	    (bank_select & CSR_FLASH_64K_BANK)) {
		bank_select &= ~(CSR_FLASH_64K_BANK);
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */
	}

	/* Always perform IO mapped accesses to the FLASH registers. */
	if (ha->pio_address) {
		uint16_t data2;

		reg = (struct device_reg_2xxx __iomem *)ha->pio_address;
		WRT_REG_WORD_PIO(&reg->flash_address, (uint16_t)addr);
		do {
			data = RD_REG_WORD_PIO(&reg->flash_data);
			barrier();
			cpu_relax();
			data2 = RD_REG_WORD_PIO(&reg->flash_data);
		} while (data != data2);
	} else {
		WRT_REG_WORD(&reg->flash_address, (uint16_t)addr);
		data = qim_debounce_register(&reg->flash_data);
	}

	return ((uint8_t)data);
}

/**
 * qim_write_flash_byte() - Write a byte to flash
 * @ha: HA context
 * @addr: Address in flash to write
 * @data: Data to write
 */
static void
qim_write_flash_byte(scsi_qla_host_t *ha, uint32_t addr, uint8_t data)
{
	uint16_t	bank_select;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	bank_select = RD_REG_WORD(&reg->ctrl_status);
	if (IS_QLA2322(ha) || IS_QLA6322(ha)) {
		/* Specify 64K address range: */
		/*  clear out Module Select and Flash Address bits [19:16]. */
		bank_select &= ~0xf8;
		bank_select |= addr >> 12 & 0xf0;
		bank_select |= CSR_FLASH_64K_BANK;
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */

		WRT_REG_WORD(&reg->flash_address, (uint16_t)addr);
		RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */
		WRT_REG_WORD(&reg->flash_data, (uint16_t)data);
		RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */

		return;
	}

	/* Setup bit 16 of flash address. */
	if ((addr & BIT_16) && ((bank_select & CSR_FLASH_64K_BANK) == 0)) {
		bank_select |= CSR_FLASH_64K_BANK;
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */
	} else if (((addr & BIT_16) == 0) &&
	    (bank_select & CSR_FLASH_64K_BANK)) {
		bank_select &= ~(CSR_FLASH_64K_BANK);
		WRT_REG_WORD(&reg->ctrl_status, bank_select);
		RD_REG_WORD(&reg->ctrl_status);	/* PCI Posting. */
	}

	/* Always perform IO mapped accesses to the FLASH registers. */
	if (ha->pio_address) {
		reg = (struct device_reg_2xxx __iomem *)ha->pio_address;
		WRT_REG_WORD_PIO(&reg->flash_address, (uint16_t)addr);
		WRT_REG_WORD_PIO(&reg->flash_data, (uint16_t)data);
	} else {
		WRT_REG_WORD(&reg->flash_address, (uint16_t)addr);
		RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */
		WRT_REG_WORD(&reg->flash_data, (uint16_t)data);
		RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */
	}
}

/**
 * qim_poll_flash() - Polls flash for completion.
 * @ha: HA context
 * @addr: Address in flash to poll
 * @poll_data: Data to be polled
 * @man_id: Flash manufacturer ID
 * @flash_id: Flash ID
 *
 * This function polls the device until bit 7 of what is read matches data
 * bit 7 or until data bit 5 becomes a 1.  If that hapens, the flash ROM timed
 * out (a fatal error).  The flash book recommeds reading bit 7 again after
 * reading bit 5 as a 1.
 *
 * Returns 0 on success, else non-zero.
 */
static uint8_t
qim_poll_flash(scsi_qla_host_t *ha, uint32_t addr, uint8_t poll_data,
    uint8_t man_id, uint8_t flash_id)
{
	uint8_t		status;
	uint8_t		flash_data;
	uint32_t	cnt;

	status = 1;

	/* Wait for 30 seconds for command to finish. */
	poll_data &= BIT_7;
	for (cnt = 3000000; cnt; cnt--) {
		flash_data = qim_read_flash_byte(ha, addr);
		if ((flash_data & BIT_7) == poll_data) {
			status = 0;
			break;
		}

		if (man_id != 0x40 && man_id != 0xda) {
			if ((flash_data & BIT_5) && cnt > 2)
				cnt = 2;
		}
		qla2xxx_schedule_udelay(10);
		barrier();
	}
	return (status);
}

/**
 * qim_program_flash_address() - Programs a flash address
 * @ha: HA context
 * @addr: Address in flash to program
 * @data: Data to be written in flash
 * @man_id: Flash manufacturer ID
 * @flash_id: Flash ID
 *
 * Returns 0 on success, else non-zero.
 */
static uint8_t
qim_program_flash_address(scsi_qla_host_t *ha, uint32_t addr, uint8_t data,
    uint8_t man_id, uint8_t flash_id)
{
	/* Write Program Command Sequence */
	if (QIM_IS_OEM_001(ha)) {
		qim_write_flash_byte(ha, 0xaaa, 0xaa);
		qim_write_flash_byte(ha, 0x555, 0x55);
		qim_write_flash_byte(ha, 0xaaa, 0xa0);
		qim_write_flash_byte(ha, addr, data);
	} else {
		if (man_id == 0xda && flash_id == 0xc1) {
			qim_write_flash_byte(ha, addr, data);
			if (addr & 0x7e)
				return 0;
		} else {
			qim_write_flash_byte(ha, 0x5555, 0xaa);
			qim_write_flash_byte(ha, 0x2aaa, 0x55);
			qim_write_flash_byte(ha, 0x5555, 0xa0);
			qim_write_flash_byte(ha, addr, data);
		}
	}

	qla2xxx_schedule_udelay(150);

	/* Wait for write to complete. */
	return (qim_poll_flash(ha, addr, data, man_id, flash_id));
}

/**
 * qim_erase_flash() - Erase the flash.
 * @ha: HA context
 * @man_id: Flash manufacturer ID
 * @flash_id: Flash ID
 *
 * Returns 0 on success, else non-zero.
 */
static uint8_t
qim_erase_flash(scsi_qla_host_t *ha, uint8_t man_id, uint8_t flash_id)
{
	/* Individual Sector Erase Command Sequence */
	if (QIM_IS_OEM_001(ha)) {
		qim_write_flash_byte(ha, 0xaaa, 0xaa);
		qim_write_flash_byte(ha, 0x555, 0x55);
		qim_write_flash_byte(ha, 0xaaa, 0x80);
		qim_write_flash_byte(ha, 0xaaa, 0xaa);
		qim_write_flash_byte(ha, 0x555, 0x55);
		qim_write_flash_byte(ha, 0xaaa, 0x10);
	} else {
		qim_write_flash_byte(ha, 0x5555, 0xaa);
		qim_write_flash_byte(ha, 0x2aaa, 0x55);
		qim_write_flash_byte(ha, 0x5555, 0x80);
		qim_write_flash_byte(ha, 0x5555, 0xaa);
		qim_write_flash_byte(ha, 0x2aaa, 0x55);
		qim_write_flash_byte(ha, 0x5555, 0x10);
	}

	qla2xxx_schedule_udelay(150);

	/* Wait for erase to complete. */
	return (qim_poll_flash(ha, 0x00, 0x80, man_id, flash_id));
}

/**
 * qim_erase_flash_sector() - Erase a flash sector.
 * @ha: HA context
 * @addr: Flash sector to erase
 * @sec_mask: Sector address mask
 * @man_id: Flash manufacturer ID
 * @flash_id: Flash ID
 *
 * Returns 0 on success, else non-zero.
 */
static uint8_t
qim_erase_flash_sector(scsi_qla_host_t *ha, uint32_t addr,
    uint32_t sec_mask, uint8_t man_id, uint8_t flash_id)
{
	/* Individual Sector Erase Command Sequence */
	qim_write_flash_byte(ha, 0x5555, 0xaa);
	qim_write_flash_byte(ha, 0x2aaa, 0x55);
	qim_write_flash_byte(ha, 0x5555, 0x80);
	qim_write_flash_byte(ha, 0x5555, 0xaa);
	qim_write_flash_byte(ha, 0x2aaa, 0x55);
	if (man_id == 0x1f && flash_id == 0x13)
		qim_write_flash_byte(ha, addr & sec_mask, 0x10);
	else
		qim_write_flash_byte(ha, addr & sec_mask, 0x30);

	qla2xxx_schedule_udelay(150);

	/* Wait for erase to complete. */
	return (qim_poll_flash(ha, addr, 0x80, man_id, flash_id));
}

/**
 * qim_get_flash_manufacturer() - Read manufacturer ID from flash chip.
 * @man_id: Flash manufacturer ID
 * @flash_id: Flash ID
 *
 */
void
qim_get_flash_manufacturer(scsi_qla_host_t *ha, uint8_t *man_id,
    uint8_t *flash_id)
{
	qim_write_flash_byte(ha, 0x5555, 0xaa);
	qim_write_flash_byte(ha, 0x2aaa, 0x55);
	qim_write_flash_byte(ha, 0x5555, 0x90);
	*man_id = qim_read_flash_byte(ha, 0x0000);
	*flash_id = qim_read_flash_byte(ha, 0x0001);
	qim_write_flash_byte(ha, 0x5555, 0xaa);
	qim_write_flash_byte(ha, 0x2aaa, 0x55);
	qim_write_flash_byte(ha, 0x5555, 0xf0);
}

void
qim24xx_get_flash_manufacturer(scsi_qla_host_t *ha, uint8_t *man_id,
    uint8_t *flash_id)
{
	uint32_t ids;

	ids = qim24xx_read_flash_dword(ha, flash_data_to_access_addr(0xd03ab));
	*man_id = LSB(ids);
	*flash_id = MSB(ids);
}

/**
 * qim_set_flash_image() - Write image to flash chip.
 * @ha: HA context
 * @image: Source image to write to flash
 *
 * Returns 0 on success, else non-zero.
 */
uint16_t
qim_set_flash_image(scsi_qla_host_t *ha, uint8_t *image, uint32_t saddr,
    uint32_t length)
{
	uint16_t	status;
	uint32_t	addr;
	uint32_t	liter;
	uint32_t	sec_mask;
	uint32_t	rest_addr;
	uint8_t		man_id, flash_id;
	uint8_t		sec_number;
	uint8_t		data;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	status = 0;
	sec_number = 0;

	/* Reset ISP chip. */
	WRT_REG_WORD(&reg->ctrl_status, CSR_ISP_SOFT_RESET);
	RD_REG_WORD(&reg->ctrl_status);		/* PCI Posting. */

	qim_flash_enable(ha);
	do {	/* Loop once to provide quick error exit */
		/* Structure of flash memory based on manufacturer */
		if (QIM_IS_OEM_001(ha)) {
			// OEM variant with special flash part.
			man_id = flash_id = 0;
			rest_addr = 0xffff;
			sec_mask   = 0x10000;
			goto update_flash;
		}
		qim_get_flash_manufacturer(ha, &man_id, &flash_id);
		DEBUG9(printk("%s(%ld): Flash man_id=%d flash_id=%d\n",
		    __func__, ha->host_no, man_id, flash_id));
		switch (man_id) {
		case 0x20: // ST flash
			if (flash_id == 0xd2 || flash_id == 0xe3) {
				// ST m29w008at part - 64kb sector size with
				// 32kb,8kb,8kb,16kb sectors at memory address
				// 0xf0000
				rest_addr = 0xffff;
				sec_mask = 0x10000;
				break;   
			}
			// ST m29w010b part - 16kb sector size  
			// Default to 16kb sectors      
			rest_addr = 0x3fff;
			sec_mask = 0x1c000;
			break;   
		case 0x40: // Mostel flash
			// Mostel v29c51001 part - 512 byte sector size  
			rest_addr = 0x1ff;
			sec_mask = 0x1fe00;
			break;   
		case 0xbf: // SST flash
			// SST39sf10 part - 4kb sector size   
			rest_addr = 0xfff;
			sec_mask = 0x1f000;
			break;
		case 0xda: // Winbond flash
			// Winbond W29EE011 part - 256 byte sector size   
			rest_addr = 0x7f;
			sec_mask = 0x1ff80;
			break;
		case 0xc2: // Macronix flash
			// 64k sector size    
			if (flash_id == 0x38 || flash_id == 0x4f) {
				rest_addr = 0xffff;
				sec_mask = 0x10000;
				break;
			}
			// Fall through...

		case 0x1f: // Atmel flash
			// 512k sector size    
			if (flash_id == 0x13) {
				rest_addr = 0x7fffffff;
				sec_mask =   0x80000000;
				break;
			}   
			// Fall through...

		case 0x01: // AMD flash 
			if (flash_id == 0x38 || flash_id == 0x40 ||
			    flash_id == 0x4f) {
				// Am29LV081 part - 64kb sector size   
				// Am29LV002BT part - 64kb sector size   
				rest_addr = 0xffff;
				sec_mask = 0x10000;
				break;
			} else if (flash_id == 0x3e) {
				// Am29LV008b part - 64kb sector size with
				// 32kb,8kb,8kb,16kb sector at memory address
				// 0xf0000
				rest_addr = 0xffff;
				sec_mask = 0x10000;
				break;
			} else if (flash_id == 0x20 || flash_id == 0x6e) {
				// Am29LV010 part or AM29f010 - 16kb sector
				// size   
				rest_addr = 0x3fff;
				sec_mask = 0x1c000;
				break;
			} else if (flash_id == 0x6d) {
				// Am29LV001 part - 8kb sector size   
				rest_addr = 0x1fff;
				sec_mask = 0x1e000;
				break;
			}   
		default:
			// Default to 16 kb sector size  
			rest_addr = 0x3fff;
			sec_mask = 0x1c000;
			break;
		}

update_flash:
		if (IS_QLA2322(ha) || IS_QLA6322(ha)) {
			if (qim_erase_flash(ha, man_id, flash_id)) {
				status = 1;
				break;
			}
		}

		for (addr = saddr, liter = 0; liter < length; liter++, addr++) {
			data = image[liter];
			/* Are we at the beginning of a sector? */
			if ((addr & rest_addr) == 0) {
				if (IS_QLA2322(ha) || IS_QLA6322(ha)) {
					if (addr >= 0x10000UL) {
						if (((addr >> 12) & 0xf0) &&
						    ((man_id == 0x01 && flash_id == 0x3e) ||
						    (man_id == 0x20 && flash_id == 0xd2))) {
							sec_number++;
							if (sec_number == 1) {   
								rest_addr = 0x7fff;
								sec_mask = 0x18000;
							} else if (sec_number == 2 ||
							    sec_number == 3) {
								rest_addr = 0x1fff;
								sec_mask = 0x1e000;
							} else if (sec_number == 4) {
								rest_addr = 0x3fff;
								sec_mask = 0x1c000;
							}         
						}                           
					}    
				} else if (addr == FLASH_IMAGE_SIZE / 2) {
					WRT_REG_WORD(&reg->nvram, NVR_SELECT);
					RD_REG_WORD(&reg->nvram);
				}

				if (flash_id == 0xda && man_id == 0xc1) {
					qim_write_flash_byte(ha, 0x5555,
					    0xaa);
					qim_write_flash_byte(ha, 0x2aaa,
					    0x55);
					qim_write_flash_byte(ha, 0x5555,
					    0xa0);
				} else if (!IS_QLA2322(ha) && !IS_QLA6322(ha)) {
					/* Then erase it */
					if (qim_erase_flash_sector(ha, addr,
					    sec_mask, man_id, flash_id)) {
						DEBUG9(printk("%s(%ld) Unable "
						    "to erase flash sector "
						    "addr=%x mask=%x.\n",
						    __func__, ha->host_no, addr,
						    sec_mask));
						status = 1;
						break;
					}
					if (man_id == 0x01 && flash_id == 0x6d)
						sec_number++;
				}
			}

			if (man_id == 0x01 && flash_id == 0x6d) {
				if (sec_number == 1 &&
				    addr == (rest_addr - 1)) {
					rest_addr = 0x0fff;
					sec_mask   = 0x1f000;
				} else if (sec_number == 3 && (addr & 0x7ffe)) {
					rest_addr = 0x3fff;
					sec_mask   = 0x1c000;
				}
			}

			if (qim_program_flash_address(ha, addr, data,
			    man_id, flash_id)) {
				DEBUG9(printk("%s(%ld) Unable to program flash "
				    "address=%x data=%x.\n", __func__,
				    ha->host_no, addr, data));
				status = 1;
				break;
			}
		}
	} while (0);
	qim_flash_disable(ha);

	return (status);
}

/*
 *  qim_unsuspend_all_target
 *	Unsuspend all target. 
 *
 * Input:
 *	ha = visable adapter block pointer.
 *
 * Return:
 *
 * Context:
 *	Process context.
 */
void
qim_unsuspend_all_target(scsi_qla_host_t *ha)
{
	os_tgt_t *tq;
	int 	 t;

	for (t = 0; t < ha->max_targets; t++) {
		if ((tq = ha->otgt[t]) == NULL)
			continue;

		clear_bit(TQF_SUSPENDED, &tq->flags); 
	}
}

/*
 *  qim_suspend_target
 *	Suspend target
 *
 * Input:
 *	ha = visable adapter block pointer.
 *  target = target queue
 *  time = time in seconds
 *
 * Return:
 *     QL_STATUS_SUCCESS  -- suspended lun 
 *     QL_STATUS_ERROR  -- Didn't suspend lun
 *
 * Context:
 *	Interrupt context.
 */
int
qim_suspend_target(scsi_qla_host_t *ha, os_tgt_t *tq, int time)
{
	srb_t *sp, *sptemp;
	unsigned long flags;

	if (test_bit(TQF_SUSPENDED, &tq->flags))
		return QLA_FUNCTION_FAILED;

	/* now suspend the lun */
	set_bit(TQF_SUSPENDED, &tq->flags);

	DEBUG2(printk(KERN_INFO
	    "scsi%ld: Starting - suspend target for %d secs\n", ha->host_no,
	    time));

	/*
	 * Remove all (TARGET) pending commands from request queue and put them
	 * in the scsi_retry queue.
	 */
	spin_lock_irqsave(&ha->list_lock, flags);
	list_for_each_entry_safe(sp, sptemp, &ha->pending_queue, list) {
		if (sp->tgt_queue != tq)
			continue;

		DEBUG3(printk("scsi%ld: %s requeue for suspended target %p\n",
		    ha->host_no, __func__, sp));

		__del_from_pending_queue(ha, sp);
		__add_to_scsi_retry_queue(ha,sp);
	}
	spin_unlock_irqrestore(&ha->list_lock, flags);

	return QLA_SUCCESS;
}

/*
 *  qim_suspend_all_target
 *	Suspend all target indefinitely. Caller need to make sure
 *	to explicitly unsuspend it later on.
 *
 * Input:
 *	ha = visable adapter block pointer.
 *  target = target queue
 *  time = time in seconds
 *
 * Return:
 *     QL_STATUS_SUCCESS  -- suspended lun 
 *     QL_STATUS_ERROR  -- Didn't suspend lun
 *
 * Context:
 *	qim_suspend_target can be called in Interrupt context.
 *	Hold the hardware lock for synchronisation.
 */
int
qim_suspend_all_target(scsi_qla_host_t *ha)
{
	int  status = 0;	
	os_tgt_t *tq;
	int 	 t, time;
	unsigned long cpu_flags = 0;

	/* Suspend the Target until explicitly cleared */
	time = 0;

	for (t = 0; t < ha->max_targets; t++) {
		if ((tq = ha->otgt[t]) == NULL)
			continue;

		spin_lock_irqsave(&ha->hardware_lock, cpu_flags);
		status = qim_suspend_target(ha, tq, time);
		spin_unlock_irqrestore(&ha->hardware_lock, cpu_flags);
	}

	return status;
}

uint16_t
qim_read_flash_image(scsi_qla_host_t *ha, uint8_t *kern_tmp, uint32_t saddr,
    uint32_t length)
{
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;
	uint32_t	midpoint;
	uint8_t		data;
	uint32_t	ilength;
	uint16_t	status = 0;

	midpoint = length / 2;
	qim_flash_enable(ha);
	WRT_REG_WORD(&reg->nvram, 0);
	RD_REG_WORD(&reg->nvram);
	for (ilength = 0; ilength < length; saddr++, ilength++, kern_tmp++) {
		if (ilength == midpoint) {
			WRT_REG_WORD(&reg->nvram, NVR_SELECT);
			RD_REG_WORD(&reg->nvram);
		}
		data = qim_read_flash_byte(ha, saddr);
		if (saddr % 100)
			qla2xxx_schedule_udelay(10);
		*kern_tmp = data;
	}
	qim_flash_disable(ha);
	
	return (status);
}

uint32_t *
qim24xx_read_flash_data(scsi_qla_host_t *ha, uint32_t *dwptr, uint32_t faddr,
    uint32_t dwords)
{
	uint32_t i;

	/* Dword reads to flash. */
	for (i = 0; i < dwords; i++, faddr++)
		dwptr[i] = cpu_to_le32(qim24xx_read_flash_dword(ha,
		    flash_data_to_access_addr(faddr)));

	return dwptr;
}

int
qim24xx_write_flash_data(scsi_qla_host_t *ha, uint32_t *dwptr, uint32_t faddr,
    uint32_t dwords)
{
	int ret;
	uint32_t liter;
	uint32_t sec_mask, rest_addr, conf_addr;
	uint32_t fdata, findex, cnt;
	uint8_t	man_id, flash_id;
	struct device_reg_24xx __iomem *reg = &ha->iobase->isp24;

	ret = QLA_SUCCESS;

	qim24xx_get_flash_manufacturer(ha, &man_id, &flash_id);
	DEBUG9(printk("%s(%ld): Flash man_id=%d flash_id=%d\n", __func__,
	    ha->host_no, man_id, flash_id));

	conf_addr = flash_conf_to_access_addr(0x03d8);
	switch (man_id) {
	case 0xbf: // STT flash
		if (flash_id == 0x8e) {
			rest_addr = 0x3fff;
			sec_mask = 0x7c000;
		} else {
			rest_addr = 0x1fff;
			sec_mask = 0x7e000;
		}
		if (flash_id == 0x80)
			conf_addr = flash_conf_to_access_addr(0x0352);
		break;
	case 0x13: // ST M25P80
		rest_addr = 0x3fff;
		sec_mask = 0x7c000;
		break;
	case 0x1f: // Atmel 26DF081A
		rest_addr = 0x3fff;
		sec_mask = 0x7c000;
		conf_addr = flash_conf_to_access_addr(0x0320);
		break;
	default:
		// Default to 64 kb sector size
		rest_addr = 0x3fff;
		sec_mask = 0x7c000;
		break;
	}

	/* Enable flash write. */
	WRT_REG_DWORD(&reg->ctrl_status,
	    RD_REG_DWORD(&reg->ctrl_status) | CSRX_FLASH_ENABLE);
	RD_REG_DWORD(&reg->ctrl_status);	/* PCI Posting. */

	/* Disable flash write-protection. */
	qim24xx_write_flash_dword(ha, flash_conf_to_access_addr(0x101), 0);
	/* Some flash parts need an additional zero-write to clear bits.*/
	qim24xx_write_flash_dword(ha, flash_conf_to_access_addr(0x101), 0);

	do {    /* Loop once to provide quick error exit. */

		for (liter = 0; liter < dwords; liter++, faddr++, dwptr++) {
			if (man_id == 0x1f) {
				findex = faddr << 2;
				fdata = findex & sec_mask;
			} else {
				findex = faddr;
				fdata = (findex & sec_mask) << 2;
			}

			/* Are we at the beginning of a sector? */
			if ((findex & rest_addr) == 0) {
			/* Do sector unprotect at 4K boundry for Atmel part. */
				if (man_id == 0x1f)
					qim24xx_write_flash_dword(ha,
					    flash_conf_to_access_addr(0x0339),
					    (fdata & 0xff00) | ((fdata << 16) &
					   0xff0000) | ((fdata >> 16) & 0xff));
				ret = qim24xx_write_flash_dword(ha, conf_addr,
				    (fdata & 0xff00) |((fdata << 16) &
				    0xff0000) | ((fdata >> 16) & 0xff));
				if (ret != QLA_SUCCESS) {
					DEBUG9(printk("%s(%ld) Unable to flash"
					    " sector: address=%x.\n", __func__,
					    ha->host_no, faddr));
					break;
				}
			}

			/* XXX, Marcus skipping burst write for now */

			ret = qim24xx_write_flash_dword(ha,
			    flash_data_to_access_addr(faddr),
			    cpu_to_le32(*dwptr));
			if (ret != QLA_SUCCESS) {
				DEBUG9(printk("%s(%ld) Unable to program flash "
				    "address=%x data=%x.\n", __func__,
				    ha->host_no, faddr, *dwptr));
				break;
			}
		}
	} while (0);

        /* Enable flash write-protection and wait for completion */
        qim24xx_write_flash_dword(ha, flash_conf_to_access_addr(0x101), 0x9c);
        for (cnt = 300; cnt &&
	    qim24xx_read_flash_dword(ha,
		flash_conf_to_access_addr(0x005)) & BIT_0;
	    cnt--) {
		qla2xxx_schedule_udelay(10);
	}

	/* Disable flash write. */
	WRT_REG_DWORD(&reg->ctrl_status,
	    RD_REG_DWORD(&reg->ctrl_status) & ~CSRX_FLASH_ENABLE);
	RD_REG_DWORD(&reg->ctrl_status);	/* PCI Posting. */

	return ret;
}

int
qim24xx_get_flash_version(struct qla_host_ioctl *ha, uint8_t *ptmp_mem)
{
	int		ret = QLA_SUCCESS;
	uint32_t	pcihdr, pcids;
	uint32_t	*dcode;
	uint8_t		*bcode;
	uint8_t		code_type, last_image;
	int		i;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	if (ptmp_mem == NULL) {
		/* error */
		return(QLA_FUNCTION_FAILED);
	}

	dcode = (uint32_t *)ptmp_mem;

	/* Begin with first PCI expansion ROM header. */
	pcihdr = 0;
	last_image = 1;
	do {
		/* Verify PCI expansion ROM header. */
		qim24xx_read_flash_data(dr_ha, dcode, pcihdr >> 2, 0x20);
		bcode = (uint8_t *)ptmp_mem + (pcihdr % 4);
		if (bcode[0x0] != 0x55 || bcode[0x1] != 0xaa) {
			/* No signature */
			DEBUG10(printk(
			    "scsi(%ld): No matching ROM signature.\n",
			    ha->host_no));
			ret = QLA_FUNCTION_FAILED;
			break;
		}

		/* Locate PCI data structure. */
		pcids = pcihdr + ((bcode[0x19] << 8) | bcode[0x18]);

		qim24xx_read_flash_data(dr_ha, dcode, pcids >> 2, 0x20);
		bcode = (uint8_t *)ptmp_mem + (pcihdr % 4);

		/* Validate signature of PCI data structure. */
		if (bcode[0x0] != 'P' || bcode[0x1] != 'C' ||
		    bcode[0x2] != 'I' || bcode[0x3] != 'R') {
			/* Incorrect header. */
			DEBUG10(printk("%s(): PCI data struct not found "
			    "pcir_adr=%x.\n",
			    __func__, pcids));
			ret = QLA_FUNCTION_FAILED;
			break;
		}

		/* Read version */
		code_type = bcode[0x14];
		switch (code_type) {
		case ROM_CODE_TYPE_BIOS:
			/* Intel x86, PC-AT compatible. */
			set_bit(ROM_CODE_TYPE_BIOS, &ha->code_types);
			ha->bios_revision[0] = bcode[0x12];
			ha->bios_revision[1] = bcode[0x13];
			DEBUG9(printk("%s(): read BIOS %d.%d.\n", __func__,
			    ha->bios_revision[1], ha->bios_revision[0]));
			break;
		case ROM_CODE_TYPE_FCODE:
			/* Open Firmware standard for PCI (FCode). */
			set_bit(ROM_CODE_TYPE_FCODE, &ha->code_types);
			ha->fcode_revision[0] = bcode[0x12];
			ha->fcode_revision[1] = bcode[0x13];
			DEBUG9(printk("%s(): read FCODE %d.%d.\n", __func__,
			    ha->fcode_revision[1], ha->fcode_revision[0]);)
			break;
		case ROM_CODE_TYPE_EFI:
			/* Extensible Firmware Interface (EFI). */
			set_bit(ROM_CODE_TYPE_EFI, &ha->code_types);
			ha->efi_revision[0] = bcode[0x12];
			ha->efi_revision[1] = bcode[0x13];
			DEBUG9(printk("%s(): read EFI %d.%d.\n", __func__,
			    ha->efi_revision[1], ha->efi_revision[0]));
			break;
		default:
			DEBUG10(printk("%s(): Unrecognized code type %x at "
			    "pcids %x.\n", __func__, code_type, pcids));
			break;
		}

		last_image = bcode[0x15] & BIT_7;

		/* Locate next PCI expansion ROM. */
		pcihdr += ((bcode[0x11] << 8) | bcode[0x10]) * 512;
	} while (!last_image);

	/* Read firmware image information. */
	memset(ha->fw_revision, 0, sizeof(ha->fw_revision));
	dcode = (uint32_t *)ptmp_mem;

	qim24xx_read_flash_data(dr_ha, dcode, FA_RISC_CODE_ADDR + 4, 4);
	for (i = 0; i < 4; i++)
		dcode[i] = be32_to_cpu(dcode[i]);

	if ((dcode[0] == 0xffffffff && dcode[1] == 0xffffffff &&
	    dcode[2] == 0xffffffff && dcode[3] == 0xffffffff) ||
	    (dcode[0] == 0 && dcode[1] == 0 && dcode[2] == 0 &&
	    dcode[3] == 0)) {
		DEBUG10(printk("%s(): Unrecognized fw version at %x.\n",
		    __func__, FA_RISC_CODE_ADDR));
	} else {
		ha->fw_revision[0] = dcode[0];
		ha->fw_revision[1] = dcode[1];
		ha->fw_revision[2] = dcode[2];
		ha->fw_revision[3] = dcode[3];
	}

	return ret;
}

int
qim24xx_refresh_flash_version(struct qla_host_ioctl *ha, uint8_t *ptmp_mem)
{
	int		ret = 0;
	int		status;
	struct scsi_qla_host	*dr_ha = ha->dr_data;
	struct qla_host_ioctl   *hba2  = NULL;
	struct list_head        *ioctl1;
	struct scsi_qla_host  *dr_ha1 = NULL;

	/* suspend targets */
	qim_suspend_all_target(dr_ha);

	/* wait for big hammer to complete if it fails */
	status = qim_cmd_wait(dr_ha);
	/*
	if (status)
		qla2x00_wait_for_hba_online(ha);
	*/
	if (status)
		return status;

	/* Dont process mailbox cmd until flash
	 * operation is done.
	 */
	set_bit(MBX_UPDATE_FLASH_ACTIVE, &dr_ha->mbx_cmd_flags);

	qim_disable_intrs(dr_ha);

	if (qim24xx_get_flash_version(ha, ptmp_mem)) {
		ret = QLA_FUNCTION_FAILED;
		DEBUG9_10(printk( "%s: ERROR reading flash versions.\n",
		    __func__);)
	}

	/* Reset the second function */
	read_lock(&qim_haioctl_list_lock);
	list_for_each(ioctl1, &qim_haioctl_list) {
		hba2 = list_entry(ioctl1, struct qla_host_ioctl, list);
		dr_ha1 = hba2->dr_data;
		if (pci_domain_nr(dr_ha1->pdev->bus) ==
		    pci_domain_nr(dr_ha->pdev->bus) &&
		    dr_ha1->pdev->bus->number ==
		    dr_ha->pdev->bus->number &&
		    PCI_SLOT(dr_ha1->pdev->devfn) ==
		    PCI_SLOT(dr_ha->pdev->devfn) &&
		    PCI_FUNC(dr_ha1->pdev->devfn) !=
		    PCI_FUNC(dr_ha->pdev->devfn)) {
		    	if (ql2xfwloadbin == 1) {
				DEBUG9(printk("%s(%ld) resetting second "
				    "function\n", __func__, dr_ha1->host_no));
				set_bit(ISP_ABORT_NEEDED, &dr_ha1->dpc_flags);
				up(dr_ha1->dpc_wait);
				qim_wait_for_hba_online(dr_ha1);
			}
			break;
		}

	}
	read_unlock(&qim_haioctl_list_lock);

	memcpy(hba2->bios_revision, ha->bios_revision, sizeof(ha->bios_revision));
	memcpy(hba2->fcode_revision, ha->fcode_revision, sizeof(ha->fcode_revision));
	memcpy(hba2->efi_revision, ha->efi_revision, sizeof(ha->efi_revision));
	memcpy(hba2->fw_revision, ha->fw_revision, sizeof(ha->fw_revision));

	qim_enable_intrs(dr_ha);
	clear_bit(MBX_UPDATE_FLASH_ACTIVE, &dr_ha->mbx_cmd_flags);
	qim_unsuspend_all_target(dr_ha);

	return (ret);
}

uint16_t
qim24xx_update_or_read_flash(scsi_qla_host_t *ha, uint8_t *image,
    uint32_t saddr, uint32_t length, uint8_t direction)
{
	uint32_t	status;

	/* Not setting the timer so that tgt remains unsuspended */
	qim_suspend_all_target(ha);

	/* wait for big hammer to complete if it fails */
	status = qim_cmd_wait(ha);
	/*
	if (status)
		qim_wait_for_hba_online(ha);
	*/

	if (status)
		/* just return busy since there's outstanding command */
		return status;

	/* Dont process mailbox cmd until flash operation is done */
	set_bit(MBX_UPDATE_FLASH_ACTIVE, &ha->mbx_cmd_flags);

	qim_disable_intrs(ha);

	switch (direction) {
	case QLA2X00_READ:

		DEBUG9(printk("%s(%ld): Reading image=%p saddr=0x%x "
		    "length=0x%x\n", __func__, ha->host_no, image, saddr >> 2,
		    length >> 2));
		qim24xx_read_flash_data(ha, (uint32_t *)image, saddr >> 2,
		    length >> 2);
		break;

	case QLA2X00_WRITE:

		DEBUG9(printk("%s(%ld): Writing image=%p saddr=0x%x "
		    "length=0x%x\n", __func__, ha->host_no, image, saddr >> 2,
		    length >> 2));
		status = qim24xx_write_flash_data(ha, (uint32_t *)image,
		    saddr >> 2, length >> 2);

		if (ql2xfwloadbin == 1) {
			/* Reset the first function */
			DEBUG9(printk("%s(%ld) resetting first function\n", __func__,
			    ha->host_no));
			set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
			up(ha->dpc_wait);
			qim_wait_for_hba_online(ha);
		}
		break;
	default:
		printk(KERN_INFO "%s unknown operation\n", __func__);
		break;
	}

	qim_enable_intrs(ha);
	clear_bit(MBX_UPDATE_FLASH_ACTIVE, &ha->mbx_cmd_flags);

	qim_unsuspend_all_target(ha);

	return status;
}

uint16_t
qim_update_or_read_flash(scsi_qla_host_t *ha, uint8_t *image,
    uint32_t saddr, uint32_t length, uint8_t direction)
{
	uint16_t    status;	
	uint32_t	cnt;
	struct device_reg_2xxx __iomem *reg = &ha->iobase->isp;

	if (IS_FWI2_CAPABLE(ha))
		return qim24xx_update_or_read_flash(ha, image, saddr, length,
		    direction);

	/* Not setting the timer so that tgt remains unsuspended */
	qim_suspend_all_target(ha);

	/* wait for big hammer to complete if it fails */
	status = qim_cmd_wait(ha);
	/*
	if (status)
		status = qim_wait_for_hba_online(ha);
	*/

	if (status)
		return status;

	/* Dont process mailbox cmd until flash operation is done */
	set_bit(MBX_UPDATE_FLASH_ACTIVE, &ha->mbx_cmd_flags);

	qim_disable_intrs(ha);

	/* Pause RISC. */
	WRT_REG_WORD(&reg->hccr, HCCR_PAUSE_RISC);
	RD_REG_WORD(&reg->hccr);
	if (IS_QLA2100(ha) || IS_QLA2200(ha) || IS_QLA2300(ha)) {
		for (cnt = 0; cnt < 30000; cnt++) {
			if ((RD_REG_WORD(&reg->hccr) &
			    HCCR_RISC_PAUSE) != 0)
				break;
			qla2xxx_schedule_udelay(100);
		}
	} else {
		qla2xxx_schedule_udelay(10);
	}

	switch (direction) {
	case QLA2X00_READ:
		DEBUG9(printk("%s(%ld): Reading image=%p saddr=0x%x "
		    "length=0x%x\n", __func__, ha->host_no, image, saddr,
		    length));		
		status = qim_read_flash_image(ha, image, saddr, length);
		break;

	case QLA2X00_WRITE:
		DEBUG9(printk("%s(%ld): Writing image=%p saddr=0x%x "
		    "length=0x%x\n", __func__, ha->host_no, image, saddr,
		    length));		
		status = qim_set_flash_image(ha, image, saddr, length);
		break;
	default:
		printk(KERN_INFO "%s unknown operation\n", __func__);
		break;
	}

	/* Schedule DPC to restart the RISC */
	set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
	up(ha->dpc_wait);
	qim_wait_for_hba_online(ha);

	clear_bit(MBX_UPDATE_FLASH_ACTIVE, &ha->mbx_cmd_flags);
	
	qim_unsuspend_all_target(ha);

	return status;
}

/**
 * qim_get_fcode_version() - Determine an FCODE image's version.
 * @ha: HA context
 * @pcids: Pointer to the FCODE PCI data structure
 *
 * The process of retrieving the FCODE version information is at best
 * described as interesting.
 *
 * Within the first 100h bytes of the image an ASCII string is present
 * which contains several pieces of information including the FCODE
 * version.  Unfortunately it seems the only reliable way to retrieve
 * the version is by scanning for another sentinel within the string,
 * the FCODE build date:
 *
 *	... 2.00.02 10/17/02 ...
 *
 * Returns QLA_SUCCESS on successful retrieval of version.
 */
static int
qim_get_fcode_version(struct qla_host_ioctl *ha, uint32_t pcids)
{
	int			ret = QLA_FUNCTION_FAILED;
	uint32_t		istart, iend, iter, vend;
	uint8_t			do_next, rbyte, *vbyte;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	memset(ha->fcode_revision, 0, sizeof(ha->fcode_revision));

	/* Skip the PCI data structure. */
	istart = pcids +
	    ((qim_read_flash_byte(dr_ha, pcids + 0x0B) << 8) |
	    qim_read_flash_byte(dr_ha, pcids + 0x0A));
	iend = istart + 0x100;
	do {
		/* Scan for the sentinel date string...eeewww. */
		do_next = 0;
		iter = istart;
		while ((iter < iend) && !do_next) {
			iter++;
			if (qim_read_flash_byte(dr_ha, iter) == '/') {
				if (qim_read_flash_byte(dr_ha, iter + 2) == '/')
					do_next++;
				else if (qim_read_flash_byte(dr_ha, iter + 3) ==
				    '/')
					do_next++;
			}
		}
		if (!do_next)
			break;

		/* Backtrack to previous ' ' (space). */
		do_next = 0;
		while ((iter > istart) && !do_next) {
			iter--;
			if (qim_read_flash_byte(dr_ha, iter) == ' ')
				do_next++;
		}
		if (!do_next)
			break;

		/*
		 * Mark end of version tag, and find previous ' ' (space) or
		 * string length (recent FCODE images -- major hack ahead!!!).
		 */
		vend = iter - 1;
		do_next = 0;
		while ((iter > istart) && !do_next) {
			iter--;
			rbyte = qim_read_flash_byte(dr_ha, iter);
			if (rbyte == ' ' || rbyte == 0xd || rbyte == 0x10)
				do_next++;
		}
		if (!do_next)
			break;

		/* Mark beginning of version tag, and copy data. */
		iter++;
		if ((vend - iter) &&
		    ((vend - iter) < sizeof(ha->fcode_revision))) {
			vbyte = ha->fcode_revision;
			while (iter <= vend) {
				*vbyte++ = qim_read_flash_byte(dr_ha, iter);
				iter++;
			}
			ret = QLA_SUCCESS;	
		}
	} while (0);

	return ret;
}

/**
 * qim_get_flash_version() - Read version information from flash.
 * @ha: HA context
 *
 * Returns QLA_SUCCESS on successful retrieval of flash version.
 */
int
qim_get_flash_version(struct qla_host_ioctl *ha, uint8_t *ptmp_mem)
{
	int		ret = QLA_SUCCESS;
	uint8_t		code_type, last_image;
	uint32_t	pcihdr, pcids;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	if (IS_FWI2_CAPABLE(dr_ha))
		return qim24xx_get_flash_version(ha, ptmp_mem);

	if (!dr_ha->pio_address)
		return QLA_FUNCTION_FAILED;

	DEBUG9(printk("%s(%ld): inst=%ld entered.\n",
	    __func__, ha->host_no, ha->instance));

	qim_flash_enable(dr_ha);

	/* Begin with first PCI expansion ROM header. */
	pcihdr = 0;
	last_image = 1;
	do {
		/* Verify PCI expansion ROM header. */
		if (qim_read_flash_byte(dr_ha, pcihdr) != 0x55 ||
		    qim_read_flash_byte(dr_ha, pcihdr + 0x01) != 0xaa) {
			/* No signature */
			DEBUG2(printk("scsi(%ld): No matching ROM signature.\n",
			    ha->host_no));
			ret = QLA_FUNCTION_FAILED;
			break;
		}

		/* Locate PCI data structure. */
		pcids = pcihdr +
		    ((qim_read_flash_byte(dr_ha, pcihdr + 0x19) << 8) |
			qim_read_flash_byte(dr_ha, pcihdr + 0x18));

		/* Validate signature of PCI data structure. */
		if (qim_read_flash_byte(dr_ha, pcids) != 'P' ||
		    qim_read_flash_byte(dr_ha, pcids + 0x1) != 'C' ||
		    qim_read_flash_byte(dr_ha, pcids + 0x2) != 'I' ||
		    qim_read_flash_byte(dr_ha, pcids + 0x3) != 'R') {
			/* Incorrect header. */
			DEBUG2(printk("%s(): PCI data struct not found "
			    "pcir_adr=%x.\n",
			    __func__, pcids));
			ret = QLA_FUNCTION_FAILED;
			break;
		}

		/* Read version */
		code_type = qim_read_flash_byte(dr_ha, pcids + 0x14);
		switch (code_type) {
		case ROM_CODE_TYPE_BIOS:
			/* Intel x86, PC-AT compatible. */
			set_bit(ROM_CODE_TYPE_BIOS, &ha->code_types);
			ha->bios_revision[0] =
			    qim_read_flash_byte(dr_ha, pcids + 0x12);
			ha->bios_revision[1] =
			    qim_read_flash_byte(dr_ha, pcids + 0x13);
			printk("%s(): read BIOS %d.%d.\n", __func__,
			    ha->bios_revision[1], ha->bios_revision[0]);
			DEBUG9(printk("%s(): read BIOS %d.%d.\n", __func__,
			    ha->bios_revision[1], ha->bios_revision[0]);)
			break;
		case ROM_CODE_TYPE_FCODE:
			/* Open Firmware standard for PCI (FCode). */
			/* Eeeewww... */
			if (qim_get_fcode_version(ha, pcids) == QLA_SUCCESS)
				set_bit(ROM_CODE_TYPE_FCODE, &ha->code_types);
			DEBUG9(printk("%s(): read FCODE %d.%d.%d.\n", __func__,
			    ha->fcode_revision[1], ha->fcode_revision[1], ha->fcode_revision[0]);)
			break;
		case ROM_CODE_TYPE_EFI:
			/* Extensible Firmware Interface (EFI). */
			set_bit(ROM_CODE_TYPE_EFI, &ha->code_types);
			ha->efi_revision[0] =
			    qim_read_flash_byte(dr_ha, pcids + 0x12);
			ha->efi_revision[1] =
			    qim_read_flash_byte(dr_ha, pcids + 0x13);
			DEBUG3(printk("%s(): read EFI %d.%d.\n", __func__,
			    dr_ha->efi_revision[1], dr_ha->efi_revision[0]));
			break;
		default:
			DEBUG2(printk("%s(): Unrecognized code type %x at "
			    "pcids %x.\n", __func__, code_type, pcids));
			break;
		}

		last_image = qim_read_flash_byte(dr_ha, pcids + 0x15) & BIT_7;

		/* Locate next PCI expansion ROM. */
		pcihdr += ((qim_read_flash_byte(dr_ha, pcids + 0x11) << 8) |
		    qim_read_flash_byte(dr_ha, pcids + 0x10)) * 512;
	} while (!last_image);

	qim_flash_disable(dr_ha);

	DEBUG9(printk("%s(%ld): inst=%ld exiting.\n",
	    __func__, ha->host_no, ha->instance));

	return ret;
}



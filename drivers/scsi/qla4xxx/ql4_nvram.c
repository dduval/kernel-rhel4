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
 *	FM93C56A_Select
 *	FM93C56A_Cmd
 *	FM93C56A_Deselect
 *	FM93C56A_DataIn
 *	EEPROM_ReadWord
 *	RD_NVRAM_WORD
 ****************************************************************************/

#include <linux/delay.h>
#include "ql4_def.h"

#define EEPROM_SIZE(ha) \
	(IS_QLA4010(ha) ? \
	 FM93C66A_SIZE_16 : \
	 FM93C86A_SIZE_16)
	
#define EEPROM_NO_ADDR_BITS(ha) \
	(IS_QLA4010(ha) ? \
	 FM93C56A_NO_ADDR_BITS_16 : \
	 FM93C86A_NO_ADDR_BITS_16)

#define EEPROM_NO_DATA_BITS(ha) FM93C56A_DATA_BITS_16

static inline void write_eeprom(scsi_qla_host_t *ha, unsigned long cmd)
{
	WRT_REG_DWORD(ISP_NVRAM(ha), cmd);
	PCI_POSTING(ISP_NVRAM(ha));
	udelay(1);
}

static int   eepromCmdData = 0;


static int FM93C56A_Select(scsi_qla_host_t *ha)
{
	QL4PRINT(QLP17, printk(KERN_ERR "FM93C56A_Select:\n"));
	eepromCmdData = AUBURN_EEPROM_CS_1 | 0x000f0000;
	write_eeprom(ha, eepromCmdData);
	return(1);
}

static int FM93C56A_Cmd(scsi_qla_host_t *ha, int cmd, int addr)
{
	int   i;
	int   mask;
	int   dataBit;
	int   previousBit;

	QL4PRINT(QLP17, printk(KERN_ERR "FM93C56A_Cmd(%d, 0x%x)\n", cmd, addr));

	// Clock in a zero, then do the start bit
	write_eeprom(ha, eepromCmdData | AUBURN_EEPROM_DO_1);
	write_eeprom(ha, eepromCmdData | AUBURN_EEPROM_DO_1 | AUBURN_EEPROM_CLK_RISE);
	write_eeprom(ha, eepromCmdData | AUBURN_EEPROM_DO_1 | AUBURN_EEPROM_CLK_FALL);

	mask = 1 << (FM93C56A_CMD_BITS-1);
	// Force the previous data bit to be different
	previousBit = 0xffff;
	for (i = 0; i < FM93C56A_CMD_BITS; i++) {
		dataBit = (cmd & mask) ? AUBURN_EEPROM_DO_1 : AUBURN_EEPROM_DO_0;
		if (previousBit != dataBit) {
			// If the bit changed, then change the DO state to match
			write_eeprom(ha, eepromCmdData | dataBit);
			previousBit = dataBit;
		}
		write_eeprom(ha, eepromCmdData | dataBit | AUBURN_EEPROM_CLK_RISE);
		write_eeprom(ha, eepromCmdData | dataBit | AUBURN_EEPROM_CLK_FALL);
		cmd = cmd << 1;
	}

	mask = 1 << (EEPROM_NO_ADDR_BITS(ha)-1);
	// Force the previous data bit to be different
	previousBit = 0xffff;
	for (i = 0; i < EEPROM_NO_ADDR_BITS(ha); i++) {
		dataBit = (addr & mask) ? AUBURN_EEPROM_DO_1 : AUBURN_EEPROM_DO_0;
		if (previousBit != dataBit) {
			// If the bit changed, then change the DO state to match
			write_eeprom(ha, eepromCmdData | dataBit);
			previousBit = dataBit;
		}
		write_eeprom(ha, eepromCmdData | dataBit | AUBURN_EEPROM_CLK_RISE);
		write_eeprom(ha, eepromCmdData | dataBit | AUBURN_EEPROM_CLK_FALL);
		addr = addr << 1;
	}
	return(1);
}

static int FM93C56A_Deselect(scsi_qla_host_t *ha)
{
	QL4PRINT(QLP17, printk(KERN_ERR "FM93C56A_Deselect:\n"));
	eepromCmdData = AUBURN_EEPROM_CS_0 | 0x000f0000 ;
	write_eeprom(ha, eepromCmdData);
	return(1);
}

static int FM93C56A_DataIn(scsi_qla_host_t *ha, unsigned short *value)
{
	int   i;
	int   data = 0;
	int   dataBit;

	// Read the data bits
	// The first bit is a dummy.  Clock right over it.
	for (i = 0; i < EEPROM_NO_DATA_BITS(ha); i++) {
		write_eeprom(ha, eepromCmdData | AUBURN_EEPROM_CLK_RISE);
		write_eeprom(ha, eepromCmdData | AUBURN_EEPROM_CLK_FALL);
		dataBit = (RD_REG_DWORD(ISP_NVRAM(ha)) & AUBURN_EEPROM_DI_1) ? 1 : 0;
		udelay(1);
		data = (data << 1) | dataBit;
	}
	*value = data;
	QL4PRINT(QLP17, printk(KERN_ERR "FM93C56A_DataIn(0x%x)\n", *value));
	return(1);
}

static int
EEPROM_ReadWord(int eepromAddr, u16 *value, scsi_qla_host_t *ha)
{
	QL4PRINT(QLP17, printk(KERN_ERR "EEPROM_Reg addr %p\n", ISP_NVRAM(ha)));
	QL4PRINT(QLP17, printk(KERN_ERR "EEPROM_ReadWord(0x%x)\n", eepromAddr));

	FM93C56A_Select(ha);
	FM93C56A_Cmd(ha, FM93C56A_READ, eepromAddr);
	FM93C56A_DataIn(ha, value);
	FM93C56A_Deselect(ha);
	QL4PRINT(QLP17, printk(KERN_ERR "EEPROM_ReadWord(0x%x, %d)\n",
			       eepromAddr, *value));
	return(1);
}

/* Hardware_lock must be set before calling */
u16
RD_NVRAM_WORD(scsi_qla_host_t *ha, int offset)
{
	u16 val;
	/* NOTE: NVRAM uses half-word addresses */
	EEPROM_ReadWord(offset, &val, ha);
	return(val);
}

uint8_t
qla4xxx_is_NVRAM_configuration_valid(scsi_qla_host_t *ha)
{
	uint16_t checksum = 0;
	uint32_t index;
	unsigned long flags;
	uint8_t status = QLA_ERROR;

	spin_lock_irqsave(&ha->hardware_lock, flags);
	for (index = 0;	index < EEPROM_SIZE(ha); index++) {
		checksum += RD_NVRAM_WORD(ha, index);
	}
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	if (checksum == 0)
		status = QLA_SUCCESS;

	return (status);
}

/*************************************************************************
 *
 *			Hardware Semaphore routines
 *
 *************************************************************************/
int ql4xxx_sem_spinlock(scsi_qla_host_t *ha, u32 sem_mask, u32 sem_bits)
{
    uint32_t      value;
    unsigned long wait_time;

    DEBUG2(printk("scsi%d: Trying to get SEM lock - mask= 0x%x, code = 0x%x\n",
	ha->host_no, sem_mask, sem_bits);)

    wait_time = jiffies + (ISP_SEM_WAIT_TOV * HZ);
    do {
        WRT_REG_DWORD(ISP_SEMAPHORE(ha), (sem_mask | sem_bits));
        value = RD_REG_DWORD(ISP_SEMAPHORE(ha));
        if ((value & (sem_mask >> 16)) == sem_bits) {
    		DEBUG2(printk("scsi%d: Got SEM LOCK - mask= 0x%x, code = 0x%x\n",
		ha->host_no, sem_mask, sem_bits);)
            break;
	}
	msleep(1);
    } while (!time_after_eq(jiffies, wait_time));
   return (1);
}

void ql4xxx_sem_unlock(scsi_qla_host_t *ha, u32 sem_mask)
{

    WRT_REG_DWORD(ISP_SEMAPHORE(ha), sem_mask);
    PCI_POSTING(ISP_SEMAPHORE(ha));
    DEBUG2(printk("scsi%d: UNLOCK SEM - mask= 0x%x\n",
	 ha->host_no, sem_mask);)
}

int ql4xxx_sem_lock(scsi_qla_host_t *ha, u32 sem_mask, u32 sem_bits)
{
    uint32_t      value;

    WRT_REG_DWORD(ISP_SEMAPHORE(ha), (sem_mask | sem_bits));
    value = RD_REG_DWORD(ISP_SEMAPHORE(ha));
    if ((value & (sem_mask >> 16)) == sem_bits) {
    	DEBUG2(printk("scsi%d: Got SEM LOCK - mask= 0x%x, code = 0x%x, sema code=0x%x\n",
		ha->host_no, sem_mask, sem_bits, value);)
        return (1);
    } else {
        return (0);
    }
}

/*
 * Overrides for Emacs so that we get a uniform tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-indent-level: 4
 * c-brace-imaginary-offset: 0
 * c-brace-offset: -4
 * c-argdecl-indent: 4
 * c-label-offset: -4
 * c-continued-statement-offset: 4
 * c-continued-brace-offset: 0
 * indent-tabs-mode: nil
 * tab-width: 8
 * End:
 */

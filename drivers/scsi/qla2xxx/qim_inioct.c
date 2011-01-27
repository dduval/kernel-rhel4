#include "qim_ioctl.h"


/* Option ROM definitions. */
INT_OPT_ROM_REGION OptionRomTable2312[] = 
{
    {INT_OPT_ROM_REGION_ALL, INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_PHBIOS_FCODE_EFI_CFW, INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};

INT_OPT_ROM_REGION OptionRomTable6312[] = // 128k x20000
{
    {INT_OPT_ROM_REGION_ALL,    INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_PHBIOS_CFW, INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};

INT_OPT_ROM_REGION OptionRomTableHp[] = // 128k x20000
{
    {INT_OPT_ROM_REGION_ALL, INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_PHEFI_PHECFW_PHVPD, INT_OPT_ROM_SIZE_2312,
	    0, INT_OPT_ROM_SIZE_2312-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};

INT_OPT_ROM_REGION  OptionRomTable2322[] = // 1 M x100000
{
    {INT_OPT_ROM_REGION_ALL, INT_OPT_ROM_SIZE_2322,
	    0, INT_OPT_ROM_SIZE_2322-1},
    {INT_OPT_ROM_REGION_PHBIOS_PHFCODE_PHEFI_FW, INT_OPT_ROM_SIZE_2322,
	    0, INT_OPT_ROM_SIZE_2322-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};

INT_OPT_ROM_REGION  OptionRomTable6322[] = // 1 M x100000
{
    {INT_OPT_ROM_REGION_ALL, INT_OPT_ROM_SIZE_2322,
	    0, INT_OPT_ROM_SIZE_2322-1},
    {INT_OPT_ROM_REGION_PHBIOS_FW, INT_OPT_ROM_SIZE_2322,
	    0, INT_OPT_ROM_SIZE_2322-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};

INT_OPT_ROM_REGION OptionRomTable2422[] = // 1 M x100000
{
    {INT_OPT_ROM_REGION_ALL, INT_OPT_ROM_SIZE_2422,
	    0, INT_OPT_ROM_SIZE_2422-1},
    {INT_OPT_ROM_REGION_PHBIOS_PHFCODE_PHEFI, 0x40000,
	    0, 0x40000-1 },
    {INT_OPT_ROM_REGION_FW, 0x80000,
	    0x80000, INT_OPT_ROM_SIZE_2422-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
}; 



int
qim_read_nvram(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int	ret = 0;
	char	*ptmp_buf;
	uint32_t transfer_size;
	unsigned long flags;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("qim_read_nvram: entered.\n");)

	if (qim_get_ioctl_scrap_mem(ha, (void **)&ptmp_buf,
	    dr_ha->nvram_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, ha->host_no, ha->instance,
		    dr_ha->nvram_size);)
		return (ret);
	}

	transfer_size = dr_ha->nvram_size;
	if (pext->ResponseLen < dr_ha->nvram_size)
		transfer_size = pext->ResponseLen;

	/* Dump NVRAM. */
	spin_lock_irqsave(&dr_ha->hardware_lock, flags);
	qim_read_nvram_data(dr_ha, (uint8_t *)ptmp_buf, dr_ha->nvram_base,
	    dr_ha->nvram_size);
	spin_unlock_irqrestore(&dr_ha->hardware_lock, flags);

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_buf, transfer_size);
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

	DEBUG9(printk("qim_read_nvram: exiting.\n");)

	return (ret);
}

/*
 * qim_update_nvram
 *	Write data to NVRAM.
 *
 * Input:
 *	ha = adapter block pointer.
 *	pext = pointer to driver internal IOCTL structure.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
int
qim_update_nvram(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	uint8_t cnt;
	uint8_t *usr_tmp, *kernel_tmp;
	nvram_t *pnew_nv;
	uint32_t transfer_size;
	int ret = 0;
	unsigned long flags;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("qim_update_nvram: entered.\n");)

	if (pext->RequestLen < dr_ha->nvram_size)
		transfer_size = pext->RequestLen;
	else
		transfer_size = dr_ha->nvram_size;

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pnew_nv,
	    dr_ha->nvram_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, ha->host_no, ha->instance, dr_ha->nvram_size));
		return (ret);
	}

	/* Read from user buffer */
	kernel_tmp = (uint8_t *)pnew_nv;
	usr_tmp = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);

	ret = copy_from_user(kernel_tmp, usr_tmp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "qim_update_nvram: ERROR in buffer copy READ. "
		    "RequestAdr=%p\n", Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode));)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	/* Checksum NVRAM. */
	if (IS_QLA24XX(dr_ha) || IS_QLA54XX(dr_ha)) {
		uint32_t *iter;
		uint32_t chksum;

		iter = (uint32_t *)pnew_nv;
		chksum = 0;
		for (cnt = 0; cnt < ((dr_ha->nvram_size >> 2) - 1); cnt++)
			chksum += le32_to_cpu(*iter++);
		chksum = ~chksum + 1;
		*iter = cpu_to_le32(chksum);
	} else {
		uint8_t *iter;
		uint8_t chksum;

		iter = (uint8_t *)pnew_nv;
		chksum = 0;
		for (cnt = 0; cnt < dr_ha->nvram_size - 1; cnt++)
			chksum += *iter++;
		chksum = ~chksum + 1;
		*iter = chksum;
	}

	/* Write NVRAM. */
	spin_lock_irqsave(&dr_ha->hardware_lock, flags);
	qim_write_nvram_data(dr_ha, (uint8_t *)pnew_nv, dr_ha->nvram_base,
	    transfer_size);
	spin_unlock_irqrestore(&dr_ha->hardware_lock, flags);

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("qim_update_nvram: exiting.\n");)

	/* Schedule DPC to restart the RISC */
	set_bit(ISP_ABORT_NEEDED, &dr_ha->dpc_flags);
	up(dr_ha->dpc_wait);

	if (qim_wait_for_hba_online(dr_ha) != QLA_SUCCESS) {
		pext->Status = EXT_STATUS_ERR;
	}

	return ret;
}

int
qim_get_vpd(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint8_t		*ptmp_buf;
	uint32_t	data_offset;
	uint32_t	transfer_size;
	unsigned long	flags;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	if (!(IS_QLA24XX(dr_ha) || IS_QLA54XX(dr_ha))) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld not 24xx or 25xx. got %x. exiting.\n",
		    __func__, ha->host_no, ha->instance,
		    dr_ha->pdev->device));
		return (ret);
	}

	DEBUG9(printk("%s(%ld): entered.\n", __func__, ha->host_no);)

	transfer_size = FA_NVRAM_VPD_SIZE * 4; /* byte count */
	if (pext->ResponseLen < transfer_size) {
		pext->ResponseLen = transfer_size;
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld Response buffer too small.\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&ptmp_buf,
	    transfer_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, ha->host_no, ha->instance,
		    dr_ha->nvram_size);)
		return (ret);
	}

	if (PCI_FUNC(dr_ha->pdev->devfn))
		data_offset = FA_NVRAM_VPD1_ADDR;
	else
		data_offset = FA_NVRAM_VPD0_ADDR;

	/* Dump VPD region in NVRAM. */
	spin_lock_irqsave(&dr_ha->hardware_lock, flags);
	qim_read_nvram_data(dr_ha, ptmp_buf, data_offset, transfer_size);
	spin_unlock_irqrestore(&dr_ha->hardware_lock, flags);

	DEBUG9(printk("%s(%ld): inst=%ld offset=%x xfr_size=%d. vpd dump-\n",
	    __func__, ha->host_no, ha->instance, data_offset, transfer_size);)
	DEBUG9(qim_dump_buffer((uint8_t *)ptmp_buf, transfer_size);)
	
	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    ptmp_buf, transfer_size);
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

	DEBUG9(printk("%s(%ld): exiting.\n", __func__, ha->host_no);)

	return (ret);
}

int
qim_update_vpd(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	uint8_t		*usr_tmp, *kernel_tmp, *pnew_nv;
	uint32_t	data_offset;
	uint32_t	transfer_size;
	unsigned long	flags;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	if (!(IS_QLA24XX(dr_ha) || IS_QLA54XX(dr_ha))) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld not 24xx or 25xx. exiting.\n",
		    __func__, ha->host_no, ha->instance));
		return (ret);
	}

	DEBUG9(printk("%s(%ld): entered.\n", __func__, ha->host_no);)

	transfer_size = FA_NVRAM_VPD_SIZE * 4; /* byte count */
	if (pext->RequestLen < transfer_size)
		transfer_size = pext->RequestLen;

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pnew_nv, transfer_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, ha->host_no, ha->instance, transfer_size));
		return (ret);
	}

	DEBUG9(printk("%s(%ld): transfer_size=%d.\n",
	    __func__, ha->host_no, transfer_size);)

	/* Read from user buffer */
	kernel_tmp = (uint8_t *)pnew_nv;
	usr_tmp = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);

	ret = copy_from_user(kernel_tmp, usr_tmp, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): ERROR in buffer copy READ. RequestAdr=%p\n",
		    __func__, ha->host_no, Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode));)
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	if (PCI_FUNC(dr_ha->pdev->devfn))
		data_offset = FA_NVRAM_VPD1_ADDR;
	else
		data_offset = FA_NVRAM_VPD0_ADDR;

	/* Write NVRAM. */
	spin_lock_irqsave(&dr_ha->hardware_lock, flags);
	qim_write_nvram_data(dr_ha, pnew_nv, data_offset, transfer_size);
	spin_unlock_irqrestore(&dr_ha->hardware_lock, flags);

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): exiting.\n", __func__, ha->host_no);)

	/* No need to reset the 24xx. */
	return ret;
}

static void
qim_get_option_rom_table(scsi_qla_host_t *ha,
    INT_OPT_ROM_REGION **pOptionRomTable, unsigned long  *OptionRomTableSize)
{
	DEBUG9(printk("%s: entered.\n", __func__));

	switch (ha->pdev->device) {
	case PCI_DEVICE_ID_QLOGIC_ISP6312:
		*pOptionRomTable = OptionRomTable6312;
		*OptionRomTableSize = sizeof(OptionRomTable6312);
		break;		       	
	case PCI_DEVICE_ID_QLOGIC_ISP2312:
		/* HBA Model 6826A - is 2312 V3 Chip */
		if (ha->pdev->subsystem_vendor == 0x103C &&
		    ha->pdev->subsystem_device == 0x12BA) {
			*pOptionRomTable = OptionRomTableHp;
			*OptionRomTableSize = sizeof(OptionRomTableHp);
		} else {
			*pOptionRomTable = OptionRomTable2312;
			*OptionRomTableSize = sizeof(OptionRomTable2312);
		}
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP2322:
		*pOptionRomTable = OptionRomTable2322;
		*OptionRomTableSize = sizeof(OptionRomTable2322);
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP6322:
		*pOptionRomTable = OptionRomTable6322;
		*OptionRomTableSize = sizeof(OptionRomTable6322);
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP2422:
	case PCI_DEVICE_ID_QLOGIC_ISP2432:
		*pOptionRomTable = OptionRomTable2422;
		*OptionRomTableSize = sizeof(OptionRomTable2422);
		break;
	default: 
		DEBUG9_10(printk("%s(%ld) Option Rom Table for device_id=0x%x "
		    "not defined\n", __func__, ha->host_no, ha->pdev->device));
		break;
	}

	DEBUG9(printk("%s: exiting.\n", __func__);)
}

int
qim_get_option_rom_layout(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int			ret = 0, iter;
	INT_OPT_ROM_REGION	*OptionRomTable = NULL;
	INT_OPT_ROM_LAYOUT	*optrom_layout;	
	uint32_t		no_regions;
	unsigned long		OptionRomTableSize; 
	unsigned long		OptionRomLayoutSize; 
	struct scsi_qla_host	*dr_ha;


	DEBUG9(printk("%s: entered.\n", __func__);)

	dr_ha = ha->dr_data;

	/* Pick the right OptionRom table based on device id */
	qim_get_option_rom_table(dr_ha, &OptionRomTable, &OptionRomTableSize);

	if (OptionRomTable == NULL) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld) Option Rom Table for device_id=0x%x "
		    "not defined\n", __func__, ha->host_no,
		    dr_ha->pdev->device));
		return ret;
	}

	/* calculate exactly how many entries we got */
	// Dont Count the NULL Entry.
	no_regions = (UINT32)
	    (OptionRomTableSize / sizeof(INT_OPT_ROM_REGION) - 1);
	OptionRomLayoutSize = (8 + sizeof(INT_OPT_ROM_REGION) * no_regions);

	if (pext->ResponseLen < OptionRomLayoutSize) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk("%s(%ld) buffer too small: response_len = %d "
		    "optrom_table_len=%ld.\n", __func__, ha->host_no,
		    pext->ResponseLen, OptionRomTableSize));
		return ret;
	}

	if (qim_get_ioctl_scrap_mem(ha, (void **)&optrom_layout,
	    OptionRomLayoutSize)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%ld.\n", __func__, ha->host_no,
		    ha->instance, OptionRomTableSize));
		return ret;
	}

	optrom_layout->NoOfRegions = no_regions;

	for (iter = 0; iter < optrom_layout->NoOfRegions; iter++) {
		optrom_layout->Region[iter].Region =
		    OptionRomTable[iter].Region;
		optrom_layout->Region[iter].Size =
		    OptionRomTable[iter].Size;
		optrom_layout->Region[iter].Beg =
		    OptionRomTable[iter].Beg;
		optrom_layout->Region[iter].End =
		    OptionRomTable[iter].End;

		if (OptionRomTable[iter].Region == INT_OPT_ROM_REGION_ALL)
			optrom_layout->Size = OptionRomTable[iter].Size;
	}

	ret = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode),
	    optrom_layout, OptionRomLayoutSize);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance));
		qim_free_ioctl_scrap_mem(ha);
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s: exiting.\n", __func__));

	return ret;
}

int
qim_read_option_rom_ext(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int			iter, found;
	int			rval = 0;
	uint8_t			*image_ptr;
	uint32_t		saddr, length;
	struct scsi_qla_host	*dr_ha = ha->dr_data;

	DEBUG9(printk("%s: entered.\n", __func__);)

	found = 0;
	saddr = length = 0;

	/* Retrieve region or raw starting address. */
	if (pext->SubCode == 0xFFFF) {
		saddr = pext->Reserved1;
		length = pext->RequestLen;
		found++;
	} else {
		INT_OPT_ROM_REGION *OptionRomTable = NULL;
		unsigned long OptionRomTableSize;

		/* Pick the right OptionRom table based on device id */
		qim_get_option_rom_table(dr_ha, &OptionRomTable,
		    &OptionRomTableSize);

		for (iter = 0; OptionRomTable != NULL && iter <
		    (OptionRomTableSize / sizeof(INT_OPT_ROM_REGION));
		    iter++) {
			if (OptionRomTable[iter].Region == pext->SubCode) {
				saddr = OptionRomTable[iter].Beg;
				length = OptionRomTable[iter].Size;
				DEBUG9(printk("%s: found region %x.\n",
				    __func__, pext->SubCode);)
				found++;
				break;
			}
		}
	}

	if (!found) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return rval;
	}

	if (pext->ResponseLen < length) {
		pext->Status = EXT_STATUS_COPY_ERR;
		return (-EFAULT);
	}

	image_ptr = vmalloc(length);
	if (image_ptr == NULL) {
		pext->Status = EXT_STATUS_NO_MEMORY;
		printk(KERN_WARNING
		    "%s: ERROR in flash allocation.\n", __func__);
		return rval;
	}

	DEBUG9(printk("%s: done malloc. going to read.\n", __func__);)

	/* Dump FLASH. */
 	if (qim_update_or_read_flash(dr_ha, image_ptr, saddr, length,
	    QLA2X00_READ)) {
		pext->Status = EXT_STATUS_BUSY;
	} else {

		DEBUG9(printk("%s: done read. going to copy.\n", __func__);)

		if (copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode), image_ptr, length)) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
			    __func__, ha->host_no, ha->instance));
			vfree(image_ptr);
			return (-EFAULT);
		}
	}

	vfree(image_ptr);

	DEBUG9(printk("%s: exiting.\n", __func__);)

	return rval;
}

int
qim_read_option_rom(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int			rval = 0;
	struct scsi_qla_host	*dr_ha = ha->dr_data;
	uint8_t			*image_ptr;


	if (pext->SubCode)
		return qim_read_option_rom_ext(ha, pext, mode);

	DEBUG9(printk("%s: entered.\n", __func__);)

	/* These interfaces are not valid for 24xx and 25xx chips. */
	if (IS_QLA24XX(dr_ha) || IS_QLA54XX(dr_ha)) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		return rval;
	}

	/* The ISP2312 v2 chip cannot access the FLASH registers via MMIO. */
	if (IS_QLA2312(dr_ha) && dr_ha->product_id[3] == 0x2 &&
	    !dr_ha->pio_address) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		return rval;
	}

	if (pext->ResponseLen != FLASH_IMAGE_SIZE) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		return rval;
	}

	image_ptr = vmalloc(FLASH_IMAGE_SIZE);
	if (image_ptr == NULL) {
		pext->Status = EXT_STATUS_NO_MEMORY;
		printk(KERN_WARNING
		    "%s: ERROR in flash allocation.\n", __func__);
		return rval;
	}

	/* Dump FLASH. This is for non-24xx/25xx */
 	if (qim_update_or_read_flash(dr_ha, image_ptr, 0, FLASH_IMAGE_SIZE,
	    QLA2X00_READ)) {
		pext->Status = EXT_STATUS_BUSY;
	} else if (copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode), image_ptr, FLASH_IMAGE_SIZE)) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, ha->host_no, ha->instance));
		rval = -EFAULT;
	}
	vfree(image_ptr);

	DEBUG9(printk("%s: exiting.\n", __func__);)

	return rval;
}

int
qim_update_option_rom_ext(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int			iter, found;
	int			ret = 0;
	uint16_t		status;
	uint8_t			*usr_tmp;
	uint8_t			*kern_tmp;
	uint8_t			*ptmp_mem = NULL;
	uint32_t		saddr, length;
	struct scsi_qla_host	*dr_ha = ha->dr_data;

	DEBUG9(printk("%s: entered.\n", __func__);)

	found = 0;
	saddr = length = 0;
	/* Retrieve region or raw starting address. */
	if (pext->SubCode == 0xFFFF) {
		saddr = pext->Reserved1;
		length = pext->RequestLen;
		found++;
	} else {
		INT_OPT_ROM_REGION *OptionRomTable = NULL;
		unsigned long  OptionRomTableSize;

		/* Pick the right OptionRom table based on device id */
		qim_get_option_rom_table(dr_ha, &OptionRomTable,
		    &OptionRomTableSize);

		for (iter = 0; OptionRomTable != NULL && iter <
		    (OptionRomTableSize / sizeof(INT_OPT_ROM_REGION));
		    iter++) {
			if (OptionRomTable[iter].Region == pext->SubCode) {
				saddr = OptionRomTable[iter].Beg;
				length = OptionRomTable[iter].Size;
				found++;
				break;
			}
		}
	}

	if (!found) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		return ret;
	}

	if (pext->RequestLen < length) {
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		return ret;
	}

	/* Read from user buffer */
	usr_tmp = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);

	kern_tmp = vmalloc(length);
	if (kern_tmp == NULL) {
		pext->Status = EXT_STATUS_NO_MEMORY;
		printk(KERN_WARNING
		    "%s: ERROR in flash allocation.\n", __func__);
		return ret;
	}

	ret = copy_from_user(kern_tmp, usr_tmp, length);
	if (ret) {
		vfree(kern_tmp);
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s: ERROR in buffer copy READ. "
		    "RequestAdr=%p\n", __func__,
		    Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode)));
		return (-EFAULT);
	}

	/* Go with update */
	status = qim_update_or_read_flash(dr_ha, kern_tmp, saddr, length,
	    QLA2X00_WRITE);

	vfree(kern_tmp);
	pext->Status = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	if (status) {
		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s: ERROR updating flash.\n", __func__);)
	} else {
		/* Update our db with the newly updated flash version values. */
		if (IS_QLA24XX(dr_ha) || IS_QLA54XX(dr_ha)) {
			DEBUG9(printk("%s(%ld): refresh flash versions.\n",
			    __func__, ha->host_no);)

			if (qim_get_ioctl_scrap_mem(ha,
			    (void **)&ptmp_mem, sizeof(request_t))) {
				/* not enough memory */
				pext->Status = EXT_STATUS_NO_MEMORY;
				DEBUG9_10(printk("%s(%ld): inst=%ld scrap not "
				    "big enough. size requested=%ld.\n",
				    __func__, ha->host_no,
				    ha->instance, (ulong)sizeof(request_t)));
			} else if (qim24xx_refresh_flash_version(ha,
			    ptmp_mem)){

				pext->Status = EXT_STATUS_ERR;
				DEBUG9_10(printk( "%s: ERROR reading updated "
				    "flash versions.\n",
				    __func__);)
			}

			qim_free_ioctl_scrap_mem(ha);
		}
	}

	DEBUG9(printk("%s: exiting.\n", __func__);)

	return ret;
}

int
qim_update_option_rom(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		rval = 0;
	uint8_t		*usr_tmp;
	uint8_t		*kern_tmp;
	uint16_t	status;
	struct scsi_qla_host	*dr_ha = ha->dr_data;

	DEBUG9(printk("%s(%ld): inst=%ld ext ioctl struct dump-\n",
	    __func__, ha->host_no, ha->instance);)
	DEBUG9(qim_dump_buffer((uint8_t *)pext,
	    sizeof(EXT_IOCTL));)

	if (pext->SubCode)
		return qim_update_option_rom_ext(ha, pext, mode);

	DEBUG9(printk("%s: entered.\n", __func__);)

	/* These interfaces are not valid for 24xx and 25xx chips. */
	if (IS_QLA24XX(dr_ha) || IS_QLA54XX(dr_ha)) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		return rval;
	}

	/* The ISP2312 v2 chip cannot access the FLASH registers via MMIO. */
	if (IS_QLA2312(dr_ha) && dr_ha->product_id[3] == 0x2 &&
	    !dr_ha->pio_address) {
		DEBUG10(printk("%s: got 2312 and no flash access via mmio.\n",
		    __func__);)
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		return rval;
	}

	if (pext->RequestLen != FLASH_IMAGE_SIZE) {
		DEBUG10(printk("%s: wrong RequestLen=%d, should be %d.\n",
		    __func__, pext->RequestLen, FLASH_IMAGE_SIZE);)
		pext->Status = EXT_STATUS_INVALID_PARAM;
		return rval;
	}

	/* Read from user buffer */
	kern_tmp = vmalloc(FLASH_IMAGE_SIZE);
	if (kern_tmp == NULL) {
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG10(printk("%s: vmalloc failed.\n", __func__);)
		printk(KERN_WARNING
			"%s: ERROR in flash allocation.\n", __func__);
		return rval;
	}

	usr_tmp = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);

	DEBUG9(printk("%s(%ld): going to copy from user.\n",
	    __func__, ha->host_no);)

	rval = copy_from_user(kern_tmp, usr_tmp, FLASH_IMAGE_SIZE);
	if (rval) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s: ERROR in buffer copy READ. "
		    "RequestAdr=%p\n",
		    __func__, Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode));)
		return (-EFAULT);
	}

	DEBUG9(printk("%s(%ld): done copy from user. data dump:\n",
	    __func__, ha->host_no);)
	DEBUG9(qim_dump_buffer((uint8_t *)kern_tmp,
	    FLASH_IMAGE_SIZE);)

	/* Go with update */
	status = qim_update_or_read_flash(dr_ha, kern_tmp, 0, FLASH_IMAGE_SIZE,
	    QLA2X00_WRITE); 

	vfree(kern_tmp);

	if (status) {
		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("%s: ERROR updating flash.\n", __func__);)
	} else {
		pext->Status = EXT_STATUS_OK;
		pext->DetailStatus = EXT_STATUS_OK;
	}

	DEBUG9(printk("%s: exiting.\n", __func__);)

	return rval;
}

int
qim_send_loopback(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		rval = 0;
	int		status;
	uint16_t	ret_mb[MAILBOX_REGISTER_COUNT];
	INT_LOOPBACK_REQ req;
	INT_LOOPBACK_RSP rsp;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("qim_send_loopback: entered.\n");)

	if (pext->RequestLen != sizeof(INT_LOOPBACK_REQ)) {
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk(
		    "qim_send_loopback: invalid RequestLen =%d.\n",
		    pext->RequestLen);)
		return rval;
	}

	if (pext->ResponseLen != sizeof(INT_LOOPBACK_RSP)) {
		pext->Status = EXT_STATUS_INVALID_PARAM;
		DEBUG9_10(printk(
		    "qim_send_loopback: invalid ResponseLen =%d.\n",
		    pext->ResponseLen);)
		return rval;
	}

	status = copy_from_user(&req, Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode), pext->RequestLen);
	if (status) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("qim_send_loopback: ERROR copy read of "
		    "request buffer.\n");)
		return (-EFAULT);
	}

	status = copy_from_user(&rsp, Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode), pext->ResponseLen);
	if (status) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("qim_send_loopback: ERROR copy read of "
		    "response buffer.\n");)
		return (-EFAULT);
	}

	if (req.TransferCount > req.BufferLength ||
	    req.TransferCount > rsp.BufferLength) {

		/* Buffer lengths not large enough. */
		pext->Status = EXT_STATUS_INVALID_PARAM;

		DEBUG9_10(printk(
		    "qim_send_loopback: invalid TransferCount =%d. "
		    "req BufferLength =%d rspBufferLength =%d.\n",
		    req.TransferCount, req.BufferLength, rsp.BufferLength);)

		return rval;
	}

	status = copy_from_user(ha->ioctl_mem, Q64BIT_TO_PTR(req.BufferAddress,
	    pext->AddrMode), req.TransferCount);
	if (status) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("qim_send_loopback: ERROR copy read of "
		    "user loopback data buffer.\n");)
		return (-EFAULT);
	}


	DEBUG9(printk("qim_send_loopback: req -- bufadr=%lx, buflen=%x, "
	    "xfrcnt=%x, rsp -- bufadr=%lx, buflen=%x.\n",
	    (unsigned long)req.BufferAddress, req.BufferLength,
	    req.TransferCount, (unsigned long)rsp.BufferAddress,
	    rsp.BufferLength);)

	/*
	 * AV - the caller of this IOCTL expects the FW to handle
	 * a loopdown situation and return a good status for the
	 * call function and a LOOPDOWN status for the test operations
	 */
	/*if (atomic_read(&ha->loop_state) != LOOP_READY || */
	if (test_bit(CFG_ACTIVE, &dr_ha->cfg_flags) ||
	    test_bit(ABORT_ISP_ACTIVE, &dr_ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &dr_ha->dpc_flags) ||
	    dr_ha->dpc_active) {

		pext->Status = EXT_STATUS_BUSY;
		DEBUG9_10(printk("qim_send_loopback(%ld): "
		    "loop not ready.\n", ha->host_no);)
		return rval;
	}

	if (dr_ha->current_topology == ISP_CFG_F) {
		if (IS_QLA2100(dr_ha) || IS_QLA2200(dr_ha)) {
			pext->Status = EXT_STATUS_INVALID_REQUEST ;
			DEBUG9_10(printk("qim_send_loopback: ERROR "
			    "command only supported for QLA23xx.\n");)
			return rval;
		}
		status = qim_echo_test(ha, &req, ret_mb);
	} else {
		status = qim_loopback_test(ha, &req, ret_mb);
	}

	if (status) {
		if (status == QLA_FUNCTION_TIMEOUT ) {
			pext->Status = EXT_STATUS_BUSY;
			DEBUG9_10(printk("qim_send_loopback: ERROR "
			    "command timed out.\n");)
			return rval;
		} else {
			/* EMPTY. Just proceed to copy back mailbox reg
			 * values for users to interpret.
			 */
			pext->Status = EXT_STATUS_ERR;
			DEBUG10(printk("qim_send_loopback: ERROR "
			    "loopback command failed 0x%x.\n", ret_mb[0]);)
		}
	}

	DEBUG9(printk("qim_send_loopback: loopback mbx cmd ok. "
	    "copying data.\n");)

	/* put loopback return data in user buffer */
	status = copy_to_user(Q64BIT_TO_PTR(rsp.BufferAddress,
	    pext->AddrMode), ha->ioctl_mem, req.TransferCount);
	if (status) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("qim_send_loopback: ERROR copy "
		    "write of return data buffer.\n");)
		return (-EFAULT);
	}

	rsp.CompletionStatus = ret_mb[0];
	if (dr_ha->current_topology == ISP_CFG_F) {
		rsp.CommandSent = INT_DEF_LB_ECHO_CMD;
	} else {
		if (rsp.CompletionStatus == INT_DEF_LB_COMPLETE ||
		    rsp.CompletionStatus == INT_DEF_LB_CMD_ERROR) {
			rsp.CrcErrorCount = ret_mb[1];
			rsp.DisparityErrorCount = ret_mb[2];
			rsp.FrameLengthErrorCount = ret_mb[3];
			rsp.IterationCountLastError =
			    (ret_mb[19] << 16) | ret_mb[18];
		}
	}

	status = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode), &rsp, pext->ResponseLen);
	if (status) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("qim_send_loopback: ERROR copy "
		    "write of response buffer.\n");)
		return (-EFAULT);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	DEBUG9(printk("qim_send_loopback: exiting.\n");)

	return rval;
}

int
qim_fw_dump(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		rval = 0;
	int		status;
	uint32_t	copy_len;
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): entered.\n", __func__, ha->host_no);)

	if (dr_ha->fw_dump_buffer == NULL) {
		DEBUG9_10(printk("%s(%ld): no fw dump.\n",
		    __func__, ha->host_no);)
		printk("%s(%ld): no fw dump.\n", __func__, ha->host_no);

		return 0;
	}

	DEBUG9(printk("%s(%ld): copying fw dump.\n", __func__, ha->host_no);)
	printk("%s(%ld): copying fw dump.\n", __func__, ha->host_no);

	copy_len = (dr_ha->fw_dump_buffer_len < pext->ResponseLen) ?
	    dr_ha->fw_dump_buffer_len : pext->ResponseLen;
	status = copy_to_user(Q64BIT_TO_PTR(pext->ResponseAdr,
	    pext->AddrMode), dr_ha->fw_dump_buffer, copy_len);
	if (status) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s: ERROR copy "
		    "write of response buffer.\n", __func__);)
		return (-EFAULT);
	}

	vfree(dr_ha->fw_dump_buffer);
	dr_ha->fw_dump_buffer = NULL;
	dr_ha->fw_dump_buffer_len = 0;

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	DEBUG9(printk("%s(%ld): exiting.\n", __func__, ha->host_no);)

	return rval;
}



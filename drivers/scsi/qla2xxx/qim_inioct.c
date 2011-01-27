#include "qim_ioctl.h"
#include <linux/vmalloc.h>



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

INT_OPT_ROM_REGION OptionRomTable25XX[] = // 1 M + 64 K  x130000
{
    {INT_OPT_ROM_REGION_ALL, INT_OPT_ROM_SIZE_25XX,
	     0, INT_OPT_ROM_SIZE_25XX-1},
    {INT_OPT_ROM_REGION_PHBIOS_PHFCODE_PHEFI, 0x80000,
	     0, 0x80000-1 },
    {INT_OPT_ROM_REGION_FW, 0x80000,
	     0x80000, INT_OPT_ROM_SIZE_25XX-1},
    {INT_OPT_ROM_REGION_VPD_HBAPARAM, 0x10000,
	     0x120000, 0x130000-1 },
    {INT_OPT_ROM_REGION_FW_DATA, 0x20000,
	     0x100000, 0x120000-1},
    {INT_OPT_ROM_REGION_NONE, 0, 0, 0 }
};



int
qim_read_nvram(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int	ret = 0;
	char	*ptmp_buf;
	uint32_t transfer_size;
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
	qim_read_nvram_data(dr_ha, (uint8_t *)ptmp_buf, dr_ha->nvram_base,
	    dr_ha->nvram_size);

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
 * qla2xxx_write_vpd_nv_data
 *	Write data to VPD or NVRAM (HBA Parameter) region.
 *	This is done by read-modify-write the whole 64K region.
 *
 * Input:
 *	ha = adapter block pointer.
 *	pnew_vpd_nv = pointer to new vpd/nv buffer 
 *	size-bytes = size in bytes for the new vpd/nv
 *	offset = offset in bytes wheren the new vpd/nv will be written
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
int
qim_write_vpd_nv_data(scsi_qla_host_t *ha, uint8_t *pnew_vpd_nv,
			  uint32_t offset, uint32_t size_bytes)
{
	int		ret = 1;
	uint8_t		*porg_vpd_nv = NULL;
	uint32_t	length = 0x10000; /* 65536 */

	DEBUG9(printk("%s: entered.\n", __func__));

	if (!IS_QLA25XX(ha)) {
		DEBUG9(printk("%s: Interface not valid for non 25xx\n",
		    __func__));
		return ret;
	}

	porg_vpd_nv = vmalloc(length);
	if (porg_vpd_nv == NULL) {
		DEBUG9_10(printk(KERN_WARNING
		    "%s: ERROR in memory allocation for vpd_nv.\n", __func__));
	return ret;
	}

	qim_read_nvram_data(ha, porg_vpd_nv, FA_NVRAM_VPD0_ADDR, length);
	/* Modify the buffer with input and write it back */
	memcpy((porg_vpd_nv + offset), pnew_vpd_nv, size_bytes); 
	ret = qim_write_nvram_data(ha, porg_vpd_nv, FA_NVRAM_VPD0_ADDR,
	    length);

	vfree (porg_vpd_nv);

	DEBUG9(printk("%s: exiting.\n", __func__));
	return ret;
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
	if (IS_FWI2_CAPABLE(dr_ha)) {
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
	if (IS_QLA25XX(dr_ha)) {
		ret = qim_write_vpd_nv_data(dr_ha, (uint8_t *)pnew_nv,
		    (dr_ha->nvram_base * 4), transfer_size);

		if (ret) {
			pext->Status = EXT_STATUS_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld nv_vpd 64K"
			    "read-modify-write failed.",
			    __func__, ha->host_no, ha->instance));
			qim_free_ioctl_scrap_mem(ha);
			return (ret);
		}
	} else {
		qim_write_nvram_data(dr_ha, (uint8_t *)pnew_nv, dr_ha->nvram_base,
		    transfer_size);
	}

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
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	if (!(IS_QLA24XX_TYPE(dr_ha) || IS_QLA25XX(dr_ha))) {
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
	qim_read_nvram_data(dr_ha, ptmp_buf, data_offset, transfer_size);

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
	struct scsi_qla_host	*dr_ha = ha->dr_data;


	if (!IS_FWI2_CAPABLE(dr_ha)) {
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
	if (IS_QLA25XX(dr_ha)) {
		ret = qim_write_vpd_nv_data(dr_ha, pnew_nv, (data_offset * 4),
		    transfer_size);

		if (ret) {
			pext->Status = EXT_STATUS_ERR;
			DEBUG9_10(printk("%s(%ld): inst=%ld nv_vpd 64K"
			    "read-modify-write failed.",
			    __func__, ha->host_no, ha->instance));
			qim_free_ioctl_scrap_mem(ha);
			return (ret);
		}        
        } else {
		qim_write_nvram_data(dr_ha, pnew_nv, data_offset, transfer_size);
	}

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
	case PCI_DEVICE_ID_QLOGIC_ISP5422:
	case PCI_DEVICE_ID_QLOGIC_ISP5432:
	case PCI_DEVICE_ID_QLOGIC_ISP8432:
		*pOptionRomTable = OptionRomTable2422;
		*OptionRomTableSize = sizeof(OptionRomTable2422);
		break;
	case PCI_DEVICE_ID_QLOGIC_ISP2532:
	case PCI_DEVICE_ID_QLOGIC_ISP2522:
	case PCI_DEVICE_ID_QLOGIC_ISP2512:
		*pOptionRomTable = OptionRomTable25XX;
		*OptionRomTableSize = sizeof(OptionRomTable25XX);
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
	if (IS_FWI2_CAPABLE(dr_ha)) {
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
		if (IS_QLA24XX_TYPE(dr_ha) || IS_QLA25XX(dr_ha)) {
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
	if (IS_FWI2_CAPABLE(dr_ha)) {
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

int
qim2x00_update_port_param(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0, rval, port_found;
	uint16_t	mb[MAILBOX_REGISTER_COUNT];
	uint16_t	idma_speed;
	uint8_t		*usr_temp;
	fc_port_t	*fcport;
	INT_PORT_PARAM	port_param;
	struct scsi_qla_host	*dr_ha = ha->dr_data;

	if (!IS_IIDMA_CAPABLE(dr_ha)) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld not 24xx. exiting.\n",
		    __func__, dr_ha->host_no, dr_ha->instance));
		return (ret);
	}

	/* Copy request buffer */
	usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->RequestAdr,
	    pext->AddrMode);
	ret = copy_from_user((uint8_t *)&port_param, usr_temp,
	    sizeof(INT_PORT_PARAM));
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld ERROR copy req buf ret=%d\n",
		    __func__, dr_ha->host_no, dr_ha->instance, ret));
		return (-EFAULT);
	}

	if (port_param.FCScsiAddr.DestType != EXT_DEF_TYPE_WWPN) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR -wrong Dest "
		    "type.\n", __func__, dr_ha->host_no, dr_ha->instance));
		return (ret);
	}

	port_found = 0;
	list_for_each_entry(fcport, &dr_ha->fcports, list) {
		if (memcmp(fcport->port_name,
		    port_param.FCScsiAddr.DestAddr.WWPN, WWN_SIZE))
			continue;

		port_found++;
		break;
	}
	if (!port_found) {
		pext->Status = EXT_STATUS_DEV_NOT_FOUND;
		DEBUG9_10(printk("%s(%ld): inst=%ld FC AddrFormat - DID NOT "
		    "FIND Port matching WWPN.\n",
		    __func__, dr_ha->host_no, dr_ha->instance));
		return (ret);
	}

	/* Go with operation. */
	if (port_param.Mode) {
		switch (port_param.Speed) {
		case EXT_DEF_PORTSPEED_1GBIT:
			idma_speed = PORT_SPEED_1GB;
			break;
		case EXT_DEF_PORTSPEED_2GBIT:
			idma_speed = PORT_SPEED_2GB;
			break;
		case EXT_DEF_PORTSPEED_4GBIT:
			idma_speed = PORT_SPEED_4GB;
			break;
		case EXT_DEF_PORTSPEED_8GBIT:
			idma_speed = PORT_SPEED_8GB;
			break;
		default:
			pext->Status = EXT_STATUS_INVALID_PARAM;
			DEBUG9_10(printk("%s(%ld): inst=%ld ERROR -invalid "
			    "speed.\n", __func__, dr_ha->host_no, dr_ha->instance));
			return (ret);
		}

		rval = qla2x00_set_idma_speed(dr_ha, fcport->loop_id, idma_speed,
		    mb);
		if (rval != QLA_SUCCESS) {
			if (mb[0] == MBS_COMMAND_ERROR && mb[1] == 0x09)
				pext->Status = EXT_STATUS_DEVICE_NOT_READY;
			else if (mb[0] == MBS_COMMAND_PARAMETER_ERROR)
				pext->Status = EXT_STATUS_INVALID_PARAM;
			else
				pext->Status = EXT_STATUS_ERR;

			DEBUG9_10(printk("%s(%ld): inst=%ld set iDMA cmd "
			    "FAILED=%x.\n", __func__, dr_ha->host_no,
			    dr_ha->instance, mb[0]));
			return (ret);
		}
	} else {
		rval = qla2x00_get_idma_speed(dr_ha, fcport->loop_id,
		    &idma_speed, mb);
		if (rval != QLA_SUCCESS) {
			if (mb[0] == MBS_COMMAND_ERROR && mb[1] == 0x09)
				pext->Status = EXT_STATUS_DEVICE_NOT_READY;
			else if (mb[0] == MBS_COMMAND_PARAMETER_ERROR)
				pext->Status = EXT_STATUS_INVALID_PARAM;
			else
				pext->Status = EXT_STATUS_ERR;

			DEBUG9_10(printk("%s(%ld): inst=%ld get iDMA cmd "
			    "FAILED=%x.\n", __func__, dr_ha->host_no,
			    dr_ha->instance, mb[0]));
			return (ret);
		}

		switch (idma_speed) {
		case PORT_SPEED_1GB:
			port_param.Speed = EXT_DEF_PORTSPEED_1GBIT;
			break;
		case PORT_SPEED_2GB:
			port_param.Speed = EXT_DEF_PORTSPEED_2GBIT;
			break;
		case PORT_SPEED_4GB:
			port_param.Speed = EXT_DEF_PORTSPEED_4GBIT;
			break;
		case PORT_SPEED_8GB:
			port_param.Speed = EXT_DEF_PORTSPEED_8GBIT;
			break;
		default:
			port_param.Speed = 0xFFFF;
			break;
		}

		usr_temp = (uint8_t *)Q64BIT_TO_PTR(pext->ResponseAdr,
		    pext->AddrMode);
		ret = copy_to_user(usr_temp, (uint8_t *)&port_param,
		    sizeof(INT_PORT_PARAM));
		if (ret) {
			pext->Status = EXT_STATUS_COPY_ERR;
			DEBUG9_10(printk(
			    "%s(%ld): inst=%ld ERROR copy rsp buf ret=%d\n",
			    __func__, dr_ha->host_no, dr_ha->instance, ret));
			return (-EFAULT);
		}
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	DEBUG9(printk("%s(%ld): exiting.\n", __func__, dr_ha->host_no));

	return (ret);
}

/*
 * qim84xx_execute_access_data_cmd
 *      Performs the actual IOCB execution for data accesses.
 *
 * Input:
 *
 * Returns:
 *
 * Context:
 *      Kernel context.
 */
static int
qim84xx_execute_access_data_cmd(scsi_qla_host_t *ha,
    struct qla_cs84xx_mgmt *cmd)
{
	int rval = QLA_FUNCTION_FAILED;
	dma_addr_t mn_dma;
	struct a84_mgmt_request  *mn;

	DEBUG9(printk("%s(%ld): entered.\n", __func__, ha->host_no));

	mn = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &mn_dma);
	if (mn == NULL) {
		qla_printk(KERN_ERR, ha,
		    "%s(%ld): failed to allocate Access "
		    "CS84 IOCB.\n", __func__, ha->host_no);
		return QLA_MEMORY_ALLOC_FAILED;
	}
	memset(mn, 0, sizeof(struct a84_mgmt_request));
	mn->p.mgmt_request.entry_type     = ACCESS_CHIP_IOCB_TYPE;
	mn->p.mgmt_request.entry_count    = 1;

	mn->p.mgmt_request.options        = cpu_to_le16(cmd->options);
	mn->p.mgmt_request.parameter1     = cpu_to_le32(cmd->parameter1);
	mn->p.mgmt_request.parameter2     = cpu_to_le32(cmd->parameter2);
	mn->p.mgmt_request.parameter3     = cpu_to_le32(cmd->parameter3);
	mn->p.mgmt_request.total_byte_cnt = cpu_to_le32(cmd->data_size);

	DEBUG16(printk("%s(%ld) Input cmd option=%x, data_size=%x "
	    "parameter1=%x parameter2=%x parameter3=%x\n",
	    __func__, ha->host_no, cmd->options,
	    cmd->data_size, cmd->parameter1,
	    cmd->parameter2, cmd->parameter3));

	DEBUG16(printk("%s(%ld): Request for data_size: %d\n", __func__,
	    ha->host_no, cmd->data_size));

	/* if DMA required */
	if (cmd->options != ACO_CHANGE_CONFIG_PARAM) {
		mn->p.mgmt_request.dseg_count     = cpu_to_le16(0x1);
		mn->p.mgmt_request.dseg_address[0] = cpu_to_le32(LSD(cmd->dseg_dma));
		mn->p.mgmt_request.dseg_address[1] = cpu_to_le32(MSD(cmd->dseg_dma));
		mn->p.mgmt_request.dseg_length    = cpu_to_le32(cmd->data_size);
	}

	DEBUG16(printk("%s(%ld): Dump of Access CS84XX IOCB request \n",
	    __func__, ha->host_no));
	DEBUG16(qim_dump_buffer((uint8_t *)mn,
	    sizeof(struct a84_mgmt_request)));

	rval = qim_issue_iocb(ha, mn, mn_dma, 0);
	if (rval != QLA_SUCCESS) {
		DEBUG2_16(printk("%s(%ld): failed to issue Access"
		    "CS84XX IOCB (%x).\n", __func__, ha->host_no, rval));
	} else {
		DEBUG16(printk("%s(%ld): Dump of Access CS84XX IOCB response\n",
		    __func__, ha->host_no));
		DEBUG16(qim_dump_buffer((uint8_t *)mn,
		    sizeof(struct a84_mgmt_request)));

		DEBUG16(printk("scsi(%ld): ql24xx_verify_cs84xx: "
		    "comp_status: %x failure code: %x\n", ha->host_no,
		    le16_to_cpu(mn->p.mgmt_response.comp_status),
		    le16_to_cpu(mn->p.mgmt_response.failure_code)));
		if (mn->p.mgmt_response.comp_status !=
		    __constant_cpu_to_le16(CS_COMPLETE))
			rval = QLA_FUNCTION_FAILED;
	}
	dma_pool_free(ha->s_dma_pool, mn, mn_dma);

	DEBUG9(printk("%s(%ld): rval: %x\n", __func__, ha->host_no, rval));

	return rval;
}

/*
 * qim84xx_access_data
 *      Handles the requests related to data.
 *      Processes following operation
 *		- Read memory
 *		- Write memory
 *		- Change configuration parameters
 *		- Request information
 *
 * Input:
 *
 * Returns:
 *
 * Context:
 *      Kernel context.
 */

static int
qim84xx_access_data(scsi_qla_host_t *ha, SD_A84_MGT *p_mgmt, EXT_IOCTL *pext)
{
	int rval = QLA_SUCCESS;
	int is_read_type_cmd;
	A84_MANAGE_INFO *pMgmtInfo = &p_mgmt->sp.ManageInfo;
	struct qla_cs84xx_mgmt  cs84xx_mgmt;
	int	ret;

	/* Set up the command parameters */
	cs84xx_mgmt.options = pMgmtInfo->Operation;

	is_read_type_cmd = pMgmtInfo->Operation == A84_OP_READ_MEM ||
	    pMgmtInfo->Operation == A84_OP_GET_INFO;

	if (pMgmtInfo->Operation == A84_OP_CHANGE_CONFIG) {
		cs84xx_mgmt.data_size = pMgmtInfo->TotalByteCount;
		cs84xx_mgmt.parameter1 =
		    pMgmtInfo->Parameters.ap.Config.ConfigParamID;
		cs84xx_mgmt.parameter2 =
		    pMgmtInfo->Parameters.ap.Config.ConfigParamData0;
		cs84xx_mgmt.parameter3 =
		    pMgmtInfo->Parameters.ap.Config.ConfigParamData1;
	}
	if (pMgmtInfo->Operation == A84_OP_READ_MEM ||
	    pMgmtInfo->Operation ==  A84_OP_WRITE_MEM) {
		cs84xx_mgmt.data_size =
		    pMgmtInfo->TotalByteCount,
		cs84xx_mgmt.parameter1 =
		    pMgmtInfo->Parameters.ap.Memory.StartingAddr;
		cs84xx_mgmt.parameter2 = 0;
		cs84xx_mgmt.parameter3 = 0;
	}
	if (pMgmtInfo->Operation == A84_OP_GET_INFO) {
		cs84xx_mgmt.data_size =
		    pMgmtInfo->TotalByteCount;
		cs84xx_mgmt.parameter1 =
		    pMgmtInfo->Parameters.ap.Info.InfoDataType;
		cs84xx_mgmt.parameter2 =
		    pMgmtInfo->Parameters.ap.Info.InfoContext;
		cs84xx_mgmt.parameter3 = 0;
	}

	cs84xx_mgmt.data = NULL;
	if (cs84xx_mgmt.data_size) {
		cs84xx_mgmt.data = dma_alloc_coherent(&ha->pdev->dev,
		    cs84xx_mgmt.data_size, &cs84xx_mgmt.dseg_dma, GFP_KERNEL);
		if (cs84xx_mgmt.data == NULL) {
			qla_printk(KERN_WARNING, ha,
			   "Unable to allocate memory for CS84XX Mgmt data\n");
			return QLA_FUNCTION_FAILED;
		}
	}

	/* If this is a write and there is some data to be read from user
	   copy in local buffer. For cs84xx change configuration, data size
	   will be zero, so no copy from user involved
	*/
	if (!is_read_type_cmd && cs84xx_mgmt.data_size) {
		/* Copy data from user space pointer */
		ret = copy_from_user(cs84xx_mgmt.data,
		    Q64BIT_TO_PTR(pMgmtInfo->pDataBytes, pext->AddrMode),
		    cs84xx_mgmt.data_size);
		if (ret) {
			qla_printk(KERN_WARNING, ha,
			   "Unable to copy data bytes from user\n");
			rval = QLA_FUNCTION_FAILED;
			goto cs84xx_mgmt_failed;
		}

	}

	if (rval == QLA_SUCCESS) {
		rval = qim84xx_execute_access_data_cmd(ha, &cs84xx_mgmt);
		if (rval != QLA_SUCCESS) {
			printk("Execute access data cmd failed\n");
			goto cs84xx_mgmt_failed;
		}
		if (is_read_type_cmd && cs84xx_mgmt.data_size) {
			ret = copy_to_user(Q64BIT_TO_PTR(
			    pMgmtInfo->pDataBytes,
			    pext->AddrMode), cs84xx_mgmt.data,
			   cs84xx_mgmt.data_size);
			if (ret) {
				qla_printk(KERN_WARNING, ha,
				    "Unable to copy data to user\n");
				rval = QLA_FUNCTION_FAILED;
				goto cs84xx_mgmt_failed;
			}
		}
	}

cs84xx_mgmt_failed:
	if (cs84xx_mgmt.data)
		dma_free_coherent(&ha->pdev->dev, cs84xx_mgmt.data_size,
		    cs84xx_mgmt.data, cs84xx_mgmt.dseg_dma);
	return rval;
}

/*
 * get f/w version of 84XX
 */
static int
qim84xx_fwversion(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	SD_A84_MGT	*pcs84xx_mgmt;
	uint8_t		*usr_cs84xx_mgmt;
	uint32_t	transfer_size;
	struct scsi_qla_host    *dr_ha = ha->dr_data;

	DEBUG9(printk("%s(%ld): entered.\n", __func__, dr_ha->host_no));
	transfer_size = pext->RequestLen;
	if (qim_get_ioctl_scrap_mem(ha, (void **)&pcs84xx_mgmt,
	    transfer_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, dr_ha->host_no, dr_ha->instance,
		    transfer_size));
		return (ret);
	}
	usr_cs84xx_mgmt = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);

	/* Get the paramters from user space */
	ret = copy_from_user(pcs84xx_mgmt, usr_cs84xx_mgmt, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "qim8xxx_cs84xx_mgmt_command: ERROR in buffer copy READ. "
		    "RequestAdr=%p\n", Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode)));
		qim_free_ioctl_scrap_mem(ha);
		return ret;
	}

	transfer_size = sizeof(dr_ha->cs84xx->op_fw_version);	/* byte count */
	if (pext->ResponseLen < transfer_size) {
		pext->ResponseLen = transfer_size;
		pext->Status = EXT_STATUS_BUFFER_TOO_SMALL;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld Response buffer too small.\n",
		    __func__, dr_ha->host_no, dr_ha->instance));
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}
	pcs84xx_mgmt->sp.GetFwVer.FwVersion =  (ULONG) dr_ha->cs84xx->op_fw_version;
	/* Copy back the struct to user */
	usr_cs84xx_mgmt = Q64BIT_TO_PTR(pext->ResponseAdr, pext->AddrMode);
	transfer_size = pext->ResponseLen;
	ret = copy_to_user(usr_cs84xx_mgmt, pcs84xx_mgmt, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("%s(%ld): inst=%ld ERROR copy rsp buffer.\n",
		    __func__, dr_ha->host_no, dr_ha->instance));
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	qim_free_ioctl_scrap_mem(ha);

	DEBUG9(printk("%s(%ld): exiting.\n", __func__, dr_ha->host_no));

	return (ret);
}

static int
qim84xx_reset(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	SD_A84_MGT	*pcs84xx_mgmt;
	uint8_t		*usr_cs84xx_mgmt;
	uint32_t	transfer_size;
	A84_RESET 	*pResetInfo;
	int 		cmd;
	uint16_t 	cmd_status;
	struct scsi_qla_host    *dr_ha = ha->dr_data;

	DEBUG9(printk("%s(%ld): entered.\n", __func__, dr_ha->host_no));

	transfer_size = pext->RequestLen;
	if (qim_get_ioctl_scrap_mem(ha, (void **)&pcs84xx_mgmt,
	    transfer_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, dr_ha->host_no, dr_ha->instance,
		    transfer_size));
		return (-EFAULT);
	}

	/* Get the paramters from user space */
	usr_cs84xx_mgmt = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);
	ret = copy_from_user(pcs84xx_mgmt, usr_cs84xx_mgmt, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "qim84xx_reset: ERROR in buffer copy READ. "
		    "RequestAdr=%p\n", Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode)));
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* Take action based on the sub command */
	pResetInfo = &pcs84xx_mgmt->sp.Reset;
	cmd = pResetInfo->Flags == A84_RESET_FLAG_ENABLE_DIAG_FW ?
	    A84_ISSUE_RESET_DIAG_FW: A84_ISSUE_RESET_OP_FW;
	ret = qim84xx_reset_chip(dr_ha, cmd == A84_ISSUE_RESET_DIAG_FW,
	    &cmd_status);
	if (ret != QLA_SUCCESS ||
	    cmd_status != MBS_COMMAND_COMPLETE) {
		DEBUG9_10(printk("%s(%ld): ISP8XXX Reset"
		    " command failed ret=%xh cmd_status=%xh\n",
		    __func__, dr_ha->host_no, ret, cmd_status));
		pext->Status = EXT_STATUS_ERR;
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}
	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	qim_free_ioctl_scrap_mem(ha);
	return (ret);
}

static int
qim84xx_mgmt_control(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	SD_A84_MGT	*pcs84xx_mgmt;
	uint8_t		*usr_cs84xx_mgmt;
	uint32_t	transfer_size;
	struct scsi_qla_host    *dr_ha = ha->dr_data;

	DEBUG9(printk("%s(%ld): entered.\n", __func__, dr_ha->host_no));

	transfer_size = pext->RequestLen;

	if (qim_get_ioctl_scrap_mem(ha, (void **)&pcs84xx_mgmt,
	    transfer_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, dr_ha->host_no, dr_ha->instance,
		    transfer_size));
		return (-EFAULT);
	}

	usr_cs84xx_mgmt = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);

	/* Get the paramters from user space */
	ret = copy_from_user(pcs84xx_mgmt, usr_cs84xx_mgmt, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "qim84xx_mgmt_control: ERROR in buffer copy READ. "
		    "RequestAdr=%p\n", Q64BIT_TO_PTR(pext->RequestAdr,
		    pext->AddrMode)));
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* Take action based on the sub command */
	ret = qim84xx_access_data(dr_ha, pcs84xx_mgmt, pext);
	if (ret != QLA_SUCCESS) {
		pext->Status = EXT_STATUS_ERR;
		pext->DetailStatus = EXT_STATUS_UNKNOWN;
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	pext->Status       = EXT_STATUS_OK;
	pext->DetailStatus = EXT_STATUS_OK;

	qim_free_ioctl_scrap_mem(ha);
	return (ret);
}

int
qim84xx_update_chip_fw(scsi_qla_host_t *ha,
    struct qla_cs84xx_mgmt *cs84xx_mgmt, uint8_t is_op_fw,
    uint16_t *comp_status, uint16_t *fail_status)
{
	struct a84_mgmt_request  *mn;
	dma_addr_t mn_dma;
	uint32_t *fw_code;
	uint32_t fw_ver;
	uint16_t options = 0;
	int rval;

	fw_code = (uint32_t *)cs84xx_mgmt->data;
	fw_ver  = le32_to_cpu(fw_code[2]);
	if (fw_ver == 0) {
		DEBUG16(printk("scsi(%ld): Not a valid Cs84XX FW image to flash\n",
		    ha->host_no));
		return QLA_FUNCTION_FAILED;
	}

	mn = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL, &mn_dma);
	if (mn == NULL) {
		qla_printk(KERN_ERR, ha,
		    "%s(%ld): failed to allocate Verify "
		    "Cs84 IOCB.\n", __func__, ha->host_no);
		return QLA_MEMORY_ALLOC_FAILED;
	}

	memset(mn, 0, sizeof(struct a84_mgmt_request));
	options |= VCO_FORCE_UPDATE | VCO_END_OF_DATA;
	if (!is_op_fw)
		options |= VCO_DIAG_FW;

	/* Fill in the IOCB headers */
	mn->p.request.entry_type  = VERIFY_CHIP_IOCB_TYPE;
	mn->p.request.entry_count = 1;
	mn->p.request.options     = cpu_to_le16(options);

	/* Fill in the FW details of the IOCB */
	mn->p.request.fw_ver = cpu_to_le32(fw_ver);
	mn->p.request.fw_size = cpu_to_le32(cs84xx_mgmt->data_size);
	mn->p.request.fw_seq_size = cpu_to_le32(cs84xx_mgmt->data_size);

	mn->p.mgmt_request.dseg_address[0] = cpu_to_le32(LSD(cs84xx_mgmt->dseg_dma));
	mn->p.mgmt_request.dseg_address[1] = cpu_to_le32(MSD(cs84xx_mgmt->dseg_dma));
	mn->p.mgmt_request.dseg_length     = cpu_to_le32(cs84xx_mgmt->data_size);
	mn->p.request.data_seg_cnt = cpu_to_le16(1);

	DEBUG16(printk("%s(%ld): Dump of Verify CS84XX (FW update) IOCB "
	    "request \n", __func__, ha->host_no));
	DEBUG16(qim_dump_buffer((uint8_t *)mn,
	    sizeof(struct a84_mgmt_request)));

	down(&ha->cs84xx->fw_update_mutex);
	rval = qim_issue_iocb_timeout(ha, mn, mn_dma, 0, 120);
	if (rval != QLA_SUCCESS) {
		DEBUG2_16(printk("%s(%ld): failed to issue Verify "
		    "CS84XX IOCB (FW update) (%x).\n", __func__,
		    ha->host_no, rval));
		goto fw_update_done;
	}

	DEBUG9_10(printk("%s(%ld): Dump of CS84XX Management "
	    "response\n", __func__, ha->host_no);
		qim_dump_buffer((uint8_t *)mn,
			sizeof(struct a84_mgmt_request)););

	DEBUG16(printk("scsi(%ld): ql24xx_verify_CS84XX: "
	    "comp_status: %x failure code: %x\n", ha->host_no,
	    le16_to_cpu(mn->p.response.comp_status),
	    le16_to_cpu(mn->p.response.failure_code)));

	if (comp_status)
		*comp_status = le16_to_cpu(mn->p.response.comp_status);
	if (fail_status)
		*fail_status = le16_to_cpu(mn->p.response.comp_status) ==
		    CS_TRANSPORT ? le16_to_cpu(mn->p.response.failure_code): 0;

fw_update_done:
	up(&ha->cs84xx->fw_update_mutex);
	dma_pool_free(ha->s_dma_pool, mn, mn_dma);

	DEBUG11(printk("%s(%ld): rval: %x\n", __func__, ha->host_no, rval));

	return (rval);
}

static int
qim84xx_updatefw(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int		ret = 0;
	SD_A84_MGT	*pcs84xx_mgmt;
	A84_UPDATE_FW      *pupdate_fw;
	int cmd;
	uint16_t cmd_status;
	uint16_t fail_code;
	uint8_t *usr_cs84xx_mgmt;
	uint32_t transfer_size;
	struct qla_cs84xx_mgmt cs84xx_mgmt;
	struct scsi_qla_host    *dr_ha = ha->dr_data;


	DEBUG9(printk("%s(%ld): entered.\n", __func__, dr_ha->host_no));

	transfer_size = pext->RequestLen;
	if (qim_get_ioctl_scrap_mem(ha, (void **)&pcs84xx_mgmt,
	    transfer_size)) {
		/* not enough memory */
		pext->Status = EXT_STATUS_NO_MEMORY;
		DEBUG9_10(printk("%s(%ld): inst=%ld scrap not big enough. "
		    "size requested=%d.\n",
		    __func__, dr_ha->host_no, dr_ha->instance,
		    transfer_size));
		return (ret);
	}

	/* Get the parameters from user space */
	usr_cs84xx_mgmt = Q64BIT_TO_PTR(pext->RequestAdr, pext->AddrMode);
	ret = copy_from_user(pcs84xx_mgmt, usr_cs84xx_mgmt, transfer_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk(
		    "qim84xx_updatefw: ERROR in buffer copy READ. "
		    "RequestAdr=%p\n", Q64BIT_TO_PTR(pext->RequestAdr,
			    pext->AddrMode)));
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	pupdate_fw = &pcs84xx_mgmt->sp.UpdateFw;
	cs84xx_mgmt.data_size = pupdate_fw->TotalByteCount;

	/* Allocate memory */
	cs84xx_mgmt.data = dma_alloc_coherent(&dr_ha->pdev->dev,
	    cs84xx_mgmt.data_size, &cs84xx_mgmt.dseg_dma, GFP_KERNEL);
	if (cs84xx_mgmt.data == NULL) {
		pext->Status = EXT_STATUS_NO_MEMORY;
		qla_printk(KERN_WARNING, dr_ha,
		    "Unable to allocate memory for Cs84 Mgmt data\n");
		qim_free_ioctl_scrap_mem(ha);
		return (ret);
	}

	/* Copy the firmware to be updated from user space */
	ret = copy_from_user(cs84xx_mgmt.data,
	    Q64BIT_TO_PTR(pupdate_fw->pFwDataBytes, pext->AddrMode),
	    cs84xx_mgmt.data_size);
	if (ret) {
		pext->Status = EXT_STATUS_COPY_ERR;
		DEBUG9_10(printk("qla84xx_updatefw: Copy from user failed\n"));
	}

	if (!ret) {

		cmd = pupdate_fw->Flags == A84_UPDATE_FW_FLAG_DIAG_FW ?
		    A84_ISSUE_UPDATE_DIAGFW_CMD: A84_ISSUE_UPDATE_OPFW_CMD;

		ret = qim84xx_update_chip_fw(dr_ha, &cs84xx_mgmt, cmd ==
		    A84_ISSUE_UPDATE_OPFW_CMD, &cmd_status, &fail_code);
		if (ret != QLA_SUCCESS || cmd_status != 0) {
			DEBUG16(printk("%s(%ld): Cs84 update FW failed "
			    " ret=%xh cmd_satus=%xh failure_code=%xh\n",
			    __func__, dr_ha->hostt_no, ret,
			    cmd_status, fail_code));
			pext->Status = EXT_STATUS_ERR;
			pext->DetailStatus = EXT_STATUS_UNKNOWN;
		}
	}

	if (!ret) {
		pext->Status       = EXT_STATUS_OK;
		pext->DetailStatus = EXT_STATUS_OK;
	}

	/* Free up the memory */
	dma_free_coherent(&dr_ha->pdev->dev, cs84xx_mgmt.data_size,
	    cs84xx_mgmt.data, cs84xx_mgmt.dseg_dma);
	qim_free_ioctl_scrap_mem(ha);

	return (ret);
}

/*
 * qim8xxx_mgmt_command
 *      This is the main entry point for the ISP 8XXX IOCTL path.
 *
 * Input:
 *
 * Returns:
 *
 * Context:
 *      Kernel context.
 */
int
qim84xx_mgmt_command(struct qla_host_ioctl *ha, EXT_IOCTL *pext, int mode)
{
	int ret = 0;
	struct scsi_qla_host    *dr_ha = ha->dr_data;

	if (!IS_QLA84XX(dr_ha)) {
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		DEBUG9_10(printk(
		    "%s(%ld): inst=%ld not 8xxx exiting.\n",
		    __func__, dr_ha->host_no, dr_ha->instance));
		return (ret);
	}

	DEBUG9(printk("%s(%ld): entered.\n", __func__, dr_ha->host_no));

	/* Take action based on the sub command */
	switch (pext->SubCode) {
	case INT_SC_A84_RESET:
		ret = qim84xx_reset(ha, pext, mode);
		break;
	case INT_SC_A84_GET_FW_VERSION:
		ret = qim84xx_fwversion(ha, pext, mode);
		break;
	case INT_SC_A84_MANAGE_INFO:
		ret = qim84xx_mgmt_control(ha, pext, mode);
		break;
	case INT_SC_A84_UPDATE_FW:
		ret = qim84xx_updatefw(ha, pext, mode);
		break;
	default:
		DEBUG9_10(printk("%s(%ld): inst=%ld Invalid sub command.\n",
		    __func__, dr_ha->host_no, dr_ha->instance));
		pext->Status = EXT_STATUS_INVALID_REQUEST;
		break;
	}
	return (ret);
}

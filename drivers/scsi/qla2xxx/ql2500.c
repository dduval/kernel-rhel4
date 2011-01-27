/*
 * QLogic ISP25XX device driver for Linux 2.6.x
 * Copyright (C) 2003-2005 QLogic Corporation (www.qlogic.com)
 *
 * Released under GPL v2.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "qla_def.h"

static char qla_driver_name[] = "qla2500";

extern uint32_t fw2500_version_str[];
extern uint32_t fw2500_addr01;
extern uint32_t fw2500_code01[];
extern uint32_t fw2500_length01;
extern uint32_t fw2500_addr02;
extern uint32_t fw2500_code02[];
extern uint32_t fw2500_length02;

static struct qla_fw_info qla_fw_tbl[] = {
	{
		.addressing	= FW_INFO_ADDR_EXTENDED,
		.fwcode		= (unsigned short *)&fw2500_code01[0],
		.fwlen		= (unsigned short *)&fw2500_length01,
		.lfwstart	= (unsigned long *)&fw2500_addr01,
	},
	{
		.addressing	= FW_INFO_ADDR_EXTENDED,
		.fwcode		= (unsigned short *)&fw2500_code02[0],
		.fwlen		= (unsigned short *)&fw2500_length02,
		.lfwstart	= (unsigned long *)&fw2500_addr02,
	},
	{ FW_INFO_ADDR_NOMORE, },
};

static struct qla_board_info qla_board_tbl[] = {
	{
		.drv_name	= qla_driver_name,
		.isp_name	= "ISP2512",
		.fw_info	= qla_fw_tbl,
		.fw_fname	= "ql2500_fw.bin",
	},
	{
		.drv_name	= qla_driver_name,
		.isp_name	= "ISP2522",
		.fw_info	= qla_fw_tbl,
		.fw_fname	= "ql2500_fw.bin",
	},
	{
		.drv_name	= qla_driver_name,
		.isp_name	= "ISP2532",
		.fw_info	= qla_fw_tbl,
		.fw_fname	= "ql2500_fw.bin",
	},
};

static struct pci_device_id qla25xx_pci_tbl[] = {
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP2512,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
		.driver_data	= (unsigned long)&qla_board_tbl[0],
	},
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP2522,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
		.driver_data	= (unsigned long)&qla_board_tbl[1],
	},
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP2532,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
		.driver_data	= (unsigned long)&qla_board_tbl[2],
	},

	{0, 0},
};
MODULE_DEVICE_TABLE(pci, qla25xx_pci_tbl);

static int __devinit
qla25xx_probe_one(struct pci_dev *pdev, const struct pci_device_id *id)
{
	return qla2x00_probe_one(pdev,
	    (struct qla_board_info *)id->driver_data);
}

static void __devexit
qla25xx_remove_one(struct pci_dev *pdev)
{
	qla2x00_remove_one(pdev);
}

static struct pci_driver qla25xx_pci_driver = {
	.name		= "qla2500",
	.id_table	= qla25xx_pci_tbl,
	.probe		= qla25xx_probe_one,
	.remove		= __devexit_p(qla25xx_remove_one),
};

static int __init
qla25xx_init(void)
{
	return pci_module_init(&qla25xx_pci_driver);
}

static void __exit
qla25xx_exit(void)
{
	pci_unregister_driver(&qla25xx_pci_driver);
}

module_init(qla25xx_init);
module_exit(qla25xx_exit);

MODULE_AUTHOR("QLogic Corporation");
MODULE_DESCRIPTION("QLogic ISP25xx FC-SCSI Host Bus Adapter driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(QLA2XXX_VERSION);

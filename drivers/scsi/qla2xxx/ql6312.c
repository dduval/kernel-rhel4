/*
 * QLogic ISP6312 device driver for Linux 2.6.x
 * Copyright (C) 2003-2005 QLogic Corporation (www.qlogic.com)
 *
 * Released under GPL v2.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "qla_def.h"

static char qla_driver_name[] = "qla6312";

extern unsigned char  fw2300ipx_version[];
extern unsigned char  fw2300ipx_version_str[];
extern unsigned short fw2300ipx_addr01;
extern unsigned short fw2300ipx_code01[];
extern unsigned short fw2300ipx_length01;
extern unsigned char  fw2322ipx_version[];
extern unsigned char  fw2322ipx_version_str[];
extern unsigned short fw2322ipx_addr01;
extern unsigned short fw2322ipx_code01[];
extern unsigned short fw2322ipx_length01;
extern unsigned long rseqipx_code_addr01;
extern unsigned short rseqipx_code01[];
extern unsigned short rseqipx_code_length01;
extern unsigned long xseqipx_code_addr01;
extern unsigned short xseqipx_code01[];
extern unsigned short xseqipx_code_length01;

static struct qla_fw_info qla_fw_tbl[] = {
	{
		.addressing	= FW_INFO_ADDR_NORMAL,
		.fwcode		= &fw2300ipx_code01[0],
		.fwlen		= &fw2300ipx_length01,
		.fwstart	= &fw2300ipx_addr01,
	},
	{ FW_INFO_ADDR_NOMORE, },

	{
		.addressing	= FW_INFO_ADDR_NORMAL,
		.fwcode		= &fw2322ipx_code01[0],
		.fwlen		= &fw2322ipx_length01,
		.fwstart	= &fw2322ipx_addr01,
	},
	{
		.addressing	= FW_INFO_ADDR_EXTENDED,
		.fwcode		= &rseqipx_code01[0],
		.fwlen		= &rseqipx_code_length01,
		.lfwstart	= &rseqipx_code_addr01,
	},
	{
		.addressing	= FW_INFO_ADDR_EXTENDED,
		.fwcode		= &xseqipx_code01[0],
		.fwlen		= &xseqipx_code_length01,
		.lfwstart	= &xseqipx_code_addr01,
	},
	{ FW_INFO_ADDR_NOMORE, },
};

static struct qla_board_info qla_board_tbl[] = {
	{
		.drv_name	= qla_driver_name,
		.isp_name	= "ISP6312",
		.fw_info	= qla_fw_tbl,
	},
	{
		.drv_name	= qla_driver_name,
		.isp_name	= "ISP6322",
		.fw_info	= &qla_fw_tbl[2],
	},
};

static struct pci_device_id qla6312_pci_tbl[] = {
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP6312,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
		.driver_data	= (unsigned long)&qla_board_tbl[0],
	},
	{
		.vendor		= PCI_VENDOR_ID_QLOGIC,
		.device		= PCI_DEVICE_ID_QLOGIC_ISP6322,
		.subvendor	= PCI_ANY_ID,
		.subdevice	= PCI_ANY_ID,
		.driver_data	= (unsigned long)&qla_board_tbl[1],
	},
	{0, 0},
};
MODULE_DEVICE_TABLE(pci, qla6312_pci_tbl);

static int __devinit
qla6312_probe_one(struct pci_dev *pdev, const struct pci_device_id *id)
{
	return qla2x00_probe_one(pdev,
	    (struct qla_board_info *)id->driver_data);
}

static void __devexit
qla6312_remove_one(struct pci_dev *pdev)
{
	qla2x00_remove_one(pdev);
}

static struct pci_driver qla6312_pci_driver = {
	.name		= "qla6312",
	.id_table	= qla6312_pci_tbl,
	.probe		= qla6312_probe_one,
	.remove		= __devexit_p(qla6312_remove_one),
};

static int __init
qla6312_init(void)
{
	return pci_module_init(&qla6312_pci_driver);
}

static void __exit
qla6312_exit(void)
{
	pci_unregister_driver(&qla6312_pci_driver);
}

module_init(qla6312_init);
module_exit(qla6312_exit);

MODULE_AUTHOR("QLogic Corporation");
MODULE_DESCRIPTION("QLogic ISP63xx FC-SCSI Host Bus Adapter driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(QLA2XXX_VERSION);

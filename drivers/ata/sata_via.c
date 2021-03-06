/*
 *  sata_via.c - VIA Serial ATA controllers
 *
 *  Maintained by:  Jeff Garzik <jgarzik@pobox.com>
 * 		   Please ALWAYS copy linux-ide@vger.kernel.org
 		   on emails.
 *
 *  Copyright 2003-2004 Red Hat, Inc.  All rights reserved.
 *  Copyright 2003-2004 Jeff Garzik
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 *  libata documentation is available via 'make {ps|pdf}docs',
 *  as Documentation/DocBook/libata.*
 *
 *  Hardware documentation available under NDA.
 *
 *
 *  To-do list:
 *  - VT6421 PATA support
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <scsi/scsi_host.h>
#include <linux/libata.h>
#include <asm/io.h>

#define DRV_NAME	"sata_via"
#define DRV_VERSION	"2.0"

enum board_ids_enum {
	vt6420,
	vt6421,
};

enum {
	SATA_CHAN_ENAB		= 0x40, /* SATA channel enable */
	SATA_INT_GATE		= 0x41, /* SATA interrupt gating */
	SATA_NATIVE_MODE	= 0x42, /* Native mode enable */
	SATA_PATA_SHARING	= 0x49, /* PATA/SATA sharing func ctrl */

	PORT0			= (1 << 1),
	PORT1			= (1 << 0),
	ALL_PORTS		= PORT0 | PORT1,
	N_PORTS			= 2,

	NATIVE_MODE_ALL		= (1 << 7) | (1 << 6) | (1 << 5) | (1 << 4),

	SATA_EXT_PHY		= (1 << 6), /* 0==use PATA, 1==ext phy */
	SATA_2DEV		= (1 << 5), /* SATA is master/slave */
};

static int svia_init_one (struct pci_dev *pdev, const struct pci_device_id *ent);
static u32 svia_scr_read (struct ata_port *ap, unsigned int sc_reg);
static void svia_scr_write (struct ata_port *ap, unsigned int sc_reg, u32 val);
static void vt6420_error_handler(struct ata_port *ap);

static const struct pci_device_id svia_pci_tbl[] = {
	{ PCI_VDEVICE(VIA, 0x0591), vt6420 },
	{ PCI_VDEVICE(VIA, 0x3149), vt6420 },
	{ PCI_VDEVICE(VIA, 0x3249), vt6421 },

	{ }	/* terminate list */
};

static struct pci_driver svia_pci_driver = {
	.name			= DRV_NAME,
	.id_table		= svia_pci_tbl,
	.probe			= svia_init_one,
	.remove			= ata_pci_remove_one,
};

static struct scsi_host_template svia_sht = {
	.eh_strategy_handler	= ata_scsi_error,
	.eh_timed_out		= ata_scsi_timed_out,
	.module			= THIS_MODULE,
	.name			= DRV_NAME,
	.ioctl			= ata_scsi_ioctl,
	.queuecommand		= ata_scsi_queuecmd,
	.can_queue		= ATA_DEF_QUEUE,
	.this_id		= ATA_SHT_THIS_ID,
	.sg_tablesize		= LIBATA_MAX_PRD,
	.cmd_per_lun		= ATA_SHT_CMD_PER_LUN,
	.emulated		= ATA_SHT_EMULATED,
	.use_clustering		= ATA_SHT_USE_CLUSTERING,
	.proc_name		= DRV_NAME,
	.dma_boundary		= ATA_DMA_BOUNDARY,
	.slave_configure	= ata_scsi_slave_config,
	.slave_destroy		= ata_scsi_slave_destroy,
	.bios_param		= ata_std_bios_param,
};

static const struct ata_port_operations vt6420_sata_ops = {
	.port_disable		= ata_port_disable,

	.tf_load		= ata_tf_load,
	.tf_read		= ata_tf_read,
	.check_status		= ata_check_status,
	.exec_command		= ata_exec_command,
	.dev_select		= ata_std_dev_select,

	.bmdma_setup            = ata_bmdma_setup,
	.bmdma_start            = ata_bmdma_start,
	.bmdma_stop		= ata_bmdma_stop,
	.bmdma_status		= ata_bmdma_status,

	.qc_prep		= ata_qc_prep,
	.qc_issue		= ata_qc_issue_prot,
	.data_xfer		= ata_pio_data_xfer,

	.freeze			= ata_bmdma_freeze,
	.thaw			= ata_bmdma_thaw,
	.error_handler		= vt6420_error_handler,
	.post_internal_cmd	= ata_bmdma_post_internal_cmd,

	.irq_handler		= ata_interrupt,
	.irq_clear		= ata_bmdma_irq_clear,

	.port_start		= ata_port_start,
	.port_stop		= ata_port_stop,
	.host_stop		= ata_host_stop,
};

static const struct ata_port_operations vt6421_sata_ops = {
	.port_disable		= ata_port_disable,

	.tf_load		= ata_tf_load,
	.tf_read		= ata_tf_read,
	.check_status		= ata_check_status,
	.exec_command		= ata_exec_command,
	.dev_select		= ata_std_dev_select,

	.bmdma_setup            = ata_bmdma_setup,
	.bmdma_start            = ata_bmdma_start,
	.bmdma_stop		= ata_bmdma_stop,
	.bmdma_status		= ata_bmdma_status,

	.qc_prep		= ata_qc_prep,
	.qc_issue		= ata_qc_issue_prot,
	.data_xfer		= ata_pio_data_xfer,

	.freeze			= ata_bmdma_freeze,
	.thaw			= ata_bmdma_thaw,
	.error_handler		= ata_bmdma_error_handler,
	.post_internal_cmd	= ata_bmdma_post_internal_cmd,

	.irq_handler		= ata_interrupt,
	.irq_clear		= ata_bmdma_irq_clear,

	.scr_read		= svia_scr_read,
	.scr_write		= svia_scr_write,

	.port_start		= ata_port_start,
	.port_stop		= ata_port_stop,
	.host_stop		= ata_host_stop,
};

static struct ata_port_info vt6420_port_info = {
	.sht		= &svia_sht,
	.flags		= ATA_FLAG_SATA | ATA_FLAG_NO_LEGACY,
	.pio_mask	= 0x1f,
	.mwdma_mask	= 0x07,
	.udma_mask	= 0x7f,
	.port_ops	= &vt6420_sata_ops,
};

MODULE_AUTHOR("Jeff Garzik");
MODULE_DESCRIPTION("SCSI low-level driver for VIA SATA controllers");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, svia_pci_tbl);
MODULE_VERSION(DRV_VERSION);

static u32 svia_scr_read (struct ata_port *ap, unsigned int sc_reg)
{
	if (sc_reg > SCR_CONTROL)
		return 0xffffffffU;
	return inl(ap->ioaddr.scr_addr + (4 * sc_reg));
}

static void svia_scr_write (struct ata_port *ap, unsigned int sc_reg, u32 val)
{
	if (sc_reg > SCR_CONTROL)
		return;
	outl(val, ap->ioaddr.scr_addr + (4 * sc_reg));
}

/**
 *	vt6420_prereset - prereset for vt6420
 *	@ap: target ATA port
 *
 *	SCR registers on vt6420 are pieces of shit and may hang the
 *	whole machine completely if accessed with the wrong timing.
 *	To avoid such catastrophe, vt6420 doesn't provide generic SCR
 *	access operations, but uses SStatus and SControl only during
 *	boot probing in controlled way.
 *
 *	As the old (pre EH update) probing code is proven to work, we
 *	strictly follow the access pattern.
 *
 *	LOCKING:
 *	Kernel thread context (may sleep)
 *
 *	RETURNS:
 *	0 on success, -errno otherwise.
 */
static int vt6420_prereset(struct ata_port *ap)
{
	struct ata_eh_context *ehc = &ap->eh_context;
	unsigned long timeout = jiffies + (HZ * 5);
	u32 sstatus, scontrol;
	int online;

	/* don't do any SCR stuff if we're not loading */
	if (!(ap->pflags & ATA_PFLAG_LOADING))
		goto skip_scr;

	/* Resume phy.  This is the old resume sequence from
	 * __sata_phy_reset().
	 */
	svia_scr_write(ap, SCR_CONTROL, 0x300);
	svia_scr_read(ap, SCR_CONTROL); /* flush */

	/* wait for phy to become ready, if necessary */
	do {
		msleep(200);
		if ((svia_scr_read(ap, SCR_STATUS) & 0xf) != 1)
			break;
	} while (time_before(jiffies, timeout));

	/* open code sata_print_link_status() */
	sstatus = svia_scr_read(ap, SCR_STATUS);
	scontrol = svia_scr_read(ap, SCR_CONTROL);

	online = (sstatus & 0xf) == 0x3;

	ata_port_printk(ap, KERN_INFO,
			"SATA link %s 1.5 Gbps (SStatus %X SControl %X)\n",
			online ? "up" : "down", sstatus, scontrol);

	/* SStatus is read one more time */
	svia_scr_read(ap, SCR_STATUS);

	if (!online) {
		/* tell EH to bail */
		ehc->i.action &= ~ATA_EH_RESET_MASK;
		return 0;
	}

 skip_scr:
	/* wait for !BSY */
	ata_busy_sleep(ap, ATA_TMOUT_BOOT_QUICK, ATA_TMOUT_BOOT);

	return 0;
}

static void vt6420_error_handler(struct ata_port *ap)
{
	return ata_bmdma_drive_eh(ap, vt6420_prereset, ata_std_softreset,
				  NULL, ata_std_postreset);
}

static const unsigned int svia_bar_sizes[] = {
	8, 4, 8, 4, 16, 256
};

static const unsigned int vt6421_bar_sizes[] = {
	16, 16, 16, 16, 32, 128
};

static unsigned long svia_scr_addr(unsigned long addr, unsigned int port)
{
	return addr + (port * 128);
}

static unsigned long vt6421_scr_addr(unsigned long addr, unsigned int port)
{
	return addr + (port * 64);
}

static void vt6421_init_addrs(struct ata_probe_ent *probe_ent,
			      struct pci_dev *pdev,
			      unsigned int port)
{
	unsigned long reg_addr = pci_resource_start(pdev, port);
	unsigned long bmdma_addr = pci_resource_start(pdev, 4) + (port * 8);
	unsigned long scr_addr;

	probe_ent->port[port].cmd_addr = reg_addr;
	probe_ent->port[port].altstatus_addr =
	probe_ent->port[port].ctl_addr = (reg_addr + 8) | ATA_PCI_CTL_OFS;
	probe_ent->port[port].bmdma_addr = bmdma_addr;

	scr_addr = vt6421_scr_addr(pci_resource_start(pdev, 5), port);
	probe_ent->port[port].scr_addr = scr_addr;

	ata_std_ports(&probe_ent->port[port]);
}

static struct ata_probe_ent *vt6420_init_probe_ent(struct pci_dev *pdev)
{
	struct ata_probe_ent *probe_ent;
	struct ata_port_info *ppi[2];
	
	ppi[0] = ppi[1] = &vt6420_port_info;
	probe_ent = ata_pci_init_native_mode(pdev, ppi, ATA_PORT_PRIMARY | ATA_PORT_SECONDARY);
	if (!probe_ent)
		return NULL;

	probe_ent->port[0].scr_addr =
		svia_scr_addr(pci_resource_start(pdev, 5), 0);
	probe_ent->port[1].scr_addr =
		svia_scr_addr(pci_resource_start(pdev, 5), 1);

	return probe_ent;
}

static struct ata_probe_ent *vt6421_init_probe_ent(struct pci_dev *pdev)
{
	struct ata_probe_ent *probe_ent;
	unsigned int i;

	probe_ent = kmalloc(sizeof(*probe_ent), GFP_KERNEL);
	if (!probe_ent)
		return NULL;

	memset(probe_ent, 0, sizeof(*probe_ent));
	probe_ent->dev = pci_dev_to_dev(pdev);
	INIT_LIST_HEAD(&probe_ent->node);

	probe_ent->sht		= &svia_sht;
	probe_ent->port_flags	= ATA_FLAG_SATA | ATA_FLAG_NO_LEGACY;
	probe_ent->port_ops	= &vt6421_sata_ops;
	probe_ent->n_ports	= N_PORTS;
	probe_ent->irq		= pdev->irq;
	probe_ent->irq_flags	= IRQF_SHARED;
	probe_ent->pio_mask	= 0x1f;
	probe_ent->mwdma_mask	= 0x07;
	probe_ent->udma_mask	= 0x7f;

	for (i = 0; i < N_PORTS; i++)
		vt6421_init_addrs(probe_ent, pdev, i);

	return probe_ent;
}

static void svia_configure(struct pci_dev *pdev)
{
	u8 tmp8;

	pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &tmp8);
	dev_printk(KERN_INFO, &pdev->dev, "routed to hard irq line %d\n",
	       (int) (tmp8 & 0xf0) == 0xf0 ? 0 : tmp8 & 0x0f);

	/* make sure SATA channels are enabled */
	pci_read_config_byte(pdev, SATA_CHAN_ENAB, &tmp8);
	if ((tmp8 & ALL_PORTS) != ALL_PORTS) {
		dev_printk(KERN_DEBUG, &pdev->dev,
			   "enabling SATA channels (0x%x)\n",
		           (int) tmp8);
		tmp8 |= ALL_PORTS;
		pci_write_config_byte(pdev, SATA_CHAN_ENAB, tmp8);
	}

	/* make sure interrupts for each channel sent to us */
	pci_read_config_byte(pdev, SATA_INT_GATE, &tmp8);
	if ((tmp8 & ALL_PORTS) != ALL_PORTS) {
		dev_printk(KERN_DEBUG, &pdev->dev,
			   "enabling SATA channel interrupts (0x%x)\n",
		           (int) tmp8);
		tmp8 |= ALL_PORTS;
		pci_write_config_byte(pdev, SATA_INT_GATE, tmp8);
	}

	/* make sure native mode is enabled */
	pci_read_config_byte(pdev, SATA_NATIVE_MODE, &tmp8);
	if ((tmp8 & NATIVE_MODE_ALL) != NATIVE_MODE_ALL) {
		dev_printk(KERN_DEBUG, &pdev->dev,
			   "enabling SATA channel native mode (0x%x)\n",
		           (int) tmp8);
		tmp8 |= NATIVE_MODE_ALL;
		pci_write_config_byte(pdev, SATA_NATIVE_MODE, tmp8);
	}
}

static int svia_init_one (struct pci_dev *pdev, const struct pci_device_id *ent)
{
	static int printed_version;
	unsigned int i;
	int rc;
	struct ata_probe_ent *probe_ent;
	int board_id = (int) ent->driver_data;
	const int *bar_sizes;
	int pci_dev_busy = 0;
	u8 tmp8;

	if (!printed_version++)
		dev_printk(KERN_DEBUG, &pdev->dev, "version " DRV_VERSION "\n");

	rc = pci_enable_device(pdev);
	if (rc)
		return rc;

	rc = pci_request_regions(pdev, DRV_NAME);
	if (rc) {
		pci_dev_busy = 1;
		goto err_out;
	}

	if (board_id == vt6420) {
		pci_read_config_byte(pdev, SATA_PATA_SHARING, &tmp8);
		if (tmp8 & SATA_2DEV) {
			dev_printk(KERN_ERR, &pdev->dev,
				   "SATA master/slave not supported (0x%x)\n",
		       		   (int) tmp8);
			rc = -EIO;
			goto err_out_regions;
		}

		bar_sizes = &svia_bar_sizes[0];
	} else {
		bar_sizes = &vt6421_bar_sizes[0];
	}

	for (i = 0; i < ARRAY_SIZE(svia_bar_sizes); i++)
		if ((pci_resource_start(pdev, i) == 0) ||
		    (pci_resource_len(pdev, i) < bar_sizes[i])) {
			dev_printk(KERN_ERR, &pdev->dev,
				"invalid PCI BAR %u (sz 0x%llx, val 0x%llx)\n",
				i,
			        (unsigned long long)pci_resource_start(pdev, i),
			        (unsigned long long)pci_resource_len(pdev, i));
			rc = -ENODEV;
			goto err_out_regions;
		}

	rc = pci_set_dma_mask(pdev, ATA_DMA_MASK);
	if (rc)
		goto err_out_regions;
	rc = pci_set_consistent_dma_mask(pdev, ATA_DMA_MASK);
	if (rc)
		goto err_out_regions;

	if (board_id == vt6420)
		probe_ent = vt6420_init_probe_ent(pdev);
	else
		probe_ent = vt6421_init_probe_ent(pdev);

	if (!probe_ent) {
		dev_printk(KERN_ERR, &pdev->dev, "out of memory\n");
		rc = -ENOMEM;
		goto err_out_regions;
	}

	svia_configure(pdev);

	pci_set_master(pdev);

	/* FIXME: check ata_device_add return value */
	ata_device_add(probe_ent);
	kfree(probe_ent);

	return 0;

err_out_regions:
	pci_release_regions(pdev);
err_out:
	if (!pci_dev_busy)
		pci_disable_device(pdev);
	return rc;
}

static int __init svia_init(void)
{
	return pci_register_driver(&svia_pci_driver);
}

static void __exit svia_exit(void)
{
	pci_unregister_driver(&svia_pci_driver);
}

module_init(svia_init);
module_exit(svia_exit);


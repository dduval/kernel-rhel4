/*
 *    ata_piix.c - Intel PATA/SATA controllers
 *
 *    Maintained by:  Jeff Garzik <jgarzik@pobox.com>
 *    		    Please ALWAYS copy linux-ide@vger.kernel.org
 *		    on emails.
 *
 *
 *	Copyright 2003-2005 Red Hat Inc
 *	Copyright 2003-2005 Jeff Garzik
 *
 *
 *	Copyright header from piix.c:
 *
 *  Copyright (C) 1998-1999 Andrzej Krzysztofowicz, Author and Maintainer
 *  Copyright (C) 1998-2000 Andre Hedrick <andre@linux-ide.org>
 *  Copyright (C) 2003 Red Hat Inc <alan@redhat.com>
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
 *  Hardware documentation available at http://developer.intel.com/
 *
 * Documentation
 *	Publically available from Intel web site. Errata documentation
 * is also publically available. As an aide to anyone hacking on this
 * driver the list of errata that are relevant is below, going back to
 * PIIX4. Older device documentation is now a bit tricky to find.
 *
 * The chipsets all follow very much the same design. The orginal Triton
 * series chipsets do _not_ support independant device timings, but this
 * is fixed in Triton II. With the odd mobile exception the chips then
 * change little except in gaining more modes until SATA arrives. This
 * driver supports only the chips with independant timing (that is those
 * with SITRE and the 0x44 timing register). See pata_oldpiix and pata_mpiix
 * for the early chip drivers.
 *
 * Errata of note:
 *
 * Unfixable
 *	PIIX4    errata #9	- Only on ultra obscure hw
 *	ICH3	 errata #13     - Not observed to affect real hw
 *				  by Intel
 *
 * Things we must deal with
 *	PIIX4	errata #10	- BM IDE hang with non UDMA
 *				  (must stop/start dma to recover)
 *	440MX   errata #15	- As PIIX4 errata #10
 *	PIIX4	errata #15	- Must not read control registers
 * 				  during a PIO transfer
 *	440MX   errata #13	- As PIIX4 errata #15
 *	ICH2	errata #21	- DMA mode 0 doesn't work right
 *	ICH0/1  errata #55	- As ICH2 errata #21
 *	ICH2	spec c #9	- Extra operations needed to handle
 *				  drive hotswap [NOT YET SUPPORTED]
 *	ICH2    spec c #20	- IDE PRD must not cross a 64K boundary
 *				  and must be dword aligned
 *	ICH2    spec c #24	- UDMA mode 4,5 t85/86 should be 6ns not 3.3
 *
 * Should have been BIOS fixed:
 *	450NX:	errata #19	- DMA hangs on old 450NX
 *	450NX:  errata #20	- DMA hangs on old 450NX
 *	450NX:  errata #25	- Corruption with DMA on old 450NX
 *	ICH3    errata #15      - IDE deadlock under high load
 *				  (BIOS must set dev 31 fn 0 bit 23)
 *	ICH3	errata #18	- Don't use native mode
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

#define DRV_NAME	"ata_piix"
#define DRV_VERSION	"2.00ac7-RH1"

enum {
	PIIX_IOCFG		= 0x54, /* IDE I/O configuration register */
	ICH5_PMR		= 0x90, /* port mapping register */
	ICH5_PCS		= 0x92,	/* port control and status */
	PIIX_SCC		= 0x0A, /* sub-class code register */

	PIIX_FLAG_SCR		= (1 << 26), /* SCR available */
	PIIX_FLAG_AHCI		= (1 << 27), /* AHCI possible */
	PIIX_FLAG_CHECKINTR	= (1 << 28), /* make sure PCI INTx enabled */

	PIIX_PATA_FLAGS		= ATA_FLAG_SLAVE_POSS,
	PIIX_SATA_FLAGS		= ATA_FLAG_SATA | PIIX_FLAG_CHECKINTR,

	/* combined mode.  if set, PATA is channel 0.
	 * if clear, PATA is channel 1.
	 */
	PIIX_PORT_ENABLED	= (1 << 0),
	PIIX_PORT_PRESENT	= (1 << 4),

	PIIX_80C_PRI		= (1 << 5) | (1 << 4),
	PIIX_80C_SEC		= (1 << 7) | (1 << 6),

	/* controller IDs */
	piix_pata_33		= 0,	/* PIIX3 or 4 at 33Mhz */
	ich_pata_33		= 1,	/* ICH up to UDMA 33 only */
	ich_pata_66		= 2,	/* ICH up to 66 Mhz */
	ich_pata_100		= 3,	/* ICH up to UDMA 100 */
	ich_pata_133		= 4,	/* ICH up to UDMA 133 */
	ich5_sata		= 5,
	ich6_sata		= 6,
	ich6_sata_ahci		= 7,
	ich6m_sata_ahci		= 8,
	ich8_sata_ahci		= 9,
	ich8_2port_sata		= 10,
	tolapai_sata_ahci	= 11,

	/* constants for mapping table */
	P0			= 0,  /* port 0 */
	P1			= 1,  /* port 1 */
	P2			= 2,  /* port 2 */
	P3			= 3,  /* port 3 */
	IDE			= -1, /* IDE */
	NA			= -2, /* not avaliable */
	RV			= -3, /* reserved */

	PIIX_AHCI_DEVICE	= 6,
};

struct piix_map_db {
	const u32 mask;
	const u16 port_enable;
	const int map[][4];
};

struct piix_host_priv {
	const int *map;
};

static int piix_init_one (struct pci_dev *pdev,
				    const struct pci_device_id *ent);
static void piix_host_stop(struct ata_host *host);
static void piix_pata_error_handler(struct ata_port *ap);
static void ich_pata_error_handler(struct ata_port *ap);
static void piix_sata_error_handler(struct ata_port *ap);
static void piix_set_piomode (struct ata_port *ap, struct ata_device *adev);
static void piix_set_dmamode (struct ata_port *ap, struct ata_device *adev);
static void ich_set_dmamode (struct ata_port *ap, struct ata_device *adev);

static unsigned int in_module_init = 1;

static const struct pci_device_id piix_pci_tbl[] = {
#ifdef ATA_ENABLE_PATA
	/* Intel PIIX4 for the 430TX/440BX/MX chipset: UDMA 33 */
	/* Also PIIX4E (fn3 rev 2) and PIIX4M (fn3 rev 3) */
	{ 0x8086, 0x7111, PCI_ANY_ID, PCI_ANY_ID, 0, 0, piix_pata_33 },
	{ 0x8086, 0x24db, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
	{ 0x8086, 0x25a2, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
	/* Intel PIIX4 */
	{ 0x8086, 0x7199, PCI_ANY_ID, PCI_ANY_ID, 0, 0, piix_pata_33 },
	/* Intel PIIX4 */
	{ 0x8086, 0x7601, PCI_ANY_ID, PCI_ANY_ID, 0, 0, piix_pata_33 },
	/* Intel PIIX */
	{ 0x8086, 0x84CA, PCI_ANY_ID, PCI_ANY_ID, 0, 0, piix_pata_33 },
	/* Intel ICH (i810, i815, i840) UDMA 66*/
	{ 0x8086, 0x2411, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_66 },
	/* Intel ICH0 : UDMA 33*/
	{ 0x8086, 0x2421, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_33 },
	/* Intel ICH2M */
	{ 0x8086, 0x244A, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
	/* Intel ICH2 (i810E2, i845, 850, 860) UDMA 100 */
	{ 0x8086, 0x244B, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
	/*  Intel ICH3M */
	{ 0x8086, 0x248A, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
	/* Intel ICH3 (E7500/1) UDMA 100 */
	{ 0x8086, 0x248B, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
	/* Intel ICH4 (i845GV, i845E, i852, i855) UDMA 100 */
	{ 0x8086, 0x24CA, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
	{ 0x8086, 0x24CB, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
	/* Intel ICH5 */
	{ 0x8086, 0x24DB, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_133 },
	/* C-ICH (i810E2) */
	{ 0x8086, 0x245B, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
	/* ESB (855GME/875P + 6300ESB) UDMA 100  */
	{ 0x8086, 0x25A2, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
	/* ICH6 (and 6) (i915) UDMA 100 */
	{ 0x8086, 0x266F, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
	/* ICH7/7-R (i945, i975) UDMA 100*/
	{ 0x8086, 0x27DF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_133 },
	{ 0x8086, 0x269E, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich_pata_100 },
#endif

	/* NOTE: The following PCI ids must be kept in sync with the
	 * list in drivers/pci/quirks.c.
	 */

	/* 82801EB (ICH5) */
	{ 0x8086, 0x24d1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich5_sata },
	/* 82801EB (ICH5) */
	{ 0x8086, 0x24df, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich5_sata },
	/* 6300ESB (ICH5 variant with broken PCS present bits) */
	{ 0x8086, 0x25a3, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich5_sata },
	/* 6300ESB pretending RAID */
	{ 0x8086, 0x25b0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich5_sata },
	/* 82801FB/FW (ICH6/ICH6W) */
	{ 0x8086, 0x2651, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich6_sata },
	/* 82801FR/FRW (ICH6R/ICH6RW) */
	{ 0x8086, 0x2652, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich6_sata_ahci },
	/* 82801FBM ICH6M (ICH6R with only port 0 and 2 implemented) */
	{ 0x8086, 0x2653, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich6m_sata_ahci },
	/* 82801GB/GR/GH (ICH7, identical to ICH6) */
	{ 0x8086, 0x27c0, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich6_sata_ahci },
	/* 2801GBM/GHM (ICH7M, identical to ICH6M) */
	{ 0x8086, 0x27c4, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich6m_sata_ahci },
	/* Enterprise Southbridge 2 (631xESB/632xESB) */
	{ 0x8086, 0x2680, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich6_sata_ahci },
	/* SATA Controller 1 IDE (ICH8) */
	{ 0x8086, 0x2820, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_sata_ahci },
	/* SATA Controller 2 IDE (ICH8) */
	{ 0x8086, 0x2825, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_2port_sata },
	/* Mobile SATA Controller IDE (ICH8M) */
	{ 0x8086, 0x2828, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_sata_ahci },
	/* SATA Controller IDE (ICH9) */
	{ 0x8086, 0x2920, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_sata_ahci },
	/* SATA Controller IDE (ICH9) */
	{ 0x8086, 0x2921, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_2port_sata },
	/* SATA Controller IDE (ICH9) */
	{ 0x8086, 0x2926, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_2port_sata },
	/* SATA Controller IDE (ICH9M) */
	{ 0x8086, 0x2928, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_2port_sata },
	/* SATA Controller IDE (ICH9M) */
	{ 0x8086, 0x292d, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_2port_sata },
	/* SATA Controller IDE (ICH9M) */
	{ 0x8086, 0x292e, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_sata_ahci },
	/* SATA Controller IDE (Tolapai) */
	{ 0x8086, 0x5028, PCI_ANY_ID, PCI_ANY_ID, 0, 0, tolapai_sata_ahci },
	/* SATA Controller IDE (ICH10) */
	{ 0x8086, 0x3a00, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_sata_ahci },
	/* SATA Controller IDE (ICH10) */
	{ 0x8086, 0x3a06, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_2port_sata },
	/* SATA Controller IDE (ICH10) */
	{ 0x8086, 0x3a20, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_sata_ahci },
	/* SATA Controller IDE (ICH10) */
	{ 0x8086, 0x3a26, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_2port_sata },
	/* SATA Controller IDE (PCH) */
	{ 0x8086, 0x3b20, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_sata_ahci },
	/* SATA Controller IDE (PCH) */
	{ 0x8086, 0x3b21, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_2port_sata },
	/* SATA Controller IDE (PCH) */
	{ 0x8086, 0x3b26, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_2port_sata },
	/* SATA Controller IDE (PCH) */
	{ 0x8086, 0x3b28, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_sata_ahci },
	/* SATA Controller IDE (PCH) */
	{ 0x8086, 0x3b2d, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_2port_sata },
	/* SATA Controller IDE (PCH) */
	{ 0x8086, 0x3b2e, PCI_ANY_ID, PCI_ANY_ID, 0, 0, ich8_sata_ahci },
	{ }	/* terminate list */
};

static struct pci_driver piix_pci_driver = {
	.name			= DRV_NAME,
	.id_table		= piix_pci_tbl,
	.probe			= piix_init_one,
	.remove			= ata_pci_remove_one,
	.suspend		= ata_pci_device_suspend,
	.resume			= ata_pci_device_resume,
};

static struct scsi_host_template piix_sht = {
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
	.dump_sanity_check	= ata_scsi_dump_sanity_check,
	.dump_quiesce		= ata_scsi_dump_quiesce,
	.dump_poll		= ata_scsi_dump_poll,
};

static const struct ata_port_operations piix_pata_ops = {
	.port_disable		= ata_port_disable,
	.set_piomode		= piix_set_piomode,
	.set_dmamode		= piix_set_dmamode,
	.mode_filter		= ata_pci_default_filter,

	.tf_load		= ata_tf_load,
	.tf_read		= ata_tf_read,
	.check_status		= ata_check_status,
	.exec_command		= ata_exec_command,
	.dev_select		= ata_std_dev_select,

	.bmdma_setup		= ata_bmdma_setup,
	.bmdma_start		= ata_bmdma_start,
	.bmdma_stop		= ata_bmdma_stop,
	.bmdma_status		= ata_bmdma_status,
	.qc_prep		= ata_qc_prep,
	.qc_issue		= ata_qc_issue_prot,
	.data_xfer		= ata_pio_data_xfer,

	.freeze			= ata_bmdma_freeze,
	.thaw			= ata_bmdma_thaw,
	.error_handler		= piix_pata_error_handler,
	.post_internal_cmd	= ata_bmdma_post_internal_cmd,

	.irq_handler		= ata_interrupt,
	.irq_clear		= ata_bmdma_irq_clear,

	.port_start		= ata_port_start,
	.port_stop		= ata_port_stop,
	.host_stop		= piix_host_stop,
};

static const struct ata_port_operations ich_pata_ops = {
	.port_disable		= ata_port_disable,
	.set_piomode		= piix_set_piomode,
	.set_dmamode		= ich_set_dmamode,
	.mode_filter		= ata_pci_default_filter,

	.tf_load		= ata_tf_load,
	.tf_read		= ata_tf_read,
	.check_status		= ata_check_status,
	.exec_command		= ata_exec_command,
	.dev_select		= ata_std_dev_select,

	.bmdma_setup		= ata_bmdma_setup,
	.bmdma_start		= ata_bmdma_start,
	.bmdma_stop		= ata_bmdma_stop,
	.bmdma_status		= ata_bmdma_status,
	.qc_prep		= ata_qc_prep,
	.qc_issue		= ata_qc_issue_prot,
	.data_xfer		= ata_pio_data_xfer,

	.freeze			= ata_bmdma_freeze,
	.thaw			= ata_bmdma_thaw,
	.error_handler		= ich_pata_error_handler,
	.post_internal_cmd	= ata_bmdma_post_internal_cmd,

	.irq_handler		= ata_interrupt,
	.irq_clear		= ata_bmdma_irq_clear,

	.port_start		= ata_port_start,
	.port_stop		= ata_port_stop,
	.host_stop		= piix_host_stop,
};

static const struct ata_port_operations piix_sata_ops = {
	.port_disable		= ata_port_disable,

	.tf_load		= ata_tf_load,
	.tf_read		= ata_tf_read,
	.check_status		= ata_check_status,
	.exec_command		= ata_exec_command,
	.dev_select		= ata_std_dev_select,

	.bmdma_setup		= ata_bmdma_setup,
	.bmdma_start		= ata_bmdma_start,
	.bmdma_stop		= ata_bmdma_stop,
	.bmdma_status		= ata_bmdma_status,
	.qc_prep		= ata_qc_prep,
	.qc_issue		= ata_qc_issue_prot,
	.data_xfer		= ata_pio_data_xfer,

	.freeze			= ata_bmdma_freeze,
	.thaw			= ata_bmdma_thaw,
	.error_handler		= piix_sata_error_handler,
	.post_internal_cmd	= ata_bmdma_post_internal_cmd,

	.irq_handler		= ata_interrupt,
	.irq_clear		= ata_bmdma_irq_clear,

	.port_start		= ata_port_start,
	.port_stop		= ata_port_stop,
	.host_stop		= piix_host_stop,
};

static const struct piix_map_db ich5_map_db = {
	.mask = 0x7,
	.port_enable = 0x3,
	.map = {
		/* PM   PS   SM   SS       MAP  */
		{  P0,  NA,  P1,  NA }, /* 000b */
		{  P1,  NA,  P0,  NA }, /* 001b */
		{  RV,  RV,  RV,  RV },
		{  RV,  RV,  RV,  RV },
		{  P0,  P1, IDE, IDE }, /* 100b */
		{  P1,  P0, IDE, IDE }, /* 101b */
		{ IDE, IDE,  P0,  P1 }, /* 110b */
		{ IDE, IDE,  P1,  P0 }, /* 111b */
	},
};

static const struct piix_map_db ich6_map_db = {
	.mask = 0x3,
	.port_enable = 0xf,
	.map = {
		/* PM   PS   SM   SS       MAP */
		{  P0,  P2,  P1,  P3 }, /* 00b */
		{ IDE, IDE,  P1,  P3 }, /* 01b */
		{  P0,  P2, IDE, IDE }, /* 10b */
		{  RV,  RV,  RV,  RV },
	},
};

static const struct piix_map_db ich6m_map_db = {
	.mask = 0x3,
	.port_enable = 0x5,

	/* Map 01b isn't specified in the doc but some notebooks use
	 * it anyway.  MAP 01b have been spotted on both ICH6M and
	 * ICH7M.
	 */
	.map = {
		/* PM   PS   SM   SS       MAP */
		{  P0,  P2,  RV,  RV }, /* 00b */
		{ IDE, IDE,  P1,  P3 }, /* 01b */
		{  P0,  P2, IDE, IDE }, /* 10b */
		{  RV,  RV,  RV,  RV },
	},
};

static const struct piix_map_db ich8_map_db = {
	.mask = 0x3,
	.port_enable = 0x3,
	.map = {
		/* PM   PS   SM   SS       MAP */
		{  P0,  P2,  P1,  P3 }, /* 00b (hardwired when in AHCI) */
		{  RV,  RV,  RV,  RV },
		{  IDE,  IDE,  NA,  NA }, /* 10b (IDE mode) */
		{  RV,  RV,  RV,  RV },
	},
};

static const struct piix_map_db ich8_2port_map_db = {
	.mask = 0x3,
	.port_enable = 0x3,
	.map = {
		/* PM   PS   SM   SS       MAP */
		{  P0,  NA,  P1,  NA }, /* 00b */
		{  RV,  RV,  RV,  RV }, /* 01b */
		{  RV,  RV,  RV,  RV }, /* 10b */
		{  RV,  RV,  RV,  RV },
	},
};

static const struct piix_map_db tolapai_map_db = {
        .mask = 0x3,
        .port_enable = 0x3,
        .map = {
                /* PM   PS   SM   SS       MAP */
                {  P0,  NA,  P1,  NA }, /* 00b */
                {  RV,  RV,  RV,  RV }, /* 01b */
                {  RV,  RV,  RV,  RV }, /* 10b */
                {  RV,  RV,  RV,  RV },
        },
};

static const struct piix_map_db *piix_map_db_table[] = {
	[ich5_sata]		= &ich5_map_db,
	[ich6_sata]		= &ich6_map_db,
	[ich6_sata_ahci]	= &ich6_map_db,
	[ich6m_sata_ahci]	= &ich6m_map_db,
	[ich8_sata_ahci]	= &ich8_map_db,
	[ich8_2port_sata]	= &ich8_2port_map_db,
	[tolapai_sata_ahci]	= &tolapai_map_db,
};

static struct ata_port_info piix_port_info[] = {
	/* piix_pata_33: 0:  PIIX3 or 4 at 33MHz */
	{
		.sht		= &piix_sht,
		.flags		= PIIX_PATA_FLAGS,
		.pio_mask	= 0x1f,	/* pio0-4 */
		.mwdma_mask	= 0x06, /* mwdma1-2 ?? CHECK 0 should be ok but slow */
		.udma_mask	= ATA_UDMA_MASK_40C,
		.port_ops	= &piix_pata_ops,
	},

	/* ich_pata_33: 1 	ICH0 - ICH at 33Mhz*/
	{
		.sht		= &piix_sht,
		.flags		= PIIX_PATA_FLAGS,
		.pio_mask 	= 0x1f,	/* pio 0-4 */
		.mwdma_mask	= 0x06, /* Check: maybe 0x07  */
		.udma_mask	= ATA_UDMA2, /* UDMA33 */
		.port_ops	= &ich_pata_ops,
	},
	/* ich_pata_66: 2 	ICH controllers up to 66MHz */
	{
		.sht		= &piix_sht,
		.flags		= PIIX_PATA_FLAGS,
		.pio_mask 	= 0x1f,	/* pio 0-4 */
		.mwdma_mask	= 0x06, /* MWDMA0 is broken on chip */
		.udma_mask	= ATA_UDMA4,
		.port_ops	= &ich_pata_ops,
	},

	/* ich_pata_100: 3 */
	{
		.sht		= &piix_sht,
		.flags		= PIIX_PATA_FLAGS | PIIX_FLAG_CHECKINTR,
		.pio_mask	= 0x1f,	/* pio0-4 */
		.mwdma_mask	= 0x06, /* mwdma1-2 */
		.udma_mask	= ATA_UDMA5, /* udma0-5 */
		.port_ops	= &ich_pata_ops,
	},

	/* ich_pata_133: 4 	ICH with full UDMA6 */
	{
		.sht		= &piix_sht,
		.flags		= PIIX_PATA_FLAGS | PIIX_FLAG_CHECKINTR,
		.pio_mask 	= 0x1f,	/* pio 0-4 */
		.mwdma_mask	= 0x06, /* Check: maybe 0x07  */
		.udma_mask	= ATA_UDMA6, /* UDMA133 */
		.port_ops	= &ich_pata_ops,
	},

	/* ich5_sata: 5 */
	{
		.sht		= &piix_sht,
		.flags		= PIIX_SATA_FLAGS,
		.pio_mask	= 0x1f,	/* pio0-4 */
		.mwdma_mask	= 0x07, /* mwdma0-2 */
		.udma_mask	= 0x7f,	/* udma0-6 */
		.port_ops	= &piix_sata_ops,
	},

	/* ich6_sata: 6 */
	{
		.sht		= &piix_sht,
		.flags		= PIIX_SATA_FLAGS | PIIX_FLAG_SCR,
		.pio_mask	= 0x1f,	/* pio0-4 */
		.mwdma_mask	= 0x07, /* mwdma0-2 */
		.udma_mask	= 0x7f,	/* udma0-6 */
		.port_ops	= &piix_sata_ops,
	},

	/* ich6_sata_ahci: 7 */
	{
		.sht		= &piix_sht,
		.flags		= PIIX_SATA_FLAGS | PIIX_FLAG_SCR |
				  PIIX_FLAG_AHCI,
		.pio_mask	= 0x1f,	/* pio0-4 */
		.mwdma_mask	= 0x07, /* mwdma0-2 */
		.udma_mask	= 0x7f,	/* udma0-6 */
		.port_ops	= &piix_sata_ops,
	},

	/* ich6m_sata_ahci: 8 */
	{
		.sht		= &piix_sht,
		.flags		= PIIX_SATA_FLAGS | PIIX_FLAG_SCR |
				  PIIX_FLAG_AHCI,
		.pio_mask	= 0x1f,	/* pio0-4 */
		.mwdma_mask	= 0x07, /* mwdma0-2 */
		.udma_mask	= 0x7f,	/* udma0-6 */
		.port_ops	= &piix_sata_ops,
	},

	/* ich8_sata_ahci: 9 */
	{
		.sht		= &piix_sht,
		.flags		= PIIX_SATA_FLAGS | PIIX_FLAG_SCR |
				  PIIX_FLAG_AHCI,
		.pio_mask	= 0x1f,	/* pio0-4 */
		.mwdma_mask	= 0x07, /* mwdma0-2 */
		.udma_mask	= 0x7f,	/* udma0-6 */
		.port_ops	= &piix_sata_ops,
	},

	/* ich8_2port_sata: 10 */
	{
		.sht		= &piix_sht,
		.flags		= PIIX_SATA_FLAGS | PIIX_FLAG_SCR |
				  PIIX_FLAG_AHCI,
		.pio_mask	= 0x1f,	/* pio0-4 */
		.mwdma_mask	= 0x07, /* mwdma0-2 */
		.udma_mask	= 0x7f,	/* udma0-6 */
		.port_ops	= &piix_sata_ops,
	},

	/* tolapai_sata_ahci: 11: */
	{
		.sht		= &piix_sht,
		.flags		= PIIX_SATA_FLAGS | PIIX_FLAG_SCR |
				  PIIX_FLAG_AHCI,
		.pio_mask	= 0x1f,	/* pio0-4 */
		.mwdma_mask	= 0x07, /* mwdma0-2 */
		.udma_mask	= ATA_UDMA6,
		.port_ops	= &piix_sata_ops,
	},

};

static struct pci_bits piix_enable_bits[] = {
	{ 0x41U, 1U, 0x80UL, 0x80UL },	/* port 0 */
	{ 0x43U, 1U, 0x80UL, 0x80UL },	/* port 1 */
};

MODULE_AUTHOR("Andre Hedrick, Alan Cox, Andrzej Krzysztofowicz, Jeff Garzik");
MODULE_DESCRIPTION("SCSI low-level driver for Intel PIIX/ICH ATA controllers");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, piix_pci_tbl);
MODULE_VERSION(DRV_VERSION);

struct ich_laptop {
	u16 device;
	u16 subvendor;
	u16 subdevice;
};

/*
 *	List of laptops that use short cables rather than 80 wire
 */

static const struct ich_laptop ich_laptop[] = {
	/* devid, subvendor, subdev */
	{ 0x27DF, 0x0005, 0x0280 },	/* ICH7 on Acer 5602WLMi */
	{ 0x27DF, 0x1025, 0x0110 },	/* ICH7 on Acer 3682WLMi */
	{ 0x27DF, 0x1043, 0x1267 },	/* ICH7 on Asus W5F */
	{ 0x24CA, 0x1025, 0x0061 },	/* ICH4 on ACER Aspire 2023WLMi */
	/* end marker */
	{ 0, }
};

/**
 *	piix_pata_cbl_detect - Probe host controller cable detect info
 *	@ap: Port for which cable detect info is desired
 *
 *	Read 80c cable indicator from ATA PCI device's PCI config
 *	register.  This register is normally set by firmware (BIOS).
 *
 *	LOCKING:
 *	None (inherited from caller).
 */

static void ich_pata_cbl_detect(struct ata_port *ap)
{
	struct pci_dev *pdev = to_pci_dev(ap->host->dev);
	const struct ich_laptop *lap = &ich_laptop[0];
	u8 tmp, mask;

	/* no 80c support in host controller? */
	if ((ap->udma_mask & ~ATA_UDMA_MASK_40C) == 0)
		goto cbl40;

	/* Check for specials - Acer Aspire 5602WLMi */
	while (lap->device) {
		if (lap->device == pdev->device &&
		    lap->subvendor == pdev->subsystem_vendor &&
		    lap->subdevice == pdev->subsystem_device) {
			ap->cbl = ATA_CBL_PATA40_SHORT;
		    	return;
		}
		lap++;
	}

	/* check BIOS cable detect results */
	mask = ap->port_no == 0 ? PIIX_80C_PRI : PIIX_80C_SEC;
	pci_read_config_byte(pdev, PIIX_IOCFG, &tmp);
	if ((tmp & mask) == 0)
		goto cbl40;

	ap->cbl = ATA_CBL_PATA80;
	return;

cbl40:
	ap->cbl = ATA_CBL_PATA40;
}

/**
 *	piix_pata_prereset - prereset for PATA host controller
 *	@ap: Target port
 *
 *
 *	LOCKING:
 *	None (inherited from caller).
 */
static int piix_pata_prereset(struct ata_port *ap)
{
	struct pci_dev *pdev = to_pci_dev(ap->host->dev);

	if (!pci_test_config_bits(pdev, &piix_enable_bits[ap->port_no]))
		return -ENOENT;
		
	ap->cbl = ATA_CBL_PATA40;
	return ata_std_prereset(ap);
}

static void piix_pata_error_handler(struct ata_port *ap)
{
	ata_bmdma_drive_eh(ap, piix_pata_prereset, ata_std_softreset, NULL,
			   ata_std_postreset);
}


/**
 *	ich_pata_prereset - prereset for PATA host controller
 *	@ap: Target port
 *
 *
 *	LOCKING:
 *	None (inherited from caller).
 */
static int ich_pata_prereset(struct ata_port *ap)
{
	struct pci_dev *pdev = to_pci_dev(ap->host->dev);

	if (!pci_test_config_bits(pdev, &piix_enable_bits[ap->port_no])) {
		ata_port_printk(ap, KERN_INFO, "port disabled. ignoring.\n");
		ap->eh_context.i.action &= ~ATA_EH_RESET_MASK;
		return 0;
	}

	ich_pata_cbl_detect(ap);

	return ata_std_prereset(ap);
}

static void ich_pata_error_handler(struct ata_port *ap)
{
	ata_bmdma_drive_eh(ap, ich_pata_prereset, ata_std_softreset, NULL,
			   ata_std_postreset);
}

static void piix_sata_error_handler(struct ata_port *ap)
{
	ata_bmdma_drive_eh(ap, ata_std_prereset, ata_std_softreset, NULL,
			   ata_std_postreset);
}

/**
 *	piix_set_piomode - Initialize host controller PATA PIO timings
 *	@ap: Port whose timings we are configuring
 *	@adev: um
 *
 *	Set PIO mode for device, in host controller PCI config space.
 *
 *	LOCKING:
 *	None (inherited from caller).
 */

static void piix_set_piomode (struct ata_port *ap, struct ata_device *adev)
{
	unsigned int pio	= adev->pio_mode - XFER_PIO_0;
	struct pci_dev *dev	= to_pci_dev(ap->host->dev);
	unsigned int is_slave	= (adev->devno != 0);
	unsigned int master_port= ap->port_no ? 0x42 : 0x40;
	unsigned int slave_port	= 0x44;
	u16 master_data;
	u8 slave_data;
	u8 udma_enable;
	int control = 0;

	/*
	 *	See Intel Document 298600-004 for the timing programing rules
	 *	for ICH controllers.
	 */

	static const	 /* ISP  RTC */
	u8 timings[][2]	= { { 0, 0 },
			    { 0, 0 },
			    { 1, 0 },
			    { 2, 1 },
			    { 2, 3 }, };

	if (pio >= 2)
		control |= 1;	/* TIME1 enable */
	if (ata_pio_need_iordy(adev))
		control |= 2;	/* IE enable */

	/* Intel specifies that the PPE functionality is for disk only */
	if (adev->class == ATA_DEV_ATA)
		control |= 4;	/* PPE enable */

	pci_read_config_word(dev, master_port, &master_data);
	if (is_slave) {
		/* Enable SITRE (seperate slave timing register) */
		master_data |= 0x4000;
		/* enable PPE1, IE1 and TIME1 as needed */
		master_data |= (control << 4);
		pci_read_config_byte(dev, slave_port, &slave_data);
		slave_data &= (ap->port_no ? 0x0f : 0xf0);
		/* Load the timing nibble for this slave */
		slave_data |= ((timings[pio][0] << 2) | timings[pio][1]) << (ap->port_no ? 4 : 0);
	} else {
		/* Master keeps the bits in a different format */
		master_data &= 0xccf8;
		/* Enable PPE, IE and TIME as appropriate */
		master_data |= control;
		master_data |=
			(timings[pio][0] << 12) |
			(timings[pio][1] << 8);
	}
	pci_write_config_word(dev, master_port, master_data);
	if (is_slave)
		pci_write_config_byte(dev, slave_port, slave_data);

	/* Ensure the UDMA bit is off - it will be turned back on if
	   UDMA is selected */

	if (ap->udma_mask) {
		pci_read_config_byte(dev, 0x48, &udma_enable);
		udma_enable &= ~(1 << (2 * ap->port_no + adev->devno));
		pci_write_config_byte(dev, 0x48, udma_enable);
	}
}

/**
 *	do_pata_set_dmamode - Initialize host controller PATA PIO timings
 *	@ap: Port whose timings we are configuring
 *	@adev: Drive in question
 *	@udma: udma mode, 0 - 6
 *	@isich: set if the chip is an ICH device
 *
 *	Set UDMA mode for device, in host controller PCI config space.
 *
 *	LOCKING:
 *	None (inherited from caller).
 */

static void do_pata_set_dmamode (struct ata_port *ap, struct ata_device *adev, int isich)
{
	struct pci_dev *dev	= to_pci_dev(ap->host->dev);
	u8 master_port		= ap->port_no ? 0x42 : 0x40;
	u16 master_data;
	u8 speed		= adev->dma_mode;
	int devid		= adev->devno + 2 * ap->port_no;
	u8 udma_enable		= 0;

	static const	 /* ISP  RTC */
	u8 timings[][2]	= { { 0, 0 },
			    { 0, 0 },
			    { 1, 0 },
			    { 2, 1 },
			    { 2, 3 }, };

	pci_read_config_word(dev, master_port, &master_data);
	if (ap->udma_mask)
		pci_read_config_byte(dev, 0x48, &udma_enable);

	if (speed >= XFER_UDMA_0) {
		unsigned int udma = adev->dma_mode - XFER_UDMA_0;
		u16 udma_timing;
		u16 ideconf;
		int u_clock, u_speed;

		/*
	 	 * UDMA is handled by a combination of clock switching and
		 * selection of dividers
		 *
		 * Handy rule: Odd modes are UDMATIMx 01, even are 02
		 *	       except UDMA0 which is 00
		 */
		u_speed = min(2 - (udma & 1), udma);
		if (udma == 5)
			u_clock = 0x1000;	/* 100Mhz */
		else if (udma > 2)
			u_clock = 1;		/* 66Mhz */
		else
			u_clock = 0;		/* 33Mhz */

		udma_enable |= (1 << devid);

		/* Load the CT/RP selection */
		pci_read_config_word(dev, 0x4A, &udma_timing);
		udma_timing &= ~(3 << (4 * devid));
		udma_timing |= u_speed << (4 * devid);
		pci_write_config_word(dev, 0x4A, udma_timing);

		if (isich) {
			/* Select a 33/66/100Mhz clock */
			pci_read_config_word(dev, 0x54, &ideconf);
			ideconf &= ~(0x1001 << devid);
			ideconf |= u_clock << devid;
			/* For ICH or later we should set bit 10 for better
			   performance (WR_PingPong_En) */
			pci_write_config_word(dev, 0x54, ideconf);
		}
	} else {
		/*
		 * MWDMA is driven by the PIO timings. We must also enable
		 * IORDY unconditionally along with TIME1. PPE has already
		 * been set when the PIO timing was set.
		 */
		unsigned int mwdma	= adev->dma_mode - XFER_MW_DMA_0;
		unsigned int control;
		u8 slave_data;
		const unsigned int needed_pio[3] = {
			XFER_PIO_0, XFER_PIO_3, XFER_PIO_4
		};
		int pio = needed_pio[mwdma] - XFER_PIO_0;

		control = 3;	/* IORDY|TIME1 */

		/* If the drive MWDMA is faster than it can do PIO then
		   we must force PIO into PIO0 */

		if (adev->pio_mode < needed_pio[mwdma])
			/* Enable DMA timing only */
			control |= 8;	/* PIO cycles in PIO0 */

		if (adev->devno) {	/* Slave */
			master_data &= 0xFF4F;  /* Mask out IORDY|TIME1|DMAONLY */
			master_data |= control << 4;
			pci_read_config_byte(dev, 0x44, &slave_data);
			slave_data &= (0x0F + 0xE1 * ap->port_no);
			/* Load the matching timing */
			slave_data |= ((timings[pio][0] << 2) | timings[pio][1]) << (ap->port_no ? 4 : 0);
			pci_write_config_byte(dev, 0x44, slave_data);
		} else { 	/* Master */
			master_data &= 0xCCF4;	/* Mask out IORDY|TIME1|DMAONLY
						   and master timing bits */
			master_data |= control;
			master_data |=
				(timings[pio][0] << 12) |
				(timings[pio][1] << 8);
		}
		udma_enable &= ~(1 << devid);
		pci_write_config_word(dev, master_port, master_data);
	}
	/* Don't scribble on 0x48 if the controller does not support UDMA */
	if (ap->udma_mask)
		pci_write_config_byte(dev, 0x48, udma_enable);
}

/**
 *	piix_set_dmamode - Initialize host controller PATA DMA timings
 *	@ap: Port whose timings we are configuring
 *	@adev: um
 *
 *	Set MW/UDMA mode for device, in host controller PCI config space.
 *
 *	LOCKING:
 *	None (inherited from caller).
 */

static void piix_set_dmamode (struct ata_port *ap, struct ata_device *adev)
{
	do_pata_set_dmamode(ap, adev, 0);
}

/**
 *	ich_set_dmamode - Initialize host controller PATA DMA timings
 *	@ap: Port whose timings we are configuring
 *	@adev: um
 *
 *	Set MW/UDMA mode for device, in host controller PCI config space.
 *
 *	LOCKING:
 *	None (inherited from caller).
 */

static void ich_set_dmamode (struct ata_port *ap, struct ata_device *adev)
{
	do_pata_set_dmamode(ap, adev, 1);
}

#define AHCI_PCI_BAR 5
#define AHCI_GLOBAL_CTL 0x04
#define AHCI_ENABLE (1 << 31)
static int piix_disable_ahci(struct pci_dev *pdev)
{
	void __iomem *mmio;
	u32 tmp;
	int rc = 0;

	/* BUG: pci_enable_device has not yet been called.  This
	 * works because this device is usually set up by BIOS.
	 */

	if (!pci_resource_start(pdev, AHCI_PCI_BAR) ||
	    !pci_resource_len(pdev, AHCI_PCI_BAR))
		return 0;

	mmio = pci_iomap(pdev, AHCI_PCI_BAR, 64);
	if (!mmio)
		return -ENOMEM;

	tmp = readl(mmio + AHCI_GLOBAL_CTL);
	if (tmp & AHCI_ENABLE) {
		tmp &= ~AHCI_ENABLE;
		writel(tmp, mmio + AHCI_GLOBAL_CTL);

		tmp = readl(mmio + AHCI_GLOBAL_CTL);
		if (tmp & AHCI_ENABLE)
			rc = -EIO;
	}

	pci_iounmap(pdev, mmio);
	return rc;
}

/**
 *	piix_check_450nx_errata	-	Check for problem 450NX setup
 *	@ata_dev: the PCI device to check
 *
 *	Check for the present of 450NX errata #19 and errata #25. If
 *	they are found return an error code so we can turn off DMA
 */

static int __devinit piix_check_450nx_errata(struct pci_dev *ata_dev)
{
	struct pci_dev *pdev = NULL;
	u16 cfg;
	u8 rev;
	int no_piix_dma = 0;

	while((pdev = pci_get_device(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82454NX, pdev)) != NULL)
	{
		/* Look for 450NX PXB. Check for problem configurations
		   A PCI quirk checks bit 6 already */
		pci_read_config_byte(pdev, PCI_REVISION_ID, &rev);
		pci_read_config_word(pdev, 0x41, &cfg);
		/* Only on the original revision: IDE DMA can hang */
		if (rev == 0x00)
			no_piix_dma = 1;
		/* On all revisions below 5 PXB bus lock must be disabled for IDE */
		else if (cfg & (1<<14) && rev < 5)
			no_piix_dma = 2;
	}
	if (no_piix_dma)
		dev_printk(KERN_WARNING, &ata_dev->dev, "450NX errata present, disabling IDE DMA.\n");
	if (no_piix_dma == 2)
		dev_printk(KERN_WARNING, &ata_dev->dev, "A BIOS update may resolve this.\n");
	return no_piix_dma;
}

static void __devinit piix_init_pcs(struct pci_dev *pdev,
				    struct ata_port_info *pinfo,
				    const struct piix_map_db *map_db)
{
	u16 pcs, new_pcs;

	pci_read_config_word(pdev, ICH5_PCS, &pcs);

	new_pcs = pcs | map_db->port_enable;

	if (new_pcs != pcs) {
		DPRINTK("updating PCS from 0x%x to 0x%x\n", pcs, new_pcs);
		pci_write_config_word(pdev, ICH5_PCS, new_pcs);
		msleep(150);
	}
}

static void __devinit piix_init_sata_map(struct pci_dev *pdev,
					 struct ata_port_info *pinfo,
					 const struct piix_map_db *map_db)
{
	struct piix_host_priv *hpriv = pinfo[0].private_data;
	const unsigned int *map;
	int i, invalid_map = 0;
	u8 map_value;

	pci_read_config_byte(pdev, ICH5_PMR, &map_value);

	map = map_db->map[map_value & map_db->mask];

	dev_printk(KERN_INFO, &pdev->dev, "MAP [");
	for (i = 0; i < 4; i++) {
		switch (map[i]) {
		case RV:
			invalid_map = 1;
			printk(" XX");
			break;

		case NA:
			printk(" --");
			break;

		case IDE:
			WARN_ON((i & 1) || map[i + 1] != IDE);
			pinfo[i / 2] = piix_port_info[ich_pata_100];
			pinfo[i / 2].private_data = hpriv;
			i++;
			printk(" IDE IDE");
			break;

		default:
			printk(" P%d", map[i]);
			if (i & 1)
				pinfo[i / 2].flags |= ATA_FLAG_SLAVE_POSS;
			break;
		}
	}
	printk(" ]\n");

	if (invalid_map)
		dev_printk(KERN_ERR, &pdev->dev,
			   "invalid MAP value %u\n", map_value);

	hpriv->map = map;
}

/**
 *	piix_init_one - Register PIIX ATA PCI device with kernel services
 *	@pdev: PCI device to register
 *	@ent: Entry in piix_pci_tbl matching with @pdev
 *
 *	Called from kernel PCI layer.  We probe for combined mode (sigh),
 *	and then hand over control to libata, for it to do the rest.
 *
 *	LOCKING:
 *	Inherited from PCI layer (may sleep).
 *
 *	RETURNS:
 *	Zero on success, or -ERRNO value.
 */

static int piix_init_one (struct pci_dev *pdev, const struct pci_device_id *ent)
{
	static int printed_version;
	struct ata_port_info port_info[2];
	struct ata_port_info *ppinfo[2] = { &port_info[0], &port_info[1] };
	struct piix_host_priv *hpriv;
	unsigned long port_flags;

	if (!printed_version++)
		dev_printk(KERN_DEBUG, &pdev->dev,
			   "version " DRV_VERSION "\n");

	/* no hotplugging support (FIXME) */
	if (!in_module_init)
		return -ENODEV;

	hpriv = kzalloc(sizeof(*hpriv), GFP_KERNEL);
	if (!hpriv)
		return -ENOMEM;

	port_info[0] = piix_port_info[ent->driver_data];
	port_info[1] = piix_port_info[ent->driver_data];
	port_info[0].private_data = hpriv;
	port_info[1].private_data = hpriv;

	port_flags = port_info[0].flags;

	if (port_flags & PIIX_FLAG_AHCI) {
		u8 tmp;
		pci_read_config_byte(pdev, PIIX_SCC, &tmp);
		if (tmp == PIIX_AHCI_DEVICE) {
			int rc = piix_disable_ahci(pdev);
			if (rc)
				return rc;
		}
	}

	/* Initialize SATA map */
	if (port_flags & ATA_FLAG_SATA) {
		piix_init_sata_map(pdev, port_info,
				   piix_map_db_table[ent->driver_data]);
		piix_init_pcs(pdev, port_info,
			      piix_map_db_table[ent->driver_data]);
	}

	/* On ICH5, some BIOSen disable the interrupt using the
	 * PCI_COMMAND_INTX_DISABLE bit added in PCI 2.3.
	 * On ICH6, this bit has the same effect, but only when
	 * MSI is disabled (and it is disabled, as we don't use
	 * message-signalled interrupts currently).
	 */
	if (port_flags & PIIX_FLAG_CHECKINTR)
		pci_intx(pdev, 1);

	if (piix_check_450nx_errata(pdev)) {
		/* This writes into the master table but it does not
		   really matter for this errata as we will apply it to
		   all the PIIX devices on the board */
		port_info[0].mwdma_mask = 0;
		port_info[0].udma_mask = 0;
		port_info[1].mwdma_mask = 0;
		port_info[1].udma_mask = 0;
	}
	return ata_pci_init_one(pdev, ppinfo, 2);
}

static void piix_host_stop(struct ata_host *host)
{
	struct piix_host_priv *hpriv = host->private_data;

	ata_host_stop(host);

	kfree(hpriv);
}

static int __init piix_init(void)
{
	int rc;

	DPRINTK("pci_register_driver\n");
	rc = pci_register_driver(&piix_pci_driver);
	if (rc)
		return rc;

	in_module_init = 0;

	DPRINTK("done\n");
	return 0;
}

static void __exit piix_exit(void)
{
	pci_unregister_driver(&piix_pci_driver);
}

module_init(piix_init);
module_exit(piix_exit);

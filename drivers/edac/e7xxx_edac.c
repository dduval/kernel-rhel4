/*
 * Intel e7xxx Memory Controller kernel module
 * (C) 2003 Linux Networx (http://lnxi.com)
 * This file may be distributed under the terms of the
 * GNU General Public License.
 *
 * See "enum e7xxx_chips" below for supported chipsets
 *
 * Written by Thayne Harbaugh
 * Based on work by Dan Hollis <goemon at anime dot net> and others.
 *	http://www.anime.net/~goemon/linux-ecc/
 *
 * Contributors:
 * 	Eric Biederman (Linux Networx)
 * 	Tom Zimmerman (Linux Networx)
 * 	Jim Garlick (Lawrence Livermore National Labs)
 *	Dave Peterson (Lawrence Livermore National Labs)
 *	That One Guy (Some other place)
 *	Wang Zhenyu (intel.com)
 *
 * $Id: linux-2.6.9-edac.pacth,v 1.3 2005/11/23 02:35:51 jbaron Exp $
 *
 */


#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/slab.h>
#include "edac_mc.h"


#ifndef PCI_DEVICE_ID_INTEL_7205_0
#define PCI_DEVICE_ID_INTEL_7205_0	0x255d
#endif				/* PCI_DEVICE_ID_INTEL_7205_0 */

#ifndef PCI_DEVICE_ID_INTEL_7205_1_ERR
#define PCI_DEVICE_ID_INTEL_7205_1_ERR	0x2551
#endif				/* PCI_DEVICE_ID_INTEL_7205_1_ERR */

#ifndef PCI_DEVICE_ID_INTEL_7500_0
#define PCI_DEVICE_ID_INTEL_7500_0	0x2540
#endif				/* PCI_DEVICE_ID_INTEL_7500_0 */

#ifndef PCI_DEVICE_ID_INTEL_7500_1_ERR
#define PCI_DEVICE_ID_INTEL_7500_1_ERR	0x2541
#endif				/* PCI_DEVICE_ID_INTEL_7500_1_ERR */

#ifndef PCI_DEVICE_ID_INTEL_7501_0
#define PCI_DEVICE_ID_INTEL_7501_0	0x254c
#endif				/* PCI_DEVICE_ID_INTEL_7501_0 */

#ifndef PCI_DEVICE_ID_INTEL_7501_1_ERR
#define PCI_DEVICE_ID_INTEL_7501_1_ERR	0x2541
#endif				/* PCI_DEVICE_ID_INTEL_7501_1_ERR */

#ifndef PCI_DEVICE_ID_INTEL_7505_0
#define PCI_DEVICE_ID_INTEL_7505_0	0x2550
#endif				/* PCI_DEVICE_ID_INTEL_7505_0 */

#ifndef PCI_DEVICE_ID_INTEL_7505_1_ERR
#define PCI_DEVICE_ID_INTEL_7505_1_ERR	0x2551
#endif				/* PCI_DEVICE_ID_INTEL_7505_1_ERR */


#define E7XXX_NR_CSROWS		8	/* number of csrows */
#define E7XXX_NR_DIMMS		8	/* FIXME - is this correct? */


/* E7XXX register addresses - device 0 function 0 */
#define E7XXX_DRB		0x60	/* DRAM row boundary register (8b) */
#define E7XXX_DRA		0x70	/* DRAM row attribute register (8b) */
					/*
					 * 31   Device width row 7 0=x8 1=x4
					 * 27   Device width row 6
					 * 23   Device width row 5
					 * 19   Device width row 4
					 * 15   Device width row 3
					 * 11   Device width row 2
					 *  7   Device width row 1
					 *  3   Device width row 0
					 */
#define E7XXX_DRC		0x7C	/* DRAM controller mode reg (32b) */
					/*
					 * 22    Number channels 0=1,1=2
					 * 19:18 DRB Granularity 32/64MB
					 */
#define E7XXX_TOLM		0xC4	/* DRAM top of low memory reg (16b) */
#define E7XXX_REMAPBASE		0xC6	/* DRAM remap base address reg (16b) */
#define E7XXX_REMAPLIMIT	0xC8	/* DRAM remap limit address reg (16b) */

/* E7XXX register addresses - device 0 function 1 */
#define E7XXX_DRAM_FERR		0x80	/* DRAM first error register (8b) */
#define E7XXX_DRAM_NERR		0x82	/* DRAM next error register (8b) */
#define E7XXX_DRAM_CELOG_ADD	0xA0	/* DRAM first correctable memory */
					/*     error address register (32b) */
					/*
					 * 31:28 Reserved
					 * 27:6  CE address (4k block 33:12)
					 *  5:0  Reserved
					 */
#define E7XXX_DRAM_UELOG_ADD	0xB0	/* DRAM first uncorrectable memory */
					/*     error address register (32b) */
					/*
					 * 31:28 Reserved
					 * 27:6  CE address (4k block 33:12)
					 *  5:0  Reserved
					 */
#define E7XXX_DRAM_CELOG_SYNDROME 0xD0	/* DRAM first correctable memory */
					/*     error syndrome register (16b) */

enum e7xxx_chips {
	E7500 = 0,
	E7501,
	E7505,
	E7205,
};


struct e7xxx_pvt {
	struct pci_dev *bridge_ck;
	u32 tolm;
	u32 remapbase;
	u32 remaplimit;
	const struct e7xxx_dev_info *dev_info;
};


struct e7xxx_dev_info {
	u16 err_dev;
	const char *ctl_name;
};


struct e7xxx_error_info {
	u8 dram_ferr;
	u8 dram_nerr;
	u32 dram_celog_add;
	u16 dram_celog_syndrome;
	u32 dram_uelog_add;
};

static const struct e7xxx_dev_info e7xxx_devs[] = {
	[E7500] = {
		   .err_dev = PCI_DEVICE_ID_INTEL_7500_1_ERR,
		   .ctl_name = "E7500"},
	[E7501] = {
		   .err_dev = PCI_DEVICE_ID_INTEL_7501_1_ERR,
		   .ctl_name = "E7501"},
	[E7505] = {
		   .err_dev = PCI_DEVICE_ID_INTEL_7505_1_ERR,
		   .ctl_name = "E7505"},
	[E7205] = {
		   .err_dev = PCI_DEVICE_ID_INTEL_7205_1_ERR,
		   .ctl_name = "E7205"},
};


/* FIXME - is this valid for both SECDED and S4ECD4ED? */
static inline int e7xxx_find_channel(u16 syndrome)
{
	debugf3("MC: " __FILE__ ": %s()\n", __func__);

	if ((syndrome & 0xff00) == 0)
		return 0;
	if ((syndrome & 0x00ff) == 0)
		return 1;
	if ((syndrome & 0xf000) == 0 || (syndrome & 0x0f00) == 0)
		return 0;
	return 1;
}


static unsigned long
ctl_page_to_phys(struct mem_ctl_info *mci, unsigned long page)
{
	u32 remap;
	struct e7xxx_pvt *pvt = (struct e7xxx_pvt *) mci->pvt_info;

	debugf3("MC: " __FILE__ ": %s()\n", __func__);

	if ((page < pvt->tolm) ||
	    ((page >= 0x100000) && (page < pvt->remapbase)))
		return page;
	remap = (page - pvt->tolm) + pvt->remapbase;
	if (remap < pvt->remaplimit)
		return remap;
	printk(KERN_ERR "Invalid page %lx - out of range\n", page);
	return pvt->tolm - 1;
}


static void process_ce(struct mem_ctl_info *mci, struct e7xxx_error_info *info)
{
	u32 error_1b, page;
	u16 syndrome;
	int row;
	int channel;

	debugf3("MC: " __FILE__ ": %s()\n", __func__);

	/* read the error address */
	error_1b = info->dram_celog_add;
	/* FIXME - should use PAGE_SHIFT */
	page = error_1b >> 6;	/* convert the address to 4k page */
	/* read the syndrome */
	syndrome = info->dram_celog_syndrome;
	/* FIXME - check for -1 */
	row = edac_mc_find_csrow_by_page(mci, page);
	/* convert syndrome to channel */
	channel = e7xxx_find_channel(syndrome);
	edac_mc_handle_ce(mci, page, 0, syndrome, row, channel,
			       "e7xxx CE");
}


static void process_ce_no_info(struct mem_ctl_info *mci)
{
	debugf3("MC: " __FILE__ ": %s()\n", __func__);
	edac_mc_handle_ce_no_info(mci, "e7xxx CE log register overflow");
}


static void process_ue(struct mem_ctl_info *mci, struct e7xxx_error_info *info)
{
	u32 error_2b, block_page;
	int row;

	debugf3("MC: " __FILE__ ": %s()\n", __func__);

	/* read the error address */
	error_2b = info->dram_uelog_add;
	/* FIXME - should use PAGE_SHIFT */
	block_page = error_2b >> 6;	/* convert to 4k address */
	row = edac_mc_find_csrow_by_page(mci, block_page);
	edac_mc_handle_ue(mci, block_page, 0, row, "e7xxx UE");
}


static void process_ue_no_info(struct mem_ctl_info *mci)
{
	debugf3("MC: " __FILE__ ": %s()\n", __func__);
	edac_mc_handle_ue_no_info(mci, "e7xxx UE log register overflow");
}


static void e7xxx_get_error_info (struct mem_ctl_info *mci,
		struct e7xxx_error_info *info)
{
	struct e7xxx_pvt *pvt;

	pvt = (struct e7xxx_pvt *) mci->pvt_info;
	pci_read_config_byte(pvt->bridge_ck, E7XXX_DRAM_FERR,
	    &info->dram_ferr);
	pci_read_config_byte(pvt->bridge_ck, E7XXX_DRAM_NERR,
	    &info->dram_nerr);

	if ((info->dram_ferr & 1) || (info->dram_nerr & 1)) {
		pci_read_config_dword(pvt->bridge_ck, E7XXX_DRAM_CELOG_ADD,
		    &info->dram_celog_add);
		pci_read_config_word(pvt->bridge_ck,
		    E7XXX_DRAM_CELOG_SYNDROME, &info->dram_celog_syndrome);
	}

	if ((info->dram_ferr & 2) || (info->dram_nerr & 2))
		pci_read_config_dword(pvt->bridge_ck, E7XXX_DRAM_UELOG_ADD,
		    &info->dram_uelog_add);

	if (info->dram_ferr & 3)
		pci_write_bits8(pvt->bridge_ck, E7XXX_DRAM_FERR, 0x03,
		    0x03);

	if (info->dram_nerr & 3)
		pci_write_bits8(pvt->bridge_ck, E7XXX_DRAM_NERR, 0x03,
		    0x03);
}


static int e7xxx_process_error_info (struct mem_ctl_info *mci,
		struct e7xxx_error_info *info, int handle_errors)
{
	int error_found;

	error_found = 0;

	/* decode and report errors */
	if (info->dram_ferr & 1) {	/* check first error correctable */
		error_found = 1;

		if (handle_errors)
			process_ce(mci, info);
	}

	if (info->dram_ferr & 2) {	/* check first error uncorrectable */
		error_found = 1;

		if (handle_errors)
			process_ue(mci, info);
	}

	if (info->dram_nerr & 1) {	/* check next error correctable */
		error_found = 1;

		if (handle_errors) {
			if (info->dram_ferr & 1)
				process_ce_no_info(mci);
			else
				process_ce(mci, info);
		}
	}

	if (info->dram_nerr & 2) {	/* check next error uncorrectable */
		error_found = 1;

		if (handle_errors) {
			if (info->dram_ferr & 2)
				process_ue_no_info(mci);
			else
				process_ue(mci, info);
		}
	}

	return error_found;
}


static void e7xxx_check(struct mem_ctl_info *mci)
{
	struct e7xxx_error_info info;

	debugf3("MC: " __FILE__ ": %s()\n", __func__);
	e7xxx_get_error_info(mci, &info);
	e7xxx_process_error_info(mci, &info, 1);
}


static int e7xxx_probe1(struct pci_dev *pdev, int dev_idx)
{
	int rc = -ENODEV;
	int index;
	u16 pci_data;
	struct mem_ctl_info *mci = NULL;
	struct e7xxx_pvt *pvt = NULL;
	u32 drc;
	int drc_chan = 1;	/* Number of channels 0=1chan,1=2chan */
	int drc_drbg = 1;	/* DRB granularity 0=32mb,1=64mb */
	int drc_ddim;		/* DRAM Data Integrity Mode 0=none,2=edac */
	u32 dra;
	unsigned long last_cumul_size;
	struct e7xxx_error_info discard;

	debugf0("MC: " __FILE__ ": %s(): mci\n", __func__);

	/* need to find out the number of channels */
	pci_read_config_dword(pdev, E7XXX_DRC, &drc);
	/* only e7501 can be single channel */
	if (dev_idx == E7501) {
		drc_chan = ((drc >> 22) & 0x1);
		drc_drbg = (drc >> 18) & 0x3;
	}
	drc_ddim = (drc >> 20) & 0x3;

	mci = edac_mc_alloc(sizeof(*pvt), E7XXX_NR_CSROWS, drc_chan + 1);

	if (mci == NULL) {
		rc = -ENOMEM;
		goto fail;
	}

	debugf3("MC: " __FILE__ ": %s(): init mci\n", __func__);

	mci->mtype_cap = MEM_FLAG_RDDR;
	mci->edac_ctl_cap =
	    EDAC_FLAG_NONE | EDAC_FLAG_SECDED | EDAC_FLAG_S4ECD4ED;
	/* FIXME - what if different memory types are in different csrows? */
	mci->mod_name = BS_MOD_STR;
	mci->mod_ver = "$Revision: 1.3 $";
	mci->pdev = pdev;

	debugf3("MC: " __FILE__ ": %s(): init pvt\n", __func__);
	pvt = (struct e7xxx_pvt *) mci->pvt_info;
	pvt->dev_info = &e7xxx_devs[dev_idx];
	pvt->bridge_ck = pci_get_device(PCI_VENDOR_ID_INTEL,
					 pvt->dev_info->err_dev,
					 pvt->bridge_ck);
	if (!pvt->bridge_ck) {
		printk(KERN_ERR
		       "MC: error reporting device not found:"
		       "vendor %x device 0x%x (broken BIOS?)\n",
		       PCI_VENDOR_ID_INTEL, e7xxx_devs[dev_idx].err_dev);
		goto fail;
	}

	debugf3("MC: " __FILE__ ": %s(): more mci init\n", __func__);
	mci->ctl_name = pvt->dev_info->ctl_name;

	mci->edac_check = e7xxx_check;
	mci->ctl_page_to_phys = ctl_page_to_phys;

	/* find out the device types */
	pci_read_config_dword(pdev, E7XXX_DRA, &dra);

	/*
	 * The dram row boundary (DRB) reg values are boundary address
	 * for each DRAM row with a granularity of 32 or 64MB (single/dual
	 * channel operation).  DRB regs are cumulative; therefore DRB7 will
	 * contain the total memory contained in all eight rows.
	 */
	for (last_cumul_size = index = 0; index < mci->nr_csrows; index++) {
		u8 value;
		u32 cumul_size;
		/* mem_dev 0=x8, 1=x4 */
		int mem_dev = (dra >> (index * 4 + 3)) & 0x1;
		struct csrow_info *csrow = &mci->csrows[index];

		pci_read_config_byte(mci->pdev, E7XXX_DRB + index, &value);
		/* convert a 64 or 32 MiB DRB to a page size. */
		cumul_size = value << (25 + drc_drbg - PAGE_SHIFT);
		debugf3("MC: " __FILE__ ": %s(): (%d) cumul_size 0x%x\n",
			__func__, index, cumul_size);
		if (cumul_size == last_cumul_size)
			continue;	/* not populated */

		csrow->first_page = last_cumul_size;
		csrow->last_page = cumul_size - 1;
		csrow->nr_pages = cumul_size - last_cumul_size;
		last_cumul_size = cumul_size;
		csrow->grain = 1 << 12;	/* 4KiB - resolution of CELOG */
		csrow->mtype = MEM_RDDR;	/* only one type supported */
		csrow->dtype = mem_dev ? DEV_X4 : DEV_X8;

		/*
		 * if single channel or x8 devices then SECDED
		 * if dual channel and x4 then S4ECD4ED
		 */
		if (drc_ddim) {
			if (drc_chan && mem_dev) {
				csrow->edac_mode = EDAC_S4ECD4ED;
				mci->edac_cap |= EDAC_FLAG_S4ECD4ED;
			} else {
				csrow->edac_mode = EDAC_SECDED;
				mci->edac_cap |= EDAC_FLAG_SECDED;
			}
		} else
			csrow->edac_mode = EDAC_NONE;
	}

	mci->edac_cap |= EDAC_FLAG_NONE;

	debugf3("MC: " __FILE__ ": %s(): tolm, remapbase, remaplimit\n",
		__func__);
	/* load the top of low memory, remap base, and remap limit vars */
	pci_read_config_word(mci->pdev, E7XXX_TOLM, &pci_data);
	pvt->tolm = ((u32) pci_data) << 4;
	pci_read_config_word(mci->pdev, E7XXX_REMAPBASE, &pci_data);
	pvt->remapbase = ((u32) pci_data) << 14;
	pci_read_config_word(mci->pdev, E7XXX_REMAPLIMIT, &pci_data);
	pvt->remaplimit = ((u32) pci_data) << 14;
	printk("tolm = %x, remapbase = %x, remaplimit = %x\n", pvt->tolm,
	       pvt->remapbase, pvt->remaplimit);

	/* clear any pending errors, or initial state bits */
	e7xxx_get_error_info(mci, &discard);

	if (edac_mc_add_mc(mci) != 0) {
		debugf3("MC: " __FILE__
			": %s(): failed edac_mc_add_mc()\n",
			__func__);
		goto fail;
	}

	/* get this far and it's successful */
	debugf3("MC: " __FILE__ ": %s(): success\n", __func__);
	return 0;

fail:
	if (mci != NULL) {
		if(pvt != NULL && pvt->bridge_ck)
			pci_dev_put(pvt->bridge_ck);
		edac_mc_free(mci);
	}

	return rc;
}

/* returns count (>= 0), or negative on error */
static int __devinit
e7xxx_init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	debugf0("MC: " __FILE__ ": %s()\n", __func__);

	/* wake up and enable device */
	return pci_enable_device(pdev) ?
	    -EIO : e7xxx_probe1(pdev, ent->driver_data);
}


static void __devexit e7xxx_remove_one(struct pci_dev *pdev)
{
	struct mem_ctl_info *mci;
	struct e7xxx_pvt *pvt;

	debugf0(__FILE__ ": %s()\n", __func__);

	if ((mci = edac_mc_del_mc(pdev)) == NULL)
		return;
	pvt = (struct e7xxx_pvt *) mci->pvt_info;
	pci_dev_put(pvt->bridge_ck);
	edac_mc_free(mci);
}


static const struct pci_device_id e7xxx_pci_tbl[] __devinitdata = {
	{PCI_VEND_DEV(INTEL, 7205_0), PCI_ANY_ID, PCI_ANY_ID, 0, 0,
	 E7205},
	{PCI_VEND_DEV(INTEL, 7500_0), PCI_ANY_ID, PCI_ANY_ID, 0, 0,
	 E7500},
	{PCI_VEND_DEV(INTEL, 7501_0), PCI_ANY_ID, PCI_ANY_ID, 0, 0,
	 E7501},
	{PCI_VEND_DEV(INTEL, 7505_0), PCI_ANY_ID, PCI_ANY_ID, 0, 0,
	 E7505},
	{0,}			/* 0 terminated list. */
};

MODULE_DEVICE_TABLE(pci, e7xxx_pci_tbl);


static struct pci_driver e7xxx_driver = {
	.name = BS_MOD_STR,
	.probe = e7xxx_init_one,
	.remove = __devexit_p(e7xxx_remove_one),
	.id_table = e7xxx_pci_tbl,
};


int __init e7xxx_init(void)
{
	return pci_module_init(&e7xxx_driver);
}


static void __exit e7xxx_exit(void)
{
	pci_unregister_driver(&e7xxx_driver);
}

module_init(e7xxx_init);
module_exit(e7xxx_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Networx (http://lnxi.com) Thayne Harbaugh et al\n"
	      "Based on.work by Dan Hollis et al");
MODULE_DESCRIPTION("MC support for Intel e7xxx memory controllers");

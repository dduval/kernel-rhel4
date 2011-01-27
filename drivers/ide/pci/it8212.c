/*
 * linux/drivers/ide/pci/it8212.c		Version 0.07	November 2004
 *
 * Copyright (C) 2004		Red Hat <alan@redhat.com>
 *
 *  May be copied or modified under the terms of the GNU General Public License
 *  Based in part on the ITE vendor provided SCSI driver.
 *
 *  Documentation available from
 * 	http://www.ite.com.tw/pc/IT8212F_V04.pdf
 *  Some other documents are NDA.
 *
 *  The ITE8212 isn't exactly a standard IDE controller. It has two
 *  modes. In pass through mode then it is an IDE controller. In its smart
 *  mode its actually quite a capable hardware raid controller disguised
 *  as an IDE controller. Smart mode only understands DMA read/write and
 *  identify, none of the fancier commands apply.
 *
 *  Errata:
 *  o	Rev 0x10 also requires master/slave hold the same DMA timings and
 *	cannot do ATAPI MWDMA. 
 *  o	The identify data for raid volumes lacks CHS info (technically ok)
 *	but also fails to set the LBA28 and other bits. We fix these in
 *	the IDE probe quirk code.
 *  o	If you write LBA48 sized I/O's (ie > 256 sector) in smart mode
 *	raid then the controller firmware dies
 *  o	Smart mode without RAID doesn't clear all the necessary identify
 *	bits to reduce the command set to the one used
 *
 *  This has a few impacts on the driver
 *  - In pass through mode we do all the work you would expect
 *  - In smart mode the clocking set up is done by the controller generally
 *    but we must watch the other limits and filter.
 *  - There are a few extra vendor commands that actually talk to the
 *    controller but only work PIO with no IRQ.
 *
 *  Vendor areas of the identify block in smart mode are used for the
 *  timing and policy set up. Each HDD in raid mode also has a serial
 *  block on the disk. The hardware extra commands are get/set chip status,
 *  rebuild, get rebuild status.
 *
 *  In Linux the driver supports pass through mode as if the device was
 *  just another IDE controller. If the smart mode is running then
 *  volumes are managed by the controller firmware and each IDE "disk"
 *  is a raid volume. Even more cute - the controller can do automated
 *  hotplug and rebuild.
 *
 *  The pass through controller itself is a little demented. It has a
 *  flaw that it has a single set of PIO/MWDMA timings per channel so
 *  non UDMA devices restrict each others performance. It also has a
 *  single clock source per channel so mixed UDMA100/133 performance
 *  isn't perfect and we have to pick a clock. Thankfully none of this
 *  matters in smart mode. ATAPI DMA is not currently supported.
 *
 *  It seems the smart mode is a win for RAID1/RAID10 but otherwise not.
 *
 *  TODO
 *	-	ATAPI UDMA is ok but not MWDMA it seems
 *	-	RAID configuration ioctls
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/hdreg.h>
#include <linux/ide.h>
#include <linux/init.h>

#include <asm/io.h>

struct it8212_dev
{
	unsigned int smart:1,		/* Are we in smart raid mode */
		timing10:1;		/* Rev 0x10 */
	u8	clock_mode;		/* 0, ATA_50 or ATA_66 */
	u8	want[2][2];		/* Mode/Pri log for master slave */
	/* We need these for switching the clock when DMA goes on/off
	   The high byte is the 66Mhz timing */
	u16	pio[2];			/* Cached PIO values */
	u16	mwdma[2];		/* Cached MWDMA values */
	u16	udma[2];		/* Cached UDMA values (per drive) */
};

#define ATA_66		0
#define ATA_50		1
#define ATA_ANY		2

#define UDMA_OFF	0
#define MWDMA_OFF	0

/*
 *	We allow users to force the card into non raid mode without
 *	flashing the alternative BIOS. This is also neccessary right now
 *	for embedded platforms that cannot run a PC BIOS but are using this
 *	device.
 */
 
static int it8212_noraid;

/**
 *	it8212_program	-	program the PIO/MWDMA registers
 *	@drive: drive to tune
 *
 *	Program the PIO/MWDMA timing for this channel according to the
 *	current clock.
 */

static void it8212_program(ide_drive_t *drive, u16 timing)
{
	ide_hwif_t *hwif	= HWIF(drive);
	struct it8212_dev *itdev = ide_get_hwifdata(hwif);
	int channel = hwif->channel;
	u8 conf;

	/* Program PIO/MWDMA timing bits */
	if(itdev->clock_mode == ATA_66)
		conf = timing >> 8;
	else	
		conf = timing & 0xFF;
	pci_write_config_byte(hwif->pci_dev, 0x54 + 4 * channel, conf);
}

/**
 *	it8212_program_udma	-	program the UDMA registers
 *	@drive: drive to tune
 *
 *	Program the UDMA timing for this drive according to the
 *	current clock.
 */

static void it8212_program_udma(ide_drive_t *drive, u16 timing)
{
	ide_hwif_t *hwif	= HWIF(drive);
	struct it8212_dev *itdev = ide_get_hwifdata(hwif);
	int channel = hwif->channel;
	int unit = drive->select.b.unit;
	u8 conf;
	
	/* Program UDMA timing bits */
	if(itdev->clock_mode == ATA_66)
		conf = timing >> 8;
	else
		conf = timing & 0xFF;
	if(itdev->timing10 == 0)
		pci_write_config_byte(hwif->pci_dev, 0x56 + 4 * channel + unit, conf);
	else {
		pci_write_config_byte(hwif->pci_dev, 0x56 + 4 * channel, conf);
		pci_write_config_byte(hwif->pci_dev, 0x56 + 4 * channel + 1, conf);
	}
}


/**
 *	it8212_clock_strategy
 *	@hwif: hardware interface
 *
 *	Select between the 50 and 66Mhz base clocks to get the best
 *	results for this interface.
 */

static void it8212_clock_strategy(ide_drive_t *drive)
{
	ide_hwif_t *hwif = HWIF(drive);
	struct it8212_dev *itdev = ide_get_hwifdata(hwif);

	u8 unit = drive->select.b.unit;
	ide_drive_t *pair = &hwif->drives[1-unit];

	int clock, altclock;
	u8 v;
	int sel = 0;

	if(itdev->want[0][0] > itdev->want[1][0]) {
		clock = itdev->want[0][1];
		altclock = itdev->want[1][1];
	} else {
		clock = itdev->want[1][1];
		altclock = itdev->want[0][1];
	}

	/* Master doesn't care does the slave ? */
	if(clock == ATA_ANY)
		clock = altclock;
		
	/* Nobody cares - keep the same clock */
	if(clock == ATA_ANY)
		return;
	/* No change */
	if(clock == itdev->clock_mode)
		return;
		
	/* Load this into the controller ? */
	if(clock == ATA_66)
		itdev->clock_mode = ATA_66;
	else {
		itdev->clock_mode = ATA_50;
		sel = 1;
	}
	pci_read_config_byte(hwif->pci_dev, 0x50, &v);
	v &= ~(1 << (1 + hwif->channel));
	v |= sel << (1 + hwif->channel);
	pci_write_config_byte(hwif->pci_dev, 0x50, v);
	
	/*
	 *	Reprogram the UDMA/PIO of the pair drive for the switch
	 *	MWDMA will be dealt with by the dma switcher
	 */
	if(pair && itdev->udma[1-unit] != UDMA_OFF) {
		it8212_program_udma(pair, itdev->udma[1-unit]);
		it8212_program(pair, itdev->pio[1-unit]);
	}
	/*
	 *	Reprogram the UDMA/PIO of our drive for the switch.
	 *	MWDMA will be dealt with by the dma switcher
	 */
	if(itdev->udma[unit] != UDMA_OFF) {
		it8212_program_udma(drive, itdev->udma[unit]);
		it8212_program(drive, itdev->pio[unit]);
	}
}

/**
 *	it8212_ratemask	-	Compute available modes
 *	@drive: IDE drive
 *
 *	Compute the available speeds for the devices on the interface. This
 *	is all modes to ATA133 clipped by drive cable setup.
 */

static byte it8212_ratemask (ide_drive_t *drive)
{
	u8 mode	= 4;
	if (!eighty_ninty_three(drive))
		mode = min(mode, (u8)1);
	return mode;
}

/**
 *	it8212_tuneproc	-	tune a drive
 *	@drive: drive to tune
 *	@mode_wanted: the target operating mode
 *
 *	Load the timing settings for this device mode into the
 *	controller. By the time we are called the mode has been
 *	modified as neccessary to handle the absence of seperate
 *	master/slave timers for MWDMA/PIO.
 *
 *	This code is only used in pass through mode.
 */

static void it8212_tuneproc (ide_drive_t *drive, byte mode_wanted)
{
	ide_hwif_t *hwif	= HWIF(drive);
	struct it8212_dev *itdev = ide_get_hwifdata(hwif);
	int unit = drive->select.b.unit;
	
	/* Spec says 89 ref driver uses 88 */
	static u16 pio[]	= { 0xAA88, 0xA382, 0xA181, 0x3332, 0x3121 };
	static u8 pio_want[]    = { ATA_66, ATA_66, ATA_66, ATA_66, ATA_ANY };
	
	if(itdev->smart)
		return;

	/* We prefer 66Mhz clock for PIO 0-3, don't care for PIO4 */
	itdev->want[unit][1] = pio_want[mode_wanted];
	itdev->want[unit][0] = 1;	/* PIO is lowest priority */
	itdev->pio[unit] = pio[mode_wanted];
	it8212_clock_strategy(drive);
	it8212_program(drive, itdev->pio[unit]);
}

/**
 *	it8212_tune_mwdma	-	tune a channel for MWDMA
 *	@drive: drive to set up
 *	@mode_wanted: the target operating mode
 *
 *	Load the timing settings for this device mode into the
 *	controller when doing MWDMA in pass through mode. The caller
 *	must manage the whole lack of per device MWDMA/PIO timings and
 *	the shared MWDMA/PIO timing register.
 */

static void it8212_tune_mwdma (ide_drive_t *drive, byte mode_wanted)
{
	ide_hwif_t *hwif	= HWIF(drive);
	struct it8212_dev *itdev = (void *)ide_get_hwifdata(hwif);
	int unit = drive->select.b.unit;
	int channel = hwif->channel;
	u8 conf;
	
	static u16 dma[]	= { 0x8866, 0x3222, 0x3121 };
	static u8 mwdma_want[]	= { ATA_ANY, ATA_66, ATA_ANY };
	
	itdev->want[unit][1] = mwdma_want[mode_wanted];
	itdev->want[unit][0] = 2;	/* MWDMA is low priority */
	itdev->mwdma[unit] = dma[mode_wanted];
	itdev->udma[unit] = UDMA_OFF;
	
	/* UDMA bits off - Revision 0x10 do them in pairs */
	pci_read_config_byte(hwif->pci_dev, 0x50, &conf);
	if(itdev->timing10)
		conf |= channel ? 0x60: 0x18;
	else
		conf |= 1 << (3 + 2 * channel + unit);
	pci_write_config_byte(hwif->pci_dev, 0x50, conf);

	it8212_clock_strategy(drive);
	/* FIXME: do we need to program this ? */
	/* it8212_program(drive, itdev->mwdma[unit]); */
}

/**
 *	it8212_tune_udma	-	tune a channel for UDMA
 *	@drive: drive to set up
 *	@mode_wanted: the target operating mode
 *
 *	Load the timing settings for this device mode into the
 *	controller when doing UDMA modes in pass through.
 */

static void it8212_tune_udma (ide_drive_t *drive, byte mode_wanted)
{
	ide_hwif_t *hwif	= HWIF(drive);
	struct it8212_dev *itdev = ide_get_hwifdata(hwif);
	int unit = drive->select.b.unit;
	int channel = hwif->channel;
	u8 conf;

	static u16 udma[]	= { 0x4433, 0x4231, 0x3121, 0x2121, 0x1111, 0x2211, 0x1111 };
	static u8 udma_want[]	= { ATA_ANY, ATA_50, ATA_ANY, ATA_66, ATA_66, ATA_50, ATA_66 };
	
	itdev->want[unit][1] = udma_want[mode_wanted];
	itdev->want[unit][0] = 3;	/* UDMA is high priority */
	itdev->mwdma[unit] = MWDMA_OFF;
	itdev->udma[unit] = udma[mode_wanted];
	if(mode_wanted >= 5)
		itdev->udma[unit] |= 0x8080;	/* UDMA 5/6 select on */
		
	/* UDMA on. Again revision 0x10 must do the pair */
	pci_read_config_byte(hwif->pci_dev, 0x50, &conf);
	if(itdev->timing10)
		conf &= channel ? 0x9F: 0xE7;
	else
		conf &= ~ (1 << (3 + 2 * channel + unit));
	pci_write_config_byte(hwif->pci_dev, 0x50, conf);

	it8212_clock_strategy(drive);
	it8212_program_udma(drive, itdev->udma[unit]);
	
}

/**
 *	config_it8212_chipset_for_pio	-	set drive timings
 *	@drive: drive to tune
 *	@speed we want
 *
 *	Compute the best pio mode we can for a given device. We must
 *	pick a speed that does not cause problems with the other device
 *	on the cable.
 */

static void config_it8212_chipset_for_pio (ide_drive_t *drive, byte set_speed)
{
	u8 unit = drive->select.b.unit;
	ide_hwif_t *hwif = HWIF(drive);
	ide_drive_t *pair = &hwif->drives[1-unit];
	u8 speed = 0, set_pio	= ide_get_best_pio_mode(drive, 4, 5, NULL);
	u8 pair_pio;
	
	/* We have to deal with this mess in pairs */
	if(pair != NULL) {
		pair_pio = ide_get_best_pio_mode(pair, 4, 5, NULL);
		/* Trim PIO to the slowest of the master/slave */
		if(pair_pio < set_pio)
			set_pio = pair_pio;
	}
	it8212_tuneproc(drive, set_pio);
	speed = XFER_PIO_0 + set_pio;
	/* XXX - We trim to the lowest of the pair so the other drive
	   will always be fine at this point until we do hotplug passthru */

	if (set_speed)
		(void) ide_config_drive_speed(drive, speed);
}

static void config_chipset_for_pio (ide_drive_t *drive, byte set_speed)
{
	config_it8212_chipset_for_pio(drive, set_speed);
}

/**
 *	it8212_dma_read	-	DMA hook
 *	@drive: drive for DMA
 *
 *	The IT8212 has a single timing register for MWDMA and for PIO
 *	operations. As we flip back and forth we have to reload the
 *	clock. In addition the rev 0x10 device only works if the same
 *	timing value is loaded into the master and slave UDMA clock
 * 	so we must also reload that.
 *
 *	FIXME: we could figure out in advance if we need to do reloads
 */

static int it8212_dma_begin(ide_drive_t *drive)
{
	ide_hwif_t *hwif = HWIF(drive);
	struct it8212_dev *itdev = ide_get_hwifdata(hwif);
	int unit = drive->select.b.unit;
	if(itdev->mwdma[unit] != MWDMA_OFF)
		it8212_program(drive, itdev->mwdma[unit]);
	else if(itdev->udma[unit] != UDMA_OFF && itdev->timing10)
		it8212_program_udma(drive, itdev->udma[unit]);
	return __ide_dma_begin(drive);
}

/**
 *	it8212_dma_write	-	DMA hook
 *	@drive: drive for DMA stop
 *
 *	The IT8212 has a single timing register for MWDMA and for PIO
 *	operations. As we flip back and forth we have to reload the
 *	clock.
 */

static int it8212_dma_end(ide_drive_t *drive)
{
	ide_hwif_t *hwif = HWIF(drive);
	int unit = drive->select.b.unit;
	struct it8212_dev *itdev = ide_get_hwifdata(hwif);
	int ret = __ide_dma_end(drive);
	if(itdev->mwdma[unit] != MWDMA_OFF)
		it8212_program(drive, itdev->pio[unit]);
	return ret;
}

	
/**
 *	it8212_tune_chipset	-	set controller timings
 *	@drive: Drive to set up
 *	@xferspeed: speed we want to achieve
 *
 *	Tune the ITE chipset for the desired mode. If we can't achieve
 *	the desired mode then tune for a lower one, but ultimately
 *	make the thing work.
 */

static int it8212_tune_chipset (ide_drive_t *drive, byte xferspeed)
{

	ide_hwif_t *hwif	= HWIF(drive);
	struct it8212_dev *itdev = ide_get_hwifdata(hwif);
	u8 speed		= ide_rate_filter(it8212_ratemask(drive), xferspeed);

	switch(speed) {
		case XFER_PIO_4:
		case XFER_PIO_3:
		case XFER_PIO_2:
		case XFER_PIO_1:
		case XFER_PIO_0:
			it8212_tuneproc(drive, (speed - XFER_PIO_0));
			break;
		/* MWDMA tuning is really hard because our MWDMA and PIO
		   timings are kept in the same place. We can switch in the
		   host dma on/off callbacks */
		case XFER_MW_DMA_2:
		case XFER_MW_DMA_1:
		case XFER_MW_DMA_0:
			if(!itdev->smart)
				it8212_tune_mwdma(drive, (speed - XFER_MW_DMA_0));
			break;
		case XFER_UDMA_6:
		case XFER_UDMA_5:
		case XFER_UDMA_4:
		case XFER_UDMA_3:
		case XFER_UDMA_2:
		case XFER_UDMA_1:
		case XFER_UDMA_0:
			if(!itdev->smart)
				it8212_tune_udma(drive, (speed - XFER_UDMA_0));
			break;
		default:
			return 1;
	}
	/*
	 *	In smart mode the clocking is done by the host controller
	 * 	snooping the mode we picked. The rest of it is not our problem
	 */
	return (ide_config_drive_speed(drive, speed));
}

/**
 *	config_chipset_for_dma	-	configure for DMA
 *	@drive: drive to configure
 *
 *	Called by the IDE layer when it wants the timings set up.
 */

static int config_chipset_for_dma (ide_drive_t *drive)
{
	u8 speed	= ide_dma_speed(drive, it8212_ratemask(drive));

	config_chipset_for_pio(drive, !speed);

	if (!speed)
		return 0;

	if (ide_set_xfer_rate(drive, speed))
		return 0;

	if (!drive->init_speed)
		drive->init_speed = speed;

	return ide_dma_enable(drive);
}

/**
 *	it8212_configure_drive_for_dma	-	set up for DMA transfers
 *	@drive: drive we are going to set up
 *
 *	Set up the drive for DMA, tune the controller and drive as
 *	required. If the drive isn't suitable for DMA or we hit
 *	other problems then we will drop down to PIO and set up
 *	PIO appropriately
 */

static int it8212_config_drive_for_dma (ide_drive_t *drive)
{
	ide_hwif_t *hwif	= HWIF(drive);
	struct hd_driveid *id	= drive->id;

	if ((id->capability & 1) != 0 && drive->autodma) {
		/* Consult the list of known "bad" drives */
		if (__ide_dma_bad_drive(drive))
			goto fast_ata_pio;

		if ((id->field_valid & 4) && it8212_ratemask(drive)) {
			if (id->dma_ultra & hwif->ultra_mask) {
				/* Force if Capable UltraDMA */
				int dma = config_chipset_for_dma(drive);
				if ((id->field_valid & 2) && !dma)
					goto try_dma_modes;
			}
		} else if (id->field_valid & 2) {
try_dma_modes:
			if ((id->dma_mword & hwif->mwdma_mask) ||
			    (id->dma_1word & hwif->swdma_mask)) {
				/* Force if Capable regular DMA modes */
				if (!config_chipset_for_dma(drive))
					goto no_dma_set;
			}
		} else if (__ide_dma_good_drive(drive) &&
			   (id->eide_dma_time < 150)) {
			/* Consult the list of known "good" drives */
			if (!config_chipset_for_dma(drive))
				goto no_dma_set;
		} else {
			goto fast_ata_pio;
		}
		return hwif->ide_dma_on(drive);
	} else if ((id->capability & 8) || (id->field_valid & 2)) {
fast_ata_pio:
no_dma_set:
		config_chipset_for_pio(drive, 1);
		return hwif->ide_dma_off_quietly(drive);
	}
	/* IORDY not supported */
	return 0;
}

/**
 *	init_chipset_it8212	-	set up an ITE device
 *	@dev: PCI device
 *	@name: device name
 *
 *	PCI chipset level initialize. Nothing to do.
 */

static unsigned int __devinit init_chipset_it8212(struct pci_dev *dev, const char *name)
{
	return 0;
}

/**
 *	ata66_it8212	-	check for 80 pin cable
 *	@hwif: interface to check
 *
 *	Check for the presence of an ATA66 capable cable on the
 *	interface. Problematic as it seems some cards don't have
 *	the needed logic onboard.
 */

static unsigned int __devinit ata66_it8212(ide_hwif_t *hwif)
{
	/* The reference driver also only does disk side */
	return 1;
}

/**
 *	it8212_fixup	-	post init callback
 *	@hwif: interface
 *
 *	This callback is run after the drives have been probed but
 *	before anything gets attached. It allows drivers to do any 
 *	final tuning that is needed, or fixups to work around bugs.
 */

static void __devinit it8212_fixups(ide_hwif_t *hwif)
{
	struct it8212_dev *itdev = ide_get_hwifdata(hwif);
	int i;

	if(!itdev->smart) {
		/*
		 *	If we are in pass through mode then not much
		 *	needs to be done, but we do bother to clear the
		 *	IRQ mask in case the drives are PIO (eg rev 0x10)
		 *	for now.
		 */
		for (i = 0; i < 2; i++) {
			ide_drive_t *drive = &hwif->drives[i];
			if(drive->present)
				drive->unmask = 1;
		}
		return;
	}
	/*
	 *	Perform fixups on smart mode. We need to "lose" some
	 *	capabilities the firmware lacks but does not filter, and
	 *	also patch up some capability bits that it forgets to set
	 *	in RAID mode.
	 */
	
	for(i = 0; i < 2; i++) {
		ide_drive_t *drive = &hwif->drives[i];
		struct hd_driveid *id;
		u16 *idbits;
		
		if(!drive->present)
			continue;
		id = drive->id;
		idbits = (u16 *)drive->id;
		
		/* Check for RAID v native */
		if(strstr(id->model, "Integrated Technology Express")) {
			/* In raid mode the ident block is slightly buggy */
			id->capability |= 3;		/* LBA28, DMA */
			id->command_set_2 |= 0x0400;	/* LBA48 valid */
			id->cfs_enable_2 |= 0x0400;	/* LBA48 on */
			/* Reporting logic */
			printk(KERN_INFO "%s: IT8212 %sRAID %d volume",
				drive->name,
				idbits[147] ? "Bootable ":"",
				idbits[129]);
				if(idbits[129] != 1)
					printk("(%dK stripe)", idbits[146]);
				printk(".\n");
		} else {
			/* Non RAID volume. Fixups to stop the core code 
			   doing unsupported things */
			id->field_valid &= 1;
			id->queue_depth = 0;
			id->command_set_1 = 0;
			id->command_set_2 &= 0xC400;
			id->cfsse &= 0xC000;
			id->cfs_enable_1 = 0;
			id->cfs_enable_2 &= 0xC400;
			id->csf_default &= 0xC000;
			id->word127 = 0;
			id->dlf = 0;
			id->csfo = 0;
			id->cfa_power = 0;
			printk(KERN_INFO "%s: Performing identify fixups.\n",
				drive->name);
		}
	}
	
}

/**
 *	init_hwif_it8212	-	set up hwif structs
 *	@hwif: interface to set up
 *
 *	We do the basic set up of the interface structure. The IT8212
 *	requires several custom handlers so we override the default
 *	ide DMA handlers appropriately
 */

static void __devinit init_hwif_it8212(ide_hwif_t *hwif)
{
	struct it8212_dev *idev = kmalloc(sizeof(struct it8212_dev), GFP_KERNEL);
	u8 conf;
	static char *mode[2] = { "pass through", "smart" };

	if(idev == NULL) {
		printk(KERN_ERR "it8212: out of memory, falling back to legacy behaviour.\n");
		goto fallback;
	}
	memset(idev, 0, sizeof(struct it8212_dev));
	ide_set_hwifdata(hwif, idev);

	/* Force the card into bypass mode if so requested */
	if (it8212_noraid) {
		printk(KERN_INFO "it8212: forcing bypass mode.\n");

		/* Reset local CPU, and set BIOS not ready */
		pci_write_config_byte(hwif->pci_dev, 0x5E, 0x01);

		/* Set to bypass mode, and reset PCI bus */
		pci_write_config_byte(hwif->pci_dev, 0x50, 0x00);

		pci_write_config_word(hwif->pci_dev, PCI_COMMAND,
				      PCI_COMMAND_PARITY | PCI_COMMAND_IO |
				      PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);

		pci_write_config_word(hwif->pci_dev, 0x40, 0xA0F3);

		pci_write_config_dword(hwif->pci_dev,0x4C, 0x02040204);
		pci_write_config_byte(hwif->pci_dev, 0x42, 0x36);
		pci_write_config_byte(hwif->pci_dev, PCI_LATENCY_TIMER, 0);
	}

	pci_read_config_byte(hwif->pci_dev, 0x50, &conf);
	if(conf & 1) {
		idev->smart = 1;
		hwif->atapi_dma = 0;
		/* Long I/O's although allowed in LBA48 space cause the
		   onboard firmware to enter the twighlight zone */
		hwif->rqsize = 256;
	}

	if(hwif->channel == 0)
		printk(KERN_INFO "it8212: controller in %s mode.\n",
			mode[idev->smart]);
		
	pci_read_config_byte(hwif->pci_dev, 0x50, &conf);
	if (conf & (1 << (1 + hwif->channel)))
		idev->clock_mode = ATA_50;
	else
		idev->clock_mode = ATA_66;
		
	idev->want[0][1] = ATA_ANY;
	idev->want[1][1] = ATA_ANY;
		
	/*
	 *	Not in the docs but according to the reference driver
	 *	this is neccessary. 
	 */

	pci_read_config_byte(hwif->pci_dev, 0x08, &conf);
	if(conf == 0x10) {
		idev->timing10 = 1;
		hwif->atapi_dma = 0;
		if(!idev->smart)
			printk(KERN_WARNING "it8212: Revision 0x10, workarounds activated.\n");
	}
		
	hwif->speedproc = &it8212_tune_chipset;
	hwif->tuneproc	= &it8212_tuneproc;
	
	/* MWDMA/PIO clock switching for pass through mode */
	if(!idev->smart) {
		hwif->ide_dma_begin = &it8212_dma_begin;
		hwif->ide_dma_end = &it8212_dma_end;
	}

	if (!hwif->dma_base)
		goto fallback;

	hwif->ultra_mask = 0x7f;
	hwif->mwdma_mask = 0x07;
	hwif->swdma_mask = 0x07;

	hwif->ide_dma_check = &it8212_config_drive_for_dma;
	if (!(hwif->udma_four))
		hwif->udma_four = ata66_it8212(hwif);

	/*
	 *	The BIOS often doesn't set up DMA on this controller
	 *	so we always do it.
	 */

	hwif->autodma = 1;
	hwif->drives[0].autodma = hwif->autodma;
	hwif->drives[1].autodma = hwif->autodma;
	return;

fallback:
	hwif->autodma = 0;
	hwif->drives[0].autotune = 1;
	hwif->drives[1].autotune = 1;
	return;
}

#define DECLARE_ITE_DEV(name_str)			\
	{						\
		.name		= name_str,		\
		.init_chipset	= init_chipset_it8212,	\
		.init_hwif	= init_hwif_it8212,	\
		.channels	= 2,			\
		.autodma	= AUTODMA,		\
		.bootable	= ON_BOARD,		\
		.fixup	 	= it8212_fixups		\
	}

static ide_pci_device_t it8212_chipsets[] __devinitdata = {
	/* 0 */ DECLARE_ITE_DEV("IT8212"),
};

/**
 *	it8212_init_one	-	pci layer discovery entry
 *	@dev: PCI device
 *	@id: ident table entry
 *
 *	Called by the PCI code when it finds an ITE8212 controller.
 *	We then use the IDE PCI generic helper to do most of the work.
 */

static int __devinit it8212_init_one(struct pci_dev *dev, const struct pci_device_id *id)
{
	ide_setup_pci_device(dev, &it8212_chipsets[id->driver_data]);
	return 0;
}

static struct pci_device_id it8212_pci_tbl[] = {
	{ PCI_VENDOR_ID_ITE, PCI_DEVICE_ID_ITE_8212,  PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{ 0, },
};

MODULE_DEVICE_TABLE(pci, it8212_pci_tbl);

static struct pci_driver driver = {
	.name		= "ITE8212 IDE",
	.id_table	= it8212_pci_tbl,
	.probe		= it8212_init_one,
};

static int __init it8212_ide_init(void)
{
	return ide_pci_register_driver(&driver);
}

module_init(it8212_ide_init);

module_param_named(noraid, it8212_noraid, int, S_IRUGO);
MODULE_PARM_DESC(it8212_noraid, "Force card into bypass mode");

MODULE_AUTHOR("Alan Cox");
MODULE_DESCRIPTION("PCI driver module for the ITE 8212");
MODULE_LICENSE("GPL");

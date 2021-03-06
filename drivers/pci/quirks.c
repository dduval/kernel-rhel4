/*
 *  This file contains work-arounds for many known PCI hardware
 *  bugs.  Devices present only on certain architectures (host
 *  bridges et cetera) should be handled in arch-specific code.
 *
 *  Note: any quirks for hotpluggable devices must _NOT_ be declared __init.
 *
 *  Copyright (c) 1999 Martin Mares <mj@ucw.cz>
 *
 *  The bridge optimization stuff has been removed. If you really
 *  have a silly BIOS which is unable to set your host bridge right,
 *  use the PowerTweak utility (see http://powertweak.sourceforge.net).
 */

#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include "pci.h"

#undef DEBUG

/* Deal with broken BIOS'es that neglect to enable passive release,
   which can cause problems in combination with the 82441FX/PPro MTRRs */
static void __devinit quirk_passive_release(struct pci_dev *dev)
{
	struct pci_dev *d = NULL;
	unsigned char dlc;

	/* We have to make sure a particular bit is set in the PIIX3
	   ISA bridge, so we have to go out and find it. */
	while ((d = pci_find_device(PCI_VENDOR_ID_INTEL, PCI_DEVICE_ID_INTEL_82371SB_0, d))) {
		pci_read_config_byte(d, 0x82, &dlc);
		if (!(dlc & 1<<1)) {
			printk(KERN_ERR "PCI: PIIX3: Enabling Passive Release on %s\n", pci_name(d));
			dlc |= 1<<1;
			pci_write_config_byte(d, 0x82, dlc);
		}
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82441,	quirk_passive_release );

/*  The VIA VP2/VP3/MVP3 seem to have some 'features'. There may be a workaround
    but VIA don't answer queries. If you happen to have good contacts at VIA
    ask them for me please -- Alan 
    
    This appears to be BIOS not version dependent. So presumably there is a 
    chipset level fix */
int isa_dma_bridge_buggy;		/* Exported */
    
static void __devinit quirk_isa_dma_hangs(struct pci_dev *dev)
{
	if (!isa_dma_bridge_buggy) {
		isa_dma_bridge_buggy=1;
		printk(KERN_INFO "Activating ISA DMA hang workarounds.\n");
	}
}
	/*
	 * Its not totally clear which chipsets are the problematic ones
	 * We know 82C586 and 82C596 variants are affected.
	 */
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C586_0,	quirk_isa_dma_hangs );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C596,	quirk_isa_dma_hangs );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,    PCI_DEVICE_ID_INTEL_82371SB_0,  quirk_isa_dma_hangs );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_AL,	PCI_DEVICE_ID_AL_M1533, 	quirk_isa_dma_hangs );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_NEC,	PCI_DEVICE_ID_NEC_CBUS_1,	quirk_isa_dma_hangs );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_NEC,	PCI_DEVICE_ID_NEC_CBUS_2,	quirk_isa_dma_hangs );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_NEC,	PCI_DEVICE_ID_NEC_CBUS_3,	quirk_isa_dma_hangs );

int pci_pci_problems;

/*
 *	Chipsets where PCI->PCI transfers vanish or hang
 */
static void __devinit quirk_nopcipci(struct pci_dev *dev)
{
	if ((pci_pci_problems & PCIPCI_FAIL)==0) {
		printk(KERN_INFO "Disabling direct PCI/PCI transfers.\n");
		pci_pci_problems |= PCIPCI_FAIL;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_5597,		quirk_nopcipci );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_496,		quirk_nopcipci );

/*
 *	Triton requires workarounds to be used by the drivers
 */
static void __devinit quirk_triton(struct pci_dev *dev)
{
	if ((pci_pci_problems&PCIPCI_TRITON)==0) {
		printk(KERN_INFO "Limiting direct PCI/PCI transfers.\n");
		pci_pci_problems |= PCIPCI_TRITON;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, 	PCI_DEVICE_ID_INTEL_82437, 	quirk_triton ); 
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, 	PCI_DEVICE_ID_INTEL_82437VX, 	quirk_triton ); 
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, 	PCI_DEVICE_ID_INTEL_82439, 	quirk_triton ); 
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, 	PCI_DEVICE_ID_INTEL_82439TX, 	quirk_triton ); 

/*
 *	VIA Apollo KT133 needs PCI latency patch
 *	Made according to a windows driver based patch by George E. Breese
 *	see PCI Latency Adjust on http://www.viahardware.com/download/viatweak.shtm
 *      Also see http://www.au-ja.org/review-kt133a-1-en.phtml for
 *      the info on which Mr Breese based his work.
 *
 *	Updated based on further information from the site and also on
 *	information provided by VIA 
 */
static void __devinit quirk_vialatency(struct pci_dev *dev)
{
	struct pci_dev *p;
	u8 rev;
	u8 busarb;
	/* Ok we have a potential problem chipset here. Now see if we have
	   a buggy southbridge */
	   
	p = pci_find_device(PCI_VENDOR_ID_VIA, PCI_DEVICE_ID_VIA_82C686, NULL);
	if (p!=NULL) {
		pci_read_config_byte(p, PCI_CLASS_REVISION, &rev);
		/* 0x40 - 0x4f == 686B, 0x10 - 0x2f == 686A; thanks Dan Hollis */
		/* Check for buggy part revisions */
		if (rev < 0x40 || rev > 0x42) 
			return;
	} else {
		p = pci_find_device(PCI_VENDOR_ID_VIA, PCI_DEVICE_ID_VIA_8231, NULL);
		if (p==NULL)	/* No problem parts */
			return;
		pci_read_config_byte(p, PCI_CLASS_REVISION, &rev);
		/* Check for buggy part revisions */
		if (rev < 0x10 || rev > 0x12) 
			return;
	}
	
	/*
	 *	Ok we have the problem. Now set the PCI master grant to 
	 *	occur every master grant. The apparent bug is that under high
	 *	PCI load (quite common in Linux of course) you can get data
	 *	loss when the CPU is held off the bus for 3 bus master requests
	 *	This happens to include the IDE controllers....
	 *
	 *	VIA only apply this fix when an SB Live! is present but under
	 *	both Linux and Windows this isnt enough, and we have seen
	 *	corruption without SB Live! but with things like 3 UDMA IDE
	 *	controllers. So we ignore that bit of the VIA recommendation..
	 */

	pci_read_config_byte(dev, 0x76, &busarb);
	/* Set bit 4 and bi 5 of byte 76 to 0x01 
	   "Master priority rotation on every PCI master grant */
	busarb &= ~(1<<5);
	busarb |= (1<<4);
	pci_write_config_byte(dev, 0x76, busarb);
	printk(KERN_INFO "Applying VIA southbridge workaround.\n");
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_8363_0,	quirk_vialatency );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_8371_1,	quirk_vialatency );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_8361,		quirk_vialatency );

/*
 *	VIA Apollo VP3 needs ETBF on BT848/878
 */
static void __devinit quirk_viaetbf(struct pci_dev *dev)
{
	if ((pci_pci_problems&PCIPCI_VIAETBF)==0) {
		printk(KERN_INFO "Limiting direct PCI/PCI transfers.\n");
		pci_pci_problems |= PCIPCI_VIAETBF;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C597_0,	quirk_viaetbf );

static void __devinit quirk_vsfx(struct pci_dev *dev)
{
	if ((pci_pci_problems&PCIPCI_VSFX)==0) {
		printk(KERN_INFO "Limiting direct PCI/PCI transfers.\n");
		pci_pci_problems |= PCIPCI_VSFX;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C576,	quirk_vsfx );

/*
 *	Ali Magik requires workarounds to be used by the drivers
 *	that DMA to AGP space. Latency must be set to 0xA and triton
 *	workaround applied too
 *	[Info kindly provided by ALi]
 */	
static void __init quirk_alimagik(struct pci_dev *dev)
{
	if ((pci_pci_problems&PCIPCI_ALIMAGIK)==0) {
		printk(KERN_INFO "Limiting direct PCI/PCI transfers.\n");
		pci_pci_problems |= PCIPCI_ALIMAGIK|PCIPCI_TRITON;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_AL, 	PCI_DEVICE_ID_AL_M1647, 	quirk_alimagik );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_AL, 	PCI_DEVICE_ID_AL_M1651, 	quirk_alimagik );

/*
 *	Natoma has some interesting boundary conditions with Zoran stuff
 *	at least
 */
static void __devinit quirk_natoma(struct pci_dev *dev)
{
	if ((pci_pci_problems&PCIPCI_NATOMA)==0) {
		printk(KERN_INFO "Limiting direct PCI/PCI transfers.\n");
		pci_pci_problems |= PCIPCI_NATOMA;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, 	PCI_DEVICE_ID_INTEL_82441, 	quirk_natoma ); 
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, 	PCI_DEVICE_ID_INTEL_82443LX_0, 	quirk_natoma ); 
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, 	PCI_DEVICE_ID_INTEL_82443LX_1, 	quirk_natoma ); 
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, 	PCI_DEVICE_ID_INTEL_82443BX_0, 	quirk_natoma ); 
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, 	PCI_DEVICE_ID_INTEL_82443BX_1, 	quirk_natoma ); 
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL, 	PCI_DEVICE_ID_INTEL_82443BX_2, 	quirk_natoma );

/*
 *  This chip can cause PCI parity errors if config register 0xA0 is read
 *  while DMAs are occurring.
 */
static void __devinit quirk_citrine(struct pci_dev *dev)
{
	dev->cfg_size = 0xA0;
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_IBM,	PCI_DEVICE_ID_IBM_CITRINE,	quirk_citrine );

/*
 *  S3 868 and 968 chips report region size equal to 32M, but they decode 64M.
 *  If it's needed, re-allocate the region.
 */
static void __devinit quirk_s3_64M(struct pci_dev *dev)
{
	struct resource *r = &dev->resource[0];

	if ((r->start & 0x3ffffff) || r->end != r->start + 0x3ffffff) {
		r->start = 0;
		r->end = 0x3ffffff;
	}
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_S3,	PCI_DEVICE_ID_S3_868,		quirk_s3_64M );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_S3,	PCI_DEVICE_ID_S3_968,		quirk_s3_64M );

static void __devinit quirk_io_region(struct pci_dev *dev, unsigned region, unsigned size, int nr)
{
	region &= ~(size-1);
	if (region) {
		struct resource *res = dev->resource + nr;

		res->name = pci_name(dev);
		res->start = region;
		res->end = region + size - 1;
		res->flags = IORESOURCE_IO;
		pci_claim_resource(dev, nr);
	}
}	

/*
 *	ATI Northbridge setups MCE the processor if you even
 *	read somewhere between 0x3b0->0x3bb or read 0x3d3
 */
static void __devinit quirk_ati_exploding_mce(struct pci_dev *dev)
{
	printk(KERN_INFO "ATI Northbridge, reserving I/O ports 0x3b0 to 0x3bb.\n");
	/* Mae rhaid i ni beidio ag edrych ar y lleoliadiau I/O hyn */
	request_region(0x3b0, 0x0C, "RadeonIGP");
	request_region(0x3d3, 0x01, "RadeonIGP");
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_ATI,	PCI_DEVICE_ID_ATI_RS100,   quirk_ati_exploding_mce );

/*
 * Let's make the southbridge information explicit instead
 * of having to worry about people probing the ACPI areas,
 * for example.. (Yes, it happens, and if you read the wrong
 * ACPI register it will put the machine to sleep with no
 * way of waking it up again. Bummer).
 *
 * ALI M7101: Two IO regions pointed to by words at
 *	0xE0 (64 bytes of ACPI registers)
 *	0xE2 (32 bytes of SMB registers)
 */
static void __devinit quirk_ali7101_acpi(struct pci_dev *dev)
{
	u16 region;

	pci_read_config_word(dev, 0xE0, &region);
	quirk_io_region(dev, region, 64, PCI_BRIDGE_RESOURCES);
	pci_read_config_word(dev, 0xE2, &region);
	quirk_io_region(dev, region, 32, PCI_BRIDGE_RESOURCES+1);
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_AL,	PCI_DEVICE_ID_AL_M7101,		quirk_ali7101_acpi );

/*
 * PIIX4 ACPI: Two IO regions pointed to by longwords at
 *	0x40 (64 bytes of ACPI registers)
 *	0x90 (32 bytes of SMB registers)
 */
static void __devinit quirk_piix4_acpi(struct pci_dev *dev)
{
	u32 region;

	pci_read_config_dword(dev, 0x40, &region);
	quirk_io_region(dev, region, 64, PCI_BRIDGE_RESOURCES);
	pci_read_config_dword(dev, 0x90, &region);
	quirk_io_region(dev, region, 32, PCI_BRIDGE_RESOURCES+1);
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82371AB_3,	quirk_piix4_acpi );

/*
 * ICH4, ICH4-M, ICH5, ICH5-M ACPI: Three IO regions pointed to by longwords at
 *	0x40 (128 bytes of ACPI, GPIO & TCO registers)
 *	0x58 (64 bytes of GPIO I/O space)
 */
static void __devinit quirk_ich4_lpc_acpi(struct pci_dev *dev)
{
	u32 region;

	pci_read_config_dword(dev, 0x40, &region);
	quirk_io_region(dev, region, 128, PCI_BRIDGE_RESOURCES);

	pci_read_config_dword(dev, 0x58, &region);
	quirk_io_region(dev, region, 64, PCI_BRIDGE_RESOURCES+1);
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,    PCI_DEVICE_ID_INTEL_82801AA_0,		quirk_ich4_lpc_acpi );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,    PCI_DEVICE_ID_INTEL_82801AB_0,		quirk_ich4_lpc_acpi );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,    PCI_DEVICE_ID_INTEL_82801BA_0,		quirk_ich4_lpc_acpi );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,    PCI_DEVICE_ID_INTEL_82801BA_10,	quirk_ich4_lpc_acpi );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,    PCI_DEVICE_ID_INTEL_82801CA_0,		quirk_ich4_lpc_acpi );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,    PCI_DEVICE_ID_INTEL_82801CA_12,	quirk_ich4_lpc_acpi );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,    PCI_DEVICE_ID_INTEL_82801DB_0,		quirk_ich4_lpc_acpi );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,    PCI_DEVICE_ID_INTEL_82801DB_12,	quirk_ich4_lpc_acpi );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,    PCI_DEVICE_ID_INTEL_82801EB_0,		quirk_ich4_lpc_acpi );

/*
 * VIA ACPI: One IO region pointed to by longword at
 *	0x48 or 0x20 (256 bytes of ACPI registers)
 */
static void __devinit quirk_vt82c586_acpi(struct pci_dev *dev)
{
	u8 rev;
	u32 region;

	pci_read_config_byte(dev, PCI_CLASS_REVISION, &rev);
	if (rev & 0x10) {
		pci_read_config_dword(dev, 0x48, &region);
		region &= PCI_BASE_ADDRESS_IO_MASK;
		quirk_io_region(dev, region, 256, PCI_BRIDGE_RESOURCES);
	}
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C586_3,	quirk_vt82c586_acpi );

/*
 * VIA VT82C686 ACPI: Three IO region pointed to by (long)words at
 *	0x48 (256 bytes of ACPI registers)
 *	0x70 (128 bytes of hardware monitoring register)
 *	0x90 (16 bytes of SMB registers)
 */
static void __devinit quirk_vt82c686_acpi(struct pci_dev *dev)
{
	u16 hm;
	u32 smb;

	quirk_vt82c586_acpi(dev);

	pci_read_config_word(dev, 0x70, &hm);
	hm &= PCI_BASE_ADDRESS_IO_MASK;
	quirk_io_region(dev, hm, 128, PCI_BRIDGE_RESOURCES + 1);

	pci_read_config_dword(dev, 0x90, &smb);
	smb &= PCI_BASE_ADDRESS_IO_MASK;
	quirk_io_region(dev, smb, 16, PCI_BRIDGE_RESOURCES + 2);
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C686_4,	quirk_vt82c686_acpi );


#ifdef CONFIG_X86_IO_APIC 

#include <asm/io_apic.h>

/*
 * VIA 686A/B: If an IO-APIC is active, we need to route all on-chip
 * devices to the external APIC.
 *
 * TODO: When we have device-specific interrupt routers,
 * this code will go away from quirks.
 */
static void __devinit quirk_via_ioapic(struct pci_dev *dev)
{
	u8 tmp;
	
	if (nr_ioapics < 1)
		tmp = 0;    /* nothing routed to external APIC */
	else
		tmp = 0x1f; /* all known bits (4-0) routed to external APIC */
		
	printk(KERN_INFO "PCI: %sbling Via external APIC routing\n",
	       tmp == 0 ? "Disa" : "Ena");

	/* Offset 0x58: External APIC IRQ output control */
	pci_write_config_byte (dev, 0x58, tmp);
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C686,	quirk_via_ioapic );

/*
 * The AMD io apic can hang the box when an apic irq is masked.
 * We check all revs >= B0 (yet not in the pre production!) as the bug
 * is currently marked NoFix
 *
 * We have multiple reports of hangs with this chipset that went away with
 * noapic specified. For the moment we assume its the errata. We may be wrong
 * of course. However the advice is demonstrably good even if so..
 */
static void __devinit quirk_amd_ioapic(struct pci_dev *dev)
{
	u8 rev;

	pci_read_config_byte(dev, PCI_REVISION_ID, &rev);
	if (rev >= 0x02) {
		printk(KERN_WARNING "I/O APIC: AMD Errata #22 may be present. In the event of instability try\n");
		printk(KERN_WARNING "        : booting with the \"noapic\" option.\n");
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_AMD,	PCI_DEVICE_ID_AMD_VIPER_7410,	quirk_amd_ioapic );

static void __init quirk_ioapic_rmw(struct pci_dev *dev)
{
	if (dev->devfn == 0 && dev->bus->number == 0)
		sis_apic_bug = 1;
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_SI,	PCI_ANY_ID,			quirk_ioapic_rmw );

#define AMD8131_revA0        0x01
#define AMD8131_revB0        0x11
#define AMD8131_MISC         0x40
#define AMD8131_NIOAMODE_BIT 0
static void __init quirk_amd_8131_bridge(struct pci_dev *dev) 
{ 
        unsigned char revid, tmp;
        
        if (nr_ioapics == 0) 
                return;

        pci_read_config_byte(dev, PCI_REVISION_ID, &revid);
        if (revid == AMD8131_revA0 || revid == AMD8131_revB0) {
                printk(KERN_INFO "Fixing up AMD8131 IOAPIC mode\n"); 
                pci_read_config_byte( dev, AMD8131_MISC, &tmp);
                tmp &= ~(1 << AMD8131_NIOAMODE_BIT);
                pci_write_config_byte( dev, AMD8131_MISC, tmp);
        }
} 
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_8131_BRIDGE,         quirk_amd_8131_bridge ); 

#endif /* CONFIG_X86_IO_APIC */


/*
 * Via 686A/B:  The PCI_INTERRUPT_LINE register for the on-chip
 * devices, USB0/1, AC97, MC97, and ACPI, has an unusual feature:
 * when written, it makes an internal connection to the PIC.
 * For these devices, this register is defined to be 4 bits wide.
 * Normally this is fine.  However for IO-APIC motherboards, or
 * non-x86 architectures (yes Via exists on PPC among other places),
 * we must mask the PCI_INTERRUPT_LINE value versus 0xf to get
 * interrupts delivered properly.
 *
 * TODO: When we have device-specific interrupt routers,
 * quirk_via_irqpic will go away from quirks.
 */

/*
 * FIXME: it is questionable that quirk_via_acpi
 * is needed.  It shows up as an ISA bridge, and does not
 * support the PCI_INTERRUPT_LINE register at all.  Therefore
 * it seems like setting the pci_dev's 'irq' to the
 * value of the ACPI SCI interrupt is only done for convenience.
 *	-jgarzik
 */
static void __devinit quirk_via_acpi(struct pci_dev *d)
{
	/*
	 * VIA ACPI device: SCI IRQ line in PCI config byte 0x42
	 */
	u8 irq;
	pci_read_config_byte(d, 0x42, &irq);
	irq &= 0xf;
	if (irq && (irq != 2))
		d->irq = irq;
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C586_3,	quirk_via_acpi );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C686_4,	quirk_via_acpi );

static void quirk_via_irqpic(struct pci_dev *dev)
{
	u8 irq, new_irq = dev->irq & 0xf;

	pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &irq);

	if (new_irq != irq) {
		printk(KERN_INFO "PCI: Via IRQ fixup for %s, from %d to %d\n",
		       pci_name(dev), irq, new_irq);

		udelay(15);
		pci_write_config_byte(dev, PCI_INTERRUPT_LINE, new_irq);
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C586_2,	quirk_via_irqpic );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C686_5,	quirk_via_irqpic );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C686_6,	quirk_via_irqpic );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_8233_5,	quirk_via_irqpic );


/*
 * PIIX3 USB: We have to disable USB interrupts that are
 * hardwired to PIRQD# and may be shared with an
 * external device.
 *
 * Legacy Support Register (LEGSUP):
 *     bit13:  USB PIRQ Enable (USBPIRQDEN),
 *     bit4:   Trap/SMI On IRQ Enable (USBSMIEN).
 *
 * We mask out all r/wc bits, too.
 */
static void __devinit quirk_piix3_usb(struct pci_dev *dev)
{
	u16 legsup;

	pci_read_config_word(dev, 0xc0, &legsup);
	legsup &= 0x50ef;
	pci_write_config_word(dev, 0xc0, legsup);
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82371SB_2,	quirk_piix3_usb );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82371AB_2,	quirk_piix3_usb );

/*
 * VIA VT82C598 has its device ID settable and many BIOSes
 * set it to the ID of VT82C597 for backward compatibility.
 * We need to switch it off to be able to recognize the real
 * type of the chip.
 */
static void __devinit quirk_vt82c598_id(struct pci_dev *dev)
{
	pci_write_config_byte(dev, 0xfc, 0);
	pci_read_config_word(dev, PCI_DEVICE_ID, &dev->device);
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_VIA,	PCI_DEVICE_ID_VIA_82C597_0,	quirk_vt82c598_id );

/*
 * CardBus controllers have a legacy base address that enables them
 * to respond as i82365 pcmcia controllers.  We don't want them to
 * do this even if the Linux CardBus driver is not loaded, because
 * the Linux i82365 driver does not (and should not) handle CardBus.
 */
static void __devinit quirk_cardbus_legacy(struct pci_dev *dev)
{
	if ((PCI_CLASS_BRIDGE_CARDBUS << 8) ^ dev->class)
		return;
	pci_write_config_dword(dev, PCI_CB_LEGACY_MODE_BASE, 0);
}
DECLARE_PCI_FIXUP_FINAL(PCI_ANY_ID,		PCI_ANY_ID,			quirk_cardbus_legacy );

/*
 * Following the PCI ordering rules is optional on the AMD762. I'm not
 * sure what the designers were smoking but let's not inhale...
 *
 * To be fair to AMD, it follows the spec by default, its BIOS people
 * who turn it off!
 */
static void __devinit quirk_amd_ordering(struct pci_dev *dev)
{
	u32 pcic;
	pci_read_config_dword(dev, 0x4C, &pcic);
	if ((pcic&6)!=6) {
		pcic |= 6;
		printk(KERN_WARNING "BIOS failed to enable PCI standards compliance, fixing this error.\n");
		pci_write_config_dword(dev, 0x4C, pcic);
		pci_read_config_dword(dev, 0x84, &pcic);
		pcic |= (1<<23);	/* Required in this mode */
		pci_write_config_dword(dev, 0x84, pcic);
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_AMD,	PCI_DEVICE_ID_AMD_FE_GATE_700C, quirk_amd_ordering );

/*
 *	DreamWorks provided workaround for Dunord I-3000 problem
 *
 *	This card decodes and responds to addresses not apparently
 *	assigned to it. We force a larger allocation to ensure that
 *	nothing gets put too close to it.
 */
static void __devinit quirk_dunord ( struct pci_dev * dev )
{
	struct resource *r = &dev->resource [1];
	r->start = 0;
	r->end = 0xffffff;
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_DUNORD,	PCI_DEVICE_ID_DUNORD_I3000,	quirk_dunord );

/*
 * i82380FB mobile docking controller: its PCI-to-PCI bridge
 * is subtractive decoding (transparent), and does indicate this
 * in the ProgIf. Unfortunately, the ProgIf value is wrong - 0x80
 * instead of 0x01.
 */
static void __devinit quirk_transparent_bridge(struct pci_dev *dev)
{
	dev->transparent = 1;
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82380FB,	quirk_transparent_bridge );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_TOSHIBA,	0x605,	quirk_transparent_bridge );

/*
 * Common misconfiguration of the MediaGX/Geode PCI master that will
 * reduce PCI bandwidth from 70MB/s to 25MB/s.  See the GXM/GXLV/GX1
 * datasheets found at http://www.national.com/ds/GX for info on what
 * these bits do.  <christer@weinigel.se>
 */
static void __init quirk_mediagx_master(struct pci_dev *dev)
{
	u8 reg;
	pci_read_config_byte(dev, 0x41, &reg);
	if (reg & 2) {
		reg &= ~2;
		printk(KERN_INFO "PCI: Fixup for MediaGX/Geode Slave Disconnect Boundary (0x41=0x%02x)\n", reg);
                pci_write_config_byte(dev, 0x41, reg);
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_CYRIX,	PCI_DEVICE_ID_CYRIX_PCI_MASTER, quirk_mediagx_master );

static void __devinit quirk_sb600_sata(struct pci_dev *pdev)
{
	if ((pdev->class >> 8) == PCI_CLASS_STORAGE_IDE) {
		u8 tmp;

		pci_read_config_byte(pdev, 0x40, &tmp);
		pci_write_config_byte(pdev, 0x40, tmp|1);
		pci_write_config_byte(pdev, 0x9, 1);
		pci_write_config_byte(pdev, 0xa, 6);
		pci_write_config_byte(pdev, 0x40, tmp);

		pdev->class = PCI_CLASS_STORAGE_SATA_AHCI;
	}
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_ATI, PCI_DEVICE_ID_ATI_IXP600_SATA, quirk_sb600_sata);
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_ATI, PCI_DEVICE_ID_ATI_IXP700_SATA, quirk_sb600_sata);

/*
 * As per PCI spec, ignore base address registers 0-3 of the IDE controllers
 * running in Compatible mode (bits 0 and 2 in the ProgIf for primary and
 * secondary channels respectively). If the device reports Compatible mode
 * but does use BAR0-3 for address decoding, we assume that firmware has
 * programmed these BARs with standard values (0x1f0,0x3f4 and 0x170,0x374).
 * Exceptions (if they exist) must be handled in chip/architecture specific
 * fixups.
 *
 * Note: for non x86 people. You may need an arch specific quirk to handle
 * moving IDE devices to native mode as well. Some plug in card devices power
 * up in compatible mode and assume the BIOS will adjust them.
 *
 * Q: should we load the 0x1f0,0x3f4 into the registers or zap them as
 * we do now ? We don't want is pci_enable_device to come along
 * and assign new resources. Both approaches work for that.
 */ 
static void __devinit quirk_ide_bases(struct pci_dev *dev)
{
       struct resource *res;
       int first_bar = 2, last_bar = 0;

       if ((dev->class >> 8) != PCI_CLASS_STORAGE_IDE)
               return;

       res = &dev->resource[0];

       /* primary channel: ProgIf bit 0, BAR0, BAR1 */
       if (!(dev->class & 1) && (res[0].flags || res[1].flags)) { 
               res[0].start = res[0].end = res[0].flags = 0;
               res[1].start = res[1].end = res[1].flags = 0;
               first_bar = 0;
               last_bar = 1;
       }

       /* secondary channel: ProgIf bit 2, BAR2, BAR3 */
       if (!(dev->class & 4) && (res[2].flags || res[3].flags)) { 
               res[2].start = res[2].end = res[2].flags = 0;
               res[3].start = res[3].end = res[3].flags = 0;
               last_bar = 3;
       }

       if (!last_bar)
               return;

       printk(KERN_INFO "PCI: Ignoring BAR%d-%d of IDE controller %s\n",
              first_bar, last_bar, pci_name(dev));
}
DECLARE_PCI_FIXUP_HEADER(PCI_ANY_ID,             PCI_ANY_ID,                     quirk_ide_bases );

/*
 *	Ensure C0 rev restreaming is off. This is normally done by
 *	the BIOS but in the odd case it is not the results are corruption
 *	hence the presence of a Linux check
 */
static void __init quirk_disable_pxb(struct pci_dev *pdev)
{
	u16 config;
	u8 rev;
	
	pci_read_config_byte(pdev, PCI_REVISION_ID, &rev);
	if (rev != 0x04)		/* Only C0 requires this */
		return;
	pci_read_config_word(pdev, 0x40, &config);
	if (config & (1<<6)) {
		config &= ~(1<<6);
		pci_write_config_word(pdev, 0x40, config);
		printk(KERN_INFO "PCI: C0 revision 450NX. Disabling PCI restreaming.\n");
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82454NX,	quirk_disable_pxb );

/*
 *	VIA northbridges care about PCI_INTERRUPT_LINE
 */
int interrupt_line_quirk;

static void __devinit quirk_via_bridge(struct pci_dev *pdev)
{
	if(pdev->devfn == 0)
		interrupt_line_quirk = 1;
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_VIA,	PCI_ANY_ID,                     quirk_via_bridge );

/*
 *	Serverworks CSB5 IDE does not fully support native mode
 */
static void __devinit quirk_svwks_csb5ide(struct pci_dev *pdev)
{
	u8 prog;
	pci_read_config_byte(pdev, PCI_CLASS_PROG, &prog);
	if (prog & 5) {
		prog &= ~5;
		pdev->class &= ~5;
		pci_write_config_byte(pdev, PCI_CLASS_PROG, prog);
		/* need to re-assign BARs for compat mode */
		quirk_ide_bases(pdev);
	}
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SERVERWORKS, PCI_DEVICE_ID_SERVERWORKS_CSB5IDE, quirk_svwks_csb5ide );

/* This was originally an Alpha specific thing, but it really fits here.
 * The i82375 PCI/EISA bridge appears as non-classified. Fix that.
 */
static void __init quirk_eisa_bridge(struct pci_dev *dev)
{
	dev->class = PCI_CLASS_BRIDGE_EISA << 8;
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82375,	quirk_eisa_bridge );

/*
 * On ASUS P4B boards, the SMBus PCI Device within the ICH2/4 southbridge
 * is not activated. The myth is that Asus said that they do not want the
 * users to be irritated by just another PCI Device in the Win98 device
 * manager. (see the file prog/hotplug/README.p4b in the lm_sensors 
 * package 2.7.0 for details)
 *
 * The SMBus PCI Device can be activated by setting a bit in the ICH LPC 
 * bridge. Unfortunately, this device has no subvendor/subdevice ID. So it 
 * becomes necessary to do this tweak in two steps -- I've chosen the Host
 * bridge as trigger.
 */
static int __initdata asus_hides_smbus = 0;

static void __init asus_hides_smbus_hostbridge(struct pci_dev *dev)
{
	if (unlikely(dev->subsystem_vendor == PCI_VENDOR_ID_ASUSTEK)) {
		if (dev->device == PCI_DEVICE_ID_INTEL_82845_HB)
			switch(dev->subsystem_device) {
			case 0x8070: /* P4B */
			case 0x8088: /* P4B533 */
			case 0x1626: /* L3C notebook */
				asus_hides_smbus = 1;
			}
		if (dev->device == PCI_DEVICE_ID_INTEL_82845G_HB)
			switch(dev->subsystem_device) {
			case 0x80b1: /* P4GE-V */
			case 0x80b2: /* P4PE */
			case 0x8093: /* P4B533-V */
				asus_hides_smbus = 1;
			}
		if (dev->device == PCI_DEVICE_ID_INTEL_82850_HB)
			switch(dev->subsystem_device) {
			case 0x8030: /* P4T533 */
				asus_hides_smbus = 1;
			}
		if (dev->device == PCI_DEVICE_ID_INTEL_7205_0)
			switch (dev->subsystem_device) {
			case 0x8070: /* P4G8X Deluxe */
				asus_hides_smbus = 1;
			}
		if (dev->device == PCI_DEVICE_ID_INTEL_82855GM_HB)
			switch (dev->subsystem_device) {
			case 0x1751: /* M2N notebook */
				asus_hides_smbus = 1;
			}
	} else if (unlikely(dev->subsystem_vendor == PCI_VENDOR_ID_HP)) {
		if (dev->device ==  PCI_DEVICE_ID_INTEL_82855PM_HB)
			switch(dev->subsystem_device) {
			case 0x088C: /* HP Compaq nc8000 */
			case 0x0890: /* HP Compaq nc6000 */
				asus_hides_smbus = 1;
			}
		if (dev->device == PCI_DEVICE_ID_INTEL_82865_HB)
			switch (dev->subsystem_device) {
			case 0x12bc: /* HP D330L */
				asus_hides_smbus = 1;
			}
	}
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82845_HB,	asus_hides_smbus_hostbridge );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82845G_HB,	asus_hides_smbus_hostbridge );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82850_HB,	asus_hides_smbus_hostbridge );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82865_HB,	asus_hides_smbus_hostbridge );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_7205_0,	asus_hides_smbus_hostbridge );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82855PM_HB,	asus_hides_smbus_hostbridge );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82855GM_HB,	asus_hides_smbus_hostbridge );

static void __init asus_hides_smbus_lpc(struct pci_dev *dev)
{
	u16 val;
	
	if (likely(!asus_hides_smbus))
		return;

	pci_read_config_word(dev, 0xF2, &val);
	if (val & 0x8) {
		pci_write_config_word(dev, 0xF2, val & (~0x8));
		pci_read_config_word(dev, 0xF2, &val);
		if (val & 0x8)
			printk(KERN_INFO "PCI: i801 SMBus device continues to play 'hide and seek'! 0x%x\n", val);
		else
			printk(KERN_INFO "PCI: Enabled i801 SMBus device\n");
	}
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82801DB_0,	asus_hides_smbus_lpc );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82801BA_0,	asus_hides_smbus_lpc );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82801CA_12,	asus_hides_smbus_lpc );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82801DB_12,	asus_hides_smbus_lpc );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_82801EB_0,	asus_hides_smbus_lpc );

#if defined(CONFIG_X86_IO_APIC) && defined(CONFIG_SMP)
#include <asm/irq.h>

void __devinit quirk_intel_irqbalance(struct pci_dev *dev)
{
	u8 config, rev;
	u32 word;
	extern struct pci_raw_ops *raw_pci_ops;

	pci_read_config_byte(dev, PCI_CLASS_REVISION, &rev);
	if (rev > 0x9)
		return;

	printk(KERN_INFO "Intel E7520/7320/7525 detected.");

	/* enable access to config space*/
	pci_read_config_byte(dev, 0xf4, &config);
	config |= 0x2;
	pci_write_config_byte(dev, 0xf4, config);

	/* read xTPR register */
	raw_pci_ops->read(0, 0, 0x40, 0x4c, 2, &word);

	if (!(word & (1 << 13))) {
		printk(KERN_INFO "Disabling irq balancing and affinity\n");
#ifdef __i386__
#ifdef CONFIG_IRQBALANCE
		irqbalance_disable("");
#endif
		noirqdebug_setup("");
#endif
		no_irq_affinity = 1;
	}

	config &= ~0x2;
	/* disable access to config space*/
	pci_write_config_byte(dev, 0xf4, config);
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_E7520_MCH,	quirk_intel_irqbalance);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_E7320_MCH,	quirk_intel_irqbalance);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_E7525_MCH,	quirk_intel_irqbalance);
#endif

/*
 * SiS 96x south bridge: BIOS typically hides SMBus device...
 */
static void __init quirk_sis_96x_smbus(struct pci_dev *dev)
{
	u8 val = 0;
	printk(KERN_INFO "Enabling SiS 96x SMBus.\n");
	pci_read_config_byte(dev, 0x77, &val);
	pci_write_config_byte(dev, 0x77, val & ~0x10);
	pci_read_config_byte(dev, 0x77, &val);
}


#define UHCI_USBLEGSUP		0xc0		/* legacy support */
#define UHCI_USBCMD		0		/* command register */
#define UHCI_USBSTS		2		/* status register */
#define UHCI_USBINTR		4		/* interrupt register */
#define UHCI_USBLEGSUP_DEFAULT	0x2000		/* only PIRQ enable set */
#define UHCI_USBCMD_RUN		(1 << 0)	/* RUN/STOP bit */
#define UHCI_USBCMD_GRESET	(1 << 2)	/* Global reset */
#define UHCI_USBCMD_CONFIGURE	(1 << 6)	/* config semaphore */
#define UHCI_USBSTS_HALTED	(1 << 5)	/* HCHalted bit */

#define OHCI_CONTROL		0x04
#define OHCI_CMDSTATUS		0x08
#define OHCI_INTRSTATUS		0x0c
#define OHCI_INTRENABLE		0x10
#define OHCI_INTRDISABLE	0x14
#define OHCI_OCR		(1 << 3)	/* ownership change request */
#define OHCI_CTRL_IR		(1 << 8)	/* interrupt routing */
#define OHCI_INTR_OC		(1 << 30)	/* ownership change */

#define EHCI_HCC_PARAMS		0x08		/* extended capabilities */
#define EHCI_USBCMD		0		/* command register */
#define EHCI_USBCMD_RUN		(1 << 0)	/* RUN/STOP bit */
#define EHCI_USBSTS		4		/* status register */
#define EHCI_USBSTS_HALTED	(1 << 12)	/* HCHalted bit */
#define EHCI_USBINTR		8		/* interrupt register */
#define EHCI_USBLEGSUP		0		/* legacy support register */
#define EHCI_USBLEGSUP_BIOS	(1 << 16)	/* BIOS semaphore */
#define EHCI_USBLEGSUP_OS	(1 << 24)	/* OS semaphore */
#define EHCI_USBLEGCTLSTS	4		/* legacy control/status */
#define EHCI_USBLEGCTLSTS_SOOE	(1 << 13)	/* SMI on ownership change */

int __devinitdata usb_early_handoff = 0;
static int __init usb_handoff_early(char *str)
{
	usb_early_handoff = 1;
	return 0;
}
__setup("usb-handoff", usb_handoff_early);

static void __devinit quirk_usb_handoff_uhci(struct pci_dev *pdev)
{
	unsigned long base = 0;
	int wait_time, delta;
	u16 val, sts;
	int i;

	for (i = 0; i < PCI_ROM_RESOURCE; i++)
		if ((pci_resource_flags(pdev, i) & IORESOURCE_IO)) {
			base = pci_resource_start(pdev, i);
			break;
		}

	if (!base)
		return;

	/*
	 * stop controller
	 */
	sts = inw(base + UHCI_USBSTS);
	val = inw(base + UHCI_USBCMD);
	val &= ~(u16)(UHCI_USBCMD_RUN | UHCI_USBCMD_CONFIGURE);
	outw(val, base + UHCI_USBCMD);

	/*
	 * wait while it stops if it was running
	 */
	if ((sts & UHCI_USBSTS_HALTED) == 0)
	{
		wait_time = 1000;
		delta = 100;

		do {
			outw(0x1f, base + UHCI_USBSTS);
			udelay(delta);
			wait_time -= delta;
			val = inw(base + UHCI_USBSTS);
			if (val & UHCI_USBSTS_HALTED)
				break;
		} while (wait_time > 0);
	}

	/*
	 * disable interrupts & legacy support
	 */
	outw(0, base + UHCI_USBINTR);
	outw(0x1f, base + UHCI_USBSTS);
	pci_read_config_word(pdev, UHCI_USBLEGSUP, &val);
	if (val & 0xbf) 
		pci_write_config_word(pdev, UHCI_USBLEGSUP, UHCI_USBLEGSUP_DEFAULT);
		
}

static irqreturn_t __devinit quirk_usb_ohci_intr(int irq, void *arg, struct pt_regs *r)
{
	char *base = arg;

	/*
	 * In theory, just dropping MIE ought to be enough,
	 * but since we're here, pound with a sledgehammer (~0).
	 */
	writel(~0, base + OHCI_INTRDISABLE);
	writel(~0, base + OHCI_INTRSTATUS);

	return IRQ_HANDLED;
}

static void __devinit quirk_usb_handoff_ohci(struct pci_dev *pdev)
{
	void __iomem *base;
	int wait_time;
	int irq;

	base = ioremap_nocache(pci_resource_start(pdev, 0),
				     pci_resource_len(pdev, 0));
	if (base == NULL) return;

	/*
	 * Register a nuisance interrupt handler, but don't bail if failed.
	 * Chances are great we'll never need it.
	 */
	irq = pdev->irq;
	if (request_irq(irq, quirk_usb_ohci_intr, SA_SHIRQ, "ohci", base) != 0)
		irq = -1;

	if (readl(base + OHCI_CONTROL) & OHCI_CTRL_IR) {
		wait_time = 500; /* 0.5 seconds */
		writel(OHCI_INTR_OC, base + OHCI_INTRENABLE);
		writel(OHCI_OCR, base + OHCI_CMDSTATUS);
		while (wait_time > 0 && 
				readl(base + OHCI_CONTROL) & OHCI_CTRL_IR) {
			wait_time -= 10;
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout((HZ*10 + 999) / 1000);
		}
	}

	/*
	 * disable interrupts
	 */
	writel(~0, base + OHCI_INTRDISABLE);
	writel(~0, base + OHCI_INTRSTATUS);

	if (irq != -1)
		free_irq(irq, base);
	iounmap(base);
}

static void __devinit quirk_usb_disable_ehci(struct pci_dev *pdev)
{
	int wait_time, delta;
	void __iomem *base, *op_reg_base;
	u32 hcc_params, val, temp;
	u8 cap_length;

	base = ioremap_nocache(pci_resource_start(pdev, 0),
				pci_resource_len(pdev, 0));
	if (base == NULL) return;

	cap_length = readb(base);
	op_reg_base = base + cap_length;
	hcc_params = readl(base + EHCI_HCC_PARAMS);
	hcc_params = (hcc_params >> 8) & 0xff;
	if (hcc_params) {
		pci_read_config_dword(pdev, 
					hcc_params + EHCI_USBLEGSUP,
					&val);
		if (((val & 0xff) == 1) && (val & EHCI_USBLEGSUP_BIOS)) {
			/*
			 * Ok, BIOS is in smm mode, try to hand off...
			 */
			pci_read_config_dword(pdev,
						hcc_params + EHCI_USBLEGCTLSTS,
						&temp);
			pci_write_config_dword(pdev,
						hcc_params + EHCI_USBLEGCTLSTS,
						temp | EHCI_USBLEGCTLSTS_SOOE);
			val |= EHCI_USBLEGSUP_OS;
			pci_write_config_dword(pdev, 
						hcc_params + EHCI_USBLEGSUP, 
						val);

			wait_time = 500;
			do {
				set_current_state(TASK_UNINTERRUPTIBLE);
				schedule_timeout((HZ*10+999)/1000);
				wait_time -= 10;
				pci_read_config_dword(pdev,
						hcc_params + EHCI_USBLEGSUP,
						&val);
			} while (wait_time && (val & EHCI_USBLEGSUP_BIOS));
			if (!wait_time) {
				/*
				 * well, possibly buggy BIOS...
				 */
				printk(KERN_WARNING "EHCI early BIOS handoff "
						"failed (BIOS bug ?)\n");
				pci_write_config_dword(pdev,
						hcc_params + EHCI_USBLEGSUP,
						EHCI_USBLEGSUP_OS);
				pci_write_config_dword(pdev,
						hcc_params + EHCI_USBLEGCTLSTS,
						0);
			}
		}
	}

	/*
	 * halt EHCI & disable its interrupts in any case
	 */
	val = readl(op_reg_base + EHCI_USBSTS);
	if ((val & EHCI_USBSTS_HALTED) == 0) {
		val = readl(op_reg_base + EHCI_USBCMD);
		val &= ~EHCI_USBCMD_RUN;
		writel(val, op_reg_base + EHCI_USBCMD);

		wait_time = 2000;
		delta = 100;
		do {
			writel(0x3f, op_reg_base + EHCI_USBSTS);
			udelay(delta);
			wait_time -= delta;
			val = readl(op_reg_base + EHCI_USBSTS);
			if ((val == ~(u32)0) || (val & EHCI_USBSTS_HALTED)) {
				break;
			}
		} while (wait_time > 0);
	}
	writel(0, op_reg_base + EHCI_USBINTR);
	writel(0x3f, op_reg_base + EHCI_USBSTS);

	iounmap(base);

	return;
}

static void __devinit quirk_usb_early_handoff(struct pci_dev *pdev)
{
	if (!usb_early_handoff)
		return;

	if (pdev->class == ((PCI_CLASS_SERIAL_USB << 8) | 0x00)) { /* UHCI */
		quirk_usb_handoff_uhci(pdev);
	} else if (pdev->class == ((PCI_CLASS_SERIAL_USB << 8) | 0x10)) { /* OHCI */
		quirk_usb_handoff_ohci(pdev);
	} else if (pdev->class == ((PCI_CLASS_SERIAL_USB << 8) | 0x20)) { /* EHCI */
		quirk_usb_disable_ehci(pdev);
	}

	return;
}
DECLARE_PCI_FIXUP_HEADER(PCI_ANY_ID, PCI_ANY_ID, quirk_usb_early_handoff);

/*
 * ... This is further complicated by the fact that some SiS96x south
 * bridges pretend to be 85C503/5513 instead.  In that case see if we
 * spotted a compatible north bridge to make sure.
 * (pci_find_device doesn't work yet)
 *
 * We can also enable the sis96x bit in the discovery register..
 */
static int __devinitdata sis_96x_compatible = 0;

#define SIS_DETECT_REGISTER 0x40

static void __init quirk_sis_503(struct pci_dev *dev)
{
	u8 reg;
	u16 devid;

	pci_read_config_byte(dev, SIS_DETECT_REGISTER, &reg);
	pci_write_config_byte(dev, SIS_DETECT_REGISTER, reg | (1 << 6));
	pci_read_config_word(dev, PCI_DEVICE_ID, &devid);
	if (((devid & 0xfff0) != 0x0960) && (devid != 0x0018)) {
		pci_write_config_byte(dev, SIS_DETECT_REGISTER, reg);
		return;
	}

	/* Make people aware that we changed the config.. */
	printk(KERN_WARNING "Uncovering SIS%x that hid as a SIS503 (compatible=%d)\n", devid, sis_96x_compatible);

	/*
	 * Ok, it now shows up as a 96x.. The 96x quirks are after
	 * the 503 quirk in the quirk table, so they'll automatically
	 * run and enable things like the SMBus device
	 */
	dev->device = devid;
}

static void __init quirk_sis_96x_compatible(struct pci_dev *dev)
{
	sis_96x_compatible = 1;
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_645,		quirk_sis_96x_compatible );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_646,		quirk_sis_96x_compatible );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_648,		quirk_sis_96x_compatible );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_650,		quirk_sis_96x_compatible );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_651,		quirk_sis_96x_compatible );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_735,		quirk_sis_96x_compatible );

DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_503,		quirk_sis_503 );

DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_961,		quirk_sis_96x_smbus );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_962,		quirk_sis_96x_smbus );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_963,		quirk_sis_96x_smbus );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_SI,	PCI_DEVICE_ID_SI_LPC,		quirk_sis_96x_smbus );

#if defined(CONFIG_ATA) || defined(CONFIG_ATA_MODULE)

/*
 *	If we are using libata we can drive this chip properly but must
 *	do this early on to make the additional device appear during
 *	the PCI scanning.
 */

static void quirk_jmicron_ata(struct pci_dev *pdev)
{
	u32 conf1, conf5, class;
	u8 hdr;

	/* Only poke fn 0 */
	if (PCI_FUNC(pdev->devfn))
		return;

	pci_read_config_dword(pdev, 0x40, &conf1);
	pci_read_config_dword(pdev, 0x80, &conf5);

	conf1 &= ~0x00CFF302; /* Clear bit 1, 8, 9, 12-19, 22, 23 */
	conf5 &= ~(1 << 24);  /* Clear bit 24 */

	switch (pdev->device) {
	case PCI_DEVICE_ID_JMICRON_JMB360:
		/* The controller should be in single function ahci mode */
		conf1 |= 0x0002A100; /* Set 8, 13, 15, 17 */
		break;

	case PCI_DEVICE_ID_JMICRON_JMB365:
	case PCI_DEVICE_ID_JMICRON_JMB366:
		/* Redirect IDE second PATA port to the right spot */
		conf5 |= (1 << 24);
		/* Fall through */
	case PCI_DEVICE_ID_JMICRON_JMB361:
	case PCI_DEVICE_ID_JMICRON_JMB363:
		/* Enable dual function mode, AHCI on fn 0, IDE fn1 */
		/* Set the class codes correctly and then direct IDE 0 */
		conf1 |= 0x00C2A1B3; /* Set 0, 1, 4, 5, 7, 8, 13, 15, 17, 22, 23 */
		break;

	case PCI_DEVICE_ID_JMICRON_JMB368:
		/* The controller should be in single function IDE mode */
		conf1 |= 0x00C00000; /* Set 22, 23 */
		break;
	}

	pci_write_config_dword(pdev, 0x40, conf1);
	pci_write_config_dword(pdev, 0x80, conf5);

	/* Update pdev accordingly */
	pci_read_config_byte(pdev, PCI_HEADER_TYPE, &hdr);
	pdev->hdr_type = hdr & 0x7f;
	pdev->multifunction = !!(hdr & 0x80);

	pci_read_config_dword(pdev, PCI_CLASS_REVISION, &class);
	pdev->class = class >> 8;
}
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB360, quirk_jmicron_ata);
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB361, quirk_jmicron_ata);
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB363, quirk_jmicron_ata);
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB365, quirk_jmicron_ata);
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB366, quirk_jmicron_ata);
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB368, quirk_jmicron_ata);
/*
DECLARE_PCI_FIXUP_RESUME(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB360, quirk_jmicron_ata);
DECLARE_PCI_FIXUP_RESUME(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB361, quirk_jmicron_ata);
DECLARE_PCI_FIXUP_RESUME(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB363, quirk_jmicron_ata);
DECLARE_PCI_FIXUP_RESUME(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB365, quirk_jmicron_ata);
DECLARE_PCI_FIXUP_RESUME(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB366, quirk_jmicron_ata);
DECLARE_PCI_FIXUP_RESUME(PCI_VENDOR_ID_JMICRON, PCI_DEVICE_ID_JMICRON_JMB368, quirk_jmicron_ata);
*/
#endif

#ifdef CONFIG_X86_IO_APIC
static void __init quirk_alder_ioapic(struct pci_dev *pdev)
{
	int i;

	if ((pdev->class >> 8) != 0xff00)
		return;

	/* the first BAR is the location of the IO APIC...we must
	 * not touch this (and it's already covered by the fixmap), so
	 * forcibly insert it into the resource tree */
	if (pci_resource_start(pdev, 0) && pci_resource_len(pdev, 0))
		insert_resource(&iomem_resource, &pdev->resource[0]);

	/* The next five BARs all seem to be rubbish, so just clean
	 * them out */
	for (i=1; i < 6; i++) {
		memset(&pdev->resource[i], 0, sizeof(pdev->resource[i]));
	}

}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_EESSC,	quirk_alder_ioapic );
#endif

enum ide_combined_type { COMBINED = 0, IDE = 1, LIBATA = 2 };
/* Defaults to combined */
static enum ide_combined_type combined_mode;

static int __init combined_setup(char *str)
{
	if (!strncmp(str, "ide", 3))
		combined_mode = IDE;
	else if (!strncmp(str, "libata", 6))
		combined_mode = LIBATA;
	else /* "combined" or anything else defaults to old behavior */
		combined_mode = COMBINED;

	return 1;
}
__setup("combined_mode=", combined_setup);

#ifdef CONFIG_SATA_INTEL_COMBINED
static void __devinit quirk_intel_ide_combined(struct pci_dev *pdev)
{
	u8 prog, comb, tmp;
	int ich = 0;

	/*
	 * Narrow down to Intel SATA PCI devices.
	 */
	switch (pdev->device) {
	/* PCI ids taken from drivers/scsi/ata_piix.c */
	case 0x24d1:
	case 0x24df:
	case 0x25a3:
	case 0x25b0:
		ich = 5;
		break;
	case 0x2651:
	case 0x2652:
	case 0x2653:
	case 0x2680:	/* ESB2 */
		ich = 6;
		break;
	case 0x27c0:
	case 0x27c4:
		ich = 7;
		break;
	case 0x2828:	/* ICH8M */
		ich = 8;
		break;
	default:
		/* we do not handle this PCI device */
		return;
	}

	/*
	 * Read combined mode register.
	 */
	pci_read_config_byte(pdev, 0x90, &tmp);	/* combined mode reg */

	if (ich == 5) {
		tmp &= 0x6;  /* interesting bits 2:1, PATA primary/secondary */
		if (tmp == 0x4)		/* bits 10x */
			comb = (1 << 0);	/* SATA port 0, PATA port 1 */
		else if (tmp == 0x6)	/* bits 11x */
			comb = (1 << 2);	/* PATA port 0, SATA port 1 */
		else
			return;			/* not in combined mode */
	} else {
		WARN_ON((ich != 6) && (ich != 7) && (ich != 8));
		tmp &= 0x3;  /* interesting bits 1:0 */
		if (tmp & (1 << 0))
			comb = (1 << 2);	/* PATA port 0, SATA port 1 */
		else if (tmp & (1 << 1))
			comb = (1 << 0);	/* SATA port 0, PATA port 1 */
		else
			return;			/* not in combined mode */
	}

	/*
	 * Read programming interface register.
	 * (Tells us if it's legacy or native mode)
	 */
	pci_read_config_byte(pdev, PCI_CLASS_PROG, &prog);

	/* if SATA port is in native mode, we're ok. */
	if (prog & comb)
		return;

	/* Don't reserve any so the IDE driver can get them (but only if
	 * combined_mode=ide).
	 */
	if (combined_mode == IDE)
		return;

	/* Grab them both for libata if combined_mode=libata. */
	if (combined_mode == LIBATA) {
		request_region(0x1f0, 8, "libata");	/* port 0 */
		request_region(0x170, 8, "libata");	/* port 1 */
		return;
	}

	/* SATA port is in legacy mode.  Reserve port so that
	 * IDE driver does not attempt to use it.  If request_region
	 * fails, it will be obvious at boot time, so we don't bother
	 * checking return values.
	 */
	if (comb == (1 << 0))
		request_region(0x1f0, 8, "libata");	/* port 0 */
	else
		request_region(0x170, 8, "libata");	/* port 1 */
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,    PCI_ANY_ID,	  quirk_intel_ide_combined );
#endif /* CONFIG_SATA_INTEL_COMBINED */

int pcie_mch_quirk;

static void __devinit quirk_pcie_mch(struct pci_dev *pdev)
{
	pcie_mch_quirk = 1;
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_E7520_MCH,	quirk_pcie_mch );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_E7320_MCH,	quirk_pcie_mch );
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_E7525_MCH,	quirk_pcie_mch );

#ifdef CONFIG_PCI_MSI
/*
 * It's possible for the MSI to get corrupted if shpc and acpi
 * are used together on certain PXH-based systems.
 */
static void __devinit quirk_pcie_pxh(struct pci_dev *dev)
{
	disable_msi_mode(dev, pci_find_capability(dev, PCI_CAP_ID_MSI),
					PCI_CAP_ID_MSI);
	dev->no_msi = 1;

	printk(KERN_WARNING "PCI: PXH quirk detected, "
		"disabling MSI for SHPC device\n");
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_PXHD_0,
quirk_pcie_pxh);
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_PXHD_1,
quirk_pcie_pxh);
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_PXH_0,
quirk_pcie_pxh);
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_PXH_1,
quirk_pcie_pxh);
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_INTEL,	PCI_DEVICE_ID_INTEL_PXHV,
quirk_pcie_pxh);
#endif

/*
 * Some Intel PCI Express chipsets have trouble with downstream
 * device power management.
 */
static void quirk_intel_pcie_pm(struct pci_dev * dev)
{
	pci_pm_d3_delay = 120;
	dev->no_d1d2 = 1;
}

DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x25e2, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x25e3, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x25e4, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x25e5, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x25e6, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x25e7, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x25f7, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x25f8, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x25f9, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x25fa, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x2601, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x2602, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x2603, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x2604, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x2605, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x2606, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x2607, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x2608, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x2609, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x260a, quirk_intel_pcie_pm);
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_INTEL,	0x260b, quirk_intel_pcie_pm);

static void __init quirk_nforce_network_class(struct pci_dev *pdev)
{
	/* Some implementations of the nVidia network controllers
	 * show up as bridges, when we need to see them as network
	 * devices.
	 */

	/* If this is already known as a network ctlr, do nothing. */
	if ((pdev->class >> 8) == PCI_CLASS_NETWORK_ETHERNET)
		return;

	if ((pdev->class >> 8) == PCI_CLASS_BRIDGE_OTHER) {
		char    c;

		/* Clearing bit 6 of the register at 0xf8
		 * selects Ethernet device class
		 */
		pci_read_config_byte(pdev, 0xf8, &c);
		c &= 0xbf;
		pci_write_config_byte(pdev, 0xf8, c);

		/* sysfs needs pdev->class to be set correctly */
		pdev->class &= 0x0000ff;
		pdev->class |= (PCI_CLASS_NETWORK_ETHERNET << 8);
	}
}

DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_NVIDIA,	PCI_DEVICE_ID_NVIDIA_NVENET_6,	quirk_nforce_network_class );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_NVIDIA,	PCI_DEVICE_ID_NVIDIA_NVENET_7,	quirk_nforce_network_class );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_NVIDIA,	PCI_DEVICE_ID_NVIDIA_NVENET_8,	quirk_nforce_network_class );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_NVIDIA,	PCI_DEVICE_ID_NVIDIA_NVENET_9,	quirk_nforce_network_class );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_NVIDIA,	PCI_DEVICE_ID_NVIDIA_NVENET_10,	quirk_nforce_network_class );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_NVIDIA,	PCI_DEVICE_ID_NVIDIA_NVENET_11,	quirk_nforce_network_class );
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_NVIDIA, PCI_DEVICE_ID_NVIDIA_NVENET_15,  quirk_nforce_network_class);

/*
 *  The 53c875 operating registers are mapped to the upper 128 bytes of 
 *  PCI configuration space. If the SBDL (SCSI Bus Data Lines) registers
 *  are read by the processor instead of by SCRIPTS code on the controller
 *  parity errors will be generated.
 */
static void __devinit quirk_sym53c875(struct pci_dev *dev)
{
	dev->cfg_size = 0x80;
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_LSI_LOGIC,	PCI_DEVICE_ID_NCR_53C875,	quirk_sym53c875 );

static void pci_do_fixups(struct pci_dev *dev, struct pci_fixup *f, struct pci_fixup *end)
{
	while (f < end) {
		if ((f->vendor == dev->vendor || f->vendor == (u16) PCI_ANY_ID) &&
 		    (f->device == dev->device || f->device == (u16) PCI_ANY_ID)) {
			pr_debug(KERN_INFO "PCI: Calling quirk %p for %s\n", f->hook, pci_name(dev));
			f->hook(dev);
		}
		f++;
	}
}

extern struct pci_fixup __start_pci_fixups_early[];
extern struct pci_fixup __end_pci_fixups_early[];
extern struct pci_fixup __start_pci_fixups_header[];
extern struct pci_fixup __end_pci_fixups_header[];
extern struct pci_fixup __start_pci_fixups_final[];
extern struct pci_fixup __end_pci_fixups_final[];

void pci_fixup_device(enum pci_fixup_pass pass, struct pci_dev *dev)
{
	struct pci_fixup *start, *end;

	switch(pass) {
	case pci_fixup_early:
		start = __start_pci_fixups_early;
		end = __end_pci_fixups_early;
		break;

	case pci_fixup_header:
		start = __start_pci_fixups_header;
		end = __end_pci_fixups_header;
		break;

	case pci_fixup_final:
		start = __start_pci_fixups_final;
		end = __end_pci_fixups_final;
		break;
	default:
		/* stupid compiler warning, you would think with an enum... */
		return;
	}
	pci_do_fixups(dev, start, end);
}

#ifdef CONFIG_PCI_MSI
/* To disable MSI globally */
int pci_msi_quirk;

/* The Serverworks PCI-X chipset does not support MSI. We cannot easily rely
 * on setting PCI_BUS_FLAGS_NO_MSI in its bus flags because there are actually
 * some other busses controlled by the chipset even if Linux is not aware of it.
 * Instead of setting the flag on all busses in the machine, simply disable MSI
 * globally.
 */
static void __init quirk_svw_msi(struct pci_dev *dev)
{
	pci_msi_quirk = 1;
	printk(KERN_WARNING "PCI: MSI quirk detected. pci_msi_quirk set.\n");
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_SERVERWORKS, PCI_DEVICE_ID_SERVERWORKS_GCNB_LE, quirk_svw_msi);

/*
 * Some settings of MMRBC can lead to data corruption so block changes.
 * See AMD 8131 HyperTransport PCI-X Tunnel Revision Guide
 */
static void __init quirk_amd_8131_mmrbc(struct pci_dev *dev)
{
	unsigned char revid;

	pci_read_config_byte(dev, PCI_REVISION_ID, &revid);
	if (dev->subordinate && revid <= 0x12) {
		printk(KERN_INFO "AMD8131 rev %x detected, disabling PCI-X MMRBC\n",
			revid);
		dev->subordinate->pad2 |= PCI_BUS_FLAGS_NO_MMRBC;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_8131_BRIDGE, 
quirk_amd_8131_mmrbc);

/* Disable MSI on chipsets that are known to not support it */
static void __devinit quirk_disable_msi(struct pci_dev *dev)
{
	if (dev->subordinate) {
		printk(KERN_WARNING "PCI: MSI quirk detected. "
		       "PCI_BUS_FLAGS_NO_MSI set for %s subordinate bus.\n",
		       pci_name(dev));
		dev->subordinate->pad2 |= PCI_BUS_FLAGS_NO_MSI;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_AMD, PCI_DEVICE_ID_AMD_8131_BRIDGE, quirk_disable_msi);

/* Go through the list of Hypertransport capabilities and
 * return 1 if a HT MSI capability is found and enabled */
static int __devinit msi_ht_cap_enabled(struct pci_dev *dev)
{
	u8 pos;
	int ttl;
	for (pos = pci_find_capability(dev, PCI_CAP_ID_HT), ttl = 48;
	     pos && ttl;
	     pos = pci_find_next_capability(dev, pos, PCI_CAP_ID_HT), ttl--) {
		u32 cap_hdr;
		/* MSI mapping section according to Hypertransport spec */
		if (pci_read_config_dword(dev, pos, &cap_hdr) == 0
		    && (cap_hdr & 0xf8000000) == 0xa8000000 /* MSI mapping */) {
			printk(KERN_INFO "PCI: Found HT MSI mapping on %s with capability %s\n",
			       pci_name(dev), cap_hdr & 0x10000 ? "enabled" : "disabled");
			return (cap_hdr & 0x10000) != 0; /* MSI mapping cap enabled */
		}
	}
	return 0;
}

/* Check the hypertransport MSI mapping to know whether MSI is enabled or not */
static void __devinit quirk_msi_ht_cap(struct pci_dev *dev)
{
	if (dev->subordinate && !msi_ht_cap_enabled(dev)) {
		printk(KERN_WARNING "PCI: MSI quirk detected. "
		       "MSI disabled on chipset %s.\n",
		       pci_name(dev));
		dev->subordinate->pad2 |= PCI_BUS_FLAGS_NO_MSI;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_SERVERWORKS, PCI_DEVICE_ID_SERVERWORKS_HT2000_PCIE,
			quirk_msi_ht_cap);

/*
 * Force enable MSI mapping capability on HT bridges
 */
static void __devinit quirk_msi_ht_cap_enable(struct pci_dev *dev)
{
	u8 pos;
	int ttl;
	for (pos = pci_find_capability(dev, PCI_CAP_ID_HT), ttl = 48;
	     pos && ttl;
	     pos = pci_find_next_capability(dev, pos, PCI_CAP_ID_HT), ttl--) {
		u32 cap_hdr;
		/* MSI mapping section according to Hypertransport spec */
		if (pci_read_config_dword(dev, pos, &cap_hdr) == 0
		    && (cap_hdr & 0xf8000000) == 0xa8000000 /* MSI mapping */) {
			printk(KERN_INFO "PCI: Enabling HT MSI Mapping on %s\n",
			       pci_name(dev));

			pci_write_config_dword(dev, pos, cap_hdr | 0x10000);

		}
	}
}

DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_SERVERWORKS, PCI_DEVICE_ID_SERVERWORKS_HT1000_PXB,
			quirk_msi_ht_cap_enable);

/* The nVidia CK804 chipset may have 2 HT MSI mappings.
 * MSI are supported if the MSI capability set in any of these mappings.
 */
static void __devinit quirk_nvidia_ck804_msi_ht_cap(struct pci_dev *dev)
{
	struct pci_dev *pdev;

	if (!dev->subordinate)
		return;

	/* check HT MSI cap on this chipset and the root one.
	 * a single one having MSI is enough to be sure that MSI are supported.
	 */
	pdev = pci_find_slot(dev->bus->number, 0);
	if (dev->subordinate && !msi_ht_cap_enabled(dev)
	    && !msi_ht_cap_enabled(pdev)) {
		printk(KERN_WARNING "PCI: MSI quirk detected. "
		       "MSI disabled on chipset %s.\n",
		       pci_name(dev));
		dev->subordinate->pad2 |= PCI_BUS_FLAGS_NO_MSI;
	}
}
DECLARE_PCI_FIXUP_FINAL(PCI_VENDOR_ID_NVIDIA, PCI_DEVICE_ID_NVIDIA_CK804_PCIE,
			quirk_nvidia_ck804_msi_ht_cap);
#endif /* CONFIG_PCI_MSI */
  
EXPORT_SYMBOL(pcie_mch_quirk);
#ifdef CONFIG_HOTPLUG
EXPORT_SYMBOL(pci_fixup_device);
#endif

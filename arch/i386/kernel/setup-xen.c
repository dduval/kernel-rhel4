/*
 *  linux/arch/i386/kernel/setup.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *
 *  Memory region support
 *	David Parsons <orc@pell.chi.il.us>, July-August 1999
 *
 *  Added E820 sanitization routine (removes overlapping memory regions);
 *  Brian Moyle <bmoyle@mvista.com>, February 2001
 *
 * Moved CPU detection code to cpu/${cpu}.c
 *    Patrick Mochel <mochel@osdl.org>, March 2002
 *
 *  Provisions for empty E820 memory regions (reported by certain BIOSes).
 *  Alex Achenbach <xela@slit.de>, December 2002.
 *
 */

/*
 * This file handles the architecture-dependent parts of initialization
 */

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/ioport.h>
#include <linux/acpi.h>
#include <linux/apm_bios.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>
#include <linux/console.h>
#include <linux/root_dev.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/efi.h>
#include <linux/init.h>
#include <linux/edd.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <video/edid.h>
#include <asm/e820.h>
#include <asm/mpspec.h>
#include <asm/setup.h>
#include <asm/arch_hooks.h>
#include <asm/sections.h>
#include <asm/io_apic.h>
#include <asm/ist.h>
#include <asm/io.h>
#include <asm/hypervisor.h>
#include <xen/interface/physdev.h>
#include <xen/interface/memory.h>
#include <xen/features.h>
#include "setup_arch_pre.h"
#include <bios_ebda.h>

/* Allows setting of maximum possible memory size  */
static unsigned long xen_override_max_pfn;

static int xen_panic_event(struct notifier_block *, unsigned long, void *);
static struct notifier_block xen_panic_block = {
	xen_panic_event, NULL, 0 /* try to go last */
};

extern char hypercall_page[PAGE_SIZE];
EXPORT_SYMBOL(hypercall_page);

int disable_pse __initdata = 0;

/*
 * Machine setup..
 */

#ifdef CONFIG_EFI
int efi_enabled = 0;
EXPORT_SYMBOL(efi_enabled);
#endif

/* cpu data as detected by the assembly code in head.S */
struct cpuinfo_x86 new_cpu_data __initdata = { 0, 0, 0, 0, -1, 1, 0, 0, -1 };
/* common cpu data for all cpus */
struct cpuinfo_x86 boot_cpu_data = { 0, 0, 0, 0, -1, 1, 0, 0, -1 };

unsigned long mmu_cr4_features;
EXPORT_SYMBOL_GPL(mmu_cr4_features);

#ifdef	CONFIG_ACPI_INTERPRETER
	int acpi_disabled = 0;
#else
	int acpi_disabled = 1;
#endif
EXPORT_SYMBOL(acpi_disabled);

#ifdef	CONFIG_ACPI_BOOT
int __initdata acpi_force = 0;
extern acpi_interrupt_flags	acpi_sci_flags;
#endif

int MCA_bus;
/* for MCA, but anyone else can use it if they want */
unsigned int machine_id;
unsigned int machine_submodel_id;
unsigned int BIOS_revision;
unsigned int mca_pentium_flag;

/* For PCI or other memory-mapped resources */
unsigned long pci_mem_start = 0x10000000;

/* user-defined highmem size */
static unsigned int highmem_pages = -1;

/*
 * Setup options
 */
struct drive_info_struct { char dummy[32]; } drive_info;
struct screen_info screen_info;
struct apm_info apm_info;
struct sys_desc_table_struct {
	unsigned short length;
	unsigned char table[0];
};
struct edid_info edid_info;
struct ist_info ist_info;
struct e820map e820;

unsigned char aux_device_present;

extern void early_cpu_init(void);
extern void dmi_scan_machine(void);
extern void generic_apic_probe(char *);
extern int root_mountflags;

unsigned long saved_videomode;

#define RAMDISK_IMAGE_START_MASK  	0x07FF
#define RAMDISK_PROMPT_FLAG		0x8000
#define RAMDISK_LOAD_FLAG		0x4000	

static char command_line[COMMAND_LINE_SIZE];

unsigned char __initdata boot_params[PARAM_SIZE];

static struct resource data_resource = {
	.name	= "Kernel data",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

static struct resource code_resource = {
	.name	= "Kernel code",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
static struct resource system_rom_resource = {
	.name	= "System ROM",
	.start	= 0xf0000,
	.end	= 0xfffff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
};

static struct resource extension_rom_resource = {
	.name	= "Extension ROM",
	.start	= 0xe0000,
	.end	= 0xeffff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
};

static struct resource adapter_rom_resources[] = { {
	.name 	= "Adapter ROM",
	.start	= 0xc8000,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
}, {
	.name 	= "Adapter ROM",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
}, {
	.name 	= "Adapter ROM",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
}, {
	.name 	= "Adapter ROM",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
}, {
	.name 	= "Adapter ROM",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
}, {
	.name 	= "Adapter ROM",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
} };

#define ADAPTER_ROM_RESOURCES \
	(sizeof adapter_rom_resources / sizeof adapter_rom_resources[0])

static struct resource video_rom_resource = {
	.name 	= "Video ROM",
	.start	= 0xc0000,
	.end	= 0xc7fff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM
};
#endif

static struct resource video_ram_resource = {
	.name	= "Video RAM area",
	.start	= 0xa0000,
	.end	= 0xbffff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_MEM
};

static struct resource standard_io_resources[] = { {
	.name	= "dma1",
	.start	= 0x0000,
	.end	= 0x001f,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "pic1",
	.start	= 0x0020,
	.end	= 0x0021,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name   = "timer0",
	.start	= 0x0040,
	.end    = 0x0043,
	.flags  = IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name   = "timer1",
	.start  = 0x0050,
	.end    = 0x0053,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "keyboard",
	.start	= 0x0060,
	.end	= 0x006f,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "dma page reg",
	.start	= 0x0080,
	.end	= 0x008f,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "pic2",
	.start	= 0x00a0,
	.end	= 0x00a1,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "dma2",
	.start	= 0x00c0,
	.end	= 0x00df,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
}, {
	.name	= "fpu",
	.start	= 0x00f0,
	.end	= 0x00ff,
	.flags	= IORESOURCE_BUSY | IORESOURCE_IO
} };

#define STANDARD_IO_RESOURCES \
	(sizeof standard_io_resources / sizeof standard_io_resources[0])

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
#define romsignature(x) (*(unsigned short *)(x) == 0xaa55)

static int __init romchecksum(unsigned char *rom, unsigned long length)
{
	unsigned char *p, sum = 0;

	for (p = rom; p < rom + length; p++)
		sum += *p;
	return sum == 0;
}

static void __init probe_roms(void)
{
	unsigned long start, length, upper;
	unsigned char *rom;
	int	      i;

	/* Nothing to do if not running in dom0. */
	if (!(xen_start_info->flags & SIF_INITDOMAIN))
		return;

	/* video rom */
	upper = adapter_rom_resources[0].start;
	for (start = video_rom_resource.start; start < upper; start += 2048) {
		rom = isa_bus_to_virt(start);
		if (!romsignature(rom))
			continue;

		video_rom_resource.start = start;

		/* 0 < length <= 0x7f * 512, historically */
		length = rom[2] * 512;

		/* if checksum okay, trust length byte */
		if (length && romchecksum(rom, length))
			video_rom_resource.end = start + length - 1;

		request_resource(&iomem_resource, &video_rom_resource);
		break;
	}

	start = (video_rom_resource.end + 1 + 2047) & ~2047UL;
	if (start < upper)
		start = upper;

	/* system rom */
	request_resource(&iomem_resource, &system_rom_resource);
	upper = system_rom_resource.start;

	/* check for extension rom (ignore length byte!) */
	rom = isa_bus_to_virt(extension_rom_resource.start);
	if (romsignature(rom)) {
		length = extension_rom_resource.end - extension_rom_resource.start + 1;
		if (romchecksum(rom, length)) {
			request_resource(&iomem_resource, &extension_rom_resource);
			upper = extension_rom_resource.start;
		}
	}

	/* check for adapter roms on 2k boundaries */
	for (i = 0; i < ADAPTER_ROM_RESOURCES && start < upper; start += 2048) {
		rom = isa_bus_to_virt(start);
		if (!romsignature(rom))
			continue;

		/* 0 < length <= 0x7f * 512, historically */
		length = rom[2] * 512;

		/* but accept any length that fits if checksum okay */
		if (!length || start + length > upper || !romchecksum(rom, length))
			continue;

		adapter_rom_resources[i].start = start;
		adapter_rom_resources[i].end = start + length - 1;
		request_resource(&iomem_resource, &adapter_rom_resources[i]);

		start = adapter_rom_resources[i++].end & ~2047UL;
	}
}
#endif

/*
 * Point at the empty zero page to start with. We map the real shared_info
 * page as soon as fixmap is up and running.
 */
shared_info_t *HYPERVISOR_shared_info = (shared_info_t *)empty_zero_page;
EXPORT_SYMBOL(HYPERVISOR_shared_info);

unsigned long *phys_to_machine_mapping;
unsigned long *pfn_to_mfn_frame_list_list, *pfn_to_mfn_frame_list[16];
EXPORT_SYMBOL(phys_to_machine_mapping);

/* Raw start-of-day parameters from the hypervisor. */
start_info_t *xen_start_info;
EXPORT_SYMBOL(xen_start_info);

static void __init limit_regions(unsigned long long size)
{
	unsigned long long current_addr = 0;
	int i;

	if (efi_enabled) {
		for (i = 0; i < memmap.nr_map; i++) {
			current_addr = memmap.map[i].phys_addr +
				       (memmap.map[i].num_pages << 12);
			if (memmap.map[i].type == EFI_CONVENTIONAL_MEMORY) {
				if (current_addr >= size) {
					memmap.map[i].num_pages -=
						(((current_addr-size) + PAGE_SIZE-1) >> PAGE_SHIFT);
					memmap.nr_map = i + 1;
					return;
				}
			}
		}
	}
	for (i = 0; i < e820.nr_map; i++) {
		if (e820.map[i].type == E820_RAM) {
			current_addr = e820.map[i].addr + e820.map[i].size;
			if (current_addr >= size) {
				e820.map[i].size -= current_addr-size;
				e820.nr_map = i + 1;
				return;
			}
		}
	}
}

static void __init add_memory_region(unsigned long long start,
                                  unsigned long long size, int type)
{
	int x;
#ifndef CONFIG_X86_4G
	static int sillymemwarning = 0;
#endif

	if (!efi_enabled) {
       		x = e820.nr_map;

		if (x == E820MAX) {
		    printk(KERN_ERR "Ooops! Too many entries in the memory map!\n");
		    return;
		}

#ifndef CONFIG_X86_4G
		/*
		 * For kernels without 4G/4G split, printk a note
		 * pointing at the hugemem kernel from 16Gb onwards:
		 */
		if (start + size >= 0x400000000ULL && !sillymemwarning++) {
			printk("********************************************************\n");
			printk("* This system has more than 16 Gigabyte of memory.     *\n");
			printk("* It is recommended that you read the release notes    *\n");
			printk("* that accompany your copy of Red Hat Enterprise Linux *\n");
			printk("* about the recommended kernel for such configurations *\n");
			printk("********************************************************\n");		
		}
#endif

		e820.map[x].addr = start;
		e820.map[x].size = size;
		e820.map[x].type = type;
		e820.nr_map++;
	}
} /* add_memory_region */

#define E820_DEBUG	1

static void __init print_memory_map(char *who)
{
	int i;

	for (i = 0; i < e820.nr_map; i++) {
		printk(" %s: %016Lx - %016Lx ", who,
			e820.map[i].addr,
			e820.map[i].addr + e820.map[i].size);
		switch (e820.map[i].type) {
		case E820_RAM:	printk("(usable)\n");
				break;
		case E820_RESERVED:
				printk("(reserved)\n");
				break;
		case E820_ACPI:
				printk("(ACPI data)\n");
				break;
		case E820_NVS:
				printk("(ACPI NVS)\n");
				break;
		default:	printk("type %lu\n", e820.map[i].type);
				break;
		}
	}
}

#if 0
/*
 * Sanitize the BIOS e820 map.
 *
 * Some e820 responses include overlapping entries.  The following 
 * replaces the original e820 map with a new one, removing overlaps.
 *
 */
struct change_member {
	struct e820entry *pbios; /* pointer to original bios entry */
	unsigned long long addr; /* address for this change point */
};
struct change_member change_point_list[2*E820MAX] __initdata;
struct change_member *change_point[2*E820MAX] __initdata;
struct e820entry *overlap_list[E820MAX] __initdata;
struct e820entry new_bios[E820MAX] __initdata;

static int __init sanitize_e820_map(struct e820entry * biosmap, char * pnr_map)
{
	struct change_member *change_tmp;
	unsigned long current_type, last_type;
	unsigned long long last_addr;
	int chgidx, still_changing;
	int overlap_entries;
	int new_bios_entry;
	int old_nr, new_nr, chg_nr;
	int i;

	/*
		Visually we're performing the following (1,2,3,4 = memory types)...

		Sample memory map (w/overlaps):
		   ____22__________________
		   ______________________4_
		   ____1111________________
		   _44_____________________
		   11111111________________
		   ____________________33__
		   ___________44___________
		   __________33333_________
		   ______________22________
		   ___________________2222_
		   _________111111111______
		   _____________________11_
		   _________________4______

		Sanitized equivalent (no overlap):
		   1_______________________
		   _44_____________________
		   ___1____________________
		   ____22__________________
		   ______11________________
		   _________1______________
		   __________3_____________
		   ___________44___________
		   _____________33_________
		   _______________2________
		   ________________1_______
		   _________________4______
		   ___________________2____
		   ____________________33__
		   ______________________4_
	*/

	/* if there's only one memory region, don't bother */
	if (*pnr_map < 2)
		return -1;

	old_nr = *pnr_map;

	/* bail out if we find any unreasonable addresses in bios map */
	for (i=0; i<old_nr; i++)
		if (biosmap[i].addr + biosmap[i].size < biosmap[i].addr)
			return -1;

	/* create pointers for initial change-point information (for sorting) */
	for (i=0; i < 2*old_nr; i++)
		change_point[i] = &change_point_list[i];

	/* record all known change-points (starting and ending addresses),
	   omitting those that are for empty memory regions */
	chgidx = 0;
	for (i=0; i < old_nr; i++)	{
		if (biosmap[i].size != 0) {
			change_point[chgidx]->addr = biosmap[i].addr;
			change_point[chgidx++]->pbios = &biosmap[i];
			change_point[chgidx]->addr = biosmap[i].addr + biosmap[i].size;
			change_point[chgidx++]->pbios = &biosmap[i];
		}
	}
	chg_nr = chgidx;    	/* true number of change-points */

	/* sort change-point list by memory addresses (low -> high) */
	still_changing = 1;
	while (still_changing)	{
		still_changing = 0;
		for (i=1; i < chg_nr; i++)  {
			/* if <current_addr> > <last_addr>, swap */
			/* or, if current=<start_addr> & last=<end_addr>, swap */
			if ((change_point[i]->addr < change_point[i-1]->addr) ||
				((change_point[i]->addr == change_point[i-1]->addr) &&
				 (change_point[i]->addr == change_point[i]->pbios->addr) &&
				 (change_point[i-1]->addr != change_point[i-1]->pbios->addr))
			   )
			{
				change_tmp = change_point[i];
				change_point[i] = change_point[i-1];
				change_point[i-1] = change_tmp;
				still_changing=1;
			}
		}
	}

	/* create a new bios memory map, removing overlaps */
	overlap_entries=0;	 /* number of entries in the overlap table */
	new_bios_entry=0;	 /* index for creating new bios map entries */
	last_type = 0;		 /* start with undefined memory type */
	last_addr = 0;		 /* start with 0 as last starting address */
	/* loop through change-points, determining affect on the new bios map */
	for (chgidx=0; chgidx < chg_nr; chgidx++)
	{
		/* keep track of all overlapping bios entries */
		if (change_point[chgidx]->addr == change_point[chgidx]->pbios->addr)
		{
			/* add map entry to overlap list (> 1 entry implies an overlap) */
			overlap_list[overlap_entries++]=change_point[chgidx]->pbios;
		}
		else
		{
			/* remove entry from list (order independent, so swap with last) */
			for (i=0; i<overlap_entries; i++)
			{
				if (overlap_list[i] == change_point[chgidx]->pbios)
					overlap_list[i] = overlap_list[overlap_entries-1];
			}
			overlap_entries--;
		}
		/* if there are overlapping entries, decide which "type" to use */
		/* (larger value takes precedence -- 1=usable, 2,3,4,4+=unusable) */
		current_type = 0;
		for (i=0; i<overlap_entries; i++)
			if (overlap_list[i]->type > current_type)
				current_type = overlap_list[i]->type;
		/* continue building up new bios map based on this information */
		if (current_type != last_type)	{
			if (last_type != 0)	 {
				new_bios[new_bios_entry].size =
					change_point[chgidx]->addr - last_addr;
				/* move forward only if the new size was non-zero */
				if (new_bios[new_bios_entry].size != 0)
					if (++new_bios_entry >= E820MAX)
						break; 	/* no more space left for new bios entries */
			}
			if (current_type != 0)	{
				new_bios[new_bios_entry].addr = change_point[chgidx]->addr;
				new_bios[new_bios_entry].type = current_type;
				last_addr=change_point[chgidx]->addr;
			}
			last_type = current_type;
		}
	}
	new_nr = new_bios_entry;   /* retain count for new bios entries */

	/* copy new bios mapping into original location */
	memcpy(biosmap, new_bios, new_nr*sizeof(struct e820entry));
	*pnr_map = new_nr;

	return 0;
}

/*
 * Copy the BIOS e820 map into a safe place.
 *
 * Sanity-check it while we're at it..
 *
 * If we're lucky and live on a modern system, the setup code
 * will have given us a memory map that we can use to properly
 * set up memory.  If we aren't, we'll fake a memory map.
 *
 * We check to see that the memory map contains at least 2 elements
 * before we'll use it, because the detection code in setup.S may
 * not be perfect and most every PC known to man has two memory
 * regions: one from 0 to 640k, and one from 1mb up.  (The IBM
 * thinkpad 560x, for example, does not cooperate with the memory
 * detection code.)
 */
static int __init copy_e820_map(struct e820entry * biosmap, int nr_map)
{
	/* Only one memory region (or negative)? Ignore it */
	if (nr_map < 2)
		return -1;

	do {
		unsigned long long start = biosmap->addr;
		unsigned long long size = biosmap->size;
		unsigned long long end = start + size;
		unsigned long type = biosmap->type;

		/* Overflow in 64 bits? Ignore the memory map. */
		if (start > end)
			return -1;

		/*
		 * Some BIOSes claim RAM in the 640k - 1M region.
		 * Not right. Fix it up.
		 */
		if (type == E820_RAM) {
			if (start < 0x100000ULL && end > 0xA0000ULL) {
				if (start < 0xA0000ULL)
					add_memory_region(start, 0xA0000ULL-start, type);
				if (end <= 0x100000ULL)
					continue;
				start = 0x100000ULL;
				size = end - start;
			}
		}
		add_memory_region(start, size, type);
	} while (biosmap++,--nr_map);
	return 0;
}
#endif

#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
struct edd edd;
#ifdef CONFIG_EDD_MODULE
EXPORT_SYMBOL(edd);
#endif
/**
 * copy_edd() - Copy the BIOS EDD information
 *              from boot_params into a safe place.
 *
 */
static inline void copy_edd(void)
{
     memcpy(edd.mbr_signature, EDD_MBR_SIGNATURE, sizeof(edd.mbr_signature));
     memcpy(edd.edd_info, EDD_BUF, sizeof(edd.edd_info));
     edd.mbr_signature_nr = EDD_MBR_SIG_NR;
     edd.edd_info_nr = EDD_NR;
}
#else
static inline void copy_edd(void)
{
}
#endif

/*
 * Do NOT EVER look at the BIOS memory size location.
 * It does not work on many machines.
 */
#define LOWMEMSIZE()	(0x9f000)

static void __init parse_cmdline_early (char ** cmdline_p)
{
	char c = ' ', *to = command_line, *from = saved_command_line;
	int len = 0, max_cmdline;
	int userdef = 0;

	if ((max_cmdline = MAX_GUEST_CMDLINE) > COMMAND_LINE_SIZE)
		max_cmdline = COMMAND_LINE_SIZE;
	memcpy(saved_command_line, xen_start_info->cmd_line, max_cmdline);
	/* Save unparsed command line copy for /proc/cmdline */
	saved_command_line[max_cmdline-1] = '\0';

	for (;;) {
		if (c != ' ')
			goto next_char;
		/*
		 * "mem=nopentium" disables the 4MB page tables.
		 * "mem=XXX[kKmM]" defines a memory region from HIGH_MEM
		 * to <mem>, overriding the bios size.
		 * "memmap=XXX[KkmM]@XXX[KkmM]" defines a memory region from
		 * <start> to <start>+<mem>, overriding the bios size.
		 *
		 * HPA tells me bootloaders need to parse mem=, so no new
		 * option should be mem=  [also see Documentation/i386/boot.txt]
		 */
		if (!memcmp(from, "mem=", 4)) {
			if (to != command_line)
				to--;
			if (!memcmp(from+4, "nopentium", 9)) {
				from += 9+4;
				clear_bit(X86_FEATURE_PSE, boot_cpu_data.x86_capability);
				disable_pse = 1;
			} else {
				/* If the user specifies memory size, we
				 * limit the BIOS-provided memory map to
				 * that size. exactmap can be used to specify
				 * the exact map. mem=number can be used to
				 * trim the existing memory map.
				 */
				unsigned long long mem_size;
 
				mem_size = memparse(from+4, &from);
#ifndef CONFIG_XEN
				limit_regions(mem_size);
				userdef=1;
#else
				xen_override_max_pfn =
					(unsigned long)(mem_size>>PAGE_SHIFT);
#endif
			}
		}

		else if (!memcmp(from, "memmap=", 7)) {
			if (to != command_line)
				to--;
			if (!memcmp(from+7, "exactmap", 8)) {
				from += 8+7;
				e820.nr_map = 0;
				userdef = 1;
			} else {
				/* If the user specifies memory size, we
				 * limit the BIOS-provided memory map to
				 * that size. exactmap can be used to specify
				 * the exact map. mem=number can be used to
				 * trim the existing memory map.
				 */
				unsigned long long start_at, mem_size;
 
				mem_size = memparse(from+7, &from);
				if (*from == '@') {
					start_at = memparse(from+1, &from);
					add_memory_region(start_at, mem_size, E820_RAM);
				} else if (*from == '#') {
					start_at = memparse(from+1, &from);
					add_memory_region(start_at, mem_size, E820_ACPI);
				} else if (*from == '$') {
					start_at = memparse(from+1, &from);
					add_memory_region(start_at, mem_size, E820_RESERVED);
				} else {
					limit_regions(mem_size);
					userdef=1;
				}
			}
		}

#if defined(CONFIG_X86_SMP) && !defined(CONFIG_XEN)
		/*
		 * If the BIOS enumerates physical processors before logical,
		 * maxcpus=N at enumeration-time can be used to disable HT.
		 */
		else if (!memcmp(from, "maxcpus=", 8)) {
			extern unsigned int maxcpus;

			maxcpus = simple_strtoul(from + 8, NULL, 0);
		}
#endif

#ifdef CONFIG_ACPI_BOOT
		/* "acpi=off" disables both ACPI table parsing and interpreter */
		else if (!memcmp(from, "acpi=off", 8)) {
			disable_acpi();
		}

		/* acpi=force to over-ride black-list */
		else if (!memcmp(from, "acpi=force", 10)) {
			acpi_force = 1;
			acpi_ht = 1;
			acpi_disabled = 0;
		}

		/* acpi=strict disables out-of-spec workarounds */
		else if (!memcmp(from, "acpi=strict", 11)) {
			acpi_strict = 1;
		}

		/* Limit ACPI just to boot-time to enable HT */
		else if (!memcmp(from, "acpi=ht", 7)) {
			if (!acpi_force)
				disable_acpi();
			acpi_ht = 1;
		}
		
		/* "pci=noacpi" disable ACPI IRQ routing and PCI scan */
		else if (!memcmp(from, "pci=noacpi", 10)) {
			acpi_disable_pci();
		}
		/* "acpi=noirq" disables ACPI interrupt routing */
		else if (!memcmp(from, "acpi=noirq", 10)) {
			acpi_noirq_set();
		}

		else if (!memcmp(from, "acpi_sci=edge", 13))
			acpi_sci_flags.trigger =  1;

		else if (!memcmp(from, "acpi_sci=level", 14))
			acpi_sci_flags.trigger = 3;

		else if (!memcmp(from, "acpi_sci=high", 13))
			acpi_sci_flags.polarity = 1;

		else if (!memcmp(from, "acpi_sci=low", 12))
			acpi_sci_flags.polarity = 3;

#ifdef CONFIG_X86_IO_APIC
		else if (!memcmp(from, "acpi_skip_timer_override", 24))
			acpi_skip_timer_override = 1;
#endif

#ifdef CONFIG_X86_LOCAL_APIC
		/* disable IO-APIC */
		else if (!memcmp(from, "noapic", 6))
			disable_ioapic_setup();
#endif /* CONFIG_X86_LOCAL_APIC */
#endif /* CONFIG_ACPI_BOOT */

		/*
		 * highmem=size forces highmem to be exactly 'size' bytes.
		 * This works even on boxes that have no highmem otherwise.
		 * This also works to reduce highmem size on bigger boxes.
		 */
		else if (!memcmp(from, "highmem=", 8))
			highmem_pages = memparse(from+8, &from) >> PAGE_SHIFT;
	
		/*
		 * vmalloc=size forces the vmalloc area to be exactly 'size'
		 * bytes. This can be used to increase (or decrease) the
		 * vmalloc area - the default is 128m.
		 */
		else if (!memcmp(from, "vmalloc=", 8))
			__VMALLOC_RESERVE = memparse(from+8, &from);

	next_char:
		c = *(from++);
		if (!c)
			break;
		if (COMMAND_LINE_SIZE <= ++len)
			break;
		*(to++) = c;
	}
	*to = '\0';
	*cmdline_p = command_line;
	if (userdef) {
		printk(KERN_INFO "user-defined physical RAM map:\n");
		print_memory_map("user");
	}
}

#if 0 /* !XEN */
/*
 * Callback for efi_memory_walk.
 */
static int __init
efi_find_max_pfn(unsigned long start, unsigned long end, void *arg)
{
	unsigned long *max_pfn = arg, pfn;

	if (start < end) {
		pfn = PFN_UP(end -1);
		if (pfn > *max_pfn)
			*max_pfn = pfn;
	}
	return 0;
}


/*
 * Find the highest page frame number we have available
 */
void __init find_max_pfn(void)
{
	int i;

	max_pfn = 0;
	if (efi_enabled) {
		efi_memmap_walk(efi_find_max_pfn, &max_pfn);
		return;
	}

	for (i = 0; i < e820.nr_map; i++) {
		unsigned long start, end;
		/* RAM? */
		if (e820.map[i].type != E820_RAM)
			continue;
		start = PFN_UP(e820.map[i].addr);
		end = PFN_DOWN(e820.map[i].addr + e820.map[i].size);
		if (start >= end)
			continue;
		if (end > max_pfn)
			max_pfn = end;
	}
}
#else
/* We don't use the fake e820 because we need to respond to user override. */
void __init find_max_pfn(void)
{
	int rc;
	struct xen_memory_map memmap;
	/*
	 * This is rather large for a stack variable but this early in
	 * the boot process we know we have plenty slack space.
	 */
	struct e820entry map[E820MAX];

	memmap.nr_entries = E820MAX;
	set_xen_guest_handle(memmap.buffer, map);

	if (xen_override_max_pfn == 0) {
		rc = HYPERVISOR_memory_op(XENMEM_memory_map, &memmap);
		if ( rc == -ENOSYS ) {
			max_pfn = xen_start_info->nr_pages;
			/* Default 8MB slack (to balance backend allocations). */
			max_pfn += 8 << (20 - PAGE_SHIFT);
		} else {
			/* xenU guests get only one e820 region */
			max_pfn = map[0].size >> PAGE_SHIFT;
		}
	} else if (xen_override_max_pfn > xen_start_info->nr_pages) {
		max_pfn = xen_override_max_pfn;
	} else {
		max_pfn = xen_start_info->nr_pages;
	}
}
#endif /* XEN */

/*
 * Determine low and high memory ranges:
 */
unsigned long __init find_max_low_pfn(void)
{
	unsigned long max_low_pfn;

	max_low_pfn = max_pfn;
	if (max_low_pfn > MAXMEM_PFN) {
		if (highmem_pages == -1)
			highmem_pages = max_pfn - MAXMEM_PFN;
		if (highmem_pages + MAXMEM_PFN < max_pfn)
			max_pfn = MAXMEM_PFN + highmem_pages;
		if (highmem_pages + MAXMEM_PFN > max_pfn) {
			printk("only %luMB highmem pages available, ignoring highmem size of %uMB.\n", pages_to_mb(max_pfn - MAXMEM_PFN), pages_to_mb(highmem_pages));
			highmem_pages = 0;
		}
		max_low_pfn = MAXMEM_PFN;
#ifndef CONFIG_HIGHMEM
		/* Maximum memory usable is what is directly addressable */
		printk(KERN_WARNING "Warning only %ldMB will be used.\n",
					MAXMEM>>20);
		if (max_pfn > MAX_NONPAE_PFN)
			printk(KERN_WARNING "Use a PAE enabled kernel.\n");
		else
			printk(KERN_WARNING "Use a HIGHMEM enabled kernel.\n");
		max_pfn = MAXMEM_PFN;
#else /* !CONFIG_HIGHMEM */
#ifndef CONFIG_X86_PAE
		if (max_pfn > MAX_NONPAE_PFN) {
			max_pfn = MAX_NONPAE_PFN;
			printk(KERN_WARNING "Warning only 4GB will be used.\n");
			printk(KERN_WARNING "Use a PAE enabled kernel.\n");
		}
#endif /* !CONFIG_X86_PAE */
#endif /* !CONFIG_HIGHMEM */
	} else {
		if (highmem_pages == -1)
			highmem_pages = 0;
#ifdef CONFIG_HIGHMEM
		if (highmem_pages >= max_pfn) {
			printk(KERN_ERR "highmem size specified (%uMB) is bigger than pages available (%luMB)!.\n", pages_to_mb(highmem_pages), pages_to_mb(max_pfn));
			highmem_pages = 0;
		}
		if (highmem_pages) {
			if (max_low_pfn-highmem_pages < 64*1024*1024/PAGE_SIZE){
				printk(KERN_ERR "highmem size %uMB results in smaller than 64MB lowmem, ignoring it.\n", pages_to_mb(highmem_pages));
				highmem_pages = 0;
			}
			max_low_pfn -= highmem_pages;
		}
#else
		if (highmem_pages)
			printk(KERN_ERR "ignoring highmem size on non-highmem kernel!\n");
#endif
	}
	return max_low_pfn;
}

#ifndef CONFIG_DISCONTIGMEM

/*
 * Free all available memory for boot time allocation.  Used
 * as a callback function by efi_memory_walk()
 */

static int __init
free_available_memory(unsigned long start, unsigned long end, void *arg)
{
	/* check max_low_pfn */
	if (start >= ((max_low_pfn + 1) << PAGE_SHIFT))
		return 0;
	if (end >= ((max_low_pfn + 1) << PAGE_SHIFT))
		end = (max_low_pfn + 1) << PAGE_SHIFT;
	if (start < end)
		free_bootmem(start, end - start);

	return 0;
}
/*
 * Register fully available low RAM pages with the bootmem allocator.
 */
static void __init register_bootmem_low_pages(unsigned long max_low_pfn)
{
	int i;

	if (efi_enabled) {
		efi_memmap_walk(free_available_memory, NULL);
		return;
	}
	for (i = 0; i < e820.nr_map; i++) {
		unsigned long curr_pfn, last_pfn, size;
		/*
		 * Reserve usable low memory
		 */
		if (e820.map[i].type != E820_RAM)
			continue;
		/*
		 * We are rounding up the start address of usable memory:
		 */
		curr_pfn = PFN_UP(e820.map[i].addr);
		if (curr_pfn >= max_low_pfn)
			continue;
		/*
		 * ... and at the end of the usable range downwards:
		 */
		last_pfn = PFN_DOWN(e820.map[i].addr + e820.map[i].size);

		if (last_pfn > max_low_pfn)
			last_pfn = max_low_pfn;

		/*
		 * .. finally, did all the rounding and playing
		 * around just make the area go away?
		 */
		if (last_pfn <= curr_pfn)
			continue;

		size = last_pfn - curr_pfn;
		free_bootmem(PFN_PHYS(curr_pfn), PFN_PHYS(size));
	}
}

#ifndef CONFIG_XEN
/*
 * workaround for Dell systems that neglect to reserve EBDA
 */
static void __init reserve_ebda_region(void)
{
	unsigned int addr;
	addr = get_bios_ebda();
	if (addr)
		reserve_bootmem(addr, PAGE_SIZE);	
}
#endif

static unsigned long __init setup_memory(void)
{
	unsigned long bootmap_size, max_low_pfn;

	/*
	 * partially used pages are not usable - thus
	 * we are rounding upwards:
	 */
 	min_low_pfn = PFN_UP(__pa(xen_start_info->pt_base)) +
		xen_start_info->nr_pt_frames;

	find_max_pfn();

	max_low_pfn = find_max_low_pfn();

#ifdef CONFIG_HIGHMEM
	highstart_pfn = highend_pfn = max_pfn;
	if (max_pfn > max_low_pfn) {
		highstart_pfn = max_low_pfn;
	}
	printk(KERN_NOTICE "%ldMB HIGHMEM available.\n",
		pages_to_mb(highend_pfn - highstart_pfn));
#endif
	printk(KERN_NOTICE "%ldMB LOWMEM available.\n",
			pages_to_mb(max_low_pfn));
	/*
	 * Initialize the boot-time allocator (with low memory only):
	 */
	bootmap_size = init_bootmem(min_low_pfn, max_low_pfn);

	register_bootmem_low_pages(max_low_pfn);

	/*
	 * Reserve the bootmem bitmap itself as well. We do this in two
	 * steps (first step was init_bootmem()) because this catches
	 * the (very unlikely) case of us accidentally initializing the
	 * bootmem allocator with an invalid RAM area.
	 */
	reserve_bootmem(HIGH_MEMORY, (PFN_PHYS(min_low_pfn) +
			 bootmap_size + PAGE_SIZE-1) - (HIGH_MEMORY));

#ifndef CONFIG_XEN
	/*
	 * reserve physical page 0 - it's a special BIOS page on many boxes,
	 * enabling clean reboots, SMP operation, laptop functions.
	 */
	reserve_bootmem(0, PAGE_SIZE);

	/* reserve EBDA region, it's a 4K region */
	reserve_ebda_region();

    /* could be an AMD 768MPX chipset. Reserve a page  before VGA to prevent
       PCI prefetch into it (errata #56). Usually the page is reserved anyways,
       unless you have no PS/2 mouse plugged in. */
	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
	    boot_cpu_data.x86 == 6)
	     reserve_bootmem(0xa0000 - 4096, 4096);

#ifdef CONFIG_SMP
	/*
	 * But first pinch a few for the stack/trampoline stuff
	 * FIXME: Don't need the extra page at 4K, but need to fix
	 * trampoline before removing it. (see the GDT stuff)
	 */
	reserve_bootmem(PAGE_SIZE, PAGE_SIZE);
#endif
#ifdef CONFIG_ACPI_SLEEP
	/*
	 * Reserve low memory region for sleep support.
	 */
	acpi_reserve_bootmem();
#endif
#endif /* !CONFIG_XEN */
#ifdef CONFIG_X86_FIND_SMP_CONFIG
	/*
	 * Find and reserve possible boot-time SMP configuration:
	 */
	find_smp_config();
#endif

#ifdef CONFIG_BLK_DEV_INITRD
	if (xen_start_info->mod_start) {
		if (INITRD_START + INITRD_SIZE <= (max_low_pfn << PAGE_SHIFT)) {
			/*reserve_bootmem(INITRD_START, INITRD_SIZE);*/
			initrd_start = INITRD_START + PAGE_OFFSET;
			initrd_end = initrd_start+INITRD_SIZE;
			initrd_below_start_ok = 1;
		}
		else {
			printk(KERN_ERR "initrd extends beyond end of memory "
			    "(0x%08lx > 0x%08lx)\ndisabling initrd\n",
			    INITRD_START + INITRD_SIZE,
			    max_low_pfn << PAGE_SHIFT);
			initrd_start = 0;
		}
	}
#endif

	if (!xen_feature(XENFEAT_auto_translated_physmap))
		phys_to_machine_mapping =
			(unsigned long *)xen_start_info->mfn_list;

	return max_low_pfn;
}
#else
extern unsigned long setup_memory(void);
#endif /* !CONFIG_DISCONTIGMEM */

/*
 * Request address space for all standard RAM and ROM resources
 * and also for regions reported as reserved by the e820.
 */
static void __init
legacy_init_iomem_resources(struct resource *code_resource, struct resource *data_resource)
{
	int i;
#if 0
	dom0_op_t op;
	struct dom0_memory_map_entry *map;
	unsigned long gapstart, gapsize;
	unsigned long long last;
#endif

#ifdef CONFIG_XEN_PRIVILEGED_GUEST
	probe_roms();
#endif

#if 0
	map = alloc_bootmem_low_pages(PAGE_SIZE);
	op.cmd = DOM0_PHYSICAL_MEMORY_MAP;
	op.u.physical_memory_map.max_map_entries =
		PAGE_SIZE / sizeof(struct dom0_memory_map_entry);
	set_xen_guest_handle(op.u.physical_memory_map.memory_map, map);
	BUG_ON(HYPERVISOR_dom0_op(&op));

	last = 0x100000000ULL;
	gapstart = 0x10000000;
	gapsize = 0x400000;

	for (i = op.u.physical_memory_map.nr_map_entries - 1; i >= 0; i--) {
		struct resource *res;

		if ((last > map[i].end) && ((last - map[i].end) > gapsize)) {
			gapsize = last - map[i].end;
			gapstart = map[i].end;
		}
		if (map[i].start < last)
			last = map[i].start;

		if (map[i].end > 0x100000000ULL)
			continue;
		res = alloc_bootmem_low(sizeof(struct resource));
		res->name = map[i].is_ram ? "System RAM" : "reserved";
		res->start = map[i].start;
		res->end = map[i].end - 1;
		res->flags = IORESOURCE_MEM | IORESOURCE_BUSY;
		request_resource(&iomem_resource, res);
	}

	free_bootmem(__pa(map), PAGE_SIZE);

	/*
	 * Start allocating dynamic PCI memory a bit into the gap,
	 * aligned up to the nearest megabyte.
	 *
	 * Question: should we try to pad it up a bit (do something
	 * like " + (gapsize >> 3)" in there too?). We now have the
	 * technology.
	 */
	pci_mem_start = (gapstart + 0xfffff) & ~0xfffff;

	printk("Allocating PCI resources starting at %08lx (gap: %08lx:%08lx)\n",
		pci_mem_start, gapstart, gapsize);
#else
	for (i = 0; i < e820.nr_map; i++) {
		struct resource *res;
		if (e820.map[i].addr + e820.map[i].size > 0x100000000ULL)
			continue;
		res = alloc_bootmem_low(sizeof(struct resource));
		switch (e820.map[i].type) {
		case E820_RAM:	res->name = "System RAM"; break;
		case E820_ACPI:	res->name = "ACPI Tables"; break;
		case E820_NVS:	res->name = "ACPI Non-volatile Storage"; break;
		default:	res->name = "reserved";
		}
		res->start = e820.map[i].addr;
		res->end = res->start + e820.map[i].size - 1;
		res->flags = IORESOURCE_MEM | IORESOURCE_BUSY;
		request_resource(&iomem_resource, res);
		if (e820.map[i].type == E820_RAM) {
			/*
			 *  We don't know which RAM region contains kernel data,
			 *  so we try it repeatedly and let the resource manager
			 *  test it.
			 */
			request_resource(res, code_resource);
			request_resource(res, data_resource);
		}
	}
#endif
}

/*
 * Request address space for all standard resources
 */
static void __init register_memory(void)
{
	unsigned long low_mem_size;
	int	      i;

	/* Nothing to do if not running in dom0. */
	if (!(xen_start_info->flags & SIF_INITDOMAIN))
		return;

	if (efi_enabled)
		efi_initialize_iomem_resources(&code_resource, &data_resource);
	else
		legacy_init_iomem_resources(&code_resource, &data_resource);

	/* EFI systems may still have VGA */
	request_resource(&iomem_resource, &video_ram_resource);

	/* request I/O space for devices used on all i[345]86 PCs */
	for (i = 0; i < STANDARD_IO_RESOURCES; i++)
		request_resource(&ioport_resource, &standard_io_resources[i]);

	/* Tell the PCI layer not to allocate too close to the RAM area.. */
	low_mem_size = ((max_low_pfn << PAGE_SHIFT) + 0xfffff) & ~0xfffff;
	if (low_mem_size > pci_mem_start)
		pci_mem_start = low_mem_size;
}

/* Use inline assembly to define this because the nops are defined 
   as inline assembly strings in the include files and we cannot 
   get them easily into strings. */
asm("\t.data\nintelnops: " 
    GENERIC_NOP1 GENERIC_NOP2 GENERIC_NOP3 GENERIC_NOP4 GENERIC_NOP5 GENERIC_NOP6
    GENERIC_NOP7 GENERIC_NOP8); 
asm("\t.data\nk8nops: " 
    K8_NOP1 K8_NOP2 K8_NOP3 K8_NOP4 K8_NOP5 K8_NOP6
    K8_NOP7 K8_NOP8); 
asm("\t.data\nk7nops: " 
    K7_NOP1 K7_NOP2 K7_NOP3 K7_NOP4 K7_NOP5 K7_NOP6
    K7_NOP7 K7_NOP8); 
    
extern unsigned char intelnops[], k8nops[], k7nops[];
static unsigned char *intel_nops[ASM_NOP_MAX+1] = { 
     NULL,
     intelnops,
     intelnops + 1,
     intelnops + 1 + 2,
     intelnops + 1 + 2 + 3,
     intelnops + 1 + 2 + 3 + 4,
     intelnops + 1 + 2 + 3 + 4 + 5,
     intelnops + 1 + 2 + 3 + 4 + 5 + 6,
     intelnops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
}; 
static unsigned char *k8_nops[ASM_NOP_MAX+1] = { 
     NULL,
     k8nops,
     k8nops + 1,
     k8nops + 1 + 2,
     k8nops + 1 + 2 + 3,
     k8nops + 1 + 2 + 3 + 4,
     k8nops + 1 + 2 + 3 + 4 + 5,
     k8nops + 1 + 2 + 3 + 4 + 5 + 6,
     k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
}; 
static unsigned char *k7_nops[ASM_NOP_MAX+1] = { 
     NULL,
     k7nops,
     k7nops + 1,
     k7nops + 1 + 2,
     k7nops + 1 + 2 + 3,
     k7nops + 1 + 2 + 3 + 4,
     k7nops + 1 + 2 + 3 + 4 + 5,
     k7nops + 1 + 2 + 3 + 4 + 5 + 6,
     k7nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
}; 
static struct nop { 
     int cpuid; 
     unsigned char **noptable; 
} noptypes[] = { 
     { X86_FEATURE_K8, k8_nops }, 
     { X86_FEATURE_K7, k7_nops }, 
     { -1, NULL }
}; 

/* Replace instructions with better alternatives for this CPU type.

   This runs before SMP is initialized to avoid SMP problems with
   self modifying code. This implies that assymetric systems where
   APs have less capabilities than the boot processor are not handled. 
   In this case boot with "noreplacement". */ 
void apply_alternatives(void *start, void *end) 
{ 
	struct alt_instr *a; 
	int diff, i, k;
        unsigned char **noptable = intel_nops; 
	for (i = 0; noptypes[i].cpuid >= 0; i++) { 
		if (boot_cpu_has(noptypes[i].cpuid)) { 
			noptable = noptypes[i].noptable;
			break;
		}
	} 
	for (a = start; (void *)a < end; a++) { 
		if (!boot_cpu_has(a->cpuid))
			continue;
		BUG_ON(a->replacementlen > a->instrlen); 
		memcpy(a->instr, a->replacement, a->replacementlen); 
		diff = a->instrlen - a->replacementlen; 
		/* Pad the rest with nops */
		for (i = a->replacementlen; diff > 0; diff -= k, i += k) {
			k = diff;
			if (k > ASM_NOP_MAX)
				k = ASM_NOP_MAX;
			memcpy(a->instr + i, noptable[k], k); 
		} 
	}
} 

static int no_replacement __initdata = 0; 
 
void __init alternative_instructions(void)
{
	extern struct alt_instr __alt_instructions[], __alt_instructions_end[];
	if (no_replacement) 
		return;
	apply_alternatives(__alt_instructions, __alt_instructions_end);
}

static int __init noreplacement_setup(char *s)
{ 
     no_replacement = 1; 
     return 0; 
} 

__setup("noreplacement", noreplacement_setup); 

static char * __init machine_specific_memory_setup(void);

extern void zone_sizes_init(void);

/*
 * Determine if we were loaded by an EFI loader.  If so, then we have also been
 * passed the efi memmap, systab, etc., so we should use these data structures
 * for initialization.  Note, the efi init code path is determined by the
 * global efi_enabled. This allows the same kernel image to be used on existing
 * systems (with a traditional BIOS) as well as on EFI systems.
 */
void __init setup_arch(char **cmdline_p)
{
	int i, j, k, fpp;
	struct physdev_set_iopl set_iopl;
	unsigned long max_low_pfn;

	/* Force a quick death if the kernel panics (not domain 0). */
	extern int panic_timeout;
	if (!panic_timeout && !(xen_start_info->flags & SIF_INITDOMAIN))
		panic_timeout = 1;

	/* Register a call for panic conditions. */
	notifier_chain_register(&panic_notifier_list, &xen_panic_block);

	HYPERVISOR_vm_assist(VMASST_CMD_enable, VMASST_TYPE_4gb_segments);
	HYPERVISOR_vm_assist(VMASST_CMD_enable,
				VMASST_TYPE_writable_pagetables);

	memcpy(&boot_cpu_data, &new_cpu_data, sizeof(new_cpu_data));
	early_cpu_init();

	/*
	 * FIXME: This isn't an official loader_type right
	 * now but does currently work with elilo.
	 * If we were configured as an EFI kernel, check to make
	 * sure that we were loaded correctly from elilo and that
	 * the system table is valid.  If not, then initialize normally.
	 */
#ifdef CONFIG_EFI
	if ((LOADER_TYPE == 0x50) && EFI_SYSTAB)
		efi_enabled = 1;
#endif

	/* This must be initialized to UNNAMED_MAJOR for ipconfig to work
	   properly.  Setting ROOT_DEV to default to /dev/ram0 breaks initrd.
	*/
 	ROOT_DEV = MKDEV(UNNAMED_MAJOR,0);
 	drive_info = DRIVE_INFO;
 	screen_info = SCREEN_INFO;
	edid_info = EDID_INFO;
	apm_info.bios = APM_BIOS_INFO;
	ist_info = IST_INFO;
	saved_videomode = VIDEO_MODE;
	if( SYS_DESC_TABLE.length != 0 ) {
		MCA_bus = SYS_DESC_TABLE.table[3] &0x2;
		machine_id = SYS_DESC_TABLE.table[0];
		machine_submodel_id = SYS_DESC_TABLE.table[1];
		BIOS_revision = SYS_DESC_TABLE.table[2];
	}

	if (xen_start_info->flags & SIF_INITDOMAIN) {
	     /* This is drawn from a dump from vgacon:startup in
	      * standard Linux. */
	     screen_info.orig_video_mode = 3; 
	     screen_info.orig_video_isVGA = 1;
	     screen_info.orig_video_lines = 25;
	     screen_info.orig_video_cols = 80;
	     screen_info.orig_video_ega_bx = 3;
	     screen_info.orig_video_points = 16;
	}

#ifdef CONFIG_BLK_DEV_RAM
	rd_image_start = RAMDISK_FLAGS & RAMDISK_IMAGE_START_MASK;
	rd_prompt = ((RAMDISK_FLAGS & RAMDISK_PROMPT_FLAG) != 0);
	rd_doload = ((RAMDISK_FLAGS & RAMDISK_LOAD_FLAG) != 0);
#endif

	setup_xen_features();

	ARCH_SETUP
	if (efi_enabled)
		efi_init();
	else {
		printk(KERN_INFO "BIOS-provided physical RAM map:\n");
		print_memory_map(machine_specific_memory_setup());
	}

	copy_edd();

	if (!MOUNT_ROOT_RDONLY)
		root_mountflags &= ~MS_RDONLY;
	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code = (unsigned long) _etext;
	init_mm.end_data = (unsigned long) _edata;
	init_mm.brk = (PFN_UP(__pa(xen_start_info->pt_base)) +
			xen_start_info->nr_pt_frames) << PAGE_SHIFT;

	/* XEN: This is nonsense: kernel may not even be contiguous in RAM. */
	/* code_resource.start = virt_to_phys(_text); */
	/* code_resource.end = virt_to_phys(_etext)-1; */
	/* data_resource.start = virt_to_phys(_etext); */
	/* data_resource.end = virt_to_phys(_edata)-1; */

	parse_cmdline_early(cmdline_p);

	max_low_pfn = setup_memory();

	/*
	 * NOTE: before this point _nobody_ is allowed to allocate
	 * any memory using the bootmem allocator.  Although the
	 * alloctor is now initialised only the first 8Mb of the kernel
	 * virtual address space has been mapped.  All allocations before
	 * paging_init() has completed must use the alloc_bootmem_low_pages()
	 * variant (which allocates DMA'able memory) and care must be taken
	 * not to exceed the 8Mb limit.
	 */

#ifdef CONFIG_SMP
	smp_alloc_memory(); /* AP processor realmode stacks in low memory*/
#endif
	paging_init();

/*	remapped_pgdat_init(); XXXAP */

#if 0 /* def CONFIG_X86_FIND_SMP_CONFIG */
	/*
	 * Find and reserve possible boot-time SMP configuration:
	 */
	find_smp_config();
#endif

	/* Make sure we have a correctly sized P->M table. */
	if (!xen_feature(XENFEAT_auto_translated_physmap)) {
		phys_to_machine_mapping = alloc_bootmem_low_pages(
			max_pfn * sizeof(unsigned long));
		memset(phys_to_machine_mapping, ~0,
			max_pfn * sizeof(unsigned long));
		memcpy(phys_to_machine_mapping,
			(unsigned long *)xen_start_info->mfn_list,
			xen_start_info->nr_pages * sizeof(unsigned long));
		free_bootmem(
			__pa(xen_start_info->mfn_list),
			PFN_PHYS(PFN_UP(xen_start_info->nr_pages *
					sizeof(unsigned long))));

		/*
		 * Initialise the list of the frames that specify the list of
		 * frames that make up the p2m table. Used by save/restore
		 */
		pfn_to_mfn_frame_list_list = alloc_bootmem_low_pages(PAGE_SIZE);
		HYPERVISOR_shared_info->arch.pfn_to_mfn_frame_list_list =
			virt_to_mfn(pfn_to_mfn_frame_list_list);

		fpp = PAGE_SIZE/sizeof(unsigned long);
		for (i=0, j=0, k=-1; i< max_pfn; i+=fpp, j++) {
			if ((j % fpp) == 0) {
				k++;
				BUG_ON(k>=16);
				pfn_to_mfn_frame_list[k] =
					alloc_bootmem_low_pages(PAGE_SIZE);
				pfn_to_mfn_frame_list_list[k] =
					virt_to_mfn(pfn_to_mfn_frame_list[k]);
				j=0;
			}
			pfn_to_mfn_frame_list[k][j] =
				virt_to_mfn(&phys_to_machine_mapping[i]);
		}
		HYPERVISOR_shared_info->arch.max_pfn = max_pfn;
	}
	
	/*
	 * NOTE: at this point the bootmem allocator is fully available.
	 */

#ifdef CONFIG_EARLY_PRINTK
	{
		char *s = strstr(*cmdline_p, "earlyprintk=");
		if (s) {
			extern void setup_early_printk(char *);

			setup_early_printk(s);
			printk("early console enabled\n");
		}
	}
#endif

	if (xen_start_info->flags & SIF_INITDOMAIN)
		dmi_scan_machine();

#ifdef CONFIG_X86_GENERICARCH
	generic_apic_probe(*cmdline_p);
#endif	
	if (efi_enabled)
		efi_map_memmap();

	set_iopl.iopl = 1;
	HYPERVISOR_physdev_op(PHYSDEVOP_set_iopl, &set_iopl);

#ifdef CONFIG_ACPI_BOOT
	if (!(xen_start_info->flags & SIF_INITDOMAIN)) {
		printk(KERN_INFO "ACPI in unprivileged domain disabled\n");
		acpi_disabled = 1;
		acpi_ht = 0;
	}
#endif

#ifdef CONFIG_ACPI_BOOT
	/*
	 * Parse the ACPI tables for possible boot-time SMP configuration.
	 */
	acpi_boot_table_init();
	acpi_boot_init();
#endif

#ifdef CONFIG_X86_LOCAL_APIC
	if (smp_found_config)
		get_smp_config();
#endif

	/* XXX Disable irqdebug until we have a way to avoid interrupt
	 * conflicts. */
	noirqdebug_setup("");

	register_memory();

	if (xen_start_info->flags & SIF_INITDOMAIN) {
		if (!(xen_start_info->flags & SIF_PRIVILEGED))
			panic("Xen granted us console access "
			      "but not privileged status");

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	if (!efi_enabled || (efi_mem_type(0xa0000) != EFI_CONVENTIONAL_MEMORY))
		conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)
		conswitchp = &dummy_con;
#endif
#endif
	} else {
#if defined(CONFIG_VT) && defined(CONFIG_DUMMY_CONSOLE)
	        conswitchp = &dummy_con;
#endif
	}
}

static int
xen_panic_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	HYPERVISOR_shutdown(SHUTDOWN_crash);
	/* we're never actually going to get here... */
	return NOTIFY_DONE;
}

#include "setup_arch_post.h"
/*
 * Local Variables:
 * mode:c
 * c-file-style:"k&r"
 * c-basic-offset:8
 * End:
 */
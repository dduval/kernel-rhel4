/*
 *  linux/arch/x86-64/kernel/setup.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Nov 2001 Dave Jones <davej@suse.de>
 *  Forked from i386 setup code.
 *
 *  $Id$
 */

/*
 * This file handles the architecture-dependent parts of initialization
 */

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/user.h>
#include <linux/a.out.h>
#include <linux/tty.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/config.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/highmem.h>
#include <linux/bootmem.h>
#include <linux/module.h>
#include <asm/processor.h>
#include <linux/console.h>
#include <linux/seq_file.h>
#include <linux/root_dev.h>
#include <linux/pci.h>
#include <linux/acpi.h>
#include <linux/kallsyms.h>
#include <linux/edd.h>
#include <linux/notifier.h>
#include <linux/dmi.h>
#include <asm/mtrr.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/msr.h>
#include <asm/desc.h>
#include <video/edid.h>
#include <asm/e820.h>
#include <asm/dma.h>
#include <asm/mpspec.h>
#include <asm/mmu_context.h>
#include <asm/bootsetup.h>
#include <asm/smp.h>
#include <asm/proto.h>
#include <asm/setup.h>
#ifdef CONFIG_XEN
#include <linux/percpu.h>
#include <xen/interface/physdev.h>
#include "setup_arch_pre.h"
#include <asm/hypervisor.h>
#include <xen/interface/nmi.h>
#include <xen/features.h>
#define PFN_UP(x)       (((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define PFN_PHYS(x)     ((x) << PAGE_SHIFT)
#include <asm/mach-xen/setup_arch_post.h>

#include <xen/evtchn.h>
#include <xen/interface/io/console.h> /* P3 */

#ifdef CONFIG_DISCONTIGMEM
void __init free_bootmem (unsigned long addr, unsigned long size)
{
	printk("free_bootmem: losing 0x%lx[0x%lx]\n", addr, size);
}
#endif

extern unsigned long start_pfn;
extern struct edid_info edid_info;

shared_info_t *HYPERVISOR_shared_info = (shared_info_t *)empty_zero_page;
EXPORT_SYMBOL(HYPERVISOR_shared_info);

extern char hypercall_page[PAGE_SIZE];
EXPORT_SYMBOL(hypercall_page);

/* Allows setting of maximum possible memory size  */
unsigned long xen_override_max_pfn;

static int xen_panic_event(struct notifier_block *, unsigned long, void *);
static struct notifier_block xen_panic_block = {
	xen_panic_event, NULL, 0 /* try to go last */
};

unsigned long *phys_to_machine_mapping;
unsigned long *pfn_to_mfn_frame_list_list, *pfn_to_mfn_frame_list[512];

EXPORT_SYMBOL(phys_to_machine_mapping);

DEFINE_PER_CPU(multicall_entry_t, multicall_list[8]);
DEFINE_PER_CPU(int, nr_multicall_ents);

/* Raw start-of-day parameters from the hypervisor. */
start_info_t *xen_start_info;
EXPORT_SYMBOL(xen_start_info);
#endif

/*
 * Machine setup..
 */

struct cpuinfo_x86 boot_cpu_data;

unsigned long mmu_cr4_features;
EXPORT_SYMBOL_GPL(mmu_cr4_features);

int acpi_disabled;
EXPORT_SYMBOL(acpi_disabled);
#ifdef	CONFIG_ACPI_BOOT
extern int __initdata acpi_ht;
extern acpi_interrupt_flags	acpi_sci_flags;
int __initdata acpi_force = 0;
#endif

#ifdef CONFIG_NUMA
extern int acpi_numa;
extern int __initdata numa_off;
#endif

int sibling_ht_mask = 0;
int disable_x86_ht;

/* For PCI or other memory-mapped resources */
unsigned long pci_mem_start = 0x10000000;

unsigned long saved_video_mode;

#ifdef CONFIG_SWIOTLB
int swiotlb;
EXPORT_SYMBOL(swiotlb);
#endif

/*
 * Setup options
 */
struct drive_info_struct { char dummy[32]; } drive_info;
struct screen_info screen_info;
struct sys_desc_table_struct {
	unsigned short length;
	unsigned char table[0];
};

struct edid_info edid_info;
struct e820map e820;

unsigned char aux_device_present;

extern int root_mountflags;
extern char _text, _etext, _edata, _end;

char command_line[COMMAND_LINE_SIZE];

struct resource standard_io_resources[] = {
	{ "dma1", 0x00, 0x1f, IORESOURCE_BUSY | IORESOURCE_IO },
	{ "pic1", 0x20, 0x21, IORESOURCE_BUSY | IORESOURCE_IO },
	{ "timer0", 0x40, 0x43, IORESOURCE_BUSY | IORESOURCE_IO },
	{ "timer1", 0x50, 0x53, IORESOURCE_BUSY | IORESOURCE_IO },
	{ "keyboard", 0x60, 0x6f, IORESOURCE_BUSY | IORESOURCE_IO },
	{ "dma page reg", 0x80, 0x8f, IORESOURCE_BUSY | IORESOURCE_IO },
	{ "pic2", 0xa0, 0xa1, IORESOURCE_BUSY | IORESOURCE_IO },
	{ "dma2", 0xc0, 0xdf, IORESOURCE_BUSY | IORESOURCE_IO },
	{ "fpu", 0xf0, 0xff, IORESOURCE_BUSY | IORESOURCE_IO }
};

#define STANDARD_IO_RESOURCES \
	(sizeof standard_io_resources / sizeof standard_io_resources[0])

#define IORESOURCE_RAM (IORESOURCE_BUSY | IORESOURCE_MEM)

struct resource data_resource = { "Kernel data", 0, 0, IORESOURCE_RAM };
struct resource code_resource = { "Kernel code", 0, 0, IORESOURCE_RAM };

#define IORESOURCE_ROM (IORESOURCE_BUSY | IORESOURCE_READONLY | IORESOURCE_MEM)

#if defined(CONFIG_XEN_PRIVILEGED_GUEST) || !defined(CONFIG_XEN)
static struct resource system_rom_resource = { "System ROM", 0xf0000, 0xfffff, IORESOURCE_ROM };
static struct resource extension_rom_resource = { "Extension ROM", 0xe0000, 0xeffff, IORESOURCE_ROM };

static struct resource adapter_rom_resources[] = {
	{ "Adapter ROM", 0xc8000, 0, IORESOURCE_ROM },
	{ "Adapter ROM", 0, 0, IORESOURCE_ROM },
	{ "Adapter ROM", 0, 0, IORESOURCE_ROM },
	{ "Adapter ROM", 0, 0, IORESOURCE_ROM },
	{ "Adapter ROM", 0, 0, IORESOURCE_ROM },
	{ "Adapter ROM", 0, 0, IORESOURCE_ROM }
};
#endif

#define ADAPTER_ROM_RESOURCES \
	(sizeof adapter_rom_resources / sizeof adapter_rom_resources[0])

#if defined(CONFIG_XEN_PRIVILEGED_GUEST) || !defined(CONFIG_XEN)
static struct resource video_rom_resource = { "Video ROM", 0xc0000, 0xc7fff, IORESOURCE_ROM };
#endif
static struct resource video_ram_resource = { "Video RAM area", 0xa0000, 0xbffff, IORESOURCE_RAM };

#if defined(CONFIG_XEN_PRIVILEGED_GUEST) || !defined(CONFIG_XEN)
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

static __init void parse_cmdline_early (char ** cmdline_p)
{
	char c = ' ', *to = command_line, *from = COMMAND_LINE;
	int len = 0;

	/* Save unparsed command line copy for /proc/cmdline */
	memcpy(saved_command_line, COMMAND_LINE, COMMAND_LINE_SIZE);
	saved_command_line[COMMAND_LINE_SIZE-1] = '\0';

	for (;;) {
		if (c != ' ') 
			goto next_char; 

#ifdef CONFIG_SMP
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
		/* "acpi=off" disables both ACPI table parsing and interpreter init */
		if (!memcmp(from, "acpi=off", 8))
			disable_acpi();

		if (!memcmp(from, "acpi=force", 10)) { 
			/* add later when we do DMI horrors: */
			acpi_force = 1;
			acpi_disabled = 0;
		}

		/* acpi=ht just means: do ACPI MADT parsing 
		   at bootup, but don't enable the full ACPI interpreter */
		if (!memcmp(from, "acpi=ht", 7)) { 
			if (!acpi_force)
				disable_acpi();
			acpi_ht = 1; 
		}
                else if (!memcmp(from, "pci=noacpi", 10)) 
			acpi_disable_pci();
		else if (!memcmp(from, "acpi=noirq", 10))
			acpi_noirq_set();

		else if (!memcmp(from, "acpi_sci=edge", 13))
			acpi_sci_flags.trigger =  1;
		else if (!memcmp(from, "acpi_sci=level", 14))
			acpi_sci_flags.trigger = 3;
		else if (!memcmp(from, "acpi_sci=high", 13))
			acpi_sci_flags.polarity = 1;
		else if (!memcmp(from, "acpi_sci=low", 12))
			acpi_sci_flags.polarity = 3;

		/* acpi=strict disables out-of-spec workarounds */
		else if (!memcmp(from, "acpi=strict", 11)) {
			acpi_strict = 1;
		}
#endif

#ifndef CONFIG_XEN
		if (!memcmp(from, "nolapic", 7) ||
		    !memcmp(from, "disableapic", 11))
			disable_apic = 1;

		if (!memcmp(from, "noapic", 6)) 
			skip_ioapic_setup = 1;

		if (!memcmp(from, "apic", 4)) { 
			skip_ioapic_setup = 0;
			ioapic_force = 1;
		}
#endif
			
		if (!memcmp(from, "mem=", 4))
			parse_memopt(from+4, &from); 

#ifdef CONFIG_DISCONTIGMEM
		if (!memcmp(from, "numa=", 5))
			numa_setup(from+5); 
#endif

#ifdef CONFIG_GART_IOMMU 
		if (!memcmp(from,"iommu=",6)) { 
			iommu_setup(from+6); 
		}
#endif

		if (!memcmp(from,"oops=panic", 10))
			panic_on_oops = 1;

#ifdef CONFIG_NUMA
		if (!memcmp(from,"numa=off", 8))
			numa_off = 1;
		if (!memcmp(from,"numa=on", 7))
			numa_off = 0;
#endif
#ifdef CONFIG_X86_HT
		/* "noht" disables hyperthreading by only recognizing
		 * the first CPU of a sibling set
		 */
		if (!memcmp(from, "noht", 4)) {
			extern int disable_x86_ht;
			disable_x86_ht = 1;
		}
#endif

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
}

#ifndef CONFIG_DISCONTIGMEM
#ifdef CONFIG_XEN
static void __init
contig_initmem_init(unsigned long start_pfn, unsigned long end_pfn)
{
	unsigned long bootmap_size;

	bootmap_size = init_bootmem(start_pfn, end_pfn);
	free_bootmem(0, xen_start_info->nr_pages << PAGE_SHIFT);
	reserve_bootmem(HIGH_MEMORY,
			(PFN_PHYS(start_pfn) + bootmap_size + PAGE_SIZE-1)
			- HIGH_MEMORY);
}
#else
static void __init contig_initmem_init(void)
{
        unsigned long bootmap_size, bootmap; 
        bootmap_size = bootmem_bootmap_pages(end_pfn)<<PAGE_SHIFT;
        bootmap = find_e820_area(0, end_pfn<<PAGE_SHIFT, bootmap_size);
        if (bootmap == -1L) 
                panic("Cannot find bootmem map of size %ld\n",bootmap_size);
        bootmap_size = init_bootmem(bootmap >> PAGE_SHIFT, end_pfn);
        e820_bootmem_free(&contig_page_data, 0, end_pfn << PAGE_SHIFT); 
        reserve_bootmem(bootmap, bootmap_size);
} 
#endif /* !CONFIG_XEN */
#endif

/* Use inline assembly to define this because the nops are defined 
   as inline assembly strings in the include files and we cannot 
   get them easily into strings. */
asm("\t.data\nk8nops: " 
    K8_NOP1 K8_NOP2 K8_NOP3 K8_NOP4 K8_NOP5 K8_NOP6
    K8_NOP7 K8_NOP8); 
    
extern unsigned char k8nops[];
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

/* Replace instructions with better alternatives for this CPU type.

   This runs before SMP is initialized to avoid SMP problems with
   self modifying code. This implies that assymetric systems where
   APs have less capabilities than the boot processor are not handled. 
   In this case boot with "noreplacement". */ 
void apply_alternatives(void *start, void *end) 
{ 
	struct alt_instr *a; 
	int diff, i, k;
	for (a = start; (void *)a < end; a++) { 
		if (!boot_cpu_has(a->cpuid))
			continue;

		BUG_ON(a->replacementlen > a->instrlen); 
		__inline_memcpy(a->instr, a->replacement, a->replacementlen); 
		diff = a->instrlen - a->replacementlen; 

		/* Pad the rest with nops */
		for (i = a->replacementlen; diff > 0; diff -= k, i += k) {
			k = diff;
			if (k > ASM_NOP_MAX)
				k = ASM_NOP_MAX;
			__inline_memcpy(a->instr + i, k8_nops[k], k); 
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

#ifndef CONFIG_XEN
#define EBDA_ADDR_POINTER 0x40E
static void __init reserve_ebda_region(void)
{
	unsigned int addr;
	/** 
	 * there is a real-mode segmented pointer pointing to the 
	 * 4K EBDA area at 0x40E
	 */
	addr = *(unsigned short *)phys_to_virt(EBDA_ADDR_POINTER);
	addr <<= 4;
	if (addr)
		reserve_bootmem_generic(addr, PAGE_SIZE);
}
#endif

#ifdef CONFIG_X86_HT
static void noht_init(void)
{
	unsigned int cpuid_level;
	char vendorid[13];
	vendorid[12] = 0;

	/* Have to get CPUID level and vendor ID here since
 	 * we haven't populated boot_cpu_data yet
	 */

	cpuid(0, &cpuid_level, (int *)&vendorid[0], (int *)&vendorid[8], (int *)&vendorid[4]);

	if (!strncmp(vendorid, "GenuineIntel", 12) && disable_x86_ht) {
		int siblings, eax, ebx, ecx, edx;
		/* If "noht" specified, calculate a mask that
		 * can be used to determine which APIC IDs
		 * correspond to the first CPU in a sibling
		 * set.
		 */
		printk("Hyperthreading disabled by user\n");
		ebx = cpuid_ebx(1);
		siblings = (ebx & 0xff0000) >> 16;
		if (!siblings) 
			siblings = 1;
		if (cpuid_level >= 4) {
			cpuid_count(4, 0, &eax, &ebx, &ecx, &edx);
			if (eax & 0x1f)
				siblings /= ((eax >> 26) + 1);
		}
		
		sibling_ht_mask = 1;
		while(sibling_ht_mask < siblings)
			sibling_ht_mask <<= 1;
		sibling_ht_mask--;
	}
}
#endif /* CONFIG_X86_HT */

void __init setup_arch(char **cmdline_p)
{
	unsigned long low_mem_size;
	unsigned long kernel_end;
	extern void dmi_scan_machine(void);

#ifdef CONFIG_XEN
	/* Register a call for panic conditions. */
	notifier_chain_register(&panic_notifier_list, &xen_panic_block);

	ROOT_DEV = MKDEV(RAMDISK_MAJOR,0);
	kernel_end = 0;         /* dummy */
	screen_info = SCREEN_INFO;

	if (is_initial_xendomain()) {
		/* This is drawn from a dump from vgacon:startup in
		 * standard Linux. */
		screen_info.orig_video_mode = 3;
		screen_info.orig_video_isVGA = 1;
		screen_info.orig_video_lines = 25;
		screen_info.orig_video_cols = 80;
		screen_info.orig_video_ega_bx = 3;
		screen_info.orig_video_points = 16;
	} else
		screen_info.orig_video_isVGA = 0;

	edid_info = EDID_INFO;
	saved_video_mode = SAVED_VIDEO_MODE;

#ifdef CONFIG_BLK_DEV_RAM
	rd_image_start = RAMDISK_FLAGS & RAMDISK_IMAGE_START_MASK;
	rd_prompt = ((RAMDISK_FLAGS & RAMDISK_PROMPT_FLAG) != 0);
	rd_doload = ((RAMDISK_FLAGS & RAMDISK_LOAD_FLAG) != 0);
#endif

	setup_xen_features();

	if (xen_feature(XENFEAT_auto_translated_physmap) &&
	    xen_start_info->shared_info < xen_start_info->nr_pages) {
		HYPERVISOR_shared_info =
			(shared_info_t *)__va(xen_start_info->shared_info);
		memset(empty_zero_page, 0, sizeof(empty_zero_page));
	}

	HYPERVISOR_vm_assist(VMASST_CMD_enable,
				VMASST_TYPE_writable_pagetables);

	ARCH_SETUP
#else
 	ROOT_DEV = old_decode_dev(ORIG_ROOT_DEV);
 	drive_info = DRIVE_INFO;
 	screen_info = SCREEN_INFO;
	edid_info = EDID_INFO;
	aux_device_present = AUX_DEVICE_INFO;
	saved_video_mode = SAVED_VIDEO_MODE;

#ifdef CONFIG_BLK_DEV_RAM
	rd_image_start = RAMDISK_FLAGS & RAMDISK_IMAGE_START_MASK;
	rd_prompt = ((RAMDISK_FLAGS & RAMDISK_PROMPT_FLAG) != 0);
	rd_doload = ((RAMDISK_FLAGS & RAMDISK_LOAD_FLAG) != 0);
#endif
	setup_memory_region();
	copy_edd();
#endif /* !CONFIG_XEN */

	if (!MOUNT_ROOT_RDONLY)
		root_mountflags &= ~MS_RDONLY;
	init_mm.start_code = (unsigned long) &_text;
	init_mm.end_code = (unsigned long) &_etext;
	init_mm.end_data = (unsigned long) &_edata;
#ifdef CONFIG_XEN
	init_mm.brk = start_pfn << PAGE_SHIFT;
	// FIXME: We bump starg_pfn later. Is the above all right?
#else
	init_mm.brk = (unsigned long) &_end;

	code_resource.start = virt_to_phys(&_text);
	code_resource.end = virt_to_phys(&_etext)-1;
	data_resource.start = virt_to_phys(&_etext);
	data_resource.end = virt_to_phys(&_edata)-1;
#endif

	parse_cmdline_early(cmdline_p);

	/*
	 * partially used pages are not usable - thus
	 * we are rounding upwards:
	 */
	end_pfn = e820_end_of_ram();

	check_efer();

	init_memory_mapping(); 

	xen_printf("xen_start_info @%p\n", xen_start_info);
	xen_printf("shared @m%010lx @%p=@%016lx [0x%x]\n",
	    (long) xen_start_info->shared_info,
	    HYPERVISOR_shared_info, fix_to_virt(FIX_SHARED_INFO), FIX_SHARED_INFO);

	xen_dump_ptab("xen_start_info", (long)xen_start_info);
	xen_dump_ptab("xen_shared_info", fix_to_virt(FIX_SHARED_INFO));
	xen_dump_ptab("PAGE_OFFSET+1.2", PAGE_OFFSET + PAGE_SIZE*1);

#ifdef CONFIG_X86_HT
	noht_init();
#endif
#ifdef CONFIG_ACPI_BOOT
	/*
	 * Initialize the ACPI boot-time table parser (gets the RSDP and SDT).
	 * Call this early for SRAT node setup.
	 */
	acpi_boot_table_init();

#ifdef CONFIG_ACPI_NUMA
	/* Choose the default for acpi_numa.  If we're a multi-core
	 * AMD CPU then default is ON, else the default is OFF
	 * (to prevent possible regressions in legacy systems).
	 * Only set the default if a choice hasn't been made by
	 * the user.
	 */

	if (acpi_numa < 0) {
		int eax, ebx, ecx, edx;

		/* this is called so early that c->vendor_id and
		 * smp_num_siblings have not been set up yet.
		 * Compute them here
		 */

		/* default is off */
		acpi_numa = 0;

		cpuid(0, &eax, &ebx, &ecx, &edx);
		
		/* ebx/edx/ecx should contain "AuthenticAMD" */
		if (ebx==0x68747541 && edx==0x69746e65 && ecx==0x444d4163) {
			if (!numa_off && ((cpuid_ecx(0x80000008) & 0xff) > 0)) {
				printk("Enabling SRAT NUMA discovery\n");
				acpi_numa = 1;
			}
		}
	}	

	/*
	 * Parse SRAT to discover nodes.
	 */
	if (acpi_numa && acpi_numa_init()) {
		printk("acpi_numa_init() failed, disabling ACPI NUMA config\n");
		acpi_numa = 0;
	}
#endif
#endif

#ifdef CONFIG_DISCONTIGMEM
	numa_initmem_init(start_pfn, end_pfn); 
#else
	contig_initmem_init(start_pfn, end_pfn); 
#endif

#ifndef CONFIG_XEN
	/* Reserve direct mapping */
	reserve_bootmem_generic(table_start << PAGE_SHIFT, 
				(table_end - table_start) << PAGE_SHIFT);

	/* reserve kernel */
	kernel_end = round_up(__pa_symbol(&_end),PAGE_SIZE);
	reserve_bootmem_generic(HIGH_MEMORY, kernel_end - HIGH_MEMORY);

	/*
	 * reserve physical page 0 - it's a special BIOS page on many boxes,
	 * enabling clean reboots, SMP operation, laptop functions.
	 */
	reserve_bootmem_generic(0, PAGE_SIZE);

	/* reserve ebda region */
	reserve_ebda_region();
#endif

#ifdef CONFIG_SMP
	/*
	 * But first pinch a few for the stack/trampoline stuff
	 * FIXME: Don't need the extra page at 4K, but need to fix
	 * trampoline before removing it. (see the GDT stuff)
	 */
	reserve_bootmem_generic(PAGE_SIZE, PAGE_SIZE);

	/* Reserve SMP trampoline */
	reserve_bootmem_generic(SMP_TRAMPOLINE_BASE, PAGE_SIZE);
#endif

#ifdef CONFIG_ACPI_SLEEP
       /*
        * Reserve low memory region for sleep support.
        */
       acpi_reserve_bootmem();
#endif
#ifdef CONFIG_XEN
#ifdef CONFIG_BLK_DEV_INITRD
	if (xen_start_info->mod_start) {
		if (INITRD_START + INITRD_SIZE <= (end_pfn << PAGE_SHIFT)) {
			/*reserve_bootmem_generic(INITRD_START, INITRD_SIZE);*/
			initrd_start = INITRD_START + PAGE_OFFSET;
			initrd_end = initrd_start+INITRD_SIZE;
			initrd_below_start_ok = 1;
		} else {
			printk(KERN_ERR "initrd extends beyond end of memory "
				"(0x%016lx > 0x%016lx)\ndisabling initrd\n",
				(unsigned long)(INITRD_START + INITRD_SIZE),
				(unsigned long)(end_pfn << PAGE_SHIFT));
			initrd_start = 0;
		}
	}
#endif
#else /* CONFIG_XEN */
#ifdef CONFIG_BLK_DEV_INITRD
	if (LOADER_TYPE && INITRD_START) {
		if (INITRD_START + INITRD_SIZE <= (end_pfn << PAGE_SHIFT)) {
			reserve_bootmem_generic(INITRD_START, INITRD_SIZE);
			initrd_start =
				INITRD_START ? INITRD_START + PAGE_OFFSET :
			initrd_end = initrd_start+INITRD_SIZE;
		}
		else {
			printk(KERN_ERR "initrd extends beyond end of memory "
			    "(0x%016lx > 0x%016lx)\ndisabling initrd\n",
			    (unsigned long)(INITRD_START + INITRD_SIZE),
			    (unsigned long)(end_pfn << PAGE_SHIFT));
			initrd_start = 0;
		}
	}
#endif
#endif /* !CONFIG_XEN */
	paging_init();
#ifdef CONFIG_X86_LOCAL_APIC
	/*
	 * Find and reserve possible boot-time SMP configuration:
	 */
	find_smp_config();
#endif
#ifdef CONFIG_XEN
	{
		int i, j, k, fpp;
		unsigned long va;
		/* 'Initial mapping' of initrd must be destroyed. */
		for (va = xen_start_info->mod_start;
		     va < (xen_start_info->mod_start+xen_start_info->mod_len);
		     va += PAGE_SIZE) {
			HYPERVISOR_update_va_mapping(va, __pte_ma(0), 0);
		}

		if (!xen_feature(XENFEAT_auto_translated_physmap)) {
			/* Make sure we have a large enough P->M table. */
			phys_to_machine_mapping = alloc_bootmem(
				end_pfn * sizeof(unsigned long));
			memset(phys_to_machine_mapping, ~0,
				end_pfn * sizeof(unsigned long));
			memcpy(phys_to_machine_mapping,
				(unsigned long *)xen_start_info->mfn_list,
				xen_start_info->nr_pages * sizeof(unsigned long));
			free_bootmem(
				__pa(xen_start_info->mfn_list),
				PFN_PHYS(PFN_UP(xen_start_info->nr_pages *
						sizeof(unsigned long))));

			/* Destroyed 'initial mapping' of old p2m table. */
			for (va = xen_start_info->mfn_list;
			     va < (xen_start_info->mfn_list +
				   (xen_start_info->nr_pages*sizeof(unsigned long)));
			     va += PAGE_SIZE) {
				HYPERVISOR_update_va_mapping(va, __pte_ma(0), 0);
			}

			/*
			 * Initialise the list of the frames that specify the
			 * list of frames that make up the p2m table. Used by
			 * save/restore.
			 */
			pfn_to_mfn_frame_list_list = alloc_bootmem(PAGE_SIZE);
			HYPERVISOR_shared_info->arch.pfn_to_mfn_frame_list_list =
				virt_to_mfn(pfn_to_mfn_frame_list_list);

			fpp = PAGE_SIZE/sizeof(unsigned long);
			for (i=0, j=0, k=-1; i< end_pfn; i+=fpp, j++) {
				if ((j % fpp) == 0) {
					k++;
					BUG_ON(k>=fpp);
					pfn_to_mfn_frame_list[k] =
						alloc_bootmem(PAGE_SIZE);
					pfn_to_mfn_frame_list_list[k] =
						virt_to_mfn(pfn_to_mfn_frame_list[k]);
					j=0;
				}
				pfn_to_mfn_frame_list[k][j] =
					virt_to_mfn(&phys_to_machine_mapping[i]);
			}
			HYPERVISOR_shared_info->arch.max_pfn = end_pfn;
		}
	}

	if (!is_initial_xendomain())
	{
		acpi_disabled = 1;
#ifdef  CONFIG_ACPI
		acpi_ht = 0;
#endif
	}
#endif

	dmi_scan_machine();

#ifndef CONFIG_XEN
	check_ioapic();
#endif
	
#ifdef CONFIG_ACPI_BOOT
	/*
	 * Initialize the ACPI boot-time table parser (gets the RSDP and SDT).
	 * Call this early for SRAT node setup.
	 */
	acpi_boot_table_init();

       /*
        * Initialize the ACPI boot-time table parser (gets the RSDP and SDT).
        * Must do this after paging_init (due to reliance on fixmap, and thus
        * the bootmem allocator) but before get_smp_config (to allow parsing
        * of MADT).
        */
	acpi_boot_init();
#endif
#ifdef CONFIG_X86_LOCAL_APIC
	/*
	 * get boot-time SMP configuration:
	 */
	if (smp_found_config)
		get_smp_config();
#ifndef CONFIG_XEN
	init_apic_mappings();
#endif
#endif

#if defined(CONFIG_XEN_PRIVILEGED_GUEST) || !defined(CONFIG_XEN)
	/*
	 * Request address space for all standard RAM and ROM resources
	 * and also for regions reported as reserved by the e820.
	 */
	probe_roms();
	e820_reserve_resources(); 
#endif

	request_resource(&iomem_resource, &video_ram_resource);

	{
	unsigned i;
	/* request I/O space for devices used on all i[345]86 PCs */
	for (i = 0; i < STANDARD_IO_RESOURCES; i++)
		request_resource(&ioport_resource, &standard_io_resources[i]);
	}

	/* Will likely break when you have unassigned resources with more
	   than 4GB memory and bridges that don't support more than 4GB. 
	   Doing it properly would require to use pci_alloc_consistent
	   in this case. */
	low_mem_size = ((end_pfn << PAGE_SHIFT) + 0xfffff) & ~0xfffff;
	if (low_mem_size > pci_mem_start)
		pci_mem_start = low_mem_size;

#ifdef CONFIG_GART_IOMMU
       iommu_hole_init();
#endif

#ifdef CONFIG_XEN
	{
		struct physdev_set_iopl set_iopl;

		set_iopl.iopl = 1;
		HYPERVISOR_physdev_op(PHYSDEVOP_set_iopl, &set_iopl);

		if (is_initial_xendomain()) {
			if (!(xen_start_info->flags & SIF_PRIVILEGED))
				panic("Xen granted us console access "
					"but not privileged status");

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
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
#else /* CONFIG_XEN */

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)
	conswitchp = &dummy_con;
#endif
#endif

#endif /* !CONFIG_XEN */
}

#ifdef CONFIG_XEN
static int
xen_panic_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	HYPERVISOR_shutdown(SHUTDOWN_crash);
	/* we're never actually going to get here... */
	return NOTIFY_DONE;
}
#endif /* !CONFIG_XEN */


static int __init get_model_name(struct cpuinfo_x86 *c)
{
	unsigned int *v;

	if (cpuid_eax(0x80000000) < 0x80000004)
		return 0;

	v = (unsigned int *) c->x86_model_id;
	cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3]);
	cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7]);
	cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11]);
	c->x86_model_id[48] = 0;
	return 1;
}


static void __init display_cacheinfo(struct cpuinfo_x86 *c)
{
	unsigned int n, dummy, eax, ebx, ecx, edx;

	n = cpuid_eax(0x80000000);

	if (n >= 0x80000005) {
		cpuid(0x80000005, &dummy, &ebx, &ecx, &edx);
		printk(KERN_INFO "CPU: L1 I Cache: %dK (%d bytes/line), D cache %dK (%d bytes/line)\n",
			edx>>24, edx&0xFF, ecx>>24, ecx&0xFF);
		c->x86_cache_size=(ecx>>24)+(edx>>24);	
		/* DTLB and ITLB together, but only 4K */
		c->x86_tlbsize = ((ebx>>16)&0xff) + (ebx&0xff);
	}

	if (n >= 0x80000006) {
		cpuid(0x80000006, &dummy, &ebx, &ecx, &edx);
	ecx = cpuid_ecx(0x80000006);
	c->x86_cache_size = ecx >> 16;
		c->x86_tlbsize += ((ebx >> 16) & 0xfff) + (ebx & 0xfff);

	printk(KERN_INFO "CPU: L2 Cache: %dK (%d bytes/line)\n",
		c->x86_cache_size, ecx & 0xFF);
	}

	if (n >= 0x80000007)
		cpuid(0x80000007, &dummy, &dummy, &dummy, &c->x86_power); 
	if (n >= 0x80000008) {
		cpuid(0x80000008, &eax, &dummy, &dummy, &dummy); 
		c->x86_virt_bits = (eax >> 8) & 0xff;
		c->x86_phys_bits = eax & 0xff;
	}
}

/*
 * On a AMD dual core setup the lower bits of the APIC id distingush the cores.
 * Assumes number of cores is a power of two.
 */
static void __init amd_detect_cmp(struct cpuinfo_x86 *c)
{
#ifdef CONFIG_SMP
	int cpu = smp_processor_id();
	unsigned bits;

	bits = 0;
	while ((1 << bits) < c->x86_num_cores)
		bits++;

	/* Low order bits define the core id (index of core in socket) */
	cpu_core_id[cpu] = phys_proc_id[cpu] & ((1 << bits)-1);
	/* Convert the APIC ID into the socket ID */
	phys_proc_id[cpu] >>= bits;
#endif
}

static int __init init_amd(struct cpuinfo_x86 *c)
{
	int r;
	int level;
#ifdef CONFIG_SMP
#ifdef CONFIG_NUMA
	int cpu;
#endif
#endif

	/* Bit 31 in normal CPUID used for nonstandard 3DNow ID;
	   3DNow is IDd by bit 31 in extended CPUID (1*32+31) anyway */
	clear_bit(0*32+31, &c->x86_capability);
	
	/* C-stepping K8? */
	level = cpuid_eax(1);
	if ((level >= 0x0f48 && level < 0x0f50) || level >= 0x0f58)
		set_bit(X86_FEATURE_K8_C, &c->x86_capability);

	r = get_model_name(c);
	if (!r) { 
		switch (c->x86) { 
		case 15:
			/* Should distinguish Models here, but this is only
			   a fallback anyways. */
			strcpy(c->x86_model_id, "Hammer");
			break; 
		} 
	} 
	display_cacheinfo(c);

#ifdef CONFIG_SMP
	if (cpuid_eax(0x80000000) >= 0x80000008) {
		c->x86_num_cores = (cpuid_ecx(0x80000008) & 0xff) + 1;
		if (c->x86_num_cores & (c->x86_num_cores - 1))
			c->x86_num_cores = 1;

		amd_detect_cmp(c);

#ifdef CONFIG_NUMA
		/* On a dual core setup the lower bits of apic id
		   distingush the cores. Fix up the CPU<->node mappings
		   here based on that.
		   Assumes number of cores is a power of two.
		   When using SRAT use mapping from SRAT. */
		cpu = c->x86_apicid;
		if (acpi_numa <= 0 && c->x86_num_cores > 1) {
			cpu_to_node[cpu] = cpu >> hweight32(c->x86_num_cores - 1);
			if (!node_online(cpu_to_node[cpu]))
				cpu_to_node[cpu] = find_first_bit(node_online_map, MAX_NUMNODES);
		}
		printk(KERN_INFO "CPU %d(%d) -> Node %d\n",
				cpu, c->x86_num_cores, cpu_to_node[cpu]);
#endif
	}
#endif

	return r;
}


static void __init detect_ht(struct cpuinfo_x86 *c)
{
#ifdef CONFIG_SMP
	if (!cpu_has(c, X86_FEATURE_HT) || (boot_cpu_data.x86_vendor == X86_VENDOR_AMD && cpu_has(c, X86_FEATURE_CMP_LEGACY)))
		return;

	smp_num_siblings = 1;
#endif
}
	
/*
 * find out the number of processor cores on the die
 */
static int __init num_cpu_cores(struct cpuinfo_x86 *c)
{
	unsigned int eax;

	if (c->cpuid_level < 4)
		return 1;

	__asm__("cpuid"
		: "=a" (eax)
		: "0" (4), "c" (0)
		: "bx", "dx");

	if (eax & 0x1f)
		return ((eax >> 26) + 1);
	else
		return 1;
}

static void __init init_intel(struct cpuinfo_x86 *c)
{
	/* Cache sizes */
	unsigned n;

	init_intel_cacheinfo(c);
	n = cpuid_eax(0x80000000);
	if (n >= 0x80000008) {
		unsigned eax = cpuid_eax(0x80000008);
		c->x86_virt_bits = (eax >> 8) & 0xff;
		c->x86_phys_bits = eax & 0xff;
	}

	if (c->x86 == 15)
		c->x86_cache_alignment = c->x86_clflush_size * 2;

#ifdef CONFIG_SMP
	c->x86_num_cores = num_cpu_cores(c);
#endif
}

void __init get_cpu_vendor(struct cpuinfo_x86 *c)
{
	char *v = c->x86_vendor_id;

	if (!strcmp(v, "AuthenticAMD"))
		c->x86_vendor = X86_VENDOR_AMD;
	else if (!strcmp(v, "GenuineIntel"))
		c->x86_vendor = X86_VENDOR_INTEL;
	else
		c->x86_vendor = X86_VENDOR_UNKNOWN;
}

struct cpu_model_info {
	int vendor;
	int family;
	char *model_names[16];
};

/* Do some early cpuid on the boot CPU to get some parameter that are
   needed before check_bugs. Everything advanced is in identify_cpu
   below. */
void __init early_identify_cpu(struct cpuinfo_x86 *c)
{
	u32 tfms;

	c->loops_per_jiffy = loops_per_jiffy;
	c->x86_cache_size = -1;
	c->x86_vendor = X86_VENDOR_UNKNOWN;
	c->x86_model = c->x86_mask = 0;	/* So far unknown... */
	c->x86_vendor_id[0] = '\0'; /* Unset */
	c->x86_model_id[0] = '\0';  /* Unset */
	c->x86_clflush_size = 64;
	c->x86_num_cores = 1;
	c->x86_cache_alignment = c->x86_clflush_size;
	c->x86_apicid = c == &boot_cpu_data ? 0 : c - cpu_data;
	memset(&c->x86_capability, 0, sizeof c->x86_capability);

	/* Get vendor name */
	cpuid(0x00000000, &c->cpuid_level,
	      (int *)&c->x86_vendor_id[0],
	      (int *)&c->x86_vendor_id[8],
	      (int *)&c->x86_vendor_id[4]);
		
	get_cpu_vendor(c);

	/* Initialize the standard set of capabilities */
	/* Note that the vendor-specific code below might override */

	/* Intel-defined flags: level 0x00000001 */
	if (c->cpuid_level >= 0x00000001) {
		__u32 misc;
		cpuid(0x00000001, &tfms, &misc, &c->x86_capability[4],
		      &c->x86_capability[0]);
		c->x86 = (tfms >> 8) & 0xf;
		c->x86_model = (tfms >> 4) & 0xf;
		c->x86_mask = tfms & 0xf;
		if (c->x86 == 0xf)
			c->x86 += (tfms >> 20) & 0xff;
		if (c->x86 >= 0x6)
			c->x86_model += ((tfms >> 16) & 0xF) << 4;
		if (c->x86_capability[0] & (1<<19)) 
			c->x86_clflush_size = ((misc >> 8) & 0xff) * 8;
		c->x86_apicid = misc >> 24;
	} else {
		/* Have CPUID level 0 only - unheard of */
		c->x86 = 4;
	}

#ifdef CONFIG_SMP
	phys_proc_id[smp_processor_id()] = (cpuid_ebx(1) >> 24) & 0xff;
#endif
}

/*
 * This does the hard work of actually picking apart the CPU stuff...
 */
void __init identify_cpu(struct cpuinfo_x86 *c)
{
	int i;
	u32 xlvl;

	early_identify_cpu(c);

	/* AMD-defined flags: level 0x80000001 */
	xlvl = cpuid_eax(0x80000000);
	if ( (xlvl & 0xffff0000) == 0x80000000 ) {
		if ( xlvl >= 0x80000001 ) {
			c->x86_capability[1] = cpuid_edx(0x80000001);
			c->x86_capability[5] = cpuid_ecx(0x80000001);
		}
		if ( xlvl >= 0x80000004 )
			get_model_name(c); /* Default name */
	}

	/* Transmeta-defined flags: level 0x80860001 */
	xlvl = cpuid_eax(0x80860000);
	if ( (xlvl & 0xffff0000) == 0x80860000 ) {
		if (  xlvl >= 0x80860001 )
			c->x86_capability[2] = cpuid_edx(0x80860001);
	}

	/*
	 * Vendor-specific initialization.  In this section we
	 * canonicalize the feature flags, meaning if there are
	 * features a certain CPU supports which CPUID doesn't
	 * tell us, CPUID claiming incorrect flags, or other bugs,
	 * we handle them here.
	 *
	 * At the end of this section, c->x86_capability better
	 * indicate the features this CPU genuinely supports!
	 */
	switch ( c->x86_vendor ) {

		case X86_VENDOR_AMD:
			init_amd(c);
			break;

		case X86_VENDOR_INTEL:
			init_intel(c); 
			break; 

		case X86_VENDOR_UNKNOWN:
		default:
			display_cacheinfo(c);
			break;
	}

	select_idle_routine(c);
	detect_ht(c); 
		
	/*
	 * On SMP, boot_cpu_data holds the common feature set between
	 * all CPUs; so make sure that we indicate which features are
	 * common between the CPUs.  The first time this routine gets
	 * executed, c == &boot_cpu_data.
	 */
	if ( c != &boot_cpu_data ) {
		/* AND the already accumulated flags with these */
		for ( i = 0 ; i < NCAPINTS ; i++ )
			boot_cpu_data.x86_capability[i] &= c->x86_capability[i];
	}
}
 

void __init print_cpu_info(struct cpuinfo_x86 *c)
{
	if (c->x86_model_id[0])
		printk("%s", c->x86_model_id);

	if (c->x86_mask || c->cpuid_level >= 0) 
		printk(" stepping %02x\n", c->x86_mask);
	else
		printk("\n");
}

/*
 *	Get CPU information for use by the procfs.
 */

static int show_cpuinfo(struct seq_file *m, void *v)
{
	struct cpuinfo_x86 *c = v;

	/* 
	 * These flag bits must match the definitions in <asm/cpufeature.h>.
	 * NULL means this bit is undefined or reserved; either way it doesn't
	 * have meaning as far as Linux is concerned.  Note that it's important
	 * to realize there is a difference between this table and CPUID -- if
	 * applications want to get the raw CPUID data, they should access
	 * /dev/cpu/<cpu_nr>/cpuid instead.
	 */
	static char *x86_cap_flags[] = {
		/* Intel-defined */
	        "fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce",
	        "cx8", "apic", NULL, "sep", "mtrr", "pge", "mca", "cmov",
	        "pat", "pse36", "pn", "clflush", NULL, "dts", "acpi", "mmx",
	        "fxsr", "sse", "sse2", "ss", "ht", "tm", "ia64", NULL,

		/* AMD-defined */
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, "syscall", NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, "nx", NULL, "mmxext", NULL,
		NULL, NULL, NULL, NULL, NULL, "lm", "3dnowext", "3dnow",

		/* Transmeta-defined */
		"recovery", "longrun", NULL, "lrti", NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

		/* Other (Linux-defined) */
		"cxmmx", "k6_mtrr", "cyrix_arr", "centaur_mcr", NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

		/* Intel-defined (#2) */
		"pni", NULL, NULL, "monitor", "ds_cpl", NULL, NULL, "est",
		"tm2", NULL, "cid", NULL, NULL, "cx16", "xtpr", NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,

		/* AMD-defined (#2) */
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	};
	static char *x86_power_flags[] = { 
		"ts",	/* temperature sensor */
		"fid",  /* frequency id control */
		"vid",  /* voltage id control */
		"ttp",  /* thermal trip */
	};


#ifdef CONFIG_SMP
	if (!cpu_online(c-cpu_data))
		return 0;
#endif

	seq_printf(m,"processor\t: %u\n"
		     "vendor_id\t: %s\n"
		     "cpu family\t: %d\n"
		     "model\t\t: %d\n"
		     "model name\t: %s\n",
		     (unsigned)(c-cpu_data),
		     c->x86_vendor_id[0] ? c->x86_vendor_id : "unknown",
		     c->x86,
		     (int)c->x86_model,
		     c->x86_model_id[0] ? c->x86_model_id : "unknown");
	
	if (c->x86_mask || c->cpuid_level >= 0)
		seq_printf(m, "stepping\t: %d\n", c->x86_mask);
	else
		seq_printf(m, "stepping\t: unknown\n");
	
	if (cpu_has(c,X86_FEATURE_TSC)) {
		seq_printf(m, "cpu MHz\t\t: %u.%03u\n",
			     cpu_khz / 1000, (cpu_khz % 1000));
	}

	/* Cache size */
	if (c->x86_cache_size >= 0) 
		seq_printf(m, "cache size\t: %d KB\n", c->x86_cache_size);
	
#ifdef CONFIG_SMP
	if (smp_num_siblings > 1 || c->x86_num_cores > 1) {
		seq_printf(m, "physical id\t: %d\n", phys_proc_id[c - cpu_data]);
		seq_printf(m, "siblings\t: %d\n", smp_num_siblings * c->x86_num_cores);
		seq_printf(m, "core id\t\t: %d\n", cpu_core_id[c - cpu_data]);
		seq_printf(m, "cpu cores\t: %d\n", c->x86_num_cores);
	}
#endif	

	seq_printf(m,
	        "fpu\t\t: yes\n"
	        "fpu_exception\t: yes\n"
	        "cpuid level\t: %d\n"
	        "wp\t\t: yes\n"
	        "flags\t\t:",
		   c->cpuid_level);

	{ 
		int i; 
		for ( i = 0 ; i < 32*NCAPINTS ; i++ )
			if ( test_bit(i, &c->x86_capability) &&
			     x86_cap_flags[i] != NULL )
				seq_printf(m, " %s", x86_cap_flags[i]);
	}
		
	seq_printf(m, "\nbogomips\t: %lu.%02lu\n",
		   c->loops_per_jiffy/(500000/HZ),
		   (c->loops_per_jiffy/(5000/HZ)) % 100);

	if (c->x86_tlbsize > 0) 
		seq_printf(m, "TLB size\t: %d 4K pages\n", c->x86_tlbsize);
	seq_printf(m, "clflush size\t: %d\n", c->x86_clflush_size);
	seq_printf(m, "cache_alignment\t: %d\n", c->x86_cache_alignment);

	seq_printf(m, "address sizes\t: %u bits physical, %u bits virtual\n", 
		   c->x86_phys_bits, c->x86_virt_bits);

	seq_printf(m, "power management:");
	{
		unsigned i;
		for (i = 0; i < 32; i++) 
			if (c->x86_power & (1 << i)) {
				if (i < ARRAY_SIZE(x86_power_flags))
					seq_printf(m, " %s", x86_power_flags[i]);
				else
					seq_printf(m, " [%d]", i);
			}
	}


	seq_printf(m, "\n\n"); 

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < NR_CPUS ? cpu_data + *pos : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

struct seq_operations cpuinfo_op = {
	.start =c_start,
	.next =	c_next,
	.stop =	c_stop,
	.show =	show_cpuinfo,
};

/* P3 */

void xen_dump_ptab(const char *tag, unsigned long vaddr)
{
	// xen_printf("shared #m%09lx(@m%010lx) @%p=@%p [0x%x]\n",
	//     (long) xen_start_info->shared_info,
	//     (long) xen_start_info->shared_info << PAGE_SHIFT,
	//     HYPERVISOR_shared_info, fix_to_virt(FIX_SHARED_INFO), FIX_SHARED_INFO);
	unsigned long cr3;
	pml4_t *__pml4;
	pgd_t *__pgd;
	pmd_t *__pmd;
	pte_t *__pte;

	xen_printf("%s: @%016lx\n", tag, vaddr);

	cr3 = read_cr3();

	__pml4 = pml4_offset_k(vaddr);
	// __pml4 = (pml4_t *) __va(cr3) + pml4_index(vaddr);
	xen_printf(" cr3 %016lx pml4p %016lx\n", cr3, (long)__pml4);
	if (pml4_none(*__pml4)) {
		xen_printf(" pml4e %016lx is none\n", (*__pml4).pml4);
		return;
	}

	// __pgd = pgd_offset_k(__pml4, vaddr);
	// __pgd = (pgd_t *) __va((*__pml4).pml4 & PTE_MASK) + pgd_index(vaddr);
	__pgd = (pgd_t *) __va(pml4_val(*__pml4) & PTE_MASK) + pgd_index(vaddr);
	xen_printf(" pml4e %016lx (real %016lx) pgdp %016lx\n", pml4_val(*__pml4), (*__pml4).pml4, (long)__pgd);
	if (pgd_none(*__pgd)) {
		xen_printf(" pgde %016lx is none\n", (*__pgd).pgd);
		return;
	}

	__pmd = pmd_offset(__pgd, vaddr);
	xen_printf(" pgde %016lx (real %016lx) pmdp %016lx\n", pgd_val(*__pgd), (*__pgd).pgd, (long)__pmd);
	if (pmd_none(*__pmd)) {
		xen_printf(" pmde %016lx is none\n", pmd_val(*__pmd));
		return;
	}

	__pte = pte_offset_kernel(__pmd, vaddr);
	xen_printf(" pmde %016lx (real %016lx) ptep %016lx\n", pmd_val(*__pmd), (*__pmd).pmd, (long)__pte);
	if (pte_none(*__pte)) {
		xen_printf(" pte %016lx is none\n", pte_val(*__pte));
		return;
	}

	xen_printf(" pte %016lx (real %016lx)\n", pte_val(*__pte), (*__pte).pte);
}

static char ppbuf[1024];

static void
xen_putchar(char ch)
{
	struct xencons_interface *xip = mfn_to_virt(xen_start_info->console_mfn);
	unsigned int cons;
	unsigned int prod, prod1;

	do {
		cons = xip->out_cons;
		prod = xip->out_prod;
		mb();
		prod1 = (prod + 1) & (sizeof(xip->out)-1);
	} while (prod1 == cons);
	xip->out[prod] = ch;
	xip->out_prod = prod1;
	wmb();
}

static void
xen_flush(void)
{
	struct xencons_interface *xip = mfn_to_virt(xen_start_info->console_mfn);
	unsigned int prod, cons;

	/* Use evtchn: this is called early, before irq is set up. */
	notify_remote_via_evtchn(xen_start_info->console_evtchn);

	do {
		cons = xip->out_cons;
		prod = xip->out_prod;
		mb();
	} while (prod != cons);
}

static void
xen_write(const char *buf, unsigned int n)
{
	char ch;

	while (n != 0) {
		--n;
		if ((ch = *buf++) == '\n')
			xen_putchar('\r');
		xen_putchar(ch);
	}
	xen_flush();
}

void
xen_printf(char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vscnprintf(ppbuf, sizeof(ppbuf), fmt, args);
	va_end(args);

	xen_write(ppbuf, i);
}

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <asm/io.h>
#include <linux/pm.h>
#include <asm/system.h>
#include <linux/dmi.h>
#include <linux/bootmem.h>


int es7000_plat = 0;

struct dmi_header
{
	u8	type;
	u8	length;
	u16	handle;
};

#undef DMI_DEBUG

#ifdef DMI_DEBUG
#define dmi_printk(x) printk x
#else
#define dmi_printk(x)
#endif

static char * __init dmi_string(struct dmi_header *dm, u8 s)
{
	u8 *bp=(u8 *)dm;
	bp+=dm->length;
	if(!s)
		return "";
	s--;
	while(s>0 && *bp)
	{
		bp+=strlen(bp);
		bp++;
		s--;
	}
	return bp;
}

/*
 *	We have to be cautious here. We have seen BIOSes with DMI pointers
 *	pointing to completely the wrong place for example
 */
 
static int __init dmi_table(u32 base, int len, int num, void (*decode)(struct dmi_header *))
{
	u8 *buf;
	struct dmi_header *dm;
	u8 *data;
	int i=0;
		
	/* Since pretty much everything is identity-mapped on x86_64,
	 * we shouldn't need to do an ioremap here.  phys_to_virt
	 * should suffice.
	 */
	buf = phys_to_virt(base);

	data = buf;

	/*
 	 *	Stop when we see all the items the table claimed to have
 	 *	OR we run off the end of the table (also happens)
 	 */
 
	while(i<num && data-buf+sizeof(struct dmi_header)<=len)
	{
		dm=(struct dmi_header *)data;
		/*
		 *  We want to know the total length (formated area and strings)
		 *  before decoding to make sure we won't run off the table in
		 *  dmi_decode or dmi_string
		 */
		data+=dm->length;
		while(data-buf<len-1 && (data[0] || data[1]))
			data++;
		if(data-buf<len-1)
			decode(dm);
		data+=2;
		i++;
	}


	return 0;
}


inline static int __init dmi_checksum(u8 *buf)
{
	u8 sum=0;
	int a;
	
	for(a=0; a<15; a++)
		sum+=buf[a];
	return (sum==0);
}

static int __init dmi_iterate(void (*decode)(struct dmi_header *))
{
	u8 buf[15];
	u32 fp=0xF0000;

	while (fp < 0xFFFFF)
	{
		isa_memcpy_fromio(buf, fp, 15);
		if(memcmp(buf, "_DMI_", 5)==0 && dmi_checksum(buf))
		{
			u16 num=buf[13]<<8|buf[12];
			u16 len=buf[7]<<8|buf[6];
			u32 base=buf[11]<<24|buf[10]<<16|buf[9]<<8|buf[8];

			/*
			 * DMI version 0.0 means that the real version is taken from
			 * the SMBIOS version, which we don't know at this point.
			 */
			if(buf[14]!=0)
				printk(KERN_INFO "DMI %d.%d present.\n",
					buf[14]>>4, buf[14]&0x0F);
			else
				printk(KERN_INFO "DMI present.\n");
			dmi_printk((KERN_INFO "%d structures occupying %d bytes.\n",
				num, len));
			dmi_printk((KERN_INFO "DMI table at 0x%08X.\n",
				base));
			if(dmi_table(base,len, num, decode)==0)
				return 0;
		}
		fp+=16;
	}
	return -1;
}

static char *dmi_ident[DMI_STRING_MAX];

/*
 *	Save a DMI string
 */
 
static void __init dmi_save_ident(struct dmi_header *dm, int slot, int string)
{
	char *d = (char*)dm;
	char *p = dmi_string(dm, d[string]);
	if(p==NULL || *p == 0)
		return;
	if (dmi_ident[slot])
		return;
	dmi_ident[slot] = alloc_bootmem(strlen(p)+1);
	if(dmi_ident[slot])
		strcpy(dmi_ident[slot], p);
	else
		printk(KERN_ERR "dmi_save_ident: out of memory.\n");
}

/*
 * Ugly compatibility crap.
 */
#define dmi_blacklist	dmi_system_id
#define NO_MATCH	{ DMI_NONE, NULL}
#define MATCH		DMI_MATCH

/*
 * Toshiba keyboard likes to repeat keys when they are not repeated.
 */

static __init int broken_toshiba_keyboard(struct dmi_blacklist *d)
{
	printk(KERN_WARNING "Toshiba with broken keyboard detected. If your keyboard sometimes generates 3 keypresses instead of one, see http://davyd.ucc.asn.au/projects/toshiba/README\n");
	return 0;
}


#ifdef CONFIG_ACPI_SLEEP
static __init int reset_videomode_after_s3(struct dmi_blacklist *d)
{
	/* See acpi_wakeup.S */
	extern long acpi_video_flags;
	acpi_video_flags |= 2;
	return 0;
}
#endif


#ifdef	CONFIG_ACPI_BOOT
extern int acpi_force;

static __init __attribute__((unused)) int dmi_disable_acpi(struct dmi_blacklist *d) 
{ 
	if (!acpi_force) { 
		printk(KERN_NOTICE "%s detected: acpi off\n",d->ident); 
		disable_acpi();
	} else { 
		printk(KERN_NOTICE 
		       "Warning: DMI blacklist says broken, but acpi forced\n"); 
	}
	return 0;
} 

/*
 * Limit ACPI to CPU enumeration for HT
 */
static __init __attribute__((unused)) int force_acpi_ht(struct dmi_blacklist *d) 
{ 
	if (!acpi_force) { 
		printk(KERN_NOTICE "%s detected: force use of acpi=ht\n", d->ident); 
		disable_acpi();
		acpi_ht = 1; 
	} else { 
		printk(KERN_NOTICE 
		       "Warning: acpi=force overrules DMI blacklist: acpi=ht\n"); 
	}
	return 0;
} 

/*
 * early nForce2 reference BIOS shipped with a
 * bogus ACPI IRQ0 -> pin2 interrupt override -- ignore it
 */
static __init int ignore_timer_override(struct dmi_blacklist *d)
{
	extern int acpi_skip_timer_override;
	printk(KERN_NOTICE "%s detected: BIOS IRQ0 pin2 override"
		" will be ignored\n", d->ident); 	

	acpi_skip_timer_override = 1;
	return 0;
}
#endif

#ifdef	CONFIG_ACPI_PCI
static __init int disable_acpi_irq(struct dmi_blacklist *d) 
{
	if (!acpi_force) {
		printk(KERN_NOTICE "%s detected: force use of acpi=noirq\n",
		       d->ident); 	
		acpi_noirq_set();
	}
	return 0;
}
static __init int disable_acpi_pci(struct dmi_blacklist *d) 
{
	if (!acpi_force) {
		printk(KERN_NOTICE "%s detected: force use of pci=noacpi\n",
		       d->ident); 	
		acpi_disable_pci();
	}
	return 0;
}  
static __init int disable_pci_mmconf(struct dmi_blacklist *d)
{
	extern char * pcibios_setup(char * str);

	printk(KERN_NOTICE "%s detected, forcing pci=nommconf\n", 
		d->ident);
	pcibios_setup("nommconf");
}

static __init int disable_pci_mmconf_seg(struct dmi_blacklist *d)
{
	extern char * pcibios_setup(char * str);

	printk(KERN_NOTICE "%s detected, forcing pci=nommconf and pci=noseg\n", 
		d->ident);
	pcibios_setup("nommconf");
	pcibios_setup("noseg");
}

#endif

/*
 *	Process the DMI blacklists
 */
 

/*
 *	This will be expanded over time to force things like the APM 
 *	interrupt mask settings according to the laptop
 */
 
static __initdata struct dmi_blacklist dmi_blacklist[]={

#ifdef CONFIG_ACPI_PCI
	{ disable_pci_mmconf_seg, "HP xw9300 Workstation", {
		MATCH(DMI_PRODUCT_NAME, "HP xw9300 Workstation"),
		NO_MATCH, NO_MATCH, NO_MATCH
		} },
	{ disable_pci_mmconf_seg, "HP xw9400 Workstation", {
		MATCH(DMI_PRODUCT_NAME, "HP xw9400 Workstation"),
		NO_MATCH, NO_MATCH, NO_MATCH
		} },
	{ disable_pci_mmconf, "HP DL585 G2", {
		MATCH(DMI_PRODUCT_NAME, "ProLiant DL585 G2"),
		NO_MATCH, NO_MATCH, NO_MATCH
		} },
	{ disable_pci_mmconf, "ASUS A8N-SLI Premium", {
		MATCH(DMI_BOARD_VENDOR, "ASUSTeK Computer INC."),
		MATCH(DMI_BOARD_NAME, "A8N-SLI Premium"),
		NO_MATCH, NO_MATCH
		} },
#endif
	{ NULL, }
};

/*
 *	Process a DMI table entry. Right now all we care about are the BIOS
 *	and machine entries. For 2.5 we should pull the smbus controller info
 *	out of here.
 */

static void __init dmi_decode(struct dmi_header *dm)
{
#ifdef DMI_DEBUG
	u8 *data = (u8 *)dm;
#endif
	
	switch(dm->type)
	{
		case  0:
			dmi_printk(("BIOS Vendor: %s\n",
				dmi_string(dm, data[4])));
			dmi_save_ident(dm, DMI_BIOS_VENDOR, 4);
			dmi_printk(("BIOS Version: %s\n", 
				dmi_string(dm, data[5])));
			dmi_save_ident(dm, DMI_BIOS_VERSION, 5);
			dmi_printk(("BIOS Release: %s\n",
				dmi_string(dm, data[8])));
			dmi_save_ident(dm, DMI_BIOS_DATE, 8);
			break;
		case 1:
			dmi_printk(("System Vendor: %s\n",
				dmi_string(dm, data[4])));
			dmi_save_ident(dm, DMI_SYS_VENDOR, 4);
			dmi_printk(("Product Name: %s\n",
				dmi_string(dm, data[5])));
			dmi_save_ident(dm, DMI_PRODUCT_NAME, 5);
			dmi_printk(("Version: %s\n",
				dmi_string(dm, data[6])));
			dmi_save_ident(dm, DMI_PRODUCT_VERSION, 6);
			dmi_printk(("Serial Number: %s\n",
				dmi_string(dm, data[7])));
			break;
		case 2:
			dmi_printk(("Board Vendor: %s\n",
				dmi_string(dm, data[4])));
			dmi_save_ident(dm, DMI_BOARD_VENDOR, 4);
			dmi_printk(("Board Name: %s\n",
				dmi_string(dm, data[5])));
			dmi_save_ident(dm, DMI_BOARD_NAME, 5);
			dmi_printk(("Board Version: %s\n",
				dmi_string(dm, data[6])));
			dmi_save_ident(dm, DMI_BOARD_VERSION, 6);
			break;
	}
}

void __init dmi_scan_machine(void)
{
	int err = dmi_iterate(dmi_decode);
	if(err == 0)
 		dmi_check_system(dmi_blacklist);
	else
		printk(KERN_INFO "DMI not present.\n");
}


/**
 *	dmi_check_system - check system DMI data
 *	@list: array of dmi_system_id structures to match against
 *
 *	Walk the blacklist table running matching functions until someone
 *	returns non zero or we hit the end. Callback function is called for
 *	each successfull match. Returns the number of matches.
 */
int dmi_check_system(struct dmi_system_id *list)
{
	int i, count = 0;
	struct dmi_system_id *d = list;

	while (d->ident) {
		for (i = 0; i < ARRAY_SIZE(d->matches); i++) {
			int s = d->matches[i].slot;
			if (s == DMI_NONE)
				continue;
			if (dmi_ident[s] && strstr(dmi_ident[s], d->matches[i].substr))
				continue;
			/* No match */
			goto fail;
		}
		if (d->callback && d->callback(d))
			break;
		count++;
fail:		d++;
	}

	return count;
}

EXPORT_SYMBOL(dmi_check_system);

/**
 *	dmi_get_system_info - return DMI data value
 *	@field: data index (see enum dmi_filed)
 *
 *	Returns one DMI data value, can be used to perform
 *	complex DMI data checks.
 */
char * dmi_get_system_info(int field)
{
	return dmi_ident[field];
}

EXPORT_SYMBOL(dmi_get_system_info);

/**
 *      dmi_get_year - Return year of a DMI date
 *      @field: data index (like dmi_get_system_info)
 *
 *      Returns -1 when the field doesn't exist. 0 when it is broken.
 */
int dmi_get_year(int field)
{
        int year;
        char *s = dmi_get_system_info(field);

        if (!s)
                return -1;
        if (*s == '\0')
                return 0;
        s = strrchr(s, '/');
        if (!s)
                return 0;

        s += 1;
        year = simple_strtoul(s, NULL, 0);
        if (year && year < 100) {       /* 2-digit year */
                year += 1900;
                if (year < 1996)        /* no dates < spec 1.0 */
                        year += 100;
        }

        return year;
}

EXPORT_SYMBOL(dmi_get_year);

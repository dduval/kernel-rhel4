/*
 * sleep.c - x86-specific ACPI sleep support.
 *
 *  Copyright (C) 2001-2003 Patrick Mochel
 *  Copyright (C) 2001-2003 Pavel Machek <pavel@suse.cz>
 */

#include <linux/acpi.h>
#include <linux/bootmem.h>
#include <asm/smp.h>


/* address in low memory of the wakeup routine. */
unsigned long acpi_wakeup_address = 0;
unsigned long acpi_video_flags;
extern char wakeup_start, wakeup_end;

extern void zap_low_mappings(void);

extern unsigned long FASTCALL(acpi_copy_wakeup_routine(unsigned long));

static void map_low(pgd_t *pgd_base, unsigned long start, unsigned long end)
{
	unsigned long vaddr;
	pmd_t *pmd;
	pgd_t *pgd;
	int i, j;

	pgd = pgd_base;

	for (i = 0; i < PTRS_PER_PGD; pgd++, i++) {
		vaddr = i*PGDIR_SIZE;
		if (end && (vaddr >= end))
			break;
		pmd = pmd_offset(pgd, 0);
		for (j = 0; j < PTRS_PER_PMD; pmd++, j++) {
			vaddr = i*PGDIR_SIZE + j*PMD_SIZE;
			if (end && (vaddr >= end))
				break;
			if (vaddr < start)
				continue;
			set_pmd(pmd, __pmd(_KERNPG_TABLE + _PAGE_PSE +
								vaddr - start));
		}
	}
}

/**
 * acpi_save_state_mem - save kernel state
 *
 * Create an identity mapped page table and copy the wakeup routine to
 * low memory.
 */
int acpi_save_state_mem (void)
{
	if (!acpi_wakeup_address)
		return 1;
	if (!cpu_has_pse)
		return 1;
	map_low(swapper_pg_dir, 0, LOW_MAPPINGS_SIZE);
	memcpy((void *) acpi_wakeup_address, &wakeup_start, &wakeup_end - &wakeup_start);
	acpi_copy_wakeup_routine(acpi_wakeup_address);

	return 0;
}

/**
 * acpi_save_state_disk - save kernel state to disk
 *
 */
int acpi_save_state_disk (void)
{
	return 1;
}

/*
 * acpi_restore_state
 */
void acpi_restore_state_mem (void)
{
	zap_low_mappings();
}

/**
 * acpi_reserve_bootmem - do _very_ early ACPI initialisation
 *
 * We allocate a page from the first 1MB of memory for the wakeup
 * routine for when we come back from a sleep state. The
 * runtime allocator allows specification of <16MB pages, but not
 * <1MB pages.
 */
void __init acpi_reserve_bootmem(void)
{
	if ((&wakeup_end - &wakeup_start) > PAGE_SIZE) {
		printk(KERN_ERR "ACPI: Wakeup code way too big, S3 disabled.\n");
		return;
	}

	acpi_wakeup_address = (unsigned long)alloc_bootmem_low(PAGE_SIZE);
	if (!acpi_wakeup_address)
		printk(KERN_ERR "ACPI: Cannot allocate lowmem, S3 disabled.\n");
}

static int __init acpi_sleep_setup(char *str)
{
	while ((str != NULL) && (*str != '\0')) {
		if (strncmp(str, "s3_bios", 7) == 0)
			acpi_video_flags = 1;
		if (strncmp(str, "s3_mode", 7) == 0)
			acpi_video_flags |= 2;
		str = strchr(str, ',');
		if (str != NULL)
			str += strspn(str, ", \t");
	}
	return 1;
}


__setup("acpi_sleep=", acpi_sleep_setup);

/*
 * Copyright 2004 James Cleverdon, IBM.
 * Subject to the GNU Public License, v.2
 *
 * Generic APIC sub-arch probe layer.
 *
 * Hacked for x86-64 by James Cleverdon from i386 architecture code by
 * Martin Bligh, Andi Kleen, James Bottomley, John Stultz, and
 * James Cleverdon.
 */
#include <linux/config.h>
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/smp.h>
#include <asm/ipi.h>

#if defined(CONFIG_ACPI_BUS)
#include <acpi/acpi_bus.h> 

#define FADT3_FEATURE_BIT_FORCE_APIC_PHYSICAL_DESTINATION_MODE (1 << 5)
#endif

/* which logical CPU number maps to which CPU (physical APIC ID) */
volatile char x86_cpu_to_apicid[NR_CPUS] = { [0 ... NR_CPUS-1] = BAD_APICID };
EXPORT_SYMBOL(x86_cpu_to_apicid);
u8 x86_cpu_to_log_apicid[NR_CPUS] = { [0 ... NR_CPUS-1] = BAD_APICID };

extern struct genapic apic_cluster;
extern struct genapic apic_flat;

struct genapic *genapic = &apic_flat;


/*
 * Check the APIC IDs in bios_cpu_apicid and choose the APIC mode.
 */
void __init clustered_apic_check(void)
{
	long i;
	u8 clusters, max_cluster;
	u8 id;
	u8 cluster_cnt[NUM_APIC_CLUSTERS];

#if defined(CONFIG_ACPI_BUS)
	/*
	 * This is ugly but this will look better once ACPI 3.0 is implemented.
	 * ACPI 3.0 adds 6 more fixed feature flags to the FADT (the one of
	 * interest is FORCE_APIC_PHYSICAL_MODE). Since we're still in 
	 * ACPI 2.0C, we compensate by tapping the reserved6 member which will
	 * contain the flag we're targetting for.
	 * 
	 * NOTE: THIS IS A TEMPORARY HACK! A more elegant solution based off of
	 *       ACPI 3.0 standards is here:
	 *       http://www.kernel.org/pub/linux/kernel/people/akpm/patches/2.6/2.6.12-rc2/2.6.12-rc2-mm3/broken-out/x86_64-genapic-update.patch
	 *
	 */
	if (acpi_fadt.revision > FADT2_REVISION_ID)
		if (acpi_fadt.reserved6 & FADT3_FEATURE_BIT_FORCE_APIC_PHYSICAL_DESTINATION_MODE) {
			printk(KERN_DEBUG "ACPI FADT FORCE_APIC_PHYSICAL_DESTINATION_MODE feature bit is set.\n");
			genapic = &apic_cluster;
			goto print;
		}
#endif
	memset(cluster_cnt, 0, sizeof(cluster_cnt));

	for (i = 0; i < NR_CPUS; i++) {
		id = bios_cpu_apicid[i];
		if (id != BAD_APICID)
			cluster_cnt[APIC_CLUSTERID(id)]++;
	}

	clusters = 0;
	max_cluster = 0;
	for (i = 0; i < NUM_APIC_CLUSTERS; i++) {
		if (cluster_cnt[i] > 0) {
			++clusters;
			if (cluster_cnt[i] > max_cluster)
				max_cluster = cluster_cnt[i];
		}
	}

	/*
	 * If we have clusters <= 1 and CPUs <= 8 in cluster 0, then flat mode,
	 * else if max_cluster <= 4 and cluster_cnt[15] == 0, clustered logical
	 * else physical mode.
	 * (We don't use lowest priority delivery + HW APIC IRQ steering, so
	 * can ignore the clustered logical case and go straight to physical.)
	 */
	if (clusters <= 1 && max_cluster <= 8 && cluster_cnt[0] == max_cluster)
		genapic = &apic_flat;
	else
		genapic = &apic_cluster;

print:
	printk(KERN_INFO "Setting APIC routing to %s\n", genapic->name);
}

/* Same for both flat and clustered. */

void send_IPI_self(int vector)
{
	__send_IPI_shortcut(APIC_DEST_SELF, vector, APIC_DEST_PHYSICAL);
}

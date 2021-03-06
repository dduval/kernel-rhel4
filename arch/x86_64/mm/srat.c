/*
 * ACPI 3.0 based NUMA setup
 * Copyright 2004 Andi Kleen, SuSE Labs.
 *
 * Reads the ACPI SRAT table to figure out what memory belongs to which CPUs.
 *
 * Called from acpi_numa_init while reading the SRAT and SLIT tables.
 * Assumes all memory regions belonging to a single proximity domain
 * are in one chunk. Holes between them will be included in the node.
 */

#include <linux/kernel.h>
#include <linux/acpi.h>
#include <linux/mmzone.h>
#include <linux/bitmap.h>
#include <asm/proto.h>
#include <asm/numa.h>

unsigned char apicid_to_node[MAX_APICS] = { [0 ... MAX_APICS-1] = 0xff };

static DECLARE_BITMAP(nodes_parsed, MAX_NUMNODES) __initdata;
static struct node nodes[MAX_NUMNODES] __initdata;
static __u8  pxm2node[256] __initdata = { [0 ... 255] = 0xff };

static __init int setup_node(int pxm)
{
	if (pxm2node[pxm] == 0xff) {
		if (numnodes > MAX_NUMNODES)
			return -1;
		pxm2node[pxm] = numnodes - 1;
		numnodes++;
	}
	return pxm2node[pxm];
}

static __init int conflicting_nodes(unsigned long start, unsigned long end)
{
	int i;
	for (i = 0; i < numnodes; i++) {
		struct node *nd = &nodes[i];
		if (nd->start == nd->end)
			continue;
		if (nd->end > start && nd->start < end)
			return 1;
		if (nd->end == end && nd->start == start)
			return 1;
	}
	return -1;
}

static __init void cutoff_node(int i, unsigned long start, unsigned long end)
{
	struct node *nd = &nodes[i];
	if (nd->start < start) {
		nd->start = start;
		if (nd->end < nd->start)
			nd->start = nd->end;
	}
	if (nd->end > end) {
		if (!(end & 0xfff))
			end--;
		nd->end = end;
		if (nd->start > nd->end)
			nd->start = nd->end;
	}
}

static __init void bad_srat(void)
{
	printk(KERN_ERR "SRAT: SRAT not used.\n");
	acpi_numa = 0;
}

static __init inline int srat_disabled(void)
{
	return numa_off || acpi_numa <= 0;
}

/* Callback for SLIT parsing */
void __init acpi_numa_slit_init(struct acpi_table_slit *slit)
{
	/* ignored for now */
}

/* Callback for Proximity Domain -> LAPIC mapping */
void __init
acpi_numa_processor_affinity_init(struct acpi_table_processor_affinity *pa)
{
	int pxm, node;
	if (srat_disabled() || pa->flags.enabled == 0)
		return;
	pxm = pa->proximity_domain;
	node = setup_node(pxm);
	if (node < 0) {
		printk(KERN_ERR "SRAT: Too many proximity domains %x\n", pxm);
		bad_srat();
		return;
	}
	apicid_to_node[pa->apic_id] = node;
	acpi_numa = 1;
	printk(KERN_INFO "SRAT: PXM %u -> APIC %u -> Node %u\n",
	       pxm, pa->apic_id, node);
}

/* Callback for parsing of the Proximity Domain <-> Memory Area mappings */
void __init
acpi_numa_memory_affinity_init(struct acpi_table_memory_affinity *ma)
{
	struct node *nd;
	unsigned long start, end;
	int node, pxm;
	int i;

	if (srat_disabled() || ma->flags.enabled == 0)
		return;
	/* hotplug bit is ignored for now */
	pxm = ma->proximity_domain;
	node = setup_node(pxm);
	if (node < 0) {
		printk(KERN_ERR "SRAT: Too many proximity domains.\n");
		bad_srat();
		return;
	}
	start = ma->base_addr_lo | ((u64)ma->base_addr_hi << 32);
	end = start + (ma->length_lo | ((u64)ma->length_hi << 32));
	i = conflicting_nodes(start, end);
	if (i >= 0) {
		printk(KERN_ERR
		       "SRAT: pxm %d overlap %lx-%lx with node %d(%Lx-%Lx)\n",
		       pxm, start, end, i, nodes[i].start, nodes[i].end);
		bad_srat();
		return;
	}
	nd = &nodes[node];
	if (!test_and_set_bit(node, &nodes_parsed)) {
		nd->start = start;
		nd->end = end;
	} else {
		if (start < nd->start)
			nd->start = start;
		if (nd->end < end)
			nd->end = end;
	}
	if (!(nd->end & 0xfff))
		nd->end--;
	printk(KERN_INFO "SRAT: Node %u PXM %u %Lx-%Lx\n", node, pxm,
	       nd->start, nd->end);
}

void __init acpi_numa_arch_fixup(void)
{
	numnodes--;
}

/* Use the information discovered above to actually set up the nodes. */
int __init acpi_scan_nodes(unsigned long start, unsigned long end)
{
	int i;
	if (acpi_numa <= 0)
		return -1;
	memnode_shift = compute_hash_shift(nodes);
	if (memnode_shift < 0) {
		printk(KERN_ERR
		     "SRAT: No NUMA node hash function found. Contact maintainer\n");
		bad_srat();
		return -1;
	}
	for (i = 0; i < MAX_NUMNODES; i++) {
		if (!test_bit(i, &nodes_parsed))
			continue;
		cutoff_node(i, start, end);
		if (nodes[i].start == nodes[i].end)
			continue;
		setup_node_bootmem(i, nodes[i].start, nodes[i].end);
	}
	numa_init_array();
	return 0;
}

void acpi_numa_setup_cpu(int cpu, int apicid)
{
	int node = apicid_to_node[apicid];

	if (node_online(node))
		cpu_to_node[cpu] = node;
	else 
		cpu_to_node[cpu] = find_first_bit(node_online_map, MAX_NUMNODES);
}

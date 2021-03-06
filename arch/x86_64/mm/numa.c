/* 
 * Generic VM initialization for x86-64 NUMA setups.
 * Copyright 2002,2003 Andi Kleen, SuSE Labs.
 */ 
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/mmzone.h>
#include <linux/ctype.h>
#include <linux/module.h>
#include <asm/e820.h>
#include <asm/proto.h>
#include <asm/dma.h>
#include <asm/numa.h>
#include <asm/acpi.h>

#ifndef Dprintk
#define Dprintk(x...)
#endif

struct pglist_data *node_data[MAX_NUMNODES];
bootmem_data_t plat_node_bdata[MAX_NUMNODES];

int memnode_shift;
u8  memnodemap[NODEMAPSIZE];

#define NUMA_NO_NODE 0xff
unsigned char cpu_to_node[NR_CPUS] = { [0 ... NR_CPUS-1] = NUMA_NO_NODE };
cpumask_t     node_to_cpumask[MAX_NUMNODES]; 

int numa_off __initdata = 0;

unsigned long nodes_present; 

int __init compute_hash_shift(struct node *nodes)
{
	int i; 
	int shift = 20;
	unsigned long addr,maxend=0;
	
	for (i = 0; i < numnodes; i++)
		if ((nodes[i].start != nodes[i].end) && (nodes[i].end > maxend))
				maxend = nodes[i].end;

	while ((1UL << shift) <  (maxend / NODEMAPSIZE))
		shift++;

	printk (KERN_DEBUG"Using %d for the hash shift. Max addr is %lx \n",
			shift,maxend);
	memset(memnodemap,0xff,sizeof(*memnodemap) * NODEMAPSIZE);
	for (i = 0; i < numnodes; i++) {
		if (nodes[i].start == nodes[i].end)
			continue;
		for (addr = nodes[i].start;
		     addr < nodes[i].end;
		     addr += (1UL << shift)) {
			if (memnodemap[addr >> shift] != 0xff) {
				printk(KERN_INFO
	"Your memory is not aligned you need to rebuild your kernel "
	"with a bigger NODEMAPSIZE shift=%d addr=%lu\n",
					shift,addr);
				return -1;
			} 
			memnodemap[addr >> shift] = i;
		} 
	} 
	return shift;
}



/* Initialize bootmem allocator for a node */
void __init setup_node_bootmem(int nodeid, unsigned long start, unsigned long end)
{ 
	unsigned long start_pfn, end_pfn, bootmap_pages, bootmap_size, bootmap_start; 
	unsigned long nodedata_phys;
	const int pgdat_size = round_up(sizeof(pg_data_t), PAGE_SIZE);

	start = round_up(start, ZONE_ALIGN); 

	printk("Bootmem setup node %d %016lx-%016lx\n", nodeid, start, end);

	start_pfn = start >> PAGE_SHIFT;
	end_pfn = end >> PAGE_SHIFT;

	nodedata_phys = find_e820_area(start, end, pgdat_size); 
	if (nodedata_phys == -1L) 
		panic("Cannot find memory pgdat in node %d\n", nodeid);

	Dprintk("nodedata_phys %lx\n", nodedata_phys); 

	node_data[nodeid] = phys_to_virt(nodedata_phys);
	memset(NODE_DATA(nodeid), 0, sizeof(pg_data_t));
	NODE_DATA(nodeid)->bdata = &plat_node_bdata[nodeid];
	NODE_DATA(nodeid)->node_start_pfn = start_pfn;
	NODE_DATA(nodeid)->node_spanned_pages = end_pfn - start_pfn;

	/* Find a place for the bootmem map */
	bootmap_pages = bootmem_bootmap_pages(end_pfn - start_pfn); 
	bootmap_start = round_up(nodedata_phys + pgdat_size, PAGE_SIZE);
	bootmap_start = find_e820_area(bootmap_start, end, bootmap_pages<<PAGE_SHIFT);
	if (bootmap_start == -1L) 
		panic("Not enough continuous space for bootmap on node %d", nodeid); 
	Dprintk("bootmap start %lu pages %lu\n", bootmap_start, bootmap_pages); 
	
	bootmap_size = init_bootmem_node(NODE_DATA(nodeid),
					 bootmap_start >> PAGE_SHIFT, 
					 start_pfn, end_pfn); 

	e820_bootmem_free(NODE_DATA(nodeid), start, end);

	reserve_bootmem_node(NODE_DATA(nodeid), nodedata_phys, pgdat_size); 
	reserve_bootmem_node(NODE_DATA(nodeid), bootmap_start, bootmap_pages<<PAGE_SHIFT);
	if (nodeid + 1 > numnodes)
		numnodes = nodeid + 1;
	node_set_online(nodeid);
} 

/* Initialize final allocator for a zone */
void __init setup_node_zones(int nodeid)
{ 
	unsigned long start_pfn, end_pfn, memmapsize, limit;
	unsigned long zones[MAX_NR_ZONES];
	unsigned long holes[MAX_NR_ZONES];
	unsigned long dma_end_pfn;

	memset(zones, 0, sizeof(unsigned long) * MAX_NR_ZONES); 
	memset(holes, 0, sizeof(unsigned long) * MAX_NR_ZONES);

	start_pfn = node_start_pfn(nodeid);
	end_pfn = node_end_pfn(nodeid);

	Dprintk(KERN_INFO "setting up node %d %lx-%lx\n", nodeid, start_pfn, end_pfn);
	
	/* All nodes > 0 have a zero length zone DMA */ 
	dma_end_pfn = __pa(MAX_DMA_ADDRESS) >> PAGE_SHIFT; 
	if (start_pfn < dma_end_pfn) { 
		zones[ZONE_DMA] = dma_end_pfn - start_pfn;
		holes[ZONE_DMA] = e820_hole_size(start_pfn, dma_end_pfn);
		zones[ZONE_NORMAL] = end_pfn - dma_end_pfn;
		holes[ZONE_NORMAL] = e820_hole_size(dma_end_pfn, end_pfn);
		
	} else { 
		zones[ZONE_NORMAL] = end_pfn - start_pfn; 
		holes[ZONE_NORMAL] = e820_hole_size(start_pfn, end_pfn);
	}

	/* Try to allocate mem_map at end to not fill up precious <4GB
	   memory. */
   	memmapsize = sizeof(struct page) * (end_pfn - start_pfn);
	limit = end_pfn << PAGE_SHIFT;
	NODE_DATA(nodeid)->node_mem_map =
		__alloc_bootmem_core(NODE_DATA(nodeid)->bdata,
				memmapsize, SMP_CACHE_BYTES,
				round_down(limit - memmapsize, PAGE_SIZE),
				limit);

	free_area_init_node(nodeid, NODE_DATA(nodeid), zones,
			    start_pfn, holes); 
} 

void __init numa_init_array(void)
{
	int rr, i;


	/* There are unfortunately some poorly designed mainboards around
	   that only connect memory to a single CPU. This breaks the 1:1 
	   cpu->node mapping. If we don't have an ACPI SRAT table available
	   to tell us about the NUMA configuration, fill in the mapping for all 
	   possible CPUs, as the number of CPUs is not known yet. 
	   We round robin the existing nodes. */
	rr = 0;
	for (i = 0; i < MAX_NUMNODES; i++) {
		if (node_online(i))
			continue;
		if (cpu_to_node[i] != NUMA_NO_NODE)
			continue;
		rr = find_next_bit(node_online_map, MAX_NUMNODES, rr);
		if (rr == MAX_NUMNODES)
			rr = find_first_bit(node_online_map, MAX_NUMNODES);
		node_data[i] = node_data[rr];
		cpu_to_node[i] = rr;
		rr++; 
	}

}

int numa_fake __initdata = 0;

/* Numa emulation */
static int numa_emulation(unsigned long start_pfn, unsigned long end_pfn)
{
 	int i;
 	struct node nodes[MAX_NUMNODES];
 	unsigned long sz = ((end_pfn - start_pfn)<<PAGE_SHIFT) / numa_fake;

 	/* Kludge needed for the hash function */
 	if (hweight64(sz) > 1) {
 		unsigned long x = 1;
 		while ((x << 1) < sz)
 			x <<= 1;
 		if (x < sz/2)
 			printk("Numa emulation unbalanced. Complain to maintainer\n");
 		sz = x;
 	}

 	memset(&nodes,0,sizeof(nodes));
 	for (i = 0; i < numa_fake; i++) {
 		nodes[i].start = (start_pfn<<PAGE_SHIFT) + i*sz;
 		if (i == numa_fake-1)
 			sz = (end_pfn<<PAGE_SHIFT) - nodes[i].start;
 		nodes[i].end = nodes[i].start + sz;
 		if (i != numa_fake-1)
 			nodes[i].end--;
 		printk(KERN_INFO "Faking node %d at %016Lx-%016Lx (%LuMB)\n",
 		       i,
 		       nodes[i].start, nodes[i].end,
 		       (nodes[i].end - nodes[i].start) >> 20);
 	}
 	numnodes = numa_fake;
 	memnode_shift = compute_hash_shift(nodes);
 	if (memnode_shift < 0) {
 		memnode_shift = 0;
 		printk(KERN_ERR "No NUMA hash function found. Emulation disabled.\n");
 		return -1;
 	}
 	for (i = 0; i < numa_fake; i++)
 		setup_node_bootmem(i, nodes[i].start, nodes[i].end);
 	numa_init_array();
 	return 0;
}

void __init numa_initmem_init(unsigned long start_pfn, unsigned long end_pfn)
{ 
	int i;

	if (numa_fake && !numa_emulation(start_pfn, end_pfn))
 		return;

#ifdef CONFIG_ACPI_NUMA
	if (!numa_off && !acpi_scan_nodes(start_pfn << PAGE_SHIFT,
					  end_pfn << PAGE_SHIFT))
 		return;
#endif

#ifdef CONFIG_K8_NUMA
	if (!numa_off && !k8_scan_nodes(start_pfn<<PAGE_SHIFT, end_pfn<<PAGE_SHIFT))
		return;
#endif
	printk(KERN_INFO "%s\n",
	       numa_off ? "NUMA turned off" : "No NUMA configuration found");

	printk(KERN_INFO "Faking a node at %016lx-%016lx\n", 
	       start_pfn << PAGE_SHIFT,
	       end_pfn << PAGE_SHIFT); 
		/* setup dummy node covering all memory */ 
	memnode_shift = 63; 
	memnodemap[0] = 0;
	numnodes = 1;
	for (i = 0; i < NR_CPUS; i++)
		cpu_to_node[i] = 0;
	node_to_cpumask[0] = cpumask_of_cpu(0);
	setup_node_bootmem(0, start_pfn << PAGE_SHIFT, end_pfn << PAGE_SHIFT);
}

__init void numa_add_cpu(int cpu)
{
	/* If we're not using ACPI SRAT NUMA config,
	 * then the boot processor is initialized elsewhere 
	 */
	set_bit(cpu, &node_to_cpumask[cpu_to_node(cpu)]);
} 

unsigned long __init numa_free_all_bootmem(void) 
{ 
	int i;
	unsigned long pages = 0;
	for_all_nodes(i) {
		pages += free_all_bootmem_node(NODE_DATA(i));
	}
	return pages;
} 

void __init paging_init(void)
{ 
	int i;
	for_all_nodes(i) { 
		setup_node_zones(i); 
	}
} 

/* [numa=off] */
__init int numa_setup(char *opt) 
{ 
	if (!strcmp(opt,"off"))
		numa_off = 1;
	if (!strcmp(opt,"on"))
		numa_off = 0;
	if(!strncmp(opt, "fake=", 5)) {
		numa_fake = simple_strtoul(opt+5,NULL,0); ;
		if (numa_fake >= MAX_NUMNODES)
			numa_fake = MAX_NUMNODES;
	}
#ifdef CONFIG_ACPI_NUMA
	if (!strncmp(opt,"acpi",4))
		acpi_numa = 1;
	else if (!strncmp(opt, "noacpi", 6))
		acpi_numa = 0;
#endif
	return 1;
} 

EXPORT_SYMBOL(cpu_to_node);
EXPORT_SYMBOL(node_to_cpumask);
EXPORT_SYMBOL(memnode_shift);
EXPORT_SYMBOL(memnodemap);
EXPORT_SYMBOL(node_data);

/*
 *      Routines to indentify caches on Intel CPU.
 *
 *      Changes:
 *      Venkatesh Pallipadi	: Adding cache identification through cpuid(4)
 *	Andi Kleen / Andreas Herrmann	: CPUID4 emulation on AMD.
 */

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/compiler.h>
#include <linux/cpu.h>

#include <asm/processor.h>
#include <asm/smp.h>

#define LVL_1_INST	1
#define LVL_1_DATA	2
#define LVL_2		3
#define LVL_3		4
#define LVL_TRACE	5

#ifndef CONFIG_X86_64
extern int smp_num_cores;
#endif

struct _cache_table
{
	unsigned char descriptor;
	char cache_type;
	short size;
};

/* all the cache descriptor types we care about (no TLB or trace cache entries) */
static struct _cache_table cache_table[] __initdata =
{
	{ 0x06, LVL_1_INST, 8 },	/* 4-way set assoc, 32 byte line size */
	{ 0x08, LVL_1_INST, 16 },	/* 4-way set assoc, 32 byte line size */
	{ 0x0a, LVL_1_DATA, 8 },	/* 2 way set assoc, 32 byte line size */
	{ 0x0c, LVL_1_DATA, 16 },	/* 4-way set assoc, 32 byte line size */
	{ 0x22, LVL_3,      512 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x23, LVL_3,      1024 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x25, LVL_3,      2048 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x29, LVL_3,      4096 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x2c, LVL_1_DATA, 32 },	/* 8-way set assoc, 64 byte line size */
	{ 0x30, LVL_1_INST, 32 },	/* 8-way set assoc, 64 byte line size */
	{ 0x39, LVL_2,      128 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x3b, LVL_2,      128 },	/* 2-way set assoc, sectored cache, 64 byte line size */
	{ 0x3c, LVL_2,      256 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x41, LVL_2,      128 },	/* 4-way set assoc, 32 byte line size */
	{ 0x42, LVL_2,      256 },	/* 4-way set assoc, 32 byte line size */
	{ 0x43, LVL_2,      512 },	/* 4-way set assoc, 32 byte line size */
	{ 0x44, LVL_2,      1024 },	/* 4-way set assoc, 32 byte line size */
	{ 0x45, LVL_2,      2048 },	/* 4-way set assoc, 32 byte line size */
	{ 0x60, LVL_1_DATA, 16 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x66, LVL_1_DATA, 8 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x67, LVL_1_DATA, 16 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x68, LVL_1_DATA, 32 },	/* 4-way set assoc, sectored cache, 64 byte line size */
	{ 0x70, LVL_TRACE,  12 },	/* 8-way set assoc */
	{ 0x71, LVL_TRACE,  16 },	/* 8-way set assoc */
	{ 0x72, LVL_TRACE,  32 },	/* 8-way set assoc */
	{ 0x78, LVL_2,    1024 },	/* 4-way set assoc, 64 byte line size */
	{ 0x79, LVL_2,     128 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x7a, LVL_2,     256 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x7b, LVL_2,     512 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x7c, LVL_2,    1024 },	/* 8-way set assoc, sectored cache, 64 byte line size */
	{ 0x7d, LVL_2,    2048 },	/* 8-way set assoc, 64 byte line size */
	{ 0x7f, LVL_2,     512 },	/* 2-way set assoc, 64 byte line size */
	{ 0x82, LVL_2,     256 },	/* 8-way set assoc, 32 byte line size */
	{ 0x83, LVL_2,     512 },	/* 8-way set assoc, 32 byte line size */
	{ 0x84, LVL_2,    1024 },	/* 8-way set assoc, 32 byte line size */
	{ 0x85, LVL_2,    2048 },	/* 8-way set assoc, 32 byte line size */
	{ 0x86, LVL_2,     512 },	/* 4-way set assoc, 64 byte line size */
	{ 0x87, LVL_2,    1024 },	/* 8-way set assoc, 64 byte line size */
	{ 0x00, 0, 0}
};


enum _cache_type
{
	CACHE_TYPE_NULL	= 0,
	CACHE_TYPE_DATA = 1,
	CACHE_TYPE_INST = 2,
	CACHE_TYPE_UNIFIED = 3
};

union _cpuid4_leaf_eax {
	struct {
		enum _cache_type	type:5;
		unsigned int		level:3;
		unsigned int		is_self_initializing:1;
		unsigned int		is_fully_associative:1;
		unsigned int		reserved:4;
		unsigned int		num_threads_sharing:12;
		unsigned int		num_cores_on_die:6;
	} split;
	u32 full;
};

union _cpuid4_leaf_ebx {
	struct {
		unsigned int		coherency_line_size:12;
		unsigned int		physical_line_partition:10;
		unsigned int		ways_of_associativity:10;
	} split;
	u32 full;
};

union _cpuid4_leaf_ecx {
	struct {
		unsigned int		number_of_sets:32;
	} split;
	u32 full;
};

struct _cpuid4_info {
	union _cpuid4_leaf_eax eax;
	union _cpuid4_leaf_ebx ebx;
	union _cpuid4_leaf_ecx ecx;
	unsigned long size;
	cpumask_t shared_cpu_map;
};

#define MAX_CACHE_LEAVES		4
unsigned short __devinitdata	num_cache_leaves;

/* AMD doesn't have CPUID4. Emulate it here to report the same
   information to the user.  This makes some assumptions about the machine:
   L2 not shared, no SMT etc. that is currently true on AMD CPUs.

   In theory the TLBs could be reported as fake type (they are in "dummy").
   Maybe later */
union l1_cache {
	struct {
		unsigned line_size : 8;
		unsigned lines_per_tag : 8;
		unsigned assoc : 8;
		unsigned size_in_kb : 8;
	};
	unsigned val;
};

union l2_cache {
	struct {
		unsigned line_size : 8;
		unsigned lines_per_tag : 4;
		unsigned assoc : 4;
		unsigned size_in_kb : 16;
	};
	unsigned val;
};

union l3_cache {
	struct {
		unsigned line_size : 8;
		unsigned lines_per_tag : 4;
		unsigned assoc : 4;
		unsigned res : 2;
		unsigned size_encoded : 14;
	};
	unsigned val;
};

static unsigned short assocs[] = {
	[1] = 1, [2] = 2, [4] = 4, [6] = 8,
	[8] = 16, [0xa] = 32, [0xb] = 48,
	[0xc] = 64,
	[0xf] = 0xffff // ??
};
static const unsigned char levels[] = { 1, 1, 2, 3 };
static const unsigned char types[] = { 1, 2, 3, 3 };

static void __cpuinit amd_cpuid4(int leaf, union _cpuid4_leaf_eax *eax,
		       union _cpuid4_leaf_ebx *ebx,
		       union _cpuid4_leaf_ecx *ecx)
{
	unsigned dummy;
	unsigned line_size, lines_per_tag, assoc, size_in_kb;
	union l1_cache l1i, l1d;
	union l2_cache l2;
	union l3_cache l3;
	union l1_cache *l1 = &l1d;

	eax->full = 0;
	ebx->full = 0;
	ecx->full = 0;

	cpuid(0x80000005, &dummy, &dummy, &l1d.val, &l1i.val);
	cpuid(0x80000006, &dummy, &dummy, &l2.val, &l3.val);


	switch (leaf) {
	case 1:
		l1 = &l1i;
	case 0:
		if (!l1->val)
			return;
		assoc = l1->assoc;
		line_size = l1->line_size;
		lines_per_tag = l1->lines_per_tag;
		size_in_kb = l1->size_in_kb;
	case 2:
		if (!l2.val)
			return;
		assoc = l2.assoc;
		line_size = l2.line_size;
		lines_per_tag = l2.lines_per_tag;
		/* cpu_data has errata corrections for K7 applied */
		size_in_kb = current_cpu_data.x86_cache_size;
		break;
	case 3:
		if (!l3.val)
			return;
		assoc = l3.assoc;
		line_size = l3.line_size;
		lines_per_tag = l3.lines_per_tag;
		switch (l3.size_encoded) {
		case 4:  size_in_kb = 2 * 1024; break;
		case 8:  size_in_kb = 4 * 1024; break;
		case 12: size_in_kb = 6 * 1024; break;
		default: size_in_kb = 0; break;
		}
		break;
	default:
		return;	
	}

	eax->split.is_self_initializing = 1;
	eax->split.type = types[leaf];
	eax->split.level = levels[leaf];
	eax->split.num_threads_sharing = 0;
#ifdef CONFIG_SMP
#ifdef CONFIG_X86_64
	eax->split.num_cores_on_die = current_cpu_data.x86_num_cores - 1;
#else
	eax->split.num_cores_on_die = smp_num_cores - 1;
#endif
#else
	eax->split.num_cores_on_die = 1;
#endif	
	

	if (assoc == 0xf)
		eax->split.is_fully_associative = 1;
	ebx->split.coherency_line_size = line_size - 1;
	ebx->split.ways_of_associativity = assocs[assoc] - 1;
	ebx->split.physical_line_partition = lines_per_tag - 1;
	ecx->split.number_of_sets = (size_in_kb * 1024) / line_size /
		(ebx->split.ways_of_associativity + 1) - 1;
}

static int __init cpuid4_cache_lookup(int index, struct _cpuid4_info *this_leaf)
{
	union _cpuid4_leaf_eax 	eax;
	union _cpuid4_leaf_ebx 	ebx;
	union _cpuid4_leaf_ecx 	ecx;
	unsigned		edx;

	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD)
		amd_cpuid4(index, &eax, &ebx, &ecx);
	else
		cpuid_count(4, index, &eax.full, &ebx.full, &ecx.full,  &edx);
	if (eax.split.type == CACHE_TYPE_NULL)
		return -1;

	this_leaf->eax = eax;
	this_leaf->ebx = ebx;
	this_leaf->ecx = ecx;
	this_leaf->size = (ecx.split.number_of_sets + 1) *
		(ebx.split.coherency_line_size + 1) *
		(ebx.split.physical_line_partition + 1) *
		(ebx.split.ways_of_associativity + 1);
	return 0;
}

static int __init find_num_cache_leaves(void)
{
	unsigned int		eax, ebx, ecx, edx;
	union _cpuid4_leaf_eax	cache_eax;
	int 			i;
	int 			retval;

	retval = MAX_CACHE_LEAVES;
	/* Do cpuid(4) loop to find out num_cache_leaves */
	for (i = 0; i < MAX_CACHE_LEAVES; i++) {
		cpuid_count(4, i, &eax, &ebx, &ecx, &edx);
		cache_eax.full = eax;
		if (cache_eax.split.type == CACHE_TYPE_NULL) {
			retval = i;
			break;
		}
	}
	return retval;
}

static __inline__ int get_count_order(unsigned int count)
{
	int order;

	order = fls(count) - 1;
	if (count & (count - 1))
		order++;
	return order;
}


unsigned int __init init_intel_cacheinfo(struct cpuinfo_x86 *c)
{
	unsigned int trace = 0, l1i = 0, l1d = 0, l2 = 0, l3 = 0; /* Cache sizes */
	int i;
#ifndef CONFIG_X86_64
	unsigned int eax, ebx, ecx, edx;
#endif
	int      initial_apic_id;
	unsigned int l2_id = 0, l3_id = 0, num_threads_sharing, index_msb;
	unsigned int l2_id_valid = 0, l3_id_valid = 0;
#ifdef CONFIG_SMP
	unsigned int cpu = (c == &boot_cpu_data) ? 0 : (c - cpu_data);
#endif


	/*
	 * for now follow the same mechanism that is being used for
	 * HT detection in EL4 kernels...
	 */
#ifdef CONFIG_X86_64
	initial_apic_id = hard_smp_processor_id();
#else
	cpuid(1, &eax, &ebx, &ecx, &edx);
	initial_apic_id = (ebx >> 24) & 0xff;
#endif

	if (c->cpuid_level > 3) {
		static int is_initialized;

		if (is_initialized == 0) {
			/* Init num_cache_leaves from boot CPU */
			num_cache_leaves = find_num_cache_leaves();
			is_initialized++;
		}

		/*
		 * Whenever possible use cpuid(4), deterministic cache 
		 * parameters cpuid leaf to find the cache details
		 */
		for (i = 0; i < num_cache_leaves; i++) {
			struct _cpuid4_info this_leaf;

			int retval;

			retval = cpuid4_cache_lookup(i, &this_leaf);
			if (retval >= 0) {
				switch(this_leaf.eax.split.level) {
				    case 1:
					if (this_leaf.eax.split.type == 
							CACHE_TYPE_DATA)
						l1d = this_leaf.size/1024;
					else if (this_leaf.eax.split.type == 
							CACHE_TYPE_INST)
						l1i = this_leaf.size/1024;
					break;
				    case 2:
					l2 = this_leaf.size/1024;
					num_threads_sharing = 1 + this_leaf.eax.split.num_threads_sharing;
					index_msb = get_count_order(num_threads_sharing);
					l2_id = initial_apic_id >> index_msb;
					l2_id_valid = 1;

					break;
				    case 3:
					l3 = this_leaf.size/1024;
					num_threads_sharing = 1 + this_leaf.eax.split.num_threads_sharing;
					index_msb = get_count_order(num_threads_sharing);
					l3_id = initial_apic_id >> index_msb;
					l3_id_valid = 1;
					break;
				    default:
					break;
				}
			}
		}
	}

	/*
	 * Don't use cpuid2 if cpuid4 is supported. For P4, we use cpuid2 for
	 * trace cache
	 */
	if ((num_cache_leaves == 0 || c->x86 == 15) && c->cpuid_level > 1) {
		/* supports eax=2  call */
		int i, j, n;
		int regs[4];
		unsigned char *dp = (unsigned char *)regs;
		int only_trace = 0;

		if (num_cache_leaves != 0 && c->x86 == 15)
			only_trace = 1;

		/* Number of times to iterate */
		n = cpuid_eax(2) & 0xFF;

		for ( i = 0 ; i < n ; i++ ) {
			cpuid(2, &regs[0], &regs[1], &regs[2], &regs[3]);

			/* If bit 31 is set, this is an unknown format */
			for ( j = 0 ; j < 3 ; j++ ) {
				if ( regs[j] < 0 ) regs[j] = 0;
			}

			/* Byte 0 is level count, not a descriptor */
			for ( j = 1 ; j < 16 ; j++ ) {
				unsigned char des = dp[j];
				unsigned char k = 0;

				/* look up this descriptor in the table */
				while (cache_table[k].descriptor != 0)
				{
					if (cache_table[k].descriptor == des) {
						if (only_trace &&
						    cache_table[k].cache_type != LVL_TRACE)
							break;

						switch (cache_table[k].cache_type) {
						case LVL_1_INST:
							l1i += cache_table[k].size;
							break;
						case LVL_1_DATA:
							l1d += cache_table[k].size;
							break;
						case LVL_2:
							l2 += cache_table[k].size;
							break;
						case LVL_3:
							l3 += cache_table[k].size;
							break;
						case LVL_TRACE:
							trace += cache_table[k].size;
							break;
						}

						break;
					}

					k++;
				}
			}
		}
	}

	if ( trace )
		printk (KERN_INFO "CPU: Trace cache: %dK uops", trace);
	else if ( l1i )
		printk (KERN_INFO "CPU: L1 I cache: %dK", l1i);
	if ( l1d )
		printk(", L1 D cache: %dK\n", l1d);
	else
		printk("\n");
	if ( l2 )
		printk(KERN_INFO "CPU: L2 cache: %dK\n", l2);

	if ( l3 )
		printk(KERN_INFO "CPU: L3 cache: %dK\n", l3);

	c->x86_cache_size = l3 ? l3 : (l2 ? l2 : (l1i+l1d));

#ifdef CONFIG_SMP
	if (l3_id_valid)
		cpu_llc_id[cpu] = l3_id;
	else if (l2_id_valid)
		cpu_llc_id[cpu] = l2_id;
#endif

	return l2;
}

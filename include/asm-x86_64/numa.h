#ifndef _ASM_X8664_NUMA_H 
#define _ASM_X8664_NUMA_H 1

#ifdef CONFIG_DISCONTIGMEM
#include <asm/numnodes.h>
#else
#define NODES_SHIFT 0
#endif

struct node { 
	u64 start,end; 
};

#define for_all_nodes(x) for ((x) = 0; (x) < numnodes; (x)++) \
				if (node_online(x))

extern int compute_hash_shift(struct node *nodes);

#define ZONE_ALIGN (1UL << (MAX_ORDER+PAGE_SHIFT))

extern void numa_add_cpu(int cpu);
extern void numa_init_array(void);
extern int numa_off;

#endif

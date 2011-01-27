/*
 *	Generic address resultion entity
 *
 *	Authors:
 *	net_random Alan Cox
 *	net_ratelimit Andy Kleen
 *
 *	Created by Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/bootmem.h>

#include <asm/system.h>
#include <asm/uaccess.h>


/*
  This is a maximally equidistributed combined Tausworthe generator
  based on code from GNU Scientific Library 1.5 (30 Jun 2004)

   x_n = (s1_n ^ s2_n ^ s3_n) 

   s1_{n+1} = (((s1_n & 4294967294) <<12) ^ (((s1_n <<13) ^ s1_n) >>19))
   s2_{n+1} = (((s2_n & 4294967288) << 4) ^ (((s2_n << 2) ^ s2_n) >>25))
   s3_{n+1} = (((s3_n & 4294967280) <<17) ^ (((s3_n << 3) ^ s3_n) >>11))

   The period of this generator is about 2^88.

   From: P. L'Ecuyer, "Maximally Equidistributed Combined Tausworthe
   Generators", Mathematics of Computation, 65, 213 (1996), 203--213.

   This is available on the net from L'Ecuyer's home page,

   http://www.iro.umontreal.ca/~lecuyer/myftp/papers/tausme.ps
   ftp://ftp.iro.umontreal.ca/pub/simulation/lecuyer/papers/tausme.ps 

   There is an erratum in the paper "Tables of Maximally
   Equidistributed Combined LFSR Generators", Mathematics of
   Computation, 68, 225 (1999), 261--269:
   http://www.iro.umontreal.ca/~lecuyer/myftp/papers/tausme2.ps

        ... the k_j most significant bits of z_j must be non-
        zero, for each j. (Note: this restriction also applies to the 
        computer code given in [4], but was mistakenly not mentioned in
        that paper.)
   
   This affects the seeding procedure by imposing the requirement
   s1 > 1, s2 > 7, s3 > 15.

*/
struct nrnd_state {
	u32 s1, s2, s3;
};

static DEFINE_PER_CPU(struct nrnd_state, net_rand_state);

static u32 __net_random(struct nrnd_state *state)
{
#define TAUSWORTHE(s,a,b,c,d) ((s&c)<<d) ^ (((s <<a) ^ s)>>b)

	state->s1 = TAUSWORTHE(state->s1, 13, 19, 4294967294UL, 12);
	state->s2 = TAUSWORTHE(state->s2, 2, 25, 4294967288UL, 4);
	state->s3 = TAUSWORTHE(state->s3, 3, 11, 4294967280UL, 17);

	return (state->s1 ^ state->s2 ^ state->s3);
}

/*
 * Handle minimum values for seeds
 */
static inline u32 __seed(u32 x, u32 m)
{
	return (x < m) ? x + m : x;
}


unsigned long net_random(void)
{
	unsigned long r;
	struct nrnd_state *state = &get_cpu_var(net_rand_state);
	r = __net_random(state);
	put_cpu_var(state);
	return r;
}


void net_srandom(unsigned long entropy)
{
	int i;
	/*
	 * No locking on the CPUs, but then somewhat random results are, well,
	 * expected.
	 */
	for_each_possible_cpu (i) {
		struct nrnd_state *state = &per_cpu(net_rand_state, i);
		state->s1 = __seed(state->s1 ^ entropy, 1);
	}
}

void __init net_random_init(void)
{
	int i;

	for_each_possible_cpu (i) {
		struct nrnd_state *state = &per_cpu(net_rand_state,i);

#define LCG(x) ((x) * 69069)   /* super-duper LCG */
		state->s1 = __seed(LCG(i + jiffies), 1);
		state->s2 = __seed(LCG(state->s1), 7);
		state->s3 = __seed(LCG(state->s2), 15);

		/* "warm it up" */
		__net_random(state);
		__net_random(state);
		__net_random(state);
		__net_random(state);
		__net_random(state);
		__net_random(state);
	}
}

static int net_random_reseed(void)
{
	int i;
	unsigned long seed[NR_CPUS];

	get_random_bytes(seed, sizeof(seed));
	for_each_possible_cpu (i) {
		struct nrnd_state *state = &per_cpu(net_rand_state,i);
		u32 seeds[3];

		get_random_bytes(&seeds, sizeof(seeds));
		state->s1 = __seed(seeds[0], 1);
		state->s2 = __seed(seeds[1], 7);
		state->s3 = __seed(seeds[2], 15);

		/* mix it in */
		__net_random(state);
	}
	return 0;
}
late_initcall(net_random_reseed);

int net_msg_cost = 5*HZ;
int net_msg_burst = 10;

/* 
 * All net warning printk()s should be guarded by this function.
 */ 
int net_ratelimit(void)
{
	return __printk_ratelimit(net_msg_cost, net_msg_burst);
}

void * __init net_alloc_hash(const char *tablename,
			     unsigned long bucketsize,
			     unsigned long numentries,
			     int scale,
			     unsigned int *_hash_shift,
			     unsigned int *_hash_mask,
			     unsigned long limit)
{
	unsigned long long max = limit;
	unsigned long log2qty, size, order;
	void *table;

	/* allow the kernel cmdline to have a say */
	if (!numentries) {
		/* round applicable memory size up to nearest megabyte */
		numentries = nr_all_pages;
		numentries += (1UL << (20 - PAGE_SHIFT)) - 1;
		numentries >>= 20 - PAGE_SHIFT;
		numentries <<= 20 - PAGE_SHIFT;

		/* limit to 1 bucket per 2^scale bytes of low memory */
		if (scale > PAGE_SHIFT)
			numentries >>= (scale - PAGE_SHIFT);
		else
			numentries <<= (PAGE_SHIFT - scale);
	}
	/* rounded up to nearest power of 2 in size */
	numentries = 1UL << (long_log2(numentries) + 1);

	/* limit allocation size to 1/16 total memory by default */
	if (max == 0) {
		max = ((unsigned long long) nr_all_pages << PAGE_SHIFT) >> 4;
		do_div(max, bucketsize);
	}

	if (numentries > max)
		numentries = max;

	log2qty = long_log2(numentries);

	do {
		size = bucketsize << log2qty;

		for (order = 0; ((1UL << order) << PAGE_SHIFT) < size; order++)
			;
		table = (void *) __get_free_pages(GFP_ATOMIC, order);
	} while (!table && size > PAGE_SIZE && --log2qty);

	if (!table)
		panic("Failed to allocate %s hash table\n", tablename);

	printk(KERN_INFO "%s hash table entries: %d (order: %d, %lu bytes)\n",
	       tablename,
	       (1U << log2qty),
	       long_log2(size) - PAGE_SHIFT,
	       size);

	if (_hash_shift)
		*_hash_shift = log2qty;

	if (_hash_mask)
		*_hash_mask = (1UL << log2qty) - 1;

	return table;
}


EXPORT_SYMBOL(net_random);
EXPORT_SYMBOL(net_ratelimit);
EXPORT_SYMBOL(net_srandom);

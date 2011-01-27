/*
 * This is only required for older kernels that
 * do not have bioset functions exported by bio.h.
 */
#ifndef __DM_BIOSETS_H__
#define __DM_BIOSETS_H__

#include <linux/bio.h>
#include <linux/mempool.h>

#define BIOVEC_NR_POOLS	6

struct bio_set;

extern struct bio_set *bioset_create(int bio_pool_size,
				int bvec_pool_size, int scale);
extern void bioset_free(struct bio_set *bs);
extern struct bio *bio_alloc_bioset(gfp_t gfp_mask, int nr_iovecs,
				struct bio_set *bs);
extern void bio_free(struct bio *bio, struct bio_set *bio_set);

extern int dm_bs_init(void);
extern void dm_bs_exit(void);

#endif /* __DM_BIOSETS_H__ */

/*
 * This is only required for older kernels that
 * do not have bioset functions exported by bio.h.
 */
#include <asm/semaphore.h>
#include <linux/slab.h>

#include "dm.h"
#include "dm-biosets.h"

kmem_cache_t *dm_bs_bio_slab = NULL;

struct biovec_slab {
	int nr_vecs;
	char *name;
	kmem_cache_t *slab;
};

/*
 * if you change this list, also change bvec_alloc or things will
 * break badly! cannot be bigger than what you can fit into an
 * unsigned short
 */

#define BV(x) { .nr_vecs = x, .name = "dm-bvec-"__stringify(x) }
static struct biovec_slab dm_bs_bvec_slabs[BIOVEC_NR_POOLS] = {
	BV(1), BV(4), BV(16), BV(64), BV(128), BV(BIO_MAX_PAGES),
};
#undef BV

/*
 * bio_set is used to allow other portions of the IO system to
 * allocate their own private memory pools for bio and iovec structures.
 * These memory pools in turn all allocate from the bio_slab
 * and the bvec_slabs[].
 */
struct bio_set {
	mempool_t *bio_pool;
	mempool_t *bvec_pools[BIOVEC_NR_POOLS];
};

static inline struct bio_vec *bvec_alloc_bs(gfp_t gfp_mask, int nr, unsigned long *idx, struct bio_set *bs)
{
	struct bio_vec *bvl;

	/*
	 * see comment near bvec_array define!
	 */
	switch (nr) {
		case   1        : *idx = 0; break;
		case   2 ...   4: *idx = 1; break;
		case   5 ...  16: *idx = 2; break;
		case  17 ...  64: *idx = 3; break;
		case  65 ... 128: *idx = 4; break;
		case 129 ... BIO_MAX_PAGES: *idx = 5; break;
		default:
			return NULL;
	}
	/*
	 * idx now points to the pool we want to allocate from
	 */

	bvl = mempool_alloc(bs->bvec_pools[*idx], gfp_mask);
	if (bvl) {
		struct biovec_slab *bp = dm_bs_bvec_slabs + *idx;

		memset(bvl, 0, bp->nr_vecs * sizeof(struct bio_vec));
	}

	return bvl;
}

void bio_free(struct bio *bio, struct bio_set *bio_set)
{
	const int pool_idx = BIO_POOL_IDX(bio);

	BIO_BUG_ON(pool_idx >= BIOVEC_NR_POOLS);

	mempool_free(bio->bi_io_vec, bio_set->bvec_pools[pool_idx]);
	mempool_free(bio, bio_set->bio_pool);
}

void bio_init(struct bio *bio)
{
	bio->bi_next = NULL;
	bio->bi_bdev = NULL;
	bio->bi_flags = 1 << BIO_UPTODATE;
	bio->bi_rw = 0;
	bio->bi_vcnt = 0;
	bio->bi_idx = 0;
	bio->bi_phys_segments = 0;
	bio->bi_hw_segments = 0;
	bio->bi_hw_front_size = 0;
	bio->bi_hw_back_size = 0;
	bio->bi_size = 0;
	bio->bi_max_vecs = 0;
	bio->bi_end_io = NULL;
	atomic_set(&bio->bi_cnt, 1);
	bio->bi_private = NULL;
}

/**
 * bio_alloc_bioset - allocate a bio for I/O
 * @gfp_mask:   the GFP_ mask given to the slab allocator
 * @nr_iovecs:	number of iovecs to pre-allocate
 * @bs:		the bio_set to allocate from
 *
 * Description:
 *   bio_alloc_bioset will first try it's on mempool to satisfy the allocation.
 *   If %__GFP_WAIT is set then we will block on the internal pool waiting
 *   for a &struct bio to become free.
 *
 *   allocate bio and iovecs from the memory pools specified by the
 *   bio_set structure.
 **/
struct bio *bio_alloc_bioset(gfp_t gfp_mask, int nr_iovecs, struct bio_set *bs)
{
	struct bio *bio = mempool_alloc(bs->bio_pool, gfp_mask);

	if (likely(bio)) {
		struct bio_vec *bvl = NULL;

		bio_init(bio);
		if (likely(nr_iovecs)) {
			unsigned long idx = 0; /* shut up gcc */

			bvl = bvec_alloc_bs(gfp_mask, nr_iovecs, &idx, bs);
			if (unlikely(!bvl)) {
				mempool_free(bio, bs->bio_pool);
				bio = NULL;
				goto out;
			}
			bio->bi_flags |= idx << BIO_POOL_OFFSET;
			bio->bi_max_vecs = dm_bs_bvec_slabs[idx].nr_vecs;
		}
		bio->bi_io_vec = bvl;
	}
out:
	return bio;
}

/*
 * create memory pools for biovec's in a bio_set.
 * use the global biovec slabs created for general use.
 */
static int biovec_create_pools(struct bio_set *bs, int pool_entries, int scale)
{
	int i;

	for (i = 0; i < BIOVEC_NR_POOLS; i++) {
		struct biovec_slab *bp  = dm_bs_bvec_slabs + i;
		mempool_t **bvp = bs->bvec_pools + i;

		if (pool_entries > 1 && i >= scale)
			pool_entries >>= 1;

		*bvp = mempool_create(pool_entries, mempool_alloc_slab,
				mempool_free_slab, bp->slab);
		if (!*bvp)
			return -ENOMEM;
	}
	return 0;
}

static void biovec_free_pools(struct bio_set *bs)
{
	int i;

	for (i = 0; i < BIOVEC_NR_POOLS; i++) {
		mempool_t *bvp = bs->bvec_pools[i];

		if (bvp)
			mempool_destroy(bvp);
	}

}

void bioset_free(struct bio_set *bs)
{
	if (bs->bio_pool)
		mempool_destroy(bs->bio_pool);

	biovec_free_pools(bs);

	kfree(bs);
}

struct bio_set *bioset_create(int bio_pool_size, int bvec_pool_size, int scale)
{
	struct bio_set *bs;

	BUG_ON(!dm_bs_bio_slab);

	bs = kzalloc(sizeof(*bs), GFP_KERNEL);
	if (!bs)
		return NULL;

	bs->bio_pool = mempool_create(bio_pool_size, mempool_alloc_slab,
				mempool_free_slab, dm_bs_bio_slab);
	if (!bs->bio_pool)
		goto bad;

	if (!biovec_create_pools(bs, bvec_pool_size, scale))
		return bs;

bad:
	bioset_free(bs);
	return NULL;
}

int dm_bs_init(void)
{
	int i;

	BUG_ON(dm_bs_bio_slab);

	dm_bs_bio_slab = kmem_cache_create(
				"dm-bio", sizeof(struct bio), 0,
				SLAB_HWCACHE_ALIGN, NULL, NULL);
	if (!dm_bs_bio_slab) {
		DMERR("failed to initialize bio slab cache");
		return -ENOMEM;
	}
	for (i = 0; i < BIOVEC_NR_POOLS; i++) {
		int size;
		struct biovec_slab *bvs = dm_bs_bvec_slabs + i;

		size = bvs->nr_vecs * sizeof(struct bio_vec);
		bvs->slab = kmem_cache_create(bvs->name, size, 0,
				SLAB_HWCACHE_ALIGN, NULL, NULL);
		if (!bvs->slab) {
			DMERR("failed to initialize biovec slab cache");
			dm_bs_exit();
			return -ENOMEM;
		}
	}
	return 0;
}

void dm_bs_exit(void)
{
	int i;

	for (i = 0; i < BIOVEC_NR_POOLS; i++) {
		struct biovec_slab *bvs = dm_bs_bvec_slabs + i;

		if (bvs->slab)
			kmem_cache_destroy(bvs->slab);
		bvs->slab = NULL;
	}

	if (dm_bs_bio_slab)
		kmem_cache_destroy(dm_bs_bio_slab);
	dm_bs_bio_slab = NULL;
}

EXPORT_SYMBOL(bio_free);
EXPORT_SYMBOL(bioset_create);
EXPORT_SYMBOL(bioset_free);
EXPORT_SYMBOL(bio_alloc_bioset);

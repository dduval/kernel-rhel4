#ifndef LINUX_SLAB_BACKPORT_H
#define LINUX_SLAB_BACKPORT_H

#include_next <linux/slab.h>

static inline
void *kmemdup(const void *src, size_t len, gfp_t gfp)
{
       void *p;

       p = kmalloc(len, gfp);
       if (p)
               memcpy(p, src, len);
       return p;
}

static inline
void *kmalloc_node(size_t size, gfp_t flags, int nid)
{
	return kmalloc(size, flags);
}

#endif

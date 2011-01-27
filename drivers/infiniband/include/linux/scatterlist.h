/* scatterlist compatibility for pre-2.6.11 kernels */

#ifndef _LINUX_SCATTERLIST_H
#define _LINUX_SCATTERLIST_H

#include <linux/mm.h>

static inline void sg_init_one(struct scatterlist *sg,
                               u8 *buf, unsigned int buflen)
{
        memset(sg, 0, sizeof(*sg));

        sg->page = virt_to_page(buf);
        sg->offset = offset_in_page(buf);
        sg->length = buflen;
}

#endif /* _LINUX_SCATTERLIST_H */

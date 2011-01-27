#ifndef LINUX_SKBUFF_H_BACKPORT
#define LINUX_SKBUFF_H_BACKPORT

#include_next <linux/skbuff.h>

/**
 *      skb_header_release - release reference to header
 *      @skb: buffer to operate on
 *
 *      Drop a reference to the header part of the buffer.  This is done
 *      by acquiring a payload reference.  You must not read from the header
 *      part of skb->data after this.
 */
static inline void skb_header_release(struct sk_buff *skb)
{
}


#endif

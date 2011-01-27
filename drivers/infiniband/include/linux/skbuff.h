#ifndef LINUX_SKBUFF_H_BACKPORT
#define LINUX_SKBUFF_H_BACKPORT

#include_next <linux/skbuff.h>

#define CHECKSUM_PARTIAL CHECKSUM_HW 
#define CHECKSUM_COMPLETE CHECKSUM_HW 

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

static inline u16 __skb_checksum_complete(struct sk_buff *skb)
{
	return csum_fold(skb_checksum(skb, 0, skb->len, skb->csum));
}

#define skb_queue_reverse_walk(queue, skb) \
	for (skb = (queue)->prev; \
		prefetch(skb->prev), (skb != (struct sk_buff *)(queue)); \
		skb = skb->prev)

#define gso_size tso_size

#endif

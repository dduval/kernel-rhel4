/*
 * Common code for low-level network console, dump, and debugger code
 *
 * Derived from netconsole, kgdb-over-ethernet, and netdump patches
 */

#ifndef _LINUX_NETPOLL_H
#define _LINUX_NETPOLL_H

#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/list.h>

struct netpoll;

struct netpoll {
	struct net_device *dev;
	char dev_name[16], *name;
	void (*rx_hook)(struct netpoll *, short, char *, int);
	void (*dump_func)(struct pt_regs *);
	u32 local_ip, remote_ip;
	u16 local_port, remote_port;
	unsigned char local_mac[6], remote_mac[6];
	struct list_head rx_list;
};

struct netpoll_info {
	spinlock_t poll_lock;
	int poll_owner;
	int tries;
	int rx_flags;
	spinlock_t rx_lock;
	struct netpoll *rx_np; /* netpoll that registered an rx_hook */
	struct sk_buff_head arp_tx; /* list of arp requests to reply to */
	struct sk_buff_head tx_backlog; /*backlog for skb to tx */
};

void netpoll_poll(struct netpoll *np);
void netpoll_poll_dev(struct net_device *dev);
void netpoll_send_skb(struct netpoll *np, struct sk_buff *skb);
void netpoll_send_udp(struct netpoll *np, const char *msg, int len);
int netpoll_parse_options(struct netpoll *np, char *opt);
int netpoll_setup(struct netpoll *np);
int netpoll_trap(void);
void netpoll_set_trap(int trap);
void netpoll_cleanup(struct netpoll *np);
int __netpoll_rx(struct sk_buff *skb);
void netpoll_reset_locks(struct netpoll *np);

#ifdef CONFIG_NETPOLL
extern inline struct net_device *skb_bond(struct sk_buff *);
static inline int netpoll_rx(struct sk_buff *skb)
{
	struct net_device *orig_dev = skb_bond(skb);
	struct net_device_wrapper *ndw;
	struct netpoll_info *npinfo;
	unsigned long flags;
	int ret = 0;

	/*
	 * If orig_dev is NULL then 
	 * tell the caller that we consumed this
	 * frame since skb_bond did it for us
	 */
	if (!orig_dev)
		return 1;

	ndw = dev_wrapper(skb->dev);

	if (!ndw || !(npinfo = ndw->npinfo) ||
	    (!npinfo->rx_np && !npinfo->rx_flags)) {
		skb->dev = orig_dev;
		return 0;
	}

	spin_lock_irqsave(&npinfo->rx_lock, flags);
	/* check rx_flags again with the lock held */
	if (npinfo->rx_flags && __netpoll_rx(skb))
		ret = 1;
	spin_unlock_irqrestore(&npinfo->rx_lock, flags);

	if (!ret)
		skb->dev = orig_dev;

	return ret;
}

static inline void *netpoll_poll_lock(struct net_device *dev)
{
	struct net_device_wrapper *ndw = dev_wrapper(dev);

	rcu_read_lock(); /* deal with race on ->npinfo */
	if (ndw && ndw->npinfo) {
		spin_lock(&ndw->npinfo->poll_lock);
		ndw->npinfo->poll_owner = smp_processor_id();
		return ndw->npinfo;
	}
	return NULL;
}

static inline void netpoll_poll_unlock(void *have)
{
	struct netpoll_info *npi = have;

	if (npi) {
		npi->poll_owner = -1;
		spin_unlock(&npi->poll_lock);
	}
	rcu_read_unlock();
}

#else
#define netpoll_rx(a) 0
#define netpoll_poll_lock(a) NULL
#define netpoll_poll_unlock(a)
#endif

#endif

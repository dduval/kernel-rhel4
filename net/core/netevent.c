/*
 *	Network event notifiers
 *
 *	Authors:
 *      Tom Tucker             <tom@opengridcomputing.com>
 *      Steve Wise             <swise@opengridcomputing.com>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *	Fixes:
 */

#include <linux/rtnetlink.h>
#include <linux/notifier.h>
#include <linux/module.h>

static struct notifier_block *netevent_notifier;
static DEFINE_SPINLOCK(netevent_notifier_lock);

/**
 *	register_netevent_notifier - register a netevent notifier block
 *	@nb: notifier
 *
 *	Register a notifier to be called when a netevent occurs.
 *	The notifier passed is linked into the kernel structures and must
 *	not be reused until it has been unregistered. A negative errno code
 *	is returned on a failure.
 */
int register_netevent_notifier(struct notifier_block *nb)
{
	int err;
	unsigned long flags;

	spin_lock_irqsave(&netevent_notifier_lock, flags);
	err = notifier_chain_register(&netevent_notifier, nb);
	spin_unlock_irqrestore(&netevent_notifier_lock, flags);
	return err;
}

/**
 *	netevent_unregister_notifier - unregister a netevent notifier block
 *	@nb: notifier
 *
 *	Unregister a notifier previously registered by
 *	register_neigh_notifier(). The notifier is unlinked into the
 *	kernel structures and may then be reused. A negative errno code
 *	is returned on a failure.
 */

int unregister_netevent_notifier(struct notifier_block *nb)
{
	int err;
	unsigned long flags;

	spin_lock_irqsave(&netevent_notifier_lock, flags);
	err = notifier_chain_unregister(&netevent_notifier, nb);
	spin_unlock_irqrestore(&netevent_notifier_lock, flags);
	return err;
}

/**
 *	call_netevent_notifiers - call all netevent notifier blocks
 *      @val: value passed unmodified to notifier function
 *      @v:   pointer passed unmodified to notifier function
 *
 *	Call all neighbour notifier blocks.  Parameters and return value
 *	are as for notifier_call_chain().
 */

int call_netevent_notifiers(unsigned long val, void *v)
{
	return notifier_call_chain(&netevent_notifier, val, v);
}

EXPORT_SYMBOL(register_netevent_notifier);
EXPORT_SYMBOL(unregister_netevent_notifier);
EXPORT_SYMBOL(call_netevent_notifiers);

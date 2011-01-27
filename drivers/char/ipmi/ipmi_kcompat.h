/*
 * ipmi_kcompat.h
 *
 * Compatability functions for new 2.6 kernel functions on older 2.6 kernels
 *
 * Copyright (c) 2005 Dell, Inc.
 *   by Matt Domsch <Matt_Domsch@dell.com>
 *
 * This file is released under the GPLv2
 */

#ifndef __LINUX_IPMI_KCOMPAT_H
#define __LINUX_IPMI_KCOMPAT_H

#include<linux/spinlock.h>
#include<linux/hardirq.h>
#include<linux/pci.h>
#include<linux/sched.h>

#ifndef DEFINE_SPINLOCK
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED
#endif

#ifndef pci_get_class
/**
 * pci_get_class - begin or continue searching for a PCI device by class
 * @class: search for a PCI device with this class designation
 * @from: Previous PCI device found in search, or %NULL for new search.
 *
 * Iterates through the list of known PCI devices.  If a PCI device is
 * found with a matching @class, the reference count to the device is
 * incremented and a pointer to its device structure is returned.
 * Otherwise, %NULL is returned.
 * A new search is initiated by passing %NULL to the @from argument.
 * Otherwise if @from is not %NULL, searches continue from next device
 * on the global list.  The reference count for @from is always decremented
 * if it is not %NULL.
 *
 * Note: this implementation differs from the standard pci_get_class()
 * routine because pci_find_class() drops pci_bus_lock before returning,
 * so we do the pci_dev_put(from) and pci_dev_get(dev) without holding
 * pci_bus_lock.  Is this a problem?  I hope not.
 */
static inline struct pci_dev *pci_get_class(unsigned int class, struct pci_dev *from)
{
        struct pci_dev *dev;

        WARN_ON(in_interrupt());
	dev = pci_find_class(class, from);
	pci_dev_put(from);
	dev = pci_dev_get(dev);
        return dev;
}
#endif /* pci_get_class */

static inline signed long __sched schedule_timeout_interruptible(signed long timeout)
{
       __set_current_state(TASK_INTERRUPTIBLE);
       return schedule_timeout(timeout);
}

#endif /* __LINUX_IPMI_KCOMPAT_H */

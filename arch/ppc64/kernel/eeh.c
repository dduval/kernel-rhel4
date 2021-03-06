/*
 * eeh.c
 * Copyright (C) 2001 Dave Engebretsen & Todd Inglett IBM Corporation
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/seq_file.h>
#include <asm/atomic.h>
#include <asm/eeh.h>
#include <asm/io.h>
#include <asm/machdep.h>
#include <asm/rtas.h>
#include "pci.h"

#undef DEBUG

/** Overview:
 *  EEH, or "Extended Error Handling" is a PCI bridge technology for
 *  dealing with PCI bus errors that can't be dealt with within the
 *  usual PCI framework, except by check-stopping the CPU.  Systems
 *  that are designed for high-availability/reliability cannot afford
 *  to crash due to a "mere" PCI error, thus the need for EEH.
 *  An EEH-capable bridge operates by converting a detected error
 *  into a "slot freeze", taking the PCI adapter off-line, making
 *  the slot behave, from the OS'es point of view, as if the slot
 *  were "empty": all reads return 0xff's and all writes are silently
 *  ignored.  EEH slot isolation events can be triggered by parity
 *  errors on the address or data busses (e.g. during posted writes),
 *  which in turn might be caused by dust, vibration, humidity,
 *  radioactivity or plain-old failed hardware.
 *
 *  Note, however, that one of the leading causes of EEH slot
 *  freeze events are buggy device drivers, buggy device microcode,
 *  or buggy device hardware.  This is because any attempt by the
 *  device to bus-master data to a memory address that is not
 *  assigned to the device will trigger a slot freeze.   (The idea
 *  is to prevent devices-gone-wild from corrupting system memory).
 *  Buggy hardware/drivers will have a miserable time co-existing
 *  with EEH.
 *
 *  Ideally, a PCI device driver, when suspecting that an isolation
 *  event has occured (e.g. by reading 0xff's), will then ask EEH
 *  whether this is the case, and then take appropriate steps to
 *  reset the PCI slot, the PCI device, and then resume operations.
 *  However, until that day,  the checking is done here, with the
 *  eeh_check_failure() routine embedded in the MMIO macros.  If
 *  the slot is found to be isolated, an "EEH Event" is synthesized
 *  and sent out for processing.
 */

/** Bus Unit ID macros; get low and hi 32-bits of the 64-bit BUID */
#define BUID_HI(buid) ((buid) >> 32)
#define BUID_LO(buid) ((buid) & 0xffffffff)

/* EEH event workqueue setup. */
static spinlock_t eeh_eventlist_lock = SPIN_LOCK_UNLOCKED;
LIST_HEAD(eeh_eventlist);
static void eeh_event_handler(void *);
DECLARE_WORK(eeh_event_wq, eeh_event_handler, NULL);

static struct notifier_block *eeh_notifier_chain;

/*
 * If a device driver keeps reading an MMIO register in an interrupt
 * handler after a slot isolation event has occurred, we assume it
 * is broken and panic.  This sets the threshold for how many read
 * attempts we allow before panicking.
 */
#define EEH_MAX_FAILS	2100000

/* Time to wait for a PCI slot to retport status, in milliseconds */
#define PCI_BUS_RESET_WAIT_MSEC (60*1000)

/* RTAS tokens */
static int ibm_set_eeh_option;
static int ibm_set_slot_reset;
static int ibm_read_slot_reset_state;
static int ibm_read_slot_reset_state2;
static int ibm_get_config_addr_info;
static int ibm_get_config_addr_info2;
static int ibm_slot_error_detail;

static int eeh_subsystem_enabled;

/* Buffer for reporting slot-error-detail rtas calls */
static unsigned char slot_errbuf[RTAS_ERROR_LOG_MAX];
static spinlock_t slot_errbuf_lock = SPIN_LOCK_UNLOCKED;
static int eeh_error_buf_size;

/* System monitoring statistics */
static DEFINE_PER_CPU(unsigned long, total_mmio_ffs);
static DEFINE_PER_CPU(unsigned long, false_positives);
static DEFINE_PER_CPU(unsigned long, ignored_failures);
static DEFINE_PER_CPU(unsigned long, slot_resets);

/**
 * The pci address cache subsystem.  This subsystem places
 * PCI device address resources into a red-black tree, sorted
 * according to the address range, so that given only an i/o
 * address, the corresponding PCI device can be **quickly**
 * found. It is safe to perform an address lookup in an interrupt
 * context; this ability is an important feature.
 *
 * Currently, the only customer of this code is the EEH subsystem;
 * thus, this code has been somewhat tailored to suit EEH better.
 * In particular, the cache does *not* hold the addresses of devices
 * for which EEH is not enabled.
 *
 * (Implementation Note: The RB tree seems to be better/faster
 * than any hash algo I could think of for this problem, even
 * with the penalty of slow pointer chases for d-cache misses).
 */
struct pci_io_addr_range
{
	struct rb_node rb_node;
	unsigned long addr_lo;
	unsigned long addr_hi;
	struct pci_dev *pcidev;
	unsigned int flags;
};

static struct pci_io_addr_cache
{
	struct rb_root rb_root;
	spinlock_t piar_lock;
} pci_io_addr_cache_root;

static inline struct pci_dev *__pci_get_device_by_addr(unsigned long addr)
{
	struct rb_node *n = pci_io_addr_cache_root.rb_root.rb_node;

	while (n) {
		struct pci_io_addr_range *piar;
		piar = rb_entry(n, struct pci_io_addr_range, rb_node);

		if (addr < piar->addr_lo) {
			n = n->rb_left;
		} else {
			if (addr > piar->addr_hi) {
				n = n->rb_right;
			} else {
				pci_dev_get(piar->pcidev);
				return piar->pcidev;
			}
		}
	}

	return NULL;
}

/**
 * pci_get_device_by_addr - Get device, given only address
 * @addr: mmio (PIO) phys address or i/o port number
 *
 * Given an mmio phys address, or a port number, find a pci device
 * that implements this address.  Be sure to pci_dev_put the device
 * when finished.  I/O port numbers are assumed to be offset
 * from zero (that is, they do *not* have pci_io_addr added in).
 * It is safe to call this function within an interrupt.
 */
static struct pci_dev *pci_get_device_by_addr(unsigned long addr)
{
	struct pci_dev *dev;
	unsigned long flags;

	spin_lock_irqsave(&pci_io_addr_cache_root.piar_lock, flags);
	dev = __pci_get_device_by_addr(addr);
	spin_unlock_irqrestore(&pci_io_addr_cache_root.piar_lock, flags);
	return dev;
}

#ifdef DEBUG
/*
 * Handy-dandy debug print routine, does nothing more
 * than print out the contents of our addr cache.
 */
static void pci_addr_cache_print(struct pci_io_addr_cache *cache)
{
	struct rb_node *n;
	int cnt = 0;

	n = rb_first(&cache->rb_root);
	while (n) {
		struct pci_io_addr_range *piar;
		piar = rb_entry(n, struct pci_io_addr_range, rb_node);
		printk(KERN_DEBUG "PCI: %s addr range %d [%lx-%lx]: %s %s\n",
		       (piar->flags & IORESOURCE_IO) ? "i/o" : "mem", cnt,
		       piar->addr_lo, piar->addr_hi, pci_name(piar->pcidev),
		       pci_pretty_name(piar->pcidev));
		cnt++;
		n = rb_next(n);
	}
}
#endif

/* Insert address range into the rb tree. */
static struct pci_io_addr_range *
pci_addr_cache_insert(struct pci_dev *dev, unsigned long alo,
		      unsigned long ahi, unsigned int flags)
{
	struct rb_node **p = &pci_io_addr_cache_root.rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct pci_io_addr_range *piar;

	/* Walk tree, find a place to insert into tree */
	while (*p) {
		parent = *p;
		piar = rb_entry(parent, struct pci_io_addr_range, rb_node);
		if (ahi < piar->addr_lo) {
			p = &parent->rb_left;
		} else if (alo > piar->addr_hi) {
			p = &parent->rb_right;
		} else {
			if (dev != piar->pcidev ||
			    alo != piar->addr_lo || ahi != piar->addr_hi) {
				printk(KERN_WARNING "PIAR: overlapping address range\n");
			}
			return piar;
		}
	}
	piar = (struct pci_io_addr_range *)kmalloc(sizeof(struct pci_io_addr_range), GFP_ATOMIC);
	if (!piar)
		return NULL;

	piar->addr_lo = alo;
	piar->addr_hi = ahi;
	piar->pcidev = dev;
	piar->flags = flags;
	
#ifdef DEBUG 
	printk (KERN_DEBUG "PIAR: insert range=[%lx:%lx] dev=%s\n", 
	               alo, ahi, pci_name (dev));
#endif

	rb_link_node(&piar->rb_node, parent, p);
	rb_insert_color(&piar->rb_node, &pci_io_addr_cache_root.rb_root);

	return piar;
}

static void __pci_addr_cache_insert_device(struct pci_dev *dev)
{
	struct device_node *dn;
	int i;
	int inserted = 0;

	dn = pci_device_to_OF_node(dev);
	if (!dn) {
		printk(KERN_WARNING "PCI: no pci dn found for dev=%s %s\n",
			pci_name(dev), pci_pretty_name(dev));
		return;
	}

	/* Skip any devices for which EEH is not enabled. */
	if (!(dn->eeh_mode & EEH_MODE_SUPPORTED) ||
	    dn->eeh_mode & EEH_MODE_NOCHECK) {
#ifdef DEBUG
		printk(KERN_INFO "PCI: skip building address cache for=%s %s\n",
		       pci_name(dev), pci_pretty_name(dev));
#endif
		return;
	}

	/* The cache holds a reference to the device... */
	pci_dev_get(dev);

	/* Walk resources on this device, poke them into the tree */
	for (i = 0; i < DEVICE_COUNT_RESOURCE; i++) {
		unsigned long start = pci_resource_start(dev,i);
		unsigned long end = pci_resource_end(dev,i);
		unsigned int flags = pci_resource_flags(dev,i);

		/* We are interested only bus addresses, not dma or other stuff */
		if (0 == (flags & (IORESOURCE_IO | IORESOURCE_MEM)))
			continue;
		if (start == 0 || ~start == 0 || end == 0 || ~end == 0)
			 continue;
		pci_addr_cache_insert(dev, start, end, flags);
		inserted = 1;
	}

	/* If there was nothing to add, the cache has no reference... */
	if (!inserted)
		pci_dev_put(dev);
}

/**
 * pci_addr_cache_insert_device - Add a device to the address cache
 * @dev: PCI device whose I/O addresses we are interested in.
 *
 * In order to support the fast lookup of devices based on addresses,
 * we maintain a cache of devices that can be quickly searched.
 * This routine adds a device to that cache.
 */
void pci_addr_cache_insert_device(struct pci_dev *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&pci_io_addr_cache_root.piar_lock, flags);
	__pci_addr_cache_insert_device(dev);
	spin_unlock_irqrestore(&pci_io_addr_cache_root.piar_lock, flags);
}

static inline void __pci_addr_cache_remove_device(struct pci_dev *dev)
{
	struct rb_node *n;
	int removed = 0;

restart:
	n = rb_first(&pci_io_addr_cache_root.rb_root);
	while (n) {
		struct pci_io_addr_range *piar;
		piar = rb_entry(n, struct pci_io_addr_range, rb_node);

		if (piar->pcidev == dev) {
			rb_erase(n, &pci_io_addr_cache_root.rb_root);
			removed = 1;
			kfree(piar);
			goto restart;
		}
		n = rb_next(n);
	}

	/* The cache no longer holds its reference to this device... */
	if (removed)
		pci_dev_put(dev);
}

/**
 * pci_addr_cache_remove_device - remove pci device from addr cache
 * @dev: device to remove
 *
 * Remove a device from the addr-cache tree.
 * This is potentially expensive, since it will walk
 * the tree multiple times (once per resource).
 * But so what; device removal doesn't need to be that fast.
 */
void pci_addr_cache_remove_device(struct pci_dev *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&pci_io_addr_cache_root.piar_lock, flags);
	__pci_addr_cache_remove_device(dev);
	spin_unlock_irqrestore(&pci_io_addr_cache_root.piar_lock, flags);
}

/**
 * pci_addr_cache_build - Build a cache of I/O addresses
 *
 * Build a cache of pci i/o addresses.  This cache will be used to
 * find the pci device that corresponds to a given address.
 * This routine scans all pci busses to build the cache.
 * Must be run late in boot process, after the pci controllers
 * have been scaned for devices (after all device resources are known).
 */
void __init pci_addr_cache_build(void)
{
	struct device_node *dn;
	struct pci_dev *dev = NULL;

	spin_lock_init(&pci_io_addr_cache_root.piar_lock);

	while ((dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, dev)) != NULL) {
		/* Ignore PCI bridges ( XXX why ??) */
		if ((dev->class >> 16) == PCI_BASE_CLASS_BRIDGE) {
			continue;
		}
		pci_addr_cache_insert_device(dev);
		
		/* Save the BAR's; firmware doesn't restore these after EEH reset */
		dn = pci_device_to_OF_node(dev);
		if (dn) {
			int i;
			for (i = 0; i < 16; i++)
				pci_read_config_dword(dev, i * 4, &dn->config_space[i]);
		}
	}

#ifdef DEBUG
	/* Verify tree built up above, echo back the list of addrs. */
	pci_addr_cache_print(&pci_io_addr_cache_root);
#endif
}

/* --------------------------------------------------------------- */
/* Above lies the PCI Address Cache. Below lies the EEH event infrastructure */

void eeh_slot_error_detail (struct device_node *dn, int severity)
{
	unsigned long flags;
	int config_addr;
	int rc;

	if (!dn) return;

	/* Log the error with the rtas logger */
	spin_lock_irqsave(&slot_errbuf_lock, flags);
	memset(slot_errbuf, 0, eeh_error_buf_size);

	/* Use PE configuration address, if present */
	config_addr = dn->eeh_config_addr;
	if (dn->eeh_pe_config_addr)
		config_addr = dn->eeh_pe_config_addr;

	rc = rtas_call(ibm_slot_error_detail,
	               8, 1, NULL, config_addr,
	               BUID_HI(dn->phb->buid),
	               BUID_LO(dn->phb->buid), NULL, 0,
	               virt_to_phys(slot_errbuf),
	               eeh_error_buf_size,
	               severity);

	if (rc == 0)
		log_error(slot_errbuf, ERR_TYPE_RTAS_LOG, 0);
	spin_unlock_irqrestore(&slot_errbuf_lock, flags);
}

EXPORT_SYMBOL(eeh_slot_error_detail);

/**
 * read_slot_reset_state - get the current state of a slot for a
 * given device node. 
 *
 * @dn device node for the slot to check
 * @rets array to return results in
 */
static int read_slot_reset_state(struct device_node *dn, unsigned int rets[])
{
	int token, outputs;
	int config_addr;
	
	if (ibm_read_slot_reset_state2 != RTAS_UNKNOWN_SERVICE) {
		token = ibm_read_slot_reset_state2;
		outputs = 4;
	} else {
		token = ibm_read_slot_reset_state;
		outputs = 3;
	}

	/* Use PE configuration address, if present */
	config_addr = dn->eeh_config_addr;
	if (dn->eeh_pe_config_addr)
		config_addr = dn->eeh_pe_config_addr;

	return rtas_call(token, 3, outputs, rets, config_addr,
			 BUID_HI(dn->phb->buid), BUID_LO(dn->phb->buid));
}

/**
 * eeh_register_notifier - Register to find out about EEH events.
 * @nb: notifier block to callback on events
 */
int eeh_register_notifier(struct notifier_block *nb)
{
	return notifier_chain_register(&eeh_notifier_chain, nb);
}

/**
 * eeh_unregister_notifier - Unregister to an EEH event notifier.
 * @nb: notifier block to callback on events
 */
int eeh_unregister_notifier(struct notifier_block *nb)
{
	return notifier_chain_unregister(&eeh_notifier_chain, nb);
}

/**
 * eeh_panic - call panic() for an eeh event that cannot be handled.
 * The philosophy of this routine is that it is better to panic and
 * halt the OS than it is to risk possible data corruption by
 * oblivious device drivers that don't know better.
 *
 * @dev pci device that had an eeh event
 * @reset_state current reset state of the device slot
 */
static void eeh_panic(struct pci_dev *dev, int reset_state)
{
	/*
	 * XXX We should create a seperate sysctl for this.
	 *
	 * Since the panic_on_oops sysctl is used to halt the system
	 * in light of potential corruption, we can use it here.
	 */
	if (panic_on_oops)
		panic("EEH: MMIO failure (%d) on device:%s %s\n", reset_state,
		      pci_name(dev), pci_pretty_name(dev));
	else {
		__get_cpu_var(ignored_failures)++;
		printk(KERN_INFO "EEH: Ignored MMIO failure (%d) on device:%s %s\n",
		       reset_state, pci_name(dev), pci_pretty_name(dev));
	}
}

/**
 * eeh_event_handler - dispatch EEH events.  The detection of a frozen
 * slot can occur inside an interrupt, where it can be hard to do
 * anything about it.  The goal of this routine is to pull these
 * detection events out of the context of the interrupt handler, and
 * re-dispatch them for processing at a later time in a normal context.
 *
 * @dummy - unused
 */
static void eeh_event_handler(void *dummy)
{
	unsigned long flags;
	struct eeh_event	*event;

	while (1) {
		spin_lock_irqsave(&eeh_eventlist_lock, flags);
		event = NULL;
		if (!list_empty(&eeh_eventlist)) {
			event = list_entry(eeh_eventlist.next, struct eeh_event, list);
			list_del(&event->list);
		}
		spin_unlock_irqrestore(&eeh_eventlist_lock, flags);
		if (event == NULL)
			break;

		printk(KERN_INFO "EEH: MMIO failure (%d), notifiying device "
		       "%s %s\n", event->reset_state,
		       pci_name(event->dev), pci_pretty_name(event->dev));

		__get_cpu_var(slot_resets)++;
		notifier_call_chain (&eeh_notifier_chain, EEH_NOTIFY_FREEZE, event);

		pci_dev_put(event->dev);
		kfree(event);
	}
}

/**
 * eeh_wait_for_slot_status - returns error status of slot
 * @pdn pci device node
 * @max_wait_msecs maximum number to millisecs to wait
 *
 * Return negative value if a permanent error, else return
 * Partition Endpoint (PE) status value.
 *
 * If @max_wait_msecs is positive, then this routine will
 * sleep until a valid status can be obtained, or until
 * the max allowed wait time is exceeded, in which case
 * a -2 is returned.
 */
int
eeh_wait_for_slot_status(struct device_node *dn, int max_wait_msecs)
{
	int rc;
	int rets[3];
	int mwait=0;

	while (1) {
		rc = read_slot_reset_state(dn, rets);
		if (rc) return rc;
		if (rets[1] == 0) return -1;  /* EEH is not supported */

		if (rets[0] != 5) return rets[0]; /* return actual status */

		if (rets[2] == 0) return -1; /* permanently unavailable */

		if (max_wait_msecs <= 0) break;

		mwait = rets[2];
		if (mwait <= 0) {
			printk (KERN_WARNING
			        "EEH: Firmware returned bad wait value=%d\n", mwait);
			mwait = 1000;
		} else if (mwait > 300*1000) {
			printk (KERN_WARNING
			        "EEH: Firmware is taking too long, time=%d\n", mwait);
			mwait = 300*1000;
		}
		max_wait_msecs -= mwait;
		msleep (mwait);
	}

	if (!mwait) return -1;
	printk(KERN_WARNING "EEH: Timed out waiting for slot status\n");
	return -2;
}

/**
 * eeh_token_to_phys - convert EEH address token to phys address
 * @token i/o token, should be address in the form 0xE....
 */
static inline unsigned long eeh_token_to_phys(unsigned long token)
{
	pte_t *ptep;
	unsigned long pa;

	ptep = find_linux_pte(ioremap_mm.pgd, token);
	if (!ptep)
		return token;
	pa = pte_pfn(*ptep) << PAGE_SHIFT;

	return pa | (token & (PAGE_SIZE-1));
}

static inline struct pci_dev * eeh_get_pci_dev(struct device_node *dn)
{
	struct pci_dev *dev = NULL;

	while ((dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, dev)) != NULL) {
		if (pci_device_to_OF_node(dev) == dn)
			return dev;
	}
	return NULL;
}

/**
 * eeh_dn_check_failure - check if all 1's data is due to EEH slot freeze
 * @dn device node
 * @dev pci device, if known
 *
 * Check for an EEH failure for the given device node.  Call this
 * routine if the result of a read was all 0xff's and you want to
 * find out if this is due to an EEH slot freeze event.  This routine
 * will query firmware for the EEH status.
 *
 * Returns 0 if there has not been an EEH error; otherwise returns
 * an error code.
 *
 * It is safe to call this routine in an interrupt context.
 */
int eeh_dn_check_failure(struct device_node *dn, struct pci_dev *dev)
{
	int ret, rets[3];
	unsigned long flags;
	int reset_state;
	struct eeh_event  *event;

	__get_cpu_var(total_mmio_ffs)++;

	if (!eeh_subsystem_enabled)
		return 0;

	if (!dn)
		return 0;

	/* Access to IO BARs might get this far and still not want checking. */
	if (!(dn->eeh_mode & EEH_MODE_SUPPORTED) ||
	    dn->eeh_mode & EEH_MODE_NOCHECK) {
		return 0;
	}

	if (!dn->eeh_config_addr)
		return 0;

	/*
	 * If we already have a pending isolation event for this
	 * slot, we know it's bad already, we don't need to check...
	 */
	if (dn->eeh_mode & EEH_MODE_ISOLATED) {
		dn->eeh_check_count ++;
		if (dn->eeh_check_count >= EEH_MAX_FAILS) {
			printk (KERN_ERR "EEH: Driver ignored %d bad reads, panicing\n",
			        dn->eeh_check_count);
			dump_stack();
			/* re-read the slot reset state */
			if (read_slot_reset_state(dn, rets))
				rets[0] = -1;  /* reset state unknown */
			eeh_panic(dev, rets[0]);
		}
		return 0;
	}

	/*
	 * Now test for an EEH failure.  This is VERY expensive.
	 * Note that the eeh_config_addr may be a parent device
	 * in the case of a device behind a bridge, or it may be
	 * function zero of a multi-function device.
	 * In any case they must share a common PHB.
	 */
	ret = read_slot_reset_state(dn, rets);

	/* Note that config-io to empty slots may fail;
	 * they are empty when they don't have children. */
	if ((rets[0] == 5) && (dn->child == NULL)) {
		__get_cpu_var(false_positives)++;
		return 0;
	}

	if (!(ret == 0 && rets[1] == 1 &&
	     (rets[0] == 1 || rets[0] == 2 || rets[0] == 4))) {
		__get_cpu_var(false_positives)++;
		return 0;
	}

	/* Prevent repeated reports of this failure */
	dn->eeh_mode |= EEH_MODE_ISOLATED;

	reset_state = rets[0];

	/* Log the error with the rtas logger */
	if (dn->eeh_freeze_count < EEH_MAX_ALLOWED_FREEZES) {
		eeh_slot_error_detail (dn, 1 /* Temporary Error */);
	} else {
		eeh_slot_error_detail (dn, 2 /* Permanent Error */);
	}

	event = kmalloc(sizeof(*event), GFP_ATOMIC);
	if (event == NULL) {
		printk (KERN_ERR "EEH: out of memory, event not handled\n");
		eeh_panic(dev, reset_state);
		return 1;
	}

	if (!dev)
		dev = eeh_get_pci_dev (dn);
	event->dev = dev;
	event->dn = dn;
	event->reset_state = reset_state;

	/* We may or may not be called in an interrupt context */
	spin_lock_irqsave(&eeh_eventlist_lock, flags);
	list_add(&event->list, &eeh_eventlist);
	spin_unlock_irqrestore(&eeh_eventlist_lock, flags);

	/* Most EEH events are due to device driver bugs.  Having
	 * a stack trace will help the device-driver authors figure
	 * out what happened.  So print that out. */
	dump_stack();
	schedule_work(&eeh_event_wq);

	return 0;
}

EXPORT_SYMBOL(eeh_dn_check_failure);

/**
 * eeh_check_failure - check if all 1's data is due to EEH slot freeze
 * @token i/o token, should be address in the form 0xA....
 * @val value, should be all 1's (XXX why do we need this arg??)
 *
 * Check for an EEH failure at the given token address.  Call this
 * routine if the result of a read was all 0xff's and you want to
 * find out if this is due to an EEH slot freeze event.  This routine
 * will query firmware for the EEH status.
 *
 * Note this routine is safe to call in an interrupt context.
 */

unsigned long eeh_check_failure(const volatile void __iomem *token, unsigned long val)
{
	unsigned long addr;
	struct pci_dev *dev;
	struct device_node *dn;

	/* Finding the phys addr + pci device; this is pretty quick. */
	addr = eeh_token_to_phys((unsigned long __force) token);
	dev = pci_get_device_by_addr(addr);
	if (!dev) 
		return val;

	dn = pci_device_to_OF_node(dev);
	eeh_dn_check_failure (dn, dev);

	pci_dev_put(dev);
	return val;
}

EXPORT_SYMBOL(eeh_check_failure);

static void rtas_pci_slot_reset(struct device_node *dn, int state)
{
	int token = rtas_token ("ibm,set-slot-reset");
	int rc;

	if (token == RTAS_UNKNOWN_SERVICE)
		return;
	rc = rtas_call(token,4,1, NULL,
	               dn->eeh_config_addr,
	               BUID_HI(dn->phb->buid),
	               BUID_LO(dn->phb->buid),
	               state);
	if (rc) {
		printk (KERN_WARNING "EEH: Unable to reset slot\n");
		return;
	}
}

/**
 * pcibios_set_pcie_slot_reset - Set PCI-E reset state
 * @dev:	pci device struct
 * @state:	reset state to enter
 *
 * Return value:
 * 	0 if success
 **/
int pcibios_set_pcie_reset_state(struct pci_dev *dev, enum pcie_reset_state state)
{
	struct device_node *dn = pci_device_to_OF_node(dev);

	switch (state) {
	case pci_reset_normal:
		rtas_pci_slot_reset(dn, 0);
		break;
	case pci_reset_pcie_hot_reset:
		rtas_pci_slot_reset(dn, 1);
		break;
	case pci_reset_pcie_warm_reset:
		rtas_pci_slot_reset(dn, 3);
		break;
	default:
		return -EINVAL;
	};

	return 0;
}

/* ------------------------------------------------------------- */
/* The code below deals with error recovery */

void
__rtas_set_slot_reset(struct device_node *dn)
{
	int token = rtas_token ("ibm,set-slot-reset");
	int rc;
	int config_addr;

	if (token == RTAS_UNKNOWN_SERVICE)
		return;

	/* Use PE configuration address, if present */
	config_addr = dn->eeh_config_addr;
	if (dn->eeh_pe_config_addr)
		config_addr = dn->eeh_pe_config_addr;

	rc = rtas_call(token,4,1, NULL, config_addr,
	               BUID_HI(dn->phb->buid),
	               BUID_LO(dn->phb->buid),
	               1);
	if (rc) {
		printk (KERN_WARNING "EEH: Unable to reset the failed slot\n");
		return;
	}
	
	/* The PCI bus requires that the reset be held high for at least
	 * a 100 milliseconds. We wait a bit longer 'just in case'.
	 */
   msleep (200);
	
	rc = rtas_call(token,4,1, NULL, config_addr,
	               BUID_HI(dn->phb->buid),
	               BUID_LO(dn->phb->buid),
	               0);

	/* After a PCI slot has been reset, the PCI Express spec requires
	 * a 1.5 second idle time for the bus to stabilize, before starting
	 * up traffic. */
#define PCI_BUS_SETTLE_TIME_MSEC 1800
	msleep (PCI_BUS_SETTLE_TIME_MSEC);
}


int rtas_set_slot_reset(struct device_node *dn)
{
	int i, rc;

	/* Take three shots at resetting the bus */
	for (i=0; i<3; i++) {
		__rtas_set_slot_reset(dn);

		rc = eeh_wait_for_slot_status(dn, PCI_BUS_RESET_WAIT_MSEC);
		if (rc == 0)
			return 0;

		if (rc < 0) {
			printk (KERN_ERR "EEH: unrecoverable slot failure %s\n",
			        dn->full_name);
			return -1;
		}
		printk (KERN_ERR "EEH: bus reset %d failed on slot %s\n",
		        i+1, dn->full_name);
	}

	return -1;
}

EXPORT_SYMBOL(rtas_set_slot_reset);

void
rtas_configure_bridge(struct device_node *dn)
{
	int token = rtas_token ("ibm,configure-bridge");
	int rc;
	int config_addr;

	if (token == RTAS_UNKNOWN_SERVICE)
		return;

	/* Use PE configuration address, if present */
	config_addr = dn->eeh_config_addr;
	if (dn->eeh_pe_config_addr)
		config_addr = dn->eeh_pe_config_addr;

	rc = rtas_call(token,3,1, NULL,
	               config_addr,
	               BUID_HI(dn->phb->buid),
	               BUID_LO(dn->phb->buid));
	if (rc) {
		printk (KERN_WARNING "EEH: Unable to configure device bridge\n");
	}
}

EXPORT_SYMBOL(rtas_configure_bridge);

/* ------------------------------------------------------- */
/** Save and restore of PCI BARs
 * 
 * Although firmware will set up BARs during boot, it doesn't
 * set up device BAR's after a device reset, although it will,
 * if requested, set up bridge configuration. Thus, we need to 
 * configure the PCI devices ourselves.  Config-space setup is 
 * stored in the PCI structures which are normally deleted during
 * device removal.  Thus, the "save" routine references the
 * structures so that they aren't deleted. 
 */

struct eeh_cfg_tree
{
	struct eeh_cfg_tree *sibling;
	struct eeh_cfg_tree *child;
	struct device_node *dn;
	int is_bridge;
};

/** 
 * eeh_save_bars - save the PCI config space info
 */
struct eeh_cfg_tree * eeh_save_bars(struct device_node *dn)
{
	struct pci_dev *dev;
	struct eeh_cfg_tree *cnode;

	if (!dn) {
		printk (KERN_WARNING "EEH: no device node\n");
		return NULL;
	}

	dev = eeh_get_pci_dev(dn);
	if (!dev) {
		printk (KERN_WARNING "EEH: no device for dn=%s\n", dn->full_name);
		return NULL;
	}
	
	cnode = kmalloc(sizeof(struct eeh_cfg_tree), GFP_KERNEL);
	if (!cnode) {
		printk (KERN_ERR "EEH: kmalloc failed for dn=%s\n", dn->full_name);
		pci_dev_put(dev);
		return NULL;
	}
	
	cnode->is_bridge = 0;
	
	if (dev->hdr_type == PCI_HEADER_TYPE_BRIDGE) 
		cnode->is_bridge = 1;
			  
	of_node_get(dn);
	cnode->dn = dn;
	
	cnode->sibling = NULL;
	cnode->child = NULL;

	if (dn->child) {
		cnode->child = eeh_save_bars (dn->child);
	}
	if (dn->sibling) {
		cnode->sibling = eeh_save_bars (dn->sibling);
	}

	return cnode;
}
EXPORT_SYMBOL(eeh_save_bars);

/**
 * __restore_bars - Restore the Base Address Registers
 * Loads the PCI configuration space base address registers, 
 * the expansion ROM base address, the latency timer, and etc.
 * from the saved values in the device node.
 */
static inline void __restore_bars (struct device_node *dn)
{
	int i;
	for (i=4; i<10; i++) {
		rtas_write_config(dn, i*4, 4, dn->config_space[i]);
	}

	/* 12 == Expansion ROM Address */
	rtas_write_config(dn, 12*4, 4, dn->config_space[12]);
	
#define SAVED_BYTE(OFF) (((u8 *)(dn->config_space))[OFF])
	
	rtas_write_config (dn, PCI_CACHE_LINE_SIZE, 1, 
	            SAVED_BYTE(PCI_CACHE_LINE_SIZE));
	
	rtas_write_config (dn, PCI_LATENCY_TIMER, 1, 
	            SAVED_BYTE(PCI_LATENCY_TIMER));
	
	rtas_write_config (dn, PCI_INTERRUPT_LINE, 1, 
	            SAVED_BYTE(PCI_INTERRUPT_LINE));
}

/** 
 * eeh_restore_bars - restore the PCI config space info
 */
void eeh_restore_bars(struct eeh_cfg_tree *tree)
{
	if (!(tree->is_bridge))
		__restore_bars (tree->dn);
	
	if (tree->child)
		eeh_restore_bars (tree->child);

	if (tree->sibling)
		eeh_restore_bars (tree->sibling);

	of_node_put (tree->dn);
	kfree (tree);
}
EXPORT_SYMBOL(eeh_restore_bars);

/* ------------------------------------------------------------- */
/* The code below deals with enabling EEH for devices during  the
 * early boot sequence.  EEH must be enabled before any PCI probing
 * can be done.
 */

struct eeh_early_enable_info {
	unsigned int buid_hi;
	unsigned int buid_lo;
};

static int get_pe_addr (int config_addr,
                        struct eeh_early_enable_info *info)
{
	unsigned int rets[3];
	int ret;

	/* Use latest config-addr token on power6 */
	if (ibm_get_config_addr_info2 != RTAS_UNKNOWN_SERVICE) {
		/* Make sure we have a PE in hand */
		ret = rtas_call (ibm_get_config_addr_info2, 4, 2, rets,
			config_addr, info->buid_hi, info->buid_lo, 1);
		if (ret || (rets[0]==0))
			return 0;

		ret = rtas_call (ibm_get_config_addr_info2, 4, 2, rets,
			config_addr, info->buid_hi, info->buid_lo, 0);
		if (ret)
			return 0;
		return rets[0];
	}

	/* Use older config-addr token on power5 */
	if (ibm_get_config_addr_info != RTAS_UNKNOWN_SERVICE) {
		ret = rtas_call (ibm_get_config_addr_info, 4, 2, rets,
			config_addr, info->buid_hi, info->buid_lo, 0);
		if (ret)
			return 0;
		return rets[0];
	}
	return 0;
}

/* Enable eeh for the given device node. */
static void *early_enable_eeh(struct device_node *dn, void *data)
{
	struct eeh_early_enable_info *info = data;
	int ret;
	char *status = get_property(dn, "status", NULL);
	u32 *class_code = (u32 *)get_property(dn, "class-code", NULL);
	u32 *vendor_id = (u32 *)get_property(dn, "vendor-id", NULL);
	u32 *device_id = (u32 *)get_property(dn, "device-id", NULL);
	u32 *regs;

	dn->eeh_mode = 0;

	if (status && strncmp(status, "ok", 2) != 0)
		return NULL;	/* ignore devices with bad status */

	/* Ignore bad nodes. */
	if (!class_code || !vendor_id || !device_id)
		return NULL;

	/* There is nothing to check on PCI to ISA bridges */
	if (dn->type && !strcmp(dn->type, "isa")) {
		dn->eeh_mode |= EEH_MODE_NOCHECK;
		return NULL;
	}

	/* Ok... see if this device supports EEH.  Some do, some don't,
	 * and the only way to find out is to check each and every one. */
	regs = (u32 *)get_property(dn, "reg", NULL);
	if (regs) {
		/* First register entry is addr (00BBSS00)  */
		/* Try to enable eeh */
		ret = rtas_call(ibm_set_eeh_option, 4, 1, NULL,
				regs[0], info->buid_hi, info->buid_lo,
				EEH_ENABLE);
		if (ret == 0) {
			eeh_subsystem_enabled = 1;
			dn->eeh_mode |= EEH_MODE_SUPPORTED;
			dn->eeh_config_addr = regs[0];
			dn->eeh_pe_config_addr = get_pe_addr(dn->eeh_config_addr, info);
#ifdef DEBUG
			printk(KERN_DEBUG "EEH: %s: eeh enabled\n", dn->full_name);
#endif
		} else {

			/* This device doesn't support EEH, but it may have an
			 * EEH parent, in which case we mark it as supported. */
			if (dn->parent && (dn->parent->eeh_mode & EEH_MODE_SUPPORTED)) {
				/* Parent supports EEH. */
				dn->eeh_mode |= EEH_MODE_SUPPORTED;
				dn->eeh_config_addr = dn->parent->eeh_config_addr;
				dn->eeh_pe_config_addr = dn->parent->eeh_pe_config_addr;
				return NULL;
			}
		}
	} else {
		printk(KERN_WARNING "EEH: %s: unable to get reg property.\n",
		       dn->full_name);
	}

	return NULL; 
}

/*
 * Initialize EEH by trying to enable it for all of the adapters in the system.
 * As a side effect we can determine here if eeh is supported at all.
 * Note that we leave EEH on so failed config cycles won't cause a machine
 * check.  If a user turns off EEH for a particular adapter they are really
 * telling Linux to ignore errors.  Some hardware (e.g. POWER5) won't
 * grant access to a slot if EEH isn't enabled, and so we always enable
 * EEH for all slots/all devices.
 *
 * The eeh-force-off option disables EEH checking globally, for all slots.
 * Even if force-off is set, the EEH hardware is still enabled, so that
 * newer systems can boot.
 */
void __init eeh_init(void)
{
	struct device_node *phb, *np;
	struct eeh_early_enable_info info;

	init_pci_config_tokens();

	np = of_find_node_by_path("/rtas");
	if (np == NULL)
		return;

	ibm_set_eeh_option = rtas_token("ibm,set-eeh-option");
	ibm_set_slot_reset = rtas_token("ibm,set-slot-reset");
	ibm_read_slot_reset_state = rtas_token("ibm,read-slot-reset-state");
	ibm_read_slot_reset_state2 = rtas_token("ibm,read-slot-reset-state2");
	ibm_slot_error_detail = rtas_token("ibm,slot-error-detail");
	ibm_get_config_addr_info = rtas_token("ibm,get-config-addr-info");
	ibm_get_config_addr_info2 = rtas_token("ibm,get-config-addr-info2");

	if (ibm_set_eeh_option == RTAS_UNKNOWN_SERVICE)
		return;

	eeh_error_buf_size = rtas_token("rtas-error-log-max");
	if (eeh_error_buf_size == RTAS_UNKNOWN_SERVICE) {
		eeh_error_buf_size = 1024;
	}
	if (eeh_error_buf_size > RTAS_ERROR_LOG_MAX) {
		printk(KERN_WARNING "EEH: rtas-error-log-max is bigger than allocated "
		       "buffer ! (%d vs %d)", eeh_error_buf_size, RTAS_ERROR_LOG_MAX);
		eeh_error_buf_size = RTAS_ERROR_LOG_MAX;
	}

	/* Enable EEH for all adapters.  Note that eeh requires buid's */
	for (phb = of_find_node_by_name(NULL, "pci"); phb;
	     phb = of_find_node_by_name(phb, "pci")) {
		unsigned long buid;

		buid = get_phb_buid(phb);
		if (buid == 0)
			continue;

		info.buid_lo = BUID_LO(buid);
		info.buid_hi = BUID_HI(buid);
		traverse_pci_devices(phb, early_enable_eeh, &info);
	}

	if (eeh_subsystem_enabled)
		printk(KERN_INFO "EEH: PCI Enhanced I/O Error Handling Enabled\n");
	else
		printk(KERN_WARNING "EEH: No capable adapters found\n");
}

/**
 * eeh_add_device_early - enable EEH for the indicated device_node
 * @dn: device node for which to set up EEH
 *
 * This routine must be used to perform EEH initialization for PCI
 * devices that were added after system boot (e.g. hotplug, dlpar).
 * This routine must be called before any i/o is performed to the
 * adapter (inluding any config-space i/o).
 * Whether this actually enables EEH or not for this device depends
 * on the CEC architecture, type of the device, on earlier boot
 * command-line arguments & etc.
 */
void eeh_add_device_early(struct device_node *dn)
{
	struct pci_controller *phb;
	struct eeh_early_enable_info info;

	if (!dn)
		return;
	phb = dn->phb;
	if (NULL == phb || 0 == phb->buid) {
		printk(KERN_WARNING "EEH: Expected buid but found none\n");
		return;
	}

	info.buid_hi = BUID_HI(phb->buid);
	info.buid_lo = BUID_LO(phb->buid);
	early_enable_eeh(dn, &info);
}
EXPORT_SYMBOL(eeh_add_device_early);

void eeh_add_tree_early(struct device_node *dn)
{
	struct device_node *sib;

	for (sib = dn->child; sib; sib = sib->sibling)
		eeh_add_tree_early(sib);
	eeh_add_device_early(dn);
}
EXPORT_SYMBOL(eeh_add_tree_early);

/**
 * eeh_add_device_late - perform EEH initialization for the indicated pci device
 * @dev: pci device for which to set up EEH
 *
 * This routine must be used to complete EEH initialization for PCI
 * devices that were added after system boot (e.g. hotplug, dlpar).
 */
void eeh_add_device_late(struct pci_dev *dev)
{
	int i;
	struct device_node *dn;

	if (!dev || !eeh_subsystem_enabled)
		return;

#ifdef DEBUG
	printk(KERN_DEBUG "EEH: adding device %s %s\n", pci_name(dev),
	       pci_pretty_name(dev));
#endif

	pci_addr_cache_insert_device (dev);

	/* Save the BAR's; firmware doesn't restore these after EEH reset */
	dn = pci_device_to_OF_node(dev);
	for (i = 0; i < 16; i++)
		pci_read_config_dword(dev, i * 4, &dn->config_space[i]);
}
EXPORT_SYMBOL(eeh_add_device_late);

/**
 * eeh_remove_device - undo EEH setup for the indicated pci device
 * @dev: pci device to be removed
 *
 * This routine should be when a device is removed from a running
 * system (e.g. by hotplug or dlpar).
 */
void eeh_remove_device(struct pci_dev *dev)
{
	if (!dev || !eeh_subsystem_enabled)
		return;

	/* Unregister the device with the EEH/PCI address search system */
#ifdef DEBUG
	printk(KERN_DEBUG "EEH: remove device %s %s\n", pci_name(dev),
	       pci_pretty_name(dev));
#endif
	pci_addr_cache_remove_device(dev);
}
EXPORT_SYMBOL(eeh_remove_device);

static int proc_eeh_show(struct seq_file *m, void *v)
{
	unsigned int cpu;
	unsigned long ffs = 0, positives = 0, failures = 0;
	unsigned long resets = 0;

	for_each_cpu(cpu) {
		ffs += per_cpu(total_mmio_ffs, cpu);
		positives += per_cpu(false_positives, cpu);
		failures += per_cpu(ignored_failures, cpu);
		resets += per_cpu(slot_resets, cpu);
	}

	if (0 == eeh_subsystem_enabled) {
		seq_printf(m, "EEH Subsystem is globally disabled\n");
		seq_printf(m, "eeh_total_mmio_ffs=%ld\n", ffs);
	} else {
		seq_printf(m, "EEH Subsystem is enabled\n");
		seq_printf(m, "eeh_total_mmio_ffs=%ld\n"
			   "eeh_false_positives=%ld\n"
			   "eeh_ignored_failures=%ld\n"
			   "eeh_slot_resets=%ld\n",
			   ffs, positives, failures, resets);
	}

	return 0;
}

static int proc_eeh_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_eeh_show, NULL);
}

static struct file_operations proc_eeh_operations = {
	.open      = proc_eeh_open,
	.read      = seq_read,
	.llseek    = seq_lseek,
	.release   = single_release,
};

static int __init eeh_init_proc(void)
{
	struct proc_dir_entry *e;

	if (systemcfg->platform & PLATFORM_PSERIES) {
		e = create_proc_entry("ppc64/eeh", 0, NULL);
		if (e)
			e->proc_fops = &proc_eeh_operations;
	}

	return 0;
}
__initcall(eeh_init_proc);

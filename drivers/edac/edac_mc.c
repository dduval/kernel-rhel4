/*
 * edac_mc kernel module
 * (C) 2003 Linux Networx (http://lnxi.com)
 * This file may be distributed under the terms of the
 * GNU General Public License.
 *
 * Written by Thayne Harbaugh
 * Based on work by Dan Hollis <goemon at anime dot net> and others.
 *	http://www.anime.net/~goemon/linux-ecc/
 *
 * $Id: linux-2.6.9-edac.pacth,v 1.3 2005/11/23 02:35:51 jbaron Exp $
 *
 */


#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/highmem.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/kthread.h>

#include <asm/uaccess.h>
#include <asm/page.h>
#include <asm/kmap_types.h>
#include <asm/edac.h>

#include "edac_mc.h"


#define	EDAC_MC_VERSION	"edac_mc  Ver: 2.0.0.devel " __DATE__

#ifdef CONFIG_EDAC_DEBUG
int edac_debug_level = 0;
EXPORT_SYMBOL(edac_debug_level);
#endif

#define MC_PROC_DIR "mc"
#define	EDAC_THREAD_NAME	"kedac"


/* /proc/mc dir */
static struct proc_dir_entry *proc_mc;

/* Setable by module parameter and sysctl */
static int panic_on_ue = 1;
static int check_pci_parity = 0;	/* default NO check PCI parity */
static int panic_on_pci_parity = 0;     /* default no panic on PCI Parity */
static int log_ue = 1;
static int log_ce = 1;
static int poll_msec = 1000;

static u32 pci_parity_count = 0;


/* lock to memory controller's control array */
static DECLARE_MUTEX(mem_ctls_mutex);

static struct list_head mc_devices = LIST_HEAD_INIT(mc_devices);

static struct task_struct *edac_thread;

#ifdef CONFIG_SYSCTL


static ctl_table mc_table[] = {
	{-1, "panic_on_ue", &panic_on_ue,
	 sizeof(int), 0644, NULL, proc_dointvec},
	{-2, "log_ue", &log_ue,
	 sizeof(int), 0644, NULL, proc_dointvec},
	{-3, "log_ce", &log_ce,
	 sizeof(int), 0644, NULL, proc_dointvec},
	{-4, "poll_msec", &poll_msec,
	 sizeof(int), 0644, NULL, proc_dointvec},
	{-7, "panic_on_pci_parity", &panic_on_pci_parity,
	 sizeof(int), 0644, NULL, proc_dointvec},
	{-8, "check_pci_parity", &check_pci_parity,
	 sizeof(int), 0644, NULL, proc_dointvec},
#ifdef CONFIG_EDAC_DEBUG
	{-9, "debug_level", &edac_debug_level,
	 sizeof(int), 0644, NULL, proc_dointvec},
#endif
	{0}
};


static ctl_table mc_root_table[] = {
	{CTL_DEBUG, MC_PROC_DIR, NULL, 0, 0555, mc_table},
	{0}
};


static struct ctl_table_header *mc_sysctl_header = NULL;
#endif				/* CONFIG_SYSCTL */


#ifdef CONFIG_PROC_FS
static const char *mem_types[] = {
	[MEM_EMPTY] = "Empty",
	[MEM_RESERVED] = "Reserved",
	[MEM_UNKNOWN] = "Unknown",
	[MEM_FPM] = "FPM",
	[MEM_EDO] = "EDO",
	[MEM_BEDO] = "BEDO",
	[MEM_SDR] = "Unbuffered-SDR",
	[MEM_RDR] = "Registered-SDR",
	[MEM_DDR] = "Unbuffered-DDR",
	[MEM_RDDR] = "Registered-DDR",
	[MEM_RMBS] = "RMBS"
};

static const char *dev_types[] = {
	[DEV_UNKNOWN] = "Unknown",
	[DEV_X1] = "x1",
	[DEV_X2] = "x2",
	[DEV_X4] = "x4",
	[DEV_X8] = "x8",
	[DEV_X16] = "x16",
	[DEV_X32] = "x32",
	[DEV_X64] = "x64"
};

static const char *edac_caps[] = {
	[EDAC_UNKNOWN] = "Unknown",
	[EDAC_NONE] = "None",
	[EDAC_RESERVED] = "Reserved",
	[EDAC_PARITY] = "PARITY",
	[EDAC_EC] = "EC",
	[EDAC_SECDED] = "SECDED",
	[EDAC_S2ECD2ED] = "S2ECD2ED",
	[EDAC_S4ECD4ED] = "S4ECD4ED",
	[EDAC_S8ECD8ED] = "S8ECD8ED",
	[EDAC_S16ECD16ED] = "S16ECD16ED"
};


/* FIXME - CHANNEL_PREFIX is pretty bad */
#define CHANNEL_PREFIX(...) \
	do { \
		p += sprintf(p, "%d.%d:%s", \
			chan->csrow->csrow_idx, \
			chan->chan_idx, \
			chan->label); \
		p += sprintf(p, ":" __VA_ARGS__); \
	} while (0)


static inline int mc_proc_output_channel(char *buf,
					 struct channel_info *chan)
{
	char *p = buf;

	CHANNEL_PREFIX("CE:\t\t%d\n", chan->ce_count);
	return p - buf;
}

#undef CHANNEL_PREFIX


#define CSROW_PREFIX(...) \
	do { \
		int i; \
		p += sprintf(p, "%d:", csrow->csrow_idx); \
		p += sprintf(p, "%s", csrow->channels[0].label); \
		for (i = 1; i < csrow->nr_channels; i++) \
			p += sprintf(p, "|%s", csrow->channels[i].label); \
		p += sprintf(p, ":" __VA_ARGS__); \
	} while (0)


static inline int mc_proc_output_csrow(char *buf, struct csrow_info *csrow)
{
	char *p = buf;
	int chan_idx;

	debugf3("MC: " __FILE__ ": %s()\n", __func__);

	CSROW_PREFIX("Memory Size:\t%d MiB\n",
		     (u32) PAGES_TO_MiB(csrow->nr_pages));
	CSROW_PREFIX("Mem Type:\t\t%s\n", mem_types[csrow->mtype]);
	CSROW_PREFIX("Dev Type:\t\t%s\n", dev_types[csrow->dtype]);
	CSROW_PREFIX("EDAC Mode:\t\t%s\n", edac_caps[csrow->edac_mode]);
	CSROW_PREFIX("UE:\t\t\t%d\n", csrow->ue_count);
	CSROW_PREFIX("CE:\t\t\t%d\n", csrow->ce_count);

	for (chan_idx = 0; chan_idx < csrow->nr_channels; chan_idx++)
		p += mc_proc_output_channel(p, &csrow->channels[chan_idx]);

	p += sprintf(p, "\n");
	return p - buf;
}

#undef CSROW_PREFIX


static inline int mc_proc_output_edac_cap(char *buf,
					  unsigned long edac_cap)
{
	char *p = buf;
	int bit_idx;

	for (bit_idx = 0; bit_idx < 8 * sizeof(edac_cap); bit_idx++) {
		if ((edac_cap >> bit_idx) & 0x1)
			p += sprintf(p, "%s ", edac_caps[bit_idx]);
	}

	return p - buf;
}


static inline int mc_proc_output_mtype_cap(char *buf,
					   unsigned long mtype_cap)
{
	char *p = buf;
	int bit_idx;

	for (bit_idx = 0; bit_idx < 8 * sizeof(mtype_cap); bit_idx++) {
		if ((mtype_cap >> bit_idx) & 0x1)
			p += sprintf(p, "%s ", mem_types[bit_idx]);
	}

	return p - buf;
}


static int mc_proc_output(struct mem_ctl_info *mci, char *buf)
{
	int csrow_idx;
	u32 total_pages;
	char *p = buf;

	debugf3("MC%d: " __FILE__ ": %s()\n", mci->mc_idx, __func__);

	p += sprintf(p, "Check PCI Parity:\t%d\n", check_pci_parity);
	p += sprintf(p, "Panic PCI Parity:\t%d\n", panic_on_pci_parity);
	p += sprintf(p, "Panic UE:\t\t%d\n", panic_on_ue);
	p += sprintf(p, "Log UE:\t\t\t%d\n", log_ue);
	p += sprintf(p, "Log CE:\t\t\t%d\n", log_ce);
	p += sprintf(p, "Poll msec:\t\t%d\n", poll_msec);

	p += sprintf(p, "\n");

	p += sprintf(p, "MC Core:\t\t%s\n", EDAC_MC_VERSION );
	p += sprintf(p, "MC Module:\t\t%s %s\n", mci->mod_name,
		     mci->mod_ver);
	p += sprintf(p, "Memory Controller:\t%s\n", mci->ctl_name);
	p += sprintf(p, "PCI Bus ID:\t\t%s (%s)\n", mci->pdev->dev.bus_id,
		     pci_name(mci->pdev));

	p += sprintf(p, "EDAC capability:\t");
	p += mc_proc_output_edac_cap(p, mci->edac_ctl_cap);
	p += sprintf(p, "\n");

	p += sprintf(p, "Current EDAC capability:\t");
	p += mc_proc_output_edac_cap(p, mci->edac_cap);
	p += sprintf(p, "\n");

	p += sprintf(p, "Supported Mem Types:\t");
	p += mc_proc_output_mtype_cap(p, mci->mtype_cap);
	p += sprintf(p, "\n");

	p += sprintf(p, "\n");

	for (total_pages = csrow_idx = 0; csrow_idx < mci->nr_csrows;
	     csrow_idx++) {
		struct csrow_info *csrow = &mci->csrows[csrow_idx];

		if (!csrow->nr_pages)
			continue;
		total_pages += csrow->nr_pages;
		p += mc_proc_output_csrow(p, csrow);
	}

	p += sprintf(p, "Total Memory Size:\t%d MiB\n",
		     (u32) PAGES_TO_MiB(total_pages));
	p += sprintf(p, "Seconds since reset:\t%ld\n",
		     (jiffies - mci->start_time) / HZ);
	p += sprintf(p, "UE No Info:\t\t%d\n", mci->ue_noinfo_count);
	p += sprintf(p, "CE No Info:\t\t%d\n", mci->ce_noinfo_count);
	p += sprintf(p, "Total UE:\t\t%d\n", mci->ue_count);
	p += sprintf(p, "Total CE:\t\t%d\n", mci->ce_count);
	p += sprintf(p, "Total PCI Parity:\t%u\n\n", pci_parity_count);
	return p - buf;
}


static int mc_read_proc(char *page, char **start, off_t off, int count,
			int *eof, void *data)
{
	int len;
	struct mem_ctl_info *mci = (struct mem_ctl_info *) data;

	debugf3("MC%d: " __FILE__ ": %s()\n", mci->mc_idx, __func__);

	down(&mem_ctls_mutex);
	len = mc_proc_output(mci, page);
	up(&mem_ctls_mutex);
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;

	return len;
}
#endif				/* CONFIG_PROC_FS */


#ifdef CONFIG_EDAC_DEBUG


EXPORT_SYMBOL(edac_mc_dump_channel);

void edac_mc_dump_channel(struct channel_info *chan)
{
	printk(KERN_INFO "\tchannel = %p\n", chan);
	printk(KERN_INFO "\tchannel->chan_idx = %d\n", chan->chan_idx);
	printk(KERN_INFO "\tchannel->ce_count = %d\n", chan->ce_count);
	printk(KERN_INFO "\tchannel->label = '%s'\n", chan->label);
	printk(KERN_INFO "\tchannel->csrow = %p\n\n", chan->csrow);
}


EXPORT_SYMBOL(edac_mc_dump_csrow);

void edac_mc_dump_csrow(struct csrow_info *csrow)
{
	printk(KERN_INFO "\tcsrow = %p\n", csrow);
	printk(KERN_INFO "\tcsrow->csrow_idx = %d\n", csrow->csrow_idx);
	printk(KERN_INFO "\tcsrow->first_page = 0x%lx\n",
	       csrow->first_page);
	printk(KERN_INFO "\tcsrow->last_page = 0x%lx\n", csrow->last_page);
	printk(KERN_INFO "\tcsrow->page_mask = 0x%lx\n", csrow->page_mask);
	printk(KERN_INFO "\tcsrow->nr_pages = 0x%x\n", csrow->nr_pages);
	printk(KERN_INFO "\tcsrow->nr_channels = %d\n",
	       csrow->nr_channels);
	printk(KERN_INFO "\tcsrow->channels = %p\n", csrow->channels);
	printk(KERN_INFO "\tcsrow->mci = %p\n\n", csrow->mci);
}


EXPORT_SYMBOL(edac_mc_dump_mci);

void edac_mc_dump_mci(struct mem_ctl_info *mci)
{
	printk(KERN_INFO "\tmci = %p\n", mci);
	printk(KERN_INFO "\tmci->mtype_cap = %lx\n", mci->mtype_cap);
	printk(KERN_INFO "\tmci->edac_ctl_cap = %lx\n", mci->edac_ctl_cap);
	printk(KERN_INFO "\tmci->edac_cap = %lx\n", mci->edac_cap);
	printk(KERN_INFO "\tmci->edac_check = %p\n", mci->edac_check);
	printk(KERN_INFO "\tmci->nr_csrows = %d, csrows = %p\n",
	       mci->nr_csrows, mci->csrows);
	printk(KERN_INFO "\tpdev = %p\n", mci->pdev);
	printk(KERN_INFO "\tmod_name:ctl_name = %s:%s\n",
	       mci->mod_name, mci->ctl_name);
	printk(KERN_INFO "\tpvt_info = %p\n\n", mci->pvt_info);
}


#endif				/* CONFIG_EDAC_DEBUG */

/* 'ptr' points to a possibly unaligned item X such that sizeof(X) is 'size'.
 * Adjust 'ptr' so that its alignment is at least as stringent as what the
 * compiler would provide for X and return the aligned result.
 *
 * If 'size' is a constant, the compiler will optimize this whole function
 * down to either a no-op or the addition of a constant to the value of 'ptr'.
 */
static inline char * align_ptr (void *ptr, unsigned size)
{
	unsigned align, r;

	/* Here we assume that the alignment of a "long long" is the most
	 * stringent alignment that the compiler will ever provide by default.
	 * As far as I know, this is a reasonable assumption.
	 */
	if (size > sizeof(long))
		align = sizeof(long long);
	else if (size > sizeof(int))
		align = sizeof(long);
	else if (size > sizeof(short))
		align = sizeof(int);
	else if (size > sizeof(char))
		align = sizeof(short);
	else
		return (char *) ptr;

	r = size % align;

	if (r == 0)
		return (char *) ptr;

	return (char *) (((unsigned long) ptr) + align - r);
}


EXPORT_SYMBOL(edac_mc_alloc);

/* Everything is kmalloc'ed as one big chunk - more efficient.
 * Only can be used if all structures have the same lifetime - otherwise
 * you have to allocate and initialize your own structures.
 *
 * Use edac_mc_free() to free mc structures allocated by this function.
 */
struct mem_ctl_info *edac_mc_alloc(unsigned sz_pvt, unsigned nr_csrows,
					unsigned nr_chans)
{
	struct mem_ctl_info *mci;
	struct csrow_info *csi, *csrow;
	struct channel_info *chi, *chp, *chan;
	void *pvt;
	unsigned size;
	int row, chn;

	/* Figure out the offsets of the various items from the start of an mc
	 * structure.  We want the alignment of each item to be at least as
	 * stringent as what the compiler would provide if we could simply
	 * hardcode everything into a single struct.
	 */
	mci = (struct mem_ctl_info *) 0;
	csi = (struct csrow_info *)
	      align_ptr(&mci[1], sizeof(*csi));
	chi = (struct channel_info *)
	      align_ptr(&csi[nr_csrows], sizeof(*chi));
	pvt = align_ptr(&chi[nr_chans * nr_csrows], sz_pvt);
	size = ((unsigned long) pvt) + sz_pvt;

	if ((mci = kmalloc(size, GFP_KERNEL)) == NULL)
		return NULL;

	/* Adjust pointers so they point within the memory we just allocated
	 * rather than an imaginary chunk of memory located at address 0.
	 */
	csi = (struct csrow_info *) (((char *) mci) + ((unsigned long) csi));
	chi = (struct channel_info *) (((char *) mci) + ((unsigned long) chi));
	pvt = sz_pvt ? (((char *) mci) + ((unsigned long) pvt)) : NULL;

	memset(mci, 0, size);
	mci->csrows = csi;
	mci->pvt_info = pvt;
	mci->nr_csrows = nr_csrows;

	for (row = 0; row < nr_csrows; row++) {
		csrow = &csi[row];
		csrow->csrow_idx = row;
		csrow->mci = mci;
		csrow->nr_channels = nr_chans;
		chp = &chi[row * nr_chans];
		csrow->channels = chp;

		for (chn = 0; chn < nr_chans; chn++) {
			chan = &chp[chn];
			chan->chan_idx = chn;
			chan->csrow = csrow;
		}
	}

	return mci;
}

static struct mem_ctl_info *find_mci_by_pdev(struct pci_dev *pdev)
{
	struct mem_ctl_info *mci;
	struct list_head *item;

	debugf3("MC: " __FILE__ ": %s()\n", __func__);

	list_for_each(item, &mc_devices) {
		mci = list_entry(item, struct mem_ctl_info, link);

		if (mci->pdev == pdev)
			return mci;
	}

	return NULL;
}

static int add_mc_to_global_list (struct mem_ctl_info *mci)
{
	struct list_head *item, *insert_before;
	struct mem_ctl_info *p;
	int i;

	if (list_empty(&mc_devices)) {
		mci->mc_idx = 0;
		insert_before = &mc_devices;
	} else {
		if (find_mci_by_pdev(mci->pdev)) {
			printk(KERN_WARNING
			       "MC: %s (%s) %s %s already assigned %d\n",
			       mci->pdev->dev.bus_id, pci_name(mci->pdev),
			       mci->mod_name, mci->ctl_name, mci->mc_idx);
			return 1;
		}

		insert_before = NULL;
		i = 0;

		list_for_each(item, &mc_devices) {
			p = list_entry(item, struct mem_ctl_info, link);

			if (p->mc_idx != i) {
				insert_before = item;
				break;
			}

			i++;
		}

		mci->mc_idx = i;

		if (insert_before == NULL)
			insert_before = &mc_devices;
	}

	list_add_tail_rcu(&mci->link, insert_before);
	return 0;
}


/**
 * edac_mc_find: Search for a mem_ctl_info structure whose index is 'idx'.
 *
 * If found, return a pointer to the structure.
 * Else return NULL.
 *
 * Caller must hold mem_ctls_mutex.
 */
struct mem_ctl_info * edac_mc_find(int idx)
{
	struct list_head *item;
	struct mem_ctl_info *mci;

	list_for_each(item, &mc_devices) {
		mci = list_entry(item, struct mem_ctl_info, link);

		if (mci->mc_idx >= idx) {
			if (mci->mc_idx == idx)
				return mci;

			break;
		}
	}

	return NULL;
}
EXPORT_SYMBOL(edac_mc_find);

static void complete_mc_list_del (struct rcu_head *head)
{
	struct mem_ctl_info *mci;

	mci = container_of(head, struct mem_ctl_info, rcu);
	INIT_LIST_HEAD(&mci->link);
	complete(&mci->complete);
}

static void del_mc_from_global_list (struct mem_ctl_info *mci)
{
	list_del_rcu(&mci->link);
	init_completion(&mci->complete);
	call_rcu(&mci->rcu, complete_mc_list_del);
	wait_for_completion(&mci->complete);
}

EXPORT_SYMBOL(edac_mc_add_mc);

/* FIXME - should a warning be printed if no error detection? correction? */
int edac_mc_add_mc(struct mem_ctl_info *mci)
{
	debugf0("MC: " __FILE__ ": %s()\n", __func__);
#ifdef CONFIG_EDAC_DEBUG
	if (edac_debug_level >= 1)
		edac_mc_dump_mci(mci);
	if (edac_debug_level >= 2) {
		int i;

		for (i = 0; i < mci->nr_csrows; i++) {
			int j;
			edac_mc_dump_csrow(&mci->csrows[i]);
			for (j = 0; j < mci->csrows[i].nr_channels; j++)
				edac_mc_dump_channel(&mci->csrows[i].
							  channels[j]);
		}
	}
#endif
	down(&mem_ctls_mutex);

	if (add_mc_to_global_list(mci))
		goto fail0;

	printk(KERN_INFO
	       "MC%d: Giving out device to %s %s: PCI %s (%s)\n",
	       mci->mc_idx, mci->mod_name, mci->ctl_name,
	       mci->pdev->dev.bus_id, pci_name(mci->pdev));

	/* set load time so that error rate can be tracked */
	mci->start_time = jiffies;

	if (snprintf(mci->proc_name, MC_PROC_NAME_MAX_LEN,
		     "%d", mci->mc_idx) == MC_PROC_NAME_MAX_LEN) {
		printk(KERN_WARNING
		       "MC%d: proc entry too long for device\n",
		       mci->mc_idx);
		goto fail1;
	}

	if(create_proc_read_entry(mci->proc_name, 0, proc_mc,
	                          mc_read_proc, (void *) mci) == NULL) {
		printk(KERN_WARNING
		       "MC%d: failed to create proc entry for controller\n",
		       mci->mc_idx);
		goto fail1;
	}

	up(&mem_ctls_mutex);
	return 0;

fail1:
	del_mc_from_global_list(mci);
fail0:
 	up(&mem_ctls_mutex);
	return 1;
}

EXPORT_SYMBOL(edac_mc_del_mc);

struct mem_ctl_info *edac_mc_del_mc(struct pci_dev *pdev)
{
	struct mem_ctl_info *mci;

	debugf0("MC: %s()\n", __func__);
	down(&mem_ctls_mutex);

	if ((mci = find_mci_by_pdev(pdev)) == NULL) {
		up(&mem_ctls_mutex);
		return NULL;
	}

	del_mc_from_global_list(mci);
	remove_proc_entry(mci->proc_name, proc_mc);
	up(&mem_ctls_mutex);
	printk(KERN_INFO
	       "MC%d: Removed device %d for %s %s: PCI %s (%s)\n",
	       mci->mc_idx, mci->mc_idx, mci->mod_name, mci->ctl_name,
	       mci->pdev->dev.bus_id, pci_name(mci->pdev));
	return mci;
}


EXPORT_SYMBOL(edac_mc_scrub_block);


void edac_mc_scrub_block(unsigned long page, unsigned long offset,
			      u32 size)
{
	struct page *pg;
	void *virt_addr;
	unsigned long flags;

	debugf3("MC: " __FILE__ ": %s()\n", __func__);

	/* ECC error page was not in our memory. Ignore it. */
	if(!pfn_valid(page))
		return;

	/* Find the actual page structure then map it and fix */
	pg = pfn_to_page(page);

	virt_addr = kmap_atomic_maybe_irqsave(pg, KM_BOUNCE_READ, flags);

	/* Perform architecture specific atomic scrub operation */
	atomic_scrub(virt_addr + offset, size);

	/* Unmap and complete */
	kunmap_atomic_maybe_irqrestore(virt_addr, KM_BOUNCE_READ, flags);
}


/* FIXME - should return -1 */
EXPORT_SYMBOL(edac_mc_find_csrow_by_page);

int edac_mc_find_csrow_by_page(struct mem_ctl_info *mci,
				    unsigned long page)
{
	struct csrow_info *csrows = mci->csrows;
	int row, i;

	debugf1("MC%d: " __FILE__ ": %s(): 0x%lx\n", mci->mc_idx, __func__,
		page);
	row = -1;

	for (i = 0; i < mci->nr_csrows; i++) {
		struct csrow_info *csrow = &csrows[i];

		if (csrow->nr_pages == 0)
			continue;

		debugf3("MC%d: " __FILE__
			": %s(): first(0x%lx) page(0x%lx)"
			" last(0x%lx) mask(0x%lx)\n", mci->mc_idx,
			__func__, csrow->first_page, page,
			csrow->last_page, csrow->page_mask);

		if ((page >= csrow->first_page) &&
		    (page <= csrow->last_page) &&
		    ((page & csrow->page_mask) ==
		     (csrow->first_page & csrow->page_mask))) {
			row = i;
			break;
		}
	}

	if (row == -1)
		printk(KERN_ERR
		       "MC%d: could not look up page error address %lx\n",
		       mci->mc_idx, (unsigned long) page);

	return row;
}


EXPORT_SYMBOL(edac_mc_handle_ce);

/* FIXME - setable log (warning/emerg) levels */
/* FIXME - integrate with evlog: http://evlog.sourceforge.net/ */
void edac_mc_handle_ce(struct mem_ctl_info *mci,
			    unsigned long page_frame_number,
			    unsigned long offset_in_page,
			    unsigned long syndrome, int row, int channel,
			    const char *msg)
{
	unsigned long remapped_page;

	debugf3("MC%d: " __FILE__ ": %s()\n", mci->mc_idx, __func__);

	/* FIXME - maybe make panic on INTERNAL ERROR an option */
	if (row >= mci->nr_csrows || row < 0) {
		/* something is wrong */
		printk(KERN_ERR
		       "MC%d: INTERNAL ERROR: row out of range (%d >= %d)\n",
		       mci->mc_idx, row, mci->nr_csrows);
		edac_mc_handle_ce_no_info(mci, "INTERNAL ERROR");
		return;
	}
	if (channel >= mci->csrows[row].nr_channels || channel < 0) {
		/* something is wrong */
		printk(KERN_ERR
		       "MC%d: INTERNAL ERROR: channel out of range "
		       "(%d >= %d)\n",
		       mci->mc_idx, channel, mci->csrows[row].nr_channels);
		edac_mc_handle_ce_no_info(mci, "INTERNAL ERROR");
		return;
	}

	if (log_ce)
		/* FIXME - put in DIMM location */
		printk(KERN_WARNING
		       "MC%d: CE page 0x%lx, offset 0x%lx,"
		       " grain %d, syndrome 0x%lx, row %d, channel %d,"
		       " label \"%s\": %s\n", mci->mc_idx,
		       page_frame_number, offset_in_page,
		       mci->csrows[row].grain, syndrome, row, channel,
		       mci->csrows[row].channels[channel].label, msg);

	mci->ce_count++;
	mci->csrows[row].ce_count++;
	mci->csrows[row].channels[channel].ce_count++;

	if (mci->scrub_mode & SCRUB_SW_SRC) {
		/*
		 * Some MC's can remap memory so that it is still available
		 * at a different address when PCI devices map into memory.
		 * MC's that can't do this lose the memory where PCI devices
		 * are mapped.  This mapping is MC dependant and so we call
		 * back into the MC driver for it to map the MC page to
		 * a physical (CPU) page which can then be mapped to a virtual
		 * page - which can then be scrubbed.
		 */
		remapped_page = mci->ctl_page_to_phys ?
		    mci->ctl_page_to_phys(mci, page_frame_number) :
		    page_frame_number;

		edac_mc_scrub_block(remapped_page, offset_in_page,
					 mci->csrows[row].grain);
	}
}


EXPORT_SYMBOL(edac_mc_handle_ce_no_info);

void edac_mc_handle_ce_no_info(struct mem_ctl_info *mci,
				    const char *msg)
{
	if (log_ce)
		printk(KERN_WARNING
		       "MC%d: CE - no information available: %s\n",
		       mci->mc_idx, msg);
	mci->ce_noinfo_count++;
	mci->ce_count++;
}


EXPORT_SYMBOL(edac_mc_handle_ue);

void edac_mc_handle_ue(struct mem_ctl_info *mci,
			    unsigned long page_frame_number,
			    unsigned long offset_in_page, int row,
			    const char *msg)
{
	int len = EDAC_MC_LABEL_LEN * 4;
	char labels[len + 1];
	char *pos = labels;
	int chan;
	int chars;

	debugf3("MC%d: " __FILE__ ": %s()\n", mci->mc_idx, __func__);

	/* FIXME - maybe make panic on INTERNAL ERROR an option */
	if (row >= mci->nr_csrows || row < 0) {
		/* something is wrong */
		printk(KERN_ERR
		       "MC%d: INTERNAL ERROR: row out of range (%d >= %d)\n",
		       mci->mc_idx, row, mci->nr_csrows);
		edac_mc_handle_ue_no_info(mci, "INTERNAL ERROR");
		return;
	}

	chars = snprintf(pos, len + 1, "%s",
			 mci->csrows[row].channels[0].label);
	len -= chars;
	pos += chars;
	for (chan = 1; (chan < mci->csrows[row].nr_channels) && (len > 0);
	     chan++) {
		chars = snprintf(pos, len + 1, ":%s",
				 mci->csrows[row].channels[chan].label);
		len -= chars;
		pos += chars;
	}

	if (log_ue)
		printk(KERN_EMERG
		       "MC%d: UE page 0x%lx, offset 0x%lx, grain %d, row %d,"
		       " labels \"%s\": %s\n", mci->mc_idx,
		       page_frame_number, offset_in_page,
		       mci->csrows[row].grain, row, labels, msg);

	if (panic_on_ue)
		panic
		    ("MC%d: UE page 0x%lx, offset 0x%lx, grain %d, row %d,"
		     " labels \"%s\": %s\n", mci->mc_idx,
		     page_frame_number, offset_in_page,
		     mci->csrows[row].grain, row, labels, msg);

	mci->ue_count++;
	mci->csrows[row].ue_count++;
}


EXPORT_SYMBOL(edac_mc_handle_ue_no_info);

void edac_mc_handle_ue_no_info(struct mem_ctl_info *mci,
				    const char *msg)
{
	if (panic_on_ue)
		panic("MC%d: Uncorrected Error", mci->mc_idx);

	if (log_ue)
		printk(KERN_WARNING
		       "MC%d: UE - no information available: %s\n",
		       mci->mc_idx, msg);
	mci->ue_noinfo_count++;
	mci->ue_count++;
}


/*
 *  PCI Parity polling
 *
 */
static inline void edac_pci_dev_parity_test( struct pci_dev *dev )
{
	u16 status;
	u8  header_type;

	/* read the STATUS register on this device
	 */
	pci_read_config_word(dev, PCI_STATUS, &status);

	debugf2("PCI STATUS= 0x%04x %s\n", status, dev->dev.bus_id );
	status &= PCI_STATUS_DETECTED_PARITY | PCI_STATUS_SIG_SYSTEM_ERROR |
		  PCI_STATUS_PARITY;

	/* check the status reg for errors */
	if (status) {

		/* reset only the bits we are interested in */
		pci_write_config_word(dev, PCI_STATUS, status);

		if (status & (PCI_STATUS_SIG_SYSTEM_ERROR))
			printk(KERN_CRIT
			   	"PCI- "
				"Signalled System Error on %s %s\n",
				dev->dev.bus_id,
				pci_name(dev));

		if (status & (PCI_STATUS_PARITY)) {
			printk(KERN_CRIT
			   	"PCI- "
				"Master Data Parity Error on %s %s\n",
				dev->dev.bus_id,
				pci_name(dev));

			pci_parity_count++;
		}

		if (status & (PCI_STATUS_DETECTED_PARITY)) {
			printk(KERN_CRIT
			   	"PCI- "
				"Detected Parity Error on %s %s\n",
				dev->dev.bus_id,
				pci_name(dev));

			pci_parity_count++;
		}
	}

	/* read the device TYPE, looking for bridges */
	pci_read_config_byte(dev, PCI_HEADER_TYPE, &header_type);

	debugf2("PCI HEADER TYPE= 0x%02x %s\n", header_type, dev->dev.bus_id );

	if( (header_type & 0x7F) == PCI_HEADER_TYPE_BRIDGE ) {

	 	/* On bridges, need to examine secondary status register  */
		pci_read_config_word(dev, PCI_SEC_STATUS, &status);

		debugf2("PCI SEC_STATUS= 0x%04x %s\n", status, dev->dev.bus_id );
		status &= PCI_STATUS_DETECTED_PARITY |
			  PCI_STATUS_SIG_SYSTEM_ERROR |
			  PCI_STATUS_PARITY;

		/* check the secondary status reg for errors */
		if (status) {

			/* reset only the bits we are interested in */
			pci_write_config_word(dev, PCI_SEC_STATUS, status);

			if (status & (PCI_STATUS_SIG_SYSTEM_ERROR))
				printk(KERN_CRIT
					"PCI-Bridge- "
					"Signalled System Error on %s %s\n",
					dev->dev.bus_id,
					pci_name(dev));

			if (status & (PCI_STATUS_PARITY)) {
				printk(KERN_CRIT
					"PCI-Bridge- "
					"Master Data Parity Error on %s %s\n",
					dev->dev.bus_id,
					pci_name(dev));

				pci_parity_count++;
			}

			if (status & (PCI_STATUS_DETECTED_PARITY)) {
				printk(KERN_CRIT
					"PCI-Bridge- "
					"Detected Parity Error on %s %s\n",
					dev->dev.bus_id,
					pci_name(dev));

				pci_parity_count++;
			}
		}
	}
}

/*
 * pci_dev parity list iterator
 * 	Scan the PCI device list for one iteration, looking for SERRORs
 *	Master Parity ERRORS or Parity ERRORs on primary or secondary devices
 */
static inline void edac_pci_dev_parity_iterator(void)
{
	struct pci_dev *dev=NULL;
	u32 before_count = pci_parity_count;


	/* request for kernel access to the next PCI device, if any,
	 * and while we are looking at it have its reference count
	 * bumped until we are done with it
	 */
	while((dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, dev)) != NULL) {

		edac_pci_dev_parity_test( dev );
	}

	/* Only if operator has selected panic on PCI Error */
	if(panic_on_pci_parity) {
		/* If the count is different 'after' from 'before' */
		if( before_count != pci_parity_count )
			panic("EDAC: PCI Parity Error");
	}
}


static void check_mc_devices (void)
{
	struct list_head *item;
	struct mem_ctl_info *mci;

	debugf3("MC: " __FILE__ ": %s()\n", __func__);

	down(&mem_ctls_mutex);

	list_for_each(item, &mc_devices) {
		mci = list_entry(item, struct mem_ctl_info, link);

		if (mci->edac_check != NULL)
			mci->edac_check(mci);
	}

	up(&mem_ctls_mutex);
}


/*
 * Check MC status every poll_msec.
 * This where the work gets done for edac.
 *
 * SMP safe, doesn't use NMI, and auto-rate-limits.
 */
static void check_mc(unsigned long dummy)
{
	unsigned long flags;

	debugf3("MC: " __FILE__ ": %s()\n", __func__);
	check_mc_devices();

	if (check_pci_parity) {
		/* scan all PCI devices looking for a Parity Error on
		 * devices and bridges
		 */
		local_irq_save(flags);
		edac_pci_dev_parity_iterator();
		local_irq_restore(flags);
	}
}

static inline signed long __sched schedule_timeout_interruptible(signed long timeout)
{
       __set_current_state(TASK_INTERRUPTIBLE);
       return schedule_timeout(timeout);
}

static int edac_kernel_thread(void *arg)
{
	while (!kthread_should_stop()) {
		check_mc_devices();

 		/* goto sleep for the interval */
		schedule_timeout_interruptible((HZ * poll_msec) / 1000);
 	}
	return 0;
}

/*
 * edac_mc_init
 *      module initialization entry point
 */
int __init edac_mc_init(void)
{
	debugf0("MC: " __FILE__ ": %s()\n", __func__);
	printk(KERN_INFO "MC: " __FILE__ " version " EDAC_MC_VER
	       "\n");

	/* perform check for first time */
	check_mc(0);

	/* Create the /proc tree */
	proc_mc = proc_mkdir(MC_PROC_DIR, &proc_root);
	if (proc_mc == NULL)
		return -ENODEV;


#ifdef CONFIG_SYSCTL
	/* configure the /proc/sys system control filesystem tree */
	mc_sysctl_header = register_sysctl_table(mc_root_table, 1);
#endif				/* CONFIG_SYSCTL */

	/* create our kernel thread */
	edac_thread = kthread_run(edac_kernel_thread, NULL, "kedac");
	if (IS_ERR(edac_thread)) {
		if (proc_mc)
			remove_proc_entry(MC_PROC_DIR, &proc_root);

#ifdef CONFIG_SYSCTL
		/* if enabled, unregister our /sys tree */
		if (mc_sysctl_header) {
			unregister_sysctl_table(mc_sysctl_header);
			mc_sysctl_header = NULL;
		}
#endif                          /* CONFIG_SYSCTL */
		return PTR_ERR(edac_thread);
	}

	return 0;
}

/*
 * edac_mc_exit()
 *      module exit/termination functioni
 */
static void __exit edac_mc_exit(void)
{
	debugf0("MC: " __FILE__ ": %s()\n", __func__);

	kthread_stop(edac_thread);

	/* if enabled, unregister our /proc/mc tree */
	if (proc_mc)
		remove_proc_entry(MC_PROC_DIR, &proc_root);

#ifdef CONFIG_SYSCTL
	/* if enabled, unregister our /sys tree */
	if (mc_sysctl_header) {
		unregister_sysctl_table(mc_sysctl_header);
		mc_sysctl_header = NULL;
	}
#endif				/* CONFIG_SYSCTL */
}




module_init(edac_mc_init);
module_exit(edac_mc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Networx (http://lnxi.com) Thayne Harbaugh et al\n"
	      "Based on.work by Dan Hollis et al");
MODULE_DESCRIPTION("Core library routines for MC reporting");

module_param(panic_on_ue, int, 0644);
MODULE_PARM_DESC(panic_on_ue, "Panic on uncorrected error: 0=off 1=on");
module_param(check_pci_parity, int, 0644);
MODULE_PARM_DESC(check_pci_parity, "Check for PCI bus parity errors: 0=off 1=on");
module_param(panic_on_pci_parity, int, 0644);
MODULE_PARM_DESC(panic_on_pci_parity, "Panic on PCI Bus Parity error: 0=off 1=on");
module_param(log_ue, int, 0644);
MODULE_PARM_DESC(log_ue, "Log uncorrectable error to console: 0=off 1=on");
module_param(log_ce, int, 0644);
MODULE_PARM_DESC(log_ce, "Log correctable error to console: 0=off 1=on");
module_param(poll_msec, int, 0644);
MODULE_PARM_DESC(poll_msec, "Polling period in milliseconds");
#ifdef CONFIG_EDAC_DEBUG
module_param(edac_debug_level, int, 0644);
MODULE_PARM_DESC(edac_debug_level, "Debug level");
#endif

#ifndef _IPATH_KERNEL_H
#define _IPATH_KERNEL_H
/*
 * Copyright (c) 2003, 2004, 2005, 2006 PathScale, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * This header file is the base header file for infinipath kernel code
 * ipath_user.h serves a similar purpose for user code.
 */

#include <linux/interrupt.h>
#include <asm/io.h>

#include "ipath_backport.h"
#include "ipath_common.h"
#include "ipath_debug.h"
#include "ipath_registers.h"

/* only s/w major version of InfiniPath we can handle */
#define IPATH_CHIP_VERS_MAJ 2U

/* don't care about this except printing */
#define IPATH_CHIP_VERS_MIN 0U

/* temporary, maybe always */
extern struct infinipath_stats ipath_stats;

#define IPATH_CHIP_SWVERSION IPATH_CHIP_VERS_MAJ

struct ipath_portdata {
	void **port_rcvegrbuf;
	dma_addr_t *port_rcvegrbuf_phys;
	/* rcvhdrq base, needs mmap before useful */
	void *port_rcvhdrq;
	/* kernel virtual address where hdrqtail is updated */
	volatile __le64 *port_rcvhdrtail_kvaddr;
	/*
	 * temp buffer for expected send setup, allocated at open, instead
	 * of each setup call
	 */
	void *port_tid_pg_list;
	/* when waiting for rcv or pioavail */
	wait_queue_head_t port_wait;
	/*
	 * rcvegr bufs base, physical, must fit
	 * in 44 bits so 32 bit programs mmap64 44 bit works)
	 */
	dma_addr_t port_rcvegr_phys;
	/* mmap of hdrq, must fit in 44 bits */
	dma_addr_t port_rcvhdrq_phys;
	dma_addr_t port_rcvhdrqtailaddr_phys;
	/*
	 * number of opens on this instance (0 or 1; ignoring forks, dup,
	 * etc. for now)
	 */
	int port_cnt;
	/*
	 * how much space to leave at start of eager TID entries for
	 * protocol use, on each TID
	 */
	/* instead of calculating it */
	unsigned port_port;
	/* chip offset of PIO buffers for this port */
	u32 port_piobufs;
	/* how many alloc_pages() chunks in port_rcvegrbuf_pages */
	u32 port_rcvegrbuf_chunks;
	/* how many egrbufs per chunk */
	u32 port_rcvegrbufs_perchunk;
	/* order for port_rcvegrbuf_pages */
	size_t port_rcvegrbuf_size;
	/* rcvhdrq size (for freeing) */
	size_t port_rcvhdrq_size;
	/* next expected TID to check when looking for free */
	u32 port_tidcursor;
	/* next expected TID to check */
	unsigned long port_flag;
	/* WAIT_RCV that timed out, no interrupt */
	u32 port_rcvwait_to;
	/* WAIT_PIO that timed out, no interrupt */
	u32 port_piowait_to;
	/* WAIT_RCV already happened, no wait */
	u32 port_rcvnowait;
	/* WAIT_PIO already happened, no wait */
	u32 port_pionowait;
	/* total number of rcvhdrqfull errors */
	u32 port_hdrqfull;
	/* pid of process using this port */
	pid_t port_pid;
	/* same size as task_struct .comm[] */
	char port_comm[16];
	/* pkeys set by this use of this port */
	u16 port_pkeys[4];
	/* so file ops can get at unit */
	struct ipath_devdata *port_dd;
};

struct sk_buff;

/*
 * control information for layered drivers
 */
struct _ipath_layer {
	void *l_arg;
};

/* Verbs layer interface */
struct _verbs_layer {
	void *l_arg;
	struct timer_list l_timer;
};

struct ipath_devdata {
	struct list_head ipath_list;

	struct ipath_kregs const *ipath_kregs;
	struct ipath_cregs const *ipath_cregs;

	/* mem-mapped pointer to base of chip regs */
	u64 __iomem *ipath_kregbase;
	/* end of mem-mapped chip space; range checking */
	u64 __iomem *ipath_kregend;
	/* physical address of chip for io_remap, etc. */
	unsigned long ipath_physaddr;
	/* base of memory alloced for ipath_kregbase, for free */
	u64 *ipath_kregalloc;
	/*
	 * version of kregbase that doesn't have high bits set (for 32 bit
	 * programs, so mmap64 44 bit works)
	 */
	u64 __iomem *ipath_kregvirt;
	/*
	 * virtual address where port0 rcvhdrqtail updated for this unit.
	 * only written to by the chip, not the driver.
	 */
	volatile __le64 *ipath_hdrqtailptr;
	/* ipath_cfgports pointers */
	struct ipath_portdata **ipath_pd;
	/* sk_buffs used by port 0 eager receive queue */
	struct sk_buff **ipath_port0_skbs;
	/* kvirt address of 1st 2k pio buffer */
	void __iomem *ipath_pio2kbase;
	/* kvirt address of 1st 4k pio buffer */
	void __iomem *ipath_pio4kbase;
	/*
	 * points to area where PIOavail registers will be DMA'ed.
	 * Has to be on a page of it's own, because the page will be
	 * mapped into user program space.  This copy is *ONLY* ever
	 * written by DMA, not by the driver!  Need a copy per device
	 * when we get to multiple devices
	 */
	volatile __le64 *ipath_pioavailregs_dma;
	/* physical address where updates occur */
	dma_addr_t ipath_pioavailregs_phys;
	struct _ipath_layer ipath_layer;
	/* setup intr */
	int (*ipath_f_intrsetup)(struct ipath_devdata *);
	/* setup on-chip bus config */
	int (*ipath_f_bus)(struct ipath_devdata *, struct pci_dev *);
	/* hard reset chip */
	int (*ipath_f_reset)(struct ipath_devdata *);
	int (*ipath_f_get_boardname)(struct ipath_devdata *, char *,
				     size_t);
	void (*ipath_f_init_hwerrors)(struct ipath_devdata *);
	void (*ipath_f_handle_hwerrors)(struct ipath_devdata *, char *,
					size_t);
	void (*ipath_f_quiet_serdes)(struct ipath_devdata *);
	int (*ipath_f_bringup_serdes)(struct ipath_devdata *);
	int (*ipath_f_early_init)(struct ipath_devdata *);
	void (*ipath_f_clear_tids)(struct ipath_devdata *, unsigned);
	void (*ipath_f_put_tid)(struct ipath_devdata *, u64 __iomem*,
				u32, unsigned long);
	void (*ipath_f_tidtemplate)(struct ipath_devdata *);
	void (*ipath_f_cleanup)(struct ipath_devdata *);
	void (*ipath_f_setextled)(struct ipath_devdata *, u64, u64);
	/* fill out chip-specific fields */
	int (*ipath_f_get_base_info)(struct ipath_portdata *, void *);
	struct _verbs_layer verbs_layer;
	/* total dwords sent (summed from counter) */
	u64 ipath_sword;
	/* total dwords rcvd (summed from counter) */
	u64 ipath_rword;
	/* total packets sent (summed from counter) */
	u64 ipath_spkts;
	/* total packets rcvd (summed from counter) */
	u64 ipath_rpkts;
	/* ipath_statusp initially points to this. */
	u64 _ipath_status;
	/* GUID for this interface, in network order */
	__be64 ipath_guid;
	/*
	 * aggregrate of error bits reported since last cleared, for
	 * limiting of error reporting
	 */
	ipath_err_t ipath_lasterror;
	/*
	 * aggregrate of error bits reported since last cleared, for
	 * limiting of hwerror reporting
	 */
	ipath_err_t ipath_lasthwerror;
	/*
	 * errors masked because they occur too fast, also includes errors
	 * that are always ignored (ipath_ignorederrs)
	 */
	ipath_err_t ipath_maskederrs;
	/* time in jiffies at which to re-enable maskederrs */
	unsigned long ipath_unmasktime;
	/*
	 * errors always ignored (masked), at least for a given
	 * chip/device, because they are wrong or not useful
	 */
	ipath_err_t ipath_ignorederrs;
	/* count of egrfull errors, combined for all ports */
	u64 ipath_last_tidfull;
	/* for ipath_qcheck() */
	u64 ipath_lastport0rcv_cnt;
	/* template for writing TIDs  */
	u64 ipath_tidtemplate;
	/* value to write to free TIDs */
	u64 ipath_tidinvalid;
	/* PE-800 rcv interrupt setup */
	u64 ipath_rhdrhead_intr_off;

	/* size of memory at ipath_kregbase */
	u32 ipath_kregsize;
	/* number of registers used for pioavail */
	u32 ipath_pioavregs;
	/* IPATH_POLL, etc. */
	u32 ipath_flags;
	/* ipath_flags sma is waiting for */
	u32 ipath_sma_state_wanted;
	/* last buffer for user use, first buf for kernel use is this
	 * index. */
	u32 ipath_lastport_piobuf;
	/* is a stats timer active */
	u32 ipath_stats_timer_active;
	/* dwords sent read from counter */
	u32 ipath_lastsword;
	/* dwords received read from counter */
	u32 ipath_lastrword;
	/* sent packets read from counter */
	u32 ipath_lastspkts;
	/* received packets read from counter */
	u32 ipath_lastrpkts;
	/* pio bufs allocated per port */
	u32 ipath_pbufsport;
	/*
	 * number of ports configured as max; zero is set to number chip
	 * supports, less gives more pio bufs/port, etc.
	 */
	u32 ipath_cfgports;
	/* port0 rcvhdrq head offset */
	u32 ipath_port0head;
	/* count of port 0 hdrqfull errors */
	u32 ipath_p0_hdrqfull;

	/*
	 * (*cfgports) used to suppress multiple instances of same
	 * port staying stuck at same point
	 */
	u32 *ipath_lastrcvhdrqtails;
	/*
	 * (*cfgports) used to suppress multiple instances of same
	 * port staying stuck at same point
	 */
	u32 *ipath_lastegrheads;
	/*
	 * index of last piobuffer we used.  Speeds up searching, by
	 * starting at this point.  Doesn't matter if multiple cpu's use and
	 * update, last updater is only write that matters.  Whenever it
	 * wraps, we update shadow copies.  Need a copy per device when we
	 * get to multiple devices
	 */
	u32 ipath_lastpioindex;
	/* max length of freezemsg */
	u32 ipath_freezelen;
	/*
	 * consecutive times we wanted a PIO buffer but were unable to
	 * get one
	 */
	u32 ipath_consec_nopiobuf;
	/*
	 * hint that we should update ipath_pioavailshadow before
	 * looking for a PIO buffer
	 */
	u32 ipath_upd_pio_shadow;
	/* so we can rewrite it after a chip reset */
	u32 ipath_pcibar0;
	/* so we can rewrite it after a chip reset */
	u32 ipath_pcibar1;
	/* sequential tries for SMA send and no bufs */
	u32 ipath_nosma_bufs;
	/* duration (seconds) ipath_nosma_bufs set */
	u32 ipath_nosma_secs;

	/* HT/PCI Vendor ID (here for NodeInfo) */
	u16 ipath_vendorid;
	/* HT/PCI Device ID (here for NodeInfo) */
	u16 ipath_deviceid;
	/* offset in HT config space of slave/primary interface block */
	u8 ipath_ht_slave_off;
	/* for write combining settings */
	unsigned long ipath_wc_cookie;
	/* ref count for each pkey */
	atomic_t ipath_pkeyrefs[4];
	/* shadow copy of all exptids physaddr; used only by funcsim */
	u64 *ipath_tidsimshadow;
	/* shadow copy of struct page *'s for exp tid pages */
	struct page **ipath_pageshadow;
	/* lock to workaround chip bug 9437 */
	spinlock_t ipath_tid_lock;

	/*
	 * IPATH_STATUS_*,
	 * this address is mapped readonly into user processes so they can
	 * get status cheaply, whenever they want.
	 */
	u64 *ipath_statusp;
	/* freeze msg if hw error put chip in freeze */
	char *ipath_freezemsg;
	/* pci access data structure */
	struct pci_dev *pcidev;
	struct cdev *user_cdev;
	struct cdev *diag_cdev;
	struct class_device *user_class_dev;
	struct class_device *diag_class_dev;
	/* timer used to prevent stats overflow, error throttling, etc. */
	struct timer_list ipath_stats_timer;
	/* check for stale messages in rcv queue */
	/* only allow one intr at a time. */
	unsigned long ipath_rcv_pending;
	void *ipath_dummy_hdrq;	/* used after port close */
	dma_addr_t ipath_dummy_hdrq_phys;

	/*
	 * Shadow copies of registers; size indicates read access size.
	 * Most of them are readonly, but some are write-only register,
	 * where we manipulate the bits in the shadow copy, and then write
	 * the shadow copy to infinipath.
	 *
	 * We deliberately make most of these 32 bits, since they have
	 * restricted range.  For any that we read, we won't to generate 32
	 * bit accesses, since Opteron will generate 2 separate 32 bit HT
	 * transactions for a 64 bit read, and we want to avoid unnecessary
	 * HT transactions.
	 */

	/* This is the 64 bit group */

	/*
	 * shadow of pioavail, check to be sure it's large enough at
	 * init time.
	 */
	unsigned long ipath_pioavailshadow[8];
	/* shadow of kr_gpio_out, for rmw ops */
	u64 ipath_gpio_out;
	/* kr_revision shadow */
	u64 ipath_revision;
	/*
	 * shadow of ibcctrl, for interrupt handling of link changes,
	 * etc.
	 */
	u64 ipath_ibcctrl;
	/*
	 * last ibcstatus, to suppress "duplicate" status change messages,
	 * mostly from 2 to 3
	 */
	u64 ipath_lastibcstat;
	/* hwerrmask shadow */
	ipath_err_t ipath_hwerrmask;
	/* interrupt config reg shadow */
	u64 ipath_intconfig;
	/* kr_sendpiobufbase value */
	u64 ipath_piobufbase;

	/* these are the "32 bit" regs */

	/*
	 * number of GUIDs in the flash for this interface; may need some
	 * rethinking for setting on other ifaces
	 */
	u32 ipath_nguid;
	/*
	 * the following two are 32-bit bitmasks, but {test,clear,set}_bit
	 * all expect bit fields to be "unsigned long"
	 */
	/* shadow kr_rcvctrl */
	unsigned long ipath_rcvctrl;
	/* shadow kr_sendctrl */
	unsigned long ipath_sendctrl;

	/* value we put in kr_rcvhdrcnt */
	u32 ipath_rcvhdrcnt;
	/* value we put in kr_rcvhdrsize */
	u32 ipath_rcvhdrsize;
	/* value we put in kr_rcvhdrentsize */
	u32 ipath_rcvhdrentsize;
	/* offset of last entry in rcvhdrq */
	u32 ipath_hdrqlast;
	/* kr_portcnt value */
	u32 ipath_portcnt;
	/* kr_pagealign value */
	u32 ipath_palign;
	/* number of "2KB" PIO buffers */
	u32 ipath_piobcnt2k;
	/* size in bytes of "2KB" PIO buffers */
	u32 ipath_piosize2k;
	/* number of "4KB" PIO buffers */
	u32 ipath_piobcnt4k;
	/* size in bytes of "4KB" PIO buffers */
	u32 ipath_piosize4k;
	/* kr_rcvegrbase value */
	u32 ipath_rcvegrbase;
	/* kr_rcvegrcnt value */
	u32 ipath_rcvegrcnt;
	/* kr_rcvtidbase value */
	u32 ipath_rcvtidbase;
	/* kr_rcvtidcnt value */
	u32 ipath_rcvtidcnt;
	/* kr_sendregbase */
	u32 ipath_sregbase;
	/* kr_userregbase */
	u32 ipath_uregbase;
	/* kr_counterregbase */
	u32 ipath_cregbase;
	/* shadow the control register contents */
	u32 ipath_control;
	/* shadow the gpio output contents */
	u32 ipath_extctrl;
	/* PCI revision register (HTC rev on FPGA) */
	u32 ipath_pcirev;

	/* chip address space used by 4k pio buffers */
	u32 ipath_4kalign;
	/* The MTU programmed for this unit */
	u32 ipath_ibmtu;
	/*
	 * The max size IB packet, included IB headers that we can send.
	 * Starts same as ipath_piosize, but is affected when ibmtu is
	 * changed, or by size of eager buffers
	 */
	u32 ipath_ibmaxlen;
	/*
	 * ibmaxlen at init time, limited by chip and by receive buffer
	 * size.  Not changed after init.
	 */
	u32 ipath_init_ibmaxlen;
	/* size of each rcvegrbuffer */
	u32 ipath_rcvegrbufsize;
	/* width (2,4,8,16,32) from HT config reg */
	u32 ipath_htwidth;
	/* HT speed (200,400,800,1000) from HT config */
	u32 ipath_htspeed;
	/* ports waiting for PIOavail intr */
	unsigned long ipath_portpiowait;
	/*
	 * number of sequential ibcstatus change for polling active/quiet
	 * (i.e., link not coming up).
	 */
	u32 ipath_ibpollcnt;
	/* low and high portions of MSI capability/vector */
	u32 ipath_msi_lo;
	/* saved after PCIe init for restore after reset */
	u32 ipath_msi_hi;
	/* MSI data (vector) saved for restore */
	u16 ipath_msi_data;
	/* MLID programmed for this instance */
	u16 ipath_mlid;
	/* LID programmed for this instance */
	u16 ipath_lid;
	/* list of pkeys programmed; 0 if not set */
	u16 ipath_pkeys[4];
	/* ASCII serial number, from flash */
	u8 ipath_serial[12];
	/* human readable board version */
	u8 ipath_boardversion[80];
	/* chip major rev, from ipath_revision */
	u8 ipath_majrev;
	/* chip minor rev, from ipath_revision */
	u8 ipath_minrev;
	/* board rev, from ipath_revision */
	u8 ipath_boardrev;
	/* unit # of this chip, if present */
	int ipath_unit;
	/* saved for restore after reset */
	u8 ipath_pci_cacheline;
	/* LID mask control */
	u8 ipath_lmc;

	/* local link integrity counter */
	u32 ipath_lli_counter;
	/* local link integrity errors */
	u32 ipath_lli_errors;
};

extern struct list_head ipath_dev_list;
extern spinlock_t ipath_devs_lock;
extern struct ipath_devdata *ipath_lookup(int unit);

extern u16 ipath_layer_rcv_opcode;
extern int __ipath_layer_intr(struct ipath_devdata *, u32);
extern int ipath_layer_intr(struct ipath_devdata *, u32);
extern int __ipath_layer_rcv(struct ipath_devdata *, void *,
			     struct sk_buff *);
extern int __ipath_layer_rcv_lid(struct ipath_devdata *, void *);
extern int __ipath_verbs_piobufavail(struct ipath_devdata *);
extern int __ipath_verbs_rcv(struct ipath_devdata *, void *, void *, u32);

void ipath_layer_add(struct ipath_devdata *);
void ipath_layer_remove(struct ipath_devdata *);

int ipath_init_chip(struct ipath_devdata *, int);
int ipath_enable_wc(struct ipath_devdata *dd);
void ipath_disable_wc(struct ipath_devdata *dd);
int ipath_count_units(int *npresentp, int *nupp, u32 *maxportsp);
void ipath_shutdown_device(struct ipath_devdata *);

struct file_operations;
int ipath_cdev_init(int minor, char *name, struct file_operations *fops,
		    struct cdev **cdevp, struct class_device **class_devp);
void ipath_cdev_cleanup(struct cdev **cdevp,
			struct class_device **class_devp);

int ipath_diag_add(struct ipath_devdata *);
void ipath_diag_remove(struct ipath_devdata *);
void ipath_diag_bringup_link(struct ipath_devdata *);

extern wait_queue_head_t ipath_sma_state_wait;

int ipath_user_add(struct ipath_devdata *dd);
void ipath_user_remove(struct ipath_devdata *dd);

struct sk_buff *ipath_alloc_skb(struct ipath_devdata *dd, gfp_t);

extern int ipath_diag_inuse;

irqreturn_t ipath_intr(int irq, void *devid, struct pt_regs *regs);
void ipath_decode_err(char *buf, size_t blen, ipath_err_t err);
#if __IPATH_INFO || __IPATH_DBG
extern const char *ipath_ibcstatus_str[];
#endif

/* clean up any per-chip chip-specific stuff */
void ipath_chip_cleanup(struct ipath_devdata *);
/* clean up any chip type-specific stuff */
void ipath_chip_done(void);

/* check to see if we have to force ordering for write combining */
int ipath_unordered_wc(void);

void ipath_disarm_piobufs(struct ipath_devdata *, unsigned first,
			  unsigned cnt);

int ipath_create_rcvhdrq(struct ipath_devdata *, struct ipath_portdata *);
void ipath_free_pddata(struct ipath_devdata *, struct ipath_portdata *);

int ipath_parse_ushort(const char *str, unsigned short *valp);

int ipath_wait_linkstate(struct ipath_devdata *, u32, int);
void ipath_set_ib_lstate(struct ipath_devdata *, int);
void ipath_kreceive(struct ipath_devdata *);
int ipath_setrcvhdrsize(struct ipath_devdata *, unsigned);
int ipath_reset_device(int);
void ipath_get_faststats(unsigned long);

/* for use in system calls, where we want to know device type, etc. */
#define port_fp(fp) ((struct ipath_portdata *) (fp)->private_data)

/*
 * values for ipath_flags
 */
/* The chip is up and initted */
#define IPATH_INITTED       0x2
		/* set if any user code has set kr_rcvhdrsize */
#define IPATH_RCVHDRSZ_SET  0x4
		/* The chip is present and valid for accesses */
#define IPATH_PRESENT       0x8
		/* HT link0 is only 8 bits wide, ignore upper byte crc
		 * errors, etc. */
#define IPATH_8BIT_IN_HT0   0x10
		/* HT link1 is only 8 bits wide, ignore upper byte crc
		 * errors, etc. */
#define IPATH_8BIT_IN_HT1   0x20
		/* The link is down */
#define IPATH_LINKDOWN      0x40
		/* The link level is up (0x11) */
#define IPATH_LINKINIT      0x80
		/* The link is in the armed (0x21) state */
#define IPATH_LINKARMED     0x100
		/* The link is in the active (0x31) state */
#define IPATH_LINKACTIVE    0x200
		/* link current state is unknown */
#define IPATH_LINKUNK       0x400
		/* no IB cable, or no device on IB cable */
#define IPATH_NOCABLE       0x4000
		/* Supports port zero per packet receive interrupts via
		 * GPIO */
#define IPATH_GPIO_INTR     0x8000
		/* uses the coded 4byte TID, not 8 byte */
#define IPATH_4BYTE_TID     0x10000
		/* packet/word counters are 32 bit, else those 4 counters
		 * are 64bit */
#define IPATH_32BITCOUNTERS 0x20000
		/* can miss port0 rx interrupts */
#define IPATH_POLL_RX_INTR  0x40000
#define IPATH_DISABLED      0x80000 /* administratively disabled */

/* portdata flag bit offsets */
		/* waiting for a packet to arrive */
#define IPATH_PORT_WAITING_RCV   2
		/* waiting for a PIO buffer to be available */
#define IPATH_PORT_WAITING_PIO   3

/* free up any allocated data at closes */
void ipath_free_data(struct ipath_portdata *dd);
int ipath_waitfor_mdio_cmdready(struct ipath_devdata *);
int ipath_waitfor_complete(struct ipath_devdata *, ipath_kreg, u64, u64 *);
u32 __iomem *ipath_getpiobuf(struct ipath_devdata *, u32 *);
/* init PE-800-specific func */
void ipath_init_pe800_funcs(struct ipath_devdata *);
/* init HT-400-specific func */
void ipath_init_ht400_funcs(struct ipath_devdata *);
void ipath_get_eeprom_info(struct ipath_devdata *);
u64 ipath_snap_cntr(struct ipath_devdata *, ipath_creg);

/*
 * number of words used for protocol header if not set by ipath_userinit();
 */
#define IPATH_DFLT_RCVHDRSIZE 9

#define IPATH_MDIO_CMD_WRITE   1
#define IPATH_MDIO_CMD_READ    2
#define IPATH_MDIO_CLD_DIV     25	/* to get 2.5 Mhz mdio clock */
#define IPATH_MDIO_CMDVALID    0x40000000	/* bit 30 */
#define IPATH_MDIO_DATAVALID   0x80000000	/* bit 31 */
#define IPATH_MDIO_CTRL_STD    0x0

static inline u64 ipath_mdio_req(int cmd, int dev, int reg, int data)
{
	return (((u64) IPATH_MDIO_CLD_DIV) << 32) |
		(cmd << 26) |
		(dev << 21) |
		(reg << 16) |
		(data & 0xFFFF);
}

		/* signal and fifo status, in bank 31 */
#define IPATH_MDIO_CTRL_XGXS_REG_8  0x8
		/* controls loopback, redundancy */
#define IPATH_MDIO_CTRL_8355_REG_1  0x10
		/* premph, encdec, etc. */
#define IPATH_MDIO_CTRL_8355_REG_2  0x11
		/* Kchars, etc. */
#define IPATH_MDIO_CTRL_8355_REG_6  0x15
#define IPATH_MDIO_CTRL_8355_REG_9  0x18
#define IPATH_MDIO_CTRL_8355_REG_10 0x1D

int ipath_get_user_pages(unsigned long, size_t, struct page **);
int ipath_get_user_pages_nocopy(unsigned long, struct page **);
void ipath_release_user_pages(struct page **, size_t);
void ipath_release_user_pages_on_close(struct page **, size_t);
int ipath_eeprom_read(struct ipath_devdata *, u8, void *, int);
int ipath_eeprom_write(struct ipath_devdata *, u8, const void *, int);

/* these are used for the registers that vary with port */
void ipath_write_kreg_port(const struct ipath_devdata *, ipath_kreg,
			   unsigned, u64);
u64 ipath_read_kreg64_port(const struct ipath_devdata *, ipath_kreg,
			   unsigned);

/*
 * We could have a single register get/put routine, that takes a group type,
 * but this is somewhat clearer and cleaner.  It also gives us some error
 * checking.  64 bit register reads should always work, but are inefficient
 * on opteron (the northbridge always generates 2 separate HT 32 bit reads),
 * so we use kreg32 wherever possible.  User register and counter register
 * reads are always 32 bit reads, so only one form of those routines.
 */

/*
 * At the moment, none of the s-registers are writable, so no
 * ipath_write_sreg(), and none of the c-registers are writable, so no
 * ipath_write_creg().
 */

/**
 * ipath_read_ureg32 - read 32-bit virtualized per-port register
 * @dd: device
 * @regno: register number
 * @port: port number
 *
 * Return the contents of a register that is virtualized to be per port.
 * Returns -1 on errors (not distinguishable from valid contents at
 * runtime; we may add a separate error variable at some point).
 */
static inline u32 ipath_read_ureg32(const struct ipath_devdata *dd,
				    ipath_ureg regno, int port)
{
	if (!dd->ipath_kregbase || !(dd->ipath_flags&IPATH_PRESENT))
		return 0;

	return readl(regno + (u64 __iomem *)
		     (dd->ipath_uregbase +
		      (char __iomem *)dd->ipath_kregbase +
		      dd->ipath_palign * port));
}

/**
 * ipath_write_ureg - write 32-bit virtualized per-port register
 * @dd: device
 * @regno: register number
 * @value: value
 * @port: port
 *
 * Write the contents of a register that is virtualized to be per port.
 */
static inline void ipath_write_ureg(const struct ipath_devdata *dd,
				    ipath_ureg regno, u64 value, int port)
{
	u64 __iomem *ubase = (u64 __iomem *)
		(dd->ipath_uregbase + (char __iomem *) dd->ipath_kregbase +
		 dd->ipath_palign * port);
	if (dd->ipath_kregbase)
		writeq(value, &ubase[regno]);
}

static inline u32 ipath_read_kreg32(const struct ipath_devdata *dd,
				    ipath_kreg regno)
{
	if (!dd->ipath_kregbase || !(dd->ipath_flags&IPATH_PRESENT))
		return -1;
	return readl((u32 __iomem *) & dd->ipath_kregbase[regno]);
}

static inline u64 ipath_read_kreg64(const struct ipath_devdata *dd,
				    ipath_kreg regno)
{
	if (!dd->ipath_kregbase || !(dd->ipath_flags&IPATH_PRESENT))
		return -1;

	return readq(&dd->ipath_kregbase[regno]);
}

static inline void ipath_write_kreg(const struct ipath_devdata *dd,
				    ipath_kreg regno, u64 value)
{
	if (dd->ipath_kregbase)
		writeq(value, &dd->ipath_kregbase[regno]);
}

static inline u64 ipath_read_creg(const struct ipath_devdata *dd,
				  ipath_sreg regno)
{
	if (!dd->ipath_kregbase || !(dd->ipath_flags&IPATH_PRESENT))
		return 0;

	return readq(regno + (u64 __iomem *)
		     (dd->ipath_cregbase +
		      (char __iomem *)dd->ipath_kregbase));
}

static inline u32 ipath_read_creg32(const struct ipath_devdata *dd,
					 ipath_sreg regno)
{
	if (!dd->ipath_kregbase || !(dd->ipath_flags&IPATH_PRESENT))
		return 0;
	return readl(regno + (u64 __iomem *)
		     (dd->ipath_cregbase +
		      (char __iomem *)dd->ipath_kregbase));
}

/*
 * sysfs interface.
 */

struct device_driver;

extern const char ipath_core_version[];

int ipath_driver_create_group(struct device_driver *);
void ipath_driver_remove_group(struct device_driver *);

int ipath_device_create_group(struct device *, struct ipath_devdata *);
void ipath_device_remove_group(struct device *, struct ipath_devdata *);
int ipath_expose_reset(struct device *);

int ipath_init_ipathfs(void);
void ipath_exit_ipathfs(void);
int ipathfs_add_device(struct ipath_devdata *);
int ipathfs_remove_device(struct ipath_devdata *);

/*
 * Flush write combining store buffers (if present) and perform a write
 * barrier.
 */
#if defined(CONFIG_X86_64)
#define ipath_flush_wc() asm volatile("sfence" ::: "memory")
#else
#define ipath_flush_wc() wmb()
#endif

extern unsigned ipath_debug; /* debugging bit mask */

const char *ipath_get_unit_name(int unit);

extern struct mutex ipath_mutex;

#define IPATH_DRV_NAME		"ipath_core"
#define IPATH_MAJOR		233
#define IPATH_USER_MINOR_BASE	0
#define IPATH_SMA_MINOR		128
#define IPATH_DIAG_MINOR_BASE	129
#define IPATH_NMINORS		255

#define ipath_dev_err(dd,fmt,...) \
	do { \
		const struct ipath_devdata *__dd = (dd); \
		if (__dd->pcidev) \
			dev_err(&__dd->pcidev->dev, "%s: " fmt, \
				ipath_get_unit_name(__dd->ipath_unit), \
				##__VA_ARGS__); \
		else \
			printk(KERN_ERR IPATH_DRV_NAME ": %s: " fmt, \
			       ipath_get_unit_name(__dd->ipath_unit), \
			       ##__VA_ARGS__); \
	} while (0)

#if _IPATH_DEBUGGING

# define __IPATH_DBG_WHICH(which,fmt,...) \
	do { \
		if(unlikely(ipath_debug&(which))) \
			printk(KERN_DEBUG IPATH_DRV_NAME ": %s: " fmt, \
			       __func__,##__VA_ARGS__); \
	} while(0)

# define ipath_dbg(fmt,...) \
	__IPATH_DBG_WHICH(__IPATH_DBG,fmt,##__VA_ARGS__)
# define ipath_cdbg(which,fmt,...) \
	__IPATH_DBG_WHICH(__IPATH_##which##DBG,fmt,##__VA_ARGS__)

#else /* ! _IPATH_DEBUGGING */

# define ipath_dbg(fmt,...)
# define ipath_cdbg(which,fmt,...)

#endif /* _IPATH_DEBUGGING */

#endif				/* _IPATH_KERNEL_H */

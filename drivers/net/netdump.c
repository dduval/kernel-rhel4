/*
 *  linux/drivers/net/netdump.c
 *
 *  Copyright (C) 2001  Ingo Molnar <mingo@redhat.com>
 *  Copyright (C) 2002  Red Hat, Inc.
 *  Copyright (C) 2004  Red Hat, Inc.
 *
 *  This file contains the implementation of an IRQ-safe, crash-safe
 *  kernel console implementation that outputs kernel messages to the
 *  network.
 *
 * Modification history:
 *
 * 2001-09-17    started by Ingo Molnar.
 * 2002-03-14    simultaneous syslog packet option by Michael K. Johnson
 * 2004-04-07    port to 2.6 netpoll facility by Dave Anderson and Jeff Moyer.
 */
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/reboot.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <asm/unaligned.h>
#include <asm/pgtable.h>
#include <linux/console.h>
#include <linux/smp_lock.h>
#include <linux/elf.h>
#include <linux/preempt.h>

#include "netdump.h"
#include <linux/netpoll.h>

/*
 *  prototypes.
 */
void netdump_rx(struct netpoll *np, short source, char *data, int dlen);
static void send_netdump_msg(struct netpoll *np, const char *msg, unsigned int msg_len, reply_t *reply);
static void send_netdump_mem(struct netpoll *np, req_t *req);
static void netdump_startup_handshake(struct netpoll *np);
static asmlinkage void netpoll_netdump(struct pt_regs *regs, void *arg);
static void netpoll_start_netdump(struct pt_regs *regs);


#include <asm/netdump.h>


#undef Dprintk
#define DEBUG 0
#if DEBUG
# define Dprintk(x...) printk(KERN_INFO x)
#else
# define Dprintk(x...)
#endif

MODULE_AUTHOR("Maintainer: Dave Anderson <anderson@redhat.com>");
MODULE_DESCRIPTION("Network kernel crash dump module");
MODULE_LICENSE("GPL");

static char config[256];
module_param_string(netdump, config, 256, 0);
MODULE_PARM_DESC(netdump, 
     " netdump=[src-port]@[src-ip]/[dev],[tgt-port]@<tgt-ip>/[tgt-macaddr]\n");

static u32 magic1, magic2;
module_param(magic1, uint, 000);
module_param(magic2, uint, 000);

static struct netpoll np = {
	.name = "netdump",
	.dev_name = "eth0",
	.local_port = 6666,
	.remote_port = 6666,
	.remote_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	.rx_hook = netdump_rx,
	.dump_func = netpoll_start_netdump,
};


/*
 * NOTE: security depends on the trusted path between the netconsole
 *       server and netconsole client, since none of the packets are
 *       encrypted. The random magic number protects the protocol
 *       against spoofing.
 */
static u64 netdump_magic;

static spinlock_t req_lock = SPIN_LOCK_UNLOCKED;
static int nr_req = 0;
static LIST_HEAD(request_list);

static unsigned long long t0, jiffy_cycles = 1000 * (1000000/HZ);
void *netdump_stack;


static void update_jiffies(void)
{
	static unsigned long long prev_tick;
	platform_timestamp(t0);

	/* maintain jiffies in a polling fashion, based on rdtsc. */
	if (t0 - prev_tick >= jiffy_cycles) {
		prev_tick += jiffy_cycles;
		jiffies++;
	}
}

static void add_new_req(req_t *req)
{
	unsigned long flags;

	spin_lock_irqsave(&req_lock, flags);
	list_add_tail(&req->list, &request_list);
	nr_req++;
	Dprintk("pending requests: %d.\n", nr_req);
	spin_unlock_irqrestore(&req_lock, flags);
}

static req_t *get_new_req(void)
{
	req_t *req = NULL;
	unsigned long flags;

	update_jiffies();

	spin_lock_irqsave(&req_lock, flags);
	if (nr_req) {
		req = list_entry(request_list.next, req_t, list);
		list_del(&req->list);
		nr_req--;
	}
	spin_unlock_irqrestore(&req_lock, flags);

	return req;
}

static req_t *alloc_req(void)
{
	req_t *req;

	req = (req_t *) kmalloc(sizeof(*req), GFP_ATOMIC);
	return req;
}

static inline void print_status (req_t *req)
{
	static int count = 0;
	static unsigned long prev_jiffies = 0;

	if (jiffies/HZ != prev_jiffies/HZ) {
		prev_jiffies = jiffies;
		count++;
		switch (count & 3) {
			case 0: printk("%d(%lu)/\r", nr_req, jiffies); break;
			case 1: printk("%d(%lu)|\r", nr_req, jiffies); break;
			case 2: printk("%d(%lu)\\\r", nr_req, jiffies); break;
			case 3: printk("%d(%lu)-\r", nr_req, jiffies); break;
		}
	}
}

void netdump_rx(struct netpoll *np, short source, char *data, int dlen)
{
	req_t *req, *__req = (req_t *)data;

	if (!netdump_mode)
		return;
#if DEBUG
	{
		static int packet_count;
		Dprintk("        %d\r", ++packet_count);
	}
#endif

	if (dlen < NETDUMP_REQ_SIZE) {
		Dprintk("... netdump_rx: len not ok.\n");
		return;
	}

	req = alloc_req();
	if (!req) {
		printk("no more RAM to allocate request - dropping it.\n");
		return;
	}

	req->command = ntohl(__req->command);
	req->from = ntohl(__req->from);
	req->to = ntohl(__req->to);
	req->nr = ntohl(__req->nr);

	Dprintk("... netdump command: %08x.\n", req->command);
	Dprintk("... netdump from:    %08x.\n", req->from);
	Dprintk("... netdump to:      %08x.\n", req->to);

	add_new_req(req);
	return;
}

#define MAX_MSG_LEN HEADER_LEN + 1024

static unsigned char effective_version = NETDUMP_VERSION;

static void send_netdump_msg(struct netpoll *np, const char *msg, unsigned int msg_len, reply_t *reply)
{
	/* max len should be 1024 + HEADER_LEN */
	static unsigned char netpoll_msg[MAX_MSG_LEN + 1];

	if (msg_len + HEADER_LEN > MAX_MSG_LEN + 1) {
		printk("CODER ERROR!!! msg_len %ud too big for send msg\n",
		       msg_len);
		for (;;) local_irq_disable();
		/* NOTREACHED */
	}

	netpoll_msg[0] = effective_version;
	put_unaligned(htonl(reply->nr), (u32 *) (&netpoll_msg[1]));
	put_unaligned(htonl(reply->code), (u32 *) (&netpoll_msg[5]));
	put_unaligned(htonl(reply->info), (u32 *) (&netpoll_msg[9]));
	memcpy(&netpoll_msg[HEADER_LEN], msg, msg_len);

	netpoll_send_udp(np, netpoll_msg, HEADER_LEN + msg_len);
}

static void send_netdump_mem(struct netpoll *np, req_t *req)
{
	int i;
	char *kaddr;
	char str[1024];
	struct page *page = NULL;
	unsigned long nr = req->from;
	int nr_chunks = PAGE_SIZE/1024;
	reply_t reply;
	
	Dprintk(" ... send_netdump_mem\n");
	reply.nr = req->nr;
	reply.info = 0;
	if (req->from >= platform_max_pfn()) {
		sprintf(str, "page %08lx is bigger than max page # %08lx!\n", 
			nr, platform_max_pfn());
		reply.code = REPLY_ERROR;
		send_netdump_msg(np, str, strlen(str), &reply);
		return;
	}
	if (platform_page_is_ram(nr)) {
		page = pfn_to_page(nr);
		if (page_to_pfn(page) != nr)
			page = NULL;
	}
	if (!page) {
		reply.code = REPLY_RESERVED;
		reply.info = platform_next_available(nr);
		send_netdump_msg(np, str, 0, &reply);
		return;
	}

	kaddr = (char *)kmap_atomic(page, KM_CRASHDUMP);

	for (i = 0; i < nr_chunks; i++) {
		unsigned int offset = i*1024;
		reply.code = REPLY_MEM;
		reply.info = offset;
		Dprintk(" ... send_netdump_mem: sending message\n");
		send_netdump_msg(np, kaddr + offset, 1024, &reply);
		Dprintk(" ... send_netdump_mem: sent message\n");
	}

	kunmap_atomic(kaddr, KM_CRASHDUMP);
	Dprintk(" ... send_netdump_mem: returning\n");
}

/*
 * This function waits for the client to acknowledge the receipt
 * of the netdump startup reply, with the possibility of packets
 * getting lost. We resend the startup packet if no ACK is received,
 * after a 1 second delay.
 *
 * (The client can test the success of the handshake via the HELLO
 * command, and send ACKs until we enter netdump mode.)
 */
static void netdump_startup_handshake(struct netpoll *np)
{
	char tmp[200];
	reply_t reply;
	req_t *req = NULL;
	int i;

repeat:
	sprintf(tmp,
   	    "task_struct:0x%lx page_offset:0x%llx netdump_magic:0x%llx\n",
		(unsigned long)current, (unsigned long long)PAGE_OFFSET, 
		(unsigned long long)netdump_magic);
	reply.code = REPLY_START_NETDUMP;
	reply.nr = platform_machine_type();
	reply.info = NETDUMP_VERSION_MAX;

	send_netdump_msg(np, tmp, strlen(tmp), &reply);

	for (i = 0; i < 10000; i++) {
		// wait 1 sec.
		udelay(100);
		Dprintk("handshake: polling controller ...\n");
		netpoll_poll(np);
		req = get_new_req();
		if (req)
			break;
	}
	if (!req)
		goto repeat;
	if (req->command != COMM_START_NETDUMP_ACK) {
		kfree(req);
		goto repeat;
	}

	/*
	 *  Negotiate an effective version that works with the server. 
	 */
	if ((effective_version = platform_effective_version(req)) == 0) {
		printk(KERN_ERR
			"netdump: server cannot handle this client -- rebooting.\n");
		netdump_mdelay(3000);
		machine_restart(NULL);
	}

	kfree(req);

	printk("NETDUMP START!\n");
}

static char cpus_frozen[NR_CPUS] = { 0 }; 

static void freeze_cpu (void * dummy)
{
	cpus_frozen[smp_processor_id()] = 1;
	platform_freeze_cpu();
}

static void netpoll_start_netdump(struct pt_regs *regs)
{
	int i;
	unsigned long flags;

	/*
	 *  The netdump code is not re-entrant for several reasons.  Most
	 *  immediately, we will switch to the base of our stack and 
	 *  overwrite all of our call history.
	 */
	if (netdump_mode) {
		printk(KERN_ERR
		"netpoll_start_netdump: called recursively.  rebooting.\n");
		netdump_mdelay(3000);
		machine_restart(NULL);
	}
	netdump_mode = 1;

	local_irq_save(flags);
	preempt_disable();

	dump_smp_call_function(freeze_cpu, NULL);
	netdump_mdelay(3000);
	for (i = 0; i < NR_CPUS; i++) {
		if (cpus_frozen[i])
			printk("CPU#%d is frozen.\n", i);
		else if (i == smp_processor_id())
			printk("CPU#%d is executing netdump.\n", i);
	}

	/*
	 *  Some platforms may want to execute netdump on its own stack.
	 */
	platform_start_crashdump(netdump_stack, netpoll_netdump, regs);

	preempt_enable_no_resched();
	local_irq_restore(flags);
	return;
}

static char command_tmp[1024];

static asmlinkage void netpoll_netdump(struct pt_regs *regs, void *platform_arg)
{
	reply_t reply;
	char *tmp = command_tmp;
	extern unsigned long totalram_pages;
	struct pt_regs myregs;
	req_t *req;

	/*
	 * Just in case we are crashing within the networking code
	 * ... attempt to fix up.
	 */
	netpoll_reset_locks(&np);
	platform_fix_regs();
	platform_timestamp(t0);
	netpoll_set_trap(1); /* bypass networking stack */

	printk("< netdump activated - performing handshake with the server. >\n");
	netdump_startup_handshake(&np);

	printk("< handshake completed - listening for dump requests. >\n");

	while (netdump_mode) {
		local_irq_disable();
		Dprintk("main netdump loop: polling controller ...\n");
		netpoll_poll(&np);

		req = get_new_req();
		if (!req)
			continue;

		Dprintk("got new req, command %d.\n", req->command);
		print_status(req);
		switch (req->command) {
		case COMM_NONE:
			Dprintk("got NO command.\n");
			break;

		case COMM_SEND_MEM:
			Dprintk("got MEM command.\n");
			send_netdump_mem(&np, req);
			break;

		case COMM_EXIT:
			Dprintk("got EXIT command.\n");
			netdump_mode = 0;
			netpoll_set_trap(0);
			break;

		case COMM_REBOOT:
			Dprintk("got REBOOT command.\n");
			printk("netdump: rebooting in 3 seconds.\n");
			netdump_mdelay(3000);
			machine_restart(NULL);
			break;

		case COMM_HELLO:
			sprintf(tmp, "Hello, this is netdump version 0.%02d\n",
				NETDUMP_VERSION);
			reply.code = REPLY_HELLO;
			reply.nr = req->nr;
			reply.info = NETDUMP_VERSION;
			send_netdump_msg(&np, tmp, strlen(tmp), &reply);
			break;

		case COMM_GET_PAGE_SIZE:
			sprintf(tmp, "PAGE_SIZE: %ld\n", PAGE_SIZE);
			reply.code = REPLY_PAGE_SIZE;
			reply.nr = req->nr;
			reply.info = PAGE_SIZE;
			send_netdump_msg(&np, tmp, strlen(tmp), &reply);
			break;

		case COMM_GET_REGS:
			reply.code = REPLY_REGS;
			reply.nr = req->nr;
			reply.info = (u32)totalram_pages;
        		send_netdump_msg(&np, tmp,
				platform_get_regs(tmp, &myregs), &reply);
			break;

		case COMM_GET_NR_PAGES:
			reply.code = REPLY_NR_PAGES;
			reply.nr = req->nr;
			reply.info = platform_max_pfn();
			sprintf(tmp, 
				"Number of pages: %ld\n", platform_max_pfn());
			send_netdump_msg(&np, tmp, strlen(tmp), &reply);
			break;

		case COMM_SHOW_STATE:
			/* send response first */
			reply.code = REPLY_SHOW_STATE;
			reply.nr = req->nr;
			reply.info = 0;

			send_netdump_msg(&np, tmp, strlen(tmp), &reply);

			netdump_mode = 0;
			if (regs)
				show_regs(regs);
			show_state();
			show_mem();
			netdump_mode = 1;
			break;

		default:
			reply.code = REPLY_ERROR;
			reply.nr = req->nr;
			reply.info = req->command;
			Dprintk("got UNKNOWN command!\n");
			sprintf(tmp, "Got unknown command code %d!\n", 
				req->command);
			send_netdump_msg(&np, tmp, strlen(tmp), &reply);
			break;
		}
		kfree(req);
		req = NULL;
	}
	sprintf(tmp, "NETDUMP end.\n");
	reply.code = REPLY_END_NETDUMP;
	reply.nr = 0;
	reply.info = 0;
	send_netdump_msg(&np, tmp, strlen(tmp), &reply);
	printk("NETDUMP END!\n");
}

static int option_setup(char *opt)
{
	return !netpoll_parse_options(&np, opt);
}

__setup("netdump=", option_setup);

static int init_netdump(void)
{
	int configured = 0;

	if (strlen(config))
		configured = option_setup(config);

	if (!configured) {
		printk(KERN_ERR "netdump: not configured, aborting\n");
		return -EINVAL;
	}

	if (netpoll_setup(&np))
		return -EINVAL;

	if (magic1 || magic2)
		netdump_magic = magic1 + (((u64)magic2)<<32);

	/*
	 *  Allocate a separate stack for netdump.
	 */
	platform_init_stack(&netdump_stack);

	platform_jiffy_cycles(&jiffy_cycles);

	printk(KERN_INFO "netdump: network crash dump enabled\n");
	return 0;
}

static void cleanup_netdump(void)
{
	netpoll_cleanup(&np);
	platform_cleanup_stack(netdump_stack);
}

module_init(init_netdump);
module_exit(cleanup_netdump);

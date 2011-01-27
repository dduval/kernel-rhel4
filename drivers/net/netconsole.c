/*
 *  linux/drivers/net/netconsole.c
 *
 *  Copyright (C) 2001  Ingo Molnar <mingo@redhat.com>
 *
 *  This file contains the implementation of an IRQ-safe, crash-safe
 *  kernel console implementation that outputs kernel messages to the
 *  network.
 *
 * Modification history:
 *
 * 2001-09-17    started by Ingo Molnar.
 * 2003-08-11    2.6 port by Matt Mackall
 *               simplified options
 *               generic card hooks
 *               works non-modular
 * 2003-09-07    rewritten with netpoll api
 */

/****************************************************************
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2, or (at your option)
 *      any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************/

#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/tty_driver.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/sysrq.h>
#include <linux/smp.h>
#include <linux/netpoll.h>
#include <asm/unaligned.h>

#include "netdump.h"

MODULE_AUTHOR("Maintainer: Matt Mackall <mpm@selenic.com>");
MODULE_DESCRIPTION("Console driver for network interfaces");
MODULE_LICENSE("GPL");

static char config[256];
module_param_string(netconsole, config, 256, 0);
MODULE_PARM_DESC(netconsole, " netconsole=[src-port]@[src-ip]/[dev],[tgt-port]@<tgt-ip>/[tgt-macaddr]\n");

static struct netpoll np = {
	.name = "netconsole",
	.dev_name = "eth0",
	.local_port = 6665,
	.remote_port = 514,
	.remote_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
};
static int configured = 0;

static char netlog_config[256];
module_param_string(netlog, netlog_config, 256, 0);
MODULE_PARM_DESC(netlog, " netlog=[src-port]@[src-ip]/[dev],[tgt-port]@<tgt-ip>/[tgt-macaddr]\n");
static struct netpoll netlog_np = {
	.name = "netlog",
	.dev_name = "eth0",
	.local_port = 6664,
	.remote_port = 6666,
	.remote_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
};
static int netlog_configured = 0;

#define MAX_PRINT_CHUNK 1000
#define SYSLOG_HEADER_LEN 4

static int syslog_chars = SYSLOG_HEADER_LEN;
static unsigned char syslog_line [MAX_PRINT_CHUNK + 10] = {
	'<',
	'5',
	'>',
	' ',
	[4 ... MAX_PRINT_CHUNK+5] = '\0',
};
static unsigned char netlog_line[MAX_PRINT_CHUNK + HEADER_LEN];
static unsigned int log_offset;

/*
 * We feed kernel messages char by char, and send the UDP packet
 * one linefeed. We buffer all characters received.
 */
static inline void feed_syslog_char(const unsigned char c)
{
	if (syslog_chars == MAX_PRINT_CHUNK)
		syslog_chars--;
	syslog_line[syslog_chars] = c;
	syslog_chars++;
	if (c == '\n') {
		netpoll_send_udp(&np, syslog_line, syslog_chars);
		syslog_chars = SYSLOG_HEADER_LEN;
	}
}

static void write_msg(struct console *con, const char *msg, unsigned int len)
{
	int left, i;
	unsigned long flags;
	reply_t reply;
	char *netlog_buf = &netlog_line[HEADER_LEN];

	if (!np.dev && !netlog_np.dev)
		return;

	if (unlikely(crashdump_mode()))
		return;

	local_irq_save(flags);

	if (np.dev)
		for (i = 0; i < len; i++)
			feed_syslog_char(msg[i]);

	if (netlog_np.dev) {
		left = len;
		while (left) {
			if (left > MAX_PRINT_CHUNK)
				len = MAX_PRINT_CHUNK;
			else
				len = left;
			netlog_line[0] = NETDUMP_VERSION;

			reply.nr = 0;
			reply.code = REPLY_LOG;
			reply.info = log_offset;

			put_unaligned(htonl(reply.nr), 
				      (u32 *)(netlog_line + 1));
			put_unaligned(htonl(reply.code),
				      (u32 *)(netlog_line + 5));
			put_unaligned(htonl(reply.info),
				      (u32 *)(netlog_line + 9));

			log_offset += len;
			memcpy(netlog_buf, msg, len);

			netpoll_send_udp(&netlog_np, 
					 netlog_line, len + HEADER_LEN);
			msg += len;
			left -= len;
		}
	}

	local_irq_restore(flags);
}

static struct console netconsole = {
	.flags = CON_ENABLED | CON_PRINTBUFFER,
	.write = write_msg
};

static int option_setup(char *opt)
{
	configured = !netpoll_parse_options(&np, opt);
	return 0;
}

__setup("netconsole=", option_setup);

static int netlog_option_setup(char *opt)
{
	netlog_configured = !netpoll_parse_options(&netlog_np, opt);
	return 0;
}

__setup("netlog=", netlog_option_setup);

static int init_netconsole(void)
{
	if(strlen(config))
		option_setup(config);

	if (strlen(netlog_config))
		netlog_option_setup(netlog_config);

	if (configured && netpoll_setup(&np)) {
		configured = 0;
		printk("netconsole: failed to configure syslog service\n");
	}

	if (netlog_configured && netpoll_setup(&netlog_np)) {
		netlog_configured = 0;
		printk("netconsole: failed to configured netlog service.\n");
	}

	if (!configured && !netlog_configured)
		return -EINVAL;

	register_console(&netconsole);
	printk(KERN_EMERG "[...network console startup...]\n");
	return 0;
}

static void cleanup_netconsole(void)
{
	unregister_console(&netconsole);

	if (configured)
		netpoll_cleanup(&np);

	if (netlog_configured)
		netpoll_cleanup(&netlog_np);
}

module_init(init_netconsole);
module_exit(cleanup_netconsole);

/******************************************************************************
 * fixup.c
 * 
 * Binary-rewriting of certain IA32 instructions, on notification by Xen.
 * Used to avoid repeated slow emulation of common instructions used by the
 * user-space TLS (Thread-Local Storage) libraries.
 * 
 * **** NOTE ****
 *  Issues with the binary rewriting have caused it to be removed. Instead
 *  we rely on Xen's emulator to boot the kernel, and then print a banner
 *  message recommending that the user disables /lib/tls.
 * 
 * Copyright (c) 2004, K A Fraser
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/config.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/version.h>

#define DP(_f, _args...) printk(KERN_ALERT "  " _f "\n" , ## _args )

fastcall void do_fixup_4gb_segment(struct pt_regs *regs, long error_code)
{
	static unsigned long printed = 0;
	char info[100];

	if (test_and_set_bit(0, &printed))
		return;

	HYPERVISOR_vm_assist(
		VMASST_CMD_disable, VMASST_TYPE_4gb_segments_notify);

	sprintf(info, "%s (pid=%d)", current->comm, current->tgid);

	DP("warning: 4GB segment emulation, offending process: %-38.38s", 
	   info);
}

static int __init fixup_init(void)
{
	HYPERVISOR_vm_assist(
		VMASST_CMD_enable, VMASST_TYPE_4gb_segments_notify);
	return 0;
}
__initcall(fixup_init);

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */

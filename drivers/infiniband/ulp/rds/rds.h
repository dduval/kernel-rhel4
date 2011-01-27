/*
 * Copyright (c) 2005 SilverStorm Technologies, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials
 * provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */


#ifndef _RDS_H_
#define _RDS_H_

/*
* Linux kernel includes
*/

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/net.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/ctype.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pci.h>
#include <linux/random.h>
#include <linux/dma-mapping.h>
#include <linux/workqueue.h>

#include <net/sock.h>
#include <net/route.h>
#include <net/dst.h>
#include <net/ip.h>

#include <asm/atomic.h>
#include <asm/byteorder.h>
#include <asm/pgtable.h>
#include <asm/io.h>

/*
* IB includes
*/
//#include <rdma/ib_verbs.h>
//#include <rdma/ib_cache.h>
#include <rdma/rdma_cm.h>

/*
* rds local includes
*/

#include "rds_protocol.h"
#include "rds_buf.h"
#include "rds_ep.h"
#include "rds_main.h"
#include "rds_inet.h"
#include "rds_cma.h"


#endif

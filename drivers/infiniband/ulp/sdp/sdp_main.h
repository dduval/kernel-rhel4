/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
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
 *
 * $Id: sdp_main.h 3202 2005-08-26 17:11:34Z roland $
 */

#ifndef _SDP_MAIN_H
#define _SDP_MAIN_H
/*
 * error compatability to MS .NET SDP
 */
#if 0
#define _SDP_MS_APRIL_ERROR_COMPAT
#endif
/*
 * Perform entire protocol except for the user/kernel data copy.
 */
#if 0
#define _SDP_DATA_PATH_NULL
#endif
/*
 * Mellanox A0 bug work around. SE amd UNSIG bits set, the event
 * gets a signal.
 */
#if 1
#define _SDP_SE_UNSIG_BUG_WORKAROUND
#endif
/*
 * keep per connection statistics
 */
#if 0
#define _SDP_CONN_STATS_REC
#endif
/*
 * keep state transition statistics.
 */
#if 0
#define _SDP_CONN_STATE_REC
#endif
/*
 * kernel includes
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
#include <linux/pci.h>
#include <linux/random.h>
#include <linux/dma-mapping.h>

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
#include <rdma/ib_verbs.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_cm.h>
#include "sdp_sock.h"
/*
 * sdp local includes
 */
#include "sdp_buff.h"
#include "sdp_proc.h"
#include "sdp_proto.h"
#include "sdp_conn.h"
#include "sdp_dev.h"
#include "sdp_msgs.h"
#include "sdp_advt.h"
#include "sdp_iocb.h"

#endif /* _SDP_MAIN_H */

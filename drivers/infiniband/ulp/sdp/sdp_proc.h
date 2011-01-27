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
 * $Id: sdp_proc.h 3362 2005-09-11 07:53:58Z mst $
 */

#ifndef _SDP_PROC_H
#define _SDP_PROC_H

#include <linux/proc_fs.h>

#define SDP_PROC_DIR_NAME "sdp"

/*
 * file and directory entries
 */

/*
 * proc filesystem framework table/file entries
 */
enum sdp_proc_ent_list {
	SDP_PROC_ENTRY_MAIN_CONN  = 0,	/* connection table */
	SDP_PROC_ENTRY_DATA_CONN  = 1,	/* connection table */
	SDP_PROC_ENTRY_RDMA_CONN  = 2,	/* connection table */
	SDP_PROC_ENTRY_OPT_CONN   = 3,	/* socket option table */
	SDP_PROC_ENTRY_ROOT_TABLE = 4,	/* device table */

	SDP_PROC_ENTRIES	/* number of entries in framework */
};

struct sdpc_proc_ent {
	char *name;
	s32 type;
	struct proc_dir_entry *entry;
	int (*read)(char *buffer,
		    int   max_size,
		    off_t start,
		    long *end);
};

#endif /* _SDP_PROC_H */

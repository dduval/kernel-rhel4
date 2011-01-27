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
 * $Id: sdp_proc.c 3362 2005-09-11 07:53:58Z mst $
 */

#include "sdp_main.h"

static const char dir_name_root[] = SDP_PROC_DIR_NAME;
static struct proc_dir_entry *dir_root = NULL;

/*
 * Generic static functions used by read/write functions
 */

/*
 * sdp_proc_read_parse - read function for the injection table
 */
static int sdp_proc_read_parse(char *page, char **start, off_t offset,
			       int count, int *eof, void *data)
{
	struct sdpc_proc_ent *sub_entry = (struct sdpc_proc_ent *)data;
	long end_index = 0;
	int  size;

#if 0
	if (!*start && offset) {
		return 0; /* I'm not sure why this always gets
			     called twice... */
	}
#endif

	size = sub_entry->read(page, count, offset, &end_index);
	if (size > 0) {
		if (end_index > 0) {
			*start = (char *)end_index;
			*eof = 0;
		} else {
			*start = NULL;
			*eof = 1;
		}
	}

	return size;
}

/*
 * Static read/write functions for each proc/framework directory entry
 */

/*
 * Initialization structure, each table in the gateway framework directory
 * (anything that is not a module) should create an entry and define read
 * write function.
 */
static struct sdpc_proc_ent file_entry_list[SDP_PROC_ENTRIES] = {
      {
	      .entry = NULL,
	      .type  = SDP_PROC_ENTRY_MAIN_CONN,
	      .name  = "conn_main",
	      .read  = sdp_proc_dump_conn_main,
      },
      {
	      .entry = NULL,
	      .type  = SDP_PROC_ENTRY_DATA_CONN,
	      .name  = "conn_data",
	      .read  = sdp_proc_dump_conn_data,
      },
      {
	      .entry = NULL,
	      .type  = SDP_PROC_ENTRY_RDMA_CONN,
	      .name  = "conn_rdma",
	      .read  = sdp_proc_dump_conn_rdma,
      },
      {
	      .entry = NULL,
	      .type  = SDP_PROC_ENTRY_OPT_CONN,
	      .name  = "opt_conn",
	      .read  = sdp_proc_dump_conn_sopt,
      },
      {
	      .entry = NULL,
	      .type  = SDP_PROC_ENTRY_ROOT_TABLE,
	      .name  = "devices",
	      .read  = sdp_proc_dump_device,
      },
} ;

/*
 * SDP module public functions.
 */

/*
 * sdp_main_proc_cleanup - cleanup the proc filesystem entries
 */
void sdp_main_proc_cleanup(void)
{
	struct sdpc_proc_ent *sub_entry;
	int counter;

	/*
	 * first clean-up the frameworks tables
	 */
	for (counter = 0; counter < SDP_PROC_ENTRIES; counter++) {
		sub_entry = &file_entry_list[counter];
		if (sub_entry->entry) {
			remove_proc_entry(sub_entry->name, dir_root);
			sub_entry->entry = NULL;
		}
	}
	/*
	 * remove SDP directory
	 */
	remove_proc_entry(dir_name_root, proc_net);
	dir_root = NULL;

	sdp_dbg_init("/proc filesystem cleanup complete.");
}

/*
 * sdp_main_proc_init - initialize the proc filesystem entries
 */
int sdp_main_proc_init(void)
{
	struct sdpc_proc_ent *sub_entry;
	int result;
	int counter;

	sdp_dbg_init("Initializing /proc filesystem entries.");
	/*
	 * XXX still need to check this:
	 * validate some assumptions the write parser will be making.
	 */
	if (0 && sizeof(s32) != sizeof(char *)) {
		sdp_warn("integers and pointers of a different size <%Zu:%Zu>",
			 sizeof(s32), sizeof(char *));
		return -EFAULT;
	}

	if (dir_root) {
		sdp_warn("/proc already initialized!");
		return -EINVAL;
	}
	/*
	 * create a gateway root, and main directories
	 */
	dir_root = proc_mkdir(dir_name_root, proc_net);
	if (!dir_root) {
		sdp_warn("Failed to create <%s> proc entry.", dir_name_root);
		return -EINVAL;
	}

	dir_root->owner = THIS_MODULE;

	for (counter = 0; counter < SDP_PROC_ENTRIES; counter++) {
		sub_entry = &file_entry_list[counter];
		if (sub_entry->type != counter) {
			result = -EFAULT;
			goto error;
		}

		sub_entry->entry = create_proc_entry(sub_entry->name,
						     S_IRUGO | S_IWUGO,
						     dir_root);
		if (!sub_entry->entry) {
			sdp_warn("Failed to create <%s> framework proc entry.",
				 sub_entry->name);
			result = -EINVAL;
			goto error;
		}

		sub_entry->entry->read_proc = sdp_proc_read_parse;
		sub_entry->entry->data = sub_entry;
		sub_entry->entry->owner = THIS_MODULE;
	}

	return 0;		/* success */
error:
	sdp_main_proc_cleanup();
	return result;
}

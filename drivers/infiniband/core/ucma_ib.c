/*
 * Copyright (c) 2006 Intel Corporation.  All rights reserved.
 *
 * This Software is licensed under one of the following licenses:
 *
 * 1) under the terms of the "Common Public License 1.0" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/cpl.php.
 *
 * 2) under the terms of the "The BSD License" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/bsd-license.php.
 *
 * 3) under the terms of the "GNU General Public License (GPL) Version 2" a
 *    copy of which is available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/gpl-license.php.
 *
 * Licensee has the right to choose one of the above licenses.
 *
 * Redistributions of source code must retain the above copyright
 * notice and one of the license notices.
 *
 * Redistributions in binary form must reproduce both the above copyright
 * notice, one of the license notices in the documentation
 * and/or other materials provided with the distribution.
 *
 */

#include <rdma/ib_addr.h>
#include <rdma/ib_local_sa.h>
#include <rdma/ib_marshall.h>
#include <rdma/rdma_cm_ib.h>
#include <rdma/rdma_user_cm.h>

#include "ucma_ib.h"

static int ucma_get_paths(struct rdma_cm_id *id,
			  void __user *paths, int *len)
{
	struct ib_sa_cursor *cursor;
	struct ib_sa_path_rec *path;
	struct ib_user_path_rec user_path;
	union ib_gid *gid;
	int left, ret = 0;
	u16 pkey;

	if (!id->device)
		return -ENODEV;

	gid = ib_addr_get_dgid(&id->route.addr.dev_addr);
	pkey = ib_addr_get_pkey(&id->route.addr.dev_addr);
	cursor = ib_create_path_cursor(id->device, id->port_num, gid);
	if (IS_ERR(cursor))
		return PTR_ERR(cursor);

	gid = ib_addr_get_sgid(&id->route.addr.dev_addr);
	left = *len;
	*len = 0;

	for (path = ib_get_next_sa_attr(&cursor); path;
	     path = ib_get_next_sa_attr(&cursor)) {
		if (pkey == path->pkey &&
		    !memcmp(gid, path->sgid.raw, sizeof *gid)) {
			if (paths) {
				ib_copy_path_rec_to_user(&user_path, path);
				if (copy_to_user(paths, &user_path,
						 sizeof(user_path))) {
					ret = -EFAULT;
					break;
				}
				left -= sizeof(user_path);
				if (left < sizeof(user_path))
					break;
				paths += sizeof(user_path);
			}
			*len += sizeof(user_path);
		}
	}

	ib_free_sa_cursor(cursor);
	return ret;
}

int ucma_get_ib_option(struct rdma_cm_id *id, int optname,
		       void *optval, int *optlen)
{
	switch (optname) {
	case IB_PATH_OPTIONS:
		return ucma_get_paths(id, optval, optlen);
	default:
		return -EINVAL;
	}
}

static int ucma_set_paths(struct rdma_cm_id *id,
			  void __user *paths, int len)
{
	struct ib_sa_path_rec *path_rec;
	struct ib_user_path_rec *user_path;
	int ret, num_paths, i;

	if (len == sizeof(*user_path))
		num_paths = 1;
	else if (len == (sizeof(*user_path) << 1))
		num_paths = 2;
	else
		return -EINVAL;

	path_rec = kmalloc(sizeof *path_rec * num_paths, GFP_KERNEL);
	if (!path_rec)
		return -ENOMEM;

	user_path = kmalloc(sizeof *user_path * num_paths, GFP_KERNEL);
	if (!user_path) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(user_path, paths, sizeof *user_path * num_paths)) {
		ret = -EFAULT;
		goto out2;
	}

	for (i = 0; i < num_paths; i++)
		ib_copy_path_rec_from_user(path_rec + i, user_path + i);

	ret = rdma_set_ib_paths(id, path_rec, num_paths);
out2:
	kfree(user_path);
out:
	kfree(path_rec);
	return ret;
}

int ucma_set_ib_option(struct rdma_cm_id *id, int optname,
		       void *optval, int optlen)
{
	switch (optname) {
	case IB_PATH_OPTIONS:
		return ucma_set_paths(id, optval, optlen);
	default:
		return -EINVAL;
	}
}

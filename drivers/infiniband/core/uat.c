/*
 * Copyright (c) 2005 Voltaire, Inc.  All rights reserved.
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
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
 *	copyright notice, this list of conditions and the following
 *	disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer in the documentation and/or other materials
 *	provided with the distribution.
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
 * $Id: uat.c 3453 2005-09-15 21:43:21Z sean.hefty $
 */
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/cdev.h>

#include <asm/uaccess.h>

#include "uat.h"
	
MODULE_AUTHOR("Hal Rosenstock");
MODULE_DESCRIPTION("InfiniBand userspace address translation access");
MODULE_LICENSE("Dual BSD/GPL");

static int uat_debug_level;

module_param_named(debug_level, uat_debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Enable debug tracing if > 0");

enum {
	IB_UAT_MAJOR = 231,
	IB_UAT_MINOR = 191
};

#define IB_UAT_DEV MKDEV(IB_UAT_MAJOR, IB_UAT_MINOR)

#define PFX "UAT: "

#define uat_dbg(format, arg...)			\
	do {					\
		if (uat_debug_level > 0)	\
			printk(KERN_DEBUG PFX format, ## arg); \
	} while (0)

static struct semaphore ctx_id_mutex;
static struct idr       ctx_id_table;
static int		ctx_id_rover = 0;


static void ib_uat_ctx_put(struct ib_uat_context *ctx)
{
	struct ib_uat_event *uevent;

	down(&ctx_id_mutex);

	ctx->ref--;
	if (ctx->ref) {
		up(&ctx_id_mutex);
		return;
	} else
		idr_remove(&ctx_id_table, ctx->id);

	up(&ctx_id_mutex);

	down(&ctx->file->mutex);

	list_del(&ctx->file_list);

	while (!list_empty(&ctx->events)) {
		uevent = list_entry(ctx->events.next,
				    struct ib_uat_event, ctx_list);
		list_del(&uevent->file_list);
		list_del(&uevent->ctx_list);

		kfree(uevent);
	}

	up(&ctx->file->mutex);

	uat_dbg("Destroyed context ID <%d>\n", ctx->id);

	kfree(ctx);
}

static struct ib_uat_context *ib_uat_ctx_alloc(struct ib_uat_file *file)
{
	struct ib_uat_context *ctx;
	int result;

	ctx = kmalloc(sizeof *ctx, GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->ref = 1; /* user reference */
	ctx->file = file;
	ctx->req_id = 0;
	ctx->rec_num = 0;
	ctx->status = IB_USER_AT_STATUS_PENDING;

	INIT_LIST_HEAD(&ctx->events);
	init_MUTEX(&ctx->mutex);

	list_add_tail(&ctx->file_list, &file->ctxs);

	ctx_id_rover = (ctx_id_rover + 1) & INT_MAX;
retry:
	result = idr_pre_get(&ctx_id_table, GFP_KERNEL);
	if (!result)
		goto error;

	down(&ctx_id_mutex);
	result = idr_get_new_above(&ctx_id_table, ctx, ctx_id_rover, &ctx->id);
	up(&ctx_id_mutex);

	if (result == -EAGAIN)
		goto retry;
	if (result)
		goto error;

	uat_dbg("Allocated context ID <%d>\n", ctx->id);

	return ctx;

error:
	list_del(&ctx->file_list);
	kfree(ctx);
	return NULL;
}

static struct ib_uat_event *ib_uat_create_event(struct ib_uat_context *ctx,
						enum ib_uat_event_type type)
{
	struct ib_uat_event *uevent;

	uevent = kmalloc(sizeof(*uevent), GFP_KERNEL);
	if (!uevent)
		goto done;

	memset(uevent, 0, sizeof(*uevent));
	uevent->ctx = ctx;
	uevent->type = type;

	down(&ctx->file->mutex);

	list_add_tail(&uevent->file_list, &ctx->file->events);
	list_add_tail(&uevent->ctx_list, &ctx->events);

	wake_up_interruptible(&ctx->file->poll_wait);

	up(&ctx->file->mutex);

done:
	return uevent;
}

static void ib_uat_callback(enum ib_uat_event_type type, u64 req_id,
			    void *context, int rec_num)
{
	struct ib_uat_context *ctx = context;
	struct ib_uat_event *uevent;

	if (ctx->req_id == 0)
		ctx->req_id = req_id;
	ctx->rec_num = rec_num;
	ctx->status = IB_USER_AT_STATUS_COMPLETED;

	kfree(ctx->comp);
	ctx->comp = NULL;
	uevent = ib_uat_create_event(ctx, type);
	if (!uevent)
		ib_uat_ctx_put(ctx);
}

static void ib_uat_ips_callback(u64 req_id, void *context, int rec_num)
{
	ib_uat_callback(IB_UAT_IPS_EVENT, req_id, context, rec_num);
}

static void ib_uat_route_callback(u64 req_id, void *context, int rec_num)
{
	ib_uat_callback(IB_UAT_ROUTE_EVENT, req_id, context, rec_num);
}

static void ib_uat_path_callback(u64 req_id, void *context, int rec_num)
{
	ib_uat_callback(IB_UAT_PATH_EVENT, req_id, context, rec_num);
}

static ssize_t ib_uat_route_by_ip(struct ib_uat_file *file,
				  const char __user *inbuf,
				  int in_len, int out_len)
{
	struct ib_uat_context *ctx;
	struct ib_uat_route_by_ip_req cmd;
	struct ib_uat_route_by_ip_resp resp;
	struct ib_uat_ib_route *ib_route;
	struct ib_at_completion *comp;
	int result;

	if (out_len < sizeof(resp))
		return -ENOSPC;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd))) {
		result = -EFAULT;
		goto err1;
	}

	ib_route = kmalloc(sizeof *ib_route, GFP_KERNEL);
	if (!ib_route) {
		result = -ENOMEM;
		goto err1;
	}

	if (copy_from_user(ib_route, cmd.ib_route, sizeof(ib_route))) {
		result = -EFAULT;
		goto err2;
	}

	comp = kmalloc(sizeof *comp, GFP_KERNEL);
	if (!comp) {
		result = -ENOMEM;
		goto err2;
	}

	ctx = ib_uat_ctx_alloc(file);
	if (!ctx) {
		result = -ENOMEM;
		goto err3;
	}

	ctx->comp = comp;
	if (cmd.async_comp) {
		ctx->user_callback = cmd.async_comp->fn;
		ctx->user_context = cmd.async_comp->context;
	} else {
		ctx->user_callback = NULL;
		ctx->user_context = NULL;
	}
	ctx->user_ib_route = cmd.ib_route;
	ctx->ib_route = (struct ib_at_route *)ib_route;
	comp->fn = &ib_uat_route_callback;
	comp->context = ctx;

	result = ib_at_route_by_ip(cmd.dst_ip, cmd.src_ip, cmd.tos, cmd.flags,
				   (struct ib_at_ib_route *)ib_route, comp);
	ctx->req_id = comp->req_id;
	resp.req_id = comp->req_id;	/* copy generated request ID to user */
	if (copy_to_user((void __user *)(unsigned long)cmd.response,
			 &resp, sizeof(resp))) {
		result = -EFAULT;
		goto err4;
	}
	if (cmd.async_comp) {
		if (copy_to_user(&cmd.async_comp->req_id, &comp->req_id,
				 sizeof(cmd.async_comp->req_id))) {
			result = -EFAULT;
			goto err4;
		}
	}
	if (result == 1) { 
		/* Copy route back to userspace */
		if (copy_to_user(ctx->user_ib_route, ctx->ib_route,
				 sizeof(*ctx->user_ib_route))) {
			result = -EFAULT;
			kfree(ctx->ib_route);
			ib_uat_ctx_put(ctx);
			goto err3;
		}
		kfree(ctx->ib_route);
		ib_uat_ctx_put(ctx);
	} else if (result < 0) {
		ib_uat_ctx_put(ctx);
		goto err3;
	}
	return result;

err4:
	ib_at_cancel(comp->req_id);
err3:
	kfree(comp);
err2:
	kfree(ib_route);
err1:
	return result;
}

static ssize_t ib_uat_paths_by_route(struct ib_uat_file *file,
				     const char __user *inbuf,
				     int in_len, int out_len)
{
	struct ib_uat_context *ctx;
	struct ib_sa_path_rec *path_arr;
	struct ib_uat_paths_by_route_req cmd;
	struct ib_uat_paths_by_route_resp resp;
	struct ib_uat_ib_route ib_route;
	struct ib_at_completion *comp;
	int path_arr_length, result;

	if (out_len < sizeof(resp))
		return -ENOSPC;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd))) {
		result = -EFAULT;
		goto err1;
	}

	if (copy_from_user(&ib_route, cmd.ib_route, sizeof(ib_route))) {
		result = -EFAULT;
		goto err1;
	}

	comp = kmalloc(sizeof *comp, GFP_KERNEL);
	if (!comp) {
		result = -ENOMEM;
		goto err1;
	}

	path_arr_length = sizeof *path_arr * cmd.npath;
	path_arr = kmalloc(path_arr_length, GFP_KERNEL);
	if (!path_arr) {
		result = -ENOMEM;
		goto err2;
	}

	ctx = ib_uat_ctx_alloc(file);
	if (!ctx) {
		result = -ENOMEM;
		goto err3;
	}

	ctx->path_arr = path_arr;
	ctx->comp = comp;
	if (cmd.async_comp) {
		ctx->user_callback = cmd.async_comp->fn;
		ctx->user_context = cmd.async_comp->context;
	} else {
		ctx->user_callback = NULL;
		ctx->user_context = NULL;
	}
	ctx->user_path_arr = cmd.path_arr;
	ctx->user_length = path_arr_length;
	comp->fn = &ib_uat_path_callback;
	comp->context = ctx;
	result = ib_at_paths_by_route((struct ib_at_ib_route *)&ib_route,
				      cmd.mpath_type, path_arr,
				      cmd.npath, comp);
	ctx->req_id = comp->req_id;
	resp.req_id = comp->req_id;	/* copy generated request ID to user */
	if (copy_to_user((void __user *)(unsigned long)cmd.response,
			 &resp, sizeof(resp))) {
		result = -EFAULT;
		goto err4;
	}
	if (cmd.async_comp) {
		if (copy_to_user(&cmd.async_comp->req_id, &comp->req_id,
				 sizeof(cmd.async_comp->req_id))) {
			result = -EFAULT;
			goto err4;
		}
	}
	if (result == 1) {
		/* Copy path records returned from SA to userspace */
		if (copy_to_user(ctx->user_path_arr, ctx->path_arr,
				 ctx->user_length)) {
			result = -EFAULT;
			kfree(ctx->path_arr);
			ib_uat_ctx_put(ctx);
			goto err3;
		}
		kfree(ctx->path_arr);
		ib_uat_ctx_put(ctx);
	} else if (result < 0) {
		ib_uat_ctx_put(ctx);
		goto err3;
	}
	return result;

err4:
	ib_at_cancel(comp->req_id);
err3:
	kfree(path_arr);
err2:
	kfree(comp);
err1:
	return result;
}

static ssize_t ib_uat_ips_by_gid(struct ib_uat_file *file,
				 const char __user *inbuf,
				 int in_len, int out_len)
{
	struct ib_uat_context *ctx;
	u32 *ips;
	u8 gid[16];
	struct ib_uat_ips_by_gid_req cmd;
	struct ib_uat_ips_by_gid_resp resp;
	struct ib_at_completion *comp;
	int result, ips_length;

	if (out_len < sizeof(resp))
		return -ENOSPC;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd))) {
		result = -EFAULT;
		goto err1;
	}

	if (copy_from_user(&gid, cmd.gid, sizeof(gid))) {
		result = -EFAULT;
		goto err1;
	}

	comp = kmalloc(sizeof *comp, GFP_KERNEL);
	if (!comp) {
		result = -ENOMEM;
		goto err1;
	}

	ips_length = sizeof *ips * cmd.nips;
	ips = kmalloc(ips_length, GFP_KERNEL);
	if (!ips) {
		result = -ENOMEM;
		goto err2;
	}
	ctx = ib_uat_ctx_alloc(file);
	if (!ctx) {
		result = -ENOMEM;
		goto err3;
	}

	ctx->ips = ips;
	ctx->comp = comp;
	if (cmd.async_comp) {
		ctx->user_callback = cmd.async_comp->fn;
		ctx->user_context = cmd.async_comp->context;
	} else {
		ctx->user_callback = NULL;
		ctx->user_context = NULL;
	}
	ctx->user_ips = cmd.dst_ips;
	ctx->user_length = ips_length;
	comp->fn = &ib_uat_ips_callback;
	comp->context = ctx;
	result = ib_at_ips_by_gid((union ib_gid *)&gid, ips,
				  cmd.nips, comp);
	ctx->req_id = comp->req_id;
	resp.req_id = comp->req_id;     /* copy generated request ID to user */
	if (copy_to_user((void __user *)(unsigned long)cmd.response,
			 &resp, sizeof(resp))) {
		result = -EFAULT;
		goto err4;
	}
	if (cmd.async_comp) {
		if (copy_to_user(&cmd.async_comp->req_id, &comp->req_id,
				 sizeof(cmd.async_comp->req_id))) {
			result = -EFAULT;
			goto err4;
		}
	}
	if (result == 1) {
		/* Copy IP addresses back to userspace */
		if (copy_to_user(ctx->user_ips, ctx->ips, ctx->user_length)) {
			result = -EFAULT;
			kfree(ctx->ips);
			ib_uat_ctx_put(ctx);
			goto err3;
		}
		kfree(ctx->ips);
		ib_uat_ctx_put(ctx);
	} else if (result < 0) {
		ib_uat_ctx_put(ctx);
		goto err3;
	}
	return result;

err4:
	ib_at_cancel(comp->req_id);
err3:
	kfree(ips);
err2:
	kfree(comp);
err1:
	return result;
}

static ssize_t ib_uat_ips_by_subnet(struct ib_uat_file *file,
				    const char __user *inbuf,
				    int in_len, int out_len)
{
	struct ib_uat_ips_by_subnet_req cmd;
	int result;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))
		return -EFAULT;

	result = ib_at_ips_by_subnet(cmd.network, cmd.netmask,
				     cmd.dst_ips, cmd.nips);
	return result;
}

static ssize_t ib_uat_invalidate_paths(struct ib_uat_file *file,
				       const char __user *inbuf,
				       int in_len, int out_len)
{
	struct ib_uat_invalidate_paths_req cmd;
	struct ib_uat_ib_route ib_route;
	int result;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))
		return -EFAULT;

	/* If ib_route is NULL, this means all cached paths */
	if (cmd.ib_route) {
		if (copy_from_user(&ib_route, cmd.ib_route, sizeof(ib_route)))
			return -EFAULT;
		result = ib_at_invalidate_paths((struct ib_at_ib_route *)&ib_route);
	} else
		result = ib_at_invalidate_paths(NULL);

	return result;
}

static ssize_t ib_uat_cancel(struct ib_uat_file *file,
			     const char __user *inbuf,
			     int in_len, int out_len)
{
	struct ib_uat_cancel_req cmd;
	int result;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))
		return -EFAULT;

	result = ib_at_cancel(cmd.req_id);
	return result;
}

static ssize_t ib_uat_status(struct ib_uat_file *file,
			     const char __user *inbuf,
			     int in_len, int out_len)
{
	struct ib_uat_status_req cmd;
	int result;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))
		return -EFAULT;

	result = ib_at_status(cmd.req_id);
	return result;
}

static ssize_t ib_uat_event(struct ib_uat_file *file,
			    const char __user *inbuf,
			    int in_len, int out_len)
{
	struct ib_uat_event_get cmd;
	struct ib_uat_event *uevent = NULL;
	int result = 0;
	DEFINE_WAIT(wait);

	if (out_len < sizeof(struct ib_uat_event_resp))
		return -ENOSPC;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))
		return -EFAULT;
	/*
	 * wait
	 */
	down(&file->mutex);

	while (list_empty(&file->events)) {
		if (file->filp->f_flags & O_NONBLOCK) {
			result = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			result = -ERESTARTSYS;
			break;
		}

		prepare_to_wait(&file->poll_wait, &wait, TASK_INTERRUPTIBLE);

		up(&file->mutex);
		schedule();
		down(&file->mutex);

		finish_wait(&file->poll_wait, &wait);
	}

	if (result)
		goto done;

	uevent = list_entry(file->events.next, struct ib_uat_event, file_list);
	if (!uevent) {
		printk(KERN_ERR "ib_uat_event: uevent NULL\n");
		result = -EIO;
		goto done;
	} else if (uevent->ctx) {
		/* Check context status for completed */
		if (uevent->ctx->status != IB_USER_AT_STATUS_COMPLETED) {
			printk(KERN_ERR "ib_uat_event: uevent %p ctx %p status %d not completed\n", uevent, uevent->ctx, uevent->ctx->status);
			uevent->ctx->rec_num = -EIO;
		}
		switch (uevent->type) {
		case IB_UAT_PATH_EVENT:
			/* Copy path records returned from SA to userspace */
			if (copy_to_user(uevent->ctx->user_path_arr,
					 uevent->ctx->path_arr,
					 uevent->ctx->user_length))
				result = -EFAULT;
			kfree(uevent->ctx->path_arr);
			uevent->ctx->path_arr = NULL;
			break;
		case IB_UAT_ROUTE_EVENT:
			/* Copy route back to userspace */
			if (copy_to_user(uevent->ctx->user_ib_route,
					 uevent->ctx->ib_route,
					 sizeof(*uevent->ctx->user_ib_route)))
				result = -EFAULT;
			kfree(uevent->ctx->ib_route);
			uevent->ctx->ib_route = NULL;
			break;
		case IB_UAT_IPS_EVENT:
			/* Copy IP addresses back to userspace */
			if (copy_to_user(uevent->ctx->user_ips,
					 uevent->ctx->ips,
					 uevent->ctx->user_length))
				result = -EFAULT;
			kfree(uevent->ctx->ips);
			uevent->ctx->ips = NULL;
			break;
		default:
			printk(KERN_ERR "ib_uat_event: type %d not handled\n",
			       uevent->type);
			break;
		}
		if (result == -EFAULT)
			goto done;
		uevent->resp.callback = (u64)(unsigned long)uevent->ctx->user_callback;
		uevent->resp.context = (u64)(unsigned long)uevent->ctx->user_context;
		uevent->resp.req_id = uevent->ctx->req_id;
		uevent->resp.rec_num = uevent->ctx->rec_num;
		if (copy_to_user((void __user *)(unsigned long)cmd.response,
				 &uevent->resp, sizeof(uevent->resp))) {
			result = -EFAULT;
			goto done;
		}
	} else {
		printk(KERN_ERR "ib_uat_event: uevent ctx NULL\n");
		result = -EIO;
		goto done;
	}

	list_del(&uevent->file_list);
	list_del(&uevent->ctx_list);

	up(&file->mutex);

	/* Release context */
	ib_uat_ctx_put(uevent->ctx);	
	kfree(uevent);
	return result;

done:
	up(&file->mutex);
	return result;
}
  
static ssize_t (*uat_cmd_table[])(struct ib_uat_file *file,
				  const char __user *inbuf,
				  int in_len, int out_len) = {
	[IB_USER_AT_CMD_ROUTE_BY_IP]	= ib_uat_route_by_ip,
	[IB_USER_AT_CMD_PATHS_BY_ROUTE]	= ib_uat_paths_by_route,
	[IB_USER_AT_CMD_IPS_BY_GID]	= ib_uat_ips_by_gid,
	[IB_USER_AT_CMD_IPS_BY_SUBNET]	= ib_uat_ips_by_subnet,
	[IB_USER_AT_CMD_INVALIDATE_PATHS] = ib_uat_invalidate_paths,
	[IB_USER_AT_CMD_CANCEL]		= ib_uat_cancel,
	[IB_USER_AT_CMD_STATUS]		= ib_uat_status,

	[IB_USER_AT_CMD_EVENT]		= ib_uat_event,
};

static ssize_t ib_uat_write(struct file *filp, const char __user *buf,
			    size_t len, loff_t *pos)
{
	struct ib_uat_file *file = filp->private_data;
	struct ib_uat_cmd_hdr hdr;
	ssize_t result;

	if (len < sizeof(hdr))
		return -EINVAL;

	if (copy_from_user(&hdr, buf, sizeof(hdr)))
		return -EFAULT;

	uat_dbg("Write. cmd <%d> in <%d> out <%d> len <%Zu>\n",
		hdr.cmd, hdr.in, hdr.out, len);

	if (hdr.cmd < 0 || hdr.cmd >= ARRAY_SIZE(uat_cmd_table))
		return -EINVAL;

	if (hdr.in + sizeof(hdr) > len)
		return -EINVAL;

	result = uat_cmd_table[hdr.cmd](file, buf + sizeof(hdr),
					hdr.in, hdr.out);

	return result;
}

static unsigned int ib_uat_poll(struct file *filp,
				struct poll_table_struct *wait)
{
	struct ib_uat_file *file = filp->private_data;
	unsigned int mask = 0;

	poll_wait(filp, &file->poll_wait, wait);

	if (!list_empty(&file->events))
		mask = POLLIN | POLLRDNORM;

	return mask;
}

static int ib_uat_open(struct inode *inode, struct file *filp)
{
	struct ib_uat_file *file;

	file = kmalloc(sizeof(*file), GFP_KERNEL);
	if (!file)
		return -ENOMEM;

	INIT_LIST_HEAD(&file->events);
	INIT_LIST_HEAD(&file->ctxs);
	init_waitqueue_head(&file->poll_wait);

	init_MUTEX(&file->mutex);

	filp->private_data = file;
	file->filp = filp;
	uat_dbg("Created struct\n");
	return 0;
}

static int ib_uat_close(struct inode *inode, struct file *filp)
{
	struct ib_uat_file *file = filp->private_data;
	struct ib_uat_context *ctx;

	down(&file->mutex);

	while (!list_empty(&file->ctxs)) {

		ctx = list_entry(file->ctxs.next,
				 struct ib_uat_context, file_list);

		up(&ctx->file->mutex);

		ib_uat_ctx_put(ctx); /* user reference */

		down(&file->mutex);
	}

	up(&file->mutex);

	kfree(file);

	uat_dbg("Deleted struct\n");
	return 0;
}

static struct file_operations ib_uat_fops = {
	.owner 	 = THIS_MODULE,
	.open 	 = ib_uat_open,
	.release = ib_uat_close,
	.write 	 = ib_uat_write,
	.poll    = ib_uat_poll,
};


static struct class *ib_uat_class;
static struct cdev   ib_uat_cdev;

static int __init ib_uat_init(void)
{
	int result;

	result = register_chrdev_region(IB_UAT_DEV, 1, "infiniband_at");
	if (result) {
		uat_dbg("Error <%d> registering dev\n", result);
		goto err_chr;
	}

	cdev_init(&ib_uat_cdev, &ib_uat_fops);

	result = cdev_add(&ib_uat_cdev, IB_UAT_DEV, 1);
	if (result) {
		uat_dbg("Error <%d> adding cdev\n", result);
		goto err_cdev;
	}

	ib_uat_class = class_create(THIS_MODULE, "infiniband_uat");
	if (IS_ERR(ib_uat_class)) {
		result = PTR_ERR(ib_uat_class);
		uat_dbg("Error <%d> creating class\n", result);
		goto err_class;
	}

	class_device_create(ib_uat_class, IB_UAT_DEV, NULL, "uat");
	
	idr_init(&ctx_id_table);
	init_MUTEX(&ctx_id_mutex);
	return 0;

err_class:
	cdev_del(&ib_uat_cdev);
err_cdev:
	unregister_chrdev_region(IB_UAT_DEV, 1);
err_chr:
	return result;
}

static void __exit ib_uat_cleanup(void)
{
	class_device_destroy(ib_uat_class, IB_UAT_DEV);
	class_destroy(ib_uat_class);
	cdev_del(&ib_uat_cdev);
	unregister_chrdev_region(IB_UAT_DEV, 1);
}

module_init(ib_uat_init);
module_exit(ib_uat_cleanup);

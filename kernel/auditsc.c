/* auditsc.c -- System-call auditing support
 * Handles all system-call specific auditing features.
 *
 * Copyright 2003-2004 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
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
 *
 * Written by Rickard E. (Rik) Faith <faith@redhat.com>
 *
 * Many of the ideas implemented here are from Stephen C. Tweedie,
 * especially the idea of avoiding a copy by using getname.
 *
 * The method for actual interception of syscall entry and exit (not in
 * this file -- see entry.S) is based on a GPL'd patch written by
 * okir@suse.de and Copyright 2003 SuSE Linux AG.
 *
 */

#include <linux/init.h>
#include <asm/atomic.h>
#include <asm/types.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/socket.h>
#include <linux/audit.h>
#include <linux/personality.h>
#include <linux/time.h>
#include <linux/netlink.h>
#include <linux/kthread.h>
#include <linux/binfmts.h>
#include <asm/unistd.h>

/* 0 = no checking
   1 = put_count checking
   2 = verbose put_count checking
*/
#define AUDIT_DEBUG 0

/* No syscall auditing will take place unless audit_enabled != 0. */
extern int audit_enabled;

/* AUDIT_NAMES is the number of slots we reserve in the audit_context
 * for saving names from getname(). */
#define AUDIT_NAMES    20

/* AUDIT_NAMES_RESERVED is the number of slots we reserve in the
 * audit_context from being used for nameless inodes from
 * path_lookup. */
#define AUDIT_NAMES_RESERVED 7

/* no execve audit message should be longer than this (userspace limits) */
#define MAX_EXECVE_AUDIT_LEN 7500

/* At task start time, the audit_state is set in the audit_context using
   a per-task filter.  At syscall entry, the audit_state is augmented by
   the syscall filter. */
enum audit_state {
	AUDIT_DISABLED,		/* Do not create per-task audit_context.
				 * No syscall-specific audit records can
				 * be generated. */
	AUDIT_SETUP_CONTEXT,	/* Create the per-task audit_context,
				 * but don't necessarily fill it in at
				 * syscall entry time (i.e., filter
				 * instead). */
	AUDIT_BUILD_CONTEXT,	/* Create the per-task audit_context,
				 * and always fill it in at syscall
				 * entry time.  This makes a full
				 * syscall record available if some
				 * other part of the kernel decides it
				 * should be recorded. */
	AUDIT_RECORD_CONTEXT	/* Create the per-task audit_context,
				 * always fill it in at syscall entry
				 * time, and always write out the audit
				 * record at syscall exit time.  */
};

/* When fs/namei.c:getname() is called, we store the pointer in name and
 * we don't let putname() free it (instead we free all of the saved
 * pointers at syscall exit time).
 *
 * Further, in fs/namei.c:path_lookup() we store the inode and device. */
struct audit_names {
	const char	*name;
	unsigned long	ino;
	dev_t		dev;
	umode_t		mode;
	uid_t		uid;
	gid_t		gid;
	dev_t		rdev;
	unsigned	flags;
};

struct audit_aux_data {
	struct audit_aux_data	*next;
	int			type;
};

struct audit_aux_data_ipcctl {
	struct audit_aux_data	d;
	struct ipc_perm		p;
	unsigned long		qbytes;
	uid_t			uid;
	gid_t			gid;
	mode_t			mode;
};

struct audit_aux_data_execve {
	struct audit_aux_data	d;
	int argc;
	int envc;
	char mem[0];
};

struct audit_aux_data_socketcall {
	struct audit_aux_data	d;
	int			nargs;
	unsigned long		args[0];
};

struct audit_aux_data_sockaddr {
	struct audit_aux_data	d;
	int			len;
	char			a[0];
};

struct audit_aux_data_path {
	struct audit_aux_data	d;
	struct dentry		*dentry;
	struct vfsmount		*mnt;
};

struct audit_aux_data_watched {
	struct audit_aux_data	link;
	struct hlist_head	watches;
	unsigned long		ino;
	int			mask;
	uid_t			uid;
	gid_t			gid;
	dev_t			dev;
	dev_t			rdev;
};

/* The per-task audit context. */
struct audit_context {
	int		    in_syscall;	/* 1 if task is in a syscall */
	enum audit_state    state;
	unsigned int	    serial;     /* serial number for record */
	struct timespec	    ctime;      /* time of syscall entry */
	uid_t		    loginuid;   /* login uid (identity) */
	int		    major;      /* syscall number */
	unsigned long	    argv[4];    /* syscall arguments */
	int		    return_valid; /* return code is valid */
	long		    return_code;/* syscall return code */
	int		    auditable;  /* 1 if record should be written */
	int		    name_count;
	struct audit_names  names[AUDIT_NAMES];
	struct dentry *	    pwd;
	struct vfsmount *   pwdmnt;
	struct audit_context *previous; /* For nested syscalls */
	struct audit_aux_data *aux;

				/* Save things to print about task_struct */
	pid_t		    pid;
	uid_t		    uid, euid, suid, fsuid;
	gid_t		    gid, egid, sgid, fsgid;
	unsigned long	    personality;
	int		    arch;

#if AUDIT_DEBUG
	int		    put_count;
	int		    ino_count;
#endif
};

				/* Public API */
/* There are three lists of rules -- one to search at task creation
 * time, one to search at syscall entry time, and another to search at
 * syscall exit time. */
static struct list_head audit_filter_list[AUDIT_NR_FILTERS] = {
	LIST_HEAD_INIT(audit_filter_list[0]),
	LIST_HEAD_INIT(audit_filter_list[1]),
	LIST_HEAD_INIT(audit_filter_list[2]),
	LIST_HEAD_INIT(audit_filter_list[3]),
	LIST_HEAD_INIT(audit_filter_list[4]),
#if AUDIT_NR_FILTERS != 5
#error Fix audit_filter_list initialiser
#endif
};

struct audit_entry {
	struct list_head  list;
	struct rcu_head   rcu;
	struct audit_rule rule;
};

extern int audit_pid;

/* Copy rule from user-space to kernel-space.  Called from 
 * audit_add_rule during AUDIT_ADD. */
static inline int audit_copy_rule(struct audit_rule *d, struct audit_rule *s)
{
	int i;

	if (s->action != AUDIT_NEVER
	    && s->action != AUDIT_POSSIBLE
	    && s->action != AUDIT_ALWAYS)
		return -1;
	if (s->field_count < 0 || s->field_count > AUDIT_MAX_FIELDS)
		return -1;
	if ((s->flags & ~AUDIT_FILTER_PREPEND) >= AUDIT_NR_FILTERS)
		return -1;

	d->flags	= s->flags;
	d->action	= s->action;
	d->field_count	= s->field_count;
	for (i = 0; i < d->field_count; i++) {
		d->fields[i] = s->fields[i];
		d->values[i] = s->values[i];
	}
	for (i = 0; i < AUDIT_BITMASK_SIZE; i++) d->mask[i] = s->mask[i];
	return 0;
}

/* Check to see if two rules are identical.  It is called from
 * audit_add_rule during AUDIT_ADD and 
 * audit_del_rule during AUDIT_DEL. */
static inline int audit_compare_rule(struct audit_rule *a, struct audit_rule *b)
{
	int i;

	if (a->flags != b->flags)
		return 1;

	if (a->action != b->action)
		return 1;

	if (a->field_count != b->field_count)
		return 1;

	for (i = 0; i < a->field_count; i++) {
		if (a->fields[i] != b->fields[i]
		    || a->values[i] != b->values[i])
			return 1;
	}

	for (i = 0; i < AUDIT_BITMASK_SIZE; i++)
		if (a->mask[i] != b->mask[i])
			return 1;

	return 0;
}

/* Note that audit_add_rule and audit_del_rule are called via
 * audit_receive() in audit.c, and are protected by
 * audit_netlink_sem. */
static inline int audit_add_rule(struct audit_rule *rule,
				  struct list_head *list)
{
	struct audit_entry  *entry;

	/* Do not use the _rcu iterator here, since this is the only
	 * addition routine. */
	list_for_each_entry(entry, list, list) {
		if (!audit_compare_rule(rule, &entry->rule)) {
			return -EEXIST;
		}
	}

	if (!(entry = kmalloc(sizeof(*entry), GFP_KERNEL)))
		return -ENOMEM;
	if (audit_copy_rule(&entry->rule, rule)) {
		kfree(entry);
		return -EINVAL;
	}

	if (entry->rule.flags & AUDIT_FILTER_PREPEND) {
		entry->rule.flags &= ~AUDIT_FILTER_PREPEND;
		list_add_rcu(&entry->list, list);
	} else {
		list_add_tail_rcu(&entry->list, list);
	}

	return 0;
}

static inline void audit_free_rule(struct rcu_head *head)
{
	struct audit_entry *e = container_of(head, struct audit_entry, rcu);
	kfree(e);
}

/* Note that audit_add_rule and audit_del_rule are called via
 * audit_receive() in audit.c, and are protected by
 * audit_netlink_sem. */
static inline int audit_del_rule(struct audit_rule *rule,
				 struct list_head *list)
{
	struct audit_entry  *e;

	/* Do not use the _rcu iterator here, since this is the only
	 * deletion routine. */
	list_for_each_entry(e, list, list) {
		if (!audit_compare_rule(rule, &e->rule)) {
			list_del_rcu(&e->list);
			call_rcu(&e->rcu, audit_free_rule);
			return 0;
		}
	}
	return -ENOENT;		/* No matching rule */
}

#ifdef CONFIG_NET
static void audit_list_rules(int pid, int seq, struct sk_buff_head *q)
{
	struct sk_buff *skb;
	struct audit_entry *entry;
	int i;

	/* The *_rcu iterators not needed here because we are
	   always called with audit_netlink_sem held. */
	for (i=0; i<AUDIT_NR_FILTERS; i++) {
		list_for_each_entry(entry, &audit_filter_list[i], list) {
			skb = audit_make_reply(pid, seq, AUDIT_LIST, 0, 1,
					&entry->rule, sizeof(entry->rule));
			if (skb)
				skb_queue_tail(q, skb);
		}
	}
	skb = audit_make_reply(pid, seq, AUDIT_LIST, 1, 1, NULL, 0);
	if (skb)
		skb_queue_tail(q, skb);
}

int audit_receive_filter(int type, int pid, int uid, int seq, void *data,
							uid_t loginuid)
{
	struct task_struct *tsk;
	struct audit_netlink_list *dest;
	int err = 0;
	unsigned listnr;

	switch (type) {
	case AUDIT_LIST:
		/* We can't just spew out the rules here because we might fill
		 * the available socket buffer space and deadlock waiting for
		 * auditctl to read from it... which isn't ever going to
		 * happen if we're actually running in the context of auditctl
		 * trying to _send_ the stuff */
		 
		dest = kmalloc(sizeof(struct audit_netlink_list), GFP_KERNEL);
		if (!dest)
			return -ENOMEM;
		dest->pid = pid;
		skb_queue_head_init(&dest->q);

		audit_list_rules(pid, seq, &dest->q);

		tsk = kthread_run(audit_send_list, dest, "audit_send_list");
		if (IS_ERR(tsk)) {
			skb_queue_purge(&dest->q);
			kfree(dest);
			err = PTR_ERR(tsk);
		}
		break;
	case AUDIT_ADD:
		listnr =((struct audit_rule *)data)->flags & ~AUDIT_FILTER_PREPEND;
		if (listnr >= AUDIT_NR_FILTERS)
			return -EINVAL;

		err = audit_add_rule(data, &audit_filter_list[listnr]);
		if (!err)
			audit_log(NULL, GFP_KERNEL, AUDIT_CONFIG_CHANGE,
				  "auid=%u added an audit rule\n", loginuid);
		break;
	case AUDIT_DEL:
		listnr =((struct audit_rule *)data)->flags & ~AUDIT_FILTER_PREPEND;
		if (listnr >= AUDIT_NR_FILTERS)
			return -EINVAL;

		err = audit_del_rule(data, &audit_filter_list[listnr]);
		if (!err)
			audit_log(NULL, GFP_KERNEL, AUDIT_CONFIG_CHANGE,
				  "auid=%u removed an audit rule\n", loginuid);
		break;
	default:
		return -EINVAL;
	}

	return err;
}
#endif

/* Compare a task_struct with an audit_rule.  Return 1 on match, 0
 * otherwise. */
static int audit_filter_rules(struct task_struct *tsk,
			      struct audit_rule *rule,
			      struct audit_context *ctx,
			      enum audit_state *state)
{
	int i, j;

	for (i = 0; i < rule->field_count; i++) {
		u32 field  = rule->fields[i] & ~AUDIT_NEGATE;
		u32 value  = rule->values[i];
		int result = 0;

		switch (field) {
		case AUDIT_PID:
			result = ((u32)tsk->pid == value);
			break;
		case AUDIT_UID:
			result = ((u32)tsk->uid == value);
			break;
		case AUDIT_EUID:
			result = ((u32)tsk->euid == value);
			break;
		case AUDIT_SUID:
			result = ((u32)tsk->suid == value);
			break;
		case AUDIT_FSUID:
			result = ((u32)tsk->fsuid == value);
			break;
		case AUDIT_GID:
			result = ((u32)tsk->gid == value);
			break;
		case AUDIT_EGID:
			result = ((u32)tsk->egid == value);
			break;
		case AUDIT_SGID:
			result = ((u32)tsk->sgid == value);
			break;
		case AUDIT_FSGID:
			result = ((u32)tsk->fsgid == value);
			break;
		case AUDIT_PERS:
			result = ((u32)tsk->personality == value);
			break;
		case AUDIT_ARCH:
			if (ctx) 
				result = ((u32)ctx->arch == value);
			break;

		case AUDIT_EXIT:
			if (ctx && ctx->return_valid)
				result = ((u32)ctx->return_code == value);
			break;
		case AUDIT_SUCCESS:
			if (ctx && ctx->return_valid) {
				if (value)
					result = ((u32)ctx->return_valid == AUDITSC_SUCCESS);
				else
					result = ((u32)ctx->return_valid == AUDITSC_FAILURE);
			}
			break;
		case AUDIT_DEVMAJOR:
			if (ctx) {
				for (j = 0; j < ctx->name_count; j++) {
					if ((u32)MAJOR(ctx->names[j].dev)==value) {
						++result;
						break;
					}
				}
			}
			break;
		case AUDIT_DEVMINOR:
			if (ctx) {
				for (j = 0; j < ctx->name_count; j++) {
					if ((u32)MINOR(ctx->names[j].dev)==value) {
						++result;
						break;
					}
				}
			}
			break;
		case AUDIT_INODE:
			if (ctx) {
				for (j = 0; j < ctx->name_count; j++) {
					if ((u32)ctx->names[j].ino == value) {
						++result;
						break;
					}
				}
			}
			break;
		case AUDIT_LOGINUID:
			result = 0;
			if (ctx)
				result = ((u32)ctx->loginuid == value);
			break;
		case AUDIT_ARG0:
		case AUDIT_ARG1:
		case AUDIT_ARG2:
		case AUDIT_ARG3:
			if (ctx)
				result = ((u32)ctx->argv[field-AUDIT_ARG0]==value);
			break;
		}

		if (rule->fields[i] & AUDIT_NEGATE)
			result = !result;
		if (!result)
			return 0;
	}
	switch (rule->action) {
	case AUDIT_NEVER:    *state = AUDIT_DISABLED;	    break;
	case AUDIT_POSSIBLE: *state = AUDIT_BUILD_CONTEXT;  break;
	case AUDIT_ALWAYS:   *state = AUDIT_RECORD_CONTEXT; break;
	}
	return 1;
}

/* At process creation time, we can determine if system-call auditing is
 * completely disabled for this task.  Since we only have the task
 * structure at this point, we can only check uid and gid.
 */
static enum audit_state audit_filter_task(struct task_struct *tsk)
{
	struct audit_entry *e;
	enum audit_state   state;

	rcu_read_lock();
	list_for_each_entry_rcu(e, &audit_filter_list[AUDIT_FILTER_TASK], list) {
		if (audit_filter_rules(tsk, &e->rule, NULL, &state)) {
			rcu_read_unlock();
			return state;
		}
	}
	rcu_read_unlock();
	return AUDIT_BUILD_CONTEXT;
}

/* At syscall entry and exit time, this filter is called if the
 * audit_state is not low enough that auditing cannot take place, but is
 * also not high enough that we already know we have to write an audit
 * record (i.e., the state is AUDIT_SETUP_CONTEXT or  AUDIT_BUILD_CONTEXT).
 */
static enum audit_state audit_filter_syscall(struct task_struct *tsk,
					     struct audit_context *ctx,
					     struct list_head *list)
{
	struct audit_entry *e;
	enum audit_state state;

	if (audit_pid && tsk->tgid == audit_pid)
		return AUDIT_DISABLED;

	rcu_read_lock();
	if (!list_empty(list)) {
		    int word = AUDIT_WORD(ctx->major);
		    int bit  = AUDIT_BIT(ctx->major);

		    list_for_each_entry_rcu(e, list, list) {
			    if ((e->rule.mask[word] & bit) == bit
				&& audit_filter_rules(tsk, &e->rule, ctx, &state)) {
				    rcu_read_unlock();
				    return state;
			    }
		    }
	}
	rcu_read_unlock();
	return AUDIT_BUILD_CONTEXT;
}

static int audit_filter_user_rules(struct netlink_skb_parms *cb,
			      struct audit_rule *rule,
			      enum audit_state *state)
{
	int i;

	for (i = 0; i < rule->field_count; i++) {
		u32 field  = rule->fields[i] & ~AUDIT_NEGATE;
		u32 value  = rule->values[i];
		int result = 0;

		switch (field) {
		case AUDIT_PID:
			result = (cb->creds.pid == value);
			break;
		case AUDIT_UID:
			result = (cb->creds.uid == value);
			break;
		case AUDIT_GID:
			result = (cb->creds.gid == value);
			break;
		case AUDIT_LOGINUID:
			result = (cb->loginuid == value);
			break;
		}

		if (rule->fields[i] & AUDIT_NEGATE)
			result = !result;
		if (!result)
			return 0;
	}
	switch (rule->action) {
	case AUDIT_NEVER:    *state = AUDIT_DISABLED;	    break;
	case AUDIT_POSSIBLE: *state = AUDIT_BUILD_CONTEXT;  break;
	case AUDIT_ALWAYS:   *state = AUDIT_RECORD_CONTEXT; break;
	}
	return 1;
}

int audit_filter_user(struct netlink_skb_parms *cb, int type)
{
	struct audit_entry *e;
	enum audit_state   state;
	int ret = 1;

	rcu_read_lock();
	list_for_each_entry_rcu(e, &audit_filter_list[AUDIT_FILTER_USER], list) {
		if (audit_filter_user_rules(cb, &e->rule, &state)) {
			if (state == AUDIT_DISABLED)
				ret = 0;
			break;
		}
	}
	rcu_read_unlock();

	return ret; /* Audit by default */
}

/* This should be called with task_lock() held. */
static inline struct audit_context *audit_get_context(struct task_struct *tsk,
						      int return_valid,
						      int return_code)
{
	struct audit_context *context = tsk->audit_context;

	if (likely(!context))
		return NULL;
	context->return_valid = return_valid;
	context->return_code  = return_code;

	if (context->in_syscall && !context->auditable) {
		enum audit_state state;
		state = audit_filter_syscall(tsk, context, &audit_filter_list[AUDIT_FILTER_EXIT]);
		if (state == AUDIT_RECORD_CONTEXT)
			context->auditable = 1;
	}

	context->pid = tsk->pid;
	context->uid = tsk->uid;
	context->gid = tsk->gid;
	context->euid = tsk->euid;
	context->suid = tsk->suid;
	context->fsuid = tsk->fsuid;
	context->egid = tsk->egid;
	context->sgid = tsk->sgid;
	context->fsgid = tsk->fsgid;
	context->personality = tsk->personality;
	tsk->audit_context = NULL;
	return context;
}

static inline void audit_free_names(struct audit_context *context)
{
	int i;

#if AUDIT_DEBUG == 2
	if (context->auditable
	    ||context->put_count + context->ino_count != context->name_count) {
		printk(KERN_ERR "audit.c:%d(:%d): major=%d in_syscall=%d"
		       " name_count=%d put_count=%d"
		       " ino_count=%d [NOT freeing]\n",
		       __LINE__,
		       context->serial, context->major, context->in_syscall,
		       context->name_count, context->put_count,
		       context->ino_count);
		for (i = 0; i < context->name_count; i++)
			printk(KERN_ERR "names[%d] = %p = %s\n", i,
			       context->names[i].name,
			       context->names[i].name);
		dump_stack();
		return;
	}
#endif
#if AUDIT_DEBUG
	context->put_count  = 0;
	context->ino_count  = 0;
#endif

	for (i = 0; i < context->name_count; i++)
		if (context->names[i].name)
			__putname(context->names[i].name);
	context->name_count = 0;
	if (context->pwd)
		dput(context->pwd);
	if (context->pwdmnt)
		mntput(context->pwdmnt);
	context->pwd = NULL;
	context->pwdmnt = NULL;
}

static inline void audit_free_aux(struct audit_context *context)
{
	struct audit_aux_data *aux;
	struct audit_watch_info *winfo;
	struct hlist_node *pos, *tmp;

	while ((aux = context->aux)) {
		switch(aux->type) {
		case AUDIT_AVC_PATH: {
			struct audit_aux_data_path *axi = (void *)aux;
			dput(axi->dentry);
			mntput(axi->mnt);
			break; }
		case AUDIT_FS_INODE: {
			struct audit_aux_data_watched *axi = (void *)aux;
			hlist_for_each_entry_safe(winfo, pos, tmp, &axi->watches, node) {
				audit_watch_put(winfo->watch);
				hlist_del(&winfo->node);
				kfree(winfo);
                        }
			break; }
		}
		
		context->aux = aux->next;
		kfree(aux);
	}
}

static inline void audit_zero_context(struct audit_context *context,
				      enum audit_state state)
{
	uid_t loginuid = context->loginuid;

	memset(context, 0, sizeof(*context));
	context->state      = state;
	context->loginuid   = loginuid;
}

static inline struct audit_context *audit_alloc_context(enum audit_state state)
{
	struct audit_context *context;

	if (!(context = kmalloc(sizeof(*context), GFP_KERNEL)))
		return NULL;
	audit_zero_context(context, state);
	return context;
}

/* Filter on the task information and allocate a per-task audit context
 * if necessary.  Doing so turns on system call auditing for the
 * specified task.  This is called from copy_process, so no lock is
 * needed. */
int audit_alloc(struct task_struct *tsk)
{
	struct audit_context *context;
	enum audit_state     state;

	if (likely(!audit_enabled))
		return 0; /* Return if not auditing. */

	state = audit_filter_task(tsk);
	if (likely(state == AUDIT_DISABLED))
		return 0;

	if (!(context = audit_alloc_context(state))) {
		audit_log_lost("out of memory in audit_alloc");
		return -ENOMEM;
	}

				/* Preserve login uid */
	context->loginuid = -1;
	if (current->audit_context)
		context->loginuid = current->audit_context->loginuid;

	tsk->audit_context  = context;
	set_tsk_thread_flag(tsk, TIF_SYSCALL_AUDIT);
	return 0;
}

static inline void audit_free_context(struct audit_context *context)
{
	struct audit_context *previous;
	int		     count = 0;

	do {
		previous = context->previous;
		if (previous || (count &&  count < 10)) {
			++count;
			printk(KERN_ERR "audit(:%d): major=%d name_count=%d:"
			       " freeing multiple contexts (%d)\n",
			       context->serial, context->major,
			       context->name_count, count);
		}
		audit_free_names(context);
		audit_free_aux(context);
		kfree(context);
		context  = previous;
	} while (context);
	if (count >= 10)
		printk(KERN_ERR "audit: freed %d contexts\n", count);
}

static void audit_log_task_info(struct audit_buffer *ab,
				struct task_struct *tsk)
{
	char name[sizeof(tsk->comm)];
	struct mm_struct *mm = tsk->mm;
	struct vm_area_struct *vma;

	/* tsk == current */

	get_task_comm(name, tsk);
	audit_log_format(ab, " comm=");
	audit_log_untrustedstring(ab, name);

	if (mm) {
		down_read(&mm->mmap_sem);
		vma = mm->mmap;
		while (vma) {
			if ((vma->vm_flags & VM_EXECUTABLE) &&
			    vma->vm_file) {
				audit_log_d_path(ab, "exe=",
						 vma->vm_file->f_dentry,
						 vma->vm_file->f_vfsmnt);
				break;
			}
			vma = vma->vm_next;
		}
		up_read(&mm->mmap_sem);
	}
}

/*
 * to_send and len_sent accounting are very loose estimates.  We aren't
 * really worried about a hard cap to MAX_EXECVE_AUDIT_LEN so much as being
 * within about 500 bytes (next page boundry)
 *
 * why snprintf?  an int is up to 12 digits long.  if we just assumed when
 * logging that a[%d]= was going to be 16 characters long we would be wasting
 * space in every audit message.  In one 7500 byte message we can log up to
 * about 1000 min size arguments.  That comes down to about 50% waste of space
 * if we didn't do the snprintf to find out how long arg_num_len was.
 */
static int audit_log_single_execve_arg(struct audit_context *context,
					struct audit_buffer **ab,
					int arg_num,
					size_t *len_sent,
					const char *p)
{
	char arg_num_len_buf[12];
	/* how many digits are in arg_num? 3 is the length of " a=" */
	size_t arg_num_len = snprintf(arg_num_len_buf, 12, "%d", arg_num) + 3;
	size_t len, len_left, to_send;
	size_t max_execve_audit_len = MAX_EXECVE_AUDIT_LEN;
	unsigned int i, has_cntl = 0, too_long = 0;

	/* strnlen_user includes the null we don't want to send */
	len_left = len = strlen(p);

	has_cntl = audit_string_contains_control(p, len);
	if (has_cntl)
		/*
		 * hex messages get logged as 2 bytes, so we can only
		 * send half as much in each message
		 */
		max_execve_audit_len = MAX_EXECVE_AUDIT_LEN / 2;

	if (len > max_execve_audit_len)
		too_long = 1;

	/* walk the argument actually logging the message */
	for (i = 0; len_left > 0; i++) {
		int room_left;

		if (len_left > max_execve_audit_len)
			to_send = max_execve_audit_len;
		else
			to_send = len_left;

		/* do we have space left to send this argument in this ab? */
		room_left = MAX_EXECVE_AUDIT_LEN - arg_num_len - *len_sent;
		if (has_cntl)
			room_left -= (to_send * 2);
		else
			room_left -= to_send;
		if (room_left < 0) {
			*len_sent = 0;
			audit_log_end(*ab);
			*ab = audit_log_start(context, GFP_KERNEL, AUDIT_EXECVE);
			if (!*ab)
				return 0;
		}

		/*
		 * first record needs to say how long the original string was
		 * so we can be sure nothing was lost.
		 */
		if ((i == 0) && (too_long))
			audit_log_format(*ab, " a%d_len=%ld", arg_num,
					 has_cntl ? 2*len : len);

		/* actually log it */
		audit_log_format(*ab, " a%d", arg_num);
		if (too_long)
			audit_log_format(*ab, "[%d]", i);
		audit_log_format(*ab, "=");
		if (has_cntl)
			audit_log_hex(*ab, p, to_send);
		else
			audit_log_n_string(*ab, to_send, p);

		p += to_send;
		len_left -= to_send;
		*len_sent += arg_num_len;
		if (has_cntl)
			*len_sent += to_send * 2;
		else
			*len_sent += to_send;
	}
	return len;
}

static void audit_log_execve_info(struct audit_context *context,
				  struct audit_buffer **ab,
				  struct audit_aux_data_execve *axi)
{
	int i;
	size_t len, len_sent = 0;
	const char *p;

	p = axi->mem;

	audit_log_format(*ab, "argc=%d", axi->argc);

	for (i = 0; i < axi->argc; i++) {
		len = audit_log_single_execve_arg(context, ab, i, &len_sent, p);
		if (len <= 0)
			break;
		/* skip the null */
		p += len + 1;
	}
}

static void audit_log_exit(struct audit_context *context,
			   struct task_struct *tsk)
{
	int i;
	struct audit_buffer *ab;
	struct audit_aux_data *aux;
	struct audit_watch_info *winfo;
	struct hlist_node *pos;

	/* tsk == current */

	ab = audit_log_start(context, GFP_KERNEL, AUDIT_SYSCALL);
	if (!ab)
		return;		/* audit_panic has been called */
	audit_log_format(ab, "arch=%x syscall=%d",
			 context->arch, context->major);
	if (context->personality != PER_LINUX)
		audit_log_format(ab, " per=%lx", context->personality);
	if (context->return_valid)
		audit_log_format(ab, " success=%s exit=%ld", 
				 (context->return_valid==AUDITSC_SUCCESS)?"yes":"no",
				 context->return_code);
	audit_log_format(ab,
		  " a0=%lx a1=%lx a2=%lx a3=%lx items=%d"
		  " pid=%d auid=%u uid=%u gid=%u"
		  " euid=%u suid=%u fsuid=%u"
		  " egid=%u sgid=%u fsgid=%u",
		  context->argv[0],
		  context->argv[1],
		  context->argv[2],
		  context->argv[3],
		  context->name_count,
		  context->pid,
		  context->loginuid,
		  context->uid,
		  context->gid,
		  context->euid, context->suid, context->fsuid,
		  context->egid, context->sgid, context->fsgid);
	audit_log_task_info(ab, tsk);
	audit_log_end(ab);
	for (aux = context->aux; aux; aux = aux->next) {

		ab = audit_log_start(context, GFP_KERNEL, aux->type);
		if (!ab)
			continue; /* audit_panic has been called */

		switch (aux->type) {
		case AUDIT_IPC: {
			struct audit_aux_data_ipcctl *axi = (void *)aux;
			audit_log_format(ab, 
					 " qbytes=%lx iuid=%u igid=%u mode=%x",
					 axi->qbytes, axi->uid, axi->gid, axi->mode);
			break; }

		case AUDIT_EXECVE: {
			struct audit_aux_data_execve *axi = (void *)aux;
			audit_log_execve_info(context, &ab, axi);
			break; }

		case AUDIT_SOCKETCALL: {
			int i;
			struct audit_aux_data_socketcall *axs = (void *)aux;
			audit_log_format(ab, "nargs=%d", axs->nargs);
			for (i=0; i<axs->nargs; i++)
				audit_log_format(ab, " a%d=%lx", i, axs->args[i]);
			break; }

		case AUDIT_SOCKADDR: {
			struct audit_aux_data_sockaddr *axs = (void *)aux;

			audit_log_format(ab, "saddr=");
			audit_log_hex(ab, axs->a, axs->len);
			break; }

		case AUDIT_AVC_PATH: {
			struct audit_aux_data_path *axi = (void *)aux;
			audit_log_d_path(ab, "path=", axi->dentry, axi->mnt);
			break; }

		case AUDIT_FS_INODE: {
			struct audit_aux_data_watched *axi = (void *)aux;
			struct audit_buffer *sub_ab;
			audit_log_format(ab,
					 "inode=%lu inode_uid=%u inode_gid=%u"
					 " inode_dev=%02x:%02x inode_rdev=%02x:%02x",
					 axi->ino, axi->uid, axi->gid,
					 MAJOR(axi->dev), MINOR(axi->dev),
					 MAJOR(axi->rdev), MINOR(axi->rdev));
			hlist_for_each_entry(winfo, pos, &axi->watches, node) {
				sub_ab = audit_log_start(context, GFP_KERNEL, AUDIT_FS_WATCH);
				if (!sub_ab)
					return;		/* audit_panic has been called */
				audit_log_format(sub_ab, "watch_inode=%lu", axi->ino);
				audit_log_format(sub_ab, " watch=");
				audit_log_untrustedstring(sub_ab, winfo->watch->w_name);
				audit_log_format(sub_ab,
						 " filterkey=%s perm=%u perm_mask=%u",
						 winfo->watch->w_filterkey,
						 winfo->watch->w_perms, axi->mask);
				audit_log_end(sub_ab);
			}
			break; }
		}
		audit_log_end(ab);
	}

	if (context->pwd && context->pwdmnt) {
		ab = audit_log_start(context, GFP_KERNEL, AUDIT_CWD);
		if (ab) {
			audit_log_d_path(ab, "cwd=", context->pwd, context->pwdmnt);
			audit_log_end(ab);
		}
	}
	for (i = 0; i < context->name_count; i++) {
		ab = audit_log_start(context, GFP_KERNEL, AUDIT_PATH);
		if (!ab)
			continue; /* audit_panic has been called */

		if (context->names[i].name) {
			audit_log_format(ab, "name=");
			audit_log_untrustedstring(ab, context->names[i].name);
		}
		audit_log_format(ab, " flags=%x", context->names[i].flags);
			 
		if (context->names[i].ino != (unsigned long)-1)
			audit_log_format(ab, " inode=%lu dev=%02x:%02x mode=%#o"
					     " ouid=%u ogid=%u rdev=%02x:%02x",
					 context->names[i].ino,
					 MAJOR(context->names[i].dev),
					 MINOR(context->names[i].dev),
					 context->names[i].mode,
					 context->names[i].uid,
					 context->names[i].gid,
					 MAJOR(context->names[i].rdev),
					 MINOR(context->names[i].rdev));
		audit_log_end(ab);
	}
}

/* Free a per-task audit context.  Called from copy_process and
 * do_exit. */
void audit_free(struct task_struct *tsk)
{
	struct audit_context *context;

	context = audit_get_context(tsk, 0, 0);
	if (likely(!context))
		return;

	/* Check for system calls that do not go through the exit
	 * function (e.g., exit_group), then free context block. 
	 * We use GFP_ATOMIC here because we might be doing this 
	 * in the context of the idle thread */
	/* that can happen only if we are called from do_exit() */
	if (context->in_syscall && context->auditable)
		audit_log_exit(context, tsk);

	audit_free_context(context);
}

/* Fill in audit context at syscall entry.  This only happens if the
 * audit context was created when the task was created and the state or
 * filters demand the audit context be built.  If the state from the
 * per-task filter or from the per-syscall filter is AUDIT_RECORD_CONTEXT,
 * then the record will be written at syscall exit time (otherwise, it
 * will only be written if another part of the kernel requests that it
 * be written). */
void audit_syscall_entry(struct task_struct *tsk, int arch, int major,
			 unsigned long a1, unsigned long a2,
			 unsigned long a3, unsigned long a4)
{
	struct audit_context *context = tsk->audit_context;
	enum audit_state     state;

	BUG_ON(!context);

	/* This happens only on certain architectures that make system
	 * calls in kernel_thread via the entry.S interface, instead of
	 * with direct calls.  (If you are porting to a new
	 * architecture, hitting this condition can indicate that you
	 * got the _exit/_leave calls backward in entry.S.)
	 *
	 * i386     no
	 * x86_64   no
	 * ppc64    yes (see arch/ppc64/kernel/misc.S)
	 *
	 * This also happens with vm86 emulation in a non-nested manner
	 * (entries without exits), so this case must be caught.
	 */
	if (context->in_syscall) {
		struct audit_context *newctx;

#if defined(__NR_vm86) && defined(__NR_vm86old)
		/* vm86 mode should only be entered once */
		if (major == __NR_vm86 || major == __NR_vm86old)
			return;
#endif
#if AUDIT_DEBUG
		printk(KERN_ERR
		       "audit(:%d) pid=%d in syscall=%d;"
		       " entering syscall=%d\n",
		       context->serial, tsk->pid, context->major, major);
#endif
		newctx = audit_alloc_context(context->state);
		if (newctx) {
			newctx->previous   = context;
			context		   = newctx;
			tsk->audit_context = newctx;
		} else	{
			/* If we can't alloc a new context, the best we
			 * can do is to leak memory (any pending putname
			 * will be lost).  The only other alternative is
			 * to abandon auditing. */
			audit_zero_context(context, context->state);
		}
	}
	BUG_ON(context->in_syscall || context->name_count);

	if (!audit_enabled)
		return;

	context->arch	    = arch;
	context->major      = major;
	context->argv[0]    = a1;
	context->argv[1]    = a2;
	context->argv[2]    = a3;
	context->argv[3]    = a4;

	state = context->state;
	if (state == AUDIT_SETUP_CONTEXT || state == AUDIT_BUILD_CONTEXT)
		state = audit_filter_syscall(tsk, context, &audit_filter_list[AUDIT_FILTER_ENTRY]);
	if (likely(state == AUDIT_DISABLED))
		return;

	context->serial     = 0;
	context->ctime      = CURRENT_TIME;
	context->in_syscall = 1;
	context->auditable  = !!(state == AUDIT_RECORD_CONTEXT);
}

/* Tear down after system call.  If the audit context has been marked as
 * auditable (either because of the AUDIT_RECORD_CONTEXT state from
 * filtering, or because some other part of the kernel write an audit
 * message), then write out the syscall information.  In call cases,
 * free the names stored from getname(). */
void audit_syscall_exit(struct task_struct *tsk, int valid, long return_code)
{
	struct audit_context *context;

	/* tsk == current */

	get_task_struct(tsk);
	task_lock(tsk);
	context = audit_get_context(tsk, valid, return_code);
	task_unlock(tsk);

	/* Not having a context here is ok, since the parent may have
	 * called __put_task_struct. */
	if (likely(!context))
		goto out;

	if (context->in_syscall && context->auditable)
		audit_log_exit(context, tsk);

	context->in_syscall = 0;
	context->auditable  = 0;

	if (context->previous) {
		struct audit_context *new_context = context->previous;
		context->previous  = NULL;
		audit_free_context(context);
		tsk->audit_context = new_context;
	} else {
		audit_free_names(context);
		audit_free_aux(context);
		tsk->audit_context = context;
	}
 out:
	put_task_struct(tsk);
}

/* Add a name to the list.  Called from fs/namei.c:getname(). */
void audit_getname(const char *name)
{
	struct audit_context *context = current->audit_context;

	BUG_ON(!context);
	if (!context->in_syscall) {
#if AUDIT_DEBUG == 2
		printk(KERN_ERR "%s:%d(:%d): ignoring getname(%p)\n",
		       __FILE__, __LINE__, context->serial, name);
		dump_stack();
#endif
		return;
	}
	BUG_ON(context->name_count >= AUDIT_NAMES);
	context->names[context->name_count].name = name;
	context->names[context->name_count].ino  = (unsigned long)-1;
	++context->name_count;
	if (!context->pwd) {
		read_lock(&current->fs->lock);
		context->pwd = dget(current->fs->pwd);
		context->pwdmnt = mntget(current->fs->pwdmnt);
		read_unlock(&current->fs->lock);
	}
		
}

/* Intercept a putname request.  Called from
 * include/linux/fs.h:putname().  If we have stored the name from
 * getname in the audit context, then we delay the putname until syscall
 * exit. */
void audit_putname(const char *name)
{
	struct audit_context *context = current->audit_context;

	BUG_ON(!context);
	if (!context->in_syscall) {
#if AUDIT_DEBUG == 2
		printk(KERN_ERR "%s:%d(:%d): __putname(%p)\n",
		       __FILE__, __LINE__, context->serial, name);
		if (context->name_count) {
			int i;
			for (i = 0; i < context->name_count; i++)
				printk(KERN_ERR "name[%d] = %p = %s\n", i,
				       context->names[i].name,
				       context->names[i].name);
		}
#endif
		__putname(name);
	}
#if AUDIT_DEBUG
	else {
		++context->put_count;
		if (context->put_count > context->name_count) {
			printk(KERN_ERR "%s:%d(:%d): major=%d"
			       " in_syscall=%d putname(%p) name_count=%d"
			       " put_count=%d\n",
			       __FILE__, __LINE__,
			       context->serial, context->major,
			       context->in_syscall, name, context->name_count,
			       context->put_count);
			dump_stack();
		}
	}
#endif
}
EXPORT_SYMBOL(audit_putname);

/* Store the inode and device from a lookup.  Called from
 * fs/namei.c:path_lookup(). */
void audit_inode(const char *name, const struct inode *inode, unsigned flags)
{
	int idx;
	struct audit_context *context = current->audit_context;

	if (!context->in_syscall)
		return;
	if (context->name_count
	    && context->names[context->name_count-1].name
	    && context->names[context->name_count-1].name == name)
		idx = context->name_count - 1;
	else if (context->name_count > 1
		 && context->names[context->name_count-2].name
		 && context->names[context->name_count-2].name == name)
		idx = context->name_count - 2;
	else {
		/* FIXME: how much do we care about inodes that have no
		 * associated name? */
		if (context->name_count >= AUDIT_NAMES - AUDIT_NAMES_RESERVED)
			return;
		idx = context->name_count++;
		context->names[idx].name = NULL;
#if AUDIT_DEBUG
		++context->ino_count;
#endif
	}
	context->names[idx].flags = flags;
	context->names[idx].ino   = inode->i_ino;
	context->names[idx].dev	  = inode->i_sb->s_dev;
	context->names[idx].mode  = inode->i_mode;
	context->names[idx].uid   = inode->i_uid;
	context->names[idx].gid   = inode->i_gid;
	context->names[idx].rdev  = inode->i_rdev;
}

void auditsc_get_stamp(struct audit_context *ctx,
		       struct timespec *t, unsigned int *serial)
{
	if (!ctx->serial)
		ctx->serial = audit_serial();
	t->tv_sec  = ctx->ctime.tv_sec;
	t->tv_nsec = ctx->ctime.tv_nsec;
	*serial    = ctx->serial;
	ctx->auditable = 1;
}

int audit_set_loginuid(struct task_struct *task, uid_t loginuid)
{
	if (task->audit_context) {
		struct audit_buffer *ab;

		ab = audit_log_start(NULL, GFP_KERNEL, AUDIT_LOGIN);
		if (ab) {
			audit_log_format(ab, "login pid=%d uid=%u "
				"old auid=%u new auid=%u",
				task->pid, task->uid, 
				task->audit_context->loginuid, loginuid);
			audit_log_end(ab);
		}
		task->audit_context->loginuid = loginuid;
	}
	return 0;
}

uid_t audit_get_loginuid(struct audit_context *ctx)
{
	return ctx ? ctx->loginuid : -1;
}

int audit_ipc_perms(unsigned long qbytes, uid_t uid, gid_t gid, mode_t mode)
{
	struct audit_aux_data_ipcctl *ax;
	struct audit_context *context = current->audit_context;

	if (likely(!context))
		return 0;

	ax = kmalloc(sizeof(*ax), GFP_KERNEL);
	if (!ax)
		return -ENOMEM;

	ax->qbytes = qbytes;
	ax->uid = uid;
	ax->gid = gid;
	ax->mode = mode;

	ax->d.type = AUDIT_IPC;
	ax->d.next = context->aux;
	context->aux = (void *)ax;
	return 0;
}

int audit_bprm(struct linux_binprm *bprm)
{
	struct audit_aux_data_execve *ax;
	struct audit_context *context = current->audit_context;
	unsigned long p, next;
	void *to;

	if (likely(!audit_enabled || !context))
		return 0;

	ax = kmalloc(sizeof(*ax) + PAGE_SIZE * MAX_ARG_PAGES - bprm->p,
				GFP_KERNEL);
	if (!ax)
		return -ENOMEM;

	ax->argc = bprm->argc;
	ax->envc = bprm->envc;
	for (p = bprm->p, to = ax->mem; p < MAX_ARG_PAGES*PAGE_SIZE; p = next) {
		struct page *page = bprm->page[p / PAGE_SIZE];
		void *kaddr = kmap(page);
		next = (p + PAGE_SIZE) & ~(PAGE_SIZE - 1);
		memcpy(to, kaddr + (p & (PAGE_SIZE - 1)), next - p);
		to += next - p;
		kunmap(page);
	}

	ax->d.type = AUDIT_EXECVE;
	ax->d.next = context->aux;
	context->aux = (void *)ax;
	return 0;
}

int audit_socketcall(int nargs, unsigned long *args)
{
	struct audit_aux_data_socketcall *ax;
	struct audit_context *context = current->audit_context;

	if (likely(!context))
		return 0;

	ax = kmalloc(sizeof(*ax) + nargs * sizeof(unsigned long), GFP_KERNEL);
	if (!ax)
		return -ENOMEM;

	ax->nargs = nargs;
	memcpy(ax->args, args, nargs * sizeof(unsigned long));

	ax->d.type = AUDIT_SOCKETCALL;
	ax->d.next = context->aux;
	context->aux = (void *)ax;
	return 0;
}

int audit_sockaddr(int len, void *a)
{
	struct audit_aux_data_sockaddr *ax;
	struct audit_context *context = current->audit_context;

	if (likely(!context))
		return 0;

	ax = kmalloc(sizeof(*ax) + len, GFP_KERNEL);
	if (!ax)
		return -ENOMEM;

	ax->len = len;
	memcpy(ax->a, a, len);

	ax->d.type = AUDIT_SOCKADDR;
	ax->d.next = context->aux;
	context->aux = (void *)ax;
	return 0;
}

int audit_avc_path(struct dentry *dentry, struct vfsmount *mnt)
{
	struct audit_aux_data_path *ax;
	struct audit_context *context = current->audit_context;

	if (likely(!context))
		return 0;

	ax = kmalloc(sizeof(*ax), GFP_ATOMIC);
	if (!ax)
		return -ENOMEM;

	ax->dentry = dget(dentry);
	ax->mnt = mntget(mnt);

	ax->d.type = AUDIT_AVC_PATH;
	ax->d.next = context->aux;
	context->aux = (void *)ax;
	return 0;
}

void audit_signal_info(int sig, struct task_struct *t)
{
	extern pid_t audit_sig_pid;
	extern uid_t audit_sig_uid;

	if (unlikely(audit_pid && t->tgid == audit_pid)) {
		if (sig == SIGTERM || sig == SIGHUP) {
			struct audit_context *ctx = current->audit_context;
			audit_sig_pid = current->pid;
			if (ctx)
				audit_sig_uid = ctx->loginuid;
			else
				audit_sig_uid = current->uid;
		}
	}
}

#ifdef CONFIG_AUDITFILESYSTEM
extern spinlock_t auditfs_lock;

/* This has to be here instead of in auditfs.c, because it needs to
   see the audit context */
void auditfs_attach_wdata(struct inode *inode, struct hlist_head *watches,
			 int mask)
{
	struct audit_context *context = current->audit_context;
	struct audit_aux_data_watched *ax;
	struct audit_watch *watch;
	struct audit_watch_info *this, *winfo;
	struct hlist_node *pos, *tmp;

	if (!context)
		return;

	ax = kmalloc(sizeof(*ax), GFP_KERNEL);
	if (!ax)
		return;

	INIT_HLIST_HEAD(&ax->watches);

	spin_lock(&auditfs_lock);
	hlist_for_each_entry(watch, pos, watches, w_watched) {
	restart:
		audit_watch_get(watch);
 		if (mask && (watch->w_perms && !(watch->w_perms&mask))) {
			continue;
		}
		spin_unlock(&auditfs_lock);
		winfo = kmalloc(sizeof(struct audit_watch_info), GFP_KERNEL);
		if (!winfo)
			goto auditfs_attach_wdata_fail;
		winfo->watch = audit_watch_get(watch);
		hlist_add_head(&winfo->node, &ax->watches);
		spin_lock(&auditfs_lock);
		if (hlist_unhashed(&watch->w_watched)) {
			audit_watch_put(watch);
			/* Someone took it off the list while we didn't have it locked.
			   Go through the list of watches again until we find one which 
			   we haven't already dealt with... */
			hlist_for_each_entry(watch, pos, watches, w_watched) {
				hlist_for_each_entry(winfo, tmp, &ax->watches, node) {
					if (winfo->watch == watch)
						continue;
				}
				/* This watch wasn't found on ax's list, so
				   pick up where we left off. */
				goto restart;
			}
			/* We'd actually covered every watch that still exists */
			break;
		}
		audit_watch_put(watch);
	}
	spin_unlock(&auditfs_lock);

	if (hlist_empty(&ax->watches))
		goto no_watches;

	if (context->in_syscall && !context->auditable &&
		 AUDIT_DISABLED != audit_filter_syscall(current, context,
							&audit_filter_list[AUDIT_FILTER_WATCH]))
		context->auditable = 1;

	
	ax->mask = mask;
	ax->ino = inode->i_ino;
	ax->uid = inode->i_uid;
	ax->gid = inode->i_gid;
	ax->dev = inode->i_sb->s_dev;
	ax->rdev = inode->i_rdev;

	ax->link.type = AUDIT_FS_INODE;
	ax->link.next = context->aux;
	context->aux = (void *)ax;
	return;

auditfs_attach_wdata_fail:
	hlist_for_each_entry_safe(this, pos, tmp, &ax->watches, node) {
		hlist_del(&this->node);
		audit_watch_put(this->watch);
		kfree(this);
	}
	audit_panic("failed to allocate memory for fs watch record");
 no_watches:
	kfree(ax);
}

#endif /* CONFIG_AUDITFILESYSTEM */

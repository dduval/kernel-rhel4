/* auditfs.c -- Filesystem auditing support
 * Implements filesystem auditing support, depends on kernel/auditsc.c
 *
 * Copyright 2005 International Business Machines Corp. (IBM)
 * Copyright 2005 Red Hat, Inc.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 * Written by:		Timothy R. Chavez <chavezt@us.ibm.com>
 *			David Woodhouse <dwmw2@infradead.org>
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/slab.h>
#include <linux/audit.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <asm/uaccess.h>

#if 1
#define dprintk(...) do { } while(0)
#define __print_symbol(x, y) do { } while(0)
#else
#define dprintk(...) printk(KERN_DEBUG  __VA_ARGS__);
extern void __print_symbol(char *, void *);
#define inline
#endif

extern int audit_enabled;

static kmem_cache_t *audit_watch_cache;

static HLIST_HEAD(master_watchlist);
spinlock_t auditfs_lock = SPIN_LOCK_UNLOCKED;

struct audit_skb_list {
	struct hlist_node list;
	void *memblk;
	size_t size;
};

extern spinlock_t inode_lock;

static int audit_nr_watches;
static int audit_pool_size;
static struct audit_inode_data *audit_data_pool;
static struct audit_inode_data **auditfs_hash_table;
static spinlock_t auditfs_hash_lock = SPIN_LOCK_UNLOCKED;
static int auditfs_hash_bits;
static int auditfs_cache_buckets = 16384;
module_param(auditfs_cache_buckets, int, 0);
MODULE_PARM_DESC(auditfs_cache_buckets, "Number of auditfs cache entries to allocate (default 16384)\n");

static void audit_data_put(struct audit_inode_data *data);

static int audit_data_pool_grow(void)
{
	struct audit_inode_data *new;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	new->next_hash = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new->next_hash) {
		kfree(new);
		return -ENOMEM;
	}
		
	spin_lock(&auditfs_hash_lock);
	new->next_hash->next_hash = audit_data_pool;
	audit_data_pool = new;
	audit_nr_watches++;
	audit_pool_size += 2;
	spin_unlock(&auditfs_hash_lock);
	return 0;
}
static void audit_data_pool_shrink(void)
{
	spin_lock(&auditfs_hash_lock);
	audit_nr_watches--;

	while (audit_pool_size > audit_nr_watches + 1) {
		struct audit_inode_data *old = audit_data_pool;
		audit_data_pool = old->next_hash;
		audit_pool_size--;
		kfree(old);
	}
	spin_unlock(&auditfs_hash_lock);
}

static struct audit_inode_data *audit_data_get(struct inode *inode, int allocate)
{
	struct audit_inode_data **list;
	struct audit_inode_data *ret = NULL;
	int h;

	/* Short-circuit _without_ getting the lock. Even if i_state is being
	   modified, it won't affect the I_AUDIT bit, unless the I_AUDIT
	   bit itself is actually being changed -- which is fine. Either
	   we tested before or after the change; either is fine. */
	if (!allocate && !(inode->i_state & I_AUDIT))
		return NULL;

	spin_lock(&auditfs_hash_lock);

	/* If we think there are audit data attached, double-check that
	   now we have the lock */
	if (!allocate && !(inode->i_state & I_AUDIT))
		goto out;

	h = hash_ptr(inode, auditfs_hash_bits);
	list = &auditfs_hash_table[h];

	while (*list && (unsigned long)((*list)->inode) < (unsigned long)inode) {
		dprintk("list %p -> %p\n", list, *list);
		list = &(*list)->next_hash;
	}
	if (*list && (*list)->inode == inode)
		ret = *list;

	if (ret) {
		ret->count++;
	} else if (allocate) {
		ret = audit_data_pool;
		audit_data_pool = ret->next_hash;
		audit_pool_size--;
		dprintk("allocate from pool. %d left\n", audit_pool_size);

		INIT_HLIST_HEAD(&ret->watchlist);
		INIT_HLIST_HEAD(&ret->watches);
		ret->inode = inode;
		ret->next_hash = *list;
		ret->count = 2;
		*list = ret;

		spin_lock(&inode_lock);
		inode->i_state |= I_AUDIT;
		spin_unlock(&inode_lock);
	}
	if (ret) {
		dprintk("Got audit data %p for inode %p (%lu), count++ now %d. From %p: ", 
			ret, ret->inode, ret->inode->i_ino, ret->count, __builtin_return_address(0));
		__print_symbol("%s\n", __builtin_return_address(0));
	}
 out:
	spin_unlock(&auditfs_hash_lock);

	return ret;
}

/* Private Interface */

/* Caller should be holding auditfs_lock */
static inline struct audit_watch *audit_fetch_watch(const char *name,
						    struct audit_inode_data *data)
{
	struct audit_watch *watch, *ret = NULL;
	struct hlist_node *pos;

	hlist_for_each_entry(watch, pos, &data->watchlist, w_node)
		if (!strcmp(watch->w_name, name)) {
			ret = audit_watch_get(watch);
			break;
		}

	return ret;
}

static inline struct audit_watch *audit_fetch_watch_lock(const char *name,
							 struct audit_inode_data *data)
{
	struct audit_watch *ret = NULL;

	if (name && data) {
		spin_lock(&auditfs_lock);
		ret = audit_fetch_watch(name, data);
		spin_unlock(&auditfs_lock);
	}

	return ret;
}

static inline struct audit_watch *audit_watch_alloc(void)
{
	struct audit_watch *watch;

	watch = kmem_cache_alloc(audit_watch_cache, GFP_KERNEL);
	if (watch) {
		memset(watch, 0, sizeof(*watch));
		atomic_set(&watch->w_count, 1);
	}

	return watch;
}

static inline void audit_watch_free(struct audit_watch *watch)
{
	if (watch) {
		kfree(watch->w_name);
		kfree(watch->w_path);
		kfree(watch->w_filterkey);
		BUG_ON(!hlist_unhashed(&watch->w_node));
		BUG_ON(!hlist_unhashed(&watch->w_master));
		BUG_ON(!hlist_unhashed(&watch->w_watched));
		kmem_cache_free(audit_watch_cache, watch);
	}
}


/* Convert a watch_transport structure into a kernel audit_watch structure. */
static inline struct audit_watch *audit_to_watch(void *memblk)
{
	unsigned int offset;
	struct watch_transport *t;
	struct audit_watch *watch;

	watch = audit_watch_alloc();
	if (!watch)
		goto audit_to_watch_fail;

	t = memblk;

	watch->w_perms = t->perms;

	offset = sizeof(struct watch_transport);
	watch->w_filterkey = kmalloc(t->fklen+1, GFP_KERNEL);
	if (!watch->w_filterkey)
		goto audit_to_watch_fail;
	watch->w_filterkey[t->fklen] = 0;
	memcpy(watch->w_filterkey, memblk + offset, t->fklen);

	offset += t->fklen;
	watch->w_path = kmalloc(t->pathlen+1, GFP_KERNEL);
	if (!watch->w_path)
		goto audit_to_watch_fail;
	watch->w_path[t->pathlen] = 0;
	memcpy(watch->w_path, memblk + offset, t->pathlen);

	return watch;

audit_to_watch_fail:
	audit_watch_free(watch);
	return NULL;
}

/*
 * Convert a kernel audit_watch structure into a watch_transport structure.
 * We do this to send watch information back to user space.
 */
static inline void *audit_to_transport(struct audit_watch *watch, size_t size)
{
	struct watch_transport *t;
	char *p;

        t = kmalloc(size, GFP_KERNEL);
        if (!t)
                goto audit_to_transport_exit;

	memset(t, 0, sizeof(*t));

	t->dev_major = MAJOR(watch->w_dev);
	t->dev_minor = MINOR(watch->w_dev);
	t->perms = watch->w_perms;
	t->pathlen = strlen(watch->w_path) + 1;

	p = (char *)&t[1];

	if (watch->w_filterkey) {
		t->fklen = strlen(watch->w_filterkey) + 1;
		memcpy(p, watch->w_filterkey, t->fklen);
		p += t->fklen;
	}
	memcpy(p, watch->w_path, t->pathlen);

audit_to_transport_exit:
	return t;
}

static inline void audit_destroy_watch(struct audit_watch *watch)
{
	if (watch) {
		if (!hlist_unhashed(&watch->w_watched)) {
			hlist_del_init(&watch->w_watched);
			audit_watch_put(watch);
		}
	
		if (!hlist_unhashed(&watch->w_master)) {
			hlist_del_init(&watch->w_master);
			audit_watch_put(watch);
		}

		if (!hlist_unhashed(&watch->w_node)) {
			hlist_del_init(&watch->w_node);
			audit_watch_put(watch);
		}
	}
}

static inline void audit_drain_watchlist(struct audit_inode_data *data)
{
	struct audit_watch *watch;
	struct hlist_node *pos, *tmp;

	spin_lock(&auditfs_lock);
	hlist_for_each_entry_safe(watch, pos, tmp, &data->watchlist, w_node) {
		audit_destroy_watch(watch);
		audit_data_pool_shrink();
		audit_log(NULL, GFP_KERNEL, AUDIT_CONFIG_CHANGE, "auid=%u removed watch implicitly", -1);
	}
	spin_unlock(&auditfs_lock);
}

static void audit_data_unhash(struct audit_inode_data *data)
{
	int h = hash_ptr(data->inode, auditfs_hash_bits);
	struct audit_inode_data **list = &auditfs_hash_table[h];

	while (*list && (unsigned long)((*list)->inode) < (unsigned long)data->inode)
		list = &(*list)->next_hash;

	BUG_ON(*list != data);
	*list = data->next_hash;

	spin_lock(&inode_lock);
	data->inode->i_state &= ~I_AUDIT;
	spin_unlock(&inode_lock);
	data->inode = NULL;
}

static void audit_data_put(struct audit_inode_data *data)
{
	if (!data)
		return;

	spin_lock(&auditfs_hash_lock);
	data->count--;
	dprintk("Put audit_data %p for inode %p (%lu), count-- now %d. From %p:", data,
	       data->inode, data->inode?data->inode->i_ino:0, data->count, __builtin_return_address(0));
	__print_symbol("%s\n", __builtin_return_address(0));

	if (data->count == 1 && data->inode && 
	    hlist_empty(&data->watches) && hlist_empty(&data->watchlist)) {
		dprintk("Last put.\n");
		data->count--;
	}

	if (!data->count) {
		/* We are last user. Remove it from the hash table to
		   disassociate it from its inode */
		if (data->inode)
			audit_data_unhash(data);
		spin_unlock(&auditfs_hash_lock);

		audit_drain_watchlist(data);

		spin_lock(&auditfs_hash_lock);
		/* Check whether to free it or return it to the pool */
		if (audit_nr_watches > audit_pool_size) {
			dprintk("Back to pool. %d watches, %d in pool\n", audit_nr_watches, audit_pool_size);
			data->next_hash = audit_data_pool;
			audit_data_pool = data;
			audit_pool_size++;
		} else {
			dprintk("Freed. %d watches, %d in pool\n", audit_nr_watches, audit_pool_size);
			kfree(data);
		}
	}
	spin_unlock(&auditfs_hash_lock);
}

static inline int audit_insert_watch(struct audit_watch *watch, uid_t loginuid)
{
	int ret;
	struct nameidata nd;
	struct audit_inode_data *pdata;
	struct audit_watch *lookup;

	/* Grow the pool by two -- one for the watch itself, and
	   one for the parent directory */
	if (audit_data_pool_grow())
		return -ENOMEM;

	ret = path_lookup(watch->w_path, LOOKUP_PARENT, &nd);
	if (ret < 0)
		goto out;

	ret = -EPERM;
	if (nd.last_type != LAST_NORM || !nd.last.name)
		goto release;

	pdata = audit_data_get(nd.dentry->d_inode, 1);
	if (!pdata)
		goto put_pdata;

	ret = -EEXIST;
	lookup = audit_fetch_watch_lock(nd.last.name, pdata);
	if (lookup) {
		audit_watch_put(lookup);
		goto put_pdata;
	}

	ret = -ENOMEM;
	watch->w_name = kmalloc(strlen(nd.last.name)+1, GFP_KERNEL);
	if (!watch->w_name)
		goto put_pdata;
	strcpy(watch->w_name, nd.last.name);

	watch->w_dev = nd.dentry->d_inode->i_sb->s_dev;

	ret = 0;
	spin_lock(&auditfs_lock);
	hlist_add_head(&watch->w_node, &pdata->watchlist);
	audit_watch_get(watch);
	hlist_add_head(&watch->w_master, &master_watchlist);
	spin_unlock(&auditfs_lock);

	audit_log(NULL, GFP_KERNEL, AUDIT_CONFIG_CHANGE, "auid=%u inserted watch", loginuid);

	/* __d_lookup will attach the audit data, if nd.last exists. */
	dput(d_lookup(nd.dentry, &nd.last));

 put_pdata:
	audit_data_put(pdata);
 release:
	path_release(&nd);
 out:
	if (ret)
		audit_data_pool_shrink();

	return ret;
}

static inline int audit_remove_watch(struct audit_watch *watch, uid_t loginuid)
{
	int ret = 0;
	struct nameidata nd;
	struct audit_inode_data *data = NULL;
	struct audit_watch *real, *this;
	struct hlist_node *pos, *tmp;

	/* Let's try removing via the master watchlist first */
	spin_lock(&auditfs_lock);
	hlist_for_each_entry_safe(this, pos, tmp, &master_watchlist, w_master)
		if (!strcmp(this->w_path, watch->w_path)) {
			audit_destroy_watch(this);
			spin_unlock(&auditfs_lock);
			goto audit_remove_watch_exit;
		}
	spin_unlock(&auditfs_lock);

	ret = path_lookup(watch->w_path, LOOKUP_PARENT, &nd);
	if (ret < 0)
		goto audit_remove_watch_exit;

	ret = -ENOENT;
	if (nd.last_type != LAST_NORM || !nd.last.name)
		goto audit_remove_watch_release;

	data = audit_data_get(nd.dentry->d_inode, 0);
	if (!data)
		goto audit_remove_watch_release;

	spin_lock(&auditfs_lock);
	real = audit_fetch_watch(nd.last.name, data);
	if (!real) {
		spin_unlock(&auditfs_lock);
		goto audit_remove_watch_release;
	}
	ret = 0;
	audit_destroy_watch(real);
	spin_unlock(&auditfs_lock);
	audit_watch_put(real);

audit_remove_watch_release:
	path_release(&nd);
audit_remove_watch_exit:
	audit_data_put(data);
	if (!ret) {
		audit_log(NULL, GFP_KERNEL, AUDIT_CONFIG_CHANGE, "auid=%u removed watch", loginuid);
		audit_data_pool_shrink();
	}

	return ret;
}

struct audit_watch *audit_watch_get(struct audit_watch *watch)
{
	int new;

	if (watch) {
		new = atomic_inc_return(&watch->w_count);
		BUG_ON(new == 1);
		dprintk("Increase count on watch %p to %d\n",
		       watch, new);
	}

	return watch;
}

void audit_watch_put(struct audit_watch *watch)
{
	int new;

	if (watch) {
		new = atomic_dec_return(&watch->w_count);
		if (!new)
			audit_watch_free(watch);
		dprintk("Reduce count on watch %p to %d\n",
		       watch, new);
	}
}

/*
 * The update hook is responsible for watching and unwatching d_inodes during
 * their lifetimes in dcache.  Each d_inode being watched is pinned in memory.
 * As soon as a d_inode becomes unwatched (ie: dentry is destroyed, watch is
 * unhashed / removed from watchlist, dentry is moved out of watch path).
 *
 * Hook appears in fs/dcache.c:
 *	d_move(),
 * 	dentry_iput(),
 *	d_instantiate(),
 *	d_splice_alias()
 *	__d_lookup()
 */
void audit_update_watch(struct dentry *dentry, int remove)
{
	struct audit_watch *this, *watch;
	struct audit_inode_data *data, *parent;
	struct hlist_node *pos, *tmp;

	if (likely(!audit_enabled))
		return;

	if (!dentry || !dentry->d_inode)
		return;

	if (!dentry->d_parent || !dentry->d_parent->d_inode)
		return;

	/* If there's no audit data on the parent inode, then there can
	   be no watches to add or remove */
	parent = audit_data_get(dentry->d_parent->d_inode, 0);
	if (!parent)
		return;

	watch = audit_fetch_watch_lock(dentry->d_name.name, parent);

	/* Fetch audit data, using the preallocated one from the watch if
	   there is actually a relevant watch and the inode didn't already
	   have any audit data */
	data = audit_data_get(dentry->d_inode, !!watch);

	/* If there's no data, then there wasn't a watch either.
	   Nothing to see here; move along */
	if (!data)
		goto put_watch;

	spin_lock(&auditfs_lock);
	if (remove) {
		if (watch && !hlist_unhashed(&watch->w_watched)) {
			hlist_del_init(&watch->w_watched);
			audit_watch_put(watch);
		}
	} else {
		hlist_for_each_entry_safe(this, pos, tmp, &data->watches, w_watched)
			if (hlist_unhashed(&this->w_node)) {
				hlist_del_init(&this->w_watched);
				audit_watch_put(this);
			}
		if (watch && hlist_unhashed(&watch->w_watched)) {
			audit_watch_get(watch);
			hlist_add_head(&watch->w_watched, &data->watches);
		}
	}
	spin_unlock(&auditfs_lock);
	audit_data_put(data);

 put_watch:
	audit_watch_put(watch);
	audit_data_put(parent);
}

/* Convert a watch to a audit_skb_list */
struct audit_skb_list *audit_to_skb(struct audit_watch *watch)
{
	size_t size;
	void *memblk;
	struct audit_skb_list *entry;

	/* We must include space for both "\0" */
	size = sizeof(struct watch_transport) + strlen(watch->w_path) +
	       strlen(watch->w_filterkey) + 2;

	entry = ERR_PTR(-ENOMEM);
	memblk = audit_to_transport(watch, size);
	if (!memblk)
		goto audit_queue_watch_exit;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		entry = ERR_PTR(-ENOMEM);
		goto audit_queue_watch_exit;
	}

	entry->memblk = memblk;
	entry->size = size;

audit_queue_watch_exit:
	return entry;
}

/*
 * Read the "master watchlist" which is a watchlist of all watches in the
 * file system and send it to user space.  There will never be concurrent
 * readers of this list.
 *
 * The reference to watch will not be put back during a read upon a
 * watch removal, until after we're done reading.  So, the potential
 * for the rug being pulled out from under us is NIL.
 *
 * This list is only a "snapshot in time".  It is not gospel.
 */
static int audit_list_watches_fn(void *_dest)
{
	int ret;
	int pid, seq;
	struct hlist_head skb_list;
	struct hlist_node *tmp, *pos;
	struct audit_skb_list *entry;
	struct audit_watch *watch;
	int *dest = _dest;

	pid = dest[0];
	seq = dest[1];
	kfree(dest);

	down(&audit_netlink_sem);

 restart:
	INIT_HLIST_HEAD(&skb_list);
	spin_lock(&auditfs_lock);

	hlist_for_each_entry(watch, pos, &master_watchlist, w_master) {
		audit_watch_get(watch);
		spin_unlock(&auditfs_lock);
		entry = audit_to_skb(watch);
		if (IS_ERR(entry)) {
			ret = PTR_ERR(entry);
			audit_watch_put(watch);
			goto audit_list_watches_fail;
		}

		hlist_add_head(&entry->list, &skb_list);
		spin_lock(&auditfs_lock);
		if (hlist_unhashed(&watch->w_master)) {
			/* This watch was removed from the list while we 
			   pondered it. We could play tricks to find how far
			   we'd got, but we might as well just start again
			   from scratch. There's no real chance of livelock,
			   as the number of watches in the system has 
			   decreased, and the netlink sem prevents new watches
			   from being added while we're looping */
			audit_watch_put(watch);
			hlist_for_each_entry_safe(entry, pos, tmp, &skb_list, list) {
				hlist_del(&entry->list);
				kfree(entry->memblk);
				kfree(entry);
			}
			spin_unlock(&auditfs_lock);
			goto restart;
		}
		audit_watch_put(watch);
	}
	spin_unlock(&auditfs_lock);

	hlist_for_each_entry_safe(entry, pos, tmp, &skb_list, list) {
		audit_send_reply(pid, seq, AUDIT_WATCH_LIST, 0, 1, 
				 entry->memblk, entry->size);
		hlist_del(&entry->list);
		kfree(entry->memblk);
		kfree(entry);
	}
	audit_send_reply(pid, seq, AUDIT_WATCH_LIST, 1, 1, NULL, 0);
	
	up(&audit_netlink_sem);
	return 0;

audit_list_watches_fail:
	hlist_for_each_entry_safe(entry, pos, tmp, &skb_list, list) {
		hlist_del(&entry->list);
		kfree(entry->memblk);
		kfree(entry);
	}
	up(&audit_netlink_sem);
	return ret;
}

int audit_list_watches(int pid, int seq)
{
	struct task_struct *tsk;
	int *dest = kmalloc(2 * sizeof(int), GFP_KERNEL);
	if (!dest)
		return -ENOMEM;
	dest[0] = pid;
	dest[1] = seq;

	tsk = kthread_run(audit_list_watches_fn, dest, "audit_list_watches");
	if (IS_ERR(tsk)) {
		kfree(dest);
		return PTR_ERR(tsk);
	}
	return 0;
}

int audit_receive_watch(int type, int pid, int uid, int seq,
			struct watch_transport *req, uid_t loginuid)
{
	int ret = 0;
	struct audit_watch *watch = NULL;
	char *payload = (char *)&req[1];

	ret = -ENAMETOOLONG;
	if (req->pathlen >= PATH_MAX)
		goto audit_receive_watch_exit;

	if (req->fklen >= AUDIT_FILTERKEY_MAX)
		goto audit_receive_watch_exit;
	
	ret = -EINVAL;
	if (req->pathlen == 0)
		goto audit_receive_watch_exit;

	if (payload[req->fklen] != '/')
		goto audit_receive_watch_exit;

	if (req->perms > (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND))
		goto audit_receive_watch_exit;

	ret = -ENOMEM;
	watch = audit_to_watch(req);
	if (!watch)
		goto audit_receive_watch_exit;

	switch (type) {
	case AUDIT_WATCH_INS:
		ret = audit_insert_watch(watch, loginuid);
		break;
	case AUDIT_WATCH_REM:
		ret = audit_remove_watch(watch, loginuid);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret < 0 || type == AUDIT_WATCH_REM)
		audit_watch_put(watch);

audit_receive_watch_exit:
	return ret;
}

void audit_inode_free(struct inode *inode)
{
	struct audit_watch *watch;
	struct hlist_node *pos, *tmp;
	struct audit_inode_data *data = audit_data_get(inode, 0);

	if (data) {
		spin_lock(&auditfs_hash_lock);
		audit_data_unhash(data);
		spin_unlock(&auditfs_hash_lock);

		audit_drain_watchlist(data);
		/* Release all our references to any watches we may have on us */
		spin_lock(&auditfs_lock);
		hlist_for_each_entry_safe(watch, pos, tmp, &data->watches, w_watched) {
			hlist_del_init(&watch->w_watched);
                	audit_watch_put(watch);
        	}
		spin_unlock(&auditfs_lock);
		audit_data_put(data);
	}
}

int audit_filesystem_init(void)
{

	audit_watch_cache =
	    kmem_cache_create("audit_watch_cache",
			      sizeof(struct audit_watch), 0, 0, NULL, NULL);
	if (!audit_watch_cache)
		goto audit_filesystem_init_fail;

	/* Set up hash table for inode objects */
	auditfs_hash_bits = long_log2(auditfs_cache_buckets);
	if (auditfs_cache_buckets != (1 << auditfs_hash_bits)) {
		auditfs_hash_bits++;
		auditfs_cache_buckets = 1 << auditfs_hash_bits;
		printk(KERN_NOTICE
		       "%s: auditfs_cache_buckets set to %d (bits %d)\n",
		       __FUNCTION__, auditfs_cache_buckets, auditfs_hash_bits);
	}

	auditfs_hash_table = kmalloc(auditfs_cache_buckets * sizeof(void *), GFP_KERNEL);

	if (!auditfs_hash_table) {
		printk(KERN_NOTICE "No memory to initialize auditfs cache.\n");
		goto audit_filesystem_init_fail;
	}

	memset(auditfs_hash_table, 0, auditfs_cache_buckets * sizeof(void *));

	return 0;

audit_filesystem_init_fail:
	kmem_cache_destroy(audit_watch_cache);
	return -ENOMEM;
}


void audit_notify_watch(struct inode *inode, int mask)
{
	struct audit_inode_data *data;

	if (likely(!audit_enabled))
		return;

	if (!inode || !current->audit_context)
		return;

	data = audit_data_get(inode, 0);
	if (!data)
		return;

	if (hlist_empty(&data->watches))
		goto out;

	auditfs_attach_wdata(inode, &data->watches, mask);

out:
	audit_data_put(data);
}


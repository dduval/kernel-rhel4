#ifndef _LINUX_PROC_FS_H
#define _LINUX_PROC_FS_H

#include <linux/config.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

/*
 * The proc filesystem constants/structures
 */

/*
 * Offset of the first process in the /proc root directory..
 */
#define FIRST_PROCESS_ENTRY 256


/*
 * We always define these enumerators
 */

enum {
	PROC_ROOT_INO = 1,
};

#define PROC_SUPER_MAGIC 0x9fa0

/*
 * This is not completely implemented yet. The idea is to
 * create an in-memory tree (like the actual /proc filesystem
 * tree) of these proc_dir_entries, so that we can dynamically
 * add new files to /proc.
 *
 * The "next" pointer creates a linked list of one /proc directory,
 * while parent/subdir create the directory structure (every
 * /proc file has a parent, but "subdir" is NULL for all
 * non-directory entries).
 *
 * "get_info" is called at "read", while "owner" is used to protect module
 * from unloading while proc_dir_entry is in use
 */

typedef	int (read_proc_t)(char *page, char **start, off_t off,
			  int count, int *eof, void *data);
typedef	int (write_proc_t)(struct file *file, const char __user *buffer,
			   unsigned long count, void *data);
typedef int (get_info_t)(char *, char **, off_t, int);

struct proc_dir_entry {
	unsigned int low_ino;
	unsigned short namelen;
	const char *name;
	mode_t mode;
	nlink_t nlink;
	uid_t uid;
	gid_t gid;
	unsigned long size;
	struct inode_operations * proc_iops;
	struct file_operations * proc_fops;
	get_info_t *get_info;
	struct module *owner;
	struct proc_dir_entry *next, *parent, *subdir;
	void *data;
	read_proc_t *read_proc;
	write_proc_t *write_proc;
	atomic_t count;		/* use count */
	int deleted;		/* delete flag */
#ifndef __GENKSYMS__
	void *set;
#endif
};

struct kcore_list {
	struct kcore_list *next;
	unsigned long addr;
	size_t size;
};

#ifdef CONFIG_PROC_FS

extern struct proc_dir_entry proc_root;
extern struct proc_dir_entry *proc_root_fs;
extern struct proc_dir_entry *proc_net;
extern struct proc_dir_entry *proc_net_stat;
extern struct proc_dir_entry *proc_bus;
extern struct proc_dir_entry *proc_root_driver;
extern struct proc_dir_entry *proc_root_kcore;

extern spinlock_t proc_subdir_lock;

extern void proc_root_init(void);
extern void proc_misc_init(void);

struct mm_struct;

struct dentry *proc_pid_lookup(struct inode *dir, struct dentry * dentry, struct nameidata *);
struct dentry *proc_pid_unhash(struct task_struct *p);
void proc_pid_flush(struct dentry *proc_dentry);
int proc_pid_readdir(struct file * filp, void * dirent, filldir_t filldir);
unsigned long task_vsize(struct mm_struct *);
int task_statm(struct mm_struct *, int *, int *, int *, int *);
char *task_mem(struct mm_struct *, char *);

extern struct proc_dir_entry *create_proc_entry(const char *name, mode_t mode,
						struct proc_dir_entry *parent);
struct proc_dir_entry *proc_create(const char *name, mode_t mode,
				struct proc_dir_entry *parent,
				const struct file_operations *proc_fops);
extern void remove_proc_entry(const char *name, struct proc_dir_entry *parent);

extern struct vfsmount *proc_mnt;
extern int proc_fill_super(struct super_block *,void *,int);
extern struct inode *proc_get_inode(struct super_block *, unsigned int, struct proc_dir_entry *);

extern int proc_match(int, const char *,struct proc_dir_entry *);

/*
 * These are generic /proc routines that use the internal
 * "struct proc_dir_entry" tree to traverse the filesystem.
 *
 * The /proc root directory has extended versions to take care
 * of the /proc/<pid> subdirectories.
 */
extern int proc_readdir(struct file *, void *, filldir_t);
extern struct dentry *proc_lookup(struct inode *, struct dentry *, struct nameidata *);

extern struct file_operations proc_kcore_operations;
extern struct file_operations proc_kmsg_operations;
extern struct file_operations ppc_htab_operations;

extern struct mm_struct *mm_for_maps(struct task_struct *);
extern int __may_ptrace_attach(struct task_struct *task);

/*
 * proc_tty.c
 */
struct tty_driver;
extern void proc_tty_init(void);
extern void proc_tty_register_driver(struct tty_driver *driver);
extern void proc_tty_unregister_driver(struct tty_driver *driver);

/*
 * proc_devtree.c
 */
struct device_node;
extern void proc_device_tree_init(void);
#ifdef CONFIG_PROC_DEVICETREE
extern void proc_device_tree_add_node(struct device_node *, struct proc_dir_entry *);
#else /* !CONFIG_PROC_DEVICETREE */
static inline void proc_device_tree_add_node(struct device_node *np, struct proc_dir_entry *pde)
{
	return;
}
#endif /* CONFIG_PROC_DEVICETREE */

extern struct proc_dir_entry *proc_symlink(const char *,
		struct proc_dir_entry *, const char *);
extern struct proc_dir_entry *proc_mkdir(const char *,struct proc_dir_entry *);
extern struct proc_dir_entry *proc_mkdir_mode(const char *name, mode_t mode,
			struct proc_dir_entry *parent);

static inline struct proc_dir_entry *create_proc_read_entry(const char *name,
	mode_t mode, struct proc_dir_entry *base, 
	read_proc_t *read_proc, void * data)
{
	struct proc_dir_entry *res=create_proc_entry(name,mode,base);
	if (res) {
		res->read_proc=read_proc;
		res->data=data;
	}
	return res;
}
 
static inline struct proc_dir_entry *create_proc_info_entry(const char *name,
	mode_t mode, struct proc_dir_entry *base, get_info_t *get_info)
{
	struct proc_dir_entry *res=create_proc_entry(name,mode,base);
	if (res) res->get_info=get_info;
	return res;
}
 
static inline struct proc_dir_entry *proc_net_create(const char *name,
	mode_t mode, get_info_t *get_info)
{
	return create_proc_info_entry(name,mode,proc_net,get_info);
}

static inline struct proc_dir_entry *proc_net_create_owner(const char *name,
	mode_t mode, get_info_t *get_info, struct module *owner)
{
	struct proc_dir_entry *newf;
	mode_t temp_mode = ((mode & (~S_IRWXUGO)) | S_ISVTX);

	/*
	 * temp_mode removes any accesibility from the created proc
	 * file and acts as a lock, preventing file access until
	 * we finish setting up the proc_dir_entry structure
	 */
	newf = create_proc_info_entry(name, temp_mode, proc_net, get_info);
	if (newf) {
		newf->owner = owner;
		/*
		 * Once we have the module owner set, we can enable file access
		 */
		if ((mode & S_IALLUGO) == 0)
			mode |= S_IRUGO;
		newf->mode |= mode;
	}
	return newf;
}

static inline struct proc_dir_entry *proc_net_fops_create(const char *name,
	mode_t mode, struct file_operations *fops)
{
	struct proc_dir_entry *res = create_proc_entry(name, mode, proc_net);
	if (res)
		res->proc_fops = fops;
	return res;
}

static inline void proc_net_remove(const char *name)
{
	remove_proc_entry(name,proc_net);
}

#else

#define proc_root_driver NULL
#define proc_net NULL

#define proc_net_fops_create(name, mode, fops)  ({ (void)(mode), NULL; })
#define proc_net_create(name, mode, info)	({ (void)(mode), NULL; })
static inline void proc_net_remove(const char *name) {}

static inline struct dentry *proc_pid_unhash(struct task_struct *p) { return NULL; }
static inline void proc_pid_flush(struct dentry *proc_dentry) { }

static inline struct proc_dir_entry *create_proc_entry(const char *name,
	mode_t mode, struct proc_dir_entry *parent) { return NULL; }
static inline struct proc_dir_entry *proc_create(const char *name,
	mode_t mode, struct proc_dir_entry *parent,
	const struct file_operations *proc_fops)
{
	return NULL;
}
#define remove_proc_entry(name, parent) do {} while (0)

static inline struct proc_dir_entry *proc_symlink(const char *name,
		struct proc_dir_entry *parent,const char *dest) {return NULL;}
static inline struct proc_dir_entry *proc_mkdir(const char *name,
	struct proc_dir_entry *parent) {return NULL;}

static inline struct proc_dir_entry *create_proc_read_entry(const char *name,
	mode_t mode, struct proc_dir_entry *base, 
	read_proc_t *read_proc, void * data) { return NULL; }
static inline struct proc_dir_entry *create_proc_info_entry(const char *name,
	mode_t mode, struct proc_dir_entry *base, get_info_t *get_info)
	{ return NULL; }

struct tty_driver;
static inline void proc_tty_register_driver(struct tty_driver *driver) {};
static inline void proc_tty_unregister_driver(struct tty_driver *driver) {};

extern struct proc_dir_entry proc_root;

#endif /* CONFIG_PROC_FS */

#if !defined(CONFIG_PROC_FS)
static inline void kclist_add(struct kcore_list *new, void *addr, size_t size)
{
}
static inline struct kcore_list * kclist_del(void *addr)
{
	return NULL;
}
#else
extern void kclist_add(struct kcore_list *, void *, size_t);
extern struct kcore_list *kclist_del(void *);
#endif

struct proc_inode {
	struct task_struct *task;
	int type;
	union {
		int (*proc_get_link)(struct inode *, struct dentry **, struct vfsmount **);
		int (*proc_read)(struct task_struct *task, char *page);
	} op;
	struct proc_dir_entry *pde;
	struct inode vfs_inode;

	/*
	 * Number of module references we've taken in the lookup codepath. It's
	 * possible to do an open on a procfile and not get a reference if the
	 * open races with pde->owner being set. Fixing this to be race free
	 * will mean changing a lot of procfile create calls, so we settle here
	 * for just making sure that we don't do more module_put's than gets
	 * in the open/close codepath. The count uses negative values, with -1
	 * indicating that 0 module refs have been taken. This allows us to use
	 * an atomic counter and avoid locking for this.
	 */
	atomic_t mod_refs;
};

static inline struct proc_inode *PROC_I(const struct inode *inode)
{
	return container_of(inode, struct proc_inode, vfs_inode);
}

static inline struct proc_dir_entry *PDE(const struct inode *inode)
{
	return PROC_I(inode)->pde;
}

struct proc_maps_private {
	struct task_struct *task;
	struct vm_area_struct *tail_vma;
};

#endif /* _LINUX_PROC_FS_H */

/*
 *  linux/fs/bad_inode.c
 *
 *  Copyright (C) 1997, Stephen Tweedie
 *
 *  Provide stub functions for unreadable inodes
 *
 *  Fabian Frederick : August 2003 - All file operations assigned to EIO
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/smp_lock.h>
#include <linux/namei.h>

#include <asm/poll.h>


static loff_t bad_file_llseek(struct file *file, loff_t offset, int origin)
{
	return -EIO;
}

static ssize_t bad_file_read(struct file *filp, char __user *buf,
			size_t size, loff_t *ppos)
{
        return -EIO;
}

static ssize_t bad_file_write(struct file *filp, const char __user *buf,
			size_t siz, loff_t *ppos)
{
        return -EIO;
}

static ssize_t bad_file_aio_read(struct kiocb *iocb, char __user *buf,
			size_t count, loff_t pos)
{
	return -EIO;
}

static ssize_t bad_file_aio_write(struct kiocb *iocb, const char __user *buf,
			size_t count, loff_t pos)
{
	return -EIO;
}

static int bad_file_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	return -EIO;
}

static unsigned int bad_file_poll(struct file *filp, struct poll_table_struct *wait)
{
	return POLLERR;
}

static int bad_file_ioctl (struct inode *inode, struct file *filp,
			unsigned int cmd, unsigned long arg)
{
	return -EIO;
}

static int bad_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	return -EIO;
}

static int bad_file_open(struct inode *inode, struct file *filp)
{
	return -EIO;
}

static int bad_file_flush(struct file *file)
{
	return -EIO;
}

static int bad_file_release(struct inode *inode, struct file *filp)
{
	return -EIO;
}

static int bad_file_fsync(struct file *file, struct dentry *dentry,
			int datasync)
{
	return -EIO;
}

static int bad_file_aio_fsync(struct kiocb *iocb, int datasync)
{
	return -EIO;
}

static int bad_file_fasync(int fd, struct file *filp, int on)
{
	return -EIO;
}

static int bad_file_lock(struct file *file, int cmd, struct file_lock *fl)
{
	return -EIO;
}

static ssize_t bad_file_readv(struct file *filp, const struct iovec *iov,
			unsigned long nr_segs, loff_t *ppos)
{
	return -EIO;
}

static ssize_t bad_file_writev(struct file *filp, const struct iovec *iov,
			unsigned long nr_segs, loff_t *ppos)
{
	return -EIO;
}

static ssize_t bad_file_sendfile(struct file *in_file, loff_t *ppos,
			size_t count, read_actor_t actor, void *target)
{
	return -EIO;
}

static ssize_t bad_file_sendpage(struct file *file, struct page *page,
			int off, size_t len, loff_t *pos, int more)
{
	return -EIO;
}

static unsigned long bad_file_get_unmapped_area(struct file *file,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags)
{
	return -EIO;
}

static int bad_file_check_flags(int flags)
{
	return -EIO;
}

static int bad_file_dir_notify(struct file *file, unsigned long arg)
{
	return -EIO;
}

static int bad_file_flock(struct file *filp, int cmd, struct file_lock *fl)
{
	return -EIO;
}

static struct file_operations bad_file_ops =
{
	.llseek		= bad_file_llseek,
	.read		= bad_file_read,
	.aio_read	= bad_file_aio_read,
	.write		= bad_file_write,
	.aio_write	= bad_file_aio_write,
	.readdir	= bad_file_readdir,
	.poll		= bad_file_poll,
	.ioctl		= bad_file_ioctl,
	.mmap		= bad_file_mmap,
	.open		= bad_file_open,
	.flush		= bad_file_flush,
	.release	= bad_file_release,
	.fsync		= bad_file_fsync,
	.aio_fsync	= bad_file_aio_fsync,
	.fasync		= bad_file_fasync,
	.lock		= bad_file_lock,
	.readv		= bad_file_readv,
	.writev		= bad_file_writev,
	.sendfile	= bad_file_sendfile,
	.sendpage	= bad_file_sendpage,
	.get_unmapped_area = bad_file_get_unmapped_area,
	.check_flags	= bad_file_check_flags,
	.dir_notify	= bad_file_dir_notify,
	.flock		= bad_file_flock,
};

static int bad_inode_create (struct inode *dir, struct dentry *dentry,
		int mode, struct nameidata *nd)
{
	return -EIO;
}

static struct dentry *bad_inode_lookup(struct inode *dir,
			struct dentry *dentry, struct nameidata *nd)
{
	return ERR_PTR(-EIO);
}

static int bad_inode_link (struct dentry *old_dentry, struct inode *dir,
		struct dentry *dentry)
{
	return -EIO;
}

static int bad_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return -EIO;
}

static int bad_inode_symlink (struct inode *dir, struct dentry *dentry,
		const char *symname)
{
	return -EIO;
}

static int bad_inode_mkdir(struct inode *dir, struct dentry *dentry,
			int mode)
{
	return -EIO;
}

static int bad_inode_rmdir (struct inode *dir, struct dentry *dentry)
{
	return -EIO;
}

static int bad_inode_mknod (struct inode *dir, struct dentry *dentry,
			int mode, dev_t rdev)
{
	return -EIO;
}

static int bad_inode_rename (struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	return -EIO;
}

static int bad_inode_readlink(struct dentry *dentry, char __user *buffer,
		int buflen)
{
	return -EIO;
}

/*
 * The follow_link operation is special: it must behave as a no-op
 * so that a bad root inode can at least be unmounted. To do this
 * we must dput() the base and return the dentry with a dget().
 */
static int bad_inode_follow_link(struct dentry *dent, struct nameidata *nd)
{
	nd_set_link(nd, ERR_PTR(-EIO));
	return 0;
}

static int bad_inode_permission(struct inode *inode, int mask,
			struct nameidata *nd)
{
	return -EIO;
}

static int bad_inode_getattr(struct vfsmount *mnt, struct dentry *dentry,
			struct kstat *stat)
{
	return -EIO;
}

static int bad_inode_getattr64(struct vfsmount *mnt, struct dentry *dentry,
			struct kstat64 *stat)
{
	return -EIO;
}

static int bad_inode_setattr(struct dentry *direntry, struct iattr *attrs)
{
	return -EIO;
}

static int bad_inode_setxattr(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags)
{
	return -EIO;
}

static ssize_t bad_inode_getxattr(struct dentry *dentry, const char *name,
			void *buffer, size_t size)
{
	return -EIO;
}

static ssize_t bad_inode_listxattr(struct dentry *dentry, char *buffer,
			size_t buffer_size)
{
	return -EIO;
}

static int bad_inode_removexattr(struct dentry *dentry, const char *name)
{
	return -EIO;
}

static struct inode_operations_ext bad_inode_ops =
{
	.i_op_orig.create	= bad_inode_create,
	.i_op_orig.lookup	= bad_inode_lookup,
	.i_op_orig.link		= bad_inode_link,
	.i_op_orig.unlink	= bad_inode_unlink,
	.i_op_orig.symlink	= bad_inode_symlink,
	.i_op_orig.mkdir	= bad_inode_mkdir,
	.i_op_orig.rmdir	= bad_inode_rmdir,
	.i_op_orig.mknod	= bad_inode_mknod,
	.i_op_orig.rename	= bad_inode_rename,
	.i_op_orig.readlink	= bad_inode_readlink,
	.i_op_orig.follow_link	= bad_inode_follow_link,
	/* put_link returns void */
	/* truncate returns void */
	.i_op_orig.permission	= bad_inode_permission,
	.i_op_orig.getattr	= bad_inode_getattr,
	.i_op_orig.setattr	= bad_inode_setattr,
	.i_op_orig.setxattr	= bad_inode_setxattr,
	.i_op_orig.getxattr	= bad_inode_getxattr,
	.i_op_orig.listxattr	= bad_inode_listxattr,
	.i_op_orig.removexattr	= bad_inode_removexattr,
	.getattr64		= bad_inode_getattr64,
	/* lookup_undo returns void */
};


/*
 * When a filesystem is unable to read an inode due to an I/O error in
 * its read_inode() function, it can call make_bad_inode() to return a
 * set of stubs which will return EIO errors as required. 
 *
 * We only need to do limited initialisation: all other fields are
 * preinitialised to zero automatically.
 */
 
/**
 *	make_bad_inode - mark an inode bad due to an I/O error
 *	@inode: Inode to mark bad
 *
 *	When an inode cannot be read due to a media or remote network
 *	failure this function makes the inode "bad" and causes I/O operations
 *	on it to fail from this point on.
 */
 
void make_bad_inode(struct inode *inode)
{
	remove_inode_hash(inode);

	inode->i_mode = S_IFREG;
	inode->i_atime = inode->i_mtime = inode->i_ctime =
		current_fs_time(inode->i_sb);
	inode->i_op = (struct inode_operations *)&bad_inode_ops;
	inode->i_fop = &bad_file_ops;
}
EXPORT_SYMBOL(make_bad_inode);

/*
 * This tests whether an inode has been flagged as bad. The test uses
 * &bad_inode_ops to cover the case of invalidated inodes as well as
 * those created by make_bad_inode() above.
 */
 
/**
 *	is_bad_inode - is an inode errored
 *	@inode: inode to test
 *
 *	Returns true if the inode in question has been marked as bad.
 */
 
int is_bad_inode(struct inode *inode)
{
	return (inode->i_op == (struct inode_operations *)&bad_inode_ops);	
}

EXPORT_SYMBOL(is_bad_inode);

/**
 * iget_failed - Mark an under-construction inode as dead and release it
 * @inode: The inode to discard
 *
 * Mark an under-construction inode as dead and release it.
 */
void iget_failed(struct inode *inode)
{
	make_bad_inode(inode);
	unlock_new_inode(inode);
	iput(inode);
}
EXPORT_SYMBOL(iget_failed);

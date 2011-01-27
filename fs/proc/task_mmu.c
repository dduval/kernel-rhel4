#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <asm/elf.h>
#include <asm/uaccess.h>

char *task_mem(struct mm_struct *mm, char *buffer)
{
	unsigned long data, text, lib;

	data = mm->total_vm - mm->shared_vm - mm->stack_vm;
	text = (mm->end_code - mm->start_code) >> 10;
	lib = (mm->exec_vm << (PAGE_SHIFT-10)) - text;
	buffer += sprintf(buffer,
		"VmSize:\t%8lu kB\n"
		"VmLck:\t%8lu kB\n"
		"VmRSS:\t%8lu kB\n"
		"VmData:\t%8lu kB\n"
		"VmStk:\t%8lu kB\n"
		"VmExe:\t%8lu kB\n"
		"VmLib:\t%8lu kB\n"
		"StaBrk:\t%08lx kB\n"
		"Brk:\t%08lx kB\n"
		"StaStk:\t%08lx kB\n"
#if __i386__
		"ExecLim:\t%08lx\n"
#endif
		,
		(mm->total_vm - mm->reserved_vm) << (PAGE_SHIFT-10),
		mm->locked_vm << (PAGE_SHIFT-10),
		mm->rss << (PAGE_SHIFT-10),
		data << (PAGE_SHIFT-10),
		mm->stack_vm << (PAGE_SHIFT-10), text, lib, mm->start_brk, mm->brk, mm->start_stack
#if __i386__
		, mm->context.exec_limit
#endif
		);
	return buffer;
}

unsigned long task_vsize(struct mm_struct *mm)
{
	return PAGE_SIZE * mm->total_vm;
}

int task_statm(struct mm_struct *mm, int *shared, int *text,
	       int *data, int *resident)
{
	*shared = mm->rss - mm->anon_rss;
	*text = (mm->end_code - mm->start_code) >> PAGE_SHIFT;
	*data = mm->total_vm - mm->shared_vm;
	*resident = mm->rss;
	return mm->total_vm;
}

static int show_map(struct seq_file *m, void *v)
{
	struct vm_area_struct *map = v;
	struct file *file = map->vm_file;
	int flags = map->vm_flags;
	unsigned long ino = 0;
	dev_t dev = 0;
	int len;

	if (file) {
		struct inode *inode = map->vm_file->f_dentry->d_inode;
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
	}

	seq_printf(m, "%08lx-%08lx %c%c%c%c %08lx %02x:%02x %lu %n",
			map->vm_start,
			map->vm_end,
			flags & VM_READ ? 'r' : '-',
			flags & VM_WRITE ? 'w' : '-',
			(flags & VM_EXEC
#ifdef __i386__
				|| (!nx_enabled && map->vm_mm &&
				(map->vm_start < map->vm_mm->context.exec_limit))
#endif
			)
				? 'x' : '-',
			flags & VM_MAYSHARE ? 's' : 'p',
			map->vm_pgoff << PAGE_SHIFT,
			MAJOR(dev), MINOR(dev), ino, &len);

	if (map->vm_file) {
		len = 25 + sizeof(void*) * 6 - len;
		if (len < 1)
			len = 1;
		seq_printf(m, "%*c", len, ' ');
		seq_path(m, file->f_vfsmnt, file->f_dentry, "");
	}
	seq_putc(m, '\n');
	return 0;
}

static void *m_start(struct seq_file *m, loff_t *pos)
{
	struct proc_maps_private *priv = m->private;
	struct task_struct *task = priv->task;
	struct mm_struct *mm;
	struct vm_area_struct * map, *tail_vma = NULL;
	loff_t l = *pos;

	priv->tail_vma = NULL;

	mm = mm_for_maps(task);
	if (!mm)
		return NULL;

	priv->tail_vma = tail_vma = get_gate_vma(priv->task);

	map = NULL;
	if ((unsigned long)l < mm->map_count) {
		map = mm->mmap;
		while (l-- && map)
			map = map->vm_next;
		goto out;
	}

	if (l != mm->map_count)
		tail_vma = NULL;

out:
	if (map)
		return map;

	up_read(&mm->mmap_sem);
	mmput(mm);
	return tail_vma;
}

static void m_stop(struct seq_file *m, void *v)
{
	struct proc_maps_private *priv = m->private;
	struct vm_area_struct *map = v;

	if (map && map != priv->tail_vma) {
		struct mm_struct *mm = map->vm_mm;
		up_read(&mm->mmap_sem);
		mmput(mm);
	}
}

static void *m_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct proc_maps_private *priv = m->private;
	struct vm_area_struct *map = v;
	struct vm_area_struct *tail_vma = priv->tail_vma;

	(*pos)++;
	if (map && (map != tail_vma) && map->vm_next)
		return map->vm_next;
	m_stop(m, v);
	return (map != tail_vma)? tail_vma: NULL;
}

struct seq_operations proc_pid_maps_op = {
	.start	= m_start,
	.next	= m_next,
	.stop	= m_stop,
	.show	= show_map
};

struct mm_struct *mm_for_maps(struct task_struct *task)
{
	struct mm_struct *mm = get_task_mm(task);
	if (!mm)
		return NULL;
	down_read(&mm->mmap_sem);
	task_lock(task);
	if (task->mm != mm)
		goto out;
	if (task->mm != current->mm && !__may_ptrace_attach(task))
		goto out;
	task_unlock(task);
	return mm;
out:
	task_unlock(task);
	up_read(&mm->mmap_sem);
	mmput(mm);
	return NULL;
}


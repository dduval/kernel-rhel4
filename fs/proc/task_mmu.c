#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/pagemap.h>
#include <linux/mempolicy.h>
#include <linux/highmem.h>
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

struct mem_size_stats
{
	unsigned long resident;
	unsigned long shared_clean;
	unsigned long shared_dirty;
	unsigned long private_clean;
	unsigned long private_dirty;
};

static void smaps_pte_range(struct vm_area_struct *vma, pmd_t *pmd,
				unsigned long addr, unsigned long end,
				struct mem_size_stats *mss)
{
	pte_t *pte, ptent;
	unsigned long pfn;
	struct page *page;

	pte = pte_offset_map(pmd, addr);
	do {
		ptent = *pte;
		if (pte_none(ptent) || !pte_present(ptent))
			continue;

		mss->resident += PAGE_SIZE;
		pfn = pte_pfn(ptent);
		if (!pfn_valid(pfn))
			continue;

		page = pfn_to_page(pfn);
		if (page_count(page) >= 2) {
			if (pte_dirty(ptent))
				mss->shared_dirty += PAGE_SIZE;
			else
				mss->shared_clean += PAGE_SIZE;
		} else {
			if (pte_dirty(ptent))
				mss->private_dirty += PAGE_SIZE;
			else
				mss->private_clean += PAGE_SIZE;
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
	pte_unmap(pte - 1);
	cond_resched();
}

static inline void smaps_pmd_range(struct vm_area_struct *vma, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				struct mem_size_stats *mss)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pgd, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		smaps_pte_range(vma, pmd, addr, next, mss);
	} while (pmd++, addr = next, addr != end);
}

static inline void smaps_pgd_range(struct vm_area_struct *vma,
				unsigned long addr, unsigned long end,
				struct mem_size_stats *mss)
{
	pgd_t *pgd;
	unsigned long next;

	pgd = pgd_offset(vma->vm_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		smaps_pmd_range(vma, pgd, addr, next, mss);
	} while (pgd++, addr = next, addr != end);
}

static int show_smap(struct seq_file *m, void *v)
{
	struct vm_area_struct *vma = v;
	unsigned long vma_len = (vma->vm_end - vma->vm_start);
	struct mem_size_stats mss;

	memset(&mss, 0, sizeof mss);

	show_map(m, v);

	if (vma->vm_mm && !is_vm_hugetlb_page(vma))
		smaps_pgd_range(vma, vma->vm_start, vma->vm_end, &mss);

	seq_printf(m,
		   "Size:          %8lu kB\n"
		   "Rss:           %8lu kB\n"
		   "Shared_Clean:  %8lu kB\n"
		   "Shared_Dirty:  %8lu kB\n"
		   "Private_Clean: %8lu kB\n"
		   "Private_Dirty: %8lu kB\n",
		   vma_len >> 10,
		   mss.resident >> 10,
		   mss.shared_clean  >> 10,
		   mss.shared_dirty  >> 10,
		   mss.private_clean >> 10,
		   mss.private_dirty >> 10);
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

struct seq_operations proc_pid_smaps_op = {
	.start	= m_start,
	.next	= m_next,
	.stop	= m_stop,
	.show	= show_smap
};

#ifdef CONFIG_NUMA
struct numa_maps {
	unsigned long pages;
	unsigned long anon;
	unsigned long mapped;
	unsigned long mapcount_max;
	unsigned long node[MAX_NUMNODES];
};

/*
 * Calculate numa node maps for a vma
 */
static struct numa_maps *get_numa_maps(const struct vm_area_struct *vma)
{
	struct page *page;
	unsigned long vaddr;
	struct mm_struct *mm = vma->vm_mm;
	int i;
	struct numa_maps *md = kmalloc(sizeof(struct numa_maps), GFP_KERNEL);

	if (!md)
		return NULL;
	md->pages = 0;
	md->anon = 0;
	md->mapped = 0;
	md->mapcount_max = 0;
	for (i = 0; i < MAX_NUMNODES; i++)
		md->node[i] = 0;

	spin_lock(&mm->page_table_lock);
 	for (vaddr = vma->vm_start; vaddr < vma->vm_end; vaddr += PAGE_SIZE) {
		page = follow_page(mm, vaddr, 0);
		if (page) {
			int count = page_mapcount(page);

			if (count)
				md->mapped++;
			if (count > md->mapcount_max)
				md->mapcount_max = count;
			md->pages++;
			if (PageAnon(page))
				md->anon++;
			md->node[page_to_nid(page)]++;
		}
	}
	spin_unlock(&mm->page_table_lock);
	return md;
}

static int show_numa_map(struct seq_file *m, void *v)
{
	struct proc_maps_private *priv = m->private;
	struct task_struct *task = priv->task;
	struct vm_area_struct *vma = v;
	struct mempolicy *pol;
	struct numa_maps *md;
	struct zone **z;
	int n;
	int first;

	if (!vma->vm_mm)
		return 0;

	md = get_numa_maps(vma);
	if (!md)
		return 0;

	seq_printf(m, "%08lx", vma->vm_start);
	pol = get_vma_policy(task, vma, vma->vm_start);
	/* Print policy */
	switch (pol->policy) {
	case MPOL_PREFERRED:
		seq_printf(m, " prefer=%d", pol->v.preferred_node);
		break;
	case MPOL_BIND:
		seq_printf(m, " bind={");
		first = 1;
		for (z = pol->v.zonelist->zones; *z; z++) {

			if (!first)
				seq_putc(m, ',');
			else
				first = 0;
			seq_printf(m, "%d/%s", (*z)->zone_pgdat->node_id,
					(*z)->name);
		}
		seq_putc(m, '}');
		break;
	case MPOL_INTERLEAVE:
		seq_printf(m, " interleave={");
		first = 1;
		for (n = 0; n < MAX_NUMNODES; n++) {
			if (test_bit(n, pol->v.nodes)) {
				if (!first)
					seq_putc(m,',');
				else
					first = 0;
				seq_printf(m, "%d",n);
			}
		}
		seq_putc(m, '}');
		break;
	default:
		seq_printf(m," default");
		break;
	}
	seq_printf(m, " MaxRef=%lu Pages=%lu Mapped=%lu",
			md->mapcount_max, md->pages, md->mapped);
	if (md->anon)
		seq_printf(m," Anon=%lu",md->anon);

	for (n = 0; n < MAX_NUMNODES; n++) {
		if (md->node[n])
			seq_printf(m, " N%d=%lu", n, md->node[n]);
	}
	seq_putc(m, '\n');
	kfree(md);

	return 0;
}

struct seq_operations proc_pid_numa_maps_op = {
	.start	= m_start,
	.next	= m_next,
	.stop	= m_stop,
	.show	= show_numa_map
};
#endif

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


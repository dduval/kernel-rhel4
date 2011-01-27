/*
 * Task I/O accounting operations
 */
#ifndef __TASK_IO_ACCOUNTING_OPS_INCLUDED
#define __TASK_IO_ACCOUNTING_OPS_INCLUDED

#ifdef CONFIG_TASK_IO_ACCOUNTING
static inline void task_io_account_read(size_t bytes)
{
	task_aux(current)->ioac.read_bytes += bytes;
}

/*
 * We approximate number of blocks, because we account bytes only.
 * A 'block' is 512 bytes
 */
static inline unsigned long task_io_get_inblock(const struct task_struct *p)
{
	return task_aux(p)->ioac.read_bytes >> 9;
}

static inline void task_io_account_write(size_t bytes)
{
	task_aux(current)->ioac.write_bytes += bytes;
}

/*
 * We approximate number of blocks, because we account bytes only.
 * A 'block' is 512 bytes
 */
static inline unsigned long task_io_get_oublock(const struct task_struct *p)
{
	return task_aux(p)->ioac.write_bytes >> 9;
}

static inline void task_io_account_cancelled_write(size_t bytes)
{
	task_aux(current)->ioac.cancelled_write_bytes += bytes;
}

static inline void task_io_accounting_init(struct task_struct *tsk)
{
	memset(&task_aux(tsk)->ioac, 0, sizeof(task_aux(tsk)->ioac));
}

#else

static inline void task_io_account_read(size_t bytes)
{
}

static inline unsigned long task_io_get_inblock(const struct task_struct *p)
{
	return 0;
}

static inline void task_io_account_write(size_t bytes)
{
}

static inline unsigned long task_io_get_oublock(const struct task_struct *p)
{
	return 0;
}

static inline void task_io_account_cancelled_write(size_t bytes)
{
}

static inline void task_io_accounting_init(struct task_struct *tsk)
{
}

#endif		/* CONFIG_TASK_IO_ACCOUNTING */
#endif		/* __TASK_IO_ACCOUNTING_OPS_INCLUDED */

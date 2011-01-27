#include <linux/kernel.h>
#include <linux/lapic_status.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");

static int actual_cpus_read_proc(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	int i, len = 0;

	for (i = 0; i < actual_cpus; i++)
		len += sprintf(page+len, "%d 1 1\n", i);

	return len;
}

static int proc_actual_cpus_init(void)
{
	create_proc_read_entry("lapics", 0, NULL, actual_cpus_read_proc,
			       NULL);
	return 0;
}

static void proc_actual_cpus_exit(void)
{
	remove_proc_entry("lapics", NULL);
	return;
}

module_init(proc_actual_cpus_init);
module_exit(proc_actual_cpus_exit);

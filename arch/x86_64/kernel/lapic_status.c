#include <linux/kernel.h>
#include <linux/lapic_status.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");

static int proc_calc_metrics(char *page, char **start, off_t off,
			     int count, int *eof, int len)
{
	if (len <= off+count) *eof = 1;
	*start = page + off;
	len -= off;
	if (len>count) len = count;
	if (len<0) len = 0;
	return len;
}

static int mp_lapic_status_read_proc(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	int apicid, len;

	len = 0;
	for (apicid = 0; apicid < MAX_APICS; apicid++) {
		if (((mp_lapic_status_info[apicid].processor_id != -1) ||
		    (mp_lapic_status_info[apicid].status != 0)))
			len += sprintf(page+len, "%d %d %d\n", apicid,
				      mp_lapic_status_info[apicid].processor_id,
				       mp_lapic_status_info[apicid].status);
	}
	return proc_calc_metrics(page, start, off, count, eof, len);
}

static int lapic_status_init(void)
{
	create_proc_read_entry("lapics", 0, NULL, mp_lapic_status_read_proc,
			       NULL);
	return 0;
}

static void lapic_status_exit(void)
{
	remove_proc_entry("lapics", NULL);
	return;
}

module_init(lapic_status_init);
module_exit(lapic_status_exit);

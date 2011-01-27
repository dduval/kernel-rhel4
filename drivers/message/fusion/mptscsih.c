/*
 * Fusion dummy module.
 *
 * Sole purpose is to pull in the split drivers modules as a single 
 * modprobe which has the same name as the old fusion driver.
  *
  */

#include <linux/module.h>
#include "mptbase.h"

#define my_NAME		"Fusion MPT SCSI Host driver"
#define my_VERSION	MPT_LINUX_VERSION_COMMON
#define MYNAM		"mptscsih"

MODULE_AUTHOR(MODULEAUTHOR);
MODULE_DESCRIPTION(my_NAME);
MODULE_LICENSE("GPL");

extern int mptsas_dummy_symbol, mptspi_dummy_symbol;

static int
mptscsih_init(void)
{
	mptsas_dummy_symbol = 1;
	mptspi_dummy_symbol = 1;
	return 0;
}

static void
mptscsih_exit(void)
{
}

module_init(mptscsih_init);
module_exit(mptscsih_exit);

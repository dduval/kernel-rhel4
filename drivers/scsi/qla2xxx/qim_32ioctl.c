/******************************************************************************
 *                  QLOGIC LINUX SOFTWARE
 *
 * QLogic ISP2x00 device driver for Linux 2.6.x
 * Copyright (C) 2005 QLogic Corporation
 * (www.qlogic.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 ******************************************************************************/

#include <linux/config.h>

#if defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)

#include <linux/file.h>

#include "exioct.h"
#include "qlfoln.h"
#include "qla_dbg.h"


/* fs/ioctl.c */
extern asmlinkage long sys_ioctl(unsigned int fd, unsigned int cmd, void *);

extern int register_ioctl32_conversion(unsigned int cmd,
    int (*handler)(unsigned int, unsigned int, unsigned long, struct file *));
extern int unregister_ioctl32_conversion(unsigned int cmd);


int
qim2xxx_ioctl32(unsigned int fd, unsigned int cmd, unsigned long arg,
    struct file *pfile)
{
	return (sys_ioctl(fd, cmd, (void *)arg));
}

static int
apidev_reg_increasing_idx(uint16_t low_idx, uint16_t high_idx)
{
	int	err = 0;
	int	i;
	unsigned int cmd;

	for (i = low_idx; i <= high_idx; i++) {
		cmd = (unsigned int)QL_IOCTL_CMD(i);
		err = register_ioctl32_conversion(cmd, qim2xxx_ioctl32);
		if (err) {
			DEBUG9(printk(
			    "%s: error registering cmd %x. err=%d.\n",
			    __func__, cmd, err);)
			break;
		}
		DEBUG9(printk("%s: registered cmd %x.\n", __func__, cmd);)
	}

	return (err);
}

static int
apidev_unreg_increasing_idx(uint16_t low_idx, uint16_t high_idx)
{
	int	err = 0;
	int	i;
	unsigned int cmd;

	for (i = low_idx; i <= high_idx; i++) {
		cmd = (unsigned int)QL_IOCTL_CMD(i);
		err = unregister_ioctl32_conversion(cmd);
		if (err) {
			DEBUG9(printk(
			    "%s: error unregistering cmd %x. err=%d.\n",
			    __func__, cmd, err);)
			break;
		}
		DEBUG9(printk("%s: unregistered cmd %x.\n", __func__, cmd);)
	}

	return (err);
}

void
apidev_init_32ioctl_reg(void)
{
	int	err;

	DEBUG9(printk("%s: going to register ioctl32 cmds.\n", __func__);)

	/* regular external ioctl codes */
	err = apidev_reg_increasing_idx(EXT_DEF_LN_REG_CC_START_IDX,
	    EXT_DEF_LN_REG_CC_END_IDX);
	if (!err) {
		/* regular internal ioctl codes */
		err = apidev_reg_increasing_idx(EXT_DEF_LN_INT_CC_START_IDX,
		    EXT_DEF_LN_INT_CC_END_IDX);
	}
	if (!err) {
		/* additional codes */
		err = apidev_reg_increasing_idx(EXT_DEF_LN_ADD_CC_START_IDX,
		    EXT_DEF_LN_ADD_CC_END_IDX);
	}
	if (!err) {
		/* QL FO specific codes */
		err = apidev_reg_increasing_idx(FO_CC_START_IDX, FO_CC_END_IDX);
	}
	if (!err) {
		/* LN Drvr specific codes are defined in decreasing order */
		err = apidev_reg_increasing_idx(EXT_DEF_LN_SPC_CC_END_IDX,
		    EXT_DEF_LN_SPC_CC_START_IDX);
	}
}

void
apidev_cleanup_32ioctl_unreg(void)
{
	int	err;

	DEBUG9(printk("%s: going to unregister ioctl32 cmds.\n", __func__);)

	/* regular external ioctl codes */
	err = apidev_unreg_increasing_idx(EXT_DEF_LN_REG_CC_START_IDX,
	    EXT_DEF_LN_REG_CC_END_IDX);
	if (!err) {
		/* regular internal ioctl codes */
		err = apidev_unreg_increasing_idx(EXT_DEF_LN_INT_CC_START_IDX,
		    EXT_DEF_LN_INT_CC_END_IDX);
	}
	if (!err) {
		/* additional codes */
		err = apidev_unreg_increasing_idx(EXT_DEF_LN_ADD_CC_START_IDX,
		    EXT_DEF_LN_ADD_CC_END_IDX);
	}
	if (!err) {
		/* QL FO specific codes */
		err = apidev_unreg_increasing_idx(FO_CC_START_IDX,
		    FO_CC_END_IDX);
	}
	if (!err) {
		/* LN Drvr specific codes are defined in decreasing order */
		err = apidev_unreg_increasing_idx(EXT_DEF_LN_SPC_CC_END_IDX,
		    EXT_DEF_LN_SPC_CC_START_IDX);
	}
}

#endif

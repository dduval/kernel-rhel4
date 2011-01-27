#ifndef __QIM_IOCTL_H__
#define __QIM_IOCTL_H__

#include <linux/delay.h>
#include <asm/uaccess.h>

#include "qim_def.h"
#include "exioct.h"
#include "inioct.h"
#include "qim_sup.h"
#include "qim_mbx.h"

extern int
qim_get_ioctl_scrap_mem(struct qla_host_ioctl *, void **, uint32_t);

extern void
qim_free_ioctl_scrap_mem(struct qla_host_ioctl *);

extern void *
Q64BIT_TO_PTR(uint64_t, uint16_t);

extern void
qim_dump_buffer(uint8_t *, uint32_t); 

#endif /* ifndef __QIM_IOCTL_H__ */


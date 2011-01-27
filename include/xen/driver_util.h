
#ifndef __ASM_XEN_DRIVER_UTIL_H__
#define __ASM_XEN_DRIVER_UTIL_H__

#include <linux/config.h>
#include <linux/vmalloc.h>

/* Allocate/destroy a 'vmalloc' VM area. */
extern struct vm_struct *alloc_vm_area(unsigned long size);
extern void free_vm_area(struct vm_struct *area);

/* Lock an area so that PTEs are accessible in the current address space. */
extern void lock_vm_area(struct vm_struct *area);
extern void unlock_vm_area(struct vm_struct *area);

#if  LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9)
extern int add_hotplug_env_var(char **envp, int num_envp, int *cur_index,
			       char *buffer, int buffer_size, int *cur_len,
			       const char *format, ...);
#endif

#endif /* __ASM_XEN_DRIVER_UTIL_H__ */

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */

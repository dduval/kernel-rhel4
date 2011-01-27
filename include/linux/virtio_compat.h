#ifndef _LINUX_VIRTIO_COMPAT_H
#define _LINUX_VIRTIO_COMPAT_H

/* RHEL-4 virtio compatibility header */

typedef _Bool bool;
#define false 0
#define true 1

#define PCI_D0 0
#define PCI_D3hot 3

#define uninitialized_var(var) var

#endif /* _LINUX_VIRTIO_COMPAT_H */

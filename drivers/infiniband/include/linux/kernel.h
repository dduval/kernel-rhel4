#ifndef BACKPORT_KERNEL_H_2_6_19
#define BACKPORT_KERNEL_H_2_6_19

#include_next <linux/kernel.h>
#include <linux/log2.h>

#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define NIPQUAD_FMT "%u.%u.%u.%u"

#define uninitialized_var(x) (x) = (x)

#endif

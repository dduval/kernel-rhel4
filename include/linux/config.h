#ifndef _LINUX_CONFIG_H
#define _LINUX_CONFIG_H

#include <linux/autoconf.h>
#if !defined (__KERNEL__) && !defined(__KERNGLUE__)
#error including kernel header in userspace; use the glibc headers instead!
#endif
#endif

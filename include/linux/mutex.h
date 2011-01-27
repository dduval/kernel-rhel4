/*
 * Copyright (c) 2006 Cisco Systems.  All rights reserved.
 *
 * This file is released under the GPLv2.
 */

/* mutex compatibility for pre-2.6.16 kernels */

#ifndef __LINUX_MUTEX_H
#define __LINUX_MUTEX_H

#include <asm/semaphore.h>

#define mutex semaphore
#define DEFINE_MUTEX(foo) DECLARE_MUTEX(foo)
#define mutex_init(foo) init_MUTEX(foo)
#define mutex_lock(foo) down(foo)
#define mutex_lock_interruptible(foo) down_interruptible(foo)
/* this function follows the spin_trylock() convention, so        *
 * it is negated to the down_trylock() return values! Be careful  */
#define mutex_trylock(foo) !down_trylock(foo)
#define mutex_unlock(foo) up(foo)
#define mutex_destroy(foo) do { } while (0)

static inline int mutex_is_locked(struct semaphore *sema)
{
	/*
	 * On RHEL4, semaphore implementation is inside
	 * include/asm-<arch>/semaphore.h. So, each architecture has
	 * their own semaphore implementation.
	 * On  all architectures, the lock happens when sema->count is lower
	 * than one.
	 * On almost all architectures, count is defined as atomic_t.
	 * The only two exceptions are:
	 * 	parisc - it is defined as just "int"
	 *	sparc - it is defined as "atomic24_t
	 * as none of the above are supported on RHEL4, instead of patching
	 * all semaphore.h, plus mutex.h, let's just assume that count is
	 * atomic_t and provide an unique implementation for all supported
	 * architetures.
	 */

	return atomic_read(&sema->count) < 1;
}


#endif /* __LINUX_MUTEX_H */

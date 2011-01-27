/*
 * Copyright (c) 2006 Cisco Systems.  All rights reserved.
 *
 * This file is released under the GPLv2.
 */

/* XXX remove this compatibility hack when 2.6.16 is released */

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

#endif /* __LINUX_MUTEX_H */
#ifndef _ASM_GENERIC_CRASHDUMP_H_
#define _ASM_GENERIC_CRASHDUMP_H_

/*
 * linux/include/asm-generic/crashdump.h
 *
 * Copyright (c) 2003, 2004 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef __KERNEL__

#define platform_timestamp(x) do { (x) = 0; } while (0)  

#define platform_fix_regs() do { } while (0)
#define platform_init_stack(stackptr) do { } while (0)
#define platform_cleanup_stack(stackptr) do { } while (0)
#define platform_start_crashdump(stackptr,dumpfunc,regs) (0)

#undef ELF_CORE_COPY_REGS
#define ELF_CORE_COPY_REGS(x, y) do { struct pt_regs *z; z = (y); } while (0)

#define show_mem() do {} while (0)

#define show_state() do {} while (0)

#define show_regs(x) do { struct pt_regs *z; z = (x); } while (0)

#undef KM_CRASHDUMP
#define KM_CRASHDUMP 0

#endif /* __KERNEL__ */

#endif /* _ASM_GENERIC_CRASHDUMP_H */

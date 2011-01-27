#ifndef _ASM_I386_DISKDUMP_H
#define _ASM_I386_DISKDUMP_H

/*
 * linux/include/asm-i386/diskdump.h
 *
 * Copyright (c) 2004 FUJITSU LIMITED
 * Copyright (c) 2003 Red Hat, Inc. All rights reserved.
 */
/*
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
 *
 */

#ifdef __KERNEL__

#include <linux/elf.h>
#include <asm/crashdump.h>

const static int platform_supports_diskdump = 1;

struct disk_dump_sub_header {
	elf_gregset_t		elf_regs;
};

#define size_of_sub_header()	((sizeof(struct disk_dump_sub_header) + PAGE_SIZE - 1) / DUMP_BLOCK_SIZE)

#define write_sub_header() 						\
({									\
 	int ret;							\
									\
	ELF_CORE_COPY_REGS(dump_sub_header.elf_regs, (&myregs));	\
	clear_page(scratch);						\
	memcpy(scratch, &dump_sub_header, sizeof(dump_sub_header));	\
 									\
	if ((ret = write_blocks(dump_part, 2, scratch, 1)) >= 0)	\
		ret = 1; /* size of sub header in page */;		\
	ret;								\
})

#endif /* __KERNEL__ */

#endif /* _ASM_I386_DISKDUMP_H */

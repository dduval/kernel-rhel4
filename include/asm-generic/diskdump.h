#ifndef _ASM_GENERIC_DISKDUMP_H_
#define _ASM_GENERIC_DISKDUMP_H_

#include <asm-generic/crashdump.h>

const static int platform_supports_diskdump = 0;

struct disk_dump_sub_header {};

#define size_of_sub_header()	1
#define write_sub_header() 	1

#endif /* _ASM_GENERIC_DISKDUMP_H */

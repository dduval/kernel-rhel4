#ifndef _LAPIC_STATUS_H
#define _LAPIC_STATUS_H

#ifdef CONFIG_X86
#include <asm/mpspec.h>

struct _mp_lapic_status_info {
	int processor_id; /* -1 if unassigned */
	int status; /* 0 if disabled, 1 if enabled */
};

extern struct _mp_lapic_status_info mp_lapic_status_info[MAX_APICS];
#endif

#ifdef CONFIG_IA64
extern int actual_cpus;
#endif

#endif

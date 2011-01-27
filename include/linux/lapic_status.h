#ifndef _LAPIC_STATUS_H
#define _LAPIC_STATUS_H

#include <asm/mpspec.h>

#ifdef CONFIG_X86
struct _mp_lapic_status_info {
	int processor_id; /* -1 if unassigned */
	int status; /* 0 if disabled, 1 if enabled */
};

extern struct _mp_lapic_status_info mp_lapic_status_info[MAX_APICS];

#endif

#endif

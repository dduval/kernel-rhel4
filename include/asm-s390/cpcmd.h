/*
 *  arch/s390/kernel/cpcmd.h
 *
 *  S390 version
 *    Copyright (C) 1999 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *    Author(s): Martin Schwidefsky (schwidefsky@de.ibm.com),
 */

#ifndef __CPCMD__
#define __CPCMD__

extern void cpcmd(char *cmd, char *response, int rlen);

/*
 * This is a backport of the 2.6.13-rc1 version of cpcmd
 * The original version of cpcmd will stay during this kernel release
 * to keep the internal API consistent
 * cpcmd_new is the in-kernel interface for issuing CP commands
 *
 * cmd:		null-terminated command string, max 240 characters
 * response:	response buffer for VM's textual response
 * rlen:	size of the response buffer, cpcmd will not exceed this size
 *		but will cap the output, if its too large. Everything that
 *		did not fit into the buffer will be silently dropped
 * response_code: return pointer for VM's error code
 * return value: the size of the response. The caller can check if the buffer
 *		was large enough by comparing the return value and rlen
 * NOTE: the response buffer has to be below 2 GB
 */
extern int cpcmd_new(const char *cmd, char *response, int rlen, int *response_code);
#endif

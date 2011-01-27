/*
 *  arch/s390/kernel/cpcmd.c
 *
 *  S390 version
 *    Copyright (C) 1999,2000 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *    Author(s): Martin Schwidefsky (schwidefsky@de.ibm.com),
 */

#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/ebcdic.h>
#include <linux/spinlock.h>
#include <asm/cpcmd.h>
#include <asm/system.h>

static spinlock_t cpcmd_lock = SPIN_LOCK_UNLOCKED;
static char cpcmd_buf[241];

void cpcmd(char *cmd, char *response, int rlen)
{
        const int mask = 0x40000000L;
	unsigned long flags;
        int cmdlen;

	spin_lock_irqsave(&cpcmd_lock, flags);
        cmdlen = strlen(cmd);
        strcpy(cpcmd_buf, cmd);
        ASCEBC(cpcmd_buf, cmdlen);

        if (response != NULL && rlen > 0) {
#ifndef CONFIG_ARCH_S390X
                asm volatile ("LRA   2,0(%0)\n\t"
                              "LR    4,%1\n\t"
                              "O     4,%4\n\t"
                              "LRA   3,0(%2)\n\t"
                              "LR    5,%3\n\t"
                              ".long 0x83240008 # Diagnose 83\n\t"
                              : /* no output */
                              : "a" (cpcmd_buf), "d" (cmdlen),
                                "a" (response), "d" (rlen), "m" (mask)
                              : "2", "3", "4", "5" );
#else /* CONFIG_ARCH_S390X */
                asm volatile ("   lrag  2,0(%0)\n"
                              "   lgr   4,%1\n"
                              "   o     4,%4\n"
                              "   lrag  3,0(%2)\n"
                              "   lgr   5,%3\n"
                              "   sam31\n"
                              "   .long 0x83240008 # Diagnose 83\n"
                              "   sam64"
                              : /* no output */
                              : "a" (cpcmd_buf), "d" (cmdlen),
                                "a" (response), "d" (rlen), "m" (mask)
                              : "2", "3", "4", "5" );
#endif /* CONFIG_ARCH_S390X */
                EBCASC(response, rlen);
        } else {
#ifndef CONFIG_ARCH_S390X
                asm volatile ("LRA   2,0(%0)\n\t"
                              "LR    3,%1\n\t"
                              ".long 0x83230008 # Diagnose 83\n\t"
                              : /* no output */
                              : "a" (cpcmd_buf), "d" (cmdlen)
                              : "2", "3"  );
#else /* CONFIG_ARCH_S390X */
                asm volatile ("   lrag  2,0(%0)\n"
                              "   lgr   3,%1\n"
                              "   sam31\n"
                              "   .long 0x83230008 # Diagnose 83\n"
                              "   sam64"
                              : /* no output */
                              : "a" (cpcmd_buf), "d" (cmdlen)
                              : "2", "3"  );
#endif /* CONFIG_ARCH_S390X */
        }
	spin_unlock_irqrestore(&cpcmd_lock, flags);
}

/*
 * This function is a backport of the cpcmd version from 2.6.13-rc1
 * The original version of cpcmd is left as is, to keep the kernel internal
 * API consistent during the lifetime of a kernel release
 * the caller of cpcmd_new has to ensure that the response buffer is below 2 GB
 */
int  cpcmd_new(const char *cmd, char *response, int rlen, int *response_code)
{
	const int mask = 0x40000000L;
	unsigned long flags;
	int return_code;
	int return_len;
	int cmdlen;

	spin_lock_irqsave(&cpcmd_lock, flags);
	cmdlen = strlen(cmd);
	BUG_ON(cmdlen > 240);
	memcpy(cpcmd_buf, cmd, cmdlen);
	ASCEBC(cpcmd_buf, cmdlen);

	if (response != NULL && rlen > 0) {
		memset(response, 0, rlen);
#ifndef CONFIG_ARCH_S390X
		asm volatile (	"lra	2,0(%2)\n"
				"lr	4,%3\n"
				"o	4,%6\n"
				"lra	3,0(%4)\n"
				"lr	5,%5\n"
				"diag	2,4,0x8\n"
				"brc	8, .Litfits\n"
				"ar	5, %5\n"
				".Litfits: \n"
				"lr	%0,4\n"
				"lr	%1,5\n"
				: "=d" (return_code), "=d" (return_len)
				: "a" (cpcmd_buf), "d" (cmdlen),
				"a" (response), "d" (rlen), "m" (mask)
				: "cc", "2", "3", "4", "5" );
#else /* CONFIG_ARCH_S390X */
                asm volatile (	"lrag	2,0(%2)\n"
				"lgr	4,%3\n"
				"o	4,%6\n"
				"lrag	3,0(%4)\n"
				"lgr	5,%5\n"
				"sam31\n"
				"diag	2,4,0x8\n"
				"sam64\n"
				"brc	8, .Litfits\n"
				"agr	5, %5\n"
				".Litfits: \n"
				"lgr	%0,4\n"
				"lgr	%1,5\n"
				: "=d" (return_code), "=d" (return_len)
				: "a" (cpcmd_buf), "d" (cmdlen),
				"a" (response), "d" (rlen), "m" (mask)
				: "cc", "2", "3", "4", "5" );
#endif /* CONFIG_ARCH_S390X */
                EBCASC(response, rlen);
        } else {
		return_len = 0;
#ifndef CONFIG_ARCH_S390X
                asm volatile (	"lra	2,0(%1)\n"
				"lr	3,%2\n"
				"diag	2,3,0x8\n"
				"lr	%0,3\n"
				: "=d" (return_code)
				: "a" (cpcmd_buf), "d" (cmdlen)
				: "2", "3"  );
#else /* CONFIG_ARCH_S390X */
                asm volatile (	"lrag	2,0(%1)\n"
				"lgr	3,%2\n"
				"sam31\n"
				"diag	2,3,0x8\n"
				"sam64\n"
				"lgr	%0,3\n"
				: "=d" (return_code)
				: "a" (cpcmd_buf), "d" (cmdlen)
				: "2", "3" );
#endif /* CONFIG_ARCH_S390X */
        }
	spin_unlock_irqrestore(&cpcmd_lock, flags);
	if (response_code != NULL)
		*response_code = return_code;
	return return_len;
}

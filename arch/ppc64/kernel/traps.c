/*
 *  linux/arch/ppc64/kernel/traps.c
 *
 *  Copyright (C) 1995-1996  Gary Thomas (gdt@linuxppc.org)
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 *  Modified by Cort Dougan (cort@cs.nmt.edu)
 *  and Paul Mackerras (paulus@cs.anu.edu.au)
 */

/*
 * This file handles the architecture-dependent parts of hardware exceptions
 */

#include <linux/config.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/user.h>
#include <linux/a.out.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/prctl.h>
#include <asm/kdebug.h>

#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/ppcdebug.h>
#include <asm/rtas.h>

#ifdef CONFIG_PPC_PSERIES
/* This is true if we are using the firmware NMI handler (typically LPAR) */
extern int fwnmi_active;
#endif

#ifdef CONFIG_DEBUGGER
int (*__debugger)(struct pt_regs *regs);
int (*__debugger_ipi)(struct pt_regs *regs);
int (*__debugger_bpt)(struct pt_regs *regs);
int (*__debugger_sstep)(struct pt_regs *regs);
int (*__debugger_iabr_match)(struct pt_regs *regs);
int (*__debugger_dabr_match)(struct pt_regs *regs);
int (*__debugger_fault_handler)(struct pt_regs *regs);

EXPORT_SYMBOL(__debugger);
EXPORT_SYMBOL(__debugger_ipi);
EXPORT_SYMBOL(__debugger_bpt);
EXPORT_SYMBOL(__debugger_sstep);
EXPORT_SYMBOL(__debugger_iabr_match);
EXPORT_SYMBOL(__debugger_dabr_match);
EXPORT_SYMBOL(__debugger_fault_handler);
#endif

struct notifier_block *ppc64_die_chain;
static spinlock_t die_notifier_lock = SPIN_LOCK_UNLOCKED;

int register_die_notifier(struct notifier_block *nb)
{
	int err = 0;
	unsigned long flags;

	spin_lock_irqsave(&die_notifier_lock, flags);
	err = notifier_chain_register(&ppc64_die_chain, nb);
	spin_unlock_irqrestore(&die_notifier_lock, flags);
	return err;
}

/*
 * Trap & Exception support
 */

static spinlock_t die_lock = SPIN_LOCK_UNLOCKED;

int die(const char *str, struct pt_regs *regs, long err)
{
	static int die_counter;
	int nl = 0;

	if (debugger(regs))
		return 1;

	console_verbose();
	spin_lock_irq(&die_lock);
	bust_spinlocks(1);
	printk("Oops: %s, sig: %ld [#%d]\n", str, err, ++die_counter);
#ifdef CONFIG_PREEMPT
	printk("PREEMPT ");
	nl = 1;
#endif
#ifdef CONFIG_SMP
	printk("SMP NR_CPUS=%d ", NR_CPUS);
	nl = 1;
#endif
#ifdef CONFIG_DEBUG_PAGEALLOC
	printk("DEBUG_PAGEALLOC ");
	nl = 1;
#endif
#ifdef CONFIG_NUMA
	printk("NUMA ");
	nl = 1;
#endif
	switch(systemcfg->platform) {
		case PLATFORM_PSERIES:
			printk("PSERIES ");
			nl = 1;
			break;
		case PLATFORM_PSERIES_LPAR:
			printk("PSERIES LPAR ");
			nl = 1;
			break;
		case PLATFORM_ISERIES_LPAR:
			printk("ISERIES LPAR ");
			nl = 1;
			break;
		case PLATFORM_POWERMAC:
			printk("POWERMAC ");
			nl = 1;
			break;
	}
	if (nl)
		printk("\n");
	show_regs(regs);
	try_crashdump(regs);
	bust_spinlocks(0);
	spin_unlock_irq(&die_lock);

	if (in_interrupt())
		panic("Fatal exception in interrupt");

	if (panic_on_oops) {
		if (netdump_func)
			netdump_func = NULL;
		printk(KERN_EMERG "Fatal exception: panic in 5 seconds\n");
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(5 * HZ);
		panic("Fatal exception");
	}
	do_exit(SIGSEGV);

	return 0;
}

static void
_exception(int signr, struct pt_regs *regs, int code, unsigned long addr)
{
	siginfo_t info;

	if (!user_mode(regs)) {
		if (die("Exception in kernel mode", regs, signr))
			return;
	}

	memset(&info, 0, sizeof(info));
	info.si_signo = signr;
	info.si_code = code;
	info.si_addr = (void __user *) addr;
	force_sig_info(signr, &info, current);
}

#ifdef CONFIG_PPC_PSERIES
/* Get the error information for errors coming through the
 * FWNMI vectors.  The pt_regs' r3 will be updated to reflect
 * the actual r3 if possible, and a ptr to the error log entry
 * will be returned if found.
 */
static struct rtas_error_log *FWNMI_get_errinfo(struct pt_regs *regs)
{
	unsigned long errdata = regs->gpr[3];
	struct rtas_error_log *errhdr = NULL;
	unsigned long *savep;

	if ((errdata >= 0x7000 && errdata < 0x7fff0) ||
	    (errdata >= rtas.base && errdata < rtas.base + rtas.size - 16)) {
		savep = __va(errdata);
		regs->gpr[3] = savep[0];	/* restore original r3 */
		errhdr = (struct rtas_error_log *)(savep + 1);
	} else {
		printk("FWNMI: corrupt r3\n");
	}
	return errhdr;
}

/* Call this when done with the data returned by FWNMI_get_errinfo.
 * It will release the saved data area for other CPUs in the
 * partition to receive FWNMI errors.
 */
static void FWNMI_release_errinfo(void)
{
	int ret = rtas_call(rtas_token("ibm,nmi-interlock"), 0, 1, NULL);
	if (ret != 0)
		printk("FWNMI: nmi-interlock failed: %d\n", ret);
}
#endif

void
SystemResetException(struct pt_regs *regs)
{
#ifdef CONFIG_PPC_PSERIES
	if (fwnmi_active) {
		struct rtas_error_log *errhdr = FWNMI_get_errinfo(regs);
		if (errhdr) {
			/* XXX Should look at FWNMI information */
		}
		FWNMI_release_errinfo();
	}
#endif

	die("System Reset", regs, 0);

	/* Must die if the interrupt is not recoverable */
	if (!(regs->msr & MSR_RI))
		panic("Unrecoverable System Reset");

	/* What should we do here? We could issue a shutdown or hard reset. */
}

#ifdef CONFIG_PPC_PSERIES
/* 
 * See if we can recover from a machine check exception.
 * This is only called on power4 (or above) and only via
 * the Firmware Non-Maskable Interrupts (fwnmi) handler
 * which provides the error analysis for us.
 *
 * Return 1 if corrected (or delivered a signal).
 * Return 0 if there is nothing we can do.
 */
static int recover_mce(struct pt_regs *regs, struct rtas_error_log err)
{
	if (err.disposition == RTAS_DISP_FULLY_RECOVERED) {
		/* Platform corrected itself */
		return 1;
	} else if ((regs->msr & MSR_RI) &&
		   user_mode(regs) &&
		   err.severity == RTAS_SEVERITY_ERROR_SYNC &&
		   err.disposition == RTAS_DISP_NOT_RECOVERED &&
		   err.target == RTAS_TARGET_MEMORY &&
		   err.type == RTAS_TYPE_ECC_UNCORR &&
		   !(current->pid == 0 || current->pid == 1)) {
		/* Kill off a user process with an ECC error */
		printk(KERN_ERR "MCE: uncorrectable ecc error for pid %d\n",
		       current->pid);
		/* XXX something better for ECC error? */
		_exception(SIGBUS, regs, BUS_ADRERR, regs->nip);
		return 1;
	}
	return 0;
}
#endif

/*
 * Handle a machine check.
 *
 * Note that on Power 4 and beyond Firmware Non-Maskable Interrupts (fwnmi)
 * should be present.  If so the handler which called us tells us if the
 * error was recovered (never true if RI=0).
 *
 * On hardware prior to Power 4 these exceptions were asynchronous which
 * means we can't tell exactly where it occurred and so we can't recover.
 */
void
MachineCheckException(struct pt_regs *regs)
{
#ifdef CONFIG_PPC_PSERIES
	struct rtas_error_log err, *errp;

	if (fwnmi_active) {
		errp = FWNMI_get_errinfo(regs);
		if (errp)
			err = *errp;
		FWNMI_release_errinfo();	/* frees errp */
		if (errp && recover_mce(regs, err))
			return;
	}
#endif

	if (debugger_fault_handler(regs))
		return;
	die("Machine check", regs, 0);

	/* Must die if the interrupt is not recoverable */
	if (!(regs->msr & MSR_RI))
		panic("Unrecoverable Machine check");
}

void
UnknownException(struct pt_regs *regs)
{
	printk("Bad trap at PC: %lx, SR: %lx, vector=%lx\n",
	       regs->nip, regs->msr, regs->trap);

	_exception(SIGTRAP, regs, 0, 0);
}

void
InstructionBreakpointException(struct pt_regs *regs)
{
	if (notify_die(DIE_IABR_MATCH, "iabr_match", regs, 5,
					5, SIGTRAP) == NOTIFY_STOP)
		return;
	if (debugger_iabr_match(regs))
		return;
	_exception(SIGTRAP, regs, TRAP_BRKPT, regs->nip);
}

void
SingleStepException(struct pt_regs *regs)
{
	regs->msr &= ~MSR_SE;  /* Turn off 'trace' bit */

	if (notify_die(DIE_SSTEP, "single_step", regs, 5,
					5, SIGTRAP) == NOTIFY_STOP)
		return;
	if (debugger_sstep(regs))
		return;

	_exception(SIGTRAP, regs, TRAP_TRACE, regs->nip);
}

/*
 * After we have successfully emulated an instruction, we have to
 * check if the instruction was being single-stepped, and if so,
 * pretend we got a single-step exception.  This was pointed out
 * by Kumar Gala.  -- paulus
 */
static inline void emulate_single_step(struct pt_regs *regs)
{
	if (regs->msr & MSR_SE)
		SingleStepException(regs);
}

static void parse_fpe(struct pt_regs *regs)
{
	int code = 0;
	unsigned long fpscr;

	flush_fp_to_thread(current);

	fpscr = current->thread.fpscr;

	/* Invalid operation */
	if ((fpscr & FPSCR_VE) && (fpscr & FPSCR_VX))
		code = FPE_FLTINV;

	/* Overflow */
	else if ((fpscr & FPSCR_OE) && (fpscr & FPSCR_OX))
		code = FPE_FLTOVF;

	/* Underflow */
	else if ((fpscr & FPSCR_UE) && (fpscr & FPSCR_UX))
		code = FPE_FLTUND;

	/* Divide by zero */
	else if ((fpscr & FPSCR_ZE) && (fpscr & FPSCR_ZX))
		code = FPE_FLTDIV;

	/* Inexact result */
	else if ((fpscr & FPSCR_XE) && (fpscr & FPSCR_XX))
		code = FPE_FLTRES;

	_exception(SIGFPE, regs, code, regs->nip);
}

/*
 * Illegal instruction emulation support.  Return non-zero if we can't
 * emulate, or -EFAULT if the associated memory access caused an access
 * fault.  Return zero on success.
 */

#define INST_DCBA		0x7c0005ec
#define INST_DCBA_MASK		0x7c0007fe

#define INST_MCRXR		0x7c000400
#define INST_MCRXR_MASK		0x7c0007fe

static int emulate_instruction(struct pt_regs *regs)
{
	unsigned int instword;

	if (!user_mode(regs) || (regs->msr & MSR_LE))
		return -EINVAL;

	CHECK_FULL_REGS(regs);

	if (get_user(instword, (unsigned int __user *)(regs->nip)))
		return -EFAULT;

	/* Emulating the dcba insn is just a no-op.  */
	if ((instword & INST_DCBA_MASK) == INST_DCBA) {
		static int warned;

		if (!warned) {
			printk(KERN_WARNING
			       "process %d (%s) uses obsolete 'dcba' insn\n",
			       current->pid, current->comm);
			warned = 1;
		}
		return 0;
	}

	/* Emulate the mcrxr insn.  */
	if ((instword & INST_MCRXR_MASK) == INST_MCRXR) {
		static int warned;
		unsigned int shift;

		if (!warned) {
			printk(KERN_WARNING
			       "process %d (%s) uses obsolete 'mcrxr' insn\n",
			       current->pid, current->comm);
			warned = 1;
		}

		shift = (instword >> 21) & 0x1c;
		regs->ccr &= ~(0xf0000000 >> shift);
		regs->ccr |= (regs->xer & 0xf0000000) >> shift;
		regs->xer &= ~0xf0000000;
		return 0;
	}

	return -EINVAL;
}

/*
 * Look through the list of trap instructions that are used for BUG(),
 * BUG_ON() and WARN_ON() and see if we hit one.  At this point we know
 * that the exception was caused by a trap instruction of some kind.
 * Returns 1 if we should continue (i.e. it was a WARN_ON) or 0
 * otherwise.
 */
extern struct bug_entry __start___bug_table[], __stop___bug_table[];

#ifndef CONFIG_MODULES
#define module_find_bug(x)	NULL
#endif

static struct bug_entry *find_bug(unsigned long bugaddr)
{
	struct bug_entry *bug;

	for (bug = __start___bug_table; bug < __stop___bug_table; ++bug)
		if (bugaddr == bug->bug_addr)
			return bug;
	return module_find_bug(bugaddr);
}

int
check_bug_trap(struct pt_regs *regs)
{
	struct bug_entry *bug;
	unsigned long addr;

	if (regs->msr & MSR_PR)
		return 0;	/* not in kernel */
	addr = regs->nip;	/* address of trap instruction */
	if (addr < PAGE_OFFSET)
		return 0;
	bug = find_bug(regs->nip);
	if (bug == NULL)
		return 0;
	if (bug->line & BUG_WARNING_TRAP) {
		/* this is a WARN_ON rather than BUG/BUG_ON */
		printk(KERN_ERR "Badness in %s at %s:%d\n",
		       bug->function, bug->file,
		      (unsigned int)bug->line & ~BUG_WARNING_TRAP);
		show_stack(current, (void *)regs->gpr[1]);
		return 1;
	}
	printk(KERN_CRIT "kernel BUG in %s at %s:%d!\n",
	       bug->function, bug->file, (unsigned int)bug->line);
	return 0;
}

void
ProgramCheckException(struct pt_regs *regs)
{
	if (regs->msr & 0x100000) {
		/* IEEE FP exception */
		parse_fpe(regs);

	} else if (regs->msr & 0x40000) {
		/* Privileged instruction */
		_exception(SIGILL, regs, ILL_PRVOPC, regs->nip);

	} else if (regs->msr & 0x20000) {
		/* trap exception */

		if (notify_die(DIE_BPT, "breakpoint", regs, 5,
					5, SIGTRAP) == NOTIFY_STOP)
			return;
		if (debugger_bpt(regs))
			return;

		if (check_bug_trap(regs)) {
			regs->nip += 4;
			return;
		}
		_exception(SIGTRAP, regs, TRAP_BRKPT, regs->nip);

	} else {
		/* Illegal instruction; try to emulate it.  */
		switch (emulate_instruction(regs)) {
		case 0:
			regs->nip += 4;
			emulate_single_step(regs);
			break;

		case -EFAULT:
			_exception(SIGSEGV, regs, SEGV_MAPERR, regs->nip);
			break;

		default:
			_exception(SIGILL, regs, ILL_ILLOPC, regs->nip);
			break;
		}
	}
}

void KernelFPUnavailableException(struct pt_regs *regs)
{
	printk(KERN_EMERG "Unrecoverable FP Unavailable Exception "
			  "%lx at %lx\n", regs->trap, regs->nip);
	die("Unrecoverable FP Unavailable Exception", regs, SIGABRT);
}

void AltivecUnavailableException(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		/* A user program has executed an altivec instruction,
		   but this kernel doesn't support altivec. */
		_exception(SIGILL, regs, ILL_ILLOPC, regs->nip);
		return;
	}
	printk(KERN_EMERG "Unrecoverable VMX/Altivec Unavailable Exception "
			  "%lx at %lx\n", regs->trap, regs->nip);
	die("Unrecoverable VMX/Altivec Unavailable Exception", regs, SIGABRT);
}

/* Ensure exceptions are disabled */
#define MMCR0_PMXE      (1UL << (31 - 5))
#define MMCR0_PMAO      (1UL << (31 - 24))

static void dummy_perf(struct pt_regs *regs)
{
	unsigned int mmcr0 = mfspr(SPRN_MMCR0);

	mmcr0 &= ~(MMCR0_PMXE|MMCR0_PMAO);
	mtspr(SPRN_MMCR0, mmcr0);
}

void (*perf_irq)(struct pt_regs *) = dummy_perf;

EXPORT_SYMBOL(perf_irq);

void
PerformanceMonitorException(struct pt_regs *regs)
{
	perf_irq(regs);
}

void
AlignmentException(struct pt_regs *regs)
{
	int fixed = 0;

	/* we don't implement logging of alignment exceptions */
	if (!(current->thread.align_ctl & PR_UNALIGN_SIGBUS))
		fixed = fix_alignment(regs);

	if (fixed == 1) {
		regs->nip += 4;	/* skip over emulated instruction */
		emulate_single_step(regs);
		return;
	}

	/* Operand address was bad */	
	if (fixed == -EFAULT) {
		if (user_mode(regs)) {
			_exception(SIGSEGV, regs, SEGV_MAPERR, regs->dar);
		} else {
			/* Search exception table */
			bad_page_fault(regs, regs->dar, SIGSEGV);
		}

		return;
	}

	_exception(SIGBUS, regs, BUS_ADRALN, regs->nip);
}

#ifdef CONFIG_ALTIVEC
void
AltivecAssistException(struct pt_regs *regs)
{
	int err;
	siginfo_t info;

	if (!user_mode(regs)) {
		printk(KERN_EMERG "VMX/Altivec assist exception in kernel mode"
		       " at %lx\n", regs->nip);
		die("Kernel VMX/Altivec assist exception", regs, SIGILL);
	}

	flush_altivec_to_thread(current);

	err = emulate_altivec(regs);
	if (err == 0) {
		regs->nip += 4;		/* skip emulated instruction */
		emulate_single_step(regs);
		return;
	}

	if (err == -EFAULT) {
		/* got an error reading the instruction */
		info.si_signo = SIGSEGV;
		info.si_errno = 0;
		info.si_code = SEGV_MAPERR;
		info.si_addr = (void __user *) regs->nip;
		force_sig_info(SIGSEGV, &info, current);
	} else {
		/* didn't recognize the instruction */
		/* XXX quick hack for now: set the non-Java bit in the VSCR */
		if (printk_ratelimit())
			printk(KERN_ERR "Unrecognized altivec instruction "
			       "in %s at %lx\n", current->comm, regs->nip);
		current->thread.vscr.u[3] |= 0x10000;
	}
}
#endif /* CONFIG_ALTIVEC */

/*
 * We enter here if we get an unrecoverable exception, that is, one
 * that happened at a point where the RI (recoverable interrupt) bit
 * in the MSR is 0.  This indicates that SRR0/1 are live, and that
 * we therefore lost state by taking this exception.
 */
void unrecoverable_exception(struct pt_regs *regs)
{
	printk(KERN_EMERG "Unrecoverable exception %lx at %lx\n",
	       regs->trap, regs->nip);
	die("Unrecoverable exception", regs, SIGABRT);
}

/*
 * We enter here if we discover during exception entry that we are
 * running in supervisor mode with a userspace value in the stack pointer.
 */
void kernel_bad_stack(struct pt_regs *regs)
{
	printk(KERN_EMERG "Bad kernel stack pointer %lx at %lx\n",
	       regs->gpr[1], regs->nip);
	die("Bad kernel stack pointer", regs, SIGABRT);
}

void __init trap_init(void)
{
}

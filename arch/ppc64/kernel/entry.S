/*
 *  arch/ppc64/kernel/entry.S
 *
 *  PowerPC version 
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *  Rewritten by Cort Dougan (cort@cs.nmt.edu) for PReP
 *    Copyright (C) 1996 Cort Dougan <cort@cs.nmt.edu>
 *  Adapted for Power Macintosh by Paul Mackerras.
 *  Low-level exception handlers and MMU support
 *  rewritten by Paul Mackerras.
 *    Copyright (C) 1996 Paul Mackerras.
 *  MPC8xx modifications Copyright (C) 1997 Dan Malek (dmalek@jlc.net).
 *
 *  This file contains the system call entry code, context switch
 *  code, and exception/interrupt return code for PowerPC.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */

#include <linux/config.h>
#include <linux/errno.h>
#include <asm/unistd.h>
#include <asm/processor.h>
#include <asm/page.h>
#include <asm/mmu.h>
#include <asm/thread_info.h>
#include <asm/ppc_asm.h>
#include <asm/offsets.h>
#include <asm/cputable.h>
#include <asm/cache.h>

#ifdef CONFIG_PPC_ISERIES
#define DO_SOFT_DISABLE
#endif

/*
 * System calls.
 */
	.section	".toc","aw"
.SYS_CALL_TABLE:
	.tc .sys_call_table[TC],.sys_call_table

.SYS_CALL_TABLE32:
	.tc .sys_call_table32[TC],.sys_call_table32

.slb_shadow:
	.tc	slb_shadow[TC],slb_shadow

/* This value is used to mark exception frames on the stack. */
exception_marker:
	.tc	ID_72656773_68657265[TC],0x7265677368657265

	.section	".text"
	.align 7

#undef SHOW_SYSCALLS

	.globl SystemCall_common
SystemCall_common:
	andi.	r10,r12,MSR_PR
	mr	r10,r1
	addi	r1,r1,-INT_FRAME_SIZE
	beq-	1f
	ld	r1,PACAKSAVE(r13)
1:	std	r10,0(r1)
	std	r11,_NIP(r1)
	std	r12,_MSR(r1)
	std	r0,GPR0(r1)
	std	r10,GPR1(r1)
	std	r2,GPR2(r1)
	std	r3,GPR3(r1)
	std	r4,GPR4(r1)
	std	r5,GPR5(r1)
	std	r6,GPR6(r1)
	std	r7,GPR7(r1)
	std	r8,GPR8(r1)
	li	r11,0
	std	r11,GPR9(r1)
	std	r11,GPR10(r1)
	std	r11,GPR11(r1)
	std	r11,GPR12(r1)
	std	r9,GPR13(r1)
	crclr	so
	mfcr	r9
	mflr	r10
	li	r11,0xc01
	std	r9,_CCR(r1)
	std	r10,_LINK(r1)
	std	r11,_TRAP(r1)
	mfxer	r9
	mfctr	r10
	std	r9,_XER(r1)
	std	r10,_CTR(r1)
	std	r3,ORIG_GPR3(r1)
	ld	r2,PACATOC(r13)
	addi	r9,r1,STACK_FRAME_OVERHEAD
	ld	r11,exception_marker@toc(r2)
	std	r11,-16(r9)		/* "regshere" marker */
#ifdef CONFIG_PPC_ISERIES
	/* Hack for handling interrupts when soft-enabling on iSeries */
	cmpdi	cr1,r0,0x5555		/* syscall 0x5555 */
	andi.	r10,r12,MSR_PR		/* from kernel */
	crand	4*cr0+eq,4*cr1+eq,4*cr0+eq
	beq	HardwareInterrupt_entry
	lbz	r10,PACAPROCENABLED(r13)
	std	r10,SOFTE(r1)
#endif
	mfmsr	r11
	ori	r11,r11,MSR_EE
	mtmsrd	r11,1

#ifdef SHOW_SYSCALLS
	bl	.do_show_syscall
	REST_GPR(0,r1)
	REST_4GPRS(3,r1)
	REST_2GPRS(7,r1)
	addi	r9,r1,STACK_FRAME_OVERHEAD
#endif
	clrrdi	r11,r1,THREAD_SHIFT
	li	r12,0
	ld	r10,TI_FLAGS(r11)
	stb	r12,TI_SC_NOERR(r11)
	andi.	r11,r10,_TIF_SYSCALL_T_OR_A
	bne-	syscall_dotrace
syscall_dotrace_cont:
	cmpldi	0,r0,NR_syscalls
	bge-	syscall_enosys

system_call:			/* label this so stack traces look sane */
/*
 * Need to vector to 32 Bit or default sys_call_table here,
 * based on caller's run-mode / personality.
 */
	ld	r11,.SYS_CALL_TABLE@toc(2)
	andi.	r10,r10,_TIF_32BIT
	beq	15f
	ld	r11,.SYS_CALL_TABLE32@toc(2)
	clrldi	r3,r3,32
	clrldi	r4,r4,32
	clrldi	r5,r5,32
	clrldi	r6,r6,32
	clrldi	r7,r7,32
	clrldi	r8,r8,32
15:
	slwi	r0,r0,3
	ldx	r10,r11,r0	/* Fetch system call handler [ptr] */
	mtctr   r10
	bctrl			/* Call handler */

syscall_exit:
#ifdef SHOW_SYSCALLS
	std	r3,GPR3(r1)
	bl	.do_show_syscall_exit
	ld	r3,GPR3(r1)
#endif
	std	r3,RESULT(r1)
	ld	r5,_CCR(r1)
	li	r10,-_LAST_ERRNO
	cmpld	r3,r10
	clrrdi	r12,r1,THREAD_SHIFT
	bge-	syscall_error
syscall_error_cont:

	/* check for syscall tracing or audit */
	ld	r9,TI_FLAGS(r12)
	andi.	r0,r9,(_TIF_SYSCALL_T_OR_A|_TIF_SINGLESTEP)
	bne-	syscall_exit_trace
syscall_exit_trace_cont:

	/* disable interrupts so current_thread_info()->flags can't change,
	   and so that we don't get interrupted after loading SRR0/1. */
	ld	r8,_MSR(r1)
	andi.	r10,r8,MSR_RI
	beq-	unrecov_restore
	mfmsr	r10
	rldicl	r10,r10,48,1
	rotldi	r10,r10,16
	mtmsrd	r10,1
	ld	r9,TI_FLAGS(r12)
	andi.	r0,r9,(_TIF_SYSCALL_T_OR_A|_TIF_SIGPENDING|_TIF_NEED_RESCHED)
	bne-	syscall_exit_work
	ld	r7,_NIP(r1)
	stdcx.	r0,0,r1			/* to clear the reservation */
	andi.	r6,r8,MSR_PR
	ld	r4,_LINK(r1)
	beq-	1f			/* only restore r13 if */
	ld	r13,GPR13(r1)		/* returning to usermode */
1:	ld	r2,GPR2(r1)
	li	r12,MSR_RI
	andc	r10,r10,r12
	mtmsrd	r10,1			/* clear MSR.RI */
	ld	r1,GPR1(r1)
	mtlr	r4
	mtcr	r5
	mtspr	SRR0,r7
	mtspr	SRR1,r8
	rfid
	b	.	/* prevent speculative execution */

syscall_enosys:
	li	r3,-ENOSYS
	std	r3,RESULT(r1)
	clrrdi	r12,r1,THREAD_SHIFT
	ld	r5,_CCR(r1)

syscall_error:
	lbz	r11,TI_SC_NOERR(r12)
	cmpwi	0,r11,0
	bne-	syscall_error_cont
	neg	r3,r3
	oris	r5,r5,0x1000	/* Set SO bit in CR */
	std	r5,_CCR(r1)
	b	syscall_error_cont
        
/* Traced system call support */
syscall_dotrace:
	bl	.save_nvgprs
	addi	r3,r1,STACK_FRAME_OVERHEAD
	bl	.do_syscall_trace_enter
	ld	r0,GPR0(r1)	/* Restore original registers */
	ld	r3,GPR3(r1)
	ld	r4,GPR4(r1)
	ld	r5,GPR5(r1)
	ld	r6,GPR6(r1)
	ld	r7,GPR7(r1)
	ld	r8,GPR8(r1)
	addi	r9,r1,STACK_FRAME_OVERHEAD
	clrrdi	r10,r1,THREAD_SHIFT
	ld	r10,TI_FLAGS(r10)
	b	syscall_dotrace_cont

syscall_exit_trace:
	std	r3,GPR3(r1)
	bl	.save_nvgprs
	addi	r3,r1,STACK_FRAME_OVERHEAD
	bl	.do_syscall_trace_leave
	REST_NVGPRS(r1)
	ld	r3,GPR3(r1)
	ld	r5,_CCR(r1)
	clrrdi	r12,r1,THREAD_SHIFT
	b	syscall_exit_trace_cont

/* Stuff to do on exit from a system call. */
syscall_exit_work:
	std	r3,GPR3(r1)
	std	r5,_CCR(r1)
	b	.ret_from_except_lite

/* Save non-volatile GPRs, if not already saved. */
_GLOBAL(save_nvgprs)
	ld	r11,_TRAP(r1)
	andi.	r0,r11,1
	beqlr-
	SAVE_NVGPRS(r1)
	clrrdi	r0,r11,1
	std	r0,_TRAP(r1)
	blr

/*
 * The sigsuspend and rt_sigsuspend system calls can call do_signal
 * and thus put the process into the stopped state where we might
 * want to examine its user state with ptrace.  Therefore we need
 * to save all the nonvolatile registers (r14 - r31) before calling
 * the C code.  Similarly, fork, vfork and clone need the full
 * register state on the stack so that it can be copied to the child.
 */
_GLOBAL(ppc32_sigsuspend)
	bl	.save_nvgprs
	bl	.sys32_sigsuspend
	b	70f

_GLOBAL(ppc64_rt_sigsuspend)
	bl	.save_nvgprs
	bl	.sys_rt_sigsuspend
	b	70f

_GLOBAL(ppc32_rt_sigsuspend)
	bl	.save_nvgprs
	bl	.sys32_rt_sigsuspend
70:	cmpdi	0,r3,0
	/* If it returned an error, we need to return via syscall_exit to set
	   the SO bit in cr0 and potentially stop for ptrace. */
	bne	syscall_exit
	/* If sigsuspend() returns zero, we are going into a signal handler. We
	   may need to call audit_syscall_exit() to mark the exit from sigsuspend() */
	ld	r3,PACACURRENT(r13)
	ld	r4,AUDITCONTEXT(r3)
	cmpdi	0,r4,0
	beq	.ret_from_except	/* No audit_context: Leave immediately. */
	li	r4, 2			/* AUDITSC_FAILURE */
	li	r5,-4			/* It's always -EINTR */
	bl	.audit_syscall_exit
	b	.ret_from_except

_GLOBAL(ppc_fork)
	bl	.save_nvgprs
	bl	.sys_fork
	b	syscall_exit

_GLOBAL(ppc_vfork)
	bl	.save_nvgprs
	bl	.sys_vfork
	b	syscall_exit

_GLOBAL(ppc_clone)
	bl	.save_nvgprs
	bl	.sys_clone
	b	syscall_exit

_GLOBAL(ppc32_swapcontext)
	bl	.save_nvgprs
	bl	.sys32_swapcontext
	b	80f
	
_GLOBAL(ppc64_swapcontext)
	bl	.save_nvgprs
	bl	.sys_swapcontext
	b	80f

_GLOBAL(ppc32_sigreturn)
	bl	.sys32_sigreturn
	b	80f

_GLOBAL(ppc32_rt_sigreturn)
	bl	.sys32_rt_sigreturn
	b	80f

_GLOBAL(ppc64_rt_sigreturn)
	bl	.sys_rt_sigreturn

80:	cmpdi	0,r3,0
	blt	syscall_exit
	clrrdi	r4,r1,THREAD_SHIFT
	ld	r4,TI_FLAGS(r4)
	andi.	r4,r4,(_TIF_SYSCALL_T_OR_A|_TIF_SINGLESTEP)
	beq+	81f
	addi	r3,r1,STACK_FRAME_OVERHEAD
	bl	.do_syscall_trace_leave
81:	b	.ret_from_except

_GLOBAL(ret_from_fork)
	bl	.schedule_tail
	REST_NVGPRS(r1)
	li	r3,0
	b	syscall_exit

/*
 * This routine switches between two different tasks.  The process
 * state of one is saved on its kernel stack.  Then the state
 * of the other is restored from its kernel stack.  The memory
 * management hardware is updated to the second process's state.
 * Finally, we can return to the second process, via ret_from_except.
 * On entry, r3 points to the THREAD for the current task, r4
 * points to the THREAD for the new task.
 *
 * Note: there are two ways to get to the "going out" portion
 * of this code; either by coming in via the entry (_switch)
 * or via "fork" which must set up an environment equivalent
 * to the "_switch" path.  If you change this you'll have to change
 * the fork code also.
 *
 * The code which creates the new task context is in 'copy_thread'
 * in arch/ppc64/kernel/process.c
 */
	.align	7
_GLOBAL(_switch)
	mflr	r0
	std	r0,16(r1)
	stdu	r1,-SWITCH_FRAME_SIZE(r1)
	/* r3-r13 are caller saved -- Cort */
	SAVE_8GPRS(14, r1)
	SAVE_10GPRS(22, r1)
	mflr	r20		/* Return to switch caller */
	mfmsr	r22
	li	r0, MSR_FP
#ifdef CONFIG_ALTIVEC
BEGIN_FTR_SECTION
	oris	r0,r0,MSR_VEC@h	/* Disable altivec */
	mfspr	r24,SPRN_VRSAVE	/* save vrsave register value */
	std	r24,THREAD_VRSAVE(r3)
END_FTR_SECTION_IFSET(CPU_FTR_ALTIVEC)
#endif /* CONFIG_ALTIVEC */
	and.	r0,r0,r22
	beq+	1f
	andc	r22,r22,r0
	mtmsrd	r22
	isync
1:	std	r20,_NIP(r1)
	mfcr	r23
	std	r23,_CCR(r1)
	std	r1,KSP(r3)	/* Set old stack pointer */

#ifdef CONFIG_SMP
	/* We need a sync somewhere here to make sure that if the
	 * previous task gets rescheduled on another CPU, it sees all
	 * stores it has performed on this one.
	 */
	sync
#endif /* CONFIG_SMP */

	addi	r6,r4,-THREAD	/* Convert THREAD to 'current' */
	std	r6,PACACURRENT(r13)	/* Set new 'current' */

	ld	r8,KSP(r4)	/* new stack pointer */
BEGIN_FTR_SECTION
	clrrdi	r6,r8,28	/* get its ESID */
	clrrdi	r9,r1,28	/* get current sp ESID */
	clrldi.	r0,r6,2		/* is new ESID c00000000? */
	cmpd	cr1,r6,r9	/* or is new ESID the same as current ESID? */
	cror	eq,4*cr1+eq,eq
	beq	2f		/* if yes, don't slbie it */
	oris	r0,r6,0x0800	/* set C (class) bit */

	/* Bolt in the new stack SLB entry */
	ld	r7,KSP_VSID(r4)	/* Get new stack's VSID */
	oris	r6,r6,(SLB_ESID_V)@h
	ori	r6,r6,(SLB_NUM_BOLTED-1)@l

	/* Update the last bolted SLB.  No write barriers are needed
	 * here, provided we only update the current CPU's SLB shadow
	 * buffer.
	 */
	ld	r9,.slb_shadow@toc(r2)
	lhz	r12,PACAPACAINDEX(r13)
	sldi	r12,r12,L1_CACHE_SHIFT
	add	r9,r9,r12
	li	r12,0
	std	r12,SLBSHADOW_STACKESID(r9) /* Clear ESID */
	std	r7,SLBSHADOW_STACKVSID(r9)  /* Save VSID */
	std	r0,SLBSHADOW_STACKESID(r9)  /* Save ESID */

	slbie	r0
	slbie	r0		/* Workaround POWER5 < DD2.1 issue */
	slbmte	r7,r6
	isync

2:
END_FTR_SECTION_IFSET(CPU_FTR_SLB)
	clrrdi	r7,r8,THREAD_SHIFT	/* base of new stack */
	/* Note: this uses SWITCH_FRAME_SIZE rather than INT_FRAME_SIZE
	   because we don't need to leave the 288-byte ABI gap at the
	   top of the kernel stack. */
	addi	r7,r7,THREAD_SIZE-SWITCH_FRAME_SIZE

	mr	r1,r8		/* start using new stack pointer */
	std	r7,PACAKSAVE(r13)

	ld	r6,_CCR(r1)
	mtcrf	0xFF,r6

#ifdef CONFIG_ALTIVEC
BEGIN_FTR_SECTION
	ld	r0,THREAD_VRSAVE(r4)
	mtspr	SPRN_VRSAVE,r0		/* if G4, restore VRSAVE reg */
END_FTR_SECTION_IFSET(CPU_FTR_ALTIVEC)
#endif /* CONFIG_ALTIVEC */

	/* r3-r13 are destroyed -- Cort */
	REST_8GPRS(14, r1)
	REST_10GPRS(22, r1)

#ifdef CONFIG_PPC_ISERIES
	clrrdi	r7,r1,THREAD_SHIFT	/* get current_thread_info() */
	ld	r7,TI_FLAGS(r7)		/* Get run light flag */
	mfspr	r9,CTRLF
	srdi	r7,r7,TIF_RUN_LIGHT
	insrdi	r9,r7,1,63		/* Insert run light into CTRL */
	mtspr	CTRLT,r9
#endif

	/* convert old thread to its task_struct for return value */
	addi	r3,r3,-THREAD
	ld	r7,_NIP(r1)	/* Return to _switch caller in new task */
	mtlr	r7
	addi	r1,r1,SWITCH_FRAME_SIZE
	blr

	.align	7
_GLOBAL(ret_from_except)
	ld	r11,_TRAP(r1)
	andi.	r0,r11,1
	bne	.ret_from_except_lite
	REST_NVGPRS(r1)

_GLOBAL(ret_from_except_lite)
	/*
	 * Disable interrupts so that current_thread_info()->flags
	 * can't change between when we test it and when we return
	 * from the interrupt.
	 */
	mfmsr	r10		/* Get current interrupt state */
	rldicl	r9,r10,48,1	/* clear MSR_EE */
	rotldi	r9,r9,16
	mtmsrd	r9,1		/* Update machine state */

#ifdef CONFIG_PREEMPT
	clrrdi	r9,r1,THREAD_SHIFT	/* current_thread_info() */
	li	r0,_TIF_NEED_RESCHED	/* bits to check */
	ld	r3,_MSR(r1)
	ld	r4,TI_FLAGS(r9)
	/* Move MSR_PR bit in r3 to _TIF_SIGPENDING position in r0 */
	rlwimi	r0,r3,32+TIF_SIGPENDING-MSR_PR_LG,_TIF_SIGPENDING
	and.	r0,r4,r0	/* check NEED_RESCHED and maybe SIGPENDING */
	bne	do_work

#else /* !CONFIG_PREEMPT */
	ld	r3,_MSR(r1)	/* Returning to user mode? */
	andi.	r3,r3,MSR_PR
	beq	restore		/* if not, just restore regs and return */

	/* Check current_thread_info()->flags */
	clrrdi	r9,r1,THREAD_SHIFT
	ld	r4,TI_FLAGS(r9)
	andi.	r0,r4,_TIF_USER_WORK_MASK
	bne	do_work
#endif

restore:
#ifdef CONFIG_PPC_ISERIES
	ld	r5,SOFTE(r1)
	cmpdi	0,r5,0
	beq	4f
	/* Check for pending interrupts (iSeries) */
	ld	r3,PACALPPACA+LPPACAANYINT(r13)
	cmpdi	r3,0
	beq+	4f			/* skip do_IRQ if no interrupts */

	li	r3,0
	stb	r3,PACAPROCENABLED(r13)	/* ensure we are soft-disabled */
	ori	r10,r10,MSR_EE
	mtmsrd	r10			/* hard-enable again */
	addi	r3,r1,STACK_FRAME_OVERHEAD
	bl	.do_IRQ
	b	.ret_from_except		/* loop back and handle more */

4:	stb	r5,PACAPROCENABLED(r13)
#endif

	ld	r3,_MSR(r1)
	andi.	r0,r3,MSR_RI
	beq-	unrecov_restore

	andi.	r0,r3,MSR_PR

	/*
	 * r13 is our per cpu area, only restore it if we are returning to
	 * userspace
	 */
	beq	1f
	REST_GPR(13, r1)
1:
	ld	r3,_CTR(r1)
	ld	r0,_LINK(r1)
	mtctr	r3
	mtlr	r0
	ld	r3,_XER(r1)
	mtspr	XER,r3

	REST_8GPRS(5, r1)

	stdcx.	r0,0,r1		/* to clear the reservation */

	mfmsr	r0
	li	r2, MSR_RI
	andc	r0,r0,r2
	mtmsrd	r0,1

	ld	r0,_MSR(r1)
	mtspr	SRR1,r0

	ld	r2,_CCR(r1)
	mtcrf	0xFF,r2
	ld	r2,_NIP(r1)
	mtspr	SRR0,r2

	ld	r0,GPR0(r1)
	ld	r2,GPR2(r1)
	ld	r3,GPR3(r1)
	ld	r4,GPR4(r1)
	ld	r1,GPR1(r1)

	rfid
	b	.	/* prevent speculative execution */

/* Note: this must change if we start using the TIF_NOTIFY_RESUME bit */
do_work:
#ifdef CONFIG_PREEMPT
	andi.	r0,r3,MSR_PR	/* Returning to user mode? */
	bne	user_work
	/* Check that preempt_count() == 0 and interrupts are enabled */
	lwz	r8,TI_PREEMPT(r9)
	cmpwi	cr1,r8,0
#ifdef CONFIG_PPC_ISERIES
	ld	r0,SOFTE(r1)
	cmpdi	r0,0
#else
	andi.	r0,r3,MSR_EE
#endif
	crandc	eq,cr1*4+eq,eq
	bne	restore
	/* here we are preempting the current task */
1:	lis	r0,PREEMPT_ACTIVE@h
	stw	r0,TI_PREEMPT(r9)
#ifdef CONFIG_PPC_ISERIES
	li	r0,1
	stb	r0,PACAPROCENABLED(r13)
#endif
	ori	r10,r10,MSR_EE
	mtmsrd	r10,1		/* reenable interrupts */
	bl	.schedule
	mfmsr	r10
	clrrdi	r9,r1,THREAD_SHIFT
	rldicl	r10,r10,48,1	/* disable interrupts again */
	li	r0,0
	rotldi	r10,r10,16
	mtmsrd	r10,1
	ld	r4,TI_FLAGS(r9)
	andi.	r0,r4,_TIF_NEED_RESCHED
	bne	1b
	stw	r0,TI_PREEMPT(r9)
	b	restore

user_work:
#endif
	/* Enable interrupts */
	ori	r10,r10,MSR_EE
	mtmsrd	r10,1

	andi.	r0,r4,_TIF_NEED_RESCHED
	beq	1f
	bl	.schedule
	b	.ret_from_except_lite

1:	bl	.save_nvgprs
	li	r3,0
	addi	r4,r1,STACK_FRAME_OVERHEAD
	bl	.do_signal
	b	.ret_from_except

unrecov_restore:
	addi	r3,r1,STACK_FRAME_OVERHEAD
	bl	.unrecoverable_exception
	b	unrecov_restore

#ifdef CONFIG_PPC_PSERIES
/*
 * On CHRP, the Run-Time Abstraction Services (RTAS) have to be
 * called with the MMU off.
 *
 * In addition, we need to be in 32b mode, at least for now.
 * 
 * Note: r3 is an input parameter to rtas, so don't trash it...
 */
_GLOBAL(enter_rtas)
	mflr	r0
	std	r0,16(r1)
        stdu	r1,-RTAS_FRAME_SIZE(r1)	/* Save SP and create stack space. */

	/* Because RTAS is running in 32b mode, it clobbers the high order half
	 * of all registers that it saves.  We therefore save those registers
	 * RTAS might touch to the stack.  (r0, r3-r13 are caller saved)
   	 */
	SAVE_GPR(2, r1)			/* Save the TOC */
	SAVE_GPR(13, r1)		/* Save paca */
	SAVE_8GPRS(14, r1)		/* Save the non-volatiles */
	SAVE_10GPRS(22, r1)		/* ditto */

	mfcr	r4
	std	r4,_CCR(r1)
	mfctr	r5
	std	r5,_CTR(r1)
	mfspr	r6,XER
	std	r6,_XER(r1)
	mfdar	r7
	std	r7,_DAR(r1)
	mfdsisr	r8
	std	r8,_DSISR(r1)
	mfsrr0	r9
	std	r9,_SRR0(r1)
	mfsrr1	r10
	std	r10,_SRR1(r1)

	/* There is no way it is acceptable to get here with interrupts enabled,
	 * check it with the asm equivalent of WARN_ON
	 */
	mfmsr	r6
	andi.	r0,r6,MSR_EE
1:	tdnei	r0,0
.section __bug_table,"a"
	.llong	1b,__LINE__ + 0x1000000, 1f, 2f
.previous
.section .rodata,"a"
1:	.asciz	__FILE__
2:	.asciz "enter_rtas"
.previous
	
	/* Unfortunately, the stack pointer and the MSR are also clobbered,
	 * so they are saved in the PACA which allows us to restore
	 * our original state after RTAS returns.
         */
	std	r1,PACAR1(r13)
        std	r6,PACASAVEDMSR(r13)

	/* Setup our real return addr */	
	SET_REG_TO_LABEL(r4,.rtas_return_loc)
	SET_REG_TO_CONST(r9,KERNELBASE)
	sub	r4,r4,r9
       	mtlr	r4

	li	r0,0
	ori	r0,r0,MSR_EE|MSR_SE|MSR_BE|MSR_RI
	andc	r0,r6,r0
	
        li      r9,1
        rldicr  r9,r9,MSR_SF_LG,(63-MSR_SF_LG)
	ori	r9,r9,MSR_IR|MSR_DR|MSR_FE0|MSR_FE1|MSR_FP
	andc	r6,r0,r9
	ori	r6,r6,MSR_RI
	sync				/* disable interrupts so SRR0/1 */
	mtmsrd	r0			/* don't get trashed */

	SET_REG_TO_LABEL(r4,rtas)
	ld	r5,RTASENTRY(r4)	/* get the rtas->entry value */
	ld	r4,RTASBASE(r4)		/* get the rtas->base value */
	
	mtspr	SRR0,r5
	mtspr	SRR1,r6
	rfid
	b	.	/* prevent speculative execution */

_STATIC(rtas_return_loc)
	/* relocation is off at this point */
	mfspr	r4,SPRG3	        /* Get PACA */
	SET_REG_TO_CONST(r5, KERNELBASE)
        sub     r4,r4,r5                /* RELOC the PACA base pointer */

	mfmsr   r6
	li	r0,MSR_RI
	andc	r6,r6,r0
	sync	
	mtmsrd  r6
        
        ld	r1,PACAR1(r4)           /* Restore our SP */
	LOADADDR(r3,.rtas_restore_regs)
        ld	r4,PACASAVEDMSR(r4)     /* Restore our MSR */

	mtspr	SRR0,r3
	mtspr	SRR1,r4
	rfid
	b	.	/* prevent speculative execution */

_STATIC(rtas_restore_regs)
	/* relocation is on at this point */
	REST_GPR(2, r1)			/* Restore the TOC */
	REST_GPR(13, r1)		/* Restore paca */
	REST_8GPRS(14, r1)		/* Restore the non-volatiles */
	REST_10GPRS(22, r1)		/* ditto */

	mfspr	r13,SPRG3

	ld	r4,_CCR(r1)
	mtcr	r4
	ld	r5,_CTR(r1)
	mtctr	r5
	ld	r6,_XER(r1)
	mtspr	XER,r6
	ld	r7,_DAR(r1)
	mtdar	r7
	ld	r8,_DSISR(r1)
	mtdsisr	r8
	ld	r9,_SRR0(r1)
	mtsrr0	r9
	ld	r10,_SRR1(r1)
	mtsrr1	r10

        addi	r1,r1,RTAS_FRAME_SIZE	/* Unstack our frame */
	ld	r0,16(r1)		/* get return address */

	mtlr    r0
        blr				/* return to caller */

#endif /* CONFIG_PPC_PSERIES */

#ifdef CONFIG_PPC_MULTIPLATFORM

_GLOBAL(enter_prom)
	mflr	r0
	std	r0,16(r1)
        stdu	r1,-PROM_FRAME_SIZE(r1)	/* Save SP and create stack space */

	/* Because PROM is running in 32b mode, it clobbers the high order half
	 * of all registers that it saves.  We therefore save those registers
	 * PROM might touch to the stack.  (r0, r3-r13 are caller saved)
   	 */
	SAVE_8GPRS(2, r1)
	SAVE_GPR(13, r1)
	SAVE_8GPRS(14, r1)
	SAVE_10GPRS(22, r1)
	mfcr	r4
	std	r4,_CCR(r1)
	mfctr	r5
	std	r5,_CTR(r1)
	mfspr	r6,XER
	std	r6,_XER(r1)
	mfdar	r7
	std	r7,_DAR(r1)
	mfdsisr	r8
	std	r8,_DSISR(r1)
	mfsrr0	r9
	std	r9,_SRR0(r1)
	mfsrr1	r10
	std	r10,_SRR1(r1)
	mfmsr	r11
	std	r11,_MSR(r1)

	/* Get the PROM entrypoint */
	ld	r0,GPR4(r1)
	mtlr	r0

	/* Switch MSR to 32 bits mode
	 */
        mfmsr   r11
        li      r12,1
        rldicr  r12,r12,MSR_SF_LG,(63-MSR_SF_LG)
        andc    r11,r11,r12
        li      r12,1
        rldicr  r12,r12,MSR_ISF_LG,(63-MSR_ISF_LG)
        andc    r11,r11,r12
        mtmsrd  r11
        isync

	/* Restore arguments & enter PROM here... */
	ld	r3,GPR3(r1)
	blrl

	/* Just make sure that r1 top 32 bits didn't get
	 * corrupt by OF
	 */
	rldicl	r1,r1,0,32

	/* Restore the MSR (back to 64 bits) */
	ld	r0,_MSR(r1)
	mtmsrd	r0
        isync

	/* Restore other registers */
	REST_GPR(2, r1)
	REST_GPR(13, r1)
	REST_8GPRS(14, r1)
	REST_10GPRS(22, r1)
	ld	r4,_CCR(r1)
	mtcr	r4
	ld	r5,_CTR(r1)
	mtctr	r5
	ld	r6,_XER(r1)
	mtspr	XER,r6
	ld	r7,_DAR(r1)
	mtdar	r7
	ld	r8,_DSISR(r1)
	mtdsisr	r8
	ld	r9,_SRR0(r1)
	mtsrr0	r9
	ld	r10,_SRR1(r1)
	mtsrr1	r10
	
        addi	r1,r1,PROM_FRAME_SIZE
	ld	r0,16(r1)
	mtlr    r0
        blr
	
#endif	/* CONFIG_PPC_MULTIPLATFORM */

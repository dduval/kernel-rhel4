/*
 *  linux/arch/i386/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * entry.S contains the system-call and fault low-level handling routines.
 * This also contains the timer-interrupt handler, as well as all interrupts
 * and faults that can result in a task-switch.
 *
 * NOTE: This code handles signal-recognition, which happens every time
 * after a timer-interrupt and after each system call.
 *
 * I changed all the .align's to 4 (16 byte alignment), as that's faster
 * on a 486.
 *
 * Stack layout in 'ret_from_system_call':
 * 	ptrace needs to have all regs on the stack.
 *	if the order here is changed, it needs to be
 *	updated in fork.c:copy_process, signal.c:do_signal,
 *	ptrace.c and ptrace.h
 *
 *	 0(%esp) - %ebx
 *	 4(%esp) - %ecx
 *	 8(%esp) - %edx
 *       C(%esp) - %esi
 *	10(%esp) - %edi
 *	14(%esp) - %ebp
 *	18(%esp) - %eax
 *	1C(%esp) - %ds
 *	20(%esp) - %es
 *	24(%esp) - orig_eax
 *	28(%esp) - %eip
 *	2C(%esp) - %cs
 *	30(%esp) - %eflags
 *	34(%esp) - %oldesp
 *	38(%esp) - %oldss
 *
 * "current" is in register %ebx during any slow entries.
 */

#include <linux/config.h>
#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/asm_offsets.h>
#include <asm/errno.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <asm/smp.h>
#include <asm/page.h>
#include "irq_vectors.h"

#define nr_syscalls ((syscall_table_size)/4)

EBX		= 0x00
ECX		= 0x04
EDX		= 0x08
ESI		= 0x0C
EDI		= 0x10
EBP		= 0x14
EAX		= 0x18
DS		= 0x1C
ES		= 0x20
ORIG_EAX	= 0x24
EIP		= 0x28
CS		= 0x2C
EFLAGS		= 0x30
OLDESP		= 0x34
OLDSS		= 0x38

CF_MASK		= 0x00000001
TF_MASK		= 0x00000100
IF_MASK		= 0x00000200
DF_MASK		= 0x00000400 
NT_MASK		= 0x00004000
VM_MASK		= 0x00020000

#ifdef CONFIG_PREEMPT
#define preempt_stop		cli
#else
#define preempt_stop
#define resume_kernel		restore_all
#endif

#ifdef CONFIG_X86_HIGH_ENTRY

#ifdef CONFIG_X86_SWITCH_PAGETABLES

#if defined(CONFIG_PREEMPT) && defined(CONFIG_SMP)
/*
 * If task is preempted in __SWITCH_KERNELSPACE, and moved to another cpu,
 * __switch_to repoints %esp to the appropriate virtual stack; but %ebp is
 * left stale, so we must check whether to repeat the real stack calculation.
 */
#define repeat_if_esp_changed				\
	xorl %esp, %ebp;				\
	testl $-THREAD_SIZE, %ebp;			\
	jnz 0b
#else
#define repeat_if_esp_changed
#endif

/* clobbers ebx, edx and ebp */

#define __SWITCH_KERNELSPACE				\
	cmpl $0xff000000, %esp;				\
	jb 1f;						\
							\
	/*						\
	 * switch pagetables and load the real stack,	\
	 * keep the stack offset:			\
	 */						\
							\
	movl $swapper_pg_dir-__PAGE_OFFSET, %edx;	\
							\
	/* GET_THREAD_INFO(%ebp) intermixed */		\
0:							\
	movl %esp, %ebp;				\
	movl %esp, %ebx;				\
	andl $(-THREAD_SIZE), %ebp;				\
	andl $(THREAD_SIZE-1), %ebx;				\
	orl TI_real_stack(%ebp), %ebx;			\
	repeat_if_esp_changed;				\
							\
	movl %edx, %cr3;				\
	movl %ebx, %esp;				\
1:

#endif


#define __SWITCH_USERSPACE \
	/* interrupted any of the user return paths? */	\
							\
	movl EIP(%esp), %eax;				\
							\
	cmpl $int80_ret_start_marker, %eax;		\
	jb 33f; /* nope - continue with sysexit check */\
	cmpl $int80_ret_end_marker, %eax;		\
	jb 22f; /* yes - switch to virtual stack */	\
33:							\
	cmpl $sysexit_ret_start_marker, %eax;		\
	jb 44f; /* nope - continue with user check */	\
	cmpl $sysexit_ret_end_marker, %eax;		\
	jb 22f; /* yes - switch to virtual stack */	\
	/* return to userspace? */			\
44:							\
	movl EFLAGS(%esp),%ecx;				\
	movb CS(%esp),%cl;				\
	testl $(VM_MASK | 3),%ecx;			\
	jz 2f;						\
22:							\
	/*						\
	 * switch to the virtual stack, then switch to	\
	 * the userspace pagetables.			\
	 */						\
							\
	GET_THREAD_INFO(%ebp);				\
	movl TI_virtual_stack(%ebp), %edx;		\
	movl TI_user_pgd(%ebp), %ecx;			\
							\
	movl %esp, %ebx;				\
	andl $(THREAD_SIZE-1), %ebx;				\
	orl %ebx, %edx;					\
int80_ret_start_marker:					\
	movl %edx, %esp; 				\
	movl %ecx, %cr3;				\
							\
	__RESTORE_ALL_USER;				\
int80_ret_end_marker:					\
2:

#else /* !CONFIG_X86_HIGH_ENTRY */

#define __SWITCH_KERNELSPACE
#define __SWITCH_USERSPACE

#endif

#define __SAVE_ALL \
	cld; \
	pushl %es; \
	pushl %ds; \
	pushl %eax; \
	pushl %ebp; \
	pushl %edi; \
	pushl %esi; \
	pushl %edx; \
	pushl %ecx; \
	pushl %ebx; \
	movl $(__USER_DS), %edx; \
	movl %edx, %ds; \
	movl %edx, %es;

#define __RESTORE_INT_REGS \
	popl %ebx;	\
	popl %ecx;	\
	popl %edx;	\
	popl %esi;	\
	popl %edi;	\
	popl %ebp;	\
	popl %eax

#define __RESTORE_REGS	\
	__RESTORE_INT_REGS; \
	popl %ds;	\
	popl %es;

#define __RESTORE_REGS_USER \
	__RESTORE_INT_REGS; \
111:	popl %ds;	\
222:	popl %es;	\
	jmp 666f;	\
444:	movl $0,(%esp);	\
	jmp 111b;	\
555:	movl $0,(%esp);	\
	jmp 222b;	\
666:			\
.section __ex_table,"a";\
	.align 4;	\
	.long 111b,444b;\
	.long 222b,555b;\
.previous

#define __RESTORE_ALL_USER \
	__RESTORE_REGS_USER \
	__RESTORE_IRET

#ifdef CONFIG_X86_HIGH_ENTRY
#define __RESTORE_ALL	\
	__RESTORE_REGS	\
	__RESTORE_IRET
#else /* !CONFIG_X86_HIGH_ENTRY */
#define __RESTORE_ALL	__RESTORE_ALL_USER
#endif

#define __RESTORE_IRET	\
	addl $4, %esp;	\
333:	iret;		\
.section __ex_table,"a";\
	.align 4;	\
	.long 333b,iret_exc;\
.previous

#define SAVE_ALL \
	__SAVE_ALL;					\
	__SWITCH_KERNELSPACE;

#define RESTORE_ALL					\
	__SWITCH_USERSPACE;				\
	__RESTORE_ALL;

.section .entry.text,"ax"

	/*
	 * Traps in iret mean that userland tried to restore a bogus
	 * cs, eip, ss, esp, or eflags.  Some kinds of bogosity just cause
	 * a trap after the iret returns, but some will cause a trap in
	 * iret itself.  We want to treat those as if the restored user
	 * state is what caused that trap, i.e. produce the appropriate signal.
	 * Since normal .fixup code doesn't have access to the trap info,
	 * traps.c has a special case for iret.  It's already generated the
	 * signal before we resume at iret_exc.  Now we just need to recover
	 * the whole frame we were trying to restore, so it can be seen on
	 * our stack by the debugger.
	 */
ENTRY(iret_exc)
	pushl $0			# orig_eax was lost
	__SAVE_ALL
	jmp ret_from_exception

ENTRY(lcall7)
	pushfl			# We get a different stack layout with call
				# gates, which has to be cleaned up later..
	pushl %eax
	SAVE_ALL
	movl %esp, %ebp
	pushl %ebp
	pushl $0x7
do_lcall:
	movl EIP(%ebp), %eax	# due to call gates, this is eflags, not eip..
	movl CS(%ebp), %edx	# this is eip..
	movl EFLAGS(%ebp), %ecx	# and this is cs..
	movl %eax,EFLAGS(%ebp)	#
	movl %edx,EIP(%ebp)	# Now we move them to their "normal" places
	movl %ecx,CS(%ebp)	#
	GET_THREAD_INFO_WITH_ESP(%ebp)	# GET_THREAD_INFO
	movl TI_exec_domain(%ebp), %edx	# Get the execution domain
	call *EXEC_DOMAIN_handler(%edx)	# Call the handler for the domain
	addl $4, %esp
	popl %eax
	jmp resume_userspace

ENTRY(lcall27)
	pushfl			# We get a different stack layout with call
				# gates, which has to be cleaned up later..
	pushl %eax
	SAVE_ALL
	movl %esp, %ebp
	pushl %ebp
	pushl $0x27
	jmp do_lcall


ENTRY(ret_from_fork)
	pushl %eax
	call schedule_tail
	GET_THREAD_INFO(%ebp)
	popl %eax
	jmp syscall_exit

/*
 * Return to user mode is not as complex as all this looks,
 * but we want the default path for a system call return to
 * go as quickly as possible which is why some of this is
 * less clear than it otherwise should be.
 */

	# userspace resumption stub bypassing syscall exit tracing
	ALIGN
ret_from_exception:
	preempt_stop
ret_from_intr:
	GET_THREAD_INFO(%ebp)
	movl EFLAGS(%esp), %eax		# mix EFLAGS and CS
	movb CS(%esp), %al
	testl $(VM_MASK | 3), %eax
	jz resume_kernel		# returning to kernel or vm86-space
ENTRY(resume_userspace)
 	cli				# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	movl TI_flags(%ebp), %ecx
	andl $_TIF_WORK_MASK, %ecx	# is there any work to be done on
					# int/exception return?
	jne work_pending
	jmp restore_all

#ifdef CONFIG_PREEMPT
ENTRY(resume_kernel)
	cmpl $0,TI_preempt_count(%ebp)	# non-zero preempt_count ?
	jnz restore_all
need_resched:
	movl TI_flags(%ebp), %ecx	# need_resched set ?
	testb $_TIF_NEED_RESCHED, %cl
	jz restore_all
	testl $IF_MASK,EFLAGS(%esp)     # interrupts off (exception path) ?
	jz restore_all
	movl $PREEMPT_ACTIVE,TI_preempt_count(%ebp)
	sti
	call schedule
	movl $0,TI_preempt_count(%ebp)
	cli
	jmp need_resched
#endif

/* SYSENTER_RETURN points to after the "sysenter" instruction in
   the vsyscall page.  See vsyscall-sysentry.S, which defines the symbol.  */

	# sysenter call handler stub
ENTRY(sysenter_entry)
	movl TSS_sysenter_esp0(%esp),%esp
sysenter_past_esp:
	sti
	pushl $(__USER_DS)
	pushl %ebp
	pushfl
	pushl $(__USER_CS)
	/*
	 * Push current_thread_info()->sysenter_return to the stack.
	 * A tiny bit of offset fixup is necessary - 4*4 means the 4 words
	 * pushed above, and the word being pushed now:
	 */
	pushl (TI_sysenter_return-THREAD_SIZE+4*4)(%esp)
	/*
	 * No six-argument syscall is ever used with sysenter.
	 */
	pushl %eax
	SAVE_ALL
	GET_THREAD_INFO(%ebp)

	testb $(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT),TI_flags(%ebp)
	jnz syscall_trace_entry
	cmpl $(nr_syscalls), %eax
	jae syscall_badsys
	call *sys_call_table(,%eax,4)
	movl %eax,EAX(%esp)
	cli
	movl TI_flags(%ebp), %ecx
	testw $_TIF_ALLWORK_MASK, %cx
	jne syscall_exit_work

#ifdef CONFIG_X86_SWITCH_PAGETABLES

	GET_THREAD_INFO(%ebp)
	movl TI_virtual_stack(%ebp), %edx
	movl TI_user_pgd(%ebp), %ecx
	movl %esp, %ebx
	andl $(THREAD_SIZE-1), %ebx
	orl %ebx, %edx
sysexit_ret_start_marker:
	movl %edx, %esp
	movl %ecx, %cr3
	/*
	 * only ebx is not restored by the userspace sysenter vsyscall
	 * code, it assumes it to be callee-saved.
	 */
	movl EBX(%esp), %ebx
#endif

/* if something modifies registers it must also disable sysexit */
	movl EIP(%esp), %edx
	movl OLDESP(%esp), %ecx
	xorl %ebp,%ebp
	sti
	sysexit
#ifdef CONFIG_X86_SWITCH_PAGETABLES
sysexit_ret_end_marker:
	nop
#endif

	# system call handler stub
ENTRY(system_call)
	pushl %eax			# save orig_eax
	SAVE_ALL
	GET_THREAD_INFO(%ebp)
					# system call tracing in operation
	testb $(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT),TI_flags(%ebp)
	jnz syscall_trace_entry
	cmpl $(nr_syscalls), %eax
	jae syscall_badsys
syscall_call:
	call *sys_call_table(,%eax,4)
	movl %eax,EAX(%esp)		# store the return value
syscall_exit:
	cli				# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	movl TI_flags(%ebp), %ecx
	testw $_TIF_ALLWORK_MASK, %cx	# current->work
	jne syscall_exit_work
restore_all:
	RESTORE_ALL

	# perform work that needs to be done immediately before resumption
	ALIGN
work_pending:
	testb $_TIF_NEED_RESCHED, %cl
	jz work_notifysig
work_resched:
	call schedule
	cli				# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	movl TI_flags(%ebp), %ecx
	andl $_TIF_WORK_MASK, %ecx	# is there any work to be done other
					# than syscall tracing?
	jz restore_all
	testb $_TIF_NEED_RESCHED, %cl
	jnz work_resched

work_notifysig:				# deal with pending signals and
					# notify-resume requests
	testl $VM_MASK, EFLAGS(%esp)
	movl %esp, %eax
	jne work_notifysig_v86		# returning to kernel-space or
					# vm86-space
	xorl %edx, %edx
	call do_notify_resume

#if CONFIG_X86_HIGH_ENTRY
	/*
	 * Reload db7 if necessary:
	 */
	movl TI_flags(%ebp), %ecx
	testb $_TIF_DB7, %cl
	jnz work_db7

	jmp restore_all

work_db7:
	movl TI_task(%ebp), %edx;
	movl task_thread_db7(%edx), %edx;
	movl %edx, %db7;
#endif
	jmp restore_all

	ALIGN
work_notifysig_v86:
	pushl %ecx
	call save_v86_state
	popl %ecx
	movl %eax, %esp
	xorl %edx, %edx
	call do_notify_resume
	jmp restore_all

	# perform syscall exit tracing
	ALIGN
syscall_trace_entry:
	movl $-ENOSYS,EAX(%esp)
	movl %esp, %eax
	xorl %edx,%edx
	call do_syscall_trace
	movl ORIG_EAX(%esp), %eax
	cmpl $(nr_syscalls), %eax
	jnae syscall_call
	jmp syscall_exit

	# perform syscall exit tracing
	ALIGN
syscall_exit_work:
	testb $(_TIF_SYSCALL_TRACE|_TIF_SYSCALL_AUDIT|_TIF_SINGLESTEP), %cl
	jz work_pending
	sti				# could let do_syscall_trace() call
					# schedule() instead
	movl %esp, %eax
	movl $1, %edx
	call do_syscall_trace
	jmp resume_userspace

	ALIGN
syscall_badsys:
	movl $-ENOSYS,EAX(%esp)
	jmp resume_userspace

/*
 * Build the entry stubs and pointer table with
 * some assembler magic.
 */
.data
ENTRY(interrupt)
.previous

vector=0
ENTRY(irq_entries_start)
.rept NR_IRQS
	ALIGN
1:	pushl $vector-256
	jmp common_interrupt
.data
	.long 1b
.previous
vector=vector+1
.endr

	ALIGN
common_interrupt:
	SAVE_ALL
	call do_IRQ
	jmp ret_from_intr

#define BUILD_INTERRUPT(name, nr)	\
ENTRY(name)				\
	pushl $nr-256;			\
	SAVE_ALL			\
	call smp_/**/name;	\
	jmp ret_from_intr;

/* The include is where all of the SMP etc. interrupts come from */
#include "entry_arch.h"

ENTRY(divide_error)
	pushl $0			# no error code
	pushl $do_divide_error
	ALIGN
error_code:
	pushl %ds
	pushl %eax
	xorl %eax, %eax
	pushl %ebp
	pushl %edi
	pushl %esi
	pushl %edx
	decl %eax			# eax = -1
	pushl %ecx
	pushl %ebx
	cld
	movl %es, %ecx
	movl ORIG_EAX(%esp), %esi	# get the error code
	movl ES(%esp), %edi		# get the function address
	movl %eax, ORIG_EAX(%esp)
	movl %ecx, ES(%esp)
	pushl %esi			# push the error code
	movl $(__USER_DS), %edx
	movl %edx, %ds
	movl %edx, %es

/* clobbers edx, ebx and ebp */
	__SWITCH_KERNELSPACE

	leal 4(%esp), %edx		# prepare pt_regs
	pushl %edx			# push pt_regs

	call *%edi
	addl $8, %esp
	jmp ret_from_exception

ENTRY(coprocessor_error)
	pushl $0
	pushl $do_coprocessor_error
	jmp error_code

ENTRY(simd_coprocessor_error)
	pushl $0
	pushl $do_simd_coprocessor_error
	jmp error_code

ENTRY(device_not_available)
	pushl $-1			# mark this as an int
	SAVE_ALL
	movl %cr0, %eax
	testl $0x4, %eax		# EM (math emulation bit)
	jne device_not_available_emulate
	preempt_stop
	call math_state_restore
	jmp ret_from_exception
device_not_available_emulate:
	pushl $0			# temporary storage for ORIG_EIP
	call math_emulate
	addl $4, %esp
	jmp ret_from_exception

/*
 * Debug traps and NMI can happen at the one SYSENTER instruction
 * that sets up the real kernel stack. Check here, since we can't
 * allow the wrong stack to be used.
 *
 * "TSS_sysenter_esp0+12" is because the NMI/debug handler will have
 * already pushed 3 words if it hits on the sysenter instruction:
 * eflags, cs and eip.
 *
 * We just load the right stack, and push the three (known) values
 * by hand onto the new stack - while updating the return eip past
 * the instruction that would have done it for sysenter.
 */
#define FIX_STACK(offset, ok, label)		\
	cmpw $__KERNEL_CS,4(%esp);		\
	jne ok;					\
label:						\
	movl TSS_sysenter_esp0+offset(%esp),%esp;	\
	pushfl;					\
	pushl $__KERNEL_CS;			\
	pushl $sysenter_past_esp

ENTRY(debug)
	cmpl $sysenter_entry,(%esp)
	jne debug_stack_correct
	FIX_STACK(12, debug_stack_correct, debug_esp_fix_insn)
debug_stack_correct:
	pushl $-1			# mark this as an int
	SAVE_ALL
	movl %esp,%edx
  	pushl $0
	pushl %edx
	call do_debug
	addl $8,%esp
	testl %eax,%eax
	jnz restore_all
	jmp ret_from_exception

/*
 * NMI is doubly nasty. It can happen _while_ we're handling
 * a debug fault, and the debug fault hasn't yet been able to
 * clear up the stack. So we first check whether we got  an
 * NMI on the sysenter entry path, but after that we need to
 * check whether we got an NMI on the debug path where the debug
 * fault happened on the sysenter path.
 */
ENTRY(nmi)
	cmpl $sysenter_entry,(%esp)
	je nmi_stack_fixup
	pushl %eax
	movl %esp,%eax
	/* Do not access memory above the end of our stack page,
	 * it might not exist.
	 */
	andl $(THREAD_SIZE-1),%eax
	cmpl $(THREAD_SIZE-20),%eax
	popl %eax
	jae nmi_stack_correct
	cmpl $sysenter_entry,12(%esp)
	je nmi_debug_stack_check
nmi_stack_correct:
	pushl %eax
	SAVE_ALL
	movl %esp, %edx
	pushl $0
	pushl %edx
	call do_nmi
	addl $8, %esp
	jmp restore_all

nmi_stack_fixup:
	FIX_STACK(12,nmi_stack_correct, 1)
	jmp nmi_stack_correct
nmi_debug_stack_check:
	cmpw $__KERNEL_CS,16(%esp)
	jne nmi_stack_correct
	cmpl $debug - 1,(%esp)
	jle nmi_stack_correct
	cmpl $debug_esp_fix_insn,(%esp)
	jle nmi_debug_stack_fixup
nmi_debug_stack_fixup:
	FIX_STACK(24,nmi_stack_correct, 1)
	jmp nmi_stack_correct

ENTRY(int3)
	pushl $-1			# mark this as an int
	SAVE_ALL
	movl %esp,%edx
	pushl $0
	pushl %edx
	call do_int3
	addl $8,%esp
	testl %eax,%eax
	jnz restore_all
	jmp ret_from_exception

ENTRY(overflow)
	pushl $0
	pushl $do_overflow
	jmp error_code

ENTRY(bounds)
	pushl $0
	pushl $do_bounds
	jmp error_code

ENTRY(invalid_op)
	pushl $0
	pushl $do_invalid_op
	jmp error_code

ENTRY(coprocessor_segment_overrun)
	pushl $0
	pushl $do_coprocessor_segment_overrun
	jmp error_code

ENTRY(invalid_TSS)
	pushl $do_invalid_TSS
	jmp error_code

ENTRY(segment_not_present)
	pushl $do_segment_not_present
	jmp error_code

ENTRY(stack_segment)
	pushl $do_stack_segment
	jmp error_code

ENTRY(general_protection)
	pushl $do_general_protection
	jmp error_code

ENTRY(alignment_check)
	pushl $do_alignment_check
	jmp error_code

ENTRY(page_fault)
	pushl $do_page_fault
	jmp error_code

#ifdef CONFIG_X86_MCE
ENTRY(machine_check)
	pushl $0
	pushl machine_check_vector
	jmp error_code
#endif

ENTRY(spurious_interrupt_bug)
	pushl $0
	pushl $do_spurious_interrupt_bug
	jmp error_code

.previous

.data
ENTRY(sys_call_table)
	.long sys_restart_syscall	/* 0 - old "setup()" system call, used for restarting */
	.long sys_exit
	.long sys_fork
	.long sys_read
	.long sys_write
	.long sys_open		/* 5 */
	.long sys_close
	.long sys_waitpid
	.long sys_creat
	.long sys_link
	.long sys_unlink	/* 10 */
	.long sys_execve
	.long sys_chdir
	.long sys_time
	.long sys_mknod
	.long sys_chmod		/* 15 */
	.long sys_lchown16
	.long sys_ni_syscall	/* old break syscall holder */
	.long sys_stat
	.long sys_lseek
	.long sys_getpid	/* 20 */
	.long sys_mount
	.long sys_oldumount
	.long sys_setuid16
	.long sys_getuid16
	.long sys_stime		/* 25 */
	.long sys_ptrace
	.long sys_alarm
	.long sys_fstat
	.long sys_pause
	.long sys_utime		/* 30 */
	.long sys_ni_syscall	/* old stty syscall holder */
	.long sys_ni_syscall	/* old gtty syscall holder */
	.long sys_access
	.long sys_nice
	.long sys_ni_syscall	/* 35 - old ftime syscall holder */
	.long sys_sync
	.long sys_kill
	.long sys_rename
	.long sys_mkdir
	.long sys_rmdir		/* 40 */
	.long sys_dup
	.long sys_pipe
	.long sys_times
	.long sys_ni_syscall	/* old prof syscall holder */
	.long sys_brk		/* 45 */
	.long sys_setgid16
	.long sys_getgid16
	.long sys_signal
	.long sys_geteuid16
	.long sys_getegid16	/* 50 */
	.long sys_acct
	.long sys_umount	/* recycled never used phys() */
	.long sys_ni_syscall	/* old lock syscall holder */
	.long sys_ioctl
	.long sys_fcntl		/* 55 */
	.long sys_ni_syscall	/* old mpx syscall holder */
	.long sys_setpgid
	.long sys_ni_syscall	/* old ulimit syscall holder */
	.long sys_olduname
	.long sys_umask		/* 60 */
	.long sys_chroot
	.long sys_ustat
	.long sys_dup2
	.long sys_getppid
	.long sys_getpgrp	/* 65 */
	.long sys_setsid
	.long sys_sigaction
	.long sys_sgetmask
	.long sys_ssetmask
	.long sys_setreuid16	/* 70 */
	.long sys_setregid16
	.long sys_sigsuspend
	.long sys_sigpending
	.long sys_sethostname
	.long sys_setrlimit	/* 75 */
	.long sys_old_getrlimit
	.long sys_getrusage
	.long sys_gettimeofday
	.long sys_settimeofday
	.long sys_getgroups16	/* 80 */
	.long sys_setgroups16
	.long old_select
	.long sys_symlink
	.long sys_lstat
	.long sys_readlink	/* 85 */
	.long sys_uselib
	.long sys_swapon
	.long sys_reboot
	.long old_readdir
	.long old_mmap		/* 90 */
	.long sys_munmap
	.long sys_truncate
	.long sys_ftruncate
	.long sys_fchmod
	.long sys_fchown16	/* 95 */
	.long sys_getpriority
	.long sys_setpriority
	.long sys_ni_syscall	/* old profil syscall holder */
	.long sys_statfs
	.long sys_fstatfs	/* 100 */
	.long sys_ioperm
	.long sys_socketcall
	.long sys_syslog
	.long sys_setitimer
	.long sys_getitimer	/* 105 */
	.long sys_newstat
	.long sys_newlstat
	.long sys_newfstat
	.long sys_uname
	.long sys_iopl		/* 110 */
	.long sys_vhangup
	.long sys_ni_syscall	/* old "idle" system call */
	.long sys_vm86old
	.long sys_wait4
	.long sys_swapoff	/* 115 */
	.long sys_sysinfo
	.long sys_ipc
	.long sys_fsync
	.long sys_sigreturn
	.long sys_clone		/* 120 */
	.long sys_setdomainname
	.long sys_newuname
	.long sys_modify_ldt
	.long sys_adjtimex
	.long sys_mprotect	/* 125 */
	.long sys_sigprocmask
	.long sys_ni_syscall	/* old "create_module" */ 
	.long sys_init_module
	.long sys_delete_module
	.long sys_ni_syscall	/* 130:	old "get_kernel_syms" */
	.long sys_quotactl
	.long sys_getpgid
	.long sys_fchdir
	.long sys_bdflush
	.long sys_sysfs		/* 135 */
	.long sys_personality
	.long sys_ni_syscall	/* reserved for afs_syscall */
	.long sys_setfsuid16
	.long sys_setfsgid16
	.long sys_llseek	/* 140 */
	.long sys_getdents
	.long sys_select
	.long sys_flock
	.long sys_msync
	.long sys_readv		/* 145 */
	.long sys_writev
	.long sys_getsid
	.long sys_fdatasync
	.long sys_sysctl
	.long sys_mlock		/* 150 */
	.long sys_munlock
	.long sys_mlockall
	.long sys_munlockall
	.long sys_sched_setparam
	.long sys_sched_getparam   /* 155 */
	.long sys_sched_setscheduler
	.long sys_sched_getscheduler
	.long sys_sched_yield
	.long sys_sched_get_priority_max
	.long sys_sched_get_priority_min  /* 160 */
	.long sys_sched_rr_get_interval
	.long sys_nanosleep
	.long sys_mremap
	.long sys_setresuid16
	.long sys_getresuid16	/* 165 */
	.long sys_vm86
	.long sys_ni_syscall	/* Old sys_query_module */
	.long sys_poll
	.long sys_nfsservctl
	.long sys_setresgid16	/* 170 */
	.long sys_getresgid16
	.long sys_prctl
	.long sys_rt_sigreturn
	.long sys_rt_sigaction
	.long sys_rt_sigprocmask	/* 175 */
	.long sys_rt_sigpending
	.long sys_rt_sigtimedwait
	.long sys_rt_sigqueueinfo
	.long sys_rt_sigsuspend
	.long sys_pread64	/* 180 */
	.long sys_pwrite64
	.long sys_chown16
	.long sys_getcwd
	.long sys_capget
	.long sys_capset	/* 185 */
	.long sys_sigaltstack
	.long sys_sendfile
	.long sys_ni_syscall	/* reserved for streams1 */
	.long sys_ni_syscall	/* reserved for streams2 */
	.long sys_vfork		/* 190 */
	.long sys_getrlimit
	.long sys_mmap2
	.long sys_truncate64
	.long sys_ftruncate64
	.long sys_stat64	/* 195 */
	.long sys_lstat64
	.long sys_fstat64
	.long sys_lchown
	.long sys_getuid
	.long sys_getgid	/* 200 */
	.long sys_geteuid
	.long sys_getegid
	.long sys_setreuid
	.long sys_setregid
	.long sys_getgroups	/* 205 */
	.long sys_setgroups
	.long sys_fchown
	.long sys_setresuid
	.long sys_getresuid
	.long sys_setresgid	/* 210 */
	.long sys_getresgid
	.long sys_chown
	.long sys_setuid
	.long sys_setgid
	.long sys_setfsuid	/* 215 */
	.long sys_setfsgid
	.long sys_pivot_root
	.long sys_mincore
	.long sys_madvise
	.long sys_getdents64	/* 220 */
	.long sys_fcntl64
#ifdef CONFIG_TUX
	.long __sys_tux
#else
# ifdef CONFIG_TUX_MODULE
	.long sys_tux
# else
	.long sys_ni_syscall
# endif
#endif
	.long sys_ni_syscall
	.long sys_gettid
	.long sys_readahead	/* 225 */
	.long sys_setxattr
	.long sys_lsetxattr
	.long sys_fsetxattr
	.long sys_getxattr
	.long sys_lgetxattr	/* 230 */
	.long sys_fgetxattr
	.long sys_listxattr
	.long sys_llistxattr
	.long sys_flistxattr
	.long sys_removexattr	/* 235 */
	.long sys_lremovexattr
	.long sys_fremovexattr
	.long sys_tkill
	.long sys_sendfile64
	.long sys_futex		/* 240 */
	.long sys_sched_setaffinity
	.long sys_sched_getaffinity
	.long sys_set_thread_area
	.long sys_get_thread_area
	.long sys_io_setup	/* 245 */
	.long sys_io_destroy
	.long sys_io_getevents
	.long sys_io_submit
	.long sys_io_cancel
	.long sys_fadvise64	/* 250 */
	.long sys_ni_syscall
	.long sys_exit_group
	.long sys_lookup_dcookie
	.long sys_epoll_create
	.long sys_epoll_ctl	/* 255 */
	.long sys_epoll_wait
 	.long sys_remap_file_pages
 	.long sys_set_tid_address
 	.long sys_timer_create
 	.long sys_timer_settime		/* 260 */
 	.long sys_timer_gettime
 	.long sys_timer_getoverrun
 	.long sys_timer_delete
 	.long sys_clock_settime
 	.long sys_clock_gettime		/* 265 */
 	.long sys_clock_getres
 	.long sys_clock_nanosleep
	.long sys_statfs64
	.long sys_fstatfs64	
	.long sys_tgkill	/* 270 */
	.long sys_utimes
 	.long sys_fadvise64_64
	.long sys_ni_syscall	/* sys_vserver */
	.long sys_mbind
	.long sys_get_mempolicy
	.long sys_set_mempolicy
	.long sys_mq_open
	.long sys_mq_unlink
	.long sys_mq_timedsend
	.long sys_mq_timedreceive	/* 280 */
	.long sys_mq_notify
	.long sys_mq_getsetattr
	.long sys_ni_syscall		/* reserved for kexec */
	.long sys_waitid
	.long sys_ni_syscall		/* 285 */ /* available */
	.long sys_add_key
	.long sys_request_key
	.long sys_keyctl

syscall_table_size=(.-sys_call_table)

/*
 *  linux/arch/i386/traps.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

/*
 * 'Traps.c' handles hardware traps and faults after we have saved some
 * state in 'asm.s'.
 */
#include <linux/config.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/kprobes.h>

#ifdef CONFIG_EISA
#include <linux/ioport.h>
#include <linux/eisa.h>
#endif

#ifdef CONFIG_MCA
#include <linux/mca.h>
#endif

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/debugreg.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/nmi.h>

#include <asm/smp.h>
#include <asm/arch_hooks.h>
#include <asm/kdebug.h>

#include <linux/irq.h>
#include <linux/module.h>

#include "mach_traps.h"

struct desc_struct default_ldt[] __attribute__((__section__(".data.default_ldt"))) = { { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 } };
struct page *default_ldt_page;

/* Do we ignore FPU interrupts ? */
char ignore_fpu_irq = 0;

/*
 * The IDT has to be page-aligned to simplify the Pentium
 * F0 0F bug workaround.. We have a special link segment
 * for this.
 */
struct desc_struct idt_table[256] __attribute__((__section__(".data.idt"))) = { {0, 0}, };

asmlinkage void divide_error(void);
asmlinkage void debug(void);
asmlinkage void nmi(void);
asmlinkage void int3(void);
asmlinkage void overflow(void);
asmlinkage void bounds(void);
asmlinkage void invalid_op(void);
asmlinkage void device_not_available(void);
asmlinkage void coprocessor_segment_overrun(void);
asmlinkage void invalid_TSS(void);
asmlinkage void segment_not_present(void);
asmlinkage void stack_segment(void);
asmlinkage void general_protection(void);
asmlinkage void page_fault(void);
asmlinkage void coprocessor_error(void);
asmlinkage void simd_coprocessor_error(void);
asmlinkage void alignment_check(void);
asmlinkage void spurious_interrupt_bug(void);
asmlinkage void machine_check(void);

static int kstack_depth_to_print = 24;
struct notifier_block *i386die_chain;
static spinlock_t die_notifier_lock = SPIN_LOCK_UNLOCKED;

int register_die_notifier(struct notifier_block *nb)
{
	int err = 0;
	unsigned long flags;
	spin_lock_irqsave(&die_notifier_lock, flags);
	err = notifier_chain_register(&i386die_chain, nb);
	spin_unlock_irqrestore(&die_notifier_lock, flags);
	return err;
}

static inline int valid_stack_ptr(struct thread_info *tinfo, void *p)
{
	return	p > (void *)tinfo &&
		p < (void *)tinfo + THREAD_SIZE - 3;
}

static inline unsigned long print_context_stack(struct thread_info *tinfo,
				unsigned long *stack, unsigned long ebp)
{
	unsigned long addr;

#ifdef	CONFIG_FRAME_POINTER
	while (valid_stack_ptr(tinfo, (void *)ebp)) {
		addr = *(unsigned long *)(ebp + 4);
		printk(" [<%08lx>] ", addr);
		print_symbol("%s", addr);
		printk("\n");
		ebp = *(unsigned long *)ebp;
	}
#else
	while (valid_stack_ptr(tinfo, stack)) {
		addr = *stack++;
		if (__kernel_text_address(addr)) {
			printk(" [<%08lx>]", addr);
			print_symbol(" %s", addr);
			printk("\n");
		}
	}
#endif
	return ebp;
}

void show_trace(struct task_struct *task, unsigned long * stack)
{
	unsigned long ebp;

	if (!task)
		task = current;

	if (task == current) {
		/* Grab ebp right from our regs */
		asm ("movl %%ebp, %0" : "=r" (ebp) : );
	} else {
		/* ebp is the last reg pushed by switch_to */
		ebp = *(unsigned long *) task->thread.esp;
	}

	while (1) {
		struct thread_info *context;
		context = (struct thread_info *)
			((unsigned long)stack & (~(THREAD_SIZE - 1)));
		ebp = print_context_stack(context, stack, ebp);
		stack = (unsigned long*)context->previous_esp;
		if (!stack)
			break;
		printk(" =======================\n");
	}
}

void show_stack(struct task_struct *task, unsigned long *esp)
{
	unsigned long *stack;
	int i;

	if (esp == NULL) {
		if (task)
			esp = (unsigned long*)task->thread.esp;
		else
			esp = (unsigned long *)&esp;
	}

	stack = esp;
	for(i = 0; i < kstack_depth_to_print; i++) {
		if (kstack_end(stack))
			break;
		if (i && ((i % 8) == 0))
			printk("\n       ");
		printk("%08lx ", *stack++);
	}
	printk("\nCall Trace:\n");
	show_trace(task, esp);
}

/*
 * The architecture-independent dump_stack generator
 */
void dump_stack(void)
{
	unsigned long stack;

	show_trace(current, &stack);
}

EXPORT_SYMBOL(dump_stack);

void show_registers(struct pt_regs *regs)
{
	int i;
	int in_kernel = 1;
	unsigned long esp;
	unsigned short ss;

	esp = (unsigned long) (&regs->esp);
	ss = __KERNEL_DS;
	if (regs->xcs & 3) {
		in_kernel = 0;
		esp = regs->esp;
		ss = regs->xss & 0xffff;
	}
	print_modules();
	printk("CPU:    %d\nEIP:    %04x:[<%08lx>]    %s VLI\nEFLAGS: %08lx"
			"   (%s) \n",
		smp_processor_id(), 0xffff & regs->xcs, regs->eip,
		print_tainted(), regs->eflags, UTS_RELEASE);
	print_symbol("EIP is at %s\n", regs->eip);
	printk("eax: %08lx   ebx: %08lx   ecx: %08lx   edx: %08lx\n",
		regs->eax, regs->ebx, regs->ecx, regs->edx);
	printk("esi: %08lx   edi: %08lx   ebp: %08lx   esp: %08lx\n",
		regs->esi, regs->edi, regs->ebp, esp);
	printk("ds: %04x   es: %04x   ss: %04x\n",
		regs->xds & 0xffff, regs->xes & 0xffff, ss);
	printk("Process %s (pid: %d, threadinfo=%p task=%p)",
		current->comm, current->pid, current_thread_info(), current);
	/*
	 * When in-kernel, we also print out the stack and code at the
	 * time of the fault..
	 */
	if (in_kernel) {
		u8 *eip;

		printk("\nStack: ");
		show_stack(NULL, (unsigned long*)esp);

		printk("Code: ");

		eip = (u8 *)regs->eip - 43;
		for (i = 0; i < 64; i++, eip++) {
			unsigned char c;

			if (eip < (u8 *)PAGE_OFFSET || __direct_get_user(c, eip)) {
				printk(" Bad EIP value.");
				break;
			}
			if (eip == (u8 *)regs->eip)
				printk("<%02x> ", c);
			else
				printk("%02x ", c);
		}
	}
	printk("\n");
}	

static void handle_BUG(struct pt_regs *regs)
{
	unsigned short ud2;
	unsigned short line;
	char *file;
	char c;
	unsigned long eip;

	if (regs->xcs & 3)
		goto no_bug;		/* Not in kernel */

	eip = regs->eip;

	if (__direct_get_user(ud2, (unsigned short *)eip))
		goto no_bug;
	if (ud2 != 0x0b0f)
		goto no_bug;
	if (__direct_get_user(line, (unsigned short *)(eip + 2)))
		goto bug;
	if (__direct_get_user(file, (char **)(eip + 4)) ||
			__direct_get_user(c, file))
		file = "<bad filename>";

	printk("------------[ cut here ]------------\n");
	printk(KERN_ALERT "kernel BUG at %s:%d!\n", file, line);

no_bug:
	return;

	/* Here we know it was a BUG but file-n-line is unavailable */
bug:
	printk("Kernel BUG\n");
}

void die(const char * str, struct pt_regs * regs, long err)
{
	static struct {
		spinlock_t lock;
		u32 lock_owner;
		int lock_owner_depth;
	} die = {
		.lock =			SPIN_LOCK_UNLOCKED,
		.lock_owner =		-1,
		.lock_owner_depth =	0
	};
	static int die_counter;

	if (die.lock_owner != smp_processor_id()) {
		console_verbose();
		spin_lock_irq(&die.lock);
		die.lock_owner = smp_processor_id();
		die.lock_owner_depth = 0;
		bust_spinlocks(1);
	}

	if (++die.lock_owner_depth < 3) {
		int nl = 0;
		handle_BUG(regs);
		printk(KERN_ALERT "%s: %04lx [#%d]\n", str, err & 0xffff, ++die_counter);
#ifdef CONFIG_PREEMPT
		printk("PREEMPT ");
		nl = 1;
#endif
#ifdef CONFIG_SMP
		printk("SMP ");
		nl = 1;
#endif
#ifdef CONFIG_DEBUG_PAGEALLOC
		printk("DEBUG_PAGEALLOC");
		nl = 1;
#endif
		if (nl)
			printk("\n");
	notify_die(DIE_OOPS, (char *)str, regs, err, 255, SIGSEGV);
		show_registers(regs);
		try_crashdump(regs);
  	} else
		printk(KERN_ERR "Recursive die() failure, output suppressed\n");

	bust_spinlocks(0);
	die.lock_owner = -1;
	spin_unlock_irq(&die.lock);
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
}

static inline void die_if_kernel(const char * str, struct pt_regs * regs, long err)
{
	if (!(regs->eflags & VM_MASK) && !(3 & regs->xcs))
		die(str, regs, err);
}

static inline unsigned long get_cr2(void)
{
	unsigned long address;

	/* get the address */
	__asm__("movl %%cr2,%0":"=r" (address));
	return address;
}

/*
 * When we get an exception in the iret instructions in entry.S, whatever
 * fault it is really belongs to the user state we are restoring.  We want
 * to turn it into a signal.  To make that signal's info exactly match what
 * this same kind of fault in a user instruction would show, the fixup
 * needs to know the trapno and error code.  But those are lost when we get
 * back to the fixup entrypoint.  So we have a special case for the iret
 * fixups, and generate the signal here like a normal user trap would.
 * Then the fixup code restores the pt_regs on the base of the stack to
 * the bogus user state it was trying to return to, before handling the signal.
 */
extern void iret_exc(void);	/* entry.S label for code in .fixup */
static inline int is_iret(struct pt_regs *regs)
{
	return (regs->eip == (unsigned long)&iret_exc);
}

/*
 * If the iret was actually trying to return to kernel mode,
 * that should be an oops.
 */
static inline int iret_to_user(struct pt_regs *regs)
{
	/*
	 * The frame being restored was all popped off and restored except
	 * the last five words that iret pops.  Instead of popping, it
	 * pushed another trap frame, clobbering the part of the old one
	 * that we had already restored.  So the restored registers are now
	 * all back in the new trap frame, but the eip et al show the
	 * in-kernel state at the iret instruction.  The bad state we tried
	 * to restore with iret is still on the stack, right below our
	 * current trap frame.  The current trap frame was for an in-kernel
	 * trap, and so doesn't include the esp and ss words--so &regs->esp
	 * is where %esp was before the iret.
	 */
	struct pt_regs *oregs = container_of(&regs->esp, struct pt_regs, eip);

	return likely((oregs->xcs & 3) == 3);
}

static inline void do_trap(int trapnr, int signr, char *str, int vm86,
			   struct pt_regs * regs, long error_code, siginfo_t *info)
{
	if (regs->eflags & VM_MASK) {
		if (vm86)
			goto vm86_trap;
		goto trap_signal;
	}

	if (!(regs->xcs & 3))
		goto kernel_trap;

	trap_signal: {
		struct task_struct *tsk = current;
		tsk->thread.error_code = error_code;
		tsk->thread.trap_no = trapnr;
		if (info)
			force_sig_info(signr, info, tsk);
		else
			force_sig(signr, tsk);
		return;
	}

	kernel_trap: {
		if (!fixup_exception(regs)) {
		die:
			die(str, regs, error_code);
		}
		else if (is_iret(regs)) {
			if (!iret_to_user(regs))
				goto die;
			local_irq_enable();
			goto trap_signal;
		}
		return;
	}

	vm86_trap: {
		int ret = handle_vm86_trap((struct kernel_vm86_regs *) regs, error_code, trapnr);
		if (ret) goto trap_signal;
		return;
	}
}

#define DO_ERROR(trapnr, signr, str, name) \
asmlinkage void do_##name(struct pt_regs * regs, long error_code) \
{ \
	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, signr) \
						== NOTIFY_STOP) \
		return; \
	do_trap(trapnr, signr, str, 0, regs, error_code, NULL); \
}

#define DO_ERROR_INFO(trapnr, signr, str, name, sicode, siaddr) \
asmlinkage void do_##name(struct pt_regs * regs, long error_code) \
{ \
	siginfo_t info; \
	info.si_signo = signr; \
	info.si_errno = 0; \
	info.si_code = sicode; \
	info.si_addr = (void __user *)siaddr; \
	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, signr) \
						== NOTIFY_STOP) \
		return; \
	do_trap(trapnr, signr, str, 0, regs, error_code, &info); \
}

#define DO_VM86_ERROR(trapnr, signr, str, name) \
asmlinkage void do_##name(struct pt_regs * regs, long error_code) \
{ \
	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, signr) \
						== NOTIFY_STOP) \
		return; \
	do_trap(trapnr, signr, str, 1, regs, error_code, NULL); \
}

#define DO_VM86_ERROR_INFO(trapnr, signr, str, name, sicode, siaddr) \
asmlinkage void do_##name(struct pt_regs * regs, long error_code) \
{ \
	siginfo_t info; \
	info.si_signo = signr; \
	info.si_errno = 0; \
	info.si_code = sicode; \
	info.si_addr = (void __user *)siaddr; \
	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, signr) \
						== NOTIFY_STOP) \
		return; \
	do_trap(trapnr, signr, str, 1, regs, error_code, &info); \
}

DO_VM86_ERROR_INFO( 0, SIGFPE,  "divide error", divide_error, FPE_INTDIV, regs->eip)
#ifndef CONFIG_KPROBES
DO_VM86_ERROR( 3, SIGTRAP, "int3", int3)
#endif
DO_VM86_ERROR( 4, SIGSEGV, "overflow", overflow)
DO_VM86_ERROR( 5, SIGSEGV, "bounds", bounds)
DO_ERROR_INFO( 6, SIGILL,  "invalid operand", invalid_op, ILL_ILLOPN, regs->eip)
DO_ERROR( 9, SIGFPE,  "coprocessor segment overrun", coprocessor_segment_overrun)
DO_ERROR(10, SIGSEGV, "invalid TSS", invalid_TSS)
DO_ERROR(11, SIGBUS,  "segment not present", segment_not_present)
DO_ERROR(12, SIGBUS,  "stack segment", stack_segment)
DO_ERROR_INFO(17, SIGBUS, "alignment check", alignment_check, BUS_ADRALN, 0)

/*
 * the original non-exec stack patch was written by
 * Solar Designer <solar at openwall.com>. Thanks!
 */
asmlinkage void do_general_protection(struct pt_regs * regs, long error_code)
{
	int cpu = get_cpu();
	struct tss_struct *tss = init_tss+ cpu;
	struct thread_struct *thread = &current->thread;

	/*
	 * Perform the lazy TSS's I/O bitmap copy. If the TSS has an
	 * invalid offset set (the LAZY one) and the faulting thread has
	 * a valid I/O bitmap pointer, we copy the I/O bitmap in the TSS
	 * and we set the offset field correctly. Then we let the CPU to
	 * restart the faulting instruction.
	 */
	if (tss->io_bitmap_base == INVALID_IO_BITMAP_OFFSET_LAZY &&
	    thread->io_bitmap_ptr) {
		memcpy(tss->io_bitmap, thread->io_bitmap_ptr,
		       thread->io_bitmap_max);
		/*
		 * If the previously set map was extending to higher ports
		 * than the current one, pad extra space with 0xff (no access).
		 */
		if (thread->io_bitmap_max < tss->io_bitmap_max)
			memset((char *) tss->io_bitmap +
				thread->io_bitmap_max, 0xff,
				tss->io_bitmap_max - thread->io_bitmap_max);
		tss->io_bitmap_max = thread->io_bitmap_max;
		tss->io_bitmap_base = IO_BITMAP_OFFSET;
		put_cpu();
		return;
	}
	put_cpu();

	if (regs->eflags & VM_MASK)
		goto gp_in_vm86;

	if (!(regs->xcs & 3))
		goto gp_in_kernel;

gp_in_user:
	/*
	 * lazy-check for CS validity on exec-shield binaries:
	 */
	if (current->mm) {
		int cpu = smp_processor_id();
		struct desc_struct *desc1, *desc2;
		struct vm_area_struct *vma;
		unsigned long limit = 0;
		
		spin_lock(&current->mm->page_table_lock);
		for (vma = current->mm->mmap; vma; vma = vma->vm_next)
			if ((vma->vm_flags & VM_EXEC) && (vma->vm_end > limit))
				limit = vma->vm_end;
		spin_unlock(&current->mm->page_table_lock);

		current->mm->context.exec_limit = limit;
		set_user_cs(&current->mm->context.user_cs, limit);

		desc1 = &current->mm->context.user_cs;
		desc2 = cpu_gdt_table[cpu] + GDT_ENTRY_DEFAULT_USER_CS;

		/*
		 * The CS was not in sync - reload it and retry the
		 * instruction. If the instruction still faults then
		 * we wont hit this branch next time around.
		 */
		if (desc1->a != desc2->a || desc1->b != desc2->b) {
			if (print_fatal_signals >= 2) {
				printk("#GPF fixup (%ld[seg:%lx]) at %08lx, CPU#%d.\n", error_code, error_code/8, regs->eip, smp_processor_id());
				printk(" exec_limit: %08lx, user_cs: %08lx/%08lx, CPU_cs: %08lx/%08lx.\n", current->mm->context.exec_limit, desc1->a, desc1->b, desc2->a, desc2->b);
			}
			load_user_cs_desc(cpu, current->mm);
			return;
		}
	}
	if (print_fatal_signals) {
		printk("#GPF(%ld[seg:%lx]) at %08lx, CPU#%d.\n", error_code, error_code/8, regs->eip, smp_processor_id());
		printk(" exec_limit: %08lx, user_cs: %08lx/%08lx.\n", current->mm->context.exec_limit, current->mm->context.user_cs.a, current->mm->context.user_cs.b);
	}

	current->thread.error_code = error_code;
	current->thread.trap_no = 13;
	force_sig(SIGSEGV, current);
	return;

gp_in_vm86:
	local_irq_enable();
	handle_vm86_fault((struct kernel_vm86_regs *) regs, error_code);
	return;

gp_in_kernel:
	if (!fixup_exception(regs)) {
	die:
		if (notify_die(DIE_GPF, "general protection fault", regs,
				error_code, 13, SIGSEGV) == NOTIFY_STOP)
			return;
		die("general protection fault", regs, error_code);
	}
	else if (is_iret(regs)) {
		if (!iret_to_user(regs))
			goto die;
		local_irq_enable();
		goto gp_in_user;
	}
}

static void mem_parity_error(unsigned char reason, struct pt_regs * regs)
{
	printk("Uhhuh. NMI received. Dazed and confused, but trying to continue\n");
	printk("You probably have a hardware problem with your RAM chips\n");
	if (panic_on_unrecovered_nmi)
		panic("NMI: Not continuing");

	/* Clear and disable the memory parity error line. */
	clear_mem_error(reason);
}

static void io_check_error(unsigned char reason, struct pt_regs * regs)
{
	unsigned long i;

	printk("NMI: IOCK error (debug interrupt?)\n");
	show_registers(regs);

	/* Re-enable the IOCK line, wait for a few seconds */
	reason = (reason & 0xf) | 8;
	outb(reason, 0x61);
	i = 2000;
	while (--i) udelay(1000);
	reason &= ~8;
	outb(reason, 0x61);
}

static void unknown_nmi_error(unsigned char reason, struct pt_regs * regs)
{
#ifdef CONFIG_MCA
	/* Might actually be able to figure out what the guilty party
	* is. */
	if( MCA_bus ) {
		mca_handle_nmi();
		return;
	}
#endif
	printk("Uhhuh. NMI received for unknown reason %02x on CPU %d.\n",
		reason, smp_processor_id());
	printk("Dazed and confused, but trying to continue\n");
	printk("Do you have a strange power saving mode enabled?\n");

	if (panic_on_unrecovered_nmi)
                panic("NMI: Not continuing");

}

static spinlock_t nmi_print_lock = SPIN_LOCK_UNLOCKED;

void die_nmi (struct pt_regs *regs, const char *msg)
{
	spin_lock(&nmi_print_lock);
	/*
	* We are in trouble anyway, lets at least try
	* to get a message out.
	*/
	bust_spinlocks(1);
	printk(msg);
	printk(" on CPU%d, eip %08lx, registers:\n",
		smp_processor_id(), regs->eip);
	show_registers(regs);
	try_crashdump(regs);
	printk("console shuts up ...\n");
	console_silent();
	spin_unlock(&nmi_print_lock);
	bust_spinlocks(0);
	do_exit(SIGSEGV);
}

static void default_do_nmi(struct pt_regs * regs)
{
	unsigned char reason = get_nmi_reason();
	int cpu =  smp_processor_id();
 
	if (!(reason & 0xc0)) {
		if (notify_die(DIE_NMI_IPI, "nmi_ipi", regs, reason, 0, SIGINT)
							== NOTIFY_STOP)
			return;
		/*
		 * Ok, so this is none of the documented NMI sources,
		 * so it must be the NMI watchdog.
		 */
		if (nmi_watchdog_tick(regs))
			return;
		if (!do_nmi_callback(regs, cpu))
			unknown_nmi_error(reason, regs);
		return;
	}
	if (notify_die(DIE_NMI, "nmi", regs, reason, 0, SIGINT) == NOTIFY_STOP)
		return;
	if (reason & 0x80)
		mem_parity_error(reason, regs);
	if (reason & 0x40)
		io_check_error(reason, regs);
	/*
	 * Reassert NMI in case it became active meanwhile
	 * as it's edge-triggered.
	 */
	reassert_nmi();
}

static int dummy_nmi_callback(struct pt_regs * regs, int cpu)
{
	return 0;
}
 
static nmi_callback_t nmi_callback = dummy_nmi_callback;
 
asmlinkage void do_nmi(struct pt_regs * regs, long error_code)
{
	int cpu;

	nmi_enter();

	cpu = smp_processor_id();
	++nmi_count(cpu);

	if (!nmi_callback(regs, cpu))
		default_do_nmi(regs);

	nmi_exit();
}

void set_nmi_callback(nmi_callback_t callback)
{
	nmi_callback = callback;
}

void unset_nmi_callback(void)
{
	nmi_callback = dummy_nmi_callback;
}

#ifdef CONFIG_KPROBES
asmlinkage int do_int3(struct pt_regs *regs, long error_code)
{
	if (notify_die(DIE_INT3, "int3", regs, error_code, 3, SIGTRAP)
			== NOTIFY_STOP)
		return 1;
	/* This is an interrupt gate, because kprobes wants interrupts
	disabled.  Normal trap handlers don't. */
	restore_interrupts(regs);
	do_trap(3, SIGTRAP, "int3", 1, regs, error_code, NULL);
	return 0;
}
#endif

/*
 * Our handling of the processor debug registers is non-trivial.
 * We do not clear them on entry and exit from the kernel. Therefore
 * it is possible to get a watchpoint trap here from inside the kernel.
 * However, the code in ./ptrace.c has ensured that the user can
 * only set watchpoints on userspace addresses. Therefore the in-kernel
 * watchpoint trap can only occur in code which is reading/writing
 * from user space. Such code must not hold kernel locks (since it
 * can equally take a page fault), therefore it is safe to call
 * force_sig_info even though that claims and releases locks.
 * 
 * Code in ./signal.c ensures that the debug control register
 * is restored before we deliver any signal, and therefore that
 * user code runs with the correct debug control register even though
 * we clear it here.
 *
 * Being careful here means that we don't have to be as careful in a
 * lot of more complicated places (task switching can be a bit lazy
 * about restoring all the debug state, and ptrace doesn't have to
 * find every occurrence of the TF bit that could be saved away even
 * by user code)
 */
asmlinkage void do_debug(struct pt_regs * regs, long error_code)
{
	unsigned int condition;
	struct task_struct *tsk = current;
	siginfo_t info;

	__asm__ __volatile__("movl %%db6,%0" : "=r" (condition));

	if (notify_die(DIE_DEBUG, "debug", regs, condition, error_code,
					SIGTRAP) == NOTIFY_STOP)
		return;
	/* It's safe to allow irq's after DR6 has been saved */
	if (regs->eflags & X86_EFLAGS_IF)
		local_irq_enable();

	/*
	 * Mask out spurious debug traps due to lazy DR7 setting or
	 * due to 4G/4G kernel mode:
	 */
	if (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3)) {
		if (!tsk->thread.debugreg[7])
			goto clear_dr7;
		if (!user_mode(regs)) {
			// restore upon return-to-userspace:
			set_thread_flag(TIF_DB7);
			goto clear_dr7;
		}
	}

	if (regs->eflags & VM_MASK)
		goto debug_vm86;

	/* Save debug status register where ptrace can see it */
	tsk->thread.debugreg[6] = condition;

	/* Mask out spurious TF errors due to lazy TF clearing */
	if (condition & DR_STEP) {
		/*
		 * The TF error should be masked out only if the current
		 * process is not traced and if the TRAP flag has been set
		 * previously by a tracing process (condition detected by
		 * the PT_DTRACE flag); remember that the i386 TRAP flag
		 * can be modified by the process itself in user mode,
		 * allowing programs to debug themselves without the ptrace()
		 * interface.
		 */
		if ((regs->xcs & 3) == 0)
			goto clear_TF_reenable;
		if ((tsk->ptrace & (PT_DTRACE|PT_PTRACED)) == PT_DTRACE)
			goto clear_TF;
	}

	/* Ok, finally something we can handle */
	tsk->thread.trap_no = 1;
	tsk->thread.error_code = error_code;
	info.si_signo = SIGTRAP;
	info.si_errno = 0;
	info.si_code = TRAP_BRKPT;
	
	/* If this is a kernel mode trap, save the user PC on entry to 
	 * the kernel, that's what the debugger can make sense of.
	 */
	info.si_addr = ((regs->xcs & 3) == 0) ? (void __user *)tsk->thread.eip
	                                      : (void __user *)regs->eip;
	force_sig_info(SIGTRAP, &info, tsk);

	/* Disable additional traps. They'll be re-enabled when
	 * the signal is delivered.
	 */
clear_dr7:
	__asm__("movl %0,%%db7"
		: /* no output */
		: "r" (0));
	return;

debug_vm86:
	handle_vm86_trap((struct kernel_vm86_regs *) regs, error_code, 1);
	return;

clear_TF_reenable:
	set_tsk_thread_flag(tsk, TIF_SINGLESTEP);
clear_TF:
	regs->eflags &= ~TF_MASK;
	return;
}

/*
 * Note that we play around with the 'TS' bit in an attempt to get
 * the correct behaviour even in the presence of the asynchronous
 * IRQ13 behaviour
 */
void math_error(void __user *eip)
{
	struct task_struct * task;
	siginfo_t info;
	unsigned short cwd, swd;

	/*
	 * Save the info for the exception handler and clear the error.
	 */
	task = current;
	save_init_fpu(task);
	task->thread.trap_no = 16;
	task->thread.error_code = 0;
	info.si_signo = SIGFPE;
	info.si_errno = 0;
	info.si_code = __SI_FAULT;
	info.si_addr = eip;
	/*
	 * (~cwd & swd) will mask out exceptions that are not set to unmasked
	 * status.  0x3f is the exception bits in these regs, 0x200 is the
	 * C1 reg you need in case of a stack fault, 0x040 is the stack
	 * fault bit.  We should only be taking one exception at a time,
	 * so if this combination doesn't produce any single exception,
	 * then we have a bad program that isn't syncronizing its FPU usage
	 * and it will suffer the consequences since we won't be able to
	 * fully reproduce the context of the exception
	 */
	cwd = get_fpu_cwd(task);
	swd = get_fpu_swd(task);
	switch (((~cwd) & swd & 0x3f) | (swd & 0x240)) {
		case 0x000:
		default:
			break;
		case 0x001: /* Invalid Op */
		case 0x041: /* Stack Fault */
		case 0x241: /* Stack Fault | Direction */
			info.si_code = FPE_FLTINV;
			/* Should we clear the SF or let user space do it ???? */
			break;
		case 0x002: /* Denormalize */
		case 0x010: /* Underflow */
			info.si_code = FPE_FLTUND;
			break;
		case 0x004: /* Zero Divide */
			info.si_code = FPE_FLTDIV;
			break;
		case 0x008: /* Overflow */
			info.si_code = FPE_FLTOVF;
			break;
		case 0x020: /* Precision */
			info.si_code = FPE_FLTRES;
			break;
	}
	force_sig_info(SIGFPE, &info, task);
}

asmlinkage void do_coprocessor_error(struct pt_regs * regs, long error_code)
{
	ignore_fpu_irq = 1;
	math_error((void __user *)regs->eip);
}

void simd_math_error(void __user *eip)
{
	struct task_struct * task;
	siginfo_t info;
	unsigned short mxcsr;

	/*
	 * Save the info for the exception handler and clear the error.
	 */
	task = current;
	save_init_fpu(task);
	task->thread.trap_no = 19;
	task->thread.error_code = 0;
	info.si_signo = SIGFPE;
	info.si_errno = 0;
	info.si_code = __SI_FAULT;
	info.si_addr = eip;
	/*
	 * The SIMD FPU exceptions are handled a little differently, as there
	 * is only a single status/control register.  Thus, to determine which
	 * unmasked exception was caught we must mask the exception mask bits
	 * at 0x1f80, and then use these to mask the exception bits at 0x3f.
	 */
	mxcsr = get_fpu_mxcsr(task);
	switch (~((mxcsr & 0x1f80) >> 7) & (mxcsr & 0x3f)) {
		case 0x000:
		default:
			break;
		case 0x001: /* Invalid Op */
			info.si_code = FPE_FLTINV;
			break;
		case 0x002: /* Denormalize */
		case 0x010: /* Underflow */
			info.si_code = FPE_FLTUND;
			break;
		case 0x004: /* Zero Divide */
			info.si_code = FPE_FLTDIV;
			break;
		case 0x008: /* Overflow */
			info.si_code = FPE_FLTOVF;
			break;
		case 0x020: /* Precision */
			info.si_code = FPE_FLTRES;
			break;
	}
	force_sig_info(SIGFPE, &info, task);
}

asmlinkage void do_simd_coprocessor_error(struct pt_regs * regs,
					  long error_code)
{
	if (cpu_has_xmm) {
		/* Handle SIMD FPU exceptions on PIII+ processors. */
		ignore_fpu_irq = 1;
		simd_math_error((void __user *)regs->eip);
	} else {
		/*
		 * Handle strange cache flush from user space exception
		 * in all other cases.  This is undocumented behaviour.
		 */
		if (regs->eflags & VM_MASK) {
			handle_vm86_fault((struct kernel_vm86_regs *)regs,
					  error_code);
			return;
		}
		die_if_kernel("cache flush denied", regs, error_code);
		current->thread.trap_no = 19;
		current->thread.error_code = error_code;
		force_sig(SIGSEGV, current);
	}
}

asmlinkage void do_spurious_interrupt_bug(struct pt_regs * regs,
					  long error_code)
{
#if 0
	/* No need to warn about this any longer. */
	printk("Ignoring P6 Local APIC Spurious Interrupt Bug...\n");
#endif
}

/*
 *  'math_state_restore()' saves the current math information in the
 * old math state array, and gets the new ones from the current task
 *
 * Careful.. There are problems with IBM-designed IRQ13 behaviour.
 * Don't touch unless you *really* know how it works.
 *
 * Must be called with kernel preemption disabled (in this case,
 * local interrupts are disabled at the call-site in entry.S).
 */
asmlinkage void math_state_restore(struct pt_regs regs)
{
	struct thread_info *thread = current_thread_info();
	struct task_struct *tsk = thread->task;

	clts();		/* Allow maths ops (or we recurse) */
	if (!tsk->used_math)
		init_fpu(tsk);
	restore_fpu(tsk);
	thread->status |= TS_USEDFPU;	/* So we fnsave on switch_to() */
}

#ifndef CONFIG_MATH_EMULATION

asmlinkage void math_emulate(long arg)
{
	printk("math-emulation not enabled and no coprocessor found.\n");
	printk("killing %s.\n",current->comm);
	force_sig(SIGFPE,current);
	schedule();
}

#endif /* CONFIG_MATH_EMULATION */

void __init trap_init_virtual_IDT(void)
{
	/*
	 * "idt" is magic - it overlaps the idt_descr
	 * variable so that updating idt will automatically
	 * update the idt descriptor..
	 */
	__set_fixmap(FIX_IDT, __pa(&idt_table), PAGE_KERNEL_RO);
	idt_descr.address = __fix_to_virt(FIX_IDT);

	__asm__ __volatile__("lidt %0" : : "m" (idt_descr));
}

void __init trap_init_virtual_GDT(void)
{
	int cpu = smp_processor_id();
	struct Xgt_desc_struct *gdt_desc = cpu_gdt_descr + cpu;
	struct Xgt_desc_struct tmp_desc = {0, 0};
	struct tss_struct * t;

	__asm__ __volatile__("sgdt %0": "=m" (tmp_desc): :"memory");

#ifdef CONFIG_X86_HIGH_ENTRY
	if (!cpu) {
		__set_fixmap(FIX_GDT_0, __pa(cpu_gdt_table), PAGE_KERNEL);
		__set_fixmap(FIX_GDT_1, __pa(cpu_gdt_table) + PAGE_SIZE, PAGE_KERNEL);
		__set_fixmap(FIX_TSS_0, __pa(init_tss), PAGE_KERNEL);
		__set_fixmap(FIX_TSS_1, __pa(init_tss) + 1*PAGE_SIZE, PAGE_KERNEL);
		__set_fixmap(FIX_TSS_2, __pa(init_tss) + 2*PAGE_SIZE, PAGE_KERNEL);
		__set_fixmap(FIX_TSS_3, __pa(init_tss) + 3*PAGE_SIZE, PAGE_KERNEL);
	}

	gdt_desc->address = __fix_to_virt(FIX_GDT_0) + sizeof(cpu_gdt_table[0]) * cpu;
#else
	gdt_desc->address = (unsigned long)cpu_gdt_table[cpu];
#endif
	__asm__ __volatile__("lgdt %0": "=m" (*gdt_desc));

#ifdef CONFIG_X86_HIGH_ENTRY
	t = (struct tss_struct *) __fix_to_virt(FIX_TSS_0) + cpu;
#else
	t = init_tss + cpu;
#endif
	set_tss_desc(cpu, t);
	cpu_gdt_table[cpu][GDT_ENTRY_TSS].b &= 0xfffffdff;
	load_TR_desc();
}

#define _set_gate(gate_addr,type,dpl,addr,seg) \
do { \
  int __d0, __d1; \
  __asm__ __volatile__ ("movw %%dx,%%ax\n\t" \
	"movw %4,%%dx\n\t" \
	"movl %%eax,%0\n\t" \
	"movl %%edx,%1" \
	:"=m" (*((long *) (gate_addr))), \
	 "=m" (*(1+(long *) (gate_addr))), "=&a" (__d0), "=&d" (__d1) \
	:"i" ((short) (0x8000+(dpl<<13)+(type<<8))), \
	 "3" ((char *) (addr)),"2" ((seg) << 16)); \
} while (0)


/*
 * This needs to use 'idt_table' rather than 'idt', and
 * thus use the _nonmapped_ version of the IDT, as the
 * Pentium F0 0F bugfix can have resulted in the mapped
 * IDT being write-protected.
 */
void set_intr_gate(unsigned int n, void *addr)
{
	_set_gate(idt_table+n,14,0,addr,__KERNEL_CS);
}

/*
 * This routine sets up an interrupt gate at directory privilege level 3.
 */
static inline void set_system_intr_gate(unsigned int n, void *addr)
{
	_set_gate(idt_table+n, 14, 3, addr, __KERNEL_CS);
}

void __init set_trap_gate(unsigned int n, void *addr)
{
	_set_gate(idt_table+n,15,0,addr,__KERNEL_CS);
}

void __init set_system_gate(unsigned int n, void *addr)
{
	_set_gate(idt_table+n,15,3,addr,__KERNEL_CS);
}

void __init set_call_gate(void *a, void *addr)
{
	_set_gate(a,12,3,addr,__KERNEL_CS);
}

static void __init set_task_gate(unsigned int n, unsigned int gdt_entry)
{
	_set_gate(idt_table+n,5,0,0,(gdt_entry<<3));
}


void __init trap_init(void)
{
#ifdef CONFIG_EISA
	if (isa_readl(0x0FFFD9) == 'E'+('I'<<8)+('S'<<16)+('A'<<24)) {
		EISA_bus = 1;
	}
#endif

#ifdef CONFIG_X86_LOCAL_APIC
	init_apic_mappings();
#endif
	init_entry_mappings();

	set_trap_gate(0,&divide_error);
	set_intr_gate(1,&debug);
	set_intr_gate(2,&nmi);
	set_system_intr_gate(3, &int3); /* int3-5 can be called from all */
	set_system_gate(4,&overflow);
	set_system_gate(5,&bounds);
	set_trap_gate(6,&invalid_op);
	set_trap_gate(7,&device_not_available);
	set_task_gate(8,GDT_ENTRY_DOUBLEFAULT_TSS);
	set_trap_gate(9,&coprocessor_segment_overrun);
	set_trap_gate(10,&invalid_TSS);
	set_trap_gate(11,&segment_not_present);
	set_trap_gate(12,&stack_segment);
	set_trap_gate(13,&general_protection);
	set_intr_gate(14,&page_fault);
	set_trap_gate(15,&spurious_interrupt_bug);
	set_trap_gate(16,&coprocessor_error);
	set_trap_gate(17,&alignment_check);
#ifdef CONFIG_X86_MCE
	set_trap_gate(18,&machine_check);
#endif
	set_trap_gate(19,&simd_coprocessor_error);

	set_system_gate(SYSCALL_VECTOR,&system_call);

	/*
	 * default LDT is a single-entry callgate to lcall7 for iBCS
	 * and a callgate to lcall27 for Solaris/x86 binaries
	 */
#if 0	 
	set_call_gate(&default_ldt[0],lcall7);
	set_call_gate(&default_ldt[4],lcall27);
#endif
	/*
	 * Should be a barrier for any external CPU state.
	 */
	cpu_init();

	trap_init_hook();
}

/*
 *  linux/arch/i386/kernel/process.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

/*
 * This file handles the architecture-dependent parts of process handling..
 */

#include <stdarg.h>

#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/elfcore.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/user.h>
#include <linux/a.out.h>
#include <linux/interrupt.h>
#include <linux/config.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/init.h>
#include <linux/mc146818rtc.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/kprobes.h>

#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/ldt.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/irq.h>
#include <asm/desc.h>
#include <asm/atomic_kmap.h>
#ifdef CONFIG_MATH_EMULATION
#include <asm/math_emu.h>
#endif

#include <xen/interface/physdev.h>
#include <xen/interface/vcpu.h>

#include <linux/irq.h>
#include <linux/err.h>

DECLARE_PER_CPU(int, cpu_state);

asmlinkage void ret_from_fork(void) __asm__("ret_from_fork");

int hlt_counter;

/*
 * Return saved PC of a blocked thread.
 */
unsigned long thread_saved_pc(struct task_struct *tsk)
{
	return ((unsigned long *)tsk->thread.esp)[3];
}

/*
 * Powermanagement idle function, if any..
 */
void (*pm_idle)(void);
static DEFINE_PER_CPU(unsigned int, cpu_idle_state);

void disable_hlt(void)
{
	hlt_counter++;
}

EXPORT_SYMBOL(disable_hlt);

void enable_hlt(void)
{
	hlt_counter--;
}

EXPORT_SYMBOL(enable_hlt);

/* XXX XEN doesn't use default_idle(), poll_idle(). Use xen_idle() instead. */
extern void stop_hz_timer(void);
extern void start_hz_timer(void);
void xen_idle(void)
{
	local_irq_disable();

	if (need_resched())
		local_irq_enable();
	else {
		clear_thread_flag(TIF_POLLING_NRFLAG);
		smp_mb__after_clear_bit();
		stop_hz_timer();
		/* Blocking includes an implicit local_irq_enable(). */
		HYPERVISOR_sched_op(SCHEDOP_block, 0);
		start_hz_timer();
		set_thread_flag(TIF_POLLING_NRFLAG);
	}
}

#ifdef CONFIG_HOTPLUG_CPU
extern cpumask_t cpu_initialized;
static inline void play_dead(void)
{
	extern void idle_task_exit(void); /* XXXAP find proper place */

	idle_task_exit();
	local_irq_disable();
	cpu_clear(smp_processor_id(), cpu_initialized);
	preempt_enable_no_resched();
	HYPERVISOR_vcpu_op(VCPUOP_down, smp_processor_id(), NULL);
	/* Same as arch/xen/kernel/smpboot.c:cpu_bringup(). */
	cpu_init();
	preempt_disable();
	local_irq_enable();
}
#endif

/*
 * The idle thread. There's no useful work to be
 * done, so just try to conserve power and have a
 * low exit latency (ie sit in a loop waiting for
 * somebody to say that they'd like to reschedule)
 */
#ifdef CONFIG_SMP
extern void smp_suspend(void);
extern void smp_resume(void);
#endif
void cpu_idle (void)
{
	int cpu = smp_processor_id();

	/* endless idle loop with no priority at all */
	while (1) {
		while (!need_resched()) {

			if (__get_cpu_var(cpu_idle_state))
				__get_cpu_var(cpu_idle_state) = 0;
			rmb();

#if defined(CONFIG_HOTPLUG_CPU)
			if (cpu_is_offline(cpu))
				play_dead();
#endif

			irq_stat[cpu].idle_timestamp = jiffies;
			xen_idle();
		}
		schedule();
	}
}

void cpu_idle_wait(void)
{
	unsigned int cpu, this_cpu = get_cpu();
	cpumask_t map;

	set_cpus_allowed(current, cpumask_of_cpu(this_cpu));
	put_cpu();

	cpus_clear(map);
	for_each_online_cpu(cpu) {
		per_cpu(cpu_idle_state, cpu) = 1;
		cpu_set(cpu, map);
	}

	__get_cpu_var(cpu_idle_state) = 0;

	wmb();
	do {
		ssleep(1);
		for_each_online_cpu(cpu) {
			if (cpu_isset(cpu, map) && !per_cpu(cpu_idle_state, cpu))
				cpu_clear(cpu, map);
		}
		cpus_and(map, map, cpu_online_map);
	} while (!cpus_empty(map));
}
EXPORT_SYMBOL_GPL(cpu_idle_wait);

/* XXX XEN doesn't use mwait_idle(), select_idle_routine(), idle_setup(). */
/* Always use xen_idle() instead. */
void __init select_idle_routine(const struct cpuinfo_x86 *c) {}

void show_regs(struct pt_regs * regs)
{
	printk("\n");
	printk("Pid: %d, comm: %20s\n", current->pid, current->comm);
	printk("EIP: %04x:[<%08lx>] CPU: %d\n",0xffff & regs->xcs,regs->eip, smp_processor_id());
	print_symbol("EIP is at %s\n", regs->eip);

	if (regs->xcs & 2)
		printk(" ESP: %04x:%08lx",0xffff & regs->xss,regs->esp);
	printk(" EFLAGS: %08lx    %s  (%s)\n",regs->eflags, print_tainted(),UTS_RELEASE);
	printk("EAX: %08lx EBX: %08lx ECX: %08lx EDX: %08lx\n",
		regs->eax,regs->ebx,regs->ecx,regs->edx);
	printk("ESI: %08lx EDI: %08lx EBP: %08lx",
		regs->esi, regs->edi, regs->ebp);
	printk(" DS: %04x ES: %04x\n",
		0xffff & regs->xds,0xffff & regs->xes);

	show_trace(NULL, &regs->esp);
}

EXPORT_SYMBOL_GPL(show_regs);

/*
 * This gets run with %ebx containing the
 * function to call, and %edx containing
 * the "args".
 */
extern void kernel_thread_helper(void);
__asm__(".section .text\n"
	".align 4\n"
	"kernel_thread_helper:\n\t"
	"movl %edx,%eax\n\t"
	"pushl %edx\n\t"
	"call *%ebx\n\t"
	"pushl %eax\n\t"
	"call do_exit\n"
	".previous");

/*
 * Create a kernel thread
 */
int kernel_thread(int (*fn)(void *), void * arg, unsigned long flags)
{
	struct pt_regs regs;

	memset(&regs, 0, sizeof(regs));

	regs.ebx = (unsigned long) fn;
	regs.edx = (unsigned long) arg;

	regs.xds = __USER_DS;
	regs.xes = __USER_DS;
	regs.orig_eax = -1;
	regs.eip = (unsigned long) kernel_thread_helper;
	regs.xcs = GET_KERNEL_CS();
	regs.eflags = X86_EFLAGS_IF | X86_EFLAGS_SF | X86_EFLAGS_PF | 0x2;

	/* Ok, create the new process.. */
	return do_fork(flags | CLONE_VM | CLONE_UNTRACED, 0, &regs, 0, NULL, NULL);
}

/*
 * Free current thread data structures etc..
 */
void exit_thread(void)
{
	struct task_struct *tsk = current;
	struct thread_struct *t = &tsk->thread;

	/*
	 * Remove function-return probe instances associated with this task
	 * and put them back on the free list. Do not insert an exit probe for
	 * this function, it will be disabled by kprobe_flush_task if you do.
	 */
	kprobe_flush_task(tsk);

	/* The process may have allocated an io port bitmap... nuke it. */
	if (unlikely(NULL != t->io_bitmap_ptr)) {
		struct physdev_set_iobitmap iobmp_op = { 0 };
		HYPERVISOR_physdev_op(PHYSDEVOP_set_iobitmap, &iobmp_op);

		kfree(t->io_bitmap_ptr);
		t->io_bitmap_ptr = NULL;
	}
}

void flush_thread(void)
{
	struct task_struct *tsk = current;

	memset(tsk->thread.debugreg, 0, sizeof(unsigned long)*8);
#ifdef CONFIG_X86_HIGH_ENTRY
	clear_thread_flag(TIF_DB7);
#endif
	memset(tsk->thread.tls_array, 0, sizeof(tsk->thread.tls_array));	
	/*
	 * Forget coprocessor state..
	 */
	clear_fpu(tsk);
	tsk->used_math = 0;
}

void release_thread(struct task_struct *dead_task)
{
	if (dead_task->mm) {
		// temporary debugging check
		if (dead_task->mm->context.size) {
			printk("WARNING: dead process %8s still has LDT? <%d>\n",
					dead_task->comm,
					dead_task->mm->context.size);
			BUG();
		}
	}

	release_x86_irqs(dead_task);
}

/*
 * This gets called before we allocate a new thread and copy
 * the current task into it.
 */
void prepare_to_copy(struct task_struct *tsk)
{
	unlazy_fpu(tsk);
}

int copy_thread(int nr, unsigned long clone_flags, unsigned long esp,
	unsigned long unused,
	struct task_struct * p, struct pt_regs * regs)
{
	struct pt_regs * childregs;
	struct task_struct *tsk;
	int err, i;

	childregs = ((struct pt_regs *) (THREAD_SIZE + (unsigned long) p->thread_info)) - 1;
	*childregs = *regs;
	childregs->eax = 0;
	childregs->esp = esp;
	p->set_child_tid = p->clear_child_tid = NULL;

	p->thread.esp = (unsigned long) childregs;
	p->thread.esp0 = (unsigned long) (childregs+1);

	/*
	 * get the two stack pages, for the virtual stack.
	 *
	 * IMPORTANT: this code relies on the fact that the task
	 * structure is an THREAD_SIZE aligned piece of physical memory.
	 */
	for (i = 0; i < ARRAY_SIZE(p->thread.stack_page); i++)
		p->thread.stack_page[i] =
				virt_to_page((unsigned long)p->thread_info + (i*PAGE_SIZE));

	p->thread.eip = (unsigned long) ret_from_fork;
	p->thread_info->real_stack = p->thread_info;

	savesegment(fs,p->thread.fs);
	savesegment(gs,p->thread.gs);

	tsk = current;
	if (unlikely(NULL != tsk->thread.io_bitmap_ptr)) {
		p->thread.io_bitmap_ptr = kmalloc(IO_BITMAP_BYTES, GFP_KERNEL);
		if (!p->thread.io_bitmap_ptr) {
			p->thread.io_bitmap_max = 0;
			return -ENOMEM;
		}
		memcpy(p->thread.io_bitmap_ptr, tsk->thread.io_bitmap_ptr,
			IO_BITMAP_BYTES);
	}

	/*
	 * Set a new TLS for the child thread?
	 */
	if (clone_flags & CLONE_SETTLS) {
		struct desc_struct *desc;
		struct user_desc info;
		int idx;

		err = -EFAULT;
		if (copy_from_user(&info, (void __user *)childregs->esi, sizeof(info)))
			goto out;
		err = -EINVAL;
		if (LDT_empty(&info))
			goto out;

		idx = info.entry_number;
		if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX)
			goto out;

		desc = p->thread.tls_array + idx - GDT_ENTRY_TLS_MIN;
		desc->a = LDT_entry_a(&info);
		desc->b = LDT_entry_b(&info);
	}

	p->thread.io_pl = current->thread.io_pl;

	err = 0;
 out:
	if (err && p->thread.io_bitmap_ptr) {
		kfree(p->thread.io_bitmap_ptr);
		p->thread.io_bitmap_max = 0;
	}
	return err;
}

/*
 * fill in the user structure for a core dump..
 */
void dump_thread(struct pt_regs * regs, struct user * dump)
{
	int i;

/* changed the size calculations - should hopefully work better. lbt */
	dump->magic = CMAGIC;
	dump->start_code = 0;
	dump->start_stack = regs->esp & ~(PAGE_SIZE - 1);
	dump->u_tsize = ((unsigned long) current->mm->end_code) >> PAGE_SHIFT;
	dump->u_dsize = ((unsigned long) (current->mm->brk + (PAGE_SIZE-1))) >> PAGE_SHIFT;
	dump->u_dsize -= dump->u_tsize;
	dump->u_ssize = 0;
	for (i = 0; i < 8; i++)
		dump->u_debugreg[i] = current->thread.debugreg[i];  

	if (dump->start_stack < TASK_SIZE)
		dump->u_ssize = ((unsigned long) (TASK_SIZE - dump->start_stack)) >> PAGE_SHIFT;

	dump->regs.ebx = regs->ebx;
	dump->regs.ecx = regs->ecx;
	dump->regs.edx = regs->edx;
	dump->regs.esi = regs->esi;
	dump->regs.edi = regs->edi;
	dump->regs.ebp = regs->ebp;
	dump->regs.eax = regs->eax;
	dump->regs.ds = regs->xds;
	dump->regs.es = regs->xes;
	savesegment(fs,dump->regs.fs);
	savesegment(gs,dump->regs.gs);
	dump->regs.orig_eax = regs->orig_eax;
	dump->regs.eip = regs->eip;
	dump->regs.cs = regs->xcs;
	dump->regs.eflags = regs->eflags;
	dump->regs.esp = regs->esp;
	dump->regs.ss = regs->xss;

	dump->u_fpvalid = dump_fpu (regs, &dump->i387);
}

/* 
 * Capture the user space registers if the task is not running (in user space)
 */
int dump_task_regs(struct task_struct *tsk, elf_gregset_t *regs)
{
	struct pt_regs ptregs;
	
	ptregs = *(struct pt_regs *)
		((unsigned long)tsk->thread_info+THREAD_SIZE - sizeof(ptregs));
	ptregs.xcs &= 0xffff;
	ptregs.xds &= 0xffff;
	ptregs.xes &= 0xffff;
	ptregs.xss &= 0xffff;

	elf_core_copy_regs(regs, &ptregs);

	return 1;
}

/*
 * This special macro can be used to load a debugging register
 */
#define loaddebug(thread,register) \
		__asm__("movl %0,%%db" #register  \
			: /* no output */ \
			:"r" (thread->debugreg[register]))

/*
 *	switch_to(x,yn) should switch tasks from x to y.
 *
 * We fsave/fwait so that an exception goes off at the right time
 * (as a call from the fsave or fwait in effect) rather than to
 * the wrong process. Lazy FP saving no longer makes any sense
 * with modern CPU's, and this simplifies a lot of things (SMP
 * and UP become the same).
 *
 * NOTE! We used to use the x86 hardware context switching. The
 * reason for not using it any more becomes apparent when you
 * try to recover gracefully from saved state that is no longer
 * valid (stale segment register values in particular). With the
 * hardware task-switch, there is no way to fix up bad state in
 * a reasonable manner.
 *
 * The fact that Intel documents the hardware task-switching to
 * be slow is a fairly red herring - this code is not noticeably
 * faster. However, there _is_ some room for improvement here,
 * so the performance issues may eventually be a valid point.
 * More important, however, is the fact that this allows us much
 * more flexibility.
 *
 * The return value (in %eax) will be the "prev" task after
 * the task-switch, and shows up in ret_from_fork in entry.S,
 * for example.
 */
struct task_struct fastcall * __switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
	struct thread_struct *prev = &prev_p->thread,
				 *next = &next_p->thread;
	int cpu = smp_processor_id();
#ifndef CONFIG_X86_NO_TSS
	struct tss_struct *tss = init_tss + cpu;
#endif
	struct physdev_set_iopl iopl_op;
	struct physdev_set_iobitmap iobmp_op;
	multicall_entry_t _mcl[8], *mcl = _mcl;

	/* XEN NOTE: FS/GS saved in switch_mm(), not here. */
	if (next_p->mm)
		load_user_cs_desc(cpu, next_p->mm);

	/*
	 * This is basically '__unlazy_fpu', except that we queue a
	 * multicall to indicate FPU task switch, rather than
	 * synchronously trapping to Xen.
	 */
	if (prev_p->thread_info->status & TS_USEDFPU) {
		__save_init_fpu(prev_p); /* _not_ save_init_fpu() */
		mcl->op      = __HYPERVISOR_fpu_taskswitch;
		mcl->args[0] = 1;
		mcl++;
	}
#if 0 /* lazy fpu sanity check */
	else BUG_ON(!(read_cr0() & 8));
#endif
 
#ifdef CONFIG_X86_HIGH_ENTRY
{
	int i;
	/*
	 * Set the ptes of the virtual stack. (NOTE: a one-page TLB flush is
	 * needed because otherwise NMIs could interrupt the
	 * user-return code with a virtual stack and stale TLBs.)
	 */
	for (i = 0; i < ARRAY_SIZE(next->stack_page); i++) {
		__kunmap_atomic_type(KM_VSTACK_TOP-i);
		__kmap_atomic(next->stack_page[i], KM_VSTACK_TOP-i);
	}
	/*
	 * NOTE: here we rely on the task being the stack as well
	 */
	next_p->thread_info->virtual_stack =
			(void *)__kmap_atomic_vaddr(KM_VSTACK_TOP);
}
#if defined(CONFIG_PREEMPT) && defined(CONFIG_SMP)
	/*
	 * If next was preempted on entry from userspace to kernel,
	 * and now it's on a different cpu, we need to adjust %esp.
	 * This assumes that entry.S does not copy %esp while on the
	 * virtual stack (with interrupts enabled): which is so,
	 * except within __SWITCH_KERNELSPACE itself.
	 */
	if (unlikely(next->esp >= TASK_SIZE)) {
		next->esp &= THREAD_SIZE - 1;
		next->esp |= (unsigned long) next_p->thread_info->virtual_stack;
	}
#endif
#endif
	/*
	 * Reload esp0, LDT and the page table pointer:
	 * This is load_esp0(tss, next) with a multicall.
	 */
	mcl->op      = __HYPERVISOR_stack_switch;
	mcl->args[0] = __KERNEL_DS;
	mcl->args[1] = next->esp0;
	mcl++;

	/*
	 * Load the per-thread Thread-Local Storage descriptor.
	 * This is load_TLS(next, cpu) with multicalls.
	 */
#define C(i) do {							\
	if (unlikely(next->tls_array[i].a != prev->tls_array[i].a ||	\
		     next->tls_array[i].b != prev->tls_array[i].b)) {	\
		mcl->op = __HYPERVISOR_update_descriptor;		\
		*(u64 *)&mcl->args[0] = virt_to_machine(		\
			&get_cpu_gdt_table(cpu)[GDT_ENTRY_TLS_MIN + i]);\
		*(u64 *)&mcl->args[2] = *(u64 *)&next->tls_array[i];	\
		mcl++;							\
	}								\
} while (0)
	C(0); C(1); C(2);
#undef C

	if (unlikely(prev->io_pl != next->io_pl)) {
		iopl_op.iopl = (next->io_pl == 0) ? 1 :
			(next->io_pl >> 12) & 3;
		mcl->op      = __HYPERVISOR_physdev_op;
		mcl->args[0] = PHYSDEVOP_set_iopl;
		mcl->args[1] = (unsigned long)&iopl_op;
		mcl++;
	}

	if (unlikely(prev->io_bitmap_ptr || next->io_bitmap_ptr)) {
		iobmp_op.bitmap   = (char *)next->io_bitmap_ptr;
		iobmp_op.nr_ports = next->io_bitmap_ptr ? IO_BITMAP_BITS : 0;
		mcl->op      = __HYPERVISOR_physdev_op;
		mcl->args[0] = PHYSDEVOP_set_iobitmap;
		mcl->args[1] = (unsigned long)&iobmp_op;
		mcl++;
	}

	(void)HYPERVISOR_multicall(_mcl, mcl - _mcl);

	/*
	 * Restore %fs and %gs if needed.
	 */
	if (unlikely(next->fs | next->gs)) {
		loadsegment(fs, next->fs);
		loadsegment(gs, next->gs);
	}

	/*
	 * Now maybe reload the debug registers
	 */
	if (unlikely(next->debugreg[7])) {
		loaddebug(next, 0);
		loaddebug(next, 1);
		loaddebug(next, 2);
		loaddebug(next, 3);
		/* no 4 and 5 */
		loaddebug(next, 6);
		loaddebug(next, 7);
	}

	return prev_p;
}

asmlinkage int sys_fork(struct pt_regs regs)
{
	return do_fork(SIGCHLD, regs.esp, &regs, 0, NULL, NULL);
}

asmlinkage int sys_clone(struct pt_regs regs)
{
	unsigned long clone_flags;
	unsigned long newsp;
	int __user *parent_tidptr, *child_tidptr;

	clone_flags = regs.ebx;
	newsp = regs.ecx;
	parent_tidptr = (int __user *)regs.edx;
	child_tidptr = (int __user *)regs.edi;
	if (!newsp)
		newsp = regs.esp;
	return do_fork(clone_flags, newsp, &regs, 0, parent_tidptr, child_tidptr);
}

/*
 * This is trivial, and on the face of it looks like it
 * could equally well be done in user mode.
 *
 * Not so, for quite unobvious reasons - register pressure.
 * In user mode vfork() cannot have a stack frame, and if
 * done by calling the "clone()" system call directly, you
 * do not have enough call-clobbered registers to hold all
 * the information you need.
 */
asmlinkage int sys_vfork(struct pt_regs regs)
{
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, regs.esp, &regs, 0, NULL, NULL);
}

/*
 * sys_execve() executes a new program.
 */
asmlinkage int sys_execve(struct pt_regs regs)
{
	int error;
	char * filename;

	filename = getname((char __user *) regs.ebx);
	error = PTR_ERR(filename);
	if (IS_ERR(filename))
		goto out;
	error = do_execve(filename,
			(char __user * __user *) regs.ecx,
			(char __user * __user *) regs.edx,
			&regs);
	if (error == 0) {
		task_lock(current);
		current->ptrace &= ~PT_DTRACE;
		task_unlock(current);
		/* Make sure we don't return using sysenter.. */
		set_thread_flag(TIF_IRET);
	}
	putname(filename);
out:
	return error;
}

#define top_esp                (THREAD_SIZE - sizeof(unsigned long))
#define top_ebp                (THREAD_SIZE - 2*sizeof(unsigned long))

unsigned long get_wchan(struct task_struct *p)
{
	unsigned long ebp, esp, eip;
	unsigned long stack_page;
	int count = 0;
	if (!p || p == current || p->state == TASK_RUNNING)
		return 0;
	stack_page = (unsigned long)p->thread_info;
	esp = p->thread.esp;
	if (!stack_page || esp < stack_page || esp > top_esp+stack_page)
		return 0;
	/* include/asm-i386/system.h:switch_to() pushes ebp last. */
	ebp = *(unsigned long *) esp;
	do {
		if (ebp < stack_page || ebp > top_ebp+stack_page)
			return 0;
		eip = *(unsigned long *) (ebp+4);
		if (!in_sched_functions(eip))
			return eip;
		ebp = *(unsigned long *) ebp;
	} while (count++ < 16);
	return 0;
}

/*
 * sys_alloc_thread_area: get a yet unused TLS descriptor index.
 */
static int get_free_idx(void)
{
	struct thread_struct *t = &current->thread;
	int idx;

	for (idx = 0; idx < GDT_ENTRY_TLS_ENTRIES; idx++)
		if (desc_empty(t->tls_array + idx))
			return idx + GDT_ENTRY_TLS_MIN;
	return -ESRCH;
}

/*
 * Set a given TLS descriptor:
 */
asmlinkage int sys_set_thread_area(struct user_desc __user *u_info)
{
	struct thread_struct *t = &current->thread;
	struct user_desc info;
	struct desc_struct *desc;
	int cpu, idx;

	if (copy_from_user(&info, u_info, sizeof(info)))
		return -EFAULT;
	idx = info.entry_number;

	/*
	 * index -1 means the kernel should try to find and
	 * allocate an empty descriptor:
	 */
	if (idx == -1) {
		idx = get_free_idx();
		if (idx < 0)
			return idx;
		if (put_user(idx, &u_info->entry_number))
			return -EFAULT;
	}

	if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX)
		return -EINVAL;

	desc = t->tls_array + idx - GDT_ENTRY_TLS_MIN;

	/*
	 * We must not get preempted while modifying the TLS.
	 */
	cpu = get_cpu();

	if (LDT_empty(&info)) {
		desc->a = 0;
		desc->b = 0;
	} else {
		desc->a = LDT_entry_a(&info);
		desc->b = LDT_entry_b(&info);
	}
	load_TLS(t, cpu);

	put_cpu();

	return 0;
}

/*
 * Get the current Thread-Local Storage area:
 */

#define GET_BASE(desc) ( \
	(((desc)->a >> 16) & 0x0000ffff) | \
	(((desc)->b << 16) & 0x00ff0000) | \
	( (desc)->b        & 0xff000000)   )

#define GET_LIMIT(desc) ( \
	((desc)->a & 0x0ffff) | \
	 ((desc)->b & 0xf0000) )
	
#define GET_32BIT(desc)		(((desc)->b >> 22) & 1)
#define GET_CONTENTS(desc)	(((desc)->b >> 10) & 3)
#define GET_WRITABLE(desc)	(((desc)->b >>  9) & 1)
#define GET_LIMIT_PAGES(desc)	(((desc)->b >> 23) & 1)
#define GET_PRESENT(desc)	(((desc)->b >> 15) & 1)
#define GET_USEABLE(desc)	(((desc)->b >> 20) & 1)

asmlinkage int sys_get_thread_area(struct user_desc __user *u_info)
{
	struct user_desc info;
	struct desc_struct *desc;
	int idx;

	if (get_user(idx, &u_info->entry_number))
		return -EFAULT;
	if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX)
		return -EINVAL;

	memset(&info, 0, sizeof(info));

	desc = current->thread.tls_array + idx - GDT_ENTRY_TLS_MIN;

	info.entry_number = idx;
	info.base_addr = GET_BASE(desc);
	info.limit = GET_LIMIT(desc);
	info.seg_32bit = GET_32BIT(desc);
	info.contents = GET_CONTENTS(desc);
	info.read_exec_only = !GET_WRITABLE(desc);
	info.limit_in_pages = GET_LIMIT_PAGES(desc);
	info.seg_not_present = !GET_PRESENT(desc);
	info.useable = GET_USEABLE(desc);

	if (copy_to_user(u_info, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}


unsigned long arch_align_stack(unsigned long sp)
{
	if (current->flags & PF_RELOCEXEC)
		sp -= ((get_random_int() % 65536) << 4);
	return sp & ~0xf;
}


void arch_add_exec_range(struct mm_struct *mm, unsigned long limit)
{
	if (limit > mm->context.exec_limit) {
		mm->context.exec_limit = limit;
		set_user_cs(&mm->context.user_cs, limit);
		if (mm == current->mm)
			load_user_cs_desc(smp_processor_id(), mm);
	}
}

void arch_remove_exec_range(struct mm_struct *mm, unsigned long old_end)
{
	struct vm_area_struct *vma;
	unsigned long limit = 0;

	if (old_end == mm->context.exec_limit) {
		for (vma = mm->mmap; vma; vma = vma->vm_next)
			if ((vma->vm_flags & VM_EXEC) && (vma->vm_end > limit))
				limit = vma->vm_end;

		mm->context.exec_limit = limit;
		set_user_cs(&mm->context.user_cs, limit);
		if (mm == current->mm)
			load_user_cs_desc(smp_processor_id(), mm);
	}
}

void arch_flush_exec_range(struct mm_struct *mm)
{
	mm->context.exec_limit = 0;
	set_user_cs(&mm->context.user_cs, 0);
}

/*
 * Generate random brk address between 128MB and 196MB. (if the layout
 * allows it.)
 */
void randomize_brk(unsigned long old_brk)
{
	unsigned long new_brk, range_start, range_end;

	range_start = 0x08000000;
	if (current->mm->brk >= range_start)
		range_start = current->mm->brk;
	range_end = range_start + 0x02000000;
	new_brk = randomize_range(range_start, range_end, 0);
	if (new_brk)
		current->mm->brk = new_brk;
}

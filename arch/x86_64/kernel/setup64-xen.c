/* 
 * X86-64 specific CPU setup.
 * Copyright (C) 1995  Linus Torvalds
 * Copyright 2001, 2002, 2003 SuSE Labs / Andi Kleen.
 * See setup.c for older changelog.
 * $Id: setup64.c,v 1.12 2002/03/21 10:09:17 ak Exp $
 *
 * Jun Nakajima <jun.nakajima@intel.com>
 *   Modified for Xen
 *
 */ 
#include <linux/config.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/bootmem.h>
#include <asm/pda.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/bitops.h>
#include <asm/atomic.h>
#include <asm/mmu_context.h>
#include <asm/smp.h>
#include <asm/i387.h>
#include <asm/percpu.h>
#include <asm/mtrr.h>
#include <asm/proto.h>
#include <asm/mman.h>
#include <asm/numa.h>
#ifdef CONFIG_XEN
#include <asm/hypervisor.h>
#endif

char x86_boot_params[2048] __initdata = {0,};

// unsigned long cpu_initialized __initdata = 0;
cpumask_t cpu_initialized __initdata = CPU_MASK_NONE;

struct x8664_pda cpu_pda[NR_CPUS] __cacheline_aligned; 

extern unsigned char __per_cpu_start[], __per_cpu_end[]; 

extern struct desc_ptr cpu_gdt_descr[];
#ifndef CONFIG_X86_NO_IDT
struct desc_ptr idt_descr = { 256 * 16, (unsigned long) idt_table }; 
#endif

char boot_cpu_stack[IRQSTACKSIZE] __attribute__((section(".bss.page_aligned")));

unsigned long __supported_pte_mask = ~0UL;
static int do_not_nx __initdata = 0;
unsigned long vm_stack_flags = __VM_STACK_FLAGS; 
unsigned long vm_stack_flags32 = __VM_STACK_FLAGS; 
unsigned long vm_data_default_flags = __VM_DATA_DEFAULT_FLAGS; 
unsigned long vm_data_default_flags32 = __VM_DATA_DEFAULT_FLAGS; 
unsigned long vm_force_exec32 = PROT_EXEC; 

/* noexec=on|off
Control non executable mappings for 64bit processes.

on	Enable
off	Disable
noforce (default) Don't enable by default for heap/stack/data, 
	but allow PROT_EXEC to be effective

*/ 
static int __init nonx_setup(char *str)
{
	if (!strcmp(str, "on")) {
                __supported_pte_mask |= _PAGE_NX; 
 		do_not_nx = 0; 
 		vm_data_default_flags &= ~VM_EXEC; 
 		vm_stack_flags &= ~VM_EXEC;  
	} else if (!strcmp(str, "noforce") || !strcmp(str, "off")) {
		do_not_nx = (str[0] == 'o');
		if (do_not_nx)
			__supported_pte_mask &= ~_PAGE_NX; 
		vm_data_default_flags |= VM_EXEC; 
		vm_stack_flags |= VM_EXEC;
        } 
        return 1;
} 

__setup("noexec=", nonx_setup); 

/* noexec32=opt{,opt} 

Control the no exec default for 32bit processes. Can be also overwritten
per executable using ELF header flags (e.g. needed for the X server)
Requires noexec=on or noexec=noforce to be effective.

Valid options: 
   all,on    Heap,stack,data is non executable. 	
   off       (default) Heap,stack,data is executable
   stack     Stack is non executable, heap/data is.
   force     Don't imply PROT_EXEC for PROT_READ 
   compat    (default) Imply PROT_EXEC for PROT_READ

*/
 static int __init nonx32_setup(char *s)
 {
	 while (*s) {
		if (!strncmp(s, "all", 3) || !strncmp(s,"on",2)) {
			vm_data_default_flags32 &= ~VM_EXEC; 
			vm_stack_flags32 &= ~VM_EXEC;  
		} else if (!strncmp(s, "off",3)) {
			vm_data_default_flags32 |= VM_EXEC; 
			vm_stack_flags32 |= VM_EXEC;  
		} else if (!strncmp(s, "stack", 5)) {
			vm_data_default_flags32 |= VM_EXEC; 
			vm_stack_flags32 &= ~VM_EXEC;  		
		} else if (!strncmp(s, "force",5)) {
			vm_force_exec32 = 0; 
		} else if (!strncmp(s, "compat",5)) {
			vm_force_exec32 = PROT_EXEC;
		} 
		s += strcspn(s, ",");
		if (*s == ',')
			++s;
	 }
	 return 1;
} 

__setup("noexec32=", nonx32_setup); 

/*
 * Great future plan:
 * Declare PDA itself and support (irqstack,tss,pml4) as per cpu data.
 * Always point %gs to its beginning
 */
void __init setup_per_cpu_areas(void)
{ 
	int i;
	unsigned long size;

#ifdef CONFIG_HOTPLUG_CPU
	prefill_possible_map();
#endif

	/* Copy section for each CPU (we discard the original) */
	size = ALIGN(__per_cpu_end - __per_cpu_start, SMP_CACHE_BYTES);
#ifdef CONFIG_MODULES
	if (size < PERCPU_ENOUGH_ROOM)
		size = PERCPU_ENOUGH_ROOM;
#endif

	for (i = 0; i < NR_CPUS; i++) { 
		unsigned char *ptr;
		/* If possible allocate on the node of the CPU.
		   In case it doesn't exist round-robin nodes. */
		if (!NODE_DATA(i % numnodes)) { 
			printk("cpu with no node %d, numnodes %d\n", i, numnodes);
			ptr = alloc_bootmem(size);
		} else { 
			ptr = alloc_bootmem_node(NODE_DATA(i % numnodes), size);
		}
		if (!ptr)
			panic("Cannot allocate cpu data for CPU %d\n", i);
		cpu_pda[i].data_offset = ptr - __per_cpu_start;
		memcpy(ptr, __per_cpu_start, __per_cpu_end - __per_cpu_start);
	}
} 

#ifdef CONFIG_XEN
static void switch_pt(pml4_t * level4)
{
	xen_pt_switch(__pa(level4));
	xen_new_user_pt(__pa(__user_pml4(level4)));
}

void __init cpu_gdt_init(struct desc_ptr *gdt_descr)
{
	unsigned long frames[16];
	unsigned long va;
	int f;

	for (va = gdt_descr->address, f = 0;
	     va < gdt_descr->address + gdt_descr->size;
	     va += PAGE_SIZE, f++) {
		frames[f] = virt_to_mfn(va);
		make_page_readonly(
			(void *)va, XENFEAT_writable_descriptor_tables);
	}
	if (HYPERVISOR_set_gdt(frames, gdt_descr->size /
				sizeof (struct desc_struct)))
		BUG();
}
#else
static void switch_pt(pml4_t * dummy)
{
	asm volatile("movq %0,%%cr3" :: "r" (__pa_symbol(&init_level4_pgt)));
}

void __init cpu_gdt_init(struct desc_ptr *gdt_descr)
{
	asm volatile("lgdt %0" :: "m" (*gdt_descr));
	asm volatile("lidt %0" :: "m" (idt_descr));
}
#endif

void pda_init(int cpu)
{ 
        pml4_t *level4;
	struct x8664_pda *pda = &cpu_pda[cpu];

	/* Setup up data that may be needed in __get_free_pages early */
	asm volatile("movl %0,%%fs ; movl %0,%%gs" :: "r" (0)); 
#ifndef CONFIG_XEN
	wrmsrl(MSR_GS_BASE, cpu_pda + cpu);
#else
	HYPERVISOR_set_segment_base(SEGBASE_GS_KERNEL, (unsigned long)pda);
#endif
	pda->me = pda;
	pda->cpunumber = cpu; 
	pda->irqcount = -1;
	pda->kernelstack = 
		(unsigned long)stack_thread_info() - PDA_STACKOFFSET + THREAD_SIZE; 
	pda->active_mm = &init_mm;
	pda->mmu_state = 0;

	if (cpu == 0) {
#ifdef CONFIG_XEN
		xen_init_pt();
#endif
		/* others are initialized in smpboot.c */
		pda->pcurrent = &init_task;
		pda->irqstackptr = boot_cpu_stack; 
		level4 = init_level4_pgt; 
	} else {
               /*
		* allocate per-cpu pml4 if not done so previously;
		* previous per-cpu pml4 may exist due to restore after save,
                * or due to vcpu-set which lowered then increased num vcpus.
		*/
		if (pda->level4_pgt == NULL) {
			level4 = (pml4_t *)__get_free_pages(GFP_ATOMIC, 1); 
		} else {
		        switch_pt((pml4_t *)pda->level4_pgt);
			return;
		}
		if (!level4) 
			panic("Cannot allocate top level page for cpu %d", cpu); 
		pda->irqstackptr = (char *)
			__get_free_pages(GFP_ATOMIC, IRQSTACK_ORDER);
		if (!pda->irqstackptr)
			panic("cannot allocate irqstack for cpu %d", cpu); 
	}

	pda->level4_pgt = (unsigned long *)level4; 
	if (level4 != init_level4_pgt) {
		memcpy(level4, &init_level4_pgt, 2 * PAGE_SIZE); 
		make_page_readonly(level4, XENFEAT_writable_page_tables);
		make_page_readonly(__user_pml4(level4),
					XENFEAT_writable_page_tables);
	}
	set_pml4(level4 + 510, mk_kernel_pml4(__pa_symbol(boot_vmalloc_pgt)));
	// already done by switch_pt ??
	// asm volatile("movq %0,%%cr3" :: "r" (__pa(level4))); 

	switch_pt(level4);

	pda->irqstackptr += IRQSTACKSIZE-64;
} 

#ifndef CONFIG_X86_NO_TSS
char boot_exception_stacks[N_EXCEPTION_STACKS * EXCEPTION_STKSZ] 
__attribute__((section(".bss.page_aligned")));
#endif

/* May not be marked __init: used by software suspend */
void syscall_init(void)
{
#ifndef CONFIG_XEN
	/* 
	 * LSTAR and STAR live in a bit strange symbiosis.
	 * They both write to the same internal register. STAR allows to set CS/DS
	 * but only a 32bit target. LSTAR sets the 64bit rip. 	 
	 */ 
	wrmsrl(MSR_STAR,  ((u64)__USER32_CS)<<48  | ((u64)__KERNEL_CS)<<32); 
	wrmsrl(MSR_LSTAR, system_call); 

	/* Flags to clear on syscall */
	wrmsrl(MSR_SYSCALL_MASK, EF_TF|EF_DF|EF_IE|0x3000);
#endif
#ifdef CONFIG_IA32_EMULATION   		
	syscall32_cpu_init ();
#endif
}

void __init check_efer(void)
{
	unsigned long efer;

	rdmsrl(MSR_EFER, efer); 
        if (!(efer & EFER_NX) || do_not_nx) { 
                __supported_pte_mask &= ~_PAGE_NX; 
        }       
}

/*
 * cpu_init() initializes state that is per-CPU. Some data is already
 * initialized (naturally) in the bootstrap process, such as the GDT
 * and IDT. We reload them nevertheless, this function acts as a
 * 'CPU state barrier', nothing should get across.
 * A lot of state is already set up in PDA init.
 */
void __init cpu_init (void)
{
#ifdef CONFIG_SMP
	int cpu = stack_smp_processor_id();
#else
	int cpu = smp_processor_id();
#endif
#ifndef CONFIG_X86_NO_TSS
	struct tss_struct *t = &per_cpu(init_tss, cpu);
	unsigned long v; 
	char *estacks = NULL; 
	int i;
#endif
	struct task_struct *me;

	/* CPU 0 is initialised in head64.c */
	if (cpu != 0) {
		pda_init(cpu);
	}
#ifndef CONFIG_X86_NO_TSS
	else 
		estacks = boot_exception_stacks; 
#endif

	me = current;

	if (test_and_set_bit(cpu, &cpu_initialized))
		panic("CPU#%d already initialized!\n", cpu);

	printk("Initializing CPU#%d\n", cpu);

		clear_in_cr4(X86_CR4_VME|X86_CR4_PVI|X86_CR4_TSD|X86_CR4_DE);

	/*
	 * Initialize the per-CPU GDT with the boot GDT,
	 * and set up the GDT descriptor:
	 */
#ifndef CONFIG_XEN
	if (cpu) {
		memcpy(cpu_gdt_table[cpu], cpu_gdt_table[0], GDT_SIZE);
	}	
#endif

	cpu_gdt_descr[cpu].size = GDT_SIZE;
	cpu_gdt_init(&cpu_gdt_descr[cpu]);

        memset(me->thread.tls_array, 0, GDT_ENTRY_TLS_ENTRIES * 8);

	/*
	 * Delete NT
	 */

	asm volatile("pushfq ; popq %%rax ; btr $14,%%rax ; pushq %%rax ; popfq" ::: "eax");

	if (cpu == 0) 
		early_identify_cpu(&boot_cpu_data);

	syscall_init();

	wrmsrl(MSR_FS_BASE, 0);
	wrmsrl(MSR_KERNEL_GS_BASE, 0);
	barrier(); 

	check_efer();

#ifndef CONFIG_X86_NO_TSS
	/*
	 * set up and load the per-CPU TSS
	 */
	for (v = 0; v < N_EXCEPTION_STACKS; v++) {
		if (cpu) {
			estacks = (char *)__get_free_pages(GFP_ATOMIC, 
						   EXCEPTION_STACK_ORDER);
			if (!estacks)
				panic("Cannot allocate exception stack %ld %d\n",
				      v, cpu); 
		}
		estacks += EXCEPTION_STKSZ;
		t->ist[v] = (unsigned long)estacks;
	}

	t->io_bitmap_base = offsetof(struct tss_struct, io_bitmap);
	/*
	 * <= is required because the CPU will access up to
	 * 8 bits beyond the end of the IO permission bitmap.
	 */
	for (i = 0; i <= IO_BITMAP_LONGS; i++)
		t->io_bitmap[i] = ~0UL;
#endif

	atomic_inc(&init_mm.mm_count);
	me->active_mm = &init_mm;
	if (me->mm)
		BUG();
	enter_lazy_tlb(&init_mm, me);

#ifndef CONFIG_X86_NO_TSS
	set_tss_desc(cpu, t);
#endif
#ifndef CONFIG_XEN
	load_TR_desc();
#endif
	load_LDT(&init_mm.context);

	/*
	 * Clear all 6 debug registers:
	 */

	set_debug(0UL, 0);
	set_debug(0UL, 1);
	set_debug(0UL, 2);
	set_debug(0UL, 3);
	set_debug(0UL, 6);
	set_debug(0UL, 7);

	fpu_init(); 

#ifdef CONFIG_NUMA
	numa_add_cpu(cpu);
#endif
}

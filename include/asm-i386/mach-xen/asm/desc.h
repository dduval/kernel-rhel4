#ifndef __ARCH_DESC_H
#define __ARCH_DESC_H

#include <asm/ldt.h>
#include <asm/segment.h>

#ifndef __ASSEMBLY__

#include <linux/preempt.h>
#include <linux/smp.h>

#include <asm/mmu.h>

extern struct desc_struct cpu_gdt_table[NR_CPUS][GDT_ENTRIES];

struct Xgt_desc_struct {
	unsigned short size;
	unsigned long address __attribute__((packed));
	unsigned short pad;
} __attribute__ ((packed));

extern struct Xgt_desc_struct idt_descr, cpu_gdt_descr[NR_CPUS];

extern void trap_init_virtual_IDT(void);
extern void trap_init_virtual_GDT(void);

// asmlinkage int system_call(void);
asmlinkage void lcall7(void);
asmlinkage void lcall27(void);

#define load_TR_desc() __asm__ __volatile__("ltr %%ax"::"a" (GDT_ENTRY_TSS*8))
#define load_LDT_desc() __asm__ __volatile__("lldt %%ax"::"a" (GDT_ENTRY_LDT*8))

#define get_cpu_gdt_table(_cpu) ((struct desc_struct *)cpu_gdt_descr[(_cpu)].address)

/*
 * This is the ldt that every process will get unless we need
 * something other than this.
 */
extern struct desc_struct default_ldt[];
extern void set_intr_gate(unsigned int irq, void * addr);
extern void set_trap_gate(unsigned int n, void *addr);

#define _set_tssldt_desc(n,addr,limit,type) \
__asm__ __volatile__ ("movw %w3,0(%2)\n\t" \
	"movw %%ax,2(%2)\n\t" \
	"rorl $16,%%eax\n\t" \
	"movb %%al,4(%2)\n\t" \
	"movb %4,5(%2)\n\t" \
	"movb $0,6(%2)\n\t" \
	"movb %%ah,7(%2)\n\t" \
	"rorl $16,%%eax" \
	: "=m"(*(n)) : "a" (addr), "r"(n), "ir"(limit), "i"(type))

#ifndef CONFIG_X86_NO_TSS
static inline void __set_tss_desc(unsigned int cpu, unsigned int entry, void *addr)
{
	_set_tssldt_desc(&get_cpu_gdt_table(cpu)[entry], (int)addr,
		offsetof(struct tss_struct, __cacheline_filler) - 1, 0x89);
}

#define set_tss_desc(cpu,addr) __set_tss_desc(cpu, GDT_ENTRY_TSS, addr)
#endif

static inline void set_ldt_desc(unsigned int cpu, void *addr, unsigned int size)
{
	_set_tssldt_desc(&get_cpu_gdt_table(cpu)[GDT_ENTRY_LDT],
	    (int)addr, ((size << 3)-1), 0x82);
}

#define LDT_entry_a(info) \
	((((info)->base_addr & 0x0000ffff) << 16) | ((info)->limit & 0x0ffff))

#define LDT_entry_b(info) \
	(((info)->base_addr & 0xff000000) | \
	(((info)->base_addr & 0x00ff0000) >> 16) | \
	((info)->limit & 0xf0000) | \
	(((info)->read_exec_only ^ 1) << 9) | \
	((info)->contents << 10) | \
	(((info)->seg_not_present ^ 1) << 15) | \
	((info)->seg_32bit << 22) | \
	((info)->limit_in_pages << 23) | \
	((info)->useable << 20) | \
	0x7000)

#define LDT_empty(info) (\
	(info)->base_addr	== 0	&& \
	(info)->limit		== 0	&& \
	(info)->contents	== 0	&& \
	(info)->read_exec_only	== 1	&& \
	(info)->seg_32bit	== 0	&& \
	(info)->limit_in_pages	== 0	&& \
	(info)->seg_not_present	== 1	&& \
	(info)->useable		== 0	)

extern int write_ldt_entry(void *ldt, int entry, __u32 entry_a, __u32 entry_b);

#if TLS_SIZE != 24
# error update this code.
#endif

static inline void load_TLS(struct thread_struct *t, unsigned int cpu)
{
#define C(i) HYPERVISOR_update_descriptor(virt_to_machine(&get_cpu_gdt_table(cpu)[GDT_ENTRY_TLS_MIN + i]), *(u64 *)&t->tls_array[i])
	C(0); C(1); C(2);
#undef C
}

static inline void clear_LDT(void)
{
	int cpu = get_cpu();

	/*
	 * NB. We load the default_ldt for lcall7/27 handling on demand, as
	 * it slows down context switching. Noone uses it anyway.
	 */
	cpu = cpu;		/* XXX avoid compiler warning */
	xen_set_ldt(0UL, 0);
	put_cpu();
}

extern struct page *default_ldt_page;

/*
 * load one particular LDT into the current CPU
 */
static inline void load_LDT_nolock(mm_context_t *pc, int cpu)
{
	void *segments = pc->ldt;
	int count = pc->size;

	if (likely(!count))
		segments = NULL;

	xen_set_ldt((unsigned long)segments, count);
}

static inline void load_LDT(mm_context_t *pc)
{
	int cpu = get_cpu();
	load_LDT_nolock(pc, cpu);
	put_cpu();
}

static inline void set_user_cs(struct desc_struct *desc, unsigned long limit)
{
	limit = (limit - 1) / PAGE_SIZE;
	desc->a = limit & 0xffff;
	desc->b = (limit & 0xf0000) | 0x00c0fb00;
}

#define load_user_cs_desc(cpu, mm) \
    	HYPERVISOR_update_descriptor(virt_to_machine(&get_cpu_gdt_table(cpu)[GDT_ENTRY_DEFAULT_USER_CS]), (u64)(mm)->context.user_cs.a | ((u64)(mm)->context.user_cs.b) << 32);

extern void arch_add_exec_range(struct mm_struct *mm, unsigned long limit);
extern void arch_remove_exec_range(struct mm_struct *mm, unsigned long limit);
extern void arch_flush_exec_range(struct mm_struct *mm);


static inline unsigned long get_desc_base(unsigned long *desc)
{
 	unsigned long base;
  	base = ((desc[0] >> 16)  & 0x0000ffff) |
   		((desc[1] << 16) & 0x00ff0000) |
    		(desc[1] & 0xff000000);
     	return base;
}

#endif /* !__ASSEMBLY__ */
#endif

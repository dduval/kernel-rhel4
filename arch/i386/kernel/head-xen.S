
#include <linux/config.h>

.text
#include <linux/threads.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <asm/thread_info.h>
#include <asm/asm_offsets.h>
#include <xen/interface/arch-x86_32.h>

/*
 * References to members of the new_cpu_data structure.
 */

#define X86		new_cpu_data+CPUINFO_x86
#define X86_VENDOR	new_cpu_data+CPUINFO_x86_vendor
#define X86_MODEL	new_cpu_data+CPUINFO_x86_model
#define X86_MASK	new_cpu_data+CPUINFO_x86_mask
#define X86_HARD_MATH	new_cpu_data+CPUINFO_hard_math
#define X86_CPUID	new_cpu_data+CPUINFO_cpuid_level
#define X86_CAPABILITY	new_cpu_data+CPUINFO_x86_capability
#define X86_VENDOR_ID	new_cpu_data+CPUINFO_x86_vendor_id

#define VIRT_ENTRY_OFFSET 0x0
.org VIRT_ENTRY_OFFSET
ENTRY(startup_32)
	movl %esi,xen_start_info
	cld

	/* Set up the stack pointer */
	movl $(init_thread_union+THREAD_SIZE),%esp

	/* get vendor info */
	xorl %eax,%eax			# call CPUID with 0 -> return vendor ID
	XEN_CPUID
	movl %eax,X86_CPUID		# save CPUID level
	movl %ebx,X86_VENDOR_ID		# lo 4 chars
	movl %edx,X86_VENDOR_ID+4	# next 4 chars
	movl %ecx,X86_VENDOR_ID+8	# last 4 chars

	movl $1,%eax		# Use the CPUID instruction to get CPU type
	XEN_CPUID
	movb %al,%cl		# save reg for future use
	andb $0x0f,%ah		# mask processor family
	movb %ah,X86
	andb $0xf0,%al		# mask model
	shrb $4,%al
	movb %al,X86_MODEL
	andb $0x0f,%cl		# mask mask revision
	movb %cl,X86_MASK
	movl %edx,X86_CAPABILITY

	movb $1,X86_HARD_MATH

	xorl %eax,%eax			# Clear FS/GS and LDT
	movl %eax,%fs
	movl %eax,%gs
	cld			# gcc2 wants the direction flag cleared at all times

	call start_kernel
L6:
	jmp L6			# main should never return here, but
				# just in case, we know what happens.

#define HYPERCALL_PAGE_OFFSET 0x1000
.org HYPERCALL_PAGE_OFFSET
ENTRY(hypercall_page)
.skip 0x1000

/*
 * Real beginning of normal "text" segment
 */
ENTRY(stext)
ENTRY(_stext)

/*
 * BSS section
 */
.section ".bss.page_aligned","w"
ENTRY(empty_zero_page)
      .fill 4096,1,0

/*
 * This starts the data section.
 */
.data

	ALIGN
	.word 0				# 32 bit align gdt_desc.address
	.globl cpu_gdt_descr
cpu_gdt_descr:
	.word GDT_SIZE
	.long cpu_gdt_table

	.fill NR_CPUS-1,8,0		# space for the other GDT descriptors

/*
 * The Global Descriptor Table contains 28 quadwords, per-CPU.
 */
	.align PAGE_SIZE_asm
ENTRY(cpu_gdt_table)
	.quad 0x0000000000000000	/* NULL descriptor */
	.quad 0x0000000000000000	/* 0x0b reserved */
	.quad 0x0000000000000000	/* 0x13 reserved */
	.quad 0x0000000000000000	/* 0x1b reserved */
	.quad 0x0000000000000000	/* 0x20 unused */
	.quad 0x0000000000000000	/* 0x28 unused */
	.quad 0x0000000000000000	/* 0x33 TLS entry 1 */
	.quad 0x0000000000000000	/* 0x3b TLS entry 2 */
	.quad 0x0000000000000000	/* 0x43 TLS entry 3 */
	.quad 0x0000000000000000	/* 0x4b reserved */
	.quad 0x0000000000000000	/* 0x53 reserved */
	.quad 0x0000000000000000	/* 0x5b reserved */

	.quad 0x00cf9a000000ffff	/* 0x60 kernel 4GB code at 0x00000000 */
	.quad 0x00cf92000000ffff	/* 0x68 kernel 4GB data at 0x00000000 */
	.quad 0x00cffa000000ffff	/* 0x73 user 4GB code at 0x00000000 */
	.quad 0x00cff2000000ffff	/* 0x7b user 4GB data at 0x00000000 */

	.quad 0x0000000000000000	/* 0x80 TSS descriptor */
	.quad 0x0000000000000000	/* 0x88 LDT descriptor */

	/* Segments used for calling PnP BIOS */
	.quad 0x0000000000000000	/* 0x90 32-bit code */
	.quad 0x0000000000000000	/* 0x98 16-bit code */
	.quad 0x0000000000000000	/* 0xa0 16-bit data */
	.quad 0x0000000000000000	/* 0xa8 16-bit data */
	.quad 0x0000000000000000	/* 0xb0 16-bit data */
	/*
	 * The APM segments have byte granularity and their bases
	 * and limits are set at run time.
	 */
	.quad 0x0000000000000000	/* 0xb8 APM CS    code */
	.quad 0x0000000000000000	/* 0xc0 APM CS 16 code (16 bit) */
	.quad 0x0000000000000000	/* 0xc8 APM DS    data */
	.quad 0x0000000000000000	/* 0xd0 - ESPFIX 16-bit SS */
	.quad 0x0000000000000000	/* 0xd8 - unused */
	.quad 0x0000000000000000	/* 0xe0 - unused */
	.quad 0x0000000000000000	/* 0xe8 - unused */
	.quad 0x0000000000000000	/* 0xf0 - unused */
	.quad 0x0000000000000000	/* 0xf8 - GDT entry 31: double-fault TSS */
	.fill GDT_ENTRIES-32,8,0
	.fill 0x1000/8-GDT_ENTRIES,8,0	/* Pad to a complete page */

/*
 * __xen_guest information
 */
.macro utoa value
 .if (\value) < 0 || (\value) >= 0x10
	utoa (((\value)>>4)&0x0fffffff)
 .endif
 .if ((\value) & 0xf) < 10
  .byte '0' + ((\value) & 0xf)
 .else
  .byte 'A' + ((\value) & 0xf) - 10
 .endif
.endm

.section __xen_guest
	.ascii	"GUEST_OS=linux,GUEST_VER=2.6"
	.ascii	",XEN_VER=xen-3.0"
	.ascii	",VIRT_BASE=0x"
		utoa __PAGE_OFFSET
	.ascii	",ELF_PADDR_OFFSET=0x"
		utoa __PAGE_OFFSET
	.ascii	",VIRT_ENTRY=0x"
		utoa (__PAGE_OFFSET + __PHYSICAL_START + VIRT_ENTRY_OFFSET)
	.ascii	",HYPERCALL_PAGE=0x"
		utoa ((__PHYSICAL_START+HYPERCALL_PAGE_OFFSET)>>PAGE_SHIFT)
	.ascii  ",FEATURES=writable_page_tables"
	.ascii	         "|writable_descriptor_tables"
	.ascii	         "|auto_translated_physmap"
	.ascii	         "|pae_pgdir_above_4gb"
	.ascii	         "|supervisor_mode_kernel"
#ifdef CONFIG_X86_PAE
	.ascii	",PAE=yes[extended-cr3]"
#else
	.ascii	",PAE=no"
#endif
	.ascii	",LOADER=generic"
	.byte	0

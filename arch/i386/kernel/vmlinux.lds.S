/* ld script to make i386 Linux kernel
 * Written by Martin Mares <mj@atrey.karlin.mff.cuni.cz>;
 */

#include <asm-generic/vmlinux.lds.h>
#include <asm/thread_info.h>
#include <asm/page.h>
#include <asm/cache.h>

#include <linux/config.h>
#include <asm/page.h>
#include <asm/asm_offsets.h>

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(startup_32)
jiffies = jiffies_64;
SECTIONS
{
  . = __PAGE_OFFSET + 0x100000;
  /* read-only */
  _text = .;			/* Text and read-only data */
  .text : {
	*(.text)
	SCHED_TEXT
	LOCK_TEXT
	*(.fixup)
	*(.gnu.warning)
	} = 0x9090

#ifdef CONFIG_X86_4G
  . = ALIGN(PAGE_SIZE_asm);
  __entry_tramp_start = .;
  . = FIX_ENTRY_TRAMPOLINE_0_addr;
  __start___entry_text = .;
  .entry.text : AT (__entry_tramp_start) { *(.entry.text) }
  __entry_tramp_end = __entry_tramp_start + SIZEOF(.entry.text);
  . = __entry_tramp_end;
  . = ALIGN(PAGE_SIZE_asm);
#else
  .entry.text : { *(.entry.text) }
#endif

  _etext = .;			/* End of text section */

  . = ALIGN(16);		/* Exception table */
  __start___ex_table = .;
  __ex_table : { *(__ex_table) }
  __stop___ex_table = .;

  RODATA

  /* writeable */
  .data : {			/* Data */
	*(.data)
	CONSTRUCTORS
	}

  . = ALIGN(PAGE_SIZE_asm);
  __nosave_begin = .;
  .data_nosave : { *(.data.nosave) }
  . = ALIGN(PAGE_SIZE_asm);
  __nosave_end = .;

  . = ALIGN(32);
  .data.cacheline_aligned : { *(.data.cacheline_aligned) }

  _edata = .;			/* End of data section */

  . = ALIGN(THREAD_SIZE);	/* init_task */
  .data.init_task : { *(.data.init_task) }

  /* will be freed after init */
  . = ALIGN(PAGE_SIZE_asm);		/* Init code and data */
  __init_begin = .;
  .init.text : { 
	_sinittext = .;
	*(.init.text)
	_einittext = .;
  }
  .init.data : { *(.init.data) }
  . = ALIGN(16);
  __setup_start = .;
  .init.setup : { *(.init.setup) }
  __setup_end = .;
  __initcall_start = .;
  .initcall.init : {
	*(.initcall1.init) 
	*(.initcall2.init) 
	*(.initcall3.init) 
	*(.initcall4.init) 
	*(.initcall5.init) 
	*(.initcall6.init) 
	*(.initcall7.init)
  }
  __initcall_end = .;
  __con_initcall_start = .;
  .con_initcall.init : { *(.con_initcall.init) }
  __con_initcall_end = .;
  SECURITY_INIT
  . = ALIGN(4);
  __alt_instructions = .;
  .altinstructions : { *(.altinstructions) } 
  __alt_instructions_end = .; 
 .altinstr_replacement : { *(.altinstr_replacement) } 
  /* .exit.text is discard at runtime, not link time, to deal with references
     from .altinstructions and .eh_frame */
  .exit.text : { *(.exit.text) }
  .exit.data : { *(.exit.data) }
  . = ALIGN(PAGE_SIZE_asm);
  __initramfs_start = .;
  .init.ramfs : { *(.init.ramfs) }
  __initramfs_end = .;
  . = ALIGN(L1_CACHE_BYTES);
  __per_cpu_start = .;
  .data.percpu  : { *(.data.percpu) }
  __per_cpu_end = .;
  . = ALIGN(PAGE_SIZE_asm);
  __init_end = .;
  /* freed after init ends here */

  . = ALIGN(PAGE_SIZE_asm);
  .data.page_aligned_tss : { *(.data.tss) }

  . = ALIGN(PAGE_SIZE_asm);
  .data.page_aligned_default_ldt : { *(.data.default_ldt) }

  . = ALIGN(PAGE_SIZE_asm);
  .data.page_aligned_idt : { *(.data.idt) }

  . = ALIGN(PAGE_SIZE_asm);
  .data.page_aligned_gdt : { *(.data.gdt) }

  __bss_start = .;		/* BSS */
  .bss : {
	*(.bss.page_aligned)
	*(.bss)
  }
  . = ALIGN(4);
  __bss_stop = .; 

  _end = . ;

  /* This is where the kernel creates the early boot page tables */
  . = ALIGN(4096);
  pg0 = .;

  /* Sections to be discarded */
  /DISCARD/ : {
	*(.exitcall.exit)
	}

  /* Stabs debugging sections.  */
  .stab 0 : { *(.stab) }
  .stabstr 0 : { *(.stabstr) }
  .stab.excl 0 : { *(.stab.excl) }
  .stab.exclstr 0 : { *(.stab.exclstr) }
  .stab.index 0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }
  .comment 0 : { *(.comment) }


}

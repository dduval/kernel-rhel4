#
# Makefile for the linux kernel.
#

extra-y 	:= head.o head64.o init_task.o vmlinux.lds
EXTRA_AFLAGS	:= -traditional
obj-y	:= process.o semaphore.o signal.o entry.o traps.o irq.o \
		ptrace.o i8259.o ioport.o ldt.o setup.o time.o sys_x86_64.o \
		x8664_ksyms.o i387.o syscall.o vsyscall.o \
		setup64.o bootflag.o e820.o reboot.o warmreboot.o 
obj-y += mce.o
obj-y += dmi_scan.o
obj-$(CONFIG_X86_LOCAL_APIC)	+= perfctr-watchdog.o

obj-$(CONFIG_X86_MCE_AMD)       += mce_amd.o
obj-$(CONFIG_MTRR)		+= ../../i386/kernel/cpu/mtrr/
obj-$(CONFIG_ACPI_BOOT)		+= acpi/
obj-$(CONFIG_X86_MSR)		+= msr.o
obj-$(CONFIG_MICROCODE)		+= microcode.o
obj-$(CONFIG_X86_CPUID)		+= cpuid.o
obj-$(CONFIG_SMP)		+= smp.o smpboot.o trampoline.o
obj-$(CONFIG_X86_LOCAL_APIC)	+= apic.o  nmi.o
obj-$(CONFIG_X86_XEN_GENAPIC)	+= genapic.o genapic_xen.o
obj-$(CONFIG_X86_IO_APIC)	+= io_apic.o mpparse.o \
		genapic.o genapic_cluster.o genapic_flat.o
obj-$(CONFIG_PM)		+= suspend.o
obj-$(CONFIG_SOFTWARE_SUSPEND)	+= suspend_asm.o
obj-$(CONFIG_CPU_FREQ)		+= cpufreq/
obj-$(CONFIG_EARLY_PRINTK)	+= early_printk.o
obj-$(CONFIG_GART_IOMMU)	+= pci-gart.o aperture.o
obj-$(CONFIG_DUMMY_IOMMU)	+= pci-nommu.o pci-dma.o
obj-$(CONFIG_SWIOTLB)		+= swiotlb.o
obj-$(CONFIG_KPROBES)		+= kprobes.o
obj-$(CONFIG_X86_PM_TIMER)	+= pmtimer.o

obj-$(CONFIG_MODULES)		+= module.o

obj-y				+= topology.o
obj-y				+= intel_cacheinfo.o

obj-$(CONFIG_X86_LOCAL_APIC_INFO_MOD)	+= lapic_status.o
bootflag-y			+= ../../i386/kernel/bootflag.o
cpuid-$(subst m,y,$(CONFIG_X86_CPUID))  += ../../i386/kernel/cpuid.o
topology-y                     += ../../i386/mach-default/topology.o
swiotlb-$(CONFIG_SWIOTLB)      += ../../ia64/lib/swiotlb.o
microcode-$(subst m,y,$(CONFIG_MICROCODE))  += ../../i386/kernel/microcode.o
intel_cacheinfo-y		+= ../../i386/kernel/cpu/intel_cacheinfo.o

ifdef CONFIG_XEN
time-y				+= ../../i386/kernel/time-xen.o
quirks-y			:= ../../i386/kernel/quirks-xen.o

n-obj-xen := i8259.o reboot.o i8237.o smpboot.o trampoline.o

include $(srctree)/scripts/Makefile.xen

obj-y := $(call filterxen, $(obj-y), $(n-obj-xen))
obj-y := $(call cherrypickxen, $(obj-y))
extra-y := $(call cherrypickxen, $(extra-y))
endif

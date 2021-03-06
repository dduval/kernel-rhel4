#
# Makefile for X86_64 specific PCI routines
#
# Reuse the i386 PCI subsystem
#
CFLAGS += -Iarch/i386/pci

obj-y		:= i386.o
obj-$(CONFIG_PCI_DIRECT)+= direct.o
obj-y		+= fixup.o
obj-$(CONFIG_ACPI_PCI)	+= acpi.o
obj-y			+= legacy.o irq.o common.o
# mmconfig has a 64bit special
obj-$(CONFIG_PCI_MMCONFIG) += mmconfig.o direct.o

obj-$(CONFIG_NUMA)	+= k8-bus.o

# pcifront should be after mmconfig.o and direct.o as it should only
# take over if direct access to the PCI bus is unavailable
obj-$(CONFIG_XEN_PCIDEV_FRONTEND)	+= pcifront.o

direct-y += ../../i386/pci/direct.o
acpi-y   += ../../i386/pci/acpi.o
pcifront-y += ../../i386/pci/pcifront.o
legacy-y += ../../i386/pci/legacy.o
irq-y    += ../../i386/pci/irq.o
common-y += ../../i386/pci/common.o
fixup-y  += ../../i386/pci/fixup.o
i386-y  += ../../i386/pci/i386.o

ifdef CONFIG_XEN
irq-y		:= ../../i386/pci/irq-xen.o
include $(srctree)/scripts/Makefile.xen

obj-y := $(call cherrypickxen, $(obj-y))
endif

#
# Makefile for the linux x86_64-specific parts of the memory manager.
#

obj-y	 := init.o fault.o ioremap.o extable.o pageattr.o mmap.o
obj-$(CONFIG_HUGETLB_PAGE) += hugetlbpage.o
obj-$(CONFIG_DISCONTIGMEM) += numa.o
obj-$(CONFIG_K8_NUMA) += k8topology.o
obj-$(CONFIG_ACPI_NUMA) += srat.o
obj-$(CONFIG_XEN) += hypervisor.o

ifdef CONFIG_XEN
include $(srctree)/scripts/Makefile.xen
obj-y := $(call cherrypickxen, $(obj-y))
endif

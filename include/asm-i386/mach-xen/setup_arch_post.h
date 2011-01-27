/**
 * machine_specific_memory_setup - Hook for machine specific memory setup.
 *
 * Description:
 *	This is included late in kernel/setup.c so that it can make
 *	use of all of the static functions.
 **/

static char * __init machine_specific_memory_setup(void)
{
	unsigned long max_pfn = xen_start_info->nr_pages;

	e820.nr_map = 0;
	add_memory_region(0, PFN_PHYS(max_pfn), E820_RAM);

	return "Xen";
}

extern void hypervisor_callback(void);
extern void failsafe_callback(void);
extern void nmi(void);

extern unsigned long *machine_to_phys_mapping;
extern unsigned int machine_to_phys_order;

#include <xen/interface/memory.h>

static void __init machine_specific_arch_setup(void)
{
	struct xen_platform_parameters pp;
	struct xennmi_callback cb;
	struct xen_machphys_mapping mapping;
	unsigned long machine_to_phys_nr_ents;

	if (xen_feature(XENFEAT_auto_translated_physmap) &&
	    xen_start_info->shared_info < xen_start_info->nr_pages) {
		HYPERVISOR_shared_info =
			(shared_info_t *)__va(xen_start_info->shared_info);
		memset(empty_zero_page, 0, sizeof(empty_zero_page));
	}

	HYPERVISOR_set_callbacks(
	    __KERNEL_CS, (unsigned long)hypervisor_callback,
	    __KERNEL_CS, (unsigned long)failsafe_callback);

	cb.handler_address = (unsigned long)&nmi;
	HYPERVISOR_nmi_op(XENNMI_register_callback, &cb);

	if (HYPERVISOR_xen_version(XENVER_platform_parameters,
				   &pp) == 0)
		set_fixaddr_top(pp.virt_start - PAGE_SIZE);

	machine_to_phys_mapping = (unsigned long *)MACH2PHYS_VIRT_START;
	machine_to_phys_nr_ents = MACH2PHYS_NR_ENTRIES;
	if (HYPERVISOR_memory_op(XENMEM_machphys_mapping, &mapping) == 0) {
		machine_to_phys_mapping = (unsigned long *)mapping.v_start;
		machine_to_phys_nr_ents = mapping.max_mfn + 1;
	}
	while ((1UL << machine_to_phys_order) < machine_to_phys_nr_ents )
		machine_to_phys_order++;
}

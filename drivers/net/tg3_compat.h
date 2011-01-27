#ifndef __TG3_COMPAT_H__
#define __TG3_COMPAT_H__

#define skb_header_cloned(skb) 0

#define pci_choose_state(pdev, state) (state)

typedef u32 pm_message_t;

#ifndef ADVERTISE_PAUSE
#define ADVERTISE_PAUSE_CAP		0x0400
#endif
#ifndef ADVERTISE_PAUSE_ASYM
#define ADVERTISE_PAUSE_ASYM		0x0800
#endif
#ifndef LPA_PAUSE
#define LPA_PAUSE_CAP			0x0400
#endif
#ifndef LPA_PAUSE_ASYM
#define LPA_PAUSE_ASYM			0x0800
#endif

/**
 * pci_dev_present - Returns 1 if device matching the device list is present, 0 if not.
 * @ids: A pointer to a null terminated list of struct pci_device_id structures
 * that describe the type of PCI device the caller is trying to find.
 *
 * This is a cheap knock-off, just to help in back-porting tg3 from
 * later kernels...beware of changes in usage...
 */
static inline int pci_dev_present(const struct pci_device_id *ids)
{
	const struct pci_device_id *dev;

	for (dev = ids; dev->vendor; dev++) {
		if (pci_find_device(dev->vendor, dev->device, NULL))
			return 1;
	}
	return 0;
}
#endif /* __TG3_COMPAT_H__ */
#include <linux/serial.h>
#include <asm/serial.h>
#include <asm/udbg.h>

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <asm/prom.h>

static inline int check_type(struct device_node *np, const char *s)
{
	char *type;

	if (np == NULL)
		return 0;

	type = (char *)get_property(np, "device_type", NULL);
	if (type == NULL)
		return 0;

	return strncmp(s, type, max(strlen(s), strlen(type))) == 0;
}

/* Read a big address */
static inline u64 of_read_addr(u32 *cell, int size)
{
	u64 r = 0;
	while (size--)
		r = (r << 32) | *(cell++);
	return r;
}

static u64 of_translate_pci_addr(struct device_node *pd, u32 *addr)
{
	struct device_node *bus = of_get_parent(pd);
	struct device_node *gparent;
	u32 new_addr[3], *ranges;
	unsigned int rlen;
	u64 result = 0;
	int pna, rs;

	/* No parent or non-PCI parent -> this wasn't a PCI device in the
	 * first place, bail out
	 */
	if (bus == NULL || !check_type(bus, "pci"))
		goto bail;

	/* Get the bus parent if any */
	gparent = of_get_parent(bus);

	/* Check if it's PCI, if not, drop it */
	if (gparent && !check_type(gparent, "pci")) {
		of_node_put(gparent);
		gparent = NULL;
	}

	/* We have a PCI grand parent, then parent address cell size is 3,
	 * else, we query OF. We do that since on well defined busses like
	 * PCI, the #address-cell property is unfortunately optional (sic !)
	 */
	if (gparent) {
		pna = 3;
		of_node_put(gparent);
	} else
		pna = prom_n_addr_cells(bus);

	/* Get the pci bus "ranges" property */
	ranges = (u32 *)get_property(bus, "ranges", &rlen);
	if (ranges == NULL)
		return 0;
	rlen /= 4;

	/* Walk through the ranges. Format is:
	 *   child_phys  parent_phys  size
	 *   (3 cells)   (pna cells)  (2 cell)
	 */
	rs = 3 + pna + 2;
	for (; rlen >= rs; rlen -= rs, ranges += rs) {
		u64 cp, pp, s, da;

		 /* Check address type match */
		if ((addr[0] ^ ranges[0]) & 0x03000000)
			continue;

		cp = of_read_addr(ranges, 3);
		pp = of_read_addr(ranges + 3, pna);
		s  = of_read_addr(ranges + pna + 3, 2);
		da = of_read_addr(addr, 3);

		if (da < cp || da >= (cp + s))
			continue;

		da = pp + (da - cp);

		/* Root: no more translations */
		if (gparent == NULL)
			result = (u64)da;
		else {
			/* Translate it again */
			new_addr[0] = ranges[3];
			new_addr[1] = da >> 32;
			new_addr[2] = da & 0xffffffffu;

			result = of_translate_pci_addr(bus, &new_addr[0]);
		}
		break;
	}

bail:
	of_node_put(bus);
	return result;
}

static u32 *of_get_pci_address(struct device_node *dev, int bar_no, u64 *size)
{
	u32 *addr;
	unsigned int psize;
	int onesize, i;

	addr = (u32 *)get_property(dev, "assigned-addresses", &psize);
	if (addr == NULL)
		return NULL;
	psize /= 4;

	onesize = 3 + 2; /* for PCI */
	for (i = 0; psize >= onesize; psize -= onesize, addr += onesize, i++)
		if ((addr[0] & 0xff) == PCI_BASE_ADDRESS_0) /* Assume BAR 0 */
			return addr;

	return NULL;
}

/* return 1 if we find a usable pci serial console */
static int add_pci_serial_port(struct device_node *np,
		struct device_node *parent)
{
	unsigned long addr;
	void *raddr;
	u32 *u32p, clock, speed;
	int lindex = 0;

	/* We only support ports that have a clock frequency */
	u32p = (u32 *)get_property(np, "clock-frequency", NULL);
	if (u32p == NULL)
		return 0;

	/* Use the specified clock if it's sane, otherwise guess */
	clock = *u32p ? *u32p : BASE_BAUD * 16;

	/* Get the PCI address. Assume BAR 0 */
	u32p = of_get_pci_address(parent, 0, NULL);
	if (u32p == NULL)
		return 0;

	addr = of_translate_pci_addr(parent, u32p);

	/* Local index means it's the Nth port in the PCI chip. The offset
	 * to add here is device specific. This works for the EXAR. */
	u32 *reg = (u32 *)get_property(np, "reg", NULL);
	if (reg && (*reg < 4))
		lindex = *reg;

	addr += 0x200 * lindex;
	raddr = ioremap(addr, 0x1000);

	speed = udbg_probe_uart_speed(raddr, clock);
	udbg_init_uart(raddr, speed, clock);

	return 1;
}

int add_legacy_serial_port(struct device_node *np)
{
	struct device_node *parent;
	char *name;
	int found = 0;

	parent = of_get_parent(np);
	if (parent == NULL)
		return found;

	name = (char *)get_property(parent, "name", NULL);

	if (name == NULL)
		found = 0;
	else if (strncmp(name, "isa", 3) == 0)
		/* XXX fix ISA serial console */
		found = 0;
	else if (device_is_compatible(parent, "pci13a8,152") ||
	    device_is_compatible(parent, "pci13a8,154") ||
	    device_is_compatible(parent, "pci13a8,158"))
		/* We only support the EXAR chip at the moment */
		found = add_pci_serial_port(np, parent);

	of_node_put(parent);
	return found;
}

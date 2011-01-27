#ifndef __LIBATA_COMPAT_H__
#define __LIBATA_COMPAT_H__

#include <asm/scatterlist.h>

typedef unsigned int pm_message_t;

static inline void sg_set_buf(struct scatterlist *sg, void *buf,
			      unsigned int buflen)
{
	sg->page = virt_to_page(buf);
	sg->offset = offset_in_page(buf);
	sg->length = buflen;
}

static inline void sg_init_one(struct scatterlist *sg, void *buf,
			       unsigned int buflen)
{
	memset(sg, 0, sizeof(*sg));
	sg_set_buf(sg, buf, buflen);
}

static inline void
pci_intx(struct pci_dev *pdev, int enable)
{
	u16 pci_command, new;

	pci_read_config_word(pdev, PCI_COMMAND, &pci_command);

	if (enable) {
		new = pci_command & ~PCI_COMMAND_INTX_DISABLE;
	} else {
		new = pci_command | PCI_COMMAND_INTX_DISABLE;
	}

	if (new != pci_command) {
		pci_write_config_word(pdev, PCI_COMMAND, new);
	}
}

#endif /* __LIBATA_COMPAT_H__ */

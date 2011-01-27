#ifndef __LIBATA_COMPAT_H__
#define __LIBATA_COMPAT_H__

#define IRQF_SHARED SA_SHIRQ

#define PCI_D0			0
#define PCI_D3hot		3

int ata_scsi_error(struct Scsi_Host *host);
enum scsi_eh_timer_return ata_scsi_timed_out(struct scsi_cmnd *cmd);

typedef u32 pm_message_t;

typedef void (*work_func_t)(void *);

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

#ifndef __SKY2_COMPAT_H__
#define __SKY2_COMPAT_H__

#define __read_mostly

#define skb_header_cloned(skb) 0

static inline int skb_is_tso(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->tso_size;
}

#define __netif_rx_schedule_prep(dev) netif_rx_schedule_prep(dev)

typedef u32 pm_message_t;

typedef int __bitwise pci_power_t;

#define PCI_D0	((pci_power_t __force) 0)
#define PCI_D1	((pci_power_t __force) 1)
#define PCI_D2	((pci_power_t __force) 2)
#define PCI_D3hot	((pci_power_t __force) 3)
#define PCI_D3cold	((pci_power_t __force) 4)

#define pci_choose_state(pdev, state)	(state)

static inline void setup_timer(struct timer_list * timer,
				void (*function)(unsigned long),
				unsigned long data)
{
	timer->function = function;
	timer->data = data;
	init_timer(timer);
}

#endif /* __SKY2_COMPAT_H__ */

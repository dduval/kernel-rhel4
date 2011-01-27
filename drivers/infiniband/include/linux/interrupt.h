#ifndef BACKPORT_LINUX_INTERRUPT_TO_2_6_18
#define BACKPORT_LINUX_INTERRUPT_TO_2_6_18
#include_next <linux/interrupt.h>

static inline int 
backport_request_irq(unsigned int irq,
                     irqreturn_t (*handler)(int, void *),
                     unsigned long flags, const char *dev_name, void *dev_id)
{
	return request_irq(irq, 
		           (irqreturn_t (*)(int, void *, struct pt_regs *))handler, 
			   flags, dev_name, dev_id);
}

#define request_irq backport_request_irq

typedef irqreturn_t (*backport_irq_handler_t)(int, void *);

#define irq_handler_t backport_irq_handler_t

#define IRQF_DISABLED SA_INTERRUPT

#endif

/*
 *  linux/include/asm-i386/nmi.h
 */
#ifndef ASM_NMI_H
#define ASM_NMI_H

#include <linux/pm.h>
 
struct pt_regs;
 
typedef int (*nmi_callback_t)(struct pt_regs * regs, int cpu);
 
/** 
 * set_nmi_callback
 *
 * Set a handler for an NMI. Only one handler may be
 * set. Return 1 if the NMI was handled.
 */
void set_nmi_callback(nmi_callback_t callback);
 
/** 
 * unset_nmi_callback
 *
 * Remove the handler previously set.
 */
void unset_nmi_callback(void);

/**
 * do_nmi_callback
 *
 * Check to see if a callback exists and execute it. Return 1
 * if the handler exists and was handled successfully.
 */
int do_nmi_callback(struct pt_regs *regs, int cpu);

extern int avail_to_resrv_perfctr_nmi_bit(unsigned int);
extern int avail_to_resrv_perfctr_nmi(unsigned int);
extern int reserve_perfctr_nmi(unsigned int);
extern void release_perfctr_nmi(unsigned int);
extern int reserve_evntsel_nmi(unsigned int);
extern void release_evntsel_nmi(unsigned int);

void lapic_watchdog_stop(void);
int lapic_watchdog_init(unsigned nmi_hz);
int lapic_wd_event(unsigned nmi_hz);
unsigned lapic_adjust_nmi_hz(unsigned hz);
int lapic_watchdog_ok(void);
void disable_lapic_nmi_watchdog(void);
void enable_lapic_nmi_watchdog(void);
extern int nmi_watchdog_tick (struct pt_regs * regs);
#endif /* ASM_NMI_H */

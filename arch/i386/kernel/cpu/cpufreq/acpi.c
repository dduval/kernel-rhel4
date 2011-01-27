/*
 * acpi-cpufreq-io.c - ACPI Processor P-States Driver ($Revision: 1.3 $)
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2002 - 2004 Dominik Brodowski <linux@brodo.de>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/io.h>
#include <asm/delay.h>
#include <asm/uaccess.h>

#include <linux/acpi.h>
#include <acpi/processor.h>

#define ACPI_PROCESSOR_COMPONENT	0x01000000
#define ACPI_PROCESSOR_CLASS		"processor"
#define ACPI_PROCESSOR_DRIVER_NAME	"ACPI Processor P-States Driver"
#define ACPI_PROCESSOR_DEVICE_NAME	"Processor"

#define _COMPONENT		ACPI_PROCESSOR_COMPONENT
ACPI_MODULE_NAME		("acpi_processor_perf")

MODULE_AUTHOR("Paul Diefenbaugh, Dominik Brodowski");
MODULE_DESCRIPTION(ACPI_PROCESSOR_DRIVER_NAME);
MODULE_LICENSE("GPL");


struct cpufreq_acpi_io {
	struct acpi_processor_performance	*acpi_data;
	struct cpufreq_frequency_table		*freq_table;
	unsigned int				resume;
};

static struct cpufreq_acpi_io	*acpi_io_data[NR_CPUS];
static struct acpi_processor_performance	*acpi_perf_data[NR_CPUS];

static struct cpufreq_driver acpi_cpufreq_driver;

static unsigned int acpi_pstate_strict;

static int
acpi_processor_write_port(
	u16	port,
	u8	bit_width,
	u32	value)
{
	if (bit_width <= 8) {
		outb(value, port);
	} else if (bit_width <= 16) {
		outw(value, port);
	} else if (bit_width <= 32) {
		outl(value, port);
	} else {
		return -ENODEV;
	}
	return 0;
}

static int
acpi_processor_read_port(
	u16	port,
	u8	bit_width,
	u32	*ret)
{
	*ret = 0;
	if (bit_width <= 8) {
		*ret = inb(port);
	} else if (bit_width <= 16) {
		*ret = inw(port);
	} else if (bit_width <= 32) {
		*ret = inl(port);
	} else {
		return -ENODEV;
	}
	return 0;
}

static int
acpi_processor_set_performance (
	struct cpufreq_acpi_io	*data,
	unsigned int		cpu,
	int			state)
{
	u16			port = 0;
	u8			bit_width = 0;
	int			i = 0;
	int			ret = 0;
	u32			value = 0;
	int			retval;
	struct acpi_processor_performance	*perf;

	ACPI_FUNCTION_TRACE("acpi_processor_set_performance");

	retval = 0;
	perf = data->acpi_data;	
	if (state == perf->state) {
		if (unlikely(data->resume)) {
			ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				"resetting to P%d\n", state));
			data->resume = 0;
		} else {
			ACPI_DEBUG_PRINT((ACPI_DB_INFO,
				"Already at target state (P%d)\n", state));
			return (retval);
		}
	}

	ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Transitioning from P%d to P%d\n", perf->state, state));

	/*
	 * First we write the target state's 'control' value to the
	 * control_register.
	 */

	port = perf->control_register.address;
	bit_width = perf->control_register.bit_width;
	value = (u32) perf->states[state].control;
 

	ACPI_DEBUG_PRINT((ACPI_DB_INFO, 
		"Writing 0x%08x to port 0x%04x\n", value, port));

	ret = acpi_processor_write_port(port, bit_width, value);
	if (ret) {
		ACPI_DEBUG_PRINT((ACPI_DB_WARN,
			"Invalid port width 0x%04x\n", bit_width));
		return (ret);
	}

	/*
	 * Assume the write went through when acpi_pstate_strict is not used.
	 * As read status_register is an expensive operation and there
	 * are no specific error cases where an IO port write will fail.
	 */
	if (acpi_pstate_strict) {
		/*
		 * Then we read the 'status_register' and compare the value with the
		 * target state's 'status' to make sure the transition was successful.
		 * Note that we'll poll for up to 1ms (100 cycles of 10us) before
		 * giving up.
		 */

		port = perf->status_register.address;
		bit_width = perf->status_register.bit_width;

		ACPI_DEBUG_PRINT((ACPI_DB_INFO, 
			"Looking for 0x%08x from port 0x%04x\n",
			(u32) perf->states[state].status, port));

		for (i = 0; i < 100; i++) {
			ret = acpi_processor_read_port(port, bit_width, &value);
			if (ret) {	
				ACPI_DEBUG_PRINT((ACPI_DB_WARN,
					"Invalid port width 0x%04x\n", bit_width));
				return (ret);
			}
			if (value == (u32) perf->states[state].status)
				break;
			udelay(10);
		}
	} else {
		value = (u32) perf->states[state].status;
	}

	if (unlikely(value != (u32) perf->states[state].status)) {
		ACPI_DEBUG_PRINT((ACPI_DB_WARN, "Transition failed\n"));
		retval = -ENODEV;
		return (retval);
	}

	ACPI_DEBUG_PRINT((ACPI_DB_INFO, 
		"Transition successful after %d microseconds\n",
		i * 10));

	perf->state = state;
	return_VALUE(retval);
}


static int
acpi_cpufreq_target (
	struct cpufreq_policy   *policy,
	unsigned int target_freq,
	unsigned int relation)
{
	struct cpufreq_acpi_io *data = acpi_io_data[policy->cpu];
	struct acpi_processor_performance *perf;
	struct cpufreq_freqs freqs;
	cpumask_t online_policy_cpus;
	cpumask_t saved_mask;
	cpumask_t set_mask;
	cpumask_t covered_cpus;
	unsigned int cur_state = 0;
	unsigned int next_state = 0;
	unsigned int result = 0;
	unsigned int j;
	unsigned int tmp;

	ACPI_FUNCTION_TRACE("acpi_cpufreq_setpolicy");

	result = cpufreq_frequency_table_target(policy,
			data->freq_table,
			target_freq,
			relation,
			&next_state);
	if (unlikely(result))
		return_VALUE(result);

	perf = data->acpi_data;
	cur_state = perf->state;
	freqs.old = data->freq_table[cur_state].frequency;
	freqs.new = data->freq_table[next_state].frequency;

	/* cpufreq holds the hotplug lock, so we are safe from here on */
	cpus_and(online_policy_cpus, cpu_online_map, policy->cpus);

	for_each_cpu_mask(j, online_policy_cpus) {
		freqs.cpu = j;
		cpufreq_notify_transition(&freqs, CPUFREQ_PRECHANGE);
	}

	/*
	 * We need to call driver->target() on all or any CPU in
	 * policy->cpus, depending on policy->shared_type.
	 */
	saved_mask = current->cpus_allowed;
	cpus_clear(covered_cpus);
	for_each_cpu_mask(j, online_policy_cpus) {
		/*
		 * Support for SMP systems.
		 * Make sure we are running on CPU that wants to change freq
		 */
		cpus_clear(set_mask);
		if (policy->shared_type == CPUFREQ_SHARED_TYPE_ANY)
			cpus_or(set_mask, set_mask, online_policy_cpus);
		else
			cpu_set(j, set_mask);

		set_cpus_allowed(current, set_mask);
		if (unlikely(!cpu_isset(smp_processor_id(), set_mask))) {
			ACPI_DEBUG_PRINT((ACPI_DB_INFO, "couldn't limit to CPUs in this domain\n"));
			result = -EAGAIN;
			break;
		}

		result = acpi_processor_set_performance (data, j, next_state);
		if (result) {
			result = -EAGAIN;
			break;
		}
 
		if (policy->shared_type == CPUFREQ_SHARED_TYPE_ANY)
			break;
 
		cpu_set(j, covered_cpus);
	}

	for_each_cpu_mask(j, online_policy_cpus) {
		freqs.cpu = j;
		cpufreq_notify_transition(&freqs, CPUFREQ_POSTCHANGE);
	}

	if (unlikely(result)) {
		/*
		 * We have failed halfway through the frequency change.
		 * We have sent callbacks to online_policy_cpus and
		 * acpi_processor_set_performance() has been called on 
		 * coverd_cpus. Best effort undo..
		 */

		if (!cpus_empty(covered_cpus)) {
			for_each_cpu_mask(j, covered_cpus) {
				policy->cpu = j;
				acpi_processor_set_performance (data, 
						j, 
						cur_state);
			}
		}

		tmp = freqs.new;
		freqs.new = freqs.old;
		freqs.old = tmp;
		for_each_cpu_mask(j, online_policy_cpus) {
			freqs.cpu = j;
			cpufreq_notify_transition(&freqs, CPUFREQ_PRECHANGE);
			cpufreq_notify_transition(&freqs, CPUFREQ_POSTCHANGE);
		}
	}

	set_cpus_allowed(current, saved_mask);
	return_VALUE(result);
}


static int
acpi_cpufreq_verify (
	struct cpufreq_policy   *policy)
{
	unsigned int result = 0;
	struct cpufreq_acpi_io *data = acpi_io_data[policy->cpu];

	ACPI_FUNCTION_TRACE("acpi_cpufreq_verify");

	result = cpufreq_frequency_table_verify(policy, 
			data->freq_table);

	return_VALUE(result);
}


static unsigned long
acpi_cpufreq_guess_freq (
	struct cpufreq_acpi_io	*data,
	unsigned int		cpu)
{
	struct acpi_processor_performance	*perf = data->acpi_data;

	if (cpu_khz) {
		/* search the closest match to cpu_khz */
		unsigned int i;
		unsigned long freq;
		unsigned long freqn = perf->states[0].core_frequency * 1000;

		for (i = 0; i < (perf->state_count - 1); i++) {
			freq = freqn;
			freqn = perf->states[i+1].core_frequency * 1000;
			if ((2 * cpu_khz) > (freqn + freq)) {
				perf->state = i;
				return (freq);
			}
		}
		perf->state = perf->state_count - 1;
		return (freqn);
	} else {
		/* assume CPU is at P0... */
		perf->state = 0;
		return perf->states[0].core_frequency * 1000;
	}
}


/*
 * acpi_cpufreq_early_init - initialize ACPI P-States library
 *
 * Initialize the ACPI P-States library (drivers/acpi/processor_perflib.c)
 * in order to determine correct frequency and voltage pairings. We can
 * do _PDC and _PSD and find out the processor dependency for the
 * actual init that will happen later...
 */
static int acpi_cpufreq_early_init_acpi(void)
{
	struct acpi_processor_performance	*data;
	unsigned int				i, j;

	ACPI_DEBUG_PRINT((ACPI_DB_INFO, "acpi_cpufreq_early_init\n"));

	for_each_cpu(i) {
		data = kzalloc(sizeof(struct acpi_processor_performance), 
			GFP_KERNEL);
		if (!data) {
			for_each_cpu(j) {
				kfree(acpi_perf_data[j]);
				acpi_perf_data[j] = NULL;
			}
			return (-ENOMEM);
		}
		acpi_perf_data[i] = data;
	}

	/* Do initialization in ACPI core */
	acpi_processor_preregister_performance(acpi_perf_data);
	return 0;
}


/* 
 * acpi_processor_cpu_init_pdc_est - let BIOS know about the SMP capabilities
 * of this driver
 * @perf: processor-specific acpi_io_data struct
 * @cpu: CPU being initialized
 *
 * To avoid issues with legacy OSes, some BIOSes require to be informed of
 * the SMP capabilities of OS P-state driver. Here we set the bits in _PDC 
 * accordingly, for Enhanced Speedstep. Actual call to _PDC is done in
 * driver/acpi/processor.c
 */
static void 
acpi_processor_cpu_init_pdc_est(
		struct acpi_processor_performance *perf, 
		unsigned int cpu,
		struct acpi_object_list *obj_list
		)
{
	union acpi_object *obj;
	u32 *buf;
	struct cpuinfo_x86 *c = cpu_data + cpu;
	ACPI_FUNCTION_TRACE("acpi_processor_cpu_init_pdc_est");

	if (!cpu_has(c, X86_FEATURE_EST))
		return_VOID;

	/* Initialize pdc. It will be used later. */
	if (!obj_list)
		return_VOID;
		
	if (!(obj_list->count && obj_list->pointer))
		return_VOID;

	obj = obj_list->pointer;
	if ((obj->buffer.length == 12) && obj->buffer.pointer) {
		buf = (u32 *)obj->buffer.pointer;
       		buf[0] = ACPI_PDC_REVISION_ID;
       		buf[1] = 1;
       		buf[2] = ACPI_PDC_EST_CAPABILITY_SMP;
		perf->pdc = obj_list;
	}
	return_VOID;
}
 

/* CPU specific PDC initialization */
static void 
acpi_processor_cpu_init_pdc(
		struct acpi_processor_performance *perf, 
		unsigned int cpu,
		struct acpi_object_list *obj_list
		)
{
	struct cpuinfo_x86 *c = cpu_data + cpu;
	ACPI_FUNCTION_TRACE("acpi_processor_cpu_init_pdc");
	perf->pdc = NULL;
	if (cpu_has(c, X86_FEATURE_EST))
		acpi_processor_cpu_init_pdc_est(perf, cpu, obj_list);
	return_VOID;
}


static int
acpi_cpufreq_cpu_init (
	struct cpufreq_policy   *policy)
{
	unsigned int		i;
	unsigned int		cpu = policy->cpu;
	struct cpufreq_acpi_io	*data;
	unsigned int		result = 0;
	struct cpuinfo_x86 *c = &cpu_data[policy->cpu];
	struct acpi_processor_performance	*perf;

	union acpi_object		arg0 = {ACPI_TYPE_BUFFER};
	u32				arg0_buf[3];
	struct acpi_object_list		arg_list = {1, &arg0};

	ACPI_FUNCTION_TRACE("acpi_cpufreq_cpu_init");
	/* setup arg_list for _PDC settings */
        arg0.buffer.length = 12;
        arg0.buffer.pointer = (u8 *) arg0_buf;

	if (!acpi_perf_data[cpu])
		return (-ENODEV);

	data = kmalloc(sizeof(struct cpufreq_acpi_io), GFP_KERNEL);
	if (!data)
		return_VALUE(-ENOMEM);
	memset(data, 0, sizeof(struct cpufreq_acpi_io));

	data->acpi_data = acpi_perf_data[cpu];
	acpi_io_data[cpu] = data;

	acpi_processor_cpu_init_pdc(data->acpi_data, cpu, &arg_list);
	result = acpi_processor_register_performance(data->acpi_data, cpu);

	data->acpi_data->pdc = NULL;

	if (result)
		goto err_free;

	perf = data->acpi_data;
	policy->shared_type = perf->shared_type;

	if (policy->shared_type == CPUFREQ_SHARED_TYPE_ALL ||
	  policy->shared_type == CPUFREQ_SHARED_TYPE_ANY)
		policy->cpus = perf->shared_cpu_map;

	if (cpu_has(c, X86_FEATURE_CONSTANT_TSC)) {
		acpi_cpufreq_driver.flags |= CPUFREQ_CONST_LOOPS;
	}

	/* capability check */
	if (perf->state_count <= 1) {
		ACPI_DEBUG_PRINT((ACPI_DB_ERROR, "No P-States\n"));
		result = -ENODEV;
		goto err_unreg;
	}

	if ((perf->control_register.space_id != ACPI_ADR_SPACE_SYSTEM_IO) ||
	    (perf->status_register.space_id != ACPI_ADR_SPACE_SYSTEM_IO)) {
		ACPI_DEBUG_PRINT((ACPI_DB_ERROR, "Unsupported address space [%d, %d]\n",
			(u32) (perf->control_register.space_id),
			(u32) (perf->status_register.space_id)));
		result = -ENODEV;
		goto err_unreg;
	}

	/* alloc freq_table */
	data->freq_table = kmalloc(sizeof(struct cpufreq_frequency_table) * (perf->state_count + 1), GFP_KERNEL);
	if (!data->freq_table) {
		result = -ENOMEM;
		goto err_unreg;
	}

	/* detect transition latency */
	policy->cpuinfo.transition_latency = 0;
	for (i=0; i<perf->state_count; i++) {
		if ((perf->states[i].transition_latency * 1000) > policy->cpuinfo.transition_latency)
			policy->cpuinfo.transition_latency = perf->states[i].transition_latency * 1000;
	}
	policy->governor = CPUFREQ_DEFAULT_GOVERNOR;

	/* The current speed is unknown and not detectable by ACPI...  */
	policy->cur = acpi_cpufreq_guess_freq(data, policy->cpu);

	/* table init */
	for (i=0; i<=perf->state_count; i++)
	{
		data->freq_table[i].index = i;
		if (i<perf->state_count)
			data->freq_table[i].frequency = perf->states[i].core_frequency * 1000;
		else
			data->freq_table[i].frequency = CPUFREQ_TABLE_END;
	}

	result = cpufreq_frequency_table_cpuinfo(policy, data->freq_table);
	if (result) {
		goto err_freqfree;
	}
		
	/* notify BIOS that we exist */
	acpi_processor_notify_smm(THIS_MODULE);

	printk(KERN_INFO "cpufreq: CPU%u - ACPI performance management activated.\n",
	       cpu);
	for (i = 0; i < perf->state_count; i++)
		printk(KERN_INFO "cpufreq: %cP%d: %d MHz, %d mW, %d uS\n",
			(i == perf->state?'*':' '), i,
			(u32) perf->states[i].core_frequency,
			(u32) perf->states[i].power,
			(u32) perf->states[i].transition_latency);

	cpufreq_frequency_table_get_attr(data->freq_table, policy->cpu);

	/* the first call to ->target() should result in us actually
	 * writing something to the appropriate registers. */
	data->resume = 1;	 

	return_VALUE(result);

 err_freqfree:
	kfree(data->freq_table);
 err_unreg:
	acpi_processor_unregister_performance(perf, cpu);
 err_free:
	kfree(data);
	acpi_io_data[cpu] = NULL;

	return_VALUE(result);
}


static int
acpi_cpufreq_cpu_exit (
	struct cpufreq_policy   *policy)
{
	struct cpufreq_acpi_io *data = acpi_io_data[policy->cpu];


	ACPI_FUNCTION_TRACE("acpi_cpufreq_cpu_exit");

	if (data) {
		cpufreq_frequency_table_put_attr(policy->cpu);
		acpi_io_data[policy->cpu] = NULL;
		acpi_processor_unregister_performance(data->acpi_data, policy->cpu);
		kfree(data);
	}

	return_VALUE(0);
}


static struct freq_attr* acpi_cpufreq_attr[] = {
	&cpufreq_freq_attr_scaling_available_freqs,
	NULL,
};

static struct cpufreq_driver acpi_cpufreq_driver = {
	.verify 	= acpi_cpufreq_verify,
	.target 	= acpi_cpufreq_target,
	.init		= acpi_cpufreq_cpu_init,
	.exit		= acpi_cpufreq_cpu_exit,
	.name		= "acpi-cpufreq",
	.owner		= THIS_MODULE,
	.attr           = acpi_cpufreq_attr,
};


static int __init
acpi_cpufreq_init (void)
{
	int                     result = 0;

	ACPI_FUNCTION_TRACE("acpi_cpufreq_init");

	result = acpi_cpufreq_early_init_acpi();

	if (!result)
 		result = cpufreq_register_driver(&acpi_cpufreq_driver);	

	return_VALUE(result);
}


static void __exit
acpi_cpufreq_exit (void)
{
	unsigned int	i;
	ACPI_FUNCTION_TRACE("acpi_cpufreq_exit");

	cpufreq_unregister_driver(&acpi_cpufreq_driver);

	for_each_cpu(i) {
		kfree(acpi_perf_data[i]);
		acpi_perf_data[i] = NULL;
	}
	return_VOID;
}

module_param(acpi_pstate_strict, uint, 0644);
MODULE_PARM_DESC(acpi_pstate_strict, "value 0 or non-zero. non-zero -> strict ACPI checks are performed during frequency changes.");

late_initcall(acpi_cpufreq_init);
module_exit(acpi_cpufreq_exit);

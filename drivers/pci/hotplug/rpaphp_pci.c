/*
 * PCI Hot Plug Controller Driver for RPA-compliant PPC64 platform.
 * Copyright (C) 2003 Linda Xie <lxie@us.ibm.com>
 *
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Send feedback to <lxie@us.ibm.com>
 *
 */
#include <linux/delay.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <asm/eeh.h>
#include <asm/pci-bridge.h>
#include <asm/prom.h>
#include <asm/rtas.h>
#include "../pci.h"		/* for pci_add_new_bus */

#include "rpaphp.h"

static struct device_node *pci_bus_to_OF_node(struct pci_bus *bus)
{
	if (bus->self)
		return pci_device_to_OF_node(bus->self);
	else
		return bus->sysdata; /* Must be root bus (PHB) */
}

static struct pci_bus *find_bus_among_children(struct pci_bus *bus,
					struct device_node *dn)
{
	struct pci_bus *child;
	struct list_head *tmp;
	struct device_node *busdn;

	busdn = pci_bus_to_OF_node(bus);
	if (busdn == dn)
		return bus;

	list_for_each(tmp, &bus->children) {
		child = find_bus_among_children(pci_bus_b(tmp), dn);
		if (child)
			return child;
	}
	return NULL;
}

struct pci_bus *rpaphp_find_pci_bus(struct device_node *dn)
{
	if (!dn->phb || !dn->phb->bus)
		return NULL;

	return find_bus_among_children(dn->phb->bus, dn);
}
EXPORT_SYMBOL_GPL(rpaphp_find_pci_bus);

int rpaphp_claim_resource(struct pci_dev *dev, int resource)
{
	struct resource *res = &dev->resource[resource];
	struct resource *root = pci_find_parent_resource(dev, res);
	char *dtype = resource < PCI_BRIDGE_RESOURCES ? "device" : "bridge";
	int err = -EINVAL;

	if (root != NULL) {
		err = request_resource(root, res);
	}

	if (err) {
		err("PCI: %s region %d of %s %s [%lx:%lx]\n",
		    root ? "Address space collision on" :
		    "No parent found for",
		    resource, dtype, pci_name(dev), res->start, res->end);
		dump_stack();
	}
	return err;
}

EXPORT_SYMBOL_GPL(rpaphp_claim_resource);

static int rpaphp_get_sensor_state(struct slot *slot, int *state)
{
	int rc;
	int setlevel;

	rc = rtas_get_sensor(DR_ENTITY_SENSE, slot->index, state);

	if (rc) {
		if (rc == NEED_POWER || rc == PWR_ONLY) {
			dbg("%s: slot must be power up to get sensor-state\n",
			    __FUNCTION__);

			/* some slots have to be powered up 
			 * before get-sensor will succeed.
			 */
			rc = rtas_set_power_level(slot->power_domain, POWER_ON,
						  &setlevel);
			if (rc) {
				dbg("%s: power on slot[%s] failed rc=%d.\n",
				    __FUNCTION__, slot->name, rc);
			} else {
				rc = rtas_get_sensor(DR_ENTITY_SENSE,
						     slot->index, state);
			}
		} else if (rc == ERR_SENSE_USE)
			info("%s: slot is unusable\n", __FUNCTION__);
		else
			err("%s failed to get sensor state\n", __FUNCTION__);
	}
	return rc;
}

/**
 * get_pci_adapter_status - get the status of a slot
 * 
 * 0-- slot is empty
 * 1-- adapter is configured
 * 2-- adapter is not configured
 * 3-- not valid
 */
int rpaphp_get_pci_adapter_status(struct slot *slot, int is_init, u8 * value)
{
	struct pci_bus *bus;
	int state, rc;

	*value = NOT_VALID;
	rc = rpaphp_get_sensor_state(slot, &state);
	if (rc)
		goto exit;

 	if (state == EMPTY)
 		*value = EMPTY;
 	else if (state == PRESENT) {
		if (!is_init) {
			/* at run-time slot->state can be changed by */
			/* config/unconfig adapter */
			*value = slot->state;
		} else {
			bus = rpaphp_find_pci_bus(slot->dn);
			if (bus && !list_empty(&bus->devices))
				*value = CONFIGURED;
			else
				*value = NOT_CONFIGURED;
		}
	}
exit:
	return rc;
}

/* Must be called before pci_bus_add_devices */
static void 
rpaphp_fixup_new_pci_devices(struct pci_bus *bus, int fix_bus)
{
	struct pci_dev *dev;

	list_for_each_entry(dev, &bus->devices, bus_list) {
		/*
		 * Skip already-present devices (which are on the
		 * global device list.)
		 */
		if (list_empty(&dev->global_list)) {
			int i;
			
			if(fix_bus)
				pcibios_fixup_device_resources(dev, bus);
			pci_read_irq_line(dev);
			for (i = 0; i < PCI_NUM_RESOURCES; i++) {
				struct resource *r = &dev->resource[i];

				if (r->parent || !r->start || !r->flags)
					continue;
				rpaphp_claim_resource(dev, i);
			}
		}
	}
}

static void rpaphp_eeh_add_bus_device(struct pci_bus *bus)
{
	struct pci_dev *dev;
	list_for_each_entry(dev, &bus->devices, bus_list) {
		eeh_add_device_late(dev);
		if (dev->hdr_type == PCI_HEADER_TYPE_BRIDGE) {
			struct pci_bus *subbus = dev->subordinate;
			if (subbus)
				rpaphp_eeh_add_bus_device (subbus);
		}
	}
}

static int rpaphp_pci_config_bridge(struct pci_dev *dev)
{
	u8 sec_busno;
	struct pci_bus *child_bus;

	dbg("Enter %s:  BRIDGE dev=%s\n", __FUNCTION__, pci_name(dev));

	/* get busno of downstream bus */
	pci_read_config_byte(dev, PCI_SECONDARY_BUS, &sec_busno);

	/* add to children of PCI bridge dev->bus */
	child_bus = pci_add_new_bus(dev->bus, dev, sec_busno);
	if (!child_bus) {
		err("%s: could not add second bus\n", __FUNCTION__);
		return -EIO;
	}
	sprintf(child_bus->name, "PCI Bus #%02x", child_bus->number);
	/* do pci_scan_child_bus */
	pci_scan_child_bus(child_bus);

	 /* fixup new pci devices without touching bus struct */
	rpaphp_fixup_new_pci_devices(child_bus, 0);

	/* Make the discovered devices available */
	pci_bus_add_devices(child_bus);
	return 0;
}

/*****************************************************************************
 rpaphp_pci_config_slot() will  configure all devices under the
 given slot->dn and return the the first pci_dev.
 *****************************************************************************/
static struct pci_dev *
rpaphp_pci_config_slot(struct pci_bus *bus)
{
	struct device_node *dn = pci_bus_to_OF_node(bus);
	struct pci_dev *dev = NULL;
	int slotno;
	int num;

	dbg("Enter %s: dn=%s bus=%s\n", __FUNCTION__, dn->full_name, bus->name);
	if (!dn || !dn->child)
		return NULL;

	slotno = PCI_SLOT(dn->child->devfn);

	/* pci_scan_slot should find all children */
	num = pci_scan_slot(bus, PCI_DEVFN(slotno, 0));
	if (num) {
		rpaphp_fixup_new_pci_devices(bus, 1);
		pci_bus_add_devices(bus);
	}
	if (list_empty(&bus->devices)) {
		err("%s: No new device found\n", __FUNCTION__);
		return NULL;
	}
	list_for_each_entry(dev, &bus->devices, bus_list) {
		if (dev->hdr_type == PCI_HEADER_TYPE_BRIDGE)
			rpaphp_pci_config_bridge(dev);
	}
	rpaphp_eeh_add_bus_device(bus);

	return dev;
}

static void print_slot_pci_funcs(struct pci_bus *bus)
{
	struct device_node *dn;
	struct pci_dev *dev;

	dn = pci_bus_to_OF_node(bus);
	if (!dn)
		return;

	dbg("%s: pci_devs of slot[%s]\n", __FUNCTION__, dn->full_name);
	list_for_each_entry (dev, &bus->devices, bus_list)
		dbg("\t%s\n", pci_name(dev));
	return;
}

int rpaphp_config_pci_adapter(struct pci_bus *bus)
{
	struct device_node *dn = pci_bus_to_OF_node(bus);
	struct pci_dev *dev;
	int rc = -ENODEV;

	dbg("Entry %s: slot[%s]\n", __FUNCTION__, dn->full_name);
	if (!dn)
		goto exit;

	eeh_add_tree_early(dn);
	dev = rpaphp_pci_config_slot(bus);
	if (!dev) {
		err("%s: can't find any devices.\n", __FUNCTION__);
		goto exit;
	}
	print_slot_pci_funcs(bus);
	rc = 0;
exit:
	dbg("Exit %s:  rc=%d\n", __FUNCTION__, rc);
	return rc;
}
EXPORT_SYMBOL_GPL(rpaphp_config_pci_adapter);

static void rpaphp_eeh_remove_bus_device(struct pci_dev *dev)
{
	eeh_remove_device(dev);
	if (dev->hdr_type == PCI_HEADER_TYPE_BRIDGE) {
		struct pci_bus *bus = dev->subordinate;
		struct list_head *ln;
		if (!bus)
			return; 
		for (ln = bus->devices.next; ln != &bus->devices; ln = ln->next) {
			struct pci_dev *pdev = pci_dev_b(ln);
			if (pdev)
				rpaphp_eeh_remove_bus_device(pdev);
		}
	}
	return;
}

int rpaphp_unconfig_pci_adapter(struct pci_bus *bus)
{
	struct pci_dev *dev, *tmp;
	
	list_for_each_entry_safe(dev, tmp, &bus->devices, bus_list) {
		rpaphp_eeh_remove_bus_device(dev);
		pci_remove_bus_device(dev);
	}
	return 0;
}

static int setup_pci_hotplug_slot_info(struct slot *slot)
{
	dbg("%s Initilize the PCI slot's hotplug->info structure ...\n",
	    __FUNCTION__);
	rpaphp_get_power_status(slot, &slot->hotplug_slot->info->power_status);
	rpaphp_get_pci_adapter_status(slot, 1,
				      &slot->hotplug_slot->info->
				      adapter_status);
	if (slot->hotplug_slot->info->adapter_status == NOT_VALID) {
		err("%s: NOT_VALID: skip dn->full_name=%s\n",
		    __FUNCTION__, slot->dn->full_name);
		return -1;
	}
	return 0;
}

static void set_slot_name(struct slot *slot)
{
	struct pci_bus *bus = slot->bus;
	struct pci_dev *bridge;

	bridge = bus->self;
	if (bridge)
		strcpy(slot->name, pci_name(bridge));
	else
		sprintf(slot->name, "%04x:%02x:%02x.%x", pci_domain_nr(bus),
			bus->number, 0, 0);
}

static int setup_pci_slot(struct slot *slot)
{
	struct device_node *dn = slot->dn;
	struct pci_bus *bus;

	BUG_ON(!dn);
	bus = rpaphp_find_pci_bus(dn);
	if (!bus) {
		err("%s: no pci_bus for dn %s\n", __FUNCTION__, dn->full_name);
		goto exit_rc;
	}

	slot->bus = bus;
	slot->pci_devs = &bus->devices;
	set_slot_name(slot);

	if (slot->hotplug_slot->info->adapter_status == EMPTY) {
		slot->state = EMPTY;	/* slot is empty */
	} else {
		/* slot is occupied */
		if (!dn->child) {
			/* non-empty slot has to have child */
			err("%s: slot[%s]'s device_node doesn't have child for adapter\n", 
				__FUNCTION__, slot->name);
			goto exit_rc;
		}

		if (slot->hotplug_slot->info->adapter_status == NOT_CONFIGURED) {
			dbg("%s CONFIGURING pci adapter in slot[%s]\n",  
				__FUNCTION__, slot->name);
			if (rpaphp_config_pci_adapter(slot->bus)) {
				err("%s: CONFIG pci adapter failed\n", __FUNCTION__);
				goto exit_rc;		
			}
		} else if (slot->hotplug_slot->info->adapter_status != CONFIGURED) {
			err("%s: slot[%s]'s adapter_status is NOT_VALID.\n",
				__FUNCTION__, slot->name);
			goto exit_rc;
		}

		print_slot_pci_funcs(slot->bus);
		if (!list_empty(slot->pci_devs)) {
			slot->state = CONFIGURED;
		} else {
			/* DLPAR add as opposed to 
		 	 * boot time */
			slot->state = NOT_CONFIGURED;
		}
	}
	return 0;
exit_rc:
	dealloc_slot_struct(slot);
	return 1;
}

int register_pci_slot(struct slot *slot)
{
	int rc = 1;

	if (setup_pci_hotplug_slot_info(slot))
		goto exit_rc;
	if (setup_pci_slot(slot))
		goto exit_rc;
	rc = register_slot(slot);
exit_rc:
	return rc;
}

int rpaphp_enable_pci_slot(struct slot *slot)
{
	int retval = 0, state;

	retval = rpaphp_get_sensor_state(slot, &state);
	if (retval)
		goto exit;
	dbg("%s: sensor state[%d]\n", __FUNCTION__, state);
	/* if slot is not empty, enable the adapter */
	if (state == PRESENT) {
		dbg("%s : slot[%s] is occupied.\n", __FUNCTION__, slot->name);
		retval = rpaphp_config_pci_adapter(slot->bus);
		if (!retval) {
			slot->state = CONFIGURED;
			dbg("%s: PCI devices in slot[%s] has been configured\n", 
				__FUNCTION__, slot->name);
		} else {
			slot->state = NOT_CONFIGURED;
			dbg("%s: no pci_dev struct for adapter in slot[%s]\n",
			    __FUNCTION__, slot->name);
		}
	} else if (state == EMPTY) {
		dbg("%s : slot[%s] is empty\n", __FUNCTION__, slot->name);
		slot->state = EMPTY;
	} else {
		err("%s: slot[%s] is in invalid state\n", __FUNCTION__,
		    slot->name);
		slot->state = NOT_VALID;
		retval = -EINVAL;
	}
exit:
	dbg("%s - Exit: rc[%d]\n", __FUNCTION__, retval);
	return retval;
}

/* ------------------------------------------------------- */
/**
 * handle_eeh_events -- reset a PCI device after hard lockup.
 *
 * pSeries systems will isolate a PCI slot if the PCI-Host
 * bridge detects address or data parity errors, DMA's 
 * occuring to wild addresses (which usually happen due to
 * bugs in device drivers or in PCI adapter firmware).
 * Slot isolations also occur if #SERR, #PERR or other misc
 * PCI-related errors are detected.
 * 
 * Recovery process consists of unplugging the device driver
 * (which generated hotplug events to userspace), then issuing
 * a PCI #RST to the device, then reconfiguring the PCI config 
 * space for all bridges & devices under this slot, and then 
 * finally restarting the device drivers (which cause a second
 * set of hotplug events to go out to userspace).
 */
int handle_eeh_events (struct notifier_block *self, 
                       unsigned long reason, void *ev)
{
	int freeze_count=0;
	struct eeh_event *event = ev;
	struct pci_bus *bus;
	struct device_node *bus_dn;
	struct eeh_cfg_tree * saved_bars;

	if (!event->dev) {
		printk (KERN_ERR 
			"EEH: Cannot find PCI device for EEH error!\n");
		return 1;
	}
	bus = event->dev->bus;
	if (!bus) {
		printk (KERN_ERR 
			"EEH: Cannot find PCI bus for EEH error! dev=%s\n",
			pci_name(event->dev));
		return 1;
	}

	/* Keep a copy of the config space registers */
	bus_dn = pci_bus_to_OF_node(bus);
	saved_bars = eeh_save_bars(bus_dn->child);
	printk(KERN_INFO "EEH: dev=%s bus_dn=%s child=%p saved=%p\n",
		pci_name(event->dev),
		bus_dn->full_name, bus_dn->child, saved_bars);
	if(bus_dn->child)
		printk(KERN_INFO "EEH: child-name=%s\n", bus_dn->child->full_name);
	if (saved_bars == NULL)
		saved_bars = eeh_save_bars(bus_dn);

	of_node_get(event->dn);
	pci_dev_get(event->dev);

	if (bus_dn->child)
		freeze_count = bus_dn->child->eeh_freeze_count;
	rpaphp_unconfig_pci_adapter(bus);

	freeze_count ++;
	if (freeze_count > EEH_MAX_ALLOWED_FREEZES) {
		/* 
		 * About 90% of all real-life EEH failures in the field
		 * are due to poorly seated PCI cards. Only 10% or so are
		 * due to actual, failed cards 
		 */
		printk (KERN_ERR
		   "EEH: device %s:%s has failed %d times \n"
			"and has been permanently disabled.  Please try reseating\n"
		   "this device or replacing it.\n",
			pci_name (event->dev),
			pci_pretty_name (event->dev),
			freeze_count);
		goto rdone;
	}
	printk (KERN_WARNING
		"EEH: This device has failed %d times since last reboot: %s:%s\n",
		freeze_count,
		pci_name (event->dev),
		pci_pretty_name (event->dev));

	/* Reset the pci controller. (Asserts RST#; resets config space). 
	 * Reconfigure bridges and devices */
	rtas_set_slot_reset (event->dn);
	rtas_configure_bridge(event->dn);
	if (saved_bars)
		eeh_restore_bars(saved_bars);

	/* Give the system 5 seconds to finish running the user-space
	 * hotplug scripts, e.g. ifdown for ethernet.  Yes, this is a hack, 
	 * but if we don't do this, weird things happen.
	 */
	ssleep (5);

	rpaphp_config_pci_adapter(bus);

	/* Store the freeze count with the pci adapter, and not the slot.
	 * This way, if the device is replaced, the count is cleared.
	 */
	if (bus_dn->child)
		bus_dn->child->eeh_freeze_count = freeze_count;

rdone:
	of_node_put(event->dn);
	pci_dev_put(event->dev);
	return 0;
}

static struct notifier_block eeh_block;

void __init init_eeh_handler (void)
{
	eeh_block.notifier_call = handle_eeh_events;
	eeh_register_notifier (&eeh_block);
}

void __exit exit_eeh_handler (void)
{
	eeh_unregister_notifier (&eeh_block);
}

/*
 * ACPI PCI HotPlug glue functions to ACPI CA subsystem
 *
 * Copyright (C) 2002,2003 Takayoshi Kochi (t-kochi@bq.jp.nec.com)
 * Copyright (C) 2002 Hiroshi Aono (h-aono@ap.jp.nec.com)
 * Copyright (C) 2002,2003 NEC Corporation
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
 * Send feedback to <t-kochi@bq.jp.nec.com>
 *
 */

#include <linux/init.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/smp_lock.h>
#include <asm/semaphore.h>

#include "../pci.h"
#include "pci_hotplug.h"
#include "acpiphp.h"

static LIST_HEAD(bridge_list);

#define MY_NAME "acpiphp_glue"

static void handle_hotplug_event_bridge (acpi_handle, u32, void *);
static void handle_hotplug_event_func (acpi_handle, u32, void *);

/*
 * initialization & terminatation routines
 */

/**
 * is_ejectable - determine if a slot is ejectable
 * @handle: handle to acpi namespace
 *
 * Ejectable slot should satisfy at least these conditions:
 *
 *  1. has _ADR method
 *  2. has _EJ0 method
 *
 * optionally
 *
 *  1. has _STA method
 *  2. has _PS0 method
 *  3. has _PS3 method
 *  4. ..
 *
 */
static int is_ejectable(acpi_handle handle)
{
	acpi_status status;
	acpi_handle tmp;

	status = acpi_get_handle(handle, "_ADR", &tmp);
	if (ACPI_FAILURE(status)) {
		return 0;
	}

	status = acpi_get_handle(handle, "_EJ0", &tmp);
	if (ACPI_FAILURE(status)) {
		return 0;
	}

	return 1;
}


/* callback routine to check the existence of ejectable slots */
static acpi_status
is_ejectable_slot(acpi_handle handle, u32 lvl, void *context, void **rv)
{
	int *count = (int *)context;

	if (is_ejectable(handle)) {
		(*count)++;
		/* only one ejectable slot is enough */
		return AE_CTRL_TERMINATE;
	} else {
		return AE_OK;
	}
}


/* callback routine to register each ACPI PCI slot object */
static acpi_status
register_slot(acpi_handle handle, u32 lvl, void *context, void **rv)
{
	struct acpiphp_bridge *bridge = (struct acpiphp_bridge *)context;
	struct acpiphp_slot *slot;
	struct acpiphp_func *newfunc;
	acpi_handle tmp;
	acpi_status status = AE_OK;
	unsigned long adr, sun;
	int device, function;
	static int num_slots = 0;	/* XXX if we support I/O node hotplug... */

	status = acpi_evaluate_integer(handle, "_ADR", NULL, &adr);

	if (ACPI_FAILURE(status))
		return AE_OK;

	status = acpi_get_handle(handle, "_EJ0", &tmp);

	if (ACPI_FAILURE(status))
		return AE_OK;

	device = (adr >> 16) & 0xffff;
	function = adr & 0xffff;

	newfunc = kmalloc(sizeof(struct acpiphp_func), GFP_KERNEL);
	if (!newfunc)
		return AE_NO_MEMORY;
	memset(newfunc, 0, sizeof(struct acpiphp_func));

	INIT_LIST_HEAD(&newfunc->sibling);
	newfunc->handle = handle;
	newfunc->function = function;
	newfunc->flags = FUNC_HAS_EJ0;

	if (ACPI_SUCCESS(acpi_get_handle(handle, "_STA", &tmp)))
		newfunc->flags |= FUNC_HAS_STA;

	if (ACPI_SUCCESS(acpi_get_handle(handle, "_PS0", &tmp)))
		newfunc->flags |= FUNC_HAS_PS0;

	if (ACPI_SUCCESS(acpi_get_handle(handle, "_PS3", &tmp)))
		newfunc->flags |= FUNC_HAS_PS3;

	status = acpi_evaluate_integer(handle, "_SUN", NULL, &sun);
	if (ACPI_FAILURE(status))
		sun = -1;

	/* search for objects that share the same slot */
	for (slot = bridge->slots; slot; slot = slot->next)
		if (slot->device == device) {
			if (slot->sun != sun)
				warn("sibling found, but _SUN doesn't match!\n");
			break;
		}

	if (!slot) {
		slot = kmalloc(sizeof(struct acpiphp_slot), GFP_KERNEL);
		if (!slot) {
			kfree(newfunc);
			return AE_NO_MEMORY;
		}

		memset(slot, 0, sizeof(struct acpiphp_slot));
		slot->bridge = bridge;
		slot->id = num_slots++;
		slot->device = device;
		slot->sun = sun;
		INIT_LIST_HEAD(&slot->funcs);
		init_MUTEX(&slot->crit_sect);

		slot->next = bridge->slots;
		bridge->slots = slot;

		bridge->nr_slots++;

		dbg("found ACPI PCI Hotplug slot at PCI %02x:%02x Slot:%d\n",
		    slot->bridge->bus, slot->device, slot->sun);
	}

	newfunc->slot = slot;
	list_add_tail(&newfunc->sibling, &slot->funcs);

	/* associate corresponding pci_dev */
	newfunc->pci_dev = pci_find_slot(bridge->bus,
					 PCI_DEVFN(device, function));
	if (newfunc->pci_dev) {
		if (acpiphp_init_func_resource(newfunc) < 0) {
			kfree(newfunc);
			return AE_ERROR;
		}
		slot->flags |= (SLOT_ENABLED | SLOT_POWEREDON);
	}

	/* install notify handler */
	status = acpi_install_notify_handler(handle,
					     ACPI_SYSTEM_NOTIFY,
					     handle_hotplug_event_func,
					     newfunc);

	if (ACPI_FAILURE(status)) {
		err("failed to register interrupt notify handler\n");
		return status;
	}

	return AE_OK;
}


/* see if it's worth looking at this bridge */
static int detect_ejectable_slots(acpi_handle *bridge_handle)
{
	acpi_status status;
	int count;

	count = 0;

	/* only check slots defined directly below bridge object */
	status = acpi_walk_namespace(ACPI_TYPE_DEVICE, bridge_handle, (u32)1,
				     is_ejectable_slot, (void *)&count, NULL);

	return count;
}


/* decode ACPI _CRS data and convert into our internal resource list
 * TBD: _TRA, etc.
 */
static acpi_status
decode_acpi_resource(struct acpi_resource *resource, void *context)
{
	struct acpiphp_bridge *bridge = (struct acpiphp_bridge *) context;
	struct acpi_resource_address64 address;
	struct pci_resource *res;

	if (resource->id != ACPI_RSTYPE_ADDRESS16 &&
	    resource->id != ACPI_RSTYPE_ADDRESS32 &&
	    resource->id != ACPI_RSTYPE_ADDRESS64)
		return AE_OK;

	acpi_resource_to_address64(resource, &address);

	if (address.producer_consumer == ACPI_PRODUCER && address.address_length > 0) {
		dbg("resource type: %d: 0x%llx - 0x%llx\n", address.resource_type,
		    (unsigned long long)address.min_address_range,
		    (unsigned long long)address.max_address_range);
		res = acpiphp_make_resource(address.min_address_range,
				    address.address_length);
		if (!res) {
			err("out of memory\n");
			return AE_OK;
		}

		switch (address.resource_type) {
		case ACPI_MEMORY_RANGE:
			if (address.attribute.memory.cache_attribute == ACPI_PREFETCHABLE_MEMORY) {
				res->next = bridge->p_mem_head;
				bridge->p_mem_head = res;
			} else {
				res->next = bridge->mem_head;
				bridge->mem_head = res;
			}
			break;
		case ACPI_IO_RANGE:
			res->next = bridge->io_head;
			bridge->io_head = res;
			break;
		case ACPI_BUS_NUMBER_RANGE:
			res->next = bridge->bus_head;
			bridge->bus_head = res;
			break;
		default:
			/* invalid type */
			kfree(res);
			break;
		}
	}

	return AE_OK;
}

/* decode ACPI 2.0 _HPP hot plug parameters */
static void decode_hpp(struct acpiphp_bridge *bridge)
{
	acpi_status status;
	struct acpi_buffer buffer = { .length = ACPI_ALLOCATE_BUFFER,
				      .pointer = NULL};
	union acpi_object *package;
	int i;

	/* default numbers */
	bridge->hpp.cache_line_size = 0x10;
	bridge->hpp.latency_timer = 0x40;
	bridge->hpp.enable_SERR = 0;
	bridge->hpp.enable_PERR = 0;

	status = acpi_evaluate_object(bridge->handle, "_HPP", NULL, &buffer);

	if (ACPI_FAILURE(status)) {
		dbg("_HPP evaluation failed\n");
		return;
	}

	package = (union acpi_object *) buffer.pointer;

	if (!package || package->type != ACPI_TYPE_PACKAGE ||
	    package->package.count != 4 || !package->package.elements) {
		err("invalid _HPP object; ignoring\n");
		goto err_exit;
	}

	for (i = 0; i < 4; i++) {
		if (package->package.elements[i].type != ACPI_TYPE_INTEGER) {
			err("invalid _HPP parameter type; ignoring\n");
			goto err_exit;
		}
	}

	bridge->hpp.cache_line_size = package->package.elements[0].integer.value;
	bridge->hpp.latency_timer = package->package.elements[1].integer.value;
	bridge->hpp.enable_SERR = package->package.elements[2].integer.value;
	bridge->hpp.enable_PERR = package->package.elements[3].integer.value;

	dbg("_HPP parameter = (%02x, %02x, %02x, %02x)\n",
		bridge->hpp.cache_line_size,
		bridge->hpp.latency_timer,
		bridge->hpp.enable_SERR,
		bridge->hpp.enable_PERR);

	bridge->flags |= BRIDGE_HAS_HPP;

 err_exit:
	kfree(buffer.pointer);
}


/* initialize miscellaneous stuff for both root and PCI-to-PCI bridge */
static void init_bridge_misc(struct acpiphp_bridge *bridge)
{
	acpi_status status;

	/* decode ACPI 2.0 _HPP (hot plug parameters) */
	decode_hpp(bridge);

	/* subtract all resources already allocated */
	acpiphp_detect_pci_resource(bridge);

	/* register all slot objects under this bridge */
	status = acpi_walk_namespace(ACPI_TYPE_DEVICE, bridge->handle, (u32)1,
				     register_slot, bridge, NULL);

	/* install notify handler */
	if (bridge->type != BRIDGE_TYPE_HOST) {
		status = acpi_install_notify_handler(bridge->handle,
					ACPI_SYSTEM_NOTIFY,
					handle_hotplug_event_bridge,
					bridge);

		if (ACPI_FAILURE(status)) {
			err("failed to register interrupt notify handler\n");
		}
	}

	list_add(&bridge->list, &bridge_list);

	dbg("Bridge resource:\n");
	acpiphp_dump_resource(bridge);
}


/* allocate and initialize host bridge data structure */
static void add_host_bridge(acpi_handle *handle, int seg, int bus)
{
	acpi_status status;
	struct acpiphp_bridge *bridge;

	bridge = kmalloc(sizeof(struct acpiphp_bridge), GFP_KERNEL);
	if (bridge == NULL)
		return;

	memset(bridge, 0, sizeof(struct acpiphp_bridge));

	bridge->type = BRIDGE_TYPE_HOST;
	bridge->handle = handle;
	bridge->seg = seg;
	bridge->bus = bus;

	bridge->pci_bus = pci_find_bus(seg, bus);

	bridge->res_lock = SPIN_LOCK_UNLOCKED;

	/* to be overridden when we decode _CRS	*/
	bridge->sub = bridge->bus;

	/* decode resources */

	status = acpi_walk_resources(handle, METHOD_NAME__CRS,
		decode_acpi_resource, bridge);

	if (ACPI_FAILURE(status)) {
		err("failed to decode bridge resources\n");
		kfree(bridge);
		return;
	}

	acpiphp_resource_sort_and_combine(&bridge->io_head);
	acpiphp_resource_sort_and_combine(&bridge->mem_head);
	acpiphp_resource_sort_and_combine(&bridge->p_mem_head);
	acpiphp_resource_sort_and_combine(&bridge->bus_head);

	dbg("ACPI _CRS resource:\n");
	acpiphp_dump_resource(bridge);

	if (bridge->bus_head) {
		bridge->bus = bridge->bus_head->base;
		bridge->sub = bridge->bus_head->base + bridge->bus_head->length - 1;
	}

	init_bridge_misc(bridge);
}


/* allocate and initialize PCI-to-PCI bridge data structure */
static void add_p2p_bridge(acpi_handle *handle, int seg, int bus, int dev, int fn)
{
	struct acpiphp_bridge *bridge;
	u8 tmp8;
	u16 tmp16;
	u64 base64, limit64;
	u32 base, limit, base32u, limit32u;

	bridge = kmalloc(sizeof(struct acpiphp_bridge), GFP_KERNEL);
	if (bridge == NULL) {
		err("out of memory\n");
		return;
	}

	memset(bridge, 0, sizeof(struct acpiphp_bridge));

	bridge->type = BRIDGE_TYPE_P2P;
	bridge->handle = handle;
	bridge->seg = seg;

	bridge->pci_dev = pci_find_slot(bus, PCI_DEVFN(dev, fn));
	if (!bridge->pci_dev) {
		err("Can't get pci_dev\n");
		kfree(bridge);
		return;
	}

	bridge->pci_bus = bridge->pci_dev->subordinate;
	if (!bridge->pci_bus) {
		err("This is not a PCI-to-PCI bridge!\n");
		kfree(bridge);
		return;
	}

	bridge->res_lock = SPIN_LOCK_UNLOCKED;

	bridge->bus = bridge->pci_bus->number;
	bridge->sub = bridge->pci_bus->subordinate;

	/*
	 * decode resources under this P2P bridge
	 */

	/* I/O resources */
	pci_read_config_byte(bridge->pci_dev, PCI_IO_BASE, &tmp8);
	base = tmp8;
	pci_read_config_byte(bridge->pci_dev, PCI_IO_LIMIT, &tmp8);
	limit = tmp8;

	switch (base & PCI_IO_RANGE_TYPE_MASK) {
	case PCI_IO_RANGE_TYPE_16:
		base = (base << 8) & 0xf000;
		limit = ((limit << 8) & 0xf000) + 0xfff;
		bridge->io_head = acpiphp_make_resource((u64)base, limit - base + 1);
		if (!bridge->io_head) {
			err("out of memory\n");
			kfree(bridge);
			return;
		}
		dbg("16bit I/O range: %04x-%04x\n",
		    (u32)bridge->io_head->base,
		    (u32)(bridge->io_head->base + bridge->io_head->length - 1));
		break;
	case PCI_IO_RANGE_TYPE_32:
		pci_read_config_word(bridge->pci_dev, PCI_IO_BASE_UPPER16, &tmp16);
		base = ((u32)tmp16 << 16) | ((base << 8) & 0xf000);
		pci_read_config_word(bridge->pci_dev, PCI_IO_LIMIT_UPPER16, &tmp16);
		limit = (((u32)tmp16 << 16) | ((limit << 8) & 0xf000)) + 0xfff;
		bridge->io_head = acpiphp_make_resource((u64)base, limit - base + 1);
		if (!bridge->io_head) {
			err("out of memory\n");
			kfree(bridge);
			return;
		}
		dbg("32bit I/O range: %08x-%08x\n",
		    (u32)bridge->io_head->base,
		    (u32)(bridge->io_head->base + bridge->io_head->length - 1));
		break;
	case 0x0f:
		dbg("I/O space unsupported\n");
		break;
	default:
		warn("Unknown I/O range type\n");
	}

	/* Memory resources (mandatory for P2P bridge) */
	pci_read_config_word(bridge->pci_dev, PCI_MEMORY_BASE, &tmp16);
	base = (tmp16 & 0xfff0) << 16;
	pci_read_config_word(bridge->pci_dev, PCI_MEMORY_LIMIT, &tmp16);
	limit = ((tmp16 & 0xfff0) << 16) | 0xfffff;
	bridge->mem_head = acpiphp_make_resource((u64)base, limit - base + 1);
	if (!bridge->mem_head) {
		err("out of memory\n");
		kfree(bridge);
		return;
	}
	dbg("32bit Memory range: %08x-%08x\n",
	    (u32)bridge->mem_head->base,
	    (u32)(bridge->mem_head->base + bridge->mem_head->length-1));

	/* Prefetchable Memory resources (optional) */
	pci_read_config_word(bridge->pci_dev, PCI_PREF_MEMORY_BASE, &tmp16);
	base = tmp16;
	pci_read_config_word(bridge->pci_dev, PCI_PREF_MEMORY_LIMIT, &tmp16);
	limit = tmp16;

	switch (base & PCI_MEMORY_RANGE_TYPE_MASK) {
	case PCI_PREF_RANGE_TYPE_32:
		base = (base & 0xfff0) << 16;
		limit = ((limit & 0xfff0) << 16) | 0xfffff;
		bridge->p_mem_head = acpiphp_make_resource((u64)base, limit - base + 1);
		if (!bridge->p_mem_head) {
			err("out of memory\n");
			kfree(bridge);
			return;
		}
		dbg("32bit Prefetchable memory range: %08x-%08x\n",
		    (u32)bridge->p_mem_head->base,
		    (u32)(bridge->p_mem_head->base + bridge->p_mem_head->length - 1));
		break;
	case PCI_PREF_RANGE_TYPE_64:
		pci_read_config_dword(bridge->pci_dev, PCI_PREF_BASE_UPPER32, &base32u);
		pci_read_config_dword(bridge->pci_dev, PCI_PREF_LIMIT_UPPER32, &limit32u);
		base64 = ((u64)base32u << 32) | ((base & 0xfff0) << 16);
		limit64 = (((u64)limit32u << 32) | ((limit & 0xfff0) << 16)) + 0xfffff;

		bridge->p_mem_head = acpiphp_make_resource(base64, limit64 - base64 + 1);
		if (!bridge->p_mem_head) {
			err("out of memory\n");
			kfree(bridge);
			return;
		}
		dbg("64bit Prefetchable memory range: %08x%08x-%08x%08x\n",
		    (u32)(bridge->p_mem_head->base >> 32),
		    (u32)(bridge->p_mem_head->base & 0xffffffff),
		    (u32)((bridge->p_mem_head->base + bridge->p_mem_head->length - 1) >> 32),
		    (u32)((bridge->p_mem_head->base + bridge->p_mem_head->length - 1) & 0xffffffff));
		break;
	case 0x0f:
		break;
	default:
		warn("Unknown prefetchale memory type\n");
	}

	init_bridge_misc(bridge);
}


/* callback routine to find P2P bridges */
static acpi_status
find_p2p_bridge(acpi_handle handle, u32 lvl, void *context, void **rv)
{
	acpi_status status;
	acpi_handle dummy_handle;
	unsigned long *segbus = context;
	unsigned long tmp;
	int seg, bus, device, function;
	struct pci_dev *dev;

	/* get PCI address */
	seg = (*segbus >> 8) & 0xff;
	bus = *segbus & 0xff;

	status = acpi_get_handle(handle, "_ADR", &dummy_handle);
	if (ACPI_FAILURE(status))
		return AE_OK;		/* continue */

	status = acpi_evaluate_integer(handle, "_ADR", NULL, &tmp);
	if (ACPI_FAILURE(status)) {
		dbg("%s: _ADR evaluation failure\n", __FUNCTION__);
		return AE_OK;
	}

	device = (tmp >> 16) & 0xffff;
	function = tmp & 0xffff;

	dev = pci_find_slot(bus, PCI_DEVFN(device, function));

	if (!dev)
		return AE_OK;

	if (!dev->subordinate)
		return AE_OK;

	/* check if this bridge has ejectable slots */
	if (detect_ejectable_slots(handle) > 0) {
		dbg("found PCI-to-PCI bridge at PCI %s\n", pci_name(dev));
		add_p2p_bridge(handle, seg, bus, device, function);
	}

	tmp = seg << 8 | dev->subordinate->number;
 	/* search P2P bridges under this p2p bridge */
 	status = acpi_walk_namespace(ACPI_TYPE_DEVICE, handle, (u32)1,
 				     find_p2p_bridge, &tmp, NULL);
 	if (ACPI_FAILURE(status))
 		warn("find_p2p_bridge failed (error code = 0x%x)\n", status);

	return AE_OK;
}


/* find hot-pluggable slots, and then find P2P bridge */
static int add_bridge(acpi_handle handle)
{
	acpi_status status;
	unsigned long tmp;
	int seg, bus;
	acpi_handle dummy_handle;

	/* if the bridge doesn't have _STA, we assume it is always there */
	status = acpi_get_handle(handle, "_STA", &dummy_handle);
	if (ACPI_SUCCESS(status)) {
		status = acpi_evaluate_integer(handle, "_STA", NULL, &tmp);
		if (ACPI_FAILURE(status)) {
			dbg("%s: _STA evaluation failure\n", __FUNCTION__);
			return 0;
		}
		if ((tmp & ACPI_STA_FUNCTIONING) == 0)
			/* don't register this object */
			return 0;
	}

	/* get PCI segment number */
	status = acpi_evaluate_integer(handle, "_SEG", NULL, &tmp);

	seg = ACPI_SUCCESS(status) ? tmp : 0;

	/* get PCI bus number */
	status = acpi_evaluate_integer(handle, "_BBN", NULL, &tmp);

	if (ACPI_SUCCESS(status)) {
		bus = tmp;
	} else {
		warn("can't get bus number, assuming 0\n");
		bus = 0;
	}

	/* check if this bridge has ejectable slots */
	if (detect_ejectable_slots(handle) > 0) {
		dbg("found PCI host-bus bridge with hot-pluggable slots\n");
		add_host_bridge(handle, seg, bus);
		return 0;
	}

	tmp = seg << 8 | bus;

	/* search P2P bridges under this host bridge */
	status = acpi_walk_namespace(ACPI_TYPE_DEVICE, handle, (u32)1,
				     find_p2p_bridge, &tmp, NULL);

	if (ACPI_FAILURE(status))
		warn("find_p2p_bridge faied (error code = 0x%x)\n",status);

	return 0;
}

static struct acpiphp_bridge *acpiphp_handle_to_bridge(acpi_handle handle)
{
	struct list_head *head;
	list_for_each(head, &bridge_list) {
		struct acpiphp_bridge *bridge = list_entry(head,
						struct acpiphp_bridge, list);
		if (bridge->handle == handle)
			return bridge;
	}

	return NULL;
}

static void remove_bridge(acpi_handle handle)
{
	/* No-op for now .. */
}


static int power_on_slot(struct acpiphp_slot *slot)
{
	acpi_status status;
	struct acpiphp_func *func;
	struct list_head *l;
	int retval = 0;

	/* if already enabled, just skip */
	if (slot->flags & SLOT_POWEREDON)
		goto err_exit;

	list_for_each (l, &slot->funcs) {
		func = list_entry(l, struct acpiphp_func, sibling);

		if (func->flags & FUNC_HAS_PS0) {
			dbg("%s: executing _PS0\n", __FUNCTION__);
			status = acpi_evaluate_object(func->handle, "_PS0", NULL, NULL);
			if (ACPI_FAILURE(status)) {
				warn("%s: _PS0 failed\n", __FUNCTION__);
				retval = -1;
				goto err_exit;
			} else
				break;
		}
	}

	/* TBD: evaluate _STA to check if the slot is enabled */

	slot->flags |= SLOT_POWEREDON;

 err_exit:
	return retval;
}


static int power_off_slot(struct acpiphp_slot *slot)
{
	acpi_status status;
	struct acpiphp_func *func;
	struct list_head *l;

	int retval = 0;

	/* if already disabled, just skip */
	if ((slot->flags & SLOT_POWEREDON) == 0)
		goto err_exit;

	list_for_each (l, &slot->funcs) {
		func = list_entry(l, struct acpiphp_func, sibling);

		if (func->pci_dev && (func->flags & FUNC_HAS_PS3)) {
			status = acpi_evaluate_object(func->handle, "_PS3", NULL, NULL);
			if (ACPI_FAILURE(status)) {
				warn("%s: _PS3 failed\n", __FUNCTION__);
				retval = -1;
				goto err_exit;
			} else
				break;
		}
	}

	/* TBD: evaluate _STA to check if the slot is disabled */

	slot->flags &= (~SLOT_POWEREDON);

 err_exit:
	return retval;
}

static void program_hpp(struct pci_dev *dev, struct acpiphp_bridge *bridge)
{
	u16 pci_cmd, pci_bctl;
	struct pci_dev *cdev;

	/* Program hpp values for this device */
	if (!(dev->hdr_type == PCI_HEADER_TYPE_NORMAL ||
			(dev->hdr_type == PCI_HEADER_TYPE_BRIDGE &&
			(dev->class >> 8) == PCI_CLASS_BRIDGE_PCI)))
		return;
	if ((dev->class >> 8) == PCI_CLASS_BRIDGE_HOST)
		return;
	pci_write_config_byte(dev, PCI_CACHE_LINE_SIZE,
			bridge->hpp.cache_line_size);
	pci_write_config_byte(dev, PCI_LATENCY_TIMER,
			bridge->hpp.latency_timer);
	pci_read_config_word(dev, PCI_COMMAND, &pci_cmd);
	if (bridge->hpp.enable_SERR)
		pci_cmd |= PCI_COMMAND_SERR;
	else
		pci_cmd &= ~PCI_COMMAND_SERR;
	if (bridge->hpp.enable_PERR)
		pci_cmd |= PCI_COMMAND_PARITY;
	else
		pci_cmd &= ~PCI_COMMAND_PARITY;
	pci_write_config_word(dev, PCI_COMMAND, pci_cmd);

	/* Program bridge control value and child devices */
	if ((dev->class >> 8) == PCI_CLASS_BRIDGE_PCI) {
		pci_write_config_byte(dev, PCI_SEC_LATENCY_TIMER,
				bridge->hpp.latency_timer);
		pci_read_config_word(dev, PCI_BRIDGE_CONTROL, &pci_bctl);
		if (bridge->hpp.enable_SERR)
			pci_bctl |= PCI_BRIDGE_CTL_SERR;
		else
			pci_bctl &= ~PCI_BRIDGE_CTL_SERR;
		if (bridge->hpp.enable_PERR)
			pci_bctl |= PCI_BRIDGE_CTL_PARITY;
		else
			pci_bctl &= ~PCI_BRIDGE_CTL_PARITY;
		pci_write_config_word(dev, PCI_BRIDGE_CONTROL, pci_bctl);
		if (dev->subordinate) {
			list_for_each_entry(cdev, &dev->subordinate->devices,
					bus_list)
				program_hpp(cdev, bridge);
		}
	}
}

static void acpiphp_set_hpp_values(acpi_handle handle, struct pci_bus *bus)
{
	struct acpiphp_bridge bridge;
	struct pci_dev *dev;

	memset(&bridge, 0, sizeof(bridge));
	bridge.handle = handle;
	bridge.pci_dev = bus->self;
	decode_hpp(&bridge);
	list_for_each_entry(dev, &bus->devices, bus_list)
		program_hpp(dev, &bridge);

}

/**
 * enable_device - enable, configure a slot
 * @slot: slot to be enabled
 *
 * This function should be called per *physical slot*,
 * not per each slot object in ACPI namespace.
 *
 */
static int enable_device(struct acpiphp_slot *slot)
{
	struct pci_dev *dev;
	struct pci_bus *bus = slot->bridge->pci_bus;
	struct list_head *l;
	struct acpiphp_func *func;
	int retval = 0;
	int num, max, pass;

	if (slot->flags & SLOT_ENABLED)
		goto err_exit;

	/* sanity check: dev should be NULL when hot-plugged in */
	dev = pci_get_slot(bus, PCI_DEVFN(slot->device, 0));
	if (dev) {
		/* This case shouldn't happen */
		err("pci_dev structure already exists.\n");
		pci_dev_put(dev);
		retval = -1;
		goto err_exit;
	}

	num = pci_scan_slot(bus, PCI_DEVFN(slot->device, 0));
	if (num == 0) {
		err("No new device found\n");
		retval = -1;
		goto err_exit;
	}

	max = bus->secondary;
	for (pass = 0; pass < 2; pass++) {
		list_for_each_entry(dev, &bus->devices, bus_list) {
			if (PCI_SLOT(dev->devfn) != slot->device)
				continue;
			if (dev->hdr_type == PCI_HEADER_TYPE_BRIDGE ||
			    dev->hdr_type == PCI_HEADER_TYPE_CARDBUS) {
				max = pci_scan_bridge(bus, dev, max, pass);
				if (pass && dev->subordinate)
					pci_bus_size_bridges(dev->subordinate);
			}
		}
	}

	pci_bus_assign_resources(bus);
	pci_enable_bridges(bus);
	pci_bus_add_devices(bus);

	/* associate pci_dev to our representation */
	list_for_each (l, &slot->funcs) {
		func = list_entry(l, struct acpiphp_func, sibling);
		func->pci_dev = pci_get_slot(bus, PCI_DEVFN(slot->device,
							func->function));
		acpiphp_set_hpp_values(func->handle, slot->bridge->pci_bus);
	}

	slot->flags |= SLOT_ENABLED;

 err_exit:
	return retval;
}


/**
 * disable_device - disable a slot
 */
static int disable_device(struct acpiphp_slot *slot)
{
	int retval = 0;
	struct acpiphp_func *func;
	struct list_head *l;

	/* is this slot already disabled? */
	if (!(slot->flags & SLOT_ENABLED))
		goto err_exit;

	list_for_each (l, &slot->funcs) {
		func = list_entry(l, struct acpiphp_func, sibling);

		if (func->pci_dev)
			acpiphp_unconfigure_function(func);
	}

	slot->flags &= (~SLOT_ENABLED);

 err_exit:
	return retval;
}


/**
 * get_slot_status - get ACPI slot status
 *
 * if a slot has _STA for each function and if any one of them
 * returned non-zero status, return it
 *
 * if a slot doesn't have _STA and if any one of its functions'
 * configuration space is configured, return 0x0f as a _STA
 *
 * otherwise return 0
 */
static unsigned int get_slot_status(struct acpiphp_slot *slot)
{
	acpi_status status;
	unsigned long sta = 0;
	u32 dvid;
	struct list_head *l;
	struct acpiphp_func *func;

	list_for_each (l, &slot->funcs) {
		func = list_entry(l, struct acpiphp_func, sibling);

		if (func->flags & FUNC_HAS_STA) {
			status = acpi_evaluate_integer(func->handle, "_STA", NULL, &sta);
			if (ACPI_SUCCESS(status) && sta)
				break;
		} else {
			pci_bus_read_config_dword(slot->bridge->pci_bus,
						  PCI_DEVFN(slot->device,
							    func->function),
						  PCI_VENDOR_ID, &dvid);
			if (dvid != 0xffffffff) {
				sta = ACPI_STA_ALL;
				break;
			}
		}
	}

	return (unsigned int)sta;
}

/**
 * acpiphp_eject_slot - physically eject the slot
 */
static int acpiphp_eject_slot(struct acpiphp_slot *slot)
{
	acpi_status status;
	struct acpiphp_func *func;
	struct list_head *l;
	struct acpi_object_list arg_list;
	union acpi_object arg;

	list_for_each (l, &slot->funcs) {
		func = list_entry(l, struct acpiphp_func, sibling);

		/* We don't want to call _EJ0 on non-existing functions. */
		if ((func->flags & FUNC_HAS_EJ0)) {
			/* _EJ0 method take one argument */
			arg_list.count = 1;
			arg_list.pointer = &arg;
			arg.type = ACPI_TYPE_INTEGER;
			arg.integer.value = 1;

			status = acpi_evaluate_object(func->handle, "_EJ0", &arg_list, NULL);
			if (ACPI_FAILURE(status)) {
				warn("%s: _EJ0 failed\n", __FUNCTION__);
				return -1;
			} else
				break;
		}
	}
	return 0;
}

/**
 * acpiphp_check_bridge - re-enumerate devices
 *
 * Iterate over all slots under this bridge and make sure that if a
 * card is present they are enabled, and if not they are disabled.
 */
static int acpiphp_check_bridge(struct acpiphp_bridge *bridge)
{
	struct acpiphp_slot *slot;
	int retval = 0;
	int enabled, disabled;

	enabled = disabled = 0;

	for (slot = bridge->slots; slot; slot = slot->next) {
		unsigned int status = get_slot_status(slot);
		if (slot->flags & SLOT_ENABLED) {
			if (status == ACPI_STA_ALL)
				continue;
			retval = acpiphp_disable_slot(slot);
			if (retval) {
				err("Error occurred in disabling\n");
				goto err_exit;
			} else {
				acpiphp_eject_slot(slot);
			}
			disabled++;
		} else {
			if (status != ACPI_STA_ALL)
				continue;
			retval = acpiphp_enable_slot(slot);
			if (retval) {
				err("Error occurred in enabling\n");
				goto err_exit;
			}
			enabled++;
		}
	}

	dbg("%s: %d enabled, %d disabled\n", __FUNCTION__, enabled, disabled);

 err_exit:
	return retval;
}

/*
 * ACPI event handlers
 */

static acpi_status
count_sub_bridges(acpi_handle handle, u32 lvl, void *context, void **rv)
{
	int *count = (int *)context;
	struct acpiphp_bridge *bridge;

	bridge = acpiphp_handle_to_bridge(handle);
	if (bridge)
		(*count)++;
	return AE_OK ;
}

static acpi_status
check_sub_bridges(acpi_handle handle, u32 lvl, void *context, void **rv)
{
	struct acpiphp_bridge *bridge;
	char objname[64];
	struct acpi_buffer buffer = { .length = sizeof(objname),
				      .pointer = objname };

	bridge = acpiphp_handle_to_bridge(handle);
	if (bridge) {
		acpi_get_name(handle, ACPI_FULL_PATHNAME, &buffer);
		dbg("%s: re-enumerating slots under %s\n",
			__FUNCTION__, objname);
		acpi_get_name(handle, ACPI_FULL_PATHNAME, &buffer);
		acpiphp_check_bridge(bridge);
	}
	return AE_OK ;
}

/**
 * handle_hotplug_event_bridge - handle ACPI event on bridges
 *
 * @handle: Notify()'ed acpi_handle
 * @type: Notify code
 * @context: pointer to acpiphp_bridge structure
 *
 * handles ACPI event notification on {host,p2p} bridges
 *
 */
static void handle_hotplug_event_bridge(acpi_handle handle, u32 type, void *context)
{
	struct acpiphp_bridge *bridge;
	char objname[64];
	struct acpi_buffer buffer = { .length = sizeof(objname),
				      .pointer = objname };
	int num_sub_bridges = 0;

	bridge = acpiphp_handle_to_bridge(handle);
	if (type == ACPI_NOTIFY_BUS_CHECK) {
		acpi_walk_namespace(ACPI_TYPE_DEVICE, handle, ACPI_UINT32_MAX,
			count_sub_bridges, &num_sub_bridges, NULL);
	}

	if (!bridge && !num_sub_bridges) {
		err("cannot get bridge info\n");
		return;
	}

	acpi_get_name(handle, ACPI_FULL_PATHNAME, &buffer);

	switch (type) {
	case ACPI_NOTIFY_BUS_CHECK:
		/* bus re-enumerate */
		dbg("%s: Bus check notify on %s\n", __FUNCTION__, objname);
		if (bridge) {
			dbg("%s: re-enumerating slots under %s\n",
				__FUNCTION__, objname);
			acpiphp_check_bridge(bridge);
		}
		if (num_sub_bridges)
			acpi_walk_namespace(ACPI_TYPE_DEVICE, handle,
				ACPI_UINT32_MAX, check_sub_bridges, NULL, NULL);
		break;

	case ACPI_NOTIFY_DEVICE_CHECK:
		/* device check */
		dbg("%s: Device check notify on %s\n", __FUNCTION__, objname);
		acpiphp_check_bridge(bridge);
		break;

	case ACPI_NOTIFY_DEVICE_WAKE:
		/* wake event */
		dbg("%s: Device wake notify on %s\n", __FUNCTION__, objname);
		break;

	case ACPI_NOTIFY_EJECT_REQUEST:
		/* request device eject */
		dbg("%s: Device eject notify on %s\n", __FUNCTION__, objname);
		break;

	case ACPI_NOTIFY_FREQUENCY_MISMATCH:
		printk(KERN_ERR "Device %s cannot be configured due"
				" to a frequency mismatch\n", objname);
		break;

	case ACPI_NOTIFY_BUS_MODE_MISMATCH:
		printk(KERN_ERR "Device %s cannot be configured due"
				" to a bus mode mismatch\n", objname);
		break;

	case ACPI_NOTIFY_POWER_FAULT:
		printk(KERN_ERR "Device %s has suffered a power fault\n",
				objname);
		break;

	default:
		warn("notify_handler: unknown event type 0x%x for %s\n", type, objname);
		break;
	}
}

/**
 * handle_hotplug_event_func - handle ACPI event on functions (i.e. slots)
 *
 * @handle: Notify()'ed acpi_handle
 * @type: Notify code
 * @context: pointer to acpiphp_func structure
 *
 * handles ACPI event notification on slots
 *
 */
static void handle_hotplug_event_func(acpi_handle handle, u32 type, void *context)
{
	struct acpiphp_func *func;
	char objname[64];
	struct acpi_buffer buffer = { .length = sizeof(objname),
				      .pointer = objname };

	acpi_get_name(handle, ACPI_FULL_PATHNAME, &buffer);

	func = (struct acpiphp_func *)context;

	switch (type) {
	case ACPI_NOTIFY_BUS_CHECK:
		/* bus re-enumerate */
		dbg("%s: Bus check notify on %s\n", __FUNCTION__, objname);
		acpiphp_enable_slot(func->slot);
		break;

	case ACPI_NOTIFY_DEVICE_CHECK:
		/* device check : re-enumerate from parent bus */
		dbg("%s: Device check notify on %s\n", __FUNCTION__, objname);
		acpiphp_check_bridge(func->slot->bridge);
		break;

	case ACPI_NOTIFY_DEVICE_WAKE:
		/* wake event */
		dbg("%s: Device wake notify on %s\n", __FUNCTION__, objname);
		break;

	case ACPI_NOTIFY_EJECT_REQUEST:
		/* request device eject */
		dbg("%s: Device eject notify on %s\n", __FUNCTION__, objname);
		if (!(acpiphp_disable_slot(func->slot)))
			acpiphp_eject_slot(func->slot);
		break;

	default:
		warn("notify_handler: unknown event type 0x%x for %s\n", type, objname);
		break;
	}
}

/* acpi_root_bridge - check to see if this acpi object is a root bridge
 *
 * @handle - the acpi object in question.
 */
static int acpi_root_bridge(acpi_handle handle)
{
	acpi_status status;
	struct acpi_device_info *info;
	struct acpi_buffer buffer = {ACPI_ALLOCATE_BUFFER, NULL};
	int i;

	status = acpi_get_object_info(handle, &buffer);
	if (ACPI_SUCCESS(status)) {
		info = buffer.pointer;
		if ((info->valid & ACPI_VALID_HID) &&
			!strcmp(PCI_ROOT_HID_STRING,
					info->hardware_id.value)) {
			kfree(buffer.pointer);
			return 1;
		}
		if (info->valid & ACPI_VALID_CID) {
			for (i=0; i < info->compatibility_id.count; i++) {
				if (!strcmp(PCI_ROOT_HID_STRING,
					info->compatibility_id.id[i].value)) {
					kfree(buffer.pointer);
					return 1;
				}
			}
		}
		kfree(buffer.pointer);
	}
	return 0;
}

static acpi_status
find_root_bridges(acpi_handle handle, u32 lvl, void *context, void **rv)
{
	int *count = (int *)context;

	if (acpi_root_bridge(handle)) {
		acpi_install_notify_handler(handle, ACPI_SYSTEM_NOTIFY,
				handle_hotplug_event_bridge, NULL);
			(*count)++;
	}
	return AE_OK ;
}

static struct acpi_pci_driver acpi_pci_hp_driver = {
	.add =		add_bridge,
	.remove =	remove_bridge,
};

/**
 * acpiphp_glue_init - initializes all PCI hotplug - ACPI glue data structures
 *
 */
int __init acpiphp_glue_init(void)
{
	int num = 0;

	acpi_walk_namespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT,
			ACPI_UINT32_MAX, find_root_bridges, &num, NULL);

	if (num <= 0)
		return -1;
	else
		acpi_pci_register_driver(&acpi_pci_hp_driver);

	return 0;
}


/**
 * acpiphp_glue_exit - terminates all PCI hotplug - ACPI glue data structures
 *
 * This function frees all data allocated in acpiphp_glue_init()
 */
void __exit acpiphp_glue_exit(void)
{
	struct list_head *l1, *l2, *n1, *n2;
	struct acpiphp_bridge *bridge;
	struct acpiphp_slot *slot, *next;
	struct acpiphp_func *func;
	acpi_status status;

	list_for_each_safe (l1, n1, &bridge_list) {
		bridge = (struct acpiphp_bridge *)l1;
		slot = bridge->slots;
		while (slot) {
			next = slot->next;
			list_for_each_safe (l2, n2, &slot->funcs) {
				func = list_entry(l2, struct acpiphp_func, sibling);
				acpiphp_free_resource(&func->io_head);
				acpiphp_free_resource(&func->mem_head);
				acpiphp_free_resource(&func->p_mem_head);
				acpiphp_free_resource(&func->bus_head);
				status = acpi_remove_notify_handler(func->handle,
								    ACPI_SYSTEM_NOTIFY,
								    handle_hotplug_event_func);
				if (ACPI_FAILURE(status))
					err("failed to remove notify handler\n");
				kfree(func);
			}
			kfree(slot);
			slot = next;
		}
		status = acpi_remove_notify_handler(bridge->handle, ACPI_SYSTEM_NOTIFY,
						    handle_hotplug_event_bridge);
		if (ACPI_FAILURE(status))
			err("failed to remove notify handler\n");

		acpiphp_free_resource(&bridge->io_head);
		acpiphp_free_resource(&bridge->mem_head);
		acpiphp_free_resource(&bridge->p_mem_head);
		acpiphp_free_resource(&bridge->bus_head);

		kfree(bridge);
	}

	acpi_pci_unregister_driver(&acpi_pci_hp_driver);
}


/**
 * acpiphp_get_num_slots - count number of slots in a system
 */
int __init acpiphp_get_num_slots(void)
{
	struct list_head *node;
	struct acpiphp_bridge *bridge;
	int num_slots;

	num_slots = 0;

	list_for_each (node, &bridge_list) {
		bridge = (struct acpiphp_bridge *)node;
		dbg("Bus%d %dslot(s)\n", bridge->bus, bridge->nr_slots);
		num_slots += bridge->nr_slots;
	}

	dbg("Total %dslots\n", num_slots);
	return num_slots;
}


#if 0
/**
 * acpiphp_for_each_slot - call function for each slot
 * @fn: callback function
 * @data: context to be passed to callback function
 *
 */
static int acpiphp_for_each_slot(acpiphp_callback fn, void *data)
{
	struct list_head *node;
	struct acpiphp_bridge *bridge;
	struct acpiphp_slot *slot;
	int retval = 0;

	list_for_each (node, &bridge_list) {
		bridge = (struct acpiphp_bridge *)node;
		for (slot = bridge->slots; slot; slot = slot->next) {
			retval = fn(slot, data);
			if (!retval)
				goto err_exit;
		}
	}

 err_exit:
	return retval;
}
#endif

/* search matching slot from id  */
struct acpiphp_slot *get_slot_from_id(int id)
{
	struct list_head *node;
	struct acpiphp_bridge *bridge;
	struct acpiphp_slot *slot;

	list_for_each (node, &bridge_list) {
		bridge = (struct acpiphp_bridge *)node;
		for (slot = bridge->slots; slot; slot = slot->next)
			if (slot->id == id)
				return slot;
	}

	/* should never happen! */
	err("%s: no object for id %d\n", __FUNCTION__, id);
	WARN_ON(1);
	return NULL;
}


/**
 * acpiphp_enable_slot - power on slot
 */
int acpiphp_enable_slot(struct acpiphp_slot *slot)
{
	int retval;

	down(&slot->crit_sect);

	/* wake up all functions */
	retval = power_on_slot(slot);
	if (retval)
		goto err_exit;

	if (get_slot_status(slot) == ACPI_STA_ALL)
		/* configure all functions */
		retval = enable_device(slot);

 err_exit:
	up(&slot->crit_sect);
	return retval;
}

/**
 * acpiphp_disable_slot - power off slot
 */
int acpiphp_disable_slot(struct acpiphp_slot *slot)
{
	int retval = 0;

	down(&slot->crit_sect);

	/* unconfigure all functions */
	retval = disable_device(slot);
	if (retval)
		goto err_exit;

	/* power off all functions */
	retval = power_off_slot(slot);
	if (retval)
		goto err_exit;

	acpiphp_resource_sort_and_combine(&slot->bridge->io_head);
	acpiphp_resource_sort_and_combine(&slot->bridge->mem_head);
	acpiphp_resource_sort_and_combine(&slot->bridge->p_mem_head);
	acpiphp_resource_sort_and_combine(&slot->bridge->bus_head);
	dbg("Available resources:\n");
	acpiphp_dump_resource(slot->bridge);

 err_exit:
	up(&slot->crit_sect);
	return retval;
}


/*
 * slot enabled:  1
 * slot disabled: 0
 */
u8 acpiphp_get_power_status(struct acpiphp_slot *slot)
{
	return (slot->flags & SLOT_POWEREDON);
}


/*
 * latch closed:  1
 * latch   open:  0
 */
u8 acpiphp_get_latch_status(struct acpiphp_slot *slot)
{
	unsigned int sta;

	sta = get_slot_status(slot);

	return (sta & ACPI_STA_SHOW_IN_UI) ? 1 : 0;
}


/*
 * adapter presence : 1
 *          absence : 0
 */
u8 acpiphp_get_adapter_status(struct acpiphp_slot *slot)
{
	unsigned int sta;

	sta = get_slot_status(slot);

	return (sta == 0) ? 0 : 1;
}


/*
 * pci address (seg/bus/dev)
 */
u32 acpiphp_get_address(struct acpiphp_slot *slot)
{
	u32 address;

	address = ((slot->bridge->seg) << 16) |
		  ((slot->bridge->bus) << 8) |
		  slot->device;

	return address;
}

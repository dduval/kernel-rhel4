/*
 *  USB Wacom Graphire and Wacom Intuos tablet support
 *
 *  Copyright (c) 2000-2004 Vojtech Pavlik	<vojtech@ucw.cz>
 *  Copyright (c) 2000 Andreas Bach Aaen	<abach@stofanet.dk>
 *  Copyright (c) 2000 Clifford Wolf		<clifford@clifford.at>
 *  Copyright (c) 2000 Sam Mosel		<sam.mosel@computer.org>
 *  Copyright (c) 2000 James E. Blair		<corvus@gnu.org>
 *  Copyright (c) 2000 Daniel Egger		<egger@suse.de>
 *  Copyright (c) 2001 Frederic Lepied		<flepied@mandrakesoft.com>
 *  Copyright (c) 2004 Panagiotis Issaris	<panagiotis.issaris@mech.kuleuven.ac.be>
 *  Copyright (c) 2002-2004 Ping Cheng		<pingc@wacom.com>
 *
 *  ChangeLog:
 *      v0.1 (vp)  - Initial release
 *      v0.2 (aba) - Support for all buttons / combinations
 *      v0.3 (vp)  - Support for Intuos added
 *	v0.4 (sm)  - Support for more Intuos models, menustrip
 *			relative mode, proximity.
 *	v0.5 (vp)  - Big cleanup, nifty features removed,
 * 			they belong in userspace
 *	v1.8 (vp)  - Submit URB only when operating, moved to CVS,
 *			use input_report_key instead of report_btn and
 *			other cleanups
 *	v1.11 (vp) - Add URB ->dev setting for new kernels
 *	v1.11 (jb) - Add support for the 4D Mouse & Lens
 *	v1.12 (de) - Add support for two more inking pen IDs
 *	v1.14 (vp) - Use new USB device id probing scheme.
 *		     Fix Wacom Graphire mouse wheel
 *	v1.18 (vp) - Fix mouse wheel direction
 *		     Make mouse relative
 *      v1.20 (fl) - Report tool id for Intuos devices
 *                 - Multi tools support
 *                 - Corrected Intuos protocol decoding (airbrush, 4D mouse, lens cursor...)
 *                 - Add PL models support
 *		   - Fix Wacom Graphire mouse wheel again
 *	v1.21 (vp) - Removed protocol descriptions
 *		   - Added MISC_SERIAL for tool serial numbers
 *	      (gb) - Identify version on module load.
 *    v1.21.1 (fl) - added Graphire2 support
 *    v1.21.2 (fl) - added Intuos2 support
 *                 - added all the PL ids
 *    v1.21.3 (fl) - added another eraser id from Neil Okamoto
 *                 - added smooth filter for Graphire from Peri Hankey
 *                 - added PenPartner support from Olaf van Es
 *                 - new tool ids from Ole Martin Bjoerndalen
 *	v1.29 (pc) - Add support for more tablets
 *		   - Fix pressure reporting
 *	v1.30 (vp) - Merge 2.4 and 2.5 drivers
 *		   - Since 2.5 now has input_sync(), remove MSC_SERIAL abuse
 *		   - Cleanups here and there
 *    v1.30.1 (pi) - Added Graphire3 support
 *	v1.40 (pc) - Add support for several new devices, fix eraser reporting, ...
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/input.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/usb.h>
#include <asm/unaligned.h>
#include <asm/byteorder.h>

/*
 * Version Information
 */
#define DRIVER_VERSION "v1.30"
#define DRIVER_AUTHOR "Vojtech Pavlik <vojtech@ucw.cz>"
#define DRIVER_DESC "USB Wacom Graphire and Wacom Intuos tablet driver"
#define DRIVER_LICENSE "GPL"

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE(DRIVER_LICENSE);

#define USB_VENDOR_ID_WACOM	0x056a

#define STYLUS_DEVICE_ID        0x02
#define CURSOR_DEVICE_ID        0x06
#define ERASER_DEVICE_ID        0x0A
#define PAD_DEVICE_ID           0x0F

enum {
	PENPARTNER = 0,
	GRAPHIRE,
	WACOM_G4,
	PTU,
	PL,
	INTUOS,
	INTUOS3S,
	INTUOS3,
	INTUOS3L,
	CINTIQ,
	BEE,
	WACOM_MO,
	MAX_TYPE,
};

struct wacom_features {
	char *name;
	int pktlen;
	int x_max;
	int y_max;
	int pressure_max;
	int distance_max;
	int type;
	usb_complete_t irq;
};

struct wacom {
	signed char *data;
	dma_addr_t data_dma;
	struct input_dev dev;
	struct usb_device *usbdev;
	struct urb *irq;
	struct wacom_features *features;
	int tool[2];
	int open;
	__u32 serial[2];
	char phys[32];
	int id[2];
};

#define USB_REQ_SET_REPORT	0x09
static int usb_set_report(struct usb_interface *intf, unsigned char type,
				unsigned char id, void *buf, int size)
{
	return usb_control_msg(interface_to_usbdev(intf),
		usb_sndctrlpipe(interface_to_usbdev(intf), 0),
                USB_REQ_SET_REPORT, USB_TYPE_CLASS | USB_RECIP_INTERFACE,
                (type << 8) + id, intf->altsetting[0].desc.bInterfaceNumber,
		buf, size, HZ);
}

static void wacom_pl_irq(struct urb *urb, struct pt_regs *regs)
{
	struct wacom *wacom = urb->context;
	unsigned char *data = wacom->data;
	struct input_dev *dev = &wacom->dev;
	int prox, pressure;
	int retval;

	switch (urb->status) {
	case 0:
		/* success */
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		dbg("%s - urb shutting down with status: %d", __FUNCTION__, urb->status);
		return;
	default:
		dbg("%s - nonzero urb status received: %d", __FUNCTION__, urb->status);
		goto exit;
	}

	if (data[0] != 2) {
		dbg("wacom_pl_irq: received unknown report #%d", data[0]);
		goto exit;
	}

	prox = data[1] & 0x40;

	input_regs(dev, regs);
	
	if (prox) {

		pressure = (signed char)((data[7] << 1) | ((data[4] >> 2) & 1));
		if (wacom->features->pressure_max > 255)
			pressure = (pressure << 1) | ((data[4] >> 6) & 1);
		pressure += (wacom->features->pressure_max + 1) / 2;

		/*
		 * if going from out of proximity into proximity select between the eraser
		 * and the pen based on the state of the stylus2 button, choose eraser if
		 * pressed else choose pen. if not a proximity change from out to in, send
		 * an out of proximity for previous tool then a in for new tool.
		 */
		if (!wacom->tool[0]) {
			/* Going into proximity select tool */
			if (data[1] & 0x10)
				/* Erase bit set for DTF */
				wacom->tool[1] = BTN_TOOL_RUBBER;
			else
				wacom->tool[1] = (data[4] & 0x20)?
						 BTN_TOOL_RUBBER:BTN_TOOL_PEN;
		}
		else {
			/* was entered with stylus2 pressed */
			if (wacom->tool[1] == BTN_TOOL_RUBBER && !(data[4] & 0x20) ) {
				/* report out proximity for previous tool */
				input_report_key(dev, wacom->tool[1], 0);
				input_sync(dev);
				wacom->tool[1] = BTN_TOOL_PEN;
				goto exit;
			}
		}
		if (wacom->tool[1] != BTN_TOOL_RUBBER) {
			/* Unknown tool selected default to pen tool */
			wacom->tool[1] = BTN_TOOL_PEN;
		}
		input_report_key(dev, wacom->tool[1], prox); /* report in proximity for tool */
		input_report_abs(dev, ABS_X, data[3] | ((__u32)data[2] << 7) | ((__u32)(data[1] & 0x03) << 14));
		input_report_abs(dev, ABS_Y, data[6] | ((__u32)data[5] << 7) | ((__u32)(data[4] & 0x03) << 14));
		input_report_abs(dev, ABS_PRESSURE, pressure);

		input_report_key(dev, BTN_TOUCH, data[4] & 0x08);
		input_report_key(dev, BTN_STYLUS, data[4] & 0x10);
		/* Only allow the stylus2 button to be reported for the pen tool. */
		input_report_key(dev, BTN_STYLUS2, (wacom->tool[1] == BTN_TOOL_PEN) && (data[4] & 0x20));
	}
	else {
		/* report proximity-out of a (valid) tool */
		if (wacom->tool[1] != BTN_TOOL_RUBBER) {
			/* Unknown tool selected default to pen tool */
			wacom->tool[1] = BTN_TOOL_PEN;
		}
		input_report_key(dev, wacom->tool[1], prox);
	}

	wacom->tool[0] = prox; /* Save proximity state */
	input_sync(dev);

exit:
	retval = usb_submit_urb (urb, GFP_ATOMIC);
	if (retval)
		err ("%s - usb_submit_urb failed with result %d",
		     __FUNCTION__, retval);
}

static void wacom_ptu_irq(struct urb *urb, struct pt_regs *regs)
{
	struct wacom *wacom = urb->context;
	unsigned char *data = wacom->data;
	struct input_dev *dev = &wacom->dev;
	int retval;

	switch (urb->status) {
	case 0:
		/* success */
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		dbg("%s - urb shutting down with status: %d", __FUNCTION__, urb->status);
		return;
	default:
		dbg("%s - nonzero urb status received: %d", __FUNCTION__, urb->status);
		goto exit;
	}

	if (data[0] != 2)
	{
		printk(KERN_INFO "wacom_ptu_irq: received unknown report #%d\n", data[0]);
		goto exit;
	}

	input_regs(dev, regs);
	if (data[1] & 0x04)
	{
		input_report_key(dev, BTN_TOOL_RUBBER, data[1] & 0x20);
		input_report_key(dev, BTN_TOUCH, data[1] & 0x08);
	}
	else
	{
		input_report_key(dev, BTN_TOOL_PEN, data[1] & 0x20);
		input_report_key(dev, BTN_TOUCH, data[1] & 0x01);
	}
	input_report_abs(dev, ABS_X, data[3] << 8 | data[2]);
	input_report_abs(dev, ABS_Y, data[5] << 8 | data[4]);
	input_report_abs(dev, ABS_PRESSURE, (data[6]|data[7] << 8));
	input_report_key(dev, BTN_STYLUS, data[1] & 0x02);
	input_report_key(dev, BTN_STYLUS2, data[1] & 0x10);

	input_sync(dev);

exit:
	retval = usb_submit_urb (urb, GFP_ATOMIC);
	if (retval)
		err ("%s - usb_submit_urb failed with result %d",
		     __FUNCTION__, retval);
}

static void wacom_penpartner_irq(struct urb *urb, struct pt_regs *regs)
{
	struct wacom *wacom = urb->context;
	unsigned char *data = wacom->data;
	struct input_dev *dev = &wacom->dev;
	int retval;

	switch (urb->status) {
	case 0:
		/* success */
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		dbg("%s - urb shutting down with status: %d", __FUNCTION__, urb->status);
		return;
	default:
		dbg("%s - nonzero urb status received: %d", __FUNCTION__, urb->status);
		goto exit;
	}

	if (data[0] != 2) {
		printk(KERN_INFO "wacom_penpartner_irq: received unknown report %d\n", data[0]);
		goto exit;
	}

	input_regs(dev, regs);
	input_report_key(dev, BTN_TOOL_PEN, 1);
	input_report_abs(dev, ABS_X, le16_to_cpu(get_unaligned((__le16 *) &data[1])));
	input_report_abs(dev, ABS_Y, le16_to_cpu(get_unaligned((__le16 *) &data[3])));
	input_report_abs(dev, ABS_PRESSURE, (signed char)data[6] + 127);
	input_report_key(dev, BTN_TOUCH, ((signed char)data[6] > -80) && !(data[5] & 0x20));
	input_report_key(dev, BTN_STYLUS, (data[5] & 0x40));
	input_sync(dev);

exit:
	retval = usb_submit_urb (urb, GFP_ATOMIC);
	if (retval)
		err ("%s - usb_submit_urb failed with result %d",
		     __FUNCTION__, retval);
}

static void wacom_graphire_irq(struct urb *urb, struct pt_regs *regs)
{
	struct wacom *wacom = urb->context;
	unsigned char *data = wacom->data;
	struct input_dev *dev = &wacom->dev;
	int x, y, rw;
	int retval;

	switch (urb->status) {
	case 0:
		/* success */
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		dbg("%s - urb shutting down with status: %d", __FUNCTION__, urb->status);
		return;
	default:
		dbg("%s - nonzero urb status received: %d", __FUNCTION__, urb->status);
		goto exit;
	}

	/* check if we can handle the data */
	if (data[0] == 99)
		goto exit;

	if (data[0] != 2) {
		dbg("wacom_graphire_irq: received unknown report #%d", data[0]);
		goto exit;
	}

	x = le16_to_cpu(*(__le16 *) &data[2]);
	y = le16_to_cpu(*(__le16 *) &data[4]);

	input_regs(dev, regs);

	switch ((data[1] >> 5) & 3) {

		case 0:	/* Pen */
			input_report_key(dev, BTN_TOOL_PEN, data[1] & 0x80);
			break;

		case 1: /* Rubber */
			input_report_key(dev, BTN_TOOL_RUBBER, data[1] & 0x80);
			break;

		case 2: /* Mouse with wheel */
			input_report_key(dev, BTN_MIDDLE, data[1] & 0x04);
			if (wacom->features->type == WACOM_G4) {
				rw = data[7] & 0x04 ? (data[7] & 0x03)-4 : (data[7] & 0x03);
				input_report_rel(dev, REL_WHEEL, -rw);
			} else
				input_report_rel(dev, REL_WHEEL, (signed char) data[6]);
			/* fall through */

                case 3: /* Mouse without wheel */
			input_report_key(dev, BTN_TOOL_MOUSE, data[7] > 24);
			input_report_key(dev, BTN_LEFT, data[1] & 0x01);
			input_report_key(dev, BTN_RIGHT, data[1] & 0x02);
			if (wacom->features->type == WACOM_G4)
				input_report_abs(dev, ABS_DISTANCE, data[6] & 0x3f);
			else
				input_report_abs(dev, ABS_DISTANCE, data[7]);
			input_report_abs(dev, ABS_X, x);
			input_report_abs(dev, ABS_Y, y);

			input_sync(dev);
			goto exit;
	}

	if (data[1] & 0x80) {
		input_report_abs(dev, ABS_X, x);
		input_report_abs(dev, ABS_Y, y);
	}

	input_report_abs(dev, ABS_PRESSURE, le16_to_cpu(*(__le16 *) &data[6]));
	input_report_key(dev, BTN_TOUCH, data[1] & 0x01);
	input_report_key(dev, BTN_STYLUS, data[1] & 0x02);
	input_report_key(dev, BTN_STYLUS2, data[1] & 0x04);

	input_sync(dev);

	/* send pad data */
	if (wacom->features->type == WACOM_G4) {
		if ((wacom->serial[1] & 0xc0) != (data[7] & 0xf8)) {
			wacom->id[1] = 1;
			wacom->serial[1] = (data[7] & 0xf8);
			input_report_key(dev, BTN_0, (data[7] & 0x40));
			input_report_key(dev, BTN_4, (data[7] & 0x80));
			rw = ((data[7] & 0x18) >> 3) - ((data[7] & 0x20) >> 3);
			input_report_rel(dev, REL_WHEEL, rw);
			input_report_key(dev, BTN_TOOL_FINGER, 0xf0);
			input_event(dev, EV_MSC, MSC_SERIAL, 0xf0);
		} else if (wacom->id[1]) {
			wacom->id[1] = 0;
			input_report_key(dev, BTN_TOOL_FINGER, 0);
			input_event(dev, EV_MSC, MSC_SERIAL, 0xf0);
		}
		input_sync(dev);
	}

exit:
	retval = usb_submit_urb (urb, GFP_ATOMIC);
	if (retval)
		err ("%s - usb_submit_urb failed with result %d",
		     __FUNCTION__, retval);
}

static int wacom_intuos_inout(struct urb *urb)
{
	struct wacom *wacom = urb->context;
	unsigned char *data = wacom->data;
	struct input_dev *dev = &wacom->dev;
	int idx;

	/* tool number */
	idx = data[1] & 0x01;

	/* Enter report */
	if ((data[1] & 0xfc) == 0xc0) 
	{	
		/* serial number of the tool */
		wacom->serial[idx] = ((__u32)(data[3] & 0x0f) << 28) +	
			((__u32)data[4] << 20) + ((__u32)data[5] << 12) +
			((__u32)data[6] << 4) + (data[7] >> 4);

		switch (((__u32)data[2] << 4) | (data[3] >> 4)) {
			case 0x812: /* Inking pen */
			case 0x801: /* Intuos3 Inking pen */
			case 0x012: 
				wacom->tool[idx] = BTN_TOOL_PENCIL;
				break;	
			case 0x822: /* Pen */
			case 0x842:
			case 0x852:
			case 0x823: /* Intuos3 Grip Pen */
			case 0x813: /* Intuos3 Classic Pen */
			case 0x885: /* Intuos3 Marker Pen */
			case 0x022: 
				wacom->tool[idx] = BTN_TOOL_PEN;
				break;
			case 0x832: /* Stroke pen */
			case 0x032: 
				wacom->tool[idx] = BTN_TOOL_BRUSH;
				break;
			case 0x007: /* Mouse 4D and 2D */
		        case 0x09c:
			case 0x094:
			case 0x017: /* Intuos3 2D Mouse */
				wacom->tool[idx] = BTN_TOOL_MOUSE;
				break;
			case 0x096: /* Lens cursor */
			case 0x097: /* Intuos3 Lens cursor */
				wacom->tool[idx] = BTN_TOOL_LENS;
				break;
			case 0x82a: /* Eraser */
			case 0x85a:
		        case 0x91a:
			case 0xd1a:
			case 0x0fa: 
			case 0x82b: /* Intuos3 Grip Pen Eraser */
			case 0x81b: /* Intuos3 Classic Pen Eraser */
			case 0x91b: /* Intuos3 Airbrush Eraser */
				wacom->tool[idx] = BTN_TOOL_RUBBER;
				break;
			case 0xd12: /* Airbrush */
			case 0x912:
			case 0x112: 
			case 0x913: /* Intuos3 Airbrush */
				wacom->tool[idx] = BTN_TOOL_AIRBRUSH;
				break;
			default: /* Unknown tool */
				wacom->tool[idx] = BTN_TOOL_PEN;
		}
		input_report_key(dev, wacom->tool[idx], 1);
		input_event(dev, EV_MSC, MSC_SERIAL, wacom->serial[idx]);
		input_sync(dev);
		return 1;
	}

	/* Exit report */
	if ((data[1] & 0xfe) == 0x80) {
		input_report_key(dev, wacom->tool[idx], 0);
		input_event(dev, EV_MSC, MSC_SERIAL, wacom->serial[idx]);
		input_sync(dev);
		return 1;
	}

	return 0;
}

static void wacom_intuos_general(struct urb *urb)
{
	struct wacom *wacom = urb->context;
	unsigned char *data = wacom->data;
	struct input_dev *dev = &wacom->dev;
	unsigned int t;

	/* general pen packet */
	if ((data[1] & 0xb8) == 0xa0)
	{
		t = ((__u32)data[6] << 2) | ((data[7] >> 6) & 3);
		input_report_abs(dev, ABS_PRESSURE, t);
		input_report_abs(dev, ABS_TILT_X,
				((data[7] << 1) & 0x7e) | (data[8] >> 7));
		input_report_abs(dev, ABS_TILT_Y, data[8] & 0x7f);
		input_report_key(dev, BTN_STYLUS, data[1] & 2);
		input_report_key(dev, BTN_STYLUS2, data[1] & 4);
		input_report_key(dev, BTN_TOUCH, t > 10);
	}

	/* airbrush second packet */
	if ((data[1] & 0xbc) == 0xb4)
	{
		input_report_abs(dev, ABS_WHEEL,
				((__u32)data[6] << 2) | ((data[7] >> 6) & 3));
		input_report_abs(dev, ABS_TILT_X,
				((data[7] << 1) & 0x7e) | (data[8] >> 7));
		input_report_abs(dev, ABS_TILT_Y, data[8] & 0x7f);
	}
	return;
}

static void wacom_intuos_irq(struct urb *urb, struct pt_regs *regs)
{
	struct wacom *wacom = urb->context;
	unsigned char *data = wacom->data;
	struct input_dev *dev = &wacom->dev;
	unsigned int t;
	int idx;
	int retval;

	switch (urb->status) {
	case 0:
		/* success */
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		dbg("%s - urb shutting down with status: %d", __FUNCTION__, urb->status);
		return;
	default:
		dbg("%s - nonzero urb status received: %d", __FUNCTION__, urb->status);
		goto exit;
	}

	if (data[0] != 2 && data[0] != 5 && data[0] != 6) {
		dbg("wacom_intuos_irq: received unknown report #%d", data[0]);
		goto exit;
	}

	input_regs(dev, regs);

	/* tool number */
	idx = data[1] & 0x01;

	/* process in/out prox events */
	if (wacom_intuos_inout(urb)) goto exit;

	input_report_abs(dev, ABS_X, be16_to_cpu(*(__be16 *) &data[2]));
	input_report_abs(dev, ABS_Y, be16_to_cpu(*(__be16 *) &data[4]));
	input_report_abs(dev, ABS_DISTANCE, data[9]);

	/* process general packets */
	wacom_intuos_general(urb);
	
	if ((data[1] & 0xbc) == 0xa8 || (data[1] & 0xbe) == 0xb0) {		/* 4D mouse or Lens cursor packets */

		if (data[1] & 0x02) {						/* Rotation packet */

			t = ((__u32)data[6] << 3) | ((data[7] >> 5) & 7);
			input_report_abs(dev, ABS_RZ, (data[7] & 0x20) ? ((t - 1) / 2) : -t / 2);

		} else {

	 		if ((data[1] & 0x10) == 0) {				/* 4D mouse packets */

				input_report_key(dev, BTN_LEFT,   data[8] & 0x01);
				input_report_key(dev, BTN_MIDDLE, data[8] & 0x02);
				input_report_key(dev, BTN_RIGHT,  data[8] & 0x04);

				input_report_key(dev, BTN_SIDE,   data[8] & 0x20);
				input_report_key(dev, BTN_EXTRA,  data[8] & 0x10);
				t = ((__u32)data[6] << 2) | ((data[7] >> 6) & 3);
				input_report_abs(dev, ABS_THROTTLE, (data[8] & 0x08) ? -t : t);
			} else {
				if (wacom->tool[idx] == BTN_TOOL_MOUSE) {	/* 2D mouse packets */	
					input_report_key(dev, BTN_LEFT,   data[8] & 0x04);
					input_report_key(dev, BTN_MIDDLE, data[8] & 0x08);
					input_report_key(dev, BTN_RIGHT,  data[8] & 0x10);
					input_report_rel(dev, REL_WHEEL, 
					    (-(__u32)(data[8] & 0x01) + (__u32)((data[8] & 0x02) >> 1)));
				}
				else {     /* Lens cursor packets */
					input_report_key(dev, BTN_LEFT,   data[8] & 0x01);
					input_report_key(dev, BTN_MIDDLE, data[8] & 0x02);
					input_report_key(dev, BTN_RIGHT,  data[8] & 0x04);
					input_report_key(dev, BTN_SIDE,   data[8] & 0x10);
					input_report_key(dev, BTN_EXTRA,  data[8] & 0x08);
				}
			}
		}
	}
	
	input_report_key(dev, wacom->tool[idx], 1);
	input_event(dev, EV_MSC, MSC_SERIAL, wacom->serial[idx]);
	input_sync(dev);

exit:
	retval = usb_submit_urb (urb, GFP_ATOMIC);
	if (retval)
		err ("%s - usb_submit_urb failed with result %d",
		     __FUNCTION__, retval);
}

static void wacom_intuos3_irq(struct urb *urb, struct pt_regs *regs)
{
	struct wacom *wacom = urb->context;
	unsigned char *data = wacom->data;
	struct input_dev *dev = &wacom->dev;
	unsigned int t;
	int idx, retval;

	switch (urb->status) {
	case 0:
		/* success */
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		dbg("%s - urb shutting down with status: %d", __FUNCTION__, urb->status);
		return;
	default:
		dbg("%s - nonzero urb status received: %d", __FUNCTION__, urb->status);
		goto exit;
	}

	/* check for valid report */
	if (data[0] != 2 && data[0] != 5 && data[0] != 12)
	{
		printk(KERN_INFO "wacom_intuos3_irq: received unknown report #%d\n", data[0]);
		goto exit;
	}

	input_regs(dev, regs);

	/* tool index is always 0 here since there is no dual input tool */
	idx = data[1] & 0x01;

	/* pad packets. Works as a second tool and is alway in prox */
	if (data[0] == 12)
	{
		/* initiate the pad as a device */
		if (wacom->tool[1] != BTN_TOOL_FINGER)
		{
			wacom->tool[1] = BTN_TOOL_FINGER;
			input_report_key(dev, wacom->tool[1], 1);
		}
		input_report_key(dev, BTN_0, (data[5] & 0x01));
		input_report_key(dev, BTN_1, (data[5] & 0x02));
		input_report_key(dev, BTN_2, (data[5] & 0x04));
		input_report_key(dev, BTN_3, (data[5] & 0x08));
		input_report_key(dev, BTN_4, (data[6] & 0x01));
		input_report_key(dev, BTN_5, (data[6] & 0x02));
		input_report_key(dev, BTN_6, (data[6] & 0x04));
		input_report_key(dev, BTN_7, (data[6] & 0x08));
		input_report_key(dev, BTN_8, (data[5] & 0x10));
		input_report_key(dev, BTN_9, (data[6] & 0x10));
		input_report_abs(dev, ABS_RX, ((data[1] & 0x1f) << 8) | data[2]);
		input_report_abs(dev, ABS_RY, ((data[3] & 0x1f) << 8) | data[4]);

		if((data[5] & 0x1f) | (data[6] & 0x1f) | (data[1] & 0x1f) |
		   data[2] | (data[3] & 0x1f) | data[4])
			input_report_key(dev, wacom->tool[1], 1);
		else
			input_report_key(dev, wacom->tool[1], 0);
		input_report_abs(dev, ABS_MISC, PAD_DEVICE_ID);
		input_event(dev, EV_MSC, MSC_SERIAL, 0xffffffff);
		input_sync(dev);
		goto exit;
	}

	/* process in/out prox events */
	if (wacom_intuos_inout(urb)) goto exit;

	/* Cintiq doesn't send data when RDY bit isn't set */
	if (wacom->features->type == CINTIQ && !(data[1] & 0x40))
		goto exit;

	input_report_abs(dev, ABS_X, ((__u32)data[2] << 9) | ((__u32)data[3] << 1) | ((data[9] >> 1) & 1));
	input_report_abs(dev, ABS_Y, ((__u32)data[4] << 9) | ((__u32)data[5] << 1) | (data[9] & 1));
	input_report_abs(dev, ABS_DISTANCE, ((data[9] >> 2) & 0x3f));

	/* process general packets */
	wacom_intuos_general(urb);

	if ((data[1] & 0xbc) == 0xa8 || (data[1] & 0xbe) == 0xb0)
	{
		if (data[1] & 0x02)
		{
			t = ((__u32)data[6] << 3) | ((data[7] >> 5) & 7);
			t = (data[7] & 0x20) ? ((t > 900) ? ((t-1) / 2 - 1350) :
				((t-1) / 2 + 450)) : (450 - t / 2) ;
			input_report_abs(dev, ABS_Z, t);
		}

		/* 2D mouse packets */
		if (wacom->tool[idx] == BTN_TOOL_MOUSE)
		{
			input_report_key(dev, BTN_LEFT,   data[8] & 0x04);
			input_report_key(dev, BTN_MIDDLE, data[8] & 0x08);
			input_report_key(dev, BTN_RIGHT,  data[8] & 0x10);
			input_report_key(dev, BTN_SIDE,   data[8] & 0x40);
			input_report_key(dev, BTN_EXTRA,  data[8] & 0x20);
			/* mouse wheel is positive when rolled backwards */
			input_report_rel(dev, REL_WHEEL,  ((__u32)((data[8] & 0x02) >> 1)
					 - (__u32)(data[8] & 0x01)));
		} else if (wacom->features->type == INTUOS3L) {
			/* Lens cursor packets */
			input_report_key(dev, BTN_LEFT,   data[8] & 0x01);
			input_report_key(dev, BTN_MIDDLE, data[8] & 0x02);
			input_report_key(dev, BTN_RIGHT,  data[8] & 0x04);
			input_report_key(dev, BTN_SIDE,   data[8] & 0x10);
			input_report_key(dev, BTN_EXTRA,  data[8] & 0x08);
		}
	}

	input_report_key(dev, wacom->tool[idx], 1);
	input_event(dev, EV_MSC, MSC_SERIAL, wacom->serial[idx]);
	input_sync(dev);

exit:
	retval = usb_submit_urb (urb, GFP_ATOMIC);
	if (retval)
		err ("%s - usb_submit_urb failed with result %d",
		    __FUNCTION__, retval);
}

static struct wacom_features wacom_features[] = {
	{ "Wacom Penpartner",    7,   5040,  3780,  255,  0, PENPARTNER, wacom_penpartner_irq },
	{ "Wacom Graphire",      8,  10206,  7422,  511, 63, GRAPHIRE, wacom_graphire_irq },
	{ "Wacom Graphire2 4x5", 8,  10206,  7422,  511, 63, GRAPHIRE, wacom_graphire_irq },
 	{ "Wacom Graphire2 5x7", 8,  13918, 10206,  511, 63, GRAPHIRE, wacom_graphire_irq },
	{ "Wacom Graphire3 4x5", 8,  10208,  7424,  511, 63, GRAPHIRE, wacom_graphire_irq },
	{ "Wacom Graphire3 6x8", 8,  16704, 12064,  511, 63, GRAPHIRE, wacom_graphire_irq },
	{ "Wacom Graphire4 4x5", 8,  10208,  7424,  511, 63, WACOM_G4, wacom_graphire_irq },
	{ "Wacom Graphire4 6x8", 8,  16704, 12064,  511, 63, WACOM_G4, wacom_graphire_irq },
	{ "Wacom Intuos 4x5",   10,  12700, 10600, 1023, 31, INTUOS, wacom_intuos_irq },
 	{ "Wacom Intuos 6x8",   10,  20320, 16240, 1023, 31, INTUOS, wacom_intuos_irq },
 	{ "Wacom Intuos 9x12",  10,  30480, 24060, 1023, 31, INTUOS, wacom_intuos_irq },
 	{ "Wacom Intuos 12x12", 10,  30480, 31680, 1023, 31, INTUOS, wacom_intuos_irq },
 	{ "Wacom Intuos 12x18", 10,  45720, 31680, 1023, 31, INTUOS, wacom_intuos_irq },
 	{ "Wacom PL400",         8,   5408,  4056,  255,  0, PL, wacom_pl_irq },
 	{ "Wacom PL500",         8,   6144,  4608,  255,  0, PL, wacom_pl_irq },
 	{ "Wacom PL600",         8,   6126,  4604,  255,  0, PL, wacom_pl_irq },
 	{ "Wacom PL600SX",       8,   6260,  5016,  255,  0, PL, wacom_pl_irq },
 	{ "Wacom PL550",         8,   6144,  4608,  511,  0, PL, wacom_pl_irq },
 	{ "Wacom PL800",         8,   7220,  5780,  511,  0, PL, wacom_pl_irq },
	{ "Wacom PL700",         8,   6758,  5406,  511,  0, PL, wacom_pl_irq },
	{ "Wacom PL510",         8,   6282,  4762,  511,  0, PL, wacom_pl_irq },
	{ "Wacom DTU710",        8,  34080, 27660,  511,  0, PL, wacom_pl_irq },
	{ "Wacom DTF521",        8,   6282,  4762,  511,  0, PL, wacom_pl_irq },
	{ "Wacom DTF720",        8,   6858,  5506,  511,  0, PL, wacom_pl_irq },
	{ "Wacom Intuos2 4x5",   10, 12700, 10600, 1023, 31, INTUOS, wacom_intuos_irq },
	{ "Wacom Intuos2 6x8",   10, 20320, 16240, 1023, 31, INTUOS, wacom_intuos_irq },
	{ "Wacom Intuos2 9x12",  10, 30480, 24060, 1023, 31, INTUOS, wacom_intuos_irq },
	{ "Wacom Intuos2 12x12", 10, 30480, 31680, 1023, 31, INTUOS, wacom_intuos_irq },
	{ "Wacom Intuos2 12x18", 10, 45720, 31680, 1023, 31, INTUOS, wacom_intuos_irq },
	{ "Wacom Volito",        8,   5104,  3712,  511, 63, GRAPHIRE, wacom_graphire_irq },
	{ "Wacom PenStation2",   8,   3250,  2320,  255, 63, GRAPHIRE, wacom_graphire_irq },
	{ "Wacom Volito2 4x5",   8,   5104,  3712,  511, 63, GRAPHIRE, wacom_graphire_irq },
	{ "Wacom Volito2 2x3",   8,   3248,  2320,  511, 63, GRAPHIRE, wacom_graphire_irq },
	{ "Wacom PenPartner2",   8,   3250,  2320,  255, 63, GRAPHIRE, wacom_graphire_irq },
	{ "Wacom Cintiq Partner",8,  20480, 15360,  511,  0, PTU, wacom_ptu_irq },
	{ "Wacom Intuos3 4x5",   10, 25400, 20320, 1023, 63, INTUOS3, wacom_intuos3_irq },
	{ "Wacom Intuos3 6x8",   10, 40640, 30480, 1023, 63, INTUOS3, wacom_intuos3_irq },
	{ "Wacom Intuos3 9x12",  10, 60960, 45720, 1023, 63, INTUOS3, wacom_intuos3_irq },
	{ "Wacom Intuos3 12x12", 10, 60960, 60960, 1023, 63, INTUOS3L, wacom_intuos3_irq },
	{ "Wacom Intuos3 12x19", 10, 97536, 60960, 1023, 63, INTUOS3L, wacom_intuos3_irq },
	{ "Wacom Intuos3 6x11",  10, 54204, 31750, 1023, 63, INTUOS3, wacom_intuos3_irq },
	{ "Wacom Intuos3 4x6",   10, 31496, 19685, 1023, 63, INTUOS3S, wacom_intuos3_irq },
	{ "Wacom Cintiq 21UX",   10, 87200, 65600, 1023, 63, CINTIQ, wacom_intuos3_irq },
	{ "Wacom Cintiq 20WSX",  10, 86680, 54180, 1023, 63, BEE, wacom_intuos3_irq },
	{ "Wacom Intuos2 6x8",   10, 20320, 16240, 1023, 31, INTUOS, wacom_intuos_irq },
 	{ }
};

static struct usb_device_id wacom_ids[] = {
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x00) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x10) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x11) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x12) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x13) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x14) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x15) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x16) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x20) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x21) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x22) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x23) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x24) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x30) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x31) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x32) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x33) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x34) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x35) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x37) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x38) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x39) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xC0) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xC4) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x41) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x42) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x43) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x44) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x45) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x60) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x61) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x62) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x63) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x64) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x03) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB0) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB1) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB2) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB3) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB4) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB5) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xB7) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x3F) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0xC5) },
	{ USB_DEVICE(USB_VENDOR_ID_WACOM, 0x47) },
	{ }
};

MODULE_DEVICE_TABLE(usb, wacom_ids);

static int wacom_open(struct input_dev *dev)
{
	struct wacom *wacom = dev->private;

	if (wacom->open++)
		return 0;

	wacom->irq->dev = wacom->usbdev;
	if (usb_submit_urb(wacom->irq, GFP_KERNEL)) {
		wacom->open--;
		return -EIO;
	}

	return 0;
}

static void wacom_close(struct input_dev *dev)
{
	struct wacom *wacom = dev->private;

	if (!--wacom->open)
		usb_unlink_urb(wacom->irq);
}

static int wacom_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	struct usb_device *dev = interface_to_usbdev(intf);
	struct usb_endpoint_descriptor *endpoint;
	char rep_data[2] = {0x02, 0x02};
	struct wacom *wacom;
	char path[64];

	if (!(wacom = kmalloc(sizeof(struct wacom), GFP_KERNEL)))
		return -ENOMEM;
	memset(wacom, 0, sizeof(struct wacom));

	wacom->data = usb_buffer_alloc(dev, 10, GFP_KERNEL, &wacom->data_dma);
	if (!wacom->data) {
		kfree(wacom);
		return -ENOMEM;
	}

	wacom->irq = usb_alloc_urb(0, GFP_KERNEL);
	if (!wacom->irq) {
		usb_buffer_free(dev, 10, wacom->data, wacom->data_dma);
		kfree(wacom);
		return -ENOMEM;
	}

	wacom->features = wacom_features + (id - wacom_ids);

	wacom->dev.evbit[0] |= BIT(EV_KEY) | BIT(EV_ABS);
	wacom->dev.absbit[0] |= BIT(ABS_X) | BIT(ABS_Y) | BIT(ABS_PRESSURE);
	wacom->dev.keybit[LONG(BTN_DIGI)] |= BIT(BTN_TOOL_PEN) | BIT(BTN_TOUCH) | BIT(BTN_STYLUS);

	switch (wacom->features->type) {
		case WACOM_G4:
			wacom->dev.keybit[LONG(BTN_DIGI)] |= BIT(BTN_TOOL_FINGER);
			wacom->dev.keybit[LONG(BTN_LEFT)] |= BIT(BTN_0) |
			BIT(BTN_1) |
			BIT(BTN_2) |
			BIT(BTN_3) |
			BIT(BTN_4) |
			BIT(BTN_5) |
			BIT(BTN_6) |
			BIT(BTN_7);
			/* fall through */
		case GRAPHIRE:
			wacom->dev.evbit[0] |= BIT(EV_REL);
			wacom->dev.relbit[0] |= BIT(REL_WHEEL);
			wacom->dev.absbit[0] |= BIT(ABS_DISTANCE);
			wacom->dev.keybit[LONG(BTN_LEFT)] |= BIT(BTN_LEFT) | BIT(BTN_RIGHT) | BIT(BTN_MIDDLE);
 			wacom->dev.keybit[LONG(BTN_DIGI)] |= BIT(BTN_TOOL_RUBBER) | BIT(BTN_TOOL_MOUSE) | BIT(BTN_STYLUS2);
			break;

		case BEE:
			wacom->dev.keybit[LONG(BTN_LEFT)] |= BIT(BTN_8) | BIT(BTN_9);
			/* fall through */
		case INTUOS3: /* new functions for Intuos3 */
		case CINTIQ: /* cintiq */
		case INTUOS3L:
			wacom->dev.keybit[LONG(BTN_DIGI)] |= BIT(BTN_TOOL_FINGER);
			wacom->dev.keybit[LONG(BTN_LEFT)] |= BIT(BTN_4) | BIT(BTN_5) | BIT(BTN_6) | BIT(BTN_7);
			wacom->dev.absbit[0] |= BIT(ABS_RY);
			/* fall through */

		case INTUOS3S:
			wacom->dev.keybit[LONG(BTN_LEFT)] |= BIT(BTN_0) | BIT(BTN_1) | BIT(BTN_2) | BIT(BTN_3);
			wacom->dev.absbit[0] |= BIT(ABS_RX) | BIT(ABS_Z);
			wacom->dev.absmax[ABS_Z] = 899;
			wacom->dev.absmin[ABS_Z] = -900;
			/* fall through */

		case INTUOS:
			wacom->dev.evbit[0] |= BIT(EV_MSC) | BIT(EV_REL);
			wacom->dev.mscbit[0] |= BIT(MSC_SERIAL);
			wacom->dev.relbit[0] |= BIT(REL_WHEEL);
			wacom->dev.keybit[LONG(BTN_LEFT)] |= BIT(BTN_LEFT) | BIT(BTN_RIGHT) | BIT(BTN_MIDDLE) | BIT(BTN_SIDE) | BIT(BTN_EXTRA);
 			wacom->dev.keybit[LONG(BTN_DIGI)] |= BIT(BTN_TOOL_RUBBER) | BIT(BTN_TOOL_MOUSE)	| BIT(BTN_TOOL_BRUSH)
							  | BIT(BTN_TOOL_PENCIL) | BIT(BTN_TOOL_AIRBRUSH) | BIT(BTN_TOOL_LENS) | BIT(BTN_STYLUS2);
			wacom->dev.absbit[0] |= BIT(ABS_DISTANCE) | BIT(ABS_WHEEL) | BIT(ABS_TILT_X) | BIT(ABS_TILT_Y) | BIT(ABS_RZ) | BIT(ABS_THROTTLE);
			break;

		case PL:
		case PTU:
 			wacom->dev.keybit[LONG(BTN_DIGI)] |= BIT(BTN_STYLUS2) | BIT(BTN_TOOL_RUBBER);
			break;
	}

	wacom->dev.absmax[ABS_X] = wacom->features->x_max;
	wacom->dev.absmax[ABS_Y] = wacom->features->y_max;
	wacom->dev.absmax[ABS_PRESSURE] = wacom->features->pressure_max;
	wacom->dev.absmax[ABS_DISTANCE] = wacom->features->distance_max;
	wacom->dev.absmax[ABS_TILT_X] = 127;
	wacom->dev.absmax[ABS_TILT_Y] = 127;
	wacom->dev.absmax[ABS_WHEEL] = 1023;

	wacom->dev.absmax[ABS_RX] = 4097;
	wacom->dev.absmax[ABS_RY] = 4097;
	wacom->dev.absmin[ABS_RZ] = -900;
	wacom->dev.absmax[ABS_RZ] = 899;
	wacom->dev.absmin[ABS_THROTTLE] = -1023;
	wacom->dev.absmax[ABS_THROTTLE] = 1023;

	wacom->dev.absfuzz[ABS_X] = 4;
	wacom->dev.absfuzz[ABS_Y] = 4;

	wacom->dev.private = wacom;
	wacom->dev.open = wacom_open;
	wacom->dev.close = wacom_close;

	usb_make_path(dev, path, 64);
	sprintf(wacom->phys, "%s/input0", path);

	wacom->dev.name = wacom->features->name;
	wacom->dev.phys = wacom->phys;
	wacom->dev.id.bustype = BUS_USB;
	wacom->dev.id.vendor = dev->descriptor.idVendor;
	wacom->dev.id.product = dev->descriptor.idProduct;
	wacom->dev.id.version = dev->descriptor.bcdDevice;
	wacom->dev.dev = &intf->dev;
	wacom->usbdev = dev;

	endpoint = &intf->cur_altsetting->endpoint[0].desc;

	if (wacom->features->pktlen > 10)
		BUG();

	usb_fill_int_urb(wacom->irq, dev,
			 usb_rcvintpipe(dev, endpoint->bEndpointAddress),
			 wacom->data, wacom->features->pktlen,
			 wacom->features->irq, wacom, endpoint->bInterval);
	wacom->irq->transfer_dma = wacom->data_dma;
	wacom->irq->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

	input_register_device(&wacom->dev);

	/* Sleep for a second here to avoid power up races. */
	set_current_state(TASK_UNINTERRUPTIBLE);
	schedule_timeout(HZ);

 	/* ask the tablet to report tablet data */
	usb_set_report(intf, 3, 2, rep_data, 2);
	usb_set_report(intf, 3, 5, rep_data, 0);
	usb_set_report(intf, 3, 6, rep_data, 0);

	printk(KERN_INFO "input: %s on %s\n", wacom->features->name, path);

	usb_set_intfdata(intf, wacom);

	return 0;
}

static void wacom_disconnect(struct usb_interface *intf)
{
	struct wacom *wacom = usb_get_intfdata (intf);

	usb_set_intfdata(intf, NULL);
	if (wacom) {
		usb_unlink_urb(wacom->irq);
		input_unregister_device(&wacom->dev);
		usb_free_urb(wacom->irq);
		usb_buffer_free(interface_to_usbdev(intf), 10, wacom->data, wacom->data_dma);
		kfree(wacom);
	}
}

static struct usb_driver wacom_driver = {
	.owner =	THIS_MODULE,
	.name =		"wacom",
	.probe =	wacom_probe,
	.disconnect =	wacom_disconnect,
	.id_table =	wacom_ids,
};

static int __init wacom_init(void)
{
	int result = usb_register(&wacom_driver);
	if (result == 0)
		info(DRIVER_VERSION ":" DRIVER_DESC);
	return result;
}

static void __exit wacom_exit(void)
{
	usb_deregister(&wacom_driver);
}

module_init(wacom_init);
module_exit(wacom_exit);

/******************************************************************************
 * Talks to Xen Store to figure out what devices we have.
 *
 * Copyright (C) 2005 Rusty Russell, IBM Corporation
 * Copyright (C) 2005 Mike Wray, Hewlett-Packard
 * Copyright (C) 2005, 2006 XenSource Ltd
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#define DPRINTK(fmt, args...)				\
	pr_debug("xenbus_probe (%s:%d) " fmt ".\n",	\
		 __FUNCTION__, __LINE__, ##args)

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/kthread.h>

#include <asm/io.h>
#include <asm/page.h>
#include <asm/maddr.h>
#include <asm/pgtable.h>
#include <asm/hypervisor.h>
#include <xen/xenbus.h>
#include <xen/xen_proc.h>
#include <xen/evtchn.h>
#include <xen/features.h>
#include <xen/driver_util.h>

#include "xenbus_comms.h"

#ifdef HAVE_XEN_PLATFORM_COMPAT_H
#include <xen/hvm.h>
#include <xen/platform-compat.h>
#endif

int xen_store_evtchn;
struct xenstore_domain_interface *xen_store_interface;
static unsigned long xen_store_mfn;

extern struct semaphore xenwatch_mutex;

static struct notifier_block *xenstore_chain;

static void wait_for_devices(struct xenbus_driver *xendrv);

static int xenbus_probe_frontend(const char *type, const char *name);
#ifdef CONFIG_XEN
static int xenbus_hotplug_backend(struct device *dev, char **envp,
				 int num_envp, char *buffer, int buffer_size);
static int xenbus_probe_backend(const char *type, const char *domid);
#endif
static int xenbus_dev_probe(struct device *_dev);
static int xenbus_dev_remove(struct device *_dev);
#ifdef CONFIG_XEN_PV_ON_HVM
static void xenbus_dev_shutdown(struct device *_dev);
#endif

/* If something in array of ids matches this device, return it. */
static const struct xenbus_device_id *
match_device(const struct xenbus_device_id *arr, struct xenbus_device *dev)
{
	for (; *arr->devicetype != '\0'; arr++) {
		if (!strcmp(arr->devicetype, dev->devicetype))
			return arr;
	}
	return NULL;
}

static int xenbus_match(struct device *_dev, struct device_driver *_drv)
{
	struct xenbus_driver *drv = to_xenbus_driver(_drv);

	if (!drv->ids)
		return 0;

	return match_device(drv->ids, to_xenbus_device(_dev)) != NULL;
}

struct xen_bus_type
{
	char *root;
	int error;
	unsigned int levels;
	int (*get_bus_id)(char bus_id[BUS_ID_SIZE], const char *nodename);
	int (*probe)(const char *type, const char *dir);
	struct bus_type bus;
	struct device dev;
};


/* device/<type>/<id> => <type>-<id> */
static int frontend_bus_id(char bus_id[BUS_ID_SIZE], const char *nodename)
{
	nodename = strchr(nodename, '/');
	if (!nodename || strlen(nodename + 1) >= BUS_ID_SIZE) {
		printk(KERN_WARNING "XENBUS: bad frontend %s\n", nodename);
		return -EINVAL;
	}

	strlcpy(bus_id, nodename + 1, BUS_ID_SIZE);
	if (!strchr(bus_id, '/')) {
		printk(KERN_WARNING "XENBUS: bus_id %s no slash\n", bus_id);
		return -EINVAL;
	}
	*strchr(bus_id, '/') = '-';
	return 0;
}


static void free_otherend_details(struct xenbus_device *dev)
{
	kfree(dev->otherend);
	dev->otherend = NULL;
}


static void free_otherend_watch(struct xenbus_device *dev)
{
	if (dev->otherend_watch.node) {
		unregister_xenbus_watch(&dev->otherend_watch);
		kfree(dev->otherend_watch.node);
		dev->otherend_watch.node = NULL;
	}
}


static int read_otherend_details(struct xenbus_device *xendev,
				 char *id_node, char *path_node)
{
	int err = xenbus_gather(XBT_NIL, xendev->nodename,
				id_node, "%i", &xendev->otherend_id,
				path_node, NULL, &xendev->otherend,
				NULL);
	if (err) {
		xenbus_dev_fatal(xendev, err,
				 "reading other end details from %s",
				 xendev->nodename);
		return err;
	}
	if (strlen(xendev->otherend) == 0 ||
	    !xenbus_exists(XBT_NIL, xendev->otherend, "")) {
		xenbus_dev_fatal(xendev, -ENOENT,
				 "unable to read other end from %s.  "
				 "missing or inaccessible.",
				 xendev->nodename);
		free_otherend_details(xendev);
		return -ENOENT;
	}

	return 0;
}


static int read_backend_details(struct xenbus_device *xendev)
{
	return read_otherend_details(xendev, "backend-id", "backend");
}

#if CONFIG_XEN
static int read_frontend_details(struct xenbus_device *xendev)
{
	return read_otherend_details(xendev, "frontend-id", "frontend");
}
#endif

/* Bus type for frontend drivers. */
static struct xen_bus_type xenbus_frontend = {
	.root = "device",
	.levels = 2, 		/* device/type/<id> */
	.get_bus_id = frontend_bus_id,
	.probe = xenbus_probe_frontend,
	/* to ensure loading pv-on-hvm drivers on bare metal doesn't 
         * blowup trying to use uninit'd xenbus.
	 */
	.error = -ENODEV,
	.bus = {
		.name  = "xen",
		.match = xenbus_match,
	},
	.dev = {
		.bus_id = "xen",
	},
};

#ifdef CONFIG_XEN
/* backend/<type>/<fe-uuid>/<id> => <type>-<fe-domid>-<id> */
static int backend_bus_id(char bus_id[BUS_ID_SIZE], const char *nodename)
{
	int domid, err;
	const char *devid, *type, *frontend;
	unsigned int typelen;

	type = strchr(nodename, '/');
	if (!type)
		return -EINVAL;
	type++;
	typelen = strcspn(type, "/");
	if (!typelen || type[typelen] != '/')
		return -EINVAL;

	devid = strrchr(nodename, '/') + 1;

	err = xenbus_gather(XBT_NIL, nodename, "frontend-id", "%i", &domid,
			    "frontend", NULL, &frontend,
			    NULL);
	if (err)
		return err;
	if (strlen(frontend) == 0)
		err = -ERANGE;
	if (!err && !xenbus_exists(XBT_NIL, frontend, ""))
		err = -ENOENT;

	kfree(frontend);

	if (err)
		return err;

	if (snprintf(bus_id, BUS_ID_SIZE,
		     "%.*s-%i-%s", typelen, type, domid, devid) >= BUS_ID_SIZE)
		return -ENOSPC;
	return 0;
}

static struct xen_bus_type xenbus_backend = {
	.root = "backend",
	.levels = 3, 		/* backend/type/<frontend>/<id> */
	.get_bus_id = backend_bus_id,
	.probe = xenbus_probe_backend,
	.bus = {
		.name  = "xen-backend",
		.match = xenbus_match,
		.hotplug = xenbus_hotplug_backend,
	},
	.dev = {
		.bus_id = "xen-backend",
	},
};

static int xenbus_hotplug_backend(struct device *dev, char **envp,
				  int num_envp, char *buffer, int buffer_size)
{
	struct xenbus_device *xdev;
	struct xenbus_driver *drv;
	int i = 0;
	int length = 0;

	DPRINTK("");

	if (dev == NULL)
		return -ENODEV;

	xdev = to_xenbus_device(dev);
	if (xdev == NULL)
		return -ENODEV;

	/* stuff we want to pass to /sbin/hotplug */
	add_hotplug_env_var(envp, num_envp, &i,
			    buffer, buffer_size, &length,
			    "XENBUS_TYPE=%s", xdev->devicetype);

	add_hotplug_env_var(envp, num_envp, &i,
			    buffer, buffer_size, &length,
			    "XENBUS_PATH=%s", xdev->nodename);

	add_hotplug_env_var(envp, num_envp, &i,
			    buffer, buffer_size, &length,
			    "XENBUS_BASE_PATH=%s", xenbus_backend.root);

	/* terminate, set to next free slot, shrink available space */
	envp[i] = NULL;
	envp = &envp[i];
	num_envp -= i;
	buffer = &buffer[length];
	buffer_size -= length;

	if (dev->driver) {
		drv = to_xenbus_driver(dev->driver);
		if (drv && drv->uevent)
			return drv->uevent(xdev, envp, num_envp, buffer,
					   buffer_size);
	}

	return 0;
}
#endif /* CONFIG_XEN */

static void otherend_changed(struct xenbus_watch *watch,
			     const char **vec, unsigned int len)
{
	struct xenbus_device *dev =
		container_of(watch, struct xenbus_device, otherend_watch);
	struct xenbus_driver *drv = to_xenbus_driver(dev->dev.driver);
	enum xenbus_state state;

	/* Protect us against watches firing on old details when the otherend
	   details change, say immediately after a resume. */
	if (!dev->otherend ||
	    strncmp(dev->otherend, vec[XS_WATCH_PATH],
		    strlen(dev->otherend))) {
		DPRINTK("Ignoring watch at %s", vec[XS_WATCH_PATH]);
		return;
	}

	state = xenbus_read_driver_state(dev->otherend);

	DPRINTK("state is %d (%s), %s, %s", state, xenbus_strstate(state),
		dev->otherend_watch.node, vec[XS_WATCH_PATH]);

	/*
	 * Ignore xenbus transitions during shutdown. This prevents us doing
	 * work that can fail e.g., when the rootfs is gone.
	 */
	if (system_state > SYSTEM_RUNNING) {
		struct xen_bus_type *bus = bus;
		bus = container_of(dev->dev.bus, struct xen_bus_type, bus);
		/* If we're frontend, drive the state machine to Closed. */
		/* This should cause the backend to release our resources. */
		if ((bus == &xenbus_frontend) && (state == XenbusStateClosing))
			xenbus_frontend_closed(dev);
		return;
	}

	if (drv->otherend_changed)
		drv->otherend_changed(dev, state);
}


static int talk_to_otherend(struct xenbus_device *dev)
{
	struct xenbus_driver *drv = to_xenbus_driver(dev->dev.driver);

	free_otherend_watch(dev);
	free_otherend_details(dev);

	return drv->read_otherend_details(dev);
}


static int watch_otherend(struct xenbus_device *dev)
{
	return xenbus_watch_path2(dev, dev->otherend, "state",
				  &dev->otherend_watch, otherend_changed);
}


static int xenbus_dev_probe(struct device *_dev)
{
	struct xenbus_device *dev = to_xenbus_device(_dev);
	struct xenbus_driver *drv = to_xenbus_driver(_dev->driver);
	const struct xenbus_device_id *id;
	int err;

	DPRINTK("%s", dev->nodename);

	if (!drv->probe) {
		err = -ENODEV;
		goto fail;
	}

	id = match_device(drv->ids, dev);
	if (!id) {
		err = -ENODEV;
		goto fail;
	}

	err = talk_to_otherend(dev);
	if (err) {
		printk(KERN_WARNING
		       "xenbus_probe: talk_to_otherend on %s failed.\n",
		       dev->nodename);
		return err;
	}

	err = drv->probe(dev, id);
	if (err)
		goto fail;

	err = watch_otherend(dev);
	if (err) {
		printk(KERN_WARNING
		       "xenbus_probe: watch_otherend on %s failed.\n",
		       dev->nodename);
		return err;
	}

	return 0;
fail:
	xenbus_dev_error(dev, err, "xenbus_dev_probe on %s", dev->nodename);
	xenbus_switch_state(dev, XenbusStateClosed);
	return -ENODEV;
}

static int xenbus_dev_remove(struct device *_dev)
{
	struct xenbus_device *dev = to_xenbus_device(_dev);
	struct xenbus_driver *drv = to_xenbus_driver(_dev->driver);

	DPRINTK("%s", dev->nodename);

	free_otherend_watch(dev);
	free_otherend_details(dev);

	if (drv->remove)
		drv->remove(dev);

	xenbus_switch_state(dev, XenbusStateClosed);
	return 0;
}

#ifdef CONFIG_XEN_PV_ON_HVM
static void xenbus_dev_shutdown(struct device *_dev)
{
	struct xenbus_device *dev = to_xenbus_device(_dev);
	unsigned long timeout = 5*HZ;

	DPRINTK("%s", dev->nodename);

	get_device(&dev->dev);
	if (dev->state != XenbusStateConnected) {
		printk("%s: %s: %s != Connected, skipping\n", __FUNCTION__,
		       dev->nodename, xenbus_strstate(dev->state));
		goto out;
	}
	xenbus_switch_state(dev, XenbusStateClosing);
	timeout = wait_for_completion_timeout(&dev->down, timeout);
	if (!timeout)
		printk("%s: %s timeout closing device\n", __FUNCTION__, dev->nodename);
 out:
	put_device(&dev->dev);
}
#endif /* XEN_PV_ON_HVM */

static int xenbus_register_driver_common(struct xenbus_driver *drv,
					 struct xen_bus_type *bus)
{
	int ret;

	if (bus->error)
		return bus->error;

	drv->driver.name = drv->name;
	drv->driver.bus = &bus->bus;
	drv->driver.probe = xenbus_dev_probe;
	drv->driver.remove = xenbus_dev_remove;
#ifdef CONFIG_XEN_PV_ON_HVM
	drv->driver.shutdown = xenbus_dev_shutdown;
#endif
	down(&xenwatch_mutex);
	ret = driver_register(&drv->driver);
	up(&xenwatch_mutex);
	return ret;
}

int xenbus_register_frontend(struct xenbus_driver *drv)
{
	int ret;

	drv->read_otherend_details = read_backend_details;

	ret = xenbus_register_driver_common(drv, &xenbus_frontend);
	if (ret)
		return ret;

	/* If this driver is loaded as a module wait for devices to attach. */
	wait_for_devices(drv);

	return 0;
}
EXPORT_SYMBOL_GPL(xenbus_register_frontend);

#ifdef CONFIG_XEN
int xenbus_register_backend(struct xenbus_driver *drv)
{
	drv->read_otherend_details = read_frontend_details;

	return xenbus_register_driver_common(drv, &xenbus_backend);
}
EXPORT_SYMBOL_GPL(xenbus_register_backend);
#endif

void xenbus_unregister_driver(struct xenbus_driver *drv)
{
	driver_unregister(&drv->driver);
}
EXPORT_SYMBOL_GPL(xenbus_unregister_driver);

struct xb_find_info
{
	struct xenbus_device *dev;
	const char *nodename;
};

static int cmp_dev(struct device *dev, void *data)
{
	struct xenbus_device *xendev = to_xenbus_device(dev);
	struct xb_find_info *info = data;

	if (!strcmp(xendev->nodename, info->nodename)) {
		info->dev = xendev;
		get_device(dev);
		return 1;
	}
	return 0;
}

struct xenbus_device *xenbus_device_find(const char *nodename,
					 struct bus_type *bus)
{
	struct xb_find_info info = { .dev = NULL, .nodename = nodename };

	bus_for_each_dev(bus, NULL, &info, cmp_dev);
	return info.dev;
}

static int cleanup_dev(struct device *dev, void *data)
{
	struct xenbus_device *xendev = to_xenbus_device(dev);
	struct xb_find_info *info = data;
	int len = strlen(info->nodename);

	DPRINTK("%s", info->nodename);

	/* Match the info->nodename path, or any subdirectory of that path. */
	if (strncmp(xendev->nodename, info->nodename, len))
		return 0;

	/* If the node name is longer, ensure it really is a subdirectory. */
	if ((strlen(xendev->nodename) > len) && (xendev->nodename[len] != '/'))
		return 0;

	info->dev = xendev;
	get_device(dev);
	return 1;
}

static void xenbus_cleanup_devices(const char *path, struct bus_type *bus)
{
	struct xb_find_info info = { .nodename = path };

	do {
		info.dev = NULL;
		bus_for_each_dev(bus, NULL, &info, cleanup_dev);
		if (info.dev) {
			device_unregister(&info.dev->dev);
			put_device(&info.dev->dev);
		}
	} while (info.dev);
}

static void xenbus_dev_release(struct device *dev)
{
	if (dev)
		kfree(to_xenbus_device(dev));
}

/* Simplified asprintf. */
char *kasprintf(gfp_t gfp, const char *fmt, ...)
{
	va_list ap;
	unsigned int len;
	char *p, dummy[1];

	va_start(ap, fmt);
	len = vsnprintf(dummy, 0, fmt, ap);
	va_end(ap);

	p = kmalloc(len + 1, gfp);
	if (!p)
		return NULL;
	va_start(ap, fmt);
	vsprintf(p, fmt, ap);
	va_end(ap);
	return p;
}

static ssize_t xendev_show_nodename(struct device *dev, char *buf)
{
	return sprintf(buf, "%s\n", to_xenbus_device(dev)->nodename);
}
DEVICE_ATTR(nodename, S_IRUSR | S_IRGRP | S_IROTH, xendev_show_nodename, NULL);

static ssize_t xendev_show_devtype(struct device *dev, char *buf)
{
	return sprintf(buf, "%s\n", to_xenbus_device(dev)->devicetype);
}
DEVICE_ATTR(devtype, S_IRUSR | S_IRGRP | S_IROTH, xendev_show_devtype, NULL);


static int xenbus_probe_node(struct xen_bus_type *bus,
			     const char *type,
			     const char *nodename)
{
	int err;
	struct xenbus_device *xendev;
	size_t stringlen;
	char *tmpstring;

	enum xenbus_state state = xenbus_read_driver_state(nodename);

	if (bus->error)
		return bus->error;

	if (state != XenbusStateInitialising) {
		/* Device is not new, so ignore it.  This can happen if a
		   device is going away after switching to Closed.  */
		return 0;
	}

	stringlen = strlen(nodename) + 1 + strlen(type) + 1;
	xendev = kzalloc(sizeof(*xendev) + stringlen, GFP_KERNEL);
	if (!xendev)
		return -ENOMEM;

	xendev->state = XenbusStateInitialising;

	/* Copy the strings into the extra space. */

	tmpstring = (char *)(xendev + 1);
	strcpy(tmpstring, nodename);
	xendev->nodename = tmpstring;

	tmpstring += strlen(tmpstring) + 1;
	strcpy(tmpstring, type);
	xendev->devicetype = tmpstring;
	init_completion(&xendev->down);

	xendev->dev.parent = &bus->dev;
	xendev->dev.bus = &bus->bus;
	xendev->dev.release = xenbus_dev_release;

	err = bus->get_bus_id(xendev->dev.bus_id, xendev->nodename);
	if (err)
		goto fail;

	/* Register with generic device framework. */
	err = device_register(&xendev->dev);
	if (err)
		goto fail;

	err = device_create_file(&xendev->dev, &dev_attr_nodename);
	if (err)
		goto unregister;
	err = device_create_file(&xendev->dev, &dev_attr_devtype);
	if (err)
		goto unregister;

	return 0;
unregister:
	device_remove_file(&xendev->dev, &dev_attr_nodename);
	device_remove_file(&xendev->dev, &dev_attr_devtype);
	device_unregister(&xendev->dev);
fail:
	kfree(xendev);
	return err;
}

/* device/<typename>/<name> */
static int xenbus_probe_frontend(const char *type, const char *name)
{
	char *nodename;
	int err;

	nodename = kasprintf(GFP_KERNEL, "%s/%s/%s", xenbus_frontend.root, type, name);
	if (!nodename)
		return -ENOMEM;

	DPRINTK("%s", nodename);

	err = xenbus_probe_node(&xenbus_frontend, type, nodename);
	kfree(nodename);
	return err;
}

#ifdef CONFIG_XEN
/* backend/<typename>/<frontend-uuid>/<name> */
static int xenbus_probe_backend_unit(const char *dir,
				     const char *type,
				     const char *name)
{
	char *nodename;
	int err;

	nodename = kasprintf(GFP_KERNEL, "%s/%s", dir, name);
	if (!nodename)
		return -ENOMEM;

	DPRINTK("%s\n", nodename);

	err = xenbus_probe_node(&xenbus_backend, type, nodename);
	kfree(nodename);
	return err;
}

/* backend/<typename>/<frontend-domid> */
static int xenbus_probe_backend(const char *type, const char *domid)
{
	char *nodename;
	int err = 0;
	char **dir;
	unsigned int i, dir_n = 0;

	DPRINTK("");

	nodename = kasprintf(GFP_KERNEL, "%s/%s/%s", xenbus_backend.root, type, domid);
	if (!nodename)
		return -ENOMEM;

	dir = xenbus_directory(XBT_NIL, nodename, "", &dir_n);
	if (IS_ERR(dir)) {
		kfree(nodename);
		return PTR_ERR(dir);
	}

	for (i = 0; i < dir_n; i++) {
		err = xenbus_probe_backend_unit(nodename, type, dir[i]);
		if (err)
			break;
	}
	kfree(dir);
	kfree(nodename);
	return err;
}
#endif /* CONFIG_XEN */

static int xenbus_probe_device_type(struct xen_bus_type *bus, const char *type)
{
	int err = 0;
	char **dir;
	unsigned int dir_n = 0;
	int i;

	dir = xenbus_directory(XBT_NIL, bus->root, type, &dir_n);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	for (i = 0; i < dir_n; i++) {
		err = bus->probe(type, dir[i]);
		if (err)
			break;
	}
	kfree(dir);
	return err;
}

static int xenbus_probe_devices(struct xen_bus_type *bus)
{
	int err = 0;
	char **dir;
	unsigned int i, dir_n;

	if (bus->error)
		return bus->error;

	dir = xenbus_directory(XBT_NIL, bus->root, "", &dir_n);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	for (i = 0; i < dir_n; i++) {
		err = xenbus_probe_device_type(bus, dir[i]);
		if (err)
			break;
	}
	kfree(dir);
	return err;
}

static unsigned int char_count(const char *str, char c)
{
	unsigned int i, ret = 0;

	for (i = 0; str[i]; i++)
		if (str[i] == c)
			ret++;
	return ret;
}

static int strsep_len(const char *str, char c, unsigned int len)
{
	unsigned int i;

	for (i = 0; str[i]; i++)
		if (str[i] == c) {
			if (len == 0)
				return i;
			len--;
		}
	return (len == 0) ? i : -ERANGE;
}

static void dev_changed(const char *node, struct xen_bus_type *bus)
{
	int exists, rootlen;
	struct xenbus_device *dev;
	char type[BUS_ID_SIZE];
	const char *p, *root;

	if (bus->error || char_count(node, '/') < 2)
 		return;

	exists = xenbus_exists(XBT_NIL, node, "");
	if (!exists) {
		xenbus_cleanup_devices(node, &bus->bus);
		return;
	}

	/* backend/<type>/... or device/<type>/... */
	p = strchr(node, '/') + 1;
	snprintf(type, BUS_ID_SIZE, "%.*s", (int)strcspn(p, "/"), p);
	type[BUS_ID_SIZE-1] = '\0';

	rootlen = strsep_len(node, '/', bus->levels);
	if (rootlen < 0)
		return;
	root = kasprintf(GFP_KERNEL, "%.*s", rootlen, node);
	if (!root)
		return;

	dev = xenbus_device_find(root, &bus->bus);
	if (!dev)
		xenbus_probe_node(bus, type, root);
	else
		put_device(&dev->dev);

	kfree(root);
}

static void frontend_changed(struct xenbus_watch *watch,
			     const char **vec, unsigned int len)
{
	DPRINTK("");

	dev_changed(vec[XS_WATCH_PATH], &xenbus_frontend);
}

#ifdef CONFIG_XEN
static void backend_changed(struct xenbus_watch *watch,
			    const char **vec, unsigned int len)
{
	DPRINTK("");

	dev_changed(vec[XS_WATCH_PATH], &xenbus_backend);
}

static struct xenbus_watch be_watch = {
	.node = "backend",
	.callback = backend_changed,
};
#endif

/* We watch for devices appearing and vanishing. */
static struct xenbus_watch fe_watch = {
	.node = "device",
	.callback = frontend_changed,
};

static int suspend_dev(struct device *dev, void *data)
{
	int err = 0;
	struct xenbus_driver *drv;
	struct xenbus_device *xdev;

	DPRINTK("");

	if (dev->driver == NULL)
		return 0;
	drv = to_xenbus_driver(dev->driver);
	xdev = container_of(dev, struct xenbus_device, dev);
	if (drv->suspend)
		err = drv->suspend(xdev);
	if (err)
		printk(KERN_WARNING
		       "xenbus: suspend %s failed: %i\n", dev->bus_id, err);
	return 0;
}

#ifdef CONFIG_XEN_PV_ON_HVM
static int suspend_cancel_dev(struct device *dev, void *data)
{
	int err = 0;
	struct xenbus_driver *drv;
	struct xenbus_device *xdev;

	DPRINTK("");

	if (dev->driver == NULL)
		return 0;
	drv = to_xenbus_driver(dev->driver);
	xdev = container_of(dev, struct xenbus_device, dev);
	if (drv->suspend_cancel)
		err = drv->suspend_cancel(xdev);
	if (err)
		printk(KERN_WARNING
		       "xenbus: suspend_cancel %s failed: %i\n",
		       dev->bus_id, err);
	return 0;
}
#endif /* CONFIG_XEN_PV_ON_HVM */

static int resume_dev(struct device *dev, void *data)
{
	int err;
	struct xenbus_driver *drv;
	struct xenbus_device *xdev;

	DPRINTK("");

	if (dev->driver == NULL)
		return 0;

	drv = to_xenbus_driver(dev->driver);
	xdev = container_of(dev, struct xenbus_device, dev);

	err = talk_to_otherend(xdev);
	if (err) {
		printk(KERN_WARNING
		       "xenbus: resume (talk_to_otherend) %s failed: %i\n",
		       dev->bus_id, err);
		return err;
	}

	xdev->state = XenbusStateInitialising;

	if (drv->resume) {
		err = drv->resume(xdev);
		if (err) { 
			printk(KERN_WARNING
			       "xenbus: resume %s failed: %i\n", 
			       dev->bus_id, err);
			return err;
		}
	}

	err = watch_otherend(xdev);
	if (err) {
		printk(KERN_WARNING
		       "xenbus_probe: resume (watch_otherend) %s failed: "
		       "%d.\n", dev->bus_id, err);
		return err;
	}

	return 0;
}

void xenbus_suspend(void)
{
	DPRINTK("");

        if (!xenbus_frontend.error)
		bus_for_each_dev(&xenbus_frontend.bus, NULL, NULL, suspend_dev);
#ifdef CONFIG_XEN
	bus_for_each_dev(&xenbus_backend.bus, NULL, NULL, suspend_dev);
#endif
	xs_suspend();
}
EXPORT_SYMBOL_GPL(xenbus_suspend);

void xenbus_resume(void)
{
	xb_init_comms();
	xs_resume();
        if (!xenbus_frontend.error)
		bus_for_each_dev(&xenbus_frontend.bus, NULL, NULL, resume_dev);
#ifdef CONFIG_XEN
	bus_for_each_dev(&xenbus_backend.bus, NULL, NULL, resume_dev);
#endif
}
EXPORT_SYMBOL_GPL(xenbus_resume);

#ifdef CONFIG_XEN_PV_ON_HVM
void xenbus_suspend_cancel(void)
{
	xs_suspend_cancel();
	if (!xenbus_frontend.error)
		bus_for_each_dev(&xenbus_frontend.bus, NULL, NULL, suspend_cancel_dev);
#if 0 /* does nothing for frontend drivers */
	xenbus_backend_resume(suspend_cancel_dev);
#endif 
}
EXPORT_SYMBOL_GPL(xenbus_suspend_cancel);
#endif /* CONFIG_XEN_PV_ON_HVM */

/* A flag to determine if xenstored is 'ready' (i.e. has started) */
int xenstored_ready = 0;


int register_xenstore_notifier(struct notifier_block *nb)
{
	int ret = 0;

	if (xenstored_ready > 0)
		ret = nb->notifier_call(nb, 0, NULL);
	else
		notifier_chain_register(&xenstore_chain, nb);

	return ret;
}
EXPORT_SYMBOL_GPL(register_xenstore_notifier);

void unregister_xenstore_notifier(struct notifier_block *nb)
{
	notifier_chain_unregister(&xenstore_chain, nb);
}
EXPORT_SYMBOL_GPL(unregister_xenstore_notifier);


static int all_devices_ready_(struct device *dev, void *data)
{
	struct xenbus_device *xendev = to_xenbus_device(dev);
	int *result = data;

	if (xendev->state != XenbusStateConnected) {
		result = 0;
		return 1;
	}

	return 0;
}


static int all_devices_ready(void)
{
	int ready = 1;
	bus_for_each_dev(&xenbus_frontend.bus, NULL, &ready,
			 all_devices_ready_);
	return ready;
}


void xenbus_probe(void *unused)
{
	int i;

	BUG_ON((xenstored_ready <= 0));

	/* Enumerate devices in xenstore. */
	xenbus_probe_devices(&xenbus_frontend);
#ifdef CONFIG_XEN
	xenbus_probe_devices(&xenbus_backend);
#endif
	/* Watch for changes. */
	register_xenbus_watch(&fe_watch);
#ifdef CONFIG_XEN
	register_xenbus_watch(&be_watch);
#endif

	/* Notify others that xenstore is up */
	notifier_call_chain(&xenstore_chain, 0, NULL);

	/* On a 10 second timeout, waiting for all devices currently
	   configured.  We need to do this to guarantee that the filesystems
	   and / or network devices needed for boot are available, before we
	   can allow the boot to proceed.

	   A possible improvement here would be to have the tools add a
	   per-device flag to the store entry, indicating whether it is needed
	   at boot time.  This would allow people who knew what they were
	   doing to accelerate their boot slightly, but of course needs tools
	   or manual intervention to set up those flags correctly.
	 */
	for (i = 0; i < 10 * HZ; i++) {
		if (all_devices_ready())
			return;

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(1);
	}

	printk(KERN_WARNING
	       "XENBUS: Timeout connecting to devices!\n");
}

#if defined(CONFIG_PROC_FS) && defined(CONFIG_XEN_PRIVILEGED_GUEST)
static struct file_operations xsd_kva_fops;
static struct proc_dir_entry *xsd_kva_intf;
static struct proc_dir_entry *xsd_port_intf;

static int xsd_kva_mmap(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;

	if ((size > PAGE_SIZE) || (vma->vm_pgoff != 0))
		return -EINVAL;

	if (remap_page_range(vma, vma->vm_start, 
			     mfn_to_pfn(xen_start_info->store_mfn),
			     size, vma->vm_page_prot))
		return -EAGAIN;

	return 0;
}

static int xsd_kva_read(char *page, char **start, off_t off,
			int count, int *eof, void *data)
{
	int len;

	len  = sprintf(page, "0x%p", mfn_to_virt(xen_start_info->store_mfn));
	*eof = 1;
	return len;
}

static int xsd_port_read(char *page, char **start, off_t off,
			 int count, int *eof, void *data)
{
	int len;

	len  = sprintf(page, "%d", xen_start_info->store_evtchn);
	*eof = 1;
	return len;
}
#endif /* CONFIG_PROC_FS && CONFIG_XEN_PRIVILEGED_GUEST */

static int __init xenbus_probe_init(void)
{
	int err = 0;
	unsigned long page = 0L;

	DPRINTK("");

	if (xen_init() < 0) {
		DPRINTK("failed");
		return -ENODEV;
	}

	/* Register ourselves with the kernel bus & device subsystems */
        xenbus_frontend.error = bus_register(&xenbus_frontend.bus);
        if (xenbus_frontend.error)
                printk(KERN_WARNING
                       "XENBUS: Error registering frontend bus: %i\n",
                       xenbus_frontend.error);
#ifdef CONFIG_XEN
	bus_register(&xenbus_backend.bus);
#endif

	if (is_initial_xendomain()) {
		struct evtchn_alloc_unbound alloc_unbound;

		/* Allocate page. */
		page = get_zeroed_page(GFP_KERNEL);
		if (!page)
			return -ENOMEM;

		xen_start_info->store_mfn =
			pfn_to_mfn(virt_to_phys((void *)page) >>
				   PAGE_SHIFT);
		xen_store_mfn = xen_start_info->store_mfn ;

		/* Next allocate a local port which xenstored can bind to */
		alloc_unbound.dom        = DOMID_SELF;
		alloc_unbound.remote_dom = 0;

		err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound,
						  &alloc_unbound);
		if (err == -ENOSYS)
			goto err;
		BUG_ON(err);
		xen_store_evtchn = xen_start_info->store_evtchn =
			alloc_unbound.port;

#if defined(CONFIG_PROC_FS) && defined(CONFIG_XEN_PRIVILEGED_GUEST)
		/* And finally publish the above info in /proc/xen */
		xsd_kva_intf = create_xen_proc_entry("xsd_kva", 0600);
		if (xsd_kva_intf) {
			memcpy(&xsd_kva_fops, xsd_kva_intf->proc_fops,
			       sizeof(xsd_kva_fops));
			xsd_kva_fops.mmap = xsd_kva_mmap;
			xsd_kva_intf->proc_fops = &xsd_kva_fops;
			xsd_kva_intf->read_proc = xsd_kva_read;
		}
		xsd_port_intf = create_xen_proc_entry("xsd_port", 0400);
		if (xsd_port_intf)
			xsd_port_intf->read_proc = xsd_port_read;
#endif
		xen_store_interface = mfn_to_virt(xen_store_mfn);
	} else {
		xenstored_ready = 1;
#ifdef CONFIG_XEN
		xen_store_evtchn = xen_start_info->store_evtchn;
		xen_store_mfn = xen_start_info->store_mfn;
		xen_store_interface = mfn_to_virt(xen_store_mfn);
#else
		xen_store_evtchn = hvm_get_parameter(HVM_PARAM_STORE_EVTCHN);
		xen_store_mfn = hvm_get_parameter(HVM_PARAM_STORE_PFN);
		xen_store_interface = ioremap(xen_store_mfn << PAGE_SHIFT,
					      PAGE_SIZE);
#endif
	}


#if defined(CONFIG_PROC_FS) && defined(CONFIG_XEN)
	xenbus_dev_init();
#endif

	/* Initialize the interface to xenstore. */
	err = xs_init();
	if (err) {
		printk(KERN_WARNING
		       "XENBUS: Error initializing xenstore comms: %i\n", err);
		goto err;
	}

	if (!xenbus_frontend.error) {
		xenbus_frontend.error = device_register(&xenbus_frontend.dev);
		if (xenbus_frontend.error) {
			bus_unregister(&xenbus_frontend.bus);
			printk(KERN_WARNING
			       "XENBUS: Error registering frontend device: %i\n",
			       xenbus_frontend.error);
		}
	}
#ifdef CONFIG_XEN
	device_register(&xenbus_backend.dev);
#endif

	if (!is_initial_xendomain())
		xenbus_probe(NULL);

	return 0;

err:
	if (page)
		free_page(page);

	/*
	 * Do not unregister the xenbus front/backend buses here. The buses
	 * must exist because front/backend drivers will use them when they are
	 * registered.
	 */

	return err;
}

#ifdef CONFIG_XEN
postcore_initcall(xenbus_probe_init);

MODULE_LICENSE("Dual BSD/GPL");
#else
int xenbus_init(void)
{
	return xenbus_probe_init();
}
#endif

static int is_disconnected_device(struct device *dev, void *data)
{
	struct xenbus_device *xendev = to_xenbus_device(dev);
	struct device_driver *drv = data;
	struct xenbus_driver *xendrv;

	/*
	 * A device with no driver will never connect. We care only about
	 * devices which should currently be in the process of connecting.
	 */
	if (!dev->driver)
		return 0;

	/* Is this search limited to a particular driver? */
	if (drv && (dev->driver != drv))
		return 0;

	xendrv = to_xenbus_driver(dev->driver);
	return (xendev->state != XenbusStateConnected ||
		(xendrv->is_ready && !xendrv->is_ready(xendev)));
}

static int exists_disconnected_device(struct device_driver *drv)
{
        if (xenbus_frontend.error)
                return xenbus_frontend.error;
	return bus_for_each_dev(&xenbus_frontend.bus, NULL, drv,
				is_disconnected_device);
}

static int print_device_status(struct device *dev, void *data)
{
	struct xenbus_device *xendev = to_xenbus_device(dev);
	struct device_driver *drv = data;

	/* Is this operation limited to a particular driver? */
	if (drv && (dev->driver != drv))
		return 0;

	if (!dev->driver) {
		/* Information only: is this too noisy? */
		printk(KERN_INFO "XENBUS: Device with no driver: %s\n",
		       xendev->nodename);
	} else if (xendev->state != XenbusStateConnected) {
		printk(KERN_WARNING "XENBUS: Timeout connecting "
		       "to device: %s (state %d)\n",
		       xendev->nodename, xendev->state);
	}

	return 0;
}

/* We only wait for device setup after most initcalls have run. */
static int ready_to_wait_for_devices;

/*
 * On a 10 second timeout, wait for all devices currently configured.  We need
 * to do this to guarantee that the filesystems and / or network devices
 * needed for boot are available, before we can allow the boot to proceed.
 *
 * This needs to be on a late_initcall, to happen after the frontend device
 * drivers have been initialised, but before the root fs is mounted.
 *
 * A possible improvement here would be to have the tools add a per-device
 * flag to the store entry, indicating whether it is needed at boot time.
 * This would allow people who knew what they were doing to accelerate their
 * boot slightly, but of course needs tools or manual intervention to set up
 * those flags correctly.
 */
static void wait_for_devices(struct xenbus_driver *xendrv)
{
	unsigned long timeout = jiffies + 10*HZ;
	struct device_driver *drv = xendrv ? &xendrv->driver : NULL;

	if (!ready_to_wait_for_devices || !is_running_on_xen())
		return;

	while (exists_disconnected_device(drv)) {
		if (time_after(jiffies, timeout))
			break;
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ/10);
	}

	bus_for_each_dev(&xenbus_frontend.bus, NULL, drv,
			 print_device_status);
}

#ifndef MODULE
static int __init boot_wait_for_devices(void)
{
	if (!xenbus_frontend.error) {
		ready_to_wait_for_devices = 1;
		wait_for_devices(NULL);
	}
	return 0;
}

late_initcall(boot_wait_for_devices);
#endif

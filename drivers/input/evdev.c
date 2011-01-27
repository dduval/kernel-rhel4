/*
 * Event char devices, giving access to raw input device events.
 *
 * Copyright (c) 1999-2002 Vojtech Pavlik
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#define EVDEV_MINOR_BASE	64
#define EVDEV_MINORS		32
#define EVDEV_BUFFER_SIZE	64

#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/major.h>
#include <linux/smp_lock.h>
#include <linux/device.h>
#include <linux/devfs_fs_kernel.h>
#include <linux/mutex.h>

DECLARE_MUTEX(evdev_mutex);

struct evdev {
/* evdev->exist is used to signalize that a device got disconnected.

   If the device is not disconnected, read/write ops to the real device
   can't happen. So, in principle, those operations should be locked.

   In fact, evdev_read() and evdev_poll() doesn't have any lock.
   A memory barrier on those functions doesn't work, since part of the
   proccessing happens inside of a workqueue.

   What happens is that the real read happens elsewhere. evdev_read() just
   copies a kernel buffer at the userspace one. This works even if the
   device got removed.

   Also, since evdev is freed only after all closes, it will still exist in
   evdev_read() and evdev_poll(), so it is ok to access those data info
   without a memory barrier.
 */
	int exist;
	int open;
	int minor;
	char name[16];
	struct input_handle handle;
	wait_queue_head_t wait;
	struct evdev_client *grab;
	struct list_head client_list;
	spinlock_t client_lock; /* protects client_list */
	struct kref kref;
};

struct evdev_client {
	struct input_event buffer[EVDEV_BUFFER_SIZE];
	int head;
	int tail;
	spinlock_t buffer_lock; /* protects access to buffer, head and tail */
	struct fasync_struct *fasync;
	struct evdev *evdev;
	struct list_head node;
};

static struct evdev *evdev_table[EVDEV_MINORS];

static void evdev_pass_event(struct evdev_client *client,
			     struct input_event *event)
{
	/*
	 * Interrupts are disabled, just acquire the lock
	 */
	spin_lock(&client->buffer_lock);
	client->buffer[client->head++] = *event;
	client->head &= EVDEV_BUFFER_SIZE - 1;
	spin_unlock(&client->buffer_lock);

	kill_fasync(&client->fasync, SIGIO, POLL_IN);
}

/*
 * Pass incoming event to all connected clients.
 */
static void evdev_event(struct input_handle *handle,
			unsigned int type, unsigned int code, int value)
{
	struct evdev *evdev = handle->private;
	struct evdev_client *client;
	struct input_event event;

	do_gettimeofday(&event.time);
	event.type = type;
	event.code = code;
	event.value = value;

	rcu_read_lock();

	client = rcu_dereference(evdev->grab);
	if (client)
		evdev_pass_event(client, &event);
	else
		list_for_each_entry_rcu(client, &evdev->client_list, node)
			evdev_pass_event(client, &event);

	rcu_read_unlock();

	wake_up_interruptible(&evdev->wait);
}

static int evdev_fasync(int fd, struct file *file, int on)
{
	struct evdev_client *client = file->private_data;
	int retval;

	retval = fasync_helper(fd, file, on, &client->fasync);

	return retval < 0 ? retval : 0;
}

static int evdev_flush(struct file * file)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev;
	int retval;

	if (!client)
		return -ENODEV;

	evdev = client->evdev;

	retval = mutex_lock_interruptible(&evdev_mutex);
	if (retval)
		return retval;

	if (!evdev->exist)
		retval = -ENODEV;
	else
		retval = input_flush_device(&evdev->handle, file);

	mutex_unlock(&evdev_mutex);
	return retval;
}

static void evdev_free(struct kref *kref)
{
	struct evdev *evdev;

	evdev = container_of(kref, struct evdev, kref);

	devfs_remove("input/event%d", evdev->minor);
	class_simple_device_remove(MKDEV(INPUT_MAJOR, EVDEV_MINOR_BASE + evdev->minor));
	kfree(evdev);
}

/*
 * Grabs an event device (along with underlying input device).
 * This function is called with evdev_mutex taken.
 */
static int evdev_grab(struct evdev *evdev, struct evdev_client *client)
{
	int error;

	if (evdev->grab)
		return -EBUSY;

	error = input_grab_device(&evdev->handle);
	if (error)
		return error;

	rcu_assign_pointer(evdev->grab, client);
	synchronize_kernel();

	return 0;
}

static int evdev_ungrab(struct evdev *evdev, struct evdev_client *client)
{
	if (evdev->grab != client)
		return  -EINVAL;

	rcu_assign_pointer(evdev->grab, NULL);
	synchronize_kernel();
	input_release_device(&evdev->handle);

	return 0;
}

static void evdev_attach_client(struct evdev *evdev,
				struct evdev_client *client)
{
	spin_lock(&evdev->client_lock);
	list_add_tail_rcu(&client->node, &evdev->client_list);
	spin_unlock(&evdev->client_lock);
	synchronize_kernel();
}

static void evdev_detach_client(struct evdev *evdev,
				struct evdev_client *client)
{
	spin_lock(&evdev->client_lock);
	list_del_rcu(&client->node);
	spin_unlock(&evdev->client_lock);
	synchronize_kernel();
}

static int evdev_open_device(struct evdev *evdev)
{
	int retval = 0;

	if (!evdev->open++) {
		retval = input_open_device(&evdev->handle);
		if (retval)
			evdev->open--;
	}

	return retval;
}

static void evdev_close_device(struct evdev *evdev)
{
	mutex_lock(&evdev_mutex);

	if (evdev->exist && !--evdev->open)
		input_close_device(&evdev->handle);

	mutex_unlock(&evdev_mutex);
}

/*
 * Wake up users waiting for IO so they can disconnect from
 * dead device.
 */
static void evdev_hangup(struct evdev *evdev)
{
	struct evdev_client *client;

	spin_lock(&evdev->client_lock);
	list_for_each_entry(client, &evdev->client_list, node)
		kill_fasync(&client->fasync, SIGIO, POLL_HUP);
	spin_unlock(&evdev->client_lock);

	wake_up_interruptible(&evdev->wait);
}

static int evdev_release(struct inode *inode, struct file *file)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;

	mutex_lock(&evdev_mutex);
	if (evdev->grab == client)
		evdev_ungrab(evdev, client);
	mutex_unlock(&evdev_mutex);

	evdev_fasync(-1, file, 0);
	evdev_detach_client(evdev, client);
	kfree(client);

	evdev_close_device(evdev);

	mutex_lock(&evdev_mutex);
	kref_put(&evdev->kref, evdev_free);
	mutex_unlock(&evdev_mutex);

	file->private_data = NULL;

	return 0;
}

static int evdev_open(struct inode *inode, struct file *file)
{
	struct evdev *evdev;
	struct evdev_client *client;
	int i = iminor(inode) - EVDEV_MINOR_BASE;
	int error;

	if (i >= EVDEV_MINORS)
		return -ENODEV;

	error = mutex_lock_interruptible(&evdev_mutex);
	if (error)
		return error;
	evdev = evdev_table[i];

	if (!evdev || !evdev->exist) {
		error = -ENODEV;
		goto err_unlock;
	}
	kref_get(&evdev->kref);

	if ((error = input_accept_process(&(evdev_table[i]->handle), file)))
		goto err_kref_put;

	client = kmalloc(sizeof(struct evdev_client), GFP_KERNEL);
	if (!client) {
		error = -ENOMEM;
		goto err_kref_put;
	}
	memset(client, 0, sizeof(struct evdev_client));

	spin_lock_init(&client->buffer_lock);
	client->evdev = evdev;
	evdev_attach_client(evdev, client);

	error = evdev_open_device(evdev);
	if (error)
		goto err_free_client;

	mutex_unlock(&evdev_mutex);

	file->private_data = client;
	return 0;

err_free_client:
	evdev_detach_client(evdev, client);
	kfree(client);

err_kref_put:
	kref_put(&evdev->kref, evdev_free);

err_unlock:
	mutex_unlock(&evdev_mutex);
	return error;
}

static int evdev_event_from_user(const char __user *buffer,
				 struct input_event *event)
{
	if (copy_from_user(event, buffer, sizeof(struct input_event)))
		return -EFAULT;

	return 0;
}

static int evdev_event_to_user(char __user *buffer,
				const struct input_event *event)
{
	if (copy_to_user(buffer, event, sizeof(struct input_event)))
		return -EFAULT;

	return 0;
}

static ssize_t evdev_write(struct file * file, const char __user * buffer, size_t count, loff_t *ppos)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;
	struct input_event event;
	int retval;

	retval = mutex_lock_interruptible(&evdev_mutex);
	if (retval)
		return retval;

	if (!evdev->exist) {
		retval = -ENODEV;
		goto out;
	}

	while (retval < count) {

		if (evdev_event_from_user(buffer + retval, &event)) {
			retval = -EFAULT;
			goto out;
		}

		input_event(evdev->handle.dev,
				   event.type, event.code, event.value);
		retval += sizeof(struct input_event);
	}

 out:
	mutex_unlock(&evdev_mutex);
	return retval;
}

static int evdev_fetch_next_event(struct evdev_client *client,
				  struct input_event *event)
{
	int have_event;

	spin_lock_irq(&client->buffer_lock);

	have_event = client->head != client->tail;
	if (have_event) {
		*event = client->buffer[client->tail++];
		client->tail &= EVDEV_BUFFER_SIZE - 1;
	}

	spin_unlock_irq(&client->buffer_lock);

	return have_event;
}

static ssize_t evdev_read(struct file *file, char __user *buffer,
			  size_t count, loff_t *ppos)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;
	struct input_event event;
	int retval;

	if (count < sizeof(struct input_event))
		return -EINVAL;

	if (client->head == client->tail && evdev->exist &&
	    (file->f_flags & O_NONBLOCK))
		return -EAGAIN;

	retval = wait_event_interruptible(evdev->wait,
		client->head != client->tail || !evdev->exist);
	if (retval)
		return retval;

	if (!evdev->exist)
		return -ENODEV;

	while (retval + sizeof(struct input_event) <= count &&
	       evdev_fetch_next_event(client, &event)) {

		if (evdev_event_to_user(buffer + retval, &event))
			return -EFAULT;

		retval += sizeof(struct input_event);
	}

	return retval;
}

/* No kernel lock - fine */
static unsigned int evdev_poll(struct file *file, poll_table *wait)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;

	poll_wait(file, &evdev->wait, wait);
	return ((client->head == client->tail) ? 0 : (POLLIN | POLLRDNORM)) |
		(evdev->exist ? 0 : (POLLHUP | POLLERR));
}

static int evdev_do_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;
	struct input_dev *dev = evdev->handle.dev;
	struct input_absinfo abs;
	void __user *p = (void __user *)arg;
	int __user *ip = (int __user *)arg;
	int i, t, u, v;

	switch (cmd) {

	case EVIOCGVERSION:
		return put_user(EV_VERSION, ip);

	case EVIOCGID:
		return copy_to_user(p, &dev->id, sizeof(struct input_id)) ? -EFAULT : 0;

	case EVIOCGKEYCODE:
		if (get_user(t, ip)) return -EFAULT;
		if (t < 0 || t > dev->keycodemax || !dev->keycodesize) return -EINVAL;
		if (put_user(INPUT_KEYCODE(dev, t), ip + 1)) return -EFAULT;
		return 0;

	case EVIOCSKEYCODE:
		if (get_user(t, ip)) return -EFAULT;
		if (t < 0 || t > dev->keycodemax || !dev->keycodesize) return -EINVAL;
		if (get_user(v, ip + 1)) return -EFAULT;
		u = SET_INPUT_KEYCODE(dev, t, v);
		clear_bit(u, dev->keybit);
		set_bit(v, dev->keybit);
		for (i = 0; i < dev->keycodemax; i++)
			if (INPUT_KEYCODE(dev,i) == u)
				set_bit(u, dev->keybit);
		return 0;

	case EVIOCSFF:
		if (dev->upload_effect) {
			struct ff_effect effect;
			int err;

			if (copy_from_user(&effect, p, sizeof(effect)))
				return -EFAULT;
			err = dev->upload_effect(dev, &effect);
			if (put_user(effect.id, &(((struct ff_effect __user *)arg)->id)))
				return -EFAULT;
			return err;
		}
		else return -ENOSYS;

	case EVIOCRMFF:
		if (dev->erase_effect) {
			return dev->erase_effect(dev, (int)arg);
		}
		else return -ENOSYS;

	case EVIOCGEFFECTS:
		if (put_user(dev->ff_effects_max, ip))
			return -EFAULT;
		return 0;

	case EVIOCGRAB:
		if (arg)
			return evdev_grab(evdev, client);
		else
			return evdev_ungrab(evdev, client);

	default:

		if (_IOC_TYPE(cmd) != 'E' || _IOC_DIR(cmd) != _IOC_READ)
			return -EINVAL;

		if ((_IOC_NR(cmd) & ~EV_MAX) == _IOC_NR(EVIOCGBIT(0, 0))) {

			unsigned long *bits;
			int len;

			switch (_IOC_NR(cmd) & EV_MAX) {

				case      0: bits = dev->evbit;  len = EV_MAX;  break;
				case EV_KEY: bits = dev->keybit; len = KEY_MAX; break;
				case EV_REL: bits = dev->relbit; len = REL_MAX; break;
				case EV_ABS: bits = dev->absbit; len = ABS_MAX; break;
				case EV_MSC: bits = dev->mscbit; len = MSC_MAX; break;
				case EV_LED: bits = dev->ledbit; len = LED_MAX; break;
				case EV_SND: bits = dev->sndbit; len = SND_MAX; break;
				case EV_FF:  bits = dev->ffbit;  len = FF_MAX;  break;
				default: return -EINVAL;
			}
			len = NBITS(len) * sizeof(long);
			if (len > _IOC_SIZE(cmd)) len = _IOC_SIZE(cmd);
			return copy_to_user(p, bits, len) ? -EFAULT : len;
		}

		if (_IOC_NR(cmd) == _IOC_NR(EVIOCGKEY(0))) {
			int len;
			len = NBITS(KEY_MAX) * sizeof(long);
			if (len > _IOC_SIZE(cmd)) len = _IOC_SIZE(cmd);
			return copy_to_user(p, dev->key, len) ? -EFAULT : len;
		}

		if (_IOC_NR(cmd) == _IOC_NR(EVIOCGLED(0))) {
			int len;
			len = NBITS(LED_MAX) * sizeof(long);
			if (len > _IOC_SIZE(cmd)) len = _IOC_SIZE(cmd);
			return copy_to_user(p, dev->led, len) ? -EFAULT : len;
		}

		if (_IOC_NR(cmd) == _IOC_NR(EVIOCGSND(0))) {
			int len;
			len = NBITS(SND_MAX) * sizeof(long);
			if (len > _IOC_SIZE(cmd)) len = _IOC_SIZE(cmd);
			return copy_to_user(p, dev->snd, len) ? -EFAULT : len;
		}

		if (_IOC_NR(cmd) == _IOC_NR(EVIOCGNAME(0))) {
			int len;
			if (!dev->name) return -ENOENT;
			len = strlen(dev->name) + 1;
			if (len > _IOC_SIZE(cmd)) len = _IOC_SIZE(cmd);
			return copy_to_user(p, dev->name, len) ? -EFAULT : len;
		}

		if (_IOC_NR(cmd) == _IOC_NR(EVIOCGPHYS(0))) {
			int len;
			if (!dev->phys) return -ENOENT;
			len = strlen(dev->phys) + 1;
			if (len > _IOC_SIZE(cmd)) len = _IOC_SIZE(cmd);
			return copy_to_user(p, dev->phys, len) ? -EFAULT : len;
		}

		if (_IOC_NR(cmd) == _IOC_NR(EVIOCGUNIQ(0))) {
			int len;
			if (!dev->uniq) return -ENOENT;
			len = strlen(dev->uniq) + 1;
			if (len > _IOC_SIZE(cmd)) len = _IOC_SIZE(cmd);
			return copy_to_user(p, dev->uniq, len) ? -EFAULT : len;
		}

		if ((_IOC_NR(cmd) & ~ABS_MAX) == _IOC_NR(EVIOCGABS(0))) {

			int t = _IOC_NR(cmd) & ABS_MAX;

			abs.value = dev->abs[t];
			abs.minimum = dev->absmin[t];
			abs.maximum = dev->absmax[t];
			abs.fuzz = dev->absfuzz[t];
			abs.flat = dev->absflat[t];

			if (copy_to_user(p, &abs, sizeof(struct input_absinfo)))
				return -EFAULT;

			return 0;
		}

		if ((_IOC_NR(cmd) & ~ABS_MAX) == _IOC_NR(EVIOCSABS(0))) {

			int t = _IOC_NR(cmd) & ABS_MAX;

			if (copy_from_user(&abs, p,
					sizeof(struct input_absinfo)))
				return -EFAULT;

			dev->abs[t] = abs.value;
			dev->absmin[t] = abs.minimum;
			dev->absmax[t] = abs.maximum;
			dev->absfuzz[t] = abs.fuzz;
			dev->absflat[t] = abs.flat;

			return 0;
		}
	}
	return -EINVAL;
}

static int evdev_ioctl_handler(struct file *file, unsigned int cmd,
                               unsigned long p)
{
	struct evdev_client *client = file->private_data;
	struct evdev *evdev = client->evdev;
	int retval;

	retval = mutex_lock_interruptible(&evdev_mutex);
	if (retval)
		return retval;

	if (!evdev->exist) {
		retval = -ENODEV;
		goto out;
	}

	retval = evdev_do_ioctl(file, cmd, p);

 out:
	mutex_unlock(&evdev_mutex);
	return retval;
}

 static int evdev_ioctl(struct inode *inode, struct file *file,
				unsigned int cmd, unsigned long arg)
{
	return evdev_ioctl_handler(file, cmd, arg);
}

static struct file_operations evdev_fops = {
	.owner		= THIS_MODULE,
	.read		= evdev_read,
	.write		= evdev_write,
	.poll		= evdev_poll,
	.open		= evdev_open,
	.release	= evdev_release,
	.ioctl		= evdev_ioctl,
	.fasync		= evdev_fasync,
	.flush		= evdev_flush
};

static int evdev_install_chrdev(struct evdev *evdev)
{
	/*
	 * No need to do any locking here as calls to connect and
	 * disconnect are serialized by the input core
	 */
	evdev_table[evdev->minor] = evdev;
	return 0;
}

static void evdev_remove_chrdev(struct evdev *evdev)
{
	/*
	 * Lock evdev table to prevent race with evdev_open()
	 */
	mutex_lock(&evdev_mutex);
	evdev_table[evdev->minor] = NULL;
	mutex_unlock(&evdev_mutex);
}

/*
 * Mark device non-existent. This disables writes, ioctls and
 * prevents new users from opening the device. Already posted
 * blocking reads will stay, however new ones will fail.
 */
static void evdev_mark_dead(struct evdev *evdev)
{
	mutex_lock(&evdev_mutex);
	evdev->exist = 0;
	mutex_unlock(&evdev_mutex);
}

static void evdev_cleanup(struct evdev *evdev)
{
	struct input_handle *handle = &evdev->handle;

	evdev_mark_dead(evdev);
	evdev_hangup(evdev);
	evdev_remove_chrdev(evdev);

	/* evdev is marked dead so no one else accesses evdev->open */
	input_flush_device(handle, NULL);
	if (evdev->open)
		input_close_device(handle);
}

/*
 * Create new evdev device. Note that input core serializes calls
 * to connect and disconnect so we don't need to lock evdev_table here.
 */
static struct input_handle *evdev_connect(struct input_handler *handler, struct input_dev *dev,
					  struct input_device_id *id)
{
	struct evdev *evdev;
	int minor;
	int error;

	for (minor = 0; minor < EVDEV_MINORS; minor++)
		if (!evdev_table[minor])
			break;

	if (minor == EVDEV_MINORS) {
		printk(KERN_ERR "evdev: no more free evdev devices\n");
		return NULL;
	}

	if (!(evdev = kmalloc(sizeof(struct evdev), GFP_KERNEL)))
		return NULL;
	memset(evdev, 0, sizeof(struct evdev));

	INIT_LIST_HEAD(&evdev->client_list);
	spin_lock_init(&evdev->client_lock);
	init_waitqueue_head(&evdev->wait);
	kref_init(&evdev->kref);

	snprintf(evdev->name, sizeof(evdev->name), "event%d", minor);
	evdev->exist = 1;
	evdev->minor = minor;

	evdev->handle.dev = dev;
	evdev->handle.name = evdev->name;
	evdev->handle.handler = handler;
	evdev->handle.private = evdev;

	error = evdev_install_chrdev(evdev);
	if (error)
		return NULL;

	devfs_mk_cdev(MKDEV(INPUT_MAJOR, EVDEV_MINOR_BASE + minor),
			S_IFCHR|S_IRUGO|S_IWUSR, "input/event%d", minor);
	class_simple_device_add(input_class,
				MKDEV(INPUT_MAJOR, EVDEV_MINOR_BASE + minor),
				dev->dev, "event%d", minor);

	return &evdev->handle;
}

static void evdev_disconnect(struct input_handle *handle)
{
	struct evdev *evdev = handle->private;

	evdev_cleanup(evdev);
	mutex_lock(&evdev_mutex);
	kref_put(&evdev->kref, evdev_free);
	mutex_unlock(&evdev_mutex);
}

static struct input_device_id evdev_ids[] = {
	{ .driver_info = 1 },	/* Matches all devices */
	{ },			/* Terminating zero entry */
};

MODULE_DEVICE_TABLE(input, evdev_ids);

static struct input_handler evdev_handler = {
	.event		= evdev_event,
	.connect	= evdev_connect,
	.disconnect	= evdev_disconnect,
	.fops		= &evdev_fops,
	.minor		= EVDEV_MINOR_BASE,
	.name		= "evdev",
	.id_table	= evdev_ids,
};

static int __init evdev_init(void)
{
	input_register_handler(&evdev_handler);
	return 0;
}

static void __exit evdev_exit(void)
{
	input_unregister_handler(&evdev_handler);
}

module_init(evdev_init);
module_exit(evdev_exit);

MODULE_AUTHOR("Vojtech Pavlik <vojtech@ucw.cz>");
MODULE_DESCRIPTION("Input driver event char devices");
MODULE_LICENSE("GPL");

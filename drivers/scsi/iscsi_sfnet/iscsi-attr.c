/*
 * iSCSI driver for Linux
 * Copyright (C) 2002 Cisco Systems, Inc.
 * Copyright (C) 2004 Mike Christie
 * Copyright (C) 2004 IBM Corporation
 * maintained by linux-iscsi-devel@lists.sourceforge.net
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 *
 * $Id: iscsi-attr.c,v 1.1.2.17 2005/04/26 17:44:50 mikenc Exp $
 *
 * The sysfs host attributes are defined here. 
 */
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_host.h>

#include "iscsi-session.h"
#include "iscsi-task.h"
#include "iscsi-sfnet.h"

static ssize_t
store_do_shutdown(struct class_device *class_dev, const char *buf, size_t count)
{
	iscsi_destroy_host(class_to_shost(class_dev));
	return count;
}

static ssize_t
store_drop_session(struct class_device *class_dev, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(class_dev);
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;

	iscsi_drop_session(session);
	return count;
}

static CLASS_DEVICE_ATTR(shutdown, S_IWUSR, NULL, store_do_shutdown);
static CLASS_DEVICE_ATTR(drop_session, S_IWUSR, NULL, store_drop_session);

static ssize_t
show_session_established(struct class_device *class_dev, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(class_dev);
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;

	if (test_bit(SESSION_ESTABLISHED, &session->control_bits))
		sprintf(buf, "1");
	else
		sprintf(buf, "0");
	return 1;
}
static CLASS_DEVICE_ATTR(session_established, S_IRUGO,
			 show_session_established, NULL);

/*
 * Macro to show session values specific to this driver
 * on the scsi host's class dev. Some of them could also
 * be moved to the transport class one day.
 */
#define session_show_function(field, format_string)			\
static ssize_t								\
show_##field (struct class_device *class_dev, char *buf)		\
{									\
	struct Scsi_Host *shost = class_to_shost(class_dev);		\
	struct iscsi_session *session;					\
	session = (struct iscsi_session *)shost->hostdata;		\
	return snprintf(buf, 20, format_string, session->field);	\
}

#define session_rd_attr(field, format_string)			\
	session_show_function(field, format_string)		\
static CLASS_DEVICE_ATTR(field, S_IRUGO, show_##field, NULL);

session_rd_attr(window_closed, "%lu");

#define session_store_tmo_function(field, format_string)		\
static ssize_t								\
store_##field(struct class_device *class_dev, const char *buf,		\
	      size_t count)						\
{									\
	struct Scsi_Host *shost = class_to_shost(class_dev);		\
	struct iscsi_session *session;					\
	int timeout;							\
									\
	session = (struct iscsi_session *)shost->hostdata;		\
	sscanf(buf, "%d\n", &timeout);					\
	iscsi_update_##field(session, timeout);				\
	return count;							\
}

#define session_tmo_attr(field, format_string)			\
	session_show_function(field, format_string)		\
	session_store_tmo_function(field, format_string)	\
static CLASS_DEVICE_ATTR(field, S_IRUGO | S_IWUSR,		\
			 show_##field, store_##field);

session_tmo_attr(login_timeout, "%d");
session_tmo_attr(active_timeout, "%d");
session_tmo_attr(idle_timeout, "%d");
session_tmo_attr(ping_timeout, "%d");
session_tmo_attr(abort_timeout, "%d");
session_tmo_attr(reset_timeout, "%d");

static ssize_t
store_replacement_timeout(struct class_device *class_dev, const char *buf,
			  size_t count)
{
	struct Scsi_Host *shost = class_to_shost(class_dev);
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;
	int timeout;

	sscanf(buf, "%d\n", &timeout);
	iscsi_update_replacement_timeout(session, timeout);
	return count;
}

session_show_function(replacement_timeout, "%d");

static CLASS_DEVICE_ATTR(connfail_timeout, S_IRUGO | S_IWUSR,
			 show_replacement_timeout, store_replacement_timeout);


#define session_show_time_fn(field, format_string)			\
static ssize_t								\
show_##field (struct class_device *class_dev, char *buf)		\
{									\
	struct Scsi_Host *shost = class_to_shost(class_dev);		\
	struct iscsi_session *session;					\
	session = (struct iscsi_session *)shost->hostdata;		\
	return snprintf(buf, 20, format_string,				\
			(jiffies - session->field) / HZ);		\
}

#define session_rd_time_attr(field, format_string)			\
	session_show_time_fn(field, format_string)			\
static CLASS_DEVICE_ATTR(field, S_IRUGO, show_##field, NULL);

session_rd_time_attr(session_established_time, "%lu");
session_rd_time_attr(session_drop_time, "%lu");

struct class_device_attribute *iscsi_host_attrs[] = {
	&class_device_attr_session_established,
	&class_device_attr_shutdown,
	&class_device_attr_drop_session,
	&class_device_attr_connfail_timeout,
	&class_device_attr_session_established_time,
	&class_device_attr_session_drop_time,
	&class_device_attr_login_timeout,
	&class_device_attr_active_timeout,
	&class_device_attr_idle_timeout,
	&class_device_attr_ping_timeout,
	&class_device_attr_abort_timeout,
	&class_device_attr_reset_timeout,
	&class_device_attr_window_closed,
	NULL
};

static ssize_t iscsi_store_queue_depth(struct device *dev, const char *buf,
				       size_t count)
{
	struct scsi_device *sdev = to_scsi_device(dev);
	int qdepth;

	if (!sdev->tagged_supported)
		return count;
	if (sscanf(buf, "%10d\n", &qdepth) == 1 && qdepth > 0)
		scsi_adjust_queue_depth(sdev, MSG_ORDERED_TAG, qdepth);

	return count;
}

static DEVICE_ATTR(queue_depth, S_IWUSR, NULL, iscsi_store_queue_depth);

struct device_attribute *iscsi_dev_attrs[] = {
	&dev_attr_queue_depth,
	NULL,
};

#define iscsi_transport_get_fn(field)					\
static void								\
iscsi_get_##field (struct scsi_target *stgt)				\
{									\
	struct Scsi_Host *shost = dev_to_shost(stgt->dev.parent);	\
	struct iscsi_session *session;					\
	session = (struct iscsi_session *)shost->hostdata;		\
	iscsi_##field(stgt) = session->field;				\
}

iscsi_transport_get_fn(tsih);
iscsi_transport_get_fn(initial_r2t);
iscsi_transport_get_fn(immediate_data);
iscsi_transport_get_fn(header_digest);
iscsi_transport_get_fn(data_digest);
iscsi_transport_get_fn(max_burst_len);
iscsi_transport_get_fn(first_burst_len);
iscsi_transport_get_fn(max_recv_data_segment_len);
iscsi_transport_get_fn(max_xmit_data_segment_len);

#define iscsi_target_transport_cp_fn(field)				\
static ssize_t								\
iscsi_get_##field (struct scsi_target *stgt, char *buf, ssize_t count)	\
{									\
	struct Scsi_Host *shost = dev_to_shost(stgt->dev.parent);	\
	struct iscsi_session *session;					\
	session = (struct iscsi_session *)shost->hostdata;		\
	return snprintf(buf, count - 1, "%s\n", session->field);	\
}

iscsi_target_transport_cp_fn(target_name);
iscsi_target_transport_cp_fn(target_alias);

static void
iscsi_copy_addr(struct scsi_target *starget, struct sockaddr *addr)
{
	iscsi_addr_type(starget) = addr->sa_family;
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;

		memcpy(&iscsi_sin_addr(starget), &addr4->sin_addr,
		       sizeof(struct in_addr));
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;

		memcpy(&iscsi_sin6_addr(starget), &addr6->sin6_addr,
		       sizeof(struct in6_addr));
	}
}

static void
iscsi_get_ip_address(struct scsi_target *starget)
{
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;

	iscsi_copy_addr(starget, (struct sockaddr *)&session->addr);
}

 static void
iscsi_get_portal_ip_address(struct scsi_target *starget)
{
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;

	iscsi_copy_addr(starget, (struct sockaddr *)&session->portal.addr);
}

static void
iscsi_get_port(struct scsi_target *starget)
{
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;

	struct sockaddr_in *addr = (struct sockaddr_in *)&session->addr;
	iscsi_port(starget) = addr->sin_port;
}

static void
iscsi_get_tpgt(struct scsi_target *starget)
{
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;

	iscsi_tpgt(starget) = session->portal_group_tag;
}

static void
iscsi_get_isid(struct scsi_target *starget)
{
	struct Scsi_Host *shost = dev_to_shost(starget->dev.parent);
	struct iscsi_session *session = (struct iscsi_session *)shost->hostdata;
	memcpy(iscsi_isid(starget), session->isid, sizeof(session->isid));
}

#define iscsi_host_transport_cp_fn(field)				\
static ssize_t								\
iscsi_get_##field (struct Scsi_Host *shost, char *buf, ssize_t count)	\
{									\
	struct iscsi_session *s = (struct iscsi_session *)shost->hostdata; \
	return snprintf(buf, count - 1, "%s\n", s->field);		\
}

iscsi_host_transport_cp_fn(initiator_name);
iscsi_host_transport_cp_fn(initiator_alias);

struct iscsi_function_template iscsi_fnt = {
	.get_isid = iscsi_get_isid,
	.show_isid = 1,
	.get_tsih = iscsi_get_tsih,
	.show_tsih = 1,
	.get_port = iscsi_get_port,
	.show_port = 1,
	.get_tpgt = iscsi_get_tpgt,
	.show_tpgt = 1,
	.get_ip_address = iscsi_get_ip_address,
	.show_ip_address = 1,
	.get_portal_ip_address = iscsi_get_portal_ip_address,
	.show_portal_ip_address = 1,
	.get_initial_r2t = iscsi_get_initial_r2t,
	.show_initial_r2t = 1,
	.get_immediate_data = iscsi_get_immediate_data,
	.show_immediate_data = 1,
	.get_header_digest = iscsi_get_header_digest,
	.show_header_digest = 1,
	.get_data_digest = iscsi_get_data_digest,
	.show_data_digest = 1,
	.get_max_burst_len = iscsi_get_max_burst_len,
	.show_max_burst_len = 1,
	.get_first_burst_len = iscsi_get_first_burst_len,
	.show_first_burst_len = 1,
	.get_max_recv_data_segment_len = iscsi_get_max_recv_data_segment_len,
	.show_max_recv_data_segment_len = 1,
	.get_max_xmit_data_segment_len = iscsi_get_max_xmit_data_segment_len,
	.show_max_xmit_data_segment_len = 1,
	.get_target_name = iscsi_get_target_name,
	.show_target_name = 1,
	.get_target_alias = iscsi_get_target_alias,
	.show_target_alias = 1,
	.get_initiator_alias = iscsi_get_initiator_alias,
	.show_initiator_alias = 1,
	.get_initiator_name = iscsi_get_initiator_name,
	.show_initiator_name = 1,
};

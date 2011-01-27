/*
 * iSCSI driver for Linux
 * Copyright (C) 2001 Cisco Systems, Inc.
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
 * $Id: iscsi-network.c,v 1.1.2.8 2005/03/29 19:35:07 mikenc Exp $
 *
 * Contains functions to handle socket operations
 */
#include <linux/tcp.h>
#include <linux/uio.h>

#include "iscsi-session.h"
#include "iscsi-sfnet.h"

/*
 * decode common network errno values into more useful strings.
 * strerror would be nice right about now.
 */
static char *
iscsi_strerror(int errno)
{
	switch (errno) {
	case EIO:
		return "I/O error";
	case EINTR:
		return "Interrupted system call";
	case ENXIO:
		return "No such device or address";
	case EFAULT:
		return "Bad address";
	case EBUSY:
		return "Device or resource busy";
	case EINVAL:
		return "Invalid argument";
	case EPIPE:
		return "Broken pipe";
	case ENONET:
		return "Machine is not on the network";
	case ECOMM:
		return "Communication error on send";
	case EPROTO:
		return "Protocol error";
	case ENOTUNIQ:
		return "Name not unique on network";
	case ENOTSOCK:
		return "Socket operation on non-socket";
	case ENETDOWN:
		return "Network is down";
	case ENETUNREACH:
		return "Network is unreachable";
	case ENETRESET:
		return "Network dropped connection because of reset";
	case ECONNABORTED:
		return "Software caused connection abort";
	case ECONNRESET:
		return "Connection reset by peer";
	case ESHUTDOWN:
		return "Cannot send after shutdown";
	case ETIMEDOUT:
		return "Connection timed out";
	case ECONNREFUSED:
		return "Connection refused";
	case EHOSTDOWN:
		return "Host is down";
	case EHOSTUNREACH:
		return "No route to host";
	default:
		return "";
	}
}

/* create and connect a new socket for this session */
int
iscsi_connect(struct iscsi_session *session)
{
	struct socket *socket;
	int arg = 1;
	int rc;

	if (session->socket)
		return 0;

	rc = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &socket);
	if (rc < 0) {
		iscsi_host_err(session, "Failed to create socket, rc %d\n", rc);
		return rc;
	}

	session->socket = socket;
	socket->sk->sk_allocation = GFP_ATOMIC;

	/* no delay in sending */
	rc = socket->ops->setsockopt(socket, IPPROTO_TCP, TCP_NODELAY,
				     (char *)&arg, sizeof(arg));
	if (rc) {
		iscsi_host_err(session, "Failed to setsockopt TCP_NODELAY, rc "
			       "%d\n", rc);
		goto done;
	}

	if (session->tcp_window_size) {
		/*
		 * Should we be accessing the sk_recv/send_buf directly like
		 * NFS (sock_setsockopt will be bounded by the sysctl limits)?
		 */
		sock_setsockopt(socket, SOL_SOCKET, SO_RCVBUF,
			        (char *)&session->tcp_window_size,
				sizeof(session->tcp_window_size));
		sock_setsockopt(socket, SOL_SOCKET, SO_SNDBUF,
			        (char *)&session->tcp_window_size,
				sizeof(session->tcp_window_size));
	}

	rc = socket->ops->connect(socket, &session->addr,
				  sizeof(struct sockaddr), 0);
 done:
	if (rc) {
		if (signal_pending(current))
			iscsi_host_err(session, "Connect failed due to "
				       "driver timeout\n");
		else
			iscsi_host_err(session, "Connect failed with rc %d: "
				       "%s\n", rc, iscsi_strerror(-rc));
		sock_release(socket);
		session->socket = NULL;
	}

	return rc;
}

void
iscsi_disconnect(struct iscsi_session *session)
{
	if (session->socket) {
		sock_release(session->socket);
		session->socket = NULL;
	}
}

/**
 * iscsi_sendpage - Transmit data using sock->ops->sendpage
 * @session: iscsi_session to the target
 * @flags: MSG_MORE or 0
 * @pg: page to send
 * @pg_offset: offset in page
 * @len: length of the data to be transmitted.
 **/
int
iscsi_sendpage(struct iscsi_session *session, int flags, struct page *pg,
	       unsigned int pg_offset, unsigned int len)
{
	struct socket *sock = session->socket;
	int rc;

	rc = sock->ops->sendpage(sock, pg, pg_offset, len, flags);
	if (signal_pending(current))
		return ISCSI_IO_INTR;
	else if (rc != len) {
		if (rc == 0)
			iscsi_host_err(session, "iscsi_sendpage() failed due "
				       "to connection closed by target\n");
		else if (rc < 0)
			iscsi_host_err(session, "iscsi_sendpage() failed with "
				       "rc %d: %s\n", rc, iscsi_strerror(-rc));
		else
			iscsi_host_err(session, "iscsi_sendpage() failed due "
				       "to short write of %d of %u\n", rc,
				       len);
		return ISCSI_IO_ERR;
	}

	return ISCSI_IO_SUCCESS;
}

/**
 * iscsi_send/recvmsg - recv or send a iSCSI PDU, or portion thereof
 * @session: iscsi session
 * @iov: contains list of buffers to receive data in
 * @iovn: number of buffers in IO vec
 * @size: total size of data to be received
 *
 * Note:
 *    tcp_*msg() might be interrupted because we got
 *    sent a signal, e.g. SIGHUP from iscsi_drop_session().  In
 *    this case, we most likely did not receive all the data, and
 *    we should just bail out.  No need to log any message since
 *    this is expected behavior.
 **/
int
iscsi_recvmsg(struct iscsi_session *session, struct kvec *iov, size_t iovn,
	      size_t size)
{
	struct msghdr msg;
	int rc;
	
	memset(&msg, 0, sizeof(msg));
	rc = kernel_recvmsg(session->socket, &msg, iov, iovn, size,
			    MSG_WAITALL);
	if (signal_pending(current))
		return ISCSI_IO_INTR;
	else if (rc != size) {
		if (rc == 0)
			iscsi_host_err(session, "iscsi_recvmsg() failed due "
				       "to connection closed by target\n");
		else if (rc < 0)
			iscsi_host_err(session, "iscsi_recvmsg() failed with "
				       "rc %d: %s\n", rc, iscsi_strerror(-rc));
		else
			iscsi_host_err(session, "iscsi_recvmsg() failed due "
				       "to short read of %d\n", rc);
		return ISCSI_IO_ERR;
	}

	return ISCSI_IO_SUCCESS;
}

int
iscsi_sendmsg(struct iscsi_session *session, struct kvec *iov, size_t iovn,
	      size_t size)
{
	struct msghdr msg;
	int rc;

	memset(&msg, 0, sizeof(msg));
	rc = kernel_sendmsg(session->socket, &msg, iov, iovn, size);
	if (signal_pending(current))
		return ISCSI_IO_INTR;
	else if (rc != size) {
		if (rc == 0)
			iscsi_host_err(session, "iscsi_sendmsg() failed due "
				       "to connection closed by target\n");
		else if (rc < 0)
			iscsi_host_err(session, "iscsi_sendmsg() failed with "
				       "rc %d: %s\n", rc, iscsi_strerror(-rc));
		else
			iscsi_host_err(session, "iscsi_sendmsg() failed due "
				       "to short write of %d\n", rc);
		return ISCSI_IO_ERR;
	}

	return ISCSI_IO_SUCCESS;
}

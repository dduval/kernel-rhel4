/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id: sdp_inet.c 3362 2005-09-11 07:53:58Z mst $
 */

#include <linux/tcp.h>
#include <asm/ioctls.h>
#include <linux/workqueue.h>
#include "sdp_main.h"

/*
 * list of connections waiting for an incoming connection
 */
static int proto_family    = AF_INET_SDP;
static int conn_size       = SDP_DEV_SK_LIST_SIZE;

static int recv_post_max   = SDP_CQ_RECV_SIZE;
static int recv_buff_max   = SDP_BUFF_RECV_MAX;
static int send_post_max   = SDP_CQ_SEND_SIZE;
static int send_buff_max   = SDP_BUFF_SEND_MAX;
static int send_usig_max   = SDP_SEND_UNSIG_MAX;

int sdp_debug_level = __SDP_DEBUG_LEVEL;

MODULE_AUTHOR("Libor Michalek");
MODULE_DESCRIPTION("InfiniBand SDP module");
MODULE_LICENSE("Dual BSD/GPL");

module_param(proto_family, int, 0);
MODULE_PARM_DESC(proto_family,
		 "Override the default protocol family value of 27.");

module_param(conn_size, int, 0);
MODULE_PARM_DESC(conn_size,
		 "Set the maximum number of active sockets.");

module_param(recv_post_max, int, 0);
MODULE_PARM_DESC(recv_post_max,
		 "Set the receive completion queue size.");

module_param(recv_buff_max, int, 0);
MODULE_PARM_DESC(recv_buff_max,
		 "Set the maximum number of receives buffered.");

module_param(send_post_max, int, 0);
MODULE_PARM_DESC(send_post_max,
		 "Set the send completion queue size.");

module_param(send_buff_max, int, 0);
MODULE_PARM_DESC(send_buff_max,
		 "Set the maximum number of sends buffered.");

module_param(send_usig_max, int, 0);
MODULE_PARM_DESC(send_usig_max,
		 "Set the maximum consecutive unsignalled send events.");

module_param(sdp_debug_level, int, 0);
MODULE_PARM_DESC(sdp_debug_level,
		 "Set the debug level 0-9.");
/*
 * socket structure relevant fields:
 *
 * struct sock {
 *    unsigned short     num;         (src port, host    byte order)
 *    __u16              sport;       (src port, network byte order)
 *    __u32              rcv_saddr;   (src addr, network byte order)
 *    __u32              saddr;       (src addr, network byte order)
 *    __u32              daddr;       (dst addr, network byte order)
 *    __u16              dport;       (dst port, network byte order)
 *    unsigned char      shutdown;    (mask of directional close)
 *    wait_queue_head_t *sleep;       (wait for event queue)
 *    int                wmem_queued; (send bytes outstanding)
 *    int                sndbuf;      (possible send bytes outstanding)
 *    unsigned long      lingertime;  (close linger time)
 *    volatile char      linger;      (close linger time valid)
 *    union {}           tp_info;     (cast for STRM/LNX CONN specific data)
 *    int                err;         (error propogation from GW to socket if)
 *    unsigned short     ack_backlog;     (current accept backlog)
 *    unsigned short     max_ack_backlog; (accept max backlog)
 * };
 */

/*
 * Notification of significant events
 */

/*
 * sdp_inet_wake_send - test, set, and notify socket of write space
 */
void sdp_inet_wake_send(struct sock *sk)
{
	struct sdp_sock *conn;

        if (!sk || !(conn = sdp_sk(sk)))
 		return;

	if (sk->sk_socket && test_bit(SOCK_NOSPACE, &sk->sk_socket->flags) &&
	    sdp_inet_writable(conn)) {
		read_lock(&sk->sk_callback_lock);
		clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

		if (sk->sk_sleep &&
		    waitqueue_active(sk->sk_sleep))
			wake_up_interruptible(sk->sk_sleep);
		/*
		 * test, clear, and notify. SOCK_ASYNC_NOSPACE
		 */
		sk_wake_async(sk, 2, POLL_OUT);
		read_unlock(&sk->sk_callback_lock);
	}
}

/*
 * sdp_inet_disconnect - disconnect a connection
 */
static int sdp_inet_disconnect(struct sdp_sock *conn)
{
	struct sock *sk;
	int result = 0;
	/*
	 * close buffered data transmission space
	 */
	sk = sk_sdp(conn);
	conn->send_buf = 0;
	/*
	 * Generate a Disconnect message, and mark self as disconnecting.
	 */
	switch (conn->state) {
	case SDP_CONN_ST_REQ_PATH:
	case SDP_CONN_ST_REQ_SENT:
		/*
		 * outstanding request. Mark it in error, and
		 * completions needs to complete the closing.
		 */
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_ERROR);
		sk->sk_err = ECONNRESET;
		break;
	case SDP_CONN_ST_REQ_RECV:
        case SDP_CONN_ST_REP_RECV:
	case SDP_CONN_ST_ESTABLISHED:
		/*
		 * Attempt to send a disconnect message
		 */
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_DIS_SEND_1);

		result = sdp_send_ctrl_disconnect(conn);
		if (result < 0) {
			sdp_dbg_warn(conn,
				     "Error <%d> send disconnect request",
				     result);
			goto error;
		}

		break;
	case SDP_CONN_ST_DIS_RECV_1:
		/*
		 * Change state, and send a disconnect request
		 */
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_DIS_SEND_2);

		result = sdp_send_ctrl_disconnect(conn);
		if (result < 0) {
			sdp_dbg_warn(conn,
				     "Error <%d> send disconnect request",
				     result);
			goto error;
		}
		break;
	case SDP_CONN_ST_TIME_WAIT_1:
	case SDP_CONN_ST_TIME_WAIT_2:
	case SDP_CONN_ST_ERROR:
	case SDP_CONN_ST_CLOSED:
		break;
	default:
		sdp_dbg_warn(conn, "Incorrect state for disconnect");
		result = -EBADE;
		goto error;
	}

	return 0;
error:
	/*
	 * abortive close.
	 */
	sdp_conn_inet_error(conn, -ECONNRESET);
	(void)ib_send_cm_dreq(conn->cm_id, NULL, 0);

	return result;
}

/*
 * Linux SOCKET interface, module specific functions
 */

/*
 * sdp_inet_release - release/close a socket
 */
static int sdp_inet_release(struct socket *sock)
{
	struct sdp_sock *conn;
	struct sock *sk = sock->sk;
	int  result;
	long timeout;
	u32  flags;

	if (!sk) {
		sdp_dbg_warn(NULL, "release empty <%d:%d> flags <%08lx>",
			     sock->type, sock->state, sock->flags);
		return 0;
	}

	conn = sdp_sk(sk);

	sdp_dbg_ctrl(conn, "RELEASE: linger <%d:%lu> data <%d:%d>",
		     sock_flag(sk, SOCK_LINGER), sk->sk_lingertime,
		     conn->byte_strm, conn->src_recv);
	/*
	 * clear out sock, so we only do this once.
	 */
	sock->sk = NULL;

	sdp_conn_lock(conn);
	conn->shutdown = SHUTDOWN_MASK;

	if (conn->state == SDP_CONN_ST_LISTEN) {
		/*
		 * stop listening
		 */
		result = sdp_inet_listen_stop(conn);
		if (result < 0)
			sdp_dbg_warn(conn, "Error <%d> while releasing listen",
				     result);

		goto done;
	}
	/*
	 * get blocking nature of the socket.
	 */
	if (sock->file)
		flags = (sock->file->f_flags & O_NONBLOCK) ? \
			MSG_DONTWAIT : 0;
	else
		flags = 0;
	/*
	 * If there is data in the receive queue, flush it,
	 * and consider this an abort. Otherwise consider
	 * this a gracefull close.
	 */
	if (sdp_buff_q_size(&conn->recv_pool) > 0 ||
	    conn->src_recv > 0 ||
	    (sock_flag(sk, SOCK_LINGER) &&
	     !sk->sk_lingertime)) {
		/*
		 * abort.
		 */
		sdp_conn_abort(conn);
		goto done;
	}
	/*
	 * disconnect. (state dependant) On error skip linger, since
	 * the socket is already out of the normal path.
	 */
	result = sdp_inet_disconnect(conn);
	if (result < 0)
		goto done;
	/*
	 * Skip lingering/canceling if
	 * non-blocking and not exiting.
	 */
	if (!(flags & MSG_DONTWAIT) ||
	    (PF_EXITING & current->flags)) {
		/*
		 * Wait if linger is set and
		 * process is not exiting.
		 */
		if (sock_flag(sk, SOCK_LINGER)
		    && !(PF_EXITING & current->flags)) {
			DECLARE_WAITQUEUE(wait, current);
			timeout = sk->sk_lingertime;

			add_wait_queue(sk->sk_sleep, &wait);
			set_current_state(TASK_INTERRUPTIBLE);

			while (timeout > 0 &&
			       !(SDP_ST_MASK_CLOSED & conn->state)) {
				sdp_conn_unlock(conn);
				timeout = schedule_timeout(timeout);
				sdp_conn_lock(conn);

				if (signal_pending(current))
					break;
			}

			set_current_state(TASK_RUNNING);
			remove_wait_queue(sk->sk_sleep, &wait);
		}
#if 0
		/*
		 * On a blocking socket, if still draining after linger,
		 * Cancel write and close again to force closing the
		 * connection.
		 */
		if (SDP_ST_MASK_DRAIN & conn->state) {

			sdp_iocb_q_cancel_all_write(conn, -ECANCELED);

			(void)sdp_inet_disconnect(conn);
		}
#endif
	}

done:
	/*
	 * finally drop socket reference. (socket API reference)
	 */
	sock_orphan(sk);
	sdp_conn_unlock(conn);
	sdp_conn_put(conn);

	return 0;
}

/*
 * sdp_inet_bind - bind a socket to an address/interface
 */
static int sdp_inet_bind(struct socket *sock, struct sockaddr *uaddr, int size)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct sock *sk;
	struct sdp_sock *conn;
	unsigned int addr_result = RTN_UNSPEC;
	u16 bind_port;
	int result;

	sk = sock->sk;
	conn = sdp_sk(sk);

	sdp_dbg_ctrl(conn, "BIND: family <%d> addr <%08x:%04x>",
		     addr->sin_family, addr->sin_addr.s_addr, addr->sin_port);

	if (size < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (proto_family != addr->sin_family &&
	    AF_INET != addr->sin_family && AF_UNSPEC != addr->sin_family)
		return -EAFNOSUPPORT;
	/*
	 * Basically we're OK with INADDR_ANY or a local interface
	 * (TODO: loopback)
	 */
	if (INADDR_ANY != addr->sin_addr.s_addr) {
		/*
		 * make sure we have a valid binding address
		 */
		addr_result = inet_addr_type(addr->sin_addr.s_addr);

		if (inet_sk(sk)->freebind == 0 &&
		    RTN_LOCAL != addr_result &&
		    RTN_MULTICAST != addr_result &&
		    RTN_BROADCAST != addr_result)
			return -EADDRNOTAVAIL;
	}
	/*
	 * check bind permission for low ports.
	 */
	bind_port = ntohs(addr->sin_port);
	if (bind_port > 0 &&
	    bind_port < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		return -EACCES;
	/*
	 * socket checks.
	 */
	sdp_conn_lock(conn);

	if (conn->state != SDP_CONN_ST_CLOSED || conn->src_port > 0) {
		result = -EINVAL;
		goto done;
	}

	conn->src_addr = ntohl(addr->sin_addr.s_addr);

	if (RTN_MULTICAST == addr_result || RTN_BROADCAST == addr_result)
		conn->src_addr = 0;

	result = sdp_inet_port_get(conn, bind_port);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> getting port during bind",
			     result);

		conn->src_addr = 0;

		goto done;
	}

	if (INADDR_ANY != conn->src_addr)
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;

	if (bind_port > 0)
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;

	inet_sk(sk)->rcv_saddr = htonl(conn->src_addr);
	inet_sk(sk)->saddr     = htonl(conn->src_addr);
	inet_sk(sk)->num       = conn->src_port;
	inet_sk(sk)->sport     = htons(conn->src_port);
	inet_sk(sk)->daddr     = 0;
	inet_sk(sk)->dport     = 0;

	result = 0;
done:
	sdp_conn_unlock(conn);
	return result;
}

/*
 * sdp_inet_connect - connect a socket to a remote address
 */
static int sdp_inet_connect(struct socket *sock, struct sockaddr *uaddr,
			    int size, int flags)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct sock *sk;
	struct sdp_sock *conn;
	long timeout;
	int result;

	sk = sock->sk;
	conn = sdp_sk(sk);

	sdp_dbg_ctrl(conn, "CONNECT: family <%d> addr <%08x:%04x>",
		     addr->sin_family, addr->sin_addr.s_addr, addr->sin_port);

	if (size < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (proto_family != addr->sin_family &&
	    AF_INET != addr->sin_family && AF_UNSPEC != addr->sin_family)
		return -EAFNOSUPPORT;

	if (MULTICAST(addr->sin_addr.s_addr) ||
	    BADCLASS(addr->sin_addr.s_addr) ||
	    ZERONET(addr->sin_addr.s_addr) ||
	    LOCAL_MCAST(addr->sin_addr.s_addr) ||
	    INADDR_ANY == addr->sin_addr.s_addr)
		return -EINVAL;
	/*
	 * lock socket
	 */
	sdp_conn_lock(conn);

	switch (sock->state) {
	case SS_UNCONNECTED:
		if (conn->state != SDP_CONN_ST_CLOSED) {
			result = -EISCONN;
			goto done;
		}

		if (!conn->src_port) {
			result = sdp_inet_port_get(conn, 0);
			if (result < 0) {
				sdp_dbg_warn(conn, "Error <%d> getting port",
					     result);
				goto done;
			}

			inet_sk(sk)->num       = conn->src_port;
			inet_sk(sk)->sport     = htons(conn->src_port);
		}

		sk->sk_err = 0;

		sock->state = SS_CONNECTING;

		conn->dst_addr = ntohl(addr->sin_addr.s_addr);
		conn->dst_port = ntohs(addr->sin_port);
		/*
		 * close, allow connection completion notification.
		 */
		set_bit(SOCK_NOSPACE, &sock->flags);
		/*
		 * post the SDP hello message
		 */
		result = sdp_cm_connect(conn);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> initiating connect",
				     result);

			conn->dst_addr = 0;
			conn->dst_port = 0;

			sock->state = SS_UNCONNECTED;
			conn->state = SDP_CONN_ST_CLOSED;

			goto done;
		}

		inet_sk(sk)->daddr = htonl(conn->dst_addr);
		inet_sk(sk)->dport = htons(conn->dst_port);

		result = -EINPROGRESS;
		break;
	case SS_CONNECTING:
		result = -EALREADY;
		break;
	case SS_CONNECTED:
		result = -EISCONN;
		goto done;
	default:
		result = -EINVAL;
		goto done;
	}
	/*
	 * wait for connection to complete.
	 */
	timeout = sock_sndtimeo(sk, O_NONBLOCK & flags);
	if (timeout > 0) {

		DECLARE_WAITQUEUE(wait, current);
		add_wait_queue(sk->sk_sleep, &wait);
		set_current_state(TASK_INTERRUPTIBLE);

		while (timeout > 0 && (conn->state & SDP_ST_MASK_CONNECT)) {

			sdp_conn_unlock(conn);
			timeout = schedule_timeout(timeout);
			sdp_conn_lock(conn);

			if (signal_pending(current)) {

				break;
			}
		}

		set_current_state(TASK_RUNNING);
		remove_wait_queue(sk->sk_sleep, &wait);

		if (conn->state & SDP_ST_MASK_CONNECT) {

			if (timeout > 0) {

				result = sock_intr_errno(timeout);
			}

			goto done;
		}
	}
	/*
	 * check state before exiting. It's possible the that connection
	 * error'd or is being closed after reaching ESTABLISHED at this
	 * point. In this case connect should return normally and allow
	 * the normal mechnaism for detecting these states.
	 */
	switch (conn->state) {
	case SDP_CONN_ST_REQ_PATH:
	case SDP_CONN_ST_REQ_SENT:
	case SDP_CONN_ST_REP_RECV:
		break;
	case SDP_CONN_ST_ESTABLISHED:
	case SDP_CONN_ST_DIS_RECV_1:
		sock->state = SS_CONNECTED;
		result = 0;
		break;
	case SDP_CONN_ST_CLOSED:
	case SDP_CONN_ST_ERROR:
		result = sock_error(sk) ? : -ECONNABORTED;
		sock->state = SS_UNCONNECTED;
		break;
	default:
		sdp_dbg_warn(conn, "Unexpected state after connect. <%08x>",
			     sock->state);
		break;
	}

	sdp_dbg_ctrl(conn, "CONNECT complete");
done:
	sdp_conn_unlock(conn);
	return result;
}

/*
 * sdp_inet_listen - listen on a socket for incoming addresses
 */
static int sdp_inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk;
	struct sdp_sock *conn;
	int result;

	sk = sock->sk;
	conn = sdp_sk(sk);

	sdp_dbg_ctrl(conn, "LISTEN: addr <%08x:%04x> backlog <%04x>",
		     conn->src_addr, conn->src_port, backlog);

	sdp_conn_lock(conn);

	if (SS_UNCONNECTED != sock->state ||
	    (conn->state != SDP_CONN_ST_CLOSED &&
	     conn->state != SDP_CONN_ST_LISTEN)) {
		result = -EINVAL;
		goto done;
	}

	if (conn->state != SDP_CONN_ST_LISTEN) {
		result = sdp_inet_listen_start(conn);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> starting listen",
				     result);
			goto done;
		}

		if (!conn->src_port) {
			result = sdp_inet_port_get(conn, 0);
			if (result < 0) {
				sdp_dbg_warn(conn, "Error <%d> getting port",
					     result);
				goto done;
			}

			inet_sk(sk)->num   = conn->src_port;
			inet_sk(sk)->sport = htons(conn->src_port);
		}
	}

#if 0				/* BUG 2034 workaround. */
	conn->backlog_max = backlog;
#else
	conn->backlog_max = 1024;
#endif
	result = 0;

done:
	sdp_conn_unlock(conn);
	return result;
}

/*
 * sdp_inet_accept - accept a new socket from a listen socket
 */
static int sdp_inet_accept(struct socket *listen_sock,
			   struct socket *accept_sock, int flags)
{
	struct sock *listen_sk;
	struct sock *accept_sk = NULL;
	struct sdp_sock *listen_conn;
	struct sdp_sock *accept_conn = NULL;
	int result;
	long timeout;

	listen_sk = listen_sock->sk;
	listen_conn = sdp_sk(listen_sk);

	sdp_dbg_ctrl(listen_conn, "ACCEPT: addr <%08x:%04x>",
		     listen_conn->src_addr, listen_conn->src_port);

	sdp_conn_lock(listen_conn);

	if (listen_conn->state != SDP_CONN_ST_LISTEN) {
		result = -EINVAL;
		goto listen_done;
	}

	timeout = sock_rcvtimeo(listen_sk, O_NONBLOCK & flags);
	/*
	 * if there is no socket on the queue, wait for one. It' done in a
	 * loop in case there is a problem with the first socket we hit.
	 */
	while (!accept_conn) {
		/*
		 * No pending socket wait.
		 */
		accept_conn = sdp_inet_accept_q_get(listen_conn);
		if (!accept_conn) {
			DECLARE_WAITQUEUE(wait, current);
			add_wait_queue(listen_sk->sk_sleep, &wait);
			set_current_state(TASK_INTERRUPTIBLE);

			while (timeout > 0 &&
			       listen_conn->state == SDP_CONN_ST_LISTEN &&
			       !listen_conn->backlog_cnt) {
				sdp_conn_unlock(listen_conn);
				timeout = schedule_timeout(timeout);
				sdp_conn_lock(listen_conn);

				if (signal_pending(current))
					break;
			}

			set_current_state(TASK_RUNNING);
			remove_wait_queue(listen_sk->sk_sleep, &wait);
			/*
			 * process result
			 */
			if (!listen_conn->backlog_cnt) {
				result = 0;

				if (listen_conn->state != SDP_CONN_ST_LISTEN)
					result = -EINVAL;
				if (signal_pending(current))
					result = sock_intr_errno(timeout);
				if (!timeout)
					result = -EAGAIN;

				goto listen_done;
			}
		} else {
			accept_sk = sk_sdp(accept_conn);

			switch (accept_conn->state) {
			case SDP_CONN_ST_REQ_RECV:
			case SDP_CONN_ST_ESTABLISHED:
			case SDP_CONN_ST_DIS_RECV_1:
				sock_graft(accept_sk, accept_sock);

				accept_conn->pid = current->pid;
				accept_sock->state = SS_CONNECTED;

				accept_sk->sk_write_space(accept_sk);

				break;
			default:
				/*
				 * this accept socket has problems, keep
				 * trying.
				 */
				/* AcceptQueueGet */
				sdp_conn_unlock(accept_conn);
				/* INET reference (AcceptQueue ref) */
				sdp_conn_put(accept_conn);

				accept_sk = NULL;
				accept_sock->sk = NULL;
				accept_conn = NULL;

				break;
			}

			if (accept_conn)
				/*
				 * Connections returned from the AcceptQueue
				 * are holding their lock, before returning
				 * the connection to the user, release the
				 * lock
				 */
				/* AcceptQueueGet */
				sdp_conn_unlock(accept_conn);
		}
	}

	result = 0;
listen_done:
	sdp_conn_unlock(listen_conn);

	sdp_dbg_ctrl(listen_conn,
		     "ACCEPT: complete <%d> <%08x:%04x><%08x:%04x>",
		     accept_conn ? accept_conn->hashent : SDP_DEV_SK_INVALID,
		     accept_sk ? accept_conn->src_addr : 0,
		     accept_sk ? accept_conn->src_port : 0,
		     accept_sk ? accept_conn->dst_addr : 0,
		     accept_sk ? accept_conn->dst_port : 0);

	return result;
}

/*
 * sdp_inet_getname - return a sockets address information
 */
static int sdp_inet_getname(struct socket *sock, struct sockaddr *uaddr,
			    int *size, int peer)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct sock *sk;
	struct sdp_sock *conn;

	sk = sock->sk;
	conn = sdp_sk(sk);

	sdp_dbg_ctrl(conn, "GETNAME: src <%08x:%04x> dst <%08x:%04x>",
		     conn->src_addr, conn->src_port,
		     conn->dst_addr, conn->dst_port);

	addr->sin_family = proto_family;
	if (peer > 0)
		if (htons(conn->dst_port) > 0 &&
		    !(SDP_ST_MASK_CLOSED & conn->state)) {

			addr->sin_port = htons(conn->dst_port);
			addr->sin_addr.s_addr = htonl(conn->dst_addr);
		} else
			return -ENOTCONN;
	else {
		addr->sin_port = htons(conn->src_port);
		addr->sin_addr.s_addr = htonl(conn->src_addr);
	}

	*size = sizeof(struct sockaddr_in);

	return 0;
}

/*
 * sdp_inet_poll - poll a socket for activity
 */
static unsigned int sdp_inet_poll(struct file *file, struct socket *sock,
				  poll_table *wait)
{
	struct sock *sk;
	struct sdp_sock *conn;
	unsigned int mask = 0;

	/*
	 * file and/or wait can be NULL, once poll is asleep and needs to
	 * recheck the falgs on being woken.
	 */
	sk = sock->sk;
	conn = sdp_sk(sk);

	sdp_dbg_data(conn, "POLL: socket flags <%08lx>", sock->flags);

	poll_wait(file, sk->sk_sleep, wait);
	/*
	 * general poll philosophy: too many mask bits are better then too
	 * few. POLLHUP is not direction maskable, and the recv path in more
	 * interesting for hang up. However, after receiving an EOF we want
	 * to be able to still select on write, if POLLHUP was set, this
	 * would not be possible.
	 */
	/*
	 * no locking, should be safe as is.
	 */
	switch (conn->state) {
	case SDP_CONN_ST_LISTEN:
		mask |= (conn->backlog_cnt > 0) ? (POLLIN | POLLRDNORM) : 0;
		break;
	case SDP_CONN_ST_ERROR:
		mask |= POLLERR;
		break;
	case SDP_CONN_ST_CLOSED:
		mask |= POLLHUP;
		break;
	case SDP_CONN_ST_ESTABLISHED:
		/*
		 * fall through
		 */
	default:
		/*
		 * recv EOF _and_ recv data
		 */
		if (!(conn->byte_strm < sk->sk_rcvlowat) ||
		    (RCV_SHUTDOWN & conn->shutdown))

			mask |= POLLIN | POLLRDNORM;
		/*
		 * send EOF _or_ send data space.
		 * (Some poll() Linux documentation says that POLLHUP is
		 *  incompatible with the POLLOUT/POLLWR flags)
		 */
		if (SEND_SHUTDOWN & conn->shutdown)
			mask |= POLLHUP;
		else {
			/*
			 * avoid race by setting flags, and only clearing
			 * them if the test is passed. Setting after the
			 * test, we can end up with them set and a passing
			 * test.
			 */
			set_bit(SOCK_ASYNC_NOSPACE, &sock->flags);
			set_bit(SOCK_NOSPACE, &sock->flags);

			if (sdp_inet_writable(conn)) {
				mask |= POLLOUT | POLLWRNORM;

				clear_bit(SOCK_ASYNC_NOSPACE, &sock->flags);
				clear_bit(SOCK_NOSPACE, &sock->flags);
			}
		}

		if (conn->rcv_urg_cnt > 0)
			mask |= POLLPRI;
	}

	sdp_dbg_data(conn, "POLL: mask <%08x> flags <%08lx> <%d:%d:%d>",
		     mask, sock->flags, conn->send_buf, conn->send_qud,
		     sdp_inet_writable(conn));


	return mask;
}

/*
 * sdp_inet_ioctl - serivce an ioctl request on a socket
 */
static int sdp_inet_ioctl(struct socket *sock, unsigned int cmd,
			  unsigned long arg)
{
	struct sock *sk;
	struct sdp_sock *conn;
	struct sdpc_buff *buff;
	int result = 0;
	int value;

	sk = sock->sk;
	conn = sdp_sk(sk);

	sdp_dbg_ctrl(conn, "IOCTL: command <%d> argument <%08lx>", cmd, arg);
	/*
	 * check IOCTLs
	 */
	switch (cmd) {
		/*
		 * standard INET IOCTLs
		 */
	case SIOCGSTAMP:
		if (!sk->sk_stamp.tv_sec)
			result = -ENOENT;
		else {
			result = copy_to_user((void __user *)arg,
					      &sk->sk_stamp,
					      sizeof(struct timeval));
			result = (result ? -EFAULT : result);
		}

		break;
		/*
		 * Standard routing IOCTLs
		 */
	case SIOCADDRT:
	case SIOCDELRT:
	case SIOCRTMSG:
		result = ip_rt_ioctl(cmd, (void __user *)arg);
		break;
		/*
		 * Standard ARP IOCTLs
		 */
	case SIOCDARP:
	case SIOCGARP:
	case SIOCSARP:
#if 0				/* currently not exported by the kernel :( */
		result = arp_ioctl(cmd, (void *)arg);
#else
		result = -ENOIOCTLCMD;
#endif
		break;
		/*
		 * standard INET device IOCTLs
		 */
	case SIOCGIFADDR:
	case SIOCSIFADDR:
	case SIOCGIFBRDADDR:
	case SIOCSIFBRDADDR:
	case SIOCGIFNETMASK:
	case SIOCSIFNETMASK:
	case SIOCGIFDSTADDR:
	case SIOCSIFDSTADDR:
	case SIOCSIFPFLAGS:
	case SIOCGIFPFLAGS:
	case SIOCSIFFLAGS:
		result = devinet_ioctl(cmd, (void __user *)arg);
		break;
		/*
		 * stadard INET STREAM IOCTLs
		 */
	case SIOCINQ:
		sdp_conn_lock(conn);

		if (conn->state != SDP_CONN_ST_LISTEN) {
			/*
			 * TODO need to subtract/add URG (inline vs. OOB)
			 */
			value = conn->byte_strm;
			result = put_user(value, (int __user *) arg);
		} else
			result = -EINVAL;

		sdp_conn_unlock(conn);
		break;
	case SIOCOUTQ:
		sdp_conn_lock(conn);

		if (conn->state != SDP_CONN_ST_LISTEN) {
			value = conn->send_qud;
			result = put_user(value, (int __user *) arg);
		} else
			result = -EINVAL;

		sdp_conn_unlock(conn);
		break;
	case SIOCATMARK:
		sdp_conn_lock(conn);

		value = 0;

		if (conn->rcv_urg_cnt > 0) {
			buff = sdp_buff_q_look_head(&conn->recv_pool);
			if (buff &&
			    (buff->flags & SDP_BUFF_F_OOB_PRES) &&
			    1 == (buff->tail - buff->data))
				value = 1;
		}

		result = put_user(value, (int __user *) arg);

		sdp_conn_unlock(conn);
		break;
	default:
		result = dev_ioctl(cmd, (void __user *)arg);
		break;
	}

	return result;
}

/*
 * sdp_inet_setopt - set a socket option
 */
static int sdp_inet_setopt(struct socket *sock, int level, int optname,
			   char __user *optval, int optlen)
{
	struct sock *sk;
	struct sdp_sock *conn;
	int value;
	int result = 0;

	sk = sock->sk;
	conn = sdp_sk(sk);

	sdp_dbg_ctrl(conn, "SETSOCKOPT: level <%d> option <%d>",
		     level, optname);

	if (SOL_TCP != level && SOL_SDP != level)
		return 0;
	if (optlen < sizeof(int))
		return -EINVAL;
	if (get_user(value, (int __user *)optval))
		return -EFAULT;

	sdp_conn_lock(conn);

	switch (optname) {
	case TCP_NODELAY:
		conn->nodelay = value ? 1 : 0;

		if (conn->nodelay > 0)
			(void)sdp_send_flush(conn);

		break;
	case SDP_ZCOPY_THRSH:
		conn->src_zthresh = value;
		conn->snk_zthresh =
		    ((value >
		      (conn->recv_size -
		       SDP_MSG_HDR_SIZE)) ? value : (conn->recv_size -
							SDP_MSG_HDR_SIZE));
		break;
	case SDP_ZCOPY_THRSH_SRC:
		conn->src_zthresh = value;
		break;
	case SDP_ZCOPY_THRSH_SNK:
		conn->snk_zthresh =
		    ((value >
		      (conn->recv_size -
		       SDP_MSG_HDR_SIZE)) ? value : (conn->recv_size -
							SDP_MSG_HDR_SIZE));
		break;
	case SDP_UNBIND:
		result = sdp_inet_port_put(conn);
		break;
	default:
		sdp_warn("SETSOCKOPT unimplemented option <%d:%d> conn <%d>.",
			 level, optname, conn->hashent);
		break;
	}

	sdp_conn_unlock(conn);
	return result;
}

/*
 * sdp_inet_getopt - get a socket option
 */
static int sdp_inet_getopt(struct socket *sock, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	struct sock *sk;
	struct sdp_sock *conn;
	int value;
	int len;

	sk = sock->sk;
	conn = sdp_sk(sk);

	sdp_dbg_ctrl(conn, "GETSOCKOPT: level <%d> option <%d>",
		     level, optname);

	if (SOL_TCP != level && SOL_SDP != level)
		return 0;
	if (get_user(len, optlen))
		return -EFAULT;

	len = min(len, (int)sizeof(int));
	if (len < 0)
		return -EINVAL;

	sdp_conn_lock(conn);

	switch (optname) {
	case TCP_NODELAY:
		value = (1 == conn->nodelay);
		break;
	case TCP_MAXSEG:
		value = max(conn->send_size, (u16)1);
		break;
	case SDP_ZCOPY_THRSH:
		value = ((conn->src_zthresh == conn->snk_zthresh) ?
			 conn->snk_zthresh : -EPROTO);
		break;
	case SDP_ZCOPY_THRSH_SRC:
		value = conn->src_zthresh;
		break;
	case SDP_ZCOPY_THRSH_SNK:
		value = conn->snk_zthresh;
		break;
	default:
		sdp_warn("GETSOCKOPT unimplemented option <%d:%d> conn <%d>",
			 level, optname, conn->hashent);
		break;
	}

	sdp_conn_unlock(conn);

	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, &value, len))
		return -EFAULT;

	return 0;
}

/*
 * sdp_inet_shutdown - shutdown a socket
 */
static int sdp_inet_shutdown(struct socket *sock, int flag)
{
	int result = 0;
	struct sdp_sock *conn;

	conn = sdp_sk(sock->sk);

	sdp_dbg_ctrl(conn, "SHUTDOWN: flag <%d>", flag);
	/*
	 * flag: 0 - recv shutdown
	 *       1 - send shutdown
	 *       2 - send/recv shutdown.
	 */
	if (flag < 0 || flag > 2)
		return -EINVAL;
	else
		flag++;		/* match shutdown mask. */

	sdp_conn_lock(conn);

	conn->shutdown |= flag;

	switch (conn->state) {
	case SDP_CONN_ST_REQ_PATH:
	case SDP_CONN_ST_REQ_SENT:
		/*
		 * outstanding request. Mark it in error, and
		 * completions needs to complete the closing.
		 */
		SDP_CONN_ST_SET(conn, SDP_CONN_ST_ERROR);
		sock->sk->sk_err = ECONNRESET;
		break;
	case SDP_CONN_ST_LISTEN:
		if (flag & RCV_SHUTDOWN) {
			result = sdp_inet_listen_stop(conn);
			if (result < 0)
				sdp_dbg_warn(conn, "listen stop error <%d>",
					     result);
		}

		break;
	case SDP_CONN_ST_CLOSED:
	case SDP_CONN_ST_ERROR:
		result = -ENOTCONN;
		break;
	default:
		if (!(flag & RCV_SHUTDOWN)) {
			result = sdp_inet_disconnect(conn);
			if (result < 0)
				sdp_dbg_warn(conn, "disconnect error <%d>",
					     result);
		}

		break;
	}

	sock->sk->sk_state_change(sock->sk);
	sdp_conn_unlock(conn);
	return result;
}

/*
 * Primary socket initialization
 */
static struct proto_ops lnx_stream_ops = {
	.family     = AF_INET_SDP,
	.release    = sdp_inet_release,
	.bind       = sdp_inet_bind,
	.connect    = sdp_inet_connect,
	.listen     = sdp_inet_listen,
	.accept     = sdp_inet_accept,
	.sendmsg    = sdp_inet_send,
	.recvmsg    = sdp_inet_recv,
	.getname    = sdp_inet_getname,
	.poll       = sdp_inet_poll,
	.setsockopt = sdp_inet_setopt,
	.getsockopt = sdp_inet_getopt,
	.shutdown   = sdp_inet_shutdown,
	.ioctl      = sdp_inet_ioctl,
	.sendpage   = sock_no_sendpage,
	.socketpair = sock_no_socketpair,
	.mmap       = sock_no_mmap,
	.owner      = THIS_MODULE,
};

/*
 * sdp_inet_create - create a socket
 */
static int sdp_inet_create(struct socket *sock, int protocol)
{
	struct sdp_sock *conn;

	sdp_dbg_ctrl(NULL, "SOCKET: type <%d> proto <%d> state <%u:%08lx>",
		     sock->type, protocol, sock->state, sock->flags);

	if (SOCK_STREAM != sock->type ||
	    (IPPROTO_IP != protocol && IPPROTO_TCP != protocol)) {
		sdp_dbg_warn(NULL, "SOCKET: unsupported type/proto. <%d:%d>",
			     sock->type, protocol);

		return -EPROTONOSUPPORT;
	}

	conn = sdp_conn_alloc(GFP_KERNEL);
	if (!conn) {
		sdp_dbg_warn(conn, "SOCKET: failed to create socket <%d:%d>",
			     sock->type, protocol);
		return -ENOMEM;
	}

	sock->ops = &lnx_stream_ops;
	sock->state = SS_UNCONNECTED;

	sock_graft(sk_sdp(conn), sock);

	conn->pid = current->pid;

#if 0				/* CPU affinity testing... */
#if 1
	current->cpus_allowed = (1 << 1);
#else
	current->cpus_allowed = (1 << 2) | (1 << 3);
#endif
#endif

	return 0;
}

/*
 * INET module initialization functions
 */
static struct net_proto_family sdp_proto = {
	.family = AF_INET_SDP,
	.create = sdp_inet_create,
	.owner  = THIS_MODULE,
};

/*
 * SDP host module load/unload functions
 */

/*
 * sdp_init - initialize the sdp host module
 */
static int __init sdp_init(void)
{
	int result = 0;

	sdp_dbg_init("SDP module load.");

	/*
	 * proc entries
	 */
	result = sdp_main_proc_init();
	if (result < 0) {
		sdp_warn("Error <%d> creating proc entries.", result);
		goto error_proc;
	}
	/*
	 * advertisment table
	 */
	result = sdp_main_advt_init();
	if (result < 0) {
		sdp_warn("Error <%d> initializing advertisments", result);
		goto error_advt;
	}
	/*
	 * link data
	 */
	result = sdp_link_addr_init();
	if (result < 0) {
		sdp_warn("Error <%d> initializing link", result);
		goto error_link;
	}
	/*
	 * buffer memory
	 */
	result = sdp_buff_pool_init();
	if (result < 0) {
		sdp_warn("Error <%d> initializing buffer pool.", result);
		goto error_buff;
	}
	/*
	 * connection table
	 */
	result = sdp_conn_table_init(proto_family,
				     conn_size,
				     recv_post_max,
				     recv_buff_max,
				     send_post_max,
				     send_buff_max,
				     send_usig_max);
	if (result < 0) {
		sdp_warn("Error <%d> initializing connection table.", result);
		goto error_conn;
	}
	/*
	 * register
	 */
	sdp_proto.family = proto_family;

	result = sock_register(&sdp_proto);
	if (result < 0) {
		sdp_warn("Error <%d> registering protocol family <%d>",
			 result, sdp_proto.family);
		goto error_sock;
	}

	return 0;
error_sock:
	sdp_conn_table_clear();
error_conn:
	sdp_buff_pool_destroy();
error_buff:
	sdp_link_addr_cleanup();
error_link:
	sdp_main_advt_cleanup();
error_advt:
	sdp_main_proc_cleanup();
error_proc:
	return result;		/* success */
}

/*
 * sdp_exit - cleanup the sdp host module
 */
static void __exit sdp_exit(void)
{
	sdp_dbg_init("SDP module unload.");
	/*
	 * unregister
	 */
	sock_unregister(sdp_proto.family);

	/*
	 * Make sure there are no deferred iocbs
	 */
	flush_scheduled_work();

	/*
	 * connection table
	 */
	sdp_conn_table_clear();
	/*
	 * delete buffer memory
	 */
	sdp_buff_pool_destroy();
	/*
	 * delete link information
	 */
	sdp_link_addr_cleanup();
	/*
	 * delete advertisment table
	 */
	sdp_main_advt_cleanup();
	/*
	 * proc tables
	 */
	sdp_main_proc_cleanup();
}

module_init(sdp_init);
module_exit(sdp_exit);

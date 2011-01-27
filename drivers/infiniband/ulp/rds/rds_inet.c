/*
 * Copyright (c) 2005 SilverStorm Technologies, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials
 * provided with the distribution.
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
 */

#include "rds.h"

#include <net/udp.h>
#include <net/inet_common.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>

static int proto_family = AF_INET_RDS;

MODULE_AUTHOR("Ranjit Pandit");
MODULE_DESCRIPTION("InfiniBand RDS module");
MODULE_LICENSE("Dual BSD/GPL");

static struct net_device *xxx_ip_dev_find(u32 addr)
{
	struct net_device *dev;
	struct in_ifaddr **ifap;
	struct in_ifaddr *ifa;
	struct in_device *in_dev;

	read_lock(&dev_base_lock);
	for (dev = dev_base; dev; dev = dev->next)
		if ((in_dev = in_dev_get(dev))) {
			for (ifap = &in_dev->ifa_list; (ifa = *ifap);
				ifap = &ifa->ifa_next) {
					if (addr == ifa->ifa_address) {
						dev_hold(dev);
						in_dev_put(in_dev);
						goto found;
					}
			}
			in_dev_put(in_dev);
		}
found:
	read_unlock(&dev_base_lock);
	return dev;
}

#define ip_dev_find xxx_ip_dev_find

static int rds_ops_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	int err = 0;
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	unsigned short port_num;
	struct net_device *dev;
	struct rds_cb *cb;

	//struct rb_node * node;

#if 0
	/*
	* Check if this process has permission to bind
	* Always allow Group ID 0 (root)
	*/

	if (current->gid !=0 && enable_groupid_table) {
		int i, found=0;

		for (i=0; (i< sizeof(allow_gids)) && !found; i++){
			if (current->gid == allow_gids[i])
				found=1;
		}
		if (!found)
			return -EACCES;
	}
#endif

	if (!addr->sin_addr.s_addr)
		return -EADDRNOTAVAIL;

	dev = ip_dev_find(addr->sin_addr.s_addr);

	if (dev)
		dev_put(dev);

	if (!dev || (!(dev->flags & IFF_LOOPBACK) && dev->type != ARPHRD_INFINIBAND)) {
		u8 *tmp;
		tmp = (u8 *)&addr->sin_addr.s_addr;
		printk("rds: bind failed; %d.%d.%d.%d not a valid IPoIB interface address!\n",
			tmp[0], tmp[1], tmp[2], tmp[3]);

		return -EADDRNOTAVAIL;
	}

	port_num = ntohs(addr->sin_port);

	err = inet_dgram_ops.bind(sock, uaddr, addr_len);

	if (err)
		return err;

	/* Create an RDS control block for this socket */
	cb = rds_alloc_cb(sock->sk);
	if (cb == NULL) {
		printk("rds: could not allocate control block for the socket 0x%p !\n", sock);
		return -EAGAIN;
	}
	cb->port_num = inet_sk(sock->sk)->sport;

	sock->sk->sk_user_data = (void*)cb;

	if (rds_insert_port(cb)) {
		printk("rds: port <%d> already exists\n", cb->port_num);
		return -EAGAIN;
	}

	return 0;
}

static int rds_ops_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	int err;

	if (!sock->sk->sk_user_data)
		err = rds_ops_bind(sock, uaddr, addr_len);

	err = inet_dgram_ops.connect(sock,uaddr,addr_len, flags);

	return err;
}

static int rds_ops_getname(struct socket *sock, struct sockaddr *uaddr,
			int *uaddr_len, int peer)
{
	int err;
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	u8 *addr;

	err = inet_dgram_ops.getname(sock,uaddr,uaddr_len,peer);
	addr = (u8 *) &sin->sin_addr.s_addr;

#if 0
	printk("sin_family 0x%x, sin_port %d, IP %d.%d.%d.%d\n",
		sin->sin_family, ntohs(sin->sin_port),
		addr[0], addr[1], addr[2], addr[3]);
#endif
	sin->sin_family = AF_INET_RDS;
	return err;
}

static int rds_ops_ioctl(struct socket *sock, unsigned int cmd,
			unsigned long arg)
{
	int err;

	sock->sk->sk_family = AF_INET;

	err = inet_dgram_ops.ioctl(sock,cmd,arg);

	switch(cmd)
	{
		case SIOCGIFCONF:
		{
			struct ifconf *ifc;
			struct ifreq *ifr;
			int numifs, i;
			struct sockaddr_in *addr;
			ifc = (struct ifconf*)arg;

			numifs = (int) (((size_t)ifc->ifc_len) / sizeof(struct ifreq));
			if (ifc->ifc_buf) {
				for (i = 0, ifr = (struct ifreq *)ifc->ifc_buf;
					i < numifs; i++, ifr++) {
					struct net_device *dev;

					addr=(struct sockaddr_in *)&ifr->ifr_addr;
					dev = ip_dev_find(addr->sin_addr.s_addr);
					if (dev) {
						dev_put(dev);
						if (dev->type == ARPHRD_INFINIBAND) {
							ifr->ifr_addr.sa_family = AF_INET_RDS;
						}
					}
				}
			}
			break;
		}
		case SIOCGIFFLAGS:
		{
			struct ifreq *ifr;

			ifr = (struct ifreq *)arg;
			ifr->ifr_flags |= IFF_RUNNING;
			break;
		}

	}
	return err;
}

unsigned int
rds_ops_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct rds_cb *cb;
	struct sock *sk = sock->sk;
	unsigned int mask;

	poll_wait(file, sk->sk_sleep, wait);

	cb = (struct rds_cb*)sk->sk_user_data;

	if (!cb || cb->magic != RDS_MAGIC_CB)
		return -EAGAIN;

	mask = 0;
	if (atomic_read(&cb->recv_pending) > 0)
		mask |= POLLIN | POLLRDNORM;
	else
		rds_chk_port_quota(cb);

	/* As we don't do any send buffering on the socket level,
	* the socket is always ready to send.
	*/
	mask |= POLLOUT | POLLWRNORM | POLLWRBAND;

	return mask;
}

static int
rds_ops_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		size_t size)
{
	int err;
	err = inet_dgram_ops.sendmsg(iocb, sock, msg ,size);
	return err;

}

static int
rds_ops_recvmsg(struct kiocb *iocb, struct socket *sock,
		struct msghdr *msg, size_t size, int flags)
{
	int err;
	err = inet_dgram_ops.recvmsg(iocb, sock, msg, size, flags);
	return err;
}

static int
rds_ops_getsockopt(struct socket *sock, int level, int optname,
		   char *optval, int *optlen)
{
	int err;
	err = inet_dgram_ops.getsockopt(sock,level,optname,optval,optlen);
	return err;
}

static int
rds_ops_setsockopt(struct socket *sock, int level, int optname,
		   char *optval, int optlen)
{
	int err;
	err = inet_dgram_ops.setsockopt(sock,level,optname,optval,optlen);
	return err;

}
struct proto_ops rds_proto_ops = {

	.family = AF_INET_RDS,
	.release = inet_release,
	.shutdown = inet_shutdown,
	.bind = rds_ops_bind,
	.recvmsg = rds_ops_recvmsg,
	.sendmsg = rds_ops_sendmsg,
	.setsockopt = rds_ops_setsockopt,
	.getsockopt = rds_ops_getsockopt,
	.connect = rds_ops_connect,
	.getname = rds_ops_getname,
	.ioctl = rds_ops_ioctl,
	.poll = rds_ops_poll,
	.listen = sock_no_listen,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
	.owner = THIS_MODULE

};

static int rds_get_port(struct sock *sk, unsigned short snum)
{
	int err = 0;
	err = udp_prot.get_port(sk, snum);
	return err;
}

static void rds_close(struct sock *sk, long timeout)
{
	struct rds_cb *cb;

	/* get port control block */
	cb = (struct rds_cb*)sk->sk_user_data;

	if (!cb || cb->magic != RDS_MAGIC_CB)
		goto udpclose;

	rds_free_pending_recvs(cb);

	rds_chk_port_quota(cb);

	rds_delete_port(cb);

	rds_free_cb(cb);

udpclose:

	udp_prot.close(sk, timeout);

	module_put(THIS_MODULE);

}

static void rds_unhash(struct sock *sk)
{
	udp_prot.unhash(sk);
}

static int rds_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	return -ENOIOCTLCMD;
}

static int rds_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *sin = (struct sockaddr_in *) uaddr;
	struct udp_sock *udp_sk = (struct udp_sock *) sk;

	udp_sk->inet.daddr = sin->sin_addr.s_addr;
	udp_sk->inet.dport = sin->sin_port;

	return 0;
}
static int rds_setsockopt(struct sock *sk, int level, int optname, char *optval, int optlen)
{
	return -EINVAL;
}

static int rds_getsockopt(struct sock *sk, int level, int optname, char *optval, int *optlen)
{
	return -EINVAL;
}

static struct proto rds_proto = {
	.name = "RDS",
	.get_port = rds_get_port,
	.close = rds_close,
	.unhash = rds_unhash,
	.ioctl = rds_ioctl,
	.connect = rds_connect,
	.sendmsg = rds_sendmsg,
	.recvmsg = rds_recvmsg,
	.setsockopt = rds_setsockopt,
	.getsockopt = rds_getsockopt
};


static int rds_inet_create(struct socket *sock, int protocol)
{
	int err = 0;
	struct socket *inet_socket;
	struct sock *new_sk;

	if (SOCK_DGRAM != sock->type ||
		(IPPROTO_IP != protocol && IPPROTO_UDP != protocol)) {
			printk("rds: unsupported type/proto. <%d:%d>\n",
				sock->type, protocol);

			err = -EPROTONOSUPPORT;
			goto error;
	}

	err = sock_create(PF_INET, sock->type, protocol, &inet_socket);
	if (err) {
		err = -ESOCKTNOSUPPORT;
		goto error;
	}
	/* swap the socks */
	new_sk = inet_socket->sk;
	new_sk->sk_socket = sock;
	new_sk->sk_sleep = &sock->wait;
	inet_socket->sk = NULL;
	sock->sk = new_sk;
	sock_release(inet_socket);

	/* change to use our vectors */

	sock->ops = &rds_proto_ops;
	sock->sk->sk_prot = &rds_proto;
	sock->sk->sk_protocol = IPPROTO_UDP;
	sock->sk->sk_no_check = 1;

	if (!try_module_get(THIS_MODULE)) {
		err = -EINVAL;
		goto error;
	}

	return 0;
error:
	return err;
}

/*
* inet module initialization functions
*/
static struct net_proto_family rds_family = {
	.family = AF_INET_RDS,
	.create = rds_inet_create,
	.owner = THIS_MODULE
};

/*
* rds_init
*/
static int rds_init(void)
{
	int err = 0;


	err = rds_init_globals();
	if (err) {
		printk("rds: error in initializing rds\n");
		goto error;
	}

	/*
	* register with socket
	*/
	rds_family.family = proto_family;

	err = sock_register(&rds_family);
	if (err < 0) {
		printk("rds: error <%d> registering RDS protocol family <%d>",
			err, rds_family.family);
		goto error;
	}

	printk("rds: sock register success\n");

	/* IB Init */
	err = rds_cma_init();
	if (err < 0) {
		printk("rds: error <%d> initializing IB\n", err);
		goto error;
	}

	return 0;

error:
	rds_cleanup_globals();

	return err;
}

/*
* rds_exit - cleanup rds
*/
static void rds_exit(void)
{
	if (rds_wq) {
		//flush_workqueue(rds_wq);
		destroy_workqueue(rds_wq);
	}

	/* Don't accept an new sockets */
	sock_unregister(rds_family.family);

	/* Don't accept any more connections */
	rds_cma_exit();

	rds_close_all_sessions();

	rds_cleanup_caches();

	printk("rds: unload complete\n");

}
module_init(rds_init);
module_exit(rds_exit);

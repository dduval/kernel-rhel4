/*
 * linux/fs/nfs/callback.c
 *
 * Copyright (C) 2004 Trond Myklebust
 *
 * NFSv4 callback handling
 */

#include <linux/config.h>
#include <linux/completion.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/nfs_fs.h>
#include "callback.h"

#define NFSDBG_FACILITY NFSDBG_CALLBACK

struct nfs_callback_data {
	unsigned int users;
	struct svc_serv *serv;
	pid_t pid;
	struct completion started;
	struct completion stopped;
};

static struct nfs_callback_data nfs_callback_info;
static DECLARE_MUTEX(nfs_callback_sema);
static struct svc_program nfs4_callback_program;

unsigned short nfs_callback_tcpport;

/*
 * This is the callback kernel thread.
 */
static void nfs_callback_svc(struct svc_rqst *rqstp)
{
	struct svc_serv *serv = rqstp->rq_server;
	int err;

	__module_get(THIS_MODULE);
	lock_kernel();

	nfs_callback_info.pid = current->pid;
	daemonize("nfsv4-svc");
	/* Process request with signals blocked, but allow SIGKILL.  */
	allow_signal(SIGKILL);

	complete(&nfs_callback_info.started);

	for(;;) {
		if (signalled()) {
			if (nfs_callback_info.users == 0)
				break;
			flush_signals(current);
		}
		/*
		 * Listen for a request on the socket
		 */
		err = svc_recv(serv, rqstp, MAX_SCHEDULE_TIMEOUT);
		if (err == -EAGAIN || err == -EINTR)
			continue;
		if (err < 0) {
			printk(KERN_WARNING
					"%s: terminating on error %d\n",
					__FUNCTION__, -err);
			break;
		}
		dprintk("%s: request from %u.%u.%u.%u\n", __FUNCTION__,
				NIPQUAD(rqstp->rq_addr.sin_addr.s_addr));
		svc_process(serv, rqstp);
	}

	flush_signals(current);
	svc_exit_thread(rqstp);
	nfs_callback_info.pid = 0;
	complete(&nfs_callback_info.stopped);
	unlock_kernel();
	module_put_and_exit(0);
}

/*
 * Bring up the server process if it is not already up.
 */
int nfs_callback_up(void)
{
	struct svc_serv *serv = NULL;
	struct svc_sock *svsk;
	int ret = 0;

	lock_kernel();
	down(&nfs_callback_sema);
	if (nfs_callback_info.users++ || nfs_callback_info.pid != 0)
		goto out;
	init_completion(&nfs_callback_info.started);
	init_completion(&nfs_callback_info.stopped);
	serv = svc_create(&nfs4_callback_program, NFS4_CALLBACK_BUFSIZE);
	ret = -ENOMEM;
	if (!serv)
		goto out_err;
	/* FIXME: We don't want to register this socket with the portmapper */
	ret = svc_makesock(serv, IPPROTO_TCP, 0);
	if (ret < 0)
		goto out_err;
	if (!list_empty(&serv->sv_permsocks)) {
		svsk = list_entry(serv->sv_permsocks.next,
				struct svc_sock, sk_list);
		nfs_callback_tcpport = ntohs(inet_sk(svsk->sk_sk)->sport);
		dprintk ("Callback port = 0x%x\n", nfs_callback_tcpport);
	} else
		BUG();
	ret = svc_create_thread(nfs_callback_svc, serv);
	if (ret < 0)
		goto out_err;
	nfs_callback_info.serv = serv;
	wait_for_completion(&nfs_callback_info.started);
out:
	/*
	 * svc_create creates the svc_serv with sv_nrthreads == 1, and then
	 * svc_create_thread increments that. So we need to call svc_destroy
	 * on both success and failure so that the refcount is 1 when the
	 * thread exits.
	 */
	if (serv)
		svc_destroy(serv);
	up(&nfs_callback_sema);
	unlock_kernel();
	return ret;
out_err:
	nfs_callback_info.users--;
	goto out;
}

/*
 * Kill the server process if it is not already up.
 */
int nfs_callback_down(void)
{
	int ret = 0;

	lock_kernel();
	down(&nfs_callback_sema);
	nfs_callback_info.users--;
	do {
		if (nfs_callback_info.users != 0 || nfs_callback_info.pid == 0)
			break;
		if (kill_proc(nfs_callback_info.pid, SIGKILL, 1) < 0)
			break;
	} while (wait_for_completion_timeout(&nfs_callback_info.stopped, 5*HZ) == 0);
	up(&nfs_callback_sema);
	unlock_kernel();
	return ret;
}

static int nfs_callback_auth(struct svc_rqst *rqstp, u32 *notused)
{
	struct in_addr *addr = &rqstp->rq_addr.sin_addr;
	struct nfs4_client *clp;

	dprintk("%s: %u.%u.%u.%u NFSv4 callback!\n", __FUNCTION__,
				NIPQUAD(rqstp->rq_addr.sin_addr.s_addr));
	/* Don't talk to strangers */
	clp = nfs4_find_client(addr);
	if (clp == NULL) {
		dprintk("%s: SVC_DROP: unknown client\n", __FUNCTION__);
		return SVC_DROP;
	}
	nfs4_put_client(clp);
	switch (rqstp->rq_authop->flavour) {
		case RPC_AUTH_NULL:
			if (rqstp->rq_proc != CB_NULL) {
				dprintk("%s: SVC_DENIED: bad proc %d\n", 
					__FUNCTION__, rqstp->rq_proc);
				return SVC_DENIED;
			}
			break;
		case RPC_AUTH_UNIX:
			break;
		case RPC_AUTH_GSS:
			/* FIXME: RPCSEC_GSS handling? */
		default:
			dprintk("%s: SVC_DENIED: flavour %d \n", 
				__FUNCTION__, rqstp->rq_authop->flavour);
			return SVC_DENIED;
	}
	return SVC_OK;
}

/*
 * Define NFS4 callback program
 */
extern struct svc_version nfs4_callback_version1;

static struct svc_version *nfs4_callback_version[] = {
	[1] = &nfs4_callback_version1,
};

static struct svc_stat nfs4_callback_stats;

static struct svc_program nfs4_callback_program = {
	.pg_prog = NFS4_CALLBACK,			/* RPC service number */
	.pg_nvers = ARRAY_SIZE(nfs4_callback_version),	/* Number of entries */
	.pg_vers = nfs4_callback_version,		/* version table */
	.pg_name = "NFSv4 callback",			/* service name */
	.pg_class = "nfs",				/* authentication class */
	.pg_stats = &nfs4_callback_stats,
	.pg_authenticate = nfs_callback_auth,
};

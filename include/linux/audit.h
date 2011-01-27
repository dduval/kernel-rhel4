/* audit.h -- Auditing support
 *
 * Copyright 2003-2004 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Written by Rickard E. (Rik) Faith <faith@redhat.com>
 *
 */

#ifndef _LINUX_AUDIT_H_
#define _LINUX_AUDIT_H_

#ifdef __KERNEL__
#include <linux/sched.h>
#include <linux/elf.h>
#include <linux/skbuff.h>

struct hlist_head;
struct hlist_node;
struct dentry;
#endif

/* The netlink messages for the audit system is divided into blocks:
 * 1000 - 1099 are for commanding the audit system
 * 1100 - 1199 user space trusted application messages
 * 1200 - 1299 messages internal to the audit daemon
 * 1300 - 1399 audit event messages
 * 1400 - 1499 SE Linux use
 * 1500 - 1599 kernel LSPP events
 * 1600 - 1699 kernel crypto events
 * 1700 - 1999 future kernel use (maybe integrity labels and related events)
 * 2000 is for otherwise unclassified kernel audit messages (legacy)
 * 2001 - 2099 unused (kernel)
 * 2100 - 2199 user space anomaly records
 * 2200 - 2299 user space actions taken in response to anomalies
 * 2300 - 2399 user space generated LSPP events
 * 2400 - 2499 user space crypto events
 * 2500 - 2999 future user space (maybe integrity labels and related events)
 *
 * Messages from 1000-1199 are bi-directional. 1200-1299 & 2100 - 2999 are
 * exclusively user space. 1300-2099 is kernel --> user space 
 * communication.
 */
#define AUDIT_GET		1000	/* Get status */
#define AUDIT_SET		1001	/* Set status (enable/disable/auditd) */
#define AUDIT_LIST		1002	/* List syscall filtering rules */
#define AUDIT_ADD		1003	/* Add syscall filtering rule */
#define AUDIT_DEL		1004	/* Delete syscall filtering rule */
#define AUDIT_USER		1005	/* Message from userspace -- deprecated */
#define AUDIT_LOGIN		1006	/* Define the login id and information */
#define AUDIT_WATCH_INS		1007	/* Insert file/dir watch entry */
#define AUDIT_WATCH_REM		1008	/* Remove file/dir watch entry */
#define AUDIT_WATCH_LIST	1009	/* List all file/dir watches */
#define AUDIT_SIGNAL_INFO	1010	/* Get info about sender of signal to auditd */

#define AUDIT_FIRST_USER_MSG	1100	/* Userspace messages mostly uninteresting to kernel */
#define AUDIT_USER_AVC		1107	/* We filter this differently */
#define AUDIT_LAST_USER_MSG	1199
#define AUDIT_FIRST_USER_MSG2	2100	/* More user space messages */
#define AUDIT_LAST_USER_MSG2	2999
 
#define AUDIT_DAEMON_START      1200    /* Daemon startup record */
#define AUDIT_DAEMON_END        1201    /* Daemon normal stop record */
#define AUDIT_DAEMON_ABORT      1202    /* Daemon error stop record */
#define AUDIT_DAEMON_CONFIG     1203    /* Daemon config change */

#define AUDIT_SYSCALL		1300	/* Syscall event */
#define AUDIT_FS_WATCH		1301	/* Filesystem watch event */
#define AUDIT_PATH		1302	/* Filename path information */
#define AUDIT_IPC		1303	/* IPC record */
#define AUDIT_SOCKETCALL	1304	/* sys_socketcall arguments */
#define AUDIT_CONFIG_CHANGE	1305	/* Audit system configuration change */
#define AUDIT_SOCKADDR		1306	/* sockaddr copied as syscall arg */
#define AUDIT_CWD		1307	/* Current working directory */
#define AUDIT_FS_INODE		1308	/* File system inode */
#define AUDIT_EXECVE		1309	/* execve arguments */

#define AUDIT_AVC		1400	/* SE Linux avc denial or grant */
#define AUDIT_SELINUX_ERR	1401	/* Internal SE Linux Errors */
#define AUDIT_AVC_PATH		1402	/* dentry, vfsmount pair from avc */

#define AUDIT_KERNEL		2000	/* Asynchronous audit record. NOT A REQUEST. */

/* Rule flags */
#define AUDIT_FILTER_USER	0x00	/* Apply rule to user-generated messages */
#define AUDIT_FILTER_TASK	0x01	/* Apply rule at task creation (not syscall) */
#define AUDIT_FILTER_ENTRY	0x02	/* Apply rule at syscall entry */
#define AUDIT_FILTER_WATCH	0x03	/* Apply rule to file system watches */
#define AUDIT_FILTER_EXIT	0x04	/* Apply rule at syscall exit */

#define AUDIT_NR_FILTERS	5

#define AUDIT_FILTER_PREPEND	0x10	/* Prepend to front of list */

/* Rule actions */
#define AUDIT_NEVER    0	/* Do not build context if rule matches */
#define AUDIT_POSSIBLE 1	/* Build context if rule matches  */
#define AUDIT_ALWAYS   2	/* Generate audit record if rule matches */

/* Rule structure sizes -- if these change, different AUDIT_ADD and
 * AUDIT_LIST commands must be implemented. */
#define AUDIT_MAX_FIELDS   64
#define AUDIT_BITMASK_SIZE 64
#define AUDIT_WORD(nr) ((__u32)((nr)/32))
#define AUDIT_BIT(nr)  (1 << ((nr) - AUDIT_WORD(nr)*32))

/* Rule fields */
				/* These are useful when checking the
				 * task structure at task creation time
				 * (AUDIT_PER_TASK).  */
#define AUDIT_PID	0
#define AUDIT_UID	1
#define AUDIT_EUID	2
#define AUDIT_SUID	3
#define AUDIT_FSUID	4
#define AUDIT_GID	5
#define AUDIT_EGID	6
#define AUDIT_SGID	7
#define AUDIT_FSGID	8
#define AUDIT_LOGINUID	9
#define AUDIT_PERS	10
#define AUDIT_ARCH	11

				/* These are ONLY useful when checking
				 * at syscall exit time (AUDIT_AT_EXIT). */
#define AUDIT_DEVMAJOR	100
#define AUDIT_DEVMINOR	101
#define AUDIT_INODE	102
#define AUDIT_EXIT	103
#define AUDIT_SUCCESS   104	/* exit >= 0; value ignored */

#define AUDIT_ARG0      200
#define AUDIT_ARG1      (AUDIT_ARG0+1)
#define AUDIT_ARG2      (AUDIT_ARG0+2)
#define AUDIT_ARG3      (AUDIT_ARG0+3)

#define AUDIT_NEGATE    0x80000000


/* Status symbols */
				/* Mask values */
#define AUDIT_STATUS_ENABLED		0x0001
#define AUDIT_STATUS_FAILURE		0x0002
#define AUDIT_STATUS_PID		0x0004
#define AUDIT_STATUS_RATE_LIMIT		0x0008
#define AUDIT_STATUS_BACKLOG_LIMIT	0x0010
				/* Failure-to-log actions */
#define AUDIT_FAIL_SILENT	0
#define AUDIT_FAIL_PRINTK	1
#define AUDIT_FAIL_PANIC	2

/* distinguish syscall tables */
#define __AUDIT_ARCH_64BIT 0x80000000
#define __AUDIT_ARCH_LE	   0x40000000
#define AUDIT_ARCH_ALPHA	(EM_ALPHA|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_ARM		(EM_ARM|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_ARMEB	(EM_ARM)
#define AUDIT_ARCH_CRIS		(EM_CRIS|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_FRV		(EM_FRV)
#define AUDIT_ARCH_H8300	(EM_H8_300)
#define AUDIT_ARCH_I386		(EM_386|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_IA64		(EM_IA_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_M32R		(EM_M32R)
#define AUDIT_ARCH_M68K		(EM_68K)
#define AUDIT_ARCH_MIPS		(EM_MIPS)
#define AUDIT_ARCH_MIPSEL	(EM_MIPS|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_MIPS64	(EM_MIPS|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_MIPSEL64	(EM_MIPS|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_PARISC	(EM_PARISC)
#define AUDIT_ARCH_PARISC64	(EM_PARISC|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_PPC		(EM_PPC)
#define AUDIT_ARCH_PPC64	(EM_PPC64|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_S390		(EM_S390)
#define AUDIT_ARCH_S390X	(EM_S390|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_SH		(EM_SH)
#define AUDIT_ARCH_SHEL		(EM_SH|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_SH64		(EM_SH|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_SHEL64	(EM_SH|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_SPARC	(EM_SPARC)
#define AUDIT_ARCH_SPARC64	(EM_SPARC64|__AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_V850		(EM_V850|__AUDIT_ARCH_LE)
#define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)

/* 32 byte max key size */
#define AUDIT_FILTERKEY_MAX   32

struct audit_status {
	__u32		mask;		/* Bit mask for valid entries */
	__u32		enabled;	/* 1 = enabled, 0 = disabled */
	__u32		failure;	/* Failure-to-log action */
	__u32		pid;		/* pid of auditd process */
	__u32		rate_limit;	/* messages rate limit (per second) */
	__u32		backlog_limit;	/* waiting messages limit */
	__u32		lost;		/* messages lost */
	__u32		backlog;	/* messages waiting in queue */
};

struct audit_rule {		/* for AUDIT_LIST, AUDIT_ADD, and AUDIT_DEL */
	__u32		flags;	/* AUDIT_PER_{TASK,CALL}, AUDIT_PREPEND */
	__u32		action;	/* AUDIT_NEVER, AUDIT_POSSIBLE, AUDIT_ALWAYS */
	__u32		field_count;
	__u32		mask[AUDIT_BITMASK_SIZE];
	__u32		fields[AUDIT_MAX_FIELDS];
	__u32		values[AUDIT_MAX_FIELDS];
};

/* Structure to transport watch data to and from the kernel */

struct watch_transport {
	__u32 dev_major;
	__u32 dev_minor;
	__u32 perms;
	__u32 valid;
	__u32 pathlen;
	__u32 fklen;
	char buf[0];
};

#ifdef __KERNEL__
/* Structure associated with inode->i_audit */

struct audit_watch {
	atomic_t		w_count;
	struct hlist_node 	w_node;		/* per-directory list	      */
	struct hlist_node	w_master;	/* Master watch list	      */
	struct hlist_node	w_watched;	/* Watches on inode	      */
	dev_t			w_dev;		/* Superblock device	      */
	__u32			w_perms;	/* Permissions filtering      */
	char			*w_name;	/* Watch point beneath parent */
	char			*w_path;	/* Insertion path             */
	char			*w_filterkey;	/* An arbitrary filtering key */
};

struct audit_inode_data {
	int			count;
	struct audit_inode_data *next_hash;	/* Watch data hash table      */
	struct inode		*inode;		/* Inode to which it belongs  */
	struct hlist_head	watches;	/* List of watches on inode   */
	struct hlist_head 	watchlist;	/* Watches for children       */
};


struct audit_sig_info {
	uid_t		uid;
	pid_t		pid;
};

struct audit_watch_info {
	struct hlist_node node;
	struct audit_watch *watch;
};

struct audit_buffer;
struct audit_context;
struct inode;
struct netlink_skb_parms;
struct linux_binprm;

#define AUDITSC_INVALID 0
#define AUDITSC_SUCCESS 1
#define AUDITSC_FAILURE 2
#define AUDITSC_RESULT(x) ( ((long)(x))<0?AUDITSC_FAILURE:AUDITSC_SUCCESS )
#ifdef CONFIG_AUDITSYSCALL
/* These are defined in auditsc.c */
				/* Public API */
extern int  audit_alloc(struct task_struct *task);
extern void audit_free(struct task_struct *task);
extern void audit_syscall_entry(struct task_struct *task, int arch,
				int major, unsigned long a0, unsigned long a1,
				unsigned long a2, unsigned long a3);
extern void audit_syscall_exit(struct task_struct *task, int failed, long return_code);
extern void audit_getname(const char *name);
extern void audit_putname(const char *name);
extern void audit_inode(const char *name, const struct inode *inode, unsigned flags);

				/* Private API (for audit.c only) */
extern int  audit_receive_filter(int type, int pid, int uid, int seq,
				 void *data, uid_t loginuid);
extern unsigned int audit_serial(void);
extern void auditsc_get_stamp(struct audit_context *ctx,
			    struct timespec *t, unsigned int *serial);
extern int  audit_set_loginuid(struct task_struct *task, uid_t loginuid);
extern uid_t audit_get_loginuid(struct audit_context *ctx);
extern int audit_ipc_perms(unsigned long qbytes, uid_t uid, gid_t gid, mode_t mode);
extern int audit_bprm(struct linux_binprm *bprm);
extern int audit_socketcall(int nargs, unsigned long *args);
extern int audit_sockaddr(int len, void *addr);
extern int audit_avc_path(struct dentry *dentry, struct vfsmount *mnt);
extern void audit_signal_info(int sig, struct task_struct *t);
extern int audit_filter_user(struct netlink_skb_parms *cb, int type);
extern void audit_panic(const char *);
struct audit_netlink_list {
	int pid;
	struct sk_buff_head q;
};

int audit_send_list(void *);

#else
#define audit_alloc(t) ({ 0; })
#define audit_free(t) do { ; } while (0)
#define audit_syscall_entry(t,ta,a,b,c,d,e) do { ; } while (0)
#define audit_syscall_exit(t,f,r) do { ; } while (0)
#define audit_getname(n) do { ; } while (0)
#define audit_putname(n) do { ; } while (0)
#define audit_inode(n,i,f) do { ; } while (0)
#define auditsc_get_stamp(c,t,s) do { BUG(); } while (0)
#define audit_receive_filter(t,p,u,s,d,l) ({ -EOPNOTSUPP; })
#define audit_get_loginuid(c) ({ -1; })
#define audit_ipc_perms(q,u,g,m) ({ 0; })
#define audit_bprm(p) ({ 0; })
#define audit_socketcall(n,a) ({ 0; })
#define audit_sockaddr(len, addr) ({ 0; })
#define audit_avc_path(dentry, mnt) ({ 0; })
#define audit_signal_info(s,t) do { ; } while (0)
#define audit_filter_user(cb,t) ({ 1; })
#endif

#ifdef CONFIG_AUDITFILESYSTEM
extern int audit_filesystem_init(void);
extern int audit_list_watches(int pid, int seq);
extern int audit_receive_watch(int type, int pid, int uid, int seq,
			       struct watch_transport *req, uid_t loginuid);
extern void audit_inode_free(struct inode *inode);
extern void audit_update_watch(struct dentry *dentry, int remove);
extern void audit_watch_put(struct audit_watch *watch);
extern struct audit_watch *audit_watch_get(struct audit_watch *watch);
extern void audit_notify_watch(struct inode *inode, int mask);
extern void auditfs_attach_wdata(struct inode *inode, struct hlist_head *watches,
				 int mask);
#else
#define audit_filesystem_init() ({ 0; })
#define audit_list_watches(p,s) ({ -EOPNOTSUPP; })
#define audit_receive_watch(t,p,u,s,r,l) ({ -EOPNOTSUPP; })
#define audit_inode_free(i) do { ; } while(0)
#define audit_update_watch(d,r) do { ; } while (0)
#define audit_watch_put(w) do { ; } while(0)
#define audit_watch_get(w) ({ 0; })
#define audit_notify_watch(i,m) do { ; } while(0)
#endif

#ifdef CONFIG_AUDIT
/* These are defined in audit.c */
				/* Public API */
extern void		    audit_log(struct audit_context *ctx, int gfp_mask,
				      int type, const char *fmt, ...)
				      __attribute__((format(printf,4,5)));

extern struct audit_buffer *audit_log_start(struct audit_context *ctx, int gfp_mask, int type);
extern void		    audit_log_format(struct audit_buffer *ab,
					     const char *fmt, ...)
			    __attribute__((format(printf,2,3)));
extern void		    audit_log_end(struct audit_buffer *ab);
extern void		    audit_log_end_fast(struct audit_buffer *ab);
extern void		    audit_log_end_irq(struct audit_buffer *ab);
extern void		    audit_log_hex(struct audit_buffer *ab, const unsigned char *buf,
					  size_t len);
extern void		    audit_log_n_string(struct audit_buffer *ab, size_t slen,
						const char *string);
extern int		    audit_string_contains_control(const char *string, size_t len);
extern void		    audit_log_n_untrustedstring(struct audit_buffer *ab, size_t len,
							const char *string);

extern void		    audit_log_untrustedstring(struct audit_buffer *ab,
						      const char *string);
extern void		    audit_log_d_path(struct audit_buffer *ab,
					     const char *prefix,
					     struct dentry *dentry,
					     struct vfsmount *vfsmnt);
extern int		    audit_set_rate_limit(int limit, uid_t loginuid);
extern int		    audit_set_backlog_limit(int limit, uid_t loginuid);
extern int		    audit_set_enabled(int state, uid_t loginuid);
extern int		    audit_set_failure(int state, uid_t loginuid);

				/* Private API (for auditsc.c only) */
extern struct sk_buff *	    audit_make_reply(int pid, int seq, int type,
					    int done, int multi,
					    void *payload, int size);

extern void		    audit_send_reply(int pid, int seq, int type,
					     int done, int multi,
					     void *payload, int size);
extern void		    audit_log_lost(const char *message);
extern struct semaphore audit_netlink_sem;
#else
#define audit_log(c,t,f,...) do { ; } while (0)
#define audit_log_start(c,t) ({ NULL; })
#define audit_log_vformat(b,f,a) do { ; } while (0)
#define audit_log_format(b,f,...) do { ; } while (0)
#define audit_log_end(b) do { ; } while (0)
#define audit_log_end_fast(b) do { ; } while (0)
#define audit_log_end_irq(b) do { ; } while (0)
#define audit_log_hex(a,b,l) do { ; } while (0)
#define audit_log_untrustedstring(a,s) do { ; } while (0)
#define audit_log_d_path(b,p,d,v) do { ; } while (0)
#define audit_set_rate_limit(l) do { ; } while (0)
#define audit_set_backlog_limit(l) do { ; } while (0)
#define audit_set_enabled(s) do { ; } while (0)
#define audit_set_failure(s) do { ; } while (0)
#endif
#endif
#endif

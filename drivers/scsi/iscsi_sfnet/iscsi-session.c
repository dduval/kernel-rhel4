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
 * $Id: iscsi-session.c,v 1.1.2.34 2005/04/26 17:44:50 mikenc Exp $
 *
 * This File implements the funtions related to establishing and
 * managing the session.
 */
#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/inet.h>
#include <linux/interrupt.h>
#include <scsi/scsi_device.h>

#include "iscsi-session.h"
#include "iscsi-ioctl.h"
#include "iscsi-task.h"
#include "iscsi-login.h"
#include "iscsi-sfnet.h"

/*
 * list of initialized iscsi sessions - this should be replaced
 * with a driver model equivalent if possible.
 */
LIST_HEAD(iscsi_sessions);
static DECLARE_MUTEX(iscsi_session_sem);

static void
signal_iscsi_threads(struct iscsi_session *session)
{
	if (session->tx_task)
		kill_proc(session->tx_task->pid, SIGHUP, 1);
	if (session->rx_task)
		kill_proc(session->rx_task->pid, SIGHUP, 1);
}

/* drop an iscsi session */
void
iscsi_drop_session(struct iscsi_session *session)
{
	if (!test_and_clear_bit(SESSION_ESTABLISHED, &session->control_bits))
		return;

	/* so we know whether to abort the connection */
	session->session_drop_time = jiffies ? jiffies : 1;
	signal_iscsi_threads(session);
}

void
iscsi_update_replacement_timeout(struct iscsi_session *session, int timeout)
{
	if (timeout < 0) {
		iscsi_host_err(session, "Cannot set negative timeout value of"
			       "%d\n", timeout);
		return;
	}

	spin_lock(&session->portal_lock);
	if (timeout == session->replacement_timeout) {
		spin_unlock(&session->portal_lock);
		return;
	}

	del_timer_sync(&session->replacement_timer);
	session->replacement_timeout = timeout;
	spin_lock_bh(&session->task_lock);
	if ((test_bit(SESSION_ESTABLISHED, &session->control_bits)) ||
	    (test_bit(SESSION_REPLACEMENT_TIMEDOUT, &session->control_bits)) ||
	    !timeout) {
		spin_unlock_bh(&session->task_lock);
		spin_unlock(&session->portal_lock);
		return;
	}
	spin_unlock_bh(&session->task_lock);
	mod_timer(&session->replacement_timer, jiffies + (timeout * HZ));
	spin_unlock(&session->portal_lock);
}

static void
handle_logout_timeouts(unsigned long data)
{
	struct iscsi_session *session = (struct iscsi_session *)data;

	if (test_bit(SESSION_TERMINATED, &session->control_bits) ||
	    !test_bit(SESSION_LOGOUT_REQUESTED, &session->control_bits))
		return;
	/*
	 * we're waiting for tasks to complete before logging out. No need to
	 * check the CmdSN window, since we won't be starting any more tasks.
	 */
	if (test_and_set_bit(SESSION_IN_LOGOUT, &session->control_bits)) {
		/*
		 * passed the deadline for a logout response, just drop the
		 * session
		 */
		iscsi_host_err(session, "Logout response timed out, dropping "
			       "session\n");
		iscsi_drop_session(session);
	} else {
		iscsi_wake_tx_thread(TX_LOGOUT, session);
		mod_timer(&session->logout_timer,
			  jiffies + (session->logout_response_timeout * HZ));
	}

}

/* caller must hold session->task_lock */
void
iscsi_request_logout(struct iscsi_session *session, int logout_timeout,
		     int logout_response_timeout)
{
	int timeout;

	if (!test_bit(SESSION_ESTABLISHED, &session->control_bits) ||
	    test_and_set_bit(SESSION_LOGOUT_REQUESTED, &session->control_bits))
		return;
	/*
	 * we should not be sending any new requests, so we do not want
	 * the net timer to send pings. If we have active tasks then
	 * we delay logout, but one way or another this session is going
	 * so we do not need the net timer even if the transport is bad.
	 */
	del_timer(&session->transport_timer);

	session->logout_response_timeout = logout_response_timeout;
	if (session->num_active_tasks == 0) {
		timeout = session->logout_response_timeout;
		set_bit(SESSION_IN_LOGOUT, &session->control_bits);
		iscsi_wake_tx_thread(TX_LOGOUT, session);
	} else
		timeout = logout_timeout;
	mod_timer(&session->logout_timer, jiffies + (timeout * HZ));
}

/*
 * return value:
 * 	1: login successfully.
 * 	-1: Failed to login. Retry.
 */
static int
login_response_status(struct iscsi_session *session,
		      enum iscsi_login_status login_status)
{
	int ret;

	switch (login_status) {
	case LOGIN_OK:
		/* check the status class and detail */
		ret = 1;
		break;
	case LOGIN_IO_ERROR:
	case LOGIN_WRONG_PORTAL_GROUP:
	case LOGIN_REDIRECTION_FAILED:
		iscsi_disconnect(session);
		ret = -1;
		break;
	default:
		iscsi_disconnect(session);
		/*
		 * these are problems that will probably occur with any portal
		 * of this target.
		 */
		ret = -1;
	}

	return ret;
}

/*
 * return value:
 * 	2: login successfully.
 * 	1: Redirected. Retry login.
 *	0: Failed to login. No need to retry. Give up.
 * 	-1: Failed to login. Retry.
 */
static int
check_iscsi_status_class(struct iscsi_session *session, u8 status_class,
			 u8 status_detail)
{
	switch (status_class) {
	case ISCSI_STATUS_CLS_SUCCESS:
		return 2;
	case ISCSI_STATUS_CLS_REDIRECT:
		switch (status_detail) {
		case ISCSI_LOGIN_STATUS_TGT_MOVED_TEMP:
			return 1;	/* not really success, but we want to
					 * retry immediately, with no delay
					 */
		case ISCSI_LOGIN_STATUS_TGT_MOVED_PERM:
			/*
			 * for a permanent redirect, we need to update the
			 * portal address,  and then try again.
			 */
			spin_lock(&session->portal_lock);
			/* reset the address in the current portal info */
			memcpy(&session->portal.addr, &session->addr,
			       sizeof(struct sockaddr));
			spin_unlock(&session->portal_lock);
                        return 1;       /* not really success, but we want to
                                         * retry immediately, with no delay
                                         */
		default:
			iscsi_host_err(session, "Login rejected: redirection "
				       "type 0x%x not supported\n",
				       status_detail);
			iscsi_disconnect(session);
			return -1;
		}
	case ISCSI_STATUS_CLS_INITIATOR_ERR:
		iscsi_disconnect(session);

		switch (status_detail) {
		case ISCSI_LOGIN_STATUS_AUTH_FAILED:
			iscsi_host_err(session, "Login rejected: Initiator "
				       "failed authentication with target\n");
			return 0;	
		case ISCSI_LOGIN_STATUS_TGT_FORBIDDEN:
			iscsi_host_err(session, "Login rejected: initiator "
				       "failed authorization with target\n");
			return 0;
		case ISCSI_LOGIN_STATUS_TGT_NOT_FOUND:
			iscsi_host_err(session, "Login rejected: initiator "
				       "error - target not found (%02x/%02x)\n",
				       status_class, status_detail);
			return 0;
		case ISCSI_LOGIN_STATUS_NO_VERSION:
			/*
			 * FIXME: if we handle multiple protocol versions,
			 * before we log an error, try the other supported
			 * versions.
			 */
			iscsi_host_err(session, "Login rejected: incompatible "
				       "version (%02x/%02x), non-retryable, "
				       "giving up\n", status_class,
				       status_detail);
			return 0;
		default:
			iscsi_host_err(session, "Login rejected: initiator "
				       "error (%02x/%02x), non-retryable, "
				       "giving up\n", status_class,
				       status_detail);
			return 0;
		}
	case ISCSI_STATUS_CLS_TARGET_ERR:
		iscsi_host_err(session, "Login rejected: target error "
			       "(%02x/%02x)\n", status_class, status_detail);
		iscsi_disconnect(session);
		/*
		 * We have no idea what the problem is. But spec says initiator
		 * may retry later.
		 */
		 return -1;
	default:
		iscsi_host_err(session, "Login response with unknown status "
			       "class 0x%x, detail 0x%x\n", status_class,
			       status_detail);
		iscsi_disconnect(session);
		return 0;
	}
}

static void
login_timed_out(unsigned long data)
{
	struct iscsi_session *session = (struct iscsi_session *)data;

	iscsi_host_err(session, "Login phase timed out, timeout was set for "
		       "%d secs\n", session->login_timeout);
	kill_proc(session->rx_task->pid, SIGHUP, 1);
}

/**
 * iscsi_update_login_timeout - update the login timeout and timer
 * @session: iscsi session
 * @timeout: new timeout
 *
 * Notes:
 * If it is a pending timer then we restart with the new value.
 * And if there was no previous timeout, and a new value
 * we start up the timer with the new value.
 */
void
iscsi_update_login_timeout(struct iscsi_session *session, int timeout)
{
	if (timeout < 0) {
		iscsi_host_err(session, "Cannot set negative timeout value of"
			       "%d\n", timeout);
		return;
	}

	spin_lock(&session->portal_lock);
	if (session->login_timeout == timeout)
		goto done;

	if ((del_timer(&session->login_timer) && timeout) ||
	    (!session->login_timeout && timeout &&
	     test_bit(SESSION_IN_LOGIN, &session->control_bits)))
		mod_timer(&session->login_timer, jiffies + (timeout * HZ));
	session->login_timeout = timeout;
 done:
	spin_unlock(&session->portal_lock);
}

static int
__establish_session(struct iscsi_session *session)
{
	int ret = -1;
	u8 status_class;
	u8 status_detail;
	enum iscsi_login_status login_status;

	if (signal_pending(current))
		flush_signals(current);

	iscsi_disconnect(session);

	spin_lock(&session->portal_lock);
	/*
	 * Set almost everything based on the portal's settings.
	 * Don't change the address, since a temporary redirect
	 * may have already changed the address,
	 * and we want to use the redirected address rather than
	 * the portal's address.
	 */
	iscsi_set_portal_info(session);

	set_bit(SESSION_IN_LOGIN, &session->control_bits);
	if (session->login_timeout)
		mod_timer(&session->login_timer,
			  jiffies + (session->login_timeout * HZ));
	spin_unlock(&session->portal_lock);

	if (iscsi_connect(session)) {
		iscsi_host_err(session, "establish_session failed. Could not "
			       "connect to target\n");
		goto done;
	}

	/*
	 * Grab the config mutex a little early incase update_session
	 * is running and something went wacko, the connect/login timer
	 * above will break us out.
	 */
	if (down_interruptible(&session->config_mutex)) {
		iscsi_host_err(session, "Failed to acquire mutex before "
			       "login\n");
		goto done;
	}

	/*
	 * initialize session fields for the iscsi-login code
	 */
	session->type = ISCSI_SESSION_TYPE_NORMAL;
	/*
	 * use iSCSI default, unless declared otherwise by the
	 * target during login
	 */
	session->max_xmit_data_segment_len =
		DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;
	session->vendor_specific_keys = 1;
	/*
	 * we do not want to allocate memory here since this might be a
	 * relogin with IO in progress, so we reuse the rx_buffer. Note
	 * that extra care must be taken when using this buffer for both
	 * send and recv here , becuase the net subsys does not copy data
	 * in sendpage.
	 */
	login_status = iscsi_login(session, session->rx_buffer,
				   sizeof(session->rx_buffer), &status_class,
				   &status_detail);
	up(&session->config_mutex);

	ret = login_response_status(session, login_status);
	if (ret < 1)
		goto done;

	ret = check_iscsi_status_class(session, status_class, status_detail);
	if (ret < 2)
		goto done;

	iscsi_host_notice(session, "Session established\n");
	/*
	 * logged in ok, get the new session ready
	 */
	session->window_closed = 0;
	session->has_logged_in = 1;
	session->session_established_time = jiffies;
	session->session_drop_time = 0;
	clear_bit(SESSION_WINDOW_CLOSED, &session->control_bits);
	spin_lock_bh(&session->task_lock);
	clear_bit(SESSION_REPLACEMENT_TIMEDOUT, &session->control_bits);
	set_bit(SESSION_ESTABLISHED, &session->control_bits);
	spin_unlock_bh(&session->task_lock);
	/*
	 * ready to go, so wake up everyone waiting for the session
	 * to be established
	 */
	wake_up(&session->login_wait_q);
 done:
	/*
	 * there is a race with the login timer here where we successfully
	 * login, but then the login timer expires. If this does occur
	 * we end up relogging in. To handle the login_wait_q
	 * being woken up we are holding the tx_blocked sema so the tx_thread
	 * will not be sending any tasks while this is going on (the worst
	 * that happens is tasks will timeout).
	 *
	 * Fixme: if time (this should be rare so maybe not a priority)
	 */
	spin_lock(&session->portal_lock);
	clear_bit(SESSION_IN_LOGIN, &session->control_bits);
	del_timer_sync(&session->login_timer);
	spin_unlock(&session->portal_lock);

	/* cleanup after a possible timeout expiration */
	if (signal_pending(current)) {
		flush_signals(current);

		if (test_bit(SESSION_TERMINATING, &session->control_bits))
			return 0;
		else
			return -1;
	}
	return ret;
}

static char*
iscsi_strdup(char *str, int *err)
{
	int len;
	char *s;

	*err = 0;
	len = strlen(str) + 1;
	if (len == 1) {
		*err = -EINVAL;
		return NULL;
	}

	s = kmalloc(len, GFP_KERNEL);
	if (!s) {
		*err = -ENOMEM;
		return NULL;
	}

	return strcpy(s, str);
}

/*
 * return value:
 * 	1: name/alias updated. Relogin required.
 *	0: No updated needed.
 * 	-Exxx: Failed to update.
 */
static int
update_iscsi_strings(struct iscsi_session *session,
		     struct iscsi_session_ioctl *ioctld)
{
	char *iname = NULL;
	char *alias = NULL;
	char *uname = NULL;
	char *uname_in = NULL;
	char *pw = NULL;
	char *pw_in = NULL;
	int rc = 0;

	/*
	 * update all the values or none of them
	 */
	if (!ioctld->initiator_name[0]) {
		iscsi_host_err(session, "No InitiatorName\n");
		return -EINVAL;
	}
	if (strcmp(ioctld->initiator_name, session->initiator_name)) {
		iname = iscsi_strdup(ioctld->initiator_name, &rc);
		if (!iname) {
			iscsi_host_err(session, "Failed to change "
				       "InitiatorName from %s to %s\n",
				       session->initiator_name,
				       ioctld->initiator_name);
			return rc;
		}
	}

	if (ioctld->initiator_alias[0] && (!session->initiator_alias ||
	    strcmp(ioctld->initiator_alias, session->initiator_alias))) {
		alias = iscsi_strdup(ioctld->initiator_alias, &rc);
		if (!alias)
			/* Alias is not ciritical so just print an error */
			iscsi_host_err(session, "Failed to change "
					"InitiatorAlias\n");
	}

	if (ioctld->username[0] && (!session->username ||
	    strcmp(ioctld->username, session->username))) {
		uname = iscsi_strdup(ioctld->username, &rc);
		if (!uname) {
			iscsi_host_err(session, "Failed to change outgoing "
				       "username\n");
				goto failed;
		}
	}

	if (ioctld->username_in[0] && (!session->username_in ||
	    strcmp(ioctld->username_in, session->username_in))) {
		uname_in = iscsi_strdup(ioctld->username_in, &rc);
		if (!uname_in) {
			iscsi_host_err(session, "Failed to change incoming "
				       "username\n");
				goto failed;
		}
	}

	if (ioctld->password_length && (!session->password ||
	    session->password_length != ioctld->password_length ||
	    memcmp(ioctld->password, session->password,
		   session->password_length))) {
		pw = kmalloc(ioctld->password_length + 1, GFP_KERNEL);
		if (!pw) {
			iscsi_host_err(session, "Failed to change outgoing "
				       "password\n");
			rc = -ENOMEM;
			goto failed;
		}
		memcpy(pw, ioctld->password, ioctld->password_length);
	}

	if (ioctld->password_length_in && (!session->password_in ||
	    session->password_length_in != ioctld->password_length_in ||
	    memcmp(ioctld->password_in, session->password_in,
		   session->password_length_in))) {
		pw_in = kmalloc(ioctld->password_length_in + 1, GFP_KERNEL);
		if (!pw_in) {
			iscsi_host_err(session, "Failed to change incoming "
				       "password\n");
			rc = -ENOMEM;
			goto failed;
		}
		memcpy(pw_in, ioctld->password_in, ioctld->password_length_in);
	}

	if (iname) {
		kfree(session->initiator_name);	
		session->initiator_name = iname;
		rc = 1;
	}
	if (alias || (!ioctld->initiator_alias[0] &&
		      session->initiator_alias[0])) {
		kfree(session->initiator_alias);
		session->initiator_alias = alias;
		rc = 1;
	}
	if (uname || (!ioctld->username[0] && session->username)) {
		kfree(session->username);
		session->username = uname;
		rc = 1;
	}
	if (uname_in || (!ioctld->username_in[0] && session->username_in)) {
		kfree(session->username_in);
		session->username_in = uname_in;
		rc = 1;
	}
	if (pw || (!ioctld->password_length && session->password)) {
		kfree(session->password);
		session->password = pw;
		session->password_length = ioctld->password_length;
		rc = 1;
	}
	if (pw_in || (!ioctld->password_length_in && session->password_in)) {
		kfree(session->password_in);
		session->password_in = pw_in;
		session->password_length_in = ioctld->password_length_in;
		rc = 1;
	}
	return rc;
 failed:
	kfree(iname);
	kfree(alias);
	kfree(uname);
	kfree(uname_in);
	kfree(pw);
	kfree(pw_in);
	return rc;
}

static int
alloc_auth_buffers(struct iscsi_session *session)
{
	if (!(session->bidirectional_auth || session->username ||
	      session->password))
		return 0;

	if (session->auth_client_block)
		return 0;

	session->md5_tfm = crypto_alloc_tfm("md5", 0);
	if (!session->md5_tfm)
		return -ENOMEM;

	session->auth_client_block =
		kmalloc(sizeof(*session->auth_client_block), GFP_KERNEL);
	if (!session->auth_client_block)
		goto error;

	session->auth_recv_string_block =
		kmalloc(sizeof(*session->auth_recv_string_block), GFP_KERNEL);
	if (!session->auth_recv_string_block)
		goto error;

	session->auth_send_string_block =
		kmalloc(sizeof(*session->auth_send_string_block), GFP_KERNEL);
	if (!session->auth_send_string_block)
		goto error;

	session->auth_recv_binary_block =
		kmalloc(sizeof(*session->auth_recv_binary_block), GFP_KERNEL);
	if (!session->auth_recv_binary_block)
		goto error;

	session->auth_send_binary_block =
		kmalloc(sizeof(*session->auth_send_binary_block), GFP_KERNEL);
	if (!session->auth_send_binary_block)
		goto error;

	return 0;

 error:
	crypto_free_tfm(session->md5_tfm);
	kfree(session->auth_client_block);
	kfree(session->auth_recv_string_block);
	kfree(session->auth_send_string_block);
	kfree(session->auth_recv_binary_block);
	iscsi_host_err(session, "Session requires authentication but couldn't "
		       "allocate authentication stuctures\n");
	return -ENOMEM;
}

void
iscsi_update_ping_timeout(struct iscsi_session *session, int timeout)
{
	if (timeout < 0) {
		iscsi_host_err(session, "Cannot set negative timeout value of"
			       "%d\n", timeout);
		return;
	}

	spin_lock_bh(&session->task_lock);
	if (timeout == session->ping_timeout)
		goto done;

	/* reset these for the next timer */
	session->last_rx = jiffies;
	session->last_ping = jiffies;
	/* this will be used for the next ping */
	session->ping_timeout = timeout;
 done:
	spin_unlock_bh(&session->task_lock);
}

void
iscsi_update_active_timeout(struct iscsi_session *session, int timeout)
{
	if (timeout < 0) {
		iscsi_host_err(session, "Cannot set negative timeout value of"
			       "%d\n", timeout);
		return;
	}

	spin_lock_bh(&session->task_lock);
	if (timeout == session->active_timeout)
		goto done;

	if (!session->num_active_tasks)
		goto done;

	/* reset these for the next timer */
	session->last_rx = jiffies;
	session->last_ping = jiffies;

	if ((del_timer(&session->transport_timer) && timeout) ||
	    (!session->active_timeout && timeout))
		mod_timer(&session->transport_timer, jiffies + (timeout * HZ));
 done:
	session->active_timeout = timeout;
	spin_unlock_bh(&session->task_lock);
}

void
iscsi_update_idle_timeout(struct iscsi_session *session, int timeout)
{
	if (timeout < 0) {
		iscsi_host_err(session, "Cannot set negative timeout value of"
			       "%d\n", timeout);
		return;
	}

	spin_lock_bh(&session->task_lock);
	if (timeout == session->idle_timeout)
		goto done;

	if (session->num_active_tasks)
		goto done;

	/* reset these for the next timer */
	session->last_rx = jiffies;
	session->last_ping = jiffies;

	if ((del_timer(&session->transport_timer) && timeout) ||
	    (!session->idle_timeout && timeout))
		mod_timer(&session->transport_timer, jiffies + (timeout * HZ));
 done:
	session->idle_timeout = timeout;
	spin_unlock_bh(&session->task_lock);
}

int
iscsi_update_session(struct iscsi_session *session,
		     struct iscsi_session_ioctl *ioctld)
{
	int rc = 0;
	int relogin = 0;

	if (down_interruptible(&session->config_mutex)) {
		iscsi_host_err(session, "Session configuration update aborted "
			       "by signal\n");
		return -EINTR;
	}
	if (test_bit(SESSION_TERMINATED, &session->control_bits))
		return -EINVAL;

	if (ioctld->update && (ioctld->config_number < session->config_number))
		/* this update is obsolete, ignore it */
		goto err_exit;

	if (ioctld->username_in[0] || ioctld->password_length_in)
		session->bidirectional_auth = 1;
	else
		session->bidirectional_auth = 0;
	rc = alloc_auth_buffers(session);
	if (rc < 0)
		goto err_exit;

	rc = update_iscsi_strings(session, ioctld);
	if (rc > 0)
		relogin = 1;
	else if (rc < 0) 
		goto err_exit;

	session->config_number = ioctld->config_number;

	/*
	 * the portals are guarded by a spinlock instead of the config
	 * mutex, so that we can request portal changes while a login is
	 * occuring.
	 */
	spin_lock(&session->portal_lock);
	if (iscsi_update_portal_info(&session->portal, &ioctld->portal))
		relogin = 1;
	spin_unlock(&session->portal_lock);

	/*
	 * update timers
	 */
	iscsi_update_abort_timeout(session, ioctld->abort_timeout);
	iscsi_update_reset_timeout(session, ioctld->reset_timeout);
	iscsi_update_idle_timeout(session, ioctld->idle_timeout);
	iscsi_update_active_timeout(session, ioctld->active_timeout);
	iscsi_update_ping_timeout(session, ioctld->ping_timeout);
	iscsi_update_replacement_timeout(session, ioctld->replacement_timeout);
	iscsi_update_login_timeout(session, ioctld->login_timeout);

	if (relogin) {
		spin_lock_bh(&session->task_lock);
		iscsi_request_logout(session, 3, session->active_timeout);
		spin_unlock_bh(&session->task_lock);
	}
	/*
	 * after we release the mutex we cannot touch any field that
	 * may be freed by a shutdown that is running at the same time
	 */
	up(&session->config_mutex);

	return 0;

 err_exit:
	up(&session->config_mutex);
	return rc;
}

static int
copy_iscsi_strings(struct iscsi_session *session,
		   struct iscsi_session_ioctl *ioctld)
{
	int rc;

	session->initiator_name = iscsi_strdup(ioctld->initiator_name, &rc);
	if (rc == -EINVAL) {
		iscsi_host_err(session, "No InitiatorName\n");
		return rc;
	}
	if (rc == -ENOMEM) {
		iscsi_host_err(session, "Cannot allocate InitiatorName\n");
		return rc;
	}

	session->initiator_alias = iscsi_strdup(ioctld->initiator_alias, &rc);
	/* Alias is not ciritical so just print an error */
	if (!session->initiator_alias)
		iscsi_host_err(session, "Cannot create InitiatorAlias\n");

	session->target_name = iscsi_strdup(ioctld->target_name, &rc);
	if (rc == -EINVAL) {
		iscsi_err("No TargetName\n");
		return rc;
	}
	if (rc == -ENOMEM) {
		iscsi_host_err(session, "Cannot allocate TargetName\n");
		return rc;
	}

	session->username = iscsi_strdup(ioctld->username, &rc);
	if (rc == -ENOMEM) {
		iscsi_host_err(session, "Failed to allocate outgoing "
			       "username\n");
		return rc;
	}

	session->username_in = iscsi_strdup(ioctld->username_in, &rc);
	if (rc == -ENOMEM) {
		iscsi_host_err(session, "Failed to allocate incoming "
			       "username\n");
		return rc;
	}

	if (ioctld->password_length) {
		session->password = kmalloc(ioctld->password_length + 1,
					    GFP_KERNEL);
		if (!session->password) {
			iscsi_host_err(session, "Failed to allocate outgoing "
				       "password\n");
			return -ENOMEM;
		}
		memcpy(session->password, ioctld->password,
		       ioctld->password_length);
		session->password_length = ioctld->password_length;
	}

	if (ioctld->password_length_in) {
		session->password_in = kmalloc(ioctld->password_length_in + 1,
					       GFP_KERNEL);
		if (!session->password_in) {
			iscsi_host_err(session, "Failed to allocate incoming "
				       "password\n");
			return -ENOMEM;
		}
		memcpy(session->password_in, ioctld->password_in,
		       ioctld->password_length_in);
		session->password_length_in = ioctld->password_length_in;
	}

	return 0;
}

/**
 * clear_session - clear session fields before attempting a re-login.
 * @session: session to initialize.
 **/
static void
clear_session(struct iscsi_session *session)
{
	struct iscsi_nop_info *nop_info, *tmp;

	session->nop_reply.ttt = ISCSI_RSVD_TASK_TAG;
	list_for_each_entry_safe(nop_info, tmp, &session->nop_reply_list,
				 reply_list) {
		list_del(&nop_info->reply_list);
		kfree(nop_info);
	}

	spin_unlock_bh(&session->task_lock);
	del_timer_sync(&session->transport_timer);
	del_timer_sync(&session->logout_timer);
	spin_lock_bh(&session->task_lock);

	clear_bit(SESSION_IN_LOGOUT, &session->control_bits);
	clear_bit(SESSION_LOGOUT_REQUESTED, &session->control_bits);
	session->logout_response_timeout = 0;
	session->last_mgmt_itt = ISCSI_RSVD_TASK_TAG;
}

/*
 * Timer processing for a session in Full Feature Phase (minus logout).
 * This timer may rearm itself.
 */
static void
check_transport_timeouts(unsigned long data)
{
	struct iscsi_session *session = (struct iscsi_session *)data;
	unsigned long timeout, next_timeout = 0, last_rx;

	spin_lock(&session->task_lock);

	if (test_bit(SESSION_TERMINATED, &session->control_bits) ||
	    !test_bit(SESSION_ESTABLISHED, &session->control_bits))
		goto done;

	if (session->num_active_tasks)
		timeout = session->active_timeout;
	else
		timeout = session->idle_timeout;
	if (!timeout)
		goto check_window;

	timeout *= HZ;
	last_rx = session->last_rx;

	if (session->ping_timeout &&
	    time_before_eq(last_rx + timeout + (session->ping_timeout * HZ),
			   jiffies)) {
		iscsi_host_err(session, "ping timeout of %d secs expired, "
			       "last rx %lu, last ping %lu, now %lu\n",
			       session->ping_timeout, last_rx,
			       session->last_ping, jiffies);
		iscsi_drop_session(session);
		goto done;
	}

	if (time_before_eq(last_rx + timeout, jiffies)) {
		if (time_before_eq(session->last_ping, last_rx)) {
			/*
			 * send a ping to try to provoke some
			 * traffic
			 */
			session->last_ping = jiffies;
			iscsi_wake_tx_thread(TX_PING, session);
		}
		next_timeout = last_rx + timeout + (session->ping_timeout * HZ);
	} else
		next_timeout = last_rx + timeout;

 check_window:
	/*
	 * Do we still want to do this, or was it for an older
	 * bad target that has been fixed?
	 */
	if (test_bit(SESSION_WINDOW_CLOSED, &session->control_bits)) {
		/*
		 * command window closed, ping once every 5 secs to ensure
		 * we find out when it re-opens.  Target should send
		 * us an update when it does, but we're not very
		 * trusting of target correctness.
		 */
		if (time_before(session->last_ping + (5 * HZ), jiffies))
			iscsi_wake_tx_thread(TX_PING, session);
		if (next_timeout)
			next_timeout = min(jiffies + (5 * HZ), next_timeout);
		else
			next_timeout = jiffies + (5 * HZ);
	}

	if (next_timeout)
		mod_timer(&session->transport_timer, next_timeout);
 done:
	spin_unlock(&session->task_lock);
}

static void
replacement_timed_out(unsigned long data)
{
	struct iscsi_session *session = (struct iscsi_session *)data;

	iscsi_host_err(session, "replacement session time out after %d "
		       "seconds, drop %lu, now %lu, failing all commands\n",
		       session->replacement_timeout,
		       session->session_drop_time, jiffies);

	spin_lock(&session->task_lock);
	if (test_bit(SESSION_ESTABLISHED, &session->control_bits) ||
	    test_and_set_bit(SESSION_REPLACEMENT_TIMEDOUT,
			     &session->control_bits)) {
		spin_unlock(&session->task_lock);
		return;
	}
	iscsi_flush_queues(session, ISCSI_MAX_LUNS, DID_BUS_BUSY);
	spin_unlock(&session->task_lock);

	wake_up_all(&session->login_wait_q);
}

static void
init_session_structure(struct iscsi_session *session,
		       struct iscsi_session_ioctl *ioctld)
{
	INIT_LIST_HEAD(&session->list);
	session->config_number = ioctld->config_number;
	spin_lock_init(&session->portal_lock);
	session->portal_group_tag = -1;
	/* the first down should block */
	sema_init(&session->config_mutex, 0);
	INIT_LIST_HEAD(&session->pending_queue);
	INIT_LIST_HEAD(&session->active_queue);
	INIT_LIST_HEAD(&session->done_queue);
	spin_lock_init(&session->task_lock);
	INIT_LIST_HEAD(&(session->tx_task_head));
	init_waitqueue_head(&session->tx_wait_q);
	init_waitqueue_head(&session->login_wait_q);
	sema_init(&session->tx_blocked, 0);
	session->next_itt = 1;
	session->time2wait = -1;
	session->last_mgmt_itt = ISCSI_RSVD_TASK_TAG;
	session->mgmt_task_complete = NULL;
	session->nop_reply.ttt = ISCSI_RSVD_TASK_TAG;
	INIT_LIST_HEAD(&session->nop_reply_list);

	session->login_timeout = ioctld->login_timeout;
	session->active_timeout = ioctld->active_timeout;
	session->idle_timeout = ioctld->idle_timeout;
	session->ping_timeout = ioctld->ping_timeout;
	session->abort_timeout = ioctld->abort_timeout;
	session->reset_timeout = ioctld->reset_timeout;
	session->replacement_timeout = ioctld->replacement_timeout;

	init_timer(&session->transport_timer);
	session->transport_timer.data = (unsigned long)session;
	session->transport_timer.function = check_transport_timeouts;

	init_timer(&session->logout_timer);
	session->logout_timer.data = (unsigned long)session;
	session->logout_timer.function = handle_logout_timeouts;

	init_timer(&session->replacement_timer);
	session->replacement_timer.data = (unsigned long)session;
	session->replacement_timer.function = replacement_timed_out;

	init_timer(&session->login_timer);
	session->login_timer.data = (unsigned long)session;
	session->login_timer.function = login_timed_out;

	init_timer(&session->tmf_timer);
	session->tmf_timer.function = iscsi_tmf_times_out;
}

/**
 * iscsi_mod_session_timer - modify the session's transport timer
 * @session: iscsi session
 * @timeout: timeout in seconds
 *
 * Note:
 *    Must hold the task lock. And, if the new timeout was shorter
 *    than the window_closed_timeout we will end up delaying the
 *    new timeout. This should be rare and not really hurt anything
 *    so we ignore it for now.
 **/
void
iscsi_mod_session_timer(struct iscsi_session *session, int timeout)
{
	/*
	 * reset last_rx and last_ping, so that it does not look like
	 * we timed out when we are just switching states
	 */
	session->last_rx = jiffies;
	session->last_ping = jiffies;

	if (test_bit(SESSION_WINDOW_CLOSED, &session->control_bits))
		return;

	if (timeout)
		mod_timer(&session->transport_timer, jiffies + (timeout * HZ));
	else
		del_timer(&session->transport_timer);
}

void
iscsi_wake_tx_thread(int control_bit, struct iscsi_session *session)
{
	set_bit(control_bit, &session->control_bits);
	set_bit(TX_WAKE, &session->control_bits);
	wake_up(&session->tx_wait_q);
}

/**
 * iscsi_wait_for_session - Wait for a session event to be established.
 * @session: session to wait on.
 * @ignore_timeout: If zero this will return when the replacement timeout fires.
 *
 * Description:
 *    Returns 1 to indicate sesssion was established, or 0 to indicate
 *    we timed out (if ignore_timeout == 0) or are terminating.
 **/
int
iscsi_wait_for_session(struct iscsi_session *session, int ignore_timeout)
{
	int rc = 0;

	while (1) {
		wait_event_interruptible(session->login_wait_q,
			test_bit(SESSION_ESTABLISHED, &session->control_bits) ||
			test_bit(SESSION_TERMINATING, &session->control_bits) ||
			(!ignore_timeout &&
			 test_bit(SESSION_REPLACEMENT_TIMEDOUT,
				  &session->control_bits)));

		if (signal_pending(current))
			flush_signals(current);

		/*
		 * need to test for termnination first to avoid falling
		 * in the tx request loop for ever
		 */
		if (test_bit(SESSION_TERMINATING, &session->control_bits))
			break;

		if (test_bit(SESSION_ESTABLISHED, &session->control_bits)) {
			rc = 1;
			break;
		}

		if (!ignore_timeout && test_bit(SESSION_REPLACEMENT_TIMEDOUT,
						 &session->control_bits))
			break;
	}

	return rc;
}

/*
 * Note the ordering matches the TX_* bit ordering.
 * See iscsi_tx_thread comment, this basically a
 * workqueue_struct.
 */
static struct {
	void (* request_fn)(struct iscsi_session *);
} tx_request_fns[] = {
	{ iscsi_send_nop_out },
	{ iscsi_send_task_mgmt },
	{ iscsi_run_pending_queue },
	{ iscsi_send_nop_replys },
	{ iscsi_send_r2t_data },
	{ iscsi_send_logout },
};

static void
wait_for_tx_requests(struct iscsi_session *session)
{
	int req;

	wait_event_interruptible(session->tx_wait_q,
		test_and_clear_bit(TX_WAKE, &session->control_bits));

	for (req = 0; req < TX_WAKE; req++) {
		if (signal_pending(current))
			return;
		/*
		 * when a logout is in progress or about to be sent
		 * we do not start new requests, but we continue to
		 * respond to R2Ts and Nops.
		 */
		if (test_and_clear_bit(req, &session->control_bits)) {
			if (test_bit(SESSION_LOGOUT_REQUESTED,
				     &session->control_bits) &&
			    req <= TX_SCSI_COMMAND)
				continue;

			tx_request_fns[req].request_fn(session);
		}
	}
}

/**
 * session_kthread_sleep - put a thread to sleep while waiting for shutdown.
 * @session: session. 
 *
 * Description:
 *    If for some reason we could not relogin into a session we sleep here
 *    and and wait for someone to remove the session. Returns -EPERM to
 *    indicate the thread should exit, or zero to indicate that the thread
 *    can proceed with its normal action.
 **/
static inline int
session_kthread_sleep(struct iscsi_session *session)
{
 retest:
	set_current_state(TASK_INTERRUPTIBLE);
	if (kthread_should_stop()) {
		__set_current_state(TASK_RUNNING);
		return -EPERM;
	}

	/*
	 * We fall into this sleep, when someone has broken us
	 * out of the lower loops that process requests or log us in,
	 * terminate the session (session drops will not sleep here),
	 * but have not (yet) cleaned up the host and called kthread_stop()).
	 */
	if (test_bit(SESSION_TERMINATING, &session->control_bits)) {
		schedule();
		if (signal_pending(current))
			flush_signals(current);
		goto retest;
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

/*
 * the writer thread
 * TODO? - this could be nicely replaced with a work queue
 * having a work struct replacing each TX_* req, but will
 * using a singlethreaded_workqueue hurt perf when all
 * targets use the same cpu_workqueue_struct?
 * Or to reduce the number of threads, should we use one
 * per cpu workqueue for the entire driver for all sends?
 */
static int
iscsi_tx_thread(void *data)
{
	struct iscsi_session *session = data;
	int rc;
	unsigned long tmo;

	current->flags |= PF_MEMALLOC;
	allow_signal(SIGHUP);

	/*
	 * tell the rx thread that we're about to block, and that
	 * it can safely call iscsi_sendmsg now as part of
	 * the Login phase.
	 */
	up(&session->tx_blocked);

	while (!session_kthread_sleep(session)) {
		spin_lock(&session->portal_lock);
		tmo = session->replacement_timeout * HZ;
		if (tmo && session->session_drop_time) {
			del_timer_sync(&session->replacement_timer);
			mod_timer(&session->replacement_timer, jiffies + tmo);
		}
		spin_unlock(&session->portal_lock);
		rc = iscsi_wait_for_session(session, 1);
		spin_lock(&session->portal_lock);
		del_timer_sync(&session->replacement_timer);
		spin_unlock(&session->portal_lock);
		if (!rc)
			continue;

		down(&session->tx_blocked);

		/*
		 * make sure we start sending commands again,
		 * and clear any stale requests
		 */
		clear_bit(TX_TMF, &session->control_bits);
		clear_bit(TX_LOGOUT, &session->control_bits);
		clear_bit(TX_DATA, &session->control_bits);
		set_bit(TX_PING, &session->control_bits);
		set_bit(TX_SCSI_COMMAND, &session->control_bits);
		set_bit(TX_WAKE, &session->control_bits);

		while (!signal_pending(current))
			wait_for_tx_requests(session);
		flush_signals(current);

		up(&session->tx_blocked);
	}

	return 0;
}

static int
establish_session(struct iscsi_session *session, unsigned int login_delay)
{
	int rc;
	unsigned long login_failures = 0;

	while (!test_bit(SESSION_ESTABLISHED, &session->control_bits)) {
		if (login_delay) {
			iscsi_host_notice(session, "Waiting %u seconds before "
					  "next login attempt\n", login_delay);
			msleep_interruptible(login_delay * 1000);
		}

		if (test_bit(SESSION_TERMINATING, &session->control_bits))
			return 0;

		rc = __establish_session(session);
		if (rc > 0)
			/* established or redirected */
			login_failures = 0;
		else if ((iscsi_max_initial_login_retries > 0 &&
			 login_failures + 1 > iscsi_max_initial_login_retries &&
			 !session->has_logged_in) || (rc == 0)) {
			/* failed, give up */
			iscsi_host_err(session, "Session giving up after %u "
				      "retries\n", login_failures);
			set_bit(SESSION_TERMINATING, &session->control_bits);
			return 0;
		} else {
			/* failed, retry */
			spin_lock(&session->portal_lock);
			iscsi_set_portal(session);
			spin_unlock(&session->portal_lock);
			login_failures++;
		 }

		/* slowly back off the frequency of login attempts */
		if (login_failures == 0)
			login_delay = 0;
		else if (login_failures < 30)
			login_delay = 1;
		else if (login_failures < 48)
			login_delay = 5;
		else if (!test_bit(SESSION_REPLACEMENT_TIMEDOUT,
				   &session->control_bits))
			login_delay = 10;
		 else
			login_delay = 60;
	}

	return 1;
}

/**
 * get_time2wait - return iSCSI DefaultTime2Wait
 * @session: iscsi session
 * @short_sessions: number of short sessions
 *
 * Description:
 *   Return DefaultTime2Wait. However, if the session dies really
 *   quicky after we reach FFP, we'll not be interoperable due to bugs
 *   in the target (or this driver) that send illegal opcodes,
 *   or disagreements about how to do CRC  calculations. To
 *   avoid spinning, we track sessions with really short
 *   lifetimes, and decrease the login frequency if we keep
 *   getting session failures, like we do for login failures.
 **/
static unsigned int
get_time2wait(struct iscsi_session *session, unsigned long *short_sessions)
{
	unsigned int login_delay = 0;

	if (session->time2wait >= 0) {
		login_delay = session->time2wait;
		session->time2wait = -1;
	} else
		login_delay = session->def_time2wait;

	if (time_before_eq(session->session_drop_time,
		     	   session->session_established_time + (2 * HZ))) {
		(*short_sessions)++;

		if (*short_sessions < 30)
			login_delay = max_t(unsigned int, login_delay, 1);
		else if (*short_sessions < 48)
			login_delay = max_t(unsigned int, login_delay, 5);
		else if (!test_bit(SESSION_REPLACEMENT_TIMEDOUT,
				   &session->control_bits))
			login_delay = max_t(unsigned int, login_delay, 10);
		else
			login_delay = max_t(unsigned int, login_delay, 60);

		iscsi_host_warn(session, "Session has ended quickly %lu times, "
				"login delay %u seconds\n", *short_sessions,
				login_delay);
	} else
		/* session lived long enough that the target is probably ok */
		*short_sessions = 0;

	return login_delay;
}

static int
iscsi_rx_thread(void *data)
{
	struct iscsi_session *session = data;
	struct iscsi_hdr hdr;
	unsigned int login_delay = 0;
	unsigned long short_sessions = 0;

	current->flags |= PF_MEMALLOC;
	allow_signal(SIGHUP);

	down(&session->tx_blocked);

        while (!session_kthread_sleep(session)) {
		if (!establish_session(session, login_delay))
			continue;

		spin_lock_bh(&session->task_lock);
		iscsi_mod_session_timer(session, session->idle_timeout);
		spin_unlock_bh(&session->task_lock);
		up(&session->tx_blocked);	

		while (!signal_pending(current))
			iscsi_recv_pdu(session, &hdr, session->header_digest,
				       session->rx_buffer, ISCSI_RXCTRL_SIZE,
				       session->data_digest);
		flush_signals(current);

		login_delay = get_time2wait(session, &short_sessions);
		/*
		 * if this is a session drop we need to wait for
		 * the tx thread to stop queueing and processing requests
		 * so we can resetup the socket.
		 */
		down(&session->tx_blocked);

		/*
		 * session dropped unexpectedly, often due to
		 * network problems
		 */
		iscsi_host_err(session, "Session dropped\n");
		spin_lock_bh(&session->task_lock);
		iscsi_flush_queues(session, ISCSI_MAX_LUNS, DID_BUS_BUSY);
		clear_session(session);
		spin_unlock_bh(&session->task_lock);
	}

	up(&session->tx_blocked);
	/*
	 * If there are any commands left this will remove them.
	 */
	spin_lock_bh(&session->task_lock);
	iscsi_flush_queues(session, ISCSI_MAX_LUNS, DID_NO_CONNECT);
	spin_unlock_bh(&session->task_lock);

	return 0;
}

static int
start_session_threads(struct iscsi_session *session)
{
	session->tx_task = kthread_run(iscsi_tx_thread, session, "iscsi-tx");
	if (IS_ERR(session->tx_task)) {
		iscsi_host_err(session, "Failed to start tx thread, terminating"
			       " session\n");
		goto fail;
	}

	session->rx_task = kthread_run(iscsi_rx_thread, session, "iscsi-rx");
	if (IS_ERR(session->rx_task)) {
		iscsi_host_err(session, "Failed to start rx thread, terminating"
			       " session\n");
		goto shutdown_tx_thread;
	}

	return 0;

 shutdown_tx_thread:
	set_bit(SESSION_TERMINATING, &session->control_bits);
	kthread_stop(session->tx_task);
 fail:
	return -EAGAIN;
}

static void
free_session(struct iscsi_session *session)
{
	if (session->preallocated_task)
		kmem_cache_free(iscsi_task_cache, session->preallocated_task);

	if (session->mgmt_task)
		kmem_cache_free(iscsi_task_cache, session->mgmt_task);

	if (session->rx_tfm)
		crypto_free_tfm(session->rx_tfm);
	if (session->tx_tfm)
		crypto_free_tfm(session->tx_tfm);
	if (session->md5_tfm)
		crypto_free_tfm(session->md5_tfm);

	kfree(session->auth_client_block);
	kfree(session->auth_recv_string_block);
	kfree(session->auth_send_string_block);
	kfree(session->auth_recv_binary_block);
	kfree(session->auth_send_binary_block);
	kfree(session->username);
	kfree(session->password);
	kfree(session->username_in);
	kfree(session->password_in);
	kfree(session->initiator_name);
	kfree(session->initiator_alias);
	kfree(session->target_name);
	kfree(session->target_alias);
}

void
iscsi_destroy_session(struct iscsi_session *session)
{
	set_bit(SESSION_TERMINATING, &session->control_bits);
	clear_bit(SESSION_ESTABLISHED, &session->control_bits);

	down(&iscsi_session_sem);
	list_del(&session->list);
	up(&iscsi_session_sem);

	session->session_drop_time = jiffies ? jiffies : 1;
	signal_iscsi_threads(session);

	kthread_stop(session->tx_task);
	kthread_stop(session->rx_task);

	iscsi_disconnect(session);

	set_bit(SESSION_TERMINATED, &session->control_bits);

	/*
	 * grab the config mutex to make sure update_session is not
	 * accessing the session fields we are going to free
	 */
	down(&session->config_mutex);
	del_timer_sync(&session->transport_timer);
	del_timer_sync(&session->logout_timer);
	free_session(session);
	up(&session->config_mutex);
}

int
iscsi_create_session(struct iscsi_session *session,
		     struct iscsi_session_ioctl *ioctld)
{
	int rc;

	init_session_structure(session, ioctld);

	session->preallocated_task = kmem_cache_alloc(iscsi_task_cache,
						      GFP_KERNEL);
	if (!session->preallocated_task) {
		iscsi_host_err(session, "Couldn't preallocate task\n");
		rc = -ENOMEM;
		goto free_session;
	}

	session->mgmt_task = kmem_cache_alloc(iscsi_task_cache, GFP_KERNEL);
	if (!session->mgmt_task) {
		iscsi_host_err(session, "Couldn't preallocate mgmt task\n");
		rc = -ENOMEM;
		goto free_session;
	}
	memset(session->mgmt_task, 0, sizeof(*session->mgmt_task));
	iscsi_init_task(session->mgmt_task);

	rc = copy_iscsi_strings(session, ioctld);
	if (rc)
		goto free_session;

	memcpy(session->isid, ioctld->isid, sizeof(session->isid));

	/*
	 * FIXME: Do we have to check on both the username_in and
	 * password_length_in. Same with iscsi_update_session as well? Smitha
	 */
	if (ioctld->username_in[0] || ioctld->password_length_in)
		session->bidirectional_auth = 1;
	else
		session->bidirectional_auth = 0;
	rc = alloc_auth_buffers(session);
	if (rc)
		goto free_session;

	memcpy(&session->portal, &ioctld->portal, sizeof(ioctld->portal));
	iscsi_set_portal(session);

	/*
	 * preallocate rx/tx_tfm, so that we do not have to possibly
	 * call crypto_alloc_tfm (it uses GFP_KERNEL) while IO is queued.
	 */
	session->rx_tfm = crypto_alloc_tfm("crc32c", 0);
	if (!session->rx_tfm) {
		rc = -ENOMEM;
		goto free_session;
	}

	session->tx_tfm = crypto_alloc_tfm("crc32c", 0);
	if (!session->tx_tfm) {
		rc = -ENOMEM;
		goto free_session;
	}

	rc = start_session_threads(session);
	up(&session->config_mutex);
	if (rc)
		goto free_session;

	down(&iscsi_session_sem);
	list_add_tail(&session->list, &iscsi_sessions);
	up(&iscsi_session_sem);

	wait_event_interruptible(session->login_wait_q,
		test_bit(SESSION_ESTABLISHED, &session->control_bits));
	if (!test_bit(SESSION_ESTABLISHED, &session->control_bits)) {
		iscsi_destroy_session(session);
		return -ENOTCONN;
	}

	return 0;
	
 free_session:
	free_session(session);
	return rc;
}

struct iscsi_session *
iscsi_find_session(const char *target_name, u8 isid[6], int tpgt)
{
	struct iscsi_session *session;

	down(&iscsi_session_sem);

	list_for_each_entry(session, &iscsi_sessions, list) {
		 if (!strcmp(session->target_name, target_name) &&
		     !memcmp(session->isid, isid, sizeof(session->isid)) &&
		     session->portal_group_tag == tpgt) {
			if (scsi_host_get(session->shost)) {
				up(&iscsi_session_sem);
				return session;
			}
			break;
		}
	}

	up(&iscsi_session_sem);
	return NULL;
}

int
iscsi_update_address(struct iscsi_session *session, char *address)
{
	struct sockaddr_in *addr;
	char *tag;
	char *port;
	int err = 1;

	tag = strrchr(address, ',');
	if (tag) {
		*tag = '\0';
		tag++;
	}

	port = strrchr(address, ':');
	if (port) {
		*port = '\0';
		port++;
	}

	/*
	 * Still only ipv4 is supported. No access to ipv6
	 * to test so feel free to implement it later...
	 */
	if (address[0] == '[') {
		iscsi_host_err(session, "Driver does not support ipv6 "
			       "addresses\n");
		err = 0;
		goto done;
	}

	addr = (struct sockaddr_in *)&session->addr;
	addr->sin_addr.s_addr = in_aton(address);
	if (port)
		addr->sin_port = htons(simple_strtoul(port, NULL, 0));
	else
		addr->sin_port = htons(ISCSI_TCP_PORT);

 done:
	/* restore the original strings */
	if (tag) {
		--tag;
		*tag = ',';
	}

	if (port) {
		--port;
		*port = ':';
	}

	return err;
}

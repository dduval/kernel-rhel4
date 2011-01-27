/*
 * iSCSI login library
 * Copyright (C) 2001 Cisco Systems, Inc.
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
 * $Id: iscsi-login.c,v 1.1.2.14 2005/06/09 06:23:21 smithan Exp $
 *
 *
 * Formation of iSCSI login pdu, processing the login response and other
 * functions are defined here
 */
#include "iscsi-session.h"
#include "iscsi-login.h"
#include "iscsi-protocol.h"
#include "iscsi-sfnet.h"

/* caller is assumed to be well-behaved and passing NUL terminated strings */
int
iscsi_add_text(struct iscsi_session *session, struct iscsi_hdr *pdu, char *data,
	       int max_data_length, char *param, char *value)
{
	int param_len = strlen(param);
	int value_len = strlen(value);
	int length = param_len + 1 + value_len + 1;	/* param, separator,
							 * value, and trailing
							 * NULL
							 */
	int pdu_length = ntoh24(pdu->dlength);
	char *text = data;
	char *end = data + max_data_length;
	char *pdu_text;

	/* find the end of the current text */
	text += pdu_length;
	pdu_text = text;
	pdu_length += length;

	if (text + length >= end) {
		iscsi_host_notice(session, "Failed to add login text "
				  "'%s=%s'\n", param, value);
		return 0;
	}

	/* param */
	strncpy(text, param, param_len);
	text += param_len;

	/* separator */
	*text++ = ISCSI_TEXT_SEPARATOR;

	/* value */
	strncpy(text, value, value_len);
	text += value_len;

	/* NUL */
	*text++ = '\0';

	/* update the length in the PDU header */
	hton24(pdu->dlength, pdu_length);

	return 1;
}

static int
iscsi_find_key_value(char *param, char *pdu, char *pdu_end, char **value_start,
		     char **value_end)
{
	char *str = param;
	char *text = pdu;
	char *value;

	if (value_start)
		*value_start = NULL;
	if (value_end)
		*value_end = NULL;

	/* make sure they contain the same bytes */
	while (*str) {
		if (text >= pdu_end)
			return 0;
		if (*text == '\0')
			return 0;
		if (*str != *text)
			return 0;
		str++;
		text++;
	}

	if ((text >= pdu_end) || (*text == '\0')
	    || (*text != ISCSI_TEXT_SEPARATOR)) {
		return 0;
	}

	/* find the value */
	value = text + 1;

	/* find the end of the value */
	while ((text < pdu_end) && (*text))
		text++;

	if (value_start)
		*value_start = value;
	if (value_end)
		*value_end = text;

	return 1;
}

static enum iscsi_login_status
get_auth_key_type(struct iscsi_acl *auth_client, char **data, char *end)
{
	char *key;
	char *value = NULL;
        char *value_end = NULL;
	char *text = *data;

	int keytype = AUTH_KEY_TYPE_NONE;

	while (acl_get_next_key_type(&keytype) == AUTH_STATUS_NO_ERROR) {
		key = (char *)acl_get_key_name(keytype);

		if (key && iscsi_find_key_value(key, text, end, &value,
						&value_end)) {
			if (acl_recv_key_value(auth_client, keytype, value) !=
					       AUTH_STATUS_NO_ERROR) {
				iscsi_err("login negotiation failed, can't "
					  "accept %s in security stage\n",
					  text);
				return LOGIN_NEGOTIATION_FAILED;
			}
			text = value_end;
			*data = text;
			return LOGIN_OK;
		}
	}
	iscsi_err("Login negotiation failed, can't accept %s in security "
		  "stage\n", text);
	return LOGIN_NEGOTIATION_FAILED;
}

static enum iscsi_login_status
get_security_text_keys(struct iscsi_session *session, char **data,
		       struct iscsi_acl *auth_client, char *end)
{
	char *text = *data;
	char *value = NULL;
	char *value_end = NULL;
	size_t size;
	int tag;
	enum iscsi_login_status ret;

	/*
	 * a few keys are possible in Security stage
	 * which the auth code doesn't care about, but
	 * which we might want to see, or at least not
	 * choke on.
	 */
	if (iscsi_find_key_value("TargetAlias", text, end, &value,
		&value_end)) {
		size = value_end - value;
		session->target_alias = kmalloc(size + 1, GFP_ATOMIC);
		if (!session->target_alias) {
			/* Alias not critical. So just print an error */
			iscsi_host_err(session, "Login failed to allocate "
				       "alias\n");
			*data = value_end;
			return LOGIN_OK;
		}
		memcpy(session->target_alias, value, size);
		session->target_alias[size] = '\0';
		text = value_end;
	} else if (iscsi_find_key_value("TargetAddress", text, end, &value,
					 &value_end)) {
		/*
		 * if possible, change the session's
		 * ip_address and port to the new
		 * TargetAddress
		 */
		if (iscsi_update_address(session, value)) {
			text = value_end;
		} else {
			iscsi_host_err(session, "Login redirection failed, "
				       "can't handle redirection to %s\n",
				       value);
			return LOGIN_REDIRECTION_FAILED;
		}
	} else if (iscsi_find_key_value("TargetPortalGroupTag", text, end,
					 &value, &value_end)) {
		/*
		 * We should have already obtained this
		 * via discovery.
		 * We've already picked an isid, so the
		 * most we can do is confirm we reached
		 * the portal group we were expecting to
		 */
		tag = simple_strtoul(value, NULL, 0);
		if (session->portal_group_tag >= 0) {
			if (tag != session->portal_group_tag) {
				iscsi_host_err(session, "Portal group tag "
					       "mismatch, expected %u, "
					       "received %u\n",
					       session->portal_group_tag, tag);
				return LOGIN_WRONG_PORTAL_GROUP;
			}
		} else
			/* we now know the tag */
			session->portal_group_tag = tag;

		text = value_end;
	} else {
		/*
		 * any key we don't recognize either
		 * goes to the auth code, or we choke
		 * on it
		 */
		ret = get_auth_key_type(auth_client, &text, end);
		if (ret != LOGIN_OK)
			return ret;
	}
	*data = text;
	return LOGIN_OK;
}

static enum iscsi_login_status
get_op_params_text_keys(struct iscsi_session *session, char **data, char *end)
{
	char *text = *data;
	char *value = NULL;
	char *value_end = NULL;
	size_t size;

	if (iscsi_find_key_value("TargetAlias", text, end, &value,
				 &value_end)) {
		size = value_end - value;
		if (session->target_alias &&
		    strlen(session->target_alias) == size &&
		    memcmp(session->target_alias, value, size) == 0) {
			*data = value_end;
			return LOGIN_OK;
		}
		kfree(session->target_alias);
		session->target_alias = kmalloc(size + 1, GFP_ATOMIC);
		if (!session->target_alias) {
			/* Alias not critical. So just print an error */
			iscsi_host_err(session, "Login failed to allocate "
				       "alias\n");
			*data = value_end;
			return LOGIN_OK;
		}
		memcpy(session->target_alias, value, size);
		session->target_alias[size] = '\0';
		text = value_end;
	} else if (iscsi_find_key_value("TargetAddress", text, end, &value,
					 &value_end)) {
		if (iscsi_update_address(session, value))
			text = value_end;
		else {
			iscsi_host_err(session, "Login redirection failed, "
				       "can't handle redirection to %s\n",
				       value);
			return LOGIN_REDIRECTION_FAILED;
		}
	} else if (iscsi_find_key_value("TargetPortalGroupTag", text, end,
					 &value, &value_end)) {
		/*
		 * confirm we reached the portal group we were expecting to
		 */
		int tag = simple_strtoul(value, NULL, 0);
		if (session->portal_group_tag >= 0) {
			if (tag != session->portal_group_tag) {
				iscsi_host_err(session, "Portal group tag "
					       "mismatch, expected %u, "
					       "received %u\n",
					       session->portal_group_tag, tag);
				return LOGIN_WRONG_PORTAL_GROUP;
			}
		} else
			/* we now know the tag */
			session->portal_group_tag = tag;

		text = value_end;
	} else if (iscsi_find_key_value("InitialR2T", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (value && !strcmp(value, "Yes"))
				session->initial_r2t = 1;
		} else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_INITIALR2T;
		text = value_end;
	} else if (iscsi_find_key_value("ImmediateData", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (value && (strcmp(value, "Yes") == 0))
				session->immediate_data = 1;
			else
				session->immediate_data = 0;
		} else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_IMMEDIATEDATA;
		text = value_end;
	} else if (iscsi_find_key_value("MaxRecvDataSegmentLength", text, end,
				     &value, &value_end)) {
		session->max_xmit_data_segment_len =
					    simple_strtoul(value, NULL, 0);
		text = value_end;
	} else if (iscsi_find_key_value("FirstBurstLength", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL)
			session->first_burst_len =
					    	simple_strtoul(value, NULL, 0);
		else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_FIRSTBURSTLENGTH;
		text = value_end;
	} else if (iscsi_find_key_value("MaxBurstLength", text, end, &value,
					 &value_end)) {
		/*
		 * we don't really care, since it's a  limit on the target's
		 * R2Ts, but record it anwyay
		 */
		if (session->type == ISCSI_SESSION_TYPE_NORMAL)
			session->max_burst_len = simple_strtoul(value, NULL, 0);
		else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_MAXBURSTLENGTH;
		text = value_end;
	} else if (iscsi_find_key_value("HeaderDigest", text, end, &value,
					 &value_end)) {
		if (strcmp(value, "None") == 0) {
			if (session->header_digest != ISCSI_DIGEST_CRC32C)
				session->header_digest = ISCSI_DIGEST_NONE;
			else {
				iscsi_host_err(session, "Login negotiation "
					       "failed, HeaderDigest=CRC32C "
					       "is required, can't accept "
					       "%s\n", text);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else if (strcmp(value, "CRC32C") == 0) {
			if (session->header_digest != ISCSI_DIGEST_NONE)
				session->header_digest = ISCSI_DIGEST_CRC32C;
			else {
				iscsi_host_err(session, "Login negotiation "
					       "failed, HeaderDigest=None is "
					       "required, can't accept %s\n",
					       text);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else {
			iscsi_host_err(session, "Login negotiation failed, "
				       "can't accept %s\n", text);
			return LOGIN_NEGOTIATION_FAILED;
		}
		text = value_end;
	} else if (iscsi_find_key_value("DataDigest", text, end, &value,
					 &value_end)) {
		if (strcmp(value, "None") == 0) {
			if (session->data_digest != ISCSI_DIGEST_CRC32C)
				session->data_digest = ISCSI_DIGEST_NONE;
			else {
				iscsi_host_err(session, "Login negotiation "
					       "failed, DataDigest=CRC32C "
					       "is required, can't accept "
					       "%s\n", text);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else if (strcmp(value, "CRC32C") == 0) {
			if (session->data_digest != ISCSI_DIGEST_NONE)
				session->data_digest = ISCSI_DIGEST_CRC32C;
			else {
				iscsi_host_err(session, "Login negotiation "
					       "failed, DataDigest=None is "
					       "required, can't accept %s\n",
					       text);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else {
			iscsi_host_err(session, "Login negotiation failed, "
				       "can't accept %s\n", text);
			return LOGIN_NEGOTIATION_FAILED;
		}
		text = value_end;
	} else if (iscsi_find_key_value("DefaultTime2Wait", text, end, &value,
					 &value_end)) {
		session->def_time2wait = simple_strtoul(value, NULL, 0);
		text = value_end;
	} else if (iscsi_find_key_value("DefaultTime2Retain", text, end,
					 &value, &value_end)) {
		session->def_time2retain = simple_strtoul(value, NULL, 0);
		text = value_end;
	} else if (iscsi_find_key_value("OFMarker", text, end, &value,
					 &value_end))
		/* result function is AND, target must honor our No */
		text = value_end;
	else if (iscsi_find_key_value("OFMarkInt", text, end, &value,
					 &value_end))
		/* we don't do markers, so we don't care */
		text = value_end;
	else if (iscsi_find_key_value("IFMarker", text, end, &value,
					 &value_end))
		/* result function is AND, target must honor our No */
		text = value_end;
	else if (iscsi_find_key_value("IFMarkInt", text, end, &value,
					 &value_end))
		/* we don't do markers, so we don't care */
		text = value_end;
	else if (iscsi_find_key_value("DataPDUInOrder", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (value && !strcmp(value, "Yes"))
				session->data_pdu_in_order = 1;
		} else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_DATAPDUINORDER;
		text = value_end;
	} else if (iscsi_find_key_value ("DataSequenceInOrder", text, end,
					 &value, &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (value && !strcmp(value, "Yes"))
				session->data_seq_in_order = 1;
		} else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_DATASEQUENCEINORDER;
		text = value_end;
	} else if (iscsi_find_key_value("MaxOutstandingR2T", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (strcmp(value, "1")) {
				iscsi_host_err(session, "Login negotiation "
					       "failed, can't accept Max"
					       "OutstandingR2T %s\n", value);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_MAXOUTSTANDINGR2T;
		text = value_end;
	} else if (iscsi_find_key_value("MaxConnections", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (strcmp(value, "1")) {
				iscsi_host_err(session, "Login negotiation "
					       "failed, can't accept Max"
					       "Connections %s\n", value);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_MAXCONNECTIONS;
		text = value_end;
	} else if (iscsi_find_key_value("ErrorRecoveryLevel", text, end,
					 &value, &value_end)) {
		if (strcmp(value, "0")) {
			iscsi_host_err(session, "Login negotiation failed, "
				       "can't accept ErrorRecovery %s\n",
				       value);
			return LOGIN_NEGOTIATION_FAILED;
		}
		text = value_end;
	} else if (iscsi_find_key_value ("X-com.cisco.protocol", text, end,
					 &value, &value_end)) {
		if (strcmp(value, "NotUnderstood") &&
		    strcmp(value, "Reject") &&
		    strcmp(value, "Irrelevant") &&
		    strcmp(value, "draft20")) {
			/* if we didn't get a compatible protocol, fail */
			iscsi_host_err(session, "Login version mismatch, "
				       "can't accept protocol %s\n", value);
			return LOGIN_VERSION_MISMATCH;
		}
		text = value_end;
	} else if (iscsi_find_key_value("X-com.cisco.PingTimeout", text, end,
					 &value, &value_end))
		/* we don't really care what the target ends up using */
		text = value_end;
	else if (iscsi_find_key_value("X-com.cisco.sendAsyncText", text, end,
					 &value, &value_end))
		/* we don't bother for the target response */
		text = value_end;
	else {
		iscsi_host_err(session, "Login negotiation failed, couldn't "
			       "recognize text %s\n", text);
		return LOGIN_NEGOTIATION_FAILED;
	}
	*data = text;
	return LOGIN_OK;
}

static enum iscsi_login_status
check_security_stage_status(struct iscsi_session *session,
			    struct iscsi_acl *auth_client)
{
	int debug_status = 0;

	switch (acl_recv_end(auth_client)) {
	case AUTH_STATUS_CONTINUE:
		/* continue sending PDUs */
		break;

	case AUTH_STATUS_PASS:
		break;

	case AUTH_STATUS_NO_ERROR:	/* treat this as an error,
					 * since we should get a
					 * different code
					 */
	case AUTH_STATUS_ERROR:
	case AUTH_STATUS_FAIL:
	default:
		if (acl_get_dbg_status(auth_client, &debug_status) !=
		    AUTH_STATUS_NO_ERROR)
			iscsi_host_err(session, "Login authentication failed "
				       "with target %s, %s\n",
				       session->target_name,
				       acl_dbg_status_to_text(debug_status));
		else
			iscsi_host_err(session, "Login authentication failed "
				       "with target %s\n",
				       session->target_name);
		return LOGIN_AUTHENTICATION_FAILED;
	}
	return LOGIN_OK;
}

/*
 * this assumes the text data is always NULL terminated.  The caller can
 * always arrange for that by using a slightly larger buffer than the max PDU
 * size, and then appending a NULL to the PDU.
 */
static enum iscsi_login_status
iscsi_process_login_response(struct iscsi_session *session,
			     struct iscsi_login_rsp_hdr *login_rsp_pdu,
			     char *data, int max_data_length)
{
	int transit = login_rsp_pdu->flags & ISCSI_FLAG_LOGIN_TRANSIT;
	char *text = data;
	char *end;
	int pdu_current_stage, pdu_next_stage;
	enum iscsi_login_status ret;
	struct iscsi_acl *auth_client = NULL;

	if (session->password_length)
		auth_client = session->auth_client_block ?
					session->auth_client_block : NULL;

	end = text + ntoh24(login_rsp_pdu->dlength) + 1;
	if (end >= (data + max_data_length)) {
		iscsi_host_err(session, "Login failed, process_login_response "
			       "buffer too small to guarantee NULL "
			       "termination\n");
		return LOGIN_FAILED;
	}

	/* guarantee a trailing NUL */
	*end = '\0';

	/* if the response status was success, sanity check the response */
	if (login_rsp_pdu->status_class == ISCSI_STATUS_CLS_SUCCESS) {
		/* check the active version */
		if (login_rsp_pdu->active_version != ISCSI_DRAFT20_VERSION) {
			iscsi_host_err(session, "Login version mismatch, "
				       "received incompatible active iSCSI "
				       "version 0x%02x, expected version "
				       "0x%02x\n",
				       login_rsp_pdu->active_version,
				       ISCSI_DRAFT20_VERSION);
			return LOGIN_VERSION_MISMATCH;
		}

		/* make sure the current stage matches */
		pdu_current_stage = (login_rsp_pdu->flags &
				    ISCSI_FLAG_LOGIN_CURRENT_STAGE_MASK) >> 2;
		if (pdu_current_stage != session->current_stage) {
			iscsi_host_err(session, "Received invalid login PDU, "
				       "current stage mismatch, session %d, "
				       "response %d\n", session->current_stage,
				       pdu_current_stage);
			return LOGIN_INVALID_PDU;
		}

		/*
		 * make sure that we're actually advancing if the T-bit is set
		 */
		pdu_next_stage = login_rsp_pdu->flags &
				 ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK;
		if (transit && (pdu_next_stage <= session->current_stage))
			return LOGIN_INVALID_PDU;
	}

	if (session->current_stage == ISCSI_SECURITY_NEGOTIATION_STAGE) {
		if (acl_recv_begin(auth_client) != AUTH_STATUS_NO_ERROR) {
			iscsi_host_err(session, "Login failed because "
				       "acl_recv_begin failed\n");
			return LOGIN_FAILED;
		}

		if (acl_recv_transit_bit(auth_client, transit) !=
		    AUTH_STATUS_NO_ERROR) {
			iscsi_host_err(session, "Login failed because "
				  "acl_recv_transit_bit failed\n");
			return LOGIN_FAILED;
		}
	}

	/* scan the text data */
	while (text && (text < end)) {
		/* skip any NULs separating each text key=value pair */
		while ((text < end) && (*text == '\0'))
			text++;
		if (text >= end)
			break;

		/* handle keys appropriate for each stage */
		switch (session->current_stage) {
		case ISCSI_SECURITY_NEGOTIATION_STAGE:{
				ret = get_security_text_keys(session, &text,
							     auth_client, end);
				if (ret != LOGIN_OK)
					return ret;
				break;
			}
		case ISCSI_OP_PARMS_NEGOTIATION_STAGE:{
				ret = get_op_params_text_keys(session, &text,
							      end);
				if (ret != LOGIN_OK)
					return ret;
				break;
			}
		default:
			return LOGIN_FAILED;
		}
	}

	if (session->current_stage == ISCSI_SECURITY_NEGOTIATION_STAGE) {
		ret = check_security_stage_status(session, auth_client);
		if (ret != LOGIN_OK)
			return ret;
	}
	/* record some of the PDU fields for later use */
	session->tsih = ntohs(login_rsp_pdu->tsih);
	session->exp_cmd_sn = ntohl(login_rsp_pdu->expcmdsn);
	session->max_cmd_sn = ntohl(login_rsp_pdu->maxcmdsn);
	if (login_rsp_pdu->status_class == ISCSI_STATUS_CLS_SUCCESS)
		session->exp_stat_sn = ntohl(login_rsp_pdu->statsn) + 1;

	if (transit) {
		/* advance to the next stage */
		session->partial_response = 0;
		session->current_stage = login_rsp_pdu->flags &
					 ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK;
		session->irrelevant_keys_bitmap = 0;
	} else
		/*
		 * we got a partial response, don't advance,
		 * more negotiation to do
		 */
		session->partial_response = 1;

	return LOGIN_OK;	/* this PDU is ok, though the login process
				 * may not be done yet
				 */
}

static int
add_params_normal_session(struct iscsi_session *session, struct iscsi_hdr *pdu,
                    char *data, int max_data_length)
{
	char value[AUTH_STR_MAX_LEN];

	/* these are only relevant for normal sessions */
	if (!iscsi_add_text(session, pdu, data, max_data_length, "InitialR2T",
			    session->initial_r2t ? "Yes" : "No"))
		return 0;

	if (!iscsi_add_text(session, pdu, data, max_data_length,
			    "ImmediateData",
			    session->immediate_data ? "Yes" : "No"))
		return 0;

	sprintf(value, "%d", session->max_burst_len);
	if (!iscsi_add_text(session, pdu, data, max_data_length,
			    "MaxBurstLength", value))
		return 0;

	sprintf(value, "%d",session->first_burst_len);
	if (!iscsi_add_text(session, pdu, data, max_data_length,
			    "FirstBurstLength", value))
		return 0;

	/* these we must have */
	if (!iscsi_add_text(session, pdu, data, max_data_length,
			    "MaxOutstandingR2T", "1"))
		return 0;
	if (!iscsi_add_text(session, pdu, data, max_data_length,
			    "MaxConnections", "1"))
		return 0;
	if (!iscsi_add_text(session, pdu, data, max_data_length,
			    "DataPDUInOrder", "Yes"))
		return 0;
	if (!iscsi_add_text(session, pdu, data, max_data_length,
			    "DataSequenceInOrder", "Yes"))
		return 0;

	return 1;
}

static int
add_vendor_specific_text(struct iscsi_session *session, struct iscsi_hdr *pdu,
                    char *data, int max_data_length)
{
	char value[AUTH_STR_MAX_LEN];

	/*
	 * adjust the target's PingTimeout for normal sessions,
	 * so that it matches the driver's ping timeout.  The
	 * network probably has the same latency in both
	 * directions, so the values ought to match.
	 */
	if (session->ping_timeout >= 0) {
		sprintf(value, "%d", session->ping_timeout);
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "X-com.cisco.PingTimeout", value))
			return 0;
	}

	if (session->send_async_text >= 0)
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "X-com.cisco.sendAsyncText",
				    session->send_async_text ? "Yes" : "No"))
			return 0;

	/*
	 * vendor-specific protocol specification. list of protocol level
	 * strings in order of preference allowable values are: draft<n>
	 * (e.g. draft8), rfc<n> (e.g. rfc666).
	 * For example: "X-com.cisco.protocol=draft20,draft8" requests draft 20,
	 * or 8 if 20 isn't supported. "X-com.cisco.protocol=draft8,draft20"
	 * requests draft 8, or 20 if 8 isn't supported. Targets that
	 * understand this key SHOULD return the protocol level they selected
	 * as a response to this key, though the active_version may be
	 * sufficient to distinguish which protocol was chosen.
	 * Note: This probably won't work unless we start in op param stage,
	 * since the security stage limits what keys we can send, and we'd need
	 * to have sent this on the first PDU of the login.  Keep sending it for
	 * informational use, and so that we can sanity check things later if
	 * the RFC and draft20 are using the same active version number,
	 * but have non-trivial differences.
	 */
	if (!iscsi_add_text(session, pdu, data, max_data_length,
			     "X-com.cisco.protocol", "draft20"))
		return 0;

	return 1;
}

static int
check_irrelevant_keys(struct iscsi_session *session, struct iscsi_hdr *pdu,
                    char *data, int max_data_length)
{
	/* If you receive irrelevant keys, just check them from the irrelevant
	 * keys bitmap and respond with the key=Irrelevant text
	 */

	if (session->irrelevant_keys_bitmap & IRRELEVANT_MAXCONNECTIONS)
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "MaxConnections", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_INITIALR2T)
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "InitialR2T", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_IMMEDIATEDATA)
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "ImmediateData", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_MAXBURSTLENGTH)
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "MaxBurstLength", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_FIRSTBURSTLENGTH)
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "FirstBurstLength", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_MAXOUTSTANDINGR2T)
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "MaxOutstandingR2T", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_DATAPDUINORDER)
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "DataPDUInOrder", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_DATASEQUENCEINORDER )
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "DataSequenceInOrder", "Irrelevant"))
			return 0;

	return 1;
}

static int
fill_crc_digest_text(struct iscsi_session *session, struct iscsi_hdr *pdu,
		     char *data, int max_data_length)
{
	switch (session->header_digest) {
	case ISCSI_DIGEST_NONE:
		if (!iscsi_add_text(session, pdu, data, max_data_length,
		    "HeaderDigest", "None"))
			return 0;
		break;
	case ISCSI_DIGEST_CRC32C:
		if (!iscsi_add_text(session, pdu, data, max_data_length,
		    "HeaderDigest", "CRC32C"))
			return 0;
		break;
	case ISCSI_DIGEST_CRC32C_NONE:
		if (!iscsi_add_text(session, pdu, data, max_data_length,
		    "HeaderDigest", "CRC32C,None"))
			return 0;
		break;
	default:
	case ISCSI_DIGEST_NONE_CRC32C:
		if (!iscsi_add_text(session, pdu, data, max_data_length,
		    "HeaderDigest", "None,CRC32C"))
			return 0;
		break;
	}

	switch (session->data_digest) {
	case ISCSI_DIGEST_NONE:
		if (!iscsi_add_text(session, pdu, data, max_data_length,
		    "DataDigest", "None"))
			return 0;
		break;
	case ISCSI_DIGEST_CRC32C:
		if (!iscsi_add_text(session, pdu, data, max_data_length,
		    "DataDigest", "CRC32C"))
			return 0;
		break;
	case ISCSI_DIGEST_CRC32C_NONE:
		if (!iscsi_add_text(session, pdu, data, max_data_length,
		    "DataDigest", "CRC32C,None"))
			return 0;
		break;
	default:
	case ISCSI_DIGEST_NONE_CRC32C:
		if (!iscsi_add_text(session, pdu, data, max_data_length,
		    "DataDigest", "None,CRC32C"))
			return 0;
		break;
	}
	return 1;
}

static int
fill_op_params_text(struct iscsi_session *session, struct iscsi_hdr *pdu,
		    char *data, int max_data_length, int *transit)
{
	char value[AUTH_STR_MAX_LEN];

	/* we always try to go from op params to full feature stage */
	session->current_stage = ISCSI_OP_PARMS_NEGOTIATION_STAGE;
	session->next_stage = ISCSI_FULL_FEATURE_PHASE;
	*transit = 1;

	/*
	 * If we haven't gotten a partial response, then either we shouldn't be
	 * here, or we just switched to this stage, and need to start offering
	 * keys.
	 */
	if (!session->partial_response) {
		/*
		 * request the desired settings the first time
		 * we are in this stage
		 */
		if (!fill_crc_digest_text(session, pdu, data, max_data_length))
			return 0;

		sprintf(value, "%d", session->max_recv_data_segment_len);
		if (!iscsi_add_text(session, pdu, data, max_data_length,
		    "MaxRecvDataSegmentLength", value))
			return 0;

		sprintf(value, "%d", session->def_time2wait);
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "DefaultTime2Wait", value))
			return 0;

		sprintf(value, "%d", session->def_time2retain);
		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "DefaultTime2Retain", value))
			return 0;

		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "IFMarker", "No"))
			return 0;

		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "OFMarker", "No"))
			return 0;

		if (!iscsi_add_text(session, pdu, data, max_data_length,
				    "ErrorRecoveryLevel", "0"))
			return 0;

		if (session->type == ISCSI_SESSION_TYPE_NORMAL)
			if (!add_params_normal_session(session, pdu, data,
						  max_data_length))
				return 0;

		/*
		 * Note: 12.22 forbids vendor-specific keys on discovery
		 * sessions, so the caller is violating the spec if it asks for
		 * these on a discovery session.
		 */
		if (session->vendor_specific_keys)
			if (!add_vendor_specific_text(session, pdu, data,
						      max_data_length))
				return 0;
	} else if (!check_irrelevant_keys(session, pdu, data, max_data_length))
		return 0;

	return 1;
}

static void
enum_auth_keys(struct iscsi_acl *auth_client, struct iscsi_hdr *pdu,
	       char *data, int max_data_length, int keytype)
{
	int present = 0, rc;
	char *key = (char *)acl_get_key_name(keytype);
	int key_length = key ? strlen(key) : 0;
	int pdu_length = ntoh24(pdu->dlength);
	char *auth_value = data + pdu_length + key_length + 1;
	unsigned int max_length = max_data_length - (pdu_length
					  + key_length + 1);

	/*
	 * add the key/value pairs the auth code wants to send
	 * directly to the PDU, since they could in theory be large.
	 */
	rc = acl_send_key_val(auth_client, keytype, &present, auth_value,
			      max_length);
	if ((rc == AUTH_STATUS_NO_ERROR) && present) {
		/* actually fill in the key */
		strncpy(&data[pdu_length], key, key_length);
		pdu_length += key_length;
		data[pdu_length] = '=';
		pdu_length++;
		/*
		 * adjust the PDU's data segment length
		 * to include the value and trailing NUL
		 */
		pdu_length += strlen(auth_value) + 1;
		hton24(pdu->dlength, pdu_length);
	}
}

static int
fill_security_params_text(struct iscsi_session *session, struct iscsi_hdr *pdu,
			  struct iscsi_acl *auth_client, char *data,
			  int max_data_length, int *transit)
{
	int keytype = AUTH_KEY_TYPE_NONE;
	int rc = acl_send_transit_bit(auth_client, transit);

	/* see if we're ready for a stage change */
	if (rc != AUTH_STATUS_NO_ERROR)
		return 0;

	if (*transit) {
		/*
		 * discovery sessions can go right to full-feature phase,
		 * unless they want to non-standard values for the few relevant
		 * keys, or want to offer vendor-specific keys
		 */
		if (session->type == ISCSI_SESSION_TYPE_DISCOVERY)
			if ((session->header_digest != ISCSI_DIGEST_NONE) ||
			    (session->data_digest != ISCSI_DIGEST_NONE) ||
			    (session-> max_recv_data_segment_len !=
			    DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH) ||
			    session->vendor_specific_keys)
				session->next_stage =
					    ISCSI_OP_PARMS_NEGOTIATION_STAGE;
			else
				session->next_stage = ISCSI_FULL_FEATURE_PHASE;
		else
			session->next_stage = ISCSI_OP_PARMS_NEGOTIATION_STAGE;
	} else
		session->next_stage = ISCSI_SECURITY_NEGOTIATION_STAGE;

	/* enumerate all the keys the auth code might want to send */
	while (acl_get_next_key_type(&keytype) == AUTH_STATUS_NO_ERROR)
		enum_auth_keys(auth_client, pdu, data, max_data_length,
			       keytype);

	return 1;
}

/**
 * iscsi_make_login_pdu - Prepare the login pdu to be sent to iSCSI target.
 * @session: session for which login is initiated.
 * @pdu: login header
 * @data: contains text keys to be negotiated during login
 * @max_data_length: data size
 *
 * Description:
 *     Based on whether authentication is enabled or not, corresponding text
 *     keys are filled up in login pdu.
 *
 **/
static int
iscsi_make_login_pdu(struct iscsi_session *session, struct iscsi_hdr *pdu,
		     char *data, int max_data_length)
{
	int transit = 0;
	int ret;
	struct iscsi_login_hdr *login_pdu = (struct iscsi_login_hdr *)pdu;
	struct iscsi_acl *auth_client = NULL;

	if (session->password_length)
		auth_client = session->auth_client_block ?
					session->auth_client_block : NULL;

	/* initialize the PDU header */
	memset(login_pdu, 0, sizeof(*login_pdu));
	login_pdu->opcode = ISCSI_OP_LOGIN_CMD | ISCSI_OP_IMMEDIATE;
	login_pdu->cid = 0;
	memcpy(login_pdu->isid, session->isid, sizeof(session->isid));
	login_pdu->tsih = 0;
	login_pdu->cmdsn = htonl(session->cmd_sn);	
	/* don't increment on immediate */
	login_pdu->min_version = ISCSI_DRAFT20_VERSION;
	login_pdu->max_version = ISCSI_DRAFT20_VERSION;

	/* we have to send 0 until full-feature stage */
	login_pdu->expstatsn = htonl(session->exp_stat_sn);

	/*
	 * the very first Login PDU has some additional requirements,
	 * and we need to decide what stage to start in.
	 */
	if (session->current_stage == ISCSI_INITIAL_LOGIN_STAGE) {
		if (session->initiator_name && session->initiator_name[0]) {
			if (!iscsi_add_text(session, pdu, data, max_data_length,
			     "InitiatorName", session->initiator_name))
				return 0;
		} else {
			iscsi_host_err(session, "InitiatorName is required "
				       "on the first Login PDU\n");
			return 0;
		}
		if (session->initiator_alias && session->initiator_alias[0]) {
			if (!iscsi_add_text(session, pdu, data, max_data_length,
			     "InitiatorAlias", session->initiator_alias))
				return 0;
		}

		if ((session->target_name && session->target_name[0]) &&
		    (session->type == ISCSI_SESSION_TYPE_NORMAL)) {
			if (!iscsi_add_text(session, pdu, data, max_data_length,
			    "TargetName", session->target_name))
				return 0;
		}

		if (!iscsi_add_text(session, pdu, data, max_data_length,
		    "SessionType", (session->type ==
		      ISCSI_SESSION_TYPE_DISCOVERY) ? "Discovery" : "Normal"))
			return 0;

		if (auth_client)
			/* we're prepared to do authentication */
			session->current_stage = session->next_stage =
			    ISCSI_SECURITY_NEGOTIATION_STAGE;
		else
			/* can't do any authentication, skip that stage */
			session->current_stage = session->next_stage =
			    ISCSI_OP_PARMS_NEGOTIATION_STAGE;
	}

	/* fill in text based on the stage */
	switch (session->current_stage) {
	case ISCSI_OP_PARMS_NEGOTIATION_STAGE:{
			ret = fill_op_params_text(session, pdu, data,
						  max_data_length, &transit);
			if (!ret)
				return ret;
			break;
		}
	case ISCSI_SECURITY_NEGOTIATION_STAGE:{
			ret = fill_security_params_text(session, pdu,
							auth_client, data,
							max_data_length,
						  	&transit);
			if (!ret)
				return ret;
			break;
		}
	case ISCSI_FULL_FEATURE_PHASE:
		iscsi_host_err(session, "Can't send login PDUs in full "
			       "feature phase\n");
		return 0;
	default:
		iscsi_host_err(session, "Can't send login PDUs in unknown "
			       "stage %d\n", session->current_stage);
		return 0;
	}

	/* fill in the flags */
	login_pdu->flags = 0;
	login_pdu->flags |= session->current_stage << 2;
	if (transit) {
		/* transit to the next stage */
		login_pdu->flags |= session->next_stage;
		login_pdu->flags |= ISCSI_FLAG_LOGIN_TRANSIT;
	} else
		/* next == current */
		login_pdu->flags |= session->current_stage;

	return 1;
}

static enum iscsi_login_status
check_for_authentication(struct iscsi_session *session,
			 struct iscsi_acl **auth_client)
{
	/* prepare for authentication */
	if (acl_init(TYPE_INITIATOR, session) != AUTH_STATUS_NO_ERROR) {
		iscsi_host_err(session, "Couldn't initialize authentication\n");
		return LOGIN_FAILED;
	}

	*auth_client = session->auth_client_block;

	if (session->username && 
	    (acl_set_user_name(*auth_client, session->username) !=
	    AUTH_STATUS_NO_ERROR)) {
		iscsi_host_err(session, "Couldn't set username\n");
		goto end;
	}

	if (session->password && (acl_set_passwd(*auth_client,
	    session->password, session->password_length) !=
		 AUTH_STATUS_NO_ERROR)) {
		iscsi_host_err(session, "Couldn't set password\n");
		goto end;
	}

	if (acl_set_ip_sec(*auth_client, 1) != AUTH_STATUS_NO_ERROR) {
		iscsi_host_err(session, "Couldn't set IPSec\n");
		goto end;
	}

	if (acl_set_auth_rmt(*auth_client, session->bidirectional_auth) !=
			     AUTH_STATUS_NO_ERROR) {
		iscsi_host_err(session, "Couldn't set remote authentication\n");
		goto end;
	}
	return LOGIN_OK;

 end:
	if (*auth_client && acl_finish(*auth_client) != AUTH_STATUS_NO_ERROR)
		iscsi_host_err(session, "Login failed, error finishing "
			       "auth_client\n");
	*auth_client = NULL;
	return LOGIN_FAILED;
}

static enum iscsi_login_status
check_status_login_response(struct iscsi_session *session,
			    struct iscsi_login_rsp_hdr *login_rsp_pdu,
			    char *data, int max_data_length, int *final)
{
	enum iscsi_login_status ret;

	switch (login_rsp_pdu->status_class) {
	case ISCSI_STATUS_CLS_SUCCESS:
		/* process this response and possibly continue sending PDUs */
		ret = iscsi_process_login_response(session, login_rsp_pdu,
						   data, max_data_length);
		if (ret != LOGIN_OK)	/* pass back whatever
					 * error we discovered
					 */
			*final = 1;
		break;
	case ISCSI_STATUS_CLS_REDIRECT:
		/*
		 * we need to process this response to get the
		 * TargetAddress of the redirect, but we don't care
		 * about the return code.
		 */
		iscsi_process_login_response(session, login_rsp_pdu,
					     data, max_data_length);
		ret = LOGIN_OK;
		*final = 1;
	case ISCSI_STATUS_CLS_INITIATOR_ERR:
		if (login_rsp_pdu->status_detail ==
		    ISCSI_LOGIN_STATUS_AUTH_FAILED) {
			iscsi_host_err(session, "Login failed to authenticate "
				       "with target %s\n",
				       session->target_name);
		}
		ret = LOGIN_OK;
		*final = 1;
	default:
		/*
		 * some sort of error, login terminated unsuccessfully,
		 * though this function did it's job.
		 * the caller must check the status_class and
		 * status_detail and decide what to do next.
		 */
		ret = LOGIN_OK;
		*final = 1;
	}
	return ret;
}

/**
 * iscsi_login - attempt to login to the target.
 * @session: login is initiated over this session
 * @buffer: holds login pdu
 * @bufsize: size of login pdu
 * @status_class: holds either success or failure as status of login
 * @status_detail: contains details based on the login status
 *
 * Description:
 *     The caller must check the status class to determine if the login
 *     succeeded. A return of 1 does not mean the login succeeded, it just
 *     means this function worked, and the status class is valid info.
 *     This allows the caller to decide whether or not to retry logins, so
 *     that we don't have any policy logic here.
 **/
enum iscsi_login_status
iscsi_login(struct iscsi_session *session, char *buffer, size_t bufsize,
	    uint8_t *status_class, uint8_t *status_detail)
{
	struct iscsi_acl *auth_client = NULL;
	struct iscsi_hdr pdu;
	struct iscsi_login_rsp_hdr *login_rsp_pdu;
	char *data;
	int received_pdu = 0;
	int max_data_length;
	int final = 0;
	enum iscsi_login_status ret = LOGIN_FAILED;

	/* prepare the session */
	session->cmd_sn = 1;
	session->exp_cmd_sn = 1;
	session->max_cmd_sn = 1;
	session->exp_stat_sn = 0;

	session->current_stage = ISCSI_INITIAL_LOGIN_STAGE;
	session->partial_response = 0;

	if (session->password_length) {
		ret = check_for_authentication(session, &auth_client);
		if (ret != LOGIN_OK)
			return ret;
	}

	/*
	 * exchange PDUs until the login stage is complete, or an error occurs
	 */
	do {
		final = 0;
		login_rsp_pdu = (struct iscsi_login_rsp_hdr *)&pdu;
		ret = LOGIN_FAILED;

		memset(buffer, 0, bufsize);
		data = buffer;
		max_data_length = bufsize;

		/*
		 * fill in the PDU header and text data based on the login
		 * stage that we're in
		 */
		if (!iscsi_make_login_pdu(session, &pdu, data,
					  max_data_length)) {
			iscsi_host_err(session, "login failed, couldn't make "
				       "a login PDU\n");
			ret = LOGIN_FAILED;
			goto done;
		}

		/* send a PDU to the target */
		if (!iscsi_send_pdu(session, &pdu, ISCSI_DIGEST_NONE,
				    data, ISCSI_DIGEST_NONE)) {
			/*
			 * FIXME: caller might want us to distinguish I/O
			 * error and timeout. Might want to switch portals on
			 * timeouts, but
			 * not I/O errors.
			 */
			iscsi_host_err(session, "Login I/O error, failed to "
				       "send a PDU\n");
			ret = LOGIN_IO_ERROR;
			goto done;
		}

		/* read the target's response into the same buffer */
		if (!iscsi_recv_pdu(session, &pdu, ISCSI_DIGEST_NONE, data,
				    max_data_length, ISCSI_DIGEST_NONE)) {
			/*
			 * FIXME: caller might want us to distinguish I/O
			 * error and timeout. Might want to switch portals on
			 * timeouts, but not I/O errors.
			 */
			iscsi_host_err(session, "Login I/O error, failed to "
				       "receive a PDU\n");
			ret = LOGIN_IO_ERROR;
			goto done;
		}

		received_pdu = 1;

		/* check the PDU response type */
		if (pdu.opcode == (ISCSI_OP_LOGIN_RSP | 0xC0)) {
			/*
			 * it's probably a draft 8 login response,
			 * which we can't deal with
			 */
			iscsi_host_err(session, "Received iSCSI draft 8 login "
				       "response opcode 0x%x, expected draft "
				       "20 login response 0x%2x\n",
				       pdu.opcode, ISCSI_OP_LOGIN_RSP);
			ret = LOGIN_VERSION_MISMATCH;
			goto done;
		} else if (pdu.opcode != ISCSI_OP_LOGIN_RSP) {
			ret = LOGIN_INVALID_PDU;
			goto done;
		}

		/*
		 * give the caller the status class and detail from the last
		 * login response PDU received
		 */
		if (status_class)
			*status_class = login_rsp_pdu->status_class;
		if (status_detail)
			*status_detail = login_rsp_pdu->status_detail;
		ret = check_status_login_response(session, login_rsp_pdu, data,
						    max_data_length, &final);
		if (final)
			goto done;
	} while (session->current_stage != ISCSI_FULL_FEATURE_PHASE);

	ret = LOGIN_OK;

 done:
	if (auth_client && acl_finish(auth_client) != AUTH_STATUS_NO_ERROR) {
		iscsi_host_err(session, "Login failed, error finishing "
			       "auth_client\n");
		if (ret == LOGIN_OK)
			ret = LOGIN_FAILED;
	}

	return ret;
}

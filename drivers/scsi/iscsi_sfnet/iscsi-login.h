/*
 * iSCSI driver for Linux
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
 * $Id: iscsi-login.h,v 1.1.2.7 2005/03/15 06:33:39 wysochanski Exp $
 *
 * include for iSCSI login
 */
#ifndef ISCSI_LOGIN_H_
#define ISCSI_LOGIN_H_

struct iscsi_session;
struct iscsi_hdr;

#define ISCSI_SESSION_TYPE_NORMAL 0
#define ISCSI_SESSION_TYPE_DISCOVERY 1

/* not defined by iSCSI, but used in the login code to determine
 * when to send the initial Login PDU
 */
#define ISCSI_INITIAL_LOGIN_STAGE -1

#define ISCSI_TEXT_SEPARATOR     '='

enum iscsi_login_status {
	LOGIN_OK = 0,		/* library worked, but caller must check
				 * the status class and detail
				 */
	LOGIN_IO_ERROR,		/* PDU I/O failed, connection have been
				 * closed or reset
				 */
	LOGIN_FAILED,		/* misc. failure */
	LOGIN_VERSION_MISMATCH,	/* incompatible iSCSI protocol version */
	LOGIN_NEGOTIATION_FAILED,	/* didn't like a key value
					 * (or received an unknown key)
					 */
	LOGIN_AUTHENTICATION_FAILED,	/* auth code indicated failure */
	LOGIN_WRONG_PORTAL_GROUP,	/* portal group tag didn't match
					 * the one required
					 */
	LOGIN_REDIRECTION_FAILED,	/* couldn't handle the redirection
					 * requested by the target
					 */
	LOGIN_INVALID_PDU,	/* received an incorrect opcode,
				 * or bogus fields in a PDU
				 */
};

/* implemented in iscsi-login.c for use on all platforms */
extern int iscsi_add_text(struct iscsi_session *session, struct iscsi_hdr *pdu,
			  char *data, int max_data_length, char *param,
			  char *value);
extern enum iscsi_login_status iscsi_login(struct iscsi_session *session,
					   char *buffer, size_t bufsize,
					   uint8_t * status_class,
					   uint8_t * status_detail);

/* Digest types */
#define ISCSI_DIGEST_NONE  0
#define ISCSI_DIGEST_CRC32C 1
#define ISCSI_DIGEST_CRC32C_NONE 2	/* offer both, prefer CRC32C */
#define ISCSI_DIGEST_NONE_CRC32C 3	/* offer both, prefer None */

#define IRRELEVANT_MAXCONNECTIONS	0x01
#define IRRELEVANT_INITIALR2T		0x02
#define IRRELEVANT_IMMEDIATEDATA	0x04
#define IRRELEVANT_MAXBURSTLENGTH	0x08
#define IRRELEVANT_FIRSTBURSTLENGTH	0x10
#define IRRELEVANT_MAXOUTSTANDINGR2T	0x20
#define IRRELEVANT_DATAPDUINORDER	0x40
#define IRRELEVANT_DATASEQUENCEINORDER	0x80

#endif

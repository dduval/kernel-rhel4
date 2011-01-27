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
 * $Id: iscsi-auth.c,v 1.1.2.5 2005/03/20 03:13:21 wysochanski Exp $
 *
 * This file contains kernel wrappers around the iscsi auth common code.
 */
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <asm/scatterlist.h>

#include "iscsi-sfnet.h"
#include "iscsi-protocol.h"
#include "iscsi-session.h"
/*
 * Authenticate a target's CHAP response.
 *
 * Use the kernel crypto API
 */

enum auth_dbg_status
acl_chap_compute_rsp(struct iscsi_acl *client, int rmt_auth, u32 id,
		     u8 *challenge_data, u32 challenge_length,
		     u8 *response_data)
{
	struct iscsi_session *session = client->session_handle;
	u8 id_data[1];
	struct scatterlist sg;
	struct crypto_tfm *tfm = session->md5_tfm;
	u8 out_data[AUTH_STR_MAX_LEN];
	u32 out_length = AUTH_STR_MAX_LEN;

	if (!client->passwd_present)
		return AUTH_DBG_STATUS_LOCAL_PASSWD_NOT_SET;

	crypto_digest_init(tfm);
	/* id byte */
	id_data[0] = id;
	sg_init_one(&sg, &id_data[0], 1);
	crypto_digest_update(tfm, &sg, 1);

	/* decrypt password */
	if (acl_data(out_data, &out_length, client->passwd_data,
		     client->passwd_length))
		return AUTH_DBG_STATUS_PASSWD_DECRYPT_FAILED;

	if (!rmt_auth && !client->ip_sec && out_length < 12)
		return AUTH_DBG_STATUS_PASSWD_TOO_SHORT_WITH_NO_IPSEC;

	/* shared secret */
	sg_init_one(&sg, out_data, out_length);
	crypto_digest_update(tfm, &sg, 1);

	/* clear decrypted password */
	memset(out_data, 0, AUTH_STR_MAX_LEN);

	/* challenge value */
	sg_init_one(&sg, challenge_data, challenge_length);
	crypto_digest_update(tfm, &sg, 1);
	crypto_digest_final(tfm, response_data);

	return AUTH_DBG_STATUS_NOT_SET;	/* no error */
}

int
acl_chap_auth_request(struct iscsi_acl *client, char *username, unsigned int id,
		      unsigned char *challenge_data,
		      unsigned int challenge_length,
		      unsigned char *response_data,
		      unsigned int rsp_length)
{
	struct iscsi_session *session = client->session_handle;
	struct crypto_tfm *tfm = session->md5_tfm;
	struct scatterlist sg[3];
	unsigned char id_byte = id;
	unsigned char verify_data[16];

	/* the expected credentials are in the session */
	if (session->username_in == NULL) {
		iscsi_err("Failing authentication, no incoming username "
			  "configured to authenticate target %s\n",
			  session->target_name);
		return AUTH_STATUS_FAIL;
	}
	if (strcmp(username, session->username_in) != 0) {
		iscsi_err("Failing authentication, received incorrect username "
			  "from target %s\n", session->target_name);
		return AUTH_STATUS_FAIL;
	}

	if ((session->password_length_in < 1) ||
	    (session->password_in == NULL) ||
	    (session->password_in[0] == '\0')) {
		iscsi_err("Failing authentication, no incoming password "
			  "configured to authenticate target %s\n",
			  session->target_name);
		return AUTH_STATUS_FAIL;
	}

	/* challenge length is I->T, and shouldn't need to be checked */

	if (rsp_length != sizeof(verify_data)) {
		iscsi_err("Failing authentication, received incorrect CHAP "
			  "response length %u from target %s\n", rsp_length,
			  session->target_name);
		return AUTH_STATUS_FAIL;
	}

	/* id byte */
	id_byte = id;
	sg_init_one(&sg[0], &id_byte, 1);

	/* shared secret */
	sg_init_one(&sg[1], session->password_in, session->password_length_in);

	/* challenge value */
	sg_init_one(&sg[2], challenge_data, challenge_length);

	memset(verify_data, 0, sizeof(verify_data));
	crypto_digest_init(tfm);
	crypto_digest_digest(tfm, sg, 3, verify_data);

	if (memcmp(response_data, verify_data, sizeof(verify_data)) == 0)
		return AUTH_STATUS_PASS;

	iscsi_err("Failing authentication, received incorrect CHAP response "
		  "from target %s\n", session->target_name);

	return AUTH_STATUS_FAIL;
}

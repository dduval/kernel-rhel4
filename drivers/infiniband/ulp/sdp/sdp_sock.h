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
 * $Id: sdp_sock.h 2663 2005-06-20 17:17:58Z libor $
 */

#ifndef _SDP_SOCK_H
#define _SDP_SOCK_H

/*
 * SDP socket protocol/address family for socket() function. For all other
 * functions (e.g bind, connect, etc.) Either AF_INET or AF_INET_SDP can
 * be used with a SDP socket.
 */
#define AF_INET_SDP  27
#define PF_INET_SDP  AF_INET_SDP
#define AF_INET_STR "AF_INET_SDP" /* SDP enabled environment variable */

/*
 * Socket option level for SDP specific parameters.
 */
#define SOL_SDP   1025

/*
 * Socket options which are SDP specific
 */

/*
 * zero copy transfer thresholds. ({get,set}sockopt parameter optval is of
 *                                 type 'int')
 */
#define SDP_ZCOPY_THRSH_SRC  257 /* Threshold for AIO write advertisments */
#define SDP_ZCOPY_THRSH_SNK  258 /* Threshold for AIO read advertisments */
#define SDP_ZCOPY_THRSH      256 /* Convenience for read and write */

/*
 * Default values for SDP specific socket options. (for reference)
 */
#define SDP_ZCOPY_THRSH_SRC_DEFAULT  0x13FF
#define SDP_ZCOPY_THRSH_SNK_DEFAULT  0x13FF

#define SDP_UNBIND           259 /* Unbind socket. For libsdp use */

#endif /* _SDP_SOCK_H */

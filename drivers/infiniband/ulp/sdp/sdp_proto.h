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
 * $Id: sdp_proto.h 3370 2005-09-12 14:15:59Z mst $
 */

#ifndef _SDP_PROTO_H
#define _SDP_PROTO_H
/*
 * types used in the prototype file.
 */
#include <rdma/ib_verbs.h>

#include "sdp_conn.h"
#include "sdp_buff.h"
#include "sdp_advt.h"
#include "sdp_iocb.h"
#include "sdp_queue.h"
/*
 * Buffer managment
 */
struct sdpc_buff *sdp_buff_pool_get(void);

void sdp_buff_pool_put(struct sdpc_buff *buff);

void sdp_buff_q_init(struct sdpc_buff_q *pool);

void sdp_buff_q_clear_unmap(struct sdpc_buff_q *pool,
			    struct device *dev,
			    int direction);

static inline void sdp_buff_q_clear(struct sdpc_buff_q *pool)
{
	sdp_buff_q_clear_unmap(pool, NULL, 0);
}

struct sdpc_buff *sdp_buff_q_get(struct sdpc_buff_q *pool);

struct sdpc_buff *sdp_buff_q_get_head(struct sdpc_buff_q *pool);

struct sdpc_buff *sdp_buff_q_get_tail(struct sdpc_buff_q *pool);

struct sdpc_buff *sdp_buff_q_look_head(struct sdpc_buff_q *pool);

void sdp_buff_q_put(struct sdpc_buff_q *pool, struct sdpc_buff *buff);

void sdp_buff_q_put_head(struct sdpc_buff_q *pool, struct sdpc_buff *buff);

void sdp_buff_q_put_tail(struct sdpc_buff_q *pool, struct sdpc_buff *buff);

int sdp_buff_q_trav_head(struct sdpc_buff_q *pool,
			 int (*trav_func)(struct sdpc_buff *buff,
					  void *arg),
			 void *usr_arg);

struct sdpc_buff *sdp_buff_q_fetch(struct sdpc_buff_q *pool,
				   int (*test)(struct sdpc_buff *buff,
					       void *arg),
				   void *usr_arg);

int sdp_buff_pool_init(void);

void sdp_buff_pool_destroy(void);

int sdp_proc_dump_buff_pool(char *buffer,
			    int   max_size,
			    off_t start_index,
			    long *end_index);

/*
 * Wall between userspace protocol and SDP protocol proper
 */
void sdp_conn_abort(struct sdp_sock *conn);

void sdp_conn_inet_error(struct sdp_sock *conn, int error);

int sdp_recv_buff(struct sdp_sock *conn, struct sdpc_buff *buff);

/*
 * Zcopy advertisment managment
 */
int sdp_main_advt_init(void);

void sdp_main_advt_cleanup(void);

void sdp_advt_q_init(struct sdpc_advt_q *table);

void sdp_advt_q_clear(struct sdpc_advt_q *table);

struct sdpc_advt *sdp_advt_create(void);

void sdp_advt_destroy(struct sdpc_advt *advt);

struct sdpc_advt *sdp_advt_q_get(struct sdpc_advt_q *table);

struct sdpc_advt *sdp_advt_q_look(struct sdpc_advt_q *table);

void sdp_advt_q_put(struct sdpc_advt_q *table, struct sdpc_advt *advt);

/*
 * Zcopy IOCB managment
 */
int sdp_main_iocb_init(void);

void sdp_main_iocb_cleanup(void);

void sdp_iocb_q_init(struct sdpc_iocb_q *table);

void sdp_iocb_q_clear(struct sdpc_iocb_q *table);

struct sdpc_iocb *sdp_iocb_create(void);

void sdp_iocb_destroy(struct sdpc_iocb *iocb);

struct sdpc_iocb *sdp_iocb_q_look(struct sdpc_iocb_q *table);

struct sdpc_iocb *sdp_iocb_q_get_head(struct sdpc_iocb_q *table);

struct sdpc_iocb *sdp_iocb_q_get_tail(struct sdpc_iocb_q *table);

void sdp_iocb_q_put_head(struct sdpc_iocb_q *table, struct sdpc_iocb *iocb);

void sdp_iocb_q_put_tail(struct sdpc_iocb_q *table, struct sdpc_iocb *iocb);

struct sdpc_iocb *sdp_iocb_q_lookup(struct sdpc_iocb_q *table, u32 key);

void sdp_iocb_q_cancel(struct sdpc_iocb_q *table, u32 mask, ssize_t comp);

void sdp_iocb_q_remove(struct sdpc_iocb *iocb);

int sdp_iocb_register(struct sdpc_iocb *iocb, struct sdp_sock *conn);

void sdp_iocb_release(struct sdpc_iocb *iocb);

void sdp_iocb_complete(struct sdpc_iocb *iocb, ssize_t status);

int sdp_iocb_lock(struct sdpc_iocb *iocb);

void sdp_iocb_unlock(struct sdpc_iocb *iocb);

/*
 * Generic object managment
 */
void sdp_desc_q_remove(struct sdpc_desc *element);

struct sdpc_desc *sdp_desc_q_get_head(struct sdpc_desc_q *table);

struct sdpc_desc *sdp_desc_q_get_tail(struct sdpc_desc_q *table);

void sdp_desc_q_put_head(struct sdpc_desc_q *table,
			 struct sdpc_desc *element);

void sdp_desc_q_put_tail(struct sdpc_desc_q *table,
			 struct sdpc_desc *element);

struct sdpc_desc *sdp_desc_q_look_head(struct sdpc_desc_q *table);

int sdp_desc_q_type_head(struct sdpc_desc_q *table);

struct sdpc_desc *sdp_desc_q_look_type_head(struct sdpc_desc_q *table,
					   enum sdp_desc_type type);

struct sdpc_desc *sdp_desc_q_look_type_tail(struct sdpc_desc_q *table,
					   enum sdp_desc_type type);

struct sdpc_desc *sdp_desc_q_lookup(struct sdpc_desc_q *table,
				    int (*lookup)(struct sdpc_desc *element,
						  void *arg),
				    void *arg);

int sdp_desc_q_types_size(struct sdpc_desc_q *table,
			  enum sdp_desc_type type);

void sdp_desc_q_init(struct sdpc_desc_q *table);

void sdp_desc_q_clear(struct sdpc_desc_q *table);

/*
 * proc entry managment
 */
int sdp_main_proc_init(void);

void sdp_main_proc_cleanup(void);

/*
 * connection table
 */
int sdp_conn_table_init(int proto_family,
			int conn_size,
			int recv_post_max,
			int recv_buff_max,
			int send_post_max,
			int send_buff_max,
			int send_usig_max);

void sdp_conn_table_clear(void);

int sdp_proc_dump_conn_main(char *buffer,
			    int   max_size,
			    off_t start_index,
			    long *end_index);

int sdp_proc_dump_conn_data(char *buffer,
			    int   max_size,
			    off_t start_index,
			    long *end_index);

int sdp_proc_dump_conn_rdma(char *buffer,
			    int   max_size,
			    off_t start_index,
			    long *end_index);

int sdp_proc_dump_conn_sopt(char *buffer,
			    int   max_size,
			    off_t start_index,
			    long *end_index);

int sdp_proc_dump_device(char *buffer,
			 int   max_size,
			 off_t start_index,
			 long *end_index);

struct sdp_sock *sdp_conn_table_lookup(s32 entry);

struct sdp_sock *sdp_conn_alloc(unsigned int priority);

int sdp_conn_alloc_ib(struct sdp_sock *conn,
		      struct ib_device *device,
		      u8 hw_port,
		      u16 pkey);

void sdp_inet_wake_send(struct sock *sk);

/*
 * port/queue managment
 */
void sdp_inet_accept_q_put(struct sdp_sock *listen_conn,
			   struct sdp_sock *accept_conn);

struct sdp_sock *sdp_inet_accept_q_get(struct sdp_sock *listen_conn);

int sdp_inet_accept_q_remove(struct sdp_sock *accept_conn);

int sdp_inet_listen_start(struct sdp_sock *listen_conn);

int sdp_inet_listen_stop(struct sdp_sock *listen_conn);

struct sdp_sock *sdp_inet_listen_lookup(u32 addr, u16 port);

int sdp_inet_port_get(struct sdp_sock *conn, u16 port);

int sdp_inet_port_put(struct sdp_sock *conn);

void sdp_inet_port_inherit(struct sdp_sock *parent, struct sdp_sock *child);

/*
 * active connect functions
 */
int sdp_cm_connect(struct sdp_sock *conn);

int sdp_cm_rep_handler(struct ib_cm_id *cm_id,
		       struct ib_cm_event *event,
		       struct sdp_sock *conn);

void sdp_cm_actv_error(struct sdp_sock *conn, int error);
/*
 * passive connect functions
 */
int sdp_cm_pass_establish(struct sdp_sock *conn);

int sdp_cm_req_handler(struct ib_cm_id *cm_id,
		       struct ib_cm_event *event);

/*
 * post functions
 */
int sdp_recv_flush(struct sdp_sock *conn);

int sdp_send_flush(struct sdp_sock *conn);

int sdp_send_ctrl_ack(struct sdp_sock *conn);

int sdp_send_ctrl_disconnect(struct sdp_sock *conn);

int sdp_send_ctrl_abort(struct sdp_sock *conn);

int sdp_send_ctrl_send_sm(struct sdp_sock *conn);

int sdp_send_ctrl_snk_avail(struct sdp_sock *conn,
			    u32 size,
			    u32 rkey,
			    u64 addr);

int sdp_send_ctrl_resize_buff_ack(struct sdp_sock *conn, u32 size);

int sdp_send_ctrl_rdma_rd(struct sdp_sock *conn, s32 size);

int sdp_send_ctrl_rdma_wr(struct sdp_sock *conn, u32 size);

int sdp_send_ctrl_mode_ch(struct sdp_sock *conn, u8 mode);

int sdp_send_ctrl_src_cancel(struct sdp_sock *conn);

int sdp_send_ctrl_snk_cancel(struct sdp_sock *conn);

int sdp_send_ctrl_snk_cancel_ack(struct sdp_sock *conn);

/*
 * inet functions
 */

/*
 * event functions
 */
int sdp_cq_event_locked(struct ib_wc *comp, struct sdp_sock *conn);

void sdp_cq_event_handler(struct ib_cq *cq, void *arg);

int sdp_cm_event_handler(struct ib_cm_id *cm_id,
			 struct ib_cm_event *event);

int sdp_event_recv(struct sdp_sock *conn, struct ib_wc *comp);

int sdp_event_send(struct sdp_sock *conn, struct ib_wc *comp);

int sdp_event_read(struct sdp_sock *conn, struct ib_wc *comp);

int sdp_event_write(struct sdp_sock *conn, struct ib_wc *comp);

/*
 * DATA transport
 */
int sdp_inet_send(struct kiocb *iocb,
		  struct socket *sock,
		  struct msghdr *msg,
		  size_t size);

int sdp_inet_recv(struct kiocb *iocb,
		  struct socket *sock,
		  struct msghdr *msg,
		  size_t size,
		  int    flags);

void sdp_iocb_q_cancel_all_read(struct sdp_sock *conn, ssize_t error);

void sdp_iocb_q_cancel_all_write(struct sdp_sock *conn, ssize_t error);

void sdp_iocb_q_cancel_all(struct sdp_sock *conn, ssize_t error);

/*
 * link address information
 */
int sdp_link_path_lookup(u32 dst_addr,
			 u32 src_addr,
			 int bound_dev_if,
			 void (*completion)(u64 id,
					    int status,
					    u32 dst_addr,
					    u32 src_addr,
					    u8  hw_port,
					    struct ib_device *ca,
					    struct ib_sa_path_rec *path,
					    void *arg),
			 void *arg,
			 u64  *id);

int sdp_link_addr_init(void);

void sdp_link_addr_cleanup(void);

/*
 * Function types
 */

/*
 * Event handling function, demultiplexed base on Message ID
 */
typedef int (*sdp_event_cb_func)(struct sdp_sock *conn,
				 struct sdpc_buff *buff);

/*
 * trace macros
 */
extern int sdp_debug_level;
#define __SDP_DEBUG_LEVEL 4

#if defined(CONFIG_INFINIBAND_SDP_DEBUG)
#undef __SDP_DEBUG_LEVEL
#define __SDP_DEBUG_LEVEL 6
#endif
#if defined(CONFIG_INFINIBAND_SDP_DEBUG_DATA)
#undef __SDP_DEBUG_LEVEL
#define __SDP_DEBUG_LEVEL 9
#endif

#define __SDP_DEBUG_DATA  7
#define __SDP_DEBUG_CTRL  6
#define __SDP_DEBUG_NOTE  5
#define __SDP_DEBUG_INIT  5
#define __SDP_DEBUG_WARN  4
#define __SDP_DEBUG_ERROR 3

#define sdp_dbg_out(level, type, format, arg...) \
        do { \
                if (!(level > sdp_debug_level)) { \
                        printk("<%d>ib_sdp %s: " format "\n", \
                               level, type, ## arg);  \
                } \
        } while (0)

#define sdp_conn_dbg(level, type, conn, format, arg...) \
        do { \
                struct sdp_sock *x = (conn); \
                if (x) { \
                        sdp_dbg_out(level, type, \
                                      "<%d> <%04x> " format,  \
                                       x->hashent, x->state , \
                                       ## arg);               \
                } \
                else {  \
                        sdp_dbg_out(level, type, format, ## arg); \
                } \
        } while (0)

#if __SDP_DEBUG_LEVEL < __SDP_DEBUG_DATA
#define sdp_dbg_data(conn, format, arg...) do { } while (0)
#else
#define sdp_dbg_data(conn, format, arg...) \
        sdp_conn_dbg(__SDP_DEBUG_DATA, "DATA", conn, format, ## arg)
#endif

#if __SDP_DEBUG_LEVEL < __SDP_DEBUG_CTRL
#define sdp_dbg_ctrl(conn, format, arg...) do { } while (0)
#else
#define sdp_dbg_ctrl(conn, format, arg...) \
        sdp_conn_dbg(__SDP_DEBUG_CTRL, "CRTL", conn, format, ## arg)
#endif

#if __SDP_DEBUG_LEVEL < __SDP_DEBUG_NOTE
#define sdp_dbg_warn(conn, format, arg...) do { } while (0)
#else
#define sdp_dbg_warn(conn, format, arg...) \
        sdp_conn_dbg(__SDP_DEBUG_NOTE, "WARN", conn, format, ## arg)
#endif


#if __SDP_DEBUG_LEVEL < __SDP_DEBUG_INIT
#define sdp_dbg_init(format, arg...) do { } while (0)
#else
#define sdp_dbg_init(format, arg...) \
        sdp_dbg_out(__SDP_DEBUG_INIT, "INIT", format, ## arg)
#endif

#if __SDP_DEBUG_LEVEL < __SDP_DEBUG_WARN
#define sdp_dbg_err(format, arg...) do { } while (0)
#else
#define sdp_dbg_err(format, arg...)  \
        sdp_dbg_out(__SDP_DEBUG_WARN, " ERR", format, ## arg)
#endif

#if __SDP_DEBUG_LEVEL < __SDP_DEBUG_WARN
#define sdp_warn(format, arg...) do { } while (0)
#else
#define sdp_warn(format, arg...)     \
        sdp_dbg_out(__SDP_DEBUG_WARN, "WARN", format, ## arg)
#endif

#if __SDP_DEBUG_LEVEL < __SDP_DEBUG_CTRL
#define SDP_EXPECT(expr)
#else
#define SDP_EXPECT(expr)                                                 \
do {                                                                     \
	if (!(expr)) {                                                   \
		sdp_dbg_err("EXCEPT: Internal error check <%s> failed.", \
		            #expr);                                      \
	}                                                                \
} while (0) /* SDP_EXPECT */
#endif

/*
 * Inline functions
 */

/*
 * sdp_inet_write_space - writable space on send side
 */
static inline int sdp_inet_write_space(struct sdp_sock *conn, int urg)
{
	int size;
	/*
	 * Allow for more space if Urgent data is being considered.
	 * send_buf may be zero if we are holding data back, state
	 * transition will open it.
	 */
	size = (conn->send_buf - conn->send_qud);
	/*
	 * write space is determined by amount of outstanding bytes of data
	 * and number of buffers used for transmission by this connection
	 */
	if (conn->send_max > sdp_desc_q_types_size(&conn->send_queue,
						   SDP_DESC_TYPE_BUFF))
		return ((SDP_INET_SEND_MARK < size || 1 < urg) ? size : 0);
	else
		return 0;
}

/*
 * sdp_inet_writable - return non-zero if socket is writable
 */
static inline int sdp_inet_writable(struct sdp_sock *conn)
{
	if (conn->send_buf > 0)
		return (sdp_inet_write_space(conn, 0) <
			(conn->send_qud / 2)) ? 0 : 1;
	else
		return 0;
}

/*
 * sdp_conn_stat_dump - dump stats to the log
 */
static inline void sdp_conn_stat_dump(struct sdp_sock *conn)
{
#ifdef _SDP_CONN_STATS_REC
	int counter;

	sdp_dbg_init("STAT: src <%u> snk <%u>",
		     conn->src_serv, conn->snk_serv);

	for (counter = 0; counter < 0x20; counter++)
		if (conn->send_mid[counter] > 0 ||
		    conn->recv_mid[counter] > 0) {
			sdp_dbg_init("STAT: MID send <%02x> <%u>", counter,
				     conn->send_mid[counter]);
			sdp_dbg_init("STAT: MID recv <%02x> <%u>", counter,
				     conn->recv_mid[counter]);
		}
#endif
}

/*
 * sdp_conn_state_dump - dump state information to the log
 */
static inline void sdp_conn_state_dump(struct sdp_sock *conn)
{
#ifdef _SDP_CONN_STATE_REC
	int counter;

	sdp_dbg_init("STATE: Connection <%04x> state:", conn->hashent);

	if (conn->state_rec.state[0] == SDP_CONN_ST_INVALID) {
		sdp_dbg_init("STATE:   No state history. <%d>",
			     conn->state_rec.value);
		return;
	}

	for (counter = 0;
	     SDP_CONN_ST_INVALID != conn->state_rec.state[counter];
	     counter++)
		sdp_dbg_init("STATE:   counter <%02x> state <%04x> <%s:%d>",
			     counter,
			     conn->state_rec.state[counter],
			     conn->state_rec.file[counter],
			     conn->state_rec.line[counter]);
#endif
}

#endif /* _SDP_PROTO_H */

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
 * $Id: sdp_recv.c 3936 2005-11-02 10:28:44Z mst $
 */

#include "sdp_main.h"

/*
 * Receive posting function(s)
 */

/*
 * sdp_post_recv_buff - post a single buffers for data recv
 */
static int sdp_post_recv_buff(struct sdp_sock *conn)
{
	struct ib_recv_wr receive_param = { NULL };
	struct ib_recv_wr *bad_wr;
	struct sdpc_buff *buff;
	s32 result;

	/*
	 * get a buffer
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "failed to allocate buff for recv queue.");
		result = -ENOMEM;
		goto error;
	}
	/*
	 * The data pointer is backed up based on what the stream interface
	 * peer advertised to us plus the required header. This way the
	 * data we end up passing to the interface will always be within
	 * the correct range.
	 */
	buff->tail = buff->end;
	buff->data = buff->tail - conn->recv_size;
	buff->sge.lkey = conn->l_key;
	buff->wrid = conn->recv_wrid++;

	conn->l_recv_bf++;
	/*
	 * save the buffer for the event handler. Make sure it's before
	 * actually posting the thing. Completion event can happen before
	 * post function returns.
	 */
	sdp_dbg_data(conn, "POST RECV BUFF wrid <%llu> of <%u> bytes.",
		     (unsigned long long) buff->wrid,
		     (unsigned)(buff->tail - buff->data));
	/*
	 * post recv
	 */
 	buff->sge.length = buff->tail - buff->data;
 	buff->sge.addr = dma_map_single(conn->ca->dma_device,
					buff->data,
					buff->sge.length,
					PCI_DMA_FROMDEVICE);
	receive_param.next    = NULL;
	receive_param.wr_id   = buff->wrid;
	receive_param.sg_list = &buff->sge;
	receive_param.num_sge = 1;

	result = ib_post_recv(conn->qp, &receive_param, &bad_wr);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> posting receive buffer",
			     result);
		goto drop;
	}

	sdp_buff_q_put_tail(&conn->recv_post, buff);

	return 0;
drop:
	sdp_buff_pool_put(buff);
	conn->l_recv_bf--;
error:
	return result;
}

/*
 * sdp_post_rdma_buff - post a single buffers for rdma read on a conn
 */
static int sdp_post_rdma_buff(struct sdp_sock *conn)
{
	struct ib_send_wr send_param = { NULL };
	struct ib_send_wr *bad_wr;
	struct sdpc_advt *advt;
	struct sdpc_buff *buff;
	int result;

	/*
	 * check queue depth
	 */
	if (!(conn->send_cq_size > conn->s_wq_size))
		return ENODEV;
	/*
	 * get a reference to the first SrcAvail advertisment.
	 */
	advt = sdp_advt_q_look(&conn->src_pend);
	if (!advt)
		return ENODEV;
	/*
	 * get a buffer
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "failed to allocate buff for rdma read.");
		return -ENOMEM;
	}
	/*
	 * The data pointer is backed up based on what the stream interface
	 * peer advertised to us plus the required header. This way the
	 * data we end up passing to the interface will always be within
	 * the correct range.
	 */
	buff->tail  = buff->end;
	buff->data = buff->tail - min((s32)conn->recv_size, advt->size);
	buff->sge.lkey = conn->l_key;
	buff->wrid = conn->send_wrid++;

	send_param.opcode              = IB_WR_RDMA_READ;
	send_param.wr.rdma.remote_addr = advt->addr;
	send_param.wr.rdma.rkey        = advt->rkey;
	send_param.send_flags          = IB_SEND_SIGNALED;

	advt->wrid  = buff->wrid;
	advt->size -= (buff->tail - buff->data);
	advt->addr += (buff->tail - buff->data);
	advt->post += (buff->tail - buff->data);
	advt->flag |= SDP_ADVT_F_READ;
	/*
	 * If there is no more advertised space move the advertisment to the
	 * active list, and match the WRID.
	 */
	if (advt->size <= 0)
		sdp_advt_q_put(&conn->src_actv,
			       sdp_advt_q_get(&conn->src_pend));

	sdp_dbg_data(conn, "POST READ BUFF wrid <%llu> of <%u> bytes.",
		     (unsigned long long) buff->wrid,
		     (unsigned)(buff->tail - buff->data));
	/*
	 * post rdma
	 */
	buff->sge.addr     = virt_to_phys(buff->data);
	buff->sge.length   = buff->tail - buff->data;

	send_param.next    = NULL;
	send_param.wr_id   = buff->wrid;
	send_param.sg_list = &buff->sge;
	send_param.num_sge = 1;

	result = ib_post_send(conn->qp, &send_param, &bad_wr);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> posting rdma read", result);
		goto drop;
	}
	/*
	 * Save buffer and update send queue depth
	 */
	sdp_desc_q_put_tail(&conn->r_src, (struct sdpc_desc *) buff);

	conn->s_wq_size++;

	return 0;
drop:
	sdp_buff_pool_put(buff);
	return result;
}

/*
 * sdp_post_rdma_iocb_src - post a iocb for rdma read on a conn
 */
static int sdp_post_rdma_iocb_src(struct sdp_sock *conn)
{
	struct ib_send_wr send_param = { NULL };
	struct ib_send_wr *bad_wr;
	struct ib_sge sg_val;
	struct sdpc_iocb *iocb;
	struct sdpc_advt *advt;
	int result;
	int zcopy;

	/*
	 * check queue depth
	 */
	if (!(conn->send_cq_size > conn->s_wq_size))
		return ENODEV;
	/*
	 * get a reference to the first SrcAvail advertisment.
	 */
	advt = sdp_advt_q_look(&conn->src_pend);
	if (!advt)
		return ENODEV;
	/*
	 * get a reference to the first IOCB pending.
	 *
	 * check if the IOCB is in cancel processing.
	 * (final complete RDMA will clear it out.)
	 */
	iocb = sdp_iocb_q_look(&conn->r_pend);
	if (!iocb)
		return ENODEV;
	/*
	 * register IOCBs physical memory.
	 */
	result = sdp_iocb_register(iocb, conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> registering IOCB. <%d:%d>",
			     result, iocb->key, iocb->len);
		goto error;
	}
	/*
	 * amount of data to zcopy.
	 */
	zcopy = min(advt->size, iocb->len);

	sg_val.addr   = iocb->io_addr;
	sg_val.lkey   = iocb->l_key;
	sg_val.length = zcopy;

	send_param.opcode              = IB_WR_RDMA_READ;
	send_param.wr.rdma.remote_addr = advt->addr;
	send_param.wr.rdma.rkey        = advt->rkey;
	send_param.send_flags          = IB_SEND_SIGNALED;

	iocb->wrid     = conn->send_wrid++;
	iocb->len     -= zcopy;
	iocb->post    += zcopy;
	iocb->io_addr += zcopy;
	iocb->flags   |= SDP_IOCB_F_ACTIVE;
	iocb->flags   |= SDP_IOCB_F_RDMA_R;

	advt->wrid  = iocb->wrid;
	advt->size -= zcopy;
	advt->addr += zcopy;
	advt->post += zcopy;
	advt->flag |= SDP_ADVT_F_READ;
	/*
	 * if there is no more advertised space,  queue the
	 * advertisment for completion
	 */
	if (!advt->size)
		sdp_advt_q_put(&conn->src_actv,
			       sdp_advt_q_get(&conn->src_pend));
	/*
	 * if there is no more iocb space queue the it for completion
	 */
	if (!iocb->len)
		sdp_desc_q_put_tail(&conn->r_src,
				    (struct sdpc_desc *)
				    sdp_iocb_q_get_head(&conn->r_pend));

	sdp_dbg_data(conn, "POST READ IOCB wrid <%llu> bytes <%u:%d:%d>.",
		     (unsigned long long) iocb->wrid, zcopy,
		     iocb->len, advt->size);
	/*
	 * post RDMA
	 */
	send_param.next    = NULL;
	send_param.wr_id   = iocb->wrid;
	send_param.sg_list = &sg_val;
	send_param.num_sge = 1;

	result = ib_post_send(conn->qp, &send_param, &bad_wr);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> posting rdma read", result);
		goto error;
	}
	/*
	 * update send queue depth
	 */
	conn->s_wq_size++;

	return 0;
error:
	return result;
}

/*
 * sdp_post_rdma_iocb_snk - post a iocb for rdma read on a conn
 */
static int sdp_post_rdma_iocb_snk(struct sdp_sock *conn)
{
	struct sdpc_iocb *iocb;
	int result = 0;

	/*
	 * check if sink cancel is pending
	 */
	if (conn->flags & SDP_CONN_F_SNK_CANCEL)
		return ENODEV;
	/*
	 * get the pending iocb
	 */
	iocb = sdp_iocb_q_look(&conn->r_pend);
	if (!iocb)
		return ENODEV;
	/*
	 * check zcopy threshold
	 */
	if (conn->snk_zthresh > iocb->len)
		return ENODEV;
	/*
	 * check number of outstanding sink advertisments
	 */
	if (!(conn->r_max_adv > conn->snk_sent))
		return ENODEV;
	/*
	 * registration
	 */
	result = sdp_iocb_register(iocb, conn);
	if (result) {
		result = (-EAGAIN == result ? EAGAIN : result);
		if (result < 0)
			sdp_dbg_warn(conn, "Error <%d> registering IOCB",
				     result);

		goto error;
	}
	/*
	 * Either post a send, or buffer the packet in the tx queue
	 */
	result = sdp_send_ctrl_snk_avail(conn,
					 iocb->len,
					 iocb->r_key,
					 iocb->io_addr);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> sending SnkAvail message",
			     result);
		goto error;
	}
	/*
	 * Update and queue IOCB
	 */
	iocb->flags |= SDP_IOCB_F_ACTIVE;
	iocb->flags |= SDP_IOCB_F_RDMA_W;

	sdp_iocb_q_put_tail(&conn->r_snk, sdp_iocb_q_get_head(&conn->r_pend));

	conn->snk_sent++;

	return 0;
error:
	return result;
}

/*
 * sdp_post_rdma - post a rdma based requests for a connection
 */
static int sdp_post_rdma(struct sdp_sock *conn)
{
	int result = 0;

	/*
	 * Since RDMA Reads rely on posting to the Send WQ, stop if
	 * we're not in an appropriate state. It's possible to queue
	 * the sink advertisment, something to explore, but SrcAvail
	 * slow start might make that unneccessart?
	 */
	if (!(SDP_ST_MASK_SEND_OK & conn->state))
		return 0;
	/*
	 * loop flushing IOCB RDMAs. Read sources, otherwise post sinks.
	 */
	if (sdp_advt_q_size(&conn->src_pend) > 0) {
		if (!sdp_desc_q_types_size(&conn->r_src,
					       SDP_DESC_TYPE_BUFF))
			while (!(result = sdp_post_rdma_iocb_src(conn))) {
				/*
				 * pass, nothing to do in loop.
				 */
			}
		/*
		 * check non-zero result
		 */
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> posting RDMA IOCB read",
				     result);
			goto done;
		}
		/*
		 * loop posting RDMA reads, if there is room.
		 */
		if (!sdp_iocb_q_size(&conn->r_pend))
			while (sdp_advt_q_size(&conn->src_pend) > 0 &&
			       conn->recv_max >
			       sdp_buff_q_size(&conn->recv_pool) &&
			       conn->rwin_max > conn->byte_strm) {
				result = sdp_post_rdma_buff(conn);
				if (result)
					/*
					 * No more posts allowed.
					 */
					break;
			}
		/*
		 * check non-zero result
		 */
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> posting RDMA BUFF read",
				     result);
			goto done;
		}
	} else {
		if (sdp_iocb_q_size(&conn->r_pend) > 0 &&
		    conn->recv_mode == SDP_MODE_PIPE &&
		    !sdp_advt_q_size(&conn->src_actv))
			while (!(result = sdp_post_rdma_iocb_snk(conn))) {
				/*
				 * pass
				 */
			}

		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> posting RDMA read sink",
				     result);
			goto done;
		}
	}

	result = 0;
done:
	return result;
}

/*
 * sdp_recv_flush - post a certain number of buffers on a connection
 */
int sdp_recv_flush(struct sdp_sock *conn)
{
	int result = 0;
	int counter;

	/*
	 * verify that the connection is in a posting state
	 */
	if (!(SDP_ST_MASK_RCV_POST & conn->state))
		return 0;
	/*
	 * loop posting receive buffers onto the queue
	 */
	/*
	 * 1) Calculate available space in the receive queue. Take the
	 *    smallest between bytes available for buffering and maximum
	 *    number of buffers allowed in the queue. (this prevents a
	 *    flood of small buffers)
	 * 2) Subtract buffers already posted
	 * 3) Take the smallest buffer count between those needed to fill
	 *    the buffered receive/receive posted queue, and the maximum
	 *    number which are allowed to be posted at a given time.
	 */
	counter = min((s32)((conn->rwin_max - conn->byte_strm) /
			    conn->recv_size),
		      (s32) (conn->recv_max -
			     sdp_buff_q_size(&conn->recv_pool)));
	counter -= conn->l_recv_bf;

	counter = min(counter,
		      ((s32)conn->recv_cq_size - (s32)conn->l_recv_bf));

	while (counter-- > 0) {
		result = sdp_post_recv_buff(conn);
		if (result)
			/*
			 * No more recv buffers allowed.
			 */
			break;
	}

	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting recv buff.", result);
		goto done;
	}
	/*
	 * If we are in Sink Cancel processing, and the active sink queue has
	 * been consumed, we can come out of sink processing.
	 */
	if ((conn->flags & SDP_CONN_F_SNK_CANCEL) &&
	    !sdp_iocb_q_size(&conn->r_snk))
		conn->flags &= ~SDP_CONN_F_SNK_CANCEL;
	/*
	 * Next the connection should consume RDMA Source advertisments or
	 * create RDMA Sink advertisments, either way setup for RDMA's for
	 * data flowing from the remote connection peer to the local
	 * connection peer.
	 */
	result = sdp_post_rdma(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting RDMAs.", result);
		goto done;
	}
	/*
	 * Gratuitous increase of remote send credits. Independant of posting
	 * recveive buffers, it may be neccessary to notify the remote client
	 * of how many buffers are available. For small numbers advertise more
	 * often, then for large numbers. Always advertise when we add the
	 * first two buffers.
	 *
	 * 1) Fewer advertised buffers then actual posted buffers.
	 * 2) Less then three buffers advertised. (OR'd with the next two
	 *    because we can have lots of sinks, but still need to send
	 *    since those sinks may never get used. (EOF))
	 * 3) The discrepency between posted and advertised is greater then
	 *    three
	 * 4) The peer has no source or sink advertisments pending. In process
	 *    advertisments generate completions, that's why no ack.
	 */
	if ((conn->l_advt_bf < 3 &&
	     conn->l_recv_bf > conn->l_advt_bf) ||
	    (SDP_RECV_POST_ACK < (conn->l_recv_bf - conn->l_advt_bf) &&
	     !((u32)conn->snk_recv + (u32)conn->src_recv))) {
		result = sdp_send_ctrl_ack(conn);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> posting gratuitous ACK",
				     result);
			goto done;
		}
	}

	result = 0;
done:
	return result;
}

/*
 * Receive incoming data function(s)
 */

/*
 * sdp_read_buff_iocb - read a SDP buffer into an IOCB
 */
static int sdp_read_buff_iocb(struct sdpc_iocb *iocb, struct sdpc_buff *buff)
{
	unsigned long copy = 0;
	unsigned long offset;
	unsigned int counter;
	void  *addr;
	void  *data;
	void  *tail;

	/*
	 * OOB buffer adjustment. We basically throw away OOB data
	 * when writing into AIO buffer. We can't split it into it's
	 * own AIO buffer, because that would violate outstanding
	 * advertisment calculations.
	 */
	data = buff->data;
	tail = buff->tail;

	buff->tail -= (buff->flags & SDP_BUFF_F_OOB_PRES) ? 1 : 0;
	/*
	 * initialize counter to correct page and offset.
	 */
	counter = (iocb->post + iocb->page_offset) >> PAGE_SHIFT;
	offset  = (iocb->post + iocb->page_offset) & (~PAGE_MASK);

	while (buff->data < buff->tail && iocb->len > 0) {
		unsigned long flags;
		local_irq_save(flags);

		addr = kmap_atomic(iocb->page_array[counter], KM_IRQ0);
		if (!addr)
			break;

		copy = min(PAGE_SIZE - offset,
			   (unsigned long)(buff->tail - buff->data));
		copy = min((unsigned long)iocb->len, copy);
#ifndef _SDP_DATA_PATH_NULL
		memcpy(addr + offset, buff->data, copy);
#endif

		buff->data += copy;
		iocb->post += copy;
		iocb->len  -= copy;

		offset     += copy;
		offset     &= (~PAGE_MASK);

		iocb->io_addr += copy;

		kunmap_atomic(iocb->page_array[counter], KM_IRQ0);
		++counter;

		local_irq_restore(flags);
	}
	/*
	 * restore tail from OOB offset.
	 */
	buff->tail = tail;

	return 0;
}

/*
 * sdp_recv_buff_iocb_active - Ease AIO read pending pressure
 */
static int sdp_recv_buff_iocb_active(struct sdp_sock *conn,
				     struct sdpc_buff *buff)
{
	struct sdpc_iocb *iocb;
	int result;

	/*
	 * Get the IOCB, We'll fill with exactly one
	 */
	iocb = sdp_iocb_q_get_head(&conn->r_snk);
	if (!iocb) {
		sdp_dbg_warn(conn, "Empty active IOCB queue. <%d>",
			     sdp_iocb_q_size(&conn->r_snk));
		return -EPROTO;
	}

	SDP_EXPECT((iocb->flags & SDP_IOCB_F_RDMA_W));
	/*
	 * TODO: need to be checking OOB here.
	 */
	result = sdp_read_buff_iocb(iocb, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> data copy <%d:%u> to IOCB",
			     result, iocb->len,
			     (unsigned)(buff->tail - buff->data));

		sdp_iocb_q_put_head(&conn->r_snk, iocb);
		return result;
	}

	SDP_CONN_STAT_READ_INC(conn, iocb->post);
	SDP_CONN_STAT_RQ_DEC(conn, iocb->size);

	conn->nond_recv--;
	conn->snk_sent--;
	/*
	 * callback to complete IOCB
	 */
	sdp_iocb_complete(iocb, 0);

	return (buff->tail - buff->data);
}

/*
 * sdp_recv_buff_iocb_pending - Ease AIO read pending pressure
 */
static int sdp_recv_buff_iocb_pending(struct sdp_sock *conn,
				      struct sdpc_buff *buff)
{
	struct sdpc_iocb *iocb;
	int result;

	/*
	 * check the IOCB
	 */
	iocb = sdp_iocb_q_look(&conn->r_pend);
	if (!iocb) {
		sdp_dbg_warn(conn, "Empty pending IOCB queue. <%d>",
			     sdp_iocb_q_size(&conn->r_pend));
		return -EPROTO;
	}
	/*
	 * TODO: need to be checking OOB here.
	 */
	result = sdp_read_buff_iocb(iocb, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> data copy <%d:%u> to IOCB",
			     result, iocb->len,
			     (unsigned)(buff->tail - buff->data));
		return result;
	}
	/*
	 * Complete the sink IOCB for either of two cases:
	 *
	 * 1) The IOCB has no more room.
	 * 2) a) there are no more pending Src advertisments with which to
	 *       populate it.
	 *    b) the amount of data moved into the IOCB is greater then the
	 *       socket recv low water mark.
	 */
	if (!iocb->len ||
	    (!conn->src_recv &&
	     !(sk_sdp(conn)->sk_rcvlowat > iocb->post))) {
		/*
		 * complete IOCB
		 */
		SDP_CONN_STAT_READ_INC(conn, iocb->post);
		SDP_CONN_STAT_RQ_DEC(conn, iocb->size);
		/*
		 * callback to complete IOCB
		 */
		sdp_iocb_complete(sdp_iocb_q_get_head(&conn->r_pend), 0);
	}

	return (buff->tail - buff->data);
}

/*
 * sdp_recv_buff - Process a new buffer based on queue type
 */
int sdp_recv_buff(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	int result;
	int buffered;

	sdp_dbg_data(conn, "RECV BUFF, bytes <%u>",
		     (unsigned)(buff->tail - buff->data));
	/*
	 * To emulate RFC 1122 (page 88) a connection should be reset/aborted
	 * if data is received and the receive half of the connection has been
	 * closed. This notifies the peer that the data was not received.
	 */
	if (RCV_SHUTDOWN & conn->shutdown) {
		sdp_dbg_warn(conn, "Receive data path closed. <%02x>",
			     conn->shutdown);
		/*
		 * abort connection (send reset)
		 */
		sdp_conn_abort(conn);
		/*
		 * drop packet
		 */
		result = 0;
		goto done;
	}
	/*
	 * oob notification.
	 */
	if (buff->flags & SDP_BUFF_F_OOB_PEND) {
		conn->rcv_urg_cnt++;
		sk_send_sigurg(sk_sdp(conn));
	}
	/*
	 * loop while there are available IOCB's, break if there is no
	 * more data to read
	 */
	while ((sdp_iocb_q_size(&conn->r_pend) +
		    sdp_iocb_q_size(&conn->r_snk))) {
		/*
		 * if there is OOB data in a buffer, the two functions below
		 * will leave the byte in the buffer, and potentially loop
		 * to here. In which case we are done and the buffer is queued.
		 * this allows POLL notification to work, and the OOB byte(s)
		 * will not be consumed until the next AIO buffer is posted,
		 * or a socket recv (regular or OOB) is called.
		 */
		if ((buff->flags & SDP_BUFF_F_OOB_PRES) &&
		    1 == (buff->tail - buff->data))
			break;
		/*
		 * process either a sink available IOCB which needs to be
		 * discarded with exactly one buffer, or process a pending
		 * IOCB.
		 */
		if (conn->snk_sent > 0)
			result = sdp_recv_buff_iocb_active(conn, buff);
		else
			result = sdp_recv_buff_iocb_pending(conn, buff);
		/*
		 * Check result. Postitive result is data left in the buffer
		 */
		if (!result)
			break;

		if (result < 0) {
			sdp_dbg_warn(conn,
				     "Error <%d> processing IOCB. <%d:%d:%d>",
				     result, conn->snk_sent,
				     sdp_iocb_q_size(&conn->r_pend),
				     sdp_iocb_q_size(&conn->r_snk));
			goto done;
		}
	}
	/*
	 * If there is still data in the buffer then queue it for later.
	 */
	buffered = buff->tail - buff->data;

	if (buffered)
		sdp_buff_q_put_tail(&conn->recv_pool, buff);

	return buffered;
done:
	return result;
}

/*
 * User initiated receive data function(s)
 */

/*
 * sdp_read_src_lookup - lookup function for cancelation
 */
static int sdp_read_src_lookup(struct sdpc_desc *element, void *arg)
{
	struct sdpc_iocb *iocb = (struct sdpc_iocb *) element;
	struct kiocb *req = (struct kiocb *)arg;

	if (element->type == SDP_DESC_TYPE_IOCB && iocb->key == req->ki_key)
		return 0;
	else
		return -ERANGE;
}

/*
 * sdp_inet_read_cancel - cancel an IO operation
 */
static int sdp_inet_read_cancel(struct kiocb *req, struct io_event *ev)
{
	struct sock_iocb *si = kiocb_to_siocb(req);
	struct sdp_sock   *conn;
	struct sdpc_iocb *iocb;
	int result = 0;

	sdp_dbg_ctrl(NULL, "Cancel Read IOCB. user <%d> key <%d> flag <%08lx>",
		     req->ki_users, req->ki_key, req->ki_flags);

	if (!si || !si->sock || !si->sock->sk) {
		sdp_warn("Cancel empty read IOCB. users <%d> flags <%d:%08lx>",
			 req->ki_users, req->ki_key, req->ki_flags);
		result = -EFAULT;
		goto done;
	}
	/*
	 * lock the socket while we operate.
	 */
	conn = sdp_sk(si->sock->sk);
	sdp_conn_lock(conn);

	sdp_dbg_ctrl(conn, "Cancel Read IOCB. <%08x:%04x> <%08x:%04x>",
		     conn->src_addr, conn->src_port,
		     conn->dst_addr, conn->dst_port);
	/*
	 * attempt to find the IOCB for this key. we don't have an indication
	 * whether this is a read or write.
	 */
	iocb = sdp_iocb_q_lookup(&conn->r_pend, req->ki_key);
	if (iocb) {
		/*
		 * always remove the IOCB. If active, then place it into
		 * the correct active queue. Inactive empty IOCBs can be
		 * deleted, while inactive partials needs to be compelted.
		 */
		sdp_iocb_q_remove(iocb);

		if (!(iocb->flags & SDP_IOCB_F_ACTIVE)) {
			if (iocb->post > 0) {
				/*
				 * callback to complete IOCB, or drop reference
				 */
				sdp_iocb_complete(iocb, 0);
				result = -EAGAIN;
			}
			else {
				sdp_iocb_destroy(iocb);
				/*
				 * completion reference
				 */
				aio_put_req(req);

				result = 0;
			}

			goto unlock;
		}

		if (iocb->flags & SDP_IOCB_F_RDMA_W)
			sdp_iocb_q_put_tail(&conn->r_snk, iocb);
		else {
			SDP_EXPECT((iocb->flags & SDP_IOCB_F_RDMA_R));

			sdp_desc_q_put_tail(&conn->r_src,
					    (struct sdpc_desc *)iocb);
		}
	}
	/*
	 * check the source queue, not much to do, since the operation is
	 * already in flight.
	 */
	iocb = (struct sdpc_iocb *)sdp_desc_q_lookup(&conn->r_src,
						     sdp_read_src_lookup,
						     req);
	if (iocb) {
		iocb->flags |= SDP_IOCB_F_CANCEL;
		result = -EAGAIN;

		goto unlock;
	}
	/*
	 * check sink queue. If we're in the sink queue, then a cancel
	 * needs to be issued.
	 */
	iocb = sdp_iocb_q_lookup(&conn->r_snk, req->ki_key);
	if (iocb) {
		/*
		 * Unfortunetly there is only a course grain cancel in SDP, so
		 * we have to cancel everything. This is OKish since it usually
		 * only happens at connection termination, and the remaining
		 * source probably will get cancel requests as well.
		 */
		if (!(conn->flags & SDP_CONN_F_SNK_CANCEL)) {

			result = sdp_send_ctrl_snk_cancel(conn);
			SDP_EXPECT(result >= 0);

			conn->flags |= SDP_CONN_F_SNK_CANCEL;
		}

		iocb->flags |= SDP_IOCB_F_CANCEL;
		result = -EAGAIN;

		goto unlock;
	}
	/*
	 * no IOCB found. The cancel is probably in a race with a completion.
	 * Assume the IOCB will be completed, return appropriate value.
	 */
	sdp_dbg_ctrl(NULL, "Cancel read with no IOCB. <%d:%d:%08lx>",
		     req->ki_users, req->ki_key, req->ki_flags);

	result = -EAGAIN;

unlock:
	sdp_conn_unlock(conn);
done:
	aio_put_req(req);
	return result;
}

/*
 * sdp_inet_recv_urg_test - recv queue urgent data cleanup function
 */
static int sdp_inet_recv_urg_test(struct sdpc_buff *buff, void *arg)
{
	return ((buff->tail == buff->head) ? 1 : 0);
}

/*
 * sdp_inet_recv_urg_trav - recv queue urg data retreival function
 */
static int sdp_inet_recv_urg_trav(struct sdpc_buff *buff, void *arg)
{
	u8 *value = (u8 *) arg;
	u8 update;

	if (buff->flags & SDP_BUFF_F_OOB_PRES) {

		update = *value;
		*value = *(u8 *) (buff->tail - 1);

		if (update > 0) {
			buff->tail--;
			buff->flags &= ~SDP_BUFF_F_OOB_PRES;
		}

		return -ERANGE;
	}

	return 0;
}

/*
 * sdp_inet_recv_urg - recv urgent data from the network to user space
 */
static int sdp_inet_recv_urg(struct sock *sk, struct msghdr *msg, int size,
			     int flags)
{
	struct sdp_sock *conn;
	struct sdpc_buff *buff;
	int result = 0;
	u8 value;

	conn = sdp_sk(sk);

	if (sock_flag(sk, SOCK_URGINLINE) || !conn->rcv_urg_cnt)
		return -EINVAL;

	/*
	 * don't cosume data on PEEK, but do consume data on TRUNC
	 */
#if 0
	value = (flags & MSG_PEEK) || !size ? 0 : 1;
#else
	value = (flags & MSG_PEEK) ? 0 : 1;
#endif

	result = sdp_buff_q_trav_head(&conn->recv_pool,
				      sdp_inet_recv_urg_trav,
				      (void *)&value);
	if (result != -ERANGE) {
		result = result ? result : -EAGAIN;
		goto done;
	}

	msg->msg_flags |= MSG_OOB;
	if (size > 0) {
		result = memcpy_toiovec(msg->msg_iov, &value, 1);
		if (result)
			goto done;
		/*
		 * clear urgent pointer on consumption
		 */
		if (!(flags & MSG_PEEK)) {
			conn->rcv_urg_cnt -= 1;
			conn->byte_strm -= 1;

			SDP_CONN_STAT_RECV_INC(conn, 1);
			/*
			 * we've potentially emptied a buffer, if
			 * so find and dispose of it, and repost
			 * if appropriate.
			 */
			buff = sdp_buff_q_fetch(&conn->recv_pool,
						sdp_inet_recv_urg_test,
						(void *)0);
			if (buff)
				sdp_buff_pool_put(buff);

			result = 1;
		}
	} else {
		msg->msg_flags |= MSG_TRUNC;
		result = 0;
	}

done:
	return result;
}

/*
 * sdp_inet_recv - recv data from the network to user space
 */
int sdp_inet_recv(struct kiocb  *req, struct socket *sock, struct msghdr *msg,
		  size_t size, int flags)
{
	struct sock      *sk;
	struct sdp_sock   *conn;
	struct sdpc_iocb *iocb;
	struct sdpc_buff *buff;
	long   timeout;
	size_t length;
	int result = 0;
	int expect;
	int low_water;
	int copied = 0;
	int copy;
	int update;
	s8 oob = 0;
	s8 ack = 0;
	struct sdpc_buff_q peek_queue;

	sk = sock->sk;
	conn = sdp_sk(sk);

	sdp_dbg_data(conn, "state <%08x> size <%Zu> pending <%d> falgs <%08x>",
		     conn->state, size, conn->byte_strm, flags);
	sdp_dbg_data(conn, "read IOCB <%d> addr <%p> users <%d> flags <%08lx>",
		     req->ki_key, msg->msg_iov->iov_base,
		     req->ki_users, req->ki_flags);

	/*
	 * TODO: unhandled, but need to be handled.
	 */
	if (flags & MSG_TRUNC)
		return -EOPNOTSUPP;

	if (flags & MSG_PEEK) {
		sdp_buff_q_init(&peek_queue);
		msg->msg_flags |= MSG_PEEK;
	}

	sdp_conn_lock(conn);

	if (conn->state == SDP_CONN_ST_LISTEN ||
	    conn->state == SDP_CONN_ST_CLOSED) {
		result = -ENOTCONN;
		goto done;
	}
	/*
	 * process urgent data
	 */
	if (flags & MSG_OOB) {
		result = sdp_inet_recv_urg(sk, msg, size, flags);
		copied = (result > 0) ? result : 0;
		result = (result > 0) ? 0 : result;

		if (copied)
			ack = copied;
		goto done;
	}
	/*
	 * get socket values we'll need.
	 */
	timeout   = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	low_water = sock_rcvlowat(sk, flags & MSG_WAITALL, size);
	/*
	 * process data first, and then check condition, then wait
	 */
	while (copied < size) {
		/*
		 * first copy any data that might be present
		 */
		while (copied < size &&
		       (buff = sdp_buff_q_get_head(&conn->recv_pool))) {
			length = buff->tail - buff->data;
			update = 0;

			if (buff->flags & SDP_BUFF_F_OOB_PRES) {
				/*
				 * if data has already been read, and the
				 * next byte is the urgent byte, reading
				 * needs to terminate, taking precidence
				 * over the low water mark. There needs to
				 * be a break in the the read stream around
				 * the OOB byte regardless if it is inline
				 * or not, to ensure that the user has a
				 * chance to read the byte.
				 */
				if (1 < length)
					length--;
				else {
					if (copied > 0) {
						/*
						 * update such that we pass
						 * through the copy phase,
						 * return the buffer, and
						 * break.
						 */
						length = 0;
						update = 0;
						oob = 1;    /* break on oob */
					} else {
					  if (sock_flag(sk, SOCK_URGINLINE)) {
					    /*
							 * skip this byte, but
							 * make sure it's
							 * counted.
							 */
							length = 0;
							update =
							    (0 <
							     (flags & MSG_PEEK))
							    ? 0 : 1;
						}
					}
				}
			}

			copy = min((size_t) (size - copied), length);

			if (copy > 0) {
#ifndef _SDP_DATA_PATH_NULL
				result = memcpy_toiovec(msg->msg_iov,
							buff->data,
							copy);
				if (result < 0) {
					sdp_buff_q_put_head(&conn->recv_pool,
							    buff);
					goto done;
				}
#endif
				update = (flags & MSG_PEEK) ? 0 : copy;
			}

			SDP_CONN_STAT_RECV_INC(conn, update);

			conn->byte_strm -= update;
			buff->data      += update;
			copied          += copy;

			if ((buff->tail - buff->data) > 0) {
				sdp_buff_q_put_head(&conn->recv_pool, buff);
				/*
				 * always break, PEEK and OOB together could
				 * throw us into a loop without a forced
				 * break here, since the buffer data pointer
				 * wasn't really updated. OOB data at the
				 * head of stream, after data has already
				 * been copied relies on this break as well.
				 */
				break;
			}

			if (flags & MSG_PEEK)
				sdp_buff_q_put_head(&peek_queue, buff);
			else {
				if (buff->flags & SDP_BUFF_F_OOB_PRES)
					conn->rcv_urg_cnt -= 1;

				sdp_buff_pool_put(buff);
				/*
				 * post additional recv buffers if
				 * needed, but check only every N
				 * buffers...
				 */
				if (SDP_RECV_POST_FREQ < ++ack) {
					result = sdp_recv_flush(conn);
					if (result < 0)
						goto done;

					ack = 0;
				}
			}
		}
		/*
		 * urgent data needs to break up the data stream, regardless
		 * of low water mark, or whether there is room in the buffer.
		 */
		if (oob > 0) {
			result = 0;
			break;
		}
		/*
		 * If there is more room for data, cycle the connection lock to
		 * potentially flush events into the recv queue. This is done
		 * before the low water mark is checked to optimize the number
		 * of syscalls a read process needs to make for a given amount
		 * of data.
		 */
		if (copied < size) {
			/*
			 * process backlog
			 */
			sdp_conn_relock(conn);

			if (sdp_buff_q_size(&conn->recv_pool) > 0)
				continue;
		}
		/*
		 * If enough data has been copied to userspace break from
		 * loop, low water mark is tested to determine if enough
		 * data to satisfy the request has been copied, and source
		 * RDMA advertisements are checked to determine if remote
		 * data is pending and accessible.
		 */
		if (copied == size)
			break;

		if (!(copied < low_water) && !conn->src_recv)
			break;
		/*
		 * check connection errors, and then wait for more data.
		 * check status. POSIX 1003.1g order.
		 */
		if (sk->sk_err) {
			result = (copied > 0) ? 0 : sock_error(sk);
			break;
		}

		if (RCV_SHUTDOWN & conn->shutdown) {
			result = 0;
			break;
		}

		if (conn->state == SDP_CONN_ST_ERROR) {
			result = -EPROTO; /* error should always be
					     set, but just in case */
			break;
		}

		if (!timeout) {
			result = -EAGAIN;
			break;
		}
		/*
		 * Either wait or create IOCB for defered completion.
		 */
		if (is_sync_kiocb(req)) {
			DECLARE_WAITQUEUE(wait, current);

			add_wait_queue(sk->sk_sleep, &wait);
			set_current_state(TASK_INTERRUPTIBLE);

			set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);

			if (!sdp_buff_q_size(&conn->recv_pool)) {
				sdp_conn_unlock(conn);
				timeout = schedule_timeout(timeout);
				sdp_conn_lock(conn);
			}

			clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);
			remove_wait_queue(sk->sk_sleep, &wait);
			set_current_state(TASK_RUNNING);
			/*
			 * check signal pending
			 */
			if (signal_pending(current)) {
				result = ((timeout > 0) ?
					  sock_intr_errno(timeout) : -EAGAIN);
				break;
			}
		} else {
			/*
			 * create IOCB with remaining space
			 */
			iocb = sdp_iocb_create();
			if (!iocb) {
				sdp_dbg_warn(conn,
					     "Error allocating IOCB <%Zu:%d>",
					     size, copied);
				result = -ENOMEM;
				break;
			}

			iocb->len  = size - copied;
			iocb->post = copied;
			iocb->size = size;
			iocb->req  = req;
			iocb->key  = req->ki_key;
			iocb->addr = ((unsigned long)msg->msg_iov->iov_base -
				      copied);

			iocb->flags |= SDP_IOCB_F_RECV;

			req->ki_cancel = sdp_inet_read_cancel;

			result = sdp_iocb_lock(iocb);
			if (result < 0) {
				sdp_dbg_warn(conn,
					     "Error <%d> IOCB lock <%Zu:%d>",
					     result, size, copied);

				sdp_iocb_destroy(iocb);
				break;
			}

			SDP_CONN_STAT_RQ_INC(conn, iocb->size);

			sdp_iocb_q_put_tail(&conn->r_pend, iocb);

			ack    = 1;
			copied = 0; /* copied amount was saved in IOCB. */
			result = -EIOCBQUEUED;

			break;
		}
	}

done:
	/*
	 * acknowledge moved data
	 */
	if (ack > 0) {
		expect = sdp_recv_flush(conn);
		if (expect < 0)
			sdp_dbg_warn(conn, "Error <%d> flushing recv queue.",
				     expect);
	}
	/*
	 * return any peeked buffers to the recv queue, in the correct order.
	 */
	if (flags & MSG_PEEK)
		while ((buff = sdp_buff_q_get_tail(&peek_queue)))
			sdp_buff_q_put_head(&conn->recv_pool, buff);

	sdp_conn_unlock(conn);
	return ((copied > 0) ? copied : result);
}

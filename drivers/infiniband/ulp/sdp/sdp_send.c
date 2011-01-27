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
 * $Id: sdp_send.c 3936 2005-11-02 10:28:44Z mst $
 */

#include "sdp_main.h"

/*
 * COMMON functions
 */

/*
 * sdp_send_buff_post - Post a buffer send on a SDP connection
 */
static int sdp_send_buff_post(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct ib_send_wr send_param = { NULL };
	struct ib_send_wr *bad_wr;
	int result;

	/*
	 * write header send buffer.
	 */
	conn->r_recv_bf--;
	conn->s_wq_size++;
	conn->l_advt_bf = conn->l_recv_bf;
	conn->send_pipe -= buff->data_size;
	conn->oob_offset -= (conn->oob_offset > 0) ? buff->data_size : 0;

	buff->wrid = conn->send_wrid++;
	buff->sge.lkey = conn->l_key;
	buff->bsdh_hdr->recv_bufs = conn->l_advt_bf;
	buff->bsdh_hdr->size = buff->tail - buff->data;
	buff->bsdh_hdr->seq_num = ++conn->send_seq;
	buff->bsdh_hdr->seq_ack = conn->advt_seq;
	/*
	 * endian swap
	 */
	sdp_msg_cpu_to_net_bsdh(buff->bsdh_hdr);
	/*
	 * OOB processing. If there is a single OOB byte in flight then the
	 * pending flag is set as early as possible. IF a second OOB byte
	 * becomes queued then the pending flag for that byte will be in the
	 * buffer which contains the data. Multiple outstanding OOB messages
	 * is not well defined, this way we won't loose any, we'll get early
	 * notification in the normal case, we adhear to the protocol, and
	 * we don't need to track every message seperatly which would be
	 * expensive.
	 *
	 * If the connections OOB flag is set and the oob
	 * counter falls below 64K we set the pending flag, and clear the
	 * the flag. This allows for at least one pending urgent message
	 * to send early notification.
	 */
	if ((conn->flags & SDP_CONN_F_OOB_SEND) &&
	    conn->oob_offset <= 0xFFFF) {
		SDP_BSDH_SET_OOB_PEND(buff->bsdh_hdr);
		SDP_BUFF_F_SET_SE(buff);

		conn->flags &= ~(SDP_CONN_F_OOB_SEND);
	}
	/*
	 * The buffer flag is checked to see if the OOB data is in the buffer,
	 * and present flag is set, potentially OOB offset is cleared. pending
	 * is set if this buffer has never had pending set.
	 */
	if (buff->flags & SDP_BUFF_F_OOB_PRES) {
		if (conn->oob_offset > 0)
			SDP_BSDH_SET_OOB_PEND(buff->bsdh_hdr);
		else {
			SDP_EXPECT(conn->oob_offset >= 0);
			conn->oob_offset = -1;
		}

		SDP_BSDH_SET_OOB_PRES(buff->bsdh_hdr);
		SDP_BUFF_F_SET_SE(buff);
	}
	/*
	 * solicite event bit.
	 */
	if (SDP_BUFF_F_GET_SE(buff))
		send_param.send_flags |= IB_SEND_SOLICITED;
	/*
	 * unsignalled event
	 */
	if (SDP_BUFF_F_GET_UNSIG(buff) &&
	    conn->usig_max > conn->send_cons) {
		conn->send_usig++;
		conn->send_cons++;
	} else {
		SDP_BUFF_F_CLR_UNSIG(buff);
		send_param.send_flags |= IB_SEND_SIGNALED;
		conn->send_cons = 0;
	}
	/*
	 * post send
	 */
 	buff->sge.length = buff->tail - buff->data;
 	buff->sge.addr = dma_map_single(conn->ca->dma_device,
					buff->data,
					buff->sge.length,
					PCI_DMA_TODEVICE);
	send_param.next    = NULL;
	send_param.wr_id   = buff->wrid;
 	send_param.sg_list = &buff->sge;
	send_param.num_sge = 1;
	send_param.opcode  = IB_WR_SEND;

	result = ib_post_send(conn->qp, &send_param, &bad_wr);
	if (result) {
		sdp_dbg_warn(conn,
			     "Error <%d> posting send. <%d:%d> <%d:%d:%d>",
			     result, conn->s_wq_cur, conn->s_wq_size,
			     sdp_buff_q_size(&conn->send_post),
			     sdp_desc_q_size(&conn->r_src),
			     sdp_desc_q_size(&conn->w_snk));
		goto done;
	}
	/*
	 * check queue membership. (first send attempt vs. flush)
	 */
	if (sdp_desc_q_member((struct sdpc_desc *) buff))
		sdp_desc_q_remove((struct sdpc_desc *) buff);
	/*
	 * save the buffer for the event handler.
	 */
	sdp_buff_q_put_tail(&conn->send_post, buff);
	/*
	 * source cancels require us to save the sequence number
	 * for validation of the cancel's completion.
	 */
	if (conn->flags & SDP_CONN_F_SRC_CANCEL_L)
		conn->src_cseq = ((buff->bsdh_hdr->mid == SDP_MID_SRC_CANCEL) ?
				  conn->send_seq : conn->src_cseq);

	return 0;
done:
	conn->r_recv_bf++;
	conn->send_seq--;
	conn->s_wq_size--;
	return result;
}

/*
 * DATA functions
 */

/*
 * sdp_send_data_buff_post - Post data for buffered transmission
 */
static int sdp_send_data_buff_post(struct sdp_sock *conn,
				   struct sdpc_buff *buff)
{
	int result;

	/*
	 * check state to determine OK to send:
	 *
	 * 1) sufficient remote buffer advertisments for data transmission
	 * 2) outstanding source advertisments, data must be held.
	 * 3) buffer from head of queue or as parameter
	 * 4) nodelay check.
	 */
	if (conn->r_recv_bf < 3 || conn->src_sent > 0)
		return ENOBUFS;
	/*
	 * The rest of the checks can proceed if there is a signalled event
	 * in the pipe, otherwise we could stall...
	 */
	if (conn->send_usig < sdp_buff_q_size(&conn->send_post) ||
	    sdp_desc_q_size(&conn->w_snk) > 0) {
		if (buff->tail < buff->end &&
		    !(buff->flags & SDP_BUFF_F_OOB_PRES) &&
		    !conn->nodelay)
			/*
			 * If the buffer is not full, and there is already
			 * data in the SDP pipe, then hold on to the buffer
			 * to fill it up with more data. If SDP acks clear
			 * the pipe they'll grab this buffer, or send will
			 * flush once it's full, which ever comes first.
			 */
			return ENOBUFS;
		/*
		 * slow start to give sink advertisments a chance for
		 * asymmetric connections. This is desirable to offload
		 * the remote host.
		 */
		if (conn->s_wq_cur <= conn->s_wq_size) {
			/*
			 * slow down the up take in the send data path to
			 * give the remote side some time to post available
			 * sink advertisments.
			 */
			if (conn->send_cq_size > conn->s_wq_cur) {
				if (SDP_SEND_POST_COUNT > conn->s_wq_par)
					conn->s_wq_par++;
				else {
					conn->s_wq_cur++;
					conn->s_wq_par = 0;
				}
			}

			return ENOBUFS;
		}
	}
	/*
	 * setup header.
	 */
	buff->data -= sizeof(struct msg_hdr_bsdh);
	buff->bsdh_hdr = (struct msg_hdr_bsdh *) buff->data;
	buff->bsdh_hdr->mid = SDP_MID_DATA;
	buff->bsdh_hdr->flags = SDP_MSG_FLAG_NON_FLAG;
	/*
	 * signalled? With no delay turned off, data transmission may be
	 * waiting for a send completion.
	 */
	SDP_BUFF_F_SET_UNSIG(buff);
	/*
	 * update non-discard counter.
	 * Make consideration for a pending sink. (can be forced by OOB)
	 */
	if (sdp_advt_q_size(&conn->snk_pend)) {
		/*
		 * As sink advertisment needs to be discarded. We always
		 * complete an advertisment if there is not enough room
		 * for an entire buffers worth of data, this allows us to
		 * not need to check how much room is going to be consumed
		 * by this buffer, and only one discard is needed.
		 * (remember the spec makes sure that the sink is bigger
		 * then the buffer.)
		 */
		sdp_advt_destroy(sdp_advt_q_get(&conn->snk_pend));
		/*
		 * update sink advertisments.
		 */
		conn->snk_recv--;
	} else
		conn->nond_send++;
	/*
	 * transmision time
	 */
	result = sdp_send_buff_post(conn, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting send data buffer",
			     result);
		return result;
	}

	return 0;
}

/*
 * sdp_send_data_buff_snk - Post data for buffered transmission
 */
static int sdp_send_data_buff_snk(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	struct ib_send_wr send_param = { NULL };
	struct ib_send_wr *bad_wr;
	struct sdpc_advt *advt;
	int result;

	/*
	 * check state to determine OK to send:
	 *
	 * 1) sufficient send resources.
	 */
	if (conn->send_cq_size <= conn->s_wq_size)
		return ENOBUFS;
	/*
	 * confirm type
	 */
	if (buff->type != SDP_DESC_TYPE_BUFF)
		return -ENOBUFS;
	/*
	 * nodelay buffering
	 */
#if 0
	if (buff->tail < buff->end &&
	    !conn->nodelay &&
	    conn->send_usig < sdp_buff_q_size(&conn->send_post)) {
		/*
		 * If the buffer is not full, and there is already data in the
		 * SDP pipe, then hold on to the buffer to fill it up with more
		 * data. If SDP acks clear the pipe they'll grab this buffer,
		 * or send will flush once it's full, which ever comes first.
		 */
		return ENOBUFS;
	}
#endif
	/*
	 * get advertisment.
	 */
	advt = sdp_advt_q_look(&conn->snk_pend);
	if (!advt)
		return ENOBUFS;
	/*
	 * signalled? With no delay turned off, data transmission may be
	 * waiting for a send completion.
	 */
#if 0
	SDP_BUFF_F_SET_UNSIG(buff);
#endif
	/*
	 * setup RDMA write
	 */
	send_param.opcode              = IB_WR_RDMA_WRITE;
	send_param.wr.rdma.remote_addr = advt->addr;
	send_param.wr.rdma.rkey        = advt->rkey;
	send_param.send_flags          = IB_SEND_SIGNALED;

	buff->wrid = conn->send_wrid++;
	buff->sge.lkey = conn->l_key;

	advt->wrid  = buff->wrid;
	advt->size -= (buff->tail - buff->data);
	advt->addr += (buff->tail - buff->data);
	advt->post += (buff->tail - buff->data);

	sdp_dbg_data(conn, "POST Write BUFF wrid <%llu> bytes <%u:%d>.",
		     (unsigned long long) buff->wrid,
		     (unsigned)(buff->tail - buff->data),
		     advt->size);
	/*
	 * post RDMA
	 */
	buff->sge.addr     = virt_to_phys(buff->data);
	buff->sge.length   = buff->tail - buff->data;

	send_param.next    = NULL;
	send_param.wr_id   = buff->wrid;
	send_param.sg_list = &buff->sge;
	send_param.num_sge = 1;

	result = ib_post_send(conn->qp, &send_param, &bad_wr);
	if (result) {
		sdp_dbg_warn(conn, "Error <%d> posting rdma write", result);
		goto error;
	}
	/*
	 * update send queue depth
	 */
	conn->s_wq_size++;
	conn->send_pipe  -= buff->data_size;
	conn->oob_offset -= (conn->oob_offset > 0) ? buff->data_size : 0;
	/*
	 * If the available space is smaller then send size, complete the
	 * advertisment.
	 */
	if (conn->send_size > advt->size) {

		result = sdp_send_ctrl_rdma_wr(conn, advt->post);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> completing sink. <%d>",
				     result, advt->post);
			result = -ENODEV;
			goto error;
		}
		/*
		 * update sink advertisments.
		 */
		sdp_advt_destroy(sdp_advt_q_get(&conn->snk_pend));
		conn->snk_recv--;
	}
	/*
	 * dequeue buffer if needed and move to active queue
	 */
	if (sdp_desc_q_member((struct sdpc_desc *) buff) > 0)
		sdp_desc_q_remove((struct sdpc_desc *) buff);

	sdp_desc_q_put_tail(&conn->w_snk, (struct sdpc_desc *)buff);

	return 0;
error:
	return result;
}

/*
 * sdp_send_data_iocb_snk - process a zcopy write advert in the data path
 */
static int sdp_send_data_iocb_snk(struct sdp_sock *conn, struct sdpc_iocb *iocb)
{
	struct ib_send_wr send_param = { NULL };
	struct ib_send_wr *bad_wr;
	struct ib_sge sg_val;
	struct sdpc_advt *advt;
	int result;
	int zcopy;

	/*
	 * register IOCBs physical memory, we check for previous
	 * registration, since multiple writes may have been required
	 * to fill the advertisement
	 */
	result = sdp_iocb_register(iocb, conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> registering IOCB. <%d:%d>",
			     result, iocb->key, iocb->len);
		goto error;
	}
	/*
	 * check queue depth
	 */
	while (iocb->len > 0 && conn->send_cq_size > conn->s_wq_size) {
		/*
		 * get the pending sink advertisment.
		 */
		advt = sdp_advt_q_look(&conn->snk_pend);
		if (!advt)
			break;
		/*
		 * amount of data to zcopy.
		 */
		zcopy = min(advt->size, iocb->len);

		sg_val.addr   = iocb->io_addr;
		sg_val.lkey   = iocb->l_key;
		sg_val.length = zcopy;

		send_param.opcode              = IB_WR_RDMA_WRITE;
		send_param.wr.rdma.remote_addr = advt->addr;
		send_param.wr.rdma.rkey        = advt->rkey;
		send_param.send_flags          = IB_SEND_SIGNALED;

		iocb->wrid     = conn->send_wrid++;
		iocb->len     -= zcopy;
		iocb->post    += zcopy;
		iocb->io_addr += zcopy;
		iocb->flags   |= SDP_IOCB_F_ACTIVE;
		iocb->flags   |= SDP_IOCB_F_RDMA_W;

		advt->wrid  = iocb->wrid;
		advt->size -= zcopy;
		advt->addr += zcopy;
		advt->post += zcopy;

		sdp_dbg_data(conn,
			     "POST Write IOCB wrid <%llu> bytes <%u:%d:%d>.",
			     (unsigned long long) iocb->wrid,
			     zcopy, iocb->len, advt->size);
		/*
		 * update send queue depth
		 */
		conn->s_wq_size++;
		conn->send_pipe -= zcopy;
		conn->oob_offset -= (conn->oob_offset > 0) ? zcopy : 0;
		/*
		 * post RDMA
		 */
		send_param.next = NULL;
		send_param.wr_id = iocb->wrid;
		send_param.sg_list = &sg_val;
		send_param.num_sge = 1;

		result = ib_post_send(conn->qp, &send_param, &bad_wr);
		if (result) {
			sdp_dbg_warn(conn, "Error <%d> posting rdma write",
				     result);

			conn->s_wq_size--;
			goto error;
		}
		/*
		 * if there is no more advertised space,  remove the
		 * advertisment from the queue, and get it ready for
		 * completion. (see note in buffered send during
		 * outstanding sink advertisment to see how the advt
		 * size remaining is picked.)
		 */
		if (conn->send_size <= advt->size)
			continue;

		result = sdp_send_ctrl_rdma_wr(conn, advt->post);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> completing sink. <%d>",
				     result, zcopy);
			result = -ENODEV;
			goto error;
		}
		/*
		 * update sink advertisments.
		 */
		sdp_advt_destroy(sdp_advt_q_get(&conn->snk_pend));
		conn->snk_recv--;
	}

	return iocb->len;
error:
	return result;
}

/*
 * sdp_send_data_iocb_src - send a zcopy read advert in the data path
 */
static int sdp_send_data_iocb_src(struct sdp_sock *conn, struct sdpc_iocb *iocb)
{
	struct msg_hdr_srcah *src_ah;
	struct sdpc_buff *buff;
	int result;

	/*
	 * 1) local source cancel is pending
	 * 2) sufficient send credits for buffered transmission.
	 */
	if ((conn->flags & SDP_CONN_F_SRC_CANCEL_L) || conn->r_recv_bf < 3)
		return ENOBUFS;

	switch (conn->send_mode) {
	case SDP_MODE_PIPE:
		if (conn->s_cur_adv <= conn->src_sent)
			return ENOBUFS;

		if (conn->s_cur_adv < conn->r_max_adv) {
			if (conn->s_par_adv >= SDP_SEND_POST_FRACTION) {
				conn->s_cur_adv++;
				conn->s_par_adv = 0;
			}
			else
				conn->s_par_adv++;
		} else {
			conn->s_cur_adv = conn->r_max_adv;
			conn->s_par_adv = 0;
		}
#if 0

		conn->s_cur_adv = ((conn->s_cur_adv < conn->r_max_adv) ?
				   conn->s_cur_adv + 1 : conn->r_max_adv);
#endif
		break;
	case SDP_MODE_COMB:
		if (conn->src_sent > 0)
			return ENOBUFS;
		break;
	default:
		sdp_dbg_warn(conn, "Unexpected SrcAvail mode. <%d>",
			     conn->send_mode);
		return -EPROTO;
	}
	/*
	 * get buffer
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "Error allocating SrcAvail buffer. <%d>",
			     iocb->key);
		return -ENOMEM;
	}
	/*
	 * register IOCBs physical memory, we check for previous registration,
	 * since SrcAvail revocations can get us to this point multiple times
	 * for the same IOCB.
	 */
	result = sdp_iocb_register(iocb, conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> registering IOCB. <%d:%d>",
			     result, iocb->key, iocb->len);
		goto drop;
	}
	/*
	 * format SrcAvail
	 */
	buff->tail             = buff->data;
	buff->bsdh_hdr         = (struct msg_hdr_bsdh *) buff->data;
	buff->bsdh_hdr->mid    = SDP_MID_SRC_AVAIL;
	buff->bsdh_hdr->flags  = SDP_MSG_FLAG_NON_FLAG;
	buff->tail            += sizeof(struct msg_hdr_bsdh);

	src_ah        = (struct msg_hdr_srcah *) buff->tail;
	src_ah->size  = iocb->len;
	src_ah->r_key = iocb->r_key;
	src_ah->addr  = iocb->io_addr;

	buff->tail += sizeof(struct msg_hdr_srcah);
	buff->data_size = 0;

	iocb->flags |= SDP_IOCB_F_ACTIVE;
	iocb->flags |= SDP_IOCB_F_RDMA_R;

	SDP_BUFF_F_CLR_SE(buff);
	SDP_BUFF_F_CLR_UNSIG(buff);

	if (conn->send_mode == SDP_MODE_COMB) {
		unsigned long flags;
		void *addr;
		int   pos;
		int   off;
		int   len;
		/*
		 * In combined mode, it's a protocol requirment to send at
		 * least a byte of data in the SrcAvail.
		 */
		pos = (iocb->post + iocb->page_offset) >> PAGE_SHIFT;
		off = (iocb->post + iocb->page_offset) & (~PAGE_MASK);
		len = min(SDP_SRC_AVAIL_MIN, (int)(PAGE_SIZE - off));

		if (len > iocb->len) {
			sdp_dbg_warn(conn, "Data <%d:%d:%d> from IOCB <%d:%d>",
				     len, pos, off,
				     iocb->page_count,
				     iocb->page_offset);

			result = -EFAULT;
			goto error;
		}

		local_irq_save(flags);

		addr = kmap_atomic(iocb->page_array[pos], KM_IRQ0);
		if (!addr) {
			result = -ENOMEM;
			local_irq_restore(flags);
			goto error;
		}

		memcpy(buff->tail, addr + off, len);

		kunmap_atomic(iocb->page_array[pos], KM_IRQ0);

		local_irq_restore(flags);

		buff->data_size  = len;
		buff->tail      += len;

		iocb->len       -= len;

		conn->nond_send++;
	}

	conn->src_sent++;
	/*
	 * endian swap of extended header
	 */
	sdp_msg_cpu_to_net_srcah(src_ah);
	/*
	 * queue/send SrcAvail message
	 */
	result = sdp_send_buff_post(conn, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting SrcAvail for IOCB <%d>",
			     result, iocb->key);
		goto release;
	}

	return 0;
release:
	conn->nond_send -= (conn->send_mode == SDP_MODE_COMB) ? 1 : 0;
	conn->src_sent--;

	iocb->len += ((conn->send_mode == SDP_MODE_COMB) ?
		      SDP_SRC_AVAIL_MIN : 0);
error:
	iocb->flags &= ~(SDP_IOCB_F_RDMA_R | SDP_IOCB_F_ACTIVE);
drop:
	sdp_buff_pool_put(buff);
	return result;
}

/*
 * sdp_send_iocb_buff_write - write part of an iocb into a SDP buffer
 */
static int sdp_send_iocb_buff_write(struct sdpc_iocb *iocb,
				    struct sdpc_buff *buff)
{
	unsigned long copy = 0;
	unsigned long offset;
	unsigned int counter;
	void  *addr;

	/*
	 * initialize counter to correct page and offset.
	 */
	counter = (iocb->post + iocb->page_offset) >> PAGE_SHIFT;
	offset  = (iocb->post + iocb->page_offset) & (~PAGE_MASK);


	while (buff->tail < buff->end && iocb->len > 0) {
		unsigned long flags;
		local_irq_save(flags);

		addr = kmap_atomic(iocb->page_array[counter], KM_IRQ0);
		if (!addr) {
			local_irq_restore(flags);
			break;
		}

		copy = min(PAGE_SIZE - offset,
			   (unsigned long)(buff->end - buff->tail));
		copy = min((unsigned long)iocb->len, copy);
#ifndef _SDP_DATA_PATH_NULL
		memcpy(buff->tail, addr + offset, copy);
#endif
		buff->data_size += copy;
		buff->tail      += copy;
		iocb->post      += copy;
		iocb->len       -= copy;
		iocb->io_addr   += copy;

		offset += copy;
		offset &= (~PAGE_MASK);

		kunmap_atomic(iocb->page_array[counter], KM_IRQ0);
		++counter;
		local_irq_restore(flags);
	}

	return 0;
}

/*
 * sdp_send_data_iocb_buff - write multiple SDP buffers from an iocb
 */
static int sdp_send_data_iocb_buff(struct sdp_sock *conn, struct sdpc_iocb *iocb)
{
	struct sdpc_buff *buff;
	int result;

	if (conn->src_sent > 0)
		return ENOBUFS;
	/*
	 * loop through queued buffers and copy them to the destination
	 */
	while (iocb->len > 0 &&
	       conn->r_recv_bf > 2 &&
	       conn->send_cq_size > conn->s_wq_size) {
		/*
		 * get a buffer for posting.
		 */
		buff = sdp_buff_pool_get();
		if (!buff) {
			result = -ENOMEM;
			goto error;
		}
		/*
		 * setup header.
		 */
		buff->tail = buff->end - conn->send_size;
		buff->data = buff->tail;

		buff->data           -= sizeof(struct msg_hdr_bsdh);
		buff->bsdh_hdr        = (struct msg_hdr_bsdh *) buff->data;
		buff->bsdh_hdr->mid   = SDP_MID_DATA;
		buff->bsdh_hdr->flags = SDP_MSG_FLAG_NON_FLAG;

		SDP_BUFF_F_CLR_SE(buff);
		SDP_BUFF_F_CLR_UNSIG(buff);
		/*
		 * TODO: need to be checking OOB here.
		 */
		result = sdp_send_iocb_buff_write(iocb, buff);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> copy from IOCB <%d>.",
				     result, iocb->key);
			goto drop;
		}

		conn->send_qud += buff->data_size;
		conn->nond_send++;
		/*
		 * transmision time. An update of send_pipe is not needed,
		 * since the IOCB queue took care of the increment.
		 */
		result = sdp_send_buff_post(conn, buff);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> send queue buff post",
				     result);
			goto drop;
		}
	}

	return iocb->len;
drop:
	sdp_buff_pool_put(buff);
error:
	return result;
}

/*
 * sdp_send_data_iocb - Post IOCB data for transmission
 */
static int sdp_send_data_iocb(struct sdp_sock *conn, struct sdpc_iocb *iocb)
{
	int result = ENOBUFS;

	if (conn->send_cq_size <= conn->s_wq_size)
		goto done;
	/*
	 * confirm IOCB usage.
	 */
	if (iocb->type != SDP_DESC_TYPE_IOCB)
		return -ENOBUFS;
	/*
	 * determin if we are sending Buffered, Source or Sink.
	 */
	if (sdp_advt_q_size(&conn->snk_pend) > 0) {
		result = sdp_send_data_iocb_snk(conn, iocb);
		if (!result) {
			/*
			 * IOCB completely processed. Otherwise we allow the
			 * callers to determine the fate of the IOCB on
			 * failure or partial processing.
			 */
			if (sdp_desc_q_member((struct sdpc_desc *)iocb) > 0)
				sdp_desc_q_remove((struct sdpc_desc *)iocb);

			sdp_desc_q_put_tail(&conn->w_snk,
					    (struct sdpc_desc *)iocb);
		}

		goto done;
	}
	/*
	 * If there are active sink IOCBs we want to stall, in the
	 * hope that a new sink advertisment will arrive, because
	 * sinks are more efficient.
	 */
	if (sdp_desc_q_size(&conn->w_snk) ||
	    iocb->flags & SDP_IOCB_F_RDMA_W)
		goto done;

	if (conn->src_zthresh > iocb->len ||
	    conn->send_mode == SDP_MODE_BUFF ||
	    (iocb->flags & SDP_IOCB_F_BUFF)) {
		result = sdp_send_data_iocb_buff(conn, iocb);
		if (!result) {
			/*
			 * complete this IOCB
			 */
			if (sdp_desc_q_member((struct sdpc_desc *) iocb) > 0)
				sdp_desc_q_remove((struct sdpc_desc *) iocb);

			SDP_CONN_STAT_WRITE_INC(conn, iocb->post);
			SDP_CONN_STAT_WQ_DEC(conn, iocb->size);

			sdp_iocb_complete(iocb, 0);
		}

		goto done;
	}

	result = sdp_send_data_iocb_src(conn, iocb);
	if (!result) {
		/*
		 * queue IOCB
		 */
		if (sdp_desc_q_member((struct sdpc_desc *) iocb) > 0)
			sdp_desc_q_remove((struct sdpc_desc *)iocb);

		sdp_iocb_q_put_tail(&conn->w_src, iocb);
	}

done:
	return result;
}

/*
 * sdp_send_data_queue_test - send data buffer if conditions are met
 */
static int sdp_send_data_queue_test(struct sdp_sock *conn,
				    struct sdpc_desc *element)
{
	int result;

	/*
	 * Notify caller to buffer data:
	 * 1) Invalid state for transmission
	 * 2) source advertisment cancel in progress.
	 */
	if (!(SDP_ST_MASK_SEND_OK & conn->state) ||
	    (conn->flags & SDP_CONN_F_SRC_CANCEL_L))
		return ENOBUFS;

	if (element->type == SDP_DESC_TYPE_IOCB)
		return sdp_send_data_iocb(conn, (struct sdpc_iocb *)element);

	if (!sdp_advt_q_look(&conn->snk_pend) ||
	    (((struct sdpc_buff *)element)->flags & SDP_BUFF_F_OOB_PRES))
		result = sdp_send_data_buff_post(conn,
						 (struct sdpc_buff *)element);
	else
		result = sdp_send_data_buff_snk(conn,
						(struct sdpc_buff *)element);

	return result;
}

/*
 * sdp_send_data_queue_flush - Flush data from send queue, to send post
 */
static int sdp_send_data_queue_flush(struct sdp_sock *conn)
{
	struct sdpc_desc *element;
	int result = 0;

	/*
	 * As long as there is data, try to post buffered data, until a
	 * non-zero result is generated.
	 * (positive: no space; negative: error)
	 */
	while ((element = sdp_desc_q_look_head(&conn->send_queue))) {

		result = sdp_send_data_queue_test(conn, element);
		if (result)
			break;
	}

	if (result < 0)
		sdp_dbg_warn(conn, "Error <%d> post data <%d> during flush",
			     result, element->type);

	return result;
}

/*
 * sdp_send_data_queue - send using the data queue if necessary
 */
static int sdp_send_data_queue(struct sdp_sock *conn, struct sdpc_desc *element)
{
	int result = 0;

	/*
	 * If data is being buffered, save and return, send/recv completions
	 * will flush the queue.
	 * If data is not being buffered, attempt to send, a positive result
	 * requires us to buffer, a negative result is an error, a return
	 * value of zero is a successful transmission
	 */
	if (sdp_desc_q_size(&conn->send_queue) > 0 ||
	    (result = sdp_send_data_queue_test(conn, element)) > 0) {

		sdp_desc_q_put_tail(&conn->send_queue, element);
		/*
		 * Potentially request a switch to pipelined mode.
		 */
		if (conn->send_mode == SDP_MODE_COMB &&
		    sdp_desc_q_size(&conn->send_queue) >= SDP_INET_SEND_MODE) {
			result = sdp_send_ctrl_mode_ch(conn,
						       SDP_MSG_MCH_PIPE_RECV);
			if (result < 0) {
				sdp_dbg_warn(conn,
					     "Error <%d> posting mode change",
					     result);
				goto done;
			}
		}
	}

	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> during data send posting",
			     result);
		goto done;
	}

	return 0;
done:
	return result;
}

/*
 * sdp_send_data_buff_get - get an appropriate write buffer for send
 */
static inline struct sdpc_buff *sdp_send_data_buff_get(struct sdp_sock *conn)
{
	struct sdpc_buff *buff;

	/*
	 * If there is no available buffer get a new one.
	 */
	buff = (struct sdpc_buff *)sdp_desc_q_look_type_tail(&conn->send_queue,
							     SDP_DESC_TYPE_BUFF);
	if (!buff ||
	    buff->tail == buff->end ||
	    (buff->flags & SDP_BUFF_F_OOB_PRES)) {
		buff = sdp_buff_pool_get();
		if (buff) {
			buff->tail = buff->end - conn->send_size;
			buff->data = buff->tail;
		}
	}

	return buff;
}

/*
 * sdp_send_data_buff_put - place a buffer into the send queue
 */
static inline int sdp_send_data_buff_put(struct sdp_sock *conn,
					 struct sdpc_buff *buff, int size,
					 int urg)
{
	int result = 0;

	/*
	 * See note on send OOB implementation in SendBuffPost.
	 */
	if (urg > 0) {
		buff->flags |= SDP_BUFF_F_OOB_PRES;
		/*
		 * The OOB PEND and PRES flags need to match up as pairs.
		 */
		if (conn->oob_offset < 0) {
			conn->oob_offset = conn->send_pipe + size;
			conn->flags |= SDP_CONN_F_OOB_SEND;
		}
	}
	/*
	 * if the buffer is already queue, then this was a fill of a partial
	 * buffer and dosn't need to be queued now.
	 */
	if (buff->flags & SDP_BUFF_F_QUEUED) {
		buff->data_size += size;
		conn->send_qud += size;
		conn->send_pipe += size;
	} else {
		buff->data_size = buff->tail - buff->data;
		conn->send_qud += buff->data_size;
		conn->send_pipe += buff->data_size;

		buff->flags |= SDP_BUFF_F_QUEUED;
		/*
		 * finally send the data buffer
		 */
		result = sdp_send_data_queue(conn, (struct sdpc_desc *) buff);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> buffer to SEND queue.",
				     result);

			sdp_buff_pool_put(buff);
		}
	}

	return result;
}

/*
 * CONTROL functions
 */

/*
 * sdp_send_ctrl_buff_test - determine if it's OK to post a control msg
 */
static int sdp_send_ctrl_buff_test(struct sdp_sock *conn, struct sdpc_buff *buff)
{
	int result = 0;

	if (!(SDP_ST_MASK_CTRL_OK & conn->state) ||
	    !(conn->send_cq_size > conn->s_wq_size) ||
	    conn->r_recv_bf <= 0 ||
	    (conn->l_recv_bf == conn->l_advt_bf && conn->r_recv_bf == 1))
		return ENOBUFS;
	/*
	 * post the control buffer
	 */
	result = sdp_send_buff_post(conn, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting control send", result);
		goto error;
	}

	return 0;
error:
	return result;
}

/*
 * sdp_send_ctrl_buff_flush - Flush control buffers, to send post
 */
static int sdp_send_ctrl_buff_flush(struct sdp_sock *conn)
{
	struct sdpc_desc *element;
	int result = 0;

	/*
	 * As long as there are buffers, try to post  until a non-zero
	 * result is generated. (positive: no space; negative: error)
	 */
	while ((element = sdp_desc_q_look_head(&conn->send_ctrl))) {

		result = sdp_send_ctrl_buff_test(conn,
						 (struct sdpc_buff *)element);
		if (result)
			break;
	}

	if (result < 0)
		sdp_dbg_warn(conn, "Error <%d> failed to flush control msg",
			     result);

	return result;
}

/*
 * sdp_send_ctrl_buff_buffered - Send a buffered control message
 */
static int sdp_send_ctrl_buff_buffered(struct sdp_sock *conn,
				       struct sdpc_buff *buff)
{
	int result = 0;

	/*
	 * Either post a send, or buffer the packet in the tx queue
	 */
	if (sdp_desc_q_size(&conn->send_ctrl) > 0 ||
	    (result = sdp_send_ctrl_buff_test(conn, buff)) > 0)
		/*
		 * save the buffer for later flushing into the post queue.
		 */
		sdp_desc_q_put_tail(&conn->send_ctrl,
				    (struct sdpc_desc *)buff);

	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> during control send posting",
			     result);
		goto error;
	}

	return 0;
error:
	return result;
}

/*
 * sdp_send_ctrl_buff - Create and Send a buffered control message
 */
static int sdp_send_ctrl_buff(struct sdp_sock *conn, u8 mid, int se, int sig)
{
	int result = 0;
	struct sdpc_buff *buff;

	/*
	 * create the message, which contains just the bsdh header.
	 * (don't need to worry about header space reservation)
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "Failed to allocate buffer for control");
		return -ENOMEM;
	}
	/*
	 * setup header.
	 */
	buff->bsdh_hdr = (struct msg_hdr_bsdh *) buff->data;
	buff->bsdh_hdr->mid = mid;
	buff->bsdh_hdr->flags = SDP_MSG_FLAG_NON_FLAG;
	buff->tail = buff->data + sizeof(struct msg_hdr_bsdh);
	buff->data_size = 0;
	/*
	 * solicite event flag for IB sends.
	 */
	if (se)
		SDP_BUFF_F_SET_SE(buff);
	else
		SDP_BUFF_F_CLR_SE(buff);
	/*
	 * try for unsignalled?
	 */
	if (sig)
		SDP_BUFF_F_CLR_UNSIG(buff);
	else
		SDP_BUFF_F_SET_UNSIG(buff);
	/*
	 * Either post a send, or buffer the packet in the tx queue
	 */
	result = sdp_send_ctrl_buff_buffered(conn, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting control message",
			     result);
		sdp_buff_pool_put(buff);
	}

	return result;
}

/*
 * do_send_ctrl_disconnect - Send a disconnect request
 */
static int do_send_ctrl_disconnect(struct sdp_sock *conn)
{
	int result = 0;
	struct sdpc_buff *buff;

	/*
	 * create the disconnect message, which contains just the bsdh header.
	 * (don't need to worry about header space reservation)
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "Failed to allocate buffer for disconnect");
		return -ENOMEM;
	}
	/*
	 * setup header.
	 */
	buff->bsdh_hdr = (struct msg_hdr_bsdh *) buff->data;
	buff->bsdh_hdr->mid = SDP_MID_DISCONNECT;
	buff->bsdh_hdr->flags = SDP_MSG_FLAG_NON_FLAG;
	buff->tail = buff->data + sizeof(struct msg_hdr_bsdh);
	buff->data_size = 0;

	SDP_BUFF_F_CLR_SE(buff);
	SDP_BUFF_F_CLR_UNSIG(buff);
	/*
	 * send
	 */
	result = sdp_send_ctrl_buff_buffered(conn, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting control message",
			     result);
		sdp_buff_pool_put(buff);
		goto error;
	}

	conn->flags &= ~SDP_CONN_F_DIS_PEND;

	return 0;
error:
	return result;
}

/*
 * sdp_send_ctrl_disconnect - potentially send a disconnect request
 */
int sdp_send_ctrl_disconnect(struct sdp_sock *conn)
{
	int result = 0;
	/*
	 * Only create/post the message if there is no data in the data queue,
	 * otherwise ignore the call. The flush queue will see to it, that a
	 * Disconnect message gets queued/sent once the data queue is flushed
	 * clean. The state is now in a disconnect send, the message will be
	 * sent once data is flushed.
	 */
	if ((conn->flags & SDP_CONN_F_DIS_HOLD) ||
	    sdp_desc_q_size(&conn->send_queue) ||
	    conn->src_sent)
		conn->flags |= SDP_CONN_F_DIS_PEND;
	else
		result = do_send_ctrl_disconnect(conn);

	return result;
}

/*
 * sdp_send_ctrl_ack - Send a gratuitous Ack
 */
int sdp_send_ctrl_ack(struct sdp_sock *conn)
{
	/*
	 * The gratuitous ack is not really and ack, but an update of the
	 * number of buffers posted for receive. Important when traffic is
	 * only moving in one direction. We check to see if the buffer
	 * credits are going to be sent in an already scheduled message
	 * before posting. The send queue has different constraints/stalling
	 * conditions then the control queue, so there is more checking to
	 * be done, then whether there is data in the queue.
	 */
	if (sdp_desc_q_size(&conn->send_ctrl) > 0 ||
	    (sdp_desc_q_size(&conn->send_queue) > 0 &&
	     conn->l_advt_bf > 2))
		return 0;

	return sdp_send_ctrl_buff(conn, SDP_MID_DATA, 0, 0);
}

/*
 * sdp_send_ctrl_send_sm - Send a request for buffered mode
 */
int sdp_send_ctrl_send_sm(struct sdp_sock *conn)
{
	return sdp_send_ctrl_buff(conn, SDP_MID_SEND_SM, 1, 1);
}

/*
 * sdp_send_ctrl_src_cancel - Send a source cancel
 */
int sdp_send_ctrl_src_cancel(struct sdp_sock *conn)
{
	return sdp_send_ctrl_buff(conn, SDP_MID_SRC_CANCEL, 1, 1);
}

/*
 * sdp_send_ctrl_snk_cancel - Send a sink cancel
 */
int sdp_send_ctrl_snk_cancel(struct sdp_sock *conn)
{
	return sdp_send_ctrl_buff(conn, SDP_MID_SNK_CANCEL, 1, 1);
}

/*
 * sdp_send_ctrl_snk_cancel_ack - Send an ack for a sink cancel
 */
int sdp_send_ctrl_snk_cancel_ack(struct sdp_sock *conn)
{
	return sdp_send_ctrl_buff(conn, SDP_MID_SNK_CANCEL_ACK, 1, 1);
}

/*
 * sdp_send_ctrl_abort - Send an abort message
 */
int sdp_send_ctrl_abort(struct sdp_sock *conn)
{
	/*
	 * send
	 */
	return sdp_send_ctrl_buff(conn, SDP_MID_ABORT_CONN, 1, 1);
}

/*
 * sdp_send_ctrl_resize_buff_ack - Send an ack for a buffer size change
 */
int sdp_send_ctrl_resize_buff_ack(struct sdp_sock *conn, u32 size)
{
	struct msg_hdr_crbah *crbah;
	struct sdpc_buff *buff;
	int result = 0;

	/*
	 * create the message, which contains just the bsdh header.
	 * (don't need to worry about header space reservation)
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "Failed to allocate buffer for resize ack");
		result = -ENOMEM;
		goto error;
	}
	/*
	 * setup header.
	 */
	buff->tail            = buff->data;
	buff->bsdh_hdr        = (struct msg_hdr_bsdh *)buff->tail;
	buff->bsdh_hdr->mid   = SDP_MID_CH_RECV_BUF_ACK;
 	buff->bsdh_hdr->flags = SDP_MSG_FLAG_NON_FLAG;
	buff->tail           += sizeof(struct msg_hdr_bsdh);
	crbah                 = (struct msg_hdr_crbah *)buff->tail;
	crbah->size           = size;
	buff->tail           += sizeof(struct msg_hdr_crbah);

	SDP_BUFF_F_CLR_SE(buff);
	SDP_BUFF_F_CLR_UNSIG(buff);
	/*
	 * endian swap of extended header
	 */
	sdp_msg_cpu_to_net_crbah(crbah);
	/*
	 * Either post a send, or buffer the packet in the tx queue
	 */
	result = sdp_send_ctrl_buff_buffered(conn, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting control message",
			     result);
		sdp_buff_pool_put(buff);
	}

error:
	return result;
}

/*
 * sdp_send_ctrl_rdma_rd - Send an rdma read completion
 */
int sdp_send_ctrl_rdma_rd(struct sdp_sock *conn, s32 size)
{
	struct msg_hdr_rrch *rrch;
	struct sdpc_buff *buff;
	int result = 0;

	/*
	 * check size
	 */
	if (size < 0) {
		sdp_dbg_warn(conn, "RDMA read completion <%d> too small.",
			     size);
		return -ERANGE;
	}
	/*
	 * create the message, which contains just the bsdh header.
	 * (don't need to worry about header space reservation)
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "Failed to allocate buffer for RDMA rd");
		result = -ENOMEM;
		goto error;
	}
	/*
	 * setup header.
	 */
	buff->tail            = buff->data;
	buff->bsdh_hdr        = (struct msg_hdr_bsdh *)buff->tail;
	buff->bsdh_hdr->mid   = SDP_MID_RDMA_RD_COMP;
	buff->bsdh_hdr->flags = SDP_MSG_FLAG_NON_FLAG;
	buff->tail           += sizeof(struct msg_hdr_bsdh);
	rrch                  = (struct msg_hdr_rrch *)buff->tail;
	rrch->size            = (u32)size;
	buff->tail           += sizeof(struct msg_hdr_rrch);
	/*
	 * solicit event
	 */
#ifdef _SDP_SE_UNSIG_BUG_WORKAROUND
	SDP_BUFF_F_CLR_SE(buff);
#else
	SDP_BUFF_F_SET_SE(buff);
#endif
	SDP_BUFF_F_SET_UNSIG(buff);
	/*
	 * set PIPE bit to request switch into pipeline mode.
	 */
	SDP_BSDH_SET_REQ_PIPE(buff->bsdh_hdr);
	/*
	 * endian swap of extended header
	 */
	sdp_msg_cpu_to_net_rrch(rrch);
	/*
	 * Either post a send, or buffer the packet in the tx queue
	 */
	result = sdp_send_ctrl_buff_buffered(conn, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting control message",
			     result);
		sdp_buff_pool_put(buff);
	}

error:
	return result;
}

/*
 * sdp_send_ctrl_rdma_wr - Send an rdma write completion
 */
int sdp_send_ctrl_rdma_wr(struct sdp_sock *conn, u32 size)
{
	struct msg_hdr_rwch *rwch;
	struct sdpc_buff *buff;
	int result = 0;

	/*
	 * create the message, which contains just the bsdh header.
	 * (don't need to worry about header space reservation)
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "Failed to allocate buffer for RDMA wr");
		result = -ENOMEM;
		goto error;
	}
	/*
	 * setup header.
	 */
	buff->tail            = buff->data;
	buff->bsdh_hdr        = (struct msg_hdr_bsdh *)buff->tail;
	buff->bsdh_hdr->mid   = SDP_MID_RDMA_WR_COMP;
	buff->bsdh_hdr->flags = SDP_MSG_FLAG_NON_FLAG;
	buff->tail           += sizeof(struct msg_hdr_bsdh);
	rwch                  = (struct msg_hdr_rwch *)buff->tail;
	rwch->size            = size;
	buff->tail           += sizeof(struct msg_hdr_rwch);
	/*
	 * solicit event
	 */
#ifdef _SDP_SE_UNSIG_BUG_WORKAROUND
	SDP_BUFF_F_CLR_SE(buff);
#else
	SDP_BUFF_F_SET_SE(buff);
#endif
	SDP_BUFF_F_SET_UNSIG(buff);
	/*
	 * endian swap of extended header
	 */
	sdp_msg_cpu_to_net_rwch(rwch);
	/*
	 * Either post a send, or buffer the packet in the tx queue
	 */
	result = sdp_send_ctrl_buff_buffered(conn, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting control message",
			     result);
		sdp_buff_pool_put(buff);
	}

error:
	return result;
}

/*
 * sdp_send_ctrl_snk_avail - Send a sink available message
 */
int sdp_send_ctrl_snk_avail(struct sdp_sock *conn, u32 size, u32 rkey, u64 addr)
{
	struct msg_hdr_snkah *snkah;
	struct sdpc_buff *buff;
	int result = 0;

	/*
	 * check mode
	 */
	if (conn->recv_mode != SDP_MODE_PIPE)
		return -EPROTO;
	/*
	 * create the message, which contains just the bsdh header.
	 * (don't need to worry about header space reservation)
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "Failed to allocate buffer for SnkAvail");
		result = -ENOMEM;
		goto error;
	}
	/*
	 * setup header.
	 */
	buff->tail = buff->data;
	buff->bsdh_hdr = (struct msg_hdr_bsdh *) buff->tail;
	buff->bsdh_hdr->mid = SDP_MID_SNK_AVAIL;
	buff->bsdh_hdr->flags = SDP_MSG_FLAG_NON_FLAG;
	buff->tail += sizeof(struct msg_hdr_bsdh);
	snkah = (struct msg_hdr_snkah *) buff->tail;
	snkah->size = size;
	snkah->r_key = rkey;
	snkah->addr = addr;
	snkah->non_disc = conn->nond_recv;
	buff->tail += sizeof(struct msg_hdr_snkah);
	buff->data_size = 0;

	SDP_BUFF_F_CLR_SE(buff);
	SDP_BUFF_F_SET_UNSIG(buff);
	/*
	 * endian swap of extended header
	 */
	sdp_msg_cpu_to_net_snkah(snkah);
	/*
	 * Either post a send, or buffer the packet in the tx queue
	 */
	result = sdp_send_ctrl_buff_buffered(conn, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting control message",
			     result);
		goto error;
	}

	result = 0;
error:
	return result;
}

/*
 * sdp_send_ctrl_mode_ch - Send a mode change command
 */
int sdp_send_ctrl_mode_ch(struct sdp_sock *conn, u8 mode)
{
	struct msg_hdr_mch *mch;
	struct sdpc_buff *buff;
	int result = 0;

	/*
	 * validate that the requested mode transition is OK.
	 */
	switch (mode) {
	case SDP_MSG_MCH_BUFF_RECV:	/* source to sink */
		conn->send_mode = ((conn->send_mode == SDP_MODE_COMB) ?
				   SDP_MODE_BUFF : SDP_MODE_ERROR);
		break;
	case SDP_MSG_MCH_COMB_SEND:	/* sink to source */
		conn->recv_mode = ((conn->recv_mode == SDP_MODE_BUFF) ?
				   SDP_MODE_COMB : SDP_MODE_ERROR);
		break;
	case SDP_MSG_MCH_PIPE_RECV:	/* source to sink */
		conn->send_mode = ((conn->send_mode == SDP_MODE_COMB) ?
				   SDP_MODE_PIPE : SDP_MODE_ERROR);
		break;
	case SDP_MSG_MCH_COMB_RECV:	/* source to sink */
		conn->send_mode = ((conn->send_mode == SDP_MODE_PIPE) ?
				   SDP_MODE_COMB : SDP_MODE_ERROR);
		break;
	default:
		sdp_dbg_warn(conn, "Invalid mode transition <%d:%d:%d>",
			     mode, conn->send_mode, conn->recv_mode);
		result = -EPROTO;
		goto error;
	}

	if (conn->send_mode == SDP_MODE_ERROR ||
	    conn->recv_mode == SDP_MODE_ERROR) {
		sdp_dbg_warn(conn, "mode transition error <%d:%d:%d>",
			     mode, conn->send_mode, conn->recv_mode);
		result = -EPROTO;
		goto error;
	}
	/*
	 * create the message, which contains just the bsdh header.
	 * (don't need to worry about header space reservation)
	 */
	buff = sdp_buff_pool_get();
	if (!buff) {
		sdp_dbg_warn(conn, "Failed to allocate buffer for ModeChange");
		result = -ENOMEM;
		goto error;
	}
	/*
	 * setup header.
	 */
	buff->tail = buff->data;
	buff->bsdh_hdr = (struct msg_hdr_bsdh *) buff->tail;
	buff->bsdh_hdr->mid = SDP_MID_MODE_CHANGE;
	buff->bsdh_hdr->flags = SDP_MSG_FLAG_NON_FLAG;
	buff->tail += sizeof(struct msg_hdr_bsdh);
	mch = (struct msg_hdr_mch *) buff->tail;
	buff->tail += sizeof(struct msg_hdr_mch);

	SDP_BUFF_F_SET_SE(buff);
	SDP_BUFF_F_CLR_UNSIG(buff);
	SDP_MSG_MCH_SET_MODE(mch, mode);
	/*
	 * endian swap of extended header
	 */
	sdp_msg_cpu_to_net_mch(mch);
	/*
	 * Either post a send, or buffer the packet in the tx queue
	 */
	result = sdp_send_ctrl_buff_buffered(conn, buff);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> posting control message",
			     result);
		sdp_buff_pool_put(buff);
	}

error:
	return result;
}

/*
 * GENERAL functions
 */

/*
 * sdp_write_src_lookup - lookup function for cancelation
 */
static int sdp_write_src_lookup(struct sdpc_desc *element, void *arg)
{
	struct sdpc_iocb *iocb = (struct sdpc_iocb *) element;
	struct kiocb *req = (struct kiocb *)arg;

	if (element->type == SDP_DESC_TYPE_IOCB && iocb->key == req->ki_key)
		return 0;
	else
		return -ERANGE;
}

/*
 * sdp_inet_write_cancel - cancel an IO operation
 */
static int sdp_inet_write_cancel(struct kiocb *req, struct io_event *ev)
{
	struct sock_iocb *si = kiocb_to_siocb(req);
	struct sdp_sock   *conn;
	struct sdpc_iocb *iocb;
	int result = 0;

	sdp_dbg_ctrl(NULL, "Cancel Write IOCB user <%d> key <%d> flag <%08lx>",
		     req->ki_users, req->ki_key, req->ki_flags);

	if (!si || !si->sock || !si->sock->sk) {
		sdp_warn("Cancel empty write IOCB users <%d> flags <%d:%08lx>",
			 req->ki_users, req->ki_key, req->ki_flags);
		result = -EFAULT;
		goto done;
	}
	/*
	 * lock the socket while we operate.
	 */
	conn = sdp_sk(si->sock->sk);
	sdp_conn_lock(conn);

	sdp_dbg_ctrl(conn, "Cancel Write IOCB. <%08x:%04x> <%08x:%04x>",
		     conn->src_addr, conn->src_port,
		     conn->dst_addr, conn->dst_port);
	/*
	 * attempt to find the IOCB for this key. we don't have an indication
	 * whether this is a read or write.
	 */
	iocb = (struct sdpc_iocb *)sdp_desc_q_lookup(&conn->send_queue,
						     sdp_write_src_lookup,
						     req);
	if (iocb) {
		/*
		 * always remove the IOCB.
		 * If active, then place it into the correct active queue
		 */
		sdp_desc_q_remove((struct sdpc_desc *)iocb);

		if (iocb->flags & SDP_IOCB_F_ACTIVE) {
			if (iocb->flags & SDP_IOCB_F_RDMA_W)
				sdp_desc_q_put_tail(&conn->w_snk,
						    (struct sdpc_desc *)iocb);
			else {
				SDP_EXPECT((iocb->flags & SDP_IOCB_F_RDMA_R));

				sdp_iocb_q_put_tail(&conn->w_src, iocb);
			}
		} else {
			/*
			 * empty IOCBs can be deleted, while partials
			 * needs to be compelted.
			 */
			if (iocb->post > 0) {
				sdp_iocb_complete(iocb, 0);
				result = -EAGAIN;
			} else {
				sdp_iocb_destroy(iocb);
				/*
				 * completion reference
				 */
				aio_put_req(req);

				result = 0;
			}

			goto unlock;
		}
	}
	/*
	 * check the sink queue, not much to do, since the operation is
	 * already in flight.
	 */
	iocb = (struct sdpc_iocb *)sdp_desc_q_lookup(&conn->w_snk,
						     sdp_write_src_lookup,
						     req);

	if (iocb) {
		iocb->flags |= SDP_IOCB_F_CANCEL;
		result = -EAGAIN;

		goto unlock;
	}
	/*
	 * check source queue. If we're ing the source queue, then a cancel
	 * needs to be issued.
	 */
	iocb = sdp_iocb_q_lookup(&conn->w_src, req->ki_key);
	if (iocb) {
		/*
		 * Unfortunetly there is only a course grain cancel in SDP,
		 * so we have to cancel everything. This is OKish since it
		 * usually only happens at connection termination, and the
		 * remaining source probably will get cancel requests as well.
		 * The main complexity is to take all the fine grain cancels
		 * from AIO and once all out standing Src messages have been
		 * cancelled we can issue the course grain SDP cancel. The
		 * connection is marked as being in cancel processing so no
		 * other writes get into the outbound pipe.
		 */
		if (!(conn->flags & SDP_CONN_F_SRC_CANCEL_L) &&
		    !(iocb->flags & SDP_IOCB_F_CANCEL)) {
			conn->src_cncl++;
			iocb->flags |= SDP_IOCB_F_CANCEL;

			if (conn->src_cncl == sdp_iocb_q_size(&conn->w_src)) {
				result = sdp_send_ctrl_src_cancel(conn);
				SDP_EXPECT(result >= 0);

				conn->flags |= SDP_CONN_F_SRC_CANCEL_L;
			}
		}

		result = -EAGAIN;
		goto unlock;
	}
	/*
	 * no IOCB found. The cancel is probably in a race with a completion.
	 * Assume the IOCB will be completed, return appropriate value.
	 */
	sdp_warn("Cancel write with no IOCB. <%d:%d:%08lx>",
		 req->ki_users, req->ki_key, req->ki_flags);

	result = -EAGAIN;

unlock:
	sdp_conn_unlock(conn);
done:

	aio_put_req(req); /* cancel call reference */
	return result;
}

/*
 * sdp_send_flush_advt - Flush passive sink advertisments
 */
static int sdp_send_flush_advt(struct sdp_sock *conn)
{
	struct sdpc_advt *advt;
	int result;
	/*
	 * If there is no data in the pending or active send pipes, and a
	 * partially complete sink advertisment is pending, then it needs
	 * to be completed. It might be some time until more data is ready
	 * for transmission, and the remote host needs to be notified of
	 * present data. (rdma ping-pong letency test...)
	 */
	if (sdp_desc_q_size(&conn->send_queue))
		return 0;

	/*
	 * might be more aggressive then we want it to be. maybe
	 * check if the active sink queue is empty as well?
	 */
	advt = sdp_advt_q_look(&conn->snk_pend);
	if (!advt || !advt->post)
		return 0;

	result = sdp_send_ctrl_rdma_wr(conn, advt->post);
	if (result < 0)
		return result;

	sdp_advt_destroy(sdp_advt_q_get(&conn->snk_pend));
	/*
	 * update sink advertisments.
	 */
	conn->snk_recv--;

	return 0;
}

/*
 * sdp_send_flush - Flush buffers from send queue, in to send post
 */
int sdp_send_flush(struct sdp_sock *conn)
{
	struct sock *sk;
	int result = 0;

	/*
	 * keep posting sends as long as there is room for an SDP post.
	 * Priority goes to control messages, and we need to follow the
	 * send credit utilization rules.
	 */
	result = sdp_send_ctrl_buff_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing control", result);
		goto done;
	}
	/*
	 * data flush
	 */
	result = sdp_send_data_queue_flush(conn);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> flushing data queue", result);
		goto done;
	}
	/*
	 * Sink advertisment flush.
	 */
	if (sdp_advt_q_size(&conn->snk_pend) > 0) {
		result = sdp_send_flush_advt(conn);
		if (result < 0) {
			sdp_dbg_warn(conn,
				     "Error <%d> flushing sink advertisments",
				     result);
			goto done;
		}
	}
	/*
	 * disconnect flush
	 */
	if (conn->flags & SDP_CONN_F_DIS_PEND) {
		result = sdp_send_ctrl_disconnect(conn);
		if (result < 0) {
			sdp_dbg_warn(conn, "Error <%d> flushing disconnect",
				     result);
			goto done;
		}
	}
	/*
	 * see if there is enough buffer to wake/notify writers
	 */
	sk = sk_sdp(conn);
	sk->sk_write_space(sk);

	return 0;
done:
	return result;
}

static inline int sdp_send_while_space(struct sock *sk, struct sdp_sock *conn,
				       struct msghdr *msg, int oob,
				       size_t size, size_t *copied)
{
	struct sdpc_buff *buff;
	int result = 0;
	int copy;
	/*
	 * send while there is room... (thresholds should be
	 * observed...) use a different threshold for urgent
	 * data to allow some space for sending.
	 */
	while (sdp_inet_write_space(conn, oob) > 0) {
		buff = sdp_send_data_buff_get(conn);
		if (!buff) {
			result = -ENOMEM;
			goto done;
		}

		copy = min((size_t)(buff->end - buff->tail), size - *copied);
		copy = min(copy, sdp_inet_write_space(conn, oob));

#ifndef _SDP_DATA_PATH_NULL
		result = memcpy_fromiovec(buff->tail, msg->msg_iov, copy);
		if (result < 0) {
			sdp_buff_pool_put(buff);
			goto done;
		}
#endif
		buff->tail += copy;
		*copied += copy;

		SDP_CONN_STAT_SEND_INC(conn, copy);

		result = sdp_send_data_buff_put(conn, buff, copy,
						(*copied == size ? oob : 0));
		if (result < 0)
			goto done;

		if (*copied == size)
			goto done;
	}
	/*
	 * set no space bits since this code path is taken
	 * when there is no write space.
	 */
	set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
	set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

done:
	return result;
}

/* Returns new timeout value */
static inline long sdp_wait_till_space(struct sock *sk, struct sdp_sock *conn,
				       int oob, long timeout)
{
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue(sk->sk_sleep, &wait);
	set_current_state(TASK_INTERRUPTIBLE);
	/*
	 * ASYNC_NOSPACE is only set if we're not sleeping,
	 * while NOSPACE is set whenever there is no space,
	 * and is only cleared once space opens up, in
	 * DevConnAck()
	 */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	sdp_conn_unlock(conn);
	if (sdp_inet_write_space(conn, oob) <= 0)
		timeout = schedule_timeout(timeout);
	sdp_conn_lock(conn);

	remove_wait_queue(sk->sk_sleep, &wait);
	set_current_state(TASK_RUNNING);
	return timeout;
}

static inline int sdp_queue_iocb(struct kiocb *req, struct sdp_sock *conn,
				 struct msghdr *msg, size_t size,
				 size_t *copied)
{
	struct sdpc_iocb *iocb;
	int result;
	/*
	 * create IOCB with remaining space
	 */
	iocb = sdp_iocb_create();
	if (!iocb) {
		sdp_dbg_warn(conn, "Failed to allocate IOCB <%Zu:%ld>",
			     size, (long)*copied);
		return -ENOMEM;
	}

	iocb->len  = size - *copied;
	iocb->post = *copied;
	iocb->size = size;
	iocb->req  = req;
	iocb->key  = req->ki_key;
	iocb->addr = (unsigned long)msg->msg_iov->iov_base - *copied;

	req->ki_cancel = sdp_inet_write_cancel;

	result = sdp_iocb_lock(iocb);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> locking IOCB <%Zu:%ld>",
			     result, size, (long)copied);

		sdp_iocb_destroy(iocb);
		return result;
	}

	SDP_CONN_STAT_WQ_INC(conn, iocb->size);

	conn->send_pipe += iocb->len;

	result = sdp_send_data_queue(conn, (struct sdpc_desc *)iocb);
	if (result < 0) {
		sdp_dbg_warn(conn, "Error <%d> queueing write IOCB",
			     result);

		sdp_iocb_destroy(iocb);
		return result;
	}

	*copied = 0; /* copied amount was saved in IOCB. */
	return -EIOCBQUEUED;
}

/*
 * sdp_inet_send - send data from user space to the network
 */
int sdp_inet_send(struct kiocb *req, struct socket *sock, struct msghdr *msg,
		  size_t size)
{
	struct sock      *sk;
	struct sdp_sock   *conn;
	int result = 0;
	size_t copied = 0;
	int oob, zcopy;
	long timeout = -1;

	/*
	 * set oob flag.
	 */
	oob = (msg->msg_flags & MSG_OOB);

	sk = sock->sk;
	conn = sdp_sk(sk);

	sdp_dbg_data(conn, "send state <%04x> size <%Zu> flags <%08x>",
		     conn->state, size, msg->msg_flags);
	sdp_dbg_data(conn, "write IOCB <%d> addr <%p> user <%d> flag <%08lx>",
		     req->ki_key, msg->msg_iov->iov_base,
		     req->ki_users, req->ki_flags);

	sdp_conn_lock(conn);
	/*
	 * ESTABLISED and CLOSE can send, while CONNECT and ACCEPTED can
	 * continue being processed, it'll wait below until the send window
	 * is opened on sucessful connect, or error on an unsucessful attempt.
	 */
	if (conn->state == SDP_CONN_ST_LISTEN ||
	    conn->state == SDP_CONN_ST_CLOSED) {
		result = -ENOTCONN;
		goto done;
	}
	/*
	 * The data should automatically be handled as an IOCB if the size
	 * is beyond the zcopy threshold. IOCBs can get into the queue if
	 * they are smaller then the zopy threshold, but only if there is
	 * no buffer write space.
	 */
	zcopy = (size >= conn->src_zthresh && !is_sync_kiocb(req));

	/*
	 * clear ASYN space bit, it'll be reset if there is no space.
	 */
	if (!zcopy)
		clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
	/*
	 * process data first if window is open, next check conditions, then
	 * wait if there is more work to be done. The absolute window size is
	 * used to 'block' the caller if the connection is still connecting.
	 */
	while (!result && copied < size) {
		if (!zcopy) {
			result = sdp_send_while_space(sk, conn, msg, oob, size,
						      &copied);
			if (result < 0 || copied == size)
				break;
		}

		/* entry point for IOCB based transfers. Before processing IOCB,
		   check that the connection is OK, otherwise return error
		   synchronously. */
		/*
		 * onetime setup of timeout, but only if it's needed.
		 */
		if (timeout < 0)
			timeout = sock_sndtimeo(sk,
						msg->msg_flags & MSG_DONTWAIT);

		if (sk->sk_err) {
			result = (copied > 0) ? 0 : sock_error(sk);
			break;
		}

		if (SEND_SHUTDOWN & conn->shutdown) {
			result = -EPIPE;
			break;
		}

		if (conn->state == SDP_CONN_ST_ERROR) {
			result = -EPROTO; /* error should always be set, but
					     just in case */
			break;
		}

		if (!timeout) {
			result = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			result =
			    (timeout > 0) ? sock_intr_errno(timeout) : -EAGAIN;
			break;
		}
		/*
		 * Either wait or create and queue an IOCB for deferred
		 * completion. Wait on sync IO call create IOCB for async
		 * call.
		 */
		if (is_sync_kiocb(req))
			timeout = sdp_wait_till_space(sk, conn, oob, timeout);
		else
			result = sdp_queue_iocb(req, conn, msg, size, &copied);
	}

done:
	sdp_conn_unlock(conn);
	result = ((copied > 0) ? copied : result);

	if (result == -EPIPE && !(msg->msg_flags & MSG_NOSIGNAL))
		send_sig(SIGPIPE, current, 0);

	return result;
}

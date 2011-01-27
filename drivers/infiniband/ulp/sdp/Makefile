EXTRA_CFLAGS += \
    -Idrivers/infiniband/include \
    -Idrivers/infiniband/ulp/ipoib

obj-$(CONFIG_INFINIBAND_SDP) += ib_sdp.o

ib_sdp-objs := \
	sdp_advt.o \
	sdp_queue.o \
	sdp_buff.o \
	sdp_rcvd.o \
	sdp_sent.o \
	sdp_read.o \
	sdp_write.o \
	sdp_proc.o \
	sdp_inet.o \
	sdp_iocb.o \
	sdp_conn.o \
	sdp_send.o \
	sdp_recv.o \
	sdp_event.o \
	sdp_pass.o \
	sdp_actv.o \
	sdp_link.o

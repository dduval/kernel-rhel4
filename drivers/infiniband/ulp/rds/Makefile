EXTRA_CFLAGS += \
    -Idrivers/infiniband/include \

obj-$(CONFIG_INFINIBAND_RDS) += ib_rds.o

ib_rds-objs :=  rds.o rds_cma.o rds_inet.o rds_ep.o rds_send.o \
                rds_recv.o rds_buf.o


#
# Makefile for Software iSCSI driver
#
obj-$(CONFIG_SCSI_ISCSI_SFNET)	+= 	iscsi_sfnet.o
iscsi_sfnet-objs		:=	iscsi-initiator.o
iscsi_sfnet-objs		+= 	iscsi-attr.o \
					iscsi-portal.o \
					iscsi-session.o \
					iscsi-task.o \
					iscsi-ioctl.o \
					iscsi-network.o \
					iscsi-recv-pdu.o \
					iscsi-xmit-pdu.o \
					iscsi-login.o \
					iscsi-auth.o \
					iscsi-auth-client.o

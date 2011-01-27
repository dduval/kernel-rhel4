# Fusion MPT drivers; recognized debug defines...
#  MPT general:
#EXTRA_CFLAGS += -DMPT_DEBUG
#EXTRA_CFLAGS += -DMPT_DEBUG_MSG_FRAME
#EXTRA_CFLAGS += -DMPT_DEBUG_SG
#EXTRA_CFLAGS += -DMPT_DEBUG_EVENTS
#EXTRA_CFLAGS += -DMPT_DEBUG_INIT
#EXTRA_CFLAGS += -DMPT_DEBUG_EXIT
#EXTRA_CFLAGS += -DMPT_DEBUG_FAIL
#EXTRA_CFLAGS  += -DMPT_DEBUG_SAS

#
# driver/module specifics...
#
#  For mptbase:
#CFLAGS_mptbase.o += -DMPT_DEBUG_HANDSHAKE
#CFLAGS_mptbase.o += -DMPT_DEBUG_CONFIG
#CFLAGS_mptbase.o += -DMPT_DEBUG_DL
#CFLAGS_mptbase.o += -DMPT_DEBUG_IRQ
#CFLAGS_mptbase.o += -DMPT_DEBUG_RESET
#
#  For mptscsih:
#CFLAGS_mptscsi.o += -DMPT_DEBUG_DV
#CFLAGS_mptscsi.o += -DMPT_DEBUG_NEGO
#CFLAGS_mptscsi.o += -DMPT_DEBUG_TM
#CFLAGS_mptscsi.o += -DMPT_DEBUG_SCSI
#CFLAGS_mptscsi.o += -DMPT_DEBUG_REPLY
#
#  For mptctl:
#CFLAGS_mptctl.o += -DMPT_DEBUG_IOCTL
#

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-} LSI_LOGIC

obj-$(CONFIG_FUSION_SPI)	+= mptbase.o mptscsi.o mptspi.o
obj-$(CONFIG_FUSION_FC)		+= mptbase.o mptscsi.o mptfc.o
obj-$(CONFIG_FUSION_SAS)	+= mptbase.o mptscsi.o mptsas.o
obj-$(CONFIG_FUSION_CTL)	+= mptctl.o
obj-$(CONFIG_FUSION_LAN)	+= mptlan.o
obj-$(CONFIG_FUSION_OLD_MODULE_COMPAT)	+= mptscsih.o

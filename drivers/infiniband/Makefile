export EXTRA_CFLAGS += -D__nocast=
INFINIBANDINCLUDE	:= -Idrivers/infiniband/include \
	$(if $(KBUILD_SRC),-I$(srctree)/drivers/infiniband/include)

CPPFLAGS	:= -D__KERNEL__ $(INFINIBANDINCLUDE) $(LINUXINCLUDE)

obj-$(CONFIG_INFINIBAND)		+= core/
obj-$(CONFIG_INFINIBAND_MTHCA)		+= hw/mthca/
obj-$(CONFIG_INFINIBAND_IPATH)		+= hw/ipath/
obj-$(CONFIG_INFINIBAND_EHCA)		+= hw/ehca/
obj-$(CONFIG_INFINIBAND_IPOIB)		+= ulp/ipoib/
obj-$(CONFIG_INFINIBAND_SRP)		+= ulp/srp/
obj-$(CONFIG_INFINIBAND_SDP)		+= ulp/sdp/
obj-$(CONFIG_INFINIBAND_MADEYE)		+= util/

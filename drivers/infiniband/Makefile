INFINIBANDINCLUDE	:= -Idrivers/infiniband/include \
	$(if $(KBUILD_SRC),-I$(srctree)/drivers/infiniband/include)

CPPFLAGS	:= -D__KERNEL__ $(INFINIBANDINCLUDE) $(LINUXINCLUDE)
export CPPFLAGS

obj-$(CONFIG_INFINIBAND)		+= core/
obj-$(CONFIG_IPATH_CORE)		+= hw/ipath/
obj-$(CONFIG_INFINIBAND_MTHCA)		+= hw/mthca/
obj-$(CONFIG_INFINIBAND_IPOIB)		+= ulp/ipoib/
obj-$(CONFIG_INFINIBAND_SDP)		+= ulp/sdp/
obj-$(CONFIG_INFINIBAND_SRP)		+= ulp/srp/
obj-$(CONFIG_INFINIBAND_ISER)		+= ulp/iser/
obj-$(CONFIG_INFINIBAND_EHCA) 		+= hw/ehca/
obj-$(CONFIG_INFINIBAND_RDS)		+= ulp/rds/

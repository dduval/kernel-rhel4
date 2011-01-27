deps_config := \
	lib/Kconfig \
	drivers/xenpv_hvm/Kconfig \
	drivers/xen/Kconfig \
	crypto/Kconfig \
	security/selinux/Kconfig \
	security/Kconfig \
	lib/Kconfig.debug \
	arch/x86_64/Kconfig.debug \
	arch/x86_64/oprofile/Kconfig \
	fs/nls/Kconfig \
	fs/partitions/Kconfig \
	fs/ncpfs/Kconfig \
	fs/Kconfig \
	drivers/firmware/Kconfig \
	drivers/edac/Kconfig \
	drivers/infiniband/util/Kconfig \
	drivers/infiniband/ulp/qlgc_vnic/Kconfig \
	drivers/infiniband/ulp/sdp/Kconfig \
	drivers/infiniband/ulp/srp/Kconfig \
	drivers/infiniband/ulp/ipoib/Kconfig \
	drivers/infiniband/hw/mlx4/Kconfig \
	drivers/infiniband/hw/nes/Kconfig \
	drivers/infiniband/hw/cxgb3/Kconfig \
	drivers/infiniband/hw/amso1100/Kconfig \
	drivers/infiniband/hw/ehca/Kconfig \
	drivers/infiniband/hw/ipath/Kconfig \
	drivers/infiniband/hw/mthca/Kconfig \
	drivers/infiniband/Kconfig \
	drivers/usb/gadget/Kconfig \
	drivers/usb/atm/Kconfig \
	drivers/usb/misc/Kconfig \
	drivers/usb/serial/Kconfig \
	drivers/usb/net/Kconfig \
	drivers/usb/media/Kconfig \
	drivers/usb/image/Kconfig \
	drivers/usb/input/Kconfig \
	drivers/usb/storage/Kconfig \
	drivers/usb/class/Kconfig \
	drivers/usb/host/Kconfig \
	drivers/usb/core/Kconfig \
	drivers/usb/Kconfig \
	sound/oss/Kconfig \
	sound/parisc/Kconfig \
	sound/sparc/Kconfig \
	sound/pcmcia/Kconfig \
	sound/usb/Kconfig \
	sound/arm/Kconfig \
	sound/ppc/Kconfig \
	sound/pci/Kconfig \
	sound/isa/Kconfig \
	sound/drivers/Kconfig \
	sound/core/Kconfig \
	sound/oss/dmasound/Kconfig \
	sound/Kconfig \
	drivers/video/logo/Kconfig \
	drivers/video/console/Kconfig \
	drivers/video/Kconfig \
	drivers/media/common/Kconfig \
	drivers/media/dvb/bt8xx/Kconfig \
	drivers/media/dvb/b2c2/Kconfig \
	drivers/media/dvb/ttusb-dec/Kconfig \
	drivers/media/dvb/ttusb-budget/Kconfig \
	drivers/media/dvb/ttpci/Kconfig \
	drivers/media/dvb/frontends/Kconfig \
	drivers/media/dvb/dvb-core/Kconfig \
	drivers/media/dvb/Kconfig \
	drivers/media/radio/Kconfig \
	drivers/media/video/Kconfig \
	drivers/media/Kconfig \
	drivers/misc/Kconfig \
	drivers/w1/Kconfig \
	drivers/hwmon/Kconfig \
	drivers/i2c/chips/Kconfig \
	drivers/i2c/busses/Kconfig \
	drivers/i2c/algos/Kconfig \
	drivers/i2c/Kconfig \
	drivers/char/pcmcia/Kconfig \
	drivers/char/drm/Kconfig \
	drivers/char/agp/Kconfig \
	drivers/char/ftape/Kconfig \
	drivers/char/watchdog/Kconfig \
	drivers/char/ipmi/Kconfig \
	drivers/serial/Kconfig \
	drivers/char/Kconfig \
	drivers/input/misc/Kconfig \
	drivers/input/touchscreen/Kconfig \
	drivers/input/joystick/iforce/Kconfig \
	drivers/input/joystick/Kconfig \
	drivers/input/mouse/Kconfig \
	drivers/input/keyboard/Kconfig \
	drivers/input/serio/Kconfig \
	drivers/input/gameport/Kconfig \
	drivers/input/Kconfig \
	drivers/telephony/Kconfig \
	drivers/isdn/hardware/eicon/Kconfig \
	drivers/isdn/hardware/avm/Kconfig \
	drivers/isdn/hardware/Kconfig \
	drivers/isdn/capi/Kconfig \
	drivers/isdn/hysdn/Kconfig \
	drivers/isdn/tpam/Kconfig \
	drivers/isdn/act2000/Kconfig \
	drivers/isdn/sc/Kconfig \
	drivers/isdn/pcbit/Kconfig \
	drivers/isdn/icn/Kconfig \
	drivers/isdn/hisax/Kconfig \
	drivers/isdn/i4l/Kconfig \
	drivers/isdn/Kconfig \
	drivers/s390/net/Kconfig \
	drivers/atm/Kconfig \
	drivers/net/wan/Kconfig \
	drivers/net/pcmcia/Kconfig \
	drivers/net/wireless/Kconfig \
	drivers/net/tokenring/Kconfig \
	drivers/net/fec_8xx/Kconfig \
	drivers/net/tulip/Kconfig \
	drivers/net/arm/Kconfig \
	drivers/net/arcnet/Kconfig \
	drivers/net/Kconfig \
	net/tux/Kconfig \
	drivers/bluetooth/Kconfig \
	net/bluetooth/hidp/Kconfig \
	net/bluetooth/cmtp/Kconfig \
	net/bluetooth/bnep/Kconfig \
	net/bluetooth/rfcomm/Kconfig \
	net/bluetooth/Kconfig \
	drivers/net/irda/Kconfig \
	net/irda/ircomm/Kconfig \
	net/irda/irnet/Kconfig \
	net/irda/irlan/Kconfig \
	net/irda/Kconfig \
	drivers/net/hamradio/Kconfig \
	net/ax25/Kconfig \
	net/sched/Kconfig \
	drivers/net/appletalk/Kconfig \
	net/ipx/Kconfig \
	net/llc/Kconfig \
	net/decnet/Kconfig \
	net/sctp/Kconfig \
	net/xfrm/Kconfig \
	net/bridge/netfilter/Kconfig \
	net/decnet/netfilter/Kconfig \
	net/ipv6/netfilter/Kconfig \
	net/ipv4/netfilter/Kconfig \
	net/ipv6/Kconfig \
	net/ipv4/ipvs/Kconfig \
	net/ipv4/Kconfig \
	net/Kconfig \
	drivers/macintosh/Kconfig \
	drivers/message/i2o/Kconfig \
	drivers/ieee1394/Kconfig \
	drivers/message/fusion/Kconfig \
	drivers/md/Kconfig \
	drivers/cdrom/Kconfig \
	drivers/ata/Kconfig \
	drivers/scsi/pcmcia/Kconfig \
	drivers/scsi/arm/Kconfig \
	drivers/scsi/qla4xxx/Kconfig \
	drivers/scsi/qla2xxx/Kconfig \
	drivers/scsi/iscsi_sfnet/Kconfig \
	drivers/scsi/megaraid/Kconfig.megaraid \
	drivers/scsi/aic7xxx/Kconfig.aic79xx \
	drivers/scsi/adp94xx/Kconfig \
	drivers/scsi/aic7xxx/Kconfig.aic7xxx \
	drivers/scsi/Kconfig \
	drivers/ide/Kconfig \
	drivers/s390/block/Kconfig \
	drivers/block/paride/Kconfig \
	drivers/block/Kconfig \
	drivers/pnp/pnpbios/Kconfig \
	drivers/pnp/isapnp/Kconfig \
	drivers/pnp/Kconfig \
	drivers/parport/Kconfig \
	drivers/mtd/nand/Kconfig \
	drivers/mtd/devices/Kconfig \
	drivers/mtd/maps/Kconfig \
	drivers/mtd/chips/Kconfig \
	drivers/mtd/Kconfig \
	drivers/base/Kconfig \
	drivers/Kconfig \
	fs/Kconfig.binfmt \
	drivers/pci/hotplug/Kconfig \
	drivers/pcmcia/Kconfig \
	drivers/pci/Kconfig \
	drivers/cpufreq/Kconfig \
	arch/x86_64/kernel/cpufreq/Kconfig \
	drivers/acpi/Kconfig \
	kernel/power/Kconfig \
	drivers/block/Kconfig.iosched \
	init/Kconfig \
	arch/x86_64/Kconfig

.config include/linux/autoconf.h: $(deps_config)

$(deps_config):

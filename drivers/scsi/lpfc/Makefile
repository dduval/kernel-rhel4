# Driver for Emulex LightPulse fibre channel host bus adapters.
EXTRA_CFLAGS +=  -DRHEL_FC -DRHEL_U3_FC_XPORT -DDISKDUMP_FC
obj-$(CONFIG_SCSI_LPFC) := lpfc.o lpfcdfc.o

lpfc-objs := lpfc_mem.o lpfc_sli.o lpfc_ct.o lpfc_els.o \
lpfc_hbadisc.o lpfc_init.o lpfc_mbox.o lpfc_nportdisc.o lpfc_scsiport.o \
lpfc_fcp.o lpfc_menlo.o

lpfcdfc-objs := lpfc_cdev.o lpfc_ct.o lpfc_debug_ioctl.o lpfc_els.o	\
lpfc_hbaapi_ioctl.o lpfc_hbadisc.o lpfc_init.o lpfc_mbox.o lpfc_mem.o	\
lpfc_misc.o lpfc_nportdisc.o lpfc_scsiport.o lpfc_sli.o lpfc_menlo.o	\
lpfc_util_ioctl.o

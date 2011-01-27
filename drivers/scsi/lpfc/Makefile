# Driver for Emulex LightPulse fibre channel host bus adapters.
EXTRA_CFLAGS +=  -DRHEL_FC
obj-$(CONFIG_SCSI_LPFC) := lpfc.o

lpfc-objs := lpfc_mem.o lpfc_sli.o lpfc_ct.o lpfc_els.o \
lpfc_hbadisc.o lpfc_init.o lpfc_mbox.o lpfc_nportdisc.o lpfc_scsiport.o \
lpfc_fcp.o

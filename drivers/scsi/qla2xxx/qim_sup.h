#ifndef __QIM_SUP_H__
#define __QIM_SUP_H__


extern void
qim_dump_buffer(uint8_t *, uint32_t); 

extern int
qim_down_timeout(struct semaphore *, unsigned long);

extern int
__qim_is_fcport_in_config(scsi_qla_host_t *, fc_port_t *);

extern uint8_t *
qim_read_nvram_data(scsi_qla_host_t *, uint8_t *, uint32_t,
    uint32_t);
extern int
qim_write_nvram_data(scsi_qla_host_t *, uint8_t *, uint32_t,
    uint32_t);

extern int
qim_cmd_wait(scsi_qla_host_t *);

extern int
qim_suspend_all_target(scsi_qla_host_t *);

extern void
qim_unsuspend_all_target(scsi_qla_host_t *);

extern int 
qim_wait_for_hba_online(scsi_qla_host_t *);

extern int
qim_get_flash_version(struct qla_host_ioctl *, uint8_t *);

extern int
qim24xx_refresh_flash_version(struct qla_host_ioctl *, uint8_t *);

extern uint16_t
qim_update_or_read_flash(scsi_qla_host_t *, uint8_t *,
    uint32_t, uint32_t, uint8_t);

static __inline int
qim_is_fcport_in_config(scsi_qla_host_t *ha, fc_port_t *fcport)
{
	if (fcport->flags & FCF_PERSISTENT_BOUND)
		return 1;

	return 0;
}

__inline__ void qim_enable_intrs(scsi_qla_host_t *);
__inline__ void qim_disable_intrs(scsi_qla_host_t *);

#endif /* ifndef __QIM_SUP_H__ */


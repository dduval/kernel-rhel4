#ifndef __QIM_MBX_H__
#define __QIM_MBX_H__

/* mailbox commands */
extern uint8_t
qim_get_link_status(struct qla_host_ioctl *, uint16_t,
    uint16_t, link_stat_t *, uint16_t *);
extern uint8_t
qim_get_isp_stats(struct qla_host_ioctl *, uint32_t *,
    uint32_t, uint16_t, uint16_t *);
extern int
qim_login_fabric(scsi_qla_host_t *, uint16_t, uint8_t,
    uint8_t, uint8_t, uint16_t *, uint8_t);
extern int
qim_loopback_test(struct qla_host_ioctl *, INT_LOOPBACK_REQ *,
    uint16_t *);
extern int
qim_echo_test(struct qla_host_ioctl *, INT_LOOPBACK_REQ *,
    uint16_t *);
extern int
qim_get_rnid_params_mbx(scsi_qla_host_t *, dma_addr_t, size_t, uint16_t *);
extern int
qim_set_rnid_params_mbx(scsi_qla_host_t *, dma_addr_t, size_t, uint16_t *);


#endif /* ifndef __QIM_MBX_H__ */



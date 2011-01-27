#ifndef __QIM_DEF_H__
#define __QIM_DEF_H__

#define CONFIG_SCSI_QLA21XX	1
#define CONFIG_SCSI_QLA22XX	1
#define CONFIG_SCSI_QLA24XX	1
#define CONFIG_SCSI_QLA25XX	1
#define CONFIG_SCSI_QLA2300	1
#define CONFIG_SCSI_QLA2322	1
#define CONFIG_SCSI_QLA6312	1

#include "qla_def.h"

extern struct list_head **qim_hostlist_ptr;
extern rwlock_t **qim_hostlist_lock_ptr;
extern rwlock_t qim_haioctl_list_lock;
extern struct list_head qim_haioctl_list;

#ifndef WWN_SIZE	
#define WWN_SIZE		8	/* Size of WWPN, & WWNN */
#endif

#ifndef MAX_STR_SIZE
#define MAX_STR_SIZE		80
#endif

#ifndef MAX_FIBRE_DEVICES
#define MAX_FIBRE_DEVICES	512
#endif

#ifndef MAX_FIBRE_LUNS
#define MAX_FIBRE_LUNS  	256
#endif

#ifndef MAX_RSCN_COUNT
#define	MAX_RSCN_COUNT		32
#endif

#ifndef MAX_HOST_COUNT
#define	MAX_HOST_COUNT		16
#endif

#ifndef FALSE
#define FALSE			0
#endif

#ifndef TRUE
#define TRUE			1
#endif

#define	QIM_SUCCESS		0
#define	QIM_FAILED		1

// Inbound or Outbound tranfer of data
#define QLA2X00_UNKNOWN  0
#define QLA2X00_READ	1
#define QLA2X00_WRITE	2


struct hba_ioctl {
	/* Ioctl cmd serialization */
	struct semaphore	access_sem;

	/* Passthru cmd/completion */
	struct semaphore	cmpl_sem;
	struct timer_list	cmpl_timer;
	uint8_t		ioctl_tov;
	uint8_t		SCSIPT_InProgress;
	uint8_t		MSIOCB_InProgress;

	os_tgt_t	*ioctl_tq;
	os_lun_t	*ioctl_lq;

#if 0
/* RLU: this need to be handled later */
	/* AEN queue */
	void		*aen_tracking_queue;/* points to async events buffer */
	uint8_t		aen_q_head;	/* index to the current head of q */
	uint8_t		aen_q_tail;	/* index to the current tail of q */
#endif

	/* Misc. */
	uint32_t	flags;
#define	IOCTL_OPEN			BIT_0
#define	IOCTL_AEN_TRACKING_ENABLE	BIT_1
	uint8_t		*scrap_mem;	/* per ha scrap buf for ioctl usage */
	uint32_t	scrap_mem_size; /* total size */
	uint32_t	scrap_mem_used; /* portion used */
};

struct qla_host_ioctl {
	struct list_head		list;

	unsigned long			host_no;
	unsigned long			instance;
	uint8_t				node_name[WWN_SIZE];
	uint8_t				port_name[WWN_SIZE];

	uint8_t				drv_ver_str[MAX_STR_SIZE];
	uint8_t				drv_major;
	uint8_t				drv_minor;
	uint8_t				drv_patch;
	uint8_t				drv_beta;

	struct scsi_qla_host		*dr_data;

	struct hba_ioctl		*ioctl;

	void				*ioctl_mem;
	dma_addr_t			ioctl_mem_phys;
	uint32_t			ioctl_mem_size;

	struct scsi_cmnd		*ioctl_err_cmd;

	/* PCI expansion ROM image information. */
	unsigned long			code_types;
#define ROM_CODE_TYPE_BIOS	0
#define ROM_CODE_TYPE_FCODE	1
#define ROM_CODE_TYPE_EFI	3

	uint8_t				bios_revision[2];
	uint8_t				efi_revision[2];
	uint8_t				fcode_revision[16];
	uint32_t			fw_revision[4];

	/* Needed for BEACON */
	uint8_t				beacon_blink_led;
 	uint8_t				beacon_color_state;
#define QLA_LED_GRN_ON		0x01
#define QLA_LED_YLW_ON		0x02
#define QLA_LED_ABR_ON		0x04
#define QLA_LED_ALL_ON		0x07	/* yellow, green, amber */
#define QLA_LED_RGA_ON		0x07	/* isp2322: red, green, amber */

};

#endif /* ifndef __QIM_DEF_H__ */


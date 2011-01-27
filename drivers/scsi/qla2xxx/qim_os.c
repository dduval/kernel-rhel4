#include "qim_def.h"
#include "qim_sup.h"
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#if defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)
#include "qim_32ioctl.h"
#endif


/* Restrict compilation to 2.6.0 or greater */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#error "This module does not support kernel versions earlier than 2.6.0"
#endif

#define	QAPIMOD_VERSION_STR	"v1.0.03"
#define	QAPIMOD_VER_MAJOR	0
#define	QAPIMOD_VER_MINOR	0
#define	QAPIMOD_VER_PATCH	1
#define	QAPIMOD_VER_BETA	2

LIST_HEAD(qim_haioctl_list);
rwlock_t qim_haioctl_list_lock = RW_LOCK_UNLOCKED;
atomic_t qim_open_cnt = ATOMIC_INIT(0);


struct list_head **qim_hostlist_ptr = NULL;
rwlock_t **qim_hostlist_lock_ptr = NULL;

extern struct list_head *qla2xxx_hostlist_ptr;
extern rwlock_t *qla2xxx_hostlist_lock_ptr;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,12)
static struct class *qim_class;
#else
static struct class_simple *qim_class;
#endif
static int qim_major;

/* extern functions */
extern int
qim_send_ioctl(struct scsi_device *, int, void *);

extern int
qim_alloc_ioctl_mem(struct qla_host_ioctl *);
extern void
qim_free_ioctl_mem(struct qla_host_ioctl *);

extern void
qim_fo_init_params(void);


/* This function is called when a new ha is first discovered. */
static void
qim_init_drvr_data(struct scsi_qla_host *drvr_ha,
    struct qla_host_ioctl *host_ioctl, uint8_t *ptmp_mem)
{
	int		status;
	uint32_t	cnt;
	unsigned long	flags;
	struct device_reg_2xxx __iomem *reg = &drvr_ha->iobase->isp;


	host_ioctl->host_no = drvr_ha->host_no;
	host_ioctl->instance = drvr_ha->instance;
	memcpy(host_ioctl->node_name, drvr_ha->node_name, WWN_SIZE);
	memcpy(host_ioctl->port_name, drvr_ha->port_name, WWN_SIZE);
	host_ioctl->dr_data = drvr_ha;

	/* temp code: assign max value for now.  */
	strcpy(host_ioctl->drv_ver_str, drvr_ha->driver_verstr);
	host_ioctl->drv_major = drvr_ha->driver_version[0];
	host_ioctl->drv_minor = drvr_ha->driver_version[1];
	host_ioctl->drv_patch = drvr_ha->driver_version[2];
	host_ioctl->drv_beta = drvr_ha->driver_version[3];

	DEBUG9(printk("%s(%ld): going to read flash version.\n",
	    __func__, drvr_ha->host_no);)

	/* Get PCI expansion ROM image information. */
	qim_suspend_all_target(drvr_ha);

	/* wait for big hammer to complete if it fails */
	status = qim_cmd_wait(drvr_ha);

	if (status)
		return;

	/* Dont process mailbox cmd until flash operation is done */
	set_bit(MBX_UPDATE_FLASH_ACTIVE, &drvr_ha->mbx_cmd_flags);

	qim_disable_intrs(drvr_ha);

	/* Pause RISC. */
	if (!IS_FWI2_CAPABLE(drvr_ha)) {
		spin_lock_irqsave(&drvr_ha->hardware_lock, flags);
		WRT_REG_WORD(&reg->hccr, HCCR_PAUSE_RISC);
		RD_REG_WORD(&reg->hccr);
		if (IS_QLA2100(drvr_ha) || IS_QLA2200(drvr_ha) ||
		    IS_QLA2300(drvr_ha)) {
			for (cnt = 0; cnt < 30000; cnt++) {
				if ((RD_REG_WORD(&reg->hccr) &
				    HCCR_RISC_PAUSE) != 0)
					break;
				udelay(100);
			}
		} else {
			udelay(10);
		}
		spin_unlock_irqrestore(&drvr_ha->hardware_lock, flags);
	}

	qim_get_flash_version(host_ioctl, ptmp_mem);

	/* Schedule DPC to restart the RISC */
	if (!IS_FWI2_CAPABLE(drvr_ha)) {
		set_bit(ISP_ABORT_NEEDED, &drvr_ha->dpc_flags);
		up(drvr_ha->dpc_wait);
		qim_wait_for_hba_online(drvr_ha);
	} else {
		qim_enable_intrs(drvr_ha);
	}

	clear_bit(MBX_UPDATE_FLASH_ACTIVE, &drvr_ha->mbx_cmd_flags);
	
	qim_unsuspend_all_target(drvr_ha);

	DEBUG9(printk("%s(%ld): exiting.\n",
	    __func__, drvr_ha->host_no);)

}

static int
qim_rescan_hostlist(void)
{
	int			ret = 0;
	uint8_t			found;
	uint8_t			*ptmp_mem;
	struct list_head	*hal;
	struct list_head	*ioctll;
	struct qla_host_ioctl	*tmp_haioctl;
	struct scsi_qla_host	*drvr_ha;


	read_lock(*qim_hostlist_lock_ptr);
	DEBUG9(printk("qim_rescan_hostlist: got hostlist lock.\n");)

	/* allocate some memory for use. */
	if ((ptmp_mem = vmalloc(sizeof(request_t))) == NULL) {
		/* memory error */
		return (-ENOMEM);
	}

	/* Allocate our host_ioctl list */
	write_lock(&qim_haioctl_list_lock);
	list_for_each(hal, *qim_hostlist_ptr) {
		drvr_ha = list_entry(hal, struct scsi_qla_host, list);
		found = FALSE;
		list_for_each(ioctll, &qim_haioctl_list) {
			tmp_haioctl = list_entry(ioctll, struct qla_host_ioctl,
			    list);
			if (tmp_haioctl->host_no == drvr_ha->host_no) {
				if (tmp_haioctl->instance ==
				    drvr_ha->instance &&
				    memcmp(tmp_haioctl->port_name,
				    drvr_ha->port_name, WWN_SIZE) == 0) {
					/* found match */
					found = TRUE;
				} else {
					/* something changed? remove this one */
					list_del(&tmp_haioctl->list);
					/* LSC: 3/24, also free up the IOCTL memory */
					qim_free_ioctl_mem(tmp_haioctl);                
					vfree(tmp_haioctl);
				}

				break;
			}
		}

		if (!found) {
			/* this is a new ha not found on our list. */
			if ((tmp_haioctl = vmalloc(sizeof(struct
			    qla_host_ioctl)))) {
				memset(tmp_haioctl, 0,
				    sizeof(struct qla_host_ioctl));
				memset(ptmp_mem, 0, sizeof(request_t));

				list_add_tail(&tmp_haioctl->list,
				    &qim_haioctl_list);
				qim_init_drvr_data(drvr_ha, tmp_haioctl,
				    ptmp_mem);
				/* LSC: 3/24 Here means new HBA found, allocate memory
				 * for the new HBA 
				 */
				if (qim_alloc_ioctl_mem(tmp_haioctl) != QIM_SUCCESS) {
                                        
					DEBUG9(printk("qim_rescan_hostlist: Out of memory, "
					    "while allocating memory for newly found HBA.\n");)
					ret = -ENOMEM;
					break;
				}
			} else {
				/* memory error */
				ret = -ENOMEM;
				break;
			}
		}
	}
	write_unlock(&qim_haioctl_list_lock);

	DEBUG9(printk("qim_rescan_hostlist: going to unlock.\n");)
	read_unlock(*qim_hostlist_lock_ptr);

	vfree(ptmp_mem);

	return (ret);
}

static int 
qim_open(struct inode *inode, struct file *fp)
{

	DEBUG9(printk("qim_open - entered.\n");)

	if (atomic_read(&qim_open_cnt) == 0) {
		/* first open. initialize some stuff. */

		/*
		DEBUG9(printk("qla_apimod: qim_open_cnt=%d.\n",
		    qim_open_cnt);)
		*/

		qim_hostlist_lock_ptr = 
		    (rwlock_t **) symbol_get(qla2xxx_hostlist_lock_ptr);

		if (qim_hostlist_lock_ptr == NULL) {
			DEBUG9(printk("qim_open: qla2xxx driver not "
			    "loaded.\n");)
			return -ENODEV;
		}

		DEBUG9(printk("qim_open: got hostlist lock pointer %p, %p.\n",
		    qim_hostlist_lock_ptr, *qim_hostlist_lock_ptr);)

		qim_hostlist_ptr = 
		    (struct list_head **) symbol_get(qla2xxx_hostlist_ptr);

		if (*qim_hostlist_ptr == NULL) {
			DEBUG9(printk("qim_open: qla2xxx driver not "
			    "loaded.\n");)
			return -ENODEV;
		}
		atomic_inc(&qim_open_cnt);

	} else {
		/*
		DEBUG9(printk(
		    "qim_open: not first open. qim_open_cnt=%d.\n",
		    qim_open_cnt);)
		*/
	}

	if (qim_rescan_hostlist() != 0) {
		DEBUG9(printk("qim_open: memory error.\n");)
		return -ENOMEM;
	}

	DEBUG9(printk("qim_open: got hostlist pointer %p.\n",
	    qim_hostlist_ptr);)

	return 0;
}

static int 
qim_release(struct inode *inode, struct file *fp)
{
	DEBUG9(printk("qla_apimod: qim_release - entered.\n");)

	if (atomic_dec_and_test(&qim_open_cnt)) {
		/* last close. clean up */
		/*
		DEBUG9(printk("qla_apimod: last close. qim_open_cnt=%d.\n",
		    qim_open_cnt);)
		*/
		symbol_put(qla2xxx_hostlist_ptr);
		symbol_put(qla2xxx_hostlist_lock_ptr);
	} else {
		/*
		DEBUG9(printk("qla_apimod: not last close. qim_open_cnt=%d.\n",
		    qim_open_cnt);)
		*/
	}

	return 0;
}

static int 
qim_ioctl(struct inode *inode, struct file *fp, unsigned int cmd,
    unsigned long arg) 
{
	DEBUG9(printk("qim_ioctl - got cmd %x arg %lx.\n",
	    cmd, arg);)
	return (qim_send_ioctl(NULL, (int)cmd, (void*)arg));
}

static struct file_operations qim_fops = {
	.owner = THIS_MODULE,
	.open = qim_open,
	.release = qim_release,
	.ioctl = qim_ioctl,
};

int 
qim_ioctl_initialize(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,12)
	qim_class = class_create(THIS_MODULE, "qla2xxx");
#else
	qim_class = class_simple_create(THIS_MODULE, "qla2xxx");
#endif
	if (IS_ERR(qim_class)) {
		DEBUG9(printk("%s(): Unable to sysfs class for qla2xxx.\n",
		    __func__);)

		qim_class = NULL;
		return 1;

	}

	DEBUG9(printk("%s(): done class_create.\n", __func__);)

	qim_major = register_chrdev(0, "qla2xxx", &qim_fops);
	if (qim_major < 0) {
		DEBUG9(printk("%s(): Unable to register CHAR device (%d)\n",
		    __func__, qim_major);)

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,12)
		class_destroy(qim_class);
#else
		class_simple_destroy(qim_class);
#endif
		qim_class = NULL;

		return qim_major;
	}

	DEBUG9(printk("%s(): done register_chrdev.\n", __func__);)

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,12)
	class_device_create(qim_class, MKDEV(qim_major, 0), NULL,
	    "qla2xxx");
#else
	class_simple_device_add(qim_class, MKDEV(qim_major, 0), NULL,
	    "qla2xxx");
#endif

#if defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)
	apidev_init_32ioctl_reg();
#endif

	DEBUG9(printk("qim_ioctl_init: exiting.\n");)

	return 0;
}

int
qim_ioctl_release(void)
{
	if (!qim_class)
		return 1;

#if defined(CONFIG_COMPAT) && !defined(CONFIG_IA64)
	apidev_cleanup_32ioctl_unreg();
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,12)
	class_device_destroy(qim_class, MKDEV(qim_major, 0));
#else
	class_simple_device_remove(MKDEV(qim_major, 0));
#endif

	unregister_chrdev(qim_major, "qla2xxx");

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,12)
	class_destroy(qim_class);
#else
	class_simple_destroy(qim_class);
#endif

	qim_class = NULL;

	return 0;
}

static void
qim_ioctl_init(void)
{
	struct list_head	*hal;
	struct qla_host_ioctl	*tmp_ha_ioctl;

	DEBUG9(printk("qim_ioctl_init: entered.\n");)
	qim_ioctl_initialize();

	list_for_each(hal, &qim_haioctl_list) {
		tmp_ha_ioctl = list_entry(hal, struct qla_host_ioctl, list);
		qim_alloc_ioctl_mem(tmp_ha_ioctl);
	}

	DEBUG9(printk("qim_ioctl_init: exiting.\n");)
}

static void
qim_ioctl_exit(void)
{
	struct list_head	*hal;
	struct qla_host_ioctl	*tmp_ha_ioctl;

	DEBUG9(printk("qim_ioctl_exit: entered.\n");)
	list_for_each(hal, &qim_haioctl_list) {
		tmp_ha_ioctl = list_entry(hal, struct qla_host_ioctl, list);
		qim_free_ioctl_mem(tmp_ha_ioctl);
	}

	qim_ioctl_release();
	DEBUG9(printk("qim_ioctl_exit: exiting.\n");)

}

static int
qim_init(void)
{
	uint8_t			*ptmp_mem;
	struct list_head	*hal = NULL;
	struct qla_host_ioctl	*tmp_haioctl = NULL;
	struct scsi_qla_host	*drvr_ha;


	DEBUG9(printk("qim_init: entered.\n");)

	qim_hostlist_lock_ptr = 
	    (rwlock_t **) symbol_get(qla2xxx_hostlist_lock_ptr);

	if (qim_hostlist_lock_ptr == NULL) {
		DEBUG9(printk("apimod: qla2xxx driver not loaded.");)
		return -ENODEV;
	}

	DEBUG9(printk("qim_init: got hostlist lock pointer %p, %p.\n",
	    qim_hostlist_lock_ptr, *qim_hostlist_lock_ptr);)

	read_lock(*qim_hostlist_lock_ptr);
	DEBUG9(printk("qim_init: got hostlist lock.\n");)

	qim_hostlist_ptr = 
	    (struct list_head **) symbol_get(qla2xxx_hostlist_ptr);

	if (*qim_hostlist_ptr == NULL) {
		read_unlock(*qim_hostlist_lock_ptr);
		DEBUG9_10(printk("apimod: qla2xxx driver not loaded.");)
		return -ENODEV;
	}

	DEBUG9(printk("qim_init: got hostlist pointer %p, %p.\n",
	    qim_hostlist_ptr, *qim_hostlist_ptr);)

	/* allocate some memory for use. */
	if ((ptmp_mem = vmalloc(sizeof(request_t))) == NULL) {
		/* memory error */
		return (-ENOMEM);
	}

	/* Allocate our host_ioctl list */
	write_lock(&qim_haioctl_list_lock);
	list_for_each(hal, *qim_hostlist_ptr) {
		drvr_ha = list_entry(hal, struct scsi_qla_host, list);
		if ((tmp_haioctl = vmalloc(sizeof(struct qla_host_ioctl)))) {
			DEBUG9(printk("qim_init: got tmp_haioctl=%p.\n",
			    tmp_haioctl);)
			memset(tmp_haioctl, 0, sizeof(struct qla_host_ioctl));
			memset(ptmp_mem, 0, sizeof(request_t));

			list_add_tail(&tmp_haioctl->list,
			    &qim_haioctl_list);
			qim_init_drvr_data(drvr_ha, tmp_haioctl, ptmp_mem);
		}
	}
	write_unlock(&qim_haioctl_list_lock);
	vfree(ptmp_mem);

	qim_ioctl_init();
	qim_fo_init_params();

	DEBUG9(printk("qim_init: going to put back hostlist ref.\n");)

	symbol_put(qla2xxx_hostlist_ptr);

	DEBUG9(printk("qim_init: going to unlock.\n");)

	read_unlock(*qim_hostlist_lock_ptr);

	symbol_put(qla2xxx_hostlist_lock_ptr);

	DEBUG9(printk("qim_init: exiting.\n");)

	return 0;
}

static void __exit
qim_exit(void)
{
	struct list_head	*hal = NULL;
	struct qla_host_ioctl	*tmp_haioctl;

	DEBUG9(printk("qim_exit: entered.\n");)

	qim_ioctl_exit();

	DEBUG9(printk("qim_exit: done ioctl_exit.\n");)

	/* remove/free the list */
	write_lock(&qim_haioctl_list_lock);
	/* original list_for_each code:
	for (pos = (head)->next; prefetch(pos->next), pos != (head);
	pos = pos->next)
	*/
	for (hal = (&qim_haioctl_list)->next; hal !=
	    (&qim_haioctl_list); ) {
		DEBUG9(printk("qim_exit: going to get next tmp_haioctl.\n");)
		tmp_haioctl = list_entry(hal, struct qla_host_ioctl, list);
		DEBUG9(printk("qim_exit: going to del &tmp_haioctl->list=%p.\n",
		    &tmp_haioctl->list);)
		hal = hal->next;
		list_del(&tmp_haioctl->list);
		DEBUG9(printk("qim_exit: going to free tmp_haioctl=%p.\n",
		    tmp_haioctl);)
		vfree(tmp_haioctl);
		DEBUG9(printk("qim_exit: freed tmp_haioctl.\n");)
	}
	write_unlock(&qim_haioctl_list_lock);

	DEBUG9(printk("qim_exit: exiting.\n");)

}

module_init(qim_init);
module_exit(qim_exit);

MODULE_AUTHOR("QLogic Corporation");
MODULE_DESCRIPTION("QLogic FC Driver IOCTL Module");
MODULE_VERSION(QAPIMOD_VERSION_STR);
MODULE_LICENSE("GPL");

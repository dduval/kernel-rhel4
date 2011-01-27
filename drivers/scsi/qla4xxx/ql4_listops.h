/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2006 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */

/* Management functions for various lists */

/*************************************/

static inline void
sp_put( scsi_qla_host_t *ha, srb_t *sp)
{
	if (atomic_read(&sp->ref_count) == 0) {
		QL4PRINT(QLP2, printk("scsi%d: %s: sp->ref_count zero\n",
				      ha->host_no, __func__));
		DEBUG2(BUG());
		return;
	}

	if (!atomic_dec_and_test(&sp->ref_count)) {
		return;
	}
	
	qla4xxx_complete_request(ha, sp);
}

static inline void
sp_get( scsi_qla_host_t *ha, srb_t *sp)
{
	atomic_inc(&sp->ref_count);

	if (atomic_read(&sp->ref_count) > 2) {
		QL4PRINT(QLP2, printk("scsi%d: %s: sp->ref_count greater than 2\n",
				      ha->host_no, __func__));
		DEBUG2(BUG());
		return;
	}
}

static inline void
__add_to_retry_srb_q(scsi_qla_host_t *ha, srb_t *srb)
{
	QL4PRINT(QLP8, printk("scsi%d: %s: ha %d, srb = %p\n",
			      ha->host_no, __func__, ha->instance, srb));
	list_add_tail(&srb->list_entry, &ha->retry_srb_q);
	srb->state = SRB_RETRY_STATE;
	ha->retry_srb_q_count++;
	srb->ha = ha;
}

static inline void
__del_from_retry_srb_q(scsi_qla_host_t *ha, srb_t *srb)
{
	QL4PRINT(QLP8, printk("scsi%d: %s: ha %d, srb = %p\n",
			      ha->host_no, __func__, ha->instance, srb));
	list_del_init(&srb->list_entry);
	srb->state = SRB_NO_QUEUE_STATE;
	ha->retry_srb_q_count--;
}

/*************************************/

static inline void
__add_to_done_srb_q(scsi_qla_host_t *ha, srb_t *srb)
{
	QL4PRINT(QLP8, printk("scsi%d: %s: ha %d, srb = %p\n",
			      ha->host_no, __func__, ha->instance, srb));
	list_add_tail(&srb->list_entry, &ha->done_srb_q);
	srb->state = SRB_DONE_STATE;
	ha->done_srb_q_count++;
	srb->ha = ha;
}

static inline void
__del_from_done_srb_q(scsi_qla_host_t *ha, srb_t *srb)
{
	QL4PRINT(QLP8, printk("scsi%d: %s: ha %d, srb = %p\n",
			      ha->host_no, __func__, ha->instance, srb));
	list_del_init(&srb->list_entry);
	srb->state = SRB_NO_QUEUE_STATE;
	ha->done_srb_q_count--;
}

static inline srb_t *__del_from_done_srb_q_head(scsi_qla_host_t *ha)
{
	struct list_head *ptr;
	srb_t *srb = NULL;

	if (!list_empty(&ha->done_srb_q)) {
		/* Remove list entry from head of queue */
		ptr = ha->done_srb_q.next;
		list_del_init(ptr);

		/* Return pointer to srb structure */
		srb = list_entry(ptr, srb_t, list_entry);
		srb->state = SRB_NO_QUEUE_STATE;
		ha->done_srb_q_count--;
	}
	QL4PRINT(QLP8, printk("scsi%d: %s: ha %d, srb = %p\n",
			      ha->host_no, __func__, ha->instance, srb));

	return(srb);
}

/*************************************/

static inline void
__add_to_free_srb_q(scsi_qla_host_t *ha, srb_t *srb)
{
	DEBUG(printk("scsi%d: %s: instance %d, srb = %p\n",
			      ha->host_no, __func__, ha->instance,
			      srb ));

	atomic_set(&srb->ref_count, 0);
	list_add_tail(&srb->list_entry, &ha->free_srb_q);
	ha->free_srb_q_count++;
	srb->state = SRB_FREE_STATE;
}

static inline void __del_from_free_srb_q(scsi_qla_host_t *ha, srb_t *srb)
{

	DEBUG(printk("scsi%d: %s: instance %d, srb = %p\n",
			      ha->host_no, __func__, ha->instance,
			      srb ));
	list_del_init(&srb->list_entry);
	atomic_set(&srb->ref_count, 1);
	srb->state = SRB_NO_QUEUE_STATE;
	ha->free_srb_q_count--;
}

static inline srb_t *__del_from_free_srb_q_head(scsi_qla_host_t *ha)
{
	struct list_head *ptr;
	srb_t *srb = NULL;

	if (!list_empty(&ha->free_srb_q)) {
		/* Remove list entry from head of queue */
		ptr = ha->free_srb_q.next;
		list_del_init(ptr);

		/* Return pointer to srb structure */
		srb = list_entry(ptr, srb_t, list_entry);
		atomic_set(&srb->ref_count, 1);
		srb->state = SRB_NO_QUEUE_STATE;
		ha->free_srb_q_count--;
	}
	DEBUG(printk("scsi%d: %s: instance %d, srb = %p\n",
			      ha->host_no, __func__, ha->instance,
			      srb ));

	return(srb);
}


/*************************************/

static inline void
add_to_retry_srb_q(scsi_qla_host_t *ha, srb_t *srb)
{
	unsigned long flags;

	spin_lock_irqsave(&ha->list_lock, flags);
	__add_to_retry_srb_q(ha ,srb);
	spin_unlock_irqrestore(&ha->list_lock, flags);
}

static inline void
del_from_retry_srb_q(scsi_qla_host_t *ha, srb_t *srb)
{
	unsigned long flags;

	spin_lock_irqsave(&ha->list_lock, flags);
	__del_from_retry_srb_q(ha ,srb);
	spin_unlock_irqrestore(&ha->list_lock, flags);
}

/*************************************/

static inline void
add_to_done_srb_q(scsi_qla_host_t *ha, srb_t *srb)
{
	unsigned long flags;

	spin_lock_irqsave(&ha->list_lock, flags);
	__add_to_done_srb_q(ha ,srb);
	spin_unlock_irqrestore(&ha->list_lock, flags);
}

static inline void
del_from_done_srb_q(scsi_qla_host_t *ha, srb_t *srb)
{
	unsigned long flags;

	spin_lock_irqsave(&ha->list_lock, flags);
	__del_from_done_srb_q(ha ,srb);
	spin_unlock_irqrestore(&ha->list_lock, flags);
}

static inline srb_t *
del_from_done_srb_q_head(scsi_qla_host_t *ha)
{
	unsigned long flags;
	srb_t *srb;

	spin_lock_irqsave(&ha->list_lock, flags);
	srb = __del_from_done_srb_q_head(ha);
	spin_unlock_irqrestore(&ha->list_lock, flags);
	return(srb);
}

/*************************************/

static inline void
add_to_free_srb_q(scsi_qla_host_t *ha, srb_t *srb)
{
	unsigned long flags;

	spin_lock_irqsave(&ha->list_lock, flags);
	__add_to_free_srb_q(ha ,srb);
	spin_unlock_irqrestore(&ha->list_lock, flags);
}

static inline srb_t *
del_from_free_srb_q_head(scsi_qla_host_t *ha)
{
	unsigned long flags;
	srb_t *srb;

	spin_lock_irqsave(&ha->list_lock, flags);
	srb = __del_from_free_srb_q_head(ha);
	spin_unlock_irqrestore(&ha->list_lock, flags);

	return(srb);
}

/*************************************/

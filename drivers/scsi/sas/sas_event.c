/*
 * Serial Attached SCSI (SAS) Event processing
 *
 * Copyright (C) 2005 Adaptec, Inc.  All rights reserved.
 * Copyright (C) 2005 Luben Tuikov <luben_tuikov@adaptec.com>
 *
 * This file is licensed under GPLv2.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * $Id: //depot/sas-class/sas_event.c#26 $
 */

/**
 * Implementation Of Priority Queue Without Duplication
 * Luben Tuikov 2005/07/11
 *
 * The SAS class implements priority queue without duplication for
 * handling ha/port/phy/discover events.  That is, we want to process
 * the last N unique/non-duplicating events, in the order they arrived.
 *
 * The requirement is that insertion is O(1), and ordered removal is O(1).
 *
 * Suppose events are identified by integers.  Then what is required
 * is that for a given sequence of any random integers R, to find a
 * sorted sequence E, where
 *     a) |E| <= |R|.  If the number of types of events is bounded,
 *        then E is also bounded by that number, from b).
 *     b) For all i and k, E[i] != E[k], except when i == k,
 *        this gives us uniqueness/non duplication.
 *     c) For all i < k, Order(E[i]) < Order(E[k]), this gives us
 *        ordering.
 *     d) If T(R) = E, then O(T) <= |R|, this ensures that insertion
 *        is O(1), and ordered removal is O(1) trivially, since we
 *        remove at the head of E.
 *
 * Example:
 * If R = {4, 5, 1, 2, 5, 3, 3, 4, 4, 3, 1}, then
 *    E = {2, 5, 4, 3, 1}.
 *
 * The algorithm, T, makes use of an array of list elements, indexed
 * by event type, and an event list head which is a linked list of the
 * elements of the array.  When the next event arrives, we index the
 * array by the event, and add that event to the tail of the event
 * list head, deleting it from its previous list position (if it had
 * one).
 *
 * Clearly insertion is O(1).
 *
 * E is given by the elements of the event list, traversed from head
 * to tail.
 */

#include <linux/sched.h>

#include <scsi/scsi_host.h>
#include "sas_internal.h"
#include "sas_dump.h"
#include <scsi/sas/sas_discover.h>

static void sas_process_phy_event(struct sas_phy *phy)
{
	unsigned long flags;
	struct sas_ha_struct *sas_ha = phy->ha;
	enum phy_event phy_event;

	spin_lock_irqsave(&sas_ha->event_lock, flags);
	while (!list_empty(&phy->phy_event_list)) {
		struct list_head *head = phy->phy_event_list.next;
		phy_event = container_of(head, struct sas_event, el)->event;
		list_del_init(head);
		spin_unlock_irqrestore(&sas_ha->event_lock, flags);

		sas_dprint_phye(phy->id, phy_event);

		switch(phy_event) {
		case PHYE_LOSS_OF_SIGNAL:
			sas_phye_loss_of_signal(phy);
			break;
		case PHYE_OOB_DONE:
			sas_phye_oob_done(phy);
			break;
		case PHYE_OOB_ERROR:
			sas_phye_oob_error(phy);
			break;
		case PHYE_SPINUP_HOLD:
			sas_phye_spinup_hold(phy);
			break;
		}
		spin_lock_irqsave(&sas_ha->event_lock, flags);
	}
	/* Clear the bit in case we received events in due time. */
	sas_ha->phye_mask &= ~(1 << phy->id);
	spin_unlock_irqrestore(&sas_ha->event_lock, flags);
}

static void sas_process_port_event(struct sas_phy *phy)
{
	unsigned long flags;
	struct sas_ha_struct *sas_ha = phy->ha;
	enum port_event port_event;

	spin_lock_irqsave(&sas_ha->event_lock, flags);
	while (!list_empty(&phy->port_event_list)) {
		struct list_head *head = phy->port_event_list.next;
		port_event = container_of(head, struct sas_event, el)->event;
		list_del_init(head);
		spin_unlock_irqrestore(&sas_ha->event_lock, flags);

		sas_dprint_porte(phy->id, port_event);

		switch (port_event) {
		case PORTE_BYTES_DMAED:
			sas_porte_bytes_dmaed(phy);
			break;
		case PORTE_BROADCAST_RCVD:
			sas_porte_broadcast_rcvd(phy);
			break;
		case PORTE_LINK_RESET_ERR:
			sas_porte_link_reset_err(phy);
			break;
		case PORTE_TIMER_EVENT:
			sas_porte_timer_event(phy);
			break;
		case PORTE_HARD_RESET:
			sas_porte_hard_reset(phy);
			break;
		}
		spin_lock_irqsave(&sas_ha->event_lock, flags);
	}
	/* Clear the bit in case we received events in due time. */
	sas_ha->porte_mask &= ~(1 << phy->id);
	spin_unlock_irqrestore(&sas_ha->event_lock, flags);
}

static void sas_process_ha_event(struct sas_ha_struct *sas_ha)
{
	unsigned long flags;
	enum ha_event ha_event;

	spin_lock_irqsave(&sas_ha->event_lock, flags);
	while (!list_empty(&sas_ha->ha_event_list)) {
		struct list_head *head = sas_ha->ha_event_list.next;
		ha_event = container_of(head, struct sas_event, el)->event;
		list_del_init(head);
		spin_unlock_irqrestore(&sas_ha->event_lock, flags);

		sas_dprint_hae(sas_ha, ha_event);

		switch (ha_event) {
		case HAE_RESET:
			sas_hae_reset(sas_ha);
			break;
		}
		spin_lock_irqsave(&sas_ha->event_lock, flags);
	}
	spin_unlock_irqrestore(&sas_ha->event_lock, flags);
}

static void sas_process_events(struct sas_ha_struct *sas_ha)
{
	unsigned long flags;
	u32 porte_mask, phye_mask;
	int p;

	spin_lock_irqsave(&sas_ha->event_lock, flags);
	phye_mask = sas_ha->phye_mask;
	sas_ha->phye_mask = 0;
	spin_unlock_irqrestore(&sas_ha->event_lock, flags);

	for (p = 0; phye_mask != 0; phye_mask >>= 1, p++)
		if (phye_mask & 01)
			sas_process_phy_event(sas_ha->sas_phy[p]);

	spin_lock_irqsave(&sas_ha->event_lock, flags);
	porte_mask = sas_ha->porte_mask;
	sas_ha->porte_mask = 0;
	spin_unlock_irqrestore(&sas_ha->event_lock, flags);

	for (p = 0; porte_mask != 0; porte_mask >>= 1, p++)
		if (porte_mask & 01)
			sas_process_port_event(sas_ha->sas_phy[p]);

	sas_process_ha_event(sas_ha);
}

static void notify_ha_event(struct sas_ha_struct *sas_ha, enum ha_event event)
{
	unsigned long flags;

	spin_lock_irqsave(&sas_ha->event_lock, flags);
	list_move_tail(&sas_ha->ha_events[event].el, &sas_ha->ha_event_list);
	up(&sas_ha->event_sema);
	spin_unlock_irqrestore(&sas_ha->event_lock, flags);
}

static void notify_port_event(struct sas_phy *phy, enum port_event event)
{
	struct sas_ha_struct *ha = phy->ha;
	unsigned long flags;

	spin_lock_irqsave(&ha->event_lock, flags);
	list_move_tail(&phy->port_events[event].el, &phy->port_event_list);
	ha->porte_mask |= (1 << phy->id);
	up(&ha->event_sema);
	spin_unlock_irqrestore(&ha->event_lock, flags);
}

static void notify_phy_event(struct sas_phy *phy, enum phy_event event)
{
	struct sas_ha_struct *ha = phy->ha;
	unsigned long flags;

	spin_lock_irqsave(&ha->event_lock, flags);
	list_move_tail(&phy->phy_events[event].el, &phy->phy_event_list);
	ha->phye_mask |= (1 << phy->id);
	up(&ha->event_sema);
	spin_unlock_irqrestore(&ha->event_lock, flags);
}

static DECLARE_COMPLETION(event_th_comp);

static int sas_event_thread(void *_sas_ha)
{
	struct sas_ha_struct *sas_ha = _sas_ha;

	daemonize("sas_event_%d", sas_ha->core.shost->host_no);
	current->flags |= PF_NOFREEZE;

	complete(&event_th_comp);

	while (1) {
		down_interruptible(&sas_ha->event_sema);
		if (sas_ha->event_thread_kill)
			break;
		sas_process_events(sas_ha);
	}

	complete(&event_th_comp);

	return 0;
}

int sas_start_event_thread(struct sas_ha_struct *sas_ha)
{
	int i;

	init_MUTEX_LOCKED(&sas_ha->event_sema);
	sas_ha->event_thread_kill = 0;

	spin_lock_init(&sas_ha->event_lock);
	INIT_LIST_HEAD(&sas_ha->ha_event_list);
	sas_ha->porte_mask = 0;
	sas_ha->phye_mask = 0;

	for (i = 0; i < HA_NUM_EVENTS; i++) {
		struct sas_event *ev = &sas_ha->ha_events[i];
		ev->event = i;
		INIT_LIST_HEAD(&ev->el);
	}

	sas_ha->notify_ha_event = notify_ha_event;
	sas_ha->notify_port_event = notify_port_event;
	sas_ha->notify_phy_event = notify_phy_event;

	i = kernel_thread(sas_event_thread, sas_ha, 0);
	if (i >= 0)
		wait_for_completion(&event_th_comp);

	return i < 0 ? i : 0;
}

void sas_kill_event_thread(struct sas_ha_struct *sas_ha)
{
	int i;

	init_completion(&event_th_comp);
	sas_ha->event_thread_kill = 1;
	up(&sas_ha->event_sema);
	wait_for_completion(&event_th_comp);

	for (i = 0; i < sas_ha->num_phys; i++)
		sas_kill_disc_thread(sas_ha->sas_port[i]);
}

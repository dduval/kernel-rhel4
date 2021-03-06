/*******************************************************************
 * This file is part of the Emulex Linux Device Driver for         *
 * Fibre Channel Host Bus Adapters.                                *
 * Copyright (C) 2003-2008 Emulex.  All rights reserved.           *
 * EMULEX and SLI are trademarks of Emulex.                        *
 * www.emulex.com                                                  *
 *                                                                 *
 * This program is free software; you can redistribute it and/or   *
 * modify it under the terms of version 2 of the GNU General       *
 * Public License as published by the Free Software Foundation.    *
 * This program is distributed in the hope that it will be useful. *
 * ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND          *
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY,  *
 * FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT, ARE      *
 * DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD *
 * TO BE LEGALLY INVALID.  See the GNU General Public License for  *
 * more details, a copy of which can be found in the file COPYING  *
 * included with this package.                                     *
 *******************************************************************/

/*
 * $Id: lpfc_crtn.h 3230 2008-11-18 21:15:25Z sf_support $
 */

#ifndef _H_LPFC_CRTN
#define _H_LPFC_CRTN

#include <linux/delay.h>
#include <linux/interrupt.h>
#include <asm/uaccess.h>

#include "lpfc_disc.h"
#include "lpfc_logmsg.h"
#include "lpfc_scsi.h"
#include "lpfc_sli.h"


void lpfc_dump_mem(struct lpfc_hba *, LPFC_MBOXQ_t *, uint16_t);
void lpfc_read_nv(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_heart_beat(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_config_async(struct lpfc_hba *, LPFC_MBOXQ_t *, uint32_t);
int lpfc_read_la(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_clear_la(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_config_link(struct lpfc_hba *, LPFC_MBOXQ_t *);
int lpfc_read_sparam(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_read_config(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_read_lnk_stat(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_set_slim(struct lpfc_hba *, LPFC_MBOXQ_t *, uint32_t, uint32_t);
int lpfc_reg_login(struct lpfc_hba *, uint32_t, uint8_t *, LPFC_MBOXQ_t *,
		   uint32_t);
void lpfc_unreg_login(struct lpfc_hba *, uint32_t, LPFC_MBOXQ_t *);
void lpfc_unreg_did(struct lpfc_hba *, uint32_t, LPFC_MBOXQ_t *);
void lpfc_init_link(struct lpfc_hba *, LPFC_MBOXQ_t *, uint32_t, uint32_t);


int lpfc_linkdown(struct lpfc_hba *);
void lpfc_mbx_cmpl_read_la(struct lpfc_hba *, LPFC_MBOXQ_t *);

void lpfc_mbx_cmpl_clear_la(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_mbx_cmpl_reg_login(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_mbx_cmpl_fabric_reg_login(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_mbx_cmpl_ns_reg_login(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_mbx_cmpl_fdmi_reg_login(struct lpfc_hba *, LPFC_MBOXQ_t *);
int lpfc_consistent_bind_save(struct lpfc_hba *, struct lpfc_bindlist *);
int lpfc_nlp_plogi(struct lpfc_hba *, struct lpfc_nodelist *);
int lpfc_nlp_adisc(struct lpfc_hba *, struct lpfc_nodelist *);
int lpfc_nlp_unmapped(struct lpfc_hba *, struct lpfc_nodelist *);
int lpfc_nlp_mapped(struct lpfc_hba *, struct lpfc_nodelist *,
		    struct lpfc_bindlist *);
int lpfc_nlp_list(struct lpfc_hba *, struct lpfc_nodelist *, int);
void lpfc_set_disctmo(struct lpfc_hba *);
int lpfc_can_disctmo(struct lpfc_hba *);
int lpfc_unreg_rpi(struct lpfc_hba *, struct lpfc_nodelist *);
int lpfc_check_sli_ndlp(struct lpfc_hba *, struct lpfc_sli_ring *,
		    struct lpfc_iocbq *, struct lpfc_nodelist *);
int lpfc_nlp_remove(struct lpfc_hba *, struct lpfc_nodelist *);
void lpfc_nlp_init(struct lpfc_hba *, struct lpfc_nodelist *, uint32_t);
struct lpfc_nodelist *lpfc_setup_disc_node(struct lpfc_hba *, uint32_t);
struct lpfc_nodelist *lpfc_setup_rscn_node(struct lpfc_hba *, uint32_t);
void lpfc_disc_list_loopmap(struct lpfc_hba *);
void lpfc_disc_start(struct lpfc_hba *);
void lpfc_disc_flush_list(struct lpfc_hba *);
void lpfc_establish_link_tmo(unsigned long);
void lpfc_disc_timeout(unsigned long);
void lpfc_scan_timeout(unsigned long);
void lpfc_linkdown_timeout(unsigned long);
struct lpfc_target *lpfc_find_target(struct lpfc_hba *, uint32_t,
			struct lpfc_nodelist *);
void lpfc_set_failmask(struct lpfc_hba *, struct lpfc_nodelist *, uint32_t,
		       uint32_t);
void lpfc_process_nodev_timeout(struct lpfc_hba *, struct lpfc_nodelist *);

struct lpfc_nodelist *lpfc_findnode_rpi(struct lpfc_hba * phba, uint16_t rpi);

int lpfc_discq_post_event(struct lpfc_hba *, void *, void *, uint32_t);
int lpfc_do_dpc(void *);
void lpfc_evt_iocb_free(struct lpfc_hba *, struct lpfc_iocbq *);
int lpfc_disc_state_machine(struct lpfc_hba *, struct lpfc_nodelist *, void *,
			    uint32_t);

uint32_t lpfc_cmpl_prli_reglogin_issue(struct lpfc_hba *,
				       struct lpfc_nodelist *, void *,
				       uint32_t);
uint32_t lpfc_cmpl_plogi_prli_issue(struct lpfc_hba *, struct lpfc_nodelist *,
				    void *, uint32_t);

int lpfc_check_sparm(struct lpfc_hba *, struct lpfc_nodelist *,
		     struct serv_parm *, uint32_t);
int lpfc_els_abort(struct lpfc_hba *, struct lpfc_nodelist * ndlp,
		   int);
int lpfc_els_abort_flogi(struct lpfc_hba *);
int lpfc_initial_flogi(struct lpfc_hba *);
void lpfc_more_plogi(struct lpfc_hba *);
struct lpfc_bindlist *lpfc_consistent_bind_get(struct lpfc_hba *, struct lpfc_nodelist *);
uint32_t lpfc_assign_binding(struct lpfc_hba *, struct lpfc_nodelist *,
			     struct lpfc_bindlist *);
int lpfc_issue_els_plogi(struct lpfc_hba *, uint32_t, uint8_t);
int lpfc_issue_els_prli(struct lpfc_hba *, struct lpfc_nodelist *, uint8_t);
int lpfc_issue_els_adisc(struct lpfc_hba *, struct lpfc_nodelist *, uint8_t);
int lpfc_issue_els_logo(struct lpfc_hba *, struct lpfc_nodelist *, uint8_t);
int lpfc_issue_els_scr(struct lpfc_hba *, uint32_t, uint8_t);
int lpfc_els_free_iocb(struct lpfc_hba *, struct lpfc_iocbq *);
int lpfc_els_rsp_acc(struct lpfc_hba *, uint32_t, struct lpfc_iocbq *,
		     struct lpfc_nodelist *, LPFC_MBOXQ_t *, uint8_t);
int lpfc_els_rsp_reject(struct lpfc_hba *, uint32_t, struct lpfc_iocbq *,
			struct lpfc_nodelist *);
int lpfc_els_rsp_adisc_acc(struct lpfc_hba *, struct lpfc_iocbq *,
			   struct lpfc_nodelist *);
int lpfc_els_rsp_prli_acc(struct lpfc_hba *, struct lpfc_iocbq *,
			  struct lpfc_nodelist *);
void lpfc_cancel_retry_delay_tmo(struct lpfc_hba *,
				 struct lpfc_nodelist *);
void lpfc_els_retry_delay(unsigned long);
void lpfc_els_retry_delay_handler(struct lpfc_nodelist *);
void lpfc_els_unsol_event(struct lpfc_hba *, struct lpfc_sli_ring *,
			  struct lpfc_iocbq *);
void lpfc_loopback_event(struct lpfc_hba *, struct lpfc_sli_ring *,
			  struct lpfc_iocbq *);
int lpfc_els_handle_rscn(struct lpfc_hba *);
int lpfc_els_flush_rscn(struct lpfc_hba *);
int lpfc_rscn_payload_check(struct lpfc_hba *, uint32_t);
void lpfc_els_flush_cmd(struct lpfc_hba *);
int lpfc_els_disc_adisc(struct lpfc_hba *);
int lpfc_els_disc_plogi(struct lpfc_hba *);
void lpfc_els_timeout(unsigned long);
void lpfc_els_timeout_handler(struct lpfc_hba *);
void lpfc_hb_timeout(unsigned long);
void lpfc_hb_timeout_handler(struct lpfc_hba *);

void lpfc_ct_unsol_event(struct lpfc_hba *, struct lpfc_sli_ring *,
			 struct lpfc_iocbq *);
int lpfc_ns_cmd(struct lpfc_hba *, struct lpfc_nodelist *, int);
int lpfc_fdmi_cmd(struct lpfc_hba *, struct lpfc_nodelist *, int);
void lpfc_fdmi_tmo(unsigned long);
void lpfc_fdmi_tmo_handler(struct lpfc_hba *);

int lpfc_config_port_prep(struct lpfc_hba *);
int lpfc_config_port_post(struct lpfc_hba *);
int lpfc_hba_down_prep(struct lpfc_hba *);
int lpfc_hba_down_post(struct lpfc_hba *);
void lpfc_handle_eratt(struct lpfc_hba *, uint32_t);
void lpfc_handle_latt(struct lpfc_hba *);
void lpfc_hba_init(struct lpfc_hba *, uint32_t *);
int lpfc_post_buffer(struct lpfc_hba *, struct lpfc_sli_ring *, int, int);
void lpfc_cleanup(struct lpfc_hba *, uint32_t);
int lpfc_scsi_free(struct lpfc_hba *);
void lpfc_decode_firmware_rev(struct lpfc_hba *, char *, int);
uint8_t *lpfc_get_lpfchba_info(struct lpfc_hba *, uint8_t *);
int lpfc_fcp_abort(struct lpfc_hba *, int, int, int);
int lpfc_put_event(struct lpfc_hba *, uint32_t, uint32_t, void *,
		       uint32_t, uint32_t);
int lpfc_online(struct lpfc_hba *);
int lpfc_offline(struct lpfc_hba *);
void lpfc_block_requests(struct lpfc_hba *);
void lpfc_unblock_requests(struct lpfc_hba *);



int lpfc_sli_queue_setup(struct lpfc_hba *);
void lpfc_slim_access(struct lpfc_hba *);
int  lpfc_sli_set_dma_length(struct lpfc_hba *, uint32_t);

void lpfc_handle_eratt(struct lpfc_hba *, uint32_t);
void lpfc_handle_latt(struct lpfc_hba *);
irqreturn_t lpfc_intr_handler(int, void *, struct pt_regs *);

void lpfc_read_rev(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_config_ring(struct lpfc_hba *, int, LPFC_MBOXQ_t *);
void lpfc_config_port(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_kill_board(struct lpfc_hba *, LPFC_MBOXQ_t *);
void lpfc_mbox_put(struct lpfc_hba *, LPFC_MBOXQ_t *);
LPFC_MBOXQ_t *lpfc_mbox_get(struct lpfc_hba *);
int lpfc_mbox_tmo_val(struct lpfc_hba *, int);

int lpfc_mem_alloc(struct lpfc_hba *);
void lpfc_mem_free(struct lpfc_hba *);

struct lpfc_iocbq *
lpfc_prep_els_iocb(struct lpfc_hba * phba,
		   uint8_t expectRsp,
		   uint16_t cmdSize,
		   uint8_t retry, struct lpfc_nodelist * ndlp,
		   uint32_t did,
		   uint32_t elscmd);

void lpfc_reset_barrier(struct lpfc_hba * phba);
int lpfc_sli_brdkill(struct lpfc_hba *);
int lpfc_sli_brdreset(struct lpfc_hba *);
int lpfc_sli_brdrestart(struct lpfc_hba *);
int lpfc_sli_brdready(struct lpfc_hba *, uint32_t);
int lpfc_sli_hba_setup(struct lpfc_hba *);
int lpfc_sli_hba_down(struct lpfc_hba *);
int lpfc_sli_intr(struct lpfc_hba *);
int lpfc_sli_abort_iocb_ring(struct lpfc_hba *, struct lpfc_sli_ring *,
			     uint32_t);
int lpfc_sli_issue_mbox(struct lpfc_hba *, LPFC_MBOXQ_t *, uint32_t);
void lpfc_sli_def_mbox_cmpl(struct lpfc_hba *, LPFC_MBOXQ_t *);
int lpfc_sli_issue_iocb(struct lpfc_hba *, struct lpfc_sli_ring *,
			struct lpfc_iocbq *, uint32_t);
void lpfc_sli_pcimem_bcopy(uint32_t *, uint32_t *, uint32_t);
int lpfc_sli_ringpostbuf_put(struct lpfc_hba *, struct lpfc_sli_ring *,
			     struct lpfc_dmabuf *);
struct lpfc_dmabuf *lpfc_sli_ringpostbuf_get(struct lpfc_hba *,
					     struct lpfc_sli_ring *,
					     dma_addr_t);
int lpfc_sli_issue_abort_iotag32(struct lpfc_hba *, struct lpfc_sli_ring *,
				 struct lpfc_iocbq *);
int lpfc_sli_abort_iocb_ctx(struct lpfc_hba *, struct lpfc_sli_ring *,
			    uint32_t);
int lpfc_sli_sum_iocb_host(struct lpfc_hba *, struct lpfc_sli_ring *);
int lpfc_sli_abort_iocb_host(struct lpfc_hba *, struct lpfc_sli_ring *, int);
int lpfc_sli_sum_iocb_lun(struct lpfc_hba *, struct lpfc_sli_ring *, uint16_t,
			  uint64_t);
int lpfc_sli_abort_iocb_lun(struct lpfc_hba *, struct lpfc_sli_ring *, uint16_t,
			    uint64_t, int);
int lpfc_sli_abort_iocb_tgt(struct lpfc_hba *, struct lpfc_sli_ring *,
			    uint16_t, int);
void lpfc_mbox_timeout(unsigned long);
void lpfc_mbox_timeout_handler(struct lpfc_hba *);
void lpfc_map_fcp_cmnd_to_bpl(struct lpfc_hba *, struct lpfc_scsi_buf *);
void lpfc_free_scsi_cmd(struct lpfc_scsi_buf *);
uint32_t lpfc_os_timeout_transform(struct lpfc_hba *, uint32_t);

struct lpfc_nodelist *
lpfc_findnode_wwpn(struct lpfc_hba * phba, uint32_t order,
		   struct lpfc_name * wwpn);
struct lpfc_nodelist *
lpfc_findnode_wwnn(struct lpfc_hba * phba, uint32_t order,
		   struct lpfc_name * wwnn);
struct lpfc_nodelist *lpfc_findnode_did(struct lpfc_hba * phba, uint32_t order,
					uint32_t did);

int lpfc_sli_issue_mbox_wait(struct lpfc_hba * phba, LPFC_MBOXQ_t * pmboxq,
			 uint32_t timeout);

int
lpfc_sli_issue_iocb_wait(struct lpfc_hba * phba,
			 struct lpfc_sli_ring * pring,
			 struct lpfc_iocbq * piocb,
			 struct lpfc_iocbq * prspiocbq, uint32_t timeout);
int lpfc_sli_issue_iocb_wait_high_priority(struct lpfc_hba * phba,
					   struct lpfc_sli_ring * pring,
					   struct lpfc_iocbq * piocb,
					   uint32_t flag,
					   struct lpfc_iocbq * prspiocbq);
void lpfc_sli_wake_iocb_high_priority(struct lpfc_hba * phba,
				      struct lpfc_iocbq * queue1,
				      struct lpfc_iocbq * queue2);
void lpfc_sli_abort_fcp_cmpl(struct lpfc_hba * phba,
			     struct lpfc_iocbq * cmdiocb,
			     struct lpfc_iocbq * rspiocb);
void *lpfc_mbuf_alloc(struct lpfc_hba *, int, dma_addr_t *);
void lpfc_mbuf_free(struct lpfc_hba *, void *, dma_addr_t);

int  lpfc_stop_timer(struct lpfc_hba *);

void lpfc_free_all_delayed_iocbs(struct lpfc_hba *);
void lpfc_free_delayed_iocbs_tmo(unsigned long);
void lpfc_free_delayed_iocbs(struct lpfc_hba *, struct lpfc_iocbq *);


/* Function prototypes. */
int lpfc_queuecommand(struct scsi_cmnd *, void (*done) (struct scsi_cmnd *));
int lpfc_abort_handler(struct scsi_cmnd *);
int lpfc_reset_bus_handler(struct scsi_cmnd *);
int lpfc_reset_lun_handler(struct scsi_cmnd *);
void lpfc_free_scsi_buf(struct lpfc_scsi_buf *);

#if defined(RHEL_FC) || defined(SLES_FC)
void lpfc_target_unblock(struct lpfc_hba *, struct lpfc_target *);
void lpfc_target_block(struct lpfc_hba *, struct lpfc_target *);
int lpfc_target_remove(struct lpfc_hba *, struct lpfc_target *);
int lpfc_target_add(struct lpfc_hba *, struct lpfc_target *);
#endif

#if defined(RHEL_FC) && defined(DISKDUMP_FC)
void lpfc_disc_done_entrance(struct lpfc_hba *);
#endif
void lpfc_hatt_timeout(unsigned long ptr);

#define ScsiResult(host_code, scsi_code) (((host_code) << 16) | scsi_code)
#define HBA_EVENT_LINK_UP                2
#define HBA_EVENT_LINK_DOWN              3
#define HBA_EVENT_RSCN                   5
#define HBA_EVENT_TEMP                   6
#define HBA_EVENT_DUMP                   0x10000
#endif				/* _H_LPFC_CRTN */

/*
 * Constants and structures defined in the iSCSI RFC.
 */
#ifndef ISCSI_H_
#define ISCSI_H_

#include <linux/types.h>

#define ISCSI_DRAFT20_VERSION	0x00

/* TCP port for iSCSI connections assigned by IANA */
#define ISCSI_TCP_PORT	3260

/* Reserved value for initiator/target task tag */
#define ISCSI_RSVD_TASK_TAG	0xffffffff

/* most PDU types have a final bit */
#define ISCSI_FLAG_FINAL	0x80

/* iSCSI Template Header */
struct iscsi_hdr {
	__u8 opcode;
	__u8 flags;		/* Final bit */
	__u8 rsvd2[2];
	__u8 hlength;		/* AHSs total length */
	__u8 dlength[3];	/* Data length */
	__u8 lun[8];
	__u32 itt;
	__u8 other[28];
};

/* Opcode encoding bits */
#define ISCSI_OP_RETRY			0x80
#define ISCSI_OP_IMMEDIATE		0x40
#define ISCSI_OPCODE_MASK		0x3F

/* Client to Server Message Opcode values */
#define ISCSI_OP_NOOP_OUT		0x00
#define ISCSI_OP_SCSI_CMD		0x01
#define ISCSI_OP_TASK_MGT_REQ		0x02
#define ISCSI_OP_LOGIN_CMD		0x03
#define ISCSI_OP_TEXT_CMD		0x04
#define ISCSI_OP_SCSI_DATA		0x05
#define ISCSI_OP_LOGOUT_CMD		0x06
#define ISCSI_OP_SNACK_CMD		0x10

/* Server to Client Message Opcode values */
#define ISCSI_OP_NOOP_IN		0x20
#define ISCSI_OP_SCSI_RSP		0x21
#define ISCSI_OP_SCSI_TASK_MGT_RSP	0x22
#define ISCSI_OP_LOGIN_RSP		0x23
#define ISCSI_OP_TEXT_RSP		0x24
#define ISCSI_OP_SCSI_DATA_RSP		0x25
#define ISCSI_OP_LOGOUT_RSP		0x26
#define ISCSI_OP_R2T			0x31
#define ISCSI_OP_ASYNC_MSG		0x32
#define ISCSI_OP_REJECT			0x3f

/* SCSI Command Header */
struct iscsi_scsi_cmd_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 rsvd2;
	__u8 cmdrn;
	__u8 hlength;
	__u8 dlength[3];
	__u8 lun[8];
	__u32 itt;
	__u32 data_length;
	__u32 cmdsn;
	__u32 expstatsn;
	__u8 scb[16];		/* SCSI Command Block */
	/* Additional Data (Command Dependent) */
};

/* Command PDU flags */
#define ISCSI_FLAG_CMD_READ		0x40
#define ISCSI_FLAG_CMD_WRITE		0x20
#define ISCSI_FLAG_CMD_ATTR_MASK	0x07	/* 3 bits */

/* SCSI Command Attribute values */
#define ISCSI_ATTR_UNTAGGED		0
#define ISCSI_ATTR_SIMPLE		1
#define ISCSI_ATTR_ORDERED		2
#define ISCSI_ATTR_HEAD_OF_QUEUE	3
#define ISCSI_ATTR_ACA			4

/* SCSI Response Header */
struct iscsi_scsi_rsp_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 response;
	__u8 cmd_status;
	__u8 hlength;
	__u8 dlength[3];
	__u8 rsvd[8];
	__u32 itt;
	__u32 rsvd1;
	__u32 statsn;
	__u32 expcmdsn;
	__u32 maxcmdsn;
	__u32 expdatasn;
	__u32 bi_residual_count;
	__u32 residual_count;
	/* Response or Sense Data (optional) */
};

/* Command Response PDU flags */
#define ISCSI_FLAG_CMD_BIDI_OVERFLOW	0x10
#define ISCSI_FLAG_CMD_BIDI_UNDERFLOW	0x08
#define ISCSI_FLAG_CMD_OVERFLOW 	0x04
#define ISCSI_FLAG_CMD_UNDERFLOW	0x02

/* iSCSI Status values. Valid if Rsp Selector bit is not set */
#define ISCSI_STATUS_CMD_COMPLETED	0
#define ISCSI_STATUS_TARGET_FAILURE	1
#define ISCSI_STATUS_SUBSYS_FAILURE	2

/* Asynchronous Message Header */
struct iscsi_async_msg_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 rsvd2[2];
	__u8 rsvd3;
	__u8 dlength[3];
	__u8 lun[8];
	__u8 rsvd4[8];
	__u32 statsn;
	__u32 expcmdsn;
	__u32 maxcmdsn;
	__u8 async_event;
	__u8 async_vcode;
	__u16 param1;
	__u16 param2;
	__u16 param3;
	__u8 rsvd5[4];
};

/* iSCSI Event Codes */
#define ISCSI_ASYNC_MSG_SCSI_EVENT			0
#define ISCSI_ASYNC_MSG_REQUEST_LOGOUT			1
#define ISCSI_ASYNC_MSG_DROPPING_CONNECTION		2
#define ISCSI_ASYNC_MSG_DROPPING_ALL_CONNECTIONS	3
#define ISCSI_ASYNC_MSG_PARAM_NEGOTIATION		4
#define ISCSI_ASYNC_MSG_VENDOR_SPECIFIC 		255

/* NOP-Out */
struct iscsi_nop_out_hdr {
	__u8 opcode;
	__u8 flags;
	__u16 rsvd2;
	__u8 rsvd3;
	__u8 dlength[3];
	__u8 lun[8];
	__u32 itt;
	__u32 ttt;
	__u32 cmdsn;
	__u32 expstatsn;
	__u8 rsvd4[16];
};

/* NOP-In */
struct iscsi_nop_in_hdr {
	__u8 opcode;
	__u8 flags;
	__u16 rsvd2;
	__u8 rsvd3;
	__u8 dlength[3];
	__u8 lun[8];
	__u32 itt;
	__u32 ttt;
	__u32 statsn;
	__u32 expcmdsn;
	__u32 maxcmdsn;
	__u8 rsvd4[12];
};

/* SCSI Task Management Request Header */
struct iscsi_scsi_task_mgmt_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 rsvd1[2];
	__u8 hlength;
	__u8 dlength[3];
	__u8 lun[8];
	__u32 itt;
	__u32 rtt;
	__u32 cmdsn;
	__u32 expstatsn;
	__u32 refcmdsn;
	__u32 expdatasn;
	__u8 rsvd2[8];
};

#define ISCSI_FLAG_TMF_MASK		0x7F

/* Function values */
#define ISCSI_TMF_ABORT_TASK		1
#define ISCSI_TMF_ABORT_TASK_SET	2
#define ISCSI_TMF_CLEAR_ACA		3
#define ISCSI_TMF_CLEAR_TASK_SET	4
#define ISCSI_TMF_LOGICAL_UNIT_RESET	5
#define ISCSI_TMF_TARGET_WARM_RESET	6
#define ISCSI_TMF_TARGET_COLD_RESET	7
#define ISCSI_TMF_TASK_REASSIGN 	8

/* SCSI Task Management Response Header */
struct iscsi_scsi_task_mgmt_rsp_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 response;		/* see Response values below */
	__u8 qualifier;
	__u8 hlength;
	__u8 dlength[3];
	__u8 rsvd2[8];
	__u32 itt;
	__u32 rtt;
	__u32 statsn;
	__u32 expcmdsn;
	__u32 maxcmdsn;
	__u8 rsvd3[12];
};

/* Response values */
#define ISCSI_TMF_RESP_COMPLETE 	0x00
#define ISCSI_TMF_RESP_UNKNOWN_TASK	0x01
#define ISCSI_TMF_RESP_UNKNOWN_LUN	0x02
#define ISCSI_TMF_RESP_TASK_ALLEGIANT	0x03
#define ISCSI_TMF_RESP_NO_FAILOVER	0x04
#define ISCSI_TMF_RESP_IN_PRGRESS	0x05
#define ISCSI_TMF_RESP_REJECTED 	0xff

/* Ready To Transfer Header */
struct iscsi_r2t_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 rsvd2[2];
	__u8 rsvd3[12];
	__u32 itt;
	__u32 ttt;
	__u32 statsn;
	__u32 expcmdsn;
	__u32 maxcmdsn;
	__u32 rttsn;
	__u32 data_offset;
	__u32 data_length;
};

/* SCSI Data Hdr */
struct iscsi_data_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 rsvd2[2];
	__u8 rsvd3;
	__u8 dlength[3];
	__u8 lun[8];
	__u32 itt;
	__u32 ttt;
	__u32 rsvd4;
	__u32 expstatsn;
	__u32 rsvd5;
	__u32 datasn;
	__u32 offset;
	__u32 rsvd6;
	/* Payload */
};

/* SCSI Data Response Hdr */
struct iscsi_data_rsp_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 rsvd2;
	__u8 cmd_status;
	__u8 hlength;
	__u8 dlength[3];
	__u8 lun[8];
	__u32 itt;
	__u32 ttt;
	__u32 statsn;
	__u32 expcmdsn;
	__u32 maxcmdsn;
	__u32 datasn;
	__u32 offset;
	__u32 residual_count;
};

/* Data Response PDU flags */
#define ISCSI_FLAG_DATA_ACK		0x40
#define ISCSI_FLAG_DATA_OVERFLOW	0x04
#define ISCSI_FLAG_DATA_UNDERFLOW	0x02
#define ISCSI_FLAG_DATA_STATUS		0x01

/* Text Header */
struct iscsi_txt_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 rsvd2[2];
	__u8 hlength;
	__u8 dlength[3];
	__u8 rsvd4[8];
	__u32 itt;
	__u32 ttt;
	__u32 cmdsn;
	__u32 expstatsn;
	__u8 rsvd5[16];
	/* Text - key=value pairs */
};

#define ISCSI_FLAG_TEXT_CONTINUE	0x40

/* Text Response Header */
struct iscsi_txt_rsp_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 rsvd2[2];
	__u8 hlength;
	__u8 dlength[3];
	__u8 rsvd4[8];
	__u32 itt;
	__u32 ttt;
	__u32 statsn;
	__u32 expcmdsn;
	__u32 maxcmdsn;
	__u8 rsvd5[12];
	/* Text Response - key:value pairs */
};

/* Login Header */
struct iscsi_login_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 max_version;
	__u8 min_version;
	__u8 hlength;
	__u8 dlength[3];
	__u8 isid[6];
	__u16 tsih;
	__u32 itt;
	__u16 cid;
	__u16 rsvd3;
	__u32 cmdsn;
	__u32 expstatsn;
	__u8 rsvd5[16];
};

/* Login PDU flags */
#define ISCSI_FLAG_LOGIN_TRANSIT		0x80
#define ISCSI_FLAG_LOGIN_CONTINUE		0x40
#define ISCSI_FLAG_LOGIN_CURRENT_STAGE_MASK	0x0C	/* 2 bits */
#define ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK	0x03	/* 2 bits */

#define ISCSI_LOGIN_CURRENT_STAGE(flags) \
	((flags & ISCSI_FLAG_LOGIN_CURRENT_STAGE_MASK) >> 2)
#define ISCSI_LOGIN_NEXT_STAGE(flags) \
	(flags & ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK)

/* Login Response Header */
struct iscsi_login_rsp_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 max_version;
	__u8 active_version;
	__u8 hlength;
	__u8 dlength[3];
	__u8 isid[6];
	__u16 tsih;
	__u32 itt;
	__u32 rsvd3;
	__u32 statsn;
	__u32 expcmdsn;
	__u32 maxcmdsn;
	__u8 status_class;	/* see Login RSP ststus classes below */
	__u8 status_detail;	/* see Login RSP Status details below */
	__u8 rsvd4[10];
};

/* Login stage (phase) codes for CSG, NSG */
#define ISCSI_SECURITY_NEGOTIATION_STAGE	0
#define ISCSI_OP_PARMS_NEGOTIATION_STAGE	1
#define ISCSI_FULL_FEATURE_PHASE		3

/* Login Status response classes */
#define ISCSI_STATUS_CLS_SUCCESS		0x00
#define ISCSI_STATUS_CLS_REDIRECT		0x01
#define ISCSI_STATUS_CLS_INITIATOR_ERR		0x02
#define ISCSI_STATUS_CLS_TARGET_ERR		0x03

/* Login Status response detail codes */
/* Class-0 (Success) */
#define ISCSI_LOGIN_STATUS_ACCEPT		0x00

/* Class-1 (Redirection) */
#define ISCSI_LOGIN_STATUS_TGT_MOVED_TEMP	0x01
#define ISCSI_LOGIN_STATUS_TGT_MOVED_PERM	0x02

/* Class-2 (Initiator Error) */
#define ISCSI_LOGIN_STATUS_INIT_ERR		0x00
#define ISCSI_LOGIN_STATUS_AUTH_FAILED		0x01
#define ISCSI_LOGIN_STATUS_TGT_FORBIDDEN	0x02
#define ISCSI_LOGIN_STATUS_TGT_NOT_FOUND	0x03
#define ISCSI_LOGIN_STATUS_TGT_REMOVED		0x04
#define ISCSI_LOGIN_STATUS_NO_VERSION		0x05
#define ISCSI_LOGIN_STATUS_ISID_ERROR		0x06
#define ISCSI_LOGIN_STATUS_MISSING_FIELDS	0x07
#define ISCSI_LOGIN_STATUS_CONN_ADD_FAILED	0x08
#define ISCSI_LOGIN_STATUS_NO_SESSION_TYPE	0x09
#define ISCSI_LOGIN_STATUS_NO_SESSION		0x0a
#define ISCSI_LOGIN_STATUS_INVALID_REQUEST	0x0b

/* Class-3 (Target Error) */
#define ISCSI_LOGIN_STATUS_TARGET_ERROR 	0x00
#define ISCSI_LOGIN_STATUS_SVC_UNAVAILABLE	0x01
#define ISCSI_LOGIN_STATUS_NO_RESOURCES 	0x02

/* Logout Header */
struct iscsi_logout_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 rsvd1[2];
	__u8 hlength;
	__u8 dlength[3];
	__u8 rsvd2[8];
	__u32 itt;
	__u16 cid;
	__u8 rsvd3[2];
	__u32 cmdsn;
	__u32 expstatsn;
	__u8 rsvd4[16];
};

/* Logout PDU flags */
#define ISCSI_FLAG_LOGOUT_REASON_MASK		0x7F

/* logout reason_code values */
#define ISCSI_LOGOUT_REASON_CLOSE_SESSION	0
#define ISCSI_LOGOUT_REASON_CLOSE_CONNECTION	1
#define ISCSI_LOGOUT_REASON_RECOVERY		2
#define ISCSI_LOGOUT_REASON_AEN_REQUEST 	3

/* Logout Response Header */
struct iscsi_logout_rsp_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 response;		/* see Logout response values below */
	__u8 rsvd2;
	__u8 hlength;
	__u8 dlength[3];
	__u8 rsvd3[8];
	__u32 itt;
	__u32 rsvd4;
	__u32 statsn;
	__u32 expcmdsn;
	__u32 maxcmdsn;
	__u32 rsvd5;
	__u16 t2wait;
	__u16 t2retain;
	__u32 rsvd6;
};

/* logout response status values */
#define ISCSI_LOGOUT_SUCCESS			0
#define ISCSI_LOGOUT_CID_NOT_FOUND		1
#define ISCSI_LOGOUT_RECOVERY_UNSUPPORTED	2
#define ISCSI_LOGOUT_CLEANUP_FAILED		3

/* SNACK Header */
struct iscsi_snack_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 rsvd2[14];
	__u32 itt;
	__u32 begrun;
	__u32 runlength;
	__u32 expstatsn;
	__u32 rsvd3;
	__u32 expdatasn;
	__u8 rsvd6[8];
};

/* SNACK PDU flags */
#define ISCSI_FLAG_SNACK_TYPE_MASK	0x0F	/* 4 bits */

/* Reject Header */
struct iscsi_reject_hdr {
	__u8 opcode;
	__u8 flags;
	__u8 reason;
	__u8 rsvd2;
	__u8 rsvd3;
	__u8 dlength[3];
	__u8 rsvd4[16];
	__u32 statsn;
	__u32 expcmdsn;
	__u32 maxcmdsn;
	__u32 datasn;
	__u8 rsvd5[8];
	/* Text - Rejected hdr */
};

/* Reason for Reject */
#define ISCSI_REJECT_RESERVED			1
#define ISCSI_REJECT_DATA_DIGEST_ERROR		2
#define ISCSI_REJECT_SNACK_REJECT		3
#define ISCSI_REJECT_ISCSI_PROTOCOL_ERROR	4
#define ISCSI_REJECT_CMD_NOT_SUPPORTED		5
#define ISCSI_REJECT_IMM_CMD_REJECT		6
#define ISCSI_REJECT_TASK_IN_PROGRESS		7
#define ISCSI_REJECT_INVALID_DATA_ACK		8
#define ISCSI_REJECT_INVALID_PDU_FIELD		9
#define ISCSI_REJECT_CANT_GENERATE_TTT		10
#define ISCSI_REJECT_NEGOTIATION_RESET		11
#define ISCSI_REJECT_WAITING_FOR_LOGOUT 	12

#endif

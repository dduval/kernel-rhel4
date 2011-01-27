/*******************************************************************
 * This file is part of the Emulex Linux Device Driver for         *
 * Fibre Channel Host Bus Adapters.                                *
 * Copyright (C) 2003-2005 Emulex.  All rights reserved.           *
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
 * $Id: lpfc_diag.h 3037 2007-05-22 14:02:22Z sf_support $
 */

#ifndef _H_LPFC_DIAG
#define _H_LPFC_DIAG


   /*
      Define interface for dynamic persistent binding
    */
#define       LPFC_WWNN_BIND 0x0
#define       LPFC_WWPN_BIND 0x1
#define       LPFC_DID_BIND  0x2
#define       LPFC_SCSI_ID   0x3


/* bits in a_onmask */
#define ONDI_MBOX       0x1	/* allows non-destructive mailbox commands */
#define ONDI_IOINFO     0x2	/* supports retrieval of I/O info */
#define ONDI_LNKINFO    0x4	/* supports retrieval of link info */
#define ONDI_NODEINFO   0x8	/* supports retrieval of node info */
#define ONDI_TRACEINFO  0x10	/* supports retrieval of trace info */
#define ONDI_SETTRACE   0x20	/* supports configuration of trace info */
#define ONDI_SLI1       0x40	/* hardware supports SLI-1 interface */
#define ONDI_SLI2       0x80	/* hardware supports SLI-2 interface */
#define ONDI_BIG_ENDIAN 0x100	/* DDI interface is BIG Endian */
#define ONDI_LTL_ENDIAN 0x200	/* DDI interface is LITTLE Endian */
#define ONDI_RMEM       0x400	/* allows reading of adapter shared memory */
#define ONDI_RFLASH     0x800	/* allows reading of adapter flash */
#define ONDI_RPCI       0x1000	/* allows reading of adapter pci registers */
#define ONDI_RCTLREG    0x2000	/* allows reading of adapter cntrol registers */
#define ONDI_CFGPARAM   0x4000	/* supports get/set configuration parameters */
#define ONDI_CT         0x8000	/* supports passthru CT interface */
#define ONDI_HBAAPI     0x10000	/* supports HBA API interface */

/* bits in a_offmask */
#define OFFDI_MBOX      0x1	/* allows all mailbox commands */
#define OFFDI_RMEM      0x2	/* allows reading of adapter shared memory */
#define OFFDI_WMEM      0x4	/* allows writing of adapter shared memory */
#define OFFDI_RFLASH    0x8	/* allows reading of adapter flash */
#define OFFDI_WFLASH    0x10	/* allows writing of adapter flash */
#define OFFDI_RPCI      0x20	/* allows reading of adapter pci registers */
#define OFFDI_WPCI      0x40	/* allows writing of adapter pci registers */
#define OFFDI_RCTLREG   0x80	/* allows reading of adapter cntrol registers */
#define OFFDI_WCTLREG   0x100	/* allows writing of adapter cntrol registers */
#define OFFDI_OFFLINE   0x80000000	/* if set, adapter is in offline
					   state */

/* values for flag in SetDiagEnv */
#define DDI_SHOW        0x0
#define DDI_ONDI        0x1
#define DDI_OFFDI       0x2
#define DDI_WARMDI      0x3
#define DDI_DIAGDI      0x4

#define DDI_BRD_SHOW    0x10
#define DDI_BRD_ONDI    0x11
#define DDI_BRD_OFFDI   0x12
#define DDI_BRD_WARMDI  0x13
#define DDI_BRD_DIAGDI  0x14

#define DDI_UNUSED      0xFFFFFFFFL

/* the drvinfo structure */
typedef struct DFCDRVINFO {
   uint8_t     drvInfoVer;     /* Version of this structure - 2 */
   uint8_t     drvType;
   uint16_t    reserved;
   uint8_t     rmLevel;        /* Remote Management (HBAnyware) Support Level */
   uint8_t     mpLevel;        /* MultiPulse support Level */
   uint8_t     hbaapiLevel;    /* HBAAPI support level */
   uint8_t     rsvd;
   uint8_t     drvVer[16];     /* Driver Version string */
   uint8_t     drvName[8];     /* Driver Name */
   uint8_t     ftrDrvVer[16];  /* Filter/IOCtl Driver Version string */
   uint8_t     ftrDrvName[8];  /* Filter/IOCtl Driver Name */
   uint8_t     ipDrvVer[16];   /* IP Driver/component Version string */
   uint8_t     ipDrvName[8];   /* IP Driver/component Name */
   uint32_t    d_id;
   uint8_t     wwpn[8];
   uint8_t     wwnn[8];
   uint8_t     hostname[32];   /* IP node hostname from uname -n */
} DFCDrvInfo;

/* the drvinfo structure */
typedef struct LPFCDFCDRVINFO {
   uint8_t     version[16];  /* Driver Version string */
   uint8_t     name[8];      /* Driver Name */
} LPFCDFCDrvInfo;

/* the ioinfo structure */
typedef struct IOINFO {
	uint32_t a_mbxCmd;	/* mailbox commands issued */
	uint32_t a_mboxCmpl;	/* mailbox commands completed */
	uint32_t a_mboxErr;	/* mailbox commands completed, error status */
	uint32_t a_iocbCmd;	/* iocb command ring issued */
	uint32_t a_iocbRsp;	/* iocb rsp ring received */
	uint32_t a_adapterIntr;	/* adapter interrupt events */
	uint32_t a_fcpCmd;	/* FCP commands issued */
	uint32_t a_fcpCmpl;	/* FCP command completions received */
	uint32_t a_fcpErr;	/* FCP command completions errors */
	uint32_t a_seqXmit;	/* IP xmit sequences sent */
	uint32_t a_seqRcv;	/* IP sequences received */
	uint32_t a_bcastXmit;	/* cnt of successful xmit bcast cmds issued */
	uint32_t a_bcastRcv;	/* cnt of receive bcast cmds received */
	uint32_t a_elsXmit;	/* cnt of successful ELS req cmds issued */
	uint32_t a_elsRcv;	/* cnt of ELS request commands received */
	uint32_t a_RSCNRcv;	/* cnt of RSCN commands received */
	uint32_t a_seqXmitErr;	/* cnt of unsuccessful xmit bcast cmds issued */
	uint32_t a_elsXmitErr;	/* cnt of unsuccessful ELS req cmds issued  */
	uint32_t a_elsBufPost;	/* cnt of ELS buffers posted to adapter */
	uint32_t a_ipBufPost;	/* cnt of IP buffers posted to adapter */
	uint32_t a_cnt1;	/* generic counter */
	uint32_t a_cnt2;	/* generic counter */
	uint32_t a_cnt3;	/* generic counter */
	uint32_t a_cnt4;	/* generic counter */
} IOinfo;

typedef struct DESTID {
   uint32_t    idType;         /* 0 - wwpn, 1 - d_id */
   uint32_t    d_id;
   uint8_t     wwpn[8];
} DestID;

typedef struct LOOPBACK {
   uint32_t    bufSize;
   uint8_t   * XmitBuffer;
   uint8_t   * RcvBuffer;
} Loopback;

/* the linkinfo structure */
typedef struct LINKINFO {
	uint32_t a_linkEventTag;
	uint32_t a_linkUp;
	uint32_t a_linkDown;
	uint32_t a_linkMulti;
	uint32_t a_DID;
	uint8_t a_topology;
	uint8_t a_linkState;
	uint8_t a_alpa;
	uint8_t a_alpaCnt;
	uint8_t a_alpaMap[128];
	uint8_t a_wwpName[8];
	uint8_t a_wwnName[8];
} LinkInfo;

/* structure used for temperature event */
typedef struct temp_event_info {
	uint32_t event_type;
	uint32_t temp;
} temp_event_info_t;

/* values for a_topology */
#define LNK_LOOP                0x1
#define LNK_PUBLIC_LOOP         0x2
#define LNK_FABRIC              0x3
#define LNK_PT2PT               0x4

/* values for a_linkState */
#define LNK_DOWN                0x1
#define LNK_UP                  0x2
#define LNK_FLOGI               0x3
#define LNK_DISCOVERY           0x4
#define LNK_REDISCOVERY         0x5
#define LNK_READY               0x6

/* the traceinfo structure */
typedef struct TRACEINFO {
	uint8_t a_event;
	uint8_t a_cmd;
	uint16_t a_status;
	uint32_t a_information;
} TraceInfo;

/* values for flag */
#define TRC_SHOW        0x0
#define TRC_MBOX        0x1
#define TRC_IOCB        0x2
#define TRC_INTR        0x4
#define TRC_EVENT       0x8

/* values for a_event */
#define TRC_MBOX_CMD    0x1
#define TRC_MBOX_CMPL   0x2
#define TRC_IOCB_CMD    0x3
#define TRC_IOCB_RSP    0x4
#define TRC_INTR_RCV    0x5
#define TRC_EVENT1      0x6
#define TRC_EVENT2      0x7
#define TRC_EVENT_MASK  0x7
#define TRC_RING0       0x0
#define TRC_RING1       0x40
#define TRC_RING2       0x80
#define TRC_RING3       0xC0
#define TRC_RING_MASK   0xC0

/* the cfgparam structure */
typedef struct CFGPARAM {
	char a_string[32];
	uint32_t a_low;
	uint32_t a_hi;
	uint32_t a_default;
	uint32_t a_current;
	uint16_t a_flag;
	uint16_t a_changestate;
	char a_help[80];
} CfgParam;

#define MAX_CFG_PARAM 64

/* the nodeinfo structure */
typedef struct NODEINFO {
	uint16_t a_flag;
	uint16_t a_state;
	uint32_t a_did;
	uint8_t a_wwpn[8];
	uint8_t a_wwnn[8];
	uint32_t a_targetid;
} NodeInfo;

#define MAX_NODES 512

/* Defines for a_state */
#define NODE_UNUSED     0
#define NODE_LIMBO      0x1	/* entry needs to hang around for wwpn / sid */
#define NODE_LOGOUT     0x2	/* NL_PORT is not logged in - entry is cached */
#define NODE_PLOGI      0x3	/* PLOGI was sent to NL_PORT */
#define NODE_LOGIN      0x4	/* NL_PORT is logged in / login REG_LOGINed */
#define NODE_PRLI       0x5	/* PRLI was sent to NL_PORT */
#define NODE_ALLOC      0x6	/* NL_PORT is  ready to initiate adapter I/O */
#define NODE_SEED       0x7	/* seed scsi id bind in table */

/* Defines for a_flag */
#define NODE_RPI_XRI        0x1	/* creating xri for entry */
#define NODE_REQ_SND        0x2	/* sent ELS request for this entry */
#define NODE_ADDR_AUTH      0x4	/* Authenticating addr for this entry */
#define NODE_RM_ENTRY       0x8	/* Remove this entry */
#define NODE_FARP_SND       0x10	/* sent FARP request for this entry */
#define NODE_FABRIC         0x20	/* this entry represents the Fabric */
#define NODE_FCP_TARGET     0x40	/* this entry is an FCP target */
#define NODE_IP_NODE        0x80	/* this entry is an IP node */
#define NODE_DISC_START     0x100	/* start discovery on this entry */
#define NODE_SEED_WWPN      0x200	/* Entry scsi id is seeded for WWPN */
#define NODE_SEED_WWNN      0x400	/* Entry scsi id is seeded for WWNN */
#define NODE_SEED_DID       0x800	/* Entry scsi id is seeded for DID */
#define NODE_SEED_MASK      0xe00	/* mask for seeded flags */
#define NODE_AUTOMAP        0x1000	/* This entry was automap'ed */
#define NODE_NS_REMOVED     0x2000	/* This entry removed from NameServer */

/* Define for fc_flag */
#define DFC_MBOX_ACTIVE  2	/* mailbox is active thru dfc */

/* Define for dfc 'riocb' function */
#define FC_RING(ringoff,sa)     ((volatile uint8_t *)((volatile uint8_t *)sa + \
						      (unsigned long)(ringoff)))
#endif				/* _H_LPFC_DIAG */

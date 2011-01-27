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
 * $Id: lpfc_ioctl.h 2791 2005-12-30 18:37:05Z sf_support $
 */

#ifndef _H_LPFC_IOCTL
#define _H_LPFC_IOCTL

#define MAX_LPFC_BRDS 32

#define DFC_MAJOR_REV	80
#define DFC_MINOR_REV	163

/* Duplicate definitions */
/*   Make sure these stay in sync with their counterparts in the */
/*   base driver. */
#define LPFC_MAX_RING_MASK  5	/* max num of rctl/type masks allowed per
				   ring */
#define LPFC_MAX_RING       4	/* max num of SLI rings used by driver */

#define LPFC_INQSN_SZ      64   /* Max size of Inquiry serial number */


/* LPFC Ioctls() 0x00 - 0x3F. */

/* LPFC_FIRST_COMMAND_USED	0x01	    First defines Ioctl used  */
#define LPFC_WRITE_PCI		0x01	/* Write to PCI */
#define LPFC_READ_PCI		0x06	/* Read from PCI */

/* LPFC COMMAND POSITION 0xc available.  Used to be Read ring information. */

#define LPFC_READ_MEM		0x0d	/* Read memory */

/* LPFC COMMAND POSITION 0xf available. */

#define LPFC_MBOX		0x12	/* Issue a MB cmd */
#define LPFC_RESET		0x13	/* Reset the adapter */
#define LPFC_READ_HBA		0x14	/* Get adapter info */

/* LPFC COMMAND POSITION 0x15 available.  Used to be Get NDD stats. */

#define LPFC_WRITE_MEM		0x16	/* Write to SLIM memory */
#define LPFC_WRITE_CTLREG	0x17	/* Write to Control register */
#define LPFC_READ_CTLREG		0x18	/* Read from Control control register */
#define LPFC_INITBRDS		0x19	/* Initialize the adapters */
#define LPFC_SETDIAG		0x1a	/* Set/get board online/offline */
#define LPFC_INST		0x1b	/* get instance info */
#define LPFC_READ_BPLIST		0x2d	/* get list of buffers post */
#define LPFC_LINKINFO		0x2f	/* get link information */
#define LPFC_IOINFO  		0x30	/* get I/O stats */
#define LPFC_NODEINFO  		0x31	/* get node (NPort) information */
#define LPFC_LIST_BIND		0x38	/* List binding */
/*	LPFC_LAST_IOCTL_USED	0x38	Last LPFC Ioctl used  */


/* LPFC Ioctls() 0x40 - 0x7F */

/* LPFC_FIRST_IOCTL_USED		0x40     First defines Ioctl used  */
#define LPFC_LIP			0x41	/* Issue a LIP */
#define LPFC_CT				0x42	/* Send CT passthru command */
#define LPFC_LISTN			0x43	/* List nodes for adapter
						 * (by WWPN, WWNN and DID) */

/*  HBA API specific Ioctls() */

#define LPFC_HBA_ADAPTERATTRIBUTES	0x48	/* Get attributes of HBA */
#define LPFC_HBA_PORTATTRIBUTES		0x49	/* Get attributes of HBA Port */
#define LPFC_HBA_PORTSTATISTICS		0x4a	/* Get statistics of HBA Port */
#define LPFC_HBA_DISCPORTATTRIBUTES	0x4b	/* Get attibutes of the
						 * discovered adapter Ports */
#define LPFC_HBA_WWPNPORTATTRIBUTES	0x4c	/* Get attributes of the Port
						 * specified by WWPN */
#define LPFC_HBA_INDEXPORTATTRIBUTES	0x4d	/* Get attributes of the Port
						 * specified by index */
#define LPFC_HBA_SETMGMTINFO		0x50	/* Sets driver values with
						 * default HBA_MGMTINFO vals */
#define LPFC_HBA_GETMGMTINFO		0x51	/* Get driver values for
						 * HBA_MGMTINFO vals */
#define LPFC_HBA_RNID			0x52	/* Send an RNID request */
#define LPFC_HBA_GETEVENT		0x53	/* Get event data */
#define LPFC_HBA_SEND_SCSI		0x55	/* Send SCSI requests to tgt */
#define LPFC_HBA_REFRESHINFO		0x56	/* Do a refresh of the stats */
#define LPFC_SEND_ELS			0x57	/* Send out an ELS command */
#define LPFC_HBA_SEND_FCP		0x58	/* Send out a FCP command */
#define LPFC_HBA_SET_EVENT		0x59	/* Set FCP event(s) */
#define LPFC_HBA_GET_EVENT		0x5a	/* Get  FCP event(s) */
#define LPFC_HBA_SEND_MGMT_CMD		0x5b	/* Send a management command */
#define LPFC_HBA_SEND_MGMT_RSP		0x5c	/* Send a management response */

#define LPFC_GETCFG			0x64	/* Get config parameters */
#define LPFC_SETCFG			0x65	/* Set config parameters */
#define LPFC_STAT			0x67	/* Statistics for SLI/FC/IP */
#define LPFC_GET_DFC_REV		0x68	/* Get the rev of the ioctl driver */
#define LPFC_GET_VPD			0x69	/* Get Adapter VPD */
#define LPFC_GET_LPFCDFC_INFO		0x70	/* Get lpfcdfc driver info */
#define LPFC_GET_DUMPREGION		0x71	/* Get Adapter Dump Region */
#define LPFC_LOOPBACK_TEST              0x72    /* Run Loopback test */
#define LPFC_LOOPBACK_MODE              0x73    /* Enter Loopback mode */
/*  LPFC_LAST_IOCTL_USED 	        0x73 Last LPFC Ioctl used  */



/* Event definitions for RegisterForEvent */
#define FC_REG_LINK_EVENT       0x1	/* Register for link up / down events */
#define FC_REG_RSCN_EVENT       0x2	/* Register for RSCN events */
#define FC_REG_CT_EVENT         0x4	/* Register for CT request events */
#define FC_REG_DUMP_EVENT       0x10    /* Register for Dump events */

#define FC_REG_EVENT_MASK       0xff	/* event mask */

/*
Data structure definitions:
*/

/*
 * Diagnostic (DFC) Command & Input structures: (LPFC)
 */
typedef struct lpfcCmdInput {
	short    lpfc_brd;
	short    lpfc_ring;
	short    lpfc_iocb;
	short    lpfc_flag;
	void    *lpfc_arg1;
	void    *lpfc_arg2;
	void    *lpfc_arg3;
	char    *lpfc_dataout;
	uint32_t lpfc_cmd;
	uint32_t lpfc_outsz;
	uint32_t lpfc_arg4;
	uint32_t lpfc_arg5;
} LPFCCMDINPUT_t;

#if defined(CONFIG_COMPAT) && !defined(__ia64__)
/* 32 bit version */
typedef struct lpfcCmdInput32 {
	short    lpfc_brd;
	short    lpfc_ring;
	short    lpfc_iocb;
	short    lpfc_flag;
	u32	lpfc_arg1;
	u32	lpfc_arg2;
	u32     lpfc_arg3;
	u32     lpfc_dataout;
	uint32_t lpfc_cmd;
	uint32_t lpfc_outsz;
	uint32_t lpfc_arg4;
	uint32_t lpfc_arg5;
} LPFCCMDINPUT32_t;
#endif

/* Structure for OUTFCPIO command */

struct out_fcp_devp {
	uint16_t target;
	uint16_t lun;
	uint16_t tx_count;
	uint16_t txcmpl_count;
	uint16_t delay_count;
	uint16_t sched_count;
	uint16_t lun_qdepth;
	uint16_t current_qdepth;
	uint32_t qcmdcnt;
	uint32_t iodonecnt;
	uint32_t errorcnt;
	uint8_t  pad[4]; /* pad structure to 8 byte boundary */
};

/* Structure for VPD command */

struct vpd {
	uint32_t version;
#define VPD_VERSION1     1
	uint8_t  ModelDescription[256];    /* VPD field V1 */
	uint8_t  Model[80];                /* VPD field V2 */
	uint8_t  ProgramType[256];         /* VPD field V3 */
	uint8_t  PortNum[20];              /* VPD field V4 */
};

#define MREC_MAX 16
#define arecord(a, b, c, d)

struct rec {
	void *arg0;
	void *arg1;
	void *arg2;
	void *arg3;
};

/*
 * This structure needs to fit in di->fc_dataout alloc'ed memory
 * array in dfc_un for dfc.c / C_TRACE
 */
struct mrec {
	ulong reccnt;
	struct rec rectbl[MREC_MAX];
};

/* the DfcRevInfo structure */
typedef struct DFCREVINFO {
	uint32_t a_Major;
	uint32_t a_Minor;
} DfcRevInfo;




/* the brdinfo structure */
typedef struct BRDINFO {
	uint32_t a_mem_hi;	/* memory identifier for adapter access */
	uint32_t a_mem_low;	/* memory identifier for adapter access */
	uint32_t a_flash_hi;	/* memory identifier for adapter access */
	uint32_t a_flash_low;	/* memory identifier for adapter access */
	uint32_t a_ctlreg_hi;	/* memory identifier for adapter access */
	uint32_t a_ctlreg_low;	/* memory identifier for adapter access */
	uint32_t a_intrlvl;	/* interrupt level for adapter */
	uint32_t a_pci;		/* PCI identifier (device / vendor id) */
	uint32_t a_busid;	/* identifier of PCI bus adapter is on */
	uint32_t a_devid;	/* identifier of PCI device number */
	uint8_t a_rsvd1;	/* reserved for future use */
	uint8_t a_rsvd2;	/* reserved for future use */
	uint8_t a_siglvl;	/* signal handler used by library */
	uint8_t a_ddi;		/* identifier device driver instance number */
	uint32_t a_onmask;	/* mask of ONDI primatives supported */
	uint32_t a_offmask;	/* mask of OFFDI primatives supported */
	uint8_t a_drvrid[16];	/* driver version */
	uint8_t a_fwname[32];	/* firmware version */
} brdinfo;

/* the dfc_brdinfo structure */
typedef struct DFC_BRDINFO {
	uint32_t a_mem_hi;	/* memory identifier for adapter access */
	uint32_t a_mem_low;	/* memory identifier for adapter access */
	uint32_t a_flash_hi;	/* memory identifier for adapter access */
	uint32_t a_flash_low;	/* memory identifier for adapter access */
	uint32_t a_ctlreg_hi;	/* memory identifier for adapter access */
	uint32_t a_ctlreg_low;	/* memory identifier for adapter access */
	uint32_t a_intrlvl;	/* interrupt level for adapter */
	uint32_t a_pci;		/* PCI identifier (device / vendor id) */
	uint32_t a_busid;	/* identifier of PCI bus adapter is on */
	uint32_t a_devid;	/* identifier of PCI device number */
	uint8_t  a_rsvd1;	/* reserved for future use */
	uint8_t  a_siglvl;	/* signal handler used by library */
	uint16_t a_ddi;		/* identifier device driver instance number */
	uint32_t a_onmask;	/* mask of ONDI primatives supported */
	uint32_t a_offmask;	/* mask of OFFDI primatives supported */
	uint8_t  a_drvrid[16];	/* driver version */
	uint8_t  a_fwname[32];	/* firmware version */
	uint8_t  a_wwpn[8];	/* worldwide portname */
} dfc_brdinfo;

typedef struct {
	uint8_t bind_type;
	uint8_t wwpn[8];
	uint8_t wwnn[8];
	uint32_t did;
	uint32_t scsi_id;
} bind_ctl_t;

struct dfc_info {
	uint32_t a_pci;
	uint32_t a_busid;
	uint32_t a_devid;
	uint32_t a_ddi;
	uint32_t a_onmask;
	uint32_t a_offmask;
	uint8_t  a_drvrid[16];
	uint8_t  a_fwname[32];
	uint8_t  a_wwpn[8];
};

#define LPFC_DFC_CMD_IOCTL_MAGIC 0xFC
#define LPFC_DFC_CMD_IOCTL _IOWR(LPFC_DFC_CMD_IOCTL_MAGIC, 0x1, LPFCCMDINPUT_t) 	/* Used for ioctl command */
#define LPFC_DFC_CMD_IOCTL32 _IOWR(LPFC_DFC_CMD_IOCTL_MAGIC, 0x1, LPFCCMDINPUT32_t) 	/* Used for ioctl command */

/* DFC specific data structures */

typedef struct dfcptr {
	uint32_t addrhi;
	uint32_t addrlo;
} dfcptr_t;

typedef struct dfcu64 {
	uint32_t hi;
	uint32_t lo;
} dfcu64_t;

typedef struct dfcringmask {
	uint8_t rctl;
	uint8_t type;
	uint8_t  pad[6]; /* pad structure to 8 byte boundary */
} dfcringmask_t;

typedef struct dfcringinit {
	dfcringmask_t prt[LPFC_MAX_RING_MASK];
	uint32_t num_mask;
	uint32_t iotag_ctr;
	uint16_t numCiocb;
	uint16_t numRiocb;
	uint8_t  pad[4]; /* pad structure to 8 byte boundary */
} dfcringinit_t;

typedef struct dfcsliinit {
	dfcringinit_t ringinit[LPFC_MAX_RING];
	uint32_t num_rings;
	uint32_t sli_flag;
} dfcsliinit_t;

typedef struct dfcsliring {
	uint16_t txq_cnt;
	uint16_t txq_max;
	uint16_t txcmplq_cnt;
	uint16_t txcmplq_max;
	uint16_t postbufq_cnt;
	uint16_t postbufq_max;
	uint32_t missbufcnt;
	dfcptr_t cmdringaddr;
	dfcptr_t rspringaddr;
	uint8_t  rspidx;
	uint8_t  cmdidx;
	uint8_t  pad[6]; /* pad structure to 8 byte boundary */
} dfcsliring_t;

typedef struct dfcslistat {
	dfcu64_t iocbEvent[LPFC_MAX_RING];
	dfcu64_t iocbCmd[LPFC_MAX_RING];
	dfcu64_t iocbRsp[LPFC_MAX_RING];
	dfcu64_t iocbCmdFull[LPFC_MAX_RING];
	dfcu64_t iocbCmdEmpty[LPFC_MAX_RING];
	dfcu64_t iocbRspFull[LPFC_MAX_RING];
	dfcu64_t mboxStatErr;
	dfcu64_t mboxCmd;
	dfcu64_t sliIntr;
	uint32_t errAttnEvent;
	uint32_t linkEvent;
} dfcslistat_t;

typedef struct dfcsli {
	dfcsliinit_t sliinit;
	dfcsliring_t ring[LPFC_MAX_RING];
	dfcslistat_t slistat;
	dfcptr_t MBhostaddr;
	uint16_t mboxq_cnt;
	uint16_t mboxq_max;
	uint32_t fcp_ring;
} dfcsli_t;

typedef struct dfchba {
	dfcsli_t sli;
	uint32_t hba_state;
	uint8_t fc_busflag;
	uint8_t  pad[3]; /* pad structure to 8 byte boundary */
} dfchba_t;

typedef struct dfcnodelist {
	uint32_t nlp_failMask;
	uint16_t nlp_type;
	uint16_t nlp_rpi;
	uint16_t nlp_state;
	uint16_t nlp_xri;
	uint32_t nlp_flag;
	uint32_t nlp_DID;
	uint32_t nlp_oldDID;
	uint8_t  nlp_portname[8];
	uint8_t  nlp_nodename[8];
	uint16_t nlp_sid;
	uint8_t  pad[6]; /* pad structure to 8 byte boundary */
} dfcnodelist_t;

typedef struct dfcscsilun {
	dfcu64_t lun_id;
	uint32_t lunFlag;
	uint32_t failMask;
	uint8_t  InquirySN[LPFC_INQSN_SZ];
	uint8_t  Vendor[8];
	uint8_t  Product[16];
	uint8_t  Rev[4];
	uint8_t  sizeSN;
	uint8_t  pad[3]; /* pad structure to 8 byte boundary */
} dfcscsilun_t;

typedef struct dfcscsitarget {
	dfcptr_t context;
	uint16_t max_lun;
	uint16_t scsi_id;
	uint16_t targetFlags;
	uint16_t addrMode;
	uint8_t  pad[6]; /* pad structure to 8 byte boundary */
} dfcscsitarget_t;

typedef struct dfcbindlist {
	uint8_t  nlp_portname[8];
	uint8_t  nlp_nodename[8];
	uint16_t nlp_bind_type;
	uint16_t nlp_sid;
	uint32_t nlp_DID;
} dfcbindlist_t;

typedef struct dfcstat {
	uint32_t elsRetryExceeded;
	uint32_t elsXmitRetry;
	uint32_t elsRcvDrop;
	uint32_t elsRcvFrame;
	uint32_t elsRcvRSCN;
	uint32_t elsRcvRNID;
	uint32_t elsRcvFARP;
	uint32_t elsRcvFARPR;
	uint32_t elsRcvFLOGI;
	uint32_t elsRcvPLOGI;
	uint32_t elsRcvADISC;
	uint32_t elsRcvPDISC;
	uint32_t elsRcvFAN;
	uint32_t elsRcvLOGO;
	uint32_t elsRcvPRLO;
	uint32_t elsRcvPRLI;
	uint32_t elsRcvRRQ;
	uint32_t frameRcvBcast;
	uint32_t frameRcvMulti;
	uint32_t strayXmitCmpl;
	uint32_t frameXmitDelay;
	uint32_t xriCmdCmpl;
	uint32_t xriStatErr;
	uint32_t LinkUp;
	uint32_t LinkDown;
	uint32_t LinkMultiEvent;
	uint32_t NoRcvBuf;
	uint32_t fcpCmd;
	uint32_t fcpCmpl;
	uint32_t fcpRspErr;
	uint32_t fcpRemoteStop;
	uint32_t fcpPortRjt;
	uint32_t fcpPortBusy;
	uint32_t fcpError;
} dfcstats_t;
#endif				/* _H_LPFC_IOCTL */

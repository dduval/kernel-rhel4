/*
 * QLogic iSCSI HBA Driver
 * Copyright (c)  2003-2006 QLogic Corporation
 *
 * See LICENSE.qla4xxx for copyright and licensing details.
 */

/*
 * This file defines mailbox structures and definitions for the QLA4xxx
 *  iSCSI HBA firmware.
 */

#ifndef _QLA4X_FW_H
#define _QLA4X_FW_H

#define QLA4XXX_VENDOR_ID   	0x1077
#define QLA4000_DEVICE_ID  	0x4000
#define QLA4010_DEVICE_ID  	0x4010

#define QLA4040_SSDID_NIC  	0x011D	/* Uses QLA4010 PCI Device ID */
#define QLA4040_SSDID_ISCSI  	0x011E
#define QLA4040C_SSDID_NIC  	0x011F
#define QLA4040C_SSDID_ISCSI  	0x0120

#define MAX_PRST_DEV_DB_ENTRIES         64
#define MIN_DISC_DEV_DB_ENTRY           MAX_PRST_DEV_DB_ENTRIES
#define MAX_DEV_DB_ENTRIES              512
#define MAX_ISNS_DISCOVERED_TARGETS     MAX_DEV_DB_ENTRIES

/* ISP Maximum number of DSD per command */
#define DSD_MAX                                 1024

/* FW check */
#define FW_UP(reg,stat)                         (((stat = RD_REG_DWORD(reg->mailbox[0])) != 0) && (stat != 0x0007))

#define INVALID_REGISTER 			((uint32_t)-1)

#define ISP4010_NET_FUNCTION                            0
#define ISP4010_ISCSI_FUNCTION                          1


/*************************************************************************
 *
 * 		ISP 4010 I/O Register Set Structure and Definitions
 *
 *************************************************************************/

typedef struct _PORT_CTRL_STAT_REGS {
	__le32  ext_hw_conf;      		/*  80 x50  R/W	*/
	__le32  intChipConfiguration;	        /*  84 x54   *  */
	__le32  port_ctrl;		        /*  88 x58   *  */
	__le32  port_status;		        /*  92 x5c   *  */
	__le32  HostPrimMACHi;		        /*  96 x60   *  */
	__le32  HostPrimMACLow;		        /* 100 x64   *  */
	__le32  HostSecMACHi;		        /* 104 x68   *  */
	__le32  HostSecMACLow;		        /* 108 x6c   *  */
	__le32  EPPrimMACHi;		        /* 112 x70   *  */
	__le32  EPPrimMACLow;		        /* 116 x74   *  */
	__le32  EPSecMACHi;		        /* 120 x78   *  */
	__le32  EPSecMACLow;		        /* 124 x7c   *  */
	__le32  HostPrimIPHi;		        /* 128 x80   *  */
	__le32  HostPrimIPMidHi;	        /* 132 x84   *  */
	__le32  HostPrimIPMidLow;	        /* 136 x88   *  */
	__le32  HostPrimIPLow;		        /* 140 x8c   *  */
	__le32  HostSecIPHi;		        /* 144 x90   *  */
	__le32  HostSecIPMidHi;		        /* 148 x94   *  */
	__le32  HostSecIPMidLow;	        /* 152 x98   *  */
	__le32  HostSecIPLow;		        /* 156 x9c   *  */
	__le32  EPPrimIPHi;		        /* 160 xa0   *  */
	__le32  EPPrimIPMidHi;		        /* 164 xa4   *  */
	__le32  EPPrimIPMidLow;		        /* 168 xa8   *  */
	__le32  EPPrimIPLow;		        /* 172 xac   *  */
	__le32  EPSecIPHi;		        /* 176 xb0   *  */
	__le32  EPSecIPMidHi;		        /* 180 xb4   *  */
	__le32  EPSecIPMidLow;		        /* 184 xb8   *  */
	__le32  EPSecIPLow;		        /* 188 xbc   *  */
	__le32  IPReassemblyTimeout;	        /* 192 xc0   *  */
	__le32  EthMaxFramePayload;	        /* 196 xc4   *  */
	__le32  TCPMaxWindowSize;	        /* 200 xc8   *  */
	__le32  TCPCurrentTimestampHi;	        /* 204 xcc   *  */
	__le32  TCPCurrentTimestampLow;	        /* 208 xd0   *  */
	__le32  LocalRAMAddress;	        /* 212 xd4   *  */
	__le32  LocalRAMData;		        /* 216 xd8   *  */
	__le32  PCSReserved1;		        /* 220 xdc   *  */
	__le32  gp_out;	       			/* 224 xe0   *  */
	__le32  gp_in;	       			/* 228 xe4   *  */
	__le32  ProbeMuxAddr;		       	/* 232 xe8   *  */
	__le32  ProbeMuxData;		       	/* 236 xec   *  */
	__le32  ERMQueueBaseAddr0;	       	/* 240 xf0   *  */
	__le32  ERMQueueBaseAddr1;	       	/* 244 xf4   *  */
	__le32  MACConfiguration;	       	/* 248 xf8   *  */
	__le32  port_err_status;	       	/* 252 xfc  COR */
} PORT_CTRL_STAT_REGS, *PPORT_CTRL_STAT_REGS;

typedef struct _HOST_MEM_CFG_REGS {
	__le32  NetRequestQueueOut;	       	   /*  80 x50   *  */
	__le32  NetRequestQueueOutAddrHi;      	   /*  84 x54   *  */
	__le32  NetRequestQueueOutAddrLow;     	   /*  88 x58   *  */
	__le32  NetRequestQueueBaseAddrHi;     	   /*  92 x5c   *  */
	__le32  NetRequestQueueBaseAddrLow;    	   /*  96 x60   *  */
	__le32  NetRequestQueueLength;	       	   /* 100 x64   *  */
	__le32  NetResponseQueueIn;	       	   /* 104 x68   *  */
	__le32  NetResponseQueueInAddrHi;      	   /* 108 x6c   *  */
	__le32  NetResponseQueueInAddrLow;     	   /* 112 x70   *  */
	__le32  NetResponseQueueBaseAddrHi;    	   /* 116 x74   *  */
	__le32  NetResponseQueueBaseAddrLow;   	   /* 120 x78   *  */
	__le32  NetResponseQueueLength;	       	   /* 124 x7c   *  */
	__le32  req_q_out;	       	       	   /* 128 x80   *  */
	__le32  RequestQueueOutAddrHi;	       	   /* 132 x84   *  */
	__le32  RequestQueueOutAddrLow;	       	   /* 136 x88   *  */
	__le32  RequestQueueBaseAddrHi;	       	   /* 140 x8c   *  */
	__le32  RequestQueueBaseAddrLow;       	   /* 144 x90   *  */
	__le32  RequestQueueLength;	       	   /* 148 x94   *  */
	__le32  ResponseQueueIn;	       	   /* 152 x98   *  */
	__le32  ResponseQueueInAddrHi;	       	   /* 156 x9c   *  */
	__le32  ResponseQueueInAddrLow;	       	   /* 160 xa0   *  */
	__le32  ResponseQueueBaseAddrHi;       	   /* 164 xa4   *  */
	__le32  ResponseQueueBaseAddrLow;      	   /* 168 xa8   *  */
	__le32  ResponseQueueLength;	       	   /* 172 xac   *  */
	__le32  NetRxLargeBufferQueueOut;      	   /* 176 xb0   *  */
	__le32  NetRxLargeBufferQueueBaseAddrHi;   /* 180 xb4   *  */
	__le32  NetRxLargeBufferQueueBaseAddrLow;  /* 184 xb8   *  */
	__le32  NetRxLargeBufferQueueLength;   	   /* 188 xbc   *  */
	__le32  NetRxLargeBufferLength;	       	   /* 192 xc0   *  */
	__le32  NetRxSmallBufferQueueOut;      	   /* 196 xc4   *  */
	__le32  NetRxSmallBufferQueueBaseAddrHi;   /* 200 xc8   *  */
	__le32  NetRxSmallBufferQueueBaseAddrLow;  /* 204 xcc   *  */
	__le32  NetRxSmallBufferQueueLength;   	   /* 208 xd0   *  */
	__le32  NetRxSmallBufferLength;	       	   /* 212 xd4   *  */
	__le32  HMCReserved0[10];	       	   /* 216 xd8   *  */
} HOST_MEM_CFG_REGS, *PHOST_MEM_CFG_REGS;

typedef struct _LOCAL_RAM_CFG_REGS {
	__le32  BufletSize;		       	/*  80 x50   *  */
	__le32  BufletMaxCount;		       	/*  84 x54   *  */
	__le32  BufletCurrCount;	       	/*  88 x58   *  */
	__le32  BufletPauseThresholdCount;     	/*  92 x5c   *  */
	__le32  BufletTCPWinThresholdHi;       	/*  96 x60   *  */
	__le32  BufletTCPWinThresholdLow;      	/* 100 x64   *  */
	__le32  IPHashTableBaseAddr;	       	/* 104 x68   *  */
	__le32  IPHashTableSize;	       	/* 108 x6c   *  */
	__le32  TCPHashTableBaseAddr;	       	/* 112 x70   *  */
	__le32  TCPHashTableSize;	       	/* 116 x74   *  */
	__le32  NCBAreaBaseAddr;	       	/* 120 x78   *  */
	__le32  NCBMaxCount;		       	/* 124 x7c   *  */
	__le32  NCBCurrCount;		       	/* 128 x80   *  */
	__le32  DRBAreaBaseAddr;	       	/* 132 x84   *  */
	__le32  DRBMaxCount;		       	/* 136 x88   *  */
	__le32  DRBCurrCount;		       	/* 140 x8c   *  */
	__le32  LRCReserved[28];	       	/* 144 x90   *  */
} LOCAL_RAM_CFG_REGS, *PLOCAL_RAM_CFG_REGS;

typedef struct _PROT_STAT_REGS {
	__le32  MACTxFrameCount;	       /*  80 x50   R   */
	__le32  MACTxByteCount;		       /*  84 x54   R   */
	__le32  MACRxFrameCount;	       /*  88 x58   R   */
	__le32  MACRxByteCount;		       /*  92 x5c   R   */
	__le32  MACCRCErrCount;		       /*  96 x60   R   */
	__le32  MACEncErrCount;		       /* 100 x64   R   */
	__le32  MACRxLengthErrCount;	       /* 104 x68   R   */
	__le32  IPTxPacketCount;	       /* 108 x6c   R   */
	__le32  IPTxByteCount;		       /* 112 x70   R   */
	__le32  IPTxFragmentCount;	       /* 116 x74   R   */
	__le32  IPRxPacketCount;	       /* 120 x78   R   */
	__le32  IPRxByteCount;		       /* 124 x7c   R   */
	__le32  IPRxFragmentCount;	       /* 128 x80   R   */
	__le32  IPDatagramReassemblyCount;     /* 132 x84   R   */
	__le32  IPV6RxPacketCount;	       /* 136 x88   R   */
	__le32  IPErrPacketCount;	       /* 140 x8c   R   */
	__le32  IPReassemblyErrCount;	       /* 144 x90   R   */
	__le32  TCPTxSegmentCount;	       /* 148 x94   R   */
	__le32  TCPTxByteCount;		       /* 152 x98   R   */
	__le32  TCPRxSegmentCount;	       /* 156 x9c   R   */
	__le32  TCPRxByteCount;		       /* 160 xa0   R   */
	__le32  TCPTimerExpCount;	       /* 164 xa4   R   */
	__le32  TCPRxAckCount;		       /* 168 xa8   R   */
	__le32  TCPTxAckCount;		       /* 172 xac   R   */
	__le32  TCPRxErrOOOCount;	       /* 176 xb0   R   */
	__le32  PSReserved0;		       /* 180 xb4   *   */
	__le32  TCPRxWindowProbeUpdateCount;   /* 184 xb8   R   */
	__le32  ECCErrCorrectionCount;	       /* 188 xbc   R   */
	__le32  PSReserved1[16];	       /* 192 xc0   *   */
} PROT_STAT_REGS, *PPROT_STAT_REGS;

#define MBOX_REG_COUNT                          8

/* remote register set (access via PCI memory read/write) */
typedef struct isp_reg_t {
	__le32 mailbox[MBOX_REG_COUNT];

	__le32 flash_address;				/* 0x20 */
	__le32 flash_data;
	__le32 ctrl_status;

	union {
		struct {
			__le32 nvram;
			__le32 reserved1[2];		/* 0x30 */
		} __attribute__((packed)) isp4010;
		struct {
			__le32 intr_mask;
			__le32 nvram;			/* 0x30 */
			__le32 semaphore;
		} __attribute__((packed)) isp4022;
	} u1;

	
	__le32 req_q_in;  /* SCSI Request Queue Producer Index */
	__le32 rsp_q_out; /* SCSI Completion Queue Consumer Index */

	__le32 reserved2[4];				/* 0x40 */

	union {
		struct {
			__le32 ext_hw_conf;		/* 0x50 */
			__le32 flow_ctrl;
			__le32 port_ctrl;
			__le32 port_status;

			__le32 reserved3[8];		/* 0x60 */

			__le32 req_q_out;		/* 0x80 */

			__le32 reserved4[23];		/* 0x84 */

			__le32 gp_out;		/* 0xe0 */
			__le32 gp_in;

			__le32 reserved5[5];

			__le32 port_err_status;	/* 0xfc */
		} __attribute__((packed)) isp4010;
		struct {
			union {
				PORT_CTRL_STAT_REGS p0;
				HOST_MEM_CFG_REGS   p1;
				LOCAL_RAM_CFG_REGS  p2;
				PROT_STAT_REGS	    p3;
				uint32_t  r_union[44];
			};

		} __attribute__((packed)) isp4022;
	} u2;
} isp_reg_t;	/* 256 x100 */

#define ISP_SEMAPHORE(ha) \
	(IS_QLA4010(ha) ? \
	 &ha->reg->u1.isp4010.nvram : \
	 &ha->reg->u1.isp4022.semaphore)

#define ISP_NVRAM(ha) \
	(IS_QLA4010(ha) ? \
	 &ha->reg->u1.isp4010.nvram : \
	 &ha->reg->u1.isp4022.nvram)

#define ISP_EXT_HW_CONF(ha) \
	(IS_QLA4010(ha) ? \
	 &ha->reg->u2.isp4010.ext_hw_conf : \
	 &ha->reg->u2.isp4022.p0.ext_hw_conf)

#define ISP_PORT_STATUS(ha) \
	(IS_QLA4010(ha) ? \
	 &ha->reg->u2.isp4010.port_status : \
	 &ha->reg->u2.isp4022.p0.port_status)

#define ISP_PORT_CTRL(ha) \
	(IS_QLA4010(ha) ? \
	 &ha->reg->u2.isp4010.port_ctrl : \
	 &ha->reg->u2.isp4022.p0.port_ctrl)

#define ISP_REQ_Q_OUT(ha) \
	(IS_QLA4010(ha) ? \
	 &ha->reg->u2.isp4010.req_q_out : \
	 &ha->reg->u2.isp4022.p1.req_q_out)

#define ISP_PORT_ERROR_STATUS(ha) \
	(IS_QLA4010(ha) ? \
	 &ha->reg->u2.isp4010.port_err_status : \
	 &ha->reg->u2.isp4022.p0.port_err_status)

#define ISP_GP_OUT(ha) \
	(IS_QLA4010(ha) ? \
	 &ha->reg->u2.isp4010.gp_out : \
	 &ha->reg->u2.isp4022.p0.gp_out)

#define ISP_GP_IN(ha) \
	(IS_QLA4010(ha) ? \
	 &ha->reg->u2.isp4010.gp_in : \
	 &ha->reg->u2.isp4022.p0.gp_in)

/* Semaphore Defines for 4010 */
#define QL4010_DRVR_SEM_BITS    0x00000030
#define QL4010_GPIO_SEM_BITS    0x000000c0
#define QL4010_SDRAM_SEM_BITS   0x00000300
#define QL4010_PHY_SEM_BITS     0x00000c00
#define QL4010_NVRAM_SEM_BITS   0x00003000
#define QL4010_FLASH_SEM_BITS   0x0000c000

#define QL4010_DRVR_SEM_MASK    0x00300000
#define QL4010_GPIO_SEM_MASK    0x00c00000
#define QL4010_SDRAM_SEM_MASK   0x03000000
#define QL4010_PHY_SEM_MASK     0x0c000000
#define	QL4010_NVRAM_SEM_MASK	0x30000000
#define QL4010_FLASH_SEM_MASK   0xc0000000


/* Semaphore Defines for 4022 */
#define QL4022_RESOURCE_MASK_BASE_CODE 0x7
#define QL4022_RESOURCE_BITS_BASE_CODE 0x4

#define QL4022_DRVR_SEM_BITS    (QL4022_RESOURCE_BITS_BASE_CODE << 1)
#define QL4022_DDR_RAM_SEM_BITS (QL4022_RESOURCE_BITS_BASE_CODE << 4)
#define QL4022_PHY_GIO_SEM_BITS (QL4022_RESOURCE_BITS_BASE_CODE << 7)
#define QL4022_NVRAM_SEM_BITS   (QL4022_RESOURCE_BITS_BASE_CODE << 10)
#define QL4022_FLASH_SEM_BITS   (QL4022_RESOURCE_BITS_BASE_CODE << 13)

#define QL4022_DRVR_SEM_MASK    (QL4022_RESOURCE_MASK_BASE_CODE << (1+16))
#define QL4022_DDR_RAM_SEM_MASK (QL4022_RESOURCE_MASK_BASE_CODE << (4+16))
#define QL4022_PHY_GIO_SEM_MASK (QL4022_RESOURCE_MASK_BASE_CODE << (7+16))
#define QL4022_NVRAM_SEM_MASK   (QL4022_RESOURCE_MASK_BASE_CODE << (10+16))
#define QL4022_FLASH_SEM_MASK   (QL4022_RESOURCE_MASK_BASE_CODE << (13+16))


#define QL4XXX_LOCK_FLASH(a)    \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_spinlock(a, QL4010_FLASH_SEM_MASK, QL4010_FLASH_SEM_BITS) : \
	ql4xxx_sem_spinlock(a, QL4022_FLASH_SEM_MASK, (QL4022_RESOURCE_BITS_BASE_CODE | (a->mac_index)) << 13) )

#define QL4XXX_LOCK_NVRAM(a)    \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_spinlock(a, QL4010_NVRAM_SEM_MASK, QL4010_NVRAM_SEM_BITS) : \
	ql4xxx_sem_spinlock(a, QL4022_NVRAM_SEM_MASK, (QL4022_RESOURCE_BITS_BASE_CODE | (a->mac_index)) << 10) )

#define QL4XXX_LOCK_GIO(a) \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_spinlock(a, QL4010_GPIO_SEM_MASK, QL4010_GPIO_SEM_BITS) : \
	ql4xxx_sem_spinlock(a, QL4022_PHY_GIO_SEM_MASK, (QL4022_RESOURCE_BITS_BASE_CODE | (a->mac_index)) << 7) )

#define QL4XXX_LOCK_PHY(a) \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_spinlock(a, QL4010_PHY_SEM_MASK, QL4010_PHY_SEM_BITS) : \
	ql4xxx_sem_spinlock(a, QL4022_PHY_GIO_SEM_MASK, (QL4022_RESOURCE_BITS_BASE_CODE | (a->mac_index)) << 7) )

#define QL4XXX_LOCK_DDR_RAM(a)  \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_spinlock(a, QL4010_SDRAM_SEM_MASK, QL4010_SDRAM_SEM_BITS) : \
	ql4xxx_sem_spinlock(a, QL4022_DDR_RAM_SEM_MASK, (QL4022_RESOURCE_BITS_BASE_CODE | (a->mac_index)) << 4) )

#define QL4XXX_LOCK_DRVR(a)  \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_lock(a, QL4010_DRVR_SEM_MASK, QL4010_DRVR_SEM_BITS) : \
	ql4xxx_sem_lock(a, QL4022_DRVR_SEM_MASK, (QL4022_RESOURCE_BITS_BASE_CODE | (a->mac_index)) << 1) )

#define QL4XXX_UNLOCK_DRVR(a) \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_unlock(a, QL4010_DRVR_SEM_MASK) : \
	ql4xxx_sem_unlock(a, QL4022_DRVR_SEM_MASK) )

#define QL4XXX_UNLOCK_GIO(a) \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_unlock(a, QL4010_GPIO_SEM_MASK) : \
	ql4xxx_sem_unlock(a, QL4022_PHY_GIO_SEM_MASK) )

#define QL4XXX_UNLOCK_DDR_RAM(a)  \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_unlock(a, QL4010_SDRAM_SEM_MASK) : \
	ql4xxx_sem_unlock(a, QL4022_DDR_RAM_SEM_MASK) )

#define QL4XXX_UNLOCK_PHY(a) \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_unlock(a, QL4010_PHY_SEM_MASK) : \
	ql4xxx_sem_unlock(a, QL4022_PHY_GIO_SEM_MASK) )

#define QL4XXX_UNLOCK_NVRAM(a) \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_unlock(a, QL4010_NVRAM_SEM_MASK) : \
	ql4xxx_sem_unlock(a, QL4022_NVRAM_SEM_MASK) )

#define QL4XXX_UNLOCK_FLASH(a)  \
	(IS_QLA4010(a) ? \
	ql4xxx_sem_unlock(a, QL4010_FLASH_SEM_MASK) : \
	ql4xxx_sem_unlock(a, QL4022_FLASH_SEM_MASK) )


/* Page # defines for 4022 */
#define PORT_CTRL_STAT_PAGE                     0 /* 4022 */
#define HOST_MEM_CFG_PAGE                       1 /* 4022 */
#define LOCAL_RAM_CFG_PAGE                      2 /* 4022 */
#define PROT_STAT_PAGE                          3 /* 4022 */

/* Register Mask - sets corresponding mask bits in the upper word */
#define SET_RMASK(val)	((val & 0xffff) | (val << 16))
#define CLR_RMASK(val)	(0 | (val << 16))

/* ctrl_status definitions */
#define CSR_SCSI_PAGE_SELECT                    0x00000003
#define CSR_SCSI_INTR_ENABLE                    0x00000004 /* 4010 */
#define CSR_SCSI_RESET_INTR                     0x00000008
#define CSR_SCSI_COMPLETION_INTR                0x00000010
#define CSR_SCSI_PROCESSOR_INTR                 0x00000020
#define CSR_INTR_RISC                           0x00000040
#define CSR_BOOT_ENABLE                         0x00000080
#define CSR_NET_PAGE_SELECT                     0x00000300 /* 4010 */
#define CSR_NET_INTR_ENABLE                     0x00000400 /* 4010 */
#define CSR_FUNC_NUM                            0x00000700 /* 4022 */
#define CSR_PCI_FUNC_NUM_MASK                   0x00000300 /* 4022 */
#define CSR_NET_RESET_INTR                      0x00000800 /* 4010 */
#define CSR_NET_COMPLETION_INTR                 0x00001000 /* 4010 */
#define CSR_FORCE_SOFT_RESET                    0x00002000 /* 4022 */
#define CSR_FATAL_ERROR                         0x00004000
#define CSR_SOFT_RESET                          0x00008000
#define ISP_CONTROL_FN_MASK     		CSR_FUNC_NUM
#define ISP_CONTROL_FN0_NET     		0x0400
#define ISP_CONTROL_FN0_SCSI    		0x0500
#define ISP_CONTROL_FN1_NET     		0x0600
#define ISP_CONTROL_FN1_SCSI    		0x0700

#define INTR_PENDING                            (CSR_SCSI_COMPLETION_INTR \
						| CSR_SCSI_PROCESSOR_INTR \
						| CSR_SCSI_RESET_INTR)

/* ISP InterruptMask definitions */
#define IMR_SCSI_INTR_ENABLE                    0x00000004  /* 4022 */

/* ISP 4022 nvram definitions */
#define NVR_WRITE_ENABLE			0x00000010  /* 4022 */

/* ISP port_ctrl definitions */
#define PCR_CONFIG_COMPLETE			0x00008000  /* 4022 */
#define PCR_BIOS_BOOTED_FIRMWARE		0x00008000  /* 4010 */
#define PCR_ENABLE_SERIAL_DATA			0x00001000  /* 4010 */
#define PCR_SERIAL_DATA_OUT			0x00000800  /* 4010 */
#define PCR_ENABLE_SERIAL_CLOCK			0x00000400  /* 4010 */
#define PCR_SERIAL_CLOCK			0x00000200  /* 4010 */

/* ISP port_status definitions */
#define PSR_CONFIG_COMPLETE			0x00000001  /* 4010 */
#define PSR_INIT_COMPLETE			0x00000200

/* ISP Semaphore definitions */
#define SR_FIRWMARE_BOOTED			0x00000001

/* shadow registers (DMA'd from HA to system memory.  read only) */
typedef struct {
	/* SCSI Request Queue Consumer Index */
	__le32   req_q_out;	/* 0 x0   R  */

	/* SCSI Completion Queue Producer Index */
	__le32   rsp_q_in;	/* 4 x4   R  */
} shadow_regs_t;		/* 8 x8	     */

#define EHWC_PROT_METHOD_NONE                         0
#define EHWC_PROT_METHOD_BYTE_PARITY                  1
#define EHWC_PROT_METHOD_ECC                          2
#define EHWC_SDRAM_BANKS_1                            0
#define EHWC_SDRAM_BANKS_2                            1
#define EHWC_SDRAM_WIDTH_8_BIT                        0
#define EHWC_SDRAM_WIDTH_16_BIT                       1
#define EHWC_SDRAM_CHIP_SIZE_64MB                     0
#define EHWC_SDRAM_CHIP_SIZE_128MB                    1
#define EHWC_SDRAM_CHIP_SIZE_256MB                    2
#define EHWC_MEM_TYPE_SYNC_FLOWTHROUGH                0
#define EHWC_MEM_TYPE_SYNC_PIPELINE                   1
#define EHWC_WRITE_BURST_512                          0
#define EHWC_WRITE_BURST_1024                         1
#define EHWC_WRITE_BURST_2048                         2
#define EHWC_WRITE_BURST_4096                         3

/* External hardware configuration register */
typedef union _EXTERNAL_HW_CONFIG_REG {
	struct {
		uint32_t  bReserved0                :1;
		uint32_t  bSDRAMProtectionMethod    :2;
		uint32_t  bSDRAMBanks               :1;
		uint32_t  bSDRAMChipWidth           :1;
		uint32_t  bSDRAMChipSize            :2;
		uint32_t  bParityDisable            :1;
		uint32_t  bExternalMemoryType       :1;
		uint32_t  bFlashBIOSWriteEnable     :1;
		uint32_t  bFlashUpperBankSelect     :1;
		uint32_t  bWriteBurst               :2;
		uint32_t  bReserved1                :3;
		uint32_t  bMask                     :16;
	};
	uint32_t   AsUINT32;
} EXTERNAL_HW_CONFIG_REG, *PEXTERNAL_HW_CONFIG_REG;

/*************************************************************************
 *
 *		Mailbox Commands Structures and Definitions
 *
 *************************************************************************/

/* Mailbox command definitions */
#define MBOX_CMD_LOAD_RISC_RAM_EXT              0x0001
#define MBOX_CMD_EXECUTE_FW                     0x0002
#define MBOX_CMD_DUMP_RISC_RAM_EXT              0x0003
#define MBOX_CMD_WRITE_RISC_RAM_EXT             0x0004
#define MBOX_CMD_READ_RISC_RAM_EXT              0x0005
#define MBOX_CMD_REGISTER_TEST                  0x0006
#define MBOX_CMD_VERIFY_CHECKSUM                0x0007
#define MBOX_CMD_ABOUT_FW                       0x0009
#define MBOX_CMD_LOOPBACK_DIAG                  0x000A
#define MBOX_CMD_PING                           0x000B
		#define PING_IPV6				0x00000001
		#define PING_SECONDARY_ACB			0x00000002
		#define PING_LOCAL_IPV6_MASK			0x0000000C
		#define PING_LOCAL_IPV6_MASK_DONT_CARE		0x00000000
		#define PING_LOCAL_IPV6_MASK_LINK_LOCAL		0x00000004
		#define PING_LOCAL_IPV6_MASK_ADDR0		0x00000008
		#define PING_LOCAL_IPV6_MASK_ADDR1		0x0000000C
		#define PING_NEIGHBOR_DISC_ONLY			0x00010000
#define MBOX_CMD_CHECKSUM_FW                    0x000E
#define MBOX_CMD_RESET_FW                       0x0014
#define MBOX_CMD_ABORT_TASK                     0x0015
#define MBOX_CMD_LUN_RESET                      0x0016
#define MBOX_CMD_TARGET_WARM_RESET              0x0017
#define MBOX_CMD_TARGET_COLD_RESET              0x0018
#define MBOX_CMD_ABORT_QUEUE                    0x001C
#define MBOX_CMD_GET_QUEUE_STATUS               0x001D
#define MBOX_CMD_GET_MANAGEMENT_DATA            0x001E
#define MBOX_CMD_GET_FW_STATUS                  0x001F
#define MBOX_CMD_SET_ISNS_SERVICE               0x0021
		#define ISNS_DISABLE                            0
		#define ISNS_ENABLE                             1
		#define ISNS_STATUS                             2 /* Not working */
		#define ISNSv6_ENABLE                           3
#define MBOX_CMD_COPY_FLASH                     0x0024
		#define COPY_FLASH_OPTION_PRIM_TO_SEC           0
		#define COPY_FLASH_OPTION_SEC_TO_PRIM           1
#define MBOX_CMD_WRITE_FLASH                    0x0025
		#define WRITE_FLASH_OPTION_HOLD_DATA            0
		#define WRITE_FLASH_OPTION_COMMIT_DATA          2
		#define WRITE_FLASH_OPTION_FLASH_DATA    	3
#define MBOX_CMD_READ_FLASH                     0x0026
#define MBOX_CMD_GET_QUEUE_PARAMS               0x0029
#define MBOX_CMD_CLEAR_DATABASE_ENTRY           0x0031
#define MBOX_CMD_SET_QUEUE_PARAMS               0x0039
#define MBOX_CMD_CONN_CLOSE_SESS_LOGOUT         0x0056
		#define LOGOUT_OPTION_CLOSE_SESSION             0x01
		#define LOGOUT_OPTION_RELOGIN                   0x02
#define MBOX_CMD_EXECUTE_IOCB_A64		0x005A
#define MBOX_CMD_INITIALIZE_FIRMWARE            0x0060
#define MBOX_CMD_GET_INIT_FW_CTRL_BLOCK         0x0061
#define MBOX_CMD_REQUEST_DATABASE_ENTRY         0x0062
#define MBOX_CMD_SET_DATABASE_ENTRY             0x0063					
#define MBOX_CMD_GET_DATABASE_ENTRY             0x0064
		#define DDB_DS_UNASSIGNED                       0x00
		#define DDB_DS_NO_CONNECTION_ACTIVE             0x01
		#define DDB_DS_DISCOVERY                        0x02
		#define DDB_DS_NO_SESSION_ACTIVE                0x03
		#define DDB_DS_SESSION_ACTIVE                   0x04
		#define DDB_DS_LOGGING_OUT                      0x05
		#define DDB_DS_SESSION_FAILED                   0x06
		#define DDB_DS_LOGIN_IN_PROCESS                 0x07
		#define DELETEABLE_DDB_DS(ds) ((ds == DDB_DS_UNASSIGNED) || \
		                               (ds == DDB_DS_NO_CONNECTION_ACTIVE) || \
					       (ds == DDB_DS_SESSION_FAILED))
#define MBOX_CMD_CLEAR_ACA                      0x0065
#define MBOX_CMD_CLEAR_TASK_SET                 0x0067
#define MBOX_CMD_ABORT_TASK_SET                 0x0068
#define MBOX_CMD_GET_FW_STATE                   0x0069

/* Mailbox 1 */
		#define FW_STATE_READY                          0x00000000
		#define FW_STATE_CONFIG_WAIT                    0x00000001
		#define FW_STATE_WAIT_AUTOCONNECT               0x00000002
		#define FW_STATE_ERROR                          0x00000004
		#define FW_STATE_DHCPv4_IN_PROGRESS		0x00000008
		#define FW_STATE_WAIT_ACTIVATE_PRI_ACB          0x00000010
		#define FW_STATE_WAIT_ACTIVATE_SEC_ACB          0x00000020

/* Mailbox 3 */
		#define FW_ADDSTATE_COPPER_MEDIA                0x00000000
		#define FW_ADDSTATE_OPTICAL_MEDIA               0x00000001
		#define	FW_ADDSTATE_DHCPv4_ENABLED		0x00000002
		#define	FW_ADDSTATE_DHCPv4_LEASE_ACQUIRED	0x00000004
		#define	FW_ADDSTATE_DHCPv4_LEASE_EXPIRED	0x00000008
		#define FW_ADDSTATE_LINK_UP                     0x00000010
		#define FW_ADDSTATE_ISNSv4_SVC_ENABLED          0x00000020
		#define FW_ADDSTATE_LINK_SPEED_10MBPS     	0x00000100
		#define FW_ADDSTATE_LINK_SPEED_100MBPS     	0x00000200
		#define FW_ADDSTATE_LINK_SPEED_1000MBPS     	0x00000400
		#define FW_ADDSTATE_HALF_DUPLEX     		0x00001000
		#define FW_ADDSTATE_FULL_DUPLEX     		0x00002000
		#define FW_ADDSTATE_FLOW_CTRL_ENABLED  		0x00004000
		#define FW_ADDSTATE_AUTONEG_ENABLED  		0x00008000
		#define FW_ADDSTATE_FW_CTRLS_PORT_LINK  	0x00010000
		#define FW_ADDSTATE_PAUSE_TX_ENABLED  		0x00020000
		#define FW_ADDSTATE_PAUSE_RX_ENABLED  		0x00040000
		#define FW_ADDSTATE_IPV4_PRI_ENABLED  		0x00080000
		#define FW_ADDSTATE_IPV4_SEC_ENABLED  		0x00100000
		#define FW_ADDSTATE_IPV6_PRI_ENABLED  		0x00200000
		#define FW_ADDSTATE_IPV6_SEC_ENABLED  		0x00400000
		#define FW_ADDSTATE_DHCPV6_ENABLED  		0x00800000
		#define FW_ADDSTATE_IPV6_AUTOCONFIG_ENABLED  	0x01000000
		#define FW_ADDSTATE_IPV6_ADDR0_STATE  		0x02000000
		#define FW_ADDSTATE_IPV6_ADDR0_EXPIRED  	0x04000000
		#define FW_ADDSTATE_IPV6_ADDR1_STATE  		0x08000000
		#define FW_ADDSTATE_IPV6_ADDR1_EXPIRED  	0x10000000
#define MBOX_CMD_GET_INIT_FW_CTRL_BLOCK_DEFAULTS 0x006A
#define MBOX_CMD_GET_DATABASE_ENTRY_DEFAULTS    0x006B
#define MBOX_CMD_CONN_OPEN_SESS_LOGIN           0x0074
#define MBOX_CMD_DIAGNOSTICS_TEST_RESULTS       0x0075	/* 4010 only */
		#define DIAG_TEST_LOCAL_RAM_SIZE		0x0002
		#define DIAG_TEST_LOCAL_RAM_READ_WRITE		0x0003
		#define DIAG_TEST_RISC_RAM			0x0004
		#define DIAG_TEST_NVRAM				0x0005
		#define DIAG_TEST_FLASH_ROM			0x0006
		#define DIAG_TEST_NW_INT_LOOPBACK		0x0007
		#define DIAG_TEST_NW_EXT_LOOPBACK		0x0008
#define MBOX_CMD_GET_CRASH_RECORD       	0x0076	/* 4010 only */
#define MBOX_CMD_GET_CONN_EVENT_LOG       	0x0077
#define MBOX_CMD_RESTORE_FACTORY_DEFAULTS      	0x0087
#define MBOX_CMD_SET_ACB                        0x0088
		#define ACB_PARAM_ERR_INVALID_VALUE		0x0001
		#define ACB_PARAM_ERR_INVALID_SIZE		0x0002
		#define ACB_PARAM_ERR_INVALID_ADDR		0x0003
#define MBOX_CMD_GET_ACB                        0x0089
#define MBOX_CMD_DISABLE_ACB                    0x008A
		#define ACB_CMD_OPTION_NOT_FORCED		0x0000
		#define ACB_CMD_OPTION_FORCED			0x0001
#define MBOX_CMD_GET_IPV6_NEIGHBOR_CACHE        0x008B
#define MBOX_CMD_GET_IPV6_DEST_CACHE            0x008C
#define MBOX_CMD_GET_IPV6_DEF_ROUTER_LIST       0x008D
#define MBOX_CMD_GET_IPV6_LCL_PREFIX_LIST       0x008E
#define MBOX_CMD_CONTROL_NEW_CONNS              0x008F
#define MBOX_CMD_SET_IPV6_NEIGHBOR_CACHE	0x0090
#define MBOX_CMD_GET_IP_ADDR_STATE		0x0091
		/* Incoming Mailbox 2 */
		#define IP_INDEX_IPv4		0
		#define IP_INDEX_IPv6_LINK_LOCAL 0
		#define IP_INDEX_IPv6_ADDR0	0
		#define IP_INDEX_IPv6_ADDR1	0
		
		/* Outgoing Mailbox 1 */
		#define ACB_STATE_ENABLED			0x0000
		#define ACB_STATE_DISABLED			0x0001
		#define ACB_STATE_DISABLING			0x0002
		#define ACB_STATE_WAITING_FOR_INIT		0x0003
		
		/* Outgoing Mailboxes 2 & 3 */
		#define ACB_CS_NOT_CONFIGURED			0x0000
		#define ACB_CS_ACTIVE				0x0001
		#define ACB_CS_ACCEPTING_NEW_CONNECTIONS      	0x0002
		#define ACB_CS_DISABLED_VIA_ACB               	0x0010
		#define ACB_CS_DHCP_LEASE_EXPIRED             	0x0020
		#define ACB_CS_DHCP_WAITING_TO_ACQUIRE_LEASE  	0x0100
		#define ACB_CS_DHCP_WAITING_FOR_NEIGHBOR_DISC 	0x0200
		#define ACB_CS_DHCP_WAITING_FOR_VALIDATION    	0x0400
		#define ACB_CS_CONFIG_ERROR                   	0x8000
#define MBOX_CMD_SEND_IPV6_ROUTER_SOL		0x0092
#define MBOX_CMD_GET_DATABASE_ENTRY_CURRENT_IP_ADDR	0x0093
#define MBOX_CMD_NOP                            0x00FF

/* Mailbox status definitions */
#define MBOX_COMPLETION_STATUS			4
#define MBOX_STS_BUSY                           0x0007
#define MBOX_STS_INTERMEDIATE_COMPLETION    	0x1000
#define MBOX_STS_COMMAND_COMPLETE               0x4000
#define MBOX_STS_INVALID_COMMAND                0x4001
#define MBOX_STS_HOST_INTERFACE_ERROR           0x4002
#define MBOX_STS_TEST_FAILED                    0x4003
#define MBOX_STS_COMMAND_ERROR                  0x4005
#define MBOX_STS_COMMAND_PARAMETER_ERROR        0x4006
#define MBOX_STS_TARGET_MODE_INIT_FAIL          0x4007
#define MBOX_STS_INITIATOR_MODE_INIT_FAIL       0x4008

#define MBOX_ASYNC_EVENT_STATUS			8
#define MBOX_ASTS_SYSTEM_ERROR                  0x8002
#define MBOX_ASTS_REQUEST_TRANSFER_ERROR        0x8003
#define MBOX_ASTS_RESPONSE_TRANSFER_ERROR       0x8004
#define MBOX_ASTS_PROTOCOL_STATISTIC_ALARM      0x8005
#define MBOX_ASTS_SCSI_COMMAND_PDU_REJECTED     0x8006
#define MBOX_ASTS_LINK_UP  			0x8010
#define MBOX_ASTS_LINK_DOWN			0x8011
#define MBOX_ASTS_DATABASE_CHANGED              0x8014
		/* Mailbox 5 */
		#define DDBCHG_EVENT_FLAG_IPv6_ADDR_MASK	0x000F
		#define DDBCHG_EVENT_FLAG_IPv4_ADDR		0x0001
		#define DDBCHG_EVENT_FLAG_IPv6_LINK_LOCAL_ADDR	0x0002
		#define DDBCHG_EVENT_FLAG_IPv6_ADDR0		0x0004
		#define DDBCHG_EVENT_FLAG_IPv6_ADDR1		0x0008
		#define DDBCHG_EVENT_FLAG_IPv6			0x0010
		#define DDBCHG_EVENT_FLAG_SECONDARY_ACB		0x0080
#define MBOX_ASTS_UNSOLICITED_PDU_RECEIVED      0x8015
#define MBOX_ASTS_SELF_TEST_FAILED      	0x8016
#define MBOX_ASTS_LOGIN_FAILED      		0x8017
#define MBOX_ASTS_DNS      			0x8018
#define MBOX_ASTS_HEARTBEAT      		0x8019
#define MBOX_ASTS_NVRAM_INVALID      		0x801A
#define MBOX_ASTS_MAC_ADDRESS_CHANGED      	0x801B
#define MBOX_ASTS_IP_ADDRESS_CHANGED      	0x801C
		/* mailbox 1 */
		#define PRIMARY_ACB				0
		#define SECONDARY_ACB				1
		/* mailbox 4 */
		#define IP_ADDR_CFG_NOT_CONFIGURED		00
		#define IP_ADDR_CFG_STATIC			01
		#define IP_ADDR_CFG_DHCP			02
		/* mailbox 5 */
		#define IP_INTERFACE_IPv4			00
		#define IP_INTERFACE_IPv6_LINK_LOCAL		01
		#define IP_INTERFACE_IPv_ADDR0			02
		#define IP_INTERFACE_IPv_ADDR1			03
		
#define MBOX_ASTS_DHCP_LEASE_EXPIRED      	0x801D
#define MBOX_ASTS_DHCP_LEASE_ACQUIRED           0x801F
#define MBOX_ASTS_ISNS_UNSOLICITED_PDU_RECEIVED 0x8021
		#define ISNS_EVENT_DATA_RECEIVED		0x0000
		#define ISNS_EVENT_CONNECTION_OPENED		0x0001
		#define ISNS_EVENT_CONNECTION_FAILED		0x0002
#define MBOX_ASTS_DUPLICATE_IP                  0x8025
#define MBOX_ASTS_ARP_COMPLETE                  0x8026
#define MBOX_ASTS_SUBNET_STATE_CHANGE		0x8027
#define MBOX_ASTS_RESPONSE_QUEUE_FULL           0x8028
#define MBOX_ASTS_IP_ADDR_STATE_CHANGED         0x8029
#define MBOX_ASTS_IPV6_PREFIX_EXPIRED           0x802B
#define MBOX_ASTS_IPV6_ND_PREFIX_IGNORED        0x802C
#define MBOX_ASTS_IPV6_LCL_PREFIX_IGNORED       0x802D
#define MBOX_ASTS_ICMPV6_ERROR_MSG_RCVD         0x802E


/*************************************************************************/

/* Host Adapter Initialization Control Block (from host) */
typedef struct _ADDRESS_CTRL_BLK {
	uint8_t   Version;			/* 00 */
   #define  IFCB_VERSION_NO_ADDITIONAL_INFO  0x00
   #define  IFCB_VER_MIN                     0x01
   #define  IFCB_VER_MAX                     0x02
	uint8_t   Control;			/* 01 */
   #define  FWCTRL_NEW_CONNECTIONS_DISABLE   0x02
   #define  FWCTRL_SECONDARY_ACB   	     0x01

	__le16  FwOptions;			/* 02-03 */
   #define  FWOPT_HEARTBEAT_ENABLE           0x1000
   #define  FWOPT_MARKER_DISABLE             0x0400
   #define  FWOPT_PROTOCOL_STAT_ALARM_ENABLE 0x0200
   #define  FWOPT_TARGET_ACCEPT_AEN_ENABLE   0x0100
   #define  FWOPT_ACCESS_CONTROL_ENABLE      0x0080
   #define  FWOPT_SESSION_MODE               0x0040
   #define  FWOPT_INITIATOR_MODE             0x0020
   #define  FWOPT_TARGET_MODE                0x0010
   #define  FWOPT_FAST_POSTING               0x0008
   #define  FWOPT_AUTO_TARGET_INFO_DISABLE   0x0004
   #define  FWOPT_SENSE_BUFFER_DATA_ENABLE   0x0002

	__le16    ExecThrottle;			/* 04-05 */
	uint8_t   ZIOCount;	  		/* 06    */
	uint8_t   Reserved0;	  		/* 07    */
	__le16    MaxEthFrPayloadSize;		/* 08-09 */
	__le16    AddFwOptions;			/* 0A-0B */
   #define  ADDFWOPT_AUTOCONNECT_DISABLE     0x0002
   #define  ADDFWOPT_SUSPEND_ON_FW_ERROR     0x0001

	uint8_t   HeartbeatInterval;		/* 0C */
	uint8_t   InstanceNumber;		/* 0D */
	uint16_t  Reserved1;		  	/* 0E-0F */
	__le16  ReqQConsumerIndex;		/* 10-11 */
	__le16  ComplQProducerIndex;		/* 12-13 */
	__le16  ReqQLen;			/* 14-15 */
	__le16  ComplQLen;			/* 16-17 */
	__le32  ReqQAddrLo;			/* 18-1B */
	__le32  ReqQAddrHi;			/* 1C-1F */
	__le32  ComplQAddrLo;			/* 20-23 */
	__le32  ComplQAddrHi;			/* 24-27 */
	__le32  ShadowRegBufAddrLo;		/* 28-2B */
	__le32  ShadowRegBufAddrHi;		/* 2C-2F */

	__le16    iSCSIOptions;			/* 30-31 */
   #define  IOPT_RCV_ISCSI_MARKER_ENABLE     0x8000
   #define  IOPT_SEND_ISCSI_MARKER_ENABLE    0x4000
   #define  IOPT_HEADER_DIGEST_ENABLE        0x2000
   #define  IOPT_DATA_DIGEST_ENABLE          0x1000
   #define  IOPT_IMMEDIATE_DATA_ENABLE       0x0800
   #define  IOPT_INITIAL_R2T_ENABLE          0x0400
   #define  IOPT_DATA_SEQ_IN_ORDER           0x0200
   #define  IOPT_DATA_PDU_IN_ORDER           0x0100
   #define  IOPT_CHAP_AUTH_ENABLE            0x0080
   #define  IOPT_SNACK_REQ_ENABLE            0x0040
   #define  IOPT_DISCOVERY_LOGOUT_ENABLE     0x0020
   #define  IOPT_BIDIR_CHAP_ENABLE     	     0x0010

	__le16  TCPOptions;			/* 32-33 */
   #define  TOPT_ISNS_ENABLE		     0x4000
   #define  TOPT_SLP_USE_DA_ENABLE	     0x2000
   #define  TOPT_AUTO_DISCOVERY_ENABLE       0x1000
   #define  TOPT_SLP_UA_ENABLE               0x0800
   #define  TOPT_SLP_SA_ENABLE               0x0400
   #define  TOPT_DHCP_ENABLE                 0x0200
   #define  TOPT_GET_DNS_VIA_DHCP_ENABLE     0x0100
   #define  TOPT_GET_SLP_VIA_DHCP_ENABLE     0x0080
   #define  TOPT_LEARN_ISNS_IP_ADDR_ENABLE   0x0040 /* Not supported */
   #define  TOPT_NAGLE_DISABLE               0x0020
   #define  TOPT_TIMER_SCALE_MASK            0x000E
   #define  TOPT_TIME_STAMP_ENABLE           0x0001

	__le16	IPOptions;	     		/* 34-35 IPv4 */
   #define  IPOPT_IPv4_PROTOCOL_ENABLE	     0x8000
   #define  IPOPT_IPv4_TOS_ENABLE	     0x4000
   #define  IPOPT_VLAN_TAGGING_ENABLE	     0x2000
   #define  IPOPT_ARP_GRAT_ENABLE	     0x1000
   #define  IPOPT_DHCP_USE_ALT_CLIENT_ID     0x0800
   #define  IPOPT_DHCP_REQUIRE_VENDOR_ID     0x0400
   #define  IPOPT_DHCP_USE_VENDOR_ID         0x0200
   #define  IPOPT_DHCP_LEARN_IQN             0x0100
   #define  IPOPT_FRAG_DISABLE               0x0010
   #define  IPOPT_INCOMING_FORWARDING_ENABLE 0x0008
   #define  IPOPT_ARP_REDIRECT_ENABLE	     0x0004
   #define  IPOPT_PAUSE_FRAME_ENABLE         0x0002
   #define  IPOPT_IP_ADDRESS_VALID           0x0001

	__le16    MaxPDUSize;			/* 36-37 */
	uint8_t   IPTypeOfSvc;   		/* 38-38 IPv4 */
	uint8_t   Reserved2;   			/* 39 */
	uint8_t   ACBVersion;   		/* 3A */
   #define ACB_NOT_SUPPORTED		    0x00
   #define ACB_SUPPORTED		    0x02

	uint8_t   Reserved12[3];   		/* 3B-3D */
	__le16    FirstBurstSize;		/* 3E-3F */
	__le16    DefaultTime2Wait;		/* 40-41 */
	__le16    DefaultTime2Retain;		/* 42-43 */
	__le16    MaxOutStndngR2T;		/* 44-45 */
	__le16    KeepAliveTimeout;		/* 46-47 */
	__le16    PortNumber;			/* 48-49 */
	__le16    MaxBurstSize;			/* 4A-4B */
	uint32_t  Reserved3;	        	/* 4C-4F */
	uint8_t   IPAddr[4];			/* 50-53 IPv4 */
	__le16    VLANTagCtrl;			/* 54-55 IPv4 */
	uint8_t   Reserved4[10];		/* 56-5F */
	uint8_t   SubnetMask[4];		/* 60-63 */
	uint8_t   Reserved5[12];		/* 64-6F */
	uint8_t   GatewayIPAddr[4];		/* 70-73 */
	uint8_t   Reserved6[12];		/* 74-7F */
	uint8_t   PriDNSIPAddr[4];		/* 80-83 */
	uint8_t   SecDNSIPAddr[4];		/* 84-87 */
	uint8_t   Reserved7[8];			/* 88-8F */
	uint8_t   iSCSIAlias[32];		/* 90-AF */
	uint8_t   Reserved8[22];		/* B0-C5 */
	__le16    TargetPortalGroup;		/* C6-C7 */
	uint8_t   AbortTimer;                   /* C8    */
	uint8_t   TCPWindowScaleFactor;       	/* C9    */
	uint8_t   Reserved9[6];                 /* CA-CF */
	uint8_t   SecIPAddr[4];			/* D0-D3 */
	uint8_t   DHCPVendorIDLen;        	/* D4    IPv4 */
	uint8_t   DHCPVendorID[11];           	/* D5-DF IPv4 */
	uint8_t   iSNSIPAddr[4];		/* E0-E3 */
	__le16    iSNSServerPortNumber;		/* E4-E5 */
	uint8_t   Reserved10[10];		/* E6-EF */
	uint8_t   SLPDAIPAddr[4];		/* F0-F3 */
	uint8_t   DHCPClientIDLen;            	/* F4    IPv4 */
	uint8_t   DHCPClientID[11];           	/* F5-FF IPv4 */
	uint8_t   iSCSINameString[224];   	/* 100-1DF */
	uint8_t   Reserved11[32];               /* 1e0-1FF */

  #define INIT_FW_CTRL_BLK_COOKIE            0x11BEAD5A
	uint32_t      Cookie;                   /* 200-203 */

  /* IPv6 section  */
	__le16    IPv6PortNumber;             	/* 204-205 */
	__le16    IPv6Options;            	/* 206-207 */
   #define IPV6_OPT_IPV6_PROTOCOL_ENABLE      0x8000
   #define IPV6_OPT_VLAN_TAG_ENABLE	      0x2000
   #define IPV6_OPT_GRAT_NEIGHBOR_AD_ENABLE   0x1000
   #define IPV6_OPT_INBOUND_FORWARDING_ENABLE 0x0008

	__le16    IPv6AddOptions;     		/* 208-209 */
   #define IPV6_ADDOPT_NEIGHBOR_DISCOVERY_ADDR_ENABLE    0x0002 /* Pri ACB Only */
   #define IPV6_ADDOPT_AUTOCONFIG_LINK_LOCAL_ADDR      	 0x0001
   	
	__le16    IPv6TCPOptions;     		/* 20A-20B */
   #define IPV6_TCPOPT_DELAYED_ACK_DISABLE	      	 0x8000
   #define IPV6_TCPOPT_ISNSv6_ENABLE	      	 	 0x4000
   #define IPV6_TCPOPT_TCP_WINDOW_SCALE	 		 0x0400
   #define IPV6_TCPOPT_NAGLE_DISABLE			 0x0020
   #define IPV6_TCPOPT_TCP_WINDOW_SCALE_DISABLE		 0x0010
   #define IPV6_TCPOPT_TIMER_SCALE			 0x000E
   #define IPV6_TCPOPT_TIME_STAMP_ENABLE		 0x0001

	uint8_t   IPv6TCPRcvScale;            	/* 20C 	   */
	uint8_t   IPv6FlowLabel[3];           	/* 20D-20F */
	uint8_t   GatewayIPv6Addr[16];        	/* 210-21F */
	uint8_t   IPv6VLANTCI[2];             	/* 220-221 */
	uint8_t   IPv6LinkLocalAddrState;       /* 222     */
	/* states also apply to ipv6_addr0 & ipv6_addr1 */
   #define IPV6_ADDRSTATE_UNCONFIGURED			0
   #define IPV6_ADDRSTATE_INVLID			1
   #define IPV6_ADDRSTATE_ACQUIRING			2
   #define IPV6_ADDRSTATE_TENTATIVE			3
   #define IPV6_ADDRSTATE_DEPRICATED			4
   #define IPV6_ADDRSTATE_PREFERRED			5
   #define IPV6_ADDRSTATE_DISABLING			6

	uint8_t   IPv6Addr0State;         	/* 223     */
	uint8_t   IPv6Addr1State;         	/* 224     */
	uint8_t   IPv6DefaultRouterState;       /* 225     */
	uint8_t   IPv6TrafficClass;         	/* 226     */
	uint8_t   IPv6HopLimit;         	/* 227     */
	uint8_t   IPv6InterfaceID[8];         	/* 228-22F */
	uint8_t   IPv6Addr0[16];               	/* 230-23F */
	uint8_t   IPv6Addr1[16];              	/* 240-24F */
	uint32_t  IPv6NDReachableTime;		/* 250-253 */
	uint32_t  IPv6NDRetransmitTimer;	/* 254-257 */
	uint32_t  IPv6NDStaleTimeout;		/* 258-25B */
	uint8_t   IPv6DuplicateAddressCount;	/* 25C     */
	uint8_t	IPv6CacheID;			/* 25D     */
	uint8_t	Reserved13[2];			/* 25E-25F */
	uint8_t	IPv6iSNSIPAddr[16];		/* 260-26F */
	uint8_t	IPv6RouterAdLinkMTUSize[4];	/* 270-273 */
	uint8_t	Reserved14[140];		/* 274-2FF */
} ADDRESS_CTRL_BLK, *PADDRESS_CTRL_BLK;         /* 300     */

#define ACB_PRIMARY	0x0000
#define ACB_SECONDARY	0x0001

typedef struct _INIT_FW_CTRL_BLK {
	ADDRESS_CTRL_BLK   pri_acb;
	ADDRESS_CTRL_BLK   sec_acb;
} INIT_FW_CTRL_BLK;

typedef struct {
	ADDRESS_CTRL_BLK init_fw_cb;
	uint32_t       Cookie;
	#define INIT_FW_CTRL_BLK_COOKIE 	0x11BEAD5A
} FLASH_INIT_FW_CTRL_BLK;

/*************************************************************************/

typedef struct _DEV_DB_ENTRY {
	__le16   options;	      		/* 00-01 */
   #define  DDB_OPT_IPv6_DEVICE		     0x0100
   #define  DDB_OPT_SECONDARY_IP_ACB         0x0020
   #define  DDB_OPT_DISABLE                  0x0008  /* do not connect to device */
   #define  DDB_OPT_ACCESSGRANTED            0x0004
   #define  DDB_OPT_TARGET                   0x0002  /* device is a target */
   #define  DDB_OPT_INITIATOR                0x0001  /* device is an initiator */

	__le16   exeThrottle;   		/* 02-03 */
	__le16   exeCount;      		/* 04-05 */
	uint8_t  retryCount;    		/* 06    */
	uint8_t  retryDelay;    		/* 07    */
	__le16   iSCSIOptions;  		/* 08-09 */
   #define DDB_IOPT_RECV_ISCSI_MARKER_ENABLE 0x8000
   #define DDB_IOPT_SEND_ISCSI_MARKER_ENABLE 0x4000
   #define DDB_IOPT_HEADER_DIGEST_ENABLE     0x2000
   #define DDB_IOPT_DATA_DIGEST_ENABLE       0x1000
   #define DDB_IOPT_IMMEDIATE_DATA_ENABLE    0x0800
   #define DDB_IOPT_INITIAL_R2T_ENABLE       0x0400
   #define DDB_IOPT_DATA_SEQUENCE_IN_ORDER   0x0200
   #define DDB_IOPT_DATA_PDU_IN_ORDER        0x0100
   #define DDB_IOPT_CHAP_AUTH_ENABLE         0x0080
   #define DDB_IOPT_BIDIR_CHAP_CHAL_ENABLE   0x0010
   #define DDB_IOPT_RESERVED2                0x007F

	__le16   TCPOptions;    		/* 0A-0B */
   #define DDB_TOPT_NAGLE_DISABLE            0x0020
   #define DDB_TOPT_TIMER_SCALE_MASK         0x000E
   #define DDB_TOPT_TIME_STAMP_ENABLE        0x0001

	__le16   IPOptions;     		/* 0C-0D */
   #define DDB_IPOPT_FRAG_DISABLE     	     0x0002
   #define DDB_IPOPT_IP_ADDRESS_VALID        0x0001

	__le16   maxPDUSize;    		/* 0E-0F */
	__le16   rcvMarkerInt;  		/* 10-11 */
	__le16   sndMarkerInt;  		/* 12-13 */
	__le16   iSCSIMaxSndDataSegLen;  	/* 14-15 */
	__le16   firstBurstSize;	   	/* 16-17 */
	__le16   DefaultTime2Wait; 		/* 18-19 */
	__le16   DefaultTime2Retain; 		/* 1A-1B */
	__le16   maxOutstndngR2T;	   	/* 1C-1D */
	__le16   keepAliveTimeout;   		/* 1E-1F */
	uint8_t ISID[6];	      		/* 20-25  big-endian, must be */
						/* converted to little-endian */
	__le16   TSID;	      			/* 26-27 */
	__le16   RemoteTCPPortNumber; 		/* 28-29 */
	__le16   maxBurstSize;  		/* 2A-2B */
	__le16   taskMngmntTimeout;  		/* 2C-2D */
	__le16   reserved1;     		/* 2E-2F */
	uint8_t  RemoteIPAddr[0x10];  		/* 30-3F */
	uint8_t  iSCSIAlias[0x20];   		/* 40-5F */
	uint8_t  targetAddr[0x20];   		/* 60-7F */
	__le16   MaxSegmentSize;  		/* 80-81 */
	uint8_t  Reserved1[2];  		/* 82-83 */
	__le16   LocalTCPPortNumber;  		/* 84-85 */
	uint8_t  IPv4TypeOfService;		/* 86    */
	uint8_t  IPv6FlowLabel[3];		/* 87-89 */
	uint8_t  Reserved2[0x36];  		/* 8A-BF */
	uint8_t  iscsiName[0xE0];   		/* C0-19F */
	uint8_t  IPv6LocalIPAddress[0x10];	/* 1A0-1AF */
	uint8_t  Reserved3[0x10];		/* 1B0-1BF */
	__le16   ddbLink;	      		/* 1C0-1C1 */
	__le16   CHAPTableIndex;	   	/* 1C2-1C3 */
	__le16   TargetPortalGroup;  		/* 1C4-1C5 */
	uint8_t  TCPTxWindowScaleFactor;	/* 1C6     */
	uint8_t  TCPRxWindowScaleFactor;	/* 1C7     */
	__le32   statSN;			/* 1C8-1CB */
	__le32   expStatSN;			/* 1CC-1CF */
	uint8_t  reserved3[0x2C];		/* 1D0-1FB */
	__le16   ddbValidCookie;		/* 1FC-1FD */
	__le16   ddbValidSize;			/* 1FE-1FF */
} DEV_DB_ENTRY;


/*************************************************************************/

/* Flash definitions */
#define FLASH_FW_IMG_PAGE_SIZE        0x20000
#define FLASH_FW_IMG_PAGE(addr)       (0xfffe0000 & (addr))
#define FLASH_STRUCTURE_TYPE_MASK     0x0f000000

#define FLASH_OFFSET_FW_LOADER_IMG    0x00000000
#define FLASH_OFFSET_SECONDARY_FW_IMG 0x01000000
#define FLASH_OFFSET_SYS_INFO         0x02000000
#define FLASH_OFFSET_DRIVER_BLK       0x03000000
#define FLASH_OFFSET_INIT_FW_CTRL_BLK 0x04000000
#define FLASH_OFFSET_DEV_DB_AREA      0x05000000
#define FLASH_OFFSET_CHAP_AREA        0x06000000
#define FLASH_OFFSET_PRIMARY_FW_IMG   0x07000000
#define FLASH_READ_RAM_FLAG           0x10000000

#define MAX_FLASH_SZ                  0x400000    /* 4M flash */
#define FLASH_DEFAULTBLOCKSIZE        0x20000
#define FLASH_EOF_OFFSET              FLASH_DEFAULTBLOCKSIZE - 8 /* 4 bytes for EOF signature */
#define FLASH_FILESIZE_OFFSET         FLASH_EOF_OFFSET - 4       /* 4 bytes for file size */
#define FLASH_CKSUM_OFFSET            FLASH_FILESIZE_OFFSET - 4  /* 4 bytes for chksum protection */

typedef struct _SYS_INFO_PHYS_ADDR {
	uint8_t            address[6];		/* 00-05 */
	uint8_t            filler[2];		/* 06-07 */
} SYS_INFO_PHYS_ADDR;

typedef struct _FLASH_SYS_INFO {
	uint32_t           cookie;		/* 00-03 */
	uint32_t           physAddrCount;		/* 04-07 */
	SYS_INFO_PHYS_ADDR physAddr[4];		/* 08-27 */
	uint8_t            vendorId[128];		/* 28-A7 */
	uint8_t            productId[128];	/* A8-127 */
	uint32_t           serialNumber;		/* 128-12B */

	/* PCI Configuration values */
	uint32_t           pciDeviceVendor;	/* 12C-12F */
	uint32_t           pciDeviceId;		/* 130-133 */
	uint32_t           pciSubsysVendor;	/* 134-137 */
	uint32_t           pciSubsysId;		/* 138-13B */

	/* This validates version 1. */
	uint32_t           crumbs;		/* 13C-13F */

	uint32_t           enterpriseNumber;	/* 140-143 */

	uint32_t           mtu;			/* 144-147 */
	uint32_t           reserved0;		/* 148-14b */
	uint32_t           crumbs2;		/* 14c-14f */
	uint8_t            acSerialNumber[16];	/* 150-15f */
	uint32_t           crumbs3;		/* 160-16f */

	/* Leave this last in the struct so it is declared invalid if
	 * any new items are added. */
	uint32_t           reserved1[39];		/* 170-1ff */
} FLASH_SYS_INFO, *PFLASH_SYS_INFO;		/* 200 */

typedef struct _FLASH_DRIVER_INFO {
	uint32_t          LinuxDriverCookie;
	#define FLASH_LINUX_DRIVER_COOKIE		0x0A1B2C3D
	uint8_t       Pad[4];

} FLASH_DRIVER_INFO, *PFLASH_DRIVER_INFO;

typedef struct _CHAP_ENTRY {
	uint16_t link;				  /*  0 x0   */
   #define CHAP_FLAG_PEER_NAME		0x40
   #define CHAP_FLAG_LOCAL_NAME    	0x80

	uint8_t flags;				 /*  2 x2    */
   #define MIN_CHAP_SECRET_LENGTH  	12
   #define MAX_CHAP_SECRET_LENGTH  	100

	uint8_t secretLength;			 /*  3 x3    */
	uint8_t secret[MAX_CHAP_SECRET_LENGTH];	 /*  4 x4    */
   #define MAX_CHAP_CHALLENGE_LENGTH       256

	uint8_t user_name[MAX_CHAP_CHALLENGE_LENGTH]; /* 104 x68  */
	uint16_t reserved;			    /* 360 x168 */
   #define CHAP_COOKIE                     0x4092

	uint16_t cookie;				    /* 362 x16a */
} CHAP_ENTRY, *PCHAP_ENTRY;			    /* 364 x16c */


/*************************************************************************/

typedef struct _CRASH_RECORD {
	uint16_t  fw_major_version;	/* 00 - 01 */
	uint16_t  fw_minor_version;	/* 02 - 03 */
	uint16_t  fw_patch_version;	/* 04 - 05 */
	uint16_t  fw_build_version;	/* 06 - 07 */

	uint8_t   build_date[16];		/* 08 - 17 */
	uint8_t   build_time[16];		/* 18 - 27 */
	uint8_t   build_user[16];		/* 28 - 37 */
	uint8_t   card_serial_num[16];	/* 38 - 47 */

	uint32_t  time_of_crash_in_secs;	/* 48 - 4B */
	uint32_t  time_of_crash_in_ms;	/* 4C - 4F */

	uint16_t  out_RISC_sd_num_frames;	/* 50 - 51 */
	uint16_t  OAP_sd_num_words;	/* 52 - 53 */
	uint16_t  IAP_sd_num_frames;	/* 54 - 55 */
	uint16_t  in_RISC_sd_num_words;	/* 56 - 57 */

	uint8_t   reserved1[28];		/* 58 - 7F */

	uint8_t   out_RISC_reg_dump[256];	/* 80 -17F */
	uint8_t   in_RISC_reg_dump[256];	/*180 -27F */
	uint8_t   in_out_RISC_stack_dump[0]; /*280 - ??? */
} CRASH_RECORD, *PCRASH_RECORD;


/*************************************************************************/

#define MAX_CONN_EVENT_LOG_ENTRIES	100

typedef struct _CONN_EVENT_LOG_ENTRY {
	uint32_t  timestamp_sec;		/* 00 - 03 seconds since boot */
	uint32_t  timestamp_ms;		/* 04 - 07 milliseconds since boot */
	uint16_t  device_index;		/* 08 - 09  */
	uint16_t  fw_conn_state;		/* 0A - 0B  */
	uint8_t   event_type;		/* 0C - 0C  */
	uint8_t   error_code;		/* 0D - 0D  */
	uint16_t  error_code_detail;	/* 0E - 0F  */
	uint8_t   num_consecutive_events;	/* 10 - 10  */
	uint8_t   rsvd[3];		/* 11 - 13  */
} CONN_EVENT_LOG_ENTRY, *PCONN_EVENT_LOG_ENTRY;


/*************************************************************************
 *
 *				IOCB Commands Structures and Definitions
 *
 *************************************************************************/
#define IOCB_MAX_CDB_LEN            16  /* Bytes in a CBD */
#define IOCB_MAX_SENSEDATA_LEN      32  /* Bytes of sense data */
#define IOCB_MAX_EXT_SENSEDATA_LEN  60  /* Bytes of extended sense data */
#define IOCB_MAX_DSD_CNT             1  /* DSDs per noncontinuation type IOCB */
#define IOCB_CONT_MAX_DSD_CNT        5  /* DSDs per Continuation */
#define CTIO_MAX_SENSEDATA_LEN      24  /* Bytes of sense data in a CTIO*/

#define RESERVED_BYTES_MARKER       40  /* Reserved Bytes at end of Marker */
#define RESERVED_BYTES_INOT         28  /* Reserved Bytes at end of Immediate Notify */
#define RESERVED_BYTES_NOTACK       28  /* Reserved Bytes at end of Notify Acknowledge */
#define RESERVED_BYTES_CTIO          2  /* Reserved Bytes in middle of CTIO */

#define MAX_MBX_COUNT               14  /* Maximum number of mailboxes in MBX IOCB */

#define ISCSI_MAX_NAME_BYTECNT      256  /* Bytes in a target name */

#define IOCB_ENTRY_SIZE       	    0x40


/* IOCB header structure */
typedef struct _HEADER {
	uint8_t entryType;
   #define ET_STATUS                0x03
   #define ET_MARKER                0x04
   #define ET_CONT_T1               0x0A
   #define ET_INOT                  0x0D
   #define ET_NACK                  0x0E
   #define ET_STATUS_CONTINUATION   0x10
   #define ET_CMND_T4               0x15
   #define ET_ATIO                  0x16
   #define ET_CMND_T3               0x19
   #define ET_CTIO4                 0x1E
   #define ET_CTIO3                 0x1F
   #define ET_PERFORMANCE_STATUS    0x20
   #define ET_MAILBOX_CMD           0x38
   #define ET_MAILBOX_STATUS        0x39
   #define ET_PASSTHRU0             0x3A
   #define ET_PASSTHRU1             0x3B
   #define ET_PASSTHRU_STATUS       0x3C
   #define ET_ASYNCH_MSG            0x3D
   #define ET_CTIO5                 0x3E
   #define ET_CTIO6                 0x3F

	uint8_t entryStatus;
    #define ES_MASK                 0x3E
    #define ES_SUPPRESS_COMPL_INT   0x01
    #define ES_BUSY                 0x02
    #define ES_INVALID_ENTRY_TYPE   0x04
    #define ES_INVALID_ENTRY_PARAM  0x08
    #define ES_INVALID_ENTRY_COUNT  0x10
    #define ES_INVALID_ENTRY_ORDER  0x20
	uint8_t systemDefined;
	uint8_t entryCount;

	/* SyetemDefined definition */
    #define SD_PASSTHRU_IOCB        0x01
} HEADER ;

/* Genric queue entry structure*/
typedef struct QUEUE_ENTRY {
	uint8_t  data[60];
	uint32_t signature;

} QUEUE_ENTRY;


/* 64 bit addressing segment counts*/

#define COMMAND_SEG_A64             1
#define CONTINUE_SEG_A64            5
#define CONTINUE_SEG_A64_MINUS1     4

/* 64 bit addressing segment definition*/

typedef struct DATA_SEG_A64 {
	struct {
		__le32 addrLow;
		__le32 addrHigh;

	} base;

	__le32 count;

} DATA_SEG_A64;

/* Command Type 3 entry structure*/

typedef struct _COMMAND_T3_ENTRY {
	HEADER  hdr;		   /* 00-03 */

	__le32  handle;		   /* 04-07 */
	__le16  target;		   /* 08-09 */
	__le16  connection_id;	   /* 0A-0B */

	uint8_t   control_flags;	   /* 0C */
   #define CF_IMMEDIATE		   0x80

	/* data direction  (bits 5-6)*/
   #define CF_WRITE                0x20
   #define CF_READ                 0x40
   #define CF_NO_DATA              0x00
   #define CF_DIRECTION_MASK       0x60

	/* misc  (bits 4-3)*/
   #define CF_DSD_PTR_ENABLE	   0x10	   /* 4010 only */
   #define CF_CMD_PTR_ENABLE	   0x08    /* 4010 only */

	/* task attributes (bits 2-0) */
   #define CF_ACA_QUEUE            0x04
   #define CF_HEAD_TAG             0x03
   #define CF_ORDERED_TAG          0x02
   #define CF_SIMPLE_TAG           0x01
   #define CF_TAG_TYPE_MASK        0x07
   #define CF_ATTRIBUTES_MASK      0x67

	/* STATE FLAGS FIELD IS A PLACE HOLDER. THE FW WILL SET BITS IN THIS FIELD
	   AS THE COMMAND IS PROCESSED. WHEN THE IOCB IS CHANGED TO AN IOSB THIS
	   FIELD WILL HAVE THE STATE FLAGS SET PROPERLY.
	*/
	uint8_t   state_flags;	   /* 0D */
	uint8_t   cmdRefNum;	   /* 0E */
	uint8_t   reserved1;	   /* 0F */
	uint8_t   cdb[IOCB_MAX_CDB_LEN];	/* 10-1F */
	uint8_t   lun[8];		   /* 20-27 */
	__le32  cmdSeqNum;	   /* 28-2B */
	__le16  timeout;	   /* 2C-2D */
	__le16  dataSegCnt;	   /* 2E-2F */
	__le32  ttlByteCnt;	   /* 30-33 */
	DATA_SEG_A64 dataseg[COMMAND_SEG_A64];	/* 34-3F */

} COMMAND_T3_ENTRY;

typedef struct _COMMAND_T4_ENTRY {
	HEADER  hdr;		  /* 00-03 */
	uint32_t  handle;		  /* 04-07 */
	uint16_t  target;		  /* 08-09 */
	uint16_t  connection_id;	  /* 0A-0B */
	uint8_t   control_flags;	  /* 0C */

	/* STATE FLAGS FIELD IS A PLACE HOLDER. THE FW WILL SET BITS IN THIS FIELD
	   AS THE COMMAND IS PROCESSED. WHEN THE IOCB IS CHANGED TO AN IOSB THIS
	   FIELD WILL HAVE THE STATE FLAGS SET PROPERLY.
	*/
	uint8_t   state_flags;	  /* 0D */
	uint8_t   cmdRefNum;	  /* 0E */
	uint8_t   reserved1;	  /* 0F */
	uint8_t   cdb[IOCB_MAX_CDB_LEN]; /* 10-1F */
	uint8_t   lun[8];		  /* 20-27 */
	uint32_t  cmdSeqNum;	  /* 28-2B */
	uint16_t  timeout;	  /* 2C-2D */
	uint16_t  dataSegCnt;	  /* 2E-2F */
	uint32_t  ttlByteCnt;	  /* 30-33 */

	/* WE ONLY USE THE ADDRESS FIELD OF THE FOLLOWING STRUCT.
	   THE COUNT FIELD IS RESERVED */
	DATA_SEG_A64 dataseg[COMMAND_SEG_A64];	/* 34-3F */
} COMMAND_T4_ENTRY;

/* Continuation Type 1 entry structure*/
typedef struct _CONTINUATION_T1_ENTRY {
	HEADER  hdr;

	DATA_SEG_A64 dataseg[CONTINUE_SEG_A64];

}CONTINUATION_T1_ENTRY;

/* Status Continuation Type entry structure*/
typedef struct _STATUS_CONTINUATION_ENTRY {
	HEADER  hdr;

	uint8_t extSenseData[IOCB_MAX_EXT_SENSEDATA_LEN];

}STATUS_CONTINUATION_ENTRY;

/* Parameterize for 64 or 32 bits */
    #define COMMAND_SEG     COMMAND_SEG_A64
    #define CONTINUE_SEG    CONTINUE_SEG_A64

    #define COMMAND_ENTRY   COMMAND_T3_ENTRY
    #define CONTINUE_ENTRY  CONTINUATION_T1_ENTRY

    #define ET_COMMAND      ET_CMND_T3
    #define ET_CONTINUE     ET_CONT_T1



/* Marker entry structure*/
typedef struct _MARKER_ENTRY {
	HEADER  hdr;		/* 00-03 */

	__le32  system_defined;	/* 04-07 */
	__le16  target;		/* 08-09 */
	__le16  modifier;	/* 0A-0B */
   #define MM_LUN_RESET         0
   #define MM_TARGET_WARM_RESET 1
   #define MM_TARGET_COLD_RESET 2
   #define MM_CLEAR_ACA    	3
   #define MM_CLEAR_TASK_SET    4
   #define MM_ABORT_TASK_SET    5

	__le16  flags;		/* 0C-0D */
	uint16_t  reserved1;	/* 0E-0F */
	uint8_t   lun[8];	/* 10-17 */
	uint64_t  reserved2;	/* 18-1F */
	uint64_t  reserved3;	/* 20-27 */
	uint64_t  reserved4;	/* 28-2F */
	uint64_t  reserved5;	/* 30-37 */
	uint64_t  reserved6;	/* 38-3F */
}MARKER_ENTRY;

/* Status entry structure*/
typedef struct _STATUS_ENTRY {
	HEADER  hdr;			     /* 00-03 */

	__le32    handle;		     /* 04-07 */

	uint8_t   scsiStatus;		     /* 08 */
   #define SCSI_STATUS_MASK                  0xFF
   #define SCSI_STATUS                       0xFF
   #define SCSI_GOOD                         0x00

	uint8_t   iscsiFlags;		     /* 09 */
   #define ISCSI_FLAG_RESIDUAL_UNDER         0x02
   #define ISCSI_FLAG_RESIDUAL_OVER          0x04
   #define ISCSI_FLAG_RESIDUAL_UNDER_BIREAD  0x08
   #define ISCSI_FLAG_RESIDUAL_OVER_BIREAD   0x10

	uint8_t   iscsiResponse;		     /* 0A */
   #define ISCSI_RSP_COMPLETE                    0x00
   #define ISCSI_RSP_TARGET_FAILURE              0x01
   #define ISCSI_RSP_DELIVERY_SUBSYS_FAILURE     0x02
   #define ISCSI_RSP_UNSOLISITED_DATA_REJECT     0x03
   #define ISCSI_RSP_NOT_ENOUGH_UNSOLISITED_DATA 0x04
   #define ISCSI_RSP_CMD_IN_PROGRESS             0x05

	uint8_t   completionStatus;	     /* 0B */
   #define SCS_COMPLETE                      0x00
   #define SCS_INCOMPLETE                    0x01
   #define SCS_DMA_ERROR                     0x02
   #define SCS_TRANSPORT_ERROR               0x03
   #define SCS_RESET_OCCURRED                0x04
   #define SCS_ABORTED                       0x05
   #define SCS_TIMEOUT                       0x06
   #define SCS_DATA_OVERRUN                  0x07
   #define SCS_DATA_DIRECTION_ERROR          0x08
   #define SCS_DATA_UNDERRUN                 0x15
   #define SCS_QUEUE_FULL                    0x1C
   #define SCS_DEVICE_UNAVAILABLE            0x28
   #define SCS_DEVICE_LOGGED_OUT             0x29
   #define SCS_DEVICE_CONFIG_CHANGED         0x2A

	uint8_t   reserved1;		     /* 0C */

	/* state_flags MUST be at the same location as state_flags in the
	   Command_T3/4_Entry */
	uint8_t   state_flags;		     /* 0D */
   #define STATE_FLAG_SENT_COMMAND           0x01
   #define STATE_FLAG_TRANSFERRED_DATA       0x02
   #define STATE_FLAG_GOT_STATUS             0x04
   #define STATE_FLAG_LOGOUT_SENT            0x10

	__le16    senseDataByteCnt;	     /* 0E-0F */
	__le32    residualByteCnt;	     /* 10-13 */
	__le32    bidiResidualByteCnt;	     /* 14-17 */
	__le32    expSeqNum;		     /* 18-1B */
	__le32    maxCmdSeqNum;		     /* 1C-1F */
	uint8_t   senseData[IOCB_MAX_SENSEDATA_LEN]; /* 20-3F */

}STATUS_ENTRY;

/*
 * Performance Status Entry where up to 30 handles can be posted in a
 * single IOSB. Handles are of 16 bit value.
 */
typedef struct  _PERFORMANCE_STATUS_ENTRY {
	uint8_t  entryType;
	uint8_t  entryCount;
	uint16_t handleCount;

   #define MAX_STATUS_HANDLE  30
	uint16_t handleArray[ MAX_STATUS_HANDLE ];

} PERFORMANCE_STATUS_ENTRY;


typedef struct _IMMEDIATE_NOTIFY_ENTRY {
	HEADER  hdr;
	uint32_t  handle;
	uint16_t  initiator;
	uint16_t  InitSessionID;
	uint16_t  ConnectionID;
	uint16_t  TargSessionID;
	uint16_t  inotStatus;
   #define INOT_STATUS_ABORT_TASK      0x0020
   #define INOT_STATUS_LOGIN_RECVD     0x0021
   #define INOT_STATUS_LOGOUT_RECVD    0x0022
   #define INOT_STATUS_LOGGED_OUT      0x0029
   #define INOT_STATUS_RESTART_RECVD   0x0030
   #define INOT_STATUS_MSG_RECVD       0x0036
   #define INOT_STATUS_TSK_REASSIGN    0x0037

	uint16_t  taskFlags;
   #define TASK_FLAG_CLEAR_ACA         0x4000
   #define TASK_FLAG_COLD_RESET        0x2000
   #define TASK_FLAG_WARM_RESET        0x0800
   #define TASK_FLAG_LUN_RESET         0x1000
   #define TASK_FLAG_CLEAR_TASK_SET    0x0400
   #define TASK_FLAG_ABORT_TASK_SET    0x0200


	uint32_t  refTaskTag;
	uint8_t   lun[8];
	uint32_t  inotTaskTag;
	uint8_t   res3[RESERVED_BYTES_INOT];
} IMMEDIATE_NOTIFY_ENTRY ;

typedef struct _NOTIFY_ACK_ENTRY {
	HEADER  hdr;
	uint32_t  handle;
	uint16_t  initiator;
	uint16_t  res1;
	uint16_t  flags;
	uint8_t        responseCode;
	uint8_t        qualifier;
	uint16_t  notAckStatus;
	uint16_t  taskFlags;
   #define NACK_FLAG_RESPONSE_CODE_VALID 0x0010

	uint32_t  refTaskTag;
	uint8_t   lun[8];
	uint32_t  inotTaskTag;
	uint8_t   res3[RESERVED_BYTES_NOTACK];
} NOTIFY_ACK_ENTRY ;

typedef struct _ATIO_ENTRY {
	HEADER  hdr;			  /* 00-03 */
	uint32_t  handle;			  /* 04-07 */
	uint16_t  initiator;		  /* 08-09 */
	uint16_t  connectionID;		  /* 0A-0B */
	uint32_t  taskTag;		  /* 0C-0f */
	uint8_t   scsiCDB[IOCB_MAX_CDB_LEN];     /* 10-1F */
	uint8_t   LUN[8];			  /* 20-27 */
	uint8_t   cmdRefNum;		  /* 28 */

	uint8_t   pduType;		  /* 29 */
   #define PDU_TYPE_NOPOUT                0x00
   #define PDU_TYPE_SCSI_CMD              0x01
   #define PDU_TYPE_SCSI_TASK_MNGMT_CMD   0x02
   #define PDU_TYPE_LOGIN_CMD             0x03
   #define PDU_TYPE_TEXT_CMD              0x04
   #define PDU_TYPE_SCSI_DATA             0x05
   #define PDU_TYPE_LOGOUT_CMD            0x06
   #define PDU_TYPE_SNACK                 0x10

	uint16_t  atioStatus;		  /* 2A-2B */
   #define ATIO_CDB_RECVD                 0x003d

	uint16_t  reserved1;		  /* 2C-2D */

	uint8_t   taskCode;		  /* 2E */
   #define ATIO_TASK_CODE_UNTAGGED        0x00
   #define ATIO_TASK_CODE_SIMPLE_QUEUE    0x01
   #define ATIO_TASK_CODE_ORDERED_QUEUE   0x02
   #define ATIO_TASK_CODE_HEAD_OF_QUEUE   0x03
   #define ATIO_TASK_CODE_ACA_QUEUE       0x04

	uint8_t   reserved2;		  /* 2F */
	uint32_t  totalByteCnt;		  /* 30-33 */
	uint32_t  cmdSeqNum;		  /* 34-37 */
	uint64_t  immDataBufDesc;		  /* 38-3F */
} ATIO_ENTRY ;

typedef struct _CTIO3_ENTRY {
	HEADER  hdr;			  /* 00-03 */
	uint32_t  handle;			  /* 04-07 */
	uint16_t  initiator;		  /* 08-09 */
	uint16_t  connectionID;		  /* 0A-0B */
	uint32_t  taskTag;		  /* 0C-0F */

	uint8_t   flags;			  /* 10 */
   #define CTIO_FLAG_SEND_SCSI_STATUS     0x01
   #define CTIO_FLAG_TERMINATE_COMMAND    0x10
   #define CTIO_FLAG_FAST_POST            0x08
   #define CTIO_FLAG_FINAL_CTIO           0x80

	/*  NOTE:  Our firmware assumes that the CTIO_FLAG_SEND_DATA and
		   CTIO_FLAG_GET_DATA flags are in the same bit positions
		   as the R and W bits in SCSI Command PDUs, so their values
		   should not be changed!
	 */
   #define CTIO_FLAG_SEND_DATA            0x0040   /* (see note) Read Data Flag, send data to initiator       */
   #define CTIO_FLAG_GET_DATA             0x0020   /* (see note) Write Data Flag, get data from the initiator */

	uint8_t   scsiStatus;		  /* 11 */
	uint16_t  timeout;		  /* 12-13 */
	uint32_t  offset;			  /* 14-17 */
	uint32_t  r2tSN;			  /* 18-1B */
	uint32_t  expCmdSN;		  /* 1C-1F */
	uint32_t  maxCmdSN;		  /* 20-23 */
	uint32_t  dataSN;			  /* 24-27 */
	uint32_t  residualCount;		  /* 28-2B */
	uint16_t  reserved;		  /* 2C-2D */
	uint16_t  segmentCnt;		  /* 2E-2F */
	uint32_t  totalByteCnt;		  /* 30-33 */
	DATA_SEG_A64 dataseg[COMMAND_SEG_A64]; /* 34-3F */
} CTIO3_ENTRY ;

typedef struct _CTIO4_ENTRY {
	HEADER  hdr;			  /* 00-03 */
	uint32_t  handle;			  /* 04-07 */
	uint16_t  initiator;		  /* 08-09 */
	uint16_t  connectionID;		  /* 0A-0B */
	uint32_t  taskTag;		  /* 0C-0F */
	uint8_t   flags;			  /* 10 */
	uint8_t   scsiStatus;		  /* 11 */
	uint16_t  timeout;		  /* 12-13 */
	uint32_t  offset;			  /* 14-17 */
	uint32_t  r2tSN;			  /* 18-1B */
	uint32_t  expCmdSN;		  /* 1C-1F */
	uint32_t  maxCmdSN;		  /* 20-23 */
	uint32_t  dataSN;			  /* 24-27 */
	uint32_t  residualCount;		  /* 28-2B */
	uint16_t  reserved;		  /* 2C-2D */
	uint16_t  segmentCnt;		  /* 2E-2F */
	uint32_t  totalByteCnt;		  /* 30-33 */
	/* WE ONLY USE THE ADDRESS FROM THE FOLLOWING STRUCTURE THE COUNT FIELD IS
	   RESERVED */
	DATA_SEG_A64 dataseg[COMMAND_SEG_A64]; /* 34-3F */
} CTIO4_ENTRY ;

typedef struct _CTIO5_ENTRY {
	HEADER  hdr;			  /* 00-03 */
	uint32_t  handle;			  /* 04-07 */
	uint16_t  initiator;		  /* 08-09 */
	uint16_t  connectionID;		  /* 0A-0B */
	uint32_t  taskTag;		  /* 0C-0F */
	uint8_t   response;		  /* 10 */
	uint8_t   scsiStatus;		  /* 11 */
	uint16_t  timeout;		  /* 12-13 */
	uint32_t  reserved1;		  /* 14-17 */
	uint32_t  expR2TSn;		  /* 18-1B */
	uint32_t  expCmdSn;		  /* 1C-1F */
	uint32_t  MaxCmdSn;		  /* 20-23 */
	uint32_t  expDataSn;		  /* 24-27 */
	uint32_t  residualCnt;		  /* 28-2B */
	uint32_t  bidiResidualCnt;	  /* 2C-2F */
	uint32_t  reserved2;		  /* 30-33 */
	DATA_SEG_A64 dataseg[1];	  /* 34-3F */
} CTIO5_ENTRY ;

typedef struct _CTIO6_ENTRY {
	HEADER  hdr;			  /* 00-03 */
	uint32_t  handle;			  /* 04-07 */
	uint16_t  initiator;		  /* 08-09 */
	uint16_t  connection;		  /* 0A-0B */
	uint32_t  taskTag;		  /* 0C-0F */
	uint16_t  flags;			  /* 10-11 */
	uint16_t  timeout;		  /* 12-13 */
	uint32_t  reserved1;		  /* 14-17 */
	uint64_t  reserved2;		  /* 18-1F */
	uint64_t  reserved3;		  /* 20-27 */
	uint64_t  reserved4;		  /* 28-2F */
	uint32_t  reserved5;		  /* 30-33 */
	DATA_SEG_A64 dataseg[1];	  /* 34-3F */
} CTIO6_ENTRY ;

typedef struct _CTIO_STATUS_ENTRY {
	HEADER  hdr;			  /* 00-03 */
	uint32_t  handle;			  /* 04-07 */
	uint16_t  initiator;		  /* 08-09 */
	uint16_t  connectionID;		  /* 0A-0B */
	uint32_t  taskTag;		  /* 0C-0F */
	uint16_t  status;			  /* 10-11 */
   #define CTIO_STATUS_COMPLETE           0x0001
   #define CTIO_STATUS_ABORTED            0x0002
   #define CTIO_STATUS_DMA_ERROR          0x0003
   #define CTIO_STATUS_ERROR              0x0004
   #define CTIO_STATUS_INVALID_TAG        0x0008
   #define CTIO_STATUS_DATA_OVERRUN       0x0009
   #define CTIO_STATUS_CMD_TIMEOUT        0x000B
   #define CTIO_STATUS_PCI_ERROR          0x0010
   #define CTIO_STATUS_DATA_UNDERRUN      0x0015
   #define CTIO_STATUS_TARGET_RESET       0x0017
   #define CTIO_STATUS_NO_CONNECTION      0x0028
   #define CTIO_STATUS_LOGGED_OUT         0x0029
   #define CTIO_STATUS_CONFIG_CHANGED     0x002A
   #define CTIO_STATUS_UNACK_EVENT        0x0035
   #define CTIO_STATUS_INVALID_DATA_XFER  0x0036

	uint16_t  timeout;		  /* 12-13 */
	uint32_t  reserved1;		  /* 14-17 */
	uint32_t  expR2TSN;		  /* 18-1B */
	uint32_t  reserved2;		  /* 1C-1F */
	uint32_t  reserved3;		  /* 20-23 */
	uint64_t  expDataSN;		  /* 24-27 */
	uint32_t  residualCount;		  /* 28-2B */
	uint32_t  reserved4;		  /* 2C-2F */
	uint64_t  reserved5;		  /* 30-37 */
	uint64_t  reserved6;		  /* 38-3F */
} CTIO_STATUS_ENTRY ;

typedef struct _MAILBOX_ENTRY {
	HEADER  hdr;
	uint32_t  handle;
	uint32_t  mbx[MAX_MBX_COUNT];
} MAILBOX_ENTRY ;

typedef struct MAILBOX_STATUS_ENTRY {
	HEADER  hdr;
	uint32_t  handle;
	uint32_t  mbx[MAX_MBX_COUNT];
} MAILBOX_STATUS_ENTRY ;

typedef struct _PDU_ENTRY {
	uint8_t       *Buff;
	uint32_t       BuffLen;
	uint32_t       SendBuffLen;
	uint32_t       RecvBuffLen;
	struct _PDU_ENTRY *Next;
	dma_addr_t DmaBuff;
} PDU_ENTRY, *PPDU_ENTRY;

typedef struct _PASSTHRU0_ENTRY {
	HEADER  hdr;			  /* 00-03 */
	__le32  handle;			  /* 04-07 */
	__le16  target;			  /* 08-09 */
	__le16  connectionID;		  /* 0A-0B */
	#define ISNS_DEFAULT_SERVER_CONN_ID     ((uint16_t)0x8000)

	__le16  controlFlags;		  /* 0C-0D */
	#define PT_FLAG_ETHERNET_FRAME   	0x8000
	#define PT_FLAG_ISNS_PDU                0x8000
	#define PT_FLAG_IP_DATAGRAM             0x4000
	#define PT_FLAG_TCP_PACKET              0x2000
	#define PT_FLAG_NETWORK_PDU             (PT_FLAG_ETHERNET_FRAME | PT_FLAG_IP_DATAGRAM | PT_FLAG_TCP_PACKET)
	#define PT_FLAG_iSCSI_PDU               0x1000
	#define PT_FLAG_SEND_BUFFER             0x0200
	#define PT_FLAG_WAIT_4_RESPONSE         0x0100
	#define PT_FLAG_NO_FAST_POST            0x0080

	__le16  timeout;		  /* 0E-0F */
	#define PT_DEFAULT_TIMEOUT              30   /* seconds */

	DATA_SEG_A64 outDataSeg64;	  /* 10-1B */
	uint32_t  res1;			  /* 1C-1F */
	DATA_SEG_A64 inDataSeg64;	  /* 20-2B */
	uint8_t   res2[20];		  /* 2C-3F */
} PASSTHRU0_ENTRY ;

typedef struct _PASSTHRU1_ENTRY {
	HEADER  hdr;			  /* 00-03 */
	uint32_t  handle;			  /* 04-07 */
	uint16_t  target;			  /* 08-09 */
	uint16_t  connectionID;		  /* 0A-0B */

	uint16_t  controlFlags;		  /* 0C-0D */
   #define PT_FLAG_ETHERNET_FRAME         	0x8000
   #define PT_FLAG_IP_DATAGRAM            	0x4000
   #define PT_FLAG_TCP_PACKET             	0x2000
   #define PT_FLAG_iSCSI_PDU              	0x1000
   #define PT_FLAG_SEND_BUFFER            	0x0200
   #define PT_FLAG_WAIT_4_REPONSE         	0x0100
   #define PT_FLAG_NO_FAST_POST           	0x0080

	uint16_t  timeout;		  /* 0E-0F */
	DATA_SEG_A64 outDSDList;	  /* 10-1B */
	uint32_t  outDSDCnt;		  /* 1C-1F */
	DATA_SEG_A64 inDSDList;		  /* 20-2B */
	uint32_t  inDSDCnt;		  /* 2C-2F */
	uint8_t  res1;			  /* 30-3F */

} PASSTHRU1_ENTRY ;

typedef struct _PASSTHRU_STATUS_ENTRY {
	HEADER  hdr;			  /* 00-03 */
	uint32_t  handle;			  /* 04-07 */
	uint16_t  target;			  /* 08-09 */
	uint16_t  connectionID;		  /* 0A-0B */

	uint8_t   completionStatus;	  /* 0C */
   #define PASSTHRU_STATUS_COMPLETE       		0x01
   #define PASSTHRU_STATUS_ERROR          		0x04
   #define PASSTHRU_STATUS_INVALID_DATA_XFER            0x06
   #define PASSTHRU_STATUS_CMD_TIMEOUT    		0x0B
   #define PASSTHRU_STATUS_PCI_ERROR      		0x10
   #define PASSTHRU_STATUS_NO_CONNECTION  		0x28

	uint8_t   residualFlags;		  /* 0D */
   #define PASSTHRU_STATUS_DATAOUT_OVERRUN              0x01
   #define PASSTHRU_STATUS_DATAOUT_UNDERRUN             0x02
   #define PASSTHRU_STATUS_DATAIN_OVERRUN               0x04
   #define PASSTHRU_STATUS_DATAIN_UNDERRUN              0x08

	uint16_t  timeout;		  /* 0E-0F */
	uint16_t  portNumber;		  /* 10-11 */
	uint8_t   res1[10];		  /* 12-1B */
	uint32_t  outResidual;		  /* 1C-1F */
	uint8_t   res2[12];		  /* 20-2B */
	uint32_t  inResidual;		  /* 2C-2F */
	uint8_t   res4[16];		  /* 30-3F */
} PASSTHRU_STATUS_ENTRY ;

typedef struct _ASYNCHMSG_ENTRY {
	HEADER  hdr;
	uint32_t  handle;
	uint16_t  target;
	uint16_t  connectionID;
	uint8_t   lun[8];
	uint16_t  iSCSIEvent;
   #define AMSG_iSCSI_EVENT_NO_EVENT                  0x0000
   #define AMSG_iSCSI_EVENT_TARG_RESET                0x0001
   #define AMSG_iSCSI_EVENT_TARGT_LOGOUT              0x0002
   #define AMSG_iSCSI_EVENT_CONNECTION_DROPPED        0x0003
   #define AMSG_ISCSI_EVENT_ALL_CONNECTIONS_DROPPED   0x0004

	uint16_t  SCSIEvent;
   #define AMSG_NO_SCSI_EVENT                         0x0000
   #define AMSG_SCSI_EVENT                            0x0001

	uint16_t  parameter1;
	uint16_t  parameter2;
	uint16_t  parameter3;
	uint32_t  expCmdSn;
	uint32_t  maxCmdSn;
	uint16_t  senseDataCnt;
	uint16_t  reserved;
	uint32_t  senseData[IOCB_MAX_SENSEDATA_LEN];
} ASYNCHMSG_ENTRY ;

/* Timer entry structure, this is an internal generated structure
   which causes the QLA4000 initiator to send a NOP-OUT or the
   QLA4000 target to send a NOP-IN */

typedef struct _TIMER_ENTRY {
	HEADER  hdr;		   /* 00-03 */

	uint32_t  handle;		   /* 04-07 */
	uint16_t  target;		   /* 08-09 */
	uint16_t  connection_id;	   /* 0A-0B */

	uint8_t   control_flags;	   /* 0C */

	/* STATE FLAGS FIELD IS A PLACE HOLDER. THE FW WILL SET BITS IN THIS FIELD
	   AS THE COMMAND IS PROCESSED. WHEN THE IOCB IS CHANGED TO AN IOSB THIS
	   FIELD WILL HAVE THE STATE FLAGS SET PROPERLY.
	*/
	uint8_t   state_flags;	   /* 0D */
	uint8_t   cmdRefNum;	   /* 0E */
	uint8_t   reserved1;	   /* 0F */
	uint8_t   cdb[IOCB_MAX_CDB_LEN];	   /* 10-1F */
	uint8_t   lun[8];		   /* 20-27 */
	uint32_t  cmdSeqNum;	   /* 28-2B */
	uint16_t  timeout;	   /* 2C-2D */
	uint16_t  dataSegCnt;	   /* 2E-2F */
	uint32_t  ttlByteCnt;	   /* 30-33 */
	DATA_SEG_A64 dataseg[COMMAND_SEG_A64];	/* 34-3F */

} TIMER_ENTRY;


#endif /* _QLA4X_FW_H */

/*
 * Overrides for Emacs so that we almost follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-indent-level: 2
 * c-brace-imaginary-offset: 0
 * c-brace-offset: -2
 * c-argdecl-indent: 2
 * c-label-offset: -2
 * c-continued-statement-offset: 2
 * c-continued-brace-offset: 0
 * indent-tabs-mode: nil
 * tab-width: 8
 * End:
 */


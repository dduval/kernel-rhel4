/*
 * linux/drivers/s390/net/qeth_mpc.c
 *
 * Linux on zSeries OSA Express and HiperSockets support
 *
 * Copyright 2000,2003 IBM Corporation
 * Author(s): Frank Pavlic <pavlic@de.ibm.com>
 * 	      Thomas Spatzier <tspat@de.ibm.com>
 *
 */
#include <asm/cio.h>
#include "qeth_mpc.h"

const char *VERSION_QETH_MPC_C = "$Revision: 1.12 $";

unsigned char IDX_ACTIVATE_READ[]={
	0x00,0x00,0x80,0x00, 0x00,0x00,0x00,0x00,
	0x19,0x01,0x01,0x80, 0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00, 0x00,0x00,0xc8,0xc1,
	0xd3,0xd3,0xd6,0xd3, 0xc5,0x40,0x00,0x00,
	0x00,0x00
};

unsigned char IDX_ACTIVATE_WRITE[]={
	0x00,0x00,0x80,0x00, 0x00,0x00,0x00,0x00,
	0x15,0x01,0x01,0x80, 0x00,0x00,0x00,0x00,
	0xff,0xff,0x00,0x00, 0x00,0x00,0xc8,0xc1,
	0xd3,0xd3,0xd6,0xd3, 0xc5,0x40,0x00,0x00,
	0x00,0x00
};

unsigned char CM_ENABLE[]={
	0x00,0xe0,0x00,0x00, 0x00,0x00,0x00,0x01,
	0x00,0x00,0x00,0x14, 0x00,0x00,0x00,0x63,
	0x10,0x00,0x00,0x01,
	0x00,0x00,0x00,0x00,
	0x81,0x7e,0x00,0x01, 0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00, 0x00,0x24,0x00,0x23,
	0x00,0x00,0x23,0x05, 0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x23, 0x00,0x00,0x00,0x40,
	0x00,0x0c,0x41,0x02, 0x00,0x17,0x00,0x00,
	0x00,0x00,0x00,0x00,
	0x00,0x0b,0x04,0x01,
	0x7e,0x04,0x05,0x00, 0x01,0x01,0x0f,
	0x00,
	0x0c,0x04,0x02,0xff, 0xff,0xff,0xff,0xff,
	0xff,0xff,0xff
};

unsigned char CM_SETUP[]={
	0x00,0xe0,0x00,0x00, 0x00,0x00,0x00,0x02,
	0x00,0x00,0x00,0x14, 0x00,0x00,0x00,0x64,
	0x10,0x00,0x00,0x01,
	0x00,0x00,0x00,0x00,
	0x81,0x7e,0x00,0x01, 0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00, 0x00,0x24,0x00,0x24,
	0x00,0x00,0x24,0x05, 0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x24, 0x00,0x00,0x00,0x40,
	0x00,0x0c,0x41,0x04, 0x00,0x18,0x00,0x00,
	0x00,0x00,0x00,0x00,
	0x00,0x09,0x04,0x04,
	0x05,0x00,0x01,0x01, 0x11,
	0x00,0x09,0x04,
	0x05,0x05,0x00,0x00, 0x00,0x00,
	0x00,0x06,
	0x04,0x06,0xc8,0x00
};

unsigned char ULP_ENABLE[]={
	0x00,0xe0,0x00,0x00, 0x00,0x00,0x00,0x03,
	0x00,0x00,0x00,0x14, 0x00,0x00,0x00,0x6b,
	0x10,0x00,0x00,0x01,
	0x00,0x00,0x00,0x00,
	0x41,0x7e,0x00,0x01, 0x00,0x00,0x00,0x01,
	0x00,0x00,0x00,0x00, 0x00,0x24,0x00,0x2b,
	0x00,0x00,0x2b,0x05, 0x20,0x01,0x00,0x00,
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x2b, 0x00,0x00,0x00,0x40,
	0x00,0x0c,0x41,0x02, 0x00,0x1f,0x00,0x00,
	0x00,0x00,0x00,0x00,
	0x00,0x0b,0x04,0x01,
	0x03,0x04,0x05,0x00, 0x01,0x01,0x12,
	0x00,
	0x14,0x04,0x0a,0x00, 0x20,0x00,0x00,0xff,
	0xff,0x00,0x08,0xc8, 0xe8,0xc4,0xf1,0xc7,
	0xf1,0x00,0x00
};

unsigned char ULP_SETUP[]={
	0x00,0xe0,0x00,0x00, 0x00,0x00,0x00,0x04,
	0x00,0x00,0x00,0x14, 0x00,0x00,0x00,0x6c,
	0x10,0x00,0x00,0x01,
	0x00,0x00,0x00,0x00,
	0x41,0x7e,0x00,0x01, 0x00,0x00,0x00,0x02,
	0x00,0x00,0x00,0x01, 0x00,0x24,0x00,0x2c,
	0x00,0x00,0x2c,0x05, 0x20,0x01,0x00,0x00,
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x2c, 0x00,0x00,0x00,0x40,
	0x00,0x0c,0x41,0x04, 0x00,0x20,0x00,0x00,
	0x00,0x00,0x00,0x00,
	0x00,0x09,0x04,0x04,
	0x05,0x00,0x01,0x01, 0x14,
	0x00,0x09,0x04,
	0x05,0x05,0x30,0x01, 0x00,0x00,
	0x00,0x06,
	0x04,0x06,0x40,0x00,
	0x00,0x08,0x04,0x0b,
	0x00,0x00,0x00,0x00
};

unsigned char DM_ACT[]={
	0x00,0xe0,0x00,0x00, 0x00,0x00,0x00,0x05,
	0x00,0x00,0x00,0x14, 0x00,0x00,0x00,0x55,
	0x10,0x00,0x00,0x01,
	0x00,0x00,0x00,0x00,
	0x41,0x7e,0x00,0x01, 0x00,0x00,0x00,0x03,
	0x00,0x00,0x00,0x02, 0x00,0x24,0x00,0x15,
	0x00,0x00,0x2c,0x05, 0x20,0x01,0x00,0x00,
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x15, 0x00,0x00,0x00,0x40,
	0x00,0x0c,0x43,0x60, 0x00,0x09,0x00,0x00,
	0x00,0x00,0x00,0x00,
	0x00,0x09,0x04,0x04,
	0x05,0x40,0x01,0x01, 0x00
};

unsigned char IPA_PDU_HEADER[]={
	0x00,0xe0,0x00,0x00, 0x77,0x77,0x77,0x77,
	0x00,0x00,0x00,0x14, 0x00,0x00,
		(IPA_PDU_HEADER_SIZE+sizeof(struct qeth_ipa_cmd))/256,
		(IPA_PDU_HEADER_SIZE+sizeof(struct qeth_ipa_cmd))%256,
	0x10,0x00,0x00,0x01, 0x00,0x00,0x00,0x00,
	0xc1,0x03,0x00,0x01, 0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00, 0x00,0x24,
		sizeof(struct qeth_ipa_cmd)/256,
		sizeof(struct qeth_ipa_cmd)%256,
	0x00,
		sizeof(struct qeth_ipa_cmd)/256,
		sizeof(struct qeth_ipa_cmd)%256,
	0x05,
	0x77,0x77,0x77,0x77,
	0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
	0x01,0x00,
		sizeof(struct qeth_ipa_cmd)/256,
		sizeof(struct qeth_ipa_cmd)%256,
	0x00,0x00,0x00,0x40,
};

unsigned char WRITE_CCW[]={
	0x01,CCW_FLAG_SLI,0,0,
	0,0,0,0
};

unsigned char READ_CCW[]={
	0x02,CCW_FLAG_SLI,0,0,
	0,0,0,0
};












/*
 * linux/drivers/block/cciss_diskdump.c
 *
 * Copyright (C) 2005 Hewlett-Packard Development Company, L.P.
 * Written by Chase Maupin (chase.maupin@hp.com)
 *
 * functions to add diskdump support to the cciss driver.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 21 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 */

#include "cciss.h"
#include "cciss_cmd.h"

/* global vars */
static int quiesce_ok = 0;
static CommandList_struct *cciss_dump_cmnd[MAX_CTLR];
static ReadCapdata_struct *size_buff;
static ReadCapdata_struct_16 *size_buff_16;
#define BLOCK_SECTOR(s) ((s) << (PAGE_SHIFT - 9))

/* function prototypes */
void *cciss_probe(struct gendisk *disk);
static CommandList_struct * cmd_alloc(ctlr_info_t *h, int get_from_pool);
static int cciss_dump_sanity_check(void *device);
static int cciss_sanity_check(int ctlr, int lun);
static int find_ctlr_lun_ids(int ctlr, int *lun, __u32 LunID);
static int cciss_dump_rw_block(void *device, int rw,
			       unsigned long dump_block_nr, void *buf,
			       int len, unsigned long start_sect,
			       unsigned long nr_sects);
static int cciss_dump_quiesce(void *device);
static int cciss_dump_shutdown(void *device);
static unsigned long diskdump_pollcomplete(int ctlr);
static unsigned int cciss_add_device(void *device);
static int sendcmd(__u8	cmd,int	ctlr,void *buff,size_t	size,
		   unsigned int use_unit_num, unsigned int log_unit,
		   __u8 page_code, unsigned char *scsi3addr, int cmd_type,
		   int block_nr, int diskdump);

/* Start of functions */

/*
 *   Wait polling for a command to complete.
 *   The memory mapped FIFO is polled for the completion.
 *   Used only at dump time, interrupts disabled.
 */
static unsigned long diskdump_pollcomplete(int ctlr)
{
	unsigned long done;

	while (1){
		done = hba[ctlr]->access.command_completed(hba[ctlr]);
		if (done == FIFO_EMPTY){
			udelay(20);
			continue;
		} else {
			QWORD tag = cciss_dump_cmnd[ctlr]->Header.Tag;
			/* our command? compare lower 4 bytes of tag */
			if (tag.lower != (done & CCISS_ERROR_BIT_MASK))
				continue;
			return done;
		}
	}
}


/*Dummy function.  Nothing to do here. */
static int cciss_dump_shutdown(void *device)
{
	return 0;
}

static int cciss_dump_quiesce(void *device)
{
	drive_info_struct *dev = device;
	int ret, ctlr, lun;
	char flush_buf[4];

	ctlr = dev->ctlr;
	if (find_ctlr_lun_ids(ctlr, &lun, dev->LunID))
		return -1;

	memset(flush_buf, 0, 4);
	ret = sendcmd(CCISS_CACHE_FLUSH, ctlr, flush_buf, 4, 0, 0, 0,
		      NULL, TYPE_CMD, 0, 1);

	if (ret != IO_OK){
		printk(KERN_ERR "cciss%d: Error flushing cache\n", ctlr);
		return -1;
	}

	quiesce_ok = 1;

	return 0;
}

static int cciss_dump_rw_block(void *device, int rw,
			       unsigned long dump_block_nr, void *buf,
			       int len, unsigned long start_sect,
			       unsigned long nr_sects)
{
	drive_info_struct *dev = device;
	int block_nr = BLOCK_SECTOR(dump_block_nr);

	/*this gives the number of bytes to write for len number
	 *of pages of memory.
	 */
	int count = (len * PAGE_SIZE);
	int ret;
	int ctlr, lun;
	__u8 cmd;

	ctlr = dev->ctlr;
	if (find_ctlr_lun_ids(ctlr, &lun, dev->LunID)){
		return -1;
	}
	
	if (rw)
		cmd = hba[ctlr]->cciss_write;
	else
		cmd = hba[ctlr]->cciss_read;


	if (!quiesce_ok) {
		return -1;
	}

	/* Calculate start block to be used in the CDB command */
	block_nr += start_sect;


	if (block_nr + (count/hba[ctlr]->drv[lun].block_size) > nr_sects + start_sect) {
		printk(KERN_ERR "block number %d is larger than %lu\n",
			block_nr + (count/hba[ctlr]->drv[lun].block_size),
			nr_sects);
		return -1;
	}

	ret = sendcmd(cmd, ctlr, buf, (size_t)count, 1, lun, 0, NULL, TYPE_CMD, block_nr, 1);
	return ret;
}

static int cciss_sanity_check(int ctlr, int lun)
{
	unsigned int block_size;
	sector_t total_size;
	int return_code;

	memset(size_buff, 0, sizeof(ReadCapdata_struct));

	if (hba[ctlr]->cciss_read == CCISS_READ_10) {
	return_code = sendcmd(CCISS_READ_CAPACITY, ctlr, size_buff,
			sizeof(ReadCapdata_struct), 1, lun, 0, NULL,
			TYPE_CMD, 0, 1);
	} else {
	return_code = sendcmd(CCISS_READ_CAPACITY_16, ctlr, size_buff_16,
			sizeof(ReadCapdata_struct_16), 1, lun, 0, NULL,
			TYPE_CMD, 0, 1);
	}

	if (return_code == IO_OK) {
		if (hba[ctlr]->cciss_read == CCISS_READ_10) {
			total_size = be32_to_cpu(*(__u32 *) size_buff->total_size);
			block_size = be32_to_cpu(*(__u32 *) size_buff->block_size);
		} else {
			total_size = be64_to_cpu(*(__u64 *) size_buff_16->total_size);
			block_size = be32_to_cpu(*(__u32 *) size_buff_16->block_size);
		}
		total_size++; 	/* command returns highest */
				/* block address */
	} else {	/* read capacity command failed */
		return -1;
	}

	if(hba[ctlr]->drv[lun].nr_blocks != total_size){
		printk(KERN_ERR "cciss:  blocks read do not match stored "
			"value\n");
		return -1;
	}

	return 0;
}

/*Will set ctlr and lun numbers if found and return 0.  If not found it
  will return 1 to indicate an error */
static int find_ctlr_lun_ids(int ctlr, int *lun, __u32 LunID)
{
	int i, j;
	*lun = -1;
	for (i=0; i<MAX_CTLR; i++){
		if (i == ctlr && hba[i] != NULL){
			for (j=0; j<CISS_MAX_LUN; j++){
				if (hba[i]->drv[j].LunID == LunID) {
					*lun = j;
					return 0;
				}
			}
		}
	}

	return 1;
}

static int cciss_dump_sanity_check(void *device)
{
	drive_info_struct *dev = device;
	int ctlr, lun;
	int adapter_sanity = 0;
	int sanity = 0;

	/* Find the controller and LUN by searching for the LUNID in our list
	   of known devices.  If not found then throw an error */
	ctlr = dev->ctlr;
	if (find_ctlr_lun_ids(ctlr, &lun, dev->LunID)){
		sanity = -1;
		return sanity;
	}

	/* send a CCISS_READ_CAPACITY command here for the drive.  If the
	   command succeeds then the drive is online.  Then we will check
	   that the values we get back match what we have recorded.  That
	   way we can tell if anything has changed */
	adapter_sanity=cciss_sanity_check(ctlr, lun);

	return sanity + adapter_sanity;
}

void* cciss_probe(struct gendisk *disk)
{
	ctlr_info_t *ctlr = get_host(disk);
	drive_info_struct *drv = get_drv(disk);

	if (!cciss_dump_cmnd[ctlr->ctlr])
		cciss_dump_cmnd[ctlr->ctlr] = cmd_alloc(ctlr, 0);

	size_buff = kmalloc(sizeof( ReadCapdata_struct), GFP_KERNEL);
	if (size_buff == NULL) {
		printk(KERN_ERR "cciss: out of memory\n");
		return NULL;
	}

	/* If the LUN does not exist on the controller then we must
	   let diskdump know that this device is not valid */
	if(drv->nr_blocks == 0){
		kfree(size_buff);
		return NULL;
	}

	return (void *)drv;
}

static unsigned int cciss_add_device(void *device)
{
	drive_info_struct *dev = device;

	return dev->nr_blocks;
}

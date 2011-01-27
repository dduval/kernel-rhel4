/*
 * dell_rbu.c
 * Bios Update driver for Dell systems
 * Author: Dell Inc
 *	   Abhay Salunke <abhay_salunke@dell.com>
 *
 * Copyright (C) 2004 Dell Inc.
 *
 * Remote BIOS Update (rbu) driver is used for updating DELL BIOS by creating 
 * entries in the /sys file systems on Linux 2.6 and higher kernels.
 * The driver supports two mechanism to update the BIOS namely contiguous and 
 * packetized. Both these methods still require to have some application to set
 * the  CMOS bit indicating the BIOS to update itself after a reboot.
 * 
 * Contiguous method:
 * This driver tries to allocates contiguos physical pages large enough 
 * to accomodate the BIOS image size specified by the user. The user 
 * supplied BIOS image is then copied in to the allocated contiguous pages.
 *
 * Packetized method:
 * In case of packetized the driver provides entries in the /sys file systems 
 * as packetdatasize and packetdata. This driver requires an application to 
 * break the BIOS image in to fixed sized packet chunks and each packet is 
 * written to the packetdata entry. The packetdatasize needs to be set once 
 * and is fixed for all the packets.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2.0 as published by
 * the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/version.h>
#include <linux/config.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include <linux/firmware.h>
#include <linux/spinlock.h>
#include <linux/moduleparam.h>

#define BIOS_SCAN_LIMIT 0xffffffff
MODULE_AUTHOR("Abhay Salunke <abhay_salunke@dell.com>");
MODULE_DESCRIPTION("Driver for updating BIOS image on DELL systems");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.8");

static unsigned long allocation_floor = 0x100000;
module_param(allocation_floor, ulong, 0644);
MODULE_PARM_DESC(allocation_floor,
	"Minimum address for allocations when using Packet mode");

static struct _rbu_data {
	void *image_update_buffer;
	unsigned long image_update_buffer_size;
	unsigned long bios_image_size;
	unsigned long image_update_order_number;
	spinlock_t lock;
	unsigned long packet_read_count;
	unsigned long packet_write_count;
	unsigned long num_packets;
	unsigned long packetsize;
} rbu_data;

struct packet_data{
	struct list_head list;
	size_t length;
	void *data;
	int ordernum;
};


static struct packet_data packet_data_head;

/* no default attributes yet. */
static struct attribute * def_attrs[] = { NULL, };

/* don't use show and store attribute functions */
static struct sysfs_ops rbu_attr_ops = { };

static struct kobj_type ktype_rbu = { 
	.sysfs_ops	= &rbu_attr_ops,
	.default_attrs	= def_attrs,
};

static decl_subsys(rbu,&ktype_rbu,NULL);

static void init_packet_head(void)
{
	INIT_LIST_HEAD(&packet_data_head.list);
	rbu_data.packet_write_count = 0;
	rbu_data.packet_read_count = 0;
	rbu_data.num_packets = 0;
	rbu_data.packetsize = 0;
}

static int fill_last_packet(void *data, size_t length)
{
	struct list_head *ptemp_list;
	struct packet_data *ppacket = NULL;
	int packet_count = 0;
	
	pr_debug("fill_last_packet: entry \n");

	/* check if we have any packets */
	if (0 == rbu_data.num_packets) {
		pr_debug("fill_last_packet: num_packets=0\n");
		return -ENOMEM;
	}

	packet_count = rbu_data.num_packets;

	ptemp_list = (&packet_data_head.list)->next;
	
	while(--packet_count) 
		ptemp_list = ptemp_list->next;
	
	ppacket = list_entry(ptemp_list,struct packet_data, list);

	if ((rbu_data.packet_write_count + length) > rbu_data.packetsize) {
		printk(KERN_WARNING "fill_last_packet: packet size data "
				"overrun\n");
		return -ENOMEM;
	}
	
	pr_debug("fill_last_packet : buffer = %p\n", ppacket->data);

	/* copy the incoming data in to the new buffer */
	memcpy((ppacket->data + rbu_data.packet_write_count), 
		data, length);
	
	if ((rbu_data.packet_write_count + length) == rbu_data.packetsize) {
		/* 
		 this was the last data chunk in the packet 
		 so reinitialize the packet data counter to zero 
		*/
		rbu_data.packet_write_count = 0;
	} else {
		rbu_data.packet_write_count += length;
	}
	pr_debug("fill_last_packet: exit \n");
	return 0;
}

/*
 get_free_pages_limited:
 This is a helper function which allocates free pages based on an upper limit.
 On x86_64 or 64 bit arch the memory allocation goes above 4GB space which is 
 not addressable by the BIOS. This function tries to get allocation below the 
 limit (4GB) address. It first tries to allocate memory normally using the 
 GFP_KERNEL argument if the incoming limit is non-zero and if the returned 
 physical memory address exceeds the upper limit, the allocated pages are freed 
 and the memory is reallocated using the GFP_DMA argument.
*/
static void *get_free_pages_limited(unsigned long size,
                                    int *ordernum,
				    unsigned long limit)
{
	unsigned long img_buf_phys_addr;
	void *pbuf = NULL;

	*ordernum = get_order(size);
	/* 
         Check if we are not getting a very large file. 
	 This can happen as a user error in entering the file size 
        */
	if (*ordernum == BITS_PER_LONG) {
		pr_debug("get_free_pages_limited: Incoming size is"
			" very large\n");
		return NULL;
	}
	
	/* try allocating a new buffer to fit the request */
	pbuf =(unsigned char *)__get_free_pages(GFP_KERNEL, *ordernum);

	if (pbuf != NULL) {
        	/* check if the image is with in limits */
		img_buf_phys_addr = (unsigned long)virt_to_phys(pbuf);
		
		if ((limit != 0) && ((img_buf_phys_addr + size) > limit)) {
			pr_debug("Got memory above 4GB range, free this "
				"and try with DMA memory\n");
			/* free this memory as we need it with in 4GB range */
			free_pages ((unsigned long)pbuf, *ordernum);
			/* 
                         Try allocating a new buffer from the GFP_DMA range 
			 as it is with in 16MB range.
			*/
			pbuf =(unsigned char *)__get_free_pages(GFP_DMA, 
						*ordernum);
			if (pbuf == NULL)
				pr_debug("Failed to get memory of size %ld "
					"using GFP_DMA\n", size);
		}
	}
	return pbuf;
}

static int create_packet(size_t length)
{
	struct packet_data *newpacket;
	int ordernum = 0;
	int retval = 0;
	unsigned int packet_array_size = 0;
	void **invalid_addr_packet_array = 0;
	void *packet_data_temp_buf = 0;
	unsigned int idx = 0;

	pr_debug("create_packet: entry \n");

	if (rbu_data.packetsize == 0 ) {
		pr_debug("create_packet: packetsize not specified\n");
		retval = -EINVAL;
		goto out_noalloc;
	}

	spin_unlock(&rbu_data.lock);

	newpacket = kmalloc(sizeof(struct packet_data) ,GFP_KERNEL);
	if(newpacket == NULL) {
		printk(KERN_WARNING "create_packet: failed to allocate new "
			"packet\n");
		retval = -ENOMEM;
		spin_lock(&rbu_data.lock);
		goto out_noalloc;
	}

	ordernum = get_order(rbu_data.packetsize);

	/*
	 * BIOS errata mean we cannot allocate packets below 1MB or they will
	 * be overwritten by BIOS.
	 *
	 * array to temporarily hold packets
	 * that are below the allocation floor
	 *
	 * NOTE: very simplistic because we only need the floor to be at 1MB
	 * 	 due to BIOS errata. This shouldn't be used for higher floors
	 *	 or you will run out of mem trying to allocate the array.
	 */
	packet_array_size = max(
			(unsigned int)(allocation_floor / rbu_data.packetsize),
			(unsigned int)1);
	invalid_addr_packet_array = kmalloc(packet_array_size * sizeof(void*),
						GFP_KERNEL);

	if (!invalid_addr_packet_array) {
		printk(KERN_WARNING
			"dell_rbu:%s: failed to allocate "
			"invalid_addr_packet_array \n",
			__FUNCTION__);
		retval = -ENOMEM;
		spin_lock(&rbu_data.lock);
		goto out_alloc_packet;
	}

	while (!packet_data_temp_buf)
	{
		packet_data_temp_buf = (unsigned char *)
			__get_free_pages(GFP_KERNEL, ordernum);
		if (!packet_data_temp_buf)
		{
			printk(KERN_WARNING
				"dell_rbu:%s: failed to allocate new "
				"packet\n", __FUNCTION__);
			retval = -ENOMEM;
			spin_lock(&rbu_data.lock);
			goto out_alloc_packet_array;
		}

		if ((unsigned long)virt_to_phys(packet_data_temp_buf)
				< allocation_floor)
		{
			pr_debug("packet 0x%lx below floor at 0x%lx.\n",
					(unsigned long)virt_to_phys(
						packet_data_temp_buf),
					allocation_floor);
			invalid_addr_packet_array[idx++] = packet_data_temp_buf;
			packet_data_temp_buf = 0;
		}
	}
	spin_lock(&rbu_data.lock);

	newpacket->data = packet_data_temp_buf;

	pr_debug("create_packet: newpacket at physical addr %lx\n",
		(unsigned long)virt_to_phys(newpacket->data));

	newpacket->ordernum = ordernum;
	++rbu_data.num_packets;
	/* initialize the newly created packet headers */
	INIT_LIST_HEAD(&newpacket->list);
	list_add_tail(&newpacket->list, &packet_data_head.list);
	/* packets have fixed size*/
	newpacket->length = rbu_data.packetsize;
	
	pr_debug("create_packet: exit \n");

out_alloc_packet_array:
	/* always free packet array */
	for (;idx>0;idx--)
	{
		pr_debug("freeing unused packet below floor 0x%lx.",
			(unsigned long)virt_to_phys(
				invalid_addr_packet_array[idx-1]));
		free_pages((unsigned long)invalid_addr_packet_array[idx-1],
			ordernum);
	}
	kfree(invalid_addr_packet_array);

out_alloc_packet:
	/* if error, free data */
	if (retval)
		kfree(newpacket);

out_noalloc:
	return retval;
}


static int packetize_data(void *data, size_t length) 
{
	int rc = 0;

	pr_debug("packetize_data : entry\n");
	if (rbu_data.packet_write_count == 0) {
		if ((rc = create_packet(length)) != 0 )
			return rc;
	}
	/* fill data in to the packet */	
	if ((rc = fill_last_packet(data, length)) != 0)
		return rc;
	
	pr_debug("packetize_data : exit\n");
	return rc;
}


/*
 do_packet_read :
 This is a helper function which reads the packet data of the 
 current list.
 data: is the incoming buffer
 ptemp_list: points to the incoming list item
 length: is the length of the free space in the buffer.
 bytes_read: is the total number of bytes read already from 
 the packet list
 list_read_count: is the counter to keep track of the number 
 of bytes read out of each packet.
*/
int do_packet_read(char *data, 
		   struct list_head *ptemp_list, 
		   int length,
		   int bytes_read, 
		   int *list_read_count)
{
	void *ptemp_buf;
	struct packet_data *newpacket = NULL;
	int bytes_copied = 0;
	int j = 0;

	newpacket = list_entry(ptemp_list,struct packet_data, list);
	*list_read_count += newpacket->length;

	if (*list_read_count > bytes_read) {
		/* point to the start of unread data */
		j = newpacket->length - (*list_read_count - bytes_read);
		/* point to the offset in the packet buffer*/
		ptemp_buf = (u8 *)newpacket->data + j;
		/* check if there is enough room in the	incoming buffer*/
		if (length > (*list_read_count - bytes_read)) 
			/* copy what ever is there in this packet and move on*/
			bytes_copied = (*list_read_count - bytes_read);
		else 
			/* copy the remaining */
			bytes_copied = length;
		memcpy(data, ptemp_buf, bytes_copied);
	} 
	return bytes_copied;
}

/*
 packet_read_list:
 This function reads the data out of the packet link list.
 It will read data from multiple packets depending upon the 
 size of the incoming buffer.
 data: is the incoming buffer pointer
 *pread_length: is the length of the incoming buffer. At return 
 this value is adjusted to the actual size of the data read.
*/
static int packet_read_list(char *data, size_t *pread_length)
{
	struct list_head *ptemp_list;
	int temp_count = 0;
	int bytes_copied = 0;
	int bytes_read = 0;
	int remaining_bytes =0;
	char *pdest = data;

	/* check if we have any packets */
	if (0 == rbu_data.num_packets)
		return -ENOMEM;

	remaining_bytes = *pread_length;
	bytes_read = rbu_data.packet_read_count;

	ptemp_list = (&packet_data_head.list)->next;
	while(!list_empty(ptemp_list)) {
		bytes_copied = do_packet_read(pdest, ptemp_list, 
			remaining_bytes, bytes_read, &temp_count);
		remaining_bytes -= bytes_copied;
		bytes_read += bytes_copied;
		pdest += bytes_copied;
		/* 
		 check if we reached end of buffer before reaching the 
		 last packet
		*/
		if (remaining_bytes == 0)
			break;

		ptemp_list = ptemp_list->next;
	}
	/*finally set the bytes read */
	*pread_length = bytes_read - rbu_data.packet_read_count;
	rbu_data.packet_read_count = bytes_read;
	return 0;
}

static void packet_empty_list(void)
{
	struct list_head *ptemp_list;
	struct list_head *pnext_list;
	struct packet_data *newpacket;

	ptemp_list = (&packet_data_head.list)->next;
	while(!list_empty(ptemp_list)) {
		newpacket = list_entry(ptemp_list, struct packet_data, list);
		pnext_list = ptemp_list->next;
		list_del(ptemp_list);
		ptemp_list = pnext_list;
		/* 
		 zero out the RBU packet memory before freeing to make sure
		 there are no stale RBU packets left in memory 
		*/
		memset(newpacket->data, 0, rbu_data.packetsize);
		free_pages((unsigned long)newpacket->data, newpacket->ordernum);
		kfree(newpacket);
	}
	rbu_data.packet_write_count = 0;
	rbu_data.packet_read_count = 0;
	rbu_data.num_packets = 0;
}


/*
 img_update_free:
 Frees the buffer allocated for storing BIOS image
 Always called with lock held and returned with lock held
*/
static void img_update_free( void)
{
	if (rbu_data.image_update_buffer == NULL)
		return;
	
	/* 
	 zero out this buffer before freeing it to get rid of any stale 
	 BIOS image copied in memory.
	*/
	memset(rbu_data.image_update_buffer, 0, 
		rbu_data.image_update_buffer_size);
 	free_pages((unsigned long)rbu_data.image_update_buffer, 
		rbu_data.image_update_order_number);
	/* Re-initialize the rbu_data variables after a free */
	rbu_data.image_update_buffer = NULL;
	rbu_data.image_update_buffer_size = 0;
	rbu_data.bios_image_size = 0;
}

/*
 img_update_realloc:
 This function allocates the contiguous pages to accomodate the requested
 size of data. The memory address and size values are stored globally and 
 on every call to this function the new size is checked to see if more 
 data is required than the existing size. If true the previous memory is freed
 and new allocation is done to accomodate the new size. If the incoming size is 
 less then than the already allocated size, then that  memory is reused.
 This function is called with lock held and returna with lock held.
*/
static int img_update_realloc(unsigned long size)
{
	unsigned char *image_update_buffer = NULL;
	unsigned long rc;
	int ordernum =0;


	/* check if the buffer of sufficient size has been already allocated */
    if (rbu_data.image_update_buffer_size >= size) {
		/* check for corruption */
		if ((size != 0) && (rbu_data.image_update_buffer == NULL)) {
			pr_debug("img_update_realloc: corruption check "
				"failed\n");
			return -EINVAL;
		}
		/* we have a valid pre-allocated buffer with sufficient size */
		return 0;
    }

	/* free any previously allocated buffer */
	img_update_free();

	/* 
	 This has already been called as locked so we can now unlock 
	 and proceed to calling get_free_pages_limited as this function
	 can sleep
	*/
	spin_unlock(&rbu_data.lock);

	image_update_buffer = (unsigned char *)get_free_pages_limited(size,
		&ordernum,
		BIOS_SCAN_LIMIT);
	
	/* acquire the spinlock again */
	spin_lock(&rbu_data.lock);

	if (image_update_buffer != NULL) {
		rbu_data.image_update_buffer = image_update_buffer;
		rbu_data.image_update_buffer_size = PAGE_SIZE << ordernum;
		rbu_data.image_update_order_number = ordernum;
		memset(rbu_data.image_update_buffer,0, 
			rbu_data.image_update_buffer_size);
		pr_debug("img_update_realloc: success\n");
		rc = 0; 
	} else {
		pr_debug("Not enough memory for image update:order number = %d"
			",size = %ld\n",ordernum, size);
		rc = -ENOMEM;
	}

	return rc;
} /* img_update_realloc */


/*
 read_packet_data_size:
 Returns the size of an RBU packet; if no packets present returns 0
*/
static ssize_t read_packet_data_size(struct kobject *kobj, 
				     char *buffer,
   				     loff_t pos, 
				     size_t count)
{
	unsigned int size = 0;
	if (pos == 0)
		size = scnprintf(buffer, count, "%lu\n", rbu_data.packetsize);
	return size;
} 

/*
 write_packet_data_size:
 Writes the RBU data size supplied by the user, if the 
 data size supplied is non zero number, this function 
 records the packet size for any packet allocations.
 If a byte size of zero is supplied this function will free
 the previously allocated packets.
*/
static ssize_t write_packet_data_size(struct kobject *kobj, 
				      char *buffer, 
				      loff_t pos, 
				      size_t count)
{
	int retval = count;

	spin_lock(&rbu_data.lock);
	/* extract the image size */
	sscanf(buffer, "%lu",&rbu_data.packetsize);
	/* free the previous packet lists */
	packet_empty_list();

	spin_unlock(&rbu_data.lock);
	return retval;
}

/*
 read_rbu_data_size:
 Returns the size of an RBU image previously downloaded
 if no image is downloaded the size returned is 0
*/
static ssize_t read_rbu_data_size(struct kobject *kobj, 
				  char *buffer, 
				  loff_t pos, 
				  size_t count)
{
	unsigned int size = 0;
	if (pos == 0)
		size = scnprintf(buffer, count, "%lu\n", rbu_data.bios_image_size);
	return size;
} 

/*
 write_rbu_data_size:
 Writes the RBU data size supplied by the user, if the 
 data size supplied is non zero number, this function 
 allocates the contiguous physical memory pages for the 
 supplied size , if it fails this function returns error.
 If a byte size of zero is supplied this function will free
 the previously allocated contiguous pages.
*/
static ssize_t write_rbu_data_size(struct kobject *kobj, 
				   char *buffer, 
				   loff_t pos, 
				   size_t count)
{
	int retval = count;

	spin_lock(&rbu_data.lock);
	/* extract the image size */
	sscanf(buffer, "%lu",&rbu_data.bios_image_size);

	if (rbu_data.bios_image_size !=0 ) {
		if (img_update_realloc(rbu_data.bios_image_size) < 0) {
			pr_debug("write_rbu_data_size: failed to allocate "
				"mem size %lu\n", 
				(unsigned long)rbu_data.bios_image_size);
			rbu_data.bios_image_size = 0;
			retval = -ENOMEM;
		} 
	} else {
		pr_debug(" freeing %ld size memory \n", 
				rbu_data.bios_image_size);
		img_update_free();
	}
	
	pr_debug("write_rbu_data_size: = %lu\n", 
		(unsigned long)rbu_data.bios_image_size);

	spin_unlock(&rbu_data.lock);
	return retval;
} /* write_rbu_data_size*/

/*
 read_rbu_data:
 Reads the BIOS image file from previously allocated contiguous physical 
 pages in to the buffer supplied in this call. 
 The reading is done in chunks of bytes supplied in the count argument.
 The reading stops when the total number of bytes read equals the image 
 size given previously.
 If image size is not specified or if the image size is zero this function 
 returns failure.
 Parameters: 
 kobj is the kernel object 
 buffer is the pointer to the incoming data buffer.
 count is the value of the incoming buffer size,
 pos is the amount of bytes already read.
*/
static ssize_t read_rbu_data(struct kobject *kobj, 
			     char *buffer,
			     loff_t pos, 
			     size_t count)
{
	unsigned char *ptemp = NULL;
	int retval =0;
	size_t bytes_left = 0;
	size_t data_length = 0;

	spin_lock(&rbu_data.lock);

	/* check to see if we have something to return */
	if ((rbu_data.image_update_buffer == NULL) || 
		(rbu_data.bios_image_size == 0)) {
		pr_debug("read_rbu_data: image_update_buffer %p ,"
			"bios_image_size %lu\n",
			rbu_data.image_update_buffer, 
			rbu_data.bios_image_size);
		retval = -ENOMEM;
		goto read_rbu_data_exit;
	}
	
	if ( pos > rbu_data.bios_image_size ) {
		retval = 0;
		goto read_rbu_data_exit;
	}

	bytes_left = rbu_data.bios_image_size - pos;
	data_length = min(bytes_left,count);

	ptemp = rbu_data.image_update_buffer;
	memcpy(buffer, (ptemp + pos), data_length);

	if ((pos + count) > rbu_data.bios_image_size)
		/* this was the last copy */
		retval = bytes_left;
	else 
		retval = count;
	
read_rbu_data_exit:
	spin_unlock(&rbu_data.lock);
	return retval;
}

/*
 write_rbu_data
 Writes from the incoming BIOS image file to the pre-allocated 
 contiguous physical memory pages. 
 The writes occur in chunks of memory supplied by the count. The writes 
 stops when the total memory supplied equals the image size given previously.
 If no memory size is previously specified or if the previously specified size 
 is zero the write returns error.
*/
static ssize_t write_rbu_data(struct kobject *kobj, 
			      char *buffer,
			      loff_t pos, 
			      size_t count)
{
	unsigned char *pDest = NULL;
	unsigned char *ptemp = NULL;
	int retval = 0;

	spin_lock(&rbu_data.lock);

	/* check if the image size is given */
	if (0 == rbu_data.bios_image_size) {
		printk(KERN_WARNING "write_rbu_data: BIOS image size "
				"not set\n");
		retval = -ENOMEM;
		goto error_exit;
	}

	if ((pos + count) > rbu_data.bios_image_size) {
		pr_debug("write_rbu_data: data_over_run, file pos %lu "
			"bios_image_size %lu\n",
			(unsigned long)pos,
			rbu_data.bios_image_size);
		retval = -ENOMEM;
		goto error_exit;
	}

	pDest = (unsigned char*)rbu_data.image_update_buffer;
	ptemp = pDest + pos;
	memcpy(ptemp, buffer,  count);
	retval = count;
	pr_debug("write_rbu_data : retval = %d\n", retval);
error_exit:
	spin_unlock(&rbu_data.lock);
	return retval;
}

/*
 read_rbu_packet_data:
 Reads the BIOS image file from previously allocated contiguous physical 
 pages in to the buffer supplied in this call. 
 The reading is done in chunks of bytes supplied in the count argument.
 The reading stops when the total number of bytes read equals the image 
 size given previously.
 If image size is not specified or if the image size is zero this function 
 returns failure.
 Parameters: 
 kobj is the kernel object 
 buffer is the pointer to the incoming data buffer.
 count is the value of the incoming buffer size,
 pos is the amount of bytes already read.
*/
static ssize_t read_rbu_packet_data(struct kobject *kobj, 
				    char *buffer,
				    loff_t pos, 
				    size_t count)
{
	int retval;
	size_t bytes_left;
	size_t data_length;
	char *ptempBuf = buffer;
	unsigned long imagesize;

	spin_lock(&rbu_data.lock);

	/* check to see if we have something to return */
	if (rbu_data.num_packets == 0) {
		pr_debug("read_rbu_packet_data: no packets written\n");
		retval = -ENOMEM;
		goto read_rbu_data_exit;
	}

	imagesize = rbu_data.num_packets * rbu_data.packetsize;
	
	if ( pos > imagesize ) {
		retval = 0;
		printk(KERN_WARNING "read_rbu_packet_data: data underrun\n");
		goto read_rbu_data_exit;
	}

	bytes_left = imagesize - pos;
	data_length = min(bytes_left, count);

	if ((retval = packet_read_list(ptempBuf, &data_length)) < 0)
		goto read_rbu_data_exit;

	if ((pos + count) > imagesize) {
		rbu_data.packet_read_count = 0;
		/* this was the last copy */
		retval = bytes_left;
	}
	else 
		retval = count;
	
read_rbu_data_exit:
	spin_unlock(&rbu_data.lock);
	return retval;
}

/*
 write_rbu_packet_data
 Writes from the incoming BIOS image file to the pre-allocated 
 contiguous physical memory pages. 
 The writes occur in chunks of memory supplied by the count. The writes 
 stops when the total memory supplied equals the image size given previously.
 If no memory size is previously specified or if the previously specified size 
 is zero the write returns error.
*/
static ssize_t write_rbu_packet_data(struct kobject *kobj, 
				     char *buffer,
				     loff_t pos, 
				     size_t count)
{
	int retval = 0;

	spin_lock(&rbu_data.lock);

	/* check if the packet size is given */
	if (0 == rbu_data.packetsize) {
		printk(KERN_WARNING "write_rbu_packet_data: packetsize " 
			"not set\n");
		retval = -ENOMEM;
		goto error_exit;
	}

	if ((pos + count) > rbu_data.packetsize) {
		pr_debug("write_rbu_packet_data: data_over_run, file pos %lu,"
			"packetsize %lu\n",
			(unsigned long)pos,
			rbu_data.packetsize);
		retval = -ENOMEM;

		/* 
		 We have a write data overrun, obviously this is 
		 not the corret file, so free the previous data
		*/
		pr_debug("data overrun freeing all the previous packets\n");
		packet_empty_list();
		goto error_exit;
	}

	if ((retval = packetize_data(buffer, count)) < 0 ) {
		pr_debug(KERN_WARNING "write_rbu_packet_data: packetize_data "
			"failed with status %d\n", retval);
		retval = -EIO;
		goto error_exit;
	} 

	retval = count;

	pr_debug("write_rbu_packet_data : retval = %d\n", retval);

error_exit:
	spin_unlock(&rbu_data.lock);
	return retval;
}


static struct bin_attribute rbudata_attr = {
	.attr = {.name = "rbudata", .owner = THIS_MODULE, .mode = 0644},
	.read = read_rbu_data,
	.write = write_rbu_data,
};

static struct bin_attribute rbudatasize_attr = {
	.attr = { .name = "rbudatasize", .owner = THIS_MODULE, .mode = 0644},
	.read = read_rbu_data_size,
	.write= write_rbu_data_size,
};

static struct bin_attribute packetdatasize_attr = {
	.attr = { .name = "packetdatasize", .owner = THIS_MODULE, .mode = 0644},
	.read = read_packet_data_size,
	.write= write_packet_data_size,
};

static struct bin_attribute packetdata_attr = {
	.attr = { .name = "packetdata", .owner = THIS_MODULE, .mode = 0644},
	.read = read_rbu_packet_data,
	.write= write_rbu_packet_data,
};

static int __init dcdrbu_init(void)
{
	int rc;

	spin_lock_init(&rbu_data.lock);

	init_packet_head();
	
	rc = firmware_register(&rbu_subsys);
	if (rc < 0) {
		printk(KERN_WARNING "dcdrbu_init: firmware_register failed\n");
		return rc;
	}

	sysfs_create_bin_file(&rbu_subsys.kset.kobj,&rbudata_attr);
	sysfs_create_bin_file(&rbu_subsys.kset.kobj,&rbudatasize_attr);
	sysfs_create_bin_file(&rbu_subsys.kset.kobj,&packetdatasize_attr);
	sysfs_create_bin_file(&rbu_subsys.kset.kobj,&packetdata_attr);

	return rc;
}

static __exit void dcdrbu_exit( void)
{
	spin_lock(&rbu_data.lock);
	packet_empty_list();
	img_update_free();
	spin_unlock(&rbu_data.lock);
	sysfs_remove_bin_file(&rbu_subsys.kset.kobj, &rbudata_attr);
	sysfs_remove_bin_file(&rbu_subsys.kset.kobj, &rbudatasize_attr);
	sysfs_remove_bin_file(&rbu_subsys.kset.kobj, &packetdatasize_attr);
	sysfs_remove_bin_file(&rbu_subsys.kset.kobj, &packetdata_attr);
	firmware_unregister(&rbu_subsys);
} 

module_exit(dcdrbu_exit);
module_init(dcdrbu_init);


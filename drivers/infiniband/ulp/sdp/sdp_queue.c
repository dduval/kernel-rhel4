/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id: sdp_queue.c 3033 2005-08-09 12:45:08Z mst $
 */

#include "sdp_main.h"

/*
 * module specific functions
 */

/*
 * sdp_desc_q_get - Get an element from a specific table
 */
static struct sdpc_desc *sdp_desc_q_get(struct sdpc_desc_q *table, int fifo)
{
	struct sdpc_desc *element;

	if (!table->head)
		return NULL;

	if (fifo)
		element = table->head;
	else
		element = table->head->prev;

	if (element->next == element && element->prev == element)
		table->head = NULL;
	else {
		element->next->prev = element->prev;
		element->prev->next = element->next;

		table->head = element->next;
	}

	table->size--;
	table->count[element->type] -=
	    ((SDP_DESC_TYPE_NONE > element->type) ? 1 : 0);

	element->next = NULL;
	element->prev = NULL;
	element->table = NULL;

	return element;
}

/*
 * sdp_desc_q_put - Place an element into a specific table
 */
static inline void sdp_desc_q_put(struct sdpc_desc_q *table,
				 struct sdpc_desc *element, int fifo)
{
	/*
	 * fifo: false == tail, true == head
	 */
	BUG_ON(element->table);

	if (!table->head) {
		element->next = element;
		element->prev = element;
		table->head = element;
	} else {
		element->next = table->head;
		element->prev = table->head->prev;

		element->next->prev = element;
		element->prev->next = element;

		if (fifo)
			table->head = element;
	}

	table->size++;
	table->count[element->type] +=
	    ((SDP_DESC_TYPE_NONE > element->type) ? 1 : 0);
	element->table = table;
}

/*
 * public advertisment object functions for FIFO object table
 */

/*
 * sdp_desc_q_remove - remove a specific element from a table
 */
void sdp_desc_q_remove(struct sdpc_desc *element)
{
	struct sdpc_desc_q *table;
	struct sdpc_desc *prev;
	struct sdpc_desc *next;

	table = element->table;

	if (element->next == element && element->prev == element)
		table->head = NULL;
	else {
		next = element->next;
		prev = element->prev;
		next->prev = prev;
		prev->next = next;

		if (table->head == element)
			table->head = next;
	}

	table->size--;
	table->count[element->type] -=((SDP_DESC_TYPE_NONE > element->type) ?
				       1 : 0);
	element->table = NULL;
	element->next = NULL;
	element->prev = NULL;
}

/*
 * sdp_desc_q_lookup - search and return an element from the table
 */
struct sdpc_desc *sdp_desc_q_lookup(struct sdpc_desc_q *table,
				    int (*lookup)(struct sdpc_desc *element,
						  void *arg),
				    void *arg)
{
	struct sdpc_desc *element;
	int counter;

	for (counter = 0, element = table->head;
	     counter < table->size; counter++, element = element->next)
		if (!lookup(element, arg))
			return element;

	return NULL;
}

/*
 * sdp_desc_q_get_head - Get the element at the front of the table
 */
struct sdpc_desc *sdp_desc_q_get_head(struct sdpc_desc_q *table)
{
	return sdp_desc_q_get(table, 1);
}

/*
 * sdp_desc_q_get_tail - Get the element at the end of the table
 */
struct sdpc_desc *sdp_desc_q_get_tail(struct sdpc_desc_q *table)
{
	return sdp_desc_q_get(table, 0);
}

/*
 * sdp_desc_q_put_head - Place an element into the head of a table
 */
void sdp_desc_q_put_head(struct sdpc_desc_q *table, struct sdpc_desc *element)
{
	sdp_desc_q_put(table, element, 1);
}

/*
 * sdp_desc_q_put_tail - Place an element into the tail of a table
 */
void sdp_desc_q_put_tail(struct sdpc_desc_q *table, struct sdpc_desc *element)
{
	sdp_desc_q_put(table, element, 0);
}

/*
 * sdp_desc_q_look_head - look at the front of the table
 */
struct sdpc_desc *sdp_desc_q_look_head(struct sdpc_desc_q *table)
{
	return table->head;
}

/*
 * sdp_desc_q_type_head - look at the type at the front of the table
 */
int sdp_desc_q_type_head(struct sdpc_desc_q *table)
{
	if (!table->head)
		return SDP_DESC_TYPE_NONE;
	else
		return table->head->type;
}

/*
 * sdp_desc_q_look_type_head - look at a specific object
 */
struct sdpc_desc *sdp_desc_q_look_type_head(struct sdpc_desc_q *table,
					    enum sdp_desc_type type)
{
	if (!table->head)
		return NULL;
	else
		return ((type == table->head->type) ? table->head : NULL);
}

/*
 * sdp_desc_q_look_type_tail - look at the type at the end of the table
 */
struct sdpc_desc *sdp_desc_q_look_type_tail(struct sdpc_desc_q *table,
					    enum sdp_desc_type type)
{
	if (!table->head)
		return NULL;
	else
		return ((type == table->head->prev->type) ?
			table->head->prev : NULL);
}

/*
 * sdp_desc_q_types_size - return the number of elements in the table
 */
int sdp_desc_q_types_size(struct sdpc_desc_q *table, enum sdp_desc_type type)
{
	return ((SDP_DESC_TYPE_NONE > type) ?
		table->count[type] : -ERANGE);
}

/*
 * sdp_desc_q_init - initialize a new empty generic table
 */
void sdp_desc_q_init(struct sdpc_desc_q *table)
{
	table->head = NULL;
	table->size = 0;

	memset(table, 0, sizeof(struct sdpc_desc_q));
}

/*
 * sdp_desc_q_clear - clear the contents of a generic table
 */
void sdp_desc_q_clear(struct sdpc_desc_q *table)
{
	struct sdpc_desc *element;
	/*
	 * drain the table of any objects
	 */
	while ((element = sdp_desc_q_get_head(table)))
		if (element->release)
			element->release(element);
}

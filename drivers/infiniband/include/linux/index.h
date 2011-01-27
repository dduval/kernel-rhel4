/*
 * Copyright (c) 2006 Intel Corporation.  All rights reserved.
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
 */

#ifndef INDEX_H
#define INDEX_H

#include <linux/types.h>

enum {
	INDEX_EMPTY,
	INDEX_NODE,
	INDEX_LEAF
};

struct index_leaf {
	void *data;
	u8 key[0];
};

struct index_node {
	void *parent;
	void *child[256];
	char child_type[256];
	unsigned int ref_cnt;
};

struct index_root {
	struct index_node node;
	size_t key_length;
	gfp_t gfp_mask;
};

/**
 * index_init - Initialize the index before use.
 * @root: The index root.
 * @key_length: The size of the index key.
 * @gfp_mask: GFP mask to use when allocating resources inserting items into the
 *   index.
 */
void index_init(struct index_root *root, size_t key_length,
		gfp_t gfp_mask);

/**
 * index_destroy - Destroy the index, cleaning up any internal resources.
 */
void index_destroy(struct index_root *root);

/**
 * index_insert - Insert a data item in the index.
 * @root: The index root.
 * @data: Data item to insert into the index.
 * @key: Index key value to associate with the specified data item.
 *
 * Returns NULL if the item was successfully inserted.  If an item already
 * exists in the index with the same key, returns that item.  Otherwise, an
 * error will be returned.
 */
void *index_insert(struct index_root *root, void *data, void *key);

/**
 * index_find - Return a data item in the index associated with the given key.
 * @root: The index root.
 * @key: The index key associated with the data item to retrieve.
 *
 * If the key is not found in the index, returns NULL.
 */
void *index_find(struct index_root *root, void *key);

/**
 * index_find_replace - Replace a data item in the index associated with the
 *   given key with the new item, and return the old item.
 * @root: The index root.
 * @data: Data item to replace the existing item.
 * @key: Index key value associated with the data item.
 *
 * If an existing item is not found in the index, the replacement fails, and
 * the function returns NULL.
 */
void *index_find_replace(struct index_root *root, void *data, void *key);

/**
 * index_remove - Remove a data item from the index.
 * @root: The index root.
 * @key: The index key to remove from the index.
 *
 * Returns the data item removed from the index, or NULL if no item was found.
 */
void *index_remove(struct index_root *root, void *key);

/**
 * index_remove_all - Remove all index values, invoking a user-specified routine
 *   for any data items that remain in the index.
 * @root: The index root.
 * @callback: A routine invoked for all objects remaining in the index.  This
 *   parameter may be NULL.
 * @context: User specified context passed to the user's %callback.
 *
 * This routine removes all indexed values, calling the specified free routine
 * for all objects stored in the index.
 */
void index_remove_all(struct index_root *root,
		      void (*callback)(void *context, void *data),
		      void *context);

#endif /* INDEX_H */

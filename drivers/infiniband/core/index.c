/*
 * Copyright (c) 2006 Intel Corporation.  All rights reserved.
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

#include <linux/err.h>
#include <linux/module.h>

#include <linux/index.h>

MODULE_AUTHOR("Sean Hefty");
MODULE_DESCRIPTION("Indexing service");
MODULE_LICENSE("Dual BSD/GPL");

void index_init(struct index_root *root, size_t key_length,
		gfp_t gfp_mask)
{
	memset(root, 0, sizeof *root);
	root->key_length = key_length;
	root->gfp_mask = gfp_mask;
	root->node.ref_cnt = 1;	/* do not delete root node */
}
EXPORT_SYMBOL(index_init);

void index_destroy(struct index_root *root)
{
	index_remove_all(root, NULL, NULL);
}
EXPORT_SYMBOL(index_destroy);

void *index_insert(struct index_root *root, void *data, void *key)
{
	struct index_node *node, *new_node;
	struct index_leaf *leaf;
	int i, k, j;

	for (node = &root->node, k = 0; 1; node = node->child[i], k++) {
		i = *((u8 *) key + k);
		if (!node->child[i]) {
			leaf = kzalloc(sizeof *leaf + root->key_length,
				       root->gfp_mask);
			if (!leaf)
				return ERR_PTR(-ENOMEM);

			leaf->data = data;
			memcpy(leaf->key, key, root->key_length);
			node->child[i] = leaf;
			node->child_type[i] = INDEX_LEAF;
			node->ref_cnt++;
			return NULL;
		} else if (node->child_type[i] == INDEX_LEAF) {
			leaf = node->child[i];
			if (!memcmp(leaf->key + k, key + k,
				    root->key_length - k))
				return leaf->data;

			new_node = kzalloc(sizeof *new_node, root->gfp_mask);
			if (!new_node)
				return ERR_PTR(-ENOMEM);

			node->child[i] = new_node;
			node->child_type[i] = INDEX_NODE;
			new_node->parent = node;
			new_node->ref_cnt++;
			j = leaf->key[k + 1];
			new_node->child[j] = leaf;
			new_node->child_type[j] = INDEX_LEAF;
		}
	}
	return ERR_PTR(-EINVAL);
}
EXPORT_SYMBOL(index_insert);

void *index_find(struct index_root *root, void *key)
{
	struct index_node *node;
	struct index_leaf *leaf;
	int i, k;

	for (node = &root->node, k = 0; node; node = node->child[i], k++) {
		i = *((u8 *) key + k);
		if (node->child_type[i] == INDEX_LEAF) {
			leaf = node->child[i];
			if ((root->key_length > k) && 
			    !memcmp(leaf->key + k, key + k,
				    root->key_length - k))
				return leaf->data;
			else
				return NULL;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(index_find);

void *index_find_replace(struct index_root *root, void *data, void *key)
{
	struct index_node *node;
	struct index_leaf *leaf;
	void *old_data;
	int i, k;

	for (node = &root->node, k = 0; node; node = node->child[i], k++) {
		i = *((u8 *) key + k);
		if (node->child_type[i] == INDEX_LEAF) {
			leaf = node->child[i];
			if ((root->key_length > k) && 
			    !memcmp(leaf->key + k, key + k,
				    root->key_length - k)) {
				old_data = leaf->data;
				leaf->data = data;
				return old_data;
			} else
				return NULL;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(index_find_replace);

void *index_remove(struct index_root *root, void *key)
{
	struct index_node *node, *temp_node;
	struct index_leaf *leaf;
	void *data = NULL;
	int i, k;

	for (node = &root->node, k = 0; node; node = node->child[i], k++) {
		i = *((u8 *) key + k);
		if (node->child_type[i] == INDEX_LEAF) {
			leaf = node->child[i];
			if (!memcmp(leaf->key + k, key + k,
				    root->key_length - k)) {
				data = leaf->data;
				kfree(leaf);

				while (1) {
					node->child[i] = NULL;
					node->child_type[i] = INDEX_EMPTY;
					if (--node->ref_cnt)
						break;
					temp_node = node;
					node = node->parent;
					kfree(temp_node);
					i = *((u8 *) key + --k);
				}
			}
			return data;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(index_remove);

void index_remove_all(struct index_root *root,
		      void (*callback)(void *context, void *data),
		      void *context)
{
	struct index_node *node = &root->node;
	struct index_leaf *leaf;
	int i = 0;

clean_node:
	for (; i < 256; i++) {
		switch (node->child_type[i]) {
		case INDEX_LEAF:
			leaf = node->child[i];
			if (callback)
				callback(context, leaf->data);
			kfree(leaf);
			break;
		case INDEX_NODE:
			node->ref_cnt = i;	/* save location */
			node = node->child[i];
			i = 0;
			goto clean_node;	/* remove child node */
		default:
			break;
		}
	}
	
	if (node != &root->node) {
		/* finish cleaning parent node */
		node = node->parent;
		i = node->ref_cnt;
		kfree(node->child[i++]);
		goto clean_node;
	}
	index_init(root, root->key_length, root->gfp_mask);
}
EXPORT_SYMBOL(index_remove_all);

static int __init index_start(void)
{
	return 0;
}

static void __exit index_exit(void)
{
}

module_init(index_start);
module_exit(index_exit);

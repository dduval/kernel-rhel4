#ifndef _IPATH_BACKPORT_H
#define _IPATH_BACKPORT_H
/*
 * Copyright (c) 2006 PathScale, Inc. All rights reserved.
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

#include <linux/version.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
#include <linux/pci.h> /* needed to avoid struct pci_dev warnings */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
#include <linux/compiler.h>
#endif

/*
 * XXX - This is here for a short time only. See bug 8823.
 *
 * optimized word copy; good for rev C and later opterons.  Among the best
 * for short copies, and does as well or slightly better than the
 * optimizization guide copies 6 and 8 at 2KB.
 */
void __iowrite32_copy(void __iomem * dst, const void *src, size_t count);

/*
 * XXX - Another short-term tenant.  See bug 8809.
 */
#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE 8
#endif

#endif				/* _IPATH_BACKPORT_H */

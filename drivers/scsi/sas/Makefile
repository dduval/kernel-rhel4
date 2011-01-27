#
# Kernel Makefile for the SAS Class
#
# Copyright (C) 2005 Adaptec, Inc.  All rights reserved.
# Copyright (C) 2005 Luben Tuikov <luben_tuikov@adaptec.com>
#
# This file is licensed under GPLv2.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 of the
# License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#
# $Id: //depot/sas-class/Makefile#20 $
#

ifeq ($(CONFIG_SAS_DEBUG),y)
	EXTRA_CFLAGS += -DSAS_DEBUG -g
endif

clean-files += expander_conf

obj-$(CONFIG_SAS_CLASS) += sas_class.o
sas_class-y +=  sas_init.o     \
		sas_common.o   \
		sas_phy.o      \
		sas_port.o     \
		sas_event.o    \
		sas_dump.o     \
		sas_discover.o \
		sas_expander.o \
		sas_scsi_host.o

#
# Makefile for the Linux Wireless network device drivers.
# 
# Original makefile by Peter Johanson

EXTRA_CFLAGS += -I$(TOPDIR)/drivers/net/wireless/ieee80211

ifeq ($(CONFIG_IPW_DEBUG),y)
	EXTRA_CFLAGS += -g -Wa,-adhlms=$@.lst
endif

list-m :=
list-$(CONFIG_IPW2100) += ipw2100

obj-$(CONFIG_IPW2100) += ipw2100.o

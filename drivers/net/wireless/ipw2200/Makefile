#
# Makefile for the Linux Wireless network device drivers.
# 
# Original makefile by Peter Johanson

EXTRA_CFLAGS += -I$(TOPDIR)/drivers/net/wireless/ieee80211

ifneq ($(CONFIG_IPW_DEBUG),)
	EXTRA_CFLAGS += -g -Wa,-adhlms=$@.lst
endif

list-m :=
list-$(CONFIG_IPW2200) += ipw2200

obj-$(CONFIG_IPW2200) += ipw2200.o

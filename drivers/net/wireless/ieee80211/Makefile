#
# Makefile for the Linux Wireless network device drivers.
# 
# Original makefile by Peter Johanson

list-m :=

list-$(CONFIG_IEEE80211) += ieee80211
list-$(CONFIG_IEEE80211_CRYPT) += ieee80211_crypt
list-$(CONFIG_IEEE80211_CRYPT) += ieee80211_crypt_wep
list-$(CONFIG_IEEE80211_WPA) += ieee80211_crypt_ccmp
list-$(CONFIG_IEEE80211_WPA) += ieee80211_crypt_tkip

obj-$(CONFIG_IEEE80211) += ieee80211.o 
obj-$(CONFIG_IEEE80211_CRYPT) += ieee80211_crypt.o
obj-$(CONFIG_IEEE80211_CRYPT) += ieee80211_crypt_wep.o
obj-$(CONFIG_IEEE80211_WPA) += ieee80211_crypt_ccmp.o
obj-$(CONFIG_IEEE80211_WPA) += ieee80211_crypt_tkip.o
ieee80211-objs := \
	ieee80211_module.o \
	ieee80211_tx.o \
	ieee80211_rx.o \
	ieee80211_wx.o
